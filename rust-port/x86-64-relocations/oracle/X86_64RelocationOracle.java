// SPDX-License-Identifier: Apache-2.0
package ghidra.app.util.bin.format.elf.relocation;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.lang.reflect.*;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;

import com.google.gson.GsonBuilder;

import ghidra.app.util.bin.ByteArrayProvider;
import ghidra.app.util.bin.format.elf.*;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.BookmarkManager;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.reloc.Relocation.Status;
import ghidra.program.model.reloc.RelocationResult;
import ghidra.util.ErrorLogger;
import ghidra.util.Msg;

/**
 * Drives the original X86_64_ElfRelocationHandler, through its own
 * X86_64_ElfRelocationContext (ElfGotRelocationContext, ElfRelocationContext),
 * over every relocation of an ELF file parsed by the original ElfHeader steps.
 * Program, Memory, BookmarkManager and ElfLoadHelper are small proxies that
 * implement the memory and symbol model documented in the Rust crate's
 * model.rs; the driver loop follows ElfProgramBuilder.processRelocationTable
 * and processRelocationTableEntries.
 */
public final class X86_64RelocationOracle {
    static final long MAX_BLOCK_BYTES = 256L << 20;
    static final long MAX_TOTAL_BLOCK_BYTES = 1L << 30;
    static final long LINKAGE_ALIGNMENT = 0x1000;
    static final long EXTERNAL_SLOT = 8;
    static final BigInteger TWO_64 = BigInteger.ONE.shiftLeft(64);
    static final AddressSpace SPACE = new GenericAddressSpace("ram", 64, AddressSpace.TYPE_RAM, 0, false);

    private static final Method PARSE_PROGRAM_HEADERS;
    private static final Method PARSE_DYNAMIC;
    private static final Method PARSE_STRINGS;
    private static final Method PARSE_LIBRARIES;
    private static final Method PARSE_SYMBOLS;
    private static final Method PARSE_RELOCATIONS;
    private static final Field GOT_ADDRESS;
    private static final Field GOT_MAP;
    static {
        try {
            PARSE_PROGRAM_HEADERS = ElfHeader.class.getDeclaredMethod("parseProgramHeaders");
            PARSE_DYNAMIC = ElfHeader.class.getDeclaredMethod("parseDynamicTable");
            PARSE_STRINGS = ElfHeader.class.getDeclaredMethod("parseStringTables");
            PARSE_LIBRARIES = ElfHeader.class.getDeclaredMethod("parseDynamicLibraryNames");
            PARSE_SYMBOLS = ElfHeader.class.getDeclaredMethod("parseSymbolTables");
            PARSE_RELOCATIONS = ElfHeader.class.getDeclaredMethod("parseRelocationTables");
            GOT_ADDRESS = ElfGotRelocationContext.class.getDeclaredField("allocatedGotAddress");
            GOT_MAP = ElfGotRelocationContext.class.getDeclaredField("gotMap");
            for (AccessibleObject member : new AccessibleObject[] { PARSE_PROGRAM_HEADERS,
                PARSE_DYNAMIC, PARSE_STRINGS, PARSE_LIBRARIES, PARSE_SYMBOLS, PARSE_RELOCATIONS,
                GOT_ADDRESS, GOT_MAP }) {
                member.setAccessible(true);
            }
        } catch (ReflectiveOperationException e) {
            throw new ExceptionInInitializerError(e);
        }
    }

    static final class Rejected extends Exception {
        final String code;
        Rejected(String code) { super(code); this.code = code; }
    }

    static final class Block {
        final long start;
        final byte[] data;
        Block(long start, byte[] data) { this.start = start; this.data = data; }
    }

    static Address addr(long offset) { return SPACE.getAddress(offset); }

    static String hex(byte[] bytes) {
        StringBuilder out = new StringBuilder();
        for (byte b : bytes) { out.append(String.format("%02x", b & 0xff)); }
        return out.toString();
    }

    static BigInteger unsigned(long value) {
        return new BigInteger(Long.toUnsignedString(value));
    }

    static BigInteger alignUp(BigInteger value, long alignment) {
        BigInteger a = BigInteger.valueOf(alignment);
        BigInteger[] qr = value.divideAndRemainder(a);
        return qr[1].signum() == 0 ? value : qr[0].add(BigInteger.ONE).multiply(a);
    }

    /** One run over one file. */
    static final class Session {
        final ElfHeader header;
        final long adjust;
        final List<Block> blocks = new ArrayList<>();
        long externalStart;
        long externalLength;
        BigInteger linkageTop;
        final Map<ElfSymbol, Address> symbolMap = new HashMap<>();
        ElfSymbol gotSymbol;

        final List<String> relocations = new ArrayList<>();
        final Map<String, Long> statusCounts = new TreeMap<>();
        final Map<String, Long> typeCounts = new TreeMap<>();
        final List<String> writes = new ArrayList<>();
        final List<String> log = new ArrayList<>();
        final List<String> loaderLog = new ArrayList<>();
        final List<String> bookmarks = new ArrayList<>();
        final List<String> console = new ArrayList<>();
        final List<String> artificial = new ArrayList<>();
        final List<String> createdSymbols = new ArrayList<>();
        String aborted;

        Session(ElfHeader header, byte[] bytes, long adjust, boolean unresolved) throws Rejected {
            this.header = header;
            this.adjust = adjust;
            long total = 0;
            for (ElfProgramHeader segment : header.getProgramHeaders()) {
                if (segment.getType() != ElfProgramHeaderConstants.PT_LOAD || segment.getMemorySize() == 0) {
                    continue;
                }
                long memsz = segment.getMemorySize();
                if (Long.compareUnsigned(memsz, MAX_BLOCK_BYTES) > 0) { throw new Rejected("segment-too-large"); }
                total += memsz;
                if (total > MAX_TOTAL_BLOCK_BYTES) { throw new Rejected("segment-too-large"); }
                long start = segment.getVirtualAddress() + adjust;
                if (unsigned(start).add(BigInteger.valueOf(memsz)).compareTo(TWO_64) > 0) {
                    throw new Rejected("segment-wraps");
                }
                byte[] data = new byte[(int) memsz];
                long count = Long.compareUnsigned(segment.getFileSize(), memsz) < 0 ? segment.getFileSize() : memsz;
                long offset = segment.getOffset();
                if (Long.compareUnsigned(offset, bytes.length) < 0) {
                    long available = bytes.length - offset;
                    int n = (int) (Long.compareUnsigned(count, available) < 0 ? count : available);
                    System.arraycopy(bytes, (int) offset, data, 0, n);
                }
                blocks.add(new Block(start, data));
            }
            List<BigInteger[]> ranges = new ArrayList<>();
            for (Block b : blocks) {
                BigInteger s = unsigned(b.start);
                ranges.add(new BigInteger[] { s, s.add(BigInteger.valueOf(b.data.length)) });
            }
            ranges.sort((x, y) -> { int c = x[0].compareTo(y[0]); return c != 0 ? c : x[1].compareTo(y[1]); });
            BigInteger top = BigInteger.ZERO;
            for (int i = 0; i < ranges.size(); i++) {
                if (i > 0 && ranges.get(i)[0].compareTo(ranges.get(i - 1)[1]) < 0) {
                    throw new Rejected("overlapping-segments");
                }
                top = top.max(ranges.get(i)[1]);
            }

            BigInteger externalBase = alignUp(top, LINKAGE_ALIGNMENT);
            long externals = 0;
            for (ElfSymbolTable table : header.getSymbolTables()) {
                for (ElfSymbol symbol : table.getSymbols()) {
                    String name = symbol.getNameAsString();
                    if (gotSymbol == null && ElfConstants.GOT_SYMBOL_NAME.equals(name)) {
                        gotSymbol = symbol;
                    }
                    if (symbolMap.containsKey(symbol)) {
                        continue;
                    }
                    int shndx = symbol.getSectionHeaderIndex() & 0xffff;
                    if (shndx == 0) {
                        boolean named = name != null && !name.isEmpty() &&
                            !ElfConstants.GOT_SYMBOL_NAME.equals(name);
                        if (named && !unresolved) {
                            BigInteger at = externalBase.add(BigInteger.valueOf(externals * EXTERNAL_SLOT));
                            symbolMap.put(symbol, addr(at.longValue()));
                            externals++;
                        }
                    }
                    else if (shndx == 0xfff1) {
                        symbolMap.put(symbol, addr(symbol.getValue()));
                    }
                    else if (shndx == 0xfff2) {
                        // SHN_COMMON stays unmapped
                    }
                    else {
                        symbolMap.put(symbol, addr(header.adjustAddressForPrelink(symbol.getValue()) + adjust));
                    }
                }
            }
            linkageTop = top;
            if (externals > 0) {
                long length = externals * EXTERNAL_SLOT;
                BigInteger end = externalBase.add(BigInteger.valueOf(length));
                if (end.compareTo(TWO_64) > 0) { throw new Rejected("no-external-room"); }
                externalStart = externalBase.longValue();
                externalLength = length;
                blocks.add(new Block(externalStart, new byte[(int) length]));
                linkageTop = end;
            }
        }

        int[] mapped(long address) {
            for (int i = 0; i < blocks.size(); i++) {
                Block b = blocks.get(i);
                long delta = address - b.start;
                if (Long.compareUnsigned(delta, b.data.length) < 0) { return new int[] { i, (int) delta }; }
            }
            return null;
        }

        void check(long address, int length) throws MemoryAccessException {
            for (int i = 0; i < length; i++) {
                long at = address + i;
                if (mapped(at) == null) {
                    throw new MemoryAccessException("Address " + addr(at) + " does not exist in memory");
                }
            }
        }

        byte[] read(Address address, int length) throws MemoryAccessException {
            long a = address.getOffset();
            check(a, length);
            byte[] out = new byte[length];
            for (int i = 0; i < length; i++) {
                int[] m = mapped(a + i);
                out[i] = blocks.get(m[0]).data[m[1]];
            }
            return out;
        }

        void write(Address address, byte[] bytes) throws MemoryAccessException {
            long a = address.getOffset();
            check(a, bytes.length);
            for (int i = 0; i < bytes.length; i++) {
                int[] m = mapped(a + i);
                blocks.get(m[0]).data[m[1]] = bytes[i];
            }
            writes.add(address + " " + hex(bytes));
        }

        static byte[] le(long value, int length) {
            byte[] out = new byte[length];
            for (int i = 0; i < length; i++) { out[i] = (byte) (value >>> (8 * i)); }
            return out;
        }

        static long fromLe(byte[] bytes) {
            long value = 0;
            for (int i = bytes.length - 1; i >= 0; i--) { value = (value << 8) | (bytes[i] & 0xff); }
            return value;
        }

        boolean isExternal(Address address) {
            return externalLength != 0 &&
                Long.compareUnsigned(address.getOffset() - externalStart, externalLength) < 0;
        }

        Long gotValue() {
            ElfDynamicTable dynamic = header.getDynamicTable();
            if (dynamic != null && dynamic.containsDynamicValue(ElfDynamicType.DT_PLTGOT)) {
                try {
                    return header.adjustAddressForPrelink(dynamic.getDynamicValue(ElfDynamicType.DT_PLTGOT)) + adjust;
                } catch (Exception e) {
                    throw new AssertionError(e);
                }
            }
            Address got = gotSymbol != null ? symbolMap.get(gotSymbol) : null;
            return got != null ? got.getOffset() : null;
        }

        AddressRange allocateLinkageBlock(int alignment, int size) {
            BigInteger start = alignUp(linkageTop, alignment);
            BigInteger end = start.add(BigInteger.valueOf(size)).subtract(BigInteger.ONE);
            if (end.compareTo(TWO_64) >= 0) { return null; }
            return new AddressRangeImpl(addr(start.longValue()), addr(end.longValue()));
        }

        Object proxy(Class<?> type, InvocationHandler handler) {
            return Proxy.newProxyInstance(type.getClassLoader(), new Class<?>[] { type }, (p, m, args) -> {
                switch (m.getName()) {
                    case "hashCode": return System.identityHashCode(p);
                    case "equals": return p == args[0];
                    case "toString": return type.getSimpleName() + " proxy";
                    default: return handler.invoke(p, m, args);
                }
            });
        }

        Memory memory() {
            return (Memory) proxy(Memory.class, (p, m, a) -> {
                switch (m.getName() + "/" + (a == null ? 0 : a.length)) {
                    case "getByte/1": return read((Address) a[0], 1)[0];
                    case "getLong/1": return fromLe(read((Address) a[0], 8));
                    case "setByte/2": write((Address) a[0], le((Byte) a[1], 1)); return null;
                    case "setShort/2": write((Address) a[0], le((Short) a[1], 2)); return null;
                    case "setInt/2": write((Address) a[0], le((Integer) a[1], 4)); return null;
                    case "setLong/2": write((Address) a[0], le((Long) a[1], 8)); return null;
                    case "getBlock/1": return null;
                    case "isExternalBlockAddress/1": return isExternal((Address) a[0]);
                    case "isBigEndian/0": return false;
                    default: throw new UnsupportedOperationException("Memory." + m.getName());
                }
            });
        }

        BookmarkManager bookmarkManager() {
            return (BookmarkManager) proxy(BookmarkManager.class, (p, m, a) -> {
                if (m.getName().equals("setBookmark") && a.length == 4) {
                    bookmarks.add(a[0] + " " + a[1] + " " + a[2] + " " + a[3]);
                    return null;
                }
                throw new UnsupportedOperationException("BookmarkManager." + m.getName());
            });
        }

        Program program() {
            Memory memory = memory();
            BookmarkManager manager = bookmarkManager();
            return (Program) proxy(Program.class, (p, m, a) -> {
                switch (m.getName()) {
                    case "getMemory": return memory;
                    case "getBookmarkManager": return manager;
                    case "getDefaultPointerSize": return 8;
                    default: throw new UnsupportedOperationException("Program." + m.getName());
                }
            });
        }

        ElfLoadHelper loadHelper(MessageLog messageLog) {
            Program program = program();
            return (ElfLoadHelper) proxy(ElfLoadHelper.class, (p, m, a) -> {
                switch (m.getName()) {
                    case "getProgram": return program;
                    case "getElfHeader": return header;
                    case "getLog": return messageLog;
                    case "log":
                        if (a[0] instanceof Throwable t) {
                            loaderLog.add("exception: " + t.getClass().getSimpleName() + ": " + t.getMessage());
                        } else {
                            loaderLog.add((String) a[0]);
                        }
                        return null;
                    case "getImageBaseWordAdjustmentOffset": return adjust;
                    case "getGOTValue": return gotValue();
                    case "allocateLinkageBlock": return allocateLinkageBlock((Integer) a[0], (Integer) a[1]);
                    case "createSymbol": createdSymbols.add(a[0] + " " + a[1]); return null;
                    case "addArtificialRelocTableEntry": artificial.add(a[0] + " " + a[1]); return true;
                    default: throw new UnsupportedOperationException("ElfLoadHelper." + m.getName());
                }
            });
        }

        void count(String status) { statusCounts.merge(status, 1L, Long::sum); }

        X86_64_ElfRelocationContext run() throws Exception {
            MessageLog messageLog = new MessageLog() {
                @Override
                public void appendMsg(String message) { log.add(message); }
            };
            X86_64_ElfRelocationHandler handler = new X86_64_ElfRelocationHandler();
            if (!handler.canRelocate(header)) { throw new Rejected("not-x86-64"); }
            X86_64_ElfRelocationContext context =
                handler.createRelocationContext(loadHelper(messageLog), symbolMap);
            Address base = addr(header.adjustAddressForPrelink(0) + adjust);
            ElfRelocationTable[] tables = header.getRelocationTables();
            outer:
            for (int t = 0; t < tables.length; t++) {
                ElfRelocationTable table = tables[t];
                ElfSectionHeader relocated = table.getSectionToBeRelocated();
                if (relocated != null && (relocated.getFlags() & ElfSectionHeaderConstants.SHF_ALLOC) == 0) {
                    loaderLog.add("Failed to identify relocation base address for relocation table 0x" +
                        table.getAddressOffset() + " [section: " + relocated.getNameAsString() + "]");
                    continue;
                }
                context.startRelocationTableProcessing(table);
                ElfSymbolTable symbolTable = table.getAssociatedSymbolTable();
                boolean missing = table.isMissingRequiredSymbolTable();
                if (missing) {
                    ElfSectionHeader section = table.getTableSectionHeader();
                    String tableName = section != null ? section.getNameAsString() : "dynamic";
                    String baseName = relocated != null ? relocated.getNameAsString() : "PT_LOAD";
                    loaderLog.add("Unable to apply " + tableName + " relocations affecting " + baseName +
                        " due to missing symbol table");
                }
                int relrType = table.isRelrTable() ? context.getRelrRelocationType() : 0;
                ElfRelocation[] relocs = table.getRelocations();
                for (int i = 0; i < relocs.length; i++) {
                    ElfRelocation reloc = relocs[i];
                    int type = reloc.getType();
                    if (type == 0 && !table.isRelrTable()) { continue; }
                    int symbolIndex = reloc.getSymbolIndex();
                    String symbolName = symbolTable != null ? symbolTable.getSymbolName(symbolIndex) : "";
                    symbolName = ElfSymbolNameUtils.replaceInvalidChars(symbolName);
                    Address relocAddr = context.getRelocationAddress(base, reloc.getOffset());
                    if (relrType != 0) {
                        type = relrType;
                        reloc.setType(relrType);
                    }
                    Status status = Status.SKIPPED;
                    int byteLength = 0;
                    try {
                        if (missing) {
                            status = Status.FAILURE;
                            context.markRelocationError(relocAddr, type, symbolIndex, symbolName,
                                "Missing symbol table");
                            continue;
                        }
                        if (mapped(relocAddr.getOffset()) == null) {
                            status = Status.FAILURE;
                            loaderLog.add("Unable to perform relocation: Type = " + type + " (0x" +
                                Long.toHexString(type) + ") at " + relocAddr + " (Symbol = " + symbolName +
                                ") - Block is non-existent");
                            continue;
                        }
                        RelocationResult result = context.processRelocation(reloc, relocAddr);
                        byteLength = result.byteLength();
                        status = result.status();
                    }
                    catch (RuntimeException e) {
                        aborted = e.getClass().getSimpleName() + ": " + e.getMessage();
                    }
                    finally {
                        relocations.add(t + " " + i + " " + relocAddr + " " + Integer.toUnsignedString(reloc.getType()) +
                            " " + status.name() + " " + byteLength);
                        count(status.name());
                        typeCounts.merge(Integer.toUnsignedString(reloc.getType()), 1L, Long::sum);
                    }
                    if (aborted != null) { break outer; }
                }
                context.endRelocationTableProcessing();
            }
            return context;
        }
    }

    static long fnv(List<String> lines) {
        long hash = 0xcbf29ce484222325L;
        for (String line : lines) {
            byte[] bytes = (line + "\n").getBytes(StandardCharsets.UTF_8);
            for (byte b : bytes) { hash = (hash ^ (b & 0xff)) * 0x100000001b3L; }
        }
        return hash;
    }

    static Object lines(List<String> values, boolean digest) {
        if (!digest) { return values; }
        Map<String,Object> out = new LinkedHashMap<>();
        out.put("count", values.size());
        out.put("fnv1a", Long.toHexString(fnv(values)));
        return out;
    }

    static Object invoke(Method method, ElfHeader header) throws Exception {
        try {
            return method.invoke(header);
        } catch (InvocationTargetException e) {
            Throwable cause = e.getCause();
            if (cause instanceof Exception ex) { throw ex; }
            throw e;
        }
    }

    @SuppressWarnings("unchecked")
    static Map<String,Object> runCase(Path path, long adjust, boolean unresolved, boolean digest,
            List<String> console, List<String> stdout) {
        Map<String,Object> row = new LinkedHashMap<>();
        row.put("file", path.getFileName().toString());
        try {
            byte[] bytes = Files.readAllBytes(path);
            ElfHeader header;
            try {
                header = new ElfHeader(new ByteArrayProvider(bytes), message -> {});
                invoke(PARSE_PROGRAM_HEADERS, header);
                header.parseSectionHeaders();
                invoke(PARSE_DYNAMIC, header);
                invoke(PARSE_STRINGS, header);
                invoke(PARSE_LIBRARIES, header);
                invoke(PARSE_SYMBOLS, header);
                invoke(PARSE_RELOCATIONS, header);
            } catch (Exception e) {
                throw new Rejected("parse");
            }
            if (!header.is64Bit()) { throw new Rejected("not-elf64"); }
            if (header.e_machine() != ElfConstants.EM_X86_64) { throw new Rejected("not-x86-64"); }
            if (header.isRelocatable()) { throw new Rejected("relocatable"); }
            Session session = new Session(header, bytes, adjust, unresolved);
            console.clear();
            stdout.clear();
            X86_64_ElfRelocationContext context = session.run();
            row.put("accepted", true);
            row.put("relocation_count", session.relocations.size());
            row.put("status_counts", session.statusCounts);
            row.put("type_counts", session.typeCounts);
            row.put("relocations", lines(session.relocations, digest));
            row.put("writes", lines(session.writes, digest));
            row.put("log", lines(session.log, digest));
            row.put("loader_log", lines(session.loaderLog, digest));
            row.put("bookmarks", lines(session.bookmarks, digest));
            row.put("console", lines(new ArrayList<>(console), digest));
            row.put("stdout", lines(new ArrayList<>(stdout), digest));
            row.put("artificial", lines(session.artificial, digest));
            row.put("created_symbols", lines(session.createdSymbols, digest));
            Address got = (Address) GOT_ADDRESS.get(context);
            row.put("got_allocation", got == null ? "not-attempted" : got == Address.NO_ADDRESS ? "failed" : got.toString());
            List<String> entries = new ArrayList<>();
            Map<Long, Address> gotMap = (Map<Long, Address>) GOT_MAP.get(context);
            if (gotMap != null) {
                List<Long> keys = new ArrayList<>(gotMap.keySet());
                keys.sort(Long::compareUnsigned);
                for (Long key : keys) {
                    Address entry = gotMap.get(key);
                    entries.add(Long.toHexString(key) + " " + (entry == Address.NO_ADDRESS ? "NO_ADDRESS" : entry.toString()));
                }
            }
            row.put("got_entries", lines(entries, digest));
            row.put("aborted", session.aborted);
        } catch (Rejected e) {
            row.put("accepted", false);
            row.put("error", e.code);
        } catch (Exception e) {
            row.put("accepted", false);
            row.put("error", "io");
            row.put("detail", e.toString());
        }
        return row;
    }

    /** Arguments: [--digest] MANIFEST OUTPUT. Manifest lines: path TAB adjust-hex TAB 0|1. */
    public static void main(String[] args) throws Exception {
        boolean digest = args[0].equals("--digest");
        int at = digest ? 1 : 0;
        List<String> manifest = Files.readAllLines(Path.of(args[at]));
        Path output = Path.of(args[at + 1]);

        List<String> console = new ArrayList<>();
        Msg.setErrorLogger(new ErrorLogger() {
            public void trace(Object o, Object m) { }
            public void trace(Object o, Object m, Throwable t) { }
            public void debug(Object o, Object m) { }
            public void debug(Object o, Object m, Throwable t) { }
            public void info(Object o, Object m) { console.add("info: " + m); }
            public void info(Object o, Object m, Throwable t) { console.add("info: " + m); }
            public void warn(Object o, Object m) { console.add("warn: " + m); }
            public void warn(Object o, Object m, Throwable t) { console.add("warn: " + m); }
            public void error(Object o, Object m) { console.add("error: " + m); }
            public void error(Object o, Object m, Throwable t) { console.add("error: " + m); }
        });
        // The GOT size computation prints duplicate symbol values to System.out.
        ByteArrayOutputStream captured = new ByteArrayOutputStream();
        PrintStream realOut = System.out;
        List<Map<String,Object>> results = new ArrayList<>();
        for (String line : manifest) {
            if (line.isEmpty()) { continue; }
            String[] fields = line.split("\t");
            long adjust = Long.parseUnsignedLong(fields[1].replaceFirst("^0x", ""), 16);
            boolean unresolved = fields[2].equals("1");
            List<String> stdout = new ArrayList<>();
            captured.reset();
            System.setOut(new PrintStream(captured, true, StandardCharsets.UTF_8));
            Map<String,Object> row;
            try {
                row = runCase(Path.of(fields[0]), adjust, unresolved, digest, console, stdout);
            } finally {
                System.out.flush();
                System.setOut(realOut);
            }
            String text = captured.toString(StandardCharsets.UTF_8);
            if (Boolean.TRUE.equals(row.get("accepted"))) {
                for (String out : text.split("\n")) {
                    if (!out.isEmpty()) { stdout.add(out); }
                }
                row.put("stdout", lines(stdout, digest));
                row.put("console", lines(new ArrayList<>(console), digest));
            }
            console.clear();
            results.add(row);
        }
        Files.writeString(output, new GsonBuilder().serializeNulls().disableHtmlEscaping()
            .create().toJson(results) + "\n");
    }
}
