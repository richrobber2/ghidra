// SPDX-License-Identifier: Apache-2.0
import java.io.FileDescriptor;
import java.io.FileOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.lang.reflect.*;
import java.nio.file.*;
import java.util.*;
import java.util.function.Consumer;
import com.google.gson.GsonBuilder;
import ghidra.app.util.bin.ByteArrayProvider;
import ghidra.app.util.bin.format.elf.*;

/**
 * Calls the original private parsers in parse() order up to the symbol tables:
 * program headers, section headers, dynamic table, string tables, DT_NEEDED
 * names and symbol tables. Load adapters, relocations and GNU version tables
 * are never run.
 */
public final class ElfDynamicOracle {
    public static final int MAX_PROGRAM_HEADERS = 4096;
    public static final int MAX_SECTION_HEADERS = 65536;
    public static final int MAX_DYNAMIC_ENTRIES = 65536;
    public static final int MAX_SYMBOLS = 1_000_000;
    public static final long MAX_TOTAL_SYMBOLS = 4_000_000;
    private static final Method PARSE_PROGRAM_HEADERS;
    private static final Method PARSE_DYNAMIC;
    private static final Method PARSE_STRINGS;
    private static final Method PARSE_LIBRARIES;
    private static final Method PARSE_SYMBOLS;
    private static final Method HASH_TYPE;
    private static final Method GNU_HASH_COUNT;
    private static final Method MAX_OFFSET;
    private static final Field DYNAMIC_STRINGS;
    private static final Field DYNAMIC_SYMBOLS;
    private static final Field ERRORS;
    private static final Field EXTENDED_INDEX;
    private static final Field INDEX_TABLE;
    private static final Field SECTION_ADDR;
    private static final Field STRING_ADDR;
    private static final Field ENTRY_SIZE;
    static {
        try {
            PARSE_PROGRAM_HEADERS = ElfHeader.class.getDeclaredMethod("parseProgramHeaders");
            PARSE_DYNAMIC = ElfHeader.class.getDeclaredMethod("parseDynamicTable");
            PARSE_STRINGS = ElfHeader.class.getDeclaredMethod("parseStringTables");
            PARSE_LIBRARIES = ElfHeader.class.getDeclaredMethod("parseDynamicLibraryNames");
            PARSE_SYMBOLS = ElfHeader.class.getDeclaredMethod("parseSymbolTables");
            HASH_TYPE = ElfHeader.class.getDeclaredMethod("getDynamicHashTableType");
            GNU_HASH_COUNT = ElfHeader.class.getDeclaredMethod("deriveGnuHashDynamicSymbolCount", long.class);
            MAX_OFFSET = ElfHeader.class.getDeclaredMethod("getMaxOffsetForLoadedRegionContaining",
                long.class, long.class);
            DYNAMIC_STRINGS = ElfHeader.class.getDeclaredField("dynamicStringTable");
            DYNAMIC_SYMBOLS = ElfHeader.class.getDeclaredField("dynamicSymbolTable");
            ERRORS = ElfHeader.class.getDeclaredField("errorConsumer");
            EXTENDED_INDEX = ElfHeader.class.getDeclaredField("hasExtendedSymbolSectionIndexTable");
            INDEX_TABLE = ElfSymbolTable.class.getDeclaredField("symbolSectionIndexTable");
            SECTION_ADDR = ElfSectionHeader.class.getDeclaredField("sh_addr");
            STRING_ADDR = ElfStringTable.class.getDeclaredField("addrOffset");
            ENTRY_SIZE = ElfSymbolTable.class.getDeclaredField("entrySize");
            for (AccessibleObject member : new AccessibleObject[] { PARSE_PROGRAM_HEADERS,
                PARSE_DYNAMIC, PARSE_STRINGS, PARSE_LIBRARIES, PARSE_SYMBOLS, HASH_TYPE,
                GNU_HASH_COUNT, MAX_OFFSET, DYNAMIC_STRINGS, DYNAMIC_SYMBOLS, ERRORS,
                EXTENDED_INDEX, INDEX_TABLE, SECTION_ADDR, STRING_ADDR, ENTRY_SIZE }) {
                member.setAccessible(true);
            }
        } catch (ReflectiveOperationException e) {
            throw new ExceptionInInitializerError(e);
        }
    }

    private static String hex(long value) { return Long.toUnsignedString(value, 16); }

    private static Object invoke(Method method, ElfHeader header, Object... args) throws Exception {
        try {
            return method.invoke(header, args);
        } catch (InvocationTargetException e) {
            Throwable cause = e.getCause();
            if (cause instanceof Exception) { throw (Exception) cause; }
            throw e;
        }
    }

    private static int indexOf(Object[] items, Object item) {
        for (int i = 0; i < items.length; i++) {
            if (items[i] == item) { return i; }
        }
        return -1;
    }

    private static boolean isSymbolTable(ElfSectionHeader section) {
        return section.getType() == ElfSectionHeaderConstants.SHT_SYMTAB ||
            section.getType() == ElfSectionHeaderConstants.SHT_DYNSYM;
    }

    /**
     * The symbol count parseDynamicSymbolTable() would use, or null when it would
     * build no table or fail on its own. Its warnings are discarded: the real call
     * repeats every step.
     */
    private static Integer dynamicSymbolCount(ElfHeader header, ElfSectionHeader[] sections,
            long fileLength) throws Exception {
        ElfDynamicTable dynamic = header.getDynamicTable();
        if (dynamic == null || !dynamic.containsDynamicValue(ElfDynamicType.DT_SYMTAB)) { return null; }
        long raw = dynamic.getDynamicValue(ElfDynamicType.DT_SYMTAB);
        long address = header.adjustAddressForPrelink(raw);
        for (ElfSectionHeader section : sections) {
            if (isSymbolTable(section) && !section.isInvalidOffset() && section.getAddress() == address) {
                return null;
            }
        }
        ElfDynamicType hashType = (ElfDynamicType) invoke(HASH_TYPE, header);
        if (!dynamic.containsDynamicValue(ElfDynamicType.DT_SYMENT) || hashType == null ||
            DYNAMIC_STRINGS.get(header) == null || raw == 0) {
            return null;
        }
        long entrySize = dynamic.getDynamicValue(ElfDynamicType.DT_SYMENT);
        long hashAddress = header.adjustAddressForPrelink(dynamic.getDynamicValue(hashType));
        ElfProgramHeader tableLoad = header.getProgramLoadHeaderContaining(address);
        ElfProgramHeader hashLoad = header.getProgramLoadHeaderContaining(hashAddress);
        if (tableLoad == null || hashLoad == null) { return null; }
        @SuppressWarnings("unchecked")
        Consumer<String> errors = (Consumer<String>) ERRORS.get(header);
        ERRORS.set(header, (Consumer<String>) message -> {});
        int count;
        try {
            tableLoad.getOffset(address);
            long hashOffset = hashLoad.getOffset(hashAddress);
            if (hashType == ElfDynamicType.DT_GNU_HASH) {
                long maxOffset = (long) invoke(MAX_OFFSET, header, hashOffset, 12L);
                if (maxOffset >= fileLength) {
                    throw new SymbolCountLimit("GNU hash table region extends past EOF");
                }
                count = (int) invoke(GNU_HASH_COUNT, header, hashOffset);
            } else if (hashType == ElfDynamicType.DT_GNU_XHASH) {
                count = header.getReader().readInt(hashOffset + 8) + header.getReader().readInt(hashOffset);
            } else {
                count = header.getReader().readInt(hashOffset + 4);
            }
        } catch (SymbolCountLimit e) {
            throw e;
        } catch (Exception e) {
            return null;
        } finally {
            ERRORS.set(header, errors);
        }
        if (count == 0 || entrySize == 0) { return null; }
        return (int) ((entrySize * count) / entrySize);
    }

    /** Oracle resource bounds, explicitly not original Ghidra semantics. */
    private static void checkLimits(ElfHeader header, ElfSectionHeader[] sections, long fileLength)
            throws Exception {
        boolean extended = EXTENDED_INDEX.getBoolean(header);
        long total = 0;
        for (ElfSectionHeader section : sections) {
            if (!isSymbolTable(section) || section.isInvalidOffset()) { continue; }
            List<Integer> counts = new ArrayList<>();
            if (section.getEntrySize() != 0) { counts.add((int) (section.getSize() / section.getEntrySize())); }
            if (extended) {
                for (ElfSectionHeader index : sections) {
                    int link = index.getLink();
                    if (index.getType() == ElfSectionHeaderConstants.SHT_SYMTAB_SHNDX && link > 0 &&
                        link < sections.length && sections[link] == section) {
                        counts.add((int) (index.getSize() / 4));
                        break;
                    }
                }
            }
            for (int count : counts) {
                total += Math.max(count, 0);
            }
            for (int count : counts) {
                if (count > MAX_SYMBOLS) {
                    throw new SymbolCountLimit("symbol count " + count + " exceeds " + MAX_SYMBOLS);
                }
            }
            if (total > MAX_TOTAL_SYMBOLS) {
                throw new SymbolCountLimit("total symbol count exceeds " + MAX_TOTAL_SYMBOLS);
            }
        }
        Integer count = dynamicSymbolCount(header, sections, fileLength);
        if (count != null) {
            if (count > MAX_SYMBOLS) {
                throw new SymbolCountLimit("symbol count " + count + " exceeds " + MAX_SYMBOLS);
            }
            total += Math.max(count, 0);
            if (total > MAX_TOTAL_SYMBOLS) {
                throw new SymbolCountLimit("total symbol count exceeds " + MAX_TOTAL_SYMBOLS);
            }
        }
    }

    public static void main(String[] args) throws Exception {
        // Ghidra's Msg logger may print; keep stdout for JSON, in UTF-8 whatever the locale.
        PrintStream json = new PrintStream(new FileOutputStream(FileDescriptor.out), true, StandardCharsets.UTF_8);
        System.setOut(System.err);
        List<Map<String,Object>> results = new ArrayList<>();
        for (String arg : args) {
            Map<String,Object> row = new LinkedHashMap<>();
            List<String> warnings = new ArrayList<>();
            row.put("file", Path.of(arg).getFileName().toString());
            row.put("warnings", warnings);
            try (ByteArrayProvider provider = new ByteArrayProvider(Files.readAllBytes(Path.of(arg)))) {
                ElfHeader header = new ElfHeader(provider, warnings::add);
                if (header.getProgramHeaderCount() > MAX_PROGRAM_HEADERS) {
                    throw new HeaderCountLimit("program header count " + header.getProgramHeaderCount() +
                        " exceeds " + MAX_PROGRAM_HEADERS);
                }
                invoke(PARSE_PROGRAM_HEADERS, header);
                if (header.getSectionHeaderCount() > MAX_SECTION_HEADERS) {
                    throw new HeaderCountLimit("section header count " + header.getSectionHeaderCount() +
                        " exceeds " + MAX_SECTION_HEADERS);
                }
                header.parseSectionHeaders();
                ElfSectionHeader[] sections = header.getSections();
                invoke(PARSE_DYNAMIC, header);
                ElfDynamicTable dynamic = header.getDynamicTable();
                if (dynamic != null && dynamic.getDynamics().length > MAX_DYNAMIC_ENTRIES) {
                    throw new DynamicEntryLimit("dynamic entry count exceeds " + MAX_DYNAMIC_ENTRIES);
                }
                invoke(PARSE_STRINGS, header);
                invoke(PARSE_LIBRARIES, header);
                checkLimits(header, sections, provider.length());
                invoke(PARSE_SYMBOLS, header);

                row.put("accepted", true);
                row.put("phnum", header.getProgramHeaders().length);
                row.put("shnum", sections.length);
                if (dynamic == null) {
                    row.put("dynamic", null);
                } else {
                    Map<String,Object> value = new LinkedHashMap<>();
                    value.put("offset_hex", hex(dynamic.getFileOffset()));
                    value.put("addr_hex", hex(dynamic.getAddressOffset()));
                    List<Map<String,Object>> entries = new ArrayList<>();
                    for (ElfDynamic entry : dynamic.getDynamics()) {
                        Map<String,Object> e = new LinkedHashMap<>();
                        e.put("tag", entry.getTag());
                        e.put("value_hex", hex(entry.getValue()));
                        entries.add(e);
                    }
                    value.put("entries", entries);
                    row.put("dynamic", value);
                }
                ElfStringTable[] stringTables = header.getStringTables();
                List<Map<String,Object>> strings = new ArrayList<>();
                for (ElfStringTable table : stringTables) {
                    Map<String,Object> value = new LinkedHashMap<>();
                    ElfSectionHeader section = table.getTableSectionHeader();
                    value.put("section", section == null ? null : indexOf(sections, section));
                    value.put("offset_hex", hex(table.getFileOffset()));
                    // Section tables report raw sh_addr; dynamic ones the address Ghidra stored.
                    value.put("addr_hex", hex(section == null ? STRING_ADDR.getLong(table)
                        : SECTION_ADDR.getLong(section)));
                    value.put("size_hex", hex(table.getLength()));
                    strings.add(value);
                }
                row.put("string_tables", strings);
                Object dynamicStrings = DYNAMIC_STRINGS.get(header);
                row.put("dynamic_string_table", dynamicStrings == null ? null : indexOf(stringTables, dynamicStrings));
                row.put("library_names", Arrays.asList(header.getDynamicLibraryNames()));
                ElfSymbolTable[] symbolTables = header.getSymbolTables();
                List<Map<String,Object>> tables = new ArrayList<>();
                for (ElfSymbolTable table : symbolTables) {
                    Map<String,Object> value = new LinkedHashMap<>();
                    ElfSectionHeader section = table.getTableSectionHeader();
                    value.put("section", section == null ? null : indexOf(sections, section));
                    value.put("dynamic", table.isDynamic());
                    value.put("offset_hex", hex(table.getFileOffset()));
                    value.put("addr_hex", hex(section == null ? table.getAddressOffset()
                        : SECTION_ADDR.getLong(section)));
                    value.put("size_hex", hex(table.getLength()));
                    value.put("entsize_hex", hex(ENTRY_SIZE.getLong(table)));
                    value.put("symbol_count", table.getSymbolCount());
                    ElfStringTable strtab = table.getStringTable();
                    value.put("string_table", strtab == null ? null : indexOf(stringTables, strtab));
                    int[] indexTable = (int[]) INDEX_TABLE.get(table);
                    value.put("extended_index_count", indexTable == null ? null : indexTable.length);
                    List<Map<String,Object>> symbols = new ArrayList<>();
                    for (ElfSymbol symbol : table.getSymbols()) {
                        Map<String,Object> s = new LinkedHashMap<>();
                        s.put("name", symbol.getNameAsString());
                        s.put("name_index", Integer.toUnsignedLong(symbol.getName()));
                        s.put("value_hex", hex(symbol.getValue()));
                        s.put("size_hex", hex(symbol.getSize()));
                        s.put("info", Byte.toUnsignedInt(symbol.getInfo()));
                        s.put("other", Byte.toUnsignedInt(symbol.getOther()));
                        s.put("shndx", Short.toUnsignedInt(symbol.getSectionHeaderIndex()));
                        s.put("xshndx", Integer.toUnsignedLong(symbol.getExtendedSectionHeaderIndex()));
                        symbols.add(s);
                    }
                    value.put("symbols", symbols);
                    tables.add(value);
                }
                row.put("symbol_tables", tables);
                Object dynamicSymbols = DYNAMIC_SYMBOLS.get(header);
                row.put("dynamic_symbol_table", dynamicSymbols == null ? null : indexOf(symbolTables, dynamicSymbols));
            } catch (Exception e) {
                row.put("accepted", false);
                row.put("error_type", e.getClass().getSimpleName());
                row.put("error", e.getMessage());
            }
            results.add(row);
        }
        json.println(new GsonBuilder().serializeNulls().setPrettyPrinting().create().toJson(results));
    }

    private static final class HeaderCountLimit extends Exception {
        HeaderCountLimit(String message) { super(message); }
    }

    private static final class DynamicEntryLimit extends Exception {
        DynamicEntryLimit(String message) { super(message); }
    }

    private static final class SymbolCountLimit extends Exception {
        SymbolCountLimit(String message) { super(message); }
    }
}
