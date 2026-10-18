// SPDX-License-Identifier: Apache-2.0
import java.lang.reflect.*;
import java.nio.file.*;
import java.util.*;
import com.google.gson.GsonBuilder;
import ghidra.app.util.bin.ByteArrayProvider;
import ghidra.app.util.bin.format.elf.ElfHeader;
import ghidra.app.util.bin.format.elf.ElfProgramHeader;

/** Calls the original private table parser, never full parse()/load adapters. */
public final class ElfProgramHeadersOracle {
    public static final int MAX_PROGRAM_HEADERS = 4096;
    private static final Method PARSE;
    private static final Field VADDR;
    private static final Field PADDR;
    static {
        try {
            PARSE = ElfHeader.class.getDeclaredMethod("parseProgramHeaders");
            PARSE.setAccessible(true);
            VADDR = ElfProgramHeader.class.getDeclaredField("p_vaddr");
            PADDR = ElfProgramHeader.class.getDeclaredField("p_paddr");
            VADDR.setAccessible(true);
            PADDR.setAccessible(true);
        } catch (ReflectiveOperationException e) {
            throw new ExceptionInInitializerError(e);
        }
    }

    private static String hex(long value) { return Long.toUnsignedString(value, 16); }

    public static void main(String[] args) throws Exception {
        List<Map<String,Object>> results = new ArrayList<>();
        for (String arg : args) {
            Map<String,Object> row = new LinkedHashMap<>();
            List<String> warnings = new ArrayList<>();
            row.put("file", Path.of(arg).getFileName().toString());
            row.put("warnings", warnings);
            try (ByteArrayProvider provider = new ByteArrayProvider(Files.readAllBytes(Path.of(arg)))) {
                ElfHeader header = new ElfHeader(provider, warnings::add);
                int count = header.getProgramHeaderCount();
                row.put("class_bits", header.is32Bit() ? 32 : 64);
                row.put("header_little_endian", header.getReader().isLittleEndian());
                row.put("phnum", count);
                row.put("phentsize", Short.toUnsignedInt(header.e_phentsize()));
                if (count > MAX_PROGRAM_HEADERS) {
                    // An oracle resource bound, explicitly not original Ghidra semantics.
                    throw new HeaderCountLimit("program header count " + count + " exceeds " + MAX_PROGRAM_HEADERS);
                }
                try {
                    PARSE.invoke(header);
                } catch (InvocationTargetException e) {
                    Throwable cause = e.getCause();
                    if (cause instanceof Exception) { throw (Exception) cause; }
                    throw e;
                }
                ElfProgramHeader[] entries = header.getProgramHeaders();
                List<Map<String,Object>> normalized = new ArrayList<>();
                long fileSizeSum = 0;
                int zeroFilledEntries = 0;
                for (int i = 0; i < entries.length; i++) {
                    ElfProgramHeader entry = entries[i];
                    // Same signed int multiplication and long addition as the original parser.
                    long index = header.e_phoff() + (i * header.e_phentsize());
                    // Reuse the actual original record constructor for the pre-rewrite offset.
                    ElfProgramHeader raw = new ElfProgramHeader(header.getReader().clone(index), header);
                    Map<String,Object> value = new LinkedHashMap<>();
                    value.put("type", Integer.toUnsignedLong(entry.getType()));
                    value.put("flags", Integer.toUnsignedLong(entry.getFlags()));
                    value.put("raw_offset_hex", hex(raw.getOffset()));
                    value.put("offset_hex", hex(entry.getOffset()));
                    // Public address getters perform lazy PRE trailer adjustment: outside scope.
                    value.put("vaddr_hex", hex(VADDR.getLong(entry)));
                    value.put("paddr_hex", hex(PADDR.getLong(entry)));
                    value.put("filesz_hex", hex(entry.getFileSize()));
                    value.put("memsz_hex", hex(entry.getMemorySize()));
                    value.put("align_hex", hex(entry.getAlign()));
                    normalized.add(value);
                    fileSizeSum += entry.getFileSize();
                    int canonicalSize = header.is32Bit() ? 32 : 56;
                    if (index > provider.length() || provider.length() - index < canonicalSize) {
                        zeroFilledEntries++;
                    }
                }
                row.put("accepted", true);
                row.put("offsets_rewritten", fileSizeSum == provider.length());
                row.put("zero_filled_entries", zeroFilledEntries);
                row.put("entries", normalized);
            } catch (Exception e) {
                row.put("accepted", false);
                row.put("error_type", e.getClass().getSimpleName());
                row.put("error", e.getMessage());
            }
            results.add(row);
        }
        System.out.println(new GsonBuilder().serializeNulls().setPrettyPrinting().create().toJson(results));
    }

    private static final class HeaderCountLimit extends Exception {
        HeaderCountLimit(String message) { super(message); }
    }
}
