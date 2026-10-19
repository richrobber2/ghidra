// SPDX-License-Identifier: Apache-2.0
import java.io.PrintStream;
import java.lang.reflect.*;
import java.nio.file.*;
import java.util.*;
import com.google.gson.GsonBuilder;
import ghidra.app.util.bin.ByteArrayProvider;
import ghidra.app.util.bin.format.elf.ElfCompressedSectionHeader;
import ghidra.app.util.bin.format.elf.ElfHeader;
import ghidra.app.util.bin.format.elf.ElfSectionHeader;

/** Calls the original public section-table parser, never full parse()/load adapters. */
public final class ElfSectionHeadersOracle {
    public static final int MAX_SECTION_HEADERS = 65536;
    private static final Field ADDR;
    private static final Field ADDRALIGN;
    private static final Field COMPRESSED;
    private static final Field EXTENDED_INDEX;
    static {
        try {
            ADDR = ElfSectionHeader.class.getDeclaredField("sh_addr");
            ADDRALIGN = ElfSectionHeader.class.getDeclaredField("sh_addralign");
            COMPRESSED = ElfSectionHeader.class.getDeclaredField("compressedHeader");
            EXTENDED_INDEX = ElfHeader.class.getDeclaredField("hasExtendedSymbolSectionIndexTable");
            for (Field field : new Field[] { ADDR, ADDRALIGN, COMPRESSED, EXTENDED_INDEX }) {
                field.setAccessible(true);
            }
        } catch (ReflectiveOperationException e) {
            throw new ExceptionInInitializerError(e);
        }
    }

    private static String hex(long value) { return Long.toUnsignedString(value, 16); }

    public static void main(String[] args) throws Exception {
        // Ghidra's Msg logger may print compression warnings; keep stdout for JSON.
        PrintStream json = System.out;
        System.setOut(System.err);
        List<Map<String,Object>> results = new ArrayList<>();
        for (String arg : args) {
            Map<String,Object> row = new LinkedHashMap<>();
            List<String> warnings = new ArrayList<>();
            row.put("file", Path.of(arg).getFileName().toString());
            row.put("warnings", warnings);
            try (ByteArrayProvider provider = new ByteArrayProvider(Files.readAllBytes(Path.of(arg)))) {
                ElfHeader header = new ElfHeader(provider, warnings::add);
                int count = header.getSectionHeaderCount();
                row.put("class_bits", header.is32Bit() ? 32 : 64);
                row.put("header_little_endian", header.getReader().isLittleEndian());
                row.put("shnum", count);
                row.put("shentsize", Short.toUnsignedInt(header.e_shentsize()));
                row.put("shstrndx", header.e_shstrndx());
                if (count > MAX_SECTION_HEADERS) {
                    // An oracle resource bound, explicitly not original Ghidra semantics.
                    throw new HeaderCountLimit("section header count " + count + " exceeds " + MAX_SECTION_HEADERS);
                }
                header.parseSectionHeaders();
                ElfSectionHeader[] entries = header.getSections();
                List<Map<String,Object>> normalized = new ArrayList<>();
                int zeroFilledEntries = 0;
                for (int i = 0; i < entries.length; i++) {
                    ElfSectionHeader entry = entries[i];
                    // Same signed int multiplication and long addition as the original parser.
                    long index = header.e_shoff() + (i * header.e_shentsize());
                    Map<String,Object> value = new LinkedHashMap<>();
                    value.put("name", entry.getNameAsString());
                    value.put("name_index", Integer.toUnsignedLong(entry.getName()));
                    value.put("type", Integer.toUnsignedLong(entry.getType()));
                    value.put("flags_hex", hex(entry.getFlags()));
                    // getAddress() performs prelink adjustment: outside scope.
                    value.put("addr_hex", hex(ADDR.getLong(entry)));
                    value.put("offset_hex", hex(entry.getOffset()));
                    value.put("size_hex", hex(entry.getSize()));
                    value.put("link", Integer.toUnsignedLong(entry.getLink()));
                    value.put("info", Integer.toUnsignedLong(entry.getInfo()));
                    // getAddressAlignment() substitutes the compressed alignment.
                    value.put("addralign_hex", hex(ADDRALIGN.getLong(entry)));
                    value.put("entsize_hex", hex(entry.getEntrySize()));
                    ElfCompressedSectionHeader compressed = (ElfCompressedSectionHeader) COMPRESSED.get(entry);
                    if (compressed == null) {
                        value.put("compressed", null);
                    } else {
                        Map<String,Object> chdr = new LinkedHashMap<>();
                        chdr.put("type", Integer.toUnsignedLong(compressed.getCh_type()));
                        chdr.put("size_hex", hex(compressed.getCh_size()));
                        chdr.put("addralign_hex", hex(compressed.getCh_addralign()));
                        chdr.put("header_size", compressed.getHeaderSize());
                        value.put("compressed", chdr);
                    }
                    normalized.add(value);
                    int canonicalSize = header.is32Bit() ? 40 : 64;
                    if (index > provider.length() || provider.length() - index < canonicalSize) {
                        zeroFilledEntries++;
                    }
                }
                row.put("accepted", true);
                row.put("zero_filled_entries", zeroFilledEntries);
                row.put("has_extended_symbol_index_table", EXTENDED_INDEX.getBoolean(header));
                row.put("entries", normalized);
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
}
