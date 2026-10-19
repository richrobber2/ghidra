// SPDX-License-Identifier: Apache-2.0
import java.io.PrintStream;
import java.lang.reflect.*;
import java.nio.file.*;
import java.util.*;
import com.google.gson.GsonBuilder;
import ghidra.app.util.bin.ByteArrayProvider;
import ghidra.app.util.bin.format.elf.*;

/**
 * Calls the original public section parser and the private string- and
 * symbol-table parsers with no dynamic table, never full parse()/load adapters.
 */
public final class ElfSymbolsOracle {
    public static final int MAX_SECTION_HEADERS = 65536;
    public static final int MAX_SYMBOLS = 1_000_000;
    private static final Method PARSE_STRINGS;
    private static final Method PARSE_SYMBOLS;
    private static final Field INDEX_TABLE;
    private static final Field EXTENDED_INDEX;
    private static final Field ADDR;
    static {
        try {
            PARSE_STRINGS = ElfHeader.class.getDeclaredMethod("parseStringTables");
            PARSE_SYMBOLS = ElfHeader.class.getDeclaredMethod("parseSymbolTables");
            INDEX_TABLE = ElfSymbolTable.class.getDeclaredField("symbolSectionIndexTable");
            EXTENDED_INDEX = ElfHeader.class.getDeclaredField("hasExtendedSymbolSectionIndexTable");
            ADDR = ElfSectionHeader.class.getDeclaredField("sh_addr");
            for (AccessibleObject member : new AccessibleObject[] { PARSE_STRINGS, PARSE_SYMBOLS,
                INDEX_TABLE, EXTENDED_INDEX, ADDR }) {
                member.setAccessible(true);
            }
        } catch (ReflectiveOperationException e) {
            throw new ExceptionInInitializerError(e);
        }
    }

    private static String hex(long value) { return Long.toUnsignedString(value, 16); }

    private static void invoke(Method method, ElfHeader header) throws Exception {
        try {
            method.invoke(header);
        } catch (InvocationTargetException e) {
            Throwable cause = e.getCause();
            if (cause instanceof Exception) { throw (Exception) cause; }
            throw e;
        }
    }

    private static int indexOf(ElfSectionHeader[] sections, ElfSectionHeader section) {
        for (int i = 0; i < sections.length; i++) {
            if (sections[i] == section) { return i; }
        }
        return -1;
    }

    private static boolean isSymbolTable(ElfSectionHeader section) {
        return section.getType() == ElfSectionHeaderConstants.SHT_SYMTAB ||
            section.getType() == ElfSectionHeaderConstants.SHT_DYNSYM;
    }

    /** Oracle resource bounds, explicitly not original Ghidra semantics. */
    private static void checkLimits(ElfHeader header, ElfSectionHeader[] sections) throws Exception {
        boolean extended = EXTENDED_INDEX.getBoolean(header);
        for (int i = 0; i < sections.length; i++) {
            ElfSectionHeader section = sections[i];
            if (!isSymbolTable(section) || section.isInvalidOffset()) { continue; }
            List<Integer> counts = new ArrayList<>();
            if (section.getEntrySize() != 0) { counts.add((int) (section.getSize() / section.getEntrySize())); }
            if (extended) {
                // Same choice as ElfHeader.getExtendedSymbolSectionIndexTable.
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
                if (count > MAX_SYMBOLS) {
                    throw new SymbolCountLimit("symbol count " + count + " exceeds " + MAX_SYMBOLS);
                }
            }
        }
    }

    public static void main(String[] args) throws Exception {
        // Ghidra's Msg logger may print; keep stdout for JSON.
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
                if (count > MAX_SECTION_HEADERS) {
                    throw new SymbolCountLimit("section header count " + count + " exceeds " + MAX_SECTION_HEADERS);
                }
                header.parseSectionHeaders();
                ElfSectionHeader[] sections = header.getSections();
                checkLimits(header, sections);
                invoke(PARSE_STRINGS, header);
                invoke(PARSE_SYMBOLS, header);
                row.put("accepted", true);
                row.put("shnum", sections.length);
                List<Map<String,Object>> strings = new ArrayList<>();
                for (ElfStringTable table : header.getStringTables()) {
                    Map<String,Object> value = new LinkedHashMap<>();
                    value.put("section", indexOf(sections, table.getTableSectionHeader()));
                    value.put("offset_hex", hex(table.getFileOffset()));
                    // Table addresses are prelink-adjusted section addresses: report raw sh_addr.
                    value.put("addr_hex", hex(ADDR.getLong(table.getTableSectionHeader())));
                    value.put("size_hex", hex(table.getLength()));
                    strings.add(value);
                }
                row.put("string_tables", strings);
                List<Map<String,Object>> tables = new ArrayList<>();
                for (ElfSymbolTable table : header.getSymbolTables()) {
                    Map<String,Object> value = new LinkedHashMap<>();
                    ElfSectionHeader section = table.getTableSectionHeader();
                    value.put("section", indexOf(sections, section));
                    value.put("dynamic", table.isDynamic());
                    value.put("offset_hex", hex(table.getFileOffset()));
                    value.put("addr_hex", hex(ADDR.getLong(section)));
                    value.put("size_hex", hex(table.getLength()));
                    value.put("entsize_hex", hex(section.getEntrySize()));
                    value.put("symbol_count", table.getSymbolCount());
                    ElfStringTable strtab = table.getStringTable();
                    value.put("string_table_section", strtab == null ? null
                        : indexOf(sections, strtab.getTableSectionHeader()));
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
            } catch (Exception e) {
                row.put("accepted", false);
                row.put("error_type", e.getClass().getSimpleName());
                row.put("error", e.getMessage());
            }
            results.add(row);
        }
        json.println(new GsonBuilder().serializeNulls().setPrettyPrinting().create().toJson(results));
    }

    private static final class SymbolCountLimit extends Exception {
        SymbolCountLimit(String message) { super(message); }
    }
}
