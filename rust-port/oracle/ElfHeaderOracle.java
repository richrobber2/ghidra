import java.nio.file.*;
import java.util.*;
import com.google.gson.GsonBuilder;
import ghidra.app.util.bin.ByteArrayProvider;
import ghidra.app.util.bin.format.elf.ElfHeader;

/** Calls the original constructor only; deliberately does not load a Ghidra Program. */
public class ElfHeaderOracle {
    public static void main(String[] args) throws Exception {
        List<Map<String,Object>> results = new ArrayList<>();
        for (String arg : args) {
            Map<String,Object> row = new LinkedHashMap<>();
            List<String> warnings = new ArrayList<>();
            row.put("file", Path.of(arg).getFileName().toString());
            row.put("warnings", warnings);
            try (ByteArrayProvider bytes = new ByteArrayProvider(Files.readAllBytes(Path.of(arg)))) {
                ElfHeader h = new ElfHeader(bytes, warnings::add);
                row.put("accepted", true);
                row.put("class_bits", h.is32Bit() ? 32 : 64);
                row.put("header_little_endian", h.getReader().isLittleEndian());
                row.put("declared_little_endian", h.isLittleEndian());
                row.put("type", Short.toUnsignedInt(h.e_type()));
                row.put("machine", Short.toUnsignedInt(h.e_machine()));
                row.put("version", Integer.toUnsignedLong(h.e_version()));
                row.put("entry_hex", Long.toUnsignedString(h.e_entry(),16));
                row.put("phoff_hex", Long.toUnsignedString(h.e_phoff(),16));
                row.put("shoff_hex", Long.toUnsignedString(h.e_shoff(),16));
                row.put("flags", Integer.toUnsignedLong(h.e_flags()));
                row.put("ehsize", Short.toUnsignedInt(h.e_ehsize()));
                row.put("phentsize", Short.toUnsignedInt(h.e_phentsize()));
                row.put("phnum", h.getProgramHeaderCount());
                row.put("shentsize", Short.toUnsignedInt(h.e_shentsize()));
                row.put("shnum", h.getSectionHeaderCount());
                row.put("shstrndx", h.e_shstrndx());
            } catch (Exception e) {
                row.put("accepted", false);
                row.put("error_type", e.getClass().getSimpleName());
                row.put("error", e.getMessage());
            }
            results.add(row);
        }
        System.out.println(new GsonBuilder().setPrettyPrinting().create().toJson(results));
    }
}
