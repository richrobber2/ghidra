import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import ghidra.app.util.bin.ByteArrayProvider;
import ghidra.app.util.bin.format.elf.ElfHeader;

/** Constructor benchmark: byte providers are preloaded and reused, parse() is never called. */
public final class ElfHeaderBench {
    private static volatile long sink;
    private static final int BATCH_PASSES = 256;

    private static long digest(ElfHeader h) {
        long x = h.is32Bit() ? 32 : 64;
        x ^= Long.rotateLeft(h.getReader().isLittleEndian() ? 1 : 0, 1);
        x ^= Long.rotateLeft(h.isLittleEndian() ? 1 : 0, 2);
        x ^= Long.rotateLeft(Short.toUnsignedLong(h.e_type()), 3);
        x ^= Long.rotateLeft(Short.toUnsignedLong(h.e_machine()), 7);
        x ^= Long.rotateLeft(Integer.toUnsignedLong(h.e_version()), 11);
        x ^= Long.rotateLeft(h.e_entry(), 13);
        x ^= Long.rotateLeft(h.e_phoff(), 17);
        x ^= Long.rotateLeft(h.e_shoff(), 19);
        x ^= Long.rotateLeft(Integer.toUnsignedLong(h.e_flags()), 23);
        x ^= Long.rotateLeft(Short.toUnsignedLong(h.e_ehsize()), 29);
        x ^= Long.rotateLeft(Short.toUnsignedLong(h.e_phentsize()), 31);
        x ^= Long.rotateLeft(h.getProgramHeaderCount(), 37);
        x ^= Long.rotateLeft(Short.toUnsignedLong(h.e_shentsize()), 41);
        x ^= Long.rotateLeft(h.getSectionHeaderCount(), 43);
        x ^= Long.rotateLeft(h.e_shstrndx(), 47);
        return x;
    }

    private static long pass(ByteArrayProvider[] inputs) throws Exception {
        long checksum = 0;
        for (ByteArrayProvider input : inputs) {
            checksum += digest(new ElfHeader(input, null));
        }
        return checksum;
    }

    private static long peakRssKib() throws Exception {
        for (String line : Files.readAllLines(Path.of("/proc/self/status"))) {
            if (line.startsWith("VmHWM:")) return Long.parseLong(line.trim().split("\\s+")[1]);
        }
        throw new IllegalStateException("Linux VmHWM is unavailable");
    }

    private static String measure(ByteArrayProvider[] inputs, long minimumNs) throws Exception {
        long checksum = 0, passes = 0;
        long start = System.nanoTime();
        long elapsed;
        do {
            for (int i = 0; i < BATCH_PASSES; i++) {
                checksum += pass(inputs);
            }
            passes += BATCH_PASSES;
            sink = checksum;
            elapsed = System.nanoTime() - start;
        } while (elapsed < minimumNs);
        return "{\"elapsed_ns\":" + elapsed + ",\"passes\":" + passes +
            ",\"parses\":" + passes * inputs.length + ",\"checksum\":\"" +
            Long.toUnsignedString(checksum) + "\"}";
    }

    public static void main(String[] args) throws Exception {
        if (args.length < 4) throw new IllegalArgumentException("warmup_ms sample_ms samples files...");
        long warmupMs = Long.parseLong(args[0]);
        long sampleMs = Long.parseLong(args[1]);
        int samples = Integer.parseInt(args[2]);
        ByteArrayProvider[] inputs = new ByteArrayProvider[args.length - 3];
        List<String> digests = new ArrayList<>();
        long corpusChecksum = 0;
        for (int i = 3; i < args.length; i++) {
            inputs[i - 3] = new ByteArrayProvider(Files.readAllBytes(Path.of(args[i])));
            ElfHeader header = new ElfHeader(inputs[i - 3], warning -> {
                throw new IllegalArgumentException("Benchmark corpus warning: " + warning);
            });
            long digest = digest(header);
            corpusChecksum += digest;
            digests.add("\"" + Long.toUnsignedString(digest) + "\"");
        }
        if (warmupMs > 0) measure(inputs, warmupMs * 1_000_000);
        List<String> results = new ArrayList<>();
        for (int i = 0; i < samples; i++) results.add(measure(inputs, sampleMs * 1_000_000));
        // Output allocation and serialization occur after every measured interval.
        long peakRssKib = peakRssKib();
        System.out.println("{\"process_vm_hwm_kib\":" + peakRssKib +
            ",\"corpus_checksum\":\"" + Long.toUnsignedString(corpusChecksum) +
            "\",\"digests\":[" + String.join(",", digests) + "],\"samples\":[" +
            String.join(",", results) + "]}");
    }
}
