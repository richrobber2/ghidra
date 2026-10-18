// SPDX-License-Identifier: Apache-2.0
import java.lang.invoke.MethodHandle;
import java.lang.invoke.MethodHandles;
import java.lang.invoke.MethodType;
import java.lang.invoke.VarHandle;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;

import ghidra.app.util.bin.ByteArrayProvider;
import ghidra.app.util.bin.format.elf.ElfHeader;
import ghidra.app.util.bin.format.elf.ElfProgramHeader;

/** Original header constructor and private program-table parser; never full parse(). */
public final class ElfProgramHeadersBench {
    private static final int BATCH_PASSES = 16;
    private static final long MIX_CONSTANT = 0x9e3779b97f4a7c15L;
    private static final MethodHandle PARSE;
    private static final VarHandle RAW_VADDR;
    private static final VarHandle RAW_PADDR;
    private static final Consumer<String> WARNING = warning -> {
        throw new IllegalArgumentException("Benchmark corpus warning: " + warning);
    };
    private static volatile long sink;

    static {
        try {
            MethodHandles.Lookup lookup = MethodHandles.lookup();
            PARSE = MethodHandles.privateLookupIn(ElfHeader.class, lookup)
                .findVirtual(ElfHeader.class, "parseProgramHeaders", MethodType.methodType(void.class));
            MethodHandles.Lookup programLookup = MethodHandles.privateLookupIn(ElfProgramHeader.class, lookup);
            RAW_VADDR = programLookup.findVarHandle(ElfProgramHeader.class, "p_vaddr", long.class);
            RAW_PADDR = programLookup.findVarHandle(ElfProgramHeader.class, "p_paddr", long.class);
        }
        catch (ReflectiveOperationException error) {
            throw new ExceptionInInitializerError(error);
        }
    }

    private static long mix(long state, long value) {
        return (Long.rotateLeft(state, 9) + value) ^ MIX_CONSTANT;
    }

    private static long digest(ElfHeader h) {
        long x = 0;
        x = mix(x, h.is32Bit() ? 32 : 64);
        x = mix(x, h.getReader().isLittleEndian() ? 1 : 0);
        x = mix(x, h.isLittleEndian() ? 1 : 0);
        x = mix(x, Byte.toUnsignedLong(h.e_ident_osabi()));
        x = mix(x, Byte.toUnsignedLong(h.e_ident_abiversion()));
        x = mix(x, Short.toUnsignedLong(h.e_type()));
        x = mix(x, Short.toUnsignedLong(h.e_machine()));
        x = mix(x, Integer.toUnsignedLong(h.e_version()));
        x = mix(x, h.e_entry());
        x = mix(x, h.e_phoff());
        x = mix(x, h.e_shoff());
        x = mix(x, Integer.toUnsignedLong(h.e_flags()));
        x = mix(x, Short.toUnsignedLong(h.e_ehsize()));
        x = mix(x, Short.toUnsignedLong(h.e_phentsize()));
        x = mix(x, h.getProgramHeaderCount());
        x = mix(x, Short.toUnsignedLong(h.e_shentsize()));
        x = mix(x, h.getSectionHeaderCount());
        x = mix(x, h.e_shstrndx());
        ElfProgramHeader[] entries = h.getProgramHeaders();
        for (ElfProgramHeader entry : entries) {
            x = mix(x, Integer.toUnsignedLong(entry.getType()));
            x = mix(x, Integer.toUnsignedLong(entry.getFlags()));
            x = mix(x, entry.getOffset());
            // Public address getters trigger lazy PRE-trailer handling, outside this scope.
            x = mix(x, (long) RAW_VADDR.get(entry));
            x = mix(x, (long) RAW_PADDR.get(entry));
            x = mix(x, entry.getFileSize());
            x = mix(x, entry.getMemorySize());
            x = mix(x, entry.getAlign());
        }
        return x;
    }

    private static long parseDigest(ByteArrayProvider input) throws Throwable {
        ElfHeader header = new ElfHeader(input, WARNING);
        if (header.getProgramHeaderCount() > 4096) {
            throw new IllegalArgumentException("Explicit benchmark wrapper count limit: 4096");
        }
        PARSE.invokeExact(header);
        return digest(header);
    }

    private static long pass(ByteArrayProvider[] inputs) throws Throwable {
        long checksum = 0;
        for (int i = 0; i < inputs.length; i++) checksum += parseDigest(inputs[i]);
        return checksum;
    }

    private static String measure(ByteArrayProvider[] inputs, long minimumNs) throws Throwable {
        long checksum = 0, passes = 0;
        long start = System.nanoTime();
        long elapsed;
        do {
            for (int i = 0; i < BATCH_PASSES; i++) checksum += pass(inputs);
            passes += BATCH_PASSES;
            sink = checksum;
            elapsed = System.nanoTime() - start;
        } while (elapsed < minimumNs);
        return "{\"elapsed_ns\":" + elapsed + ",\"passes\":" + passes +
            ",\"parses\":" + passes * inputs.length + ",\"checksum\":\"" +
            Long.toUnsignedString(checksum) + "\"}";
    }

    private static long vmHwmKib() throws Exception {
        for (String line : Files.readAllLines(Path.of("/proc/self/status"))) {
            if (line.startsWith("VmHWM:")) return Long.parseLong(line.trim().split("\\s+")[1]);
        }
        throw new IllegalStateException("Linux VmHWM unavailable");
    }

    public static void main(String[] args) throws Throwable {
        if (args.length < 4) throw new IllegalArgumentException("warmup_ms sample_ms samples files...");
        long warmupMs = Long.parseLong(args[0]), sampleMs = Long.parseLong(args[1]);
        int samples = Integer.parseInt(args[2]);
        if (warmupMs < 0 || sampleMs < 0 || samples < 0) throw new IllegalArgumentException("negative interval/count");
        ByteArrayProvider[] inputs = new ByteArrayProvider[args.length - 3];
        List<String> digests = new ArrayList<>();
        long corpusChecksum = 0;
        for (int i = 3; i < args.length; i++) {
            byte[] bytes = Files.readAllBytes(Path.of(args[i]));
            if (bytes.length > 64 * 1024 * 1024) throw new IllegalArgumentException("benchmark input too large");
            inputs[i - 3] = new ByteArrayProvider(bytes);
            long value = parseDigest(inputs[i - 3]);
            corpusChecksum += value;
            digests.add("\"" + Long.toUnsignedString(value) + "\"");
        }
        if (warmupMs > 0) measure(inputs, Math.multiplyExact(warmupMs, 1_000_000));
        List<String> results = new ArrayList<>();
        for (int i = 0; i < samples; i++) {
            results.add(measure(inputs, Math.multiplyExact(sampleMs, 1_000_000)));
        }
        System.out.println("{\"process_vm_hwm_kib\":" + vmHwmKib() +
            ",\"corpus_checksum\":\"" + Long.toUnsignedString(corpusChecksum) +
            "\",\"digests\":[" + String.join(",", digests) + "],\"samples\":[" +
            String.join(",", results) + "]}");
    }
}
