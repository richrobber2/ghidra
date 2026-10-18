# ELF header benchmark

Run `python3 /workspace/ghidra-rust-port/bench/run.py`. The prepared Java and Rust
toolchains are used automatically. Use `--prepare-only` to build all variants and
check their per-file normalized-header digests without running throughput samples.

The comparison is the original Ghidra `ElfHeader` constructor against the Rust
`parse_header(..., GhidraCompatible)` function, followed by the same observable
digest of all normalized header fields exposed by the Java oracle. Ghidra's
`ElfHeader.parse()`, table decoding, loading, analysis, and decompilation are outside
this benchmark. Whole files are preloaded before timing. Java reuses each
`ByteArrayProvider`; Rust borrows each byte vector. Parser-internal allocations
remain part of the timed work. Rust uses `black_box` on inputs and parsed output;
Java publishes the accumulated checksum to a volatile field once per batch.

The default corpus has four canonical headers, four extended-count headers, and
four local executable files. Every file has equal weight. The timed reads touch
their headers and, when needed, section zero; this is a cache-resident header
microbenchmark, not file-size-scaled throughput. Input bytes and their SHA-256
hashes are retained in `corpus/` and `corpus-manifest.json`. Malformed inputs are
covered by correctness checks outside the throughput corpus.

The harness builds release, max (fat LTO and one codegen unit), and max with
`-C target-cpu=native`, using `--offline --locked`. The native variant requires the
measured host CPU's instruction set. All processes run on one allowed logical CPU.
The JVM heap is explicitly bounded to 64 MiB initial and 256 MiB maximum. Each
fresh process warms up for at least 10 seconds and collects five samples lasting
at least 500 ms each. Three process repetitions rotate variant order. Both
implementations use the same timed batch size and checksum; elapsed time and
completed parses are recorded, so the faster implementation performs more parses.

`results.json` contains every sample and process observation, toolchain versions,
build flags, source hashes, CPU metadata, corpus identity, and summaries based on
the median of the three process sample medians. Checksum agreement is required
before reporting results. This custom harness is not JMH and does not characterize
all JIT compilation, cache, scheduling, thermal, or corpus effects.

Startup is measured separately: wall time from process launch through exit after
preloading and parsing every input once. It includes `taskset`/`timeout`, runtime
initialization, file I/O, and output, using warm filesystem caches. Summary memory
results use each benchmark process's own Linux `/proc/self/status` `VmHWM`, read
after timing. This includes runtime, input preloading, warmup, and measured samples;
it does not count parser allocations. Raw Linux `wait4` process-tree high-water
RSS is also retained, but can include an inherited launcher floor and is not used
in summaries. CPU pinning and a bounded JVM heap make the run reproducible, but
these measurements do not predict every deployment configuration.

## Measured results, 2026-10-17

The validated run used an Intel Xeon Platinum 8573C, pinned logical CPU 0,
Java HotSpot 25.0.4.1+1-LTS-5, and rustc 1.99.1 with LLVM 23.1.1 targeting
`x86_64-unknown-linux-gnu`. All 12 per-file digests and every timed checksum agreed.
Results below use three fresh processes per variant, 10 seconds of warmup per
process, and five samples of at least 500 ms. The JVM used `-Xms64m -Xmx256m`.

| Variant | Median ns/header | Range of process medians, ns/header | Java time / variant time | Median process peak RSS, MiB |
|---|---:|---:|---:|---:|
| Ghidra Java constructor | 322.62 | 308.39–453.76 | 1.00 | 84.6 |
| Rust release, opt-level 3 | 57.36 | 48.89–59.27 | 5.62 | 9.0 |
| Rust max, fat LTO and one codegen unit | 62.05 | 60.99–261.46 | 5.20 | 8.9 |
| Rust max plus native CPU | 147.69 | 61.57–271.83 | 2.18 | 8.9 |

These are medians from this cache-resident header corpus, not a whole-Ghidra
speedup or a guaranteed speedup on other inputs or machines. There is substantial
variation, including slow individual samples in both max profiles. Its cause was
not isolated; CPU pinning does not remove shared-cloud or runtime variability.
No sample was discarded. The run supports a header-level improvement over the
original constructor, but does not establish an additional benefit from LTO or
native CPU instructions. Ordinary release had the lowest observed median here;
the evidence does not justify a general ranking of optimization profiles.

Median launch-through-exit times were 514.8 ms for Java, 17.7 ms for Rust release,
19.4 ms for max, and 24.5 ms for max-native. These separately measured values
include launcher overhead, runtime initialization, all file reads, one parse per
input, and JSON output. They are not isolated parser latency or cold-cache startup.

The first run used 1.5 seconds of warmup and 300 ms samples. Its Java timings
declined strongly throughout the measured interval, so its apparent speedup was
not used as the final comparison. That evidence remains in
[`results-initial-1500ms.json`](results-initial-1500ms.json). The longer-warmup run
removed that multi-fold downward trend; its complete observations, including
outliers and source hashes, are in [`results.json`](results.json).
