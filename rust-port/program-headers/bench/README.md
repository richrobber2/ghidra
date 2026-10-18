# ELF header and program-table component benchmark

Run only after correctness gates pass, without concurrent builds, Ghidra analysis,
hash audits or other CPU-heavy work. Every result path must be new:

```sh
python3 /workspace/ghidra-rust-port/program-headers/bench/run.py \
  --smoke --result /workspace/ghidra-rust-port/program-headers/results/bench-smoke-01
python3 /workspace/ghidra-rust-port/program-headers/bench/run.py \
  --result /workspace/ghidra-rust-port/program-headers/results/bench-fixed-01
```

The default protocol is frozen: three processes per arm, ten seconds of warmup
per process, then five samples of at least 500 ms each. Process order is Java,
Rust, Rust, Java, Java, Rust; all execute serially on one allowed CPU. `--cpu`
selects that CPU. `--smoke` uses one process per arm and short intervals and is
only a harness check. `--prepare-only` builds and verifies digests without timed
samples. Do not interpret either as performance evidence.

The 23 preloaded inputs are 16 synthetic canonical program tables (32/64-bit,
little/big endian, 1/4/32/128 entries), four legacy offset-rewrite tables and copies
of the host `ls`, `cat` and libz ELF files. They are frozen in each result directory
with hashes and resolved source paths. Synthetic inputs validate this table
boundary; they are not complete executable payload fixtures. Each file receives
equal weight in a pass, regardless of record count or file size.

Java uses the actual original `ElfHeader` constructor and its private
`parseProgramHeaders`, invoked by a cached static-final `MethodHandle`. It does
not call full `ElfHeader.parse()`. Static-final `VarHandle`s read raw virtual and
physical addresses to avoid the public getters' lazy PRE-trailer adjustment.
Rust uses `parse_program_headers(GhidraCompatible)` and linear iteration, with
portable release optimization (level 3, no LTO or native CPU flags). Both compute
the same checksum over shared header fields and every entry's
type, flags, effective offset, raw addresses, file size, memory size and alignment.
All per-input checksums must match before timing; every measured sample must
match its expected checksum and fixed minimum duration. The separate Java oracle
checks pre-rewrite raw offsets and unexposed rewrite status, excluded from both
timed checksums. Effective post-rewrite offsets are included.

These are equivalent semantic outputs at the component boundary, with different
representations and runtime work. Java allocates its original objects and arrays;
Rust borrows bytes and decodes during validation and iteration. Cached Java
bridge/field access costs are included and not isolated. The harness is not JMH,
and the fixed corpus stays cache-resident. Startup,
file reads, JSON output, full loading, analysis and decompilation are outside the
sample intervals. Do not infer whole-Ghidra speed from these timings.

Each invocation retains source snapshots, source and jar hashes, its Rust binary
and Java class, corpus bytes, complete command records, stdout/stderr, raw sample
counts/checksums, process CPU observations and failures. Summary dispersion is
the range of the three process sample medians. Raw Linux VmHWM and wait4 readings
describe whole processes; they are not allocation counts or reliable true peaks,
and the runner does not derive a memory-savings claim. Preserve a failed run and
correct its cause in a new result directory; never select favorable timing reruns.

Audit retained receipts without rerunning the benchmark:

```sh
python3 /workspace/ghidra-rust-port/program-headers/bench/audit.py \
  /workspace/ghidra-rust-port/program-headers/results/bench-fixed-01 --external
```

The default audit uses retained snapshots and artifacts. `--external` also checks
the current source files and original classpath jars; omit it when auditing an
archive after a deliberate later source change.

## Retained result, 2026-10-18

The sole fixed run is [results/fixed-01/results.json](results/fixed-01/results.json).
All 23 per-input digests, 30 timed sample checksums, six process observations and
13 complete command lifecycles pass the read-only external hash audit. It used
CPU 0 on an Intel Xeon Platinum 8573C, Java 25 and portable Rust 1.99.1 release
optimization. The smoke run is retained separately in `results/smoke-01` and is
not performance evidence.

| Arm | Process 1 median | Process 2 median | Process 3 median | Median of process medians |
| --- | ---: | ---: | ---: | ---: |
| Original Java | 2,258 ns | 5,970 ns | 8,635 ns | 5,970 ns |
| Borrowed Rust | 36,177 ns | 3,678 ns | 1,769 ns | 3,678 ns |

Each value is wall nanoseconds per header plus its complete program table,
including the shared field digest, averaged over the fixed equal-weight corpus.
The ratio of the final medians is 1.623 Java/Rust, but the large process and
sample variation prevents a stable acceleration claim. The first Rust process
is slower than its paired Java process and includes a 241,343 ns/table sample;
both remain in the result. The latter two paired process medians favor Rust.
No observation was discarded or retimed, and the cause of the variation is
unestablished. This result does not establish whole-Ghidra speed or justify
replacing the installed parser. Raw process memory readings are retained without
a memory-savings conclusion.
