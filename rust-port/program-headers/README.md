# Rust ELF program-header parser

This second Rust component extends the existing ELF file-header parser with
program-header tables: the segment descriptions used when mapping an executable.
It is a separate library and JSON CLI. Ghidra's installed Java loader and native
decompiler remain original; this component is not connected to the loader yet.

```bash
/workspace/ghidra-rust-port/program-headers/elf-segments /bin/ls
/workspace/ghidra-rust-port/program-headers/elf-segments --compatible /bin/ls
```

The CLI defaults to strict mode. It emits one JSON array for all input files,
returns 1 if any file fails and 2 for argument errors. Use `--` before paths that
start with `-`. It accepts regular files up to 64 MiB each. No background service
or toolchain activation is needed to run the built binary.

To build without touching the first component's retained build artifacts:

```bash
source /workspace/rust-optimization/activate.sh
export CARGO_TARGET_DIR=/workspace/ghidra-rust-port/program-headers/target
cargo build --manifest-path /workspace/ghidra-rust-port/program-headers/Cargo.toml \
  --release --offline --locked --bin ghidra-elf-segments
```

The library has no third-party dependencies, forbids unsafe Rust and borrows the
input bytes. `parse_program_headers(&bytes, ParsePolicy::Strict)` returns a checked
view; `header()`, `iter()` and `get(index)` expose owned numeric fields. Iteration
uses constant additional storage. Random access becomes O(index) when compatibility
mode applies the legacy offset rewrite, so prefer `iter()` for complete tables.
Both policies cap the resolved program-header count at 4096 as an explicit resource
bound. That is a wrapper policy, not an ELF-format limit.

| Policy | Behavior |
|---|---|
| Strict, default | Validates the ELF header, required section zero and the full canonical program-header table extent. Preserves raw segment offsets. |
| Ghidra compatible | Uses Java's signed-short record stride, zero-fills missing record bytes, reproduces its missing-table warning and applies its wrapping file-size-sum offset rewrite. Exposes both raw and effective offsets. |

Compatibility mode deliberately rejects signed record-address arithmetic overflow
instead of allowing Java to wrap to another file region. The earlier header
parser's documented section-zero overflow rejections are also inherited. Overflow
exceptions must be reported separately from matching Java cases. A declared zero
or short record size can produce padded bytes without a missing-region warning:
the original Java warning checks the declared stride, while its constructor reads
the complete 32- or 56-byte record. `zero_filled_entries` makes this distinction
visible.

Neither policy validates segment payload extents, alignment, segment relationships,
section-table contents or architecture-specific constraints. Addresses are raw
record fields: PRE trailer adjustment and architecture adapters are outside this
boundary. Header diagnostics remain available through `header().diagnostics`.

The reference is the original `ElfHeader` constructor followed by its private
`parseProgramHeaders` method, with actual `ElfProgramHeader` objects. Calling the
full `parse()` method would add section, dynamic and loader behavior outside this
experiment. See `oracle/` for the isolated reference and fixture runner, `review/`
for independent edge checks and `bench/` for equivalent preloaded parsing work.
All builds, Java runs, Ghidra imports and benchmarks must run serially.

## Verified checks

```bash
python3 /workspace/ghidra-rust-port/program-headers/check.py \
  --output /workspace/ghidra-rust-port/program-headers/results/check-NEW
python3 /workspace/ghidra-rust-port/program-headers/review/adversarial.py \
  --output /workspace/ghidra-rust-port/program-headers/review/results/adversarial-NEW
```

Each output directory must be new. The check runner builds only this component,
checks pinned original-source hashes, runs six unit tests in both debug and
optimized release, then compares real Java and Rust table results. The independent
review uses separately generated inputs and a Python `struct` decoder for strict
table bounds and field expectations.

- [Core run](results/check-01/summary.json): 228 exact Java parity cases and four
  separately checked safety differences across 232 inputs.
- [Independent run](review/results/adversarial-01/summary.json): 366 exact Java
  parity cases, four separately checked safety differences and 370 strict-policy
  expectations across 370 independently generated inputs.
- Both suites check acceptance, warnings and all normalized record fields. The
  independent model also verifies zero-fill counts. Cases include complete
  4096-entry iteration, extended counts, signed and zero strides, truncation at
  each record byte, high-bit values and wrapping legacy offset sums.
- The four differences in each suite are final 64-bit reads near
  `Long.MAX_VALUE`: Java accepts zero-filled reads whose last byte crosses that
  boundary; Rust rejects them as `RecordOffsetOverflow`. These are tested
  exceptions, not parity successes. Broader inherited header-overflow differences
  remain documented in the parent component.
- The CLI parses the host `ls` and `cat`; a mixed valid/missing-file batch keeps
  valid JSON and returns failure. Unknown options return 2.

The [compiled-code review](lower-level/README.md) exports three exact release
function extents through original Ghidra, with no automatic whole-program analysis.
All three selected exports complete without timeout or truncation. Five gaps in
the parser listing are alignment NOPs; the other two extents have full instruction
coverage. Default inferred Rust prototypes remain unverified. This is bounded
inspection of actual machine code, not proof of recovered C types or execution cost.

## Performance evidence

The [fixed benchmark](bench/README.md) consumes all shared header and program-table
fields over 23 preloaded inputs. Each arm runs three separate processes, with
ten seconds of warmup and five samples of at least 500 ms per process, serially
on the same CPU. All per-input and timed checksums pass. File I/O, JSON output,
full ELF loading and later Ghidra work are outside the measured intervals.

| Implementation | Median ns/header + table | Range of process medians |
|---|---:|---:|
| Original Java | 5,970 | 2,258–8,635 |
| Rust portable release | 3,678 | 1,769–36,177 |

The ratio of process medians is 1.62× Java/Rust, but dispersion is substantial:
the first Rust process loses badly, and its slowest sample is 241,343 ns/table.
This single fixed run does **not** establish stable acceleration. Every sample
and process is retained; no favorable timing rerun was selected. The cause of
the variation remains unresolved. Neither native CPU flags nor LTO were tested
for this component.

Original Java creates reusable loader objects and arrays; Rust returns a borrowed
view whose complete iteration is included in the benchmark. Java's cached private
method/field access bridge also remains in its timed boundary. These costs are
not isolated as language effects. This standalone parser is not integrated into
Ghidra, so these results do not establish whole-Ghidra or loader acceleration.

[Raw results](bench/results/fixed-01/results.json) include all six process medians,
30 samples, toolchain versions, source/input/artifact hashes and memory readings.
Memory readings are retained as whole-process observations, not reliable true
peaks or parser allocation counts. The [receipt auditor](bench/audit.py) rechecks
the frozen work and artifacts without retiming.

## Retained artifacts

[Final review](results/final-review-01.json) confirms the original checkout,
installed engine and checked prior header artifacts remain unchanged. The
external archive `../artifacts/program-headers-final-01.tar` preserves this
component's sources, compiled CLI, both benchmark builds, Java classes, raw
receipts and selected-function Ghidra project, together with the parent Rust
dependency sources. Its adjacent `.tar.json` manifest records file and archive
hashes. Future checks and benchmarks must use new result directories so these
receipts remain available.
