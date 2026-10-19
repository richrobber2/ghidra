# Ghidra ELF → Rust: header parser and porting map

Source checkout: `/workspace/ghidra`, commit
`9a723ce99952771b8368329503aa589ae233e916`.

The first Rust component implements ELF file-header decoding and extended counts,
with a JSON CLI and an executable reference using Ghidra's original Java class.
The performance goal is faster equivalent parsing while retaining compatibility.
The original Ghidra checkout is unchanged; loading, analysis, decompilation and UI
remain outside this component.

The next slice is now implemented separately: the
[Rust program-header table parser](program-headers/README.md). It adds checked
segment-table iteration and a ready-to-run JSON CLI, with original-Java
differential tests and explicit strict/compatibility policies. Its build and
measurement artifacts are isolated from this first component.

The third slice is the [Rust section-header table parser](section-headers/README.md).
It decodes section records, resolves section names the way Ghidra does (including
its UTF-8 replacement rules) and reproduces the compressed-section header probe,
with original-Java differential tests over synthetic fixtures and real system
binaries.

The fourth slice, the [Rust string- and symbol-table parser](symbol-tables/README.md),
decodes section-based `.symtab`/`.dynsym` tables with Ghidra's name lookup,
warnings and extended section indices. Tables reachable only through the dynamic
table are left for the dynamic-table slice. The decompiler now reads its section
table through the section-header parser.

A [standalone Rust decompiler prototype](decompiler/README.md) now uses these
components to discover x86-64 ELF functions, lift scalar instructions/control
flow and emit guarded executable C without Java or the original native engine.
It now supports bounded read-only image loads and explicit pointer results;
seven real zlib functions have finite execution checks. Its leaf-function, ABI
and memory limits remain explicit; broader Ghidra parity is unfinished. Independent source, instruction-edge, optimized Rust, real-zlib and
original-Ghidra instruction comparisons are retained in its own directory.

## Build and use

```bash
cd /workspace/ghidra-rust-port
source /workspace/rust-optimization/activate.sh
cargo build --release --offline --locked --bin ghidra-elf
target/release/ghidra-elf --compatible /bin/ls
target/release/ghidra-elf --strict /bin/ls
```

The CLI defaults to strict **header** validation, emits a JSON array, and exits 1
if any file fails (2 for argument errors). Use `--` before paths beginning with `-`.
It reads each whole input file; the library itself borrows `&[u8]` and performs no
heap allocation or iteration over untrusted table counts. The crate forbids unsafe
Rust and has no third-party dependencies. Raw fields and recovery diagnostics remain
available alongside normalized values.

Strict mode checks header versions, encoding, required record sizes, count/index
relationships, and section-zero bounds when needed. It does **not** validate whole
table extents or contents: a normal program/section-table offset beyond EOF can
remain accepted until a future table parser uses it. Strict mode also supports
unsigned 32-bit extended counts; compatibility mode applies Java's signed-int cap.

```bash
python3 check.py
python3 review/differential.py --rust target/release/ghidra-elf
python3 review/safety_edges.py --rust target/release/ghidra-elf
python3 bench/run.py
```

`check.py` checks pinned source hashes, refreshes the Java oracle, runs Rust unit
tests and compares the original 30 cases. The independent review adds bounded,
deterministic cases. [Benchmark methodology](bench/README.md) describes CPU pinning,
JVM warmup, checksum verification and release/max/native build comparisons.
Benchmark results describe header decoding only, not complete ELF loading speed.

[Lower-level review](lower-level/README.md) compares the exact measured Rust
artifacts with the Java parser's bytecode and captured C2 code, and includes
selected decompilations of both plus Ghidra's native action dispatch. It records
available symbols, remaining work and limits of inferred C types and JVM flow.

## Verified correctness

- 30 original Java/Rust baseline cases pass.
- 1,047 independent differential cases match acceptance, normalized fields, and
  Java warning arrays. See [the review](review/README.md).
- Eight Rust unit tests pass in debug and optimized release builds.
- Eight separate overflow-boundary probes pass their explicit expectations. They
  record **three intentional differences**: Rust rejects offset arithmetic overflow
  where Java accepts after signed addition wraps. These are documented exceptions,
  not claimed parity cases.
- The strict CLI successfully parsed `/bin/ls`; a mixed batch containing a missing
  file retained valid JSON and returned a failure exit status.

The deterministic corpus is bounded testing, not exhaustive fuzzing. Compression
probe messages sent through Ghidra's global logger are recorded by the review but
are outside the CLI's normalized header/warning contract.

## Measured performance

On this environment's Intel Xeon Platinum 8573C, using Java 25.0.4.1 and Rust
1.99.1, the portable Rust release build measured **5.6× faster** than the original
Java constructor for the benchmark's equivalent header work. This measures parsing
and a field digest over preloaded inputs; it excludes file I/O and later analysis.

| Implementation | Median ns/header | Process-median range | Java time / implementation time |
|---|---:|---:|---:|
| Original Java | 322.6 | 308.4–453.8 | 1.0× |
| Rust release | 57.4 | 48.9–59.3 | 5.6× |
| Rust max: fat LTO, one codegen unit | 62.1 | 61.0–261.5 | 5.2× |
| Rust max plus native CPU | 147.7 | 61.6–271.8 | 2.2× |

Each variant ran in three separate processes on the same pinned CPU, with a
10-second warmup and five samples of at least 500 ms per process. Reported medians
are medians of process medians. All twelve inputs produced matching field digests.
The max/native variants had substantial variation whose cause was not isolated;
these results do not establish an advantage from CPU-specific flags or LTO. Use
the portable release build as the current default.

Median whole-process peak memory was about 84.6 MiB for Java and 9.0 MiB for Rust
release, including runtimes and preloaded files. This is not a parser allocation
count. Startup measurements and every raw sample are retained in
[bench/results.json](bench/results.json); details are in [bench/README.md](bench/README.md).
The initial 1.5-second-warmup run is preserved separately because Java was still
speeding up during measurement; its larger speedup estimate is not used here.

## First component: ELF file-header decoding

The Rust parser implements the behavior of `new ElfHeader(provider, diagnostics)` before its `parse()`
method runs. This reads the identification bytes, file header, and (when needed)
section header zero for extended numbering. It does not create a Ghidra `Program`,
map memory, apply relocations, resolve dynamic dependencies, or start analysis.

This boundary is backed by a runnable oracle: `oracle/ElfHeaderOracle.java` constructs
the real Ghidra class directly and emits normalized JSON. It runs without a GUI or
Ghidra project. `oracle/run.py` builds its classpath from existing module jars and
`build/libraryDependencies.txt`.

```bash
cd /workspace/ghidra-rust-port
python3 oracle/run.py
```

Verified: **30 source-guided synthetic fixtures** exercised against the original
constructor. The four canonical ELF32/64 × little/big-endian fixtures were also
accepted by `readelf -h`; its outputs are retained. The Java expectations, not the
fixture generator alone, define the compatibility baseline.

## Source map and dependency boundaries

Paths below are relative to `/workspace/ghidra`. The JSON inventory in
`source-map.json` records file hashes, line counts, and explicit imports at the
recorded commit. It is not a complete transitive dependency graph.

| Layer | Source anchors | Porting decision |
|---|---|---|
| Byte access | `Ghidra/Features/Base/src/main/java/ghidra/app/util/bin/BinaryReader.java:120`, `ByteProvider.java`, `UnlimitedByteProviderWrapper.java` | Replace with a checked Rust slice reader; emulate zero-fill only in explicit compatibility mode. |
| Header constructor | `Ghidra/Features/Base/src/main/java/ghidra/app/util/bin/format/elf/ElfHeader.java:105` | First port. Preserve raw fields separately from interpreted values and diagnostics. |
| Extended counts | `ElfHeader.java:208`, `:225`, `:241`, `:257` in the same package | Include a minimal section-zero decoder; do not port the entire section subsystem first. |
| Endianness recovery | `ElfHeader.java:1365` | Track declared byte order and actual header-decoding byte order separately. |
| Parse orchestration | `ElfHeader.java:290` | Later: program headers → sections → dynamic table → strings → library names → symbols → relocations. |
| Program headers | `ElfProgramHeader.java:90`, `ElfHeader.java:1149` | Second slice; distinguish raw offsets from adjusted loader values. |
| Section headers | `ElfSectionHeader.java:99`, `ElfHeader.java:1111` | Third slice, implemented in `section-headers/`: records, names and the compression-header probe; no decompression. |
| String tables | `ElfStringTable.java:56` | Implemented in `symbol-tables/` with Java's UTF-8 decoding and `trim()`. |
| Symbols | `ElfSymbol.java:137`, `ElfSymbolTable.java:62`, `ElfHeader.java:850` | Fourth slice, implemented in `symbol-tables/` for section-based tables; dynamic-table fallback deferred. |
| Dynamic metadata | `ElfHeader.java:692`, `:926`, `:1016` | Defer initially. Sectionless dynamic-symbol discovery needs segment/address translation and hash-table logic. |
| Format detection/loading | `Ghidra/Features/Base/src/main/java/ghidra/app/util/opinion/ElfLoader.java:116`, `:162` | Keep Java loader integration outside the first parser. |
| Program construction | `Ghidra/Features/Base/src/main/java/ghidra/app/util/opinion/ElfProgramBuilder.java` | Defer: depends on Program, memory, symbols, data types and monitor/log infrastructure. |
| Architecture adjustments | `.../format/elf/extend/ElfLoadAdapter.java`, `ElfExtensionFactory.java` | Defer adapters, adjusted addresses, architecture hooks and loading decisions. |
| Relocations | `.../format/elf/relocation/` and `Ghidra/Processors/*/.../elf/relocation/` | Separate later project; not merely another header table. |

`StructConverter` and `toDataType()` belong to Ghidra's data-type presentation layer;
the Rust decoding library should not reproduce them. Java constructors still have
class dependencies on that layer, but the standalone oracle demonstrates that the
header operation does not need a populated Program or running service.

## Compatibility specification from inspected source and executed fixtures

| Input / behavior | Observed Ghidra constructor result | Rust policy |
|---|---|---|
| ELF32/64, either byte order | Accepted; expected field values | Match in both modes. |
| Wrong magic / unsupported EI_CLASS | Rejected | Reject with stable error categories. |
| Length below 34 bytes | Rejected | Reject; strict mode also requires the full 52/64-byte header. |
| Valid initial bytes, total length 34–63 for ELF64 | Accepted; missing later fields zero-filled | Match in compatibility mode with an explicit truncation diagnostic; reject in strict mode. |
| Invalid EI_DATA | Logs a diagnostic and decodes headers as little-endian | Compatibility fallback; strict rejection. Preserve the original byte. |
| EI_DATA says big-endian, e_type's first byte is nonzero and e_version's first byte is 1 | Decodes the header as little-endian, while declared-endian accessors still reflect EI_DATA | Preserve this distinction; strict mode uses the declared encoding and validates independently. |
| Zero version fields | Accepted by this constructor | Compatibility accepts; strict validation is an intentional difference. |
| e_ehsize=0 / noncanonical entry sizes | Preserved; constructor does not validate them | Compatibility preserves; strict mode validates the sizes needed for the requested operation. |
| ELF32 values with high bit set | Unsigned values widened into Java long | Represent as u32/u64; never sign-extend addresses. |
| ELF64 high-bit addresses/offsets | Bit patterns survive signed Java long storage | Preserve as u64 and render losslessly in JSON. Validate only when using an offset. |
| e_phnum=0xffff | Read count from section-zero sh_info | Decode this indirection. |
| e_shnum=0 or ≥0xff00 | Read count from section-zero sh_size | Match Ghidra's reserved-range behavior in compatibility mode. |
| e_shstrndx=0xffff | Read section-zero sh_link when sections exist | Code uses sh_link despite a misleading nearby comment mentioning sh_size. |
| Missing section zero / extended values beyond signed-int range | Counts or index resolve to zero | Capture recovery diagnostics; don't allocate from untrusted counts. |
| No resolved sections | Section-name string-table index forced to zero | Preserve raw index as well as the normalized result. |
| Positive section offset plus signed entry size overflows Java long | May reject or accept a zero-filled record depending on later pointer arithmetic | Reject with OffsetOverflow; explicit compatibility exception. |

See `results/java-header-baseline.json` for exact observed values and messages.
The oracle normalizes signed Java small integers to unsigned values and serializes
64-bit offsets/addresses as hexadecimal strings. It does **not** call `parse()` and
therefore does not validate the table bodies described by a header.

Additional source observations need their own fixtures before later slices claim
compatibility:

- `parseProgramHeaders` and `parseSectionHeaders` allocate arrays from resolved
  counts, warn on missing records, and read through the zero-filling wrapper.
- Program-header parsing has a historical offset-rewriting heuristic when summed
  segment file sizes equal file length. Its comment explicitly requests a sample
  proving the need; do not treat it as an ordinary ELF rule.
- String-table reads use UTF-8 conversion followed by Java `trim()`. The start
  offset is checked against table length; termination behavior also depends on the
  binary reader. Raw-byte preservation avoids silently losing whitespace or invalid
  UTF-8 during the first Rust decoding layer.
- Section constructors may inspect compressed-section headers. Keep basic record
  decoding separate from decompression and Ghidra data-type conversion.
- Symbol names are initialized after record decoding. Section symbols with no
  explicit name can inherit a section name. Extended symbol section indices and
  sectionless dynamic tables require additional handling.

## Rust API and layout

```text
Cargo.toml            ghidra-elf crate; release and max profiles
src/lib.rs            checked reads, header/section-zero decoding, policies, tests
src/main.rs           JSON CLI
oracle/               original Java constructor and the first 30 fixtures
check.py              build/unit-test/original-baseline check
review/               independent expanded differential checks
bench/                Java/Rust benchmark adapters and orchestration
```

```rust
pub enum ParsePolicy { Strict, GhidraCompatible }
pub fn parse_header(bytes: &[u8], policy: ParsePolicy)
    -> Result<ParsedHeader, ParseError>;
```

`ParsedHeader` contains raw identification bytes, class, declared encoding,
effective header encoding, raw header fields, resolved counts/index, and diagnostics.
Errors such as BadMagic, UnsupportedClass, TruncatedHeader, InvalidEncoding and
OffsetOverflow are distinct. Unknown machine/OSABI values remain numeric rather
than making the parser architecture-specific. Recovery diagnostics use a bitset;
Java's EI_DATA warning text is also preserved by the CLI.

The standalone CLI defaults to strict parsing and exposes compatibility as an
explicit option. A future Ghidra replacement path would use compatibility mode.
This is not a claim of complete ELF validation.
Compatibility does not require reproducing integer overflow, unbounded allocation,
or out-of-bounds access. Such differences must be documented and tested.

## Existing tests and the coverage gap

The inspected `Ghidra/**/*Test.java` search for `ElfHeader`, `ElfProgramHeader`,
`ElfSectionHeader`, `ElfSymbolTable`, and `ElfLoader` found no direct references.
This does not establish that Ghidra has no indirect ELF coverage or external corpora.

Reusable low-level cases are present in:

- `Ghidra/Features/Base/src/test/java/ghidra/app/util/bin/BinaryReaderTest.java`:
  unsigned reads, endian handling, oversized reads, EOF/string cases and bad UTF-8.
- `FileByteProviderTest.java`: file-backed byte access.
- `RangeMappedByteProviderTest.java`: sparse ranges and misaligned multibyte reads,
  useful later when mapping segments.

Those Ghidra suites were inspected, not rerun during this component port. The new
Java/Rust checks run independently of the full Ghidra test suite; reports retain
accepted fields, rejected cases and diagnostic differences.

## Implementation status and next increments

1. Completed: checked header/section-zero decoding without third-party dependencies;
   Apache-2.0 license and source attribution retained in LICENSE and NOTICE.
2. Completed: compatibility mode, original and expanded differential checks, raw
   fields and recovery diagnostics. Java exception prose is not a Rust API promise.
3. Completed: strict header checks, overflow rejection and deterministic truncation/
   mutation tests. Sustained coverage-guided fuzzing remains future work.
4. Next: program/section tables, then names and symbols. Extend both Java oracle and
   corpus at each boundary; compare canonical files with `readelf` as a second reference.
5. Only then connect the JSON CLI to Ghidra experimentally. Keep direct Java parsing
   available for differential checks and fallback while compatibility matures.

The first implementation milestone ends at header compatibility, strict-mode tests
and a scoped Java/Rust performance comparison.
Relocation processing, compressed contents, dynamic hash walking, symbol versioning,
memory mapping, UI and JNI are outside it. Benchmark after correctness; maximum Rust
optimization settings are not evidence of a successful port.

Whole-workflow profiling now lives in `/workspace/ghidra-profiler`. See its
`OBSERVATIONS.md` for measured phases on real ELF inputs and `FINDINGS.md` for
the next performance priorities. The proposed next Rust performance experiment
is an in-memory value-flow kernel with a measured database boundary; the header
port remains a separate completed component.
