# Standalone Rust decompiler

This is a native Rust ELF loader, x86-64 instruction lifter, reachable control-flow
graph and executable C emitter. It runs without Java, the Ghidra native engine or
external disassemblers. The decoder is the pinned pure Rust `iced-x86` dependency;
the ELF loader builds on the two existing Rust ELF components. It is an early
working subset, not a complete Ghidra replica.

The goal is a better standalone Rust decompiler, with freedom to choose a
different architecture and output. [Goals and acceptance criteria](GOALS.md)
prioritize useful coverage, readable code, preserved behavior and measured
efficiency; matching Ghidra's internal design or C text is not required.

```bash
/workspace/ghidra-rust-port/decompiler/build.sh
/workspace/ghidra-rust-port/decompiler/rust-ghidra functions /path/to/binary
/workspace/ghidra-rust-port/decompiler/rust-ghidra decompile /path/to/binary \
  --function function_name --output /workspace/new-function-result
/workspace/ghidra-rust-port/decompiler/rust-ghidra analyze /path/to/binary \
  --max-functions 100 --output /workspace/new-binary-result
```

For a read-only pointer result, choose its result model explicitly:

```bash
/workspace/ghidra-rust-port/decompiler/rust-ghidra decompile \
  /usr/lib/x86_64-linux-gnu/libz.so.1.3.1 --function zlibVersion \
  --return pointer --output /workspace/new-zlib-version
```

`--return u64` is the default. `--return u8`, `u16` and `u32` model narrower
integer results: SysV defines only those low bits of RAX, so only they must be
known, and the generated `uint64_t` result is their zero extension. Use `u8`
for `bool`/`char` results computed with `SETcc`, which leave the rest of RAX
undefined and therefore always abort under `u64`. `--return pointer` emits a
`const unsigned char *` result into immutable static image data. `analyze`
accepts one result model for the whole batch; it does not infer each
function's prototype, so a `u64` batch can report a narrow-result function as
decompiled even though its guards abort at run time.

Every output directory must be new. The built command runs without activation;
the build script uses this component's target directory and cached, locked
dependencies. It never replaces prior ELF-parser builds or installed Ghidra.
To prepare dependencies on a machine without the retained Cargo cache, activate
the existing Rust toolchain and run `cargo fetch --locked --manifest-path
/workspace/ghidra-rust-port/decompiler/Cargo.toml` before the offline build.

`functions` inventories defined ELF function symbols, preserving aliases and
zero-size entries. `decompile` emits `manifest.json`, `ir.json` and `decompiled.c`.
For a stripped binary use `--address 0xVMA --size N` instead of a name; the tool
requires an explicit extent and does not guess function boundaries. `analyze`
attempts symbol-discovered function extents and writes combined C plus per-function
outcomes in its manifest. It deduplicates identical address/size aliases. Partial
coverage or a function limit returns 1 and stays visible as `status:partial` and
`truncated`; success is 0 and argument/output-directory errors return 2.

## Implemented behavior

| Layer | Current coverage |
|---|---|
| Input | ELF64, little-endian x86-64, ET_EXEC/ET_DYN; strict program/section bounds, SYMTAB/DYNSYM, extended indices, executable file-backed mappings |
| Instructions | Scalar integer moves/extensions, LEA arithmetic, add/ADC/sub/SBB, logical operations, IMUL, shifts/rotates, INC/DEC/NEG/NOT, compare/test, Jcc/JMP, CMOV/SETcc, push/pop/leave/return, alignment NOPs |
| State | 8/16/32/64-bit aliases including AH; 32-bit zero extension; modeled CF/PF/ZF/SF/OF and undefined-flag guards; bounded stack locals and saved registers |
| Memory | Validated file-backed read-only PT_LOAD objects, RIP-relative addresses/loads, indexed integer loads, full-width pointer spills, same-object subtraction and explicit pointer results |
| Control flow | Reachable direct branches, loops, byte-ownership overlap checks, explicit labels in generated C |
| Output | Guarded machine-level GNU C11 using `uint64_t` and `__int128`; no inline assembly or calls back into the original engine |

An unsupported reachable instruction rejects the whole function and produces no
C for it. Calls, writable/global state, external pointer arguments, indirect branches,
SIMD/floating point, atomics, exceptions, other ABIs/architectures, relocated data,
DWARF recovery and structured variable/type/loop reconstruction remain outside
this version. It does not implement Ghidra's SSA/p-code optimization pipeline or
GUI. These are explicit remaining parity gaps, not silently substituted features.

## Meaning of guarded C

Each generated function takes six `uint64_t` SysV integer arguments. Its explicit
result model returns the 64-bit RAX bit pattern or a read-only image pointer.
This is an explicit input/output model, not a recovered source prototype. Unknown entry registers and flags remain unknown. Generated C
tracks known bits, stack-pointer provenance and image-object identity, and aborts
if execution observes undefined state, uses unsupported memory, leaks a synthetic stack address or
changes the modeled return/caller stack slot. It does not invent a numeric pointer
to make a function return a plausible value.

Read-only objects contain the file-backed bytes of nonwritable readable load
segments, using a conservative x86-64 4096-byte mapping-page contract. Page aliases,
relocation writes and loader bookkeeping exclude entire intersecting objects.
Dynamic REL/RELA metadata must be bounded, file-mapped and covered by validated
allocated relocation sections. Packed/RELR, COPY, unknown relocation formats or
dynamic tags make the image model unavailable; scalar functions still work.

A raw numeric VMA never becomes a pointer. Image pointers retain an object ID and
offset; loads require the entire access inside that object, stores stay stack
only, and partial pointer spills/bitwise operations remain guarded. Pointer
arithmetic leaves flags unknown; same-object pointer CMP establishes equality
(ZF) only. These bounds apply to load-segment objects,
not recovered source arrays. Typed results have static lifetime and support
contents/within-object-offset comparisons; cross-function pointer identity is not
preserved because each emitted function embeds its own objects.

The modeled stack is 8192 bytes with entry alignment of 16 bytes. It supports
ordinary leaf frames, spills and red-zone locals; deeper frames are unsupported.
Pointer arithmetic invalidates modeled flags rather than deriving them from an
invented stack location. The C output deliberately keeps machine state and labels
visible; it is executable low-level reconstruction, not polished source code.
`status:ok` means a guarded artifact was produced, not proof that arbitrary inputs
or unsupported calling conventions satisfy its guards.

Input is capped at 128 MiB, program headers at 4096, sections at 65536, symbols at
one million and total retained symbol-name bytes at 16 MiB, with a 16,777,216
declared-symbol × PT_LOAD mapping-work budget. Function decoding is bounded to
1 MiB/65536 reachable instructions; C output is bounded to 32 MiB per
function and 64 MiB for a batch. Batch attempts are capped at 1000 functions.
Image modeling additionally caps objects at 128, one object at 4 MiB, total image
bytes at 8 MiB, relocation entries at 262144 and relocation/object work at 16777216.
The manifest records the chosen return kind and embedded object VMAs/sizes.

## Verification and future ports

The independent suites compile known C/Rust/assembly inputs, decompile them with
the Rust CLI, recompile the generated C and compare original and generated
executions to separate integer formulas. Failures, unsupported cases and timeouts
remain in new result directories. Original Ghidra is a differential inspection
reference; it is not used to execute this Rust pipeline. See `review/` for the
suite drivers and semantic review. Heavy builds, executions, Ghidra imports and
audits run serially.

The next stage is call/prototype modeling, followed by SSA/data-flow optimization
and structured C recovery. Each needs an explicit
contract and differential gates before broadening claims. This first subset has
no whole-Ghidra speed claim; correctness and coverage precede a fair performance
comparison.

## Read-only memory verification

The current executable is frozen by [image-build-04](results/image-build-04/sources.json)
with 34 optimized-release unit tests. Independent execution gates:

| Suite | Result |
|---|---|
| [Image C matrix](results/image-memory-03/results.json) | 10 functions at O0/O2/O3 plus two real pointer targets: 32 positives ×1035 inputs per native/generated arm; all 20 required guards pass |
| [Assembly edges](results/image-edges-02/results.json) | Nine functions ×586 inputs per arm; all 17 guards pass, including image boundary, partial provenance and unknown CMP flags |
| [Two-object runtime](results/image-runtime-01/results.json) | 15 valid behaviors and 29 exact SIGABRT guards, including cross-object operations and full/partial spills |
| [Real CRC functions](results/image-zlib-numeric-01/results.json) | `crc32_combine64`: 361 actual-data concatenations; `crc32_combine_gen64`: 37 nonnegative lengths through 2^63−1; `crc32_combine_op`: 731 cases; native/generated results match independent polynomial/CRC expectations |

Existing suites also pass unchanged on this executable: [C regression](results/image-regression-c-01/results.json)
(42 functions/builds ×523 inputs and 18 rejects), [ISA regression](results/image-regression-isa-01/results.json)
(17×751 and seven guards), [optimized Rust](results/image-regression-rust-02/results.json)
(four×523), and [original zlib gate](results/image-regression-zlib-01/results.json)
(two×523 and scalar-mode pointer rejection). The initial Rust regression receipt
retains its missing toolchain-activation failure; the activated rerun changes no
fixture or expectation.

[Batch integration](results/image-batch-01/results.json) compiles both combined
numeric/pointer translation units and checks four real functions ×523 inputs per
arm. The absolute Rust executable decompiles an image pointer with PATH,
JAVA_HOME and GHIDRA_HOME pointing to nonexistent locations. Output reuse
preserves existing files and exits 2; a one-function limit retains the full
88-body denominator and explicit partial/truncated status.

The frozen zlib inventory still contains **88 distinct function bodies**. Default
numeric mode emits five guarded artifacts and rejects 83; explicit pointer mode
emits two and rejects 86, with no truncation. The seven distinct bodies now have
finite execution checks: `compressBound`, `zlibCompileFlags`, `crc32_combine64`,
`crc32_combine_gen64`, `crc32_combine_op`, `zlibVersion` and `get_crc_table`.
The version comparison includes its NUL terminator; the table comparison checks
its first 64 bytes against a separate CRC polynomial calculation. Large-length
CRC tests validate operators, not fabricated huge byte strings. `zlibCompileFlags`
has native-library equivalence only. These domains do not prove arbitrary input,
ABI or whole-library support.

[Review and reproduction](review/README-image.md) and the
[independent semantic review](review/image-semantics.md) explain the object,
provenance and result contracts. Initial `image-memory-01` retains a test-fixture
section-placement failure; `image-memory-02` retains the optimized pointer-loop
failure that motivated ZF-only pointer comparison. Both failures and the earlier
build/edge candidates remain archived. The final integrity audit is
[image-final-review-02](results/image-final-review-02.json). Snapshot
`../artifacts/decompiler-image-memory-01.tar` and its adjacent `.tar.json` manifest
preserve current sources, the executable, all retained results and Rust ELF
dependencies; toolchains and Cargo registry cache remain external. No performance
comparison is claimed.

## Retained scalar baseline

The original portable release is captured by `results/build-04/sources.json` and
the frozen CLI copies in each accepted suite:

| Suite | Accepted result |
|---|---|
| Rust units | 16 loader/lifter tests in optimized release |
| C compiler matrix | 42 functions/builds, 523 inputs each; original and regenerated C match independent formulas. All 18 required unsupported cases reject. |
| ISA edges | 17 functions, 751 inputs each; both execution arms match formulas. All seven unknown-state/provenance guards abort explicitly. |
| Optimized Rust | Four portable opt-level-3 `extern "C"` kernels, 523 inputs each; native Rust and regenerated C match independent formulas. This does not verify arbitrary Rust internal ABIs. |
| Installed zlib 1.3.1 | `compressBound`: formula and native comparison; `zlibCompileFlags`: native comparison only, 523 inputs each. `zlibVersion` rejects its unsupported global address. |

Accepted raw receipts: [C matrix](results/semantics-03/results.json),
[ISA edges](results/isa-03/results.json), [optimized Rust](results/rust-02/results.json),
and [real zlib](results/real-zlib-01/results.json). On the frozen full zlib symbol
inventory, batch mode emits three guarded artifacts and explicitly rejects 85
other functions, with no truncation. Only the two named positive functions have
execution validation; artifact coverage is not whole-library semantic coverage.

The initial C matrix `semantics-01` retains its single unsupported GCC alignment
NOP case. The decoder correction passes the unchanged corpus in `semantics-02`
and final `semantics-03`; earlier candidates/results stay retained. ISA and Rust
suites are rerun after candidate changes, not selected for favorable timing.
There is no benchmark or speed claim for this decompiler.

The [original Ghidra reference](reference/README.md) checks selected real input
instruction boundaries and direct control flow independently. Its C and p-code
are review aids; inferred types and C text are not an execution oracle.
The accepted [reference comparison](results/reference-02/results.json) matches six
functions and all 77 reachable instruction starts/lengths/bytes and direct-flow
edges. The first reference run retains a corrected harness error caused by Gson
omitting null fallthrough fields; no engine error was hidden. The selected C loop
has 13 unreachable padding bytes, recorded by both decoders.

[Batch integration](results/batch-integration-01/summary.json) also compiles the
combined real-library C and executes its two validated functions. The Rust CLI
successfully decompiles `compressBound` with PATH, JAVA_HOME and GHIDRA_HOME
pointing to nonexistent locations; it does not invoke the original toolchain at
runtime. Existing output reuse and explicit batch truncation are checked.

The [remaining port stages](PORTING-PLAN.md) describe the path toward broader
Ghidra coverage.

The [final review](results/final-review-01.json) binds the accepted executable to
all final suites and confirms original Ghidra and checked prior artifacts remain
unchanged. Archive `../artifacts/decompiler-native-first-01.tar` preserves sources,
the compiled CLI, all retained receipts (including initial failures), generated C
and selected Ghidra projects, plus the two Rust ELF dependency sources. Its
adjacent `.tar.json` manifest records file/archive hashes. Toolchains, Cargo's
registry cache and the original Ghidra installation remain external environment
dependencies; this archive is not a full machine snapshot.
