# Lower-level review of the measured parser and Ghidra itself

We recovered the symbols and examined the actual compiled artifacts, rather than
substituting new diagnostic Rust builds. This directory contains Java bytecode,
captured HotSpot C2 machine code, ELF symbols, x86 listings, raw instruction
p-code, and Ghidra's selected C output. The original Ghidra checkout and Rust
parser implementation remain unchanged. No new performance result is claimed.

## What the comparison establishes

| Question | Evidence and consequence |
|---|---|
| Does Rust avoid per-field object construction? | Its successful parser paths load fields directly from borrowed bytes. Separate LE/BE decoders remove repeated dynamic endian dispatch. No heap allocation call is present in the inspected successful parser graph. |
| Does Java still execute its literal source read chain? | No. C2 eliminated ten temporary byte-array allocation sites, devirtualized provider reads under guards, and used array intrinsics. Source-level `new` and interface calls overstate the surviving work. |
| What Java work remains? | The captured constructor retains reader/provider-wrapper and loader-state construction, buffers, guards, GC machinery and some uninlined helpers. Its reusable loader-object contract is broader than Rust's header-data API. The earlier 5.6x header benchmark does not isolate a language-only effect or whole-Ghidra speed. |
| What can still improve in Rust? | The existing release and LTO code clears a 64-byte recovery buffer before deciding whether a complete header can be decoded directly. Section-zero recovery has a similar pattern. Move initialization into the truncated branch as a small candidate experiment, then verify parity and measure it. Some tail bounds checks also survive; keep safety and measure changes rather than removing checks speculatively. |
| Does maximum optimization guarantee faster code? | No. LTO merges helpers and specializes away strict mode for this compatible-only benchmark. Native flags change instructions, including byte-swap lowering. Neither observation establishes a timing advantage; the retained warmed benchmark favors portable release. |
| Are the profiled debug runtime functions slower because they contain more code? | Four expensive runtime symbols have matching normalized assembly; the reviewed Unit/Cache pairs also have matching relative function-body ranges. References and callback traffic differ. The debug analysis was capped, and referenced data is not proven equal, so these are not controlled equal-work timing comparisons. |
| Can Ghidra inspect its own native engine? | Yes. The retained native engine has C++ symbols, and selected `Action::perform` and `ActionPool::processOp` have been decompiled and checked against source. It lacks DWARF types/lines; source supplies those details. Java portions require bytecode or JIT capture rather than treating a JAR as a native executable. |

The retained `Unit::new` pair exposes a concrete metadata issue: debug has an
imported `void(void)` signature and warns that parameter storage is locked with
an unknown calling convention; release has a default uninferred signature and
recovers parameters. Both warn about unsettled type propagation and fail to
recover the same relative computed jump. The subsequent
[controlled experiment](/workspace/ghidra-profiler/NEXT-OPTIMIZATION.md) tested
signature-source unlocking and verified flow destinations independently on the
same saved program state. Unlocking removed the unsupported storage lock;
the flow override recovered the four cases. Neither establishes a verified
Rust ABI or a speed improvement. These post-analysis exports cannot reconstruct
the original request state exactly.

For overall decompiler latency, add **action-level native CPU profiling** before
choosing a Rust port of a native pass. The existing
corpus measured much more native-command CPU than Java callback CPU during
decompilation. `Action::perform` dispatches the virtual `apply(data)` call and
handles repeated execution; this is a concrete timing boundary. Nested actions
need both inclusive and exclusive CPU accounting. Only add per-rule timing around
`Rule::applyOp` if the action pool dominates. Keep diagnostic output off the
decompiler protocol stream. The symbols and source locations are already known.
That boundary now has a [validated opt-in implementation](/workspace/ghidra-profiler/native-actions/README.md).
The [follow-up measurements](/workspace/ghidra-profiler/NEXT-OPTIMIZATION.md)
rank SSA/heritage first on the chosen function and include an isolated,
instruction-tested TZCNT lowering candidate that recovers the missed switch.

For Java autoanalysis, the separate profile still supports a bounded in-memory
value-flow snapshot experiment with batched database access. Header-parser
nanoseconds do not rank that work or the native passes.

## Read the evidence

- [Rust source/assembly/C review](rust/README.md), [exact artifact symbols](rust/symbols.json),
  and [C reconstruction audit](rust/decompilation-review.json).
- [Java bytecode, C2 compiler decisions and field-layout review](java/README.md),
  [JIT code addresses and hashes](java/methods.json), and
  [named call-site mapping](java/constructor-decisions.json).
- [Native engine and matched runtime symbol review](/workspace/ghidra-profiler/symbol-review/README.md)
  and [retained-state comparison](/workspace/ghidra-profiler/symbol-review/RETAINED-METADATA.md).
- [Export summary](summary.json): per-function statuses, compiler specification,
  warnings, instruction coverage and body metadata. Each `exports/JOB` includes
  `selected.json`, combined `decompiled.c`, per-function C, instruction listings,
  raw p-code, specs, launch log and invocation record.

All 15 selected entries produced C across eight jobs, with no export cancellation
or decompilation timeout. Some requested bytes remain undisassembled in the saved
listings, particularly around computed flow and JVM cold paths; `summary.json`
records every gap. The full captured bytes and independent objdump disassembly
remain available. C warnings and missing external JVM targets remain explicit.

New imports use ELF symbol extents as explicit function bodies. Retained profiler
projects are opened read-only and preserve their original bodies; no global
autoanalysis runs. `exports-baseline` retains the first Rust exports, where ELF
loader-created function bodies were one-byte stubs. Their bounded instruction
listings cover the symbol extents; later exports correct that function metadata.

## How to interpret the C output

The instruction bytes, original source and compiler evidence are the checks on
pseudocode. A successful C export only means Ghidra produced C for the selected
entry. It does not imply correct inferred types, signatures, all external code
being present, or a whole-program result.

Rust's internal ABI passes a hidden result pointer and uses niche encoding.
Missing prototypes can invent extra arguments or drop real arguments to calls.
SIMD stores expand into unwieldy concatenations. Unknown no-return panic helpers
can cause C flow to continue into unrelated adjacent code even with a bounded
function body. The exported instruction listings and raw p-code remain limited
to the requested extent; C flow can extend beyond it. Max's type-propagation
warning is preserved rather than treated as valid recovered Rust types.

The raw JVM imports use Ghidra's default `windows` compiler specification, which
does not model the HotSpot Java ABI. For the constructor, RSI is `this`, RDX the
provider and RCX the consumer; R15 holds thread state. The captured layout maps
field offsets and compressed references. There is no JVM heap snapshot or code
for external runtime stubs. Uncommon-trap exits are misrepresented as continuing
calls or loops; missing tail targets produce explicit control-flow warnings.
These C files are a review aid, not recovered Java source or executable C.

## Reproduce selected exports

```sh
python3 /workspace/ghidra-rust-port/lower-level/export.py
python3 /workspace/ghidra-rust-port/lower-level/summarize.py
```

Exports run serially, use the prepared headless launcher, check measured input
hashes and cap each decompilation at 45 seconds. Existing results are skipped;
`--select rust-release rust-max --rerun` explicitly replaces those exports.
Diagnostic export times are not benchmark samples. Do not run this workload
alongside `bench/run.py`.

`tools/SelectedExport.java` also accepts a bounded JSON spec directly through
`ghidra-agent headless ... -noanalysis -postScript SelectedExport.java SPECS OUT 45`.
Use `image_offset_hex` for ELF VMA relative to the imported image base, or
`address_hex` for an absolute retained/JIT address. Set
`set_body_to_requested_extent:true` only for a new import whose symbol extents
are trusted. Omit it when preserving an existing analyzed project.
