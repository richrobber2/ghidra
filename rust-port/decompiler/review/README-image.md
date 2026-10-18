# Read-only image memory and pointer-result gate

This suite is a fixed correctness/coverage gate, not a performance comparison.
It never compares unrelated numeric addresses from separately loaded libraries.
The CLI must explicitly emit `--return pointer` C before returned image bytes
are observed; `--return u64` must reject or guard image pointers.

```bash
python3 /workspace/ghidra-rust-port/decompiler/review/image_validation.py \
  --cli /workspace/ghidra-rust-port/decompiler/rust-ghidra \
  --output /workspace/ghidra-rust-port/decompiler/results/image-NEW
```

Run only with the root agent's serial heavy-work slot. The runner refuses an
existing directory and snapshots its sources, CLI, installed zlib input and
historical 88-body coverage map. All commands, timeouts, mismatches, static
unsupported results and runtime guards are retained. No earlier results change.

The predeclared C fixture has ten positive functions at GCC `-O0`, `-O2` and
`-O3`: indexed unsigned 8/16/32/64-bit loads, paired reads, a bounded byte loop,
base/offset/full-width-spilled pointer returns, and same-object subtraction of
spilled pointers. Fixed compiler flags disable vectorization and runtime support
calls. Local static constants avoid dynamic GOT relocations. The independent
expectations are literal bytes/integers and wrapping arithmetic in Python;
native functions and reconstructed C must each match those expectations.
Boundary/random inputs from the existing numeric suite are augmented with all
32 byte-table indices and all 16-by-16 pointer-difference orderings.

Six guard cases per build cover a writable global read, a read-only image write,
an external integer-derived pointer read, an image pointer returned under the
numeric result model, a partial-width pointer spill, and a very large out-of-
bounds image offset. These original functions are never executed. A static
`unsupported` result with no C artifact, or generated C aborting with `SIGABRT`,
is accepted; a segmentation fault, arbitrary failure or successful numeric
pointer leakage fails the gate.

Real zlib 1.3.1 pointer targets are `zlibVersion` (six bytes including the NUL)
and `get_crc_table` (64 bytes). Each is compared to native library content and
independent expectations: the frozen library version and the first sixteen
reflected IEEE CRC32 table entries generated from polynomial `0xedb88320`.
Both also have mandatory numeric-result guards.

Separate numeric and pointer batch runs must preserve all 88 historical input
function address/size/file-offset triples, with no truncation. Their artifact
counts and distinct union are reported separately from the two pointer
functions with execution validation. The suite does not infer arbitrary ABI or
whole-library support from guarded artifact generation.

Initial `results/image-memory-01` is retained as a failed fixture setup. Its
top-level assembly left the current section at `.note.GNU-stack`; GCC `-O2` and
`-O3` consequently emitted the following C functions there, without executable
or allocated flags. The loader correctly rejected the whole malformed input.
The fixture now restores `.text` after the note. The same ten functions and all
input expectations remain fixed; use a new result directory after that fix.

`results/image-memory-02` retains the corrected fixture and a genuine coverage
failure: 31 positives and all 20 guards pass, while the GCC `-O2` byte loop aborts
because its same-object pointer comparison leaves the equality flag unknown.
The positive remains required; no input or supported case is removed.

Accepted `results/image-memory-03/results.json` passes all 32 positive
function/build cases with 1,035 inputs each in both native and reconstructed
arms. All 20 guards pass: eleven static unsupported results and nine generated
`SIGABRT` results. The 52 cases retain 172 command records and 41 compiled
generated artifacts, including guard artifacts. The frozen candidate SHA-256 is
`bd86a9af949b1c17231291cf5a856643afc3c99f2dbe06c11b9e8c3c432053fe`.

The unchanged 88-function zlib body map yields five guarded numeric artifacts
and two explicit-pointer artifacts, seven distinct bodies total. The two
pointer functions pass the content checks above. These counts do not turn the
other emitted functions into execution-validated library coverage. Both batch
runs retain explicit partial statuses and every unsupported body.
