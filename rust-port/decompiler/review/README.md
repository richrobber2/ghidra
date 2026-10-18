# Independent scalar validation

`validate.py` fixes a 20-function source corpus before candidate execution. The
14 supported functions cover wrapping arithmetic, multiplication, bit logic,
masked shifts and rotates, 32-bit zero extension, signed/unsigned predicates,
conditional selection, bounded loops and stack spills. Each has six `uint64_t`
arguments and one `uint64_t` result. GCC builds the same corpus at `-O0`, `-O2`
and `-O3`; vectorization is disabled because this gate explicitly targets scalar
code. This is a scope declaration, not evidence that arbitrary compiler output
is supported.

Six assembly symbols must fail closed: a call, SIMD operation, indirect branch,
truncated instruction, direct branch outside the selected symbol and a branch
into an instruction that is also reachable by fallthrough. These symbols are never run.
A rejection must exit 1, report a failure/unsupported manifest and emit no C artifact.

Before any execution, independent review corrected the overlap fixture from an
unconditional jump (`eb 01`) to a conditional jump (`74 01`). An unconditional
jump past a skipped REX byte has only one reachable instruction stream and is
not intrinsically malformed on x86. The corrected fixture makes both the full
`48 89 f8` instruction and its interior `89 f8` entry reachable, so overlap is
unambiguous. This correction is recorded rather than silently broadening an
instruction-boundary claim.

For every supported candidate the runner recompiles generated C into a shared
library, executes both original and generated functions on the same fixed
boundary and deterministic random vectors, and compares both with independent
Python integer formulas. These formulas specify wrapping and narrowing
explicitly. Execution takes place in separate timeout-bounded processes with
CPU/address-space/core/file-size limits. This is protection against accidental
runaway generated loops, not a general-purpose sandbox for untrusted programs.

Run heavy work serially, after the root agent grants the slot:

```bash
python3 review/validate.py --cli /absolute/path/to/rust-ghidra --output results/NEW
```

The runner refuses an existing output directory. It retains source and CLI
hashes, all commands/stdout/stderr, all decompiler outputs, inputs and complete
mismatch vectors. `results.json` reports unsupported, malformed, compilation,
execution and semantic failures separately. A partial coverage result exits
nonzero. The fixed corpus is not silently reduced or retried after failures.

Expected CLI contract:

```text
rust-ghidra decompile INPUT --function NAME --output NEW
```

`NEW/manifest.json` must contain an explicit `status` (`ok`, `unsupported`, or
`error`), optionally `generated_function` if the C symbol differs from the ELF
symbol, and optionally `output_files.decompiled_c` (default `decompiled.c`).
Paths may be absolute or relative to `NEW`. The generated function uses the
six-argument unsigned 64-bit ABI above. Successful reports require exit zero and
a C artifact. Rejected/malformed functions require exit 1, an explicit failure
status and no C artifact. No Java/Ghidra engine is used by this validation runner.

The matrix checks this bounded scalar boundary. It does not establish complete
Ghidra parity, structuring quality, cross-architecture support, decompilation of
calls/data structures/relocations, or a performance advantage.
