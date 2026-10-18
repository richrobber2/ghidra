# Independent source semantics review

Scope: the new native Rust ELF loader, x86-64 scalar lifter, and generated C
runtime. This is a first standalone scalar subset, not complete Ghidra parity.
This review does not run or link the original Ghidra engine. Source observations
do not substitute for execution validation.

## Findings raised before execution

1. **Reachable overlapping instructions.** The initial malformed-instruction
   fixture used an unconditional jump into the bytes of an instruction that
   was never reached from its beginning. That is a valid alternate-entry x86
   stream under the declared reachable-CFG policy. The fixture was corrected,
   before execution, to a conditional jump so both starts are reachable. The
   lifter must reject demonstrated overlap, not invent a linear decode policy.
2. **Synthetic stack addresses.** A known synthetic RSP is not the actual
   caller's stack address. Known numeric bits alone cannot justify returning
   RSP, comparing it with arbitrary scalar arguments, or treating a scalar
   argument that equals the synthetic address as a stack pointer. The runtime
   must retain stack provenance, reject unsupported observable pointer use,
   and require stack provenance as well as bounds for stack access.
3. **CLI rejection consistency.** The independent validation runner should
   require both a failure manifest/no C artifact and a nonzero process exit
   for mandatory rejection cases.
4. **Return-slot mutation and stack alignment.** The runtime initially checked
   only restored RSP at RET, without guarding stores that could modify the
   native return address. Stores now reserve the entry return slot and caller
   stack. Initial pointer alignment accepted page-sized masks; only the known
   SysV sixteen-byte alignment relationship justifies modeled low-bit clearing.
   The independent suite includes return-slot corruption and alignment to
   thirty-two bytes as mandatory guard cases.
5. **Byte/word rotate carry.** Rotation data uses the masked count modulo the
   operand width, but CF is updated when the masked count is nonzero. ROL8 by
   eight therefore preserves data and sets CF from bit zero. This is explicit
   in the [instruction pseudocode](https://www.felixcloutier.com/x86/rcl:rcr:rol:ror)
   read on 2026-10-18 and agrees with the original Ghidra `rolflags` helper.
   The initial runtime and independent pre-run formula both needed correction;
   no execution result was used to select the expected answer.

## Source checks completed

The loader validates canonical x86-64 ELF mappings before slicing code and
requires a complete known symbol extent or an explicit user-selected range.
Undefined imported symbols and zero-size function extents are not guessed.
The executable mapping supplies actual bytes even where section metadata may
be inconsistent; overlapping executable mappings fail closed.

The lifter tracks ownership of every reachable instruction byte and rejects
demonstrated overlap, branches outside the selected extent, invalid/truncated
instructions, unsupported instructions and fallthrough outside the extent.
Direct branches are modeled; calls and indirect branches are rejected. Input
byte and instruction-count limits bound decoder work. Prefixes that introduce
unmodeled segment/address-size/LOCK/REP behavior are rejected. Register views
retain partial widths and high-byte identity; immediate forms preserve their
decoded sign extension.

The independent scalar validation formulas explicitly specify narrowing and
wrapping for all fourteen selected source functions. The matrix preserves
unsupported cases, compiler failures, timeouts and mismatches instead of
selecting only successful functions. The subprocess limits bound accidental
runaway fixture/generated code, not arbitrary hostile native code.

## Emitter and runtime source review

The current emitter retains partial register views; thirty-two-bit writes clear
the upper half, including the false branch of thirty-two-bit CMOV. CMOV obtains
a memory source before testing its condition. Runtime register/memory known-bit
masks retain uninitialized state rather than pretending it was zero. Callee-save
push/pop can preserve an opaque initial value without consuming its unknown bits.
Full-width pointer provenance survives complete stack spills; partial or mixed
pointer bytes become invalid provenance. A scalar argument cannot access the
modeled stack merely by matching its numeric address. Returned values require
fully known numeric bits, and RET requires the original modeled stack pointer.

Arithmetic uses unsigned modular operations and bounded signed `__int128`
intermediates. Shift counts are masked, width-sized shifts are guarded, and
signed shifts are expressed using unsigned shifts and sign fill. The modeled
64-bit signed multiply fits inside signed 128-bit range. No signed C overflow or
invalid-width C shift was identified in these helpers. Register-index/operand
width invariants are supplied by the decoder/lifter; this observation applies
to IR produced by that path.

CF/OF calculations use widened carry/borrow and signed range checks. INC/DEC
preserve CF. Zero-count shifts preserve the existing modeled flags. IMUL
invalidates ZF/SF/PF; shifts/rotates invalidate OF where architecturally undefined.
Undefined entry flags remain unknown. Branches and SETcc/CMOV fail when required
flags are unknown. AF is not modeled because no accepted operation exposes it;
instructions that would expose additional flag/state effects must remain outside
this subset until modeled. Algebraic self-XOR/SUB and self-SBB permit compiler
zero/mask idioms without consuming an undefined initial register value.

These are source observations, not a proof of all x86 behavior. The runtime is
deliberately conservative: accepted instruction forms may still abort for an
unsupported reachable state. An `ok` emission manifest therefore means that a
guarded representation was produced; it is not a proof that every input follows
a supported state path. The representation preserves labels and machine state,
not original variables, types or structured source.

## Independent ISA edge gate

`instruction-edges.S` and `instruction_edges.py` fix seventeen numeric functions
and seven mandatory guards before execution. The numeric cases cover ADC/SBB
carry and overflow, AH/AL and word writes, false CMOV32 upper clearing, zero-count
flag preservation, byte/64-bit rotates, byte shift counts, signed shifts, IMUL
flags, opaque push/pop, unknown self-SBB, INC CF preservation and sign extension.
Each is compared against explicit integer formulas and original native execution.

Mandatory guards cover stack-address escape, unknown entry flags, undefined
IMUL/shift flags, return-slot mutation, unmodeled thirty-two-byte stack alignment
and numeric aliases of the synthetic stack. The original guard functions are
never executed. Generated code must explicitly reject with no C artifact or abort
with SIGABRT in its bounded child; a timeout or segfault does not satisfy a guard.

Run only during an exclusive heavy-work slot, using a fresh output directory:

```bash
python3 review/instruction_edges.py --cli /absolute/path/to/rust-ghidra --output results/NEW
```

The sole initial [ISA run](../results/isa-01/results.json) passes all seventeen
numeric functions on 751 fixed vectors. Both native original and regenerated C
match the independent formulas: 12,767 comparisons per arm. All seven guard
cases abort specifically with SIGABRT; none pass by timeout, segfault or numeric
return. Ninety commands and complete sources, binaries and output logs are
retained. The frozen and live candidate SHA-256 match
`fcd2e473eedb9308d7811635de786c304eca970eb63d671dc9a4d1268da7b8de`, and all
recorded binary artifact hashes were rechecked after the run.

No failed cases were removed and no candidate or corpus changes occurred during
that run. These finite checks support the declared scalar boundary; they are not
a proof for arbitrary x86-64 code, a memory sandbox or performance evidence.
