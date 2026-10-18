# Independent read-only image and pointer review

This review covers the next native Rust decompiler boundary. It does not run or
link Ghidra and does not treat an emitted artifact as a proof for every input.
The edge corpus is fixed before candidate execution; native guard functions are
never called. The first exclusive serial run is retained below.

## Representation contract

Keep image provenance separate from numeric values and modeled stack pointers.
An image value should carry an immutable validated object identifier and an
object-relative offset. ELF virtual addresses are not reconstructed host
pointers: scalar immediates and memory contents that happen to equal a VMA do
not acquire pointer provenance. RIP-relative addresses may obtain provenance
only after the loader resolves them to one unambiguous supported image object.

Reads require the whole access width inside immutable, file-backed bytes.
Writable or relocation-dependent bytes, ambiguous mappings and invented
zero-fill remain unsupported in this slice. Byte-wise decoding avoids host
alignment and aliasing assumptions and explicitly preserves x86 little-endian
load semantics. Pointer arithmetic must retain its object identity and use
checked object bounds before access or return. Memory writes through image
pointers fail explicitly.

The typed pointer result model returns a pointer into a generated static const
byte array. The data must outlive the call. The result ABI is explicit in the
manifest and generated C; the six inputs remain scalar uint64 values. Scalar
mode must reject image addresses, and pointer mode must reject stack pointers,
invalid/mixed provenance and arbitrary scalar numbers. Comparing unrelated
native and regenerated process addresses is not an equivalence check: compare
returned contents and relative offsets within each arm instead.

## Critical integration gates

1. The old stack spill tag records the starting stack slot, not the identity of
   an image object. Extending only `rg_value.p` loses image provenance across
   spills. Complete-width reloads must prove all eight bytes came from the same
   complete store and restore the original pointer kind/object. Partial reads
   or overlapping writes invalidate provenance.
2. Object offsets have different numeric bits from real pointers. Truncation,
   partial-register writes, shifts, pointer-to-integer results and arbitrary
   masks cannot silently expose those offsets as native numeric addresses.
   The old stack-only alignment mask is not sound for image objects: their
   host alignment is a separate fact and their ELF VMA alignment is not the
   generated C array's alignment.
3. Pointer arithmetic must invalidate unmodeled machine flags. Computing flags
   from a synthetic object offset can change branches. Cross-object subtraction
   and comparisons need a separate proven address model; they are not justified
   merely because both operands carry pointer provenance.
4. The object boundary is the loader's declared object, possibly a full read-only
   segment, not necessarily a recovered C variable. Do not claim symbol-size
   memory safety from a mapping-sized bound. Explicit mapping-edge guards are
   required in addition to ordinary table/string fixtures.
5. A pointer load from arbitrary immutable bytes is still a scalar load unless
   its pointer representation and relocations are modeled. Supporting read-only
   memory does not make ELF relocation processing or external pointer arguments
   supported.

## Runtime source review before execution

The updated `runtime.h` represents image values with `p >= 3` and an
object-relative `x`. Image loads check the complete width before accessing
individual bytes, so unaligned x86 reads need no host typed-pointer cast.
Pointer results require a known full-width image offset within the array or its
one-past position. Stack-only `rg_slot` rejects image writes. Full-width spills
now preserve both their original stack-store start and pointer object identity;
partial and overlapping stores cannot reconstruct a valid pointer. The image
alignment mask path rejects, and arithmetic invalidates unmodeled flags. Same
object subtraction yields the modulo-64-bit offset difference; cross-object
subtraction rejects. No critical C bounds, alignment or provenance issue was
identified in this source pass. Loader mapping/relocation validity and emitter
static-array construction remain separate dependencies, not proven by that
runtime observation.

The subsequent `rg_compare` extension gives same-object, known 64-bit image
pointers only an equality flag. Adding the same unknown load base is a bijection
modulo 2^64, so the native addresses are equal exactly when their relative
offsets are equal. `rg_compare` validates the object ID and both known values,
clears all known flags and establishes only ZF. CF, OF, PF and SF stay unknown;
cross-object and numeric/pointer comparisons do not gain this shortcut.
Numeric CMP still delegates to ordinary SUB flag handling, while TEST retains
its existing AND behavior. This source review finds the narrow change sound;
the added JE/JNE positives and CF/OF guards exercise its intended boundary.
The current flag guards write SETcc into scalar R8B and then overwrite EAX
fully, so invalid partial image-pointer provenance cannot independently make
the test abort. The first receipt's older arithmetic-flag guard used AL and
therefore established a guarded result without isolating which guard fired;
its original fixture remains archived rather than rewritten.

## Fixed independent edge corpus

`fixtures/image-edges.S` provides six numeric positives: byte loads, unaligned
little-endian 64-bit loads, complete image-pointer stack spilling and subtraction
of a scalar index before a byte load, plus same-object pointer JE and JNE.
Three typed pointer positives check a
base address, indexed address and complete spill/reload followed by LEA.
Expectations derive from the fixed 64-byte arithmetic-pattern table and offsets,
not from generated C or Ghidra output.

Seventeen mandatory guards cover a numeric VMA alias, pointer truncation and
partial-register overwrite, scalar-mode pointer escape, image writes, huge
out-of-bounds offsets, the final executable mapping boundary, scalar values in pointer mode, image alignment masks,
unmodeled pointer arithmetic flags and CMP CF/OF, partial and split pointer spills, stack pointers in
pointer mode, scalar immediates in pointer mode, and writable image loads.
Each must either reject with exit 1, a rejection manifest and no C, or produce
C that aborts specifically with SIGABRT. Timeout, SIGSEGV or any numeric return
does not satisfy a guard.

The runner freezes the candidate, fixtures and helper sources into a new output
directory, logs every command/input, snapshots all manifests and retains all
failures. It runs trusted assembly and generated fixture C in bounded children;
it is not a general binary sandbox or new speed evidence.

Run only during an exclusive heavy-work slot:

```bash
python3 review/image_edges.py --cli /absolute/rust-ghidra --output results/NEW
```

## First execution receipt

[image-edges-01](../results/image-edges-01/results.json) passes all four numeric
and three typed pointer functions on 586 fixed vectors. Native originals and
regenerated C each match 4,102 independent expected results, including exact
relative pointer offsets within each execution arm. All fifteen mandatory
guards pass: three explicit unsupported rejections and twelve SIGABRT results.
The final executable-mapping boundary guard aborts before the full-width read.
No timeout, SIGSEGV, numeric guard return or removed case counts as success.

All 68 command records are complete. The twenty original/generated binary
artifact hashes and live/frozen candidate hashes were rechecked after execution
with no mismatches. The frozen candidate SHA-256 is
`259fa6f531d294b0c105bcd048dfd044ffef97957d94e9a35e8b1465e02ea144`.
The candidate, fixture source, helper source, vectors, manifests, generated C,
libraries and stdout/stderr remain in the fresh result directory. This finite
corpus validates its declared memory/provenance behavior; it is not arbitrary
ABI, full-binary support or performance evidence.

## Final candidate gates

The final [image-edges-02](../results/image-edges-02/results.json) passes all six
numeric and three pointer positives on the unchanged 586 vectors: 5,274
independent expected results per native/generated arm. Both equal and unequal
pointer JE/JNE branches match the original. All seventeen mandatory guards pass
as eight explicit unsupported rejections and nine SIGABRT results, including
the isolated arithmetic-ZF and CMP CF/OF guards. All 72 command records and
nineteen binary artifact hashes recheck without errors. The final frozen CLI
SHA-256 is
`bd86a9af949b1c17231291cf5a856643afc3c99f2dbe06c11b9e8c3c432053fe`.

The separate [image-runtime-01](../results/image-runtime-01/results.json) helper
gate passes fifteen positive cases and twenty-nine exact SIGABRT guards across
two distinct immutable objects. It covers complete and overlapping spills,
object replacement, unaligned slots, one-past pointer results versus one-past
reads, full-width boundary reads, cross-object arithmetic/comparison and all
remaining unknown CMP flags. This directly tests the C helper boundary rather
than native function reconstruction. Its 45 command records, compiled helper,
runtime and frozen source hashes recheck without errors. The frozen runtime
SHA-256 is
`8ea4b99047393b254ce90ffd5c53000f7dcf3b8bd474106f4e8825f56c1804b5`.
Both runs were serial and retain all sources, commands, generated artifacts and
guard outcomes. The first receipt remains unchanged.
