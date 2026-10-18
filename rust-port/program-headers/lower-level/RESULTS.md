# Portable release CLI code review, 2026-10-18

The three selected functions exported successfully in
[`results/selected-01`](results/selected-01). The copied CLI SHA-256 is
`26b3167fed6766a42e78fd0650b7d36d2e338914b360c4cdc19435db7f8cbc31`.
The build is the component's existing portable `opt-level=3` release artifact;
this workflow performed no build. Original engine SHA-256
`876c28d48c07126e5db94946c10719eeb96b057c9271daa0114df34e598f262a`
and all recorded source/artifact hashes remained unchanged through the export.

| Selected symbol | ELF VMA | Symbol bytes | Exported instructions | Outcome |
|---|---:|---:|---:|---|
| `ghidra_elf_segments::parse_program_headers` | `0x19440` | 1671 | 381 | C, listing and raw p-code complete for selected scope; five NOP padding gaps |
| `<ghidra_elf_segments::ProgramHeaders>::raw` | `0x19ad0` | 449 | 138 | C, listing and raw p-code; full instruction coverage |
| `ProgramHeaderIter`'s `Iterator::next` | `0x1a180` | 177 | 51 | C, listing and raw p-code; full instruction coverage |

All three statuses are `decompiled`, with no request timeout, cancellation,
failed start, export truncation or decompiler error text. The exact completion
footer occurs once. Function bodies equal the requested symbol extents and do
not extend outside them. The overall `complete_instruction_coverage` flag is
**false**, separate from the passing selected-export gate. Ghidra's bounded
disassembler did not follow five alignment gaps; independent retained objdump
output decodes all five as NOP instructions:

| ELF VMA, inclusive | Bytes | Retained objdump interpretation |
|---|---:|---|
| `0x19614`–`0x1961f` | 12 | prefixed `nopw` |
| `0x196af` | 1 | `nop` |
| `0x19726`–`0x1972f` | 10 | prefixed `nopw` |
| `0x19742`–`0x1974f` | 14 | prefixed `nopw` |
| `0x19792`–`0x1979f` | 14 | prefixed `nopw` |

These total 51 bytes. Their byte ranges remain explicit in `summary.json`; no
extra disassembly or artificial flow overrides were applied to conceal them.
Ghidra addresses in the exported project add image base `0x100000` to ELF VMAs.

## Source and instruction checks

The component's successful path borrows input bytes and returns numeric records.
The retained assembly substantiates these specific observations:

| Source behavior | Observed compiled path |
|---|---|
| Delegate file-header decoding, then enforce the 4096-entry cap | `0x19462` calls the existing `parse_header` through its relocated pointer; `0x194f4` compares the resolved count with `0x1000`. |
| Strict mode checks a complete table extent before creating a view | `0x197e7`–`0x19803` multiplies count by unsigned stride, adds table offset with a carry rejection and compares the end with input length. It skips the compatibility record scan. |
| Compatibility mode uses a signed stride and rejects record-address overflow | `0x195cb` sign-extends the short stride; the loop checks signed addition at `0x1963a`/`0x1963d` and canonical record end at `0x1965c`/`0x19661`. Negative positions have their own rejection branch. |
| Compatibility's initial scan needs only `file_size` | Optimized loop loads only offset `0x20` for ELF64 or `0x10` for ELF32, with a `bswap` on big-endian paths. The full temporary `ProgramHeader` does not survive this scan. |
| Missing records use bounded zero padding | Both the scan and raw accessor check the available byte span, use a stack buffer, and call `memcpy` only for a partial available tail. Complete records select the borrowed input pointer. |
| Preserve raw offsets and optionally advance effective offsets | `raw` writes the decoded offset twice at `0x19c5b`/`0x19c5f`. `next` calls `raw` once, increments the index after `Some`, and uses one running wrapping sum when the rewrite flag is set (`0x1a1de`–`0x1a1ed`). It does not rescan preceding records. |
| Decode full records in both ELF classes and byte orders | `raw` selects 32/56-byte records, uses class-specific field positions, zero-extends ELF32 loads and applies native `bswap` instructions only on big-endian paths. |

There are two call sites inside the selected parser body: `parse_header` and the
partial-record `memcpy`. The raw accessor has one partial-record `memcpy` call;
the iterator has one call to `raw`. There is no allocator or panic call in these
three selected bodies. This is a scoped observation: the header helper, its call
graph, the runtime and CLI buffering/JSON allocation were not exported here.

One concrete future experiment is visible in both objdump and C: the inlined
decoder clears a 56-byte stack padding buffer **before** selecting the complete
borrowed record. In `raw`, that is the stores at `0x19b3f`–`0x19b4d`; the initial
compatibility scan does the same at `0x19676`–`0x1968e`. Moving initialization
inside the truncated-record branch could remove stores for complete records.
That is a hypothesis requiring a separate candidate, parity gate and benchmark;
this review does not establish a timing benefit or change the current source.

## Limits of the C reconstruction

The empty decompiler error strings do not verify Rust types or its internal ABI.
All original function metadata has `DEFAULT` signature source and `unknown`
calling convention. The C expands compiler-reordered numeric fields, stack
temporaries and result discriminants into inferred arrays and wide concatenations.
Those inferred layouts are properties of this artifact, not a public Rust ABI.

There is a specific lost-argument example in the parser's C: the header call is
rendered as `parse_header(&uStack_d8)` even though the machine call retains the
input pointer, slice length and policy in argument registers. The assembly
saves RSI, RDX and ECX, substitutes the stack result pointer in RDI, then calls
the header helper. Treat the C call signature as incomplete. The iterator C also
names fields after stack slots rather than the source's record types.

The ELF import records five unsupported TLS symbols and 65 unresolved external
symbols, with no external runtime libraries imported. These are preserved in
the headless log and reinforce the selected scope. The input was imported with
`-noanalysis`; no whole-program analysis, runtime reconstruction or Rust source
recovery is claimed. The bounded listings and raw p-code, original source and
actual bytes are the checks on C. Instruction counts, symbol size and export
times are not measurements of parser execution cost or whole-Ghidra speed.

Read [`summary.json`](results/selected-01/summary.json),
[`provenance.json`](results/selected-01/provenance.json),
[`export/selected.json`](results/selected-01/export/selected.json) and the three
`*-objdump.stdout.txt` files for the complete retained evidence. The project is
new and isolated; no old retained project or original Ghidra source was edited.
