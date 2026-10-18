# Independent compatibility review

This corpus supplements the original 30 cases. It exercises the actual Java
`ElfHeader` constructor without calling `parse()`. It contains 1,047 deterministic
inputs, each at most 512 bytes: every byte boundary in all four header formats,
identification/version variants, signed/unsigned boundaries, truncated section
zero, extended numbering, endianness recovery, compressed section-zero records,
extreme encoded offsets, and 96 seeded mutations.

```bash
python3 review/differential.py
python3 review/differential.py --rust target/release/ghidra-elf --reuse-java
python3 review/safety_edges.py --rust target/release/ghidra-elf
```

The first command records the original Java result. The second compares every
accepted normalized header field, accept/reject decisions, and the oracle's
`warnings` array. Rust may expose extra structured `diagnostics`; these are not
compared to Java prose. Java error classes/messages are retained as evidence but
are not required to be Rust API names. A mismatch or unexpected output makes the
check exit nonzero. Reusing Java results requires identical input SHA-256 hashes,
lengths, filenames, categories, and order; generator changes require a fresh run.

**Verified result:** all 1,047 main-corpus accept/reject decisions and accepted
normalized header values match the original Java constructor, and all 1,047 oracle
warning arrays match. Java accepts 882 of these inputs. The separate eight-case
safety probe passes its explicit expectations and records **three intentional
rejection differences**, detailed below. These observations support this bounded
constructor contract; they do not establish universal Java/Rust equivalence.

Generated artifacts are `manifest.json`, `java-manifest.json`, `java-expanded.json`,
`java-stderr.txt`, and (after a Rust run) `rust-expanded.json` and `comparison.json`.
The corpus is a correctness check, not a performance workload. The fixed mutation
sample is not exhaustive fuzzing.

## Source findings verified with Java

- **Initialization order changes extended counts.** Program count resolution runs
  before `e_shentsize` is assigned, so Java's first region check uses zero. If that
  probe caches section zero, later section and string counts reuse it even when
  the declared section entry extends past EOF. For ELF64 with only 39 section-zero
  bytes present, `phnum=0` resolves section count zero while `phnum=0xffff` resolves
  section count three from the same available bytes. Requiring a complete section
  record before every compatible-mode read would change this behavior.
- **`e_shentsize` is passed as a signed Java short.** Values 0x8000–0xffff can make
  the region check succeed even if a positive unsigned interpretation would fail.
  The parser must distinguish the stored unsigned field from this compatibility
  predicate. It should never allocate based on that signed value.
- **Byte-order recovery is conditional.** Declared big-endian switches to
  little-endian only if the first type byte is nonzero and the first version byte
  equals one. The declared-endian accessor remains unchanged. Invalid EI_DATA
  diagnostics print sign-extended Java byte values for values at least 0x80.
- **Extended counts require SHT_NULL.** `sh_info` and `sh_link` are signed Java ints;
  values above 0x7fffffff resolve to zero. `sh_size` must fit 0..0x7fffffff as well.
  A zero resolved section count forces the resolved string-table index to zero.
- **Compressed section zero does not change the resolved count in this revision.**
  `ElfSectionHeader.getSize()` returns raw `sh_size`; only `getLogicalSize()` reads
  the compressed logical size. A valid ELF64 compressed header with raw size 24 and
  compressed logical size 17 resolves section count 24. Invalid compression probes
  produce process stderr through `Msg.warn`, outside the oracle's error-consumer
  `warnings` array; these messages are preserved in `java-stderr.txt` and are not
  part of the normalized header contract.
- **Java region arithmetic can overflow.** Tiny files encoding `e_shoff` near
  0x7fffffffffffffff with `e_shentsize=64` pass the unchecked signed-addition region
  test and later throw `ElfException` when the read pointer wraps negative. Rust
  should reject safely using checked arithmetic. Reproducing the overflow itself
  is unnecessary for matching rejection.

The overflow boundary also exposes intentional differences: with `e_shoff` equal
to signed-long maximum minus 63 or minus 56 and `e_shentsize=64`, Java's unchecked
addition wraps, but every individual section-field read still begins at a positive
index. Java zero-fills the record and accepts. Rust rejects with `OffsetOverflow`.
An entry size of 32767 with offset maximum minus 32766 behaves similarly. These
three exact cases are asserted in `safety_edges.py` and recorded in
`safety-comparison.json`; the main equality checker does not suppress mismatches.

## Strict policy requirements and resource boundary

The implemented strict mode requires the complete canonical header, recognized class and
encoding, current identification/header versions, and the canonical ELF header
size. It uses declared byte order directly. Extended numbering requires an
available SHT_NULL section-zero record, representable unsigned counts, and a
sensible string-table index. It checks required program/section entry sizes and
nonzero offsets but **does not validate complete table extents or bodies**. Ordinary
table offsets beyond EOF can therefore be accepted as metadata. Its unsigned
32-bit extended counts can also exceed Java's signed-int cap. Both choices are
explicit policy differences; strict mode is not a complete ELF validator.

Future table parsing must validate multiplication/addition and file bounds before
reading or allocating, including normal-count paths that do not need section zero.

The constructor-only compatibility contract does not allocate arrays from counts
or read whole tables. Keep that property in Rust. Large encoded counts and offsets
should not cause proportional allocation, recursion, or scanning. Future table
iteration needs explicit size/resource limits; reproducing Java's later unbounded
array allocations is outside this milestone. A CLI that reads a whole input file
has different memory costs from the borrowed-slice parser and must be measured
separately.
