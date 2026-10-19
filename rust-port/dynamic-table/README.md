# Rust ELF dynamic-table parser

This fifth Rust component runs Ghidra's ELF parse steps up to the symbol tables:
program headers, section headers, the dynamic table, string tables, `DT_NEEDED`
library names and symbol tables. It builds on the
[program-header](../program-headers/README.md),
[section-header](../section-headers/README.md) and
[string/symbol-table](../symbol-tables/README.md) parsers, and adds what Ghidra
finds through the dynamic table: the dynamic string table, the library names and
the dynamic symbol table, whose size comes from the hash table. That is how symbols
are found in files with no section headers. It is a separate library and JSON CLI;
Ghidra's Java loader remains original.

```bash
cd rust-port/dynamic-table
cargo build --release --locked --bin ghidra-elf-dynamic
target/release/ghidra-elf-dynamic /bin/ls
target/release/ghidra-elf-dynamic --compatible /bin/ls
```

The CLI defaults to strict mode, emits one JSON array for all inputs, returns 1 if
any file fails and 2 for argument errors, and accepts regular files up to 64 MiB.

`parse_dynamic(&bytes, policy)` returns the program headers, the checked section
table, the dynamic table, Ghidra's string- and symbol-table lists with the dynamic
entries marked, the library names and every warning in Ghidra's order. The library
has no third-party dependencies and forbids unsafe Rust. Both policies keep the
earlier bounds (4,096 program headers, 65,536 section headers, 1,000,000 symbols
per table and 4,000,000 in total, now counting the dynamic symbol table) and add
two: at most 65,536 dynamic entries, and no `DT_GNU_HASH` walk whose region runs
past EOF, since zero-filled reads would never end the chain. These are wrapper
policies, not ELF-format limits, and the Java oracle applies the same ones.

| Policy | Behavior |
|---|---|
| Strict, default | Everything the earlier parsers check, plus: one `PT_DYNAMIC` inside a `PT_LOAD`, with the table up to `DT_NULL` inside the file; `DT_STRTAB`, `DT_STRSZ`, `DT_SYMTAB`, `DT_SYMENT` and a hash table present, mapped and inside the file; canonical `DT_SYMENT`; every library name inside the string table and NUL-terminated there; a hash-table count reached without Ghidra's warnings. Any input on which Ghidra would warn is rejected. |
| Ghidra compatible | Reproduces Ghidra's lookups, recovery and warnings, listed below. |

## Reference boundary

The reference is the original `ElfHeader` constructor followed by the private
`parseProgramHeaders()`, `parseSectionHeaders()`, `parseDynamicTable()`,
`parseStringTables()`, `parseDynamicLibraryNames()` and `parseSymbolTables()`, in
`parse()` order. The load adapter stays the default one, so architecture
extensions never run; relocation and GNU version tables are out of scope.
Compatibility mode matches Ghidra on these points:

- The dynamic table comes from a single `PT_DYNAMIC`, located through its virtual
  address in the containing `PT_LOAD` (or its own `p_offset` when none contains
  it). A zero address or file size is reported as stripped. With several
  `PT_DYNAMIC` headers, or none, a lone `SHT_DYNAMIC` section inside a `PT_LOAD`
  is used instead.
- Entries are read up to the first `DT_NULL`, zero-filled past EOF, so the table
  always ends at the end of the file. ELF64 tags are truncated to 32 bits as
  Ghidra's int `d_tag` does, so `0x1_0000_0000` ends the table.
- Addresses get the `PRE` trailer's image base, as Ghidra adds it, including the
  double adjustment Ghidra applies when comparing a section string table's
  address with `DT_STRTAB`. Ghidra's "no address" value is -1 and is compared
  like any other address, so a section at address -1 can be chosen even with no
  dynamic table.
- A dynamic string or symbol table is built from `DT_STRTAB`/`DT_SYMTAB` only
  when no section table has the same address; it is appended to Ghidra's list.
  The symbol count comes from `DT_HASH`'s `nchain`, the `DT_GNU_HASH` bucket and
  chain walk (with Java's int arithmetic and its bounds checks) or
  `DT_GNU_XHASH`'s `symndx + ngnusyms`, in that order of preference.
- Library names use Ghidra's string reads, and an unreadable one becomes
  `UNK_LIB_NAME_<n>`. Every warning Ghidra emits on the way, including its
  misspellings, is reproduced in order.
- An address in a `PT_LOAD` with no file or memory size is a failure, as Java's
  `UnsupportedOperationException` is; so are reads at negative offsets and a zero
  `DT_SYMENT`.

Section-based tables report raw `sh_addr`; tables found through the dynamic table
report the address Ghidra stored.

## Verified checks

```bash
export JAVA_HOME=/usr/lib/jvm/java-25-openjdk-amd64   # Ghidra 12.3 needs JDK 25
python3 rust-port/dynamic-table/check.py --output /tmp/dynamic-check-NEW
python3 rust-port/dynamic-table/review/corpus.py --output /tmp/dynamic-corpus-NEW
```

Both need the Ghidra jars (`./gradlew jar generateLibraryDependencyMapping`), and
each output directory must be new. `check.py` checks pinned source hashes in
`reference.json`, runs the unit tests in debug and release, generates the fixtures
in `oracle/fixtures.py` and compares the real Java results with the Rust CLI. It
then runs strict mode over the same corpus: canonical inputs must be accepted, and
anything strict accepts must carry exactly Java's values. `review/corpus.py` does
the same comparison over real ELF files, gcc-linked shared objects with each hash
style, and copies of shared objects with their section-header fields cleared.

Results on this branch:

- All 454 synthetic inputs match Java exactly, including warnings: 410 Java
  acceptances and 44 rejections, 12 of the inputs randomized dynamic tables.
  Strict mode accepted 187 inputs, all with values identical to Java.
- 2,196 files gave no mismatches: real ELF files from `/usr/bin` and
  `/usr/lib/x86_64-linux-gnu` (files over the 64 MiB CLI limit are skipped), three
  gcc-linked shared objects and 400 section-less copies. That covered 2,186
  dynamic tables, 6,075 library names and 556,757 symbols; 400 symbol tables with
  59,786 symbols were sized from hash tables. Strict mode accepted all 2,196 with
  Java's values.

Performance has not been measured for this component yet.
