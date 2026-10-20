# Rust ELF relocation-table parser

This sixth Rust component runs Ghidra's ELF parse steps up to the relocation
tables. It builds on the [dynamic-table parser](../dynamic-table/README.md) and
adds what `ElfHeader.parseRelocationTables()` finds: the `DT_REL`, `DT_RELA`,
`DT_JMPREL`, `DT_RELR` and `DT_ANDROID_RELR` tables named by the dynamic table,
then every `SHT_REL`, `SHT_RELA`, `SHT_RELR` and `SHT_ANDROID_RELR` section, each
decoded into `r_offset`, `r_info` and `r_addend` records. Applying relocations is
out of scope. It is a separate library and JSON CLI; Ghidra's Java loader remains
original.

```bash
cd rust-port/relocation-tables
cargo build --release --locked --bin ghidra-elf-relocations
target/release/ghidra-elf-relocations /bin/ls
target/release/ghidra-elf-relocations --compatible --digest /bin/ls
```

The CLI defaults to strict mode, emits one JSON array for all inputs, returns 1 if
any file fails and 2 for argument errors, and accepts regular files up to 64 MiB.
`--digest` replaces each table's records with their count and an FNV-1a hash.

`parse_relocations(&bytes, policy)` returns everything the dynamic-table parser
returns, Ghidra's relocation-table list and every warning in Ghidra's order. The
library has no third-party dependencies and forbids unsafe Rust. Both policies
keep the earlier bounds and add two: at most 1,000,000 relocations per table and
4,000,000 in total, counted over every table Ghidra could build before any is
read. RELR tables are counted at their largest possible size (63 relocations per
8-byte word, 31 per 4-byte word), and one whose entry size is not positive is
rejected, because Ghidra's loop over it would never end. Android packed tables
(`DT_ANDROID_REL`/`RELA`, `SHT_ANDROID_REL`/`RELA`) are rejected: Ghidra's APS2
decoder loops forever on a zero group size. These are wrapper policies, not
ELF-format limits, and the Java oracle applies the same ones.

| Policy | Behavior |
|---|---|
| Strict, default | Everything the dynamic-table parser checks, plus: `DT_PLTREL` is `DT_REL` or `DT_RELA` and present with `DT_JMPREL`; each dynamic table has its size and entry-size values; a dynamic address that falls in a section falls in a relocation section; standard tables use the canonical entry size, RELR tables the word size; sizes are multiples of the entry size and RELR tables are not empty; every table lies inside the file. Any input on which Ghidra would warn is rejected. |
| Ghidra compatible | Reproduces Ghidra's lookups, recovery and warnings, listed below. |

## Reference boundary

The reference is the original `ElfHeader` constructor followed by the private
parse steps of the dynamic-table parser and `parseRelocationTables()`, in
`parse()` order. The load adapter stays the default one, so architecture
extensions and their relocation classes never run; GNU version tables are out of
scope. Compatibility mode matches Ghidra on these points:

- Dynamic tables are tried in Ghidra's order: `DT_REL`, `DT_RELA`, `DT_JMPREL`
  (only with `DT_PLTREL`, and with no entry size), `DT_RELR`, `DT_ANDROID_RELR`,
  then `DT_JMPREL` again with `DT_RELAENT` or `DT_RELENT`. A missing value skips
  the table silently. `DT_PLTREL` selects RELA only when it is exactly 7.
- A dynamic address inside an allocated section is handed to that section, which
  yields nothing when it is not a relocation section. Otherwise it is located in
  a `PT_LOAD`, or warned about. Tables are de-duplicated by file offset, and every
  section is then tried the same way.
- Section tables take their symbol table from `sh_link` (`.dynsym` when it is 0)
  and their relocated section from `sh_info`, with Ghidra's
  "Failed to process relocation section" warnings for bad indices. Two `.dynsym`
  sections are a failure, as Java's RuntimeException is.
- Standard tables hold `(int) (size / entrySize)` records, a non-positive entry
  size meaning the standard one, but the records are read back to back at the
  standard size. RELR tables read 8-byte words only when the entry size is 8,
  always read the first word, and advance offsets by the entry size.
- Reads past EOF return zeros. Reads at negative offsets fail, as Java's
  IOException does, and so does an address in a `PT_LOAD` with no file size.

Section tables report raw `sh_addr`; tables found through the dynamic table
report the address Ghidra stored.

## Verified checks

```bash
export JAVA_HOME=/usr/lib/jvm/java-25-openjdk-amd64   # Ghidra 12.3 needs JDK 25
python3 rust-port/relocation-tables/check.py --output /tmp/relocation-check-NEW
python3 rust-port/relocation-tables/review/corpus.py --output /tmp/relocation-corpus-NEW
```

Both need the Ghidra jars (`./gradlew jar generateLibraryDependencyMapping`), and
each output directory must be new. `check.py` checks pinned source hashes in
`reference.json`, runs the unit tests in debug and release, generates the fixtures
in `oracle/fixtures.py` (built on the dynamic-table fixtures) and compares the real
Java results with the Rust CLI. It then runs strict mode over the same corpus:
canonical inputs must be accepted, and anything strict accepts must carry exactly
Java's values. `review/corpus.py` does the same comparison over real ELF files,
gcc-built shared objects, PIEs and relocatable objects (with `DT_RELR` where the
linker supports it), and copies with their section-header fields cleared.

Results on this branch:

- All 348 synthetic inputs match Java exactly, including warnings: 298 Java
  acceptances and 50 rejections, 24 of the inputs randomized. Strict mode
  accepted 149 inputs, all with values identical to Java.
- 2,198 files gave no mismatches: real ELF files from `/usr/bin` and
  `/usr/lib/x86_64-linux-gnu` (files over the 64 MiB CLI limit are skipped), five
  gcc-built objects and 400 section-less copies. That covered 4,653 relocation
  tables with 3,221,143 relocations, 292 of them RELR tables and 806 found only
  through the dynamic table. Strict mode accepted all 2,198 with Java's values.

`decode_relr(&bytes, little_endian, is64)` decodes a canonical RELR table on its
own; the decompiler's image model uses it. A unit test checks it against the
Ghidra-compatible loop, and it matches `readelf -r` on all 35 system files with a
`.relr.dyn` section.

Performance has not been measured for this component yet.
