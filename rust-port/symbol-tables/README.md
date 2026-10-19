# Rust ELF string- and symbol-table parser

This fourth Rust component builds on the [section-header parser](../section-headers/README.md)
to decode section-based string tables and symbol tables (`.symtab`, `.dynsym`),
including names and extended section indices. It is a separate library and JSON
CLI. Ghidra's Java loader remains original; this component is not connected to
the loader yet.

```bash
cd rust-port/symbol-tables
cargo build --release --locked --bin ghidra-elf-symbols
target/release/ghidra-elf-symbols /bin/ls
target/release/ghidra-elf-symbols --compatible /bin/ls
```

The CLI defaults to strict mode, emits one JSON array for all inputs, returns 1 if
any file fails and 2 for argument errors, and accepts regular files up to 64 MiB.

`parse_symbols(&bytes, policy)` returns the checked section table plus owned
`StringTable` and `SymbolTable` records; symbol names borrow the input where they
are valid UTF-8. The library has no third-party dependencies and forbids unsafe
Rust. Both policies cap each symbol table and extended-index table at 1,000,000
entries, checked before any table is decoded. That is a wrapper policy, not an
ELF-format limit.

| Policy | Behavior |
|---|---|
| Strict, default | Everything the section parser checks, plus: each symbol table has the canonical entry size, a whole number of entries and lies inside the file; its `sh_link` names an `SHT_STRTAB` section inside the file; every name lies inside that table and is NUL-terminated there; linked extended-index tables lie inside the file. |
| Ghidra compatible | Reproduces Ghidra's lookups, recovery and warnings, listed below. |

## Reference boundary

The reference is the original `ElfHeader` constructor, `parseSectionHeaders()`, and
the private `parseStringTables()` and `parseSymbolTables()` methods, with no
dynamic table parsed. So symbol and string tables found only through `DT_SYMTAB`,
`DT_STRTAB` and the hash tables are out of scope; they belong with the dynamic
table slice. Within that boundary, compatibility mode matches Ghidra on these
points:

- Every `SHT_STRTAB` section is a string table. A symbol table's string table is
  the first one at the same file offset as its `sh_link` section, which need not
  be a string table itself. An `sh_link` outside the table is an error.
- Symbol tables with an invalid offset are skipped. The symbol count is Java's
  `(int) (size / entsize)` on signed longs: a zero entry size is an error, and a
  negative count decodes no symbols. Records past EOF are zero-filled. A field read
  that would start past `Long.MAX_VALUE` is an error, exactly where Java fails.
- `STT_SECTION` symbols with `st_name == 0` take their section's name. Other names
  are read from the string table at the sign-extended `st_name`, up to NUL or EOF,
  decoded with the JDK's UTF-8 rules and trimmed as `String.trim` does. A read
  outside the table produces Ghidra's warning and a null name. Names are read in
  sorted `st_name` order, so warnings come out in Ghidra's order.
- The extended-index table is the first `SHT_SYMTAB_SHNDX` section linked to the
  symbol table, read as `(int) (size / 4)` entries with Ghidra's warning when the
  read fails. `SHN_XINDEX` symbols take their index from it.
- A table is dynamic when its section is named `.dynsym`, as in Ghidra.

Table addresses are raw `sh_addr` values; Ghidra's getters add prelink
adjustment, which is outside this boundary.

## Verified checks

```bash
export JAVA_HOME=/usr/lib/jvm/java-25-openjdk-amd64   # Ghidra 12.3 needs JDK 25
python3 rust-port/symbol-tables/check.py --output /tmp/symbols-check-NEW
python3 rust-port/symbol-tables/review/corpus.py --output /tmp/symbols-corpus-NEW
```

Both need the Ghidra jars (`./gradlew jar generateLibraryDependencyMapping`), and
each output directory must be new. `check.py` checks pinned source hashes in
`reference.json`, runs the unit tests in debug and release, generates the fixtures
in `oracle/fixtures.py` and compares the real Java results with the Rust CLI. It
then runs strict mode over the same corpus: canonical inputs must be accepted, and
anything strict accepts must carry exactly Java's values. `review/corpus.py` does
the same comparison over real ELF files and gcc objects.

Results on this branch:

- All 298 synthetic inputs match Java exactly, including warnings: 256 Java
  acceptances with 5,006 symbols, 46 inputs with warnings and 42 rejections. Four
  of the inputs are randomized tables. Strict mode accepted 124 inputs, all with
  values identical to Java.
- 1,798 real ELF files from `/usr/bin` and `/usr/lib/x86_64-linux-gnu`, plus gcc
  objects, gave 1,802 symbol tables and 627,708 symbols with no mismatches. The
  objects include one with 65,413 sections, which uses `SHN_XINDEX` symbols and an
  `SHT_SYMTAB_SHNDX` table.

Performance has not been measured for this component yet.
