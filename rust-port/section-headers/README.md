# Rust ELF section-header parser

This third Rust component extends the ELF file-header parser with section-header
tables: the records that name and describe an object's sections. It is a
separate library and JSON CLI. Ghidra's Java loader and native decompiler remain
original; this component is not connected to the loader yet.

```bash
cd rust-port/section-headers
cargo build --release --locked --bin ghidra-elf-sections
target/release/ghidra-elf-sections /bin/ls
target/release/ghidra-elf-sections --compatible /bin/ls
```

The CLI defaults to strict mode. It emits one JSON array for all input files,
returns 1 if any file fails and 2 for argument errors. Use `--` before paths that
start with `-`. It accepts regular files up to 64 MiB each.

The library has no third-party dependencies, forbids unsafe Rust and borrows the
input bytes. `parse_section_headers(&bytes, ParsePolicy::Strict)` returns a
checked view; `header()`, `iter()`, `get(index)`, `name(index)` and
`name_bytes(index)` expose owned numeric fields and borrowed names. Iteration
uses constant additional storage. Both policies cap the resolved section count at
65536 as an explicit resource bound. That is a wrapper policy, not an ELF-format
limit.

| Policy | Behavior |
|---|---|
| Strict, default | Validates the ELF header, required section zero, the full canonical table extent, the name string table's extent and every name's bounds and terminator. |
| Ghidra compatible | Uses Java's signed-short record stride, zero-fills missing record bytes, reproduces its missing-table warning, and looks names up exactly as `ElfSectionHeader.updateName` does. |

## Reference boundary

The reference is the original `ElfHeader` constructor followed by its public
`parseSectionHeaders()` method, before `parse()` installs an architecture load
adapter. That covers:

- `ElfSectionHeader` record decoding for ELF32/64 in either byte order. Addresses
  and alignment are the raw `sh_addr`/`sh_addralign` fields; the public getters
  apply prelink and compression adjustments outside this boundary.
- Section names. Ghidra reads UTF-8 from the string table's file offset plus
  `sh_name` up to a NUL or end of file, ignoring the string table's own size and
  any negative `sh_name`. A missing or empty name becomes `SECTION<index>`.
  Malformed UTF-8 is replaced as the JDK's `String` decoder does, which differs
  from `String::from_utf8_lossy` for encoded surrogates; `java_utf8_lossy`
  implements those rules.
- The `SHF_COMPRESSED` probe. A non-allocated section whose region fits in the
  file and whose `Elf32_Chdr`/`Elf64_Chdr` names `ELFCOMPRESS_ZLIB` is reported as
  compressed with its uncompressed size and alignment. The compression header is
  read with the declared EI_DATA byte order, which can differ from the order used
  for the records. Rejected probes are reported as `Compression::Invalid` with a
  reason; Ghidra logs them and treats the section as uncompressed. No data is
  decompressed.
- Whether any `SHT_SYMTAB_SHNDX` section exists.

Compatibility mode deliberately rejects signed record-address overflow instead of
allowing Java to wrap: Ghidra fails only when a field read starts past
`Long.MAX_VALUE`, while Rust rejects a record whose last byte would. Such cases are
checked separately from parity cases. Neither policy validates section payload
extents, alignment, links or architecture-specific constraints.

## Verified checks

```bash
export JAVA_HOME=/usr/lib/jvm/java-25-openjdk-amd64   # Ghidra 12.3 needs JDK 25
python3 rust-port/section-headers/check.py --output /tmp/sections-check-NEW
python3 rust-port/section-headers/review/corpus.py --output /tmp/sections-corpus-NEW
```

Both need the Ghidra jars (`./gradlew jar generateLibraryDependencyMapping`).
Each output directory must be new. `check.py` checks pinned original-source hashes
in `reference.json`, runs seven unit tests in debug and optimized release,
generates the fixture corpus in `oracle/fixtures.py`, then compares the real Java
results with the Rust CLI. It also runs strict mode over the same corpus: every
canonical table must be accepted, and anything strict accepts must carry exactly
Java's values. `review/corpus.py` compares Java and Rust over real ELF files and
over gcc objects whose debug sections objcopy has zlib-compressed.

Results on this branch:

- 464 exact Java parity cases and six separately checked safety differences
  across 470 synthetic inputs, including randomized malformed UTF-8 names. Strict
  mode accepted 154 of them, all with values identical to Java.
- 1,797 real ELF files from `/usr/bin` and `/usr/lib/x86_64-linux-gnu`, plus the
  compiled objects: 53,064 sections, 15 of them compressed, with no mismatches.

Performance has not been measured for this component yet.
