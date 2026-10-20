# Rust x86-64 ELF relocation handler

This seventh Rust component applies relocations. It ports Ghidra's
`X86_64_ElfRelocationHandler` together with what it uses from its base classes
and context: `AbstractElfRelocationHandler.relocate`, the markup methods of
`ElfRelocationHandler`, `ElfRelocationContext.processRelocation`, and the GOT
allocation of `ElfGotRelocationContext` as `X86_64_ElfRelocationContext`
configures it. For each relocation record it computes the bytes Ghidra writes,
the status and byte length Ghidra reports (`APPLIED`, `UNSUPPORTED`, `FAILURE`,
`SKIPPED`), and every log line, bookmark and console message on the way. The
records come from the [relocation-table parser](../relocation-tables/README.md).
It is a separate library and JSON CLI; Ghidra's Java loader remains original.

```bash
cd rust-port/x86-64-relocations
cargo build --release --locked --bin ghidra-elf-x86-64-relocations
target/release/ghidra-elf-x86-64-relocations /usr/lib/x86_64-linux-gnu/libc.so.6
target/release/ghidra-elf-x86-64-relocations --digest --adjust 0 /bin/ls
```

The CLI emits one JSON array for all inputs and returns 1 if any input is
rejected, 2 for argument errors. `--adjust HEX` sets the image-base adjustment
(default `0x100000`, Ghidra's default base for a position-independent image),
`--unresolved-externals` leaves undefined symbols out of the symbol map, and
`--manifest FILE` takes lines of `path<TAB>adjust<TAB>0|1` instead.
`--digest` replaces each list with its length and an FNV-1a hash.

## Library

`process_relocation(env, &record, address)` is the handler for one record. It
reaches the program, memory and context only through the `Environment` trait:
symbol lookup and value, `getGOTValue`, `getGotEntryAddress`, the image-base
adjustment, the prelink flag, little-endian memory reads and writes, and the log,
bookmark and console sinks. A unit-test environment drives it record by record.
`model::apply_file(&bytes, &options)` implements the trait for a whole ELF file:
it parses the file with the relocation-table parser in Ghidra-compatible mode,
then runs every relocation in table order as `ElfProgramBuilder` does. The crate
has no third-party dependencies and forbids unsafe Rust.

The handler part is exact for every type id. In particular:

- `R_X86_64_RELATIVE`, `RELATIVE64` and `IRELATIVE` add the image-base
  adjustment to the addend, or, in a prelinked image, to the value in memory;
  RELR entries are processed as `R_X86_64_RELATIVE`. REL records read their
  addend from memory first, for every type, so a bad address fails before the
  type is looked at.
- The four TLS types and `R_X86_64_COPY` are `UNSUPPORTED` with Ghidra's
  warnings; a TLS symbol is refused before the handler runs. Type ids the enum
  defines but the handler does not apply (`PC64`, `GOTPC64`, `GOTPLT64`, the
  other TLS and `CODE_*` types, the `_BND` types, `GNU_VTINHERIT`/`VTENTRY`) are
  "Unhandled"; ids it does not define are "Undefined". Both are `UNSUPPORTED`.
- A nonzero symbol index whose symbol has no address fails ("Failed to resolve
  relocation symbol") for every type after the relative, TLS and COPY ones.
- `GOTPCRELX`/`REX_GOTPCRELX` relax `mov` to `lea`, `jmp *` to `jmp` plus a `nop`
  and `call *` to `addr32 call`, recording the artificial relocation entry, unless
  the symbol type is OS-specific; anything else falls through to `GOTPCREL`.
- `GOTPCREL`, `GOTPCREL64` and `GOT64` take an entry from the `%got` block, which
  `ElfGotRelocationContext` allocates on first use, sized from every GOT-requiring
  relocation's unique symbol value (printing its "Duplicate sym value" lines),
  and only when `_GLOBAL_OFFSET_TABLE_` is undefined or zero-valued. `GOTOFF64`,
  `GOTPC32` and `PLTOFF64` use `getGOTValue()`, which falls back to that block.
  Ghidra's signed check of the block address, its message typos and its
  `NO_ADDRESS` entries for an exhausted block are reproduced.
- `R_X86_64_64` with an addend against an EXTERNAL symbol reports Ghidra's
  "EXTERNAL Data ELF Relocation with offset" error.
- Memory failures become "Processing Failure" errors. An `Address.add` or
  `subtract` overflow in the relaxation code escapes, as Java's
  `AddressOutOfBoundsException` does, and ends the run.

## Memory and symbol model

Ghidra's handler needs a `Program`. The oracle does not build one: it gives the
original handler and context small proxies for `Program`, `Memory`,
`BookmarkManager` and `ElfLoadHelper`, and the Rust `model` module implements the
same model. This keeps the oracle headless and fast (2 million relocations in
about 20 seconds), at the cost of replacing the parts of `ElfProgramBuilder`
that build memory and symbols:

- Memory is one block per `PT_LOAD` with a nonzero memory size, at its
  (prelink-adjusted) address plus the image-base adjustment, holding the file
  bytes and zeros past `p_filesz`. An EXTERNAL block of 8 bytes per undefined
  symbol follows at the next 4 KiB boundary. `getBlock` reports no block to the
  handler, so `applyComponentOffsetPointer` and the EXTERNAL bookmark, which are
  data-type markup rather than bytes, are not exercised.
- The symbol map holds the first of equal `ElfSymbol`s (Java `equals`): defined
  symbols at their adjusted value, `SHN_ABS` at `st_value`, undefined named
  symbols other than `_GLOBAL_OFFSET_TABLE_` in the EXTERNAL block (unless
  externals are left unresolved), `SHN_COMMON` unmapped.
- `getGOTValue()` is the adjusted `DT_PLTGOT`, else the address of the first
  `_GLOBAL_OFFSET_TABLE_` symbol; `allocateLinkageBlock` returns the next
  aligned range after every block. The `%got` block that `dispose()` would
  create is not built; its entries (symbol value to entry address) are reported.
- Relocation addresses are the image base plus `r_offset`. A table whose
  `sh_info` section is not allocated is skipped with Ghidra's "Failed to identify
  relocation base address" message, where Ghidra would use the OTHER space. An
  address outside every block fails as "Block is non-existent".
- Out of scope: relocatable (`ET_REL`) files, whose section placement belongs to
  the loader, ELF32 (x32) files, PT_LOAD segments over 256 MiB (1 GiB in total),
  overlapping or wrapping segments. Both sides reject these with the same code.
  Symbol-name repair (`replaceInvalidChars`) is exact for ASCII and the C1
  controls; beyond them Rust knows only the separator, format and private-use
  ranges listed in `src/lib.rs`, not Java's full Unicode category table.

## Verified checks

```bash
export JAVA_HOME=/usr/lib/jvm/java-25-openjdk-amd64   # Ghidra 12.3 needs JDK 25
python3 rust-port/x86-64-relocations/check.py --output /tmp/x86-64-relocations-NEW
```

It needs the Ghidra jars (`./gradlew jar generateLibraryDependencyMapping`); in a
git worktree without a build of its own, `oracle/run.py` uses the main checkout's
jars after checking that its copies of the pinned Java sources are identical
(or set `GHIDRA_BUILD`). `check.py` verifies the pinned sources in
`reference.json`, runs `cargo fmt --check` and the unit tests in debug and
release, compiles `oracle/X86_64RelocationOracle.java` against the jars, and
compares the Rust CLI with the original handler on every reported line:
per-relocation status and length, each memory write, the import log, loader
messages, bookmarks, console and stdout output, artificial relocation entries,
created symbols and `%got` entries.

Results on this branch:

- 213 synthetic inputs from `oracle/fixtures.py`, all identical to Java: 207
  run and 6 rejected by the model. They hold 10,098 relocations covering all 58
  type ids tested (every id the enum defines except `NONE`, plus five it does
  not) against every kind of symbol, REL and RELA addends, RELR tables, prelinked
  images, each `%got` situation (absent, undefined, zero, defined, `DT_PLTGOT`,
  exhausted, unplaceable, past 2^63), every relaxation form, unmapped and
  partially mapped targets, a table with no symbol table, a non-allocated target
  section and both escaping exceptions, plus 120 randomized files. Statuses:
  2,771 applied, 4,396 unsupported, 2,929 failures, 2 skipped.
- 1,119 real x86-64 ELF files from `/usr/lib/x86_64-linux-gnu` (`*.so*`) and
  `/usr/bin` (files over 64 MiB skipped), all identical to Java: 2,098,056
  relocations of types 1, 5, 6, 7, 8, 16, 17, 18, 36 and 37 (2,097,529 applied
  and 527 unsupported TLS/COPY), and again with externals left unresolved
  (1,950,411 applied, 147,118 failures, 527 unsupported).

Performance has not been measured for this component yet.
