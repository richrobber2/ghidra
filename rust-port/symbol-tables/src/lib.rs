// SPDX-License-Identifier: Apache-2.0
// Adapted from Ghidra ElfHeader.parseStringTables/parseSymbolTables,
// ElfStringTable, ElfSymbolTable and ElfSymbol.
//! Section-based ELF string and symbol tables. No Program, dynamic table,
//! hash-table symbol counting, relocation or symbol interpretation is performed.
//!
//! Compatibility mode follows Ghidra with no dynamic table parsed: every
//! `SHT_STRTAB` section is a string table, and every `SHT_SYMTAB`/`SHT_DYNSYM`
//! section with a valid offset is decoded with its linked string table (found by
//! file offset), its extended section-index table and zero-filled records past
//! EOF. Names are read up to NUL or EOF, decoded as Java decodes UTF-8 and
//! trimmed as `String.trim` does; unreadable names produce Ghidra's warnings.
//! Strict mode also requires canonical entry sizes, in-file tables, a linked
//! `SHT_STRTAB` section and every name inside its string table.

#![forbid(unsafe_code)]

pub use ghidra_elf::ParsePolicy;
use ghidra_elf_sections::{
    MissingHeaders, SectionHeader, SectionHeaders, java_utf8_lossy, parse_section_headers,
};
use std::borrow::Cow;
use std::fmt;

/// An explicit time/resource bound per table, not a limit of the ELF format.
pub const MAX_SYMBOLS: i32 = 1_000_000;
/// The same kind of bound on symbols plus index entries over all tables;
/// compatibility mode zero-fills tables past EOF, so file size does not bound it.
pub const MAX_TOTAL_SYMBOLS: i64 = 4_000_000;

pub const SHT_SYMTAB: u32 = 2;
pub const SHT_STRTAB: u32 = 3;
pub const SHT_DYNSYM: u32 = 11;
pub const SHT_SYMTAB_SHNDX: u32 = 18;
pub const STT_SECTION: u8 = 3;
pub const SHN_LORESERVE: u16 = 0xff00;
pub const SHN_XINDEX: u16 = 0xffff;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StringTable {
    pub section_index: u32,
    pub offset: u64,
    pub address: u64,
    pub size: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Symbol<'a> {
    pub index: u32,
    /// `None` where Ghidra leaves the name null: no string table, or a failed
    /// read (which also produces a warning).
    pub name: Option<Cow<'a, str>>,
    pub name_index: u32,
    pub value: u64,
    pub size: u64,
    pub info: u8,
    pub other: u8,
    pub section_index: u16,
    /// From the `SHT_SYMTAB_SHNDX` table when `section_index` is `SHN_XINDEX`.
    pub extended_section_index: u32,
}

impl Symbol<'_> {
    pub fn bind(&self) -> u8 {
        self.info >> 4
    }
    pub fn symbol_type(&self) -> u8 {
        self.info & 0xf
    }
    pub fn visibility(&self) -> u8 {
        self.other & 3
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtendedIndexTable {
    pub section_index: u32,
    pub entries: Vec<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SymbolTable<'a> {
    pub section_index: u32,
    /// Ghidra's test: the section is named `.dynsym`.
    pub is_dynamic: bool,
    pub offset: u64,
    pub address: u64,
    pub size: u64,
    pub entry_size: u64,
    /// `(int) (size / entry_size)` with Java's signed long arithmetic; it can be
    /// negative, in which case no symbols are decoded.
    pub symbol_count: i32,
    pub string_table: Option<StringTable>,
    pub extended_index_table: Option<ExtendedIndexTable>,
    pub symbols: Vec<Symbol<'a>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorKind {
    Sections(ghidra_elf_sections::ErrorKind),
    SymbolCountLimit {
        section: u32,
        count: i32,
        limit: i32,
    },
    TotalSymbolLimit {
        limit: i64,
    },
    /// `sh_link` does not name a section (Java ArrayIndexOutOfBoundsException).
    InvalidLink {
        section: u32,
        link: u32,
    },
    /// Java ArithmeticException.
    ZeroEntrySize {
        section: u32,
    },
    /// Java NegativeArraySizeException.
    NegativeIndexTableSize {
        section: u32,
    },
    /// A record field would be read at a negative offset (Java IOException).
    InvalidSymbolOffset {
        section: u32,
        symbol: u32,
    },
    NotStringTable {
        section: u32,
        link: u32,
    },
    MissingStringTable {
        section: u32,
    },
    InvalidEntrySize {
        section: u32,
        entry_size: u64,
    },
    TableOutOfBounds {
        section: u32,
    },
    NameOutOfBounds {
        section: u32,
        symbol: u32,
    },
    UnterminatedName {
        section: u32,
        symbol: u32,
    },
}

impl ErrorKind {
    pub const fn name(self) -> &'static str {
        match self {
            Self::Sections(error) => error.name(),
            Self::SymbolCountLimit { .. } => "SymbolCountLimit",
            Self::TotalSymbolLimit { .. } => "TotalSymbolLimit",
            Self::InvalidLink { .. } => "InvalidLink",
            Self::ZeroEntrySize { .. } => "ZeroEntrySize",
            Self::NegativeIndexTableSize { .. } => "NegativeIndexTableSize",
            Self::InvalidSymbolOffset { .. } => "InvalidSymbolOffset",
            Self::NotStringTable { .. } => "NotStringTable",
            Self::MissingStringTable { .. } => "MissingStringTable",
            Self::InvalidEntrySize { .. } => "InvalidEntrySize",
            Self::TableOutOfBounds { .. } => "TableOutOfBounds",
            Self::NameOutOfBounds { .. } => "NameOutOfBounds",
            Self::UnterminatedName { .. } => "UnterminatedName",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseFailure {
    pub kind: ErrorKind,
    /// The section table's missing-records warning, when it was reached.
    pub missing: Option<MissingHeaders>,
    /// String- and symbol-table warnings emitted before the failure.
    pub warnings: Vec<String>,
}

impl fmt::Display for ParseFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{:?}", self.kind)
    }
}

impl std::error::Error for ParseFailure {}

#[derive(Debug, Clone)]
pub struct ElfSymbols<'a> {
    pub sections: SectionHeaders<'a>,
    pub string_tables: Vec<StringTable>,
    pub symbol_tables: Vec<SymbolTable<'a>>,
    /// Ghidra's string- and symbol-table warnings, in emission order. Header
    /// and section-table warnings are on `sections`.
    pub warnings: Vec<String>,
}

fn is_invalid_offset(offset: u64, bits: u8) -> bool {
    (offset as i64) < 0 || (bits == 32 && offset == 0xffff_ffff)
}

fn is_symbol_table(section: &SectionHeader) -> bool {
    matches!(section.section_type, SHT_SYMTAB | SHT_DYNSYM)
}

/// Java's `(int) (size / entrySize)` on signed longs.
fn java_count(size: u64, entry_size: u64) -> i32 {
    (size as i64).wrapping_div(entry_size as i64) as i32
}

/// Bytes from `offset` up to NUL or EOF; Ghidra's unbounded reader zero-fills.
fn c_string(bytes: &[u8], offset: u64) -> &[u8] {
    let Some(tail) = usize::try_from(offset).ok().and_then(|o| bytes.get(o..)) else {
        return &[];
    };
    match tail.iter().position(|&b| b == 0) {
        Some(end) => &tail[..end],
        None => tail,
    }
}

/// Java `String.trim`: strips code points at or below U+0020 at both ends.
fn java_trim(text: Cow<'_, str>) -> Cow<'_, str> {
    let is_space = |c: char| c <= ' ';
    match text {
        Cow::Borrowed(text) => Cow::Borrowed(text.trim_matches(is_space)),
        Cow::Owned(text) => {
            let trimmed = text.trim_matches(is_space);
            if trimmed.len() == text.len() {
                Cow::Owned(text)
            } else {
                Cow::Owned(trimmed.to_owned())
            }
        }
    }
}

fn u16_at(record: &[u8], at: usize, little: bool) -> u16 {
    let value = record[at..at + 2].try_into().unwrap();
    if little {
        u16::from_le_bytes(value)
    } else {
        u16::from_be_bytes(value)
    }
}

fn u32_at(record: &[u8], at: usize, little: bool) -> u32 {
    let value = record[at..at + 4].try_into().unwrap();
    if little {
        u32::from_le_bytes(value)
    } else {
        u32::from_be_bytes(value)
    }
}

fn u64_at(record: &[u8], at: usize, little: bool) -> u64 {
    let value = record[at..at + 8].try_into().unwrap();
    if little {
        u64::from_le_bytes(value)
    } else {
        u64::from_be_bytes(value)
    }
}

/// `length` bytes at a non-negative offset, zero-filled past EOF.
fn padded<const N: usize>(bytes: &[u8], offset: u64) -> [u8; N] {
    let mut out = [0u8; N];
    if let Ok(start) = usize::try_from(offset)
        && start < bytes.len()
    {
        let count = N.min(bytes.len() - start);
        out[..count].copy_from_slice(&bytes[start..start + count]);
    }
    out
}

pub fn parse_symbols(bytes: &[u8], policy: ParsePolicy) -> Result<ElfSymbols<'_>, ParseFailure> {
    let sections = parse_section_headers(bytes, policy).map_err(|error| ParseFailure {
        kind: ErrorKind::Sections(error.kind),
        missing: error.missing,
        warnings: Vec::new(),
    })?;
    let missing = sections.missing();
    let mut warnings = Vec::new();
    let fail = |kind, warnings: &mut Vec<String>| ParseFailure {
        kind,
        missing,
        warnings: std::mem::take(warnings),
    };
    let header = *sections.header();
    let bits = header.class_bits;
    let little = header.header_little_endian;
    let strict = policy == ParsePolicy::Strict;
    let records: Vec<SectionHeader> = sections.iter().collect();
    let has_index_tables = sections.has_extended_symbol_index_table();

    // The first SHT_SYMTAB_SHNDX section linked to each section, found once so
    // many tables cannot make the lookup quadratic.
    let mut index_tables = vec![None; records.len()];
    if has_index_tables {
        for (index, section) in records.iter().enumerate().rev() {
            let link = section.link as usize;
            if section.section_type == SHT_SYMTAB_SHNDX
                && section.link as i32 > 0
                && link < records.len()
            {
                index_tables[link] = Some(index);
            }
        }
    }

    // Resource bounds, checked before any table is decoded (as the oracle does).
    let mut total = 0i64;
    for (index, section) in records.iter().enumerate() {
        if !is_symbol_table(section) || is_invalid_offset(section.offset, bits) {
            continue;
        }
        let mut counts = Vec::with_capacity(2);
        if section.entry_size != 0 {
            counts.push(java_count(section.size, section.entry_size));
        }
        if let Some(table) = index_tables[index] {
            counts.push(java_count(records[table].size, 4));
        }
        total += counts
            .iter()
            .map(|&count| i64::from(count.max(0)))
            .sum::<i64>();
        if let Some(&count) = counts.iter().find(|&&count| count > MAX_SYMBOLS) {
            return Err(fail(
                ErrorKind::SymbolCountLimit {
                    section: index as u32,
                    count,
                    limit: MAX_SYMBOLS,
                },
                &mut warnings,
            ));
        }
        if total > MAX_TOTAL_SYMBOLS {
            return Err(fail(
                ErrorKind::TotalSymbolLimit {
                    limit: MAX_TOTAL_SYMBOLS,
                },
                &mut warnings,
            ));
        }
    }

    let string_tables: Vec<StringTable> = records
        .iter()
        .enumerate()
        .filter(|(_, section)| section.section_type == SHT_STRTAB)
        .map(|(index, section)| StringTable {
            section_index: index as u32,
            offset: section.offset,
            address: section.address,
            size: section.size,
        })
        .collect();

    let file_length = bytes.len() as u64;
    let in_file = |offset: u64, size: u64| {
        offset
            .checked_add(size)
            .is_some_and(|end| end <= file_length)
    };
    let mut symbol_tables = Vec::new();
    for (index, section) in records.iter().enumerate() {
        if !is_symbol_table(section) {
            continue;
        }
        let table_index = index as u32;
        if is_invalid_offset(section.offset, bits) {
            if strict {
                return Err(fail(
                    ErrorKind::TableOutOfBounds {
                        section: table_index,
                    },
                    &mut warnings,
                ));
            }
            continue;
        }
        let Some(linked) = records.get(section.link as usize) else {
            return Err(fail(
                ErrorKind::InvalidLink {
                    section: table_index,
                    link: section.link,
                },
                &mut warnings,
            ));
        };
        let string_table = string_tables
            .iter()
            .find(|table| table.offset == linked.offset)
            .copied();
        if strict {
            let canonical = if bits == 64 { 24 } else { 16 };
            if linked.section_type != SHT_STRTAB {
                return Err(fail(
                    ErrorKind::NotStringTable {
                        section: table_index,
                        link: section.link,
                    },
                    &mut warnings,
                ));
            }
            match string_table {
                Some(table) if in_file(table.offset, table.size) => {}
                _ => {
                    return Err(fail(
                        ErrorKind::MissingStringTable {
                            section: table_index,
                        },
                        &mut warnings,
                    ));
                }
            }
            if section.entry_size != canonical {
                return Err(fail(
                    ErrorKind::InvalidEntrySize {
                        section: table_index,
                        entry_size: section.entry_size,
                    },
                    &mut warnings,
                ));
            }
            if section.size % canonical != 0 || !in_file(section.offset, section.size) {
                return Err(fail(
                    ErrorKind::TableOutOfBounds {
                        section: table_index,
                    },
                    &mut warnings,
                ));
            }
        }
        let is_dynamic = sections.name(index).as_deref() == Some(".dynsym");

        let mut extended_index_table = None;
        if let Some(table) = index_tables[index] {
            let index_section = records[table];
            let count = java_count(index_section.size, 4);
            let Ok(count) = usize::try_from(count) else {
                return Err(fail(
                    ErrorKind::NegativeIndexTableSize {
                        section: table as u32,
                    },
                    &mut warnings,
                ));
            };
            if strict && !in_file(index_section.offset, 4 * count as u64) {
                return Err(fail(
                    ErrorKind::TableOutOfBounds {
                        section: table as u32,
                    },
                    &mut warnings,
                ));
            }
            let mut entries = vec![0u32; count];
            let start = index_section.offset as i64;
            for (position, entry) in entries.iter_mut().enumerate() {
                let offset = start.wrapping_add(4 * position as i64);
                if offset < 0 {
                    warnings.push(format!(
                        "Failed to read symbol section index table at 0x{:x}: {}",
                        index_section.offset,
                        sections.name(table).unwrap()
                    ));
                    break;
                }
                *entry = u32_at(&padded::<4>(bytes, offset as u64), 0, little);
            }
            extended_index_table = Some(ExtendedIndexTable {
                section_index: table as u32,
                entries,
            });
        }

        if section.entry_size == 0 {
            return Err(fail(
                ErrorKind::ZeroEntrySize {
                    section: table_index,
                },
                &mut warnings,
            ));
        }
        let symbol_count = java_count(section.size, section.entry_size);
        let decoded = symbol_count.max(0) as u32;
        let last_field = if bits == 64 { 16 } else { 14 };
        let mut symbols = Vec::with_capacity(decoded as usize);
        for symbol in 0..decoded {
            let position = (section.offset as i64)
                .wrapping_add((section.entry_size as i64).wrapping_mul(i64::from(symbol)));
            if position < 0 || position > i64::MAX - last_field {
                return Err(fail(
                    ErrorKind::InvalidSymbolOffset {
                        section: table_index,
                        symbol,
                    },
                    &mut warnings,
                ));
            }
            let record = padded::<24>(bytes, position as u64);
            let (name_index, value, size, info, other, section_index) = if bits == 64 {
                (
                    u32_at(&record, 0, little),
                    u64_at(&record, 8, little),
                    u64_at(&record, 16, little),
                    record[4],
                    record[5],
                    u16_at(&record, 6, little),
                )
            } else {
                (
                    u32_at(&record, 0, little),
                    u64::from(u32_at(&record, 4, little)),
                    u64::from(u32_at(&record, 8, little)),
                    record[12],
                    record[13],
                    u16_at(&record, 14, little),
                )
            };
            let mut value = Symbol {
                index: symbol,
                name: None,
                name_index,
                value,
                size,
                info,
                other,
                section_index,
                extended_section_index: 0,
            };
            if name_index == 0
                && value.symbol_type() == STT_SECTION
                && section_index < SHN_LORESERVE
                && usize::from(section_index) < records.len()
            {
                value.name = sections.name(usize::from(section_index));
            }
            if section_index == SHN_XINDEX
                && let Some(table) = &extended_index_table
                && let Some(&entry) = table.entries.get(symbol as usize)
            {
                value.extended_section_index = entry;
            }
            symbols.push(value);
        }

        // Ghidra reads names sorted by signed st_name; warnings follow that order.
        if let Some(strings) = string_table {
            let mut order: Vec<u32> = (0..decoded).collect();
            order.sort_by_key(|&i| symbols[i as usize].name_index as i32);
            for i in order {
                let symbol = &symbols[i as usize];
                if symbol.name.is_some() {
                    continue;
                }
                let name = if strict {
                    let end = strings.offset + strings.size;
                    let start = strings.offset + u64::from(symbol.name_index);
                    if u64::from(symbol.name_index) >= strings.size {
                        return Err(fail(
                            ErrorKind::NameOutOfBounds {
                                section: table_index,
                                symbol: i,
                            },
                            &mut warnings,
                        ));
                    }
                    if !bytes[start as usize..end as usize].contains(&0) {
                        return Err(fail(
                            ErrorKind::UnterminatedName {
                                section: table_index,
                                symbol: i,
                            },
                            &mut warnings,
                        ));
                    }
                    Some(java_trim(java_utf8_lossy(c_string(bytes, start))))
                } else {
                    read_string(bytes, strings, symbol.name_index, &mut warnings)
                };
                symbols[i as usize].name = name;
            }
        }

        symbol_tables.push(SymbolTable {
            section_index: table_index,
            is_dynamic,
            offset: section.offset,
            address: section.address,
            size: section.size,
            entry_size: section.entry_size,
            symbol_count,
            string_table,
            extended_index_table,
            symbols,
        });
    }

    Ok(ElfSymbols {
        sections,
        string_tables,
        symbol_tables,
        warnings,
    })
}

/// `ElfStringTable.readString` with Ghidra's sign-extended `st_name`.
fn read_string<'a>(
    bytes: &'a [u8],
    table: StringTable,
    name_index: u32,
    warnings: &mut Vec<String>,
) -> Option<Cow<'a, str>> {
    let start = table.offset as i64;
    if start < 0 {
        return None;
    }
    let offset = i64::from(name_index as i32);
    let absolute = start.wrapping_add(offset);
    if offset >= table.size as i64 || absolute < 0 {
        warnings.push(format!(
            "Failed to read Elf String at offset 0x{:x} within String Table at offset 0x{:x}",
            offset, table.offset
        ));
        return None;
    }
    Some(java_trim(java_utf8_lossy(c_string(bytes, absolute as u64))))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn put(bytes: &mut Vec<u8>, at: usize, width: usize, value: u64) {
        if bytes.len() < at + width {
            bytes.resize(at + width, 0);
        }
        bytes[at..at + width].copy_from_slice(&value.to_le_bytes()[..width]);
    }

    /// ELF64 LE: strtab at 0x100, symtab at 0x200, sections at 0x400.
    /// Sections: null, .text, .symtab (link 3), .strtab, .shstrtab.
    fn fixture(symbols: &[(u32, u8, u16, u64)], strings: &[u8]) -> Vec<u8> {
        let mut bytes = vec![0u8; 0x400];
        bytes[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
        put(&mut bytes, 16, 2, 1);
        put(&mut bytes, 18, 2, 62);
        put(&mut bytes, 20, 4, 1);
        put(&mut bytes, 40, 8, 0x400);
        put(&mut bytes, 52, 2, 64);
        put(&mut bytes, 58, 2, 64);
        put(&mut bytes, 60, 2, 5);
        put(&mut bytes, 62, 2, 4);
        let shstr = b"\0.text\0.symtab\0.strtab\0.shstrtab\0";
        bytes[0x80..0x80 + shstr.len()].copy_from_slice(shstr);
        bytes[0x100..0x100 + strings.len()].copy_from_slice(strings);
        for (i, &(name, info, shndx, value)) in symbols.iter().enumerate() {
            let at = 0x200 + 24 * i;
            put(&mut bytes, at, 4, u64::from(name));
            bytes[at + 4] = info;
            put(&mut bytes, at + 6, 2, u64::from(shndx));
            put(&mut bytes, at + 8, 8, value);
        }
        let rows: [(u32, u32, u64, u64, u32, u64); 5] = [
            (0, 0, 0, 0, 0, 0),
            (1, 1, 0x300, 0x10, 0, 0),
            (7, 2, 0x200, 24 * symbols.len() as u64, 3, 24),
            (15, 3, 0x100, strings.len() as u64, 0, 0),
            (23, 3, 0x80, shstr.len() as u64, 0, 0),
        ];
        for (i, (name, kind, offset, size, link, entsize)) in rows.into_iter().enumerate() {
            let at = 0x400 + 64 * i;
            put(&mut bytes, at, 4, u64::from(name));
            put(&mut bytes, at + 4, 4, u64::from(kind));
            put(&mut bytes, at + 24, 8, offset);
            put(&mut bytes, at + 32, 8, size);
            put(&mut bytes, at + 40, 4, u64::from(link));
            put(&mut bytes, at + 56, 8, entsize);
        }
        bytes
    }

    #[test]
    fn decodes_symbols_names_and_section_symbols() {
        let bytes = fixture(
            &[
                (0, 0, 0, 0),
                (1, 0x12, 1, 0x1234),
                (0, 3, 1, 0),
                (6, 0x11, 1, 8),
            ],
            b"\0main\0 data \0",
        );
        for policy in [ParsePolicy::Strict, ParsePolicy::GhidraCompatible] {
            let parsed = parse_symbols(&bytes, policy).unwrap();
            assert_eq!(parsed.string_tables.len(), 2);
            let table = &parsed.symbol_tables[0];
            assert_eq!(table.section_index, 2);
            assert!(!table.is_dynamic);
            assert_eq!(table.symbol_count, 4);
            assert_eq!(table.string_table.unwrap().section_index, 3);
            let names: Vec<_> = table.symbols.iter().map(|s| s.name.as_deref()).collect();
            assert_eq!(names, [Some(""), Some("main"), Some(".text"), Some("data")]);
            assert_eq!(table.symbols[1].bind(), 1);
            assert_eq!(table.symbols[1].symbol_type(), 2);
            assert_eq!(table.symbols[1].value, 0x1234);
            assert!(parsed.warnings.is_empty());
        }
    }

    #[test]
    fn unreadable_names_warn_in_sorted_order_but_strict_rejects() {
        let bytes = fixture(&[(0, 0, 0, 0), (0x40, 0, 0, 0), (0x30, 0, 0, 0)], b"\0a\0");
        let parsed = parse_symbols(&bytes, ParsePolicy::GhidraCompatible).unwrap();
        assert_eq!(
            parsed.warnings,
            [
                "Failed to read Elf String at offset 0x30 within String Table at offset 0x100",
                "Failed to read Elf String at offset 0x40 within String Table at offset 0x100",
            ]
        );
        assert_eq!(parsed.symbol_tables[0].symbols[1].name, None);
        assert_eq!(
            parse_symbols(&bytes, ParsePolicy::Strict).unwrap_err().kind,
            ErrorKind::NameOutOfBounds {
                section: 2,
                symbol: 2
            }
        );
    }

    #[test]
    fn invalid_link_and_zero_entry_size_fail_like_java() {
        let mut bytes = fixture(&[(0, 0, 0, 0)], b"\0");
        put(&mut bytes, 0x400 + 128 + 40, 4, 9);
        assert_eq!(
            parse_symbols(&bytes, ParsePolicy::GhidraCompatible)
                .unwrap_err()
                .kind,
            ErrorKind::InvalidLink {
                section: 2,
                link: 9
            }
        );
        put(&mut bytes, 0x400 + 128 + 40, 4, 3);
        put(&mut bytes, 0x400 + 128 + 56, 8, 0);
        assert_eq!(
            parse_symbols(&bytes, ParsePolicy::GhidraCompatible)
                .unwrap_err()
                .kind,
            ErrorKind::ZeroEntrySize { section: 2 }
        );
    }

    #[test]
    fn java_trim_and_count_semantics() {
        assert_eq!(java_trim(Cow::Borrowed("\u{1} a \t")), "a");
        assert_eq!(java_trim(Cow::Owned("\u{a0}x".into())), "\u{a0}x");
        assert_eq!(java_count(u64::MAX, 24), 0);
        assert_eq!(java_count(i64::MIN as u64, u64::MAX), 0);
        assert_eq!(java_count(0x1_0000_0018, 1), 0x18);
    }
}
