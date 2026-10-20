// SPDX-License-Identifier: Apache-2.0
// Adapted from Ghidra ElfHeader.parseDynamicTable/parseStringTables/
// parseDynamicLibraryNames/parseSymbolTables, ElfDynamicTable and ElfDynamic.
//! The ELF dynamic table and what Ghidra finds through it: the dynamic string
//! table, `DT_NEEDED` library names and the dynamic symbol table, with its size
//! taken from `DT_HASH`, `DT_GNU_HASH` or `DT_GNU_XHASH`. Relocations, GNU
//! version tables, load adapters and Program creation are out of scope.
//!
//! Compatibility mode runs Ghidra's `parse()` steps up to the symbol tables:
//! program headers, section headers, the dynamic table (from `PT_DYNAMIC`, or a
//! lone `SHT_DYNAMIC` section), string tables, library names and symbol tables,
//! with Ghidra's warnings, `PRE` trailer address adjustment and zero-filled reads
//! past EOF. Strict mode rejects every input on which Ghidra would warn, guess or
//! read outside the file.

#![forbid(unsafe_code)]

pub use ghidra_elf::ParsePolicy;
use ghidra_elf_sections::{SectionHeader, SectionHeaders, parse_section_headers};
use ghidra_elf_segments::{ProgramHeader, parse_program_headers};
use ghidra_elf_symbols::{
    NO_SECTION, StringTable, SymbolTable, TableLayout, check_symbol_limits,
    decode_section_symbol_tables, decode_symbols, read_string, section_string_tables,
};
use std::borrow::Cow;
use std::fmt;

/// An explicit time/resource bound, not a limit of the ELF format.
pub const MAX_DYNAMIC_ENTRIES: usize = 65536;

pub const PT_LOAD: u32 = 1;
pub const PT_DYNAMIC: u32 = 2;
pub const SHT_NULL: u32 = 0;
pub const SHT_DYNAMIC: u32 = 6;
pub const DT_NULL: i32 = 0;
pub const DT_NEEDED: i32 = 1;
pub const DT_HASH: i32 = 4;
pub const DT_STRTAB: i32 = 5;
pub const DT_SYMTAB: i32 = 6;
pub const DT_STRSZ: i32 = 10;
pub const DT_SYMENT: i32 = 11;
pub const DT_GNU_XHASH: i32 = 0x6fff_fef4;
pub const DT_GNU_HASH: i32 = 0x6fff_fef5;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DynamicEntry {
    /// Ghidra keeps `d_tag` as an int: ELF64 tags are truncated to 32 bits.
    pub tag: i32,
    pub value: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DynamicSource {
    Segment,
    Section(u32),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DynamicTable {
    pub source: DynamicSource,
    /// File offset as Ghidra computed it; a negative Java long is kept as its
    /// two's-complement value.
    pub offset: u64,
    /// Address after `PRE` trailer adjustment.
    pub address: u64,
    /// Every entry up to and including the first `DT_NULL`.
    pub entries: Vec<DynamicEntry>,
}

impl DynamicTable {
    /// The first entry with this tag, as `getDynamicValue` returns it.
    pub fn value(&self, tag: i32) -> Option<u64> {
        self.entries
            .iter()
            .find(|entry| entry.tag == tag)
            .map(|entry| entry.value)
    }
    pub fn contains(&self, tag: i32) -> bool {
        self.value(tag).is_some()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorKind {
    ProgramHeaders(ghidra_elf_segments::ErrorKind),
    Sections(ghidra_elf_sections::ErrorKind),
    Symbols(ghidra_elf_symbols::ErrorKind),
    DynamicEntryLimit {
        limit: usize,
    },
    /// The GNU hash walk's region runs past EOF, so file size would not bound it.
    GnuHashRegionLimit,
    /// A dynamic-table read at a negative offset (Java IOException).
    InvalidDynamicOffset {
        entry: u32,
    },
    /// `ElfProgramHeader.getOffset(address)` on a segment with no file or memory
    /// size (Java UnsupportedOperationException).
    UnloadedSegment {
        address: u64,
    },
    /// A hash-table read at a negative offset (Java IOException).
    InvalidHashTableOffset,
    /// `DT_SYMENT` is zero (Java ArithmeticException).
    ZeroDynamicEntrySize,
    // Strict-only rejections.
    OffsetsRewritten,
    MultipleDynamicSegments,
    StrippedDynamicTable,
    DynamicSegmentNotLoaded,
    DynamicTableOutOfBounds,
    MissingDynamicValue {
        tag: i32,
    },
    StrippedDynamicAddress {
        tag: i32,
    },
    AddressNotLoaded {
        tag: i32,
        address: u64,
    },
    StringTableOutOfBounds,
    LibraryNameOutOfBounds {
        entry: u32,
    },
    UnterminatedLibraryName {
        entry: u32,
    },
    MissingStringTable,
    InvalidDynamicEntrySize {
        entry_size: u64,
    },
    InvalidHashTable,
    DynamicSymbolTableOutOfBounds,
}

impl ErrorKind {
    pub const fn name(self) -> &'static str {
        match self {
            Self::ProgramHeaders(error) => error.name(),
            Self::Sections(error) => error.name(),
            Self::Symbols(error) => error.name(),
            Self::DynamicEntryLimit { .. } => "DynamicEntryLimit",
            Self::GnuHashRegionLimit => "GnuHashRegionLimit",
            Self::InvalidDynamicOffset { .. } => "InvalidDynamicOffset",
            Self::UnloadedSegment { .. } => "UnloadedSegment",
            Self::InvalidHashTableOffset => "InvalidHashTableOffset",
            Self::ZeroDynamicEntrySize => "ZeroDynamicEntrySize",
            Self::OffsetsRewritten => "OffsetsRewritten",
            Self::MultipleDynamicSegments => "MultipleDynamicSegments",
            Self::StrippedDynamicTable => "StrippedDynamicTable",
            Self::DynamicSegmentNotLoaded => "DynamicSegmentNotLoaded",
            Self::DynamicTableOutOfBounds => "DynamicTableOutOfBounds",
            Self::MissingDynamicValue { .. } => "MissingDynamicValue",
            Self::StrippedDynamicAddress { .. } => "StrippedDynamicAddress",
            Self::AddressNotLoaded { .. } => "AddressNotLoaded",
            Self::StringTableOutOfBounds => "StringTableOutOfBounds",
            Self::LibraryNameOutOfBounds { .. } => "LibraryNameOutOfBounds",
            Self::UnterminatedLibraryName { .. } => "UnterminatedLibraryName",
            Self::MissingStringTable => "MissingStringTable",
            Self::InvalidDynamicEntrySize { .. } => "InvalidDynamicEntrySize",
            Self::InvalidHashTable => "InvalidHashTable",
            Self::DynamicSymbolTableOutOfBounds => "DynamicSymbolTableOutOfBounds",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseFailure {
    pub kind: ErrorKind,
    /// Warnings emitted before the failure, in order (the header's EI_DATA
    /// warning excepted).
    pub warnings: Vec<String>,
}

impl fmt::Display for ParseFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{:?}", self.kind)
    }
}

impl std::error::Error for ParseFailure {}

#[derive(Debug, Clone)]
pub struct ElfDynamic<'a> {
    pub program_headers: Vec<ProgramHeader>,
    pub sections: SectionHeaders<'a>,
    /// The `PRE` trailer's image base, which Ghidra adds to addresses.
    pub prelink_base: Option<u64>,
    pub dynamic_table: Option<DynamicTable>,
    /// Section string tables, then the dynamic one if no section matched it.
    pub string_tables: Vec<StringTable>,
    pub dynamic_string_table: Option<usize>,
    pub library_names: Vec<Cow<'a, str>>,
    /// Section symbol tables, then the dynamic one if no section matched it.
    pub symbol_tables: Vec<SymbolTable<'a>>,
    pub dynamic_symbol_table: Option<usize>,
    /// Every warning after the header's, in Ghidra's order.
    pub warnings: Vec<String>,
}

/// Ghidra's view of the file: header-endian reads that fail at negative offsets
/// and return zeros past EOF, and `PRE`-adjusted addresses.
struct Image<'a, 'b> {
    bytes: &'a [u8],
    bits: u8,
    little: bool,
    base: u64,
    phnum: u32,
    shnum: u32,
    program_headers: &'b [ProgramHeader],
    sections: &'b [SectionHeader],
}

fn is_invalid_offset(offset: u64, bits: u8) -> bool {
    (offset as i64) < 0 || (bits == 32 && offset == 0xffff_ffff)
}

fn prelink_base(bytes: &[u8], little: bool) -> Option<u64> {
    let length = bytes.len();
    if length < 8 {
        return None;
    }
    // readAsciiString(...).trim(): trailing NULs and code points <= U+0020 go.
    let tail = &bytes[length - 4..];
    let start = tail.iter().position(|&b| b > 0x20)?;
    let end = tail.iter().rposition(|&b| b > 0x20)? + 1;
    if &tail[start..end] != b"PRE" {
        return None;
    }
    let word: [u8; 4] = bytes[length - 8..length - 4].try_into().unwrap();
    Some(u64::from(if little {
        u32::from_le_bytes(word)
    } else {
        u32::from_be_bytes(word)
    }))
}

/// `getProgramLoadHeaderContaining`, with Java's signed comparisons.
fn load_containing(
    program_headers: &[ProgramHeader],
    base: u64,
    address: u64,
) -> Option<&ProgramHeader> {
    let address = address as i64;
    program_headers.iter().find(|header| {
        let start = base.wrapping_add(header.virtual_address) as i64;
        let end = (header.memory_size as i64)
            .wrapping_sub(1)
            .wrapping_add(start);
        header.segment_type == PT_LOAD && address >= start && address <= end
    })
}

/// `ElfProgramHeader.getOffset(address)` with the default load adapter.
fn load_offset(base: u64, header: &ProgramHeader, address: u64) -> Result<i64, ErrorKind> {
    if header.segment_type != PT_LOAD || header.file_size == 0 || header.memory_size == 0 {
        return Err(ErrorKind::UnloadedSegment { address });
    }
    // The addressable unit size is filesz / filesz, always 1.
    Ok(
        (address.wrapping_sub(base.wrapping_add(header.virtual_address)) as i64)
            .wrapping_add(header.offset as i64),
    )
}

impl ElfDynamic<'_> {
    /// An address as Ghidra adjusts it for the `PRE` trailer.
    pub fn adjust_address(&self, address: u64) -> u64 {
        self.prelink_base.unwrap_or(0).wrapping_add(address)
    }

    /// The `PT_LOAD` header Ghidra finds for an adjusted address.
    pub fn load_containing(&self, address: u64) -> Option<&ProgramHeader> {
        load_containing(
            &self.program_headers,
            self.prelink_base.unwrap_or(0),
            address,
        )
    }

    /// The file offset Ghidra computes for an adjusted address in `header`.
    pub fn load_offset(&self, header: &ProgramHeader, address: u64) -> Result<i64, ErrorKind> {
        load_offset(self.prelink_base.unwrap_or(0), header, address)
    }
}

impl Image<'_, '_> {
    fn adjust(&self, address: u64) -> u64 {
        self.base.wrapping_add(address)
    }

    fn read<const N: usize>(&self, offset: i64) -> Option<[u8; N]> {
        if offset < 0 {
            return None;
        }
        let mut out = [0u8; N];
        if let Ok(start) = usize::try_from(offset)
            && start < self.bytes.len()
        {
            let count = N.min(self.bytes.len() - start);
            out[..count].copy_from_slice(&self.bytes[start..start + count]);
        }
        Some(out)
    }

    fn read_u32(&self, offset: i64) -> Option<u32> {
        let word = self.read::<4>(offset)?;
        Some(if self.little {
            u32::from_le_bytes(word)
        } else {
            u32::from_be_bytes(word)
        })
    }

    fn read_u64(&self, offset: i64) -> Option<u64> {
        let word = self.read::<8>(offset)?;
        Some(if self.little {
            u64::from_le_bytes(word)
        } else {
            u64::from_be_bytes(word)
        })
    }

    fn in_file(&self, offset: i64, size: u64) -> bool {
        offset >= 0
            && (offset as u64)
                .checked_add(size)
                .is_some_and(|end| end <= self.bytes.len() as u64)
    }

    fn load_containing(&self, address: u64) -> Option<&ProgramHeader> {
        load_containing(self.program_headers, self.base, address)
    }

    fn load_offset(&self, header: &ProgramHeader, address: u64) -> Result<i64, ErrorKind> {
        load_offset(self.base, header, address)
    }

    /// `getMaxOffsetForLoadedRegionContaining(offset, 12)`.
    fn region_end(&self, offset: i64) -> i64 {
        if self.shnum != 0 {
            let last = offset.wrapping_add(11);
            for section in self.sections {
                if section.section_type == SHT_NULL
                    || is_invalid_offset(section.offset, self.bits)
                    || section.size == 0
                {
                    continue;
                }
                let start = section.offset as i64;
                let end = start.wrapping_add(section.size as i64).wrapping_sub(1);
                if offset >= start && last <= end {
                    return start.wrapping_add(section.size as i64).wrapping_sub(1);
                }
            }
        }
        if self.phnum != 0 {
            for header in self.program_headers {
                if header.segment_type != PT_LOAD || is_invalid_offset(header.offset, self.bits) {
                    continue;
                }
                let start = header.offset as i64;
                let end = start.wrapping_add((header.file_size as i64).wrapping_sub(1));
                if offset >= start && offset <= end {
                    return start.wrapping_add(header.file_size as i64).wrapping_sub(1);
                }
            }
        }
        -1
    }
}

pub fn parse_dynamic(bytes: &[u8], policy: ParsePolicy) -> Result<ElfDynamic<'_>, ParseFailure> {
    let mut warnings = Vec::new();
    let segments = parse_program_headers(bytes, policy).map_err(|error| ParseFailure {
        kind: ErrorKind::ProgramHeaders(error.kind),
        warnings: error.missing.iter().map(ToString::to_string).collect(),
    })?;
    warnings.extend(segments.missing().map(|missing| missing.to_string()));
    let program_headers: Vec<ProgramHeader> = segments.iter().collect();
    let strict = policy == ParsePolicy::Strict;
    if strict
        && !program_headers.is_empty()
        && program_headers
            .iter()
            .fold(0u64, |sum, header| sum.wrapping_add(header.file_size))
            == bytes.len() as u64
    {
        return Err(ParseFailure {
            kind: ErrorKind::OffsetsRewritten,
            warnings,
        });
    }
    let sections = match parse_section_headers(bytes, policy) {
        Ok(sections) => sections,
        Err(error) => {
            warnings.extend(error.missing.map(|missing| missing.to_string()));
            return Err(ParseFailure {
                kind: ErrorKind::Sections(error.kind),
                warnings,
            });
        }
    };
    warnings.extend(sections.missing().map(|missing| missing.to_string()));
    let records: Vec<SectionHeader> = sections.iter().collect();
    let header = *sections.header();
    let image = Image {
        bytes,
        bits: header.class_bits,
        little: header.header_little_endian,
        base: prelink_base(bytes, header.header_little_endian).unwrap_or(0),
        phnum: header.phnum,
        shnum: header.shnum,
        program_headers: &program_headers,
        sections: &records,
    };
    match parse_rest(&image, &sections, policy, &mut warnings) {
        Ok(parts) => Ok(ElfDynamic {
            prelink_base: prelink_base(bytes, image.little),
            program_headers,
            sections,
            dynamic_table: parts.dynamic_table,
            string_tables: parts.string_tables,
            dynamic_string_table: parts.dynamic_string_table,
            library_names: parts.library_names,
            symbol_tables: parts.symbol_tables,
            dynamic_symbol_table: parts.dynamic_symbol_table,
            warnings,
        }),
        Err(kind) => Err(ParseFailure { kind, warnings }),
    }
}

struct Parts<'a> {
    dynamic_table: Option<DynamicTable>,
    string_tables: Vec<StringTable>,
    dynamic_string_table: Option<usize>,
    library_names: Vec<Cow<'a, str>>,
    symbol_tables: Vec<SymbolTable<'a>>,
    dynamic_symbol_table: Option<usize>,
}

fn parse_rest<'a>(
    image: &Image<'a, '_>,
    sections: &SectionHeaders<'a>,
    policy: ParsePolicy,
    warnings: &mut Vec<String>,
) -> Result<Parts<'a>, ErrorKind> {
    let strict = policy == ParsePolicy::Strict;
    let dynamic_table = locate_dynamic_table(image, strict, warnings)?;

    // parseStringTables. -1 is Ghidra's "no address" value, and it is compared
    // like any other address.
    let mut string_address = u64::MAX;
    if let Some(table) = &dynamic_table {
        match table.value(DT_STRTAB) {
            Some(value) => string_address = image.adjust(value),
            None => {
                if strict {
                    return Err(ErrorKind::MissingDynamicValue { tag: DT_STRTAB });
                }
                warnings.push("ELF does not contain a dynamic string table (DT_STRTAB)".into());
            }
        }
    }
    let mut string_tables = section_string_tables(sections);
    // ElfStringTable.getAddressOffset adjusts the already adjusted section address.
    let mut dynamic_string_table = string_tables
        .iter()
        .rposition(|table| image.adjust(image.adjust(table.address)) == string_address);
    if dynamic_string_table.is_none() && string_address != u64::MAX {
        let table = dynamic_table.as_ref().unwrap();
        if let Some(strings) = dynamic_strings(image, table, string_address, strict, warnings)? {
            string_tables.push(strings);
            dynamic_string_table = Some(string_tables.len() - 1);
        }
    }
    if strict
        && let Some(index) = dynamic_string_table
        && !image.in_file(
            string_tables[index].offset as i64,
            string_tables[index].size,
        )
    {
        return Err(ErrorKind::StringTableOutOfBounds);
    }

    // parseDynamicLibraryNames.
    let mut library_names = Vec::new();
    if let Some(table) = &dynamic_table {
        let strings = dynamic_string_table.map(|index| string_tables[index]);
        for (position, entry) in table
            .entries
            .iter()
            .filter(|entry| entry.tag == DT_NEEDED)
            .enumerate()
        {
            let entry_index = position as u32;
            let name = match strings {
                Some(strings) if strict => {
                    if entry.value >= strings.size {
                        return Err(ErrorKind::LibraryNameOutOfBounds { entry: entry_index });
                    }
                    let start = (strings.offset + entry.value) as usize;
                    let end = (strings.offset + strings.size) as usize;
                    if !image.bytes[start..end].contains(&0) {
                        return Err(ErrorKind::UnterminatedLibraryName { entry: entry_index });
                    }
                    read_string(image.bytes, strings, entry.value as i64, warnings)
                }
                Some(strings) => read_string(image.bytes, strings, entry.value as i64, warnings),
                None if strict => return Err(ErrorKind::MissingStringTable),
                None => None,
            };
            library_names.push(name.unwrap_or_else(|| format!("UNK_LIB_NAME_{position}").into()));
        }
    }

    // parseSymbolTables, with the oracle's resource bounds checked first.
    let mut symbol_address = u64::MAX;
    let mut missing_symtab = false;
    if let Some(table) = &dynamic_table {
        match table.value(DT_SYMTAB) {
            Some(value) => symbol_address = image.adjust(value),
            None if strict => return Err(ErrorKind::MissingDynamicValue { tag: DT_SYMTAB }),
            None => missing_symtab = true,
        }
    }
    let matched = image.sections.iter().any(|section| {
        matches!(
            section.section_type,
            ghidra_elf_symbols::SHT_SYMTAB | ghidra_elf_symbols::SHT_DYNSYM
        ) && !is_invalid_offset(section.offset, image.bits)
            && image.adjust(section.address) == symbol_address
    });
    let plan = match &dynamic_table {
        Some(table) if !matched && symbol_address != u64::MAX => plan_dynamic_symbols(
            image,
            table,
            dynamic_string_table.map(|index| string_tables[index]),
            strict,
        ),
        _ => Plan::None(Vec::new()),
    };
    check_symbol_limits(sections, None).map_err(ErrorKind::Symbols)?;
    if let Plan::RegionLimit = plan {
        return Err(ErrorKind::GnuHashRegionLimit);
    }
    if let Plan::Table {
        entry_size, count, ..
    } = plan
        && entry_size != 0
    {
        let length = entry_size.wrapping_mul(count as i64 as u64);
        let count = (length as i64).wrapping_div(entry_size as i64) as i32;
        check_symbol_limits(sections, Some(count)).map_err(ErrorKind::Symbols)?;
    }

    if missing_symtab {
        warnings.push("ELF does not contain a dynamic symbol table (DT_SYMTAB)".into());
    }
    let mut symbol_tables =
        decode_section_symbol_tables(image.bytes, policy, sections, &string_tables, warnings)
            .map_err(ErrorKind::Symbols)?;
    let mut dynamic_symbol_table = symbol_tables
        .iter()
        .rposition(|table| image.adjust(table.address) == symbol_address);
    match plan {
        Plan::None(messages) => warnings.extend(messages),
        Plan::Fail(kind) => return Err(kind),
        Plan::RegionLimit => unreachable!(),
        Plan::Table {
            offset,
            address,
            entry_size,
            count,
        } => {
            if entry_size == 0 {
                return Err(ErrorKind::ZeroDynamicEntrySize);
            }
            let length = entry_size.wrapping_mul(count as i64 as u64);
            let symbol_count = (length as i64).wrapping_div(entry_size as i64) as i32;
            let strings_index = dynamic_string_table.unwrap();
            let strings = string_tables[strings_index];
            if strict && !image.in_file(offset, length) {
                return Err(ErrorKind::DynamicSymbolTableOutOfBounds);
            }
            let symbols = decode_symbols(
                image.bytes,
                policy,
                sections,
                TableLayout {
                    id: NO_SECTION,
                    offset: offset as u64,
                    entry_size,
                    symbol_count,
                },
                Some(strings),
                None,
                warnings,
            )
            .map_err(ErrorKind::Symbols)?;
            symbol_tables.push(SymbolTable {
                section_index: None,
                is_dynamic: true,
                offset: offset as u64,
                address,
                size: length,
                entry_size,
                symbol_count,
                string_table: Some(strings),
                string_table_index: Some(strings_index),
                extended_index_table: None,
                symbols,
            });
            dynamic_symbol_table = Some(symbol_tables.len() - 1);
        }
    }
    Ok(Parts {
        dynamic_table,
        string_tables,
        dynamic_string_table,
        library_names,
        symbol_tables,
        dynamic_symbol_table,
    })
}

/// `parseDynamicTable`.
fn locate_dynamic_table(
    image: &Image<'_, '_>,
    strict: bool,
    warnings: &mut Vec<String>,
) -> Result<Option<DynamicTable>, ErrorKind> {
    let segments: Vec<&ProgramHeader> = image
        .program_headers
        .iter()
        .filter(|header| header.segment_type == PT_DYNAMIC)
        .collect();
    if let [segment] = segments[..] {
        let address = image.adjust(segment.virtual_address);
        if address == 0 || segment.file_size == 0 {
            if strict {
                return Err(ErrorKind::StrippedDynamicTable);
            }
            warnings.push("ELF Dynamic table appears to have been stripped from binary".into());
            return Ok(None);
        }
        // p_offset may not point at the table, so it is found through p_vaddr.
        let load = match image.load_containing(address) {
            Some(load) => load,
            None if strict => return Err(ErrorKind::DynamicSegmentNotLoaded),
            None => segment,
        };
        let offset = (load.offset as i64)
            .wrapping_add(address.wrapping_sub(image.adjust(load.virtual_address)) as i64);
        return read_dynamic_table(image, DynamicSource::Segment, offset, address, strict)
            .map(Some);
    }
    if segments.len() > 1 {
        if strict {
            return Err(ErrorKind::MultipleDynamicSegments);
        }
        warnings.push("Multiple ELF Dynamic table program headers found".into());
    }
    let mut dynamic_sections = image
        .sections
        .iter()
        .enumerate()
        .filter(|(_, section)| section.section_type == SHT_DYNAMIC);
    if let (Some((index, section)), None) = (dynamic_sections.next(), dynamic_sections.next()) {
        let address = image.adjust(section.address);
        if let Some(load) = image.load_containing(address) {
            let offset = (load.offset as i64)
                .wrapping_add(address.wrapping_sub(image.adjust(load.virtual_address)) as i64);
            return read_dynamic_table(
                image,
                DynamicSource::Section(index as u32),
                offset,
                address,
                strict,
            )
            .map(Some);
        }
    }
    Ok(None)
}

/// `ElfDynamicTable`: entries up to and including `DT_NULL`, zero-filled past
/// EOF, so the table always ends by the end of the file.
fn read_dynamic_table(
    image: &Image<'_, '_>,
    source: DynamicSource,
    offset: i64,
    address: u64,
    strict: bool,
) -> Result<DynamicTable, ErrorKind> {
    let width: i64 = if image.bits == 64 { 8 } else { 4 };
    let mut entries = Vec::new();
    let mut position = offset;
    loop {
        let entry = entries.len() as u32;
        if entries.len() == MAX_DYNAMIC_ENTRIES {
            return Err(ErrorKind::DynamicEntryLimit {
                limit: MAX_DYNAMIC_ENTRIES,
            });
        }
        if strict && !image.in_file(position, 2 * width as u64) {
            return Err(ErrorKind::DynamicTableOutOfBounds);
        }
        let invalid = ErrorKind::InvalidDynamicOffset { entry };
        let value_position = position.wrapping_add(width);
        let (tag, value) = if width == 8 {
            let tag = image.read_u64(position).ok_or(invalid)? as i32;
            (tag, image.read_u64(value_position).ok_or(invalid)?)
        } else {
            let tag = image.read_u32(position).ok_or(invalid)? as i32;
            (
                tag,
                u64::from(image.read_u32(value_position).ok_or(invalid)?),
            )
        };
        entries.push(DynamicEntry { tag, value });
        if tag == DT_NULL {
            break;
        }
        position = value_position.wrapping_add(width);
    }
    Ok(DynamicTable {
        source,
        offset: offset as u64,
        address,
        entries,
    })
}

/// `parseDynamicStringTable`.
fn dynamic_strings(
    image: &Image<'_, '_>,
    table: &DynamicTable,
    address: u64,
    strict: bool,
    warnings: &mut Vec<String>,
) -> Result<Option<StringTable>, ErrorKind> {
    let Some(size) = table.value(DT_STRSZ) else {
        if strict {
            return Err(ErrorKind::MissingDynamicValue { tag: DT_STRSZ });
        }
        warnings.push("Failed to parse DT_STRTAB, missing dynamic dependency".into());
        return Ok(None);
    };
    if address == 0 {
        if strict {
            return Err(ErrorKind::StrippedDynamicAddress { tag: DT_STRTAB });
        }
        warnings.push(format!(
            "ELF Dynamic String Table of size {} appears to have been stripped from binary",
            size as i64
        ));
        return Ok(None);
    }
    let Some(load) = image.load_containing(address) else {
        if strict {
            return Err(ErrorKind::AddressNotLoaded {
                tag: DT_STRTAB,
                address,
            });
        }
        warnings.push(format!(
            "Failed to locate DT_STRTAB in memory at 0x{address:x}"
        ));
        return Ok(None);
    };
    let offset = image.load_offset(load, address)?;
    Ok(Some(StringTable {
        section_index: None,
        offset: offset as u64,
        address,
        size,
    }))
}

enum Plan {
    /// No dynamic symbol table, with the warnings Ghidra emits on the way.
    None(Vec<String>),
    Fail(ErrorKind),
    /// The oracle's bound on the GNU hash walk.
    RegionLimit,
    Table {
        offset: i64,
        address: u64,
        entry_size: u64,
        count: i32,
    },
}

/// `parseDynamicSymbolTable` up to the symbol count, without decoding records,
/// so the resource bounds can be checked first.
fn plan_dynamic_symbols(
    image: &Image<'_, '_>,
    table: &DynamicTable,
    strings: Option<StringTable>,
    strict: bool,
) -> Plan {
    let mut warnings = Vec::new();
    let fail = |kind| Plan::Fail(kind);
    let hash_type = [DT_HASH, DT_GNU_HASH, DT_GNU_XHASH]
        .into_iter()
        .find(|&tag| table.contains(tag));
    let (Some(raw), Some(entry_size), Some(hash_type)) =
        (table.value(DT_SYMTAB), table.value(DT_SYMENT), hash_type)
    else {
        if strict {
            return fail(ErrorKind::MissingDynamicValue {
                tag: if table.contains(DT_SYMENT) {
                    DT_HASH
                } else {
                    DT_SYMENT
                },
            });
        }
        if strings.is_some() {
            warnings.push("Failed to parse DT_SYMTAB, missing dynamic dependency".into());
        }
        return Plan::None(warnings);
    };
    if raw == 0 {
        if strict {
            return fail(ErrorKind::StrippedDynamicAddress { tag: DT_SYMTAB });
        }
        warnings.push(
            "ELF Dynamic String Table of size appears to have been stripped from binary".into(),
        );
    }
    if strings.is_none() {
        if strict {
            return fail(ErrorKind::MissingStringTable);
        }
        warnings.push("Failed to process DT_SYMTAB, missing dynamic string table".into());
        return Plan::None(warnings);
    }
    if raw == 0 {
        return Plan::None(warnings);
    }
    let address = image.adjust(raw);
    let hash_address = image.adjust(table.value(hash_type).unwrap());
    let canonical = if image.bits == 64 { 24 } else { 16 };
    if strict && entry_size != canonical {
        return fail(ErrorKind::InvalidDynamicEntrySize { entry_size });
    }
    let Some(load) = image.load_containing(address) else {
        if strict {
            return fail(ErrorKind::AddressNotLoaded {
                tag: DT_SYMTAB,
                address,
            });
        }
        warnings.push(format!(
            "Failed to locate DT_SYMTAB in memory at 0x{address:x}"
        ));
        return Plan::None(warnings);
    };
    let Some(hash_load) = image.load_containing(hash_address) else {
        if strict {
            return fail(ErrorKind::AddressNotLoaded {
                tag: hash_type,
                address: hash_address,
            });
        }
        warnings.push(format!(
            "Failed to locate DT_HASH, DT_GNU_HASH, or DT_GNU_XHASH in memory at 0x{hash_address:x}"
        ));
        return Plan::None(warnings);
    };
    let offset = match image.load_offset(load, address) {
        Ok(offset) => offset,
        Err(kind) => return fail(kind),
    };
    let hash_offset = match image.load_offset(hash_load, hash_address) {
        Ok(offset) => offset,
        Err(kind) => return fail(kind),
    };
    let read = |at: i64| {
        if strict && !image.in_file(at, 4) {
            return Err(ErrorKind::InvalidHashTable);
        }
        image
            .read_u32(at)
            .map(|value| value as i32)
            .ok_or(ErrorKind::InvalidHashTableOffset)
    };
    let count = match hash_type {
        DT_GNU_HASH => {
            let region_end = image.region_end(hash_offset);
            if region_end >= image.bytes.len() as i64 {
                return Plan::RegionLimit;
            }
            gnu_hash_count(image, hash_offset, region_end, &read, &mut warnings)
        }
        DT_GNU_XHASH => read(hash_offset)
            .and_then(|symbols| Ok(read(hash_offset.wrapping_add(8))?.wrapping_add(symbols))),
        _ => read(hash_offset.wrapping_add(4)),
    };
    let count = match count {
        Ok(count) => count,
        Err(kind) => return fail(kind),
    };
    if strict && (!warnings.is_empty() || count < 0) {
        return fail(ErrorKind::InvalidHashTable);
    }
    if count == 0 {
        return Plan::None(warnings);
    }
    Plan::Table {
        offset,
        address,
        entry_size,
        count,
    }
}

/// `deriveGnuHashDynamicSymbolCount`, with Java's int arithmetic. The caller
/// has checked that the region ends inside the file, which bounds both walks.
fn gnu_hash_count(
    image: &Image<'_, '_>,
    offset: i64,
    region_end: i64,
    read: &dyn Fn(i64) -> Result<i32, ErrorKind>,
    warnings: &mut Vec<String>,
) -> Result<i32, ErrorKind> {
    let buckets = read(offset)?;
    let symbol_base = read(offset.wrapping_add(4))?;
    let bloom_size = i64::from(read(offset.wrapping_add(8))? as u32);
    let word: i64 = if image.bits == 64 { 8 } else { 4 };
    if region_end <= 0 {
        warnings.push("Failed to idenitify loaded GNU Hash table".into());
        return Ok(0);
    }
    let error = "Error occured while inspecting GNU Hash table";
    let mut bucket = offset
        .wrapping_add(16)
        .wrapping_add(word.wrapping_mul(bloom_size));
    let mut max_symbol = 0i32;
    for _ in 0..buckets.max(0) {
        if bucket < offset || bucket > region_end {
            warnings.push(error.into());
            return Ok(0);
        }
        max_symbol = max_symbol.max(read(bucket)?);
        bucket = bucket.wrapping_add(4);
    }
    let chain_index = max_symbol.wrapping_sub(symbol_base);
    max_symbol = max_symbol.wrapping_add(1);
    let mut chain = bucket.wrapping_add(i64::from(4i32.wrapping_mul(chain_index)));
    loop {
        if chain < offset || chain > region_end {
            warnings.push(error.into());
            return Ok(0);
        }
        if read(chain)? & 1 != 0 {
            return Ok(max_symbol);
        }
        max_symbol = max_symbol.wrapping_add(1);
        chain = chain.wrapping_add(4);
    }
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

    const BASE: u64 = 0x40_0000;

    /// ELF64 LE shared object with no section headers: PT_LOAD over the first
    /// 0x800 bytes at BASE, PT_DYNAMIC at 0x500, .dynsym at 0x200, .dynstr at
    /// 0x300 and a hash table at 0x380.
    fn fixture(entries: &[(i64, u64)], hash: &[u32]) -> Vec<u8> {
        let mut bytes = vec![0u8; 0x800];
        bytes[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
        put(&mut bytes, 16, 2, 3);
        put(&mut bytes, 18, 2, 62);
        put(&mut bytes, 20, 4, 1);
        put(&mut bytes, 32, 8, 0x40);
        put(&mut bytes, 52, 2, 64);
        put(&mut bytes, 54, 2, 56);
        put(&mut bytes, 56, 2, 2);
        put(&mut bytes, 58, 2, 64);
        let segments: [(u32, u64, u64, u64); 2] = [
            (PT_LOAD, 0, BASE, 0x800),
            (PT_DYNAMIC, 0x500, BASE + 0x500, 16 * entries.len() as u64),
        ];
        for (i, (kind, offset, vaddr, size)) in segments.into_iter().enumerate() {
            let at = 0x40 + 56 * i;
            put(&mut bytes, at, 4, u64::from(kind));
            put(&mut bytes, at + 8, 8, offset);
            put(&mut bytes, at + 16, 8, vaddr);
            put(&mut bytes, at + 32, 8, size);
            put(&mut bytes, at + 40, 8, size);
        }
        let strings = b"\0libc.so.6\0puts\0";
        bytes[0x300..0x300 + strings.len()].copy_from_slice(strings);
        put(&mut bytes, 0x200 + 24, 4, 11);
        bytes[0x200 + 24 + 4] = 0x12;
        for (i, &word) in hash.iter().enumerate() {
            put(&mut bytes, 0x380 + 4 * i, 4, u64::from(word));
        }
        for (i, &(tag, value)) in entries.iter().enumerate() {
            put(&mut bytes, 0x500 + 16 * i, 8, tag as u64);
            put(&mut bytes, 0x500 + 16 * i + 8, 8, value);
        }
        bytes
    }

    fn entries(hash_tag: i32) -> Vec<(i64, u64)> {
        vec![
            (i64::from(DT_NEEDED), 1),
            (i64::from(hash_tag), BASE + 0x380),
            (i64::from(DT_STRTAB), BASE + 0x300),
            (i64::from(DT_SYMTAB), BASE + 0x200),
            (i64::from(DT_STRSZ), 16),
            (i64::from(DT_SYMENT), 24),
            (0, 0),
        ]
    }

    #[test]
    fn finds_tables_through_the_dynamic_table() {
        let bytes = fixture(&entries(DT_HASH), &[1, 2, 1, 0, 0]);
        for policy in [ParsePolicy::Strict, ParsePolicy::GhidraCompatible] {
            let parsed = parse_dynamic(&bytes, policy).unwrap();
            assert_eq!(parsed.dynamic_table.as_ref().unwrap().entries.len(), 7);
            assert_eq!(parsed.library_names, ["libc.so.6"]);
            assert_eq!(parsed.dynamic_string_table, Some(0));
            let table = &parsed.symbol_tables[parsed.dynamic_symbol_table.unwrap()];
            assert_eq!(table.section_index, None);
            assert_eq!(table.symbol_count, 2);
            assert_eq!(table.symbols[1].name.as_deref(), Some("puts"));
            assert!(parsed.warnings.is_empty());
        }
    }

    #[test]
    fn counts_symbols_from_the_gnu_hash_table() {
        // One bucket starting at symbol 1, one bloom word, chain ends at symbol 1.
        let bytes = fixture(&entries(DT_GNU_HASH), &[1, 1, 1, 6, 0, 0, 1, 1]);
        let parsed = parse_dynamic(&bytes, ParsePolicy::GhidraCompatible).unwrap();
        let table = &parsed.symbol_tables[parsed.dynamic_symbol_table.unwrap()];
        assert_eq!(table.symbol_count, 2);
        // Buckets past the end of the loaded region are Ghidra's warning.
        let unterminated = fixture(&entries(DT_GNU_HASH), &[1, 1, 0x1000, 6]);
        let parsed = parse_dynamic(&unterminated, ParsePolicy::GhidraCompatible).unwrap();
        assert_eq!(parsed.dynamic_symbol_table, None);
        assert_eq!(
            parsed.warnings,
            ["Error occured while inspecting GNU Hash table"]
        );
        assert_eq!(
            parse_dynamic(&unterminated, ParsePolicy::Strict)
                .unwrap_err()
                .kind,
            ErrorKind::InvalidHashTable
        );
    }

    #[test]
    fn truncates_elf64_tags_and_warns_like_ghidra() {
        // 0x1_0000_0000 truncates to DT_NULL and ends the table.
        let mut list = vec![(1i64 << 32, 7)];
        list.extend(entries(DT_HASH));
        let bytes = fixture(&list, &[1, 2]);
        let parsed = parse_dynamic(&bytes, ParsePolicy::GhidraCompatible).unwrap();
        assert_eq!(
            parsed.dynamic_table.unwrap().entries,
            [DynamicEntry { tag: 0, value: 7 }]
        );
        assert_eq!(
            parsed.warnings,
            [
                "ELF does not contain a dynamic string table (DT_STRTAB)",
                "ELF does not contain a dynamic symbol table (DT_SYMTAB)",
            ]
        );
        assert!(parsed.library_names.is_empty());
    }

    #[test]
    fn reads_the_prelink_trailer() {
        let mut bytes = vec![0u8; 16];
        bytes[8..12].copy_from_slice(&0x1000u32.to_le_bytes());
        bytes[12..].copy_from_slice(b"PRE ");
        assert_eq!(prelink_base(&bytes, true), Some(0x1000));
        bytes[12..].copy_from_slice(b"\x01PRE");
        assert_eq!(prelink_base(&bytes, true), Some(0x1000));
        bytes[12..].copy_from_slice(b"PREX");
        assert_eq!(prelink_base(&bytes, true), None);
    }
}
