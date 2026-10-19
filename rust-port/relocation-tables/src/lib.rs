// SPDX-License-Identifier: Apache-2.0
// Adapted from Ghidra ElfHeader.parseRelocationTables/parseDynamicRelocTable/
// parseJMPRelocTable/parseSectionBasedRelocationTable, ElfRelocationTable and
// ElfRelocation.
//! ELF relocation tables as Ghidra finds them: `DT_REL`, `DT_RELA`,
//! `DT_JMPREL` and `DT_RELR` through the dynamic table, then every relocation
//! section. Android packed tables, load adapters and relocation processing are
//! out of scope.
//!
//! Compatibility mode runs Ghidra's `parse()` steps up to the relocation
//! tables, with Ghidra's lookups, de-duplication by file offset, warnings and
//! zero-filled reads past EOF. Strict mode rejects every input on which Ghidra
//! would warn, guess or read outside the file.

#![forbid(unsafe_code)]

pub use ghidra_elf::ParsePolicy;
use ghidra_elf_dynamic::{DynamicTable, ElfDynamic, PT_LOAD, parse_dynamic};
use ghidra_elf_sections::SectionHeader;
use std::fmt;

/// Explicit time/resource bounds, not limits of the ELF format.
pub const MAX_RELOCATIONS: u64 = 1_000_000;
pub const MAX_TOTAL_RELOCATIONS: u64 = 4_000_000;

pub const DT_PLTRELSZ: i32 = 2;
pub const DT_RELA: i32 = 7;
pub const DT_RELASZ: i32 = 8;
pub const DT_RELAENT: i32 = 9;
pub const DT_REL: i32 = 17;
pub const DT_RELSZ: i32 = 18;
pub const DT_RELENT: i32 = 19;
pub const DT_PLTREL: i32 = 20;
pub const DT_JMPREL: i32 = 23;
pub const DT_RELRSZ: i32 = 35;
pub const DT_RELR: i32 = 36;
pub const DT_RELRENT: i32 = 37;
pub const DT_ANDROID_REL: i32 = 0x6000_000f;
pub const DT_ANDROID_RELSZ: i32 = 0x6000_0010;
pub const DT_ANDROID_RELA: i32 = 0x6000_0011;
pub const DT_ANDROID_RELASZ: i32 = 0x6000_0012;
pub const DT_ANDROID_RELR: i32 = 0x6fff_e000;
pub const DT_ANDROID_RELRSZ: i32 = 0x6fff_e001;
pub const DT_ANDROID_RELRENT: i32 = 0x6fff_e003;

pub const SHT_RELA: u32 = 4;
pub const SHT_REL: u32 = 9;
pub const SHT_RELR: u32 = 19;
pub const SHT_DYNSYM: u32 = 11;
pub const SHT_SYMTAB: u32 = 2;
pub const SHT_ANDROID_REL: u32 = 0x6000_0001;
pub const SHT_ANDROID_RELA: u32 = 0x6000_0002;
pub const SHT_ANDROID_RELR: u32 = 0x6fff_ff00;

fn tag_name(tag: i32) -> &'static str {
    match tag {
        DT_REL => "DT_REL",
        DT_RELA => "DT_RELA",
        DT_JMPREL => "DT_JMPREL",
        DT_RELR => "DT_RELR",
        DT_ANDROID_RELR => "DT_ANDROID_RELR",
        DT_ANDROID_REL => "DT_ANDROID_REL",
        DT_ANDROID_RELA => "DT_ANDROID_RELA",
        _ => "DT_UNKNOWN",
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TableFormat {
    Default,
    Relr,
}

impl TableFormat {
    /// Ghidra's `TableFormat` constant name.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Default => "DEFAULT",
            Self::Relr => "RELR",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Relocation {
    pub offset: u64,
    pub info: u64,
    pub addend: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelocationTable {
    /// `None` for a table found only through the dynamic table.
    pub section_index: Option<u32>,
    pub format: TableFormat,
    pub has_addend: bool,
    pub offset: u64,
    /// Raw `sh_addr` for a section table; the adjusted address Ghidra stored for
    /// a dynamic one.
    pub address: u64,
    pub size: u64,
    /// Ghidra's `entrySize` field: the standard size replaces a non-positive
    /// one in a standard table.
    pub entry_size: u64,
    /// Position in Ghidra's symbol-table list.
    pub symbol_table: Option<usize>,
    /// `sh_info`'s section, for a section table.
    pub relocated_section: Option<u32>,
    pub relocations: Vec<Relocation>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorKind {
    Dynamic(ghidra_elf_dynamic::ErrorKind),
    /// `DT_ANDROID_REL`/`RELA` or an `SHT_ANDROID_REL`/`RELA` section.
    AndroidRelocations,
    /// A RELR table whose entry size is not positive would never end.
    RelrEntrySize {
        entry_size: i64,
    },
    RelocationLimit {
        bound: u64,
        limit: u64,
    },
    TotalRelocationLimit {
        limit: u64,
    },
    /// A relocation read at a negative offset (Java IOException).
    InvalidRelocationOffset,
    /// More than one `.dynsym` section (Java RuntimeException).
    DuplicateDynamicSymbolSection,
    // Strict-only rejections.
    InvalidPltRel {
        value: u64,
    },
    MissingDynamicValue {
        tag: i32,
    },
    AddressNotLoaded {
        tag: i32,
        address: u64,
    },
    /// The dynamic address lies in a section that is not a relocation table, so
    /// Ghidra ignores the table.
    NotRelocationSection {
        tag: i32,
        section: u32,
    },
    InvalidLinkedSection {
        section: u32,
    },
    InvalidRelocationEntrySize {
        entry_size: u64,
    },
    RelocationSizeNotMultiple {
        size: u64,
    },
    EmptyRelrTable,
    RelocationTableOutOfBounds,
}

impl ErrorKind {
    pub const fn name(self) -> &'static str {
        match self {
            Self::Dynamic(error) => error.name(),
            Self::AndroidRelocations => "AndroidRelocations",
            Self::RelrEntrySize { .. } => "RelrEntrySize",
            Self::RelocationLimit { .. } => "RelocationLimit",
            Self::TotalRelocationLimit { .. } => "TotalRelocationLimit",
            Self::InvalidRelocationOffset => "InvalidRelocationOffset",
            Self::DuplicateDynamicSymbolSection => "DuplicateDynamicSymbolSection",
            Self::InvalidPltRel { .. } => "InvalidPltRel",
            Self::MissingDynamicValue { .. } => "MissingDynamicValue",
            Self::AddressNotLoaded { .. } => "AddressNotLoaded",
            Self::NotRelocationSection { .. } => "NotRelocationSection",
            Self::InvalidLinkedSection { .. } => "InvalidLinkedSection",
            Self::InvalidRelocationEntrySize { .. } => "InvalidRelocationEntrySize",
            Self::RelocationSizeNotMultiple { .. } => "RelocationSizeNotMultiple",
            Self::EmptyRelrTable => "EmptyRelrTable",
            Self::RelocationTableOutOfBounds => "RelocationTableOutOfBounds",
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
pub struct ElfRelocations<'a> {
    /// Everything up to the symbol tables; its `warnings` are moved to
    /// `warnings` below.
    pub dynamic: ElfDynamic<'a>,
    /// Ghidra's relocation-table list, in order.
    pub relocation_tables: Vec<RelocationTable>,
    /// Every warning after the header's, in Ghidra's order.
    pub warnings: Vec<String>,
}

fn is_invalid_offset(offset: u64, bits: u8) -> bool {
    (offset as i64) < 0 || (bits == 32 && offset == 0xffff_ffff)
}

/// `ElfRelocation.getStandardRelocationEntrySize`.
pub const fn standard_entry_size(is64: bool, addend: bool) -> u64 {
    match (is64, addend) {
        (true, true) => 24,
        (true, false) => 16,
        (false, true) => 12,
        (false, false) => 8,
    }
}

struct Candidate {
    relr: bool,
    addend: bool,
    size: i64,
    entry_size: i64,
}

/// The relocation count of a standard table, or an upper bound for RELR.
fn relocation_bound(is64: bool, candidate: &Candidate) -> Result<u64, ErrorKind> {
    let entry_size = candidate.entry_size;
    if candidate.relr {
        if entry_size <= 0 {
            return Err(ErrorKind::RelrEntrySize { entry_size });
        }
        let size = candidate.size;
        // Ghidra reads the first word whatever the size, then one per entrySize.
        let words = if size <= entry_size {
            1
        } else {
            1 + ((size - 1) / entry_size) as u64
        };
        let per_word = if entry_size == 8 { 63 } else { 31 };
        return Ok(words.saturating_mul(per_word));
    }
    let entry_size = if entry_size <= 0 {
        standard_entry_size(is64, candidate.addend) as i64
    } else {
        entry_size
    };
    Ok(((candidate.size / entry_size) as i32).max(0) as u64)
}

/// Oracle resource bounds, not Ghidra semantics: every table
/// `parseRelocationTables()` could build, from the dynamic values and the
/// section types alone.
fn check_relocation_limits(
    is64: bool,
    bits: u8,
    dynamic: Option<&DynamicTable>,
    sections: &[SectionHeader],
) -> Result<(), ErrorKind> {
    let mut candidates = Vec::new();
    if let Some(table) = dynamic {
        if table.contains(DT_ANDROID_REL) || table.contains(DT_ANDROID_RELA) {
            return Err(ErrorKind::AndroidRelocations);
        }
        let plt = table.value(DT_PLTREL);
        let plt_rela = plt == Some(DT_RELA as u64);
        let plt_entry = if plt_rela { DT_RELAENT } else { DT_RELENT };
        let groups = [
            (DT_REL, Some(DT_RELENT), DT_RELSZ, false, false, true),
            (DT_RELA, Some(DT_RELAENT), DT_RELASZ, true, false, true),
            (DT_JMPREL, None, DT_PLTRELSZ, plt_rela, false, plt.is_some()),
            (DT_RELR, Some(DT_RELRENT), DT_RELRSZ, false, true, true),
            (
                DT_ANDROID_RELR,
                Some(DT_ANDROID_RELRENT),
                DT_ANDROID_RELRSZ,
                false,
                true,
                true,
            ),
            (
                DT_JMPREL,
                Some(plt_entry),
                DT_PLTRELSZ,
                plt_rela,
                false,
                plt.is_some(),
            ),
        ];
        for (address, entry, size, addend, relr, enabled) in groups {
            if !enabled || !table.contains(address) {
                continue;
            }
            let Some(size) = table.value(size) else {
                continue;
            };
            let entry_size = match entry {
                Some(entry) => match table.value(entry) {
                    Some(value) => value as i64,
                    None => continue,
                },
                None => -1,
            };
            candidates.push(Candidate {
                relr,
                addend,
                size: size as i64,
                entry_size,
            });
        }
    }
    for section in sections {
        let kind = section.section_type;
        if kind == SHT_ANDROID_REL || kind == SHT_ANDROID_RELA {
            return Err(ErrorKind::AndroidRelocations);
        }
        if matches!(kind, SHT_REL | SHT_RELA | SHT_RELR | SHT_ANDROID_RELR)
            && !is_invalid_offset(section.offset, bits)
        {
            candidates.push(Candidate {
                relr: matches!(kind, SHT_RELR | SHT_ANDROID_RELR),
                addend: kind == SHT_RELA,
                size: section.size as i64,
                entry_size: section.entry_size as i64,
            });
        }
    }
    let mut total = 0u64;
    for candidate in &candidates {
        let bound = relocation_bound(is64, candidate)?;
        if bound > MAX_RELOCATIONS {
            return Err(ErrorKind::RelocationLimit {
                bound,
                limit: MAX_RELOCATIONS,
            });
        }
        total += bound;
        if total > MAX_TOTAL_RELOCATIONS {
            return Err(ErrorKind::TotalRelocationLimit {
                limit: MAX_TOTAL_RELOCATIONS,
            });
        }
    }
    Ok(())
}

/// The relocated and symbol-table sections, or Ghidra's NotFoundException text.
type Links = Result<(Option<usize>, Option<usize>), String>;

struct Context<'a, 'b> {
    bytes: &'a [u8],
    dynamic: &'b ElfDynamic<'a>,
    records: Vec<SectionHeader>,
    bits: u8,
    little: bool,
    strict: bool,
}

impl Context<'_, '_> {
    fn is64(&self) -> bool {
        self.bits == 64
    }

    /// Header-endian reads that fail at negative offsets and return zeros past
    /// EOF, as Ghidra's unlimited reader does.
    fn read<const N: usize>(&self, offset: i64) -> Result<[u8; N], ErrorKind> {
        if offset < 0 {
            return Err(ErrorKind::InvalidRelocationOffset);
        }
        let mut out = [0u8; N];
        if let Ok(start) = usize::try_from(offset)
            && start < self.bytes.len()
        {
            let count = N.min(self.bytes.len() - start);
            out[..count].copy_from_slice(&self.bytes[start..start + count]);
        }
        Ok(out)
    }

    fn read_u32(&self, offset: i64) -> Result<u32, ErrorKind> {
        let word = self.read::<4>(offset)?;
        Ok(if self.little {
            u32::from_le_bytes(word)
        } else {
            u32::from_be_bytes(word)
        })
    }

    fn read_u64(&self, offset: i64) -> Result<u64, ErrorKind> {
        let word = self.read::<8>(offset)?;
        Ok(if self.little {
            u64::from_le_bytes(word)
        } else {
            u64::from_be_bytes(word)
        })
    }

    fn in_file(&self, offset: u64, size: u64) -> bool {
        (offset as i64) >= 0
            && offset
                .checked_add(size)
                .is_some_and(|end| end <= self.bytes.len() as u64)
    }

    fn section_name(&self, index: usize) -> String {
        self.dynamic
            .sections
            .name(index)
            .map(|name| name.into_owned())
            .unwrap_or_else(|| "null".into())
    }

    /// `getSectionLoadHeaderContaining`, with Java's signed comparisons.
    fn section_containing(&self, address: u64) -> Option<usize> {
        let address = address as i64;
        self.records.iter().position(|section| {
            let start = self.dynamic.adjust_address(section.address) as i64;
            let end = start.wrapping_add(section.size as i64);
            section.is_alloc() && start <= address && address < end
        })
    }

    /// `getSymbolTable(section)`: the first table at the section's offset.
    fn symbol_table_at(&self, section: Option<usize>) -> Option<usize> {
        let offset = self.records[section?].offset;
        self.dynamic
            .symbol_tables
            .iter()
            .position(|table| table.offset == offset)
    }

    fn known(tables: &[RelocationTable], offset: u64) -> bool {
        tables.iter().any(|table| table.offset == offset)
    }

    fn check_table(
        &self,
        format: TableFormat,
        addend: bool,
        offset: u64,
        size: u64,
        entry_size: u64,
    ) -> Result<(), ErrorKind> {
        let canonical = match format {
            TableFormat::Default => standard_entry_size(self.is64(), addend),
            TableFormat::Relr => {
                if size == 0 {
                    return Err(ErrorKind::EmptyRelrTable);
                }
                if self.is64() { 8 } else { 4 }
            }
        };
        if entry_size != canonical {
            return Err(ErrorKind::InvalidRelocationEntrySize { entry_size });
        }
        if !size.is_multiple_of(entry_size) {
            return Err(ErrorKind::RelocationSizeNotMultiple { size });
        }
        if !self.in_file(offset, size) {
            return Err(ErrorKind::RelocationTableOutOfBounds);
        }
        Ok(())
    }

    /// `new ElfRelocationTable(...)` for a standard or RELR table.
    #[allow(clippy::too_many_arguments)]
    fn build(
        &self,
        section_index: Option<u32>,
        offset: u64,
        address: u64,
        size: u64,
        entry_size: u64,
        addend: bool,
        symbol_table: Option<usize>,
        relocated_section: Option<u32>,
        format: TableFormat,
    ) -> Result<RelocationTable, ErrorKind> {
        let entry_size = if format == TableFormat::Default && (entry_size as i64) <= 0 {
            standard_entry_size(self.is64(), addend)
        } else {
            entry_size
        };
        if self.strict {
            self.check_table(format, addend, offset, size, entry_size)?;
        }
        let relocations = match format {
            TableFormat::Default => self.standard(offset, size, entry_size, addend)?,
            TableFormat::Relr => self.relr(offset, size, entry_size)?,
        };
        Ok(RelocationTable {
            section_index,
            format,
            has_addend: addend,
            offset,
            address,
            size,
            entry_size,
            symbol_table,
            relocated_section,
            relocations,
        })
    }

    fn standard(
        &self,
        offset: u64,
        size: u64,
        entry_size: u64,
        addend: bool,
    ) -> Result<Vec<Relocation>, ErrorKind> {
        let count = ((size as i64) / (entry_size as i64)) as i32;
        let mut relocations = Vec::with_capacity(count.max(0) as usize);
        // Records are read back to back at the standard size, whatever entrySize says.
        let mut position = offset as i64;
        for _ in 0..count.max(0) {
            let relocation = if self.is64() {
                let r_offset = self.read_u64(position)?;
                let info = self.read_u64(position.wrapping_add(8))?;
                position = position.wrapping_add(16);
                let r_addend = if addend {
                    let value = self.read_u64(position)? as i64;
                    position = position.wrapping_add(8);
                    value
                } else {
                    0
                };
                Relocation {
                    offset: r_offset,
                    info,
                    addend: r_addend,
                }
            } else {
                let r_offset = u64::from(self.read_u32(position)?);
                let info = u64::from(self.read_u32(position.wrapping_add(4))?);
                position = position.wrapping_add(8);
                let r_addend = if addend {
                    let value = i64::from(self.read_u32(position)? as i32);
                    position = position.wrapping_add(4);
                    value
                } else {
                    0
                };
                Relocation {
                    offset: r_offset,
                    info,
                    addend: r_addend,
                }
            };
            relocations.push(relocation);
        }
        Ok(relocations)
    }

    /// `parseRelrRelocations`: words are 8 bytes when entrySize is 8 and 4
    /// otherwise, while offsets advance by entrySize.
    fn relr(&self, offset: u64, size: u64, entry_size: u64) -> Result<Vec<Relocation>, ErrorKind> {
        let mut relocations = Vec::new();
        let is32 = !self.is64();
        let mut add = |offset: u64| {
            relocations.push(Relocation {
                offset: if is32 {
                    u64::from(offset as u32)
                } else {
                    offset
                },
                info: 0,
                addend: 0,
            })
        };
        let mut position = offset as i64;
        let mut next = || -> Result<u64, ErrorKind> {
            let value = if entry_size == 8 {
                let value = self.read_u64(position)?;
                position = position.wrapping_add(8);
                value
            } else {
                let value = u64::from(self.read_u32(position)?);
                position = position.wrapping_add(4);
                value
            };
            Ok(value)
        };
        let mut remaining = size as i64;
        let mut current = next()?;
        add(current);
        current = current.wrapping_add(entry_size);
        remaining = remaining.wrapping_sub(entry_size as i64);
        while remaining > 0 {
            let value = next()?;
            if value & 1 == 1 {
                let base = current;
                let mut bits = value;
                let mut at = base;
                while bits != 0 {
                    bits >>= 1;
                    if bits & 1 != 0 {
                        add(at);
                    }
                    at = at.wrapping_add(entry_size);
                }
                current = base.wrapping_add(
                    entry_size
                        .wrapping_mul(8)
                        .wrapping_sub(1)
                        .wrapping_mul(entry_size),
                );
            } else {
                add(value);
                current = value.wrapping_add(entry_size);
            }
            remaining = remaining.wrapping_sub(entry_size as i64);
        }
        Ok(relocations)
    }

    /// `parseSectionBasedRelocationTable`.
    fn section_table(
        &self,
        index: usize,
        tables: &mut Vec<RelocationTable>,
        warnings: &mut Vec<String>,
    ) -> Result<(), ErrorKind> {
        let section = self.records[index];
        let kind = section.section_type;
        if !matches!(kind, SHT_REL | SHT_RELA | SHT_RELR | SHT_ANDROID_RELR) {
            return Ok(());
        }
        if Self::known(tables, section.offset) || is_invalid_offset(section.offset, self.bits) {
            return Ok(());
        }
        let count = self.records.len();
        let linked = |value: u32| -> Result<usize, String> {
            let signed = value as i32;
            if signed < 0 || signed as usize >= count {
                return Err(format!("invalid linked section index {signed}"));
            }
            Ok(signed as usize)
        };
        let resolved = (|| -> Result<Links, ErrorKind> {
            let relocated = if section.info != 0 {
                match linked(section.info) {
                    Ok(index) => Some(index),
                    Err(message) => return Ok(Err(message)),
                }
            } else {
                None
            };
            let symbols = if section.link == 0 {
                let mut matches =
                    (0..count).filter(|&position| self.section_name(position) == ".dynsym");
                let first = matches.next();
                if matches.next().is_some() {
                    return Err(ErrorKind::DuplicateDynamicSymbolSection);
                }
                first
            } else {
                match linked(section.link) {
                    Ok(position)
                        if matches!(
                            self.records[position].section_type,
                            SHT_DYNSYM | SHT_SYMTAB
                        ) =>
                    {
                        Some(position)
                    }
                    Ok(_) => {
                        return Ok(Err(format!(
                            "unexpected section type for section index {}",
                            section.link as i32
                        )));
                    }
                    Err(message) => return Ok(Err(message)),
                }
            };
            Ok(Ok((relocated, symbols)))
        })()?;
        let (relocated, symbols) = match resolved {
            Ok(found) => found,
            Err(message) => {
                if self.strict {
                    return Err(ErrorKind::InvalidLinkedSection {
                        section: index as u32,
                    });
                }
                warnings.push(format!(
                    "Failed to process relocation section {}: {message}",
                    self.section_name(index)
                ));
                return Ok(());
            }
        };
        let format = if matches!(kind, SHT_RELR | SHT_ANDROID_RELR) {
            TableFormat::Relr
        } else {
            TableFormat::Default
        };
        let table = self.build(
            Some(index as u32),
            section.offset,
            section.address,
            section.size,
            section.entry_size,
            kind == SHT_RELA,
            self.symbol_table_at(symbols),
            relocated.map(|position| position as u32),
            format,
        )?;
        tables.push(table);
        Ok(())
    }

    /// `parseDynamicRelocTable`.
    fn dynamic_table(
        &self,
        address_tag: i32,
        entry_tag: Option<i32>,
        size_tag: i32,
        addend: bool,
        tables: &mut Vec<RelocationTable>,
        warnings: &mut Vec<String>,
    ) -> Result<(), ErrorKind> {
        let Some(table) = &self.dynamic.dynamic_table else {
            return Ok(());
        };
        let Some(value) = table.value(address_tag) else {
            return Ok(());
        };
        if self.strict {
            for tag in [Some(size_tag), entry_tag].into_iter().flatten() {
                if !table.contains(tag) {
                    return Err(ErrorKind::MissingDynamicValue { tag });
                }
            }
        }
        let address = self.dynamic.adjust_address(value);
        if let Some(index) = self.section_containing(address) {
            let kind = self.records[index].section_type;
            if self.strict && !matches!(kind, SHT_REL | SHT_RELA | SHT_RELR | SHT_ANDROID_RELR) {
                return Err(ErrorKind::NotRelocationSection {
                    tag: address_tag,
                    section: index as u32,
                });
            }
            return self.section_table(index, tables, warnings);
        }
        let Some(load) = self.dynamic.load_containing(address) else {
            if self.strict {
                return Err(ErrorKind::AddressNotLoaded {
                    tag: address_tag,
                    address,
                });
            }
            warnings.push(format!(
                "Failed to locate {} in memory at 0x{address:x}",
                tag_name(address_tag)
            ));
            return Ok(());
        };
        debug_assert_eq!(load.segment_type, PT_LOAD);
        if is_invalid_offset(load.offset, self.bits) {
            return Ok(());
        }
        let offset = self
            .dynamic
            .load_offset(load, address)
            .map_err(ErrorKind::Dynamic)? as u64;
        if Self::known(tables, offset) {
            return Ok(());
        }
        let entry_size = match entry_tag {
            Some(tag) => match table.value(tag) {
                Some(value) => value,
                None => return Ok(()),
            },
            None => u64::MAX,
        };
        let Some(size) = table.value(size_tag) else {
            return Ok(());
        };
        let format = if matches!(address_tag, DT_RELR | DT_ANDROID_RELR) {
            TableFormat::Relr
        } else {
            TableFormat::Default
        };
        let built = self.build(
            None,
            offset,
            address,
            size,
            entry_size,
            addend,
            self.dynamic.dynamic_symbol_table,
            None,
            format,
        )?;
        tables.push(built);
        Ok(())
    }

    /// `parseRelocationTables`.
    fn parse(&self, warnings: &mut Vec<String>) -> Result<Vec<RelocationTable>, ErrorKind> {
        let mut tables = Vec::new();
        let plt = self
            .dynamic
            .dynamic_table
            .as_ref()
            .and_then(|table| table.value(DT_PLTREL));
        if self.strict
            && let Some(value) = plt
            && value != DT_RELA as u64
            && value != DT_REL as u64
        {
            return Err(ErrorKind::InvalidPltRel { value });
        }
        if self.strict
            && let Some(table) = &self.dynamic.dynamic_table
            && table.contains(DT_JMPREL)
            && plt.is_none()
        {
            return Err(ErrorKind::MissingDynamicValue { tag: DT_PLTREL });
        }
        let plt_rela = plt == Some(DT_RELA as u64);
        self.dynamic_table(
            DT_REL,
            Some(DT_RELENT),
            DT_RELSZ,
            false,
            &mut tables,
            warnings,
        )?;
        self.dynamic_table(
            DT_RELA,
            Some(DT_RELAENT),
            DT_RELASZ,
            true,
            &mut tables,
            warnings,
        )?;
        if plt.is_some() {
            self.dynamic_table(
                DT_JMPREL,
                None,
                DT_PLTRELSZ,
                plt_rela,
                &mut tables,
                warnings,
            )?;
        }
        // The Android packed tables are rejected before this point.
        self.dynamic_table(
            DT_RELR,
            Some(DT_RELRENT),
            DT_RELRSZ,
            false,
            &mut tables,
            warnings,
        )?;
        self.dynamic_table(
            DT_ANDROID_RELR,
            Some(DT_ANDROID_RELRENT),
            DT_ANDROID_RELRSZ,
            false,
            &mut tables,
            warnings,
        )?;
        // parseJMPRelocTable.
        if plt.is_some() {
            let entry = if plt_rela { DT_RELAENT } else { DT_RELENT };
            self.dynamic_table(
                DT_JMPREL,
                Some(entry),
                DT_PLTRELSZ,
                plt_rela,
                &mut tables,
                warnings,
            )?;
        }
        for index in 0..self.records.len() {
            self.section_table(index, &mut tables, warnings)?;
        }
        Ok(tables)
    }
}

pub fn parse_relocations(
    bytes: &[u8],
    policy: ParsePolicy,
) -> Result<ElfRelocations<'_>, ParseFailure> {
    let mut dynamic = parse_dynamic(bytes, policy).map_err(|error| ParseFailure {
        kind: ErrorKind::Dynamic(error.kind),
        warnings: error.warnings,
    })?;
    let mut warnings = std::mem::take(&mut dynamic.warnings);
    let header = *dynamic.sections.header();
    let records: Vec<SectionHeader> = dynamic.sections.iter().collect();
    let is64 = header.class_bits == 64;
    if let Err(kind) = check_relocation_limits(
        is64,
        header.class_bits,
        dynamic.dynamic_table.as_ref(),
        &records,
    ) {
        return Err(ParseFailure { kind, warnings });
    }
    let context = Context {
        bytes,
        dynamic: &dynamic,
        records,
        bits: header.class_bits,
        little: header.header_little_endian,
        strict: policy == ParsePolicy::Strict,
    };
    let tables = match context.parse(&mut warnings) {
        Ok(tables) => tables,
        Err(kind) => return Err(ParseFailure { kind, warnings }),
    };
    drop(context);
    Ok(ElfRelocations {
        dynamic,
        relocation_tables: tables,
        warnings,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn relr_context(bytes: &[u8]) -> Vec<Relocation> {
        // A minimal 64-bit little-endian ELF header is enough for parse_dynamic.
        let mut file = vec![0u8; 64];
        file[..4].copy_from_slice(b"\x7fELF");
        file[4] = 2;
        file[5] = 1;
        file[6] = 1;
        file[16] = 3;
        file[18] = 62;
        file[20] = 1;
        file[52] = 64;
        file[54] = 56;
        file[58] = 64;
        let start = file.len() as u64;
        file.extend_from_slice(bytes);
        let dynamic = parse_dynamic(&file, ParsePolicy::GhidraCompatible).unwrap();
        let context = Context {
            bytes: &file,
            dynamic: &dynamic,
            records: Vec::new(),
            bits: 64,
            little: true,
            strict: false,
        };
        context.relr(start, bytes.len() as u64, 8).unwrap()
    }

    #[test]
    fn relr_bitmaps_follow_the_address_entry() {
        let mut words = Vec::new();
        words.extend_from_slice(&0x1000u64.to_le_bytes());
        words.extend_from_slice(&0b1011u64.to_le_bytes());
        words.extend_from_slice(&0x2000u64.to_le_bytes());
        let offsets: Vec<u64> = relr_context(&words).iter().map(|r| r.offset).collect();
        assert_eq!(offsets, [0x1000, 0x1008, 0x1018, 0x2000]);
    }

    #[test]
    fn relr_reads_one_word_even_when_empty() {
        let offsets: Vec<u64> = relr_context(&[]).iter().map(|r| r.offset).collect();
        assert_eq!(offsets, [0]);
    }

    #[test]
    fn bounds_match_ghidra_counts() {
        let standard = Candidate {
            relr: false,
            addend: true,
            size: 48,
            entry_size: -1,
        };
        assert_eq!(relocation_bound(true, &standard), Ok(2));
        let truncated = Candidate {
            relr: false,
            addend: false,
            size: (1 << 32) * 16,
            entry_size: 16,
        };
        assert_eq!(relocation_bound(true, &truncated), Ok(0));
        let relr = Candidate {
            relr: true,
            addend: false,
            size: 17,
            entry_size: 8,
        };
        assert_eq!(relocation_bound(true, &relr), Ok(3 * 63));
        let zero = Candidate {
            relr: true,
            addend: false,
            size: 8,
            entry_size: 0,
        };
        assert_eq!(
            relocation_bound(true, &zero),
            Err(ErrorKind::RelrEntrySize { entry_size: 0 })
        );
    }
}
