//! A whole-file relocation run: Ghidra's parse up to the relocation tables,
//! then every relocation applied in table order through
//! [`crate::process_relocation`].
//!
//! The parts of Ghidra's loader the handler depends on are replaced by a
//! small, fixed model that the Java oracle implements identically:
//!
//! - Memory: one block per `PT_LOAD` with a nonzero memory size, at the
//!   prelink-adjusted `p_vaddr` plus the image-base adjustment, holding the
//!   file bytes (zeros past `p_filesz` or EOF). An `EXTERNAL` block of 8 bytes
//!   per external symbol follows at the next 4 KiB boundary. `getBlock` reports
//!   no block to the handler, so the component-offset pointer markup and the
//!   EXTERNAL bookmark of `R_X86_64_64` are not made.
//! - Symbols: the first of equal `ElfSymbol`s (Java `equals`) is mapped. An
//!   undefined named symbol other than `_GLOBAL_OFFSET_TABLE_` gets the next
//!   EXTERNAL slot unless externals are left unresolved, `SHN_ABS` maps to
//!   `st_value`, `SHN_COMMON` stays unmapped and every other symbol maps to
//!   its adjusted value.
//! - `getGOTValue()`: the adjusted `DT_PLTGOT`, else the mapped address of the
//!   first symbol named `_GLOBAL_OFFSET_TABLE_`.
//! - `allocateLinkageBlock`: the next aligned address after the highest block.
//! - Relocation addresses: image base plus `r_offset`. A table whose
//!   relocated section (`sh_info`) is not `SHF_ALLOC` is skipped with Ghidra's
//!   "Failed to identify relocation base address" message.
//! - The `%got` block itself (created on `dispose()`) is not built; its
//!   entries are reported instead.

use std::collections::{BTreeMap, HashMap, HashSet};

use ghidra_elf_relocations::{ElfRelocations, ParsePolicy, TableFormat, parse_relocations};

use crate::{
    Abort, EM_X86_64, Environment, GOT_SYMBOL_NAME, MemoryError, RELR_RELOCATION_TYPE, Record,
    RelocationResult, SymbolInfo, format_address, mark_relocation_error, process_relocation,
    replace_invalid_chars, requires_got_entry,
};

pub const PT_LOAD: u32 = 1;
pub const ET_REL: u16 = 1;
pub const SHN_UNDEF: u16 = 0;
pub const SHN_ABS: u16 = 0xfff1;
pub const SHN_COMMON: u16 = 0xfff2;
pub const DT_PLTGOT: i32 = 3;
pub const DT_GNU_PRELINKED: i32 = 0x6fff_fdf5;
pub const SHF_ALLOC: u64 = 2;
/// Model bound on one block's size, and on all blocks together.
pub const MAX_BLOCK_BYTES: u64 = 256 << 20;
pub const MAX_TOTAL_BLOCK_BYTES: u64 = 1 << 30;
/// `ElfLoadAdapter.getLinkageBlockAlignment()`.
pub const LINKAGE_ALIGNMENT: u64 = 0x1000;
pub const EXTERNAL_SLOT: u64 = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Options {
    /// `getImageBaseWordAdjustmentOffset()`.
    pub adjust: u64,
    /// Leave undefined symbols out of the symbol map.
    pub unresolved_externals: bool,
}

/// Inputs the model does not run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Rejection {
    Parse(String),
    NotElf64,
    NotX86_64,
    Relocatable,
    SegmentTooLarge,
    SegmentWraps,
    OverlappingSegments,
    NoExternalRoom,
}

impl Rejection {
    pub fn code(&self) -> &'static str {
        match self {
            Self::Parse(_) => "parse",
            Self::NotElf64 => "not-elf64",
            Self::NotX86_64 => "not-x86-64",
            Self::Relocatable => "relocatable",
            Self::SegmentTooLarge => "segment-too-large",
            Self::SegmentWraps => "segment-wraps",
            Self::OverlappingSegments => "overlapping-segments",
            Self::NoExternalRoom => "no-external-room",
        }
    }
}

/// Everything one run reports, as lines both implementations format alike.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Outcome {
    /// `table index address type status length` per recorded relocation.
    pub relocations: Vec<String>,
    pub status_counts: BTreeMap<&'static str, u64>,
    /// Recorded relocations per type id, after the RELR type is set.
    pub type_counts: BTreeMap<u32, u64>,
    /// `address bytes` for every successful memory write, in order.
    pub writes: Vec<String>,
    /// The import `MessageLog`.
    pub log: Vec<String>,
    /// `ElfLoadHelper.log` and the loader loop's own messages.
    pub loader_log: Vec<String>,
    pub bookmarks: Vec<String>,
    /// `Msg` output.
    pub console: Vec<String>,
    /// `System.out` output (duplicate GOT symbol values).
    pub stdout: Vec<String>,
    pub artificial: Vec<String>,
    pub created_symbols: Vec<String>,
    /// `not-attempted`, `failed` or the `%got` address.
    pub got_allocation: String,
    /// `symbol-value entry-address` per `gotMap` entry, by value.
    pub got_entries: Vec<String>,
    /// An exception that ended the run, as `Class: message`.
    pub aborted: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct SymbolKey {
    info: u8,
    name: u32,
    other: u8,
    shndx: u16,
    size: u64,
    value: u64,
    index: u32,
}

struct Sym {
    key: SymbolKey,
    name: Option<String>,
}

struct Block {
    start: u64,
    data: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Slot {
    Null,
    NoAddress,
    At(u64),
}

struct Table {
    symbol_table: Option<usize>,
    format: TableFormat,
    section_index: Option<u32>,
    relocated_section: Option<u32>,
    address: u64,
    records: Vec<Record>,
}

struct Session {
    adjust: u64,
    prelink: u64,
    prelinked: bool,
    relocatable: bool,
    pltgot: Option<u64>,
    symbols: Vec<Sym>,
    tables: Vec<Vec<usize>>,
    symbol_map: HashMap<SymbolKey, u64>,
    got_symbol: Option<usize>,
    current: Option<usize>,
    blocks: Vec<Block>,
    external: Option<(u64, u64)>,
    linkage_top: u128,
    reloc_tables: Vec<Table>,
    allocated: Slot,
    next: Slot,
    limits: Option<(u64, u64)>,
    got_map: Option<HashMap<u64, Slot>>,
    out: Outcome,
}

fn align_up(value: u128, alignment: u64) -> u128 {
    let alignment = u128::from(alignment);
    value.div_ceil(alignment) * alignment
}

fn hex_bytes(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Runs every relocation of an ELF64 x86-64 file through the handler.
pub fn apply_file(bytes: &[u8], options: &Options) -> Result<Outcome, Rejection> {
    let parsed = parse_relocations(bytes, ParsePolicy::GhidraCompatible)
        .map_err(|error| Rejection::Parse(error.to_string()))?;
    let mut session = Session::new(bytes, &parsed, options)?;
    session.run(&parsed);
    Ok(session.out)
}

impl Session {
    fn new(
        bytes: &[u8],
        parsed: &ElfRelocations<'_>,
        options: &Options,
    ) -> Result<Self, Rejection> {
        let dynamic = &parsed.dynamic;
        let header = dynamic.sections.header();
        if header.class_bits != 64 {
            return Err(Rejection::NotElf64);
        }
        if header.machine != EM_X86_64 {
            return Err(Rejection::NotX86_64);
        }
        if header.elf_type == ET_REL {
            return Err(Rejection::Relocatable);
        }
        let adjust = options.adjust;
        let prelink = dynamic.prelink_base.unwrap_or(0);

        // Memory blocks.
        let mut blocks = Vec::new();
        let mut total = 0u64;
        for segment in &dynamic.program_headers {
            if segment.segment_type != PT_LOAD || segment.memory_size == 0 {
                continue;
            }
            if segment.memory_size > MAX_BLOCK_BYTES {
                return Err(Rejection::SegmentTooLarge);
            }
            total += segment.memory_size;
            if total > MAX_TOTAL_BLOCK_BYTES {
                return Err(Rejection::SegmentTooLarge);
            }
            let start = dynamic
                .adjust_address(segment.virtual_address)
                .wrapping_add(adjust);
            if u128::from(start) + u128::from(segment.memory_size) > 1u128 << 64 {
                return Err(Rejection::SegmentWraps);
            }
            let mut data = vec![0u8; segment.memory_size as usize];
            let count = segment.file_size.min(segment.memory_size);
            if segment.offset < bytes.len() as u64 {
                let from = segment.offset as usize;
                let available = (bytes.len() - from) as u64;
                let count = count.min(available) as usize;
                data[..count].copy_from_slice(&bytes[from..from + count]);
            }
            blocks.push(Block { start, data });
        }
        let mut ranges: Vec<(u128, u128)> = blocks
            .iter()
            .map(|block| {
                let start = u128::from(block.start);
                (start, start + block.data.len() as u128)
            })
            .collect();
        ranges.sort();
        if ranges.windows(2).any(|pair| pair[1].0 < pair[0].1) {
            return Err(Rejection::OverlappingSegments);
        }
        let top = ranges.iter().map(|range| range.1).max().unwrap_or(0);

        // Symbols, with the null symbol of a table-less relocation table first.
        let mut symbols = vec![Sym {
            key: SymbolKey {
                info: 0,
                name: 0,
                other: 0,
                shndx: 0,
                size: 0,
                value: 0,
                index: 0,
            },
            name: Some(String::new()),
        }];
        let mut tables = Vec::new();
        let mut got_symbol = None;
        let mut pending = Vec::new();
        for table in &dynamic.symbol_tables {
            let mut ids = Vec::with_capacity(table.symbols.len());
            for symbol in &table.symbols {
                let id = symbols.len();
                let name = symbol.name.as_deref().map(str::to_owned);
                if got_symbol.is_none() && name.as_deref() == Some(GOT_SYMBOL_NAME) {
                    got_symbol = Some(id);
                }
                let key = SymbolKey {
                    info: symbol.info,
                    name: symbol.name_index,
                    other: symbol.other,
                    shndx: symbol.section_index,
                    size: symbol.size,
                    value: symbol.value,
                    index: symbol.index,
                };
                pending.push((key, name.clone()));
                symbols.push(Sym { key, name });
                ids.push(id);
            }
            tables.push(ids);
        }
        let mut symbol_map = HashMap::new();
        let external_start = align_up(top, LINKAGE_ALIGNMENT);
        let mut external_count = 0u64;
        for (key, name) in pending {
            if symbol_map.contains_key(&key) {
                continue;
            }
            match key.shndx {
                SHN_UNDEF => {
                    let named = name
                        .as_deref()
                        .is_some_and(|text| !text.is_empty() && text != GOT_SYMBOL_NAME);
                    if named && !options.unresolved_externals {
                        let address = external_start + u128::from(external_count * EXTERNAL_SLOT);
                        symbol_map.insert(key, address as u64);
                        external_count += 1;
                    }
                }
                SHN_ABS => {
                    symbol_map.insert(key, key.value);
                }
                SHN_COMMON => {}
                _ => {
                    symbol_map.insert(key, prelink.wrapping_add(key.value).wrapping_add(adjust));
                }
            }
        }
        let mut external = None;
        let mut linkage_top = top;
        if external_count > 0 {
            let length = external_count * EXTERNAL_SLOT;
            let end = external_start + u128::from(length);
            if end > 1u128 << 64 {
                return Err(Rejection::NoExternalRoom);
            }
            let start = external_start as u64;
            blocks.push(Block {
                start,
                data: vec![0; length as usize],
            });
            external = Some((start, length));
            linkage_top = end;
        }

        let reloc_tables = parsed
            .relocation_tables
            .iter()
            .map(|table| Table {
                symbol_table: table.symbol_table,
                format: table.format,
                section_index: table.section_index,
                relocated_section: table.relocated_section,
                address: match table.section_index {
                    Some(_) => dynamic.adjust_address(table.address),
                    None => table.address,
                },
                records: table
                    .relocations
                    .iter()
                    .map(|r| Record {
                        offset: r.offset,
                        info: r.info,
                        addend: r.addend,
                        has_addend: table.has_addend,
                    })
                    .collect(),
            })
            .collect();
        let pltgot = dynamic
            .dynamic_table
            .as_ref()
            .and_then(|t| t.value(DT_PLTGOT));
        let prelinked = dynamic.prelink_base.is_some()
            || dynamic
                .dynamic_table
                .as_ref()
                .is_some_and(|t| t.contains(DT_GNU_PRELINKED));
        Ok(Self {
            adjust,
            prelink,
            prelinked,
            relocatable: header.elf_type == ET_REL,
            pltgot: pltgot.map(|value| dynamic.adjust_address(value).wrapping_add(adjust)),
            symbols,
            tables,
            symbol_map,
            got_symbol,
            current: None,
            blocks,
            external,
            linkage_top,
            reloc_tables,
            allocated: Slot::Null,
            next: Slot::Null,
            limits: None,
            got_map: None,
            out: Outcome::default(),
        })
    }

    fn mapped(&self, address: u64) -> Option<(usize, usize)> {
        self.blocks.iter().enumerate().find_map(|(index, block)| {
            let delta = address.wrapping_sub(block.start);
            (delta < block.data.len() as u64).then_some((index, delta as usize))
        })
    }

    fn check(&self, address: u64, length: usize) -> Result<(), MemoryError> {
        for i in 0..length as u64 {
            let at = address.wrapping_add(i);
            if self.mapped(at).is_none() {
                return Err(MemoryError(format!(
                    "Address {} does not exist in memory",
                    format_address(at)
                )));
            }
        }
        Ok(())
    }

    /// The loader loop: `ElfProgramBuilder.processRelocationTable(Entries)`.
    fn run(&mut self, parsed: &ElfRelocations<'_>) {
        let sections = &parsed.dynamic.sections;
        let base = self.prelink.wrapping_add(self.adjust);
        for t in 0..self.reloc_tables.len() {
            let (symbol_table, format, section_index, relocated, address) = {
                let table = &self.reloc_tables[t];
                (
                    table.symbol_table,
                    table.format,
                    table.section_index,
                    table.relocated_section,
                    table.address,
                )
            };
            if let Some(index) = relocated {
                let alloc = sections
                    .get(index as usize)
                    .is_some_and(|section| section.flags & SHF_ALLOC != 0);
                if !alloc {
                    let name = sections.name(index as usize).unwrap_or_default();
                    self.out.loader_log.push(format!(
                        "Failed to identify relocation base address for relocation table 0x{} [section: {name}]",
                        address as i64
                    ));
                    continue;
                }
            }
            self.current = symbol_table;
            let missing = symbol_table.is_none()
                && match section_index {
                    None => true,
                    Some(index) => sections.get(index as usize).is_none_or(|s| s.link != 0),
                };
            if missing {
                let table_name = section_index
                    .and_then(|index| sections.name(index as usize))
                    .map_or_else(|| "dynamic".to_owned(), |name| name.into_owned());
                let base_name = relocated
                    .and_then(|index| sections.name(index as usize))
                    .map_or_else(|| "PT_LOAD".to_owned(), |name| name.into_owned());
                self.out.loader_log.push(format!(
                    "Unable to apply {table_name} relocations affecting {base_name} due to missing symbol table"
                ));
            }
            let relr = format == TableFormat::Relr;
            for i in 0..self.reloc_tables[t].records.len() {
                let mut record = self.reloc_tables[t].records[i];
                let mut type_id = record.type_id();
                if type_id == 0 && !relr {
                    continue;
                }
                let symbol_index = record.symbol_index();
                let symbol_name = replace_invalid_chars(
                    match symbol_table {
                        Some(_) => self.symbol_name(symbol_index),
                        None => Some(String::new()),
                    }
                    .as_deref(),
                );
                let address = base.wrapping_add(record.offset);
                if relr {
                    type_id = RELR_RELOCATION_TYPE;
                    record.set_type(type_id);
                    self.reloc_tables[t].records[i] = record;
                }
                let mut result = RelocationResult::SKIPPED;
                let mut abort = None;
                if missing {
                    result = RelocationResult::FAILURE;
                    mark_relocation_error(
                        self,
                        address,
                        type_id,
                        symbol_name.as_deref(),
                        -1,
                        "Missing symbol table",
                    );
                } else if self.mapped(address).is_none() {
                    result = RelocationResult::FAILURE;
                    self.out.loader_log.push(format!(
                        "Unable to perform relocation: Type = {type_id} (0x{:x}) at {} (Symbol = {}) - Block is non-existent",
                        i64::from(type_id) as u64,
                        format_address(address),
                        symbol_name.as_deref().unwrap_or("null")
                    ));
                } else {
                    match process_relocation(self, &record, address) {
                        Ok(value) => result = value,
                        Err(error) => abort = Some(error),
                    }
                }
                self.out.relocations.push(format!(
                    "{t} {i} {} {} {} {}",
                    format_address(address),
                    type_id as u32,
                    result.status.name(),
                    result.byte_length
                ));
                *self
                    .out
                    .status_counts
                    .entry(result.status.name())
                    .or_default() += 1;
                *self.out.type_counts.entry(type_id as u32).or_default() += 1;
                if let Some(Abort { exception, message }) = abort {
                    self.out.aborted = Some(format!("{exception}: {message}"));
                    self.finish();
                    return;
                }
            }
            self.current = None;
        }
        self.finish();
    }

    fn finish(&mut self) {
        self.out.got_allocation = match self.allocated {
            Slot::Null => "not-attempted".to_owned(),
            Slot::NoAddress => "failed".to_owned(),
            Slot::At(address) => format_address(address),
        };
        if let Some(map) = &self.got_map {
            let mut entries: Vec<_> = map.iter().collect();
            entries.sort_by_key(|(value, _)| **value);
            self.out.got_entries = entries
                .into_iter()
                .map(|(value, slot)| match slot {
                    Slot::At(address) => format!("{value:x} {}", format_address(*address)),
                    _ => format!("{value:x} NO_ADDRESS"),
                })
                .collect();
        }
    }

    fn info(&self, id: usize) -> SymbolInfo {
        let symbol = &self.symbols[id];
        SymbolInfo {
            handle: id,
            name: symbol.name.clone(),
            size: symbol.key.size,
            symbol_type: symbol.key.info & 0xf,
        }
    }

    fn table_symbol(&self, table: usize, index: i32) -> Option<usize> {
        let index = usize::try_from(index).ok()?;
        self.tables[table].get(index).copied()
    }

    /// `ElfGotRelocationContext.allocateGot()`.
    fn allocate_got(&mut self) -> Option<u64> {
        match self.allocated {
            Slot::At(address) => return Some(address),
            Slot::NoAddress => return None,
            Slot::Null => {}
        }
        self.allocated = Slot::NoAddress;
        self.next = Slot::NoAddress;
        let got = self.got_symbol;
        if got.is_none() && !self.relocatable {
            self.out.loader_log.push(format!(
                "GOT allocatiom failed. {GOT_SYMBOL_NAME} not defined"
            ));
            return None;
        }
        if let Some(id) = got
            && self.symbols[id].key.value != 0
        {
            self.out.loader_log.push(format!(
                "GOT allocatiom failed. {GOT_SYMBOL_NAME} already defined"
            ));
            return None;
        }
        let size = self.required_got_size();
        // allocateLinkageBlock model: the next aligned address after every block.
        let start = align_up(self.linkage_top, LINKAGE_ALIGNMENT);
        let end = start + u128::from(size) - 1;
        let limits = (end <= u128::from(u64::MAX)).then_some((start as u64, end as u64));
        self.limits = limits;
        if let Some((min, _)) = limits
            && (min as i64) < i64::from(i32::MAX)
        {
            if let Some(id) = got {
                self.out
                    .created_symbols
                    .push(format!("{} {GOT_SYMBOL_NAME}", format_address(min)));
                self.symbol_map.insert(self.symbols[id].key, min);
            }
            self.allocated = Slot::At(min);
            self.next = Slot::At(min);
            self.got_map = Some(HashMap::new());
            self.out
                .loader_log
                .push("Created %got block required for GOT relocation processing".to_owned());
            return Some(min);
        }
        self.out
            .loader_log
            .push("Failed to allocate GOT block required for relocation processing".to_owned());
        None
    }

    /// `computeRequiredGotSize()`.
    fn required_got_size(&mut self) -> u64 {
        let mut candidates = Vec::new();
        for table in &self.reloc_tables {
            let Some(symbols) = table.symbol_table else {
                continue;
            };
            for record in &table.records {
                let index = record.symbol_index();
                if !requires_got_entry(record.type_id()) || index == 0 {
                    continue;
                }
                if let Some(id) = self.table_symbol(symbols, index) {
                    candidates.push(id);
                }
            }
        }
        let mut unique = HashSet::new();
        for id in candidates {
            let symbol = self.info(id);
            let value = self.symbol_value(&symbol);
            if !unique.insert(value) {
                self.out.stdout.push(format!(
                    "Duplicate sym value 0x{value:x} for {}",
                    symbol.name.as_deref().unwrap_or("null")
                ));
            }
        }
        (unique.len() as u64 * 8).max(8)
    }

    /// `getNextAllocatedGotEntryAddress()`.
    fn next_got_entry(&mut self) -> Slot {
        if self.next == Slot::Null && self.allocate_got().is_none() {
            return Slot::NoAddress;
        }
        let Slot::At(address) = self.next else {
            return Slot::NoAddress;
        };
        let (min, max) = self.limits.expect("limits are set with the first entry");
        let contains = |value: u64| value >= min && value <= max;
        if let Some(last) = address.checked_add(7)
            && contains(last)
            && let Some(next) = last.checked_add(1)
        {
            self.next = if contains(next) {
                Slot::At(next)
            } else {
                Slot::NoAddress
            };
            return Slot::At(address);
        }
        self.next = Slot::NoAddress;
        Slot::NoAddress
    }
}

impl Environment for Session {
    fn symbol(&self, index: i32) -> Option<SymbolInfo> {
        match self.current {
            None => (index == 0).then(|| self.info(0)),
            Some(table) => self.table_symbol(table, index).map(|id| self.info(id)),
        }
    }

    fn symbol_name(&self, index: i32) -> Option<String> {
        let id = self.table_symbol(self.current?, index)?;
        self.symbols[id].name.clone()
    }

    fn symbol_address(&self, symbol: &SymbolInfo) -> Option<u64> {
        self.symbol_map
            .get(&self.symbols[symbol.handle].key)
            .copied()
    }

    fn symbol_value(&mut self, symbol: &SymbolInfo) -> u64 {
        let value = self.symbol_address(symbol).unwrap_or(0);
        if value == 0 && symbol.name.as_deref() == Some(GOT_SYMBOL_NAME) {
            let address = match self.symbol_address(symbol) {
                Some(address) => Some(address),
                None => self.allocate_got(),
            };
            if let Some(address) = address {
                return address;
            }
        }
        value
    }

    fn got_value(&mut self) -> Result<u64, String> {
        let loaded = self.pltgot.or_else(|| {
            self.got_symbol
                .and_then(|id| self.symbol_map.get(&self.symbols[id].key).copied())
        });
        if let Some(value) = loaded {
            return Ok(value);
        }
        self.allocate_got()
            .ok_or_else(|| format!("Failed to identify {GOT_SYMBOL_NAME}"))
    }

    fn got_entry_address(&mut self, symbol: &SymbolInfo) -> Option<u64> {
        let value = self.symbol_value(symbol);
        let mut slot = self
            .got_map
            .as_ref()
            .and_then(|map| map.get(&value).copied());
        if slot.is_none() {
            let next = self.next_got_entry();
            if let Some(map) = &mut self.got_map {
                map.insert(value, next);
            }
            slot = Some(next);
        }
        match slot {
            Some(Slot::At(address)) => Some(address),
            _ => None,
        }
    }

    fn image_base_adjustment(&self) -> u64 {
        self.adjust
    }

    fn is_prelinked(&self) -> bool {
        self.prelinked
    }

    fn read(&mut self, address: u64, out: &mut [u8]) -> Result<(), MemoryError> {
        self.check(address, out.len())?;
        for (i, byte) in out.iter_mut().enumerate() {
            let (block, offset) = self.mapped(address.wrapping_add(i as u64)).unwrap();
            *byte = self.blocks[block].data[offset];
        }
        Ok(())
    }

    fn write(&mut self, address: u64, bytes: &[u8]) -> Result<(), MemoryError> {
        self.check(address, bytes.len())?;
        for (i, byte) in bytes.iter().enumerate() {
            let (block, offset) = self.mapped(address.wrapping_add(i as u64)).unwrap();
            self.blocks[block].data[offset] = *byte;
        }
        self.out
            .writes
            .push(format!("{} {}", format_address(address), hex_bytes(bytes)));
        Ok(())
    }

    fn is_external_address(&self, address: u64) -> bool {
        self.external
            .is_some_and(|(start, length)| address.wrapping_sub(start) < length)
    }

    fn add_artificial_relocation(&mut self, address: u64, length: u32) {
        self.out
            .artificial
            .push(format!("{} {length}", format_address(address)));
    }

    fn log(&mut self, message: String) {
        self.out.log.push(message);
    }

    fn loader_log(&mut self, message: String) {
        self.out.loader_log.push(message);
    }

    fn bookmark(
        &mut self,
        address: u64,
        kind: &'static str,
        category: &'static str,
        comment: String,
    ) {
        self.out.bookmarks.push(format!(
            "{} {kind} {category} {comment}",
            format_address(address)
        ));
    }

    fn console(&mut self, level: &'static str, message: String) {
        self.out.console.push(format!("{level}: {message}"));
    }
}
