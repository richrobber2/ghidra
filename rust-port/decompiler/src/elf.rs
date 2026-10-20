// SPDX-License-Identifier: Apache-2.0
//! Bounded, borrowed ELF loader for the first native Rust decompiler slice.
//!
//! This loader supports ELF64 little-endian x86-64 ET_EXEC/ET_DYN images. It
//! validates file-backed executable mappings and retains defined STT_FUNC
//! symbols from ordinary and dynamic symbol tables. It does not guess the
//! extent of zero-size symbols, recover stripped functions, apply relocations,
//! or execute the input. An explicit address and size can select stripped code.

use ghidra_elf_sections::parse_section_headers;
use ghidra_elf_segments::{ParsePolicy, ProgramHeader, parse_program_headers};
use ghidra_elf_symbols::{ErrorKind as SymbolError, parse_symbols};

pub const MAX_IMAGE_BYTES: usize = 128 * 1024 * 1024;
pub const MAX_SECTIONS: u32 = 65_536;
pub const MAX_SYMBOLS: u64 = 1_000_000;
pub const MAX_NAME_BYTES: usize = 65_536;
pub const MAX_RETAINED_NAME_BYTES: usize = 16 * 1024 * 1024;
/// Explicit wrapper CPU-work bound, not a limit imposed by the ELF format.
pub const MAX_SYMBOL_MAPPING_WORK: u64 = 16_777_216;

const PT_LOAD: u32 = 1;
const PF_X: u32 = 1;
const SHT_NULL: u32 = 0;
const SHT_SYMTAB: u32 = 2;
const SHT_STRTAB: u32 = 3;
const SHT_NOBITS: u32 = 8;
const SHT_DYNSYM: u32 = 11;
const SHT_SYMTAB_SHNDX: u32 = 18;
const SHF_EXECINSTR: u64 = 4;
const SHN_UNDEF: u32 = 0;
const SHN_ABS: u32 = 0xfff1;
const SHN_COMMON: u32 = 0xfff2;
const SHN_XINDEX: u32 = 0xffff;

/// One retained symbol, or an explicit address/size selection. An empty name
/// means the ELF symbol was unnamed. A size of zero has no known code extent;
/// it remains visible in inventory but `function_bytes` refuses to decode it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Function {
    pub name: String,
    pub address: u64,
    pub size: u64,
    pub file_offset: usize,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct Section {
    pub(crate) section_type: u32,
    pub(crate) flags: u64,
    pub(crate) address: u64,
    pub(crate) offset: u64,
    pub(crate) size: u64,
    pub(crate) link: u32,
    pub(crate) entry_size: u64,
}

/// The original input is borrowed. Numeric mappings and symbol names are owned;
/// no loaded virtual memory or native execution is created.
#[derive(Debug)]
pub struct ElfImage<'a> {
    bytes: &'a [u8],
    entry: u64,
    loads: Vec<ProgramHeader>,
    program_headers: Vec<ProgramHeader>,
    sections: Vec<Section>,
    functions: Vec<Function>,
}

impl<'a> ElfImage<'a> {
    pub fn parse(bytes: &'a [u8]) -> Result<Self, String> {
        if bytes.len() > MAX_IMAGE_BYTES {
            return Err(format!(
                "image exceeds {MAX_IMAGE_BYTES}-byte resource limit"
            ));
        }
        let program_headers = parse_program_headers(bytes, ParsePolicy::Strict)
            .map_err(|error| format!("ELF header/program table: {error}"))?;
        let header = program_headers.header();
        if header.class_bits != 64 || !header.header_little_endian {
            return Err("only ELF64 little-endian images are supported".into());
        }
        if header.machine != 62 {
            return Err(format!(
                "only x86-64 ELF machine 62 is supported (got {})",
                header.machine
            ));
        }
        if !matches!(header.elf_type, 2 | 3) {
            return Err(format!(
                "only ET_EXEC/ET_DYN images are supported (got type {})",
                header.elf_type
            ));
        }
        if header.shnum > MAX_SECTIONS {
            return Err(format!(
                "section count {} exceeds resource limit {MAX_SECTIONS}",
                header.shnum
            ));
        }

        let mut loads = Vec::new();
        for (index, load) in program_headers.iter().enumerate() {
            if load.segment_type != PT_LOAD {
                continue;
            }
            if load.file_size > load.memory_size {
                return Err(format!("PT_LOAD {index} file size exceeds memory size"));
            }
            checked_slice(bytes, load.raw_offset, load.file_size, "PT_LOAD payload")?;
            load.virtual_address
                .checked_add(load.memory_size)
                .ok_or_else(|| format!("PT_LOAD {index} virtual extent overflows"))?;
            if load.align > 1 {
                if !load.align.is_power_of_two() {
                    return Err(format!("PT_LOAD {index} alignment is not a power of two"));
                }
                if load.virtual_address % load.align != load.raw_offset % load.align {
                    return Err(format!(
                        "PT_LOAD {index} address and file offset violate alignment"
                    ));
                }
            }
            loads.push(load);
        }
        if !loads
            .iter()
            .any(|load| load.flags & PF_X != 0 && load.file_size != 0)
        {
            return Err("no file-backed executable PT_LOAD segment".into());
        }

        let mut image = Self {
            bytes,
            entry: header.entry,
            loads,
            program_headers: program_headers.iter().collect(),
            sections: Vec::new(),
            functions: Vec::new(),
        };
        if header.shnum == 0 {
            return Ok(image);
        }
        let table = parse_section_headers(bytes, ParsePolicy::Strict)
            .map_err(|error| format!("ELF section table: {error}"))?;
        let mut sections = Vec::with_capacity(table.len());
        for (index, record) in table.iter().enumerate() {
            let section = Section {
                section_type: record.section_type,
                flags: record.flags,
                address: record.address,
                offset: record.offset,
                size: record.size,
                link: record.link,
                entry_size: record.entry_size,
            };
            if index == 0 && section.section_type != SHT_NULL {
                return Err("section zero must have SHT_NULL type".into());
            }
            if !matches!(section.section_type, SHT_NULL | SHT_NOBITS) {
                checked_slice(bytes, section.offset, section.size, "section payload")
                    .map_err(|error| format!("section {index}: {error}"))?;
            }
            section
                .address
                .checked_add(section.size)
                .ok_or_else(|| format!("section {index} virtual extent overflows"))?;
            sections.push(section);
        }

        // Index links once; many tables must not make lookup quadratic.
        let mut extended_indices = vec![None; sections.len()];
        for (index, section) in sections.iter().enumerate() {
            if section.section_type != SHT_SYMTAB_SHNDX {
                continue;
            }
            let linked = sections.get(section.link as usize).ok_or_else(|| {
                format!("extended symbol-index section {index} has invalid sh_link")
            })?;
            if !matches!(linked.section_type, SHT_SYMTAB | SHT_DYNSYM) {
                return Err(format!(
                    "extended symbol-index section {index} does not link a symbol table"
                ));
            }
            if section.entry_size != 4 || section.size % 4 != 0 {
                return Err(format!(
                    "extended symbol-index section {index} requires four-byte entries"
                ));
            }
            if extended_indices[section.link as usize]
                .replace(index)
                .is_some()
            {
                return Err(format!(
                    "symbol table {} has multiple extended-index tables",
                    section.link
                ));
            }
        }

        // Resource bounds over declared counts, checked before any symbol is
        // decoded. Every retained function may inspect every load interval, so
        // all declared symbols are charged conservatively: a many-table or
        // many-segment input must not amplify bounded counts into billions of
        // interval checks. These are wrapper work caps.
        let mut total_symbols = 0u64;
        for (table_index, section) in sections.iter().enumerate() {
            if !matches!(section.section_type, SHT_SYMTAB | SHT_DYNSYM) {
                continue;
            }
            if section.entry_size != 24 || section.size % 24 != 0 {
                return Err(format!(
                    "symbol table {table_index} requires complete 24-byte entries"
                ));
            }
            total_symbols = total_symbols
                .checked_add(section.size / 24)
                .ok_or("symbol count overflows")?;
            if total_symbols > MAX_SYMBOLS {
                return Err(format!(
                    "total symbol count exceeds resource limit {MAX_SYMBOLS}"
                ));
            }
            let mapping_work = total_symbols
                .checked_mul(image.loads.len() as u64)
                .ok_or("symbol mapping work estimate overflows")?;
            if mapping_work > MAX_SYMBOL_MAPPING_WORK {
                return Err(format!(
                    "declared symbol/load mapping work {mapping_work} exceeds resource limit {MAX_SYMBOL_MAPPING_WORK}"
                ));
            }
        }
        // Table-level checks also run before decoding, so their messages win
        // over the symbol parser's for the same defect.
        let mut string_tables = vec![None; sections.len()];
        for (table_index, section) in sections.iter().enumerate() {
            if !matches!(section.section_type, SHT_SYMTAB | SHT_DYNSYM) {
                continue;
            }
            let string_section = sections.get(section.link as usize).ok_or_else(|| {
                format!("symbol table {table_index} has invalid string-table link")
            })?;
            if string_section.section_type != SHT_STRTAB {
                return Err(format!(
                    "symbol table {table_index} does not link SHT_STRTAB"
                ));
            }
            let strings = checked_slice(
                bytes,
                string_section.offset,
                string_section.size,
                "symbol string table",
            )?;
            if strings.first() != Some(&0) || strings.last() != Some(&0) {
                return Err(format!(
                    "symbol table {table_index} requires a NUL-bounded string table"
                ));
            }
            checked_slice(bytes, section.offset, section.size, "symbol table")?;
            string_tables[table_index] = Some(strings);
        }
        let parsed =
            parse_symbols(bytes, ParsePolicy::Strict).map_err(|error| match error.kind {
                SymbolError::NameOutOfBounds { section, symbol } => {
                    format!("symbol {section}:{symbol} has out-of-range name offset")
                }
                _ => format!("ELF symbol tables: {error}"),
            })?;
        let mut parsed_tables = vec![None; sections.len()];
        for table in &parsed.symbol_tables {
            parsed_tables[table.section_index.unwrap() as usize] = Some(table);
        }

        let mut total_name_bytes = 0usize;
        for (table_index, section) in sections.iter().enumerate() {
            let Some(strings) = string_tables[table_index] else {
                continue;
            };
            let count = section.size / 24;
            let symbols = parsed_tables[table_index]
                .ok_or_else(|| format!("symbol table {table_index} was not decoded"))?;
            if let Some(index) = extended_indices[table_index]
                && sections[index].size / 4 != count
            {
                return Err(format!(
                    "symbol table {table_index} extended-index count does not match"
                ));
            }
            for (symbol_index, symbol) in symbols.symbols.iter().enumerate() {
                let name_offset = symbol.name_index as usize;
                if name_offset >= strings.len() {
                    return Err(format!(
                        "symbol {table_index}:{symbol_index} has out-of-range name offset"
                    ));
                }
                if symbol.symbol_type() != 2 {
                    continue; // STT_FUNC only, not imports, objects or IFUNC resolvers.
                }
                let mut section_index = u32::from(symbol.section_index);
                let absolute = section_index == SHN_ABS;
                if section_index == SHN_UNDEF {
                    continue;
                }
                if section_index == SHN_COMMON {
                    return Err(format!(
                        "function {table_index}:{symbol_index} uses unsupported SHN_COMMON"
                    ));
                }
                if section_index >= 0xff00 && !matches!(section_index, SHN_ABS | SHN_XINDEX) {
                    return Err(format!(
                        "function {table_index}:{symbol_index} uses an unsupported reserved section index"
                    ));
                }
                if section_index == SHN_XINDEX {
                    if extended_indices[table_index].is_none() {
                        return Err(format!(
                            "function {table_index}:{symbol_index} needs an extended-index table"
                        ));
                    }
                    section_index = symbol.extended_section_index;
                    if section_index == SHN_UNDEF {
                        continue;
                    }
                }
                let (address, size) = (symbol.value, symbol.size);
                let end = address.checked_add(size).ok_or_else(|| {
                    format!("function {table_index}:{symbol_index} address extent overflows")
                })?;
                if !absolute {
                    let code_section = sections.get(section_index as usize).ok_or_else(|| {
                        format!("function {table_index}:{symbol_index} has invalid section index")
                    })?;
                    if code_section.flags & SHF_EXECINSTR == 0
                        || code_section.section_type == SHT_NOBITS
                    {
                        return Err(format!(
                            "function {table_index}:{symbol_index} is not in a file-backed executable section"
                        ));
                    }
                    let section_end = code_section.address + code_section.size;
                    if address < code_section.address || end > section_end {
                        return Err(format!(
                            "function {table_index}:{symbol_index} extends outside its code section"
                        ));
                    }
                }
                let tail = &strings[name_offset..];
                let inspected = &tail[..tail.len().min(MAX_NAME_BYTES + 1)];
                let name_length = inspected.iter().position(|byte| *byte == 0)
                    .ok_or_else(|| format!("function {table_index}:{symbol_index} name exceeds {MAX_NAME_BYTES} bytes"))?;
                total_name_bytes = total_name_bytes
                    .checked_add(name_length)
                    .ok_or("retained function-name size overflows")?;
                if total_name_bytes > MAX_RETAINED_NAME_BYTES {
                    return Err(format!(
                        "retained function names exceed {MAX_RETAINED_NAME_BYTES}-byte resource limit"
                    ));
                }
                let name = std::str::from_utf8(&tail[..name_length]).map_err(|_| {
                    format!("function {table_index}:{symbol_index} name is not supported UTF-8")
                })?;
                let file_offset = image
                    .map_range(address, size)
                    .map_err(|error| format!("function {table_index}:{symbol_index}: {error}"))?;
                image.functions.push(Function {
                    name: name.to_owned(),
                    address,
                    size,
                    file_offset,
                });
            }
        }
        // Equal keys are equal functions and dedup removes them, so stability is moot.
        image.functions.sort_unstable_by(|a, b| {
            (a.address, a.size, &a.name, a.file_offset).cmp(&(
                b.address,
                b.size,
                &b.name,
                b.file_offset,
            ))
        });
        image.functions.dedup();
        image.sections = sections;
        Ok(image)
    }

    pub fn entry(&self) -> u64 {
        self.entry
    }

    pub fn functions(&self) -> &[Function] {
        &self.functions
    }

    pub(crate) fn file_bytes(&self) -> &'a [u8] {
        self.bytes
    }

    pub(crate) fn load_segments(&self) -> &[ProgramHeader] {
        &self.loads
    }

    pub(crate) fn program_headers(&self) -> &[ProgramHeader] {
        &self.program_headers
    }

    pub(crate) fn sections(&self) -> &[Section] {
        &self.sections
    }

    /// Select a complete explicit range for a stripped image. This does not
    /// discover a function or prove that the selected boundary is correct.
    pub fn function_range(&self, address: u64, size: u64) -> Result<Function, String> {
        if size == 0 {
            return Err("an explicit function range requires a nonzero size".into());
        }
        Ok(Function {
            name: String::new(),
            address,
            size,
            file_offset: self.map_range(address, size)?,
        })
    }

    pub fn function_bytes(&self, function: &Function) -> Result<&'a [u8], String> {
        if function.size == 0 {
            return Err("zero-size function symbol has no known code extent; supply an explicit address and size".into());
        }
        let offset = self.map_range(function.address, function.size)?;
        if offset != function.file_offset {
            return Err(
                "function file offset does not match its validated executable mapping".into(),
            );
        }
        checked_slice(self.bytes, offset as u64, function.size, "function bytes")
    }

    fn map_range(&self, address: u64, size: u64) -> Result<usize, String> {
        let end = address
            .checked_add(size)
            .ok_or("function address extent overflows")?;
        let mut selected = None;
        for load in &self.loads {
            if load.flags & PF_X == 0 || load.file_size == 0 {
                continue;
            }
            let load_end = load.virtual_address + load.file_size;
            let intersects = if size == 0 {
                address >= load.virtual_address && address < load_end
            } else {
                address < load_end && load.virtual_address < end
            };
            if !intersects {
                continue;
            }
            if selected.is_some() {
                return Err("function range has ambiguous executable PT_LOAD mappings".into());
            }
            if address < load.virtual_address || end > load_end {
                return Err(
                    "function range crosses a file-backed executable PT_LOAD boundary".into(),
                );
            }
            let offset = load
                .raw_offset
                .checked_add(address - load.virtual_address)
                .ok_or("function file offset overflows")?;
            selected = Some(
                usize::try_from(offset)
                    .map_err(|_| "function file offset exceeds host address space")?,
            );
        }
        selected.ok_or_else(|| {
            "function range is not file-backed in an executable PT_LOAD segment".into()
        })
    }
}

fn checked_slice<'a>(
    bytes: &'a [u8],
    offset: u64,
    length: u64,
    label: &str,
) -> Result<&'a [u8], String> {
    let end = offset
        .checked_add(length)
        .ok_or_else(|| format!("{label} extent overflows"))?;
    let start = usize::try_from(offset)
        .map_err(|_| format!("{label} offset exceeds host address space"))?;
    let end =
        usize::try_from(end).map_err(|_| format!("{label} end exceeds host address space"))?;
    bytes
        .get(start..end)
        .ok_or_else(|| format!("{label} is outside the file"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn put16(bytes: &mut [u8], offset: usize, value: u16) {
        bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }
    fn put32(bytes: &mut [u8], offset: usize, value: u32) {
        bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }
    fn put64(bytes: &mut [u8], offset: usize, value: u64) {
        bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }

    fn section(
        bytes: &mut [u8],
        index: usize,
        kind: u32,
        flags: u64,
        address: u64,
        offset: u64,
        size: u64,
        link: u32,
        entry_size: u64,
    ) {
        let base = 768 + index * 64;
        put32(bytes, base + 4, kind);
        put64(bytes, base + 8, flags);
        put64(bytes, base + 16, address);
        put64(bytes, base + 24, offset);
        put64(bytes, base + 32, size);
        put32(bytes, base + 40, link);
        put64(bytes, base + 56, entry_size);
    }

    fn fixture() -> Vec<u8> {
        let mut bytes = vec![0; 1024];
        bytes[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
        put16(&mut bytes, 16, 2);
        put16(&mut bytes, 18, 62);
        put32(&mut bytes, 20, 1);
        put64(&mut bytes, 24, 0x400100);
        put64(&mut bytes, 32, 64);
        put64(&mut bytes, 40, 768);
        put16(&mut bytes, 52, 64);
        put16(&mut bytes, 54, 56);
        put16(&mut bytes, 56, 1);
        put16(&mut bytes, 58, 64);
        put16(&mut bytes, 60, 4);
        put32(&mut bytes, 64, PT_LOAD);
        put32(&mut bytes, 68, 5);
        put64(&mut bytes, 80, 0x400000);
        put64(&mut bytes, 88, 0x400000);
        put64(&mut bytes, 96, 1024);
        put64(&mut bytes, 104, 1024);
        put64(&mut bytes, 112, 4096);
        bytes[256..272].copy_from_slice(&[0x90; 16]);
        section(&mut bytes, 1, 1, 6, 0x400100, 256, 16, 0, 0);
        section(&mut bytes, 2, SHT_SYMTAB, 0, 0, 512, 96, 3, 24);
        section(&mut bytes, 3, SHT_STRTAB, 0, 0, 640, 16, 0, 0);
        bytes[640..656].copy_from_slice(b"\0foo\0alias\0zero\0");
        for (index, name, size) in [(1, 1, 16), (2, 5, 16), (3, 11, 0)] {
            let base = 512 + index * 24;
            put32(&mut bytes, base, name);
            bytes[base + 4] = 0x12;
            put16(&mut bytes, base + 6, 1);
            put64(&mut bytes, base + 8, 0x400100);
            put64(&mut bytes, base + 16, size);
        }
        bytes
    }

    #[test]
    fn retains_aliases_zero_size_and_exact_function_bytes() {
        let bytes = fixture();
        let image = ElfImage::parse(&bytes).unwrap();
        assert_eq!(image.entry(), 0x400100);
        assert_eq!(image.functions().len(), 3);
        let foo = image
            .functions()
            .iter()
            .find(|function| function.name == "foo")
            .unwrap();
        assert_eq!(foo.file_offset, 256);
        assert_eq!(image.function_bytes(foo).unwrap(), &[0x90; 16]);
        let zero = image
            .functions()
            .iter()
            .find(|function| function.name == "zero")
            .unwrap();
        assert!(
            image
                .function_bytes(zero)
                .unwrap_err()
                .contains("zero-size")
        );
        let selected = image.function_range(0x400102, 4).unwrap();
        assert_eq!(selected.file_offset, 258);
        assert_eq!(image.function_bytes(&selected).unwrap(), &[0x90; 4]);
    }

    #[test]
    fn accepts_extended_section_count_and_dynamic_symbols() {
        let mut bytes = fixture();
        put16(&mut bytes, 60, 0);
        put64(&mut bytes, 768 + 32, 4);
        put32(&mut bytes, 768 + 2 * 64 + 4, SHT_DYNSYM);
        let image = ElfImage::parse(&bytes).unwrap();
        assert_eq!(image.functions().len(), 3);
    }

    #[test]
    fn sectionless_image_requires_explicit_ranges() {
        let mut bytes = fixture();
        put64(&mut bytes, 40, 0);
        put16(&mut bytes, 58, 0);
        put16(&mut bytes, 60, 0);
        let image = ElfImage::parse(&bytes).unwrap();
        assert!(image.functions().is_empty());
        assert_eq!(image.function_range(0x400100, 16).unwrap().file_offset, 256);
        assert!(image.function_range(0x400100, 0).is_err());
    }

    #[test]
    fn rejects_truncated_tables_payloads_and_invalid_links() {
        let mut bytes = fixture();
        bytes.truncate(1000);
        assert!(
            ElfImage::parse(&bytes)
                .unwrap_err()
                .contains("PT_LOAD payload")
        );
        let mut bytes = fixture();
        put64(&mut bytes, 40, 1000);
        assert!(
            ElfImage::parse(&bytes)
                .unwrap_err()
                .contains("section table")
        );
        let mut bytes = fixture();
        put64(&mut bytes, 768 + 3 * 64 + 24, 1016);
        assert!(
            ElfImage::parse(&bytes)
                .unwrap_err()
                .contains("section payload")
        );
        let mut bytes = fixture();
        put32(&mut bytes, 768 + 2 * 64 + 40, 99);
        assert!(
            ElfImage::parse(&bytes)
                .unwrap_err()
                .contains("string-table link")
        );
    }

    #[test]
    fn rejects_bad_strings_noncanonical_symbols_and_code_extent() {
        let mut bytes = fixture();
        put32(&mut bytes, 512 + 24, 16);
        assert!(ElfImage::parse(&bytes).unwrap_err().contains("name offset"));
        let mut bytes = fixture();
        bytes[655] = b'x';
        assert!(ElfImage::parse(&bytes).unwrap_err().contains("NUL-bounded"));
        let mut bytes = fixture();
        bytes[641] = 0xff;
        assert!(ElfImage::parse(&bytes).unwrap_err().contains("UTF-8"));
        let mut bytes = fixture();
        put64(&mut bytes, 768 + 2 * 64 + 56, 16);
        assert!(ElfImage::parse(&bytes).unwrap_err().contains("24-byte"));
        let mut bytes = fixture();
        put64(&mut bytes, 512 + 24 + 16, 17);
        assert!(
            ElfImage::parse(&bytes)
                .unwrap_err()
                .contains("code section")
        );
    }

    #[test]
    fn rejects_nonfilebacked_ambiguous_and_overflowing_ranges() {
        let bytes = fixture();
        let image = ElfImage::parse(&bytes).unwrap();
        assert!(
            image
                .function_range(0x400400, 1)
                .unwrap_err()
                .contains("not file-backed")
        );
        assert!(
            image
                .function_range(u64::MAX, 2)
                .unwrap_err()
                .contains("overflows")
        );
        let mut false_offset = image.function_range(0x400100, 16).unwrap();
        false_offset.file_offset += 1;
        assert!(
            image
                .function_bytes(&false_offset)
                .unwrap_err()
                .contains("does not match")
        );
        let mut bytes = fixture();
        bytes.copy_within(64..120, 120);
        put16(&mut bytes, 56, 2);
        assert!(ElfImage::parse(&bytes).unwrap_err().contains("ambiguous"));
        let mut bytes = fixture();
        put64(&mut bytes, 96, 256);
        assert!(
            ElfImage::parse(&bytes)
                .unwrap_err()
                .contains("not file-backed")
        );
        let mut bytes = fixture();
        put64(&mut bytes, 80, u64::MAX - 512);
        assert!(
            ElfImage::parse(&bytes)
                .unwrap_err()
                .contains("virtual extent overflows")
        );
    }

    #[test]
    fn supports_extended_symbol_section_indices_and_rejects_missing_table() {
        let mut bytes = fixture();
        put16(&mut bytes, 512 + 24 + 6, SHN_XINDEX as u16);
        assert!(
            ElfImage::parse(&bytes)
                .unwrap_err()
                .contains("extended-index table")
        );
        bytes.resize(1088, 0);
        put64(&mut bytes, 96, 1088);
        put64(&mut bytes, 104, 1088);
        put16(&mut bytes, 60, 5);
        section(&mut bytes, 4, SHT_SYMTAB_SHNDX, 0, 0, 704, 16, 2, 4);
        put32(&mut bytes, 708, 1);
        let image = ElfImage::parse(&bytes).unwrap();
        assert_eq!(image.functions().len(), 3);
    }

    #[test]
    fn rejects_architecture_type_and_section_count_resource_limits() {
        let mut bytes = fixture();
        put16(&mut bytes, 18, 183);
        assert!(ElfImage::parse(&bytes).unwrap_err().contains("machine 62"));
        let mut bytes = fixture();
        put16(&mut bytes, 16, 1);
        assert!(
            ElfImage::parse(&bytes)
                .unwrap_err()
                .contains("ET_EXEC/ET_DYN")
        );
        let mut bytes = fixture();
        put16(&mut bytes, 60, 0);
        put64(&mut bytes, 768 + 32, u64::from(MAX_SECTIONS) + 1);
        assert!(
            ElfImage::parse(&bytes)
                .unwrap_err()
                .contains("section count")
        );
    }

    #[test]
    fn rejects_actual_elf_with_excessive_declared_symbol_mapping_work() {
        // Each individual count is allowed, and every table fits the file.
        // Their product exceeds the explicit wrapper CPU-work budget. All
        // symbols are NULL: the conservative precheck still bounds the work.
        let program_count = 4096usize;
        let symbol_count = 4097usize;
        let symbol_offset = 64 + program_count * 56;
        let strings_offset = symbol_offset + symbol_count * 24;
        let section_offset = strings_offset + 16;
        let file_size = section_offset + 4 * 64;
        let template = fixture();
        let mut bytes = vec![0; file_size];
        bytes[..64].copy_from_slice(&template[..64]);
        put16(&mut bytes, 56, program_count as u16);
        put64(&mut bytes, 40, section_offset as u64);
        let mut load = template[64..120].to_vec();
        put64(&mut load, 32, file_size as u64);
        put64(&mut load, 40, file_size as u64);
        for index in 0..program_count {
            bytes[64 + index * 56..64 + (index + 1) * 56].copy_from_slice(&load);
        }
        bytes[section_offset..section_offset + 4 * 64].copy_from_slice(&template[768..1024]);
        put64(
            &mut bytes,
            section_offset + 2 * 64 + 24,
            symbol_offset as u64,
        );
        put64(
            &mut bytes,
            section_offset + 2 * 64 + 32,
            (symbol_count * 24) as u64,
        );
        put64(
            &mut bytes,
            section_offset + 3 * 64 + 24,
            strings_offset as u64,
        );
        put64(&mut bytes, section_offset + 3 * 64 + 32, 1);
        let error = ElfImage::parse(&bytes).unwrap_err();
        assert!(error.contains("symbol/load mapping work"), "{error}");
        assert!(error.contains(&MAX_SYMBOL_MAPPING_WORK.to_string()));
    }
}
