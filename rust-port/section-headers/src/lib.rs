// SPDX-License-Identifier: Apache-2.0
// Adapted from Ghidra ElfHeader.parseSectionHeaders, ElfSectionHeader and
// ElfCompressedSectionHeader.
//! Borrowed ELF section-header table decoding. No Program, memory mapping,
//! architecture adapter, PRE trailer, decompression or section-payload decoding
//! is performed.
//!
//! Compatibility mode retains the original signed short stride, missing-region
//! warning, zero-filled records, section-name lookup (which ignores the string
//! table's size) and the compressed-section header probe of the default load
//! adapter. Signed record-address overflow is rejected instead of allowing Java
//! wrap. Strict mode validates the header, the complete canonical table extent,
//! the section-name string table extent and every name's bounds and terminator.
//! Neither policy validates section payload extents, alignment, links or
//! architecture-specific constraints.

#![forbid(unsafe_code)]

pub use ghidra_elf::ParsePolicy;
use ghidra_elf::{ParseError, ParsedHeader, parse_header};
use std::borrow::Cow;
use std::fmt;
use std::iter::FusedIterator;

/// An explicit time/resource bound, not a limit imposed by the ELF format.
pub const MAX_SECTION_HEADERS: u32 = 65536;

pub const SHT_NOBITS: u32 = 8;
pub const SHT_SYMTAB_SHNDX: u32 = 18;
pub const SHF_ALLOC: u64 = 0x2;
pub const SHF_COMPRESSED: u64 = 0x800;
pub const ELFCOMPRESS_ZLIB: u32 = 1;
const ELF32_INVALID_OFFSET: u64 = 0xffff_ffff;

/// An `Elf32_Chdr`/`Elf64_Chdr` accepted by Ghidra's default load adapter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CompressionHeader {
    pub compression_type: u32,
    pub size: u64,
    pub address_align: u64,
    pub header_size: u8,
}

/// Why a section flagged `SHF_COMPRESSED` is treated as uncompressed. Ghidra
/// logs these through its global logger and keeps loading.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompressionError {
    /// Allocated, empty, negative or out-of-file section region.
    InvalidRegion,
    /// `SHT_NOBITS` sections have no bytes to hold a header.
    NoBits,
    /// The section is shorter than the compression header.
    Truncated,
    UnsupportedType(u32),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Compression {
    None,
    Compressed(CompressionHeader),
    Invalid(CompressionError),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SectionHeader {
    pub name_index: u32,
    pub section_type: u32,
    pub flags: u64,
    pub address: u64,
    pub offset: u64,
    pub size: u64,
    pub link: u32,
    pub info: u32,
    pub address_align: u64,
    pub entry_size: u64,
    pub compression: Compression,
}

impl SectionHeader {
    pub fn is_alloc(&self) -> bool {
        self.flags & SHF_ALLOC != 0
    }
    pub fn is_compressed(&self) -> bool {
        matches!(self.compression, Compression::Compressed(_))
    }
    /// Uncompressed size for supported compressed sections, else `size`.
    pub fn logical_size(&self) -> u64 {
        match self.compression {
            Compression::Compressed(header) => header.size,
            _ => self.size,
        }
    }
    /// Uncompressed alignment for supported compressed sections, else
    /// `address_align`.
    pub fn logical_address_align(&self) -> u64 {
        match self.compression {
            Compression::Compressed(header) => header.address_align,
            _ => self.address_align,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MissingHeaders {
    pub first_missing: u32,
    pub total: u32,
}

impl fmt::Display for MissingHeaders {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{} of {} section headers are truncated/missing from file",
            self.total - self.first_missing,
            self.total
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorKind {
    Header(ParseError),
    HeaderCountLimit {
        count: u32,
        limit: u32,
    },
    TableExtentOverflow,
    TableOutOfBounds {
        offset: u64,
        length: u64,
        file_length: u64,
    },
    InvalidRecordOffset {
        index: u32,
        offset: i64,
    },
    RecordOffsetOverflow {
        index: u32,
    },
    InvalidStringTable {
        index: u32,
    },
    NameOutOfBounds {
        index: u32,
        name_index: u32,
    },
    UnterminatedName {
        index: u32,
    },
}

impl ErrorKind {
    pub const fn name(self) -> &'static str {
        match self {
            Self::Header(error) => error.kind(),
            Self::HeaderCountLimit { .. } => "HeaderCountLimit",
            Self::TableExtentOverflow => "TableExtentOverflow",
            Self::TableOutOfBounds { .. } => "TableOutOfBounds",
            Self::InvalidRecordOffset { .. } => "InvalidRecordOffset",
            Self::RecordOffsetOverflow { .. } => "RecordOffsetOverflow",
            Self::InvalidStringTable { .. } => "InvalidStringTable",
            Self::NameOutOfBounds { .. } => "NameOutOfBounds",
            Self::UnterminatedName { .. } => "UnterminatedName",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParseFailure {
    pub kind: ErrorKind,
    pub header: Option<ParsedHeader>,
    pub missing: Option<MissingHeaders>,
}

impl fmt::Display for ParseFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{:?}", self.kind)
    }
}

impl std::error::Error for ParseFailure {}

/// Byte range searched for section names. Compatibility mode ends it at EOF,
/// as Ghidra does; strict mode ends it at the string table's own size.
#[derive(Debug, Clone, Copy)]
struct StringTable {
    start: u64,
    end: u64,
}

/// A validated borrowed view. Fields affecting iteration are private so callers
/// cannot invalidate the bounds established by `parse_section_headers`.
#[derive(Debug, Clone)]
pub struct SectionHeaders<'a> {
    bytes: &'a [u8],
    header: ParsedHeader,
    policy: ParsePolicy,
    missing: Option<MissingHeaders>,
    zero_filled_entries: u32,
    has_extended_symbol_index_table: bool,
    string_table: Option<StringTable>,
}

impl<'a> SectionHeaders<'a> {
    pub fn header(&self) -> &ParsedHeader {
        &self.header
    }
    pub fn len(&self) -> usize {
        self.header.shnum as usize
    }
    pub fn is_empty(&self) -> bool {
        self.header.shnum == 0
    }
    pub fn missing(&self) -> Option<MissingHeaders> {
        self.missing
    }
    pub fn zero_filled_entries(&self) -> u32 {
        self.zero_filled_entries
    }
    /// True when any section has type `SHT_SYMTAB_SHNDX`.
    pub fn has_extended_symbol_index_table(&self) -> bool {
        self.has_extended_symbol_index_table
    }

    fn record_offset(&self, index: u32) -> Option<u64> {
        if index >= self.header.shnum {
            return None;
        }
        match self.policy {
            ParsePolicy::Strict => self
                .header
                .shoff
                .checked_add(u64::from(index) * u64::from(self.header.shentsize)),
            ParsePolicy::GhidraCompatible => {
                compatible_offset(self.header, index).ok().map(|o| o as u64)
            }
        }
    }

    fn raw(&self, index: u32) -> Option<SectionHeader> {
        let offset = self.record_offset(index)?;
        Some(decode_at(
            self.bytes,
            offset,
            self.header.class_bits,
            self.header.header_little_endian,
        ))
    }

    /// The record at `index`, including its compression-header probe.
    pub fn get(&self, index: usize) -> Option<SectionHeader> {
        let index = u32::try_from(index).ok()?;
        let mut value = self.raw(index)?;
        value.compression = compression(self.bytes, &value, &self.header);
        Some(value)
    }

    pub fn iter(&self) -> SectionHeaderIter<'_, 'a> {
        SectionHeaderIter {
            table: self,
            index: 0,
        }
    }

    /// Name bytes from the section-name string table, without the terminator.
    /// `None` when Ghidra would fall back to a generated name.
    pub fn name_bytes(&self, index: usize) -> Option<&'a [u8]> {
        let index = u32::try_from(index).ok()?;
        let name_index = self.raw(index)?.name_index;
        lookup_name(self.bytes, self.string_table?, name_index)
    }

    /// The section name as Ghidra reports it: the string-table entry decoded
    /// as Java decodes UTF-8, or `SECTION<index>` when that entry is missing
    /// or empty.
    pub fn name(&self, index: usize) -> Option<Cow<'a, str>> {
        if index >= self.len() {
            return None;
        }
        Some(match self.name_bytes(index) {
            Some(bytes) => java_utf8_lossy(bytes),
            None => Cow::Owned(format!("SECTION{index}")),
        })
    }
}

pub struct SectionHeaderIter<'table, 'bytes> {
    table: &'table SectionHeaders<'bytes>,
    index: u32,
}

impl Iterator for SectionHeaderIter<'_, '_> {
    type Item = SectionHeader;
    fn next(&mut self) -> Option<Self::Item> {
        let value = self.table.get(self.index as usize)?;
        self.index += 1;
        Some(value)
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = (self.table.header.shnum - self.index) as usize;
        (remaining, Some(remaining))
    }
}
impl ExactSizeIterator for SectionHeaderIter<'_, '_> {}
impl FusedIterator for SectionHeaderIter<'_, '_> {}

fn compatible_offset(header: ParsedHeader, index: u32) -> Result<i64, ErrorKind> {
    // The count bound makes Java's int multiplication fit. Checked addition
    // deliberately refuses signed-long wrapping into a different file region.
    let stride = i64::from(header.shentsize as i16);
    let delta = i64::from(index)
        .checked_mul(stride)
        .ok_or(ErrorKind::RecordOffsetOverflow { index })?;
    let offset = (header.shoff as i64)
        .checked_add(delta)
        .ok_or(ErrorKind::RecordOffsetOverflow { index })?;
    if offset < 0 {
        return Err(ErrorKind::InvalidRecordOffset { index, offset });
    }
    Ok(offset)
}

fn lookup_name(bytes: &[u8], table: StringTable, name_index: u32) -> Option<&[u8]> {
    // Java skips negative int name indices; the long sum cannot exceed u64.
    if (name_index as i32) < 0 {
        return None;
    }
    let start = table.start + u64::from(name_index);
    if start >= table.end {
        return None;
    }
    let tail = &bytes[start as usize..table.end as usize];
    // Ghidra's unbounded reader zero-fills past EOF, so EOF also terminates.
    let name = match tail.iter().position(|&b| b == 0) {
        Some(end) => &tail[..end],
        None => tail,
    };
    (!name.is_empty()).then_some(name)
}

/// `new String(bytes, UTF_8)`. Valid UTF-8 decodes as in Rust; malformed
/// input follows the JDK's `String.decodeUTF8_UTF16` replacement rules, which
/// differ from `String::from_utf8_lossy` for encoded surrogates (one U+FFFD
/// for `ED A0 80`, not three) and for some truncated sequences.
pub fn java_utf8_lossy(src: &[u8]) -> Cow<'_, str> {
    if let Ok(text) = std::str::from_utf8(src) {
        return Cow::Borrowed(text);
    }
    const REPL: char = '\u{fffd}';
    let continuation = |b: u8| b & 0xc0 == 0x80;
    let bad3_2 = |b1: u8, b2: u8| (b1 == 0xe0 && b2 & 0xe0 == 0x80) || !continuation(b2);
    let bad4_2 = |b1: u8, b2: u8| {
        (b1 == 0xf0 && !(0x90..=0xbf).contains(&b2))
            || (b1 == 0xf4 && b2 & 0xf0 != 0x80)
            || !continuation(b2)
    };
    let mut out = String::with_capacity(src.len() + 8);
    let length = src.len();
    let mut sp = 0;
    while sp < length {
        let b1 = src[sp];
        sp += 1;
        if b1 < 0x80 {
            out.push(char::from(b1));
        } else if b1 & 0xe0 == 0xc0 && b1 & 0x1e != 0 {
            if sp < length {
                let b2 = src[sp];
                if continuation(b2) {
                    sp += 1;
                    let c = (u32::from(b1 & 0x1f) << 6) | u32::from(b2 & 0x3f);
                    out.push(char::from_u32(c).unwrap());
                } else {
                    out.push(REPL);
                }
                continue;
            }
            out.push(REPL);
            break;
        } else if b1 & 0xf0 == 0xe0 {
            if sp + 1 < length {
                let (b2, b3) = (src[sp], src[sp + 1]);
                if bad3_2(b1, b2) || !continuation(b3) {
                    out.push(REPL);
                    sp += if bad3_2(b1, b2) { 0 } else { 1 };
                } else {
                    sp += 2;
                    let c = (u32::from(b1 & 0x0f) << 12)
                        | (u32::from(b2 & 0x3f) << 6)
                        | u32::from(b3 & 0x3f);
                    // Encoded surrogates are well formed to Java's decoder but
                    // replaced as a whole.
                    out.push(char::from_u32(c).unwrap_or(REPL));
                }
                continue;
            }
            out.push(REPL);
            if sp < length && bad3_2(b1, src[sp]) {
                continue;
            }
            break;
        } else if b1 & 0xf8 == 0xf0 {
            if sp + 2 < length {
                let (b2, b3, b4) = (src[sp], src[sp + 1], src[sp + 2]);
                let c = (u32::from(b1 & 0x07) << 18)
                    | (u32::from(b2 & 0x3f) << 12)
                    | (u32::from(b3 & 0x3f) << 6)
                    | u32::from(b4 & 0x3f);
                if !continuation(b2)
                    || !continuation(b3)
                    || !continuation(b4)
                    || !(0x10000..=0x10ffff).contains(&c)
                {
                    out.push(REPL);
                    // String.malformed4: the replacement covers 1 to 3 bytes.
                    sp += if b1 > 0xf4 || bad4_2(b1, b2) {
                        0
                    } else if !continuation(b3) {
                        1
                    } else {
                        2
                    };
                } else {
                    sp += 3;
                    out.push(char::from_u32(c).unwrap());
                }
                continue;
            }
            out.push(REPL);
            if b1 > 0xf4 || (sp < length && bad4_2(b1, src[sp])) {
                continue;
            }
            sp += 1;
            if sp < length && !continuation(src[sp]) {
                continue;
            }
            break;
        } else {
            out.push(REPL);
        }
    }
    Cow::Owned(out)
}

fn is_invalid_offset(offset: u64, bits: u8) -> bool {
    (offset as i64) < 0 || (bits == 32 && offset == ELF32_INVALID_OFFSET)
}

pub fn parse_section_headers(
    bytes: &[u8],
    policy: ParsePolicy,
) -> Result<SectionHeaders<'_>, ParseFailure> {
    let header = parse_header(bytes, policy).map_err(|error| ParseFailure {
        kind: ErrorKind::Header(error),
        header: None,
        missing: None,
    })?;
    let mut table = SectionHeaders {
        bytes,
        header,
        policy,
        missing: None,
        zero_filled_entries: 0,
        has_extended_symbol_index_table: false,
        string_table: None,
    };
    let fail = |kind, missing| ParseFailure {
        kind,
        header: Some(header),
        missing,
    };
    if header.shnum > MAX_SECTION_HEADERS {
        return Err(fail(
            ErrorKind::HeaderCountLimit {
                count: header.shnum,
                limit: MAX_SECTION_HEADERS,
            },
            None,
        ));
    }
    if header.shnum == 0 {
        return Ok(table);
    }
    let file_length = bytes.len() as u64;
    let record_size = if header.class_bits == 64 {
        64u64
    } else {
        40u64
    };
    if policy == ParsePolicy::Strict {
        let length = u64::from(header.shnum)
            .checked_mul(u64::from(header.shentsize))
            .ok_or_else(|| fail(ErrorKind::TableExtentOverflow, None))?;
        let end = header
            .shoff
            .checked_add(length)
            .ok_or_else(|| fail(ErrorKind::TableExtentOverflow, None))?;
        if end > file_length {
            return Err(fail(
                ErrorKind::TableOutOfBounds {
                    offset: header.shoff,
                    length,
                    file_length,
                },
                None,
            ));
        }
        table.has_extended_symbol_index_table =
            (0..header.shnum).any(|i| table.raw(i).unwrap().section_type == SHT_SYMTAB_SHNDX);
    } else {
        let stride = i64::from(header.shentsize as i16);
        for index in 0..header.shnum {
            let delta = i64::from(index) * stride;
            let Some(offset) = (header.shoff as i64).checked_add(delta) else {
                return Err(fail(
                    ErrorKind::RecordOffsetOverflow { index },
                    table.missing,
                ));
            };
            // Match providerContainsRegion's signed addition, even when the
            // declared entry size differs from the actual 40/64-byte read.
            if table.missing.is_none()
                && !(offset >= 0 && offset.wrapping_add(stride) <= file_length as i64)
            {
                table.missing = Some(MissingHeaders {
                    first_missing: index,
                    total: header.shnum,
                });
            }
            if offset < 0 {
                return Err(fail(
                    ErrorKind::InvalidRecordOffset { index, offset },
                    table.missing,
                ));
            }
            if offset.checked_add(record_size as i64 - 1).is_none() {
                return Err(fail(
                    ErrorKind::RecordOffsetOverflow { index },
                    table.missing,
                ));
            }
            let offset = offset as u64;
            if offset + record_size > file_length {
                table.zero_filled_entries += 1;
            }
            let record = decode_at(
                bytes,
                offset,
                header.class_bits,
                header.header_little_endian,
            );
            if record.section_type == SHT_SYMTAB_SHNDX {
                table.has_extended_symbol_index_table = true;
            }
        }
    }
    let missing = table.missing;
    if header.shstrndx > 0 && header.shstrndx < header.shnum {
        let strings = table.raw(header.shstrndx).unwrap();
        match policy {
            ParsePolicy::GhidraCompatible => {
                if !is_invalid_offset(strings.offset, header.class_bits) {
                    table.string_table = Some(StringTable {
                        start: strings.offset,
                        end: file_length,
                    });
                }
            }
            ParsePolicy::Strict => {
                let invalid = || {
                    fail(
                        ErrorKind::InvalidStringTable {
                            index: header.shstrndx,
                        },
                        missing,
                    )
                };
                if strings.section_type == SHT_NOBITS {
                    return Err(invalid());
                }
                let end = strings
                    .offset
                    .checked_add(strings.size)
                    .filter(|&end| end <= file_length)
                    .ok_or_else(invalid)?;
                let strings_table = StringTable {
                    start: strings.offset,
                    end,
                };
                for index in 0..header.shnum {
                    let name_index = table.raw(index).unwrap().name_index;
                    if u64::from(name_index) >= strings.size {
                        return Err(fail(
                            ErrorKind::NameOutOfBounds { index, name_index },
                            missing,
                        ));
                    }
                    let start = (strings.offset + u64::from(name_index)) as usize;
                    if !bytes[start..end as usize].contains(&0) {
                        return Err(fail(ErrorKind::UnterminatedName { index }, missing));
                    }
                }
                table.string_table = Some(strings_table);
            }
        }
    }
    Ok(table)
}

/// The default load adapter's `SHF_COMPRESSED` probe. The header is read with
/// the declared EI_DATA order (`ElfHeader.isLittleEndian`), which can differ
/// from the order used for the section records themselves.
fn compression(bytes: &[u8], section: &SectionHeader, header: &ParsedHeader) -> Compression {
    if section.flags & SHF_COMPRESSED == 0 {
        return Compression::None;
    }
    let offset = section.offset as i64;
    let size = section.size as i64;
    let end = offset.wrapping_add(size);
    if section.is_alloc() || offset < 0 || size <= 0 || end <= 0 || end as u64 > bytes.len() as u64
    {
        return Compression::Invalid(CompressionError::InvalidRegion);
    }
    if section.section_type == SHT_NOBITS {
        return Compression::Invalid(CompressionError::NoBits);
    }
    let is_64 = header.class_bits == 64;
    let header_size: u8 = if is_64 { 24 } else { 12 };
    if section.size < u64::from(header_size) {
        return Compression::Invalid(CompressionError::Truncated);
    }
    let start = offset as usize;
    let record = &bytes[start..start + usize::from(header_size)];
    let little = header.ident[5] == 1;
    let u32_at = |at: usize| {
        let value = record[at..at + 4].try_into().unwrap();
        if little {
            u32::from_le_bytes(value)
        } else {
            u32::from_be_bytes(value)
        }
    };
    let u64_at = |at: usize| {
        let value = record[at..at + 8].try_into().unwrap();
        if little {
            u64::from_le_bytes(value)
        } else {
            u64::from_be_bytes(value)
        }
    };
    let compression_type = u32_at(0);
    let (size, address_align) = if is_64 {
        (u64_at(8), u64_at(16))
    } else {
        (u64::from(u32_at(4)), u64::from(u32_at(8)))
    };
    if compression_type != ELFCOMPRESS_ZLIB {
        return Compression::Invalid(CompressionError::UnsupportedType(compression_type));
    }
    Compression::Compressed(CompressionHeader {
        compression_type,
        size,
        address_align,
        header_size,
    })
}

#[inline]
fn decode_at(bytes: &[u8], offset: u64, bits: u8, little: bool) -> SectionHeader {
    let size = if bits == 64 { 64 } else { 40 };
    let mut padded = [0u8; 64];
    let record = if let Ok(start) = usize::try_from(offset) {
        if start <= bytes.len() && bytes.len() - start >= size {
            &bytes[start..start + size]
        } else {
            if start < bytes.len() {
                let count = size.min(bytes.len() - start);
                padded[..count].copy_from_slice(&bytes[start..start + count]);
            }
            &padded[..size]
        }
    } else {
        &padded[..size]
    };
    if little {
        decode::<true>(record, bits)
    } else {
        decode::<false>(record, bits)
    }
}

#[inline]
fn decode<const LE: bool>(record: &[u8], bits: u8) -> SectionHeader {
    let u32_at = |offset| {
        let value = record[offset..offset + 4].try_into().unwrap();
        if LE {
            u32::from_le_bytes(value)
        } else {
            u32::from_be_bytes(value)
        }
    };
    let u64_at = |offset| {
        let value = record[offset..offset + 8].try_into().unwrap();
        if LE {
            u64::from_le_bytes(value)
        } else {
            u64::from_be_bytes(value)
        }
    };
    let word = |offset| u64::from(u32_at(offset));
    let (flags, address, offset, size, link, info, address_align, entry_size) = if bits == 64 {
        (
            u64_at(8),
            u64_at(16),
            u64_at(24),
            u64_at(32),
            u32_at(40),
            u32_at(44),
            u64_at(48),
            u64_at(56),
        )
    } else {
        (
            word(8),
            word(12),
            word(16),
            word(20),
            u32_at(24),
            u32_at(28),
            word(32),
            word(36),
        )
    };
    SectionHeader {
        name_index: u32_at(0),
        section_type: u32_at(4),
        flags,
        address,
        offset,
        size,
        link,
        info,
        address_align,
        entry_size,
        compression: Compression::None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Section {
        name: u32,
        kind: u32,
        flags: u64,
        offset: u64,
        size: u64,
    }

    fn put(bytes: &mut [u8], position: usize, width: usize, value: u64, little: bool) {
        let values = if little {
            value.to_le_bytes()
        } else {
            value.to_be_bytes()
        };
        bytes[position..position + width].copy_from_slice(if little {
            &values[..width]
        } else {
            &values[8 - width..]
        });
    }

    /// Header at 0, string table at 0x80, data at 0x100, sections at 0x200.
    fn fixture(bits: u8, little: bool, sections: &[Section], shstrndx: u16) -> Vec<u8> {
        let size = if bits == 64 { 64 } else { 40 };
        let mut bytes = vec![0u8; 0x200 + sections.len() * size];
        bytes[..7].copy_from_slice(&[
            0x7f,
            b'E',
            b'L',
            b'F',
            if bits == 64 { 2 } else { 1 },
            if little { 1 } else { 2 },
            1,
        ]);
        put(&mut bytes, 16, 2, 1, little);
        put(&mut bytes, 18, 2, 62, little);
        put(&mut bytes, 20, 4, 1, little);
        let tail = if bits == 64 { 48 } else { 36 };
        let word = if bits == 64 { 8 } else { 4 };
        put(
            &mut bytes,
            if bits == 64 { 40 } else { 32 },
            word,
            0x200,
            little,
        );
        put(
            &mut bytes,
            tail + 4,
            2,
            if bits == 64 { 64 } else { 52 },
            little,
        );
        put(&mut bytes, tail + 10, 2, size as u64, little);
        put(&mut bytes, tail + 12, 2, sections.len() as u64, little);
        put(&mut bytes, tail + 14, 2, u64::from(shstrndx), little);
        bytes[0x80..0x80 + 22].copy_from_slice(b"\0.text\0.shstrtab\0.dbg\0");
        for (index, section) in sections.iter().enumerate() {
            let start = 0x200 + index * size;
            put(&mut bytes, start, 4, u64::from(section.name), little);
            put(&mut bytes, start + 4, 4, u64::from(section.kind), little);
            let fields = if bits == 64 {
                [(8, section.flags), (24, section.offset), (32, section.size)]
            } else {
                [(8, section.flags), (16, section.offset), (20, section.size)]
            };
            for (at, value) in fields {
                put(&mut bytes, start + at, word, value, little);
            }
        }
        bytes
    }

    fn standard() -> Vec<Section> {
        vec![
            Section {
                name: 0,
                kind: 0,
                flags: 0,
                offset: 0,
                size: 0,
            },
            Section {
                name: 1,
                kind: 1,
                flags: 6,
                offset: 0x100,
                size: 16,
            },
            Section {
                name: 7,
                kind: 3,
                flags: 0,
                offset: 0x80,
                size: 22,
            },
        ]
    }

    #[test]
    fn all_four_layouts_decode_records_and_names() {
        for bits in [32, 64] {
            for little in [false, true] {
                let bytes = fixture(bits, little, &standard(), 2);
                for policy in [ParsePolicy::Strict, ParsePolicy::GhidraCompatible] {
                    let table = parse_section_headers(&bytes, policy).unwrap();
                    assert_eq!(table.len(), 3);
                    let text = table.get(1).unwrap();
                    assert_eq!(
                        (text.section_type, text.flags, text.offset, text.size),
                        (1, 6, 0x100, 16)
                    );
                    assert_eq!(table.name(0).unwrap(), "SECTION0");
                    assert_eq!(table.name(1).unwrap(), ".text");
                    assert_eq!(table.name(2).unwrap(), ".shstrtab");
                    assert_eq!(table.name(3), None);
                    assert_eq!(table.get(3), None);
                    let mut iter = table.iter();
                    assert_eq!(iter.len(), 3);
                    assert_eq!(iter.nth(1), Some(text));
                    assert_eq!(iter.len(), 1);
                    assert!(iter.next().is_some());
                    assert_eq!(iter.next(), None);
                    assert_eq!(iter.next(), None);
                }
            }
        }
    }

    #[test]
    fn compatible_names_ignore_string_table_size_but_strict_rejects() {
        let mut sections = standard();
        sections[2].size = 1;
        let bytes = fixture(64, true, &sections, 2);
        let table = parse_section_headers(&bytes, ParsePolicy::GhidraCompatible).unwrap();
        assert_eq!(table.name(1).unwrap(), ".text");
        assert_eq!(table.name(2).unwrap(), ".shstrtab");
        assert_eq!(
            parse_section_headers(&bytes, ParsePolicy::Strict)
                .unwrap_err()
                .kind,
            ErrorKind::NameOutOfBounds {
                index: 1,
                name_index: 1
            }
        );
        sections[2].size = 22;
        sections[1].name = 0x8000_0000;
        let bytes = fixture(64, true, &sections, 2);
        let table = parse_section_headers(&bytes, ParsePolicy::GhidraCompatible).unwrap();
        assert_eq!(table.name(1).unwrap(), "SECTION1");
        assert_eq!(table.name_bytes(1), None);
    }

    #[test]
    fn compression_probe_follows_the_default_load_adapter() {
        for bits in [32, 64] {
            for little in [false, true] {
                let mut sections = standard();
                sections.push(Section {
                    name: 17,
                    kind: 1,
                    flags: SHF_COMPRESSED,
                    offset: 0x100,
                    size: 40,
                });
                let mut bytes = fixture(bits, little, &sections, 2);
                put(&mut bytes, 0x100, 4, 1, little);
                if bits == 64 {
                    put(&mut bytes, 0x108, 8, 0x1234, little);
                    put(&mut bytes, 0x110, 8, 8, little);
                } else {
                    put(&mut bytes, 0x104, 4, 0x1234, little);
                    put(&mut bytes, 0x108, 4, 8, little);
                }
                let table = parse_section_headers(&bytes, ParsePolicy::GhidraCompatible).unwrap();
                let section = table.get(3).unwrap();
                assert_eq!(
                    section.compression,
                    Compression::Compressed(CompressionHeader {
                        compression_type: 1,
                        size: 0x1234,
                        address_align: 8,
                        header_size: if bits == 64 { 24 } else { 12 },
                    })
                );
                assert_eq!(section.logical_size(), 0x1234);
                assert_eq!(table.name(3).unwrap(), ".dbg");

                put(&mut bytes, 0x100, 4, 2, little);
                let table = parse_section_headers(&bytes, ParsePolicy::GhidraCompatible).unwrap();
                assert_eq!(
                    table.get(3).unwrap().compression,
                    Compression::Invalid(CompressionError::UnsupportedType(2))
                );
            }
        }
        let mut sections = standard();
        sections[1].flags |= SHF_COMPRESSED;
        let bytes = fixture(64, true, &sections, 2);
        let table = parse_section_headers(&bytes, ParsePolicy::Strict).unwrap();
        assert_eq!(
            table.get(1).unwrap().compression,
            Compression::Invalid(CompressionError::InvalidRegion)
        );
    }

    #[test]
    fn truncated_table_zero_fills_only_in_compatible_mode() {
        let mut bytes = fixture(64, true, &standard(), 2);
        bytes.truncate(0x200 + 64 + 10);
        let table = parse_section_headers(&bytes, ParsePolicy::GhidraCompatible).unwrap();
        assert_eq!(
            table.missing(),
            Some(MissingHeaders {
                first_missing: 1,
                total: 3
            })
        );
        assert_eq!(table.zero_filled_entries(), 2);
        assert_eq!(table.get(1).unwrap().section_type, 1);
        assert_eq!(table.get(2).unwrap().offset, 0);
        assert!(matches!(
            parse_section_headers(&bytes, ParsePolicy::Strict)
                .unwrap_err()
                .kind,
            ErrorKind::TableOutOfBounds { .. }
        ));
    }

    #[test]
    fn negative_offsets_and_count_limit_are_rejected() {
        let mut bytes = fixture(64, true, &standard(), 2);
        bytes[58..60].copy_from_slice(&0xffffu16.to_le_bytes());
        bytes[40..48].copy_from_slice(&0u64.to_le_bytes());
        let error = parse_section_headers(&bytes, ParsePolicy::GhidraCompatible).unwrap_err();
        assert_eq!(
            error.kind,
            ErrorKind::InvalidRecordOffset {
                index: 1,
                offset: -1
            }
        );
        let mut bytes = fixture(64, true, &[], 0);
        bytes[40..48].copy_from_slice(&0x200u64.to_le_bytes());
        bytes.extend_from_slice(&[0u8; 64]);
        bytes[0x200 + 32..0x200 + 40].copy_from_slice(&65537u64.to_le_bytes());
        assert_eq!(
            parse_section_headers(&bytes, ParsePolicy::GhidraCompatible)
                .unwrap_err()
                .kind,
            ErrorKind::HeaderCountLimit {
                count: 65537,
                limit: MAX_SECTION_HEADERS
            }
        );
    }

    #[test]
    fn utf8_replacement_follows_java() {
        for (input, expected) in [
            (&b".text"[..], ".text"),
            (b"\xed\xa0\x80", "\u{fffd}"),
            (b"\xed\xa0", "\u{fffd}"),
            (b"\xed\xa0A", "\u{fffd}A"),
            (b"\xe0\x80\x80", "\u{fffd}\u{fffd}\u{fffd}"),
            (b"\xe2\x82", "\u{fffd}"),
            (b"\xe2(", "\u{fffd}("),
            (b"\xf0\x9f\x98", "\u{fffd}"),
            (b"\xf0\x9f\x98A", "\u{fffd}A"),
            (b"\xf0\x9fA", "\u{fffd}A"),
            (b"\xf4\x90\x80\x80", "\u{fffd}\u{fffd}\u{fffd}\u{fffd}"),
            (b"\xc0\x80", "\u{fffd}\u{fffd}"),
            (b"\xc3", "\u{fffd}"),
            (b"\xc3\xa9\xff", "\u{e9}\u{fffd}"),
            (b"\xf0\x9f\x98\x80", "\u{1f600}"),
        ] {
            assert_eq!(java_utf8_lossy(input), expected, "{input:x?}");
        }
    }

    #[test]
    fn extended_symbol_index_table_is_detected() {
        let mut sections = standard();
        sections[1].kind = SHT_SYMTAB_SHNDX;
        let bytes = fixture(32, false, &sections, 2);
        for policy in [ParsePolicy::Strict, ParsePolicy::GhidraCompatible] {
            assert!(
                parse_section_headers(&bytes, policy)
                    .unwrap()
                    .has_extended_symbol_index_table()
            );
        }
    }
}
