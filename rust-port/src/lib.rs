// SPDX-License-Identifier: Apache-2.0
// Source-guided port of Ghidra's ElfHeader constructor (see NOTICE).
//! ELF file-header decoding only: no table allocation or executable loading.
//!
//! The input is borrowed for the duration of parsing. The returned numeric fields,
//! identification bytes and diagnostic bitset are owned and allocate no memory.
//! Strict mode validates header structure and required section-zero reads; it
//! does not validate program/section table bodies or target-specific constraints.

#![forbid(unsafe_code)]

use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParsePolicy {
    Strict,
    GhidraCompatible,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum Diagnostic {
    TruncatedHeaderZeroFilled = 1,
    InvalidEncodingAssumedLittleEndian = 2,
    DeclaredEndianOverridden = 4,
    MissingSectionZero = 8,
    TruncatedSectionZeroFilled = 16,
    NonNullSectionZero = 32,
    ExtendedValueOutOfRange = 64,
    StringIndexClearedWithoutSections = 128,
}

impl Diagnostic {
    pub const fn name(self) -> &'static str {
        match self {
            Self::TruncatedHeaderZeroFilled => "truncated_header_zero_filled",
            Self::InvalidEncodingAssumedLittleEndian => "invalid_encoding_assumed_little_endian",
            Self::DeclaredEndianOverridden => "declared_endian_overridden",
            Self::MissingSectionZero => "missing_section_zero",
            Self::TruncatedSectionZeroFilled => "truncated_section_zero_filled",
            Self::NonNullSectionZero => "non_null_section_zero",
            Self::ExtendedValueOutOfRange => "extended_value_out_of_range",
            Self::StringIndexClearedWithoutSections => "string_index_cleared_without_sections",
        }
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Diagnostics(u16);

impl Diagnostics {
    pub const fn bits(self) -> u16 {
        self.0
    }

    pub const fn contains(self, diagnostic: Diagnostic) -> bool {
        self.0 & diagnostic as u16 != 0
    }

    pub fn iter(self) -> impl Iterator<Item = Diagnostic> {
        [
            Diagnostic::TruncatedHeaderZeroFilled,
            Diagnostic::InvalidEncodingAssumedLittleEndian,
            Diagnostic::DeclaredEndianOverridden,
            Diagnostic::MissingSectionZero,
            Diagnostic::TruncatedSectionZeroFilled,
            Diagnostic::NonNullSectionZero,
            Diagnostic::ExtendedValueOutOfRange,
            Diagnostic::StringIndexClearedWithoutSections,
        ]
        .into_iter()
        .filter(move |item| self.contains(*item))
    }

    fn insert(&mut self, diagnostic: Diagnostic) {
        self.0 |= diagnostic as u16;
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParsedHeader {
    pub ident: [u8; 16],
    pub class_bits: u8,
    pub header_little_endian: bool,
    pub declared_little_endian: bool,
    pub elf_type: u16,
    pub machine: u16,
    pub version: u32,
    pub entry: u64,
    pub phoff: u64,
    pub shoff: u64,
    pub flags: u32,
    pub ehsize: u16,
    pub phentsize: u16,
    pub phnum: u32,
    pub shentsize: u16,
    pub shnum: u32,
    pub shstrndx: u32,
    pub raw_phnum: u16,
    pub raw_shnum: u16,
    pub raw_shstrndx: u16,
    pub diagnostics: Diagnostics,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseError {
    TruncatedHeader { needed: usize, actual: usize },
    BadMagic,
    UnsupportedClass(u8),
    InvalidEncoding(u8),
    InvalidIdentVersion(u8),
    InvalidVersion(u32),
    InvalidHeaderSize { expected: u16, actual: u16 },
    InvalidProgramEntrySize { expected: u16, actual: u16 },
    InvalidSectionEntrySize { expected: u16, actual: u16 },
    MissingProgramTableOffset,
    MissingSectionTableOffset,
    MissingSectionZero,
    TruncatedSectionZero,
    InvalidSectionZeroType(u32),
    ExtendedValueOverflow,
    ReservedSectionCount(u16),
    InvalidStringTableIndex(u32),
    OffsetOverflow,
}

impl ParseError {
    pub const fn kind(self) -> &'static str {
        match self {
            Self::TruncatedHeader { .. } => "TruncatedHeader",
            Self::BadMagic => "BadMagic",
            Self::UnsupportedClass(_) => "UnsupportedClass",
            Self::InvalidEncoding(_) => "InvalidEncoding",
            Self::InvalidIdentVersion(_) => "InvalidIdentVersion",
            Self::InvalidVersion(_) => "InvalidVersion",
            Self::InvalidHeaderSize { .. } => "InvalidHeaderSize",
            Self::InvalidProgramEntrySize { .. } => "InvalidProgramEntrySize",
            Self::InvalidSectionEntrySize { .. } => "InvalidSectionEntrySize",
            Self::MissingProgramTableOffset => "MissingProgramTableOffset",
            Self::MissingSectionTableOffset => "MissingSectionTableOffset",
            Self::MissingSectionZero => "MissingSectionZero",
            Self::TruncatedSectionZero => "TruncatedSectionZero",
            Self::InvalidSectionZeroType(_) => "InvalidSectionZeroType",
            Self::ExtendedValueOverflow => "ExtendedValueOverflow",
            Self::ReservedSectionCount(_) => "ReservedSectionCount",
            Self::InvalidStringTableIndex(_) => "InvalidStringTableIndex",
            Self::OffsetOverflow => "OffsetOverflow",
        }
    }
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for ParseError {}

/// Decode the ELF header and the section-zero fields needed for extended counts.
/// No input-dependent allocation or iteration over declared table counts occurs.
pub fn parse_header(bytes: &[u8], policy: ParsePolicy) -> Result<ParsedHeader, ParseError> {
    if bytes.len() < 4 {
        return Err(ParseError::TruncatedHeader {
            needed: 4,
            actual: bytes.len(),
        });
    }
    if bytes[..4] != *b"\x7fELF" {
        return Err(ParseError::BadMagic);
    }
    if bytes.len() < 34 {
        return Err(ParseError::TruncatedHeader {
            needed: 34,
            actual: bytes.len(),
        });
    }
    let compatible = policy == ParsePolicy::GhidraCompatible;
    let mut diagnostics = Diagnostics::default();
    let mut little_endian = bytes[5] != 2;
    if !matches!(bytes[5], 1 | 2) {
        if !compatible {
            return Err(ParseError::InvalidEncoding(bytes[5]));
        }
        diagnostics.insert(Diagnostic::InvalidEncodingAssumedLittleEndian);
    }
    if compatible && !little_endian && bytes[16] != 0 && bytes[20] == 1 {
        little_endian = true;
        diagnostics.insert(Diagnostic::DeclaredEndianOverridden);
    }
    let header_len = match bytes[4] {
        1 => 52,
        2 => 64,
        other => return Err(ParseError::UnsupportedClass(other)),
    };
    let mut padded = [0u8; 64];
    let header_bytes = if bytes.len() < header_len {
        if !compatible {
            return Err(ParseError::TruncatedHeader {
                needed: header_len,
                actual: bytes.len(),
            });
        }
        diagnostics.insert(Diagnostic::TruncatedHeaderZeroFilled);
        padded[..bytes.len()].copy_from_slice(bytes);
        &padded[..header_len]
    } else {
        &bytes[..header_len]
    };
    let mut header = if little_endian {
        decode_header::<true>(header_bytes)
    } else {
        decode_header::<false>(header_bytes)
    };
    header.diagnostics = diagnostics;
    if compatible {
        resolve_compatible(bytes, &mut header)?;
    } else {
        resolve_strict(bytes, &mut header)?;
    }
    Ok(header)
}

#[inline]
fn u16_at<const LE: bool>(bytes: &[u8], offset: usize) -> u16 {
    let value = bytes[offset..offset + 2].try_into().unwrap();
    if LE {
        u16::from_le_bytes(value)
    } else {
        u16::from_be_bytes(value)
    }
}

#[inline]
fn u32_at<const LE: bool>(bytes: &[u8], offset: usize) -> u32 {
    let value = bytes[offset..offset + 4].try_into().unwrap();
    if LE {
        u32::from_le_bytes(value)
    } else {
        u32::from_be_bytes(value)
    }
}

#[inline]
fn u64_at<const LE: bool>(bytes: &[u8], offset: usize) -> u64 {
    let value = bytes[offset..offset + 8].try_into().unwrap();
    if LE {
        u64::from_le_bytes(value)
    } else {
        u64::from_be_bytes(value)
    }
}

fn decode_header<const LE: bool>(bytes: &[u8]) -> ParsedHeader {
    let is_64 = bytes[4] == 2;
    let (entry, phoff, shoff, tail) = if is_64 {
        (
            u64_at::<LE>(bytes, 24),
            u64_at::<LE>(bytes, 32),
            u64_at::<LE>(bytes, 40),
            48,
        )
    } else {
        (
            u32_at::<LE>(bytes, 24) as u64,
            u32_at::<LE>(bytes, 28) as u64,
            u32_at::<LE>(bytes, 32) as u64,
            36,
        )
    };
    let raw_phnum = u16_at::<LE>(bytes, tail + 8);
    let raw_shnum = u16_at::<LE>(bytes, tail + 12);
    let raw_shstrndx = u16_at::<LE>(bytes, tail + 14);
    ParsedHeader {
        ident: bytes[..16].try_into().unwrap(),
        class_bits: if is_64 { 64 } else { 32 },
        header_little_endian: LE,
        declared_little_endian: bytes[5] == 1,
        elf_type: u16_at::<LE>(bytes, 16),
        machine: u16_at::<LE>(bytes, 18),
        version: u32_at::<LE>(bytes, 20),
        entry,
        phoff,
        shoff,
        flags: u32_at::<LE>(bytes, tail),
        ehsize: u16_at::<LE>(bytes, tail + 4),
        phentsize: u16_at::<LE>(bytes, tail + 6),
        phnum: raw_phnum as u32,
        shentsize: u16_at::<LE>(bytes, tail + 10),
        shnum: raw_shnum as u32,
        shstrndx: raw_shstrndx as u32,
        raw_phnum,
        raw_shnum,
        raw_shstrndx,
        diagnostics: Diagnostics::default(),
    }
}

#[derive(Clone, Copy)]
struct SectionZero {
    section_type: u32,
    size: u64,
    link: u32,
    info: u32,
}

fn decode_section<const LE: bool>(bytes: &[u8], is_64: bool) -> SectionZero {
    SectionZero {
        section_type: u32_at::<LE>(bytes, 4),
        size: if is_64 {
            u64_at::<LE>(bytes, 32)
        } else {
            u32_at::<LE>(bytes, 20) as u64
        },
        link: u32_at::<LE>(bytes, if is_64 { 40 } else { 24 }),
        info: u32_at::<LE>(bytes, if is_64 { 44 } else { 28 }),
    }
}

fn section_from_bytes(bytes: &[u8], header: &ParsedHeader) -> SectionZero {
    if header.header_little_endian {
        decode_section::<true>(bytes, header.class_bits == 64)
    } else {
        decode_section::<false>(bytes, header.class_bits == 64)
    }
}

fn compatible_section(
    bytes: &[u8],
    header: &mut ParsedHeader,
    gate_size: i16,
) -> Result<Option<SectionZero>, ParseError> {
    // Java's short entry size is signed. During e_phnum resolution its final
    // field has not been assigned yet and is still zero. Preserve both details,
    // using widened arithmetic so malformed offsets cannot overflow or wrap.
    if header.shoff <= i64::MAX as u64
        && header.shoff as i128 + gate_size as i128 > i64::MAX as i128
    {
        return Err(ParseError::OffsetOverflow);
    }
    if header.shoff == 0
        || header.shoff > i64::MAX as u64
        || header.shoff as i128 + gate_size as i128 > bytes.len() as i128
    {
        if header.shoff != 0 || header.raw_phnum == u16::MAX || header.raw_shstrndx == u16::MAX {
            header.diagnostics.insert(Diagnostic::MissingSectionZero);
        }
        return Ok(None);
    }
    let length = if header.class_bits == 64 { 64 } else { 40 };
    let offset = usize::try_from(header.shoff).map_err(|_| ParseError::OffsetOverflow)?;
    let tail = bytes.get(offset..).unwrap_or_default();
    let mut padded = [0u8; 64];
    let section_bytes = if tail.len() < length {
        header
            .diagnostics
            .insert(Diagnostic::TruncatedSectionZeroFilled);
        padded[..tail.len()].copy_from_slice(tail);
        &padded[..length]
    } else {
        &tail[..length]
    };
    let section = section_from_bytes(section_bytes, header);
    if section.section_type != 0 {
        header.diagnostics.insert(Diagnostic::NonNullSectionZero);
    }
    Ok(Some(section))
}

fn compatible_value(value: u64, diagnostics: &mut Diagnostics) -> u32 {
    if value <= i32::MAX as u64 {
        value as u32
    } else {
        diagnostics.insert(Diagnostic::ExtendedValueOutOfRange);
        0
    }
}

fn resolve_compatible(bytes: &[u8], header: &mut ParsedHeader) -> Result<(), ParseError> {
    let mut section = None;
    if header.raw_phnum == u16::MAX {
        section = compatible_section(bytes, header, 0)?;
        header.phnum = match section {
            Some(s) if s.section_type == 0 => {
                compatible_value(s.info as u64, &mut header.diagnostics)
            }
            _ => 0,
        };
    }
    if header.raw_shnum == 0 || header.raw_shnum >= 0xff00 {
        if section.is_none() {
            section = compatible_section(bytes, header, header.shentsize as i16)?;
        }
        header.shnum = match section {
            Some(s) if s.section_type == 0 => compatible_value(s.size, &mut header.diagnostics),
            _ => 0,
        };
    }
    if header.shnum == 0 {
        if header.raw_shstrndx != 0 {
            header
                .diagnostics
                .insert(Diagnostic::StringIndexClearedWithoutSections);
        }
        header.shstrndx = 0;
    } else if header.raw_shstrndx == u16::MAX {
        if section.is_none() {
            section = compatible_section(bytes, header, header.shentsize as i16)?;
        }
        header.shstrndx = match section {
            Some(s) if s.section_type == 0 => {
                compatible_value(s.link as u64, &mut header.diagnostics)
            }
            _ => 0,
        };
    }
    Ok(())
}

fn resolve_strict(bytes: &[u8], header: &mut ParsedHeader) -> Result<(), ParseError> {
    if header.ident[6] != 1 {
        return Err(ParseError::InvalidIdentVersion(header.ident[6]));
    }
    if header.version != 1 {
        return Err(ParseError::InvalidVersion(header.version));
    }
    let is_64 = header.class_bits == 64;
    let expected_header = if is_64 { 64 } else { 52 };
    let expected_program = if is_64 { 56 } else { 32 };
    let expected_section = if is_64 { 64 } else { 40 };
    if header.ehsize != expected_header {
        return Err(ParseError::InvalidHeaderSize {
            expected: expected_header,
            actual: header.ehsize,
        });
    }
    if header.raw_shnum >= 0xff00 {
        return Err(ParseError::ReservedSectionCount(header.raw_shnum));
    }
    let need_section = header.raw_phnum == u16::MAX
        || header.raw_shstrndx == u16::MAX
        || (header.raw_shnum == 0 && header.shoff != 0);
    if (header.shoff != 0 || header.raw_shnum != 0 || need_section)
        && header.shentsize != expected_section
    {
        return Err(ParseError::InvalidSectionEntrySize {
            expected: expected_section,
            actual: header.shentsize,
        });
    }
    if header.raw_shnum != 0 && header.shoff == 0 {
        return Err(ParseError::MissingSectionTableOffset);
    }
    if need_section {
        if header.shoff == 0 {
            return Err(ParseError::MissingSectionZero);
        }
        let offset = usize::try_from(header.shoff).map_err(|_| ParseError::OffsetOverflow)?;
        let end = offset
            .checked_add(expected_section as usize)
            .ok_or(ParseError::OffsetOverflow)?;
        let section_bytes = bytes
            .get(offset..end)
            .ok_or(ParseError::TruncatedSectionZero)?;
        let section = section_from_bytes(section_bytes, header);
        if section.section_type != 0 {
            return Err(ParseError::InvalidSectionZeroType(section.section_type));
        }
        if header.raw_phnum == u16::MAX {
            header.phnum = section.info;
        }
        if header.raw_shnum == 0 {
            header.shnum =
                u32::try_from(section.size).map_err(|_| ParseError::ExtendedValueOverflow)?;
        }
        if header.raw_shstrndx == u16::MAX {
            header.shstrndx = section.link;
        }
    }
    if header.phnum != 0 {
        if header.phentsize != expected_program {
            return Err(ParseError::InvalidProgramEntrySize {
                expected: expected_program,
                actual: header.phentsize,
            });
        }
        if header.phoff == 0 {
            return Err(ParseError::MissingProgramTableOffset);
        }
    }
    if (header.shnum == 0 && header.shstrndx != 0)
        || (header.shnum != 0 && header.shstrndx >= header.shnum)
        || (header.raw_shstrndx >= 0xff00 && header.raw_shstrndx != u16::MAX)
    {
        return Err(ParseError::InvalidStringTableIndex(header.shstrndx));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid() -> Vec<u8> {
        include_bytes!("../fixtures/valid-64-le.elf").to_vec()
    }

    #[test]
    fn canonical_classes_and_encodings() {
        for (bytes, bits, little) in [
            (&include_bytes!("../fixtures/valid-32-le.elf")[..], 32, true),
            (
                &include_bytes!("../fixtures/valid-32-be.elf")[..],
                32,
                false,
            ),
            (&include_bytes!("../fixtures/valid-64-le.elf")[..], 64, true),
            (
                &include_bytes!("../fixtures/valid-64-be.elf")[..],
                64,
                false,
            ),
        ] {
            for policy in [ParsePolicy::Strict, ParsePolicy::GhidraCompatible] {
                let h = parse_header(bytes, policy).unwrap();
                assert_eq!((h.class_bits, h.header_little_endian), (bits, little));
                assert_eq!(h.entry, 0x12345678);
                assert_eq!(h.diagnostics.bits(), 0);
            }
        }
    }

    #[test]
    fn every_header_truncation_has_explicit_policy() {
        let bytes = valid();
        for n in 0..64 {
            assert!(
                parse_header(&bytes[..n], ParsePolicy::Strict).is_err(),
                "length {n}"
            );
            let compatible = parse_header(&bytes[..n], ParsePolicy::GhidraCompatible);
            assert_eq!(compatible.is_ok(), n >= 34, "length {n}");
            if let Ok(h) = compatible {
                assert!(
                    h.diagnostics
                        .contains(Diagnostic::TruncatedHeaderZeroFilled)
                );
            }
        }
    }

    #[test]
    fn endian_recovery_remains_opt_in() {
        let mut bytes = valid();
        bytes[5] = 2;
        let h = parse_header(&bytes, ParsePolicy::GhidraCompatible).unwrap();
        assert!(!h.declared_little_endian);
        assert!(h.header_little_endian);
        assert!(h.diagnostics.contains(Diagnostic::DeclaredEndianOverridden));
        assert!(matches!(
            parse_header(&bytes, ParsePolicy::Strict),
            Err(ParseError::InvalidVersion(_))
        ));
        bytes[5] = 255;
        assert_eq!(
            parse_header(&bytes, ParsePolicy::Strict),
            Err(ParseError::InvalidEncoding(255))
        );
        assert!(
            parse_header(&bytes, ParsePolicy::GhidraCompatible)
                .unwrap()
                .header_little_endian
        );
    }

    #[test]
    fn strict_versions_and_required_sizes() {
        let mut bytes = valid();
        bytes[6] = 0;
        assert_eq!(
            parse_header(&bytes, ParsePolicy::Strict),
            Err(ParseError::InvalidIdentVersion(0))
        );
        bytes[6] = 1;
        bytes[20] = 0;
        assert_eq!(
            parse_header(&bytes, ParsePolicy::Strict),
            Err(ParseError::InvalidVersion(0))
        );
        bytes[20] = 1;
        bytes[52] = 0;
        assert!(matches!(
            parse_header(&bytes, ParsePolicy::Strict),
            Err(ParseError::InvalidHeaderSize { .. })
        ));
        bytes[52] = 64;
        bytes[54] = 1; // irrelevant while there are no program headers
        assert!(parse_header(&bytes, ParsePolicy::Strict).is_ok());
        bytes[56] = 1;
        assert!(matches!(
            parse_header(&bytes, ParsePolicy::Strict),
            Err(ParseError::InvalidProgramEntrySize { .. })
        ));
    }

    #[test]
    fn java_initialization_order_preserves_truncated_section_zero() {
        let mut bytes = include_bytes!("../fixtures/extended-64-le.elf").to_vec();
        bytes.truncate(112); // info is available, last 16 bytes are missing
        let h = parse_header(&bytes, ParsePolicy::GhidraCompatible).unwrap();
        assert_eq!((h.phnum, h.shnum, h.shstrndx), (2, 3, 1));
        assert!(
            h.diagnostics
                .contains(Diagnostic::TruncatedSectionZeroFilled)
        );
        bytes[56..58].copy_from_slice(&0u16.to_le_bytes()); // no early section0 cache
        let h = parse_header(&bytes, ParsePolicy::GhidraCompatible).unwrap();
        assert_eq!((h.phnum, h.shnum, h.shstrndx), (0, 0, 0));
        assert_eq!(
            parse_header(&bytes, ParsePolicy::Strict),
            Err(ParseError::TruncatedSectionZero)
        );
    }

    #[test]
    fn strict_extended_count_and_offset_boundaries() {
        let mut bytes = include_bytes!("../fixtures/extended-64-le.elf").to_vec();
        bytes[32..40].copy_from_slice(&64u64.to_le_bytes());
        let h = parse_header(&bytes, ParsePolicy::Strict).unwrap();
        assert_eq!((h.phnum, h.shnum, h.shstrndx), (2, 3, 1));
        bytes[96..104].copy_from_slice(&(u32::MAX as u64 + 1).to_le_bytes());
        assert_eq!(
            parse_header(&bytes, ParsePolicy::Strict),
            Err(ParseError::ExtendedValueOverflow)
        );
        bytes[40..48].copy_from_slice(&u64::MAX.to_le_bytes());
        assert_eq!(
            parse_header(&bytes, ParsePolicy::Strict),
            Err(ParseError::OffsetOverflow)
        );
        assert_eq!(
            parse_header(&bytes, ParsePolicy::GhidraCompatible)
                .unwrap()
                .shnum,
            0
        );
    }

    #[test]
    fn strict_string_index_and_missing_offsets() {
        let mut bytes = valid();
        bytes[62] = 1;
        assert_eq!(
            parse_header(&bytes, ParsePolicy::Strict),
            Err(ParseError::InvalidStringTableIndex(1))
        );
        bytes[62] = 0;
        bytes[56] = 1;
        assert_eq!(
            parse_header(&bytes, ParsePolicy::Strict),
            Err(ParseError::MissingProgramTableOffset)
        );
        bytes[56] = 0;
        bytes[60] = 1;
        assert_eq!(
            parse_header(&bytes, ParsePolicy::Strict),
            Err(ParseError::MissingSectionTableOffset)
        );
    }

    #[test]
    fn signed_region_overflow_is_rejected_without_pointer_wrap() {
        let mut bytes = valid();
        for offset in [i64::MAX as u64 - 3, i64::MAX as u64, i64::MAX as u64 - 63] {
            bytes[40..48].copy_from_slice(&offset.to_le_bytes());
            assert_eq!(
                parse_header(&bytes, ParsePolicy::GhidraCompatible),
                Err(ParseError::OffsetOverflow)
            );
        }
        // The first extended-program-count lookup uses a zero gate size and
        // rejects the out-of-file offset before the later positive-size lookup.
        bytes[56..58].copy_from_slice(&u16::MAX.to_le_bytes());
        assert_eq!(
            parse_header(&bytes, ParsePolicy::GhidraCompatible),
            Err(ParseError::OffsetOverflow)
        );
        bytes[40..48].copy_from_slice(&(i64::MAX as u64 + 1).to_le_bytes());
        assert_eq!(
            parse_header(&bytes, ParsePolicy::GhidraCompatible)
                .unwrap()
                .shnum,
            0
        );
    }
}
