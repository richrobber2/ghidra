// SPDX-License-Identifier: Apache-2.0
// Adapted from Ghidra ElfHeader.parseProgramHeaders and ElfProgramHeader.
//! Borrowed ELF program-header table decoding. No Program, memory mapping,
//! architecture adapter, PRE trailer or segment-payload decoding is performed.
//!
//! Compatibility mode retains the original signed short stride, missing-region
//! warning, zero-filled records and wrapping-sum offset-rewriting heuristic.
//! Signed record-address overflow is rejected instead of allowing Java wrap.
//! Strict mode validates the header and complete canonical program-header table;
//! it preserves raw offsets and does not apply that heuristic. Neither policy
//! validates section tables, segment payload extents or segment constraints.

#![forbid(unsafe_code)]

use std::fmt;
use std::iter::FusedIterator;
use ghidra_elf::{parse_header, ParseError, ParsedHeader};
pub use ghidra_elf::ParsePolicy;

/// An explicit time/resource bound, not a limit imposed by the ELF format.
pub const MAX_PROGRAM_HEADERS: u32 = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProgramHeader {
    pub segment_type: u32,
    pub flags: u32,
    pub raw_offset: u64,
    pub offset: u64,
    pub virtual_address: u64,
    pub physical_address: u64,
    pub file_size: u64,
    pub memory_size: u64,
    pub align: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MissingHeaders {
    pub first_missing: u32,
    pub total: u32,
}

impl fmt::Display for MissingHeaders {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{} of {} program headers are truncated/missing from file",
               self.total - self.first_missing, self.total)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorKind {
    Header(ParseError),
    HeaderCountLimit { count: u32, limit: u32 },
    TableExtentOverflow,
    TableOutOfBounds { offset: u64, length: u64, file_length: u64 },
    InvalidRecordOffset { index: u32, offset: i64 },
    RecordOffsetOverflow { index: u32 },
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

/// A validated borrowed view. Fields affecting iteration are private so callers
/// cannot invalidate the bounds established by `parse_program_headers`.
#[derive(Debug, Clone)]
pub struct ProgramHeaders<'a> {
    bytes: &'a [u8],
    header: ParsedHeader,
    policy: ParsePolicy,
    missing: Option<MissingHeaders>,
    offsets_rewritten: bool,
    zero_filled_entries: u32,
}

impl<'a> ProgramHeaders<'a> {
    pub fn header(&self) -> &ParsedHeader { &self.header }
    pub fn len(&self) -> usize { self.header.phnum as usize }
    pub fn is_empty(&self) -> bool { self.header.phnum == 0 }
    pub fn missing(&self) -> Option<MissingHeaders> { self.missing }
    pub fn offsets_rewritten(&self) -> bool { self.offsets_rewritten }
    pub fn zero_filled_entries(&self) -> u32 { self.zero_filled_entries }

    fn raw(&self, index: u32) -> Option<ProgramHeader> {
        if index >= self.header.phnum { return None; }
        let offset = match self.policy {
            ParsePolicy::Strict => self.header.phoff.checked_add(u64::from(index) * u64::from(self.header.phentsize))?,
            ParsePolicy::GhidraCompatible => compatible_offset(self.header, index).ok()? as u64,
        };
        Some(decode_at(self.bytes, offset, self.header.class_bits, self.header.header_little_endian))
    }

    /// Random access is O(index) only when the legacy rewrite is active; use
    /// `iter` for a linear scan with constant additional storage.
    pub fn get(&self, index: usize) -> Option<ProgramHeader> {
        let index = u32::try_from(index).ok()?;
        let mut value = self.raw(index)?;
        if self.offsets_rewritten {
            let mut offset = 0u64;
            for prior in 0..index { offset = offset.wrapping_add(self.raw(prior)?.file_size); }
            value.offset = offset;
        }
        Some(value)
    }

    pub fn iter(&self) -> ProgramHeaderIter<'_, 'a> {
        ProgramHeaderIter { table: self, index: 0, adjusted_offset: 0 }
    }
}

pub struct ProgramHeaderIter<'table, 'bytes> {
    table: &'table ProgramHeaders<'bytes>,
    index: u32,
    adjusted_offset: u64,
}

impl Iterator for ProgramHeaderIter<'_, '_> {
    type Item = ProgramHeader;
    fn next(&mut self) -> Option<Self::Item> {
        let mut value = self.table.raw(self.index)?;
        self.index += 1;
        if self.table.offsets_rewritten {
            value.offset = self.adjusted_offset;
            self.adjusted_offset = self.adjusted_offset.wrapping_add(value.file_size);
        }
        Some(value)
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = (self.table.header.phnum - self.index) as usize;
        (remaining, Some(remaining))
    }
}
impl ExactSizeIterator for ProgramHeaderIter<'_, '_> {}
impl FusedIterator for ProgramHeaderIter<'_, '_> {}

fn compatible_offset(header: ParsedHeader, index: u32) -> Result<i64, ErrorKind> {
    // The count bound makes Java's int multiplication fit. Checked addition
    // deliberately refuses signed-long wrapping into a different file region.
    let stride = i64::from(header.phentsize as i16);
    let delta = i64::from(index).checked_mul(stride)
        .ok_or(ErrorKind::RecordOffsetOverflow { index })?;
    let offset = (header.phoff as i64).checked_add(delta)
        .ok_or(ErrorKind::RecordOffsetOverflow { index })?;
    if offset < 0 { return Err(ErrorKind::InvalidRecordOffset { index, offset }); }
    Ok(offset)
}

pub fn parse_program_headers(bytes: &[u8], policy: ParsePolicy) -> Result<ProgramHeaders<'_>, ParseFailure> {
    let header = parse_header(bytes, policy)
        .map_err(|error| ParseFailure { kind: ErrorKind::Header(error), header: None, missing: None })?;
    let mut table = ProgramHeaders {
        bytes, header, policy, missing: None, offsets_rewritten: false, zero_filled_entries: 0,
    };
    let fail = |kind, missing| ParseFailure { kind, header: Some(header), missing };
    if header.phnum > MAX_PROGRAM_HEADERS {
        return Err(fail(ErrorKind::HeaderCountLimit { count: header.phnum, limit: MAX_PROGRAM_HEADERS }, None));
    }
    if header.phnum == 0 { return Ok(table); }
    let record_size = if header.class_bits == 64 { 56u64 } else { 32u64 };
    if policy == ParsePolicy::Strict {
        let length = u64::from(header.phnum).checked_mul(u64::from(header.phentsize))
            .ok_or_else(|| fail(ErrorKind::TableExtentOverflow, None))?;
        let end = header.phoff.checked_add(length)
            .ok_or_else(|| fail(ErrorKind::TableExtentOverflow, None))?;
        if end > bytes.len() as u64 {
            return Err(fail(ErrorKind::TableOutOfBounds { offset: header.phoff, length, file_length: bytes.len() as u64 }, None));
        }
        return Ok(table);
    }
    let mut file_size_sum = 0u64;
    for index in 0..header.phnum {
        let stride = i64::from(header.phentsize as i16);
        let delta = i64::from(index) * stride;
        let offset = match (header.phoff as i64).checked_add(delta) {
            Some(offset) => offset,
            None => return Err(fail(ErrorKind::RecordOffsetOverflow { index }, table.missing)),
        };
        // Match providerContainsRegion's signed addition, even when declared
        // entry size differs from the actual 32/56-byte constructor read.
        if table.missing.is_none() && !(offset >= 0 && offset.wrapping_add(stride) <= bytes.len() as i64) {
            table.missing = Some(MissingHeaders { first_missing: index, total: header.phnum });
        }
        if offset < 0 {
            return Err(fail(ErrorKind::InvalidRecordOffset { index, offset }, table.missing));
        }
        if offset.checked_add(record_size as i64 - 1).is_none() {
            return Err(fail(ErrorKind::RecordOffsetOverflow { index }, table.missing));
        }
        let offset = offset as u64;
        if offset + record_size > bytes.len() as u64 { table.zero_filled_entries += 1; }
        file_size_sum = file_size_sum.wrapping_add(decode_at(bytes, offset, header.class_bits, header.header_little_endian).file_size);
    }
    table.offsets_rewritten = file_size_sum == bytes.len() as u64;
    Ok(table)
}

#[inline]
fn decode_at(bytes: &[u8], offset: u64, bits: u8, little: bool) -> ProgramHeader {
    let size = if bits == 64 { 56 } else { 32 };
    let mut padded = [0u8; 56];
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
    } else { &padded[..size] };
    if little { decode::<true>(record, bits) } else { decode::<false>(record, bits) }
}

#[inline]
fn decode<const LE: bool>(record: &[u8], bits: u8) -> ProgramHeader {
    let u32_at = |offset| {
        let value = record[offset..offset + 4].try_into().unwrap();
        if LE { u32::from_le_bytes(value) } else { u32::from_be_bytes(value) }
    };
    let u64_at = |offset| {
        let value = record[offset..offset + 8].try_into().unwrap();
        if LE { u64::from_le_bytes(value) } else { u64::from_be_bytes(value) }
    };
    let (flags, offset, virtual_address, physical_address, file_size, memory_size, align) = if bits == 64 {
        (u32_at(4), u64_at(8), u64_at(16), u64_at(24), u64_at(32), u64_at(40), u64_at(48))
    } else {
        (u32_at(24), u64::from(u32_at(4)), u64::from(u32_at(8)), u64::from(u32_at(12)),
         u64::from(u32_at(16)), u64::from(u32_at(20)), u64::from(u32_at(28)))
    };
    ProgramHeader { segment_type: u32_at(0), flags, raw_offset: offset, offset,
                    virtual_address, physical_address, file_size, memory_size, align }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(bits: u8, little: bool, count: u16) -> Vec<u8> {
        let size = if bits == 64 { 56 } else { 32 };
        let mut bytes = vec![0u8; 128 + usize::from(count) * size];
        bytes[..7].copy_from_slice(&[0x7f,b'E',b'L',b'F',if bits == 64 { 2 } else { 1 },if little { 1 } else { 2 },1]);
        fn put(bytes: &mut [u8], position: usize, width: usize, value: u64, little: bool) {
            let values = if little { value.to_le_bytes() } else { value.to_be_bytes() };
            bytes[position..position + width].copy_from_slice(if little { &values[..width] } else { &values[8-width..] });
        }
        put(&mut bytes,16,2,2,little); put(&mut bytes,18,2,62,little); put(&mut bytes,20,4,1,little);
        let tail = if bits == 64 { 48 } else { 36 };
        put(&mut bytes,if bits == 64 { 32 } else { 28 },if bits == 64 { 8 } else { 4 },128,little);
        put(&mut bytes,tail+4,2,if bits == 64 { 64 } else { 52 },little);
        put(&mut bytes,tail+6,2,size as u64,little); put(&mut bytes,tail+8,2,u64::from(count),little);
        for index in 0..usize::from(count) {
            let start = 128 + index * size;
            put(&mut bytes,start,4,1,little);
            if bits == 64 {
                for (offset,width,value) in [(4,4,5),(8,8,0x98),(16,8,0x1234),(24,8,0x5678),(32,8,7),(40,8,11),(48,8,4096)] {
                    put(&mut bytes,start+offset,width,value,little);
                }
            } else {
                for (offset,value) in [(4,0x98),(8,0x1234),(12,0x5678),(16,7),(20,11),(24,5),(28,4096)] {
                    put(&mut bytes,start+offset,4,value,little);
                }
            }
        }
        bytes
    }

    #[test]
    fn all_four_layouts_preserve_fields_and_iterator_contract() {
        for bits in [32,64] { for little in [false,true] {
            let bytes = fixture(bits,little,2);
            for policy in [ParsePolicy::Strict,ParsePolicy::GhidraCompatible] {
                let table = parse_program_headers(&bytes,policy).unwrap();
                assert_eq!(table.len(),2); assert!(!table.offsets_rewritten());
                let expected = ProgramHeader { segment_type:1,flags:5,raw_offset:0x98,offset:0x98,
                    virtual_address:0x1234,physical_address:0x5678,file_size:7,memory_size:11,align:4096 };
                assert_eq!(table.get(0),Some(expected)); assert_eq!(table.get(1),Some(expected));
                assert_eq!(table.get(2),None); assert_eq!(table.get(usize::MAX),None);
                let mut iter = table.iter(); assert_eq!(iter.len(),2);
                assert_eq!(iter.next(),Some(expected)); assert_eq!(iter.len(),1);
                assert_eq!(iter.next(),Some(expected)); assert_eq!(iter.next(),None); assert_eq!(iter.next(),None);
            }
        }}
    }

    #[test]
    fn compatibility_padding_is_separate_from_strict_table_bounds() {
        let mut bytes = fixture(64,true,2); bytes.truncate(128+56+5);
        let table = parse_program_headers(&bytes,ParsePolicy::GhidraCompatible).unwrap();
        assert_eq!(table.zero_filled_entries(),1);
        assert_eq!(table.missing(),Some(MissingHeaders{first_missing:1,total:2}));
        assert_eq!(table.get(1).unwrap().segment_type,1);
        assert_eq!(table.get(1).unwrap().offset,0);
        assert!(matches!(parse_program_headers(&bytes,ParsePolicy::Strict).unwrap_err().kind,ErrorKind::TableOutOfBounds{..}));
    }

    #[test]
    fn legacy_offset_rewrite_preserves_raw_values() {
        let mut bytes = fixture(64,true,2);
        let length = bytes.len() as u64;
        bytes[160..168].copy_from_slice(&100u64.to_le_bytes());
        bytes[216..224].copy_from_slice(&(length-100).to_le_bytes());
        let table = parse_program_headers(&bytes,ParsePolicy::GhidraCompatible).unwrap();
        assert!(table.offsets_rewritten());
        assert_eq!(table.iter().map(|p|p.offset).collect::<Vec<_>>(),[0,100]);
        assert_eq!(table.get(1).unwrap().raw_offset,0x98);
        assert_eq!(table.get(1),table.iter().nth(1));
        let strict = parse_program_headers(&bytes,ParsePolicy::Strict).unwrap();
        assert!(!strict.offsets_rewritten()); assert_eq!(strict.get(0).unwrap().offset,0x98);
    }

    #[test]
    fn zero_stride_repeats_the_same_record_without_missing_warning() {
        let mut bytes = fixture(64,true,2); bytes[54..56].fill(0);
        let table = parse_program_headers(&bytes,ParsePolicy::GhidraCompatible).unwrap();
        assert_eq!(table.get(0),table.get(1)); assert_eq!(table.missing(),None);
        assert!(matches!(parse_program_headers(&bytes,ParsePolicy::Strict).unwrap_err().kind,ErrorKind::Header(ParseError::InvalidProgramEntrySize{..})));
    }

    #[test]
    fn negative_stride_uses_signed_java_short_and_reports_failed_index() {
        let mut bytes = fixture(64,true,2); bytes[54..56].copy_from_slice(&0xffffu16.to_le_bytes());
        let table = parse_program_headers(&bytes,ParsePolicy::GhidraCompatible).unwrap();
        assert_eq!(table.len(),2); assert_eq!(table.get(1).unwrap().segment_type,0x100);
        bytes[32..40].copy_from_slice(&0u64.to_le_bytes());
        let error = parse_program_headers(&bytes,ParsePolicy::GhidraCompatible).unwrap_err();
        assert_eq!(error.kind,ErrorKind::InvalidRecordOffset{index:1,offset:-1});
        assert_eq!(error.missing,Some(MissingHeaders{first_missing:1,total:2}));
    }

    #[test]
    fn resource_limit_and_unsigned_offsets_cannot_trigger_unbounded_iteration() {
        let mut bytes = fixture(64,true,0); bytes[56..58].copy_from_slice(&4097u16.to_le_bytes());
        assert_eq!(parse_program_headers(&bytes,ParsePolicy::Strict).unwrap_err().kind,
                   ErrorKind::HeaderCountLimit{count:4097,limit:4096});
        bytes[56..58].copy_from_slice(&1u16.to_le_bytes()); bytes[32..40].copy_from_slice(&u64::MAX.to_le_bytes());
        assert_eq!(parse_program_headers(&bytes,ParsePolicy::Strict).unwrap_err().kind,ErrorKind::TableExtentOverflow);
        assert_eq!(parse_program_headers(&bytes,ParsePolicy::GhidraCompatible).unwrap_err().kind,
                   ErrorKind::InvalidRecordOffset{index:0,offset:-1});
    }
}
