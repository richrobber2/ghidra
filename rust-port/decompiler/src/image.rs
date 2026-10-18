// SPDX-License-Identifier: Apache-2.0
//! Static, file-backed read-only image objects. ELF VMAs are identifiers here,
//! never reconstructed host pointers. Writable mappings, BSS, overlapping load
//! mappings, and regions touched by runtime relocations are not image objects.
//!
//! This deliberately does not relocate an ELF or emulate its dynamic linker.
//! Unknown relocation formats/tags fail closed, independently of scalar lifting.

use crate::elf::ElfImage;

pub const MAX_IMAGE_OBJECTS: usize = 128;
pub const MAX_IMAGE_OBJECT_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_EMBEDDED_IMAGE_BYTES: usize = 8 * 1024 * 1024;
pub const MAX_RELOCATION_ENTRIES: u64 = 262_144;
pub const MAX_RELOCATION_OBJECT_WORK: u64 = 16_777_216;
pub const MAX_DYNAMIC_ENTRIES: u64 = 65_536;
/// Explicit minimum-page mapping contract for this x86-64 image-memory slice.
pub const IMAGE_PAGE_BYTES: u64 = 4096;

const PT_DYNAMIC: u32 = 2;
const PF_W: u32 = 2;
const PF_R: u32 = 4;
const SHF_ALLOC: u64 = 2;
const SHT_RELA: u32 = 4;
const SHT_REL: u32 = 9;
const SHT_RELR: u32 = 19;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ImageRegion {
    /// One-based, stable VMA order; zero is reserved for unknown provenance.
    pub id: u32,
    pub address: u64,
    pub bytes: Vec<u8>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ImageLocation {
    pub object: u32,
    pub offset: u64,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ImageModel {
    regions: Vec<ImageRegion>,
}

#[derive(Clone, Copy)]
struct Candidate {
    address: u64,
    end: u64,
    file_offset: usize,
    size: usize,
    excluded: bool,
}

impl ImageModel {
    /// Build once per input image. Failure makes image-memory functionality
    /// unavailable; it need not reject functions using only scalar/stack state.
    pub fn build(image: &ElfImage<'_>) -> Result<Self, String> {
        let mut candidates = Vec::new();
        let loads = image.load_segments();
        for (index, load) in loads.iter().enumerate() {
            if load.flags & PF_R == 0 || load.flags & PF_W != 0 || load.file_size == 0 {
                continue;
            }
            if candidates.len() == MAX_IMAGE_OBJECTS {
                return Err(format!(
                    "read-only object count exceeds {MAX_IMAGE_OBJECTS}"
                ));
            }
            let size = usize::try_from(load.file_size)
                .map_err(|_| "read-only object exceeds host address space")?;
            if size > MAX_IMAGE_OBJECT_BYTES {
                return Err(format!(
                    "read-only object exceeds {MAX_IMAGE_OBJECT_BYTES} bytes"
                ));
            }
            let end = load
                .virtual_address
                .checked_add(load.file_size)
                .ok_or("read-only object extent overflows")?;
            let (page_start, page_end) = page_extent(load.virtual_address, load.memory_size)?;
            let mut excluded =
                load.virtual_address % IMAGE_PAGE_BYTES != load.raw_offset % IMAGE_PAGE_BYTES;
            for (other_index, other) in loads.iter().enumerate() {
                if index == other_index || other.memory_size == 0 {
                    continue;
                }
                let (other_start, other_end) =
                    page_extent(other.virtual_address, other.memory_size)?;
                if intersects(page_start, page_end, other_start, other_end) {
                    excluded = true;
                }
            }
            candidates.push(Candidate {
                address: load.virtual_address,
                end,
                file_offset: usize::try_from(load.raw_offset)
                    .map_err(|_| "read-only file offset exceeds host address space")?,
                size,
                excluded,
            });
        }

        // Canonical entries are mandatory even for nonallocated relocation
        // sections. Only allocated tables can describe runtime writes.
        let mut relocation_count = 0u64;
        for (index, section) in image.sections().iter().enumerate() {
            if matches!(
                section.section_type,
                SHT_RELR | 0x6000_0001 | 0x6000_0002 | 0x6fff_ff00
            ) {
                return Err(format!(
                    "relocation section {index} uses unsupported packed/RELR encoding"
                ));
            }
            let stride = match section.section_type {
                SHT_RELA => 24,
                SHT_REL => 16,
                _ => continue,
            };
            if section.entry_size != stride || section.size % stride != 0 {
                return Err(format!(
                    "relocation section {index} requires complete {stride}-byte entries"
                ));
            }
            relocation_count = relocation_count
                .checked_add(section.size / stride)
                .ok_or("relocation count overflows")?;
            if relocation_count > MAX_RELOCATION_ENTRIES {
                return Err(format!("relocation count exceeds {MAX_RELOCATION_ENTRIES}"));
            }
        }
        if relocation_count
            .checked_mul(candidates.len() as u64)
            .ok_or("relocation/object work overflows")?
            > MAX_RELOCATION_OBJECT_WORK
        {
            return Err(format!(
                "relocation/object work exceeds {MAX_RELOCATION_OBJECT_WORK}"
            ));
        }

        validate_dynamic(image, &mut candidates)?;
        for section in image.sections() {
            if !matches!(section.section_type, SHT_REL | SHT_RELA) || section.flags & SHF_ALLOC == 0
            {
                continue;
            }
            let entries = file_slice(
                image.file_bytes(),
                section.offset,
                section.size,
                "relocation section",
            )?;
            for raw in entries.chunks_exact(section.entry_size as usize) {
                let address = u64_at(raw, 0);
                let kind = u64_at(raw, 8) as u32;
                let width = relocation_width(kind)?;
                if width != 0 {
                    block_span(&mut candidates, address, width, "relocation write")?;
                }
            }
        }

        candidates.sort_by_key(|candidate| candidate.address);
        let mut total = 0usize;
        let mut regions = Vec::new();
        for candidate in candidates
            .into_iter()
            .filter(|candidate| !candidate.excluded)
        {
            total = total
                .checked_add(candidate.size)
                .ok_or("embedded image size overflows")?;
            if total > MAX_EMBEDDED_IMAGE_BYTES {
                return Err(format!(
                    "embedded read-only image exceeds {MAX_EMBEDDED_IMAGE_BYTES} bytes"
                ));
            }
            let bytes = image
                .file_bytes()
                .get(candidate.file_offset..)
                .and_then(|tail| tail.get(..candidate.size))
                .ok_or("read-only object is outside file")?
                .to_vec();
            regions.push(ImageRegion {
                id: regions.len() as u32 + 1,
                address: candidate.address,
                bytes,
            });
        }
        Ok(Self { regions })
    }

    pub fn regions(&self) -> &[ImageRegion] {
        &self.regions
    }

    pub fn region(&self, object: u32) -> Option<&ImageRegion> {
        let index = usize::try_from(object.checked_sub(1)?).ok()?;
        self.regions.get(index).filter(|region| region.id == object)
    }

    /// Require a nonempty read wholly inside one validated object. One-past
    /// addresses are pointer values only, and cannot be read.
    pub fn locate(&self, address: u64, width: u64) -> Result<ImageLocation, String> {
        if width == 0 {
            return Err("an image read requires nonzero width".into());
        }
        let end = address
            .checked_add(width)
            .ok_or("image read extent overflows")?;
        let region = self
            .regions
            .iter()
            .find(|region| {
                address >= region.address && end <= region.address + region.bytes.len() as u64
            })
            .ok_or("image read is outside validated read-only file-backed objects")?;
        Ok(ImageLocation {
            object: region.id,
            offset: address - region.address,
        })
    }

    /// Resolve an address-producing operation, allowing a one-past object
    /// pointer only if it is not simultaneously another object's start.
    pub fn locate_pointer(&self, address: u64) -> Result<ImageLocation, String> {
        let mut selected = None;
        for region in &self.regions {
            if address >= region.address && address <= region.address + region.bytes.len() as u64 {
                if selected.is_some() {
                    return Err(
                        "image pointer has ambiguous object provenance at a boundary".into(),
                    );
                }
                selected = Some(ImageLocation {
                    object: region.id,
                    offset: address - region.address,
                });
            }
        }
        selected.ok_or_else(|| {
            "image pointer is outside validated read-only file-backed objects".into()
        })
    }
}

fn intersects(first: u64, first_end: u64, second: u64, second_end: u64) -> bool {
    first < first_end && second < second_end && first < second_end && second < first_end
}

fn page_extent(address: u64, size: u64) -> Result<(u64, u64), String> {
    let end = address
        .checked_add(size)
        .ok_or("mapped image extent overflows")?;
    let rounded_end = end
        .checked_add(IMAGE_PAGE_BYTES - 1)
        .ok_or("page-rounded image extent overflows")?
        & !(IMAGE_PAGE_BYTES - 1);
    Ok((address & !(IMAGE_PAGE_BYTES - 1), rounded_end))
}

fn block_span(
    candidates: &mut [Candidate],
    address: u64,
    width: u64,
    label: &str,
) -> Result<(), String> {
    let end = address
        .checked_add(width)
        .ok_or_else(|| format!("{label} extent overflows"))?;
    for candidate in candidates {
        if intersects(address, end, candidate.address, candidate.end) {
            candidate.excluded = true;
        }
    }
    Ok(())
}

// System V AMD64 relocation storage widths. COPY depends on a symbol size,
// unknown extensions might write more bytes, and both therefore fail closed.
fn relocation_width(kind: u32) -> Result<u64, String> {
    match kind {
        0 | 35 => Ok(0), // NONE, TLSDESC_CALL marker.
        1 | 6 | 7 | 8 | 16 | 17 | 18 | 24 | 25 | 27 | 28 | 29 | 30 | 31 | 33 | 37 | 38 => Ok(8),
        2 | 3 | 4 | 9 | 10 | 11 | 19 | 20 | 21 | 22 | 23 | 26 | 32 | 34 | 41 | 42 => Ok(4),
        12 | 13 => Ok(2),
        14 | 15 => Ok(1),
        36 => Ok(16), // TLSDESC stores two machine words.
        5 => Err(
            "R_X86_64_COPY relocation requires unsupported symbol-size relocation modeling".into(),
        ),
        _ => Err(format!("unsupported x86-64 relocation kind {kind}")),
    }
}

#[derive(Default)]
struct DynamicRelocations {
    rela: Option<u64>,
    relasz: Option<u64>,
    relaent: Option<u64>,
    rel: Option<u64>,
    relsz: Option<u64>,
    relent: Option<u64>,
    jmprel: Option<u64>,
    pltrelsz: Option<u64>,
    pltrel: Option<u64>,
    relacount: Option<u64>,
    relcount: Option<u64>,
}

fn set_once(slot: &mut Option<u64>, value: u64, name: &str) -> Result<(), String> {
    if slot.replace(value).is_some() {
        return Err(format!("duplicate dynamic {name} tag"));
    }
    Ok(())
}

fn validate_dynamic(image: &ElfImage<'_>, candidates: &mut [Candidate]) -> Result<(), String> {
    let mut dynamic_seen = false;
    for segment in image
        .program_headers()
        .iter()
        .filter(|segment| segment.segment_type == PT_DYNAMIC)
    {
        if dynamic_seen {
            return Err("multiple PT_DYNAMIC segments are unsupported".into());
        }
        dynamic_seen = true;
        if segment.file_size == 0 || segment.file_size % 16 != 0 {
            return Err("PT_DYNAMIC requires complete nonempty 16-byte entries".into());
        }
        if segment.file_size > segment.memory_size {
            return Err("PT_DYNAMIC file size exceeds memory size".into());
        }
        if segment.file_size / 16 > MAX_DYNAMIC_ENTRIES {
            return Err(format!("dynamic entry count exceeds {MAX_DYNAMIC_ENTRIES}"));
        }
        let mapped = map_file_range(image, segment.virtual_address, segment.file_size)?;
        if mapped != segment.raw_offset {
            return Err("PT_DYNAMIC file offset differs from its load mapping".into());
        }
        // DT_DEBUG and other loader bookkeeping can mutate the dynamic table
        // without ordinary relocations. Never export its enclosing RO object.
        block_span(
            candidates,
            segment.virtual_address,
            segment.file_size,
            "dynamic table",
        )?;
        let entries = file_slice(
            image.file_bytes(),
            segment.raw_offset,
            segment.file_size,
            "dynamic table",
        )?;
        let mut dynamic = DynamicRelocations::default();
        let mut terminated = false;
        for raw in entries.chunks_exact(16) {
            let tag = u64_at(raw, 0);
            let value = u64_at(raw, 8);
            match tag {
                0 => {
                    terminated = true;
                    break;
                }
                2 => set_once(&mut dynamic.pltrelsz, value, "DT_PLTRELSZ")?,
                3 => block_span(candidates, value, 24, "loader-reserved GOT slots")?,
                7 => set_once(&mut dynamic.rela, value, "DT_RELA")?,
                8 => set_once(&mut dynamic.relasz, value, "DT_RELASZ")?,
                9 => set_once(&mut dynamic.relaent, value, "DT_RELAENT")?,
                17 => set_once(&mut dynamic.rel, value, "DT_REL")?,
                18 => set_once(&mut dynamic.relsz, value, "DT_RELSZ")?,
                19 => set_once(&mut dynamic.relent, value, "DT_RELENT")?,
                20 => set_once(&mut dynamic.pltrel, value, "DT_PLTREL")?,
                23 => set_once(&mut dynamic.jmprel, value, "DT_JMPREL")?,
                0x6fff_fff9 => set_once(&mut dynamic.relacount, value, "DT_RELACOUNT")?,
                0x6fff_fffa => set_once(&mut dynamic.relcount, value, "DT_RELCOUNT")?,
                22 => return Err("DT_TEXTREL image memory is unsupported".into()),
                30 if value & 4 != 0 => return Err("DF_TEXTREL image memory is unsupported".into()),
                35..=37 | 0x6000_000f..=0x6000_0012 | 0x6fff_e000 | 0x6fff_e001 | 0x6fff_e003 => {
                    return Err("packed/RELR dynamic relocations are unsupported".into());
                }
                // Ordinary ELF and GNU metadata which does not add a new
                // relocation encoding. Everything else fails closed.
                1
                | 4..=6
                | 10..=16
                | 21
                | 24..=30
                | 32..=34
                | 0x6fff_fef5
                | 0x6fff_fff0
                | 0x6fff_fff9..=0x6fff_ffff
                | 0x7fff_fffd
                | 0x7fff_ffff => {}
                _ => {
                    return Err(format!(
                        "unsupported dynamic tag 0x{tag:x} for static image memory"
                    ));
                }
            }
        }
        if !terminated {
            return Err("PT_DYNAMIC lacks a bounded DT_NULL terminator".into());
        }
        if dynamic.relaent.is_some_and(|entry| entry != 24)
            || dynamic.relent.is_some_and(|entry| entry != 16)
        {
            return Err("dynamic relocation entry size is noncanonical".into());
        }
        validate_dynamic_table(image, dynamic.rela, dynamic.relasz, SHT_RELA, "DT_RELA")?;
        validate_dynamic_table(image, dynamic.rel, dynamic.relsz, SHT_REL, "DT_REL")?;
        validate_relative_prefix(
            image,
            dynamic.rela,
            dynamic.relasz,
            24,
            dynamic.relacount,
            "DT_RELACOUNT",
        )?;
        validate_relative_prefix(
            image,
            dynamic.rel,
            dynamic.relsz,
            16,
            dynamic.relcount,
            "DT_RELCOUNT",
        )?;
        if dynamic.jmprel.is_some() || dynamic.pltrelsz.is_some() {
            let kind = match dynamic.pltrel {
                Some(7) => SHT_RELA,
                Some(17) => SHT_REL,
                _ => return Err("DT_JMPREL requires REL/RELA DT_PLTREL".into()),
            };
            validate_dynamic_table(image, dynamic.jmprel, dynamic.pltrelsz, kind, "DT_JMPREL")?;
        } else if dynamic.pltrel.is_some() {
            return Err("DT_PLTREL has no bounded jump relocation table".into());
        }
    }
    Ok(())
}

fn validate_relative_prefix(
    image: &ElfImage<'_>,
    address: Option<u64>,
    size: Option<u64>,
    stride: u64,
    count: Option<u64>,
    name: &str,
) -> Result<(), String> {
    let Some(count) = count else {
        return Ok(());
    };
    if count == 0 {
        return Ok(());
    }
    let (Some(address), Some(size)) = (address, size) else {
        return Err(format!("{name} has no bounded relocation table"));
    };
    if count > size / stride {
        return Err(format!("{name} exceeds its relocation table count"));
    }
    let bytes = count
        .checked_mul(stride)
        .ok_or("relative prefix size overflows")?;
    let offset = map_file_range(image, address, bytes)?;
    let prefix = file_slice(
        image.file_bytes(),
        offset,
        bytes,
        "relative relocation prefix",
    )?;
    // A dynamic linker may optimize this prefix without consulting r_info.
    // Require the explicit type to agree with the runtime RELATIVE operation;
    // NONE markers must not hide writes from the ordinary section scan.
    for raw in prefix.chunks_exact(stride as usize) {
        if u64_at(raw, 8) as u32 != 8 {
            return Err(format!("{name} prefix contains a non-RELATIVE relocation"));
        }
    }
    Ok(())
}

fn validate_dynamic_table(
    image: &ElfImage<'_>,
    address: Option<u64>,
    size: Option<u64>,
    kind: u32,
    name: &str,
) -> Result<(), String> {
    let (address, size) = match (address, size) {
        (None, None) => return Ok(()),
        (Some(address), Some(size)) => (address, size),
        _ => return Err(format!("{name} requires both address and size")),
    };
    let stride = if kind == SHT_RELA { 24 } else { 16 };
    if size % stride != 0 {
        return Err(format!("{name} size is not a whole relocation entry"));
    }
    if size == 0 {
        return Ok(());
    }
    let offset = map_file_range(image, address, size)?;
    let end = address
        .checked_add(size)
        .ok_or("dynamic relocation extent overflows")?;
    let covered = image.sections().iter().any(|section| {
        section.section_type == kind
            && section.flags & SHF_ALLOC != 0
            && section.entry_size == stride
            && address >= section.address
            && end <= section.address + section.size
            && (address - section.address) % stride == 0
            && section.offset.checked_add(address - section.address) == Some(offset)
    });
    if !covered {
        return Err(format!(
            "{name} is not covered by a validated allocated relocation section"
        ));
    }
    Ok(())
}

fn map_file_range(image: &ElfImage<'_>, address: u64, size: u64) -> Result<u64, String> {
    let end = address
        .checked_add(size)
        .ok_or("dynamic address extent overflows")?;
    let mut selected = None;
    for (index, load) in image.load_segments().iter().enumerate() {
        if !intersects(
            address,
            end,
            load.virtual_address,
            load.virtual_address + load.memory_size,
        ) {
            continue;
        }
        if load.virtual_address % IMAGE_PAGE_BYTES != load.raw_offset % IMAGE_PAGE_BYTES {
            return Err(
                "dynamic mapping violates the 4096-byte VMA/file-offset congruence contract".into(),
            );
        }
        if selected.is_some()
            || address < load.virtual_address
            || end > load.virtual_address + load.file_size
        {
            return Err("dynamic range has ambiguous or non-file-backed PT_LOAD mapping".into());
        }
        selected = Some((
            index,
            load.raw_offset
                .checked_add(address - load.virtual_address)
                .ok_or("dynamic file offset overflows")?,
        ));
    }
    let (selected_index, offset) =
        selected.ok_or("dynamic range is not file-backed in a PT_LOAD mapping")?;
    let load = &image.load_segments()[selected_index];
    let (page_start, page_end) = page_extent(load.virtual_address, load.memory_size)?;
    // The loader consumes these bytes, so metadata must have the same unaliased
    // mapping guarantee as exported objects. A later mapping can overwrite an
    // entire shared page even when its declared bytes do not touch this table.
    for (index, other) in image.load_segments().iter().enumerate() {
        if index == selected_index || other.memory_size == 0 {
            continue;
        }
        let (other_start, other_end) = page_extent(other.virtual_address, other.memory_size)?;
        if intersects(page_start, page_end, other_start, other_end) {
            return Err(
                "dynamic metadata load has ambiguous page-overlapping PT_LOAD mappings".into(),
            );
        }
    }
    Ok(offset)
}

fn file_slice<'a>(
    bytes: &'a [u8],
    offset: u64,
    size: u64,
    label: &str,
) -> Result<&'a [u8], String> {
    let end = offset
        .checked_add(size)
        .ok_or_else(|| format!("{label} extent overflows"))?;
    let start = usize::try_from(offset)
        .map_err(|_| format!("{label} offset exceeds host address space"))?;
    let end =
        usize::try_from(end).map_err(|_| format!("{label} end exceeds host address space"))?;
    bytes
        .get(start..end)
        .ok_or_else(|| format!("{label} is outside file"))
}

fn u64_at(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
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

    fn fixture() -> Vec<u8> {
        let mut bytes = vec![0; 2048];
        bytes[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
        put16(&mut bytes, 16, 2);
        put16(&mut bytes, 18, 62);
        put32(&mut bytes, 20, 1);
        put64(&mut bytes, 32, 64);
        put16(&mut bytes, 52, 64);
        put16(&mut bytes, 54, 56);
        put16(&mut bytes, 56, 2);
        load(&mut bytes, 0, 5, 0, 0x400000, 512, 512);
        load(&mut bytes, 1, 4, 512, 0x500200, 256, 512);
        bytes[512..520].copy_from_slice(b"read me\0");
        bytes
    }

    fn load(
        bytes: &mut [u8],
        index: usize,
        flags: u32,
        offset: u64,
        address: u64,
        file_size: u64,
        memory_size: u64,
    ) {
        let base = 64 + index * 56;
        put32(bytes, base, 1);
        put32(bytes, base + 4, flags);
        put64(bytes, base + 8, offset);
        put64(bytes, base + 16, address);
        put64(bytes, base + 32, file_size);
        put64(bytes, base + 40, memory_size);
        put64(bytes, base + 48, 1);
    }

    fn section(
        bytes: &mut [u8],
        index: usize,
        kind: u32,
        flags: u64,
        address: u64,
        offset: u64,
        size: u64,
        entry_size: u64,
    ) {
        let base = 1536 + index * 64;
        put32(bytes, base + 4, kind);
        put64(bytes, base + 8, flags);
        put64(bytes, base + 16, address);
        put64(bytes, base + 24, offset);
        put64(bytes, base + 32, size);
        put64(bytes, base + 56, entry_size);
    }

    fn reloc_fixture(kind: u32, target: u64) -> Vec<u8> {
        let mut bytes = fixture();
        put64(&mut bytes, 40, 1536);
        put16(&mut bytes, 58, 64);
        put16(&mut bytes, 60, 2);
        section(&mut bytes, 1, SHT_RELA, SHF_ALLOC, 0x600400, 1024, 24, 24);
        put64(&mut bytes, 1024, target);
        put64(&mut bytes, 1032, u64::from(kind));
        bytes
    }

    fn dynamic_fixture() -> Vec<u8> {
        let mut bytes = reloc_fixture(8, 0x700000);
        put16(&mut bytes, 56, 4);
        load(&mut bytes, 2, 6, 1024, 0x600400, 256, 256);
        let base = 64 + 3 * 56;
        put32(&mut bytes, base, PT_DYNAMIC);
        put64(&mut bytes, base + 8, 1088);
        put64(&mut bytes, base + 16, 0x600440);
        put64(&mut bytes, base + 32, 64);
        put64(&mut bytes, base + 40, 64);
        put64(&mut bytes, 1088, 7);
        put64(&mut bytes, 1096, 0x600400);
        put64(&mut bytes, 1104, 8);
        put64(&mut bytes, 1112, 24);
        put64(&mut bytes, 1120, 9);
        put64(&mut bytes, 1128, 24);
        bytes
    }

    #[test]
    fn readonly_regions_exclude_bss_and_resolve_bounded_pointers() {
        let bytes = fixture();
        let image = ElfImage::parse(&bytes).unwrap();
        let model = ImageModel::build(&image).unwrap();
        assert_eq!(model.regions().len(), 2);
        assert_eq!(
            model.locate(0x500200, 8).unwrap(),
            ImageLocation {
                object: 2,
                offset: 0
            }
        );
        assert_eq!(&model.region(2).unwrap().bytes[..8], b"read me\0");
        assert!(model.locate(0x500300, 1).is_err());
        assert!(model.locate(0x5002ff, 2).is_err());
        assert!(model.locate(u64::MAX, 2).is_err());
        assert!(model.locate(0x500200, 0).is_err());
        assert_eq!(model.locate_pointer(0x500300).unwrap().offset, 256);
        assert!(model.locate_pointer(0x500301).is_err());
        assert!(model.region(0).is_none());
    }

    #[test]
    fn writable_unreadable_and_ambiguous_regions_are_not_objects() {
        let mut bytes = fixture();
        put32(&mut bytes, 124, 6);
        assert!(
            ImageModel::build(&ElfImage::parse(&bytes).unwrap())
                .unwrap()
                .locate(0x500200, 1)
                .is_err()
        );
        let mut bytes = fixture();
        put32(&mut bytes, 124, 0);
        assert!(
            ImageModel::build(&ElfImage::parse(&bytes).unwrap())
                .unwrap()
                .locate(0x500200, 1)
                .is_err()
        );
        let mut bytes = fixture();
        put16(&mut bytes, 56, 3);
        load(&mut bytes, 2, 6, 1024, 0x5002f0, 16, 32);
        assert!(
            ImageModel::build(&ElfImage::parse(&bytes).unwrap())
                .unwrap()
                .locate(0x500200, 1)
                .is_err()
        );
    }

    #[test]
    fn native_page_aliases_and_incongruent_mappings_are_not_image_objects() {
        for flags in [4, 6] {
            let mut bytes = fixture();
            put16(&mut bytes, 56, 3);
            put64(&mut bytes, 160, 256); // RO logical extent ends at 0x500300.
            load(&mut bytes, 2, flags, 1024, 0x500400, 16, 16);
            let model = ImageModel::build(&ElfImage::parse(&bytes).unwrap()).unwrap();
            assert!(model.locate(0x500200, 1).is_err());
            assert_eq!(model.regions().len(), 1);
        }
        let mut bytes = fixture();
        put64(&mut bytes, 136, 0x500201);
        let model = ImageModel::build(&ElfImage::parse(&bytes).unwrap()).unwrap();
        assert!(model.locate(0x500201, 1).is_err());
    }

    #[test]
    fn adjacent_object_boundary_has_no_invented_provenance() {
        let mut bytes = fixture();
        bytes.resize(8192, 0);
        put64(&mut bytes, 96, 4096);
        put64(&mut bytes, 104, 4096);
        put64(&mut bytes, 128, 4096);
        put64(&mut bytes, 136, 0x401000);
        let model = ImageModel::build(&ElfImage::parse(&bytes).unwrap()).unwrap();
        assert_eq!(model.regions().len(), 2);
        assert!(
            model
                .locate_pointer(0x401000)
                .unwrap_err()
                .contains("ambiguous")
        );
        assert_eq!(model.locate(0x401000, 1).unwrap().object, 2);
    }

    #[test]
    fn relocation_spans_exclude_whole_objects_including_cross_boundary_writes() {
        for target in [0x500200, 0x5001fc] {
            let bytes = reloc_fixture(8, target);
            let model = ImageModel::build(&ElfImage::parse(&bytes).unwrap()).unwrap();
            assert_eq!(model.regions().len(), 1);
            assert!(model.locate_pointer(0x500210).is_err());
        }
        let bytes = reloc_fixture(0, 0x500200);
        assert_eq!(
            ImageModel::build(&ElfImage::parse(&bytes).unwrap())
                .unwrap()
                .regions()
                .len(),
            2
        );
        let bytes = reloc_fixture(36, 0x5001f4); // 16-byte descriptor crosses boundary.
        assert_eq!(
            ImageModel::build(&ElfImage::parse(&bytes).unwrap())
                .unwrap()
                .regions()
                .len(),
            1
        );
    }

    #[test]
    fn unknown_copy_packed_malformed_and_overflowing_relocations_fail_closed() {
        for kind in [5, 0xffff] {
            let bytes = reloc_fixture(kind, 0x700000);
            assert!(ImageModel::build(&ElfImage::parse(&bytes).unwrap()).is_err());
        }
        let mut bytes = reloc_fixture(8, 0x500200);
        put64(&mut bytes, 1536 + 64 + 56, 16);
        assert!(
            ImageModel::build(&ElfImage::parse(&bytes).unwrap())
                .unwrap_err()
                .contains("complete")
        );
        let mut bytes = reloc_fixture(8, 0x500200);
        put32(&mut bytes, 1536 + 64 + 4, SHT_RELR);
        assert!(
            ImageModel::build(&ElfImage::parse(&bytes).unwrap())
                .unwrap_err()
                .contains("RELR")
        );
        let bytes = reloc_fixture(8, u64::MAX - 3);
        assert!(
            ImageModel::build(&ElfImage::parse(&bytes).unwrap())
                .unwrap_err()
                .contains("overflows")
        );
    }

    #[test]
    fn nonallocated_relocations_do_not_describe_runtime_writes() {
        let mut bytes = reloc_fixture(0xffff, 0x500200);
        put64(&mut bytes, 1536 + 64 + 8, 0);
        assert_eq!(
            ImageModel::build(&ElfImage::parse(&bytes).unwrap())
                .unwrap()
                .regions()
                .len(),
            2
        );
    }

    #[test]
    fn dynamic_relocations_require_matching_allocated_file_mapped_sections() {
        let bytes = dynamic_fixture();
        assert_eq!(
            ImageModel::build(&ElfImage::parse(&bytes).unwrap())
                .unwrap()
                .regions()
                .len(),
            2
        );
        let mut bytes = dynamic_fixture();
        put16(&mut bytes, 60, 0);
        put64(&mut bytes, 40, 0);
        put16(&mut bytes, 58, 0);
        assert!(
            ImageModel::build(&ElfImage::parse(&bytes).unwrap())
                .unwrap_err()
                .contains("validated allocated")
        );
        let mut bytes = dynamic_fixture();
        put64(&mut bytes, 1536 + 64 + 24, 1000);
        assert!(
            ImageModel::build(&ElfImage::parse(&bytes).unwrap())
                .unwrap_err()
                .contains("validated allocated")
        );
        let mut bytes = dynamic_fixture();
        put64(&mut bytes, 1536 + 64 + 8, 0);
        assert!(
            ImageModel::build(&ElfImage::parse(&bytes).unwrap())
                .unwrap_err()
                .contains("validated allocated")
        );
    }

    #[test]
    fn aliased_metadata_pages_cannot_hide_different_runtime_relocations() {
        let mut bytes = dynamic_fixture();
        bytes.resize(8192, 0);
        put16(&mut bytes, 56, 5);
        // This later load has no logical overlap with the metadata load, but
        // maps file page 0x1000 over its page at VMA 0x600000. The dynamic and
        // relocation records the loader sees therefore differ from raw bytes.
        load(&mut bytes, 4, 6, 0x1500, 0x600500, 16, 16);
        assert!(
            ImageModel::build(&ElfImage::parse(&bytes).unwrap())
                .unwrap_err()
                .contains("page-overlapping")
        );
    }

    #[test]
    fn dynamic_unknown_relr_textrel_duplicates_and_missing_terminator_reject() {
        for tag in [36, 22, 0x123456, 0x6000000f] {
            let mut bytes = dynamic_fixture();
            put64(&mut bytes, 1088, tag);
            assert!(ImageModel::build(&ElfImage::parse(&bytes).unwrap()).is_err());
        }
        let mut bytes = dynamic_fixture();
        put64(&mut bytes, 1120, 7);
        assert!(
            ImageModel::build(&ElfImage::parse(&bytes).unwrap())
                .unwrap_err()
                .contains("duplicate")
        );
        let mut bytes = dynamic_fixture();
        put64(&mut bytes, 1136, 1);
        assert!(
            ImageModel::build(&ElfImage::parse(&bytes).unwrap())
                .unwrap_err()
                .contains("terminator")
        );
        let mut bytes = dynamic_fixture();
        put64(&mut bytes, 64 + 3 * 56 + 8, 1080);
        assert!(
            ImageModel::build(&ElfImage::parse(&bytes).unwrap())
                .unwrap_err()
                .contains("differs")
        );
    }

    #[test]
    fn optimized_relative_prefix_count_cannot_hide_runtime_writes() {
        for (count_tag, rela) in [(0x6fff_fff9, true), (0x6fff_fffa, false)] {
            let mut bytes = dynamic_fixture();
            if !rela {
                put32(&mut bytes, 1536 + 64 + 4, SHT_REL);
                put64(&mut bytes, 1536 + 64 + 32, 16);
                put64(&mut bytes, 1536 + 64 + 56, 16);
                put64(&mut bytes, 1088, 17);
                put64(&mut bytes, 1104, 18);
                put64(&mut bytes, 1112, 16);
                put64(&mut bytes, 1120, 19);
                put64(&mut bytes, 1128, 16);
            }
            put64(&mut bytes, 64 + 3 * 56 + 32, 80);
            put64(&mut bytes, 64 + 3 * 56 + 40, 80);
            put64(&mut bytes, 1136, count_tag);
            put64(&mut bytes, 1144, 1);
            assert!(ImageModel::build(&ElfImage::parse(&bytes).unwrap()).is_ok());
            put64(&mut bytes, 1144, 2);
            assert!(
                ImageModel::build(&ElfImage::parse(&bytes).unwrap())
                    .unwrap_err()
                    .contains("exceeds")
            );
            put64(&mut bytes, 1144, 1);
            put64(&mut bytes, 1032, 0);
            assert!(
                ImageModel::build(&ElfImage::parse(&bytes).unwrap())
                    .unwrap_err()
                    .contains("non-RELATIVE")
            );
        }
    }

    #[test]
    fn resource_limits_precede_copying_and_entry_iteration() {
        let mut bytes = fixture();
        bytes.resize(MAX_IMAGE_OBJECT_BYTES + 2048, 0);
        put64(&mut bytes, 152, (MAX_IMAGE_OBJECT_BYTES + 1) as u64);
        put64(&mut bytes, 160, (MAX_IMAGE_OBJECT_BYTES + 1) as u64);
        assert!(
            ImageModel::build(&ElfImage::parse(&bytes).unwrap())
                .unwrap_err()
                .contains("read-only object exceeds")
        );
        let mut bytes = reloc_fixture(8, 0x700000);
        let count = MAX_RELOCATION_ENTRIES + 1;
        bytes.resize(4096 + (count as usize) * 24, 0);
        put64(&mut bytes, 1536 + 64 + 24, 4096);
        put64(&mut bytes, 1536 + 64 + 32, count * 24);
        assert!(
            ImageModel::build(&ElfImage::parse(&bytes).unwrap())
                .unwrap_err()
                .contains("relocation count")
        );
    }
}
