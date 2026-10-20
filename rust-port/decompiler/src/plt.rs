// SPDX-License-Identifier: Apache-2.0
//! PLT stubs of imported functions that terminate the process with SIGABRT.
//!
//! A call or jump to such a stub never returns, and the process aborts, so the
//! generated code may abort in its place. A stub is recognized only by its
//! code: an optional `endbr64`, then `jmp *GOT(%rip)` (with or without a BND
//! prefix), where the GOT slot carries an `R_X86_64_JUMP_SLOT` or
//! `R_X86_64_GLOB_DAT` relocation against an undefined dynamic symbol of one
//! of the names below. This assumes the dynamic linker binds those names to
//! the C library's functions, as it does without symbol interposition.

use crate::elf::ElfImage;
use iced_x86::{Decoder, DecoderOptions, Mnemonic, OpKind, Register};
use std::collections::HashMap;

/// Imports that abort the process: glibc's stack-protector and fortify
/// failure paths, `abort` itself and `assert`'s failure path.
pub const ABORTING_IMPORTS: [&str; 5] = [
    "__stack_chk_fail",
    "__fortify_fail",
    "__chk_fail",
    "abort",
    "__assert_fail",
];

const SHF_ALLOC: u64 = 2;
const SHF_EXECINSTR: u64 = 4;
const SHT_PROGBITS: u32 = 1;
const SHT_STRTAB: u32 = 3;
const SHT_RELA: u32 = 4;
const SHT_DYNSYM: u32 = 11;
const R_X86_64_GLOB_DAT: u32 = 6;
const R_X86_64_JUMP_SLOT: u32 = 7;
/// The longest stub prefix examined: `endbr64` (4) + `bnd jmp *disp32(%rip)` (7).
const STUB_BYTES: usize = 11;

/// GOT slots relocated against an aborting import, by slot address.
#[derive(Debug, Default)]
pub struct AbortingImports {
    slots: HashMap<u64, &'static str>,
}

impl AbortingImports {
    /// Index the allocated RELA sections once per image. Malformed tables
    /// contribute nothing; they never make a stub look like an abort.
    pub fn build(image: &ElfImage<'_>) -> Self {
        let sections = image.sections();
        let bytes = image.file_bytes();
        let slice = |offset: u64, size: u64| {
            let start = usize::try_from(offset).ok()?;
            let end = start.checked_add(usize::try_from(size).ok()?)?;
            bytes.get(start..end)
        };
        let mut slots = HashMap::new();
        for section in sections {
            if section.section_type != SHT_RELA
                || section.flags & SHF_ALLOC == 0
                || section.entry_size != 24
            {
                continue;
            }
            let Some(symbols) = sections.get(section.link as usize) else {
                continue;
            };
            let Some(strings) = sections.get(symbols.link as usize) else {
                continue;
            };
            if symbols.section_type != SHT_DYNSYM
                || symbols.entry_size != 24
                || strings.section_type != SHT_STRTAB
            {
                continue;
            }
            let (Some(records), Some(symbol_bytes), Some(string_bytes)) = (
                slice(section.offset, section.size),
                slice(symbols.offset, symbols.size),
                slice(strings.offset, strings.size),
            ) else {
                continue;
            };
            for record in records.chunks_exact(24) {
                let offset = u64::from_le_bytes(record[0..8].try_into().unwrap());
                let info = u64::from_le_bytes(record[8..16].try_into().unwrap());
                if !matches!(info as u32, R_X86_64_JUMP_SLOT | R_X86_64_GLOB_DAT) {
                    continue;
                }
                let Some(symbol) = usize::try_from(info >> 32)
                    .ok()
                    .filter(|index| *index != 0)
                    .and_then(|index| symbol_bytes.get(index.checked_mul(24)?..)?.get(..24))
                else {
                    continue;
                };
                let name = u32::from_le_bytes(symbol[0..4].try_into().unwrap()) as usize;
                let section_index = u16::from_le_bytes(symbol[6..8].try_into().unwrap());
                let Some(name) = string_bytes
                    .get(name..)
                    .and_then(|tail| tail.split(|byte| *byte == 0).next())
                else {
                    continue;
                };
                if section_index != 0 {
                    continue;
                }
                if let Some(known) = ABORTING_IMPORTS
                    .iter()
                    .find(|known| known.as_bytes() == name)
                {
                    slots.insert(offset, *known);
                }
            }
        }
        Self { slots }
    }

    /// The aborting import whose PLT stub starts at `target`, if any.
    pub fn stub(&self, image: &ElfImage<'_>, target: u64) -> Option<&'static str> {
        if self.slots.is_empty() {
            return None;
        }
        let section = image.sections().iter().find(|section| {
            section.section_type == SHT_PROGBITS
                && section.flags & (SHF_ALLOC | SHF_EXECINSTR) == SHF_ALLOC | SHF_EXECINSTR
                && target >= section.address
                && target - section.address < section.size
        })?;
        let start = usize::try_from(section.offset.checked_add(target - section.address)?).ok()?;
        let available = usize::try_from(section.size - (target - section.address)).ok()?;
        let code = image
            .file_bytes()
            .get(start..start.checked_add(available.min(STUB_BYTES))?)?;
        let mut decoder = Decoder::with_ip(64, code, target, DecoderOptions::NONE);
        let mut instruction = decoder.decode();
        if instruction.mnemonic() == Mnemonic::Endbr64 {
            instruction = decoder.decode();
        }
        if instruction.is_invalid()
            || instruction.mnemonic() != Mnemonic::Jmp
            || instruction.op_count() != 1
            || instruction.op_kind(0) != OpKind::Memory
            || instruction.memory_base() != Register::RIP
            || instruction.memory_size().size() != 8
            || instruction.segment_prefix() != Register::None
        {
            return None;
        }
        self.slots
            .get(&instruction.ip_rel_memory_address())
            .copied()
    }
}
