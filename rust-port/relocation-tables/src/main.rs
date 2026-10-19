// SPDX-License-Identifier: Apache-2.0
#![forbid(unsafe_code)]

use ghidra_elf_relocations::{ElfRelocations, ParsePolicy, parse_relocations};
use std::fmt::Write;
use std::io::{Read, Write as IoWrite};
use std::path::Path;
use std::process::ExitCode;

const MAX_INPUT_BYTES: u64 = 64 * 1024 * 1024;

fn json_string(out: &mut String, value: &str) {
    out.push('"');
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            ch if ch < '\u{20}' => {
                write!(out, "\\u{:04x}", ch as u32).unwrap();
            }
            ch => out.push(ch),
        }
    }
    out.push('"');
}

fn warnings(out: &mut String, bytes: &[u8], policy: ParsePolicy, extra: &[String]) {
    out.push_str(",\"warnings\":[");
    let mut separator = false;
    if policy == ParsePolicy::GhidraCompatible
        && bytes.len() >= 34
        && bytes[..4] == *b"\x7fELF"
        && !matches!(bytes[5], 1 | 2)
    {
        let encoding = bytes[5] as i8 as i32 as u32;
        json_string(
            out,
            &format!("Invalid EI_DATA, assuming little-endian headers (EI_DATA=0x{encoding:x})"),
        );
        separator = true;
    }
    for warning in extra {
        if separator {
            out.push(',');
        }
        json_string(out, warning);
        separator = true;
    }
    out.push(']');
}

fn optional(out: &mut String, value: Option<u32>) {
    match value {
        Some(value) => write!(out, "{value}").unwrap(),
        None => out.push_str("null"),
    }
}

fn fnv(mut hash: u64, value: u64) -> u64 {
    for byte in value.to_le_bytes() {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x0100_0000_01b3);
    }
    hash
}

fn accepted(out: &mut String, parsed: &ElfRelocations<'_>, digest: bool) {
    write!(
        out,
        ",\"accepted\":true,\"phnum\":{},\"shnum\":{},\"symbol_table_count\":{},\"relocation_tables\":[",
        parsed.dynamic.program_headers.len(),
        parsed.dynamic.sections.len(),
        parsed.dynamic.symbol_tables.len()
    )
    .unwrap();
    for (index, t) in parsed.relocation_tables.iter().enumerate() {
        if index != 0 {
            out.push(',');
        }
        out.push_str("{\"section\":");
        optional(out, t.section_index);
        write!(
            out,
            ",\"format\":\"{}\",\"addend\":{},\"offset_hex\":\"{:x}\",\"addr_hex\":\"{:x}\",\"size_hex\":\"{:x}\",\"entsize_hex\":\"{:x}\",\"symbol_table\":",
            t.format.name(),
            t.has_addend,
            t.offset,
            t.address,
            t.size,
            t.entry_size
        )
        .unwrap();
        optional(out, t.symbol_table.map(|value| value as u32));
        out.push_str(",\"relocated_section\":");
        optional(out, t.relocated_section);
        write!(out, ",\"relocation_count\":{}", t.relocations.len()).unwrap();
        if digest {
            let hash = t.relocations.iter().fold(0xcbf2_9ce4_8422_2325, |hash, r| {
                fnv(fnv(fnv(hash, r.offset), r.info), r.addend as u64)
            });
            write!(out, ",\"relocations_fnv1a\":\"{hash:x}\"").unwrap();
        } else {
            out.push_str(",\"relocations\":[");
            for (position, r) in t.relocations.iter().enumerate() {
                if position != 0 {
                    out.push(',');
                }
                write!(out, "\"{:x} {:x} {:x}\"", r.offset, r.info, r.addend as u64).unwrap();
            }
            out.push(']');
        }
        out.push('}');
    }
    out.push(']');
}

fn main() -> ExitCode {
    let mut policy = ParsePolicy::Strict;
    let mut positional = false;
    let mut digest = false;
    let mut paths = Vec::new();
    for arg in std::env::args_os().skip(1) {
        if !positional && arg == "--" {
            positional = true;
        } else if !positional && arg == "--compatible" {
            policy = ParsePolicy::GhidraCompatible;
        } else if !positional && arg == "--digest" {
            digest = true;
        } else if !positional && arg == "--strict" {
            policy = ParsePolicy::Strict;
        } else if !positional && (arg == "--help" || arg == "-h") {
            println!(
                "Usage: ghidra-elf-relocations [--strict|--compatible] [--digest] [--] FILE...\nStrict validation is the default. Relocation tables found through the dynamic table and the section headers; --digest prints an FNV-1a hash of each table instead of its entries.\nLimits: 4096 program headers, 65536 section headers, 65536 dynamic entries, 1000000 symbols per table, 4000000 in total, 1000000 relocations per table, 4000000 in total and 64 MiB per CLI input. JSON output; exit 1 if any input fails."
            );
            return ExitCode::SUCCESS;
        } else if !positional && arg.to_string_lossy().starts_with('-') {
            eprintln!("unknown option: {}", arg.to_string_lossy());
            return ExitCode::from(2);
        } else {
            paths.push(arg);
        }
    }
    if paths.is_empty() {
        eprintln!("Usage: ghidra-elf-relocations [--strict|--compatible] [--digest] [--] FILE...");
        return ExitCode::from(2);
    }
    let mut output = String::from("[");
    let mut failed = false;
    for (index, path) in paths.iter().enumerate() {
        if index != 0 {
            output.push(',');
        }
        let path = Path::new(path);
        output.push_str("\n{\"file\":");
        json_string(
            &mut output,
            &path
                .file_name()
                .unwrap_or(path.as_os_str())
                .to_string_lossy(),
        );
        let data = (|| {
            let file = std::fs::File::open(path)?;
            if !file.metadata()?.is_file() {
                return Err(std::io::Error::other("input must be a regular file"));
            }
            let mut bytes = Vec::new();
            file.take(MAX_INPUT_BYTES + 1).read_to_end(&mut bytes)?;
            if bytes.len() as u64 > MAX_INPUT_BYTES {
                return Err(std::io::Error::other("input exceeds 64 MiB CLI limit"));
            }
            Ok(bytes)
        })();
        match data {
            Ok(bytes) => match parse_relocations(&bytes, policy) {
                Ok(parsed) => {
                    warnings(&mut output, &bytes, policy, &parsed.warnings);
                    accepted(&mut output, &parsed, digest);
                }
                Err(error) => {
                    failed = true;
                    warnings(&mut output, &bytes, policy, &error.warnings);
                    output.push_str(",\"accepted\":false,\"error_type\":");
                    json_string(&mut output, error.kind.name());
                    output.push_str(",\"error\":");
                    json_string(&mut output, &error.to_string());
                }
            },
            Err(error) => {
                failed = true;
                output.push_str(
                    ",\"accepted\":false,\"warnings\":[],\"error_type\":\"IoError\",\"error\":",
                );
                json_string(&mut output, &error.to_string());
            }
        }
        output.push('}');
    }
    output.push_str("\n]\n");
    if let Err(error) = std::io::stdout().lock().write_all(output.as_bytes()) {
        eprintln!("could not write results: {error}");
        return ExitCode::from(1);
    }
    if failed {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    }
}
