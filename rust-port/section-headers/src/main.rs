// SPDX-License-Identifier: Apache-2.0
#![forbid(unsafe_code)]

use ghidra_elf_sections::{
    Compression, MissingHeaders, ParsePolicy, SectionHeaders, parse_section_headers,
};
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

fn warnings(out: &mut String, bytes: &[u8], policy: ParsePolicy, missing: Option<MissingHeaders>) {
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
    if let Some(missing) = missing {
        if separator {
            out.push(',');
        }
        json_string(out, &missing.to_string());
    }
    out.push(']');
}

fn accepted(out: &mut String, table: &SectionHeaders<'_>) {
    let h = table.header();
    write!(out,",\"accepted\":true,\"class_bits\":{},\"header_little_endian\":{},\"shnum\":{},\"shentsize\":{},\"shstrndx\":{},\"zero_filled_entries\":{},\"has_extended_symbol_index_table\":{},\"entries\":[",
           h.class_bits,h.header_little_endian,h.shnum,h.shentsize,h.shstrndx,table.zero_filled_entries(),table.has_extended_symbol_index_table()).unwrap();
    for (index, s) in table.iter().enumerate() {
        if index != 0 {
            out.push(',');
        }
        out.push_str("{\"name\":");
        json_string(out, &table.name(index).unwrap());
        write!(out,",\"name_index\":{},\"type\":{},\"flags_hex\":\"{:x}\",\"addr_hex\":\"{:x}\",\"offset_hex\":\"{:x}\",\"size_hex\":\"{:x}\",\"link\":{},\"info\":{},\"addralign_hex\":\"{:x}\",\"entsize_hex\":\"{:x}\",\"compressed\":",
               s.name_index,s.section_type,s.flags,s.address,s.offset,s.size,s.link,s.info,s.address_align,s.entry_size).unwrap();
        match s.compression {
            Compression::Compressed(c) => write!(out,"{{\"type\":{},\"size_hex\":\"{:x}\",\"addralign_hex\":\"{:x}\",\"header_size\":{}}}",
                                                c.compression_type,c.size,c.address_align,c.header_size).unwrap(),
            _ => out.push_str("null"),
        }
        out.push('}');
    }
    out.push(']');
}

fn main() -> ExitCode {
    let mut policy = ParsePolicy::Strict;
    let mut positional = false;
    let mut paths = Vec::new();
    for arg in std::env::args_os().skip(1) {
        if !positional && arg == "--" {
            positional = true;
        } else if !positional && arg == "--compatible" {
            policy = ParsePolicy::GhidraCompatible;
        } else if !positional && arg == "--strict" {
            policy = ParsePolicy::Strict;
        } else if !positional && (arg == "--help" || arg == "-h") {
            println!(
                "Usage: ghidra-elf-sections [--strict|--compatible] [--] FILE...\nStrict header/table/name validation is the default. No section payload validation or decompression.\nLimits: 65536 section headers and 64 MiB per CLI input. JSON output; exit 1 if any input fails."
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
        eprintln!("Usage: ghidra-elf-sections [--strict|--compatible] [--] FILE...");
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
            Ok(bytes) => match parse_section_headers(&bytes, policy) {
                Ok(table) => {
                    warnings(&mut output, &bytes, policy, table.missing());
                    accepted(&mut output, &table);
                }
                Err(error) => {
                    failed = true;
                    warnings(&mut output, &bytes, policy, error.missing);
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
