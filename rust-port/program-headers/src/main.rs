// SPDX-License-Identifier: Apache-2.0
#![forbid(unsafe_code)]

use std::fmt::Write;
use std::io::{Read, Write as IoWrite};
use std::path::Path;
use std::process::ExitCode;
use ghidra_elf_segments::{parse_program_headers, MissingHeaders, ParsePolicy, ProgramHeaders};

const MAX_INPUT_BYTES: u64 = 64 * 1024 * 1024;

fn json_string(out: &mut String, value: &str) {
    out.push('"');
    for ch in value.chars() { match ch {
        '"' => out.push_str("\\\""), '\\' => out.push_str("\\\\"),
        '\n' => out.push_str("\\n"), '\r' => out.push_str("\\r"), '\t' => out.push_str("\\t"),
        ch if ch < '\u{20}' => { write!(out,"\\u{:04x}",ch as u32).unwrap(); },
        ch => out.push(ch),
    }}
    out.push('"');
}

fn warnings(out: &mut String, bytes: &[u8], policy: ParsePolicy, missing: Option<MissingHeaders>) {
    out.push_str(",\"warnings\":[");
    let mut separator = false;
    if policy == ParsePolicy::GhidraCompatible && bytes.len() >= 34 && bytes[..4] == *b"\x7fELF" && !matches!(bytes[5],1|2) {
        let encoding = bytes[5] as i8 as i32 as u32;
        json_string(out,&format!("Invalid EI_DATA, assuming little-endian headers (EI_DATA=0x{encoding:x})"));
        separator = true;
    }
    if let Some(missing) = missing {
        if separator { out.push(','); }
        json_string(out,&missing.to_string());
    }
    out.push(']');
}

fn accepted(out: &mut String, table: &ProgramHeaders<'_>) {
    let h = table.header();
    write!(out,",\"accepted\":true,\"class_bits\":{},\"header_little_endian\":{},\"phnum\":{},\"phentsize\":{},\"offsets_rewritten\":{},\"zero_filled_entries\":{},\"entries\":[",
           h.class_bits,h.header_little_endian,h.phnum,h.phentsize,table.offsets_rewritten(),table.zero_filled_entries()).unwrap();
    for (index,p) in table.iter().enumerate() {
        if index != 0 { out.push(','); }
        write!(out,"{{\"type\":{},\"flags\":{},\"raw_offset_hex\":\"{:x}\",\"offset_hex\":\"{:x}\",\"vaddr_hex\":\"{:x}\",\"paddr_hex\":\"{:x}\",\"filesz_hex\":\"{:x}\",\"memsz_hex\":\"{:x}\",\"align_hex\":\"{:x}\"}}",
               p.segment_type,p.flags,p.raw_offset,p.offset,p.virtual_address,p.physical_address,p.file_size,p.memory_size,p.align).unwrap();
    }
    out.push(']');
}

fn main() -> ExitCode {
    let mut policy = ParsePolicy::Strict;
    let mut positional = false;
    let mut paths = Vec::new();
    for arg in std::env::args_os().skip(1) {
        if !positional && arg == "--" { positional = true; }
        else if !positional && arg == "--compatible" { policy = ParsePolicy::GhidraCompatible; }
        else if !positional && arg == "--strict" { policy = ParsePolicy::Strict; }
        else if !positional && (arg == "--help" || arg == "-h") {
            println!("Usage: ghidra-elf-segments [--strict|--compatible] [--] FILE...\nStrict header/table validation is the default. No segment payload or section-table validation.\nLimits: 4096 program headers and 64 MiB per CLI input. JSON output; exit 1 if any input fails.");
            return ExitCode::SUCCESS;
        } else if !positional && arg.to_string_lossy().starts_with('-') {
            eprintln!("unknown option: {}",arg.to_string_lossy()); return ExitCode::from(2);
        } else { paths.push(arg); }
    }
    if paths.is_empty() {
        eprintln!("Usage: ghidra-elf-segments [--strict|--compatible] [--] FILE..."); return ExitCode::from(2);
    }
    let mut output = String::from("[");
    let mut failed = false;
    for (index,path) in paths.iter().enumerate() {
        if index != 0 { output.push(','); }
        let path = Path::new(path);
        output.push_str("\n{\"file\":");
        json_string(&mut output,&path.file_name().unwrap_or(path.as_os_str()).to_string_lossy());
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
            Ok(bytes) => match parse_program_headers(&bytes,policy) {
                Ok(table) => { warnings(&mut output,&bytes,policy,table.missing()); accepted(&mut output,&table); },
                Err(error) => {
                    failed = true; warnings(&mut output,&bytes,policy,error.missing);
                    output.push_str(",\"accepted\":false,\"error_type\":"); json_string(&mut output,error.kind.name());
                    output.push_str(",\"error\":"); json_string(&mut output,&error.to_string());
                }
            },
            Err(error) => {
                failed = true; output.push_str(",\"accepted\":false,\"warnings\":[],\"error_type\":\"IoError\",\"error\":");
                json_string(&mut output,&error.to_string());
            }
        }
        output.push('}');
    }
    output.push_str("\n]\n");
    if let Err(error) = std::io::stdout().lock().write_all(output.as_bytes()) {
        eprintln!("could not write results: {error}"); return ExitCode::from(1);
    }
    if failed { ExitCode::from(1) } else { ExitCode::SUCCESS }
}
