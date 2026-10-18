// SPDX-License-Identifier: Apache-2.0
#![forbid(unsafe_code)]

use ghidra_elf::{ParsePolicy, ParsedHeader, parse_header};
use std::fmt::Write;
use std::io::{self, Write as IoWrite};
use std::path::Path;
use std::process::ExitCode;

fn json_string(out: &mut String, text: &str) {
    out.push('"');
    for ch in text.chars() {
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

fn warnings(out: &mut String, bytes: &[u8], compatible: bool) {
    out.push_str(",\"warnings\":[");
    if compatible && bytes.len() >= 34 && bytes[..4] == *b"\x7fELF" && !matches!(bytes[5], 1 | 2) {
        // Java promotes a signed byte before Integer.toHexString.
        let encoding = bytes[5] as i8 as i32 as u32;
        json_string(
            out,
            &format!("Invalid EI_DATA, assuming little-endian headers (EI_DATA=0x{encoding:x})"),
        );
    }
    out.push(']');
}

fn accepted(out: &mut String, h: ParsedHeader) {
    write!(out, ",\"accepted\":true,\"class_bits\":{},\"header_little_endian\":{},\"declared_little_endian\":{},\"type\":{},\"machine\":{},\"version\":{},\"entry_hex\":\"{:x}\",\"phoff_hex\":\"{:x}\",\"shoff_hex\":\"{:x}\",\"flags\":{},\"ehsize\":{},\"phentsize\":{},\"phnum\":{},\"shentsize\":{},\"shnum\":{},\"shstrndx\":{},\"raw_phnum\":{},\"raw_shnum\":{},\"raw_shstrndx\":{},\"diagnostics\":[",
        h.class_bits, h.header_little_endian, h.declared_little_endian, h.elf_type,
        h.machine, h.version, h.entry, h.phoff, h.shoff, h.flags, h.ehsize,
        h.phentsize, h.phnum, h.shentsize, h.shnum, h.shstrndx,
        h.raw_phnum, h.raw_shnum, h.raw_shstrndx).unwrap();
    for (i, diagnostic) in h.diagnostics.iter().enumerate() {
        if i != 0 {
            out.push(',');
        }
        json_string(out, diagnostic.name());
    }
    out.push(']');
}

fn main() -> ExitCode {
    let mut policy = ParsePolicy::Strict;
    let mut paths = Vec::new();
    let mut positional = false;
    for arg in std::env::args_os().skip(1) {
        if !positional && arg == "--" {
            positional = true;
        } else if !positional && arg == "--compatible" {
            policy = ParsePolicy::GhidraCompatible;
        } else if !positional && arg == "--strict" {
            policy = ParsePolicy::Strict;
        } else if !positional && (arg == "--help" || arg == "-h") {
            println!(
                "Usage: ghidra-elf [--strict|--compatible] [--] FILE...\nEmits a JSON array; exits 1 if any input fails. Strict header validation is the default."
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
        eprintln!("Usage: ghidra-elf [--strict|--compatible] [--] FILE...");
        return ExitCode::from(2);
    }
    let mut output = String::from("[");
    let mut failed = false;
    for (i, path) in paths.iter().enumerate() {
        if i != 0 {
            output.push(',');
        }
        output.push_str("\n{\"file\":");
        let path = Path::new(path);
        json_string(
            &mut output,
            &path
                .file_name()
                .unwrap_or(path.as_os_str())
                .to_string_lossy(),
        );
        match std::fs::read(path) {
            Ok(bytes) => {
                warnings(&mut output, &bytes, policy == ParsePolicy::GhidraCompatible);
                match parse_header(&bytes, policy) {
                    Ok(header) => accepted(&mut output, header),
                    Err(error) => {
                        failed = true;
                        output.push_str(",\"accepted\":false,\"error_type\":");
                        json_string(&mut output, error.kind());
                        output.push_str(",\"error\":");
                        json_string(&mut output, &error.to_string());
                    }
                }
            }
            Err(error) => {
                failed = true;
                output.push_str(
                    ",\"warnings\":[],\"accepted\":false,\"error_type\":\"IoError\",\"error\":",
                );
                json_string(&mut output, &error.to_string());
            }
        }
        output.push('}');
    }
    output.push_str("\n]\n");
    if let Err(error) = io::stdout().lock().write_all(output.as_bytes()) {
        eprintln!("could not write results: {error}");
        return ExitCode::from(1);
    }
    ExitCode::from(u8::from(failed))
}
