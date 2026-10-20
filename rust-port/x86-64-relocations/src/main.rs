// SPDX-License-Identifier: Apache-2.0
#![forbid(unsafe_code)]

use ghidra_elf_x86_64_relocations::model::{Options, Outcome, apply_file};
use std::fmt::Write;
use std::io::{Read, Write as IoWrite};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

const MAX_INPUT_BYTES: u64 = 64 * 1024 * 1024;
const USAGE: &str = "usage: ghidra-elf-x86-64-relocations [--digest] [--adjust HEX] \
[--unresolved-externals] FILE... | [--digest] --manifest FILE";

fn json_string(out: &mut String, value: &str) {
    out.push('"');
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            ch if ch < '\u{20}' => write!(out, "\\u{:04x}", ch as u32).unwrap(),
            ch => out.push(ch),
        }
    }
    out.push('"');
}

/// FNV-1a over each line's UTF-8 bytes followed by a newline.
fn fnv1a(lines: &[String]) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325u64;
    for line in lines {
        for &byte in line.as_bytes().iter().chain(b"\n") {
            hash = (hash ^ u64::from(byte)).wrapping_mul(0x0000_0100_0000_01b3);
        }
    }
    hash
}

fn lines(out: &mut String, key: &str, values: &[String], digest: bool) {
    write!(out, ",\"{key}\":").unwrap();
    if digest {
        write!(
            out,
            "{{\"count\":{},\"fnv1a\":\"{:x}\"}}",
            values.len(),
            fnv1a(values)
        )
        .unwrap();
        return;
    }
    out.push('[');
    for (index, value) in values.iter().enumerate() {
        if index > 0 {
            out.push(',');
        }
        json_string(out, value);
    }
    out.push(']');
}

fn outcome(out: &mut String, value: &Outcome, digest: bool) {
    out.push_str(",\"accepted\":true,\"relocation_count\":");
    write!(out, "{}", value.relocations.len()).unwrap();
    out.push_str(",\"status_counts\":{");
    for (index, (name, count)) in value.status_counts.iter().enumerate() {
        if index > 0 {
            out.push(',');
        }
        write!(out, "\"{name}\":{count}").unwrap();
    }
    out.push_str("},\"type_counts\":{");
    for (index, (type_id, count)) in value.type_counts.iter().enumerate() {
        if index > 0 {
            out.push(',');
        }
        write!(out, "\"{type_id}\":{count}").unwrap();
    }
    out.push('}');
    lines(out, "relocations", &value.relocations, digest);
    lines(out, "writes", &value.writes, digest);
    lines(out, "log", &value.log, digest);
    lines(out, "loader_log", &value.loader_log, digest);
    lines(out, "bookmarks", &value.bookmarks, digest);
    lines(out, "console", &value.console, digest);
    lines(out, "stdout", &value.stdout, digest);
    lines(out, "artificial", &value.artificial, digest);
    lines(out, "created_symbols", &value.created_symbols, digest);
    out.push_str(",\"got_allocation\":");
    json_string(out, &value.got_allocation);
    lines(out, "got_entries", &value.got_entries, digest);
    out.push_str(",\"aborted\":");
    match &value.aborted {
        Some(text) => json_string(out, text),
        None => out.push_str("null"),
    }
}

fn read_input(path: &Path) -> Result<Vec<u8>, String> {
    let file = std::fs::File::open(path).map_err(|e| e.to_string())?;
    let metadata = file.metadata().map_err(|e| e.to_string())?;
    if !metadata.is_file() {
        return Err("not a regular file".to_owned());
    }
    if metadata.len() > MAX_INPUT_BYTES {
        return Err(format!("larger than {MAX_INPUT_BYTES} bytes"));
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(MAX_INPUT_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    Ok(bytes)
}

fn parse_hex(text: &str) -> Option<u64> {
    let text = text.strip_prefix("0x").unwrap_or(text);
    u64::from_str_radix(text, 16).ok()
}

/// Manifest lines: `path<TAB>adjust-hex<TAB>0|1` (unresolved externals).
fn read_manifest(path: &Path) -> Result<Vec<(PathBuf, Options)>, String> {
    let text = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
    let mut cases = Vec::new();
    for line in text.lines().filter(|line| !line.is_empty()) {
        let fields: Vec<&str> = line.split('\t').collect();
        let [file, adjust, unresolved] = fields[..] else {
            return Err(format!("bad manifest line: {line}"));
        };
        let adjust = parse_hex(adjust).ok_or_else(|| format!("bad adjust: {adjust}"))?;
        cases.push((
            PathBuf::from(file),
            Options {
                adjust,
                unresolved_externals: unresolved == "1",
            },
        ));
    }
    Ok(cases)
}

fn main() -> ExitCode {
    let mut digest = false;
    let mut options = Options {
        adjust: 0x10_0000,
        unresolved_externals: false,
    };
    let mut cases = Vec::new();
    let mut paths = Vec::new();
    let mut args = std::env::args_os().skip(1);
    let mut literal = false;
    while let Some(arg) = args.next() {
        let text = arg.to_string_lossy().into_owned();
        if literal || !text.starts_with("--") {
            paths.push(PathBuf::from(arg));
            continue;
        }
        match text.as_str() {
            "--" => literal = true,
            "--digest" => digest = true,
            "--unresolved-externals" => options.unresolved_externals = true,
            "--adjust" => match args.next().and_then(|v| parse_hex(&v.to_string_lossy())) {
                Some(value) => options.adjust = value,
                None => {
                    eprintln!("{USAGE}");
                    return ExitCode::from(2);
                }
            },
            "--manifest" => {
                let Some(file) = args.next() else {
                    eprintln!("{USAGE}");
                    return ExitCode::from(2);
                };
                match read_manifest(Path::new(&file)) {
                    Ok(found) => cases.extend(found),
                    Err(error) => {
                        eprintln!("{error}");
                        return ExitCode::from(2);
                    }
                }
            }
            _ => {
                eprintln!("{USAGE}");
                return ExitCode::from(2);
            }
        }
    }
    cases.extend(paths.into_iter().map(|path| (path, options)));
    if cases.is_empty() {
        eprintln!("{USAGE}");
        return ExitCode::from(2);
    }
    let mut failed = false;
    let stdout = std::io::stdout();
    let mut handle = stdout.lock();
    let _ = handle.write_all(b"[\n");
    for (index, (path, options)) in cases.iter().enumerate() {
        let mut out = String::from("{\"file\":");
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        json_string(&mut out, &name);
        match read_input(path).map(|bytes| apply_file(&bytes, options)) {
            Ok(Ok(value)) => outcome(&mut out, &value, digest),
            Ok(Err(rejection)) => {
                failed = true;
                out.push_str(",\"accepted\":false,\"error\":");
                json_string(&mut out, rejection.code());
                out.push_str(",\"detail\":");
                json_string(&mut out, &format!("{rejection:?}"));
            }
            Err(error) => {
                failed = true;
                out.push_str(",\"accepted\":false,\"error\":\"io\",\"detail\":");
                json_string(&mut out, &error);
            }
        }
        out.push('}');
        if index + 1 < cases.len() {
            out.push(',');
        }
        out.push('\n');
        if handle.write_all(out.as_bytes()).is_err() {
            return ExitCode::from(1);
        }
    }
    let _ = handle.write_all(b"]\n");
    let _ = handle.flush();
    ExitCode::from(u8::from(failed))
}
