// SPDX-License-Identifier: Apache-2.0
#![forbid(unsafe_code)]
use rust_ghidra::{
    elf::{ElfImage, Function, MAX_IMAGE_BYTES},
    emit::{EmbeddedImage, ReturnKind, emit_c_with_image},
    image::ImageModel,
    lift::lift_function,
};
use std::{
    fmt::Write,
    io::Read,
    path::{Path, PathBuf},
    process::ExitCode,
};

fn quote(value: &str) -> String {
    let mut out = String::from("\"");
    for c in value.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c < '\u{20}' => {
                write!(out, "\\u{:04x}", c as u32).unwrap();
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}
fn number(value: &str) -> Result<u64, String> {
    if let Some(hex) = value.strip_prefix("0x") {
        u64::from_str_radix(hex, 16)
    } else {
        value.parse()
    }
    .map_err(|_| format!("invalid integer: {value}"))
}
fn load(path: &Path) -> Result<Vec<u8>, String> {
    if !path.metadata().map_err(|e| e.to_string())?.is_file() {
        return Err("input must be a regular file".into());
    }
    let file = std::fs::File::open(path).map_err(|e| e.to_string())?;
    let mut data = Vec::new();
    file.take(MAX_IMAGE_BYTES as u64 + 1)
        .read_to_end(&mut data)
        .map_err(|e| e.to_string())?;
    if data.len() > MAX_IMAGE_BYTES {
        return Err("128 MiB input limit exceeded".into());
    }
    Ok(data)
}
fn function_json(f: &Function) -> String {
    format!(
        "{{\"name\":{},\"address\":{},\"address_hex\":\"0x{:x}\",\"size\":{},\"file_offset\":{}}}",
        quote(&f.name),
        f.address,
        f.address,
        f.size,
        f.file_offset
    )
}
fn images_json(objects: &[EmbeddedImage]) -> String {
    format!(
        "[{}]",
        objects
            .iter()
            .map(|o| format!(
                "{{\"id\":{},\"address_hex\":\"0x{:x}\",\"size\":{}}}",
                o.id, o.address, o.size
            ))
            .collect::<Vec<_>>()
            .join(",")
    )
}
fn help() {
    println!(
        "rust-ghidra functions INPUT\nrust-ghidra decompile INPUT (--function NAME | --address 0xVMA --size N) [--return u8|u16|u32|u64|pointer] --output NEW\nrust-ghidra analyze INPUT --output NEW [--max-functions 100] [--return u8|u16|u32|u64|pointer]\nStandalone Rust x86-64 little-endian ELF scalar decompiler. No Ghidra/Java runtime.\nOutput is guarded GNU C11 using a six-uint64 SysV input model; unsupported code fails explicitly.\nLimits: 128 MiB input, 4096 program headers, 1 MiB/65536 reachable instructions per function."
    );
}

fn analyze(input: &Path, args: &[std::ffi::OsString]) -> Result<u8, String> {
    let (mut output, mut limit, mut return_option) = (None, 100usize, None);
    let mut index = 0;
    while index < args.len() {
        let key = args[index].to_str().ok_or("option must be UTF-8")?;
        let value = args.get(index + 1).ok_or("option requires a value")?;
        match key {
            "--output" if output.is_none() => output = Some(PathBuf::from(value)),
            "--return" if return_option.is_none() => {
                return_option = Some(ReturnKind::parse(
                    value.to_str().ok_or("return kind must be UTF-8")?,
                )?)
            }
            "--max-functions" => {
                limit = value
                    .to_str()
                    .ok_or("invalid function limit")?
                    .parse()
                    .map_err(|_| "invalid function limit")?;
                if limit == 0 || limit > 1000 {
                    return Err("function limit must be 1..1000".into());
                }
            }
            _ => return Err(format!("unknown or repeated option: {key}")),
        }
        index += 2;
    }
    let return_kind = return_option.unwrap_or(ReturnKind::U64);
    let output = output.ok_or("--output NEW is required")?;
    if let Some(parent) = output.parent().filter(|p| !p.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    std::fs::create_dir(&output).map_err(|e| format!("output must be new: {e}"))?;
    let result = (|| -> Result<(String, String, usize, usize, usize, bool), String> {
        let bytes = load(input)?;
        let elf = ElfImage::parse(&bytes)?;
        let image = ImageModel::build(&elf);
        let mut seen = std::collections::BTreeSet::new();
        let selected: Vec<_> = elf
            .functions()
            .iter()
            .filter(|f| seen.insert((f.address, f.size)))
            .collect();
        let total = selected.len();
        let mut rows = Vec::new();
        let mut c = String::new();
        let (mut accepted, mut attempted) = (0, 0);
        let mut truncated = total > limit;
        for f in selected.iter().take(limit) {
            let result = (|| {
                let code = elf.function_bytes(f)?;
                let ir = lift_function(code, f.address).map_err(|e| e.to_string())?;
                emit_c_with_image(
                    &ir,
                    &f.name,
                    image.as_ref().map_err(|e| e.as_str()),
                    return_kind,
                )
            })();
            attempted += 1;
            match result {
                Ok(emitted) => {
                    if c.len() + emitted.c.len() > 64 * 1024 * 1024 {
                        rows.push(format!("{{\"function\":{},\"status\":\"unsupported\",\"error\":\"64 MiB aggregate C limit\"}}",function_json(f)));
                        truncated = true;
                        break;
                    }
                    c.push_str(&emitted.c);
                    accepted += 1;
                    rows.push(format!("{{\"function\":{},\"status\":\"ok\",\"generated_function\":{},\"instruction_count\":{},\"image_objects\":{}}}",function_json(f),quote(&emitted.function_name),emitted.instruction_count,images_json(&emitted.image_objects)));
                }
                Err(error) => rows.push(format!(
                    "{{\"function\":{},\"status\":\"unsupported\",\"error\":{}}}",
                    function_json(f),
                    quote(&error)
                )),
            }
        }
        Ok((rows.join(",\n"), c, total, attempted, accepted, truncated))
    })();
    let (manifest, exit) = match result {
        Ok((rows, c, total, attempted, accepted, truncated)) => {
            let complete = total > 0 && total == accepted && !truncated;
            let status = if complete { "ok" } else { "partial" };
            let files = if accepted > 0 {
                std::fs::write(output.join("decompiled.c"), c).map_err(|e| e.to_string())?;
                "{\"decompiled_c\":\"decompiled.c\"}"
            } else {
                "{}"
            };
            (
                format!(
                    "{{\"status\":\"{status}\",\"backend\":\"native-rust\",\"input\":{},\"function_count\":{total},\"attempted_count\":{attempted},\"decompiled_count\":{accepted},\"unsupported_count\":{},\"truncated\":{truncated},\"guarded\":true,\"functions\":[{rows}],\"output_files\":{files}}}\n",
                    quote(&input.display().to_string()),
                    attempted - accepted
                ),
                if complete { 0 } else { 1 },
            )
        }
        Err(error) => (
            format!(
                "{{\"status\":\"error\",\"backend\":\"native-rust\",\"error\":{},\"output_files\":{{}}}}\n",
                quote(&error)
            ),
            1,
        ),
    };
    let manifest = manifest.replacen(
        "{",
        &format!("{{\"return_kind\":{},", quote(return_kind.name())),
        1,
    );
    std::fs::write(output.join("manifest.json"), &manifest).map_err(|e| e.to_string())?;
    print!("{manifest}");
    Ok(exit)
}
fn run() -> Result<u8, String> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    if args.len() == 1 && (args[0] == "--help" || args[0] == "-h") {
        help();
        return Ok(0);
    }
    if args.len() < 2 {
        help();
        return Ok(2);
    }
    let command = args[0].to_str().ok_or("command must be UTF-8")?;
    let input = PathBuf::from(&args[1]);
    if command == "analyze" {
        return analyze(&input, &args[2..]);
    }
    if command == "functions" {
        if args.len() != 2 {
            return Err("functions accepts exactly one input".into());
        }
        let bytes = load(&input)?;
        let elf = ElfImage::parse(&bytes)?;
        println!(
            "{{\"status\":\"ok\",\"backend\":\"native-rust\",\"entry_hex\":\"0x{:x}\",\"functions\":[{}]}}",
            elf.entry(),
            elf.functions()
                .iter()
                .map(function_json)
                .collect::<Vec<_>>()
                .join(",")
        );
        return Ok(0);
    }
    if command != "decompile" {
        return Err(format!("unknown command: {command}"));
    }
    let (mut name, mut address, mut size, mut output, mut return_option) =
        (None, None, None, None, None);
    let mut index = 2;
    while index < args.len() {
        let key = args[index].to_str().ok_or("option must be UTF-8")?;
        let value = args
            .get(index + 1)
            .ok_or_else(|| format!("missing value for {key}"))?;
        match key {
            "--function" if name.is_none() => {
                name = Some(
                    value
                        .to_str()
                        .ok_or("function name must be UTF-8")?
                        .to_owned(),
                )
            }
            "--address" if address.is_none() => {
                address = Some(number(value.to_str().ok_or("address must be UTF-8")?)?)
            }
            "--size" if size.is_none() => {
                size = Some(number(value.to_str().ok_or("size must be UTF-8")?)?)
            }
            "--output" if output.is_none() => output = Some(PathBuf::from(value)),
            "--return" if return_option.is_none() => {
                return_option = Some(ReturnKind::parse(
                    value.to_str().ok_or("return kind must be UTF-8")?,
                )?)
            }
            _ => return Err(format!("unknown or repeated option: {key}")),
        }
        index += 2;
    }
    if (name.is_some() && (address.is_some() || size.is_some()))
        || (name.is_none() && (address.is_none() || size.is_none()))
    {
        return Err("choose --function NAME or both --address VMA --size N".into());
    }
    let return_kind = return_option.unwrap_or(ReturnKind::U64);
    let output = output.ok_or("--output NEW is required")?;
    if let Some(parent) = output.parent().filter(|p| !p.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    std::fs::create_dir(&output)
        .map_err(|e| format!("output must be new ({}): {e}", output.display()))?;
    let mut selected = None;
    let result = (|| -> Result<(String, String, usize, String, String), (String, String)> {
        let bytes = load(&input).map_err(|e| ("error".into(), e))?;
        let elf = ElfImage::parse(&bytes).map_err(|e| ("unsupported".into(), e))?;
        let function = if let Some(name) = name {
            let candidates: Vec<_> = elf.functions().iter().filter(|f| f.name == name).collect();
            if candidates.len() != 1 {
                return Err((
                    "unsupported".into(),
                    format!(
                        "expected one function named {name:?}; found {}; use explicit --address and --size for stripped/ambiguous inputs",
                        candidates.len()
                    ),
                ));
            }
            candidates[0].clone()
        } else {
            elf.function_range(address.unwrap(), size.unwrap())
                .map_err(|e| ("unsupported".into(), e))?
        };
        selected = Some(function.clone());
        let function_bytes = elf
            .function_bytes(&function)
            .map_err(|e| ("unsupported".into(), e))?;
        let lifted = lift_function(function_bytes, function.address)
            .map_err(|e| ("unsupported".into(), e.to_string()))?;
        let image = ImageModel::build(&elf);
        let emitted = emit_c_with_image(
            &lifted,
            &function.name,
            image.as_ref().map_err(|e| e.as_str()),
            return_kind,
        )
        .map_err(|e| ("unsupported".into(), e))?;
        let mut ir = String::from("[\n");
        for (i, ins) in lifted.instructions.iter().enumerate() {
            if i != 0 {
                ir.push_str(",\n");
            }
            write!(
                ir,
                "{{\"address_hex\":\"0x{:x}\",\"size\":{},\"op\":{}}}",
                ins.address,
                ins.len,
                quote(&format!("{:?}", ins.op))
            )
            .unwrap();
        }
        ir.push_str("\n]\n");
        Ok((
            emitted.c,
            emitted.function_name,
            emitted.instruction_count,
            ir,
            images_json(&emitted.image_objects),
        ))
    })();
    let function = selected
        .as_ref()
        .map(function_json)
        .unwrap_or("null".into());
    let (manifest, exit) = match result {
        Ok((c, generated, count, ir, images)) => {
            std::fs::write(output.join("decompiled.c"), c).map_err(|e| e.to_string())?;
            std::fs::write(output.join("ir.json"), ir).map_err(|e| e.to_string())?;
            (
                format!(
                    "{{\"status\":\"ok\",\"backend\":\"native-rust\",\"input\":{},\"function\":{function},\"generated_function\":{},\"instruction_count\":{count},\"image_objects\":{images},\"guarded\":true,\"output_files\":{{\"decompiled_c\":\"decompiled.c\",\"ir\":\"ir.json\"}},\"scope\":\"x86-64 scalar leaf, six uint64 SysV arguments; bounded stack and immutable file-backed image objects; unknown state/provenance aborts\"}}\n",
                    quote(&input.display().to_string()),
                    quote(&generated)
                ),
                0,
            )
        }
        Err((status, error)) => (
            format!(
                "{{\"status\":{},\"backend\":\"native-rust\",\"input\":{},\"function\":{function},\"error\":{},\"output_files\":{{}}}}\n",
                quote(&status),
                quote(&input.display().to_string()),
                quote(&error)
            ),
            1,
        ),
    };
    let manifest = manifest.replacen(
        "{",
        &format!("{{\"return_kind\":{},", quote(return_kind.name())),
        1,
    );
    std::fs::write(output.join("manifest.json"), &manifest).map_err(|e| e.to_string())?;
    print!("{manifest}");
    Ok(exit)
}
fn main() -> ExitCode {
    match run() {
        Ok(code) => ExitCode::from(code),
        Err(error) => {
            eprintln!("{error}");
            ExitCode::from(2)
        }
    }
}
