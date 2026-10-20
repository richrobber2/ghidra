// SPDX-License-Identifier: Apache-2.0
//! Explicit, guarded low-level GNU C output from the normalized scalar IR.
use crate::lift::{BinaryKind, Condition, LiftedFunction, Memory, Op, Operand, RegView, UnaryKind};
use crate::{image::ImageModel, provenance};
use std::fmt::Write;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReturnKind {
    U8,
    U16,
    U32,
    U64,
    Pointer,
}
impl ReturnKind {
    pub fn name(self) -> &'static str {
        match self {
            Self::U8 => "u8",
            Self::U16 => "u16",
            Self::U32 => "u32",
            Self::U64 => "u64",
            Self::Pointer => "pointer",
        }
    }
    pub fn parse(value: &str) -> Result<Self, String> {
        match value {
            "u8" => Ok(Self::U8),
            "u16" => Ok(Self::U16),
            "u32" => Ok(Self::U32),
            "u64" => Ok(Self::U64),
            "pointer" => Ok(Self::Pointer),
            _ => Err("--return requires u8, u16, u32, u64 or pointer".into()),
        }
    }
    /// SysV defines only the low bits of RAX for a narrow integer result, so
    /// only those bits must be known; the C result is their zero extension.
    fn integer_width(self) -> Option<u8> {
        match self {
            Self::U8 => Some(8),
            Self::U16 => Some(16),
            Self::U32 => Some(32),
            Self::U64 => Some(64),
            Self::Pointer => None,
        }
    }
}
#[derive(Debug, Clone)]
pub struct EmbeddedImage {
    pub id: u32,
    pub address: u64,
    pub size: usize,
}
#[derive(Debug, Clone)]
pub struct Emitted {
    /// The generated source: a complete C file, or one Rust function and its
    /// image statics (see [`rust_file_prefix`]).
    pub c: String,
    pub function_name: String,
    pub instruction_count: usize,
    pub image_objects: Vec<EmbeddedImage>,
}

const IMAGE_SETUP: &str = "/* IMAGE_SETUP */";

/// The generated source language. Both run the same guarded machine model:
/// C through `runtime.h`, Rust through `runtime.rs`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Language {
    C,
    Rust,
}

fn reg(r: RegView) -> String {
    format!("rg_reg(&s,{},{},{})", r.family, r.width, u8::from(r.high8))
}
struct Context<'a> {
    image: Result<&'a ImageModel, &'a str>,
    used: Vec<u32>,
    language: Language,
}
impl Context<'_> {
    fn constant(&self, v: u64) -> String {
        match self.language {
            Language::C => format!("UINT64_C(0x{v:x})"),
            Language::Rust => format!("0x{v:x}u64"),
        }
    }
    fn address(
        &mut self,
        m: &Memory,
        access: bool,
        store: bool,
        state: &[u8; 16],
    ) -> Result<String, String> {
        if let Some(address) = m.rip_relative_address {
            if store {
                return Err(
                    "RIP-relative image stores are unsupported; read-only objects only".into(),
                );
            }
            let image = self.image.map_err(|e| {
                format!("RIP-relative relocation/global-memory model unavailable: {e}")
            })?;
            let location = if access {
                image.locate(address, u64::from(m.width / 8))
            } else {
                image.locate_pointer(address)
            }
            .map_err(|e| format!("RIP-relative relocation/global-memory: {e}"))?;
            let local = if let Some(i) = self.used.iter().position(|id| *id == location.object) {
                i + 1
            } else {
                self.used.push(location.object);
                self.used.len()
            };
            return Ok(format!(
                "rg_image(&s,{local},{})",
                self.constant(location.offset)
            ));
        }
        if access && !provenance::memory_admissible(m, state) {
            return Err(
                "memory requires stack or image provenance; external memory is unsupported".into(),
            );
        }
        Ok(format!(
            "rg_lea(&s,{},{},{},{})",
            m.base.map(i32::from).unwrap_or(-1),
            m.index.map(i32::from).unwrap_or(-1),
            m.scale,
            self.constant(m.disp as u64)
        ))
    }
    fn read(&mut self, o: &Operand, state: &[u8; 16]) -> Result<String, String> {
        Ok(match o {
            Operand::Imm(v) => format!("rg_const({})", self.constant(*v)),
            Operand::Reg(r) => reg(*r),
            Operand::Mem(m) => format!(
                "rg_load(&s,{},{})",
                self.address(m, true, false, state)?,
                m.width
            ),
        })
    }
    fn put(
        &mut self,
        out: &mut String,
        o: &Operand,
        value: &str,
        state: &[u8; 16],
    ) -> Result<(), String> {
        // Rust cannot borrow `s` mutably while the value expression reads it,
        // so the value and address are bound first.
        match (o, self.language) {
            (Operand::Reg(r), Language::C) => writeln!(
                out,
                "  rg_setreg(&s,{},{},{},{value});",
                r.family,
                r.width,
                u8::from(r.high8)
            )
            .unwrap(),
            (Operand::Reg(r), Language::Rust) => writeln!(
                out,
                "  {{ let v={value}; rg_setreg(&mut s,{},{},{},v); }}",
                r.family,
                r.width,
                u8::from(r.high8)
            )
            .unwrap(),
            (Operand::Mem(m), Language::C) => writeln!(
                out,
                "  rg_store(&s,{},{},{value});",
                self.address(m, true, true, state)?,
                m.width
            )
            .unwrap(),
            (Operand::Mem(m), Language::Rust) => writeln!(
                out,
                "  {{ let v={value}; let a={}; rg_store(&mut s,a,{},v); }}",
                self.address(m, true, true, state)?,
                m.width
            )
            .unwrap(),
            (Operand::Imm(_), _) => return Err("IR has an immediate destination".into()),
        }
        Ok(())
    }
}
fn binary(k: BinaryKind) -> &'static str {
    match k {
        BinaryKind::Add => "RG_ADD",
        BinaryKind::Adc => "RG_ADC",
        BinaryKind::Sub => "RG_SUB",
        BinaryKind::Sbb => "RG_SBB",
        BinaryKind::And => "RG_AND",
        BinaryKind::Or => "RG_OR",
        BinaryKind::Xor => "RG_XOR",
        BinaryKind::Imul => "RG_IMUL",
        BinaryKind::Shl => "RG_SHL",
        BinaryKind::Shr => "RG_SHR",
        BinaryKind::Sar => "RG_SAR",
        BinaryKind::Rol => "RG_ROL",
        BinaryKind::Ror => "RG_ROR",
    }
}
fn condition(c: Condition) -> u8 {
    match c {
        Condition::Overflow => 0,
        Condition::NotOverflow => 1,
        Condition::Below => 2,
        Condition::AboveOrEqual => 3,
        Condition::Equal => 4,
        Condition::NotEqual => 5,
        Condition::BelowOrEqual => 6,
        Condition::Above => 7,
        Condition::Sign => 8,
        Condition::NotSign => 9,
        Condition::Parity => 10,
        Condition::NotParity => 11,
        Condition::Less => 12,
        Condition::GreaterOrEqual => 13,
        Condition::LessOrEqual => 14,
        Condition::Greater => 15,
    }
}

/// Append `0xNN,` initializers, 24 per line. Image objects can be most of a
/// large library's read-only data, so this avoids per-byte formatting.
fn push_byte_rows(out: &mut String, bytes: &[u8]) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    out.reserve(bytes.len() * 5 + bytes.len().div_ceil(24));
    let mut row = Vec::with_capacity(24 * 5 + 1);
    for chunk in bytes.chunks(24) {
        row.clear();
        for byte in chunk {
            row.extend_from_slice(&[
                b'0',
                b'x',
                HEX[usize::from(byte >> 4)],
                HEX[usize::from(byte & 15)],
                b',',
            ]);
        }
        row.push(b'\n');
        out.push_str(std::str::from_utf8(&row).unwrap());
    }
}

/// The crate-level header and guard runtime that precede the functions of one
/// generated Rust file.
pub fn rust_file_prefix() -> String {
    format!(
        "// SPDX-License-Identifier: Apache-2.0\n// Generated by rust-ghidra: guarded machine-level Rust, edition 2024.\n// Build as a library, e.g. rustc --edition 2024 -O --crate-type cdylib.\n#![allow(unused, unreachable_code, non_snake_case)]\n\n{}",
        include_str!("runtime.rs")
    )
}

pub fn emit_c(function: &LiftedFunction, name: &str) -> Result<Emitted, String> {
    emit_c_with_image(function, name, Err("no image supplied"), ReturnKind::U64)
}
pub fn emit_c_with_image(
    function: &LiftedFunction,
    name: &str,
    image: Result<&ImageModel, &str>,
    return_kind: ReturnKind,
) -> Result<Emitted, String> {
    emit(function, name, image, return_kind, Language::C)
}
/// One generated Rust function with its image statics, without the runtime;
/// prefix one or more of these with [`rust_file_prefix`] to build a file.
pub fn emit_rust_with_image(
    function: &LiftedFunction,
    name: &str,
    image: Result<&ImageModel, &str>,
    return_kind: ReturnKind,
) -> Result<Emitted, String> {
    emit(function, name, image, return_kind, Language::Rust)
}

fn emit(
    function: &LiftedFunction,
    name: &str,
    image: Result<&ImageModel, &str>,
    return_kind: ReturnKind,
    language: Language,
) -> Result<Emitted, String> {
    let rust = language == Language::Rust;
    let limit = if rust {
        "32 MiB emitted Rust limit exceeded"
    } else {
        "32 MiB emitted C limit exceeded"
    };
    let states = provenance::analyze(function)?;
    let mut ctx = Context {
        image,
        used: Vec::new(),
        language,
    };
    let clean: String = name
        .chars()
        .take(80)
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect();
    let function_name = format!(
        "decompiled_{}_{:x}_{:x}",
        clean,
        function.start,
        function.end - function.start
    );
    let mut out = String::new();
    if rust {
        let result_type = if return_kind == ReturnKind::Pointer {
            "*const u8"
        } else {
            "u64"
        };
        writeln!(out,"\n// Native Rust lifting; six unsigned integer SysV arguments.\n// Match arms preserve the recovered CFG. Runtime guards reject undefined state.\n#[unsafe(no_mangle)]\npub extern \"C\" fn {function_name}(a0: u64, a1: u64, a2: u64, a3: u64, a4: u64, a5: u64) -> {result_type} {{\n  let mut s = RgState::new({IMAGE_SETUP});\n  s.r[4] = RgValue {{ x: RG_ENTRY_SP, k: u64::MAX, p: 1 }};\n  s.r[7]=rg_const(a0); s.r[6]=rg_const(a1); s.r[2]=rg_const(a2);\n  s.r[1]=rg_const(a3); s.r[8]=rg_const(a4); s.r[9]=rg_const(a5);\n  let mut pc: u64 = 0x{:x};\n  loop {{ match pc {{",function.start).unwrap();
    } else {
        let result_type = if return_kind == ReturnKind::Pointer {
            "const unsigned char *"
        } else {
            "uint64_t "
        };
        writeln!(out,"\n/* Native Rust lifting; six unsigned integer SysV arguments.\n * Labels preserve the recovered CFG. Runtime guards reject undefined state. */\n{result_type}{function_name}(uint64_t a0,uint64_t a1,uint64_t a2,uint64_t a3,uint64_t a4,uint64_t a5) {{\n  rg_state s={{0}};\n  s.r[4]=(rg_value){{RG_ENTRY_SP,UINT64_MAX,1}};\n  s.r[7]=rg_const(a0); s.r[6]=rg_const(a1); s.r[2]=rg_const(a2);\n  s.r[1]=rg_const(a3); s.r[8]=rg_const(a4); s.r[9]=rg_const(a5);\n  {IMAGE_SETUP}\n  goto L_{:x};",function.start).unwrap();
    }
    let setup_at = out.find(IMAGE_SETUP).expect("header placeholder");
    // Jumps: C uses labels; Rust assigns the next match arm.
    let jump = |target: u64| {
        if rust {
            format!("pc = 0x{target:x};")
        } else {
            format!("goto L_{target:x};")
        }
    };
    for (ins, state) in function.instructions.iter().zip(&states) {
        if out.len() > 32 * 1024 * 1024 {
            return Err(limit.into());
        }
        if rust {
            writeln!(out, "0x{:x} => {{ // {:?}", ins.address, ins.op).unwrap();
        } else {
            writeln!(out, "L_{:x}: {{ /* {:?} */", ins.address, ins.op).unwrap();
        }
        let next = ins.address + u64::from(ins.len);
        let mut terminal = false;
        match &ins.op {
            Op::Move{dst,src}=>{let value=ctx.read(src,state)?;ctx.put(&mut out,dst,&value,state)?;},
            Op::MoveZeroExtend{dst,src}|Op::MoveSignExtend{dst,src}=>{
                let sign=matches!(&ins.op,Op::MoveSignExtend{..});
                let v=format!("rg_extend({},{},{},{})",ctx.read(src,state)?,src.width().ok_or("extension source width")?,dst.width,u8::from(sign));
                ctx.put(&mut out,&Operand::Reg(*dst),&v,state)?;
            }
            Op::Lea{dst,address:m}=>{let value=ctx.address(m,false,false,state)?;ctx.put(&mut out,&Operand::Reg(*dst),&value,state)?;},
            Op::Binary{kind,dst,left,right}=>{
                let width=dst.width().ok_or("binary destination width")?;
                let zero=left==right && matches!(kind,BinaryKind::Xor|BinaryKind::Sub|BinaryKind::Sbb);
                let a=if zero {"rg_const(0)".into()}else{ctx.read(left,state)?};
                let b=if zero {"rg_const(0)".into()}else{ctx.read(right,state)?};
                // Evaluate all operands before the destination address is computed.
                if rust {
                    writeln!(out,"  let a={a}; let b={b};\n  let value=rg_alu(&mut s,{},a,b,{width});",binary(*kind)).unwrap();
                } else {
                    writeln!(out,"  rg_value value=rg_alu(&s,{},{a},{b},{width});",binary(*kind)).unwrap();
                }
                ctx.put(&mut out,dst,"value",state)?;
            }
            Op::Unary{kind,dst}=>{
                let k=match kind {UnaryKind::Inc=>0,UnaryKind::Dec=>1,UnaryKind::Neg=>2,UnaryKind::Not=>3};
                let operand=ctx.read(dst,state)?;
                let width=dst.width().ok_or("unary width")?;
                if rust {
                    writeln!(out,"  let v={operand};\n  let value=rg_unary(&mut s,{k},v,{width});").unwrap();
                } else {
                    writeln!(out,"  rg_value value=rg_unary(&s,{k},{operand},{width});").unwrap();
                }
                ctx.put(&mut out,dst,"value",state)?;
            }
            Op::Compare{left,right,test}=>{
                let (a,b)=(ctx.read(left,state)?,ctx.read(right,state)?);
                let width=left.width().ok_or("comparison width")?;
                if rust {
                    let call=if *test {"let _=rg_alu(&mut s,RG_AND"}else{"rg_compare(&mut s"};
                    writeln!(out,"  let a={a}; let b={b};\n  {call},a,b,{width});").unwrap();
                } else {
                    let call=if *test {"(void)rg_alu(&s,RG_AND"}else{"rg_compare(&s"};
                    writeln!(out,"  {call},{a},{b},{width});").unwrap();
                }
            }
            Op::Jump{target}=>{writeln!(out,"  {}",jump(*target)).unwrap();terminal=true;}
            Op::Branch{condition:c,target}=>{
                if rust {
                    writeln!(out,"  if rg_condition(&s,{}) {{ {} continue; }}",condition(*c),jump(*target)).unwrap();
                } else {
                    writeln!(out,"  if(rg_condition(&s,{})) {}",condition(*c),jump(*target)).unwrap();
                }
            }
            Op::ConditionalMove{condition:c,dst,src}=>{
                let value=ctx.read(src,state)?;
                if rust {
                    writeln!(out,"  let value={value};\n  if rg_condition(&s,{}) {{",condition(*c)).unwrap();
                } else {
                    writeln!(out,"  rg_value value={value};\n  if(rg_condition(&s,{})) {{",condition(*c)).unwrap();
                }
                ctx.put(&mut out,&Operand::Reg(*dst),"value",state)?;out.push_str("  }");
                if dst.width==32 {out.push_str(" else {\n");ctx.put(&mut out,&Operand::Reg(*dst),&reg(*dst),state)?;out.push_str("  }");}
                out.push('\n');
            }
            Op::SetCondition{condition:c,dst}=>{
                let value=if rust {
                    format!("rg_const(u64::from(rg_condition(&s,{})))",condition(*c))
                } else {
                    format!("rg_const(rg_condition(&s,{}))",condition(*c))
                };
                ctx.put(&mut out,dst,&value,state)?
            }
            Op::Push{src}=>{
                let value=ctx.read(src,state)?;
                if rust {
                    writeln!(out,"  let value={value};\n  s.r[4].x=s.r[4].x.wrapping_sub(8);\n  let a=s.r[4]; rg_store(&mut s,a,64,value);").unwrap();
                } else {
                    writeln!(out,"  rg_value value={value};\n  s.r[4].x-=8;\n  rg_store(&s,s.r[4],64,value);").unwrap();
                }
            }
            Op::Pop{dst}=>{
                out.push_str(if rust {
                    "  let value=rg_load(&s,s.r[4],64);\n  s.r[4].x=s.r[4].x.wrapping_add(8);\n"
                } else {
                    "  rg_value value=rg_load(&s,s.r[4],64);\n  s.r[4].x+=8;\n"
                });
                ctx.put(&mut out,dst,"value",state)?;
            }
            Op::Leave=>out.push_str(if rust {
                "  s.r[4]=s.r[5];\n  let value=rg_load(&s,s.r[4],64);\n  s.r[4].x=s.r[4].x.wrapping_add(8);\n  s.r[5]=value;\n"
            } else {
                "  s.r[4]=s.r[5];\n  rg_value value=rg_load(&s,s.r[4],64);\n  s.r[4].x+=8;\n  s.r[5]=value;\n"
            }),
            Op::Return=>{
                if return_kind==ReturnKind::Pointer && state[0]&provenance::IMAGE==0 {
                    return Err("pointer result requires image provenance; scalar, stack and unknown returns are unsupported".into());
                }
                if return_kind!=ReturnKind::Pointer && state[0]==provenance::IMAGE {
                    return Err("RIP-relative pointer result requires --return pointer; relocation-derived numeric addresses are unsupported".into());
                }
                out.push_str(if rust {
                    "  if s.r[4].p!=1 || rg_need(s.r[4],64)!=RG_ENTRY_SP { rg_fail(); }\n"
                } else {
                    "  if(s.r[4].p!=1 || rg_need(s.r[4],64)!=RG_ENTRY_SP) rg_fail();\n"
                });
                match return_kind.integer_width() {
                    Some(width)=>writeln!(out,"  return rg_num(s.r[0],{width});").unwrap(),
                    None=>out.push_str("  return rg_pointer_result(&s,s.r[0]);\n"),
                }
                terminal=true;
            }
            Op::Nop=>{}
        }
        if !terminal {
            writeln!(out, "  {}", jump(next)).unwrap();
        }
        out.push_str("}\n");
    }
    out.push_str(if rust {
        "_ => rg_fail(),\n  } }\n}\n"
    } else {
        "}\n"
    });
    let mut prefix = if rust {
        String::new()
    } else {
        String::from(include_str!("runtime.h"))
    };
    let static_name = if rust {
        function_name.to_ascii_uppercase()
    } else {
        function_name.clone()
    };
    let mut image_objects = Vec::new();
    let setup = if !ctx.used.is_empty() {
        let model = ctx.image.map_err(str::to_owned)?;
        for (i, id) in ctx.used.iter().enumerate() {
            let region = model.region(*id).ok_or("missing image region")?;
            if region
                .bytes
                .len()
                .checked_mul(5)
                .and_then(|n| prefix.len().checked_add(n))
                .and_then(|n| n.checked_add(out.len()))
                .is_none_or(|n| n > 32 * 1024 * 1024)
            {
                return Err(if rust {
                    "32 MiB emitted Rust limit exceeded by image objects".into()
                } else {
                    "32 MiB emitted C limit exceeded by image objects".into()
                });
            }
            if rust {
                writeln!(
                    prefix,
                    "\nstatic {static_name}_IMAGE_{}: [u8; {}] = [",
                    i + 1,
                    region.bytes.len()
                )
                .unwrap();
                push_byte_rows(&mut prefix, &region.bytes);
                prefix.push_str("];\n");
            } else {
                writeln!(
                    prefix,
                    "\nstatic const unsigned char {function_name}_image_{}[] = {{",
                    i + 1
                )
                .unwrap();
                push_byte_rows(&mut prefix, &region.bytes);
                prefix.push_str("};\n");
            }
            image_objects.push(EmbeddedImage {
                id: i as u32 + 1,
                address: region.address,
                size: region.bytes.len(),
            });
        }
        if rust {
            writeln!(
                prefix,
                "static {static_name}_IMAGES: [&[u8]; {}] = [",
                image_objects.len()
            )
            .unwrap();
            for object in &image_objects {
                writeln!(prefix, "  &{static_name}_IMAGE_{},", object.id).unwrap();
            }
            prefix.push_str("];\n");
            format!("&{static_name}_IMAGES")
        } else {
            writeln!(
                prefix,
                "static const rg_image_object {function_name}_images[] = {{"
            )
            .unwrap();
            for object in &image_objects {
                writeln!(
                    prefix,
                    "  {{{function_name}_image_{},UINT64_C({})}},",
                    object.id, object.size
                )
                .unwrap();
            }
            prefix.push_str("};\n");
            format!(
                "s.images={function_name}_images; s.image_count={};",
                image_objects.len()
            )
        }
    } else if rust {
        "&[]".into()
    } else {
        String::new()
    };
    // The header holds the only placeholder; splice instead of rescanning `out`.
    let (head, body) = out.split_at(setup_at);
    prefix.reserve(out.len() + setup.len());
    prefix.push_str(head);
    prefix.push_str(&setup);
    prefix.push_str(&body[IMAGE_SETUP.len()..]);
    if prefix.len() > 32 * 1024 * 1024 {
        return Err(limit.into());
    }
    Ok(Emitted {
        c: prefix,
        function_name,
        instruction_count: function.instructions.len(),
        image_objects,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lift::lift_function;

    #[test]
    fn byte_rows_match_formatted_initializers() {
        let bytes: Vec<u8> = (0..=255).chain(0..=60).collect();
        for len in [0, 1, 23, 24, 25, 48, bytes.len()] {
            let mut expected = String::new();
            for chunk in bytes[..len].chunks(24) {
                for byte in chunk {
                    write!(expected, "0x{byte:02x},").unwrap();
                }
                expected.push('\n');
            }
            let mut actual = String::new();
            push_byte_rows(&mut actual, &bytes[..len]);
            assert_eq!(actual, expected, "length {len}");
        }
    }

    #[test]
    fn narrow_returns_require_only_their_low_bits() {
        // GCC -O2 bool is_zero(int): test edi,edi; sete al; ret
        let lifted = lift_function(&[0x85, 0xff, 0x0f, 0x94, 0xc0, 0xc3], 0x1000).unwrap();
        for (kind, width) in [
            (ReturnKind::U8, 8),
            (ReturnKind::U16, 16),
            (ReturnKind::U32, 32),
            (ReturnKind::U64, 64),
        ] {
            let c = emit_c_with_image(&lifted, "is_zero", Err("no image"), kind)
                .unwrap()
                .c;
            assert!(
                c.contains(&format!("return rg_num(s.r[0],{width});")),
                "{kind:?}"
            );
        }
        assert!(
            emit_c_with_image(&lifted, "is_zero", Err("no image"), ReturnKind::Pointer).is_err()
        );
    }

    /// The Rust runtime compiles inside this crate too, so its semantics can
    /// be unit-tested directly.
    mod runtime {
        include!("runtime.rs");

        #[test]
        fn alu_flags_match_the_c_runtime_definitions() {
            let mut s = RgState::new(&[]);
            // 0x7f + 1 at 8 bits: signed overflow, no carry, sign set.
            let r = rg_alu(&mut s, RG_ADD, rg_const(0x7f), rg_const(1), 8);
            assert_eq!(r.x, 0x80);
            assert!(rg_condition(&s, 0) && !rg_condition(&s, 2) && rg_condition(&s, 8));
            // 0 - 1 at 32 bits borrows.
            let r = rg_alu(&mut s, RG_SUB, rg_const(0), rg_const(1), 32);
            assert_eq!(r.x, 0xffff_ffff);
            assert!(rg_condition(&s, 2) && !rg_condition(&s, 4));
            let r = rg_alu(
                &mut s,
                RG_ROL,
                rg_const(0x8000_0000_0000_0001),
                rg_const(1),
                64,
            );
            assert_eq!(r.x, 3);
            let r = rg_alu(&mut s, RG_SAR, rg_const(0x80), rg_const(9), 8);
            assert_eq!(r.x, 0xff);
            let v = rg_extend(rg_const(0x80), 8, 64, 1);
            assert_eq!(v.x, 0xffff_ffff_ffff_ff80);
        }

        #[test]
        fn stack_round_trips_keep_provenance() {
            let mut s = RgState::new(&[]);
            let sp = RgValue {
                x: RG_ENTRY_SP - 16,
                k: u64::MAX,
                p: 1,
            };
            rg_store(&mut s, sp, 64, sp);
            let loaded = rg_load(&s, sp, 64);
            assert_eq!((loaded.x, loaded.p), (sp.x, 1));
            rg_store(&mut s, sp, 32, rg_const(0x1234_5678));
            assert_eq!(rg_load(&s, sp, 32).x, 0x1234_5678);
        }
    }

    #[test]
    fn rust_and_c_accept_the_same_functions() {
        let lifted = lift_function(&[0x85, 0xff, 0x0f, 0x94, 0xc0, 0xc3], 0x1000).unwrap();
        let rust = emit_rust_with_image(&lifted, "is_zero", Err("no image"), ReturnKind::U8)
            .unwrap()
            .c;
        assert!(rust.contains("pub extern \"C\" fn decompiled_is_zero_1000_6("));
        assert!(rust.contains("return rg_num(s.r[0],8);"));
        assert!(rust.contains("0x1000 => {"));
        assert!(
            emit_rust_with_image(&lifted, "is_zero", Err("no image"), ReturnKind::Pointer).is_err()
        );
    }

    #[test]
    fn return_kind_names_round_trip() {
        for kind in [
            ReturnKind::U8,
            ReturnKind::U16,
            ReturnKind::U32,
            ReturnKind::U64,
            ReturnKind::Pointer,
        ] {
            assert_eq!(ReturnKind::parse(kind.name()), Ok(kind));
        }
        assert!(ReturnKind::parse("i32").is_err());
    }
}
