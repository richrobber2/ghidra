//! Bounded, fail-closed x86-64 scalar instruction lifting.
//!
//! This is a new Rust decoder/lifter, not a call into the original decompiler.
//! Instruction decoding is provided by iced-x86. Only the explicitly modeled
//! instruction forms below enter the IR. The reachable CFG is decoded, so data
//! and alignment bytes following a return need not be valid instructions.
//! Overlap between two reachable instruction interpretations is unsupported.

use iced_x86::{Decoder, DecoderOptions, Instruction as Decoded, Mnemonic, OpKind, Register};
use std::collections::{BTreeMap, VecDeque};
use std::fmt;

pub const MAX_FUNCTION_BYTES: usize = 1024 * 1024;
pub const MAX_INSTRUCTIONS: usize = 65_536;

/// The canonical register ordering is RAX, RCX, RDX, RBX, RSP, RBP, RSI,
/// RDI, R8, R9, R10, R11, R12, R13, R14, R15. Widths are in bits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RegView {
    pub family: u8,
    pub width: u8,
    pub high8: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Memory {
    pub base: Option<u8>,
    pub index: Option<u8>,
    pub scale: u8,
    pub disp: i64,
    pub width: u8,
    /// The decoder resolves RIP/EIP-relative displacement to its absolute IP.
    /// EIP-relative addressing is rejected, so this field is RIP-only.
    pub rip_relative_address: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Operand {
    Reg(RegView),
    Imm(u64),
    Mem(Memory),
}

impl Operand {
    pub fn width(&self) -> Option<u8> {
        match self {
            Self::Reg(reg) => Some(reg.width),
            Self::Mem(mem) => Some(mem.width),
            Self::Imm(_) => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BinaryKind {
    Add,
    Adc,
    Sub,
    Sbb,
    And,
    Or,
    Xor,
    Imul,
    Shl,
    Shr,
    Sar,
    Rol,
    Ror,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UnaryKind {
    Inc,
    Dec,
    Neg,
    Not,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Condition {
    Overflow,
    NotOverflow,
    Below,
    AboveOrEqual,
    Equal,
    NotEqual,
    BelowOrEqual,
    Above,
    Sign,
    NotSign,
    Parity,
    NotParity,
    Less,
    GreaterOrEqual,
    LessOrEqual,
    Greater,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Op {
    Move {
        dst: Operand,
        src: Operand,
    },
    MoveZeroExtend {
        dst: RegView,
        src: Operand,
    },
    MoveSignExtend {
        dst: RegView,
        src: Operand,
    },
    Lea {
        dst: RegView,
        address: Memory,
    },
    Binary {
        kind: BinaryKind,
        dst: Operand,
        left: Operand,
        right: Operand,
    },
    Unary {
        kind: UnaryKind,
        dst: Operand,
    },
    Compare {
        left: Operand,
        right: Operand,
        test: bool,
    },
    Jump {
        target: u64,
    },
    Branch {
        condition: Condition,
        target: u64,
    },
    ConditionalMove {
        condition: Condition,
        dst: RegView,
        src: Operand,
    },
    SetCondition {
        condition: Condition,
        dst: Operand,
    },
    Push {
        src: Operand,
    },
    Pop {
        dst: Operand,
    },
    Leave,
    Return,
    Nop,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Instruction {
    pub address: u64,
    pub len: u8,
    pub op: Op,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LiftedFunction {
    pub start: u64,
    /// Exclusive end of the supplied, bounded function extent.
    pub end: u64,
    /// Reachable instructions in ascending address order.
    pub instructions: Vec<Instruction>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LiftError {
    pub address: u64,
    pub reason: String,
}

impl fmt::Display for LiftError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "unsupported function at 0x{:x}: {}",
            self.address, self.reason
        )
    }
}

impl std::error::Error for LiftError {}

fn error(address: u64, reason: impl Into<String>) -> LiftError {
    LiftError {
        address,
        reason: reason.into(),
    }
}

/// Lift only instructions reachable from `start`, checking all direct branch
/// targets against the supplied byte range and complete reachable instruction
/// boundaries. An unreachable alternate interpretation does not constrain the
/// CFG, but overlap between two reachable streams rejects the function.
/// An unsupported instruction rejects the entire function; no instruction is
/// silently discarded or rendered as an invented operation.
pub fn lift_function(bytes: &[u8], start: u64) -> Result<LiftedFunction, LiftError> {
    if bytes.is_empty() || bytes.len() > MAX_FUNCTION_BYTES {
        return Err(error(
            start,
            "empty function or function byte limit exceeded",
        ));
    }
    let end = start
        .checked_add(bytes.len() as u64)
        .ok_or_else(|| error(start, "function address extent overflow"))?;
    let mut work = VecDeque::from([start]);
    let mut owners = vec![None; bytes.len()];
    let mut instructions = BTreeMap::new();
    let mut saw_return = false;
    while let Some(address) = work.pop_front() {
        if address < start || address >= end {
            return Err(error(address, "control flow leaves the bounded function"));
        }
        let offset = (address - start) as usize;
        if let Some(owner) = owners[offset] {
            if owner != address {
                return Err(error(
                    address,
                    "branch target enters the middle of an instruction",
                ));
            }
            continue;
        }
        if instructions.len() >= MAX_INSTRUCTIONS {
            return Err(error(address, "reachable instruction limit exceeded"));
        }
        let mut decoder = Decoder::with_ip(64, &bytes[offset..], address, DecoderOptions::NONE);
        let decoded = decoder.decode();
        if decoded.is_invalid() || decoded.len() == 0 {
            return Err(error(address, "invalid or truncated x86-64 instruction"));
        }
        let next = address
            .checked_add(decoded.len() as u64)
            .ok_or_else(|| error(address, "instruction address overflow"))?;
        if next > end {
            return Err(error(address, "instruction exceeds bounded function"));
        }
        for owner in &mut owners[offset..offset + decoded.len()] {
            if owner.is_some() {
                return Err(error(address, "overlapping instruction streams"));
            }
            *owner = Some(address);
        }
        // Architectural NOP never reads its encoded memory operand. Compilers
        // use ignored segment/address-size prefixes to construct alignment
        // NOPs, so they need no address-size semantics in our IR.
        if decoded.mnemonic() != Mnemonic::Nop
            && has_address_size_prefix(&bytes[offset..offset + decoded.len()])
        {
            return Err(error(
                address,
                "32-bit address-size wrapping is not modeled",
            ));
        }
        let op = lift_instruction(&decoded)?;
        match &op {
            Op::Return => saw_return = true,
            Op::Jump { target } => work.push_back(*target),
            Op::Branch { target, .. } => {
                work.push_back(*target);
                work.push_back(next);
            }
            _ => work.push_back(next),
        }
        instructions.insert(
            address,
            Instruction {
                address,
                len: decoded.len() as u8,
                op,
            },
        );
    }
    if !saw_return {
        return Err(error(start, "reachable CFG has no modeled return"));
    }
    Ok(LiftedFunction {
        start,
        end,
        instructions: instructions.into_values().collect(),
    })
}

fn lift_instruction(ins: &Decoded) -> Result<Op, LiftError> {
    let ip = ins.ip();
    // REP/REPNE and LOCK introduce semantics absent from this scalar IR. Reject
    // even redundant prefixes rather than relying on mnemonic normalization.
    if ins.has_lock_prefix()
        || ins.has_repne_prefix()
        || (ins.has_rep_prefix() && ins.mnemonic() != Mnemonic::Endbr64)
    {
        return Err(error(ip, "LOCK/REP prefixes are outside the scalar model"));
    }
    if ins.segment_prefix() != Register::None && ins.mnemonic() != Mnemonic::Nop {
        return Err(error(
            ip,
            "segment overrides are outside the flat SysV model",
        ));
    }
    use Mnemonic::*;
    let mnemonic = ins.mnemonic();
    match mnemonic {
        Mov => {
            require_count(ins, 2)?;
            let dst = writable_operand(ins, 0)?;
            let src = operand(ins, 1)?;
            require_same_width(ip, &dst, &src)?;
            Ok(Op::Move { dst, src })
        }
        Movzx | Movsx | Movsxd => {
            require_count(ins, 2)?;
            let dst = register_operand(ins, 0)?;
            let src = operand(ins, 1)?;
            let width = src
                .width()
                .ok_or_else(|| error(ip, "extension source is not a register/memory value"))?;
            if width >= dst.width || (mnemonic == Movsxd && (width != 32 || dst.width != 64)) {
                return Err(error(ip, "unsupported non-widening extension form"));
            }
            if mnemonic == Movzx {
                Ok(Op::MoveZeroExtend { dst, src })
            } else {
                Ok(Op::MoveSignExtend { dst, src })
            }
        }
        Lea => {
            require_count(ins, 2)?;
            let dst = register_operand(ins, 0)?;
            if !matches!(dst.width, 16 | 32 | 64) || ins.op_kind(1) != OpKind::Memory {
                return Err(error(ip, "unsupported LEA form"));
            }
            Ok(Op::Lea {
                dst,
                address: memory(ins, dst.width)?,
            })
        }
        Add | Adc | Sub | Sbb | And | Or | Xor | Shl | Sal | Shr | Sar | Rol | Ror => {
            require_count(ins, 2)?;
            let dst = writable_operand(ins, 0)?;
            let right = operand(ins, 1)?;
            if !matches!(mnemonic, Shl | Sal | Shr | Sar | Rol | Ror) {
                require_same_width(ip, &dst, &right)?;
            }
            let kind = match mnemonic {
                Add => BinaryKind::Add,
                Adc => BinaryKind::Adc,
                Sub => BinaryKind::Sub,
                Sbb => BinaryKind::Sbb,
                And => BinaryKind::And,
                Or => BinaryKind::Or,
                Xor => BinaryKind::Xor,
                Shl | Sal => BinaryKind::Shl,
                Shr => BinaryKind::Shr,
                Sar => BinaryKind::Sar,
                Rol => BinaryKind::Rol,
                Ror => BinaryKind::Ror,
                _ => unreachable!(),
            };
            Ok(Op::Binary {
                kind,
                left: dst.clone(),
                dst,
                right,
            })
        }
        Imul => {
            if !matches!(ins.op_count(), 2 | 3) {
                return Err(error(ip, "implicit double-width IMUL is not modeled"));
            }
            let dst = Operand::Reg(register_operand(ins, 0)?);
            let left = if ins.op_count() == 3 {
                operand(ins, 1)?
            } else {
                dst.clone()
            };
            let right = operand(ins, ins.op_count() - 1)?;
            require_same_width(ip, &dst, &left)?;
            require_same_width(ip, &dst, &right)?;
            Ok(Op::Binary {
                kind: BinaryKind::Imul,
                dst,
                left,
                right,
            })
        }
        Inc | Dec | Neg | Not => {
            require_count(ins, 1)?;
            let kind = match mnemonic {
                Inc => UnaryKind::Inc,
                Dec => UnaryKind::Dec,
                Neg => UnaryKind::Neg,
                Not => UnaryKind::Not,
                _ => unreachable!(),
            };
            Ok(Op::Unary {
                kind,
                dst: writable_operand(ins, 0)?,
            })
        }
        Cmp | Test => {
            require_count(ins, 2)?;
            let left = operand(ins, 0)?;
            let right = operand(ins, 1)?;
            require_same_width(ip, &left, &right)?;
            Ok(Op::Compare {
                left,
                right,
                test: mnemonic == Test,
            })
        }
        Jmp => {
            require_count(ins, 1)?;
            Ok(Op::Jump {
                target: branch_target(ins)?,
            })
        }
        Jo | Jno | Jb | Jae | Je | Jne | Jbe | Ja | Js | Jns | Jp | Jnp | Jl | Jge | Jle | Jg => {
            require_count(ins, 1)?;
            Ok(Op::Branch {
                condition: condition(mnemonic).unwrap(),
                target: branch_target(ins)?,
            })
        }
        Cmovo | Cmovno | Cmovb | Cmovae | Cmove | Cmovne | Cmovbe | Cmova | Cmovs | Cmovns
        | Cmovp | Cmovnp | Cmovl | Cmovge | Cmovle | Cmovg => {
            require_count(ins, 2)?;
            let dst = register_operand(ins, 0)?;
            let src = operand(ins, 1)?;
            require_same_width(ip, &Operand::Reg(dst), &src)?;
            Ok(Op::ConditionalMove {
                condition: condition(mnemonic).unwrap(),
                dst,
                src,
            })
        }
        Seto | Setno | Setb | Setae | Sete | Setne | Setbe | Seta | Sets | Setns | Setp | Setnp
        | Setl | Setge | Setle | Setg => {
            require_count(ins, 1)?;
            let dst = writable_operand(ins, 0)?;
            if dst.width() != Some(8) {
                return Err(error(ip, "SETcc destination is not eight bits"));
            }
            Ok(Op::SetCondition {
                condition: condition(mnemonic).unwrap(),
                dst,
            })
        }
        Push => {
            require_count(ins, 1)?;
            if !matches!(
                ins.code(),
                iced_x86::Code::Push_r64
                    | iced_x86::Code::Push_rm64
                    | iced_x86::Code::Pushq_imm8
                    | iced_x86::Code::Pushq_imm32
            ) {
                return Err(error(ip, "only 64-bit stack pushes are modeled"));
            }
            let src = operand(ins, 0)?;
            if src.width().is_some_and(|width| width != 64) {
                return Err(error(ip, "only 64-bit stack pushes are modeled"));
            }
            Ok(Op::Push { src })
        }
        Pop => {
            require_count(ins, 1)?;
            let dst = writable_operand(ins, 0)?;
            if dst.width() != Some(64) || matches!(&dst, Operand::Reg(reg) if reg.family == 4) {
                return Err(error(ip, "only non-RSP 64-bit stack pops are modeled"));
            }
            // POP r/m calculates memory addresses after incrementing RSP;
            // rejecting memory destinations keeps that subtle form explicit.
            if !matches!(dst, Operand::Reg(_)) {
                return Err(error(ip, "POP memory destinations are not modeled"));
            }
            Ok(Op::Pop { dst })
        }
        Leave => {
            require_count(ins, 0)?;
            // iced exposes the operand size through the actual code name.
            if ins.code() != iced_x86::Code::Leaveq {
                return Err(error(ip, "only 64-bit LEAVE is modeled"));
            }
            Ok(Op::Leave)
        }
        Ret => {
            require_count(ins, 0)?;
            if ins.code() != iced_x86::Code::Retnq {
                return Err(error(ip, "only plain 64-bit near RET is modeled"));
            }
            Ok(Op::Return)
        }
        Nop | Endbr64 => Ok(Op::Nop),
        Cbw | Cwde | Cdqe => {
            require_count(ins, 0)?;
            let (width, source_width) = match mnemonic {
                Cbw => (16, 8),
                Cwde => (32, 16),
                Cdqe => (64, 32),
                _ => unreachable!(),
            };
            Ok(Op::MoveSignExtend {
                dst: RegView {
                    family: 0,
                    width,
                    high8: false,
                },
                src: Operand::Reg(RegView {
                    family: 0,
                    width: source_width,
                    high8: false,
                }),
            })
        }
        _ => Err(error(ip, format!("unmodeled instruction {mnemonic:?}"))),
    }
}

fn has_address_size_prefix(bytes: &[u8]) -> bool {
    for byte in bytes {
        match byte {
            0x67 => return true,
            0x26 | 0x2e | 0x36 | 0x3e | 0x64 | 0x65 | 0x66 | 0xf0 | 0xf2 | 0xf3 | 0x40..=0x4f => {}
            _ => break,
        }
    }
    false
}

fn require_count(ins: &Decoded, count: u32) -> Result<(), LiftError> {
    if ins.op_count() == count {
        Ok(())
    } else {
        Err(error(ins.ip(), "unsupported operand count"))
    }
}

fn require_same_width(ip: u64, left: &Operand, right: &Operand) -> Result<(), LiftError> {
    if left.width().is_some() && right.width().is_some() && left.width() != right.width() {
        return Err(error(ip, "operand widths differ"));
    }
    Ok(())
}

fn branch_target(ins: &Decoded) -> Result<u64, LiftError> {
    if ins.op_kind(0) != OpKind::NearBranch64 {
        return Err(error(
            ins.ip(),
            "indirect or non-64-bit branch is not modeled",
        ));
    }
    Ok(ins.near_branch64())
}

fn register_operand(ins: &Decoded, index: u32) -> Result<RegView, LiftError> {
    if ins.op_kind(index) != OpKind::Register {
        return Err(error(ins.ip(), "expected general-purpose register operand"));
    }
    register(ins.op_register(index))
        .ok_or_else(|| error(ins.ip(), "non-integer register is not modeled"))
}

fn writable_operand(ins: &Decoded, index: u32) -> Result<Operand, LiftError> {
    let value = operand(ins, index)?;
    if matches!(value, Operand::Imm(_)) {
        return Err(error(ins.ip(), "immediate destination is invalid"));
    }
    Ok(value)
}

fn operand(ins: &Decoded, index: u32) -> Result<Operand, LiftError> {
    let value = match ins.op_kind(index) {
        OpKind::Register => Operand::Reg(register_operand(ins, index)?),
        OpKind::Memory => {
            let size = ins.memory_size().size();
            if !matches!(size, 1 | 2 | 4 | 8) {
                return Err(error(ins.ip(), "non-scalar or unsupported memory width"));
            }
            Operand::Mem(memory(ins, (size * 8) as u8)?)
        }
        OpKind::Immediate8 => Operand::Imm(ins.immediate8() as u64),
        OpKind::Immediate16 => Operand::Imm(ins.immediate16() as u64),
        OpKind::Immediate32 => Operand::Imm(ins.immediate32() as u64),
        OpKind::Immediate64 => Operand::Imm(ins.immediate64()),
        OpKind::Immediate8to16 => Operand::Imm(ins.immediate8to16() as u16 as u64),
        OpKind::Immediate8to32 => Operand::Imm(ins.immediate8to32() as u32 as u64),
        OpKind::Immediate8to64 => Operand::Imm(ins.immediate8to64() as u64),
        OpKind::Immediate32to64 => Operand::Imm(ins.immediate32to64() as u64),
        _ => return Err(error(ins.ip(), "unmodeled operand encoding")),
    };
    Ok(value)
}

fn memory(ins: &Decoded, width: u8) -> Result<Memory, LiftError> {
    let ip = ins.ip();
    let base_reg = ins.memory_base();
    let index_reg = ins.memory_index();
    let rip_relative_address = if base_reg == Register::RIP {
        Some(ins.ip_rel_memory_address())
    } else {
        None
    };
    let base = if matches!(base_reg, Register::None | Register::RIP) {
        None
    } else {
        let reg = register(base_reg).ok_or_else(|| error(ip, "unmodeled memory base register"))?;
        if reg.width != 64 {
            return Err(error(ip, "32-bit address-size wrapping is not modeled"));
        }
        Some(reg.family)
    };
    let index = if index_reg == Register::None {
        None
    } else {
        let reg =
            register(index_reg).ok_or_else(|| error(ip, "unmodeled memory index register"))?;
        if reg.width != 64 {
            return Err(error(ip, "32-bit address-size wrapping is not modeled"));
        }
        Some(reg.family)
    };
    // The raw-prefix check also rejects absolute disp32 addressing under a
    // 32-bit address-size override, which has no base/index register to expose
    // the narrower address size here.
    if base_reg == Register::EIP {
        return Err(error(ip, "32-bit address-size wrapping is not modeled"));
    }
    Ok(Memory {
        base,
        index,
        scale: ins.memory_index_scale() as u8,
        disp: ins.memory_displacement64() as i64,
        width,
        rip_relative_address,
    })
}

fn register(reg: Register) -> Option<RegView> {
    use Register::*;
    let (family, width, high8) = match reg {
        AL => (0, 8, false),
        CL => (1, 8, false),
        DL => (2, 8, false),
        BL => (3, 8, false),
        AH => (0, 8, true),
        CH => (1, 8, true),
        DH => (2, 8, true),
        BH => (3, 8, true),
        SPL => (4, 8, false),
        BPL => (5, 8, false),
        SIL => (6, 8, false),
        DIL => (7, 8, false),
        R8L => (8, 8, false),
        R9L => (9, 8, false),
        R10L => (10, 8, false),
        R11L => (11, 8, false),
        R12L => (12, 8, false),
        R13L => (13, 8, false),
        R14L => (14, 8, false),
        R15L => (15, 8, false),
        AX => (0, 16, false),
        CX => (1, 16, false),
        DX => (2, 16, false),
        BX => (3, 16, false),
        SP => (4, 16, false),
        BP => (5, 16, false),
        SI => (6, 16, false),
        DI => (7, 16, false),
        R8W => (8, 16, false),
        R9W => (9, 16, false),
        R10W => (10, 16, false),
        R11W => (11, 16, false),
        R12W => (12, 16, false),
        R13W => (13, 16, false),
        R14W => (14, 16, false),
        R15W => (15, 16, false),
        EAX => (0, 32, false),
        ECX => (1, 32, false),
        EDX => (2, 32, false),
        EBX => (3, 32, false),
        ESP => (4, 32, false),
        EBP => (5, 32, false),
        ESI => (6, 32, false),
        EDI => (7, 32, false),
        R8D => (8, 32, false),
        R9D => (9, 32, false),
        R10D => (10, 32, false),
        R11D => (11, 32, false),
        R12D => (12, 32, false),
        R13D => (13, 32, false),
        R14D => (14, 32, false),
        R15D => (15, 32, false),
        RAX => (0, 64, false),
        RCX => (1, 64, false),
        RDX => (2, 64, false),
        RBX => (3, 64, false),
        RSP => (4, 64, false),
        RBP => (5, 64, false),
        RSI => (6, 64, false),
        RDI => (7, 64, false),
        R8 => (8, 64, false),
        R9 => (9, 64, false),
        R10 => (10, 64, false),
        R11 => (11, 64, false),
        R12 => (12, 64, false),
        R13 => (13, 64, false),
        R14 => (14, 64, false),
        R15 => (15, 64, false),
        _ => return Option::None,
    };
    Some(RegView {
        family,
        width,
        high8,
    })
}

fn condition(mnemonic: Mnemonic) -> Option<Condition> {
    use Mnemonic::*;
    Some(match mnemonic {
        Jo | Cmovo | Seto => Condition::Overflow,
        Jno | Cmovno | Setno => Condition::NotOverflow,
        Jb | Cmovb | Setb => Condition::Below,
        Jae | Cmovae | Setae => Condition::AboveOrEqual,
        Je | Cmove | Sete => Condition::Equal,
        Jne | Cmovne | Setne => Condition::NotEqual,
        Jbe | Cmovbe | Setbe => Condition::BelowOrEqual,
        Ja | Cmova | Seta => Condition::Above,
        Js | Cmovs | Sets => Condition::Sign,
        Jns | Cmovns | Setns => Condition::NotSign,
        Jp | Cmovp | Setp => Condition::Parity,
        Jnp | Cmovnp | Setnp => Condition::NotParity,
        Jl | Cmovl | Setl => Condition::Less,
        Jge | Cmovge | Setge => Condition::GreaterOrEqual,
        Jle | Cmovle | Setle => Condition::LessOrEqual,
        Jg | Cmovg | Setg => Condition::Greater,
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lifts_integer_leaf_and_ignores_unreachable_tail_data() {
        let lifted = lift_function(&[0x48, 0x8d, 0x04, 0x37, 0xc3, 0x0f], 0x1000).unwrap();
        assert_eq!(lifted.instructions.len(), 2);
        assert!(matches!(
            lifted.instructions[0].op,
            Op::Lea {
                dst: RegView {
                    family: 0,
                    width: 64,
                    ..
                },
                ..
            }
        ));
        assert_eq!(lifted.instructions[1].op, Op::Return);
    }

    #[test]
    fn partial_registers_and_sign_extended_immediates_are_explicit() {
        let lifted = lift_function(&[0xb4, 0x7f, 0x48, 0x83, 0xc0, 0xff, 0xc3], 0x1000).unwrap();
        assert!(matches!(
            lifted.instructions[0].op,
            Op::Move {
                dst: Operand::Reg(RegView {
                    family: 0,
                    width: 8,
                    high8: true
                }),
                src: Operand::Imm(0x7f)
            }
        ));
        assert!(matches!(
            lifted.instructions[1].op,
            Op::Binary {
                right: Operand::Imm(u64::MAX),
                ..
            }
        ));
    }

    #[test]
    fn rejects_overlapping_and_outside_control_flow() {
        // JZ enters the immediate byte of a reachable MOV EAX,imm32.
        assert!(lift_function(&[0x74, 0x01, 0xb8, 0, 0, 0, 0, 0xc3], 0x1000).is_err());
        assert!(lift_function(&[0x74, 0x01, 0x48, 0x89, 0xf8, 0xc3], 0x1000).is_err());
        assert!(lift_function(&[0xeb, 0x7f, 0xc3], 0x1000).is_err());
        assert!(lift_function(&[0x90], 0x1000).is_err());
    }

    #[test]
    fn accepts_unreachable_prefix_before_a_valid_branch_target() {
        // Only MOV EAX,EDI is reachable. The skipped REX byte must not invent
        // a second, unreachable instruction stream that blocks this target.
        let lifted = lift_function(&[0xeb, 0x01, 0x48, 0x89, 0xf8, 0xc3], 0x1000).unwrap();
        assert!(matches!(
            lifted.instructions[1].op,
            Op::Move {
                dst: Operand::Reg(RegView {
                    family: 0,
                    width: 32,
                    ..
                }),
                ..
            }
        ));
    }

    #[test]
    fn rejects_calls_simd_indirect_jumps_and_prefix_semantics() {
        for bytes in [
            &[0xe8, 0, 0, 0, 0, 0xc3][..],
            &[0x0f, 0x57, 0xc0, 0xc3][..],
            &[0xff, 0xe0][..],
            &[0xf0, 0x01, 0x07, 0xc3][..],
            &[0x64, 0x48, 0x8b, 0x00, 0xc3][..],
            &[0x67, 0x8b, 0x00, 0xc3][..],
            &[0x67, 0x8b, 0x04, 0x25, 0x78, 0x56, 0x34, 0x12, 0xc3][..],
            &[0x66, 0x6a, 0x01, 0xc3][..],
            &[0xc2, 0x08, 0x00][..],
        ] {
            assert!(lift_function(bytes, 0x1000).is_err(), "{bytes:02x?}");
        }
    }

    #[test]
    fn lifts_back_edges_without_redecoding_forever() {
        let lifted = lift_function(
            &[
                0x31, 0xc0, 0x83, 0xc0, 0x01, 0x83, 0xf8, 0x03, 0x7c, 0xf8, 0xc3,
            ],
            0x1000,
        )
        .unwrap();
        assert_eq!(lifted.instructions.len(), 5);
        assert!(matches!(
            lifted.instructions[3].op,
            Op::Branch {
                condition: Condition::Less,
                target: 0x1002
            }
        ));
    }

    #[test]
    fn alignment_nops_ignore_segment_and_address_size_prefixes() {
        for bytes in [
            // Common GCC 10-byte alignment NOP with operand-size and CS prefixes.
            &[
                0x66, 0x2e, 0x0f, 0x1f, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc3,
            ][..],
            &[0x67, 0x0f, 0x1f, 0x00, 0xc3][..],
            &[0x67, 0x90, 0xc3][..],
        ] {
            let lifted = lift_function(bytes, 0x1000).unwrap();
            assert_eq!(lifted.instructions.len(), 2);
            assert_eq!(lifted.instructions[0].op, Op::Nop);
            assert_eq!(lifted.instructions[1].op, Op::Return);
        }
        // Prefix exceptions apply only to NOP, and never permit LOCK.
        for bytes in [
            &[0x2e, 0x48, 0x8b, 0x00, 0xc3][..],
            &[0x67, 0x8b, 0x00, 0xc3][..],
            &[0xf0, 0x0f, 0x1f, 0x00, 0xc3][..],
        ] {
            assert!(lift_function(bytes, 0x1000).is_err());
        }
    }
}
