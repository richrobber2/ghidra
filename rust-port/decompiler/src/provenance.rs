// SPDX-License-Identifier: Apache-2.0
//! Coarse, bounded register provenance used to admit image-memory operands.
//!
//! These sets describe possible value categories, not known bits or a proof that
//! a memory operation is safe. The emitted runtime still checks provenance,
//! complete values, bounds and permissions on every executed operation. Stack
//! contents are one deliberately coarse union; no alias or slot claim is made.

use crate::lift::{
    BinaryKind, LiftedFunction, MAX_INSTRUCTIONS, Memory, Op, Operand, RegView, UnaryKind,
};
use std::collections::VecDeque;

pub const NUM: u8 = 1;
pub const STACK: u8 = 2;
pub const IMAGE: u8 = 4;
pub const UNKNOWN: u8 = 8;
pub const INVALID: u8 = 16;
pub const POINTER: u8 = STACK | IMAGE;
const KINDS: [u8; 5] = [NUM, STACK, IMAGE, UNKNOWN, INVALID];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct State {
    regs: [u8; 16],
    stack: u8,
}

/// An operand may enter the guarded memory implementation if some incoming path
/// supplies a modeled address. Conventional stack/frame bases retain the former
/// admission rule; scalar input arguments alone never become host pointers.
pub fn memory_admissible(memory: &Memory, regs: &[u8; 16]) -> bool {
    memory.rip_relative_address.is_some()
        || matches!(memory.base, Some(4 | 5))
        || [memory.base, memory.index]
            .into_iter()
            .flatten()
            .any(|r| regs.get(r as usize).is_some_and(|v| v & POINTER != 0))
}

fn narrow(kinds: u8) -> u8 {
    (kinds & (NUM | UNKNOWN | INVALID)) | if kinds & POINTER != 0 { INVALID } else { 0 }
}

fn pairwise(a: u8, b: u8, mut operation: impl FnMut(u8, u8) -> u8) -> u8 {
    let mut result = 0;
    for left in KINDS {
        if a & left == 0 {
            continue;
        }
        for right in KINDS {
            if b & right != 0 {
                result |= operation(left, right);
            }
        }
    }
    result
}

fn add_kind(a: u8, b: u8, subtract: bool) -> u8 {
    if a == INVALID || b == INVALID {
        return INVALID;
    }
    if a == UNKNOWN || b == UNKNOWN {
        // Unknown numeric bits may abort before an address is formed, but do
        // not erase a possible pointer on the other operand.
        let pointer = (a | b) & POINTER;
        return UNKNOWN
            | if subtract && a == UNKNOWN && pointer != 0 {
                INVALID
            } else {
                pointer
            };
    }
    if a == NUM && b == NUM {
        return NUM;
    }
    if a & POINTER != 0 && b == NUM {
        return a;
    }
    if !subtract && a == NUM && b & POINTER != 0 {
        return b;
    }
    if subtract && a == b && a & POINTER != 0 {
        return NUM;
    }
    INVALID
}

fn address_kind(memory: &Memory, state: &State) -> u8 {
    if memory.rip_relative_address.is_some() {
        return IMAGE;
    }
    let a = memory.base.map(|r| state.regs[r as usize]).unwrap_or(NUM);
    let mut b = memory.index.map(|r| state.regs[r as usize]).unwrap_or(NUM);
    if memory.scale != 1 {
        b = narrow(b);
    }
    pairwise(a, b, |a, b| add_kind(a, b, false))
}

fn stack_address(memory: &Memory, state: &State) -> bool {
    memory.rip_relative_address.is_none()
        && (matches!(memory.base, Some(4 | 5)) || address_kind(memory, state) & STACK != 0)
}

fn load(memory: &Memory, state: &State) -> u8 {
    if !stack_address(memory, state) {
        return NUM;
    }
    if memory.width == 64 {
        NUM | UNKNOWN | state.stack
    } else {
        NUM | UNKNOWN
            | if state.stack & (POINTER | INVALID) != 0 {
                INVALID
            } else {
                0
            }
    }
}

fn read(operand: &Operand, state: &State) -> u8 {
    match operand {
        Operand::Imm(_) => NUM,
        Operand::Reg(reg) => {
            let value = state.regs[reg.family as usize];
            if reg.width == 64 {
                value
            } else {
                narrow(value)
            }
        }
        Operand::Mem(memory) => load(memory, state),
    }
}

fn write_reg(state: &mut State, reg: RegView, value: u8) {
    let slot = &mut state.regs[reg.family as usize];
    *slot = match reg.width {
        64 => value,
        32 => narrow(value),
        _ => narrow(*slot) | narrow(value),
    };
}

fn write(state: &mut State, operand: &Operand, value: u8) {
    match operand {
        Operand::Reg(reg) => write_reg(state, *reg, value),
        Operand::Mem(memory) if stack_address(memory, state) => {
            state.stack |= if memory.width == 64 {
                value
            } else {
                narrow(value)
            };
        }
        _ => {}
    }
}

fn transfer(op: &Op, input: State) -> State {
    let mut state = input;
    match op {
        Op::Move { dst, src } => write(&mut state, dst, read(src, &input)),
        Op::MoveZeroExtend { dst, src } | Op::MoveSignExtend { dst, src } => {
            write_reg(&mut state, *dst, narrow(read(src, &input)));
        }
        Op::Lea { dst, address } => write_reg(&mut state, *dst, address_kind(address, &input)),
        Op::Binary {
            kind,
            dst,
            left,
            right,
        } => {
            let a = read(left, &input);
            let b = read(right, &input);
            let result = if left == right
                && matches!(kind, BinaryKind::Xor | BinaryKind::Sub | BinaryKind::Sbb)
            {
                NUM
            } else if matches!(kind, BinaryKind::Add | BinaryKind::Sub) {
                pairwise(a, b, |a, b| add_kind(a, b, *kind == BinaryKind::Sub))
            } else {
                pairwise(a, b, |a, b| {
                    if a == INVALID || b == INVALID || (a | b) & POINTER != 0 {
                        // Stack alignment AND is supported by the runtime for
                        // selected masks; retaining STACK admits its guard.
                        if *kind == BinaryKind::And && a == STACK && b == NUM {
                            STACK | INVALID
                        } else {
                            INVALID
                        }
                    } else if a == UNKNOWN || b == UNKNOWN {
                        UNKNOWN
                    } else {
                        NUM
                    }
                })
            };
            write(&mut state, dst, result);
        }
        Op::Unary { kind, dst } => {
            let value = read(dst, &input);
            let result = if matches!(kind, UnaryKind::Inc | UnaryKind::Dec) {
                value
            } else {
                narrow(value)
            };
            write(&mut state, dst, result);
        }
        Op::ConditionalMove { dst, src, .. } => {
            let old = input.regs[dst.family as usize];
            let new = read(src, &input);
            write_reg(&mut state, *dst, old | new);
        }
        Op::SetCondition { dst, .. } => write(&mut state, dst, NUM),
        Op::Push { src } => state.stack |= read(src, &input),
        Op::Pop { dst } => write(&mut state, dst, NUM | UNKNOWN | input.stack),
        Op::Leave => {
            state.regs[4] = input.regs[5];
            state.regs[5] = NUM | UNKNOWN | input.stack;
        }
        Op::Compare { .. } | Op::Jump { .. } | Op::Branch { .. } | Op::Return | Op::Nop => {}
    }
    state
}

fn valid_reg(reg: RegView) -> bool {
    reg.family < 16 && matches!(reg.width, 8 | 16 | 32 | 64) && (!reg.high8 || reg.width == 8)
}

fn valid_memory(memory: &Memory) -> bool {
    memory.base.is_none_or(|r| r < 16)
        && memory.index.is_none_or(|r| r < 16)
        && matches!(memory.scale, 1 | 2 | 4 | 8)
        && matches!(memory.width, 8 | 16 | 32 | 64)
}

fn valid_operand(operand: &Operand) -> bool {
    match operand {
        Operand::Reg(r) => valid_reg(*r),
        Operand::Mem(m) => valid_memory(m),
        Operand::Imm(_) => true,
    }
}

fn valid_op(op: &Op) -> bool {
    match op {
        Op::Move { dst, src } => valid_operand(dst) && valid_operand(src),
        Op::MoveZeroExtend { dst, src }
        | Op::MoveSignExtend { dst, src }
        | Op::ConditionalMove { dst, src, .. } => valid_reg(*dst) && valid_operand(src),
        Op::Lea { dst, address } => valid_reg(*dst) && valid_memory(address),
        Op::Binary {
            dst, left, right, ..
        } => valid_operand(dst) && valid_operand(left) && valid_operand(right),
        Op::Unary { dst, .. } | Op::SetCondition { dst, .. } | Op::Pop { dst } => {
            valid_operand(dst)
        }
        Op::Compare { left, right, .. } => valid_operand(left) && valid_operand(right),
        Op::Push { src } => valid_operand(src),
        _ => true,
    }
}

/// Return possible register categories immediately before each instruction, in
/// `function.instructions` order. Union joins preserve both arms of conditionals.
/// The fixed point is bounded independently of the instruction decoder. This
/// analysis intentionally does not reject mixed return categories; runtime guards
/// decide the executed path. A return state exactly equal to IMAGE is a useful
/// static indication that a caller must choose the image-pointer output model.
pub fn analyze(function: &LiftedFunction) -> Result<Vec<[u8; 16]>, String> {
    let count = function.instructions.len();
    if count == 0 || count > MAX_INSTRUCTIONS {
        return Err("provenance instruction limit exceeded or empty CFG".into());
    }
    for instruction in &function.instructions {
        if instruction.address < function.start
            || instruction.address >= function.end
            || instruction.len == 0
            || !valid_op(&instruction.op)
        {
            return Err("invalid instruction in provenance CFG".into());
        }
    }
    // Sorted (address, index) pairs; lifted input is already in address order.
    let mut indices: Vec<(u64, usize)> = function
        .instructions
        .iter()
        .enumerate()
        .map(|(index, instruction)| (instruction.address, index))
        .collect();
    indices.sort_unstable();
    if indices.windows(2).any(|pair| pair[0].0 == pair[1].0) {
        return Err("invalid instruction in provenance CFG".into());
    }
    let index_of = |address: u64| {
        indices
            .binary_search_by_key(&address, |entry| entry.0)
            .ok()
            .map(|position| indices[position].1)
    };
    let entry = index_of(function.start).ok_or("provenance CFG has no entry instruction")?;
    // At most two successors each: a branch target and its fall-through.
    let mut successors = vec![([0usize; 2], 0u8); count];
    for (index, instruction) in function.instructions.iter().enumerate() {
        let next = instruction
            .address
            .checked_add(u64::from(instruction.len))
            .ok_or("provenance instruction address overflow")?;
        if next > function.end {
            return Err("provenance instruction exceeds function extent".into());
        }
        let (addresses, used) = match instruction.op {
            Op::Return => ([0, 0], 0),
            Op::Jump { target } => ([target, 0], 1),
            Op::Branch { target, .. } => ([target, next], 2),
            _ => ([next, 0], 1),
        };
        for &address in &addresses[..used] {
            let (slots, len) = &mut successors[index];
            slots[usize::from(*len)] = index_of(address).ok_or_else(|| {
                format!("provenance CFG successor 0x{address:x} has no instruction")
            })?;
            *len += 1;
        }
    }
    let mut initial = State {
        regs: [UNKNOWN; 16],
        stack: UNKNOWN,
    };
    initial.regs[4] = STACK;
    for register in [7, 6, 2, 1, 8, 9] {
        initial.regs[register] = NUM;
    }
    let mut states = vec![None; count];
    states[entry] = Some(initial);
    let mut work = VecDeque::from([entry]);
    let mut queued = vec![false; count];
    queued[entry] = true;
    let mut steps = 0;
    let budget = count * 128;
    while let Some(index) = work.pop_front() {
        queued[index] = false;
        steps += 1;
        if steps > budget {
            return Err("provenance CFG propagation work limit exceeded".into());
        }
        let output = transfer(&function.instructions[index].op, states[index].unwrap());
        let (slots, len) = successors[index];
        for &successor in &slots[..usize::from(len)] {
            let joined = if let Some(previous) = states[successor] {
                let mut joined = previous;
                for (slot, value) in joined.regs.iter_mut().zip(output.regs) {
                    *slot |= value;
                }
                joined.stack |= output.stack;
                joined
            } else {
                output
            };
            if states[successor] != Some(joined) {
                states[successor] = Some(joined);
                if !queued[successor] {
                    work.push_back(successor);
                    queued[successor] = true;
                }
            }
        }
    }
    states
        .into_iter()
        .map(|state| {
            state
                .map(|s| s.regs)
                .ok_or_else(|| "provenance CFG contains unreachable instructions".into())
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lift::{Condition, Instruction};

    fn reg(family: u8) -> RegView {
        RegView {
            family,
            width: 64,
            high8: false,
        }
    }
    fn r(family: u8) -> Operand {
        Operand::Reg(reg(family))
    }
    fn memory(base: Option<u8>, image: bool) -> Memory {
        Memory {
            base,
            index: None,
            scale: 1,
            disp: 0,
            width: 64,
            rip_relative_address: image.then_some(0x2000),
        }
    }
    fn function(ops: Vec<Op>) -> LiftedFunction {
        let instructions = ops
            .into_iter()
            .enumerate()
            .map(|(index, op)| Instruction {
                address: 0x1000 + index as u64,
                len: 1,
                op,
            })
            .collect::<Vec<_>>();
        LiftedFunction {
            start: 0x1000,
            end: 0x1000 + instructions.len() as u64,
            instructions,
        }
    }

    #[test]
    fn direct_image_pointer_return_is_distinct_from_integer_return() {
        let f = function(vec![
            Op::Lea {
                dst: reg(0),
                address: memory(None, true),
            },
            Op::Return,
        ]);
        let states = analyze(&f).unwrap();
        assert_eq!(states[1][0], IMAGE);
        assert_eq!(states[0][4], STACK);
        assert_eq!(states[0][7], NUM);
        assert_eq!(states[0][3], UNKNOWN);
    }

    #[test]
    fn table_address_is_admitted_but_loaded_bytes_are_numeric() {
        let m = memory(Some(0), false);
        let f = function(vec![
            Op::Lea {
                dst: reg(0),
                address: memory(None, true),
            },
            Op::Move {
                dst: r(0),
                src: Operand::Mem(m.clone()),
            },
            Op::Return,
        ]);
        let states = analyze(&f).unwrap();
        assert!(memory_admissible(&m, &states[1]));
        assert_eq!(states[2][0], NUM);
    }

    #[test]
    fn external_integer_argument_is_not_an_address() {
        let f = function(vec![
            Op::Move {
                dst: r(0),
                src: r(7),
            },
            Op::Return,
        ]);
        let states = analyze(&f).unwrap();
        assert!(!memory_admissible(&memory(Some(7), false), &states[0]));
        assert!(!memory_admissible(&memory(Some(0), false), &states[1]));
        assert!(memory_admissible(&memory(Some(5), false), &states[0]));
    }

    #[test]
    fn cfg_merge_keeps_scalar_and_image_paths() {
        let f = function(vec![
            Op::Branch {
                condition: Condition::Equal,
                target: 0x1003,
            },
            Op::Lea {
                dst: reg(0),
                address: memory(None, true),
            },
            Op::Jump { target: 0x1004 },
            Op::Move {
                dst: r(0),
                src: Operand::Imm(3),
            },
            Op::Return,
        ]);
        assert_eq!(analyze(&f).unwrap()[4][0], NUM | IMAGE);
    }

    #[test]
    fn pointer_spill_retains_a_possible_image_restore() {
        let slot = Operand::Mem(memory(Some(4), false));
        let f = function(vec![
            Op::Lea {
                dst: reg(0),
                address: memory(None, true),
            },
            Op::Move {
                dst: slot.clone(),
                src: r(0),
            },
            Op::Move {
                dst: r(3),
                src: slot,
            },
            Op::Return,
        ]);
        let states = analyze(&f).unwrap();
        assert_ne!(states[3][3] & IMAGE, 0);
        assert!(memory_admissible(&memory(Some(3), false), &states[3]));
    }

    #[test]
    fn partial_pointer_write_cannot_retain_pointer_provenance() {
        let low = Operand::Reg(RegView {
            family: 0,
            width: 32,
            high8: false,
        });
        let f = function(vec![
            Op::Lea {
                dst: reg(0),
                address: memory(None, true),
            },
            Op::Move {
                dst: low,
                src: Operand::Imm(0),
            },
            Op::Return,
        ]);
        assert_eq!(analyze(&f).unwrap()[2][0], NUM);
        let low = Operand::Reg(RegView {
            family: 0,
            width: 8,
            high8: false,
        });
        let f = function(vec![
            Op::Lea {
                dst: reg(0),
                address: memory(None, true),
            },
            Op::Move {
                dst: low,
                src: Operand::Imm(0),
            },
            Op::Return,
        ]);
        assert_eq!(analyze(&f).unwrap()[2][0], NUM | INVALID);
    }
}
