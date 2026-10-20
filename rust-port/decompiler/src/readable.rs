// SPDX-License-Identifier: Apache-2.0
//! Readable Rust for functions over registers and the stack.
//!
//! The guarded emitters keep a machine model at run time. This emitter instead
//! executes the lifted IR symbolically along every path, from the entry to
//! each return, and writes what each path computes as ordinary Rust: argument
//! expressions, `let` bindings for large intermediate values, `if` blocks for
//! branches and `loop` blocks for natural loops. It accepts a function only
//! when that can be done exactly:
//!
//! - Every path ends in a return or an abort within a fixed step budget;
//!   branches whose condition folds to a constant follow one side.
//! - A natural loop of the entry function with at most one exit target, and
//!   no calls, pushes or pops, carries the registers and stack slots it
//!   writes in `let mut` variables, assigned together at each back edge and
//!   at the exit. A variable whose value depends on an unknown value stays
//!   unknown instead. Other cycles, including loops in called functions, are
//!   rejected.
//! - Memory is the function's own stack frame, addressed through registers
//!   that hold a known stack offset, and a load reads bytes the same path
//!   stored. Image, external and caller memory are rejected.
//! - Registers other than the six arguments start opaque. A path may save and
//!   restore them, but its result and branch conditions must not depend on
//!   them or on the stack-protector canary, except where a value cancels
//!   against itself (`x - x`, `x ^ x`, `x == x`).
//! - Flags are kept as the operation that set them, and only the conditions
//!   that operation defines exactly are read.
//! - Direct calls to linked functions are followed inline; recursion is
//!   rejected.
//!
//! Everything else returns an error, and the caller keeps the guarded output.
use crate::emit::ReturnKind;
use crate::lift::{BinaryKind, Condition, LiftedFunction, Memory, Op, Operand, RegView, UnaryKind};
use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::fmt::Write;

thread_local! {
    /// `let` bindings and loop variables that rendered output reads.
    static READS: RefCell<(HashSet<u32>, HashSet<Name>)> = RefCell::default();
}

/// Instructions executed over all paths together.
const MAX_STEPS: usize = 4096;
const MAX_OUTPUT: usize = 256 * 1024;
/// The guarded runtime's stack lies 4,104 bytes below the entry stack pointer.
const STACK_LOW: i64 = -4104;
/// Values larger than this many expression nodes are bound with `let`.
const BIND_NODES: usize = 8;
const CANARY: u8 = 16;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum Ty {
    Bool,
    U8,
    U16,
    U32,
    U64,
}
impl Ty {
    fn of(width: u8) -> Self {
        match width {
            8 => Self::U8,
            16 => Self::U16,
            32 => Self::U32,
            _ => Self::U64,
        }
    }
    fn bits(self) -> u32 {
        match self {
            Self::Bool => 1,
            Self::U8 => 8,
            Self::U16 => 16,
            Self::U32 => 32,
            Self::U64 => 64,
        }
    }
    fn mask(self) -> u64 {
        if self == Self::U64 {
            u64::MAX
        } else {
            (1u64 << self.bits()) - 1
        }
    }
    fn name(self) -> &'static str {
        match self {
            Self::Bool => "bool",
            Self::U8 => "u8",
            Self::U16 => "u16",
            Self::U32 => "u32",
            Self::U64 => "u64",
        }
    }
    fn signed(self) -> &'static str {
        match self {
            Self::U8 => "i8",
            Self::U16 => "i16",
            Self::U32 => "i32",
            _ => "i64",
        }
    }
    fn sign_extend(self, v: u64) -> u64 {
        let shift = 64 - self.bits();
        (((v << shift) as i64) >> shift) as u64
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum Bop {
    Add,
    Sub,
    Mul,
    And,
    Or,
    Xor,
    /// Shifts by a constant count below the width.
    Shl,
    Shr,
    Sar,
    /// Shifts by a `u8` count, masked as `wrapping_shl` does (32 and 64 bits).
    ShlVar,
    ShrVar,
    SarVar,
    /// Rotates by a constant `u32` count, or by a `u8` count.
    Rotl,
    Rotr,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum Cop {
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
    SLt,
    SLe,
    SGt,
    SGe,
}
impl Cop {
    fn negate(self) -> Self {
        match self {
            Self::Eq => Self::Ne,
            Self::Ne => Self::Eq,
            Self::Lt => Self::Ge,
            Self::Ge => Self::Lt,
            Self::Le => Self::Gt,
            Self::Gt => Self::Le,
            Self::SLt => Self::SGe,
            Self::SGe => Self::SLt,
            Self::SLe => Self::SGt,
            Self::SGt => Self::SLe,
        }
    }
    fn signed(self) -> bool {
        matches!(self, Self::SLt | Self::SLe | Self::SGt | Self::SGe)
    }
    fn symbol(self) -> &'static str {
        match self {
            Self::Eq => "==",
            Self::Ne => "!=",
            Self::Lt | Self::SLt => "<",
            Self::Le | Self::SLe => "<=",
            Self::Gt | Self::SGt => ">",
            Self::Ge | Self::SGe => ">=",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
enum Expr {
    /// A `u64` argument, `a0` (RDI) to `a5` (R9).
    Arg(u8),
    /// A `u64` the function did not compute: a register's entry value (by
    /// family) or the canary.
    Opaque(u8),
    Const(u64, Ty),
    Var(u32, Ty),
    /// A mutable variable of a structured loop.
    Mut(Name, Ty),
    /// Conversion to a type; widening sign-extends when the flag is set.
    Cast(Box<Expr>, Ty, bool),
    Bin(Bop, Box<Expr>, Box<Expr>),
    Not(Box<Expr>),
    Neg(Box<Expr>),
    Cmp(Cop, Box<Expr>, Box<Expr>),
    Select(Box<Expr>, Box<Expr>, Box<Expr>),
    /// x86 PF of a `u8`: an even number of set bits.
    Parity(Box<Expr>),
    /// Unsigned overflow of `a + b`.
    Carry(Box<Expr>, Box<Expr>),
    /// Signed overflow of `a - b` (flag set) or `a + b`.
    Overflow(bool, Box<Expr>, Box<Expr>),
}

/// What a loop variable holds, and the loop that declares it: a register, or
/// the stack bytes at an offset from the entry stack pointer.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum Name {
    Reg(u8, u32),
    Slot(i64, u32),
}
const REGISTERS: [&str; 16] = [
    "rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi", "r8", "r9", "r10", "r11", "r12", "r13",
    "r14", "r15",
];
impl std::fmt::Display for Name {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Reg(family, id) => write!(f, "{}_{id}", REGISTERS[*family as usize]),
            Self::Slot(offset, id) => write!(f, "local_{:x}_{id}", offset.unsigned_abs()),
        }
    }
}

/// A loop being structured: its body, its one exit, and the variables it
/// carries. A variable whose next value depends on an unknown value is
/// marked so the loop can be structured again without it.
struct LoopContext {
    header: u64,
    body: std::rc::Rc<HashSet<u64>>,
    exit: Option<u64>,
    vars: Vec<(Name, Ty, i64)>,
    tainted: Vec<bool>,
    fresh: bool,
}

/// Natural loops of the entry function's frame, by header: the header and
/// every instruction that reaches one of its back edges without passing it.
/// A call's successor is its return site.
fn natural_loops(
    function: &LiftedFunction,
    at: &HashMap<u64, usize>,
) -> HashMap<u64, HashSet<u64>> {
    let successors = |address: u64| -> Vec<u64> {
        let ins = &function.instructions[at[&address]];
        let next = ins.address + u64::from(ins.len);
        let all = match ins.op {
            Op::Jump { target } => vec![target],
            Op::Branch { target, .. } => vec![target, next],
            Op::Return | Op::Abort => vec![],
            _ => vec![next],
        };
        all.into_iter().filter(|a| at.contains_key(a)).collect()
    };
    // Reverse postorder by an explicit depth-first search.
    let mut postorder = Vec::new();
    let mut seen = HashSet::from([function.start]);
    let mut stack = vec![(function.start, successors(function.start), 0usize)];
    while let Some((node, next, index)) = stack.last_mut() {
        if let Some(&child) = next.get(*index) {
            *index += 1;
            if seen.insert(child) {
                let children = successors(child);
                stack.push((child, children, 0));
            }
        } else {
            postorder.push(*node);
            stack.pop();
        }
    }
    let order: HashMap<u64, usize> = postorder
        .iter()
        .rev()
        .enumerate()
        .map(|(i, a)| (*a, i))
        .collect();
    let rpo: Vec<u64> = postorder.iter().rev().copied().collect();
    let mut predecessors: HashMap<u64, Vec<u64>> = HashMap::new();
    for &node in &rpo {
        for child in successors(node) {
            predecessors.entry(child).or_default().push(node);
        }
    }
    // Immediate dominators (Cooper, Harvey and Kennedy), as RPO indices.
    let mut idom = vec![usize::MAX; rpo.len()];
    idom[0] = 0;
    let mut changed = true;
    while changed {
        changed = false;
        for (i, node) in rpo.iter().enumerate().skip(1) {
            let mut new = usize::MAX;
            for p in predecessors.get(node).into_iter().flatten() {
                let mut p = order[p];
                if idom[p] == usize::MAX {
                    continue;
                }
                if new == usize::MAX {
                    new = p;
                    continue;
                }
                let mut q = new;
                while p != q {
                    while p > q {
                        p = idom[p];
                    }
                    while q > p {
                        q = idom[q];
                    }
                }
                new = p;
            }
            if new != idom[i] {
                idom[i] = new;
                changed = true;
            }
        }
    }
    let dominates = |a: usize, mut b: usize| loop {
        if a == b {
            return true;
        }
        if b == 0 {
            return false;
        }
        b = idom[b];
    };
    let mut loops: HashMap<u64, HashSet<u64>> = HashMap::new();
    for &node in &rpo {
        for header in successors(node) {
            if !dominates(order[&header], order[&node]) {
                continue;
            }
            let body = loops
                .entry(header)
                .or_insert_with(|| HashSet::from([header]));
            let mut work = vec![node];
            while let Some(n) = work.pop() {
                if body.insert(n) {
                    work.extend(predecessors.get(&n).into_iter().flatten().copied());
                }
            }
        }
    }
    loops
}

fn b(e: Expr) -> Box<Expr> {
    Box::new(e)
}

impl Expr {
    fn ty(&self) -> Ty {
        match self {
            Self::Arg(_) | Self::Opaque(_) => Ty::U64,
            Self::Const(_, t) | Self::Var(_, t) | Self::Mut(_, t) | Self::Cast(_, t, _) => *t,
            Self::Bin(_, a, _) | Self::Not(a) | Self::Neg(a) => a.ty(),
            Self::Select(_, a, _) => a.ty(),
            Self::Cmp(..) | Self::Parity(_) | Self::Carry(..) | Self::Overflow(..) => Ty::Bool,
        }
    }
    fn children(&self) -> Vec<&Expr> {
        match self {
            Self::Arg(_) | Self::Opaque(_) | Self::Const(..) | Self::Var(..) | Self::Mut(..) => {
                vec![]
            }
            Self::Cast(a, ..) | Self::Not(a) | Self::Neg(a) | Self::Parity(a) => vec![a],
            Self::Bin(_, a, c)
            | Self::Cmp(_, a, c)
            | Self::Carry(a, c)
            | Self::Overflow(_, a, c) => {
                vec![a, c]
            }
            Self::Select(a, c, d) => vec![a, c, d],
        }
    }
    fn nodes(&self) -> usize {
        1 + self.children().iter().map(|c| c.nodes()).sum::<usize>()
    }
    fn opaque(&self) -> bool {
        matches!(self, Self::Opaque(_)) || self.children().iter().any(|c| c.opaque())
    }
    fn constant(&self) -> Option<u64> {
        match self {
            Self::Const(v, _) => Some(*v),
            _ => None,
        }
    }
}

fn konst(v: u64, t: Ty) -> Expr {
    Expr::Const(v & t.mask(), t)
}
fn boolean(v: bool) -> Expr {
    Expr::Const(u64::from(v), Ty::Bool)
}

/// Convert to `to`, folding constants and nested conversions.
fn cast(e: Expr, to: Ty, sign: bool) -> Expr {
    let from = e.ty();
    if from == to {
        return e;
    }
    if let Expr::Const(v, _) = e {
        let v = if sign && from != Ty::Bool {
            from.sign_extend(v)
        } else {
            v
        };
        return konst(v, to);
    }
    if from == Ty::Bool {
        return Expr::Cast(b(e), to, false);
    }
    if to.bits() < from.bits() {
        return low(e, to);
    }
    match e {
        // Widening a widened value: a zero extension stays one, and equal
        // sign extensions combine.
        Expr::Cast(inner, _, inner_sign)
            if inner.ty().bits() < from.bits() && (!inner_sign || sign) =>
        {
            Expr::Cast(inner, to, inner_sign)
        }
        e => Expr::Cast(b(e), to, sign),
    }
}

/// The low `to` bits of `e`.
fn low(e: Expr, to: Ty) -> Expr {
    match e {
        Expr::Cast(inner, _, sign) => {
            let bits = inner.ty().bits();
            if inner.ty() == Ty::Bool || bits < to.bits() {
                Expr::Cast(inner, to, sign)
            } else {
                cast(*inner, to, false)
            }
        }
        Expr::Bin(Bop::Or, l, r) => {
            // A merge `(old & !mask) | new` whose `old` part has no low bits.
            let clears = |x: &Expr| {
                matches!(x, Expr::Bin(Bop::And, _, m)
                    if m.constant().is_some_and(|m| m & to.mask() == 0))
            };
            if clears(&l) {
                low(*r, to)
            } else if clears(&r) {
                low(*l, to)
            } else {
                Expr::Cast(b(Expr::Bin(Bop::Or, l, r)), to, false)
            }
        }
        Expr::Bin(Bop::And, l, r) if r.constant().is_some_and(|m| m & to.mask() == to.mask()) => {
            low(*l, to)
        }
        e => Expr::Cast(b(e), to, false),
    }
}

fn fold(op: Bop, a: u64, c: u64, t: Ty) -> u64 {
    let bits = t.bits();
    let r = match op {
        Bop::Add => a.wrapping_add(c),
        Bop::Sub => a.wrapping_sub(c),
        Bop::Mul => a.wrapping_mul(c),
        Bop::And => a & c,
        Bop::Or => a | c,
        Bop::Xor => a ^ c,
        Bop::Shl | Bop::ShlVar => a << (c as u32 % bits),
        Bop::Shr | Bop::ShrVar => a >> (c as u32 % bits),
        Bop::Sar | Bop::SarVar => (t.sign_extend(a) as i64 >> (c as u32 % bits)) as u64,
        Bop::Rotl | Bop::Rotr => {
            let n = c as u32 % bits;
            let n = if op == Bop::Rotr {
                (bits - n) % bits
            } else {
                n
            };
            if n == 0 {
                a
            } else {
                (a << n) | (a >> (bits - n))
            }
        }
    };
    r & t.mask()
}

fn bin(op: Bop, l: Expr, r: Expr) -> Expr {
    let t = l.ty();
    if let (Some(x), Some(y)) = (l.constant(), r.constant()) {
        return konst(fold(op, x, y, t), t);
    }
    let commutes = matches!(op, Bop::Add | Bop::Mul | Bop::And | Bop::Or | Bop::Xor);
    let (l, r) = if commutes && l.constant().is_some() {
        (r, l)
    } else {
        (l, r)
    };
    let c = r.constant();
    match (op, c) {
        (Bop::Add | Bop::Sub | Bop::Or | Bop::Xor, Some(0)) => return l,
        (Bop::Shl | Bop::Shr | Bop::Sar | Bop::Rotl | Bop::Rotr, Some(0)) => return l,
        (Bop::Mul, Some(1)) => return l,
        (Bop::And | Bop::Mul, Some(0)) => return konst(0, t),
        (Bop::And, Some(m)) if m == t.mask() => return l,
        (Bop::Or, Some(m)) if m == t.mask() => return konst(m, t),
        // `x + 0xffffffff` reads better as `x - 1`.
        (Bop::Add, Some(v)) if v > t.mask() / 2 => {
            return Expr::Bin(Bop::Sub, b(l), b(konst(v.wrapping_neg(), t)));
        }
        (Bop::Sub, Some(v)) if v > t.mask() / 2 => {
            return Expr::Bin(Bop::Add, b(l), b(konst(v.wrapping_neg(), t)));
        }
        _ => {}
    }
    if l == r {
        match op {
            Bop::Sub | Bop::Xor => return konst(0, t),
            Bop::And | Bop::Or => return l,
            _ => {}
        }
    }
    Expr::Bin(op, b(l), b(r))
}

fn cmp(op: Cop, l: Expr, r: Expr) -> Expr {
    let t = l.ty();
    if let (Some(x), Some(y)) = (l.constant(), r.constant()) {
        let (x, y) = if op.signed() {
            (
                t.sign_extend(x) as i64 as i128,
                t.sign_extend(y) as i64 as i128,
            )
        } else {
            (x as i128, y as i128)
        };
        return boolean(match op {
            Cop::Eq => x == y,
            Cop::Ne => x != y,
            Cop::Lt | Cop::SLt => x < y,
            Cop::Le | Cop::SLe => x <= y,
            Cop::Gt | Cop::SGt => x > y,
            Cop::Ge | Cop::SGe => x >= y,
        });
    }
    if l == r {
        return boolean(matches!(
            op,
            Cop::Eq | Cop::Le | Cop::Ge | Cop::SLe | Cop::SGe
        ));
    }
    // Keep a constant on the right.
    if l.constant().is_some() {
        let mirrored = match op {
            Cop::Lt => Cop::Gt,
            Cop::Gt => Cop::Lt,
            Cop::Le => Cop::Ge,
            Cop::Ge => Cop::Le,
            Cop::SLt => Cop::SGt,
            Cop::SGt => Cop::SLt,
            Cop::SLe => Cop::SGe,
            Cop::SGe => Cop::SLe,
            op => op,
        };
        return cmp(mirrored, r, l);
    }
    // Comparisons with the type's limits, which rustc rejects as useless.
    if let Some(c) = r.constant().filter(|_| t != Ty::Bool) {
        let (least, most) = if op.signed() {
            (1u64 << (t.bits() - 1), t.mask() >> 1)
        } else {
            (0, t.mask())
        };
        let (l, r) = (b(l), b(r));
        match op {
            Cop::Lt | Cop::SLt if c == least => return boolean(false),
            Cop::Ge | Cop::SGe if c == least => return boolean(true),
            Cop::Le | Cop::SLe if c == least => return Expr::Cmp(Cop::Eq, l, r),
            Cop::Gt | Cop::SGt if c == least => return Expr::Cmp(Cop::Ne, l, r),
            Cop::Gt | Cop::SGt if c == most => return boolean(false),
            Cop::Le | Cop::SLe if c == most => return boolean(true),
            Cop::Ge | Cop::SGe if c == most => return Expr::Cmp(Cop::Eq, l, r),
            Cop::Lt | Cop::SLt if c == most => return Expr::Cmp(Cop::Ne, l, r),
            _ => return Expr::Cmp(op, l, r),
        }
    }
    if t == Ty::Bool && !matches!(op, Cop::Eq | Cop::Ne) {
        // Not produced by any flag condition.
        unreachable!("ordered comparison of booleans")
    }
    Expr::Cmp(op, b(l), b(r))
}

fn not(e: Expr) -> Expr {
    match e {
        Expr::Const(v, t) => konst(!v, t),
        Expr::Not(inner) => *inner,
        Expr::Cmp(op, l, r) => Expr::Cmp(op.negate(), l, r),
        e => Expr::Not(b(e)),
    }
}

fn select(c: Expr, then: Expr, otherwise: Expr) -> Expr {
    match c.constant() {
        Some(1) => then,
        Some(_) => otherwise,
        None if then == otherwise => then,
        None => Expr::Select(b(c), b(then), b(otherwise)),
    }
}

#[derive(Clone, Debug, PartialEq)]
enum Val {
    /// A number, as a `u64` in registers and at its store width on the stack.
    E(Expr),
    /// The address `entry RSP + offset`.
    Stack(i64),
    /// A return address pushed by a followed call.
    Ret(u64),
}

#[derive(Clone, Debug)]
struct Slot {
    offset: i64,
    bytes: i64,
    val: Val,
}

#[derive(Clone, Debug)]
enum Flags {
    Unknown,
    /// `cmp`/`sub a, b` (and `neg` as `0 - b`).
    Sub(Expr, Expr),
    Add(Expr, Expr),
    /// `test`/`and`/`or`/`xor`: CF and OF clear.
    Logic(Expr),
    /// ZF, SF and PF of a result, with CF when it is known.
    Result(Expr, Option<Expr>),
}

#[derive(Clone)]
struct State {
    regs: [Val; 16],
    slots: Vec<Slot>,
    flags: Flags,
    /// Frame ids of followed calls, the entry frame first.
    frames: Vec<usize>,
    /// Targets of followed calls, for rejecting recursion.
    calls: Vec<u64>,
}

struct Walker<'a> {
    function: &'a LiftedFunction,
    at: HashMap<u64, usize>,
    return_kind: ReturnKind,
    steps: usize,
    vars: u32,
    frames: usize,
    path: HashSet<(usize, u64)>,
    loops: HashMap<u64, std::rc::Rc<HashSet<u64>>>,
    contexts: Vec<LoopContext>,
    loop_ids: u32,
    /// Bindings and loop variables an earlier pass found unread, left out.
    dead: (HashSet<u32>, HashSet<Name>),
}

/// The statements before a path's last line, and that line.
fn split_last(text: &str) -> (&str, &str) {
    let text = text.strip_suffix('\n').unwrap_or(text);
    match text.rfind('\n') {
        Some(i) => (&text[..=i], &text[i + 1..]),
        None => ("", text),
    }
}

fn indent(text: &str) -> String {
    text.lines().map(|line| format!("    {line}\n")).collect()
}

const ARGS: [(u8, u8); 6] = [(7, 0), (6, 1), (2, 2), (1, 3), (8, 4), (9, 5)];

impl Walker<'_> {
    fn bind(&mut self, out: &mut String, e: Expr) -> Expr {
        if e.nodes() <= BIND_NODES || e.opaque() {
            return e;
        }
        // Bind a zero-extended value at its own width.
        let (inner, widen) = match e {
            Expr::Cast(inner, to, false) if inner.ty() != Ty::Bool => (*inner, Some(to)),
            e => (e, None),
        };
        if inner.nodes() <= BIND_NODES {
            return match widen {
                Some(to) => Expr::Cast(b(inner), to, false),
                None => inner,
            };
        }
        let t = inner.ty();
        let n = self.vars;
        self.vars += 1;
        if !self.dead.0.contains(&n) {
            writeln!(out, "let v{n}: {} = {};", t.name(), render(&inner)).unwrap();
        }
        match widen {
            Some(to) => Expr::Cast(b(Expr::Var(n, t)), to, false),
            None => Expr::Var(n, t),
        }
    }

    fn stack(&self, s: &State, m: &Memory) -> Result<i64, String> {
        if m.rip_relative_address.is_some() || m.index.is_some() {
            return Err("memory outside the stack frame".into());
        }
        let base = m.base.ok_or("absolute memory")?;
        let Val::Stack(offset) = s.regs[base as usize] else {
            return Err("memory through a register that is not a stack address".into());
        };
        let offset = offset.checked_add(m.disp).ok_or("stack offset overflow")?;
        let bytes = i64::from(m.width / 8);
        if offset < STACK_LOW || offset + bytes > 0 {
            return Err("memory outside the function's own stack frame".into());
        }
        Ok(offset)
    }
    fn load(&self, s: &State, offset: i64, bytes: i64) -> Result<Val, String> {
        let slot = s
            .slots
            .iter()
            .find(|slot| slot.offset <= offset && offset + bytes <= slot.offset + slot.bytes)
            .ok_or("a stack load that does not read one earlier store")?;
        match &slot.val {
            Val::E(e) => {
                let shift = 8 * (offset - slot.offset) as u64;
                let shifted = bin(Bop::Shr, e.clone(), konst(shift, e.ty()));
                Ok(Val::E(cast(shifted, Ty::of((bytes * 8) as u8), false)))
            }
            val if slot.offset == offset && bytes == 8 => Ok(val.clone()),
            _ => Err("a partial load of a stored address".into()),
        }
    }
    fn store(&mut self, out: &mut String, s: &mut State, offset: i64, bytes: i64, val: Val) {
        s.slots
            .retain(|slot| slot.offset + slot.bytes <= offset || offset + bytes <= slot.offset);
        let val = match val {
            Val::E(e) => Val::E(self.bind(out, e)),
            val => val,
        };
        s.slots.push(Slot { offset, bytes, val });
    }
    fn read_val(&self, s: &State, o: &Operand) -> Result<Val, String> {
        match o {
            Operand::Reg(r) if r.width == 64 => Ok(s.regs[r.family as usize].clone()),
            Operand::Mem(m) if m.width == 64 => self.load(s, self.stack(s, m)?, 8),
            o => self.read(s, o, 64).map(Val::E),
        }
    }
    /// An integer operand at its width, or `width` for an immediate.
    fn read(&self, s: &State, o: &Operand, width: u8) -> Result<Expr, String> {
        match o {
            Operand::Imm(v) => Ok(konst(*v, Ty::of(width))),
            Operand::Canary => Ok(Expr::Opaque(CANARY)),
            Operand::Reg(r) => {
                let Val::E(e) = &s.regs[r.family as usize] else {
                    return Err("an address used as a number".into());
                };
                if r.high8 {
                    Ok(cast(
                        bin(Bop::Shr, e.clone(), konst(8, Ty::U64)),
                        Ty::U8,
                        false,
                    ))
                } else {
                    Ok(cast(e.clone(), Ty::of(r.width), false))
                }
            }
            Operand::Mem(m) => match self.load(s, self.stack(s, m)?, i64::from(m.width / 8))? {
                Val::E(e) => Ok(e),
                _ => Err("an address used as a number".into()),
            },
        }
    }
    fn write_reg(
        &mut self,
        out: &mut String,
        s: &mut State,
        r: RegView,
        v: Expr,
    ) -> Result<(), String> {
        if r.family == 4 {
            return Err("RSP set to a number".into());
        }
        let family = r.family as usize;
        let value = match (r.width, r.high8) {
            (64, _) => v,
            (32, _) => cast(v, Ty::U64, false),
            (width, high8) => {
                let Val::E(old) = &s.regs[family] else {
                    return Err("a partial write to an address".into());
                };
                let (mask, part) = if high8 {
                    (
                        0xff00,
                        bin(Bop::Shl, cast(v, Ty::U64, false), konst(8, Ty::U64)),
                    )
                } else {
                    (Ty::of(width).mask(), cast(v, Ty::U64, false))
                };
                // Replace an earlier write of the same bits.
                let base = match old {
                    Expr::Bin(Bop::Or, l, _)
                        if matches!(&**l, Expr::Bin(Bop::And, _, m)
                        if m.constant() == Some(!mask)) =>
                    {
                        match &**l {
                            Expr::Bin(_, base, _) => (**base).clone(),
                            _ => unreachable!(),
                        }
                    }
                    old => old.clone(),
                };
                bin(Bop::Or, bin(Bop::And, base, konst(!mask, Ty::U64)), part)
            }
        };
        s.regs[family] = Val::E(self.bind(out, value));
        Ok(())
    }
    fn write(
        &mut self,
        out: &mut String,
        s: &mut State,
        o: &Operand,
        v: Expr,
    ) -> Result<(), String> {
        match o {
            Operand::Reg(r) => self.write_reg(out, s, *r, v),
            Operand::Mem(m) => {
                let offset = self.stack(s, m)?;
                self.store(out, s, offset, i64::from(m.width / 8), Val::E(v));
                Ok(())
            }
            _ => Err("IR writes an immediate or the canary".into()),
        }
    }
    fn write_val(
        &mut self,
        out: &mut String,
        s: &mut State,
        o: &Operand,
        v: Val,
    ) -> Result<(), String> {
        match (o, v) {
            (o, Val::E(e)) => self.write(out, s, o, e),
            (Operand::Reg(r), v) if r.width == 64 => {
                s.regs[r.family as usize] = v;
                Ok(())
            }
            (Operand::Mem(m), v) if m.width == 64 => {
                let offset = self.stack(s, m)?;
                self.store(out, s, offset, 8, v);
                Ok(())
            }
            _ => Err("a partial write of an address".into()),
        }
    }
    fn push(&mut self, out: &mut String, s: &mut State, v: Val) -> Result<(), String> {
        let Val::Stack(offset) = s.regs[4] else {
            return Err("RSP is not a stack address".into());
        };
        let offset = offset - 8;
        if offset < STACK_LOW {
            return Err("stack overflow".into());
        }
        self.store(out, s, offset, 8, v);
        s.regs[4] = Val::Stack(offset);
        Ok(())
    }
    fn pop(&self, s: &mut State) -> Result<Val, String> {
        let Val::Stack(offset) = s.regs[4] else {
            return Err("RSP is not a stack address".into());
        };
        if offset + 8 > 0 {
            return Err("a pop of the caller's frame".into());
        }
        let v = self.load(s, offset, 8)?;
        s.regs[4] = Val::Stack(offset + 8);
        Ok(v)
    }

    fn walk(&mut self, mut s: State, mut pc: u64) -> Result<String, String> {
        let mut out = String::new();
        let mut added = Vec::new();
        let result = self.walk_from(&mut s, &mut pc, &mut out, &mut added);
        for key in added {
            self.path.remove(&key);
        }
        result.map(|()| out)
    }

    fn walk_from(
        &mut self,
        s: &mut State,
        pc: &mut u64,
        out: &mut String,
        added: &mut Vec<(usize, u64)>,
    ) -> Result<(), String> {
        loop {
            self.steps += 1;
            if self.steps > MAX_STEPS || out.len() > MAX_OUTPUT {
                return Err("the readable form exceeds its size budget".into());
            }
            let frame = *s.frames.last().unwrap();
            if s.frames.len() == 1 {
                if let Some(context) = self.contexts.last_mut() {
                    if context.fresh {
                        context.fresh = false;
                    } else if *pc == context.header {
                        self.assign(s, out)?;
                        out.push_str("continue;\n");
                        return Ok(());
                    } else if !context.body.contains(pc) {
                        if Some(*pc) != context.exit {
                            return Err("a loop exit outside the loop's one exit".into());
                        }
                        self.assign(s, out)?;
                        out.push_str("break;\n");
                        return Ok(());
                    }
                }
                let active = self.contexts.last().is_some_and(|c| c.header == *pc);
                if !active && self.loops.contains_key(pc) {
                    match self.structure(s, *pc, out)? {
                        Some(exit) => {
                            *pc = exit;
                            continue;
                        }
                        None => return Ok(()),
                    }
                }
            }
            if !self.path.insert((frame, *pc)) {
                return Err("an irreducible loop or a loop in a called function".into());
            }
            added.push((frame, *pc));
            let index = *self
                .at
                .get(pc)
                .ok_or("control reaches an unlifted address")?;
            let function = self.function;
            let ins = &function.instructions[index];
            let next = ins.address + u64::from(ins.len);
            *pc = next;
            match &ins.op {
                Op::Nop => {}
                Op::Move { dst, src } => {
                    let v = if dst.width() == Some(64) {
                        self.read_val(s, src)?
                    } else {
                        Val::E(self.read(s, src, dst.width().unwrap_or(64))?)
                    };
                    self.write_val(out, s, dst, v)?;
                }
                Op::MoveZeroExtend { dst, src } | Op::MoveSignExtend { dst, src } => {
                    let sign = matches!(ins.op, Op::MoveSignExtend { .. });
                    let v = self.read(s, src, 64)?;
                    self.write_reg(out, s, *dst, cast(v, Ty::of(dst.width), sign))?;
                }
                Op::Lea { dst, address: m } => {
                    if m.rip_relative_address.is_some() {
                        return Err("an image address".into());
                    }
                    let base = m.base.map(|r| s.regs[r as usize].clone());
                    if let Some(Val::Stack(offset)) = base {
                        if m.index.is_some() || dst.width != 64 {
                            return Err("arithmetic on a stack address".into());
                        }
                        s.regs[dst.family as usize] = Val::Stack(offset + m.disp);
                        continue;
                    }
                    let number = |r: Option<u8>| -> Result<Option<Expr>, String> {
                        match r.map(|r| &s.regs[r as usize]) {
                            None => Ok(None),
                            Some(Val::E(e)) => Ok(Some(e.clone())),
                            Some(_) => Err("arithmetic on an address".into()),
                        }
                    };
                    let mut v = konst(m.disp as u64, Ty::U64);
                    if let Some(index) = number(m.index)? {
                        let scaled = bin(
                            Bop::Shl,
                            index,
                            konst(u64::from(m.scale.trailing_zeros()), Ty::U64),
                        );
                        v = bin(Bop::Add, scaled, v);
                    }
                    if let Some(base) = number(m.base)? {
                        v = bin(Bop::Add, base, v);
                    }
                    self.write_reg(out, s, *dst, cast(v, Ty::of(dst.width), false))?;
                }
                Op::Binary {
                    kind,
                    dst,
                    left,
                    right,
                } => {
                    let width = dst.width().ok_or("binary destination width")?;
                    let t = Ty::of(width);
                    if let (Operand::Reg(r), Operand::Imm(imm), BinaryKind::Add | BinaryKind::Sub) =
                        (dst, right, kind)
                    {
                        if let Val::Stack(offset) = s.regs[r.family as usize] {
                            if width != 64 || left != dst {
                                return Err("arithmetic on a stack address".into());
                            }
                            let delta = *imm as i64;
                            let offset = if *kind == BinaryKind::Add {
                                offset.checked_add(delta)
                            } else {
                                offset.checked_sub(delta)
                            }
                            .ok_or("stack offset overflow")?;
                            s.regs[r.family as usize] = Val::Stack(offset);
                            s.flags = Flags::Unknown;
                            continue;
                        }
                    }
                    let shift = matches!(
                        kind,
                        BinaryKind::Shl
                            | BinaryKind::Shr
                            | BinaryKind::Sar
                            | BinaryKind::Rol
                            | BinaryKind::Ror
                    );
                    let a = self.read(s, left, width)?;
                    let value = if shift {
                        match right {
                            Operand::Imm(count) => {
                                let count = (*count as u32) & if width == 64 { 63 } else { 31 };
                                let r = match kind {
                                    _ if count == 0 => a,
                                    BinaryKind::Rol | BinaryKind::Ror => {
                                        let op = if *kind == BinaryKind::Rol {
                                            Bop::Rotl
                                        } else {
                                            Bop::Rotr
                                        };
                                        bin(op, a, konst(u64::from(count % t.bits()), t))
                                    }
                                    BinaryKind::Sar => bin(
                                        Bop::Sar,
                                        a,
                                        konst(u64::from(count.min(t.bits() - 1)), t),
                                    ),
                                    _ if count >= t.bits() => konst(0, t),
                                    BinaryKind::Shl => bin(Bop::Shl, a, konst(u64::from(count), t)),
                                    _ => bin(Bop::Shr, a, konst(u64::from(count), t)),
                                };
                                if count != 0 {
                                    s.flags = if matches!(kind, BinaryKind::Rol | BinaryKind::Ror) {
                                        Flags::Unknown
                                    } else {
                                        Flags::Result(r.clone(), None)
                                    };
                                }
                                r
                            }
                            _ => {
                                let count = self.read(s, right, 8)?;
                                if count.ty() != Ty::U8 {
                                    return Err("a shift count that is not CL".into());
                                }
                                let op = match kind {
                                    BinaryKind::Rol => Bop::Rotl,
                                    BinaryKind::Ror => Bop::Rotr,
                                    _ if width < 32 => {
                                        return Err("a variable 8- or 16-bit shift".into());
                                    }
                                    BinaryKind::Shl => Bop::ShlVar,
                                    BinaryKind::Shr => Bop::ShrVar,
                                    _ => Bop::SarVar,
                                };
                                s.flags = Flags::Unknown;
                                Expr::Bin(op, b(a), b(count))
                            }
                        }
                    } else {
                        let c = self.read(s, right, width)?;
                        match kind {
                            BinaryKind::Add => {
                                s.flags = Flags::Add(a.clone(), c.clone());
                                bin(Bop::Add, a, c)
                            }
                            BinaryKind::Sub => {
                                s.flags = Flags::Sub(a.clone(), c.clone());
                                bin(Bop::Sub, a, c)
                            }
                            BinaryKind::Adc | BinaryKind::Sbb => {
                                let carry = cast(
                                    carry(&s.flags).ok_or("ADC/SBB without a known carry")?,
                                    t,
                                    false,
                                );
                                s.flags = Flags::Unknown;
                                if *kind == BinaryKind::Adc {
                                    bin(Bop::Add, bin(Bop::Add, a, c), carry)
                                } else {
                                    bin(Bop::Sub, bin(Bop::Sub, a, c), carry)
                                }
                            }
                            BinaryKind::Imul => {
                                s.flags = Flags::Unknown;
                                bin(Bop::Mul, a, c)
                            }
                            _ => {
                                let op = match kind {
                                    BinaryKind::And => Bop::And,
                                    BinaryKind::Or => Bop::Or,
                                    _ => Bop::Xor,
                                };
                                let r = bin(op, a, c);
                                s.flags = Flags::Logic(r.clone());
                                r
                            }
                        }
                    };
                    self.write(out, s, dst, value)?;
                }
                Op::Unary { kind, dst } => {
                    let width = dst.width().ok_or("unary width")?;
                    let t = Ty::of(width);
                    let a = self.read(s, dst, width)?;
                    let r = match kind {
                        UnaryKind::Inc | UnaryKind::Dec => {
                            let op = if *kind == UnaryKind::Inc {
                                Bop::Add
                            } else {
                                Bop::Sub
                            };
                            let r = bin(op, a, konst(1, t));
                            s.flags = Flags::Result(r.clone(), carry(&s.flags));
                            r
                        }
                        UnaryKind::Neg => {
                            s.flags = Flags::Sub(konst(0, t), a.clone());
                            match a {
                                Expr::Const(v, _) => konst(v.wrapping_neg(), t),
                                Expr::Neg(inner) => *inner,
                                a => Expr::Neg(b(a)),
                            }
                        }
                        UnaryKind::Not => not(a),
                    };
                    self.write(out, s, dst, r)?;
                }
                Op::Compare { left, right, test } => {
                    let width = left.width().ok_or("comparison width")?;
                    let (a, c) = (self.read(s, left, width)?, self.read(s, right, width)?);
                    s.flags = if *test {
                        Flags::Logic(bin(Bop::And, a, c))
                    } else {
                        Flags::Sub(a, c)
                    };
                }
                Op::SetCondition { condition, dst } => {
                    let c = self.condition(s, *condition)?;
                    self.write(out, s, dst, cast(c, Ty::U8, false))?;
                }
                Op::ConditionalMove {
                    condition,
                    dst,
                    src,
                } => {
                    let c = self.condition(s, *condition)?;
                    let new = self.read(s, src, dst.width)?;
                    let old = self.read(s, &Operand::Reg(*dst), dst.width)?;
                    self.write_reg(out, s, *dst, select(c, new, old))?;
                }
                Op::Push { src } => {
                    let v = self.read_val(s, src)?;
                    self.push(out, s, v)?;
                }
                Op::Pop { dst } => {
                    let v = self.pop(s)?;
                    self.write_val(out, s, dst, v)?;
                }
                Op::Leave => {
                    s.regs[4] = s.regs[5].clone();
                    let v = self.pop(s)?;
                    s.regs[5] = v;
                }
                Op::Jump { target } => *pc = *target,
                Op::Branch { condition, target } => {
                    let c = self.condition(s, *condition)?;
                    match c.constant() {
                        Some(1) => *pc = *target,
                        Some(_) => {}
                        None => {
                            if c.opaque() {
                                return Err("a branch on an unknown value".into());
                            }
                            let taken = self.walk(s.clone(), *target)?;
                            let fall = self.walk(s.clone(), next)?;
                            // Paths that differ only in leaving the loop or
                            // repeating it share their statements; the
                            // condition is evaluated before them.
                            let (taken_body, taken_last) = split_last(&taken);
                            let (fall_body, fall_last) = split_last(&fall);
                            let jumps = ["break;", "continue;"];
                            if taken_body == fall_body
                                && taken_last != fall_last
                                && jumps.contains(&taken_last)
                                && jumps.contains(&fall_last)
                            {
                                let c = if taken_last == "break;" { c } else { not(c) };
                                let c = if taken_body.is_empty() {
                                    render(&c)
                                } else {
                                    let n = self.vars;
                                    self.vars += 1;
                                    writeln!(out, "let v{n}: bool = {};", render(&c)).unwrap();
                                    format!("v{n}")
                                };
                                write!(out, "{taken_body}if {c} {{\n    break;\n}}\ncontinue;\n")
                                    .unwrap();
                                return Ok(());
                            }
                            let (c, inside, after) = if taken.len() <= fall.len() {
                                (c, taken, fall)
                            } else {
                                (not(c), fall, taken)
                            };
                            write!(out, "if {} {{\n{}}}\n{after}", render(&c), indent(&inside))
                                .unwrap();
                            return Ok(());
                        }
                    }
                }
                Op::Call { target } => {
                    if s.calls.contains(target) {
                        return Err("recursion".into());
                    }
                    self.push(out, s, Val::Ret(next))?;
                    self.frames += 1;
                    s.frames.push(self.frames);
                    s.calls.push(*target);
                    *pc = *target;
                }
                Op::Return => {
                    let Val::Stack(offset) = s.regs[4] else {
                        return Err("RSP is not a stack address at RET".into());
                    };
                    if s.frames.len() > 1 {
                        let Val::Ret(site) = self.pop(s)? else {
                            return Err("RET to an address no call pushed".into());
                        };
                        s.frames.pop();
                        s.calls.pop();
                        *pc = site;
                        continue;
                    }
                    if offset != 0 {
                        return Err("RET with an unbalanced stack".into());
                    }
                    let width = self
                        .return_kind
                        .integer_width()
                        .ok_or("pointer results keep the guarded form")?;
                    let Val::E(rax) = &s.regs[0] else {
                        return Err("an address result".into());
                    };
                    let result = cast(cast(rax.clone(), Ty::of(width), false), Ty::U64, false);
                    if result.opaque() {
                        return Err("a result that depends on an unknown value".into());
                    }
                    writeln!(out, "return {};", render(&result)).unwrap();
                    return Ok(());
                }
                Op::Abort => {
                    out.push_str("std::process::abort();\n");
                    return Ok(());
                }
            }
        }
    }

    /// Emit the loop headed at `header` and leave `s` as the state after it;
    /// returns the address after the loop, or `None` if it never exits.
    fn structure(
        &mut self,
        s: &mut State,
        header: u64,
        out: &mut String,
    ) -> Result<Option<u64>, String> {
        let body = self.loops[&header].clone();
        let mut exits = HashSet::new();
        let mut regs = Vec::new();
        let mut slots: Vec<(i64, i64)> = Vec::new();
        let function = self.function;
        let mut addresses: Vec<u64> = body.iter().copied().collect();
        addresses.sort_unstable();
        for &address in &addresses {
            let ins = &function.instructions[self.at[&address]];
            let next = ins.address + u64::from(ins.len);
            let (targets, dst): (Vec<u64>, Option<&Operand>) = match &ins.op {
                Op::Call { .. } | Op::Push { .. } | Op::Pop { .. } | Op::Leave => {
                    return Err("a loop that calls, pushes or pops".into());
                }
                Op::Jump { target } => (vec![*target], None),
                Op::Branch { target, .. } => (vec![*target, next], None),
                Op::Return | Op::Abort => (vec![], None),
                Op::Move { dst, .. }
                | Op::Binary { dst, .. }
                | Op::Unary { dst, .. }
                | Op::SetCondition { dst, .. } => (vec![next], Some(dst)),
                Op::MoveZeroExtend { dst, .. }
                | Op::MoveSignExtend { dst, .. }
                | Op::Lea { dst, .. }
                | Op::ConditionalMove { dst, .. } => {
                    regs.push(dst.family);
                    (vec![next], None)
                }
                _ => (vec![next], None),
            };
            exits.extend(targets.into_iter().filter(|t| !body.contains(t)));
            match dst {
                Some(Operand::Reg(r)) => regs.push(r.family),
                Some(Operand::Mem(m)) => {
                    if m.base.is_some_and(|base| {
                        addresses.iter().any(|&a| {
                            let op = &function.instructions[self.at[&a]].op;
                            writes_family(op, base)
                        })
                    }) {
                        return Err("a loop that moves the base of its stack accesses".into());
                    }
                    let slot = (self.stack(s, m)?, i64::from(m.width / 8));
                    if !slots.contains(&slot) {
                        slots.push(slot);
                    }
                }
                _ => {}
            }
        }
        if exits.len() > 1 {
            return Err("a loop with more than one exit".into());
        }
        let exit = exits.into_iter().next();
        regs.sort_unstable();
        regs.dedup();
        if regs.contains(&4) {
            return Err("a loop that moves RSP".into());
        }
        slots.sort_unstable();
        if slots.windows(2).any(|w| w[0].0 + w[0].1 > w[1].0) {
            return Err("a loop with overlapping stack stores".into());
        }
        self.loop_ids += 1;
        let id = self.loop_ids;
        // Each variable with its pre-loop value, or None when that is unknown.
        let mut vars: Vec<(Name, Ty, i64, Option<Expr>)> = Vec::new();
        for &family in &regs {
            let Val::E(e) = &s.regs[family as usize] else {
                return Err("a loop that changes a register holding an address".into());
            };
            vars.push((
                Name::Reg(family, id),
                Ty::U64,
                0,
                Some(e.clone()).filter(|e| !e.opaque()),
            ));
        }
        for &(offset, bytes) in &slots {
            let init = match self.load(s, offset, bytes) {
                Ok(Val::E(e)) if !e.opaque() => Some(e),
                _ => None,
            };
            vars.push((
                Name::Slot(offset, id),
                Ty::of((bytes * 8) as u8),
                bytes,
                init,
            ));
        }
        let mut tainted: Vec<bool> = vars.iter().map(|v| v.3.is_none()).collect();
        let text = loop {
            let mut header_state = s.clone();
            header_state.flags = Flags::Unknown;
            self.enter(&mut header_state, &vars, &tainted);
            self.contexts.push(LoopContext {
                header,
                body: body.clone(),
                exit,
                vars: vars
                    .iter()
                    .zip(&tainted)
                    .filter(|(_, t)| !**t)
                    .map(|(v, _)| (v.0, v.1, v.2))
                    .collect(),
                tainted: Vec::new(),
                fresh: true,
            });
            let result = self.walk(header_state, header);
            let context = self.contexts.pop().unwrap();
            let text = result?;
            let clean: Vec<usize> = (0..vars.len()).filter(|i| !tainted[*i]).collect();
            let newly: Vec<usize> = clean
                .iter()
                .zip(context.tainted.iter().chain(std::iter::repeat(&false)))
                .filter(|(_, t)| **t)
                .map(|(i, _)| *i)
                .collect();
            if newly.is_empty() {
                break text;
            }
            for i in newly {
                tainted[i] = true;
            }
        };
        for ((name, t, _, init), tainted) in vars.iter().zip(&tainted) {
            if !tainted && !self.dead.1.contains(name) {
                let init = init.clone().unwrap();
                writeln!(
                    out,
                    "let mut {name}: {} = {};",
                    t.name(),
                    render(&cast(init, *t, false))
                )
                .unwrap();
            }
        }
        let text = text.strip_suffix("continue;\n").unwrap_or(&text);
        write!(out, "loop {{\n{}}}\n", indent(text)).unwrap();
        self.enter(s, &vars, &tainted);
        s.flags = Flags::Unknown;
        Ok(exit)
    }
    /// Give the loop's variables their names, or unknown values when tainted.
    fn enter(&self, s: &mut State, vars: &[(Name, Ty, i64, Option<Expr>)], tainted: &[bool]) {
        for ((name, t, bytes, _), tainted) in vars.iter().zip(tainted) {
            let value = if *tainted {
                Expr::Opaque(17)
            } else {
                Expr::Mut(*name, *t)
            };
            match name {
                Name::Reg(family, _) => s.regs[*family as usize] = Val::E(value),
                Name::Slot(offset, _) => {
                    let (offset, bytes) = (*offset, *bytes);
                    s.slots.retain(|slot| {
                        slot.offset + slot.bytes <= offset || offset + bytes <= slot.offset
                    });
                    s.slots.push(Slot {
                        offset,
                        bytes,
                        val: Val::E(value),
                    });
                }
            }
        }
    }
    /// Assign the innermost loop's variables their values at a back edge or exit.
    fn assign(&mut self, s: &State, out: &mut String) -> Result<(), String> {
        let vars = self.contexts.last().unwrap().vars.clone();
        let mut tainted = Vec::new();
        let mut pairs = Vec::new();
        for (name, t, bytes) in vars {
            let value = match name {
                Name::Reg(family, _) => s.regs[family as usize].clone(),
                Name::Slot(offset, _) => self.load(s, offset, bytes)?,
            };
            let Val::E(value) = value else {
                return Err("a loop variable that becomes an address".into());
            };
            tainted.push(value.opaque());
            if value != Expr::Mut(name, t) && !self.dead.1.contains(&name) {
                pairs.push((name, value));
            }
        }
        let context = self.contexts.last_mut().unwrap();
        if context.tainted.is_empty() {
            context.tainted = tainted;
        } else {
            for (old, new) in context.tainted.iter_mut().zip(tainted) {
                *old |= new;
            }
        }
        match pairs.len() {
            0 => {}
            1 => writeln!(out, "{} = {};", pairs[0].0, render(&pairs[0].1)).unwrap(),
            _ => writeln!(
                out,
                "({}) = ({});",
                pairs
                    .iter()
                    .map(|p| p.0.to_string())
                    .collect::<Vec<_>>()
                    .join(", "),
                pairs
                    .iter()
                    .map(|p| render(&p.1))
                    .collect::<Vec<_>>()
                    .join(", ")
            )
            .unwrap(),
        }
        Ok(())
    }

    fn condition(&self, s: &State, c: Condition) -> Result<Expr, String> {
        use Condition::*;
        let negated = matches!(
            c,
            NotOverflow
                | AboveOrEqual
                | NotEqual
                | Above
                | NotSign
                | NotParity
                | GreaterOrEqual
                | Greater
        );
        let base = match c {
            NotOverflow => Overflow,
            AboveOrEqual => Below,
            NotEqual => Equal,
            Above => BelowOrEqual,
            NotSign => Sign,
            NotParity => Parity,
            GreaterOrEqual => Less,
            Greater => LessOrEqual,
            c => c,
        };
        let sign = |r: &Expr| cmp(Cop::SLt, r.clone(), konst(0, r.ty()));
        let zero = |r: &Expr| cmp(Cop::Eq, r.clone(), konst(0, r.ty()));
        let parity = |r: &Expr| Expr::Parity(b(cast(r.clone(), Ty::U8, false)));
        let unsupported = || {
            Err(format!(
                "{c:?} after an operation that does not define it exactly"
            ))
        };
        let v = match &s.flags {
            Flags::Unknown => return Err(format!("{c:?} with unknown flags")),
            Flags::Sub(a, x) => {
                let r = bin(Bop::Sub, a.clone(), x.clone());
                match base {
                    Overflow => Expr::Overflow(true, b(a.clone()), b(x.clone())),
                    Below => cmp(Cop::Lt, a.clone(), x.clone()),
                    Equal => cmp(Cop::Eq, a.clone(), x.clone()),
                    BelowOrEqual => cmp(Cop::Le, a.clone(), x.clone()),
                    Sign => sign(&r),
                    Parity => parity(&r),
                    Less => cmp(Cop::SLt, a.clone(), x.clone()),
                    _ => cmp(Cop::SLe, a.clone(), x.clone()),
                }
            }
            Flags::Add(a, x) => {
                let r = bin(Bop::Add, a.clone(), x.clone());
                match base {
                    Overflow => Expr::Overflow(false, b(a.clone()), b(x.clone())),
                    Below => Expr::Carry(b(a.clone()), b(x.clone())),
                    Equal => zero(&r),
                    Sign => sign(&r),
                    Parity => parity(&r),
                    _ => return unsupported(),
                }
            }
            Flags::Logic(r) => match base {
                Overflow | Below => boolean(false),
                Equal | BelowOrEqual => zero(r),
                Sign | Less => sign(r),
                Parity => parity(r),
                _ => cmp(Cop::SLe, r.clone(), konst(0, r.ty())),
            },
            Flags::Result(r, carry) => match (base, carry) {
                (Equal, _) => zero(r),
                (Sign, _) => sign(r),
                (Parity, _) => parity(r),
                (Below, Some(carry)) => carry.clone(),
                _ => return unsupported(),
            },
        };
        Ok(if negated { not(v) } else { v })
    }
}

/// Whether `op` writes register `family`.
fn writes_family(op: &Op, family: u8) -> bool {
    match op {
        Op::Move {
            dst: Operand::Reg(r),
            ..
        }
        | Op::Binary {
            dst: Operand::Reg(r),
            ..
        }
        | Op::Unary {
            dst: Operand::Reg(r),
            ..
        }
        | Op::SetCondition {
            dst: Operand::Reg(r),
            ..
        }
        | Op::Pop {
            dst: Operand::Reg(r),
        } => r.family == family,
        Op::MoveZeroExtend { dst, .. }
        | Op::MoveSignExtend { dst, .. }
        | Op::Lea { dst, .. }
        | Op::ConditionalMove { dst, .. } => dst.family == family,
        Op::Push { .. } | Op::Call { .. } | Op::Return => family == 4,
        Op::Leave => family == 4 || family == 5,
        _ => false,
    }
}

fn carry(flags: &Flags) -> Option<Expr> {
    match flags {
        Flags::Sub(a, x) => Some(cmp(Cop::Lt, a.clone(), x.clone())),
        Flags::Add(a, x) => Some(Expr::Carry(b(a.clone()), b(x.clone()))),
        Flags::Logic(_) => Some(boolean(false)),
        Flags::Result(_, carry) => carry.clone(),
        Flags::Unknown => None,
    }
}

const PRIMARY: u8 = 0;
const UNARY: u8 = 1;
const CAST: u8 = 2;
const SHIFT: u8 = 5;
const AND: u8 = 6;
const XOR: u8 = 7;
const OR: u8 = 8;
const COMPARE: u8 = 9;
const IF: u8 = 12;

fn literal(v: u64) -> String {
    if v < 10 {
        v.to_string()
    } else {
        format!("0x{v:x}")
    }
}

/// `e` as an operand that must bind at least as tightly as `max`. Casts are
/// always parenthesized in operand position: `x as u32 < y` does not parse.
fn operand(e: &Expr, max: u8) -> String {
    let (text, precedence) = rendered(e, false);
    if precedence > max || precedence == CAST {
        format!("({text})")
    } else {
        text
    }
}
/// A method receiver: a primary expression with a typed literal.
fn receiver(e: &Expr) -> String {
    let (text, precedence) = rendered(e, true);
    if precedence > PRIMARY {
        format!("({text})")
    } else {
        text
    }
}
/// A value as its signed type, for a signed comparison or shift.
fn signed(e: &Expr) -> String {
    signed_as(e, false)
}
/// As [`signed`]; a constant is untyped when `plain`, for a comparison's right side.
fn signed_as(e: &Expr, plain: bool) -> String {
    let t = e.ty();
    match e {
        Expr::Const(v, _) => {
            let v = t.sign_extend(*v) as i64;
            let text = if v < 0 {
                format!("-{}", literal(v.unsigned_abs()))
            } else {
                literal(v as u64)
            };
            if plain {
                text
            } else {
                format!("({text}{})", t.signed())
            }
        }
        // A truncation to the signed type needs no unsigned step.
        Expr::Cast(inner, to, false) if inner.ty().bits() > to.bits() => {
            format!("({} as {})", operand(inner, CAST), t.signed())
        }
        e => format!("({} as {})", operand(e, CAST), t.signed()),
    }
}
/// `text` without one pair of enclosing parentheses, for a call argument.
fn bare(text: &str) -> &str {
    let Some(inner) = text.strip_prefix('(').and_then(|t| t.strip_suffix(')')) else {
        return text;
    };
    let mut depth = 0i32;
    for c in inner.chars() {
        depth += match c {
            '(' => 1,
            ')' => -1,
            _ => 0,
        };
        if depth < 0 {
            return text;
        }
    }
    inner
}
fn render(e: &Expr) -> String {
    rendered(e, false).0
}
fn rendered(e: &Expr, typed: bool) -> (String, u8) {
    match e {
        Expr::Arg(n) => (format!("a{n}"), PRIMARY),
        Expr::Opaque(n) => (format!("unknown{n}"), PRIMARY),
        Expr::Var(n, _) => {
            READS.with(|reads| reads.borrow_mut().0.insert(*n));
            (format!("v{n}"), PRIMARY)
        }
        Expr::Mut(name, _) => {
            READS.with(|reads| reads.borrow_mut().1.insert(*name));
            (name.to_string(), PRIMARY)
        }
        Expr::Const(v, Ty::Bool) => ((if *v != 0 { "true" } else { "false" }).into(), PRIMARY),
        Expr::Const(v, t) if typed => (format!("{}{}", literal(*v), t.name()), PRIMARY),
        Expr::Const(v, _) => (literal(*v), PRIMARY),
        Expr::Cast(inner, to, sign) => {
            let from = inner.ty();
            if from == Ty::Bool || (!sign && from.bits() < to.bits()) {
                (format!("{}::from({})", to.name(), render(inner)), PRIMARY)
            } else if *sign && from.bits() < to.bits() {
                (format!("{} as {}", signed(inner), to.name()), CAST)
            } else {
                (format!("{} as {}", operand(inner, CAST), to.name()), CAST)
            }
        }
        Expr::Bin(op, l, r) => {
            let t = l.ty();
            match op {
                Bop::Add | Bop::Sub | Bop::Mul => {
                    let method = match op {
                        Bop::Add => "wrapping_add",
                        Bop::Sub => "wrapping_sub",
                        _ => "wrapping_mul",
                    };
                    (format!("{}.{method}({})", receiver(l), render(r)), PRIMARY)
                }
                Bop::And | Bop::Or | Bop::Xor => {
                    let (symbol, precedence) = match op {
                        Bop::And => ("&", AND),
                        Bop::Or => ("|", OR),
                        _ => ("^", XOR),
                    };
                    (
                        format!(
                            "{} {symbol} {}",
                            operand(l, precedence),
                            operand(r, precedence - 1)
                        ),
                        precedence,
                    )
                }
                Bop::Shl | Bop::Shr => {
                    let symbol = if *op == Bop::Shl { "<<" } else { ">>" };
                    (
                        format!("{} {symbol} {}", operand(l, SHIFT), operand(r, PRIMARY)),
                        SHIFT,
                    )
                }
                Bop::Sar => (
                    format!("({} >> {}) as {}", signed(l), operand(r, PRIMARY), t.name()),
                    CAST,
                ),
                Bop::ShlVar | Bop::ShrVar => {
                    let method = if *op == Bop::ShlVar {
                        "wrapping_shl"
                    } else {
                        "wrapping_shr"
                    };
                    (
                        format!("{}.{method}(u32::from({}))", receiver(l), render(r)),
                        PRIMARY,
                    )
                }
                Bop::SarVar => (
                    format!(
                        "{}.wrapping_shr(u32::from({})) as {}",
                        signed(l),
                        render(r),
                        t.name()
                    ),
                    CAST,
                ),
                Bop::Rotl | Bop::Rotr => {
                    let method = if *op == Bop::Rotl {
                        "rotate_left"
                    } else {
                        "rotate_right"
                    };
                    let count = match &**r {
                        Expr::Const(v, _) => literal(*v),
                        r => format!("u32::from({})", render(r)),
                    };
                    (format!("{}.{method}({count})", receiver(l)), PRIMARY)
                }
            }
        }
        Expr::Not(inner) => (format!("!{}", operand(inner, PRIMARY)), UNARY),
        Expr::Neg(inner) => (format!("{}.wrapping_neg()", receiver(inner)), PRIMARY),
        Expr::Cmp(op, l, r) => {
            let text = if op.signed() {
                format!("{} {} {}", signed(l), op.symbol(), signed_as(r, true))
            } else {
                format!(
                    "{} {} {}",
                    operand(l, SHIFT),
                    op.symbol(),
                    operand(r, SHIFT)
                )
            };
            (text, COMPARE)
        }
        Expr::Select(c, then, otherwise) => (
            format!(
                "if {} {{ {} }} else {{ {} }}",
                render(c),
                rendered(then, true).0,
                rendered(otherwise, true).0
            ),
            IF,
        ),
        Expr::Parity(inner) => (
            format!("{}.count_ones() % 2 == 0", receiver(inner)),
            COMPARE,
        ),
        Expr::Carry(l, r) => (
            format!("{}.overflowing_add({}).1", receiver(l), render(r)),
            PRIMARY,
        ),
        Expr::Overflow(sub, l, r) => {
            let method = if *sub {
                "overflowing_sub"
            } else {
                "overflowing_add"
            };
            (
                format!("{}.{method}({}).1", signed(l), bare(&signed(r))),
                PRIMARY,
            )
        }
    }
}

/// Readable Rust for `function`, exported as `function_name` with the guarded
/// form's SysV signature, or why it keeps the guarded form.
pub fn emit(
    function: &LiftedFunction,
    function_name: &str,
    return_kind: ReturnKind,
) -> Result<String, String> {
    if return_kind == ReturnKind::Pointer {
        return Err("pointer results keep the guarded form".into());
    }
    let mut regs: [Val; 16] = std::array::from_fn(|family| Val::E(Expr::Opaque(family as u8)));
    for (family, arg) in ARGS {
        regs[family as usize] = Val::E(Expr::Arg(arg));
    }
    regs[4] = Val::Stack(0);
    let state = State {
        regs,
        slots: Vec::new(),
        flags: Flags::Unknown,
        frames: vec![0],
        calls: Vec::new(),
    };
    let at: HashMap<u64, usize> = function
        .instructions
        .iter()
        .enumerate()
        .map(|(i, ins)| (ins.address, i))
        .collect();
    let loops: HashMap<u64, std::rc::Rc<HashSet<u64>>> = natural_loops(function, &at)
        .into_iter()
        .map(|(header, body)| (header, std::rc::Rc::new(body)))
        .collect();
    // Each pass leaves out what the previous one found unread; the walk is
    // deterministic, so names and numbers agree between passes.
    let mut dead = (HashSet::new(), HashSet::new());
    let mut body = String::new();
    for _ in 0..4 {
        let mut walker = Walker {
            function,
            at: at.clone(),
            return_kind,
            steps: 0,
            vars: 0,
            frames: 0,
            path: HashSet::new(),
            loops: loops.clone(),
            contexts: Vec::new(),
            loop_ids: 0,
            dead: dead.clone(),
        };
        READS.with(|reads| *reads.borrow_mut() = Default::default());
        body = walker.walk(state.clone(), function.start)?;
        let (vars, names) = READS.with(|reads| std::mem::take(&mut *reads.borrow_mut()));
        let declared = |line: &str, prefix: &str| {
            line.trim_start()
                .strip_prefix(prefix)
                .and_then(|rest| rest.split(':').next())
                .map(str::to_owned)
        };
        let mut new_dead = dead.clone();
        for line in body.lines() {
            if let Some(n) = declared(line, "let v").and_then(|n| n.parse::<u32>().ok()) {
                if !vars.contains(&n) {
                    new_dead.0.insert(n);
                }
            }
        }
        for name in walker_names(&body) {
            if !names.iter().any(|n| n.to_string() == name) {
                if let Some(n) = parse_name(&name) {
                    new_dead.1.insert(n);
                }
            }
        }
        if new_dead == dead {
            break;
        }
        dead = new_dead;
    }
    // A body that never returns is left to the guarded form.
    if !body.contains("return ") {
        return Err("no path returns".into());
    }
    Ok(format!(
        "\n// Readable Rust recovered from 0x{:x}: six unsigned integer SysV arguments.\n#[unsafe(no_mangle)]\npub extern \"C\" fn {function_name}(a0: u64, a1: u64, a2: u64, a3: u64, a4: u64, a5: u64) -> u64 {{\n{}}}\n",
        function.start,
        indent(&body)
    ))
}

/// Loop variables declared in `body`.
fn walker_names(body: &str) -> Vec<String> {
    body.lines()
        .filter_map(|line| line.trim_start().strip_prefix("let mut "))
        .filter_map(|rest| rest.split(':').next())
        .map(str::to_owned)
        .collect()
}
/// The loop variable a declared name stands for.
fn parse_name(text: &str) -> Option<Name> {
    let (base, id) = text.rsplit_once('_')?;
    let id = id.parse().ok()?;
    if let Some(offset) = base.strip_prefix("local_") {
        return Some(Name::Slot(-i64::from_str_radix(offset, 16).ok()?, id));
    }
    let family = REGISTERS.iter().position(|r| *r == base)?;
    Some(Name::Reg(family as u8, id))
}

#[cfg(test)]
mod tests {
    use super::emit;
    use crate::emit::ReturnKind;
    use crate::lift::lift_function;

    fn readable(code: &[u8]) -> Result<String, String> {
        let function = lift_function(code, 0x1000).map_err(|e| e.to_string())?;
        emit(&function, "f", ReturnKind::U64)
    }

    #[test]
    fn straight_line_code_becomes_one_expression() {
        // lea eax, [rdi+rsi]; ret
        let text = readable(&[0x8d, 0x04, 0x37, 0xc3]).unwrap();
        assert!(
            text.contains("return u64::from(a0.wrapping_add(a1) as u32);"),
            "{text}"
        );
    }

    #[test]
    fn branches_become_if_blocks() {
        // cmp rdi, rsi; jb 1f; mov rax, rdi; ret; 1: mov rax, rsi; ret
        let text = readable(&[
            0x48, 0x39, 0xf7, 0x72, 0x04, 0x48, 0x89, 0xf8, 0xc3, 0x48, 0x89, 0xf0, 0xc3,
        ])
        .unwrap();
        assert!(
            text.contains("if a0 < a1 {\n        return a1;\n    }\n    return a0;"),
            "{text}"
        );
    }

    #[test]
    fn loops_carry_mutable_variables() {
        // xor eax, eax; 1: add rax, rdi; dec rsi; jnz 1b; ret
        let text = readable(&[
            0x31, 0xc0, 0x48, 0x01, 0xf8, 0x48, 0xff, 0xce, 0x75, 0xf8, 0xc3,
        ])
        .unwrap();
        assert!(text.contains("let mut rax_1: u64 = 0;"), "{text}");
        assert!(text.contains("loop {"), "{text}");
        assert!(
            text.contains("(rax_1, rsi_1) = (rax_1.wrapping_add(a0), rsi_1.wrapping_sub(1));"),
            "{text}"
        );
        assert!(text.contains("return rax_1;"), "{text}");
    }

    #[test]
    fn stack_spills_are_followed_and_saved_registers_cancel() {
        // push rbx; mov [rsp-8], rdi; mov rbx, [rsp-8]; lea rax, [rbx+1]; pop rbx; ret
        let text = readable(&[
            0x53, 0x48, 0x89, 0x7c, 0x24, 0xf8, 0x48, 0x8b, 0x5c, 0x24, 0xf8, 0x48, 0x8d, 0x43,
            0x01, 0x5b, 0xc3,
        ])
        .unwrap();
        assert!(text.contains("return a0.wrapping_add(1);"), "{text}");
    }

    #[test]
    fn unknown_values_and_other_memory_keep_the_guarded_form() {
        // mov rax, rbx; ret
        assert!(
            readable(&[0x48, 0x89, 0xd8, 0xc3])
                .unwrap_err()
                .contains("unknown")
        );
        // mov rax, [rdi]; ret
        assert!(
            readable(&[0x48, 0x8b, 0x07, 0xc3])
                .unwrap_err()
                .contains("stack address")
        );
    }
}
