// SPDX-License-Identifier: Apache-2.0
// Guarded machine-level Rust support, a line-for-line port of runtime.h for
// the generated Rust backend: same uint64 six-integer SysV model, same value,
// flag and provenance tracking, and the same aborts. Unknown values and
// unsupported memory/provenance never become invented data. This file is
// embedded verbatim in every generated Rust file, so it has no `use` items of
// its own beyond core paths and no crate-level attributes.

/// p=0 is scalar, p=1 is this invocation's stack, p=2 is invalid/partial
/// provenance, and p>=3 is image object p-2. Image x is an object-relative
/// offset, never an ELF address or a reconstructed host pointer.
#[derive(Clone, Copy)]
pub struct RgValue {
    pub x: u64,
    pub k: u64,
    pub p: u32,
}
pub const RG_CF: u32 = 1;
pub const RG_PF: u32 = 2;
pub const RG_ZF: u32 = 4;
pub const RG_SF: u32 = 8;
pub const RG_OF: u32 = 16;
pub const RG_ADD: u32 = 0;
pub const RG_ADC: u32 = 1;
pub const RG_SUB: u32 = 2;
pub const RG_SBB: u32 = 3;
pub const RG_AND: u32 = 4;
pub const RG_OR: u32 = 5;
pub const RG_XOR: u32 = 6;
pub const RG_IMUL: u32 = 7;
pub const RG_SHL: u32 = 8;
pub const RG_SHR: u32 = 9;
pub const RG_SAR: u32 = 10;
pub const RG_ROL: u32 = 11;
pub const RG_ROR: u32 = 12;
pub const RG_STACK_SIZE: usize = 8192;
pub const RG_STACK_BASE: u64 = 0x100000;
pub const RG_ENTRY_SP: u64 = RG_STACK_BASE + RG_STACK_SIZE as u64 / 2 + 8;

pub struct RgState {
    pub r: [RgValue; 16],
    pub mem: [u8; RG_STACK_SIZE],
    pub known: [u8; RG_STACK_SIZE],
    pub provenance: [u16; RG_STACK_SIZE],
    pub pointer_origin: [u32; RG_STACK_SIZE],
    pub flags: u32,
    pub known_flags: u32,
    pub images: &'static [&'static [u8]],
}

impl RgState {
    pub fn new(images: &'static [&'static [u8]]) -> Self {
        RgState {
            r: [RgValue { x: 0, k: 0, p: 0 }; 16],
            mem: [0; RG_STACK_SIZE],
            known: [0; RG_STACK_SIZE],
            provenance: [0; RG_STACK_SIZE],
            pointer_origin: [0; RG_STACK_SIZE],
            flags: 0,
            known_flags: 0,
            images,
        }
    }
}

pub fn rg_fail() -> ! {
    std::process::abort()
}
pub fn rg_mask(w: u32) -> u64 {
    if w != 8 && w != 16 && w != 32 && w != 64 {
        rg_fail();
    }
    if w == 64 { u64::MAX } else { (1u64 << w) - 1 }
}
pub fn rg_const(x: u64) -> RgValue {
    RgValue {
        x,
        k: u64::MAX,
        p: 0,
    }
}
pub fn rg_need(v: RgValue, w: u32) -> u64 {
    let mask = rg_mask(w);
    if v.k & mask != mask {
        rg_fail();
    }
    v.x & mask
}
pub fn rg_num(v: RgValue, w: u32) -> u64 {
    if v.p != 0 {
        rg_fail();
    }
    rg_need(v, w)
}
pub fn rg_image_object_for(s: &RgState, provenance: u32) -> &'static [u8] {
    if provenance < 3 || (provenance - 3) as usize >= s.images.len() {
        rg_fail();
    }
    s.images[(provenance - 3) as usize]
}
pub fn rg_image(s: &RgState, id: u32, offset: u64) -> RgValue {
    if id == 0 || id > u32::MAX - 2 || id as usize > s.images.len() {
        rg_fail();
    }
    let provenance = id + 2;
    let object = rg_image_object_for(s, provenance);
    if offset > object.len() as u64 {
        rg_fail();
    }
    RgValue {
        x: offset,
        k: u64::MAX,
        p: provenance,
    }
}
pub fn rg_pointer_result(s: &RgState, v: RgValue) -> *const u8 {
    let offset = rg_need(v, 64);
    let object = rg_image_object_for(s, v.p);
    if offset > object.len() as u64 {
        rg_fail();
    }
    object.as_ptr().wrapping_add(offset as usize)
}
pub fn rg_reg(s: &RgState, n: usize, w: u32, high: u32) -> RgValue {
    let shift = if high != 0 { 8 } else { 0 };
    let mut v = s.r[n];
    v.x = (v.x >> shift) & rg_mask(w);
    v.k = (v.k >> shift) & rg_mask(w);
    if w != 64 && v.p != 0 {
        v.p = 2;
    }
    v
}
pub fn rg_setreg(s: &mut RgState, n: usize, w: u32, high: u32, v: RgValue) {
    if w == 64 {
        s.r[n] = v;
        return;
    }
    if w == 32 {
        s.r[n] = RgValue {
            x: v.x & u64::from(u32::MAX),
            k: (v.k & u64::from(u32::MAX)) | 0xffff_ffff_0000_0000,
            p: if v.p != 0 { 2 } else { 0 },
        };
        return;
    }
    let shift = if high != 0 { 8 } else { 0 };
    let mask = rg_mask(w) << shift;
    s.r[n].x = (s.r[n].x & !mask) | ((v.x << shift) & mask);
    s.r[n].k = (s.r[n].k & !mask) | ((v.k << shift) & mask);
    if s.r[n].p != 0 || v.p != 0 {
        s.r[n].p = 2;
    }
}
pub fn rg_lea_value(s: &RgState, a: RgValue, index: i32, scale: u32, disp: u64) -> RgValue {
    let b = if index < 0 {
        rg_const(0)
    } else {
        s.r[index as usize]
    };
    if a.p == 2 || b.p == 2 || (a.p != 0 && b.p != 0) || (b.p != 0 && scale != 1) {
        rg_fail();
    }
    RgValue {
        x: rg_need(a, 64)
            .wrapping_add(rg_need(b, 64).wrapping_mul(u64::from(scale)))
            .wrapping_add(disp),
        k: u64::MAX,
        p: if a.p != 0 { a.p } else { b.p },
    }
}
pub fn rg_lea(s: &RgState, base: i32, index: i32, scale: u32, disp: u64) -> RgValue {
    let a = if base < 0 {
        rg_const(0)
    } else {
        s.r[base as usize]
    };
    rg_lea_value(s, a, index, scale, disp)
}
// An absolute ET_EXEC displacement plus a scaled index: the image object comes
// from the displacement, never from the index.
pub fn rg_lea_from(s: &RgState, image: RgValue, index: i32, scale: u32) -> RgValue {
    rg_lea_value(s, image, index, scale, 0)
}
pub fn rg_slot(address: RgValue, w: u32) -> usize {
    let _ = rg_mask(w);
    let a = rg_need(address, 64);
    let length = u64::from(w / 8);
    if address.p != 1 || a < RG_STACK_BASE || a - RG_STACK_BASE > RG_STACK_SIZE as u64 - length {
        rg_fail();
    }
    (a - RG_STACK_BASE) as usize
}
pub fn rg_load(s: &RgState, address: RgValue, w: u32) -> RgValue {
    if address.p >= 3 {
        let _ = rg_mask(w);
        let offset = rg_need(address, 64);
        let n = u64::from(w / 8);
        let object = rg_image_object_for(s, address.p);
        let size = object.len() as u64;
        if offset > size || n > size - offset {
            rg_fail();
        }
        let mut x = 0u64;
        for i in 0..n as usize {
            x |= u64::from(object[offset as usize + i]) << (8 * i);
        }
        return RgValue {
            x,
            k: rg_mask(w),
            p: 0,
        };
    }
    let at = rg_slot(address, w);
    let n = (w / 8) as usize;
    let mut any = false;
    let mut complete = w == 64;
    let origin = s.pointer_origin[at];
    let mut v = RgValue { x: 0, k: 0, p: 0 };
    for i in 0..n {
        v.x |= u64::from(s.mem[at + i]) << (8 * i);
        v.k |= u64::from(s.known[at + i]) << (8 * i);
        any |= s.provenance[at + i] != 0;
        complete &= s.provenance[at + i] as usize == at + 1 && s.pointer_origin[at + i] == origin;
    }
    v.p = if any {
        if complete && (origin == 1 || origin >= 3) {
            origin
        } else {
            2
        }
    } else {
        0
    };
    v
}
pub fn rg_store(s: &mut RgState, address: RgValue, w: u32, v: RgValue) {
    let at = rg_slot(address, w);
    let n = (w / 8) as usize;
    // Caller state and the return-address slot are outside this leaf model.
    if address.x.wrapping_add(n as u64) > RG_ENTRY_SP {
        rg_fail();
    }
    let tag = if v.p == 0 {
        0
    } else if (v.p == 1 || v.p >= 3) && w == 64 {
        (at + 1) as u16
    } else {
        u16::MAX
    };
    for i in 0..n {
        s.mem[at + i] = (v.x >> (8 * i)) as u8;
        s.known[at + i] = (v.k >> (8 * i)) as u8;
        s.provenance[at + i] = tag;
        s.pointer_origin[at + i] = v.p;
    }
}
pub fn rg_bit(s: &mut RgState, bit: u32, value: bool) {
    s.flags = (s.flags & !bit) | if value { bit } else { 0 };
    s.known_flags |= bit;
}
pub fn rg_szp(s: &mut RgState, r: u64, w: u32) {
    let mut x = (r & 255) as u32;
    x ^= x >> 4;
    x ^= x >> 2;
    x ^= x >> 1;
    rg_bit(s, RG_ZF, r == 0);
    rg_bit(s, RG_SF, (r >> (w - 1)) & 1 != 0);
    rg_bit(s, RG_PF, x & 1 == 0);
}
pub fn rg_signed(x: u64, w: u32) -> i128 {
    let x = x & rg_mask(w);
    i128::from(x) - if x >> (w - 1) != 0 { 1i128 << w } else { 0 }
}
pub fn rg_extend(mut v: RgValue, from: u32, to: u32, sign: u32) -> RgValue {
    if v.p != 0 {
        v.p = 2;
        return v;
    }
    let mask = rg_mask(from);
    let target = rg_mask(to);
    v.x &= mask;
    v.k &= mask;
    if sign == 0 {
        v.k |= target & !mask;
    } else if v.k & (1u64 << (from - 1)) != 0 {
        if v.x & (1u64 << (from - 1)) != 0 {
            v.x |= target & !mask;
        }
        v.k |= target & !mask;
    }
    v
}
pub fn rg_alu(s: &mut RgState, op: u32, av: RgValue, bv: RgValue, w: u32) -> RgValue {
    let shift = (RG_SHL..=RG_ROR).contains(&op);
    let mask = rg_mask(w);
    let a = rg_need(av, w);
    let b = rg_need(bv, if shift { 8 } else { w });
    let mut r: u64;
    if av.p != 0 || bv.p != 0 {
        if w != 64 || av.p == 2 || bv.p == 2 {
            rg_fail();
        }
        let pointer;
        if op == RG_ADD && (av.p == 0 || bv.p == 0) {
            r = a.wrapping_add(b);
            pointer = if av.p != 0 { av.p } else { bv.p };
        } else if op == RG_SUB && av.p != 0 && bv.p == 0 {
            r = a.wrapping_sub(b);
            pointer = av.p;
        } else if op == RG_SUB && av.p != 0 && av.p == bv.p {
            r = a.wrapping_sub(b);
            pointer = 0;
        } else if op == RG_AND
            && av.p == 1
            && bv.p == 0
            && !b <= 15
            && (!b & (!b).wrapping_add(1)) == 0
        {
            r = a & b;
            pointer = 1;
        } else {
            rg_fail();
        }
        s.known_flags = 0;
        return RgValue {
            x: r,
            k: u64::MAX,
            p: pointer,
        };
    }
    if shift {
        let count = (b as u32) & if w == 64 { 63 } else { 31 };
        if op == RG_ROL || op == RG_ROR {
            let effective = count % w;
            if effective != 0 {
                r = if op == RG_ROL {
                    (a << effective) | (a >> (w - effective))
                } else {
                    (a >> effective) | (a << (w - effective))
                };
                r &= mask;
            } else {
                r = a;
            }
            if count != 0 {
                let bit = if op == RG_ROL { r & 1 } else { (r >> (w - 1)) & 1 };
                rg_bit(s, RG_CF, bit != 0);
            }
            if count == 1 {
                let bit = if op == RG_ROL {
                    ((r >> (w - 1)) ^ u64::from(s.flags & RG_CF)) & 1
                } else {
                    ((r >> (w - 1)) ^ (r >> (w - 2))) & 1
                };
                rg_bit(s, RG_OF, bit != 0);
            } else if count != 0 {
                s.known_flags &= !RG_OF;
            }
            return rg_const(r);
        }
        if count == 0 {
            return rg_const(a);
        }
        if op == RG_SHL {
            r = if count >= w { 0 } else { (a << count) & mask };
        } else if op == RG_SHR {
            r = if count >= w { 0 } else { a >> count };
        } else {
            let sign = (a >> (w - 1)) & 1 != 0;
            r = if count >= w {
                if sign { mask } else { 0 }
            } else {
                (a >> count) | if sign { mask ^ (mask >> count) } else { 0 }
            };
        }
        rg_szp(s, r, w);
        if op == RG_SAR {
            let at = if count >= w { w - 1 } else { count - 1 };
            rg_bit(s, RG_CF, (a >> at) & 1 != 0);
        } else if count < w {
            let bit = if op == RG_SHL {
                a >> (w - count)
            } else {
                a >> (count - 1)
            };
            rg_bit(s, RG_CF, bit & 1 != 0);
        } else {
            s.known_flags &= !RG_CF;
        }
        if count == 1 {
            let bit = if op == RG_SHL {
                ((r >> (w - 1)) ^ u64::from(s.flags & RG_CF)) & 1
            } else if op == RG_SHR {
                (a >> (w - 1)) & 1
            } else {
                0
            };
            rg_bit(s, RG_OF, bit != 0);
        } else {
            s.known_flags &= !RG_OF;
        }
        return rg_const(r & mask);
    }
    if op == RG_AND || op == RG_OR || op == RG_XOR {
        r = (if op == RG_AND {
            a & b
        } else if op == RG_OR {
            a | b
        } else {
            a ^ b
        }) & mask;
        rg_szp(s, r, w);
        rg_bit(s, RG_CF, false);
        rg_bit(s, RG_OF, false);
    } else if op == RG_IMUL {
        let p = rg_signed(a, w) * rg_signed(b, w);
        let limit = 1i128 << (w - 1);
        r = ((u128::from(a) * u128::from(b)) as u64) & mask;
        s.known_flags &= !(RG_ZF | RG_SF | RG_PF);
        rg_bit(s, RG_CF, p < -limit || p >= limit);
        rg_bit(s, RG_OF, p < -limit || p >= limit);
    } else {
        let mut carry = 0u64;
        if op == RG_ADC || op == RG_SBB {
            if s.known_flags & RG_CF == 0 {
                rg_fail();
            }
            carry = u64::from(s.flags & RG_CF != 0);
        }
        let signed_result;
        if op == RG_ADD || op == RG_ADC {
            let wide = u128::from(a) + u128::from(b) + u128::from(carry);
            r = (wide as u64) & mask;
            rg_bit(s, RG_CF, (wide >> w) & 1 != 0);
            signed_result = rg_signed(a, w) + rg_signed(b, w) + i128::from(carry);
        } else if op == RG_SUB || op == RG_SBB {
            r = a.wrapping_sub(b).wrapping_sub(carry) & mask;
            rg_bit(s, RG_CF, u128::from(a) < u128::from(b) + u128::from(carry));
            signed_result = rg_signed(a, w) - rg_signed(b, w) - i128::from(carry);
        } else {
            rg_fail();
        }
        let limit = 1i128 << (w - 1);
        rg_bit(
            s,
            RG_OF,
            signed_result < -limit || signed_result >= limit,
        );
        rg_szp(s, r, w);
    }
    rg_const(r)
}
/// Same-object pointer equality is independent of the unknown image load base.
/// Keep every other CMP flag unknown: subtraction alone does not establish the
/// address-dependent flags of the original machine pointers.
pub fn rg_compare(s: &mut RgState, a: RgValue, b: RgValue, w: u32) {
    if w == 64 && a.p >= 3 && a.p == b.p {
        let _ = rg_image_object_for(s, a.p);
        let x = rg_need(a, 64);
        let y = rg_need(b, 64);
        s.known_flags = 0;
        rg_bit(s, RG_ZF, x == y);
        return;
    }
    let _ = rg_alu(s, RG_SUB, a, b, w);
}
pub fn rg_unary(s: &mut RgState, op: u32, mut v: RgValue, w: u32) -> RgValue {
    if op == 3 {
        if v.p != 0 {
            rg_fail();
        }
        v.x = !v.x & rg_mask(w);
        return v;
    }
    let cf = s.flags & RG_CF;
    let ck = s.known_flags & RG_CF;
    let result = if op == 2 {
        rg_alu(s, RG_SUB, rg_const(0), v, w)
    } else {
        rg_alu(s, if op == 0 { RG_ADD } else { RG_SUB }, v, rg_const(1), w)
    };
    if op != 2 {
        s.flags = (s.flags & !RG_CF) | cf;
        s.known_flags = (s.known_flags & !RG_CF) | ck;
    }
    result
}
pub fn rg_condition(s: &RgState, condition: u32) -> bool {
    let need = match condition {
        0 | 1 => RG_OF,
        2 | 3 => RG_CF,
        4 | 5 => RG_ZF,
        6 | 7 => RG_CF | RG_ZF,
        8 | 9 => RG_SF,
        10 | 11 => RG_PF,
        12 | 13 => RG_SF | RG_OF,
        _ => RG_ZF | RG_SF | RG_OF,
    };
    if s.known_flags & need != need {
        rg_fail();
    }
    let cf = s.flags & RG_CF != 0;
    let pf = s.flags & RG_PF != 0;
    let zf = s.flags & RG_ZF != 0;
    let sf = s.flags & RG_SF != 0;
    let of = s.flags & RG_OF != 0;
    match condition {
        0 => of,
        1 => !of,
        2 => cf,
        3 => !cf,
        4 => zf,
        5 => !zf,
        6 => cf || zf,
        7 => !cf && !zf,
        8 => sf,
        9 => !sf,
        10 => pf,
        11 => !pf,
        12 => sf != of,
        13 => sf == of,
        14 => zf || sf != of,
        15 => !zf && sf == of,
        _ => rg_fail(),
    }
}
