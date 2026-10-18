//! Four fixed optimized-Rust demonstrations, using a six-u64 System V ABI.
//! All arithmetic has explicit wrapping semantics. These are leaf kernels,
//! not a claim that the decompiler supports Rust allocation/panics/trait calls.

#[unsafe(no_mangle)]
pub extern "C" fn rust_arithmetic(a: u64, b: u64, c: u64, d: u64, e: u64, f: u64) -> u64 {
    a.wrapping_add(b)
        .wrapping_mul(c.wrapping_add(37))
        .wrapping_sub(d ^ e)
        .wrapping_add(f)
}

#[unsafe(no_mangle)]
pub extern "C" fn rust_rotate(a: u64, b: u64, c: u64, d: u64, e: u64, f: u64) -> u64 {
    a.rotate_left((b & 63) as u32)
        .wrapping_add(c.rotate_right((d & 63) as u32))
        ^ e
        ^ f
}

#[unsafe(no_mangle)]
pub extern "C" fn rust_branch(a: u64, b: u64, c: u64, d: u64, e: u64, f: u64) -> u64 {
    if a < b { c.wrapping_add(d) } else { e.wrapping_sub(f) }
}

#[unsafe(no_mangle)]
pub extern "C" fn rust_loop(a: u64, b: u64, c: u64, d: u64, e: u64, f: u64) -> u64 {
    let mut n = (a & 15) + 1;
    let mut value = b;
    while n != 0 {
        value = (value ^ c.wrapping_add(n)).wrapping_add(d);
        n -= 1;
    }
    value ^ e ^ f
}
