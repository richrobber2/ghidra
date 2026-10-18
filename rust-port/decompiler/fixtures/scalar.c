/* Fixed, bounded scalar x86-64 validation corpus. Not performance evidence. */
#include <stdint.h>
#define F __attribute__((noinline, visibility("default"))) uint64_t
#define ARGS uint64_t a, uint64_t b, uint64_t c, uint64_t d, uint64_t e, uint64_t f

F add_mix(ARGS) {
    return ((a + b) ^ (c + UINT64_C(0x9e3779b97f4a7c15))) + (d ^ e) + f;
}
F sub_borrow(ARGS) {
    uint64_t x = a - b;
    return x - c + (a < b) + (d <= e) + f;
}
F bit_logic(ARGS) {
    return ((a & b) | (c ^ d)) ^ (~e & f);
}
F shifts64(ARGS) {
    return (a << (b & 63)) ^ (c >> (d & 63)) ^ (e + f);
}
F rotate64(ARGS) {
    uint64_t n = b & 63;
    return ((a << n) | (a >> ((-n) & 63))) ^ c ^ d ^ e ^ f;
}
F multiply64(ARGS) {
    return a * b + c * UINT64_C(37) - d * e + f;
}
F select_unsigned(ARGS) {
    uint64_t x = a < b ? c : d;
    return x + (e >= f ? a : b);
}
F select_signed(ARGS) {
    uint64_t x = (int64_t)a < (int64_t)b ? c : d;
    return x ^ ((int64_t)e >= (int64_t)f ? a : b);
}
F minmax_u32(ARGS) {
    uint32_t x = (uint32_t)a, y = (uint32_t)b;
    uint32_t lo = x < y ? x : y;
    uint32_t hi = (uint32_t)c > (uint32_t)d ? (uint32_t)c : (uint32_t)d;
    return (uint64_t)(uint32_t)(lo + hi + (uint32_t)e) ^ f;
}
F signed32_branch(ARGS) {
    uint32_t x = (uint32_t)a, y = (uint32_t)b;
    if ((int32_t)x <= (int32_t)y) {
        return (uint64_t)(uint32_t)(x + (uint32_t)c) + d;
    }
    return (uint64_t)(uint32_t)(y - (uint32_t)e) ^ f;
}
F loop_accumulate(ARGS) {
    uint64_t n = (a & 15) + 1, result = b;
    for (uint64_t i = 0; i < n; ++i) {
        result = (result ^ (c + i)) + d;
    }
    return result ^ e ^ f;
}
F loop_xor(ARGS) {
    uint64_t n = (a & 7) + 1, result = b;
    while (n != 0) {
        result = (result << 1) ^ (c + n) ^ (result >> 3);
        --n;
    }
    return result + d + e + f;
}
F stack_spill(ARGS) {
    volatile uint64_t x = a + b;
    volatile uint64_t y = c ^ d;
    volatile uint64_t z = e - f;
    x = x ^ y;
    y = y + z;
    return x + y + z;
}
F zero_extend32(ARGS) {
    uint32_t x = (uint32_t)a + (uint32_t)b;
    x ^= (uint32_t)c;
    x = (x << (d & 31)) | (x >> ((-(uint32_t)d) & 31));
    return (uint64_t)x + e - f;
}
