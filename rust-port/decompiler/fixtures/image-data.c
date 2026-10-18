/* Fixed read-only image-memory corpus. Semantic validation, not a benchmark. */
#include <stdint.h>
#include <stddef.h>
#define API __attribute__((noinline, visibility("default")))
#define F API uint64_t
#define P API const unsigned char *
#define ARGS uint64_t a, uint64_t b, uint64_t c, uint64_t d, uint64_t e, uint64_t f

/* Kept local so PIC code does not require dynamic GOT relocations. */
__attribute__((used)) static const unsigned char image_bytes[32] = {
    0x00, 0xff, 0x81, 0x7e, 0x19, 0xa4, 0x55, 0xc3,
    0x02, 0x61, 0xe7, 0x34, 0xb8, 0x0d, 0x9a, 0x46,
    0xf1, 0x28, 0x63, 0xbd, 0x05, 0x92, 0x4a, 0xd6,
    0x73, 0x0b, 0xe0, 0x5c, 0xa9, 0x31, 0x87, 0x6f
};
__attribute__((used)) static const uint16_t image_words[8] = {
    0x0000, 0xffff, 0x8001, 0x7ffe, 0x19a4, 0x55c3, 0xe734, 0xb80d
};
__attribute__((used)) static const uint32_t image_dwords[8] = {
    UINT32_C(0), UINT32_C(0xffffffff), UINT32_C(0x80000001), UINT32_C(0x7ffffffe),
    UINT32_C(0x19a455c3), UINT32_C(0xe734b80d), UINT32_C(0x9a46f128), UINT32_C(0x63bd0592)
};
__attribute__((used)) static const uint64_t image_qwords[8] = {
    UINT64_C(0), UINT64_C(0xffffffffffffffff), UINT64_C(0x8000000000000001),
    UINT64_C(0x7ffffffffffffffe), UINT64_C(0x19a455c3e734b80d),
    UINT64_C(0x9a46f12863bd0592), UINT64_C(0x4ad6730be05ca931), UINT64_C(0x876f028161e734b8)
};
static volatile uint64_t image_writable = UINT64_C(0x8192a3b4c5d6e7f8);

F image_u8(ARGS) { return image_bytes[a & 31] + b; }
F image_u16(ARGS) { return image_words[a & 7] ^ b; }
F image_u32(ARGS) { return image_dwords[a & 7] + b; }
F image_u64(ARGS) { return image_qwords[a & 7] ^ b; }
F image_pair(ARGS) { return image_bytes[a & 31] + ((uint64_t)image_words[b & 7] << 8) + c; }
F image_loop(ARGS) {
    uint64_t sum = b;
    for (uint64_t i = 0; i < (a & 7) + 1; ++i) sum += image_bytes[i];
    return sum;
}
P image_pointer_base(ARGS) { return image_bytes; }
P image_pointer_offset(ARGS) { return image_bytes + (a & 15); }
P image_pointer_spill(ARGS) {
    const unsigned char * volatile p = image_bytes + (a & 15);
    return p;
}
F image_same_object_delta(ARGS) {
    const unsigned char * volatile p = image_bytes + (a & 15);
    const unsigned char * volatile q = image_bytes + (b & 15);
    return (uint64_t)(q - p);
}

/* Rejected statically, or guarded at execution. Never execute these originals. */
F image_guard_writable(ARGS) { return image_writable + a; }
F image_guard_external(ARGS) { return *(const unsigned char *)(uintptr_t)a; }

/* Assembly makes the exact invalid state independent of C UB/optimization. */
__asm__(
    ".text\n"
    ".globl image_guard_write\n.type image_guard_write,@function\n"
    "image_guard_write:\nlea image_bytes(%rip),%rax\nmovb %dil,(%rax)\nxor %eax,%eax\nret\n"
    ".size image_guard_write,.-image_guard_write\n"
    ".globl image_guard_partial\n.type image_guard_partial,@function\n"
    "image_guard_partial:\nlea image_bytes(%rip),%rax\nmovq $0,-8(%rsp)\n"
    "movl %eax,-8(%rsp)\nmovq -8(%rsp),%rax\nret\n"
    ".size image_guard_partial,.-image_guard_partial\n"
    ".globl image_guard_oob\n.type image_guard_oob,@function\n"
    "image_guard_oob:\nlea image_bytes(%rip),%rax\nmovabs $0x4000000000,%rcx\n"
    "add %rcx,%rax\nmovzbl (%rax),%eax\nret\n"
    ".size image_guard_oob,.-image_guard_oob\n"
    ".section .note.GNU-stack,\"\",@progbits\n"
    ".text\n"
);
