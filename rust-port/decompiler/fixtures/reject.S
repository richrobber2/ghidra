/* These symbols are never executed. Rejection is a mandatory correctness gate. */
.text
.globl unsupported_call
.type unsupported_call, @function
unsupported_call:
    call .Ltarget
    ret
.size unsupported_call, .-unsupported_call
.Ltarget:
    mov %rdi, %rax
    ret

.globl unsupported_simd
.type unsupported_simd, @function
unsupported_simd:
    pxor %xmm0, %xmm0
    mov %rdi, %rax
    ret
.size unsupported_simd, .-unsupported_simd

.globl unsupported_indirect
.type unsupported_indirect, @function
unsupported_indirect:
    jmp *%rdi
.size unsupported_indirect, .-unsupported_indirect

.globl malformed_truncated
.type malformed_truncated, @function
malformed_truncated:
    .byte 0x48, 0x89
.size malformed_truncated, .-malformed_truncated

.globl malformed_outside
.type malformed_outside, @function
malformed_outside:
    .byte 0xeb, 0x7f, 0xc3
.size malformed_outside, .-malformed_outside

.globl malformed_mid_instruction
.type malformed_mid_instruction, @function
malformed_mid_instruction:
    .byte 0x74, 0x01
    .byte 0x48, 0x89, 0xf8
    .byte 0xc3
.size malformed_mid_instruction, .-malformed_mid_instruction
.section .note.GNU-stack,"",@progbits
