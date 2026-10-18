/* Fixed ISA edge corpus. Original and generated code run only in bounded
 * fixture children. Guard cases intentionally do not have numeric outputs. */
.text
.macro FUNC name
.globl \name
.type \name, @function
\name:
.endm
.macro END name
.size \name, .-\name
.endm

FUNC edge_adc_flags
    mov %rdi, %rax
    mov %rdx, %rcx
    and $1, %ecx
    neg %rcx
    adc %rsi, %rax
    seto %cl
    setb %dl
    movzbl %cl, %ecx
    movzbl %dl, %edx
    shl $63, %rcx
    shl $62, %rdx
    xor %rcx, %rax
    xor %rdx, %rax
    ret
END edge_adc_flags

FUNC edge_sbb_flags
    mov %rdi, %rax
    mov %rdx, %rcx
    and $1, %ecx
    neg %rcx
    sbb %rsi, %rax
    seto %cl
    setb %dl
    movzbl %cl, %ecx
    movzbl %dl, %edx
    shl $63, %rcx
    shl $62, %rdx
    xor %rcx, %rax
    xor %rdx, %rax
    ret
END edge_sbb_flags

FUNC edge_partial_bytes
    mov %rdi, %rax
    mov %rsi, %rcx
    mov %cl, %ah
    mov %dl, %al
    ret
END edge_partial_bytes

FUNC edge_partial_word
    mov %rdi, %rax
    mov %si, %ax
    ret
END edge_partial_word

FUNC edge_cmov32
    mov %rdi, %rax
    test %rdx, %rdx
    cmovz %esi, %eax
    ret
END edge_cmov32

FUNC edge_shift_zero_zf
    mov %rdi, %rax
    mov %rsi, %rcx
    cmp %rdx, %r8
    shl %cl, %rax
    setz %dl
    movzbl %dl, %edx
    xor %rdx, %rax
    ret
END edge_shift_zero_zf

FUNC edge_shift_zero_cf
    mov %rdi, %rax
    mov %rsi, %rcx
    cmp %rdx, %r8
    shr %cl, %rax
    setb %dl
    movzbl %dl, %edx
    xor %rdx, %rax
    ret
END edge_shift_zero_cf

FUNC edge_sar64
    mov %rdi, %rax
    mov %rsi, %rcx
    sar %cl, %rax
    ret
END edge_sar64

FUNC edge_rotate8_cf
    mov %rdi, %rax
    mov %rsi, %rcx
    cmp %rdx, %r8
    rol %cl, %al
    setb %dl
    movzbl %al, %eax
    movzbl %dl, %edx
    shl $8, %rdx
    or %rdx, %rax
    ret
END edge_rotate8_cf

FUNC edge_rotate64_cf
    mov %rdi, %rax
    mov %rsi, %rcx
    cmp %rdx, %r8
    ror %cl, %rax
    setb %dl
    movzbl %dl, %edx
    xor %rdx, %rax
    ret
END edge_rotate64_cf

FUNC edge_shift8_value
    mov %rdi, %rax
    mov %rsi, %rcx
    shl %cl, %al
    movzbl %al, %eax
    ret
END edge_shift8_value

FUNC edge_imul_flags
    mov %rdi, %rax
    imul %rsi, %rax
    seto %dl
    setb %cl
    movzbl %dl, %edx
    movzbl %cl, %ecx
    shl $63, %rdx
    shl $62, %rcx
    xor %rdx, %rax
    xor %rcx, %rax
    ret
END edge_imul_flags

FUNC edge_push_pop_unknown
    push %rbx
    mov %rdi, %rbx
    mov %rbx, %rax
    pop %rbx
    ret
END edge_push_pop_unknown

FUNC edge_sbb_unknown_self
    cmp %rdi, %rsi
    sbb %rax, %rax
    ret
END edge_sbb_unknown_self

FUNC edge_inc_preserves_cf
    cmp %rdi, %rsi
    mov %rdx, %rax
    inc %rax
    setb %cl
    movzbl %cl, %ecx
    xor %rcx, %rax
    ret
END edge_inc_preserves_cf

FUNC edge_sign8_to32
    movsbl %dil, %eax
    ret
END edge_sign8_to32

FUNC edge_sign32_to64
    movslq %edi, %rax
    ret
END edge_sign32_to64

FUNC guard_stack_escape
    mov %rsp, %rax
    ret
END guard_stack_escape

FUNC guard_undefined_entry_flags
    seto %al
    movzbl %al, %eax
    ret
END guard_undefined_entry_flags

FUNC guard_undefined_imul_zf
    mov %rdi, %rax
    imul %rsi, %rax
    setz %al
    movzbl %al, %eax
    ret
END guard_undefined_imul_zf

FUNC guard_undefined_shift_of
    mov %rdi, %rax
    shl $2, %rax
    seto %al
    movzbl %al, %eax
    ret
END guard_undefined_shift_of

FUNC guard_stack_return_corrupt
    movq $0, (%rsp)
    mov $1, %eax
    ret
END guard_stack_return_corrupt

FUNC guard_stack_align32
    mov %rsp, %rbp
    and $-32, %rsp
    mov $1, %eax
    mov %rbp, %rsp
    ret
END guard_stack_align32

FUNC guard_stack_numeric_alias
    mov $0x101008, %rsp
    mov (%rsp), %rax
    ret
END guard_stack_numeric_alias
.section .note.GNU-stack,"",@progbits
