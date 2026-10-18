/* Independent image/provenance edge gate. Never execute guard_* natively. */
.text
.macro FUNC name
.globl \name
.type \name, @function
\name:
.endm
.macro END name
.size \name, .-\name
.endm

FUNC edge_image_load8
    and $63, %edi
    lea image_bytes(%rip), %rax
    movzbl (%rax,%rdi), %eax
    ret
END edge_image_load8

FUNC edge_image_load64
    and $31, %edi
    lea image_bytes(%rip), %rax
    mov (%rax,%rdi), %rax
    ret
END edge_image_load64

FUNC edge_image_spill_load
    lea image_bytes(%rip), %rax
    mov %rax, -16(%rsp)
    mov -16(%rsp), %rcx
    and $63, %edi
    movzbl (%rcx,%rdi), %eax
    ret
END edge_image_spill_load

FUNC edge_image_negative_load
    and $31, %edi
    lea image_bytes+32(%rip), %rax
    sub %rdi, %rax
    movzbl (%rax), %eax
    ret
END edge_image_negative_load

FUNC edge_image_pointer_je
    and $63, %edi
    and $63, %esi
    lea image_bytes(%rip), %rax
    lea (%rax,%rdi), %rdx
    lea (%rax,%rsi), %rcx
    cmp %rcx, %rdx
    je .Limage_je_equal
    mov $19, %eax
    ret
.Limage_je_equal:
    mov $77, %eax
    ret
END edge_image_pointer_je

FUNC edge_image_pointer_jne
    and $63, %edi
    and $63, %esi
    lea image_bytes(%rip), %rax
    lea (%rax,%rdi), %rdx
    lea (%rax,%rsi), %rcx
    cmp %rcx, %rdx
    jne .Limage_jne_unequal
    mov $7, %eax
    ret
.Limage_jne_unequal:
    mov $93, %eax
    ret
END edge_image_pointer_jne

FUNC edge_image_pointer_base
    lea image_bytes(%rip), %rax
    ret
END edge_image_pointer_base

FUNC edge_image_pointer_index
    and $63, %edi
    lea image_bytes(%rip), %rax
    add %rdi, %rax
    ret
END edge_image_pointer_index

FUNC edge_image_pointer_spill
    lea image_bytes(%rip), %rax
    mov %rax, -16(%rsp)
    mov -16(%rsp), %rax
    and $63, %edi
    lea (%rax,%rdi), %rax
    ret
END edge_image_pointer_spill

FUNC guard_image_numeric_alias
    mov $0x2000, %eax
    movzbl (%rax), %eax
    ret
END guard_image_numeric_alias

FUNC guard_image_truncate
    lea image_bytes(%rip), %rax
    mov %eax, %eax
    ret
END guard_image_truncate

FUNC guard_image_partial_register
    lea image_bytes(%rip), %rax
    mov $0, %al
    ret
END guard_image_partial_register

FUNC guard_image_numeric_return
    lea image_bytes(%rip), %rax
    ret
END guard_image_numeric_return

FUNC guard_image_write
    lea image_bytes(%rip), %rax
    movb $0x31, (%rax)
    xor %eax, %eax
    ret
END guard_image_write

FUNC guard_image_far_oob
    lea image_bytes(%rip), %rax
    movabs $0x8000000000000000, %rcx
    add %rcx, %rax
    movzbl (%rax), %eax
    ret
END guard_image_far_oob

/* GNU ld's final executable-segment address, with no file-backed byte at it. */
.hidden _etext
FUNC guard_image_cross_end
    lea _etext(%rip), %rax
    mov (%rax), %rax
    ret
END guard_image_cross_end

FUNC guard_image_scalar_pointer_return
    mov %rdi, %rax
    ret
END guard_image_scalar_pointer_return

FUNC guard_image_align_mask
    lea image_bytes+17(%rip), %rax
    and $-16, %rax
    ret
END guard_image_align_mask

FUNC guard_image_pointer_flags
    lea image_bytes(%rip), %rax
    add $1, %rax
    sete %r8b
    movzbl %r8b, %eax
    ret
END guard_image_pointer_flags

FUNC guard_image_cmp_cf
    and $63, %edi
    and $63, %esi
    lea image_bytes(%rip), %rax
    lea (%rax,%rdi), %rdx
    lea (%rax,%rsi), %rcx
    cmp %rcx, %rdx
    setb %r8b
    movzbl %r8b, %eax
    ret
END guard_image_cmp_cf

FUNC guard_image_cmp_of
    and $63, %edi
    and $63, %esi
    lea image_bytes(%rip), %rax
    lea (%rax,%rdi), %rdx
    lea (%rax,%rsi), %rcx
    cmp %rcx, %rdx
    seto %r8b
    movzbl %r8b, %eax
    ret
END guard_image_cmp_of

FUNC guard_image_partial_spill
    lea image_bytes(%rip), %rax
    mov %rax, -16(%rsp)
    movb $0, -13(%rsp)
    mov -16(%rsp), %rax
    ret
END guard_image_partial_spill

FUNC guard_image_split_spill
    lea image_bytes(%rip), %rax
    mov %rax, -16(%rsp)
    mov -16(%rsp), %eax
    mov -12(%rsp), %edx
    shl $32, %rdx
    or %rdx, %rax
    ret
END guard_image_split_spill

FUNC guard_image_stack_pointer_return
    lea -16(%rsp), %rax
    ret
END guard_image_stack_pointer_return

FUNC guard_image_immediate_pointer_return
    mov $0x2000, %eax
    ret
END guard_image_immediate_pointer_return

FUNC guard_image_writable_load
    movzbl image_mutable(%rip), %eax
    ret
END guard_image_writable_load

.section .rodata
.balign 16
.globl image_bytes
.hidden image_bytes
.type image_bytes, @object
image_bytes:
    .byte 3,20,37,54,71,88,105,122,139,156,173,190,207,224,241,2
    .byte 19,36,53,70,87,104,121,138,155,172,189,206,223,240,1,18
    .byte 35,52,69,86,103,120,137,154,171,188,205,222,239,0,17,34
    .byte 51,68,85,102,119,136,153,170,187,204,221,238,255,16,33,50
.size image_bytes, .-image_bytes

.data
.globl image_mutable
.hidden image_mutable
.type image_mutable, @object
image_mutable:
    .byte 91
.size image_mutable, .-image_mutable
.section .note.GNU-stack,"",@progbits
