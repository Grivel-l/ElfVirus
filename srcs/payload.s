[bits 64]

section .text
  push rbp
  mov rbp, rsp
  getDataSectionHeader:
    push rbx
    mov rax, rdi
    add rax, 0x28 ; e_shoff
    mov rax, [rax]
    mov rbx, rdi
    add rbx, rax  ; pointer
    mov rax, rdi
    add rax, 0x3e ; e_shstrndx
    xor rcx, rcx
    mov cx, [rax]
    xor rax, rax
    mov ax, cx
    xor rcx, rcx
    mov cl, 64
    mul rcx
    mov rcx, rbx
    add rcx, rax  ; shstrHeader
    pop rbx
  int3
  pop rbp
