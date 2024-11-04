.intel_syntax noprefix # use intel syntax (dest, src) and no prefix (%rax -> rax)

base:
    jmp payload                   # 2 bytes: ab 16


entry_delta:                     # next 8 bytes hold this variable 
.quad 0                          # This value will be patched by the injector (new_entry - original_entry)

message:
    .ascii "....WOODY....\n"

payload:
                                 # save registers
    push rdi                     # argc
    push rsi                     # argv
    push rdx                     # envp
 
    mov rdi, 1                   # stdout
    lea rsi, [rip + message]     # message
    mov rdx, 14                  # length
    mov rax, 1                   # sys_write
    syscall

    mov rax, [rip + entry_delta] # delta between old and new entry (need to use rip-relative addressing otherwise the code will not be position independent => segfault)
    lea r10, [rip + base]        # address of the payload (this code)
    sub r10, rax                 # address of the original entry, working with position independent code

    pop rdx                      # restore registers
    pop rsi
    pop rdi

    jmp r10                      # jump to the original entry
