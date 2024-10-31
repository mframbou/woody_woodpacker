.intel_syntax noprefix # use intel syntax (dest, src) and no prefix (%rax -> rax)

base:
    jmp past

message:
    .ascii "Test\n"

past:
    push rdi                   /* Preserve registers */
    push rsi                   /*   ... */
    push rdx                   /*   ... */

    mov rdi, 1                    # STDOUT file descriptor
    lea rsi, [rip + message]      # Pointer to message string
    mov rdx, 5                    # Message size
    mov rax, 1                    # Write syscall number
    syscall                       # Execute system call
    mov rax, 0x00001060   # old entry
    mov rbx, 0x00001175   # new entry
    sub rbx, rax
    lea r10, [rip + base]         # Get vaddr of the stager
    sub r10, rbx                  # Subtract the delta from vaddr of the stager to get the vaddr of real entry

    pop rdx                    /* Restore registers */
    pop rsi                    /*   ... */
    pop rdi                    /*   ... */

    jmp r10