.intel_syntax noprefix # use intel syntax (dest, src) and no prefix (%rax -> rax)

base:
    jmp decrypt_data             # 2 bytes: eb 16
# we cannot directly jump to payload since its too bigits not short jmp (EB) but near jmp (E9) which doesnt work since its relative to the next instruction

# VARIABLES
entry_delta:                     # next 8 bytes hold this variable 
    .8byte 0                     # This value will be patched by the injector (new_entry - original_entry)

decryption_key:                  # 8 bit key
    .8byte 0                     # This value will be patched by the injector

decrypt_size:                    # length of section to decrypt
    .8byte 0                     # This value will be patched by the injector

decrypt_offset:                  # offset of section to decrypt
    .8byte 0                     # This value will be patched by the injector


# DECRYPTION
decrypt_data:
    push rax
    push rbx
    push rcx
    push rdx
    push r8
    push r9
    push r10
    push rsi
    push rdi
                                    # Decrypt data at decrypt_offset of size decrypt_size with decryption_key TEA algorithm
                                    # simple XOR decryption
    mov rax, [rip + decrypt_size]
    mov r8, [rip + decrypt_offset]
    lea r9, [rip + base]            # address of the base of the code (find payload REAL base address)
    add r8, r9                      # real address of .text section (payload REAL base address + decrypt_offset)
    mov rbx, r8                     # real address of the data to decrypt (.text section address)
    mov rcx, 0x42 # [rip + decryption_key] TODO debug why variable isnt working 
    mov rdx, 0                      # counter (i)

    push rax                       # save before syscall
    push rbx
    push rcx
    push rdx


    mov r10, rax                    # copy of size of the section to decrypt (since we need to use rax for syscall)
    mov rax, 10                     # call mprotect (syscall 10) to make the section Read-Write-Execute, after decryption reset it back to Read-Execute
    mov rdi, rbx                    # address of the section to decrypt
    mov rsi, r10                    # size of the section to decrypt
    mov rdx, 7                      # RWX
    syscall

    pop rdx                        # restore after syscall
    pop rcx
    pop rbx
    pop rax



decrypt_loop:
    cmp rdx, rax
    jge decrypt_end             # if i >= size then exit loop

    mov rdi, rbx                # address of the section to decrypt
    add rdi, rdx                # address of the byte to decrypt (decrypt_offset + i)
    movzx rsi, byte ptr [rdi]   # byte to decrypt
    mov r8, rcx                 # key

    xor rsi, r8                 # decrypt byte
    mov [rdi], sil              # save decrypted byte
    inc rdx                     # i++

    jmp decrypt_loop


decrypt_end:
    mov rax, 10                 # call mprotect (syscall 10) to make the section Read-Execute
    mov rdi, rbx                # address of the section to decrypt
    mov rsi, r10                # size of the section to decrypt
    mov rdx, 5                  # RX
    syscall
    
    pop rdi
    pop rsi
    pop r10
    pop r9
    pop r8
    pop rdx
    pop rcx
    pop rbx
    pop rax

    jmp payload                  # jump to the payload


# PRINT MESSAGE
message:
    .ascii "....WOODY....\n"

payload:
                                 # save registers
    push rdi                     # argc
    push rsi                     # argv
    push rdx                     # envp

    push rax
 
    mov rdi, 1                   # stdout
    lea rsi, [rip + message]     # message
    mov rdx, 14                  # length
    mov rax, 1                   # sys_write
    syscall

    mov rax, [rip + entry_delta] # delta between old and new entry (need to use rip-relative addressing otherwise the code will not be position independent => segfault)
    lea r10, [rip + base]        # address of the payload (this code)
    sub r10, rax                 # address of the original entry, working with position independent code

    pop rax

    pop rdx                      # restore registers
    pop rsi
    pop rdi

    jmp r10                      # jump to the original entry
