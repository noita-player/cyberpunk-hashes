PUBLIC trampoline
EXTERN hash_hook:PROC ; our tramp will call this after preserving state

.code

; v1.0.3 looks built for SSE2, change these for AVX
SSE_NUM_REGS TEXTEQU <16>
SSE_REG_SIZE TEXTEQU <16>
SSE_SPACE TEXTEQU %(SSE_NUM_REGS*SSE_REG_SIZE)
savesse MACRO idx
   curreg CATSTR <xmm>, %(idx)
   movaps [rsp+idx*SSE_REG_SIZE], curreg
ENDM
restoresse MACRO idx
   curreg CATSTR <xmm>, %(idx)
   ;varoff TEXTEQU %(SSE_SPACE - (idx*SSE_REG_SIZE))
   movaps curreg, [rsp+(idx*SSE_REG_SIZE)]
ENDM

ALIGNMENT_FLAG TEXTEQU <4142434445464748h>

; sync this to struct CPU_STATE in main.h
saveregs MACRO
    ; save rflags (twice, keep 0x10 alignment)
    pushfq
    pushfq

    ; align stack to 0x10 so movaps doesn't AV. todo: avx512?
    push rax
    mov rax, rsp
    lea rax, [rax+8] ; we modified SP to preserve flags+rax
    and rax, 0Fh
    je noalignrax ; if and got 0, it's aligned

    ; otherwise, align it
    mov rax, ALIGNMENT_FLAG
    xchg qword ptr [rsp], rax
    jmp dosse

    ; restore rax in either case
noalignrax:
    pop rax
    jmp dosse

dosse:
    ; save SSE 
    ; macro'd up in case they move to using ymm or whatever
    sub rsp, SSE_SPACE

    ; repeat/macroidx are evaluated at compile-time
    macroidx = 0
    REPEAT SSE_NUM_REGS
        savesse macroidx;
        macroidx = macroidx + 1;
    ENDM

    ; grab original hook RIP from return addr
    sub rsp, 20h

    IP_OFFSET TEXTEQU %(20h + 8 + SSE_SPACE)

    mov qword ptr [rsp], rax           ; preserve regs
    mov qword ptr [rsp+8], rdx          
    mov rdx, ALIGNMENT_FLAG
    mov rax, QWORD PTR [rsp+IP_OFFSET-8] ; we either have RFLAGS or alignment @ [rip_buffer_size+sse_space]
    cmp rax, rdx
    jne gotrealrip
    mov rax, QWORD PTR [rsp+IP_OFFSET+16] ; if we had to align for SSE, skip the align padding...
    jmp aftergotrip
gotrealrip:
    mov rax, QWORD PTR [rsp+IP_OFFSET+8] ; actual rip here if we didn't align
aftergotrip:
    lea rax, [rax-6]                   ; the retaddr points after the 6 byte call to trampoline, fix that
    mov qword ptr [rsp+18h], rax       ; store it

    mov rax, qword ptr [rsp]          ; restore rax/rdx
    mov rdx, qword ptr [rsp+8]
    add rsp, 18h                      ; restore stack except for original IP + padding, clean that up in restoreregs

    ; save gprs
    push rax    ; registers
    push rbx
    push rcx
    push rdx
    push rbp
    push rsi
    push rdi
    push r8
    push r9
    push r10
    push r11
    push r12
    push r13
    push r14
    push r15
ENDM
restoreregs MACRO
    pop r15
    pop r14
    pop r13
    pop r12
    pop r11
    pop r10
    pop r9
    pop r8
    pop rdi    
    pop rsi    
    pop rbp    
    pop rdx    
    pop rcx
    pop rbx    
    pop rax
    add rsp, 8 ; skip old instruction pointer we stored

    ; sse
    macroidx = 0
    REPEAT SSE_NUM_REGS
        restoresse macroidx;
        macroidx = macroidx + 1;
    ENDM
    add rsp, SSE_SPACE

    ; if this flag is on the stack we had to align
    push rdi
    mov rdi, ALIGNMENT_FLAG
    cmp qword ptr [rsp+8], rdi  ; +8 because we had to preserve rdi..
    jne restore_noalign         ; if it's not the flag, just pop rdi
    pop rdi
    add rsp, 8                  ; if it is, remove it
    jmp restore_after
restore_noalign:
    pop rdi

restore_after:
    popfq
    popfq
ENDM

; we reach here via
; ff 14 xx xx xx xx   call [g_pTrampoline]
trampoline PROC
    ; grab cpu state
    saveregs

    ; pass state to hook
    mov rcx, rsp ; cx dx 8 9
    
    ; let's assume we have some really dumb shit getting called...
    sub rsp, 200h
    call hash_hook
    add rsp, 200h

    restoreregs
    ret
trampoline ENDP
trampoline_end: nop ; for calculating size

END
