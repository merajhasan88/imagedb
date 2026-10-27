; void imdb_sum_masked_i64_avx2(const int64_t *col, const uint64_t *bits, size_t n, int64_t out[2])
;   Exact sum of col[i] where bit i of bits is set, returned as a 128-bit
;   integer (out[0] = low 64 bits, out[1] = high 64 bits, two's complement).
;   rdi = col, rsi = bits, rdx = n, rcx = out
;
; Exactness without 128-bit SIMD: every value is split into
;   lo = x & 0xffffffff   (unsigned, < 2^32)      hi = x >> 32 (signed, 32 bit)
; and the halves are summed in separate 64-bit lanes, which cannot overflow
; for n < 2^32 values. The result is hi_total * 2^32 + lo_total. Unselected
; lanes are zeroed with a mask looked up from their 4 selector bits.
%include "common.inc"

section .rodata
align 32
masks:                                  ; entry m: lane i all-ones iff bit i of m is set
%assign m 0
%rep 16
    dq ((m >> 0) & 1) * -1, ((m >> 1) & 1) * -1, ((m >> 2) & 1) * -1, ((m >> 3) & 1) * -1
%assign m m + 1
%endrep
lo32:
    dq 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff

section .text

FUNC imdb_sum_masked_i64_avx2
    push    rbx
    push    r12
    push    r13
    push    r14
    push    r15
    mov     r15, rcx                    ; out
    mov     r9, rdx                     ; n
    lea     r8, [rel masks]
    vmovdqu ymm13, [rel lo32]
    vpxor   ymm10, ymm10, ymm10         ; lo-half sums
    vpxor   ymm11, ymm11, ymm11         ; hi-half sums
    mov     r11, r9
    shr     r11, 2                      ; groups of 4 values
    xor     r10d, r10d                  ; group index
    test    r11, r11
    jz      .reduce
.grp:
    mov     rax, r10
    shr     rax, 4                      ; selector word = group / 16
    mov     rbx, [rsi + rax * 8]
    mov     ecx, r10d
    and     ecx, 15
    shl     ecx, 2                      ; bit offset of this group in the word
    shr     rbx, cl
    and     ebx, 15
    jz      .next                       ; nothing selected
    shl     ebx, 5                      ; 32-byte table entries
    vmovdqu ymm0, [rdi]
    vpand   ymm0, ymm0, [r8 + rbx]
    vpand   ymm1, ymm0, ymm13           ; lo halves, zero-extended
    vpsrlq  ymm2, ymm0, 32              ; hi half moved to the low dword
    vpsrad  ymm3, ymm0, 31              ; per-dword sign fill
    vpblendd ymm2, ymm2, ymm3, 0xaa     ; upper dword := sign of hi -> sign-extended hi
    vpaddq  ymm10, ymm10, ymm1
    vpaddq  ymm11, ymm11, ymm2
.next:
    add     rdi, 32
    inc     r10
    cmp     r10, r11
    jb      .grp
.reduce:
    vextracti128 xmm0, ymm10, 1
    vpaddq  xmm0, xmm0, xmm10
    vpshufd xmm1, xmm0, 0x4e
    vpaddq  xmm0, xmm0, xmm1
    vmovq   r12, xmm0                   ; lo_total (unsigned)
    vextracti128 xmm0, ymm11, 1
    vpaddq  xmm0, xmm0, xmm11
    vpshufd xmm1, xmm0, 0x4e
    vpaddq  xmm0, xmm0, xmm1
    vmovq   rax, xmm0                   ; hi_total (signed)
    mov     r13, rax                    ; r14:r13 = hi_total << 32 (128-bit)
    shl     r13, 32
    mov     r14, rax
    sar     r14, 32
    add     r13, r12                    ; + lo_total
    adc     r14, 0
    mov     rcx, r9                     ; scalar tail: the last n % 4 values
    and     rcx, 3
    jz      .store
    mov     r10, r9
    and     r10, -4
.tail:
    mov     rax, r10
    shr     rax, 6
    mov     rbx, [rsi + rax * 8]
    mov     rax, r10
    and     eax, 63
    bt      rbx, rax
    jnc     .tskip
    mov     rax, [rdi]
    cqo                                 ; rdx:rax = value sign-extended to 128 bits
    add     r13, rax
    adc     r14, rdx
.tskip:
    add     rdi, 8
    inc     r10
    dec     rcx
    jnz     .tail
.store:
    mov     [r15], r13
    mov     [r15 + 8], r14
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rbx
    vzeroupper
    ret
