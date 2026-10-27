; void imdb_filter_range_i64_avx2(const int64_t *col, size_t n, int64_t lo, int64_t hi, uint64_t *out)
;   out bit i = (lo <= col[i] <= hi), signed; ceil(n/64) words written, bits >= n zero.
;   rdi = col, rsi = n, rdx = lo, rcx = hi, r8 = out
;
; Four lanes per compare: out-of-range = (lo > x) | (x > hi) via vpcmpgtq;
; vmovmskpd takes the four lane sign bits; sixteen nibbles make one word.
; Only AVX2 is required (no BMI). Values past n are never loaded.
%include "common.inc"

section .text

FUNC imdb_filter_range_i64_avx2
    push    rbx
    vmovq   xmm14, rdx
    vpbroadcastq ymm14, xmm14       ; lo in every lane
    vmovq   xmm15, rcx
    vpbroadcastq ymm15, xmm15       ; hi in every lane
    mov     rbx, rcx                ; hi, scalar, for the tail
    mov     r9, rsi
    shr     r9, 6                   ; number of full 64-value words
    jz      .tail
.word:
    xor     r10d, r10d              ; word under construction
    xor     ecx, ecx                ; bit position of the current nibble
.nib:
    vmovdqu ymm0, [rdi]
    vpcmpgtq ymm1, ymm14, ymm0      ; lo > x
    vpcmpgtq ymm2, ymm0, ymm15      ; x > hi
    vpor    ymm1, ymm1, ymm2
    vmovmskpd eax, ymm1             ; 4 bits: lanes out of range
    xor     eax, 15                 ; -> lanes in range
    shl     rax, cl
    or      r10, rax
    add     rdi, 32
    add     ecx, 4
    cmp     ecx, 64
    jb      .nib
    mov     [r8], r10
    add     r8, 8
    dec     r9
    jnz     .word
.tail:
    mov     r11, rsi
    and     r11, 63                 ; values left over (< 64)
    jz      .done
    xor     r10d, r10d
    xor     ecx, ecx
.t:
    mov     rax, [rdi]
    cmp     rax, rdx
    jl      .skip                   ; x < lo
    cmp     rax, rbx
    jg      .skip                   ; x > hi
    bts     r10, rcx
.skip:
    add     rdi, 8
    inc     ecx
    cmp     ecx, r11d
    jb      .t
    mov     [r8], r10
.done:
    pop     rbx
    vzeroupper
    ret
