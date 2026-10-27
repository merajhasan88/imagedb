; void imdb_lthash_add_avx2(uint16_t *acc, const uint16_t *x)   acc[i] += x[i]  (mod 2^16)
; void imdb_lthash_sub_avx2(uint16_t *acc, const uint16_t *x)   acc[i] -= x[i]  (mod 2^16)
; 1024 lanes = 2048 bytes = 64 ymm registers' worth; unaligned loads/stores.
%include "common.inc"

section .text

%macro LTOP 2                   ; name, vpaddw|vpsubw
FUNC %1
    xor     eax, eax
.loop:
    vmovdqu ymm0, [rdi + rax]
    vmovdqu ymm1, [rdi + rax + 32]
    vmovdqu ymm2, [rdi + rax + 64]
    vmovdqu ymm3, [rdi + rax + 96]
    %2      ymm0, ymm0, [rsi + rax]
    %2      ymm1, ymm1, [rsi + rax + 32]
    %2      ymm2, ymm2, [rsi + rax + 64]
    %2      ymm3, ymm3, [rsi + rax + 96]
    vmovdqu [rdi + rax], ymm0
    vmovdqu [rdi + rax + 32], ymm1
    vmovdqu [rdi + rax + 64], ymm2
    vmovdqu [rdi + rax + 96], ymm3
    add     eax, 128
    cmp     eax, 2048
    jb      .loop
    vzeroupper
    ret
%endmacro

LTOP imdb_lthash_add_avx2, vpaddw
LTOP imdb_lthash_sub_avx2, vpsubw
