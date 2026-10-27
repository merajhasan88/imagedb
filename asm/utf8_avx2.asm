; size_t imdb_ascii_prefix_avx2(const uint8_t *p, size_t n)
;   Length of the prefix made of bytes 0x01..0x7F (ASCII without NUL): the
;   fast path of strict UTF-8 validation. Bytes are signed-compared with zero,
;   so NUL (== 0) and any byte >= 0x80 (< 0) stop the prefix. Only whole
;   32-byte blocks are loaded; the tail is byte-at-a-time.
;   rdi = p, rsi = n  ->  rax
%include "common.inc"

section .text

FUNC imdb_ascii_prefix_avx2
    xor     eax, eax
    vpxor   ymm1, ymm1, ymm1
    mov     rcx, rsi
    and     rcx, -32                    ; end of the last whole block
.loop:
    cmp     rax, rcx
    jae     .tail
    vmovdqu ymm0, [rdi + rax]
    vpcmpgtb ymm2, ymm0, ymm1           ; byte > 0 (signed) <=> 0x01..0x7F
    vpmovmskb edx, ymm2
    cmp     edx, -1
    jne     .found
    add     rax, 32
    jmp     .loop
.found:
    not     edx
    bsf     edx, edx                    ; first failing byte in the block
    add     rax, rdx
    vzeroupper
    ret
.tail:
    cmp     rax, rsi
    jae     .end
    movzx   edx, byte [rdi + rax]
    dec     edx                         ; 0x01..0x7F -> 0..0x7e; NUL and >= 0x80 fall outside
    cmp     edx, 0x7e
    ja      .end
    inc     rax
    jmp     .tail
.end:
    vzeroupper
    ret
