; uint32_t imdb_crc32c_sse42(uint32_t crc, const void *p, size_t n)
; CRC-32C (Castagnoli) with the SSE4.2 crc32 instruction; same contract as
; imdb_crc32c_ref: crc is the running value, pre/post inversion inside.
%include "common.inc"

section .text

FUNC imdb_crc32c_sse42
    mov     eax, edi
    not     eax
    test    rdx, rdx
    jz      .done
.head:                          ; align the pointer to 8 bytes
    test    rsi, 7
    jz      .body
    crc32   eax, byte [rsi]
    inc     rsi
    dec     rdx
    jnz     .head
    jmp     .done
.body:
    mov     rcx, rdx
    shr     rcx, 5              ; 32-byte blocks
    jz      .qwords
.blk:
    crc32   rax, qword [rsi]
    crc32   rax, qword [rsi + 8]
    crc32   rax, qword [rsi + 16]
    crc32   rax, qword [rsi + 24]
    add     rsi, 32
    dec     rcx
    jnz     .blk
.qwords:
    mov     rcx, rdx
    and     rcx, 31
    shr     rcx, 3
    jz      .bytes
.qw:
    crc32   rax, qword [rsi]
    add     rsi, 8
    dec     rcx
    jnz     .qw
.bytes:
    and     rdx, 7
    jz      .done
.by:
    crc32   eax, byte [rsi]
    inc     rsi
    dec     rdx
    jnz     .by
.done:
    not     eax
    ret
