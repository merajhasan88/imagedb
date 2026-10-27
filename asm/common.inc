; Shared definitions for imagedb x86-64 kernels (NASM, System V ABI).
;
; Rules for every kernel in this directory:
;   - a C reference with identical semantics lives in src/cpu.c and the
;     differential tests in tests/unit/t_kernels.c compare the two;
;   - never read or write outside the caller's buffers (tails are scalar);
;   - position independent (RIP-relative data only);
;   - every function starts with endbr64 (CET/IBT) and AVX code ends with
;     vzeroupper;
;   - every file declares a non-executable stack (below), otherwise the
;     linker marks the whole binary's stack executable.

%define ENDBR db 0xf3, 0x0f, 0x1e, 0xfa      ; endbr64

%macro FUNC 1
    global %1:function
    align 32
%1:
    ENDBR
%endmacro

section .note.GNU-stack noalloc noexec nowrite progbits

; CET property: every function starts with endbr64 (IBT) and none touches
; return addresses (SHSTK). Without this note the linker would silently drop
; IBT/SHSTK for the entire binary.
section .note.gnu.property note alloc noexec nowrite align=8
    dd 4                    ; n_namesz
    dd 16                   ; n_descsz
    dd 5                    ; NT_GNU_PROPERTY_TYPE_0
    db "GNU", 0
    dd 0xc0000002           ; GNU_PROPERTY_X86_FEATURE_1_AND
    dd 4                    ; pr_datasz
    dd 3                    ; IBT | SHSTK
    dd 0                    ; pad to 8
