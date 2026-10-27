/*
 * CPU feature detection and kernel dispatch.
 *
 * Every SIMD/assembly kernel has a portable C reference with identical
 * semantics. The dispatch table picks the fastest available implementation at
 * startup; IMDB_NO_SIMD=1 in the environment forces the C references, which is
 * how the test-suite proves both paths produce byte-identical results.
 */
#ifndef IMDB_CPU_H
#define IMDB_CPU_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct imdb_cpu {
    bool sse42, popcnt, avx2, bmi2;
    bool forced_scalar;
} imdb_cpu;

const imdb_cpu *imdb_cpu_get(void);

typedef struct imdb_kernels {
    const char *crc32c_name;
    uint32_t (*crc32c)(uint32_t crc, const void *p, size_t n);

    const char *lthash_name;
    void (*lthash_add)(uint16_t *acc, const uint16_t *x);   /* 1024 lanes */
    void (*lthash_sub)(uint16_t *acc, const uint16_t *x);

    const char *expand_name;
    /* MGF1-SHA256 expansion of a 40-byte seed into 2048 bytes */
    void (*lthash_expand)(const uint8_t seed[40], uint8_t out[2048]);

    const char *expand2_name;
    /* digest_alg 2's expansion: 32 ChaCha20 blocks (RFC 8439) under key, nonce imdb_lthash2_nonce,
     * block counter 0..31, i.e. the first 2048 bytes of its keystream */
    void (*lthash_expand2)(const uint8_t key[32], uint8_t out[2048]);

    const char *sha8_name;
    /* SHA-256 of eight messages of nblk 64-byte blocks each (padded by the caller), side by side */
    void (*sha256_x8)(const uint8_t *const msg[8], size_t nblk, uint8_t out[8][32]);

    const char *utf8_name;
    /* length of the prefix of bytes in 0x01..0x7F, i.e. index of the first
     * byte that is NUL or >= 0x80 (n if none) */
    size_t (*ascii_prefix)(const uint8_t *p, size_t n);

    const char *filter_name;
    /* out[i/64] bit i set iff lo <= col[i] <= hi (signed); n multiple of 64 not required */
    void (*filter_range_i64)(const int64_t *col, size_t n, int64_t lo, int64_t hi, uint64_t *out);

    const char *sum_name;
    /* Exact sum of col[i] for selected bits: returns low/high halves of a 128-bit total */
    void (*sum_masked_i64)(const int64_t *col, const uint64_t *bits, size_t n, int64_t out[2]);
} imdb_kernels;

const imdb_kernels *imdb_kern(void);

/* the twelve nonce bytes of digest_alg 2's expansion: "IMDBLT20", then four zeros */
extern const uint8_t imdb_lthash2_nonce[12];

/* SIMD implementations (sha256x8.c and chacha20x8.c always; asm/ when built with NASM). */
void imdb_lthash_expand_avx2(const uint8_t seed[40], uint8_t out[2048]);
void imdb_lthash_expand2_avx2(const uint8_t key[32], uint8_t out[2048]);
void imdb_sha256_x8_avx2(const uint8_t *const msg[8], size_t nblk, uint8_t out[8][32]);
uint32_t imdb_crc32c_sse42(uint32_t crc, const void *p, size_t n);
void imdb_lthash_add_avx2(uint16_t *acc, const uint16_t *x);
void imdb_lthash_sub_avx2(uint16_t *acc, const uint16_t *x);
size_t imdb_ascii_prefix_avx2(const uint8_t *p, size_t n);
void imdb_filter_range_i64_avx2(const int64_t *col, size_t n, int64_t lo, int64_t hi, uint64_t *out);
void imdb_sum_masked_i64_avx2(const int64_t *col, const uint64_t *bits, size_t n, int64_t out[2]);

/* Portable references (always available; used by tests as oracles). */
uint32_t imdb_crc32c_ref(uint32_t crc, const void *p, size_t n);
void imdb_lthash_add_ref(uint16_t *acc, const uint16_t *x);
void imdb_lthash_sub_ref(uint16_t *acc, const uint16_t *x);
void imdb_lthash_expand_ref(const uint8_t seed[40], uint8_t out[2048]);
void imdb_lthash_expand2_ref(const uint8_t key[32], uint8_t out[2048]);
void imdb_sha256_x8_ref(const uint8_t *const msg[8], size_t nblk, uint8_t out[8][32]);
size_t imdb_ascii_prefix_ref(const uint8_t *p, size_t n);
void imdb_filter_range_i64_ref(const int64_t *col, size_t n, int64_t lo, int64_t hi, uint64_t *out);
void imdb_sum_masked_i64_ref(const int64_t *col, const uint64_t *bits, size_t n, int64_t out[2]);

#endif
