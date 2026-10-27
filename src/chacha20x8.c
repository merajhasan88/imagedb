/*
 * 8-lane AVX2 ChaCha20 (RFC 8439's block function, 20 rounds) for digest_alg 2's LtHash expansion:
 * eight consecutive blocks of one key and nonce per step, lane l the block counter + l, so an
 * element's 32 blocks are four steps. Output is bit-identical to imdb_lthash_expand2_ref
 * (Monocypher's keystream; checked in tests, and against OpenSSL's).
 */
#include <immintrin.h>
#include <string.h>

#include "cpu.h"

#define T_AVX2 __attribute__((target("avx2")))

T_AVX2 static inline __m256i rotl(__m256i x, int n)
{
    return _mm256_or_si256(_mm256_slli_epi32(x, n), _mm256_srli_epi32(x, 32 - n));
}

/* rotations by whole bytes are byte shuffles within each 32-bit word */
T_AVX2 static inline __m256i rot16(__m256i x)
{
    const __m256i m = _mm256_setr_epi8(2, 3, 0, 1, 6, 7, 4, 5, 10, 11, 8, 9, 14, 15, 12, 13, 2, 3, 0, 1, 6, 7, 4, 5, 10, 11,
                                       8, 9, 14, 15, 12, 13);
    return _mm256_shuffle_epi8(x, m);
}

T_AVX2 static inline __m256i rot8(__m256i x)
{
    const __m256i m = _mm256_setr_epi8(3, 0, 1, 2, 7, 4, 5, 6, 11, 8, 9, 10, 15, 12, 13, 14, 3, 0, 1, 2, 7, 4, 5, 6, 11, 8,
                                       9, 10, 15, 12, 13, 14);
    return _mm256_shuffle_epi8(x, m);
}

/* r[i] holds 32-bit word i of eight blocks; afterwards r[l] holds words 0-7 of block l */
T_AVX2 static inline void transpose8(__m256i r[8])
{
    __m256i t0 = _mm256_unpacklo_epi32(r[0], r[1]), t1 = _mm256_unpackhi_epi32(r[0], r[1]);
    __m256i t2 = _mm256_unpacklo_epi32(r[2], r[3]), t3 = _mm256_unpackhi_epi32(r[2], r[3]);
    __m256i t4 = _mm256_unpacklo_epi32(r[4], r[5]), t5 = _mm256_unpackhi_epi32(r[4], r[5]);
    __m256i t6 = _mm256_unpacklo_epi32(r[6], r[7]), t7 = _mm256_unpackhi_epi32(r[6], r[7]);
    __m256i u0 = _mm256_unpacklo_epi64(t0, t2), u1 = _mm256_unpackhi_epi64(t0, t2);
    __m256i u2 = _mm256_unpacklo_epi64(t1, t3), u3 = _mm256_unpackhi_epi64(t1, t3);
    __m256i u4 = _mm256_unpacklo_epi64(t4, t6), u5 = _mm256_unpackhi_epi64(t4, t6);
    __m256i u6 = _mm256_unpacklo_epi64(t5, t7), u7 = _mm256_unpackhi_epi64(t5, t7);
    r[0] = _mm256_permute2x128_si256(u0, u4, 0x20), r[1] = _mm256_permute2x128_si256(u1, u5, 0x20);
    r[2] = _mm256_permute2x128_si256(u2, u6, 0x20), r[3] = _mm256_permute2x128_si256(u3, u7, 0x20);
    r[4] = _mm256_permute2x128_si256(u0, u4, 0x31), r[5] = _mm256_permute2x128_si256(u1, u5, 0x31);
    r[6] = _mm256_permute2x128_si256(u2, u6, 0x31), r[7] = _mm256_permute2x128_si256(u3, u7, 0x31);
}

#define QR(a, b, c, d)                                                                             \
    do {                                                                                           \
        a = _mm256_add_epi32(a, b);                                                                \
        d = rot16(_mm256_xor_si256(d, a));                                                         \
        c = _mm256_add_epi32(c, d);                                                                \
        b = rotl(_mm256_xor_si256(b, c), 12);                                                      \
        a = _mm256_add_epi32(a, b);                                                                \
        d = rot8(_mm256_xor_si256(d, a));                                                          \
        c = _mm256_add_epi32(c, d);                                                                \
        b = rotl(_mm256_xor_si256(b, c), 7);                                                       \
    } while (0)

static inline uint32_t ld32le(const uint8_t *p)
{
    return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}

/* blocks counter .. counter + 7 of the keystream, 512 bytes */
T_AVX2 static void chacha20_x8(const uint8_t key[32], const uint8_t nonce[12], uint32_t counter, uint8_t out[512])
{
    static const uint32_t sigma[4] = {0x61707865u, 0x3320646eu, 0x79622d32u, 0x6b206574u};
    __m256i s[16], x[16];
    for (int i = 0; i < 4; i++) s[i] = _mm256_set1_epi32((int)sigma[i]);
    for (int i = 0; i < 8; i++) s[4 + i] = _mm256_set1_epi32((int)ld32le(key + 4 * i));
    s[12] = _mm256_add_epi32(_mm256_set1_epi32((int)counter), _mm256_setr_epi32(0, 1, 2, 3, 4, 5, 6, 7));
    for (int i = 0; i < 3; i++) s[13 + i] = _mm256_set1_epi32((int)ld32le(nonce + 4 * i));
    memcpy(x, s, sizeof x);
    for (int r = 0; r < 10; r++) {
        QR(x[0], x[4], x[8], x[12]);
        QR(x[1], x[5], x[9], x[13]);
        QR(x[2], x[6], x[10], x[14]);
        QR(x[3], x[7], x[11], x[15]);
        QR(x[0], x[5], x[10], x[15]);
        QR(x[1], x[6], x[11], x[12]);
        QR(x[2], x[7], x[8], x[13]);
        QR(x[3], x[4], x[9], x[14]);
    }
    for (int i = 0; i < 16; i++) x[i] = _mm256_add_epi32(x[i], s[i]);
    /* the keystream is little-endian words, the host's order: two transposes, then plain stores */
    transpose8(x);
    transpose8(x + 8);
    for (int l = 0; l < 8; l++) {
        _mm256_storeu_si256((__m256i *)(void *)(out + 64 * l), x[l]);
        _mm256_storeu_si256((__m256i *)(void *)(out + 64 * l + 32), x[8 + l]);
    }
}

T_AVX2 void imdb_lthash_expand2_avx2(const uint8_t key[32], uint8_t out[2048])
{
    for (uint32_t c = 0; c < 32; c += 8) chacha20_x8(key, imdb_lthash2_nonce, c, out + 64 * c);
}
