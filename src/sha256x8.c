/*
 * 8-lane AVX2 SHA-256: eight messages side by side (digest_alg 2's tree digest). Its round function (ROUND) was
 * first digest_alg 1's MGF1 expansion kernel's, gone with that algorithm (format 1: digest_alg 2 alone, 2026-11-15).
 * Output is bit-identical to imdb_sha256_x8_ref (checked in tests).
 */
#include <immintrin.h>
#include <string.h>

#include "cpu.h"
#include "sha256.h"

#define T_AVX2 __attribute__((target("avx2")))

T_AVX2 static inline __m256i rorv(__m256i x, int n)
{
    return _mm256_or_si256(_mm256_srli_epi32(x, n), _mm256_slli_epi32(x, 32 - n));
}

T_AVX2 static inline __m256i sig0(__m256i x)
{
    return _mm256_xor_si256(_mm256_xor_si256(rorv(x, 7), rorv(x, 18)), _mm256_srli_epi32(x, 3));
}

T_AVX2 static inline __m256i sig1(__m256i x)
{
    return _mm256_xor_si256(_mm256_xor_si256(rorv(x, 17), rorv(x, 19)), _mm256_srli_epi32(x, 10));
}

/* One round with rotating register roles: afterwards the new 'a' lives in h
 * and the new 'e' in d; the caller rotates the argument list. */
#define ROUND(a, b, c, d, e, f, g, h, kw)                                                         \
    do {                                                                                          \
        __m256i S1 = _mm256_xor_si256(_mm256_xor_si256(rorv(e, 6), rorv(e, 11)), rorv(e, 25));   \
        __m256i ch = _mm256_xor_si256(_mm256_and_si256(e, f), _mm256_andnot_si256(e, g));         \
        __m256i t1 = _mm256_add_epi32(_mm256_add_epi32(h, S1), _mm256_add_epi32(ch, kw));         \
        __m256i S0 = _mm256_xor_si256(_mm256_xor_si256(rorv(a, 2), rorv(a, 13)), rorv(a, 22));   \
        __m256i mj = _mm256_xor_si256(_mm256_and_si256(a, b),                                     \
                                      _mm256_and_si256(c, _mm256_xor_si256(a, b)));               \
        d = _mm256_add_epi32(d, t1);                                                              \
        h = _mm256_add_epi32(t1, _mm256_add_epi32(S0, mj));                                       \
    } while (0)

/* Eight messages of nblk 64-byte blocks each, already padded, one per lane: the round function is
 * ROUND's, the schedule computed per lane from each block's words. */
T_AVX2 void imdb_sha256_x8_avx2(const uint8_t *const msg[8], size_t nblk, uint8_t out[8][32])
{
    __m256i st[8];
    for (int j = 0; j < 8; j++) st[j] = _mm256_set1_epi32((int)imdb_sha256_iv[j]);
    for (size_t blk = 0; blk < nblk; blk++) {
        __m256i W[64];
        for (int i = 0; i < 16; i++) {
            uint32_t w[8];
            for (int l = 0; l < 8; l++) {
                const uint8_t *p = msg[l] + 64 * blk + 4 * (size_t)i;
                w[l] = (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | p[3];
            }
            W[i] = _mm256_loadu_si256((const __m256i *)(const void *)w);
        }
        for (int i = 16; i < 64; i++)
            W[i] = _mm256_add_epi32(_mm256_add_epi32(sig1(W[i - 2]), W[i - 7]), _mm256_add_epi32(sig0(W[i - 15]), W[i - 16]));
        for (int i = 0; i < 64; i++) W[i] = _mm256_add_epi32(W[i], _mm256_set1_epi32((int)imdb_sha256_k[i]));
        __m256i a = st[0], b = st[1], c = st[2], d = st[3], e = st[4], f = st[5], g = st[6], h = st[7];
        for (int i = 0; i < 64; i += 8) { /* after eight rounds the roles are back on a..h */
            ROUND(a, b, c, d, e, f, g, h, W[i]);
            ROUND(h, a, b, c, d, e, f, g, W[i + 1]);
            ROUND(g, h, a, b, c, d, e, f, W[i + 2]);
            ROUND(f, g, h, a, b, c, d, e, W[i + 3]);
            ROUND(e, f, g, h, a, b, c, d, W[i + 4]);
            ROUND(d, e, f, g, h, a, b, c, W[i + 5]);
            ROUND(c, d, e, f, g, h, a, b, W[i + 6]);
            ROUND(b, c, d, e, f, g, h, a, W[i + 7]);
        }
        st[0] = _mm256_add_epi32(st[0], a), st[1] = _mm256_add_epi32(st[1], b);
        st[2] = _mm256_add_epi32(st[2], c), st[3] = _mm256_add_epi32(st[3], d);
        st[4] = _mm256_add_epi32(st[4], e), st[5] = _mm256_add_epi32(st[5], f);
        st[6] = _mm256_add_epi32(st[6], g), st[7] = _mm256_add_epi32(st[7], h);
    }
    uint32_t t[8][8];
    for (int j = 0; j < 8; j++) _mm256_storeu_si256((__m256i *)(void *)t[j], st[j]);
    for (int l = 0; l < 8; l++)
        for (int j = 0; j < 8; j++) {
            uint32_t v = t[j][l];
            out[l][4 * j] = (uint8_t)(v >> 24);
            out[l][4 * j + 1] = (uint8_t)(v >> 16);
            out[l][4 * j + 2] = (uint8_t)(v >> 8);
            out[l][4 * j + 3] = (uint8_t)v;
        }
}
