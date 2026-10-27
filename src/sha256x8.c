/*
 * 8-lane AVX2 SHA-256: one kernel specialised for digest_alg 1's LtHash expansion, and one for
 * eight messages side by side (digest_alg 2's tree digest).
 *
 * Every alg 1 expansion hashes 64 single-block messages  seed(40) || BE32(i)  that
 * differ only in message word 10 (the counter). Consequences exploited here:
 *   - rounds 0..9 consume only seed words, so they run once (scalar) and the
 *     resulting state is broadcast to all lanes;
 *   - message words 11..15 are padding constants; W16 and W18 are lane-invariant.
 * Output is bit-identical to imdb_lthash_expand_ref (checked in tests), and the
 * eight-message kernel's to imdb_sha256_x8_ref.
 */
#include <immintrin.h>
#include <string.h>

#include "cpu.h"
#include "sha256.h"

#define T_AVX2 __attribute__((target("avx2")))

static inline uint32_t ror32(uint32_t x, int n) { return x >> n | x << (32 - n); }

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

T_AVX2 void imdb_lthash_expand_avx2(const uint8_t seed[40], uint8_t out[2048])
{
    uint32_t w[16];
    for (int i = 0; i < 10; i++)
        w[i] = (uint32_t)seed[4 * i] << 24 | (uint32_t)seed[4 * i + 1] << 16 |
               (uint32_t)seed[4 * i + 2] << 8 | seed[4 * i + 3];
    w[10] = 0; /* counter: per lane */
    w[11] = 0x80000000u;
    w[12] = w[13] = w[14] = 0;
    w[15] = 352;

    /* Scalar rounds 0..9 (lane-invariant). */
    uint32_t s[8];
    memcpy(s, imdb_sha256_iv, sizeof s);
    for (int i = 0; i < 10; i++) {
        uint32_t S1 = ror32(s[4], 6) ^ ror32(s[4], 11) ^ ror32(s[4], 25);
        uint32_t ch = (s[4] & s[5]) ^ (~s[4] & s[6]);
        uint32_t t1 = s[7] + S1 + ch + imdb_sha256_k[i] + w[i];
        uint32_t S0 = ror32(s[0], 2) ^ ror32(s[0], 13) ^ ror32(s[0], 22);
        uint32_t mj = (s[0] & s[1]) ^ (s[0] & s[2]) ^ (s[1] & s[2]);
        s[7] = s[6]; s[6] = s[5]; s[5] = s[4]; s[4] = s[3] + t1;
        s[3] = s[2]; s[2] = s[1]; s[1] = s[0]; s[0] = t1 + mj + S0;
    }
    /* Lane-invariant schedule words. */
    uint32_t w16 = (ror32(w[14], 17) ^ ror32(w[14], 19) ^ (w[14] >> 10)) + w[9] +
                   (ror32(w[1], 7) ^ ror32(w[1], 18) ^ (w[1] >> 3)) + w[0];
    uint32_t w18 = (ror32(w16, 17) ^ ror32(w16, 19) ^ (w16 >> 10)) + w[11] +
                   (ror32(w[3], 7) ^ ror32(w[3], 18) ^ (w[3] >> 3)) + w[2];

    const __m256i lane = _mm256_setr_epi32(0, 1, 2, 3, 4, 5, 6, 7);
    __m256i KW[64];
    __m256i W[64];
    for (int i = 0; i < 16; i++) W[i] = _mm256_set1_epi32((int)w[i]);
    W[16] = _mm256_set1_epi32((int)w16);
    W[18] = _mm256_set1_epi32((int)w18);

    for (uint32_t batch = 0; batch < 8; batch++) {
        W[10] = _mm256_add_epi32(lane, _mm256_set1_epi32((int)(batch * 8)));
        W[17] = _mm256_add_epi32(_mm256_add_epi32(sig1(W[15]), W[10]),
                                 _mm256_add_epi32(sig0(W[2]), W[1]));
        for (int i = 19; i < 64; i++)
            W[i] = _mm256_add_epi32(_mm256_add_epi32(sig1(W[i - 2]), W[i - 7]),
                                    _mm256_add_epi32(sig0(W[i - 15]), W[i - 16]));
        for (int i = 10; i < 64; i++)
            KW[i] = _mm256_add_epi32(W[i], _mm256_set1_epi32((int)imdb_sha256_k[i]));

        __m256i a = _mm256_set1_epi32((int)s[0]), b = _mm256_set1_epi32((int)s[1]);
        __m256i c = _mm256_set1_epi32((int)s[2]), d = _mm256_set1_epi32((int)s[3]);
        __m256i e = _mm256_set1_epi32((int)s[4]), f = _mm256_set1_epi32((int)s[5]);
        __m256i g = _mm256_set1_epi32((int)s[6]), h = _mm256_set1_epi32((int)s[7]);
        /* Rounds 10..57: six groups of eight (roles return to a..h after each). */
        for (int i = 10; i < 58; i += 8) {
            ROUND(a, b, c, d, e, f, g, h, KW[i]);
            ROUND(h, a, b, c, d, e, f, g, KW[i + 1]);
            ROUND(g, h, a, b, c, d, e, f, KW[i + 2]);
            ROUND(f, g, h, a, b, c, d, e, KW[i + 3]);
            ROUND(e, f, g, h, a, b, c, d, KW[i + 4]);
            ROUND(d, e, f, g, h, a, b, c, KW[i + 5]);
            ROUND(c, d, e, f, g, h, a, b, KW[i + 6]);
            ROUND(b, c, d, e, f, g, h, a, KW[i + 7]);
        }
        /* Rounds 58..63; afterwards roles A..H are held by c,d,e,f,g,h,a,b. */
        ROUND(a, b, c, d, e, f, g, h, KW[58]);
        ROUND(h, a, b, c, d, e, f, g, KW[59]);
        ROUND(g, h, a, b, c, d, e, f, KW[60]);
        ROUND(f, g, h, a, b, c, d, e, KW[61]);
        ROUND(e, f, g, h, a, b, c, d, KW[62]);
        ROUND(d, e, f, g, h, a, b, c, KW[63]);

        __m256i fin[8] = {c, d, e, f, g, h, a, b};
        uint32_t tmp[8][8];
        for (int j = 0; j < 8; j++) {
            fin[j] = _mm256_add_epi32(fin[j], _mm256_set1_epi32((int)imdb_sha256_iv[j]));
            _mm256_storeu_si256((__m256i *)tmp[j], fin[j]);
        }
        for (int l = 0; l < 8; l++) {
            uint8_t *o = out + 32 * (batch * 8 + (uint32_t)l);
            for (int j = 0; j < 8; j++) {
                uint32_t v = tmp[j][l];
                o[4 * j] = (uint8_t)(v >> 24);
                o[4 * j + 1] = (uint8_t)(v >> 16);
                o[4 * j + 2] = (uint8_t)(v >> 8);
                o[4 * j + 3] = (uint8_t)v;
            }
        }
    }
}

/* Eight messages of nblk 64-byte blocks each, already padded, one per lane: the round function is
 * the alg 1 kernel's, the schedule computed per lane from each block's words. */
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
