/* Ed25519, the engine's fast path (see ed25519.h). */
#include "ed25519.h"

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cpu.h"
#include "util.h"
#include "vendor/monocypher/monocypher-ed25519.h"

__extension__ typedef unsigned __int128 u128;
typedef uint64_t u64;

/* ---- the field GF(2^255 - 19) ----------------------------------------------------
 *
 * Five limbs of 51 bits, value = sum v[i] * 2^(51 i). Limbs may exceed 51 bits
 * between operations; the bounds each operation accepts and returns:
 *   fe_mul, fe_sq      inputs < 2^56 per limb; output "carried": < 2^51 + 2^23
 *   fe_add             output = f + g limb by limb (no carry)
 *   fe_sub, fe_neg     subtrahend at most 4p's limbs (2^53 - 76, 2^53 - 4): any
 *                      carried value or the sum of two; output < f + 2^53
 *   fe_carry           inputs < 2^63; output < 2^51 + 2^17
 * The SAN build checks these bounds (IMDB_FE_CHECKS) at every entry. */

#define M51 ((u64)0x7ffffffffffff)
#define P4_0 ((u64)0x1fffffffffffb4) /* 4 * (2^51 - 19) */
#define P4_1 ((u64)0x1ffffffffffffc) /* 4 * (2^51 - 1) */

typedef struct fe {
    u64 v[5];
} fe;

#ifdef IMDB_FE_CHECKS
static void fe_bound_fail(const char *what)
{
    fprintf(stderr, "ed25519: field limb bound violated (%s)\n", what);
    abort();
}
#define FE_BELOW(f, bits)                                                                              \
    do {                                                                                               \
        for (int k_ = 0; k_ < 5; k_++)                                                                 \
            if ((f)->v[k_] >> (bits)) fe_bound_fail(#f " >= 2^" #bits);                                \
    } while (0)
#define FE_SUBTRAHEND(g)                                                                               \
    do {                                                                                               \
        if ((g)->v[0] > P4_0) fe_bound_fail("subtrahend limb 0");                                      \
        for (int k_ = 1; k_ < 5; k_++)                                                                 \
            if ((g)->v[k_] > P4_1) fe_bound_fail("subtrahend limb");                                   \
    } while (0)
#else
#define FE_BELOW(f, bits) ((void)0)
#define FE_SUBTRAHEND(g) ((void)0)
#endif

static void fe_0(fe *h) { memset(h, 0, sizeof *h); }

static void fe_1(fe *h)
{
    memset(h, 0, sizeof *h);
    h->v[0] = 1;
}

static void fe_add(fe *h, const fe *f, const fe *g)
{
    for (int i = 0; i < 5; i++) h->v[i] = f->v[i] + g->v[i];
}

static void fe_sub(fe *h, const fe *f, const fe *g)
{
    FE_SUBTRAHEND(g);
    h->v[0] = f->v[0] + P4_0 - g->v[0];
    for (int i = 1; i < 5; i++) h->v[i] = f->v[i] + P4_1 - g->v[i];
}

static void fe_neg(fe *h, const fe *f)
{
    FE_SUBTRAHEND(f);
    h->v[0] = P4_0 - f->v[0];
    for (int i = 1; i < 5; i++) h->v[i] = P4_1 - f->v[i];
}

static void fe_carry(fe *h)
{
    FE_BELOW(h, 63);
    u64 c;
    c = h->v[0] >> 51, h->v[0] &= M51, h->v[1] += c;
    c = h->v[1] >> 51, h->v[1] &= M51, h->v[2] += c;
    c = h->v[2] >> 51, h->v[2] &= M51, h->v[3] += c;
    c = h->v[3] >> 51, h->v[3] &= M51, h->v[4] += c;
    c = h->v[4] >> 51, h->v[4] &= M51, h->v[0] += 19 * c;
}

/* Column sums t0..t4 (each < 2^119) back to carried limbs. */
static inline __attribute__((always_inline)) void fe_from128(fe *h, u128 t0, u128 t1, u128 t2, u128 t3, u128 t4)
{
    t1 += t0 >> 51;
    t2 += t1 >> 51;
    t3 += t2 >> 51;
    t4 += t3 >> 51;
    u128 x = ((u128)((u64)t0 & M51)) + (t4 >> 51) * 19; /* 2^255 = 19 (mod p) */
    h->v[0] = (u64)x & M51;
    h->v[1] = ((u64)t1 & M51) + (u64)(x >> 51);
    h->v[2] = (u64)t2 & M51;
    h->v[3] = (u64)t3 & M51;
    h->v[4] = (u64)t4 & M51;
}

static void fe_mul(fe *h, const fe *f, const fe *g)
{
    FE_BELOW(f, 56);
    FE_BELOW(g, 56);
    u64 f0 = f->v[0], f1 = f->v[1], f2 = f->v[2], f3 = f->v[3], f4 = f->v[4];
    u64 g0 = g->v[0], g1 = g->v[1], g2 = g->v[2], g3 = g->v[3], g4 = g->v[4];
    u64 g1_19 = 19 * g1, g2_19 = 19 * g2, g3_19 = 19 * g3, g4_19 = 19 * g4;
    u128 t0 = (u128)f0 * g0 + (u128)f1 * g4_19 + (u128)f2 * g3_19 + (u128)f3 * g2_19 + (u128)f4 * g1_19;
    u128 t1 = (u128)f0 * g1 + (u128)f1 * g0 + (u128)f2 * g4_19 + (u128)f3 * g3_19 + (u128)f4 * g2_19;
    u128 t2 = (u128)f0 * g2 + (u128)f1 * g1 + (u128)f2 * g0 + (u128)f3 * g4_19 + (u128)f4 * g3_19;
    u128 t3 = (u128)f0 * g3 + (u128)f1 * g2 + (u128)f2 * g1 + (u128)f3 * g0 + (u128)f4 * g4_19;
    u128 t4 = (u128)f0 * g4 + (u128)f1 * g3 + (u128)f2 * g2 + (u128)f3 * g1 + (u128)f4 * g0;
    fe_from128(h, t0, t1, t2, t3, t4);
}

static void fe_sq(fe *h, const fe *f)
{
    FE_BELOW(f, 56);
    u64 f0 = f->v[0], f1 = f->v[1], f2 = f->v[2], f3 = f->v[3], f4 = f->v[4];
    u64 d0 = 2 * f0, d1 = 2 * f1;
    u64 f1_38 = 38 * f1, f2_38 = 38 * f2, f3_38 = 38 * f3, f3_19 = 19 * f3, f4_19 = 19 * f4;
    u128 t0 = (u128)f0 * f0 + (u128)f1_38 * f4 + (u128)f2_38 * f3;
    u128 t1 = (u128)d0 * f1 + (u128)f2_38 * f4 + (u128)f3_19 * f3;
    u128 t2 = (u128)d0 * f2 + (u128)f1 * f1 + (u128)f3_38 * f4;
    u128 t3 = (u128)d0 * f3 + (u128)d1 * f2 + (u128)f4_19 * f4;
    u128 t4 = (u128)d0 * f4 + (u128)d1 * f3 + (u128)f2 * f2;
    fe_from128(h, t0, t1, t2, t3, t4);
}

static void fe_sqn(fe *h, const fe *f, int n)
{
    fe_sq(h, f);
    for (int i = 1; i < n; i++) fe_sq(h, h);
}

/* Little-endian, bit 255 ignored; values in [p, 2^255) are accepted as they are. */
static void fe_frombytes(fe *h, const uint8_t s[32])
{
    u64 w[4];
    for (int i = 0; i < 4; i++) {
        w[i] = 0;
        for (int b = 7; b >= 0; b--) w[i] = (w[i] << 8) | s[8 * i + b];
    }
    h->v[0] = w[0] & M51;
    h->v[1] = ((w[0] >> 51) | (w[1] << 13)) & M51;
    h->v[2] = ((w[1] >> 38) | (w[2] << 26)) & M51;
    h->v[3] = ((w[2] >> 25) | (w[3] << 39)) & M51;
    h->v[4] = (w[3] >> 12) & M51;
}

/* The canonical encoding (fully reduced mod p). Constant time. */
static void fe_tobytes(uint8_t s[32], const fe *f)
{
    fe t = *f;
    /* two passes: every limb < 2^51 and the value < 2^255 (a third pass is never needed:
     * when the second one wraps, the value left is below 2^17 + 19) */
    fe_carry(&t);
    fe_carry(&t);
    /* t in [0, 2^255): add 19, carry, then add 2^255 - 19 limb-wise without the final wrap,
     * which leaves t + 2^255 - p truncated to 255 bits = t mod p */
    t.v[0] += 19;
    fe_carry(&t);
    t.v[0] += M51 + 1 - 19;
    for (int i = 1; i < 5; i++) t.v[i] += M51;
    for (int i = 0; i < 4; i++) {
        t.v[i + 1] += t.v[i] >> 51;
        t.v[i] &= M51;
    }
    t.v[4] &= M51;
    u64 w0 = t.v[0] | (t.v[1] << 51), w1 = (t.v[1] >> 13) | (t.v[2] << 38), w2 = (t.v[2] >> 26) | (t.v[3] << 25),
        w3 = (t.v[3] >> 39) | (t.v[4] << 12);
    u64 w[4] = {w0, w1, w2, w3};
    for (int i = 0; i < 4; i++)
        for (int b = 0; b < 8; b++) s[8 * i + b] = (uint8_t)(w[i] >> (8 * b));
    imdb_wipe(&t, sizeof t);
}

static int fe_isodd(const fe *f)
{
    uint8_t s[32];
    fe_tobytes(s, f);
    int odd = s[0] & 1;
    imdb_wipe(s, sizeof s);
    return odd;
}

/* Variable time: public values only. */
static bool fe_iszero_vt(const fe *f)
{
    uint8_t s[32];
    fe_tobytes(s, f);
    uint8_t acc = 0;
    for (int i = 0; i < 32; i++) acc |= s[i];
    return acc == 0;
}

static bool fe_equal_vt(const fe *f, const fe *g)
{
    uint8_t a[32], b[32];
    fe_tobytes(a, f);
    fe_tobytes(b, g);
    return memcmp(a, b, 32) == 0;
}

/* f = mask ? g : f, mask all ones or zero. Constant time. */
static void fe_cmov(fe *f, const fe *g, u64 mask)
{
    for (int i = 0; i < 5; i++) f->v[i] ^= (f->v[i] ^ g->v[i]) & mask;
}

/* z^(2^250 - 1), and z^11 on the side (the shared prefix of both chains below). */
static void fe_pow2_250m1(fe *out, fe *z11, const fe *z)
{
    fe t0, t1, t2, z9;
    fe_sq(&t0, z);           /* 2 */
    fe_sqn(&t1, &t0, 2);     /* 8 */
    fe_mul(&z9, z, &t1);     /* 9 */
    fe_mul(z11, &t0, &z9);   /* 11 */
    fe_sq(&t0, z11);         /* 22 */
    fe_mul(&t0, &t0, &z9);   /* 31 = 2^5 - 1 */
    fe_sqn(&t1, &t0, 5);
    fe_mul(&t0, &t1, &t0);   /* 2^10 - 1 */
    fe_sqn(&t1, &t0, 10);
    fe_mul(&t1, &t1, &t0);   /* 2^20 - 1 */
    fe_sqn(&t2, &t1, 20);
    fe_mul(&t1, &t2, &t1);   /* 2^40 - 1 */
    fe_sqn(&t1, &t1, 10);
    fe_mul(&t0, &t1, &t0);   /* 2^50 - 1 */
    fe_sqn(&t1, &t0, 50);
    fe_mul(&t1, &t1, &t0);   /* 2^100 - 1 */
    fe_sqn(&t2, &t1, 100);
    fe_mul(&t1, &t2, &t1);   /* 2^200 - 1 */
    fe_sqn(&t1, &t1, 50);
    fe_mul(out, &t1, &t0);   /* 2^250 - 1 */
    imdb_wipe(&t0, sizeof t0);
    imdb_wipe(&t1, sizeof t1);
    imdb_wipe(&t2, sizeof t2);
    imdb_wipe(&z9, sizeof z9);
}

/* z^(p - 2) = z^(2^255 - 21): the inverse (0 for 0). Constant time. */
static void fe_invert(fe *out, const fe *z)
{
    fe t, z11;
    fe_pow2_250m1(&t, &z11, z);
    fe_sqn(&t, &t, 5);       /* 2^255 - 32 */
    fe_mul(out, &t, &z11);   /* 2^255 - 21 */
    imdb_wipe(&t, sizeof t);
    imdb_wipe(&z11, sizeof z11);
}

/* z^((p - 5) / 8) = z^(2^252 - 3), for square roots. */
static void fe_pow22523(fe *out, const fe *z)
{
    fe t, z11;
    fe_pow2_250m1(&t, &z11, z);
    fe_sqn(&t, &t, 2);       /* 2^252 - 4 */
    fe_mul(out, &t, z);      /* 2^252 - 3 */
    imdb_wipe(&t, sizeof t);
    imdb_wipe(&z11, sizeof z11);
}

/* ---- the field, four at a time (AVX2) ------------------------------------------------
 *
 * Four field elements in the four 64-bit lanes of ten vectors, radix 2^25.5: limb i
 * starts at bit ceil(25.5 i) and holds 26 bits for even i, 25 for odd, so a limb
 * product is one 32 x 32 -> 64 lane of vpmuludq (_mm256_mul_epu32), four per
 * instruction. The bounds each operation accepts and returns:
 *   fe4_mul, fe4_sq    even limbs <= 3 * 2^26 + 2^20, odd <= 3 * 2^25 + 2^20 (a carried
 *                      value plus 2p minus a carried value fits); output carried: even
 *                      < 2^26, odd < 2^25, limb 1 < 2^25 + 2^17
 *   fe4_add            f + g limb by limb (no carry)
 *   fe4_sub, fe4_neg   subtrahend at most 2p's limbs (any carried value); output < f + 2p
 *   fe4_carry          inputs < 2^63; output carried
 * Within the input bounds 19 g_j, 2 f_i and 38 f_i stay below 2^32 and every column
 * sum below 2^63 (the largest, five 2^58.5 and four 2^59.5 terms, is 5.1e18). The
 * SAN build checks them (IMDB_FE_CHECKS). Intrinsics, not assembly, so a constant-time
 * use could be checked by `make ct` (clang's MemorySanitizer follows them lane by lane),
 * but today only verification uses them: on this CPU (Kaby Lake) the four-way field
 * pays in the batch (its decodings, tables and multi-scalar loop, about 20% fewer
 * cycles) and not in single verification or the signing comb, which stay scalar
 * (docs/plan-round3.md has the measurements). The scalar radix-2^51 code above is the
 * reference (t_ed25519.c). */

#if defined(__x86_64__)
#include <immintrin.h>
#define HAVE_FE4 1
#define T_AVX2 __attribute__((target("avx2")))

typedef struct fe4 {
    __m256i v[10];
} fe4;

#define M26 0x3ffffffull
#define M25 0x1ffffffull

#ifdef IMDB_FE_CHECKS
T_AVX2 static void fe4_bound(const fe4 *f, uint64_t even, uint64_t odd, const char *what)
{
    for (int i = 0; i < 10; i++) {
        uint64_t l[4];
        _mm256_storeu_si256((__m256i *)l, f->v[i]);
        for (int k = 0; k < 4; k++)
            if (l[k] > ((i & 1) ? odd : even)) fe_bound_fail(what);
    }
}
#define FE4_MULIN(f) fe4_bound((f), 3 * (M26 + 1) + (1u << 20), 3 * (M25 + 1) + (1u << 20), #f " above the fe4_mul bound")
#define FE4_SUBTRAHEND(g) fe4_bound((g), 2 * (M26 + 1 - 19), 2 * M25, #g " above 2p") /* limb 0 of 2p bounds every even one */
#define FE4_SUBTRAHEND4(g) fe4_bound((g), 4 * (M26 + 1 - 19), 4 * M25, #g " above 4p")
#else
#define FE4_MULIN(f) ((void)0)
#define FE4_SUBTRAHEND(g) ((void)0)
#define FE4_SUBTRAHEND4(g) ((void)0)
#endif

T_AVX2 static void fe4_add(fe4 *h, const fe4 *f, const fe4 *g)
{
    for (int i = 0; i < 10; i++) h->v[i] = _mm256_add_epi64(f->v[i], g->v[i]);
}

/* 2p, limb by limb: 2 (2^26 - 19), then 2 (2^25 - 1) and 2 (2^26 - 1) alternately */
T_AVX2 static __m256i p2_limb(int i)
{
    return _mm256_set1_epi64x(i == 0 ? (long long)(2 * (M26 + 1 - 19)) : (i & 1) ? (long long)(2 * M25) : (long long)(2 * M26));
}

T_AVX2 static void fe4_sub(fe4 *h, const fe4 *f, const fe4 *g)
{
    FE4_SUBTRAHEND(g);
    for (int i = 0; i < 10; i++) h->v[i] = _mm256_sub_epi64(_mm256_add_epi64(f->v[i], p2_limb(i)), g->v[i]);
}

T_AVX2 static void fe4_neg(fe4 *h, const fe4 *f)
{
    FE4_SUBTRAHEND(f);
    for (int i = 0; i < 10; i++) h->v[i] = _mm256_sub_epi64(p2_limb(i), f->v[i]);
}

/* the ref10 carry order: two interleaved chains, then 2^255 = 19 back into limb 0 */
T_AVX2 static void fe4_carry_h(__m256i h[10])
{
    const __m256i m26 = _mm256_set1_epi64x((long long)M26), m25 = _mm256_set1_epi64x((long long)M25);
#define C26(a, b) (h[b] = _mm256_add_epi64(h[b], _mm256_srli_epi64(h[a], 26)), h[a] = _mm256_and_si256(h[a], m26))
#define C25(a, b) (h[b] = _mm256_add_epi64(h[b], _mm256_srli_epi64(h[a], 25)), h[a] = _mm256_and_si256(h[a], m25))
    C26(0, 1);
    C26(4, 5);
    C25(1, 2);
    C25(5, 6);
    C26(2, 3);
    C26(6, 7);
    C25(3, 4);
    C25(7, 8);
    C26(4, 5);
    C26(8, 9);
    __m256i c = _mm256_srli_epi64(h[9], 25); /* < 2^38: times 19 by shifts */
    h[9] = _mm256_and_si256(h[9], m25);
    h[0] = _mm256_add_epi64(h[0], _mm256_add_epi64(_mm256_add_epi64(_mm256_slli_epi64(c, 4), _mm256_slli_epi64(c, 1)), c));
    C26(0, 1);
#undef C26
#undef C25
}

T_AVX2 static void fe4_carry(fe4 *h) { fe4_carry_h(h->v); }

#define MUL(a, b) _mm256_mul_epu32((a), (b))
#define ADD(a, b) _mm256_add_epi64((a), (b))

T_AVX2 static void fe4_mul(fe4 *h, const fe4 *f, const fe4 *g)
{
    FE4_MULIN(f);
    FE4_MULIN(g);
    const __m256i n19 = _mm256_set1_epi64x(19);
    __m256i f0 = f->v[0], f1 = f->v[1], f2 = f->v[2], f3 = f->v[3], f4 = f->v[4], f5 = f->v[5], f6 = f->v[6],
            f7 = f->v[7], f8 = f->v[8], f9 = f->v[9];
    __m256i g0 = g->v[0], g1 = g->v[1], g2 = g->v[2], g3 = g->v[3], g4 = g->v[4], g5 = g->v[5], g6 = g->v[6],
            g7 = g->v[7], g8 = g->v[8], g9 = g->v[9];
    __m256i g1_19 = MUL(g1, n19), g2_19 = MUL(g2, n19), g3_19 = MUL(g3, n19), g4_19 = MUL(g4, n19), g5_19 = MUL(g5, n19),
            g6_19 = MUL(g6, n19), g7_19 = MUL(g7, n19), g8_19 = MUL(g8, n19), g9_19 = MUL(g9, n19);
    __m256i f1_2 = ADD(f1, f1), f3_2 = ADD(f3, f3), f5_2 = ADD(f5, f5), f7_2 = ADD(f7, f7), f9_2 = ADD(f9, f9);
    __m256i t[10];
    t[0] = ADD(ADD(ADD(MUL(f0, g0), MUL(f1_2, g9_19)), ADD(MUL(f2, g8_19), MUL(f3_2, g7_19))),
               ADD(ADD(MUL(f4, g6_19), MUL(f5_2, g5_19)), ADD(ADD(MUL(f6, g4_19), MUL(f7_2, g3_19)),
                                                              ADD(MUL(f8, g2_19), MUL(f9_2, g1_19)))));
    t[1] = ADD(ADD(ADD(MUL(f0, g1), MUL(f1, g0)), ADD(MUL(f2, g9_19), MUL(f3, g8_19))),
               ADD(ADD(MUL(f4, g7_19), MUL(f5, g6_19)), ADD(ADD(MUL(f6, g5_19), MUL(f7, g4_19)),
                                                            ADD(MUL(f8, g3_19), MUL(f9, g2_19)))));
    t[2] = ADD(ADD(ADD(MUL(f0, g2), MUL(f1_2, g1)), ADD(MUL(f2, g0), MUL(f3_2, g9_19))),
               ADD(ADD(MUL(f4, g8_19), MUL(f5_2, g7_19)), ADD(ADD(MUL(f6, g6_19), MUL(f7_2, g5_19)),
                                                              ADD(MUL(f8, g4_19), MUL(f9_2, g3_19)))));
    t[3] = ADD(ADD(ADD(MUL(f0, g3), MUL(f1, g2)), ADD(MUL(f2, g1), MUL(f3, g0))),
               ADD(ADD(MUL(f4, g9_19), MUL(f5, g8_19)), ADD(ADD(MUL(f6, g7_19), MUL(f7, g6_19)),
                                                            ADD(MUL(f8, g5_19), MUL(f9, g4_19)))));
    t[4] = ADD(ADD(ADD(MUL(f0, g4), MUL(f1_2, g3)), ADD(MUL(f2, g2), MUL(f3_2, g1))),
               ADD(ADD(MUL(f4, g0), MUL(f5_2, g9_19)), ADD(ADD(MUL(f6, g8_19), MUL(f7_2, g7_19)),
                                                           ADD(MUL(f8, g6_19), MUL(f9_2, g5_19)))));
    t[5] = ADD(ADD(ADD(MUL(f0, g5), MUL(f1, g4)), ADD(MUL(f2, g3), MUL(f3, g2))),
               ADD(ADD(MUL(f4, g1), MUL(f5, g0)), ADD(ADD(MUL(f6, g9_19), MUL(f7, g8_19)),
                                                      ADD(MUL(f8, g7_19), MUL(f9, g6_19)))));
    t[6] = ADD(ADD(ADD(MUL(f0, g6), MUL(f1_2, g5)), ADD(MUL(f2, g4), MUL(f3_2, g3))),
               ADD(ADD(MUL(f4, g2), MUL(f5_2, g1)), ADD(ADD(MUL(f6, g0), MUL(f7_2, g9_19)),
                                                        ADD(MUL(f8, g8_19), MUL(f9_2, g7_19)))));
    t[7] = ADD(ADD(ADD(MUL(f0, g7), MUL(f1, g6)), ADD(MUL(f2, g5), MUL(f3, g4))),
               ADD(ADD(MUL(f4, g3), MUL(f5, g2)), ADD(ADD(MUL(f6, g1), MUL(f7, g0)),
                                                      ADD(MUL(f8, g9_19), MUL(f9, g8_19)))));
    t[8] = ADD(ADD(ADD(MUL(f0, g8), MUL(f1_2, g7)), ADD(MUL(f2, g6), MUL(f3_2, g5))),
               ADD(ADD(MUL(f4, g4), MUL(f5_2, g3)), ADD(ADD(MUL(f6, g2), MUL(f7_2, g1)),
                                                        ADD(MUL(f8, g0), MUL(f9_2, g9_19)))));
    t[9] = ADD(ADD(ADD(MUL(f0, g9), MUL(f1, g8)), ADD(MUL(f2, g7), MUL(f3, g6))),
               ADD(ADD(MUL(f4, g5), MUL(f5, g4)), ADD(ADD(MUL(f6, g3), MUL(f7, g2)),
                                                      ADD(MUL(f8, g1), MUL(f9, g0)))));
    fe4_carry_h(t);
    for (int i = 0; i < 10; i++) h->v[i] = t[i];
}

/* f^2 in 55 products (ref10's fe_sq pattern, unsigned) */
T_AVX2 static void fe4_sq(fe4 *h, const fe4 *f)
{
    FE4_MULIN(f);
    const __m256i n19 = _mm256_set1_epi64x(19), n38 = _mm256_set1_epi64x(38);
    __m256i f0 = f->v[0], f1 = f->v[1], f2 = f->v[2], f3 = f->v[3], f4 = f->v[4], f5 = f->v[5], f6 = f->v[6],
            f7 = f->v[7], f8 = f->v[8], f9 = f->v[9];
    __m256i f0_2 = ADD(f0, f0), f1_2 = ADD(f1, f1), f2_2 = ADD(f2, f2), f3_2 = ADD(f3, f3), f4_2 = ADD(f4, f4),
            f5_2 = ADD(f5, f5), f6_2 = ADD(f6, f6), f7_2 = ADD(f7, f7);
    __m256i f5_38 = MUL(f5, n38), f6_19 = MUL(f6, n19), f7_38 = MUL(f7, n38), f8_19 = MUL(f8, n19), f9_38 = MUL(f9, n38);
    __m256i t[10];
    t[0] = ADD(ADD(ADD(MUL(f0, f0), MUL(f1_2, f9_38)), ADD(MUL(f2_2, f8_19), MUL(f3_2, f7_38))),
               ADD(MUL(f4_2, f6_19), MUL(f5, f5_38)));
    t[1] = ADD(ADD(ADD(MUL(f0_2, f1), MUL(f2, f9_38)), ADD(MUL(f3_2, f8_19), MUL(f4, f7_38))), MUL(f5_2, f6_19));
    t[2] = ADD(ADD(ADD(MUL(f0_2, f2), MUL(f1_2, f1)), ADD(MUL(f3_2, f9_38), MUL(f4_2, f8_19))),
               ADD(MUL(f5_2, f7_38), MUL(f6, f6_19)));
    t[3] = ADD(ADD(ADD(MUL(f0_2, f3), MUL(f1_2, f2)), ADD(MUL(f4, f9_38), MUL(f5_2, f8_19))), MUL(f6, f7_38));
    t[4] = ADD(ADD(ADD(MUL(f0_2, f4), MUL(f1_2, f3_2)), ADD(MUL(f2, f2), MUL(f5_2, f9_38))),
               ADD(MUL(f6_2, f8_19), MUL(f7, f7_38)));
    t[5] = ADD(ADD(ADD(MUL(f0_2, f5), MUL(f1_2, f4)), ADD(MUL(f2_2, f3), MUL(f6, f9_38))), MUL(f7_2, f8_19));
    t[6] = ADD(ADD(ADD(MUL(f0_2, f6), MUL(f1_2, f5_2)), ADD(MUL(f2_2, f4), MUL(f3_2, f3))),
               ADD(MUL(f7_2, f9_38), MUL(f8, f8_19)));
    t[7] = ADD(ADD(ADD(MUL(f0_2, f7), MUL(f1_2, f6)), ADD(MUL(f2_2, f5), MUL(f3_2, f4))), MUL(f8, f9_38));
    t[8] = ADD(ADD(ADD(MUL(f0_2, f8), MUL(f1_2, f7_2)), ADD(MUL(f2_2, f6), MUL(f3_2, f5_2))),
               ADD(MUL(f4, f4), MUL(f9, f9_38)));
    t[9] = ADD(ADD(ADD(MUL(f0_2, f9), MUL(f1_2, f8)), ADD(MUL(f2_2, f7), MUL(f3_2, f6))), MUL(f4_2, f5));
    fe4_carry_h(t);
    for (int i = 0; i < 10; i++) h->v[i] = t[i];
}
#undef MUL
#undef ADD

/* four radix-2^51 elements (each below 2^52 per limb) into the lanes, in order */
T_AVX2 static void fe4_from(fe4 *h, const fe *a, const fe *b, const fe *c, const fe *d)
{
    const __m256i m26 = _mm256_set1_epi64x((long long)M26);
    for (int j = 0; j < 5; j++) {
        __m256i x = _mm256_set_epi64x((long long)d->v[j], (long long)c->v[j], (long long)b->v[j], (long long)a->v[j]);
        h->v[2 * j] = _mm256_and_si256(x, m26);
        h->v[2 * j + 1] = _mm256_srli_epi64(x, 26);
    }
}

/* the lanes back as radix-2^51 elements (limbs below 2^53: carry before use where it matters) */
T_AVX2 static void fe4_to(fe *a, fe *b, fe *c, fe *d, const fe4 *h)
{
    for (int j = 0; j < 5; j++) {
        uint64_t x[4];
        _mm256_storeu_si256((__m256i *)x, _mm256_add_epi64(h->v[2 * j], _mm256_slli_epi64(h->v[2 * j + 1], 26)));
        a->v[j] = x[0], b->v[j] = x[1], c->v[j] = x[2], d->v[j] = x[3];
    }
}
#endif /* __x86_64__ */

/* ---- the group: -x^2 + y^2 = 1 + d x^2 y^2 ------------------------------------------
 *
 * Extended coordinates (Hisil, Wong, Carter, Dawson 2008) with the formulas for
 * a = -1, as in ref10:
 *   p2     (X:Y:Z)          x = X/Z, y = Y/Z
 *   p3     (X:Y:Z:T)        also XY = ZT
 *   p1p1   ((X:Z), (Y:T))   x = X/Z, y = Y/T: what doubling and addition return
 *   precomp (y+x, y-x, 2dxy) affine (Z = 1); cached (Y+X, Y-X, Z, 2dT)
 * Every coordinate of a p2/p3 point is a fe_mul output (carried). */

typedef struct ge_p2 {
    fe X, Y, Z;
} ge_p2;
typedef struct ge_p3 {
    fe X, Y, Z, T;
} ge_p3;
typedef struct ge_p1p1 {
    fe X, Y, Z, T;
} ge_p1p1;
typedef struct ge_precomp {
    fe ypx, ymx, xy2d;
} ge_precomp;
typedef struct ge_cached {
    fe ypx, ymx, Z, T2d;
} ge_cached;

/* Derived once, from their definitions (no field constants are typed in). */
static fe g_d, g_d2, g_sqrtm1;
static ge_p3 g_B;
static ge_precomp g_comb[32][8]; /* g_comb[i][j] = (j + 1) * 256^i * B: the signing comb */
static ge_precomp g_bodd[32];    /* (2k + 1) * B: verification, wNAF width 7 */
static pthread_once_t g_once = PTHREAD_ONCE_INIT;

static void ge_p3_0(ge_p3 *h)
{
    fe_0(&h->X);
    fe_1(&h->Y);
    fe_1(&h->Z);
    fe_0(&h->T);
}

static void ge_p3_to_p2(ge_p2 *r, const ge_p3 *p)
{
    r->X = p->X;
    r->Y = p->Y;
    r->Z = p->Z;
}

static void ge_p3_to_cached(ge_cached *r, const ge_p3 *p)
{
    fe_add(&r->ypx, &p->Y, &p->X);
    fe_carry(&r->ypx);
    fe_sub(&r->ymx, &p->Y, &p->X);
    fe_carry(&r->ymx);
    r->Z = p->Z;
    fe_mul(&r->T2d, &p->T, &g_d2);
}

static void ge_p1p1_to_p2(ge_p2 *r, const ge_p1p1 *p)
{
    fe_mul(&r->X, &p->X, &p->T);
    fe_mul(&r->Y, &p->Y, &p->Z);
    fe_mul(&r->Z, &p->Z, &p->T);
}

static void ge_p1p1_to_p3(ge_p3 *r, const ge_p1p1 *p)
{
    fe_mul(&r->X, &p->X, &p->T);
    fe_mul(&r->Y, &p->Y, &p->Z);
    fe_mul(&r->Z, &p->Z, &p->T);
    fe_mul(&r->T, &p->X, &p->Y);
}

/* 2p. A = X^2, B = Y^2, C = 2Z^2: x = E/(B - A), y = (A + B)/(C + A - B) with
 * E = (X + Y)^2 - A - B. (ref10 forms C - (B - A); here (C + A) - B keeps every
 * subtrahend a carried value.) */
static void ge_p2_dbl(ge_p1p1 *r, const ge_p2 *p)
{
    fe t0;
    fe_sq(&r->X, &p->X);
    fe_sq(&r->Z, &p->Y);
    fe_sq(&r->T, &p->Z);
    fe_add(&r->T, &r->T, &r->T);
    fe_add(&r->T, &r->T, &r->X);
    fe_sub(&r->T, &r->T, &r->Z);
    fe_add(&r->Y, &p->X, &p->Y);
    fe_sq(&t0, &r->Y);
    fe_add(&r->Y, &r->Z, &r->X);
    fe_sub(&r->Z, &r->Z, &r->X);
    fe_sub(&r->X, &t0, &r->Y);
}

static void ge_p3_dbl(ge_p1p1 *r, const ge_p3 *p)
{
    ge_p2 q;
    ge_p3_to_p2(&q, p);
    ge_p2_dbl(r, &q);
}

/* p + q, q affine: A = (Y-X)(y-x), B = (Y+X)(y+x), C = T 2dxy, D = 2Z;
 * x = (B - A)/(D + C), y = (B + A)/(D - C). */
static void ge_madd(ge_p1p1 *r, const ge_p3 *p, const ge_precomp *q)
{
    fe t0;
    fe_add(&r->X, &p->Y, &p->X);
    fe_sub(&r->Y, &p->Y, &p->X);
    fe_mul(&r->Z, &r->X, &q->ypx);
    fe_mul(&r->Y, &r->Y, &q->ymx);
    fe_mul(&r->T, &q->xy2d, &p->T);
    fe_add(&t0, &p->Z, &p->Z);
    fe_sub(&r->X, &r->Z, &r->Y);
    fe_add(&r->Y, &r->Z, &r->Y);
    fe_add(&r->Z, &t0, &r->T);
    fe_sub(&r->T, &t0, &r->T);
}

/* p - q, q affine (-q swaps y+x and y-x and negates 2dxy). */
static void ge_msub(ge_p1p1 *r, const ge_p3 *p, const ge_precomp *q)
{
    fe t0;
    fe_add(&r->X, &p->Y, &p->X);
    fe_sub(&r->Y, &p->Y, &p->X);
    fe_mul(&r->Z, &r->X, &q->ymx);
    fe_mul(&r->Y, &r->Y, &q->ypx);
    fe_mul(&r->T, &q->xy2d, &p->T);
    fe_add(&t0, &p->Z, &p->Z);
    fe_sub(&r->X, &r->Z, &r->Y);
    fe_add(&r->Y, &r->Z, &r->Y);
    fe_sub(&r->Z, &t0, &r->T);
    fe_add(&r->T, &t0, &r->T);
}

/* p + q, q cached: as madd with D = 2 Z1 Z2. */
static void ge_add(ge_p1p1 *r, const ge_p3 *p, const ge_cached *q)
{
    fe t0;
    fe_add(&r->X, &p->Y, &p->X);
    fe_sub(&r->Y, &p->Y, &p->X);
    fe_mul(&r->Z, &r->X, &q->ypx);
    fe_mul(&r->Y, &r->Y, &q->ymx);
    fe_mul(&r->T, &q->T2d, &p->T);
    fe_mul(&r->X, &p->Z, &q->Z);
    fe_add(&t0, &r->X, &r->X);
    fe_sub(&r->X, &r->Z, &r->Y);
    fe_add(&r->Y, &r->Z, &r->Y);
    fe_add(&r->Z, &t0, &r->T);
    fe_sub(&r->T, &t0, &r->T);
}

static void ge_sub(ge_p1p1 *r, const ge_p3 *p, const ge_cached *q)
{
    fe t0;
    fe_add(&r->X, &p->Y, &p->X);
    fe_sub(&r->Y, &p->Y, &p->X);
    fe_mul(&r->Z, &r->X, &q->ymx);
    fe_mul(&r->Y, &r->Y, &q->ypx);
    fe_mul(&r->T, &q->T2d, &p->T);
    fe_mul(&r->X, &p->Z, &q->Z);
    fe_add(&t0, &r->X, &r->X);
    fe_sub(&r->X, &r->Z, &r->Y);
    fe_add(&r->Y, &r->Z, &r->Y);
    fe_sub(&r->Z, &t0, &r->T);
    fe_add(&r->T, &t0, &r->T);
}

/* y, with x's parity in bit 255. Constant time. */
static void ge_tobytes(uint8_t s[32], const fe *X, const fe *Y, const fe *Z)
{
    fe recip, x, y;
    fe_invert(&recip, Z);
    fe_mul(&x, X, &recip);
    fe_mul(&y, Y, &recip);
    fe_tobytes(s, &y);
    s[31] ^= (uint8_t)(fe_isodd(&x) << 7);
    imdb_wipe(&recip, sizeof recip);
    imdb_wipe(&x, sizeof x);
    imdb_wipe(&y, sizeof y);
}

/* Decoding as Monocypher does (README: the verification rule): y = the low 255
 * bits, values >= p accepted; x = sqrt((y^2 - 1)/(d y^2 + 1)) by RFC 8032's
 * procedure, rejected when no root exists; x = 0 accepted with either sign
 * bit. negate = true returns -P, the form verification uses. Variable time. */
static bool ge_frombytes_vt(ge_p3 *h, const uint8_t s[32], bool negate)
{
    fe u, v, v3, vxx, t;
    fe_frombytes(&h->Y, s);
    fe_1(&h->Z);
    fe_sq(&u, &h->Y);
    fe_mul(&v, &u, &g_d);
    fe_sub(&u, &u, &h->Z);    /* y^2 - 1 */
    fe_add(&v, &v, &h->Z);    /* d y^2 + 1 */
    fe_sq(&v3, &v);
    fe_mul(&v3, &v3, &v);     /* v^3 */
    fe_sq(&h->X, &v3);
    fe_mul(&h->X, &h->X, &v);
    fe_mul(&h->X, &h->X, &u); /* u v^7 */
    fe_pow22523(&h->X, &h->X);
    fe_mul(&h->X, &h->X, &v3);
    fe_mul(&h->X, &h->X, &u); /* candidate root u v^3 (u v^7)^((p-5)/8) */
    fe_sq(&vxx, &h->X);
    fe_mul(&vxx, &vxx, &v);
    if (!fe_equal_vt(&vxx, &u)) {
        fe_add(&t, &vxx, &u);
        if (!fe_iszero_vt(&t)) return false; /* (y^2 - 1)/(d y^2 + 1) is not a square */
        fe_mul(&h->X, &h->X, &g_sqrtm1);
    }
    if ((fe_isodd(&h->X) == (s[31] >> 7)) == negate) {
        fe_neg(&h->X, &h->X);
        fe_carry(&h->X);
    }
    fe_mul(&h->T, &h->X, &h->Y);
    return true;
}

/* n points to affine precomp form with one inversion (Montgomery's trick). */
static void ge_batch_precomp(ge_precomp *out, const ge_p3 *in, size_t n, fe *prefix)
{
    prefix[0] = in[0].Z;
    for (size_t i = 1; i < n; i++) fe_mul(&prefix[i], &prefix[i - 1], &in[i].Z);
    fe inv, zinv, x, y;
    fe_invert(&inv, &prefix[n - 1]);
    for (size_t i = n; i-- > 0;) {
        if (i > 0) {
            fe_mul(&zinv, &inv, &prefix[i - 1]);
            fe_mul(&inv, &inv, &in[i].Z);
        } else {
            zinv = inv;
        }
        fe_mul(&x, &in[i].X, &zinv);
        fe_mul(&y, &in[i].Y, &zinv);
        fe_add(&out[i].ypx, &y, &x);
        fe_carry(&out[i].ypx);
        fe_sub(&out[i].ymx, &y, &x);
        fe_carry(&out[i].ymx);
        fe_mul(&out[i].xy2d, &x, &y);
        fe_mul(&out[i].xy2d, &out[i].xy2d, &g_d2);
    }
}

#ifdef HAVE_FE4
/* ---- four signatures at a time (horizontal: lane k holds signature k) ----------------
 *
 * The batch's per-signature work: decoding -R_k and its odd multiples. These are the
 * scalar formulas on fe4, with a carry wherever a sum or difference would pass
 * fe4_mul's input bound (the bounds of the four-way field above). The decision steps
 * of the decoding run per lane on the scalar field, as in ge_frombytes_vt. */

typedef struct ge4_p3 {
    fe4 X, Y, Z, T;
} ge4_p3;
typedef struct ge4_p1p1 {
    fe4 X, Y, Z, T;
} ge4_p1p1;
typedef struct ge4_cached {
    fe4 ypx, ymx, Z, Z2, T2d; /* Z2 = 2 Z, for ge4_add; Z, for the scalar cached points */
} ge4_cached;

/* f - g for g up to 4p's limbs (the sum of two carried values); output < f + 4p */
T_AVX2 static void fe4_sub4(fe4 *h, const fe4 *f, const fe4 *g)
{
    FE4_SUBTRAHEND4(g);
    for (int i = 0; i < 10; i++)
        h->v[i] = _mm256_sub_epi64(_mm256_add_epi64(f->v[i], _mm256_add_epi64(p2_limb(i), p2_limb(i))), g->v[i]);
}

T_AVX2 static void fe4_bcast(fe4 *h, const fe *f) { fe4_from(h, f, f, f, f); }

T_AVX2 static void fe4_sqn(fe4 *h, const fe4 *f, int n)
{
    fe4_sq(h, f);
    for (int i = 1; i < n; i++) fe4_sq(h, h);
}

/* z^((p - 5) / 8), the chain of fe_pow22523 */
T_AVX2 static void fe4_pow22523(fe4 *out, const fe4 *z)
{
    fe4 t0, t1, t2, z9, z11;
    fe4_sq(&t0, z);
    fe4_sqn(&t1, &t0, 2);
    fe4_mul(&z9, z, &t1);
    fe4_mul(&z11, &t0, &z9);
    fe4_sq(&t0, &z11);
    fe4_mul(&t0, &t0, &z9); /* 2^5 - 1 */
    fe4_sqn(&t1, &t0, 5);
    fe4_mul(&t0, &t1, &t0); /* 2^10 - 1 */
    fe4_sqn(&t1, &t0, 10);
    fe4_mul(&t1, &t1, &t0); /* 2^20 - 1 */
    fe4_sqn(&t2, &t1, 20);
    fe4_mul(&t1, &t2, &t1); /* 2^40 - 1 */
    fe4_sqn(&t1, &t1, 10);
    fe4_mul(&t0, &t1, &t0); /* 2^50 - 1 */
    fe4_sqn(&t1, &t0, 50);
    fe4_mul(&t1, &t1, &t0); /* 2^100 - 1 */
    fe4_sqn(&t2, &t1, 100);
    fe4_mul(&t1, &t2, &t1); /* 2^200 - 1 */
    fe4_sqn(&t1, &t1, 50);
    fe4_mul(&t0, &t1, &t0); /* 2^250 - 1 */
    fe4_sqn(&t0, &t0, 2);   /* 2^252 - 4 */
    fe4_mul(out, &t0, z);   /* 2^252 - 3 */
}

/* -P for four encodings, decoded as ge_frombytes_vt(.., true) decodes each; ok[k] is
 * false where lane k does not decode. Variable time (public data only). */
T_AVX2 static void ge4_decode_neg(ge_p3 out[4], bool ok[4], const uint8_t *const s[4])
{
    fe y[4], one;
    for (int k = 0; k < 4; k++) fe_frombytes(&y[k], s[k]);
    fe_1(&one);
    fe4 Y, ONE, D, u, v, v3, x, vxx;
    fe4_from(&Y, &y[0], &y[1], &y[2], &y[3]);
    fe4_bcast(&ONE, &one);
    fe4_bcast(&D, &g_d);
    fe4_sq(&u, &Y);
    fe4_mul(&v, &u, &D);
    fe4_sub(&u, &u, &ONE); /* y^2 - 1 */
    fe4_add(&v, &v, &ONE); /* d y^2 + 1 */
    fe4_sq(&v3, &v);
    fe4_mul(&v3, &v3, &v);
    fe4_sq(&x, &v3);
    fe4_mul(&x, &x, &v);
    fe4_mul(&x, &x, &u); /* u v^7 */
    fe4_pow22523(&x, &x);
    fe4_mul(&x, &x, &v3);
    fe4_mul(&x, &x, &u); /* the candidate root u v^3 (u v^7)^((p-5)/8) */
    fe4_sq(&vxx, &x);
    fe4_mul(&vxx, &vxx, &v);
    fe X[4], VXX[4], U[4];
    fe4_to(&X[0], &X[1], &X[2], &X[3], &x);
    fe4_to(&VXX[0], &VXX[1], &VXX[2], &VXX[3], &vxx);
    fe4_to(&U[0], &U[1], &U[2], &U[3], &u);
    for (int k = 0; k < 4; k++) {
        ge_p3 *h = &out[k];
        h->X = X[k];
        h->Y = y[k];
        fe_1(&h->Z);
        fe_carry(&h->X);
        fe_carry(&VXX[k]);
        fe_carry(&U[k]);
        ok[k] = true;
        if (!fe_equal_vt(&VXX[k], &U[k])) {
            fe t;
            fe_add(&t, &VXX[k], &U[k]);
            if (!fe_iszero_vt(&t)) { /* not a square */
                ok[k] = false;
                continue;
            }
            fe_mul(&h->X, &h->X, &g_sqrtm1);
        }
        if (fe_isodd(&h->X) == (s[k][31] >> 7)) { /* -P: the root of the other sign */
            fe_neg(&h->X, &h->X);
            fe_carry(&h->X);
        }
        fe_mul(&h->T, &h->X, &h->Y);
    }
}

T_AVX2 static void ge4_from_p3(ge4_p3 *h, const ge_p3 p[4])
{
    fe4_from(&h->X, &p[0].X, &p[1].X, &p[2].X, &p[3].X);
    fe4_from(&h->Y, &p[0].Y, &p[1].Y, &p[2].Y, &p[3].Y);
    fe4_from(&h->Z, &p[0].Z, &p[1].Z, &p[2].Z, &p[3].Z);
    fe4_from(&h->T, &p[0].T, &p[1].T, &p[2].T, &p[3].T);
}

T_AVX2 static void ge4_to_cached(ge4_cached *r, const ge4_p3 *p, const fe4 *d2)
{
    fe4_add(&r->ypx, &p->Y, &p->X);
    fe4_sub(&r->ymx, &p->Y, &p->X);
    r->Z = p->Z;
    fe4_add(&r->Z2, &p->Z, &p->Z);
    fe4_mul(&r->T2d, &p->T, d2);
}

/* the lanes as four scalar cached points, carried */
T_AVX2 static void ge4_cached_out(ge_cached out[4], const ge4_cached *c)
{
    fe4_to(&out[0].ypx, &out[1].ypx, &out[2].ypx, &out[3].ypx, &c->ypx);
    fe4_to(&out[0].ymx, &out[1].ymx, &out[2].ymx, &out[3].ymx, &c->ymx);
    fe4_to(&out[0].Z, &out[1].Z, &out[2].Z, &out[3].Z, &c->Z);
    fe4_to(&out[0].T2d, &out[1].T2d, &out[2].T2d, &out[3].T2d, &c->T2d);
    for (int k = 0; k < 4; k++) {
        fe_carry(&out[k].ypx);
        fe_carry(&out[k].ymx);
        fe_carry(&out[k].Z);
        fe_carry(&out[k].T2d);
    }
}

/* p + q (the formulas of ge_add, with Z1 2Z2 from the cached 2Z) */
T_AVX2 static void ge4_add(ge4_p1p1 *r, const ge4_p3 *p, const ge4_cached *q)
{
    fe4 a, b, c, d;
    fe4_add(&a, &p->Y, &p->X);
    fe4_sub(&b, &p->Y, &p->X);
    fe4_mul(&a, &a, &q->ypx);
    fe4_mul(&b, &b, &q->ymx);
    fe4_mul(&c, &q->T2d, &p->T);
    fe4_mul(&d, &p->Z, &q->Z2);
    fe4_sub(&r->X, &a, &b);
    fe4_add(&r->Y, &a, &b);
    fe4_add(&r->Z, &d, &c);
    fe4_sub(&r->T, &d, &c);
}

T_AVX2 static void ge4_p1p1_to_p3(ge4_p3 *r, const ge4_p1p1 *p)
{
    fe4 x, y, z, t;
    fe4_mul(&x, &p->X, &p->T);
    fe4_mul(&y, &p->Y, &p->Z);
    fe4_mul(&z, &p->Z, &p->T);
    fe4_mul(&t, &p->X, &p->Y);
    r->X = x, r->Y = y, r->Z = z, r->T = t;
}

/* 2p (the formulas of ge_p2_dbl, with the two carries the four-way bounds need) */
T_AVX2 static void ge4_dbl(ge4_p1p1 *r, const ge4_p3 *p)
{
    fe4 t0;
    fe4_sq(&r->X, &p->X);
    fe4_sq(&r->Z, &p->Y);
    fe4_sq(&r->T, &p->Z);
    fe4_add(&r->T, &r->T, &r->T);
    fe4_add(&r->T, &r->T, &r->X);
    fe4_sub(&r->T, &r->T, &r->Z);
    fe4_carry(&r->T);
    fe4_add(&r->Y, &p->X, &p->Y);
    fe4_sq(&t0, &r->Y);
    fe4_add(&r->Y, &r->Z, &r->X);
    fe4_sub(&r->Z, &r->Z, &r->X);
    fe4_sub4(&r->X, &t0, &r->Y);
    fe4_carry(&r->X);
}

/* (2k + 1) P for k < 8, for four points P at once, as cached points */
T_AVX2 static void ge4_odd_multiples(ge_cached out[4][8], const ge_p3 p[4])
{
    fe4 d2;
    fe4_bcast(&d2, &g_d2);
    ge4_p3 P, P2;
    ge4_p1p1 r;
    ge4_cached c2, c;
    ge4_from_p3(&P, p);
    ge4_dbl(&r, &P);
    ge4_p1p1_to_p3(&P2, &r);
    ge4_to_cached(&c2, &P2, &d2);
    for (int k = 0; k < 8; k++) {
        if (k) {
            ge4_add(&r, &P, &c2);
            ge4_p1p1_to_p3(&P, &r);
        }
        ge4_to_cached(&c, &P, &d2);
        ge_cached lane[4];
        ge4_cached_out(lane, &c);
        for (int j = 0; j < 4; j++) out[j][k] = lane[j];
    }
}
/* ---- one point at a time (vertical: the lanes are X, Y, Z, T) -----------------------
 *
 * The parallel formulas of Hisil, Wong, Carter and Dawson (2008), arranged as
 * curve25519-dalek's AVX2 backend arranges them: an addition is two four-way
 * multiplications, a doubling one squaring and one multiplication, with lane
 * permutations and blends between them. A cached point is (Y - X, Y + X, 2Z, 2dT). */

#define LANES(l0, l1, l2, l3) ((l0) | (l1) << 2 | (l2) << 4 | (l3) << 6)
#define FE4_PERMUTE(h, f, imm)                                                                         \
    do {                                                                                               \
        for (int i_ = 0; i_ < 10; i_++) (h)->v[i_] = _mm256_permute4x64_epi64((f)->v[i_], (imm));      \
    } while (0)
/* 64-bit lane k from g where bit k of m is set, else from f */
#define BLEND64(m) (((m) & 1 ? 0x03 : 0) | ((m) & 2 ? 0x0c : 0) | ((m) & 4 ? 0x30 : 0) | ((m) & 8 ? 0xc0 : 0))
#define FE4_BLEND(h, f, g, m)                                                                          \
    do {                                                                                               \
        for (int i_ = 0; i_ < 10; i_++) (h)->v[i_] = _mm256_blend_epi32((f)->v[i_], (g)->v[i_], BLEND64(m)); \
    } while (0)

/* P + Q, Q cached. Each limb vector goes through its permutations in registers in one
 * pass between the two multiplications (separate passes per operation cost more than
 * the multiplications save). */
T_AVX2 static void gev_add(fe4 *r, const fe4 *p, const fe4 *q)
{
    fe4 r1, m, l, rr;
    for (int i = 0; i < 10; i++) {
        __m256i v = p->v[i], p2 = p2_limb(i);
        __m256i a = _mm256_permute4x64_epi64(v, LANES(1, 1, 2, 3)); /* (Y, Y, Z, T) */
        __m256i x = _mm256_permute4x64_epi64(v, LANES(0, 0, 2, 3));
        __m256i d = _mm256_sub_epi64(_mm256_add_epi64(a, p2), x);
        __m256i s = _mm256_add_epi64(a, x);
        r1.v[i] = _mm256_blend_epi32(_mm256_blend_epi32(a, d, BLEND64(1)), s, BLEND64(2)); /* (Y - X, Y + X, Z, T) */
    }
    fe4_mul(&m, &r1, q); /* (A, B, D, C) */
    for (int i = 0; i < 10; i++) {
        __m256i mm = m.v[i], p2 = p2_limb(i);
        __m256i msw = _mm256_permute4x64_epi64(mm, LANES(1, 0, 3, 2)); /* (B, A, C, D) */
        __m256i sum = _mm256_add_epi64(mm, msw);                       /* (H, H, G, G) */
        __m256i dif = _mm256_sub_epi64(_mm256_add_epi64(msw, p2), mm); /* (E, -E, -F, F) */
        l.v[i] = _mm256_blend_epi32(_mm256_permute4x64_epi64(dif, LANES(0, 0, 3, 0)),
                                    _mm256_permute4x64_epi64(sum, LANES(2, 2, 2, 2)), BLEND64(2)); /* (E, G, F, E) */
        rr.v[i] = _mm256_blend_epi32(_mm256_permute4x64_epi64(sum, LANES(0, 0, 2, 0)),
                                     _mm256_permute4x64_epi64(dif, LANES(3, 3, 3, 3)), BLEND64(1)); /* (F, H, G, H) */
    }
    fe4_mul(r, &l, &rr); /* (EF, GH, FG, EH) */
}

/* -Q for Q cached: (Y + X, Y - X, 2Z, -2dT). Only lane 3 of the difference is kept: the
 * others may wrap and are discarded by the blend. */
T_AVX2 static void gev_cached_neg(fe4 *r, const fe4 *q)
{
    fe4 sw, n;
    FE4_PERMUTE(&sw, q, LANES(1, 0, 2, 3));
    for (int i = 0; i < 10; i++) n.v[i] = _mm256_sub_epi64(p2_limb(i), q->v[i]);
    FE4_BLEND(r, &sw, &n, 8);
}

/* 2P (T unused): ref10's doubling, its p1p1-to-p3 products done as one multiplication;
 * the permutations fused per limb as in gev_add */
T_AVX2 static void gev_dbl(fe4 *r, const fe4 *p)
{
    fe4 s1, sq, e, tp, l, rr;
    __m256i bab[10], bba[10];
    for (int i = 0; i < 10; i++) {
        __m256i v = p->v[i];
        __m256i a = _mm256_permute4x64_epi64(v, LANES(0, 1, 2, 0));
        __m256i y = _mm256_permute4x64_epi64(v, LANES(1, 1, 1, 1));
        s1.v[i] = _mm256_blend_epi32(a, _mm256_add_epi64(a, y), BLEND64(8)); /* (X, Y, Z, X + Y) */
    }
    fe4_sq(&sq, &s1); /* (A, B, Z^2, K) */
    for (int i = 0; i < 10; i++) {
        __m256i q = sq.v[i], p2 = p2_limb(i);
        __m256i sw = _mm256_permute4x64_epi64(q, LANES(1, 0, 3, 2));    /* (B, A, K, Z^2) */
        __m256i v1 = _mm256_add_epi64(q, sw);                           /* lane 0: A + B */
        __m256i v2 = _mm256_sub_epi64(_mm256_add_epi64(sw, p2), q);     /* lane 0: B - A; lane 1: A - B */
        bab[i] = _mm256_permute4x64_epi64(v1, LANES(0, 0, 0, 0));
        bba[i] = _mm256_permute4x64_epi64(v2, LANES(0, 0, 0, 0));
        __m256i amb = _mm256_permute4x64_epi64(v2, LANES(1, 1, 1, 1));
        __m256i k = _mm256_permute4x64_epi64(q, LANES(3, 3, 3, 3));
        __m256i z = _mm256_permute4x64_epi64(q, LANES(2, 2, 2, 2));
        e.v[i] = _mm256_sub_epi64(_mm256_add_epi64(k, _mm256_add_epi64(p2, p2)), bab[i]); /* K - (A + B) + 4p */
        tp.v[i] = _mm256_add_epi64(_mm256_add_epi64(z, z), amb);                         /* 2 Z^2 + A - B */
    }
    fe4_carry(&e);
    fe4_carry(&tp);
    for (int i = 0; i < 10; i++) {
        l.v[i] = _mm256_blend_epi32(_mm256_blend_epi32(e.v[i], bab[i], BLEND64(2)), bba[i], BLEND64(4));
        rr.v[i] = _mm256_blend_epi32(_mm256_blend_epi32(tp.v[i], bba[i], BLEND64(2)), bab[i], BLEND64(8));
    }
    fe4_mul(r, &l, &rr); /* (E Tp, (A + B)(B - A), (B - A) Tp, E (A + B)) */
}

T_AVX2 static void gev_from_p3(fe4 *v, const ge_p3 *p) { fe4_from(v, &p->X, &p->Y, &p->Z, &p->T); }

T_AVX2 static void gev_to_p3(ge_p3 *p, const fe4 *v)
{
    fe4_to(&p->X, &p->Y, &p->Z, &p->T, v);
    fe_carry(&p->X);
    fe_carry(&p->Y);
    fe_carry(&p->Z);
    fe_carry(&p->T);
}

T_AVX2 static void gev_from_cached(fe4 *v, const ge_cached *c)
{
    fe z2;
    fe_add(&z2, &c->Z, &c->Z);
    fe4_from(v, &c->ymx, &c->ypx, &z2, &c->T2d);
}

T_AVX2 static void gev_from_precomp(fe4 *v, const ge_precomp *c)
{
    fe two;
    fe_0(&two);
    two.v[0] = 2;
    fe4_from(v, &c->ymx, &c->ypx, &two, &c->xy2d);
}

T_AVX2 static void gev_identity(fe4 *v)
{
    fe z, o;
    fe_0(&z);
    fe_1(&o);
    fe4_from(v, &z, &o, &o, &z);
}

/* (2k + 1) B as vertical cached points, built once by ed_init where AVX2 exists */
static fe4 g_bodd_v[32];

T_AVX2 static void bodd_vertical(void)
{
    for (int k = 0; k < 32; k++) gev_from_precomp(&g_bodd_v[k], &g_bodd[k]);
}

#endif /* HAVE_FE4 */

static void ed_init(void)
{
    fe a, b;
    fe_0(&a);
    fe_0(&b);
    a.v[0] = 121665;
    b.v[0] = 121666;
    fe_invert(&b, &b);
    fe_neg(&a, &a);
    fe_mul(&g_d, &a, &b); /* d = -121665/121666 */
    fe_add(&g_d2, &g_d, &g_d);
    fe_carry(&g_d2);
    fe_0(&a);
    a.v[0] = 2;
    fe_pow22523(&b, &a);
    fe_sq(&b, &b);
    fe_add(&g_sqrtm1, &b, &b); /* 2^((p-1)/4): 2 is not a square (p = 5 mod 8) */
    fe_carry(&g_sqrtm1);
    fe_0(&a);
    a.v[0] = 5;
    fe_invert(&a, &a);
    fe_add(&a, &a, &a);
    fe_add(&a, &a, &a); /* y = 4/5 */
    fe_carry(&a);
    uint8_t by[32];
    fe_tobytes(by, &a); /* sign bit 0: x even */
    if (!ge_frombytes_vt(&g_B, by, false)) abort();
    /* the comb: 32 rows of 1..8 times 256^i B; and 1B, 3B, ..., 63B */
    static ge_p3 pts[256];
    static fe prefix[256];
    ge_p3 row = g_B;
    ge_p1p1 r;
    ge_cached c;
    for (int i = 0; i < 32; i++) {
        pts[8 * i] = row;
        ge_p3_to_cached(&c, &row);
        for (int j = 1; j < 8; j++) {
            ge_add(&r, &pts[8 * i + j - 1], &c);
            ge_p1p1_to_p3(&pts[8 * i + j], &r);
        }
        for (int k = 0; k < 8; k++) { /* 256 * row */
            ge_p3_dbl(&r, &row);
            ge_p1p1_to_p3(&row, &r);
        }
    }
    ge_batch_precomp(&g_comb[0][0], pts, 256, prefix);
    ge_p3 b2;
    ge_p3_dbl(&r, &g_B);
    ge_p1p1_to_p3(&b2, &r);
    ge_p3_to_cached(&c, &b2);
    pts[0] = g_B;
    for (int k = 1; k < 32; k++) {
        ge_add(&r, &pts[k - 1], &c);
        ge_p1p1_to_p3(&pts[k], &r);
    }
    ge_batch_precomp(g_bodd, pts, 32, prefix);
#ifdef HAVE_FE4
    if (imdb_cpu_get()->avx2) bodd_vertical();
#endif
}

static void ed_ready(void) { pthread_once(&g_once, ed_init); }

/* The four-way field on CPUs with AVX2, unless a test turned it off. */
static bool g_fe4_off;

static bool use_fe4(void)
{
#ifdef HAVE_FE4
    return !g_fe4_off && imdb_cpu_get()->avx2;
#else
    return false;
#endif
}

void imdb_ed25519_set_fe4(bool on) { g_fe4_off = !on; }

/* ---- [a]B, constant time (signing) ------------------------------------------------- */

/* all ones iff a == b */
static u64 eq_mask(u64 a, u64 b)
{
    u64 x = a ^ b;
    return ((x | (0 - x)) >> 63) - 1;
}

static void precomp_cmov(ge_precomp *t, const ge_precomp *u, u64 mask)
{
    fe_cmov(&t->ypx, &u->ypx, mask);
    fe_cmov(&t->ymx, &u->ymx, mask);
    fe_cmov(&t->xy2d, &u->xy2d, mask);
}

/* t = b * 256^row * B for a digit b in [-8, 8]: every entry is read, the right one
 * kept by mask, and the sign applied by mask. */
static void comb_select(ge_precomp *t, int row, int8_t b)
{
    u64 bu = (u64)(int64_t)b;
    u64 neg = 0 - (bu >> 63);
    u64 babs = (bu ^ neg) - neg;
    fe_1(&t->ypx);
    fe_1(&t->ymx);
    fe_0(&t->xy2d);
    for (int j = 0; j < 8; j++) precomp_cmov(t, &g_comb[row][j], eq_mask(babs, (u64)j + 1));
    ge_precomp minus;
    minus.ypx = t->ymx;
    minus.ymx = t->ypx;
    fe_neg(&minus.xy2d, &t->xy2d);
    fe_carry(&minus.xy2d);
    precomp_cmov(t, &minus, neg);
    imdb_wipe(&minus, sizeof minus);
}

/* h = [a]B for a < 2^255 (a clamped secret scalar or a value reduced mod L): 64
 * signed radix-16 digits in [-8, 8]; odd digits first, times 16, then the even
 * ones. 64 mixed additions, 4 doublings, no branch on a. */
static void ge_scalarmult_base(ge_p3 *h, const uint8_t a[32])
{
#ifdef IMDB_FE_CHECKS
    if (a[31] & 0x80) fe_bound_fail("comb scalar >= 2^255");
#endif
    int8_t e[64];
    for (int i = 0; i < 32; i++) {
        e[2 * i] = (int8_t)(a[i] & 15);
        e[2 * i + 1] = (int8_t)(a[i] >> 4);
    }
    int8_t carry = 0;
    for (int i = 0; i < 63; i++) {
        e[i] = (int8_t)(e[i] + carry);
        carry = (int8_t)((e[i] + 8) >> 4);
        e[i] = (int8_t)(e[i] - carry * 16);
    }
    e[63] = (int8_t)(e[63] + carry);
    ge_p1p1 r;
    ge_p2 s;
    ge_precomp t;
    ge_p3_0(h);
    for (int i = 1; i < 64; i += 2) {
        comb_select(&t, i / 2, e[i]);
        ge_madd(&r, h, &t);
        ge_p1p1_to_p3(h, &r);
    }
    ge_p3_dbl(&r, h);
    ge_p1p1_to_p2(&s, &r);
    ge_p2_dbl(&r, &s);
    ge_p1p1_to_p2(&s, &r);
    ge_p2_dbl(&r, &s);
    ge_p1p1_to_p2(&s, &r);
    ge_p2_dbl(&r, &s);
    ge_p1p1_to_p3(h, &r);
    for (int i = 0; i < 64; i += 2) {
        comb_select(&t, i / 2, e[i]);
        ge_madd(&r, h, &t);
        ge_p1p1_to_p3(h, &r);
    }
    imdb_wipe(e, sizeof e);
    imdb_wipe(&r, sizeof r);
    imdb_wipe(&s, sizeof s);
    imdb_wipe(&t, sizeof t);
}

/* [k]P by plain double-and-add, any 256-bit k. Variable time: tests only. */
static void ge_scalarmult_vt(ge_p3 *h, const uint8_t k[32], const ge_p3 *p)
{
    ge_cached c;
    ge_p1p1 r;
    ge_p3_to_cached(&c, p);
    ge_p3_0(h);
    for (int i = 255; i >= 0; i--) {
        ge_p3_dbl(&r, h);
        ge_p1p1_to_p3(h, &r);
        if (k[i / 8] >> (i % 8) & 1) {
            ge_add(&r, h, &c);
            ge_p1p1_to_p3(h, &r);
        }
    }
}

/* ---- scalars mod L = 2^252 + 27742317777372353535851937790883648493 -------------------- */

static const u64 L64[4] = {0x5812631a5cf5d3edull, 0x14def9dea2f79cd6ull, 0, 0x1000000000000000ull};
/* floor(2^512 / L), 260 bits (computed with bc; Monocypher's mod_l uses the same constant) */
static const u64 MU[5] = {0xed9ce5a30a2c131bull, 0x2106215d086329a7ull, 0xffffffffffffffebull, 0xffffffffffffffffull, 0xf};

static void sc_load(u64 *r, const uint8_t *s, int limbs)
{
    for (int i = 0; i < limbs; i++) {
        r[i] = 0;
        for (int b = 7; b >= 0; b--) r[i] = (r[i] << 8) | s[8 * i + b];
    }
}

static void sc_store(uint8_t s[32], const u64 r[4])
{
    for (int i = 0; i < 4; i++)
        for (int b = 0; b < 8; b++) s[8 * i + b] = (uint8_t)(r[i] >> (8 * b));
}

/* r = x mod L for x < 2^512. Barrett: q = floor(x MU / 2^512) is floor(x/L) or one
 * less, so x - q L lies in [0, 2L), which fits 256 bits and needs one subtraction
 * of L, applied by mask. Constant time. */
static void sc_reduce512(u64 r[4], const u64 x[8])
{
    u64 prod[13] = {0};
    for (int i = 0; i < 8; i++) {
        u128 carry = 0;
        for (int j = 0; j < 5; j++) {
            u128 t = (u128)x[i] * MU[j] + prod[i + j] + carry;
            prod[i + j] = (u64)t;
            carry = t >> 64;
        }
        prod[i + 5] = (u64)carry;
    }
    const u64 *q = prod + 8;
    u64 ql[4] = {0}; /* q L mod 2^256 */
    for (int i = 0; i < 4; i++) {
        u128 carry = 0;
        for (int j = 0; i + j < 4; j++) {
            u128 t = (u128)q[i] * L64[j] + ql[i + j] + carry;
            ql[i + j] = (u64)t;
            carry = t >> 64;
        }
    }
    u64 t[4], borrow = 0;
    for (int i = 0; i < 4; i++) { /* r = x - q L (mod 2^256): exact, the true value is < 2L */
        u128 d = (u128)x[i] - ql[i] - borrow;
        t[i] = (u64)d;
        borrow = (u64)(d >> 64) & 1;
    }
    u64 s[4];
    borrow = 0;
    for (int i = 0; i < 4; i++) {
        u128 d = (u128)t[i] - L64[i] - borrow;
        s[i] = (u64)d;
        borrow = (u64)(d >> 64) & 1;
    }
    u64 keep = 0 - borrow; /* all ones when t < L */
    for (int i = 0; i < 4; i++) r[i] = (t[i] & keep) | (s[i] & ~keep);
    imdb_wipe(prod, sizeof prod);
    imdb_wipe(ql, sizeof ql);
    imdb_wipe(t, sizeof t);
    imdb_wipe(s, sizeof s);
}

static void sc_reduce(uint8_t out[32], const uint8_t in[64])
{
    u64 x[8], r[4];
    sc_load(x, in, 8);
    sc_reduce512(r, x);
    sc_store(out, r);
    imdb_wipe(x, sizeof x);
    imdb_wipe(r, sizeof r);
}

/* s = (a b + c) mod L for any 256-bit a, b, c: a b < 2^512 is reduced, then
 * (that + c) < 2^257. Constant time. */
static void sc_muladd(uint8_t s[32], const uint8_t a[32], const uint8_t b[32], const uint8_t c[32])
{
    u64 A[4], B[4], C[4], x[8] = {0}, r[4];
    sc_load(A, a, 4);
    sc_load(B, b, 4);
    sc_load(C, c, 4);
    for (int i = 0; i < 4; i++) {
        u128 carry = 0;
        for (int j = 0; j < 4; j++) {
            u128 t = (u128)A[i] * B[j] + x[i + j] + carry;
            x[i + j] = (u64)t;
            carry = t >> 64;
        }
        x[i + 4] = (u64)carry;
    }
    sc_reduce512(r, x);
    u128 carry = 0;
    for (int i = 0; i < 4; i++) {
        u128 t = (u128)r[i] + C[i] + carry;
        x[i] = (u64)t;
        carry = t >> 64;
    }
    x[4] = (u64)carry;
    x[5] = x[6] = x[7] = 0;
    sc_reduce512(r, x);
    sc_store(s, r);
    imdb_wipe(A, sizeof A);
    imdb_wipe(B, sizeof B);
    imdb_wipe(C, sizeof C);
    imdb_wipe(x, sizeof x);
    imdb_wipe(r, sizeof r);
}

/* S < L (public data). */
static bool sc_below_l_vt(const uint8_t s[32])
{
    u64 v[4];
    sc_load(v, s, 4);
    for (int i = 3; i >= 0; i--)
        if (v[i] != L64[i]) return v[i] < L64[i];
    return false;
}

/* ---- signing and verification ----------------------------------------------------- */

void imdb_ed25519_expand(const uint8_t seed[32], uint8_t a[32], uint8_t prefix[32], uint8_t pk[32])
{
    ed_ready();
    uint8_t h[64];
    crypto_sha512(h, seed, 32);
    h[0] &= 248;
    h[31] &= 127;
    h[31] |= 64;
    memcpy(a, h, 32);
    memcpy(prefix, h + 32, 32);
    ge_p3 A;
    ge_scalarmult_base(&A, a);
    ge_tobytes(pk, &A.X, &A.Y, &A.Z);
    imdb_wipe(h, sizeof h);
    imdb_wipe(&A, sizeof A);
}

void imdb_ed25519_sign(uint8_t sig[64], const uint8_t a[32], const uint8_t prefix[32], const uint8_t pk[32],
                       const void *msg, size_t n)
{
    ed_ready();
    crypto_sha512_ctx ctx;
    uint8_t hr[64], r[32], hh[64], h[32];
    crypto_sha512_init(&ctx);
    crypto_sha512_update(&ctx, prefix, 32);
    crypto_sha512_update(&ctx, msg, n);
    crypto_sha512_final(&ctx, hr);
    sc_reduce(r, hr); /* the nonce: secret, below L */
    ge_p3 R;
    uint8_t re[32], s[32]; /* sig is written last: it may overlap msg, as Monocypher allows */
    ge_scalarmult_base(&R, r);
    ge_tobytes(re, &R.X, &R.Y, &R.Z);
    crypto_sha512_init(&ctx);
    crypto_sha512_update(&ctx, re, 32);
    crypto_sha512_update(&ctx, pk, 32);
    crypto_sha512_update(&ctx, msg, n);
    crypto_sha512_final(&ctx, hh);
    sc_reduce(h, hh);
    sc_muladd(s, h, a, r); /* S = (h a + r) mod L */
    memcpy(sig, re, 32);
    memcpy(sig + 32, s, 32);
    imdb_wipe(s, sizeof s);
    imdb_wipe(hr, sizeof hr);
    imdb_wipe(r, sizeof r);
    imdb_wipe(&R, sizeof R);
}

/* Width-w NAF: s = sum r[i] 2^i with every nonzero r[i] odd, |r[i]| < 2^(w-1), and at
 * most one nonzero in any w consecutive positions. Returns the highest nonzero
 * position (-1 for 0). Public scalars only. */
static int wnaf_vt(int8_t r[257], const uint8_t s[32], int w)
{
    memset(r, 0, 257);
    int carry = 0, top = -1;
    for (int bit = 0; bit < 257;) {
        int b = bit < 256 ? (s[bit / 8] >> (bit % 8)) & 1 : 0;
        if (b == carry) {
            bit++;
            continue;
        }
        int word = 0;
        for (int k = 0; k < w; k++)
            if (bit + k < 256) word |= ((s[(bit + k) / 8] >> ((bit + k) % 8)) & 1) << k;
        word += carry;
        carry = (word >> (w - 1)) & 1;
        word -= carry << w;
        r[bit] = (int8_t)word;
        top = bit;
        bit += w;
    }
    return top;
}


/* The writer's key is the same commit after commit: -A and its odd multiples
 * (wNAF width 5) are kept per thread, keyed by the encoding. */
typedef struct a_cache {
    bool valid, ok;
    uint8_t pk[32];
    ge_cached t[8]; /* (2k + 1) (-A) */
#ifdef HAVE_FE4
    bool tv_ok;
    fe4 tv[8]; /* the same, vertical (built on first use) */
#endif
} a_cache;
static _Thread_local a_cache t_acache;

static const ge_cached *minus_a_table(const uint8_t pk[32])
{
    a_cache *c = &t_acache;
    if (c->valid && memcmp(c->pk, pk, 32) == 0) return c->ok ? c->t : NULL;
    memcpy(c->pk, pk, 32);
    c->valid = true;
#ifdef HAVE_FE4
    c->tv_ok = false;
#endif
    ge_p3 p, a2;
    c->ok = ge_frombytes_vt(&p, pk, true);
    if (!c->ok) return NULL;
    ge_p1p1 r;
    ge_cached a2c;
    ge_p3_dbl(&r, &p);
    ge_p1p1_to_p3(&a2, &r);
    ge_p3_to_cached(&a2c, &a2);
    ge_p3_to_cached(&c->t[0], &p);
    for (int k = 1; k < 8; k++) {
        ge_add(&r, &p, &a2c);
        ge_p1p1_to_p3(&p, &r);
        ge_p3_to_cached(&c->t[k], &p);
    }
    return c->t;
}

/* [s]B + [h]P, P given by its odd multiples Pi (width 5); B by g_bodd (width 7). */
static void ge_double_scalarmult_vt(ge_p3 *out, const uint8_t s[32], const ge_cached Pi[8], const uint8_t h[32])
{
    int8_t sn[257], hn[257];
    int ts = wnaf_vt(sn, s, 7), th = wnaf_vt(hn, h, 5);
    int i = ts > th ? ts : th;
    ge_p3_0(out);
    if (i < 0) return;
    ge_p2 r;
    ge_p3_to_p2(&r, out);
    ge_p1p1 t;
    ge_p3 u;
    for (; i >= 0; i--) {
        ge_p2_dbl(&t, &r);
        if (sn[i]) {
            ge_p1p1_to_p3(&u, &t);
            if (sn[i] > 0) ge_madd(&t, &u, &g_bodd[sn[i] / 2]);
            else ge_msub(&t, &u, &g_bodd[-sn[i] / 2]);
        }
        if (hn[i]) {
            ge_p1p1_to_p3(&u, &t);
            if (hn[i] > 0) ge_add(&t, &u, &Pi[hn[i] / 2]);
            else ge_sub(&t, &u, &Pi[-hn[i] / 2]);
        }
        if (i > 0) ge_p1p1_to_p2(&r, &t);
        else ge_p1p1_to_p3(out, &t);
    }
}

#ifdef HAVE_FE4
/* the vertical copy of the thread's table of -A (minus_a_table called first) */
T_AVX2 static const fe4 *minus_a_vtable(void)
{
    a_cache *c = &t_acache;
    if (!c->tv_ok) {
        for (int k = 0; k < 8; k++) gev_from_cached(&c->tv[k], &c->t[k]);
        c->tv_ok = true;
    }
    return c->tv;
}

/* acc + d T for a wNAF digit d and a table of odd multiples T */
T_AVX2 static void gev_add_digit(fe4 *acc, const fe4 *tab, int8_t d)
{
    if (d > 0) {
        gev_add(acc, acc, &tab[d / 2]);
    } else if (d < 0) {
        fe4 n;
        gev_cached_neg(&n, &tab[-d / 2]);
        gev_add(acc, acc, &n);
    }
}

#endif

/* Monocypher's rule (vendor/monocypher/README): A and R decode, S < L, and
 * [8]([S]B - [h]A - R) is the identity, h = SHA-512(R || A || M) mod L. */
bool imdb_ed25519_verify(const uint8_t sig[64], const uint8_t pk[32], const void *msg, size_t n)
{
    ed_ready();
    const ge_cached *mA = minus_a_table(pk);
    ge_p3 mR;
    if (!mA || !ge_frombytes_vt(&mR, sig, true) || !sc_below_l_vt(sig + 32)) return false;
    crypto_sha512_ctx ctx;
    uint8_t hh[64], h[32];
    crypto_sha512_init(&ctx);
    crypto_sha512_update(&ctx, sig, 32);
    crypto_sha512_update(&ctx, pk, 32);
    crypto_sha512_update(&ctx, msg, n);
    crypto_sha512_final(&ctx, hh);
    sc_reduce(h, hh);
    ge_p3 sum;
    ge_double_scalarmult_vt(&sum, sig + 32, mA, h); /* scalar: its doublings are cheaper than the four-way ones */
    ge_cached cr;
    ge_p3_to_cached(&cr, &mR);
    ge_p1p1 t;
    ge_add(&t, &sum, &cr);
    ge_p2 q;
    ge_p1p1_to_p2(&q, &t);
    for (int k = 0; k < 3; k++) { /* times the cofactor: small-order parts vanish */
        ge_p2_dbl(&t, &q);
        ge_p1p1_to_p2(&q, &t);
    }
    return fe_iszero_vt(&q.X) && fe_equal_vt(&q.Y, &q.Z);
}

/* ---- batch verification ----------------------------------------------------------- *
 *
 * One key A, signatures (R_i, S_i) on messages M_i, h_i = SHA-512(R_i || A || M_i)
 * mod L. Each single check is [8]([S_i]B - [h_i]A - R_i) = O. With random odd
 * 128-bit z_i the batch checks [8]([sum z_i S_i]B - [sum z_i h_i]A - sum [z_i]R_i)
 * = O: one multi-scalar multiplication (Straus, wNAF) instead of n. If every
 * single check holds, so does the batch, whatever the z_i. If one fails, its term
 * D_i = [8](...) is a nonzero point of the prime-order subgroup (8 clears every
 * small-order part), z_i -> [z_i]D_i is injective on [0, 2^128), so at most one
 * odd z_i of the 2^127 cancels it: the batch then passes with probability at most
 * 2^-127 over the z_i (the reason they must be unpredictable). A failed batch is
 * re-checked one signature at a time, so a rejection is always exact. */

#define BATCH_GROUP 64 /* signatures per multi-scalar multiplication */

typedef struct bsig {
    uint8_t z[32]; /* 128-bit odd coefficient, little-endian, high half zero */
    uint8_t h[32];
    int8_t zn[257];
    int top;
    ge_p3 mR;       /* -R */
    bool decoded;
    ge_cached t[8]; /* (2k + 1)(-R) */
#ifdef HAVE_FE4
    fe4 tv[8]; /* the same, vertical */
#endif
} bsig;
#ifdef HAVE_FE4
_Static_assert(sizeof(bsig) % 32 == 0, "bsig arrays must keep every fe4 32-byte aligned");
#endif


/* b[i].mR and b[i].decoded for n signatures: four at a time on AVX2 */
static void decode_group(size_t n, const uint8_t *const sigs[], bsig *b)
{
#ifdef HAVE_FE4
    if (use_fe4()) {
        for (size_t i = 0; i < n; i += 4) {
            const uint8_t *s4[4];
            ge_p3 o[4];
            bool k4[4];
            for (size_t j = 0; j < 4; j++) s4[j] = sigs[i + j < n ? i + j : n - 1]; /* the last repeats as padding */
            ge4_decode_neg(o, k4, s4);
            for (size_t j = 0; j < 4 && i + j < n; j++) b[i + j].mR = o[j], b[i + j].decoded = k4[j];
        }
        return;
    }
#endif
    for (size_t i = 0; i < n; i++) b[i].decoded = ge_frombytes_vt(&b[i].mR, sigs[i], true);
}

/* the odd multiples of -R for the m signatures listed in idx: four at a time on AVX2 */
static void tables_group(size_t m, const size_t idx[], bsig *b)
{
#ifdef HAVE_FE4
    if (use_fe4()) {
        for (size_t j = 0; j < m; j += 4) {
            ge_p3 p4[4];
            ge_cached t4[4][8];
            for (size_t l = 0; l < 4; l++) p4[l] = b[idx[j + l < m ? j + l : m - 1]].mR;
            ge4_odd_multiples(t4, p4);
            for (size_t l = 0; l < 4 && j + l < m; l++) memcpy(b[idx[j + l]].t, t4[l], sizeof t4[l]);
        }
        return;
    }
#endif
    for (size_t j = 0; j < m; j++) {
        bsig *s = &b[idx[j]];
        ge_p3 p = s->mR, p2;
        ge_p1p1 r;
        ge_cached p2c;
        ge_p3_dbl(&r, &s->mR);
        ge_p1p1_to_p3(&p2, &r);
        ge_p3_to_cached(&p2c, &p2);
        ge_p3_to_cached(&s->t[0], &p);
        for (int k = 1; k < 8; k++) {
            ge_add(&r, &p, &p2c);
            ge_p1p1_to_p3(&p, &r);
            ge_p3_to_cached(&s->t[k], &p);
        }
    }
}

/* [s]B + [h](-A) + sum [z_i](-R_i), every scalar in wNAF from bit top down */
static void batch_msm_scalar(ge_p2 *out, int top, const int8_t sn[257], const int8_t hn[257], const ge_cached *mA,
                             size_t m, const size_t idx[], const bsig *b)
{
    ge_p3 q;
    ge_p3_0(&q);
    ge_p2 r2;
    ge_p3_to_p2(&r2, &q);
    ge_p1p1 t;
    ge_p3 u;
    for (int i = top; i >= 0; i--) {
        ge_p2_dbl(&t, &r2); /* each term below: to extended coordinates, then add */
        if (sn[i] > 0) ge_p1p1_to_p3(&u, &t), ge_madd(&t, &u, &g_bodd[sn[i] / 2]);
        if (sn[i] < 0) ge_p1p1_to_p3(&u, &t), ge_msub(&t, &u, &g_bodd[-sn[i] / 2]);
        if (hn[i] > 0) ge_p1p1_to_p3(&u, &t), ge_add(&t, &u, &mA[hn[i] / 2]);
        if (hn[i] < 0) ge_p1p1_to_p3(&u, &t), ge_sub(&t, &u, &mA[-hn[i] / 2]);
        for (size_t j = 0; j < m; j++) {
            int8_t d = b[idx[j]].zn[i];
            if (d > 0) ge_p1p1_to_p3(&u, &t), ge_add(&t, &u, &b[idx[j]].t[d / 2]);
            if (d < 0) ge_p1p1_to_p3(&u, &t), ge_sub(&t, &u, &b[idx[j]].t[-d / 2]);
        }
        ge_p1p1_to_p2(&r2, &t);
    }
    *out = r2;
}

#ifdef HAVE_FE4
/* the same on the vertical four-way field (its additions are the cheaper ones, and the
 * batch is mostly additions) */
T_AVX2 static void batch_msm_vertical(ge_p2 *out, int top, const int8_t sn[257], const int8_t hn[257], size_t m,
                                      const size_t idx[], bsig *b)
{
    const fe4 *Av = minus_a_vtable();
    for (size_t j = 0; j < m; j++)
        for (int k = 0; k < 8; k++) gev_from_cached(&b[idx[j]].tv[k], &b[idx[j]].t[k]);
    fe4 acc;
    gev_identity(&acc);
    for (int i = top; i >= 0; i--) {
        gev_dbl(&acc, &acc);
        gev_add_digit(&acc, g_bodd_v, sn[i]);
        gev_add_digit(&acc, Av, hn[i]);
        for (size_t j = 0; j < m; j++) gev_add_digit(&acc, b[idx[j]].tv, b[idx[j]].zn[i]);
    }
    ge_p3 p;
    gev_to_p3(&p, &acc);
    ge_p3_to_p2(out, &p);
}
#endif

/* One group: the cheap checks, the equation, singles if it fails. b[i] is signature i's slot. */
static bool verify_group(size_t n, const uint8_t *const sigs[], const uint8_t pk[32], const uint8_t *const msgs[],
                         const size_t lens[], const uint8_t *zbytes, bool ok[], bsig *b)
{
    const ge_cached *mA = minus_a_table(pk);
    size_t m = 0;
    size_t idx[BATCH_GROUP];
    uint8_t s_acc[32] = {0}, h_acc[32] = {0};
    if (mA) decode_group(n, sigs, b);
    for (size_t i = 0; i < n; i++) {
        ok[i] = false;
        if (!mA || !b[i].decoded || !sc_below_l_vt(sigs[i] + 32)) continue;
        bsig *s = &b[i];
        crypto_sha512_ctx ctx;
        uint8_t hh[64];
        crypto_sha512_init(&ctx);
        crypto_sha512_update(&ctx, sigs[i], 32);
        crypto_sha512_update(&ctx, pk, 32);
        crypto_sha512_update(&ctx, msgs[i], lens[i]);
        crypto_sha512_final(&ctx, hh);
        sc_reduce(s->h, hh);
        memset(s->z, 0, 32);
        memcpy(s->z, zbytes + 16 * i, 16);
        s->z[0] |= 1;
        sc_muladd(s_acc, s->z, sigs[i] + 32, s_acc); /* sum z_i S_i */
        sc_muladd(h_acc, s->z, s->h, h_acc);         /* sum z_i h_i */
        s->top = wnaf_vt(s->zn, s->z, 5);
        idx[m++] = i;
    }
    if (m == 0) return false;
    tables_group(m, idx, b);
    /* [s]B + [h](-A) + sum [z_i](-R_i), every scalar in wNAF from the top bit down */
    int8_t sn[257], hn[257];
    int top = wnaf_vt(sn, s_acc, 7), th = wnaf_vt(hn, h_acc, 5);
    if (th > top) top = th;
    for (size_t j = 0; j < m; j++)
        if (b[idx[j]].top > top) top = b[idx[j]].top;
    ge_p2 q2;
#ifdef HAVE_FE4
    if (use_fe4())
        batch_msm_vertical(&q2, top, sn, hn, m, idx, b);
    else
#endif
        batch_msm_scalar(&q2, top, sn, hn, mA, m, idx, b);
    ge_p1p1 t;
    for (int k = 0; k < 3; k++) { /* times the cofactor */
        ge_p2_dbl(&t, &q2);
        ge_p1p1_to_p2(&q2, &t);
    }
    if (fe_iszero_vt(&q2.X) && fe_equal_vt(&q2.Y, &q2.Z)) {
        for (size_t j = 0; j < m; j++) ok[idx[j]] = true;
        return m == n;
    }
    bool all = true; /* some signature is bad: the exact verdicts, one by one */
    for (size_t j = 0; j < m; j++) {
        size_t i = idx[j];
        ok[i] = imdb_ed25519_verify(sigs[i], pk, msgs[i], lens[i]);
        all = all && ok[i];
    }
    return all && m == n;
}

bool imdb_ed25519_verify_batch_z(size_t n, const uint8_t *const sigs[], const uint8_t pk[32],
                                 const uint8_t *const msgs[], const size_t lens[], const uint8_t *z, bool ok[])
{
    ed_ready();
    imdb_err e = {0};
    bsig *b = imdb_alloc_aligned(BATCH_GROUP, sizeof *b, &e); /* aligned: it holds AVX2 vectors */
    bool all = true;
    for (size_t at = 0; at < n; at += BATCH_GROUP) {
        size_t k = n - at < BATCH_GROUP ? n - at : BATCH_GROUP;
        if (b) {
            all = verify_group(k, sigs + at, pk, msgs + at, lens + at, z + 16 * at, ok + at, b) && all;
        } else { /* no memory for the tables: the single checks */
            for (size_t i = at; i < at + k; i++) all = (ok[i] = imdb_ed25519_verify(sigs[i], pk, msgs[i], lens[i])) && all;
        }
    }
    imdb_free(b);
    return all;
}

bool imdb_ed25519_verify_batch(size_t n, const uint8_t *const sigs[], const uint8_t pk[32], const uint8_t *const msgs[],
                               const size_t lens[], bool ok[])
{
    uint8_t z[16 * BATCH_GROUP];
    bool all = true;
    for (size_t at = 0; at < n; at += BATCH_GROUP) {
        size_t k = n - at < BATCH_GROUP ? n - at : BATCH_GROUP;
        imdb_err e = {0};
        if (imdb_random(z, 16 * k, &e) == IMDB_OK) {
            all = imdb_ed25519_verify_batch_z(k, sigs + at, pk, msgs + at, lens + at, z, ok + at) && all;
        } else { /* no unpredictable coefficients, no batch */
            for (size_t i = at; i < at + k; i++) all = (ok[i] = imdb_ed25519_verify(sigs[i], pk, msgs[i], lens[i])) && all;
        }
    }
    imdb_wipe(z, sizeof z);
    return all;
}

/* ---- test hooks for the field ----------------------------------------------------- */

void imdb_fe25519_op(int op, uint64_t h[5], const uint64_t f[5], const uint64_t g[5])
{
    fe a, b, r;
    memcpy(a.v, f, sizeof a.v);
    memcpy(b.v, g, sizeof b.v);
    switch (op) {
    case IMDB_FE_MUL: fe_mul(&r, &a, &b); break;
    case IMDB_FE_SQ: fe_sq(&r, &a); break;
    case IMDB_FE_ADD: fe_add(&r, &a, &b); break;
    case IMDB_FE_SUB: fe_sub(&r, &a, &b); break;
    case IMDB_FE_NEG: fe_neg(&r, &a); break;
    case IMDB_FE_INV: fe_invert(&r, &a); break;
    case IMDB_FE_POW22523: fe_pow22523(&r, &a); break;
    case IMDB_FE_CARRY: r = a, fe_carry(&r); break;
    default: fe_0(&r); break;
    }
    memcpy(h, r.v, sizeof r.v);
}

void imdb_fe25519_tobytes(uint8_t s[32], const uint64_t f[5])
{
    fe a;
    memcpy(a.v, f, sizeof a.v);
    fe_tobytes(s, &a);
}

void imdb_fe25519_frombytes(uint64_t h[5], const uint8_t s[32])
{
    fe a;
    fe_frombytes(&a, s);
    memcpy(h, a.v, sizeof a.v);
}

/* ---- test hooks for the group ------------------------------------------------------ */

void imdb_ed25519_constants(uint8_t d[32], uint8_t sqrtm1[32], uint8_t by[32], uint8_t bx[32])
{
    ed_ready();
    fe_tobytes(d, &g_d);
    fe_tobytes(sqrtm1, &g_sqrtm1);
    fe_tobytes(by, &g_B.Y);
    fe_tobytes(bx, &g_B.X);
}

void imdb_ed25519_scalarbase(uint8_t out[32], const uint8_t k[32])
{
    ed_ready();
    ge_p3 h;
    ge_scalarmult_base(&h, k);
    ge_tobytes(out, &h.X, &h.Y, &h.Z);
}

void imdb_ed25519_scalarbase_slow(uint8_t out[32], const uint8_t k[32])
{
    ed_ready();
    ge_p3 h;
    ge_scalarmult_vt(&h, k, &g_B);
    ge_tobytes(out, &h.X, &h.Y, &h.Z);
}

bool imdb_ed25519_scalarmult_slow(uint8_t out[32], const uint8_t k[32], const uint8_t p[32])
{
    ed_ready();
    ge_p3 P, h;
    if (!ge_frombytes_vt(&P, p, false)) return false;
    ge_scalarmult_vt(&h, k, &P);
    ge_tobytes(out, &h.X, &h.Y, &h.Z);
    return true;
}

/* ---- test hooks for the scalars --------------------------------------------------- */

void imdb_sc25519_reduce(uint8_t out[32], const uint8_t in[64]) { sc_reduce(out, in); }

void imdb_sc25519_muladd(uint8_t s[32], const uint8_t a[32], const uint8_t b[32], const uint8_t c[32])
{
    sc_muladd(s, a, b, c);
}

int imdb_ed25519_wnaf(int8_t r[257], const uint8_t s[32], int w) { return wnaf_vt(r, s, w); }

bool imdb_ed25519_double_scalarmult(uint8_t out[32], const uint8_t s[32], const uint8_t h[32], const uint8_t p[32])
{
    ed_ready();
    ge_p3 P, sum;
    if (!ge_frombytes_vt(&P, p, false)) return false;
    ge_cached t[8];
    ge_p3 q = P, p2;
    ge_p1p1 r;
    ge_cached p2c;
    ge_p3_dbl(&r, &P);
    ge_p1p1_to_p3(&p2, &r);
    ge_p3_to_cached(&p2c, &p2);
    ge_p3_to_cached(&t[0], &q);
    for (int k = 1; k < 8; k++) {
        ge_add(&r, &q, &p2c);
        ge_p1p1_to_p3(&q, &r);
        ge_p3_to_cached(&t[k], &q);
    }
    ge_double_scalarmult_vt(&sum, s, t, h);
    ge_tobytes(out, &sum.X, &sum.Y, &sum.Z);
    return true;
}

/* ---- test hooks for the four-way field ---------------------------------------------- */

bool imdb_fe4_available(void)
{
#ifdef HAVE_FE4
    return imdb_cpu_get()->avx2;
#else
    return false;
#endif
}

#ifdef HAVE_FE4
T_AVX2 static void fe4_load(fe4 *h, const uint64_t l[4][10])
{
    for (int i = 0; i < 10; i++) h->v[i] = _mm256_set_epi64x((long long)l[3][i], (long long)l[2][i], (long long)l[1][i], (long long)l[0][i]);
}

T_AVX2 static void fe4_store(uint64_t l[4][10], const fe4 *h)
{
    for (int i = 0; i < 10; i++) {
        uint64_t x[4];
        _mm256_storeu_si256((__m256i *)x, h->v[i]);
        for (int k = 0; k < 4; k++) l[k][i] = x[k];
    }
}

T_AVX2 static void fe4_op_avx2(int op, uint64_t h[4][10], const uint64_t f[4][10], const uint64_t g[4][10])
{
    fe4 a, b, r;
    fe4_load(&a, f);
    fe4_load(&b, g);
    switch (op) {
    case IMDB_FE_MUL: fe4_mul(&r, &a, &b); break;
    case IMDB_FE_SQ: fe4_sq(&r, &a); break;
    case IMDB_FE_ADD: fe4_add(&r, &a, &b); break;
    case IMDB_FE_SUB: fe4_sub(&r, &a, &b); break;
    case IMDB_FE_NEG: fe4_neg(&r, &a); break;
    default: r = a, fe4_carry(&r); break;
    }
    fe4_store(h, &r);
}

T_AVX2 static void fe4_roundtrip_avx2(uint64_t out[4][5], const uint64_t in[4][5])
{
    fe x[4];
    for (int k = 0; k < 4; k++) memcpy(x[k].v, in[k], sizeof x[k].v);
    fe4 h;
    fe4_from(&h, &x[0], &x[1], &x[2], &x[3]);
    fe4_to(&x[0], &x[1], &x[2], &x[3], &h);
    for (int k = 0; k < 4; k++) memcpy(out[k], x[k].v, sizeof x[k].v);
}
#endif

bool imdb_fe4_op(int op, uint64_t h[4][10], const uint64_t f[4][10], const uint64_t g[4][10])
{
#ifdef HAVE_FE4
    if (!imdb_fe4_available()) return false;
    fe4_op_avx2(op, h, f, g);
    return true;
#else
    (void)op, (void)h, (void)f, (void)g;
    return false;
#endif
}

bool imdb_fe4_roundtrip(uint64_t out[4][5], const uint64_t in[4][5])
{
#ifdef HAVE_FE4
    if (!imdb_fe4_available()) return false;
    fe4_roundtrip_avx2(out, in);
    return true;
#else
    (void)out, (void)in;
    return false;
#endif
}

#ifdef HAVE_FE4
T_AVX2 static bool gev_ops_avx2(uint8_t sum[32], uint8_t dif[32], uint8_t dbl[32], const uint8_t p[32], const uint8_t q[32])
{
    ge_p3 P, Q, R;
    if (!ge_frombytes_vt(&P, p, false) || !ge_frombytes_vt(&Q, q, false)) return false;
    ge_cached qc;
    ge_p3_to_cached(&qc, &Q);
    fe4 vp, vq, vn, r;
    gev_from_p3(&vp, &P);
    gev_from_cached(&vq, &qc);
    gev_add(&r, &vp, &vq);
    gev_to_p3(&R, &r);
    ge_tobytes(sum, &R.X, &R.Y, &R.Z);
    gev_cached_neg(&vn, &vq);
    gev_add(&r, &vp, &vn);
    gev_to_p3(&R, &r);
    ge_tobytes(dif, &R.X, &R.Y, &R.Z);
    gev_dbl(&r, &vp);
    gev_to_p3(&R, &r);
    ge_tobytes(dbl, &R.X, &R.Y, &R.Z);
    return true;
}
#endif

bool imdb_ed25519_gev_ops(uint8_t sum[32], uint8_t dif[32], uint8_t dbl[32], const uint8_t p[32], const uint8_t q[32])
{
    ed_ready();
#ifdef HAVE_FE4
    if (imdb_fe4_available()) return gev_ops_avx2(sum, dif, dbl, p, q);
#endif
    (void)sum, (void)dif, (void)dbl, (void)p, (void)q;
    return false;
}
