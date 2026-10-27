/* Verification-only crypto for imagedb-audit (see acrypto.h). */
#include "acrypto.h"

#include <string.h>

/* ---- SHA-256 (FIPS 180-4) ------------------------------------------------ */

static const uint32_t K256[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};

static uint32_t ror32(uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }

static void sha256_block(uint32_t h[8], const uint8_t *b)
{
    uint32_t w[64];
    for (int i = 0; i < 16; i++)
        w[i] = (uint32_t)b[4 * i] << 24 | (uint32_t)b[4 * i + 1] << 16 | (uint32_t)b[4 * i + 2] << 8 | b[4 * i + 3];
    for (int i = 16; i < 64; i++) {
        uint32_t s0 = ror32(w[i - 15], 7) ^ ror32(w[i - 15], 18) ^ (w[i - 15] >> 3);
        uint32_t s1 = ror32(w[i - 2], 17) ^ ror32(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    uint32_t a = h[0], bb = h[1], c = h[2], d = h[3], e = h[4], f = h[5], g = h[6], hh = h[7];
    for (int i = 0; i < 64; i++) {
        uint32_t t1 = hh + (ror32(e, 6) ^ ror32(e, 11) ^ ror32(e, 25)) + ((e & f) ^ (~e & g)) + K256[i] + w[i];
        uint32_t t2 = (ror32(a, 2) ^ ror32(a, 13) ^ ror32(a, 22)) + ((a & bb) ^ (a & c) ^ (bb & c));
        hh = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = bb;
        bb = a;
        a = t1 + t2;
    }
    h[0] += a;
    h[1] += bb;
    h[2] += c;
    h[3] += d;
    h[4] += e;
    h[5] += f;
    h[6] += g;
    h[7] += hh;
}

void a_sha256_init(a_sha256_ctx *c)
{
    static const uint32_t iv[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                                   0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
    memcpy(c->h, iv, sizeof iv);
    c->n = 0;
    c->used = 0;
}

void a_sha256_update(a_sha256_ctx *c, const void *p, size_t n)
{
    const uint8_t *q = p;
    c->n += n;
    while (n) {
        size_t k = 64 - c->used < n ? 64 - c->used : n;
        memcpy(c->buf + c->used, q, k);
        c->used += k;
        q += k;
        n -= k;
        if (c->used == 64) {
            sha256_block(c->h, c->buf);
            c->used = 0;
        }
    }
}

void a_sha256_final(a_sha256_ctx *c, uint8_t out[32])
{
    uint64_t bits = c->n * 8;
    uint8_t pad = 0x80, zero = 0, len[8];
    a_sha256_update(c, &pad, 1);
    while (c->used != 56) a_sha256_update(c, &zero, 1);
    for (int i = 0; i < 8; i++) len[i] = (uint8_t)(bits >> (56 - 8 * i));
    a_sha256_update(c, len, 8);
    for (int i = 0; i < 8; i++)
        for (int j = 0; j < 4; j++) out[4 * i + j] = (uint8_t)(c->h[i] >> (24 - 8 * j));
}

void a_sha256(const void *p, size_t n, uint8_t out[32])
{
    a_sha256_ctx c;
    a_sha256_init(&c);
    a_sha256_update(&c, p, n);
    a_sha256_final(&c, out);
}

/* ---- SHA-512 (FIPS 180-4) ------------------------------------------------- */

static const uint64_t K512[80] = {
    0x428a2f98d728ae22ull, 0x7137449123ef65cdull, 0xb5c0fbcfec4d3b2full, 0xe9b5dba58189dbbcull,
    0x3956c25bf348b538ull, 0x59f111f1b605d019ull, 0x923f82a4af194f9bull, 0xab1c5ed5da6d8118ull,
    0xd807aa98a3030242ull, 0x12835b0145706fbeull, 0x243185be4ee4b28cull, 0x550c7dc3d5ffb4e2ull,
    0x72be5d74f27b896full, 0x80deb1fe3b1696b1ull, 0x9bdc06a725c71235ull, 0xc19bf174cf692694ull,
    0xe49b69c19ef14ad2ull, 0xefbe4786384f25e3ull, 0x0fc19dc68b8cd5b5ull, 0x240ca1cc77ac9c65ull,
    0x2de92c6f592b0275ull, 0x4a7484aa6ea6e483ull, 0x5cb0a9dcbd41fbd4ull, 0x76f988da831153b5ull,
    0x983e5152ee66dfabull, 0xa831c66d2db43210ull, 0xb00327c898fb213full, 0xbf597fc7beef0ee4ull,
    0xc6e00bf33da88fc2ull, 0xd5a79147930aa725ull, 0x06ca6351e003826full, 0x142929670a0e6e70ull,
    0x27b70a8546d22ffcull, 0x2e1b21385c26c926ull, 0x4d2c6dfc5ac42aedull, 0x53380d139d95b3dfull,
    0x650a73548baf63deull, 0x766a0abb3c77b2a8ull, 0x81c2c92e47edaee6ull, 0x92722c851482353bull,
    0xa2bfe8a14cf10364ull, 0xa81a664bbc423001ull, 0xc24b8b70d0f89791ull, 0xc76c51a30654be30ull,
    0xd192e819d6ef5218ull, 0xd69906245565a910ull, 0xf40e35855771202aull, 0x106aa07032bbd1b8ull,
    0x19a4c116b8d2d0c8ull, 0x1e376c085141ab53ull, 0x2748774cdf8eeb99ull, 0x34b0bcb5e19b48a8ull,
    0x391c0cb3c5c95a63ull, 0x4ed8aa4ae3418acbull, 0x5b9cca4f7763e373ull, 0x682e6ff3d6b2b8a3ull,
    0x748f82ee5defb2fcull, 0x78a5636f43172f60ull, 0x84c87814a1f0ab72ull, 0x8cc702081a6439ecull,
    0x90befffa23631e28ull, 0xa4506cebde82bde9ull, 0xbef9a3f7b2c67915ull, 0xc67178f2e372532bull,
    0xca273eceea26619cull, 0xd186b8c721c0c207ull, 0xeada7dd6cde0eb1eull, 0xf57d4f7fee6ed178ull,
    0x06f067aa72176fbaull, 0x0a637dc5a2c898a6ull, 0x113f9804bef90daeull, 0x1b710b35131c471bull,
    0x28db77f523047d84ull, 0x32caab7b40c72493ull, 0x3c9ebe0a15c9bebcull, 0x431d67c49c100d4cull,
    0x4cc5d4becb3e42b6ull, 0x597f299cfc657e2aull, 0x5fcb6fab3ad6faecull, 0x6c44198c4a475817ull,
};

static uint64_t ror64(uint64_t x, int n) { return (x >> n) | (x << (64 - n)); }

static void sha512_block(uint64_t h[8], const uint8_t *b)
{
    uint64_t w[80];
    for (int i = 0; i < 16; i++) {
        uint64_t v = 0;
        for (int j = 0; j < 8; j++) v = v << 8 | b[8 * i + j];
        w[i] = v;
    }
    for (int i = 16; i < 80; i++) {
        uint64_t s0 = ror64(w[i - 15], 1) ^ ror64(w[i - 15], 8) ^ (w[i - 15] >> 7);
        uint64_t s1 = ror64(w[i - 2], 19) ^ ror64(w[i - 2], 61) ^ (w[i - 2] >> 6);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    uint64_t a = h[0], bb = h[1], c = h[2], d = h[3], e = h[4], f = h[5], g = h[6], hh = h[7];
    for (int i = 0; i < 80; i++) {
        uint64_t t1 = hh + (ror64(e, 14) ^ ror64(e, 18) ^ ror64(e, 41)) + ((e & f) ^ (~e & g)) + K512[i] + w[i];
        uint64_t t2 = (ror64(a, 28) ^ ror64(a, 34) ^ ror64(a, 39)) + ((a & bb) ^ (a & c) ^ (bb & c));
        hh = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = bb;
        bb = a;
        a = t1 + t2;
    }
    h[0] += a;
    h[1] += bb;
    h[2] += c;
    h[3] += d;
    h[4] += e;
    h[5] += f;
    h[6] += g;
    h[7] += hh;
}

void a_sha512_init(a_sha512_ctx *c)
{
    static const uint64_t iv[8] = {0x6a09e667f3bcc908ull, 0xbb67ae8584caa73bull, 0x3c6ef372fe94f82bull,
                                   0xa54ff53a5f1d36f1ull, 0x510e527fade682d1ull, 0x9b05688c2b3e6c1full,
                                   0x1f83d9abfb41bd6bull, 0x5be0cd19137e2179ull};
    memcpy(c->h, iv, sizeof iv);
    c->n = 0;
    c->used = 0;
}

void a_sha512_update(a_sha512_ctx *c, const void *p, size_t n)
{
    const uint8_t *q = p;
    c->n += n;
    while (n) {
        size_t k = 128 - c->used < n ? 128 - c->used : n;
        memcpy(c->buf + c->used, q, k);
        c->used += k;
        q += k;
        n -= k;
        if (c->used == 128) {
            sha512_block(c->h, c->buf);
            c->used = 0;
        }
    }
}

void a_sha512_final(a_sha512_ctx *c, uint8_t out[64])
{
    uint64_t bits = c->n * 8;
    uint8_t pad = 0x80, zero = 0, len[16] = {0};
    a_sha512_update(c, &pad, 1);
    while (c->used != 112) a_sha512_update(c, &zero, 1);
    for (int i = 0; i < 8; i++) len[8 + i] = (uint8_t)(bits >> (56 - 8 * i));
    a_sha512_update(c, len, 16);
    for (int i = 0; i < 8; i++)
        for (int j = 0; j < 8; j++) out[8 * i + j] = (uint8_t)(c->h[i] >> (56 - 8 * j));
}

/* ---- CRC32C (Castagnoli, reflected 0x82F63B78) ------------------------- */

uint32_t a_crc32c(const void *p, size_t n)
{
    static uint32_t table[256];
    static int ready;
    if (!ready) {
        for (uint32_t i = 0; i < 256; i++) {
            uint32_t c = i;
            for (int k = 0; k < 8; k++) c = (c >> 1) ^ ((c & 1) ? 0x82F63B78u : 0);
            table[i] = c;
        }
        ready = 1;
    }
    const uint8_t *q = p;
    uint32_t crc = 0xFFFFFFFFu;
    for (size_t i = 0; i < n; i++) crc = table[(crc ^ q[i]) & 0xFF] ^ (crc >> 8);
    return crc ^ 0xFFFFFFFFu;
}

/* ---- GF(2^255 - 19), radix 2^51 ------------------------------------------ */

typedef struct fe {
    uint64_t v[5];
} fe;

#define M51 ((uint64_t)0x7ffffffffffffull)
typedef unsigned __int128 u128;

static void fe_small(fe *h, uint64_t x)
{
    memset(h, 0, sizeof *h);
    h->v[0] = x;
}

/* One carry pass with the wrap-around (2^255 = 19): limbs 1..4 < 2^51. */
static void fe_carry(fe *h)
{
    uint64_t c;
    c = h->v[0] >> 51, h->v[0] &= M51, h->v[1] += c;
    c = h->v[1] >> 51, h->v[1] &= M51, h->v[2] += c;
    c = h->v[2] >> 51, h->v[2] &= M51, h->v[3] += c;
    c = h->v[3] >> 51, h->v[3] &= M51, h->v[4] += c;
    c = h->v[4] >> 51, h->v[4] &= M51, h->v[0] += 19 * c;
}

static void fe_add(fe *h, const fe *f, const fe *g)
{
    for (int i = 0; i < 5; i++) h->v[i] = f->v[i] + g->v[i];
    fe_carry(h);
}

/* f - g + 2p, so no limb underflows (inputs are carried). */
static void fe_sub(fe *h, const fe *f, const fe *g)
{
    h->v[0] = f->v[0] + 0xfffffffffffdaull - g->v[0];
    for (int i = 1; i < 5; i++) h->v[i] = f->v[i] + 0xffffffffffffeull - g->v[i];
    fe_carry(h);
}

static void fe_neg(fe *h, const fe *f)
{
    fe z;
    fe_small(&z, 0);
    fe_sub(h, &z, f);
}

static void fe_mul(fe *h, const fe *f, const fe *g)
{
    uint64_t f0 = f->v[0], f1 = f->v[1], f2 = f->v[2], f3 = f->v[3], f4 = f->v[4];
    uint64_t g0 = g->v[0], g1 = g->v[1], g2 = g->v[2], g3 = g->v[3], g4 = g->v[4];
    uint64_t g1_19 = 19 * g1, g2_19 = 19 * g2, g3_19 = 19 * g3, g4_19 = 19 * g4;
    u128 t0 = (u128)f0 * g0 + (u128)f1 * g4_19 + (u128)f2 * g3_19 + (u128)f3 * g2_19 + (u128)f4 * g1_19;
    u128 t1 = (u128)f0 * g1 + (u128)f1 * g0 + (u128)f2 * g4_19 + (u128)f3 * g3_19 + (u128)f4 * g2_19;
    u128 t2 = (u128)f0 * g2 + (u128)f1 * g1 + (u128)f2 * g0 + (u128)f3 * g4_19 + (u128)f4 * g3_19;
    u128 t3 = (u128)f0 * g3 + (u128)f1 * g2 + (u128)f2 * g1 + (u128)f3 * g0 + (u128)f4 * g4_19;
    u128 t4 = (u128)f0 * g4 + (u128)f1 * g3 + (u128)f2 * g2 + (u128)f3 * g1 + (u128)f4 * g0;
    t1 += (uint64_t)(t0 >> 51);
    t2 += (uint64_t)(t1 >> 51);
    t3 += (uint64_t)(t2 >> 51);
    t4 += (uint64_t)(t3 >> 51);
    uint64_t r0 = (uint64_t)t0 & M51, r1 = (uint64_t)t1 & M51, r2 = (uint64_t)t2 & M51, r3 = (uint64_t)t3 & M51;
    uint64_t r4 = (uint64_t)t4 & M51, c = (uint64_t)(t4 >> 51);
    r0 += 19 * c;
    r1 += r0 >> 51;
    r0 &= M51;
    h->v[0] = r0;
    h->v[1] = r1;
    h->v[2] = r2;
    h->v[3] = r3;
    h->v[4] = r4;
}

static void fe_sq(fe *h, const fe *f) { fe_mul(h, f, f); }

static uint64_t ld64(const uint8_t *p)
{
    uint64_t v = 0;
    for (int i = 7; i >= 0; i--) v = v << 8 | p[i];
    return v;
}

/* 255 bits, top bit ignored; values >= p are accepted (they reduce mod p). */
static void fe_frombytes(fe *h, const uint8_t s[32])
{
    h->v[0] = ld64(s) & M51;
    h->v[1] = (ld64(s + 6) >> 3) & M51;
    h->v[2] = (ld64(s + 12) >> 6) & M51;
    h->v[3] = (ld64(s + 19) >> 1) & M51;
    h->v[4] = (ld64(s + 24) >> 12) & M51;
}

/* Canonical encoding (fully reduced mod p). */
static void fe_tobytes(uint8_t out[32], const fe *h)
{
    fe t = *h;
    fe_carry(&t);
    fe_carry(&t); /* now every limb < 2^51 and t < 2^255 */
    uint64_t q = (t.v[0] + 19) >> 51;
    q = (t.v[1] + q) >> 51;
    q = (t.v[2] + q) >> 51;
    q = (t.v[3] + q) >> 51;
    q = (t.v[4] + q) >> 51; /* q = 1 iff t >= p */
    t.v[0] += 19 * q;
    uint64_t c;
    c = t.v[0] >> 51, t.v[0] &= M51, t.v[1] += c;
    c = t.v[1] >> 51, t.v[1] &= M51, t.v[2] += c;
    c = t.v[2] >> 51, t.v[2] &= M51, t.v[3] += c;
    c = t.v[3] >> 51, t.v[3] &= M51, t.v[4] += c;
    t.v[4] &= M51; /* drops 2^255: t - p */
    uint64_t w[4] = {t.v[0] | t.v[1] << 51, t.v[1] >> 13 | t.v[2] << 38, t.v[2] >> 26 | t.v[3] << 25,
                     t.v[3] >> 39 | t.v[4] << 12};
    for (int i = 0; i < 4; i++)
        for (int j = 0; j < 8; j++) out[8 * i + j] = (uint8_t)(w[i] >> (8 * j));
}

static bool fe_eq(const fe *f, const fe *g)
{
    uint8_t a[32], b[32];
    fe_tobytes(a, f);
    fe_tobytes(b, g);
    return memcmp(a, b, 32) == 0;
}

static bool fe_iszero(const fe *f)
{
    uint8_t a[32];
    fe_tobytes(a, f);
    for (int i = 0; i < 32; i++)
        if (a[i]) return false;
    return true;
}

static int fe_isodd(const fe *f)
{
    uint8_t a[32];
    fe_tobytes(a, f);
    return a[0] & 1;
}

/* f^e for a 255-bit little-endian exponent. */
static void fe_pow(fe *h, const fe *f, const uint8_t e[32])
{
    fe r, b = *f;
    fe_small(&r, 1);
    for (int i = 254; i >= 0; i--) {
        fe_sq(&r, &r);
        if ((e[i >> 3] >> (i & 7)) & 1) fe_mul(&r, &r, &b);
    }
    *h = r;
}

/* ---- edwards25519, extended coordinates (RFC 8032 section 5.1.4) -------- */

typedef struct ge {
    fe X, Y, Z, T;
} ge;

static fe g_d, g_d2, g_sqrtm1;
static ge g_base;
static int g_ready;

static void ge_identity(ge *p)
{
    fe_small(&p->X, 0);
    fe_small(&p->Y, 1);
    fe_small(&p->Z, 1);
    fe_small(&p->T, 0);
}

static void ge_add(ge *r, const ge *p, const ge *q)
{
    fe a, b, c, d, e, f, g, h, t;
    fe_sub(&a, &p->Y, &p->X);
    fe_sub(&t, &q->Y, &q->X);
    fe_mul(&a, &a, &t);
    fe_add(&b, &p->Y, &p->X);
    fe_add(&t, &q->Y, &q->X);
    fe_mul(&b, &b, &t);
    fe_mul(&c, &p->T, &q->T);
    fe_mul(&c, &c, &g_d2);
    fe_mul(&d, &p->Z, &q->Z);
    fe_add(&d, &d, &d);
    fe_sub(&e, &b, &a);
    fe_sub(&f, &d, &c);
    fe_add(&g, &d, &c);
    fe_add(&h, &b, &a);
    fe_mul(&r->X, &e, &f);
    fe_mul(&r->Y, &g, &h);
    fe_mul(&r->T, &e, &h);
    fe_mul(&r->Z, &f, &g);
}

static void ge_double(ge *r, const ge *p)
{
    fe a, b, c, e, f, g, h, t;
    fe_sq(&a, &p->X);
    fe_sq(&b, &p->Y);
    fe_sq(&c, &p->Z);
    fe_add(&c, &c, &c);
    fe_add(&h, &a, &b);
    fe_add(&t, &p->X, &p->Y);
    fe_sq(&t, &t);
    fe_sub(&e, &h, &t);
    fe_sub(&g, &a, &b);
    fe_add(&f, &c, &g);
    fe_mul(&r->X, &e, &f);
    fe_mul(&r->Y, &g, &h);
    fe_mul(&r->T, &e, &h);
    fe_mul(&r->Z, &f, &g);
}

static void ge_neg(ge *r, const ge *p)
{
    fe_neg(&r->X, &p->X);
    r->Y = p->Y;
    r->Z = p->Z;
    fe_neg(&r->T, &p->T);
}

static void ge_scalarmult(ge *r, const ge *p, const uint8_t k[32])
{
    ge q;
    ge_identity(&q);
    for (int i = 255; i >= 0; i--) {
        ge_double(&q, &q);
        if ((k[i >> 3] >> (i & 7)) & 1) ge_add(&q, &q, p);
    }
    *r = q;
}

/* RFC 8032 decoding, except that (like Monocypher) y >= p and x = 0 with
 * the sign bit set are accepted rather than rejected. */
static bool ge_decode(ge *p, const uint8_t s[32])
{
    static const uint8_t p58[32] = {0xfd, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                                    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                                    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x0f}; /* (p-5)/8 */
    fe y, u, v, v3, x, vxx, one, t;
    fe_frombytes(&y, s);
    fe_small(&one, 1);
    fe_sq(&u, &y);
    fe_mul(&v, &u, &g_d);
    fe_sub(&u, &u, &one); /* u = y^2 - 1   */
    fe_add(&v, &v, &one); /* v = d y^2 + 1 */
    fe_sq(&v3, &v);
    fe_mul(&v3, &v3, &v);
    fe_sq(&x, &v3);
    fe_mul(&x, &x, &v);
    fe_mul(&x, &x, &u); /* u v^7 */
    fe_pow(&x, &x, p58);
    fe_mul(&x, &x, &v3);
    fe_mul(&x, &x, &u); /* candidate root of u/v */
    fe_sq(&vxx, &x);
    fe_mul(&vxx, &vxx, &v);
    if (!fe_eq(&vxx, &u)) {
        fe_neg(&t, &u);
        if (!fe_eq(&vxx, &t)) return false; /* not on the curve */
        fe_mul(&x, &x, &g_sqrtm1);
    }
    if (fe_isodd(&x) != (s[31] >> 7)) fe_neg(&x, &x);
    p->X = x;
    p->Y = y;
    fe_small(&p->Z, 1);
    fe_mul(&p->T, &x, &y);
    return true;
}

static void ed_init(void)
{
    if (g_ready) return;
    static const uint8_t pm2[32] = {0xeb, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                                    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                                    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f}; /* p-2 */
    static const uint8_t pm14[32] = {0xfb, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                                     0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                                     0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x1f}; /* (p-1)/4 */
    fe num, den, two;
    fe_small(&num, 121665);
    fe_neg(&num, &num);
    fe_small(&den, 121666);
    fe_pow(&den, &den, pm2);
    fe_mul(&g_d, &num, &den); /* d = -121665/121666 */
    fe_add(&g_d2, &g_d, &g_d);
    fe_small(&two, 2);
    fe_pow(&g_sqrtm1, &two, pm14); /* 2 is a non-residue mod p, so this squares to -1 */
    uint8_t b[32];
    memset(b, 0x66, sizeof b);
    b[0] = 0x58; /* y = 4/5, x even */
    ge_decode(&g_base, b);
    g_ready = 1;
}

/* ---- scalars mod L --------------------------------------------------------- */

static const int64_t kL[32] = {0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7,
                               0xa2, 0xde, 0xf9, 0xde, 0x14, 0, 0, 0, 0, 0, 0,
                               0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10};

static bool below_l(const uint8_t s[32])
{
    for (int i = 31; i >= 0; i--) {
        if (s[i] < kL[i]) return true;
        if (s[i] > kL[i]) return false;
    }
    return false;
}

/* 512-bit little-endian value mod L (the reduction from TweetNaCl, public
 * domain, with the left shifts of negative values written as products). */
static void reduce_l(uint8_t r[32], const uint8_t in[64])
{
    int64_t x[64];
    for (int i = 0; i < 64; i++) x[i] = in[i];
    for (int i = 63; i >= 32; i--) {
        int64_t carry = 0;
        int j;
        for (j = i - 32; j < i - 12; j++) {
            x[j] += carry - 16 * x[i] * kL[j - (i - 32)];
            carry = (x[j] + 128) >> 8;
            x[j] -= carry * 256;
        }
        x[j] += carry;
        x[i] = 0;
    }
    int64_t carry = 0;
    for (int j = 0; j < 32; j++) {
        x[j] += carry - (x[31] >> 4) * kL[j];
        carry = x[j] >> 8;
        x[j] &= 255;
    }
    for (int j = 0; j < 32; j++) x[j] -= carry * kL[j];
    for (int i = 0; i < 32; i++) {
        x[i + 1] += x[i] >> 8;
        r[i] = (uint8_t)(x[i] & 255);
    }
}

bool a_ed25519_verify(const uint8_t pk[32], const void *msg, size_t n, const uint8_t sig[64])
{
    ed_init();
    if (!below_l(sig + 32)) return false;
    ge A, R;
    if (!ge_decode(&A, pk) || !ge_decode(&R, sig)) return false;
    uint8_t hram[64], h[32];
    a_sha512_ctx c;
    a_sha512_init(&c);
    a_sha512_update(&c, sig, 32);
    a_sha512_update(&c, pk, 32);
    a_sha512_update(&c, msg, n);
    a_sha512_final(&c, hram);
    reduce_l(h, hram);
    ge sB, hA, sum;
    ge_scalarmult(&sB, &g_base, sig + 32);
    ge_scalarmult(&hA, &A, h);
    ge_neg(&hA, &hA);
    ge_add(&sum, &sB, &hA);
    ge_neg(&R, &R);
    ge_add(&sum, &sum, &R);
    ge_double(&sum, &sum);
    ge_double(&sum, &sum);
    ge_double(&sum, &sum);
    return fe_iszero(&sum.X) && fe_eq(&sum.Y, &sum.Z);
}

/* ---- ChaCha20 (RFC 8439, section 2.3) --------------------------------------------- */

static uint32_t rotl32(uint32_t x, int n) { return x << n | x >> (32 - n); }

static void quarter(uint32_t *s, int a, int b, int c, int d)
{
    s[a] += s[b], s[d] ^= s[a], s[d] = rotl32(s[d], 16);
    s[c] += s[d], s[b] ^= s[c], s[b] = rotl32(s[b], 12);
    s[a] += s[b], s[d] ^= s[a], s[d] = rotl32(s[d], 8);
    s[c] += s[d], s[b] ^= s[c], s[b] = rotl32(s[b], 7);
}

static uint32_t le32_of(const uint8_t *p) { return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24; }

void a_chacha20_block(const uint8_t key[32], uint32_t counter, const uint8_t nonce[12], uint8_t out[64])
{
    uint32_t s[16], x[16];
    s[0] = 0x61707865u, s[1] = 0x3320646eu, s[2] = 0x79622d32u, s[3] = 0x6b206574u; /* "expand 32-byte k" */
    for (int i = 0; i < 8; i++) s[4 + i] = le32_of(key + 4 * i);
    s[12] = counter;
    for (int i = 0; i < 3; i++) s[13 + i] = le32_of(nonce + 4 * i);
    memcpy(x, s, sizeof x);
    for (int r = 0; r < 10; r++) { /* a column round, then a diagonal round */
        quarter(x, 0, 4, 8, 12), quarter(x, 1, 5, 9, 13), quarter(x, 2, 6, 10, 14), quarter(x, 3, 7, 11, 15);
        quarter(x, 0, 5, 10, 15), quarter(x, 1, 6, 11, 12), quarter(x, 2, 7, 8, 13), quarter(x, 3, 4, 9, 14);
    }
    for (int i = 0; i < 16; i++) {
        uint32_t v = x[i] + s[i];
        out[4 * i] = (uint8_t)v, out[4 * i + 1] = (uint8_t)(v >> 8), out[4 * i + 2] = (uint8_t)(v >> 16), out[4 * i + 3] = (uint8_t)(v >> 24);
    }
}

/* ---- LtHash element ------------------------------------------------------- */

void a_lthash_element(uint8_t alg, const uint8_t commit[32], uint16_t lanes[1024])
{
    if (alg == 2) { /* ChaCha20 under the commitment itself as the key, nonce "IMDBLT20" || 0^4, blocks 0..31 */
        uint8_t blk[64];
        static const uint8_t nonce[12] = {'I', 'M', 'D', 'B', 'L', 'T', '2', '0', 0, 0, 0, 0};
        for (uint32_t b = 0; b < 32; b++) {
            a_chacha20_block(commit, b, nonce, blk);
            for (int k = 0; k < 32; k++) lanes[32 * b + (uint32_t)k] = (uint16_t)(blk[2 * k] | blk[2 * k + 1] << 8);
        }
        return;
    }
    uint8_t seed[44];
    memcpy(seed, "IMDBLT16", 8);
    memcpy(seed + 8, commit, 32);
    for (uint32_t i = 0; i < 64; i++) {
        uint8_t out[32];
        seed[40] = (uint8_t)(i >> 24);
        seed[41] = (uint8_t)(i >> 16);
        seed[42] = (uint8_t)(i >> 8);
        seed[43] = (uint8_t)i;
        a_sha256(seed, sizeof seed, out);
        for (int k = 0; k < 16; k++) lanes[16 * i + (uint32_t)k] = (uint16_t)(out[2 * k] | out[2 * k + 1] << 8);
    }
}
