/* The fast Ed25519 path, layer by layer: field arithmetic against OpenSSL's
 * BIGNUM, then the group, scalars mod L and signatures against Monocypher
 * (the reference, src/vendor/monocypher) and OpenSSL. */
#include <openssl/bn.h>
#include <stdlib.h>

#include "../../src/ed25519.h"
#include "../../src/util.h"
#include "../../src/vendor/monocypher/monocypher-ed25519.h"
#include "../../src/vendor/monocypher/monocypher.h"
#include "../../tools/audit/acrypto.h"
#include "test.h"

static BIGNUM *g_p; /* 2^255 - 19 */
static BN_CTX *g_bn;

static void bn_setup(void)
{
    if (g_p) return;
    g_bn = BN_CTX_new();
    g_p = BN_new();
    BN_set_bit(g_p, 255);
    BN_sub_word(g_p, 19);
}

/* sum f[i] * 2^(51 i), exactly (limbs may exceed 51 bits) */
static BIGNUM *bn_limbs(const uint64_t f[5])
{
    BIGNUM *r = BN_new(), *t = BN_new();
    BN_zero(r);
    for (int i = 4; i >= 0; i--) {
        BN_lshift(r, r, 51);
        BN_set_word(t, f[i]);
        BN_add(r, r, t);
    }
    BN_free(t);
    return r;
}

/* a mod p as 32 little-endian bytes */
static void bn_canon(uint8_t out[32], const BIGNUM *a)
{
    BIGNUM *m = BN_new();
    BN_nnmod(m, a, g_p, g_bn);
    BN_bn2lebinpad(m, out, 32);
    BN_free(m);
}

/* random limbs below 2^bits; now and then every limb at the maximum, or zero */
static void rand_limbs(uint64_t f[5], int bits)
{
    uint64_t r = test_rand() % 16, max = bits >= 64 ? UINT64_MAX : ((uint64_t)1 << bits) - 1;
    for (int i = 0; i < 5; i++) {
        uint64_t v = test_rand() & max;
        if (r == 0) v = max;
        else if (r == 1) v = 0;
        else if (r == 2 && (test_rand() & 1)) v = max - (test_rand() & 0xff);
        f[i] = v;
    }
}

static bool op_matches(int op, const uint64_t f[5], const uint64_t g[5])
{
    uint64_t h[5];
    imdb_fe25519_op(op, h, f, g);
    uint8_t got[32], want[32];
    imdb_fe25519_tobytes(got, h);
    BIGNUM *a = bn_limbs(f), *b = bn_limbs(g), *r = BN_new();
    switch (op) {
    case IMDB_FE_MUL: BN_mod_mul(r, a, b, g_p, g_bn); break;
    case IMDB_FE_SQ: BN_mod_sqr(r, a, g_p, g_bn); break;
    case IMDB_FE_ADD: BN_add(r, a, b); break;
    case IMDB_FE_SUB: BN_sub(r, a, b); break;
    case IMDB_FE_NEG: BN_zero(r), BN_sub(r, r, a); break;
    case IMDB_FE_CARRY: BN_copy(r, a); break;
    default: break;
    }
    bn_canon(want, r);
    BN_free(a);
    BN_free(b);
    BN_free(r);
    return memcmp(got, want, 32) == 0;
}

static void t_fe_arith(void)
{
    bn_setup();
    /* 4p's limbs: the largest subtrahend fe_sub accepts */
    const uint64_t p4[5] = {0x1fffffffffffb4, 0x1ffffffffffffc, 0x1ffffffffffffc, 0x1ffffffffffffc, 0x1ffffffffffffc};
    for (int it = 0; it < 20000; it++) {
        uint64_t f[5], g[5];
        rand_limbs(f, 56);
        rand_limbs(g, 56);
        CHECK(op_matches(IMDB_FE_MUL, f, g));
        CHECK(op_matches(IMDB_FE_SQ, f, g));
        rand_limbs(f, 52);
        rand_limbs(g, 52);
        CHECK(op_matches(IMDB_FE_ADD, f, g));
        /* subtrahends up to 4p, limb by limb */
        for (int i = 0; i < 5; i++) g[i] = test_rand() % (p4[i] + 1);
        if (it % 7 == 0) memcpy(g, p4, sizeof g);
        CHECK(op_matches(IMDB_FE_SUB, f, g));
        CHECK(op_matches(IMDB_FE_NEG, g, g));
        rand_limbs(f, 63);
        CHECK(op_matches(IMDB_FE_CARRY, f, g));
        /* carried outputs stay within the documented bounds */
        uint64_t h[5];
        imdb_fe25519_op(IMDB_FE_CARRY, h, f, g);
        CHECK(h[0] < ((uint64_t)1 << 51) + ((uint64_t)1 << 17));
        for (int i = 1; i < 5; i++) CHECK(h[i] < ((uint64_t)1 << 51));
        rand_limbs(f, 56);
        rand_limbs(g, 56);
        imdb_fe25519_op(IMDB_FE_MUL, h, f, g);
        for (int i = 0; i < 5; i++) CHECK(h[i] < ((uint64_t)1 << 51) + ((uint64_t)1 << 23));
    }
}

/* ---- layer 1b: the four-way AVX2 field (radix 2^25.5) ---------------------------------- */

/* sum l[i] * 2^ceil(25.5 i), exactly */
static BIGNUM *bn_limbs10(const uint64_t l[10])
{
    static const int w[10] = {0, 26, 51, 77, 102, 128, 153, 179, 204, 230};
    BIGNUM *r = BN_new(), *t = BN_new();
    BN_zero(r);
    for (int i = 0; i < 10; i++) {
        BN_set_word(t, l[i]);
        BN_lshift(t, t, w[i]);
        BN_add(r, r, t);
    }
    BN_free(t);
    return r;
}

/* limbs up to the given bounds (even, odd); sometimes all at the bound, or zero */
static void rand_limbs10(uint64_t l[10], uint64_t even, uint64_t odd)
{
    uint64_t r = test_rand() % 16;
    for (int i = 0; i < 10; i++) {
        uint64_t max = (i & 1) ? odd : even;
        uint64_t v = test_rand() % (max + 1);
        if (r == 0) v = max;
        else if (r == 1) v = 0;
        else if (r == 2 && (test_rand() & 1)) v = max - (test_rand() & 0xff);
        l[i] = v;
    }
}

static bool carried10(const uint64_t l[10])
{
    for (int i = 0; i < 10; i++)
        if (l[i] >> ((i & 1) ? 25 : 26) && !(i == 1 && l[i] < (1u << 25) + (1u << 17))) return false;
    return true;
}

static void t_fe4_arith(void)
{
    if (!imdb_fe4_available()) {
        printf("    no AVX2 here: skipped\n");
        return;
    }
    bn_setup();
    const uint64_t in_even = 3 * (1ull << 26) + (1u << 20), in_odd = 3 * (1ull << 25) + (1u << 20);
    const uint64_t sub_even = 2 * ((1ull << 26) - 19), sub_odd = 2 * ((1ull << 25) - 1);
    for (int it = 0; it < 3000; it++) {
        uint64_t f[4][10], g[4][10], h[4][10];
        int op = it % 6; /* MUL, SQ, ADD, SUB, NEG, CARRY */
        for (int k = 0; k < 4; k++) {
            if (op == IMDB_FE_SUB || op == IMDB_FE_NEG) {
                rand_limbs10(f[k], in_even / 2, in_odd / 2);
                rand_limbs10(g[k], sub_even, sub_odd);
            } else if (op == IMDB_FE_CARRY) {
                rand_limbs10(f[k], (1ull << 62) - 1, (1ull << 62) - 1);
                rand_limbs10(g[k], 0, 0);
            } else {
                rand_limbs10(f[k], in_even, in_odd);
                rand_limbs10(g[k], in_even, in_odd);
            }
        }
        int fop = op == 5 ? IMDB_FE_CARRY : op;
        CHECK(imdb_fe4_op(fop, h, (const uint64_t(*)[10])f, (const uint64_t(*)[10])g));
        for (int k = 0; k < 4; k++) {
            BIGNUM *a = bn_limbs10(f[k]), *b = bn_limbs10(g[k]), *got = bn_limbs10(h[k]), *want = BN_new();
            switch (fop) {
            case IMDB_FE_MUL: BN_mod_mul(want, a, b, g_p, g_bn); break;
            case IMDB_FE_SQ: BN_mod_mul(want, a, a, g_p, g_bn); break;
            case IMDB_FE_ADD: BN_add(want, a, b); break;
            case IMDB_FE_SUB: BN_sub(want, a, b); break;
            case IMDB_FE_NEG: BN_sub(want, BN_value_one(), BN_value_one()), BN_sub(want, want, a); break;
            default: BN_copy(want, a); break;
            }
            uint8_t x[32], y[32];
            bn_canon(x, got);
            bn_canon(y, want);
            CHECK(memcmp(x, y, 32) == 0);
            if (fop == IMDB_FE_MUL || fop == IMDB_FE_SQ || fop == IMDB_FE_CARRY) CHECK(carried10(h[k]));
            if (fop == IMDB_FE_ADD)
                for (int i = 0; i < 10; i++) CHECK(h[k][i] == f[k][i] + g[k][i]);
            BN_free(a), BN_free(b), BN_free(got), BN_free(want);
        }
    }
    /* packing: radix-2^51 elements below 2^52 per limb, through the lanes and back */
    for (int it = 0; it < 2000; it++) {
        uint64_t in[4][5], out[4][5];
        for (int k = 0; k < 4; k++) rand_limbs(in[k], 52);
        CHECK(imdb_fe4_roundtrip(out, (const uint64_t(*)[5])in));
        for (int k = 0; k < 4; k++) {
            BIGNUM *a = bn_limbs(in[k]), *b = bn_limbs(out[k]);
            CHECK(BN_cmp(a, b) == 0);
            BN_free(a), BN_free(b);
        }
    }
}

static void t_fe_invert_pow(void)
{
    bn_setup();
    BIGNUM *e = BN_new(); /* (p - 5) / 8 */
    BN_copy(e, g_p);
    BN_sub_word(e, 5);
    BN_rshift(e, e, 3);
    for (int it = 0; it < 2000; it++) {
        uint64_t f[5], h[5];
        rand_limbs(f, 56);
        BIGNUM *a = bn_limbs(f), *r = BN_new();
        BN_nnmod(a, a, g_p, g_bn);
        uint8_t got[32], want[32];
        imdb_fe25519_op(IMDB_FE_INV, h, f, f);
        imdb_fe25519_tobytes(got, h);
        if (BN_is_zero(a)) BN_zero(r);
        else BN_mod_inverse(r, a, g_p, g_bn);
        bn_canon(want, r);
        CHECK(memcmp(got, want, 32) == 0);
        imdb_fe25519_op(IMDB_FE_POW22523, h, f, f);
        imdb_fe25519_tobytes(got, h);
        BN_mod_exp(r, a, e, g_p, g_bn);
        bn_canon(want, r);
        CHECK(memcmp(got, want, 32) == 0);
        BN_free(a);
        BN_free(r);
    }
    BN_free(e);
}

/* The canonical encoding at the values where a reduction goes wrong first. */
static void t_fe_tobytes_edges(void)
{
    bn_setup();
    static const char *vals[] = {
        "0", "1", "13", "12", /* 19, 18 */
        "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeb", /* p - 2 */
        "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffec", /* p - 1 */
        "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed", /* p */
        "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffee", /* p + 1 */
        "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", /* 2^255 - 1 */
        "8000000000000000000000000000000000000000000000000000000000000000", /* 2^255 */
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd9", /* 2p - 1 */
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffda", /* 2p */
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", /* 2^256 - 1 */
    };
    for (size_t i = 0; i < sizeof vals / sizeof *vals; i++) {
        BIGNUM *v = NULL;
        CHECK(BN_hex2bn(&v, vals[i]) > 0);
        /* canonical limbs of v (limb 4 takes everything above bit 204), then the same value
         * with weight moved between limbs */
        uint8_t le[40];
        CHECK(BN_bn2lebinpad(v, le, sizeof le) == (int)sizeof le);
        uint64_t f[5] = {0};
        for (int bit = 0; bit < 320; bit++) {
            int k = bit / 51 < 4 ? bit / 51 : 4;
            if (le[bit / 8] >> (bit % 8) & 1) f[k] |= (uint64_t)1 << (bit - 51 * k);
        }
        for (int shape = 0; shape < 5; shape++) {
            uint64_t g[5];
            memcpy(g, f, sizeof g);
            if (shape > 0 && g[shape] >= 1) { /* borrow one unit of limb `shape` into the one below */
                g[shape] -= 1;
                g[shape - 1] += (uint64_t)1 << 51;
            }
            uint8_t got[32], want[32];
            imdb_fe25519_tobytes(got, g);
            bn_canon(want, v);
            CHECK(memcmp(got, want, 32) == 0);
        }
        BN_free(v);
    }
    /* every limb at the largest value fe_carry takes */
    uint64_t m[5] = {((uint64_t)1 << 63) - 1, ((uint64_t)1 << 63) - 1, ((uint64_t)1 << 63) - 1, ((uint64_t)1 << 63) - 1,
                     ((uint64_t)1 << 63) - 1};
    uint8_t got[32], want[32];
    imdb_fe25519_tobytes(got, m);
    BIGNUM *a = bn_limbs(m);
    bn_canon(want, a);
    BN_free(a);
    CHECK(memcmp(got, want, 32) == 0);
}

static void t_fe_frombytes(void)
{
    bn_setup();
    for (int it = 0; it < 5000; it++) {
        uint8_t s[32], got[32], want[32];
        test_rand_bytes(s, 32);
        if (it % 5 == 0) memset(s, 0xff, 32); /* 2^256 - 1: bit 255 dropped, then >= p */
        if (it % 5 == 1) { /* p .. 2^255 - 1: non-canonical, accepted as is */
            memset(s, 0xff, 32);
            s[31] = 0x7f;
            s[0] = (uint8_t)(0xed + test_rand() % 0x13);
        }
        uint64_t h[5];
        imdb_fe25519_frombytes(h, s);
        for (int i = 0; i < 5; i++) CHECK(h[i] < ((uint64_t)1 << 51));
        imdb_fe25519_tobytes(got, h);
        uint8_t low[32];
        memcpy(low, s, 32);
        low[31] &= 0x7f;
        BIGNUM *v = BN_lebin2bn(low, 32, NULL);
        bn_canon(want, v);
        BN_free(v);
        CHECK(memcmp(got, want, 32) == 0);
    }
}

/* ---- layer 2: the group ------------------------------------------------------------- */

/* big-endian hex (as bc prints it) to 32 little-endian bytes */
static void be_hex(uint8_t out[32], const char *hex)
{
    uint8_t be[32];
    CHECK(imdb_unhex(hex, 64, be, 32));
    for (int i = 0; i < 32; i++) out[i] = be[31 - i];
}

static BIGNUM *bn_le(const uint8_t s[32])
{
    return BN_lebin2bn(s, 32, NULL);
}

static void t_ge_constants(void)
{
    bn_setup();
    uint8_t d[32], i[32], by[32], bx[32], w[32];
    imdb_ed25519_constants(d, i, by, bx);
    /* computed independently with bc (docs/plan-round2.md) */
    be_hex(w, "52036cee2b6ffe738cc740797779e89800700a4d4141d8ab75eb4dca135978a3");
    CHECK(memcmp(d, w, 32) == 0);
    be_hex(w, "2b8324804fc1df0b2b4d00993dfbd7a72f431806ad2fe478c4ee1b274a0ea0b0");
    CHECK(memcmp(i, w, 32) == 0);
    be_hex(w, "6666666666666666666666666666666666666666666666666666666666666658");
    CHECK(memcmp(by, w, 32) == 0);
    be_hex(w, "216936d3cd6e53fec0a4e231fdd6dc5c692cc7609525a7b2c9562d608f25d51a");
    CHECK(memcmp(bx, w, 32) == 0);
    /* and by their definitions, in BIGNUM */
    BIGNUM *D = bn_le(d), *I = bn_le(i), *X = bn_le(bx), *Y = bn_le(by), *t = BN_new(), *u = BN_new(), *one = BN_new();
    BN_one(one);
    BN_set_word(t, 121666);
    BN_mod_mul(t, t, D, g_p, g_bn);
    BN_add_word(t, 121665);
    BN_nnmod(t, t, g_p, g_bn);
    CHECK(BN_is_zero(t)); /* d * 121666 = -121665 */
    BN_mod_sqr(t, I, g_p, g_bn);
    BN_add_word(t, 1);
    BN_nnmod(t, t, g_p, g_bn);
    CHECK(BN_is_zero(t)); /* sqrt(-1)^2 = -1 */
    BN_set_word(t, 5);
    BN_mod_mul(t, t, Y, g_p, g_bn);
    CHECK(BN_is_word(t, 4)); /* y = 4/5 */
    BIGNUM *x2 = BN_new(), *y2 = BN_new();
    BN_mod_sqr(x2, X, g_p, g_bn);
    BN_mod_sqr(y2, Y, g_p, g_bn);
    BN_mod_sub(t, y2, x2, g_p, g_bn); /* -x^2 + y^2 */
    BN_mod_mul(u, x2, y2, g_p, g_bn);
    BN_mod_mul(u, u, D, g_p, g_bn);
    BN_mod_add(u, u, one, g_p, g_bn); /* 1 + d x^2 y^2 */
    CHECK(BN_cmp(t, u) == 0);
    CHECK(!BN_is_odd(X));
    BN_free(D), BN_free(I), BN_free(X), BN_free(Y), BN_free(t), BN_free(u), BN_free(one), BN_free(x2), BN_free(y2);
}

static const uint8_t L_LE[32] = {0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7,
                                 0xa2, 0xde, 0xf9, 0xde, 0x14, 0, 0, 0, 0, 0, 0,
                                 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10};

static void le_add_small(uint8_t s[32], int delta) /* s += delta (|delta| small), mod 2^256 */
{
    int carry = delta;
    for (int i = 0; i < 32; i++) {
        int t = s[i] + carry;
        s[i] = (uint8_t)(t & 0xff);
        carry = t >> 8; /* arithmetic: -1 when borrowing */
    }
}

static void t_ge_order(void)
{
    uint8_t d[32], i[32], by[32], bx[32], out[32], k[32];
    imdb_ed25519_constants(d, i, by, bx);
    static const uint8_t ident[32] = {1};
    memcpy(k, L_LE, 32);
    imdb_ed25519_scalarbase_slow(out, k);
    CHECK(memcmp(out, ident, 32) == 0); /* [L]B = 0 */
    le_add_small(k, 1);
    imdb_ed25519_scalarbase_slow(out, k);
    CHECK(memcmp(out, by, 32) == 0); /* [L + 1]B = B (x even: sign bit clear) */
    le_add_small(k, -2);
    imdb_ed25519_scalarbase_slow(out, k);
    uint8_t negb[32];
    memcpy(negb, by, 32);
    negb[31] |= 0x80;
    CHECK(memcmp(out, negb, 32) == 0); /* [L - 1]B = -B */
}

static void t_ge_scalarbase(void)
{
    uint8_t k[32], a[32], b[32], c[32];
    for (int it = 0; it < 2500; it++) {
        test_rand_bytes(k, 32);
        switch (it) {
        case 0: memset(k, 0, 32); break;
        case 1: memset(k, 0, 32), k[0] = 1; break;
        case 2: memset(k, 0x88, 32); break;           /* every nibble 8: the most carries */
        case 3: memset(k, 0xff, 32); break;           /* 2^255 - 1 after the mask below */
        case 4: memset(k, 0x77, 32); break;
        case 5: memcpy(k, L_LE, 32); break;           /* L */
        case 6: memcpy(k, L_LE, 32), le_add_small(k, -1); break;
        case 7: memcpy(k, L_LE, 32), le_add_small(k, 1); break;
        case 8: memset(k, 0, 32), k[31] = 0x10; break; /* 2^252 */
        default: break;
        }
        k[31] &= 0x7f; /* the comb's domain: k < 2^255 */
        imdb_ed25519_scalarbase(a, k);
        imdb_ed25519_scalarbase_slow(b, k);
        crypto_eddsa_scalarbase(c, k);
        CHECK(memcmp(a, b, 32) == 0);
        CHECK(memcmp(a, c, 32) == 0);
    }
}

/* Decoding accepts exactly when (y^2 - 1)/(d y^2 + 1) is a square (Euler's criterion
 * in BIGNUM), whatever the sign bit and including y >= p; and it round-trips. */
static void t_ge_decode(void)
{
    bn_setup();
    uint8_t d[32], i[32], by[32], bx[32];
    imdb_ed25519_constants(d, i, by, bx);
    BIGNUM *D = bn_le(d), *e = BN_new(), *one = BN_new();
    BN_one(one);
    BN_copy(e, g_p);
    BN_sub_word(e, 1);
    BN_rshift1(e, e); /* (p - 1)/2 */
    int accepted = 0;
    for (int it = 0; it < 3000; it++) {
        uint8_t s[32], out[32], k1[32] = {1};
        test_rand_bytes(s, 32);
        if (it == 0) memset(s, 0, 32), s[0] = 1;                 /* y = 1, x = 0 */
        if (it == 1) memset(s, 0, 32), s[0] = 1, s[31] = 0x80;   /* x = 0 with the sign bit set */
        if (it == 2) memset(s, 0xff, 32), s[0] = 0xec, s[31] = 0x7f; /* y = p - 1 = -1, x = 0 */
        if (it == 3) memset(s, 0xff, 32), s[0] = 0xee, s[31] = 0x7f; /* y = p + 1 >= p */
        uint8_t low[32];
        memcpy(low, s, 32);
        low[31] &= 0x7f;
        BIGNUM *y = bn_le(low), *y2 = BN_new(), *u = BN_new(), *v = BN_new(), *t = BN_new();
        BN_mod_sqr(y2, y, g_p, g_bn);
        BN_mod_sub(u, y2, one, g_p, g_bn);
        BN_mod_mul(v, y2, D, g_p, g_bn);
        BN_mod_add(v, v, one, g_p, g_bn);
        BN_mod_mul(t, u, v, g_p, g_bn); /* u/v square <=> u*v square (v != 0) */
        BN_mod_exp(t, t, e, g_p, g_bn);
        bool square = BN_is_zero(t) || BN_is_one(t);
        bool ok = imdb_ed25519_scalarmult_slow(out, k1, s);
        CHECK(ok == square);
        if (ok) {
            accepted++;
            /* [1]P re-encodes canonically: y reduced mod p; the sign bit kept unless x = 0 */
            uint8_t want[32];
            bn_canon(want, y);
            BIGNUM *x2 = BN_new();
            bool xzero = BN_is_zero(u);
            if (!xzero) want[31] |= (uint8_t)(s[31] & 0x80);
            CHECK(memcmp(out, want, 32) == 0);
            BN_free(x2);
        }
        BN_free(y), BN_free(y2), BN_free(u), BN_free(v), BN_free(t);
    }
    CHECK(accepted > 1000 && accepted < 2000); /* about half of all y are on the curve */
    BN_free(D), BN_free(e), BN_free(one);
}

/* ---- layer 3: scalars mod L --------------------------------------------------------- */

static BIGNUM *g_l;

static void l_setup(void)
{
    bn_setup();
    if (g_l) return;
    g_l = BN_lebin2bn(L_LE, 32, NULL);
}

static void t_sc_reduce(void)
{
    l_setup();
    for (int it = 0; it < 20000; it++) {
        uint8_t in[64], a[32], b[32];
        test_rand_bytes(in, 64);
        if (it < 40) { /* k L + delta, k up to 2^259: the Barrett estimate's edges */
            BIGNUM *k = BN_new(), *x = BN_new();
            BN_rand(k, 1 + it * 259 / 40, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY);
            BN_mul(x, k, g_l, g_bn);
            if (it % 3 == 1) BN_sub_word(x, 1);
            if (it % 3 == 2) BN_add(x, x, g_l), BN_sub_word(x, 1);
            if (BN_num_bits(x) > 512) BN_rshift1(x, x);
            CHECK(BN_bn2lebinpad(x, in, 64) == 64);
            BN_free(k), BN_free(x);
        }
        if (it == 40) memset(in, 0xff, 64); /* 2^512 - 1 */
        if (it == 41) memset(in, 0, 64);
        imdb_sc25519_reduce(a, in);
        crypto_eddsa_reduce(b, in);
        CHECK(memcmp(a, b, 32) == 0);
        if (it < 42) { /* and against BIGNUM where Monocypher could share a mistake */
            BIGNUM *x = BN_lebin2bn(in, 64, NULL), *r = BN_new();
            BN_nnmod(r, x, g_l, g_bn);
            uint8_t w[32];
            BN_bn2lebinpad(r, w, 32);
            CHECK(memcmp(a, w, 32) == 0);
            BN_free(x), BN_free(r);
        }
    }
}

static void t_sc_muladd(void)
{
    l_setup();
    for (int it = 0; it < 20000; it++) {
        uint8_t a[32], b[32], c[32], s1[32], s2[32];
        test_rand_bytes(a, 32);
        test_rand_bytes(b, 32);
        test_rand_bytes(c, 32);
        if (it == 0) memset(a, 0xff, 32), memset(b, 0xff, 32), memset(c, 0xff, 32);
        if (it == 1) memcpy(a, L_LE, 32), memcpy(c, L_LE, 32);
        imdb_sc25519_muladd(s1, a, b, c);
        crypto_eddsa_mul_add(s2, a, b, c);
        CHECK(memcmp(s1, s2, 32) == 0);
        if (it < 2) {
            BIGNUM *A = BN_lebin2bn(a, 32, NULL), *B = BN_lebin2bn(b, 32, NULL), *C = BN_lebin2bn(c, 32, NULL), *r = BN_new();
            BN_mul(r, A, B, g_bn);
            BN_add(r, r, C);
            BN_nnmod(r, r, g_l, g_bn);
            uint8_t w[32];
            BN_bn2lebinpad(r, w, 32);
            CHECK(memcmp(s1, w, 32) == 0);
            BN_free(A), BN_free(B), BN_free(C), BN_free(r);
        }
    }
}

/* The vertical (one point in the four lanes) formulas: P + Q, P - Q and 2P for P = [a]B,
 * Q = [b]B against [a + b]B, [a - b]B (mod L) and the plain double-and-add. */
static void t_ge4_vertical(void)
{
    if (!imdb_fe4_available()) {
        printf("    no AVX2 here: skipped\n");
        return;
    }
    l_setup();
    for (int it = 0; it < 400; it++) {
        uint8_t a[32], b[32], wide[64] = {0}, P[32], Q[32], sum[32], dif[32], dbl[32], want[32], s[32], two[32] = {2};
        test_rand_bytes(wide, 32);
        imdb_sc25519_reduce(a, wide);
        test_rand_bytes(wide, 32);
        imdb_sc25519_reduce(b, wide);
        if (it == 0) memset(b, 0, 32);  /* Q the identity */
        if (it == 1) memcpy(b, a, 32);  /* P = Q: the addition formula doubles */
        imdb_ed25519_scalarbase(P, a);
        imdb_ed25519_scalarbase(Q, b);
        CHECK(imdb_ed25519_gev_ops(sum, dif, dbl, P, Q));
        BIGNUM *A = BN_lebin2bn(a, 32, NULL), *B = BN_lebin2bn(b, 32, NULL), *r = BN_new();
        BN_mod_add(r, A, B, g_l, g_bn);
        BN_bn2lebinpad(r, s, 32);
        imdb_ed25519_scalarbase(want, s);
        CHECK(memcmp(sum, want, 32) == 0);
        BN_mod_sub(r, A, B, g_l, g_bn);
        BN_bn2lebinpad(r, s, 32);
        imdb_ed25519_scalarbase(want, s);
        CHECK(memcmp(dif, want, 32) == 0);
        CHECK(imdb_ed25519_scalarmult_slow(want, two, P));
        CHECK(memcmp(dbl, want, 32) == 0);
        BN_free(A), BN_free(B), BN_free(r);
    }
}

/* ---- layer 4: keys, signatures, verification ---------------------------------------- */

static bool mono_check(const uint8_t pk[32], const void *m, size_t n, const uint8_t sig[64])
{
    return crypto_ed25519_check(sig, pk, m, n) == 0;
}

static void t_ed_sign_vs_monocypher(void)
{
    static uint8_t msg[1100];
    for (int it = 0; it < 3000; it++) {
        uint8_t seed[32], a[32], prefix[32], pk[32], msk[64], mpk[32], sig[64], msig[64], tmp[32];
        test_rand_bytes(seed, 32);
        size_t n = (size_t)(test_rand() % (it < 100 ? sizeof msg : 200));
        test_rand_bytes(msg, n);
        imdb_ed25519_expand(seed, a, prefix, pk);
        memcpy(tmp, seed, 32); /* Monocypher wipes the seed it is given */
        crypto_ed25519_key_pair(msk, mpk, tmp);
        CHECK(memcmp(pk, mpk, 32) == 0);
        imdb_ed25519_sign(sig, a, prefix, pk, msg, n);
        crypto_ed25519_sign(msig, msk, msg, n);
        CHECK(memcmp(sig, msig, 64) == 0); /* deterministic: byte-identical */
        CHECK(imdb_ed25519_verify(sig, pk, msg, n));
        /* one flipped bit anywhere: the same verdict as Monocypher (a rejection) */
        for (int k = 0; k < 3; k++) {
            uint8_t bad[64], kp[32];
            memcpy(bad, sig, 64);
            memcpy(kp, pk, 32);
            if (k == 0) bad[test_rand() % 64] ^= (uint8_t)(1u << (test_rand() % 8));
            if (k == 1) kp[test_rand() % 32] ^= (uint8_t)(1u << (test_rand() % 8));
            if (k == 2 && n) msg[test_rand() % n] ^= 0x20;
            bool ours = imdb_ed25519_verify(bad, kp, msg, n), theirs = mono_check(kp, msg, n, bad);
            CHECK(ours == theirs);
            CHECK(!ours || (k == 2 && !n));
        }
        test_rand_bytes(msg, n); /* fresh message for the next round */
        if (it % 100 == 0) { /* the signature may overwrite its own message (Monocypher allows it) */
            uint8_t b1[80], b2[80];
            test_rand_bytes(b1, sizeof b1);
            memcpy(b2, b1, sizeof b2);
            imdb_ed25519_sign(b1 + 8, a, prefix, pk, b1, sizeof b1);
            crypto_ed25519_sign(b2 + 8, msk, b2, sizeof b2);
            CHECK(memcmp(b1, b2, sizeof b1) == 0);
        }
    }
}

/* Random garbage: almost every case is a rejection, and the reason must not matter. */
static void t_ed_verify_garbage(void)
{
    for (int it = 0; it < 4000; it++) {
        uint8_t pk[32], sig[64], m[16];
        test_rand_bytes(pk, 32);
        test_rand_bytes(sig, 64);
        test_rand_bytes(m, sizeof m);
        if (it % 2) sig[63] &= 0x0f; /* S below 2^252: past the S < L check */
        CHECK(imdb_ed25519_verify(sig, pk, m, sizeof m) == mono_check(pk, m, sizeof m, sig));
    }
}

/* Where Ed25519 implementations are known to differ (README: the verification
 * rule): every pair of edge encodings as A and R, with S = 0 and S = 1, three
 * ways (this path, Monocypher, the independent auditor). */
static void t_ed_edge_encodings(void)
{
    static const char *const pts[] = {
        "0100000000000000000000000000000000000000000000000000000000000000", /* identity */
        "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", /* identity, y = 1 + p */
        "0100000000000000000000000000000000000000000000000000000000000080", /* x = 0, sign bit set */
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", /* y = -1: order 2 */
        "0000000000000000000000000000000000000000000000000000000000000000", /* y = 0: order 4 */
        "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a", /* order 8 */
        "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05", /* order 8 */
        "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", /* y = p */
    };
    size_t np = sizeof pts / sizeof *pts, accepted = 0;
    for (size_t i = 0; i < np; i++)
        for (size_t j = 0; j < np; j++)
            for (int sz = 0; sz < 2; sz++) {
                uint8_t pk[32], sig[64] = {0};
                CHECK(imdb_unhex(pts[i], 64, pk, 32) && imdb_unhex(pts[j], 64, sig, 32));
                if (sz) sig[32] = 1;
                bool ours = imdb_ed25519_verify(sig, pk, "x", 1), mono = mono_check(pk, "x", 1, sig),
                     aud = a_ed25519_verify(pk, (const uint8_t *)"x", 1, sig);
                if (ours != mono || ours != aud)
                    fprintf(stderr, "    differ: A=%s R=%s S=%d fast=%d monocypher=%d audit=%d\n", pts[i], pts[j], sz, ours,
                            mono, aud);
                CHECK(ours == mono && ours == aud);
                accepted += ours;
            }
    CHECK(accepted == 64); /* the same count the auditor test pins */
}

/* The width-w NAF represents its scalar exactly, with the digit rules; and the
 * double-scalar product [s]B + [h]P (P = [k]B) equals [(s + h k) mod L]B. */
static void t_ed_wnaf(void)
{
    l_setup();
    for (int it = 0; it < 3000; it++) {
        uint8_t s[32], h[32], k[32];
        test_rand_bytes(s, 32);
        test_rand_bytes(h, 32);
        if (it == 0) memset(s, 0, 32);
        if (it == 1) memset(s, 0xff, 32); /* the final carry reaches digit 256 */
        if (it == 2) memcpy(s, L_LE, 32);
        for (int w = 5; w <= 7; w += 2) {
            int8_t r[257];
            int top = imdb_ed25519_wnaf(r, s, w);
            BIGNUM *acc = BN_new(), *t = BN_new(), *want = BN_lebin2bn(s, 32, NULL);
            BN_zero(acc);
            int last = -1000, hi = -1;
            for (int i = 256; i >= 0; i--) {
                BN_lshift1(acc, acc);
                if (!r[i]) continue;
                CHECK((r[i] & 1) && r[i] < (1 << (w - 1)) && r[i] > -(1 << (w - 1)));
                if (hi < 0) hi = i;
                CHECK(last - i >= w || last == -1000); /* nonzero digits at least w apart */
                last = i;
                BN_set_word(t, (BN_ULONG)(r[i] > 0 ? r[i] : -r[i]));
                if (r[i] > 0) BN_add(acc, acc, t);
                else BN_sub(acc, acc, t);
            }
            CHECK(BN_cmp(acc, want) == 0 && hi == top);
            BN_free(acc), BN_free(t), BN_free(want);
        }
        /* s and h below L, as verification uses them */
        uint8_t wide[64] = {0};
        memcpy(wide, s, 32);
        imdb_sc25519_reduce(s, wide);
        memcpy(wide, h, 32);
        imdb_sc25519_reduce(h, wide);
        test_rand_bytes(k, 32);
        k[31] &= 0x0f;
        uint8_t P[32], got[32], sum[32], want[32];
        imdb_ed25519_scalarbase(P, k);
        CHECK(imdb_ed25519_double_scalarmult(got, s, h, P));
        imdb_sc25519_muladd(sum, h, k, s);
        imdb_ed25519_scalarbase(want, sum);
        CHECK(memcmp(got, want, 32) == 0);
    }
}

/* ---- layer 5: batch verification ----------------------------------------------------- */

typedef struct bset {
    uint8_t pk[32];
    uint8_t sig[200][64];
    uint8_t msg[200][24];
    const uint8_t *sp[200], *mp[200];
    size_t len[200];
    bool ok[200];
} bset;

/* n valid signatures under one fresh key, on random messages */
static void bset_make(bset *b, size_t n)
{
    uint8_t seed[32], a[32], prefix[32];
    test_rand_bytes(seed, 32);
    imdb_ed25519_expand(seed, a, prefix, b->pk);
    for (size_t i = 0; i < n; i++) {
        test_rand_bytes(b->msg[i], sizeof b->msg[i]);
        b->len[i] = 1 + (size_t)(test_rand() % sizeof b->msg[i]);
        imdb_ed25519_sign(b->sig[i], a, prefix, b->pk, b->msg[i], b->len[i]);
        b->sp[i] = b->sig[i];
        b->mp[i] = b->msg[i];
    }
}

/* the batch verdicts, each and together, are Monocypher's single ones */
static bool bset_agrees(bset *b, size_t n)
{
    bool all = imdb_ed25519_verify_batch(n, b->sp, b->pk, b->mp, b->len, b->ok), want_all = true;
    for (size_t i = 0; i < n; i++) {
        bool want = mono_check(b->pk, b->mp[i], b->len[i], b->sp[i]);
        if (b->ok[i] != want) return false;
        want_all = want_all && want;
    }
    return all == want_all;
}

static void t_ed_batch_vs_single_body(void)
{
    static bset b;
    for (size_t n = 1; n <= 130; n++) { /* every size, across two group boundaries */
        bset_make(&b, n);
        CHECK(bset_agrees(&b, n));
        for (size_t i = 0; i < n; i++) CHECK(b.ok[i]);
    }
    for (size_t n = 64; n <= 70; n += 6) { /* one bad signature at every position */
        bset_make(&b, n);
        for (size_t pos = 0; pos < n; pos++) {
            uint8_t keep[64], mk = b.msg[pos][0];
            memcpy(keep, b.sig[pos], 64);
            switch (pos % 4) {
            case 0: b.sig[pos][test_rand() % 32] ^= (uint8_t)(1u << (test_rand() % 8)); break; /* R */
            case 1: b.sig[pos][32 + test_rand() % 31] ^= (uint8_t)(1u << (test_rand() % 8)); break; /* S */
            case 2: b.msg[pos][0] ^= 0x40; break;
            default: b.sig[pos][63] |= 0xf0; break; /* S >= L */
            }
            CHECK(bset_agrees(&b, n));
            CHECK(!b.ok[pos]);
            memcpy(b.sig[pos], keep, 64);
            b.msg[pos][0] = mk;
        }
    }
    bset_make(&b, 100); /* two bad ones, in different groups */
    b.sig[3][40] ^= 2;
    b.sig[97][10] ^= 4;
    CHECK(bset_agrees(&b, 100) && !b.ok[3] && !b.ok[97] && b.ok[4]);
    bset_make(&b, 9); /* a key that does not decode: every verdict false */
    b.pk[31] ^= 0x40;
    CHECK(bset_agrees(&b, 9));
}

/* The edge encodings of ed_edge_encodings, batched per key, plus a signature whose R
 * has a small-order part that its signer hashed (valid for the cofactored check
 * Monocypher uses, invalid for a cofactorless one): batch and singles agree. */
static void t_ed_batch_edges_body(void)
{
    static const char *const pts[] = {
        "0100000000000000000000000000000000000000000000000000000000000000", "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "0100000000000000000000000000000000000000000000000000000000000080", "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "0000000000000000000000000000000000000000000000000000000000000000", "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
        "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05", "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    };
    enum { NP = sizeof pts / sizeof *pts };
    for (size_t i = 0; i < NP; i++) {
        uint8_t pk[32], sig[2 * NP][64];
        const uint8_t *sp[2 * NP], *mp[2 * NP];
        size_t len[2 * NP];
        bool ok[2 * NP];
        CHECK(imdb_unhex(pts[i], 64, pk, 32));
        for (size_t j = 0; j < 2 * NP; j++) {
            memset(sig[j], 0, 64);
            CHECK(imdb_unhex(pts[j / 2], 64, sig[j], 32));
            sig[j][32] = (uint8_t)(j & 1);
            sp[j] = sig[j];
            mp[j] = (const uint8_t *)"x";
            len[j] = 1;
        }
        imdb_ed25519_verify_batch(2 * NP, sp, pk, mp, len, ok);
        for (size_t j = 0; j < 2 * NP; j++) CHECK(ok[j] == mono_check(pk, "x", 1, sig[j]));
    }
    /* R' = [r]B + T with T of order 8, h' = H(R' || A || M), S = r + h' a */
    static bset b;
    bset_make(&b, 5);
    uint8_t seed[32], a[32], prefix[32], one[32] = {1}, r[32], T[32], wide[64] = {0}, hh[64], h[32];
    test_rand_bytes(seed, 32);
    imdb_ed25519_expand(seed, a, prefix, b.pk);
    for (size_t i = 0; i < 5; i++) imdb_ed25519_sign(b.sig[i], a, prefix, b.pk, b.msg[i], b.len[i]);
    test_rand_bytes(wide, 32);
    imdb_sc25519_reduce(r, wide);
    CHECK(imdb_unhex(pts[5], 64, T, 32));
    CHECK(imdb_ed25519_double_scalarmult(b.sig[2], r, one, T));
    crypto_sha512_ctx c;
    crypto_sha512_init(&c);
    crypto_sha512_update(&c, b.sig[2], 32);
    crypto_sha512_update(&c, b.pk, 32);
    crypto_sha512_update(&c, b.msg[2], b.len[2]);
    crypto_sha512_final(&c, hh);
    imdb_sc25519_reduce(h, hh);
    imdb_sc25519_muladd(b.sig[2] + 32, h, a, r);
    CHECK(mono_check(b.pk, b.msg[2], b.len[2], b.sig[2])); /* cofactored: valid */
    CHECK(bset_agrees(&b, 5) && b.ok[2]);
}

/* Why the coefficients must be random: S_1 + d and S_2 - d make two invalid
 * signatures whose errors cancel when z_1 = z_2. A batch with those coefficients
 * is fooled; the one with random coefficients rejects both, exactly. */
static void t_ed_batch_needs_randomness_body(void)
{
    static bset b;
    bset_make(&b, 2);
    le_add_small(b.sig[0] + 32, 1);
    le_add_small(b.sig[1] + 32, -1);
    CHECK(!mono_check(b.pk, b.mp[0], b.len[0], b.sp[0]) && !mono_check(b.pk, b.mp[1], b.len[1], b.sp[1]));
    uint8_t z[32] = {0};
    z[0] = z[16] = 1;
    bool ok[2];
    CHECK(imdb_ed25519_verify_batch_z(2, b.sp, b.pk, b.mp, b.len, z, ok) && ok[0] && ok[1]);
    CHECK(!imdb_ed25519_verify_batch(2, b.sp, b.pk, b.mp, b.len, ok) && !ok[0] && !ok[1]);
}

/* each batch test on the scalar field, then (with AVX2) on the four-way one */
static void both_fields(void (*body)(void))
{
    imdb_ed25519_set_fe4(false);
    body();
    imdb_ed25519_set_fe4(true);
    if (!g_test_failed && imdb_fe4_available()) body();
}

static void t_ed_batch_vs_single(void) { both_fields(t_ed_batch_vs_single_body); }
static void t_ed_batch_edges(void) { both_fields(t_ed_batch_edges_body); }
static void t_ed_batch_needs_randomness(void) { both_fields(t_ed_batch_needs_randomness_body); }

const test_case ed25519_tests[] = {
    {"fe_arith", t_fe_arith},
    {"fe4_arith", t_fe4_arith},
    {"fe_invert_pow", t_fe_invert_pow},
    {"fe_tobytes_edges", t_fe_tobytes_edges},
    {"fe_frombytes", t_fe_frombytes},
    {"ge_constants", t_ge_constants},
    {"ge_order", t_ge_order},
    {"ge_scalarbase", t_ge_scalarbase},
    {"ge_decode", t_ge_decode},
    {"sc_reduce", t_sc_reduce},
    {"sc_muladd", t_sc_muladd},
    {"ed_wnaf", t_ed_wnaf},
    {"ge4_vertical", t_ge4_vertical},
    {"ed_sign_vs_monocypher", t_ed_sign_vs_monocypher},
    {"ed_verify_garbage", t_ed_verify_garbage},
    {"ed_edge_encodings", t_ed_edge_encodings},
    {"ed_batch_vs_single", t_ed_batch_vs_single},
    {"ed_batch_edges", t_ed_batch_edges},
    {"ed_batch_needs_randomness", t_ed_batch_needs_randomness},
};
const size_t ed25519_ntests = sizeof ed25519_tests / sizeof *ed25519_tests;
