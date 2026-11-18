/* N1a: IMDBWIR1's codec (server/wire.c; docs/n1-design.md §4). The value vectors are the contract the drivers keep; the
 * SCRAM exchange is recomputed with OpenSSL from RFC 5802's definitions over an AuthMessage built here by hand, and a
 * pinned exchange computed by a program of OpenSSL alone; every message round-trips byte for byte, any bytes a decoder
 * takes encode back to themselves (one encoding each), an encoder refuses what its decoder would, a ROWS frame is held
 * to its COLUMNS, and every allocation's failure is survived. */
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <stdlib.h>
#include <string.h>

#include "../../server/wire.h"
#include "../../src/codec.h"
#include "../../src/scram.h"
#include "test.h"

static imdb_err we;

static int nib(char c) { return c >= '0' && c <= '9' ? c - '0' : c >= 'a' && c <= 'f' ? c - 'a' + 10 : -1; }

static size_t unhex(const char *h, uint8_t *out, size_t cap)
{
    size_t n = 0;
    while (*h) {
        if (*h == ' ') {
            h++;
            continue;
        }
        int a = nib(h[0]), b = h[1] ? nib(h[1]) : -1;
        if (a < 0 || b < 0 || n == cap) abort(); /* a malformed vector: the test's own bug */
        out[n++] = (uint8_t)(a << 4 | b);
        h += 2;
    }
    return n;
}

static int value_decode(const uint8_t *p, size_t n, imdbw_value *v)
{
    imdb_rd r;
    imdb_rd_init(&r, p, n);
    imdb_err_clear(&we);
    int rc = imdbw_value_get(&r, v, &we);
    if (!rc && imdb_rd_left(&r)) rc = -100;
    return rc;
}

static const uint8_t kUuid[16] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};

typedef struct vec {
    imdbw_value v;
    const char *hex;
} vec;

/* the contract: each type's bytes (docs/n1-design.md §4) */
static const vec kVecs[] = {
    {{.null = true}, "80"},                                   /* a NULL of no type */
    {{.null = true, .type = IMDBW_T_INT64}, "81"},           /* a NULL INT64 */
    {{.null = true, .type = IMDBW_T_DECIMAL}, "85"},
    {{.null = true, .type = IMDBW_T_ENUM}, "8d"},
    {{.type = IMDBW_T_INT64, .i = -2}, "01 feffffffffffffff"},
    {{.type = IMDBW_T_INT64, .i = INT64_MIN}, "01 0000000000000080"},
    {{.type = IMDBW_T_FLOAT64, .f = 0x3ff8000000000000ull}, "02 000000000000f83f"}, /* 1.5 */
    {{.type = IMDBW_T_FLOAT64, .f = 0}, "02 0000000000000000"},                    /* the one zero */
    {{.type = IMDBW_T_BOOL, .i = 1}, "03 01"},
    {{.type = IMDBW_T_BOOL, .i = 0}, "03 00"},
    {{.type = IMDBW_T_TEXT, .s = (const uint8_t *)"h\xc3\xa9", .len = 3}, "04 03000000 68c3a9"},
    {{.type = IMDBW_T_TEXT, .s = (const uint8_t *)"", .len = 0}, "04 00000000"},
    {{.type = IMDBW_T_DECIMAL, .scale = 2, .d = -12345}, "05 02 c7cfffffffffffffffffffffffffffff"},
    {{.type = IMDBW_T_DECIMAL, .scale = 0, .d = 0}, "05 00 00000000000000000000000000000000"},
    {{.type = IMDBW_T_TIMESTAMP, .i = 1}, "06 0100000000000000"},
    {{.type = IMDBW_T_TIMESTAMP, .i = -62135596800000000LL}, "06 0040d400014023ff"}, /* 0001-01-01 00:00 */
    {{.type = IMDBW_T_TIMESTAMPTZ, .i = -1}, "07 ffffffffffffffff"},
    {{.type = IMDBW_T_TIMESTAMPTZ, .i = 253402300799999999LL}, "07 ff5f73cc0c448403"}, /* 9999-12-31 23:59:59.999999 */
    {{.type = IMDBW_T_DATE, .day = -719162}, "08 c606f5ff"}, /* 0001-01-01 */
    {{.type = IMDBW_T_DATE, .day = 2932896}, "08 a0c02c00"},  /* 9999-12-31 */
    {{.type = IMDBW_T_TIME, .i = 0}, "09 0000000000000000"},
    {{.type = IMDBW_T_TIME, .i = 86399999999}, "09 ff5fd71d14000000"}, /* 23:59:59.999999 */
    {{.type = IMDBW_T_UUID, .s = kUuid, .len = 16}, "0a 000102030405060708090a0b0c0d0e0f"},
    {{.type = IMDBW_T_BYTEA, .s = (const uint8_t *)"\x00\xff", .len = 2}, "0b 02000000 00ff"},
    {{.type = IMDBW_T_INTERVAL, .mon = 1, .day = -2, .i = 3}, "0c 01000000 feffffff 0300000000000000"},
    {{.type = IMDBW_T_INTERVAL, .mon = INT32_MIN, .day = INT32_MAX, .i = INT64_MIN}, "0c 00000080 ffffff7f 0000000000000080"},
    {{.type = IMDBW_T_ENUM, .s = (const uint8_t *)"a", .len = 1}, "0d 01 61"},
    {{.type = IMDBW_T_ENUM, .s = (const uint8_t *)"", .len = 0}, "0d 00"},
};
#define NVECS (sizeof kVecs / sizeof *kVecs)

static void t_wire_value_vectors(void)
{
    int64_t live = imdbw_live_blocks();
    for (size_t k = 0; k < NVECS; k++) {
        uint8_t want[64];
        size_t n = unhex(kVecs[k].hex, want, sizeof want);
        imdbw_buf b;
        imdbw_buf_init(&b);
        imdbw_value_put(&b, &kVecs[k].v);
        bool same = !b.err && b.len == n && !memcmp(b.p, want, n);
        imdbw_buf_free(&b);
        if (!same) fprintf(stderr, "    vector %zu\n", k);
        CHECK(same);
        imdbw_value v;
        CHECK(value_decode(want, n, &v) == 0);
        CHECK(imdbw_value_eq(&v, &kVecs[k].v));
        for (size_t cut = 0; cut < n; cut++) CHECK(value_decode(want, cut, &v) != 0); /* every prefix refused */
    }
    /* DECIMAL's range: 10^38 - 1 and its negation taken, 10^38 and -10^38 refused, scale 39 refused */
    __int128 lim = imdb_pow10_128(38);
    __int128 ds[] = {lim - 1, -(lim - 1), lim, -lim};
    for (int k = 0; k < 4; k++) {
        uint8_t x[18] = {IMDBW_T_DECIMAL, 38};
        unsigned __int128 u = (unsigned __int128)ds[k];
        for (int i = 0; i < 16; i++) x[2 + i] = (uint8_t)(u >> (8 * i));
        imdbw_value v;
        CHECK((value_decode(x, sizeof x, &v) == 0) == (k < 2));
        x[1] = 39;
        CHECK(value_decode(x, sizeof x, &v) != 0);
    }
    CHECK(imdbw_live_blocks() == live);
}

static void t_wire_value_refused(void)
{
    static const char *const refused[] = {
        "03 02",                                 /* a BOOL neither 0 nor 1 */
        "02 000000000000f07f",                   /* +infinity */
        "02 000000000000f0ff",                   /* -infinity */
        "02 010000000000f87f",                   /* a NaN */
        "02 0000000000000080",                   /* -0: the engine keeps one zero */
        "06 ff3fd400014023ff",                   /* a TIMESTAMP a microsecond before year 1 */
        "07 006073cc0c448403",                   /* a TIMESTAMPTZ a microsecond past 9999 */
        "09 ffffffffffffffff",                   /* TIME -1 */
        "09 0060d71d14000000",                   /* TIME 86,400,000,000: a day */
        "08 c506f5ff",                           /* a DATE before 0001-01-01 */
        "08 a1c02c00",                           /* a DATE after 9999-12-31 */
        "04 01000000 ff",                        /* TEXT not UTF-8 */
        "04 01000000 00",                        /* TEXT with a NUL */
        "04 02000000 c0af",                      /* an overlong encoding */
        "0d 01 c3",                              /* an ENUM label cut inside a character */
        "0d 01 00",                              /* an ENUM label with a NUL */
        "0e",                                    /* no type 14 */
        "00",                                    /* type 0 is a NULL's alone (0x80) */
        "8e",                                    /* a NULL of type 14 */
        "ff",                                    /* nor 255 */
        "",                                      /* nothing */
    };
    for (size_t k = 0; k < sizeof refused / sizeof *refused; k++) {
        uint8_t x[64];
        size_t n = unhex(refused[k], x, sizeof x);
        imdbw_value v;
        if (value_decode(x, n, &v) == 0) fprintf(stderr, "    taken: %s\n", refused[k]);
        CHECK(value_decode(x, n, &v) != 0);
    }
    /* a length past its bound refused before its bytes: TEXT, BYTEA 65,536, a label 64 */
    static const char *const limit[] = {"04 00000100", "0b 00000100", "0d 40"};
    for (size_t k = 0; k < 3; k++) {
        uint8_t x[8];
        size_t n = unhex(limit[k], x, sizeof x);
        imdbw_value v;
        CHECK(value_decode(x, n, &v) == IMDB_ERR_LIMIT);
    }
    /* the encoder refuses what the decoder would: nothing written, the buffer's error set */
    static const imdbw_value no[] = {
        {.type = IMDBW_T_BOOL, .i = 2},
        {.type = IMDBW_T_FLOAT64, .f = 0x8000000000000000ull},
        {.type = IMDBW_T_TEXT, .s = (const uint8_t *)"\xff", .len = 1},
        {.type = IMDBW_T_TEXT, .s = NULL, .len = 1},
        {.type = IMDBW_T_TEXT, .s = (const uint8_t *)"", .len = 65536},
        {.type = IMDBW_T_ENUM, .s = (const uint8_t *)"0123456789012345678901234567890123456789012345678901234567890123", .len = 64},
        {.type = IMDBW_T_DECIMAL, .scale = 39},
        {.type = IMDBW_T_DATE, .day = 2932897},
        {.type = IMDBW_T_TIMESTAMP, .i = INT64_MAX},
        {.type = IMDBW_T_UUID, .s = kUuid, .len = 15},
        {.type = 14},
        {.type = IMDBW_T_NONE},                  /* a value of no type */
        {.type = 14, .null = true},
    };
    for (size_t k = 0; k < sizeof no / sizeof *no; k++) {
        imdbw_buf b;
        imdbw_buf_init(&b);
        imdbw_value_put(&b, &no[k]);
        bool refused_ = b.err && !b.len;
        imdbw_buf_free(&b);
        CHECK(refused_ && !imdbw_value_ok(&no[k]));
    }
}

static void t_wire_utf8_fit(void)
{
    const uint8_t *s = (const uint8_t *)"ab\xc3\xa9" "c\xe2\x82\xac"; /* a b é c € */
    CHECK(imdbw_utf8_fit(s, 8, 100) == 8);
    CHECK(imdbw_utf8_fit(s, 8, 8) == 8);
    CHECK(imdbw_utf8_fit(s, 8, 7) == 5); /* € cut: before it */
    CHECK(imdbw_utf8_fit(s, 8, 6) == 5);
    CHECK(imdbw_utf8_fit(s, 8, 5) == 5);
    CHECK(imdbw_utf8_fit(s, 8, 3) == 2); /* é cut */
    CHECK(imdbw_utf8_fit(s, 8, 0) == 0);
    CHECK(imdbw_utf8_fit((const uint8_t *)"ab\xff" "cd", 5, 5) == 2); /* before the first byte that is not UTF-8 */
    CHECK(imdbw_utf8_fit((const uint8_t *)"ab\0cd", 5, 5) == 2);       /* nor a NUL */
    /* any bytes, any bound: the prefix is UTF-8 and nothing longer within the bound is */
    for (int round = 0; round < 20000; round++) {
        uint8_t x[24];
        size_t n = test_rand() % sizeof x, max = test_rand() % 26;
        for (size_t i = 0; i < n; i++) x[i] = (uint8_t)(test_rand() % 3 ? 0x61 + test_rand() % 3 : 0x80 + test_rand() % 0x70);
        size_t k = imdbw_utf8_fit(x, n, max);
        CHECK(k <= n && k <= max && (!k || imdb_utf8_valid(x, k, NULL)));
        size_t top = n < max ? n : max;
        for (size_t j = k + 1; j <= top; j++) CHECK(!imdb_utf8_valid(x, j, NULL));
    }
    /* the codec's own validator (scalar, so a client links no kernel) against the engine's: one verdict and one first
     * bad byte, on bytes drawn to reach every rule (lead bytes, continuations, the overlong, surrogate and U+10FFFF edges) */
    static const uint8_t pick[] = {0x00, 0x41, 0x7f, 0x80, 0x8f, 0x90, 0x9f, 0xa0, 0xbf, 0xc0, 0xc1, 0xc2, 0xdf, 0xe0,
                                   0xe1, 0xec, 0xed, 0xee, 0xef, 0xf0, 0xf1, 0xf3, 0xf4, 0xf5, 0xff};
    for (int round = 0; round < 200000; round++) {
        uint8_t x[12];
        size_t n = 1 + test_rand() % sizeof x;
        for (size_t i = 0; i < n; i++) x[i] = test_rand() % 4 ? pick[test_rand() % sizeof pick] : (uint8_t)test_rand();
        size_t bad = 0;
        bool ok = imdb_utf8_valid(x, n, &bad);
        CHECK(imdbw_utf8_fit(x, n, n) == (ok ? n : bad));
    }
}

/* the pre-auth messages: any bytes a decoder takes encode back to themselves */
static void t_wire_preauth(void)
{
    imdbw_hello h = {.version = 1};
    memcpy(h.user, "alice", 5);
    test_rand_bytes(h.nonce, sizeof h.nonce);
    uint8_t hb[IMDBW_HELLO_LEN], again[IMDBW_HELLO_LEN];
    CHECK(imdbw_hello_put(&h, hb) == 0);
    CHECK(!memcmp(hb, "IMDBWIR1\x01\0\0\0\0\0\0\0alice", 21));
    imdbw_hello g;
    CHECK_OK(imdbw_hello_get(hb, &g, &we));
    CHECK(!strcmp(g.user, "alice") && !memcmp(g.nonce, h.nonce, 32) && g.version == 1 && !g.flags);
    int took = 0, refused = 0;
    for (size_t i = 0; i < sizeof hb; i++)
        for (int f = 0; f < 3; f++) {
            uint8_t x[IMDBW_HELLO_LEN];
            memcpy(x, hb, sizeof x);
            x[i] ^= (uint8_t)(f == 0 ? 0x01 : f == 1 ? 0x80 : 0xff);
            imdb_err_clear(&we);
            if (imdbw_hello_get(x, &g, &we) == 0) {
                CHECK(imdbw_hello_put(&g, again) == 0);
                CHECK(!memcmp(again, x, sizeof x));
                took++;
            } else
                refused++;
        }
    CHECK(took >= 32 * 3 + 1 && refused >= 16 * 3); /* the nonce's flips taken and flags 1 (§8f: a binding type), the
                                                     * magic's, version's and the other flags' refused */
    for (uint32_t fl = 0; fl < 5; fl++) { /* §8f: 0 none, 1 the exporter, 2 tls-server-end-point; past them refused */
        uint8_t y[IMDBW_HELLO_LEN];
        memcpy(y, hb, sizeof y);
        y[12] = (uint8_t)fl;
        imdb_err_clear(&we);
        int r2 = imdbw_hello_get(y, &g, &we);
        CHECK(fl <= IMDBW_CB_ENDPOINT ? r2 == 0 && g.flags == fl : r2 == IMDB_ERR_CORRUPT);
    }
    /* a later version and a later magic refused by name; another magic, version 0 and flags as damage */
    uint8_t x[IMDBW_HELLO_LEN];
    memcpy(x, hb, sizeof x);
    x[8] = 2;
    imdb_err_clear(&we);
    CHECK(imdbw_hello_get(x, &g, &we) == IMDB_ERR_UNSUPPORTED && strstr(we.msg, "version 2"));
    memcpy(x, hb, sizeof x);
    x[7] = '2';
    imdb_err_clear(&we);
    CHECK(imdbw_hello_get(x, &g, &we) == IMDB_ERR_UNSUPPORTED && strstr(we.msg, "IMDBWIR2"));
    x[7] = '0';
    CHECK(imdbw_hello_get(x, &g, &we) == IMDB_ERR_CORRUPT);
    memcpy(x, hb, sizeof x);
    x[0] = 'X';
    CHECK(imdbw_hello_get(x, &g, &we) == IMDB_ERR_CORRUPT);
    memcpy(x, hb, sizeof x);
    x[8] = 0;
    CHECK(imdbw_hello_get(x, &g, &we) == IMDB_ERR_CORRUPT);
    memcpy(x, hb, sizeof x);
    x[12] = 3; /* §8f: a binding type past 2 */
    CHECK(imdbw_hello_get(x, &g, &we) == IMDB_ERR_CORRUPT);
    /* the role name: 1 to 63 bytes of UTF-8, NUL-padded */
    memcpy(x, hb, sizeof x);
    memset(x + 16, 0, IMDBW_USER);
    CHECK(imdbw_hello_get(x, &g, &we) != 0); /* empty */
    memset(x + 16, 'a', IMDBW_USER);
    CHECK(imdbw_hello_get(x, &g, &we) != 0); /* 64 bytes: no NUL */
    x[16 + 63] = 0;
    CHECK_OK(imdbw_hello_get(x, &g, &we)); /* 63 */
    CHECK(strlen(g.user) == 63);
    memset(x + 16, 0, IMDBW_USER);
    x[16] = 'a';
    x[18] = 'b';
    CHECK(imdbw_hello_get(x, &g, &we) != 0); /* a byte past the NUL */
    x[18] = 0;
    x[16] = (char)0xff;
    CHECK(imdbw_hello_get(x, &g, &we) != 0); /* not UTF-8 */
    CHECK(imdbw_user_ok("\xc3\xa9", 2) && !imdbw_user_ok("", 0) && !imdbw_user_ok("\xc3", 1));
    /* the head every version keeps: any version read (the server answers a later one with its own head and a close),
     * version 0 and another magic as damage, a later magic by name */
    uint32_t ver;
    CHECK(imdbw_preauth_head(hb, &ver, &we) == 0 && ver == 1);
    memcpy(x, hb, IMDBW_PREAUTH_HEAD);
    imdb_le32(x + 8, 7);
    CHECK(imdbw_preauth_head(x, &ver, &we) == 0 && ver == 7);
    imdb_le32(x + 8, 0);
    CHECK(imdbw_preauth_head(x, &ver, &we) == IMDB_ERR_CORRUPT);
    imdb_le32(x + 8, 1);
    x[7] = '2';
    CHECK(imdbw_preauth_head(x, &ver, &we) == IMDB_ERR_UNSUPPORTED);
    x[0] = 'X';
    CHECK(imdbw_preauth_head(x, &ver, &we) == IMDB_ERR_CORRUPT);
    uint8_t va[IMDBW_PREAUTH_HEAD];
    imdbw_version_put(va);
    CHECK(!memcmp(va, "IMDBWIR1\x01\0\0\0", 12) && !memcmp(va, hb, 12));
    /* the encoder refuses what the decoder would */
    imdbw_hello hh = h;
    hh.version = 2;
    CHECK(imdbw_hello_put(&hh, x) != 0);
    hh = h;
    hh.flags = 3;
    CHECK(imdbw_hello_put(&hh, x) != 0);
    hh.flags = IMDBW_CB_ENDPOINT;
    CHECK(imdbw_hello_put(&hh, x) == 0 && x[12] == 2);
    hh = h;
    memset(hh.user, 0, sizeof hh.user);
    CHECK(imdbw_hello_put(&hh, x) != 0);
    hh.user[0] = (char)0xc3;
    CHECK(imdbw_hello_put(&hh, x) != 0);

    imdbw_challenge c = {.version = 1, .salt_len = 16, .iter = 4096};
    test_rand_bytes(c.salt, 16);
    test_rand_bytes(c.nonce, 32);
    uint8_t cb[IMDBW_CHALLENGE_LEN], cagain[IMDBW_CHALLENGE_LEN];
    CHECK(imdbw_challenge_put(&c, cb) == 0);
    imdbw_challenge d;
    CHECK_OK(imdbw_challenge_get(cb, &d, &we));
    CHECK(d.salt_len == 16 && !memcmp(d.salt, c.salt, 64) && d.iter == 4096 && !memcmp(d.nonce, c.nonce, 32));
    took = refused = 0;
    for (size_t i = 0; i < sizeof cb; i++)
        for (int f = 0; f < 3; f++) {
            uint8_t y[IMDBW_CHALLENGE_LEN];
            memcpy(y, cb, sizeof y);
            y[i] ^= (uint8_t)(f == 0 ? 0x01 : f == 1 ? 0x80 : 0xff);
            if (imdbw_challenge_get(y, &d, &we) == 0) {
                CHECK(imdbw_challenge_put(&d, cagain) == 0);
                CHECK(!memcmp(cagain, y, sizeof y));
                took++;
            } else
                refused++;
        }
    CHECK(took >= (16 + 32) * 3 && refused >= (48 + 7) * 3); /* salt, nonce taken; the salt's padding and the tail refused */
    static const struct {
        uint8_t salt_len;
        uint32_t iter;
        bool ok;
    } sc[] = {{7, 4096, false}, {8, 4096, true}, {64, 4096, true}, {65, 4096, false}, {16, 999, false},
              {16, 1000, true}, {16, 1000000, true}, {16, 1000001, false}};
    for (size_t k = 0; k < sizeof sc / sizeof *sc; k++) {
        imdbw_challenge ch = c;
        ch.salt_len = sc[k].salt_len;
        ch.iter = sc[k].iter;
        CHECK((imdbw_challenge_put(&ch, cb) == 0) == sc[k].ok);
        if (!sc[k].ok) { /* the same bytes made by hand: the decoder refuses them too */
            ch.salt_len = 16;
            ch.iter = 4096;
            CHECK(imdbw_challenge_put(&ch, cb) == 0);
            cb[12] = sc[k].salt_len;
            imdb_le32(cb + 13 + IMDBW_SALT, sc[k].iter);
        }
        CHECK((imdbw_challenge_get(cb, &d, &we) == 0) == sc[k].ok);
    }
    CHECK(imdbw_challenge_put(&c, cb) == 0);
    cb[13 + 16] = 1; /* a byte in the salt's padding */
    CHECK(imdbw_challenge_get(cb, &d, &we) != 0);

    imdbw_verdict vd = {.code = 0};
    test_rand_bytes(vd.sig, 32);
    uint8_t vb[IMDBW_VERDICT_LEN];
    CHECK(imdbw_verdict_put(&vd, vb) == 0);
    imdbw_verdict ve;
    CHECK_OK(imdbw_verdict_get(vb, &ve, &we));
    CHECK(ve.code == 0 && !memcmp(ve.sig, vd.sig, 32));
    vb[0] = 1;
    CHECK(imdbw_verdict_get(vb, &ve, &we) != 0); /* a refusal with a signature */
    vd.code = 1;
    CHECK(imdbw_verdict_put(&vd, vb) != 0);
    memset(vd.sig, 0, 32);
    CHECK(imdbw_verdict_put(&vd, vb) == 0);
    CHECK_OK(imdbw_verdict_get(vb, &ve, &we));
    vb[0] = 2; /* §8f: the binding type refused, no signature */
    CHECK_OK(imdbw_verdict_get(vb, &ve, &we));
    CHECK(ve.code == IMDBW_VERDICT_BINDING);
    vb[4] = 1;
    CHECK(imdbw_verdict_get(vb, &ve, &we) != 0); /* with a signature: refused */
    vb[4] = 0;
    vb[0] = 3;
    CHECK(imdbw_verdict_get(vb, &ve, &we) != 0);
    vd.code = 3;
    CHECK(imdbw_verdict_put(&vd, vb) != 0);
}

/* RFC 5802's computation with OpenSSL, from the password */
static void ossl_scram(const char *pw, const uint8_t *salt, int salt_len, uint32_t iter, const uint8_t *am,
                       uint8_t proof[32], uint8_t ssig[32], uint8_t stored[32], uint8_t skey[32])
{
    uint8_t sp[32], ck[32], cs[32];
    unsigned int n = 32;
    PKCS5_PBKDF2_HMAC(pw, (int)strlen(pw), salt, salt_len, (int)iter, EVP_sha256(), 32, sp);
    HMAC(EVP_sha256(), sp, 32, (const uint8_t *)"Client Key", 10, ck, &n);
    HMAC(EVP_sha256(), sp, 32, (const uint8_t *)"Server Key", 10, skey, &n);
    SHA256(ck, 32, stored);
    HMAC(EVP_sha256(), stored, 32, am, IMDBW_AUTHMSG_LEN, cs, &n);
    for (int i = 0; i < 32; i++) proof[i] = ck[i] ^ cs[i];
    HMAC(EVP_sha256(), skey, 32, am, IMDBW_AUTHMSG_LEN, ssig, &n);
}

static void t_wire_scram(void)
{
    /* the AuthMessage, built here: the magic, the endpoint, the two messages' bytes, the binding */
    imdbw_hello h = {.version = 1, .flags = IMDBW_CB_EXPORTER}; /* §8f: TCP by the exporter */
    memcpy(h.user, "alice", 5);
    memset(h.nonce, 0x01, 32);
    imdbw_challenge c = {.version = 1, .salt_len = 16, .iter = 4096};
    memset(c.salt, 0x03, 16);
    memset(c.nonce, 0x02, 32);
    uint8_t hb[IMDBW_HELLO_LEN], cb[IMDBW_CHALLENGE_LEN], bind[32];
    CHECK(imdbw_hello_put(&h, hb) == 0 && imdbw_challenge_put(&c, cb) == 0);
    memset(bind, 0x04, 32);
    uint8_t am[IMDBW_AUTHMSG_LEN], want[IMDBW_AUTHMSG_LEN];
    imdbw_auth_message(IMDBW_EP_TCP, hb, cb, bind, am);
    memcpy(want, "IMDBWIR1-SCRAM", 14);
    want[14] = 1;
    memcpy(want + 15, hb, sizeof hb);
    memcpy(want + 15 + sizeof hb, cb, sizeof cb);
    memset(want + 15 + sizeof hb + sizeof cb, 0x04, 32);
    CHECK(!memcmp(am, want, sizeof am));

    /* the pinned exchange (a driver's first test): password "pencil" over the AuthMessage above */
    uint8_t proof[32], ssig[32], oproof[32], ossig[32], ostored[32], oskey[32], sig[32], pin[32];
    CHECK(imdbw_scram_client("pencil", 6, &c, am, proof, ssig) == 0);
    ossl_scram("pencil", c.salt, 16, 4096, am, oproof, ossig, ostored, oskey);
    CHECK(!memcmp(proof, oproof, 32) && !memcmp(ssig, ossig, 32));
    /* computed once by a program of OpenSSL alone, every byte of the hello, the challenge and the AuthMessage laid
     * out there from docs/n1-design.md §4 (v3, 2026-11-18: §8f's binding type in the hello's flags; the program printed
     * v2's numbers for flags 0, so its layout is v2's but that byte) */
    unhex("28562c1bef99b0a917ecb28c1b32c22930f154f92c134b13fee7a64e8deb733e", pin, 32);
    CHECK(!memcmp(proof, pin, 32));
    unhex("5d3ef834c39e6c429d1f4e27993ba451a8b8e35322af9055abc1dd40e88ad322", pin, 32);
    CHECK(!memcmp(ssig, pin, 32));
    /* the other two exchanges a driver meets: TCP by tls-server-end-point (flags 2, binding 32 x 05) and the socket
     * (endpoint 2, flags 0, binding zeros); and a proof over a hello whose type byte alone differs is refused */
    static const struct {
        uint8_t ep, flags, bind;
        const char *proof, *ssig;
    } more[] = {
        {IMDBW_EP_TCP, IMDBW_CB_ENDPOINT, 0x05, "1065f5e038b75f2671d831f5bd5d29f56d22a787f260db523bb986ef7c53f486",
         "28fef60553090aae9b5f184bfc0cfb455e58261131da359f525a59f4dfaa9904"},
        {IMDBW_EP_UNIX, IMDBW_CB_NONE, 0x00, "5ee7e7bd402f0c91e2399a84c3d544763bace50b44ea82a780e57130bb5405a7",
         "82c9d498cc5fa830d26b29740244ecf4f343962f302a647150e9d74ea7588027"},
    };
    for (size_t k = 0; k < sizeof more / sizeof more[0]; k++) {
        imdbw_hello h2 = h;
        h2.flags = more[k].flags;
        uint8_t hb2[IMDBW_HELLO_LEN], bind2[32], am2[IMDBW_AUTHMSG_LEN], p2[32], s2[32];
        CHECK(imdbw_hello_put(&h2, hb2) == 0 && hb2[12] == more[k].flags);
        memset(bind2, more[k].bind, 32);
        imdbw_auth_message(more[k].ep, hb2, cb, bind2, am2);
        CHECK(imdbw_scram_client("pencil", 6, &c, am2, p2, s2) == 0);
        unhex(more[k].proof, pin, 32);
        CHECK(!memcmp(p2, pin, 32));
        unhex(more[k].ssig, pin, 32);
        CHECK(!memcmp(s2, pin, 32));
    }
    {
        imdb_scram v0;
        CHECK_OK(imdb_scram_make("pencil", 6, 4096, c.salt, 16, &v0, &we));
        for (uint8_t fl = 0; fl <= IMDBW_CB_ENDPOINT; fl++) { /* the hello the server got says fl, the proof's says 1 */
            uint8_t hb2[IMDBW_HELLO_LEN], am2[IMDBW_AUTHMSG_LEN];
            memcpy(hb2, hb, sizeof hb2);
            hb2[12] = fl;
            imdbw_auth_message(IMDBW_EP_TCP, hb2, cb, bind, am2);
            CHECK(imdbw_scram_server(v0.stored, v0.server, am2, proof, sig) == (fl == IMDBW_CB_EXPORTER));
        }
    }

    /* the server, from the verifier CREATE ROLE makes of the same password and salt */
    imdb_scram v;
    CHECK_OK(imdb_scram_make("pencil", 6, 4096, c.salt, 16, &v, &we));
    CHECK(!memcmp(v.stored, ostored, 32) && !memcmp(v.server, oskey, 32));
    CHECK(imdbw_scram_server(v.stored, v.server, am, proof, sig) && !memcmp(sig, ssig, 32));
    for (int bit = 0; bit < 256; bit++) { /* any bit of the proof off: refused */
        uint8_t p2[32];
        memcpy(p2, proof, 32);
        p2[bit / 8] ^= (uint8_t)(1u << (bit % 8));
        CHECK(!imdbw_scram_server(v.stored, v.server, am, p2, sig));
    }
    for (size_t i = 0; i < sizeof am; i++) { /* any byte of the AuthMessage another: refused (every byte is bound) */
        uint8_t am2[IMDBW_AUTHMSG_LEN];
        memcpy(am2, am, sizeof am2);
        am2[i] ^= 0x20;
        CHECK(!imdbw_scram_server(v.stored, v.server, am2, proof, sig));
    }
    CHECK(imdbw_scram_client("pencim", 6, &c, am, proof, ssig) == 0); /* another password */
    CHECK(!imdbw_scram_server(v.stored, v.server, am, proof, sig));
    /* the socket's AuthMessage: endpoint 2, the binding zeros */
    uint8_t zero[32] = {0}, am3[IMDBW_AUTHMSG_LEN];
    imdbw_auth_message(IMDBW_EP_UNIX, hb, cb, zero, am3);
    CHECK(am3[14] == 2 && !memcmp(am3 + IMDBW_AUTHMSG_LEN - 32, zero, 32) && !memcmp(am3 + 15, am + 15, IMDBW_AUTHMSG_LEN - 47));

    /* drawn passwords, salts and the iteration bounds, each against OpenSSL and the engine's verifier */
    for (int k = 0; k < 12; k++) {
        char pw[80];
        size_t pl = 1 + test_rand() % 70;
        for (size_t i = 0; i < pl; i++) pw[i] = (char)(0x20 + test_rand() % 95);
        pw[pl] = 0;
        c.salt_len = (uint8_t)(8 + test_rand() % 57);
        memset(c.salt, 0, sizeof c.salt);
        test_rand_bytes(c.salt, c.salt_len);
        c.iter = k < 6 ? 1000 : k < 11 ? 1000 + (uint32_t)(test_rand() % 3000) : 4096;
        test_rand_bytes(h.nonce, 32);
        test_rand_bytes(c.nonce, 32);
        test_rand_bytes(bind, 32);
        CHECK(imdbw_hello_put(&h, hb) == 0 && imdbw_challenge_put(&c, cb) == 0);
        imdbw_auth_message(IMDBW_EP_TCP, hb, cb, bind, am);
        CHECK(imdbw_scram_client(pw, pl, &c, am, proof, ssig) == 0);
        ossl_scram(pw, c.salt, c.salt_len, c.iter, am, oproof, ossig, ostored, oskey);
        CHECK(!memcmp(proof, oproof, 32) && !memcmp(ssig, ossig, 32));
        CHECK_OK(imdb_scram_make(pw, pl, c.iter, c.salt, c.salt_len, &v, &we));
        CHECK(imdbw_scram_server(v.stored, v.server, am, proof, sig) && !memcmp(sig, ssig, 32));
    }
    /* the client refuses a password CREATE ROLE would, and a challenge its decoder would */
    c.salt_len = 16;
    c.iter = 1000;
    CHECK(imdbw_scram_client("", 0, &c, am, proof, ssig) != 0);
    CHECK(imdbw_scram_client("a\x7f", 2, &c, am, proof, ssig) != 0);
    CHECK(imdbw_scram_client("a\x1f", 2, &c, am, proof, ssig) != 0);
    CHECK(imdbw_scram_client("\xc3\xa9", 2, &c, am, proof, ssig) != 0);
    char big[1026];
    memset(big, 'a', sizeof big);
    CHECK(imdbw_scram_client(big, 1025, &c, am, proof, ssig) != 0);
    CHECK(imdbw_scram_client(big, 1024, &c, am, proof, ssig) == 0);
    c.iter = 999;
    CHECK(imdbw_scram_client("pencil", 6, &c, am, proof, ssig) != 0);
}

static void t_wire_fake_salt(void)
{
    uint8_t s1[32], s2[32], a[16], b[16], x[16];
    memset(s1, 7, 32);
    memset(s2, 8, 32);
    imdbw_fake_salt(s1, "alice", a);
    imdbw_fake_salt(s1, "alice", x);
    CHECK(!memcmp(a, x, 16)); /* the same at every attempt */
    imdbw_fake_salt(s1, "bob", b);
    CHECK(memcmp(a, b, 16));
    imdbw_fake_salt(s2, "alice", b);
    CHECK(memcmp(a, b, 16));
    uint8_t field[64] = {0}, mac[32];
    unsigned int n = 32;
    memcpy(field, "alice", 5);
    HMAC(EVP_sha256(), s1, 32, field, 64, mac, &n);
    CHECK(!memcmp(a, mac, 16));
}

/* ---- messages ---- */

static const imdbw_text kTexts[] = {{(const uint8_t *)"SELECT $1, $2", 13}, {(const uint8_t *)"BEGIN", 5},
                                    {(const uint8_t *)"\xc3\xa9", 2}};
static const imdbw_text kLabels[] = {{(const uint8_t *)"", 0}, {(const uint8_t *)"x", 1}, {(const uint8_t *)"\xc3\xa9", 2}};

/* the samples: one message of every type, the value-carrying ones' bytes in their own buffers */
typedef struct smp {
    imdbw_msg m[24];
    size_t n;
    size_t kcols, krows; /* the COLUMNS sample and the ROWS sample (its columns) */
    imdbw_text texts[3], labels[3];
    imdbw_span params[3];
    imdbw_col cols[4];
    imdbw_buf bq0, bq2, be, br;
} smp;

static imdbw_span span_of(imdbw_buf *b, const imdbw_value *v, uint32_t n)
{
    imdbw_buf_init(b);
    for (uint32_t i = 0; i < n; i++) imdbw_value_put(b, &v[i]);
    return (imdbw_span){b->p, b->len, n};
}

static void samples(smp *s)
{
    memset(s, 0, sizeof *s);
    memcpy(s->texts, kTexts, sizeof kTexts);
    memcpy(s->labels, kLabels, sizeof kLabels);
    imdbw_col *c = s->cols;
    strcpy(c[0].name, "id");
    c[0].type = IMDBW_T_INT64;
    c[0].precision = 32;
    strcpy(c[1].name, "amount");
    c[1].type = IMDBW_T_DECIMAL;
    c[1].precision = 38;
    c[1].scale = 6;
    strcpy(c[2].name, "name");
    c[2].type = IMDBW_T_TEXT;
    c[2].precision = 12;
    strcpy(c[3].name, "mood");
    c[3].type = IMDBW_T_ENUM;
    c[3].labels = s->labels;
    c[3].nlabels = 3;
    imdbw_value q0[] = {{.type = IMDBW_T_INT64, .i = 7}, {.type = IMDBW_T_TEXT, .s = (const uint8_t *)"t", .len = 1}};
    imdbw_value q2[] = {{.null = true, .type = IMDBW_T_ENUM}}; /* a NULL ENUM: the one ENUM a parameter can be */
    s->params[0] = span_of(&s->bq0, q0, 2);
    s->params[2] = span_of(&s->bq2, q2, 1);
    imdbw_value ev[8] = {
        {.type = IMDBW_T_INT64, .i = -2},
        {.type = IMDBW_T_FLOAT64, .f = 0x3ff8000000000000ull},
        {.null = true},                                         /* a NULL of no type among them */
        {.type = IMDBW_T_DECIMAL, .scale = 2, .d = -12345},
        {.type = IMDBW_T_TIMESTAMPTZ, .i = -1},
        {.type = IMDBW_T_DATE, .day = 2932896},
        {.type = IMDBW_T_UUID, .s = kUuid, .len = 16},
        {.type = IMDBW_T_INTERVAL, .mon = INT32_MIN, .day = INT32_MAX, .i = INT64_MIN},
    };
    s->m[s->n].type = IMDBW_EXECUTE;
    strcpy(s->m[s->n].name, "p1");
    s->m[s->n].nsets = 2;
    s->m[s->n].nvals = 4;
    s->m[s->n++].vals = span_of(&s->be, ev, 8);
    __int128 lim = imdb_pow10_128(38);
    imdbw_value rv[] = {{.type = IMDBW_T_INT64, .i = INT32_MIN},
                        {.type = IMDBW_T_DECIMAL, .scale = 6, .d = -1234567},
                        {.type = IMDBW_T_TEXT, .s = (const uint8_t *)"h\xc3\xa9llo", .len = 6},
                        {.type = IMDBW_T_ENUM, .s = (const uint8_t *)"x", .len = 1},
                        {.null = true, .type = IMDBW_T_INT64},
                        {.type = IMDBW_T_DECIMAL, .scale = 6, .d = lim - 1},
                        {.type = IMDBW_T_TEXT, .s = (const uint8_t *)"", .len = 0},
                        {.type = IMDBW_T_ENUM, .s = (const uint8_t *)"", .len = 0}};
    s->m[s->n++] = (imdbw_msg){.type = IMDBW_QUERY, .texts = s->texts, .params = s->params, .ntexts = 3};
    s->m[s->n++] = (imdbw_msg){.type = IMDBW_QUERY, .texts = s->texts + 1, .params = s->params + 1, .ntexts = 1};
    s->m[s->n] = (imdbw_msg){.type = IMDBW_PREPARE, .texts = s->texts, .ntexts = 1};
    strcpy(s->m[s->n++].name, "p1");
    s->m[s->n] = (imdbw_msg){.type = IMDBW_PREPARE, .texts = s->texts + 1, .ntexts = 1};
    memset(s->m[s->n++].name, 'n', IMDBW_NAME_MAX); /* 63 bytes, the longest */
    s->m[s->n] = (imdbw_msg){.type = IMDBW_EXECUTE, .nsets = 3, .nvals = 0};
    strcpy(s->m[s->n++].name, "p2");
    s->m[s->n] = (imdbw_msg){.type = IMDBW_DEALLOCATE};
    strcpy(s->m[s->n++].name, "p1");
    s->m[s->n++] = (imdbw_msg){.type = IMDBW_COPY_DATA, .data = (const uint8_t *)"a,b\n\x00\xff", .dlen = 6};
    s->m[s->n++] = (imdbw_msg){.type = IMDBW_COPY_DONE};
    s->m[s->n++] = (imdbw_msg){.type = IMDBW_COPY_FAIL, .texts = s->texts, .ntexts = 1};
    s->m[s->n++] = (imdbw_msg){.type = IMDBW_CANCEL};
    s->m[s->n++] = (imdbw_msg){.type = IMDBW_PING};
    s->m[s->n++] = (imdbw_msg){.type = IMDBW_TERMINATE};
    s->kcols = s->n;
    s->m[s->n++] = (imdbw_msg){.type = IMDBW_COLUMNS, .cols = s->cols, .ncols = 4};
    s->krows = s->n;
    s->m[s->n++] = (imdbw_msg){.type = IMDBW_ROWS, .vals = span_of(&s->br, rv, 8), .nsets = 2, .nvals = 4};
    imdbw_msg d = {.type = IMDBW_DONE, .status = {(const uint8_t *)"INSERT 0 3", 10}, .has_read = true, .has_write = true,
                   .count = 3, .read_commit = 41, .lake_commit = 44, .write_commit = 42}; /* a lake past the read point: an AS OF */
    memset(d.read_hash, 1, 32);
    memset(d.digest, 2, 32);
    memset(d.lake_manifest, 3, 32);
    memset(d.db_id, 4, 16);
    d.own = true; /* a read inside its transaction, its own writes seen */
    memset(d.write_hash, 5, 32);
    s->m[s->n++] = d;
    s->m[s->n++] = (imdbw_msg){.type = IMDBW_DONE, .status = {(const uint8_t *)"", 0}};
    s->m[s->n++] = (imdbw_msg){.type = IMDBW_DONE, .status = {(const uint8_t *)"SELECT 0", 8}, .has_read = true};
    s->m[s->n++] = (imdbw_msg){.type = IMDBW_ERROR, .code = 5, .index = 2, .texts = s->texts + 1, .ntexts = 1};
    s->m[s->n++] = (imdbw_msg){.type = IMDBW_WARNING, .texts = s->texts + 2, .ntexts = 1};
    s->m[s->n++] = (imdbw_msg){.type = IMDBW_COPY_IN};
    s->m[s->n++] = (imdbw_msg){.type = IMDBW_COPY_OUT, .data = (const uint8_t *)"1,2\n", .dlen = 4};
    s->m[s->n++] = (imdbw_msg){.type = IMDBW_READY, .state = IMDBW_DOOMED};
    s->m[s->n++] = (imdbw_msg){.type = IMDBW_PONG};
    if (imdbw_cols_index(&s->m[s->kcols])) abort();
}

static void samples_free(smp *s)
{
    imdbw_cols_unindex(&s->m[s->kcols]);
    imdbw_buf_free(&s->bq0);
    imdbw_buf_free(&s->bq2);
    imdbw_buf_free(&s->be);
    imdbw_buf_free(&s->br);
}

static bool type_is_server(uint8_t t) { return t >= IMDBW_COLUMNS; }

/* the frame's body decoded, then encoded again: 0 and the same frame, or the decoder's refusal */
static int reencode(const uint8_t *frame, size_t len, const imdbw_msg *cols, bool *same)
{
    *same = false;
    uint32_t flen;
    uint8_t type;
    if (len < IMDBW_HEAD) return -1;
    imdb_err_clear(&we);
    int rc = imdbw_head_get(frame, type_is_server(frame[4]), &flen, &type, &we);
    if (rc) return rc;
    if ((size_t)flen + 4 != len) return -2;
    imdbw_msg m;
    if ((rc = imdbw_msg_get(type, frame + IMDBW_HEAD, len - IMDBW_HEAD, cols, &m, &we))) return rc;
    imdbw_buf b;
    imdbw_buf_init(&b);
    imdbw_msg_put(&b, &m, cols);
    *same = !b.err && b.len == len && !memcmp(b.p, frame, len);
    imdbw_buf_free(&b);
    imdbw_msg_free(&m);
    return 0;
}

static void t_wire_messages(void)
{
    int64_t live = imdbw_live_blocks();
    smp s;
    samples(&s);
    const imdbw_msg *cols = &s.m[s.kcols];
    for (size_t k = 0; k < s.n; k++) {
        imdbw_buf b;
        imdbw_buf_init(&b);
        imdbw_msg_put(&b, &s.m[k], cols);
        CHECK(!b.err && b.len >= IMDBW_HEAD && b.p[4] == s.m[k].type);
        bool same;
        int rc = reencode(b.p, b.len, cols, &same);
        imdbw_buf_free(&b);
        if (rc || !same) fprintf(stderr, "    sample %zu (type %u): %d %s\n", k, s.m[k].type, rc, we.msg);
        CHECK(rc == 0 && same);
    }
    /* the decoded fields themselves */
    imdbw_buf b;
    imdbw_buf_init(&b);
    imdbw_msg_put(&b, cols, NULL);
    imdbw_msg d;
    CHECK_OK(imdbw_msg_get(IMDBW_COLUMNS, b.p + IMDBW_HEAD, b.len - IMDBW_HEAD, NULL, &d, &we));
    bool ok = d.ncols == 4 && !strcmp(d.cols[1].name, "amount") && d.cols[1].precision == 38 && d.cols[1].scale == 6 &&
              d.cols[3].nlabels == 3 && d.cols[3].labels[2].len == 2 && !memcmp(d.cols[3].labels[2].p, "\xc3\xa9", 2) &&
              d.cols[3].sorted != NULL;
    imdbw_msg_free(&d);
    imdbw_buf_free(&b);
    CHECK(ok);
    imdbw_buf_init(&b);
    imdbw_msg_put(&b, &s.m[1], cols); /* QUERY: three statements, values 2, 0 and 1 */
    CHECK_OK(imdbw_msg_get(IMDBW_QUERY, b.p + IMDBW_HEAD, b.len - IMDBW_HEAD, NULL, &d, &we));
    ok = d.ntexts == 3 && d.params[0].n == 2 && d.params[1].n == 0 && d.params[2].n == 1 && d.texts[0].len == 13;
    imdb_rd r;
    imdbw_value v;
    imdbw_span_begin(&d.params[0], &r);
    ok = ok && imdbw_span_next(&r, &v) && v.type == IMDBW_T_INT64 && v.i == 7 && imdbw_span_next(&r, &v) &&
         v.type == IMDBW_T_TEXT && v.len == 1 && !imdbw_span_next(&r, &v) && !r.err;
    imdbw_msg_free(&d);
    imdbw_buf_free(&b);
    CHECK(ok);
    samples_free(&s);
    CHECK(imdbw_live_blocks() == live);
}

/* a ROWS frame held to its COLUMNS: each value its column's type or NULL, at its scale, within its precision, width,
 * VARCHAR length and labels */
static void t_wire_rows_fit(void)
{
    int64_t live = imdbw_live_blocks();
    smp s;
    samples(&s);
    const imdbw_msg *cols = &s.m[s.kcols];
    __int128 lim = imdb_pow10_128(38);
    static const imdbw_value ok0 = {.type = IMDBW_T_INT64, .i = INT32_MAX};
    const struct {
        int col;
        imdbw_value v;
        bool ok;
    } cases[] = {
        {0, ok0, true},
        {0, {.type = IMDBW_T_INT64, .i = (int64_t)INT32_MAX + 1}, false}, /* INTEGER's width */
        {0, {.type = IMDBW_T_INT64, .i = (int64_t)INT32_MIN - 1}, false},
        {0, {.type = IMDBW_T_TIMESTAMP, .i = 1}, false},                  /* another type */
        {0, {.null = true, .type = IMDBW_T_INT64}, true},          /* a NULL of its column's type */
        {0, {.null = true, .type = IMDBW_T_TEXT}, false},          /* a NULL of another type */
        {0, {.null = true}, false},                                 /* a NULL of none in a typed column */
        {1, {.type = IMDBW_T_DECIMAL, .scale = 6, .d = lim - 1}, true},
        {1, {.type = IMDBW_T_DECIMAL, .scale = 5, .d = 1}, false},        /* another scale */
        {1, {.type = IMDBW_T_INT64, .i = 1}, false},
        {2, {.type = IMDBW_T_TEXT, .s = (const uint8_t *)"\xc3\xa9\xc3\xa9\xc3\xa9\xc3\xa9\xc3\xa9\xc3\xa9\xc3\xa9\xc3\xa9\xc3\xa9\xc3\xa9\xc3\xa9\xc3\xa9", .len = 24}, true}, /* 12 characters */
        {2, {.type = IMDBW_T_TEXT, .s = (const uint8_t *)"0123456789abc", .len = 13}, false}, /* VARCHAR(12) */
        {2, {.type = IMDBW_T_BYTEA, .s = (const uint8_t *)"a", .len = 1}, false},
        {3, {.type = IMDBW_T_ENUM, .s = (const uint8_t *)"\xc3\xa9", .len = 2}, true},
        {3, {.type = IMDBW_T_ENUM, .s = (const uint8_t *)"y", .len = 1}, false},        /* not a label */
        {3, {.type = IMDBW_T_ENUM, .s = (const uint8_t *)"xx", .len = 2}, false},
        {3, {.type = IMDBW_T_TEXT, .s = (const uint8_t *)"x", .len = 1}, false},        /* a label as TEXT */
    };
    for (size_t k = 0; k < sizeof cases / sizeof *cases; k++) {
        CHECK(imdbw_value_fits(&cols->cols[cases[k].col], &cases[k].v) == cases[k].ok);
        /* in a frame: a row of NULLs but the case's column */
        imdbw_value row[4] = {{.null = true, .type = IMDBW_T_INT64}, {.null = true, .type = IMDBW_T_DECIMAL},
                              {.null = true, .type = IMDBW_T_TEXT}, {.null = true, .type = IMDBW_T_ENUM}};
        row[cases[k].col] = cases[k].v;
        imdbw_buf vb, fb, hb;
        imdbw_buf_init(&fb);
        imdbw_buf_init(&hb);
        imdbw_msg m = {.type = IMDBW_ROWS, .vals = span_of(&vb, row, 4), .nsets = 1, .nvals = 4};
        imdbw_msg_put(&fb, &m, cols); /* the encoder, which holds the row to its columns */
        size_t at = imdbw_frame_begin(&hb, IMDBW_ROWS); /* the same frame by hand, unchecked: for the decoder */
        imdbw_put_u32(&hb, 1);
        imdbw_put(&hb, vb.p, vb.len);
        imdbw_frame_end(&hb, at);
        bool same;
        int rc = reencode(hb.p, hb.len, cols, &same);
        bool agree = !vb.err && !hb.err && fb.err == !cases[k].ok && (rc == 0) == cases[k].ok &&
                     (!cases[k].ok || (same && fb.len == hb.len && !memcmp(fb.p, hb.p, hb.len)));
        imdbw_buf_free(&vb);
        imdbw_buf_free(&fb);
        imdbw_buf_free(&hb);
        if (!agree) fprintf(stderr, "    case %zu\n", k);
        CHECK(agree);
    }
    /* a SMALLINT's width, a DECIMAL(5,2)'s digits, a label not distinct, an ENUM column unindexed */
    imdbw_col sc = {.name = "s", .type = IMDBW_T_INT64, .precision = 16};
    imdbw_value v16 = {.type = IMDBW_T_INT64, .i = INT16_MAX}, v17 = {.type = IMDBW_T_INT64, .i = INT16_MAX + 1};
    CHECK(imdbw_value_fits(&sc, &v16) && !imdbw_value_fits(&sc, &v17));
    imdbw_col d52 = {.name = "d", .type = IMDBW_T_DECIMAL, .precision = 5, .scale = 2};
    imdbw_value d5 = {.type = IMDBW_T_DECIMAL, .scale = 2, .d = -99999}, d6 = {.type = IMDBW_T_DECIMAL, .scale = 2, .d = 100000};
    CHECK(imdbw_value_fits(&d52, &d5) && !imdbw_value_fits(&d52, &d6)); /* 999.99 fits, 1000.00 does not */
    /* a DECIMAL column of no known precision: 38 digits at its scale */
    imdbw_col d0 = {.name = "d", .type = IMDBW_T_DECIMAL, .precision = 0, .scale = 2};
    imdbw_value big = {.type = IMDBW_T_DECIMAL, .scale = 2, .d = imdb_pow10_128(38) - 1}, sc3 = {.type = IMDBW_T_DECIMAL, .scale = 3};
    CHECK(imdbw_value_fits(&d0, &big) && !imdbw_value_fits(&d0, &sc3));
    /* a column of no known type: any value, each its own type; a NULL of any type or of none */
    imdbw_col none = {.name = "x", .type = IMDBW_T_NONE};
    imdbw_value any[] = {{.type = IMDBW_T_INT64, .i = 1}, {.type = IMDBW_T_ENUM, .s = (const uint8_t *)"q", .len = 1},
                         {.null = true}, {.null = true, .type = IMDBW_T_DATE}};
    for (size_t k = 0; k < 4; k++) CHECK(imdbw_value_fits(&none, &any[k]));
    imdbw_value badv = {.type = IMDBW_T_BOOL, .i = 2};
    CHECK(!imdbw_value_fits(&none, &badv));
    imdbw_text dup[] = {{(const uint8_t *)"a", 1}, {(const uint8_t *)"b", 1}, {(const uint8_t *)"a", 1}};
    imdbw_col ec = {.name = "e", .type = IMDBW_T_ENUM, .labels = dup, .nlabels = 3};
    imdbw_msg em = {.type = IMDBW_COLUMNS, .cols = &ec, .ncols = 1};
    CHECK(imdbw_cols_index(&em) == -1);
    imdbw_cols_unindex(&em);
    imdbw_buf b;
    imdbw_buf_init(&b);
    ec.nlabels = 2;
    imdbw_msg_put(&b, &em, cols); /* an ENUM column not indexed: its labels unchecked, refused */
    CHECK(b.err);
    imdbw_buf_reset(&b);
    CHECK(imdbw_cols_index(&em) == 0);
    imdbw_msg_put(&b, &em, cols);
    CHECK(!b.err);
    /* the same COLUMNS with the label twice, made by hand: the decoder refuses it */
    uint8_t x[64];
    size_t n = unhex("0100 0165 0d 0000 0000 0200 0161 0161", x, sizeof x);
    imdbw_msg d;
    imdb_err_clear(&we);
    CHECK(imdbw_msg_get(IMDBW_COLUMNS, x, n, NULL, &d, &we) == IMDB_ERR_CORRUPT && strstr(we.msg, "distinct"));
    imdbw_cols_unindex(&em);
    imdbw_buf_free(&b);
    samples_free(&s);
    CHECK(imdbw_live_blocks() == live);
}

/* every byte of every sample flipped three ways, every cut and one byte more: what a decoder takes encodes back to
 * itself; a cut or a longer body is refused but for COPY's raw pieces */
static void t_wire_flips(void)
{
    int64_t live = imdbw_live_blocks();
    smp s;
    samples(&s);
    const imdbw_msg *cols = &s.m[s.kcols];
    for (size_t k = 0; k < s.n; k++) {
        imdbw_buf b;
        imdbw_buf_init(&b);
        imdbw_msg_put(&b, &s.m[k], cols);
        CHECK(!b.err);
        bool raw = s.m[k].type == IMDBW_COPY_DATA || s.m[k].type == IMDBW_COPY_OUT;
        uint8_t *x = malloc(b.len + 1);
        CHECK(x);
        bool fine = true;
        for (size_t i = IMDBW_HEAD; i < b.len && fine; i++)
            for (int f = 0; f < 3 && fine; f++) {
                memcpy(x, b.p, b.len);
                x[i] ^= (uint8_t)(f == 0 ? 0x01 : f == 1 ? 0x80 : 0xff);
                bool same;
                if (reencode(x, b.len, cols, &same) == 0 && !same) fine = false;
            }
        for (size_t cut = IMDBW_HEAD; cut < b.len && fine; cut++) { /* the head's length made to agree with the cut */
            memcpy(x, b.p, cut);
            imdb_le32(x, (uint32_t)(cut - 4));
            bool same;
            int rc = reencode(x, cut, cols, &same);
            if (raw ? rc == 0 && !same && cut > IMDBW_HEAD : rc == 0) fine = false;
        }
        memcpy(x, b.p, b.len);
        x[b.len] = 0;
        imdb_le32(x, (uint32_t)(b.len + 1 - 4));
        bool same;
        int rc = reencode(x, b.len + 1, cols, &same);
        if (raw ? rc != 0 || !same : rc == 0) fine = false;
        free(x);
        imdbw_buf_free(&b);
        if (!fine) fprintf(stderr, "    sample %zu (type %u)\n", k, s.m[k].type);
        CHECK(fine);
    }
    samples_free(&s);
    CHECK(imdbw_live_blocks() == live);
}

static int body(uint8_t type, const char *hex, const imdbw_msg *cols)
{
    uint8_t x[512];
    size_t n = unhex(hex, x, sizeof x);
    imdbw_msg m;
    imdb_err_clear(&we);
    int rc = imdbw_msg_get(type, x, n, cols, &m, &we);
    if (!rc) imdbw_msg_free(&m);
    return rc;
}

static void t_wire_bounds(void)
{
    int64_t live = imdbw_live_blocks();
    uint32_t len;
    uint8_t type;
    uint8_t h[5] = {0, 0, 0, 0, IMDBW_QUERY};
    CHECK(imdbw_head_get(h, false, &len, &type, &we) == IMDB_ERR_LIMIT); /* length 0 */
    imdb_le32(h, IMDBW_FRAME_MAX + 1);
    CHECK(imdbw_head_get(h, false, &len, &type, &we) == IMDB_ERR_LIMIT);
    imdb_le32(h, IMDBW_FRAME_MAX);
    CHECK(imdbw_head_get(h, false, &len, &type, &we) == 0 && len == IMDBW_FRAME_MAX);
    CHECK(imdbw_head_get(h, true, &len, &type, &we) != 0); /* a client's type from the server */
    static const uint8_t bad_client[] = {0, 11, 63, 64, 72, 255}, bad_server[] = {0, 1, 10, 63, 73, 255};
    for (size_t i = 0; i < sizeof bad_client; i++) {
        h[4] = bad_client[i];
        CHECK(imdbw_head_get(h, false, &len, &type, &we) != 0);
        h[4] = bad_server[i];
        CHECK(imdbw_head_get(h, true, &len, &type, &we) != 0);
    }
    CHECK(body(IMDBW_QUERY, "00000000", NULL) != 0);                            /* no statement */
    CHECK(body(IMDBW_QUERY, "01100000 01000000 61 0000", NULL) != 0);           /* 4,097 */
    CHECK(body(IMDBW_QUERY, "ffffffff 01000000 61 0000", NULL) != 0);           /* more than the bytes hold */
    CHECK(body(IMDBW_QUERY, "01000000 00000000 0000", NULL) != 0);              /* an empty statement */
    CHECK(body(IMDBW_QUERY, "01000000 01004000 61 0000", NULL) == IMDB_ERR_LIMIT); /* 4 MiB + 1 claimed */
    CHECK(body(IMDBW_QUERY, "01000000 01000000 61 0000", NULL) == 0);
    CHECK(body(IMDBW_QUERY, "01000000 01000000 61 0100 81", NULL) == 0);        /* a statement with a NULL INT64 */
    CHECK(body(IMDBW_QUERY, "01000000 01000000 61 0100 00", NULL) != 0);        /* type 0 is no value */
    CHECK(body(IMDBW_QUERY, "01000000 01000000 61 0100 0d0161", NULL) != 0);    /* an ENUM parameter: a label goes as TEXT */
    CHECK(body(IMDBW_QUERY, "01000000 01000000 61 0100 8d", NULL) == 0);        /* a NULL ENUM: the one ENUM parameter */
    CHECK(body(IMDBW_QUERY, "01000000 01000000 61 0101 00", NULL) != 0);        /* 257 values */
    CHECK(body(IMDBW_QUERY, "01000000 01000000 61 0000 00", NULL) != 0);        /* a byte past the end */
    CHECK(body(IMDBW_QUERY, "01000000 01000000 61", NULL) != 0);                /* no count of values */
    /* every text strict UTF-8 without NUL (a round trip cannot see it: the bytes would come back the same) */
    CHECK(body(IMDBW_QUERY, "01000000 01000000 ff 0000", NULL) != 0);
    CHECK(body(IMDBW_QUERY, "01000000 02000000 6100 0000", NULL) != 0);
    CHECK(body(IMDBW_DEALLOCATE, "01 c3", NULL) != 0);
    CHECK(body(IMDBW_COLUMNS, "0100 01ff 03 0000 0000", NULL) != 0);              /* a column's name */
    CHECK(body(IMDBW_COLUMNS, "0100 0161 0d 0000 0000 0100 01 80", NULL) != 0);   /* a label */
    CHECK(body(IMDBW_DONE, "0100 ff 0000000000000000 00 00", NULL) != 0);        /* the status */
    CHECK(body(IMDBW_ERROR, "05000000 00000000 0100 00", NULL) != 0);             /* the message */
    CHECK(body(IMDBW_WARNING, "0200 c0af", NULL) != 0);
    CHECK(body(IMDBW_COPY_DATA, "ff00", NULL) == 0);                              /* COPY's bytes are raw */
    CHECK(body(IMDBW_EXECUTE, "0170 01000000 0101", NULL) != 0);                  /* 257 values */
    CHECK(body(IMDBW_EXECUTE, "0170 00000000 0000", NULL) != 0);                  /* no set */
    CHECK(body(IMDBW_EXECUTE, "0170 01000000 0100 80", NULL) == 0);               /* one NULL of no type */
    CHECK(body(IMDBW_EXECUTE, "0170 01000000 0100 0d0161", NULL) != 0);           /* an ENUM parameter */
    CHECK(body(IMDBW_EXECUTE, "00 01000000 0000", NULL) != 0);                    /* an empty name */
    CHECK(body(IMDBW_PREPARE, "0170 01000000 61", NULL) == 0);
    CHECK(body(IMDBW_PREPARE, "0170 01000000 61 00", NULL) != 0);                 /* declared types: none in version 1 */
    CHECK(body(IMDBW_DEALLOCATE, "40 6161616161616161616161616161616161616161616161616161616161616161"
                                 "6161616161616161616161616161616161616161616161616161616161616161", NULL) != 0); /* 64 */
    CHECK(body(IMDBW_ROWS, "01000000 00", NULL) != 0);                            /* no COLUMNS before */
    CHECK(body(IMDBW_COLUMNS, "0000", NULL) != 0);                                /* no column */
    CHECK(body(IMDBW_COLUMNS, "0100 0161 05 2700 0000", NULL) != 0);              /* DECIMAL(39) */
    CHECK(body(IMDBW_COLUMNS, "0100 0161 05 0200 0300", NULL) != 0);              /* scale past precision */
    CHECK(body(IMDBW_COLUMNS, "0100 0161 05 2600 2600", NULL) == 0);              /* DECIMAL(38,38) */
    CHECK(body(IMDBW_COLUMNS, "0100 0161 01 0800 0000", NULL) != 0);              /* INT64 of 8 bits */
    CHECK(body(IMDBW_COLUMNS, "0100 0161 01 1000 0000", NULL) == 0);              /* SMALLINT */
    CHECK(body(IMDBW_COLUMNS, "0100 0161 03 0100 0000", NULL) != 0);              /* BOOL with a precision */
    CHECK(body(IMDBW_COLUMNS, "0100 0161 00 0000 0000", NULL) == 0);              /* a column of no known type */
    CHECK(body(IMDBW_COLUMNS, "0100 0161 00 0100 0000", NULL) != 0);              /* ... with a precision */
    CHECK(body(IMDBW_COLUMNS, "0100 0161 05 0000 2600", NULL) == 0);              /* DECIMAL, precision not known, scale 38 */
    CHECK(body(IMDBW_COLUMNS, "0100 0161 05 0000 2700", NULL) != 0);              /* ... scale 39 */
    CHECK(body(IMDBW_COLUMNS, "0100 0161 0e 0000 0000", NULL) != 0);              /* type 14 */
    CHECK(body(IMDBW_COLUMNS, "0100 0161 0d 0000 0000 ffff", NULL) != 0);         /* labels past the bytes */
    CHECK(body(IMDBW_COLUMNS, "0100 0161 0d 0000 0000 0104", NULL) != 0);         /* 1,025 labels */
    CHECK(body(IMDBW_COLUMNS, "0100 0161 0d 0000 0000 0100 00", NULL) == 0);      /* one empty label */
    CHECK(body(IMDBW_COLUMNS, "0100 0161 0d 0000 0000 0100 40", NULL) == IMDB_ERR_LIMIT); /* a label of 64 bytes */
    CHECK(body(IMDBW_COLUMNS, "0100 0161 0d 0100 0000 0100 00", NULL) != 0);      /* an ENUM with a precision */
    CHECK(body(IMDBW_DONE, "0000 0000000000000000 02 00", NULL) != 0);            /* a read flag of 2 */
    CHECK(body(IMDBW_DONE, "0000 0000000000000000 00 00", NULL) == 0);
    CHECK(body(IMDBW_DONE, "0000 ffffffffffffffff 00 00", NULL) == 0);            /* any count */
    CHECK(body(IMDBW_DONE, "0000 00 00", NULL) != 0);                             /* no count */
    static const char *const zero32 = "0000000000000000000000000000000000000000000000000000000000000000";
    char done[600];
    static const char *const zero16 = "00000000000000000000000000000000";
    snprintf(done, sizeof done, "0000 0000000000000000 01 0000000000000000 %s %s 0100000000000000 01%.62s %s 00 00", zero32, zero32, zero32, zero16);
    CHECK(body(IMDBW_DONE, done, NULL) == 0); /* whatever the read point: the engine's (an AS OF below the lake) */
    snprintf(done, sizeof done, "0000 0000000000000000 01 0000000000000000 %s %s 0100000000000000 %s %s 01 00", zero32, zero32, zero32, zero16);
    CHECK(body(IMDBW_DONE, done, NULL) == 0); /* its own writes seen */
    snprintf(done, sizeof done, "0000 0000000000000000 01 0000000000000000 %s %s 0100000000000000 %s %s 02 00", zero32, zero32, zero32, zero16);
    CHECK(body(IMDBW_DONE, done, NULL) != 0); /* an own-writes flag of 2 */
    snprintf(done, sizeof done, "0000 0000000000000000 00 01 0000000000000000 %s", zero32);
    CHECK(body(IMDBW_DONE, done, NULL) != 0); /* a write at commit 0 */
    snprintf(done, sizeof done, "0002 %0*d 00 00", 1024, 0);
    CHECK(body(IMDBW_DONE, done, NULL) == IMDB_ERR_LIMIT); /* a status of 512 bytes */
    CHECK(body(IMDBW_ERROR, "05000000 00100000 0000", NULL) != 0);                /* index 4,096 */
    CHECK(body(IMDBW_ERROR, "00000000 00000000 0000", NULL) != 0);                /* code 0 */
    CHECK(body(IMDBW_ERROR, "05000000 ff0f0000 0000", NULL) == 0);
    CHECK(body(IMDBW_READY, "03", NULL) != 0);
    CHECK(body(IMDBW_READY, "", NULL) != 0);
    CHECK(body(IMDBW_PING, "00", NULL) != 0);                                     /* a body where none is */
    CHECK(body(IMDBW_COPY_DATA, "", NULL) != 0);                                  /* an empty piece */
    CHECK(body(IMDBW_COPY_FAIL, "0110", NULL) == IMDB_ERR_LIMIT);                 /* 4,097 bytes claimed */
    /* an ENUM of 1,024 distinct labels taken, of 1,025 refused (each three letters: only the count can refuse it) */
    for (uint32_t nl = 1024; nl <= 1025; nl++) {
        imdbw_buf cb;
        imdbw_buf_init(&cb);
        static const uint8_t head[] = {1, 0, 1, 'e', IMDBW_T_ENUM, 0, 0, 0, 0};
        imdbw_put(&cb, head, sizeof head);
        imdbw_put_u16(&cb, (uint16_t)nl);
        static uint8_t lab[1025][3];
        static imdbw_text lt[1025];
        for (uint32_t i = 0; i < nl; i++) {
            lab[i][0] = (uint8_t)('a' + i / 676), lab[i][1] = (uint8_t)('a' + i / 26 % 26), lab[i][2] = (uint8_t)('a' + i % 26);
            imdbw_put_u8(&cb, 3);
            imdbw_put(&cb, lab[i], 3);
            lt[i] = (imdbw_text){lab[i], 3};
        }
        imdbw_msg m;
        imdb_err_clear(&we);
        int rc = imdbw_msg_get(IMDBW_COLUMNS, cb.p, cb.len, NULL, &m, &we);
        if (!rc) imdbw_msg_free(&m);
        imdbw_buf_free(&cb);
        CHECK((rc == 0) == (nl == 1024));
        imdbw_col ec = {.name = "e", .type = IMDBW_T_ENUM, .labels = lt, .nlabels = nl};
        imdbw_msg em = {.type = IMDBW_COLUMNS, .cols = &ec, .ncols = 1};
        int ix = imdbw_cols_index(&em);
        imdbw_buf_init(&cb);
        imdbw_msg_put(&cb, &em, NULL);
        bool err = cb.err;
        imdbw_buf_free(&cb);
        imdbw_cols_unindex(&em);
        CHECK((ix == 0) == (nl == 1024) && err == (nl == 1025));
    }
    /* a count past its bytes is refused before it sizes anything */
    static const struct {
        uint8_t type;
        const char *hex;
    } counts[] = {
        {IMDBW_QUERY, "00100000 01000000 61 0000"},          /* 4,096 statements in 7 bytes */
        {IMDBW_COLUMNS, "0001 0161 01 0000 0000"},           /* 256 columns in 8 bytes */
        {IMDBW_COLUMNS, "0100 0161 0d 0000 0000 0004"},      /* 1,024 labels in none */
    };
    for (size_t k = 0; k < sizeof counts / sizeof *counts; k++) {
        imdbw_alloc_peak_reset();
        CHECK(body(counts[k].type, counts[k].hex, NULL) != 0);
        CHECK(imdbw_alloc_peak() < 256);
    }
    CHECK(imdbw_live_blocks() == live);
}

/* what a decoder takes costs its bytes: values are never copied into arrays (4,096 sets of 256 values, a megabyte, and
 * a ROWS of a million NULLs ask nothing), and the arrays a frame does make are a small multiple of its bytes */
static void t_wire_amplification(void)
{
    int64_t live = imdbw_live_blocks();
    size_t nb = 2 + 2 + 4 + 2 + (size_t)IMDBW_BATCH_MAX * IMDBW_VALUES_MAX;
    uint8_t *x = calloc(nb, 1);
    CHECK(x);
    x[0] = 2, x[1] = 'p', x[2] = '1'; /* the name "p1" */
    imdb_le32(x + 3, IMDBW_BATCH_MAX);     /* sets */
    x[7] = 0, x[8] = 1;                    /* 256 values a set: NULLs of no type after */
    memset(x + 9, IMDBW_NULL_TAG, (size_t)IMDBW_BATCH_MAX * IMDBW_VALUES_MAX);
    imdbw_msg m;
    imdbw_alloc_peak_reset();
    imdb_err_clear(&we);
    int rc = imdbw_msg_get(IMDBW_EXECUTE, x, 9 + (size_t)IMDBW_BATCH_MAX * IMDBW_VALUES_MAX, NULL, &m, &we);
    size_t peak = imdbw_alloc_peak();
    if (!rc) imdbw_msg_free(&m);
    free(x);
    CHECK(rc == 0 && peak == 0);
    /* ROWS of a million NULLs in four columns */
    smp s;
    samples(&s);
    size_t rows = 1u << 18;
    uint8_t *y = calloc(4 + rows * 4, 1);
    CHECK(y);
    imdb_le32(y, (uint32_t)rows);
    for (size_t i = 0; i < rows; i++) { /* each column's NULL: INT64, DECIMAL, TEXT, ENUM */
        y[4 + i * 4] = IMDBW_NULL_TAG | IMDBW_T_INT64, y[5 + i * 4] = IMDBW_NULL_TAG | IMDBW_T_DECIMAL;
        y[6 + i * 4] = IMDBW_NULL_TAG | IMDBW_T_TEXT, y[7 + i * 4] = IMDBW_NULL_TAG | IMDBW_T_ENUM;
    }
    imdbw_alloc_peak_reset();
    rc = imdbw_msg_get(IMDBW_ROWS, y, 4 + rows * 4, &s.m[s.kcols], &m, &we);
    peak = imdbw_alloc_peak();
    if (!rc) imdbw_msg_free(&m);
    free(y);
    CHECK(rc == 0 && peak == 0);
    /* QUERY: 4,096 empty-valued statements of one byte, 28 KiB: its arrays within 8 times its bytes */
    size_t qn = 4 + (size_t)IMDBW_BATCH_MAX * 7;
    uint8_t *q = calloc(qn, 1);
    CHECK(q);
    imdb_le32(q, IMDBW_BATCH_MAX);
    for (size_t i = 0; i < IMDBW_BATCH_MAX; i++) {
        imdb_le32(q + 4 + i * 7, 1);
        q[4 + i * 7 + 4] = 'a';
    }
    imdbw_alloc_peak_reset();
    rc = imdbw_msg_get(IMDBW_QUERY, q, qn, NULL, &m, &we);
    peak = imdbw_alloc_peak();
    if (!rc) imdbw_msg_free(&m);
    free(q);
    CHECK(rc == 0 && peak <= 8 * qn);
    samples_free(&s);
    CHECK(imdbw_live_blocks() == live);
}

/* every allocation of every sample's decode and encode failed in turn: NOMEM or a sticky error, nothing left */
static void t_wire_alloc_failures(void)
{
    int64_t live = imdbw_live_blocks();
    smp s;
    samples(&s);
    const imdbw_msg *cols = &s.m[s.kcols];
    int failures = 0;
    for (size_t k = 0; k < s.n; k++) {
        imdbw_buf b;
        imdbw_buf_init(&b);
        imdbw_msg_put(&b, &s.m[k], cols);
        CHECK(!b.err);
        for (int64_t at = 1;; at++) { /* the decode */
            imdbw_msg m;
            imdb_err_clear(&we);
            imdbw_alloc_fail_at(at);
            int rc = imdbw_msg_get(s.m[k].type, b.p + IMDBW_HEAD, b.len - IMDBW_HEAD, cols, &m, &we);
            imdbw_alloc_fail_at(0);
            if (rc == 0) {
                imdbw_msg_free(&m);
                break;
            }
            CHECK(rc == IMDB_ERR_NOMEM);
            failures++;
        }
        for (int64_t at = 1;; at++) { /* the encode */
            imdbw_buf c;
            imdbw_buf_init(&c);
            imdbw_alloc_fail_at(at);
            imdbw_msg_put(&c, &s.m[k], cols);
            imdbw_alloc_fail_at(0);
            bool err = c.err;
            bool same = !err && c.len == b.len && !memcmp(c.p, b.p, b.len);
            imdbw_buf_free(&c);
            if (!err) {
                CHECK(same);
                break;
            }
            failures++;
        }
        imdbw_buf_free(&b);
    }
    CHECK(failures > 20);
    samples_free(&s);
    CHECK(imdbw_live_blocks() == live);
}

/* the encoder refuses each field its decoder would: b->err, never a frame the other side refuses */
static void t_wire_encoder_refuses(void)
{
    int64_t live = imdbw_live_blocks();
    smp s;
    samples(&s);
    const imdbw_msg *cols = &s.m[s.kcols];
    imdbw_text bad_utf8 = {(const uint8_t *)"\xff", 1}, empty = {(const uint8_t *)"", 0};
    imdbw_text long_status = {(const uint8_t *)"", 512};
    static char big[600];
    memset(big, 'a', sizeof big);
    long_status.p = (const uint8_t *)big;
    imdbw_span three = s.params[0];
    imdbw_buf eb;
    imdbw_value ev = {.type = IMDBW_T_ENUM, .s = (const uint8_t *)"x", .len = 1};
    imdbw_span enum_param = span_of(&eb, &ev, 1); /* an ENUM among a statement's values */
    three.n = 3; /* a count other than its values' */
    imdbw_msg no[32];
    size_t n = 0;
    no[n++] = (imdbw_msg){.type = IMDBW_QUERY, .texts = s.texts, .params = s.params, .ntexts = 0};
    no[n++] = (imdbw_msg){.type = IMDBW_QUERY, .texts = &bad_utf8, .params = s.params + 1, .ntexts = 1};
    no[n++] = (imdbw_msg){.type = IMDBW_QUERY, .texts = &empty, .params = s.params + 1, .ntexts = 1};
    no[n++] = (imdbw_msg){.type = IMDBW_QUERY, .texts = s.texts, .params = &three, .ntexts = 1};
    no[n++] = (imdbw_msg){.type = IMDBW_QUERY, .texts = s.texts, .params = &enum_param, .ntexts = 1};
    no[n++] = (imdbw_msg){.type = IMDBW_PREPARE, .texts = s.texts, .ntexts = 1}; /* no name */
    no[n] = (imdbw_msg){.type = IMDBW_EXECUTE, .nsets = 0};
    strcpy(no[n++].name, "p");
    no[n] = (imdbw_msg){.type = IMDBW_EXECUTE, .vals = s.m[0].vals, .nsets = 2, .nvals = 3}; /* 6 values said, 8 given */
    strcpy(no[n++].name, "p");
    no[n] = (imdbw_msg){.type = IMDBW_DEALLOCATE};
    no[n++].name[0] = (char)0xc3;
    no[n++] = (imdbw_msg){.type = IMDBW_COPY_DATA, .data = (const uint8_t *)"", .dlen = 0};
    no[n++] = (imdbw_msg){.type = IMDBW_COPY_FAIL, .texts = &bad_utf8, .ntexts = 1};
    no[n++] = (imdbw_msg){.type = IMDBW_COLUMNS, .cols = s.cols, .ncols = 0};
    imdbw_col badcol = s.cols[1];
    badcol.scale = 39;
    no[n++] = (imdbw_msg){.type = IMDBW_COLUMNS, .cols = &badcol, .ncols = 1};
    no[n++] = (imdbw_msg){.type = IMDBW_ROWS, .vals = s.m[s.krows].vals, .nsets = 0, .nvals = 4};
    no[n++] = (imdbw_msg){.type = IMDBW_ROWS, .vals = s.m[s.krows].vals, .nsets = 2, .nvals = 3};
    no[n++] = (imdbw_msg){.type = IMDBW_ROWS, .vals = s.m[s.krows].vals, .nsets = 4, .nvals = 2}; /* 8 values, 2 a row */
    no[n++] = (imdbw_msg){.type = IMDBW_DONE, .status = long_status};
    no[n++] = (imdbw_msg){.type = IMDBW_DONE, .status = bad_utf8};
    no[n++] = (imdbw_msg){.type = IMDBW_DONE, .has_write = true, .write_commit = 0};
    no[n++] = (imdbw_msg){.type = IMDBW_ERROR, .code = 5, .index = IMDBW_BATCH_MAX, .texts = s.texts + 1, .ntexts = 1};
    no[n++] = (imdbw_msg){.type = IMDBW_ERROR, .code = 0, .texts = s.texts + 1, .ntexts = 1};
    no[n++] = (imdbw_msg){.type = IMDBW_ERROR, .code = 5, .texts = &bad_utf8, .ntexts = 1};
    no[n++] = (imdbw_msg){.type = IMDBW_WARNING, .ntexts = 0};
    no[n++] = (imdbw_msg){.type = IMDBW_READY, .state = 3};
    no[n++] = (imdbw_msg){.type = 11};
    for (size_t k = 0; k < n; k++) {
        imdbw_buf b;
        imdbw_buf_init(&b);
        imdbw_msg_put(&b, &no[k], cols);
        bool err = b.err;
        imdbw_buf_free(&b);
        if (!err) fprintf(stderr, "    message %zu (type %u) encoded\n", k, no[k].type);
        CHECK(err);
    }
    /* a frame past 16 MiB: refused whole */
    imdbw_buf b;
    imdbw_buf_init(&b);
    size_t at = imdbw_frame_begin(&b, IMDBW_COPY_OUT);
    for (int i = 0; i < 17 && !b.err; i++) {
        static uint8_t mb[1 << 20];
        imdbw_put(&b, mb, sizeof mb);
    }
    imdbw_frame_end(&b, at);
    CHECK(b.err);
    imdbw_buf_free(&b);
    imdbw_buf_free(&eb);
    samples_free(&s);
    CHECK(imdbw_live_blocks() == live);
}


/* the server's ROWS path: a value at a time, each checked once against its column; the same bytes as the encoder's for the
 * same rows, each refusal, and the two paths' rates measured (printed, not held: the advisor's question) */
static void t_wire_rows_writer(void)
{
    int64_t live = imdbw_live_blocks();
    smp s;
    samples(&s);
    const imdbw_msg *cols = &s.m[s.kcols], *rows = &s.m[s.krows];
    imdbw_buf a, b;
    imdbw_buf_init(&a);
    imdbw_buf_init(&b);
    imdbw_msg_put(&a, rows, cols);
    imdbw_rows w;
    imdbw_rows_begin(&w, &b, cols);
    imdb_rd r;
    imdbw_value v;
    imdbw_span_begin(&rows->vals, &r);
    while (imdbw_span_next(&r, &v)) imdbw_rows_value(&w, &v);
    imdbw_rows_end(&w);
    bool same = !a.err && !b.err && a.len == b.len && !memcmp(a.p, b.p, a.len) && w.n == 2 && !r.err;
    imdbw_buf_free(&a);
    imdbw_buf_reset(&b);
    CHECK(same);
    /* a value its column does not take; a row left part way; no row; no columns */
    imdbw_value bad = {.type = IMDBW_T_TEXT, .s = (const uint8_t *)"x", .len = 1}, ok0 = {.type = IMDBW_T_INT64, .i = 1};
    imdbw_rows_begin(&w, &b, cols);
    imdbw_rows_value(&w, &bad);
    CHECK(b.err);
    imdbw_buf_reset(&b);
    imdbw_rows_begin(&w, &b, cols);
    imdbw_rows_value(&w, &ok0);
    imdbw_rows_end(&w);
    CHECK(b.err);
    imdbw_buf_reset(&b);
    imdbw_rows_begin(&w, &b, cols); /* a whole row, then one value of the next */
    for (int i = 0; i < 4; i++) {
        imdbw_value nv = {.null = true, .type = cols->cols[i].type};
        imdbw_rows_value(&w, &nv);
    }
    imdbw_rows_value(&w, &ok0);
    imdbw_rows_end(&w);
    CHECK(w.n == 1 && b.err);
    imdbw_buf_reset(&b);
    imdbw_rows_begin(&w, &b, cols);
    imdbw_rows_end(&w);
    CHECK(b.err);
    imdbw_buf_reset(&b);
    imdbw_rows_begin(&w, &b, NULL);
    CHECK(b.err);
    imdbw_buf_reset(&b);
    /* frames cut at a target, at a row's end: 10,000 rows in frames of 4 KiB and one row more at most, each a frame the
     * decoder takes against its columns, their rows the rows written */
    {
        imdbw_value fv[8];
        imdbw_span_begin(&rows->vals, &r);
        for (int i = 0; i < 8; i++) CHECK(imdbw_span_next(&r, &fv[i]));
        uint64_t total = 0, frames = 0;
        bool fine = true;
        imdbw_buf_reset(&b);
        imdbw_rows_begin(&w, &b, cols);
        CHECK(imdbw_rows_len(&w) == IMDBW_HEAD + 4 && imdbw_rows_whole(&w)); /* the head and the count so far */
        for (int k = 0; k < 10000 && fine; k++) {
            for (int i = 0; i < 4; i++) {
                imdbw_rows_value(&w, &fv[(k % 2) * 4 + i]);
                if (i < 3 && imdbw_rows_whole(&w)) fine = false; /* a row part way is not whole */
            }
            bool last = k == 9999;
            if (!last && imdbw_rows_whole(&w) && imdbw_rows_len(&w) < 4096 && imdbw_rows_len(&w) != b.len) fine = false;
            if (imdbw_rows_whole(&w) && (imdbw_rows_len(&w) >= 4096 || last)) {
                imdbw_rows_end(&w);
                imdbw_msg d;
                fine = !b.err && b.len <= 4096 + 64 &&
                       imdbw_msg_get(IMDBW_ROWS, b.p + IMDBW_HEAD, b.len - IMDBW_HEAD, cols, &d, &we) == 0;
                if (fine) {
                    total += d.nsets;
                    imdbw_msg_free(&d);
                }
                frames++;
                imdbw_buf_reset(&b);
                if (!last) imdbw_rows_begin(&w, &b, cols);
            }
        }
        CHECK(fine && total == 10000 && frames > 50 && frames < 200); /* about 40 bytes a row: some 95 frames */
        imdbw_buf_reset(&b);
    }
    /* the rates: 100,000 rows of the sample's two, a frame of 25,000 at a time, by the writer and by the encoder (the
     * encoder walks its span a second time) */
    imdbw_value rv[8];
    imdbw_span_begin(&rows->vals, &r);
    for (int i = 0; i < 8; i++) CHECK(imdbw_span_next(&r, &rv[i]));
    uint64_t t0 = imdb_mono_ns();
    for (int f = 0; f < 4; f++) {
        imdbw_buf_reset(&b);
        imdbw_rows_begin(&w, &b, cols);
        for (int k = 0; k < 12500; k++)
            for (int i = 0; i < 8; i++) imdbw_rows_value(&w, &rv[i]);
        imdbw_rows_end(&w);
        CHECK(!b.err && w.n == 25000);
    }
    uint64_t t1 = imdb_mono_ns();
    imdbw_buf vals;
    imdbw_buf_init(&vals);
    for (int k = 0; k < 12500; k++)
        for (int i = 0; i < 8; i++) imdbw_value_put(&vals, &rv[i]);
    CHECK(!vals.err);
    imdbw_msg m = {.type = IMDBW_ROWS, .vals = {vals.p, vals.len, 100000}, .nsets = 25000, .nvals = 4};
    uint64_t t2 = imdb_mono_ns();
    for (int f = 0; f < 4; f++) {
        imdbw_buf_reset(&a);
        imdbw_msg_put(&a, &m, cols);
        CHECK(!a.err);
    }
    uint64_t t3 = imdb_mono_ns();
    fprintf(stderr, "    ROWS of 4 columns: the writer %.1f M rows/s, the encoder over a span %.1f M rows/s\n",
            1e5 / ((double)(t1 - t0) / 1e9) / 1e6, 1e5 / ((double)(t3 - t2) / 1e9) / 1e6);
    imdbw_buf_free(&vals);
    imdbw_buf_free(&a);
    imdbw_buf_free(&b);
    samples_free(&s);
    CHECK(imdbw_live_blocks() == live);
}
/* drawn bodies of every type and drawn damage to the samples: anything taken encodes back to itself */
static void t_wire_random(void)
{
    int64_t live = imdbw_live_blocks();
    smp s;
    samples(&s);
    const imdbw_msg *cols = &s.m[s.kcols];
    uint8_t x[400];
    static const uint8_t types[] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 64, 65, 66, 67, 68, 69, 70, 71, 72};
    long taken = 0;
    for (int round = 0; round < 60000; round++) {
        uint8_t t = types[test_rand() % sizeof types];
        size_t n = IMDBW_HEAD + test_rand() % 64;
        test_rand_bytes(x, n);
        if (test_rand() % 2) { /* small counts and lengths, so that some bodies are taken */
            for (size_t i = IMDBW_HEAD; i < n; i++)
                if (test_rand() % 3 == 0) x[i] = (uint8_t)(test_rand() % 4);
        }
        imdb_le32(x, (uint32_t)(n - 4));
        x[4] = t;
        bool same;
        if (reencode(x, n, cols, &same) == 0) {
            taken++;
            CHECK(same);
        }
    }
    for (int round = 0; round < 20000; round++) {
        size_t k = test_rand() % s.n;
        imdbw_buf b;
        imdbw_buf_init(&b);
        imdbw_msg_put(&b, &s.m[k], cols);
        CHECK(!b.err && b.len <= sizeof x);
        memcpy(x, b.p, b.len);
        size_t n = b.len;
        imdbw_buf_free(&b);
        int hits = 1 + (int)(test_rand() % 4);
        for (int i = 0; i < hits && n > IMDBW_HEAD; i++) x[IMDBW_HEAD + test_rand() % (n - IMDBW_HEAD)] = (uint8_t)test_rand();
        bool same;
        if (reencode(x, n, cols, &same) == 0) {
            taken++;
            CHECK(same);
        }
    }
    CHECK(taken > 1000);
    samples_free(&s);
    CHECK(imdbw_live_blocks() == live);
}

const test_case wire_tests[] = {
    {"wire_value_vectors", t_wire_value_vectors},
    {"wire_value_refused", t_wire_value_refused},
    {"wire_utf8_fit", t_wire_utf8_fit},
    {"wire_preauth", t_wire_preauth},
    {"wire_scram", t_wire_scram},
    {"wire_fake_salt", t_wire_fake_salt},
    {"wire_messages", t_wire_messages},
    {"wire_rows_fit", t_wire_rows_fit},
    {"wire_flips", t_wire_flips},
    {"wire_bounds", t_wire_bounds},
    {"wire_amplification", t_wire_amplification},
    {"wire_alloc_failures", t_wire_alloc_failures},
    {"wire_encoder_refuses", t_wire_encoder_refuses},
    {"wire_rows_writer", t_wire_rows_writer},
    {"wire_random", t_wire_random},
};
const size_t wire_ntests = sizeof wire_tests / sizeof *wire_tests;
