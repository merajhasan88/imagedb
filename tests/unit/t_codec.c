/* Codec tests: UTF-8 (exhaustive vs an independent decoder), literals, rows,
 * schemas, SipHash vectors, terminal-safe formatting, hash map. */
#include <float.h>
#include <locale.h>
#include <math.h>
#include <openssl/bn.h>
#include <stdlib.h>

#include "../../src/codec.h"
#include "../../src/cpu.h"
#include "../../src/fsum.h"
#include "../../src/hashmap.h"
#include "../../tools/audit/afsum.h"
#include "test.h"

uint64_t imdb_siphash24(const uint8_t *in, size_t n, uint64_t k0, uint64_t k1);

/* Independent reference: decode code points, then apply the rules. */
static bool ref_utf8(const uint8_t *s, size_t n, size_t *bad)
{
    size_t i = 0;
    while (i < n) {
        uint8_t c = s[i];
        uint32_t cp;
        size_t len;
        if (c < 0x80) cp = c, len = 1;
        else if ((c & 0xE0) == 0xC0) cp = c & 0x1F, len = 2;
        else if ((c & 0xF0) == 0xE0) cp = c & 0x0F, len = 3;
        else if ((c & 0xF8) == 0xF0) cp = c & 0x07, len = 4;
        else goto fail;
        if (len > n - i) goto fail;
        for (size_t k = 1; k < len; k++) {
            if ((s[i + k] & 0xC0) != 0x80) goto fail;
            cp = cp << 6 | (s[i + k] & 0x3F);
        }
        static const uint32_t minv[5] = {0, 0, 0x80, 0x800, 0x10000};
        if (cp == 0 || cp < minv[len] || cp > 0x10FFFF || (cp >= 0xD800 && cp <= 0xDFFF)) goto fail;
        i += len;
    }
    return true;
fail:
    *bad = i;
    return false;
}

/* exact-size heap copy so ASan catches any read past the end */
static bool check_one(const uint8_t *s, size_t n)
{
    uint8_t *h = malloc(n ? n : 1);
    memcpy(h, s, n);
    size_t b1 = 0, b2 = 0;
    bool a = imdb_utf8_valid(h, n, &b1), r = ref_utf8(h, n, &b2);
    free(h);
    if (a != r || (!a && b1 != b2)) {
        fprintf(stderr, "    utf8 mismatch len=%zu bytes=%02x %02x %02x %02x valid=%d/%d bad=%zu/%zu\n", n,
                n > 0 ? s[0] : 0, n > 1 ? s[1] : 0, n > 2 ? s[2] : 0, n > 3 ? s[3] : 0, a, r, b1, b2);
        return false;
    }
    return true;
}

static void t_utf8_exhaustive_short(void)
{
    uint8_t b[4];
    for (int x = 0; x < 256; x++) {
        b[0] = (uint8_t)x;
        CHECK(check_one(b, 1));
    }
    for (int x = 0; x < 65536; x++) {
        b[0] = (uint8_t)(x >> 8);
        b[1] = (uint8_t)x;
        CHECK(check_one(b, 2));
    }
    /* all 3-byte sequences whose lead byte is E0..EF (the interesting range) */
    for (int x = 0xE0; x <= 0xEF; x++)
        for (int y = 0; y < 256; y++)
            for (int z = 0; z < 256; z++) {
                b[0] = (uint8_t)x;
                b[1] = (uint8_t)y;
                b[2] = (uint8_t)z;
                CHECK(check_one(b, 3));
            }
}

static void t_utf8_boundaries(void)
{
    struct {
        const char *s;
        size_t n;
        bool ok;
    } cases[] = {
        {"a\0b", 3, false},                 /* embedded NUL */
        {"\xC2\x80", 2, true},              /* U+0080 */
        {"\xC1\xBF", 2, false},             /* overlong */
        {"\xE0\x9F\xBF", 3, false},         /* overlong 3-byte */
        {"\xE0\xA0\x80", 3, true},          /* U+0800 */
        {"\xED\x9F\xBF", 3, true},          /* U+D7FF */
        {"\xED\xA0\x80", 3, false},         /* U+D800 surrogate */
        {"\xEF\xBF\xBF", 3, true},          /* U+FFFF */
        {"\xF0\x8F\xBF\xBF", 4, false},     /* overlong 4-byte */
        {"\xF0\x90\x80\x80", 4, true},      /* U+10000 */
        {"\xF4\x8F\xBF\xBF", 4, true},      /* U+10FFFF */
        {"\xF4\x90\x80\x80", 4, false},     /* > U+10FFFF */
        {"\xF5\x80\x80\x80", 4, false},
        {"\x80", 1, false},                 /* stray continuation */
        {"caf\xC3\xA9", 5, true},
    };
    for (size_t i = 0; i < sizeof cases / sizeof *cases; i++) {
        size_t bad;
        CHECK(imdb_utf8_valid((const uint8_t *)cases[i].s, cases[i].n, &bad) == cases[i].ok);
        CHECK(check_one((const uint8_t *)cases[i].s, cases[i].n));
    }
    /* every truncation of valid multi-byte sequences fails without over-reading */
    const char *valid[] = {"\xC3\xA9", "\xE2\x82\xAC", "\xF0\x9F\x98\x80"};
    for (int v = 0; v < 3; v++) {
        size_t n = strlen(valid[v]);
        for (size_t cut = 1; cut < n; cut++) {
            uint8_t tmp[8] = {'x', 'y'};
            memcpy(tmp + 2, valid[v], cut);
            size_t bad = 99;
            CHECK(!imdb_utf8_valid(tmp, 2 + cut, &bad) && bad == 2);
            CHECK(check_one(tmp, 2 + cut));
        }
    }
    /* random 4-byte-heavy strings */
    for (int it = 0; it < 200000; it++) {
        uint8_t b[12];
        size_t n = 1 + test_rand() % sizeof b;
        for (size_t k = 0; k < n; k++) {
            uint64_t r = test_rand();
            b[k] = (r & 3) == 0 ? (uint8_t)(0xF0 | (r >> 8 & 7)) : (r & 3) == 1 ? (uint8_t)(0x80 | (r >> 8 & 0x3F)) : (uint8_t)(r >> 16);
        }
        CHECK(check_one(b, n));
    }
}

static void t_ident(void)
{
    char out[IMDB_MAX_IDENT + 1];
    CHECK(imdb_ident_fold("User_ID", 7, out) && strcmp(out, "user_id") == 0);
    CHECK(!imdb_ident_valid("1abc", 4));
    CHECK(!imdb_ident_valid("a-b", 3));
    CHECK(!imdb_ident_valid("a\nb", 3)); /* newline in a name (CVE-2025-8715 class) */
    CHECK(!imdb_ident_valid("a\"b", 3));
    CHECK(!imdb_ident_valid("", 0));
    char longname[70];
    memset(longname, 'a', sizeof longname);
    CHECK(imdb_ident_valid(longname, 63) && !imdb_ident_valid(longname, 64));
}

static void t_int64_literals(void)
{
    imdb_err e = {0};
    int64_t v;
    CHECK(imdb_parse_int64("9223372036854775807", 19, &v, &e) == 0 && v == INT64_MAX);
    CHECK(imdb_parse_int64("-9223372036854775808", 20, &v, &e) == 0 && v == INT64_MIN);
    imdb_err_clear(&e);
    CHECK(imdb_parse_int64("9223372036854775808", 19, &v, &e) == IMDB_ERR_LIMIT);
    imdb_err_clear(&e);
    CHECK(imdb_parse_int64("-9223372036854775809", 20, &v, &e) == IMDB_ERR_LIMIT);
    imdb_err_clear(&e);
    CHECK(imdb_parse_int64("99999999999999999999999", 23, &v, &e) == IMDB_ERR_LIMIT);
    imdb_err_clear(&e);
    CHECK(imdb_parse_int64("12a", 3, &v, &e) == IMDB_ERR_INVALID);
    imdb_err_clear(&e);
    CHECK(imdb_parse_int64("-", 1, &v, &e) == IMDB_ERR_INVALID);
}

static void fmt(int64_t v, int scale, char *out, size_t n)
{
    imdb_buf b;
    imdb_buf_init(&b);
    imdb_format_decimal(v, scale, &b);
    snprintf(out, n, "%.*s", (int)b.len, (const char *)b.p);
    imdb_buf_free(&b);
}

static void t_decimal(void)
{
    imdb_err e = {0};
    int64_t v;
    char s[64];
    CHECK(imdb_parse_decimal("19.99", 5, 12, 2, &v, &e) == 0 && v == 1999);
    CHECK(imdb_parse_decimal("-0.05", 5, 12, 2, &v, &e) == 0 && v == -5);
    CHECK(imdb_parse_decimal("7", 1, 12, 2, &v, &e) == 0 && v == 700);
    CHECK(imdb_parse_decimal("1.500", 5, 12, 2, &v, &e) == 0 && v == 150); /* exact trailing zeros ok */
    CHECK(imdb_parse_decimal("-0.00", 5, 12, 2, &v, &e) == 0 && v == 0);
    CHECK(imdb_parse_decimal("000123.4", 8, 5, 1, &v, &e) == 0 && v == 1234);
    imdb_err_clear(&e);
    CHECK(imdb_parse_decimal("1.505", 5, 12, 2, &v, &e) == IMDB_ERR_INVALID); /* no silent rounding */
    imdb_err_clear(&e);
    CHECK(imdb_parse_decimal("1234", 4, 5, 2, &v, &e) == IMDB_ERR_LIMIT);     /* exceeds DECIMAL(5,2) */
    imdb_err_clear(&e);
    CHECK(imdb_parse_decimal("999.99", 6, 5, 2, &v, &e) == 0 && v == 99999);
    CHECK(imdb_parse_decimal(".5", 2, 5, 2, &v, &e) == IMDB_ERR_INVALID);
    imdb_err_clear(&e);
    CHECK(imdb_parse_decimal("5.", 2, 5, 2, &v, &e) == IMDB_ERR_INVALID);
    imdb_err_clear(&e);
    CHECK(imdb_parse_decimal("1e5", 3, 18, 0, &v, &e) == IMDB_ERR_INVALID);
    imdb_err_clear(&e);
    CHECK(imdb_parse_decimal("999999999999999999", 18, 18, 0, &v, &e) == 0 && v == 999999999999999999LL);
    fmt(1999, 2, s, sizeof s);
    CHECK(strcmp(s, "19.99") == 0);
    fmt(-5, 2, s, sizeof s);
    CHECK(strcmp(s, "-0.05") == 0);
    fmt(7, 0, s, sizeof s);
    CHECK(strcmp(s, "7") == 0);
    fmt(INT64_MIN, 4, s, sizeof s);
    CHECK(strcmp(s, "-922337203685477.5808") == 0);
    /* round trip */
    for (int it = 0; it < 20000; it++) {
        int scale = (int)(test_rand() % 7);
        int64_t x = (int64_t)(test_rand() % 2000000000000ull) - 1000000000000ll;
        fmt(x, scale, s, sizeof s);
        int64_t y;
        imdb_err_clear(&e);
        CHECK(imdb_parse_decimal(s, strlen(s), 18, scale, &y, &e) == 0 && y == x);
    }
    imdb_buf b;
    imdb_buf_init(&b);
    imdb_format_i128((__int128)INT64_MAX * 1000, 2, &b);
    CHECK(b.len == 23 && memcmp(b.p, "92233720368547758070.00", 23) == 0);
    imdb_buf_free(&b);
}

static void t_timestamp(void)
{
    imdb_err e = {0};
    int64_t v;
    CHECK(imdb_parse_timestamp("1970-01-01", 10, &v, &e) == 0 && v == 0);
    CHECK(imdb_parse_timestamp("1970-01-01 00:00:01", 19, &v, &e) == 0 && v == 1000000);
    CHECK(imdb_parse_timestamp("2000-02-29T12:00:00Z", 20, &v, &e) == 0);
    CHECK(imdb_parse_timestamp("1969-12-31 23:59:59.5", 21, &v, &e) == 0 && v == -500000);
    CHECK(imdb_parse_timestamp("2024-06-30 08:15:00.123456", 26, &v, &e) == 0 && v % 1000000 == 123456);
    const char *bad[] = {"1900-02-29", "2023-02-29", "2024-13-01", "2024-00-10", "2024-01-32", "2024-01-01 24:00:00",
                         "2024-01-01 10:00:00+02:00", "2024-01-01 10:00:00.1234567", "2024-1-01", "0000-01-01",
                         "2024-01-01 10:00", "2024-01-01x"};
    for (size_t i = 0; i < sizeof bad / sizeof *bad; i++) {
        imdb_err_clear(&e);
        CHECK(imdb_parse_timestamp(bad[i], strlen(bad[i]), &v, &e) != 0);
    }
    for (int it = 0; it < 20000; it++) {
        int64_t x = (int64_t)(test_rand() % 400000000000000000ull) - 62000000000000000ll;
        if (x > 253402300799999999LL) x = 253402300799999999LL;
        imdb_buf b;
        imdb_buf_init(&b);
        imdb_format_timestamp(x, &b);
        int64_t y;
        imdb_err_clear(&e);
        CHECK(imdb_parse_timestamp((const char *)b.p, b.len, &y, &e) == 0 && y == x);
        imdb_buf_free(&b);
    }
}

static void schema3(imdb_schema *s)
{
    memset(s, 0, sizeof *s);
    strcpy(s->name, "t");
    s->ncols = 5;
    strcpy(s->cols[0].name, "k");
    s->cols[0].type = IMDB_T_TEXT;
    s->cols[0].flags = IMDB_COL_PK;
    strcpy(s->cols[1].name, "n");
    s->cols[1].type = IMDB_T_INT64;
    strcpy(s->cols[2].name, "d");
    s->cols[2].type = IMDB_T_DECIMAL;
    s->cols[2].precision = 4;
    s->cols[2].scale = 1;
    strcpy(s->cols[3].name, "b");
    s->cols[3].type = IMDB_T_BOOL;
    strcpy(s->cols[4].name, "ts");
    s->cols[4].type = IMDB_T_TIMESTAMP;
    s->pk = 0;
    s->subject = -1;
}

static void t_rows(void)
{
    imdb_schema s;
    schema3(&s);
    imdb_err e = {0};
    CHECK(imdb_schema_check(&s, &e) == 0);
    imdb_value v[5] = {{.type = IMDB_T_TEXT, .s = (const uint8_t *)"k\xC3\xA9y", .len = 4},
                       {.type = IMDB_T_INT64, .i = -7},
                       {.type = IMDB_T_DECIMAL, .scale = 1, .i = 999},
                       {.type = IMDB_T_BOOL, .i = 1},
                       {.type = IMDB_T_TIMESTAMP, .i = 1700000000000000}};
    imdb_buf b;
    imdb_buf_init(&b);
    CHECK(imdb_row_encode(&s, v, &b, &e) == 0 && b.len == 4 + 4 + 8 + 8 + 1 + 8);
    imdb_value out[5];
    CHECK(imdb_row_decode(&s, b.p, b.len, out, &e) == 0);
    for (int i = 0; i < 5; i++) CHECK(imdb_value_cmp(&v[i], &out[i]) == 0);
    /* strictness */
    imdb_err_clear(&e);
    CHECK(imdb_row_decode(&s, b.p, b.len - 1, out, &e) == IMDB_ERR_CORRUPT);
    uint8_t *x = malloc(b.len + 1);
    memcpy(x, b.p, b.len);
    x[b.len] = 0;
    imdb_err_clear(&e);
    CHECK(imdb_row_decode(&s, x, b.len + 1, out, &e) == IMDB_ERR_CORRUPT); /* trailing */
    memcpy(x, b.p, b.len);
    x[4 + 4 + 8 + 8] = 2; /* BOOL must be 0/1 */
    imdb_err_clear(&e);
    CHECK(imdb_row_decode(&s, x, b.len, out, &e) == IMDB_ERR_CORRUPT);
    memcpy(x, b.p, b.len);
    x[5] = 0xFF; /* invalid UTF-8 inside TEXT from disk is rejected on decode */
    imdb_err_clear(&e);
    CHECK(imdb_row_decode(&s, x, b.len, out, &e) == IMDB_ERR_CORRUPT);
    memcpy(x, b.p, b.len);
    imdb_le32(x, 0xFFFFFFF0u); /* TEXT length beyond the buffer */
    imdb_err_clear(&e);
    CHECK(imdb_row_decode(&s, x, b.len, out, &e) == IMDB_ERR_CORRUPT);
    memcpy(x, b.p, b.len);
    imdb_le64(x + 4 + 4 + 8, 10000); /* exceeds DECIMAL(4,1) */
    imdb_err_clear(&e);
    CHECK(imdb_row_decode(&s, x, b.len, out, &e) == IMDB_ERR_CORRUPT);
    free(x);
    /* tag mismatch is rejected, never reinterpreted (type confusion) */
    v[1].type = IMDB_T_TEXT;
    imdb_err_clear(&e);
    b.len = 0;
    CHECK(imdb_row_encode(&s, v, &b, &e) == IMDB_ERR_INVALID);
    imdb_buf_free(&b);
}

static void t_schema_codec(void)
{
    imdb_schema s, d;
    schema3(&s);
    s.id = 3;
    imdb_buf b;
    imdb_buf_init(&b);
    imdb_schema_encode(&s, &b);
    imdb_rd r;
    imdb_rd_init(&r, b.p, b.len);
    imdb_err e = {0};
    CHECK(imdb_schema_decode(&r, &d, &e) == 0 && imdb_rd_left(&r) == 0);
    CHECK(d.id == 3 && d.ncols == 5 && d.pk == 0 && d.subject == -1 && strcmp(d.cols[2].name, "d") == 0);
    /* every truncation is rejected */
    for (size_t cut = 0; cut < b.len; cut++) {
        imdb_rd_init(&r, b.p, cut);
        imdb_err_clear(&e);
        CHECK(imdb_schema_decode(&r, &d, &e) != 0);
    }
    /* uppercase identifier on disk is rejected (one canonical spelling) */
    b.p[5] = 'T';
    imdb_rd_init(&r, b.p, b.len);
    imdb_err_clear(&e);
    CHECK(imdb_schema_decode(&r, &d, &e) != 0);
    imdb_buf_free(&b);
    /* semantic checks */
    schema3(&s);
    s.cols[1].flags = IMDB_COL_PK;
    imdb_err_clear(&e);
    CHECK(imdb_schema_check(&s, &e) != 0); /* two PKs */
    schema3(&s);
    strcpy(s.cols[1].name, "k");
    imdb_err_clear(&e);
    CHECK(imdb_schema_check(&s, &e) != 0); /* duplicate column */
    schema3(&s);
    s.cols[2].precision = 19;
    imdb_err_clear(&e);
    CHECK(imdb_schema_check(&s, &e) != 0);
    schema3(&s);
    strcpy(s.cols[1].name, "_vid");
    imdb_err_clear(&e);
    CHECK(imdb_schema_check(&s, &e) != 0); /* reserved prefix */
}

static void t_siphash_vectors(void)
{
    /* SipHash-2-4 reference vectors (Aumasson & Bernstein, key 00..0f) */
    uint8_t k[16], m[64];
    for (int i = 0; i < 16; i++) k[i] = (uint8_t)i;
    for (int i = 0; i < 64; i++) m[i] = (uint8_t)i;
    uint64_t k0 = imdb_get_le64(k), k1 = imdb_get_le64(k + 8);
    CHECK(imdb_siphash24(m, 0, k0, k1) == 0x726fdb47dd0e0e31ull);
    CHECK(imdb_siphash24(m, 15, k0, k1) == 0xa129ca6149be45e5ull);
}

static void safe(const char *in, size_t n, char *out, size_t on)
{
    imdb_value v = {.type = IMDB_T_TEXT, .s = (const uint8_t *)in, .len = (uint32_t)n};
    imdb_buf b;
    imdb_buf_init(&b);
    imdb_format_value_safe(&v, &b);
    snprintf(out, on, "%.*s", (int)b.len, (const char *)b.p);
    imdb_buf_free(&b);
}

static void t_safe_format(void)
{
    char o[128];
    safe("a\x1b[31mb", 7, o, sizeof o);
    CHECK(strcmp(o, "a\\x1b[31mb") == 0);
    safe("x\xE2\x80\xAEy", 5, o, sizeof o); /* RIGHT-TO-LEFT OVERRIDE */
    CHECK(strcmp(o, "x\\u202ey") == 0);
    safe("\xE2\x81\xA6z", 4, o, sizeof o); /* LEFT-TO-RIGHT ISOLATE */
    CHECK(strcmp(o, "\\u2066z") == 0);
    safe("\xC2\x9B", 2, o, sizeof o); /* C1 CSI */
    CHECK(strcmp(o, "\\u009b") == 0);
    safe("caf\xC3\xA9 \\", 7, o, sizeof o);
    CHECK(strcmp(o, "caf\xC3\xA9 \\\\") == 0);
}

static void t_hashmap(void)
{
    imdb_err e = {0};
    imdb_hmap m;
    CHECK(imdb_hmap_init(&m, IMDB_T_INT64, &e) == 0);
    enum { N = 5000 };
    static uint64_t model[N];
    static bool present[N];
    memset(present, 0, sizeof present);
    for (int it = 0; it < 60000; it++) {
        int k = (int)(test_rand() % N);
        imdb_value key = {.type = IMDB_T_INT64, .i = k * 7919LL};
        int op = (int)(test_rand() % 3);
        if (op == 0) {
            uint64_t val = test_rand();
            CHECK(imdb_hmap_put(&m, &key, val, &e) == 0);
            model[k] = val;
            present[k] = true;
        } else if (op == 1) {
            CHECK(imdb_hmap_del(&m, &key) == present[k]);
            present[k] = false;
        } else {
            uint64_t *v = imdb_hmap_get(&m, &key);
            CHECK((v != NULL) == present[k]);
            if (v) CHECK(*v == model[k]);
        }
    }
    size_t cnt = 0;
    for (int k = 0; k < N; k++) cnt += present[k];
    CHECK(cnt == m.count);
    imdb_hmap_free(&m);
    /* TEXT keys including empty and binary-ish UTF-8 */
    CHECK(imdb_hmap_init(&m, IMDB_T_TEXT, &e) == 0);
    char keys[200][16];
    for (int i = 0; i < 200; i++) snprintf(keys[i], sizeof keys[i], "k%d\xC3\xA9", i);
    for (int i = 0; i < 200; i++) {
        imdb_value key = {.type = IMDB_T_TEXT, .s = (const uint8_t *)keys[i], .len = (uint32_t)strlen(keys[i])};
        CHECK(imdb_hmap_put(&m, &key, (uint64_t)i, &e) == 0);
    }
    imdb_value empty = {.type = IMDB_T_TEXT, .s = (const uint8_t *)"", .len = 0};
    CHECK(imdb_hmap_put(&m, &empty, 999, &e) == 0);
    for (int i = 0; i < 200; i += 2) {
        imdb_value key = {.type = IMDB_T_TEXT, .s = (const uint8_t *)keys[i], .len = (uint32_t)strlen(keys[i])};
        CHECK(imdb_hmap_del(&m, &key));
    }
    for (int i = 0; i < 200; i++) {
        imdb_value key = {.type = IMDB_T_TEXT, .s = (const uint8_t *)keys[i], .len = (uint32_t)strlen(keys[i])};
        uint64_t *v = imdb_hmap_get(&m, &key);
        CHECK((v != NULL) == (i % 2 == 1));
        if (v) CHECK(*v == (uint64_t)i);
    }
    CHECK(imdb_hmap_get(&m, &empty) && *imdb_hmap_get(&m, &empty) == 999);
    imdb_hmap_free(&m);
}

/* ---- FLOAT64 and NULL (E1) ---------------------------------------------------- */

static double rand_double(void)
{
    for (;;) { /* any finite double, subnormals and both zeros included */
        uint64_t b = test_rand();
        if (test_rand() % 4 == 0) b &= 0x800fffffffffffffull | (test_rand() % 3 == 0 ? 0 : 0x7f00000000000000ull);
        double d;
        memcpy(&d, &b, 8);
        if (isfinite(d)) return d;
    }
}

static void t_float64_keys(void)
{
    CHECK(imdb_f64_key(-0.0) == 0 && imdb_f64_key(0.0) == 0);
    CHECK(!imdb_f64_key_valid(-1));                          /* the key -0.0 would have */
    CHECK(!imdb_f64_key_valid(imdb_f64_key(INFINITY)) && !imdb_f64_key_valid(imdb_f64_key(-INFINITY)));
    CHECK(!imdb_f64_key_valid(imdb_f64_key(NAN)) && !imdb_f64_key_valid(INT64_MAX) && !imdb_f64_key_valid(INT64_MIN));
    const double edge[] = {-DBL_MAX, -1.0, -DBL_MIN, -4.9406564584124654e-324, 0.0,
                           4.9406564584124654e-324, DBL_MIN, 1.0, DBL_MAX};
    for (size_t i = 0; i + 1 < sizeof edge / sizeof *edge; i++)
        CHECK(imdb_f64_key(edge[i]) < imdb_f64_key(edge[i + 1]) && imdb_f64_key_valid(imdb_f64_key(edge[i])));
    for (int i = 0; i < 200000 && !g_test_failed; i++) {
        double a = rand_double(), b = rand_double();
        int64_t ka = imdb_f64_key(a), kb = imdb_f64_key(b);
        CHECK(imdb_f64_key_valid(ka));
        CHECK((a < b) == (ka < kb) && (a == b) == (ka == kb));
        double back = imdb_f64_value(ka);
        CHECK(back == a && !signbit(back) == !(signbit(a) && a != 0));
    }
}

static int pf(const char *s, int64_t *k)
{
    imdb_err e = {0};
    return imdb_parse_float64(s, strlen(s), k, &e);
}

static void t_float64_literals(void)
{
    int64_t k;
    static const char *const ok[] = {"0", "1", "-1", "+2.5e+10", "1.5", "1e3", "1E-3", "0.1", "1e308",
                                     "4.9406564584124654e-324", "1e-320", "0e-400", "-0", "123456789012345678901234567890"};
    for (size_t i = 0; i < sizeof ok / sizeof *ok; i++) {
        CHECK(pf(ok[i], &k) == IMDB_OK && imdb_f64_key_valid(k));
        CHECK(imdb_f64_value(k) == strtod(ok[i], NULL));
    }
    CHECK(pf("-0", &k) == IMDB_OK && k == 0); /* normalised: one encoding */
    CHECK(pf("0.1", &k) == IMDB_OK && imdb_f64_value(k) == 0x1.999999999999ap-4);
    CHECK(pf("9007199254740993", &k) == IMDB_OK && imdb_f64_value(k) == 9007199254740992.0); /* tie: even */
    CHECK(pf("9007199254740995", &k) == IMDB_OK && imdb_f64_value(k) == 9007199254740996.0);
    CHECK(pf("1e309", &k) == IMDB_ERR_LIMIT && pf("-1e309", &k) == IMDB_ERR_LIMIT);
    CHECK(pf("1e-400", &k) == IMDB_ERR_LIMIT && pf("2.4703282292062327e-324", &k) == IMDB_ERR_LIMIT);
    CHECK(pf("2.4703282292062328e-324", &k) == IMDB_OK && imdb_f64_value(k) == 0x1p-1074);
    static const char *const bad[] = {"", "-", "+", ".5", "5.", "1e", "1e+", "0x10", "inf", "nan", "infinity",
                                      " 1", "1 ", "1,5", "1.2.3", "1e5.5", "--1", "1e-", "e5", "1_0"};
    for (size_t i = 0; i < sizeof bad / sizeof *bad; i++) CHECK(pf(bad[i], &k) == IMDB_ERR_INVALID);
    char big[IMDB_MAX_NUMERIC + 2];
    memset(big, '1', sizeof big - 1);
    big[sizeof big - 1] = '\0';
    CHECK(pf(big, &k) == IMDB_ERR_LIMIT);
    /* formatting reads back exactly, and is short where it can be */
    imdb_buf b;
    imdb_buf_init(&b);
    struct { double d; const char *s; } fmt[] = {{0.1, "0.1"}, {1e300, "1e+300"}, {-2.5, "-2.5"}, {0.0, "0"},
                                                {1.0 / 3, "0.3333333333333333"}, {0x1p-1074, "4.94065645841247e-324"}};
    for (size_t i = 0; i < sizeof fmt / sizeof *fmt; i++) {
        b.len = 0;
        imdb_format_float64(imdb_f64_key(fmt[i].d), &b);
        imdb_buf_put_u8(&b, 0);
        CHECK(strcmp((const char *)b.p, fmt[i].s) == 0);
    }
    for (int i = 0; i < 100000 && !g_test_failed; i++) {
        int64_t key = imdb_f64_key(rand_double()), back;
        b.len = 0;
        imdb_format_float64(key, &b);
        imdb_err e = {0};
        CHECK(b.len <= 24 && imdb_parse_float64((const char *)b.p, b.len, &back, &e) == IMDB_OK && back == key);
    }
    /* a host locale with a decimal comma changes neither direction */
    if (setlocale(LC_NUMERIC, "en_DK.utf8")) {
        CHECK(pf("1.5", &k) == IMDB_OK && imdb_f64_value(k) == 1.5 && pf("1,5", &k) == IMDB_ERR_INVALID);
        b.len = 0;
        imdb_format_float64(imdb_f64_key(1.5), &b);
        CHECK(b.len == 3 && memcmp(b.p, "1.5", 3) == 0);
        setlocale(LC_NUMERIC, "C");
    } else {
        fprintf(stderr, "    (en_DK.utf8 not installed: the decimal-comma locale check was skipped)\n");
    }
    imdb_buf_free(&b);
}

/* id PK, then ten NULLABLE columns (a two-byte bitmap with six padding bits) and a NOT NULL one */
static void schema_null(imdb_schema *s)
{
    memset(s, 0, sizeof *s);
    strcpy(s->name, "n");
    s->subject = -1;
    s->ncols = 12;
    static const uint8_t ty[12] = {IMDB_T_INT64, IMDB_T_INT64, IMDB_T_TEXT, IMDB_T_FLOAT64, IMDB_T_BOOL,
                                   IMDB_T_DECIMAL, IMDB_T_TIMESTAMP, IMDB_T_INT64, IMDB_T_TEXT, IMDB_T_FLOAT64,
                                   IMDB_T_INT64, IMDB_T_FLOAT64};
    for (int i = 0; i < 12; i++) {
        snprintf(s->cols[i].name, sizeof s->cols[i].name, "c%d", i);
        s->cols[i].type = ty[i];
        s->cols[i].flags = i == 0 ? IMDB_COL_PK : i == 11 ? 0 : IMDB_COL_NULLABLE;
        if (ty[i] == IMDB_T_DECIMAL) s->cols[i].precision = 10, s->cols[i].scale = 2;
    }
}

static void t_null_rows(void)
{
    imdb_schema s;
    schema_null(&s);
    imdb_err e = {0};
    CHECK(imdb_schema_check(&s, &e) == 0);
    imdb_value v[12];
    imdb_buf b;
    imdb_buf_init(&b);
    for (int round = 0; round < 2000 && !g_test_failed; round++) {
        memset(v, 0, sizeof v);
        size_t want = 2;
        for (int i = 0; i < 12; i++) {
            v[i].type = s.cols[i].type;
            v[i].scale = s.cols[i].scale;
            if ((s.cols[i].flags & IMDB_COL_NULLABLE) && test_rand() % 2) {
                v[i].null = true;
                continue;
            }
            switch (v[i].type) {
            case IMDB_T_TEXT: v[i].s = (const uint8_t *)"abc", v[i].len = (uint32_t)(test_rand() % 4); break;
            case IMDB_T_FLOAT64: v[i].i = imdb_f64_key(rand_double()); break;
            case IMDB_T_BOOL: v[i].i = (int64_t)(test_rand() % 2); break;
            case IMDB_T_DECIMAL: v[i].i = (int64_t)(test_rand() % 1000) - 500; break;
            default: v[i].i = (int64_t)(test_rand() % 100000); break;
            }
            want += v[i].type == IMDB_T_TEXT ? 4 + v[i].len : v[i].type == IMDB_T_BOOL ? 1 : 8;
        }
        b.len = 0;
        CHECK(imdb_row_encode(&s, v, &b, &e) == 0 && b.len == want);
        imdb_value out[12];
        CHECK(imdb_row_decode(&s, b.p, b.len, out, &e) == 0);
        for (int i = 0; i < 12; i++) {
            imdb_value g;
            imdb_row_get(&s, b.p, b.len, i, &g);
            CHECK(out[i].null == v[i].null && imdb_value_cmp(&out[i], &v[i]) == 0 && imdb_value_cmp(&g, &v[i]) == 0);
        }
    }
    /* strictness */
    memset(v, 0, sizeof v);
    for (int i = 0; i < 12; i++) v[i].type = s.cols[i].type, v[i].scale = s.cols[i].scale, v[i].null = i && i < 11;
    b.len = 0;
    CHECK(imdb_row_encode(&s, v, &b, &e) == 0 && b.len == 2 + 8 + 8 && b.p[0] == 0xff && b.p[1] == 0x03);
    uint8_t x[64];
    memcpy(x, b.p, b.len);
    imdb_value out[12];
    for (int bit = 2; bit < 8; bit++) { /* padding bits */
        x[1] = (uint8_t)(0x03 | 1u << bit);
        imdb_err_clear(&e);
        CHECK(imdb_row_decode(&s, x, b.len, out, &e) == IMDB_ERR_CORRUPT);
    }
    memcpy(x, b.p, b.len);
    imdb_le64(x + 2 + 8, (uint64_t)-1); /* the key -0.0 would have */
    imdb_err_clear(&e);
    CHECK(imdb_row_decode(&s, x, b.len, out, &e) == IMDB_ERR_CORRUPT);
    imdb_le64(x + 2 + 8, (uint64_t)imdb_f64_key(NAN));
    imdb_err_clear(&e);
    CHECK(imdb_row_decode(&s, x, b.len, out, &e) == IMDB_ERR_CORRUPT);
    x[0] = 0xfe; /* c1 present: the row is now too short for its values */
    imdb_err_clear(&e);
    CHECK(imdb_row_decode(&s, b.p, 1, out, &e) == IMDB_ERR_CORRUPT && imdb_row_decode(&s, x, b.len, out, &e) == IMDB_ERR_CORRUPT);
    v[11].null = true; /* NOT NULL */
    imdb_err_clear(&e);
    CHECK(imdb_row_encode(&s, v, &b, &e) == IMDB_ERR_CONSTRAINT);
    v[11].null = false;
    v[3].type = IMDB_T_INT64; /* a NULL keeps its column's tag */
    imdb_err_clear(&e);
    CHECK(imdb_row_encode(&s, v, &b, &e) == IMDB_ERR_INVALID);
    imdb_buf_free(&b);
    /* schema rules */
    schema_null(&s);
    s.cols[0].flags |= IMDB_COL_NULLABLE;
    imdb_err_clear(&e);
    CHECK(imdb_schema_check(&s, &e) == IMDB_ERR_INVALID);
    schema_null(&s);
    s.cols[1].flags = IMDB_COL_SUBJECT | IMDB_COL_NULLABLE;
    s.subject = 1;
    imdb_err_clear(&e);
    CHECK(imdb_schema_check(&s, &e) == IMDB_ERR_INVALID);
    schema_null(&s);
    s.cols[0].type = IMDB_T_FLOAT64;
    imdb_err_clear(&e);
    CHECK(imdb_schema_check(&s, &e) == IMDB_ERR_INVALID);
    schema_null(&s);
    s.cols[2].flags = 0x08;
    imdb_err_clear(&e);
    CHECK(imdb_schema_check(&s, &e) == IMDB_ERR_INVALID);
    schema_null(&s);
    s.id = 9;
    imdb_buf_init(&b);
    imdb_schema_encode(&s, &b);
    imdb_rd r;
    imdb_rd_init(&r, b.p, b.len);
    imdb_schema d;
    CHECK(imdb_schema_decode(&r, &d, &e) == 0 && memcmp(&d, &s, sizeof d) == 0);
    imdb_buf_free(&b);
}

/* The exact sum, independently: OpenSSL BN adds each double as an integer number of
 * 2^-1074 units (decomposed with frexp, not bit fields), and glibc's correctly rounded
 * strtod rounds the exact decimal expansion. 1 and the key on success; 0 out of range. */
static int oracle_sum(const int64_t *keys, size_t n, int64_t *key)
{
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *acc = BN_new(), *t = BN_new(), *p5 = BN_new(), *five = BN_new();
    BN_zero(acc);
    for (size_t i = 0; i < n; i++) {
        double d = imdb_f64_value(keys[i]);
        if (d == 0) continue;
        int ex;
        double f = frexp(fabs(d), &ex); /* |d| = f * 2^ex, f in [0.5, 1) */
        uint64_t m = (uint64_t)ldexp(f, 53);
        int shift = ex - 53 + 1074;
        BN_set_word(t, m);
        if (shift >= 0) BN_lshift(t, t, shift);
        else BN_rshift(t, t, -shift); /* exact: those low bits are zero */
        if (d < 0) BN_sub(acc, acc, t);
        else BN_add(acc, acc, t);
    }
    bool neg = BN_is_negative(acc);
    BN_set_negative(acc, 0);
    BN_set_word(five, 5);
    BN_set_word(t, 1074);
    BN_exp(p5, five, t, ctx);
    BN_mul(acc, acc, p5, ctx); /* |sum| * 2^-1074 = acc * 10^-1074 */
    char *dec = BN_bn2dec(acc);
    size_t dl = strlen(dec);
    char *s = malloc(dl + 16);
    snprintf(s, dl + 16, "%s%se-1074", neg ? "-" : "", dec);
    double r = strtod(s, NULL);
    free(s);
    OPENSSL_free(dec);
    BN_free(acc);
    BN_free(t);
    BN_free(p5);
    BN_free(five);
    BN_CTX_free(ctx);
    if (!isfinite(r)) return 0;
    *key = imdb_f64_key(r);
    return 1;
}

static int fsum_of(const int64_t *keys, size_t n, int64_t *key)
{
    imdb_fsum s = {0};
    imdb_err e = {0};
    int rc = IMDB_OK;
    for (size_t i = 0; i < n && !rc; i++) rc = imdb_fsum_add(&s, keys[i], &e);
    if (!rc) rc = imdb_fsum_result(&s, key, &e);
    imdb_fsum_free(&s);
    return rc;
}

/* the auditor's method (tools/audit/afsum.c: long double partials), 0 and the key, 1 out of range */
static int afsum_of(const double *v, size_t n, int64_t *key)
{
    afsum a;
    afsum_init(&a);
    for (size_t i = 0; i < n; i++) afsum_add(&a, v[i]);
    double d;
    int rc = afsum_result(&a, &d);
    if (!rc) *key = imdb_f64_key(d);
    return rc;
}

/* three methods agree bit for bit, overflow included: the oracle, the engine, the auditor */
static void check_sum(const double *vals, size_t n)
{
    int64_t keys[64], want = 0, got = 0, ak = 0;
    for (size_t i = 0; i < n; i++) keys[i] = imdb_f64_key(vals[i]);
    int ok = oracle_sum(keys, n, &want), rc = fsum_of(keys, n, &got), ar = afsum_of(vals, n, &ak);
    CHECK(ok ? rc == IMDB_OK && got == want : rc == IMDB_ERR_LIMIT);
    CHECK(ok ? ar == 0 && ak == want : ar == 1);
}

static void t_fsum_exact(void)
{
    double ulp_max = 0x1p971; /* the spacing of doubles just below DBL_MAX */
    const double c1[] = {1e308, 1e308, -1e308, -1e308, 1.0}; /* naive: inf, then nan */
    const double c2[] = {1.0, 1e100, 1.0, -1e100};           /* naive: 0, exact: 2 */
    const double c3[] = {0x1p53, 1.0};                       /* a tie: rounds to even, 2^53 */
    const double c4[] = {0x1p53, 1.0, 0x1p-1074};            /* just above the tie: 2^53 + 2 */
    const double c5[] = {DBL_MAX, DBL_MAX};                  /* out of range */
    const double c6[] = {DBL_MAX, DBL_MAX, -DBL_MAX};        /* back in range: exact */
    const double c7[] = {DBL_MAX, ulp_max / 2};              /* a tie above DBL_MAX (odd): overflows */
    const double c8[] = {DBL_MAX, ulp_max / 2, -0x1p-1074};  /* just below it: DBL_MAX */
    const double c9[] = {0x1p-1074, 0x1p-1074, 0x1p-1074};   /* subnormal */
    const double c10[] = {1.5, -1.5};                        /* zero: +0.0 */
    const double c11[] = {0.1, 0.2, -0.3};                   /* naive: 5.55e-17 */
    const double c12[] = {1.0, 0x1p-53};                     /* a tie below 1 + 2^-52: even, 1.0 */
    const double c13[] = {1.0, 0x1p-53, 0x1p-1074};          /* the sticky bit: 1 + 2^-52 */
    const double c14[] = {1.0, 0x1p-53, -0x1p-1074};         /* and below the tie: 1.0 */
    const double c15[] = {0x1p-1022, 0x1p-1074};             /* exact across the subnormal edge */
    const double c16[] = {1e308, 1.0, -1e308};               /* naive: 0 */
    const double c17[] = {-DBL_MAX, -ulp_max / 2};           /* the tie below -DBL_MAX: overflows */
    const double c18[] = {-DBL_MAX, -ulp_max / 2, 0x1p-1074}; /* just inside it: -DBL_MAX */
    struct { const double *v; size_t n; } cs[] = {{c1, 5}, {c2, 4}, {c3, 2}, {c4, 3}, {c5, 2}, {c6, 3},
                                                  {c7, 2}, {c8, 3}, {c9, 3}, {c10, 2}, {c11, 3}, {c12, 2},
                                                  {c13, 3}, {c14, 3}, {c15, 2}, {c16, 3}, {c17, 2}, {c18, 3}};
    for (size_t i = 0; i < sizeof cs / sizeof *cs; i++) check_sum(cs[i].v, cs[i].n);
    int64_t k;
    double c2r[] = {1.0, 1e100, 1.0, -1e100};
    CHECK(fsum_of((int64_t[]){imdb_f64_key(c2r[0]), imdb_f64_key(c2r[1]), imdb_f64_key(c2r[2]), imdb_f64_key(c2r[3])}, 4,
                  &k) == IMDB_OK && imdb_f64_value(k) == 2.0);
    CHECK(fsum_of((int64_t[]){imdb_f64_key(1.5), imdb_f64_key(-1.5)}, 2, &k) == IMDB_OK && k == 0);
    /* ties at every magnitude: a and half its ulp is a tie (the even one wins); 2^-1074 either way
     * breaks it (the sticky bit a rounding of the top partial alone loses) */
    for (int round = 0; round < 400 && !g_test_failed; round++) {
        double a;
        do a = rand_double();
        while (!(fabs(a) >= 0x1p-1021 && fabs(a) <= 0x1p1020)); /* half an ulp representable, no overflow */
        int ex;
        frexp(a, &ex); /* |a| in [2^(ex-1), 2^ex): ulp 2^(ex-53) */
        double half = ldexp(1.0, ex - 54), t[3] = {a, a > 0 ? half : -half, 0x1p-1074};
        check_sum(t, 2);
        check_sum(t, 3);
        t[2] = -0x1p-1074;
        check_sum(t, 3);
    }
    /* up to 20 values, exponents uniform over the whole range, in three orders */
    for (int round = 0; round < 300 && !g_test_failed; round++) {
        double v[20], w[20];
        size_t n = 1 + test_rand() % 20;
        for (size_t i = 0; i < n; i++) {
            double m = (double)(test_rand() >> 11); /* below 2^53: exact */
            v[i] = ldexp(m, (int)(test_rand() % 2046) - 1074) * (test_rand() % 2 ? -1 : 1);
        }
        check_sum(v, n);
        for (size_t i = 0; i < n; i++) w[i] = v[n - 1 - i];
        check_sum(w, n);
        for (size_t i = 0; i < n; i++) w[i] = v[(i * 7 + 3) % n];
        if (n % 7) check_sum(w, n); /* a permutation when 7 and n share no factor */
    }
    /* random multisets over the whole range; any order and any split gives the same bits */
    for (int round = 0; round < 300 && !g_test_failed; round++) {
        double v[64];
        size_t n = 1 + test_rand() % 64;
        int span = (int)(test_rand() % 3);
        for (size_t i = 0; i < n; i++) {
            v[i] = rand_double();
            if (span == 1) v[i] = ldexp(frexp(v[i], &(int){0}), (int)(test_rand() % 120) - 60);
            if (span == 2 && i % 2) v[i] = -v[i - 1] * (1 + 0x1p-52 * (double)(test_rand() % 4));
        }
        check_sum(v, n);
        int64_t keys[64], first = 0;
        for (size_t i = 0; i < n; i++) keys[i] = imdb_f64_key(v[i]);
        int rc0 = fsum_of(keys, n, &first);
        for (int sh = 0; sh < 20 && !g_test_failed; sh++) {
            for (size_t i = n; i > 1; i--) {
                size_t j = test_rand() % i;
                int64_t tk = keys[i - 1];
                keys[i - 1] = keys[j];
                keys[j] = tk;
            }
            imdb_fsum a = {0}, b = {0};
            imdb_err e = {0};
            size_t cut = test_rand() % (n + 1);
            for (size_t i = 0; i < n; i++) CHECK(imdb_fsum_add(i < cut ? &a : &b, keys[i], &e) == IMDB_OK);
            CHECK(imdb_fsum_merge(&a, &b, &e) == IMDB_OK);
            int64_t got = 0;
            int rc = imdb_fsum_result(&a, &got, &e);
            CHECK(rc == rc0 && (rc || got == first));
            double sv[64];
            for (size_t i = 0; i < n; i++) sv[i] = imdb_f64_value(keys[i]);
            int64_t ag = 0;
            int ar = afsum_of(sv, n, &ag);
            CHECK(rc0 ? ar == 1 : ar == 0 && ag == first);
            imdb_fsum_free(&a);
            imdb_fsum_free(&b);
        }
    }
}

const test_case codec_tests[] = {
    {"float64_keys", t_float64_keys},
    {"float64_literals", t_float64_literals},
    {"null_rows", t_null_rows},
    {"fsum_exact", t_fsum_exact},
    {"utf8_exhaustive_short", t_utf8_exhaustive_short},
    {"utf8_boundaries", t_utf8_boundaries},
    {"ident", t_ident},
    {"int64_literals", t_int64_literals},
    {"decimal", t_decimal},
    {"timestamp", t_timestamp},
    {"rows", t_rows},
    {"schema_codec", t_schema_codec},
    {"siphash_vectors", t_siphash_vectors},
    {"safe_format", t_safe_format},
    {"hashmap", t_hashmap},
};
const size_t codec_ntests = sizeof codec_tests / sizeof *codec_tests;
