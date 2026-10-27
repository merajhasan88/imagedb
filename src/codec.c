#include "codec.h"

#include <errno.h>
#include <locale.h>
#include <math.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>

#include "cpu.h"
#include "sha256.h"

/* ---- text ---------------------------------------------------------------- */

bool imdb_utf8_valid(const uint8_t *s, size_t n, size_t *bad)
{
    const imdb_kernels *k = imdb_kern();
    size_t i = 0;
    while (i < n) {
        i += k->ascii_prefix(s + i, n - i); /* bytes 0x01..0x7F */
        if (i >= n) break;
        uint8_t c = s[i];
        size_t need;
        uint8_t lo = 0x80, hi = 0xBF;
        if (c == 0x00) goto fail;
        if (c < 0x80) {
            i++;
            continue;
        }
        if (c >= 0xC2 && c <= 0xDF) need = 1;
        else if (c == 0xE0) need = 2, lo = 0xA0;
        else if (c >= 0xE1 && c <= 0xEC) need = 2;
        else if (c == 0xED) need = 2, hi = 0x9F;           /* no UTF-16 surrogates */
        else if (c == 0xEE || c == 0xEF) need = 2;
        else if (c == 0xF0) need = 3, lo = 0x90;           /* no overlongs */
        else if (c >= 0xF1 && c <= 0xF3) need = 3;
        else if (c == 0xF4) need = 3, hi = 0x8F;           /* <= U+10FFFF */
        else goto fail;                                     /* C0, C1, F5..FF, stray continuation */
        if (need > n - i - 1) goto fail;                    /* truncated: never read past the end */
        if (s[i + 1] < lo || s[i + 1] > hi) goto fail;
        for (size_t j = 2; j <= need; j++)
            if ((s[i + j] & 0xC0) != 0x80) goto fail;
        i += need + 1;
    }
    return true;
fail:
    if (bad) *bad = i;
    return false;
}

static bool ident_char(char c, bool first)
{
    if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_') return true;
    return !first && c >= '0' && c <= '9';
}

bool imdb_ident_valid(const char *s, size_t n)
{
    if (n == 0 || n > IMDB_MAX_IDENT) return false;
    for (size_t i = 0; i < n; i++)
        if (!ident_char(s[i], i == 0)) return false;
    return true;
}

bool imdb_ident_fold(const char *s, size_t n, char out[IMDB_MAX_IDENT + 1])
{
    if (!imdb_ident_valid(s, n)) return false;
    for (size_t i = 0; i < n; i++) out[i] = (s[i] >= 'A' && s[i] <= 'Z') ? (char)(s[i] + 32) : s[i];
    out[n] = '\0';
    return true;
}

/* ---- schema ------------------------------------------------------------ */

const char *imdb_type_name(uint8_t t)
{
    switch (t) {
    case IMDB_T_INT64: return "INT64";
    case IMDB_T_DECIMAL: return "DECIMAL";
    case IMDB_T_TEXT: return "TEXT";
    case IMDB_T_BOOL: return "BOOL";
    case IMDB_T_TIMESTAMP: return "TIMESTAMP";
    case IMDB_T_FLOAT64: return "FLOAT64";
    }
    return "?";
}

bool imdb_type_is_int(uint8_t t) { return t != IMDB_T_TEXT; }

/* ---- FLOAT64 ------------------------------------------------------------- */

/* Negative doubles flip their 63 magnitude bits, so they order below the
 * non-negative ones as int64s; the map is its own inverse. */
static uint64_t f64_flip(uint64_t b) { return (int64_t)b >= 0 ? b : b ^ 0x7fffffffffffffffull; }

int64_t imdb_f64_key(double d)
{
    uint64_t b;
    memcpy(&b, &d, 8);
    if (b == 0x8000000000000000ull) b = 0; /* -0.0: one encoding per value */
    return (int64_t)f64_flip(b);
}

double imdb_f64_value(int64_t key)
{
    uint64_t b = f64_flip((uint64_t)key);
    double d;
    memcpy(&d, &b, 8);
    return d;
}

bool imdb_f64_key_valid(int64_t key)
{
    uint64_t b = f64_flip((uint64_t)key);
    return ((b >> 52) & 0x7ff) != 0x7ff && b != 0x8000000000000000ull;
}

/* strtod and printf follow LC_NUMERIC, which a host program may change: both run
 * under the C locale, on this thread only. */
static locale_t g_c_locale;
static pthread_once_t g_c_locale_once = PTHREAD_ONCE_INIT;

static void c_locale_init(void)
{
    g_c_locale = newlocale(LC_ALL_MASK, "C", (locale_t)0);
    if (!g_c_locale) { /* glibc returns a static object for "C": cannot happen */
        fputs("imagedb: no C locale\n", stderr);
        abort();
    }
}

static locale_t c_locale(void)
{
    pthread_once(&g_c_locale_once, c_locale_init);
    return g_c_locale;
}

int imdb_schema_col(const imdb_schema *s, const char *name)
{
    for (int i = 0; i < s->ncols; i++)
        if (strcmp(s->cols[i].name, name) == 0) return i;
    return -1;
}

int imdb_schema_check(const imdb_schema *s, imdb_err *e)
{
    size_t nl = strnlen(s->name, sizeof s->name);
    if (!imdb_ident_valid(s->name, nl)) return imdb_fail(e, IMDB_ERR_INVALID, "invalid table name");
    if (s->ncols < 1 || s->ncols > IMDB_MAX_COLS)
        return imdb_fail(e, IMDB_ERR_LIMIT, "table must have 1..%u columns", IMDB_MAX_COLS);
    int pk = -1, subj = -1;
    for (int i = 0; i < s->ncols; i++) {
        const imdb_column *c = &s->cols[i];
        size_t cl = strnlen(c->name, sizeof c->name);
        if (!imdb_ident_valid(c->name, cl)) return imdb_fail(e, IMDB_ERR_INVALID, "invalid column name");
        if (c->name[0] == '_') return imdb_fail(e, IMDB_ERR_INVALID, "column names starting with '_' are reserved");
        for (int j = 0; j < i; j++)
            if (strcmp(s->cols[j].name, c->name) == 0)
                return imdb_fail(e, IMDB_ERR_INVALID, "duplicate column name %s", c->name);
        if (c->type < IMDB_T_INT64 || c->type > IMDB_T_FLOAT64)
            return imdb_fail(e, IMDB_ERR_INVALID, "column %s: unknown type", c->name);
        if (c->type == IMDB_T_DECIMAL) {
            if (c->precision < 1 || c->precision > 18 || c->scale > c->precision)
                return imdb_fail(e, IMDB_ERR_INVALID, "column %s: DECIMAL(p,s) needs 1<=p<=18, 0<=s<=p", c->name);
        } else if (c->precision || c->scale) {
            return imdb_fail(e, IMDB_ERR_INVALID, "column %s: precision/scale only valid for DECIMAL", c->name);
        }
        if (c->flags & ~(IMDB_COL_PK | IMDB_COL_SUBJECT | IMDB_COL_NULLABLE))
            return imdb_fail(e, IMDB_ERR_INVALID, "column %s: unknown flags", c->name);
        if ((c->flags & IMDB_COL_NULLABLE) && (c->flags & (IMDB_COL_PK | IMDB_COL_SUBJECT)))
            return imdb_fail(e, IMDB_ERR_INVALID, "column %s: PRIMARY KEY and SUBJECT columns are NOT NULL", c->name);
        if (c->flags & IMDB_COL_PK) {
            if (pk >= 0) return imdb_fail(e, IMDB_ERR_INVALID, "only one PRIMARY KEY column is supported");
            if (c->type != IMDB_T_INT64 && c->type != IMDB_T_TEXT)
                return imdb_fail(e, IMDB_ERR_INVALID, "PRIMARY KEY must be INT64 or TEXT");
            pk = i;
        }
        if (c->flags & IMDB_COL_SUBJECT) {
            if (subj >= 0) return imdb_fail(e, IMDB_ERR_INVALID, "only one SUBJECT column is supported");
            if (c->type != IMDB_T_INT64 && c->type != IMDB_T_TEXT)
                return imdb_fail(e, IMDB_ERR_INVALID, "SUBJECT column must be INT64 or TEXT");
            subj = i;
        }
    }
    if (pk < 0) return imdb_fail(e, IMDB_ERR_INVALID, "table needs a PRIMARY KEY column");
    if (s->pk != pk || s->subject != subj) return imdb_fail(e, IMDB_ERR_INVALID, "schema key indexes inconsistent");
    return IMDB_OK;
}

void imdb_schema_encode(const imdb_schema *s, imdb_buf *b)
{
    size_t nl = strlen(s->name);
    imdb_buf_put_u32(b, s->id);
    imdb_buf_put_u8(b, (uint8_t)nl);
    imdb_buf_put(b, s->name, nl);
    imdb_buf_put_u16(b, s->ncols);
    for (int i = 0; i < s->ncols; i++) {
        const imdb_column *c = &s->cols[i];
        size_t cl = strlen(c->name);
        imdb_buf_put_u8(b, (uint8_t)cl);
        imdb_buf_put(b, c->name, cl);
        imdb_buf_put_u8(b, c->type);
        imdb_buf_put_u8(b, c->precision);
        imdb_buf_put_u8(b, c->scale);
        imdb_buf_put_u8(b, c->flags);
    }
}

int imdb_rd_ident(imdb_rd *r, char out[IMDB_MAX_IDENT + 1], imdb_err *e)
{
    uint8_t n = imdb_rd_u8(r);
    const uint8_t *p = imdb_rd_bytes(r, n);
    if (!p || !imdb_ident_valid((const char *)p, n))
        return imdb_fail(e, IMDB_ERR_CORRUPT, "schema: bad identifier");
    memcpy(out, p, n);
    out[n] = '\0';
    for (size_t i = 0; i < n; i++)
        if (out[i] >= 'A' && out[i] <= 'Z') return imdb_fail(e, IMDB_ERR_CORRUPT, "schema: identifier not folded");
    return IMDB_OK;
}

int imdb_schema_decode(imdb_rd *r, imdb_schema *s, imdb_err *e)
{
    memset(s, 0, sizeof *s);
    s->id = imdb_rd_u32(r);
    if (imdb_rd_ident(r, s->name, e)) return e->code;
    s->ncols = imdb_rd_u16(r);
    if (s->ncols < 1 || s->ncols > IMDB_MAX_COLS) return imdb_fail(e, IMDB_ERR_CORRUPT, "schema: bad column count");
    s->subject = -1;
    for (int i = 0; i < s->ncols; i++) {
        imdb_column *c = &s->cols[i];
        if (imdb_rd_ident(r, c->name, e)) return e->code;
        c->type = imdb_rd_u8(r);
        c->precision = imdb_rd_u8(r);
        c->scale = imdb_rd_u8(r);
        c->flags = imdb_rd_u8(r);
        if (c->flags & IMDB_COL_PK) s->pk = (uint16_t)i;
        if (c->flags & IMDB_COL_SUBJECT) s->subject = (int16_t)i;
    }
    if (r->err) return imdb_fail(e, IMDB_ERR_CORRUPT, "schema: truncated");
    imdb_err e2 = {0};
    if (imdb_schema_check(s, &e2)) return imdb_fail(e, IMDB_ERR_CORRUPT, "schema: %s", e2.msg);
    return IMDB_OK;
}

/* ---- values -------------------------------------------------------------- */

int64_t imdb_pow10(int n)
{
    static const int64_t p[19] = {1LL, 10LL, 100LL, 1000LL, 10000LL, 100000LL, 1000000LL, 10000000LL,
                                  100000000LL, 1000000000LL, 10000000000LL, 100000000000LL,
                                  1000000000000LL, 10000000000000LL, 100000000000000LL,
                                  1000000000000000LL, 10000000000000000LL, 100000000000000000LL,
                                  1000000000000000000LL};
    return (n >= 0 && n <= 18) ? p[n] : 0;
}

#define TS_MIN (-62135596800000000LL) /* 0001-01-01 00:00:00 */
#define TS_MAX (253402300799999999LL) /* 9999-12-31 23:59:59.999999 */

int imdb_value_check(const imdb_column *c, const imdb_value *v, imdb_err *e)
{
    if (v->type != c->type)
        return imdb_fail(e, IMDB_ERR_INVALID, "column %s expects %s, got %s", c->name, imdb_type_name(c->type),
                         imdb_type_name(v->type));
    if (v->null)
        return (c->flags & IMDB_COL_NULLABLE) ? IMDB_OK
                                              : imdb_fail(e, IMDB_ERR_CONSTRAINT, "column %s is NOT NULL", c->name);
    switch (c->type) {
    case IMDB_T_INT64: return IMDB_OK;
    case IMDB_T_DECIMAL: {
        if (v->scale != c->scale) return imdb_fail(e, IMDB_ERR_INVALID, "column %s: decimal scale mismatch", c->name);
        int64_t lim = imdb_pow10(c->precision) - 1;
        if (v->i > lim || v->i < -lim)
            return imdb_fail(e, IMDB_ERR_LIMIT, "column %s: value exceeds DECIMAL(%u,%u)", c->name, c->precision, c->scale);
        return IMDB_OK;
    }
    case IMDB_T_BOOL:
        if (v->i != 0 && v->i != 1) return imdb_fail(e, IMDB_ERR_INVALID, "column %s: bad BOOL", c->name);
        return IMDB_OK;
    case IMDB_T_TIMESTAMP:
        if (v->i < TS_MIN || v->i > TS_MAX)
            return imdb_fail(e, IMDB_ERR_LIMIT, "column %s: timestamp out of range", c->name);
        return IMDB_OK;
    case IMDB_T_FLOAT64:
        if (!imdb_f64_key_valid(v->i)) return imdb_fail(e, IMDB_ERR_INVALID, "column %s: not a finite FLOAT64", c->name);
        return IMDB_OK;
    case IMDB_T_TEXT: {
        if (v->len > IMDB_MAX_TEXT) return imdb_fail(e, IMDB_ERR_LIMIT, "column %s: TEXT longer than %u bytes", c->name, IMDB_MAX_TEXT);
        size_t bad;
        if (v->len && !imdb_utf8_valid(v->s, v->len, &bad))
            return imdb_fail(e, IMDB_ERR_INVALID, "column %s: invalid UTF-8 at byte %zu", c->name, bad);
        return IMDB_OK;
    }
    }
    return imdb_fail(e, IMDB_ERR_INVALID, "column %s: unknown type", c->name);
}

static uint32_t nullable_count(const imdb_schema *s)
{
    uint32_t n = 0;
    for (int i = 0; i < s->ncols; i++) n += (s->cols[i].flags & IMDB_COL_NULLABLE) != 0;
    return n;
}

static size_t value_width(uint8_t type, const imdb_value *v)
{
    return type == IMDB_T_TEXT ? 4 + (size_t)v->len : type == IMDB_T_BOOL ? 1 : 8;
}

int imdb_row_encode(const imdb_schema *s, const imdb_value *vals, imdb_buf *out, imdb_err *e)
{
    uint32_t nn = nullable_count(s);
    size_t total = (nn + 7) / 8;
    uint8_t bm[(IMDB_MAX_COLS + 7) / 8] = {0};
    for (int i = 0, k = 0; i < s->ncols; i++) {
        if (imdb_value_check(&s->cols[i], &vals[i], e)) return e->code;
        if (s->cols[i].flags & IMDB_COL_NULLABLE) {
            if (vals[i].null) bm[k >> 3] |= (uint8_t)(1u << (k & 7));
            k++;
        }
        if (vals[i].null) continue;
        if (imdb_add_ovf(total, value_width(s->cols[i].type, &vals[i]), &total) || total > IMDB_MAX_ROW)
            return imdb_fail(e, IMDB_ERR_LIMIT, "row exceeds %u bytes", IMDB_MAX_ROW);
    }
    if (!imdb_buf_reserve(out, total)) return imdb_buf_check(out, e);
    imdb_buf_put(out, bm, (nn + 7) / 8);
    for (int i = 0; i < s->ncols; i++) {
        const imdb_value *v = &vals[i];
        if (v->null) continue;
        switch (s->cols[i].type) {
        case IMDB_T_TEXT:
            imdb_buf_put_u32(out, v->len);
            imdb_buf_put(out, v->s, v->len);
            break;
        case IMDB_T_BOOL: imdb_buf_put_u8(out, (uint8_t)v->i); break;
        default: imdb_buf_put_u64(out, (uint64_t)v->i); break;
        }
    }
    return imdb_buf_check(out, e);
}

/* The null bitmap at the front of a row; NULL when the row is too short. */
static const uint8_t *row_bitmap(const imdb_schema *s, imdb_rd *r, uint32_t *nn)
{
    *nn = nullable_count(s);
    return *nn ? imdb_rd_bytes(r, (*nn + 7) / 8) : (const uint8_t *)"";
}

int imdb_row_decode(const imdb_schema *s, const uint8_t *row, size_t len, imdb_value *vals, imdb_err *e)
{
    imdb_rd r;
    imdb_rd_init(&r, row, len);
    if (len > IMDB_MAX_ROW) return imdb_fail(e, IMDB_ERR_CORRUPT, "row too long");
    uint32_t nn;
    const uint8_t *bm = row_bitmap(s, &r, &nn);
    if (!bm) return imdb_fail(e, IMDB_ERR_CORRUPT, "row: truncated null bitmap");
    if ((nn & 7) && (bm[nn >> 3] >> (nn & 7)) != 0) return imdb_fail(e, IMDB_ERR_CORRUPT, "row: null bitmap padding");
    for (int i = 0, k = 0; i < s->ncols; i++) {
        const imdb_column *c = &s->cols[i];
        imdb_value *v = &vals[i];
        memset(v, 0, sizeof *v);
        v->type = c->type;
        v->scale = c->scale;
        if (c->flags & IMDB_COL_NULLABLE) {
            bool isnull = bm[k >> 3] >> (k & 7) & 1;
            k++;
            if (isnull) {
                v->null = true;
                continue;
            }
        }
        switch (c->type) {
        case IMDB_T_TEXT:
            v->len = imdb_rd_u32(&r);
            if (v->len > IMDB_MAX_TEXT) return imdb_fail(e, IMDB_ERR_CORRUPT, "row: TEXT length out of range");
            v->s = imdb_rd_bytes(&r, v->len);
            if (!v->s) return imdb_fail(e, IMDB_ERR_CORRUPT, "row: truncated TEXT");
            break;
        case IMDB_T_BOOL: v->i = imdb_rd_u8(&r); break;
        default: v->i = (int64_t)imdb_rd_u64(&r); break;
        }
        if (r.err) return imdb_fail(e, IMDB_ERR_CORRUPT, "row: truncated");
        imdb_err e2 = {0};
        if (imdb_value_check(c, v, &e2)) return imdb_fail(e, IMDB_ERR_CORRUPT, "row: %s", e2.msg);
    }
    if (imdb_rd_left(&r)) return imdb_fail(e, IMDB_ERR_CORRUPT, "row: trailing bytes");
    return IMDB_OK;
}

void imdb_row_get(const imdb_schema *s, const uint8_t *row, size_t len, int col, imdb_value *v)
{
    imdb_rd r;
    imdb_rd_init(&r, row, len);
    memset(v, 0, sizeof *v);
    uint32_t nn;
    const uint8_t *bm = row_bitmap(s, &r, &nn);
    for (int i = 0, k = 0; bm && i <= col; i++) {
        const imdb_column *c = &s->cols[i];
        uint8_t t = c->type;
        bool isnull = false;
        if (c->flags & IMDB_COL_NULLABLE) {
            isnull = bm[k >> 3] >> (k & 7) & 1;
            k++;
        }
        if (i < col) {
            if (isnull) continue;
            if (t == IMDB_T_TEXT) {
                uint32_t n = imdb_rd_u32(&r);
                (void)imdb_rd_bytes(&r, n);
            } else {
                (void)imdb_rd_bytes(&r, t == IMDB_T_BOOL ? 1 : 8);
            }
            continue;
        }
        v->type = t;
        v->scale = c->scale;
        if (isnull) {
            v->null = true;
        } else if (t == IMDB_T_TEXT) {
            v->len = imdb_rd_u32(&r);
            v->s = imdb_rd_bytes(&r, v->len);
            if (!v->s) v->len = 0;
        } else if (t == IMDB_T_BOOL) {
            v->i = imdb_rd_u8(&r);
        } else {
            v->i = (int64_t)imdb_rd_u64(&r);
        }
    }
}

int imdb_value_cmp(const imdb_value *a, const imdb_value *b)
{
    if (a->null || b->null) return a->null == b->null ? 0 : a->null ? 1 : -1; /* NULLS LAST */
    if (a->type == IMDB_T_TEXT) {
        uint32_t n = a->len < b->len ? a->len : b->len;
        int c = n ? memcmp(a->s, b->s, n) : 0;
        if (c) return c < 0 ? -1 : 1;
        return a->len < b->len ? -1 : a->len > b->len;
    }
    return a->i < b->i ? -1 : a->i > b->i;
}

/* SipHash-2-4 (Aumasson & Bernstein): keyed hash for in-memory hash tables,
 * so adversarial keys cannot force collisions (hash flooding). */
#define ROTL64(x, b) (uint64_t)(((x) << (b)) | ((x) >> (64 - (b))))
#define SIPROUND                                                          \
    do {                                                                  \
        v0 += v1; v1 = ROTL64(v1, 13); v1 ^= v0; v0 = ROTL64(v0, 32);     \
        v2 += v3; v3 = ROTL64(v3, 16); v3 ^= v2;                          \
        v0 += v3; v3 = ROTL64(v3, 21); v3 ^= v0;                          \
        v2 += v1; v1 = ROTL64(v1, 17); v1 ^= v2; v2 = ROTL64(v2, 32);     \
    } while (0)

uint64_t imdb_siphash24(const uint8_t *in, size_t n, uint64_t k0, uint64_t k1);
uint64_t imdb_siphash24(const uint8_t *in, size_t n, uint64_t k0, uint64_t k1)
{
    uint64_t v0 = 0x736f6d6570736575ull ^ k0, v1 = 0x646f72616e646f6dull ^ k1;
    uint64_t v2 = 0x6c7967656e657261ull ^ k0, v3 = 0x7465646279746573ull ^ k1;
    uint64_t b = (uint64_t)n << 56;
    size_t full = n - (n & 7);
    for (size_t i = 0; i < full; i += 8) {
        uint64_t m = imdb_get_le64(in + i);
        v3 ^= m;
        SIPROUND;
        SIPROUND;
        v0 ^= m;
    }
    for (size_t i = 0; i < (n & 7); i++) b |= (uint64_t)in[full + i] << (8 * i);
    v3 ^= b;
    SIPROUND;
    SIPROUND;
    v0 ^= b;
    v2 ^= 0xff;
    SIPROUND;
    SIPROUND;
    SIPROUND;
    SIPROUND;
    return v0 ^ v1 ^ v2 ^ v3;
}

uint64_t imdb_value_hash(const imdb_value *v, uint64_t seed)
{
    if (v->null) return imdb_siphash24((const uint8_t *)"", 0, seed, 0x6a09e667f3bcc909ull);
    if (v->type == IMDB_T_TEXT) return imdb_siphash24(v->s, v->len, seed, 0x9e3779b97f4a7c15ull);
    uint8_t t[8];
    imdb_le64(t, (uint64_t)v->i);
    return imdb_siphash24(t, 8, seed, 0x9e3779b97f4a7c15ull);
}

void imdb_row_commit(uint32_t table_id, const uint8_t salt[16], const uint8_t *row, size_t len, uint8_t out[32])
{
    static const uint8_t tag[8] = {'I', 'M', 'D', 'B', 'R', 'O', 'W', '1'};
    uint8_t hdr[8 + 4 + 16 + 4];
    memcpy(hdr, tag, 8);
    imdb_le32(hdr + 8, table_id);
    memcpy(hdr + 12, salt, 16);
    imdb_le32(hdr + 28, (uint32_t)len);
    imdb_sha256_ctx c;
    imdb_sha256_init(&c);
    imdb_sha256_update(&c, hdr, sizeof hdr);
    imdb_sha256_update(&c, row, len);
    imdb_sha256_final(&c, out);
}

/* ---- literals ------------------------------------------------------------ */

int imdb_parse_int64(const char *s, size_t n, int64_t *out, imdb_err *e)
{
    size_t i = 0;
    bool neg = false;
    if (i < n && (s[i] == '-' || s[i] == '+')) neg = s[i++] == '-';
    if (i == n) return imdb_fail(e, IMDB_ERR_INVALID, "invalid integer literal");
    uint64_t mag = 0;
    for (; i < n; i++) {
        if (s[i] < '0' || s[i] > '9') return imdb_fail(e, IMDB_ERR_INVALID, "invalid integer literal");
        if (imdb_mul_ovf(mag, (uint64_t)10, &mag) || imdb_add_ovf(mag, (uint64_t)(s[i] - '0'), &mag))
            return imdb_fail(e, IMDB_ERR_LIMIT, "integer literal out of INT64 range");
    }
    if (neg) {
        if (mag > (uint64_t)INT64_MAX + 1) return imdb_fail(e, IMDB_ERR_LIMIT, "integer literal out of INT64 range");
        *out = mag == (uint64_t)INT64_MAX + 1 ? INT64_MIN : -(int64_t)mag;
    } else {
        if (mag > (uint64_t)INT64_MAX) return imdb_fail(e, IMDB_ERR_LIMIT, "integer literal out of INT64 range");
        *out = (int64_t)mag;
    }
    return IMDB_OK;
}

int imdb_parse_float64(const char *s, size_t n, int64_t *key, imdb_err *e)
{
    /* the grammar is checked here, so strtod never sees hex, inf, nan or spaces */
    size_t i = 0;
    bool nonzero = false;
    if (i < n && (s[i] == '-' || s[i] == '+')) i++;
    size_t d0 = i;
    for (; i < n && s[i] >= '0' && s[i] <= '9'; i++) nonzero |= s[i] != '0';
    bool ok = i > d0;
    if (ok && i < n && s[i] == '.') {
        size_t f0 = ++i;
        for (; i < n && s[i] >= '0' && s[i] <= '9'; i++) nonzero |= s[i] != '0';
        ok = i > f0;
    }
    if (ok && i < n && (s[i] == 'e' || s[i] == 'E')) {
        if (++i < n && (s[i] == '-' || s[i] == '+')) i++;
        size_t x0 = i;
        while (i < n && s[i] >= '0' && s[i] <= '9') i++;
        ok = i > x0;
    }
    if (!ok || i != n) return imdb_fail(e, IMDB_ERR_INVALID, "invalid FLOAT64 literal");
    char buf[IMDB_MAX_NUMERIC + 1];
    if (n > IMDB_MAX_NUMERIC) return imdb_fail(e, IMDB_ERR_LIMIT, "numeric literal longer than %u bytes", IMDB_MAX_NUMERIC);
    memcpy(buf, s, n);
    buf[n] = '\0';
    locale_t old = uselocale(c_locale());
    char *end;
    double d = strtod(buf, &end);
    uselocale(old);
    if (end != buf + n) return imdb_fail(e, IMDB_ERR_INVALID, "invalid FLOAT64 literal");
    if (!isfinite(d)) return imdb_fail(e, IMDB_ERR_LIMIT, "FLOAT64 literal out of range");
    if (d == 0 && nonzero) return imdb_fail(e, IMDB_ERR_LIMIT, "FLOAT64 literal underflows to zero");
    *key = imdb_f64_key(d);
    return IMDB_OK;
}

int imdb_parse_decimal(const char *s, size_t n, int precision, int scale, int64_t *out, imdb_err *e)
{
    size_t i = 0;
    bool neg = false;
    if (i < n && (s[i] == '-' || s[i] == '+')) neg = s[i++] == '-';
    size_t int_start = i;
    while (i < n && s[i] >= '0' && s[i] <= '9') i++;
    size_t int_digits = i - int_start;
    size_t frac_start = 0, frac_digits = 0;
    if (i < n && s[i] == '.') {
        frac_start = ++i;
        while (i < n && s[i] >= '0' && s[i] <= '9') i++;
        frac_digits = i - frac_start;
        if (frac_digits == 0) return imdb_fail(e, IMDB_ERR_INVALID, "invalid decimal literal");
    }
    if (i != n || int_digits == 0) return imdb_fail(e, IMDB_ERR_INVALID, "invalid decimal literal");
    if (frac_digits > (size_t)scale) {
        /* trailing zeros beyond the scale are exact and allowed; anything else would round */
        for (size_t j = (size_t)scale; j < frac_digits; j++)
            if (s[frac_start + j] != '0')
                return imdb_fail(e, IMDB_ERR_INVALID, "decimal literal has more than %d fractional digits (no silent rounding)", scale);
        frac_digits = (size_t)scale;
    }
    /* skip leading zeros of the integer part for the precision check */
    size_t z = int_start;
    while (z < int_start + int_digits - 1 && s[z] == '0') z++;
    size_t sig_int = int_start + int_digits - z;
    if (!(sig_int == 1 && s[z] == '0') && sig_int > (size_t)(precision - scale))
        return imdb_fail(e, IMDB_ERR_LIMIT, "decimal literal exceeds DECIMAL(%d,%d)", precision, scale);
    int64_t v = 0;
    for (size_t j = z; j < int_start + int_digits; j++) v = v * 10 + (s[j] - '0');
    for (size_t j = 0; j < (size_t)scale; j++) v = v * 10 + (j < frac_digits ? s[frac_start + j] - '0' : 0);
    *out = neg ? -v : v;
    return IMDB_OK;
}

static bool is_leap(int64_t y) { return (y % 4 == 0 && y % 100 != 0) || y % 400 == 0; }

static int days_in_month(int64_t y, int m)
{
    static const int d[12] = {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
    return m == 2 && is_leap(y) ? 29 : d[m - 1];
}

/* Howard Hinnant's days_from_civil (proleptic Gregorian). */
static int64_t days_from_civil(int64_t y, int m, int d)
{
    y -= m <= 2;
    int64_t era = (y >= 0 ? y : y - 399) / 400;
    int64_t yoe = y - era * 400;
    int64_t doy = (153 * (m + (m > 2 ? -3 : 9)) + 2) / 5 + d - 1;
    int64_t doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    return era * 146097 + doe - 719468;
}

static void civil_from_days(int64_t z, int64_t *y, int *m, int *d)
{
    z += 719468;
    int64_t era = (z >= 0 ? z : z - 146096) / 146097;
    int64_t doe = z - era * 146097;
    int64_t yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    int64_t doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    int64_t mp = (5 * doy + 2) / 153;
    *d = (int)(doy - (153 * mp + 2) / 5 + 1);
    *m = (int)(mp < 10 ? mp + 3 : mp - 9);
    *y = yoe + era * 400 + (*m <= 2);
}

static bool digits(const char *s, size_t n, size_t off, size_t cnt, int64_t *v)
{
    if (off > n || cnt > n - off) return false;
    int64_t x = 0;
    for (size_t i = 0; i < cnt; i++) {
        char c = s[off + i];
        if (c < '0' || c > '9') return false;
        x = x * 10 + (c - '0');
    }
    *v = x;
    return true;
}

int imdb_parse_timestamp(const char *s, size_t n, int64_t *out, imdb_err *e)
{
    int64_t Y, M, D, h = 0, mi = 0, se = 0, us = 0;
    if (n > 32 || !digits(s, n, 0, 4, &Y) || n < 10 || s[4] != '-' || !digits(s, n, 5, 2, &M) || s[7] != '-' ||
        !digits(s, n, 8, 2, &D))
        return imdb_fail(e, IMDB_ERR_INVALID, "timestamp must look like 'YYYY-MM-DD HH:MM:SS[.ffffff]' (UTC)");
    size_t i = 10;
    if (i < n) {
        if ((s[i] != ' ' && s[i] != 'T') || !digits(s, n, i + 1, 2, &h) || i + 3 >= n || s[i + 3] != ':' ||
            !digits(s, n, i + 4, 2, &mi) || i + 6 >= n || s[i + 6] != ':' || !digits(s, n, i + 7, 2, &se))
            return imdb_fail(e, IMDB_ERR_INVALID, "timestamp must look like 'YYYY-MM-DD HH:MM:SS[.ffffff]' (UTC)");
        i += 9;
        if (i < n && s[i] == '.') {
            size_t f0 = ++i;
            while (i < n && s[i] >= '0' && s[i] <= '9') i++;
            size_t fd = i - f0;
            if (fd < 1 || fd > 6) return imdb_fail(e, IMDB_ERR_INVALID, "timestamp fraction must have 1..6 digits");
            int64_t f;
            digits(s, n, f0, fd, &f);
            for (size_t k = fd; k < 6; k++) f *= 10;
            us = f;
        }
        if (i < n && s[i] == 'Z') i++;
        if (i != n) return imdb_fail(e, IMDB_ERR_INVALID, "timestamp: only UTC is supported (no offsets)");
    }
    if (Y < 1 || M < 1 || M > 12 || D < 1 || D > days_in_month(Y, (int)M) || h > 23 || mi > 59 || se > 59)
        return imdb_fail(e, IMDB_ERR_INVALID, "timestamp field out of range");
    int64_t days = days_from_civil(Y, (int)M, (int)D);
    *out = ((days * 86400 + h * 3600 + mi * 60 + se) * 1000000) + us;
    return IMDB_OK;
}

void imdb_format_timestamp(int64_t t, imdb_buf *out)
{
    int64_t days = t / 86400000000LL, rem = t % 86400000000LL;
    if (rem < 0) {
        rem += 86400000000LL;
        days--;
    }
    int64_t y;
    int m, d;
    civil_from_days(days, &y, &m, &d);
    int64_t secs = rem / 1000000, us = rem % 1000000;
    imdb_buf_printf(out, "%04lld-%02d-%02d %02lld:%02lld:%02lld", (long long)y, m, d, (long long)(secs / 3600),
                    (long long)(secs / 60 % 60), (long long)(secs % 60));
    if (us) imdb_buf_printf(out, ".%06lld", (long long)us);
}

void imdb_format_float64(int64_t key, imdb_buf *out)
{
    double d = imdb_f64_value(key);
    char b[40];
    locale_t old = uselocale(c_locale());
    for (int prec = 15; prec <= 17; prec++) {
        snprintf(b, sizeof b, "%.*g", prec, d);
        if (prec == 17 || strtod(b, NULL) == d) break;
    }
    uselocale(old);
    imdb_buf_put_str(out, b);
}

void imdb_format_i128(__int128 v, int scale, imdb_buf *out)
{
    char tmp[64];
    int n = 0;
    bool neg = v < 0;
    unsigned __int128 mag = neg ? (unsigned __int128)0 - (unsigned __int128)v : (unsigned __int128)v;
    do {
        tmp[n++] = (char)('0' + (int)(mag % 10));
        mag /= 10;
    } while (mag || n <= scale);
    if (neg) imdb_buf_put_u8(out, '-');
    for (int i = n - 1; i >= 0; i--) {
        imdb_buf_put_u8(out, (uint8_t)tmp[i]);
        if (i == scale && scale > 0) imdb_buf_put_u8(out, '.');
    }
}

void imdb_format_decimal(int64_t v, int scale, imdb_buf *out) { imdb_format_i128(v, scale, out); }

void imdb_format_value(const imdb_value *v, imdb_buf *out)
{
    if (v->null) {
        imdb_buf_put_str(out, "null");
        return;
    }
    switch (v->type) {
    case IMDB_T_INT64: imdb_buf_printf(out, "%lld", (long long)v->i); break;
    case IMDB_T_DECIMAL: imdb_format_decimal(v->i, v->scale, out); break;
    case IMDB_T_BOOL: imdb_buf_put_str(out, v->i ? "true" : "false"); break;
    case IMDB_T_TIMESTAMP: imdb_format_timestamp(v->i, out); break;
    case IMDB_T_FLOAT64: imdb_format_float64(v->i, out); break;
    case IMDB_T_TEXT: imdb_buf_put(out, v->s, v->len); break;
    }
}

/* Terminal-safe rendering: control characters, C1 controls and bidi overrides
 * are shown as escapes so stored data cannot spoof the display (cf. CVE-2024-10977). */
void imdb_format_value_safe(const imdb_value *v, imdb_buf *out)
{
    if (v->type != IMDB_T_TEXT) {
        imdb_format_value(v, out);
        return;
    }
    const uint8_t *s = v->s;
    size_t n = v->len;
    for (size_t i = 0; i < n;) {
        uint8_t c = s[i];
        if (c < 0x20 || c == 0x7f) {
            imdb_buf_printf(out, "\\x%02x", c);
            i++;
        } else if (c == '\\') {
            imdb_buf_put_str(out, "\\\\");
            i++;
        } else if (c == 0xC2 && i + 1 < n && s[i + 1] >= 0x80 && s[i + 1] <= 0x9F) {
            imdb_buf_printf(out, "\\u%04x", s[i + 1]);
            i += 2;
        } else if (c == 0xE2 && i + 2 < n && s[i + 1] == 0x80 && s[i + 2] >= 0x8E && s[i + 2] <= 0xAE &&
                   (s[i + 2] <= 0x8F || s[i + 2] >= 0xAA)) {
            imdb_buf_printf(out, "\\u20%02x", (unsigned)(s[i + 2] - 0x80));
            i += 3;
        } else if (c == 0xE2 && i + 2 < n && s[i + 1] == 0x81 && s[i + 2] >= 0xA6 && s[i + 2] <= 0xA9) {
            imdb_buf_printf(out, "\\u20%02x", (unsigned)(s[i + 2] - 0x80 + 0x40));
            i += 3;
        } else if (c == 0xD8 && i + 1 < n && s[i + 1] == 0x9C) {
            imdb_buf_put_str(out, "\\u061c");
            i += 2;
        } else {
            imdb_buf_put_u8(out, c);
            i++;
        }
    }
}
