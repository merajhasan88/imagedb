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
    case IMDB_T_TIMESTAMPTZ: return "TIMESTAMPTZ";
    case IMDB_T_DATE: return "DATE";
    case IMDB_T_TIME: return "TIME";
    case IMDB_T_UUID: return "UUID";
    case IMDB_T_BYTEA: return "BYTEA";
    }
    return "?";
}

bool imdb_type_bytes(uint8_t t) { return t == IMDB_T_TEXT || t == IMDB_T_UUID || t == IMDB_T_BYTEA; }

bool imdb_type_is_int(uint8_t t) { return !imdb_type_bytes(t); }

bool imdb_int_width_ok(uint8_t width) { return width == 0 || width == 16 || width == 32; }

bool imdb_int_fits(uint8_t width, int64_t v)
{
    return width == 16 ? v >= INT16_MIN && v <= INT16_MAX : width == 32 ? v >= INT32_MIN && v <= INT32_MAX : true;
}

const char *imdb_int_name(uint8_t width) { return width == 16 ? "SMALLINT" : width == 32 ? "INTEGER" : "INT64"; }

uint32_t imdb_text_max(const imdb_column *c) { return c->type == IMDB_T_TEXT ? c->vlen : 0; }

void imdb_text_set_max(imdb_column *c, uint32_t n)
{
    c->vlen = (uint16_t)n;
}

uint32_t imdb_utf8_chars(const uint8_t *s, uint32_t n)
{
    uint32_t k = 0;
    for (uint32_t i = 0; i < n; i++) k += (s[i] & 0xC0) != 0x80; /* every byte but a continuation begins one */
    return k;
}

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
    int nflag = 0, subj = -1;
    for (int i = 0; i < s->ncols; i++) {
        const imdb_column *c = &s->cols[i];
        size_t cl = strnlen(c->name, sizeof c->name);
        if (!imdb_ident_valid(c->name, cl)) return imdb_fail(e, IMDB_ERR_INVALID, "invalid column name");
        if (c->name[0] == '_') return imdb_fail(e, IMDB_ERR_INVALID, "column names starting with '_' are reserved");
        for (int j = 0; j < i; j++)
            if (strcmp(s->cols[j].name, c->name) == 0)
                return imdb_fail(e, IMDB_ERR_INVALID, "duplicate column name %s", c->name);
        if (c->type < IMDB_T_INT64 || c->type > IMDB_T_LAST)
            return imdb_fail(e, IMDB_ERR_INVALID, "column %s: unknown type", c->name);
        if (c->type == IMDB_T_INT64) { /* F3a: SMALLINT 16, INTEGER 32, INT64 (BIGINT) 0: the one spelling of each */
            if (!imdb_int_width_ok(c->precision) || c->scale)
                return imdb_fail(e, IMDB_ERR_INVALID, "column %s: an integer of 16, 32 or 64 bits", c->name);
        } else if (c->type == IMDB_T_DECIMAL) {
            if (c->precision < 1 || c->precision > IMDB_DEC_MAX_DIGITS || c->scale > c->precision)
                return imdb_fail(e, IMDB_ERR_INVALID, "column %s: DECIMAL(p,s) needs 1<=p<=38, 0<=s<=p", c->name);
        } else if (c->precision || c->scale) {
            return imdb_fail(e, IMDB_ERR_INVALID, "column %s: precision/scale only valid for DECIMAL", c->name);
        }
        if (c->flags & ~(IMDB_COL_PK | IMDB_COL_SUBJECT | IMDB_COL_NULLABLE))
            return imdb_fail(e, IMDB_ERR_INVALID, "column %s: unknown flags", c->name);
        if ((c->flags & IMDB_COL_NULLABLE) && (c->flags & (IMDB_COL_PK | IMDB_COL_SUBJECT)))
            return imdb_fail(e, IMDB_ERR_INVALID, "column %s: PRIMARY KEY and SUBJECT columns are NOT NULL", c->name);
        if (c->flags & IMDB_COL_PK) { /* every type held exactly: a measured FLOAT64 is no identity (F4) */
            if (c->type == IMDB_T_FLOAT64)
                return imdb_fail(e, IMDB_ERR_INVALID, "column %s: a PRIMARY KEY column cannot be FLOAT64", c->name);
            nflag++;
        }
        if (c->flags & IMDB_COL_SUBJECT) {
            if (subj >= 0) return imdb_fail(e, IMDB_ERR_INVALID, "only one SUBJECT column is supported");
            if (c->type != IMDB_T_INT64 && c->type != IMDB_T_TEXT)
                return imdb_fail(e, IMDB_ERR_INVALID, "SUBJECT column must be INT64 or TEXT");
            subj = i;
        }
    }
    if (!nflag) return imdb_fail(e, IMDB_ERR_INVALID, "table needs a PRIMARY KEY column (or PRIMARY KEY (a, b, ...))");
    if (s->npk < 1 || s->npk > IMDB_MAX_KEY_COLS)
        return imdb_fail(e, IMDB_ERR_LIMIT, "a PRIMARY KEY of 1..%u columns", IMDB_MAX_KEY_COLS);
    /* the key list and the flags name one set: each listed column flagged, once, and as many as are flagged */
    for (int k = 0; k < s->npk; k++) {
        if (s->key[k] >= s->ncols || !(s->cols[s->key[k]].flags & IMDB_COL_PK))
            return imdb_fail(e, IMDB_ERR_INVALID, "schema key indexes inconsistent");
        for (int j = 0; j < k; j++)
            if (s->key[j] == s->key[k]) return imdb_fail(e, IMDB_ERR_INVALID, "schema key indexes inconsistent");
    }
    for (int k = s->npk; k < (int)IMDB_MAX_KEY_COLS; k++) /* zero past the key: a schema is compared and copied whole */
        if (s->key[k]) return imdb_fail(e, IMDB_ERR_INVALID, "schema key indexes inconsistent");
    if (nflag != s->npk || s->subject != subj) return imdb_fail(e, IMDB_ERR_INVALID, "schema key indexes inconsistent");
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
        imdb_buf_put_u8(b, c->type == IMDB_T_TEXT ? (uint8_t)(c->vlen & 0xff) : c->precision); /* F3c: a VARCHAR's length */
        imdb_buf_put_u8(b, c->type == IMDB_T_TEXT ? (uint8_t)(c->vlen >> 8) : c->scale);
        imdb_buf_put_u8(b, c->flags);
    }
    /* the key, in key order (the format design's slice 1; F4: up to IMDB_MAX_KEY_COLS columns; each keeps its flag) */
    imdb_buf_put_u8(b, s->npk);
    for (int k = 0; k < s->npk; k++) imdb_buf_put_u16(b, s->key[k]);
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
        if (c->type == IMDB_T_TEXT) { /* F3c: the two bytes a VARCHAR's length; a TEXT's precision and scale 0 */
            c->vlen = (uint16_t)(c->precision | c->scale << 8);
            c->precision = c->scale = 0;
        }
        if (c->flags & IMDB_COL_SUBJECT) s->subject = (int16_t)i;
    }
    s->npk = imdb_rd_u8(r); /* the key list, in key order: the schema check wants it and the flags to agree */
    if (!r->err && (s->npk < 1 || s->npk > IMDB_MAX_KEY_COLS))
        return imdb_fail(e, IMDB_ERR_CORRUPT, "schema: a key of %u columns", s->npk);
    for (int k = 0; k < s->npk && !r->err; k++) s->key[k] = imdb_rd_u16(r);
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

#define Q18 ((__int128)1000000000000000000LL)
__int128 imdb_pow10_128(int n)
{
    static const __int128 p[IMDB_DEC_MAX_DIGITS + 1] = { /* constant expressions: no table made at run time */
        1LL, 10LL, 100LL, 1000LL, 10000LL, 100000LL, 1000000LL, 10000000LL, 100000000LL, 1000000000LL,
        10000000000LL, 100000000000LL, 1000000000000LL, 10000000000000LL, 100000000000000LL, 1000000000000000LL,
        10000000000000000LL, 100000000000000000LL, 1000000000000000000LL,
        Q18 * 10LL, Q18 * 100LL, Q18 * 1000LL, Q18 * 10000LL, Q18 * 100000LL, Q18 * 1000000LL, Q18 * 10000000LL,
        Q18 * 100000000LL, Q18 * 1000000000LL, Q18 * 10000000000LL, Q18 * 100000000000LL, Q18 * 1000000000000LL,
        Q18 * 10000000000000LL, Q18 * 100000000000000LL, Q18 * 1000000000000000LL, Q18 * 10000000000000000LL,
        Q18 * 100000000000000000LL, Q18 * Q18, Q18 * Q18 * 10, Q18 * Q18 * 100};
    return (n >= 0 && n <= IMDB_DEC_MAX_DIGITS) ? p[n] : 0;
}
#undef Q18

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
    case IMDB_T_INT64: /* F3a: SMALLINT's and INTEGER's ranges, the values INT64 everywhere else */
        if (!imdb_int_fits(c->precision, v->i))
            return imdb_fail(e, IMDB_ERR_LIMIT, "column %s: a value out of %s's range", c->name, imdb_int_name(c->precision));
        return IMDB_OK;
    case IMDB_T_DECIMAL: {
        if (v->scale != c->scale) return imdb_fail(e, IMDB_ERR_INVALID, "column %s: decimal scale mismatch", c->name);
        /* F3e: the form is the column's, never the value's: a narrow value in a wide column (or the reverse), and a
         * narrow value's hi, refused; the bound 10^p - 1 from the one 128-bit table */
        if (v->wide != imdb_dec_wide(c->precision) || (!v->wide && v->hi))
            return imdb_fail(e, IMDB_ERR_INVALID, "column %s: a DECIMAL value of another width than DECIMAL(%u,%u)'s", c->name,
                             c->precision, c->scale);
        __int128 lim = imdb_pow10_128(c->precision) - 1, x = imdb_dec_value(v);
        if (x > lim || x < -lim)
            return imdb_fail(e, IMDB_ERR_LIMIT, "column %s: value exceeds DECIMAL(%u,%u)", c->name, c->precision, c->scale);
        return IMDB_OK;
    }
    case IMDB_T_BOOL:
        if (v->i != 0 && v->i != 1) return imdb_fail(e, IMDB_ERR_INVALID, "column %s: bad BOOL", c->name);
        return IMDB_OK;
    case IMDB_T_TIMESTAMP:
    case IMDB_T_TIMESTAMPTZ:
        if (v->i < TS_MIN || v->i > TS_MAX)
            return imdb_fail(e, IMDB_ERR_LIMIT, "column %s: timestamp out of range", c->name);
        return IMDB_OK;
    case IMDB_T_DATE: /* F3b: TIMESTAMP's years, so a cast between them never fails */
        if (v->i < IMDB_DATE_MIN || v->i > IMDB_DATE_MAX) return imdb_fail(e, IMDB_ERR_LIMIT, "column %s: date out of range", c->name);
        return IMDB_OK;
    case IMDB_T_TIME:
        if (v->i < 0 || v->i > IMDB_TIME_MAX) return imdb_fail(e, IMDB_ERR_LIMIT, "column %s: time out of range", c->name);
        return IMDB_OK;
    case IMDB_T_FLOAT64:
        if (!imdb_f64_key_valid(v->i)) return imdb_fail(e, IMDB_ERR_INVALID, "column %s: not a finite FLOAT64", c->name);
        return IMDB_OK;
    case IMDB_T_TEXT: {
        if (v->len > IMDB_MAX_TEXT) return imdb_fail(e, IMDB_ERR_LIMIT, "column %s: TEXT longer than %u bytes", c->name, IMDB_MAX_TEXT);
        size_t bad;
        if (v->len && !imdb_utf8_valid(v->s, v->len, &bad))
            return imdb_fail(e, IMDB_ERR_INVALID, "column %s: invalid UTF-8 at byte %zu", c->name, bad);
        if (imdb_text_max(c) && imdb_utf8_chars(v->s, v->len) > imdb_text_max(c)) /* F3c: characters, not bytes */
            return imdb_fail(e, IMDB_ERR_LIMIT, "column %s: a value longer than VARCHAR(%u)", c->name, imdb_text_max(c));
        return IMDB_OK;
    }
    case IMDB_T_UUID: /* F3d: 16 bytes always */
        if (v->len != IMDB_UUID_LEN || !v->s) return imdb_fail(e, IMDB_ERR_INVALID, "column %s: a UUID is 16 bytes", c->name);
        return IMDB_OK;
    case IMDB_T_BYTEA: /* F3d: any bytes, TEXT's bound */
        if (v->len > IMDB_MAX_TEXT) return imdb_fail(e, IMDB_ERR_LIMIT, "column %s: BYTEA longer than %u bytes", c->name, IMDB_MAX_TEXT);
        if (v->len && !v->s) return imdb_fail(e, IMDB_ERR_INVALID, "column %s: a BYTEA without its bytes", c->name);
        return IMDB_OK;
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
    return type == IMDB_T_TEXT || type == IMDB_T_BYTEA ? 4 + (size_t)v->len : type == IMDB_T_UUID ? IMDB_UUID_LEN : type == IMDB_T_BOOL ? 1
         : type == IMDB_T_DECIMAL && v->wide ? 16 : 8; /* F3e: a wide DECIMAL (its form checked to be its column's) */
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
        case IMDB_T_BYTEA:
            imdb_buf_put_u32(out, v->len);
            imdb_buf_put(out, v->s, v->len);
            break;
        case IMDB_T_UUID: imdb_buf_put(out, v->s, IMDB_UUID_LEN); break; /* F3d: no length: 16 always */
        case IMDB_T_BOOL: imdb_buf_put_u8(out, (uint8_t)v->i); break;
        case IMDB_T_DECIMAL: /* F3e: a wide one i then hi (imdb_value_check made the form the column's) */
            imdb_buf_put_u64(out, (uint64_t)v->i);
            if (v->wide) imdb_buf_put_u64(out, (uint64_t)v->hi);
            break;
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
        case IMDB_T_BYTEA:
            v->len = imdb_rd_u32(&r);
            if (v->len > IMDB_MAX_TEXT) return imdb_fail(e, IMDB_ERR_CORRUPT, "row: %s length out of range", imdb_type_name(c->type));
            v->s = imdb_rd_bytes(&r, v->len);
            if (!v->s) return imdb_fail(e, IMDB_ERR_CORRUPT, "row: truncated %s", imdb_type_name(c->type));
            break;
        case IMDB_T_UUID:
            v->len = IMDB_UUID_LEN;
            v->s = imdb_rd_bytes(&r, IMDB_UUID_LEN);
            if (!v->s) return imdb_fail(e, IMDB_ERR_CORRUPT, "row: truncated UUID");
            break;
        case IMDB_T_BOOL: v->i = imdb_rd_u8(&r); break;
        case IMDB_T_DECIMAL: /* F3e: the column's precision decides the form */
            v->i = (int64_t)imdb_rd_u64(&r);
            if ((v->wide = imdb_dec_wide(c->precision))) v->hi = (int64_t)imdb_rd_u64(&r);
            break;
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
            if (t == IMDB_T_TEXT || t == IMDB_T_BYTEA) {
                uint32_t n = imdb_rd_u32(&r);
                (void)imdb_rd_bytes(&r, n);
            } else {
                (void)imdb_rd_bytes(&r, t == IMDB_T_BOOL ? 1 : t == IMDB_T_UUID ? IMDB_UUID_LEN
                                      : t == IMDB_T_DECIMAL && imdb_dec_wide(c->precision) ? 16 : 8);
            }
            continue;
        }
        v->type = t;
        v->scale = c->scale;
        if (isnull) {
            v->null = true;
        } else if (t == IMDB_T_TEXT || t == IMDB_T_BYTEA) {
            v->len = imdb_rd_u32(&r);
            v->s = imdb_rd_bytes(&r, v->len);
            if (!v->s) v->len = 0;
        } else if (t == IMDB_T_UUID) {
            v->s = imdb_rd_bytes(&r, IMDB_UUID_LEN);
            v->len = v->s ? IMDB_UUID_LEN : 0;
        } else if (t == IMDB_T_BOOL) {
            v->i = imdb_rd_u8(&r);
        } else if (t == IMDB_T_DECIMAL && imdb_dec_wide(c->precision)) { /* F3e */
            v->wide = true;
            v->i = (int64_t)imdb_rd_u64(&r);
            v->hi = (int64_t)imdb_rd_u64(&r);
        } else {
            v->i = (int64_t)imdb_rd_u64(&r);
        }
    }
}

int imdb_value_cmp(const imdb_value *a, const imdb_value *b)
{
    if (a->null || b->null) return a->null == b->null ? 0 : a->null ? 1 : -1; /* NULLS LAST */
    if (imdb_type_bytes(a->type)) { /* F3d: TEXT, UUID and BYTEA alike: memcmp, then the shorter first */
        uint32_t n = a->len < b->len ? a->len : b->len;
        int c = n ? memcmp(a->s, b->s, n) : 0;
        if (c) return c < 0 ? -1 : 1;
        return a->len < b->len ? -1 : a->len > b->len;
    }
    if (a->type == IMDB_T_DECIMAL) { /* F3e: either form, by the 128-bit value */
        __int128 x = imdb_dec_value(a), y = imdb_dec_value(b);
        return x < y ? -1 : x > y;
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
    if (imdb_type_bytes(v->type)) return imdb_siphash24(v->s, v->len, seed, 0x9e3779b97f4a7c15ull);
    if (v->type == IMDB_T_DECIMAL) { /* F3e: the 128-bit value, a narrow one sign-extended: equal numbers meet */
        uint8_t t[16];
        unsigned __int128 x = (unsigned __int128)imdb_dec_value(v);
        imdb_le64(t, (uint64_t)x);
        imdb_le64(t + 8, (uint64_t)(x >> 64));
        return imdb_siphash24(t, 16, seed, 0x9e3779b97f4a7c15ull);
    }
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
    __int128 v;
    if (precision > IMDB_DEC_NARROW_DIGITS) return imdb_fail(e, IMDB_ERR_INVALID, "decimal literal: a precision past 18");
    if (imdb_parse_decimal128(s, n, precision, scale, &v, e)) return e->code;
    *out = (int64_t)v; /* at most 18 digits */
    return IMDB_OK;
}

int imdb_parse_decimal_col(const char *s, size_t n, const imdb_column *c, imdb_value *v, imdb_err *e)
{
    __int128 x;
    if (imdb_parse_decimal128(s, n, c->precision, c->scale, &x, e)) return e->code;
    memset(v, 0, sizeof *v);
    v->type = IMDB_T_DECIMAL;
    v->scale = c->scale;
    imdb_dec_set(v, x, imdb_dec_wide(c->precision));
    return IMDB_OK;
}

int imdb_parse_decimal128(const char *s, size_t n, int precision, int scale, __int128 *out, imdb_err *e)
{
    if (precision < 1 || precision > IMDB_DEC_MAX_DIGITS || scale < 0 || scale > precision)
        return imdb_fail(e, IMDB_ERR_INVALID, "decimal literal: DECIMAL(%d,%d) is no type", precision, scale);
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
    __int128 v = 0; /* at most precision digits: below 10^38, inside an int128 */
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

int64_t imdb_days_from_civil(int64_t y, int m, int d) { return days_from_civil(y, m, d); }
void imdb_civil_from_days(int64_t z, int64_t *y, int *m, int *d) { civil_from_days(z, y, m, d); }

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

/* a TIMESTAMP's text from s's start, its shape alone: the date, then a time after ' ' or 'T' (a digit next), then a
 * fraction; *end where it stops (a zone part, a Z, or the end) */
typedef struct dt_fields {
    int64_t Y, M, D, h, mi, se, us;
} dt_fields;

static int scan_dt(const char *s, size_t n, size_t *end, dt_fields *f, const char *shape, imdb_err *e)
{
    memset(f, 0, sizeof *f);
    if (!digits(s, n, 0, 4, &f->Y) || n < 10 || s[4] != '-' || !digits(s, n, 5, 2, &f->M) || s[7] != '-' ||
        !digits(s, n, 8, 2, &f->D))
        return imdb_fail(e, IMDB_ERR_INVALID, "%s", shape);
    size_t i = 10;
    if (i < n && (s[i] == ' ' || s[i] == 'T') && i + 1 < n && s[i + 1] >= '0' && s[i + 1] <= '9') {
        if (!digits(s, n, i + 1, 2, &f->h) || i + 3 >= n || s[i + 3] != ':' || !digits(s, n, i + 4, 2, &f->mi) ||
            i + 6 >= n || s[i + 6] != ':' || !digits(s, n, i + 7, 2, &f->se))
            return imdb_fail(e, IMDB_ERR_INVALID, "%s", shape);
        i += 9;
        if (i < n && s[i] == '.') {
            size_t f0 = ++i;
            while (i < n && s[i] >= '0' && s[i] <= '9') i++;
            size_t fd = i - f0;
            if (fd < 1 || fd > 6) return imdb_fail(e, IMDB_ERR_INVALID, "timestamp fraction must have 1..6 digits");
            int64_t fr;
            digits(s, n, f0, fd, &fr);
            for (size_t k = fd; k < 6; k++) fr *= 10;
            f->us = fr;
        }
    } else if (i < n && s[i] == 'T') {
        return imdb_fail(e, IMDB_ERR_INVALID, "%s", shape);
    }
    *end = i;
    return IMDB_OK;
}

static int dt_value(const dt_fields *f, int64_t *out, imdb_err *e)
{
    if (f->Y < 1 || f->M < 1 || f->M > 12 || f->D < 1 || f->D > days_in_month(f->Y, (int)f->M) || f->h > 23 || f->mi > 59 ||
        f->se > 59)
        return imdb_fail(e, IMDB_ERR_INVALID, "timestamp field out of range");
    int64_t days = days_from_civil(f->Y, (int)f->M, (int)f->D);
    *out = ((days * 86400 + f->h * 3600 + f->mi * 60 + f->se) * 1000000) + f->us;
    return IMDB_OK;
}

#define TS_SHAPE "timestamp must look like 'YYYY-MM-DD HH:MM:SS[.ffffff]' (UTC)"
#define TSTZ_SHAPE "a TIMESTAMPTZ must look like 'YYYY-MM-DD HH:MM:SS[.ffffff]' with an offset (+HH:MM, Z), a zone's name or neither"

int imdb_parse_timestamp(const char *s, size_t n, int64_t *out, imdb_err *e)
{
    dt_fields f;
    size_t i;
    if (n > 32) return imdb_fail(e, IMDB_ERR_INVALID, TS_SHAPE);
    if (scan_dt(s, n, &i, &f, TS_SHAPE, e)) return e->code;
    if (i < n && i > 10 && s[i] == 'Z') i++;
    if (i < n && i == 10) return imdb_fail(e, IMDB_ERR_INVALID, TS_SHAPE);
    if (i != n) return imdb_fail(e, IMDB_ERR_INVALID, "timestamp: only UTC is supported (no offsets)");
    return dt_value(&f, out, e);
}

/* F3b: a DATE's text is exactly 'YYYY-MM-DD'; a TIME's 'HH:MM:SS', then '.' and 1 to 6 digits (24:00:00, which
 * PostgreSQL takes, is refused: the standard's and SQL Server's range ends at 23:59:59.999999) */
#define DATE_SHAPE "a DATE must look like 'YYYY-MM-DD'"
#define TIME_SHAPE "a TIME must look like 'HH:MM:SS[.ffffff]'"

int imdb_parse_date(const char *s, size_t n, int64_t *out, imdb_err *e)
{
    int64_t Y, M, D;
    if (n != 10 || !digits(s, n, 0, 4, &Y) || s[4] != '-' || !digits(s, n, 5, 2, &M) || s[7] != '-' || !digits(s, n, 8, 2, &D))
        return imdb_fail(e, IMDB_ERR_INVALID, DATE_SHAPE);
    if (Y < 1 || M < 1 || M > 12 || D < 1 || D > days_in_month(Y, (int)M)) return imdb_fail(e, IMDB_ERR_INVALID, "date field out of range");
    *out = days_from_civil(Y, (int)M, (int)D);
    return IMDB_OK;
}

int imdb_parse_time(const char *s, size_t n, int64_t *out, imdb_err *e)
{
    int64_t h, mi, se, fr = 0;
    if (n < 8 || n > 15 || !digits(s, n, 0, 2, &h) || s[2] != ':' || !digits(s, n, 3, 2, &mi) || s[5] != ':' ||
        !digits(s, n, 6, 2, &se))
        return imdb_fail(e, IMDB_ERR_INVALID, TIME_SHAPE);
    if (n > 8) {
        size_t fd = n - 9;
        if (s[8] != '.' || fd < 1 || !digits(s, n, 9, fd, &fr)) return imdb_fail(e, IMDB_ERR_INVALID, TIME_SHAPE);
        for (size_t k = fd; k < 6; k++) fr *= 10;
    }
    if (h > 23 || mi > 59 || se > 59) return imdb_fail(e, IMDB_ERR_INVALID, "time field out of range");
    *out = (h * 3600 + mi * 60 + se) * 1000000 + fr;
    return IMDB_OK;
}

int imdb_parse_timestamptz(const char *s, size_t n, imdb_tzlit *o, imdb_err *e)
{
    memset(o, 0, sizeof *o);
    dt_fields f;
    size_t i;
    if (n > 32 + 1 + IMDB_MAX_TZ_NAME) return imdb_fail(e, IMDB_ERR_INVALID, TSTZ_SHAPE);
    if (scan_dt(s, n, &i, &f, TSTZ_SHAPE, e)) return e->code;
    if (i < n && s[i] == 'Z') {
        o->has_off = true;
        i++;
    } else if (i < n) {
        size_t j = i + (s[i] == ' ' && i + 1 < n && (s[i + 1] == '+' || s[i + 1] == '-'));
        if (s[j] == '+' || s[j] == '-') {
            int sign = s[j] == '-' ? -1 : 1;
            int64_t hh, mm = 0, ss = 0;
            j++;
            if (!digits(s, n, j, 2, &hh)) return imdb_fail(e, IMDB_ERR_INVALID, TSTZ_SHAPE);
            j += 2;
            if (j < n) {
                bool colon = s[j] == ':';
                j += colon;
                if (!digits(s, n, j, 2, &mm)) return imdb_fail(e, IMDB_ERR_INVALID, TSTZ_SHAPE);
                j += 2;
                if (j < n) { /* seconds only after colons: +HH:MM:SS */
                    if (!colon || s[j] != ':' || !digits(s, n, j + 1, 2, &ss)) return imdb_fail(e, IMDB_ERR_INVALID, TSTZ_SHAPE);
                    j += 3;
                }
            }
            if (mm > 59 || ss > 59 || hh * 3600 + mm * 60 + ss > 15 * 3600 + 59 * 60 + 59)
                return imdb_fail(e, IMDB_ERR_INVALID, "a TIMESTAMPTZ offset of at most 15:59:59");
            o->has_off = true;
            o->off = (int32_t)(sign * (hh * 3600 + mm * 60 + ss));
            i = j;
        } else if (s[i] == ' ' && i + 1 < n) { /* the rest a zone's name, for the caller to look up */
            o->zoff = (uint32_t)(i + 1);
            o->zlen = (uint32_t)(n - i - 1);
            i = n;
        }
    }
    if (i != n) return imdb_fail(e, IMDB_ERR_INVALID, TSTZ_SHAPE);
    return dt_value(&f, &o->local, e);
}

/* v's decimal digits, written right to left ending at end (the zone slice's speed step: printf's machinery was most of
 * a row's output); the count */
static size_t udigits(uint64_t v, char *end)
{
    char *p = end;
    do {
        *--p = (char)('0' + (int)(v % 10));
        v /= 10;
    } while (v);
    return (size_t)(end - p);
}

/* printf's %0*lld: a '-' then digits zero-padded to width in all; written ending at end, the count */
static size_t pad_digits(int64_t v, int width, char *end)
{
    uint64_t u = v < 0 ? (uint64_t)0 - (uint64_t)v : (uint64_t)v;
    char *p = end - udigits(u, end);
    for (int dw = width - (v < 0); end - p < dw;) *--p = '0';
    if (v < 0) *--p = '-';
    return (size_t)(end - p);
}

void imdb_format_int64(int64_t v, imdb_buf *out)
{
    char b[24];
    size_t n = pad_digits(v, 1, b + sizeof b);
    imdb_buf_put(out, b + sizeof b - n, n);
}

/* the text "%04lld-%02d-%02d %02lld:%02lld:%02lld" and ".%06lld" when microseconds remain made, byte for byte,
 * without printf */
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
    char b[64], *e = b + sizeof b, *p = e;
    if (us) {
        p -= pad_digits(us, 6, p);
        *--p = '.';
    }
    p -= pad_digits(secs % 60, 2, p);
    *--p = ':';
    p -= pad_digits(secs / 60 % 60, 2, p);
    *--p = ':';
    p -= pad_digits(secs / 3600, 2, p);
    *--p = ' ';
    p -= pad_digits(d, 2, p);
    *--p = '-';
    p -= pad_digits(m, 2, p);
    *--p = '-';
    p -= pad_digits(y, 4, p);
    imdb_buf_put(out, p, (size_t)(e - p));
}

/* F3b: 'YYYY-MM-DD', the date part of a TIMESTAMP's text */
void imdb_format_date(int64_t days, imdb_buf *out)
{
    int64_t y;
    int m, d;
    civil_from_days(days, &y, &m, &d);
    char b[16], *e = b + sizeof b, *p = e;
    p -= pad_digits(d, 2, p);
    *--p = '-';
    p -= pad_digits(m, 2, p);
    *--p = '-';
    p -= pad_digits(y, 4, p);
    imdb_buf_put(out, p, (size_t)(e - p));
}

/* F3b: 'HH:MM:SS', and '.ffffff' when microseconds remain (a TIMESTAMP's time part, its rule) */
void imdb_format_time(int64_t us, imdb_buf *out)
{
    int64_t secs = us / 1000000, f = us % 1000000;
    char b[24], *e = b + sizeof b, *p = e;
    if (f) {
        p -= pad_digits(f, 6, p);
        *--p = '.';
    }
    p -= pad_digits(secs % 60, 2, p);
    *--p = ':';
    p -= pad_digits(secs / 60 % 60, 2, p);
    *--p = ':';
    p -= pad_digits(secs / 3600, 2, p);
    imdb_buf_put(out, p, (size_t)(e - p));
}


/* ---- F3d: UUID and BYTEA text forms ---- */

static int hexval(char c)
{
    return c >= '0' && c <= '9' ? c - '0' : c >= 'a' && c <= 'f' ? c - 'a' + 10 : c >= 'A' && c <= 'F' ? c - 'A' + 10 : -1;
}

int imdb_parse_uuid(const char *s, size_t n, uint8_t out[IMDB_UUID_LEN], imdb_err *e)
{
    bool hyph = n == 36; /* 8-4-4-4-12, or 32 digits alone: one family (braces and other hyphens refused) */
    if (n != 36 && n != 32) return imdb_fail(e, IMDB_ERR_INVALID, "a UUID is 32 hex digits, hyphenated 8-4-4-4-12 or not");
    size_t at = 0;
    for (int k = 0; k < IMDB_UUID_LEN; k++) {
        if (hyph && (k == 4 || k == 6 || k == 8 || k == 10)) {
            if (s[at] != '-') return imdb_fail(e, IMDB_ERR_INVALID, "a UUID is 32 hex digits, hyphenated 8-4-4-4-12 or not");
            at++;
        }
        int h = hexval(s[at]), l = hexval(s[at + 1]);
        if (h < 0 || l < 0) return imdb_fail(e, IMDB_ERR_INVALID, "a UUID is 32 hex digits, hyphenated 8-4-4-4-12 or not");
        out[k] = (uint8_t)(h << 4 | l);
        at += 2;
    }
    return IMDB_OK;
}

int imdb_parse_bytea(const char *s, size_t n, uint8_t *out, size_t cap, size_t *outlen, imdb_err *e)
{
    if (n < 2 || s[0] != '\\' || s[1] != 'x')
        return imdb_fail(e, IMDB_ERR_INVALID, "a BYTEA is written \\x and two hex digits a byte (the escape form is refused)");
    if ((n - 2) % 2) return imdb_fail(e, IMDB_ERR_INVALID, "a BYTEA's hex form has an odd number of digits");
    size_t m = (n - 2) / 2;
    if (m > IMDB_MAX_TEXT) return imdb_fail(e, IMDB_ERR_LIMIT, "BYTEA longer than %u bytes", IMDB_MAX_TEXT);
    if (m > cap) return imdb_fail(e, IMDB_ERR_LIMIT, "BYTEA longer than its buffer");
    for (size_t k = 0; k < m; k++) {
        int h = hexval(s[2 + 2 * k]), l = hexval(s[3 + 2 * k]);
        if (h < 0 || l < 0) return imdb_fail(e, IMDB_ERR_INVALID, "a BYTEA's hex form holds a character that is no hex digit");
        out[k] = (uint8_t)(h << 4 | l);
    }
    *outlen = m;
    return IMDB_OK;
}

void imdb_format_uuid(const uint8_t *b, imdb_buf *out)
{
    static const char hx[] = "0123456789abcdef";
    char t[36];
    size_t o = 0;
    for (int k = 0; k < IMDB_UUID_LEN; k++) {
        if (k == 4 || k == 6 || k == 8 || k == 10) t[o++] = '-';
        t[o++] = hx[b[k] >> 4];
        t[o++] = hx[b[k] & 15];
    }
    imdb_buf_put(out, t, sizeof t);
}

void imdb_format_bytea(const uint8_t *b, size_t n, imdb_buf *out)
{
    static const char hx[] = "0123456789abcdef";
    imdb_buf_put_str(out, "\\x");
    char t[128];
    size_t o = 0;
    for (size_t k = 0; k < n; k++) {
        t[o++] = hx[b[k] >> 4];
        t[o++] = hx[b[k] & 15];
        if (o == sizeof t) {
            imdb_buf_put(out, t, o);
            o = 0;
        }
    }
    if (o) imdb_buf_put(out, t, o);
}
void imdb_format_timestamptz(int64_t utc_us, int32_t off, imdb_buf *out)
{
    imdb_format_timestamp(utc_us + (int64_t)off * 1000000, out);
    uint32_t a = off < 0 ? (uint32_t)0 - (uint32_t)off : (uint32_t)off;
    char b[12], *p = b;
    *p++ = off < 0 ? '-' : '+';
    *p++ = (char)('0' + a / 36000), *p++ = (char)('0' + a / 3600 % 10);
    if (a % 3600) {
        *p++ = ':', *p++ = (char)('0' + a / 60 % 60 / 10), *p++ = (char)('0' + a / 60 % 10);
        if (a % 60) *p++ = ':', *p++ = (char)('0' + a % 60 / 10), *p++ = (char)('0' + a % 10);
    }
    imdb_buf_put(out, b, (size_t)(p - b));
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
    while (mag >> 64) { /* a SUM's width: __int128's division; then 64-bit, the same digits (the speed step) */
        tmp[n++] = (char)('0' + (int)(mag % 10));
        mag /= 10;
    }
    uint64_t m64 = (uint64_t)mag;
    do {
        tmp[n++] = (char)('0' + (int)(m64 % 10));
        m64 /= 10;
    } while (m64 || n <= scale);
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
    case IMDB_T_INT64: imdb_format_int64(v->i, out); break;
    case IMDB_T_DECIMAL: imdb_format_i128(imdb_dec_value(v), v->scale, out); break; /* F3e: either form */
    case IMDB_T_BOOL: imdb_buf_put_str(out, v->i ? "true" : "false"); break;
    case IMDB_T_TIMESTAMP: imdb_format_timestamp(v->i, out); break;
    case IMDB_T_DATE: imdb_format_date(v->i, out); break;
    case IMDB_T_TIME: imdb_format_time(v->i, out); break;
    case IMDB_T_TIMESTAMPTZ: imdb_format_timestamptz(v->i, 0, out); break; /* no zone here: UTC (the renderer has its cell's offset) */
    case IMDB_T_FLOAT64: imdb_format_float64(v->i, out); break;
    case IMDB_T_TEXT: imdb_buf_put(out, v->s, v->len); break;
    case IMDB_T_UUID: imdb_format_uuid(v->s, out); break;
    case IMDB_T_BYTEA: imdb_format_bytea(v->s, v->len, out); break;
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

/* ---- the primary key's encoding (F4) ------------------------------------------------ */

/* An INT64-like value's 8 bytes, big-endian with the sign bit flipped: unsigned order is signed order */
static void key_put_i64(uint8_t *p, int64_t v)
{
    uint64_t u = (uint64_t)v ^ (1ull << 63);
    for (int i = 7; i >= 0; i--) {
        p[i] = (uint8_t)u;
        u >>= 8;
    }
}

size_t imdb_key_len(const imdb_schema *s, const imdb_value *kv)
{
    size_t n = 0;
    for (int k = 0; k < s->npk; k++) {
        const imdb_value *v = &kv[k];
        if (v->type == IMDB_T_BOOL) {
            n += 1;
        } else if (v->type == IMDB_T_UUID) { /* F3d: its 16 bytes, fixed: memcmp order */
            n += IMDB_UUID_LEN;
        } else if (v->type == IMDB_T_TEXT || v->type == IMDB_T_BYTEA) {
            n += 2; /* the terminator */
            for (uint32_t i = 0; i < v->len; i++) n += v->s[i] == 0 ? 2 : 1;
        } else if (v->type == IMDB_T_DECIMAL && imdb_dec_wide(s->cols[s->key[k]].precision)) {
            n += 16; /* F3e: by the column's precision, whatever form the value came in */
        } else {
            n += 8;
        }
    }
    return n;
}

void imdb_key_write(const imdb_schema *s, const imdb_value *kv, uint8_t *out)
{
    size_t o = 0;
    for (int k = 0; k < s->npk; k++) {
        const imdb_value *v = &kv[k];
        if (v->type == IMDB_T_BOOL) {
            out[o++] = (uint8_t)(v->i != 0);
        } else if (v->type == IMDB_T_UUID) {
            memcpy(out + o, v->s, IMDB_UUID_LEN);
            o += IMDB_UUID_LEN;
        } else if (v->type == IMDB_T_TEXT || v->type == IMDB_T_BYTEA) { /* 0x00 written 0x00 0xFF, then 0x00 0x00: a prefix sorts first */
            for (uint32_t i = 0; i < v->len; i++) {
                out[o++] = (uint8_t)v->s[i];
                if (v->s[i] == 0) out[o++] = 0xFF;
            }
            out[o++] = 0;
            out[o++] = 0;
        } else if (v->type == IMDB_T_DECIMAL && imdb_dec_wide(s->cols[s->key[k]].precision)) {
            /* F3e: 16 bytes big-endian, the sign bit flipped: the high half as an INT64-like word, the low half
             * unsigned after it, so memcmp order is numeric order */
            unsigned __int128 x = (unsigned __int128)imdb_dec_value(v);
            key_put_i64(out + o, (int64_t)(uint64_t)(x >> 64));
            uint64_t lo = (uint64_t)x;
            for (int i = 15; i >= 8; i--) {
                out[o + i] = (uint8_t)lo;
                lo >>= 8;
            }
            o += 16;
        } else {
            key_put_i64(out + o, v->type == IMDB_T_DECIMAL ? (int64_t)imdb_dec_value(v) : v->i);
            o += 8;
        }
    }
}

/* F3d: gen_random_uuid's value: 122 random bits from the engine's source (imdb_random), version 4 in the high nibble of
 * byte 6 and RFC 9562's variant (10) in the top bits of byte 8 */
int imdb_uuid_v4(uint8_t out[IMDB_UUID_LEN], imdb_err *e)
{
    if (imdb_random(out, IMDB_UUID_LEN, e)) return e->code;
    out[6] = (uint8_t)((out[6] & 0x0F) | 0x40);
    out[8] = (uint8_t)((out[8] & 0x3F) | 0x80);
    return IMDB_OK;
}
