/* sql_expr.c (1b): any two values within the evaluator's bounds and any operation are computed or refused, never
 * undefined behaviour (this build traps signed overflow: no -fno-strict-overflow), every result within its own bounds
 * (an INT64 inside int64, a DECIMAL under 10^38 at the bound scale, a FLOAT64 finite), comparisons antisymmetric and
 * reflexive, an assignment checked like any value, and a DECIMAL literal's parse total; P2 S1: every function, CAST
 * and LIKE (against a reference matcher) on them and on two texts from the tail. */
#include <math.h>

#include "../src/sql_internal.h"
#include "fuzz_common.h"

static const __int128 P38 = (__int128)10000000000000000000ull * 10000000000000000000ull; /* 10^38 */

/* the value at p (16 bytes) of type t (an INT64 within 2^103, a SUM's bound; a DECIMAL under 10^38, scale <= 38) */
static void value(uint8_t t, uint8_t s, const uint8_t *p, imdb_xval *v)
{
    static const uint8_t T[] = {IMDB_T_INT64, IMDB_T_DECIMAL, IMDB_T_FLOAT64, IMDB_T_TEXT};
    memset(v, 0, sizeof *v);
    v->type = T[t % 4];
    v->null = (t & 0x80) != 0;
    __int128 x;
    memcpy(&x, p, sizeof x);
    if (v->type == IMDB_T_INT64) {
        int64_t i;
        memcpy(&i, p, sizeof i);
        v->i = (t & 0x40) ? x % ((__int128)1 << 103) : i; /* sometimes a SUM's width */
    } else if (v->type == IMDB_T_DECIMAL) {
        v->scale = (uint8_t)(s % (IMDB_X_MAX_SCALE + 1));
        v->i = x % P38;
    } else if (v->type == IMDB_T_FLOAT64) {
        double d;
        memcpy(&d, p, sizeof d);
        v->f = isfinite(d) ? d : 0;
    } else {
        v->s = p;
        v->len = 16;
    }
}

static void bounds(const imdb_xval *r, uint8_t rt, uint8_t rs)
{
    if (r->type != rt || (rt == IMDB_T_DECIMAL && r->scale != rs)) abort();
    if (r->null) return;
    if (rt == IMDB_T_INT64 && (r->i < INT64_MIN || r->i > INT64_MAX)) abort();
    if (rt == IMDB_T_DECIMAL && (r->i >= P38 || r->i <= -P38)) abort();
    if (rt == IMDB_T_FLOAT64 && !isfinite(r->f)) abort();
}

/* ---- P2 S1: the functions, CAST and LIKE ------------------------------------------------------------------------- */

static bool text_ok(const imdb_xval *v)
{
    size_t bad;
    return v->null || (v->len <= IMDB_MAX_TEXT && imdb_utf8_valid(v->s, v->len, &bad) && !memchr(v->s, 0, v->len));
}

/* a text's characters (at most 64: else -1) */
static int chars(const uint8_t *s, uint32_t n, uint32_t *cp)
{
    int k = 0;
    for (uint32_t i = 0; i < n; k++) {
        if (k == 64) return -1;
        uint8_t c = s[i];
        uint32_t l = c < 0x80 ? 1 : c < 0xE0 ? 2 : c < 0xF0 ? 3 : 4, v = l == 1 ? c : l == 2 ? c & 0x1Fu : l == 3 ? c & 0x0Fu : c & 0x07u;
        for (uint32_t j = 1; j < l; j++) v = v << 6 | (s[i + j] & 0x3Fu);
        cp[k] = v;
        i += l;
    }
    return k;
}

/* the reference LIKE: the pattern's items (escape first, then % and _), matched by dynamic programming over (text
 * position, item); -1 when the pattern ends in its escape */
static int ref_like(const uint32_t *s, int n, const uint32_t *p, int m, uint32_t esc)
{
    uint32_t it[64];
    int kind[64], k = 0; /* 0 a literal, 1 _, 2 % */
    for (int j = 0; j < m; j++) {
        if (esc && p[j] == esc) {
            if (j + 1 >= m) return -1;
            it[k] = p[++j];
            kind[k++] = 0;
        } else {
            it[k] = p[j];
            kind[k++] = p[j] == '%' ? 2 : p[j] == '_' ? 1 : 0;
        }
    }
    bool dp[65][65];
    for (int i = 0; i <= n; i++) dp[i][k] = i == n;
    for (int j = k - 1; j >= 0; j--)
        for (int i = n; i >= 0; i--)
            dp[i][j] = kind[j] == 2 ? dp[i][j + 1] || (i < n && dp[i + 1][j])
                                    : i < n && (kind[j] == 1 || it[j] == s[i]) && dp[i + 1][j + 1];
    return dp[0][0];
}

/* every function on a pool of four values (two of the caller's, two texts from the input's tail: valid UTF-8, as
 * TEXT always is), each CAST of them, and LIKE against the reference: computed or refused, never undefined
 * behaviour; a result of its bound type and within it, a TEXT result valid UTF-8 without NUL and within IMDB_MAX_TEXT */
static void s1(const uint8_t *data, size_t size, const imdb_xval *a, const imdb_xval *b)
{
    if (size < 44) return;
    const uint8_t *tail = data + 42;
    size_t tn = size - 42, cut = data[40] % (tn + 1);
    imdb_xval t[2];
    memset(t, 0, sizeof t);
    t[0].type = t[1].type = IMDB_T_TEXT;
    t[0].s = tail;
    t[0].len = (uint32_t)cut;
    t[1].s = tail + cut;
    t[1].len = (uint32_t)(tn - cut);
    if (!text_ok(&t[0]) || !text_ok(&t[1])) return;
    imdb_xarena arena = {0};
    imdb_xenv env = {.arena = &arena};
    imdb_err e = {0};
    /* the caller's TEXT values are raw bytes (for comparisons): one not valid UTF-8 is replaced, as TEXT always is */
    const imdb_xval *pool[4] = {a->type == IMDB_T_TEXT && !text_ok(a) ? &t[0] : a, b->type == IMDB_T_TEXT && !text_ok(b) ? &t[1] : b,
                                &t[0], &t[1]};
    uint8_t sel = data[41];
    for (uint8_t fn = FN_ABS; fn <= FN_CONCAT; fn++) {
        if (fn == FN_COALESCE || fn == FN_NULLIF) continue; /* the evaluator's (lazy) */
        for (uint8_t nargs = 1; nargs <= 3; nargs++) {
            const imdb_xval *av[3];
            imdb_xval args[3];
            uint8_t ta[3], sa[3], rt, rs;
            for (int i = 0; i < nargs; i++) {
                av[i] = pool[(sel >> (2 * i)) & 3];
                args[i] = *av[i];
                ta[i] = args[i].type;
                sa[i] = args[i].scale;
            }
            imdb_err_clear(&e);
            if (imdb_x_fn_type(fn, nargs, ta, sa, av, &rt, &rs, &e)) continue;
            imdb_xval out;
            imdb_xmark mk = imdb_xarena_mark(&arena);
            imdb_err_clear(&e);
            if (imdb_x_fn(fn, args, nargs, rt, rs, &env, &out, &e) == 0) {
                bounds(&out, rt, rs);
                if (rt == IMDB_T_TEXT && !text_ok(&out)) abort();
            }
            imdb_xarena_reset(&arena, mk);
        }
    }
    static const uint8_t CT[] = {IMDB_T_INT64, IMDB_T_DECIMAL, IMDB_T_FLOAT64, IMDB_T_TEXT, IMDB_T_BOOL, IMDB_T_TIMESTAMP};
    for (int i = 0; i < 4; i++)
        for (size_t c = 0; c < sizeof CT; c++) {
            imdb_column col;
            memset(&col, 0, sizeof col);
            strcpy(col.name, "c");
            col.type = CT[c];
            col.precision = (uint8_t)(1 + data[38] % 18);
            col.scale = (uint8_t)(data[39] % (col.precision + 1u));
            imdb_xval out;
            imdb_xmark mk = imdb_xarena_mark(&arena);
            imdb_err_clear(&e);
            if (imdb_x_cast(pool[i], &col, &env, &out, &e) == 0) {
                if (out.type != col.type) abort();
                if (!out.null && col.type == IMDB_T_DECIMAL) {
                    __int128 lim = 1;
                    for (int d = 0; d < col.precision; d++) lim *= 10;
                    if (out.scale != col.scale || out.i >= lim || out.i <= -lim) abort();
                }
                if (!out.null && col.type != IMDB_T_DECIMAL && col.type != IMDB_T_TEXT && col.type != IMDB_T_BOOL &&
                    col.type != IMDB_T_TIMESTAMP)
                    bounds(&out, col.type, 0);
                if (!out.null && col.type == IMDB_T_BOOL && out.i != 0 && out.i != 1) abort();
                if (col.type == IMDB_T_TEXT && !text_ok(&out)) abort();
            }
            imdb_xarena_reset(&arena, mk);
        }
    uint32_t sc[64], pc[64];
    int n = chars(t[0].s, t[0].len, sc), m = chars(t[1].s, t[1].len, pc);
    uint32_t esc = data[41] & 1 ? 0 : (uint32_t)(data[41] >> 1); /* none, or an ASCII character (0 also none) */
    bool match = false;
    imdb_err_clear(&e);
    int rc = imdb_x_like(t[0].s, t[0].len, t[1].s, t[1].len, esc, &env, &match, &e);
    if (n >= 0 && m >= 0) {
        int want = ref_like(sc, n, pc, m, esc);
        if (want < 0 ? rc == 0 : rc != 0 || match != (bool)want) abort();
    }
    imdb_xarena_free(&arena);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < 40) return 0;
    imdb_xval a, b, r;
    value(data[0], data[2], data + 4, &a);
    value(data[1], data[3], data + 20, &b);
    imdb_err e = {0};
    uint8_t op = (uint8_t)(EX_ADD + data[36] % 5), rt, rs;
    if (imdb_x_type(op, a.type, a.scale, b.type, b.scale, &rt, &rs, &e) == 0) {
        imdb_err_clear(&e);
        if (imdb_x_arith(op, &a, &b, rt, rs, &r, &e) == 0) bounds(&r, rt, rs);
    }
    imdb_err_clear(&e);
    if (a.type != IMDB_T_TEXT && imdb_x_neg(&a, &r, &e) == 0 && a.type == IMDB_T_INT64 && !a.null &&
        (r.i < INT64_MIN || r.i > INT64_MAX))
        abort();
    if (!a.null && !b.null && imdb_x_comparable(a.type, b.type)) {
        if (imdb_x_cmp(&a, &b) != -imdb_x_cmp(&b, &a) || imdb_x_cmp(&a, &a) != 0) abort();
    }
    static const uint8_t CT[] = {IMDB_T_INT64, IMDB_T_DECIMAL, IMDB_T_FLOAT64, IMDB_T_TEXT};
    imdb_column c;
    memset(&c, 0, sizeof c);
    strcpy(c.name, "c");
    c.type = CT[data[37] % 4];
    c.precision = (uint8_t)(1 + data[38] % 18);
    c.scale = (uint8_t)(data[39] % (c.precision + 1u));
    c.flags = IMDB_COL_NULLABLE;
    imdb_value out;
    imdb_err_clear(&e);
    if (imdb_x_assign(&c, &a, &out, &e) == 0 && imdb_value_check(&c, &out, &e) != 0) abort();
    imdb_err_clear(&e);
    imdb_x_parse_decimal((const char *)data + 40, size - 40, &r, &e);
    s1(data, size, &a, &b); /* P2 S1 */
    return 0;
}
