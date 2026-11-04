/* sql_expr.c (1b): any two values within the evaluator's bounds and any operation are computed or refused, never
 * undefined behaviour (this build traps signed overflow: no -fno-strict-overflow), every result within its own bounds
 * (an INT64 inside int64, a DECIMAL under 10^38 at the bound scale, a FLOAT64 finite), comparisons antisymmetric and
 * reflexive, an assignment checked like any value, and a DECIMAL literal's parse total. */
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
    return 0;
}
