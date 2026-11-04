/* Arithmetic expressions (docs/plan-p0.md 1b, design.md "Expressions"): the type of each operation, the operation
 * itself, checked, the comparisons and the assignment of a result to a column. No engine state: the executor binds a
 * statement's trees (sql_exec.c) and calls these on its rows.
 *
 * INT64 is computed in __int128 and every result checked against int64, so INT64_MIN / -1 never reaches an idiv (it
 * would trap) and an operand past int64 (a SUM's result) is still exact. DECIMAL is a scaled __int128 of at most 38
 * digits: + - % at the larger scale, * at the scales' sum, / at the larger scale plus six, rounded half away from
 * zero. FLOAT64 is IEEE: a zero divisor and a non-finite result are errors, % is not defined; an INT64 joins it only
 * when exact (|v| <= 2^53), a DECIMAL correctly rounded. Comparisons are exact and never fail; a NULL operand makes
 * an operation NULL. Messages never carry a value (the rule for every error the engine reports). */
#include <math.h>
#include <stdio.h>
#include <string.h>

#include "sql_internal.h"

#define U128_MAX (~(unsigned __int128)0)

static unsigned __int128 p10(int n) /* n in 0..38 */
{
    unsigned __int128 r = 1;
    while (n-- > 0) r *= 10;
    return r;
}

static bool is_num(uint8_t t) { return t == IMDB_T_INT64 || t == IMDB_T_DECIMAL || t == IMDB_T_FLOAT64; }

static unsigned __int128 mag(__int128 v) { return v < 0 ? (unsigned __int128)0 - (unsigned __int128)v : (unsigned __int128)v; }

static int overflow(imdb_err *e, uint8_t t)
{
    return imdb_fail(e, IMDB_ERR_LIMIT, t == IMDB_T_INT64 ? "INT64 overflow in an expression"
                                                          : "a DECIMAL result of more than 38 digits in an expression");
}

static int div0(imdb_err *e) { return imdb_fail(e, IMDB_ERR_INVALID, "division by zero"); }

int imdb_x_type(uint8_t op, uint8_t ta, uint8_t sa, uint8_t tb, uint8_t sb, uint8_t *rt, uint8_t *rs, imdb_err *e)
{
    if (!is_num(ta) || !is_num(tb))
        return imdb_fail(e, IMDB_ERR_INVALID, "arithmetic takes INT64, DECIMAL and FLOAT64 values");
    *rs = 0;
    if (ta == IMDB_T_FLOAT64 || tb == IMDB_T_FLOAT64) {
        if (op == EX_MOD) return imdb_fail(e, IMDB_ERR_INVALID, "%% is not defined on FLOAT64");
        *rt = IMDB_T_FLOAT64;
        return IMDB_OK;
    }
    if (ta == IMDB_T_INT64 && tb == IMDB_T_INT64) {
        *rt = IMDB_T_INT64;
        return IMDB_OK;
    }
    int s1 = ta == IMDB_T_DECIMAL ? sa : 0, s2 = tb == IMDB_T_DECIMAL ? sb : 0, big = s1 > s2 ? s1 : s2, s;
    switch (op) {
    case EX_MUL: s = s1 + s2; break;
    case EX_DIV: s = big + 6; break; /* no standard fixes it: PostgreSQL's depends on the values, MySQL's is s1 + 4 */
    default: s = big; break;
    }
    if (s > IMDB_X_MAX_SCALE)
        return imdb_fail(e, IMDB_ERR_LIMIT, "a DECIMAL result of more than %u decimal places", IMDB_X_MAX_SCALE);
    *rt = IMDB_T_DECIMAL;
    *rs = (uint8_t)s;
    return IMDB_OK;
}

void imdb_x_from_value(const imdb_value *v, imdb_xval *out)
{
    memset(out, 0, sizeof *out);
    out->type = v->type;
    out->scale = v->scale;
    out->null = v->null;
    if (v->null) return;
    if (v->type == IMDB_T_FLOAT64) out->f = imdb_f64_value(v->i);
    else if (v->type == IMDB_T_TEXT) out->s = v->s, out->len = v->len;
    else out->i = v->i;
}

/* a DECIMAL (or INT64, scale 0) as the nearest double: one rounding (strtod's, through the literal parser) */
static double dec_f64(__int128 v, int scale)
{
    static const double P10D[23] = {1e0,  1e1,  1e2,  1e3,  1e4,  1e5,  1e6,  1e7,  1e8,  1e9,  1e10, 1e11,
                                    1e12, 1e13, 1e14, 1e15, 1e16, 1e17, 1e18, 1e19, 1e20, 1e21, 1e22}; /* exact */
    unsigned __int128 m = mag(v);
    if (m <= ((unsigned __int128)1 << 53) && scale <= 22) { /* both exact doubles: IEEE division rounds once */
        double d = (double)(int64_t)m / P10D[scale];
        return v < 0 ? -d : d;
    }
    char b[64]; /* digits, then e-scale: the grammar imdb_parse_float64 takes */
    char t[48];
    int n = 0, k = 0;
    do {
        t[n++] = (char)('0' + (int)(m % 10));
        m /= 10;
    } while (m);
    if (v < 0) b[k++] = '-';
    while (n) b[k++] = t[--n];
    k += snprintf(b + k, sizeof b - (size_t)k, "e-%d", scale);
    int64_t key;
    imdb_err e2 = {0};
    if (imdb_parse_float64(b, (size_t)k, &key, &e2)) return 0; /* unreachable: under 10^38 and over 10^-38 */
    return imdb_f64_value(key);
}

static int to_f64(const imdb_xval *v, double *out, imdb_err *e)
{
    if (v->type == IMDB_T_FLOAT64) {
        *out = v->f;
        return IMDB_OK;
    }
    if (v->type == IMDB_T_INT64) {
        if (v->i > ((__int128)1 << 53) || v->i < -((__int128)1 << 53))
            return imdb_fail(e, IMDB_ERR_LIMIT, "an INT64 beyond 2^53 is not exact as a FLOAT64");
        *out = (double)(int64_t)v->i;
        return IMDB_OK;
    }
    *out = dec_f64(v->i, v->scale);
    return IMDB_OK;
}

/* v at scale s raised to scale t (t >= s), or false past 38 digits */
static bool rescale(__int128 v, int s, int t, __int128 *out)
{
    __int128 r;
    if (__builtin_mul_overflow(v, (__int128)p10(t - s), &r) || mag(r) >= p10(IMDB_X_MAX_SCALE)) return false;
    *out = r;
    return true;
}

/* |a| * 10^k / |b| rounded half away from zero, signed: the quotient at its scale */
static int dec_div(__int128 a, __int128 b, int k, __int128 *out, imdb_err *e)
{
    if (!b) return div0(e);
    unsigned __int128 ua = mag(a), ub = mag(b), q, r, lim = p10(IMDB_X_MAX_SCALE);
    if (k <= IMDB_X_MAX_SCALE && ua <= U128_MAX / p10(k)) { /* the common case: scaled in one step (k reaches 70) */
        unsigned __int128 n = ua * p10(k);
        q = n / ub;
        r = n % ub;
    } else { /* long division, a digit at a time, so a large dividend does not overflow */
        if (ub > U128_MAX / 10) return imdb_fail(e, IMDB_ERR_LIMIT, "a DECIMAL division by a value of more than 37 digits");
        q = ua / ub;
        r = ua % ub;
        for (int i = 0; i < k; i++) {
            if (q > (lim - 1) / 10) return overflow(e, IMDB_T_DECIMAL);
            r *= 10;
            q = q * 10 + r / ub;
            r %= ub;
        }
    }
    if (r >= ub - r) q++; /* 2r >= |b| without overflow */
    if (q >= lim) return overflow(e, IMDB_T_DECIMAL);
    *out = (a < 0) != (b < 0) ? -(__int128)q : (__int128)q;
    return IMDB_OK;
}

int imdb_x_arith(uint8_t op, const imdb_xval *a, const imdb_xval *b, uint8_t rt, uint8_t rs, imdb_xval *out,
                 imdb_err *e)
{
    memset(out, 0, sizeof *out);
    out->type = rt;
    out->scale = rs;
    if (a->null || b->null) {
        out->null = true;
        return IMDB_OK;
    }
    if (rt == IMDB_T_FLOAT64) {
        double x, y, r = 0;
        if (to_f64(a, &x, e) || to_f64(b, &y, e)) return e->code;
        switch (op) {
        case EX_ADD: r = x + y; break;
        case EX_SUB: r = x - y; break;
        case EX_MUL: r = x * y; break;
        case EX_DIV:
            if (y == 0) return div0(e);
            r = x / y;
            break;
        default: return imdb_fail(e, IMDB_ERR_INVALID, "%% is not defined on FLOAT64");
        }
        if (!isfinite(r)) return imdb_fail(e, IMDB_ERR_LIMIT, "a FLOAT64 result out of range in an expression");
        out->f = r;
        return IMDB_OK;
    }
    __int128 x = a->i, y = b->i, r = 0;
    if (rt == IMDB_T_INT64) { /* operands within 2^103 (a SUM's bound): only * can leave __int128 */
        switch (op) {
        case EX_ADD: r = x + y; break;
        case EX_SUB: r = x - y; break;
        case EX_MUL:
            if (__builtin_mul_overflow(x, y, &r)) return overflow(e, rt);
            break;
        case EX_DIV:
            if (!y) return div0(e);
            r = x / y; /* truncates toward zero, as C, PostgreSQL and SQL Server do */
            break;
        default:
            if (!y) return div0(e);
            r = x % y; /* the dividend's sign; INT64_MIN % -1 is 0 here, no trap */
            break;
        }
        if (r < INT64_MIN || r > INT64_MAX) return overflow(e, rt);
        out->i = r;
        return IMDB_OK;
    }
    int sa = a->type == IMDB_T_DECIMAL ? a->scale : 0, sb = b->type == IMDB_T_DECIMAL ? b->scale : 0;
    switch (op) {
    case EX_MUL:
        if (__builtin_mul_overflow(x, y, &r) || mag(r) >= p10(IMDB_X_MAX_SCALE)) return overflow(e, rt);
        break;
    case EX_DIV:
        if (dec_div(x, y, rs - sa + sb, &r, e)) return e->code;
        break;
    default:
        if (!rescale(x, sa, rs, &x) || !rescale(y, sb, rs, &y)) return overflow(e, rt);
        if (op == EX_MOD) {
            if (!y) return div0(e);
            r = x % y;
        } else { /* two operands under 10^38 may still sum past __int128 (1.7 * 10^38): checked */
            if (op == EX_ADD ? __builtin_add_overflow(x, y, &r) : __builtin_sub_overflow(x, y, &r)) return overflow(e, rt);
            if (mag(r) >= p10(IMDB_X_MAX_SCALE)) return overflow(e, rt);
        }
        break;
    }
    out->i = r;
    return IMDB_OK;
}

int imdb_x_neg(const imdb_xval *a, imdb_xval *out, imdb_err *e)
{
    *out = *a;
    if (a->null) return IMDB_OK;
    if (a->type == IMDB_T_FLOAT64) out->f = -a->f;
    else out->i = -a->i;
    if (a->type == IMDB_T_INT64 && (out->i > INT64_MAX || out->i < INT64_MIN)) /* -INT64_MIN; -SUM past int64 */
        return overflow(e, IMDB_T_INT64);
    return IMDB_OK;
}

bool imdb_x_comparable(uint8_t ta, uint8_t tb) { return ta == tb || (is_num(ta) && is_num(tb)); }

/* an integer against a double, exactly: no conversion that could round or fail */
static int cmp_i_f(__int128 i, double d)
{
    if (d >= 0x1p127) return -1;
    if (d < -0x1p127) return 1;
    double t = trunc(d);
    __int128 ti = (__int128)t; /* |t| <= 2^127 and integral: exact */
    if (i != ti) return i < ti ? -1 : 1;
    double fr = d - t; /* exact */
    return fr > 0 ? -1 : fr < 0 ? 1 : 0;
}

/* x at scale sx against y at scale sy: the smaller scale raised; if that overflows, its magnitude decides */
static int cmp_dec(__int128 x, int sx, __int128 y, int sy)
{
    __int128 r;
    if (sx < sy) {
        if (__builtin_mul_overflow(x, (__int128)p10(sy - sx), &r)) return x < 0 ? -1 : 1;
        x = r;
    } else if (sy < sx) {
        if (__builtin_mul_overflow(y, (__int128)p10(sx - sy), &r)) return y < 0 ? 1 : -1;
        y = r;
    }
    return x < y ? -1 : x > y;
}

int imdb_x_cmp(const imdb_xval *a, const imdb_xval *b)
{
    if (a->type == IMDB_T_TEXT) {
        uint32_t n = a->len < b->len ? a->len : b->len;
        int c = n ? memcmp(a->s, b->s, n) : 0;
        if (c) return c < 0 ? -1 : 1;
        return a->len < b->len ? -1 : a->len > b->len;
    }
    if (a->type == IMDB_T_FLOAT64 || b->type == IMDB_T_FLOAT64) {
        if (a->type == IMDB_T_INT64) return cmp_i_f(a->i, b->f);
        if (b->type == IMDB_T_INT64) return -cmp_i_f(b->i, a->f);
        double x = a->type == IMDB_T_FLOAT64 ? a->f : dec_f64(a->i, a->scale); /* as PostgreSQL compares them */
        double y = b->type == IMDB_T_FLOAT64 ? b->f : dec_f64(b->i, b->scale);
        return x < y ? -1 : x > y;
    }
    if (a->type == IMDB_T_DECIMAL || b->type == IMDB_T_DECIMAL)
        return cmp_dec(a->i, a->type == IMDB_T_DECIMAL ? a->scale : 0, b->i, b->type == IMDB_T_DECIMAL ? b->scale : 0);
    return a->i < b->i ? -1 : a->i > b->i; /* INT64, BOOL, TIMESTAMP */
}

int imdb_x_assign(const imdb_column *c, const imdb_xval *v, imdb_value *out, imdb_err *e)
{
    memset(out, 0, sizeof *out);
    out->type = c->type;
    out->scale = c->scale;
    if (v->null) {
        out->null = true;
        return imdb_value_check(c, out, e);
    }
    switch (c->type) {
    case IMDB_T_INT64:
        if (v->type != IMDB_T_INT64)
            return imdb_fail(e, IMDB_ERR_INVALID, "column %s expects an integer: a DECIMAL or FLOAT64 value is not converted", c->name);
        if (v->i < INT64_MIN || v->i > INT64_MAX) return overflow(e, IMDB_T_INT64);
        out->i = (int64_t)v->i;
        break;
    case IMDB_T_DECIMAL: {
        if (v->type != IMDB_T_INT64 && v->type != IMDB_T_DECIMAL)
            return imdb_fail(e, IMDB_ERR_INVALID, "column %s expects a DECIMAL: a FLOAT64 value is not converted", c->name);
        int s = v->type == IMDB_T_DECIMAL ? v->scale : 0;
        __int128 r = v->i;
        if (s < c->scale) {
            if (!rescale(r, s, c->scale, &r))
                return imdb_fail(e, IMDB_ERR_LIMIT, "column %s: value exceeds DECIMAL(%u,%u)", c->name, c->precision, c->scale);
        } else if (s > c->scale) { /* PostgreSQL's assignment: half away from zero */
            unsigned __int128 d = p10(s - c->scale), m = mag(r), q = m / d, rem = m % d;
            if (rem >= d - rem) q++;
            r = r < 0 ? -(__int128)q : (__int128)q;
        }
        if (mag(r) >= p10(18))
            return imdb_fail(e, IMDB_ERR_LIMIT, "column %s: value exceeds DECIMAL(%u,%u)", c->name, c->precision, c->scale);
        out->i = (int64_t)r; /* the precision: imdb_value_check */
        break;
    }
    case IMDB_T_FLOAT64: {
        double d;
        if (!is_num(v->type))
            return imdb_fail(e, IMDB_ERR_INVALID, "column %s expects a number", c->name);
        if (to_f64(v, &d, e)) return e->code;
        out->i = imdb_f64_key(d); /* -0.0 becomes 0.0: one encoding per value */
        break;
    }
    default:
        if (v->type != c->type)
            return imdb_fail(e, IMDB_ERR_INVALID, "column %s expects a %s", c->name, imdb_type_name(c->type));
        if (c->type == IMDB_T_TEXT) out->s = v->s, out->len = v->len;
        else out->i = (int64_t)v->i;
        break;
    }
    return imdb_value_check(c, out, e);
}

int imdb_x_parse_decimal(const char *s, size_t n, imdb_xval *out, imdb_err *e)
{
    memset(out, 0, sizeof *out);
    out->type = IMDB_T_DECIMAL;
    size_t i = 0, digits = 0;
    bool neg = false, point = false, any = false;
    if (i < n && (s[i] == '-' || s[i] == '+')) neg = s[i++] == '-';
    unsigned __int128 m = 0;
    for (; i < n; i++) {
        if (s[i] == '.' && !point) {
            point = true;
            continue;
        }
        if (s[i] < '0' || s[i] > '9') return imdb_fail(e, IMDB_ERR_INVALID, "invalid DECIMAL literal");
        any = true;
        if (point) out->scale++;
        if (m || s[i] != '0') digits++; /* significant digits: leading zeros are not */
        if (digits > IMDB_X_MAX_SCALE || out->scale > IMDB_X_MAX_SCALE)
            return imdb_fail(e, IMDB_ERR_LIMIT, "a DECIMAL literal of more than %u digits", IMDB_X_MAX_SCALE);
        m = m * 10 + (unsigned)(s[i] - '0');
    }
    if (!any) return imdb_fail(e, IMDB_ERR_INVALID, "invalid DECIMAL literal");
    out->i = neg ? -(__int128)m : (__int128)m;
    return IMDB_OK;
}

/* a BOOL that is TRUE, FALSE, or UNKNOWN (NULL) */
static void truth(imdb_xval *out, int t) /* 1, 0, -1 */
{
    memset(out, 0, sizeof *out);
    out->type = IMDB_T_BOOL;
    out->null = t < 0;
    out->i = t > 0;
}

static int tv(const imdb_xval *v) { return v->null ? -1 : v->i != 0; }

bool imdb_x_true(const imdb_xval *v) { return !v->null && v->type == IMDB_T_BOOL && v->i != 0; }

/* a cmp b, both computed and comparable (the binder's check): UNKNOWN when either is NULL */
static int cmp3(uint8_t op, const imdb_xval *a, const imdb_xval *b)
{
    if (a->null || b->null) return -1;
    int c = imdb_x_cmp(a, b);
    switch (op) {
    case CMP_EQ: return c == 0;
    case CMP_NE: return c != 0;
    case CMP_LT: return c < 0;
    case CMP_LE: return c <= 0;
    case CMP_GT: return c > 0;
    default: return c >= 0; /* CMP_GE */
    }
}

int imdb_x_eval(const sql_stmt *st, const imdb_xnode *xn, uint16_t k, const imdb_value *row, const imdb_xval *slots,
                imdb_xval *out, imdb_err *e)
{
    const sql_expr *x = &st->ex[k];
    const imdb_xnode *b = &xn[k];
    imdb_xval l, r, h;
    switch (x->op) {
    case EX_LIT: *out = b->k; return IMDB_OK;
    case EX_COL: imdb_x_from_value(&row[b->col], out); return IMDB_OK;
    case EX_AGG: *out = slots[b->slot]; return IMDB_OK;
    case EX_NEG:
        if (imdb_x_eval(st, xn, x->l, row, slots, &l, e)) return e->code; /* the height bounds the recursion */
        return imdb_x_neg(&l, out, e);
    case EX_NOT: {
        if (imdb_x_eval(st, xn, x->l, row, slots, &l, e)) return e->code;
        int t = tv(&l);
        truth(out, t < 0 ? -1 : !t);
        return IMDB_OK;
    }
    case EX_AND:
    case EX_OR: { /* left to right, stopping once decided (AND at FALSE, OR at TRUE), as PostgreSQL, MySQL and SQLite
                   * do inside an expression: the tree fixes the order, never the plan */
        if (imdb_x_eval(st, xn, x->l, row, slots, &l, e)) return e->code;
        int a = tv(&l), stop = x->op == EX_AND ? 0 : 1;
        if (a == stop) {
            truth(out, stop);
            return IMDB_OK;
        }
        if (imdb_x_eval(st, xn, x->r, row, slots, &r, e)) return e->code;
        int c = tv(&r);
        truth(out, c == stop ? stop : a < 0 || c < 0 ? -1 : !stop);
        return IMDB_OK;
    }
    case EX_CMP: {
        if (imdb_x_eval(st, xn, x->l, row, slots, &l, e)) return e->code;
        if (x->cmp == CMP_ISNULL || x->cmp == CMP_NOTNULL) {
            truth(out, l.null == (x->cmp == CMP_ISNULL));
            return IMDB_OK;
        }
        if (imdb_x_eval(st, xn, x->r, row, slots, &r, e)) return e->code;
        if (x->cmp != CMP_BETWEEN) {
            truth(out, cmp3(x->cmp, &l, &r));
            return IMDB_OK;
        }
        /* its three operands all computed; l >= r AND l <= x3, three-valued (5 BETWEEN 10 AND NULL is FALSE) */
        if (imdb_x_eval(st, xn, x->x3, row, slots, &h, e)) return e->code;
        int lo = cmp3(CMP_GE, &l, &r), hi = cmp3(CMP_LE, &l, &h);
        truth(out, lo == 0 || hi == 0 ? 0 : lo < 0 || hi < 0 ? -1 : 1);
        return IMDB_OK;
    }
    default:
        if (imdb_x_eval(st, xn, x->l, row, slots, &l, e) || imdb_x_eval(st, xn, x->r, row, slots, &r, e)) return e->code;
        return imdb_x_arith(x->op, &l, &r, b->type, b->scale, out, e);
    }
}
