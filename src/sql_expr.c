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
#include <strings.h>

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

/* ---- P2 S1: the statement's arena for computed TEXT -------------------------------------------------------------- */

uint8_t *imdb_xarena_alloc(imdb_xarena *a, size_t n, imdb_err *e)
{
    imdb_xchunk *c = a->head;
    if (!n) n = 1;
    if (!c || c->cap - c->used < n) {
        size_t cap = n > 65536 ? n : 65536; /* n is a TEXT's bytes at most: computed results are held to IMDB_MAX_TEXT */
        c = imdb_alloc(sizeof *c + cap, e);
        if (!c) return NULL;
        c->cap = cap;
        c->next = a->head;
        a->head = c;
    }
    uint8_t *p = c->data + c->used;
    c->used += n;
    return p;
}

imdb_xmark imdb_xarena_mark(const imdb_xarena *a)
{
    imdb_xmark m = {a->head, a->head ? a->head->used : 0};
    return m;
}

void imdb_xarena_reset(imdb_xarena *a, imdb_xmark m)
{
    while (a->head && a->head != m.head) {
        imdb_xchunk *n = a->head->next;
        imdb_free(a->head);
        a->head = n;
    }
    if (a->head) a->head->used = m.used;
}

void imdb_xarena_free(imdb_xarena *a)
{
    imdb_xmark none = {NULL, 0};
    imdb_xarena_reset(a, none);
}

/* n bytes of computed TEXT from the statement's arena: refused past IMDB_MAX_TEXT, as a stored TEXT would be */
static uint8_t *x_text(imdb_xenv *env, size_t n, imdb_xval *out, imdb_err *e)
{
    if (n > IMDB_MAX_TEXT) {
        imdb_fail(e, IMDB_ERR_LIMIT, "a computed TEXT of more than %u bytes", IMDB_MAX_TEXT);
        return NULL;
    }
    if (!env || !env->arena) {
        imdb_fail(e, IMDB_ERR_STATE, "a computed TEXT where no statement memory is given");
        return NULL;
    }
    uint8_t *p = imdb_xarena_alloc(env->arena, n, e);
    if (p) {
        out->s = p;
        out->len = (uint32_t)n;
    }
    return p;
}

/* LOWER, UPPER (ASCII letters: every other byte, UTF-8's included, is kept), REPLACE, || */
static int fn_text(uint8_t fn, const imdb_xval *a, imdb_xenv *env, imdb_xval *out, imdb_err *e)
{
    if (fn == FN_LOWER || fn == FN_UPPER) {
        uint8_t *p = x_text(env, a[0].len, out, e);
        if (!p) return e->code;
        for (uint32_t i = 0; i < a[0].len; i++) {
            uint8_t c = a[0].s[i];
            p[i] = fn == FN_LOWER && c >= 'A' && c <= 'Z' ? (uint8_t)(c + 32) : fn == FN_UPPER && c >= 'a' && c <= 'z' ? (uint8_t)(c - 32) : c;
        }
        return IMDB_OK;
    }
    if (fn == FN_CONCAT) {
        uint8_t *p = x_text(env, (size_t)a[0].len + a[1].len, out, e);
        if (!p) return e->code;
        if (a[0].len) memcpy(p, a[0].s, a[0].len);
        if (a[1].len) memcpy(p + a[0].len, a[1].s, a[1].len);
        return IMDB_OK;
    }
    /* REPLACE(s, from, to): every occurrence, left to right, never overlapping; an empty from changes nothing */
    if (!a[1].len) {
        *out = a[0];
        return IMDB_OK;
    }
    size_t hits = 0;
    for (uint32_t i = 0; i + a[1].len <= a[0].len;) {
        const uint8_t *h = memmem(a[0].s + i, a[0].len - i, a[1].s, a[1].len);
        if (!h) break;
        hits++;
        i = (uint32_t)(h - a[0].s) + a[1].len;
    }
    size_t n = (size_t)a[0].len - hits * a[1].len + hits * a[2].len;
    uint8_t *p = x_text(env, n, out, e);
    if (!p) return e->code;
    size_t o = 0;
    for (uint32_t i = 0; i < a[0].len;) {
        const uint8_t *h = i + a[1].len <= a[0].len ? memmem(a[0].s + i, a[0].len - i, a[1].s, a[1].len) : NULL;
        uint32_t upto = h ? (uint32_t)(h - a[0].s) : a[0].len;
        memcpy(p + o, a[0].s + i, upto - i);
        o += upto - i;
        if (!h) break;
        if (a[2].len) memcpy(p + o, a[2].s, a[2].len);
        o += a[2].len;
        i = upto + a[1].len;
    }
    return IMDB_OK;
}

/* CAST(v AS TEXT): the CLI's own rendering of the value (imdb_format_value; a DECIMAL past 18 digits by its 128 bits) */
static int cast_to_text(const imdb_xval *v, imdb_xenv *env, imdb_xval *out, imdb_err *e)
{
    if (v->type == IMDB_T_TEXT) {
        *out = *v;
        return IMDB_OK;
    }
    imdb_buf b;
    imdb_buf_init(&b);
    if (v->type == IMDB_T_DECIMAL || v->type == IMDB_T_INT64) {
        imdb_format_i128(v->i, v->type == IMDB_T_DECIMAL ? v->scale : 0, &b);
    } else {
        imdb_value iv = {.type = v->type};
        iv.i = v->type == IMDB_T_FLOAT64 ? imdb_f64_key(v->f) : (int64_t)v->i;
        imdb_format_value(&iv, &b);
    }
    int rc = imdb_buf_check(&b, e);
    if (!rc) {
        uint8_t *p = x_text(env, b.len, out, e);
        if (!p) rc = e->code;
        else if (b.len) memcpy(p, b.p, b.len);
    }
    imdb_buf_free(&b);
    out->type = IMDB_T_TEXT;
    return rc;
}

/* ---- P2 S1: functions, CASE, CAST, IN, LIKE (design.md §5, Functions) ---------------------------------------- */

int imdb_x_unify(uint8_t *t, uint8_t *s, uint8_t t2, uint8_t s2, const char *what, imdb_err *e)
{
    if (!t2) return IMDB_OK; /* an untyped NULL: the others' type */
    if (!*t) {
        *t = t2;
        *s = s2;
        return IMDB_OK;
    }
    if (*t == t2) {
        if (t2 == IMDB_T_DECIMAL && s2 > *s) *s = s2;
        return IMDB_OK;
    }
    if ((*t == IMDB_T_INT64 && t2 == IMDB_T_DECIMAL) || (*t == IMDB_T_DECIMAL && t2 == IMDB_T_INT64)) {
        uint8_t a = *t == IMDB_T_DECIMAL ? *s : 0, b = t2 == IMDB_T_DECIMAL ? s2 : 0;
        *t = IMDB_T_DECIMAL;
        *s = a > b ? a : b;
        return IMDB_OK;
    }
    return imdb_fail(e, IMDB_ERR_INVALID, "%s %s and %s: values are not converted", what, imdb_type_name(*t),
                     imdb_type_name(t2));
}

int imdb_x_widen(imdb_xval *v, uint8_t rt, uint8_t rs, imdb_err *e)
{
    if (v->null || v->type == rt) {
        if (v->null || rt != IMDB_T_DECIMAL || v->scale == rs) {
            v->type = rt;
            v->scale = rs;
            return IMDB_OK;
        }
    }
    if (rt == IMDB_T_DECIMAL && (v->type == IMDB_T_INT64 || v->type == IMDB_T_DECIMAL)) {
        int s = v->type == IMDB_T_DECIMAL ? v->scale : 0;
        if (s > rs || !rescale(v->i, s, rs, &v->i)) return overflow(e, IMDB_T_DECIMAL);
        v->type = IMDB_T_DECIMAL;
        v->scale = rs;
        return IMDB_OK;
    }
    return imdb_fail(e, IMDB_ERR_STATE, "a value of another type than its CASE's or COALESCE's"); /* the binder unified */
}

static const char *fn_name(uint8_t fn)
{
    static const char *const n[] = {"?",     "ABS",    "SIGN",  "ROUND", "CEIL",     "FLOOR",    "MOD",    "LENGTH",
                                    "SUBSTR", "TRIM",  "LTRIM", "RTRIM", "POSITION", "COALESCE", "NULLIF",
                                    "LOWER",  "UPPER", "REPLACE", "||"};
    return fn < sizeof n / sizeof *n ? n[fn] : "?";
}

static int fn_args(uint8_t fn, uint8_t nargs, unsigned lo, unsigned hi, imdb_err *e)
{
    if (nargs >= lo && nargs <= hi) return IMDB_OK;
    if (lo == hi) return imdb_fail(e, IMDB_ERR_INVALID, "%s takes %u argument%s", fn_name(fn), lo, lo == 1 ? "" : "s");
    return imdb_fail(e, IMDB_ERR_INVALID, "%s takes %u to %u arguments", fn_name(fn), lo, hi);
}

int imdb_x_fn_type(uint8_t fn, uint8_t nargs, const uint8_t *ta, const uint8_t *sa, const imdb_xval *const *kv,
                   uint8_t *rt, uint8_t *rs, imdb_err *e)
{
    *rt = 0;
    *rs = 0;
    switch (fn) {
    case FN_ABS:
    case FN_SIGN:
    case FN_CEIL:
    case FN_FLOOR:
        if (fn_args(fn, nargs, 1, 1, e)) return e->code;
        if (!is_num(ta[0])) return imdb_fail(e, IMDB_ERR_INVALID, "%s takes a number", fn_name(fn));
        *rt = fn == FN_SIGN ? IMDB_T_INT64 : ta[0];
        *rs = fn == FN_ABS && ta[0] == IMDB_T_DECIMAL ? sa[0] : 0; /* CEIL and FLOOR: a DECIMAL at scale 0 */
        return IMDB_OK;
    case FN_ROUND: {
        if (fn_args(fn, nargs, 1, 2, e)) return e->code;
        if (!is_num(ta[0])) return imdb_fail(e, IMDB_ERR_INVALID, "ROUND takes a number");
        __int128 d = 0;
        if (nargs == 2) { /* the places fix the result's scale: a constant, known when the statement is bound */
            if (ta[1] != IMDB_T_INT64 || !kv[1] || kv[1]->null)
                return imdb_fail(e, IMDB_ERR_INVALID, "ROUND's places are an integer constant");
            d = kv[1]->i;
            if (d < 0 || d > IMDB_X_MAX_SCALE)
                return imdb_fail(e, IMDB_ERR_INVALID, "ROUND's places are 0 to %u", IMDB_X_MAX_SCALE);
        }
        if (ta[0] == IMDB_T_FLOAT64 && d)
            return imdb_fail(e, IMDB_ERR_INVALID, "ROUND of a FLOAT64 rounds to an integer: CAST it to a DECIMAL to keep places");
        *rt = ta[0];
        *rs = ta[0] == IMDB_T_DECIMAL ? (uint8_t)(sa[0] < d ? sa[0] : d) : 0;
        return IMDB_OK;
    }
    case FN_MOD:
        if (fn_args(fn, nargs, 2, 2, e)) return e->code;
        return imdb_x_type(EX_MOD, ta[0], sa[0], ta[1], sa[1], rt, rs, e);
    case FN_LOWER:
    case FN_UPPER:
    case FN_LENGTH:
    case FN_TRIM:
    case FN_LTRIM:
    case FN_RTRIM:
        if (fn_args(fn, nargs, 1, 1, e)) return e->code;
        if (ta[0] != IMDB_T_TEXT) return imdb_fail(e, IMDB_ERR_INVALID, "%s takes a TEXT value", fn_name(fn));
        *rt = fn == FN_LENGTH ? IMDB_T_INT64 : IMDB_T_TEXT;
        return IMDB_OK;
    case FN_REPLACE:
    case FN_CONCAT: /* || : TEXT alone, as values are not converted (CAST(x AS TEXT) first) */
        if (fn_args(fn, nargs, fn == FN_REPLACE ? 3 : 2, fn == FN_REPLACE ? 3 : 2, e)) return e->code;
        for (unsigned i = 0; i < nargs; i++)
            if (ta[i] != IMDB_T_TEXT) return imdb_fail(e, IMDB_ERR_INVALID, "%s takes TEXT values", fn_name(fn));
        *rt = IMDB_T_TEXT;
        return IMDB_OK;
    case FN_SUBSTR:
        if (fn_args(fn, nargs, 2, 3, e)) return e->code;
        if (ta[0] != IMDB_T_TEXT || ta[1] != IMDB_T_INT64 || (nargs == 3 && ta[2] != IMDB_T_INT64))
            return imdb_fail(e, IMDB_ERR_INVALID, "SUBSTR takes a TEXT value, a start and a length (integers)");
        *rt = IMDB_T_TEXT;
        return IMDB_OK;
    case FN_POSITION:
        if (fn_args(fn, nargs, 2, 2, e)) return e->code;
        if (ta[0] != IMDB_T_TEXT || ta[1] != IMDB_T_TEXT) return imdb_fail(e, IMDB_ERR_INVALID, "POSITION takes TEXT values");
        *rt = IMDB_T_INT64;
        return IMDB_OK;
    case FN_COALESCE:
        if (fn_args(fn, nargs, 1, 255, e)) return e->code;
        for (unsigned i = 0; i < nargs; i++)
            if (imdb_x_unify(rt, rs, ta[i], sa[i], "COALESCE of", e)) return e->code;
        if (!*rt) return imdb_fail(e, IMDB_ERR_INVALID, "COALESCE of NULL alone has no type");
        return IMDB_OK;
    case FN_NULLIF:
        if (fn_args(fn, nargs, 2, 2, e)) return e->code;
        if (!ta[0]) return imdb_fail(e, IMDB_ERR_INVALID, "NULLIF of NULL has no type");
        if (ta[1] && !imdb_x_comparable(ta[0], ta[1]))
            return imdb_fail(e, IMDB_ERR_INVALID, "NULLIF of %s and %s: values are not converted", imdb_type_name(ta[0]),
                             imdb_type_name(ta[1]));
        *rt = ta[0];
        *rs = sa[0];
        return IMDB_OK;
    default: return imdb_fail(e, IMDB_ERR_STATE, "an unknown function");
    }
}

/* FLOAT64 to an integral value without libm: exact under 2^52, and integral already past it */
static double f64_trunc(double f) { return f > -4503599627370496.0 && f < 4503599627370496.0 ? (double)(int64_t)f : f; }
static double f64_floor(double f)
{
    double t = f64_trunc(f);
    return t > f ? t - 1.0 : t;
}
static double f64_ceil(double f)
{
    double t = f64_trunc(f);
    return t < f ? t + 1.0 : t;
}
static double f64_round(double f) /* half away from zero: f - t is exact here */
{
    double t = f64_trunc(f), d = f - t;
    return d >= 0.5 ? t + 1.0 : d <= -0.5 ? t - 1.0 : t;
}

/* UTF-8 (valid: TEXT always is): the next character's start after i, its code point in *cp */
static uint32_t u8_next(const uint8_t *s, uint32_t n, uint32_t i, uint32_t *cp)
{
    uint8_t c = s[i];
    uint32_t k = c < 0x80 ? 1 : c < 0xE0 ? 2 : c < 0xF0 ? 3 : 4, v = k == 1 ? c : k == 2 ? c & 0x1Fu : k == 3 ? c & 0x0Fu : c & 0x07u;
    if (k > n - i) k = n - i; /* never for valid UTF-8 */
    for (uint32_t j = 1; j < k; j++) v = v << 6 | (s[i + j] & 0x3Fu);
    *cp = v;
    return i + k;
}

static uint32_t u8_chars(const uint8_t *s, uint32_t n) /* the characters in n bytes: every byte but a continuation */
{
    uint32_t c = 0;
    for (uint32_t i = 0; i < n; i++) c += (s[i] & 0xC0) != 0x80;
    return c;
}

static uint32_t u8_byte(const uint8_t *s, uint32_t n, uint64_t ch) /* the byte where character ch (0-based) starts */
{
    uint32_t i = 0, cp;
    while (ch-- && i < n) i = u8_next(s, n, i, &cp);
    return i;
}

static int fn_eval(uint8_t fn, const imdb_xval *a, uint8_t nargs, uint8_t rt, uint8_t rs, imdb_xenv *env, imdb_xval *out,
              imdb_err *e)
{
    memset(out, 0, sizeof *out);
    out->type = rt;
    out->scale = rs;
    for (unsigned i = 0; i < nargs; i++) /* each of these is NULL on a NULL argument (COALESCE and NULLIF: the caller's) */
        if (a[i].null) {
            out->null = true;
            return IMDB_OK;
        }
    switch (fn) {
    case FN_ABS:
        if (a[0].type == IMDB_T_FLOAT64) {
            out->f = a[0].f < 0 ? -a[0].f : a[0].f + 0.0; /* -0.0 becomes 0.0 */
            return IMDB_OK;
        }
        out->i = a[0].i < 0 ? -a[0].i : a[0].i;
        return a[0].type == IMDB_T_INT64 && out->i > INT64_MAX ? overflow(e, IMDB_T_INT64) : IMDB_OK;
    case FN_SIGN:
        out->i = a[0].type == IMDB_T_FLOAT64 ? (a[0].f > 0) - (a[0].f < 0) : (a[0].i > 0) - (a[0].i < 0);
        return IMDB_OK;
    case FN_ROUND:
        if (a[0].type == IMDB_T_FLOAT64) out->f = f64_round(a[0].f) + 0.0;
        else if (a[0].type == IMDB_T_INT64 || rs >= a[0].scale) out->i = a[0].i;
        else { /* a DECIMAL to fewer places, half away from zero (as PostgreSQL, MySQL and SQL Server round DECIMAL) */
            unsigned __int128 d = p10(a[0].scale - rs), m = mag(a[0].i), q = m / d, rem = m % d;
            if (rem >= d - rem) q++;
            out->i = a[0].i < 0 ? -(__int128)q : (__int128)q;
        }
        return IMDB_OK;
    case FN_CEIL:
    case FN_FLOOR:
        if (a[0].type == IMDB_T_FLOAT64) out->f = (fn == FN_CEIL ? f64_ceil(a[0].f) : f64_floor(a[0].f)) + 0.0;
        else if (a[0].type == IMDB_T_INT64 || !a[0].scale) out->i = a[0].i;
        else {
            __int128 d = (__int128)p10(a[0].scale), q = a[0].i / d, r = a[0].i % d; /* C truncates toward zero */
            out->i = fn == FN_FLOOR ? q - (r < 0) : q + (r > 0);
        }
        return IMDB_OK;
    case FN_MOD: return imdb_x_arith(EX_MOD, &a[0], &a[1], rt, rs, out, e);
    case FN_LOWER:
    case FN_UPPER:
    case FN_REPLACE:
    case FN_CONCAT: return fn_text(fn, a, env, out, e);
    case FN_LENGTH: out->i = u8_chars(a[0].s, a[0].len); return IMDB_OK;
    case FN_SUBSTR: { /* characters [start, start + length), clipped to the text (PostgreSQL's: a start below 1 is
                       * outside it, so it shortens what is left) */
        __int128 st = a[1].i, en = nargs == 3 ? a[1].i + a[2].i : (__int128)UINT32_MAX + 1;
        if (nargs == 3 && a[2].i < 0) return imdb_fail(e, IMDB_ERR_INVALID, "SUBSTR's length is negative");
        __int128 n = u8_chars(a[0].s, a[0].len);
        if (st < 1) st = 1;
        if (en > n + 1) en = n + 1;
        out->s = a[0].s;
        if (en <= st) return IMDB_OK; /* the empty text */
        uint32_t b0 = u8_byte(a[0].s, a[0].len, (uint64_t)(st - 1)), b1 = u8_byte(a[0].s, a[0].len, (uint64_t)(en - 1));
        out->s = a[0].s + b0;
        out->len = b1 - b0;
        return IMDB_OK;
    }
    case FN_TRIM:
    case FN_LTRIM:
    case FN_RTRIM: { /* spaces only (U+0020), as every engine's one-argument form */
        uint32_t b0 = 0, b1 = a[0].len;
        if (fn != FN_RTRIM)
            while (b0 < b1 && a[0].s[b0] == ' ') b0++;
        if (fn != FN_LTRIM)
            while (b1 > b0 && a[0].s[b1 - 1] == ' ') b1--;
        out->s = a[0].s + b0;
        out->len = b1 - b0;
        return IMDB_OK;
    }
    case FN_POSITION: { /* the needle's first character's place in the haystack (1-based), 0 when absent; an empty
                         * needle is at 1. A byte match is a character match: UTF-8 synchronises */
        if (!a[0].len) {
            out->i = 1;
            return IMDB_OK;
        }
        const uint8_t *hit = a[1].len ? memmem(a[1].s, a[1].len, a[0].s, a[0].len) : NULL;
        out->i = hit ? (__int128)u8_chars(a[1].s, (uint32_t)(hit - a[1].s)) + 1 : 0;
        return IMDB_OK;
    }
    default: return imdb_fail(e, IMDB_ERR_STATE, "an unknown function");
    }
}

/* an INT64 result within int64, as arithmetic's is: an argument may be a SUM's wider INT64 (checked under 10^38), which
 * ROUND, CEIL and FLOOR would otherwise pass on unchanged (found by fuzz_expr) */
int imdb_x_fn(uint8_t fn, const imdb_xval *a, uint8_t nargs, uint8_t rt, uint8_t rs, imdb_xenv *env, imdb_xval *out,
              imdb_err *e)
{
    if (fn_eval(fn, a, nargs, rt, rs, env, out, e)) return e->code;
    if (out->type == IMDB_T_INT64 && !out->null && (out->i < INT64_MIN || out->i > INT64_MAX)) return overflow(e, IMDB_T_INT64);
    return IMDB_OK;
}

/* f's exact value rounded half away from zero to scale s, as an integer scaled by 10^s: false past 10^38 */
static bool f64_dec(double f, int s, __int128 *out)
{
    uint64_t bits;
    memcpy(&bits, &f, sizeof bits);
    int ex = (int)(bits >> 52 & 0x7FF);
    unsigned __int128 m = bits & 0xFFFFFFFFFFFFFull, q;
    if (ex) m |= (unsigned __int128)1 << 52;
    int e2 = (ex ? ex : 1) - 1075; /* f = m * 2^e2 */
    unsigned __int128 num = m * p10(s); /* m < 2^53, 10^s <= 10^38: checked below for s past 22 */
    if (s > 22 && m && num / m != p10(s)) return false;
    if (e2 >= 0) {
        if (e2 > 127 || (num >> (127 - e2)) != 0) return false;
        q = num << e2;
    } else {
        int k = -e2;
        if (k >= 128) q = 0; /* num < 2^126 < half of 2^k */
        else {
            q = num >> k;
            unsigned __int128 rem = num & (((unsigned __int128)1 << k) - 1), half = (unsigned __int128)1 << (k - 1);
            if (rem >= half) q++;
        }
    }
    if (q >= p10(IMDB_X_MAX_SCALE)) return false;
    *out = (bits >> 63) ? -(__int128)q : (__int128)q;
    return true;
}

/* a DECIMAL r at scale s, to scale t of precision p: rounded half away from zero, or refused past p digits */
static int dec_fit(__int128 r, int s, const imdb_column *c, __int128 *out, imdb_err *e)
{
    if (s < c->scale) {
        if (!rescale(r, s, c->scale, &r)) return imdb_fail(e, IMDB_ERR_LIMIT, "CAST: the value exceeds DECIMAL(%u,%u)", c->precision, c->scale);
    } else if (s > c->scale) {
        unsigned __int128 d = p10(s - c->scale), m = mag(r), q = m / d, rem = m % d;
        if (rem >= d - rem) q++;
        r = r < 0 ? -(__int128)q : (__int128)q;
    }
    if (mag(r) >= p10(c->precision ? c->precision : 18))
        return imdb_fail(e, IMDB_ERR_LIMIT, "CAST: the value exceeds DECIMAL(%u,%u)", c->precision, c->scale);
    *out = r;
    return IMDB_OK;
}

static int cast_bad(const imdb_column *c, imdb_err *e) /* never the text itself: a row's value (design.md §5) */
{
    return imdb_fail(e, IMDB_ERR_INVALID, "CAST: a text that is not a valid %s", imdb_type_name(c->type));
}

int imdb_x_cast(const imdb_xval *v, const imdb_column *c, imdb_xenv *env, imdb_xval *out, imdb_err *e)
{
    memset(out, 0, sizeof *out);
    out->type = c->type;
    out->scale = c->type == IMDB_T_DECIMAL ? c->scale : 0;
    if (v->null) {
        out->null = true;
        return IMDB_OK;
    }
    if (v->type == IMDB_T_TEXT && c->type != IMDB_T_TEXT) { /* the literal's own syntax, no spaces around it */
        const char *s = (const char *)v->s;
        imdb_err pe = {0};
        int64_t i;
        switch (c->type) {
        case IMDB_T_INT64:
            if (imdb_parse_int64(s, v->len, &i, &pe)) return cast_bad(c, e);
            out->i = i;
            return IMDB_OK;
        case IMDB_T_DECIMAL: {
            imdb_xval d;
            if (!imdb_parse_int64(s, v->len, &i, &pe)) {
                memset(&d, 0, sizeof d);
                d.i = i;
            } else if (imdb_x_parse_decimal(s, v->len, &d, &pe)) {
                return cast_bad(c, e);
            }
            return dec_fit(d.i, d.scale, c, &out->i, e);
        }
        case IMDB_T_FLOAT64:
            if (imdb_parse_float64(s, v->len, &i, &pe)) return cast_bad(c, e);
            out->f = imdb_f64_value(i);
            return IMDB_OK;
        case IMDB_T_BOOL:
            if (v->len == 4 && !strncasecmp(s, "true", 4)) out->i = 1;
            else if (v->len == 5 && !strncasecmp(s, "false", 5)) out->i = 0;
            else return cast_bad(c, e);
            return IMDB_OK;
        case IMDB_T_TIMESTAMP:
            if (imdb_parse_timestamp(s, v->len, &i, &pe)) return cast_bad(c, e);
            out->i = i;
            return IMDB_OK;
        default: break;
        }
    }
    switch (c->type) {
    case IMDB_T_INT64:
        if (v->type == IMDB_T_INT64) out->i = v->i;
        else if (v->type == IMDB_T_DECIMAL) {
            __int128 d = (__int128)p10(v->scale);
            if (v->i % d) /* PostgreSQL and MySQL round it, SQL Server and SQLite truncate: refused, never guessed */
                return imdb_fail(e, IMDB_ERR_INVALID, "CAST to INT64 of a value with a fraction: ROUND, FLOOR or CEIL it first");
            out->i = v->i / d;
        } else if (v->type == IMDB_T_FLOAT64) {
            if (!(v->f >= -9223372036854775808.0 && v->f < 9223372036854775808.0)) return overflow(e, IMDB_T_INT64);
            if (v->f != f64_trunc(v->f))
                return imdb_fail(e, IMDB_ERR_INVALID, "CAST to INT64 of a value with a fraction: ROUND, FLOOR or CEIL it first");
            out->i = (int64_t)v->f;
        } else break;
        return out->i < INT64_MIN || out->i > INT64_MAX ? overflow(e, IMDB_T_INT64) : IMDB_OK;
    case IMDB_T_DECIMAL:
        if (v->type == IMDB_T_INT64 || v->type == IMDB_T_DECIMAL)
            return dec_fit(v->i, v->type == IMDB_T_DECIMAL ? v->scale : 0, c, &out->i, e);
        if (v->type == IMDB_T_FLOAT64) {
            __int128 r;
            if (!f64_dec(v->f, c->scale, &r)) return imdb_fail(e, IMDB_ERR_LIMIT, "CAST: the value exceeds DECIMAL(%u,%u)", c->precision, c->scale);
            return dec_fit(r, c->scale, c, &out->i, e);
        }
        break;
    case IMDB_T_FLOAT64:
        if (!is_num(v->type)) break;
        if (to_f64(v, &out->f, e)) return e->code;
        out->f += 0.0;
        return IMDB_OK;
    case IMDB_T_BOOL:
    case IMDB_T_TIMESTAMP:
        if (v->type != c->type) break;
        out->i = v->i;
        return IMDB_OK;
    case IMDB_T_TEXT: return cast_to_text(v, env, out, e);
    default: break;
    }
    return imdb_fail(e, IMDB_ERR_INVALID, "CAST of %s to %s is not defined", imdb_type_name(v->type), imdb_type_name(c->type));
}

/* the pattern's next item from byte j: a wildcard ('%' or '_' unescaped: *wild) or a literal character (*cp); -1 when
 * it ends in its escape character */
static int pat_item(const uint8_t *p, uint32_t m, uint32_t j, uint32_t esc, uint32_t *cp, int *wild, uint32_t *next)
{
    uint32_t c, k = u8_next(p, m, j, &c);
    *wild = 0;
    if (esc && c == esc) {
        if (k >= m) return -1;
        *next = u8_next(p, m, k, cp);
        return 0;
    }
    if (c == '%' || c == '_') *wild = (int)c;
    *cp = c;
    *next = k;
    return 0;
}

int imdb_x_like(const uint8_t *s, uint32_t n, const uint8_t *p, uint32_t m, uint32_t esc, imdb_xenv *env, bool *match,
                imdb_err *e)
{
    /* the two-pointer match with one backtrack point (the last %): characters, not bytes, for _ and literals */
    uint32_t i = 0, j = 0, star_j = UINT32_MAX, star_i = 0, cp, tc, next;
    int wild;
    /* a pattern ending in its escape is refused whatever the text, before any match: an error never depends on the
     * row (PostgreSQL's and MySQL's depend on how far the match got) */
    for (uint32_t k = 0; k < m;) {
        if (pat_item(p, m, k, esc, &cp, &wild, &next)) return imdb_fail(e, IMDB_ERR_INVALID, "a LIKE pattern ends in its escape character");
        k = next;
    }
    while (i < n) {
        if (env && !(++env->steps & 0xFFFF) && env->check && env->check(env->ctx, e)) return e->code;
        if (j < m) {
            if (pat_item(p, m, j, esc, &cp, &wild, &next))
                return imdb_fail(e, IMDB_ERR_INVALID, "a LIKE pattern ends in its escape character");
            if (wild == '%') {
                star_j = next;
                star_i = i;
                j = next;
                continue;
            }
            uint32_t ni = u8_next(s, n, i, &tc);
            if (wild == '_' || cp == tc) {
                i = ni;
                j = next;
                continue;
            }
        }
        if (star_j == UINT32_MAX) {
            *match = false;
            return IMDB_OK;
        }
        star_i = u8_next(s, n, star_i, &tc); /* the last % takes one more character */
        i = star_i;
        j = star_j;
    }
    while (j < m) { /* what is left must be % alone */
        if (pat_item(p, m, j, esc, &cp, &wild, &next))
            return imdb_fail(e, IMDB_ERR_INVALID, "a LIKE pattern ends in its escape character");
        if (wild != '%') break;
        j = next;
    }
    *match = j >= m;
    return IMDB_OK;
}

int imdb_x_eval(const sql_stmt *st, const imdb_xnode *xn, uint16_t k, const imdb_value *row, const imdb_xval *slots,
                imdb_xenv *env, imdb_xval *out, imdb_err *e)
{
    const sql_expr *x = &st->ex[k];
    const imdb_xnode *b = &xn[k];
    imdb_xval l, r, h;
    imdb_xlist it;
    if (slots && b->gslot) { /* P2 S2: a GROUP BY key over its group (per row, slots is NULL: it is computed) */
        *out = slots[b->gslot - 1];
        return IMDB_OK;
    }
    switch (x->op) {
    case EX_LIT: *out = b->k; return IMDB_OK;
    case EX_SUBQ: *out = b->k; return IMDB_OK; /* P2 S4: a subquery's value or EXISTS, computed once */
    case EX_COL: imdb_x_from_value(&row[b->col], out); return IMDB_OK;
    case EX_AGG: *out = slots[b->slot]; return IMDB_OK;
    case EX_NEG:
        if (imdb_x_eval(st, xn, x->l, row, slots, env, &l, e)) return e->code; /* the height bounds the recursion */
        return imdb_x_neg(&l, out, e);
    case EX_NOT: {
        if (imdb_x_eval(st, xn, x->l, row, slots, env, &l, e)) return e->code;
        int t = tv(&l);
        truth(out, t < 0 ? -1 : !t);
        return IMDB_OK;
    }
    case EX_AND:
    case EX_OR: { /* left to right, stopping once decided (AND at FALSE, OR at TRUE), as PostgreSQL, MySQL and SQLite
                   * do inside an expression: the tree fixes the order, never the plan */
        if (imdb_x_eval(st, xn, x->l, row, slots, env, &l, e)) return e->code;
        int a = tv(&l), stop = x->op == EX_AND ? 0 : 1;
        if (a == stop) {
            truth(out, stop);
            return IMDB_OK;
        }
        if (imdb_x_eval(st, xn, x->r, row, slots, env, &r, e)) return e->code;
        int c = tv(&r);
        truth(out, c == stop ? stop : a < 0 || c < 0 ? -1 : !stop);
        return IMDB_OK;
    }
    case EX_CMP: {
        if (imdb_x_eval(st, xn, x->l, row, slots, env, &l, e)) return e->code;
        if (x->cmp == CMP_ISNULL || x->cmp == CMP_NOTNULL) {
            truth(out, l.null == (x->cmp == CMP_ISNULL));
            return IMDB_OK;
        }
        if (x->cmp == CMP_IN || x->cmp == CMP_NOTIN) { /* P2 S1: TRUE at a match, else UNKNOWN past a NULL, else FALSE */
            if (st->ex[x->r].op == EX_SUBQ) { /* P2 S4: a subquery's values, sorted: an empty set is FALSE, even for NULL */
                const imdb_xset *s = xn[x->r].set;
                int t = 0;
                if (!s) return imdb_fail(e, IMDB_ERR_STATE, "IN's subquery unbound");
                if (s->n || s->has_null) {
                    uint64_t lo = 0, hi = s->n;
                    while (!l.null && lo < hi) {
                        uint64_t mid = lo + (hi - lo) / 2;
                        int c = imdb_x_cmp(&l, &s->v[mid]);
                        if (!c) {
                            t = 1;
                            break;
                        }
                        if (c > 0) lo = mid + 1;
                        else hi = mid;
                    }
                    if (t != 1 && (l.null || s->has_null)) t = -1;
                }
                truth(out, x->cmp == CMP_IN ? t : t < 0 ? -1 : !t);
                return IMDB_OK;
            }
            int t = l.null ? -1 : 0;
            imdb_xlist_start(&it, st, x->r);
            for (uint16_t a = imdb_xlist_next(&it); a && !l.null; a = imdb_xlist_next(&it)) {
                if (imdb_x_eval(st, xn, a, row, slots, env, &r, e)) return e->code;
                if (r.null) t = -1;
                else if (imdb_x_cmp(&l, &r) == 0) {
                    t = 1;
                    break;
                }
            }
            truth(out, x->cmp == CMP_IN ? t : t < 0 ? -1 : !t);
            return IMDB_OK;
        }
        if (imdb_x_eval(st, xn, x->r, row, slots, env, &r, e)) return e->code;
        if (x->cmp == CMP_LIKE || x->cmp == CMP_NOTLIKE) { /* P2 S1 */
            uint32_t esc = 0;
            if (x->x3) {
                if (imdb_x_eval(st, xn, x->x3, row, slots, env, &h, e)) return e->code;
                if (h.null) l.null = true;
                else if (h.len) {
                    uint32_t k2 = u8_next(h.s, h.len, 0, &esc);
                    if (k2 != h.len) return imdb_fail(e, IMDB_ERR_INVALID, "a LIKE's ESCAPE is one character");
                }
            }
            if (l.null || r.null) {
                truth(out, -1);
                return IMDB_OK;
            }
            bool m;
            if (imdb_x_like(l.s, l.len, r.s, r.len, esc, env, &m, e)) return e->code;
            truth(out, (x->cmp == CMP_LIKE) == m);
            return IMDB_OK;
        }
        if (x->cmp != CMP_BETWEEN) {
            truth(out, cmp3(x->cmp, &l, &r));
            return IMDB_OK;
        }
        /* its three operands all computed; l >= r AND l <= x3, three-valued (5 BETWEEN 10 AND NULL is FALSE) */
        if (imdb_x_eval(st, xn, x->x3, row, slots, env, &h, e)) return e->code;
        int lo = cmp3(CMP_GE, &l, &r), hi = cmp3(CMP_LE, &l, &h);
        truth(out, lo == 0 || hi == 0 ? 0 : lo < 0 || hi < 0 ? -1 : 1);
        return IMDB_OK;
    }
    case EX_FN: { /* P2 S1 */
        imdb_xlist_start(&it, st, x->l);
        if (x->fn == FN_COALESCE) { /* left to right, stopping at the first value (later ones are not computed) */
            for (uint16_t a = imdb_xlist_next(&it); a; a = imdb_xlist_next(&it)) {
                if (imdb_x_eval(st, xn, a, row, slots, env, out, e)) return e->code;
                if (!out->null) return imdb_x_widen(out, b->type, b->scale, e);
            }
            memset(out, 0, sizeof *out);
            out->null = true;
            out->type = b->type;
            out->scale = b->scale;
            return IMDB_OK;
        }
        imdb_xval a[3]; /* the binder holds every other function to three arguments */
        unsigned n = 0;
        for (uint16_t ak = imdb_xlist_next(&it); ak && n < 3; ak = imdb_xlist_next(&it))
            if (imdb_x_eval(st, xn, ak, row, slots, env, &a[n++], e)) return e->code;
        if (x->fn == FN_NULLIF) { /* NULL when the two are equal, else the first */
            *out = a[0];
            if (!a[0].null && !a[1].null && imdb_x_cmp(&a[0], &a[1]) == 0) out->null = true;
            out->type = b->type;
            out->scale = b->scale;
            return IMDB_OK;
        }
        return imdb_x_fn(x->fn, a, (uint8_t)n, b->type, b->scale, env, out, e);
    }
    case EX_CASE: { /* P2 S1: the first WHEN that holds (a simple CASE's: equal to its operand), else ELSE, else NULL */
        if (x->l && imdb_x_eval(st, xn, x->l, row, slots, env, &l, e)) return e->code;
        imdb_xlist_start(&it, st, x->r);
        for (uint16_t w = imdb_xlist_next(&it); w; w = imdb_xlist_next(&it)) {
            const sql_expr *wx = &st->ex[w];
            if (imdb_x_eval(st, xn, wx->l, row, slots, env, &r, e)) return e->code;
            bool hit = x->l ? !l.null && !r.null && imdb_x_cmp(&l, &r) == 0 : imdb_x_true(&r);
            if (hit) {
                if (imdb_x_eval(st, xn, wx->r, row, slots, env, out, e)) return e->code;
                return imdb_x_widen(out, b->type, b->scale, e);
            }
        }
        if (x->x3) {
            if (imdb_x_eval(st, xn, x->x3, row, slots, env, out, e)) return e->code;
            return imdb_x_widen(out, b->type, b->scale, e);
        }
        memset(out, 0, sizeof *out);
        out->null = true;
        out->type = b->type;
        out->scale = b->scale;
        return IMDB_OK;
    }
    case EX_CAST: { /* P2 S1 */
        if (imdb_x_eval(st, xn, x->l, row, slots, env, &l, e)) return e->code;
        imdb_column c;
        memset(&c, 0, sizeof c);
        c.type = x->ctype;
        c.scale = x->cscale;
        c.precision = x->cprec;
        return imdb_x_cast(&l, &c, env, out, e);
    }
    default:
        if (imdb_x_eval(st, xn, x->l, row, slots, env, &l, e) || imdb_x_eval(st, xn, x->r, row, slots, env, &r, e))
            return e->code;
        return imdb_x_arith(x->op, &l, &r, b->type, b->scale, out, e);
    }
}
