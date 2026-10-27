/* Exact FLOAT64 sums for the auditor (afsum.h). */
#include "afsum.h"

#include <float.h>
#include <stdint.h>
#include <string.h>

/* At least 11 more mantissa bits than a double and the exponent range of IEEE extended: x86-64's
 * 80-bit format (and IEEE quad) qualify; a long double that is only a double does not. */
_Static_assert(LDBL_MANT_DIG >= 64 && LDBL_MAX_EXP >= 16384, "afsum needs an extended long double");

void afsum_init(afsum *s) { memset(s, 0, sizeof *s); }

/* libc only, no libm (the auditor links nothing else) */
static long double mag(long double x) { return x < 0 ? -x : x; }

/* the next double after d, up or down (d finite; -0.0 never occurs here) */
static double neighbour(double d, bool up)
{
    uint64_t b;
    memcpy(&b, &d, 8);
    if (d == 0) b = up ? 1 : 0x8000000000000001ull;
    else if ((d > 0) == up) b++;
    else b--;
    memcpy(&d, &b, 8);
    return d;
}

void afsum_add(afsum *s, double d)
{
    long double x = d;
    int i = 0;
    for (int j = 0; j < s->n; j++) {
        long double y = s->p[j];
        if (mag(x) < mag(y)) {
            long double t = x;
            x = y;
            y = t;
        }
        long double hi = x + y, lo = y - (hi - x); /* exact: |x| >= |y|, round to nearest */
        if (lo != 0) s->p[i++] = lo;
        x = hi;
    }
    if (i >= AFSUM_MAX_PARTIALS) {
        s->overflow = true;
        return;
    }
    s->p[i++] = x;
    s->n = i;
}

int afsum_result(const afsum *s, double *out)
{
    *out = 0;
    if (s->overflow) return 2;
    int k = s->n - 1;
    while (k >= 0 && s->p[k] == 0) k--;
    if (k < 0) return 0; /* exactly zero: +0.0 */
    /* the partials added downward while that stays exact: hi is then the sum rounded to long
     * double, and the rest (sum - hi) has the sign of lo, the partials being non-overlapping */
    long double hi = s->p[k], lo = 0;
    for (int j = k - 1; j >= 0; j--) {
        long double x = hi, y = s->p[j];
        hi = x + y;
        lo = y - (hi - x);
        if (lo != 0) break;
    }
    double d = (double)hi; /* nearest, ties to even, subnormals included */
    if (d > DBL_MAX || d < -DBL_MAX) {
        /* DBL_MAX + half its ulp rounds up; the sum is below it only if hi is exactly there
         * and the rest points back */
        long double edge = (long double)DBL_MAX + 0x1p970L;
        if (mag(hi) == edge && lo != 0 && (lo < 0) == (hi > 0)) {
            *out = hi > 0 ? DBL_MAX : -DBL_MAX;
            return 0;
        }
        return 1;
    }
    if ((long double)d != hi) {
        /* rounding twice (to long double, then to double) differs from once only when hi is
         * exactly halfway between d and its neighbour toward hi: the rest then decides */
        double nb = neighbour(d, hi > (long double)d);
        long double mid = ((long double)d + (long double)nb) / 2;
        if (hi == mid && lo != 0 && (lo > 0) == (nb > d)) d = nb;
    }
    *out = d;
    return 0;
}
