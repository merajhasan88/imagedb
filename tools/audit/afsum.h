/* Exact FLOAT64 sums for the auditor, by another method than the engine's (src/fsum.c keeps an
 * integer superaccumulator): Shewchuk's non-overlapping partials (the msum of Python's
 * math.fsum), held in an extended long double. Its 15-bit exponent leaves room for any sum of
 * doubles, so no partial overflows (msum's "intermediate overflow") or underflows, and every
 * two-sum is exact. The result is the exact sum rounded once: nearest, ties to even; exactly
 * zero is +0.0. Shares no code with src/, like acrypto.c. */
#ifndef AFSUM_H
#define AFSUM_H

#include <stdbool.h>

/* non-overlapping partials of 64 bits each over the 2^-1074 .. 2^1088 that sums of up to 2^64
 * doubles reach: at most 34 */
#define AFSUM_MAX_PARTIALS 64

typedef struct afsum {
    long double p[AFSUM_MAX_PARTIALS]; /* increasing magnitude */
    int n;
    bool overflow; /* more partials than the bound above: cannot happen */
} afsum;

void afsum_init(afsum *s);
void afsum_add(afsum *s, double x); /* x finite */
/* 0: *out holds the sum; 1: it rounds beyond the finite range (the engine's "SUM out of FLOAT64
 * range"); 2: the partials' bound was broken */
int afsum_result(const afsum *s, double *out);

#endif
