/* Exact FLOAT64 sums: the true sum of any multiset of finite doubles, rounded
 * once. The result does not depend on the order of the addends, so every access
 * path, thread count and replica gets the same bits. */
#ifndef IMDB_FSUM_H
#define IMDB_FSUM_H

#include <stdint.h>

#include "util.h"

/* The sum in units of 2^-1074 (the least subnormal) as 32-bit chunks held in
 * int64 limbs, carried lazily; only the chunks the addends reach are allocated
 * (a few for typical data, at most 70). */
typedef struct imdb_fsum {
    int64_t *limb;     /* limb[k] holds chunk lo + k */
    int32_t lo;
    uint32_t n;
    uint32_t pending;  /* addends since the last carry pass */
} imdb_fsum;

void imdb_fsum_free(imdb_fsum *s); /* a zeroed imdb_fsum is an empty sum */
int imdb_fsum_add(imdb_fsum *s, int64_t key, imdb_err *e);          /* a FLOAT64 key */
int imdb_fsum_merge(imdb_fsum *s, imdb_fsum *o, imdb_err *e);       /* s += o (o is normalised) */
/* Nearest, ties to even. IMDB_ERR_LIMIT when the exact sum rounds beyond the finite range. */
int imdb_fsum_result(imdb_fsum *s, int64_t *key, imdb_err *e);

#endif
