#include "fsum.h"

#include <stdlib.h>
#include <string.h>

#include "codec.h"

#define CHUNK ((int64_t)1 << 32)
#define MAX_CHUNKS 70 /* 2098 value bits + 64 bits of carries, in 32-bit chunks, and spare */

void imdb_fsum_free(imdb_fsum *s)
{
    imdb_free(s->limb);
    memset(s, 0, sizeof *s);
}

/* Makes the window cover chunks clo..chi. */
static int grow(imdb_fsum *s, int32_t clo, int32_t chi, imdb_err *e)
{
    int32_t hi = s->lo + (int32_t)s->n - 1;
    if (s->n && clo >= s->lo && chi <= hi) return IMDB_OK;
    int32_t nlo = s->n && s->lo < clo ? s->lo : clo, nhi = s->n && hi > chi ? hi : chi;
    if (nlo < 0 || nhi >= MAX_CHUNKS) return imdb_fail(e, IMDB_ERR_STATE, "FLOAT64 sum outside its range");
    int64_t *l = imdb_alloc_array((size_t)(nhi - nlo + 1), sizeof *l, e);
    if (!l) return e->code;
    if (s->n) memcpy(l + (s->lo - nlo), s->limb, s->n * sizeof *l);
    imdb_free(s->limb);
    s->limb = l;
    s->lo = nlo;
    s->n = (uint32_t)(nhi - nlo + 1);
    return IMDB_OK;
}

/* Floor carries upward until every limb but the top is in [0, 2^32) and the top
 * one is in [-2^31, 2^31). Exact: each step moves a multiple of 2^32. */
static int carry(imdb_fsum *s, imdb_err *e)
{
    while (s->n) {
        int64_t cy = 0;
        for (uint32_t k = 0; k + 1 < s->n; k++) {
            int64_t x = s->limb[k] + cy;
            int64_t low = (int64_t)((uint64_t)x & 0xffffffffull);
            cy = (x - low) / CHUNK;
            s->limb[k] = low;
        }
        int64_t t = (s->limb[s->n - 1] += cy);
        if (t >= -(CHUNK / 2) && t < CHUNK / 2) break;
        if (grow(s, s->lo, s->lo + (int32_t)s->n, e)) return e->code;
    }
    s->pending = 0;
    return IMDB_OK;
}

int imdb_fsum_add(imdb_fsum *s, int64_t key, imdb_err *e)
{
    double d = imdb_f64_value(key);
    uint64_t b;
    memcpy(&b, &d, 8);
    uint32_t ex = (uint32_t)(b >> 52) & 0x7ff;
    uint64_t m = b & ((1ull << 52) - 1);
    if (ex) m |= 1ull << 52;
    else if (!m) return IMDB_OK;
    /* normal: m * 2^(ex - 1075) = m << (ex - 1) units; subnormal: m units */
    uint32_t shift = ex ? ex - 1 : 0;
    int32_t c = (int32_t)(shift >> 5);
    unsigned __int128 v = (unsigned __int128)m << (shift & 31);
    int64_t part[3] = {(int64_t)(uint32_t)v, (int64_t)(uint32_t)(v >> 32), (int64_t)(uint64_t)(v >> 64)};
    int32_t top = part[2] ? c + 2 : part[1] ? c + 1 : c;
    if (grow(s, c, top, e)) return e->code;
    bool neg = b >> 63;
    for (int32_t k = c; k <= top; k++) s->limb[k - s->lo] += neg ? -part[k - c] : part[k - c];
    /* each addend moves a limb by less than 2^32: 2^30 of them stay below 2^62 */
    if (++s->pending >= (1u << 30)) return carry(s, e);
    return IMDB_OK;
}

int imdb_fsum_merge(imdb_fsum *s, imdb_fsum *o, imdb_err *e)
{
    if (!o->n) return IMDB_OK;
    if (carry(o, e) || carry(s, e)) return e->code;
    if (grow(s, o->lo, o->lo + (int32_t)o->n - 1, e)) return e->code;
    for (uint32_t k = 0; k < o->n; k++) s->limb[o->lo - s->lo + (int32_t)k] += o->limb[k];
    s->pending = 2; /* both sides were normalised: at most two addends' worth per limb */
    return IMDB_OK;
}

/* Bit pos of the magnitude held in chunks u (chunk lo first). */
static int mag_bit(const uint32_t *u, int32_t lo, uint32_t n, int64_t pos)
{
    if (pos < 0) return 0;
    int64_t c = pos / 32 - lo;
    if (c < 0 || c >= (int64_t)n) return 0;
    return (int)(u[c] >> (pos % 32)) & 1;
}

static bool mag_any_below(const uint32_t *u, int32_t lo, uint32_t n, int64_t pos)
{
    for (int64_t p = (int64_t)lo * 32; p < pos && p < ((int64_t)lo + n) * 32; p++)
        if (mag_bit(u, lo, n, p)) return true;
    return false;
}

int imdb_fsum_result(imdb_fsum *s, int64_t *key, imdb_err *e)
{
    *key = 0;
    if (carry(s, e)) return e->code;
    int32_t k = (int32_t)s->n - 1;
    while (k >= 0 && !s->limb[k]) k--;
    if (k < 0) return IMDB_OK; /* exactly zero: +0.0 */
    bool neg = s->limb[k] < 0;
    imdb_fsum m = {0};
    if (grow(&m, s->lo, s->lo + (int32_t)s->n - 1, e)) return e->code;
    for (uint32_t i = 0; i < s->n; i++) m.limb[i] = neg ? -s->limb[i] : s->limb[i];
    if (carry(&m, e)) {
        imdb_fsum_free(&m);
        return e->code;
    }
    uint32_t u[MAX_CHUNKS];
    for (uint32_t i = 0; i < m.n; i++) u[i] = (uint32_t)m.limb[i]; /* all in [0, 2^32) now */
    int32_t lo = m.lo;
    uint32_t n = m.n;
    imdb_fsum_free(&m);
    int32_t top = (int32_t)n - 1;
    while (!u[top]) top--;
    int64_t h = ((int64_t)lo + top) * 32 + 31 - __builtin_clz(u[top]); /* the highest set bit */
    uint64_t b;
    if (h <= 52) { /* below 2^53 units: exact, and the bits are the double's own */
        b = 0;
        for (int64_t p = 0; p <= h; p++) b |= (uint64_t)mag_bit(u, lo, n, p) << p;
    } else {
        uint64_t q = 0;
        for (int64_t p = h - 52; p <= h; p++) q |= (uint64_t)mag_bit(u, lo, n, p) << (p - (h - 52));
        if (mag_bit(u, lo, n, h - 53) && ((q & 1) || mag_any_below(u, lo, n, h - 53))) q++;
        if (q >> 53) {
            q >>= 1;
            h++;
        }
        int64_t biased = h - 51; /* the exponent of q * 2^(h - 52 - 1074), biased by 1023 */
        if (biased >= 2047) return imdb_fail(e, IMDB_ERR_LIMIT, "SUM out of FLOAT64 range");
        b = (uint64_t)biased << 52 | (q & ((1ull << 52) - 1));
    }
    if (neg) b |= 1ull << 63;
    double d;
    memcpy(&d, &b, 8);
    *key = imdb_f64_key(d);
    return IMDB_OK;
}
