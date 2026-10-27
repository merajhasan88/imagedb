/* CREATE INDEX's ordered structure (oidx.h). */
#include "oidx.h"

#include <stdlib.h>
#include <string.h>

/* the words of one entry */
static size_t width(const imdb_oidx *x) { return (size_t)x->nk + 1; }

/* key a against key b, word by word: -1, 0 or 1 */
static int kcmp(const uint64_t *a, const uint64_t *b, uint8_t nk)
{
    for (uint8_t i = 0; i < nk; i++)
        if (a[i] != b[i]) return a[i] < b[i] ? -1 : 1;
    return 0;
}

/* whole entries, the key and then the vid (qsort_r: arg is the width) */
static int cmp_ent(const void *a, const void *b, void *arg)
{
    const uint64_t *x = a, *y = b;
    size_t w = *(const size_t *)arg;
    for (size_t i = 0; i < w; i++)
        if (x[i] != y[i]) return x[i] < y[i] ? -1 : 1;
    return 0;
}

static uint64_t *alloc_ents(uint64_t n, size_t w, imdb_err *e) { return imdb_alloc_array(n, w * sizeof(uint64_t), e); }

static void free_run(uint64_t *r, uint64_t n, size_t w)
{
    if (!r) return;
    imdb_wipe(r, n * w * sizeof *r);
    free(r);
}

/* the two sorted runs merged into a new one */
static uint64_t *merge(const uint64_t *a, uint64_t na, const uint64_t *b, uint64_t nb, size_t w, imdb_err *e)
{
    uint64_t *m = alloc_ents(na + nb, w, e);
    if (!m) return NULL;
    size_t wb = w * sizeof *m;
    uint64_t i = 0, j = 0, k = 0;
    while (i < na && j < nb) {
        const uint64_t *s = cmp_ent(a + i * w, b + j * w, &w) <= 0 ? a + i++ * w : b + j++ * w;
        memcpy(m + k++ * w, s, wb);
    }
    if (i < na) memcpy(m + k * w, a + i * w, (na - i) * wb), k += na - i;
    if (j < nb) memcpy(m + k * w, b + j * w, (nb - j) * wb);
    return m;
}

void imdb_oidx_init(imdb_oidx *x, uint8_t nk)
{
    memset(x, 0, sizeof *x);
    x->nk = nk;
}

int imdb_oidx_insert(imdb_oidx *x, const uint64_t *key, uint64_t vid, imdb_err *e)
{
    size_t w = width(x);
    if (!x->buf && !(x->buf = alloc_ents(IMDB_OIDX_BASE, w, e))) return e->code;
    uint64_t *slot = x->buf + (size_t)x->nbuf * w;
    memcpy(slot, key, x->nk * sizeof *key);
    slot[x->nk] = vid;
    if (++x->nbuf < IMDB_OIDX_BASE) return IMDB_OK;
    /* the buffer is full: sorted, it is a level-0 run, carried down while levels are taken */
    qsort_r(x->buf, IMDB_OIDX_BASE, w * sizeof *x->buf, cmp_ent, &w);
    uint64_t *carry = x->buf;
    uint64_t n = IMDB_OIDX_BASE;
    x->buf = NULL;
    x->nbuf = 0;
    for (int i = 0; i < IMDB_OIDX_LEVELS; i++, n <<= 1) {
        if (!x->run[i]) {
            x->run[i] = carry;
            return IMDB_OK;
        }
        uint64_t *m = merge(x->run[i], n, carry, n, w, e);
        if (!m) {
            /* after a durable commit: the caller stops the handle (reads are refused), and a
             * reopen builds the index again, so the entries the carry held may go */
            free_run(carry, n, w);
            return e->code;
        }
        free_run(x->run[i], n, w);
        free_run(carry, n, w);
        x->run[i] = NULL;
        carry = m;
    }
    free_run(carry, n, w);
    return imdb_fail(e, IMDB_ERR_LIMIT, "ordered index: too many entries");
}

int imdb_oidx_build(imdb_oidx *x, uint64_t *all, uint64_t n, imdb_err *e)
{
    imdb_oidx_free(x);
    size_t w = width(x);
    if (n) qsort_r(all, n, w * sizeof *all, cmp_ent, &w);
    /* binary decomposition of n: the remainder below IMDB_OIDX_BASE stays in the buffer */
    uint64_t at = 0, rest = n % IMDB_OIDX_BASE, full = n / IMDB_OIDX_BASE;
    int rc = IMDB_OK;
    for (int i = IMDB_OIDX_LEVELS - 1; i >= 0 && !rc; i--) {
        if (!(full >> i & 1)) continue;
        uint64_t len = (uint64_t)IMDB_OIDX_BASE << i;
        x->run[i] = alloc_ents(len, w, e);
        if (!x->run[i]) rc = e->code;
        else memcpy(x->run[i], all + at * w, len * w * sizeof *all);
        at += len;
    }
    if (!rc && rest) {
        x->buf = alloc_ents(IMDB_OIDX_BASE, w, e);
        if (!x->buf) rc = e->code;
        else memcpy(x->buf, all + at * w, rest * w * sizeof *all);
        x->nbuf = (uint32_t)rest;
    }
    /* the runs are in any order relative to each other: each is sorted, which is all a range needs */
    if (all) {
        imdb_wipe(all, n * w * sizeof *all);
        free(all);
    }
    if (rc) imdb_oidx_free(x);
    return rc;
}

void imdb_oidx_free(imdb_oidx *x)
{
    size_t w = width(x);
    for (int i = 0; i < IMDB_OIDX_LEVELS; i++) free_run(x->run[i], (uint64_t)IMDB_OIDX_BASE << i, w);
    free_run(x->buf, IMDB_OIDX_BASE, w);
    imdb_oidx_init(x, x->nk);
}

/* the first entry of the run whose key is >= lo */
static uint64_t lower(const uint64_t *r, uint64_t n, const uint64_t *lo, uint8_t nk)
{
    size_t w = (size_t)nk + 1;
    uint64_t a = 0, b = n;
    while (a < b) {
        uint64_t m = a + (b - a) / 2;
        if (kcmp(r + m * w, lo, nk) < 0) a = m + 1;
        else b = m;
    }
    return a;
}

/* the first entry of the run whose key is > hi */
static uint64_t upper(const uint64_t *r, uint64_t n, const uint64_t *hi, uint8_t nk)
{
    size_t w = (size_t)nk + 1;
    uint64_t a = 0, b = n;
    while (a < b) {
        uint64_t m = a + (b - a) / 2;
        if (kcmp(r + m * w, hi, nk) <= 0) a = m + 1;
        else b = m;
    }
    return a;
}

int imdb_oidx_range(const imdb_oidx *x, const uint64_t *lo, const uint64_t *hi,
                    int (*f)(void *ctx, const uint64_t *key, uint64_t vid), void *ctx)
{
    if (kcmp(lo, hi, x->nk) > 0) return IMDB_OK;
    size_t w = width(x);
    for (int i = 0; i < IMDB_OIDX_LEVELS; i++) {
        const uint64_t *r = x->run[i];
        if (!r) continue;
        uint64_t n = (uint64_t)IMDB_OIDX_BASE << i;
        for (uint64_t k = lower(r, n, lo, x->nk); k < n && kcmp(r + k * w, hi, x->nk) <= 0; k++) {
            int rc = f(ctx, r + k * w, r[k * w + x->nk]);
            if (rc) return rc;
        }
    }
    for (uint32_t k = 0; k < x->nbuf; k++) {
        const uint64_t *b = x->buf + (size_t)k * w;
        if (kcmp(b, lo, x->nk) >= 0 && kcmp(b, hi, x->nk) <= 0) {
            int rc = f(ctx, b, b[x->nk]);
            if (rc) return rc;
        }
    }
    return IMDB_OK;
}

/* the entries imdb_oidx_range would visit, without visiting them: two searches per run */
uint64_t imdb_oidx_count(const imdb_oidx *x, const uint64_t *lo, const uint64_t *hi)
{
    if (kcmp(lo, hi, x->nk) > 0) return 0;
    size_t w = width(x);
    uint64_t c = 0;
    for (int i = 0; i < IMDB_OIDX_LEVELS; i++) {
        const uint64_t *r = x->run[i];
        if (!r) continue;
        uint64_t n = (uint64_t)IMDB_OIDX_BASE << i;
        c += upper(r, n, hi, x->nk) - lower(r, n, lo, x->nk);
    }
    for (uint32_t k = 0; k < x->nbuf; k++) {
        const uint64_t *b = x->buf + (size_t)k * w;
        c += kcmp(b, lo, x->nk) >= 0 && kcmp(b, hi, x->nk) <= 0;
    }
    return c;
}

uint64_t imdb_oidx_bytes(const imdb_oidx *x)
{
    uint64_t eb = imdb_oidx_entry_bytes(x->nk), b = x->buf ? IMDB_OIDX_BASE * eb : 0;
    for (int i = 0; i < IMDB_OIDX_LEVELS; i++)
        if (x->run[i]) b += ((uint64_t)IMDB_OIDX_BASE << i) * eb;
    return b;
}

uint64_t imdb_oidx_growth(const imdb_oidx *x, uint64_t k)
{
    /* the counter the runs form, played forward: a filled buffer merges each taken level into
     * one twice its size (counted whole, though the inputs are freed after); a new buffer each time */
    uint64_t eb = imdb_oidx_entry_bytes(x->nk), taken = 0, g = 0, nbuf = x->nbuf;
    for (int i = 0; i < IMDB_OIDX_LEVELS && i < 64; i++)
        if (x->run[i]) taken |= 1ull << i;
    bool buf = x->buf != NULL;
    while (k) {
        if (!buf) {
            g += IMDB_OIDX_BASE * eb;
            buf = true;
        }
        uint64_t room = IMDB_OIDX_BASE - nbuf;
        if (k < room) break;
        k -= room;
        nbuf = 0;
        buf = false;
        uint64_t n = IMDB_OIDX_BASE;
        for (int i = 0; i < 63 && (taken >> i & 1); i++, n <<= 1) g += 2 * n * eb;
        taken++; /* a carry is a binary increment: the taken levels it passes empty, the next one taken */
    }
    return g;
}
