#include "util.h"

#include <errno.h>
#include <malloc.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/random.h>
#include <time.h>

#include "fsio.h"

/* The heap's counter (util.h): every block the helpers below return is charged what malloc reserved
 * for it, and imdb_free credits the same, so the count is exact whatever size each caller asked for.
 * One for the process: the helpers know no database handle, and the pool's workers allocate too. */
static _Atomic uint64_t g_heap;

/* P0 R2: a read statement's ceiling on the counter (imdb_heap_ceiling_set; 0: none). A request is reserved
 * against it before its block exists (added, then taken back if that passed the ceiling), so the pool's
 * workers cannot all pass one check at once; the block's slack over the request is settled after, unchecked
 * (malloc's rounding). */
static _Atomic uint64_t g_ceiling;
static _Atomic uint64_t g_workspace; /* the ceiling's workspace, for its message */
/* This thread is inside an allocation the ceiling does not cover (a segment image's load: the segment cache's
 * own budget bounds it): what it reserves raises the ceiling first, what it frees lowers it, so the ceiling
 * keeps bounding the statement's workspace alone. A depth: loads may nest. */
static _Thread_local int t_exempt;

static void ceiling_move(uint64_t up, uint64_t down)
{
    uint64_t c = atomic_load_explicit(&g_ceiling, memory_order_relaxed);
    for (;;) {
        if (!c) return; /* none set: nothing to move */
        uint64_t n = c + up;
        n = n > down ? n - down : 1; /* stays set */
        if (atomic_compare_exchange_weak_explicit(&g_ceiling, &c, n, memory_order_relaxed, memory_order_relaxed))
            return;
    }
}

static int reserve(size_t n, size_t *held, imdb_err *e)
{
    if (!t_exempt && !atomic_load_explicit(&g_ceiling, memory_order_relaxed)) {
        *held = 0; /* no ceiling (set only between the engine thread's parallel loops): settle charges the block */
        return IMDB_OK;
    }
    *held = n;
    if (t_exempt) {
        ceiling_move(n, 0); /* first: another thread's check never sees this block without its room */
        atomic_fetch_add_explicit(&g_heap, n, memory_order_relaxed);
        return IMDB_OK;
    }
    uint64_t now = atomic_fetch_add_explicit(&g_heap, n, memory_order_relaxed) + n;
    uint64_t c = atomic_load_explicit(&g_ceiling, memory_order_relaxed);
    if (c && now > c) {
        atomic_fetch_sub_explicit(&g_heap, n, memory_order_relaxed);
        return imdb_fail(e, IMDB_ERR_LIMIT,
                         "statement memory: this statement would hold more than its %llu bytes (SET statement_memory); "
                         "narrow it, or add LIMIT",
                         (unsigned long long)atomic_load_explicit(&g_workspace, memory_order_relaxed));
    }
    return IMDB_OK;
}

static void unreserve(size_t n)
{
    atomic_fetch_sub_explicit(&g_heap, n, memory_order_relaxed);
    if (t_exempt) ceiling_move(0, n);
}

/* p, just allocated for a reservation of n: the counter takes what malloc reserved for it */
static void *settle(void *p, size_t n) /* n: what reserve held (0 on its fast path) */
{
    size_t u = malloc_usable_size(p);
    if (u > n) {
        if (t_exempt) ceiling_move(u - n, 0);
        atomic_fetch_add_explicit(&g_heap, u - n, memory_order_relaxed);
    } else if (u < n) {
        atomic_fetch_sub_explicit(&g_heap, n - u, memory_order_relaxed);
        if (t_exempt) ceiling_move(0, n - u);
    }
    return p;
}

uint64_t imdb_heap_bytes(void) { return atomic_load_explicit(&g_heap, memory_order_relaxed); }
void imdb_heap_ceiling_set(uint64_t ceiling, uint64_t workspace)
{
    atomic_store_explicit(&g_workspace, workspace, memory_order_relaxed);
    atomic_store_explicit(&g_ceiling, ceiling, memory_order_relaxed);
}
uint64_t imdb_heap_ceiling(void) { return atomic_load_explicit(&g_ceiling, memory_order_relaxed); }
void imdb_heap_exempt_begin(void) { t_exempt++; }
void imdb_heap_exempt_end(void) { t_exempt--; }

int imdb_fail(imdb_err *e, int code, const char *fmt, ...)
{
    if (e && e->code == IMDB_OK) {
        e->code = code;
        va_list ap;
        va_start(ap, fmt);
        vsnprintf(e->msg, sizeof e->msg, fmt, ap);
        va_end(ap);
    }
    return code;
}

void imdb_err_clear(imdb_err *e)
{
    e->code = IMDB_OK;
    e->msg[0] = '\0';
}

const char *imdb_err_name(int code)
{
    switch (code) {
    case IMDB_OK: return "ok";
    case IMDB_ERR_IO: return "io";
    case IMDB_ERR_CORRUPT: return "corrupt";
    case IMDB_ERR_LIMIT: return "limit";
    case IMDB_ERR_INVALID: return "invalid";
    case IMDB_ERR_NOMEM: return "nomem";
    case IMDB_ERR_CONSTRAINT: return "constraint";
    case IMDB_ERR_VERIFY: return "verify";
    case IMDB_ERR_AUTH: return "auth";
    case IMDB_ERR_STATE: return "state";
    case IMDB_ERR_SYNTAX: return "syntax";
    case IMDB_ERR_NOTFOUND: return "notfound";
    case IMDB_ERR_UNSUPPORTED: return "unsupported";
    case IMDB_ERR_HISTORY: return "history";
    case IMDB_ERR_CONFLICT: return "conflict";
    case IMDB_ERR_CANCELLED: return "cancelled";
    }
    return "unknown";
}

void *imdb_alloc(size_t n, imdb_err *e)
{
    if (n > IMDB_MAX_ALLOC) {
        imdb_fail(e, IMDB_ERR_LIMIT, "allocation of %zu bytes exceeds limit", n);
        return NULL;
    }
    size_t req = n ? n : 1;
    if (imdb_io_fail_alloc(n)) {
        imdb_fail(e, IMDB_ERR_NOMEM, "out of memory (%zu bytes)", n);
        return NULL;
    }
    size_t held;
    if (reserve(req, &held, e)) return NULL; /* past a read statement's ceiling (P0 R2) */
    void *p = calloc(1, req);
    if (!p) {
        unreserve(held);
        imdb_fail(e, IMDB_ERR_NOMEM, "out of memory (%zu bytes)", n);
        return NULL;
    }
    return settle(p, held);
}

void *imdb_alloc_array(size_t count, size_t size, imdb_err *e)
{
    size_t total;
    if (imdb_mul_ovf(count, size, &total) || total > IMDB_MAX_ALLOC) {
        imdb_fail(e, IMDB_ERR_LIMIT, "array allocation %zu x %zu exceeds limit", count, size);
        return NULL;
    }
    return imdb_alloc(total, e);
}

/* Never realloc: it may move the block and free the old one unwiped, and these
 * arrays can hold row bytes, salts or key values that a later ERASE must be able
 * to remove from memory. Growth copies, wipes the old block, then frees it.
 * old_count must not exceed what p was allocated with. */
void *imdb_realloc_array(void *p, size_t old_count, size_t new_count, size_t size, imdb_err *e)
{
    size_t total, old_total;
    if (imdb_mul_ovf(new_count, size, &total) || total > IMDB_MAX_ALLOC ||
        imdb_mul_ovf(old_count, size, &old_total)) {
        imdb_fail(e, IMDB_ERR_LIMIT, "array growth %zu x %zu exceeds limit", new_count, size);
        return NULL;
    }
    if (!p) old_total = 0; /* a NULL block with a stale count was harmless before; keep it so */
    size_t req = total ? total : 1;
    if (imdb_io_fail_alloc(total)) {
        imdb_fail(e, IMDB_ERR_NOMEM, "out of memory (%zu bytes)", total);
        return NULL;
    }
    size_t held;
    if (reserve(req, &held, e)) return NULL; /* the old block is still held: both count while the copy is made */
    uint8_t *q = malloc(req);
    if (!q) {
        unreserve(held);
        imdb_fail(e, IMDB_ERR_NOMEM, "out of memory (%zu bytes)", total);
        return NULL;
    }
    settle(q, held);
    size_t keep = old_total < total ? old_total : total;
    if (keep) memcpy(q, p, keep);
    if (total > keep) memset(q + keep, 0, total - keep);
    if (p) {
        imdb_wipe(p, old_total);
        imdb_free(p);
    }
    return q;
}

void imdb_free(void *p)
{
    if (!p) return;
    size_t u = malloc_usable_size(p);
    atomic_fetch_sub_explicit(&g_heap, u, memory_order_relaxed);
    if (t_exempt) ceiling_move(0, u); /* an exempt section's own block (seg_load's temporaries) */
    free(p);
}

void *imdb_alloc_aligned(size_t count, size_t size, imdb_err *e)
{
    size_t total;
    if (imdb_mul_ovf(count, size, &total) || total > IMDB_MAX_ALLOC) {
        imdb_fail(e, IMDB_ERR_LIMIT, "aligned allocation %zu x %zu exceeds limit", count, size);
        return NULL;
    }
    total = (total + 31) & ~(size_t)31;
    size_t req = total ? total : 32;
    if (imdb_io_fail_alloc(total)) {
        imdb_fail(e, IMDB_ERR_NOMEM, "out of memory (%zu bytes)", total);
        return NULL;
    }
    size_t held;
    if (reserve(req, &held, e)) return NULL;
    void *p = aligned_alloc(32, req);
    if (!p) {
        unreserve(held);
        imdb_fail(e, IMDB_ERR_NOMEM, "out of memory (%zu bytes)", total);
        return NULL;
    }
    settle(p, held);
    memset(p, 0, total ? total : 32);
    return p;
}

char *imdb_strndup(const char *s, size_t n, imdb_err *e)
{
    size_t total;
    if (imdb_add_ovf(n, (size_t)1, &total)) {
        imdb_fail(e, IMDB_ERR_LIMIT, "string too long");
        return NULL;
    }
    char *d = imdb_alloc(total, e);
    if (d) {
        memcpy(d, s, n);
        d[n] = '\0';
    }
    return d;
}

void imdb_wipe(void *p, size_t n)
{
    if (p && n) explicit_bzero(p, n);
}

int imdb_random(void *out, size_t n, imdb_err *e)
{
    uint8_t *p = out;
    while (n) {
        ssize_t got = getrandom(p, n, 0);
        if (got < 0) {
            if (errno == EINTR) continue;
            return imdb_fail(e, IMDB_ERR_IO, "getrandom failed: %s", strerror(errno));
        }
        p += got;
        n -= (size_t)got;
    }
    return IMDB_OK;
}

/* ---- buffer ----------------------------------------------------------- */

void imdb_buf_init(imdb_buf *b)
{
    b->p = NULL;
    b->len = b->cap = 0;
    b->err = IMDB_OK;
}

void imdb_buf_free(imdb_buf *b)
{
    imdb_free(b->p);
    imdb_buf_init(b);
}

void imdb_buf_wipe_free(imdb_buf *b)
{
    imdb_wipe(b->p, b->cap);
    imdb_buf_free(b);
}

bool imdb_buf_reserve_limit(imdb_buf *b, size_t extra, size_t limit)
{
    if (b->err) return false;
    if (limit > IMDB_MAX_ALLOC) limit = IMDB_MAX_ALLOC;
    size_t need;
    if (imdb_add_ovf(b->len, extra, &need) || need > limit || b->cap > limit) {
        b->err = IMDB_ERR_LIMIT;
        return false;
    }
    if (need <= b->cap) return true;
    size_t ncap = b->cap ? b->cap : 256;
    while (ncap < need) {
        if (imdb_mul_ovf(ncap, (size_t)2, &ncap)) {
            ncap = need;
            break;
        }
    }
    if (ncap > limit) ncap = need;
    if (imdb_io_fail_alloc(ncap)) {
        b->err = IMDB_ERR_NOMEM;
        return false;
    }
    imdb_err er = {0};
    size_t held;
    if (reserve(ncap, &held, &er)) { /* past a read statement's ceiling (P0 R2) */
        b->err = IMDB_ERR_LIMIT;
        return false;
    }
    uint8_t *q = malloc(ncap); /* not realloc: see imdb_realloc_array */
    if (!q) {
        unreserve(held);
        b->err = IMDB_ERR_NOMEM;
        return false;
    }
    settle(q, held);
    if (b->len) memcpy(q, b->p, b->len);
    memset(q + b->len, 0, ncap - b->len);
    if (b->p) {
        imdb_wipe(b->p, b->cap);
        imdb_free(b->p);
    }
    b->p = q;
    b->cap = ncap;
    return true;
}

bool imdb_buf_reserve(imdb_buf *b, size_t extra) { return imdb_buf_reserve_limit(b, extra, IMDB_MAX_ALLOC); }

void imdb_buf_put(imdb_buf *b, const void *src, size_t n)
{
    if (!n || !imdb_buf_reserve(b, n)) return;
    memcpy(b->p + b->len, src, n);
    b->len += n;
}

void imdb_buf_put_u8(imdb_buf *b, uint8_t v) { imdb_buf_put(b, &v, 1); }

void imdb_buf_put_u16(imdb_buf *b, uint16_t v)
{
    uint8_t t[2] = {(uint8_t)v, (uint8_t)(v >> 8)};
    imdb_buf_put(b, t, 2);
}

void imdb_buf_put_u32(imdb_buf *b, uint32_t v)
{
    uint8_t t[4];
    imdb_le32(t, v);
    imdb_buf_put(b, t, 4);
}

void imdb_buf_put_u64(imdb_buf *b, uint64_t v)
{
    uint8_t t[8];
    imdb_le64(t, v);
    imdb_buf_put(b, t, 8);
}

void imdb_buf_put_zeros(imdb_buf *b, size_t n)
{
    if (!n || !imdb_buf_reserve(b, n)) return;
    memset(b->p + b->len, 0, n);
    b->len += n;
}

void imdb_buf_put_str(imdb_buf *b, const char *s) { imdb_buf_put(b, s, strlen(s)); }

void imdb_buf_printf(imdb_buf *b, const char *fmt, ...)
{
    if (b->err) return;
    va_list ap;
    va_start(ap, fmt);
    char small[256];
    int n = vsnprintf(small, sizeof small, fmt, ap);
    va_end(ap);
    if (n < 0) {
        b->err = IMDB_ERR_INVALID;
        return;
    }
    if ((size_t)n < sizeof small) {
        imdb_buf_put(b, small, (size_t)n);
        return;
    }
    if (!imdb_buf_reserve(b, (size_t)n + 1)) return;
    va_start(ap, fmt);
    vsnprintf((char *)b->p + b->len, (size_t)n + 1, fmt, ap);
    va_end(ap);
    b->len += (size_t)n;
}

int imdb_buf_check(const imdb_buf *b, imdb_err *e)
{
    if (b->err == IMDB_OK) return IMDB_OK;
    if (b->err == IMDB_ERR_LIMIT) /* its own bound, or a read statement's memory (SET statement_memory) */
        return imdb_fail(e, b->err, "buffer: past its limit or the statement's memory (SET statement_memory)");
    return imdb_fail(e, b->err, "buffer: %s", imdb_err_name(b->err));
}

/* ---- hex ---------------------------------------------------------------- */

void imdb_hex(const uint8_t *in, size_t n, char *out)
{
    static const char d[] = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) {
        out[2 * i] = d[in[i] >> 4];
        out[2 * i + 1] = d[in[i] & 15];
    }
    out[2 * n] = '\0';
}

static int hexval(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    return -1; /* uppercase rejected on purpose: one canonical spelling */
}

bool imdb_unhex(const char *in, size_t inlen, uint8_t *out, size_t n)
{
    if (inlen != 2 * n) return false;
    for (size_t i = 0; i < n; i++) {
        int hi = hexval(in[2 * i]), lo = hexval(in[2 * i + 1]);
        if (hi < 0 || lo < 0) return false;
        out[i] = (uint8_t)(hi << 4 | lo);
    }
    return true;
}

bool imdb_ct_eq(const void *a, const void *b, size_t n)
{
    const volatile uint8_t *x = a, *y = b;
    uint8_t acc = 0;
    for (size_t i = 0; i < n; i++) acc |= (uint8_t)(x[i] ^ y[i]);
    return acc == 0;
}

uint64_t imdb_mono_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000u + (uint64_t)ts.tv_nsec;
}

/* below 4 us one bucket a microsecond; from there four an octave: [4,5) [5,6) [6,7) [7,8), [8,10) [10,12) .. */
unsigned imdb_hist_bucket(uint64_t us)
{
    if (us < 4) return (unsigned)us;
    unsigned e = 63u - (unsigned)__builtin_clzll(us); /* 2.. */
    unsigned i = 4u * (e - 1u) + (unsigned)((us >> (e - 2u)) & 3u);
    return i < IMDB_HIST_N ? i : IMDB_HIST_N - 1;
}

uint64_t imdb_hist_upper(unsigned i)
{
    if (i < 4) return i;
    unsigned e = i / 4u + 1u, sub = i % 4u;
    return ((uint64_t)(5u + sub) << (e - 2u)) - 1u;
}

void imdb_hist_add(imdb_hist *h, uint64_t us)
{
    h->n++;
    h->sum_us += us;
    if (us > h->max_us) h->max_us = us;
    h->b[imdb_hist_bucket(us)]++;
}

void imdb_hist_add_atomic(imdb_hist *h, uint64_t us)
{
    __atomic_fetch_add(&h->n, 1, __ATOMIC_RELAXED);
    __atomic_fetch_add(&h->sum_us, us, __ATOMIC_RELAXED);
    __atomic_fetch_add(&h->b[imdb_hist_bucket(us)], 1, __ATOMIC_RELAXED);
    uint64_t m = __atomic_load_n(&h->max_us, __ATOMIC_RELAXED);
    while (us > m && !__atomic_compare_exchange_n(&h->max_us, &m, us, true, __ATOMIC_RELAXED, __ATOMIC_RELAXED)) {
    }
}

uint64_t imdb_hist_quantile(const imdb_hist *h, unsigned permille)
{
    uint64_t n = __atomic_load_n(&h->n, __ATOMIC_RELAXED);
    if (!n) return 0;
    uint64_t want = (n * permille + 999u) / 1000u, seen = 0; /* the ceil: the 990th permille of 100 is the 99th */
    if (!want) want = 1;
    uint64_t max = __atomic_load_n(&h->max_us, __ATOMIC_RELAXED);
    for (unsigned i = 0; i < IMDB_HIST_N; i++) {
        seen += __atomic_load_n(&h->b[i], __ATOMIC_RELAXED);
        if (seen >= want) {
            uint64_t u = imdb_hist_upper(i);
            return u < max ? u : max;
        }
    }
    return max;
}
