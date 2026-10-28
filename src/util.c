#include "util.h"

#include <errno.h>
#include <malloc.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/random.h>

#include "fsio.h"

/* The heap's counter (util.h): every block the helpers below return is charged what malloc reserved
 * for it, and imdb_free credits the same, so the count is exact whatever size each caller asked for.
 * One for the process: the helpers know no database handle, and the pool's workers allocate too. */
static _Atomic uint64_t g_heap;

static void *charged(void *p)
{
    if (p) atomic_fetch_add_explicit(&g_heap, malloc_usable_size(p), memory_order_relaxed);
    return p;
}

uint64_t imdb_heap_bytes(void) { return atomic_load_explicit(&g_heap, memory_order_relaxed); }

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
    }
    return "unknown";
}

void *imdb_alloc(size_t n, imdb_err *e)
{
    if (n > IMDB_MAX_ALLOC) {
        imdb_fail(e, IMDB_ERR_LIMIT, "allocation of %zu bytes exceeds limit", n);
        return NULL;
    }
    void *p = imdb_io_fail_alloc(n) ? NULL : charged(calloc(1, n ? n : 1));
    if (!p) imdb_fail(e, IMDB_ERR_NOMEM, "out of memory (%zu bytes)", n);
    return p;
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
    uint8_t *q = imdb_io_fail_alloc(total) ? NULL : charged(malloc(total ? total : 1));
    if (!q) {
        imdb_fail(e, IMDB_ERR_NOMEM, "out of memory (%zu bytes)", total);
        return NULL;
    }
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
    atomic_fetch_sub_explicit(&g_heap, malloc_usable_size(p), memory_order_relaxed);
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
    void *p = imdb_io_fail_alloc(total) ? NULL : charged(aligned_alloc(32, total ? total : 32));
    if (!p) {
        imdb_fail(e, IMDB_ERR_NOMEM, "out of memory (%zu bytes)", total);
        return NULL;
    }
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
    uint8_t *q = imdb_io_fail_alloc(ncap) ? NULL : charged(malloc(ncap)); /* not realloc: see imdb_realloc_array */
    if (!q) {
        b->err = IMDB_ERR_NOMEM;
        return false;
    }
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
