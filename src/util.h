/*
 * imagedb — memory-safety primitives shared by every module.
 *
 *   - imdb_err:   error code + message; messages never contain row values.
 *   - imdb_buf:   growable byte buffer with a sticky error flag.
 *   - imdb_rd:    bounded reader; every read is checked against the remaining
 *                 length with the overflow-safe idiom (n > len - off).
 *   - checked size arithmetic and array allocation.
 */
#ifndef IMDB_UTIL_H
#define IMDB_UTIL_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "limits.h"

enum {
    IMDB_OK = 0,
    IMDB_ERR_IO = -1,          /* operating-system I/O failure               */
    IMDB_ERR_CORRUPT = -2,     /* stored bytes fail structural checks        */
    IMDB_ERR_LIMIT = -3,       /* input exceeds a limit from limits.h        */
    IMDB_ERR_INVALID = -4,     /* malformed input (bad UTF-8, bad literal)   */
    IMDB_ERR_NOMEM = -5,
    IMDB_ERR_CONSTRAINT = -6,  /* primary-key / schema constraint violated   */
    IMDB_ERR_VERIFY = -7,      /* hash, digest or chain verification failed  */
    IMDB_ERR_AUTH = -8,        /* MAC verification failed                    */
    IMDB_ERR_STATE = -9,       /* operation not valid in the current state   */
    IMDB_ERR_SYNTAX = -10,     /* SQL syntax error                           */
    IMDB_ERR_NOTFOUND = -11,
    IMDB_ERR_UNSUPPORTED = -12,
    IMDB_ERR_HISTORY = -13,    /* requested history was purged               */
    IMDB_ERR_CONFLICT = -14,   /* a concurrent commit won: retry the transaction */
};

typedef struct imdb_err {
    int code;
    char msg[256];
} imdb_err;

/* Records the first error only; returns code so callers can `return imdb_fail(...)`.
 * The format string must be a literal (enforced by -Wformat=2 -Werror). */
int imdb_fail(imdb_err *e, int code, const char *fmt, ...)
    __attribute__((format(printf, 3, 4)));
void imdb_err_clear(imdb_err *e);
const char *imdb_err_name(int code);

/* ---- checked arithmetic --------------------------------------------- */
#define imdb_add_ovf(a, b, r) __builtin_add_overflow((a), (b), (r))
#define imdb_mul_ovf(a, b, r) __builtin_mul_overflow((a), (b), (r))
#define imdb_sub_ovf(a, b, r) __builtin_sub_overflow((a), (b), (r))

/* Allocation helpers: refuse overflowing or oversized requests. All returned
 * memory is zeroed so no uninitialised byte can reach a file or a hash. */
void *imdb_alloc(size_t n, imdb_err *e);
void *imdb_alloc_array(size_t count, size_t size, imdb_err *e);
void *imdb_realloc_array(void *p, size_t old_count, size_t new_count, size_t size, imdb_err *e);
void imdb_free(void *p);
/* 32-byte aligned, zeroed (for SIMD-friendly arrays such as LtHash states). */
void *imdb_alloc_aligned(size_t count, size_t size, imdb_err *e);
char *imdb_strndup(const char *s, size_t n, imdb_err *e);

/* Wipe memory that held erased data or key material. */
void imdb_wipe(void *p, size_t n);

/* Kernel CSPRNG (getrandom); 0 on success. */
int imdb_random(void *out, size_t n, imdb_err *e);

/* ---- growable buffer -------------------------------------------------- */
typedef struct imdb_buf {
    uint8_t *p;
    size_t len;
    size_t cap;
    int err;        /* sticky: IMDB_OK or the first error code */
} imdb_buf;

void imdb_buf_init(imdb_buf *b);
void imdb_buf_free(imdb_buf *b);
void imdb_buf_wipe_free(imdb_buf *b);
bool imdb_buf_reserve(imdb_buf *b, size_t extra);
/* Bounds allocated capacity, including geometric growth; failure is sticky. */
bool imdb_buf_reserve_limit(imdb_buf *b, size_t extra, size_t limit);
void imdb_buf_put(imdb_buf *b, const void *src, size_t n);
void imdb_buf_put_u8(imdb_buf *b, uint8_t v);
void imdb_buf_put_u16(imdb_buf *b, uint16_t v);
void imdb_buf_put_u32(imdb_buf *b, uint32_t v);
void imdb_buf_put_u64(imdb_buf *b, uint64_t v);
void imdb_buf_put_zeros(imdb_buf *b, size_t n);
void imdb_buf_put_str(imdb_buf *b, const char *s); /* bytes without NUL */
/* printf-style append; format must be a literal. */
void imdb_buf_printf(imdb_buf *b, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
/* Returns IMDB_OK or the sticky error, filling e. */
int imdb_buf_check(const imdb_buf *b, imdb_err *e);

/* ---- bounded reader -------------------------------------------------- */
typedef struct imdb_rd {
    const uint8_t *p;
    size_t len;
    size_t off;     /* invariant: off <= len */
    bool err;       /* sticky: any short read sets it; later reads return 0 */
} imdb_rd;

static inline void imdb_rd_init(imdb_rd *r, const void *p, size_t len)
{
    r->p = (const uint8_t *)p;
    r->len = len;
    r->off = 0;
    r->err = false;
}

static inline size_t imdb_rd_left(const imdb_rd *r) { return r->len - r->off; }

static inline bool imdb_rd_need(imdb_rd *r, size_t n)
{
    if (r->err || n > r->len - r->off) {
        r->err = true;
        return false;
    }
    return true;
}

/* Returns NULL (and sets the sticky error) on a short read; callers must check. */
static inline const uint8_t *imdb_rd_bytes(imdb_rd *r, size_t n)
{
    if (!imdb_rd_need(r, n))
        return NULL;
    const uint8_t *q = r->p + r->off;
    r->off += n;
    return q;
}

static inline uint8_t imdb_rd_u8(imdb_rd *r)
{
    if (!imdb_rd_need(r, 1)) return 0;
    return r->p[r->off++];
}

static inline uint16_t imdb_rd_u16(imdb_rd *r)
{
    if (!imdb_rd_need(r, 2)) return 0;
    const uint8_t *q = r->p + r->off;
    r->off += 2;
    return (uint16_t)(q[0] | (uint16_t)q[1] << 8);
}

static inline uint32_t imdb_rd_u32(imdb_rd *r)
{
    if (!imdb_rd_need(r, 4)) return 0;
    const uint8_t *q = r->p + r->off;
    r->off += 4;
    return (uint32_t)q[0] | (uint32_t)q[1] << 8 | (uint32_t)q[2] << 16 | (uint32_t)q[3] << 24;
}

static inline uint64_t imdb_rd_u64(imdb_rd *r)
{
    if (!imdb_rd_need(r, 8)) return 0;
    const uint8_t *q = r->p + r->off;
    r->off += 8;
    uint64_t v = 0;
    for (int i = 7; i >= 0; i--) v = v << 8 | q[i];
    return v;
}

/* Copies n bytes into dst (zero-filled on short read). */
static inline void imdb_rd_copy(imdb_rd *r, void *dst, size_t n)
{
    if (!imdb_rd_need(r, n)) {
        memset(dst, 0, n);
        return;
    }
    memcpy(dst, r->p + r->off, n);
    r->off += n;
}

/* ---- little-endian helpers for fixed buffers -------------------------- */
static inline void imdb_le32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24);
}
static inline void imdb_le64(uint8_t *p, uint64_t v)
{
    for (int i = 0; i < 8; i++) p[i] = (uint8_t)(v >> (8 * i));
}
static inline uint32_t imdb_get_le32(const uint8_t *p)
{
    return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}
static inline uint64_t imdb_get_le64(const uint8_t *p)
{
    uint64_t v = 0;
    for (int i = 7; i >= 0; i--) v = v << 8 | p[i];
    return v;
}

/* ---- hex ----------------------------------------------------------- */
void imdb_hex(const uint8_t *in, size_t n, char *out /* 2n+1 */);
/* Strict: exactly 2n lowercase hex digits. */
bool imdb_unhex(const char *in, size_t inlen, uint8_t *out, size_t n);

/* Constant-time comparison for MACs. */
bool imdb_ct_eq(const void *a, const void *b, size_t n);

#endif
