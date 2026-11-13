/*
 * The auditor's own reader of imagedb's canonical Parquet subset (docs/f5-design.md; src/lake.h's segment format),
 * sharing no code with src/: its own compact-protocol decoder, its own levels codec and its own writer. A file is
 * decoded by the shapes its schema version gives (bounded, not strict), then written again by apq_write from what was
 * decoded; the two must be the same bytes, so the padding, every page header, the levels, the values' layout, the
 * statistics, the footer and every chunk's SHA-256 in imagedb.chunks are checked by one rule.
 */
#ifndef APQ_H
#define APQ_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define APQ_MAX_COLS 80
#define APQ_MAX_KV 9
#define APQ_PAGE_ROWS 16384u /* a BYTE_ARRAY chunk's rows a page */

enum { APQ_BOOLEAN = 0, APQ_INT32 = 1, APQ_INT64 = 2, APQ_DOUBLE = 5, APQ_BYTES = 6, APQ_FIXED = 7 }; /* parquet.thrift Type */
enum { APQ_L_NONE, APQ_L_STRING, APQ_L_DECIMAL, APQ_L_DATE, APQ_L_TIME, APQ_L_TIMESTAMP, APQ_L_INT, APQ_L_UUID };

typedef struct apq_shape {
    const char *name;
    int32_t id;          /* the field id */
    uint8_t phys, logical;
    bool opt, utc, stats;
    uint8_t bits;        /* APQ_L_INT */
    int32_t tlen;        /* APQ_FIXED */
    int32_t scale, prec; /* APQ_L_DECIMAL */
} apq_shape;

/* a column decoded: pres (OPTIONAL) a bit a row, LSB first; fixed-width values in w bytes a row (zero where absent;
 * BOOLEAN a byte, 0 or 1); a byte array's u32 offsets (n + 1) and its bytes (an absent row empty) */
typedef struct apq_col {
    uint8_t *pres, *fixed, *data;
    uint32_t *off;
} apq_col;

typedef struct apq_file {
    uint64_t nrows;
    uint32_t ncols, nkv;
    const uint8_t *key[APQ_MAX_KV], *val[APQ_MAX_KV]; /* into the file: imagedb.chunks first */
    uint32_t klen[APQ_MAX_KV], vlen[APQ_MAX_KV];
    apq_col col[APQ_MAX_COLS];
} apq_file;

/* the value of key in a file's footer (decoded only so far as to find its pairs), or NULL; *why on a frame or footer
 * that does not decode */
const uint8_t *apq_peek(const uint8_t *f, size_t len, const char *key, uint32_t *vlen, const char **why);
/* 0, or -1 with *why: decoded by sh (ncols of them) and written again the same */
int apq_read(const uint8_t *f, size_t len, const apq_shape *sh, uint32_t ncols, apq_file *out, const char **why);
void apq_free(apq_file *a);

#endif
