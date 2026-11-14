/*
 * F5 (docs/f5-design.md): imagedb's canonical Parquet subset, the lake's segment file.
 *
 * One row group; per column one chunk of v1 data pages, PLAIN, UNCOMPRESSED: a fixed-width column's chunk one page, a
 * BYTE_ARRAY column's pages of PQ_PAGE_ROWS rows (by row count, never by size); each chunk preceded by zero padding so
 * that its first page's values begin 8-byte aligned; an OPTIONAL column's page its definition levels (bit width 1) in
 * the RLE/bit-packed hybrid by one algorithm (pq_levels_encode), then the present rows' values. FileMetaData in Thrift's
 * compact protocol with column_orders, created_by "imagedb" and the caller's key-value metadata after "imagedb.chunks"
 * (each chunk's offset, length and SHA-256). One writer output for each content; the reader decodes, re-encodes with
 * this writer and compares the bytes.
 *
 * A file's name (F5b, docs/f5b-design.md) is the SHA-256 of its tail: the footer, its length and the closing magic.
 * Every other byte is fixed by it (the chunks by their hashes in imagedb.chunks, the opening magic a constant, zeros
 * between the chunks at the ranges the footer gives, the last chunk ending at the footer), so a file authenticates
 * against a name by its tail's hash, its frame and each chunk's hash (imdb_pq_authenticate; streamed,
 * imdb_pq_authenticate_stream): one SHA-256 pass in all, the chunks' on the pool, the tail hashed before the footer is
 * parsed.
 *
 * The subset's rules, one check for both sides (the writer's input IMDB_ERR_STATE, a file's content IMDB_ERR_CORRUPT): a
 * row at least (every segment builder's); each column a type of the subset with its annotations' fields alone, names and
 * field ids unique, and one REQUIRED column of four bytes or more a row (so a file holds more bytes than rows); present
 * bits exactly where OPTIONAL; a BOOLEAN 0 or 1; a DOUBLE imagedb's FLOAT64 (finite, never -0.0); a BYTE_ARRAY value at
 * most IMDB_MAX_TEXT bytes. A checked build (IMDB_STORE_CHECKS) reads back every file it writes.
 *
 * The column model is neutral (no imagedb_table): lake.c fills it from a segment's rows; the tests and parquet-check
 * from synthetic data.
 */
#ifndef IMDB_PARQUET_H
#define IMDB_PARQUET_H

#include <stdbool.h>
#include <stdint.h>

#include "util.h"

#define PQ_PAGE_ROWS 16384u /* a BYTE_ARRAY chunk's rows a page: 16,384 x (65,535 + 4) bytes stays under a page's i32 */
#define PQ_MAX_COLUMNS 80u   /* the five system columns and IMDB_MAX_COLS (64) user columns, with room */
#define PQ_MAX_KV 8u         /* key-value pairs besides imagedb.chunks */
#define PQ_MAX_FOOTER (1u << 20) /* F5b: a footer's bytes (80 columns' are under 40 KB): a tail is read whole */

enum { PQ_BOOLEAN = 0, PQ_INT32 = 1, PQ_INT64 = 2, PQ_DOUBLE = 5, PQ_BYTE_ARRAY = 6, PQ_FLBA = 7 }; /* Parquet's Type */

enum { /* the logical type written (with its ConvertedType where Parquet keeps one compatible) */
    PQL_NONE = 0,
    PQL_STRING,    /* BYTE_ARRAY UTF-8 */
    PQL_DECIMAL,   /* Iceberg's mapping (F5b): INT32 to 9 digits, INT64 to 18, FLBA(imdb_pq_dec_bytes) past them */
    PQL_DATE,      /* INT32 days */
    PQL_TIME,      /* INT64 microseconds, utc */
    PQL_TIMESTAMP, /* INT64 microseconds, utc */
    PQL_INT,       /* INT32 or INT64: int_bits, signed */
    PQL_UUID,      /* FLBA(16) */
};

typedef struct pq_col {
    const char *name;    /* the column's name (UTF-8, no NUL inside; at most IMDB_MAX_IDENT bytes) */
    int32_t field_id;    /* Iceberg's field id: a user column's position + 1, a system column's reserved id */
    uint8_t phys;        /* PQ_* */
    uint8_t logical;     /* PQL_* */
    bool optional;       /* OPTIONAL (definition levels) or REQUIRED */
    bool utc;            /* PQL_TIME, PQL_TIMESTAMP: isAdjustedToUTC */
    bool stats;          /* min_value and max_value written (the types with today's zone maps) */
    uint8_t int_bits;    /* PQL_INT: 16, 32 or 64 */
    int32_t type_length; /* PQ_FLBA: 16 or 32, or a DECIMAL's imdb_pq_dec_bytes (9 to 16) */
    int32_t scale, precision; /* PQL_DECIMAL */
    /* the values, one slot per row (n rows), a NULL slot's content ignored:
     * BOOLEAN one byte (0 or 1), INT32 four bytes LE, INT64 and DOUBLE eight bytes LE, FLBA type_length bytes */
    const uint8_t *fixed;
    const uint64_t *off; /* BYTE_ARRAY: row i's bytes are data[off[i] .. off[i + 1]) (n + 1 offsets) */
    const uint8_t *data;
    const uint8_t *present; /* OPTIONAL: bit i (LSB first) set when row i has a value; NULL when REQUIRED */
} pq_col;

typedef struct pq_kv {
    const char *key; /* sorted, each after "imagedb.chunks", none repeated */
    const char *value;
} pq_kv;

/* writes the whole file into out (cleared first); fails on a limit or an allocation failure, never a short file */
int imdb_pq_write(const pq_col *cols, uint32_t ncols, uint64_t nrows, const pq_kv *kv, uint32_t nkv, imdb_buf *out,
                  imdb_err *e);

/* a chunk's statistics: its NULLs, and (a column asking, a value present) the least and greatest value's bytes */
typedef struct pq_stat {
    uint64_t nulls;
    bool has;
    uint8_t mn[8], mx[8];
} pq_stat;

/* the same file a column at a time, so a caller holds one column's values while it writes (lake.c's segment build):
 * begin with every column's shape (values unset) and the rows, then each column in order with its values (its shape
 * the next one's), then the pairs. bound: the output's capacity reserved up front (0: none), the sum of
 * imdb_pq_col_bound over the columns and imdb_pq_frame_bound; then the buffer is allocated once */
typedef struct pq_writer {
    imdb_buf *out;
    uint64_t nrows;
    uint32_t ncols, done;
    uint64_t bound; /* the capacity reserved (0: none): a file past it is the bound's bug (checked builds stop) */
    pq_col shape[PQ_MAX_COLUMNS];
    pq_stat st[PQ_MAX_COLUMNS];
    uint64_t off[PQ_MAX_COLUMNS], size[PQ_MAX_COLUMNS];
    uint8_t hash[32]; /* the file's name, its tail's SHA-256 (imdb_pq_name), once imdb_pq_writer_end has succeeded */
} pq_writer;

int imdb_pq_writer_begin(pq_writer *w, imdb_buf *out, const pq_col *shapes, uint32_t ncols, uint64_t nrows,
                         uint64_t bound, imdb_err *e);
int imdb_pq_writer_column(pq_writer *w, const pq_col *c, imdb_err *e);
int imdb_pq_writer_end(pq_writer *w, const pq_kv *kv, uint32_t nkv, imdb_err *e);
/* bytes: a BYTE_ARRAY column's values' bytes, all rows' (0 for another type) */
uint64_t imdb_pq_col_bound(const pq_col *shape, uint64_t nrows, uint64_t bytes);
uint64_t imdb_pq_frame_bound(const pq_kv *kv, uint32_t nkv);

/* ---- the strict reader (docs/f5-design.md, "What a load checks, exactly") ----
 * imdb_pq_footer walks the frame and the footer, taking the row count, each chunk's offset and size and the key-value
 * pairs (pointers into the file); the caller finds the shapes (lake.c: the schema version named by imagedb.schema);
 * imdb_pq_read then reads every chunk by its shape (the writer's padding, page headers written again and compared, the
 * levels by re-encode-and-compare, the values structurally) and writes the footer again from what it read, comparing
 * the bytes. imagedb.chunks' hashes are not checked here: a file read from disk is authenticated first (F5b:
 * imdb_pq_authenticate checks every chunk against them). */
typedef struct pq_footer {
    uint64_t nrows;
    uint32_t ncols, nkv;
    uint64_t off[PQ_MAX_COLUMNS], size[PQ_MAX_COLUMNS];
    const uint8_t *key[PQ_MAX_KV + 1], *val[PQ_MAX_KV + 1];
    uint32_t klen[PQ_MAX_KV + 1], vlen[PQ_MAX_KV + 1];
    size_t meta_at, meta_len; /* the footer's bytes */
    const uint8_t *chunk_hex[PQ_MAX_COLUMNS]; /* imagedb.chunks: each chunk's SHA-256, 64 lowercase hex digits */
} pq_footer;

/* a column as read: c holds the values in pq_col's model; what it points to is the file's bytes (a REQUIRED fixed-width
 * column's page: no copy) or the owned arrays, freed by imdb_pq_free_read */
typedef struct pq_rcol {
    pq_col c;
    uint8_t *own_fixed, *own_data, *own_present;
    uint64_t *own_off;
    size_t own_fixed_n, own_data_n, own_present_n; /* their sizes: a caller taking one wipes and frees it so */
} pq_rcol;

int imdb_pq_footer(const uint8_t *f, size_t len, pq_footer *ft, imdb_err *e);
/* a key's value in the footer, or NULL */
const uint8_t *imdb_pq_kv(const pq_footer *ft, const char *key, uint32_t *len);
/* shapes: the caller's ncols columns (the schema version's), each with every field but the values as the writer had them; a
 * file of another column count is refused before anything is sized by it */
int imdb_pq_read(const uint8_t *f, size_t len, const pq_footer *ft, const pq_col *shapes, uint32_t ncols, pq_rcol *out,
                 imdb_err *e);
void imdb_pq_free_read(pq_rcol *cols, uint32_t ncols);
/* each chunk's bytes against its SHA-256 in imagedb.chunks (on the pool past 1 MiB), IMDB_ERR_CORRUPT otherwise; each
 * chunk's range is bounded first */
int imdb_pq_chunks_verify(const uint8_t *f, const pq_footer *ft, imdb_err *e);

/* ---- F5b: a file's name and its authentication (docs/f5b-design.md section 1) ---- */
/* the name: the SHA-256 of the last meta_len + 8 bytes, the footer's length bounded first (PQ_MAX_FOOTER) */
int imdb_pq_name(const uint8_t *f, size_t len, uint8_t out[32], imdb_err *e);
/* a file read whole against its name, in this order: the tail hashed and compared (nothing parsed before), the footer
 * walked (into ft), the frame (the opening magic; the chunks in column order, each at or past its predecessor's end,
 * zeros between them, the last ending at the footer), each chunk against imagedb.chunks. IMDB_ERR_VERIFY: not the
 * named object (the tail's hash or a chunk's); IMDB_ERR_CORRUPT: not a file of the subset's frame */
int imdb_pq_authenticate(const uint8_t *f, size_t len, const uint8_t name[32], pq_footer *ft, imdb_err *e);
/* the same over a file read in pieces (seed.c: a seed's segment, from its temporary file), one verdict for any bytes:
 * rd reads exactly n bytes at off into its buffer (a failure its own error in e); buf (bufsz bytes, at least 4096) holds
 * the pieces; the tail is allocated (at most PQ_MAX_FOOTER + 8 bytes) and wiped */
typedef int (*pq_read_fn)(void *ctx, uint64_t off, uint8_t *buf, size_t n, imdb_err *e);
int imdb_pq_authenticate_stream(pq_read_fn rd, void *ctx, uint64_t len, const uint8_t name[32], uint8_t *buf,
                                size_t bufsz, imdb_err *e);
/* a DECIMAL's FIXED_LEN_BYTE_ARRAY width past 18 digits, Iceberg's "minimum number of bytes that can store P": the least b
 * with 10^P <= 2^(8b - 1) (19-21 9, 22-23 10, 24-26 11, 27-28 12, 29-31 13, 32-33 14, 34-35 15, 36-38 16); 0 outside 19-38 */
unsigned imdb_pq_dec_bytes(int32_t precision);
/* the footer (key[0] imagedb.chunks's) and a page header as the writer encodes them: for tools that build hostile files
 * (forge.c, the tests), a lie's sizes and footer made consistent so that only the reader's rule for it can refuse it */
void imdb_pq_footer_encode(imdb_buf *out, const pq_col *cols, uint32_t ncols, uint64_t nrows, const uint64_t *off,
                           const uint64_t *size, const uint8_t *const *key, const uint32_t *klen,
                           const uint8_t *const *val, const uint32_t *vlen, uint32_t nkv);
void imdb_pq_page_header_encode(imdb_buf *out, uint32_t size, uint64_t nvalues);
/* the byte offset of row's value in column ci (fixed-width, not BOOLEAN), its present bits as read: forge.c's */
int imdb_pq_value_at(const uint8_t *f, size_t len, const pq_footer *ft, uint32_t ci, const pq_col *shape,
                     const uint8_t *present, uint64_t row, size_t *at, imdb_err *e);

/* the definition levels' hybrid by the one algorithm: n levels (each 0 or 1, one byte each) appended to out without the
 * u32 length; and its strict decoder: exactly n levels from exactly len bytes, any other encoding refused (it decodes,
 * re-encodes and compares) */
void imdb_pq_levels_encode(const uint8_t *levels, uint64_t n, imdb_buf *out);
int imdb_pq_levels_decode(const uint8_t *p, size_t len, uint64_t n, uint8_t *levels, imdb_err *e);

#endif
