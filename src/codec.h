/*
 * Types, schemas, values and the canonical row encoding.
 *
 * Exactness rules enforced here:
 *   - one canonical byte encoding per row (what gets hashed is what gets stored);
 *   - values are tagged; a value whose tag differs from the column type is
 *     rejected, never reinterpreted (PostgreSQL CVE class D: type confusion);
 *   - TEXT is strict UTF-8 without NUL, validated at every ingress *and* on
 *     every decode from disk or network (CVE class C: multibyte validation);
 *   - DECIMAL is a scaled int64 with declared precision: no float, no silent
 *     rounding, overflow is an error.
 */
#ifndef IMDB_CODEC_H
#define IMDB_CODEC_H

#include <stdbool.h>
#include <stdint.h>

#include "util.h"

typedef enum imdb_type {
    IMDB_T_INT64 = 1,
    IMDB_T_DECIMAL = 2,
    IMDB_T_TEXT = 3,
    IMDB_T_BOOL = 4,
    IMDB_T_TIMESTAMP = 5, /* microseconds since 1970-01-01 00:00:00 UTC */
    IMDB_T_FLOAT64 = 6,   /* finite IEEE-754 binary64, held as its order-preserving key (imdb_f64_key) */
} imdb_type;

#define IMDB_COL_PK       0x01
#define IMDB_COL_SUBJECT  0x02
#define IMDB_COL_NULLABLE 0x04 /* never on a PRIMARY KEY or SUBJECT column */

typedef struct imdb_column {
    char name[IMDB_MAX_IDENT + 1];
    uint8_t type;
    uint8_t precision; /* DECIMAL only: 1..18 */
    uint8_t scale;     /* DECIMAL only: 0..precision */
    uint8_t flags;
} imdb_column;

typedef struct imdb_schema {
    uint32_t id;
    char name[IMDB_MAX_IDENT + 1];
    uint16_t ncols;
    uint16_t pk;       /* column index of the primary key */
    int16_t subject;   /* column index of the data-subject key, -1 if none */
    imdb_column cols[IMDB_MAX_COLS];
} imdb_schema;

typedef struct imdb_value {
    uint8_t type;      /* imdb_type tag; must match the column */
    uint8_t scale;     /* DECIMAL: scale of i */
    bool null;         /* SQL NULL, only in a NULLABLE column: i, len and s stay zero */
    uint32_t len;      /* TEXT length */
    int64_t i;         /* INT64, DECIMAL (scaled), TIMESTAMP, BOOL (0/1), FLOAT64 (key) */
    const uint8_t *s;  /* TEXT bytes (not owned) */
} imdb_value;

/* ---- text ----------------------------------------------------------- */
/* Strict UTF-8 (Unicode 15 Table 3-7), U+0000 rejected. On failure *bad gets
 * the byte offset of the first offending byte. Never reads past s+n. */
bool imdb_utf8_valid(const uint8_t *s, size_t n, size_t *bad);
/* Identifier: [A-Za-z_][A-Za-z0-9_]{0,62}; folded to lowercase into out. */
bool imdb_ident_valid(const char *s, size_t n);
bool imdb_ident_fold(const char *s, size_t n, char out[IMDB_MAX_IDENT + 1]);

/* ---- schema --------------------------------------------------------- */
int imdb_schema_check(const imdb_schema *s, imdb_err *e);
void imdb_schema_encode(const imdb_schema *s, imdb_buf *b);
int imdb_schema_decode(imdb_rd *r, imdb_schema *s, imdb_err *e);
/* u8 length then the identifier, valid and folded to lowercase (schemas, index names) */
int imdb_rd_ident(imdb_rd *r, char out[IMDB_MAX_IDENT + 1], imdb_err *e);
int imdb_schema_col(const imdb_schema *s, const char *name); /* -1 if absent */
const char *imdb_type_name(uint8_t t);
bool imdb_type_is_int(uint8_t t); /* every type but TEXT: compared as int64 */

/* ---- FLOAT64 -------------------------------------------------------- */
/* The order-preserving key of a finite double (-0.0 is taken as +0.0): key order is
 * numeric order and key equality numeric equality, so FLOAT64 is compared, hashed,
 * zone-mapped and filtered as an int64. */
int64_t imdb_f64_key(double d);
double imdb_f64_value(int64_t key);
bool imdb_f64_key_valid(int64_t key); /* a finite double, and not the key of -0.0 */

/* ---- values --------------------------------------------------------- */
int64_t imdb_pow10(int n); /* n in 0..18 */
/* Checks a tagged value against a column (type, range, UTF-8). */
int imdb_value_check(const imdb_column *c, const imdb_value *v, imdb_err *e);
/* Canonical row: a null bitmap of ceil(nullable columns / 8) bytes (bit k: the k-th
 * NULLABLE column is NULL; padding bits zero), then each non-null value in column order:
 *   INT64/DECIMAL/TIMESTAMP/FLOAT64 (key): 8 bytes LE; BOOL: 1 byte; TEXT: u32 LE length + bytes */
int imdb_row_encode(const imdb_schema *s, const imdb_value *vals, imdb_buf *out, imdb_err *e);
/* Strict decode with full validation; TEXT values point into row. */
int imdb_row_decode(const imdb_schema *s, const uint8_t *row, size_t len, imdb_value *vals, imdb_err *e);
/* Decode one column without materialising the others (row already validated). */
void imdb_row_get(const imdb_schema *s, const uint8_t *row, size_t len, int col, imdb_value *v);
int imdb_value_cmp(const imdb_value *a, const imdb_value *b); /* same type; bytewise for TEXT; NULL last */
uint64_t imdb_value_hash(const imdb_value *v, uint64_t seed);

/* Row commitment: SHA256("IMDBROW1" || u32 table || salt16 || u32 len || row) */
void imdb_row_commit(uint32_t table_id, const uint8_t salt[16], const uint8_t *row, size_t len,
                     uint8_t out[32]);

/* ---- literals (used by the SQL front-end and tools) ----------------- */
/* Exact decimal text -> scaled int64; rejects excess fractional digits. */
int imdb_parse_decimal(const char *s, size_t n, int precision, int scale, int64_t *out, imdb_err *e);
int imdb_parse_int64(const char *s, size_t n, int64_t *out, imdb_err *e);
/* [+-]digits[.digits][(e|E)[+-]digits] correctly rounded to the nearest double, as its key;
 * a literal that overflows, or a non-zero one that rounds to zero, is refused. */
int imdb_parse_float64(const char *s, size_t n, int64_t *key, imdb_err *e);
/* 'YYYY-MM-DD[ HH:MM:SS[.ffffff]]' UTC only. */
int imdb_parse_timestamp(const char *s, size_t n, int64_t *out, imdb_err *e);
void imdb_format_value(const imdb_value *v, imdb_buf *out);       /* plain */
void imdb_format_value_safe(const imdb_value *v, imdb_buf *out);  /* terminal-safe */
void imdb_format_decimal(int64_t v, int scale, imdb_buf *out);
void imdb_format_i128(__int128 v, int scale, imdb_buf *out);
void imdb_format_timestamp(int64_t us, imdb_buf *out);
/* The shortest of %.15g, %.16g, %.17g that reads back as the same double (C locale). */
void imdb_format_float64(int64_t key, imdb_buf *out);

#endif
