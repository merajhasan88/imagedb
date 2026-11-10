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
    IMDB_T_TIMESTAMPTZ = 7, /* P2: an instant, microseconds since 1970-01-01 00:00:00 UTC, shown in the session's zone */
    IMDB_T_DATE = 8,        /* F3b: days since 1970-01-01, 0001-01-01 to 9999-12-31 (TIMESTAMP's years) */
    IMDB_T_TIME = 9,        /* F3b: microseconds since midnight, 00:00:00 to 23:59:59.999999 */
    IMDB_T_UUID = 10,       /* F3d: 16 bytes in s (len 16 always), ordered as memcmp orders them */
    IMDB_T_BYTEA = 11,      /* F3d: 0 to IMDB_MAX_TEXT bytes in s, any byte; memcmp, then the shorter first */
} imdb_type;
#define IMDB_T_LAST IMDB_T_BYTEA /* the highest tag a schema may hold */
#define IMDB_UUID_LEN 16

#define IMDB_COL_PK       0x01
#define IMDB_COL_SUBJECT  0x02
#define IMDB_COL_NULLABLE 0x04 /* never on a PRIMARY KEY or SUBJECT column */

typedef struct imdb_column {
    char name[IMDB_MAX_IDENT + 1];
    uint8_t type;
    uint8_t precision; /* DECIMAL only: 1..18 */
    uint8_t scale;     /* DECIMAL only: 0..precision */
    uint8_t flags;
    uint16_t vlen;     /* F3c: a TEXT's VARCHAR length in characters, 0 unbounded; written in the precision and scale
                        * bytes (little-endian) of the schema's encoding, its precision and scale in memory 0 */
} imdb_column;

typedef struct imdb_schema {
    uint32_t id;
    char name[IMDB_MAX_IDENT + 1];
    uint16_t ncols;
    uint8_t npk;       /* the primary key's columns, 1..IMDB_MAX_KEY_COLS (F4) */
    uint16_t key[IMDB_MAX_KEY_COLS]; /* their column indexes, in key order; key[npk..] zero */
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
/* F4: the primary key's one encoding (design.md §3, the format design's section 6), of its npk values kv in key order
 * (none NULL, each its column's type): INT64, DECIMAL and TIMESTAMP 8 bytes big-endian with the sign bit flipped, BOOL
 * one byte, TEXT its bytes with 0x00 written 0x00 0xFF and ended 0x00 0x00; memcmp order is the tuple's order.
 * imdb_key_len says how many bytes imdb_key_write writes. A composite key's PK map is keyed by it; it reaches no file */
size_t imdb_key_len(const imdb_schema *s, const imdb_value *kv);
void imdb_key_write(const imdb_schema *s, const imdb_value *kv, uint8_t *out);
/* u8 length then the identifier, valid and folded to lowercase (schemas, index names) */
int imdb_rd_ident(imdb_rd *r, char out[IMDB_MAX_IDENT + 1], imdb_err *e);
int imdb_schema_col(const imdb_schema *s, const char *name); /* -1 if absent */
const char *imdb_type_name(uint8_t t);
bool imdb_type_is_int(uint8_t t); /* every type but the byte strings: its value in i, compared as int64 */
/* F3d: TEXT, UUID and BYTEA: a byte string in s and len (compared by memcmp, the shorter first; hashed, keyed and kept in
 * a segment as bytes). TEXT alone has the UTF-8 rules, LIKE, the case functions and VARCHAR's length */
bool imdb_type_bytes(uint8_t t);
/* F3a: an INT64 column's width, its precision (16 SMALLINT, 32 INTEGER, 0 INT64 or BIGINT, the one spelling of each): valid,
 * whether a value fits it, and its type's name */
bool imdb_int_width_ok(uint8_t width);
bool imdb_int_fits(uint8_t width, int64_t v);
const char *imdb_int_name(uint8_t width);
/* F3c: a TEXT column's VARCHAR length in characters (vlen; 0: TEXT unbounded) */
uint32_t imdb_text_max(const imdb_column *c);
void imdb_text_set_max(imdb_column *c, uint32_t n);
uint32_t imdb_utf8_chars(const uint8_t *s, uint32_t n); /* code points of valid UTF-8 */

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
uint64_t imdb_siphash24(const uint8_t *in, size_t n, uint64_t k0, uint64_t k1); /* SipHash-2-4, keyed by (k0, k1) */

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
/* F3b: 'YYYY-MM-DD' (days since 1970-01-01) and 'HH:MM:SS[.f]' (1 to 6 fraction digits; microseconds since
 * midnight; 24:00:00 refused) */
int imdb_parse_date(const char *s, size_t n, int64_t *out, imdb_err *e);
int imdb_parse_time(const char *s, size_t n, int64_t *out, imdb_err *e);
/* F3d: a UUID's text, 32 hex digits in either case, with hyphens after the 8th, 12th, 16th and 20th or none */
int imdb_parse_uuid(const char *s, size_t n, uint8_t out[IMDB_UUID_LEN], imdb_err *e);
/* F3d: a BYTEA's text, PostgreSQL's hex form: \x then two hex digits a byte, either case (the escape form refused);
 * *outlen bytes into out (cap at least (n - 2) / 2) */
int imdb_parse_bytea(const char *s, size_t n, uint8_t *out, size_t cap, size_t *outlen, imdb_err *e);
#define IMDB_DATE_MIN (-719162LL)  /* 0001-01-01 */
#define IMDB_DATE_MAX 2932896LL    /* 9999-12-31 */
#define IMDB_TIME_MAX 86399999999LL /* 23:59:59.999999 */
#define IMDB_DAY_US 86400000000LL
/* P2: a TIMESTAMPTZ literal: a TIMESTAMP's text (its wall-clock time in local), then nothing (the session's zone
 * decides), an offset (Z, +HH, +HHMM, +HH:MM or +HH:MM:SS, at most 15:59:59 as PostgreSQL's, a space before it
 * allowed) or a space and a zone's name (zoff, zlen: where in s; the caller looks it up) */
typedef struct imdb_tzlit {
    int64_t local;
    bool has_off;
    int32_t off;     /* seconds east of UTC */
    uint32_t zoff, zlen; /* the zone's name, when zlen */
} imdb_tzlit;
int imdb_parse_timestamptz(const char *s, size_t n, imdb_tzlit *out, imdb_err *e);
void imdb_format_value(const imdb_value *v, imdb_buf *out);       /* plain */
void imdb_format_int64(int64_t v, imdb_buf *out);                  /* "%lld", without printf */
void imdb_format_value_safe(const imdb_value *v, imdb_buf *out);  /* terminal-safe */
void imdb_format_decimal(int64_t v, int scale, imdb_buf *out);
void imdb_format_i128(__int128 v, int scale, imdb_buf *out);
/* the proleptic Gregorian calendar: days since 1970-01-01 (P2: date_trunc's) */
int64_t imdb_days_from_civil(int64_t y, int m, int d);
void imdb_civil_from_days(int64_t z, int64_t *y, int *m, int *d);
void imdb_format_timestamp(int64_t us, imdb_buf *out);
void imdb_format_date(int64_t days, imdb_buf *out); /* F3b: 'YYYY-MM-DD' */
void imdb_format_time(int64_t us, imdb_buf *out);   /* F3b: 'HH:MM:SS', and '.ffffff' when microseconds remain */
void imdb_format_uuid(const uint8_t *b, imdb_buf *out);              /* F3d: lowercase 8-4-4-4-12 */
int imdb_uuid_v4(uint8_t out[IMDB_UUID_LEN], imdb_err *e); /* F3d: gen_random_uuid's: random bytes, version 4, RFC 9562's variant */
void imdb_format_bytea(const uint8_t *b, size_t n, imdb_buf *out);  /* F3d: \x and lowercase hex; empty is \x */
/* P2: a TIMESTAMPTZ in a zone whose offset at it is off (seconds east): its local time as a TIMESTAMP's, then the
 * offset as PostgreSQL writes it: +HH, +HH:MM, or +HH:MM:SS (a local mean time's) */
void imdb_format_timestamptz(int64_t utc_us, int32_t off, imdb_buf *out);
/* The shortest of %.15g, %.16g, %.17g that reads back as the same double (C locale). */
void imdb_format_float64(int64_t key, imdb_buf *out);

#endif
