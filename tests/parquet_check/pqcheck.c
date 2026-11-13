/* F5 (docs/f5-design.md): `make parquet-check`, opt-in, outside the matrix (the user, 2026-11-13: "DuckDB is fine").
 * Files written by imagedb's Parquet writer (src/parquet.c) are read by DuckDB's library (/opt/duckdb), the one reader
 * from outside on this machine:
 *   - every column's type as DuckDB reads it (the annotations: an INT(16) a SMALLINT, a UTC TIMESTAMP one WITH TIME ZONE);
 *   - every value of every type, NULLs in runs of every length (so DuckDB decodes the levels' hybrid as imagedb wrote
 *     it), REQUIRED columns with placeholders, a TEXT column over several pages, the schema's field ids;
 *   - the statistics: each null count, and each min and max parsed by DuckDB as the column's type against the data's
 *     MIN and MAX; a file of the DOUBLE zero rule (a zero min written -0.0, a zero max +0.0);
 *   - row-group pruning by them: rows at each min and max, none past either, all between.
 * Usage: pqcheck DIR (a scratch directory; test scratch: /dev/shm/imdb-*). */
#include <inttypes.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "duckdb.h"
#include "../../src/parquet.h"

static int fails;
#define FAIL(...)                                                                                                      \
    do {                                                                                                               \
        if (fails++ < 40) fprintf(stderr, "FAIL: " __VA_ARGS__);                                                       \
    } while (0)

static uint64_t rng = 88172645463325252ull;
static uint64_t next(void)
{
    rng ^= rng << 13;
    rng ^= rng >> 7;
    rng ^= rng << 17;
    return rng;
}

enum { NC = 23 };
typedef struct data {
    uint64_t n;
    uint8_t *fixed[NC];
    uint64_t *off[NC];
    uint8_t *bytes[NC];
    uint8_t *present[NC];
} data;

/* the system columns' names hold a '$', which no imagedb identifier does: no user column can take one */
static const char *const names[NC] = {"imdb$vid", "imdb$begin", "imdb$flags", "imdb$salt", "imdb$commit",
                                      "k",        "i",          "s",          "d",         "w",
                                      "t",        "b",          "ts",         "tz",        "dt",
                                      "tm",       "u",          "bya",        "f",         "iv",
                                      "en",       "rt",         "zn"};

/* each column's type as DuckDB reads it */
static const char *const dtype[NC] = {"BIGINT",  "BIGINT",  "INTEGER",   "BLOB",
                                      "BLOB",    "BIGINT",  "INTEGER",   "SMALLINT",
                                      "DECIMAL(10,2)", "DECIMAL(38,6)", "VARCHAR", "BOOLEAN",
                                      "TIMESTAMP", "TIMESTAMP WITH TIME ZONE", "DATE", "TIME",
                                      "UUID",    "BLOB",    "DOUBLE",    "BLOB",
                                      "BIGINT",  "VARCHAR", "BIGINT"};

static void col_shape(int c, pq_col *p)
{
    memset(p, 0, sizeof *p);
    p->name = names[c];
    p->field_id = c < 5 ? 2147483000 + c : c + 1;
    switch (c) {
    case 0: case 1: p->phys = PQ_INT64; break;
    case 2: p->phys = PQ_INT32; break;
    case 3: p->phys = PQ_FLBA; p->type_length = 16; break;
    case 4: p->phys = PQ_FLBA; p->type_length = 32; break;
    case 5: p->phys = PQ_INT64; p->logical = PQL_INT; p->int_bits = 64; p->stats = true; break;
    case 6: p->phys = PQ_INT32; p->logical = PQL_INT; p->int_bits = 32; p->stats = true; p->optional = true; break;
    case 7: p->phys = PQ_INT32; p->logical = PQL_INT; p->int_bits = 16; p->stats = true; p->optional = true; break;
    case 8: p->phys = PQ_INT64; p->logical = PQL_DECIMAL; p->scale = 2; p->precision = 10; p->stats = true; p->optional = true; break;
    case 9: p->phys = PQ_FLBA; p->type_length = 16; p->logical = PQL_DECIMAL; p->scale = 6; p->precision = 38; p->optional = true; break;
    case 10: p->phys = PQ_BYTE_ARRAY; p->logical = PQL_STRING; p->optional = true; break;
    case 11: p->phys = PQ_BOOLEAN; p->stats = true; p->optional = true; break;
    case 12: p->phys = PQ_INT64; p->logical = PQL_TIMESTAMP; p->stats = true; p->optional = true; break;
    case 13: p->phys = PQ_INT64; p->logical = PQL_TIMESTAMP; p->utc = true; p->stats = true; p->optional = true; break;
    case 14: p->phys = PQ_INT32; p->logical = PQL_DATE; p->stats = true; p->optional = true; break;
    case 15: p->phys = PQ_INT64; p->logical = PQL_TIME; p->stats = true; p->optional = true; break;
    case 16: p->phys = PQ_FLBA; p->type_length = 16; p->logical = PQL_UUID; p->optional = true; break;
    case 17: p->phys = PQ_BYTE_ARRAY; p->optional = true; break;
    case 18: p->phys = PQ_DOUBLE; p->stats = true; p->optional = true; break;
    case 19: p->phys = PQ_FLBA; p->type_length = 16; p->optional = true; break;
    case 20: p->phys = PQ_INT64; p->stats = true; p->optional = true; break;
    case 21: p->phys = PQ_BYTE_ARRAY; p->logical = PQL_STRING; break;
    case 22: p->phys = PQ_INT64; p->logical = PQL_INT; p->int_bits = 64; p->stats = true; p->optional = true; break;
    }
}

static unsigned width(const pq_col *p)
{
    return p->phys == PQ_BOOLEAN ? 1 : p->phys == PQ_INT32 ? 4 : p->phys == PQ_FLBA ? (unsigned)p->type_length : 8;
}

/* a NULL pattern drawn as runs of 1 to 20 equal levels (column zn: every row NULL) */
static void draw_present(int c, uint64_t n, uint8_t *pr)
{
    memset(pr, 0, (n + 7) / 8);
    uint64_t i = 0;
    int v = 1;
    while (i < n) {
        uint64_t run = 1 + next() % (c % 3 == 0 ? 20 : 9);
        for (uint64_t k = 0; k < run && i < n; k++, i++)
            if (v && c != 22) pr[i >> 3] |= (uint8_t)(1u << (i & 7));
        v = !v;
    }
}

static void build(data *d, uint64_t n)
{
    d->n = n;
    pq_col p;
    for (int c = 0; c < NC; c++) {
        col_shape(c, &p);
        unsigned w = width(&p);
        d->present[c] = p.optional ? calloc((n + 7) / 8 + 1, 1) : NULL;
        if (p.optional) draw_present(c, n, d->present[c]);
        if (p.phys == PQ_BYTE_ARRAY) {
            d->off[c] = calloc(n + 1, sizeof(uint64_t));
            size_t cap = 1024, len = 0;
            d->bytes[c] = malloc(cap);
            for (uint64_t i = 0; i < n; i++) {
                bool flagged = i % 10 == 9;
                size_t vl = flagged && c == 21 ? 0 : (size_t)(next() % (c == 10 ? 120 : 9));
                if (c == 10 && i % 997 == 0) vl = 4000; /* long values, so the pages hold much */
                while (len + vl > cap) d->bytes[c] = realloc(d->bytes[c], cap *= 2);
                for (size_t k = 0; k < vl; k++) d->bytes[c][len + k] = c == 17 ? (uint8_t)next() : (uint8_t)('a' + next() % 26);
                len += vl;
                d->off[c][i + 1] = len;
            }
            continue;
        }
        d->fixed[c] = calloc(n ? n : 1, w);
        for (uint64_t i = 0; i < n; i++) {
            uint8_t *v = d->fixed[c] + i * w;
            bool flagged = i % 10 == 9; /* a stub: REQUIRED user columns hold the placeholder zero */
            int64_t x = 0;
            switch (c) {
            case 0: x = (int64_t)i + 1; break;
            case 1: x = (int64_t)(i / 3) + 1; break;
            case 2: x = flagged; break;
            case 3: case 4:
                if (c == 4 || !flagged)
                    for (unsigned k = 0; k < w; k++) v[k] = (uint8_t)next();
                continue;
            case 5: x = flagged ? 0 : (int64_t)(next() % 2000000) - 1000000; break;
            case 6: x = (int64_t)(int32_t)next(); break;
            case 7: x = (int16_t)next(); break;
            case 8: x = (int64_t)(next() % 2000000000) - 1000000000; break;
            case 9: {
                unsigned __int128 m = ((unsigned __int128)next() << 64 | next()) % ((unsigned __int128)10000000000000000000ull * 1000000000000000000ull);
                __int128 sv = (next() & 1) ? -(__int128)m : (__int128)m;
                for (unsigned k = 0; k < 16; k++) v[k] = (uint8_t)((unsigned __int128)sv >> (8 * (15 - k))); /* big-endian */
                continue;
            }
            case 11: x = next() & 1; break;
            case 12: case 13: x = (int64_t)(next() % 4000000000000000ull) - 1000000000000000ll; break;
            case 14: x = (int64_t)(next() % 3000000) - 700000; break;
            case 15: x = (int64_t)(next() % 86400000000ull); break;
            case 16: case 19:
                for (unsigned k = 0; k < w; k++) v[k] = (uint8_t)next();
                continue;
            case 18: { /* imagedb's FLOAT64: finite, its zero +0.0 */
                double f = ((double)(int64_t)(next() >> 11) - 4e15) / 1024.0;
                if (i % 31 == 0) f = 0.0;
                memcpy(v, &f, 8);
                continue;
            }
            case 20: x = (int64_t)(next() % 5); break;
            case 22: x = 0; break;
            }
            if (w == 4) {
                uint32_t u = (uint32_t)x;
                for (unsigned k = 0; k < 4; k++) v[k] = (uint8_t)(u >> (8 * k));
            } else if (w == 1) {
                v[0] = (uint8_t)x;
            } else {
                uint64_t u = (uint64_t)x;
                for (unsigned k = 0; k < 8; k++) v[k] = (uint8_t)(u >> (8 * k));
            }
        }
    }
}

static bool present(const data *d, int c, uint64_t i) { return !d->present[c] || (d->present[c][i >> 3] >> (i & 7) & 1); }

static int64_t fixed_i(const data *d, int c, uint64_t i, unsigned w)
{
    const uint8_t *v = d->fixed[c] + i * w;
    if (w == 1) return v[0];
    if (w == 4) return (int32_t)(v[0] | v[1] << 8 | v[2] << 16 | (uint32_t)v[3] << 24);
    uint64_t u = 0;
    for (unsigned k = 0; k < 8; k++) u |= (uint64_t)v[k] << (8 * k);
    return (int64_t)u;
}

static double fixed_d(const data *d, int c, uint64_t i)
{
    double f;
    memcpy(&f, d->fixed[c] + i * 8, 8);
    return f;
}

static void dec128_text(const uint8_t *be, int scale, char *out)
{
    unsigned __int128 u = 0;
    for (int k = 0; k < 16; k++) u = u << 8 | be[k];
    bool neg = (be[0] & 0x80) != 0;
    if (neg) u = ~u + 1;
    char digits[64];
    int nd = 0;
    do {
        digits[nd++] = (char)('0' + (int)(u % 10));
        u /= 10;
    } while (u);
    while (nd <= scale) digits[nd++] = '0';
    int at = 0;
    if (neg) out[at++] = '-';
    for (int k = nd - 1; k >= 0; k--) {
        out[at++] = digits[k];
        if (k == scale && scale > 0) out[at++] = '.';
    }
    out[at] = 0;
}

static int query(duckdb_connection con, const char *sql, duckdb_result *r)
{
    if (duckdb_query(con, sql, r) == DuckDBError) {
        FAIL("%s: %s\n", sql, duckdb_result_error(r));
        duckdb_destroy_result(r);
        return -1;
    }
    return 0;
}

/* one integer from a one-row, one-column query, or INT64_MIN on an error */
static int64_t query_i64(duckdb_connection con, const char *sql)
{
    duckdb_result r;
    if (query(con, sql, &r)) return INT64_MIN;
    int64_t v = duckdb_row_count(&r) == 1 && !duckdb_value_is_null(&r, 0, 0) ? duckdb_value_int64(&r, 0, 0) : INT64_MIN;
    duckdb_destroy_result(&r);
    return v;
}

/* the order of a statistics column's values: DOUBLE by value, BOOLEAN 0 < 1, the rest as signed integers */
static int cmp_rows(const data *d, int c, uint64_t a, uint64_t b, unsigned w)
{
    if (c == 18) {
        double x = fixed_d(d, c, a), y = fixed_d(d, c, b);
        return (x > y) - (x < y);
    }
    int64_t x = fixed_i(d, c, a, w), y = fixed_i(d, c, b, w);
    return (x > y) - (x < y);
}

/* row i's value as a DuckDB constant of the column's type (folded before the scan's filters) */
static void literal(const data *d, int c, uint64_t i, char *out, size_t cap)
{
    pq_col p;
    col_shape(c, &p);
    int64_t x = c == 18 ? 0 : fixed_i(d, c, i, width(&p));
    switch (c) {
    case 8: {
        uint64_t a = x < 0 ? (uint64_t)0 - (uint64_t)x : (uint64_t)x;
        snprintf(out, cap, "CAST('%s%" PRIu64 ".%02" PRIu64 "' AS DECIMAL(10,2))", x < 0 ? "-" : "", a / 100, a % 100);
        break;
    }
    case 11: snprintf(out, cap, "%s", x ? "true" : "false"); break;
    case 12: snprintf(out, cap, "make_timestamp(CAST(%" PRId64 " AS BIGINT))", x); break;
    case 13: snprintf(out, cap, "CAST(make_timestamp(CAST(%" PRId64 " AS BIGINT)) AS TIMESTAMPTZ)", x); break;
    case 14: snprintf(out, cap, "(DATE '1970-01-01' + CAST(%" PRId64 " AS INTEGER))", x); break;
    case 15: snprintf(out, cap, "(TIME '00:00:00' + to_microseconds(CAST(%" PRId64 " AS BIGINT)))", x); break;
    case 18: snprintf(out, cap, "CAST('%.17g' AS DOUBLE)", fixed_d(d, c, i)); break;
    default: snprintf(out, cap, "CAST(%" PRId64 " AS %s)", x, dtype[c]); break;
    }
}

static void check_file(duckdb_connection con, const char *path, const data *d)
{
    char sql[2048];
    duckdb_result r;
    if (query_i64(con, (snprintf(sql, sizeof sql, "SELECT COUNT(*) FROM read_parquet('%s')", path), sql)) != (int64_t)d->n)
        FAIL("%s: the row count\n", path);
    /* the schema as DuckDB parses the footer: each column's field id, physical type, length, repetition, ConvertedType
     * and LogicalType (DuckDB prints IntType's bitWidth, an i8, as its character: 64 '@', 32 ' ', 16 '\x10') */
    static const char *const want_schema[NC][5] = {
        {"INT64", "NULL", "REQUIRED", "NULL", "NULL"},
        {"INT64", "NULL", "REQUIRED", "NULL", "NULL"},
        {"INT32", "NULL", "REQUIRED", "NULL", "NULL"},
        {"FIXED_LEN_BYTE_ARRAY", "16", "REQUIRED", "NULL", "NULL"},
        {"FIXED_LEN_BYTE_ARRAY", "32", "REQUIRED", "NULL", "NULL"},
        {"INT64", "NULL", "REQUIRED", "INT_64", "IntType(bitWidth=\x40, isSigned=1)"},
        {"INT32", "NULL", "OPTIONAL", "INT_32", "IntType(bitWidth=\x20, isSigned=1)"},
        {"INT32", "NULL", "OPTIONAL", "INT_16", "IntType(bitWidth=\x10, isSigned=1)"},
        {"INT64", "NULL", "OPTIONAL", "DECIMAL", "DecimalType(scale=2, precision=10)"},
        {"FIXED_LEN_BYTE_ARRAY", "16", "OPTIONAL", "DECIMAL", "DecimalType(scale=6, precision=38)"},
        {"BYTE_ARRAY", "NULL", "OPTIONAL", "UTF8", "StringType()"},
        {"BOOLEAN", "NULL", "OPTIONAL", "NULL", "NULL"},
        {"INT64", "NULL", "OPTIONAL", "TIMESTAMP_MICROS",
         "TimestampType(isAdjustedToUTC=0, unit=TimeUnit(MILLIS=<null>, MICROS=MicroSeconds(), NANOS=<null>))"},
        {"INT64", "NULL", "OPTIONAL", "TIMESTAMP_MICROS",
         "TimestampType(isAdjustedToUTC=1, unit=TimeUnit(MILLIS=<null>, MICROS=MicroSeconds(), NANOS=<null>))"},
        {"INT32", "NULL", "OPTIONAL", "DATE", "DateType()"},
        {"INT64", "NULL", "OPTIONAL", "TIME_MICROS",
         "TimeType(isAdjustedToUTC=0, unit=TimeUnit(MILLIS=<null>, MICROS=MicroSeconds(), NANOS=<null>))"},
        {"FIXED_LEN_BYTE_ARRAY", "16", "OPTIONAL", "NULL", "UUIDType()"},
        {"BYTE_ARRAY", "NULL", "OPTIONAL", "NULL", "NULL"},
        {"DOUBLE", "NULL", "OPTIONAL", "NULL", "NULL"},
        {"FIXED_LEN_BYTE_ARRAY", "16", "OPTIONAL", "NULL", "NULL"},
        {"INT64", "NULL", "OPTIONAL", "NULL", "NULL"},
        {"BYTE_ARRAY", "NULL", "REQUIRED", "UTF8", "StringType()"},
        {"INT64", "NULL", "OPTIONAL", "INT_64", "IntType(bitWidth=\x40, isSigned=1)"},
    };
    snprintf(sql, sizeof sql,
             "SELECT name, field_id, type, type_length, repetition_type, converted_type, logical_type "
             "FROM parquet_schema('%s') WHERE name <> 'schema'", path);
    if (!query(con, sql, &r)) {
        if (duckdb_row_count(&r) != NC) FAIL("%s: %" PRIu64 " schema rows\n", path, (uint64_t)duckdb_row_count(&r));
        for (idx_t row = 0; row < duckdb_row_count(&r) && row < NC; row++) {
            char *nm = duckdb_value_varchar(&r, 0, row);
            pq_col p;
            col_shape((int)row, &p);
            if (strcmp(nm, p.name) || duckdb_value_int64(&r, 1, row) != p.field_id) FAIL("%s: schema row %" PRIu64 "\n", path, (uint64_t)row);
            duckdb_free(nm);
            for (idx_t k = 0; k < 5; k++) {
                char *v = duckdb_value_is_null(&r, 2 + k, row) ? NULL : duckdb_value_varchar(&r, 2 + k, row);
                if (strcmp(v ? v : "NULL", want_schema[row][k]))
                    FAIL("%s: column %s's schema field %u is %s, want %s\n", path, names[row], (unsigned)k, v ? v : "NULL",
                         want_schema[row][k]);
                duckdb_free(v);
            }
        }
        duckdb_destroy_result(&r);
    }
    snprintf(sql, sizeof sql, "DESCRIBE SELECT * FROM read_parquet('%s')", path);
    if (!query(con, sql, &r)) {
        for (idx_t row = 0; row < duckdb_row_count(&r) && row < NC; row++) {
            char *nm = duckdb_value_varchar(&r, 0, row), *ty = duckdb_value_varchar(&r, 1, row);
            if (strcmp(nm, names[row]) || strcmp(ty, dtype[row]))
                FAIL("%s: column %s is %s %s, want %s\n", path, names[row], nm, ty, dtype[row]);
            duckdb_free(nm);
            duckdb_free(ty);
        }
        duckdb_destroy_result(&r);
    }
    /* every value, by column, in the file's order (vid ascending) */
    static const char *const expr[NC] = {"\"imdb$vid\"", "\"imdb$begin\"", "\"imdb$flags\"", "\"imdb$salt\"",
                                         "\"imdb$commit\"", "k", "i", "s", "CAST(d * 100 AS BIGINT)", "CAST(w AS VARCHAR)",
                                         "t", "CAST(b AS INTEGER)", "epoch_us(ts)", "epoch_us(tz)", "dt - DATE '1970-01-01'",
                                         "CAST(round(EXTRACT(EPOCH FROM tm) * 1000000) AS BIGINT)", "CAST(u AS VARCHAR)",
                                         "bya", "f", "iv", "en", "rt", "zn"};
    for (int c = 0; c < NC; c++) {
        snprintf(sql, sizeof sql, "SELECT %s FROM read_parquet('%s') ORDER BY \"imdb$vid\"", expr[c], path);
        if (query(con, sql, &r)) continue;
        pq_col p;
        col_shape(c, &p);
        unsigned w = width(&p);
        for (uint64_t i = 0; i < d->n; i++) {
            bool isnull = duckdb_value_is_null(&r, 0, i);
            if (isnull != !present(d, c, i)) {
                FAIL("%s: column %s row %" PRIu64 " NULL %d\n", path, names[c], i, isnull);
                continue;
            }
            if (isnull) continue;
            if (p.logical == PQL_STRING) { /* DuckDB's VARCHAR */
                char *got = duckdb_value_varchar(&r, 0, i);
                size_t wl = (size_t)(d->off[c][i + 1] - d->off[c][i]);
                if (strlen(got) != wl || memcmp(got, d->bytes[c] + d->off[c][i], wl)) FAIL("%s: column %s row %" PRIu64 " text\n", path, names[c], i);
                duckdb_free(got);
            } else if (p.phys == PQ_BYTE_ARRAY || (p.phys == PQ_FLBA && p.logical == PQL_NONE)) {
                duckdb_blob b = duckdb_value_blob(&r, 0, i);
                const uint8_t *want = p.phys == PQ_FLBA ? d->fixed[c] + i * w : d->bytes[c] + d->off[c][i];
                size_t wl = p.phys == PQ_FLBA ? w : (size_t)(d->off[c][i + 1] - d->off[c][i]);
                if (b.size != wl || memcmp(b.data, want, wl)) FAIL("%s: column %s row %" PRIu64 " bytes\n", path, names[c], i);
                duckdb_free(b.data);
            } else if (c == 9 || c == 16) {
                char *got = duckdb_value_varchar(&r, 0, i), want[80];
                const uint8_t *v = d->fixed[c] + i * w;
                if (c == 9) dec128_text(v, 6, want);
                else
                    snprintf(want, sizeof want, "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
                             v[0], v[1], v[2], v[3], v[4], v[5], v[6], v[7], v[8], v[9], v[10], v[11], v[12], v[13], v[14], v[15]);
                if (strcmp(got, want)) FAIL("%s: column %s row %" PRIu64 " %s, want %s\n", path, names[c], i, got, want);
                duckdb_free(got);
            } else if (p.phys == PQ_DOUBLE) {
                if (duckdb_value_double(&r, 0, i) != fixed_d(d, c, i)) FAIL("%s: column f row %" PRIu64 "\n", path, i);
            } else {
                int64_t want = fixed_i(d, c, i, w);
                if (duckdb_value_int64(&r, 0, i) != want)
                    FAIL("%s: column %s row %" PRIu64 " %" PRId64 ", want %" PRId64 "\n", path, names[c], i,
                         duckdb_value_int64(&r, 0, i), want);
            }
        }
        duckdb_destroy_result(&r);
    }
    /* the statistics: each null count; min and max present exactly where asked and a value is, each parsed as the
     * column's type and equal to the data's MIN and MAX */
    snprintf(sql, sizeof sql,
             "SELECT stats_null_count, stats_min_value IS NOT NULL, stats_max_value IS NOT NULL FROM parquet_metadata('%s') "
             "ORDER BY column_id", path);
    if (!query(con, sql, &r)) {
        if (duckdb_row_count(&r) != NC) FAIL("%s: %" PRIu64 " metadata rows\n", path, (uint64_t)duckdb_row_count(&r));
        for (idx_t row = 0; row < duckdb_row_count(&r) && row < NC; row++) {
            int c = (int)row;
            pq_col p;
            col_shape(c, &p);
            uint64_t nulls = 0;
            for (uint64_t i = 0; i < d->n; i++) nulls += !present(d, c, i);
            if ((uint64_t)duckdb_value_int64(&r, 0, row) != nulls) FAIL("%s: column %s null count\n", path, names[c]);
            bool want = p.stats && nulls < d->n;
            if (duckdb_value_boolean(&r, 1, row) != want || duckdb_value_boolean(&r, 2, row) != want)
                FAIL("%s: column %s min and max present: %d %d, want %d\n", path, names[c], duckdb_value_boolean(&r, 1, row),
                     duckdb_value_boolean(&r, 2, row), want);
        }
        duckdb_destroy_result(&r);
    }
    for (int c = 0; c < NC; c++) {
        pq_col p;
        col_shape(c, &p);
        if (!p.stats) continue;
        unsigned w = width(&p);
        uint64_t imin = UINT64_MAX, imax = UINT64_MAX, npresent = 0;
        for (uint64_t i = 0; i < d->n; i++) {
            if (!present(d, c, i)) continue;
            npresent++;
            if (imin == UINT64_MAX || cmp_rows(d, c, i, imin, w) < 0) imin = i;
            if (imax == UINT64_MAX || cmp_rows(d, c, i, imax, w) > 0) imax = i;
        }
        if (!npresent) continue;
        snprintf(sql, sizeof sql,
                 "SELECT CAST(m.stats_min_value AS %s) = d.mn AND CAST(m.stats_max_value AS %s) = d.mx "
                 "FROM parquet_metadata('%s') m, (SELECT MIN(\"%s\") mn, MAX(\"%s\") mx FROM read_parquet('%s')) d "
                 "WHERE m.column_id = %d",
                 dtype[c], dtype[c], path, names[c], names[c], path, c);
        if (query_i64(con, sql) != 1) FAIL("%s: column %s min and max are not the data's\n", path, names[c]);
        /* pruning by them: one row group, so a bound that lied would prune rows a predicate wants */
        char lmin[160], lmax[160];
        literal(d, c, imin, lmin, sizeof lmin);
        literal(d, c, imax, lmax, sizeof lmax);
        int64_t at_min = 0, at_max = 0;
        for (uint64_t i = 0; i < d->n; i++)
            if (present(d, c, i)) {
                at_min += cmp_rows(d, c, i, imin, w) == 0;
                at_max += cmp_rows(d, c, i, imax, w) == 0;
            }
        struct {
            const char *op;
            const char *lit;
            int64_t want;
        } pr[] = {{"=", lmin, at_min}, {"=", lmax, at_max}, {"<", lmin, 0}, {">", lmax, 0}};
        for (size_t k = 0; k < sizeof pr / sizeof *pr; k++) {
            snprintf(sql, sizeof sql, "SELECT COUNT(*) FROM read_parquet('%s') WHERE \"%s\" %s %s", path, names[c], pr[k].op,
                     pr[k].lit);
            int64_t got = query_i64(con, sql);
            if (got != pr[k].want) FAIL("%s: column %s %s %s: %" PRId64 " rows, want %" PRId64 "\n", path, names[c], pr[k].op, pr[k].lit, got, pr[k].want);
        }
        snprintf(sql, sizeof sql, "SELECT COUNT(*) FROM read_parquet('%s') WHERE \"%s\" BETWEEN %s AND %s", path, names[c], lmin, lmax);
        if (query_i64(con, sql) != (int64_t)npresent) FAIL("%s: column %s between its bounds\n", path, names[c]);
    }
}

/* Parquet's zero rule for DOUBLE statistics: a zero min written -0.0, a zero max +0.0 (the values imagedb's +0.0) */
static void check_zero_rule(duckdb_connection con, const char *dir)
{
    int64_t v[3] = {1, 2, 3};
    double up[3] = {0.0, 1.5, 2.5}, down[3] = {-3.0, 0.0, -1.0};
    pq_col cols[3] = {
        {.name = "v", .field_id = 1, .phys = PQ_INT64, .fixed = (const uint8_t *)v},
        {.name = "up", .field_id = 2, .phys = PQ_DOUBLE, .stats = true, .fixed = (const uint8_t *)up},
        {.name = "down", .field_id = 3, .phys = PQ_DOUBLE, .stats = true, .fixed = (const uint8_t *)down},
    };
    pq_kv kv[] = {{"imagedb.format", "1"}};
    imdb_buf b;
    imdb_buf_init(&b);
    imdb_err e = {0};
    char path[600], sql[1024];
    snprintf(path, sizeof path, "%s/zero-rule.parquet", dir);
    FILE *f = NULL;
    if (imdb_pq_write(cols, 3, 3, kv, 1, &b, &e) || !(f = fopen(path, "wb")) || fwrite(b.p, 1, b.len, f) != b.len ||
        fclose(f)) {
        FAIL("%s: not written\n", path);
        imdb_buf_free(&b);
        return;
    }
    imdb_buf_free(&b);
    duckdb_result r;
    snprintf(sql, sizeof sql, "SELECT stats_min_value, stats_max_value FROM parquet_metadata('%s') ORDER BY column_id", path);
    if (query(con, sql, &r)) return;
    if (duckdb_row_count(&r) == 3) {
        char *umin = duckdb_value_varchar(&r, 0, 1), *dmax = duckdb_value_varchar(&r, 1, 2);
        double a = strtod(umin, NULL), z = strtod(dmax, NULL);
        if (a != 0 || !signbit(a) || z != 0 || signbit(z))
            FAIL("%s: the zero rule: up's min %s (want -0.0), down's max %s (want 0.0)\n", path, umin, dmax);
        duckdb_free(umin);
        duckdb_free(dmax);
    } else {
        FAIL("%s: metadata rows\n", path);
    }
    duckdb_destroy_result(&r);
    snprintf(sql, sizeof sql, "SELECT COUNT(*) FROM read_parquet('%s') WHERE up = 0 AND down = -3", path);
    if (query_i64(con, sql) != 1) FAIL("%s: the zero rows\n", path);
}

static void free_data(data *d)
{
    for (int c = 0; c < NC; c++) {
        free(d->fixed[c]);
        free(d->off[c]);
        free(d->bytes[c]);
        free(d->present[c]);
    }
}

int main(int argc, char **argv)
{
    if (argc != 2) {
        fprintf(stderr, "usage: pqcheck DIR\n");
        return 2;
    }
    duckdb_database db;
    duckdb_connection con;
    if (duckdb_open(NULL, &db) == DuckDBError || duckdb_connect(db, &con) == DuckDBError) {
        fprintf(stderr, "pqcheck: DuckDB does not open\n");
        return 2;
    }
    duckdb_result r;
    if (duckdb_query(con, "SET TimeZone = 'UTC'", &r) == DuckDBError) /* TIMESTAMPTZ's text and casts in UTC */
        fprintf(stderr, "pqcheck: SET TimeZone refused: %s\n", duckdb_result_error(&r));
    duckdb_destroy_result(&r);
    static const uint64_t sizes[] = {1, 7, 8, 9, 16, 100, 16385, 40000};
    for (size_t s = 0; s < sizeof sizes / sizeof *sizes; s++) {
        data d;
        memset(&d, 0, sizeof d);
        build(&d, sizes[s]);
        pq_col cols[NC];
        for (int c = 0; c < NC; c++) {
            col_shape(c, &cols[c]);
            cols[c].fixed = d.fixed[c];
            cols[c].off = d.off[c];
            cols[c].data = d.bytes[c];
            cols[c].present = d.present[c];
        }
        pq_kv kv[] = {{"imagedb.format", "1"}, {"imagedb.table", "7"}};
        imdb_buf b;
        imdb_buf_init(&b);
        imdb_err e = {0};
        if (imdb_pq_write(cols, NC, d.n, kv, 2, &b, &e)) {
            FAIL("write %" PRIu64 " rows: %s\n", d.n, e.msg);
        } else {
            char path[600];
            snprintf(path, sizeof path, "%s/rows-%" PRIu64 ".parquet", argv[1], d.n);
            FILE *f = fopen(path, "wb");
            if (!f || fwrite(b.p, 1, b.len, f) != b.len || fclose(f)) FAIL("%s: not written\n", path);
            else check_file(con, path, &d);
            printf("rows %" PRIu64 ": %zu bytes\n", d.n, b.len);
        }
        imdb_buf_free(&b);
        free_data(&d);
    }
    check_zero_rule(con, argv[1]);
    duckdb_disconnect(&con);
    duckdb_close(&db);
    if (fails) {
        fprintf(stderr, "pqcheck: %d failures\n", fails);
        return 1;
    }
    printf("pqcheck: every file read by DuckDB %s as written: types, values, statistics and pruning\n",
           duckdb_library_version());
    return 0;
}
