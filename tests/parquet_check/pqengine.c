/* F5: `make parquet-check`'s second part (the advisor 16:2x): DuckDB reads the segments the engine itself wrote, so the
 * engine's mapping (lake.c seg_shapes and seg_kv, which its build and parse share) meets a reader from outside. A table
 * of every type, at their edges (DECIMAL(1,0), (18,18), (19,0), (38,6); F5b, Iceberg's widths: (9,9) an INT32 at its
 * end, (19,0) 9 bytes, (30,4) 13 bytes and (38,6) 16, each at its precision's ends; INTEGER and SMALLINT at their ends; a NOT NULL
 * INTEGER; a SUBJECT; an ENUM), NULLs in every nullable column, 300 rows and a CHECKPOINT, an ALTER adding a column and
 * 100 more rows, an ERASE SUBJECT (segments rewritten with stubs), a CHECKPOINT. Then each segment's file in objects/:
 * DuckDB's types against the schema version that built it; each data row's values against imagedb's own SELECT of that
 * row (by id; the integers, times and FLOAT64 as numbers, DECIMAL as text, bytes as bytes, INTERVAL as its 16 bytes,
 * an ENUM as its ordinal); each stub's columns NULL or zero; every live row met once. Usage: pqengine DIR (a fresh
 * directory is made beneath it) */
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "duckdb.h"
#include "../../src/db_internal.h"
#include "../../src/lake.h"
#include "../../src/sql.h"

static int fails;
#define FAIL(...)                                                                                                      \
    do {                                                                                                               \
        if (fails++ < 40) fprintf(stderr, "FAIL: " __VA_ARGS__);                                                       \
    } while (0)

static imdb_session s;
static imdb_err e;

static void run(const char *q)
{
    imdb_result r;
    if (imdb_exec_one(&s, q, strlen(q), NULL, 0, &r, &e)) {
        fprintf(stderr, "%s: %s\n", q, e.msg);
        exit(2);
    }
    imdb_result_free(&r);
}

/* DuckDB's type for an imagedb column, and the expression that reads it in a comparable form */
static void dtype(const imdb_column *c, char *out, size_t cap)
{
    switch (c->type) {
    case IMDB_T_INT64: snprintf(out, cap, "%s", c->precision == 16 ? "SMALLINT" : c->precision == 32 ? "INTEGER" : "BIGINT"); break;
    case IMDB_T_DECIMAL: snprintf(out, cap, "DECIMAL(%u,%u)", c->precision, c->scale); break;
    case IMDB_T_TEXT: snprintf(out, cap, "VARCHAR"); break;
    case IMDB_T_BYTEA: snprintf(out, cap, "BLOB"); break;
    case IMDB_T_BOOL: snprintf(out, cap, "BOOLEAN"); break;
    case IMDB_T_TIMESTAMP: snprintf(out, cap, "TIMESTAMP"); break;
    case IMDB_T_TIMESTAMPTZ: snprintf(out, cap, "TIMESTAMP WITH TIME ZONE"); break;
    case IMDB_T_DATE: snprintf(out, cap, "DATE"); break;
    case IMDB_T_TIME: snprintf(out, cap, "TIME"); break;
    case IMDB_T_UUID: snprintf(out, cap, "UUID"); break;
    case IMDB_T_FLOAT64: snprintf(out, cap, "DOUBLE"); break;
    case IMDB_T_INTERVAL: snprintf(out, cap, "BLOB"); break;
    default: snprintf(out, cap, "BIGINT"); break; /* ENUM: its ordinal */
    }
}

static void dexpr(const imdb_column *c, char *out, size_t cap)
{
    const char *n = c->name;
    switch (c->type) {
    case IMDB_T_DECIMAL:
    case IMDB_T_UUID: snprintf(out, cap, "CAST(\"%s\" AS VARCHAR)", n); break;
    case IMDB_T_BOOL: snprintf(out, cap, "CAST(\"%s\" AS INTEGER)", n); break;
    case IMDB_T_TIMESTAMP:
    case IMDB_T_TIMESTAMPTZ: snprintf(out, cap, "epoch_us(\"%s\")", n); break;
    case IMDB_T_DATE: snprintf(out, cap, "\"%s\" - DATE '1970-01-01'", n); break;
    case IMDB_T_TIME: snprintf(out, cap, "CAST(round(EXTRACT(EPOCH FROM \"%s\") * 1000000) AS BIGINT)", n); break;
    default: snprintf(out, cap, "\"%s\"", n); break;
    }
}

/* one cell: DuckDB's column k of row r against imagedb's value v of column c */
static bool same(const imdb_column *c, duckdb_result *r, idx_t k, idx_t row, const imdb_value *v)
{
    bool dnull = duckdb_value_is_null(r, k, row);
    if (dnull || v->null) return dnull && v->null;
    switch (c->type) {
    case IMDB_T_DECIMAL: {
        imdb_buf b;
        imdb_buf_init(&b);
        imdb_format_value(v, &b);
        imdb_buf_put_u8(&b, 0);
        char *got = duckdb_value_varchar(r, k, row);
        /* DuckDB prints a DECIMAL of no integer digits (its precision its scale) as ".99", imagedb as "0.99": the same
         * value, compared without that leading zero */
        const char *gs = got, *ws = (const char *)b.p;
        char gz[80], wz[80];
        if (!strncmp(ws, "0.", 2) || !strncmp(ws, "-0.", 3)) {
            snprintf(wz, sizeof wz, "%s%s", ws[0] == '-' ? "-" : "", ws + (ws[0] == '-' ? 2 : 1));
            ws = wz;
        }
        if (!strncmp(gs, "0.", 2) || !strncmp(gs, "-0.", 3)) {
            snprintf(gz, sizeof gz, "%s%s", gs[0] == '-' ? "-" : "", gs + (gs[0] == '-' ? 2 : 1));
            gs = gz;
        }
        bool ok = !strcmp(gs, ws);
        if (!ok) fprintf(stderr, "  %s: %s against imagedb's %s\n", c->name, got, (const char *)b.p);
        duckdb_free(got);
        imdb_buf_free(&b);
        return ok;
    }
    case IMDB_T_UUID: {
        char want[40];
        const uint8_t *u = v->s;
        snprintf(want, sizeof want, "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x", u[0], u[1], u[2],
                 u[3], u[4], u[5], u[6], u[7], u[8], u[9], u[10], u[11], u[12], u[13], u[14], u[15]);
        char *got = duckdb_value_varchar(r, k, row);
        bool ok = !strcmp(got, want);
        duckdb_free(got);
        return ok;
    }
    case IMDB_T_TEXT: {
        char *got = duckdb_value_varchar(r, k, row);
        bool ok = strlen(got) == v->len && !memcmp(got, v->s, v->len);
        duckdb_free(got);
        return ok;
    }
    case IMDB_T_BYTEA:
    case IMDB_T_INTERVAL: {
        uint8_t iv[16];
        const uint8_t *want = v->s;
        size_t wl = v->len;
        if (c->type == IMDB_T_INTERVAL) { /* its 16 bytes: months, days, microseconds, little-endian */
            imdb_le32(iv, (uint32_t)v->iv.mon);
            imdb_le32(iv + 4, (uint32_t)v->iv.day);
            imdb_le64(iv + 8, (uint64_t)v->i);
            want = iv;
            wl = 16;
        }
        duckdb_blob b = duckdb_value_blob(r, k, row);
        bool ok = b.size == wl && (!wl || !memcmp(b.data, want, wl));
        duckdb_free(b.data);
        return ok;
    }
    case IMDB_T_FLOAT64: return duckdb_value_double(r, k, row) == imdb_f64_value(v->i);
    default: return duckdb_value_int64(r, k, row) == v->i; /* integers, BOOL, times, an ENUM's ordinal */
    }
}

int main(int argc, char **argv)
{
    if (argc != 2) {
        fprintf(stderr, "usage: pqengine DIR\n");
        return 2;
    }
    char parent[1024], dir[1100]; /* a fresh directory beneath DIR: nothing removed before a run */
    snprintf(parent, sizeof parent, "%s/engine-XXXXXX", argv[1]);
    if (!mkdtemp(parent)) {
        perror("pqengine: mkdtemp");
        return 2;
    }
    snprintf(dir, sizeof dir, "%s/db", parent);
    imdb_db *db;
    imdb_open_opts o = {.sync = 0, .seg_cache_bytes = UINT64_MAX / 2};
    if (imdb_init(dir, false, NULL, &e) || imdb_open(dir, &o, &db, &e)) {
        fprintf(stderr, "pqengine: %s\n", e.msg);
        return 2;
    }
    imdb_session_init(&s, db);
    run("CREATE TYPE mood AS ENUM ('sad', 'ok', 'happy')");
    run("CREATE TABLE t (id BIGINT PRIMARY KEY, sub BIGINT SUBJECT, n INTEGER NOT NULL, i INTEGER, s SMALLINT, b BIGINT, "
        "d DECIMAL(10,2), d1 DECIMAL(1,0), d18 DECIMAL(18,18), w DECIMAL(38,6), w19 DECIMAL(19,0), x TEXT, v VARCHAR(5), "
        "bya BYTEA, bo BOOLEAN, ts TIMESTAMP, tz TIMESTAMPTZ, dt DATE, tm TIME, u UUID, f FLOAT64, iv INTERVAL, e mood, "
        "w30 DECIMAL(30,4), d9 DECIMAL(9,9))");
    for (int r = 1; r <= 400; r++) {
        if (r == 301) {
            run("CHECKPOINT");
            run("ALTER TABLE t ADD COLUMN z INTEGER");
        }
        char q[2048];
        int nul = r % 7; /* each nullable column NULL in a seventh of the rows, by its own residue */
#define NV(k, lit) (nul == (k) ? "NULL" : (lit))
        char d[40], w[64], x[40], ts[48];
        snprintf(d, sizeof d, "%d.%02d", (r % 2 ? -1 : 1) * (r * 37 % 100000), r % 100);
        snprintf(w, sizeof w, "%s%d%s", r % 3 ? "" : "-", r % 9 + 1,
                 r % 3 ? "12345678901234567890123456789.123456" : "1234567890123456789012345.000001");
        snprintf(x, sizeof x, "'text %d with ''quote'''", r);
        snprintf(ts, sizeof ts, "'%04d-0%d-1%d 12:34:56.%06d'", 1900 + r, r % 9 + 1, r % 10, r * 1009 % 1000000);
        snprintf(q, sizeof q,
                 "INSERT INTO t (id, sub, n, i, s, b, d, d1, d18, w, w19, x, v, bya, bo, ts, tz, dt, tm, u, f, iv, e, w30, d9%s) "
                 "VALUES (%d, %d, %d, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, TIMESTAMP %s, TIMESTAMPTZ %s, "
                 "DATE '%04d-12-31', TIME '23:59:%02d.999999', '%08x-1111-4222-8333-444455556666', %s, INTERVAL '%d mons %d "
                 "days %d microseconds', %s, %s, %s%s%s)",
                 r > 300 ? ", z" : "", r, r % 10, r % 2 ? 2147483647 : -2147483647 - 1, NV(1, r % 2 ? "2147483647" : "-2147483648"),
                 NV(2, r % 2 ? "32767" : "-32768"), NV(3, "9223372036854775807"), NV(4, d), NV(5, r % 2 ? "9" : "-9"),
                 NV(6, "0.999999999999999999"), NV(0, w), NV(1, r % 2 ? "9999999999999999999" : "-9999999999999999999"),
                 NV(2, x), NV(3, "'abcde'"), NV(4, "'\\x00ff10'"), NV(5, r % 2 ? "TRUE" : "FALSE"), ts, ts,
                 1 + r % 9999, r % 60, r * 2654435761u, NV(6, r % 5 ? "-1.25e300" : "0"), r % 1000 - 500, r % 61 - 30,
                 r * 1000003, NV(0, r % 3 ? "'happy'" : "'sad'"),
                 NV(2, r % 2 ? "99999999999999999999999999.9999" : r % 5 ? "-99999999999999999999999999.9999" : "-0.0001"),
                 NV(3, r % 2 ? "0.999999999" : r % 5 ? "-0.999999999" : "0.000000001"), r > 300 ? ", " : "",
                 r > 300 ? (r % 4 ? "77" : "NULL") : "");
        run(q);
    }
    run("ERASE SUBJECT 7");
    run("CHECKPOINT");
    /* imagedb's own rows, by id */
    imdb_result all;
    const char *q = "SELECT * FROM t";
    if (imdb_exec_one(&s, q, strlen(q), NULL, 0, &all, &e)) {
        fprintf(stderr, "%s: %s\n", q, e.msg);
        return 2;
    }
    int64_t *at = calloc(401, sizeof *at); /* id -> its row in all, +1 */
    for (uint64_t r = 0; r < all.nrows; r++) at[all.cells[r * all.ncols].v.i] = (int64_t)r + 1;
    uint8_t *met = calloc(401, 1);
    duckdb_database ddb;
    duckdb_connection con;
    if (duckdb_open(NULL, &ddb) || duckdb_connect(ddb, &con)) return 2;
    duckdb_result dr;
    if (duckdb_query(con, "SET TimeZone = 'UTC'", &dr) == DuckDBError) fprintf(stderr, "%s\n", duckdb_result_error(&dr));
    duckdb_destroy_result(&dr);
    imdb_table *t = imdb_table_by_name(db, "t");
    uint64_t data_rows = 0, stubs = 0;
    for (uint32_t k = 0; k < t->nseg; k++) {
        imdb_segment *g = t->seg[k];
        const imdb_schema *sv = &t->hist.vers[g->gver].s;
        char hx[65], path[1300], sql[8192];
        imdb_hex(g->hash, 32, hx);
        snprintf(path, sizeof path, "%s/objects/%s.seg", dir, hx);
        /* the types: the system columns, then the version's columns in its order */
        snprintf(sql, sizeof sql, "DESCRIBE SELECT * FROM read_parquet('%s')", path);
        if (duckdb_query(con, sql, &dr) == DuckDBError) {
            FAIL("%s: %s\n", path, duckdb_result_error(&dr));
            duckdb_destroy_result(&dr);
            continue;
        }
        if (duckdb_row_count(&dr) != 5u + sv->ncols) FAIL("%s: %llu columns\n", path, (unsigned long long)duckdb_row_count(&dr));
        for (uint16_t c = 0; c < sv->ncols && 5u + c < duckdb_row_count(&dr); c++) {
            char want[64], *nm = duckdb_value_varchar(&dr, 0, 5u + c), *ty = duckdb_value_varchar(&dr, 1, 5u + c);
            dtype(&sv->cols[c], want, sizeof want);
            if (strcmp(nm, sv->cols[c].name) || strcmp(ty, want))
                FAIL("%s: column %u is %s %s, want %s %s\n", path, c, nm, ty, sv->cols[c].name, want);
            duckdb_free(nm);
            duckdb_free(ty);
        }
        duckdb_destroy_result(&dr);
        /* F5b, as DuckDB's parquet_schema reads the file: imdb$vid and imdb$begin under Iceberg v3's row-lineage field ids,
         * each DECIMAL in Iceberg's physical type and width (the least bytes with 10^P <= 2^(8b - 1), computed here) */
        snprintf(sql, sizeof sql, "SELECT name, CAST(field_id AS VARCHAR), type, CAST(type_length AS VARCHAR) FROM parquet_schema('%s')", path);
        if (duckdb_query(con, sql, &dr) == DuckDBError) {
            FAIL("%s: %s\n", path, duckdb_result_error(&dr));
            duckdb_destroy_result(&dr);
            continue;
        }
        unsigned ndec = 0, wdec = 0, nlin = 0;
        for (uint16_t c = 0; c < sv->ncols; c++) wdec += sv->cols[c].type == IMDB_T_DECIMAL;
        for (idx_t row = 0; row < duckdb_row_count(&dr); row++) {
            char *nm = duckdb_value_varchar(&dr, 0, row), *fid = duckdb_value_varchar(&dr, 1, row),
                 *ty = duckdb_value_varchar(&dr, 2, row), *tl = duckdb_value_varchar(&dr, 3, row);
            if (!strcmp(nm, "imdb$vid") || !strcmp(nm, "imdb$begin")) {
                nlin++;
                if (strcmp(fid, nm[5] == 'v' ? "2147483540" : "2147483539")) FAIL("%s: %s's field id %s\n", path, nm, fid);
            }
            for (uint16_t c = 0; c < sv->ncols; c++) {
                const imdb_column *cc = &sv->cols[c];
                if (cc->type != IMDB_T_DECIMAL || strcmp(nm, cc->name)) continue;
                char wl[8] = "NULL";
                if (cc->precision > 18) {
                    unsigned __int128 ten = 1;
                    for (unsigned i = 0; i < cc->precision; i++) ten *= 10u;
                    unsigned b = 1;
                    while (ten > (unsigned __int128)1 << (8 * b - 1)) b++;
                    snprintf(wl, sizeof wl, "%u", b);
                }
                const char *wt = cc->precision <= 9 ? "INT32" : cc->precision <= 18 ? "INT64" : "FIXED_LEN_BYTE_ARRAY";
                if (strcmp(ty, wt) || strcmp(tl ? tl : "NULL", wl))
                    FAIL("%s: DECIMAL(%u,%u) %s is %s of %s, want %s of %s\n", path, cc->precision, cc->scale, nm, ty, tl ? tl : "NULL", wt, wl);
                ndec++;
            }
            duckdb_free(nm);
            duckdb_free(fid);
            duckdb_free(ty);
            if (tl) duckdb_free(tl);
        }
        if (ndec != wdec || nlin != 2) FAIL("%s: %u DECIMAL columns of %u and %u lineage columns seen\n", path, ndec, wdec, nlin);
        duckdb_destroy_result(&dr);
        /* the rows in vid order: the flags, then each column comparable */
        size_t at_sql = (size_t)snprintf(sql, sizeof sql, "SELECT \"imdb$flags\"");
        for (uint16_t c = 0; c < sv->ncols; c++) {
            char ex[160];
            dexpr(&sv->cols[c], ex, sizeof ex);
            at_sql += (size_t)snprintf(sql + at_sql, sizeof sql - at_sql, ", %s", ex);
        }
        snprintf(sql + at_sql, sizeof sql - at_sql, " FROM read_parquet('%s') ORDER BY \"imdb$vid\"", path);
        if (duckdb_query(con, sql, &dr) == DuckDBError) {
            FAIL("%s: %s\n", path, duckdb_result_error(&dr));
            duckdb_destroy_result(&dr);
            continue;
        }
        if (duckdb_row_count(&dr) != g->nrows) FAIL("%s: %llu rows, the segment %u\n", path, (unsigned long long)duckdb_row_count(&dr), g->nrows);
        for (idx_t row = 0; row < duckdb_row_count(&dr); row++) {
            int64_t flags = duckdb_value_int64(&dr, 0, row);
            if (flags) { /* a stub: each column NULL where OPTIONAL, zero where REQUIRED */
                stubs++;
                for (uint16_t c = 0; c < sv->ncols; c++) {
                    bool opt = (sv->cols[c].flags & IMDB_COL_NULLABLE) != 0;
                    if (opt ? !duckdb_value_is_null(&dr, 1 + c, row)
                            : (sv->cols[c].type == IMDB_T_INT64 && duckdb_value_int64(&dr, 1 + c, row) != 0))
                        FAIL("%s: a stub's %s is not its placeholder\n", path, sv->cols[c].name);
                }
                continue;
            }
            data_rows++;
            int64_t id = duckdb_value_int64(&dr, 1, row);
            if (id < 1 || id > 400 || !at[id]) {
                FAIL("%s: a row of id %lld imagedb does not hold\n", path, (long long)id);
                continue;
            }
            if (met[id]++) FAIL("%s: id %lld met twice\n", path, (long long)id);
            uint64_t ir = (uint64_t)(at[id] - 1);
            for (uint16_t c = 0; c < sv->ncols; c++) {
                uint16_t ic = 0; /* imagedb's column of that name */
                while (ic < all.ncols && strcmp(all.names[ic], sv->cols[c].name)) ic++;
                if (ic == all.ncols) {
                    FAIL("%s: column %s not in imagedb's SELECT\n", path, sv->cols[c].name);
                    continue;
                }
                imdb_value cv = all.cells[ir * all.ncols + ic].v; /* a cell is NULL by its own flag or its value's (the renderer's) */
                cv.null = cv.null || all.cells[ir * all.ncols + ic].null;
                if (!same(&sv->cols[c], &dr, 1 + c, row, &cv))
                    FAIL("%s: row %lld's %s differs\n", path, (long long)id, sv->cols[c].name);
            }
        }
        duckdb_destroy_result(&dr);
    }
    if (data_rows != all.nrows) FAIL("%llu data rows in the segments, imagedb holds %llu\n", (unsigned long long)data_rows, (unsigned long long)all.nrows);
    if (!stubs) FAIL("no stub: the ERASE rewrote nothing\n");
    printf("pqengine: %u segments, %llu data rows and %llu stubs, every type and value as imagedb holds them\n", t->nseg,
           (unsigned long long)data_rows, (unsigned long long)stubs);
    imdb_result_free(&all);
    free(at);
    free(met);
    duckdb_disconnect(&con);
    duckdb_close(&ddb);
    imdb_session_close(&s);
    imdb_close(db);
    if (fails) {
        fprintf(stderr, "pqengine: %d failures\n", fails);
        return 1;
    }
    return 0;
}
