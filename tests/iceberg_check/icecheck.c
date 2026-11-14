/* F5c: `make iceberg-check`: DuckDB (its iceberg and avro extensions, test-only: the user's yes, 2026-11-14) reads the
 * Iceberg v3 layer the engine writes, each snapshot of each kept generation against imagedb's own answer AS OF it. A
 * table of every type Iceberg carries (INTEGER, SMALLINT, BIGINT, DECIMALs narrow and wide, TEXT, BYTEA, DOUBLE,
 * BOOLEAN, DATE, TIME, TIMESTAMP, TIMESTAMPTZ, UUID) at their edges with NULLs, a SUBJECT, an INTERVAL and an ENUM (left
 * out of the Iceberg schema); then by publications: updates and deletes (deletion vectors), columns added with DEFAULTs of
 * every type (an older file's rows answer their initial-default: Appendix D's texts as DuckDB reads them), an ERASE
 * SUBJECT (stubs: flagged rows in the vectors), a RENAME and a DROP COLUMN (schema evolution by field id), a widening, a
 * COMPACT. At each publication every snapshot the head's metadata names is read through iceberg_scan(..., snapshot_from_id
 * => S): its rows ordered by id, each cell in one canonical text on both sides (integers and DECIMALs as their digits,
 * BYTEA as hex, DOUBLE as %.17g, BOOLEAN 0 or 1, DATE as days, TIME, TIMESTAMP and TIMESTAMPTZ as microseconds, UUID as
 * its text), against SELECT ... AS OF S of the same columns by position (a renamed column by its current name).
 * Usage: icecheck DIR (a fresh directory is made beneath it) */
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "duckdb.h"
#include "../../src/db_internal.h"
#include "../../src/iceberg.h"
#include "../../src/lake.h"
#include "../../src/sql.h"
#include "../../tools/audit/aice.h"

static int fails, snaps_checked, rows_checked;
#define FAIL(...)                                                                                                      \
    do {                                                                                                               \
        if (fails++ < 40) fprintf(stderr, "FAIL: " __VA_ARGS__);                                                       \
    } while (0)

static imdb_session s;
static imdb_err e;
static duckdb_connection dc;
static char g_dir[1024];

static void run(const char *q)
{
    imdb_result r;
    if (imdb_exec_one(&s, q, strlen(q), NULL, 0, &r, &e)) {
        fprintf(stderr, "%s: %s\n", q, e.msg);
        exit(2);
    }
    imdb_result_free(&r);
}

/* DuckDB's expression for column n of imagedb type c, in the canonical text */
static void dexpr(const imdb_column *c, const char *n, char *out, size_t cap)
{
    switch (c->type) {
    case IMDB_T_BYTEA: snprintf(out, cap, "lower(hex(\"%s\"))", n); break;
    case IMDB_T_FLOAT64: snprintf(out, cap, "printf('%%.17g', \"%s\")", n); break;
    case IMDB_T_BOOL: snprintf(out, cap, "CAST(CAST(\"%s\" AS INTEGER) AS VARCHAR)", n); break;
    case IMDB_T_DATE: snprintf(out, cap, "CAST(\"%s\" - DATE '1970-01-01' AS VARCHAR)", n); break;
    case IMDB_T_TIME: snprintf(out, cap, "CAST(CAST(round(EXTRACT(EPOCH FROM \"%s\") * 1000000) AS BIGINT) AS VARCHAR)", n); break;
    case IMDB_T_TIMESTAMP:
    case IMDB_T_TIMESTAMPTZ: snprintf(out, cap, "CAST(epoch_us(\"%s\") AS VARCHAR)", n); break;
    default: snprintf(out, cap, "CAST(\"%s\" AS VARCHAR)", n); break;
    }
}

/* imagedb's cell in the canonical text */
static void itext(const imdb_cell *cl, char *out, size_t cap)
{
    const imdb_value *v = &cl->v;
    if (cl->null || v->null) {
        snprintf(out, cap, "NULL");
        return;
    }
    imdb_buf b;
    imdb_buf_init(&b);
    switch (v->type) {
    case IMDB_T_INT64:
    case IMDB_T_DATE:
    case IMDB_T_TIME:
    case IMDB_T_TIMESTAMP:
    case IMDB_T_TIMESTAMPTZ: snprintf(out, cap, "%" PRId64, v->i); break;
    case IMDB_T_BOOL: snprintf(out, cap, "%d", v->i != 0); break;
    case IMDB_T_FLOAT64: snprintf(out, cap, "%.17g", imdb_f64_value(v->i)); break;
    case IMDB_T_TEXT: snprintf(out, cap, "%.*s", (int)v->len, (const char *)v->s); break;
    case IMDB_T_BYTEA: {
        size_t n = 0;
        for (uint32_t k = 0; k < v->len && n + 3 < cap; k++) n += (size_t)snprintf(out + n, cap - n, "%02x", v->s[k]);
        out[n] = 0;
        break;
    }
    default: /* DECIMAL, UUID: imagedb's own text */
        imdb_format_value(v, &b);
        snprintf(out, cap, "%.*s", (int)b.len, b.p ? (const char *)b.p : "");
        break;
    }
    imdb_buf_free(&b);
}

/* the table's snapshots in its layer at the head, each read by DuckDB against imagedb AS OF it */
static void check(imdb_db *db, const char *tname, const char *when)
{
    imdb_table *t = imdb_table_by_name(db, tname);
    if (!t) {
        FAIL("%s: no table %s\n", when, tname);
        return;
    }
    char meta[1400];
    snprintf(meta, sizeof meta, "%s/iceberg/%u/metadata/v%llu.metadata.json", db->location, (unsigned)t->s.id,
             (unsigned long long)db->lake_seq);
    FILE *fp = fopen(meta, "rb");
    if (!fp) {
        FAIL("%s: no layer at %s\n", when, meta);
        return;
    }
    static char jb[1 << 22];
    size_t jl = fread(jb, 1, sizeof jb, fp);
    fclose(fp);
    aj m;
    const char *why;
    if (aj_parse(jb, jl, &m, &why)) {
        FAIL("%s: the metadata does not parse: %s\n", when, why);
        return;
    }
    const aj *sn = aj_get(&m, "snapshots");
    for (size_t k = 0; sn && sn->kind == AJ_ARR && k < sn->n; k++) {
        const aj *id = aj_get(&sn->v[k], "snapshot-id"), *sid = aj_get(&sn->v[k], "schema-id");
        if (!id || id->kind != AJ_INT || !sid || sid->kind != AJ_INT || sid->i < 0 || (uint64_t)sid->i >= t->hist.nvers) {
            FAIL("%s: a snapshot without its id or schema\n", when);
            continue;
        }
        uint64_t S = (uint64_t)id->i;
        const imdb_sver *v = &t->hist.vers[sid->i], *cur = &t->hist.vers[t->hist.nvers - 1];
        char dq[16384], iq[16384];
        size_t dn = 0, in = 0;
        dn += (size_t)snprintf(dq + dn, sizeof dq - dn, "SELECT ");
        in += (size_t)snprintf(iq + in, sizeof iq - in, "SELECT ");
        int nc = 0;
        for (uint16_t c = 0; c < v->s.ncols; c++) { /* the snapshot's columns Iceberg carries, by position into today's names */
            const imdb_column *col = &v->s.cols[c];
            if (col->type == IMDB_T_INTERVAL || col->type == IMDB_T_ENUM) continue;
            uint16_t p = v->pos[c];
            int8_t at = p < cur->npos ? cur->at[p] : -1;
            if (at < 0) continue; /* dropped since: imagedb names it no more */
            char ex[600];
            dexpr(col, col->name, ex, sizeof ex);
            dn += (size_t)snprintf(dq + dn, sizeof dq - dn, "%s%s", nc ? ", " : "", ex);
            in += (size_t)snprintf(iq + in, sizeof iq - in, "%s%s", nc ? ", " : "", cur->s.cols[at].name); /* imagedb's names bare */
            nc++;
        }
        const char *idname = cur->s.cols[cur->at[v->pos[0]]].name; /* the key: position 0 here (id) */
        snprintf(dq + dn, sizeof dq - dn, " FROM iceberg_scan('%s', snapshot_from_id => %llu) ORDER BY \"%s\"", meta,
                 (unsigned long long)S, v->s.cols[0].name);
        snprintf(iq + in, sizeof iq - in, " FROM %s AS OF %llu ORDER BY %s", tname, (unsigned long long)S, idname);
        duckdb_result dr;
        if (duckdb_query(dc, dq, &dr) == DuckDBError) {
            FAIL("%s: snapshot %llu: DuckDB: %s\n  %s\n", when, (unsigned long long)S, duckdb_result_error(&dr), dq);
            duckdb_destroy_result(&dr);
            continue;
        }
        imdb_result ir;
        if (imdb_exec_one(&s, iq, strlen(iq), NULL, 0, &ir, &e)) {
            FAIL("%s: snapshot %llu: imagedb: %s\n  %s\n", when, (unsigned long long)S, e.msg, iq);
            duckdb_destroy_result(&dr);
            continue;
        }
        idx_t rows = duckdb_row_count(&dr);
        if (rows != ir.nrows || duckdb_column_count(&dr) != (idx_t)nc || ir.ncols != nc)
            FAIL("%s: snapshot %llu: DuckDB %llu rows of %llu columns, imagedb %llu of %u\n", when, (unsigned long long)S,
                 (unsigned long long)rows, (unsigned long long)duckdb_column_count(&dr), (unsigned long long)ir.nrows, ir.ncols);
        for (idx_t r = 0; r < rows && r < ir.nrows; r++) {
            for (int c = 0; c < nc && (idx_t)c < duckdb_column_count(&dr); c++) {
                char it[4096], *dv = duckdb_value_is_null(&dr, (idx_t)c, r) ? NULL : duckdb_value_varchar(&dr, (idx_t)c, r);
                itext(&ir.cells[r * ir.ncols + (size_t)c], it, sizeof it);
                char dn0[4200]; /* DuckDB writes a DECIMAL below one without its leading zero (.5, -.5): imagedb with it */
                const char *d = dv ? dv : "NULL";
                if (dv && (dv[0] == '.' || (dv[0] == '-' && dv[1] == '.'))) {
                    snprintf(dn0, sizeof dn0, "%s0%s", dv[0] == '-' ? "-" : "", dv + (dv[0] == '-'));
                    d = dn0;
                }
                if (strcmp(d, it))
                    FAIL("%s: snapshot %llu, row %llu, column %s: DuckDB %s, imagedb %s\n", when, (unsigned long long)S,
                         (unsigned long long)r, duckdb_column_name(&dr, (idx_t)c), d, it);
                duckdb_free(dv);
            }
            rows_checked++;
        }
        snaps_checked++;
        imdb_result_free(&ir);
        duckdb_destroy_result(&dr);
    }
    aj_free(&m);
}

int main(int argc, char **argv)
{
    if (argc != 2) {
        fprintf(stderr, "usage: icecheck DIR\n");
        return 2;
    }
    snprintf(g_dir, sizeof g_dir, "%s/icecheck-%ld", argv[1], (long)getpid());
    duckdb_database ddb;
    if (duckdb_open(NULL, &ddb) == DuckDBError || duckdb_connect(ddb, &dc) == DuckDBError) {
        fprintf(stderr, "cannot open DuckDB\n");
        return 2;
    }
    const char *pre[] = {"LOAD avro", "LOAD iceberg"};
    for (int k = 0; k < 2; k++) {
        duckdb_result r;
        if (duckdb_query(dc, pre[k], &r) == DuckDBError) {
            fprintf(stderr, "%s: %s (the extensions: INSTALL avro; INSTALL iceberg)\n", pre[k], duckdb_result_error(&r));
            return 2;
        }
        duckdb_destroy_result(&r);
    }
    if (imdb_init(g_dir, false, NULL, &e)) {
        fprintf(stderr, "init: %s\n", e.msg);
        return 2;
    }
    imdb_open_opts o = {.sync = 0, .iceberg = true};
    imdb_db *db = NULL;
    if (imdb_open(g_dir, &o, &db, &e)) {
        fprintf(stderr, "open: %s\n", e.msg);
        return 2;
    }
    imdb_session_init(&s, db);
    const char *lie = getenv("IMDB_ICECHECK_LIE"); /* its own check: the writer's lie (iceberg.h) must fail it */
    if (lie) imdb_iceberg_set_lie(atoi(lie));
    run("CREATE TYPE mood AS ENUM ('sad', 'ok', 'happy')");
    run("CREATE TABLE t (id BIGINT PRIMARY KEY, sub BIGINT SUBJECT, i INTEGER, sm SMALLINT, b BIGINT, d DECIMAL(10,2), "
        "d9 DECIMAL(9,9), w DECIMAL(38,6), x TEXT, y BYTEA, f DOUBLE PRECISION, o BOOLEAN, dt DATE, tm TIME, ts TIMESTAMP, "
        "tz TIMESTAMPTZ, u UUID, iv INTERVAL, en mood, nn INTEGER NOT NULL)");
    run("INSERT INTO t VALUES "
        "(1, 7, 2147483647, 32767, 9223372036854775807, 99999999.99, 0.999999999, 99999999999999999999999999999999.999999, "
        "'one', '\\x00ff', 1.5, TRUE, DATE '9999-12-31', TIME '23:59:59.999999', TIMESTAMP '2017-11-16 22:31:08.123456', "
        "TIMESTAMPTZ '2017-11-16 22:31:08.123456+00', 'f79c3e09-677c-4bbd-a479-3f349cb785e7', INTERVAL '1 day', 'ok', 1), "
        "(2, 8, -2147483648, -32768, -9223372036854775807, -99999999.99, -0.999999999, -99999999999999999999999999999999.999999, "
        "'', '\\x', -0.0, FALSE, DATE '0001-01-01', TIME '00:00:00', TIMESTAMP '1969-12-31 23:59:59.999999', "
        "TIMESTAMPTZ '1900-01-01 00:00:00+00', '00000000-0000-0000-0000-000000000000', INTERVAL '-1 month', 'sad', 2), "
        "(3, 7, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 3), "
        "(4, 9, 0, 0, 0, 0.01, 0.000000001, 0.000001, 'zé\"\\\\', '\\x0102ff', 1e300, TRUE, DATE '1970-01-01', TIME '12:00:00', "
        "TIMESTAMP '1970-01-01 00:00:00', TIMESTAMPTZ '2262-01-01 00:00:00+00', 'ffffffff-ffff-ffff-ffff-ffffffffffff', "
        "INTERVAL '0 seconds', 'happy', 4)");
    run("CHECKPOINT");
    check(db, "t", "first publication");
    run("UPDATE t SET x = 'one, again', i = 5 WHERE id = 1");
    run("DELETE FROM t WHERE id = 2");
    run("INSERT INTO t (id, sub, nn) VALUES (5, 9, 5), (6, 10, 6)");
    run("CHECKPOINT");
    check(db, "t", "an update and a delete");
    static const char *const adds[] = { /* each type's initial-default: an older file's rows read it */
        "ALTER TABLE t ADD COLUMN a1 INTEGER DEFAULT -7",
        "ALTER TABLE t ADD COLUMN a2 BIGINT NOT NULL DEFAULT 9223372036854775807",
        "ALTER TABLE t ADD COLUMN a3 DECIMAL(10,2) DEFAULT -0.05",
        "ALTER TABLE t ADD COLUMN a4 DECIMAL(38,6) DEFAULT 12345678901234567890.123456",
        "ALTER TABLE t ADD COLUMN a5 TEXT DEFAULT 'zé\"\\\\ x'",
        "ALTER TABLE t ADD COLUMN a6 BYTEA DEFAULT '\\x000102ff'",
        "ALTER TABLE t ADD COLUMN a7 DOUBLE PRECISION DEFAULT 2",
        "ALTER TABLE t ADD COLUMN a8 BOOLEAN DEFAULT TRUE",
        "ALTER TABLE t ADD COLUMN a9 DATE DEFAULT DATE '1969-12-31'",
        "ALTER TABLE t ADD COLUMN b1 TIME DEFAULT TIME '22:31:08.123456'",
        "ALTER TABLE t ADD COLUMN b2 TIMESTAMP DEFAULT TIMESTAMP '2017-11-16 22:31:08.123456'",
        "ALTER TABLE t ADD COLUMN b3 TIMESTAMPTZ DEFAULT TIMESTAMPTZ '2017-11-16 22:31:08.123456+00'",
        "ALTER TABLE t ADD COLUMN b4 UUID DEFAULT 'f79c3e09-677c-4bbd-a479-3f349cb785e7'",
        "ALTER TABLE t ADD COLUMN b5 SMALLINT DEFAULT -32768",
        "ALTER TABLE t ADD COLUMN b6 DOUBLE PRECISION DEFAULT 0.1",
    };
    for (size_t k = 0; k < sizeof adds / sizeof *adds; k++) run(adds[k]);
    run("INSERT INTO t (id, sub, nn) VALUES (7, 11, 7)");
    run("CHECKPOINT");
    check(db, "t", "columns added with DEFAULTs");
    run("ERASE SUBJECT 7");
    check(db, "t", "an ERASE");
    run("ALTER TABLE t RENAME COLUMN x TO x2");
    run("ALTER TABLE t DROP COLUMN sm");
    run("ALTER TABLE t ALTER COLUMN i SET DATA TYPE BIGINT");
    run("UPDATE t SET x2 = 'four, renamed', i = 9000000000 WHERE id = 4");
    run("CHECKPOINT");
    check(db, "t", "a rename, a drop and a widening");
    run("COMPACT t");
    check(db, "t", "a COMPACT");
    run("DELETE FROM t WHERE id = 6");
    run("CHECKPOINT");
    check(db, "t", "after the COMPACT");
    imdb_session_close(&s);
    imdb_close(db);
    duckdb_disconnect(&dc);
    duckdb_close(&ddb);
    printf("iceberg-check: %d snapshots, %d rows read by DuckDB against imagedb AS OF each: %s\n", snaps_checked, rows_checked,
           fails ? "FAILED" : "all equal");
    return fails ? 1 : 0;
}
