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

static int fails, snaps_checked, rows_checked, dir_reads;
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

/* the rows DuckDB gave each (table, snapshot id) the first time, hashed: every later read of that id must give the same
 * rows, whichever form its metadata then takes, alone or beside an older snapshot (f5c-design 9.4: an id names a table
 * state; its parent and first-row-id are its metadata file's) */
static struct {
    uint32_t tid;
    uint64_t S, sig, h; /* sig: the columns compared, by position (a DROP COLUMN since reads fewer) */
} g_seen[512];
static int g_nseen, ids_reread;

static uint64_t fnv(uint64_t h, const char *p)
{
    for (; *p; p++) h = (h ^ (uint8_t)*p) * 1099511628211ull;
    return (h ^ 0xffu) * 1099511628211ull;
}

/* one read: DuckDB's rows FROM src against imagedb's AS OF at, the snapshot's columns (version v) by position into
 * today's names; the hash of DuckDB's rows, 0 when either side failed */
static uint64_t cmp_rows(imdb_table *t, const char *tname, const char *when, const imdb_sver *v, const char *src, uint64_t *sig,
                         uint64_t S, uint64_t at)
{
    const imdb_sver *cur = &t->hist.vers[t->hist.nvers - 1];
    char dq[16384], iq[16384];
    size_t dn = 0, in = 0;
    dn += (size_t)snprintf(dq + dn, sizeof dq - dn, "SELECT ");
    in += (size_t)snprintf(iq + in, sizeof iq - in, "SELECT ");
    int nc = 0;
    for (uint16_t c = 0; c < v->s.ncols; c++) { /* the snapshot's columns Iceberg carries, by position into today's names */
        const imdb_column *col = &v->s.cols[c];
        if (col->type == IMDB_T_INTERVAL || col->type == IMDB_T_ENUM) continue;
        uint16_t p = v->pos[c];
        int8_t at2 = p < cur->npos ? cur->at[p] : -1;
        if (at2 < 0) continue; /* dropped since: imagedb names it no more */
        if (sig) *sig = (*sig ^ p) * 1099511628211ull;
        char ex[600];
        dexpr(col, col->name, ex, sizeof ex);
        dn += (size_t)snprintf(dq + dn, sizeof dq - dn, "%s%s", nc ? ", " : "", ex);
        in += (size_t)snprintf(iq + in, sizeof iq - in, "%s%s", nc ? ", " : "", cur->s.cols[at2].name); /* imagedb's names bare */
        nc++;
    }
    const char *idname = cur->s.cols[cur->at[v->pos[0]]].name; /* the key: position 0 here (id) */
    snprintf(dq + dn, sizeof dq - dn, " FROM %s ORDER BY \"%s\"", src, v->s.cols[0].name);
    snprintf(iq + in, sizeof iq - in, " FROM %s AS OF %llu ORDER BY %s", tname, (unsigned long long)at, idname);
    duckdb_result dr;
    if (duckdb_query(dc, dq, &dr) == DuckDBError) {
        FAIL("%s: %s snapshot %llu: DuckDB: %s\n  %s\n", when, tname, (unsigned long long)S, duckdb_result_error(&dr), dq);
        duckdb_destroy_result(&dr);
        return 0;
    }
    imdb_result ir;
    if (imdb_exec_one(&s, iq, strlen(iq), NULL, 0, &ir, &e)) {
        FAIL("%s: %s snapshot %llu: imagedb: %s\n  %s\n", when, tname, (unsigned long long)S, e.msg, iq);
        duckdb_destroy_result(&dr);
        return 0;
    }
    uint64_t h = 1469598103934665603ull;
    idx_t rows = duckdb_row_count(&dr);
    if (rows != ir.nrows || duckdb_column_count(&dr) != (idx_t)nc || ir.ncols != nc)
        FAIL("%s: %s snapshot %llu: DuckDB %llu rows of %llu columns, imagedb %llu of %u\n", when, tname, (unsigned long long)S,
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
                FAIL("%s: %s snapshot %llu, row %llu, column %s: DuckDB %s, imagedb %s\n", when, tname, (unsigned long long)S,
                     (unsigned long long)r, duckdb_column_name(&dr, (idx_t)c), d, it);
            h = fnv(h, d);
            duckdb_free(dv);
        }
        h = fnv(h, "\n");
        rows_checked++;
    }
    imdb_result_free(&ir);
    duckdb_destroy_result(&dr);
    return h ? h : 1;
}

/* the table's snapshots in its layer at the head (its metadata by its version hint), each read by DuckDB by its id
 * against imagedb AS OF its read point (the head's commit, or the retained generation's for the older: a label may lie
 * below a horizon), the current one once more by the table's directory; returns how many snapshots its metadata names */
static int check(imdb_db *db, const char *tname, const char *when);
static void want(const char *tname, const char *when, int got, int n)
{
    if (got != n) FAIL("%s: %s: %d snapshots, %d wanted\n", when, tname, got, n);
}

static int check(imdb_db *db, const char *tname, const char *when)
{
    imdb_table *t = imdb_table_by_name(db, tname);
    if (!t) {
        FAIL("%s: no table %s\n", when, tname);
        return 0;
    }
    char meta[1400], hint[1400], hk[32] = "";
    snprintf(hint, sizeof hint, "%s/iceberg/%u/metadata/version-hint.text", db->location, (unsigned)t->s.id);
    FILE *hp = fopen(hint, "rb"); /* the current metadata by its version hint (f5c-design 9.1: v<K>.metadata.json) */
    size_t hn = hp ? fread(hk, 1, sizeof hk - 1, hp) : 0;
    if (hp) fclose(hp);
    hk[hn] = 0;
    snprintf(meta, sizeof meta, "%s/iceberg/%u/metadata/v%s.metadata.json", db->location, (unsigned)t->s.id, hk);
    FILE *fp = fopen(meta, "rb");
    if (!fp) {
        FAIL("%s: no layer at %s\n", when, meta);
        return 0;
    }
    static char jb[1 << 22];
    size_t jl = fread(jb, 1, sizeof jb, fp);
    fclose(fp);
    aj m;
    const char *why;
    if (aj_parse(jb, jl, &m, &why)) {
        FAIL("%s: the metadata does not parse: %s\n", when, why);
        return 0;
    }
    uint64_t pseq = 0; /* the retained generation's commit: the older snapshot's read point */
    if (db->lake_prev) {
        imdb_manifest pm;
        imdb_err e2 = {0};
        if (!imdb_manifest_parse(db->lake_prev, db->lake_prevlen, &pm, &e2)) {
            pseq = pm.seq;
            imdb_manifest_free(&pm);
        }
    }
    const aj *cs = aj_get(&m, "current-snapshot-id"), *sn = aj_get(&m, "snapshots");
    int n = 0;
    for (size_t k = 0; sn && sn->kind == AJ_ARR && k < sn->n; k++) {
        const aj *id = aj_get(&sn->v[k], "snapshot-id"), *sid = aj_get(&sn->v[k], "schema-id");
        if (!id || id->kind != AJ_INT || !sid || sid->kind != AJ_INT || sid->i < 0 || (uint64_t)sid->i >= t->hist.nvers) {
            FAIL("%s: a snapshot without its id or schema\n", when);
            continue;
        }
        n++;
        uint64_t S = (uint64_t)id->i;
        bool head = cs && cs->kind == AJ_INT && (uint64_t)cs->i == S;
        if (!head && !pseq) {
            FAIL("%s: %s: an older snapshot %llu where the head retains no generation\n", when, tname, (unsigned long long)S);
            continue;
        }
        uint64_t at = head ? db->lake_seq : pseq;
        const imdb_sver *v = &t->hist.vers[sid->i];
        char src[1600];
        snprintf(src, sizeof src, "iceberg_scan('%s', snapshot_from_id => %llu)", meta, (unsigned long long)S);
        uint64_t sig = 1469598103934665603ull, h = cmp_rows(t, tname, when, v, src, &sig, S, at);
        if (h) {
            int q = 0;
            while (q < g_nseen && !(g_seen[q].tid == t->s.id && g_seen[q].S == S && g_seen[q].sig == sig)) q++;
            if (q < g_nseen) {
                ids_reread++;
                if (g_seen[q].h != h) FAIL("%s: %s snapshot %llu: other rows than when it was first read\n", when, tname, (unsigned long long)S);
            } else if (g_nseen < (int)(sizeof g_seen / sizeof *g_seen)) {
                g_seen[g_nseen].tid = t->s.id;
                g_seen[g_nseen].S = S;
                g_seen[g_nseen].sig = sig;
                g_seen[g_nseen++].h = h;
            }
        }
        if (head && h) { /* once more by the table's directory: DuckDB finds the metadata by the version hint itself */
            snprintf(src, sizeof src, "iceberg_scan('%s/iceberg/%u')", db->location, (unsigned)t->s.id);
            uint64_t hd = cmp_rows(t, tname, when, v, src, NULL, S, at);
            if (hd && hd != h) FAIL("%s: %s: by its directory, other rows than its current snapshot's\n", when, tname);
            dir_reads++;
        }
        snaps_checked++;
    }
    aj_free(&m);
    return n;
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
    /* idle (f5c-design 9.4): changed at the first two publications, then by the ERASE alone, so DuckDB reads its snapshot
     * beside an older, then alone under the same id, then untouched (labelled below the head), each against imagedb */
    run("CREATE TABLE idle (id BIGINT PRIMARY KEY, v TEXT, n INTEGER)");
    run("INSERT INTO idle VALUES (1, 'a', 1), (2, 'b', NULL), (3, NULL, 3)");
    run("CHECKPOINT");
    check(db, "t", "first publication");
    want("idle", "first publication", check(db, "idle", "first publication"), 1);
    run("UPDATE t SET x = 'one, again', i = 5 WHERE id = 1");
    run("DELETE FROM t WHERE id = 2");
    run("INSERT INTO t (id, sub, nn) VALUES (5, 9, 5), (6, 10, 6)");
    run("UPDATE idle SET v = 'a2' WHERE id = 1");
    run("DELETE FROM idle WHERE id = 2");
    run("CHECKPOINT");
    check(db, "t", "an update and a delete");
    want("idle", "an update and a delete", check(db, "idle", "an update and a delete"), 2);
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
    want("idle", "columns added with DEFAULTs", check(db, "idle", "columns added with DEFAULTs"), 1); /* written alone: the same id */
    run("ERASE SUBJECT 7");
    check(db, "t", "an ERASE");
    want("idle", "an ERASE", check(db, "idle", "an ERASE"), 1); /* changed (an ERASE changes every table), alone: an ERASE
                                                                 * retains no generation (it holds the erased values) */
    run("ALTER TABLE t RENAME COLUMN x TO x2");
    run("ALTER TABLE t DROP COLUMN sm");
    run("ALTER TABLE t ALTER COLUMN i SET DATA TYPE BIGINT");
    run("UPDATE t SET x2 = 'four, renamed', i = 9000000000 WHERE id = 4");
    run("CHECKPOINT");
    check(db, "t", "a rename, a drop and a widening");
    want("idle", "a rename, a drop and a widening", check(db, "idle", "a rename, a drop and a widening"), 1);
    run("COMPACT t");
    check(db, "t", "a COMPACT");
    want("idle", "a COMPACT", check(db, "idle", "a COMPACT"), 1); /* untouched from here */
    run("DELETE FROM t WHERE id = 6");
    run("CHECKPOINT");
    check(db, "t", "after the COMPACT");
    want("idle", "after the COMPACT", check(db, "idle", "after the COMPACT"), 1);
    /* a COMPACT's PURGE BEFORE past the generation it retains: t's horizon passes the older snapshot's read point, where
     * imagedb answers no AS OF, so the layer offers the head alone (9.4) */
    run("UPDATE t SET nn = 66 WHERE id = 5");
    run("CHECKPOINT");
    want("t", "before a purge", check(db, "t", "before a purge"), 2);
    run("UPDATE t SET nn = 67 WHERE id = 5"); /* a commit past that publication, so the horizon can pass it */
    char pq[96];
    snprintf(pq, sizeof pq, "COMPACT t PURGE BEFORE %llu", (unsigned long long)db->seq);
    run(pq);
    want("t", "a COMPACT past the generation it retains", check(db, "t", "a COMPACT past the generation it retains"), 1);
    want("idle", "a COMPACT past the generation it retains", check(db, "idle", "a COMPACT past the generation it retains"), 1);
    imdb_session_close(&s);
    imdb_close(db);
    duckdb_disconnect(&dc);
    duckdb_close(&ddb);
    printf("iceberg-check: %d snapshots (%d ids read again, %d tables read by their directory), %d rows read by DuckDB "
           "against imagedb AS OF each: %s\n", snaps_checked, ids_reread, dir_reads, rows_checked, fails ? "FAILED" : "all equal");
    return fails ? 1 : 0;
}
