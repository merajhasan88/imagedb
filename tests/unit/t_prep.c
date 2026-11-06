/* P2 S9 (docs/plan-p2.md): PREPARE, EXECUTE, DEALLOCATE and SHOW PREPARED, and the API's imdb_prepare, imdb_execute,
 * imdb_deallocate. Every statement form answers the same prepared as written out (a differential over S1-S8's forms),
 * a statement with $n the same as its literal twin, declared and not; writes prepared run twice in a transaction and
 * rolled back; names and types bind at each run (a table made again between runs); every rule and limit; what a
 * session holds freed by DEALLOCATE and by its close; a slow EXECUTE's event names its prepared statement and gives
 * the prepared text's shape. */
#include <stdio.h>
#include <stdlib.h>

#include "../../src/db.h"
#include "../../src/sql.h"
#include "thelp.h"

static imdb_session g_s;
static char g_out[1 << 16], g_out2[1 << 16];

static const char *csv_to(imdb_session *s, const char *sql, char *out, size_t cap)
{
    imdb_result r;
    imdb_err_clear(&g_e);
    if (imdb_exec_one(s, sql, strlen(sql), NULL, 0, &r, &g_e)) {
        snprintf(out, cap, "ERR %s", g_e.msg);
        return out;
    }
    imdb_buf b;
    imdb_buf_init(&b);
    if (r.has_rows) imdb_result_render(&r, true, &b);
    else imdb_buf_put_str(&b, r.status);
    if (imdb_buf_check(&b, &g_e)) snprintf(out, cap, "ERR render");
    else snprintf(out, cap, "%.*s", (int)b.len, (const char *)b.p);
    imdb_buf_free(&b);
    imdb_result_free(&r);
    return out;
}
static const char *csv(const char *sql) { return csv_to(&g_s, sql, g_out, sizeof g_out); }

static int run(const char *sql)
{
    imdb_result r;
    imdb_err_clear(&g_e);
    int rc = imdb_exec_one(&g_s, sql, strlen(sql), NULL, 0, &r, &g_e);
    if (!rc) imdb_result_free(&r);
    return rc;
}

static const char *body(const char *s)
{
    const char *n = strchr(s, '\n');
    return n ? n + 1 : s;
}

#define EXPECT(sql, want)                                                                                          \
    do {                                                                                                           \
        const char *got_ = csv(sql);                                                                               \
        bool ok_ = !strncmp((want), "ERR ", 4) ? !strncmp(got_, "ERR ", 4) && strstr(got_ + 4, (want) + 4) != NULL \
                                               : !strcmp(body(got_), body(want));                                  \
        if (!ok_) {                                                                                                \
            char m_[1600];                                                                                         \
            snprintf(m_, sizeof m_, "%s\n      want: %s\n      got:  %s", (sql), (want), got_);                    \
            test_fail(__FILE__, __LINE__, m_);                                                                     \
        }                                                                                                          \
    } while (0)

static imdb_db *open_fresh(void)
{
    const char *dir = test_tmpdir();
    imdb_err e = {0};
    if (imdb_init(dir, false, NULL, &e)) return NULL;
    imdb_open_opts o = {.sync = 0};
    imdb_db *db = NULL;
    if (imdb_open(dir, &o, &db, &e)) return NULL;
    imdb_session_init(&g_s, db);
    return db;
}

static void done(imdb_db *db)
{
    imdb_session_close(&g_s);
    imdb_close(db);
}

static void load(void)
{
    CHECK(run("CREATE TABLE t (id INT64 PRIMARY KEY, g INT64, x INT64, d DECIMAL(10,2), s TEXT, ts TIMESTAMP)") == 0);
    CHECK(run("CREATE TABLE u (id INT64 PRIMARY KEY, tid INT64, v INT64)") == 0);
    imdb_buf b;
    imdb_buf_init(&b);
    imdb_buf_put_str(&b, "INSERT INTO t VALUES ");
    for (int i = 1; i <= 60; i++)
        imdb_buf_printf(&b, "%s(%d, %d, %s, %d.%02d, %s, '2026-01-%02d 10:00:00')", i > 1 ? ", " : "", i, i % 4,
                        i % 9 ? "1" : "NULL", i * 3 % 50, i % 100, i % 7 ? "'r'" : "NULL", 1 + i % 28);
    imdb_buf_put_u8(&b, 0);
    CHECK(!imdb_buf_check(&b, &g_e) && run((const char *)b.p) == 0);
    b.len = 0;
    imdb_buf_put_str(&b, "INSERT INTO u VALUES ");
    for (int i = 1; i <= 40; i++) imdb_buf_printf(&b, "%s(%d, %d, %d)", i > 1 ? ", " : "", i, 1 + i * 7 % 70, i * 11 % 13);
    imdb_buf_put_u8(&b, 0);
    CHECK(!imdb_buf_check(&b, &g_e) && run((const char *)b.p) == 0);
    imdb_buf_free(&b);
    CHECK(run("UPDATE t SET x = id * 3 WHERE x IS NOT NULL") == 0);
}

/* S1-S8's forms: each answers the same prepared as written out */
static const char *const g_forms[] = {
    "SELECT * FROM t ORDER BY id",
    "SELECT id, x * 2 + 1, -x, x % 7 FROM t WHERE x > 30 ORDER BY id",
    "SELECT id, CASE WHEN g = 1 THEN 'one' WHEN g = 2 THEN 'two' ELSE 'many' END, COALESCE(s, '-') FROM t ORDER BY id",
    "SELECT id, CAST(d AS TEXT), UPPER(COALESCE(s, 'n')), LENGTH(COALESCE(s, '')) FROM t WHERE s LIKE 'r%' ORDER BY id",
    "SELECT id FROM t WHERE g IN (1, 3) AND NOT (x BETWEEN 10 AND 20) ORDER BY id",
    "SELECT g, COUNT(*), SUM(x), AVG(d), MIN(s), MAX(ts) FROM t GROUP BY g ORDER BY g",
    "SELECT g, COUNT(DISTINCT x % 5), SUM(x) FILTER (WHERE x > 50) FROM t GROUP BY g HAVING COUNT(*) > 3 ORDER BY g",
    "SELECT DISTINCT g, s FROM t ORDER BY g, s NULLS FIRST",
    "SELECT id, x FROM t ORDER BY x DESC NULLS LAST, id LIMIT 5 OFFSET 3",
    "SELECT t.id, u.v FROM t JOIN u ON u.tid = t.id ORDER BY t.id, u.v",
    "SELECT t.id, u.v FROM t LEFT JOIN u ON u.tid = t.id WHERE t.id < 20 ORDER BY t.id, u.v",
    "SELECT COUNT(*) FROM t RIGHT JOIN u ON u.tid = t.id",
    "SELECT COUNT(*) FROM t FULL JOIN u ON u.tid = t.id AND u.v > 3",
    "SELECT COUNT(*) FROM t CROSS JOIN u WHERE t.g = u.v % 4",
    "SELECT id FROM t WHERE id IN (SELECT tid FROM u WHERE v > 5) ORDER BY id",
    "SELECT id FROM t WHERE NOT EXISTS (SELECT 1 FROM u WHERE u.tid = t.id) AND id < 30 ORDER BY id",
    "SELECT id, (SELECT COUNT(*) FROM u WHERE u.tid = t.id) FROM t WHERE id <= 12 ORDER BY id",
    "SELECT q.g, q.n FROM (SELECT g, COUNT(*) AS n FROM t GROUP BY g) AS q WHERE q.n > 10 ORDER BY q.g",
    "WITH a AS (SELECT id, x FROM t WHERE x > 20), b AS (SELECT id FROM a WHERE x < 90) SELECT COUNT(*) FROM b",
    "SELECT id FROM t WHERE g = 1 UNION SELECT tid FROM u WHERE v = 2 ORDER BY 1",
    "SELECT g FROM t INTERSECT SELECT v FROM u EXCEPT SELECT 3 ORDER BY 1",
    "WITH RECURSIVE r(n) AS (SELECT 1 UNION ALL SELECT n + 1 FROM r WHERE n < 50) SELECT SUM(n), COUNT(*) FROM r",
    "SELECT id, ROW_NUMBER() OVER (PARTITION BY g ORDER BY id DESC), SUM(x) OVER (ORDER BY id ROWS BETWEEN 2 PRECEDING "
    "AND CURRENT ROW) FROM t ORDER BY id",
    "SELECT id, LAG(x, 1, -1) OVER (ORDER BY id), RANK() OVER (ORDER BY g) FROM t ORDER BY id",
    "SELECT 1 + 2, 'a' || 'b', NULL, CAST('2026-03-04 05:06:07' AS TIMESTAMP)",
    "SELECT id, NULL AS n FROM t WHERE id < 4 ORDER BY id",
    "SELECT id FROM t AS OF 3 ORDER BY id",
    "SELECT COUNT(*) FROM t WITH (NOLOCK)",
};

static void t_prep_forms(void)
{
    imdb_db *db = open_fresh();
    CHECK(db);
    if (!db) return;
    load();
    char sql[1400];
    for (int pass = 0; pass < 2; pass++) { /* in memory, then from the lake cross-checked */
        for (size_t k = 0; k < sizeof g_forms / sizeof *g_forms; k++) {
            csv_to(&g_s, g_forms[k], g_out2, sizeof g_out2);
            snprintf(sql, sizeof sql, "PREPARE f%zu AS %s", k, g_forms[k]);
            if (run(sql) != 0) {
                char m[1600];
                snprintf(m, sizeof m, "%s: %s", sql, g_e.msg);
                test_fail(__FILE__, __LINE__, m);
                continue;
            }
            snprintf(sql, sizeof sql, "EXECUTE f%zu", k);
            const char *got = csv(sql);
            if (strcmp(got, g_out2) != 0) {
                char m[1600];
                snprintf(m, sizeof m, "%s, prepared, answered otherwise:\n      written: %.400s\n      prepared: %.400s",
                         g_forms[k], g_out2, got);
                test_fail(__FILE__, __LINE__, m);
            }
            snprintf(sql, sizeof sql, "DEALLOCATE f%zu", k);
            CHECK(run(sql) == 0);
        }
        CHECK(run("CHECKPOINT") == 0 && run("SET cross_check = on") == 0);
    }
    CHECK(run("SET cross_check = off") == 0);
    /* $n against the literal twin: undeclared (each value its literal's type) and declared (converted exactly) */
    static const char *const par[][3] = {
        {"SELECT id, s FROM t WHERE id = $1", "(17)", "SELECT id, s FROM t WHERE id = 17"},
        {"SELECT id FROM t WHERE x > $1 AND g = $2 ORDER BY id", "(100, 2)", "SELECT id FROM t WHERE x > 100 AND g = 2 ORDER BY id"},
        {"SELECT id, x + $1, s || $2 FROM t WHERE id <= $3 ORDER BY id", "(1000, '!', 5)",
         "SELECT id, x + 1000, s || '!' FROM t WHERE id <= 5 ORDER BY id"},
        {"SELECT COUNT(*) FROM t WHERE s LIKE $1", "('r%')", "SELECT COUNT(*) FROM t WHERE s LIKE 'r%'"},
        {"SELECT id FROM t WHERE id IN ($1, $2, $3) ORDER BY id", "(3, 30, 33)", "SELECT id FROM t WHERE id IN (3, 30, 33) ORDER BY id"},
        {"SELECT g, COUNT(*) FROM t GROUP BY g HAVING COUNT(*) > $1 ORDER BY g", "(14)",
         "SELECT g, COUNT(*) FROM t GROUP BY g HAVING COUNT(*) > 14 ORDER BY g"},
        {"SELECT t.id FROM t JOIN u ON u.tid = t.id WHERE u.v = $1 ORDER BY t.id", "(4)",
         "SELECT t.id FROM t JOIN u ON u.tid = t.id WHERE u.v = 4 ORDER BY t.id"},
        {"SELECT id FROM t WHERE id IN (SELECT tid FROM u WHERE v > $1) ORDER BY id", "(9)",
         "SELECT id FROM t WHERE id IN (SELECT tid FROM u WHERE v > 9) ORDER BY id"},
        {"SELECT $1 * 3, $2", "(7, 'x')", "SELECT 7 * 3, 'x'"},
    };
    for (size_t k = 0; k < sizeof par / sizeof *par; k++) {
        csv_to(&g_s, par[k][2], g_out2, sizeof g_out2);
        snprintf(sql, sizeof sql, "PREPARE p AS %s", par[k][0]);
        CHECK(run(sql) == 0);
        snprintf(sql, sizeof sql, "EXECUTE p %s", par[k][1]);
        const char *got = csv(sql);
        if (strcmp(body(got), body(g_out2)) != 0) {
            char m[1600];
            snprintf(m, sizeof m, "%s with %s:\n      literal: %.300s\n      prepared: %.300s", par[k][0], par[k][1], g_out2, got);
            test_fail(__FILE__, __LINE__, m);
        }
        CHECK(run("DEALLOCATE p") == 0);
    }
    /* declared: a DECIMAL's places, a TIMESTAMP from its text, a BOOL, a FLOAT64 from an integer */
    CHECK(run("PREPARE dq (DECIMAL(10,2), TIMESTAMP) AS SELECT COUNT(*) FROM t WHERE d >= $1 AND ts > $2") == 0);
    csv_to(&g_s, "SELECT COUNT(*) FROM t WHERE d >= 20.50 AND ts > '2026-01-10 00:00:00'", g_out2, sizeof g_out2);
    EXPECT("EXECUTE dq (20.5, '2026-01-10 00:00:00')", g_out2);
    EXPECT("EXECUTE dq (20.555, '2026-01-10 00:00:00')", "ERR EXECUTE dq, value 1:");
    EXPECT("EXECUTE dq (20.5, 'tomorrow')", "ERR EXECUTE dq, value 2:");
    CHECK(run("PREPARE fq (FLOAT64, BOOL) AS SELECT $1 / 4, NOT $2") == 0);
    EXPECT("EXECUTE fq (3, true)", "x\n0.75,false\n");
    CHECK(run("DEALLOCATE ALL") == 0);
    CHECK(run("VERIFY") == 0);
    done(db);
}

/* writes prepared: run twice in a transaction (each run its own statement: its savepoint, its rows), then rolled back;
 * an upsert, UPDATE ... FROM, RETURNING, FOR UPDATE */
static void t_prep_writes(void)
{
    imdb_db *db = open_fresh();
    CHECK(db);
    if (!db) return;
    load();
    CHECK(run("PREPARE ins (INT64, TEXT) AS INSERT INTO t (id, s) VALUES ($1, $2) RETURNING id, s") == 0);
    CHECK(run("PREPARE ups (INT64) AS INSERT INTO t (id, x) VALUES ($1, 1) ON CONFLICT (id) DO UPDATE SET x = COALESCE(t.x, 0) + 1 "
              "RETURNING x") == 0);
    CHECK(run("PREPARE uf AS UPDATE t SET x = t.x + u.v FROM u WHERE u.tid = t.id AND u.id = $1 RETURNING t.id") == 0);
    CHECK(run("PREPARE del (INT64) AS DELETE FROM t WHERE id = $1 RETURNING id") == 0);
    CHECK(run("PREPARE lock (INT64) AS SELECT id FROM t WHERE id = $1 FOR UPDATE") == 0);
    CHECK(run("BEGIN") == 0);
    EXPECT("EXECUTE ins (100, 'a')", "id,s\n100,\"a\"\n");
    EXPECT("EXECUTE ins (101, 'b')", "id,s\n101,\"b\"\n");
    EXPECT("EXECUTE ins (101, 'c')", "ERR duplicate primary key"); /* the statement undone alone */
    EXPECT("EXECUTE ups (100)", "x\n1\n");
    EXPECT("EXECUTE ups (100)", "x\n2\n");
    EXPECT("EXECUTE lock (100)", "id\n100\n");
    EXPECT("EXECUTE del (101)", "id\n101\n");
    EXPECT("EXECUTE del (101)", "id\n");
    EXPECT("SELECT id, s, x FROM t WHERE id >= 100 ORDER BY id", "id,s,x\n100,\"a\",2\n");
    CHECK(run("ROLLBACK") == 0);
    EXPECT("SELECT COUNT(*) FROM t WHERE id >= 100", "count\n0\n");
    csv_to(&g_s, "SELECT x FROM t WHERE id = 8", g_out2, sizeof g_out2);
    EXPECT("EXECUTE uf (1)", "id\n8\n"); /* u's row 1: tid 8 */
    EXPECT("SHOW PREPARED", "name,parameters,statement,uses\n"
                            "\"del\",\"INT64\",\"DELETE FROM t WHERE id = $1 RETURNING id\",2\n"
                            "\"ins\",\"INT64, TEXT\",\"INSERT INTO t (id, s) VALUES ($1, $2) RETURNING id, s\",2\n" /* a failed run is no use */
                            "\"lock\",\"INT64\",\"SELECT id FROM t WHERE id = $1 FOR UPDATE\",1\n"
                            "\"uf\",\"\",\"UPDATE t SET x = t.x + u.v FROM u WHERE u.tid = t.id AND u.id = $1 RETURNING t.id\",1\n"
                            "\"ups\",\"INT64\",\"INSERT INTO t (id, x) VALUES ($1, 1) ON CONFLICT (id) DO UPDATE SET x = COALESCE(t.x, 0) + 1 "
                            "RETURNING x\",2\n");
    CHECK(run("VERIFY") == 0);
    done(db);
}

/* the rules: names, kinds, values; names and types bound at each run; the limits; what a session holds freed by
 * DEALLOCATE and by its close; the API */
static void t_prep_rules(void)
{
    imdb_db *db = open_fresh();
    CHECK(db);
    if (!db) return;
    CHECK(run("CREATE TABLE k (id INT64 PRIMARY KEY, s TEXT)") == 0 && run("INSERT INTO k VALUES (1, 'a')") == 0);
    CHECK(run("PREPARE a AS SELECT COUNT(*) FROM k") == 0);
    EXPECT("PREPARE a AS SELECT 2", "ERR a statement named a is prepared already");
    EXPECT("EXECUTE nosuch", "ERR no prepared statement nosuch");
    EXPECT("DEALLOCATE nosuch", "ERR no prepared statement nosuch");
    EXPECT("PREPARE b AS CREATE TABLE z (id INT64 PRIMARY KEY)", "ERR PREPARE takes a query, INSERT, UPDATE or DELETE");
    EXPECT("PREPARE b AS BEGIN", "ERR PREPARE takes a query, INSERT, UPDATE or DELETE");
    EXPECT("PREPARE b AS PREPARE c AS SELECT 1", "ERR PREPARE takes a query, INSERT, UPDATE or DELETE");
    EXPECT("PREPARE b AS EXECUTE a", "ERR PREPARE takes a query, INSERT, UPDATE or DELETE");
    EXPECT("PREPARE b AS SELECT 1; SELECT 2", "ERR end of statement");
    EXPECT("PREPARE b AS", "ERR a statement to prepare");
    EXPECT("PREPARE b AS SELEC 1", "ERR syntax error");
    EXPECT("EXPLAIN EXECUTE a", "ERR EXPLAIN explains SELECT, UPDATE and DELETE");
    CHECK(run("PREPARE b (INT64) AS SELECT $1") == 0);
    EXPECT("EXECUTE b (1, 2)", "ERR EXECUTE b passes 2 values: its PREPARE declares 1");
    CHECK(run("PREPARE c AS SELECT $1, $2") == 0);
    EXPECT("EXECUTE c (1)", "ERR parameter $2 was not supplied");
    EXPECT("EXECUTE c (NULL, 1)", "ERR EXECUTE c, value 1: NULL has no type of its own: declare it");
    EXPECT("EXECUTE c (1 + 1, 1)", "ERR EXECUTE c, value 1: an expression has no type of its own: declare it");
    CHECK(run("PREPARE d (INT64) AS SELECT $1 * 2") == 0);
    EXPECT("EXECUTE d (2 + 3)", "x\n10\n");
    EXPECT("EXECUTE d (NULL)", "x\n\n");
    EXPECT("EXECUTE d ('a')", "ERR EXECUTE d, value 1:");
    /* names bind at each run: the table made again is the one read; gone, the statement fails as written would */
    EXPECT("EXECUTE a", "count\n1\n");
    CHECK(run("DROP TABLE k") == 0);
    EXPECT("EXECUTE a", "ERR no table k");
    CHECK(run("CREATE TABLE k (id INT64 PRIMARY KEY, s TEXT)") == 0);
    EXPECT("EXECUTE a", "count\n0\n");
    /* in a transaction: PREPARE and DEALLOCATE are the session's, never the transaction's */
    CHECK(run("BEGIN") == 0 && run("PREPARE e AS SELECT 5") == 0 && run("ROLLBACK") == 0);
    EXPECT("EXECUTE e", "x\n5\n");
    /* the bound: 256 a session */
    CHECK(run("DEALLOCATE ALL") == 0);
    char sql[64];
    for (int i = 0; i < 256; i++) {
        snprintf(sql, sizeof sql, "PREPARE p%d AS SELECT %d", i, i);
        if (run(sql) != 0) {
            test_fail(__FILE__, __LINE__, g_e.msg);
            break;
        }
    }
    EXPECT("PREPARE p256 AS SELECT 256", "ERR a session prepares at most 256 statements");
    EXPECT("EXECUTE p255", "x\n255\n");
    CHECK(run("DEALLOCATE p17") == 0 && run("PREPARE p256 AS SELECT 256") == 0); /* room again */
    EXPECT("EXECUTE p256", "x\n256\n");
    CHECK(run("DEALLOCATE ALL") == 0);
    CHECK(run("DROP TABLE k") == 0);
    /* the API: by name, its params typed by the caller; a name as SQL folds it */
    imdb_err e = {0};
    CHECK(run("CREATE TABLE m (id INT64 PRIMARY KEY, s TEXT)") == 0);
    CHECK(imdb_prepare(&g_s, "ins", "INSERT INTO m VALUES ($1, $2)", 29, &e) == 0);
    CHECK(imdb_prepare(&g_s, "Ins", "SELECT 1", 8, &e) == IMDB_ERR_INVALID);
    CHECK(imdb_prepare(&g_s, "ins", "SELECT 1", 8, &e) == IMDB_ERR_INVALID);
    imdb_value pv[2] = {{.type = IMDB_T_INT64, .i = 7}, {.type = IMDB_T_TEXT, .s = (const uint8_t *)"seven", .len = 5}};
    imdb_result r;
    CHECK(imdb_execute(&g_s, "ins", pv, 2, &r, &e) == 0);
    imdb_result_free(&r);
    CHECK(imdb_execute(&g_s, "nosuch", pv, 2, &r, &e) == IMDB_ERR_NOTFOUND);
    EXPECT("SELECT id, s FROM m", "id,s\n7,\"seven\"\n");
    /* the API's params through EXECUTE's own values */
    CHECK(run("PREPARE sel AS SELECT s FROM m WHERE id = $1") == 0);
    imdb_value one = {.type = IMDB_T_INT64, .i = 7};
    CHECK(imdb_exec_one(&g_s, "EXECUTE sel ($1)", 16, &one, 1, &r, &e) == 0 && r.nrows == 1);
    imdb_result_free(&r);
    CHECK(imdb_exec_one(&g_s, "EXECUTE sel", 11, &one, 1, &r, &e) == 0 && r.nrows == 1); /* no values: the API's */
    imdb_result_free(&r);
    CHECK(imdb_deallocate(&g_s, "ins", &e) == 0 && imdb_deallocate(&g_s, "ins", &e) == IMDB_ERR_NOTFOUND);
    /* another session's registry is its own: the same name prepared in each, dropped in one, the other's runs */
    imdb_session s2;
    imdb_session_init(&s2, db);
    CHECK(run("PREPARE twin AS SELECT 1") == 0);
    CHECK(!strcmp(body(csv_to(&s2, "PREPARE twin AS SELECT 2", g_out2, sizeof g_out2)), "PREPARE"));
    CHECK(!strcmp(body(csv_to(&s2, "EXECUTE twin", g_out2, sizeof g_out2)), "2\n"));
    CHECK(!strcmp(body(csv_to(&s2, "DEALLOCATE twin", g_out2, sizeof g_out2)), "DEALLOCATE"));
    EXPECT("EXECUTE twin", "x\n1\n");
    CHECK(!strncmp(csv_to(&s2, "EXECUTE twin", g_out2, sizeof g_out2), "ERR no prepared statement twin", 30));
    imdb_session_close(&s2);
    /* a session's close frees what it prepared: the test's heap check sees it */
    CHECK(run("PREPARE z1 AS SELECT * FROM m") == 0 && run("PREPARE z2 AS SELECT COUNT(*) FROM m") == 0);
    done(db);
}

/* a slow EXECUTE: its event names the prepared statement and gives the prepared text's shape, never a value */
static void t_prep_events(void)
{
    const char *dir = test_tmpdir();
    char p[700], f[720];
    snprintf(p, sizeof p, "%s/db", dir);
    snprintf(f, sizeof f, "%s/events.jsonl", dir);
    imdb_err e = {0};
    CHECK(imdb_init(p, false, NULL, &e) == 0);
    imdb_open_opts o = {.sync = 0, .events_path = f};
    imdb_db *db = NULL;
    CHECK(imdb_open(p, &o, &db, &e) == 0);
    if (!db) return;
    imdb_session_init(&g_s, db);
    CHECK(run("CREATE TABLE t (id INT64 PRIMARY KEY, a INT64)") == 0);
    imdb_buf b;
    imdb_buf_init(&b);
    for (int base = 0; base < 60000; base += 10000) {
        b.len = 0;
        imdb_buf_put_str(&b, "INSERT INTO t VALUES ");
        for (int i = base + 1; i <= base + 10000; i++) imdb_buf_printf(&b, "%s(%d, %d)", i > base + 1 ? ", " : "", i, i % 997);
        imdb_buf_put_u8(&b, 0);
        CHECK(!imdb_buf_check(&b, &g_e) && run((const char *)b.p) == 0);
    }
    imdb_buf_free(&b);
    CHECK(run("PREPARE heavy AS SELECT a, COUNT(*) FROM t WHERE a > $1 GROUP BY a ORDER BY a DESC") == 0);
    CHECK(run("SET slow_statement_ms = 1") == 0 && run("SET statement_timeout = 1") == 0);
    CHECK(run("EXECUTE heavy (31337)") == IMDB_ERR_CANCELLED); /* its timeout: a millisecond at least */
    CHECK(run("SET statement_timeout = 0") == 0 && run("SET slow_statement_ms = 0") == 0);
    done(db);
    FILE *fp = fopen(f, "r");
    CHECK(fp);
    if (!fp) return;
    char line[4096];
    bool seen = false, leak = false;
    while (fgets(line, sizeof line, fp)) {
        if (!strstr(line, "\"prepared\":\"heavy\"")) continue;
        seen = strstr(line, "\"shape\":\"SELECT a , COUNT ( * ) FROM t WHERE a > $1 GROUP BY a ORDER BY a DESC\"") != NULL; /* $n
                                                                                                                   * as written */
        leak |= strstr(line, "31337") != NULL;
    }
    fclose(fp);
    CHECK(seen && !leak);
}

/* EXECUTE runs as its statement: a prepared query's memory and a prepared write's reading under statement_memory,
 * refused at 1 MiB with nothing changed and the ceiling never left set; answered at the default */
static void t_prep_ceiling(void)
{
    imdb_db *db = open_fresh();
    CHECK(db);
    if (!db) return;
    CHECK(run("CREATE TABLE big (id INT64 PRIMARY KEY, s TEXT)") == 0);
    for (int base = 0; base < 20000; base += 5000) {
        imdb_buf b;
        imdb_buf_init(&b);
        imdb_buf_put_str(&b, "INSERT INTO big VALUES ");
        for (int i = base + 1; i <= base + 5000; i++)
            imdb_buf_printf(&b, "%s(%d, 'row %05d of a table wide enough to pass one MiB in a sort')", i > base + 1 ? ", " : "", i,
                            (i * 7919) % 20000);
        imdb_buf_put_u8(&b, 0);
        CHECK(!imdb_buf_check(&b, &g_e) && !run((const char *)b.p));
        imdb_buf_free(&b);
    }
    CHECK(run("PREPARE heavy AS SELECT id, s FROM big ORDER BY s") == 0);
    CHECK(run("PREPARE wipe AS DELETE FROM big WHERE id IN (SELECT id FROM big ORDER BY s DESC)") == 0);
    CHECK(run("SET statement_memory = 1048576") == 0);
    EXPECT("EXECUTE heavy", "ERR statement memory");
    CHECK(imdb_heap_ceiling() == 0);
    EXPECT("EXECUTE wipe", "ERR statement memory");
    CHECK(imdb_heap_ceiling() == 0);
    EXPECT("SELECT COUNT(*) FROM big", "count\n20000\n");
    CHECK(run("SET statement_memory = 0") == 0);
    CHECK(run("EXECUTE heavy") == 0);
    EXPECT("EXECUTE wipe", "DELETE 20000");
    EXPECT("SHOW PREPARED", "name,parameters,statement,uses\n\"heavy\",\"\",\"SELECT id, s FROM big ORDER BY s\",1\n"
                             "\"wipe\",\"\",\"DELETE FROM big WHERE id IN (SELECT id FROM big ORDER BY s DESC)\",1\n");
    done(db);
}

const test_case prep_tests[] = {
    {"prep_forms", t_prep_forms},
    {"prep_writes", t_prep_writes},
    {"prep_rules", t_prep_rules},
    {"prep_events", t_prep_events},
    {"prep_ceiling", t_prep_ceiling},
};
const size_t prep_ntests = sizeof prep_tests / sizeof prep_tests[0];
