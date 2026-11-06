/* P2 S11 (deferred.md D9, O1 and O2: the 2026-11-05 review): a SELECT's expression SELECTs are typed and bound before
 * any row and run the first time a row needs one (once when it reads no column around it, per distinct value when it
 * does); a bind-only pass runs nothing at any depth (derived tables, set operations and WITH RECURSIVE typed alone);
 * EXISTS answers by presence, computing no item, and stops at its first row only where no WHERE tree is left to test;
 * cross_check runs both plans whatever either did; a nested SELECT reads WITH's row sets by name, never a derived
 * table's; a write's own subqueries still run before its first write. Each on every access path, cross-checked and
 * not, in memory and in the lake. */
#include <stdlib.h>

#include "../../src/db.h"
#include "../../src/sql.h"
#include "thelp.h"

static imdb_session g_s;
static char g_out[1 << 16];

static const char *csv(const char *sql)
{
    imdb_result r;
    imdb_err_clear(&g_e);
    if (imdb_exec_one(&g_s, sql, strlen(sql), NULL, 0, &r, &g_e)) {
        snprintf(g_out, sizeof g_out, "ERR %s", g_e.msg);
        return g_out;
    }
    imdb_buf b;
    imdb_buf_init(&b);
    if (r.has_rows) imdb_result_render(&r, true, &b);
    else imdb_buf_put_str(&b, r.status);
    if (imdb_buf_check(&b, &g_e)) snprintf(g_out, sizeof g_out, "ERR render");
    else snprintf(g_out, sizeof g_out, "%.*s", (int)b.len, (const char *)b.p);
    imdb_buf_free(&b);
    imdb_result_free(&r);
    return g_out;
}

static int run(const char *sql)
{
    imdb_result r;
    imdb_err_clear(&g_e);
    int rc = imdb_exec_one(&g_s, sql, strlen(sql), NULL, 0, &r, &g_e);
    if (!rc) imdb_result_free(&r);
    return rc;
}

/* an error wanted is its message's words, and never a cross-check's failure (whose message quotes a plan's error) */
#define EXPECT(sql, want)                                                                                          \
    do {                                                                                                           \
        const char *got_ = csv(sql);                                                                               \
        bool ok_ = !strncmp((want), "ERR ", 4)                                                                     \
                       ? !strncmp(got_, "ERR ", 4) && strstr(got_ + 4, (want) + 4) != NULL &&                      \
                             g_e.code != IMDB_ERR_VERIFY                                                           \
                       : !strcmp(got_, (want));                                                                    \
        if (!ok_) {                                                                                                \
            char m_[1600];                                                                                         \
            snprintf(m_, sizeof m_, "%s\n      want: %s\n      got:  %s", (sql), (want), got_);                    \
            test_fail(__FILE__, __LINE__, m_);                                                                     \
        }                                                                                                          \
    } while (0)

enum { NBIG = 3000 };

/* t: three rows on every path (the primary key, an ordered index on a, a SUBJECT column s); u: two rows, so that
 * 1/(u.id - u.id) fails and (SELECT u.id FROM u) is two rows; b: NBIG rows */
static void done(imdb_db *db);

static char g_dir[4096];

/* the open's own build of the ordered structures: one sorted run, read in its keys' order */
static imdb_db *reopen(imdb_db *db)
{
    done(db);
    imdb_err e = {0};
    imdb_open_opts o = {.sync = 0};
    imdb_db *n = NULL;
    if (imdb_open(g_dir, &o, &n, &e)) return NULL;
    imdb_session_init(&g_s, n);
    return n;
}

static imdb_db *setup(void)
{
    const char *dir = test_tmpdir();
    snprintf(g_dir, sizeof g_dir, "%s", dir);
    imdb_err e = {0};
    if (imdb_init(dir, false, NULL, &e)) return NULL;
    imdb_open_opts o = {.sync = 0};
    imdb_db *db = NULL;
    if (imdb_open(dir, &o, &db, &e)) return NULL;
    imdb_session_init(&g_s, db);
    imdb_buf q;
    imdb_buf_init(&q);
    imdb_buf_put_str(&q, "INSERT INTO b VALUES ");
    for (int i = 1; i <= NBIG; i++) imdb_buf_printf(&q, "%s(%d, %d)", i > 1 ? ", " : "", i, i % 97);
    imdb_buf_put_u8(&q, 0);
    bool ok = !imdb_buf_check(&q, &g_e) && !run("CREATE TABLE t (id INT64 PRIMARY KEY, a INT64, s TEXT SUBJECT)") &&
              !run("CREATE INDEX ta ON t (a)") && !run("CREATE TABLE u (id INT64 PRIMARY KEY, x INT64)") &&
              !run("CREATE TABLE b (id INT64 PRIMARY KEY, v INT64)") &&
              !run("INSERT INTO t VALUES (1, 10, 'p'), (2, 20, 'q'), (3, 30, 'r')") &&
              !run("INSERT INTO u VALUES (2, 7), (3, 8)") && !run((const char *)q.p);
    imdb_buf_free(&q);
    if (!ok) {
        test_fail(__FILE__, __LINE__, "setup");
        done(db);
        return NULL;
    }
    return db;
}

static void done(imdb_db *db)
{
    imdb_session_close(&g_s);
    imdb_close(db);
}

static const char *const PATHS[] = {"auto", "scan", "index", "store", "ordered"};

/* the review's O1 and its kin: a branch no row takes, a COALESCE argument never reached, a WHERE tree no row reaches
 * (every plain predicate first, on every path), a value's second row read by no row */
static void t_lazy_branches(void)
{
    imdb_db *db = setup();
    if (!db) return;
    for (int pass = 0; pass < 2; pass++) {
        if (pass) CHECK(run("CHECKPOINT") == 0); /* the lake: the rows read from segments where the store lets them go */
        for (int xc = 0; xc < 2; xc++) {
            CHECK(run(xc ? "SET cross_check = on" : "SET cross_check = off") == 0);
            for (size_t p = 0; p < sizeof PATHS / sizeof *PATHS; p++) {
                char set[64];
                snprintf(set, sizeof set, "SET access_path = %s", PATHS[p]);
                CHECK(run(set) == 0);
                EXPECT("SELECT CASE WHEN id = 1 THEN 7 ELSE (SELECT 1/(u.id - u.id) FROM u) END AS v FROM t WHERE id = 1", "v\n7\n");
                EXPECT("SELECT CASE WHEN id = 1 THEN 7 ELSE (SELECT 1/(u.id - u.id) FROM u) END AS v FROM t WHERE a = 10", "v\n7\n");
                EXPECT("SELECT CASE WHEN id = 1 THEN 7 ELSE (SELECT 1/(u.id - u.id) FROM u) END AS v FROM t WHERE s = 'p'", "v\n7\n");
                EXPECT("SELECT CASE WHEN id = 1 THEN 7 ELSE (SELECT 1/(u.id - u.id) FROM u) END AS v FROM t WHERE a + 0 = 10",
                       "v\n7\n");
                EXPECT("SELECT CASE WHEN id = 1 THEN 7 ELSE (SELECT 1/(u.id - u.id) FROM u) END AS v FROM t", "ERR division by zero");
                CHECK(g_e.code == IMDB_ERR_INVALID); /* the rows' error, both plans' alike: never a cross-check failure */
                EXPECT("SELECT COALESCE(a, (SELECT 1/(u.id - u.id) FROM u)) AS v FROM t WHERE id < 3", "v\n10\n20\n");
                EXPECT("SELECT id FROM t WHERE a > 100 AND (SELECT 1/(u.id - u.id) FROM u) = 1", "id\n");
                EXPECT("SELECT id FROM t WHERE a = 10 AND (id = 1 OR (SELECT 1/(u.id - u.id) FROM u) = 1)", "id\n1\n");
                EXPECT("SELECT id FROM t WHERE a >= 10 AND (id = 1 OR (SELECT 1/(u.id - u.id) FROM u) = 1)", "ERR division by zero");
                EXPECT("SELECT (SELECT u.id FROM u) AS v FROM t WHERE id < 0", "v\n");
                EXPECT("SELECT (SELECT u.id FROM u) AS v FROM t", "ERR more than one row");
                EXPECT("SELECT id FROM t WHERE id < 0 AND a IN (SELECT 1/(u.id - u.id) FROM u)", "id\n");
                /* a join: a WHERE tree on the joined row, ON's condition on each candidate pair, under both plans */
                EXPECT("SELECT t.id FROM t JOIN u ON t.id = u.id WHERE u.x = 7 AND "
                       "CASE WHEN u.x = 7 THEN 1 ELSE (SELECT 1/(w.id - w.id) FROM u AS w) END = 1",
                       "id\n2\n");
                EXPECT("SELECT t.id FROM t JOIN u ON t.id = u.id WHERE CASE WHEN u.x = 7 THEN 1 ELSE (SELECT 1/(w.id - w.id) "
                       "FROM u AS w) END = 1",
                       "ERR division by zero");
                EXPECT("SELECT t.id FROM t JOIN u ON t.id = u.id AND (u.x < 100 OR (SELECT 1/(w.id - w.id) FROM u AS w) = 1) "
                       "ORDER BY t.id",
                       "id\n2\n3\n");
                EXPECT("SELECT t.id FROM t JOIN u ON t.id = u.id AND (u.x = 7 OR (SELECT 1/(w.id - w.id) FROM u AS w) = 1)",
                       "ERR division by zero");
            }
        }
    }
    CHECK(run("SET access_path = auto") == 0 && run("SET cross_check = off") == 0);
    /* aggregates beside one: it reads no row, so it is no correlated one's refusal (one answer for any row or none) */
    EXPECT("SELECT COUNT(*) AS n, (SELECT MAX(x) FROM u) AS m FROM t", "n,m\n3,8\n");
    EXPECT("SELECT a, (SELECT MAX(x) FROM u) AS m FROM t GROUP BY a HAVING a > (SELECT MIN(x) FROM u) * 3 ORDER BY a",
           "a,m\n30,8\n");
    EXPECT("SELECT COUNT(*) AS n, (SELECT 1/(u.id - u.id) FROM u) AS m FROM t WHERE id < 0", "ERR division by zero");
    done(db);
}

/* a bind-only pass runs nothing at any depth: an unreached SELECT's own nested SELECTs, derived tables, set operations
 * and WITH RECURSIVE are typed and bound, none run; and the cost of one never reached is never paid */
static void t_lazy_depth(void)
{
    imdb_db *db = setup();
    if (!db) return;
    EXPECT("SELECT CASE WHEN id = 1 THEN 7 ELSE (SELECT (SELECT 1/(u.id - u.id) FROM u) FROM u) END AS v FROM t WHERE id = 1",
           "v\n7\n");
    EXPECT("SELECT CASE WHEN id = 1 THEN 7 ELSE (SELECT z FROM (SELECT 1/(u.id - u.id) AS z FROM u) AS q) END AS v FROM t "
           "WHERE id = 1",
           "v\n7\n");
    EXPECT("SELECT CASE WHEN id = 1 THEN 7 ELSE (SELECT MAX(z) FROM (SELECT 1/(u.id - u.id) AS z FROM u UNION SELECT 1 FROM u) "
           "AS q) END AS v FROM t WHERE id = 1",
           "v\n7\n");
    EXPECT("SELECT CASE WHEN id = 1 THEN 7 ELSE (SELECT 1/(u.id - u.id) FROM u UNION SELECT 1 FROM u) END AS v FROM t "
           "WHERE id = 1",
           "v\n7\n");
    EXPECT("SELECT id FROM t WHERE a IN (SELECT x * 10 FROM u UNION SELECT 30 FROM u) ORDER BY id", "id\n3\n");
    EXPECT("SELECT id FROM t WHERE a IN (SELECT x * 10 FROM u INTERSECT SELECT 30 FROM u) ORDER BY id", "id\n");
    /* a correlated value of a window function: its copy's hidden ORDER BY item is no column of it */
    EXPECT("SELECT id, (SELECT ROW_NUMBER() OVER (ORDER BY u.x) FROM u WHERE u.id = t.id) AS r FROM t ORDER BY id",
           "id,r\n1,\n2,1\n3,1\n");
    /* never reached: none of b's rows tested; reached: once, its rows tested with the statement's */
    CHECK(run("SELECT CASE WHEN id > 0 THEN 1 ELSE (SELECT COUNT(*) FROM b) END FROM t") == 0);
    CHECK(g_s.rows_tested == 3 && g_s.corr_runs == 0);
    CHECK(run("SELECT CASE WHEN id > 1 THEN 1 ELSE (SELECT COUNT(*) FROM b) END FROM t") == 0);
    CHECK(g_s.rows_tested == 3 + NBIG && g_s.corr_runs == 1 && g_s.corr_hits == 0);
    /* once for the statement: the memo's empty tuple */
    EXPECT("SELECT id, (SELECT MAX(x) FROM u) AS m FROM t ORDER BY id", "id,m\n1,8\n2,8\n3,8\n");
    CHECK(g_s.corr_runs == 1 && g_s.corr_hits == 2);
    done(db);
}

/* names and types are bound before any row, at every depth, as before: an unreached branch still refuses them; WITH
 * RECURSIVE's second SELECT is bound whatever its first returns (a first of no row left it unbound before S11) */
static void t_lazy_bind(void)
{
    imdb_db *db = setup();
    if (!db) return;
    EXPECT("SELECT CASE WHEN id = 1 THEN 7 ELSE (SELECT nosuch FROM u) END FROM t WHERE id = 1", "ERR no column nosuch");
    EXPECT("SELECT CASE WHEN id = 1 THEN 7 ELSE (SELECT (SELECT nosuch FROM u) FROM u) END FROM t WHERE id = 1",
           "ERR no column nosuch");
    EXPECT("SELECT CASE WHEN id = 1 THEN 7 ELSE (SELECT z FROM (SELECT nosuch AS z FROM u) AS q) END FROM t WHERE id = 1",
           "ERR no column nosuch");
    EXPECT("SELECT CASE WHEN id = 1 THEN 7 ELSE (SELECT 'x' FROM u) END FROM t WHERE id = 1", "ERR a CASE of INT64 and TEXT");
    EXPECT("SELECT id FROM t WHERE id < 0 AND a IN (SELECT 'x' FROM u)", "ERR IN compares INT64 with TEXT");
    EXPECT("SELECT (SELECT x, id FROM u) FROM t WHERE id < 0", "ERR returns one column");
    EXPECT("SELECT CASE WHEN id = 1 THEN 7 ELSE (SELECT x FROM nosuch) END FROM t WHERE id = 1", "ERR no table nosuch");
    EXPECT("WITH RECURSIVE r(n) AS (SELECT id FROM t WHERE id < 0 UNION ALL SELECT nosuch FROM r) SELECT * FROM r",
           "ERR no column nosuch");
    EXPECT("WITH RECURSIVE r(n) AS (SELECT id FROM t WHERE id < 0 UNION ALL SELECT n, n FROM r) SELECT * FROM r",
           "ERR return 1 and 2 columns");
    EXPECT("WITH RECURSIVE r(n) AS (SELECT id FROM t WHERE id < 0 UNION ALL SELECT 'x' FROM r) SELECT * FROM r", "ERR ");
    EXPECT("WITH RECURSIVE r(n) AS (SELECT id FROM t WHERE id < 2 UNION ALL SELECT n + 1 FROM r WHERE n < 4) SELECT * FROM r",
           "n\n1\n2\n3\n4\n");
    done(db);
}

/* O2: EXISTS by presence; the shapes it computes as they stand; the first row stops the path only where no WHERE tree
 * is left (one tested on a later row could fail, and which rows come first is the path's) */
static void t_lazy_exists(void)
{
    imdb_db *db = setup();
    if (!db) return;
    for (int xc = 0; xc < 2; xc++) {
        CHECK(run(xc ? "SET cross_check = on" : "SET cross_check = off") == 0);
        EXPECT("SELECT EXISTS (SELECT 1/(u.id - u.id) FROM u) AS v", "v\ntrue\n");
        EXPECT("SELECT NOT EXISTS (SELECT 1/(u.id - u.id) FROM u) AS v", "v\nfalse\n");
        EXPECT("SELECT EXISTS (SELECT DISTINCT 1/(x - x) FROM u) AS v", "v\ntrue\n");
        EXPECT("SELECT EXISTS (SELECT x FROM u ORDER BY 1/(x - x)) AS v", "v\ntrue\n");
        EXPECT("SELECT EXISTS (SELECT x, 1/(x - x) FROM u GROUP BY x) AS v", "v\ntrue\n");
        EXPECT("SELECT EXISTS (SELECT 1/(x - x) FROM u LIMIT 1) AS v", "v\ntrue\n");
        EXPECT("SELECT EXISTS (SELECT 1/(x - x) FROM u LIMIT 0) AS v", "v\nfalse\n");
        EXPECT("SELECT EXISTS (SELECT 1/(x - x) FROM u WHERE x > 100) AS v", "v\nfalse\n");
        EXPECT("SELECT EXISTS (SELECT 1/0) AS v", "v\ntrue\n");
        /* computed as they stand: an aggregate (one row over none), HAVING, OFFSET, a window function, a set operation */
        EXPECT("SELECT EXISTS (SELECT COUNT(*) FROM u WHERE x > 100) AS v", "v\ntrue\n");
        EXPECT("SELECT EXISTS (SELECT SUM(1/(x - x)) FROM u) AS v", "ERR division by zero");
        EXPECT("SELECT EXISTS (SELECT x FROM u GROUP BY x HAVING SUM(1/(x - x)) > 0) AS v", "ERR division by zero");
        EXPECT("SELECT EXISTS (SELECT 1/(x - x) FROM u OFFSET 0) AS v", "ERR division by zero");
        EXPECT("SELECT EXISTS (SELECT ROW_NUMBER() OVER (ORDER BY x), 1/(x - x) FROM u) AS v", "ERR division by zero");
        EXPECT("SELECT EXISTS (SELECT 1/(x - x) FROM u UNION SELECT 1 FROM u) AS v", "ERR division by zero");
        /* WHERE trees are tested: a failing one fails */
        EXPECT("SELECT EXISTS (SELECT 1 FROM u WHERE 1/(x - x) > 0) AS v", "ERR division by zero");
        /* correlated, each run's presence; a join's */
        EXPECT("SELECT id FROM t WHERE EXISTS (SELECT 1/(u.x - u.x) FROM u WHERE u.id = t.id) ORDER BY id", "id\n2\n3\n");
        EXPECT("SELECT id FROM t WHERE NOT EXISTS (SELECT 1/(u.x - u.x) FROM u WHERE u.id = t.id) ORDER BY id", "id\n1\n");
        EXPECT("SELECT EXISTS (SELECT 1/(u.x - u.x) FROM u JOIN t ON t.id = u.id) AS v", "v\ntrue\n");
        EXPECT("SELECT EXISTS (SELECT 1/(u.x - u.x) FROM u JOIN t ON t.id = u.id WHERE t.a > 100) AS v", "v\nfalse\n");
    }
    CHECK(run("SET cross_check = off") == 0);
    for (int pass = 0; pass < 2; pass++) {
        if (pass) CHECK(run("CHECKPOINT") == 0);
        for (size_t p = 0; p < sizeof PATHS / sizeof *PATHS; p++) {
            char set[64];
            snprintf(set, sizeof set, "SET access_path = %s", PATHS[p]);
            CHECK(run(set) == 0);
            EXPECT("SELECT EXISTS (SELECT 1 FROM b) AS v", "v\ntrue\n");
            CHECK(g_s.rows_tested == 1);
            EXPECT("SELECT EXISTS (SELECT 1 FROM b WHERE v = 96) AS v", "v\ntrue\n");
            CHECK(g_s.rows_tested == 1);
            EXPECT("SELECT EXISTS (SELECT 1 FROM b WHERE v + 0 = 96) AS v", "v\ntrue\n"); /* a tree: every row it may fail on */
            CHECK(g_s.rows_tested == NBIG);
            EXPECT("SELECT EXISTS (SELECT 1 FROM b WHERE v = 97) AS v", "v\nfalse\n");
        }
    }
    CHECK(run("SET access_path = auto") == 0);
    done(db);
}

/* why the first row stops a path only with no WHERE tree left: in the ordered index's key order the row v = 50 (a
 * division by zero) comes before any that qualifies; in the store's and the scan's order a qualifying one (v = 90)
 * comes first. A path that stopped there would make the outcome its own: every path tests every row, and fails */
static void t_lazy_first_row(void)
{
    imdb_db *db = setup();
    if (!db) return;
    CHECK(run("CREATE TABLE c (id INT64 PRIMARY KEY, v INT64)") == 0 && run("CREATE INDEX cv ON c (v)") == 0);
    CHECK(run("INSERT INTO c VALUES (1, 90), (2, 50), (3, 10)") == 0);
    db = reopen(db); /* v's index read in its keys' order (its runs before, as they were inserted) */
    CHECK(db != NULL);
    for (int xc = 0; xc < 2; xc++) {
        CHECK(run(xc ? "SET cross_check = on" : "SET cross_check = off") == 0);
        for (size_t p = 0; p < sizeof PATHS / sizeof *PATHS; p++) {
            char set[64];
            snprintf(set, sizeof set, "SET access_path = %s", PATHS[p]);
            CHECK(run(set) == 0);
            EXPECT("SELECT EXISTS (SELECT 1 FROM c WHERE v >= 0 AND 100 / (v - 50) > 0) AS e", "ERR division by zero");
            EXPECT("SELECT EXISTS (SELECT 1 FROM c WHERE v >= 60) AS e", "e\ntrue\n");
        }
    }
    CHECK(run("SET access_path = auto") == 0 && run("SET cross_check = off") == 0);
    done(db);
}

/* a lazy run is the statement's: its cancel and deadline, its memory ceiling; EXPLAIN runs none; nothing written */
static void t_lazy_limits(void)
{
    imdb_db *db = setup();
    if (!db) return;
    uint64_t seq = db->seq;
    static const char heavy[] = "SELECT CASE WHEN id = 1 THEN (SELECT COUNT(*) FROM b AS b1 CROSS JOIN b AS b2 WHERE b1.v + b2.v > -1) "
                                "ELSE 0 END AS n FROM t";
    CHECK(run("SET statement_timeout = 30") == 0);
    CHECK(run(heavy) == IMDB_ERR_CANCELLED);
    EXPECT("SELECT CASE WHEN id = 0 THEN (SELECT COUNT(*) FROM b AS b1 CROSS JOIN b AS b2 WHERE b1.v + b2.v > -1) ELSE 0 END "
           "AS n FROM t",
           "n\n0\n0\n0\n"); /* never reached: its cost never paid */
    CHECK(run("SET statement_timeout = 0") == 0);
    CHECK(run("SET statement_memory = 1048576") == 0);
    int rc = run("SELECT CASE WHEN id = 1 THEN (SELECT COUNT(*) FROM (SELECT b1.v, b2.v AS w FROM b AS b1 CROSS JOIN b AS b2) "
                 "AS q) ELSE 0 END AS n FROM t");
    CHECK(rc == IMDB_ERR_NOMEM || rc == IMDB_ERR_LIMIT);
    CHECK(run("SET statement_memory = 0") == 0);
    EXPECT("SELECT COUNT(*) AS n FROM t", "n\n3\n"); /* the session goes on */
    /* the row limit is a plan's own: the memo spares a second plan the runs the first made, so a first plan it stops
     * (here in its second correlated run: 2 rows, then 31 and 31 of b's) fails the statement, never the cross-check */
    CHECK(run("SET cross_check = on") == 0 && run("SET statement_row_limit = 50") == 0);
    EXPECT("SELECT id, (SELECT COUNT(*) FROM b WHERE b.v = t.a) AS n FROM t WHERE id < 3", "ERR statement row limit");
    CHECK(g_e.code == IMDB_ERR_LIMIT);
    CHECK(run("SET statement_row_limit = 100") == 0);
    EXPECT("SELECT id, (SELECT COUNT(*) FROM b WHERE b.v = t.a) AS n FROM t WHERE id < 3", "id,n\n1,31\n2,31\n");
    CHECK(run("SET statement_row_limit = 0") == 0 && run("SET cross_check = off") == 0);
    /* EXPLAIN: an expression's SELECT waits for a row, so EXPLAIN runs none (a derived table's still, as before) */
    const char *x = csv("EXPLAIN SELECT CASE WHEN id = 1 THEN 7 ELSE (SELECT COUNT(*) FROM b) END FROM t");
    CHECK(strstr(x, "(an expression's) run when a row first needs it") != NULL);
    CHECK(g_s.rows_tested == 0 && g_s.corr_runs == 0);
    x = csv("EXPLAIN SELECT COUNT(*) FROM (SELECT id FROM b) AS q WHERE id IN (SELECT id FROM u)");
    CHECK(strstr(x, "2 nested SELECTs: q 3000 rows, run first; (an expression's)") != NULL);
    x = csv("EXPLAIN DELETE FROM t WHERE EXISTS (SELECT 1/(x - x) FROM u)"); /* a write's, run first by presence */
    CHECK(strstr(x, "1 nested SELECT, run first (its rows are what the rest is planned over; EXPLAIN reads them): (EXISTS) a row") !=
          NULL);
    x = csv("EXPLAIN DELETE FROM t WHERE id IN (SELECT id FROM u)");
    CHECK(strstr(x, "1 nested SELECT, run first (its rows are what the rest is planned over; EXPLAIN reads them): (a value) 2 rows") != NULL);
    CHECK(db->seq == seq);
    done(db);
}

/* the memory ceiling is a plan's own under cross_check: a hash join's two plans build different sides, so the second
 * (40,000 rows of big built) may pass the ceiling the first (t's three) kept under: the statement fails with the
 * ceiling's refusal, never a cross-check failure (xc_own reads the ceiling's refusals since the plan began) */
static void t_lazy_cross_ceiling(void)
{
    imdb_db *db = setup();
    if (!db) return;
    CHECK(run("CREATE TABLE big (id INT64 PRIMARY KEY, v INT64)") == 0);
    for (int k = 0; k < 8; k++) {
        imdb_buf q;
        imdb_buf_init(&q);
        imdb_buf_put_str(&q, "INSERT INTO big VALUES ");
        for (int i = 1; i <= 5000; i++) imdb_buf_printf(&q, "%s(%d, %d)", i > 1 ? ", " : "", k * 5000 + i, (k * 5000 + i) % 5);
        imdb_buf_put_u8(&q, 0);
        bool ok = !imdb_buf_check(&q, &g_e) && run((const char *)q.p) == 0;
        imdb_buf_free(&q);
        CHECK(ok);
    }
    CHECK(run("SET cross_check = on") == 0 && run("SET statement_memory = 1048576") == 0);
    EXPECT("SELECT COUNT(*) AS n FROM big JOIN t ON t.id = big.v", "ERR statement memory");
    CHECK(run("SET statement_memory = 0") == 0);
    EXPECT("SELECT COUNT(*) AS n FROM big JOIN t ON t.id = big.v", "n\n24000\n");
    CHECK(run("SET cross_check = off") == 0);
    done(db);
}

/* a write's own subqueries run before its first write (they read the statement's snapshot, never its own writes);
 * INSERT's query is a SELECT run whole before the first write, lazy inside */
static void t_lazy_writes(void)
{
    imdb_db *db = setup();
    if (!db) return;
    EXPECT("UPDATE t SET a = CASE WHEN id = 1 THEN 11 ELSE (SELECT 1/(u.id - u.id) FROM u) END WHERE id = 1",
           "ERR division by zero");
    EXPECT("UPDATE t SET a = (SELECT MAX(a) FROM t) + id", "UPDATE 3");
    EXPECT("SELECT a FROM t ORDER BY id", "a\n31\n32\n33\n");
    CHECK(run("CREATE TABLE w (id INT64 PRIMARY KEY, v INT64)") == 0);
    EXPECT("INSERT INTO w SELECT id, CASE WHEN id = 1 THEN 7 ELSE (SELECT 1/(u.id - u.id) FROM u) END FROM t WHERE id = 1",
           "INSERT 1");
    EXPECT("SELECT * FROM w", "id,v\n1,7\n");
    EXPECT("UPDATE w SET v = 8 WHERE EXISTS (SELECT 1/(x - x) FROM u)", "UPDATE 1"); /* run first, by presence */
    EXPECT("UPDATE w SET v = 9 WHERE EXISTS (SELECT SUM(1/(x - x)) FROM u)", "ERR division by zero");
    EXPECT("SELECT * FROM w", "id,v\n1,8\n");
    EXPECT("DELETE FROM w WHERE EXISTS (SELECT 1/(u.x - u.x) FROM u WHERE u.id = w.id + 1)", "DELETE 1");
    done(db);
}

/* a nested SELECT reads WITH's row sets by name, never a derived table's: that name is a range variable of its own
 * statement (before S11 a later nested SELECT read it, over a table of that name) */
static void t_lazy_names(void)
{
    imdb_db *db = setup();
    if (!db) return;
    CHECK(run("CREATE TABLE d (id INT64 PRIMARY KEY)") == 0 && run("INSERT INTO d VALUES (2), (3)") == 0);
    EXPECT("SELECT id FROM (SELECT id FROM t) AS d WHERE id IN (SELECT id FROM d) ORDER BY id", "id\n2\n3\n");
    EXPECT("SELECT (SELECT COUNT(*) FROM d) AS n FROM (SELECT id FROM t) AS d ORDER BY n", "n\n2\n2\n2\n");
    EXPECT("SELECT id FROM (SELECT id FROM t) AS q WHERE id IN (SELECT id FROM q)", "ERR no table q");
    EXPECT("SELECT * FROM (SELECT id FROM t) AS q1, (SELECT id FROM q1) AS q2", "ERR no table q1");
    EXPECT("WITH c AS (SELECT id FROM t WHERE id > 1) SELECT id FROM t WHERE id IN (SELECT id FROM c) ORDER BY id",
           "id\n2\n3\n");
    EXPECT("WITH c AS (SELECT id FROM t WHERE id > 1) SELECT (SELECT COUNT(*) FROM c) AS n FROM t WHERE id = 1", "n\n2\n");
    EXPECT("WITH c AS (SELECT id FROM t WHERE id > 1), e AS (SELECT id FROM c WHERE id > 2) SELECT * FROM e", "id\n3\n");
    done(db);
}

const test_case lazy_tests[] = {
    {"lazy_branches", t_lazy_branches},
    {"lazy_depth", t_lazy_depth},
    {"lazy_bind", t_lazy_bind},
    {"lazy_exists", t_lazy_exists},
    {"lazy_first_row", t_lazy_first_row},
    {"lazy_limits", t_lazy_limits},
    {"lazy_cross_ceiling", t_lazy_cross_ceiling},
    {"lazy_writes", t_lazy_writes},
    {"lazy_names", t_lazy_names},
};
const size_t lazy_ntests = sizeof lazy_tests / sizeof *lazy_tests;
