/* P2 S4 (docs/plan-p2.md): nested SELECTs read as tables (row sets): FROM (SELECT ...) AS x, a join's, WITH x AS
 * (SELECT ...). A differential (each statement over (SELECT * FROM t) AS x answers as the same statement over t, in
 * memory and in the lake); WITH chains and a CTE read twice; a row set's types when it is empty; joins of row sets and
 * tables under both plans with cross_check; the enclosing transaction's view (its own pending writes); the memory
 * ceiling and a timeout reaching a nested SELECT; every refusal. */
#include <stdlib.h>

#include "../../src/db.h"
#include "../../src/sql.h"
#include "thelp.h"

static imdb_session g_s;
static char g_out[1 << 16], g_out2[1 << 16];

static const char *csv_to(const char *sql, char *out, size_t cap)
{
    imdb_result r;
    imdb_err_clear(&g_e);
    if (imdb_exec_one(&g_s, sql, strlen(sql), NULL, 0, &r, &g_e)) {
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
static const char *csv(const char *sql) { return csv_to(sql, g_out, sizeof g_out); }

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

static void fill(int n)
{
    imdb_buf b;
    imdb_buf_init(&b);
    imdb_buf_put_str(&b, "INSERT INTO t VALUES ");
    for (int i = 1; i <= n; i++)
        imdb_buf_printf(&b, "%s(%d, %s, %d.%02d, %s, %s)", i > 1 ? ", " : "", i, i % 9 ? (i % 7 == 0 ? "NULL" : "1") : "2",
                        i % 50, i % 100, i % 11 ? (i % 2 ? "'ab'" : "'Cd'") : "NULL", i % 3 ? "TRUE" : "FALSE");
    imdb_buf_put_u8(&b, 0);
    CHECK(!imdb_buf_check(&b, &g_e) && !run((const char *)b.p));
    imdb_buf_free(&b);
}

/* tmpl with each @T replaced by with */
static void subst(char *out, size_t cap, const char *tmpl, const char *with)
{
    size_t o = 0, wl = strlen(with);
    for (const char *p = tmpl; *p && o + 1 < cap; p++) {
        if (p[0] == '@' && p[1] == 'T' && o + wl + 1 < cap) {
            memcpy(out + o, with, wl);
            o += wl;
            p++;
        } else {
            out[o++] = *p;
        }
    }
    out[o] = 0;
}

/* each statement over a row set of all of t answers as over t itself (the row set keeps t's key order) */
static void t_rset_differential(void)
{
    imdb_db *db = open_fresh();
    CHECK(db != NULL);
    if (!db) return;
    CHECK(run("CREATE TABLE t (id INT64 PRIMARY KEY, g INT64, d DECIMAL(9,2), s TEXT, k BOOL)") == 0);
    fill(400);
    static const char *const q[] = {
        "SELECT id, g, d FROM @T WHERE d > 20 AND s = 'ab'",
        "SELECT * FROM @T WHERE g IS NULL OR k",
        "SELECT g, COUNT(*), SUM(d), MIN(s), MAX(id) FROM @T GROUP BY g",
        "SELECT LOWER(s), COUNT(DISTINCT g) FROM @T GROUP BY LOWER(s)",
        "SELECT id, d * 2 FROM @T WHERE id BETWEEN 50 AND 90 ORDER BY d DESC, id LIMIT 7",
        "SELECT DISTINCT g, k FROM @T ORDER BY 1, 2",
        "SELECT COUNT(*), AVG(d) FROM @T WHERE s LIKE 'C%'",
        "SELECT id FROM @T WHERE id IN (3, 30, 300) ORDER BY id",
    };
    char a[512], b[512];
    for (int pass = 0; pass < 2; pass++) {
        for (size_t i = 0; i < sizeof q / sizeof *q; i++) {
            subst(a, sizeof a, q[i], "t");
            subst(b, sizeof b, q[i], "(SELECT * FROM t) AS x");
            csv_to(a, g_out, sizeof g_out);
            csv_to(b, g_out2, sizeof g_out2);
            if (strncmp(g_out, "ERR", 3) == 0 || strcmp(body(g_out), body(g_out2))) {
                char m[700];
                snprintf(m, sizeof m, "%s\n      direct: %.200s\n      nested: %.200s", b, g_out, g_out2);
                test_fail(__FILE__, __LINE__, m);
            }
        }
        if (!pass) CHECK(run("CHECKPOINT") == 0);
    }
    done(db);
}

/* WITH chains, a CTE read twice, a row set's types when it is empty, joins with cross_check under both plans */
static void t_rset_forms(void)
{
    imdb_db *db = open_fresh();
    CHECK(db != NULL);
    if (!db) return;
    CHECK(run("CREATE TABLE t (id INT64 PRIMARY KEY, g INT64, d DECIMAL(9,2), s TEXT, k BOOL)") == 0);
    fill(40);
    EXPECT("WITH a AS (SELECT id, d FROM t WHERE d > 30), b AS (SELECT COUNT(*) AS n, SUM(d) AS sd FROM a) SELECT * FROM b",
           "n,sd\n11,388.85\n"); /* ids 30..40: d = 1.01 id */
    EXPECT("WITH w AS (SELECT id, g FROM t WHERE id <= 4) SELECT x.id, y.id FROM w AS x JOIN w AS y ON x.g = y.g AND x.id < y.id",
           "id,id\n1,2\n1,3\n1,4\n2,3\n2,4\n3,4\n");
    EXPECT("SELECT q.dd + 1, LOWER(q.s) FROM (SELECT d * 2 AS dd, s FROM t WHERE id > 1000) AS q", "x,y\n"); /* empty, typed */
    EXPECT("SELECT COUNT(*), SUM(q.dd) FROM (SELECT d * 2 AS dd FROM t WHERE id > 1000) AS q", "x,y\n0,\n");
    EXPECT("WITH n AS (SELECT 41 + 1 AS v, 'x' AS w) SELECT v * 2, w || w FROM n", "x,y\n84,\"xx\"\n");
    CHECK(run("SET cross_check = on") == 0);
    for (int plan = 0; plan < 2; plan++) {
        CHECK(run(plan ? "SET join_plan = index" : "SET join_plan = hash") == 0);
        EXPECT("SELECT g.g, g.n, t.id FROM (SELECT g, COUNT(*) AS n FROM t GROUP BY g) AS g JOIN t ON g.g = t.g WHERE t.id <= 9",
               "g,n,id\n1,31,1\n1,31,2\n1,31,3\n1,31,4\n1,31,5\n1,31,6\n1,31,8\n2,4,9\n"); /* g 1: 40 less 4 and 5 */
        EXPECT("SELECT t.id, r.c FROM t LEFT JOIN (SELECT id, s || '!' AS c FROM t WHERE k) AS r ON t.id = r.id WHERE t.id <= 4",
               "id,c\n1,\"ab!\"\n2,\"Cd!\"\n3,\n4,\"Cd!\"\n");
        EXPECT("SELECT a.n, b.n FROM (SELECT COUNT(*) AS n FROM t) AS a FULL JOIN (SELECT COUNT(*) AS n FROM t WHERE k) AS b ON a.n = b.n",
               "n,n\n40,\n,27\n");
    }
    done(db);
}

/* the enclosing transaction's view: its own pending writes, as the outer statement reads them */
static void t_rset_view(void)
{
    imdb_db *db = open_fresh();
    CHECK(db != NULL);
    if (!db) return;
    CHECK(run("CREATE TABLE t (id INT64 PRIMARY KEY, g INT64, d DECIMAL(9,2), s TEXT, k BOOL)") == 0);
    fill(10);
    CHECK(run("BEGIN") == 0);
    CHECK(run("INSERT INTO t VALUES (100, 5, 9.99, 'new', TRUE)") == 0);
    CHECK(run("DELETE FROM t WHERE id <= 5") == 0);
    EXPECT("SELECT COUNT(*), MAX(x.id) FROM (SELECT id FROM t) AS x", "x,y\n6,100\n");
    EXPECT("WITH a AS (SELECT id FROM t WHERE g = 5) SELECT a.id, t.s FROM a JOIN t ON a.id = t.id", "id,s\n100,\"new\"\n");
    CHECK(run("ROLLBACK") == 0);
    EXPECT("SELECT COUNT(*), MAX(x.id) FROM (SELECT id FROM t) AS x", "x,y\n10,10\n");
    done(db);
}

/* a nested SELECT's result is the statement's memory; a timeout stops it; every refusal */
static void t_rset_limits(void)
{
    imdb_db *db = open_fresh();
    CHECK(db != NULL);
    if (!db) return;
    CHECK(run("CREATE TABLE t (id INT64 PRIMARY KEY, g INT64, d DECIMAL(9,2), s TEXT, k BOOL)") == 0);
    fill(20000);
    CHECK(run("SET statement_memory = 1048576") == 0);
    EXPECT("SELECT COUNT(*) FROM (SELECT id, s, d FROM t) AS x", "ERR statement memory");
    EXPECT("SELECT COUNT(*) FROM (SELECT COUNT(*) AS n FROM t) AS x", "count\n1\n"); /* one row: within the ceiling */
    CHECK(run("SET statement_memory = 0") == 0);
    CHECK(run("SET statement_timeout = 1") == 0);
    imdb_buf b;
    imdb_buf_init(&b);
    imdb_buf_put_str(&b, "SELECT COUNT(*) FROM (SELECT x.id FROM t AS x JOIN t AS y ON x.g = y.g WHERE x.id + y.id > 0) AS q");
    imdb_buf_put_u8(&b, 0);
    CHECK(!imdb_buf_check(&b, &g_e));
    int rc = run((const char *)b.p);
    CHECK(rc == IMDB_ERR_CANCELLED || rc == IMDB_ERR_LIMIT); /* stopped inside the nested SELECT (or its pairs' cap) */
    imdb_buf_free(&b);
    CHECK(run("SET statement_timeout = 0") == 0);
    EXPECT("SELECT * FROM (SELECT id, id FROM t) AS q", "ERR names two columns id");
    EXPECT("SELECT * FROM (SELECT id FROM t)", "ERR needs a name");
    EXPECT("EXPLAIN SELECT COUNT(*) FROM (SELECT id FROM t WHERE id < 4) AS q",
           "item,detail\n\"nested\",\"1 nested SELECT, run first (its rows are what the rest is planned over; EXPLAIN reads "
           "them): q 3 rows\"\n\"table\",\"q\"\n\"snapshot\",\"commit 2 (the latest)\"\n\"path\",\"nested\"\n"
           "\"why\",\"a nested SELECT's rows: no index; read in their order\"\n\"conditions\",\"none: every visible row\"\n"
           "\"estimate\",\"3 rows, the nested SELECT's (it ran first)\"\n\"output\",\"one row of aggregates\"\n");
    EXPECT("SELECT * FROM (SELECT id FROM t) AS q FOR UPDATE", "ERR FOR UPDATE");
    EXPECT("SELECT * FROM (SELECT id FROM t) AS q AS OF 1", "ERR AS OF with a nested SELECT");
    EXPECT("SELECT * FROM (SELECT id FROM t AS OF 1) AS q", "ERR AS OF in a nested SELECT");
    EXPECT("SELECT * FROM (SELECT * FROM (SELECT * FROM (SELECT * FROM (SELECT * FROM (SELECT id FROM t) AS a) AS b) AS c) AS d) AS e",
           "ERR nested deeper than 4");
    EXPECT("WITH a AS (SELECT 1 AS v), a AS (SELECT 2 AS v) SELECT * FROM a", "ERR two nested SELECTs named a");
    EXPECT("SELECT * FROM (SELECT SUM(id * 1000000000000) AS big FROM t) AS q", "ERR past 18 digits"); /* 2e20: each term fits */
    done(db);
}


/* x IN / NOT IN (SELECT ...) three-valued, against a model over every value of a small domain with NULLs on both
 * sides: TRUE at a match; else UNKNOWN when x is NULL or the set holds a NULL (but FALSE over an empty set) */
static void t_rset_in_model(void)
{
    imdb_db *db = open_fresh();
    CHECK(db != NULL);
    if (!db) return;
    CHECK(run("CREATE TABLE a (id INT64 PRIMARY KEY, x INT64)") == 0);
    CHECK(run("CREATE TABLE b (id INT64 PRIMARY KEY, y INT64, grp INT64)") == 0);
    CHECK(run("INSERT INTO a VALUES (1, 1), (2, 2), (3, 3), (4, NULL), (5, 5)") == 0);
    /* grp 0: {1, 2}; grp 1: {2, NULL}; grp 2: {NULL}; grp 3: {} (no row) */
    CHECK(run("INSERT INTO b VALUES (1, 1, 0), (2, 2, 0), (3, 2, 1), (4, NULL, 1), (5, NULL, 2)") == 0);
    static const int set[4][3] = {{1, 2, 0}, {2, -1, 0}, {-1, 0, 0}, {0, 0, 0}}; /* -1 NULL, 0 end */
    static const int setn[4] = {2, 2, 1, 0};
    static const int xs[5] = {1, 2, 3, -1, 5};
    char q[256], want[256];
    for (int g = 0; g < 4; g++)
        for (int neg = 0; neg < 2; neg++) {
            size_t o = (size_t)snprintf(want, sizeof want, "id,v\n");
            for (int i = 0; i < 5; i++) {
                int t = 0; /* 1 TRUE, 0 FALSE, -1 UNKNOWN */
                bool has_null = false;
                for (int k = 0; k < setn[g]; k++) {
                    if (set[g][k] < 0) has_null = true;
                    else if (xs[i] >= 0 && set[g][k] == xs[i]) t = 1;
                }
                if (t != 1 && setn[g] && (xs[i] < 0 || has_null)) t = -1;
                if (neg) t = t < 0 ? -1 : !t;
                o += (size_t)snprintf(want + o, sizeof want - o, "%d,%s\n", i + 1, t < 0 ? "" : t ? "true" : "false");
            }
            snprintf(q, sizeof q, "SELECT id, x %sIN (SELECT y FROM b WHERE grp = %d) AS v FROM a ORDER BY id", neg ? "NOT " : "", g);
            EXPECT(q, want);
        }
    /* WHERE keeps TRUE alone: NOT IN with a NULL in the set keeps nothing */
    EXPECT("SELECT id FROM a WHERE x NOT IN (SELECT y FROM b WHERE grp = 1)", "id\n");
    EXPECT("SELECT id FROM a WHERE x NOT IN (SELECT y FROM b WHERE grp = 3) ORDER BY id", "id\n1\n2\n3\n4\n5\n"); /* empty set */
    /* exact across numeric kinds, as comparisons are */
    EXPECT("SELECT id FROM a WHERE x IN (SELECT y * 1.00 FROM b) ORDER BY id", "id\n1\n2\n");
    done(db);
}

/* EXISTS, scalar subqueries (no row: NULL; more than one: refused), subqueries in writes, a subquery in a subquery */
static void t_rset_subq_forms(void)
{
    imdb_db *db = open_fresh();
    CHECK(db != NULL);
    if (!db) return;
    CHECK(run("CREATE TABLE t (id INT64 PRIMARY KEY, g INT64, d DECIMAL(9,2), s TEXT, k BOOL)") == 0);
    fill(40);
    EXPECT("SELECT EXISTS (SELECT 1 FROM t WHERE g = 2), EXISTS (SELECT 1 FROM t WHERE g = 9), NOT EXISTS (SELECT 1 FROM t WHERE g = 9)",
           "x,y,z\ntrue,false,true\n");
    EXPECT("SELECT (SELECT MAX(d) FROM t), (SELECT s FROM t WHERE id = 3), (SELECT s FROM t WHERE id = 1000)", "x,y,z\n40.40,\"ab\",\n");
    EXPECT("SELECT COUNT(*) FROM t WHERE d > (SELECT AVG(d) FROM t) AND g IN (SELECT g FROM t WHERE id = 9)", "count\n2\n");
    EXPECT("SELECT id FROM t WHERE id IN (SELECT id FROM t WHERE id IN (SELECT id + 30 FROM t WHERE id < 3)) ORDER BY id",
           "id\n31\n32\n");
    EXPECT("SELECT (SELECT s FROM t WHERE id < 3)", "ERR returned more than one row");
    EXPECT("SELECT (SELECT id, s FROM t WHERE id = 1)", "ERR returns one column");
    EXPECT("SELECT id FROM t WHERE id IN (SELECT id, s FROM t)", "ERR takes one column");
    EXPECT("SELECT id FROM t WHERE s IN (SELECT id FROM t)", "ERR IN compares TEXT with INT64");
    /* P2 S4b: a nested SELECT reads the statement directly around it from its conditions and expressions (t_rset_corr);
     * a bare item's column of it, a statement further out, SET's and an unknown name are each told so */
    EXPECT("SELECT id FROM t WHERE id = (SELECT t.id FROM t AS u WHERE u.id = t.id)", "ERR a bare item's or an aggregate's column");
    EXPECT("SELECT COUNT(*) FROM t AS o WHERE EXISTS (SELECT 1 FROM t WHERE t.g = o.g)", "count\n35\n");
    EXPECT("SELECT id FROM t WHERE id IN (SELECT id FROM t AS a WHERE EXISTS (SELECT 1 FROM t AS b WHERE b.id = a.id AND t.g = 1))",
           "ERR a statement further out, is a later step");
    EXPECT("UPDATE t SET g = (SELECT MAX(w.g) FROM t AS w WHERE w.d = t.d)", "ERR a correlated subquery in UPDATE's SET");
    EXPECT("SELECT id FROM t WHERE id IN (SELECT id FROM t AS w WHERE nosuch.d = 1)", "ERR no table nosuch in this statement");
    CHECK(run("UPDATE t SET g = (SELECT MAX(id) FROM t) WHERE id IN (SELECT id FROM t WHERE id > 38)") == 0);
    EXPECT("SELECT id, g FROM t WHERE id > 37 ORDER BY id", "id,g\n38,1\n39,40\n40,40\n");
    CHECK(run("DELETE FROM t WHERE g IN (SELECT MAX(g) FROM t)") == 0); /* read before the delete: 40 */
    EXPECT("SELECT COUNT(*), MAX(id) FROM t", "x,y\n38,38\n");
    CHECK(run("INSERT INTO t VALUES ((SELECT MAX(id) FROM t) + 1, 7, 0.00, 'n', TRUE)") == 0);
    EXPECT("SELECT id, g FROM t WHERE id = (SELECT MAX(id) FROM t)", "id,g\n39,7\n");
    done(db);
}


/* SHOW TRANSACTIONS' lock count of g_s's own transaction (-1: none listed) */
static int64_t own_locks(void)
{
    imdb_result r;
    int64_t n = -1;
    imdb_err_clear(&g_e);
    if (imdb_exec_one(&g_s, "SHOW TRANSACTIONS", 17, NULL, 0, &r, &g_e) == 0) {
        for (uint64_t i = 0; i < r.nrows; i++)
            if (r.ncols == 7 && r.cells[7 * i + 6].v.i == 1) n = r.cells[7 * i + 5].v.i;
        imdb_result_free(&r);
    }
    return n;
}

/* EXPLAIN of a statement with a nested SELECT runs that SELECT (its rows are what the rest is planned over) and
 * nothing more: no commit, no lock, the view token unchanged; the nested run is under the statement's own limits */
static void t_rset_explain(void)
{
    imdb_db *db = open_fresh();
    CHECK(db != NULL);
    if (!db) return;
    CHECK(run("CREATE TABLE t (id INT64 PRIMARY KEY, g INT64, d DECIMAL(9,2), s TEXT, k BOOL)") == 0);
    fill(40);
    uint64_t seq = db->seq;
    uint8_t t0[32], t1[32];
    CHECK(imdb_view_token(db, t0, &g_e) == 0);
    static const char *const q[] = {
        "EXPLAIN SELECT COUNT(*) FROM (SELECT id FROM t WHERE g = 1) AS q",
        "EXPLAIN WITH q AS (SELECT id, g FROM t) SELECT g, COUNT(*) FROM q GROUP BY g",
        "EXPLAIN UPDATE t SET g = 5 WHERE id IN (SELECT id FROM t WHERE id < 3)",
        "EXPLAIN DELETE FROM t WHERE id = (SELECT MAX(id) FROM t)",
        "EXPLAIN SELECT t.id FROM t JOIN (SELECT id FROM t WHERE id < 5) AS q ON q.id = t.id",
    };
    for (size_t i = 0; i < sizeof q / sizeof *q; i++) {
        const char *got = csv(q[i]);
        if (strncmp(got, "item,detail\n\"nested\",\"1 nested SELECT, run first", 48) != 0) {
            char m[600];
            snprintf(m, sizeof m, "%s: %.400s", q[i], got);
            test_fail(__FILE__, __LINE__, m);
        }
    }
    CHECK(db->seq == seq); /* an autocommitted write's EXPLAIN commits nothing */
    CHECK(imdb_view_token(db, t1, &g_e) == 0 && !memcmp(t0, t1, sizeof t0));
    EXPECT("SELECT COUNT(*) FROM t WHERE g = 5", "count\n0\n");
    EXPECT("SELECT MAX(id) FROM t", "max\n40\n");
    /* in a transaction, EXPLAIN ... FOR UPDATE with a nested SELECT takes no lock; the statement then takes its rows' */
    CHECK(run("BEGIN") == 0);
    CHECK(!strncmp(csv("EXPLAIN SELECT * FROM t WHERE id IN (SELECT id FROM t WHERE id < 3) FOR UPDATE"), "item,detail\n\"nested\"", 20));
    CHECK(own_locks() == 0);
    CHECK(run("SELECT * FROM t WHERE id IN (SELECT id FROM t WHERE id < 3) FOR UPDATE") == 0);
    CHECK(own_locks() == 2);
    CHECK(run("ROLLBACK") == 0 && db->seq == seq);
    /* the nested SELECT's rows tested are the statement's: the row limit refuses EXPLAIN as it refuses the run */
    CHECK(run("SET statement_row_limit = 10") == 0);
    EXPECT("EXPLAIN SELECT COUNT(*) FROM (SELECT id FROM t) AS q", "ERR statement row limit");
    EXPECT("SELECT COUNT(*) FROM (SELECT id FROM t) AS q", "ERR statement row limit");
    EXPECT("EXPLAIN SELECT id FROM t WHERE id = 1 AND g IN (SELECT g FROM t)", "ERR statement row limit");
    CHECK(run("SET statement_row_limit = 100") == 0);
    EXPECT("SELECT COUNT(*) FROM (SELECT id FROM t) AS q", "count\n40\n");
    CHECK(run("SET statement_row_limit = 0") == 0);
    done(db);
}


/* two statements answer alike (their bodies: the headers may name columns differently) */
static void same_body(const char *a, const char *b, int line)
{
    csv_to(a, g_out, sizeof g_out);
    csv_to(b, g_out2, sizeof g_out2);
    if (!strncmp(g_out, "ERR", 3) || strcmp(body(g_out), body(g_out2)) != 0) {
        char m[1600];
        snprintf(m, sizeof m, "%s\n      vs %s\n      got:  %.300s\n      want: %.300s", a, b, g_out, g_out2);
        test_fail(__FILE__, line, m);
    }
}
#define SAME(a, b) same_body((a), (b), __LINE__)

/* P2 S4b: correlated subqueries (the statement directly around them), each form against an uncorrelated twin or a model
 * computed here, in memory, cross-checked and in the lake; writes; the memo (the row limit proves it); the memory
 * ceiling; errors decided before any row; EXPLAIN; every refusal */
static void t_rset_corr(void)
{
    imdb_db *db = open_fresh();
    CHECK(db != NULL);
    if (!db) return;
    enum { N = 300 };
    CHECK(run("CREATE TABLE t (id INT64 PRIMARY KEY, g INT64, d DECIMAL(9,2), s TEXT, k BOOL)") == 0);
    CHECK(run("CREATE TABLE u (id INT64 PRIMARY KEY, tid INT64, v INT64, w TEXT)") == 0);
    CHECK(run("CREATE TABLE z (id INT64 PRIMARY KEY, uid INT64)") == 0);
    fill(N);
    imdb_buf b;
    imdb_buf_init(&b);
    imdb_buf_put_str(&b, "INSERT INTO u VALUES ");
    int64_t tid[N + 1], v[N + 1];
    for (int i = 1; i <= N; i++) {
        tid[i] = i % 11 ? (i * 7) % (N / 2) : -1; /* -1: NULL */
        v[i] = (i * 13) % 50 - 10;
        char ts[16];
        snprintf(ts, sizeof ts, "%lld", (long long)tid[i]);
        imdb_buf_printf(&b, "%s(%d, %s, %lld, %s)", i > 1 ? ", " : "", i, tid[i] < 0 ? "NULL" : ts, (long long)v[i],
                        i % 5 ? (i % 2 ? "'ab'" : "'Cd'") : "NULL");
    }
    imdb_buf_put_u8(&b, 0);
    CHECK(!imdb_buf_check(&b, &g_e) && !run((const char *)b.p));
    b.len = 0;
    imdb_buf_put_str(&b, "INSERT INTO z VALUES ");
    for (int i = 1; i <= N; i++) imdb_buf_printf(&b, "%s(%d, %d)", i > 1 ? ", " : "", i, (i * 3) % N + 1);
    imdb_buf_put_u8(&b, 0);
    CHECK(!imdb_buf_check(&b, &g_e) && !run((const char *)b.p));
    imdb_buf_free(&b);
    /* a model: for each t row, the u rows whose v exceeds its g (g NULL: none), in t's order */
    char want[1 << 14];
    size_t o = (size_t)snprintf(want, sizeof want, "id,c\n");
    for (int i = 1; i <= N && o < sizeof want; i++) {
        int g = i % 9 ? (i % 7 == 0 ? -1000 : 1) : 2, c = 0;
        for (int j = 1; g != -1000 && j <= N; j++) c += v[j] > g;
        o += (size_t)snprintf(want + o, sizeof want - o, "%d,%d\n", i, c);
    }
    for (int pass = 0; pass < 3; pass++) { /* in memory, cross-checked, in the lake */
        if (pass == 1) CHECK(run("SET cross_check = on") == 0);
        if (pass == 2) CHECK(run("CHECKPOINT") == 0);
        SAME("SELECT id FROM t WHERE EXISTS (SELECT 1 FROM u WHERE u.tid = t.id) ORDER BY id",
             "SELECT id FROM t WHERE id IN (SELECT tid FROM u) ORDER BY id");
        SAME("SELECT id FROM t WHERE NOT EXISTS (SELECT 1 FROM u WHERE u.tid = t.id) ORDER BY id",
             "SELECT id FROM t WHERE id NOT IN (SELECT tid FROM u WHERE tid IS NOT NULL) ORDER BY id");
        SAME("SELECT id, (SELECT MAX(v) FROM u WHERE u.tid = t.id) AS m FROM t ORDER BY id",
             "SELECT t.id, MAX(u.v) FROM t LEFT JOIN u ON u.tid = t.id GROUP BY t.id ORDER BY t.id");
        SAME("SELECT id, (SELECT COUNT(*) FROM u WHERE u.tid = t.id) AS c FROM t ORDER BY id",
             "SELECT t.id, COUNT(u.id) FROM t LEFT JOIN u ON u.tid = t.id GROUP BY t.id ORDER BY t.id");
        SAME("SELECT id FROM t WHERE id IN (SELECT tid FROM u WHERE u.v = t.id % 50 - 10) ORDER BY id",
             "SELECT DISTINCT t.id FROM t JOIN u ON u.tid = t.id AND u.v = t.id % 50 - 10 ORDER BY t.id");
        SAME("SELECT COUNT(*) FROM t WHERE EXISTS (SELECT 1 FROM u WHERE u.w = t.s)", /* TEXT, NULLs on both sides */
             "SELECT COUNT(*) FROM t WHERE s IN (SELECT w FROM u)");
        SAME("SELECT id FROM t WHERE EXISTS (SELECT 1 FROM u WHERE u.tid = t.id AND EXISTS (SELECT 1 FROM z WHERE z.uid = u.id)) "
             "ORDER BY id", /* each level reads the one directly around it */
             "SELECT id FROM t WHERE id IN (SELECT tid FROM u WHERE id IN (SELECT uid FROM z)) ORDER BY id");
        EXPECT("SELECT id, (SELECT COUNT(*) FROM u WHERE u.v > t.g) AS c FROM t ORDER BY id", want);
        for (int jp = 0; jp < 2; jp++) { /* a join around it, under each plan */
            CHECK(run(jp ? "SET join_plan = index" : "SET join_plan = hash") == 0);
            SAME("SELECT t.id, z.id FROM t JOIN z ON z.uid = t.id WHERE EXISTS (SELECT 1 FROM u WHERE u.tid = z.uid AND u.v > 0) "
                 "ORDER BY t.id, z.id",
                 "SELECT t.id, z.id FROM t JOIN z ON z.uid = t.id WHERE z.uid IN (SELECT tid FROM u WHERE v > 0) ORDER BY t.id, z.id");
            SAME("SELECT t.id, (SELECT MIN(v) FROM u WHERE u.tid = z.uid) AS m FROM t LEFT JOIN z ON z.uid = t.id ORDER BY t.id, m",
                 "SELECT t.id, (SELECT MIN(v) FROM u WHERE u.tid = t.id AND z.uid IS NOT NULL) AS m FROM t LEFT JOIN z ON z.uid = t.id "
                 "ORDER BY t.id, m"); /* two columns around it: a NULL-extended row's z.uid is NULL */
        }
        CHECK(run("SET join_plan = auto") == 0);
        /* ORDER BY's keys computed per row too, a TEXT one kept past its row */
        SAME("SELECT id FROM t ORDER BY (SELECT MAX(v) FROM u WHERE u.tid = t.id), id",
             "SELECT t.id FROM t LEFT JOIN u ON u.tid = t.id GROUP BY t.id ORDER BY MAX(u.v), t.id");
        SAME("SELECT id, (SELECT MIN(w) FROM u WHERE u.tid = t.id) AS m FROM t ORDER BY m DESC, id",
             "SELECT t.id, MIN(u.w) FROM t LEFT JOIN u ON u.tid = t.id GROUP BY t.id ORDER BY 2 DESC, t.id");
        /* a grouped statement's aggregate argument */
        SAME("SELECT g, SUM((SELECT MAX(v) FROM u WHERE u.tid = t.id)) FROM t GROUP BY g ORDER BY g",
             "SELECT g, SUM(m) FROM (SELECT t.id, t.g AS g, MAX(u.v) AS m FROM t LEFT JOIN u ON u.tid = t.id GROUP BY t.id, t.g) "
             "AS q GROUP BY g ORDER BY g");
        /* a row set around it: a CTE's and a derived table's rows (path_rset's values) */
        SAME("WITH q AS (SELECT id, s FROM t) SELECT id FROM q WHERE EXISTS (SELECT 1 FROM u WHERE u.tid = q.id AND u.w = q.s) "
             "ORDER BY id",
             "SELECT id FROM t WHERE EXISTS (SELECT 1 FROM u WHERE u.tid = t.id AND u.w = t.s) ORDER BY id");
        SAME("SELECT id FROM (SELECT id, g FROM t WHERE g IS NOT NULL) AS q WHERE g < (SELECT COUNT(*) FROM u WHERE u.tid = q.id) "
             "ORDER BY id",
             "SELECT id FROM t WHERE g IS NOT NULL AND g < (SELECT COUNT(*) FROM u WHERE u.tid = t.id) ORDER BY id");
        /* RIGHT and FULL joins around it, its outer column on a NULL-extended side (ON's t.g = 2 leaves most unmatched) */
        SAME("SELECT t.id, z.id FROM t RIGHT JOIN z ON z.uid = t.id AND t.g = 2 WHERE NOT EXISTS (SELECT 1 FROM u WHERE u.tid = t.id) "
             "ORDER BY z.id",
             "SELECT t.id, z.id FROM t RIGHT JOIN z ON z.uid = t.id AND t.g = 2 "
             "WHERE t.id IS NULL OR t.id NOT IN (SELECT tid FROM u WHERE tid IS NOT NULL) ORDER BY z.id");
        SAME("SELECT t.id, z.id FROM t FULL JOIN z ON z.uid = t.id AND t.g = 2 WHERE EXISTS (SELECT 1 FROM u WHERE u.tid = z.uid) "
             "ORDER BY t.id, z.id",
             "SELECT t.id, z.id FROM t FULL JOIN z ON z.uid = t.id AND t.g = 2 WHERE z.uid IN (SELECT tid FROM u) ORDER BY t.id, z.id");
        SAME("SELECT COUNT(*), SUM((SELECT MAX(v) FROM u WHERE u.tid = t.id)) FROM t", /* inside an aggregate's argument */
             "SELECT COUNT(*), SUM(m) FROM (SELECT t.id, MAX(u.v) AS m FROM t LEFT JOIN u ON u.tid = t.id GROUP BY t.id) AS q");
    }
    CHECK(run("SET cross_check = off") == 0);
    /* writes: decided over every row before any is written (select_vids), each as its uncorrelated twin */
    CHECK(run("BEGIN") == 0 && run("UPDATE t SET k = FALSE WHERE EXISTS (SELECT 1 FROM u WHERE u.tid = t.id AND u.v > 20)") == 0);
    csv_to("SELECT id FROM t WHERE NOT k ORDER BY id", g_out2, sizeof g_out2);
    char first[1 << 12];
    snprintf(first, sizeof first, "%s", g_out2);
    CHECK(run("ROLLBACK") == 0 && run("BEGIN") == 0);
    CHECK(run("UPDATE t SET k = FALSE WHERE id IN (SELECT tid FROM u WHERE v > 20)") == 0);
    csv_to("SELECT id FROM t WHERE NOT k ORDER BY id", g_out2, sizeof g_out2);
    CHECK(!strcmp(first, g_out2));
    CHECK(run("ROLLBACK") == 0 && run("BEGIN") == 0);
    CHECK(run("DELETE FROM u WHERE NOT EXISTS (SELECT 1 FROM t WHERE t.id = u.tid)") == 0);
    EXPECT("SELECT COUNT(*) FROM u WHERE tid IS NULL", "count\n0\n");
    CHECK(run("ROLLBACK") == 0);
    /* the transaction's own writes are what a correlated run reads */
    CHECK(run("BEGIN") == 0 && run("INSERT INTO u VALUES (100000, 299, 1, 'q')") == 0);
    EXPECT("SELECT id FROM t WHERE id > 296 AND EXISTS (SELECT 1 FROM u WHERE u.tid = t.id AND u.w = 'q')", "id\n299\n");
    CHECK(run("ROLLBACK") == 0);
    /* the memo: one run per distinct tuple of the values read (g: 1, 2 or NULL), so 3 x 300 rows past the outer 300 fit a
     * limit of 2,000; one per row (id: 300 values) does not */
    CHECK(run("SET statement_row_limit = 2000") == 0);
    int nong = 0; /* t rows whose g is not NULL: u holds tids 5 and 6 */
    for (int i = 1; i <= N; i++) nong += i % 9 == 0 || i % 7 != 0;
    char cw[32];
    snprintf(cw, sizeof cw, "count\n%d\n", nong);
    EXPECT("SELECT COUNT(*) FROM t WHERE EXISTS (SELECT 1 FROM u WHERE u.tid = t.g + 4)", cw);
    CHECK(g_s.corr_runs == 3 && g_s.corr_hits == N - 3); /* one run each for g 1, 2 and NULL; the rest kept */
    EXPECT("SELECT COUNT(*) FROM t WHERE EXISTS (SELECT 1 FROM u WHERE u.tid = t.id + 4)", "ERR statement row limit");
    CHECK(run("SET statement_row_limit = 0") == 0);
    /* inner op outer is a plain predicate on each run (corr_pred), as a literal would be: a run tests only its matches
     * (the rows past its predicates, on any path), the primary key's one row; as residuals the 300 runs would test
     * 90,000 rows. The path a run takes is the planner's, as for a literal (u.tid's index once there is one) */
    int nin = 0;
    for (int X = 1; X <= N; X++) {
        bool f = false;
        for (int j = 1; j <= N; j++) f |= tid[j] == X;
        nin += f;
    }
    char cin[32];
    snprintf(cin, sizeof cin, "count\n%d\n", nin);
    CHECK(run("SET statement_row_limit = 1000") == 0);
    EXPECT("SELECT COUNT(*) FROM t WHERE EXISTS (SELECT 1 FROM u WHERE u.id = t.id)", "count\n300\n");
    CHECK(g_s.corr_runs == N && g_s.corr_hits == 0 && g_s.rows_tested == 2 * N); /* a run per row, a row each */
    for (int ix = 0; ix < 2; ix++) { /* a scan's predicate, then u.tid's index */
        if (ix) CHECK(run("CREATE INDEX u_tid ON u (tid)") == 0);
        EXPECT("SELECT COUNT(*) FROM t WHERE EXISTS (SELECT 1 FROM u WHERE u.tid = t.id)", cin);
        CHECK(g_s.corr_runs == N && g_s.rows_tested < 1000);
        EXPECT("SELECT COUNT(*) FROM t WHERE EXISTS (SELECT 1 FROM u WHERE t.id = u.tid)", cin); /* flipped */
    }
    CHECK(run("SET statement_row_limit = 0") == 0);
    EXPECT("SELECT COUNT(*) FROM t WHERE EXISTS (SELECT 1 FROM u WHERE t.g > u.v)", cw); /* v reaches -10: every g */
    /* a correlated IN keeps a set per tuple, charged to the statement: 300 sets of ~270 values past 1 MiB */
    CHECK(run("SET statement_memory = 1048576") == 0);
    EXPECT("SELECT COUNT(*) FROM t WHERE id IN (SELECT tid FROM u WHERE u.id <> t.id)", "ERR statement memory");
    CHECK(run("SET statement_memory = 0") == 0);
    SAME("SELECT COUNT(*) FROM t WHERE id IN (SELECT tid FROM u WHERE u.id <> t.id)",
         "SELECT COUNT(DISTINCT t.id) FROM t JOIN u ON u.tid = t.id AND u.id <> t.id");
    /* errors are decided when the statement binds, before any row: no row needs to reach the subquery */
    CHECK(run("CREATE TABLE e (id INT64 PRIMARY KEY, g INT64)") == 0);
    EXPECT("SELECT id FROM e WHERE EXISTS (SELECT 1 FROM u WHERE u.tid = e.nosuch)", "ERR no column nosuch in table e");
    EXPECT("SELECT id FROM e WHERE EXISTS (SELECT 1 FROM u WHERE u.w = e.g)", "ERR a comparison of TEXT with INT64");
    EXPECT("SELECT id FROM e WHERE e.g IN (SELECT w FROM u WHERE u.tid = e.id)", "ERR IN compares INT64 with TEXT");
    EXPECT("SELECT id FROM t WHERE id = (SELECT tid FROM u WHERE u.v = t.g)", "ERR returned more than one row"); /* data's */
    /* EXPLAIN: binds the correlated subquery (its names), runs nothing, commits and locks nothing */
    uint8_t t0[32], t1[32];
    uint64_t seq = db->seq;
    CHECK(imdb_view_token(db, t0, &g_e) == 0);
    CHECK(strstr(csv("EXPLAIN DELETE FROM t WHERE EXISTS (SELECT 1 FROM u WHERE u.tid = t.id)"), "a correlated one") != NULL);
    CHECK(g_s.rows_tested == 0 && db->seq == seq && imdb_view_token(db, t1, &g_e) == 0 && !memcmp(t0, t1, sizeof t0));
    /* refused, each with its reason */
    EXPECT("UPDATE t SET g = (SELECT MAX(v) FROM u WHERE u.tid = t.id)", "ERR in UPDATE's SET");
    EXPECT("SELECT g, (SELECT MAX(v) FROM u WHERE u.tid = t.g) FROM t GROUP BY g", "ERR with GROUP BY or an aggregate");
    EXPECT("SELECT COUNT(*), (SELECT MAX(v) FROM u WHERE u.tid = t.id) FROM t", "ERR with GROUP BY or an aggregate");
    EXPECT("SELECT g, COUNT(*) FROM t GROUP BY g HAVING EXISTS (SELECT 1 FROM u WHERE u.tid = t.g)", "ERR with GROUP BY");
    EXPECT("SELECT id FROM t WHERE EXISTS (SELECT 1 FROM (SELECT tid FROM u WHERE u.tid = t.id) AS q)", "ERR further out");
    EXPECT("SELECT id FROM t, (SELECT tid FROM u WHERE u.tid = t.id) AS q", "ERR LATERAL is a later step");
    EXPECT("SELECT id FROM t WHERE EXISTS (SELECT t.g FROM u)", "ERR a bare item's or an aggregate's column");
    SAME("SELECT t.id FROM t JOIN z ON z.uid = t.id WHERE EXISTS (SELECT 1 FROM u WHERE u.tid = uid) ORDER BY t.id", /* z's, unqualified */
         "SELECT t.id FROM t JOIN z ON z.uid = t.id WHERE EXISTS (SELECT 1 FROM u WHERE u.tid = z.uid) ORDER BY t.id");
    done(db);
}

const test_case rset_tests[] = {
    {"rset_differential", t_rset_differential},
    {"rset_forms", t_rset_forms},
    {"rset_view", t_rset_view},
    {"rset_limits", t_rset_limits},
    {"rset_in_model", t_rset_in_model},
    {"rset_subq_forms", t_rset_subq_forms},
    {"rset_explain", t_rset_explain},
    {"rset_corr", t_rset_corr},
};
const size_t rset_ntests = sizeof rset_tests / sizeof *rset_tests;
