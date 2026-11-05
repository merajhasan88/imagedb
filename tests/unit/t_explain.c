/* P1 Q1 (docs/plan-p1.md): EXPLAIN SELECT / UPDATE / DELETE, the planner's plan stopped before any path runs. A
 * differential over every path and join plan: what EXPLAIN says is the path the statement then reports when it runs
 * (cross_check off), EXPLAIN reading no row and moving nothing; errors as the statement's own; the rest refused. */
#include <stdlib.h>

#include "../../src/db.h"
#include "../../src/sql.h"
#include "thelp.h"

static imdb_session g_s, g_b;

static int run(imdb_session *s, const char *sql)
{
    imdb_result r;
    imdb_err_clear(&g_e);
    int rc = imdb_exec_one(s, sql, strlen(sql), NULL, 0, &r, &g_e);
    if (!rc) imdb_result_free(&r);
    return rc;
}

/* the statement's reported path (a SELECT's, a join's, a write's), or "" when it fails */
static int ran_path(imdb_session *s, const char *sql, char *out, size_t cap)
{
    imdb_result r;
    imdb_err_clear(&g_e);
    out[0] = 0;
    int rc = imdb_exec_one(s, sql, strlen(sql), NULL, 0, &r, &g_e);
    if (rc) return rc;
    snprintf(out, cap, "%s", r.path);
    imdb_result_free(&r);
    return 0;
}

static bool cell_is(const imdb_value *v, const char *s)
{
    size_t n = strlen(s);
    return v->len == n && memcmp(v->s, s, n) == 0;
}

/* EXPLAIN sql: its row `item`'s detail into out; the result's shape checked (two TEXT columns, item and detail, each
 * item once, output last); no row tested, the view token unchanged */
/* a check that does not return (CHECK returns from the function: this one returns a value) */
#define NOTE(c)                                                                                                  \
    do {                                                                                                         \
        if (!(c)) test_fail(__FILE__, __LINE__, #c);                                                            \
    } while (0)

static int explain(imdb_session *s, const char *sql, const char *item, char *out, size_t cap)
{
    char q[1200];
    snprintf(q, sizeof q, "EXPLAIN %s", sql);
    uint8_t t0[32], t1[32];
    if (imdb_view_token(s->db, t0, &g_e)) return g_e.code;
    imdb_result r;
    imdb_err_clear(&g_e);
    out[0] = 0;
    int rc = imdb_exec_one(s, q, strlen(q), NULL, 0, &r, &g_e);
    if (rc) return rc;
    bool shape = r.ncols == 2 && r.nrows >= 4 && !strcmp(r.names[0], "item") && !strcmp(r.names[1], "detail");
    for (uint64_t i = 0; shape && i < r.nrows; i++) {
        const imdb_value *it = &r.cells[2 * i].v, *d = &r.cells[2 * i + 1].v;
        shape = it->type == IMDB_T_TEXT && d->type == IMDB_T_TEXT && it->len && d->len;
        for (uint64_t j = 0; shape && j < i; j++)
            shape = it->len != r.cells[2 * j].v.len || memcmp(it->s, r.cells[2 * j].v.s, it->len) != 0;
        if (cell_is(it, item) && d->len < cap) {
            memcpy(out, d->s, d->len);
            out[d->len] = 0;
        }
    }
    shape = shape && cell_is(&r.cells[2 * (r.nrows - 1)].v, "output");
    imdb_result_free(&r);
    NOTE(shape);
    NOTE(s->rows_tested == 0);
    NOTE(!imdb_view_token(s->db, t1, &g_e) && !memcmp(t0, t1, sizeof t0));
    return 0;
}

/* EXPLAIN sql's path (or a join's plan) is the one sql reports when it runs */
static void same_path(imdb_session *s, const char *sql)
{
    char want[800], got[100];
    bool join = strstr(sql, " JOIN ") != NULL;
    int rx = explain(s, sql, join ? "plan" : "path", want, sizeof want);
    int rr = ran_path(s, sql, got, sizeof got);
    if (rx || rr || strcmp(want, got) != 0) {
        char m[1400];
        snprintf(m, sizeof m, "%s: EXPLAIN says '%s' (rc %d), the run '%s' (rc %d: %s)", sql, want, rx, got, rr, g_e.msg);
        test_fail(__FILE__, __LINE__, m);
    }
}

static bool explained_as(imdb_session *s, const char *sql, const char *item, const char *needle)
{
    char d[800];
    return explain(s, sql, item, d, sizeof d) == 0 && strstr(d, needle) != NULL;
}

enum { N = 20000 };

static imdb_db *loaded(uint64_t *before_cp)
{
    const char *dir = test_tmpdir();
    imdb_err e = {0};
    if (imdb_init(dir, false, NULL, &e)) return NULL;
    imdb_open_opts o = {.sync = 0};
    imdb_db *db = NULL;
    if (imdb_open(dir, &o, &db, &e)) return NULL;
    imdb_session_init(&g_s, db);
    imdb_session_init(&g_b, db);
    if (run(&g_s, "CREATE TABLE t (id INT64 PRIMARY KEY, g INT64, a INT64, s TEXT, who BIGINT SUBJECT)") ||
        run(&g_s, "CREATE TABLE u (id INT64 PRIMARY KEY, tid INT64, v INT64)"))
        return db;
    imdb_buf b;
    imdb_buf_init(&b);
    for (int base = 0; base < N && !g_e.code; base += 5000) {
        b.len = 0;
        imdb_buf_put_str(&b, "INSERT INTO t VALUES ");
        for (int i = base + 1; i <= base + 5000; i++)
            imdb_buf_printf(&b, "%s(%d, %d, %d, 'r%d', %d)", i > base + 1 ? ", " : "", i, i % 7, i % 1000, i % 13, i % 50);
        if (imdb_buf_check(&b, &g_e)) break;
        imdb_result r;
        if (!imdb_exec_one(&g_s, (const char *)b.p, b.len, NULL, 0, &r, &g_e)) imdb_result_free(&r);
    }
    b.len = 0;
    imdb_buf_put_str(&b, "INSERT INTO u VALUES ");
    for (int i = 1; i <= 60; i++) imdb_buf_printf(&b, "%s(%d, %d, %d)", i > 1 ? ", " : "", i, i * 300, i % 5);
    if (!g_e.code && !imdb_buf_check(&b, &g_e)) {
        imdb_result r;
        if (!imdb_exec_one(&g_s, (const char *)b.p, b.len, NULL, 0, &r, &g_e)) imdb_result_free(&r);
    }
    imdb_buf_free(&b);
    if (!g_e.code) run(&g_s, "CREATE INDEX t_ga ON t (g, a)");
    if (!g_e.code) run(&g_s, "CREATE INDEX t_a ON t (a)");
    if (!g_e.code) run(&g_s, "CREATE INDEX u_tid ON u (tid)");
    *before_cp = db->seq;
    if (!g_e.code) run(&g_s, "CHECKPOINT");
    if (!g_e.code) run(&g_s, "UPDATE t SET a = a + 1 WHERE id <= 40"); /* versions in memory past the segments */
    if (!g_e.code) run(&g_s, "INSERT INTO t VALUES (20001, 1, 5, 'new', 7)");
    return db;
}

static void done(imdb_db *db)
{
    imdb_session_close(&g_b);
    imdb_session_close(&g_s);
    imdb_close(db);
}

/* every single-table path, the price in both directions, forced paths, AS OF, an empty range */
static void t_explain_single(void)
{
    uint64_t before_cp = 0;
    imdb_db *db = loaded(&before_cp);
    CHECK(db && !g_e.code);
    if (!db || g_e.code) return;
    static const char *const q[] = {
        "SELECT * FROM t WHERE id = 77",
        "SELECT COUNT(*) FROM t WHERE who = 7",
        "SELECT s FROM t WHERE g = 3 AND a = 5",
        "SELECT COUNT(*) FROM t WHERE g = 3",              /* many candidates: the scan's price is lower */
        "SELECT COUNT(*) FROM t WHERE g = 3 AND a = 5",    /* few: under the floor, the index kept */
        "SELECT SUM(a) FROM t WHERE a >= 990",
        "SELECT SUM(a) FROM t WHERE a >= 100",
        "SELECT * FROM t WHERE s = 'r3'",
        "SELECT g, COUNT(*) FROM t GROUP BY g",
        "SELECT * FROM t WHERE a BETWEEN 5 AND 3",         /* an empty range: nothing read */
        "SELECT id FROM t WHERE g = 2 ORDER BY a DESC LIMIT 5 OFFSET 2",
        "SELECT DISTINCT g FROM t WHERE a < 10",
        "SELECT id, a * 2 FROM t WHERE a + 1 > 998 AND g = 4",
        "SELECT COUNT(*) FROM t WHERE g = 1 HAVING COUNT(*) > 1",
    };
    for (size_t i = 0; i < sizeof q / sizeof *q; i++) same_path(&g_s, q[i]);
    /* the price, read back: the scan below the index for many candidates, the index kept under the floor */
    CHECK(explained_as(&g_s, q[3], "path", "scan") && explained_as(&g_s, q[3], "why", "the price: scan"));
    CHECK(explained_as(&g_s, q[4], "path", "index(ordered)") /* a: nullable, second: not in the key */ && explained_as(&g_s, q[4], "why", "the index is kept"));
    CHECK(explained_as(&g_s, q[0], "index", "the primary key (id)") && explained_as(&g_s, q[1], "index", "subject"));
    CHECK(explained_as(&g_s, q[2], "index", "t_ga (g, a): equality on g, a"));
    CHECK(explained_as(&g_s, q[9], "why", "an empty range"));
    CHECK(explained_as(&g_s, q[7], "segments", " read (") && explained_as(&g_s, q[7], "conditions", "1: 0 by the index"));
    CHECK(explained_as(&g_s, q[10], "output", "ordered by 1 key; OFFSET 2; LIMIT 5"));
    /* forced paths */
    static const char *const forced[] = {"scan", "store", "ordered", "index"};
    for (size_t f = 0; f < sizeof forced / sizeof *forced; f++) {
        char set[64];
        snprintf(set, sizeof set, "SET access_path = %s", forced[f]);
        CHECK(run(&g_s, set) == 0);
        for (size_t i = 0; i < sizeof q / sizeof *q; i++) same_path(&g_s, q[i]);
        CHECK(explained_as(&g_s, q[0], "why", set));
    }
    CHECK(run(&g_s, "SET access_path = auto") == 0);
    /* AS OF before the checkpoint: below this copy's memory floor or not, by the mode; the path the run's either way */
    char asof[160];
    snprintf(asof, sizeof asof, "SELECT COUNT(*) FROM t AS OF %llu WHERE g = 2", (unsigned long long)before_cp);
    same_path(&g_s, asof);
    CHECK(explained_as(&g_s, asof, "snapshot", "(AS OF)"));
    if (db->mem_floor > before_cp) CHECK(explained_as(&g_s, asof, "why", "below this copy's memory floor"));
    done(db);
}

/* joins: plan C each way, the hash join, LEFT, the forced plans and paths; the prices printed */
static void t_explain_join(void)
{
    uint64_t before_cp = 0;
    imdb_db *db = loaded(&before_cp);
    CHECK(db && !g_e.code);
    if (!db || g_e.code) return;
    static const char *const q[] = {
        "SELECT t.id, u.v FROM t JOIN u ON t.id = u.tid",
        "SELECT u.v, t.a FROM u JOIN t ON u.tid = t.id",
        "SELECT COUNT(*) FROM t JOIN u ON t.id = u.tid WHERE t.g = 1",
        "SELECT t.id, u.v FROM t LEFT JOIN u ON t.id = u.tid WHERE t.a < 3",
        "SELECT t.g, COUNT(*) FROM t JOIN u ON t.a = u.v GROUP BY t.g",
        "SELECT t.id FROM t JOIN u ON t.id = u.tid WHERE u.v = 2 ORDER BY t.id DESC LIMIT 3",
    };
    static const char *const sets[] = {"SET join_plan = auto", "SET join_plan = hash", "SET join_plan = index",
                                       "SET access_path = scan", "SET access_path = auto"};
    for (size_t k = 0; k < sizeof sets / sizeof *sets; k++) {
        CHECK(run(&g_s, sets[k]) == 0);
        for (size_t i = 0; i < sizeof q / sizeof *q; i++) same_path(&g_s, q[i]);
    }
    CHECK(run(&g_s, "SET join_plan = auto") == 0);
    CHECK(explained_as(&g_s, q[0], "plan", "join(index") && explained_as(&g_s, q[0], "price", "hash join "));
    CHECK(explained_as(&g_s, q[0], "side 1", "t: index(primary key), probed"));
    CHECK(explained_as(&g_s, q[3], "join", "t LEFT JOIN u, on t.id = u.tid"));
    CHECK(run(&g_s, "SET join_plan = hash") == 0);
    CHECK(explained_as(&g_s, q[0], "why", "SET join_plan = hash") && explained_as(&g_s, q[0], "side 2", "built into the hash"));
    CHECK(run(&g_s, "SET join_plan = auto") == 0);
    done(db);
}

/* UPDATE and DELETE: the path that finds the rows to change, as the write reports it; nothing written by EXPLAIN, in a
 * transaction or not, and against an autocommitted write; a FOR UPDATE's locks not taken */
static void t_explain_dml(void)
{
    uint64_t before_cp = 0;
    imdb_db *db = loaded(&before_cp);
    CHECK(db && !g_e.code);
    if (!db || g_e.code) return;
    static const char *const q[] = {
        "UPDATE t SET a = a + 1 WHERE id = 9",
        "DELETE FROM t WHERE g = 6 AND a = 6",
        "UPDATE t SET s = 'q' WHERE s = 'r1'",
        "DELETE FROM u WHERE tid >= 600",
        "UPDATE t SET a = 0 WHERE who = 3 AND g = 3",
    };
    uint64_t seq = db->seq;
    char d[800];
    for (size_t i = 0; i < sizeof q / sizeof *q; i++) CHECK(explain(&g_s, q[i], "path", d, sizeof d) == 0 && d[0]);
    CHECK(db->seq == seq); /* no autocommit: nothing was written */
    CHECK(run(&g_s, "BEGIN") == 0);
    for (size_t i = 0; i < sizeof q / sizeof *q; i++) same_path(&g_s, q[i]);
    CHECK(explained_as(&g_s, q[0], "snapshot", "(the transaction's), and this transaction's own writes"));
    CHECK(run(&g_s, "ROLLBACK") == 0 && db->seq == seq);
    /* EXPLAIN ... FOR UPDATE takes no lock: SHOW TRANSACTIONS' locks stay 0 until the statement itself runs */
    CHECK(run(&g_s, "BEGIN") == 0);
    CHECK(explain(&g_s, "SELECT * FROM t WHERE id = 3 FOR UPDATE", "path", d, sizeof d) == 0);
    imdb_result r;
    int64_t locks[2] = {-1, -1};
    for (int pass = 0; pass < 2; pass++) {
        if (pass) CHECK(run(&g_s, "SELECT * FROM t WHERE id = 3 FOR UPDATE") == 0);
        imdb_err_clear(&g_e);
        if (imdb_exec_one(&g_s, "SHOW TRANSACTIONS", 17, NULL, 0, &r, &g_e) == 0) {
            for (uint64_t i = 0; i < r.nrows; i++)
                if (r.cells[7 * i + 6].v.i == 1) locks[pass] = r.cells[7 * i + 5].v.i;
            imdb_result_free(&r);
        }
    }
    CHECK(locks[0] == 0 && locks[1] == 1);
    CHECK(run(&g_s, "ROLLBACK") == 0);
    /* outside a transaction too: the run autocommits (a commit of its own), EXPLAIN plans without one */
    same_path(&g_s, "UPDATE t SET a = a WHERE id = 20001");
    same_path(&g_s, "DELETE FROM t WHERE id = 20001");
    /* a write reports its path to the CLI too */
    imdb_err_clear(&g_e);
    CHECK(imdb_exec_one(&g_s, q[0], strlen(q[0]), NULL, 0, &r, &g_e) == 0);
    if (!g_e.code) {
        imdb_buf out;
        imdb_buf_init(&out);
        imdb_result_render(&r, false, &out);
        CHECK(!imdb_buf_check(&out, &g_e) && out.len && strstr((const char *)out.p, "UPDATE 1  [index(primary key)]"));
        imdb_buf_free(&out);
        imdb_result_free(&r);
    }
    done(db);
}

/* a statement that fails to plan fails the same way under EXPLAIN; EXPLAIN of anything else is refused */
static void t_explain_errors(void)
{
    uint64_t before_cp = 0;
    imdb_db *db = loaded(&before_cp);
    CHECK(db && !g_e.code);
    if (!db || g_e.code) return;
    static const char *const bad[] = {
        "SELECT nosuch FROM t",
        "SELECT * FROM nosuch",
        "SELECT g, COUNT(*) FROM t",
        "SELECT t.id FROM t JOIN u ON t.s = u.tid",
        "SELECT t.id FROM t JOIN u ON t.id = u.nosuch",
        "SELECT nosuch FROM t JOIN u ON t.id = u.tid",
        "UPDATE t SET id = 1 WHERE g = 1",
        "UPDATE t SET nosuch = 1",
        "DELETE FROM nosuch WHERE id = 1",
        "SELECT * FROM t WHERE nosuch = 1",
    };
    for (size_t i = 0; i < sizeof bad / sizeof *bad; i++) {
        char q[300], m1[sizeof g_e.msg];
        int r1 = run(&g_s, bad[i]);
        snprintf(m1, sizeof m1, "%s", g_e.msg);
        snprintf(q, sizeof q, "EXPLAIN %s", bad[i]);
        int r2 = run(&g_s, q);
        if (!r1 || r1 != r2 || strcmp(m1, g_e.msg) != 0) {
            char m[1200];
            snprintf(m, sizeof m, "%s: the statement rc %d (%s), EXPLAIN rc %d (%s)", bad[i], r1, m1, r2, g_e.msg);
            test_fail(__FILE__, __LINE__, m);
        }
    }
    static const char *const refused[] = {"EXPLAIN INSERT INTO t VALUES (99999, 1, 1, 'x', 1)",
                                          "EXPLAIN CREATE TABLE z (id INT64 PRIMARY KEY)", "EXPLAIN CHECKPOINT",
                                          "EXPLAIN SHOW TABLES"};
    uint64_t seq = db->seq;
    for (size_t i = 0; i < sizeof refused / sizeof *refused; i++)
        CHECK(run(&g_s, refused[i]) == IMDB_ERR_INVALID && strstr(g_e.msg, "EXPLAIN explains SELECT, UPDATE and DELETE"));
    CHECK(run(&g_s, "EXPLAIN") != 0 && run(&g_s, "EXPLAIN EXPLAIN SELECT * FROM t") != 0);
    CHECK(db->seq == seq && run(&g_s, "SELECT COUNT(*) FROM z") != 0);
    done(db);
}

const test_case explain_tests[] = {
    {"explain_single", t_explain_single},
    {"explain_join", t_explain_join},
    {"explain_dml", t_explain_dml},
    {"explain_errors", t_explain_errors},
};
const size_t explain_ntests = sizeof explain_tests / sizeof *explain_tests;
