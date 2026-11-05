/* Regressions from the external review of the 2026-11-05 archive (docs/imagedb-p2-feedback-2026-11-05.md), and the
 * siblings found integrating it (docs/review-2026-11-06.md): a qualified name's local alias hides the outer relation as
 * a whole (C2); a moving window frame's inner loop is cancellable (C3). The typed NULL through EXECUTE (C1) joins this
 * group with P2 S9. */
#include <stdio.h>

#include "../../src/db.h"
#include "../../src/sql.h"
#include "test.h"

static int run(imdb_session *s, const char *sql, const imdb_value *p, uint32_t np, imdb_result *r)
{
    imdb_err e = {0};
    return imdb_exec_one(s, sql, strlen(sql), p, np, r, &e);
}

static void expect(imdb_session *s, const char *sql, bool ok)
{
    imdb_result r;
    int rc = run(s, sql, NULL, 0, &r);
    if ((rc == IMDB_OK) != ok) test_fail(__FILE__, __LINE__, sql);
    if (rc == IMDB_OK) imdb_result_free(&r);
}

static imdb_db *fresh(imdb_session *s)
{
    const char *dir = test_tmpdir();
    imdb_err e = {0};
    imdb_db *db = NULL;
    imdb_open_opts o = {.sync = 0};
    if (imdb_init(dir, false, NULL, &e) || imdb_open(dir, &o, &db, &e)) return NULL;
    imdb_session_init(s, db);
    return db;
}

static void t_scope(void)
{
    imdb_session s;
    imdb_db *db = fresh(&s);
    CHECK(db);
    if (!db) return;
    expect(&s, "CREATE TABLE t(id INT64 PRIMARY KEY, a INT64)", true);
    expect(&s, "CREATE TABLE u(id INT64 PRIMARY KEY, x INT64)", true);
    expect(&s, "INSERT INTO t VALUES(1,22)", true);
    expect(&s, "INSERT INTO u VALUES(1,22)", true);
    /* PostgreSQL-style qualified lookup: a local range variable shadows the entire outer
     * range variable, even when its column is absent. SQLite 3.46.1 permits fallback instead;
     * this test makes the chosen stricter dialect rule explicit.
     * Exercise a literal predicate, an expression, the indexed correlation fast path and a joined scope. */
    static const char *const bad[] = {
        "SELECT id FROM t WHERE EXISTS(SELECT 1 FROM u AS t WHERE t.a = 22)",
        "SELECT id FROM t WHERE EXISTS(SELECT 1 FROM u AS t WHERE t.a + 0 = 22)",
        "SELECT id FROM t WHERE EXISTS(SELECT 1 FROM u AS t WHERE t.id = t.a)",
        "SELECT id FROM t WHERE EXISTS(SELECT 1 FROM u AS t JOIN u AS v ON t.id = v.id WHERE t.a + 0 = 22)",
        "SELECT id FROM t WHERE EXISTS(SELECT 1 FROM (SELECT id FROM u) AS t WHERE t.a = 22)",
        "EXPLAIN SELECT id FROM t WHERE EXISTS(SELECT 1 FROM u AS t WHERE t.a = 22)"
    };
    for (unsigned pass = 0; pass < 3; pass++) {
        for (size_t i = 0; i < sizeof bad / sizeof *bad; i++) expect(&s, bad[i], false);
        /* Unqualified outer columns and differently named qualifiers still correlate. */
        expect(&s, "SELECT id FROM t WHERE EXISTS(SELECT 1 FROM u WHERE x = t.a)", true);
        expect(&s, "SELECT id FROM t WHERE EXISTS(SELECT 1 FROM u WHERE x = a)", true);
        expect(&s, pass == 0 ? "CHECKPOINT" : "DELETE FROM t", true);
    }
    imdb_session_close(&s);
    imdb_close(db);
}

/* C3: a suffix frame's MIN visits every following value for each row: the review measured 610 ms past a 50 ms
 * statement_timeout before the frame loop charged its work to the deadline, 51 ms after. 1,000 rows here: the scan's and
 * the rows' own ticks stay under one check (4,096), so only the frame loop's can stop it (with 3,000 they passed one
 * anyway, and the test passed without the fix), while each visit is a new minimum whose 4 KiB the accumulator copies:
 * about half a second uncancelled.
 * The values' leading bytes differ, so a comparison is cheap: the time is the visits' and the copies'. A read: no commit */
static void t_window_cancel(void)
{
    imdb_session s;
    imdb_db *db = fresh(&s);
    CHECK(db);
    if (!db) return;
    expect(&s, "CREATE TABLE w(id INT64 PRIMARY KEY, s TEXT NOT NULL)", true);
    imdb_table *t = imdb_table_by_name(db, "w");
    static uint8_t text[4096];
    memset(text, 'x', sizeof text);
    imdb_err e = {0};
    int rc = imdb_begin(db, &e);
    for (int i = 0; !rc && i < 1000; i++) {
        char head[16];
        snprintf(head, sizeof head, "%08d", 1000 - i); /* the order the frames visit: each a new minimum */
        memcpy(text, head, 8);
        imdb_value v[] = {{.type = IMDB_T_INT64, .i = i}, {.type = IMDB_T_TEXT, .s = text, .len = sizeof text}};
        rc = imdb_insert(db, t, v, &e);
    }
    if (!rc) rc = imdb_commit(db, &e);
    CHECK(rc == IMDB_OK);
    uint64_t seq = db->seq;
    expect(&s, "SET statement_timeout = 50", true);
    imdb_result r;
    rc = run(&s, "SELECT MIN(s) OVER (ORDER BY id ROWS BETWEEN CURRENT ROW AND UNBOUNDED FOLLOWING) FROM w WHERE id < 1000",
             NULL, 0, &r);
    if (rc == IMDB_OK) imdb_result_free(&r);
    CHECK(rc == IMDB_ERR_CANCELLED);
    expect(&s, "SET statement_timeout = 0", true);
    CHECK(db->seq == seq);
    /* without the deadline it answers: every row's minimum is the last row's value */
    rc = run(&s, "SELECT COUNT(*) FROM (SELECT MIN(s) OVER (ORDER BY id ROWS BETWEEN CURRENT ROW AND UNBOUNDED FOLLOWING) AS m "
                 "FROM w WHERE id >= 990) AS q WHERE SUBSTR(m, 1, 8) = '00000001'",
             NULL, 0, &r);
    CHECK(rc == IMDB_OK && r.nrows == 1 && r.cells[0].v.i == 10);
    if (rc == IMDB_OK) imdb_result_free(&r);
    imdb_session_close(&s);
    imdb_close(db);
}

const test_case review1105_tests[] = {
    {"review1105_scope", t_scope},
    {"review1105_window_cancel", t_window_cancel},
};
const size_t review1105_ntests = sizeof review1105_tests / sizeof *review1105_tests;
