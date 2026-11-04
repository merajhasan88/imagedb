/* Statement timeouts and cancellation (P0 resource limits, R1; docs/plan-p0.md): SET statement_timeout and
 * imdb_session_cancel stop a running statement at its next check (every few thousand rows its read paths, joins and
 * row loops pass) with IMDB_ERR_CANCELLED, and nothing it did stays: the view token is unchanged, a write is undone
 * by its statement savepoint, a transaction goes on. COMMIT and the physical statements run to their end. A timeout
 * depends on time, so these tests never assert where a statement stopped, only that it stopped and left nothing. */
#include <pthread.h>
#include <time.h>

#include "../../src/sql.h"
#include "thelp.h"

static imdb_session g_ss;

static int q(const char *sql, imdb_result *r)
{
    imdb_err_clear(&g_e);
    return imdb_exec_one(&g_ss, sql, strlen(sql), NULL, 0, r, &g_e);
}

static int run(const char *sql)
{
    imdb_result r;
    int rc = q(sql, &r);
    if (!rc) imdb_result_free(&r);
    return rc;
}

#define RUN(sql)                                                                \
    do {                                                                        \
        if (run(sql)) {                                                         \
            char m_[900];                                                       \
            snprintf(m_, sizeof m_, "%s -> %s", sql, g_e.msg);                  \
            test_fail(__FILE__, __LINE__, m_);                                  \
            return;                                                             \
        }                                                                       \
    } while (0)

/* the first cell of a one-row answer, as an integer */
static int64_t one_i64(const char *sql)
{
    imdb_result r;
    if (q(sql, &r)) return INT64_MIN;
    const imdb_cell *c = r.nrows == 1 ? &r.cells[0] : NULL; /* a SUM is a wide cell (128 bits) */
    int64_t v = !c || c->null ? INT64_MIN : c->wide ? (c->i128 >= INT64_MIN && c->i128 <= INT64_MAX ? (int64_t)c->i128 : INT64_MIN) : c->v.i;
    imdb_result_free(&r);
    return v;
}

static double now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec * 1e3 + (double)ts.tv_nsec / 1e6;
}

/* t: N rows (id, g = id % 7, a = id * 31 % 1000), an index on a; u: a row for every tenth id of t */
enum { N = 200000 };

/* a statement built in b, its result freed */
static int run_buf(const imdb_buf *b)
{
    imdb_result r;
    imdb_err_clear(&g_e);
    int rc = imdb_exec_one(&g_ss, (const char *)b->p, b->len, NULL, 0, &r, &g_e);
    if (!rc) imdb_result_free(&r);
    return rc;
}

static imdb_db *loaded(void)
{
    const char *dir = test_tmpdir();
    imdb_err e = {0};
    if (imdb_init(dir, false, NULL, &e)) return NULL;
    imdb_db *db = open_db(dir);
    if (!db) return NULL;
    imdb_session_init(&g_ss, db);
    if (run("CREATE TABLE t (id INT64 PRIMARY KEY, g INT64, a INT64)") ||
        run("CREATE TABLE u (id INT64 PRIMARY KEY, tid INT64, v INT64)"))
        return db;
    imdb_buf b;
    imdb_buf_init(&b);
    for (int base = 0; base < N; base += 10000) {
        b.len = 0;
        imdb_buf_put_str(&b, "INSERT INTO t VALUES ");
        for (int i = base + 1; i <= base + 10000; i++)
            imdb_buf_printf(&b, "%s(%d, %d, %d)", i > base + 1 ? ", " : "", i, i % 7, (int)((int64_t)i * 31 % 1000));
        if (imdb_buf_check(&b, &g_e) || run_buf(&b)) break;
    }
    for (int base = 0; base < N / 10 && !g_e.code; base += 10000) {
        b.len = 0;
        imdb_buf_put_str(&b, "INSERT INTO u VALUES ");
        for (int i = base + 1; i <= base + 10000; i++)
            imdb_buf_printf(&b, "%s(%d, %d, %d)", i > base + 1 ? ", " : "", i, i * 10, i % 13);
        if (imdb_buf_check(&b, &g_e) || run_buf(&b)) break;
    }
    imdb_buf_free(&b);
    if (!g_e.code) run("CREATE INDEX t_a ON t (a)");
    return db;
}

static void done(imdb_db *db)
{
    imdb_session_close(&g_ss);
    imdb_close(db);
}

/* sql must stop with IMDB_ERR_CANCELLED and its timeout's message */
#define TIMES_OUT(sql)                                                                                  \
    do {                                                                                                \
        int rc_ = run(sql);                                                                             \
        if (rc_ != IMDB_ERR_CANCELLED || !strstr(g_e.msg, "statement timeout")) {                       \
            char m_[700];                                                                               \
            snprintf(m_, sizeof m_, "%s -> rc %d (%s), want a timeout", sql, rc_, g_e.msg);            \
            test_fail(__FILE__, __LINE__, m_);                                                          \
            return;                                                                                     \
        }                                                                                               \
    } while (0)

/* every read path, in memory and in the lake: a 1 ms timeout stops the statement, 60 s does not; the state stays */
static void t_timeout_paths(void)
{
    imdb_db *db = loaded();
    CHECK(db && !g_e.code);
    if (!db || g_e.code) return;
    CHECK(!strcmp(imdb_err_name(IMDB_ERR_CANCELLED), "cancelled"));
    uint8_t tok0[32], tok1[32];
    static const char *const paths[] = {"auto", "scan", "store", "ordered"};
    char sql[200];
    for (int round = 0; round < 2; round++) {
        if (round) RUN("CHECKPOINT");
        CHECK_OK(imdb_view_token(db, tok0, &g_e)); /* a CHECKPOINT is a commit: the token moves with it */
        for (size_t p = 0; p < sizeof paths / sizeof *paths; p++) {
            snprintf(sql, sizeof sql, "SET access_path = %s", paths[p]);
            RUN(sql);
            RUN("SET statement_timeout = 1");
            TIMES_OUT("SELECT COUNT(*) FROM t WHERE a >= 0 AND a + 1 > 0");      /* a residual: every row tested */
            TIMES_OUT("SELECT id FROM t WHERE a >= 0 ORDER BY a * 2 DESC LIMIT 3"); /* keys for every row, a sort */
            TIMES_OUT("SELECT g, SUM(a + 1) FROM t WHERE a >= 0 GROUP BY g");
            RUN("SET statement_timeout = 60000");
            CHECK(one_i64("SELECT COUNT(*) FROM t WHERE a >= 0 AND a + 1 > 0") == N);
            RUN("SET statement_timeout = 0");
        }
        CHECK_OK(imdb_view_token(db, tok1, &g_e));
        CHECK(!memcmp(tok0, tok1, sizeof tok0));
    }
    RUN("SET access_path = auto");
    /* joins, under each plan: a hash join's pairs, an index join's probes */
    static const char *const plans[] = {"hash", "index"};
    for (size_t p = 0; p < sizeof plans / sizeof *plans; p++) {
        snprintf(sql, sizeof sql, "SET join_plan = %s", plans[p]);
        RUN(sql);
        RUN("SET statement_timeout = 1");
        TIMES_OUT("SELECT COUNT(*) FROM t JOIN u ON t.id = u.tid WHERE t.a + 1 > 0");
        TIMES_OUT("SELECT t.id, u.v FROM t LEFT JOIN u ON t.id = u.tid ORDER BY u.v DESC, t.a LIMIT 2");
        RUN("SET statement_timeout = 0");
    }
    RUN("SET join_plan = auto");
    CHECK_OK(imdb_view_token(db, tok1, &g_e)); /* no commit since the last round: nothing moved */
    CHECK(!memcmp(tok0, tok1, sizeof tok0));
    /* cross_check: the deadline may stop the second plan, after the first built its result. Which plan it stops is
     * the clock's (a timeout cannot be placed), so timeouts are swept from a quarter of the plain run's time to twice
     * it, and every run must answer rightly or time out: never a cross-check failure, both results freed (the
     * runner's heap check); some must time out */
    double t0 = now_ms();
    CHECK(one_i64("SELECT COUNT(*) FROM t WHERE a >= 0 AND a + 1 > 0") == N);
    double plain = now_ms() - t0;
    RUN("SET cross_check = on");
    int timed_out = 0;
    for (int i = 1; i <= 8; i++) {
        unsigned ms = (unsigned)(plain * i / 4);
        snprintf(sql, sizeof sql, "SET statement_timeout = %u", ms ? ms : 1);
        RUN(sql);
        for (int s = 0; s < 2; s++) {
            imdb_result r;
            int rc = q(s ? "SELECT id, a FROM t WHERE a >= 0 AND a + 1 > 0 ORDER BY a DESC, id LIMIT 3"
                         : "SELECT COUNT(*) FROM t WHERE a >= 0 AND a + 1 > 0", &r);
            if (rc) {
                CHECK(rc == IMDB_ERR_CANCELLED && strstr(g_e.msg, "statement timeout"));
                timed_out++;
                continue;
            }
            CHECK(r.nrows == (s ? 3u : 1u) && (s || r.cells[0].v.i == N || (r.cells[0].wide && r.cells[0].i128 == N)));
            imdb_result_free(&r);
        }
    }
    CHECK(timed_out > 0);
    RUN("SET statement_timeout = 0");
    RUN("SET cross_check = off");
    /* the settings' bounds */
    CHECK(run("SET statement_timeout = 86400001") == IMDB_ERR_INVALID);
    CHECK(run("SET statement_timeout = soon") == IMDB_ERR_INVALID);
    RUN("SET statement_timeout = 86400000");
    RUN("SET statement_timeout = 0");
    done(db);
}

/* a cancelled write leaves nothing: autocommit rolls back; inside a transaction the statement is undone and the
 * transaction goes on */
static void t_timeout_writes(void)
{
    imdb_db *db = loaded();
    CHECK(db && !g_e.code);
    if (!db || g_e.code) return;
    uint8_t tok0[32], tok1[32];
    CHECK_OK(imdb_view_token(db, tok0, &g_e));
    uint64_t seq = db->seq;
    int64_t sum = one_i64("SELECT SUM(a) FROM t");
    RUN("SET statement_timeout = 1");
    TIMES_OUT("UPDATE t SET a = a + 1 WHERE a >= 0");
    TIMES_OUT("DELETE FROM t WHERE a + 1 > 0");
    CHECK(db->seq == seq);
    CHECK_OK(imdb_view_token(db, tok1, &g_e));
    CHECK(!memcmp(tok0, tok1, sizeof tok0));
    RUN("SET statement_timeout = 0");
    CHECK(one_i64("SELECT SUM(a) FROM t") == sum);
    /* inside a transaction */
    RUN("BEGIN");
    RUN("UPDATE t SET a = 5000 WHERE id = 1");
    RUN("SET statement_timeout = 1");
    TIMES_OUT("UPDATE t SET a = a + 1 WHERE a >= 0");
    RUN("SET statement_timeout = 0");
    CHECK(g_ss.txn.open);
    CHECK(one_i64("SELECT a FROM t WHERE id = 1") == 5000); /* the statement before it stays */
    CHECK(one_i64("SELECT a FROM t WHERE id = 2") == 62);   /* the cancelled one left nothing */
    RUN("UPDATE t SET a = 5001 WHERE id = 2");             /* the transaction goes on */
    RUN("COMMIT");
    CHECK(db->seq == seq + 1);
    CHECK(one_i64("SELECT SUM(a) FROM t") == sum - 31 + 5000 - 62 + 5001);
    /* COMMIT, VERIFY and CHECKPOINT run to their end, whatever the timeout */
    RUN("BEGIN");
    RUN("UPDATE t SET a = 1 WHERE g = 3");
    RUN("SET statement_timeout = 1");
    RUN("COMMIT");
    CHECK(db->seq == seq + 2);
    RUN("CHECKPOINT");
    RUN("VERIFY");
    RUN("SET statement_timeout = 0");
    done(db);
}

/* a cancel in the write phase. An UPDATE of 20,000 rows reads them in a few milliseconds and writes them in many
 * more, so timeouts swept from an eighth of that time to twice it land in its writes on any machine (a few in the read
 * phase, the longest not at all). Where one lands is the clock's; the test asserts all or nothing: each run commits
 * the whole UPDATE (SUM(a) up by exactly 20,000) or leaves no trace of it (the commit count and the view token
 * unchanged); half the runs inside a transaction, which goes on after a timeout and commits what it kept */
static void t_timeout_write_phase(void)
{
    const char *dir = test_tmpdir();
    imdb_err e = {0};
    CHECK_OK(imdb_init(dir, false, NULL, &e));
    imdb_db *db = open_db(dir);
    CHECK(db);
    if (!db) return;
    imdb_session_init(&g_ss, db);
    RUN("CREATE TABLE w (id INT64 PRIMARY KEY, a INT64)");
    imdb_buf b;
    imdb_buf_init(&b);
    for (int base = 0; base < 20000 && !g_e.code; base += 10000) {
        b.len = 0;
        imdb_buf_put_str(&b, "INSERT INTO w VALUES ");
        for (int i = base + 1; i <= base + 10000; i++) imdb_buf_printf(&b, "%s(%d, %d)", i > base + 1 ? ", " : "", i, i % 100);
        CHECK_OK(imdb_buf_check(&b, &g_e) || run_buf(&b));
    }
    imdb_buf_free(&b);
    /* the UPDATE's cancellable part, its reads and writes: timed inside a transaction, which leaves out the commit (never
     * cut, and without SIMD its digests outweigh everything else), the least of three runs */
    double plain = 1e18;
    for (int k = 0; k < 3; k++) {
        RUN("BEGIN");
        double t0 = now_ms();
        RUN("UPDATE w SET a = a + 1");
        double dt = now_ms() - t0;
        RUN("ROLLBACK");
        if (dt < plain) plain = dt;
    }
    int timed_out = 0, whole = 0;
    char sql[80];
    for (int i = 1; i <= 16; i++) {
        bool txn = i & 1;
        int64_t sum = one_i64("SELECT SUM(a) FROM w");
        uint8_t tok0[32], tok1[32];
        CHECK_OK(imdb_view_token(db, tok0, &g_e));
        uint64_t seq = db->seq;
        if (txn) {
            RUN("BEGIN");
            RUN("UPDATE w SET a = a + 1 WHERE id = 1"); /* kept whatever the timed UPDATE does */
        }
        unsigned ms = (unsigned)(plain * i / 8);
        snprintf(sql, sizeof sql, "SET statement_timeout = %u", ms ? ms : 1);
        RUN(sql);
        int rc = run("UPDATE w SET a = a + 1");
        char msg[sizeof g_e.msg];
        snprintf(msg, sizeof msg, "%s", g_e.msg); /* the next statement clears g_e */
        RUN("SET statement_timeout = 0");
        if (rc) {
            CHECK(rc == IMDB_ERR_CANCELLED && strstr(msg, "statement timeout"));
            timed_out++;
        } else {
            whole++;
        }
        if (txn) {
            CHECK(g_ss.txn.open);
            CHECK(one_i64("SELECT SUM(a) FROM w") == sum + 1 + (rc ? 0 : 20000)); /* inside: its own writes */
            RUN("COMMIT");
            CHECK(db->seq == seq + 1);
            CHECK(one_i64("SELECT SUM(a) FROM w") == sum + 1 + (rc ? 0 : 20000));
        } else if (rc) {
            CHECK(db->seq == seq);
            CHECK_OK(imdb_view_token(db, tok1, &g_e));
            CHECK(!memcmp(tok0, tok1, sizeof tok0));
            CHECK(one_i64("SELECT SUM(a) FROM w") == sum);
        } else {
            CHECK(db->seq == seq + 1);
            CHECK(one_i64("SELECT SUM(a) FROM w") == sum + 20000);
        }
    }
    CHECK(timed_out > 0);
    done(db);
}

/* another thread's cancel (imdb_session_cancel), asked for again and again until the statement returns: the flag is
 * cleared at each statement's start, so one asked for before it began is dropped. make tsan runs this. */
typedef struct canceller {
    imdb_session *ss;
    atomic_bool stop;
    int asked;
} canceller;

static void *cancel_loop(void *arg)
{
    canceller *c = arg;
    struct timespec ts = {0, 5000000}; /* 5 ms */
    while (!atomic_load(&c->stop)) {
        nanosleep(&ts, NULL);
        imdb_session_cancel(c->ss);
        c->asked++;
    }
    return NULL;
}

static void t_cancel_thread(void)
{
    const char *dir = test_tmpdir();
    imdb_err e = {0};
    CHECK_OK(imdb_init(dir, false, NULL, &e));
    imdb_db *db = open_db(dir);
    CHECK(db);
    if (!db) return;
    imdb_session_init(&g_ss, db);
    RUN("CREATE TABLE j (id INT64 PRIMARY KEY, k INT64)");
    imdb_buf b;
    imdb_buf_init(&b);
    for (int base = 0; base < 30000; base += 10000) { /* k in 0..2: 3 x 10,000^2 = 300 M pairs, many seconds */
        b.len = 0;
        imdb_buf_put_str(&b, "INSERT INTO j VALUES ");
        for (int i = base + 1; i <= base + 10000; i++) imdb_buf_printf(&b, "%s(%d, %d)", i > base + 1 ? ", " : "", i, i % 3);
        CHECK_OK(imdb_buf_check(&b, &g_e));
        imdb_result r0;
        CHECK_OK(imdb_exec_one(&g_ss, (const char *)b.p, b.len, NULL, 0, &r0, &g_e));
        imdb_result_free(&r0);
    }
    imdb_buf_free(&b);
    uint8_t tok0[32], tok1[32];
    CHECK_OK(imdb_view_token(db, tok0, &g_e));
    canceller c = {.ss = &g_ss, .asked = 0};
    atomic_init(&c.stop, false);
    pthread_t th;
    CHECK(pthread_create(&th, NULL, cancel_loop, &c) == 0);
    double t0 = now_ms();
    int rc = run("SELECT COUNT(*) FROM j JOIN j AS b ON j.k = b.k");
    double dt = now_ms() - t0;
    atomic_store(&c.stop, true);
    pthread_join(th, NULL);
    CHECK(rc == IMDB_ERR_CANCELLED && strstr(g_e.msg, "statement cancelled"));
    CHECK(dt < 10000); /* the join alone takes far longer; the cancel within a few checks of the first request */
    CHECK_OK(imdb_view_token(db, tok1, &g_e));
    CHECK(!memcmp(tok0, tok1, sizeof tok0));
    /* a cancel asked for between statements is dropped: the next statement runs */
    imdb_session_cancel(&g_ss);
    CHECK(one_i64("SELECT COUNT(*) FROM j") == 30000);
    done(db);
}

const test_case cancel_tests[] = {
    {"cancel_timeout_paths", t_timeout_paths},
    {"cancel_timeout_writes", t_timeout_writes},
    {"cancel_timeout_write_phase", t_timeout_write_phase},
    {"cancel_thread", t_cancel_thread},
};
const size_t cancel_ntests = sizeof cancel_tests / sizeof *cancel_tests;
