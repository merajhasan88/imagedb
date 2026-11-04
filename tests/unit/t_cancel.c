/* Statement timeouts and cancellation (P0 resource limits, R1; docs/plan-p0.md): SET statement_timeout and
 * imdb_session_cancel stop a running statement at its next check (every few thousand rows its read paths, joins and
 * row loops pass) with IMDB_ERR_CANCELLED, and nothing it did stays: the view token is unchanged, a write is undone
 * by its statement savepoint, a transaction goes on. COMMIT and the physical statements run to their end. A timeout
 * depends on time, so these tests never assert where a statement stopped, only that it stopped and left nothing. */
#include <pthread.h>
#include <time.h>

#include "../../src/sql.h"
#include <stdlib.h>

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


static int64_t one_i64_s(imdb_session *s, const char *sql)
{
    imdb_result r;
    imdb_err_clear(&g_e);
    if (imdb_exec_one(s, sql, strlen(sql), NULL, 0, &r, &g_e)) return INT64_MIN;
    const imdb_cell *c = r.nrows == 1 ? &r.cells[0] : NULL;
    int64_t v = !c || c->null ? INT64_MIN : c->wide ? (int64_t)c->i128 : c->v.i; /* SUM: wide */
    imdb_result_free(&r);
    return v;
}

/* ---- R4: transaction and idle-in-transaction timeouts ---------------------------------------------------------- */

static void sleep_ms(int ms)
{
    struct timespec ts = {ms / 1000, (long)(ms % 1000) * 1000000L};
    while (nanosleep(&ts, &ts) != 0) {
    }
}

static int srun(imdb_session *s, const char *sql)
{
    imdb_result r;
    imdb_err_clear(&g_e);
    int rc = imdb_exec_one(s, sql, strlen(sql), NULL, 0, &r, &g_e);
    if (!rc) imdb_result_free(&r);
    return rc;
}

static imdb_db *small_db(imdb_session *s)
{
    const char *dir = test_tmpdir();
    imdb_err e = {0};
    if (imdb_init(dir, false, NULL, &e)) return NULL;
    imdb_db *db = open_db(dir);
    if (!db) return NULL;
    imdb_session_init(s, db);
    if (srun(s, "CREATE TABLE t (id INT64 PRIMARY KEY, v INT64)") || srun(s, "INSERT INTO t VALUES (1, 1)")) return db;
    return db;
}

/* SET transaction_timeout: a transaction older than it fails its next statement (cancelled), can then only roll back,
 * and its writes never commit; one that ends within it commits. Margins of 150 ms or more either way, for loaded and
 * sanitizer runs */
static void t_txn_timeout(void)
{
    imdb_session s;
    imdb_db *db = small_db(&s);
    CHECK(db);
    if (!db) return;
    CHECK(srun(&s, "SET transaction_timeout = 300") == 0);
    CHECK(srun(&s, "BEGIN") == 0 && srun(&s, "INSERT INTO t VALUES (2, 2)") == 0);
    sleep_ms(450);
    CHECK(srun(&s, "SELECT COUNT(*) FROM t") == IMDB_ERR_CANCELLED && strstr(g_e.msg, "transaction timeout"));
    CHECK(s.txn.open && s.txn.doomed && db->active == NULL); /* still open: only ROLLBACK ends it; its writes gone */
    CHECK(srun(&s, "INSERT INTO t VALUES (3, 3)") == IMDB_ERR_CONFLICT && strstr(g_e.msg, "transaction timeout"));
    CHECK(srun(&s, "SAVEPOINT a") == IMDB_ERR_CONFLICT);
    CHECK(srun(&s, "COMMIT") == IMDB_ERR_CONFLICT); /* a doomed COMMIT rolls back */
    CHECK(!s.txn.open);
    CHECK(srun(&s, "BEGIN") == 0 && srun(&s, "INSERT INTO t VALUES (5, 5)") == 0); /* a COMMIT the first statement past */
    sleep_ms(450);
    CHECK(srun(&s, "COMMIT") == IMDB_ERR_CANCELLED && strstr(g_e.msg, "rolled back"));
    CHECK(!s.txn.open && db->active == NULL);
    CHECK(srun(&s, "SET transaction_timeout = 0") == 0); /* the quick one is about the rule, not the disk's speed */
    CHECK(srun(&s, "BEGIN") == 0 && srun(&s, "INSERT INTO t VALUES (4, 4)") == 0 && srun(&s, "COMMIT") == 0);
    CHECK(one_i64_s(&s, "SELECT COUNT(*) FROM t") == 2); /* 1 and 4: nothing of the timed-out ones */
    CHECK(srun(&s, "SET transaction_timeout = 86400001") == IMDB_ERR_INVALID);
    CHECK(srun(&s, "SET idle_in_transaction_timeout = -1") != 0 && s.idle_timeout_ms == 0); /* a syntax error */
    imdb_session_close(&s);
    imdb_close(db);
}

/* SET idle_in_transaction_timeout: statements closer together than it keep a transaction alive however long it runs;
 * a pause longer than it makes the next statement fail (cancelled), and the transaction can only roll back */
static void t_txn_idle_timeout(void)
{
    imdb_session s;
    imdb_db *db = small_db(&s);
    CHECK(db);
    if (!db) return;
    CHECK(srun(&s, "SET idle_in_transaction_timeout = 300") == 0);
    CHECK(srun(&s, "BEGIN") == 0);
    for (int i = 0; i < 8; i++) { /* 8 statements 60 ms apart: 480 ms in all, never idle 300 */
        char q[64];
        snprintf(q, sizeof q, "INSERT INTO t VALUES (%d, %d)", 10 + i, i);
        CHECK(srun(&s, q) == 0);
        sleep_ms(60);
    }
    sleep_ms(450);
    CHECK(srun(&s, "SELECT COUNT(*) FROM t") == IMDB_ERR_CANCELLED && strstr(g_e.msg, "idle in transaction"));
    CHECK(srun(&s, "ROLLBACK") == 0 && !s.txn.open);
    CHECK(one_i64_s(&s, "SELECT COUNT(*) FROM t") == 1);
    imdb_session_close(&s);
    imdb_close(db);
}

static void insert_many(imdb_session *s, int from, int n)
{
    imdb_buf q;
    imdb_buf_init(&q);
    imdb_buf_put_str(&q, "INSERT INTO t VALUES ");
    for (int i = 0; i < n; i++) imdb_buf_printf(&q, "%s(%d, %d)", i ? ", " : "", from + i, i);
    OK(imdb_buf_check(&q, &g_e));
    imdb_result r;
    imdb_err_clear(&g_e);
    CHECK(imdb_exec_one(s, (const char *)q.p, q.len, NULL, 0, &r, &g_e) == 0);
    imdb_result_free(&r);
    imdb_buf_free(&q);
}

/* Another session's statement ends a parked transaction idle past its limit and frees its saved writes at once: the
 * memory an abandoned session held comes back without it; its own next statement then fails as doomed */
static void t_txn_idle_sweep(void)
{
    imdb_session a, b;
    imdb_db *db = small_db(&a);
    CHECK(db);
    if (!db) return;
    imdb_session_init(&b, db);
    CHECK(srun(&a, "SET idle_in_transaction_timeout = 200") == 0);
    CHECK(srun(&a, "BEGIN") == 0);
    insert_many(&a, 100, 3000);
    CHECK(srun(&b, "INSERT INTO t VALUES (99999, 0)") == 0); /* a's writes parked: saved, undone in the store */
    CHECK(a.txn.nops == 3000);
    uint64_t held = imdb_heap_bytes();
    sleep_ms(350);
    CHECK(srun(&b, "SELECT COUNT(*) FROM t") == 0); /* b's statement: a is past its limit, doomed, its copies freed */
    CHECK(a.txn.doomed && a.txn.nops == 0 && imdb_heap_bytes() + 3000 * 16 < held);
    CHECK(srun(&a, "SELECT COUNT(*) FROM t") == IMDB_ERR_CONFLICT && strstr(g_e.msg, "idle in transaction"));
    CHECK(srun(&a, "ROLLBACK") == 0 && !a.txn.open);
    CHECK(one_i64_s(&b, "SELECT COUNT(*) FROM t") == 2);
    imdb_session_close(&a);
    imdb_session_close(&b);
    imdb_close(db);
}

/* The same for the active transaction: its pending versions leave the store at another session's next statement, a
 * read that never switches transactions; the table holds again only what it held before the BEGIN */
static void t_txn_idle_sweep_active(void)
{
    imdb_session a, b;
    imdb_db *db = small_db(&a);
    CHECK(db);
    if (!db) return;
    imdb_session_init(&b, db);
    const imdb_table *t = imdb_table_by_name(db, "t");
    CHECK(t);
    if (!t) return;
    uint64_t before = t->nver;
    CHECK(srun(&a, "SET idle_in_transaction_timeout = 200") == 0);
    CHECK(srun(&a, "BEGIN") == 0);
    insert_many(&a, 100, 3000);
    CHECK(db->active == &a.txn && t->nver == before + 3000);
    CHECK(one_i64_s(&b, "SELECT COUNT(*) FROM t") == 1); /* within the limit: nothing happens to a */
    CHECK(db->active == &a.txn && !a.txn.doomed);
    sleep_ms(350);
    CHECK(one_i64_s(&b, "SELECT COUNT(*) FROM t") == 1);
    CHECK(a.txn.doomed && a.txn.open && db->active == NULL && t->nver == before);
    CHECK(srun(&a, "INSERT INTO t VALUES (5, 5)") == IMDB_ERR_CONFLICT && strstr(g_e.msg, "idle in transaction"));
    CHECK(srun(&a, "ROLLBACK") == 0 && !a.txn.open);
    CHECK(srun(&a, "INSERT INTO t VALUES (100, 1)") == 0); /* a key the expired one held is free */
    CHECK(one_i64_s(&b, "SELECT COUNT(*) FROM t") == 2);
    imdb_session_close(&a);
    imdb_session_close(&b);
    imdb_close(db);
}


/* ---- D8 #4: the work limit (SET statement_row_limit) ------------------------------------------------------------ */

/* t: 3,000 rows published (CHECKPOINT), 300 of them updated after and 200 more inserted, so a read meets segments,
 * ended versions in them and the memtable; u: the keys 0..9 and two that match nothing */
static imdb_db *wl_db(imdb_session *s, uint64_t *before_update)
{
    const char *dir = test_tmpdir();
    imdb_err e = {0};
    if (imdb_init(dir, false, NULL, &e)) return NULL;
    imdb_db *db = open_db(dir);
    if (!db) return NULL;
    imdb_session_init(s, db);
    int rc = srun(s, "CREATE TABLE t (id INT64 PRIMARY KEY, g INT64, v INT64)");
    if (!rc) rc = srun(s, "CREATE INDEX t_g ON t (g)");
    for (int b = 0; !rc && b < 30; b++) {
        imdb_buf q;
        imdb_buf_init(&q);
        imdb_buf_put_str(&q, "INSERT INTO t VALUES ");
        for (int i = 1; i <= 100; i++) imdb_buf_printf(&q, "%s(%d, %d, %d)", i > 1 ? ", " : "", b * 100 + i, (b * 100 + i) % 50, b * 100 + i);
        imdb_result r;
        rc = imdb_buf_check(&q, &e) ? e.code : imdb_exec_one(s, (const char *)q.p, q.len, NULL, 0, &r, &g_e);
        if (!rc) imdb_result_free(&r);
        imdb_buf_free(&q);
    }
    if (!rc) rc = srun(s, "CHECKPOINT");
    *before_update = db->seq;
    if (!rc) rc = srun(s, "UPDATE t SET v = v + 1 WHERE id <= 300");
    for (int i = 3001; !rc && i <= 3200; i++) {
        char q[96];
        snprintf(q, sizeof q, "INSERT INTO t VALUES (%d, %d, %d)", i, i % 50, i);
        rc = srun(s, q);
    }
    if (!rc) rc = srun(s, "CREATE TABLE u (k INT64 PRIMARY KEY, w INT64)");
    if (!rc) rc = srun(s, "INSERT INTO u VALUES (0, 0), (1, 1), (2, 2), (3, 3), (4, 4), (5, 5), (6, 6), (7, 7), (8, 8), (9, 9), "
                          "(100, 100), (101, 101)");
    if (rc) test_fail(__FILE__, __LINE__, "the work limit's database: its setup failed");
    return db;
}

/* q tests `want` rows on the session's current path: it passes at a limit of want and fails at want - 1, with nothing
 * changed (the view token); the limit off again after */
static void wl_expect(imdb_session *s, const char *q, uint64_t want, const char *label)
{
    char m[300];
    uint8_t v0[32], v1[32];
    OK(imdb_view_token(s->db, v0, E));
    CHECK(srun(s, "SET statement_row_limit = 0") == 0);
    int rc = srun(s, q);
    if (rc || s->rows_tested != want) {
        snprintf(m, sizeof m, "%s: rc %d, %llu rows tested, %llu wanted: %s", label, rc, (unsigned long long)s->rows_tested,
                 (unsigned long long)want, q);
        test_fail(__FILE__, __LINE__, m);
        return;
    }
    char set[80];
    snprintf(set, sizeof set, "SET statement_row_limit = %llu", (unsigned long long)want);
    CHECK(srun(s, set) == 0);
    CHECK(srun(s, q) == 0);
    if (want > 1) { /* a limit of 0 is none */
        snprintf(set, sizeof set, "SET statement_row_limit = %llu", (unsigned long long)(want - 1));
        CHECK(srun(s, set) == 0);
        rc = srun(s, q);
        if (rc != IMDB_ERR_LIMIT || !strstr(g_e.msg, "statement row limit")) {
            snprintf(m, sizeof m, "%s: at a limit of %llu rc %d (%s): %s", label, (unsigned long long)(want - 1), rc, g_e.msg, q);
            test_fail(__FILE__, __LINE__, m);
        }
    }
    CHECK(srun(s, "SET statement_row_limit = 0") == 0);
    OK(imdb_view_token(s->db, v1, E));
    CHECK(memcmp(v0, v1, 32) == 0);
}

/* Every path and placement tests the same rows: a statement's count is a function of the statement and the data
 * (the matrix runs this in the eager and the tiny modes too, where the lake answers what memory does here) */
static void t_row_limit_paths(void)
{
    imdb_session s;
    uint64_t before = 0;
    imdb_db *db = wl_db(&s, &before);
    CHECK(db);
    if (!db) return;
    static const char *const paths[] = {"auto", "scan", "store", "ordered", "index"};
    char asof[160];
    snprintf(asof, sizeof asof, "SELECT COUNT(*) FROM t AS OF %llu WHERE g = 7", (unsigned long long)before);
    for (size_t p = 0; p < sizeof paths / sizeof *paths; p++) {
        char set[64];
        snprintf(set, sizeof set, "SET access_path = %s", paths[p]);
        CHECK(srun(&s, set) == 0);
        wl_expect(&s, "SELECT COUNT(*) FROM t WHERE g = 7", 64, paths[p]);           /* 7, 57, .. 3157 */
        wl_expect(&s, "SELECT id, v FROM t WHERE g = 7", 64, paths[p]);
        wl_expect(&s, "SELECT COUNT(*), SUM(v) FROM t WHERE g = 7", 64, paths[p]);
        wl_expect(&s, "SELECT COUNT(*) FROM t WHERE g = 7 AND v + 0 > 1000", 64, paths[p]); /* a tree: after the 64 */
        wl_expect(&s, "SELECT COUNT(*) FROM t WHERE v >= 2001", 1200, paths[p]);
        wl_expect(&s, "SELECT g, COUNT(*) FROM t WHERE g < 5 GROUP BY g", 320, paths[p]);
        wl_expect(&s, "SELECT v FROM t WHERE id = 42", 1, paths[p]);
        wl_expect(&s, "SELECT COUNT(*) FROM t WHERE g = 7 AND g = 8", 0, paths[p]);  /* never: nothing tested */
        wl_expect(&s, asof, 60, paths[p]);                                          /* 7 .. 2957 */
    }
    /* a second publish: under IMDB_EVICT=eager the floor passes `before`, the versions the UPDATE ended leave memory,
     * and the AS OF read is the lake's alone (below_floor); elsewhere memory answers it: the same count either way */
    CHECK(srun(&s, "CHECKPOINT") == 0);
    for (size_t p = 0; p < sizeof paths / sizeof *paths; p++) {
        char set[64];
        snprintf(set, sizeof set, "SET access_path = %s", paths[p]);
        CHECK(srun(&s, set) == 0);
        wl_expect(&s, asof, 60, paths[p]);
        wl_expect(&s, "SELECT COUNT(*) FROM t WHERE g = 7", 64, paths[p]);
        wl_expect(&s, "SELECT COUNT(*) FROM t WHERE v >= 2001", 1200, paths[p]);
    }
    if (getenv("IMDB_EVICT") && strcmp(getenv("IMDB_EVICT"), "eager") == 0) CHECK(db->mem_floor > before);
    CHECK(srun(&s, "SET access_path = auto") == 0);
    CHECK(srun(&s, "SET cross_check = on") == 0); /* each plan counts from zero: the limit is each one's */
    uint64_t runs = s.cross_checks_run;
    wl_expect(&s, "SELECT COUNT(*) FROM t WHERE g = 7", 64, "cross_check");
    CHECK(s.cross_checks_run > runs);
    CHECK(srun(&s, "SET cross_check = off") == 0);
    CHECK(srun(&s, "SET statement_row_limit = 4611686018427387905") == IMDB_ERR_INVALID);
    imdb_session_close(&s);
    imdb_close(db);
}

/* A join tests the pairs it forms, the same under the hash and the index plan; a LEFT row without a match is one */
static void t_row_limit_join(void)
{
    imdb_session s;
    uint64_t before = 0;
    imdb_db *db = wl_db(&s, &before);
    CHECK(db);
    if (!db) return;
    static const char *const plans[] = {"auto", "hash", "index"};
    for (size_t p = 0; p < sizeof plans / sizeof *plans; p++) {
        char set[64];
        snprintf(set, sizeof set, "SET join_plan = %s", plans[p]);
        CHECK(srun(&s, set) == 0);
        wl_expect(&s, "SELECT COUNT(*) FROM t JOIN u ON t.g = u.k", 640, plans[p]); /* g 0..9: 64 rows each */
        wl_expect(&s, "SELECT t.id, u.w FROM t JOIN u ON t.g = u.k WHERE u.k = 3", 64, plans[p]);
        wl_expect(&s, "SELECT COUNT(*) FROM u LEFT JOIN t ON u.k = t.g", 642, plans[p]); /* 100 and 101 unmatched */
    }
    CHECK(srun(&s, "SET join_plan = auto") == 0);
    imdb_session_close(&s);
    imdb_close(db);
}

/* A write past the limit is undone like any failed statement: in autocommit nothing commits; in a transaction the
 * statement goes and the transaction goes on */
static void t_row_limit_write(void)
{
    imdb_session s;
    uint64_t before = 0;
    imdb_db *db = wl_db(&s, &before);
    CHECK(db);
    if (!db) return;
    uint8_t v0[32], v1[32];
    OK(imdb_view_token(db, v0, E));
    CHECK(srun(&s, "SET statement_row_limit = 63") == 0);
    CHECK(srun(&s, "UPDATE t SET v = v + 1 WHERE g = 7") == IMDB_ERR_LIMIT);
    CHECK(srun(&s, "DELETE FROM t WHERE g = 7") == IMDB_ERR_LIMIT);
    OK(imdb_view_token(db, v1, E));
    CHECK(memcmp(v0, v1, 32) == 0);
    CHECK(srun(&s, "BEGIN") == 0);
    CHECK(srun(&s, "UPDATE t SET v = 0 WHERE id = 1") == 0);
    CHECK(srun(&s, "UPDATE t SET v = v + 1 WHERE g = 7") == IMDB_ERR_LIMIT);
    CHECK(s.txn.open && !s.txn.doomed);
    CHECK(srun(&s, "COMMIT") == 0);
    CHECK(srun(&s, "SET statement_row_limit = 0") == 0);
    CHECK(one_i64_s(&s, "SELECT v FROM t WHERE id = 1") == 0);
    int64_t sum = one_i64_s(&s, "SELECT SUM(v) FROM t WHERE g = 7");
    CHECK(sum == 101254); /* untouched: the 64 ids, the six <= 300 one more */
    imdb_session_close(&s);
    imdb_close(db);
}

const test_case cancel_tests[] = {
    {"cancel_timeout_paths", t_timeout_paths},
    {"cancel_timeout_writes", t_timeout_writes},
    {"cancel_timeout_write_phase", t_timeout_write_phase},
    {"cancel_thread", t_cancel_thread},
    {"cancel_txn_timeout", t_txn_timeout},
    {"cancel_txn_idle_timeout", t_txn_idle_timeout},
    {"cancel_txn_idle_sweep", t_txn_idle_sweep},
    {"cancel_txn_idle_sweep_active", t_txn_idle_sweep_active},
    {"cancel_row_limit_paths", t_row_limit_paths},
    {"cancel_row_limit_join", t_row_limit_join},
    {"cancel_row_limit_write", t_row_limit_write},
};
const size_t cancel_ntests = sizeof cancel_tests / sizeof *cancel_tests;
