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


/* N1e stage two: a held cancel (the server's KILL): every statement starting while it is held starts cancelled, however
 * soon after a plain cancel's clear (the statement's start clears a plain one, then reads the hold); released, the next
 * statement runs. A statement never checked (COMMIT, a DDL) runs to its end as a plain cancel's does */
static void t_cancel_held(void)
{
    imdb_db *db = loaded();
    CHECK(db);
    RUN("SET statement_timeout = 20000"); /* a hold that failed ends anyway, by its timeout's words */
    imdb_session_cancel_held(&g_ss, true);
    double t0 = now_ms();
    int rc = run("SELECT COUNT(*) FROM t JOIN t AS b ON t.g = b.g"); /* billions of pairs: minutes */
    SOFT(rc == IMDB_ERR_CANCELLED && strstr(g_e.msg, "statement cancelled"));
    if (rc != IMDB_ERR_CANCELLED) fprintf(stderr, "    the join: %d %s\n", rc, g_e.msg);
    rc = run("SELECT COUNT(*) FROM t"); /* the next one too, while held */
    SOFT(rc == IMDB_ERR_CANCELLED);
    SOFT(now_ms() - t0 < 10000);
    imdb_session_cancel_held(&g_ss, false);
    SOFT(one_i64("SELECT COUNT(*) FROM t") == N); /* released: it runs (the cancel the hold set is cleared at its start) */
    done(db);
}

/* ---- 2b-2b: the sort's deadline (docs/n1-design.md §8e; .work/scratch/sortdl/REPORT.md) ---- */
/* s: 5,000 rows (id, g = id % 7, v = id % 13: ties everywhere); s2: 5,000 rows (id, v = id % 11, p = id * 7919 % 5003:
 * distinct and scrambled, so a sort of large elements moves nearly all of them); h: one row updated 3,000 times. Each
 * statement reaches sort sites with thousands of elements; the tests sort in runs of 64 (imdb_sql_set_sort_run), so the
 * runs, the merges and the permutation all run */
static imdb_db *sort_db(void)
{
    const char *dir = test_tmpdir();
    imdb_err e = {0};
    if (imdb_init(dir, false, NULL, &e)) return NULL;
    imdb_db *db = open_db(dir);
    if (!db) return NULL;
    imdb_session_init(&g_ss, db);
    if (run("CREATE TABLE s (id INT64 PRIMARY KEY, g INT64, v INT64)") ||
        run("CREATE TABLE s2 (id INT64 PRIMARY KEY, v INT64, p INT64)") || run("CREATE TABLE h (id INT64 PRIMARY KEY, v INT64)") ||
        run("INSERT INTO h VALUES (1, 0)"))
        return db;
    imdb_buf b;
    imdb_buf_init(&b);
    imdb_buf_put_str(&b, "INSERT INTO s VALUES ");
    for (int i = 1; i <= 5000; i++) imdb_buf_printf(&b, "%s(%d, %d, %d)", i > 1 ? ", " : "", i, i % 7, i % 13);
    if (!imdb_buf_check(&b, &g_e) && !run_buf(&b)) {
        b.len = 0;
        imdb_buf_put_str(&b, "INSERT INTO s2 VALUES ");
        for (int i = 1; i <= 5000; i++) imdb_buf_printf(&b, "%s(%d, %d, %d)", i > 1 ? ", " : "", i, i % 11, i * 7919 % 5003);
        if (!imdb_buf_check(&b, &g_e)) run_buf(&b);
    }
    imdb_buf_free(&b);
    for (int i = 1; i <= 3000 && !g_e.code; i++) run("UPDATE h SET v = v + 1 WHERE id = 1");
    /* sortpg: a table inserted out of key order, so a write's vids (in the walk's key order) are not in order */
    if (!g_e.code && !run("CREATE TABLE s3 (id INT64 PRIMARY KEY, g INT64, v INT64)")) {
        imdb_buf_init(&b);
        imdb_buf_put_str(&b, "INSERT INTO s3 VALUES ");
        for (int i = 1; i <= 5000; i++) imdb_buf_printf(&b, "%s(%d, %d, %d)", i > 1 ? ", " : "", i * 7919 % 5003 + 1, i % 7, i % 13);
        if (!imdb_buf_check(&b, &g_e) && !run_buf(&b)) run("CREATE INDEX s3g ON s3 (g)"); /* (a walk by g: vids out of order) */
        imdb_buf_free(&b);
    }
    /* 2b-3: keys sharing a 2,000-byte prefix, 50 values, each running past eight bytes after it: before a second key over
     * 1,024 rows (the run knob's threshold) the 1,024 rows' sample finds them few, so the sort goes to the old merge before
     * ab_common runs: the sampled prefix pass is the one source of phase 6 there */
    if (!g_e.code && !run("CREATE TABLE s4 (id INT64 PRIMARY KEY, k TEXT)")) {
        imdb_buf_init(&b);
        for (int base = 0; base < 5000 && !g_e.code; base += 250) {
            b.len = 0;
            imdb_buf_put_str(&b, "INSERT INTO s4 VALUES ");
            for (int i = base + 1; i <= base + 250; i++) {
                imdb_buf_printf(&b, "%s(%d, '", i > base + 1 ? ", " : "", i);
                for (int x = 0; x < 2000; x++) imdb_buf_put_str(&b, "P");
                imdb_buf_printf(&b, "%02d-suffixxxx')", i * 7919 % 5003 % 50);
            }
            if (!imdb_buf_check(&b, &g_e)) run_buf(&b);
        }
        imdb_buf_free(&b);
    }
    return db;
}

typedef struct sort_stmt {
    const char *sql;
    bool write, perm; /* perm: a sort of large elements it reaches moves thousands of them (the permutation's checks) */
    uint32_t sites;   /* the sort sites it must reach (xsortc.site: 1u << site), each seen checking */
    bool xc;          /* run with cross_check on (select_vids' second plan) */
    uint32_t phases;  /* sortpg: the phases it must show checking (1u << phase; 0: a run and a merge, and the permutation
                       * where perm), at psite alone when given */
    int psite;
} sort_stmt;

#define S_(n) (1u << (n))

static const sort_stmt k_sort_stmts[] = {
    {"SELECT id, v FROM s ORDER BY v DESC, g", false, false, S_(4) | S_(5), false, 0, 0}, /* the walk's keys, ORDER BY */
    {"SELECT id, COUNT(*) FROM s GROUP BY id", false, false, S_(6), false, S_(5), 6}, /* 5,000 groups by a column, in order */
    {"SELECT p, COUNT(*) FROM s2 GROUP BY p", false, false, S_(6), false, S_(0) | S_(1), 6}, /* 5,000 groups, out of order */
    {"SELECT id / 2 + v, COUNT(*) FROM s GROUP BY id / 2 + v", false, false, S_(6), false, 0, 0}, /* groups by a tree's keys */
    {"SELECT p / 2 AS k, COUNT(*) AS c FROM s2 GROUP BY p / 2 ORDER BY c, k DESC", false, false, S_(6) | S_(3), false, 0, 0}, /* reorder_rows */
    {"SELECT a.id, b.v FROM s AS a JOIN s2 AS b ON a.id = b.p", false, true, S_(7), false, 0, 0}, /* a join's pairs */
    {"SELECT a.id, b.v FROM s AS a JOIN s2 AS b ON a.id = b.id ORDER BY b.v, a.g", false, false, S_(7) | S_(8), false, 0, 0}, /* a join's ORDER BY */
    {"SELECT v FROM s UNION ALL SELECT v FROM s2 ORDER BY 1", false, false, S_(9), false, 0, 0}, /* a set operation's tail */
    {"SELECT id, ROW_NUMBER() OVER (ORDER BY v, g) FROM s", false, false, S_(10), false, 0, 0}, /* a window's sort */
    {"SELECT id, SUM(v) OVER (PARTITION BY g ORDER BY v) AS w FROM s ORDER BY w, v", false, false, S_(10) | S_(11), false, 0, 0}, /* window and tail */
    {"SELECT COUNT(*) FROM s WHERE v IN (SELECT p FROM s2)", false, true, S_(2), false, 0, 0}, /* an IN set run on demand */
    {"SHOW HISTORY h (1)", false, false, S_(15), false, 0, 0}, /* a key's versions */
    {"UPDATE s SET v = v + 1 WHERE v >= 0", true, false, S_(12), false, S_(5), 12}, /* the vids to change, in order */
    {"UPDATE s3 SET v = v + 1 WHERE g >= 0", true, false, S_(12), false, S_(0) | S_(1), 12}, /* the vids by an index: out of order */
    {"UPDATE s SET v = s2.v FROM s2 WHERE s.id = s2.p", true, true, S_(14), false, 0, 0}, /* UPDATE ... FROM's pairs by the key */
    {"DELETE FROM s WHERE v IN (SELECT p FROM s2 WHERE v > 3)", true, true, S_(1), false, 0, 0}, /* a write's IN set, before its first write */
    {"UPDATE s3 SET v = v + 2 WHERE g >= 0", true, false, S_(12) | S_(13), true, 0, 0}, /* cross_check: the second plan's vids */
    /* sortpg: an ORDER BY's abbreviated merge sort, each phase (0 a run, 1 a merge from the left, 3 the images and the
     * shared prefix's pass, 4 a merge from the right, 5 the in-order pass) */
    {"SELECT id, v FROM s ORDER BY v, g", false, false, S_(5), false, S_(0) | S_(1) | S_(3) | S_(4), 5},
    {"SELECT id, v FROM s ORDER BY id", false, false, S_(5), false, S_(5), 5}, /* the default order: in order, nothing made */
    {"SELECT id FROM s ORDER BY 'prefix-' || CAST(id * 7919 % 5003 AS TEXT)", false, false, S_(5), false, S_(0) | S_(1) | S_(3) | S_(4) | S_(6), 5},
    {"SELECT id, v FROM s ORDER BY CASE WHEN v < 0 THEN v END, v DESC, id", false, false, S_(5), false, S_(3), 5}, /* a first key NULL in every row: the scan past its NULLs */
    {"SELECT id FROM s4 ORDER BY k, id", false, false, S_(5), false, S_(6), 5}, /* 2b-3: the sampled prefix pass alone */
    /* topk: ORDER BY ... LIMIT's top-k: its threshold's pass over 5,000 rows out of order (phase 7), its selections over
     * 2,000 (phase 8); a join's pairs (site 8) and grouped rows (site 3) cut the same way */
    {"SELECT id FROM s2 ORDER BY p LIMIT 3", false, false, S_(5), false, S_(7), 5},
    {"SELECT id FROM s2 ORDER BY p LIMIT 1000", false, false, S_(5), false, S_(8), 5},
    {"SELECT a.id FROM s AS a JOIN s2 AS b ON a.id = b.p ORDER BY b.v, a.id DESC LIMIT 2", false, false, S_(8), false, S_(7), 8},
};

typedef struct sort_hook_ctx {
    int mode;      /* 0: count, 1: another thread's cancel, 2: a sleep past the statement's deadline */
    int at_phase;  /* the stop at the first check of this phase (0 a run, 1 a merge, 2 the permutation; sortpg: 3 the
                    * images, 4 a merge from the right, 5 the in-order pass) */
    int seen[9];   /* checks seen by phase (6: the shared prefix's pass; topk: 7 the threshold's pass, 8 the selections) */
    uint16_t sp[32]; /* the phases seen checking at each site */
    uint32_t sites; /* the sites seen checking */
    bool fired;
    int sleep_ms; /* mode 2: how long the hook waits (past the statement's timeout; 0: 1,100 ms) */
} sort_hook_ctx;

static void *cancel_from(void *arg)
{
    imdb_session_cancel(arg);
    return NULL;
}

static void sort_hook(void *arg, int phase, int site)
{
    sort_hook_ctx *h = arg;
    if (phase >= 0 && phase < 9) h->seen[phase]++;
    if (site > 0 && site < 32) h->sites |= 1u << site;
    if (site > 0 && site < 32 && phase >= 0 && phase < 9) h->sp[site] |= (uint16_t)(1u << phase);
    if (!h->mode || h->fired || phase != h->at_phase) return;
    h->fired = true;
    if (h->mode == 1) {
        pthread_t t;
        if (!pthread_create(&t, NULL, cancel_from, &g_ss)) pthread_join(t, NULL);
    } else {
        sleep_ms(h->sleep_ms ? h->sleep_ms : 1100); /* past statement_timeout (1,000 ms, or the retry's longer one) */
    }
}

/* the table's state (its rows' sum and count) */
static int64_t s_state(void) { return one_i64("SELECT COUNT(*) * 1000000 + SUM(v) FROM s"); }

/* Every statement's sorts check as they go: counted, each statement shows checks in the runs and the merges (and in the
 * permutation where it moves thousands of large elements). Then stopped at the first check of each phase it showed, by
 * another thread's cancel, and at its first check by the deadline: CANCELLED in its words, one stop counted inside a sort
 * (the hook runs at a sort's checks alone), the table unchanged, the next statement answering. (Before, a sort ran to its
 * end: the deadline passed, unseen, for seconds) */
static void t_sort_stops(void)
{
    imdb_db *db = sort_db();
    CHECK(db && !g_e.code);
    imdb_sql_set_sort_run(64);
    int64_t st0 = s_state();
    sort_hook_ctx h;
    imdb_sql_set_sort_hook(sort_hook, &h);
    for (size_t i = 0; i < sizeof k_sort_stmts / sizeof *k_sort_stmts; i++) {
        const sort_stmt *ss = &k_sort_stmts[i];
        memset(&h, 0, sizeof h);
        if (ss->xc) RUN("SET cross_check = on");
        if (ss->write) RUN("BEGIN");
        int rc = run(ss->sql);
        if (ss->write) RUN("ROLLBACK");
        int seen[9];
        uint32_t shown = 0, need = ss->phases ? ss->phases : S_(0) | S_(1) | (ss->perm ? S_(2) : 0);
        for (int p = 0; p < 9; p++) seen[p] = h.seen[p], shown |= seen[p] ? 1u << p : 0;
        if (ss->psite) shown = h.sp[ss->psite];
        bool counted = rc == 0 && (shown & need) == need && (h.sites & ss->sites) == ss->sites;
        SOFT(counted);
        if (!counted)
            fprintf(stderr, "    %s: rc %d (%s), checks %d / %d / %d / %d / %d / %d / %d / %d / %d (at its site %#x), sites %#x of %#x\n",
                    ss->sql, rc, g_e.msg, seen[0], seen[1], seen[2], seen[3], seen[4], seen[5], seen[6], seen[7], seen[8],
                    (unsigned)shown, h.sites, ss->sites);
        for (int mode = 1; mode <= 2; mode++)
            for (int ph = 0; ph < 9; ph++) {
                if (!seen[ph] || (mode == 2 && ph)) continue; /* (the deadline: its first check alone) */
                uint64_t stopped = 0;
                char msg[sizeof g_e.msg];
                /* mode 2: the deadline must pass inside the sort. A deadline that passed before the sort was reached (the
                 * hook never fired: SAN on a loaded machine, 11-22) tests nothing: again with a longer one, the hook
                 * waiting past it. A sort that fails to stop still fails: its hook fired */
                for (int tmo = 1000; tmo <= 16000; tmo *= 4) {
                    char set[64];
                    if (mode == 2) {
                        snprintf(set, sizeof set, "SET statement_timeout = %d", tmo);
                        RUN(set);
                    }
                    memset(&h, 0, sizeof h);
                    h.mode = mode, h.at_phase = ph, h.sleep_ms = tmo + 100;
                    stopped = imdb_sql_sorts_stopped();
                    rc = run(ss->sql);
                    snprintf(msg, sizeof msg, "%s", g_e.msg);
                    h.mode = 0;
                    if (mode == 2) RUN("SET statement_timeout = 0");
                    if (mode != 2 || h.fired || rc != IMDB_ERR_CANCELLED) break;
                    fprintf(stderr, "    mode 2, phase %d, %s: the deadline of %d ms passed before the sort; again\n", ph,
                            ss->sql, tmo);
                }
                bool ok = rc == IMDB_ERR_CANCELLED && strstr(msg, mode == 1 ? "statement cancelled" : "statement timeout") &&
                          h.fired && imdb_sql_sorts_stopped() == stopped + 1;
                SOFT(ok);
                if (!ok) fprintf(stderr, "    mode %d, phase %d, %s: rc %d (%s), %llu stops\n", mode, ph, ss->sql, rc, msg,
                                 (unsigned long long)(imdb_sql_sorts_stopped() - stopped));
                SOFT(s_state() == st0); /* nothing it did stays; the session answers */
            }
        if (ss->xc) RUN("SET cross_check = off");
    }
    imdb_sql_set_sort_hook(NULL, NULL);
    imdb_sql_set_sort_run(0);
    done(db);
}

/* every sort's order is the old sort's (the C library's qsort whole: imdb_sql_set_sort_reference), cell for cell, with
 * cross_check on, in runs of 64 (the merges and the permutation) and of the default (one run, in place): each read
 * statement, and the table after each write (rolled back between) */
static void t_sort_order(void)
{
    imdb_db *db = sort_db();
    CHECK(db && !g_e.code);
    RUN("SET cross_check = on");
    for (int runs = 0; runs < 2; runs++) {
        imdb_sql_set_sort_run(runs ? 0 : 64);
        for (size_t i = 0; i < sizeof k_sort_stmts / sizeof *k_sort_stmts; i++) {
            const sort_stmt *ss = &k_sort_stmts[i];
            imdb_buf out[2];
            for (int ref = 0; ref < 2; ref++) {
                imdb_buf_init(&out[ref]);
                imdb_sql_set_sort_reference(ref == 1);
                imdb_result r;
                if (ss->write) RUN("BEGIN");
                int rc = q(ss->sql, &r);
                SOFT(rc == 0);
                if (rc) fprintf(stderr, "    %s (%s): %s\n", ss->sql, ref ? "the reference" : "xsort", g_e.msg);
                if (!rc) {
                    if (!ss->write) imdb_result_render(&r, true, &out[ref]);
                    imdb_result_free(&r);
                }
                if (ss->write) {
                    if (!q("SELECT id, g, v FROM s ORDER BY id", &r)) {
                        imdb_result_render(&r, true, &out[ref]);
                        imdb_result_free(&r);
                    }
                    RUN("ROLLBACK");
                }
            }
            imdb_sql_set_sort_reference(false);
            SOFT(out[0].len > 0 && out[0].len == out[1].len && !memcmp(out[0].p, out[1].p, out[0].len));
            if (out[0].len != out[1].len || memcmp(out[0].p, out[1].p, out[0].len))
                fprintf(stderr, "    %s (runs of %d): %zu bytes against the reference's %zu\n", ss->sql, runs ? 16384 : 64,
                        out[0].len, out[1].len);
            imdb_buf_free(&out[0]);
            imdb_buf_free(&out[1]);
        }
    }
    imdb_sql_set_sort_run(0);
    RUN("SET cross_check = off");
    done(db);
}

/* measured, printed only (IMDB_SORT_MEASURE=1): a million rows sorted by ORDER BY and by GROUP BY, xsort against the
 * reference, each statement's time (the memory: its ceiling's tests, qmem) */
static void t_sort_measure(void)
{
    imdb_sql_set_sort_topk(1); /* topk: this measures the full sort (LIMIT 1 is only its output's cut) */
    if (!getenv("IMDB_SORT_MEASURE")) return;
    const char *dir = test_tmpdir();
    imdb_err e = {0};
    CHECK(!imdb_init(dir, false, NULL, &e));
    imdb_db *db = open_db(dir);
    CHECK(db);
    imdb_session_init(&g_ss, db);
    RUN("CREATE TABLE m (id INT64 PRIMARY KEY, v INT64)");
    imdb_buf b;
    imdb_buf_init(&b);
    for (int base = 0; base < 1000000; base += 10000) {
        b.len = 0;
        imdb_buf_put_str(&b, "INSERT INTO m VALUES ");
        for (int i = base + 1; i <= base + 10000; i++) imdb_buf_printf(&b, "%s(%d, %d)", i > base + 1 ? ", " : "", i, (int)((int64_t)i * 7919 % 1000003));
        CHECK(!imdb_buf_check(&b, &g_e) && !run_buf(&b));
    }
    imdb_buf_free(&b);
    RUN("CREATE TABLE m2 (id INT64 PRIMARY KEY, w INT64)");
    RUN("INSERT INTO m2 SELECT v, id FROM m WHERE id <= 1000000");
    static const char *const ms[] = {"SELECT id FROM m ORDER BY v LIMIT 1", "SELECT v, COUNT(*) FROM m GROUP BY v LIMIT 1",
                                     "SELECT COUNT(*) FROM (SELECT a.id, b.w FROM m AS a JOIN m2 AS b ON a.v = b.id) AS j"};
    const char *only = getenv("IMDB_SORT_ONLY"); /* (a profile's: "qsort" or "xsort", the ORDER BY alone, five times) */
    if (getenv("IMDB_SORT_RUN")) imdb_sql_set_sort_run((size_t)atoi(getenv("IMDB_SORT_RUN"))); /* (a run length to measure) */
    for (int rep = 0; rep < (only ? 5 : 3); rep++)
    for (size_t i = 0; i < (only ? 1 : 3); i++)
        for (int ref = 1; ref >= 0; ref--) {
            if (only && ref != !strcmp(only, "qsort")) continue;
            imdb_sql_set_sort_reference(ref);
            double t0 = now_ms();
            CHECK(run(ms[i]) == 0);
            fprintf(stderr, "    %-48s %s: %.0f ms\n", ms[i], ref ? "qsort" : "xsort", now_ms() - t0);
        }
    imdb_sql_set_sort_reference(false);
    imdb_sql_set_sort_run(0);
    done(db);
}

/* the longest stretch a sort runs between two of its checks, timed by the hook */
typedef struct gap_ctx {
    double last, worst;
    int calls;
} gap_ctx;

static void gap_hook(void *arg, int phase, int site)
{
    (void)phase, (void)site;
    gap_ctx *g = arg;
    double now = now_ms();
    if (g->calls++ && now - g->last > g->worst) g->worst = now - g->last;
    g->last = now;
}

/* printed only (IMDB_SORT_MEASURE=1): a sort's longest unchecked stretch over TEXT keys sharing a long prefix (each
 * comparison scans it), inserted in scrambled order: 20,000 keys of 4,000 bytes and 4,000 of 32,000; then (sortpg) with
 * one outlier (no prefix shared: no image, xsort's merge) and with the 32 rows the images are sampled at distinct in
 * their first eight bytes and every other row sharing them (the images taken, every comparison whole) */
static void t_sort_gap(void)
{
    imdb_sql_set_sort_topk(1); /* topk: this measures the full sort (LIMIT 1 is only its output's cut) */
    if (!getenv("IMDB_SORT_MEASURE")) return;
    static const int rows[2] = {20000, 4000}, plen[2] = {4000, 32000};
    static const char *const how[4] = {"", ", one outlier", ", the sampled rows distinct", ", a second key (runs of 64: the 1,024 rows' pass)"};
    for (int cc = 0; cc < 8; cc++) {
        int c = cc % 2, mode = cc / 2;
        const char *dir = test_tmpdir();
        imdb_err e = {0};
        CHECK(!imdb_init(dir, false, NULL, &e));
        imdb_db *db = open_db(dir);
        CHECK(db);
        imdb_session_init(&g_ss, db);
        RUN("CREATE TABLE g (id INT64 PRIMARY KEY, k TEXT)");
        imdb_buf b;
        imdb_buf_init(&b);
        for (int base = 0; base < rows[c]; base += 100) {
            b.len = 0;
            imdb_buf_put_str(&b, "INSERT INTO g VALUES ");
            for (int i = base; i < base + 100 && i < rows[c]; i++) {
                imdb_buf_printf(&b, "%s(%d, '", i > base ? ", " : "", i);
                if (mode == 1 && i == rows[c] / 2) {
                    imdb_buf_put_str(&b, "outlier')");
                    continue;
                }
                if (mode == 2 && i % (rows[c] / 32) == 0) imdb_buf_printf(&b, "A%07d", i);
                for (int x = 0; x < plen[c]; x++) imdb_buf_put_str(&b, "x");
                imdb_buf_printf(&b, "%010d')", (int)((int64_t)i * 7919 % 1000003));
            }
            CHECK(!imdb_buf_check(&b, &g_e) && !run_buf(&b));
        }
        imdb_buf_free(&b);
        gap_ctx g = {0, 0, 0};
        imdb_sql_set_sort_hook(gap_hook, &g);
        double t0 = now_ms();
        if (mode == 3) imdb_sql_set_sort_run(64);
        CHECK(run(mode == 3 ? "SELECT id FROM g ORDER BY k, id DESC LIMIT 1" : "SELECT id FROM g ORDER BY k LIMIT 1") == 0);
        imdb_sql_set_sort_run(0);
        double total = now_ms() - t0;
        imdb_sql_set_sort_hook(NULL, NULL);
        fprintf(stderr, "    %d keys of %d bytes%s: the statement %.0f ms, %d sort checks, the longest stretch between two %.1f ms\n",
                rows[c], plen[c], how[mode], total, g.calls, g.worst);
        done(db);
    }
}

/* printed only (IMDB_SORT_MEASURE=1): the sizes the no-allocation threshold moved across (512): an ORDER BY over 5,000 and
 * 50,000 rows, xsort against the C library's, alternating in blocks of ten, many repetitions */
static void t_sort_measure_mid(void)
{
    imdb_sql_set_sort_topk(1); /* topk: this measures the full sort (LIMIT 1 is only its output's cut) */
    if (!getenv("IMDB_SORT_MEASURE")) return;
    static const int rows[2] = {5000, 50000}, reps[2] = {400, 40};
    for (int c = 0; c < 2; c++) {
        const char *dir = test_tmpdir();
        imdb_err e = {0};
        CHECK(!imdb_init(dir, false, NULL, &e));
        imdb_db *db = open_db(dir);
        CHECK(db);
        imdb_session_init(&g_ss, db);
        RUN("CREATE TABLE mm (id INT64 PRIMARY KEY, v INT64)");
        imdb_buf b;
        imdb_buf_init(&b);
        for (int base = 0; base < rows[c]; base += 5000) {
            b.len = 0;
            imdb_buf_put_str(&b, "INSERT INTO mm VALUES ");
            for (int i = base + 1; i <= base + 5000; i++) imdb_buf_printf(&b, "%s(%d, %d)", i > base + 1 ? ", " : "", i, (int)((int64_t)i * 7919 % 1000003));
            CHECK(!imdb_buf_check(&b, &g_e) && !run_buf(&b));
        }
        imdb_buf_free(&b);
        double sum[2] = {0, 0};
        for (int k = 0; k < reps[c]; k += 10)
            for (int ref = 1; ref >= 0; ref--) {
                imdb_sql_set_sort_reference(ref);
                double t0 = now_ms();
                for (int j = 0; j < 10; j++) CHECK(run("SELECT id FROM mm ORDER BY v LIMIT 1") == 0);
                sum[ref] += now_ms() - t0;
            }
        imdb_sql_set_sort_reference(false);
        fprintf(stderr, "    ORDER BY over %d rows: qsort %.3f ms, xsort %.3f ms a statement (%d each, alternating)\n", rows[c],
                sum[1] / reps[c], sum[0] / reps[c], reps[c]);
        done(db);
    }
}

/* ---- sortpg (a prototype): ORDER BY's order arrays through abbreviated keys, merged (1) or by introsort (2) ---- */
static void proto_db(int n, imdb_db **out)
{
    const char *dir = test_tmpdir();
    imdb_err e = {0};
    CHECK(!imdb_init(dir, false, NULL, &e));
    imdb_db *db = open_db(dir);
    *out = NULL;
    CHECK(db);
    imdb_session_init(&g_ss, db);
    RUN("CREATE TABLE pt (id INT64 PRIMARY KEY, v INT64, s TEXT, p TEXT, vn INT64, g INT64, f FLOAT64, d DECIMAL(12,2), "
        "iv INTERVAL, q TEXT, c2 TEXT, w DECIMAL(38,0))");
    imdb_buf b;
    imdb_buf_init(&b);
    for (int base = 0; base < n; base += 2000) {
        b.len = 0;
        imdb_buf_put_str(&b, "INSERT INTO pt VALUES ");
        for (int i = base + 1; i <= base + 2000 && i <= n; i++) {
            int v = (int)((int64_t)i * 7919 % 1000003);
            imdb_buf_printf(&b, "%s(%d, %d, 'k%07d', 'commonprefix-%07d', ", i > base + 1 ? ", " : "", i, v, v, v);
            if (i % 10 == 0) imdb_buf_put_str(&b, "NULL, ");
            else imdb_buf_printf(&b, "%d, ", v % 5000);
            imdb_buf_printf(&b, "%d, %d.25, ", v % 100, v - 500000);
            if (i % 7 == 0) imdb_buf_put_str(&b, "NULL, ");
            else imdb_buf_printf(&b, "%d.%02d, ", v / 100, v % 100);
            if (v % 3 == 0) imdb_buf_printf(&b, "INTERVAL '%d months', ", v % 50);
            else imdb_buf_printf(&b, "INTERVAL '%d days', ", v % 50 * 30);
            if (i == n / 2 + 1) imdb_buf_put_str(&b, "'outlier', ");
            else imdb_buf_printf(&b, "'commonprefix-%07d', ", v);
            imdb_buf_printf(&b, "'%s-%07d', ", v % 2 ? "aaaaaaaaaaaa" : "bbbbbbbbbbbb", v);
            if (i == n / 2 + 1) imdb_buf_put_str(&b, "100000000000000000000)");
            else imdb_buf_printf(&b, "%d)", v - 500000);
        }
        CHECK(!imdb_buf_check(&b, &g_e) && !run_buf(&b));
    }
    imdb_buf_free(&b);
    *out = db;
}

/* a statement's first column, every row */
static int64_t *proto_ids(const char *sql, uint64_t *n)
{
    imdb_result r;
    *n = 0;
    if (q(sql, &r)) {
        fprintf(stderr, "    %s: %s\n", sql, g_e.msg);
        return NULL;
    }
    int64_t *ids = calloc(r.nrows ? r.nrows : 1, sizeof *ids);
    for (uint64_t i = 0; i < r.nrows; i++) ids[i] = r.cells[i * r.ncols].null ? INT64_MIN : (int64_t)r.cells[i * r.ncols].v.i;
    *n = r.nrows;
    imdb_result_free(&r);
    return ids;
}

static const char *const k_proto_stmts[] = {
    "SELECT id FROM pt ORDER BY v", "SELECT id FROM pt ORDER BY s", "SELECT id FROM pt ORDER BY p",
    "SELECT id FROM pt ORDER BY vn DESC", "SELECT id FROM pt ORDER BY vn NULLS FIRST", "SELECT id FROM pt ORDER BY g, s",
    "SELECT id FROM pt ORDER BY f DESC", "SELECT id FROM pt ORDER BY d NULLS FIRST", "SELECT id FROM pt ORDER BY d DESC",
    "SELECT id FROM pt ORDER BY iv", "SELECT id FROM pt ORDER BY iv DESC, v", "SELECT id FROM pt ORDER BY id",
    "SELECT id FROM pt ORDER BY id DESC", "SELECT id FROM pt ORDER BY -v", "SELECT id FROM pt ORDER BY s || 'x' DESC",
    "SELECT id FROM pt ORDER BY v % 7, p", "SELECT id FROM pt ORDER BY CASE WHEN v % 2 = 0 THEN v ELSE NULL END",
    "SELECT id FROM pt ORDER BY CASE WHEN v % 2 = 0 THEN 1 ELSE 1.5 END, id DESC",
    "SELECT g FROM pt GROUP BY g ORDER BY COUNT(*) DESC, g", "SELECT g FROM pt GROUP BY g ORDER BY MAX(p) DESC",
    "SELECT a.id FROM pt AS a JOIN pt AS b ON a.g = b.id ORDER BY b.p, a.id",
    "SELECT a.id FROM pt AS a JOIN pt AS b ON a.g = b.id ORDER BY b.vn DESC, a.s",
    "SELECT id FROM pt ORDER BY q", "SELECT id FROM pt ORDER BY q DESC, v", "SELECT id FROM pt ORDER BY c2", "SELECT id FROM pt ORDER BY w",
    "SELECT id FROM pt ORDER BY w DESC", "SELECT id FROM pt ORDER BY CASE WHEN v % 2 = 0 THEN v ELSE v + 0.5 END",
    /* in order for a while, then not: the in-order start the first run */
    "SELECT id FROM pt ORDER BY CASE WHEN id > 2900 THEN -id ELSE id END",
    "SELECT id FROM pt ORDER BY CASE WHEN id % 700 = 0 THEN -id ELSE id END, v",
    /* a first key equal in every row (one to one: the second decides; alone, the default order), a constant TEXT */
    "SELECT id FROM pt ORDER BY v * 0, s DESC", "SELECT id FROM pt ORDER BY v * 0", "SELECT id FROM pt ORDER BY 'k', v",
    /* TEXT whose values end within eight bytes past the shared prefix: one to one (equal images, the second key decides);
     * and values running past them that differ only there (never one to one) */
    "SELECT id FROM pt ORDER BY CAST(v / 5000 AS TEXT), v DESC",
    "SELECT id FROM pt ORDER BY CAST(v / 5000 AS TEXT) || CASE WHEN v % 2 = 0 THEN 'abcdefghij' ELSE 'abcdefghik' END, id DESC"};

/* every statement's order through each mode, cutoff and run length the same as the C library's whole */
static void t_sort_proto_equal(void)
{
    imdb_db *db;
    proto_db(3000, &db);
    CHECK(db);
    static const struct { int mode; size_t run; } cfg[] = {{0, 0}, {0, 1}, {0, 2}, {0, 3}, {0, 7}, {0, 64}, {1, 0}, {1, 64}}; /* (mode 1: no image, xsort) */
    bool updated = false;
    for (size_t s = 0; s < sizeof k_proto_stmts / sizeof *k_proto_stmts; s++) {
        imdb_sql_set_sort_reference(true);
        uint64_t nr, n;
        int64_t *ref = proto_ids(k_proto_stmts[s], &nr);
        imdb_sql_set_sort_reference(false);
        CHECK(ref);
        for (size_t c = 0; c < sizeof cfg / sizeof *cfg; c++) {
            imdb_sql_set_sort_noab(cfg[c].mode == 1);
            imdb_sql_set_sort_run(cfg[c].run);
            int64_t *got = proto_ids(k_proto_stmts[s], &n);
            if (n != nr || (n && memcmp(got, ref, n * sizeof *got))) {
                fprintf(stderr, "    %s: mode %d runs of %zu differs from the reference\n", k_proto_stmts[s], cfg[c].mode, cfg[c].run);
                CHECK(0);
            }
            free(got);
        }
        imdb_sql_set_sort_noab(false);
        imdb_sql_set_sort_run(0);
        free(ref);
        /* then again after a tenth of the rows were updated (their versions last: the walk's keys in key order for nine
         * tenths, then not), once each statement has run */
        if (s + 1 == sizeof k_proto_stmts / sizeof *k_proto_stmts && !updated) {
            RUN("UPDATE pt SET g = g + 1 WHERE id % 10 = 3");
            updated = true;
            s = (size_t)-1;
        }
    }
    done(db);
}


/* topk: ORDER BY ... LIMIT's top-k against the full sort, id for id: every proto statement (single tables of every key
 * type, grouped rows: site 3, a join's pairs: site 8) under eight cuts (LIMIT 0, 1, 7, 100, 100 OFFSET 50, 1 OFFSET 2999,
 * 749 and 5000 of 3,000 rows), by quickselect, by heaps alone and where the default takes it; again after a tenth of the
 * rows were updated; and the top-k ran (its runs counted) */
static void t_sort_topk_equal(void)
{
    imdb_db *db;
    proto_db(3000, &db);
    CHECK(db);
    static const char *const cut[] = {" LIMIT 0", " LIMIT 1", " LIMIT 7", " LIMIT 100", " LIMIT 100 OFFSET 50",
                                      " LIMIT 1 OFFSET 2999", " LIMIT 749", " LIMIT 5000"};
    static const int modes[] = {0, 2, 3};
    /* and DISTINCT, whose window reads past the rows it drops (never the top-k): repeated values under every cut */
    static const char *const dist[] = {"SELECT DISTINCT g FROM pt ORDER BY g DESC", "SELECT DISTINCT v % 13 FROM pt ORDER BY 1",
                                       "SELECT DISTINCT id % 17 FROM pt ORDER BY 1 DESC"};
    const size_t np = sizeof k_proto_stmts / sizeof *k_proto_stmts, nd = sizeof dist / sizeof *dist;
    uint64_t runs0 = imdb_sql_sorts_topk();
    bool updated = false;
    char sql[512];
    for (size_t s = 0; s < np + nd; s++) {
        for (size_t c = 0; c < sizeof cut / sizeof *cut; c++) {
            snprintf(sql, sizeof sql, "%s%s", s < np ? k_proto_stmts[s] : dist[s - np], cut[c]);
            imdb_sql_set_sort_topk(1);
            uint64_t nr, n;
            int64_t *ref = proto_ids(sql, &nr);
            CHECK(ref);
            for (size_t m = 0; m < sizeof modes / sizeof *modes; m++) {
                imdb_sql_set_sort_topk(modes[m]);
                int64_t *got = proto_ids(sql, &n);
                if (!got || n != nr || (n && memcmp(got, ref, n * sizeof *got))) {
                    fprintf(stderr, "    %s: the top-k (mode %d) differs from the full sort (%llu rows, %llu)\n", sql, modes[m],
                            (unsigned long long)n, (unsigned long long)nr);
                    free(got);
                    free(ref);
                    imdb_sql_set_sort_topk(0);
                    CHECK(0);
                }
                free(got);
            }
            free(ref);
        }
        if (s + 1 == np + nd && !updated) {
            imdb_sql_set_sort_topk(0);
            RUN("UPDATE pt SET g = g + 1 WHERE id % 10 = 3");
            updated = true;
            s = (size_t)-1;
        }
    }
    /* again after a CHECKPOINT (the rows' segments written: the matrix's eager and tiny modes then read them from the
     * lake), then with cross_check on (each statement's two plans, each through the top-k, compared by the engine) */
    for (int pass = 0; pass < 2; pass++) {
        imdb_sql_set_sort_topk(0);
        RUN(pass == 0 ? "CHECKPOINT" : "SET cross_check = on");
        uint64_t pr = imdb_sql_sorts_topk();
        for (size_t s = 0; s < np + nd; s++)
            for (size_t c = 0; c < sizeof cut / sizeof *cut; c++) {
                snprintf(sql, sizeof sql, "%s%s", s < np ? k_proto_stmts[s] : dist[s - np], cut[c]);
                imdb_sql_set_sort_topk(1);
                uint64_t nr, n;
                int64_t *ref = proto_ids(sql, &nr);
                CHECK(ref);
                imdb_sql_set_sort_topk(2);
                int64_t *got = proto_ids(sql, &n);
                bool same = got && n == nr && (!n || !memcmp(got, ref, n * sizeof *got));
                free(got);
                free(ref);
                if (!same) {
                    fprintf(stderr, "    %s: the top-k differs from the full sort (%s)\n", sql, pass ? "cross_check" : "after a CHECKPOINT");
                    imdb_sql_set_sort_topk(0);
                    CHECK(0);
                }
            }
        SOFT(imdb_sql_sorts_topk() > pr); /* (this pass's own statements took the top-k, not the full sort twice) */
    }
    RUN("SET cross_check = off");
    imdb_sql_set_sort_topk(0);
    SOFT(imdb_sql_sorts_topk() > runs0);
    done(db);
}

/* topk's measure (printed, never asserted; IMDB_TOPK_MEASURE=rows, else skipped): ORDER BY v and ORDER BY s (TEXT) with
 * LIMIT 1, 10 and 1000, the full sort against the top-k, the statement's time, the least of three */
static void t_sort_topk_measure(void)
{
    const char *env = getenv("IMDB_TOPK_MEASURE");
    if (!env) return;
    int nrows = atoi(env);
    imdb_db *db;
    proto_db(nrows, &db);
    CHECK(db);
    static const char *const keys[] = {"v", "s"};
    static const int lims[] = {1, 10, 1000};
    for (size_t k = 0; k < 2; k++)
        for (size_t l = 0; l < 3; l++) {
            char sql[128];
            snprintf(sql, sizeof sql, "SELECT id FROM pt ORDER BY %s LIMIT %d", keys[k], lims[l]);
            double best[2] = {1e30, 1e30}, s4[2] = {0, 0}, s5[2] = {0, 0}; /* the best run's, and its sites 4 and 5's sorts */
            imdb_sql_sort_time(true);
            for (int run = 0; run < 3; run++)
                for (int full = 0; full < 2; full++) {
                    imdb_sql_set_sort_topk(full ? 1 : 0);
                    imdb_result r;
                    uint64_t a4 = imdb_sql_sort_ns_site(4), a5 = imdb_sql_sort_ns_site(5), t0 = imdb_mono_ns();
                    CHECK(q(sql, &r) == 0);
                    double ms = (double)(imdb_mono_ns() - t0) / 1e6;
                    imdb_result_free(&r);
                    if (ms < best[full])
                        best[full] = ms, s4[full] = (double)(imdb_sql_sort_ns_site(4) - a4) / 1e6,
                        s5[full] = (double)(imdb_sql_sort_ns_site(5) - a5) / 1e6;
                }
            imdb_sql_sort_time(false);
            fprintf(stderr, "    %d rows, %s: full sort %.1f ms (site 4 %.1f, site 5 %.1f), top-k %.1f ms (site 4 %.1f, site 5 %.1f)\n",
                    nrows, sql, best[1], s4[1], s5[1], best[0], s4[0], s5[0]);
        }
    /* the floors: the same rows walked with no key kept (a count over a predicate every row meets, then the ids of
     * every row unsorted, LIMIT cutting the output alone), so a top-k in the walk can be priced before it is built */
    static const char *const floors[] = {"SELECT COUNT(*) FROM pt WHERE v + 0 >= -9223372036854775807",
                                         "SELECT id FROM pt WHERE v + 0 >= -9223372036854775807 LIMIT 1"};
    for (size_t f = 0; f < 2; f++) {
        double best = 1e30;
        for (int run = 0; run < 3; run++) {
            imdb_result r;
            uint64_t t0 = imdb_mono_ns();
            CHECK(q(floors[f], &r) == 0);
            double ms = (double)(imdb_mono_ns() - t0) / 1e6;
            imdb_result_free(&r);
            if (ms < best) best = ms;
        }
        fprintf(stderr, "    %d rows, the floor %s: %.1f ms\n", nrows, floors[f], best);
    }
    imdb_sql_set_sort_topk(0);
    done(db);
}

/* sortpg: the images at their edges, each statement's order against the C library's whole: INT64's ends beside NULLs in
 * both places and directions (a NULL's image a value's), -0 beside 0, DECIMALs past int64 (saturated: equal images, the
 * values in the opposite order to their ids) spread and only late, a value shorter than the others' shared prefix and one
 * exactly it, BYTEA with NULs and the empty string */
static void t_sort_proto_edges(void)
{
    const char *dir = test_tmpdir();
    imdb_err e = {0};
    CHECK(!imdb_init(dir, false, NULL, &e));
    imdb_db *db = open_db(dir);
    CHECK(db);
    imdb_session_init(&g_ss, db);
    RUN("CREATE TABLE pe (id INT64 PRIMARY KEY, i INT64, f FLOAT64, d DECIMAL(38,0), d2 DECIMAL(38,0), t TEXT, b BYTEA, u UUID)");
    imdb_buf b;
    imdb_buf_init(&b);
    imdb_buf_put_str(&b, "INSERT INTO pe VALUES ");
    for (int k = 0; k < 300; k++) {
        imdb_buf_printf(&b, "%s(%d, ", k ? ", " : "", k + 1);
        if (k % 10 == 0) imdb_buf_put_str(&b, "NULL, ");
        else if (k % 10 == 1) imdb_buf_put_str(&b, "9223372036854775807, ");
        else if (k % 10 == 2) imdb_buf_put_str(&b, "-9223372036854775808, ");
        else imdb_buf_printf(&b, "%d, ", (k * 7919) % 1000 - 500);
        if (k % 10 == 0) imdb_buf_put_str(&b, "NULL, ");
        else if (k % 3 == 0) imdb_buf_put_str(&b, "0.0, ");
        else imdb_buf_printf(&b, "%d.5, ", k % 50 - 25);
        if (k % 10 == 0) imdb_buf_put_str(&b, "NULL, ");
        else if (k % 25 == 1) imdb_buf_printf(&b, "%d00000000000000000000, ", 300 - k);
        else if (k % 25 == 2) imdb_buf_printf(&b, "-%d00000000000000000000, ", 300 - k);
        else imdb_buf_printf(&b, "%d, ", k * 1000 - 150000);
        if (k >= 290) imdb_buf_printf(&b, "%d00000000000000000000, ", 300 - k);
        else imdb_buf_printf(&b, "%d, ", (k * 37) % 300 - 150);
        if (k % 10 == 0) imdb_buf_put_str(&b, "NULL, ");
        else if (k == 5) imdb_buf_put_str(&b, "'ab', ");
        else if (k == 6) imdb_buf_put_str(&b, "'abc', ");
        else if (k == 7) imdb_buf_put_str(&b, "'abcd', ");
        else imdb_buf_printf(&b, "'abcd%03d', ", (k * 37) % 300);
        if (k % 10 == 0) imdb_buf_put_str(&b, "NULL, ");
        else if (k % 7 == 0) imdb_buf_printf(&b, "'\\x%04x00', ", (k * 37) % 300 / 2); /* X and X 00: one image, two values */
        else if (k == 1) imdb_buf_put_str(&b, "'\\x00', ");
        else if (k == 2) imdb_buf_put_str(&b, "'\\x0000', ");
        else if (k == 3) imdb_buf_put_str(&b, "'\\x', ");
        else if (k == 4) imdb_buf_put_str(&b, "'\\x00ff', ");
        else imdb_buf_printf(&b, "'\\x%04x', ", (k * 37) % 300 / 2);
        /* a UUID: its first ten bytes shared, fifty values (one to one past the prefix: one length) */
        if (k % 10 == 0) imdb_buf_put_str(&b, "NULL)");
        else imdb_buf_printf(&b, "'00000000-0000-0000-0000-0000%08x')", (unsigned)((k * 37) % 50) * 0x01010101u);
    }
    CHECK(!imdb_buf_check(&b, &g_e) && !run_buf(&b));
    imdb_buf_free(&b);
    static const char *const ks[] = {
        "i", "i DESC", "i NULLS FIRST", "i DESC NULLS LAST", "f * CASE WHEN id % 2 = 0 THEN -1.0 ELSE 1.0 END", "-f",
        "f DESC", "d", "d DESC", "d NULLS FIRST", "d2", "d2 DESC", "t", "t DESC", "t NULLS FIRST", "b", "b DESC",
        "b NULLS FIRST", "i, t", "d, i DESC", "t, b", "u, i DESC", "u DESC NULLS LAST, id DESC"};
    for (size_t k = 0; k < sizeof ks / sizeof *ks; k++) {
        char sql[160];
        snprintf(sql, sizeof sql, "SELECT id FROM pe ORDER BY %s", ks[k]);
        imdb_sql_set_sort_reference(true);
        uint64_t nr, n;
        int64_t *ref = proto_ids(sql, &nr);
        imdb_sql_set_sort_reference(false);
        CHECK(ref && nr == 300);
        static const size_t cut[] = {0, 1, 3};
        for (size_t c = 0; c < 3; c++) {
            imdb_sql_set_sort_run(cut[c]);
            int64_t *got = proto_ids(sql, &n);
            if (n != nr || memcmp(got, ref, n * sizeof *got)) {
                fprintf(stderr, "    %s (runs of %zu): differs from the reference\n", sql, cut[c]);
                CHECK(0);
            }
            free(got);
        }
        imdb_sql_set_sort_run(0);
        free(ref);
    }
    done(db);
}

/* printed only (IMDB_SORT_MEASURE=1): an ORDER BY's sorts by site (4: the walk's keys by the primary key; 5: ORDER BY's),
 * and how far site 4's input is in order already, on a table inserted in key order, then in segments (CHECKPOINTs), then
 * with a tenth of its rows updated, then inserted in another order */
static void t_sort_site4(void)
{
    imdb_sql_set_sort_topk(1); /* topk: this measures the full sort (LIMIT 1 is only its output's cut) */
    if (!getenv("IMDB_SORT_MEASURE")) return;
    int n = getenv("IMDB_SORT_ROWS") ? atoi(getenv("IMDB_SORT_ROWS")) : 200000;
    imdb_db *db;
    proto_db(n, &db);
    CHECK(db);
    for (int stage = 0; stage < 4; stage++) {
        if (stage == 1)
            for (int k = 0; k < 4; k++) {
                char sql[96];
                snprintf(sql, sizeof sql, "UPDATE pt SET g = g + 1 WHERE id %% 4 = %d AND id %% 10 = 0", k);
                RUN(sql);
                RUN("CHECKPOINT");
            }
        if (stage == 2) RUN("UPDATE pt SET v = v + 1 WHERE id % 10 = 3");
        if (stage == 3) {
            RUN("CREATE TABLE pr (id INT64 PRIMARY KEY, v INT64)");
            RUN("INSERT INTO pr SELECT v, id FROM pt");
        }
        const char *sql = stage == 3 ? "SELECT id FROM pr ORDER BY v LIMIT 1" : "SELECT id FROM pt ORDER BY v LIMIT 1";
        uint64_t n4 = imdb_sql_sort_ns_site(4), n5 = imdb_sql_sort_ns_site(5), io0, nn0, io1, nn1, pre[2] = {0, 0};
        imdb_sql_sort_inorder(4, &io0, &nn0);
        imdb_sql_sort_time(true);
        for (int r = 0; r < 3; r++) CHECK(run(sql) == 0);
        imdb_sql_sort_time(false);
        imdb_sql_sort_inorder(4, &io1, &nn1);
        for (int r = 0; r < 10; r++) /* the in-order pass's cost: site 4 with it and without, alternating */
            for (int np = 0; np < 2; np++) {
                imdb_sql_set_sort_nopre(np == 1);
                uint64_t a = imdb_sql_sort_ns_site(4);
                imdb_sql_sort_time(true);
                CHECK(run(sql) == 0);
                imdb_sql_sort_time(false);
                pre[np] += imdb_sql_sort_ns_site(4) - a;
            }
        imdb_sql_set_sort_nopre(false);
        fprintf(stderr, "      site 4 alternating, ten each: with the in-order pass %.1f ms, without %.1f ms\n", (double)pre[0] / 1e7,
                (double)pre[1] / 1e7);
        static const char *const what[4] = {"inserted in key order", "after updates and CHECKPOINTs (segments)",
                                            "a tenth updated since", "another table inserted out of key order"};
        fprintf(stderr, "    %d rows, %s: site 4 %.1f ms (in order %.1f%% of %llu), site 5 %.1f ms\n", n, what[stage],
                (double)(imdb_sql_sort_ns_site(4) - n4) / 3e6, nn1 > nn0 ? 100.0 * (double)(io1 - io0) / (double)(nn1 - nn0) : 0,
                (unsigned long long)((nn1 - nn0) / 3), (double)(imdb_sql_sort_ns_site(5) - n5) / 3e6);
    }
    done(db);
}

/* sortpg: every size from 2 to 300 rows (the stack's 128 and 129, odd sizes, merges whose shorter side is half), each
 * key and site against the C library's whole, in runs of the default, 1 and 3 */
static void t_sort_proto_sizes(void)
{
    imdb_db *db;
    proto_db(300, &db);
    CHECK(db);
    static const char *const ks[][2] = {{"SELECT id FROM pt WHERE id <=", "ORDER BY v"}, {"SELECT id FROM pt WHERE id <=", "ORDER BY s DESC"},
                                        {"SELECT id FROM pt WHERE id <=", "ORDER BY p"}, {"SELECT id FROM pt WHERE id <=", "ORDER BY vn DESC, s"},
                                        {"SELECT id FROM pt WHERE id <=", "ORDER BY q"}, /* (the outlier past 150: no image) */
                                        {"SELECT id FROM pt WHERE id <=", "GROUP BY id ORDER BY MAX(s)"}, /* site 3 */
                                        {"SELECT a.id FROM pt AS a JOIN pt AS b ON a.id = b.id WHERE a.id <=", "ORDER BY b.f DESC"}}; /* 8 */
    static const size_t runs[] = {0, 1, 3};
    int bad = 0;
    for (int nr = 2; nr <= 300 && bad < 5; nr++)
        for (size_t k = 0; k < sizeof ks / sizeof *ks; k++) {
            char sql[200];
            snprintf(sql, sizeof sql, "%s %d %s", ks[k][0], nr, ks[k][1]);
            imdb_sql_set_sort_reference(true);
            uint64_t n0, n;
            int64_t *ref = proto_ids(sql, &n0);
            imdb_sql_set_sort_reference(false);
            CHECK(ref && n0 == (uint64_t)nr);
            for (size_t r = 0; r < 3; r++) {
                imdb_sql_set_sort_run(runs[r]);
                int64_t *got = proto_ids(sql, &n);
                if (n != n0 || memcmp(got, ref, n * sizeof *got)) {
                    fprintf(stderr, "    %s (runs of %zu): differs from the reference\n", sql, runs[r]);
                    bad++;
                }
                free(got);
            }
            imdb_sql_set_sort_run(0);
            free(ref);
        }
    CHECK(bad == 0);
    done(db);
}
/* printed only (IMDB_SORT_MEASURE=1): the sort's own time (and the statement's) by method, keys and size */
static void t_sort_proto_measure(void)
{
    imdb_sql_set_sort_topk(1); /* topk: this measures the full sort (LIMIT 1 is only its output's cut) */
    if (!getenv("IMDB_SORT_MEASURE")) return;
    static const int rows[6] = {10, 100, 500, 5000, 50000, 1000000}, reps[6] = {20000, 4000, 1000, 200, 20, 3};
    static const char *const ms[] = {"v", "s", "p", "q", "c2", "vn DESC", "g, s", "f", "d", "w", "CASE WHEN v % 2 = 0 THEN v ELSE v + 0.5 END", "id",
                                     /* low-cardinality TEXT (the advisor, 11-21) */
                                     "CAST(v % 20 AS TEXT)", "CAST(v % 200 AS TEXT)", "CAST(v % 2000 AS TEXT)", "CAST(v % 200 AS TEXT), v",
                                     "'category-' || CAST(v % 200 AS TEXT) || '-suffix'", "CAST(v / 50000 AS TEXT)", "CAST(v / 5000 AS TEXT)",
                                     "CAST(v / 5000 AS TEXT), v", "'category-' || CAST(v / 5000 AS TEXT) || '-suffix'",
                                     "'category-' || CAST(v / 5000 AS TEXT) || '-suffix', v",
                                     "'category-' || CAST(v / 500 AS TEXT) || '-suffix', v", "'category-' || CAST(v / 50 AS TEXT) || '-suffix', v",
                                     "'category-' || CAST(v / 5 AS TEXT) || '-suffix', v"};
    static const char *const mname[3] = {"qsort", "xsort", "msort"}; /* (xsort: the merge of words, no image) */
    const char *sz = getenv("IMDB_SORT_SIZES"); /* (a subset: "012") */
    const char *only_s = getenv("IMDB_SORT_STMT"), *only_m = getenv("IMDB_SORT_MODE"); /* (a profile's: one of each) */
    for (int c = 0; c < 6; c++) {
        if (sz && !strchr(sz, '0' + c)) continue;
        imdb_db *db;
        proto_db(rows[c], &db);
        CHECK(db);
        fprintf(stderr, "    %d rows (%d repetitions, alternating): the sort's ms a statement [the statement's]\n", rows[c], reps[c]);
        for (size_t s = 0; s < sizeof ms / sizeof *ms; s++) {
            if (only_s && strcmp(only_s, ms[s])) continue;
            char sql[128];
            snprintf(sql, sizeof sql, "SELECT id FROM pt ORDER BY %s LIMIT 1", ms[s]);
            double sort_ms[3] = {0}, st_ms[3] = {0};
            for (int rep = 0; rep < reps[c]; rep++)
                for (int m = 0; m < 3; m++) {
                    if (only_m && atoi(only_m) != m) continue;
                    imdb_sql_set_sort_reference(m == 0);
                    imdb_sql_set_sort_noab(m == 1);
                    uint64_t n0 = imdb_sql_sort_ns();
                    imdb_sql_sort_time(true);
                    double t0 = now_ms();
                    CHECK(run(sql) == 0);
                    st_ms[m] += now_ms() - t0;
                    imdb_sql_sort_time(false);
                    sort_ms[m] += (double)(imdb_sql_sort_ns() - n0) / 1e6;
                }
            imdb_sql_set_sort_reference(false);
            imdb_sql_set_sort_noab(false);
            fprintf(stderr, "      %-24.24s", ms[s]);
            for (int m = 0; m < 3; m++)
                fprintf(stderr, " %s %.3f [%.3f] |", mname[m], sort_ms[m] / reps[c], st_ms[m] / reps[c]);
            fprintf(stderr, "\n");
        }
        done(db);
    }
}
const test_case cancel_tests[] = {
    {"cancel_timeout_paths", t_timeout_paths},
    {"cancel_timeout_writes", t_timeout_writes},
    {"cancel_timeout_write_phase", t_timeout_write_phase},
    {"cancel_thread", t_cancel_thread},
    {"cancel_held", t_cancel_held},
    {"cancel_sort_stops", t_sort_stops},
    {"cancel_sort_order", t_sort_order},
    {"cancel_sort_measure", t_sort_measure},
    {"cancel_sort_gap", t_sort_gap},
    {"cancel_sort_measure_mid", t_sort_measure_mid},
    {"cancel_sort_proto_equal", t_sort_proto_equal},
    {"cancel_sort_topk_equal", t_sort_topk_equal},
    {"cancel_sort_topk_measure", t_sort_topk_measure},
    {"cancel_sort_proto_edges", t_sort_proto_edges},
    {"cancel_sort_proto_sizes", t_sort_proto_sizes},
    {"cancel_sort_proto_measure", t_sort_proto_measure},
    {"cancel_sort_site4", t_sort_site4},
    {"cancel_txn_timeout", t_txn_timeout},
    {"cancel_txn_idle_timeout", t_txn_idle_timeout},
    {"cancel_txn_idle_sweep", t_txn_idle_sweep},
    {"cancel_txn_idle_sweep_active", t_txn_idle_sweep_active},
    {"cancel_row_limit_paths", t_row_limit_paths},
    {"cancel_row_limit_join", t_row_limit_join},
    {"cancel_row_limit_write", t_row_limit_write},
};
const size_t cancel_ntests = sizeof cancel_tests / sizeof *cancel_tests;
