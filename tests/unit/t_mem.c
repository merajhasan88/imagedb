/* The memory budget (db.h, deferred.md R4): what the database holds, by kind; a write on the
 * primary refused at the growth step that would cross the budget, before anything is logged; the
 * ways down (DELETE, CHECKPOINT, COMPACT ... PURGE, ERASE) never refused; an open never refused; a
 * replica over its budget stopping before a commit, consistent; a result over its cap refused; and
 * the accounting against what the process holds (RSS). */
#include <fcntl.h>
#include <malloc.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "../../src/db_internal.h"
#include "../../src/lake.h"
#include "../../src/sql.h"
#include "thelp.h"

static imdb_db *open_budget(const char *dir, uint64_t limit)
{
    imdb_open_opts o = {.sync = 1, .mem_limit = limit};
    imdb_db *db = NULL;
    imdb_err_clear(E);
    return imdb_open(dir, &o, &db, E) ? NULL : db;
}

static int verify_db(imdb_db *db)
{
    imdb_verify_report vr;
    imdb_err_clear(E);
    return imdb_verify(db, &vr, E);
}

static int run(imdb_session *s, const char *sql, imdb_result *r)
{
    imdb_err_clear(E);
    return imdb_exec_one(s, sql, strlen(sql), NULL, 0, r, E);
}

static uint64_t held(imdb_db *db)
{
    imdb_mem_report m;
    imdb_mem(db, &m);
    return m.total;
}

/* Refused at a growth step with nothing written, never above the budget, the database consistent
 * after; the ways down go through over it; an open over it succeeds; a larger budget goes on. */
static void t_mem_admission(void)
{
    const char *dir = test_tmpdir();
    OK(imdb_init(dir, false, NULL, E));
    imdb_db *db = open_budget(dir, 0);
    CHECK(db);
    if (!db) return;
    OK(make_table(db, E));
    uint64_t budget = held(db) + (256u << 10);
    imdb_close(db);
    db = open_budget(dir, budget);
    CHECK(db);
    if (!db) return;
    int64_t id = 1;
    int rc = IMDB_OK;
    uint64_t before = 0;
    for (; id < 1000000; id++) {
        before = db->seq;
        if ((rc = ins1(db, id, id % 5, 100, "a row with some text in it"))) break;
    }
    CHECK(rc == IMDB_ERR_LIMIT && strstr(g_e.msg, "growth step") && strstr(g_e.msg, "nothing was written"));
    CHECK(db->seq == before && held(db) <= budget); /* the refused insert left no commit and no growth */
    OK(verify_db(db));
    imdb_session s;
    imdb_session_init(&s, db);
    imdb_result r;
    OK(run(&s, "SHOW MEMORY", &r));
    CHECK(r.nrows == 7 && strstr(r.status, "budget"));
    imdb_result_free(&r);
    /* the ways down, over the budget or not */
    OK(run(&s, "DELETE FROM txns WHERE id = 1", &r));
    imdb_result_free(&r);
    OK(run(&s, "CHECKPOINT", &r));
    imdb_result_free(&r);
    OK(run(&s, "ERASE SUBJECT 3", &r));
    imdb_result_free(&r);
    char purge[64];
    snprintf(purge, sizeof purge, "COMPACT txns PURGE BEFORE %llu", (unsigned long long)db->seq);
    OK(run(&s, purge, &r));
    imdb_result_free(&r);
    OK(verify_db(db));
    imdb_session_close(&s);
    uint64_t now = held(db);
    imdb_close(db);
    db = open_budget(dir, now / 2); /* an open never fails for its budget */
    CHECK(db);
    if (db) {
        imdb_session_init(&s, db);
        OK(run(&s, "SHOW MEMORY", &r));
        CHECK(strstr(r.status, "over it"));
        imdb_result_free(&r);
        imdb_session_close(&s);
        imdb_close(db);
    }
    db = open_budget(dir, budget * 8);
    CHECK(db);
    if (db) {
        OK(ins1(db, id + 10, 1, 1, "more"));
        OK(verify_db(db));
        imdb_close(db);
    }
}

/* A result has its own cap: a quarter of the budget, or IMDB_MAX_RESULT_BYTES. */
static void t_mem_result_cap(void)
{
    const char *dir = test_tmpdir();
    OK(imdb_init(dir, false, NULL, E));
    imdb_db *db = open_budget(dir, 0);
    CHECK(db);
    if (!db) return;
    OK(make_table(db, E));
    for (int64_t id = 1; id <= 4000; id++) OK(ins1(db, id, id % 7, id, "a memo long enough to count for something"));
    uint64_t budget = held(db) * 2;
    imdb_close(db);
    db = open_budget(dir, budget);
    CHECK(db);
    if (!db) return;
    imdb_session s;
    imdb_session_init(&s, db);
    imdb_result r;
    CHECK(run(&s, "SELECT * FROM txns", &r) == IMDB_ERR_LIMIT && strstr(g_e.msg, "result over its cap"));
    imdb_result_free(&r);
    OK(run(&s, "SELECT * FROM txns LIMIT 10", &r));
    CHECK(r.nrows == 10);
    imdb_result_free(&r);
    OK(run(&s, "SELECT COUNT(*) FROM txns", &r));
    imdb_result_free(&r);
    imdb_session_close(&s);
    imdb_close(db);
}

/* A replica cannot refuse a logged commit: over its budget it stops before the next one, its state
 * consistent, and goes on once reopened with a larger budget. */
static void t_mem_replica(void)
{
    const char *tmp = test_tmpdir();
    char p[600], rr[600], st[700];
    snprintf(p, sizeof p, "%s/p", tmp);
    snprintf(rr, sizeof rr, "%s/r", tmp);
    snprintf(st, sizeof st, "%s/stream", tmp);
    OK(imdb_init(p, false, NULL, E));
    OK(imdb_init(rr, true, p, E));
    imdb_db *db = open_budget(p, 0);
    CHECK(db);
    if (!db) return;
    OK(make_table(db, E));
    for (int64_t id = 1; id <= 3000; id++) OK(ins1(db, id, id % 7, id, "replicated row"));
    uint64_t last = db->seq;
    imdb_close(db);
    OK(ship_to_file(p, 0, st, E));
    imdb_db *rep = open_budget(rr, 0);
    CHECK(rep);
    if (!rep) return;
    uint64_t base = held(rep);
    imdb_close(rep);
    rep = open_budget(rr, base + (128u << 10));
    CHECK(rep);
    if (!rep) return;
    uint64_t applied = 0;
    int fd = open(st, O_RDONLY | O_CLOEXEC);
    imdb_err_clear(E);
    int rc = imdb_apply_stream(rep, fd, &applied, E);
    close(fd);
    CHECK(rc == IMDB_ERR_LIMIT && strstr(g_e.msg, "stops before commit") && rep->seq < last && !rep->failed);
    OK(verify_db(rep));
    imdb_close(rep);
    rep = open_budget(rr, 0); /* reopened without the budget: it goes on from where it stopped */
    CHECK(rep);
    if (!rep) return;
    uint64_t from = rep->seq;
    OK(ship_to_file(p, from, st, E));
    fd = open(st, O_RDONLY | O_CLOEXEC);
    OK(imdb_apply_stream(rep, fd, &applied, E));
    close(fd);
    CHECK(rep->seq == last);
    OK(verify_db(rep));
    imdb_close(rep);
}

#if defined(__SANITIZE_ADDRESS__) || defined(__SANITIZE_THREAD__)
#define RSS_MEANINGFUL 0
#elif defined(__has_feature)
#if __has_feature(address_sanitizer) || __has_feature(thread_sanitizer) || __has_feature(memory_sanitizer)
#define RSS_MEANINGFUL 0
#endif
#endif
#ifndef RSS_MEANINGFUL
#define RSS_MEANINGFUL 1
#endif

/* Resident bytes after malloc_trim: memory freed earlier (by other tests in this process, or by
 * the round's own transient copies) goes back to the kernel first; otherwise later allocations
 * reuse it without growing RSS, and the accounting would look like an overcount it is not. */
static bool thp_always(void)
{
    char b[128] = {0};
    FILE *f = fopen("/sys/kernel/mm/transparent_hugepage/enabled", "r");
    if (f) {
        if (!fgets(b, sizeof b, f)) b[0] = 0;
        fclose(f);
    }
    return strstr(b, "[always]") != NULL;
}

static uint64_t rss_bytes(void)
{
    malloc_trim(0);
    FILE *f = fopen("/proc/self/statm", "r");
    unsigned long long size = 0, res = 0;
    if (f) {
        if (fscanf(f, "%llu %llu", &size, &res) != 2) res = 0;
        fclose(f);
    }
    return (uint64_t)res * (uint64_t)sysconf(_SC_PAGESIZE);
}

/* ids 1..n in one INSERT: the live set the churn tests update */
static int load_live_memo(imdb_session *s, int64_t n, const char *memo)
{
    imdb_result r;
    imdb_buf ins;
    imdb_buf_init(&ins);
    imdb_buf_put(&ins, "INSERT INTO txns VALUES ", 24);
    for (int64_t id = 1; id <= n; id++) {
        char v[192];
        int k = snprintf(v, sizeof v, "%s(%lld, %lld, %lld, '%s')", id > 1 ? ", " : "", (long long)id,
                         (long long)(id % 9), (long long)id, memo);
        if (k < 0 || (size_t)k >= sizeof v) {
            imdb_buf_free(&ins);
            return imdb_fail(E, IMDB_ERR_INVALID, "load_live: a row does not fit its buffer");
        }
        imdb_buf_put(&ins, v, (size_t)k);
    }
    int rc = imdb_buf_check(&ins, E);
    if (!rc) rc = imdb_exec_one(s, (const char *)ins.p, ins.len, NULL, 0, &r, E);
    if (!rc) imdb_result_free(&r);
    imdb_buf_free(&ins);
    return rc;
}

static int load_live(imdb_session *s, int64_t n) { return load_live_memo(s, n, "the live set"); }

/* Sustained churn on a fixed live set, with periodic CHECKPOINT and COMPACT ... PURGE: the
 * accounting against the process's resident memory at a few points (within a factor: it counts
 * capacity, malloc keeps what it frees); and what churn costs that purges do not return (each
 * update leaves a version entry: history tombstones are stage 2 of R4). */
static void t_mem_churn(void)
{
    const char *dir = test_tmpdir();
    OK(imdb_init(dir, false, NULL, E));
    imdb_open_opts o = {.sync = 0}; /* memory, not durability: no fdatasync per commit */
    imdb_db *db = NULL;
    OK(imdb_open(dir, &o, &db, E));
    CHECK(db);
    if (!db) return;
    OK(make_table(db, E));
    enum { LIVE = 12000, ROUNDS = 8 };
    imdb_session s;
    imdb_session_init(&s, db);
    imdb_result r;
    OK(load_live(&s, LIVE));
    uint64_t rss0 = rss_bytes(), acc0 = held(db), acc_at[ROUNDS], rss_at[ROUNDS];
    for (int k = 0; k < ROUNDS; k++) {
        char q[160];
        snprintf(q, sizeof q, "UPDATE txns SET amount = %d WHERE id > 0", k + 2);
        OK(run(&s, q, &r));
        imdb_result_free(&r);
        OK(run(&s, "CHECKPOINT", &r));
        imdb_result_free(&r);
        snprintf(q, sizeof q, "COMPACT txns PURGE BEFORE %llu", (unsigned long long)db->seq);
        OK(run(&s, q, &r));
        imdb_result_free(&r);
        acc_at[k] = held(db);
        rss_at[k] = rss_bytes();
    }
    imdb_session_close(&s);
    /* With malloc_trim before each reading, resident growth follows the accounting: within 1.1% at
     * every round, alone, in the whole suite and single-threaded (2026-10-23), and 1.65-2.2x above
     * it with the segments left out of imdb_mem. So both directions are held to 10% at every round
     * past the first three: an accounting gap of a tenth of the growth fails. Transparent huge
     * pages set to always make RSS move in 2 MiB steps: there the bound is 1.5x. Sanitizers
     * inflate RSS (shadow memory, quarantine): no RSS check. */
    uint64_t tol = thp_always() ? 150 : 110;
    for (int k = 3; k < ROUNDS; k++) {
        uint64_t da = acc_at[k] - acc0, dr = rss_at[k] > rss0 ? rss_at[k] - rss0 : 0;
        printf("    churn round %d: accounted +%llu, rss +%llu\n", k + 1, (unsigned long long)da, (unsigned long long)dr);
        CHECK(!RSS_MEANINGFUL || (dr * 100 <= da * tol && da * 100 <= dr * tol));
    }
    printf("    churn: %d rounds over %d live rows: accounted %llu -> %llu bytes, rss +%llu\n", ROUNDS, LIVE,
           (unsigned long long)acc0, (unsigned long long)acc_at[ROUNDS - 1],
           (unsigned long long)(rss_at[ROUNDS - 1] > rss0 ? rss_at[ROUNDS - 1] - rss0 : 0));
    OK(verify_db(db));
    imdb_close(db);
}

/* Parking a transaction (another session's write needs the engine) copies its writes: new memory,
 * admitted like any growth. Refused past the budget, with the transaction intact, and committable. */
static void t_mem_park(void)
{
    const char *dir = test_tmpdir();
    OK(imdb_init(dir, false, NULL, E));
    imdb_db *db = open_budget(dir, 0);
    CHECK(db);
    if (!db) return;
    OK(make_table(db, E));
    imdb_session a, b;
    imdb_session_init(&a, db);
    imdb_session_init(&b, db);
    imdb_result r;
    OK(run(&a, "BEGIN", &r));
    imdb_result_free(&r);
    for (int i = 1; i <= 200; i++) {
        char q[160];
        snprintf(q, sizeof q, "INSERT INTO txns VALUES (%d, %d, %d, 'a pending row of the open transaction')", i, i % 3, i);
        OK(run(&a, q, &r));
        imdb_result_free(&r);
    }
    db->mem_limit = held(db) + 1024; /* room for B's own row, not for a copy of A's 200 */
    CHECK(run(&b, "INSERT INTO txns VALUES (1000, 1, 1, 'b')", &r) == IMDB_ERR_LIMIT && strstr(g_e.msg, "budget"));
    imdb_result_free(&r);
    db->mem_limit = 0;
    OK(run(&a, "COMMIT", &r)); /* intact: still the active transaction */
    imdb_result_free(&r);
    OK(run(&b, "SELECT COUNT(*) FROM txns", &r));
    CHECK(r.nrows == 1 && r.cells[0].v.i == 200);
    imdb_result_free(&r);
    imdb_session_close(&a);
    imdb_session_close(&b);
    OK(verify_db(db));
    imdb_close(db);
}

/* ---- automatic retention (--retain-history; db.c retain) --------------------------------- */

static imdb_db *open_retain(const char *dir, uint64_t commits)
{
    imdb_open_opts o = {.sync = 0, .retain_commits = commits}; /* the policy, not durability */
    imdb_db *db = NULL;
    imdb_err_clear(E);
    return imdb_open(dir, &o, &db, E) ? NULL : db;
}

static int exec_free(imdb_session *s, const char *sql)
{
    imdb_result r;
    int rc = run(s, sql, &r);
    if (!rc) imdb_result_free(&r);
    return rc;
}

/* Due once a table has ended as many versions as it holds live (above IMDB_RETAIN_MIN_ENDED),
 * not one version earlier; a purge starts the count again. */
static void t_mem_retain_threshold(void)
{
    const char *dir = test_tmpdir();
    OK(imdb_init(dir, false, NULL, E));
    imdb_db *db = open_retain(dir, 1);
    CHECK(db);
    if (!db) return;
    OK(make_table(db, E));
    imdb_session s;
    imdb_session_init(&s, db);
    enum { LIVE = 5000 };
    CHECK(LIVE > IMDB_RETAIN_MIN_ENDED);
    OK(load_live(&s, LIVE));
    imdb_table *t = db->t[0];
    OK(exec_free(&s, "UPDATE txns SET amount = 2 WHERE id < 5000"));
    CHECK(t->ended == LIVE - 1 && t->horizon == 0);
    uint64_t before = db->seq;
    OK(exec_free(&s, "UPDATE txns SET amount = 3 WHERE id = 5000")); /* the 5,000th: due */
    CHECK(t->horizon == before && t->ended == 0); /* floor: the commit before the last N = 1 */
    uint64_t h = t->horizon;
    OK(exec_free(&s, "UPDATE txns SET amount = 4 WHERE id = 1"));
    CHECK(t->horizon == h && t->ended == 1);
    imdb_session_close(&s);
    OK(verify_db(db));
    imdb_close(db);
}

/* A small table waits for IMDB_RETAIN_MIN_ENDED, so tiny tables are not rewritten constantly. */
static void t_mem_retain_floor(void)
{
    const char *dir = test_tmpdir();
    OK(imdb_init(dir, false, NULL, E));
    imdb_db *db = open_retain(dir, 1);
    CHECK(db);
    if (!db) return;
    OK(make_table(db, E));
    imdb_session s;
    imdb_session_init(&s, db);
    OK(load_live(&s, 100));
    imdb_table *t = db->t[0];
    int rounds = 0;
    while (t->horizon == 0 && rounds < 100) {
        char q[96];
        snprintf(q, sizeof q, "UPDATE txns SET amount = %d WHERE id > 0", ++rounds);
        OK(exec_free(&s, q));
    }
    CHECK(rounds == (IMDB_RETAIN_MIN_ENDED + 99) / 100); /* 41: the first count past 4,096 */
    imdb_session_close(&s);
    OK(verify_db(db));
    imdb_close(db);
}

/* An open transaction's snapshot caps the floor, while it is parked and another session's
 * statement runs the policy; its reads still answer; once it ends, purges pass it. */
static void t_mem_retain_open_txn(void)
{
    const char *dir = test_tmpdir();
    OK(imdb_init(dir, false, NULL, E));
    imdb_db *db = open_retain(dir, 1);
    CHECK(db);
    if (!db) return;
    OK(make_table(db, E));
    imdb_session a, b;
    imdb_session_init(&a, db);
    imdb_session_init(&b, db);
    OK(load_live(&b, 5000));
    imdb_table *t = db->t[0];
    imdb_result r;
    OK(exec_free(&a, "BEGIN"));
    OK(run(&a, "SELECT SUM(amount) FROM txns", &r));
    imdb_result_free(&r);
    uint64_t S = db->seq; /* a's snapshot */
    for (int i = 1; i <= 10; i++) { /* the window's floor moves past S */
        char q[96];
        snprintf(q, sizeof q, "UPDATE txns SET amount = 0 WHERE id = %d", i);
        OK(exec_free(&b, q));
    }
    OK(exec_free(&b, "UPDATE txns SET amount = 7 WHERE id > 0")); /* due */
    CHECK(t->horizon == S);
    OK(run(&a, "SELECT SUM(amount) FROM txns", &r)); /* its snapshot: the loaded amounts, 1..5000 (DECIMAL, scale 2) */
    CHECK(r.nrows == 1 && !r.cells[0].null && (r.cells[0].wide ? r.cells[0].i128 : r.cells[0].v.i) == 5000 * 5001 / 2 * 100);
    imdb_result_free(&r);
    OK(exec_free(&a, "COMMIT"));
    OK(exec_free(&b, "UPDATE txns SET amount = 8 WHERE id > 0")); /* due again, nothing holds S */
    CHECK(t->horizon > S);
    imdb_session_close(&a);
    imdb_session_close(&b);
    OK(verify_db(db));
    imdb_close(db);
}

/* Replicas replay the logged purges: the same horizon and digest; the option is the primary's. */
static void t_mem_retain_replica(void)
{
    const char *tmp = test_tmpdir();
    char p[600], rr[600], st[700];
    snprintf(p, sizeof p, "%s/p", tmp);
    snprintf(rr, sizeof rr, "%s/r", tmp);
    snprintf(st, sizeof st, "%s/stream", tmp);
    OK(imdb_init(p, false, NULL, E));
    OK(imdb_init(rr, true, p, E));
    imdb_db *db = open_retain(p, 1);
    CHECK(db);
    if (!db) return;
    OK(make_table(db, E));
    imdb_session s;
    imdb_session_init(&s, db);
    OK(load_live(&s, 5000));
    for (int k = 0; k < 3; k++) {
        char q[96];
        snprintf(q, sizeof q, "UPDATE txns SET amount = %d WHERE id > 0", k + 2);
        OK(exec_free(&s, q));
    }
    imdb_session_close(&s);
    uint64_t horizon = db->t[0]->horizon, last = db->seq;
    uint8_t d[IMDB_HASH_LEN], dr[IMDB_HASH_LEN];
    imdb_lthash_digest(db->meta.digest_alg, &db->global, d);
    CHECK(horizon > 0);
    imdb_close(db);
    OK(ship_to_file(p, 0, st, E));
    CHECK(!open_retain(rr, 1) && strstr(g_e.msg, "--retain-history is set on the primary"));
    imdb_open_opts ro = {.read_only = true, .retain_commits = 1};
    imdb_db *x = NULL;
    imdb_err_clear(E);
    CHECK(imdb_open(p, &ro, &x, E) == IMDB_ERR_INVALID && !x);
    imdb_db *rep = open_budget(rr, 0);
    CHECK(rep);
    if (!rep) return;
    uint64_t applied = 0;
    int fd = open(st, O_RDONLY | O_CLOEXEC);
    OK(imdb_apply_stream(rep, fd, &applied, E));
    close(fd);
    imdb_lthash_digest(rep->meta.digest_alg, &rep->global, dr);
    CHECK(rep->seq == last && rep->t[0]->horizon == horizon && memcmp(d, dr, sizeof d) == 0);
    OK(verify_db(rep));
    imdb_close(rep);
}

/* Churn with the policy on and no manual PURGE, against the same churn unpurged with a
 * CHECKPOINT each round (the same physical cadence: a purge publishes the lake too, and a long
 * unpurged run is checkpointed anyway, at IMDB_CHECKPOINT_BYTES): what the policy returns (the
 * history's row payloads; the version entries and their tombstones stay until log retirement),
 * and what each purge costs as the tombstones accumulate. */
static void t_mem_retain_churn(void)
{
    enum { LIVE = 12000, ROUNDS = 8 };
    uint64_t grew[2] = {0, 0};
    for (int policy = 0; policy < 2; policy++) {
        const char *dir = test_tmpdir();
        OK(imdb_init(dir, false, NULL, E));
        imdb_db *db = open_retain(dir, policy ? 1 : 0);
        CHECK(db);
        if (!db) return;
        OK(make_table(db, E));
        imdb_session s;
        imdb_session_init(&s, db);
        OK(load_live_memo(&s, LIVE, "a memo of a typical length for a row in this table")); /* R8's rows */
        OK(exec_free(&s, "CHECKPOINT"));
        uint64_t acc0 = held(db);
        for (int k = 0; k < ROUNDS; k++) {
            char q[96];
            snprintf(q, sizeof q, "UPDATE txns SET amount = %d WHERE id > 0", k + 2);
            uint64_t h = db->t[0]->horizon;
            struct timespec t0, t1;
            clock_gettime(CLOCK_MONOTONIC, &t0);
            OK(exec_free(&s, q));
            if (!policy) OK(exec_free(&s, "CHECKPOINT"));
            clock_gettime(CLOCK_MONOTONIC, &t1);
            if (policy)
                printf("    retain round %d: %.1f ms%s\n", k + 1,
                       (double)(t1.tv_sec - t0.tv_sec) * 1e3 + (double)(t1.tv_nsec - t0.tv_nsec) / 1e6,
                       db->t[0]->horizon > h ? " (the update and an automatic purge)" : "");
            CHECK(!policy || db->t[0]->horizon > h); /* every round is due: 12,000 ended, 12,000 live */
        }
        grew[policy] = held(db) - acc0;
        imdb_session_close(&s);
        OK(verify_db(db));
        imdb_close(db);
    }
    printf("    retain churn: %d updates: unpurged +%llu bytes (%llu per update), with the policy +%llu (%llu)\n",
           LIVE * ROUNDS, (unsigned long long)grew[0], (unsigned long long)(grew[0] / (LIVE * ROUNDS)),
           (unsigned long long)grew[1], (unsigned long long)(grew[1] / (LIVE * ROUNDS)));
    CHECK(grew[1] * 10 <= grew[0] * 9); /* measured 239 against 283 bytes per update: the payloads */
}

const test_case mem_tests[] = {
    {"mem_admission", t_mem_admission},
    {"mem_result_cap", t_mem_result_cap},
    {"mem_replica", t_mem_replica},
    {"mem_park", t_mem_park},
    {"mem_churn", t_mem_churn},
    {"mem_retain_threshold", t_mem_retain_threshold},
    {"mem_retain_floor", t_mem_retain_floor},
    {"mem_retain_open_txn", t_mem_retain_open_txn},
    {"mem_retain_replica", t_mem_retain_replica},
    {"mem_retain_churn", t_mem_retain_churn},
};
const size_t mem_ntests = sizeof mem_tests / sizeof *mem_tests;
