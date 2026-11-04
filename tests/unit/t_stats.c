/* P1 M1, observability (docs/plan-p1.md): the counters a copy keeps since its open (SHOW STATS, db.h imdb_stats), its
 * open transactions (SHOW TRANSACTIONS), the export a monitor reads without the process (imdb_open_opts.stats_path:
 * rewritten in place, its CRC last, advisory, from a fixed buffer) and a data directory's cheap health. */
#include <fcntl.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

#include "../../src/cpu.h"
#include "../../src/db.h"
#include "../../src/fsio.h"
#include "../../src/sql.h"
#include "thelp.h"

static int run(imdb_session *s, const char *sql)
{
    imdb_result r;
    imdb_err_clear(&g_e);
    int rc = imdb_exec_one(s, sql, strlen(sql), NULL, 0, &r, &g_e);
    if (!rc) imdb_result_free(&r);
    return rc;
}

/* the histogram's arithmetic: every value lands in a bucket whose bound is at least it and at most a quarter above it,
 * the buckets contiguous; quantiles of 1..1000 read within their bound; an empty one answers 0 */
static void t_stats_hist(void)
{
    for (uint64_t us = 0; us < 50000000; us = us < 64 ? us + 1 : us + us / 7 + 1) {
        unsigned i = imdb_hist_bucket(us);
        uint64_t up = imdb_hist_upper(i);
        CHECK(up >= us && (us < 4 || up <= us + us / 4));
        CHECK(i == 0 || imdb_hist_upper(i - 1) < us);
    }
    imdb_hist h;
    memset(&h, 0, sizeof h);
    for (uint64_t v = 1; v <= 1000; v++) imdb_hist_add(&h, v);
    uint64_t p50 = imdb_hist_quantile(&h, 500), p99 = imdb_hist_quantile(&h, 990);
    CHECK(h.n == 1000 && h.max_us == 1000 && h.sum_us == 500500);
    CHECK(p50 >= 500 && p50 <= 625 && p99 >= 990 && p99 <= 1000 && imdb_hist_quantile(&h, 1000) == 1000);
    imdb_hist z;
    memset(&z, 0, sizeof z);
    CHECK(imdb_hist_quantile(&z, 500) == 0);
    imdb_hist_add_atomic(&z, 7);
    CHECK(z.n == 1 && z.max_us == 7 && imdb_hist_quantile(&z, 500) == 7);
}

static bool text_is(const imdb_value *v, const char *s) /* a result's TEXT cell: bytes and a length */
{
    size_t n = strlen(s);
    return v->len == n && memcmp(v->s, s, n) == 0;
}

static bool text_eq(const imdb_value *a, const imdb_value *b)
{
    return a->len == b->len && memcmp(a->s, b->s, a->len) == 0;
}

/* the counters after a known workload: statements by class, failures by kind, commits, rollbacks; every histogram holds
 * as many values as its count; SHOW STATS gives those numbers, the same rows every time (a fixed shape a monitor can
 * rely on), each name once; SHOW TRANSACTIONS lists the open transactions, each with its state */
static void t_stats_counts(void)
{
    const char *dir = test_tmpdir();
    OK(imdb_init(dir, false, NULL, E));
    imdb_db *db = open_db(dir);
    CHECK(db);
    if (!db) return;
    imdb_session a, b;
    imdb_session_init(&a, db);
    imdb_session_init(&b, db);
    imdb_stats s0 = db->stats;
    CHECK(run(&a, "CREATE TABLE t (id INT64 PRIMARY KEY, v INT64)") == 0);
    for (int i = 1; i <= 5; i++) {
        char q[64];
        snprintf(q, sizeof q, "INSERT INTO t VALUES (%d, %d)", i, i);
        CHECK(run(&a, q) == 0);
    }
    CHECK(run(&a, "SELECT COUNT(*) FROM t") == 0);
    CHECK(run(&a, "BEGIN") == 0 && run(&a, "UPDATE t SET v = 9 WHERE id = 1") == 0 && run(&a, "ROLLBACK") == 0);
    CHECK(run(&a, "BEGIN") == 0 && run(&a, "UPDATE t SET v = 7 WHERE id = 2") == 0);
    CHECK(run(&b, "UPDATE t SET v = 8 WHERE id = 2") == 0);  /* b commits first */
    CHECK(run(&a, "COMMIT") == IMDB_ERR_CONFLICT && !a.txn.open); /* rolled back by its commit */
    CHECK(run(&a, "SET statement_row_limit = 2") == 0 && run(&a, "SELECT * FROM t") == IMDB_ERR_LIMIT);
    CHECK(run(&a, "SET statement_row_limit = 0") == 0 && run(&a, "SHOW TABLES") == 0 && run(&a, "CHECKPOINT") == 0);
    const imdb_stats *s = &db->stats;
    static const uint64_t want[IMDB_SC_N] = {[IMDB_SC_READ] = 2, [IMDB_SC_WRITE] = 8, [IMDB_SC_TXN] = 4, [IMDB_SC_DDL] = 1,
                                            [IMDB_SC_PHYSICAL] = 1, [IMDB_SC_SHOW] = 1, [IMDB_SC_OTHER] = 2};
    for (int k = 0; k < IMDB_SC_N; k++) {
        CHECK(s->stmts[k] - s0.stmts[k] == want[k]);
        CHECK(s->stmt_lat[k].n == s->stmts[k]);
    }
    CHECK(s->fails[IMDB_SF_CONFLICT] - s0.fails[IMDB_SF_CONFLICT] == 1 && s->fails[IMDB_SF_LIMIT] - s0.fails[IMDB_SF_LIMIT] == 1);
    CHECK(s->fails[IMDB_SF_CANCELLED] == s0.fails[IMDB_SF_CANCELLED] && s->fails[IMDB_SF_OTHER] == s0.fails[IMDB_SF_OTHER]);
    CHECK(s->commits - s0.commits == 8 && s->commit_lat.n == s->commits); /* CREATE, 5 INSERTs, b's UPDATE, CHECKPOINT */
    CHECK(s->rollbacks - s0.rollbacks == 2 && s->log_bytes > s0.log_bytes);
    CHECK(s->maint_n[IMDB_MT_CHECKPOINT] - s0.maint_n[IMDB_MT_CHECKPOINT] == 1);
    /* SHOW STATS: the same rows twice, each name once, the commits row the counter (its own statement counted after) */
    uint64_t rows[2] = {0, 0};
    for (int pass = 0; pass < 2; pass++) {
        imdb_result r;
        imdb_err_clear(&g_e);
        OK(imdb_exec_one(&a, "SHOW STATS", 10, NULL, 0, &r, &g_e));
        rows[pass] = r.nrows;
        bool dup = false, commits = false;
        for (uint64_t i = 0; i < r.nrows; i++) {
            const imdb_value *n = &r.cells[2 * i].v;
            for (uint64_t j = 0; j < i; j++) dup |= text_eq(n, &r.cells[2 * j].v);
            if (text_is(n, "commits")) commits = r.cells[2 * i + 1].v.i == (int64_t)s->commits;
        }
        CHECK(!dup && commits && r.ncols == 2);
        imdb_result_free(&r);
    }
    CHECK(rows[0] == rows[1] && rows[0] > 60);
    /* SHOW TRANSACTIONS: a's active write, b's parked one (its write saved when a's became active) */
    CHECK(run(&b, "BEGIN") == 0 && run(&b, "UPDATE t SET v = 1 WHERE id = 3") == 0);
    CHECK(run(&a, "BEGIN") == 0 && run(&a, "UPDATE t SET v = 2 WHERE id = 4") == 0);
    imdb_result r;
    imdb_err_clear(&g_e);
    OK(imdb_exec_one(&a, "SHOW TRANSACTIONS", 17, NULL, 0, &r, &g_e));
    CHECK(r.nrows == 2 && r.ncols == 7);
    int mine = 0, active = 0, parked = 0;
    for (uint64_t i = 0; i < r.nrows; i++) {
        const imdb_cell *c = &r.cells[7 * i];
        mine += c[6].v.i == 1;
        active += text_is(&c[0].v, "active");
        parked += text_is(&c[0].v, "parked");
        CHECK(c[4].v.i == 1 && c[2].v.i >= 0);
    }
    CHECK(mine == 1 && active == 1 && parked == 1);
    imdb_result_free(&r);
    CHECK(run(&a, "ROLLBACK") == 0 && run(&b, "ROLLBACK") == 0);
    imdb_session_close(&a);
    imdb_session_close(&b);
    imdb_close(db);
}

static size_t slurp_stats(const char *path, char *buf, size_t cap)
{
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return 0;
    ssize_t n = read(fd, buf, cap - 1);
    close(fd);
    if (n <= 0) return 0;
    buf[n] = 0;
    return (size_t)n;
}

/* the export's file as a reader takes it: its CRC32C over every line before the last, and a value by name */
static bool stats_ok(const char *buf, size_t n)
{
    const char *last = n >= 2 ? memrchr(buf, '\n', n - 1) : NULL;
    unsigned crc;
    return last && sscanf(last + 1, "crc32c %8x", &crc) == 1 &&
           imdb_kern()->crc32c(0, buf, (size_t)(last + 1 - buf)) == crc && strncmp(buf, "imagedb.stats 1\n", 16) == 0;
}

static long long stats_get(const char *buf, const char *name)
{
    size_t n = strlen(name);
    for (const char *p = buf; p && *p; p = strchr(p, '\n') ? strchr(p, '\n') + 1 : NULL)
        if (strncmp(p, name, n) == 0 && p[n] == ' ') return strtoll(p + n + 1, NULL, 10);
    return -1;
}

/* the export: written whole at the open, its CRC good; at most once a second between them (statements past it are
 * not each a write); a tick allocates nothing; the close writes the last state; a path that cannot be written costs
 * the open nothing (counted, warned) and no statement fails for it */
static void t_stats_export(void)
{
    const char *dir = test_tmpdir();
    char p[700], f[720], bad[740];
    snprintf(p, sizeof p, "%s/db", dir);
    snprintf(f, sizeof f, "%s/stats.txt", dir);
    snprintf(bad, sizeof bad, "%s/no/such/dir/stats.txt", dir);
    OK(imdb_init(p, false, NULL, E));
    imdb_open_opts o = {.sync = 0, .stats_path = f};
    imdb_db *db = NULL;
    OK(imdb_open(p, &o, &db, E));
    if (!db) return;
    static char buf[IMDB_STATS_EXPORT_MAX + 1];
    size_t n = slurp_stats(f, buf, sizeof buf);
    CHECK(n && stats_ok(buf, n) && stats_get(buf, "commit") == 0 && stats_get(buf, "failed") == 0);
    CHECK(stats_get(buf, "pid") == (long long)getpid() && db->stats_exports == 1);
    imdb_session s;
    imdb_session_init(&s, db);
    uint64_t t0 = imdb_mono_ns(), w0 = db->stats_exports;
    CHECK(run(&s, "CREATE TABLE t (id INT64 PRIMARY KEY, v INT64)") == 0);
    for (int i = 1; i <= 300; i++) {
        char q[64];
        snprintf(q, sizeof q, "INSERT INTO t VALUES (%d, %d)", i, i);
        CHECK(run(&s, q) == 0);
    }
    uint64_t secs = (imdb_mono_ns() - t0) / 1000000000u;
    CHECK(db->stats_exports - w0 <= 2 * (secs + 1)); /* 301 statements: a start and an end a second at most */
    uint64_t h0 = imdb_heap_bytes();
    imdb_stats_tick(db, true);
    CHECK(imdb_heap_bytes() == h0 && db->stats_errors == 0);
    n = slurp_stats(f, buf, sizeof buf);
    CHECK(n && stats_ok(buf, n) && stats_get(buf, "commit") == (long long)db->seq);
    CHECK(stats_get(buf, "statements.write") == 300 && stats_get(buf, "statement.running") == 0);
    /* an idle copy shows nothing running: a short statement's end is exported when its start was (no forced tick) */
    struct timespec ts = {1, 100000000L};
    nanosleep(&ts, NULL);
    CHECK(run(&s, "SELECT COUNT(*) FROM t") == 0);
    n = slurp_stats(f, buf, sizeof buf);
    CHECK(n && stats_ok(buf, n) && stats_get(buf, "statement.running") == 0 && stats_get(buf, "statements.read") == 1);
    /* a failed handle reaches the export at its next statement, refused, at once */
    db->failed = true;
    CHECK(run(&s, "SELECT COUNT(*) FROM t") == IMDB_ERR_STATE);
    n = slurp_stats(f, buf, sizeof buf);
    CHECK(n && stats_ok(buf, n) && stats_get(buf, "failed") == 1 && db->stats_said_failed);
    const char *kpath = getenv("IMDB_STATS_KEEP"); /* a copy for checking imagedb health's exit 2 by hand */
    if (kpath) {
        int kfd = open(kpath, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
        if (kfd >= 0 && write(kfd, buf, n) != (ssize_t)n) fprintf(stderr, "    IMDB_STATS_KEEP: short write\n");
        if (kfd >= 0) close(kfd);
    }
    uint64_t last = db->seq;
    imdb_session_close(&s);
    imdb_close(db);
    n = slurp_stats(f, buf, sizeof buf);
    CHECK(n && stats_ok(buf, n) && stats_get(buf, "commit") == (long long)last && stats_get(buf, "export.writes") >= 2);
    /* another file at FILE (an operator's typo) is left as it is; the open goes on without an export */
    char other[740];
    snprintf(other, sizeof other, "%s/precious.txt", dir);
    static const char keep[] = "precious data, not an export\n";
    int pfd = open(other, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
    CHECK(pfd >= 0 && write(pfd, keep, sizeof keep - 1) == (ssize_t)(sizeof keep - 1));
    if (pfd >= 0) close(pfd);
    imdb_open_opts o3 = {.sync = 0, .stats_path = other};
    db = NULL;
    OK(imdb_open(p, &o3, &db, E));
    if (!db) return;
    CHECK(db->stats_fd == -1 && db->stats_errors == 1);
    imdb_session_init(&s, db);
    CHECK(run(&s, "INSERT INTO t VALUES (999, 1)") == 0);
    imdb_session_close(&s);
    imdb_close(db);
    n = slurp_stats(other, buf, sizeof buf);
    CHECK(n == sizeof keep - 1 && memcmp(buf, keep, n) == 0);
    imdb_open_opts o2 = {.sync = 0, .stats_path = bad};
    db = NULL;
    OK(imdb_open(p, &o2, &db, E));
    if (!db) return;
    CHECK(db->stats_fd == -1 && db->stats_errors == 1);
    imdb_session_init(&s, db);
    CHECK(run(&s, "INSERT INTO t VALUES (1000, 1)") == 0);
    imdb_session_close(&s);
    imdb_close(db);
}

/* a replica's export (apply, follow): the commits it applied counted apart from its own (none), said at its close */
static void t_stats_replica(void)
{
    const char *dir = test_tmpdir();
    char p[700], r[700], f[720], sf[720];
    snprintf(p, sizeof p, "%s/p", dir);
    snprintf(r, sizeof r, "%s/r", dir);
    snprintf(f, sizeof f, "%s/stream", dir);
    snprintf(sf, sizeof sf, "%s/replica-stats.txt", dir);
    OK(imdb_init(p, false, NULL, E));
    imdb_db *db = open_db(p);
    CHECK(db);
    if (!db) return;
    OK(make_table(db, E));
    for (int64_t i = 1; i <= 20; i++) OK(ins1(db, i, i % 3, i, "row"));
    imdb_close(db);
    OK(imdb_init(r, true, p, E));
    OK(ship_to_file(p, 0, f, E));
    imdb_open_opts o = {.sync = 0, .stats_path = sf};
    imdb_db *rep = NULL;
    OK(imdb_open(r, &o, &rep, E));
    if (!rep) return;
    uint64_t applied = 0;
    OK(apply_file(rep, f, &applied, E));
    CHECK(applied == 21 && rep->stats.applied == applied && rep->stats.commits == 0);
    imdb_close(rep);
    static char buf[IMDB_STATS_EXPORT_MAX + 1];
    size_t n = slurp_stats(sf, buf, sizeof buf);
    CHECK(n && stats_ok(buf, n) && stats_get(buf, "replica") == 1 && stats_get(buf, "commits.applied") == 21);
}

/* a data directory's health: a sound one passes; a recorded replica incident fails it by name, as a DURABLE that is
 * not one and a path that is not a database do */
static void t_stats_health(void)
{
    const char *dir = test_tmpdir();
    char p[700], q[760];
    snprintf(p, sizeof p, "%s/db", dir);
    OK(imdb_init(p, false, NULL, E));
    imdb_db *db = open_db(p);
    CHECK(db);
    if (db) imdb_close(db);
    imdb_err_clear(&g_e);
    OK(imdb_health_dir(p, E));
    snprintf(q, sizeof q, "%s/replicas", p);
    (void)mkdir(q, 0755);
    snprintf(q, sizeof q, "%s/replicas/r1.diverged", p);
    int fd = open(q, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
    CHECK(fd >= 0);
    if (fd >= 0) close(fd);
    imdb_err_clear(&g_e);
    CHECK(imdb_health_dir(p, E) == IMDB_ERR_VERIFY && strstr(g_e.msg, "r1.diverged"));
    CHECK(unlink(q) == 0);
    imdb_err_clear(&g_e);
    OK(imdb_health_dir(p, E));
    snprintf(q, sizeof q, "%s/DURABLE", p);
    fd = open(q, O_WRONLY | O_TRUNC | O_CLOEXEC);
    CHECK(fd >= 0);
    if (fd >= 0) {
        CHECK(write(fd, "this is not a watermark, but sixty bytes of something else entirely....", 60) == 60);
        close(fd);
    }
    imdb_err_clear(&g_e);
    CHECK(imdb_health_dir(p, E) != 0);
    snprintf(q, sizeof q, "%s/nothing-here", dir);
    imdb_err_clear(&g_e);
    CHECK(imdb_health_dir(q, E) == IMDB_ERR_IO);
}

const test_case stats_tests[] = {
    {"stats_hist", t_stats_hist},
    {"stats_counts", t_stats_counts},
    {"stats_export", t_stats_export},
    {"stats_replica", t_stats_replica},
    {"stats_health", t_stats_health},
};
const size_t stats_ntests = sizeof stats_tests / sizeof *stats_tests;
