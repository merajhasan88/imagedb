/* Q2's measurements (P1; docs/plan-p1.md, where their expectations were registered before any number): what whole.c
 * does not measure, imagedb alone. Every answer is checked; one line a measure, "workload MODE PARAMS metric value
 * unit", after the environment's lines (WORKLOAD_COMMIT names the tree: the caller sets it).
 *   workload interleave DIR ACCOUNTS SESSIONS rr|burst TXNS sync|nosync
 *       SESSIONS sessions on one handle, each running one transaction at a time: BEGIN, an UPDATE of a random
 *       account by its key, a SELECT of it back (its own write, checked against the snapshot's value), an INSERT of
 *       a history row, COMMIT. rr: one statement of each session in turn (a swap at every statement, the worst case);
 *       burst: a session's whole transaction, then the next one's. A conflict rolls the transaction back and it runs
 *       again. The final balances and history are checked against a model; SHOW STATS (P1 M1) is printed beside
 *       the exact samples (its buckets are a quarter wide).
 *   workload scale DIR ROWS
 *       a child loads ROWS rows (--nosync, 10,000 a statement), indexes and checkpoints them; another opens the
 *       snapshot and reads: point reads, COUNT(*), a 1% range SUM through the index; each child's own peak RSS.
 *   workload stall DIR ROWS K...
 *       ROWS rows checkpointed; then for each K, K distinct random rows updated, the CHECKPOINT timed (every session
 *       of a copy waits for it: one engine thread), then COMPACT t PURGE BEFORE the last commit timed.
 * WORKLOAD_EVENTS=FILE: each open writes the event log there (P1 M2), statements of 5 ms or more included.
 * DIR must not exist: a new database each run. Not in the matrix: run by hand, on a quiet machine. */
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "../src/db_internal.h"
#include "../src/sql.h"

static imdb_err e;
static char g_mode[256]; /* "MODE PARAMS", the start of every line */

static double now(void)
{
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (double)t.tv_sec + (double)t.tv_nsec / 1e9;
}

static void die(const char *what, const char *q)
{
    fprintf(stderr, "workload: %s: %.200s: %s\n", what, q, e.msg);
    exit(1);
}

static void out(const char *metric, double v, const char *unit)
{
    printf("workload %s %s %.6g%s%s\n", g_mode, metric, v, unit[0] ? " " : "", unit);
    fflush(stdout);
}

static uint64_t xs(uint64_t *s) /* xorshift64: the same keys every run */
{
    *s ^= *s << 13;
    *s ^= *s >> 7;
    *s ^= *s << 17;
    return *s;
}

/* q run, its result freed; a conflict returned when the caller handles it, any other failure ends the run */
static int ex(imdb_session *s, const char *q, bool conflict_ok)
{
    imdb_result r;
    imdb_err_clear(&e);
    int rc = imdb_exec_one(s, q, strlen(q), NULL, 0, &r, &e);
    if (rc == IMDB_ERR_CONFLICT && conflict_ok) return rc;
    if (rc) die("statement", q);
    imdb_result_free(&r);
    return 0;
}

/* q's one cell, and its path (if path) */
static int one(imdb_session *s, const char *q, int64_t *v, bool conflict_ok, char *path, size_t cap)
{
    imdb_result r;
    imdb_err_clear(&e);
    int rc = imdb_exec_one(s, q, strlen(q), NULL, 0, &r, &e);
    if (rc == IMDB_ERR_CONFLICT && conflict_ok) return rc;
    if (rc) die("statement", q);
    if (r.nrows != 1 || r.ncols < 1) die("not one row", q);
    *v = r.cells[0].wide ? (int64_t)r.cells[0].i128 : r.cells[0].v.i;
    if (path) snprintf(path, cap, "%s", r.path);
    imdb_result_free(&r);
    return 0;
}

/* a SHOW STATS row (P1 M1), -1 when it has none */
static int64_t stat_of(imdb_session *s, const char *name)
{
    imdb_result r;
    imdb_err_clear(&e);
    if (imdb_exec_one(s, "SHOW STATS", 10, NULL, 0, &r, &e)) die("statement", "SHOW STATS");
    int64_t v = -1;
    size_t n = strlen(name);
    for (uint64_t i = 0; i < r.nrows; i++)
        if (r.cells[2 * i].v.len == n && memcmp(r.cells[2 * i].v.s, name, n) == 0) v = r.cells[2 * i + 1].v.i;
    imdb_result_free(&r);
    return v;
}

static long status_kb(const char *key) /* /proc/self/status: VmHWM (the peak RSS) or VmRSS, in kB */
{
    FILE *f = fopen("/proc/self/status", "r");
    char line[256];
    long v = -1;
    size_t n = strlen(key);
    while (f && fgets(line, sizeof line, f))
        if (strncmp(line, key, n) == 0 && line[n] == ':') {
            v = strtol(line + n + 1, NULL, 10);
            break;
        }
    if (f) fclose(f);
    return v;
}

/* a file's first line starting with prefix (any first line when prefix is NULL), its value after a colon if any */
static void file_value(const char *path, const char *prefix, char *o, size_t cap)
{
    FILE *f = fopen(path, "r");
    char line[512];
    snprintf(o, cap, "(unknown)");
    while (f && fgets(line, sizeof line, f)) {
        if (prefix && strncmp(line, prefix, strlen(prefix)) != 0) continue;
        char *v = prefix && strchr(line, ':') ? strchr(line, ':') + 1 : line;
        while (*v == ' ' || *v == '\t') v++;
        v[strcspn(v, "\n")] = 0;
        snprintf(o, cap, "%s", v);
        break;
    }
    if (f) fclose(f);
}

static void env_lines(const char *sync)
{
    const char *c = getenv("WORKLOAD_COMMIT"), *t = getenv("IMDB_THREADS");
    char b[512];
    printf("workload env commit %s\n", c ? c : "(not given: set WORKLOAD_COMMIT)");
    file_value("/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor", NULL, b, sizeof b);
    printf("workload env governor %s\n", b);
    printf("workload env threads %s\n", t ? t : "(the CPUs)");
    file_value("/proc/meminfo", "MemTotal", b, sizeof b);
    printf("workload env mem_total %s\n", b);
    file_value("/proc/meminfo", "MemAvailable", b, sizeof b);
    printf("workload env mem_available %s\n", b);
    file_value("/proc/cpuinfo", "model name", b, sizeof b);
    printf("workload env cpu %s\n", b);
    printf("workload env sync %s\n", sync);
    fflush(stdout);
}

/* exact samples, in microseconds, and their nearest-rank quantiles */
typedef struct samples {
    double *v;
    size_t n, cap;
    const char *name;
} samples;

static void add(samples *s, double us)
{
    if (s->n == s->cap) {
        s->cap = s->cap ? s->cap * 2 : 4096;
        s->v = realloc(s->v, s->cap * sizeof *s->v);
        if (!s->v) {
            perror("workload");
            exit(1);
        }
    }
    s->v[s->n++] = us;
}

static int cmp_d(const void *a, const void *b)
{
    double x = *(const double *)a, y = *(const double *)b;
    return x < y ? -1 : x > y;
}

static double rank(const samples *s, double p)
{
    if (!s->n) return 0;
    size_t k = (size_t)(p * (double)s->n + 0.999999);
    return s->v[(k < 1 ? 1 : k > s->n ? s->n : k) - 1];
}

static void report(samples *s)
{
    char m[96];
    qsort(s->v, s->n, sizeof *s->v, cmp_d);
    snprintf(m, sizeof m, "%s_count", s->name);
    out(m, (double)s->n, "");
    snprintf(m, sizeof m, "%s_p50", s->name);
    out(m, rank(s, 0.50), "us");
    snprintf(m, sizeof m, "%s_p99", s->name);
    out(m, rank(s, 0.99), "us");
    snprintf(m, sizeof m, "%s_max", s->name);
    out(m, s->n ? s->v[s->n - 1] : 0, "us");
    free(s->v);
    s->v = NULL;
    s->n = s->cap = 0;
}

enum { BATCH = 10000 };

/* n rows into table: acct's (id, 1000), or t's (id, k = id, v = id % 1000) */
static void load_rows(imdb_session *s, const char *table, int64_t n, bool acct)
{
    size_t cap = (size_t)BATCH * 64 + 64;
    char *q = malloc(cap);
    if (!q) die("memory", "the load's statement");
    for (int64_t base = 0; base < n; base += BATCH) {
        int64_t hi = base + BATCH < n ? base + BATCH : n;
        size_t len = (size_t)snprintf(q, cap, "INSERT INTO %s VALUES ", table);
        for (int64_t i = base + 1; i <= hi; i++) {
            const char *sep = i > base + 1 ? ", " : "";
            if (acct) len += (size_t)snprintf(q + len, cap - len, "%s(%lld, 1000)", sep, (long long)i);
            else len += (size_t)snprintf(q + len, cap - len, "%s(%lld, %lld, %lld)", sep, (long long)i, (long long)i, (long long)(i % 1000));
        }
        ex(s, q, false);
    }
    free(q);
}

static imdb_db *open_new(const char *dir, int sync)
{
    imdb_db *db = NULL;
    imdb_open_opts o = {.sync = sync, .events_path = getenv("WORKLOAD_EVENTS")}; /* P1 M2: an outlier explained */
    if (imdb_init(dir, false, NULL, &e) || imdb_open(dir, &o, &db, &e)) die("open", dir);
    return db;
}

/* ---- interleave ------------------------------------------------------------------------------------------------- */

typedef struct sess {
    imdb_session ss;
    int step; /* the next statement: 0 BEGIN, 1 UPDATE, 2 SELECT, 3 INSERT, 4 COMMIT */
    int64_t acct, d, base;
} sess;

static int interleave(const char *dir, int64_t naccts, int nsess, bool rr, int64_t ntxn, bool sync)
{
    snprintf(g_mode, sizeof g_mode, "interleave accounts=%lld sessions=%d order=%s txns=%lld %s", (long long)naccts, nsess,
             rr ? "rr" : "burst", (long long)ntxn, sync ? "sync" : "nosync");
    env_lines(sync ? "fdatasync per commit (it measures the disk)" : "--nosync");
    imdb_db *db = open_new(dir, 0);
    imdb_session s0;
    imdb_session_init(&s0, db);
    s0.cross_check = false;
    ex(&s0, "CREATE TABLE acct (id INT64 PRIMARY KEY, bal INT64 NOT NULL)", false);
    ex(&s0, "CREATE TABLE hist (id INT64 PRIMARY KEY, acct INT64 NOT NULL, delta INT64 NOT NULL)", false);
    load_rows(&s0, "acct", naccts, true);
    ex(&s0, "CHECKPOINT", false);
    imdb_session_close(&s0);
    if (imdb_close(db)) die("close", dir);
    /* the measured phase in a fresh open: SHOW STATS then counts it alone */
    imdb_open_opts o = {.sync = sync ? 1 : 0, .events_path = getenv("WORKLOAD_EVENTS")};
    if (imdb_open(dir, &o, &db, &e)) die("open", dir);
    int64_t *model = calloc((size_t)naccts + 1, sizeof *model);
    sess *S = calloc((size_t)nsess, sizeof *S);
    if (!model || !S) die("memory", "the model");
    for (int64_t i = 1; i <= naccts; i++) model[i] = 1000;
    for (int i = 0; i < nsess; i++) {
        imdb_session_init(&S[i].ss, db);
        S[i].ss.cross_check = false;
        if (getenv("WORKLOAD_EVENTS")) ex(&S[i].ss, "SET slow_statement_ms = 5", false);
    }
    samples sm[5] = {{.name = "begin"}, {.name = "update"}, {.name = "select"}, {.name = "insert"}, {.name = "commit"}};
    int64_t done = 0, conflicts = 0, hid = 0;
    double first_commit = -1; /* it begins a log segment (the load's CHECKPOINT ended the last): apart */
    uint64_t rng = 0x9e3779b97f4a7c15ull;
    char q[200];
    double t0 = now();
    while (done < ntxn) {
        for (int i = 0; i < nsess && done < ntxn; i++) {
            sess *x = &S[i];
            for (int k = 0; k < (rr ? 1 : 5) && done < ntxn; k++) {
                int rc = 0;
                int64_t v = 0;
                double a = now();
                switch (x->step) {
                case 0:
                    x->acct = 1 + (int64_t)(xs(&rng) % (uint64_t)naccts);
                    x->d = 1 + (int64_t)(xs(&rng) % 9);
                    rc = ex(&x->ss, "BEGIN", true);
                    break;
                case 1: /* the transaction's first statement: its snapshot is taken here (txn.c imdb_txn_view) */
                    x->base = model[x->acct];
                    snprintf(q, sizeof q, "UPDATE acct SET bal = bal + %lld WHERE id = %lld", (long long)x->d, (long long)x->acct);
                    rc = ex(&x->ss, q, true);
                    break;
                case 2:
                    snprintf(q, sizeof q, "SELECT bal FROM acct WHERE id = %lld", (long long)x->acct);
                    rc = one(&x->ss, q, &v, true, NULL, 0);
                    if (!rc && v != x->base + x->d) {
                        fprintf(stderr, "workload: session %d read %lld for account %lld, want %lld\n", i, (long long)v,
                                (long long)x->acct, (long long)(x->base + x->d));
                        exit(1);
                    }
                    break;
                case 3:
                    snprintf(q, sizeof q, "INSERT INTO hist VALUES (%lld, %lld, %lld)", (long long)++hid, (long long)x->acct,
                             (long long)x->d);
                    rc = ex(&x->ss, q, true);
                    break;
                default: rc = ex(&x->ss, "COMMIT", true); break;
                }
                double us = (now() - a) * 1e6;
                if (rc == IMDB_ERR_CONFLICT) { /* first committer wins: this one runs again */
                    conflicts++;
                    if (x->step != 4) ex(&x->ss, "ROLLBACK", false); /* a failed COMMIT has ended it */
                    x->step = 0;
                    break;
                }
                add(&sm[x->step], us);
                if (x->step == 4) {
                    if (first_commit < 0) first_commit = us;
                    model[x->acct] += x->d;
                    done++;
                    x->step = 0;
                } else {
                    x->step++;
                }
            }
        }
    }
    double el = now() - t0;
    for (int i = 0; i < nsess; i++)
        if (S[i].step) ex(&S[i].ss, "ROLLBACK", false);
    out("transactions", (double)done, "");
    out("seconds", el, "s");
    out("transactions_per_s", (double)done / el, "/s");
    out("conflicts", (double)conflicts, "");
    out("first_commit", first_commit, "us");
    for (int k = 0; k < 5; k++) report(&sm[k]);
    /* M1's histograms over the same statements since this open: within a bucket (a quarter) of the exact ones, less
     * each statement's parse, which they do not time */
    static const char *const st[] = {"statements.read.p50_us",        "statements.read.p99_us",  "statements.write.p50_us",
                                     "statements.write.p99_us",       "statements.transaction.p50_us",
                                     "statements.transaction.p99_us", "commits",                 "commits.p50_us",
                                     "commits.p99_us",                "failures.conflict"};
    for (size_t i = 0; i < sizeof st / sizeof *st; i++) {
        char m[96];
        snprintf(m, sizeof m, "stats.%s", st[i]);
        out(m, (double)stat_of(&S[0].ss, st[i]), strstr(st[i], "_us") ? "us" : "");
    }
    int64_t sum = 0, got = 0, rows = 0;
    for (int64_t i = 1; i <= naccts; i++) sum += model[i];
    one(&S[0].ss, "SELECT SUM(bal) FROM acct", &got, false, NULL, 0);
    one(&S[0].ss, "SELECT COUNT(*) FROM hist", &rows, false, NULL, 0);
    if (got != sum || rows != done) {
        fprintf(stderr, "workload: the balances sum to %lld (the model: %lld), %lld history rows (committed: %lld)\n",
                (long long)got, (long long)sum, (long long)rows, (long long)done);
        exit(1);
    }
    out("checked_against_the_model", 1, "");
    for (int i = 0; i < nsess; i++) imdb_session_close(&S[i].ss);
    if (imdb_close(db)) die("close", dir);
    free(S);
    free(model);
    return 0;
}

/* ---- scale ------------------------------------------------------------------------------------------------------ */

static int wait_child(pid_t p, const char *what)
{
    int st = 0;
    if (p < 0 || waitpid(p, &st, 0) != p || !WIFEXITED(st) || WEXITSTATUS(st) != 0) {
        fprintf(stderr, "workload: %s failed\n", what);
        return 1;
    }
    return 0;
}

static int scale(const char *dir, int64_t n)
{
    snprintf(g_mode, sizeof g_mode, "scale rows=%lld", (long long)n);
    env_lines("--nosync (the load); then reads only");
    fflush(stdout);
    pid_t p = fork();
    if (p == 0) { /* the load: its own process, so neither peak is the other's */
        imdb_db *db = open_new(dir, 0);
        imdb_session s;
        imdb_session_init(&s, db);
        s.cross_check = false;
        ex(&s, "CREATE TABLE t (id INT64 PRIMARY KEY, k INT64 NOT NULL, v INT64 NOT NULL)", false);
        double a = now();
        load_rows(&s, "t", n, false);
        double l = now() - a;
        out("load_s", l, "s");
        out("load_rows_per_s", (double)n / l, "/s");
        a = now();
        ex(&s, "CREATE INDEX t_k ON t (k)", false);
        out("create_index_s", now() - a, "s");
        a = now();
        ex(&s, "CHECKPOINT", false);
        out("checkpoint_s", now() - a, "s");
        out("load_peak_rss", (double)status_kb("VmHWM") / 1024.0, "MB");
        imdb_session_close(&s);
        if (imdb_close(db)) die("close", dir);
        _exit(0);
    }
    if (wait_child(p, "the load")) return 1;
    p = fork();
    if (p == 0) { /* the open from that snapshot, then the reads */
        imdb_db *db = NULL;
        imdb_open_opts o = {.sync = 1, .events_path = getenv("WORKLOAD_EVENTS")};
        double a = now();
        if (imdb_open(dir, &o, &db, &e)) die("open", dir);
        out("open_s", now() - a, "s");
        out("open_peak_rss", (double)status_kb("VmHWM") / 1024.0, "MB");
        imdb_session s;
        imdb_session_init(&s, db);
        s.cross_check = false;
        samples pr = {.name = "point_read"};
        uint64_t rng = 0x2545f4914f6cdd1dull;
        char q[160], path[sizeof ((imdb_result *)0)->path]; /* a result's path, whatever its size (S4 made it 128) */
        for (int i = 0; i < 10000; i++) {
            int64_t id = 1 + (int64_t)(xs(&rng) % (uint64_t)n), v = -1;
            snprintf(q, sizeof q, "SELECT v FROM t WHERE id = %lld", (long long)id);
            a = now();
            one(&s, q, &v, false, NULL, 0);
            add(&pr, (now() - a) * 1e6);
            if (v != id % 1000) die("a point read's answer", q);
        }
        int64_t rp50 = stat_of(&s, "statements.read.p50_us"), rp99 = stat_of(&s, "statements.read.p99_us");
        report(&pr);
        out("stats.statements.read.p50_us", (double)rp50, "us");
        out("stats.statements.read.p99_us", (double)rp99, "us");
        int64_t c = 0;
        a = now();
        one(&s, "SELECT COUNT(*) FROM t", &c, false, path, sizeof path);
        double el = now() - a;
        if (c != n) die("COUNT(*)'s answer", "SELECT COUNT(*) FROM t");
        out("count_s", el, "s");
        out("count_rows_per_s", (double)n / el, "/s");
        printf("workload %s count_path %s\n", g_mode, path);
        int64_t lo = n / 2 - n / 200 + 1, hi = lo + (n / 100 > 0 ? n / 100 : 1) - 1, want = 0, got = 0;
        if (lo < 1) lo = 1;
        for (int64_t i = lo; i <= hi; i++) want += i % 1000;
        snprintf(q, sizeof q, "SELECT SUM(v) FROM t WHERE k BETWEEN %lld AND %lld", (long long)lo, (long long)hi);
        a = now();
        one(&s, q, &got, false, path, sizeof path);
        el = now() - a;
        if (got != want) die("the range SUM's answer", q);
        out("range_1pct_ms", el * 1e3, "ms");
        printf("workload %s range_path %s\n", g_mode, path);
        out("peak_rss", (double)status_kb("VmHWM") / 1024.0, "MB");
        imdb_session_close(&s);
        if (imdb_close(db)) die("close", dir);
        _exit(0);
    }
    return wait_child(p, "the open and the reads");
}

static double pow_1m(double p, int64_t k) /* (1 - p)^k by squaring: no libm */
{
    double b = 1.0 - p, r = 1.0;
    for (uint64_t x = (uint64_t)k; x; x >>= 1) {
        if (x & 1) r *= b;
        b *= b;
    }
    return r;
}

/* ---- stall ------------------------------------------------------------------------------------------------------ */

static int stall(const char *dir, int64_t n, int nk, char **ks)
{
    snprintf(g_mode, sizeof g_mode, "stall rows=%lld", (long long)n);
    env_lines("--nosync");
    imdb_db *db = open_new(dir, 0);
    imdb_session s;
    imdb_session_init(&s, db);
    s.cross_check = false;
    ex(&s, "CREATE TABLE t (id INT64 PRIMARY KEY, k INT64 NOT NULL, v INT64 NOT NULL)", false);
    load_rows(&s, "t", n, false);
    ex(&s, "CHECKPOINT", false);
    int64_t *ids = malloc((size_t)n * sizeof *ids), *add1 = calloc((size_t)n + 1, sizeof *add1);
    if (!ids || !add1) die("memory", "the keys");
    uint64_t rng = 0x853c49e6748fea9bull;
    char q[160];
    for (int j = 0; j < nk; j++) {
        int64_t k = atoll(ks[j]);
        if (k < 1 || k > n) {
            fprintf(stderr, "workload: K %s is not 1 to ROWS\n", ks[j]);
            return 2;
        }
        snprintf(g_mode, sizeof g_mode, "stall rows=%lld k=%lld", (long long)n, (long long)k);
        for (int64_t i = 0; i < n; i++) ids[i] = i + 1;
        for (int64_t i = 0; i < k; i++) { /* K distinct keys: a partial shuffle */
            int64_t r = i + (int64_t)(xs(&rng) % (uint64_t)(n - i)), t = ids[i];
            ids[i] = ids[r];
            ids[r] = t;
        }
        imdb_table *tb = imdb_table_by_name(db, "t");
        double segs = tb ? (double)tb->nseg : 0;
        out("segments_before", segs, "");
        out("segments_touched_expected", segs > 0 ? segs * (1.0 - pow_1m(1.0 / segs, k)) : 0, "");
        double a = now();
        for (int64_t i = 0; i < k; i++) {
            snprintf(q, sizeof q, "UPDATE t SET v = v + 1 WHERE id = %lld", (long long)ids[i]);
            ex(&s, q, false);
            add1[ids[i]]++;
        }
        out("updates_s", now() - a, "s");
        a = now();
        ex(&s, "CHECKPOINT", false);
        out("checkpoint_ms", (now() - a) * 1e3, "ms");
        tb = imdb_table_by_name(db, "t");
        out("segments_after_checkpoint", tb ? (double)tb->nseg : 0, "");
        snprintf(q, sizeof q, "COMPACT t PURGE BEFORE %llu", (unsigned long long)db->seq);
        a = now();
        ex(&s, q, false);
        out("compact_purge_ms", (now() - a) * 1e3, "ms");
        tb = imdb_table_by_name(db, "t");
        out("segments_after_compact", tb ? (double)tb->nseg : 0, "");
    }
    int64_t want = 0, got = 0;
    for (int64_t i = 1; i <= n; i++) want += i % 1000 + add1[i];
    one(&s, "SELECT SUM(v) FROM t", &got, false, NULL, 0);
    if (got != want) die("the final SUM", "SELECT SUM(v) FROM t");
    snprintf(g_mode, sizeof g_mode, "stall rows=%lld", (long long)n);
    out("checked_against_the_model", 1, "");
    imdb_session_close(&s);
    if (imdb_close(db)) die("close", dir);
    free(ids);
    free(add1);
    return 0;
}

static int usage(void)
{
    fputs("usage: workload interleave DIR ACCOUNTS SESSIONS rr|burst TXNS sync|nosync\n"
          "       workload scale DIR ROWS\n"
          "       workload stall DIR ROWS K...\n"
          "DIR must not exist; WORKLOAD_COMMIT names the tree in the output\n",
          stderr);
    return 2;
}

int main(int argc, char **argv)
{
    if (argc == 8 && strcmp(argv[1], "interleave") == 0) {
        int64_t n = atoll(argv[3]), t = atoll(argv[6]);
        int s = atoi(argv[4]);
        bool rr = strcmp(argv[5], "rr") == 0, sync = strcmp(argv[7], "sync") == 0;
        if (n < 1 || s < 1 || t < 1 || (!rr && strcmp(argv[5], "burst") != 0) || (!sync && strcmp(argv[7], "nosync") != 0))
            return usage();
        return interleave(argv[2], n, s, rr, t, sync);
    }
    if (argc == 4 && strcmp(argv[1], "scale") == 0 && atoll(argv[3]) >= 100) return scale(argv[2], atoll(argv[3]));
    if (argc >= 5 && strcmp(argv[1], "stall") == 0 && atoll(argv[3]) >= 1) return stall(argv[2], atoll(argv[3]), argc - 4, argv + 4);
    return usage();
}
