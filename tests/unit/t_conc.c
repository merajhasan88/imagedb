/* Concurrency against an independent model (P0 concurrency correctness, 2026-11-04; docs/plan-p0.md): 200 sessions
 * interleaved at random over 48 hot keys, each in SNAPSHOT or READ COMMITTED transactions or in autocommit, with
 * savepoints, rollbacks to them, FOR UPDATE locks, statements that fail on purpose (a duplicate key, a division by zero)
 * and sessions abandoned with a transaction open, CHECKPOINTs between them. The model keeps every key's committed
 * history (the commit that wrote it, its value or its absence) and each transaction's writes, locks and the version each
 * was based on; it never predicts when a conflict is reported, only that each outcome is lawful:
 *   - a read answers the transaction's view: its snapshot (its first statement's commit; READ COMMITTED: the statement's)
 *     overlaid with its own writes;
 *   - a conflict is genuine: some key the transaction wrote, locked or is writing changed after the version it saw
 *     (first committer wins), and the transaction is then doomed until it rolls back;
 *   - a commit that succeeds had no such key, and its writes become the commit's;
 *   - a duplicate key is refused only when the key is there, in the view or committed since;
 * and at the end the table is the model's latest state, before and after a reopen, VERIFY passing. Write skew is
 * lawful under SNAPSHOT, so the model does not look for it there. E3 (docs/e3-design.md), the proof executable: in
 * conc_ser a third of the transactions are SERIALIZABLE; each read one makes of what it has not written itself (a
 * point read, a write's read of its key, an aggregate over the keys it has not written) is logged, and when one with
 * writes commits, every logged read answers the same in the state just before its commit, so it ran as if alone
 * there and those writers ran serially in commit order (a read-only one's reads are its snapshot's, checked at each
 * read); a refusal at its COMMIT with no key's cause is genuine only when a commit after its snapshot wrote t, which
 * each of its statements read. */
#include <stdlib.h>

#include "../../src/sql.h"
#include "thelp.h"

enum { NKEYS = 48, NSESS = 200, NSTEPS = 20000, NSP = 6, MAXRD = 256 };

typedef struct mver {
    uint64_t stamp; /* the commit that wrote it (0: before any) */
    bool present;
    int64_t v;
} mver;

typedef struct mkey {
    mver *h; /* ascending stamps; h[0] = {0, absent} */
    size_t n, cap;
} mkey;

typedef struct mwr {
    bool w, present;
    int64_t v;
    uint64_t base; /* the stamp of the version the first write saw */
    bool base_present; /* that version was a row (an INSERT's is an absence) */
} mwr;

typedef struct msp {
    char name[8];
    mwr wr[NKEYS];
} msp;

typedef struct mrd { /* E3: a SERIALIZABLE transaction's read of what it had not written itself */
    int k;           /* the key of a point read (a write's of its key too), or -1: COUNT(*) and SUM(v) */
    bool there;      /* a point read's answer */
    int64_t v;
    uint64_t mask;   /* an aggregate's: the keys it had written by then, whose part is its own */
    int64_t n, sum;  /* and the rest's count and sum, as answered */
} mrd;

typedef struct msess {
    imdb_session s;
    bool open, started, rc, doomed, ser; /* ser: SERIALIZABLE (E3) */
    uint64_t snap;
    mwr wr[NKEYS];
    bool locked[NKEYS];
    uint64_t lbase[NKEYS];
    msp sp[NSP];
    int nsp;
    mrd rds[MAXRD]; /* E3: its reads, for the proof at its commit */
    int nrd;
} msess;

static mkey g_keys[NKEYS];
static imdb_db *g_db;
static char g_fail[600];
static uint64_t g_ser_proved, g_ser_reads, g_ser_refused, g_ser_engine; /* E3: writers proved, their reads checked,
                                                                    * refusals by the model and by the engine */

static void model_init(void)
{
    for (int k = 0; k < NKEYS; k++) {
        g_keys[k].cap = 8;
        g_keys[k].n = 1;
        g_keys[k].h = calloc(g_keys[k].cap, sizeof *g_keys[k].h);
    }
}

static void model_free(void)
{
    for (int k = 0; k < NKEYS; k++) free(g_keys[k].h);
}

static const mver *at(int k, uint64_t snap)
{
    const mkey *m = &g_keys[k];
    size_t i = m->n;
    while (i > 1 && m->h[i - 1].stamp > snap) i--;
    return &m->h[i - 1];
}

static const mver *latest(int k) { return &g_keys[k].h[g_keys[k].n - 1]; }

static void model_commit(int k, uint64_t stamp, bool present, int64_t v)
{
    mkey *m = &g_keys[k];
    if (m->n == m->cap) {
        m->cap *= 2;
        m->h = realloc(m->h, m->cap * sizeof *m->h);
    }
    m->h[m->n++] = (mver){stamp, present, v};
}

/* the version a statement of m sees for key k: its own write, else its snapshot's (READ COMMITTED and autocommit: the
 * latest committed) */
static bool view(const msess *m, int k, int64_t *v, uint64_t *stamp)
{
    if (m->open && m->wr[k].w) {
        *v = m->wr[k].v;
        *stamp = m->wr[k].base;
        return m->wr[k].present;
    }
    const mver *x = m->open && !m->rc ? at(k, m->snap) : latest(k);
    *v = x->v;
    *stamp = x->stamp;
    return x->present;
}

/* a key m wrote or locked changed since the version it saw, or key k (about to be touched, -1: none) did */
/* a write based on version (stamp, present) of key k still holds: a row's version must still be the latest (versions are
 * never made again); an absence must still be one, whatever came and went since (an insert where a row was made and
 * removed meanwhile is lawful: serially after those commits it does the same) */
static bool base_holds(int k, uint64_t stamp, bool present)
{
    return present ? latest(k)->stamp == stamp : !latest(k)->present;
}

static bool conflict_genuine(const msess *m, int k)
{
    for (int i = 0; i < NKEYS; i++) {
        if (m->wr[i].w && !base_holds(i, m->wr[i].base, m->wr[i].base_present)) return true;
        if (m->locked[i] && latest(i)->stamp != m->lbase[i]) return true;
    }
    if (k >= 0 && !(m->open && m->wr[k].w)) {
        int64_t v;
        uint64_t st;
        bool pr = view(m, k, &v, &st);
        if (!base_holds(k, st, pr)) return true;
    }
    return false;
}

static void sess_reset(msess *m)
{
    m->open = m->started = m->rc = m->doomed = m->ser = false;
    m->nrd = 0;
    m->snap = 0;
    memset(m->wr, 0, sizeof m->wr);
    memset(m->locked, 0, sizeof m->locked);
    memset(m->lbase, 0, sizeof m->lbase);
    m->nsp = 0;
}

static int run(msess *m, const char *sql, imdb_result *r)
{
    imdb_err_clear(E);
    return imdb_exec_one(&m->s, sql, strlen(sql), NULL, 0, r, E);
}

#define FAILF(...)                                                     \
    do {                                                               \
        if (!g_fail[0]) snprintf(g_fail, sizeof g_fail, __VA_ARGS__);  \
        return;                                                        \
    } while (0)

/* the first statement of a transaction (not a control one) takes its snapshot */
static void starts(msess *m)
{
    if (m->open && !m->started) {
        m->started = true;
        m->snap = g_db->seq;
    }
}

/* a write m's statement makes to key k: present (with v) or not, based on the version its view saw */
static void wrote(msess *m, int k, bool present, int64_t v, uint64_t seen, bool seen_present)
{
    if (!m->wr[k].w) {
        m->wr[k].w = true;
        m->wr[k].base = seen;
        m->wr[k].base_present = seen_present;
    }
    m->wr[k].present = present;
    m->wr[k].v = v;
}

/* E3: a SERIALIZABLE transaction's read logged (the answer already matched the model's view) */
static void ser_log_point(msess *m, int k, bool there, int64_t v)
{
    if (m->nrd == MAXRD) FAILF("the model's read log is full (%d reads in one transaction)", MAXRD);
    m->rds[m->nrd++] = (mrd){.k = k, .there = there, .v = there ? v : 0};
}

static void ser_log_agg(msess *m)
{
    if (m->nrd == MAXRD) FAILF("the model's read log is full (%d reads in one transaction)", MAXRD);
    mrd q = {.k = -1};
    for (int k = 0; k < NKEYS; k++) {
        if (m->wr[k].w) {
            q.mask |= 1ull << k;
            continue;
        }
        const mver *x = at(k, m->snap);
        if (x->present) {
            q.n++;
            q.sum += x->v;
        }
    }
    m->rds[m->nrd++] = q;
}

/* E3, the proof: a SERIALIZABLE writer whose commit succeeded, the model still the state before it: every read it
 * logged answers the same there, so it ran as if alone at its commit (its own writes' values follow from those reads
 * and its statements, the same in that run) */
static void ser_proof(const msess *m)
{
    for (int i = 0; i < m->nrd; i++) {
        const mrd *q = &m->rds[i];
        if (q->k >= 0) {
            const mver *x = latest(q->k);
            if (x->present != q->there || (x->present && x->v != q->v))
                FAILF("SERIALIZABLE: key %d, read at snapshot %llu, is otherwise in the state before its commit at %llu",
                      q->k, (unsigned long long)m->snap, (unsigned long long)g_db->seq);
        } else {
            int64_t n = 0, sum = 0;
            for (int k = 0; k < NKEYS; k++)
                if (!(q->mask >> k & 1) && latest(k)->present) {
                    n++;
                    sum += latest(k)->v;
                }
            if (n != q->n || sum != q->sum)
                FAILF("SERIALIZABLE: an aggregate read at snapshot %llu is otherwise in the state before its commit at %llu",
                      (unsigned long long)m->snap, (unsigned long long)g_db->seq);
        }
    }
    g_ser_proved++;
    g_ser_reads += (uint64_t)m->nrd;
}

/* E3: a commit after m's snapshot wrote t (a CHECKPOINT writes no key) */
static bool ser_changed(const msess *m)
{
    for (int k = 0; k < NKEYS; k++)
        if (latest(k)->stamp > m->snap) return true;
    return false;
}

/* after an autocommit write or a COMMIT that succeeded: the transaction's writes are the new commit's */
static void committed(msess *m, uint64_t before)
{
    bool any = false;
    for (int k = 0; k < NKEYS; k++) any |= m->wr[k].w;
    uint64_t stamp = g_db->seq;
    if (!any) {
        if (stamp != before) FAILF("a commit with no write moved the log from %llu to %llu", (unsigned long long)before,
                                   (unsigned long long)stamp);
        return;
    }
    if (stamp <= before) FAILF("a commit with writes made no commit (log at %llu)", (unsigned long long)stamp);
    for (int k = 0; k < NKEYS; k++) {
        if (m->wr[k].w && !base_holds(k, m->wr[k].base, m->wr[k].base_present))
            FAILF("lost update: key %d committed at %llu over a version newer than its write saw (%llu %s, now %llu %s)", k,
                  (unsigned long long)stamp, (unsigned long long)m->wr[k].base, m->wr[k].base_present ? "a row" : "none",
                  (unsigned long long)latest(k)->stamp, latest(k)->present ? "a row" : "none");
        if (m->locked[k] && latest(k)->stamp != m->lbase[k])
            FAILF("a lock did not hold: key %d changed (%llu) after it was locked at %llu", k,
                  (unsigned long long)latest(k)->stamp, (unsigned long long)m->lbase[k]);
    }
    if (m->ser) ser_proof(m); /* E3 */
    for (int k = 0; k < NKEYS; k++)
        if (m->wr[k].w) model_commit(k, stamp, m->wr[k].present, m->wr[k].v);
}

/* a conflict reported now: lawful only when genuine; the transaction is doomed */
static void conflicted(msess *m, int k, const char *what)
{
    if (!conflict_genuine(m, k)) FAILF("%s: a conflict with nothing changed (%s)", what, g_e.msg);
    m->doomed = true;
}

static void step_read(msess *m, int k)
{
    starts(m);
    char q[96];
    imdb_result r;
    if (k >= 0) {
        snprintf(q, sizeof q, "SELECT v FROM t WHERE id = %d", k);
        int rc = run(m, q, &r);
        if (rc == IMDB_ERR_CONFLICT && m->open) return conflicted(m, -1, q);
        if (rc) FAILF("%s: %d (%s)", q, rc, g_e.msg);
        int64_t v;
        uint64_t st;
        bool there = view(m, k, &v, &st);
        bool ok = there ? r.nrows == 1 && r.cells[0].v.i == v : r.nrows == 0;
        imdb_result_free(&r);
        if (!ok) FAILF("%s: the answer is not the view (%s, snapshot %llu)", q, there ? "a row" : "no row", (unsigned long long)m->snap);
        if (m->ser && !m->wr[k].w) ser_log_point(m, k, there, v); /* E3 */
    } else {
        snprintf(q, sizeof q, "SELECT COUNT(*), SUM(v) FROM t");
        int rc = run(m, q, &r);
        if (rc == IMDB_ERR_CONFLICT && m->open) return conflicted(m, -1, q);
        if (rc) FAILF("%s: %d (%s)", q, rc, g_e.msg);
        int64_t n = 0, sum = 0, v;
        uint64_t st;
        for (int i = 0; i < NKEYS; i++)
            if (view(m, i, &v, &st)) {
                n++;
                sum += v;
            }
        bool ok = r.nrows == 1 && r.cells[0].v.i == n &&
                  (n ? !r.cells[1].null && (int64_t)(r.cells[1].wide ? (int64_t)r.cells[1].i128 : r.cells[1].v.i) == sum
                     : r.cells[1].null);
        imdb_result_free(&r);
        if (!ok) FAILF("%s: the answer is not the view (count %lld, sum %lld)", q, (long long)n, (long long)sum);
        if (m->ser) ser_log_agg(m); /* E3 */
    }
}

/* INSERT, UPDATE (+d, or a division by zero), DELETE, SELECT FOR UPDATE of key k */
static void step_write(msess *m, int kind, int k, int64_t d)
{
    starts(m);
    uint64_t before = g_db->seq;
    int64_t v;
    uint64_t seen;
    bool there = view(m, k, &v, &seen);
    char q[128];
    switch (kind) {
    case 0: snprintf(q, sizeof q, "INSERT INTO t VALUES (%d, %lld)", k, (long long)d); break;
    case 1: snprintf(q, sizeof q, "UPDATE t SET v = v + %lld WHERE id = %d", (long long)d, k); break;
    case 2: snprintf(q, sizeof q, "UPDATE t SET v = v / (v - v) WHERE id = %d", k); break;
    case 3: snprintf(q, sizeof q, "DELETE FROM t WHERE id = %d", k); break;
    default: snprintf(q, sizeof q, "SELECT v FROM t WHERE id = %d FOR UPDATE", k); break;
    }
    imdb_result r;
    int rc = run(m, q, &r);
    if (!rc) imdb_result_free(&r);
    if (rc == IMDB_ERR_CONFLICT) {
        if (!m->open) { /* autocommit: the statement alone, retried by nobody; genuine all the same */
            if (latest(k)->stamp == seen && kind != 0) FAILF("%s (autocommit): a conflict with nothing changed (%s)", q, g_e.msg);
            return;
        }
        return conflicted(m, k, q);
    }
    if (m->open && m->ser && !m->wr[k].w) ser_log_point(m, k, there, v); /* E3: the statement read its key */
    if (kind == 0 && rc == IMDB_ERR_CONSTRAINT) {
        if (!there && !latest(k)->present) FAILF("%s: a duplicate key refused, with no row there", q);
        return;
    }
    if (kind == 2 && there && rc) return; /* the injected failure: refused, nothing written */
    if (rc) FAILF("%s: %d (%s)", q, rc, g_e.msg);
    if (kind == 0 && there) FAILF("%s: a key the view holds inserted again", q);
    if (kind == 2 && there) FAILF("%s: a division by zero accepted", q);
    if (kind == 4) {
        if (there && m->open && !m->locked[k] && !m->wr[k].w) {
            m->locked[k] = true;
            m->lbase[k] = seen;
        }
        return;
    }
    msess one = {0}; /* autocommit: a transaction of one statement */
    msess *w = m->open ? m : &one;
    if (!m->open) {
        w->open = true;
        w->started = true;
        w->rc = true;
    }
    if (kind == 0) wrote(w, k, true, d, seen, there);
    else if (kind == 1 && there) wrote(w, k, true, v + d, seen, there);
    else if (kind == 3 && there) wrote(w, k, false, 0, seen, there);
    if (!m->open) committed(w, before);
}

static void step_end(msess *m, bool commit)
{
    uint64_t before = g_db->seq;
    imdb_result r;
    int rc = run(m, commit ? "COMMIT" : "ROLLBACK", &r);
    if (!rc) imdb_result_free(&r);
    if (commit && m->doomed) {
        if (rc != IMDB_ERR_CONFLICT) FAILF("COMMIT of a doomed transaction: %d (%s)", rc, g_e.msg);
        sess_reset(m); /* refused, and it can only end: closed */
        return;
    }
    if (commit && rc == IMDB_ERR_CONFLICT) {
        bool wrote_any = false;
        for (int k = 0; k < NKEYS; k++) wrote_any |= m->wr[k].w;
        if (m->ser && wrote_any && !conflict_genuine(m, -1)) {
            /* E3: no key's cause; genuine only when a commit after its snapshot wrote t (a read-only one is not
             * validated, so the excuse is a writer's alone) */
            if (!ser_changed(m))
                FAILF("COMMIT (SERIALIZABLE): refused with t unwritten since snapshot %llu (%s)", (unsigned long long)m->snap,
                      g_e.msg);
            g_ser_refused++;
        } else {
            conflicted(m, -1, "COMMIT");
        }
        sess_reset(m);
        return;
    }
    if (rc) FAILF("%s: %d (%s)", commit ? "COMMIT" : "ROLLBACK", rc, g_e.msg);
    if (commit) committed(m, before);
    else if (g_db->seq != before) FAILF("a ROLLBACK moved the log");
    sess_reset(m);
}

static void step_savepoint(msess *m, int op)
{
    imdb_result r;
    char q[64];
    if (op == 0 && m->nsp < NSP) {
        snprintf(m->sp[m->nsp].name, sizeof m->sp[m->nsp].name, "s%d", m->nsp);
        snprintf(q, sizeof q, "SAVEPOINT s%d", m->nsp);
        int rc = run(m, q, &r);
        if (!rc) imdb_result_free(&r);
        if (rc == IMDB_ERR_CONFLICT && m->doomed) return;
        if (rc) FAILF("%s: %d (%s)", q, rc, g_e.msg);
        memcpy(m->sp[m->nsp].wr, m->wr, sizeof m->wr);
        m->nsp++;
    } else if (op == 1 && m->nsp) {
        int k = (int)(test_rand() % (uint64_t)m->nsp);
        snprintf(q, sizeof q, "ROLLBACK TO s%d", k);
        int rc = run(m, q, &r);
        if (!rc) imdb_result_free(&r);
        if (rc == IMDB_ERR_CONFLICT && m->doomed) return;
        if (rc) FAILF("%s: %d (%s)", q, rc, g_e.msg);
        memcpy(m->wr, m->sp[k].wr, sizeof m->wr); /* the writes since go; the locks stay (txn.c) */
        m->nsp = k + 1;
    }
}

/* the committed table equals the model's latest state */
static void check_final(imdb_session *s)
{
    for (int k = 0; k < NKEYS; k++) {
        char q[64];
        snprintf(q, sizeof q, "SELECT v FROM t WHERE id = %d", k);
        imdb_result r;
        imdb_err_clear(E);
        if (imdb_exec_one(s, q, strlen(q), NULL, 0, &r, E)) FAILF("final %s: %s", q, g_e.msg);
        const mver *x = latest(k);
        bool ok = x->present ? r.nrows == 1 && r.cells[0].v.i == x->v : r.nrows == 0;
        imdb_result_free(&r);
        if (!ok) FAILF("final: key %d is not the model's (%s %lld)", k, x->present ? "value" : "absent", (long long)x->v);
    }
}

static void conc_run(uint64_t seed, int nsess, bool ser)
{
    const char *dir = test_tmpdir();
    OK(imdb_init(dir, false, NULL, E));
    g_db = open_db(dir);
    CHECK(g_db);
    if (!g_db) return;
    g_fail[0] = 0;
    model_init();
    msess *ss = calloc((size_t)nsess, sizeof *ss);
    for (int i = 0; i < nsess; i++) imdb_session_init(&ss[i].s, g_db);
    imdb_result r;
    CHECK(run(&ss[0], "CREATE TABLE t (id INT64 PRIMARY KEY, v INT64)", &r) == 0);
    imdb_result_free(&r);
    test_seed(seed);
    uint64_t conflicts = 0, commits = 0, aborted = 0;
    for (int step = 0; step < NSTEPS && !g_fail[0]; step++) {
        msess *m = &ss[test_rand() % (uint64_t)nsess];
        int k = (int)(test_rand() % NKEYS), dice = (int)(test_rand() % 100);
        int64_t d = (int64_t)(test_rand() % 9) + 1;
        if (m->doomed) {
            step_end(m, false);
            continue;
        }
        if (!m->open) {
            if (dice < 30) {
                uint64_t lv = test_rand() % 3; /* E3: under ser, 1 is SERIALIZABLE (the draws as before) */
                bool rc_iso = lv == 0, ser_iso = ser && lv == 1;
                if (run(m, rc_iso    ? "BEGIN ISOLATION LEVEL READ COMMITTED"
                           : ser_iso ? "BEGIN ISOLATION LEVEL SERIALIZABLE"
                                     : "BEGIN",
                        &r)) {
                    snprintf(g_fail, sizeof g_fail, "BEGIN: %s", g_e.msg);
                    break;
                }
                imdb_result_free(&r);
                m->open = true;
                m->rc = rc_iso;
                m->ser = ser_iso;
            } else if (dice < 32) {
                if (run(m, "CHECKPOINT", &r) == 0) imdb_result_free(&r);
                else snprintf(g_fail, sizeof g_fail, "CHECKPOINT: %s", g_e.msg);
            } else if (dice < 60) {
                step_read(m, dice < 45 ? k : -1);
            } else {
                step_write(m, (int)(test_rand() % 4), k, d);
            }
            continue;
        }
        if (dice < 25) step_read(m, dice < 18 ? k : -1);
        else if (dice < 70) step_write(m, (int)(test_rand() % 5), k, d);
        else if (dice < 76) step_savepoint(m, dice < 73 ? 0 : 1);
        else if (dice < 90) {
            commits++;
            step_end(m, true);
        } else if (dice < 98) step_end(m, false);
        else { /* abandoned: the session closes with its transaction open, which rolls back */
            imdb_session_close(&m->s);
            imdb_session_init(&m->s, g_db);
            sess_reset(m);
            aborted++;
        }
        conflicts += m->doomed;
    }
    for (int i = 0; i < nsess; i++) {
        if (ss[i].open && !g_fail[0]) step_end(&ss[i], false);
        imdb_session_close(&ss[i].s);
    }
    if (g_fail[0]) {
        char m_[700];
        snprintf(m_, sizeof m_, "seed %llu: %s", (unsigned long long)seed, g_fail);
        test_fail(__FILE__, __LINE__, m_);
    }
    imdb_session s;
    imdb_session_init(&s, g_db);
    check_final(&s);
    imdb_session_close(&s);
    imdb_verify_report vr;
    memset(&vr, 0, sizeof vr);
    if (!g_fail[0] && imdb_verify(g_db, &vr, E)) snprintf(g_fail, sizeof g_fail, "VERIFY: %s", g_e.msg);
    g_ser_engine += g_db->stats.ser_conflicts; /* E3: the engine's count of its refusals */
    imdb_close(g_db);
    if (!g_fail[0]) { /* reopened: the same state */
        g_db = open_db(dir);
        if (!g_db) snprintf(g_fail, sizeof g_fail, "the reopen fails");
        else {
            imdb_session_init(&s, g_db);
            check_final(&s);
            imdb_session_close(&s);
            imdb_close(g_db);
        }
    }
    if (g_fail[0]) {
        char m_[700];
        snprintf(m_, sizeof m_, "seed %llu: %s", (unsigned long long)seed, g_fail);
        test_fail(__FILE__, __LINE__, m_);
    }
    if (getenv("IMDB_CONC_STATS"))
        fprintf(stderr, "    seed %llu: %llu commits tried, %llu conflicts seen, %llu sessions abandoned\n",
                (unsigned long long)seed, (unsigned long long)commits, (unsigned long long)conflicts,
                (unsigned long long)aborted);
    free(ss);
    model_free();
}

static void t_conc_model(void)
{
    const char *ns = getenv("IMDB_CONC_SEEDS"); /* more seeds by hand; three in the suite */
    uint64_t n = ns && atoi(ns) > 0 ? (uint64_t)atoi(ns) : 3;
    for (uint64_t seed = 1; seed <= n; seed++) conc_run(seed, NSESS, false);
}


/* Starvation under sustained contention, measured (P0 transaction correctness): first committer wins and nothing gives
 * a transaction that keeps losing a turn, so a long transaction that writes a hot row loses every round in which a
 * short one commits a write of that row between its write and its commit: here 100 rounds of 100, each refused with
 * a conflict naming the change, while the short writer commits every time. A round with no write in between commits.
 * The cure is the application's (retry with backoff, or write the hot row in a short transaction); fairness is not
 * built in, and this test holds that statement true. */
static void t_conc_starvation(void)
{
    const char *dir = test_tmpdir();
    OK(imdb_init(dir, false, NULL, E));
    imdb_db *db = open_db(dir);
    CHECK(db);
    if (!db) return;
    imdb_session lng, sht;
    imdb_session_init(&lng, db);
    imdb_session_init(&sht, db);
    imdb_result r;
#define X(s, q) (imdb_err_clear(E), imdb_exec_one((s), (q), strlen(q), NULL, 0, &r, E) == 0 ? (imdb_result_free(&r), 0) : g_e.code)
    CHECK(X(&lng, "CREATE TABLE t (id INT64 PRIMARY KEY, v INT64)") == 0);
    CHECK(X(&lng, "INSERT INTO t VALUES (1, 0), (2, 0)") == 0);
    int lost = 0, short_won = 0;
    for (int round = 0; round < 100; round++) {
        CHECK(X(&lng, "BEGIN") == 0);
        CHECK(X(&lng, "UPDATE t SET v = v + 1000 WHERE id = 2") == 0); /* the long transaction's other work */
        CHECK(X(&lng, "UPDATE t SET v = v + 1 WHERE id = 1") == 0);
        short_won += X(&sht, "UPDATE t SET v = v + 1 WHERE id = 1") == 0; /* commits first */
        int rc = X(&lng, "COMMIT");
        lost += rc == IMDB_ERR_CONFLICT;
        if (rc) (void)X(&lng, "ROLLBACK");
    }
    CHECK(lost == 100 && short_won == 100);
    CHECK(X(&lng, "BEGIN") == 0); /* no write between: it commits */
    CHECK(X(&lng, "UPDATE t SET v = v + 1000 WHERE id = 2") == 0);
    CHECK(X(&lng, "UPDATE t SET v = v + 1 WHERE id = 1") == 0);
    CHECK(X(&lng, "COMMIT") == 0);
    imdb_err_clear(E);
    CHECK(imdb_exec_one(&lng, "SELECT v FROM t WHERE id = 1", 28, NULL, 0, &r, E) == 0);
    CHECK(r.nrows == 1 && r.cells[0].v.i == 101); /* the short writer's 100 and the long one's last */
    imdb_result_free(&r);
#undef X
    imdb_session_close(&lng);
    imdb_session_close(&sht);
    imdb_close(db);
}

/* E3: SERIALIZABLE among READ COMMITTED, SNAPSHOT and autocommit, the proof at each SERIALIZABLE writer's commit:
 * 200 sessions (on one hot table mostly refusals, each one's cause checked) and 4 (most commit, each proved) */
static void t_conc_ser(void)
{
    const char *ns = getenv("IMDB_CONC_SEEDS");
    uint64_t n = ns && atoi(ns) > 0 ? (uint64_t)atoi(ns) : 2;
    g_ser_proved = g_ser_reads = g_ser_refused = g_ser_engine = 0;
    for (uint64_t seed = 1; seed <= n; seed++) {
        conc_run(seed, NSESS, true);
        conc_run(seed, 4, true);
    }
    if (getenv("IMDB_CONC_STATS"))
        fprintf(stderr, "    SERIALIZABLE: %llu writers proved (%llu reads), %llu refusals (the engine's %llu)\n",
                (unsigned long long)g_ser_proved, (unsigned long long)g_ser_reads, (unsigned long long)g_ser_refused,
                (unsigned long long)g_ser_engine);
    /* each path ran; and each refusal the model saw with no key's cause is one of the engine's validation's */
    CHECK(g_ser_proved > 0 && g_ser_reads > 0 && g_ser_refused > 0 && g_ser_refused <= g_ser_engine);
}

const test_case conc_tests[] = {
    {"conc_model", t_conc_model},
    {"conc_starvation", t_conc_starvation},
    {"conc_ser", t_conc_ser},
};
const size_t conc_ntests = sizeof conc_tests / sizeof *conc_tests;
