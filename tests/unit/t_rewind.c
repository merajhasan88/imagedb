/* P2 R1.3: rewind (rewind.h; design.md §8, "Rewind"). A failover makes the fork: a primary p and replicas r and q,
 * r stopped at F while p commits on and q follows p past F, then r promoted (the old writer stopped) and committing
 * its own. p, the old primary, and q, a replica ahead of the promoted one, are each rewound onto r's history: FILE
 * holds exactly the copy's frames past F, the copy is at F, follows r to its head with r's view token, VERIFY and
 * the auditor pass, and FILE applied to a copy at F gives back the commits it took off. With a CHECKPOINT at, below
 * and past F, in both log formats. Every refusal leaves the copy untouched. */
#include <errno.h>
#include <time.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

#include "../../src/fsio.h"
#include "../../src/lake.h"
#include "../../src/repl.h"
#include "../../src/rewind.h"
#include "../../src/sql.h"
#include "../../src/writer.h"
#include "thelp.h"

static imdb_db *open_with(const char *dir, int sync)
{
    imdb_open_opts o = {.sync = sync};
    imdb_db *db = NULL;
    imdb_err_clear(E);
    return imdb_open(dir, &o, &db, E) ? NULL : db;
}

static int audit_ok(const char *dir) /* 1: no auditor in this build (IMDB_AUDIT_BIN) */
{
    const char *bin = getenv("IMDB_AUDIT_BIN");
    if (!bin || !*bin) return 1;
    char cmd[1600];
    snprintf(cmd, sizeof cmd, "'%s' verify '%s' >/dev/null 2>&1", bin, dir);
    return system(cmd) == 0;
}

static int replicate(const char *p, const char *r)
{
    char st[700];
    snprintf(st, sizeof st, "%s.stream", r);
    imdb_db *db = open_with(r, 1);
    if (!db) return -1;
    uint64_t applied;
    imdb_err_clear(E);
    int rc = ship_to_file(p, db->seq, st, E);
    if (!rc) rc = apply_file(db, st, &applied, E);
    imdb_close(db);
    return rc;
}

typedef struct membuf {
    uint8_t *p;
    size_t len, cap;
} membuf;

static int mem_write(void *ctx, const void *p, size_t n, imdb_err *e)
{
    membuf *m = ctx;
    if (m->len + n > m->cap) {
        size_t c = (m->len + n) * 2;
        uint8_t *q = realloc(m->p, c);
        if (!q) return imdb_fail(e, IMDB_ERR_NOMEM, "test buffer");
        m->p = q;
        m->cap = c;
    }
    memcpy(m->p + m->len, p, n);
    m->len += n;
    return IMDB_OK;
}

typedef struct memrd {
    const uint8_t *p;
    size_t n, off;
} memrd;

static int mem_read(void *ctx, void *buf, size_t n, size_t *got, imdb_err *e)
{
    (void)e;
    memrd *m = ctx;
    size_t k = m->n - m->off < n ? m->n - m->off : n;
    memcpy(buf, m->p + m->off, k);
    m->off += k;
    *got = k;
    return IMDB_OK;
}

static int hashes_of(const char *primary, uint64_t after, membuf *out)
{
    out->len = 0;
    imdb_sink s = {mem_write, out};
    imdb_err_clear(E);
    return imdb_ship_hashes(primary, after, &s, E);
}

/* the start the CLI takes by default */
static uint64_t default_start(const imdb_rewind_report *r)
{
    uint64_t a = r->last > IMDB_REWIND_WINDOW ? r->last - IMDB_REWIND_WINDOW : 0;
    return a < r->lowest ? r->lowest : a;
}

typedef enum { DAMAGE_NONE, DAMAGE_ENTRY, DAMAGE_CUT, DAMAGE_START, DAMAGE_DB } damage;

/* dir rewound onto primary's history from after (UINT64_MAX: the default start), the hashes damaged as asked */
static int rewind_onto(const char *dir, const char *primary, uint64_t after, const char *save, bool demote, damage d,
                       imdb_rewind_report *rep)
{
    imdb_rewind *rw = NULL;
    imdb_err_clear(E);
    if (imdb_rewind_begin(dir, &rw, rep, E)) return g_e.code ? g_e.code : -1;
    uint64_t a = after == UINT64_MAX ? default_start(rep) : after;
    membuf m = {0};
    int rc = hashes_of(primary, d == DAMAGE_START && a ? a - 1 : a, &m);
    if (!rc && d == DAMAGE_ENTRY && m.len > IMDB_HASHES_HDR + 20) m.p[IMDB_HASHES_HDR + 20] ^= 1;
    if (!rc && d == DAMAGE_CUT && m.len > IMDB_HASHES_HDR + 4) m.len -= 3;
    if (!rc) {
        memrd rd = {m.p, m.len, 0};
        imdb_err_clear(E);
        rc = imdb_rewind_run(rw, a, mem_read, &rd, save, demote, rep, E);
    }
    imdb_rewind_end(rw);
    free(m.p);
    return rc;
}

typedef enum { CKPT_BELOW, CKPT_AT, CKPT_PAST } ckpt;

typedef struct fork_fx {
    char dir[600], p[620], r[620], q[620], o[620];
    uint8_t rseed[32];
    uint64_t f, plast, rlast;
    uint8_t phead[32];  /* p's last commit's hash */
    uint8_t *ptail;     /* p's frames past f, as ship sends them */
    size_t ptail_n;
} fork_fx;

static void fork_free(fork_fx *x) { free(x->ptail); }

/* The fork (above); erase: p's own commits past f include an ERASE */
static bool make_fork(fork_fx *x, ckpt where, bool erase)
{
    memset(x, 0, sizeof *x);
    const char *base = test_tmpdir();
    snprintf(x->dir, sizeof x->dir, "%s", base);
    snprintf(x->p, sizeof x->p, "%s/p", base);
    snprintf(x->r, sizeof x->r, "%s/r", base);
    snprintf(x->q, sizeof x->q, "%s/q", base);
    snprintf(x->o, sizeof x->o, "%s/other", base);
    memset(x->rseed, 0x31, sizeof x->rseed);
    imdb_signer root;
    imdb_signer_init(&root, x->rseed);
    if (imdb_init_primary(x->p, root.pk, E) || imdb_init(x->r, true, x->p, E) || imdb_init(x->q, true, x->p, E)) return false;
    imdb_db *db = open_with(x->p, 1);
    if (!db) return false;
    int rc = make_table(db, E);
    for (int64_t i = 1; !rc && i <= 6; i++) {
        rc = ins1(db, i, i == 3 ? 42 : 7, i * 10, "shared");
        if (!rc && i == 3 && where == CKPT_BELOW) rc = imdb_checkpoint(db, E);
    }
    if (!rc && where == CKPT_AT) rc = imdb_checkpoint(db, E); /* the fork's commit publishes: f + 1 begins a segment */
    imdb_close(db);
    if (rc || replicate(x->p, x->r) || replicate(x->p, x->q)) return false;
    db = open_with(x->r, 1);
    if (!db) return false;
    x->f = db->seq;
    imdb_close(db);
    db = open_with(x->p, 1);
    if (!db) return false;
    for (int64_t i = 7; !rc && i <= 10; i++) {
        rc = ins1(db, i, 7, i * 10, "old-primary-only");
        if (!rc && i == 8 && where == CKPT_PAST) rc = imdb_checkpoint(db, E);
    }
    if (!rc && erase) {
        imdb_value subj = {.type = IMDB_T_INT64, .i = 42};
        imdb_erase_report er;
        rc = imdb_erase_subject(db, &subj, &er, E);
    }
    x->plast = db->seq;
    memcpy(x->phead, db->head, 32);
    imdb_close(db);
    char tail[700];
    snprintf(tail, sizeof tail, "%s/p-tail.stream", base);
    if (rc || replicate(x->p, x->q) || ship_to_file(x->p, x->f, tail, E)) return false;
    x->ptail = slurp(tail, &x->ptail_n);
    imdb_promote_opts po = {.old_writer_stopped = true};
    imdb_promote_result pr;
    if (!x->ptail || imdb_promote(x->r, x->rseed, &po, &pr, E) || !pr.committed) return false;
    db = open_with(x->r, 1);
    if (!db) return false;
    for (int64_t i = 7; !rc && i <= 9; i++) rc = ins1(db, i, 8, i * 100, "new-primary");
    x->rlast = db->seq;
    imdb_close(db);
    return rc == 0;
}

/* dir's log and watermark, to tell a refusal left it untouched */
typedef struct snap {
    uint8_t *dur;
    size_t ndur;
    uint8_t *meta;
    size_t nmeta;
    char logc[640];
} snap;

static bool snap_take(const char *dir, snap *s, const char *copy)
{
    char p[700];
    snprintf(p, sizeof p, "%s/DURABLE", dir);
    s->dur = slurp(p, &s->ndur);
    snprintf(p, sizeof p, "%s/META", dir);
    s->meta = slurp(p, &s->nmeta);
    snprintf(s->logc, sizeof s->logc, "%s", copy);
    return s->dur && s->meta && copy_tree(dir, copy) == 0;
}

static const char *snap_same(const char *dir, snap *s)
{
    static char why[300];
    char p[700];
    size_t n;
    snprintf(p, sizeof p, "%s/DURABLE", dir);
    uint8_t *b = slurp(p, &n);
    bool same = b && n == s->ndur && memcmp(b, s->dur, n) == 0;
    free(b);
    if (!same) return "DURABLE changed";
    snprintf(p, sizeof p, "%s/META", dir);
    b = slurp(p, &n);
    same = b && n == s->nmeta && memcmp(b, s->meta, n) == 0;
    free(b);
    if (!same) return "META changed";
    char la[700], lb[700];
    snprintf(la, sizeof la, "%s/log", dir);
    snprintf(lb, sizeof lb, "%s/log", s->logc);
    if (!logs_identical(la, lb, why, sizeof why)) return why;
    return NULL;
}

static void snap_free(snap *s)
{
    free(s->dur);
    free(s->meta);
}

#define UNTOUCHED(dir, s)                                                                                       \
    do {                                                                                                        \
        const char *w_ = snap_same((dir), (s));                                                                 \
        if (w_) test_fail(__FILE__, __LINE__, w_);                                                              \
    } while (0)

static bool exists(const char *dir, const char *name)
{
    char p[700];
    snprintf(p, sizeof p, "%s/%s", dir, name);
    return access(p, F_OK) == 0;
}

/* after a rewind to f: the copy follows r to its head and holds r's history: token, VERIFY, the auditor */
static const char *follows(fork_fx *x, const char *dir)
{
    static char why[300];
    imdb_db *db = open_with(dir, 1);
    if (!db) return "the rewound copy does not open";
    bool at = db->seq == x->f;
    bool replica = db->replica;
    imdb_close(db);
    if (!at) return "the rewound copy is not at the fork";
    if (!replica) return "the rewound copy is not a replica";
    if (replicate(x->r, dir)) {
        snprintf(why, sizeof why, "the rewound copy does not follow the new primary: %s", g_e.msg);
        return why;
    }
    imdb_open_opts ro = {.sync = 0, .read_only = true};
    imdb_db *a = NULL, *b = NULL;
    uint8_t ta[32], tb[32];
    bool same = !imdb_open(dir, &ro, &a, E) && !imdb_open(x->r, &ro, &b, E) && !imdb_view_token(a, ta, E) &&
                !imdb_view_token(b, tb, E) && a->seq == x->rlast && memcmp(ta, tb, 32) == 0;
    imdb_verify_report vr;
    memset(&vr, 0, sizeof vr);
    bool verified = same && !imdb_verify(a, &vr, E);
    imdb_close(a);
    imdb_close(b);
    if (!same) return "caught up, but not to the new primary's commit and token";
    if (!verified) return "VERIFY fails on the rewound copy";
    if (!audit_ok(dir)) return "the auditor refuses the rewound copy";
    return NULL;
}

#define FOLLOWS(x, dir)                                                                                         \
    do {                                                                                                        \
        const char *w_ = follows((x), (dir));                                                                   \
        if (w_) test_fail(__FILE__, __LINE__, w_);                                                              \
    } while (0)

/* FILE is p's frames past f, as ship sent them, and a copy at f takes it back to p's old head */
static const char *file_is_tail(fork_fx *x, const char *file, const char *copy_at_f)
{
    size_t n;
    uint8_t *b = slurp(file, &n);
    bool same = b && n == x->ptail_n && memcmp(b, x->ptail, n) == 0;
    free(b);
    if (!same) return "FILE is not the copy's frames past the fork";
    imdb_db *db = open_with(copy_at_f, 1);
    if (!db) return "the copy at the fork does not open";
    uint64_t applied = 0;
    int rc = apply_file(db, file, &applied, E);
    bool back = !rc && db->seq == x->plast && memcmp(db->head, x->phead, 32) == 0;
    imdb_close(db);
    return back ? NULL : "FILE applied at the fork does not give back the commits it took off";
}

static void rewind_old_primary(ckpt where, bool tagged)
{
    imdb_log_set_tagged(tagged);
    fork_fx x;
    CHECK(make_fork(&x, where, false));
    char save[700], keep[700], atf[700];
    snprintf(save, sizeof save, "%s/p-past-fork.frames", x.dir);
    snprintf(keep, sizeof keep, "%s/p-before", x.dir);
    snprintf(atf, sizeof atf, "%s/p-at-fork", x.dir);
    snap s;
    CHECK(snap_take(x.p, &s, keep));
    imdb_rewind_report rep;
    /* a primary without --demote: refused, untouched */
    SOFT(rewind_onto(x.p, x.r, UINT64_MAX, save, false, DAMAGE_NONE, &rep) == IMDB_ERR_STATE && !rep.applied &&
         !exists(x.dir, "p-past-fork.frames"));
    UNTOUCHED(x.p, &s);
    bool lake_before = exists(x.p, "LAKE_HEAD");
    SOFT(rewind_onto(x.p, x.r, UINT64_MAX, save, true, DAMAGE_NONE, &rep) == IMDB_OK);
    SOFT(rep.applied && rep.demoted && rep.fork == x.f && rep.saved == x.plast - x.f && rep.primary == x.rlast &&
         rep.lake_dropped == (where == CKPT_PAST));
    SOFT(exists(x.p, "LAKE_HEAD") == (lake_before && where != CKPT_PAST));
    bool replica = false;
    SOFT(!imdb_read_role(x.p, &replica, E) && replica);
    SOFT(!exists(x.p, "signing.key") && exists(x.p, "signing.key.demoted") && exists(x.p, "replica.key"));
    SOFT(copy_tree(x.p, atf) == 0);
    FOLLOWS(&x, x.p);
    const char *w = file_is_tail(&x, save, atf);
    if (w) test_fail(__FILE__, __LINE__, w);
    snap_free(&s);
    fork_free(&x);
}

static void t_rewind_demote(void) { rewind_old_primary(CKPT_BELOW, true); }
static void t_rewind_fork_publishes(void) { rewind_old_primary(CKPT_AT, true); }
static void t_rewind_lake_past(void) { rewind_old_primary(CKPT_PAST, true); }
static void t_rewind_untagged(void) { rewind_old_primary(CKPT_BELOW, false); }

/* q, a replica that applied p's commits the promoted r never had: rewound without --demote (refused with it) */
static void t_rewind_replica(void)
{
    fork_fx x;
    CHECK(make_fork(&x, CKPT_BELOW, false));
    char save[700], keep[700];
    snprintf(save, sizeof save, "%s/q-past-fork.frames", x.dir);
    snprintf(keep, sizeof keep, "%s/q-before", x.dir);
    snap s;
    CHECK(snap_take(x.q, &s, keep));
    imdb_rewind_report rep;
    SOFT(rewind_onto(x.q, x.r, UINT64_MAX, save, true, DAMAGE_NONE, &rep) == IMDB_ERR_INVALID && !rep.applied);
    UNTOUCHED(x.q, &s);
    uint8_t before[32] = {0};
    char kp[700];
    snprintf(kp, sizeof kp, "%s/replica.key", x.q);
    size_t kn;
    uint8_t *k0 = slurp(kp, &kn);
    SOFT(k0 && kn == 32);
    if (k0) memcpy(before, k0, 32);
    free(k0);
    SOFT(rewind_onto(x.q, x.r, UINT64_MAX, save, false, DAMAGE_NONE, &rep) == IMDB_OK);
    SOFT(rep.applied && !rep.demoted && rep.fork == x.f && rep.saved == x.plast - x.f && !rep.lake_dropped);
    uint8_t *k1 = slurp(kp, &kn);
    SOFT(k1 && kn == 32 && memcmp(k1, before, 32) != 0); /* a new incarnation */
    free(k1);
    FOLLOWS(&x, x.q);
    size_t n;
    uint8_t *b = slurp(save, &n);
    SOFT(b && n == x.ptail_n && memcmp(b, x.ptail, n) == 0);
    free(b);
    snap_free(&s);
    fork_free(&x);
}

/* Refused, each leaving the copy untouched: nothing to rewind (behind on the same history, or equal), another
 * database's hashes, hashes from another start, histories differing at the start, damaged and cut hashes, FILE there
 * already, an ERASE past the fork, the copy in use, a start out of range */
static void t_rewind_refusals(void)
{
    fork_fx x;
    CHECK(make_fork(&x, CKPT_BELOW, false));
    char save[700], keep[700], r2[700], other[700];
    snprintf(save, sizeof save, "%s/refused.frames", x.dir);
    snprintf(keep, sizeof keep, "%s/q-before", x.dir);
    snprintf(r2, sizeof r2, "%s/r2", x.dir);
    snprintf(other, sizeof other, "%s/other", x.dir);
    snap s;
    CHECK(snap_take(x.q, &s, keep));
    imdb_rewind_report rep;
    /* a replica of the new primary, caught up, and one behind it: its history is r's */
    SOFT(imdb_init(r2, true, x.r, E) == 0 && replicate(x.r, r2) == 0);
    SOFT(rewind_onto(r2, x.r, UINT64_MAX, save, false, DAMAGE_NONE, &rep) == IMDB_ERR_STATE && rep.nothing &&
         !rep.applied && !exists(x.dir, "refused.frames"));
    SOFT(rewind_onto(x.r, x.r, UINT64_MAX, save, false, DAMAGE_NONE, &rep) == IMDB_ERR_STATE && rep.nothing);
    /* another database */
    SOFT(imdb_init(other, false, NULL, E) == 0);
    imdb_db *db = open_with(other, 1);
    SOFT(db && make_table(db, E) == 0 && ins1(db, 1, 1, 1, "other") == 0);
    imdb_close(db);
    SOFT(rewind_onto(x.q, other, UINT64_MAX, save, false, DAMAGE_NONE, &rep) == IMDB_ERR_VERIFY && !rep.applied);
    UNTOUCHED(x.q, &s);
    /* hashes from another start than the one run was given */
    SOFT(rewind_onto(x.q, x.r, x.f, save, false, DAMAGE_START, &rep) == IMDB_ERR_INVALID && !rep.applied);
    UNTOUCHED(x.q, &s);
    /* a start past the fork: the histories already differ there */
    SOFT(rewind_onto(x.q, x.r, x.f + 1, save, false, DAMAGE_NONE, &rep) == IMDB_ERR_STATE && !rep.applied &&
         strstr(g_e.msg, "differ at or below"));
    UNTOUCHED(x.q, &s);
    /* damaged and cut hashes */
    SOFT(rewind_onto(x.q, x.r, 0, save, false, DAMAGE_ENTRY, &rep) != IMDB_OK && !rep.applied);
    UNTOUCHED(x.q, &s);
    SOFT(rewind_onto(x.q, x.r, 0, save, false, DAMAGE_CUT, &rep) != IMDB_OK && !rep.applied);
    UNTOUCHED(x.q, &s);
    SOFT(!exists(x.dir, "refused.frames"));
    /* FILE there already: never written over */
    spit(save, (const uint8_t *)"keep me", 7);
    SOFT(rewind_onto(x.q, x.r, UINT64_MAX, save, false, DAMAGE_NONE, &rep) == IMDB_ERR_IO && !rep.applied);
    UNTOUCHED(x.q, &s);
    size_t n;
    uint8_t *b = slurp(save, &n);
    SOFT(b && n == 7 && memcmp(b, "keep me", 7) == 0);
    free(b);
    unlink(save);
    /* a reader reading q's generation (q has a lake: a CHECKPOINT below the fork) holds its pin meanwhile (lake.h) */
    int qd = open(x.q, O_RDONLY | O_DIRECTORY | O_CLOEXEC), pinfd = -1;
    bool lp = false;
    uint64_t ls = 0;
    uint8_t lmh[32];
    SOFT(qd >= 0 && imdb_lake_head(qd, &lp, &ls, lmh, E) == 0 && lp && imdb_lake_pin(qd, lmh, &pinfd, E) == 0 && pinfd >= 0);
    imdb_rewind *pr = NULL;
    imdb_err_clear(E);
    int prc = imdb_rewind_begin(x.q, &pr, &rep, E);
    if (!(prc == IMDB_ERR_STATE && !pr && strstr(g_e.msg, "a reader holds pins/"))) {
        char m[400];
        snprintf(m, sizeof m, "a held pin: begin %d (%s)", prc, g_e.msg);
        test_fail(__FILE__, __LINE__, m);
    }
    imdb_rewind_end(pr);
    imdb_lake_unpin(pinfd);
    if (qd >= 0) close(qd);
    UNTOUCHED(x.q, &s);
    /* the copy in use, and a start out of range */
    db = open_with(x.q, 1);
    SOFT(db);
    imdb_rewind *rw = NULL;
    SOFT(imdb_rewind_begin(x.q, &rw, &rep, E) == IMDB_ERR_STATE && !rw);
    imdb_close(db);
    SOFT(imdb_rewind_begin(x.q, &rw, &rep, E) == IMDB_OK && rw);
    if (rw) {
        memrd rd = {(const uint8_t *)"", 0, 0};
        SOFT(imdb_rewind_run(rw, rep.last + 1, mem_read, &rd, save, false, &rep, E) == IMDB_ERR_INVALID);
        imdb_rewind_end(rw);
    }
    UNTOUCHED(x.q, &s);
    snap_free(&s);
    fork_free(&x);
    /* an ERASE past the fork: what it took from below it cannot be put back */
    CHECK(make_fork(&x, CKPT_BELOW, true));
    snprintf(keep, sizeof keep, "%s/p-before-erase", x.dir);
    CHECK(snap_take(x.p, &s, keep));
    SOFT(rewind_onto(x.p, x.r, UINT64_MAX, save, true, DAMAGE_NONE, &rep) == IMDB_ERR_STATE && !rep.applied &&
         strstr(g_e.msg, "is an ERASE"));
    UNTOUCHED(x.p, &s);
    SOFT(!exists(x.dir, "refused.frames"));
    snap_free(&s);
    fork_free(&x);
}

static int exec_all(imdb_db *db, const char *const *q, size_t n, uint64_t *first_ckpt)
{
    imdb_session s;
    imdb_session_init(&s, db);
    int rc = 0;
    for (size_t i = 0; !rc && i < n; i++) {
        imdb_result r;
        imdb_err_clear(E);
        rc = imdb_exec_one(&s, q[i], strlen(q[i]), NULL, 0, &r, E);
        if (!rc) imdb_result_free(&r);
        if (!rc && first_ckpt && !*first_ckpt && strcmp(q[i], "CHECKPOINT") == 0) *first_ckpt = db->seq;
    }
    imdb_session_close(&s);
    return rc;
}

/* a replica seeded from a primary whose log is cut (a RETIRE): seeded at S, its log then from S + 1 */
static int seed_from(const char *p, const char *r)
{
    char st[700];
    snprintf(st, sizeof st, "%s.seed", r);
    imdb_err_clear(E);
    if (imdb_init(r, true, p, E) || ship_to_file(p, 0, st, E)) return -1;
    imdb_db *db = open_with(r, 1);
    if (!db) return -1;
    uint64_t applied = 0;
    int rc = apply_file(db, st, &applied, E);
    bool seeded = !rc && db->seeded;
    imdb_close(db);
    return seeded ? replicate(p, r) : -1;
}

/* Copies whose logs are cut: p RETIREs below a boundary, r and q are seeded from it (each copy's log begins past its
 * floor, its lowest rewind point), q follows p past r's last, r is promoted. q's rewind onto r starts at its floor,
 * both hashes there the first frame's prev; a start below the floor is refused, q untouched */
static void t_rewind_cut(void)
{
    const char *base = test_tmpdir();
    char p[620], r[620], q[620], save[620], keep[620];
    snprintf(p, sizeof p, "%s/p", base);
    snprintf(r, sizeof r, "%s/r", base);
    snprintf(q, sizeof q, "%s/q", base);
    snprintf(save, sizeof save, "%s/q-past-fork.frames", base);
    snprintf(keep, sizeof keep, "%s/q-before", base);
    uint8_t rseed[32];
    memset(rseed, 0x31, sizeof rseed);
    imdb_signer root;
    imdb_signer_init(&root, rseed);
    CHECK(imdb_init_primary(p, root.pk, E) == 0);
    imdb_db *db = open_with(p, 1);
    CHECK(db);
    SOFT(make_table(db, E) == 0);
    for (int64_t i = 1; i <= 4; i++) SOFT(ins1(db, i, 7, i, "before-the-cut") == 0);
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    int64_t pin = (int64_t)db->last_time - ((int64_t)ts.tv_sec * 1000000 + ts.tv_nsec / 1000) + 1000;
    imdb_clock_offset(pin);
    db->no_auto_retire = true;
    static const char *const q1[] = {"ALTER TABLE txns SET RETENTION 10 SECONDS", "UPDATE txns SET memo = 'r1' WHERE id = 2",
                                     "CHECKPOINT", "UPDATE txns SET memo = 'r2' WHERE id = 2", "CHECKPOINT"};
    uint64_t b = 0;
    SOFT(exec_all(db, q1, sizeof q1 / sizeof *q1, &b) == 0 && b);
    imdb_clock_offset(pin + 15 * 1000000ll);
    static const char *const q2[] = {"SELECT COUNT(*) FROM txns"}; /* a statement: the policy expires the history */
    SOFT(exec_all(db, q2, 1, NULL) == 0);
    if (imdb_retire(db, b, E) != 0) {
        char m[400];
        snprintf(m, sizeof m, "RETIRE below %llu: %s", (unsigned long long)b, g_e.msg);
        test_fail(__FILE__, __LINE__, m);
    }
    for (int64_t i = 5; i <= 6; i++) SOFT(ins1(db, i, 7, i, "past-the-cut") == 0);
    imdb_close(db);
    imdb_clock_offset(0);
    SOFT(seed_from(p, r) == 0 && seed_from(p, q) == 0);
    db = open_with(q, 1);
    CHECK(db);
    uint64_t f = db->seq, qfloor = db->log_floor;
    imdb_close(db);
    SOFT(qfloor > 0 && qfloor < f);
    db = open_with(p, 1);
    CHECK(db);
    for (int64_t i = 7; i <= 8; i++) SOFT(ins1(db, i, 7, i, "old-primary-only") == 0);
    imdb_close(db);
    SOFT(replicate(p, q) == 0);
    imdb_promote_opts po = {.old_writer_stopped = true};
    imdb_promote_result pr;
    SOFT(imdb_promote(r, rseed, &po, &pr, E) == 0 && pr.committed);
    db = open_with(r, 1);
    CHECK(db);
    SOFT(ins1(db, 9, 8, 9, "new-primary") == 0);
    uint64_t rlast = db->seq;
    imdb_close(db);
    snap s;
    CHECK(snap_take(q, &s, keep));
    imdb_rewind_report rep;
    imdb_rewind *rw = NULL;
    SOFT(imdb_rewind_begin(q, &rw, &rep, E) == 0 && rw);
    uint64_t lowest = rep.lowest;
    imdb_rewind_end(rw);
    SOFT(lowest == qfloor && lowest < f); /* seeded at its floor: the lake there too, so the start is the floor itself */
    { /* the floor's hash, independently: FLOOR's (r's open) is the one ship --hashes names at the floor */
        imdb_open_opts fro = {.sync = 0, .read_only = true};
        imdb_db *rd = NULL;
        membuf hm = {0};
        SOFT(imdb_open(r, &fro, &rd, E) == 0 && rd && rd->log_floor == lowest);
        SOFT(rd && hashes_of(r, lowest, &hm) == 0 && hm.len > 64 && memcmp(hm.p + 32, rd->floor_hash, 32) == 0);
        imdb_close(rd);
        free(hm.p);
    }
    if (lowest) { /* below its lowest point: refused by the copy before it reads anything, and by the shipper below its floor */
        SOFT(imdb_rewind_begin(q, &rw, &rep, E) == 0 && rw);
        memrd none = {(const uint8_t *)"", 0, 0};
        imdb_err_clear(E);
        SOFT(rw && imdb_rewind_run(rw, lowest - 1, mem_read, &none, save, false, &rep, E) == IMDB_ERR_INVALID && !rep.applied);
        imdb_rewind_end(rw);
        membuf m = {0};
        SOFT(hashes_of(r, lowest - 1, &m) == IMDB_ERR_STATE && strstr(g_e.msg, "retired here"));
        free(m.p);
        UNTOUCHED(q, &s);
    }
    SOFT(rewind_onto(q, r, lowest, save, false, DAMAGE_NONE, &rep) == IMDB_OK && rep.applied && rep.fork == f &&
         rep.saved == 2 && rep.primary == rlast);
    fork_fx x; /* follows() takes these */
    memset(&x, 0, sizeof x);
    snprintf(x.r, sizeof x.r, "%s", r);
    x.f = f;
    x.rlast = rlast;
    FOLLOWS(&x, q);
    snap_free(&s);
}

/* ship --hashes: the header's fields, every entry in order with the commit's hash, the trailer's CRC; a start past the
 * last commit names none; the log below a cut refused */
static void t_rewind_hashes(void)
{
    fork_fx x;
    CHECK(make_fork(&x, CKPT_BELOW, false));
    membuf m = {0};
    imdb_open_opts ro = {.sync = 0, .read_only = true};
    imdb_db *db = NULL;
    CHECK(imdb_open(x.r, &ro, &db, E) == 0);
    for (uint64_t after = 0; after <= x.rlast + 1; after++) {
        SOFT(hashes_of(x.r, after, &m) == 0);
        uint64_t n = after < x.rlast ? x.rlast - after : 0;
        SOFT(m.len == IMDB_HASHES_HDR + n * IMDB_HASHES_ENTRY + 4);
        if (m.len != IMDB_HASHES_HDR + n * IMDB_HASHES_ENTRY + 4) continue;
        SOFT(memcmp(m.p, "IMDBHSH1", 8) == 0 && memcmp(m.p + 8, db->db_id, 16) == 0 && imdb_get_le64(m.p + 24) == after &&
             imdb_get_le64(m.p + 64) == x.rlast && memcmp(m.p + 72, db->head, 32) == 0 &&
             imdb_get_le32(m.p + 104) == imdb_crc32c_ref(0, m.p, 104));
        uint8_t g[32];
        imdb_genesis_hash(db->db_id, g);
        const imdb_commit_info *ci = after && after <= x.rlast ? imdb_ci_at(db, after, E) : NULL;
        SOFT(after > x.rlast ? 1 : memcmp(m.p + 32, after ? (ci ? ci->hash : g) : g, 32) == 0);
        uint32_t crc = 0;
        for (uint64_t i = 0; i < n; i++) {
            const uint8_t *en = m.p + IMDB_HASHES_HDR + i * IMDB_HASHES_ENTRY;
            const imdb_commit_info *c = imdb_ci_at(db, after + 1 + i, E);
            SOFT(imdb_get_le64(en) == after + 1 + i && c && memcmp(en + 8, c->hash, 32) == 0);
            crc = imdb_crc32c_ref(crc, en, IMDB_HASHES_ENTRY);
        }
        SOFT(imdb_get_le32(m.p + m.len - 4) == crc);
    }
    imdb_close(db);
    free(m.p);
    fork_free(&x);
}

const test_case rewind_tests[] = {
    {"rewind_demote", t_rewind_demote},
    {"rewind_fork_publishes", t_rewind_fork_publishes},
    {"rewind_lake_past", t_rewind_lake_past},
    {"rewind_untagged", t_rewind_untagged},
    {"rewind_replica", t_rewind_replica},
    {"rewind_refusals", t_rewind_refusals},
    {"rewind_cut", t_rewind_cut},
    {"rewind_hashes", t_rewind_hashes},
};
const size_t rewind_ntests = sizeof rewind_tests / sizeof *rewind_tests;
