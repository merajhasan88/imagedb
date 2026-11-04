/* The replication stream through a relay that cuts, duplicates, reorders and garbles it (P0 fault injection,
 * 2026-11-04; docs/plan-p0.md), and a process out of file descriptors. A replica must take only what is the primary's:
 * whatever arrives, it ends at a prefix of the primary's chain (its last commit's hash the primary's for that commit),
 * refuses at or before the damage, and catches up from a clean stream to the primary's view token. A cut stream is a
 * dropped connection, never an error about the data; a damaged one is refused, never applied. */
#include <fcntl.h>
#include <stdlib.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>

#include "../../src/log.h"
#include "../../src/sql.h"
#include "thelp.h"

static int ex(imdb_db *db, const char *sql)
{
    imdb_session s;
    imdb_session_init(&s, db);
    imdb_result r;
    imdb_err_clear(E);
    int rc = imdb_exec_one(&s, sql, strlen(sql), NULL, 0, &r, E);
    if (!rc) imdb_result_free(&r);
    imdb_session_close(&s);
    return rc;
}

/* a primary with variety in its stream: inserts, updates, deletes, a CHECKPOINT (a publish), an ERASE (redactions a
 * replica must see authorised) and commits after it; *n: its last commit */
static int make_primary(const char *p, uint64_t *n)
{
    if (imdb_init(p, false, NULL, E)) return -1;
    imdb_db *db = open_db(p);
    if (!db) return -1;
    int rc = make_table(db, E);
    for (int64_t i = 1; !rc && i <= 12; i++) rc = ins1(db, i, i % 3 == 0 ? 42 : i % 4, i * 10, i % 3 == 0 ? "relay-42" : "relay");
    if (!rc) rc = ex(db, "UPDATE txns SET amount = amount + 1 WHERE id <= 4");
    if (!rc) rc = ex(db, "DELETE FROM txns WHERE id = 5");
    if (!rc) rc = imdb_checkpoint(db, E);
    imdb_value subj = {.type = IMDB_T_INT64, .i = 42};
    imdb_erase_report rep;
    if (!rc) rc = imdb_erase_subject(db, &subj, &rep, E);
    for (int64_t i = 20; !rc && i <= 24; i++) rc = ins1(db, i, 1, i, "after-erase");
    *n = db->seq;
    imdb_close(db);
    return rc;
}

typedef struct relay {
    char p[600], dir[600], s[620], s2[620];
    uint8_t *stream;
    size_t len;
    size_t *frames; /* each frame's offset; frames[nf] = len */
    size_t nf;
    uint8_t token[32];          /* the primary's view token at its last commit */
    uint8_t (*hash)[32];        /* the primary's commit hashes, hash[seq] */
    uint64_t last;
    int k;                      /* replicas made */
} relay;

static bool relay_setup(relay *r)
{
    memset(r, 0, sizeof *r);
    const char *base = test_tmpdir();
    snprintf(r->dir, sizeof r->dir, "%s", base);
    snprintf(r->p, sizeof r->p, "%s/p", base);
    snprintf(r->s, sizeof r->s, "%s/stream", base);
    snprintf(r->s2, sizeof r->s2, "%s/rest", base);
    if (make_primary(r->p, &r->last) || ship_to_file(r->p, 0, r->s, E)) return false;
    r->stream = slurp(r->s, &r->len);
    if (!r->stream) return false;
    r->frames = calloc(r->last + 2, sizeof *r->frames);
    r->hash = calloc(r->last + 1, sizeof *r->hash);
    size_t off = 0, fl = 0;
    while (r->nf <= r->last && imdb_frame_scan(r->stream, r->len, off, &fl, E) == IMDB_SCAN_FRAME) {
        r->frames[r->nf++] = off;
        off += fl;
    }
    r->frames[r->nf] = off;
    if (off != r->len || r->nf != r->last) return false; /* a plain ship from 0: frames only */
    imdb_open_opts ro = {.sync = 0, .read_only = true};
    imdb_db *db = NULL;
    if (imdb_open(r->p, &ro, &db, E)) return false;
    bool ok = !imdb_view_token(db, r->token, E);
    for (uint64_t q = 1; ok && q <= r->last; q++) {
        const imdb_commit_info *ci = imdb_ci_at(db, q, E);
        ok = ci != NULL;
        if (ok) memcpy(r->hash[q], ci->hash, 32);
    }
    imdb_close(db);
    return ok;
}

static void relay_free(relay *r)
{
    free(r->stream);
    free(r->frames);
    free(r->hash);
}

/* What the relay delivered, applied to a new replica; then a clean stream from where it stands. Returns NULL when the
 * replica held only a prefix of the primary's chain at every step and caught up to its token; *rc: the first apply's */
static const char *deliver(relay *r, const uint8_t *b, size_t n, int *rc_out, uint64_t *at, bool *cut)
{
    static char why[300];
    char rep[700];
    snprintf(rep, sizeof rep, "%s/r%d", r->dir, r->k++);
    imdb_err e0 = {0};
    if (imdb_init(rep, true, r->p, &e0)) return "the replica could not be made";
    spit(r->s, b, n);
    imdb_db *db = open_db(rep);
    if (!db) return "the replica does not open";
    uint64_t applied = 0;
    imdb_err_clear(E);
    int fd = open(r->s, O_RDONLY);
    imdb_apply_opts ao;
    memset(&ao, 0, sizeof ao);
    *rc_out = imdb_apply_stream_ex(db, fd, &applied, &ao, E);
    close(fd);
    *cut = ao.truncated; /* the stream ended inside a frame, or before an ERASE's authorisation: resumable */
    *at = db->seq;
    const char *bad = NULL;
    if (db->seq > r->last || (db->seq && memcmp(db->head, r->hash[db->seq], 32) != 0))
        bad = "the replica holds a commit the primary does not";
    imdb_close(db);
    if (bad) return bad;
    db = open_db(rep); /* reopened: what it holds is what is durable */
    if (!db) {
        snprintf(why, sizeof why, "the replica does not reopen after the relay's stream: %s", g_e.msg);
        return why;
    }
    if (db->seq > r->last || (db->seq && memcmp(db->head, r->hash[db->seq], 32) != 0)) bad = "reopened, not a prefix";
    if (!bad && (ship_to_file(r->p, db->seq, r->s2, E) || apply_file(db, r->s2, &applied, E))) {
        snprintf(why, sizeof why, "the clean stream from commit %llu does not apply: %s", (unsigned long long)db->seq, g_e.msg);
        bad = why;
    }
    uint8_t tok[32];
    if (!bad && (imdb_view_token(db, tok, E) || memcmp(tok, r->token, 32) != 0)) bad = "caught up, but not to the primary's token";
    imdb_verify_report vr;
    memset(&vr, 0, sizeof vr);
    if (!bad && imdb_verify(db, &vr, E)) {
        snprintf(why, sizeof why, "VERIFY fails after the catch-up: %s", g_e.msg);
        bad = why;
    }
    imdb_close(db);
    return bad;
}

#define DELIVER(b, n, what, cond)                                                                                \
    do {                                                                                                         \
        int rc_ = 0;                                                                                             \
        bool cut_ = false;                                                                                       \
        uint64_t at_ = 0;                                                                                        \
        const char *w_ = deliver(&r, (b), (n), &rc_, &at_, &cut_);                                              \
        if (w_ || !(cond)) {                                                                                     \
            char m_[600];                                                                                        \
            snprintf(m_, sizeof m_, "%s: %s (apply %d, at %llu: %s)", (what), w_ ? w_ : "unexpected outcome", rc_, \
                     (unsigned long long)at_, g_e.msg);                                                          \
            test_fail(__FILE__, __LINE__, m_);                                                                   \
        }                                                                                                        \
    } while (0)

/* Cut at each frame's edges (the byte before, at and after each boundary) and at fifty more places: the replica takes
 * the whole frames before the cut and nothing of the one cut, the apply never calls the data damaged (a cut is a
 * dropped connection), and a clean stream from where it stands catches it up */
static void t_relay_cut(void)
{
    relay r;
    CHECK(relay_setup(&r));
    test_seed(11);
    size_t cuts[512];
    size_t nc = 0;
    for (size_t f = 1; f <= r.nf && nc + 3 < 512; f++) {
        cuts[nc++] = r.frames[f] - 1;
        cuts[nc++] = r.frames[f];
        if (r.frames[f] + 1 < r.len) cuts[nc++] = r.frames[f] + 1;
    }
    for (int i = 0; i < 50 && nc < 512; i++) cuts[nc++] = (size_t)(test_rand() % r.len);
    for (size_t i = 0; i < nc; i++) {
        size_t c = cuts[i];
        uint64_t whole = 0; /* the frames wholly before the cut */
        while (whole < r.nf && r.frames[whole + 1] <= c) whole++;
        char what[80];
        snprintf(what, sizeof what, "cut at byte %zu", c);
        int rc_ = 0;
        uint64_t at_ = 0;
        bool cut_ = false;
        const char *w_ = deliver(&r, r.stream, c, &rc_, &at_, &cut_);
        /* a cut inside a frame, or between an ERASE's redactions and their authorisation: flagged resumable, never damage */
        bool ok = !w_ && at_ <= whole && (rc_ == IMDB_OK || cut_);
        if (!ok) {
            char m_[600];
            snprintf(m_, sizeof m_, "%s: %s (apply %d, at %llu of %llu whole: %s)", what, w_ ? w_ : "unexpected outcome",
                     rc_, (unsigned long long)at_, (unsigned long long)whole, g_e.msg);
            test_fail(__FILE__, __LINE__, m_);
        }
    }
    relay_free(&r);
}

/* A frame twice, two frames swapped, a frame missing: refused where the order breaks, the frames before it taken */
static void t_relay_order(void)
{
    relay r;
    CHECK(relay_setup(&r));
    uint8_t *b = malloc(r.len * 2);
    CHECK(b);
    if (!b) return;
    for (size_t f = 0; f + 1 < r.nf; f++) {
        size_t a0 = r.frames[f], a1 = r.frames[f + 1], a2 = r.frames[f + 2];
        char what[80];
        /* frame f twice */
        memcpy(b, r.stream, a1);
        memcpy(b + a1, r.stream + a0, a1 - a0);
        memcpy(b + a1 + (a1 - a0), r.stream + a1, r.len - a1);
        snprintf(what, sizeof what, "frame %zu twice", f + 1);
        DELIVER(b, r.len + (a1 - a0), what, rc_ != IMDB_OK && at_ <= f + 1);
        /* frames f and f + 1 swapped */
        memcpy(b, r.stream, a0);
        memcpy(b + a0, r.stream + a1, a2 - a1);
        memcpy(b + a0 + (a2 - a1), r.stream + a0, a1 - a0);
        memcpy(b + a2, r.stream + a2, r.len - a2);
        snprintf(what, sizeof what, "frames %zu and %zu swapped", f + 1, f + 2);
        DELIVER(b, r.len, what, rc_ != IMDB_OK && at_ <= f);
        /* frame f + 1 missing */
        memcpy(b, r.stream, a1);
        memcpy(b + a1, r.stream + a2, r.len - a2);
        snprintf(what, sizeof what, "frame %zu missing", f + 2);
        /* the last frame missing leaves a whole, shorter stream: applied to the one before it */
        DELIVER(b, r.len - (a2 - a1), what, f + 2 == r.nf ? rc_ == IMDB_OK && at_ == f + 1 : rc_ != IMDB_OK && at_ <= f + 1);
    }
    free(b);
    relay_free(&r);
}

static void refresh_crcs(uint8_t *f)
{
    uint32_t blen = imdb_get_le32(f + 4);
    imdb_le32(f + 8, imdb_crc32c_ref(0, f + 16, blen));
    imdb_le32(f + 12, imdb_crc32c_ref(0, f, 12));
}

/* A byte flipped at 120 places, as the wire would (the frame's checksums then disagree) and as an attacker would (the
 * checksums made again: only the signatures, the chain and the commitments stand): never applied, the frames before it
 * taken */
static void t_relay_garble(void)
{
    relay r;
    CHECK(relay_setup(&r));
    test_seed(29);
    uint8_t *b = malloc(r.len);
    CHECK(b);
    if (!b) return;
    for (int i = 0; i < 120; i++) {
        memcpy(b, r.stream, r.len);
        size_t at = (size_t)(test_rand() % r.len);
        uint8_t bit = (uint8_t)(1u << (test_rand() % 8));
        b[at] ^= bit;
        size_t f = 0;
        while (f + 1 < r.nf && r.frames[f + 1] <= at) f++;
        bool attacker = i % 2 == 1 && at >= r.frames[f] + 16; /* a body byte: its checksums recomputed */
        if (attacker) refresh_crcs(b + r.frames[f]);
        char what[120];
        snprintf(what, sizeof what, "byte %zu (frame %zu) flipped%s", at, f + 1, attacker ? ", checksums made again" : "");
        DELIVER(b, r.len, what, rc_ != IMDB_OK && at_ <= f);
    }
    free(b);
    relay_free(&r);
}

/* Out of file descriptors (EMFILE), in a child: an open, a commit, a CHECKPOINT and a ship each fail cleanly or work,
 * never crash, and once the limit is raised the database opens with every acknowledged commit, VERIFY passing */
static void t_relay_emfile(void)
{
    const char *base = test_tmpdir();
    char p[600], out[620];
    snprintf(p, sizeof p, "%s/p", base);
    snprintf(out, sizeof out, "%s/ship", base);
    OK(imdb_init(p, false, NULL, E));
    imdb_db *db = open_db(p);
    CHECK(db);
    if (!db) return;
    OK(make_table(db, E));
    OK(ins1(db, 1, 1, 1, "before"));
    uint64_t before = db->seq;
    imdb_close(db);
    for (int squeeze = 0; squeeze < 12; squeeze++) {
        int pf[2];
        CHECK(pipe(pf) == 0);
        fflush(NULL);
        pid_t pid = fork();
        if (pid == 0) {
            close(pf[0]);
            struct rlimit rl;
            getrlimit(RLIMIT_NOFILE, &rl);
            int open_now = 0;
            for (int fd = 0; fd < 1024; fd++) open_now += fcntl(fd, F_GETFD) != -1;
            rl.rlim_cur = (rlim_t)(open_now + squeeze); /* a few to spare, then none */
            setrlimit(RLIMIT_NOFILE, &rl);
            imdb_err e = {0};
            imdb_open_opts o = {.sync = 1};
            imdb_db *d = NULL;
            uint64_t acked = 0;
            if (!imdb_open(p, &o, &d, &e)) {
                imdb_err e2 = {0};
                int64_t id = 100 + squeeze;
                if (ins1(d, id, 1, 1, "under the limit") == 0) acked = d->seq;
                (void)imdb_checkpoint(d, &e2);
                imdb_close(d);
            }
            (void)ship_to_file(p, 0, out, &e);
            if (write(pf[1], &acked, sizeof acked) != (ssize_t)sizeof acked) _exit(3);
            _exit(0);
        }
        close(pf[1]);
        uint64_t acked = 0;
        ssize_t got = read(pf[0], &acked, sizeof acked);
        close(pf[0]);
        int st = 0;
        CHECK(pid > 0 && waitpid(pid, &st, 0) == pid);
        CHECK(WIFEXITED(st) && WEXITSTATUS(st) == 0 && got == (ssize_t)sizeof acked);
        db = open_db(p);
        CHECK(db);
        if (!db) return;
        CHECK(db->seq >= before && db->seq >= acked);
        imdb_verify_report vr;
        memset(&vr, 0, sizeof vr);
        OK(imdb_verify(db, &vr, E));
        before = db->seq;
        imdb_close(db);
    }
}

const test_case relay_tests[] = {
    {"relay_cut", t_relay_cut},
    {"relay_order", t_relay_order},
    {"relay_garble", t_relay_garble},
    {"relay_emfile", t_relay_emfile},
};
const size_t relay_ntests = sizeof relay_tests / sizeof *relay_tests;
