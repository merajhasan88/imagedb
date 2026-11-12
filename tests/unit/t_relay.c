/* The replication stream through a relay that cuts, duplicates, reorders and garbles it (P0 fault injection,
 * 2026-11-04; docs/plan-p0.md), and a process out of file descriptors. A replica must take only what is the primary's:
 * whatever arrives, it ends at a prefix of the primary's chain (its last commit's hash the primary's for that commit),
 * refuses at or before the damage, and catches up from a clean stream to the primary's view token. A cut stream is a
 * dropped connection, never an error about the data; a damaged one is refused, never applied. R1.2: the keep-alives
 * between a session's frames (repl.h) under the same relay, ship's idle ones, and a follower's silence. */
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdlib.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>

#include "../../src/log.h"
#include "../../src/repl.h"
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

/* a primary with variety in its stream: inserts, updates, deletes, role ops (L), a CHECKPOINT (a publish), an ERASE and
 * an ERASE ROLE (redactions a replica must see authorised) and commits after them; *n: its last commit */
static int make_primary(const char *p, uint64_t *n)
{
    if (imdb_init(p, false, NULL, E)) return -1;
    imdb_db *db = open_db(p);
    if (!db) return -1;
    int rc = make_table(db, E);
    for (int64_t i = 1; !rc && i <= 12; i++) rc = ins1(db, i, i % 3 == 0 ? 42 : i % 4, i * 10, i % 3 == 0 ? "relay-42" : "relay");
    if (!rc) rc = ex(db, "UPDATE txns SET amount = amount + 1 WHERE id <= 4");
    if (!rc) rc = ex(db, "DELETE FROM txns WHERE id = 5");
    if (!rc) rc = ex(db, "CREATE ROLE relay_r PASSWORD 'relay-pw'"); /* L: role entries in the stream, cut at every byte */
    if (!rc) rc = ex(db, "ALTER ROLE relay_r PASSWORD 'relay-pw-2'");
    if (!rc) rc = imdb_checkpoint(db, E);
    imdb_value subj = {.type = IMDB_T_INT64, .i = 42};
    imdb_erase_report rep;
    if (!rc) rc = imdb_erase_subject(db, &subj, &rep, E);
    if (!rc) rc = ex(db, "ERASE ROLE relay_r"); /* L stage 2: its first verifier redacted, the ERASE authorising it */
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
    uint8_t db_id[16];          /* the primary's (R1.2: a session's records carry it) */
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
    memcpy(r->db_id, db->db_id, 16);
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
static uint64_t g_primary_seq; /* R1.2: the last delivery's replication.primary_seq, before the clean stream */

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
    g_primary_seq = db->stats.repl_primary_seq;
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

/* ---- R1.2: keep-alives (repl.h) --------------------------------------------------------------------------------- */

typedef struct alive_stream {
    uint8_t *b;
    size_t len;
    size_t ka[64];       /* each keep-alive's offset */
    uint64_t before[64]; /* the whole frames before it */
    size_t nka;
    uint8_t nonce[16];
} alive_stream;

/* The stream ship --follow --acks makes: its session record, then the frames, a keep-alive before the first, after every
 * third and after the last (that one naming last_named), each naming the commits before it and counted from 1 */
static bool alive_make(const relay *r, alive_stream *a, uint64_t last_named)
{
    memset(a, 0, sizeof *a);
    for (int i = 0; i < 16; i++) a->nonce[i] = (uint8_t)(0xA0 + i);
    a->b = malloc(IMDB_SESSION_LEN + r->len + (r->nf / 3 + 3) * IMDB_ALIVE_LEN);
    if (!a->b) return false;
    imdb_session_encode(r->db_id, a->nonce, a->b);
    a->len = IMDB_SESSION_LEN;
    for (size_t f = 0; f <= r->nf; f++) {
        if (f % 3 == 0 || f == r->nf) {
            if (a->nka == 64) return false;
            a->ka[a->nka] = a->len;
            a->before[a->nka] = f;
            imdb_alive_encode(r->db_id, a->nonce, f == r->nf ? last_named : f, r->hash[f], a->nka + 1, a->b + a->len);
            a->nka++;
            a->len += IMDB_ALIVE_LEN;
        }
        if (f < r->nf) {
            size_t fl = r->frames[f + 1] - r->frames[f];
            memcpy(a->b + a->len, r->stream + r->frames[f], fl);
            a->len += fl;
        }
    }
    return true;
}

/* Keep-alives in a shipping session's stream. Whole, it applies to the primary's last commit, the replica noting the
 * commit the last keep-alive named; cut at every byte of one keep-alive and at the edges of the others, it is a dropped
 * connection holding exactly the frames before the cut; a keep-alive twice or out of order is refused, as is each byte
 * of one flipped (its checksum then disagrees), one of another database or shipping session (the checksum made again),
 * and one outside a session; another commit or head named (the checksum made again) is taken as said, advisory: no
 * keep-alive is ever a commit */
static void t_relay_alive(void)
{
    relay r;
    CHECK(relay_setup(&r));
    alive_stream a;
    CHECK(alive_make(&r, &a, r.last + 5));
    uint8_t *b = malloc(a.len + 2 * IMDB_ALIVE_LEN);
    CHECK(b && a.b && a.nka >= 4);
    if (!b || !a.b || a.nka < 4) {
        free(b);
        free(a.b);
        relay_free(&r);
        return;
    }
    char what[120];
    DELIVER(a.b, a.len, "keep-alives between the frames", rc_ == IMDB_OK && at_ == r.last);
    SOFT(g_primary_seq == r.last + 5);
    size_t mid = a.nka / 2;
    for (size_t k = 0; k < a.nka; k++) {
        size_t lo = a.ka[k], hi = lo + IMDB_ALIVE_LEN;
        for (size_t c = lo; c <= hi && c <= a.len; c++) {
            if (k != mid && c > lo + 1 && c + 1 < hi) continue;
            int rc_ = 0;
            uint64_t at_ = 0;
            bool cut_ = false;
            const char *w_ = deliver(&r, a.b, c, &rc_, &at_, &cut_);
            bool inside = c > lo && c < hi;
            /* the end right before or after a keep-alive is a clean end (or, between an ERASE's redactions and their
             * authorisation, a resumable one) */
            bool ok = !w_ && at_ == a.before[k] && (inside ? rc_ != IMDB_OK && cut_ : rc_ == IMDB_OK || cut_);
            if (!ok) {
                char m_[600];
                snprintf(m_, sizeof m_, "keep-alive %zu cut at its byte %zu: %s (apply %d, cut %d, at %llu of %llu: %s)",
                         k + 1, c - lo, w_ ? w_ : "unexpected outcome", rc_, (int)cut_, (unsigned long long)at_,
                         (unsigned long long)a.before[k], g_e.msg);
                test_fail(__FILE__, __LINE__, m_);
            }
        }
    }
    for (size_t k = 0; k < a.nka; k++) { /* each one twice */
        size_t lo = a.ka[k], hi = lo + IMDB_ALIVE_LEN;
        memcpy(b, a.b, hi);
        memcpy(b + hi, a.b + lo, IMDB_ALIVE_LEN);
        memcpy(b + hi + IMDB_ALIVE_LEN, a.b + hi, a.len - hi);
        snprintf(what, sizeof what, "keep-alive %zu twice", k + 1);
        DELIVER(b, a.len + IMDB_ALIVE_LEN, what, rc_ != IMDB_OK && !cut_ && at_ == a.before[k]);
    }
    { /* the first again after the third */
        size_t at3 = a.ka[2] + IMDB_ALIVE_LEN;
        memcpy(b, a.b, at3);
        memcpy(b + at3, a.b + a.ka[0], IMDB_ALIVE_LEN);
        memcpy(b + at3 + IMDB_ALIVE_LEN, a.b + at3, a.len - at3);
        DELIVER(b, a.len + IMDB_ALIVE_LEN, "the first keep-alive again after the third",
                rc_ != IMDB_OK && !cut_ && at_ == a.before[2]);
    }
    for (size_t i = 0; i < IMDB_ALIVE_LEN; i++) { /* each byte of the middle one flipped */
        memcpy(b, a.b, a.len);
        b[a.ka[mid] + i] ^= 0x10;
        snprintf(what, sizeof what, "keep-alive %zu, its byte %zu flipped", mid + 1, i);
        DELIVER(b, a.len, what, rc_ != IMDB_OK && !cut_ && at_ == a.before[mid]);
    }
    uint8_t other[32];
    memset(other, 0x5A, sizeof other);
    uint64_t named = a.before[mid];
    memcpy(b, a.b, a.len);
    imdb_alive_encode(other, a.nonce, named, r.hash[named], mid + 1, b + a.ka[mid]);
    DELIVER(b, a.len, "a keep-alive of another database", rc_ != IMDB_OK && !cut_ && at_ == a.before[mid]);
    memcpy(b, a.b, a.len);
    imdb_alive_encode(r.db_id, other, named, r.hash[named], mid + 1, b + a.ka[mid]);
    DELIVER(b, a.len, "a keep-alive of another shipping session", rc_ != IMDB_OK && !cut_ && at_ == a.before[mid]);
    memcpy(b, a.b, a.len);
    imdb_alive_encode(r.db_id, a.nonce, 7, other, a.nka, b + a.ka[a.nka - 1]);
    DELIVER(b, a.len, "the last keep-alive naming commit 7 and another head", rc_ == IMDB_OK && at_ == r.last);
    SOFT(g_primary_seq == 7);
    { /* outside a session: the plain stream, a keep-alive after its second frame (a zero nonce, as a reader without a
       * session holds: only the rule refuses it) */
        size_t at = r.frames[2];
        memcpy(b, r.stream, at);
        static const uint8_t zero16[16];
        imdb_alive_encode(r.db_id, zero16, 2, r.hash[2], 1, b + at);
        memcpy(b + at + IMDB_ALIVE_LEN, r.stream + at, r.len - at);
        DELIVER(b, r.len + IMDB_ALIVE_LEN, "a keep-alive outside a shipping session", rc_ != IMDB_OK && !cut_ && at_ == 2);
    }
    free(b);
    free(a.b);
    relay_free(&r);
}

/* n bytes from fd, each read waiting at most 5 s (a shipper that sends nothing fails the test, never hangs it) */
static bool read_full(int fd, void *p, size_t n)
{
    size_t done = 0;
    while (done < n) {
        struct pollfd pl = {.fd = fd, .events = POLLIN};
        if (poll(&pl, 1, 5000) <= 0) return false;
        ssize_t k = read(fd, (uint8_t *)p + done, n - done);
        if (k < 0 && errno == EINTR) continue;
        if (k <= 0) return false;
        done += (size_t)k;
    }
    return true;
}

static bool write_full(int fd, const void *p, size_t n)
{
    size_t done = 0;
    while (done < n) {
        ssize_t k = write(fd, (const uint8_t *)p + done, n - done);
        if (k < 0 && errno == EINTR) continue;
        if (k <= 0) return false;
        done += (size_t)k;
    }
    return true;
}

/* ship --follow --acks, caught up and idle, sends a keep-alive each interval (40 ms here): its session's nonce, counted
 * from 1, naming the primary's durable commit and its head; without --acks (no session) it sends none */
static void t_relay_alive_ship(void)
{
    relay r;
    CHECK(relay_setup(&r));
    for (int acks = 1; acks >= 0; acks--) {
        int so[2], ai[2];
        CHECK(pipe(so) == 0 && pipe(ai) == 0);
        fflush(NULL);
        pid_t pid = fork();
        if (pid == 0) {
            close(so[0]);
            close(ai[1]);
            imdb_err e = {0};
            imdb_ship_opts o = {.follow = true, .ackfd = acks ? ai[0] : -1, .keepalive_ms = 40};
            (void)imdb_ship_ex(r.p, r.last, so[1], &o, &e);
            _exit(0);
        }
        close(so[1]);
        close(ai[0]);
        if (acks) {
            uint8_t sr[IMDB_SESSION_LEN], ka[IMDB_ALIVE_LEN], nonce[16];
            SOFT(read_full(so[0], sr, sizeof sr) && imdb_session_decode(sr, r.db_id, nonce, E) == 1);
            uint64_t t0 = imdb_mono_ns();
            for (uint64_t k = 1; k <= 4; k++) {
                uint64_t seq = 0, counter = 0;
                uint8_t head[32];
                SOFT(read_full(so[0], ka, sizeof ka));
                SOFT(imdb_alive_decode(ka, r.db_id, nonce, &seq, head, &counter, E) == 1);
                SOFT(seq == r.last && memcmp(head, r.hash[r.last], 32) == 0 && counter == k);
            }
            SOFT((imdb_mono_ns() - t0) / 1000000u >= 4 * 40 - 15); /* each at least the interval after the one before */
        } else {
            struct pollfd p = {.fd = so[0], .events = POLLIN};
            SOFT(poll(&p, 1, 300) == 0); /* nothing in 300 ms, seven intervals */
        }
        kill(pid, SIGKILL);
        int st = 0;
        SOFT(waitpid(pid, &st, 0) == pid);
        close(so[0]);
        close(ai[1]);
    }
    relay_free(&r);
}

static int note_ack(void *ctx, imdb_db *db)
{
    *(uint64_t *)ctx = db->seq;
    return 0;
}

typedef struct stat_find {
    const char *name;
    int64_t v;
    bool found;
} stat_find;

static int stat_find_fn(void *ctx, const char *name, int64_t v)
{
    stat_find *f = ctx;
    if (strcmp(name, f->name) == 0) {
        f->v = v;
        f->found = true;
    }
    return 0;
}

static bool stat_row(imdb_db *db, const char *name, int64_t *v)
{
    stat_find f = {name, 0, false};
    (void)imdb_stats_each(db, stat_find_fn, &f, false);
    *v = f.v;
    return f.found;
}

/* A follower's apply (silent_ms, 300 here) drops a connection that says nothing for so long once its session began, and
 * calls it a cut (resumable, silent), holding every frame before; keep-alives keep a quiet one open; without a session
 * it waits for the stream's end. The replica takes the commit the keep-alives name (replication.primary_seq) and, once
 * following, says how long since it heard any record (replication.last_heard_ms; -1 while not following). The stream
 * arrives at once, so its last commit is read with its keep-alive behind it: that keep-alive, with nothing more ready,
 * is the point that acknowledges the commit (none would come before the silence) */
static void t_relay_alive_silence(void)
{
    relay r;
    CHECK(relay_setup(&r));
    alive_stream a;
    CHECK(alive_make(&r, &a, r.last));
    for (int mode = 0; mode < 3 && a.b; mode++) { /* 0: then silence; 1: keep-alives for 600 ms, then silence; 2: no session */
        char rep[700];
        snprintf(rep, sizeof rep, "%s/silent%d", r.dir, mode);
        OK(imdb_init(rep, true, r.p, E));
        imdb_db *db = open_db(rep);
        CHECK(db);
        if (!db) break;
        int pf[2];
        if (pipe(pf) != 0) {
            test_fail(__FILE__, __LINE__, "pipe");
            imdb_close(db);
            break;
        }
        fflush(NULL);
        pid_t pid = fork();
        if (pid == 0) {
            close(pf[0]);
            if (!write_full(pf[1], mode == 2 ? r.stream : a.b, mode == 2 ? r.len : a.len)) _exit(1);
            for (uint64_t k = 0; mode == 1 && k < 6; k++) {
                struct timespec ts = {0, 100 * 1000 * 1000};
                nanosleep(&ts, NULL);
                uint8_t ka[IMDB_ALIVE_LEN];
                imdb_alive_encode(r.db_id, a.nonce, r.last, r.hash[r.last], a.nka + 1 + k, ka);
                if (!write_full(pf[1], ka, sizeof ka)) _exit(1);
            }
            struct timespec ts = {mode == 2 ? 0 : 10, mode == 2 ? 600 * 1000 * 1000 : 0}; /* the pipe held open (killed sooner) */
            nanosleep(&ts, NULL);
            _exit(0);
        }
        close(pf[1]);
        imdb_apply_opts ao;
        memset(&ao, 0, sizeof ao);
        ao.silent_ms = 300;
        uint64_t acked = UINT64_MAX;
        ao.applied = note_ack;
        ao.ctx = &acked;
        uint64_t applied = 0, t0 = imdb_mono_ns();
        imdb_err_clear(E);
        int rc = imdb_apply_stream_ex(db, pf[0], &applied, &ao, E);
        uint64_t el = (imdb_mono_ns() - t0) / 1000000u;
        kill(pid, SIGKILL);
        int st = 0;
        SOFT(waitpid(pid, &st, 0) == pid);
        close(pf[0]);
        SOFT(db->seq == r.last && memcmp(db->head, r.hash[r.last], 32) == 0);
        if (mode < 2) {
            if (!(rc != IMDB_OK && ao.silent && ao.truncated && ao.has_session)) {
                char m[400];
                snprintf(m, sizeof m, "mode %d: apply %d silent %d cut %d session %d after %llu ms: %s", mode, rc,
                         (int)ao.silent, (int)ao.truncated, (int)ao.has_session, (unsigned long long)el, g_e.msg);
                test_fail(__FILE__, __LINE__, m);
            }
            /* before the child's end (10 s, room for a loaded SAN run: 2.5 s was missed at load 12, 11-07), past the keep-alives;
             * ao.silent already says a read timed out, which a pipe the child closed never does */
            SOFT(el < 9500 && (mode == 0 || el >= 600 + 300 - 50));
        } else {
            SOFT(rc == IMDB_OK && !ao.silent && !ao.truncated && !ao.has_session && el >= 550);
        }
        SOFT(db->stats.repl_primary_seq == r.last);
        SOFT(acked == r.last); /* the last commit acknowledged before the silence (mode 2: at the stream's end) */
        int64_t heard = 0, named = 0;
        SOFT(stat_row(db, "replication.last_heard_ms", &heard) && heard == -1); /* not following */
        db->following = true;
        /* modes 0 and 1: the read that ended it waited 300 ms after the last record; mode 2: heard, the time unbounded */
        bool hr = stat_row(db, "replication.last_heard_ms", &heard);
        /* mode 1: heard counts from the last keep-alive, 600 ms after the frames, so well short of the whole wait */
        if (!hr || heard < (mode == 2 ? 0 : 300) || (mode == 1 && (uint64_t)heard + 300 >= el)) {
            char m[160];
            snprintf(m, sizeof m, "mode %d: replication.last_heard_ms %lld (found %d), the apply %llu ms", mode,
                     (long long)heard, (int)hr, (unsigned long long)el);
            test_fail(__FILE__, __LINE__, m);
        }
        SOFT(stat_row(db, "replication.primary_seq", &named) && named == (int64_t)r.last);
        db->following = false;
        imdb_close(db);
    }
    free(a.b);
    relay_free(&r);
}

const test_case relay_tests[] = {
    {"relay_cut", t_relay_cut},
    {"relay_order", t_relay_order},
    {"relay_garble", t_relay_garble},
    {"relay_emfile", t_relay_emfile},
    {"relay_alive", t_relay_alive},
    {"relay_alive_ship", t_relay_alive_ship},
    {"relay_alive_silence", t_relay_alive_silence},
};
const size_t relay_ntests = sizeof relay_tests / sizeof *relay_tests;
