/* External round-3 review: failure paths across writer epochs and replica administration. */
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

#include "../../src/repl.h"
#include "../../src/sql.h"
#include "../../src/writer.h"
#include "thelp.h"

static imdb_db *anchored(const char *dir, const char *anchor, bool ro)
{
    imdb_open_opts o = {.sync = 1, .anchor = anchor, .read_only = ro};
    imdb_db *db = NULL;
    imdb_err_clear(E);
    return imdb_open(dir, &o, &db, E) ? NULL : db;
}

static void review_key(imdb_signer *s, uint8_t tag)
{
    uint8_t seed[32];
    memset(seed, tag, sizeof seed);
    imdb_signer_init(s, seed);
    imdb_wipe(seed, sizeof seed);
}

static long unreadable_anchor(imdb_io_call *c, void *ctx)
{
    if (c->op == IMDB_IO_OPEN && c->name && strcmp(c->name, ctx) == 0) {
        errno = EIO;
        return -1;
    }
    return 0;
}

static void t_round3_anchor_unavailable(void)
{
    const char *base = test_tmpdir();
    for (int mode = 0; mode < 3; mode++) {
        char p[650], a[650], saved[650];
        snprintf(p, sizeof p, "%s/p%d", base, mode);
        snprintf(a, sizeof a, "%s/anchor%d", base, mode);
        snprintf(saved, sizeof saved, "%s/saved%d", base, mode);
        OK(imdb_init(p, false, NULL, E));
        imdb_db *db = anchored(p, a, false);
        CHECK(db);
        OK(make_table(db, E));
        uint64_t seq = db->seq;
        size_t len;
        uint8_t *bytes = slurp(a, &len);
        CHECK(bytes && len == IMDB_ANCHOR_FILE);
        if (mode == 0) CHECK(rename(a, saved) == 0);
        if (mode == 1) {
            uint8_t bad[IMDB_ANCHOR_FILE] = {0};
            spit(a, bad, sizeof bad);
        }
        imdb_io_hooks h = {.before = unreadable_anchor, .ctx = a};
        if (mode == 2) imdb_io_set_hooks(&h);
        int rc = ins1(db, 1, 42, 100, "must be refused");
        imdb_io_set_hooks(NULL);
        bool stopped = rc != IMDB_OK && db->failed && db->seq == seq;
        if (mode == 0) CHECK(rename(saved, a) == 0);
        else spit(a, bytes, len);
        free(bytes);
        imdb_close(db);
        CHECK(stopped);
    }
}

static int audit_anchor(const char *dir, const char *anchor)
{
    const char *bin = getenv("IMDB_AUDIT_BIN");
    if (!bin || !*bin) return -1;
    char cmd[2200];
    snprintf(cmd, sizeof cmd, "'%s' verify '%s' --anchor '%s' >/dev/null 2>&1", bin, dir, anchor);
    return system(cmd) == 0 ? 0 : 1;
}

/* The old writer reached commit 7, while promotion deliberately branches from 2 at epoch 1. */
static void anchor_promotion(bool mixed)
{
    const char *base = test_tmpdir();
    char p[650], r[650], a[650], stream[650];
    snprintf(p, sizeof p, "%s/p", base);
    snprintf(r, sizeof r, "%s/r", base);
    snprintf(a, sizeof a, "%s/anchor", base);
    snprintf(stream, sizeof stream, "%s/stream", base);
    uint8_t seed[32];
    memset(seed, 0x69, sizeof seed);
    imdb_signer root;
    imdb_signer_init(&root, seed);
    OK(imdb_init_primary(p, root.pk, E));
    OK(imdb_init(r, true, p, E));
    imdb_db *old = anchored(p, a, false);
    CHECK(old);
    OK(make_table(old, E));
    OK(ins1(old, 1, 42, 100, "base"));
    OK(ship_to_file(p, 0, stream, E));
    imdb_db *rep = anchored(r, NULL, false);
    CHECK(rep);
    uint64_t applied;
    OK(apply_file(rep, stream, &applied, E));
    CHECK(applied == 2);
    imdb_close(rep);
    for (int64_t id = 2; id <= 6; id++) OK(ins1(old, id, 42, 100, "abandoned"));
    CHECK(old->seq == 7);
    imdb_close(old);
    imdb_promote_opts po = {.old_writer_stopped = true}; /* the old writer is closed: the anchor sees the cut later */
    imdb_promote_result pr;
    OK(imdb_promote(r, seed, &po, &pr, E));
    rep = anchored(r, NULL, false);
    CHECK(rep && rep->seq == 3 && imdb_current_epoch(rep) == 1);
    if (mixed) {
        size_t n;
        uint8_t *b = slurp(a, &n);
        CHECK(b && n == IMDB_ANCHOR_FILE);
        imdb_anchor next = {.seq = rep->seq, .hlen = rep->last_hlen, .epoch = 1};
        memcpy(next.db_id, rep->db_id, 16);
        memcpy(next.hash, rep->head, 32);
        memcpy(next.sig, rep->last_sig, IMDB_SIG_LEN);
        imdb_anchor_encode(&next, b + IMDB_ANCHOR_SLOT);
        spit(a, b, n); /* a crash between replacing the two old-epoch slots */
        free(b);
    }
    imdb_close(rep);
    bool old_refused = true, audit_old_refused = true;
    if (mixed) {
        old = anchored(p, a, true);
        old_refused = old == NULL;
        if (old) imdb_close(old);
        audit_old_refused = audit_anchor(p, a) != 0;
    }
    bool audit_new_ok = audit_anchor(r, a) <= 0;
    rep = anchored(r, a, false);
    bool new_ok = rep && rep->seq == 3;
    if (rep) imdb_close(rep);
    imdb_signer_wipe(&root);
    imdb_wipe(seed, sizeof seed);
    CHECK(old_refused && audit_old_refused && audit_new_ok && new_ok);
}

static void t_round3_anchor_epoch_priority(void) { anchor_promotion(true); }
static void t_round3_anchor_promotion_gap(void) { anchor_promotion(false); }

typedef struct rotate_fault {
    bool renamed, fired;
    int dirfd;
} rotate_fault;

static long rotation_sync_fault(imdb_io_call *c, void *ctx)
{
    rotate_fault *f = ctx;
    if (c->op == IMDB_IO_RENAME && c->name && strcmp(c->name, IMDB_SIGNING_NEXT_NAME) == 0)
        f->renamed = true;
    if (f->renamed && !f->fired && c->op == IMDB_IO_FSYNC && c->fd == f->dirfd) {
        f->fired = true;
        errno = EIO;
        return -1;
    }
    return 0;
}

static void t_round3_rotation_sync_failure(void)
{
    const char *p = test_tmpdir();
    OK(imdb_init(p, false, NULL, E));
    imdb_db *db = anchored(p, NULL, false);
    CHECK(db);
    OK(make_table(db, E));
    rotate_fault f = {.dirfd = db->dirfd};
    imdb_io_hooks h = {.before = rotation_sync_fault, .ctx = &f};
    imdb_io_set_hooks(&h);
    int rc = imdb_rotate_key(db, E);
    imdb_io_set_hooks(NULL);
    bool stopped = f.fired && rc == IMDB_OK && db->seq == 2 && db->failed && db->warning[0];
    imdb_close(db);
    db = anchored(p, NULL, false);
    bool recovered = db && imdb_current_epoch(db) == 1;
    if (db) imdb_close(db);
    CHECK(stopped && recovered);
}

static long readdir_fault(imdb_io_call *c, void *ctx)
{
    (void)ctx;
    if (c->op == IMDB_IO_READDIR) {
        errno = EIO;
        return -1;
    }
    return 0;
}

static void t_round3_allowlist_read_failure(void)
{
    const char *p = test_tmpdir();
    OK(imdb_init(p, false, NULL, E));
    imdb_db *db = anchored(p, NULL, false);
    CHECK(db);
    imdb_signer k;
    review_key(&k, 0x79);
    OK(imdb_replica_add(p, "r1", k.pk, false, E));
    imdb_allow *a = NULL;
    size_t n = 0;
    imdb_io_hooks h = {.before = readdir_fault};
    imdb_io_set_hooks(&h);
    int rc = imdb_allowlist_load(db->dirfd, &a, &n, E);
    imdb_io_set_hooks(NULL);
    bool refused = rc == IMDB_ERR_IO && a == NULL && n == 0;
    free(a);
    imdb_signer_wipe(&k);
    imdb_close(db);
    CHECK(refused);
}

/* these acknowledgements carry a zero nonce: the session they are received in */
static const uint8_t kNoNonce[IMDB_NONCE_LEN];

static int same_head(void *ctx, uint64_t seq, uint8_t out[32])
{
    imdb_db *db = ctx;
    if (seq != db->seq) return 0;
    memcpy(out, db->head, 32);
    return 1;
}

static void t_round3_revoked_replica_cache(void)
{
    const char *p = test_tmpdir();
    OK(imdb_init(p, false, NULL, E));
    imdb_db *db = anchored(p, NULL, false);
    CHECK(db);
    OK(make_table(db, E));
    imdb_signer old, next;
    review_key(&old, 0x7a);
    review_key(&next, 0x7b);
    OK(imdb_replica_add(p, "r1", old.pk, false, E));
    imdb_allow *allow = NULL;
    size_t n = 0;
    OK(imdb_allowlist_load(db->dirfd, &allow, &n, E)); /* a long-running shipper's cache */
    OK(imdb_replica_add(p, "r1", next.pk, true, E));
    imdb_ack ack = {.seq = db->seq};
    memcpy(ack.db_id, db->db_id, 16);
    memcpy(ack.replica, old.pk, 32);
    memcpy(ack.head, db->head, 32);
    ack.head[0] ^= 1; /* a revoked key must not poison the replacement's divergence state */
    uint8_t raw[IMDB_ACK_LEN];
    imdb_ack_sign(&ack, &old, raw);
    int rc = imdb_ack_receive(db->dirfd, db->db_id, kNoNonce, &allow, &n, raw, same_head, db, NULL, E);
    char incident[700];
    snprintf(incident, sizeof incident, "%s/replicas/r1.diverged", p);
    bool refused = rc == IMDB_ERR_AUTH && file_size(incident) < 0;
    memcpy(ack.replica, next.pk, 32);
    memcpy(ack.head, db->head, 32);
    imdb_ack_sign(&ack, &next, raw);
    int nrc = imdb_ack_receive(db->dirfd, db->db_id, kNoNonce, &allow, &n, raw, same_head, db, NULL, E);
    imdb_free(allow);
    imdb_signer_wipe(&old);
    imdb_signer_wipe(&next);
    imdb_close(db);
    CHECK(refused && nrc == IMDB_OK);
}

typedef struct close_fault {
    int fd;
    bool fired;
} close_fault;

static long closing_sync_fault(imdb_io_call *c, void *ctx)
{
    close_fault *f = ctx;
    if (c->op == IMDB_IO_FSYNC && c->fd == f->fd) {
        f->fired = true;
        errno = EIO;
        return -1;
    }
    return 0;
}

static void t_round3_close_sync_failure(void)
{
    const char *base = test_tmpdir();
    bool reported = true;
    for (int mode = 0; mode < 2; mode++) {
        char p[650], a[650];
        snprintf(p, sizeof p, "%s/p%d", base, mode);
        snprintf(a, sizeof a, "%s/anchor%d", base, mode);
        OK(imdb_init(p, false, NULL, E));
        imdb_db *db = anchored(p, a, false);
        CHECK(db);
        OK(make_table(db, E));
        close_fault f = {.fd = mode ? db->anchorfd : db->durfd};
        imdb_io_hooks h = {.before = closing_sync_fault, .ctx = &f};
        imdb_io_set_hooks(&h);
        int rc = imdb_close(db);
        imdb_io_set_hooks(NULL);
        reported &= f.fired && rc == IMDB_ERR_IO;
    }
    CHECK(reported);
}

typedef struct incident_fault {
    int mode;
    bool fired;
} incident_fault;

static long incident_io_fault(imdb_io_call *c, void *ctx)
{
    incident_fault *f = ctx;
    bool hit = f->mode == 0 ? c->op == IMDB_IO_STAT && c->name && strcmp(c->name, "r1.diverged") == 0
                           : c->op == IMDB_IO_RENAME && c->name2 && strcmp(c->name2, "r1.diverged") == 0;
    if (hit) {
        f->fired = true;
        errno = EIO;
        return -1;
    }
    return 0;
}

static void t_round3_incident_io_failure(void)
{
    const char *base = test_tmpdir();
    bool refused = true;
    for (int mode = 0; mode < 2; mode++) {
        char p[650], ackpath[700];
        snprintf(p, sizeof p, "%s/p%d", base, mode);
        snprintf(ackpath, sizeof ackpath, "%s/replicas/r1.ack", p);
        OK(imdb_init(p, false, NULL, E));
        imdb_db *db = anchored(p, NULL, false);
        CHECK(db);
        OK(make_table(db, E));
        imdb_signer key;
        review_key(&key, 0x7c);
        OK(imdb_replica_add(p, "r1", key.pk, false, E));
        imdb_allow *allow = NULL;
        size_t n = 0;
        OK(imdb_allowlist_load(db->dirfd, &allow, &n, E));
        imdb_ack ack = {.seq = db->seq};
        memcpy(ack.db_id, db->db_id, 16);
        memcpy(ack.replica, key.pk, 32);
        memcpy(ack.head, db->head, 32);
        if (mode) ack.head[0] ^= 1;
        uint8_t raw[IMDB_ACK_LEN];
        imdb_ack_sign(&ack, &key, raw);
        incident_fault f = {.mode = mode};
        imdb_io_hooks h = {.before = incident_io_fault, .ctx = &f};
        imdb_io_set_hooks(&h);
        int rc = imdb_ack_receive(db->dirfd, db->db_id, kNoNonce, &allow, &n, raw, same_head, db, NULL, E);
        imdb_io_set_hooks(NULL);
        refused &= f.fired && rc == IMDB_ERR_IO && file_size(ackpath) < 0;
        imdb_free(allow);
        imdb_signer_wipe(&key);
        imdb_close(db);
    }
    CHECK(refused);
}

static long seed_stat_fault(imdb_io_call *c, void *ctx)
{
    bool *fired = ctx;
    if (c->op == IMDB_IO_STAT && !c->name) {
        *fired = true;
        errno = EIO;
        return -1;
    }
    return 0;
}

static void t_round3_pending_key_preserved(void)
{
    const char *base = test_tmpdir();
    for (int mode = 0; mode < 2; mode++) {
        char p[650], key[700], next[700];
        snprintf(p, sizeof p, "%s/p%d", base, mode);
        snprintf(key, sizeof key, "%s/signing.key", p);
        snprintf(next, sizeof next, "%s/signing.key.next", p);
        OK(imdb_init(p, false, NULL, E));
        imdb_db *db = anchored(p, NULL, false);
        CHECK(db);
        CHECK(rename(key, next) == 0);
        bool fired = false;
        imdb_io_hooks h = {.before = seed_stat_fault, .ctx = &fired};
        if (mode == 0) imdb_io_set_hooks(&h);
        else CHECK(chmod(next, 0644) == 0);
        int rc = imdb_writer_settle(db, E);
        imdb_io_set_hooks(NULL);
        bool kept = rc == (mode ? IMDB_ERR_AUTH : IMDB_ERR_IO) && file_size(next) == IMDB_SEED_LEN;
        if (mode == 0) kept &= fired;
        if (file_size(next) >= 0) {
            CHECK(chmod(next, 0600) == 0);
            CHECK(rename(next, key) == 0);
        }
        imdb_close(db);
        CHECK(kept);
    }
}

/* the auditor's verdict on dir: 0 accepts, 1 rejects, -1 when it is not available (IMDB_AUDIT_BIN) */
static int audit_dir(const char *dir)
{
    const char *bin = getenv("IMDB_AUDIT_BIN");
    if (!bin || !*bin) return -1;
    char cmd[1600];
    snprintf(cmd, sizeof cmd, "'%s' verify '%s' >/dev/null 2>&1", bin, dir);
    return system(cmd) == 0 ? 0 : 1;
}

/* Review B2: a commit acknowledged under a watermark that is not synced per commit. After an OS
 * crash the older DURABLE image may come back while the commit's frame (synced) stays; damage to
 * that complete frame then looks like an unfinished append. Nothing may drop it but the operator:
 * every open refuses with the bytes untouched, and recover names the doubt. Under --durable-ack the
 * older image means the commit never returned, and an open truncates it; that open, without the
 * flag, marks the watermark not strict before any commit, so the flag never outlives the proof. */
static void damaged_tail(bool strict)
{
    const char *tmp = test_tmpdir();
    char p[600], wm[650];
    snprintf(p, sizeof p, "%s/%s", tmp, strict ? "strict" : "lagging");
    snprintf(wm, sizeof wm, "%s/DURABLE", p);
    OK(imdb_init(p, false, NULL, E));
    imdb_open_opts o = {.sync = 1, .durable_ack = strict}, plain = {.sync = 1}, ro = {.read_only = true};
    imdb_db *db = NULL;
    OK(imdb_open(p, &o, &db, E));
    OK(make_table(db, E));
    size_t wn, n;
    uint8_t *w = slurp(wm, &wn); /* the watermark before the last commit */
    imdb_durable d;
    CHECK(w && imdb_durable_decode(w, wn, &d, E) == IMDB_OK && d.synced && d.strict == strict);
    OK(ins1(db, 1, 42, 100, "the last commit"));
    uint64_t last = db->seq;
    OK(imdb_close(db));
    for (int round = 0; round < (strict ? 2 : 1); round++) {
        if (round) { /* the writer that truncated it commits, without the flag, and its rewrite is lost */
            db = NULL;
            OK(imdb_open(p, &plain, &db, E));
            free(w);
            w = slurp(wm, &wn);
            CHECK(w && imdb_durable_decode(w, wn, &d, E) == IMDB_OK && d.synced && !d.strict && d.seq == last - 1);
            OK(ins1(db, 2, 42, 100, "acknowledged, not strict"));
            CHECK(db->seq == last);
            OK(imdb_close(db));
        }
        spit(wm, w, wn); /* the older image: lost in an OS crash, or (strict) the commit never returned */
        char *log = seg_path(p, -1);
        uint64_t first;
        bool tg;
        uint8_t *b = log ? seg_frames(log, &n, &first, &tg) : NULL; /* frames, either format */
        CHECK(b && n);
        if (!b) break;
        b[n - 1] ^= 1; /* the complete frame fails its checksum */
        seg_put_frames(log, first, tg, b, n);
        free(b);
        long fsz = file_size(log);
        db = NULL;
        if (!strict || round) {
            CHECK(imdb_open(p, &plain, &db, E) == IMDB_ERR_CORRUPT && !db && strstr(g_e.msg, "cannot show that commit"));
            CHECK(imdb_open(p, &ro, &db, E) == IMDB_ERR_CORRUPT && !db);
            CHECK(file_size(log) == fsz);
            imdb_recover_report r;
            OK(imdb_recover_tail(p, false, NULL, &r, E));
            CHECK(r.damaged && r.maybe_acked && !r.acked_lost && r.durable_synced && !r.durable_strict &&
                  r.last == last - 1);
            CHECK(audit_dir(p) != 0);
            break;
        }
        OK(imdb_open(p, &plain, &db, E)); /* the strict record decides, whatever the new writer asks for */
        CHECK(db->seq == last - 1 && strstr(db->warning, "tail truncated") && seg_frames_len(log) < (long)n);
        OK(imdb_close(db));
        CHECK(audit_dir(p) <= 0);
    }
    free(w);
    imdb_open_opts nosync = {.sync = 0, .durable_ack = true}, reader = {.read_only = true, .durable_ack = true};
    db = NULL;
    CHECK(imdb_open(p, &nosync, &db, E) == IMDB_ERR_INVALID && !db);
    CHECK(imdb_open(p, &reader, &db, E) == IMDB_ERR_INVALID && !db);
}
static void t_round3_damaged_tail_lagging(void) { damaged_tail(false); }
static void t_round3_damaged_tail_strict(void) { damaged_tail(true); }

/* digest_alg 2 (2026-10-26): META 4 and identity 3 name the digest algorithm, the older versions
 * are alg 1, and both decoders stay strict about the new line */
static int meta_text(const char *dir, int i, const char *text, imdb_identity *id, bool *rep)
{
    char d[700], f[760];
    snprintf(d, sizeof d, "%s/m%d", dir, i);
    snprintf(f, sizeof f, "%s/META", d);
    FILE *fp = mkdir(d, 0700) == 0 ? fopen(f, "w") : NULL;
    if (!fp || fputs(text, fp) < 0 || fclose(fp) != 0) return -1;
    imdb_err_clear(E);
    return imdb_identity_read(d, id, rep, E);
}

static void t_round3_meta_digest_alg(void)
{
    const char *dir = test_tmpdir();
    char p[700], buf[600], hx[33], wx[65], rx[65];
    snprintf(p, sizeof p, "%s/p", dir);
    OK(imdb_init_primary(p, NULL, E));
    imdb_identity id, b;
    bool rep = true;
    uint8_t def = 0;
    OK(imdb_identity_read(p, &id, &rep, E));
    OK(imdb_default_digest_alg(&def, E));
    CHECK(id.digest_alg == def && !rep && !id.has_root);
    /* identity 3: written and read back, with a root key and without, either algorithm */
    for (int r = 0; r < 2; r++)
        for (uint8_t alg = IMDB_DIGEST_ALG_LTHASH16; alg <= IMDB_DIGEST_ALG_LTHASH16_TREE; alg++) {
            imdb_identity a = id;
            a.has_root = r;
            memset(a.root, r ? 0x5a : 0, sizeof a.root);
            a.digest_alg = alg;
            int n = imdb_identity_format(&a, buf, sizeof buf);
            CHECK(n > 0);
            OK(imdb_identity_parse(buf, (size_t)n, &b, E));
            CHECK(b.digest_alg == alg && b.has_root == a.has_root && memcmp(b.db_id, a.db_id, 16) == 0 &&
                  memcmp(b.writer, a.writer, 32) == 0 && memcmp(b.root, a.root, 32) == 0);
        }
    imdb_hex(id.db_id, 16, hx);
    imdb_hex(id.writer, 32, wx);
    memset(rx, 'a', 64);
    rx[64] = 0;
    /* identity 1 and 2 predate the algorithm: alg 1 */
    snprintf(buf, sizeof buf, "imagedb-identity 1\ndb_id %s\nwriter %s\n", hx, wx);
    OK(imdb_identity_parse(buf, strlen(buf), &b, E));
    CHECK(b.digest_alg == IMDB_DIGEST_ALG_LTHASH16 && !b.has_root);
    snprintf(buf, sizeof buf, "imagedb-identity 2\ndb_id %s\nwriter %s\nroot %s\n", hx, wx, rx);
    OK(imdb_identity_parse(buf, strlen(buf), &b, E));
    CHECK(b.digest_alg == IMDB_DIGEST_ALG_LTHASH16 && b.has_root);
    static const struct {
        const char *tail;
        int rc;
    } bad[] = {{"digest 3\n", IMDB_ERR_UNSUPPORTED}, {"digest x\n", IMDB_ERR_INVALID}, {"digest 1", IMDB_ERR_INVALID},
               {"digest 1\n\n", IMDB_ERR_INVALID}, {"digest  1\n", IMDB_ERR_INVALID}, {"digest 12\n", IMDB_ERR_INVALID},
               {"", IMDB_ERR_INVALID}, {"root zz\ndigest 1\n", IMDB_ERR_INVALID}};
    for (size_t i = 0; i < sizeof bad / sizeof *bad; i++) {
        snprintf(buf, sizeof buf, "imagedb-identity 3\ndb_id %s\nwriter %s\n%s", hx, wx, bad[i].tail);
        imdb_err_clear(E);
        CHECK(imdb_identity_parse(buf, strlen(buf), &b, E) == bad[i].rc);
    }
    /* META 5, with a root key or without, either algorithm; 1 to 4 (earlier formats) refused by name */
    snprintf(buf, sizeof buf, "imagedb-meta 5\ndb_id %s\nrole primary\nwriter %s\ndigest 2\n", hx, wx);
    CHECK(meta_text(dir, 0, buf, &b, &rep) == 0 && b.digest_alg == IMDB_DIGEST_ALG_LTHASH16_TREE && !b.has_root && !rep);
    snprintf(buf, sizeof buf, "imagedb-meta 5\ndb_id %s\nrole replica\nwriter %s\nroot %s\ndigest 1\n", hx, wx, rx);
    CHECK(meta_text(dir, 1, buf, &b, &rep) == 0 && b.digest_alg == IMDB_DIGEST_ALG_LTHASH16 && b.has_root && rep);
    for (int v = 1; v <= 4; v++) {
        snprintf(buf, sizeof buf, "imagedb-meta %d\ndb_id %s\nrole primary\nwriter %s\ndigest 2\n", v, hx, wx);
        CHECK(meta_text(dir, 1 + v, buf, &b, &rep) == IMDB_ERR_UNSUPPORTED && strstr(g_e.msg, "before the retention format"));
    }
    static const char *const badm[] = {"digest 3\n", "", "digest 1", "digest 1\nx", "digest 0\n", "root zz\ndigest 1\n"};
    static const int badrc[] = {IMDB_ERR_UNSUPPORTED, IMDB_ERR_CORRUPT, IMDB_ERR_CORRUPT,
                                IMDB_ERR_CORRUPT, IMDB_ERR_UNSUPPORTED, IMDB_ERR_CORRUPT};
    for (size_t i = 0; i < sizeof badm / sizeof *badm; i++) {
        snprintf(buf, sizeof buf, "imagedb-meta 5\ndb_id %s\nrole primary\nwriter %s\n%s", hx, wx, badm[i]);
        CHECK(meta_text(dir, 10 + (int)i, buf, &b, &rep) == badrc[i]);
    }
}

/* digest_alg 2: every commit of a database names its algorithm. A replica whose META names the
 * other one refuses its primary's stream, either way round; a commit re-signed under the other
 * one is refused by VERIFY (reading the log under an open handle) and by the next open. */
static void meta_with_alg(const char *dir, uint8_t alg)
{
    imdb_identity id;
    bool rep = false;
    OK(imdb_identity_read(dir, &id, &rep, E));
    char hx[33], wx[65], buf[400], m[700];
    snprintf(m, sizeof m, "%s/META", dir);
    imdb_hex(id.db_id, 16, hx);
    imdb_hex(id.writer, 32, wx);
    snprintf(buf, sizeof buf, "imagedb-meta 5\ndb_id %s\nrole %s\nwriter %s\ndigest %u\n", hx, rep ? "replica" : "primary",
             wx, (unsigned)alg);
    spit(m, (const uint8_t *)buf, strlen(buf));
}

static void t_round3_digest_alg_mismatch(void)
{
    const char *dir = test_tmpdir();
    for (uint8_t alg = IMDB_DIGEST_ALG_LTHASH16; alg <= IMDB_DIGEST_ALG_LTHASH16_TREE && !g_test_failed; alg++) {
        char p[700], r[700], s[700];
        snprintf(p, sizeof p, "%s/p%u", dir, alg);
        snprintf(r, sizeof r, "%s/r%u", dir, alg);
        snprintf(s, sizeof s, "%s/s%u", dir, alg);
        OK(imdb_init_primary_alg(p, NULL, alg, E));
        OK(imdb_init(r, true, p, E));
        imdb_identity id;
        bool rep;
        OK(imdb_identity_read(r, &id, &rep, E));
        CHECK(id.digest_alg == alg && rep); /* a replica takes its primary's */
        imdb_db *db = open_db(p);
        CHECK(db);
        if (!db) return;
        OK(make_table(db, E));
        for (int i = 1; i <= 3; i++) CHECK(ins1(db, i, 7, 100 * i, "m") == 0);
        imdb_close(db);
        meta_with_alg(r, alg == IMDB_DIGEST_ALG_LTHASH16 ? IMDB_DIGEST_ALG_LTHASH16_TREE : IMDB_DIGEST_ALG_LTHASH16);
        OK(ship_to_file(p, 0, s, E));
        imdb_db *rdb = open_db(r);
        CHECK(rdb);
        if (!rdb) return;
        uint64_t applied = 0;
        imdb_err_clear(E);
        CHECK(apply_file(rdb, s, &applied, E) != 0 && applied == 0 && strstr(g_e.msg, "digest algorithm") &&
              strstr(g_e.msg, "but this database's is"));
        imdb_close(rdb);
    }
    /* commit 2 of p1 (alg 1) re-signed under alg 2: the same length, so overwritten in place */
    char p[700];
    snprintf(p, sizeof p, "%s/p1", dir);
    imdb_db *db = open_db(p);
    CHECK(db);
    if (!db) return;
    char *seg = seg_path(p, 0);
    size_t n = 0;
    uint64_t first = 0;
    bool tg = false;
    uint8_t *log = seg_frames(seg, &n, &first, &tg); /* frames, either format */
    int dfd = open(p, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    imdb_signer sg;
    bool has = false;
    CHECK(log && dfd >= 0 && imdb_seed_read(dfd, "signing.key", &sg, &has, E) == 0 && has);
    if (dfd >= 0) close(dfd);
    bool done = false;
    for (size_t off = 0, fl = 0; log && has && !done; off += fl) {
        imdb_err e2 = {0};
        if (imdb_frame_scan(log, n, off, &fl, &e2) != IMDB_SCAN_FRAME) break;
        imdb_commit_rec c;
        OK(imdb_frame_decode_body(log + off + IMDB_FRAME_HDR, fl - IMDB_FRAME_HDR, &c, E));
        if (c.seq == 2) {
            c.alg = IMDB_DIGEST_ALG_LTHASH16_TREE;
            imdb_buf h, pl, f;
            imdb_buf_init(&h);
            imdb_buf_init(&pl);
            imdb_buf_init(&f);
            imdb_commit_encode_header(&c, &h);
            imdb_commit_encode_payload(&c, &pl);
            uint8_t hash[32], msg[IMDB_SIGMSG_LEN], sig[IMDB_SIG_LEN];
            imdb_commit_hash(h.p, h.len, hash);
            imdb_commit_sigmsg(c.seq, (uint32_t)h.len, hash, msg);
            imdb_sign(&sg, msg, sizeof msg, sig);
            imdb_frame_build(h.p, h.len, c.seq, hash, sig, pl.p, pl.len, &f);
            CHECK(!h.err && !pl.err && !f.err && f.len == fl);
            if (f.len == fl) memcpy(log + off, f.p, fl);
            imdb_buf_free(&h);
            imdb_buf_free(&pl);
            imdb_buf_free(&f);
            done = true;
        }
        imdb_commit_free(&c);
    }
    CHECK(done);
    if (has) imdb_signer_wipe(&sg);
    if (done) seg_put_frames(seg, first, tg, log, n);
    free(log);
    imdb_verify_report vr;
    memset(&vr, 0, sizeof vr);
    imdb_err_clear(E);
    CHECK(imdb_verify(db, &vr, E) != 0 && strstr(g_e.msg, "commit 2: digest algorithm 2, but this database's is 1"));
    imdb_close(db);
    imdb_db *db2 = NULL;
    imdb_open_opts o = {.sync = 1};
    imdb_err_clear(E);
    CHECK(imdb_open(p, &o, &db2, E) != 0 && strstr(g_e.msg, "commit 2: digest algorithm 2, but this database's is 1"));
    if (db2) imdb_close(db2);
}

/* one statement through a session of its own */
static int srun_db(imdb_db *db, const char *sql)
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

/* A fixture of one digest algorithm (tests/fixtures/make_alg<N>.sh) or of one log format
 * (make_tagged.sh: tagged, every segment tagged): it opens with META's algorithm, VERIFY and the
 * auditor pass both directories, a commit is written to it and shipped to its replica, and their
 * digests stay equal; a plain open never rewrites META (meta_head: its first line). Run from the tree
 * root (as make runs the suite); a missing tarball fails, never passes. */
static void fixture_check(const char *tgz, uint8_t alg, const char *meta_head, bool tagged)
{
    const char *dir = test_tmpdir();
    struct stat st;
    if (stat(tgz, &st) != 0) {
        test_fail(__FILE__, __LINE__, "a fixture tarball (tests/fixtures) is missing: run the suite from the tree root");
        return;
    }
    char cmd[1600], p[700], r[700], s[700];
    snprintf(cmd, sizeof cmd, "tar -xzf '%s' -C '%s'", tgz, dir);
    CHECK(system(cmd) == 0);
    snprintf(p, sizeof p, "%s/primary", dir);
    snprintf(r, sizeof r, "%s/replica", dir);
    snprintf(s, sizeof s, "%s/stream", dir);
    imdb_identity id;
    bool rep = true;
    OK(imdb_identity_read(p, &id, &rep, E));
    CHECK(id.digest_alg == alg && !rep && !id.has_root);
    imdb_db *db = open_db(p);
    CHECK(db && db->meta.digest_alg == alg && db->seq == 13);
    if (!db) return;
    imdb_verify_report vr;
    memset(&vr, 0, sizeof vr);
    OK(imdb_verify(db, &vr, E));
    CHECK(srun_db(db, "INSERT INTO ev VALUES (3001, 9, 4, 'after digest_alg 2')") == 0 && db->seq == 14);
    /* a CHECKPOINT ends that segment, and the next commit begins a tagged one (design.md §3): an
     * untagged fixture's segments, then tagged ones, in both directories; a tagged one's all tagged */
    CHECK(srun_db(db, "CHECKPOINT") == 0 && srun_db(db, "INSERT INTO ev VALUES (3002, 9, 5, 'tagged')") == 0 &&
          db->seq == 16);
    size_t hn = 0;
    uint8_t *h0 = slurp(seg_path(p, 0), &hn), *hl = NULL;
    CHECK(h0 && imdb_tseg_is_tagged(h0, hn) == tagged);
    free(h0);
    hl = slurp(seg_path(p, -1), &hn);
    CHECK(hl && imdb_tseg_is_tagged(hl, hn));
    free(hl);
    memset(&vr, 0, sizeof vr);
    OK(imdb_verify(db, &vr, E));
    uint8_t dp[32], dr[32];
    imdb_state_digest(db, NULL, dp);
    imdb_close(db);
    OK(ship_to_file(p, 13, s, E));
    imdb_db *rdb = open_db(r);
    CHECK(rdb);
    if (!rdb) return;
    uint64_t applied = 0;
    OK(apply_file(rdb, s, &applied, E));
    imdb_state_digest(rdb, NULL, dr);
    CHECK(applied == 3 && rdb->seq == 16 && memcmp(dp, dr, 32) == 0);
    char la[800], lb[800], why[300] = "";
    snprintf(la, sizeof la, "%s/log", p);
    snprintf(lb, sizeof lb, "%s/log", r);
    CHECK(logs_identical(la, lb, why, sizeof why));
    memset(&vr, 0, sizeof vr);
    OK(imdb_verify(rdb, &vr, E));
    imdb_close(rdb);
    CHECK(audit_dir(p) != 1 && audit_dir(r) != 1); /* -1: no auditor in this build */
    size_t n = 0;
    snprintf(cmd, sizeof cmd, "%s/META", p);
    uint8_t *m = slurp(cmd, &n);
    CHECK(m && n > strlen(meta_head) && memcmp(m, meta_head, strlen(meta_head)) == 0); /* a plain open never rewrites META */
    free(m);
}

/* The format's fixtures (make_fixtures.sh, 2026-10-29: META 5, manifest version 4, op 16, tagged
 * segments), one a digest algorithm: they pin the format, so a change to it fails here first */
static void t_round3_alg1_fixture(void)
{
    fixture_check("tests/fixtures/alg1-20261029.tar.gz", IMDB_DIGEST_ALG_LTHASH16, "imagedb-meta 5\n", true);
}

static void t_round3_alg2_fixture(void)
{
    fixture_check("tests/fixtures/alg2-20261029.tar.gz", IMDB_DIGEST_ALG_LTHASH16_TREE, "imagedb-meta 5\n", true);
}

/* The fixtures of the formats before the retention's (alg1-20261026: META 2; alg2-20261026 and
 * tagged-20261027: META 4): directories this imagedb refuses by name, and the auditor too, since no
 * reader is kept for them before the format freeze */
static void t_round3_old_fixtures(void)
{
    static const char *const tgz[] = {"tests/fixtures/alg1-20261026.tar.gz", "tests/fixtures/alg2-20261026.tar.gz",
                                      "tests/fixtures/tagged-20261027.tar.gz"};
    const char *dir = test_tmpdir();
    for (size_t i = 0; i < sizeof tgz / sizeof *tgz; i++) {
        struct stat st;
        if (stat(tgz[i], &st) != 0) {
            test_fail(__FILE__, __LINE__, "a fixture tarball (tests/fixtures) is missing: run the suite from the tree root");
            return;
        }
        char d[700], cmd[1600], p[760];
        snprintf(d, sizeof d, "%s/f%zu", dir, i);
        CHECK(mkdir(d, 0700) == 0);
        snprintf(cmd, sizeof cmd, "tar -xzf '%s' -C '%s'", tgz[i], d);
        CHECK(system(cmd) == 0);
        snprintf(p, sizeof p, "%s/primary", d);
        imdb_identity id;
        bool rep;
        imdb_err_clear(E);
        CHECK(imdb_identity_read(p, &id, &rep, E) == IMDB_ERR_UNSUPPORTED && strstr(g_e.msg, "before the retention format"));
        imdb_open_opts o = {.sync = 0};
        imdb_db *db = NULL;
        imdb_err_clear(E);
        CHECK(imdb_open(p, &o, &db, E) == IMDB_ERR_UNSUPPORTED && !db && strstr(g_e.msg, "before the retention format"));
        CHECK(audit_dir(p) != 0); /* refused (1), or no auditor in this build (-1) */
    }
}

/* A promotion rewrites the replica's META as a primary's: version 5, the root line and "digest 1" kept */
static void t_round3_meta_promotion(void)
{
    const char *dir = test_tmpdir();
    char p[700], r[700], s[700], f[760];
    snprintf(p, sizeof p, "%s/p", dir);
    snprintf(r, sizeof r, "%s/r", dir);
    snprintf(s, sizeof s, "%s/stream", dir);
    uint8_t seed[32];
    memset(seed, 0x6b, sizeof seed);
    imdb_signer root;
    imdb_signer_init(&root, seed);
    OK(imdb_init_primary_alg(p, root.pk, IMDB_DIGEST_ALG_LTHASH16, E));
    imdb_signer_wipe(&root);
    OK(imdb_init(r, true, p, E));
    imdb_db *db = open_db(p);
    CHECK(db);
    if (!db) return;
    OK(make_table(db, E));
    CHECK(ins1(db, 1, 42, 100, "a") == 0);
    imdb_close(db);
    imdb_identity id;
    bool rep = false;
    snprintf(f, sizeof f, "%s/META", r);
    OK(imdb_identity_read(r, &id, &rep, E));
    CHECK(id.digest_alg == IMDB_DIGEST_ALG_LTHASH16 && rep && id.has_root);
    OK(ship_to_file(p, 0, s, E));
    imdb_db *rdb = open_db(r);
    CHECK(rdb);
    if (!rdb) return;
    uint64_t applied = 0;
    OK(apply_file(rdb, s, &applied, E));
    imdb_close(rdb);
    imdb_promote_opts o = {.old_writer_stopped = true};
    imdb_promote_result pr;
    OK(imdb_promote(r, seed, &o, &pr, E));
    size_t n = 0;
    uint8_t *m = slurp(f, &n);
    CHECK(m && n > 15 && memcmp(m, "imagedb-meta 5\n", 15) == 0 && mem_contains(m, n, "role primary\n") &&
          mem_contains(m, n, "\nroot ") && mem_contains(m, n, "\ndigest 1\n"));
    free(m);
    OK(imdb_identity_read(r, &id, &rep, E));
    CHECK(id.digest_alg == IMDB_DIGEST_ALG_LTHASH16 && !rep && id.has_root);
}

const test_case round3_tests[] = {
    {"round3_meta_digest_alg", t_round3_meta_digest_alg},
    {"round3_alg1_fixture", t_round3_alg1_fixture},
    {"round3_alg2_fixture", t_round3_alg2_fixture},
    {"round3_old_fixtures", t_round3_old_fixtures},
    {"round3_meta_promotion", t_round3_meta_promotion},
    {"round3_digest_alg_mismatch", t_round3_digest_alg_mismatch},
    {"round3_anchor_unavailable", t_round3_anchor_unavailable},
    {"round3_anchor_epoch_priority", t_round3_anchor_epoch_priority},
    {"round3_anchor_promotion_gap", t_round3_anchor_promotion_gap},
    {"round3_rotation_sync_failure", t_round3_rotation_sync_failure},
    {"round3_allowlist_read_failure", t_round3_allowlist_read_failure},
    {"round3_revoked_replica_cache", t_round3_revoked_replica_cache},
    {"round3_close_sync_failure", t_round3_close_sync_failure},
    {"round3_incident_io_failure", t_round3_incident_io_failure},
    {"round3_pending_key_preserved", t_round3_pending_key_preserved},
    {"round3_damaged_tail_lagging", t_round3_damaged_tail_lagging},
    {"round3_damaged_tail_strict", t_round3_damaged_tail_strict},
};
const size_t round3_ntests = sizeof round3_tests / sizeof *round3_tests;
