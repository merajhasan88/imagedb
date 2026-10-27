/* Public-boundary regressions from the 2026-10-26 review. */
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

#include "../../src/sql.h"
#include "../../src/repl.h"
#include "../../src/writer.h"
#include "thelp.h"

static void t_review26_result_text_cap(void)
{
    const char *dir = test_tmpdir();
    OK(imdb_init(dir, false, NULL, E));
    imdb_db *db = open_db(dir);
    CHECK(db);
    OK(make_table(db, E));
    char memo[16385];
    memset(memo, 'x', sizeof memo - 1);
    memo[sizeof memo - 1] = 0;
    OK(ins1(db, 1, 42, 10, memo));
    imdb_close(db);
    imdb_open_opts o = {.sync = 1, .mem_limit = 32768}; /* result cap: 8192 */
    OK(imdb_open(dir, &o, &db, E));
    imdb_session s;
    imdb_session_init(&s, db);
    const char *queries[] = {"SELECT memo FROM txns LIMIT 1", "SELECT MIN(memo) FROM txns",
                            "SELECT MAX(memo) FROM txns"};
    bool bounded = true;
    for (int disk = 0; disk < 2; disk++) {
        if (disk) OK(imdb_checkpoint(db, E));
        for (size_t i = 0; i < sizeof queries / sizeof *queries; i++) {
            imdb_result r;
            int rc = imdb_exec_one(&s, queries[i], strlen(queries[i]), NULL, 0, &r, E);
            if (!rc) fprintf(stderr, "    text result: cap=%llu allocated=%llu\n",
                             (unsigned long long)r.byte_cap,
                             (unsigned long long)(r.caprows * r.ncols * sizeof *r.cells + r.text.cap));
            bounded &= rc == IMDB_ERR_LIMIT && strstr(g_e.msg, "result over its cap");
            imdb_result_free(&r);
        }
    }
    /* The same handle must still answer a result that fits. */
    imdb_result r;
    const char *q = "SELECT id FROM txns LIMIT 1";
    OK(imdb_exec_one(&s, q, strlen(q), NULL, 0, &r, E));
    bool intact = r.nrows == 1 && r.cells[0].v.i == 1;
    imdb_result_free(&r);
    imdb_session_close(&s);
    imdb_close(db);
    CHECK(bounded && intact);
}

typedef struct ledger_probe {
    char p[600], r[600], q[600], ledger[600], parent[600];
    uint8_t seed[32];
    int fd, nested_rc;
    bool fired, nested_committed;
} ledger_probe;

static int ledger_setup(ledger_probe *p)
{
    const char *base = test_tmpdir();
    memset(p, 0, sizeof *p);
    p->fd = -1;
    snprintf(p->p, sizeof p->p, "%s/p", base);
    snprintf(p->r, sizeof p->r, "%s/r", base);
    snprintf(p->q, sizeof p->q, "%s/q", base);
    snprintf(p->parent, sizeof p->parent, "%s", base);
    snprintf(p->ledger, sizeof p->ledger, "%s/root.ledger", base);
    memset(p->seed, 0x26, sizeof p->seed);
    imdb_signer root;
    imdb_signer_init(&root, p->seed);
    int rc = imdb_init_primary(p->p, root.pk, E);
    imdb_signer_wipe(&root);
    if (!rc) rc = imdb_init(p->r, true, p->p, E);
    if (!rc) rc = imdb_init(p->q, true, p->p, E);
    return rc;
}

/* Pause A after EOF completes its ledger read. B then attempts a real promotion of a
 * different replica against the same ledger. Nonblocking ledger locking must refuse B. */
static void interleave_ledger(const imdb_io_call *c, long result, void *ctx)
{
    ledger_probe *p = ctx;
    if (c->op == IMDB_IO_OPEN && c->name &&
        (!strcmp(c->name, p->ledger) || !strcmp(c->name, "root.ledger")) && result >= 0) p->fd = (int)result;
    if (p->fired || c->op != IMDB_IO_READ || c->fd != p->fd || result != 0) return;
    p->fired = true;
    imdb_io_set_hooks(NULL);
    imdb_promote_opts o = {.old_writer_stopped = true, .ledger = p->ledger};
    imdb_promote_result r;
    imdb_err e = {0};
    p->nested_rc = imdb_promote(p->q, p->seed, &o, &r, &e);
    p->nested_committed = r.committed;
}

static void t_review26_ledger_serialization(void)
{
    ledger_probe p;
    OK(ledger_setup(&p));
    static const uint8_t header[] = "imagedb-root-ledger 1\n";
    spit(p.ledger, header, sizeof header - 1);
    imdb_io_hooks h = {.after = interleave_ledger, .ctx = &p};
    imdb_io_set_hooks(&h);
    imdb_promote_opts o = {.old_writer_stopped = true, .ledger = p.ledger};
    imdb_promote_result r;
    int rc = imdb_promote(p.r, p.seed, &o, &r, E);
    imdb_io_set_hooks(NULL);
    fprintf(stderr, "    competing promotions: first=%d/%d second=%d/%d\n", rc, r.committed,
            p.nested_rc, p.nested_committed);
    CHECK(!rc && r.committed && p.fired && p.nested_rc == IMDB_ERR_STATE && !p.nested_committed);
    /* Once A has released the lock, its reservation still refuses B. */
    CHECK(imdb_promote(p.q, p.seed, &o, &r, E) == IMDB_ERR_STATE && !r.committed);
}

static void track_parent(const imdb_io_call *c, long result, void *ctx)
{
    ledger_probe *p = ctx;
    if (c->op == IMDB_IO_OPEN && c->name && !strcmp(c->name, p->parent) && result >= 0) p->fd = (int)result;
}

static long fail_parent_sync(imdb_io_call *c, void *ctx)
{
    ledger_probe *p = ctx;
    if (c->op == IMDB_IO_FSYNC && c->fd == p->fd) {
        p->fired = true;
        errno = EIO;
        return -1;
    }
    return 0;
}

static void t_review26_ledger_directory_sync(void)
{
    ledger_probe p;
    OK(ledger_setup(&p));
    imdb_io_hooks h = {.before = fail_parent_sync, .after = track_parent, .ctx = &p};
    imdb_io_set_hooks(&h);
    imdb_promote_opts o = {.old_writer_stopped = true, .ledger = p.ledger};
    imdb_promote_result r;
    int rc = imdb_promote(p.r, p.seed, &o, &r, E);
    imdb_io_set_hooks(NULL);
    fprintf(stderr, "    ledger parent sync: observed=%d rc=%d committed=%d\n", p.fired, rc, r.committed);
    CHECK(p.fired && rc == IMDB_ERR_IO && !r.committed);
    /* A failed reservation may be readable: an automatic retry must refuse it,
     * since the ledger cannot distinguish a copy that completed promotion. */
    rc = imdb_promote(p.r, p.seed, &o, &r, E);
    CHECK(rc == IMDB_ERR_STATE && !r.committed);
    /* This fixture proved no certificate was signed. Simulate operator recovery. */
    static const uint8_t header[] = "imagedb-root-ledger 1\n";
    spit(p.ledger, header, sizeof header - 1);
    OK(imdb_promote(p.r, p.seed, &o, &r, E));
    CHECK(r.committed);
}

static void t_review26_ledger_cloned_replica(void)
{
    ledger_probe p;
    OK(ledger_setup(&p));
    /* Replace q with the same replica identity, exactly as a restored copy has. */
    char from[700], to[700];
    snprintf(from, sizeof from, "%s/replica.key", p.r);
    snprintf(to, sizeof to, "%s/replica.key", p.q);
    size_t n = 0;
    uint8_t *key = slurp(from, &n);
    CHECK(key && n == IMDB_SEED_LEN);
    spit(to, key, n);
    imdb_wipe(key, n);
    free(key);
    CHECK(chmod(to, 0600) == 0);
    imdb_promote_opts o = {.old_writer_stopped = true, .ledger = p.ledger};
    imdb_promote_result r;
    OK(imdb_promote(p.r, p.seed, &o, &r, E));
    CHECK(r.committed);
    int rc = imdb_promote(p.q, p.seed, &o, &r, E);
    fprintf(stderr, "    cloned replica retry: rc=%d committed=%d\n", rc, r.committed);
    CHECK(rc == IMDB_ERR_STATE && !r.committed);
}

typedef struct ack_probe {
    imdb_db *db;
    imdb_signer key;
    int fd, nested_rc;
    bool fired;
} ack_probe;

static int ack_hash(void *ctx, uint64_t seq, uint8_t h[32])
{
    imdb_db *db = ctx;
    if (!seq) { imdb_genesis_hash(db->db_id, h); return 1; }
    imdb_err e = {0};
    const imdb_commit_info *ci = imdb_ci_at(db, seq, &e);
    if (!ci) return -1;
    memcpy(h, ci->hash, 32);
    return 1;
}

static int ack_receive_at(ack_probe *p, uint64_t seq)
{
    imdb_ack a = {.seq = seq, .cleanup = seq};
    memcpy(a.db_id, p->db->db_id, 16);
    memcpy(a.replica, p->key.pk, 32);
    a.nonce[0] = (uint8_t)seq + 1; /* distinct live shipping sessions */
    if (ack_hash(p->db, seq, a.head) != 1) return IMDB_ERR_STATE;
    uint8_t raw[IMDB_ACK_LEN];
    imdb_ack_sign(&a, &p->key, raw);
    imdb_allow *allow = NULL;
    size_t n = 0;
    imdb_err e = {0};
    int rc = imdb_ack_receive(p->db->dirfd, p->db->db_id, a.nonce, &allow, &n, raw, ack_hash, p->db, NULL, &e);
    free(allow);
    return rc;
}

/* Do not block the nested caller: an exclusive lock that would block it is
 * cancelled with EWOULDBLOCK and retried after the outer receipt returns. */
static long no_wait_lock(imdb_io_call *c, void *ctx)
{
    (void)ctx;
    return c->op == IMDB_IO_LOCK && flock(c->fd, c->flags | LOCK_NB) != 0 ? -1 : 0;
}

static void interleave_ack(const imdb_io_call *c, long result, void *ctx)
{
    ack_probe *p = ctx;
    if (c->op == IMDB_IO_OPEN && c->name && !strcmp(c->name, "r.ack") && result >= 0) p->fd = (int)result;
    if (p->fired || c->op != IMDB_IO_READ || c->fd != p->fd || result <= 0) return;
    p->fired = true;
    imdb_io_hooks h = {.before = no_wait_lock};
    imdb_io_set_hooks(&h);
    p->nested_rc = ack_receive_at(p, 2);
    imdb_io_set_hooks(NULL);
}

static void t_review26_ack_serialization(void)
{
    const char *dir = test_tmpdir();
    OK(imdb_init(dir, false, NULL, E));
    ack_probe p = {.fd = -1};
    p.db = open_db(dir);
    CHECK(p.db);
    OK(make_table(p.db, E));
    OK(ins1(p.db, 1, 42, 10, "ack"));
    uint8_t seed[32] = {0x26};
    imdb_signer_init(&p.key, seed);
    OK(imdb_replica_add(dir, "r", p.key.pk, false, E));
    OK(ack_receive_at(&p, 0));
    imdb_io_hooks h = {.after = interleave_ack, .ctx = &p};
    imdb_io_set_hooks(&h);
    int rc = ack_receive_at(&p, 1);
    imdb_io_set_hooks(NULL);
    CHECK(!rc && p.fired);
    if (p.nested_rc == IMDB_ERR_IO) OK(ack_receive_at(&p, 2));
    imdb_replica_status *v = NULL;
    size_t n = 0;
    OK(imdb_replicas_status(p.db, &v, &n, E));
    bool monotonic = n == 1 && v[0].acked && v[0].ack.seq == 2 && !v[0].incident;
    fprintf(stderr, "    interleaved receipts: nested=%d stored=%llu\n", p.nested_rc,
            (unsigned long long)(n && v[0].acked ? v[0].ack.seq : 0));
    free(v);
    imdb_signer_wipe(&p.key);
    imdb_close(p.db);
    CHECK(monotonic);
}

/* ---- siblings found while integrating the review (2026-10-27) ---- */

/* recover --save: the saved tail is the only copy of those bytes once the log is cut, so its name is
 * synced before the cut. A failed sync of its directory fails recover, and the log keeps the frame. */
static void t_review26_recover_save_directory_sync(void)
{
    const char *base = test_tmpdir();
    char dir[600], sdir[600], save[700], seg[700];
    snprintf(dir, sizeof dir, "%s/db", base);
    snprintf(sdir, sizeof sdir, "%s/saved", base);
    snprintf(save, sizeof save, "%s/tail", sdir);
    CHECK(mkdir(sdir, 0700) == 0);
    OK(imdb_init(dir, false, NULL, E));
    imdb_db *db = open_db(dir);
    CHECK(db);
    OK(make_table(db, E));
    OK(ins1(db, 1, 42, 10, "kept"));
    snprintf(seg, sizeof seg, "%s/log/%020llu.ilg", dir, (unsigned long long)db->segs[db->nsegs - 1]);
    imdb_close(db);
    uint8_t f[IMDB_FRAME_HDR + 64];
    memset(f, 0x55, sizeof f);
    imdb_le32(f, IMDB_FRAME_MAGIC);
    imdb_le32(f + 4, 64);
    imdb_le32(f + 8, 0xdeadbeefu); /* a complete frame whose body fails its checksum */
    imdb_le32(f + 12, imdb_kern()->crc32c(0, f, 12));
    long kept = seg_frames_len(seg);
    seg_append(seg, f, sizeof f); /* where an unfinished append would have left it, either format */
    size_t raw = 0, raw2 = 0;
    uint8_t *before = slurp(seg, &raw);
    ledger_probe p;
    memset(&p, 0, sizeof p);
    p.fd = -1;
    snprintf(p.parent, sizeof p.parent, "%s", sdir);
    imdb_io_hooks h = {.before = fail_parent_sync, .after = track_parent, .ctx = &p};
    imdb_recover_report r;
    imdb_io_set_hooks(&h);
    int rc = imdb_recover_tail(dir, true, save, &r, E);
    imdb_io_set_hooks(NULL);
    fprintf(stderr, "    recover --save, its directory's sync failed: observed=%d rc=%d\n", p.fired, rc);
    uint8_t *after = slurp(seg, &raw2);
    bool same = before && after && raw == raw2 && memcmp(before, after, raw) == 0;
    free(before);
    free(after);
    CHECK(p.fired && rc == IMDB_ERR_IO && same); /* the log as it was */
    /* then a recover that completes, under the same name (the failed one removed its file), cuts the
     * frame, its bytes saved */
    OK(imdb_recover_tail(dir, true, save, &r, E));
    CHECK(r.applied && seg_frames_len(seg) == kept);
    size_t n = 0;
    uint8_t *saved = slurp(save, &n);
    CHECK(saved && mem_contains_n(saved, n, f, sizeof f)); /* tagged: the raw sectors it was in */
    free(saved);
    db = open_db(dir);
    CHECK(db);
    if (db) imdb_close(db);
}

/* A root key kept in a directory reached through a symlink (the operator's choice) keeps working:
 * the ledger's directory opens without O_NOFOLLOW. The ledger file itself is never followed. */
static void t_review26_ledger_symlinked_directory(void)
{
    ledger_probe p;
    OK(ledger_setup(&p));
    char real[700], link[700], led[700], inreal[700], sym[700];
    snprintf(real, sizeof real, "%s/keys", p.parent);
    snprintf(link, sizeof link, "%s/keys-link", p.parent);
    /* the targets relative to the links' directory: IMDB_TEST_TMP may be a relative path */
    CHECK(mkdir(real, 0700) == 0 && symlink("keys", link) == 0);
    snprintf(led, sizeof led, "%s/root.ledger", link);
    snprintf(inreal, sizeof inreal, "%s/root.ledger", real);
    imdb_promote_opts o = {.old_writer_stopped = true, .ledger = led};
    imdb_promote_result r;
    OK(imdb_promote(p.r, p.seed, &o, &r, E));
    CHECK(r.committed && file_size(inreal) > 0);
    snprintf(sym, sizeof sym, "%s/sym.ledger", p.parent);
    CHECK(symlink("keys/root.ledger", sym) == 0 && file_size(sym) == file_size(inreal)); /* a live link */
    o.ledger = sym;
    CHECK(imdb_promote(p.q, p.seed, &o, &r, E) == IMDB_ERR_IO && !r.committed);
}

const test_case review26_tests[] = {
    {"review26_result_text_cap", t_review26_result_text_cap},
    {"review26_ledger_serialization", t_review26_ledger_serialization},
    {"review26_ledger_directory_sync", t_review26_ledger_directory_sync},
    {"review26_ledger_cloned_replica", t_review26_ledger_cloned_replica},
    {"review26_ack_serialization", t_review26_ack_serialization},
    {"review26_recover_save_directory_sync", t_review26_recover_save_directory_sync},
    {"review26_ledger_symlinked_directory", t_review26_ledger_symlinked_directory},
};
const size_t review26_ntests = sizeof review26_tests / sizeof *review26_tests;
