/* Writer epochs (writer.h, deferred.md R2b): key rotation, promotion by the root key, every
 * verifier following the keys (replay, snapshot open with WRITERS, a replica's stream, VERIFY, the
 * auditor), the crash rules for signing.key.next, refusal of forged or inconsistent epoch changes,
 * and fencing through the external anchor. */
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

#include "../../src/fsio.h"
#include "../../src/repl.h"
#include "../../src/writer.h"
#include "thelp.h"

static imdb_db *open_with(const char *dir, int sync, const char *anchor)
{
    imdb_open_opts o = {.sync = sync, .anchor = anchor};
    imdb_db *db = NULL;
    imdb_err_clear(E);
    return imdb_open(dir, &o, &db, E) ? NULL : db;
}

/* the independent auditor, when the Makefile names it: 0 accepted, 1 refused, -1 not available */
static int audit_verify(const char *dir)
{
    const char *bin = getenv("IMDB_AUDIT_BIN");
    if (!bin || !*bin) return -1;
    char cmd[1600];
    snprintf(cmd, sizeof cmd, "'%s' verify '%s' >/dev/null 2>&1", bin, dir);
    return system(cmd) == 0 ? 0 : 1;
}

static int verify_ok(imdb_db *db)
{
    imdb_verify_report vr;
    imdb_err_clear(E);
    return imdb_verify(db, &vr, E);
}

static int replicate(const char *p, const char *r, imdb_db **rep)
{
    char st[700];
    snprintf(st, sizeof st, "%s.stream", r);
    uint64_t applied;
    imdb_db *db = *rep ? *rep : open_with(r, 1, NULL);
    if (!db) return -1;
    *rep = db;
    imdb_err_clear(E);
    int rc = ship_to_file(p, db->seq, st, E);
    if (!rc) rc = apply_file(db, st, &applied, E);
    return rc;
}

static void t_writer_rotate(void)
{
    const char *tmp = test_tmpdir();
    char p[600], r[600];
    snprintf(p, sizeof p, "%s/p", tmp);
    snprintf(r, sizeof r, "%s/r", tmp);
    OK(imdb_init(p, false, NULL, E));
    OK(imdb_init(r, true, p, E));
    imdb_db *db = open_with(p, 1, NULL);
    CHECK(db);
    uint8_t k0[IMDB_PUBKEY_LEN];
    memcpy(k0, db->writer_pk, sizeof k0);
    OK(make_table(db, E));
    OK(ins1(db, 1, 42, 100, "a"));
    OK(imdb_rotate_key(db, E));
    CHECK(imdb_current_epoch(db) == 1 && memcmp(db->writer_pk, k0, 32) != 0 && imdb_ct_eq(db->signer.pk, db->writer_pk, 32));
    uint64_t rot1 = db->seq;
    OK(ins1(db, 2, 7, 100, "b"));
    OK(imdb_checkpoint(db, E)); /* a snapshot under epoch 1: its open needs WRITERS */
    OK(imdb_rotate_key(db, E));
    OK(ins1(db, 3, 7, 100, "c"));
    uint64_t last = db->seq;
    uint8_t kcur[IMDB_PUBKEY_LEN];
    memcpy(kcur, db->writer_pk, sizeof kcur);
    CHECK(imdb_writer_epoch_at(db, rot1) == 0 && imdb_writer_epoch_at(db, rot1 + 1) == 1);
    OK(verify_ok(db));
    imdb_close(db);
    /* the snapshot open: keys from WRITERS, then the tail (with the second rotation) */
    db = open_with(p, 1, NULL);
    CHECK(db && db->snapshot_seq && !strstr(db->warning, "not used"));
    CHECK(db->seq == last && imdb_current_epoch(db) == 2 && memcmp(db->writer_pk, kcur, 32) == 0 && db->can_sign);
    OK(ins1(db, 4, 7, 100, "d")); /* signs with the epoch-2 key */
    OK(verify_ok(db));
    last = db->seq;
    imdb_close(db);
    /* a full replay derives the same */
    imdb_open_opts fo = {.sync = 1, .full_replay = true};
    OK(imdb_open(p, &fo, &db, E));
    CHECK(db->seq == last && imdb_current_epoch(db) == 2);
    imdb_close(db);
    /* a replica follows through both rotations (the stream reader switches keys) */
    imdb_db *rep = NULL;
    OK(replicate(p, r, &rep));
    CHECK(rep->seq == last && imdb_current_epoch(rep) == 2);
    OK(verify_ok(rep));
    imdb_close(rep);
    char a[700], b[700];
    snprintf(a, sizeof a, "%s/WRITERS", p);
    snprintf(b, sizeof b, "%s/WRITERS", r);
    size_t na, nb;
    uint8_t *wa = slurp(a, &na), *wb = slurp(b, &nb);
    CHECK(wa && wb && na == nb && memcmp(wa, wb, na) == 0); /* derived, and the same on every copy */
    imdb_db *pd = calloc(1, sizeof *pd); /* the parse alone (what fuzz_frame drives): all three epochs proven */
    OK(imdb_identity_read(p, &pd->meta, NULL, E));
    memcpy(pd->db_id, pd->meta.db_id, 16);
    OK(imdb_writers_parse(pd, wa, na, E));
    CHECK(pd->nwep == 3 && imdb_current_epoch(pd) == 2 && memcmp(pd->writer_pk, kcur, 32) == 0);
    wa[na - 5] ^= 1; /* any byte: the CRC refuses it, and the schedule falls back to epoch 0 */
    CHECK(imdb_writers_parse(pd, wa, na, E) != IMDB_OK && pd->nwep == 1);
    imdb_writers_free(pd);
    free(pd);
    free(wa);
    free(wb);
    CHECK(audit_verify(p) <= 0 && audit_verify(r) <= 0);
    /* without WRITERS the snapshot cannot be authenticated: the whole log is replayed, and the
     * writable open writes it again */
    unlink(a);
    db = open_with(p, 1, NULL);
    CHECK(db && strstr(db->warning, "not used") && db->seq == last && imdb_current_epoch(db) == 2);
    imdb_close(db);
    CHECK(file_size(a) > 0);
}

/* signing.key.next: a rotation that never reached the log is dropped at open; one that did is
 * completed (the logged op finishing), so the directory always signs with the log's current key */
static long fail_next_rename(imdb_io_call *c, void *ctx)
{
    (void)ctx;
    if (c->op == IMDB_IO_RENAME && c->name && strcmp(c->name, IMDB_SIGNING_NEXT_NAME) == 0) {
        errno = EIO;
        return -1;
    }
    return 0;
}

static void t_writer_settle(void)
{
    const char *p = test_tmpdir();
    OK(imdb_init(p, false, NULL, E));
    imdb_db *db = open_with(p, 1, NULL);
    CHECK(db);
    OK(make_table(db, E));
    imdb_close(db);
    /* a leftover next key (a crash before the rotation commit): removed, the old key stays */
    char nx[700];
    snprintf(nx, sizeof nx, "%s/%s", p, IMDB_SIGNING_NEXT_NAME);
    uint8_t seed[32];
    memset(seed, 9, sizeof seed);
    spit(nx, seed, sizeof seed);
    chmod(nx, 0600);
    db = open_with(p, 1, NULL);
    CHECK(db && file_size(nx) < 0 && imdb_current_epoch(db) == 0);
    OK(ins1(db, 1, 7, 100, "x"));
    /* the rotation commit made it, the rename did not: completed at the next open */
    imdb_io_hooks h = {.before = fail_next_rename};
    imdb_io_set_hooks(&h);
    int rc = imdb_rotate_key(db, E);
    imdb_io_set_hooks(NULL);
    OK_RC(rc);
    CHECK(strstr(db->warning, "not replaced yet") && file_size(nx) == 32);
    OK(ins1(db, 2, 7, 100, "y")); /* the handle signs with the new key already */
    uint8_t k1[32];
    memcpy(k1, db->writer_pk, 32);
    imdb_close(db);
    db = open_with(p, 1, NULL);
    CHECK(db && file_size(nx) < 0 && imdb_current_epoch(db) == 1 && imdb_ct_eq(db->signer.pk, k1, 32));
    OK(ins1(db, 3, 7, 100, "z"));
    OK(verify_ok(db));
    imdb_close(db);
    /* a rotation on a replica, or while a transaction is open: refused */
    char r[700];
    snprintf(r, sizeof r, "%s-r", p);
    OK(imdb_init(r, true, p, E));
    db = open_with(r, 1, NULL);
    CHECK(db && imdb_rotate_key(db, E) == IMDB_ERR_STATE);
    imdb_close(db);
}

/* The review: a damaged signing.key.next after the epoch change that logged it may be the only copy
 * of the current key, so the open keeps it and refuses (torn, or a flipped bit: any 32 bytes are a
 * seed); restored, the change completes. A pending key no epoch change used still goes. */
static void t_writer_pending_damaged(void)
{
    const char *tmp = test_tmpdir();
    char p[600], r[600], nx[700], rnx[700];
    snprintf(p, sizeof p, "%s/p", tmp);
    snprintf(r, sizeof r, "%s/r", tmp);
    snprintf(nx, sizeof nx, "%s/%s", p, IMDB_SIGNING_NEXT_NAME);
    snprintf(rnx, sizeof rnx, "%s/%s", r, IMDB_SIGNING_NEXT_NAME);
    uint8_t rseed[32], junk[32];
    memset(rseed, 0x57, sizeof rseed);
    memset(junk, 3, sizeof junk);
    imdb_signer root;
    imdb_signer_init(&root, rseed);
    OK(imdb_init_primary(p, root.pk, E));
    imdb_signer_wipe(&root);
    OK(imdb_init(r, true, p, E));
    imdb_db *db = open_with(p, 1, NULL);
    CHECK(db);
    OK(make_table(db, E));
    imdb_close(db);
    spit(nx, junk, 10); /* torn before any rotation: unused, it goes */
    chmod(nx, 0600);
    db = open_with(p, 1, NULL);
    CHECK(db && file_size(nx) < 0);
    imdb_io_hooks h = {.before = fail_next_rename};
    imdb_io_set_hooks(&h); /* the rotation reaches the log, the rename does not */
    int rc = imdb_rotate_key(db, E);
    imdb_io_set_hooks(NULL);
    OK_RC(rc);
    imdb_close(db);
    size_t kn;
    uint8_t *kb = slurp(nx, &kn);
    CHECK(kb && kn == 32);
    if (!kb) return;
    for (int how = 0; how < 2; how++) {
        uint8_t bad[32];
        memcpy(bad, kb, 32);
        bad[5] ^= 0x10;
        spit(nx, how ? bad : kb, how ? 32 : 10);
        chmod(nx, 0600);
        CHECK(!open_with(p, 1, NULL) && g_e.code == IMDB_ERR_CORRUPT && strstr(g_e.msg, "kept as it is"));
        CHECK(file_size(nx) == (how ? 32 : 10));
    }
    spit(nx, kb, kn); /* restored from a copy */
    chmod(nx, 0600);
    free(kb);
    db = open_with(p, 1, NULL);
    CHECK(db && file_size(nx) < 0 && imdb_current_epoch(db) == 1);
    OK(ins1(db, 1, 7, 100, "after the rotation"));
    imdb_close(db);
    /* a replica: a leftover key goes, unless the log ends with a promotion */
    imdb_db *rr = NULL;
    OK(replicate(p, r, &rr));
    imdb_close(rr);
    spit(rnx, junk, 32);
    chmod(rnx, 0600);
    rr = open_with(r, 1, NULL);
    CHECK(rr && file_size(rnx) < 0);
    imdb_close(rr);
    imdb_promote_opts po = {.old_writer_stopped = true};
    imdb_promote_result pr;
    imdb_io_set_hooks(&h); /* promoted, its key not renamed */
    (void)imdb_promote(r, rseed, &po, &pr, E);
    imdb_io_set_hooks(NULL);
    CHECK(pr.committed && pr.recovery_required);
    kb = slurp(rnx, &kn);
    CHECK(kb && kn == 32);
    if (!kb) return;
    spit(rnx, kb, 10);
    chmod(rnx, 0600);
    CHECK(!open_with(r, 1, NULL) && g_e.code == IMDB_ERR_CORRUPT && file_size(rnx) == 10);
    spit(rnx, kb, kn);
    chmod(rnx, 0600);
    free(kb);
    rr = open_with(r, 1, NULL);
    CHECK(rr && !rr->replica && rr->can_sign && file_size(rnx) < 0);
    if (rr) OK(ins1(rr, 2, 7, 100, "the promoted writer"));
    imdb_close(rr);
}

/* the frame of a commit on top of db's state: header encoded, signed by key (ext: a promotion) */
static void frame_on(imdb_db *db, imdb_op *op, uint32_t nops, const imdb_signer *key, const uint8_t *ext,
                     imdb_buf *f)
{
    imdb_commit_rec c;
    memset(&c, 0, sizeof c);
    c.seq = db->seq + 1;
    c.alg = db->meta.digest_alg;
    c.time_us = db->last_time + 1000;
    memcpy(c.prev, db->head, 32);
    c.ops = op;
    c.nops = nops;
    imdb_state_digest(db, NULL, c.digest);
    imdb_buf h;
    imdb_buf_init(&h);
    imdb_commit_encode_header(&c, &h);
    imdb_commit_hash(h.p, h.len, c.hash);
    uint8_t m[IMDB_SIGMSG_LEN];
    imdb_commit_sigmsg(c.seq, (uint32_t)h.len, c.hash, m);
    imdb_sign(key, m, sizeof m, c.sig);
    imdb_frame_build_ext(h.p, h.len, c.seq, c.hash, c.sig, ext, NULL, 0, f);
    imdb_buf_free(&h);
}

/* ... appended to db's log by hand */
static void forge(const char *dir, imdb_db *db, imdb_op *op, uint32_t nops, const imdb_signer *key,
                  const uint8_t *ext, const uint8_t *prev)
{
    (void)prev;
    imdb_buf f;
    imdb_buf_init(&f);
    frame_on(db, op, nops, key, ext, &f);
    seg_append(seg_path(dir, -1), f.p, f.len); /* where the writer would have put it */
    imdb_buf_free(&f);
}

static void t_writer_forged(void)
{
    const char *tmp = test_tmpdir();
    char p[600], cp[700];
    snprintf(p, sizeof p, "%s/p", tmp);
    OK(imdb_init(p, false, NULL, E));
    imdb_db *db = open_with(p, 1, NULL);
    CHECK(db);
    OK(make_table(db, E));
    OK(ins1(db, 1, 42, 100, "a"));
    imdb_close(db);
    imdb_signer att;
    uint8_t s[32];
    memset(s, 0x77, sizeof s);
    imdb_signer_init(&att, s);
    struct {
        const char *what;
        int expect;
    } cases[] = {{"a rotation signed by someone else", IMDB_ERR_AUTH},
                 {"a rotation beside another op", IMDB_ERR_CORRUPT},
                 {"a rotation that skips an epoch", IMDB_ERR_CORRUPT},
                 {"a promotion in a kind-2 body", IMDB_ERR_CORRUPT},
                 {"a promotion without a root key", IMDB_ERR_AUTH}};
    for (int k = 0; k < 5; k++) {
        snprintf(cp, sizeof cp, "%s/case%d", tmp, k);
        CHECK(copy_tree(p, cp) == 0);
        db = open_with(cp, 1, NULL);
        CHECK(db);
        imdb_signer own = db->signer;
        imdb_op ops[2];
        memset(ops, 0, sizeof ops);
        ops[0].code = IMDB_OP_WRITER_KEY;
        ops[0].epoch = 1;
        memcpy(ops[0].new_pk, att.pk, 32);
        ops[0].how = IMDB_WRITER_ROTATE;
        ops[1].code = IMDB_OP_CHECKPOINT;
        uint8_t ext[IMDB_BODY_EXT];
        memset(ext, 0, sizeof ext);
        if (k == 0) forge(cp, db, ops, 1, &att, NULL, NULL);
        if (k == 1) forge(cp, db, ops, 2, &own, NULL, NULL);
        if (k == 2) {
            ops[0].epoch = 2;
            forge(cp, db, ops, 1, &own, NULL, NULL);
        }
        if (k == 3) {
            ops[0].how = IMDB_WRITER_PROMOTE;
            forge(cp, db, ops, 1, &att, NULL, NULL);
        }
        if (k == 4) { /* the right shape, but this database has no root key to certify it */
            ops[0].how = IMDB_WRITER_PROMOTE;
            imdb_le32(ext, 1);
            memcpy(ext + 4, att.pk, 32);
            forge(cp, db, ops, 1, &att, ext, NULL);
        }
        db->sync = 0; /* closes without touching the forged tail */
        db->failed = true;
        imdb_close(db);
        imdb_db *d2 = open_with(cp, 1, NULL);
        if (d2) imdb_close(d2);
        if (d2 || g_e.code != cases[k].expect) {
            char m[200];
            snprintf(m, sizeof m, "%s: opened=%d code=%d (%s)", cases[k].what, d2 != NULL, g_e.code, g_e.msg);
            test_fail(__FILE__, __LINE__, m);
            return;
        }
        CHECK(audit_verify(cp) != 0);
    }
    imdb_signer_wipe(&att);
}

static void t_writer_promote(void)
{
    const char *tmp = test_tmpdir();
    char p[600], r[600], q[600], nr[600], np[600], st[700];
    snprintf(p, sizeof p, "%s/p", tmp);
    snprintf(r, sizeof r, "%s/r", tmp);
    snprintf(q, sizeof q, "%s/q", tmp);
    snprintf(nr, sizeof nr, "%s/noroot", tmp);
    snprintf(np, sizeof np, "%s/noroot-r", tmp);
    uint8_t rseed[32], wseed[32];
    memset(rseed, 0x31, sizeof rseed);
    memset(wseed, 0x32, sizeof wseed);
    imdb_signer root, wrong;
    imdb_signer_init(&root, rseed);
    imdb_signer_init(&wrong, wseed);
    OK(imdb_init_primary(p, root.pk, E));
    OK(imdb_init(r, true, p, E));
    OK(imdb_init(q, true, p, E));
    imdb_db *db = open_with(p, 1, NULL);
    CHECK(db);
    OK(make_table(db, E));
    OK(ins1(db, 1, 42, 100, "a"));
    imdb_close(db);
    imdb_db *rr = NULL, *qq = NULL;
    OK(replicate(p, r, &rr));
    OK(replicate(p, q, &qq));
    imdb_close(rr);
    uint64_t cut = qq->seq;
    /* no proof that the old writer is stopped, the wrong root key, a primary, a database without a
     * root: refused, and nothing committed */
    imdb_promote_opts noproof = {0}, po = {.old_writer_stopped = true};
    imdb_promote_result pr;
    CHECK(imdb_promote(r, rseed, &noproof, &pr, E) == IMDB_ERR_STATE && !pr.committed);
    CHECK(imdb_promote(r, wseed, &po, &pr, E) == IMDB_ERR_AUTH && !pr.committed);
    CHECK(imdb_promote(p, rseed, &po, &pr, E) == IMDB_ERR_STATE && !pr.committed);
    OK(imdb_init(nr, false, NULL, E));
    OK(imdb_init(np, true, nr, E));
    CHECK(imdb_promote(np, rseed, &po, &pr, E) == IMDB_ERR_STATE && !pr.committed);
    /* the promotion: r is the writer of epoch 1 on top of its commit */
    OK(imdb_promote(r, rseed, &po, &pr, E));
    CHECK(pr.committed && pr.epoch == 1 && pr.seq == cut + 1 && !pr.recovery_required && !pr.abandoned_to);
    bool replica = true;
    OK(imdb_read_role(r, &replica, E));
    CHECK(!replica);
    rr = open_with(r, 1, NULL);
    CHECK(rr && rr->can_sign && imdb_current_epoch(rr) == 1 && rr->seq == cut + 1);
    OK(ins1(rr, 2, 7, 100, "b"));
    OK(verify_ok(rr));
    imdb_close(rr);
    CHECK(audit_verify(r) <= 0);
    /* a follower goes through the promotion frame (root certificate, then the new key) */
    snprintf(st, sizeof st, "%s/stream", tmp);
    uint64_t applied;
    OK(ship_to_file(r, qq->seq, st, E));
    OK(apply_file(qq, st, &applied, E));
    CHECK(applied == 2 && imdb_current_epoch(qq) == 1);
    OK(verify_ok(qq));
    /* the old writer's key is fenced out: a commit it signed, even one that chains exactly onto the
     * follower's head, is refused, because epoch 1 holds */
    db = open_with(p, 1, NULL);
    CHECK(db);
    imdb_signer oldkey = db->signer;
    imdb_close(db);
    imdb_op none[1];
    memset(none, 0, sizeof none);
    none[0].code = IMDB_OP_CHECKPOINT; /* any op will do: it never gets past the signature */
    imdb_buf f;
    imdb_buf_init(&f);
    frame_on(qq, none, 1, &oldkey, NULL, &f);
    spit(st, f.p, f.len);
    imdb_buf_free(&f);
    imdb_signer_wipe(&oldkey);
    CHECK(apply_file(qq, st, &applied, E) == IMDB_ERR_AUTH && applied == 0 && strstr(g_e.msg, "not signed"));
    imdb_close(qq);
    CHECK(audit_verify(q) <= 0);
    imdb_signer_wipe(&root);
    imdb_signer_wipe(&wrong);
}

/* a promotion certified for another history (another cut point) is refused */
static void t_writer_promote_elsewhere(void)
{
    const char *tmp = test_tmpdir();
    char p[600], r[600];
    snprintf(p, sizeof p, "%s/p", tmp);
    snprintf(r, sizeof r, "%s/r", tmp);
    uint8_t rseed[32];
    memset(rseed, 0x41, sizeof rseed);
    imdb_signer root;
    imdb_signer_init(&root, rseed);
    OK(imdb_init_primary(p, root.pk, E));
    imdb_db *db = open_with(p, 1, NULL);
    CHECK(db);
    OK(make_table(db, E));
    OK(ins1(db, 1, 42, 100, "a"));
    uint8_t other_prev[32];
    memset(other_prev, 0x5c, sizeof other_prev);
    imdb_signer nk;
    uint8_t s[32];
    memset(s, 0x42, sizeof s);
    imdb_signer_init(&nk, s);
    imdb_op op;
    memset(&op, 0, sizeof op);
    op.code = IMDB_OP_WRITER_KEY;
    op.epoch = 1;
    memcpy(op.new_pk, nk.pk, 32);
    op.how = IMDB_WRITER_PROMOTE;
    uint8_t ext[IMDB_BODY_EXT], pm[IMDB_PROMOTE_MSG_LEN];
    imdb_le32(ext, 1);
    memcpy(ext + 4, nk.pk, 32);
    imdb_promote_msg(db->db_id, 1, db->seq + 1, other_prev, nk.pk, pm); /* certifies a cut on another history */
    imdb_sign(&root, pm, sizeof pm, ext + 36);
    forge(p, db, &op, 1, &nk, ext, NULL);
    db->failed = true;
    imdb_close(db);
    CHECK(!open_with(p, 1, NULL) && g_e.code == IMDB_ERR_AUTH);
    CHECK(audit_verify(p) != 0);
    imdb_signer_wipe(&root);
    imdb_signer_wipe(&nk);
}

/* A primary (root key from the seed byte rb) anchored at anc, open for writing, with commits 1-2, and
 * a replica r caught up with it: the starting point of the fencing tests. */
static imdb_db *fence_setup(const char *tmp, char *p, char *r, char *anc, size_t cap, uint8_t rb, uint8_t rseed[32])
{
    snprintf(p, cap, "%s/p", tmp);
    snprintf(r, cap, "%s/r", tmp);
    snprintf(anc, cap, "%s/anchor", tmp);
    memset(rseed, rb, 32);
    imdb_signer root;
    imdb_signer_init(&root, rseed);
    int rc = imdb_init_primary(p, root.pk, E) || imdb_init(r, true, p, E);
    imdb_signer_wipe(&root);
    imdb_db *old = rc ? NULL : open_with(p, 1, anc);
    if (!old || make_table(old, E) || ins1(old, 1, 42, 100, "a")) return NULL;
    imdb_db *rr = NULL;
    if (replicate(p, r, &rr)) return NULL;
    imdb_close(rr);
    return old;
}

/* One writer per anchor: a second writable open with it is refused while the first lives (a reader
 * is not), and succeeds once the first has gone. */
static void t_writer_lease(void)
{
    const char *tmp = test_tmpdir();
    char p[600], r[600], anc[600], p2[640];
    uint8_t rseed[32];
    imdb_db *old = fence_setup(tmp, p, r, anc, sizeof p, 0x51, rseed);
    CHECK(old);
    snprintf(p2, sizeof p2, "%s-copy", p);
    CHECK(copy_tree(p, p2) == 0); /* the same database in another directory: its own lock, the shared anchor */
    CHECK(!open_with(p2, 1, anc) && g_e.code == IMDB_ERR_STATE && strstr(g_e.msg, ".lock is held"));
    imdb_open_opts ro = {.read_only = true, .anchor = anc};
    imdb_db *rd;
    OK(imdb_open(p, &ro, &rd, E)); /* checking against the anchor needs no lease */
    imdb_close(rd);
    imdb_close(old);
    imdb_db *w2 = open_with(p2, 1, anc);
    CHECK(w2);
    imdb_close(w2);
}

typedef struct pause_promote {
    const char *r, *anc;
    const uint8_t *seed;
    long at, n; /* promote at the at-th I/O call of the old writer; n counts them */
    bool tried;
    int rc;
    imdb_promote_result pr;
} pause_promote;

static long pause_and_promote(imdb_io_call *c, void *ctx)
{
    pause_promote *pp = ctx;
    (void)c;
    if (++pp->n != pp->at || pp->tried) return 0;
    pp->tried = true;
    imdb_io_set_hooks(NULL); /* the promotion runs as another process would, unhooked */
    imdb_promote_opts o = {.anchor = pp->anc, .abandon = true};
    imdb_err e = {0};
    pp->rc = imdb_promote(pp->r, pp->seed, &o, &pp->pr, &e);
    return 0; /* then the old writer's call goes ahead */
}

/* The review's B1: an old writer paused at any point between its ownership check and its
 * acknowledgement while a promotion runs elsewhere. With the lease the promotion is refused at every
 * one of those points, nothing is committed, the old commit completes; once the old writer stops,
 * the promotion goes through and the old directory no longer opens with the anchor. */
static void t_writer_promote_lease(void)
{
    const char *tmp = test_tmpdir();
    char p[600], r[600], anc[600];
    uint8_t rseed[32];
    imdb_db *old = fence_setup(tmp, p, r, anc, sizeof p, 0x52, rseed);
    CHECK(old);
    OK(ins1(old, 3, 7, 100, "warm")); /* the first commit after the setup makes an extra call; count a later one */
    pause_promote count = {.r = r, .anc = anc, .seed = rseed};
    imdb_io_hooks h = {.before = pause_and_promote, .ctx = &count};
    imdb_io_set_hooks(&h);
    int rc = ins1(old, 2, 7, 100, "counted");
    imdb_io_set_hooks(NULL);
    OK_RC(rc);
    long calls = count.n, tried = 0;
    CHECK(calls > 3);
    for (long k = 1; k <= calls + 2; k++) {
        pause_promote q = {.r = r, .anc = anc, .seed = rseed, .at = k};
        imdb_io_hooks hk = {.before = pause_and_promote, .ctx = &q};
        imdb_io_set_hooks(&hk);
        rc = ins1(old, 10 + k, 7, 100, "old writer");
        imdb_io_set_hooks(NULL);
        if (!q.tried) continue; /* this commit made fewer calls */
        tried++;
        if (q.rc != IMDB_ERR_STATE || q.pr.committed || rc != IMDB_OK) {
            char m[200];
            snprintf(m, sizeof m, "pause point %ld of %ld: promote=%d committed=%d old commit=%d", k, calls, q.rc,
                     q.pr.committed, rc);
            test_fail(__FILE__, __LINE__, m);
            imdb_close(old);
            return;
        }
    }
    CHECK(tried >= calls);
    bool replica = false;
    OK(imdb_read_role(r, &replica, E));
    CHECK(replica); /* never promoted */
    uint64_t last = old->seq;
    imdb_close(old); /* the old writer stops: the lease is free */
    imdb_promote_opts o = {.anchor = anc, .abandon = true};
    imdb_promote_result pr;
    OK(imdb_promote(r, rseed, &o, &pr, E));
    CHECK(pr.committed && pr.anchor_published && pr.abandoned_to == last);
    CHECK(!open_with(p, 1, anc) && strstr(g_e.msg, "newer writer"));
    imdb_db *nw = open_with(r, 1, anc);
    CHECK(nw && imdb_current_epoch(nw) == 1);
    OK(ins1(nw, 99, 7, 100, "the new writer"));
    imdb_close(nw);
}

/* The lease cannot reach another host (its own lock namespace). Model one: a promotion that ignores
 * the anchor's lock (the operator's word, wrongly given) and whose writer then writes its epoch into
 * the shared anchor, as that host would. The old writer's next commit stops it: the per-commit
 * anchor check narrows that window, it does not close it. */
static void t_writer_fence_cross_host(void)
{
    const char *tmp = test_tmpdir();
    char p[600], r[600], anc[600], other[640];
    uint8_t rseed[32];
    imdb_db *old = fence_setup(tmp, p, r, anc, sizeof p, 0x53, rseed);
    CHECK(old);
    imdb_promote_opts o = {.old_writer_stopped = true};
    imdb_promote_result pr;
    OK(imdb_promote(r, rseed, &o, &pr, E));
    snprintf(other, sizeof other, "%s.otherhost", anc);
    imdb_db *nw = open_with(r, 1, other);
    CHECK(nw);
    imdb_close(nw);
    size_t n;
    uint8_t *b = slurp(other, &n);
    CHECK(b && n == IMDB_ANCHOR_FILE);
    spit(anc, b, n); /* what the other host's writer leaves in the shared anchor */
    free(b);
    CHECK(ins1(old, 2, 7, 100, "late") == IMDB_ERR_STATE && strstr(g_e.msg, "fenced") && old->failed);
    imdb_close(old);
    CHECK(!open_with(p, 1, anc) && strstr(g_e.msg, "newer writer"));
}

/* The cut: a promotion that abandons old-writer commits the anchor shows needs to say so; it then
 * publishes the new epoch, and a second promotion from the old epoch (another replica) is refused. */
static void t_writer_abandon(void)
{
    const char *tmp = test_tmpdir();
    char p[600], r[600], anc[600], q[640];
    uint8_t rseed[32];
    imdb_db *old = fence_setup(tmp, p, r, anc, sizeof p, 0x54, rseed);
    CHECK(old);
    snprintf(q, sizeof q, "%s/q", tmp);
    OK(imdb_init(q, true, p, E));
    imdb_db *qq = NULL;
    OK(replicate(p, q, &qq)); /* another replica at the same cut */
    imdb_close(qq);
    OK(ins1(old, 2, 7, 100, "past the cut")); /* commit 3 of epoch 0, named by the anchor */
    uint64_t oldtip = old->seq;
    imdb_close(old);
    imdb_promote_opts o = {.anchor = anc};
    imdb_promote_result pr;
    CHECK(imdb_promote(r, rseed, &o, &pr, E) == IMDB_ERR_STATE && !pr.committed && pr.abandoned_to == oldtip &&
          strstr(g_e.msg, "--abandon"));
    o.abandon = true;
    OK(imdb_promote(r, rseed, &o, &pr, E));
    CHECK(pr.committed && pr.anchor_published && pr.abandoned_to == oldtip && pr.seq == oldtip);
    CHECK(imdb_promote(q, rseed, &o, &pr, E) == IMDB_ERR_STATE && !pr.committed && strstr(g_e.msg, "another promotion"));
    imdb_db *nw = open_with(r, 1, anc);
    CHECK(nw && !strstr(nw->warning, "abandoned"));
    imdb_close(nw);
}

/* Without an anchor, the root key's ledger: each epoch is certified once, for one replica at one
 * cut. Even that replica's retry is refused (a clone could fork); a malformed ledger
 * is refused, never ignored. */
static void t_writer_ledger(void)
{
    int rc;
    const char *tmp = test_tmpdir();
    char p[600], r[600], anc[600], q[640], led[640];
    uint8_t rseed[32];
    imdb_db *old = fence_setup(tmp, p, r, anc, sizeof p, 0x55, rseed);
    CHECK(old);
    imdb_close(old);
    snprintf(q, sizeof q, "%s/q", tmp);
    snprintf(led, sizeof led, "%s/root.key.ledger", tmp);
    OK(imdb_init(q, true, p, E));
    imdb_db *qq = NULL;
    OK(replicate(p, q, &qq));
    imdb_close(qq);
    /* a ledger line for r's promotion, as an attempt that failed after writing it would leave */
    imdb_open_opts ro = {.read_only = true};
    imdb_db *rd;
    OK(imdb_open(r, &ro, &rd, E));
    uint64_t last_seq = rd->seq; /* q is at the same commit */
    imdb_signer rk;
    bool created;
    OK(imdb_replica_key(r, false, &rk, &created, E));
    char id[33], prev[65], who[65], line[400];
    imdb_hex(rd->db_id, 16, id);
    imdb_hex(rd->head, 32, prev);
    imdb_hex(rk.pk, 32, who);
    int ln = snprintf(line, sizeof line, "imagedb-root-ledger 1\npromote %s 1 %llu %s %s\n", id,
                      (unsigned long long)rd->seq + 1, prev, who);
    imdb_signer_wipe(&rk);
    imdb_close(rd);
    spit(led, (const uint8_t *)line, (size_t)ln);
    imdb_promote_opts o = {.old_writer_stopped = true, .ledger = led};
    imdb_promote_result pr;
    CHECK(imdb_promote(r, rseed, &o, &pr, E) == IMDB_ERR_STATE && !pr.committed);
    CHECK(file_size(led) == ln);
    /* No promotion occurred in this fixture: explicit recovery removes the reservation. */
    static const uint8_t header[] = "imagedb-root-ledger 1\n";
    spit(led, header, sizeof header - 1);
    OK(imdb_promote(r, rseed, &o, &pr, E));
    CHECK(pr.committed);
    CHECK(file_size(led) == ln); /* not written twice */
    CHECK(imdb_promote(q, rseed, &o, &pr, E) == IMDB_ERR_STATE && !pr.committed && strstr(g_e.msg, "already certified"));
    char bad[700];
    snprintf(bad, sizeof bad, "%s.bad", led);
    spit(bad, (const uint8_t *)"imagedb-root-ledger 1\npromote x\n", 32);
    o.ledger = bad;
    imdb_err_clear(E);
    rc = imdb_promote(q, rseed, &o, &pr, E);
    CHECK(rc == IMDB_ERR_CORRUPT && !pr.committed && strstr(g_e.msg, "malformed"));
    /* a line left by a promotion that never committed, for a replica since destroyed: it blocks
     * every other one (the ledger cannot know), and the root key's holder removes it */
    char stale[700];
    snprintf(stale, sizeof stale, "%s.stale", led);
    char gone[65];
    memset(gone, 'a', 64);
    gone[64] = 0;
    ln = snprintf(line, sizeof line, "imagedb-root-ledger 1\npromote %s 1 %llu %s %s\n", id,
                  (unsigned long long)last_seq + 1, prev, gone);
    spit(stale, (const uint8_t *)line, (size_t)ln);
    o.ledger = stale;
    imdb_err_clear(E);
    rc = imdb_promote(q, rseed, &o, &pr, E);
    CHECK(rc == IMDB_ERR_STATE && !pr.committed && strstr(g_e.msg, "remove its line from"));
    spit(stale, (const uint8_t *)"imagedb-root-ledger 1\n", 22);
    OK(imdb_promote(q, rseed, &o, &pr, E));
    CHECK(pr.committed);
}

const test_case writer_tests[] = {
    {"writer_rotate", t_writer_rotate},
    {"writer_settle", t_writer_settle},
    {"writer_pending_damaged", t_writer_pending_damaged},
    {"writer_forged", t_writer_forged},
    {"writer_promote", t_writer_promote},
    {"writer_promote_elsewhere", t_writer_promote_elsewhere},
    {"writer_lease", t_writer_lease},
    {"writer_promote_lease", t_writer_promote_lease},
    {"writer_fence_cross_host", t_writer_fence_cross_host},
    {"writer_abandon", t_writer_abandon},
    {"writer_ledger", t_writer_ledger},
};
const size_t writer_ntests = sizeof writer_tests / sizeof *writer_tests;
