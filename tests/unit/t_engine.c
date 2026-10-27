/* Engine tests (C API, no SQL): commit/replay, MVCC, torn tails, replication,
 * tamper detection, erasure completeness, and a randomized model check. */
#include <dirent.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

#include "thelp.h"

/* ---- tests ------------------------------------------------------------------------ */

static void t_commit_replay(void)
{
    const char *dir = test_tmpdir();
    OK(imdb_init(dir, false, NULL, E));
    imdb_db *db = open_db(dir);
    CHECK(db);
    OK(make_table(db, E));
    for (int i = 1; i <= 50; i++) OK(ins1(db, i, i % 5, i * 100, "coffee"));
    uint8_t d1[32], h1[32];
    imdb_state_digest(db, NULL, d1);
    memcpy(h1, db->head, 32);
    uint64_t seq = db->seq;
    CHECK(seq == 51);
    CHECK(count_subject(db, 3, db->seq) == 10);
    imdb_close(db);
    db = open_db(dir);
    CHECK(db);
    uint8_t d2[32];
    imdb_state_digest(db, NULL, d2);
    CHECK(db->seq == seq && memcmp(d1, d2, 32) == 0 && memcmp(h1, db->head, 32) == 0);
    CHECK(count_subject(db, 3, db->seq) == 10);
    imdb_verify_report rep;
    OK(imdb_verify(db, &rep, E));
    CHECK(rep.commits == 51 && rep.live == 50 && rep.sigs_checked == 51);
    imdb_close(db);
}

static void t_mvcc_time_travel(void)
{
    const char *dir = test_tmpdir();
    OK(imdb_init(dir, false, NULL, E));
    imdb_db *db = open_db(dir);
    CHECK(db);
    OK(make_table(db, E));
    OK(ins1(db, 1, 42, 1999, "first"));
    uint64_t s_ins = db->seq;
    imdb_table *t = imdb_table_by_name(db, "txns");
    imdb_value v[4];
    row_vals(v, 1, 42, 2000, "second");
    OK(imdb_begin(db, E));
    OK(imdb_update(db, t, pk_lookup(db, 1, imdb_read_snapshot(db)), v, E));
    OK(imdb_commit(db, E));
    uint64_t s_upd = db->seq;
    OK(imdb_begin(db, E));
    OK(imdb_delete(db, t, pk_lookup(db, 1, imdb_read_snapshot(db)), E));
    OK(imdb_commit(db, E));
    uint64_t s_del = db->seq;
    /* exact history: before insert nothing, then v0, then v1, then nothing */
    CHECK(pk_lookup(db, 1, s_ins - 1) == IMDB_NONE);
    CHECK(pk_lookup(db, 1, s_ins) == 0);
    CHECK(pk_lookup(db, 1, s_upd) == 1);
    CHECK(pk_lookup(db, 1, s_del) == IMDB_NONE);
    imdb_value got[4];
    OK(imdb_version_values(db, t, pk_lookup(db, 1, s_ins), got, E));
    CHECK(got[2].i == 1999);
    OK(imdb_version_values(db, t, pk_lookup(db, 1, s_upd), got, E));
    CHECK(got[2].i == 2000);
    /* re-insert after delete is allowed and gets a fresh version */
    OK(ins1(db, 1, 42, 5, "again"));
    CHECK(pk_lookup(db, 1, db->seq) == 2);
    /* duplicate live key is a constraint error with no value in the message */
    OK(ins1(db, 987654, 7, 1, "LEAKCHECK"));
    imdb_err_clear(E);
    CHECK(ins1(db, 987654, 7, 1, "LEAKCHECK") == IMDB_ERR_CONSTRAINT);
    CHECK(strstr(g_e.msg, "duplicate primary key") && !strstr(g_e.msg, "987654") && !strstr(g_e.msg, "LEAKCHECK"));
    imdb_close(db);
}

static void t_rollback_savepoint(void)
{
    const char *dir = test_tmpdir();
    OK(imdb_init(dir, false, NULL, E));
    imdb_db *db = open_db(dir);
    CHECK(db);
    OK(make_table(db, E));
    uint8_t d0[32];
    imdb_state_digest(db, NULL, d0);
    imdb_table *t = imdb_table_by_name(db, "txns");
    imdb_value v[4];
    OK(imdb_begin(db, E));
    row_vals(v, 1, 1, 1, "a");
    OK(imdb_insert(db, t, v, E));
    imdb_savepoint sp = imdb_savepoint_take(db);
    row_vals(v, 2, 1, 1, "b");
    OK(imdb_insert(db, t, v, E));
    CHECK(pk_lookup(db, 2, imdb_read_snapshot(db)) != IMDB_NONE); /* read-your-writes */
    imdb_savepoint_restore(db, sp);
    CHECK(pk_lookup(db, 2, imdb_read_snapshot(db)) == IMDB_NONE);
    CHECK(pk_lookup(db, 1, imdb_read_snapshot(db)) != IMDB_NONE);
    imdb_rollback(db);
    CHECK(t->nver == 0 && t->live == 0 && db->seq == 2 - 1);
    uint8_t d1[32];
    imdb_state_digest(db, NULL, d1);
    CHECK(memcmp(d0, d1, 32) == 0);
    /* rolled-back CREATE TABLE disappears */
    imdb_schema s;
    txn_schema(&s);
    strcpy(s.name, "other");
    OK(imdb_begin(db, E));
    OK(imdb_create_table(db, &s, E));
    imdb_rollback(db);
    CHECK(imdb_table_by_name(db, "other") == NULL && db->nt == 1);
    imdb_close(db);
    db = open_db(dir);
    CHECK(db && db->seq == 1);
    imdb_close(db);
}

static void t_torn_tail_every_offset(void)
{
    imdb_log_set_tagged(false); /* the untagged format: an append cut at every byte (t_tseg: the tagged one) */
    const char *dir = test_tmpdir();
    OK(imdb_init(dir, false, NULL, E));
    imdb_db *db = open_db(dir);
    CHECK(db);
    OK(make_table(db, E));
    for (int i = 1; i <= 3; i++) OK(ins1(db, i, 1, i, "row"));
    long before_last = (long)db->log_size;
    uint8_t head3[32];
    memcpy(head3, db->head, 32);
    OK(ins1(db, 4, 1, 4, "last-row"));
    long full = (long)db->log_size;
    uint64_t seq_full = db->seq;
    imdb_close(db);
    /* a crash during commit 4's append: the writer never published it as durable */
    durable_set(dir, seq_full - 1, head3, true);
    size_t n;
    char lp[700];
    snprintf(lp, sizeof lp, "%s", seg_path(dir, -1)); /* no CHECKPOINT: one segment */
    CHECK(log_segments(dir) == 1);
    uint8_t *orig = slurp(lp, &n);
    CHECK(orig && (long)n == full);
    /* every truncation point inside the last frame recovers to the previous commit */
    for (long cut = before_last; cut < full; cut++) {
        spit(lp, orig, (size_t)cut);
        db = open_db(dir);
        CHECK(db);
        CHECK(db->seq == seq_full - 1);
        CHECK(cut == before_last || db->warning[0]);
        CHECK(file_size(lp) == before_last);
        imdb_close(db);
    }
    /* zero-filled tail (size extended, data not persisted) is also a torn tail */
    uint8_t *z = calloc(1, (size_t)full + 100);
    memcpy(z, orig, (size_t)before_last);
    spit(lp, z, (size_t)full + 100);
    db = open_db(dir);
    CHECK(db && db->seq == seq_full - 1);
    imdb_close(db);
    /* a corrupt frame followed by data is never silently dropped */
    uint8_t *c = malloc(n);
    memcpy(c, orig, n);
    c[before_last - 40] ^= 0x01; /* inside the third insert's frame */
    spit(lp, c, n);
    imdb_open_opts o = {.sync = 0};
    imdb_err_clear(E);
    CHECK(imdb_open(dir, &o, &db, E) == IMDB_ERR_CORRUPT);
    /* restore and confirm full state */
    spit(lp, orig, n);
    db = open_db(dir);
    CHECK(db && db->seq == seq_full);
    imdb_close(db);
    free(orig);
    free(z);
    free(c);
}

static void t_replication_exact(void)
{
    const char *pdir = test_tmpdir();
    char p[600], r[600], s[600];
    snprintf(p, sizeof p, "%s/primary", pdir);
    snprintf(r, sizeof r, "%s/replica", pdir);
    snprintf(s, sizeof s, "%s/stream", pdir);
    OK(imdb_init(p, false, NULL, E));
    OK(imdb_init(r, true, p, E));
    imdb_db *db = open_db(p);
    CHECK(db);
    OK(make_table(db, E));
    for (int i = 1; i <= 30; i++) OK(ins1(db, i, i % 3, i, "x"));
    OK(ship_to_file(p, 0, s, E));
    imdb_db *rep = open_db(r);
    CHECK(rep);
    uint64_t applied;
    OK(apply_file(rep, s, &applied, E));
    CHECK(applied == 31 && rep->seq == db->seq && memcmp(rep->head, db->head, 32) == 0);
    CHECK(memcmp(&rep->global, &db->global, sizeof db->global) == 0);
    /* incremental: ship only the new commits */
    for (int i = 31; i <= 40; i++) OK(ins1(db, i, 9, i, "y"));
    OK(ship_to_file(p, rep->seq, s, E));
    OK(apply_file(rep, s, &applied, E));
    CHECK(applied == 10 && rep->seq == db->seq);
    CHECK(count_subject(rep, 9, rep->seq) == 10 && count_subject(db, 9, db->seq) == 10);
    /* replicas refuse local writes */
    imdb_err_clear(E);
    CHECK(imdb_begin(rep, E) == IMDB_ERR_STATE);
    imdb_close(rep);
    imdb_close(db);
    /* physical exactness: the replica's log segments hold the primary's frames, byte for byte (design.md §1) */
    char why[300], la[700], lb[700];
    snprintf(la, sizeof la, "%s/log", p);
    snprintf(lb, sizeof lb, "%s/log", r);
    CHECK(log_segments(p) >= 1 && logs_identical(la, lb, why, sizeof why));
    rep = open_db(r);
    CHECK(rep);
    imdb_verify_report vr;
    OK(imdb_verify(rep, &vr, E));
    CHECK(vr.commits == 41 && vr.sigs_checked == 41);
    imdb_close(rep);
}

/* Rewrites frame CRCs so a tampered frame passes framing and is caught by
 * the cryptographic checks (what an attacker who controls the wire can do). */
static void refresh_crcs(uint8_t *f, size_t len)
{
    uint32_t blen = imdb_get_le32(f + 4);
    (void)len;
    imdb_le32(f + 8, imdb_crc32c_ref(0, f + 16, blen));
    imdb_le32(f + 12, imdb_crc32c_ref(0, f, 12));
}

static void t_replication_tamper(void)
{
    const char *base = test_tmpdir();
    char p[600], s[600];
    snprintf(p, sizeof p, "%s/primary", base);
    snprintf(s, sizeof s, "%s/stream", base);
    OK(imdb_init(p, false, NULL, E));
    imdb_db *db = open_db(p);
    CHECK(db);
    OK(make_table(db, E));
    OK(ins1(db, 1, 1, 100, "honest-memo"));
    imdb_close(db);
    OK(ship_to_file(p, 0, s, E));
    size_t n;
    uint8_t *orig = slurp(s, &n);
    CHECK(orig);
    size_t f1 = 16 + imdb_get_le32(orig + 4); /* second frame = the insert */
    struct {
        const char *what;
        int expect;
    } cases[] = {{"payload byte", IMDB_ERR_VERIFY}, {"header byte", IMDB_ERR_AUTH}, {"wrong key", IMDB_ERR_AUTH}};
    for (int k = 0; k < 3; k++) {
        char r[600];
        snprintf(r, sizeof r, "%s/replica%d", base, k);
        if (k == 2) { /* a replica that trusts a different writer key */
            imdb_identity id;
            uint8_t seed[32];
            OK(imdb_identity_read(p, &id, NULL, E));
            test_rand_bytes(seed, 32);
            imdb_signer other;
            imdb_signer_init(&other, seed);
            memcpy(id.writer, other.pk, 32);
            OK(imdb_init_replica(r, &id, E));
        } else {
            OK(imdb_init(r, true, p, E));
        }
        uint8_t *m = malloc(n);
        memcpy(m, orig, n);
        uint8_t *fr = m + f1;
        if (k == 0) {
            /* flip a byte inside the memo text (payload is at the end of the frame) */
            size_t at = n - 3;
            m[at] ^= 0x20;
        } else if (k == 1) {
            fr[16 + IMDB_BODY_DESC + 2 + 8 + 2] ^= 1; /* timestamp byte in the chained header */
        }
        if (k < 2) refresh_crcs(fr, n - f1);
        spit(s, m, n);
        imdb_db *rep = open_db(r);
        CHECK(rep);
        uint64_t applied;
        imdb_err_clear(E);
        int rc = apply_file(rep, s, &applied, E);
        if (rc != cases[k].expect) fprintf(stderr, "    case %s: rc=%d %s\n", cases[k].what, rc, g_e.msg);
        CHECK(rc == cases[k].expect);
        /* the stream reader's row check is the only one on this path (apply trusts it) */
        if (k == 0) CHECK(strstr(g_e.msg, "does not match its signed commitment"));
        CHECK(rep->seq <= 1); /* nothing past the tampered commit was accepted */
        imdb_close(rep);
        free(m);
    }
    free(orig);
}

static void t_erase_subject_everywhere(void)
{
    const char *base = test_tmpdir();
    char p[600], r[600], r2[600], s[600];
    snprintf(p, sizeof p, "%s/primary", base);
    snprintf(r, sizeof r, "%s/replica", base);
    snprintf(r2, sizeof r2, "%s/late-replica", base);
    snprintf(s, sizeof s, "%s/stream", base);
    OK(imdb_init(p, false, NULL, E));
    OK(imdb_init(r, true, p, E));
    OK(imdb_init(r2, true, p, E));
    imdb_db *db = open_db(p);
    CHECK(db);
    OK(make_table(db, E));
    imdb_table *t = imdb_table_by_name(db, "txns");
    /* user 42: 15 transactions, one updated (history holds two versions) */
    for (int i = 1; i <= 15; i++) OK(ins1(db, 100 + i, 42, i * 10, "SECRET-42-memo"));
    for (int i = 1; i <= 5; i++) OK(ins1(db, 200 + i, 7, i, "user7-memo"));
    imdb_value v[4];
    row_vals(v, 101, 42, 99999, "SECRET-42-updated");
    OK(imdb_begin(db, E));
    OK(imdb_update(db, t, pk_lookup(db, 101, imdb_read_snapshot(db)), v, E));
    OK(imdb_commit(db, E));
    uint64_t before = db->seq;
    CHECK(count_subject(db, 42, db->seq) == 15);
    /* replica 1 sees everything before the erasure */
    OK(ship_to_file(p, 0, s, E));
    imdb_db *rep = open_db(r);
    CHECK(rep);
    uint64_t applied;
    OK(apply_file(rep, s, &applied, E));
    CHECK(count_subject(rep, 42, rep->seq) == 15);
    CHECK(tree_contains(r, "SECRET-42"));

    imdb_value subj = {.type = IMDB_T_INT64, .i = 42};
    imdb_erase_report er;
    OK(imdb_erase_subject(db, &subj, &er, E));
    CHECK(er.versions == 16 && er.live_deleted == 15 && er.tables == 1);
    CHECK(count_subject(db, 42, db->seq) == 0);
    CHECK(count_subject(db, 42, before) == 0); /* erased from history too */
    CHECK(count_subject(db, 7, db->seq) == 5);
    CHECK(!tree_contains(p, "SECRET-42"));    /* gone from every file of the primary */
    imdb_verify_report vr;
    OK(imdb_verify(db, &vr, E));
    CHECK(vr.stubs == 16);

    /* replica 1 receives the ERASE and redacts its own copy */
    OK(ship_to_file(p, rep->seq, s, E));
    OK(apply_file(rep, s, &applied, E));
    CHECK(applied == 1 && rep->seq == db->seq);
    CHECK(!tree_contains(r, "SECRET-42"));
    CHECK(memcmp(&rep->global, &db->global, sizeof db->global) == 0);
    OK(imdb_verify(rep, &vr, E));
    imdb_close(rep);

    /* a replica that bootstraps afterwards never sees the payload at all */
    OK(ship_to_file(p, 0, s, E));
    CHECK(!tree_contains(base, "SECRET-42"));
    imdb_db *late = open_db(r2);
    CHECK(late);
    OK(apply_file(late, s, &applied, E));
    CHECK(late->seq == db->seq && late->pending_auth == 0);
    OK(imdb_verify(late, &vr, E));
    imdb_close(late);
    imdb_close(db);

    /* the log segments hold the same frames on the primary and both replicas */
    char why[300], la[700], lb[700], lc[700];
    snprintf(la, sizeof la, "%s/log", p);
    snprintf(lb, sizeof lb, "%s/log", r);
    snprintf(lc, sizeof lc, "%s/log", r2);
    CHECK(logs_identical(la, lb, why, sizeof why) && logs_identical(la, lc, why, sizeof why));
    db = open_db(p);
    CHECK(db && count_subject(db, 7, db->seq) == 5 && count_subject(db, 42, db->seq) == 0);
    imdb_close(db);
}

static void t_stub_needs_authorisation(void)
{
    /* A log whose payload was blanked without an ERASE record must be rejected. */
    const char *base = test_tmpdir();
    char p[600];
    snprintf(p, sizeof p, "%s/primary", base);
    OK(imdb_init(p, false, NULL, E));
    imdb_db *db = open_db(p);
    CHECK(db);
    OK(make_table(db, E));
    OK(ins1(db, 1, 1, 1, "data"));
    imdb_close(db);
    size_t n;
    char lp[700];
    snprintf(lp, sizeof lp, "%s", seg_path(p, -1));
    uint64_t first;
    bool tg;
    uint8_t *log = seg_frames(lp, &n, &first, &tg); /* its frames, either format */
    size_t f1 = 16 + imdb_get_le32(log + 4);
    imdb_commit_rec c;
    OK(imdb_frame_decode_body(log + f1 + 16, n - f1 - 16, &c, E));
    c.ops[0].pkind = IMDB_PAYLOAD_REDACTED;
    imdb_buf pay, out;
    imdb_buf_init(&pay);
    imdb_buf_init(&out);
    imdb_commit_encode_payload(&c, &pay);
    imdb_buf_put(&out, log, f1);
    imdb_frame_build(log + f1 + 16 + IMDB_BODY_DESC, c.hlen, c.seq, c.hash, c.sig, pay.p, pay.len, &out);
    imdb_commit_free(&c);
    seg_put_frames(lp, first, tg, out.p, out.len);
    imdb_open_opts o = {.sync = 0};
    imdb_err_clear(E);
    CHECK(imdb_open(p, &o, &db, E) == IMDB_ERR_CORRUPT);
    CHECK(strstr(g_e.msg, "no ERASE authorises"));
    imdb_buf_free(&pay);
    imdb_buf_free(&out);
    free(log);
}

/* Crash window: the ERASE commit is durable but the log rewrite never ran. */
static void t_erase_crash_window(void)
{
    const char *dir = test_tmpdir();
    OK(imdb_init(dir, false, NULL, E));
    imdb_db *db = open_db(dir);
    CHECK(db);
    OK(make_table(db, E));
    for (int i = 1; i <= 5; i++) OK(ins1(db, i, 42, i, "SECRET-crash-42"));
    OK(ins1(db, 50, 7, 1, "keep-7"));
    imdb_close(db);
    size_t npre, npost;
    char lp[700];
    snprintf(lp, sizeof lp, "%s", seg_path(dir, -1));
    CHECK(log_segments(dir) == 1);
    uint64_t first;
    bool tg;
    uint8_t *pre = seg_frames(lp, &npre, &first, &tg); /* frames, either format */
    db = open_db(dir);
    CHECK(db);
    imdb_value subj = {.type = IMDB_T_INT64, .i = 42};
    imdb_erase_report er;
    OK(imdb_erase_subject(db, &subj, &er, E));
    CHECK(er.versions == 5 && !er.redaction_pending);
    imdb_close(db);
    /* the ERASE ended the segment it was appended to: still one segment */
    CHECK(log_segments(dir) == 1);
    uint8_t *post = seg_frames(lp, &npost, &first, &tg);
    size_t off = 0, last = 0;
    while (off < npost) {
        last = off;
        off += 16 + imdb_get_le32(post + off + 4);
    }
    uint8_t *crash = malloc(npre + (npost - last));
    memcpy(crash, pre, npre);
    memcpy(crash + npre, post + last, npost - last);
    seg_put_frames(lp, first, tg, crash, npre + (npost - last));
    /* the crash is before the log redaction, so (the invariant of lake_persist)
     * the ERASE's lake state was never published: no lake existed before it */
    rm_lake(dir);
    CHECK(tree_contains(dir, "SECRET-crash-42"));
    /* read-only open must not hide the incomplete erasure */
    imdb_open_opts ro = {.sync = 0, .read_only = true};
    imdb_err_clear(E);
    CHECK(imdb_open(dir, &ro, &db, E) == 0);
    imdb_verify_report vr;
    imdb_err_clear(E);
    CHECK(imdb_verify(db, &vr, E) == IMDB_ERR_VERIFY && strstr(g_e.msg, "erasure incomplete"));
    imdb_close(db);
    CHECK(tree_contains(dir, "SECRET-crash-42"));
    /* a normal open finishes the redaction */
    db = open_db(dir);
    CHECK(db);
    CHECK(!tree_contains(dir, "SECRET-crash-42"));
    OK(imdb_verify(db, &vr, E));
    CHECK(count_subject(db, 7, db->seq) == 1 && vr.stubs == 5);
    imdb_close(db);
    free(pre);
    free(post);
    free(crash);
}

/* Crash window of the new order: the log is redacted, the lake not yet
 * published. LAKE_HEAD still names the pre-ERASE manifest, whose objects hold
 * the erased rows. VERIFY must fail and a normal open must finish the job. */
static void t_erase_crash_before_lake(void)
{
    const char *dir = test_tmpdir();
    OK(imdb_init(dir, false, NULL, E));
    imdb_db *db = open_db(dir);
    CHECK(db);
    OK(make_table(db, E));
    for (int i = 1; i <= 4; i++) OK(ins1(db, i, 42, i, "SECRET-lake-42"));
    OK(ins1(db, 9, 7, 9, "keep-7"));
    OK(imdb_checkpoint(db, E));
    imdb_close(db);
    /* the published lake before the ERASE */
    size_t hn;
    uint8_t *head = slurp(path_join(dir, "LAKE_HEAD"), &hn);
    char od[700], bk[700];
    snprintf(od, sizeof od, "%s/objects", dir);
    snprintf(bk, sizeof bk, "%s/objects-before", dir);
    CHECK(rename(od, bk) == 0 && mkdir(od, 0700) == 0);
    db = open_db(dir); /* republishes the objects into the fresh objects/ */
    CHECK(db);
    imdb_value subj = {.type = IMDB_T_INT64, .i = 42};
    imdb_erase_report er;
    OK(imdb_erase_subject(db, &subj, &er, E));
    imdb_close(db);
    CHECK(!tree_contains(dir, "SECRET-lake-42") || tree_contains(bk, "SECRET-lake-42"));
    /* the crash: redaction done, lake_persist never ran */
    rm_lake(dir);
    CHECK(rmdir(od) == 0 && rename(bk, od) == 0);
    spit(path_join(dir, "LAKE_HEAD"), head, hn);
    CHECK(tree_contains(od, "SECRET-lake-42"));
    imdb_open_opts ro = {.sync = 0, .read_only = true};
    CHECK(imdb_open(dir, &ro, &db, E) == 0);
    imdb_verify_report vr;
    imdb_err_clear(E);
    CHECK(imdb_verify(db, &vr, E) != 0);
    imdb_close(db);
    db = open_db(dir);
    CHECK(db);
    CHECK(!tree_contains(dir, "SECRET-lake-42"));
    OK(imdb_verify(db, &vr, E));
    CHECK(count_subject(db, 7, db->seq) == 1 && count_subject(db, 42, db->seq) == 0 && vr.stubs == 4);
    imdb_close(db);
    free(head);
}

/* TEXT primary key and TEXT subject: key chains, map deletion and wiping. */
static void t_erase_text_keys(void)
{
    const char *base = test_tmpdir();
    char p[600], r[600], s[600];
    snprintf(p, sizeof p, "%s/primary", base);
    snprintf(r, sizeof r, "%s/replica", base);
    snprintf(s, sizeof s, "%s/stream", base);
    OK(imdb_init(p, false, NULL, E));
    OK(imdb_init(r, true, p, E));
    imdb_db *db = open_db(p);
    CHECK(db);
    imdb_schema sc;
    memset(&sc, 0, sizeof sc);
    strcpy(sc.name, "accounts");
    sc.ncols = 3;
    strcpy(sc.cols[0].name, "email");
    sc.cols[0].type = IMDB_T_TEXT;
    sc.cols[0].flags = IMDB_COL_PK;
    strcpy(sc.cols[1].name, "owner");
    sc.cols[1].type = IMDB_T_TEXT;
    sc.cols[1].flags = IMDB_COL_SUBJECT;
    strcpy(sc.cols[2].name, "balance");
    sc.cols[2].type = IMDB_T_DECIMAL;
    sc.cols[2].precision = 10;
    sc.cols[2].scale = 2;
    sc.pk = 0;
    sc.subject = 1;
    OK(imdb_begin(db, E));
    OK(imdb_create_table(db, &sc, E));
    OK(imdb_commit(db, E));
    imdb_table *t = imdb_table_by_name(db, "accounts");
    const char *apk = "alice-PK-7f3a@example.com", *asub = "alice-SUBJ-77";
#define ACC(v, pk, sub, cents)                                                                       \
    imdb_value v[3] = {{.type = IMDB_T_TEXT, .s = (const uint8_t *)(pk), .len = (uint32_t)strlen(pk)},  \
                       {.type = IMDB_T_TEXT, .s = (const uint8_t *)(sub), .len = (uint32_t)strlen(sub)}, \
                       {.type = IMDB_T_DECIMAL, .scale = 2, .i = (cents)}}
    imdb_value key = {.type = IMDB_T_TEXT, .s = (const uint8_t *)apk, .len = (uint32_t)strlen(apk)};
    {
        ACC(v, apk, asub, 100);
        OK(imdb_begin(db, E));
        OK(imdb_insert(db, t, v, E));
        OK(imdb_commit(db, E));
    }
    {
        ACC(v, "bob@example.com", "bob", 5);
        OK(imdb_begin(db, E));
        OK(imdb_insert(db, t, v, E));
        OK(imdb_commit(db, E));
    }
    {
        ACC(v, apk, asub, 200);
        OK(imdb_begin(db, E));
        OK(imdb_update(db, t, imdb_lookup_pk(db, t, &key, imdb_read_snapshot(db)), v, E));
        OK(imdb_commit(db, E));
    }
    OK(imdb_begin(db, E));
    OK(imdb_delete(db, t, imdb_lookup_pk(db, t, &key, imdb_read_snapshot(db)), E));
    OK(imdb_commit(db, E));
    {
        ACC(v, apk, asub, 300);
        OK(imdb_begin(db, E));
        OK(imdb_insert(db, t, v, E));
        OK(imdb_commit(db, E));
    }
    uint64_t mid = db->seq;
    CHECK(imdb_lookup_pk(db, t, &key, mid) == 3);
    OK(ship_to_file(p, 0, s, E));
    imdb_db *rep = open_db(r);
    CHECK(rep);
    uint64_t applied;
    OK(apply_file(rep, s, &applied, E));
    CHECK(tree_contains(r, apk));

    imdb_value sv = {.type = IMDB_T_TEXT, .s = (const uint8_t *)asub, .len = (uint32_t)strlen(asub)};
    imdb_erase_report er;
    OK(imdb_erase_subject(db, &sv, &er, E));
    CHECK(er.versions == 3 && er.live_deleted == 1);
    for (uint64_t snap = 0; snap <= db->seq; snap++) CHECK(imdb_lookup_pk(db, t, &key, snap) == IMDB_NONE);
    CHECK(imdb_hmap_get(&t->pk, &key) == NULL && imdb_hmap_get(&t->subj, &sv) == NULL);
    CHECK(!mem_contains(t->arena.p, t->arena.len, apk) && !mem_contains(t->arena.p, t->arena.len, asub));
    imdb_value bob = {.type = IMDB_T_TEXT, .s = (const uint8_t *)"bob@example.com", .len = 15};
    CHECK(imdb_lookup_pk(db, t, &bob, db->seq) == 1);
    CHECK(!tree_contains(p, apk) && !tree_contains(p, asub) && tree_contains(p, "bob@example.com"));
    imdb_verify_report vr;
    OK(imdb_verify(db, &vr, E));
    OK(ship_to_file(p, rep->seq, s, E));
    OK(apply_file(rep, s, &applied, E));
    CHECK(!tree_contains(r, apk) && !tree_contains(r, asub));
    CHECK(imdb_lookup_pk(rep, imdb_table_by_name(rep, "accounts"), &key, mid) == IMDB_NONE);
    OK(imdb_verify(rep, &vr, E));
    imdb_close(rep);
    /* the same key may be used again after erasure: a fresh, unrelated row */
    {
        ACC(v, apk, "someone-else", 1);
        OK(imdb_begin(db, E));
        OK(imdb_insert(db, t, v, E));
        OK(imdb_commit(db, E));
    }
    CHECK(imdb_lookup_pk(db, t, &key, mid) == IMDB_NONE && imdb_lookup_pk(db, t, &key, db->seq) == 4);
    imdb_close(db);
    db = open_db(p);
    CHECK(db);
    t = imdb_table_by_name(db, "accounts");
    CHECK(imdb_lookup_pk(db, t, &key, mid) == IMDB_NONE && imdb_lookup_pk(db, t, &key, db->seq) == 4);
    OK(imdb_verify(db, &vr, E));
    imdb_close(db);
#undef ACC
}

/* Random workload against a simple oracle; checks digests, history, replay,
 * verification and replica equality. */
typedef struct oracle_row {
    bool live;
    int64_t user, cents;
} oracle_row;

static void t_random_model(void)
{
    const char *base = test_tmpdir();
    char p[600], r[600], s[600];
    snprintf(p, sizeof p, "%s/primary", base);
    snprintf(r, sizeof r, "%s/replica", base);
    snprintf(s, sizeof s, "%s/stream", base);
    OK(imdb_init(p, false, NULL, E));
    OK(imdb_init(r, true, p, E));
    imdb_db *db = open_db(p);
    CHECK(db);
    OK(make_table(db, E));
    imdb_table *t = imdb_table_by_name(db, "txns");
    enum { KEYS = 64, STEPS = 600, USERS = 6 };
    oracle_row model[KEYS];
    memset(model, 0, sizeof model);
    uint64_t erased_users = 0;
    for (int step = 0; step < STEPS; step++) {
        int op = (int)(test_rand() % 100);
        if (op < 3) { /* erase a user */
            int64_t u = (int64_t)(test_rand() % USERS);
            imdb_value sv = {.type = IMDB_T_INT64, .i = u};
            imdb_erase_report er;
            OK(imdb_erase_subject(db, &sv, &er, E));
            for (int k = 0; k < KEYS; k++)
                if (model[k].live && model[k].user == u) model[k].live = false;
            erased_users |= 1ull << u;
            continue;
        }
        OK(imdb_begin(db, E));
        int nops = 1 + (int)(test_rand() % 4);
        for (int j = 0; j < nops; j++) {
            int k = (int)(test_rand() % KEYS);
            uint64_t vid = pk_lookup(db, k, imdb_read_snapshot(db));
            CHECK((vid != IMDB_NONE) == model[k].live);
            imdb_value v[4];
            int64_t u = (int64_t)(test_rand() % USERS), cents = (int64_t)(test_rand() % 100000);
            row_vals(v, k, u, cents, (test_rand() & 1) ? "m" : "memo-\xc3\xa9");
            if (!model[k].live) {
                OK(imdb_insert(db, t, v, E));
                model[k] = (oracle_row){true, u, cents};
            } else if (test_rand() & 1) {
                OK(imdb_update(db, t, vid, v, E));
                model[k] = (oracle_row){true, u, cents};
            } else {
                OK(imdb_delete(db, t, vid, E));
                model[k].live = false;
            }
        }
        if (test_rand() % 10 == 0) {
            imdb_rollback(db);
            /* rebuild the model from the engine's committed state */
            for (int k = 0; k < KEYS; k++) {
                uint64_t vid = pk_lookup(db, k, db->seq);
                model[k].live = vid != IMDB_NONE;
                if (model[k].live) {
                    imdb_value got[4];
                    OK(imdb_version_values(db, t, vid, got, E));
                    model[k].user = got[1].i;
                    model[k].cents = got[2].i;
                }
            }
        } else {
            OK(imdb_commit(db, E));
        }
        /* check every key against the model, and the incremental digest */
        uint64_t live = 0;
        for (int k = 0; k < KEYS; k++) {
            uint64_t vid = pk_lookup(db, k, db->seq);
            CHECK((vid != IMDB_NONE) == model[k].live);
            if (vid != IMDB_NONE) {
                imdb_value got[4];
                OK(imdb_version_values(db, t, vid, got, E));
                CHECK(got[1].i == model[k].user && got[2].i == model[k].cents);
                live++;
            }
        }
        CHECK(live == t->live);
        if (step % 50 == 0) {
            imdb_lthash re;
            OK(imdb_recompute_digest(db, t, db->seq, &re, E));
            CHECK(memcmp(&re, &t->digest, sizeof re) == 0);
        }
    }
    (void)erased_users;
    imdb_verify_report vr;
    OK(imdb_verify(db, &vr, E));
    uint8_t d[32];
    imdb_state_digest(db, NULL, d);
    uint64_t seq = db->seq;
    imdb_close(db);
    db = open_db(p);
    CHECK(db);
    uint8_t d2[32];
    imdb_state_digest(db, NULL, d2);
    CHECK(db->seq == seq && memcmp(d, d2, 32) == 0);
    OK(ship_to_file(p, 0, s, E));
    imdb_db *rep = open_db(r);
    CHECK(rep);
    uint64_t applied;
    OK(apply_file(rep, s, &applied, E));
    CHECK(rep->seq == seq && memcmp(&rep->global, &db->global, sizeof rep->global) == 0);
    OK(imdb_verify(rep, &vr, E));
    imdb_close(rep);
    imdb_close(db);
}

/* ---- staged stream reader: nothing unauthenticated is decoded or buffered ---- */

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

/* Runs the reader over bytes for commit `seq` after `prev`; returns rc and
 * how many bytes it consumed and buffered. */
static int stream_try(const uint8_t *w, const uint8_t *b, size_t n, uint64_t seq, const uint8_t prev[32],
                      size_t *consumed, size_t *buffered)
{
    memrd m = {b, n, 0};
    imdb_stream s;
    imdb_stream_init(&s, w, mem_read, &m);
    bool eof;
    imdb_err_clear(E);
    int rc = imdb_stream_next(&s, seq, prev, &eof, E);
    *consumed = m.off;
    *buffered = s.frame.len;
    imdb_stream_free(&s);
    return rc;
}

static void t_stream_preauth(void)
{
    const char *base = test_tmpdir();
    char p[600], s[600];
    snprintf(p, sizeof p, "%s/primary", base);
    snprintf(s, sizeof s, "%s/stream", base);
    OK(imdb_init(p, false, NULL, E));
    imdb_db *db = open_db(p);
    CHECK(db);
    OK(make_table(db, E));
    OK(ins1(db, 1, 1, 100, "first-row-memo"));
    uint8_t head1[32];
    memcpy(head1, imdb_ci_at(db, 1, E)->hash, 32);
    imdb_close(db);
    OK(ship_to_file(p, 0, s, E));
    size_t n;
    uint8_t *orig = slurp(s, &n);
    CHECK(orig);
    uint8_t id[16], w[32], g[32];
    OK(imdb_read_identity(p, id, w, E));
    imdb_genesis_hash(id, g);
    size_t f1 = 16 + imdb_get_le32(orig + 4), want = IMDB_FRAME_HDR + IMDB_BODY_DESC;
    size_t used, held;

    /* honest stream: both frames authenticate, then a clean end */
    memrd m = {orig, n, 0};
    imdb_stream st;
    imdb_stream_init(&st, w, mem_read, &m);
    bool eof;
    OK(imdb_stream_next(&st, 1, g, &eof, E));
    CHECK(!eof && st.frame.len == f1 && st.preauth_bytes == want);
    OK(imdb_stream_next(&st, 2, head1, &eof, E));
    CHECK(!eof && m.off == n);
    OK(imdb_stream_next(&st, 3, head1, &eof, E));
    CHECK(eof);
    imdb_stream_free(&st);

    uint8_t *b = malloc(n);
    /* forged signature: rejected after exactly 125 bytes, nothing buffered */
    memcpy(b, orig, n);
    b[f1 + 16 + 45 + 7] ^= 0x40;
    CHECK(stream_try(w, b + f1, n - f1, 2, head1, &used, &held) == IMDB_ERR_AUTH && used == want && held == 0);
    /* a 1 GiB body length with a forged descriptor: still 125 bytes, no allocation */
    memcpy(b, orig, n);
    imdb_le32(b + f1 + 4, IMDB_MAX_FRAME);
    imdb_le32(b + f1 + 12, imdb_crc32c_ref(0, b + f1, 12));
    b[f1 + 16 + 45] ^= 1;
    CHECK(stream_try(w, b + f1, n - f1, 2, head1, &used, &held) == IMDB_ERR_AUTH && used == want && held == 0);
    /* replay of a genuine frame where the next commit is expected */
    CHECK(stream_try(w, orig, n, 2, head1, &used, &held) == IMDB_ERR_VERIFY && used == want && held == 0);
    /* a header length that cannot fit the frame is refused before the signature check */
    memcpy(b, orig, n);
    imdb_le32(b + f1 + 16 + 1, IMDB_MAX_HEADER);
    CHECK(stream_try(w, b + f1, n - f1, 2, head1, &used, &held) == IMDB_ERR_CORRUPT && used == want && held == 0);
    /* a genuine descriptor over a tampered header: caught by the signed hash */
    memcpy(b, orig, n);
    b[f1 + 16 + IMDB_BODY_DESC + 12] ^= 1;
    CHECK(stream_try(w, b + f1, n - f1, 2, head1, &used, &held) == IMDB_ERR_AUTH && used > want);
    /* a tampered row: caught by its signed commitment */
    memcpy(b, orig, n);
    b[n - 2] ^= 0x20;
    CHECK(stream_try(w, b + f1, n - f1, 2, head1, &used, &held) == IMDB_ERR_VERIFY);
    /* the right commit chained to the wrong head */
    CHECK(stream_try(w, orig + f1, n - f1, 2, g, &used, &held) == IMDB_ERR_VERIFY);
    /* truncation anywhere inside a frame is an error, never a silent end */
    for (size_t cut = 1; cut < n - f1; cut += 7)
        CHECK(stream_try(w, orig + f1, cut, 2, head1, &used, &held) == IMDB_ERR_CORRUPT);
    free(b);
    free(orig);
}

/* ---- the segmented log: rotation, partial redaction, layout rules ---------------- */

static uint64_t inode_of(const char *p)
{
    struct stat st;
    return stat(p, &st) == 0 ? (uint64_t)st.st_ino : 0;
}

static void t_log_segments(void)
{
    imdb_log_set_tagged(false); /* the untagged format, byte by byte (segments of both kinds: t_tseg) */
    const char *base = test_tmpdir();
    char p[600], r[600], s[600];
    snprintf(p, sizeof p, "%s/primary", base);
    snprintf(r, sizeof r, "%s/replica", base);
    snprintf(s, sizeof s, "%s/stream", base);
    OK(imdb_init(p, false, NULL, E));
    imdb_db *db = open_db(p);
    CHECK(db);
    OK(make_table(db, E));
    /* three batches, a CHECKPOINT after each: the subject 42 rows only in the middle one */
    for (int i = 1; i <= 4; i++) OK(ins1(db, i, 7, i, "batch-one"));
    OK(imdb_checkpoint(db, E));
    for (int i = 5; i <= 8; i++) OK(ins1(db, i, 42, i, "SEG-SECRET-42"));
    OK(imdb_checkpoint(db, E));
    for (int i = 9; i <= 12; i++) OK(ins1(db, i, 7, i, "batch-three"));
    imdb_close(db);
    /* a segment ends at each manifest-publishing commit; names are first seqs */
    CHECK(log_segments(p) == 3);
    CHECK(strstr(seg_path(p, 0), "/00000000000000000001.ilg"));
    char s0[700], s1[700], s2[700];
    snprintf(s0, sizeof s0, "%s", seg_path(p, 0));
    snprintf(s1, sizeof s1, "%s", seg_path(p, 1));
    snprintf(s2, sizeof s2, "%s", seg_path(p, 2));
    uint64_t i0 = inode_of(s0), i1 = inode_of(s1), i2 = inode_of(s2);
    /* ERASE rewrites only the segment that holds the erased payloads */
    db = open_db(p);
    CHECK(db);
    imdb_value subj = {.type = IMDB_T_INT64, .i = 42};
    imdb_erase_report er;
    OK(imdb_erase_subject(db, &subj, &er, E));
    CHECK(er.versions == 4 && !er.redaction_pending);
    imdb_close(db);
    CHECK(!tree_contains(p, "SEG-SECRET-42"));
    (void)i1; /* segment 2 was rewritten; its inode number may be reused, so only the others are asserted */
    CHECK(inode_of(s0) == i0 && inode_of(s2) == i2);
    CHECK(log_segments(p) == 3); /* the ERASE ended segment 3; the next commit starts a fourth */
    db = open_db(p);
    CHECK(db);
    OK(ins1(db, 13, 7, 13, "after-erase"));
    imdb_verify_report vr;
    OK(imdb_verify(db, &vr, E));
    uint64_t seq = db->seq;
    imdb_close(db);
    CHECK(log_segments(p) == 4);
    /* the replica lays out the same segments, byte for byte */
    OK(imdb_init(r, true, p, E));
    OK(ship_to_file(p, 0, s, E));
    imdb_db *rep = open_db(r);
    CHECK(rep);
    uint64_t applied;
    OK(apply_file(rep, s, &applied, E));
    CHECK(rep->seq == seq);
    imdb_close(rep);
    char la[700], lb[700], why[300] = "";
    snprintf(la, sizeof la, "%s/log", p);
    snprintf(lb, sizeof lb, "%s/log", r);
    CHECK(dirs_identical(la, lb, why, sizeof why));
    /* ship from the middle of the log streams exactly the later commits */
    OK(ship_to_file(p, 6, s, E));
    size_t sn;
    uint8_t *sb = slurp(s, &sn);
    CHECK(sb && sn > 16 && imdb_frame_seq(sb) == 7);
    free(sb);

    /* an empty last segment (a crash after a CHECKPOINT ended the previous one and
     * the next commit had created its file) is adopted */
    db = open_db(p);
    CHECK(db);
    OK(imdb_checkpoint(db, E));
    seq = db->seq;
    imdb_close(db);
    char empty[700];
    snprintf(empty, sizeof empty, "%s/log/%020llu.ilg", p, (unsigned long long)(seq + 1));
    spit(empty, (const uint8_t *)"", 0);
    db = open_db(p);
    CHECK(db);
    OK(ins1(db, 14, 7, 14, "into-the-empty-one"));
    imdb_close(db);
    CHECK(log_segments(p) == 5 && file_size(empty) > 0);
    /* a segment that continues past a manifest-publishing commit is corruption. A
     * snapshot open does not read segments before the snapshot (by design: VERIFY
     * does), so the full replay and VERIFY are the ones that must refuse it */
    size_t n0, n1b;
    uint8_t *a = slurp(s0, &n0), *b = slurp(s1, &n1b);
    uint8_t *m = malloc(n0 + n1b);
    memcpy(m, a, n0);
    memcpy(m + n0, b, n1b);
    spit(s0, m, n0 + n1b);
    unlink(s1);
    imdb_open_opts o = {.sync = 0, .full_replay = true};
    imdb_err_clear(E);
    CHECK(imdb_open(p, &o, &db, E) == IMDB_ERR_CORRUPT && strstr(g_e.msg, "continues past"));
    imdb_open_opts ro = {.sync = 0, .read_only = true};
    OK(imdb_open(p, &ro, &db, E));
    CHECK(db->snapshot_seq > 0);
    imdb_err_clear(E);
    CHECK(imdb_verify(db, &vr, E) == IMDB_ERR_VERIFY && strstr(g_e.msg, "segments do not end exactly"));
    imdb_close(db);
    /* a torn frame anywhere but the last segment is corruption, never truncated */
    spit(s0, a, n0 - 5);
    spit(s1, b, n1b);
    imdb_err_clear(E);
    CHECK(imdb_open(p, &o, &db, E) == IMDB_ERR_CORRUPT && file_size(s0) == (long)(n0 - 5));
    spit(s0, a, n0);
    db = open_db(p);
    CHECK(db);
    OK(imdb_verify(db, &vr, E));
    imdb_close(db);
    free(a);
    free(b);
    free(m);

    /* the size-triggered CHECKPOINT: a logged op, so the replica rotates with it */
    char p2[600], r2[600];
    snprintf(p2, sizeof p2, "%s/auto", base);
    snprintf(r2, sizeof r2, "%s/auto-replica", base);
    OK(imdb_init(p2, false, NULL, E));
    imdb_open_opts small = {.sync = 0, .checkpoint_bytes = 2048};
    OK(imdb_open(p2, &small, &db, E));
    OK(make_table(db, E));
    for (int i = 1; i <= 40; i++) OK(ins1(db, i, 1, i, "auto-checkpoint-row-with-some-text"));
    CHECK(db->lake_seq > 0 && log_segments(p2) >= 3);
    imdb_close(db);
    OK(imdb_init(r2, true, p2, E));
    OK(ship_to_file(p2, 0, s, E));
    rep = open_db(r2);
    CHECK(rep);
    OK(apply_file(rep, s, &applied, E));
    imdb_close(rep);
    snprintf(la, sizeof la, "%s/log", p2);
    snprintf(lb, sizeof lb, "%s/log", r2);
    CHECK(dirs_identical(la, lb, why, sizeof why));
    CHECK(dirs_identical(path_join(p2, "objects"), path_join(r2, "objects"), why, sizeof why));
}

/* A signed commit whose ops name 20,000 distinct, impossible table ids is
 * rejected as an unknown table by replay and by VERIFY. Their parallel stages
 * keep digest deltas only for tables that can exist, so the ids cost no memory
 * of their own (allocation stays proportional to the input). */
static void t_unknown_tables_bounded(void)
{
    const char *dir = test_tmpdir();
    OK(imdb_init(dir, false, NULL, E));
    imdb_db *db = open_db(dir);
    CHECK(db);
    OK(make_table(db, E));
    OK(ins1(db, 1, 1, 100, "row"));
    enum { N = 20000 };
    imdb_op *ops = calloc(N, sizeof *ops);
    CHECK(ops);
    for (int k = 0; k < N; k++) {
        ops[k].code = IMDB_OP_INSERT;
        ops[k].table = 1000000u + (uint32_t)k;
        test_rand_bytes(ops[k].commit, 32);
        ops[k].pkind = IMDB_PAYLOAD_REDACTED;
    }
    imdb_commit_rec c;
    memset(&c, 0, sizeof c);
    c.seq = db->seq + 1;
    c.alg = db->meta.digest_alg;
    c.time_us = db->last_time + 1;
    memcpy(c.prev, db->head, 32);
    c.ops = ops;
    c.nops = N;
    imdb_buf h, pay, frame;
    imdb_buf_init(&h);
    imdb_buf_init(&pay);
    imdb_buf_init(&frame);
    imdb_commit_encode_header(&c, &h);
    imdb_commit_encode_payload(&c, &pay);
    imdb_commit_hash(h.p, h.len, c.hash);
    uint8_t msg[IMDB_SIGMSG_LEN];
    imdb_commit_sigmsg(c.seq, (uint32_t)h.len, c.hash, msg);
    imdb_sign(&db->signer, msg, sizeof msg, c.sig);
    imdb_frame_build(h.p, h.len, c.seq, c.hash, c.sig, pay.p, pay.len, &frame);
    CHECK(!frame.err);
    /* the frame lands on disk behind the open engine: VERIFY reads it */
    char seg[700];
    snprintf(seg, sizeof seg, "%s", seg_path(dir, -1));
    seg_append(seg, frame.p, frame.len);
    imdb_verify_report vr;
    imdb_err_clear(E);
    CHECK(imdb_verify(db, &vr, E) == IMDB_ERR_VERIFY && strstr(g_e.msg, "unknown table"));
    imdb_close(db);
    /* and replay at open stops at it */
    imdb_open_opts o = {.sync = 0, .full_replay = true, .read_only = true};
    imdb_db *db2 = NULL;
    imdb_err_clear(E);
    CHECK(imdb_open(dir, &o, &db2, E) != IMDB_OK && strstr(g_e.msg, "unknown table"));
    imdb_buf_free(&h);
    imdb_buf_free(&pay);
    imdb_buf_free(&frame);
    free(ops);
}

const test_case engine_tests[] = {
    {"unknown_tables_bounded", t_unknown_tables_bounded},
    {"commit_replay", t_commit_replay},
    {"mvcc_time_travel", t_mvcc_time_travel},
    {"rollback_savepoint", t_rollback_savepoint},
    {"torn_tail_every_offset", t_torn_tail_every_offset},
    {"replication_exact", t_replication_exact},
    {"replication_tamper", t_replication_tamper},
    {"stream_preauth", t_stream_preauth},
    {"log_segments", t_log_segments},
    {"erase_subject_everywhere", t_erase_subject_everywhere},
    {"stub_needs_authorisation", t_stub_needs_authorisation},
    {"erase_crash_window", t_erase_crash_window},
    {"erase_crash_before_lake", t_erase_crash_before_lake},
    {"erase_text_keys", t_erase_text_keys},
    {"random_model", t_random_model},
};
const size_t engine_ntests = sizeof engine_tests / sizeof *engine_tests;
