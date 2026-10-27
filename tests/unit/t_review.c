/* Regressions from the 2026-10-21 review. Faults are injected at public
 * boundaries (files/descriptors), without changing production I/O code. */
#include <fcntl.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

#include "../../src/logdir.h"
#include "../../src/sql.h"
#include "thelp.h"

static int run(imdb_session *s, const char *sql)
{
    imdb_result r;
    imdb_err_clear(E);
    int rc = imdb_exec_one(s, sql, strlen(sql), NULL, 0, &r, E);
    if (!rc) imdb_result_free(&r);
    return rc;
}

static int64_t cell(imdb_session *s, const char *sql)
{
    imdb_result r;
    imdb_err_clear(E);
    int rc = imdb_exec_one(s, sql, strlen(sql), NULL, 0, &r, E);
    int64_t v = !rc && r.nrows == 1 && !r.cells[0].null ? r.cells[0].v.i : INT64_MIN;
    if (!rc) imdb_result_free(&r);
    return v;
}

static imdb_db *sessions(imdb_session *a, imdb_session *b)
{
    const char *dir = test_tmpdir();
    if (imdb_init(dir, false, NULL, E)) return NULL;
    imdb_db *db = open_db(dir);
    if (!db) return NULL;
    imdb_session_init(a, db);
    imdb_session_init(b, db);
    if (run(a, "CREATE TABLE t (id INT64 PRIMARY KEY, u INT64 SUBJECT, v INT64, s TEXT)") ||
        run(a, "INSERT INTO t VALUES (1, 42, 0, 'ERASE-REVIEW-SECRET'), (2, 7, 20, 'keep')")) {
        imdb_close(db);
        return NULL;
    }
    a->cross_check = b->cross_check = true;
    return db;
}

static void t_review_null_parameters(void)
{
    imdb_session a, b;
    imdb_db *db = sessions(&a, &b);
    CHECK(db);
    const char *sql[] = {
        "SELECT id FROM t WHERE v = $1",
        "SELECT id FROM t WHERE v != $1",
        "SELECT id FROM t WHERE v BETWEEN 0 AND $1",
        "DELETE FROM t WHERE v = $1",
        "UPDATE t SET v = 9 WHERE v >= $1",
        "SELECT id FROM t WHERE s != $1"
    };
    bool rejected = true;
    for (int disk = 0; disk < 2; disk++) {
        if (disk) OK(run(&a, "CHECKPOINT"));
        for (int path = IMDB_PATH_INDEX; path <= IMDB_PATH_STORE; path++) {
            a.access_path = path;
            for (size_t i = 0; i < sizeof sql / sizeof *sql; i++) {
                imdb_value p = {.type = i == 5 ? IMDB_T_TEXT : IMDB_T_INT64, .null = true};
                imdb_result r;
                imdb_err_clear(E);
                int rc = imdb_exec_one(&a, sql[i], strlen(sql[i]), &p, 1, &r, E);
                rejected &= rc == IMDB_ERR_INVALID;
                if (!rc) imdb_result_free(&r);
            }
        }
    }
    bool intact = cell(&a, "SELECT COUNT(*) FROM t") == 2 && cell(&a, "SELECT v FROM t WHERE id = 1") == 0;
    imdb_session_close(&a);
    imdb_session_close(&b);
    imdb_close(db);
    CHECK(rejected && intact);
}

static void t_review_lock_own_writes(void)
{
    imdb_session a, b;
    imdb_db *db = sessions(&a, &b);
    CHECK(db);
    bool committed = true;
    for (int parked = 0; parked < 2; parked++) {
        OK(run(&a, "BEGIN"));
        OK(run(&a, "SELECT id FROM t WHERE id = 1 FOR UPDATE"));
        OK(run(&a, "UPDATE t SET v = 11 WHERE id = 1"));
        if (parked) OK(run(&b, "UPDATE t SET v = 21 WHERE id = 2"));
        committed &= run(&a, "COMMIT") == IMDB_OK;
    }
    OK(run(&a, "BEGIN"));
    OK(run(&a, "SELECT id FROM t WHERE id = 1 FOR UPDATE"));
    OK(run(&a, "DELETE FROM t WHERE id = 1"));
    committed &= run(&a, "COMMIT") == IMDB_OK;
    bool gone = cell(&b, "SELECT COUNT(*) FROM t WHERE id = 1") == 0;
    imdb_session_close(&a);
    imdb_session_close(&b);
    imdb_close(db);
    CHECK(committed && gone);
}

static void t_review_lock_uncommitted_competitor(void)
{
    imdb_session a, b;
    imdb_db *db = sessions(&a, &b);
    CHECK(db);
    OK(run(&a, "BEGIN"));
    OK(run(&a, "SELECT id FROM t WHERE id = 1 FOR UPDATE"));
    OK(run(&b, "BEGIN"));
    OK(run(&b, "UPDATE t SET v = 12 WHERE id = 1"));
    int rc = run(&a, "COMMIT"); /* B has not committed: A's observation still holds. */
    OK(run(&b, "ROLLBACK"));
    imdb_session_close(&a);
    imdb_session_close(&b);
    imdb_close(db);
    CHECK(rc == IMDB_OK);
}

static void t_review_erasure_doomed_transaction(void)
{
    imdb_session a, b;
    imdb_db *db = sessions(&a, &b);
    CHECK(db);
    OK(run(&a, "BEGIN"));
    OK(run(&a, "UPDATE t SET v = 11 WHERE id = 1"));
    OK(run(&b, "UPDATE t SET v = 21 WHERE id = 2"));
    /* Conflict on row 2 dooms A, but A still holds its row-1 write. */
    CHECK(run(&a, "UPDATE t SET v = 22 WHERE id = 2") == IMDB_ERR_CONFLICT);
    OK(run(&b, "ERASE SUBJECT 42"));
    bool wiped = a.txn.doomed && a.txn.ops == NULL && a.txn.nops == 0;
    bool disk_clean = !tree_contains(db->path, "ERASE-REVIEW-SECRET");
    imdb_session_close(&a);
    imdb_session_close(&b);
    imdb_close(db);
    CHECK(wiped && disk_clean);
}

static void paths(char p[600], char r[600], char s[600])
{
    const char *base = test_tmpdir();
    snprintf(p, 600, "%s/primary", base);
    snprintf(r, 600, "%s/replica", base);
    snprintf(s, 600, "%s/stream", base);
}

static void t_review_replica_read_only(void)
{
    char p[600], r[600], s[600];
    paths(p, r, s);
    OK(imdb_init(p, false, NULL, E));
    OK(imdb_init(r, true, p, E));
    imdb_db *db = open_db(p);
    CHECK(db);
    OK(make_table(db, E));
    OK(ins1(db, 1, 42, 10, "read-only"));
    OK(ship_to_file(p, 0, s, E));
    imdb_db *rep;
    imdb_open_opts o = {.sync = 0, .read_only = true};
    OK(imdb_open(r, &o, &rep, E));
    uint64_t applied = UINT64_MAX;
    int rc = apply_file(rep, s, &applied, E);
    bool untouched = applied == 0 && rep->seq == 0 && log_segments(r) == 0;
    imdb_close(rep);
    imdb_close(db);
    CHECK(rc == IMDB_ERR_STATE && untouched);
}

static void t_review_replica_publish_after_append(void)
{
    char p[600], r[600], s[600], head[700];
    paths(p, r, s);
    OK(imdb_init(p, false, NULL, E));
    OK(imdb_init(r, true, p, E));
    imdb_db *db = open_db(p), *rep = open_db(r);
    CHECK(db && rep);
    OK(make_table(db, E));
    OK(ins1(db, 1, 7, 10, "first"));
    OK(imdb_checkpoint(db, E));
    OK(ins1(db, 2, 7, 20, "second"));
    OK(ship_to_file(p, 0, s, E));
    uint64_t applied;
    OK(apply_file(rep, s, &applied, E));
    uint64_t durable = rep->seq;
    snprintf(head, sizeof head, "%s/LAKE_HEAD", r);
    size_t before_n, after_n;
    uint8_t *before = slurp(head, &before_n);
    CHECK(before);
    int before_files = count_files(r, ".seg");
    OK(imdb_checkpoint(db, E));
    OK(ship_to_file(p, durable, s, E));
    /* A complete validated CHECKPOINT, but appending its log frame fails. */
    close(rep->logfd);
    rep->logfd = open(seg_path(r, -1), O_RDONLY | O_CLOEXEC);
    CHECK(rep->logfd >= 0);
    int rc = apply_file(rep, s, &applied, E);
    uint8_t *after = slurp(head, &after_n);
    bool unchanged = after && before_n == after_n && !memcmp(before, after, before_n) &&
                     count_files(r, ".seg") == before_files;
    free(before);
    free(after);
    imdb_close(rep);
    rep = open_db(r);
    bool recovered = rep && rep->seq == durable;
    imdb_close(rep);
    imdb_close(db);
    CHECK(rc == IMDB_ERR_IO && unchanged && recovered);
}

static void t_review_redaction_temp_recovery(void)
{
    imdb_session a, b;
    imdb_db *db = sessions(&a, &b);
    CHECK(db);
    char dir[600], tmp[800];
    snprintf(dir, sizeof dir, "%s", db->path);
    snprintf(tmp, sizeof tmp, "%s.tmp", seg_path(dir, -1));
    uint64_t seq = db->seq;
    imdb_close(db);
    spit(tmp, (const uint8_t *)"interrupted redaction", 21);
    db = open_db(dir);
    bool recovered = db && db->seq == seq && access(tmp, F_OK) != 0;
    imdb_close(db);
    CHECK(recovered);
}

static void t_review_checkpoint_committed_warning(void)
{
    imdb_session a, b;
    imdb_db *db = sessions(&a, &b);
    CHECK(db);
    char dir[600], block[700];
    snprintf(dir, sizeof dir, "%s", db->path);
    snprintf(block, sizeof block, "%s/LAKE_HEAD.tmp", dir);
    CHECK(mkdir(block, 0700) == 0); /* publication fails after the log commit */
    uint64_t before = db->seq;
    int rc = run(&a, "CHECKPOINT");
    bool committed = db->seq == before + 1 && db->failed && db->warning[0];
    CHECK(rmdir(block) == 0);
    imdb_session_close(&a);
    imdb_session_close(&b);
    imdb_close(db);
    db = open_db(dir);
    bool recovered = db && db->seq == before + 1;
    imdb_verify_report vr;
    if (db) recovered &= imdb_verify(db, &vr, E) == IMDB_OK;
    imdb_close(db);
    CHECK(rc == IMDB_OK && committed && recovered);
}

static void t_review_erase_gc_failure(void)
{
    imdb_session a, b;
    imdb_db *db = sessions(&a, &b);
    CHECK(db);
    OK(run(&a, "CHECKPOINT"));
    char dir[600], block[700];
    snprintf(dir, sizeof dir, "%s", db->path);
    snprintf(block, sizeof block, "%s/objects/gc-obstruction", dir);
    CHECK(mkdir(block, 0700) == 0); /* unlinkat must fail, not report complete erasure */
    imdb_value subject = {.type = IMDB_T_INT64, .i = 42};
    imdb_erase_report er;
    OK(imdb_erase_subject(db, &subject, &er, E));
    /* the ERASE committed and its lake is published; only the cleanup is pending */
    bool pending = er.redaction_pending && !db->lake_pending && db->gc_pending && db->lake_seq == db->seq &&
                   strstr(db->warning, "old objects");
    /* GC removed everything else despite the failure: the erased rows are gone from the files */
    bool removed = !tree_contains(dir, "ERASE-REVIEW-SECRET");
    imdb_session_close(&a);
    imdb_session_close(&b);
    imdb_close(db);
    /* a foreign undeletable entry never makes the database unopenable */
    db = open_db(dir);
    CHECK(db && db->gc_pending && strstr(db->warning, "old objects"));
    imdb_verify_report vr;
    imdb_err_clear(E);
    CHECK(imdb_verify(db, &vr, E) == IMDB_ERR_VERIFY && strstr(E->msg, "objects/"));
    imdb_close(db);
    CHECK(rmdir(block) == 0);
    db = open_db(dir); /* the retry at open now succeeds */
    CHECK(db && !db->gc_pending);
    OK(imdb_verify(db, &vr, E));
    imdb_close(db);
    CHECK(pending && removed);
}

static void t_review_corrupt_complete_tail(void)
{
    imdb_log_set_tagged(false); /* the untagged format's tail, byte by byte (the tagged one: t_tseg) */
    imdb_session a, b;
    imdb_db *db = sessions(&a, &b);
    CHECK(db);
    char dir[600], lp[700];
    snprintf(dir, sizeof dir, "%s", db->path);
    snprintf(lp, sizeof lp, "%s", seg_path(dir, -1));
    imdb_session_close(&a);
    imdb_session_close(&b);
    imdb_close(db);
    size_t n;
    uint8_t *bytes = slurp(lp, &n);
    CHECK(bytes && n > 0);
    bytes[n - 1] ^= 1; /* corruption in a full, previously committed final frame */
    spit(lp, bytes, n);
    free(bytes);
    imdb_open_opts o = {.sync = 0};
    int rc = imdb_open(dir, &o, &db, E);
    imdb_close(db);
    CHECK(rc == IMDB_ERR_CORRUPT && file_size(lp) == (long)n);
}

static void t_review_partial_redaction_quarantine(void)
{
    char p[600], r[600], s[600];
    paths(p, r, s);
    OK(imdb_init(p, false, NULL, E));
    OK(imdb_init(r, true, p, E));
    imdb_db *db = open_db(p), *rep = open_db(r);
    CHECK(db && rep);
    OK(make_table(db, E));
    OK(ins1(db, 1, 42, 10, "redact-me"));
    OK(ins1(db, 2, 7, 20, "keep"));
    OK(imdb_checkpoint(db, E));
    uint64_t stop = db->seq;
    imdb_value subject = {.type = IMDB_T_INT64, .i = 42};
    imdb_erase_report er;
    OK(imdb_erase_subject(db, &subject, &er, E));
    OK(ship_to_file(p, 0, s, E));
    size_t n, off = 0;
    uint8_t *bytes = slurp(s, &n);
    CHECK(bytes);
    while (off < n && imdb_frame_seq(bytes + off) <= stop) off += 16 + imdb_get_le32(bytes + off + 4);
    spit(s, bytes, off);
    free(bytes);
    uint64_t applied;
    int rc = apply_file(rep, s, &applied, E);
    imdb_session q;
    imdb_session_init(&q, rep);
    int read_rc = run(&q, "SELECT COUNT(*) FROM txns");
    bool blocked = rc == IMDB_ERR_AUTH && read_rc == IMDB_ERR_STATE && rep->pending_auth > 0;
    imdb_err_clear(E);
    blocked &= imdb_check_history(rep, rep->t[0], rep->seq, E) == IMDB_ERR_STATE;
    imdb_session_close(&q);
    imdb_close(rep);
    rep = open_db(r);
    CHECK(rep);
    imdb_session_init(&q, rep);
    blocked &= run(&q, "SELECT COUNT(*) FROM txns") == IMDB_ERR_STATE;
    /* Resuming is allowed; the authorising ERASE makes the state usable. */
    OK(ship_to_file(p, rep->seq, s, E));
    OK(apply_file(rep, s, &applied, E));
    bool resumed = rep->pending_auth == 0 && !rep->lake_unverified && cell(&q, "SELECT COUNT(*) FROM txns") == 1;
    imdb_session_close(&q);
    imdb_close(rep);
    imdb_close(db);
    CHECK(blocked && resumed);
}

static void t_review_history_index_authentication(void)
{
    imdb_session a, b;
    imdb_db *db = sessions(&a, &b);
    CHECK(db);
    OK(run(&a, "CHECKPOINT"));
    char dir[600], lp[700];
    snprintf(dir, sizeof dir, "%s", db->path);
    snprintf(lp, sizeof lp, "%s", seg_path(dir, 0));
    imdb_session_close(&a);
    imdb_session_close(&b);
    imdb_close(db);
    size_t n;
    uint64_t first;
    bool tg;
    uint8_t *bytes = seg_frames(lp, &n, &first, &tg); /* frames, either format */
    CHECK(bytes);
    /* Change an older timestamp, repair the unsigned framing and descriptor
     * hash, but do not possess or use the signing key. Snapshot open may skip
     * this old record; AS OF time must authenticate it before trusting it. */
    uint8_t *body = bytes + IMDB_FRAME_HDR;
    uint32_t blen = imdb_get_le32(bytes + 4), hlen = imdb_get_le32(body + 1);
    uint8_t *header = body + IMDB_BODY_DESC;
    header[10] ^= 1;
    imdb_commit_hash(header, hlen, body + 13);
    imdb_le32(bytes + 8, imdb_kern()->crc32c(0, body, blen));
    imdb_le32(bytes + 12, imdb_kern()->crc32c(0, bytes, 12));
    seg_put_frames(lp, first, tg, bytes, n);
    free(bytes);
    db = open_db(dir);
    CHECK(db && db->snapshot_seq > 0);
    imdb_err_clear(E);
    const imdb_commit_info *ci = imdb_ci_at(db, 1, E);
    bool rejected = ci == NULL && E->code == IMDB_ERR_AUTH;
    imdb_close(db);
    CHECK(rejected);
}

/* A doomed transaction holds nothing: neither pending versions in the store nor
 * saved row copies (it can only roll back; ERASE should not be needed to free them). */
static void t_review_doomed_discards(void)
{
    imdb_session a, b;
    imdb_db *db = sessions(&a, &b);
    CHECK(db);
    OK(run(&a, "BEGIN"));
    OK(run(&a, "UPDATE t SET s = 'DOOMED-PENDING-MARK' WHERE id = 1"));
    OK(run(&b, "UPDATE t SET v = 21 WHERE id = 2")); /* parks a: its row is copied out */
    CHECK(run(&a, "UPDATE t SET v = 22 WHERE id = 2") == IMDB_ERR_CONFLICT);
    imdb_table *t = imdb_table_by_name(db, "t");
    bool empty = a.txn.doomed && a.txn.ops == NULL && a.txn.nops == 0 && db->active != &a.txn && !db->in_txn &&
                 t && !mem_contains(t->arena.p, t->arena.cap, "DOOMED-PENDING-MARK");
    /* still doomed: every statement but ROLLBACK refuses, COMMIT rolls back */
    bool refused = run(&a, "SELECT id FROM t") == IMDB_ERR_CONFLICT && run(&a, "COMMIT") == IMDB_ERR_CONFLICT &&
                   !a.txn.open;
    bool intact = cell(&b, "SELECT COUNT(*) FROM t WHERE s = 'DOOMED-PENDING-MARK'") == 0 &&
                  cell(&b, "SELECT v FROM t WHERE id = 2") == 21;
    imdb_session_close(&a);
    imdb_session_close(&b);
    imdb_close(db);
    CHECK(empty && refused && intact);
}

/* The C API is public too: a NULL value never stands for a key (its unused bytes
 * are 0 here, so a lookup would otherwise find, or ERASE erase, subject 0). */
static void t_review_null_keys_c_api(void)
{
    const char *dir = test_tmpdir();
    OK(imdb_init(dir, false, NULL, E));
    imdb_db *db = open_db(dir);
    CHECK(db);
    OK(make_table(db, E));
    OK(ins1(db, 0, 0, 5, "subject-zero"));
    imdb_table *t = db->t[0];
    imdb_value nk = {.type = IMDB_T_INT64, .null = true};
    bool none = imdb_lookup_pk(db, t, &nk, db->seq) == IMDB_NONE && imdb_subject_versions(t, &nk) == NULL;
    imdb_erase_report er;
    imdb_err_clear(E);
    bool refused = imdb_erase_subject(db, &nk, &er, E) == IMDB_ERR_INVALID;
    bool kept = count_subject(db, 0, db->seq) == 1 && pk_lookup(db, 0, db->seq) != IMDB_NONE;
    imdb_close(db);
    CHECK(none && refused && kept);
}

/* ---- the durable watermark (DURABLE, log.h) ---------------------------------------- */

static int read_dur(const char *dir, imdb_durable *w, bool *present)
{
    int dfd = open(dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    imdb_err_clear(E);
    int rc = dfd < 0 ? IMDB_ERR_IO : imdb_durable_read(dfd, w, present, E);
    if (dfd >= 0) close(dfd);
    return rc;
}

static size_t count_frames(const char *file)
{
    size_t n, k = 0, off = 0, fl;
    uint8_t *b = slurp(file, &n);
    imdb_err e = {0};
    while (b && imdb_frame_scan(b, n, off, &fl, &e) == IMDB_SCAN_FRAME) {
        off += fl;
        k++;
    }
    free(b);
    return k;
}

/* Five commits (CREATE + four INSERTs) in one segment; *head4 = the hash of commit 4 and
 * *before5 = the log size before commit 5. */
static imdb_db *five_commits(const char *dir, uint8_t head4[32], long *before5)
{
    if (imdb_init(dir, false, NULL, E)) return NULL;
    imdb_db *db = open_db(dir);
    if (!db || make_table(db, E)) return db;
    for (int i = 1; i <= 4; i++) {
        if (ins1(db, i, 42, i, "row")) return db;
        if (i == 3) {
            memcpy(head4, db->head, 32);
            *before5 = (long)db->log_size;
        }
    }
    return db;
}

static void t_review_durable_tracks_commits(void)
{
    char p[600], r[600], s[600];
    paths(p, r, s);
    OK(imdb_init(p, false, NULL, E));
    OK(imdb_init(r, true, p, E));
    imdb_durable w;
    bool present;
    OK(read_dur(p, &w, &present));
    CHECK(present && w.seq == 0 && w.synced); /* init: nothing acknowledged */
    imdb_db *db = open_db(p); /* sync = 0 */
    CHECK(db);
    OK(make_table(db, E));
    bool tracks = true;
    for (int i = 1; i <= 3; i++) {
        OK(ins1(db, i, 42, i, "row"));
        tracks &= db->have_dur && db->dur.seq == db->seq && !memcmp(db->dur.head, db->head, 32) && !db->dur.synced;
    }
    uint64_t seq = db->seq;
    imdb_close(db);
    OK(read_dur(p, &w, &present)); /* a clean close syncs --nosync commits, and says so */
    CHECK(tracks && present && w.seq == seq && w.synced);
    imdb_open_opts so = {.sync = 1};
    OK(imdb_open(p, &so, &db, E));
    OK(ins1(db, 4, 42, 4, "synced"));
    CHECK(db->dur.seq == db->seq && db->dur.synced);
    imdb_close(db);
    /* a replica's watermark advances with apply */
    imdb_db *rep = open_db(r);
    CHECK(rep);
    OK(ship_to_file(p, 0, s, E));
    uint64_t applied;
    OK(apply_file(rep, s, &applied, E));
    CHECK(applied == seq + 1 && rep->dur.seq == rep->seq);
    imdb_close(rep);
    OK(read_dur(r, &w, &present));
    CHECK(present && w.seq == seq + 1 && w.synced);
}

static void t_review_durable_acked_loss(void)
{
    imdb_log_set_tagged(false); /* the untagged format's tail, byte by byte (the tagged one: t_tseg) */
    const char *dir = test_tmpdir();
    uint8_t head4[32];
    long before_last;
    imdb_db *db = five_commits(dir, head4, &before_last);
    CHECK(db && db->seq == 5);
    imdb_close(db);
    char lp[700];
    snprintf(lp, sizeof lp, "%s", seg_path(dir, -1));
    size_t n;
    uint8_t *orig = slurp(lp, &n);
    CHECK(orig);
    /* commit 5 vanished at a frame boundary: no torn bytes, yet it was acknowledged */
    spit(lp, orig, (size_t)before_last);
    imdb_open_opts o = {.sync = 0};
    imdb_err_clear(E);
    CHECK(imdb_open(dir, &o, &db, E) == IMDB_ERR_CORRUPT && strstr(E->msg, "acknowledged as durable"));
    imdb_open_opts ro = {.sync = 0, .read_only = true};
    imdb_err_clear(E);
    CHECK(imdb_open(dir, &ro, &db, E) == IMDB_ERR_CORRUPT);
    CHECK(file_size(lp) == before_last);
    /* recover: nothing to cut and nothing to save, only the watermark comes down */
    imdb_recover_report rr;
    OK(imdb_recover_tail(dir, false, NULL, &rr, E));
    CHECK(!rr.damaged && rr.acked_lost && rr.last == 4 && rr.durable == 5 && !rr.applied);
    OK(imdb_recover_tail(dir, true, NULL, &rr, E));
    CHECK(rr.applied);
    db = open_db(dir);
    CHECK(db && db->seq == 4 && db->dur.seq == 4 && !memcmp(db->dur.head, head4, 32));
    imdb_close(db);
    /* a commit lost under --nosync is not damage, but it is never silent */
    durable_set(dir, 6, head4, false);
    db = open_db(dir);
    CHECK(db && db->seq == 4 && strstr(db->warning, "--nosync"));
    imdb_close(db);
    free(orig);
}

static void t_review_durable_foreign(void)
{
    char a[600], b[600];
    snprintf(a, sizeof a, "%s/a", test_tmpdir());
    snprintf(b, sizeof b, "%s/b", test_tmpdir());
    uint8_t h[32];
    long l;
    imdb_db *da = five_commits(a, h, &l), *dbb = five_commits(b, h, &l);
    CHECK(da && dbb && da->seq == dbb->seq);
    imdb_close(da);
    imdb_close(dbb);
    char pa[700], pb[700];
    snprintf(pa, sizeof pa, "%s/DURABLE", a);
    snprintf(pb, sizeof pb, "%s/DURABLE", b);
    size_t n;
    uint8_t *w = slurp(pb, &n);
    CHECK(w);
    spit(pa, w, n); /* another database's watermark, at the same commit number */
    free(w);
    imdb_open_opts o = {.sync = 0};
    imdb_err_clear(E);
    CHECK(imdb_open(a, &o, &da, E) == IMDB_ERR_CORRUPT && strstr(E->msg, "different history"));
}

static void t_review_durable_absent(void)
{
    imdb_log_set_tagged(false); /* the untagged format's tail, byte by byte (the tagged one: t_tseg) */
    const char *dir = test_tmpdir();
    uint8_t head4[32];
    long before_last;
    imdb_db *db = five_commits(dir, head4, &before_last);
    CHECK(db);
    long full;
    imdb_close(db);
    char lp[700], dp[700];
    snprintf(lp, sizeof lp, "%s", seg_path(dir, -1));
    snprintf(dp, sizeof dp, "%s/DURABLE", dir);
    size_t n;
    uint8_t *orig = slurp(lp, &n);
    CHECK(orig);
    full = (long)n;
    /* without a watermark a damaged complete final frame cannot be told from damage */
    CHECK(unlink(dp) == 0);
    uint8_t *c = malloc(n);
    memcpy(c, orig, n);
    c[n - 1] ^= 1;
    spit(lp, c, n);
    imdb_open_opts o = {.sync = 0};
    imdb_err_clear(E);
    CHECK(imdb_open(dir, &o, &db, E) == IMDB_ERR_CORRUPT && strstr(E->msg, "no DURABLE watermark"));
    CHECK(file_size(lp) == full);
    /* an incomplete one is an unfinished append either way */
    spit(lp, orig, (size_t)(full - 3));
    db = open_db(dir);
    CHECK(db && db->seq == 4 && file_size(lp) == before_last && db->warning[0]);
    imdb_close(db);
    imdb_durable w;
    bool present;
    OK(read_dur(dir, &w, &present)); /* the writable open published a new one */
    CHECK(present && w.seq == 4 && w.synced && !memcmp(w.head, head4, 32));
    free(orig);
    free(c);
}

static void t_review_ship_bound(void)
{
    imdb_log_set_tagged(false); /* the untagged format's tail, byte by byte (the tagged one: t_tseg) */
    char p[600], r[600], s[600];
    paths(p, r, s);
    uint8_t head4[32];
    long l;
    imdb_db *db = five_commits(p, head4, &l);
    CHECK(db);
    uint8_t head5[32];
    memcpy(head5, db->head, 32);
    imdb_close(db);
    OK(ship_to_file(p, 0, s, E));
    CHECK(count_frames(s) == 5);
    durable_set(p, 4, head4, true); /* commit 5 written, its fdatasync not yet returned */
    OK(ship_to_file(p, 0, s, E));
    CHECK(count_frames(s) == 4);
    OK(ship_to_file(p, 4, s, E));
    CHECK(count_frames(s) == 0);
    /* damage inside the durable range is never "mid-append" */
    char lp[700];
    snprintf(lp, sizeof lp, "%s", seg_path(p, -1));
    size_t n;
    uint8_t *b = slurp(lp, &n);
    CHECK(b);
    b[n - 1] ^= 1;
    spit(lp, b, n);
    OK(ship_to_file(p, 0, s, E)); /* commit 5's damage is past the watermark: held back */
    CHECK(count_frames(s) == 4);
    durable_set(p, 5, head5, true);
    imdb_err_clear(E);
    CHECK(ship_to_file(p, 0, s, E) == IMDB_ERR_CORRUPT && strstr(E->msg, "acknowledged as durable"));
    free(b);
    /* a directory with no watermark ships nothing */
    char dp[700];
    snprintf(dp, sizeof dp, "%s/DURABLE", p);
    CHECK(unlink(dp) == 0);
    imdb_err_clear(E);
    CHECK(ship_to_file(p, 0, s, E) == IMDB_ERR_STATE);
}

/* A lake published at a commit the log no longer holds (an older writer published under
 * --nosync before LAKE_HEAD waited for the log, then an OS crash took the frame). With an
 * unsynced watermark that is the loss --nosync accepts: open warns and rebuilds the lake from
 * the log. With a synced watermark the commit was durable: refused, and recover drops the lake. */
static void lake_ahead_state(const char *p, bool synced_watermark)
{
    OK(imdb_init(p, false, NULL, E));
    imdb_db *db = open_db(p);
    CHECK(db);
    OK(make_table(db, E));
    OK(ins1(db, 1, 42, 100, "ahead"));
    uint64_t before = db->seq;
    uint8_t head[32];
    memcpy(head, db->head, 32);
    char seg[700];
    snprintf(seg, sizeof seg, "%s", seg_path(p, 0));
    uint64_t first;
    bool tg;
    size_t cut = 0, n = 0;
    free(seg_frames(seg, &cut, &first, &tg)); /* the frames before the CHECKPOINT */
    OK(imdb_checkpoint(db, E)); /* LAKE_HEAD names commit before + 1 */
    imdb_close(db);
    uint8_t *fr = seg_frames(seg, &n, &first, &tg);
    CHECK(fr && n > cut);
    seg_put_frames(seg, first, tg, fr, cut); /* the CHECKPOINT's frame never landed */
    free(fr);
    durable_set(p, before, head, synced_watermark);
}

static bool objects_empty(const char *p)
{
    return count_files(path_join(p, "objects"), "") == 0;
}

static void t_review_lake_ahead_of_log(void)
{
    const char *dir = test_tmpdir();
    char p[600], q[600], saved[600];
    snprintf(p, sizeof p, "%s/p", dir);
    snprintf(q, sizeof q, "%s/q", dir);
    snprintf(saved, sizeof saved, "%s/saved", dir);
    lake_ahead_state(p, false);
    CHECK(file_size(path_join(p, "LAKE_HEAD")) > 0);
    imdb_db *db = open_db(p);
    CHECK(db);
    CHECK(strstr(db->warning, "ahead of the log"));
    CHECK(db->seq == 2 && db->lake_seq == 0);
    CHECK(file_size(path_join(p, "LAKE_HEAD")) < 0 && objects_empty(p)); /* nothing claims the lost commit */
    imdb_verify_report vr;
    OK(imdb_verify(db, &vr, E));
    imdb_close(db);

    lake_ahead_state(q, true);
    imdb_open_opts o = {.sync = 1};
    imdb_err_clear(E);
    CHECK(imdb_open(q, &o, &db, E) == IMDB_ERR_CORRUPT && strstr(g_e.msg, "past the end of the log"));
    o.read_only = true;
    imdb_err_clear(E);
    CHECK(imdb_open(q, &o, &db, E) == IMDB_ERR_CORRUPT);
    imdb_recover_report r;
    OK(imdb_recover_tail(q, false, NULL, &r, E));
    CHECK(r.lake_ahead && r.lake_seq == 3 && !r.applied);
    OK(imdb_recover_tail(q, true, saved, &r, E));
    CHECK(r.applied && file_size(path_join(q, "LAKE_HEAD")) < 0);
    db = open_db(q); /* the writable open rebuilds the lake from the log: here, none */
    CHECK(db);
    CHECK(objects_empty(q));
    OK(imdb_verify(db, &vr, E));
    imdb_close(db);
}

/* R1: a SELECT names its read point: the commit, its hash and recorded digest (from the commit
 * index, also below the snapshot an open started from), the database and the lake then. */
static void t_review_read_point(void)
{
    imdb_session a, b;
    imdb_db *db = sessions(&a, &b);
    CHECK(db);
    CHECK(run(&a, "CHECKPOINT") == 0);
    CHECK(run(&a, "INSERT INTO t VALUES (3, 42, 5, 'x')") == 0);
    imdb_result r;
    const char *sel = "SELECT COUNT(*) FROM t WHERE u = 42";
    CHECK(imdb_exec_one(&a, sel, strlen(sel), NULL, 0, &r, E) == 0);
    const imdb_commit_info *ci = imdb_ci_at(db, db->seq, E);
    CHECK(r.has_snap && r.snap == db->seq && ci && memcmp(r.head, ci->hash, 32) == 0 && memcmp(r.digest, ci->digest, 32) == 0);
    CHECK(memcmp(r.db_id, db->db_id, 16) == 0 && r.lake_seq == db->lake_seq && r.lake_seq < r.snap);
    imdb_result_free(&r);
    char q[120];
    snprintf(q, sizeof q, "SELECT COUNT(*) FROM t AS OF 1");
    CHECK(imdb_exec_one(&a, q, strlen(q), NULL, 0, &r, E) == 0);
    ci = imdb_ci_at(db, 1, E);
    CHECK(r.snap == 1 && ci && memcmp(r.head, ci->hash, 32) == 0);
    imdb_result_free(&r);
    /* min_commit: reads refuse a database not yet at the commit a session needs */
    CHECK(run(&a, "SET min_commit = 1000") == 0);
    CHECK(run(&a, sel) == IMDB_ERR_STATE && strstr(g_e.msg, "requires commit 1000"));
    CHECK(run(&a, "SET min_commit = 0") == 0 && run(&a, sel) == 0);
    CHECK(run(&a, "SET min_commit = -1") != 0);
    imdb_session_close(&a);
    imdb_session_close(&b);
    imdb_close(db);
}

/* R5: the view token changes with every commit, schema change and history horizon, and is
 * what a reopened copy (and the auditor, tests/integration/run.sh) computes again. */
static void t_review_view_token(void)
{
    const char *dir = test_tmpdir();
    OK(imdb_init(dir, false, NULL, E));
    imdb_db *db = open_db(dir);
    CHECK(db);
    uint8_t t0[32], t1[32], t2[32], t3[32], t4[32];
    OK(imdb_view_token(db, t0, E));
    OK(make_table(db, E));
    OK(imdb_view_token(db, t1, E));
    OK(ins1(db, 1, 42, 100, "a"));
    OK(imdb_view_token(db, t2, E));
    OK(imdb_checkpoint(db, E)); /* the rows are unchanged, but the chain position moved */
    OK(imdb_view_token(db, t3, E));
    imdb_table *t = imdb_table_by_name(db, "txns");
    OK(imdb_compact(db, t, db->seq, E)); /* the horizon */
    OK(imdb_view_token(db, t4, E));
    CHECK(memcmp(t0, t1, 32) && memcmp(t1, t2, 32) && memcmp(t2, t3, 32) && memcmp(t3, t4, 32));
    imdb_close(db);
    db = open_db(dir);
    CHECK(db);
    uint8_t again[32];
    OK(imdb_view_token(db, again, E));
    CHECK(memcmp(again, t4, 32) == 0);
    imdb_close(db);
}

/* R1, priced: with lake_sync the lake is published after every commit that changed data, so the
 * lake files alone answer at the latest commit (and the log has a CHECKPOINT after each). */
static void t_review_lake_sync(void)
{
    const char *dir = test_tmpdir();
    OK(imdb_init(dir, false, NULL, E));
    imdb_open_opts o = {.sync = 0, .lake_sync = true};
    imdb_db *db = NULL;
    OK(imdb_open(dir, &o, &db, E));
    OK(make_table(db, E));
    OK(imdb_maintain(db, E));
    CHECK(db->lake_seq == db->seq);
    for (int64_t id = 1; id <= 3; id++) {
        OK(ins1(db, id, 42, 100, "a")); /* ins1 runs the maintenance step */
        CHECK(db->lake_seq == db->seq && !db->lake_dirty);
    }
    uint64_t seq = db->seq;
    OK(imdb_maintain(db, E)); /* nothing changed: no CHECKPOINT of an unchanged lake */
    CHECK(db->seq == seq);
    imdb_close(db);
}

/* R5: the external anchor. An older copy of the directory (or one that lost commits) is refused at
 * open, read-only too, unless the operator accepts the rollback; a forked history and another
 * database's anchor are refused; a damaged anchor is refused, never ignored; under --nosync the
 * anchor moves only at the sync points (a CHECKPOINT, the close). */
static int open_anchor(const char *dir, const char *anchor, bool ro, bool accept, int sync, imdb_db **db)
{
    imdb_open_opts o = {.sync = sync, .read_only = ro, .anchor = anchor, .accept_rollback = accept};
    imdb_err_clear(E);
    return imdb_open(dir, &o, db, E);
}

/* the newest record of the two (log.h) */
static uint64_t anchor_seq(const char *path)
{
    size_t n;
    uint8_t *b = slurp(path, &n);
    uint64_t s = UINT64_MAX;
    for (size_t off = 0; b && off + IMDB_ANCHOR_LEN <= n; off += IMDB_ANCHOR_SLOT) {
        imdb_anchor a;
        imdb_err e = {0};
        if (imdb_anchor_decode(b + off, IMDB_ANCHOR_LEN, &a, &e) == IMDB_OK && (s == UINT64_MAX || a.seq > s)) s = a.seq;
    }
    free(b);
    return s;
}

static void t_review_anchor(void)
{
    const char *tmp = test_tmpdir();
    char p[600], old[600], anc[600], other[600], cmd[2000];
    snprintf(p, sizeof p, "%s/p", tmp);
    snprintf(old, sizeof old, "%s/old", tmp);
    snprintf(anc, sizeof anc, "%s/anchor", tmp);
    snprintf(other, sizeof other, "%s/other", tmp);
    OK(imdb_init(p, false, NULL, E));
    imdb_db *db;
    OK(open_anchor(p, anc, false, false, 1, &db));
    OK(make_table(db, E));
    OK(ins1(db, 1, 42, 100, "a"));
    CHECK(anchor_seq(anc) == db->seq); /* every durable commit moves it */
    imdb_close(db);
    snprintf(cmd, sizeof cmd, "cp -a '%s' '%s'", p, old);
    CHECK(system(cmd) == 0);
    OK(open_anchor(p, anc, false, false, 1, &db));
    OK(ins1(db, 2, 42, 100, "b"));
    OK(ins1(db, 3, 42, 100, "c"));
    uint64_t newest = db->seq;
    imdb_close(db);
    CHECK(open_anchor(old, anc, false, false, 1, &db) == IMDB_ERR_CORRUPT && strstr(g_e.msg, "older copy"));
    CHECK(open_anchor(old, anc, true, false, 0, &db) == IMDB_ERR_CORRUPT);
    CHECK(anchor_seq(anc) == newest); /* a refused open leaves it alone */
    OK(open_anchor(p, anc, true, false, 0, &db)); /* the newer copy, read-only: checked, not moved */
    imdb_close(db);
    /* the operator's decision: continue from the older copy; the anchor follows, and the newer copy is
     * then a different history once the older one has a commit of its own */
    OK(open_anchor(old, anc, false, true, 1, &db));
    CHECK(strstr(db->warning, "rolled back") && anchor_seq(anc) == db->seq);
    OK(ins1(db, 9, 7, 100, "fork"));
    imdb_close(db);
    CHECK(open_anchor(p, anc, false, false, 1, &db) == IMDB_ERR_CORRUPT && strstr(g_e.msg, "different history"));
    /* accepting a rollback does not excuse another history */
    CHECK(open_anchor(p, anc, false, true, 1, &db) == IMDB_ERR_CORRUPT && strstr(g_e.msg, "different history"));
    /* another database's anchor */
    OK(imdb_init(other, false, NULL, E));
    CHECK(open_anchor(other, anc, false, false, 1, &db) == IMDB_ERR_CORRUPT && strstr(g_e.msg, "another database"));
    /* one damaged record: the other one is the anchor (a torn rewrite); both damaged: refused */
    size_t n;
    uint8_t *b = slurp(anc, &n);
    CHECK(b && n == IMDB_ANCHOR_FILE);
    b[40] ^= 1;
    spit(anc, b, n);
    OK(open_anchor(old, anc, true, false, 0, &db));
    imdb_close(db);
    b[IMDB_ANCHOR_SLOT + 40] ^= 1;
    spit(anc, b, n);
    free(b);
    CHECK(open_anchor(old, anc, false, false, 1, &db) == IMDB_ERR_CORRUPT && strstr(g_e.msg, "damaged"));
    /* --nosync: only the sync points move it */
    unlink(anc);
    OK(open_anchor(old, anc, false, false, 0, &db));
    uint64_t at = db->seq;
    OK(ins1(db, 10, 7, 100, "n"));
    OK(ins1(db, 11, 7, 100, "n"));
    CHECK(anchor_seq(anc) == at);
    OK(imdb_checkpoint(db, E));
    CHECK(anchor_seq(anc) == db->seq);
    OK(ins1(db, 12, 7, 100, "n"));
    CHECK(anchor_seq(anc) == db->seq - 1);
    uint64_t last = db->seq;
    CHECK(imdb_close(db) == IMDB_OK);
    CHECK(anchor_seq(anc) == last);
}

const test_case review_tests[] = {
    {"review_null_parameters", t_review_null_parameters},
    {"review_lock_own_writes", t_review_lock_own_writes},
    {"review_lock_uncommitted_competitor", t_review_lock_uncommitted_competitor},
    {"review_erasure_doomed_transaction", t_review_erasure_doomed_transaction},
    {"review_replica_read_only", t_review_replica_read_only},
    {"review_replica_publish_after_append", t_review_replica_publish_after_append},
    {"review_redaction_temp_recovery", t_review_redaction_temp_recovery},
    {"review_checkpoint_committed_warning", t_review_checkpoint_committed_warning},
    {"review_erase_gc_failure", t_review_erase_gc_failure},
    {"review_corrupt_complete_tail", t_review_corrupt_complete_tail},
    {"review_partial_redaction_quarantine", t_review_partial_redaction_quarantine},
    {"review_history_index_authentication", t_review_history_index_authentication},
    {"review_doomed_discards", t_review_doomed_discards},
    {"review_null_keys_c_api", t_review_null_keys_c_api},
    {"review_durable_tracks_commits", t_review_durable_tracks_commits},
    {"review_durable_acked_loss", t_review_durable_acked_loss},
    {"review_durable_foreign", t_review_durable_foreign},
    {"review_durable_absent", t_review_durable_absent},
    {"review_ship_bound", t_review_ship_bound},
    {"review_lake_ahead_of_log", t_review_lake_ahead_of_log},
    {"review_read_point", t_review_read_point},
    {"review_view_token", t_review_view_token},
    {"review_lake_sync", t_review_lake_sync},
    {"review_anchor", t_review_anchor},
};
const size_t review_ntests = sizeof review_tests / sizeof *review_tests;
