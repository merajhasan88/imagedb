/* Lake tests: segments, deletion vectors, manifests, compaction, erasure in
 * segments, physical exactness of replicas (built in another process), tamper. */
#include <dirent.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include "../../src/fsio.h"
#include "../../src/lake.h"
#include "thelp.h"

static uint64_t lookup_cents(imdb_db *db, int64_t id, uint64_t snap)
{
    imdb_table *t = imdb_table_by_name(db, "txns");
    uint64_t vid = pk_lookup(db, id, snap);
    if (vid == IMDB_NONE) return UINT64_MAX;
    imdb_value v[4];
    imdb_err e = {0};
    if (imdb_version_values(db, t, vid, v, &e)) return UINT64_MAX - 1;
    return (uint64_t)v[2].i;
}

static void t_checkpoint_basic(void)
{
    const char *dir = test_tmpdir();
    OK(imdb_init(dir, false, NULL, E));
    imdb_db *db = open_db(dir);
    CHECK(db);
    OK(make_table(db, E));
    for (int i = 1; i <= 100; i++) OK(ins1(db, i, i % 7, i * 3, i % 2 ? "odd" : "even"));
    uint8_t d0[32];
    imdb_state_digest(db, NULL, d0);
    OK(imdb_checkpoint(db, E));
    uint8_t d1[32];
    imdb_state_digest(db, NULL, d1);
    CHECK(memcmp(d0, d1, 32) == 0); /* physical work never changes the logical digest */
    imdb_table *t = imdb_table_by_name(db, "txns");
    CHECK(t->nseg == 1 && t->mem_first == t->nver && (imdb_vh(t, 5)->flags & IMDB_V_SEG));
    CHECK(lookup_cents(db, 42, db->seq) == 126);
    CHECK(count_subject(db, 3, db->seq) == 14);
    char *objs = path_join(dir, "objects");
    CHECK(count_files(objs, ".seg") == 1 && count_files(objs, ".man") == 1 && count_files(objs, ".dv") == 0);
    CHECK(file_size(path_join(dir, "LAKE_HEAD")) > 0);
    /* nothing new: checkpoint is a no-op (no commit) */
    uint64_t seq = db->seq;
    OK(imdb_checkpoint(db, E));
    CHECK(db->seq == seq);
    imdb_verify_report vr;
    OK(imdb_verify(db, &vr, E));
    CHECK(vr.segments_checked == 1 && vr.lake_rows_checked == 100);
    imdb_close(db);
    /* reopen rebuilds the lake from the log; files must be byte-identical */
    size_t n1, n2;
    uint8_t *m1 = slurp(path_join(dir, "LAKE_HEAD"), &n1);
    db = open_db(dir);
    CHECK(db);
    uint8_t *m2 = slurp(path_join(dir, "LAKE_HEAD"), &n2);
    CHECK(m1 && m2 && n1 == n2 && memcmp(m1, m2, n1) == 0);
    CHECK(lookup_cents(db, 42, db->seq) == 126);
    OK(imdb_verify(db, &vr, E));
    imdb_close(db);
    free(m1);
    free(m2);
}

static void t_deletion_vectors_time_travel(void)
{
    const char *dir = test_tmpdir();
    OK(imdb_init(dir, false, NULL, E));
    imdb_db *db = open_db(dir);
    CHECK(db);
    OK(make_table(db, E));
    imdb_table *t = imdb_table_by_name(db, "txns");
    for (int i = 1; i <= 50; i++) OK(ins1(db, i, 1, i, "row"));
    OK(imdb_checkpoint(db, E));
    uint64_t s_full = db->seq;
    for (int i = 1; i <= 10; i++) {
        OK(imdb_begin(db, E));
        OK(imdb_delete(db, t, pk_lookup(db, i, imdb_read_snapshot(db)), E));
        OK(imdb_commit(db, E));
    }
    imdb_value v[4];
    row_vals(v, 20, 1, 999, "updated");
    OK(imdb_begin(db, E));
    OK(imdb_update(db, t, pk_lookup(db, 20, imdb_read_snapshot(db)), v, E));
    OK(imdb_commit(db, E));
    OK(imdb_checkpoint(db, E));
    char *objs = path_join(dir, "objects");
    CHECK(count_files(objs, ".dv") >= 1);
    CHECK(count_subject(db, 1, db->seq) == 40);
    CHECK(count_subject(db, 1, s_full) == 50);    /* time travel through the DV */
    CHECK(lookup_cents(db, 20, s_full) == 20 && lookup_cents(db, 20, db->seq) == 999);
    CHECK(lookup_cents(db, 5, s_full) == 5 && lookup_cents(db, 5, db->seq) == UINT64_MAX);
    imdb_verify_report vr;
    OK(imdb_verify(db, &vr, E));
    /* more deletes after the checkpoint stay correct across reopen */
    OK(imdb_begin(db, E));
    OK(imdb_delete(db, t, pk_lookup(db, 30, imdb_read_snapshot(db)), E));
    OK(imdb_commit(db, E));
    imdb_close(db);
    db = open_db(dir);
    CHECK(db && count_subject(db, 1, db->seq) == 39 && count_subject(db, 1, s_full) == 50);
    OK(imdb_verify(db, &vr, E));
    imdb_close(db);
}

static void t_compact_purge_horizon(void)
{
    const char *dir = test_tmpdir();
    OK(imdb_init(dir, false, NULL, E));
    imdb_db *db = open_db(dir);
    CHECK(db);
    OK(make_table(db, E));
    imdb_table *t = imdb_table_by_name(db, "txns");
    for (int i = 1; i <= 30; i++) OK(ins1(db, i, 1, i, "v1"));
    OK(imdb_checkpoint(db, E));
    uint64_t s_before = db->seq;
    for (int i = 1; i <= 30; i += 2) {
        imdb_value v[4];
        row_vals(v, i, 1, i * 100, "v2");
        OK(imdb_begin(db, E));
        OK(imdb_update(db, t, pk_lookup(db, i, imdb_read_snapshot(db)), v, E));
        OK(imdb_commit(db, E));
    }
    OK(imdb_checkpoint(db, E));
    uint64_t s_after = db->seq;
    CHECK(t->nseg == 2);
    uint8_t d0[32];
    imdb_state_digest(db, NULL, d0);
    OK(imdb_compact(db, t, s_after, E));
    CHECK(t->nseg == 1 && t->horizon == s_after);
    uint8_t d1[32];
    imdb_state_digest(db, NULL, d1);
    CHECK(memcmp(d0, d1, 32) == 0);
    /* purged history is an error, never a partial answer */
    imdb_err_clear(E);
    CHECK(imdb_check_history(db, t, s_before, E) == IMDB_ERR_HISTORY);
    imdb_err_clear(E);
    CHECK(imdb_check_history(db, t, s_after, E) == 0);
    CHECK(lookup_cents(db, 1, db->seq) == 100 && lookup_cents(db, 2, db->seq) == 2);
    /* the 15 old versions are purged to tombstones: vid, begin, commitment and the
     * subject only, so ERASE SUBJECT still finds them (their payloads stay in the log) */
    CHECK(t->seg[0]->nrows == 45);
    uint32_t tomb = 0;
    for (uint32_t i = 0; i < t->seg[0]->nrows; i++) {
        if (t->seg[0]->flags[i] != IMDB_SEG_PURGED) continue;
        tomb++;
        const imdb_segment *g = t->seg[0];
        CHECK(g->col[1].i64[i] == 1 && g->col[0].i64[i] == 0 && g->col[2].i64[i] == 0 && g->col[3].off[i] == g->col[3].off[i + 1]);
        CHECK(g->end[i] != IMDB_LIVE && g->end[i] <= s_after);
    }
    CHECK(tomb == 15);
    imdb_verify_report vr;
    OK(imdb_verify(db, &vr, E));
    imdb_close(db);
    db = open_db(dir);
    CHECK(db);
    t = imdb_table_by_name(db, "txns");
    CHECK(t->nseg == 1 && t->horizon == s_after && lookup_cents(db, 1, db->seq) == 100);
    OK(imdb_verify(db, &vr, E));
    imdb_close(db);
}

/* Replica built in a separate process must end up with byte-identical files. */
static void t_replica_lake_identical(void)
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
    for (int i = 1; i <= 200; i++) OK(ins1(db, i, i % 9, i, (i % 3) ? "memo-\xc3\xa9" : "x"));
    OK(imdb_checkpoint(db, E));
    for (int i = 1; i <= 200; i += 7) {
        OK(imdb_begin(db, E));
        OK(imdb_delete(db, t, pk_lookup(db, i, imdb_read_snapshot(db)), E));
        OK(imdb_commit(db, E));
    }
    OK(imdb_checkpoint(db, E));
    OK(imdb_compact(db, t, 0, E));
    for (int i = 201; i <= 230; i++) OK(ins1(db, i, 3, i, "tail"));
    OK(imdb_checkpoint(db, E));
    OK(ship_to_file(p, 0, s, E));
    pid_t pid = fork();
    if (pid == 0) {
        imdb_db *rep = open_db(r);
        uint64_t applied;
        imdb_err e2 = {0};
        int rc = rep ? imdb_apply_stream(rep, open(s, O_RDONLY), &applied, &e2) : 1;
        if (rc) fprintf(stderr, "    child apply: %s\n", e2.msg);
        imdb_close(rep);
        _exit(rc ? 1 : 0);
    }
    int status = 0;
    waitpid(pid, &status, 0);
    CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    imdb_close(db);
    char why[300] = "";
    bool same = dirs_identical(path_join(p, "objects"), path_join(r, "objects"), why, sizeof why);
    if (!same) fprintf(stderr, "    %s\n", why);
    CHECK(same);
    size_t a, b;
    uint8_t *ha = slurp(path_join(p, "LAKE_HEAD"), &a), *hb = slurp(path_join(r, "LAKE_HEAD"), &b);
    CHECK(ha && hb && a == b && memcmp(ha, hb, a) == 0);
    free(ha);
    free(hb);
    char lpa[700], lpb[700];
    snprintf(lpa, sizeof lpa, "%s/log", p);
    snprintf(lpb, sizeof lpb, "%s/log", r);
    CHECK(logs_identical(lpa, lpb, why, sizeof why));
    imdb_db *rep = open_db(r);
    CHECK(rep);
    imdb_verify_report vr;
    OK(imdb_verify(rep, &vr, E));
    CHECK(count_subject(rep, 3, rep->seq) > 30);
    imdb_close(rep);
}

static void t_erase_in_lake(void)
{
    const char *base = test_tmpdir();
    char p[600], r[600], r2[600], s[600];
    snprintf(p, sizeof p, "%s/primary", base);
    snprintf(r, sizeof r, "%s/replica", base);
    snprintf(r2, sizeof r2, "%s/late", base);
    snprintf(s, sizeof s, "%s/stream", base);
    OK(imdb_init(p, false, NULL, E));
    OK(imdb_init(r, true, p, E));
    OK(imdb_init(r2, true, p, E));
    imdb_db *db = open_db(p);
    CHECK(db);
    OK(make_table(db, E));
    imdb_table *t = imdb_table_by_name(db, "txns");
    const int64_t big = 9876543210; /* the column maximum: lives in the zone map */
    uint8_t pat[8];
    imdb_le64(pat, (uint64_t)big);
    for (int i = 1; i <= 40; i++) OK(ins1(db, i, i % 4, i, "plain"));
    for (int i = 0; i < 15; i++) OK(ins1(db, 1000 + i, 42, i == 7 ? big : 100 + i, "SECRET-LAKE-42"));
    OK(imdb_checkpoint(db, E));
    /* history: one of user 42's rows updated, more rows in the memtable */
    imdb_value v[4];
    row_vals(v, 1003, 42, 555, "SECRET-LAKE-42-v2");
    OK(imdb_begin(db, E));
    OK(imdb_update(db, t, pk_lookup(db, 1003, imdb_read_snapshot(db)), v, E));
    OK(imdb_commit(db, E));
    OK(imdb_checkpoint(db, E));
    CHECK(count_files(path_join(p, "objects"), ".man") == 2); /* previous generation retained */
    OK(ins1(db, 2000, 42, 1, "SECRET-LAKE-42-mem")); /* memtable only */
    uint64_t s_before = db->seq;
    CHECK(count_subject(db, 42, db->seq) == 16);
    CHECK(tree_contains(p, "SECRET-LAKE-42") && tree_contains_n(p, pat, 8));
    OK(ship_to_file(p, 0, s, E));
    imdb_db *rep = open_db(r);
    CHECK(rep);
    uint64_t applied;
    OK(apply_file(rep, s, &applied, E));
    CHECK(tree_contains(r, "SECRET-LAKE-42"));

    imdb_value sv = {.type = IMDB_T_INT64, .i = 42};
    imdb_erase_report er;
    OK(imdb_erase_subject(db, &sv, &er, E));
    CHECK(er.versions == 17 && er.live_deleted == 16 && er.segments_rewritten >= 1 && !er.redaction_pending);
    CHECK(count_subject(db, 42, db->seq) == 0 && count_subject(db, 42, s_before) == 0);
    CHECK(count_subject(db, 1, db->seq) == 10);
    CHECK(!tree_contains(p, "SECRET-LAKE-42"));
    CHECK(!tree_contains_n(p, pat, 8)); /* not even in a zone map or DV */
    CHECK(count_files(path_join(p, "objects"), ".man") == 1); /* no retention after an erasure */
    imdb_verify_report vr;
    OK(imdb_verify(db, &vr, E));
    CHECK(vr.stubs == 17);

    OK(ship_to_file(p, rep->seq, s, E));
    OK(apply_file(rep, s, &applied, E));
    CHECK(!tree_contains(r, "SECRET-LAKE-42") && !tree_contains_n(r, pat, 8));
    OK(imdb_verify(rep, &vr, E));
    imdb_close(rep);

    /* a replica bootstrapping from the redacted log: deferred checks resolve at the ERASE */
    OK(ship_to_file(p, 0, s, E));
    imdb_db *late = open_db(r2);
    CHECK(late);
    OK(apply_file(late, s, &applied, E));
    CHECK(late->pending_auth == 0 && !late->lake_unverified);
    OK(imdb_verify(late, &vr, E));
    imdb_close(late);
    imdb_close(db);
    char why[300] = "";
    bool same = dirs_identical(path_join(p, "objects"), path_join(r, "objects"), why, sizeof why) &&
                dirs_identical(path_join(p, "objects"), path_join(r2, "objects"), why, sizeof why);
    if (!same) fprintf(stderr, "    %s\n", why);
    CHECK(same);
    db = open_db(p);
    CHECK(db && count_subject(db, 42, db->seq) == 0);
    OK(imdb_verify(db, &vr, E));
    /* one more checkpoint, then restart: GC must not depend on restarts */
    OK(ins1(db, 3000, 5, 1, "after"));
    OK(imdb_checkpoint(db, E));
    imdb_close(db);
    db = open_db(p);
    CHECK(db);
    imdb_close(db);
    OK(ship_to_file(p, 0, s, E));
    rep = open_db(r);
    CHECK(rep);
    OK(ship_to_file(p, rep->seq, s, E));
    OK(apply_file(rep, s, &applied, E));
    imdb_close(rep);
    same = dirs_identical(path_join(p, "objects"), path_join(r, "objects"), why, sizeof why);
    if (!same) fprintf(stderr, "    after restart: %s\n", why);
    CHECK(same);
    CHECK(count_files(path_join(p, "objects"), ".man") == 2);
}

static void t_lake_tamper(void)
{
    const char *dir = test_tmpdir();
    OK(imdb_init(dir, false, NULL, E));
    imdb_db *db = open_db(dir);
    CHECK(db);
    OK(make_table(db, E));
    for (int i = 1; i <= 20; i++) OK(ins1(db, i, 1, i, "row"));
    OK(imdb_checkpoint(db, E));
    imdb_table *t = imdb_table_by_name(db, "txns");
    char hex[65], seg[700];
    imdb_hex(t->seg[0]->hash, 32, hex);
    snprintf(seg, sizeof seg, "%s/objects/%s.seg", dir, hex);
    size_t n;
    uint8_t *orig = slurp(seg, &n);
    CHECK(orig);
    imdb_verify_report vr;
    /* flipped byte */
    uint8_t *m = malloc(n);
    memcpy(m, orig, n);
    m[n / 2] ^= 0x40;
    chmod(seg, 0600);
    spit(seg, m, n);
    imdb_err_clear(E);
    CHECK(imdb_verify(db, &vr, E) == IMDB_ERR_VERIFY && strstr(g_e.msg, "does not hash to its name"));
    spit(seg, orig, n);
    OK(imdb_verify(db, &vr, E));
    /* a foreign file in objects/ */
    spit(path_join(path_join(dir, "objects"), "notes.txt"), (const uint8_t *)"hi", 2);
    imdb_err_clear(E);
    CHECK(imdb_verify(db, &vr, E) == IMDB_ERR_VERIFY);
    unlink(path_join(path_join(dir, "objects"), "notes.txt"));
    /* a deleted segment is detected, and the next open restores it from the log */
    unlink(seg);
    imdb_err_clear(E);
    CHECK(imdb_verify(db, &vr, E) != 0);
    imdb_close(db);
    db = open_db(dir);
    CHECK(db);
    OK(imdb_verify(db, &vr, E));
    imdb_close(db);
    free(orig);
    free(m);
}

/* Strict decoders reject every truncation and single-byte corruption. */
static void t_segment_decoder_strict(void)
{
    const char *dir = test_tmpdir();
    OK(imdb_init(dir, false, NULL, E));
    imdb_db *db = open_db(dir);
    CHECK(db);
    OK(make_table(db, E));
    for (int i = 1; i <= 6; i++) OK(ins1(db, i, i, i, i % 2 ? "a\xc3\xa9" : ""));
    OK(imdb_checkpoint(db, E));
    imdb_table *t = imdb_table_by_name(db, "txns");
    const imdb_segment *g = t->seg[0];
    size_t n = g->len;
    int accepted_mut = 0;
    for (size_t cut = 0; cut < n; cut++) {
        uint8_t *b = imdb_alloc_aligned(1, cut ? cut : 1, E);
        memcpy(b, g->bytes, cut);
        imdb_segment *x;
        imdb_err e2 = {0};
        CHECK(imdb_segment_parse(&t->s, b, cut, &x, &e2) != 0);
        free(b);
    }
    for (size_t at = 0; at < n; at++) {
        uint8_t *b = imdb_alloc_aligned(1, n, E);
        memcpy(b, g->bytes, n);
        b[at] ^= 0x01;
        imdb_segment *x;
        imdb_err e2 = {0};
        if (imdb_segment_parse(&t->s, b, n, &x, &e2) == 0) {
            /* A structurally valid mutation always changes the content hash.
             * If it also survives the commitment check it can only be in the
             * VID or BEGIN columns, which VERIFY compares with the version store. */
            uint8_t h[32];
            imdb_sha256(x->bytes, x->len, h);
            CHECK(memcmp(h, g->hash, 32) != 0);
            imdb_err e3 = {0};
            if (imdb_segment_check_commitments(&t->s, x, &e3) == 0) {
                uint64_t vid_off = imdb_get_le64(g->bytes + IMDB_SEG_HEADER + 8);
                uint64_t beg_off = imdb_get_le64(g->bytes + IMDB_SEG_HEADER + 24 + 8);
                bool in_sys = (at >= vid_off && at < vid_off + 8u * g->nrows) ||
                              (at >= beg_off && at < beg_off + 8u * g->nrows);
                CHECK(in_sys);
            }
            accepted_mut++;
            imdb_segment_free(x);
        } else {
            free(b);
        }
    }
    CHECK(accepted_mut > 0 && (size_t)accepted_mut < n);
    /* manifest: every truncation rejected */
    for (size_t cut = 0; cut < db->lake_mlen; cut++) {
        imdb_manifest mm;
        imdb_err e2 = {0};
        CHECK(imdb_manifest_parse(db->lake_mbytes, cut, &mm, &e2) != 0);
    }
    imdb_manifest mm;
    OK(imdb_manifest_parse(db->lake_mbytes, db->lake_mlen, &mm, E));
    CHECK(mm.nt == 1 && mm.t[0].nseg == 1 && mm.t[0].live == 6);
    imdb_manifest_free(&mm);
    CHECK(imdb_object_name_valid("0000000000000000000000000000000000000000000000000000000000000000.seg"));
    CHECK(!imdb_object_name_valid("0000000000000000000000000000000000000000000000000000000000000000.SEG"));
    CHECK(!imdb_object_name_valid("../000000000000000000000000000000000000000000000000000000000000.seg"));
    CHECK(!imdb_object_name_valid("000000000000000000000000000000000000000000000000000000000000000A.seg"));
    imdb_close(db);
}


static void t_dv_decoder_hostile(void)
{
    imdb_err e = {0};
    uint8_t seg[32];
    memset(seg, 0xAB, sizeof seg);
    imdb_buf b;
    imdb_buf_init(&b);
    imdb_buf_put(&b, "IMDBDV01", 8);
    imdb_buf_put(&b, seg, 32);
    imdb_buf_put_u32(&b, 2);
    imdb_buf_put_u32(&b, 0);
    imdb_buf_put_u32(&b, 1);
    imdb_buf_put_u32(&b, 0);
    imdb_buf_put_u64(&b, 7);
    imdb_buf_put_u32(&b, 4);
    imdb_buf_put_u32(&b, 0);
    imdb_buf_put_u64(&b, 9);
    uint8_t got[32];
    imdb_dv_ent *ents;
    uint32_t n;
    CHECK(imdb_dv_parse(b.p, b.len, got, &ents, &n, 10, &e) == 0 && n == 2 && ents[1].row == 4 && ents[1].end == 9);
    free(ents);
    CHECK(memcmp(got, seg, 32) == 0);
    for (size_t cut = 0; cut < b.len; cut++) {
        imdb_err_clear(&e);
        CHECK(imdb_dv_parse(b.p, cut, got, &ents, &n, 10, &e) != 0);
    }
    struct {
        size_t at;
        uint8_t val;
    } bad[] = {
        {40, 3},            /* count larger than the entries present */
        {44, 1},            /* reserved word non-zero */
        {48, 10},           /* row beyond the segment */
        {52, 1},            /* entry padding non-zero */
        {56, 0},            /* end = 0 (low byte) with the rest zero below */
        {64, 0},            /* second row 0 < first row 1: not ascending */
    };
    for (size_t k = 0; k < sizeof bad / sizeof *bad; k++) {
        uint8_t *m = malloc(b.len);
        memcpy(m, b.p, b.len);
        m[bad[k].at] = bad[k].val;
        imdb_err_clear(&e);
        int rc = imdb_dv_parse(m, b.len, got, &ents, &n, 10, &e);
        if (rc == 0) {
            fprintf(stderr, "    dv mutation %zu accepted\n", k);
            free(ents);
        }
        CHECK(rc != 0);
        free(m);
    }
    /* end = LIVE is not a deletion */
    uint8_t *m = malloc(b.len);
    memcpy(m, b.p, b.len);
    memset(m + 56, 0xFF, 8);
    imdb_err_clear(&e);
    CHECK(imdb_dv_parse(m, b.len, got, &ents, &n, 10, &e) != 0);
    free(m);
    /* zero rows in the segment means no DV can be valid */
    imdb_err_clear(&e);
    CHECK(imdb_dv_parse(b.p, b.len, got, &ents, &n, 0, &e) != 0);
    imdb_buf_free(&b);
}

static void t_dv_file_tamper(void)
{
    const char *dir = test_tmpdir();
    OK(imdb_init(dir, false, NULL, E));
    imdb_db *db = open_db(dir);
    CHECK(db);
    OK(make_table(db, E));
    imdb_table *t = imdb_table_by_name(db, "txns");
    for (int i = 1; i <= 10; i++) OK(ins1(db, i, 1, i, "r"));
    OK(imdb_checkpoint(db, E));
    OK(imdb_begin(db, E));
    OK(imdb_delete(db, t, pk_lookup(db, 3, imdb_read_snapshot(db)), E));
    OK(imdb_commit(db, E));
    OK(imdb_checkpoint(db, E));
    char hex[65], dv[700];
    CHECK(t->nseg == 1);
    imdb_hex(t->seg[0]->dv_hash, 32, hex);
    snprintf(dv, sizeof dv, "%s/objects/%s.dv", dir, hex);
    size_t n;
    uint8_t *orig = slurp(dv, &n);
    CHECK(orig && n == 64);
    imdb_verify_report vr;
    for (size_t at = 48; at < 64; at++) { /* row and end fields of the only entry */
        uint8_t *m = malloc(n);
        memcpy(m, orig, n);
        m[at] ^= 0x01;
        spit(dv, m, n);
        imdb_err_clear(E);
        CHECK(imdb_verify(db, &vr, E) == IMDB_ERR_VERIFY);
        free(m);
    }
    spit(dv, orig, n);
    OK(imdb_verify(db, &vr, E));
    /* open repairs a corrupted object from the authoritative rebuild */
    orig[50] ^= 0x10;
    spit(dv, orig, n);
    imdb_close(db);
    db = open_db(dir);
    CHECK(db && strstr(db->warning, "repaired lake object"));
    OK(imdb_verify(db, &vr, E));
    imdb_close(db);
    free(orig);
}

/* CHECKPOINT with payloads -> ERASE -> COMPACT PURGE, then a replica that only
 * ever sees the redacted log: the CHECKPOINT check is deferred, the ERASE
 * resolves it, and the COMPACT must match strictly. */
static void t_erase_compact_late_replica(void)
{
    const char *base = test_tmpdir();
    char p[600], r[600], s[600];
    snprintf(p, sizeof p, "%s/primary", base);
    snprintf(r, sizeof r, "%s/late", base);
    snprintf(s, sizeof s, "%s/stream", base);
    OK(imdb_init(p, false, NULL, E));
    OK(imdb_init(r, true, p, E));
    imdb_db *db = open_db(p);
    CHECK(db);
    OK(make_table(db, E));
    imdb_table *t = imdb_table_by_name(db, "txns");
    for (int i = 1; i <= 20; i++) OK(ins1(db, i, i % 3, i, i % 3 == 1 ? "PII-ONE" : "other"));
    OK(imdb_checkpoint(db, E));
    for (int i = 2; i <= 20; i += 3) {
        OK(imdb_begin(db, E));
        OK(imdb_delete(db, t, pk_lookup(db, i, imdb_read_snapshot(db)), E));
        OK(imdb_commit(db, E));
    }
    OK(imdb_checkpoint(db, E));
    imdb_value sv = {.type = IMDB_T_INT64, .i = 1};
    imdb_erase_report er;
    OK(imdb_erase_subject(db, &sv, &er, E));
    CHECK(er.versions == 7);
    uint64_t purge = db->seq;
    OK(imdb_compact(db, t, purge, E));
    for (int i = 21; i <= 25; i++) OK(ins1(db, i, 2, i, "late"));
    OK(imdb_checkpoint(db, E));
    imdb_verify_report vr;
    OK(imdb_verify(db, &vr, E));
    CHECK(!tree_contains(p, "PII-ONE"));
    OK(ship_to_file(p, 0, s, E));
    imdb_db *rep = open_db(r);
    CHECK(rep);
    uint64_t applied;
    OK(apply_file(rep, s, &applied, E));
    CHECK(rep->seq == db->seq && !rep->lake_unverified && rep->pending_auth == 0);
    OK(imdb_verify(rep, &vr, E));
    imdb_table *rt = imdb_table_by_name(rep, "txns");
    CHECK(rt->horizon == purge && rt->nseg == t->nseg);
    imdb_close(rep);
    imdb_close(db);
    char why[300] = "";
    bool same = dirs_identical(path_join(p, "objects"), path_join(r, "objects"), why, sizeof why);
    if (!same) fprintf(stderr, "    %s\n", why);
    CHECK(same);
    /* and the replica survives a restart with the same verdict */
    rep = open_db(r);
    CHECK(rep && !rep->lake_unverified);
    OK(imdb_verify(rep, &vr, E));
    imdb_close(rep);
}

/* ---- snapshot open (open from the lake, replay only the tail) -------------------- */

/* Every piece of logical state two opens of the same directory must agree on. */
static bool same_state(imdb_db *a, imdb_db *b, char *why, size_t wl)
{
    if (a->seq != b->seq || memcmp(a->head, b->head, 32) || memcmp(&a->global, &b->global, sizeof a->global) ||
        a->nt != b->nt || a->lake_seq != b->lake_seq || memcmp(a->lake_manifest, b->lake_manifest, 32) ||
        a->last_time != b->last_time) {
        snprintf(why, wl, "database header (seq %llu/%llu)", (unsigned long long)a->seq, (unsigned long long)b->seq);
        return false;
    }
    if ((a->lake_prev == NULL) != (b->lake_prev == NULL) ||
        (a->lake_prev && (a->lake_prevlen != b->lake_prevlen || memcmp(a->lake_prev, b->lake_prev, a->lake_prevlen)))) {
        snprintf(why, wl, "retained manifest generation");
        return false;
    }
    for (uint32_t ti = 0; ti < a->nt; ti++) {
        imdb_table *x = a->t[ti], *y = b->t[ti];
        if (x->nver != y->nver || x->live != y->live || x->horizon != y->horizon ||
            memcmp(&x->digest, &y->digest, sizeof x->digest) || x->nseg != y->nseg) {
            snprintf(why, wl, "table %s header", x->s.name);
            return false;
        }
        for (uint64_t vid = 0; vid < x->nver; vid++) {
            const imdb_version *u = imdb_vh(x, vid), *w = imdb_vh(y, vid);
            uint8_t fm = IMDB_V_STUB | IMDB_V_PURGED | IMDB_V_PENDING_AUTH;
            if (u->begin != w->begin || u->end != w->end || (u->flags & fm) != (w->flags & fm) ||
                memcmp(imdb_vc(x, vid)->commit, imdb_vc(y, vid)->commit, 32) || memcmp(imdb_vc(x, vid)->salt, imdb_vc(y, vid)->salt, 16)) {
                snprintf(why, wl, "table %s version %llu", x->s.name, (unsigned long long)vid);
                return false;
            }
        }
        /* the indexes answer alike: every key at every snapshot from the horizon on */
        for (uint64_t vid = 0; vid < x->nver; vid++) {
            imdb_value k;
            if (imdb_version_key(x, vid, x->s.pk, &k)) continue;
            for (uint64_t s = x->horizon; s <= a->seq; s += 1 + a->seq / 7)
                if (imdb_lookup_pk(a, x, &k, s) != imdb_lookup_pk(b, y, &k, s)) {
                    snprintf(why, wl, "table %s key lookup at %llu", x->s.name, (unsigned long long)s);
                    return false;
                }
        }
        if (x->s.subject >= 0)
            for (int64_t subj = 0; subj < 12; subj++) {
                imdb_value sv = {.type = IMDB_T_INT64, .i = subj};
                const imdb_vlist *l1 = imdb_subject_versions(x, &sv), *l2 = imdb_subject_versions(y, &sv);
                uint32_t n1 = l1 ? l1->n : 0, n2 = l2 ? l2->n : 0;
                if (n1 != n2 || (n1 && memcmp(l1->v, l2->v, n1 * sizeof *l1->v))) {
                    snprintf(why, wl, "table %s subject %lld list", x->s.name, (long long)subj);
                    return false;
                }
            }
    }
    return true;
}

/* A second, read-only handle (no lock) that replays the whole log. */
static imdb_db *open_full(const char *dir)
{
    imdb_open_opts o = {.sync = 0, .full_replay = true, .read_only = true};
    imdb_db *db = NULL;
    imdb_err_clear(&g_e);
    if (imdb_open(dir, &o, &db, &g_e)) return NULL;
    return db;
}

static void t_snapshot_equivalence(void)
{
    const char *dir = test_tmpdir();
    OK(imdb_init(dir, false, NULL, E));
    imdb_db *db = open_db(dir);
    CHECK(db);
    OK(make_table(db, E));
    int64_t next_id = 1;
    for (int round = 0; round < 6; round++) {
        imdb_table *t = imdb_table_by_name(db, "txns");
        for (int k = 0; k < 40; k++) {
            uint64_t r = test_rand() % 100;
            int64_t id = 1 + (int64_t)(test_rand() % (uint64_t)next_id);
            uint64_t vid = pk_lookup(db, id, db->seq);
            if (r < 55 || vid == IMDB_NONE) {
                OK(ins1(db, next_id, (int64_t)(test_rand() % 12), (int64_t)(test_rand() % 9000), "snap-row"));
                next_id++;
            } else if (r < 80) {
                imdb_value v[4];
                row_vals(v, id, (int64_t)(test_rand() % 12), (int64_t)(test_rand() % 9000), "snap-upd");
                OK(imdb_begin(db, E));
                OK(imdb_update(db, t, vid, v, E));
                OK(imdb_commit(db, E));
            } else {
                OK(imdb_begin(db, E));
                OK(imdb_delete(db, t, vid, E));
                OK(imdb_commit(db, E));
            }
        }
        OK(imdb_checkpoint(db, E));
        if (round % 2) OK(imdb_compact(db, t, db->seq - 10, E)); /* purge: tombstones */
        if (round >= 2) {
            imdb_value subj = {.type = IMDB_T_INT64, .i = (int64_t)(test_rand() % 12)};
            imdb_erase_report er;
            OK(imdb_erase_subject(db, &subj, &er, E));
        }
        /* a tail after the snapshot, so both paths of open are exercised */
        for (int k = 0; k < 5; k++) OK(ins1(db, next_id++, 3, 7, "tail-row"));
        imdb_close(db);
        /* a writable open completes the last publish (objects, LAKE_HEAD, GC); both paths must
         * leave the same files */
        char copy[700];
        snprintf(copy, sizeof copy, "%s-full%d", dir, round);
        CHECK(copy_tree(dir, copy) == 0);
        imdb_open_opts fo = {.sync = 0, .full_replay = true};
        imdb_db *c = NULL;
        OK(imdb_open(copy, &fo, &c, E));
        imdb_db *a = open_db(dir), *b = open_full(dir);
        char fwhy[200] = "";
        bool same_files = dirs_identical(path_join(dir, "objects"), path_join(copy, "objects"), fwhy, sizeof fwhy) &&
                          dirs_identical(path_join(dir, "log"), path_join(copy, "log"), fwhy, sizeof fwhy);
        size_t h1, h2;
        uint8_t *lh1 = slurp(path_join(dir, "LAKE_HEAD"), &h1), *lh2 = slurp(path_join(copy, "LAKE_HEAD"), &h2);
        same_files = same_files && lh1 && lh2 && h1 == h2 && memcmp(lh1, lh2, h1) == 0;
        free(lh1);
        free(lh2);
        if (!same_files) fprintf(stderr, "    round %d: snapshot vs full-replay open: %s\n", round, fwhy);
        CHECK(same_files);
        imdb_close(c);
        if (!a || !b || !a->snapshot_seq || a->warning[0])
            fprintf(stderr, "    round %d: a=%p b=%p snap=%llu warn=[%s] err=[%s]\n", round, (void *)a, (void *)b,
                    a ? (unsigned long long)a->snapshot_seq : 0ull, a ? a->warning : "", g_e.msg);
        CHECK(a && b && a->snapshot_seq > 0 && b->snapshot_seq == 0 && !a->warning[0]);
        char why[200] = "";
        bool same = same_state(a, b, why, sizeof why);
        if (!same) fprintf(stderr, "    round %d: %s\n", round, why);
        CHECK(same);
        imdb_verify_report vr;
        OK(imdb_verify(a, &vr, E));
        imdb_close(b);
        db = a;
    }
    imdb_close(db);
}

static void t_snapshot_fallbacks(void)
{
    const char *base = test_tmpdir();
    char p[600], r[600], s[600];
    snprintf(p, sizeof p, "%s/primary", base);
    snprintf(r, sizeof r, "%s/replica", base);
    snprintf(s, sizeof s, "%s/stream", base);
    OK(imdb_init(p, false, NULL, E));
    imdb_db *db = open_db(p);
    CHECK(db);
    OK(make_table(db, E));
    for (int i = 1; i <= 6; i++) OK(ins1(db, i, 42, i, "SNAP-FALLBACK-42"));
    OK(imdb_checkpoint(db, E));
    uint64_t ckpt = db->seq;
    for (int i = 7; i <= 9; i++) OK(ins1(db, i, 7, i, "keep"));
    imdb_value subj = {.type = IMDB_T_INT64, .i = 42};
    imdb_erase_report er;
    OK(imdb_erase_subject(db, &subj, &er, E));
    imdb_close(db);

    /* 1. a replica bootstrapping from the redacted log stops after the first
     * CHECKPOINT. Its unverified manifest must not be published; open resumes
     * from the log until the authorising ERASE arrives. */
    OK(imdb_init(r, true, p, E));
    OK(ship_to_file(p, 0, s, E));
    size_t sn;
    uint8_t *sb = slurp(s, &sn);
    size_t off = 0;
    while (off < sn && imdb_frame_seq(sb + off) <= ckpt) off += 16 + imdb_get_le32(sb + off + 4);
    spit(s, sb, off);
    free(sb);
    imdb_db *rep = open_db(r);
    CHECK(rep);
    uint64_t applied;
    CHECK(apply_file(rep, s, &applied, E) == IMDB_ERR_AUTH);
    CHECK(rep->seq == ckpt && rep->lake_unverified && rep->pending_auth == 6);
    imdb_close(rep);
    rep = open_db(r);
    CHECK(rep && rep->snapshot_seq == 0);
    CHECK(rep->seq == ckpt && rep->pending_auth == 6);
    imdb_close(rep);

    /* 2. a corrupted segment: the snapshot is refused, the full replay rebuilds
     * the object and the next open uses the snapshot again */
    char seg[700] = "";
    char **names;
    (void)names;
    DIR *d = opendir(path_join(p, "objects"));
    struct dirent *de;
    while (d && (de = readdir(d)))
        if (strstr(de->d_name, ".seg")) snprintf(seg, sizeof seg, "%s/objects/%s", p, de->d_name);
    if (d) closedir(d);
    CHECK(seg[0]);
    size_t gn;
    uint8_t *g = slurp(seg, &gn);
    g[gn / 2] ^= 1;
    spit(seg, g, gn);
    free(g);
    db = open_db(p);
    CHECK(db && db->snapshot_seq == 0 && strstr(db->warning, "lake"));
    imdb_close(db);
    db = open_db(p);
    CHECK(db && db->snapshot_seq > 0 && !db->warning[0]);
    imdb_verify_report vr;
    OK(imdb_verify(db, &vr, E));
    imdb_close(db);

    /* 3. AS OF TIMESTAMP and SHOW LOG reach before the snapshot (the lazy index) */
    db = open_db(p);
    imdb_db *full = open_full(p);
    CHECK(db && full && db->snapshot_seq > 0 && db->ci_first > 1);
    for (uint64_t q = 1; q <= full->seq; q++) {
        uint64_t t_us = imdb_ci_at(full, q, E)->time_us, s1, s2;
        OK(imdb_seq_at_time(db, t_us, &s1, E));
        OK(imdb_seq_at_time(full, t_us, &s2, E));
        CHECK(s1 == q && s2 == q);
    }
    CHECK(db->ci_first == 1);
    uint64_t z;
    OK(imdb_seq_at_time(db, 0, &z, E));
    CHECK(z == 0);
    imdb_close(full);
    imdb_close(db);
}

/* After a snapshot open, ERASE SUBJECT still reaches purged history (from the
 * tombstones) in segments the open never read, on the primary and a replica. */
static void t_snapshot_erase_purged(void)
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
    for (int i = 1; i <= 8; i++) OK(ins1(db, i, 42, i, "OLD-HISTORY-42"));
    for (int i = 9; i <= 12; i++) OK(ins1(db, i, 7, i, "other"));
    OK(imdb_checkpoint(db, E));
    for (int i = 1; i <= 8; i++) { /* history: the old versions die */
        imdb_value v[4];
        row_vals(v, i, 42, i * 10, "NEW-42");
        OK(imdb_begin(db, E));
        OK(imdb_update(db, t, pk_lookup(db, i, db->seq), v, E));
        OK(imdb_commit(db, E));
    }
    OK(imdb_checkpoint(db, E));
    OK(imdb_compact(db, t, db->seq, E)); /* the old versions are tombstones now */
    imdb_close(db);
    OK(ship_to_file(p, 0, s, E));
    imdb_db *rep = open_db(r);
    CHECK(rep);
    uint64_t applied;
    OK(apply_file(rep, s, &applied, E));
    uint64_t after = rep->seq;
    imdb_close(rep);
    CHECK(tree_contains(p, "OLD-HISTORY-42") && tree_contains(r, "OLD-HISTORY-42"));
    /* both reopen from their snapshots, then the erasure */
    db = open_db(p);
    CHECK(db && db->snapshot_seq > 0);
    imdb_value subj = {.type = IMDB_T_INT64, .i = 42};
    imdb_erase_report er;
    OK(imdb_erase_subject(db, &subj, &er, E));
    CHECK(er.versions == 16);
    imdb_close(db);
    OK(ship_to_file(p, after, s, E));
    rep = open_db(r);
    CHECK(rep && rep->snapshot_seq > 0);
    OK(apply_file(rep, s, &applied, E));
    imdb_close(rep);
    CHECK(!tree_contains(p, "OLD-HISTORY-42") && !tree_contains(p, "NEW-42"));
    CHECK(!tree_contains(r, "OLD-HISTORY-42") && !tree_contains(r, "NEW-42"));
    char la[700], lb[700], why[300] = "";
    snprintf(la, sizeof la, "%s/log", p);
    snprintf(lb, sizeof lb, "%s/log", r);
    CHECK(logs_identical(la, lb, why, sizeof why));
    CHECK(dirs_identical(path_join(p, "objects"), path_join(r, "objects"), why, sizeof why));
    db = open_db(p);
    imdb_db *full = open_full(p);
    CHECK(db && full);
    CHECK(same_state(db, full, why, sizeof why));
    imdb_verify_report vr;
    OK(imdb_verify(db, &vr, E));
    CHECK(vr.stubs == 16 && count_subject(db, 42, db->seq) == 0 && count_subject(db, 7, db->seq) == 4);
    imdb_close(full);
    imdb_close(db);
}

/* ---- reader pins (deferred.md R3, lake.h) --------------------------------------------- */

static int lake_verify(imdb_db *db)
{
    imdb_verify_report vr;
    imdb_err_clear(E);
    return imdb_verify(db, &vr, E);
}

/* the auditor's verdict: 0 accepts, 1 rejects, -1 when it is not available (IMDB_AUDIT_BIN) */
static int lake_audit(const char *dir)
{
    const char *bin = getenv("IMDB_AUDIT_BIN");
    if (!bin || !*bin) return -1;
    char cmd[1600];
    snprintf(cmd, sizeof cmd, "'%s' verify '%s' >/dev/null 2>&1", bin, dir);
    return system(cmd) == 0 ? 0 : 1;
}

static bool obj_there(const char *dir, const uint8_t h[32], const char *ext)
{
    char p[800], hx[65];
    imdb_hex(h, 32, hx);
    snprintf(p, sizeof p, "%s/objects/%s%s", dir, hx, ext);
    struct stat st;
    return stat(p, &st) == 0;
}

static int pins_in(const char *dir)
{
    char p[700];
    snprintf(p, sizeof p, "%s/pins", dir);
    DIR *d = opendir(p);
    int n = 0;
    for (struct dirent *de; d && (de = readdir(d));) n += de->d_name[0] != '.';
    if (d) closedir(d);
    return n;
}

static int gen_next(imdb_db *db, int64_t id, uint8_t g[32]) /* a commit, then a publication */
{
    int rc = ins1(db, id, id % 3, 100 * id, "row");
    if (!rc) rc = imdb_checkpoint(db, E);
    if (!rc && g) memcpy(g, db->lake_manifest, 32);
    return rc;
}

/* A reader's pin keeps its generation through later publications; when it lets go the next
 * publication's GC removes it and the pin file. An ERASE revokes the pins of every generation
 * before it. VERIFY and the auditor accept a pinned generation's files, a stale pin's too, until the
 * GC that removes them. */
static void t_pin_keeps_generation(void)
{
    const char *dir = test_tmpdir();
    OK(imdb_init(dir, false, NULL, E));
    imdb_db *db = open_db(dir);
    CHECK(db);
    OK(make_table(db, E));
    uint8_t g1[32], g2[32];
    OK(gen_next(db, 1, g1));
    int pin;
    OK(imdb_lake_pin(db->dirfd, g1, &pin, E));
    CHECK(pin >= 0 && pins_in(dir) == 1);
    OK(gen_next(db, 2, NULL));
    OK(gen_next(db, 3, NULL));
    CHECK(obj_there(dir, g1, ".man")); /* two publications later: kept for its reader */
    OK(lake_verify(db));
    CHECK(lake_audit(dir) <= 0);
    imdb_lake_unpin(pin); /* stale: still accepted until the GC that removes it */
    OK(lake_verify(db));
    CHECK(lake_audit(dir) <= 0);
    OK(gen_next(db, 4, NULL));
    CHECK(!obj_there(dir, g1, ".man") && pins_in(dir) == 0);
    OK(lake_verify(db));
    memcpy(g2, db->lake_manifest, 32);
    OK(imdb_lake_pin(db->dirfd, g2, &pin, E));
    OK(gen_next(db, 5, NULL));
    OK(gen_next(db, 6, NULL));
    CHECK(obj_there(dir, g2, ".man"));
    imdb_value subj = {.type = IMDB_T_INT64, .i = 1};
    imdb_erase_report er;
    OK(imdb_erase_subject(db, &subj, &er, E));
    CHECK(!obj_there(dir, g2, ".man")); /* revoked: its files may hold the erased rows */
    OK(lake_verify(db));
    CHECK(lake_audit(dir) <= 0);
    imdb_lake_unpin(pin);
    imdb_close(db);
}

/* At most IMDB_MAX_PINNED older generations stay for pins, the newest; and none that lags the
 * current commit by more than pin_max_lag (a hung reader cannot hold one forever). */
static void t_pin_bounds(void)
{
    const char *dir = test_tmpdir();
    OK(imdb_init(dir, false, NULL, E));
    imdb_db *db = open_db(dir);
    CHECK(db);
    OK(make_table(db, E));
    enum { N = IMDB_MAX_PINNED + 2 };
    uint8_t g[N][32];
    int pin[N];
    for (int k = 0; k < N; k++) {
        OK(gen_next(db, 10 + k, g[k]));
        OK(imdb_lake_pin(db->dirfd, g[k], &pin[k], E));
        CHECK(pin[k] >= 0);
    }
    OK(gen_next(db, 100, NULL));
    OK(gen_next(db, 101, NULL));
    for (int k = 0; k < N; k++) CHECK(obj_there(dir, g[k], ".man") == (k >= N - (int)IMDB_MAX_PINNED));
    OK(lake_verify(db));
    CHECK(lake_audit(dir) <= 0);
    db->pin_max_lag = 1; /* every pinned generation now lags too far */
    OK(gen_next(db, 102, NULL));
    for (int k = 0; k < N; k++) CHECK(!obj_there(dir, g[k], ".man"));
    OK(lake_verify(db));
    for (int k = 0; k < N; k++) imdb_lake_unpin(pin[k]);
    imdb_close(db);
}

typedef struct pause_ctx {
    imdb_db *writer;
    bool erase, fired;
    int rc;
} pause_ctx;

static int del1(imdb_db *db, int64_t id)
{
    int rc = imdb_begin(db, E);
    if (!rc) rc = imdb_delete(db, imdb_table_by_name(db, "txns"), pk_lookup(db, id, db->seq), E);
    return rc ? rc : imdb_commit(db, E);
}

/* the reader is about to read its first segment: the writer deletes in it and publishes, twice, so
 * the deletion vector the reader needs is referenced by no later generation (and erases) meanwhile */
static long pause_reader(imdb_io_call *c, void *ctx)
{
    pause_ctx *p = ctx;
    if (p->fired || c->op != IMDB_IO_OPEN || !c->name || !strstr(c->name, ".seg")) return 0;
    p->fired = true;
    imdb_io_set_hooks(NULL); /* the writer runs unhooked, as another process would */
    p->rc = del1(p->writer, 4);
    if (!p->rc) p->rc = gen_next(p->writer, 500, NULL);
    if (!p->rc) p->rc = del1(p->writer, 5);
    if (!p->rc) p->rc = gen_next(p->writer, 501, NULL);
    if (!p->rc && p->erase) {
        imdb_value subj = {.type = IMDB_T_INT64, .i = 2};
        imdb_erase_report er;
        p->rc = imdb_erase_subject(p->writer, &subj, &er, E);
    }
    return 0;
}

/* The review's test: a reader paused between its manifest and its segments while the writer
 * publishes twice keeps its generation (pinned) and opens from it; when an ERASE revokes it
 * meanwhile, the reader starts again at the current generation and opens from that one, not from
 * a full replay. */
static void t_pin_paused_reader(void)
{
    const char *tmp = test_tmpdir();
    for (int mode = 0; mode < 2; mode++) {
        char dir[700];
        snprintf(dir, sizeof dir, "%s/m%d", tmp, mode);
        OK(imdb_init(dir, false, NULL, E));
        imdb_db *db = open_db(dir);
        CHECK(db);
        if (!db) return;
        OK(make_table(db, E));
        for (int i = 1; i <= 30; i++) OK(ins1(db, i, i % 3, 100 * i, "row"));
        OK(del1(db, 3)); /* the first segment gets a deletion vector */
        OK(imdb_checkpoint(db, E));
        uint64_t first = db->lake_seq;
        pause_ctx p = {.writer = db, .erase = mode == 1, .rc = -1};
        imdb_io_hooks h = {.before = pause_reader, .ctx = &p};
        imdb_open_opts ro = {.read_only = true};
        imdb_db *rd = NULL;
        imdb_io_set_hooks(&h);
        imdb_err_clear(E);
        int rc = imdb_open(dir, &ro, &rd, E);
        imdb_io_set_hooks(NULL);
        CHECK(p.fired && p.rc == IMDB_OK && rc == IMDB_OK && rd);
        if (rd) {
            CHECK(!strstr(rd->warning, "replayed the whole log"));
            CHECK(mode ? rd->snapshot_seq == db->lake_seq : rd->snapshot_seq == first);
            CHECK(rd->seq >= rd->snapshot_seq && rd->seq <= db->seq); /* a consistent prefix: what it listed */
            imdb_close(rd);
        }
        imdb_close(db);
    }
}

static void restore_obj(const char *from, const char *to, const uint8_t h[32], const char *ext)
{
    char hx[65], src[1000], dst[1000];
    imdb_hex(h, 32, hx);
    snprintf(src, sizeof src, "%s/%s%s", from, hx, ext);
    snprintf(dst, sizeof dst, "%s/%s%s", to, hx, ext);
    struct stat st;
    if (stat(dst, &st) == 0) return;
    size_t n;
    uint8_t *b = slurp(src, &n);
    if (b) spit(dst, b, n);
    free(b);
}

/* A pin never makes erased or foreign files legitimate: the files of a generation from before the
 * last ERASE, put back with a pin naming it, are refused by VERIFY and the auditor; those of a
 * generation published after it, put back the same way, are accepted. */
static void t_pin_verify_rules(void)
{
    const char *dir = test_tmpdir();
    OK(imdb_init(dir, false, NULL, E));
    imdb_db *db = open_db(dir);
    CHECK(db);
    OK(make_table(db, E));
    for (int pass = 0; pass < 2; pass++) {
        uint8_t g[32];
        OK(gen_next(db, 1000 + 10 * pass, g));
        /* keep its files aside (manifest and every object it references) */
        char od[700], keep[740];
        snprintf(od, sizeof od, "%s/objects", dir);
        snprintf(keep, sizeof keep, "%s/kept%d", dir, pass);
        CHECK(copy_tree(od, keep) == 0);
        if (pass == 0) {
            imdb_value subj = {.type = IMDB_T_INT64, .i = 1};
            imdb_erase_report er;
            OK(imdb_erase_subject(db, &subj, &er, E)); /* g is now from before the last ERASE */
        }
        OK(gen_next(db, 1001 + 10 * pass, NULL));
        OK(gen_next(db, 1002 + 10 * pass, NULL));
        CHECK(!obj_there(dir, g, ".man"));
        /* put back g's manifest and what it references, and a pin naming g */
        char hx0[65], src[1000];
        imdb_hex(g, 32, hx0);
        snprintf(src, sizeof src, "%s/%s.man", keep, hx0);
        size_t mn;
        uint8_t *mbytes = slurp(src, &mn);
        imdb_manifest gm;
        memset(&gm, 0, sizeof gm);
        CHECK(mbytes && imdb_manifest_parse(mbytes, mn, &gm, E) == IMDB_OK);
        restore_obj(keep, od, g, ".man");
        for (uint32_t ti = 0; ti < gm.nt; ti++)
            for (uint32_t k = 0; k < gm.t[ti].nseg; k++) {
                restore_obj(keep, od, gm.t[ti].seg[k].seg, ".seg");
                static const uint8_t zero[32];
                if (memcmp(gm.t[ti].seg[k].dv, zero, 32) != 0) restore_obj(keep, od, gm.t[ti].seg[k].dv, ".dv");
            }
        imdb_manifest_free(&gm);
        free(mbytes);
        char pp[800], hx[65];
        imdb_hex(g, 32, hx);
        snprintf(pp, sizeof pp, "%s/pins/%s.pin", dir, hx);
        spit(pp, (const uint8_t *)"", 0);
        int vr = lake_verify(db), ar = lake_audit(dir);
        if (pass == 0) CHECK(vr == IMDB_ERR_VERIFY && strstr(g_e.msg, "no retained manifest") && ar != 0);
        else CHECK(vr == IMDB_OK && ar <= 0);
        OK(gen_next(db, 1003 + 10 * pass, NULL)); /* GC: the stale pin and the files go */
        CHECK(!obj_there(dir, g, ".man") && pins_in(dir) == 0);
        OK(lake_verify(db));
    }
    imdb_close(db);
}

const test_case lake_tests[] = {
    {"checkpoint_basic", t_checkpoint_basic},
    {"deletion_vectors_time_travel", t_deletion_vectors_time_travel},
    {"compact_purge_horizon", t_compact_purge_horizon},
    {"replica_lake_identical", t_replica_lake_identical},
    {"erase_in_lake", t_erase_in_lake},
    {"lake_tamper", t_lake_tamper},
    {"segment_decoder_strict", t_segment_decoder_strict},
    {"dv_decoder_hostile", t_dv_decoder_hostile},
    {"dv_file_tamper", t_dv_file_tamper},
    {"erase_compact_late_replica", t_erase_compact_late_replica},
    {"snapshot_equivalence", t_snapshot_equivalence},
    {"snapshot_fallbacks", t_snapshot_fallbacks},
    {"snapshot_erase_purged", t_snapshot_erase_purged},
    {"pin_keeps_generation", t_pin_keeps_generation},
    {"pin_bounds", t_pin_bounds},
    {"pin_paused_reader", t_pin_paused_reader},
    {"pin_verify_rules", t_pin_verify_rules},
};
const size_t lake_ntests = sizeof lake_tests / sizeof *lake_tests;
