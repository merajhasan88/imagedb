/* Stage 3c-1 (round 4): the lake's segment images under a budget (db.h: imdb_segcache). An image loads when an
 * operation pins it and leaves when the outermost operation ends past the budget, the least recently pinned first;
 * it leaves only once its objects are on disk. The rules these tests hold it to: a reloaded image is the image that
 * left, its ends included (the published ones, later ones, a running transaction's), so every answer and every byte
 * is the same at any budget; an image that is the only copy never leaves; a load that fails is an error, never an
 * empty answer and never a stopped handle. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>

#include "../../src/db_internal.h"
#include "../../src/lake.h"
#include "../../src/sql.h"
#include "thelp.h"

/* The test's own budget, whatever IMDB_SEGCACHE says. No window and no eager pass: the store holds every version,
 * so what is in memory is the budget's alone (a held version's values are its segment row's once flushed). */
static imdb_db *copen(const char *dir, uint64_t budget)
{
    imdb_open_opts o = {.sync = 0, .mem_window_us = UINT64_MAX, .seg_cache_bytes = UINT64_MAX};
    imdb_db *db = NULL;
    imdb_err_clear(E);
    if (imdb_open(dir, &o, &db, E)) return NULL;
    db->segcache.budget = budget;
    return db;
}

static int ex(imdb_session *s, const char *sql)
{
    imdb_result r;
    imdb_err_clear(E);
    int rc = imdb_exec_one(s, sql, strlen(sql), NULL, 0, &r, E);
    if (!rc) imdb_result_free(&r);
    return rc;
}

/* a statement's outcome as text: its code, then its rows and status (the access path is part of neither) */
static int outcome(imdb_session *s, const char *sql, imdb_buf *out)
{
    imdb_result r;
    imdb_err e = {0};
    out->len = 0;
    int rc = imdb_exec_one(s, sql, strlen(sql), NULL, 0, &r, &e);
    imdb_buf_printf(out, "%d\n", rc);
    if (rc) return rc;
    char *man = strstr(r.status, "manifest "); /* a publish names its manifest: it holds its commit's hash and time */
    if (man) *man = 0;
    if (r.has_rows) imdb_result_render(&r, true, out);
    imdb_buf_printf(out, "%s\n", r.status);
    imdb_result_free(&r);
    return rc;
}

static bool same(imdb_session *a, imdb_session *b, const char *sql)
{
    imdb_buf x, y;
    imdb_buf_init(&x);
    imdb_buf_init(&y);
    outcome(a, sql, &x);
    outcome(b, sql, &y);
    bool eq = x.len == y.len && (!x.len || memcmp(x.p, y.p, x.len) == 0);
    if (!eq)
        fprintf(stderr, "    differ: %s\n    --- every image kept:\n%.*s    --- none kept:\n%.*s", sql,
                (int)(x.len > 600 ? 600 : x.len), (const char *)x.p, (int)(y.len > 600 ? 600 : y.len),
                (const char *)y.p);
    imdb_buf_free(&x);
    imdb_buf_free(&y);
    return eq;
}

static bool all_zero32(const uint8_t *p)
{
    uint8_t x = 0;
    for (int i = 0; i < 32; i++) x |= p[i];
    return x == 0;
}

static uint64_t resident_images(const imdb_table *t)
{
    uint64_t n = 0;
    for (uint32_t k = 0; k < t->nseg; k++) n += imdb_seg_resident(t, t->seg[k]) != NULL;
    return n;
}

/* A table of 200 rows in one segment, then ends after its publish (updates and deletes, held, written into the
 * resident image at commit) and no publish since. The same directory twice: every image kept, and none kept
 * between operations. Inside a transaction (its pending delete's end goes into the image at the write), across
 * its rollback (the undo writes LIVE into a resident image only), then across a commit and a publish (the deletion
 * vector is built from the image's ends), every statement's outcome is the same (a scan reads visibility from the
 * image's ends too), and so are the reloaded segment and the deletion vector the publish makes from its ends: the
 * reload took each end from the vector and the store. */
static void t_segcache_reload_ends(void)
{
    char da[512], dbb[512], cmd[1100], sql[128];
    snprintf(da, sizeof da, "%s", test_tmpdir());
    OK(imdb_init(da, false, NULL, E));
    imdb_db *db = copen(da, UINT64_MAX);
    CHECK(db);
    if (!db) return;
    imdb_session s;
    imdb_session_init(&s, db);
    OK(ex(&s, "CREATE TABLE t (id INT64 PRIMARY KEY, v INT64, s TEXT NOT NULL)"));
    OK(ex(&s, "BEGIN"));
    for (int i = 0; i < 200; i++) {
        snprintf(sql, sizeof sql, "INSERT INTO t VALUES (%d, %d, 'text %d')", i, i, i);
        OK(ex(&s, sql));
    }
    OK(ex(&s, "COMMIT"));
    OK(ex(&s, "CHECKPOINT"));
    for (int i = 0; i < 40; i++) {
        snprintf(sql, sizeof sql, "UPDATE t SET v = %d WHERE id = %d", i + 1000, i);
        OK(ex(&s, sql));
    }
    for (int i = 100; i < 110; i++) {
        snprintf(sql, sizeof sql, "DELETE FROM t WHERE id = %d", i);
        OK(ex(&s, sql));
    }
    imdb_session_close(&s);
    OK(imdb_close(db));
    snprintf(dbb, sizeof dbb, "%s", test_tmpdir());
    snprintf(cmd, sizeof cmd, "rm -rf '%s' && cp -a '%s' '%s'", dbb, da, dbb);
    CHECK(system(cmd) == 0);
    imdb_db *a = copen(da, UINT64_MAX), *b = copen(dbb, 0);
    CHECK(a && b);
    if (!a || !b) {
        imdb_close(a);
        imdb_close(b);
        return;
    }
    imdb_session sa, sb;
    imdb_session_init(&sa, a);
    imdb_session_init(&sb, b);
    uint64_t loads0 = b->segcache.loads;
    static const char *const steps[] = {
        "SELECT COUNT(*), SUM(v) FROM t",
        "BEGIN",
        "DELETE FROM t WHERE id = 5",
        "SHOW HISTORY t 5",
        "SELECT COUNT(*), SUM(v) FROM t",
        "SHOW HISTORY t 1",
        "SHOW HISTORY t 100",
        "SELECT id, v, s FROM t WHERE id = 39",
        "ROLLBACK",
        "SHOW HISTORY t 5",
        "BEGIN",
        "DELETE FROM t WHERE id = 6",
        "UPDATE t SET v = 7777 WHERE id = 7",
        "COMMIT",
        "SHOW HISTORY t 6",
        "SHOW HISTORY t 7",
        "CHECKPOINT",
        "SELECT COUNT(*), SUM(v) FROM t",
        "SHOW HISTORY t 1",
    };
    bool ok = true;
    for (size_t i = 0; i < sizeof steps / sizeof *steps && ok; i++) {
        ok = same(&sa, &sb, steps[i]);
        CHECK(ok);
        if (ok) CHECK(resident_images(imdb_table_by_name(b, "t")) == 0); /* none left past its operation */
    }
    CHECK(b->segcache.loads > loads0 + 10 && a->segcache.loads == 0); /* the run reloaded, and often */
    imdb_table *ta = imdb_table_by_name(a, "t"), *tb = imdb_table_by_name(b, "t");
    CHECK(ta && tb && ta->nseg == tb->nseg && ta->nseg >= 1);
    /* the publish's bytes: the reloaded segment and the deletion vector made from its ends, by name; the segment the
     * memtable became differs by a salt (the UPDATE after the copy drew its own in each), so its rows only */
    if (ok && ta && tb && ta->nseg == tb->nseg)
        for (uint32_t k = 0; k < ta->nseg; k++)
            CHECK(k ? ta->seg[k]->nrows == tb->seg[k]->nrows
                    : memcmp(ta->seg[k]->hash, tb->seg[k]->hash, 32) == 0 &&
                          memcmp(ta->seg[k]->dv_hash, tb->seg[k]->dv_hash, 32) == 0 && !all_zero32(ta->seg[k]->dv_hash));
    imdb_verify_report vr;
    imdb_err_clear(E);
    CHECK(imdb_verify(b, &vr, E) == 0);
    imdb_session_close(&sa);
    imdb_session_close(&sb);
    OK(imdb_close(a));
    OK(imdb_close(b));
}

/* The least recently pinned leave first. Three segments of equal size and a budget of one image: a key read pins
 * its row's segment alone, so after each statement exactly that segment's image is in memory. */
static void t_segcache_lru(void)
{
    const char *dir = test_tmpdir();
    OK(imdb_init(dir, false, NULL, E));
    imdb_db *db = copen(dir, UINT64_MAX);
    CHECK(db);
    if (!db) return;
    imdb_session s;
    imdb_session_init(&s, db);
    OK(ex(&s, "CREATE TABLE t (id INT64 PRIMARY KEY, v INT64)"));
    char sql[96];
    for (int g = 0; g < 3; g++) {
        OK(ex(&s, "BEGIN"));
        for (int i = 0; i < 100; i++) {
            snprintf(sql, sizeof sql, "INSERT INTO t VALUES (%d, %d)", g * 100 + i, i);
            OK(ex(&s, sql));
        }
        OK(ex(&s, "COMMIT"));
        OK(ex(&s, "CHECKPOINT"));
    }
    imdb_table *t = imdb_table_by_name(db, "t");
    CHECK(t && t->nseg == 3);
    if (!t || t->nseg != 3) goto out;
    db->segcache.budget = 0;
    OK(ex(&s, "SELECT v FROM t WHERE id = 150"));
    CHECK(resident_images(t) == 0 && db->segcache.resident == 0);
    uint64_t loads = db->segcache.loads;
    db->segcache.budget = UINT64_MAX;
    OK(ex(&s, "SELECT v FROM t WHERE id = 150")); /* segment 1 alone */
    CHECK(db->segcache.loads == loads + 1 && resident_images(t) == 1 && imdb_seg_resident(t, t->seg[1]));
    db->segcache.budget = db->segcache.resident; /* one image's bytes: they are all the same size */
    OK(ex(&s, "SELECT v FROM t WHERE id = 50")); /* segment 0 loads; segment 1 was pinned before it: it leaves */
    CHECK(db->segcache.loads == loads + 2 && resident_images(t) == 1 && imdb_seg_resident(t, t->seg[0]));
    OK(ex(&s, "SELECT v FROM t WHERE id = 250"));
    CHECK(db->segcache.loads == loads + 3 && resident_images(t) == 1 && imdb_seg_resident(t, t->seg[2]));
    OK(ex(&s, "SELECT v FROM t WHERE id = 251")); /* in memory: no load, and it stays */
    CHECK(db->segcache.loads == loads + 3 && imdb_seg_resident(t, t->seg[2]));
    imdb_result r;
    OK(imdb_exec_one(&s, "SHOW MEMORY", 11, NULL, 0, &r, E));
    char want[120];
    snprintf(want, sizeof want, "; %llu loaded since the open (", (unsigned long long)db->segcache.loads);
    CHECK(strstr(r.status, want) != NULL && strstr(r.status, "segment images ") != NULL);
    imdb_result_free(&r);
out:
    imdb_session_close(&s);
    imdb_close(db);
}

static long refuse_rename(imdb_io_call *c, void *ctx)
{
    (void)ctx;
    return c->op == IMDB_IO_RENAME ? -1 : 0;
}

static const imdb_io_hooks g_no_rename = {refuse_rename, NULL, NULL};

/* An image that is the only copy never leaves. An ERASE installs a rewritten lake in memory and publishes it once
 * the log is redacted; with the redaction refused (its rename), the rewritten segments are written nowhere yet, so
 * at a budget of none they stay, the reads keep working without the erased rows, and once a reopen completes the
 * redaction and the publish, they leave like any other. */
static void t_segcache_unwritten_kept(void)
{
    char dir[512];
    snprintf(dir, sizeof dir, "%s", test_tmpdir());
    OK(imdb_init(dir, false, NULL, E));
    imdb_db *db = copen(dir, UINT64_MAX);
    CHECK(db);
    if (!db) return;
    imdb_session s;
    imdb_session_init(&s, db);
    OK(ex(&s, "CREATE TABLE t (id INT64 PRIMARY KEY, u INT64 SUBJECT, v INT64)"));
    char sql[96];
    OK(ex(&s, "BEGIN"));
    for (int i = 0; i < 60; i++) {
        snprintf(sql, sizeof sql, "INSERT INTO t VALUES (%d, %d, %d)", i, i % 6, i);
        OK(ex(&s, sql));
    }
    OK(ex(&s, "COMMIT"));
    OK(ex(&s, "CHECKPOINT"));
    db->segcache.budget = 0;
    OK(ex(&s, "SELECT COUNT(*) FROM t"));
    imdb_table *t = imdb_table_by_name(db, "t");
    CHECK(t && resident_images(t) == 0);
    imdb_io_set_hooks(&g_no_rename);
    int rc = ex(&s, "ERASE SUBJECT 3"); /* committed; its redaction and its lake's publication wait */
    imdb_io_set_hooks(NULL);
    CHECK(rc == 0 && db->needs_redaction && db->lake_pending && !db->failed);
    CHECK(t && t->nseg >= 1 && resident_images(t) == t->nseg); /* the rewritten segments: nowhere else yet */
    uint64_t loads = db->segcache.loads; /* the ERASE read the old segment: it had left at the budget of none */
    for (uint32_t k = 0; t && k < t->nseg; k++) CHECK(!t->seg[k]->ondisk);
    imdb_result r;
    OK(imdb_exec_one(&s, "SELECT COUNT(*), SUM(v) FROM t", 30, NULL, 0, &r, E));
    CHECK(r.nrows == 1 && r.cells[0].v.i == 50); /* the subject's ten rows are gone from the answer */
    imdb_result_free(&r);
    CHECK(t && resident_images(t) == t->nseg && db->segcache.loads == loads); /* read in memory: never left */
    imdb_session_close(&s);
    OK(imdb_close(db));
    db = copen(dir, 0); /* the open completes the redaction, then the publish: written, they may leave */
    CHECK(db);
    if (!db) return;
    CHECK(!db->needs_redaction && !db->lake_pending);
    imdb_session_init(&s, db);
    OK(ex(&s, "SELECT COUNT(*) FROM t"));
    t = imdb_table_by_name(db, "t");
    CHECK(t && resident_images(t) == 0 && db->segcache.resident == 0);
    for (uint32_t k = 0; t && k < t->nseg; k++) CHECK(t->seg[k]->ondisk);
    imdb_verify_report vr;
    OK(imdb_verify(db, &vr, E));
    imdb_session_close(&s);
    OK(imdb_close(db));
}

/* A load that fails is an error, never an empty or a partial answer, and never stops the handle: the segment's
 * file moved away, then a damaged one (its bytes no longer its name), refuse every read and write that needs it;
 * once the file is back the same statements answer. */
static void t_segcache_load_fails(void)
{
    char dir[512], from[700], to[700], cmd[1600];
    snprintf(dir, sizeof dir, "%s", test_tmpdir());
    OK(imdb_init(dir, false, NULL, E));
    imdb_db *db = copen(dir, UINT64_MAX);
    CHECK(db);
    if (!db) return;
    imdb_session s;
    imdb_session_init(&s, db);
    OK(ex(&s, "CREATE TABLE t (id INT64 PRIMARY KEY, v INT64, s TEXT NOT NULL)"));
    char sql[96];
    OK(ex(&s, "BEGIN"));
    for (int i = 0; i < 50; i++) {
        snprintf(sql, sizeof sql, "INSERT INTO t VALUES (%d, %d, 'row %d')", i, i, i);
        OK(ex(&s, sql));
    }
    OK(ex(&s, "COMMIT"));
    OK(ex(&s, "CHECKPOINT"));
    imdb_table *t = imdb_table_by_name(db, "t");
    CHECK(t && t->nseg == 1);
    if (!t || t->nseg != 1) goto out;
    db->segcache.budget = 0;
    OK(ex(&s, "SELECT COUNT(*) FROM t"));
    CHECK(resident_images(t) == 0);
    char hex[65];
    imdb_hex(t->seg[0]->hash, 32, hex);
    snprintf(from, sizeof from, "%s/objects/%s.seg", dir, hex);
    snprintf(to, sizeof to, "%s/objects/%s.away", dir, hex);
    static const char *const needs[] = {"SELECT COUNT(*), SUM(v) FROM t", "SELECT s FROM t WHERE id = 3",
                                        "SHOW HISTORY t 3", "UPDATE t SET v = 1 WHERE id = 3",
                                        "DELETE FROM t WHERE id = 4"};
    for (int round = 0; round < 2; round++) {
        if (round == 0) {
            CHECK(rename(from, to) == 0);
        } else { /* a copy with one byte changed in its place */
            snprintf(cmd, sizeof cmd, "cp '%s' '%s' && printf 'X' | dd of='%s' bs=1 seek=100 conv=notrunc 2>/dev/null",
                     to, from, from);
            CHECK(system(cmd) == 0);
        }
        for (size_t i = 0; i < sizeof needs / sizeof *needs; i++) {
            imdb_result r;
            imdb_err e = {0};
            int rc = imdb_exec_one(&s, needs[i], strlen(needs[i]), NULL, 0, &r, &e);
            CHECK(rc != 0);
            if (!rc) {
                fprintf(stderr, "    answered without its segment: %s\n", needs[i]);
                imdb_result_free(&r);
            }
            CHECK(!db->failed && !db->in_txn);
        }
        CHECK(resident_images(t) == 0);
        if (round == 1) CHECK(unlink(from) == 0);
    }
    CHECK(rename(to, from) == 0);
    imdb_result r;
    OK(imdb_exec_one(&s, "SELECT COUNT(*), SUM(v) FROM t", 30, NULL, 0, &r, E));
    CHECK(r.nrows == 1 && r.cells[0].v.i == 50 && r.cells[1].wide && r.cells[1].i128 == 49 * 50 / 2); /* SUM: wide */
    imdb_result_free(&r);
    OK(ex(&s, "UPDATE t SET v = 1 WHERE id = 3"));
    OK(ex(&s, "DELETE FROM t WHERE id = 4"));
    imdb_verify_report vr;
    OK(imdb_verify(db, &vr, E));
out:
    imdb_session_close(&s);
    imdb_close(db);
}

/* imdb_par_for's workers load at once: the digest recompute reads each held version's commitment, its segment
 * row's, in parallel parts. Each segment loads once (a worker that waited finds the other's image), the count says
 * so, and the state check passes. */
static void t_segcache_parallel_loads(void)
{
    const char *dir = test_tmpdir();
    OK(imdb_init(dir, false, NULL, E));
    imdb_db *db = copen(dir, UINT64_MAX);
    CHECK(db);
    if (!db) return;
    imdb_session s;
    imdb_session_init(&s, db);
    OK(ex(&s, "CREATE TABLE t (id INT64 PRIMARY KEY, v INT64)"));
    char sql[96];
    for (int g = 0; g < 8; g++) {
        OK(ex(&s, "BEGIN"));
        for (int i = 0; i < 400; i++) {
            snprintf(sql, sizeof sql, "INSERT INTO t VALUES (%d, %d)", g * 400 + i, i);
            OK(ex(&s, sql));
        }
        OK(ex(&s, "COMMIT"));
        OK(ex(&s, "CHECKPOINT"));
    }
    imdb_table *t = imdb_table_by_name(db, "t");
    CHECK(t && t->nseg == 8);
    db->segcache.budget = 0;
    OK(ex(&s, "SELECT COUNT(*) FROM t WHERE id = 1"));
    CHECK(t && resident_images(t) == 0);
    for (int round = 0; round < 3; round++) {
        uint64_t loads = db->segcache.loads;
        OK(imdb_check_state(db, E));
        CHECK(db->segcache.loads == loads + 8 && t && resident_images(t) == 0);
    }
    imdb_session_close(&s);
    imdb_close(db);
}

/* (b2) A publish reads only what changed. Four segments at a budget of none: a CHECKPOINT with no end since the last
 * publish loads no image (every deletion vector stands by its hash, lake_persist skips what is on disk, the held
 * versions keep their places by their segments' positions); after an end in one segment, the CHECKPOINT loads that
 * segment alone, to make its vector again. The answers, VERIFY and a reopen agree. */
static void t_segcache_publish_loads(void)
{
    char dir[512];
    snprintf(dir, sizeof dir, "%s", test_tmpdir());
    OK(imdb_init(dir, false, NULL, E));
    imdb_db *db = copen(dir, UINT64_MAX);
    CHECK(db);
    if (!db) return;
    imdb_session s;
    imdb_session_init(&s, db);
    OK(ex(&s, "CREATE TABLE t (id INT64 PRIMARY KEY, v INT64)"));
    char sql[96];
    for (int g = 0; g < 4; g++) {
        OK(ex(&s, "BEGIN"));
        for (int i = 0; i < 100; i++) {
            snprintf(sql, sizeof sql, "INSERT INTO t VALUES (%d, %d)", g * 100 + i, i);
            OK(ex(&s, sql));
        }
        OK(ex(&s, "COMMIT"));
        OK(ex(&s, "CHECKPOINT"));
    }
    imdb_table *t = imdb_table_by_name(db, "t");
    CHECK(t && t->nseg == 4);
    db->segcache.budget = 0;
    OK(ex(&s, "SELECT COUNT(*) FROM t"));
    CHECK(resident_images(t) == 0);
    uint64_t loads = db->segcache.loads;
    OK(ex(&s, "INSERT INTO t VALUES (1000, 1)"));
    OK(ex(&s, "CHECKPOINT")); /* a fifth segment, built: nothing read */
    CHECK(t->nseg == 5 && db->segcache.loads == loads);
    OK(ex(&s, "UPDATE t SET v = 7 WHERE id = 250")); /* its old row is segment 2's: read, and its end goes in */
    CHECK(db->segcache.loads == loads + 1 && t->seg[2]->dv_stale);
    OK(ex(&s, "CHECKPOINT")); /* segment 2's vector made again: that segment alone */
    CHECK(db->segcache.loads == loads + 2 && !t->seg[2]->dv_stale && t->nseg == 6);
    for (uint32_t k = 0; k < t->nseg; k++) CHECK(t->seg[k]->ondisk && t->seg[k]->seg_ondisk);
    imdb_result r;
    for (int q = 0; q < 2; q++) { /* the updated row, and the row the first CHECKPOINT flushed */
        const char *sq = q ? "SELECT v FROM t WHERE id = 1000" : "SELECT v FROM t WHERE id = 250";
        OK(imdb_exec_one(&s, sq, strlen(sq), NULL, 0, &r, E));
        CHECK(r.nrows == 1 && r.cells[0].v.i == (q ? 1 : 7));
        imdb_result_free(&r);
    }
    imdb_verify_report vr;
    imdb_err_clear(E);
    CHECK(imdb_verify(db, &vr, E) == 0);
    imdb_session_close(&s);
    OK(imdb_close(db));
    db = copen(dir, 0);
    CHECK(db);
    if (!db) return;
    imdb_session_init(&s, db);
    for (int q = 0; q < 2; q++) { /* the updated row, and the row the first CHECKPOINT flushed */
        const char *sq = q ? "SELECT v FROM t WHERE id = 1000" : "SELECT v FROM t WHERE id = 250";
        OK(imdb_exec_one(&s, sq, strlen(sq), NULL, 0, &r, E));
        CHECK(r.nrows == 1 && r.cells[0].v.i == (q ? 1 : 7));
        imdb_result_free(&r);
    }
    imdb_session_close(&s);
    OK(imdb_close(db));
}

static int64_t first_cell(imdb_session *s, const char *sql)
{
    imdb_result r;
    imdb_err e = {0};
    if (imdb_exec_one(s, sql, strlen(sql), NULL, 0, &r, &e)) return -1;
    int64_t v = r.nrows != 1 ? -2 : r.cells[0].wide ? (int64_t)r.cells[0].i128 : r.cells[0].v.i;
    imdb_result_free(&r);
    return v;
}

/* (b2) An eviction pass reads no key: at a budget of none, with versions to evict in old segments, an ordered index,
 * a unique index and a subject whose every version leaves, it loads no image (the PK map, the unique maps and the
 * subjects are pruned by vid, the ordered structure filtered by vid). What stays answers, and what left is the
 * lake's (evict's own tests compare whole workloads evicting and not). */
static void t_segcache_evict_loads(void)
{
    char dir[512], sql[128];
    snprintf(dir, sizeof dir, "%s", test_tmpdir());
    OK(imdb_init(dir, false, NULL, E));
    imdb_db *db = copen(dir, UINT64_MAX);
    CHECK(db);
    if (!db) return;
    imdb_session s;
    imdb_session_init(&s, db);
    OK(ex(&s, "CREATE TABLE t (id INT64 PRIMARY KEY, u INT64 SUBJECT, v INT64, w INT64 NULL)"));
    OK(ex(&s, "CREATE INDEX t_v ON t (v)"));
    OK(ex(&s, "CREATE UNIQUE INDEX t_w ON t (w)"));
    OK(ex(&s, "BEGIN"));
    for (int i = 0; i < 300; i++) {
        snprintf(sql, sizeof sql, "INSERT INTO t VALUES (%d, %d, %d, %d)", i, i % 10, i, i);
        OK(ex(&s, sql));
    }
    OK(ex(&s, "COMMIT"));
    OK(ex(&s, "CHECKPOINT"));
    uint64_t before = db->seq;
    OK(ex(&s, "BEGIN"));
    for (int i = 0; i < 150; i++) {
        snprintf(sql, sizeof sql, "UPDATE t SET v = %d WHERE id = %d", i + 1000, i);
        OK(ex(&s, sql));
    }
    for (int i = 9; i < 300; i += 10) { /* subject 9: every version of it ends */
        snprintf(sql, sizeof sql, "DELETE FROM t WHERE id = %d", i);
        OK(ex(&s, sql));
    }
    OK(ex(&s, "COMMIT"));
    OK(ex(&s, "CHECKPOINT")); /* the ends published: the old versions may leave */
    imdb_table *t = imdb_table_by_name(db, "t");
    CHECK(t);
    if (!t) goto out;
    db->segcache.budget = 0;
    OK(ex(&s, "SELECT COUNT(*) FROM t"));
    CHECK(resident_images(t) == 0);
    uint64_t loads = db->segcache.loads, held = t->nheld;
    OK(imdb_evict(db, db->lake_seq, E));
    CHECK(t->nheld + 150 + 30 == held && db->segcache.loads == loads); /* 180 left memory, no image read */
    CHECK(first_cell(&s, "SELECT COUNT(*) FROM t WHERE v >= 1000") == 135); /* the ordered index: 150 less subject 9's 15 */
    CHECK(first_cell(&s, "SELECT id FROM t WHERE w = 77") == 77);           /* the unique index */
    CHECK(first_cell(&s, "SELECT COUNT(*) FROM t WHERE u = 9") == 0);       /* the subject left with every version */
    CHECK(first_cell(&s, "SELECT COUNT(*) FROM t WHERE u = 3") == 30);
    snprintf(sql, sizeof sql, "SELECT COUNT(*) FROM t AS OF %llu WHERE u = 9", (unsigned long long)before);
    CHECK(first_cell(&s, sql) == 30); /* below the floor: the lake */
    snprintf(sql, sizeof sql, "SELECT v FROM t AS OF %llu WHERE id = 5", (unsigned long long)before);
    CHECK(first_cell(&s, sql) == 5);
    OK(ex(&s, "INSERT INTO t VALUES (1000, 9, 1, 1009)")); /* a key and a subject again, after they left */
    CHECK(first_cell(&s, "SELECT COUNT(*) FROM t WHERE u = 9") == 1);
    CHECK(ex(&s, "INSERT INTO t VALUES (1001, 1, 1, 77)") != 0); /* w = 77 is still taken: the unique map kept it */
    imdb_verify_report vr;
    imdb_err_clear(E);
    CHECK(imdb_verify(db, &vr, E) == 0);
out:
    imdb_session_close(&s);
    imdb_close(db);
}

/* (b2) RETIRE reads only the segments its boundary splits: from each descriptor's end marks, a segment whose rows all
 * ended at or before the boundary leaves whole, one with none leaves nothing, unread. Four segments at a budget of
 * none: S0 straddles (rows ended before B, after it, and live), S1's rows all ended before B, S2's and S3's are live:
 * the RETIRE loads one image, its indexes (ordered, unique, PK, subject) pruned and filtered by vid: no key read.
 * The rows it keeps answer by each index, the dropped ones are gone, VERIFY agrees. */
static void t_segcache_retire_loads(void)
{
    char dir[512], sql[128];
    snprintf(dir, sizeof dir, "%s", test_tmpdir());
    OK(imdb_init(dir, false, NULL, E));
    imdb_db *db = copen(dir, UINT64_MAX);
    CHECK(db);
    if (!db) return;
    db->no_auto_retire = true; /* this RETIRE is the test's own */
    imdb_session s;
    imdb_session_init(&s, db);
    OK(ex(&s, "CREATE TABLE a (id INT64 PRIMARY KEY, u INT64 SUBJECT, v INT64, w INT64 NULL) RETENTION 10 SECONDS"));
    OK(ex(&s, "CREATE INDEX a_v ON a (v)"));
    OK(ex(&s, "CREATE UNIQUE INDEX a_w ON a (w)"));
    for (int g = 0; g < 2; g++) { /* S0: ids 1..100; S1: ids 101..200 */
        OK(ex(&s, "BEGIN"));
        for (int i = 1; i <= 100; i++) {
            snprintf(sql, sizeof sql, "INSERT INTO a VALUES (%d, %d, 0, %d)", g * 100 + i, (g * 100 + i) % 7, g * 100 + i);
            OK(ex(&s, sql));
        }
        OK(ex(&s, "COMMIT"));
        OK(ex(&s, "CHECKPOINT"));
    }
    OK(ex(&s, "BEGIN")); /* every row of S1 and half of S0 end before B */
    for (int i = 1; i <= 200; i++) {
        if (i > 50 && i <= 100) continue;
        snprintf(sql, sizeof sql, "UPDATE a SET v = 1 WHERE id = %d", i);
        OK(ex(&s, sql));
    }
    OK(ex(&s, "COMMIT"));
    OK(ex(&s, "CHECKPOINT")); /* S2: their new versions; this commit ends a log segment: B */
    uint64_t B = db->seq;
    OK(ex(&s, "BEGIN")); /* ten rows of S0 end after B */
    for (int i = 51; i <= 60; i++) {
        snprintf(sql, sizeof sql, "UPDATE a SET v = 2 WHERE id = %d", i);
        OK(ex(&s, sql));
    }
    OK(ex(&s, "COMMIT"));
    OK(ex(&s, "CHECKPOINT")); /* S3 */
    imdb_table *t = imdb_table_by_name(db, "a");
    CHECK(t && t->nseg == 4);
    if (!t || t->nseg != 4) goto out;
    CHECK(imdb_seg_ended_by(t->seg[0], B) == -1 && imdb_seg_ended_by(t->seg[1], B) == 100 &&
          imdb_seg_ended_by(t->seg[2], B) == 0 && imdb_seg_ended_by(t->seg[3], B) == 0);
    imdb_clock_offset(15 * 1000000ll);
    OK(ex(&s, "SELECT COUNT(*) FROM a")); /* the policy's EXPIRE moves the horizon past B */
    CHECK(t->horizon > B);
    db->segcache.budget = 0;
    OK(ex(&s, "SELECT COUNT(*) FROM a"));
    CHECK(resident_images(t) == 0);
    uint64_t loads = db->segcache.loads;
    OK(imdb_retire(db, B, E));
    CHECK(db->segcache.loads == loads + 1); /* S0 alone: S1 left whole, S2 and S3 stayed whole, unread */
    CHECK(t->nseg == 3); /* S0 rewritten without its 50 rows ended before B, S1 gone */
    CHECK(first_cell(&s, "SELECT COUNT(*) FROM a") == 200);
    CHECK(first_cell(&s, "SELECT v FROM a WHERE id = 55") == 2 && first_cell(&s, "SELECT v FROM a WHERE id = 150") == 1);
    CHECK(first_cell(&s, "SELECT COUNT(*) FROM a WHERE v = 2") == 10 && first_cell(&s, "SELECT COUNT(*) FROM a WHERE v = 1") == 150);
    CHECK(first_cell(&s, "SELECT id FROM a WHERE w = 123") == 123 && first_cell(&s, "SELECT COUNT(*) FROM a WHERE u = 3") == 29);
    CHECK(ex(&s, "INSERT INTO a VALUES (500, 1, 9, 77)") != 0); /* w = 77 still taken: its unique key stayed */
    imdb_verify_report vr;
    imdb_err_clear(E);
    CHECK(imdb_verify(db, &vr, E) == 0);
out:
    imdb_session_close(&s);
    imdb_close(db);
}

static uint64_t g_mod, g_rem;
static bool keep_val(void *ctx, uint64_t val)
{
    (void)ctx;
    return val % g_mod != g_rem;
}

static void hp_key(int text, uint64_t i, char *buf, size_t n, imdb_value *k)
{
    memset(k, 0, sizeof *k);
    if (text) {
        k->type = IMDB_T_TEXT;
        k->len = (uint32_t)snprintf(buf, n, "key-%llu", (unsigned long long)(i * 7919));
        k->s = (const uint8_t *)buf;
    } else {
        k->type = IMDB_T_INT64;
        k->i = (int64_t)(i * 2654435761u);
    }
}

/* (b2) imdb_hmap_prune, against a model: a removal shifts a later entry of its cluster back into the slot, so the walk
 * looks at that slot again; small tables make clusters that wrap past the end. Every kept key is found with its
 * value, every pruned one is gone, the count is exact (INT64 and TEXT keys, sizes 1 to 4097, several patterns). */
static void t_segcache_hmap_prune(void)
{
    static const uint64_t sizes[] = {1, 2, 7, 8, 9, 63, 64, 65, 1000, 4097};
    char buf[32];
    for (int text = 0; text < 2; text++)
        for (size_t si = 0; si < sizeof sizes / sizeof *sizes; si++)
            for (g_mod = 2; g_mod <= 3; g_mod++)
                for (g_rem = 0; g_rem < g_mod; g_rem++) {
                    uint64_t n = sizes[si];
                    imdb_hmap m;
                    OK(imdb_hmap_init(&m, text ? IMDB_T_TEXT : IMDB_T_INT64, E));
                    imdb_value k;
                    int rc = IMDB_OK;
                    for (uint64_t i = 0; i < n && !rc; i++) {
                        hp_key(text, i, buf, sizeof buf, &k);
                        rc = imdb_hmap_put(&m, &k, i, E);
                    }
                    size_t removed = rc ? 0 : imdb_hmap_prune(&m, keep_val, NULL), want = 0;
                    for (uint64_t i = 0; i < n; i++) want += i % g_mod == g_rem;
                    bool ok = !rc && removed == want && m.count == n - want;
                    for (uint64_t i = 0; i < n && ok; i++) {
                        hp_key(text, i, buf, sizeof buf, &k);
                        uint64_t *v = imdb_hmap_get(&m, &k);
                        ok = (i % g_mod == g_rem) ? v == NULL : (v && *v == i);
                    }
                    imdb_hmap_free(&m);
                    CHECK(ok);
                }
}


/* ---- 3c-2: the open streams ------------------------------------------------------------------------------------- */

static imdb_db *sopen(const char *dir, uint64_t budget, bool ro)
{
    imdb_open_opts o = {.sync = 0, .mem_window_us = UINT64_MAX, .seg_cache_bytes = budget, .read_only = ro};
    imdb_db *db = NULL;
    imdb_err_clear(E);
    return imdb_open(dir, &o, &db, E) ? NULL : db;
}

/* the most segments one chunk of 2^16 vids overlaps: phase 2 holds those while it counts the chunk's rows */
static uint64_t chunk_span(const imdb_table *t)
{
    uint64_t most = 0;
    for (uint64_t k = 0; k <= (t->nver >> IMDB_VCHUNK_BITS); k++) {
        uint64_t lo = k << IMDB_VCHUNK_BITS, hi = lo + (1u << IMDB_VCHUNK_BITS) - 1, n = 0;
        for (uint32_t s = 0; s < t->nseg; s++) n += t->seg[s]->vid_first <= hi && t->seg[s]->vid_last >= lo;
        if (n > most) most = n;
    }
    return most;
}


/* An open holds what it keeps, the budget and the images in hand, not the whole lake (3c-2): ten segments of 9,000
 * rows (a 300-byte TEXT each), a unique and an ordered index, and a tail of updates, deletes and inserts after the
 * last publish (in one segment: a replayed commit holds the segments it touches until it ends, as it did when it ran),
 * which the open replays. Opened with every image kept and with a budget of one byte, writable and
 * read-only: the same view token and answers each time, and the streaming opens' peak within the images one chunk
 * of 2^16 versions spans (phase 2 counts a chunk's rows before it places them) and two more, against the whole lake's
 * when every image is kept; each segment read a bounded number of times */
static void t_segcache_open_streams(void)
{
    const char *dir = test_tmpdir();
    OK(imdb_init(dir, false, NULL, E));
    imdb_db *db = sopen(dir, UINT64_MAX, false);
    CHECK(db);
    if (!db) return;
    imdb_session s;
    imdb_session_init(&s, db);
    OK(ex(&s, "CREATE TABLE t (id INT64 PRIMARY KEY, a INT64 NOT NULL, s TEXT)"));
    OK(ex(&s, "CREATE UNIQUE INDEX t_a ON t (a)"));
    OK(ex(&s, "CREATE INDEX t_s ON t (s)"));
    imdb_buf b;
    imdb_buf_init(&b);
    for (int seg = 0; seg < 10; seg++) {
        for (int part = 0; part < 3; part++) {
            b.len = 0;
            imdb_buf_put_str(&b, "INSERT INTO t VALUES ");
            for (int i = 0; i < 3000; i++) {
                int id = seg * 9000 + part * 3000 + i + 1;
                imdb_buf_printf(&b, "%s(%d, %d, '%0300d')", i ? ", " : "", id, 1000000 - id, id);
            }
            OK(imdb_buf_check(&b, E));
            imdb_result r;
            imdb_err_clear(E);
            OK(imdb_exec_one(&s, (const char *)b.p, b.len, NULL, 0, &r, E));
            imdb_result_free(&r);
        }
        OK(ex(&s, "CHECKPOINT"));
    }
    imdb_buf_free(&b);
    OK(ex(&s, "UPDATE t SET a = a + 2000000 WHERE id % 97 = 0 AND id < 9000")); /* the tail: one segment's versions ended */
    OK(ex(&s, "DELETE FROM t WHERE id % 89 = 0 AND id > 81000"));
    OK(ex(&s, "INSERT INTO t VALUES (100001, 1, 'tail'), (100002, 2, 'tail')"));
    imdb_session_close(&s);
    imdb_close(db);
    static const char *const q[] = {"SELECT COUNT(*), SUM(a) FROM t", "SELECT id FROM t WHERE a = 1000000 - 4500",
                                    "SELECT COUNT(*) FROM t WHERE s >= '000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000045000'",
                                    "SELECT id FROM t WHERE id = 89", "SELECT COUNT(*) FROM t WHERE a > 2000000"};
    uint8_t tok[3][32];
    imdb_buf ans[3];
    uint64_t peak[3] = {0}, loads[3] = {0}, largest = 0, nseg = 0, span = 0;
    for (int run = 0; run < 3; run++) { /* every image kept; a budget of one byte; the same, read-only */
        db = sopen(dir, run ? 1 : UINT64_MAX, run == 2);
        CHECK(db);
        if (!db) return;
        peak[run] = db->segcache.peak;
        loads[run] = db->segcache.loads;
        if (run == 0) /* every image resident: the largest, as the cache counts it */
            for (uint32_t k = 0; k < db->t[0]->nseg; k++)
                if (imdb_seg_image_bytes(db->t[0]->seg[k]) > largest) largest = imdb_seg_image_bytes(db->t[0]->seg[k]);
        nseg = db->t[0]->nseg;
        span = chunk_span(db->t[0]);
        OK(imdb_view_token(db, tok[run], E));
        imdb_buf_init(&ans[run]);
        imdb_session_init(&s, db);
        imdb_buf o;
        imdb_buf_init(&o);
        for (size_t i = 0; i < sizeof q / sizeof *q; i++) {
            outcome(&s, q[i], &o);
            imdb_buf_put(&ans[run], o.p, o.len);
        }
        imdb_buf_free(&o);
        imdb_session_close(&s);
        imdb_verify_report vr;
        memset(&vr, 0, sizeof vr);
        OK(imdb_verify(db, &vr, E));
        imdb_close(db);
    }
    if (getenv("IMDB_SEGCACHE_DEBUG")) fprintf(stderr, "    peaks %llu %llu %llu, largest image bound %llu, loads %llu %llu %llu, segments %llu\n", (unsigned long long)peak[0],
            (unsigned long long)peak[1], (unsigned long long)peak[2], (unsigned long long)largest, (unsigned long long)loads[0],
            (unsigned long long)loads[1], (unsigned long long)loads[2], (unsigned long long)nseg);
    CHECK(nseg == 10);
    for (int run = 1; run < 3; run++) {
        CHECK(!memcmp(tok[0], tok[run], 32));
        CHECK(ans[0].len == ans[run].len && !memcmp(ans[0].p, ans[run].p, ans[0].len));
        /* the segments one chunk spans while phase 2 counts it, the one in hand and the replayed commit's one */
        CHECK(peak[run] <= (span + 2) * largest);
        CHECK(peak[run] < peak[0] * 9 / 10 + 1);
        CHECK(loads[run] <= 6 * nseg); /* phase 2, the reindex, the unique and the ordered builds, the replay */
    }
    if (peak[1] > (span + 2) * largest || loads[1] > 6 * nseg)
        fprintf(stderr, "    peaks %llu %llu %llu, largest image bound %llu, loads %llu %llu\n", (unsigned long long)peak[0],
                (unsigned long long)peak[1], (unsigned long long)peak[2], (unsigned long long)largest,
                (unsigned long long)loads[1], (unsigned long long)loads[2]);
    for (int run = 0; run < 3; run++) imdb_buf_free(&ans[run]);
}

/* ---- P2 S14, the 2026-11-05 review's O4: a cold image read outside the cache's lock, one load an image ---- */

/* the load hook: each load held between its read and its publication until the test lets its segment go */
static struct {
    pthread_mutex_t m;
    pthread_cond_t cv;
    const imdb_segment *go[8];
    int nheld, ngo, calls;
} H = {PTHREAD_MUTEX_INITIALIZER, PTHREAD_COND_INITIALIZER, {0}, 0, 0, 0};

static bool h_gone(const imdb_segment *g)
{
    for (int i = 0; i < H.ngo; i++)
        if (H.go[i] == g) return true;
    return false;
}

static void hold_hook(const imdb_segment *g, void *ctx)
{
    (void)ctx;
    pthread_mutex_lock(&H.m);
    H.calls++;
    H.nheld++;
    pthread_cond_broadcast(&H.cv);
    while (!h_gone(g)) pthread_cond_wait(&H.cv, &H.m);
    pthread_mutex_unlock(&H.m);
}

static void h_reset(void)
{
    pthread_mutex_lock(&H.m);
    H.nheld = H.ngo = H.calls = 0;
    pthread_mutex_unlock(&H.m);
}

static void h_wait_held(int n) /* until n loads have read and are held */
{
    pthread_mutex_lock(&H.m);
    while (H.nheld < n) pthread_cond_wait(&H.cv, &H.m);
    pthread_mutex_unlock(&H.m);
}

static void h_let_go(const imdb_segment *g)
{
    pthread_mutex_lock(&H.m);
    if (H.ngo < 8) H.go[H.ngo++] = g;
    pthread_cond_broadcast(&H.cv);
    pthread_mutex_unlock(&H.m);
}

static int h_calls(void)
{
    pthread_mutex_lock(&H.m);
    int n = H.calls;
    pthread_mutex_unlock(&H.m);
    return n;
}

static void wait_waits(imdb_db *db, uint64_t n) /* until the cache has counted n pins waiting for another's load */
{
    for (;;) {
        pthread_mutex_lock(&db->segcache.lock);
        uint64_t w = db->segcache.load_waits;
        pthread_mutex_unlock(&db->segcache.lock);
        if (w >= n) return;
        usleep(1000);
    }
}

typedef struct pinner {
    const imdb_table *t;
    imdb_segment *g;
    imdb_segimg *gi;
    imdb_err e;
    pthread_t th;
} pinner;

static void *pin_main(void *arg)
{
    pinner *p = arg;
    p->gi = imdb_seg_pin(p->t, p->g, &p->e);
    return NULL;
}

static bool pin_start(pinner *p, const imdb_table *t, imdb_segment *g)
{
    memset(p, 0, sizeof *p);
    p->t = t;
    p->g = g;
    return pthread_create(&p->th, NULL, pin_main, p) == 0;
}

/* an I/O or allocation failure in a load, after its object opened (the fault hooks: no other thread in the engine
 * while they are set, but the test's own pinners, one of which reads) */
static struct {
    int op, seen_open, failed;
} F;

static long fail_mid(imdb_io_call *c, void *ctx)
{
    (void)ctx;
    if (F.failed) return 0;
    if (c->op == IMDB_IO_OPEN && c->name && strstr(c->name, ".seg")) {
        F.seen_open = 1;
        return 0;
    }
    if (F.seen_open && c->op == F.op) {
        F.failed = 1;
        errno = F.op == IMDB_IO_ALLOC ? ENOMEM : EIO;
        return -1;
    }
    return 0;
}

/* Two cold segments pinned by four threads: each load held after its read (the hook) until the test has seen a second
 * pin of the same segment wait for it, the other segment's load running meanwhile; the loads let go in the other order
 * than they began. Each segment loads once, and every pin of it has that one image. Then loads that fail (the object
 * away, a read failing after its open, an allocation failing after it): the worker waiting takes the loader's error
 * whole (its code and message, as its own read would have said), a third pin in that operation the same without
 * reading, and the next operation reads again */
static void t_segcache_one_load(void)
{
    char dir[512], from[700], to[700];
    snprintf(dir, sizeof dir, "%s", test_tmpdir());
    OK(imdb_init(dir, false, NULL, E));
    imdb_db *db = copen(dir, UINT64_MAX);
    CHECK(db);
    if (!db) return;
    imdb_session s;
    imdb_session_init(&s, db);
    OK(ex(&s, "CREATE TABLE t (id INT64 PRIMARY KEY, v INT64)"));
    char sql[96];
    for (int k = 0; k < 2; k++) {
        OK(ex(&s, "BEGIN"));
        for (int i = 0; i < 200; i++) {
            snprintf(sql, sizeof sql, "INSERT INTO t VALUES (%d, %d)", k * 200 + i, i);
            OK(ex(&s, sql));
        }
        OK(ex(&s, "COMMIT"));
        OK(ex(&s, "CHECKPOINT"));
    }
    imdb_table *t = imdb_table_by_name(db, "t");
    CHECK(t && t->nseg == 2);
    if (!t || t->nseg != 2) goto out;
    db->segcache.budget = 0;
    OK(ex(&s, "SELECT COUNT(*) FROM t WHERE id = 1")); /* an operation ends: at a budget of none every image leaves */
    CHECK(resident_images(t) == 0);
    imdb_segment *A = t->seg[0], *B = t->seg[1];
    pinner p[4];
    h_reset();
    imdb_seg_load_hook(hold_hook, NULL);
    uint64_t loads0 = db->segcache.loads, waits0 = db->segcache.load_waits;
    imdb_op_enter(db);
    CHECK(pin_start(&p[0], t, A));
    h_wait_held(1); /* A read, held */
    CHECK(pin_start(&p[1], t, A));
    wait_waits(db, waits0 + 1); /* a second pin of A waits for that load */
    CHECK(pin_start(&p[2], t, B));
    h_wait_held(2); /* B's load ran meanwhile: no lock held through a read */
    CHECK(pin_start(&p[3], t, B));
    wait_waits(db, waits0 + 2);
    h_let_go(B); /* the later load ends first */
    pthread_join(p[2].th, NULL);
    pthread_join(p[3].th, NULL);
    CHECK(p[2].gi && p[2].gi == p[3].gi && !imdb_seg_resident(t, A));
    h_let_go(A);
    pthread_join(p[0].th, NULL);
    pthread_join(p[1].th, NULL);
    CHECK(p[0].gi && p[0].gi == p[1].gi && p[0].gi != p[2].gi);
    CHECK(db->segcache.loads == loads0 + 2 && h_calls() == 2 && resident_images(t) == 2);
    imdb_op_leave(db);
    CHECK(resident_images(t) == 0);
    /* a load that fails, three ways */
    imdb_hex(A->hash, 32, from); /* the object's name, then the paths */
    char hex[65];
    memcpy(hex, from, 65);
    snprintf(from, sizeof from, "%s/objects/%s.seg", dir, hex);
    snprintf(to, sizeof to, "%s/objects/%s.away", dir, hex);
    for (int how = 0; how < 3; how++) {
        static const imdb_io_hooks hooks = {fail_mid, NULL, NULL};
        if (how == 0) CHECK(rename(from, to) == 0);
        else {
            memset(&F, 0, sizeof F);
            F.op = how == 1 ? IMDB_IO_READ : IMDB_IO_ALLOC;
            imdb_io_set_hooks(&hooks);
        }
        h_reset();
        loads0 = db->segcache.loads;
        waits0 = db->segcache.load_waits;
        imdb_op_enter(db);
        CHECK(pin_start(&p[0], t, A));
        h_wait_held(1);
        CHECK(pin_start(&p[1], t, A));
        wait_waits(db, waits0 + 1);
        h_let_go(A);
        pthread_join(p[0].th, NULL);
        pthread_join(p[1].th, NULL);
        if (how) imdb_io_set_hooks(NULL);
        if (how) CHECK(F.failed);
        CHECK(!p[0].gi && !p[1].gi && p[0].e.code && p[0].e.code == p[1].e.code && !strcmp(p[0].e.msg, p[1].e.msg));
        imdb_err e3 = {0};
        CHECK(!imdb_seg_pin(t, A, &e3) && e3.code == p[0].e.code && !strcmp(e3.msg, p[0].e.msg));
        CHECK(h_calls() == 1 && db->segcache.loads == loads0 && !db->failed); /* the third read nothing */
        imdb_op_leave(db);
        if (how == 0) CHECK(rename(to, from) == 0);
        imdb_op_enter(db); /* the next operation reads again */
        imdb_err e4 = {0};
        CHECK(imdb_seg_pin(t, A, &e4) != NULL && !e4.code && db->segcache.loads == loads0 + 1 && h_calls() == 2);
        imdb_op_leave(db);
    }
    imdb_seg_load_hook(NULL, NULL);
    imdb_result r;
    OK(imdb_exec_one(&s, "SELECT COUNT(*), SUM(v) FROM t", 30, NULL, 0, &r, E));
    CHECK(r.nrows == 1 && r.cells[0].v.i == 400);
    imdb_result_free(&r);
out:
    imdb_seg_load_hook(NULL, NULL);
    imdb_session_close(&s);
    imdb_close(db);
}

/* ---- P2 S15, the 2026-11-05 review's O3 (its first step): an aggregate lets each image go as it leaves the segment ---- */

/* one statement at the cache's present budget: its outcome as text, and the most resident while it ran */
static uint64_t peak_of(imdb_db *db, imdb_session *s, const char *sql, imdb_buf *out)
{
    db->segcache.peak = db->segcache.resident;
    outcome(s, sql, out);
    return db->segcache.peak;
}

/* Twelve segments of 400 rows, then rows in the memtable. Aggregates over the table (COUNT, SUM, AVG, MIN and MAX of
 * INT64 and TEXT, DISTINCT, FILTER, a tree's extreme, predicates), on the scan and the store paths: the same outcome
 * at a budget of every image, of the largest image, and of none. At one image's budget a statement holds at most two
 * images at once (the budget and the one in hand), at none at most one, and the images it let go are counted;
 * grouped ones too (a group's keys copied as it is made, its accumulators their own); a row SELECT, not on the
 * allow-list, still holds every image it read until its operation ends; and a statement inside
 * EXISTS, or under cross_check, lets none go */
static void t_segcache_release(void)
{
    const char *dir = test_tmpdir();
    OK(imdb_init(dir, false, NULL, E));
    imdb_db *db = copen(dir, UINT64_MAX);
    CHECK(db);
    if (!db) return;
    imdb_session s;
    imdb_session_init(&s, db);
    OK(ex(&s, "CREATE TABLE t (id INT64 PRIMARY KEY, g INT64, v INT64, s TEXT)"));
    char sql[160];
    enum { NSEG = 12, ROWS = 400 };
    for (int k = 0; k <= NSEG; k++) {
        OK(ex(&s, "BEGIN"));
        for (int i = 0; i < ROWS; i++) {
            int id = k * ROWS + i;
            if (id % 97 == 0 || id % 89 == 0) /* an empty TEXT and a NULL among them: group keys of their own */
                snprintf(sql, sizeof sql, "INSERT INTO t VALUES (%d, %d, %d, %s)", id, id % 7, (id * 7919) % 1000 - 500,
                         id % 97 == 0 ? "''" : "NULL");
            else
                snprintf(sql, sizeof sql, "INSERT INTO t VALUES (%d, %d, %d, 'text %05d of a row, a while long %d')", id,
                         id % 7, (id * 7919) % 1000 - 500, (id * 104729) % (NSEG * ROWS), id % 3);
            OK(ex(&s, sql));
        }
        OK(ex(&s, "COMMIT"));
        if (k < NSEG) OK(ex(&s, "CHECKPOINT")); /* the last batch stays in the memtable */
    }
    imdb_table *t = imdb_table_by_name(db, "t");
    CHECK(t && t->nseg == NSEG);
    if (!t || t->nseg != NSEG) goto out;
    uint64_t largest = 0;
    OK(ex(&s, "SELECT COUNT(*) FROM t WHERE v > 0")); /* every image resident (no budget yet) */
    for (uint32_t k = 0; k < t->nseg; k++) {
        uint64_t b = imdb_seg_image_bytes(t->seg[k]);
        if (b > largest) largest = b;
    }
    CHECK(largest > 0);
    static const char *const aggs[] = {
        "SELECT COUNT(*), SUM(v), AVG(v), MIN(v), MAX(v) FROM t",
        "SELECT MIN(s), MAX(s), COUNT(s) FROM t",
        "SELECT MIN(s), MAX(s) FROM t WHERE v > 100 AND s >= 'text 01'",
        "SELECT COUNT(DISTINCT s), COUNT(DISTINCT g), SUM(v) FILTER (WHERE g = 3) FROM t",
        "SELECT MAX(s || '!'), MIN(UPPER(s)), SUM(v * 2) FROM t WHERE id % 5 = 1",
        "SELECT COUNT(*) FROM t WHERE s LIKE '%of a row%' HAVING COUNT(*) > 10",
        "SELECT g, COUNT(*), MIN(s), MAX(s), SUM(v) FROM t GROUP BY g",
        "SELECT g, id % 3, MAX(UPPER(s)), COUNT(DISTINCT s) FROM t GROUP BY g, id % 3 HAVING COUNT(*) > 5 ORDER BY 2, 1",
        "SELECT s, COUNT(*), MIN(v) FROM t WHERE v > 400 GROUP BY s", /* TEXT keys out of the images, copied as made */
        "SELECT s, COUNT(*), MAX(g) FROM t WHERE id % 97 = 0 OR id % 89 = 0 GROUP BY s", /* the empty key and the NULL one */
    };
    static const char *const paths[] = {"SET access_path = scan", "SET access_path = store"};
    enum { NA = sizeof aggs / sizeof *aggs };
    imdb_buf want[2][NA], got;
    imdb_buf_init(&got);
    for (int p = 0; p < 2; p++)
        for (int a = 0; a < NA; a++) {
            imdb_buf_init(&want[p][a]);
            OK(ex(&s, paths[p]));
            outcome(&s, aggs[a], &want[p][a]);
        }
    for (int p = 0; p < 2; p++) /* the two paths agree before anything is let go */
        for (int a = 0; a < NA; a++) CHECK(want[0][a].len == want[p][a].len && !memcmp(want[0][a].p, want[p][a].p, want[0][a].len));
    static const uint64_t budget_of[] = {1, 0}; /* in largest images: one, none */
    for (int b = 0; b < 2; b++) {
        db->segcache.budget = budget_of[b] * largest;
        for (int p = 0; p < 2; p++) {
            OK(ex(&s, paths[p]));
            for (int a = 0; a < NA; a++) {
                uint64_t rel = db->segcache.released;
                uint64_t peak = peak_of(db, &s, aggs[a], &got);
                bool eq = got.len == want[p][a].len && !memcmp(got.p, want[p][a].p, got.len);
                if (!eq || peak > (budget_of[b] + 1) * largest)
                    fprintf(stderr, "    %s at %llu: peak %llu (largest %llu), released %llu\n%.*s", aggs[a],
                            (unsigned long long)db->segcache.budget, (unsigned long long)peak,
                            (unsigned long long)largest, (unsigned long long)(db->segcache.released - rel), (int)got.len,
                            (const char *)got.p);
                CHECK(eq);
                CHECK(peak <= (budget_of[b] + 1) * largest);
                CHECK(db->segcache.released > rel);
            }
        }
    }
    /* P2 S16, S18: row SELECTs let their walk's images go too, and take their sort keys in the walk (walk_keys), so the
     * result's reading takes again only the segments of the rows it outputs: a selective statement holds fewer than every
     * image at once, a LIMIT n at most the budget, the image in hand and n more (OFFSET skips unread); a DISTINCT reads
     * the rows its window passes over (out 0: no bound) */
    static const struct {
        const char *sql;
        int out; /* the rows the result reads at most: -1 a selective statement's (fewer than every image), 0 unbounded */
    } rows[] = {
        {"SELECT id, s FROM t WHERE v + 1 = 500 ORDER BY s, id", -1},
        {"SELECT id FROM t WHERE v * 2 > 990 ORDER BY id DESC LIMIT 3", 3},
        {"SELECT id, s FROM t WHERE s = '' OR s IS NULL ORDER BY id", -1},
        {"SELECT DISTINCT g FROM t WHERE s LIKE '%a while long 1%' ORDER BY g", 0},
        {"SELECT id, s FROM t ORDER BY s DESC LIMIT 5", 5},
        {"SELECT id, v FROM t ORDER BY v, id LIMIT 3 OFFSET 2", 3},
        {"SELECT id FROM t WHERE g = 3 ORDER BY s LIMIT 4", 4},
        {"SELECT id, s || '!' AS e FROM t ORDER BY s || '!' DESC LIMIT 2", 2}, /* a computed key: the arena's, copied */
        {"SELECT DISTINCT s FROM t WHERE s IS NOT NULL ORDER BY s DESC LIMIT 3", 6}, /* nearly distinct: a few rows (the
                                                                                      * NULLs first under DESC would be
                                                                                      * ~58 rows over every segment) */
    };
    enum { NR = sizeof rows / sizeof *rows };
    imdb_buf wantr[2][NR];
    db->segcache.budget = UINT64_MAX;
    for (int p = 0; p < 2; p++)
        for (int a = 0; a < NR; a++) {
            imdb_buf_init(&wantr[p][a]);
            OK(ex(&s, paths[p]));
            outcome(&s, rows[a].sql, &wantr[p][a]);
        }
    for (int b = 0; b < 2; b++) {
        db->segcache.budget = budget_of[b] * largest;
        for (int p = 0; p < 2; p++) {
            OK(ex(&s, paths[p]));
            for (int a = 0; a < NR; a++) {
                uint64_t rel = db->segcache.released;
                uint64_t peak = peak_of(db, &s, rows[a].sql, &got);
                bool eq = got.len == wantr[p][a].len && !memcmp(got.p, wantr[p][a].p, got.len);
                uint64_t bound = rows[a].out < 0    ? (uint64_t)NSEG * largest - 1
                                 : rows[a].out == 0 ? UINT64_MAX
                                                    : (budget_of[b] + 1 + (uint64_t)rows[a].out) * largest;
                if (!eq || peak > bound)
                    fprintf(stderr, "    %s at %llu: peak %llu (largest %llu, bound %llu), released %llu\n%.*s", rows[a].sql,
                            (unsigned long long)db->segcache.budget, (unsigned long long)peak, (unsigned long long)largest,
                            (unsigned long long)bound, (unsigned long long)(db->segcache.released - rel), (int)got.len,
                            (const char *)got.p);
                CHECK(eq);
                CHECK(db->segcache.released > rel);
                CHECK(peak <= bound);
            }
        }
    }
    for (int p = 0; p < 2; p++)
        for (int a = 0; a < NR; a++) imdb_buf_free(&wantr[p][a]);
    /* not on the allow-list: a nested run (a derived table's, a subquery's) and the statement around it, EXISTS,
     * cross_check: every image the statement pinned kept */
    db->segcache.budget = 0;
    OK(ex(&s, "SET access_path = scan"));
    static const char *const keep[] = {"SELECT COUNT(*) FROM (SELECT id FROM t WHERE v + 1 = 500) AS q",
                                       "SELECT id FROM t WHERE v = (SELECT MAX(v) FROM t WHERE v + 1 < 400)",
                                       "SELECT EXISTS (SELECT 1 FROM t WHERE v = 499 AND s > 'z')"};
    for (size_t i = 0; i < sizeof keep / sizeof *keep; i++) {
        uint64_t rel = db->segcache.released;
        uint64_t peak = peak_of(db, &s, keep[i], &got);
        if (db->segcache.released != rel || (i < 2 && peak < (uint64_t)NSEG * largest / 2))
            fprintf(stderr, "    %s: released %llu, peak %llu (largest %llu)\n", keep[i],
                    (unsigned long long)(db->segcache.released - rel), (unsigned long long)peak, (unsigned long long)largest);
        CHECK(db->segcache.released == rel);
        if (i < 2) CHECK(peak >= (uint64_t)NSEG * largest / 2); /* a tree in WHERE: no zone map skips a segment, so every
                                                                  * image is read and kept; EXISTS' first row reads a few */
    }
    OK(ex(&s, "SET cross_check = on"));
    uint64_t rel = db->segcache.released;
    peak_of(db, &s, aggs[1], &got);
    CHECK(db->segcache.released == rel && got.len == want[0][1].len && !memcmp(got.p, want[0][1].p, got.len));
    OK(ex(&s, "SET cross_check = off"));
    for (int p = 0; p < 2; p++)
        for (int a = 0; a < NA; a++) imdb_buf_free(&want[p][a]);
    imdb_buf_free(&got);
    OK(ex(&s, "SET access_path = auto"));
    imdb_verify_report vr;
    memset(&vr, 0, sizeof vr);
    OK(imdb_verify(db, &vr, E));
out:
    imdb_session_close(&s);
    imdb_close(db);
}

const test_case segcache_tests[] = {
    {"segcache_release", t_segcache_release},
    {"segcache_one_load", t_segcache_one_load},
    {"segcache_reload_ends", t_segcache_reload_ends},
    {"segcache_lru", t_segcache_lru},
    {"segcache_unwritten_kept", t_segcache_unwritten_kept},
    {"segcache_load_fails", t_segcache_load_fails},
    {"segcache_parallel_loads", t_segcache_parallel_loads},
    {"segcache_publish_loads", t_segcache_publish_loads},
    {"segcache_evict_loads", t_segcache_evict_loads},
    {"segcache_retire_loads", t_segcache_retire_loads},
    {"segcache_hmap_prune", t_segcache_hmap_prune},
    {"segcache_open_streams", t_segcache_open_streams},
};
const size_t segcache_ntests = sizeof segcache_tests / sizeof *segcache_tests;
