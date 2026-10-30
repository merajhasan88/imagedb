/* Stage 3b (round 4): the memory window. A copy keeps in memory every version live, ended past its floor, or not
 * yet in a segment; the others leave the store and every index, and a read below the floor goes to the lake
 * (docs/plan-round4.md, "Stage 3b design at the fork"). The rule these tests hold it to: eviction is invisible.
 * Nothing anyone reads and nothing derived depends on what was evicted: the same statements give the same rows and
 * the same errors with and without it, replicas that evict and replicas that do not write the same bytes, and
 * VERIFY and the auditor pass on both. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "../../src/db_internal.h"
#include "../../src/fsio.h"
#include "../../src/lake.h"
#include "../../src/sql.h"
#include "thelp.h"

/* every handle here keeps the time policy off: the evictions are the test's own (imdb_evict, or the eager mode
 * at each publish), so they land where the test means them to */
static imdb_db *eopen(const char *dir, bool eager)
{
    imdb_open_opts o = {.sync = 0, .mem_window_us = UINT64_MAX};
    imdb_db *db = NULL;
    imdb_err_clear(E);
    if (imdb_open(dir, &o, &db, E)) return NULL;
    db->evict_eager = eager;
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

static int audit_ok(const char *dir) /* 1: no auditor in this build (IMDB_AUDIT_BIN) */
{
    const char *bin = getenv("IMDB_AUDIT_BIN");
    if (!bin || !*bin) return 1;
    char cmd[1600];
    snprintf(cmd, sizeof cmd, "'%s' verify '%s' >/dev/null 2>&1", bin, dir);
    return system(cmd) == 0;
}

/* a statement's outcome as text: its code, then its rows (CSV) or its status; the access path is left out (a
 * diagnostic: below the floor it says scan where memory said index), and so is SHOW DIGEST's digest when the
 * two databases' salts differ (digests: false) */
static int outcome(imdb_session *s, const char *sql, imdb_buf *out, bool digests)
{
    imdb_result r;
    imdb_err e = {0};
    out->len = 0;
    int rc = imdb_exec_one(s, sql, strlen(sql), NULL, 0, &r, &e);
    imdb_buf_printf(out, "%d\n", rc);
    if (rc) return rc;
    char *man = digests ? NULL : strstr(r.status, "manifest "); /* a publish names its manifest: their salts differ */
    if (man) *man = 0;
    if (strncmp(sql, "SHOW DIGEST", 11) == 0) { /* every column but the path's name; the digest when the salts agree */
        for (uint64_t i = 0; i < r.nrows; i++)
            for (uint16_t c = 1; c < r.ncols; c++) {
                const imdb_value *v = &r.cells[i * r.ncols + c].v;
                if (c == 3 && !digests) continue;
                if (v->type == IMDB_T_TEXT) imdb_buf_printf(out, "%.*s;", (int)v->len, (const char *)v->s);
                else imdb_buf_printf(out, "%lld;", (long long)v->i);
            }
        imdb_buf_printf(out, "\n");
    } else if (!r.has_rows) {
        imdb_buf_printf(out, "%s\n", r.status);
    } else {
        imdb_result_render(&r, true, out);
        if (r.has_rows) imdb_buf_printf(out, "%s\n", r.status);
    }
    imdb_result_free(&r);
    return rc;
}

/* the same statement on two sessions: the same outcome */
static bool same(imdb_session *a, imdb_session *b, const char *sql, bool digests, int *rc)
{
    imdb_buf x, y;
    imdb_buf_init(&x);
    imdb_buf_init(&y);
    *rc = outcome(a, sql, &x, digests);
    outcome(b, sql, &y, digests);
    bool eq = x.len == y.len && (!x.len || memcmp(x.p, y.p, x.len) == 0);
    if (!eq)
        fprintf(stderr, "    differ: %s\n    --- one:\n%.*s    --- other:\n%.*s", sql, (int)(x.len > 600 ? 600 : x.len),
                (const char *)x.p, (int)(y.len > 600 ? 600 : y.len), (const char *)y.p);
    imdb_buf_free(&x);
    imdb_buf_free(&y);
    return eq;
}

static bool sweep_at(imdb_session *a, imdb_session *b, uint64_t s, int64_t k, bool digests)
{
    unsigned long long sl = (unsigned long long)s;
    long long kl = (long long)k, sj = (long long)(k % 7);
    char q[7][200];
    snprintf(q[0], sizeof q[0], "SELECT * FROM a AS OF %llu WHERE id = %lld", sl, kl);
    snprintf(q[1], sizeof q[1], "SELECT id, v FROM a AS OF %llu WHERE s = %lld", sl, sj);
    snprintf(q[2], sizeof q[2], "SELECT COUNT(*), SUM(v) FROM a AS OF %llu WHERE v BETWEEN %lld AND 600", sl, kl);
    snprintf(q[3], sizeof q[3], "SELECT s, COUNT(*), MIN(v), MAX(txt) FROM a AS OF %llu WHERE id > %lld GROUP BY s", sl, kl);
    snprintf(q[4], sizeof q[4], "SELECT a.id, b.x FROM a JOIN b ON a.id = b.a_id AS OF %llu WHERE b.x > %lld", sl, kl);
    snprintf(q[5], sizeof q[5], "SELECT * FROM a AS OF %llu WHERE w = %lld", sl, kl % 9);
    snprintf(q[6], sizeof q[6], "SHOW DIGEST a SUBJECT %lld AS OF %llu", sj, sl);
    bool ok = true;
    int rc;
    for (size_t i = 0; i < 7 && ok; i++) ok = same(a, b, q[i], digests, &rc);
    return ok;
}

/* every snapshot from 1 to the latest (below a horizon: HISTORY on both), a key and a subject each */
static bool sweep(imdb_db *da, imdb_session *a, imdb_session *b, bool digests)
{
    bool ok = true;
    for (uint64_t s = 1; s <= da->seq && ok; s += 1 + s / 64)
        ok = sweep_at(a, b, s, (int64_t)(test_rand() % 60), digests);
    char sql[80];
    int rc;
    for (int64_t k = 0; k < 60 && ok; k += 7) {
        snprintf(sql, sizeof sql, "SHOW HISTORY a %lld", (long long)k);
        ok = same(a, b, sql, digests, &rc);
    }
    return ok;
}

static void step_sql(char *sql, size_t n)
{
    uint64_t r = test_rand() % 100;
    int64_t k = (int64_t)(test_rand() % 60), v = (int64_t)(test_rand() % 1000);
    if (r < 35) snprintf(sql, n, "UPDATE a SET v = %lld, txt = 'u%lld' WHERE id = %lld", (long long)v, (long long)v, (long long)k);
    else if (r < 45) snprintf(sql, n, "DELETE FROM a WHERE id = %lld", (long long)k);
    else if (r < 60)
        snprintf(sql, n, "INSERT INTO a VALUES (%lld, %lld, %lld, %s, 'i%lld')", (long long)k, (long long)(k % 7),
                 (long long)v, test_rand() % 3 ? "NULL" : "7", (long long)v);
    else if (r < 66) snprintf(sql, n, "UPDATE a SET w = %lld WHERE id = %lld", (long long)(v % 9), (long long)k);
    else if (r < 74)
        snprintf(sql, n, "INSERT INTO b VALUES (%lld, %lld, %lld)", (long long)(v + 1000 * (int64_t)(test_rand() % 50)),
                 (long long)k, (long long)v);
    else if (r < 78) snprintf(sql, n, "DELETE FROM b WHERE a_id = %lld", (long long)k);
    else if (r < 84) snprintf(sql, n, "CHECKPOINT");
    else if (r < 86) snprintf(sql, n, "ERASE SUBJECT %lld", (long long)(k % 7));
    else if (r < 88) snprintf(sql, n, "ERASE FROM a WHERE v BETWEEN %lld AND %lld", (long long)v, (long long)(v + 5));
    else snprintf(sql, n, "SELECT * FROM a WHERE id = %lld", (long long)k);
}

/* The differential test: one seeded workload on a primary that evicts at every publish (P) and one that never does
 * (Q): every statement the same outcome (rows and error codes; their salts differ, so not their digests); an old
 * transaction on each, open across many evictions, reading, updating and inserting in its own snapshot; AS OF at
 * every snapshot from the start; a replica that evicts (R2) and one that does not (R1) apply P's log: the same
 * lake files, the same log, and the same answers, digests included; VERIFY on all four and the auditor on P and
 * the replicas; then each reopened from its snapshot and swept again. */
static void t_evict_differential(void)
{
    const char *base = test_tmpdir();
    char dp[600], dq[600], r1[600], r2[600], st[600];
    snprintf(dp, sizeof dp, "%s/p", base);
    snprintf(dq, sizeof dq, "%s/q", base);
    snprintf(r1, sizeof r1, "%s/r1", base);
    snprintf(r2, sizeof r2, "%s/r2", base);
    snprintf(st, sizeof st, "%s/stream", base);
    OK(imdb_init(dp, false, NULL, E));
    OK(imdb_init(dq, false, NULL, E));
    OK(imdb_init(r1, true, dp, E));
    OK(imdb_init(r2, true, dp, E));
    imdb_db *P = eopen(dp, true), *Q = eopen(dq, false);
    CHECK(P && Q);
    if (!P || !Q) return;
    imdb_session p1, q1, p2, q2; /* p2, q2: the old transactions' sessions */
    imdb_session_init(&p1, P);
    imdb_session_init(&q1, Q);
    imdb_session_init(&p2, P);
    imdb_session_init(&q2, Q);
    p1.cross_check = q1.cross_check = p2.cross_check = q2.cross_check = true;
    static const char *const ddl[] = {
        "CREATE TABLE a (id INT64 PRIMARY KEY, s INT64 SUBJECT, v INT64, w INT64 NULL, txt TEXT)",
        "CREATE TABLE b (id INT64 PRIMARY KEY, a_id INT64, x INT64)",
        "CREATE INDEX a_v ON a (v)",
        "CREATE UNIQUE INDEX a_w ON a (w)",
    };
    int rc;
    for (size_t i = 0; i < sizeof ddl / sizeof *ddl; i++) CHECK(same(&p1, &q1, ddl[i], false, &rc) && rc == 0);
    char sql[256];
    bool ok = true, old_open = false;
    uint64_t lows = 0; /* reads of the old transactions below their copy's floor */
    for (int step = 0; step < 900 && ok; step++) {
        if (test_rand() % 10 == 0) { /* the old transaction: begun, read, written, ended */
            uint64_t r = test_rand() % 10;
            int64_t k = (int64_t)(test_rand() % 60);
            if (!old_open) snprintf(sql, sizeof sql, "BEGIN");
            else if (r < 4) snprintf(sql, sizeof sql, "SELECT * FROM a WHERE id = %lld", (long long)k);
            else if (r < 5) snprintf(sql, sizeof sql, "SELECT s, COUNT(*) FROM a GROUP BY s");
            else if (r < 6) snprintf(sql, sizeof sql, "SELECT a.id, b.x FROM a JOIN b ON a.id = b.a_id WHERE a.v < 500");
            else if (r < 7) snprintf(sql, sizeof sql, "UPDATE a SET v = 1 WHERE id = %lld", (long long)k);
            else if (r < 8) snprintf(sql, sizeof sql, "INSERT INTO a VALUES (%lld, 1, 1, NULL, 'o')", (long long)k);
            else if (r < 9) snprintf(sql, sizeof sql, "SELECT * FROM a WHERE id = %lld FOR UPDATE", (long long)k);
            else snprintf(sql, sizeof sql, test_rand() % 2 ? "COMMIT" : "ROLLBACK");
            if (old_open && r < 9 && p2.txn.open && p2.txn.snap < P->mem_floor) lows++;
            ok = same(&p2, &q2, sql, false, &rc);
            if (!old_open && !rc) {
                ok = ok && same(&p2, &q2, "SELECT COUNT(*) FROM a", false, &rc); /* its snapshot taken */
                old_open = true;
            } else if (old_open && r >= 9) {
                old_open = false;
            } else if (old_open && !p2.txn.open && !q2.txn.open) {
                old_open = false; /* a conflict ended it on both */
            }
            continue;
        }
        step_sql(sql, sizeof sql);
        ok = same(&p1, &q1, sql, false, &rc);
        CHECK(P->mem_floor == P->lake_seq || !P->lake_seq); /* eager: every publish evicts to itself */
        if (step % 150 == 149) ok = ok && sweep(P, &p1, &q1, false);
    }
    CHECK(ok);
    CHECK(lows > 0); /* the old transactions did read below the floor */
    if (old_open) {
        ex(&p2, "ROLLBACK");
        ex(&q2, "ROLLBACK");
    }
    OK(ex(&p1, "CHECKPOINT"));
    OK(ex(&q1, "CHECKPOINT"));
    CHECK(sweep(P, &p1, &q1, false));
    uint64_t held_p = 0, held_q = 0;
    for (uint32_t i = 0; i < P->nt; i++) held_p += P->t[i]->nheld, held_q += Q->t[i]->nheld;
    CHECK(held_p < held_q); /* P let go what Q keeps */
    imdb_verify_report vr;
    memset(&vr, 0, sizeof vr);
    OK(imdb_verify(P, &vr, E));
    uint64_t pv = vr.versions, ps = vr.stubs;
    memset(&vr, 0, sizeof vr);
    OK(imdb_verify(Q, &vr, E));
    CHECK(vr.versions == pv && vr.stubs == ps); /* VERIFY's counts do not depend on the window */
    imdb_session_close(&p2);
    imdb_session_close(&q2);
    imdb_session_close(&p1);
    imdb_session_close(&q1);
    imdb_close(P);
    imdb_close(Q);
    /* two replicas of P, one evicting at every publish it applies */
    OK(ship_to_file(dp, 0, st, E));
    imdb_db *R1 = eopen(r1, false), *R2 = eopen(r2, true);
    CHECK(R1 && R2);
    if (!R1 || !R2) return;
    uint64_t applied;
    OK(apply_file(R1, st, &applied, E));
    OK(apply_file(R2, st, &applied, E));
    CHECK(R2->mem_floor > 0 && R1->mem_floor == 0);
    imdb_session a, b;
    imdb_session_init(&a, R1);
    imdb_session_init(&b, R2);
    a.cross_check = b.cross_check = true;
    CHECK(sweep(R1, &a, &b, true)); /* the same database: digests too */
    memset(&vr, 0, sizeof vr);
    OK(imdb_verify(R1, &vr, E));
    memset(&vr, 0, sizeof vr);
    OK(imdb_verify(R2, &vr, E));
    imdb_session_close(&a);
    imdb_session_close(&b);
    imdb_close(R1);
    imdb_close(R2);
    char why[300] = "";
    CHECK(dirs_identical(path_join(r1, "objects"), path_join(r2, "objects"), why, sizeof why));
    CHECK(logs_identical(path_join(r1, "log"), path_join(r2, "log"), why, sizeof why));
    CHECK(audit_ok(dp) && audit_ok(r1) && audit_ok(r2));
    /* reopened from their snapshots: R2 evicts at once (step e) or keeps all (its window is off); the answers stay */
    R1 = eopen(r1, false);
    R2 = eopen(r2, true);
    CHECK(R1 && R2);
    if (!R1 || !R2) return;
    imdb_session_init(&a, R1);
    imdb_session_init(&b, R2);
    OK(imdb_evict(R2, R2->lake_seq, E));
    CHECK(sweep(R1, &a, &b, true));
    imdb_session_close(&a);
    imdb_session_close(&b);
    imdb_close(R1);
    imdb_close(R2);
}


static int64_t sval_of(imdb_session *s, const char *sql) /* a query's one value; INT64_MIN when it fails */
{
    imdb_result r;
    imdb_err_clear(E);
    if (imdb_exec_one(s, sql, strlen(sql), NULL, 0, &r, E)) return INT64_MIN;
    int64_t v = r.nrows == 1 && r.ncols >= 1 ? r.cells[0].v.i : INT64_MIN;
    imdb_result_free(&r);
    return v;
}

#define SEC_US 1000000ll

/* The policy, on the clock: a 60-second window over 2,000 rows updated 6,000 times across four segments. Nothing
 * leaves memory while every segment is younger than the window; once the clock is two minutes on, the next
 * statement's policy moves the floor to a segment's end, the versions ended by then leave the store, and every
 * answer recorded before (each commit's COUNT and SUM, a key's history) is the same after; VERIFY passes, and the
 * store holds about the live rows and what ended past the floor. */
static void t_evict_policy(void)
{
    const char *dir = test_tmpdir();
    OK(imdb_init(dir, false, NULL, E));
    imdb_open_opts o = {.sync = 0, .mem_window_us = 60 * SEC_US};
    imdb_db *db = NULL;
    OK(imdb_open(dir, &o, &db, E));
    if (!db) return;
    db->evict_eager = false; /* the policy's own floor, whatever IMDB_EVICT says */
    imdb_session s;
    imdb_session_init(&s, db);
    OK(ex(&s, "CREATE TABLE t (id INT64 PRIMARY KEY, v INT64)"));
    char sql[160];
    OK(ex(&s, "BEGIN"));
    for (int i = 0; i < 2000; i++) {
        snprintf(sql, sizeof sql, "INSERT INTO t VALUES (%d, %d)", i, i);
        OK(ex(&s, sql));
    }
    OK(ex(&s, "COMMIT"));
    for (int round = 0; round < 4; round++) {
        for (int i = 0; i < 1500; i++) {
            snprintf(sql, sizeof sql, "UPDATE t SET v = %d WHERE id = %d", round * 10000 + i, (i * 7 + round) % 2000);
            OK(ex(&s, sql));
        }
        OK(ex(&s, "CHECKPOINT"));
    }
    imdb_table *t = imdb_table_by_name(db, "t");
    uint64_t seq = db->seq, held = t->nheld;
    CHECK(db->mem_floor == 0 && held == t->nver); /* all younger than the window: nothing left */
    int64_t cnt[64], sum[64];
    for (int k = 0; k < 64; k++) {
        uint64_t at = 1 + (seq - 1) * (uint64_t)k / 63;
        snprintf(sql, sizeof sql, "SELECT COUNT(*) FROM t AS OF %llu", (unsigned long long)at);
        cnt[k] = sval_of(&s, sql);
        snprintf(sql, sizeof sql, "SELECT SUM(v) FROM t AS OF %llu WHERE id < 100", (unsigned long long)at);
        sum[k] = sval_of(&s, sql);
    }
    imdb_clock_offset(120 * SEC_US);
    OK(ex(&s, "SELECT COUNT(*) FROM t")); /* its maintain runs the policy */
    CHECK(db->mem_floor > 0 && db->mem_floor < db->seq);
    CHECK(t->nheld < held / 2 && t->nheld >= 2000);
    imdb_result r;
    OK(imdb_exec_one(&s, "SHOW MEMORY", 11, NULL, 0, &r, E)); /* the status names the window, the floor and what is held */
    char want[160];
    snprintf(want, sizeof want, "memory window 60 s, floor commit %llu: %llu versions held of ",
             (unsigned long long)db->mem_floor, (unsigned long long)t->nheld);
    CHECK(strstr(r.status, want) != NULL);
    imdb_result_free(&r);
    for (uint64_t vid = imdb_v_next(t, 0); vid < t->nver; vid = imdb_v_next(t, vid + 1)) { /* held: past the floor */
        const imdb_version *v = imdb_vh(t, vid);
        if (v->end != IMDB_LIVE && v->end <= db->mem_floor && (v->flags & IMDB_V_SEG)) {
            CHECK(!"a version ended at or before the floor is still held");
            break;
        }
    }
    s.cross_check = true;
    for (int k = 0; k < 64; k++) {
        uint64_t at = 1 + (seq - 1) * (uint64_t)k / 63;
        snprintf(sql, sizeof sql, "SELECT COUNT(*) FROM t AS OF %llu", (unsigned long long)at);
        CHECK(sval_of(&s, sql) == cnt[k]);
        snprintf(sql, sizeof sql, "SELECT SUM(v) FROM t AS OF %llu WHERE id < 100", (unsigned long long)at);
        CHECK(sval_of(&s, sql) == sum[k]);
    }
    imdb_verify_report vr;
    memset(&vr, 0, sizeof vr);
    OK(imdb_verify(db, &vr, E));
    /* a tail past the snapshot: 300 updates (300 endings, too few for a pass here or in the reopen's replay), then the
     * clock moved so that the tail's segment too began longer than the window ago */
    for (int i = 0; i < 300; i++) {
        snprintf(sql, sizeof sql, "UPDATE t SET v = %d WHERE id = %d", 90000 + i, i);
        OK(ex(&s, sql));
    }
    imdb_clock_offset(240 * SEC_US);
    imdb_session_close(&s);
    /* A reopen takes its floor while it loads, before its replay, from the segments' first times up to its snapshot
     * (the smoke of 10-30 found every open's floor 0: the times were read only up to db->seq, 0 until the replay).
     * Not past the snapshot (a segment after it may have been begun for a commit never made): so the end of the
     * segment before the snapshot's, the floor the pass took, though the tail's segment is old enough too. The tail
     * starts no pass in the replay, so the store holds exactly what this handle holds. Under IMDB_EVICT=eager the
     * open's floor is its snapshot: the live rows held, and the tail's 300 versions */
    uint64_t floor = db->mem_floor, before = t->nheld;
    CHECK(floor > 0 && floor < seq && db->seq == seq + 300);
    imdb_close(db);
    db = NULL;
    OK(imdb_open(dir, &o, &db, E));
    if (!db) return;
    const char *ev = getenv("IMDB_EVICT");
    bool eager = ev && strcmp(ev, "eager") == 0;
    db->evict_eager = false;
    t = imdb_table_by_name(db, "t");
    CHECK(t && db->lake_seq == seq && db->seq == seq + 300);
    if (eager) CHECK(db->mem_floor == seq && t->nheld == 2300);
    else CHECK(db->mem_floor == floor && t->nheld == before);
    imdb_session_init(&s, db);
    s.cross_check = true;
    for (int k = 0; k < 64; k++) {
        uint64_t at = 1 + (seq - 1) * (uint64_t)k / 63;
        snprintf(sql, sizeof sql, "SELECT COUNT(*) FROM t AS OF %llu", (unsigned long long)at);
        CHECK(sval_of(&s, sql) == cnt[k]);
        snprintf(sql, sizeof sql, "SELECT SUM(v) FROM t AS OF %llu WHERE id < 100", (unsigned long long)at);
        CHECK(sval_of(&s, sql) == sum[k]);
    }
    memset(&vr, 0, sizeof vr);
    OK(imdb_verify(db, &vr, E));
    imdb_session_close(&s);
    imdb_close(db);
    CHECK(audit_ok(dir));
}

/* An old transaction across an eviction: its snapshot S, then a commit updates row 5, deletes row 6 and changes
 * row 7, and the floor moves past them. Its reads still see S (row 5's old value, row 6, the count), from the lake;
 * its INSERT of 6 is a duplicate in its view (CONSTRAINT, found in the lake); its UPDATE of 5 conflicts (the
 * version it saw was ended by a later commit, and the store holds it no longer); a FOR UPDATE lock on 7 is lost
 * when 7 changes and is evicted: its COMMIT conflicts. */
static void t_evict_old_txn(void)
{
    const char *dir = test_tmpdir();
    OK(imdb_init(dir, false, NULL, E));
    imdb_db *db = eopen(dir, false);
    CHECK(db);
    if (!db) return;
    imdb_session s1, s2;
    imdb_session_init(&s1, db);
    imdb_session_init(&s2, db);
    OK(ex(&s1, "CREATE TABLE t (id INT64 PRIMARY KEY, v INT64)"));
    OK(ex(&s1, "BEGIN"));
    char sql[96];
    for (int i = 1; i <= 100; i++) {
        snprintf(sql, sizeof sql, "INSERT INTO t VALUES (%d, %d)", i, i);
        OK(ex(&s1, sql));
    }
    OK(ex(&s1, "COMMIT"));
    OK(ex(&s1, "CHECKPOINT"));
    OK(ex(&s2, "BEGIN"));
    CHECK(sval_of(&s2, "SELECT v FROM t WHERE id = 5") == 5); /* S */
    OK(ex(&s1, "UPDATE t SET v = 99 WHERE id = 5"));
    OK(ex(&s1, "DELETE FROM t WHERE id = 6"));
    OK(ex(&s1, "CHECKPOINT"));
    OK(imdb_evict(db, db->lake_seq, E));
    CHECK(db->mem_floor == db->lake_seq && s2.txn.snap < db->mem_floor);
    s2.cross_check = true;
    CHECK(sval_of(&s2, "SELECT v FROM t WHERE id = 5") == 5);
    CHECK(sval_of(&s2, "SELECT v FROM t WHERE id = 6") == 6);
    CHECK(sval_of(&s2, "SELECT COUNT(*) FROM t") == 100);
    CHECK(ex(&s2, "INSERT INTO t VALUES (6, 1)") == IMDB_ERR_CONSTRAINT);
    CHECK(ex(&s2, "UPDATE t SET v = 1 WHERE id = 5") == IMDB_ERR_CONFLICT);
    OK(ex(&s2, "ROLLBACK"));
    OK(ex(&s2, "BEGIN"));
    CHECK(sval_of(&s2, "SELECT v FROM t WHERE id = 7 FOR UPDATE") == 7);
    OK(ex(&s1, "UPDATE t SET v = 77 WHERE id = 7"));
    OK(ex(&s1, "CHECKPOINT"));
    OK(imdb_evict(db, db->lake_seq, E));
    OK(ex(&s2, "UPDATE t SET v = 1 WHERE id = 8"));
    CHECK(ex(&s2, "COMMIT") == IMDB_ERR_CONFLICT);
    imdb_verify_report vr;
    memset(&vr, 0, sizeof vr);
    OK(imdb_verify(db, &vr, E));
    imdb_session_close(&s2);
    imdb_session_close(&s1);
    imdb_close(db);
}

/* A pass whose new structures cannot be made: the nth allocation of imdb_evict refused, n from 1 until one goes
 * through. Each refusal leaves the table as it was (every version held, the indexes whole), the floor moves anyway,
 * and every answer stays right; nothing leaks (the heap's counter, the SAN build's leak check). */
static int g_refuse_at, g_allocs;

static long refuse_nth_alloc(imdb_io_call *c, void *ctx)
{
    (void)ctx;
    return c->op == IMDB_IO_ALLOC && ++g_allocs == g_refuse_at ? -1 : 0;
}

static const imdb_io_hooks g_refuse_hooks = {refuse_nth_alloc, NULL, NULL};

static void t_evict_refused(void)
{
    int first_ok = 0; /* the first nth past every allocation that matters; eight more refuse the optional ones */
    for (int nth = 1; nth <= 80 && !g_test_failed && (!first_ok || nth <= first_ok + 8); nth++) {
        const char *dir = test_tmpdir();
        OK(imdb_init(dir, false, NULL, E));
        imdb_db *db = eopen(dir, false);
        CHECK(db);
        if (!db) return;
        imdb_session s;
        imdb_session_init(&s, db);
        OK(ex(&s, "CREATE TABLE t (id INT64 PRIMARY KEY, v INT64, w INT64 NULL)"));
        OK(ex(&s, "CREATE INDEX t_v ON t (v)"));
        OK(ex(&s, "CREATE UNIQUE INDEX t_w ON t (w)"));
        char sql[96];
        for (int i = 0; i < 300; i++) {
            snprintf(sql, sizeof sql, "INSERT INTO t VALUES (%d, %d, %d)", i, i, i);
            OK(ex(&s, sql));
        }
        for (int i = 0; i < 300; i += 2) {
            snprintf(sql, sizeof sql, "UPDATE t SET v = %d WHERE id = %d", i + 1000, i);
            OK(ex(&s, sql));
        }
        OK(ex(&s, "CHECKPOINT"));
        imdb_table *t = imdb_table_by_name(db, "t");
        uint64_t held = t->nheld, floor = db->lake_seq;
        g_refuse_at = nth;
        g_allocs = 0;
        imdb_err e = {0};
        imdb_io_set_hooks(&g_refuse_hooks);
        int rc = imdb_evict(db, floor, &e);
        imdb_io_set_hooks(NULL);
        CHECK(db->mem_floor == floor);
        if (rc) CHECK(rc == IMDB_ERR_NOMEM && t->nheld == held); /* kept whole */
        else if (!first_ok) first_ok = nth;
        CHECK(rc || t->nheld == held - 150);
        s.cross_check = true;
        CHECK(sval_of(&s, "SELECT COUNT(*) FROM t WHERE v BETWEEN 1000 AND 1300") == 150);
        CHECK(ex(&s, "INSERT INTO t VALUES (500, 1, 3)") == IMDB_ERR_CONSTRAINT); /* w = 3 is live */
        CHECK(sval_of(&s, "SELECT COUNT(*) FROM t AS OF 3") == 0 && sval_of(&s, "SELECT v FROM t AS OF 304 WHERE id = 2") == 2);
        imdb_verify_report vr;
        memset(&vr, 0, sizeof vr);
        OK(imdb_verify(db, &vr, E));
        imdb_session_close(&s);
        imdb_close(db);
    }
    CHECK(first_ok); /* a pass with no refusal went through, and so did the passes refused only where it may be */
}


/* The commit index past the window (step f): 2,500 commits over several segments; every commit's time, hash and digest
 * and every AS OF TIMESTAMP answer (each commit's time, and a microsecond before it) recorded; then the floor moves to
 * the last publish and the index keeps only the commits past it (its room given back); every answer is the same, an
 * older commit read from its log segment on demand (one segment kept), and a time before the first commit names 0. */
static void t_evict_commit_index(void)
{
    const char *dir = test_tmpdir();
    OK(imdb_init(dir, false, NULL, E));
    imdb_db *db = eopen(dir, false);
    CHECK(db);
    if (!db) return;
    imdb_session s;
    imdb_session_init(&s, db);
    OK(ex(&s, "CREATE TABLE t (id INT64 PRIMARY KEY, v INT64)"));
    char sql[96];
    for (int i = 0; i < 2500; i++) {
        snprintf(sql, sizeof sql, i < 100 ? "INSERT INTO t VALUES (%d, 0)" : "UPDATE t SET v = %d WHERE id = %d", i,
                 i % 100);
        OK(ex(&s, sql));
        if (i % 500 == 499) OK(ex(&s, "CHECKPOINT"));
    }
    uint64_t n = db->seq;
    imdb_commit_info *ci = imdb_alloc_array(n + 1, sizeof *ci, E);
    uint64_t *at = imdb_alloc_array(2 * (n + 1), sizeof *at, E);
    CHECK(ci && at);
    if (!ci || !at) return;
    for (uint64_t q = 1; q <= n; q++) {
        const imdb_commit_info *c = imdb_ci_at(db, q, E);
        CHECK(c);
        if (c) ci[q] = *c;
    }
    for (uint64_t q = 1; q <= n; q++) {
        OK(imdb_seq_at_time(db, ci[q].time_us, &at[2 * q], E));
        OK(imdb_seq_at_time(db, ci[q].time_us - 1, &at[2 * q + 1], E));
        CHECK(at[2 * q] == q && at[2 * q + 1] == q - 1);
    }
    uint64_t cap = db->capci;
    OK(imdb_evict(db, db->lake_seq, E));
    CHECK(db->ci_first == db->lake_seq + 1 && db->nci == db->seq - db->lake_seq && db->capci < cap); /* room back */
    for (uint64_t q = n; q >= 1; q--) { /* newest first: each older segment read as it is reached */
        const imdb_commit_info *c = imdb_ci_at(db, q, E);
        CHECK(c && c->time_us == ci[q].time_us && !memcmp(c->hash, ci[q].hash, 32) && !memcmp(c->digest, ci[q].digest, 32));
        uint64_t a = 0, b = 0;
        OK(imdb_seq_at_time(db, ci[q].time_us, &a, E));
        OK(imdb_seq_at_time(db, ci[q].time_us - 1, &b, E));
        CHECK(a == at[2 * q] && b == at[2 * q + 1]);
    }
    uint64_t z = 1;
    OK(imdb_seq_at_time(db, ci[1].time_us - 1000000, &z, E));
    CHECK(z == 0);
    snprintf(sql, sizeof sql, "SELECT COUNT(*) FROM t AS OF %llu", (unsigned long long)(n / 3));
    CHECK(sval_of(&s, sql) == 100);
    imdb_free(ci);
    imdb_free(at);
    imdb_session_close(&s);
    imdb_close(db);
}

const test_case evict_tests[] = {
    {"evict_differential", t_evict_differential},
    {"evict_policy", t_evict_policy},
    {"evict_old_txn", t_evict_old_txn},
    {"evict_refused", t_evict_refused},
    {"evict_commit_index", t_evict_commit_index},
};
const size_t evict_ntests = sizeof evict_tests / sizeof *evict_tests;
