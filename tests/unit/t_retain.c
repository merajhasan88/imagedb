/* Stage 3 (round 4): history's retention, its expiry and the boundary below which the log is retired
 * (docs/plan-round4.md, "Stage 3a design at the fork"). Step (a): the per-table retention, logged (op 16
 * after every CREATE_TABLE, alone for ALTER), in manifest version 4, replayed by replicas and re-derived
 * by VERIFY and the auditor. */
#include <errno.h>
#include <dirent.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "../../src/cpu.h"
#include "../../src/fsio.h"
#include "../../src/db_internal.h"
#include "../../src/lake.h"
#include "../../src/log.h"
#include "../../src/logdir.h"
#include "../../src/repl.h"
#include "../../src/sign.h"
#include "../../src/writer.h"
#include "../../src/sql.h"
#include "thelp.h"

#define HOUR_US (3600ull * 1000000)

static uint32_t g_stride = 1; /* every publish a keeper (lake.c), so a RETIRE's FLOOR finds its manifest and cuts */

static imdb_db *ropen(const char *dir, bool full_replay)
{
    imdb_open_opts o = {.sync = 0, .full_replay = full_replay, .floor_stride = g_stride};
    imdb_db *db = NULL;
    imdb_err_clear(E);
    return imdb_open(dir, &o, &db, E) ? NULL : db;
}

static int ex(imdb_session *s, const char *sql)
{
    imdb_result r;
    imdb_err_clear(E);
    int rc = imdb_exec_one(s, sql, strlen(sql), NULL, 0, &r, E);
    if (!rc) imdb_result_free(&r);
    return rc;
}

static uint64_t ret_of(imdb_db *db, const char *name)
{
    imdb_table *t = imdb_table_by_name(db, name);
    return t ? t->retention_us : 0;
}

static int audit_ok(const char *dir) /* 1: no auditor in this build (IMDB_AUDIT_BIN) */
{
    const char *bin = getenv("IMDB_AUDIT_BIN");
    if (!bin || !*bin) return 1;
    char cmd[1600];
    snprintf(cmd, sizeof cmd, "'%s' verify '%s' >/dev/null 2>&1", bin, dir);
    return system(cmd) == 0;
}

/* The DDL: the default (24 hours) written out, a RETENTION clause in each unit and FOREVER, ALTER in
 * effect from its commit, SHOW RETENTION in the largest whole unit; out of range, malformed or misplaced
 * ones refused, by SQL and by the C API */
static void t_retain_ddl(void)
{
    const char *dir = test_tmpdir();
    OK(imdb_init(dir, false, NULL, E));
    imdb_db *db = ropen(dir, false);
    CHECK(db);
    if (!db) return;
    imdb_session s;
    imdb_session_init(&s, db);
    OK(ex(&s, "CREATE TABLE a (id INT64 PRIMARY KEY, v INT64)"));
    OK(ex(&s, "CREATE TABLE b (id INT64 PRIMARY KEY, v INT64) RETENTION 90 MINUTES"));
    OK(ex(&s, "CREATE TABLE c (id INT64 PRIMARY KEY, v INT64) retention forever"));
    OK(ex(&s, "CREATE TABLE d (id INT64 PRIMARY KEY, v INT64) RETENTION 1 SECOND"));
    CHECK(ret_of(db, "a") == IMDB_RETAIN_DEFAULT_US && IMDB_RETAIN_DEFAULT_US == 24 * HOUR_US);
    CHECK(ret_of(db, "b") == 90 * 60ull * 1000000 && ret_of(db, "c") == IMDB_RETAIN_FOREVER && ret_of(db, "d") == 1000000);
    OK(ex(&s, "ALTER TABLE a SET RETENTION 7 DAYS"));
    CHECK(ret_of(db, "a") == 7 * 24 * HOUR_US);
    imdb_result r;
    imdb_err_clear(E);
    OK(imdb_exec_one(&s, "SHOW RETENTION", 14, NULL, 0, &r, E));
    static const char *const want[] = {"7 DAYS", "90 MINUTES", "FOREVER", "1 SECOND"};
    bool shown = r.nrows == 4 && r.ncols == 3;
    for (uint64_t i = 0; shown && i < r.nrows; i++) {
        const imdb_value *v = &r.cells[i * r.ncols + 1].v;
        shown = v->len == strlen(want[i]) && memcmp(v->s, want[i], v->len) == 0;
    }
    imdb_result_free(&r);
    CHECK(shown);
    static const char *const bad[] = {
        "CREATE TABLE e (id INT64 PRIMARY KEY) RETENTION 0 SECONDS",    /* below a second */
        "CREATE TABLE e (id INT64 PRIMARY KEY) RETENTION 36526 DAYS",   /* past a century */
        "CREATE TABLE e (id INT64 PRIMARY KEY) RETENTION 5",            /* no unit */
        "CREATE TABLE e (id INT64 PRIMARY KEY) RETENTION -5 DAYS",      /* not an unsigned count */
        "CREATE TABLE e (id INT64 PRIMARY KEY) RETENTION 5 WEEKS",      /* no such unit */
        "ALTER TABLE nosuch SET RETENTION 1 DAY",                       /* no such table */
        "ALTER TABLE a SET RETENTION",                                  /* nothing after it */
    };
    for (size_t i = 0; i < sizeof bad / sizeof *bad; i++) CHECK(ex(&s, bad[i]) != 0);
    CHECK(!imdb_table_by_name(db, "e") && ret_of(db, "a") == 7 * 24 * HOUR_US);
    OK(ex(&s, "BEGIN"));
    CHECK(ex(&s, "ALTER TABLE a SET RETENTION 1 DAY") == IMDB_ERR_STATE); /* it commits on its own, as CREATE does */
    OK(ex(&s, "ROLLBACK"));
    CHECK(ret_of(db, "a") == 7 * 24 * HOUR_US);
    imdb_session_close(&s);
    OK(imdb_begin(db, E));
    imdb_table *ta = imdb_table_by_name(db, "a");
    imdb_err_clear(E);
    CHECK(imdb_set_retention(db, ta, IMDB_RETAIN_MIN_US - 1, E) == IMDB_ERR_INVALID);
    imdb_err_clear(E);
    CHECK(imdb_set_retention(db, ta, IMDB_RETAIN_MAX_US + 1, E) == IMDB_ERR_INVALID);
    imdb_err_clear(E);
    OK(imdb_set_retention(db, ta, IMDB_RETAIN_MAX_US, E));
    imdb_rollback(db); /* nothing was installed: the table keeps its retention */
    CHECK(ret_of(db, "a") == 7 * 24 * HOUR_US);
    imdb_close(db);
}

/* The retention survives every way back: a snapshot open (manifest version 4 carries it, its boundary
 * 0), a full replay (op 16 replayed), an ALTER in the log's tail past the snapshot, a replica by ship |
 * apply; VERIFY re-derives it on both copies and the auditor accepts both */
static void t_retain_persist(void)
{
    const char *dir = test_tmpdir();
    char p[700], r[700], sf[700];
    snprintf(p, sizeof p, "%s/p", dir);
    snprintf(r, sizeof r, "%s/r", dir);
    snprintf(sf, sizeof sf, "%s/stream", dir);
    OK(imdb_init(p, false, NULL, E));
    OK(imdb_init(r, true, p, E));
    imdb_db *db = ropen(p, false);
    CHECK(db);
    if (!db) return;
    imdb_session s;
    imdb_session_init(&s, db);
    OK(ex(&s, "CREATE TABLE a (id INT64 PRIMARY KEY, v INT64) RETENTION 2 HOURS"));
    OK(ex(&s, "CREATE TABLE b (id INT64 PRIMARY KEY, v INT64)"));
    OK(ex(&s, "INSERT INTO a VALUES (1, 1)"));
    OK(ex(&s, "CHECKPOINT"));
    imdb_manifest m;
    OK(imdb_manifest_parse(db->lake_mbytes, db->lake_mlen, &m, E));
    CHECK(m.nt == 2 && m.t[0].retention_us == 2 * HOUR_US && m.t[1].retention_us == IMDB_RETAIN_DEFAULT_US &&
          m.boundary == 0);
    imdb_manifest_free(&m);
    OK(ex(&s, "ALTER TABLE b SET RETENTION FOREVER")); /* in the tail only */
    uint64_t pseq = db->seq;
    imdb_session_close(&s);
    imdb_close(db);
    for (int full = 0; full < 2; full++) {
        db = ropen(p, full);
        CHECK(db);
        if (!db) return;
        CHECK(ret_of(db, "a") == 2 * HOUR_US && ret_of(db, "b") == IMDB_RETAIN_FOREVER);
        CHECK(full || db->snapshot_seq > 0); /* the first open from the snapshot, the second a full replay */
        imdb_verify_report vr;
        memset(&vr, 0, sizeof vr);
        OK(imdb_verify(db, &vr, E));
        imdb_close(db);
    }
    OK(ship_to_file(p, 0, sf, E));
    imdb_db *rdb = ropen(r, false);
    CHECK(rdb);
    if (!rdb) return;
    uint64_t applied = 0;
    OK(apply_file(rdb, sf, &applied, E));
    CHECK(applied == pseq && rdb->seq == pseq && ret_of(rdb, "a") == 2 * HOUR_US && ret_of(rdb, "b") == IMDB_RETAIN_FOREVER);
    imdb_verify_report vr;
    memset(&vr, 0, sizeof vr);
    OK(imdb_verify(rdb, &vr, E));
    imdb_close(rdb);
    CHECK(audit_ok(p) && audit_ok(r));
}

/* The log's rules for op 16 on real header bytes: one encoding of a table's retention, always logged.
 * The decoder refuses a CREATE_TABLE without its op 16 at once after it, an op 16 for another table
 * there, and a retention out of range; the encoder never produces either, so nothing such is signed. */
static void t_retain_log_rules(void)
{
    imdb_schema sc;
    txn_schema(&sc);
    sc.id = 0;
    imdb_op ops[2];
    memset(ops, 0, sizeof ops);
    ops[0].code = IMDB_OP_CREATE_TABLE;
    ops[0].schema = &sc;
    ops[1].code = IMDB_OP_SET_RETENTION;
    ops[1].retention_us = IMDB_RETAIN_DEFAULT_US;
    imdb_commit_rec c;
    memset(&c, 0, sizeof c);
    c.seq = 1;
    c.alg = IMDB_DIGEST_ALG_LTHASH16_TREE;
    c.time_us = 1;
    c.ops = ops;
    c.nops = 2;
    imdb_buf b;
    imdb_buf_init(&b);
    imdb_commit_encode_header(&c, &b);
    OK(imdb_buf_check(&b, E));
    imdb_commit_rec d;
    memset(&d, 0, sizeof d);
    OK(imdb_commit_decode_header(b.p, b.len, &d, E));
    CHECK(d.nops == 2 && d.ops[1].code == IMDB_OP_SET_RETENTION && d.ops[1].retention_us == IMDB_RETAIN_DEFAULT_US);
    imdb_commit_free(&d);
    /* op 16 is the 13 bytes before the 32-byte state digest; n_ops the u32 at 50 (version, algorithm,
     * seq, time, prev) */
    size_t n = b.len;
    uint8_t *w = malloc(n);
    CHECK(w && n > 50 + 4 + 13 + 32);
    if (!w) {
        imdb_buf_free(&b);
        return;
    }
    memcpy(w, b.p, n);
    memmove(w + n - 45, w + n - 32, 32); /* op 16 dropped, n_ops 1 */
    w[50] = 1;
    memset(&d, 0, sizeof d);
    imdb_err_clear(E);
    CHECK(imdb_commit_decode_header(w, n - 13, &d, E) == IMDB_ERR_CORRUPT && strstr(g_e.msg, "without its SET_RETENTION"));
    imdb_commit_free(&d);
    memcpy(w, b.p, n);
    w[n - 32 - 12] = 1; /* op 16 names table 1, not CREATE_TABLE's 0 */
    memset(&d, 0, sizeof d);
    imdb_err_clear(E);
    CHECK(imdb_commit_decode_header(w, n, &d, E) == IMDB_ERR_CORRUPT && strstr(g_e.msg, "without its SET_RETENTION"));
    imdb_commit_free(&d);
    memcpy(w, b.p, n);
    memset(w + n - 32 - 8, 0, 8); /* a retention of 0 */
    memset(&d, 0, sizeof d);
    imdb_err_clear(E);
    CHECK(imdb_commit_decode_header(w, n, &d, E) == IMDB_ERR_CORRUPT && strstr(g_e.msg, "retention out of range"));
    imdb_commit_free(&d);
    free(w);
    c.nops = 1; /* CREATE_TABLE alone */
    imdb_buf_free(&b);
    imdb_buf_init(&b);
    imdb_commit_encode_header(&c, &b);
    imdb_err_clear(E);
    CHECK(imdb_buf_check(&b, E) != 0);
    c.nops = 2;
    ops[1].retention_us = 0; /* out of range */
    imdb_buf_free(&b);
    imdb_buf_init(&b);
    imdb_commit_encode_header(&c, &b);
    imdb_err_clear(E);
    CHECK(imdb_buf_check(&b, E) != 0);
    imdb_buf_free(&b);
}

/* ---- step (b): expiry by retention ---------------------------------------------------------- */

#define SEC_US 1000000ll

static uint64_t horizon_of(imdb_db *db, const char *name)
{
    imdb_table *t = imdb_table_by_name(db, name);
    return t ? t->horizon : UINT64_MAX;
}

static bool verify_fails(imdb_db *db, const char *why)
{
    imdb_verify_report vr;
    memset(&vr, 0, sizeof vr);
    imdb_err_clear(E);
    return imdb_verify(db, &vr, E) != IMDB_OK && strstr(g_e.msg, why) != NULL;
}

/* the auditor's verify output holds needle (1 without an auditor in this build) */
static int audit_says(const char *dir, const char *needle)
{
    const char *bin = getenv("IMDB_AUDIT_BIN");
    if (!bin || !*bin) return 1;
    char cmd[1600], line[512];
    snprintf(cmd, sizeof cmd, "'%s' verify '%s' 2>&1", bin, dir);
    FILE *f = popen(cmd, "r");
    if (!f) return 0;
    int found = 0;
    while (fgets(line, sizeof line, f)) found |= strstr(line, needle) != NULL;
    return pclose(f) == 0 && found;
}

static int audit_fails(const char *dir) /* 1: no auditor in this build */
{
    const char *bin = getenv("IMDB_AUDIT_BIN");
    if (!bin || !*bin) return 1;
    char cmd[1600];
    snprintf(cmd, sizeof cmd, "'%s' verify '%s' >/dev/null 2>&1", bin, dir);
    return system(cmd) != 0;
}

/* Two tables, a kept 10 seconds, f FOREVER, each with history, in two log segments; *s2: the second
 * segment's first commit (0 when the setup failed) */
static void expire_setup(imdb_session *s, uint64_t *s2)
{
    imdb_db *db = s->db;
    OK(ex(s, "CREATE TABLE a (id INT64 PRIMARY KEY, v INT64) RETENTION 10 SECONDS"));
    OK(ex(s, "CREATE TABLE f (id INT64 PRIMARY KEY, v INT64) RETENTION FOREVER"));
    OK(ex(s, "INSERT INTO a VALUES (1, 1)"));
    OK(ex(s, "INSERT INTO f VALUES (1, 1)"));
    OK(ex(s, "UPDATE a SET v = 2 WHERE id = 1"));
    OK(ex(s, "UPDATE f SET v = 2 WHERE id = 1"));
    OK(ex(s, "CHECKPOINT")); /* ends the first segment */
    uint64_t first = db->seq + 1;
    OK(ex(s, "INSERT INTO a VALUES (2, 2)"));
    OK(ex(s, "UPDATE a SET v = 3 WHERE id = 1"));
    OK(ex(s, "CHECKPOINT"));
    CHECK(db->nsegs == 2 && db->segs[1] == first);
    *s2 = first;
}

/* A table kept for R moves its horizon by a logged EXPIRE to the newest segment start at least R old,
 * once; a FOREVER table never does. AS OF below the horizon is refused, at it answered. The horizon is
 * in the next manifest, survives both kinds of open, reaches a replica, and VERIFY and the auditor
 * re-derive it, the rule checked against the segments' first times. */
static void t_retain_expire(void)
{
    const char *dir = test_tmpdir();
    char p[700], r[700], sf[700];
    snprintf(p, sizeof p, "%s/p", dir);
    snprintf(r, sizeof r, "%s/r", dir);
    snprintf(sf, sizeof sf, "%s/stream", dir);
    OK(imdb_init(p, false, NULL, E));
    OK(imdb_init(r, true, p, E));
    imdb_db *db = ropen(p, false);
    CHECK(db);
    if (!db) return;
    imdb_session s;
    imdb_session_init(&s, db);
    uint64_t s2 = 0;
    expire_setup(&s, &s2);
    if (!s2) return;
    uint64_t before = db->seq;
    OK(ex(&s, "SELECT COUNT(*) FROM a")); /* every statement runs the policy: nothing is 10 seconds old */
    CHECK(db->seq == before && horizon_of(db, "a") == 0);
    imdb_clock_offset(15 * SEC_US);
    OK(ex(&s, "SELECT COUNT(*) FROM f")); /* both segments now began more than 10 seconds ago */
    CHECK(db->seq == before + 1 && horizon_of(db, "a") == s2 && horizon_of(db, "f") == 0);
    OK(ex(&s, "SELECT COUNT(*) FROM f"));
    CHECK(db->seq == before + 1); /* once: the next segment start is not old yet */
    char q[200];
    snprintf(q, sizeof q, "SELECT v FROM a AS OF %llu WHERE id = 1", (unsigned long long)(s2 - 1));
    CHECK(ex(&s, q) == IMDB_ERR_HISTORY);
    snprintf(q, sizeof q, "SELECT v FROM a AS OF %llu WHERE id = 1", (unsigned long long)s2);
    OK(ex(&s, q));
    OK(ex(&s, "SELECT v FROM f AS OF 3 WHERE id = 1"));
    imdb_result res;
    imdb_err_clear(E);
    OK(imdb_exec_one(&s, "SHOW RETENTION", 14, NULL, 0, &res, E));
    CHECK(res.nrows == 2 && res.cells[2].v.i == (int64_t)s2 && res.cells[5].v.i == 0); /* history_from */
    imdb_result_free(&res);
    imdb_verify_report vr;
    memset(&vr, 0, sizeof vr);
    OK(imdb_verify(db, &vr, E));
    OK(ex(&s, "CHECKPOINT")); /* the manifest carries the horizon */
    imdb_manifest m;
    OK(imdb_manifest_parse(db->lake_mbytes, db->lake_mlen, &m, E));
    CHECK(m.t[0].horizon == s2 && m.t[1].horizon == 0);
    imdb_manifest_free(&m);
    OK(ex(&s, "INSERT INTO a VALUES (3, 3)")); /* and a tail past it */
    uint64_t pseq = db->seq;
    imdb_session_close(&s);
    imdb_close(db);
    for (int full = 0; full < 2; full++) {
        db = ropen(p, full);
        CHECK(db);
        if (!db) return;
        CHECK(horizon_of(db, "a") == s2 && horizon_of(db, "f") == 0 && (full || db->snapshot_seq > 0));
        memset(&vr, 0, sizeof vr);
        OK(imdb_verify(db, &vr, E));
        imdb_close(db);
    }
    OK(ship_to_file(p, 0, sf, E));
    imdb_db *rdb = ropen(r, false);
    CHECK(rdb);
    if (!rdb) return;
    uint64_t applied = 0;
    OK(apply_file(rdb, sf, &applied, E));
    CHECK(rdb->seq == pseq && horizon_of(rdb, "a") == s2 && horizon_of(rdb, "f") == 0);
    memset(&vr, 0, sizeof vr);
    OK(imdb_verify(rdb, &vr, E));
    imdb_close(rdb);
    CHECK(audit_ok(p) && audit_ok(r));
}

/* The log's first commit is a segment start too: a young database whose only start old enough is commit 1
 * expires to it (the policy names it; VERIFY and the auditor, which keep it as the first segment's, accept
 * it), in both kinds of open; an unknown table refused by the op's own check */
static void t_retain_expire_first(void)
{
    const char *dir = test_tmpdir();
    OK(imdb_init(dir, false, NULL, E));
    imdb_db *db = ropen(dir, false);
    CHECK(db);
    if (!db) return;
    imdb_session s;
    imdb_session_init(&s, db);
    OK(ex(&s, "CREATE TABLE a (id INT64 PRIMARY KEY, v INT64) RETENTION 10 SECONDS"));
    OK(ex(&s, "INSERT INTO a VALUES (1, 1)"));
    OK(ex(&s, "UPDATE a SET v = 2 WHERE id = 1"));
    OK(ex(&s, "CHECKPOINT")); /* the first segment ends: commits 1 to 4 */
    imdb_clock_offset(15 * SEC_US);
    uint64_t s2 = db->seq + 1;
    OK(ex(&s, "INSERT INTO a VALUES (2, 2)")); /* begins the second segment, young; then the policy */
    CHECK(db->nsegs == 2 && db->segs[1] == s2 && horizon_of(db, "a") == 1 && db->seq == s2 + 1);
    imdb_verify_report vr;
    memset(&vr, 0, sizeof vr);
    OK(imdb_verify(db, &vr, E));
    OK(imdb_begin(db, E));
    imdb_err_clear(E);
    CHECK(imdb_expire_op(db, 7, 1, E) == IMDB_ERR_INVALID);
    imdb_rollback(db);
    imdb_session_close(&s);
    imdb_close(db);
    CHECK(audit_ok(dir));
    for (int full = 0; full < 2; full++) {
        db = ropen(dir, full);
        CHECK(db);
        if (!db) return;
        CHECK(horizon_of(db, "a") == 1);
        memset(&vr, 0, sizeof vr);
        OK(imdb_verify(db, &vr, E));
        imdb_close(db);
    }
}

/* No open transaction holds expiry back: one whose snapshot is older than a table's retention has been
 * open that long, and once the horizon passes its snapshot its next read of that table conflicts (it
 * can only roll back; the retry reads); one reading only a FOREVER table keeps its snapshot and commits */
static void t_retain_expire_txn(void)
{
    const char *dir = test_tmpdir();
    OK(imdb_init(dir, false, NULL, E));
    imdb_db *db = ropen(dir, false);
    CHECK(db);
    if (!db) return;
    imdb_session s, x1, x2;
    imdb_session_init(&s, db);
    imdb_session_init(&x1, db);
    imdb_session_init(&x2, db);
    OK(ex(&s, "CREATE TABLE a (id INT64 PRIMARY KEY, v INT64) RETENTION 10 SECONDS"));
    OK(ex(&s, "CREATE TABLE f (id INT64 PRIMARY KEY, v INT64) RETENTION FOREVER"));
    OK(ex(&s, "INSERT INTO a VALUES (1, 1)"));
    OK(ex(&s, "INSERT INTO f VALUES (1, 1)"));
    OK(ex(&x1, "BEGIN"));
    OK(ex(&x1, "SELECT v FROM a WHERE id = 1")); /* its snapshot: commit 4 */
    OK(ex(&x2, "BEGIN"));
    OK(ex(&x2, "SELECT v FROM f WHERE id = 1"));
    OK(ex(&s, "UPDATE a SET v = 2 WHERE id = 1"));
    OK(ex(&s, "CHECKPOINT"));
    uint64_t s2 = db->seq + 1;
    OK(ex(&s, "INSERT INTO a VALUES (2, 2)"));
    OK(ex(&s, "CHECKPOINT"));
    OK(ex(&x1, "SELECT v FROM a WHERE id = 1")); /* still inside the retention */
    imdb_clock_offset(15 * SEC_US);
    OK(ex(&s, "SELECT COUNT(*) FROM f")); /* the policy: a's horizon passes x1's snapshot */
    CHECK(horizon_of(db, "a") == s2 && s2 > x1.txn.snap);
    CHECK(ex(&x1, "SELECT v FROM a WHERE id = 1") == IMDB_ERR_CONFLICT && strstr(g_e.msg, "roll back and retry"));
    CHECK(ex(&x1, "SELECT v FROM f WHERE id = 1") == IMDB_ERR_CONFLICT); /* doomed now */
    OK(ex(&x1, "ROLLBACK"));
    OK(ex(&x1, "BEGIN"));
    OK(ex(&x1, "SELECT v FROM a WHERE id = 1")); /* the retry, from a fresh snapshot */
    OK(ex(&x1, "COMMIT"));
    OK(ex(&x2, "SELECT v FROM f WHERE id = 1")); /* f keeps its history: x2 is untouched */
    OK(ex(&x2, "UPDATE f SET v = 5 WHERE id = 1"));
    OK(ex(&x2, "COMMIT"));
    imdb_verify_report vr;
    memset(&vr, 0, sizeof vr);
    OK(imdb_verify(db, &vr, E));
    imdb_session_close(&x1);
    imdb_session_close(&x2);
    imdb_session_close(&s);
    imdb_close(db);
    CHECK(audit_ok(dir));
}

/* EXPIRE's rule, re-derived from the log: VERIFY and the auditor refuse an EXPIRE naming a commit that
 * begins no log segment, one of history younger than the retention, one of a FOREVER table and one
 * that does not move the horizon; replay refuses the last two. The policy commits none of them: these
 * are committed by hand. The encoder refuses what the decoder would (an EXPIRE beside another op, two
 * for one table, out of table order, a horizon not in the past), so nothing such is ever signed. */
static void t_retain_expire_rules(void)
{
    static const struct {
        int kind; /* 0 not a start, 1 too young, 2 FOREVER, 3 does not move */
        const char *verify, *open;
    } cases[] = {
        {0, "begins no log segment", NULL},
        {1, "younger than the table's retention", NULL},
        {2, "kept FOREVER", "kept FOREVER"},
        {3, "does not move the horizon", "does not move"},
    };
    for (size_t k = 0; k < sizeof cases / sizeof *cases; k++) {
        imdb_clock_offset(0);
        const char *dir = test_tmpdir();
        OK(imdb_init(dir, false, NULL, E));
        imdb_db *db = ropen(dir, false);
        CHECK(db);
        if (!db) return;
        imdb_session s;
        imdb_session_init(&s, db);
        uint64_t s2 = 0;
        expire_setup(&s, &s2);
        if (!s2) return;
        if (cases[k].kind != 1) imdb_clock_offset(15 * SEC_US);
        if (cases[k].kind == 3) OK(ex(&s, "SELECT COUNT(*) FROM f")); /* the policy's own EXPIRE first */
        uint32_t table = imdb_table_by_name(db, cases[k].kind == 2 ? "f" : "a")->s.id;
        uint64_t before = cases[k].kind == 0 ? s2 + 1 : s2;
        OK(imdb_begin(db, E));
        OK(imdb_expire_op(db, table, before, E));
        OK(imdb_commit(db, E)); /* the engine installs what it signs */
        CHECK(verify_fails(db, cases[k].verify));
        imdb_session_close(&s);
        imdb_close(db);
        CHECK(audit_fails(dir));
        if (cases[k].open) {
            imdb_open_opts o = {.sync = 0, .full_replay = true};
            db = NULL;
            imdb_err_clear(E);
            CHECK(imdb_open(dir, &o, &db, E) != IMDB_OK && strstr(g_e.msg, cases[k].open));
            if (db) imdb_close(db);
        }
    }
    imdb_clock_offset(0);
    /* the encoder's refusals: nothing signed */
    const char *dir = test_tmpdir();
    OK(imdb_init(dir, false, NULL, E));
    imdb_db *db = ropen(dir, false);
    CHECK(db);
    if (!db) return;
    imdb_session s;
    imdb_session_init(&s, db);
    OK(ex(&s, "CREATE TABLE a (id INT64 PRIMARY KEY, v INT64) RETENTION 10 SECONDS"));
    OK(ex(&s, "CREATE TABLE b (id INT64 PRIMARY KEY, v INT64) RETENTION 10 SECONDS"));
    OK(ex(&s, "INSERT INTO a VALUES (1, 1)"));
    uint64_t seq = db->seq;
    static const uint32_t tabs[][2] = {{0, 0}, {1, 0}};
    for (int k = 0; k < 3; k++) {
        OK(imdb_begin(db, E));
        if (k < 2) {
            OK(imdb_expire_op(db, tabs[k][0], 1, E));
            OK(imdb_expire_op(db, tabs[k][1], 1, E));
        } else {
            OK(imdb_expire_op(db, 0, db->seq + 1, E)); /* its own commit */
        }
        imdb_err_clear(E);
        CHECK(imdb_commit(db, E) != IMDB_OK && db->seq == seq);
    }
    OK(imdb_begin(db, E));
    OK(imdb_set_retention(db, imdb_table_by_name(db, "a"), IMDB_RETAIN_FOREVER, E));
    OK(imdb_expire_op(db, 1, 1, E)); /* beside another op */
    imdb_err_clear(E);
    CHECK(imdb_commit(db, E) != IMDB_OK && db->seq == seq);
    imdb_session_close(&s);
    imdb_close(db);
    /* the decoder's, on real header bytes: two EXPIREs (tables 0 and 1, horizon 1) at commit 5 */
    imdb_op ops[2];
    memset(ops, 0, sizeof ops);
    ops[0].code = ops[1].code = IMDB_OP_EXPIRE;
    ops[1].table = 1;
    ops[0].purge_before = ops[1].purge_before = 1;
    imdb_commit_rec c;
    memset(&c, 0, sizeof c);
    c.seq = 5;
    c.alg = IMDB_DIGEST_ALG_LTHASH16_TREE;
    c.time_us = 1;
    c.ops = ops;
    c.nops = 2;
    imdb_buf b;
    imdb_buf_init(&b);
    imdb_commit_encode_header(&c, &b);
    OK(imdb_buf_check(&b, E));
    imdb_commit_rec d;
    memset(&d, 0, sizeof d);
    OK(imdb_commit_decode_header(b.p, b.len, &d, E));
    CHECK(d.nops == 2 && d.ops[1].code == IMDB_OP_EXPIRE && d.ops[1].table == 1 && d.ops[1].purge_before == 1);
    imdb_commit_free(&d);
    /* the ops: 13 bytes each (code, u32 table, u64 horizon) from offset 54, the digest's 32 after them */
    size_t n = b.len;
    CHECK(n == 54 + 2 * 13 + 32);
    uint8_t *w = malloc(n);
    CHECK(w != NULL);
    if (!w) {
        imdb_buf_free(&b);
        return;
    }
    static const struct {
        size_t at;
        uint8_t v;
        const char *why;
    } bad[] = {
        {54 + 13 + 1, 0, "one a table, by table"},          /* the second names table 0 too */
        {54 + 1, 2, "one a table, by table"},               /* tables 2 then 1 */
        {54 + 13 + 5, 5, "not in the past"},                /* a horizon at its own commit */
        {54 + 5, 0, "not in the past"},                     /* a horizon of 0 */
        {54 + 13, IMDB_OP_SET_RETENTION, "stand alone"},    /* beside another op (the bytes fit op 16) */
    };
    for (size_t k = 0; k < sizeof bad / sizeof *bad; k++) {
        memcpy(w, b.p, n);
        w[bad[k].at] = bad[k].v;
        if (bad[k].v == IMDB_OP_SET_RETENTION) memset(w + 54 + 13 + 5, 0xff, 8); /* a FOREVER retention there */
        memset(&d, 0, sizeof d);
        imdb_err_clear(E);
        CHECK(imdb_commit_decode_header(w, n, &d, E) == IMDB_ERR_CORRUPT && strstr(g_e.msg, bad[k].why));
        imdb_commit_free(&d);
    }
    free(w);
    imdb_buf_free(&b);
}

/* When a segment began, from its first frame alone, in both formats: a small first frame and one larger
 * than the first read, a missing segment and a damaged first frame refused */
static void t_retain_seg_time(void)
{
    for (int tagged = 1; tagged >= 0; tagged--) {
        imdb_log_set_tagged(tagged != 0);
        const char *dir = test_tmpdir();
        OK(imdb_init(dir, false, NULL, E));
        imdb_db *db = ropen(dir, false);
        CHECK(db);
        if (!db) return;
        imdb_session s;
        imdb_session_init(&s, db);
        OK(ex(&s, "CREATE TABLE a (id INT64 PRIMARY KEY, v TEXT)"));
        OK(ex(&s, "CHECKPOINT"));
        uint64_t s2 = db->seq + 1;
        char *sql = malloc(64 * 1024);
        CHECK(sql != NULL);
        if (!sql) return;
        size_t at = (size_t)snprintf(sql, 64 * 1024, "INSERT INTO a VALUES ");
        for (int i = 0; i < 300; i++) /* a first frame of about 20 kB: more than the first read */
            at += (size_t)snprintf(sql + at, 64 * 1024 - at, "%s(%d, 'row %d of the first commit of the segment, padded')",
                                   i ? ", " : "", i, i);
        OK(ex(&s, sql));
        free(sql);
        uint64_t t2 = db->last_time;
        OK(ex(&s, "CHECKPOINT"));
        uint64_t t1 = 0, tt = 0;
        OK(imdb_logseg_first_time(db->logdirfd, 1, &t1, E));
        OK(imdb_logseg_first_time(db->logdirfd, s2, &tt, E));
        CHECK(t1 > 0 && t1 < t2 && tt == t2);
        imdb_err_clear(E);
        CHECK(imdb_logseg_first_time(db->logdirfd, s2 + 1, &tt, E) == IMDB_ERR_IO); /* no such segment */
        imdb_session_close(&s);
        imdb_close(db);
        char seg[800];
        snprintf(seg, sizeof seg, "%s/log/%020llu.ilg", dir, (unsigned long long)s2);
        size_t n = 0;
        uint8_t *b = slurp(seg, &n);
        CHECK(b && n > 2048);
        if (!b) return;
        b[(tagged ? IMDB_TSEG_SECTOR + 8 : 0) + IMDB_FRAME_HDR + 200] ^= 1; /* inside its body: the checksum fails */
        spit(seg, b, n);
        free(b);
        char logdir[800];
        snprintf(logdir, sizeof logdir, "%s/log", dir);
        int lfd = open(logdir, O_RDONLY | O_DIRECTORY | O_CLOEXEC); /* an open would refuse the damage itself */
        CHECK(lfd >= 0);
        if (lfd < 0) return;
        imdb_err_clear(E);
        CHECK(imdb_logseg_first_time(lfd, s2, &tt, E) == IMDB_ERR_CORRUPT && strstr(g_e.msg, "no whole first frame"));
        OK(imdb_logseg_first_time(lfd, 1, &tt, E)); /* the segment before it is intact */
        CHECK(tt == t1);
        close(lfd);
    }
}

/* ---- step (c1): RETIRE, the log kept whole --------------------------------------------------- */

static int64_t sval_of(imdb_session *s, const char *sql) /* a query's one value; INT64_MIN when it fails */
{
    imdb_result r;
    imdb_err_clear(E);
    if (imdb_exec_one(s, sql, strlen(sql), NULL, 0, &r, E)) return INT64_MIN;
    int64_t v = r.nrows == 1 && r.ncols >= 1 ? r.cells[0].v.i : INT64_MIN;
    imdb_result_free(&r);
    return v;
}

static uint64_t held_of(imdb_db *db, const char *name)
{
    imdb_table *t = imdb_table_by_name(db, name);
    uint64_t n = 0;
    if (!t) return 0;
    for (uint64_t vid = imdb_v_skip(t, 0); vid < t->nver; vid = imdb_v_skip(t, vid + 1)) n += imdb_v_present(t, vid);
    return n;
}

/* Two tables kept 10 seconds, a with history in the first segment, a unique index on b; the policy's EXPIRE
 * moves both horizons to the second segment's start. *s2: that start (0 when the setup failed) */
static void retire_setup(imdb_session *s, uint64_t *s2)
{
    imdb_db *db = s->db;
    db->no_auto_retire = true; /* these tests RETIRE by hand (retain_retire_policy tests the policy) */
    OK(ex(s, "CREATE TABLE a (id INT64 PRIMARY KEY, v INT64) RETENTION 10 SECONDS"));
    OK(ex(s, "CREATE TABLE b (id INT64 PRIMARY KEY, k INT64) RETENTION 10 SECONDS"));
    OK(ex(s, "CREATE UNIQUE INDEX bk ON b (k)"));
    OK(ex(s, "INSERT INTO a VALUES (1, 0), (2, 0)"));
    OK(ex(s, "INSERT INTO b VALUES (1, 10), (2, 20)"));
    for (int i = 1; i <= 5; i++) {
        char q[100];
        snprintf(q, sizeof q, "UPDATE a SET v = %d WHERE id = 1", i);
        OK(ex(s, q));
    }
    OK(ex(s, "UPDATE b SET k = 11 WHERE id = 1"));
    OK(ex(s, "CHECKPOINT")); /* the first segment ends */
    uint64_t first = db->seq + 1;
    OK(ex(s, "UPDATE a SET v = 100 WHERE id = 1"));
    OK(ex(s, "UPDATE b SET k = 12 WHERE id = 1"));
    OK(ex(s, "CHECKPOINT"));
    imdb_clock_offset(15 * SEC_US);
    OK(ex(s, "SELECT COUNT(*) FROM a")); /* the policy: both horizons to the second segment's start */
    CHECK(horizon_of(db, "a") == first && horizon_of(db, "b") == first);
    *s2 = first;
}

/* RETIRE below the horizon: every version ended at or before the boundary leaves the store, the lake and the
 * indexes, nothing a horizon answers does; refused when the boundary is not past the last, ends no segment or
 * reaches a horizon; the store keeps working; a reopen from the snapshot (vids it never holds again) and a full
 * replay (which re-executes the RETIRE) agree, as does a replica; VERIFY re-derives the retired set exactly */
static void t_retain_retire(void)
{
    const char *dir = test_tmpdir();
    char p[700], r[700], sf[700];
    snprintf(p, sizeof p, "%s/p", dir);
    snprintf(r, sizeof r, "%s/r", dir);
    snprintf(sf, sizeof sf, "%s/stream", dir);
    OK(imdb_init(p, false, NULL, E));
    OK(imdb_init(r, true, p, E));
    imdb_db *db = ropen(p, false);
    CHECK(db);
    if (!db) return;
    imdb_session s;
    imdb_session_init(&s, db);
    uint64_t s2 = 0;
    retire_setup(&s, &s2);
    if (!s2) return;
    uint64_t B = s2 - 1, held_a = held_of(db, "a"), held_b = held_of(db, "b");
    CHECK(held_a == 2 + 5 + 1 && held_b == 2 + 2); /* every version so far */
    /* the replica follows before the RETIRE: past the cut a copy below the floor can only be seeded again (e) */
    OK(ship_to_file(p, 0, sf, E));
    imdb_db *rdb = ropen(r, false);
    CHECK(rdb);
    if (!rdb) return;
    uint64_t applied = 0, rseq = 0;
    OK(apply_file(rdb, sf, &applied, E));
    rseq = rdb->seq;
    imdb_close(rdb);
    imdb_err_clear(E);
    CHECK(imdb_retire(db, s2, E) == IMDB_ERR_INVALID);     /* reaches the horizon */
    imdb_err_clear(E);
    CHECK(imdb_retire(db, B - 1, E) == IMDB_ERR_INVALID);  /* ends no segment */
    OK(imdb_retire(db, B, E));
    CHECK(db->boundary == B);
    imdb_err_clear(E);
    CHECK(imdb_retire(db, B, E) == IMDB_ERR_INVALID);      /* not past the last */
    /* a: the five versions of id 1 ended inside the first segment are gone; id 1's version ended at s2 stays
     * (AS OF s2 - 1 is refused, but it is s2's predecessor's end that matters: it ended at s2, after B) */
    CHECK(held_of(db, "a") == held_a - 5 && held_of(db, "b") == held_b - 1);
    imdb_manifest m;
    OK(imdb_manifest_parse(db->lake_mbytes, db->lake_mlen, &m, E));
    CHECK(m.boundary == B);
    imdb_manifest_free(&m);
    CHECK(sval_of(&s, "SELECT v FROM a WHERE id = 1") == 100 && sval_of(&s, "SELECT COUNT(*) FROM a") == 2);
    char q[200];
    snprintf(q, sizeof q, "SELECT v FROM a AS OF %llu WHERE id = 1", (unsigned long long)B);
    CHECK(ex(&s, q) == IMDB_ERR_HISTORY);
    snprintf(q, sizeof q, "SELECT v FROM a AS OF %llu WHERE id = 1", (unsigned long long)s2);
    CHECK(sval_of(&s, q) == 100);
    CHECK(ex(&s, "INSERT INTO b VALUES (3, 12)") == IMDB_ERR_CONSTRAINT); /* the unique index, rebuilt */
    OK(ex(&s, "INSERT INTO b VALUES (3, 10)"));                            /* 10 is free since id 1 moved */
    OK(ex(&s, "UPDATE a SET v = 101 WHERE id = 1"));                       /* the store goes on */
    imdb_verify_report vr;
    memset(&vr, 0, sizeof vr);
    OK(imdb_verify(db, &vr, E));
    uint64_t pseq = db->seq;
    imdb_session_close(&s);
    imdb_close(db);
    for (int full = 0; full < 2; full++) {
        db = ropen(p, full);
        if (full) { /* past the cut the log begins after the floor: only the snapshot starts it (FLOOR) */
            CHECK(!db && strstr(g_e.msg, "is retired"));
            if (db) imdb_close(db);
            continue;
        }
        CHECK(db && db->log_floor > 0); /* the cut was made */
        if (!db) return;
        CHECK(db->boundary == B && held_of(db, "a") == held_a - 5 + 1 && held_of(db, "b") == held_b - 1 + 1);
        CHECK(full || (db->snapshot_seq > 0 && !db->warning[0])); /* the snapshot itself, not a fallback replay */
        memset(&vr, 0, sizeof vr);
        OK(imdb_verify(db, &vr, E));
        imdb_close(db);
    }
    char r2[700];
    snprintf(r2, sizeof r2, "%s/r2", dir);
    OK(imdb_init(r2, true, p, E));
    imdb_err_clear(E);
    OK(ship_to_file(p, 0, sf, E)); /* a fresh copy: past the cut, a seed (retain_seed takes one) */
    {
        size_t sn = 0;
        uint8_t *sb = slurp(sf, &sn);
        CHECK(sb && sn > 28 && memcmp(sb, "IMDBSED1", 8) == 0);
        free(sb);
    }
    OK(ship_to_file(p, rseq, sf, E)); /* the one that followed: from where it is, the RETIRE included */
    rdb = ropen(r, false);
    CHECK(rdb);
    if (!rdb) return;
    applied = 0;
    OK(apply_file(rdb, sf, &applied, E));
    CHECK(rdb->seq == pseq && rdb->boundary == B && rdb->log_floor == B && held_of(rdb, "a") == held_a - 5 + 1);
    memset(&vr, 0, sizeof vr);
    OK(imdb_verify(rdb, &vr, E));
    imdb_close(rdb);
    CHECK(audit_ok(p) && audit_ok(r) && audit_says(p, "log floor: commit") && audit_says(r, "log floor: commit"));
}

/* RETIRE's rule, re-derived from the log: VERIFY, the auditor and a replaying open each refuse a boundary not
 * past the last, one whose next commit begins no log segment, and one at or past a horizon (which would drop
 * history still answered); the engine signs none of them (imdb_retire refuses: retain_retire), so these come
 * through the unchecked hook. A boundary the RETIRE's own commit forbids (not at least two below it) the encoder
 * refuses: nothing signed. */
static void t_retain_retire_rules(void)
{
    static const struct {
        int kind; /* 0 not past the last, 1 ends no segment, 2 at or past a horizon */
        const char *verify, *audit_open;
    } cases[] = {
        {0, "is not past", "is not past"},
        {1, "ends no log segment", "log segment"},
        {2, "is not below table", "is not below table"},
    };
    for (size_t k = 0; k < sizeof cases / sizeof *cases; k++) {
        imdb_clock_offset(0);
        g_stride = UINT32_MAX; /* no keepers: with two more publishes below, F's manifest is gone, so no RETIRE here
                                * cuts the log and a replaying open re-executes each (its rule is what this tests) */
        const char *dir = test_tmpdir();
        OK(imdb_init(dir, false, NULL, E));
        imdb_db *db = ropen(dir, false);
        CHECK(db);
        if (!db) return;
        imdb_session s;
        imdb_session_init(&s, db);
        uint64_t s2 = 0;
        retire_setup(&s, &s2);
        if (!s2) return;
        uint64_t B = s2 - 1;
        for (int i = 0; i < 2; i++) { /* F (s2 - 1 or s2 + 2) neither the current generation nor the retained one */
            char q[100];
            snprintf(q, sizeof q, "INSERT INTO b VALUES (%d, %d)", 100 + i, 1000 + i);
            OK(ex(&s, q));
            OK(ex(&s, "CHECKPOINT"));
        }
        if (cases[k].kind == 0) {
            OK(imdb_retire(db, B, E));
            OK(imdb_retire_unchecked(db, B, E)); /* the same boundary again */
        } else if (cases[k].kind == 1) {
            OK(imdb_retire_unchecked(db, B - 1, E)); /* commit B begins no segment */
        } else {
            /* the second segment's end: the commit after it (the EXPIRE) begins one, but b's version ended at
             * s2 + 1 is still answered at AS OF s2 */
            OK(imdb_retire_unchecked(db, s2 + 2, E));
        }
        CHECK(verify_fails(db, cases[k].verify));
        imdb_session_close(&s);
        imdb_close(db);
        CHECK(audit_fails(dir));
        imdb_open_opts o = {.sync = 0, .full_replay = true};
        db = NULL;
        imdb_err_clear(E);
        CHECK(imdb_open(dir, &o, &db, E) != IMDB_OK && strstr(g_e.msg, cases[k].audit_open));
        if (db) imdb_close(db);
        g_stride = 1;
    }
    imdb_clock_offset(0);
    const char *dir = test_tmpdir();
    OK(imdb_init(dir, false, NULL, E));
    imdb_db *db = ropen(dir, false);
    CHECK(db);
    if (!db) return;
    imdb_session s;
    imdb_session_init(&s, db);
    uint64_t s2 = 0;
    retire_setup(&s, &s2);
    if (!s2) return;
    uint64_t seq = db->seq;
    imdb_err_clear(E);
    CHECK(imdb_retire_unchecked(db, db->seq, E) != IMDB_OK && db->seq == seq); /* one below its own commit */
    imdb_session_close(&s);
    imdb_close(db);
}

/* The memory comes back: 70,000 versions, 69,000 of them ended in the first segment, so RETIRE leaves chunk 0
 * (vids 0 to 65,535) with none present and frees it; the store's size and the heap's counter drop by its bytes;
 * the snapshot open allocates no chunk for it again; a full replay frees it the same way */
static void t_retain_retire_chunks(void)
{
    const char *dir = test_tmpdir();
    OK(imdb_init(dir, false, NULL, E));
    imdb_db *db = ropen(dir, false);
    CHECK(db);
    if (!db) return;
    imdb_session s;
    imdb_session_init(&s, db);
    db->no_auto_retire = true;
    OK(ex(&s, "CREATE TABLE a (id INT64 PRIMARY KEY, v INT64) RETENTION 10 SECONDS"));
    char *q = malloc(32 * 1000 + 64);
    CHECK(q != NULL);
    if (!q) return;
    OK(ex(&s, "BEGIN"));
    for (int b = 0; b < 70; b++) {
        size_t at = (size_t)snprintf(q, 64, "INSERT INTO a VALUES ");
        for (int i = 0; i < 1000; i++) at += (size_t)snprintf(q + at, 32, "%s(%d, 0)", i ? ", " : "", b * 1000 + i);
        OK(ex(&s, q));
    }
    free(q);
    OK(ex(&s, "COMMIT"));
    OK(ex(&s, "DELETE FROM a WHERE id < 69000"));
    OK(ex(&s, "CHECKPOINT"));
    uint64_t s2 = db->seq + 1;
    OK(ex(&s, "INSERT INTO a VALUES (100000, 1)"));
    OK(ex(&s, "CHECKPOINT"));
    imdb_clock_offset(15 * SEC_US);
    OK(ex(&s, "SELECT COUNT(*) FROM a"));
    imdb_table *t = imdb_table_by_name(db, "a");
    CHECK(t->horizon == s2 && t->nchunk == 2 && t->nfreed == 0);
    uint64_t bytes = imdb_ver_bytes(t), heap = imdb_heap_bytes();
    OK(imdb_retire(db, s2 - 1, E));
    uint64_t chunk = IMDB_VCHUNK * (sizeof(imdb_version) + sizeof(imdb_version_cold));
    CHECK(t->nfreed == 1 && !t->vh[0] && imdb_ver_bytes(t) == bytes - chunk);
    CHECK(imdb_heap_bytes() + chunk / 2 < heap); /* the chunk's 6 MB and the lake's dropped rows, less the rebuilt */
    CHECK(held_of(db, "a") == 1001 && sval_of(&s, "SELECT COUNT(*) FROM a") == 1001);
    imdb_verify_report vr;
    memset(&vr, 0, sizeof vr);
    OK(imdb_verify(db, &vr, E));
    imdb_session_close(&s);
    imdb_close(db);
    for (int full = 0; full < 2; full++) {
        db = ropen(dir, full);
        if (full) { /* past the cut the log begins after the floor: only the snapshot starts it (FLOOR) */
            CHECK(!db && strstr(g_e.msg, "is retired"));
            if (db) imdb_close(db);
            continue;
        }
        CHECK(db && db->log_floor > 0); /* the cut was made */
        if (!db) return;
        t = imdb_table_by_name(db, "a");
        /* one chunk of entries allocated (the directory's own room may differ from the live handle's) */
        CHECK(t->nfreed == 1 && !t->vh[0] && held_of(db, "a") == 1001 &&
              t->capver - (uint64_t)t->nfreed * IMDB_VCHUNK == IMDB_VCHUNK);
        CHECK(full || (db->snapshot_seq > 0 && !db->warning[0]));
        memset(&vr, 0, sizeof vr);
        OK(imdb_verify(db, &vr, E));
        imdb_close(db);
    }
    CHECK(audit_ok(dir));
}

/* The steady state: a second RETIRE on a store a snapshot open rebuilt sparse (its vids below the first boundary
 * never allocated again), after a second expiry; then AS OF a time before the boundary is refused without the
 * commit index reading back the retired commits (it keeps only those past the boundary), AS OF one past it
 * answered; VERIFY, the auditor and both kinds of reopen agree */
/* the lowest commit any manifest in objects/ was published at (UINT64_MAX: none), and how many there are */
static uint64_t man_min_seq(const char *dir, size_t *n)
{
    char od[800];
    snprintf(od, sizeof od, "%s/objects", dir);
    DIR *d = opendir(od);
    uint64_t lo = UINT64_MAX;
    *n = 0;
    for (struct dirent *de; d && (de = readdir(d));) {
        if (strlen(de->d_name) != 68 || strcmp(de->d_name + 64, ".man") != 0) continue;
        char f[900];
        snprintf(f, sizeof f, "%s/%s", od, de->d_name);
        uint8_t h[40];
        FILE *fp = fopen(f, "rb");
        size_t got = fp ? fread(h, 1, sizeof h, fp) : 0;
        if (fp) fclose(fp);
        if (got != sizeof h) continue;
        uint64_t s = 0;
        for (int k = 7; k >= 0; k--) s = s << 8 | h[32 + k];
        if (s < lo) lo = s;
        (*n)++;
    }
    if (d) closedir(d);
    return lo;
}

static void t_retain_retire_again(void)
{
    const char *dir = test_tmpdir();
    OK(imdb_init(dir, false, NULL, E));
    imdb_db *db = ropen(dir, false);
    CHECK(db);
    if (!db) return;
    imdb_session s;
    imdb_session_init(&s, db);
    uint64_t s2 = 0;
    retire_setup(&s, &s2);
    if (!s2) return;
    OK(imdb_retire(db, s2 - 1, E));
    OK(ex(&s, "UPDATE a SET v = 200 WHERE id = 1"));
    OK(ex(&s, "UPDATE b SET k = 13 WHERE id = 1"));
    OK(ex(&s, "CHECKPOINT"));
    imdb_session_close(&s);
    imdb_close(db);
    db = ropen(dir, false); /* the snapshot: a sparse store from here on */
    CHECK(db && db->snapshot_seq > 0 && !db->warning[0] && db->boundary == s2 - 1);
    if (!db) return;
    db->no_auto_retire = true;
    imdb_session_init(&s, db);
    uint64_t s3 = db->seq + 1;
    OK(ex(&s, "UPDATE a SET v = 300 WHERE id = 1"));
    OK(ex(&s, "CHECKPOINT"));
    imdb_clock_offset(30 * SEC_US);
    OK(ex(&s, "SELECT COUNT(*) FROM b")); /* the second expiry */
    CHECK(horizon_of(db, "a") == s3 && horizon_of(db, "b") == s3);
    uint64_t a_held = held_of(db, "a"), b_held = held_of(db, "b");
    OK(imdb_retire(db, s3 - 1, E));
    /* a: 5 (ended at s2) and 100 (ended by the first UPDATE after the RETIRE) go, 200 (ended at s3) stays; b: 11 and
     * 12 go */
    CHECK(db->boundary == s3 - 1 && held_of(db, "a") == a_held - 2 && held_of(db, "b") == b_held - 2 &&
          db->log_floor == s3 - 1); /* the second cut found its keeper's manifest */
    CHECK(sval_of(&s, "SELECT v FROM a WHERE id = 1") == 300 && sval_of(&s, "SELECT k FROM b WHERE id = 1") == 13);
    CHECK(ex(&s, "SELECT COUNT(*) FROM a AS OF TIMESTAMP '2000-01-01 00:00:00'") == IMDB_ERR_HISTORY);
    CHECK(db->ci_first > s3 - 1 && db->nci <= db->seq - (s3 - 1)); /* nothing at or below the boundary read back */
    imdb_buf tb;
    imdb_buf_init(&tb);
    imdb_format_timestamp((int64_t)imdb_ci_at(db, db->seq, E)->time_us, &tb);
    imdb_buf_put_u8(&tb, 0);
    char q[200];
    snprintf(q, sizeof q, "SELECT v FROM a AS OF TIMESTAMP '%s' WHERE id = 1", (const char *)tb.p);
    imdb_buf_free(&tb);
    CHECK(sval_of(&s, q) == 300);
    imdb_err_clear(E);
    CHECK(imdb_ci_at(db, s2 - 1, E) == NULL && g_e.code == IMDB_ERR_HISTORY); /* retired */
    OK(ex(&s, "CHECKPOINT")); /* the RETIRE's publish becomes the retained generation */
    size_t nman = 0;
    CHECK(man_min_seq(dir, &nman) > db->boundary && nman >= 2); /* keepers past the boundary, none at or below it */
    imdb_verify_report vr;
    memset(&vr, 0, sizeof vr);
    OK(imdb_verify(db, &vr, E));
    imdb_session_close(&s);
    imdb_close(db);
    for (int full = 0; full < 2; full++) {
        db = ropen(dir, full);
        if (full) { /* past the cut the log begins after the floor: only the snapshot starts it (FLOOR) */
            CHECK(!db && strstr(g_e.msg, "is retired"));
            if (db) imdb_close(db);
            continue;
        }
        CHECK(db && db->log_floor > 0); /* the cut was made */
        if (!db) return;
        CHECK(db->boundary == s3 - 1 && held_of(db, "a") == a_held - 2 && (full || db->snapshot_seq > 0));
        memset(&vr, 0, sizeof vr);
        OK(imdb_verify(db, &vr, E));
        imdb_close(db);
    }
    CHECK(audit_ok(dir));
}

/* Purged history and retirement together, on a table with a subject: COMPACT ... PURGE BEFORE n made tombstones of
 * versions ended in both segments; RETIRE below the first drops its tombstones whole and keeps the later ones,
 * which still name their subject (the reindex's tombstone branch); VERIFY's purge point and boundary apart */
static void t_retain_retire_purged(void)
{
    const char *dir = test_tmpdir();
    OK(imdb_init(dir, false, NULL, E));
    imdb_db *db = ropen(dir, false);
    CHECK(db);
    if (!db) return;
    imdb_session s;
    imdb_session_init(&s, db);
    db->no_auto_retire = true;
    OK(ex(&s, "CREATE TABLE c (id INT64 PRIMARY KEY, u INT64 SUBJECT, v INT64) RETENTION 10 SECONDS"));
    OK(ex(&s, "INSERT INTO c VALUES (1, 7, 0), (2, 8, 0)"));
    OK(ex(&s, "UPDATE c SET v = 1 WHERE id = 1"));
    OK(ex(&s, "UPDATE c SET v = 2 WHERE id = 1"));
    OK(ex(&s, "CHECKPOINT")); /* the first segment: vids 0 and 2 end in it */
    uint64_t s2 = db->seq + 1;
    OK(ex(&s, "UPDATE c SET v = 3 WHERE id = 1")); /* ends vid 3 at s2 */
    OK(ex(&s, "UPDATE c SET v = 4 WHERE id = 1")); /* ends vid 4 at s2 + 1 */
    char q[100];
    snprintf(q, sizeof q, "COMPACT c PURGE BEFORE %llu", (unsigned long long)(s2 + 1));
    OK(ex(&s, q)); /* vids 0, 2, 3 and 4: tombstones; the horizon s2 + 1 */
    CHECK(horizon_of(db, "c") == s2 + 1);
    imdb_clock_offset(15 * SEC_US);
    OK(ex(&s, "SELECT COUNT(*) FROM c")); /* the newest old start is s2, below the horizon: no EXPIRE */
    CHECK(horizon_of(db, "c") == s2 + 1);
    OK(imdb_retire(db, s2 - 1, E));
    imdb_table *t = imdb_table_by_name(db, "c");
    CHECK(held_of(db, "c") == 4 && !imdb_v_present(t, 0) && !imdb_v_present(t, 2));
    CHECK((imdb_vh(t, 3)->flags & IMDB_V_PURGED) && (imdb_vh(t, 4)->flags & IMDB_V_PURGED));
    imdb_value sv = {.type = IMDB_T_INT64, .i = 7};
    uint64_t *li = imdb_hmap_get(&t->subj, &sv);
    CHECK(li && t->subj_lists[*li].n == 3); /* subject 7: the two tombstones and the live version */
    snprintf(q, sizeof q, "SELECT v FROM c AS OF %llu WHERE id = 1", (unsigned long long)(s2 + 1));
    CHECK(sval_of(&s, q) == 4);
    imdb_verify_report vr;
    memset(&vr, 0, sizeof vr);
    OK(imdb_verify(db, &vr, E));
    imdb_session_close(&s);
    imdb_close(db);
    for (int full = 0; full < 2; full++) {
        db = ropen(dir, full);
        if (full) { /* past the cut the log begins after the floor: only the snapshot starts it (FLOOR) */
            CHECK(!db && strstr(g_e.msg, "is retired"));
            if (db) imdb_close(db);
            continue;
        }
        CHECK(db && db->log_floor > 0); /* the cut was made */
        if (!db) return;
        t = imdb_table_by_name(db, "c");
        CHECK(held_of(db, "c") == 4 && (imdb_vh(t, 3)->flags & IMDB_V_PURGED) && (full || db->snapshot_seq > 0));
        memset(&vr, 0, sizeof vr);
        OK(imdb_verify(db, &vr, E));
        imdb_close(db);
    }
    CHECK(audit_ok(dir));
}

/* A RETIRE dooms a snapshot transaction at or below its boundary (every table's horizon is past it): even its
 * read-only COMMIT conflicts; one whose snapshot is past the boundary, and a READ COMMITTED one, go on */
static void t_retain_retire_txn(void)
{
    const char *dir = test_tmpdir();
    OK(imdb_init(dir, false, NULL, E));
    imdb_db *db = ropen(dir, false);
    CHECK(db);
    if (!db) return;
    imdb_session s, x1, x2, x3;
    imdb_session_init(&s, db);
    imdb_session_init(&x1, db);
    imdb_session_init(&x2, db);
    imdb_session_init(&x3, db);
    db->no_auto_retire = true;
    OK(ex(&s, "CREATE TABLE a (id INT64 PRIMARY KEY, v INT64) RETENTION 10 SECONDS"));
    OK(ex(&s, "INSERT INTO a VALUES (1, 0), (2, 0)"));
    OK(ex(&x1, "BEGIN"));
    OK(ex(&x1, "SELECT v FROM a WHERE id = 2")); /* its snapshot: commit 2 */
    OK(ex(&x3, "BEGIN ISOLATION LEVEL READ COMMITTED"));
    OK(ex(&x3, "SELECT v FROM a WHERE id = 2"));
    OK(ex(&s, "UPDATE a SET v = 1 WHERE id = 1"));
    OK(ex(&s, "CHECKPOINT"));
    uint64_t s2 = db->seq + 1;
    OK(ex(&s, "UPDATE a SET v = 2 WHERE id = 1"));
    OK(ex(&s, "CHECKPOINT"));
    OK(ex(&x2, "BEGIN"));
    OK(ex(&x2, "SELECT v FROM a WHERE id = 1")); /* its snapshot: past the boundary to come */
    imdb_clock_offset(15 * SEC_US);
    OK(ex(&s, "SELECT COUNT(*) FROM a"));
    CHECK(horizon_of(db, "a") == s2 && x1.txn.snap < s2 - 1 && x2.txn.snap > s2 - 1);
    OK(imdb_retire(db, s2 - 1, E));
    CHECK(x1.txn.doomed && !x2.txn.doomed && !x3.txn.doomed);
    CHECK(ex(&x1, "COMMIT") == IMDB_ERR_CONFLICT && strstr(g_e.msg, "retirement boundary"));
    CHECK(sval_of(&x2, "SELECT v FROM a WHERE id = 1") == 2);
    OK(ex(&x2, "COMMIT"));
    CHECK(sval_of(&x3, "SELECT v FROM a WHERE id = 1") == 2); /* a fresh snapshot each statement */
    OK(ex(&x3, "COMMIT"));
    imdb_session_close(&x1);
    imdb_session_close(&x2);
    imdb_session_close(&x3);
    imdb_session_close(&s);
    imdb_close(db);
}

/* The policy: a RETIRE comes by itself after an expiry once the versions it would drop reach the live rows and an
 * eighth of those held (one ended version against four live: not yet; six: yes), at the lowest horizon's segment
 * start less one; never while a table is kept FOREVER */
static void t_retain_retire_policy(void)
{
    const char *dir = test_tmpdir();
    OK(imdb_init(dir, false, NULL, E));
    imdb_db *db = ropen(dir, false);
    CHECK(db);
    if (!db) return;
    imdb_session s;
    imdb_session_init(&s, db);
    OK(ex(&s, "CREATE TABLE a (id INT64 PRIMARY KEY, v INT64) RETENTION 10 SECONDS"));
    OK(ex(&s, "INSERT INTO a VALUES (1, 0), (2, 0), (3, 0), (4, 0)"));
    OK(ex(&s, "UPDATE a SET v = 1 WHERE id = 1"));
    OK(ex(&s, "CHECKPOINT"));
    uint64_t s2 = db->seq + 1;
    OK(ex(&s, "UPDATE a SET v = 2 WHERE id = 1"));
    OK(ex(&s, "CHECKPOINT"));
    imdb_clock_offset(15 * SEC_US);
    OK(ex(&s, "SELECT COUNT(*) FROM a")); /* the expiry to s2; at s2 - 1 one version ended, four are live */
    CHECK(horizon_of(db, "a") == s2 && db->boundary == 0 && db->retire_cand[0] == s2 - 1 && db->retire_cand_n[0] == 1);
    OK(ex(&s, "UPDATE a SET v = 10 WHERE id >= 1")); /* four more end */
    OK(ex(&s, "CHECKPOINT"));
    uint64_t s4 = db->seq + 1;
    OK(ex(&s, "UPDATE a SET v = 99 WHERE id = 2"));
    OK(ex(&s, "CHECKPOINT"));
    imdb_clock_offset(30 * SEC_US);
    OK(ex(&s, "SELECT COUNT(*) FROM a")); /* the expiry to s4, then six ended at s4 - 1: the RETIRE */
    CHECK(horizon_of(db, "a") == s4 && db->boundary == s4 - 1 && held_of(db, "a") == 11 - 6);
    OK(ex(&s, "CREATE TABLE f (id INT64 PRIMARY KEY) RETENTION FOREVER"));
    OK(ex(&s, "UPDATE a SET v = 7 WHERE id = 3"));
    OK(ex(&s, "CHECKPOINT"));
    imdb_clock_offset(45 * SEC_US);
    OK(ex(&s, "SELECT COUNT(*) FROM a")); /* a expires again, but f holds horizon 0: no RETIRE */
    CHECK(horizon_of(db, "a") > s4 && db->boundary == s4 - 1);
    imdb_verify_report vr;
    memset(&vr, 0, sizeof vr);
    OK(imdb_verify(db, &vr, E));
    imdb_session_close(&s);
    imdb_close(db);
    CHECK(audit_ok(dir));
}

/* (c2) the cut: FLOOR is what a copy past it begins from, so the engine's open and the auditor refuse it damaged, and
 * refuse one whose manifest or segment starts were changed and the checksum made good again */
static void t_retain_floor_forged(void)
{
    const char *dir = test_tmpdir();
    OK(imdb_init(dir, false, NULL, E));
    imdb_db *db = ropen(dir, false);
    CHECK(db);
    if (!db) return;
    imdb_session s;
    imdb_session_init(&s, db);
    uint64_t s2 = 0;
    retire_setup(&s, &s2);
    if (!s2) return;
    OK(imdb_retire(db, s2 - 1, E));
    CHECK(db->log_floor == s2 - 1 && db->nfloor_starts == 1); /* the starts in (0, F]: every horizon at F is 0: commit 1 */
    imdb_session_close(&s);
    imdb_close(db);
    char fp[800];
    snprintf(fp, sizeof fp, "%s/FLOOR", dir);
    size_t n = 0;
    uint8_t *orig = slurp(fp, &n), *b = malloc(n ? n : 1);
    CHECK(orig && b && n > 200);
    if (!orig || !b) return;
    static const struct {
        int what; /* 0 a byte of F's header (the checksum fails), 1 the manifest, 2 the segment starts, 3 F's header */
        const char *why;
    } cases[] = {{0, "FLOOR: damaged"},
                 {1, "is not the one commit"},
                 {2, "not ascending below the floor"},
                 {3, "is not signed by its writer key"}};
    uint64_t mlen = 0; /* the manifest is last, before the checksum, after its u64 length */
    for (size_t at = n - 4 - 8; at > 64 && !mlen; at--) {
        uint64_t v = 0;
        for (int i = 7; i >= 0; i--) v = v << 8 | orig[at + (size_t)i];
        if (v && at + 8 + v == n - 4) mlen = v;
    }
    CHECK(mlen > 64);
    for (size_t k = 0; k < sizeof cases / sizeof *cases; k++) {
        memcpy(b, orig, n);
        if (cases[k].what == 0) {
            b[40] ^= 1;
        } else {
            if (cases[k].what == 1) b[n - 4 - mlen / 2] ^= 1; /* inside the manifest */
            else if (cases[k].what == 2) memset(b + n - 4 - mlen - 8 - 16, 0, 8); /* the last start's seq zeroed */
            else b[36 + 12] ^= 1; /* a byte of F's time: only the signature can tell */
            uint32_t crc = imdb_kern()->crc32c(0, b, n - 4);
            for (int i = 0; i < 4; i++) b[n - 4 + (size_t)i] = (uint8_t)(crc >> (8 * i));
        }
        spit(fp, b, n);
        imdb_open_opts o = {.sync = 0};
        db = NULL;
        imdb_err_clear(E);
        CHECK(imdb_open(dir, &o, &db, E) != IMDB_OK && strstr(g_e.msg, cases[k].why));
        if (db) imdb_close(db);
        CHECK(audit_fails(dir));
    }
    spit(fp, orig, n); /* put back: the copy opens again */
    free(orig);
    free(b);
    db = ropen(dir, false);
    CHECK(db && db->log_floor == s2 - 1);
    if (db) imdb_close(db);
}

/* (c2) closes (c1)'s limitation: ERASE SUBJECT after a RETIRE reaches every byte of the subject, the retired
 * versions' payloads having gone with the log segments the cut removed */
static void t_retain_retire_erase(void)
{
    const char *dir = test_tmpdir();
    OK(imdb_init(dir, false, NULL, E));
    imdb_db *db = ropen(dir, false);
    CHECK(db);
    if (!db) return;
    db->no_auto_retire = true;
    imdb_session s;
    imdb_session_init(&s, db);
    OK(ex(&s, "CREATE TABLE c (id INT64 PRIMARY KEY, u INT64 SUBJECT, memo TEXT) RETENTION 10 SECONDS"));
    OK(ex(&s, "INSERT INTO c VALUES (1, 7, 'secret-a'), (2, 8, 'other')"));
    OK(ex(&s, "UPDATE c SET memo = 'secret-b' WHERE id = 1"));
    OK(ex(&s, "UPDATE c SET memo = 'secret-c' WHERE id = 1"));
    OK(ex(&s, "CHECKPOINT"));
    uint64_t s2 = db->seq + 1;
    OK(ex(&s, "UPDATE c SET memo = 'secret-d' WHERE id = 1"));
    OK(ex(&s, "CHECKPOINT"));
    imdb_clock_offset(15 * SEC_US);
    OK(ex(&s, "SELECT COUNT(*) FROM c"));
    OK(imdb_retire(db, s2 - 1, E)); /* 'secret-a' and 'secret-b' retired, their segment cut */
    CHECK(db->log_floor == s2 - 1 && tree_contains(dir, "secret-c"));
    OK(ex(&s, "ERASE SUBJECT 7"));
    OK(ex(&s, "CHECKPOINT"));
    imdb_verify_report vr;
    memset(&vr, 0, sizeof vr);
    OK(imdb_verify(db, &vr, E));
    imdb_session_close(&s);
    imdb_close(db);
    static const char *const gone[] = {"secret-a", "secret-b", "secret-c", "secret-d"};
    for (size_t k = 0; k < sizeof gone / sizeof *gone; k++) CHECK(!tree_contains(dir, gone[k]));
    CHECK(tree_contains(dir, "other") && audit_ok(dir));
}

/* replicas/r1.ack as ship --acks writes it: replica key 1's signed acknowledgement of (seq, head), received age_ms ago */
static void put_ack(const char *dir, const imdb_db *db, uint64_t seq, const uint8_t head[32], int64_t age_ms)
{
    uint8_t seed[IMDB_SEED_LEN];
    memset(seed, 1, sizeof seed);
    imdb_signer k;
    imdb_signer_init(&k, seed);
    imdb_ack a;
    memset(&a, 0, sizeof a);
    memcpy(a.db_id, db->db_id, 16);
    memcpy(a.replica, k.pk, IMDB_PUBKEY_LEN);
    memset(a.nonce, 7, IMDB_NONCE_LEN);
    a.epoch = imdb_writer_epoch_at(db, seq);
    a.seq = a.cleanup = seq;
    memcpy(a.head, head, 32);
    uint8_t rec[IMDB_ACK_LEN + 12];
    imdb_ack_sign(&a, &k, rec);
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    imdb_le64(rec + IMDB_ACK_LEN, (uint64_t)((int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000 - age_ms));
    imdb_le32(rec + IMDB_ACK_LEN + 8, imdb_kern()->crc32c(0, rec, IMDB_ACK_LEN + 8));
    char f[800];
    snprintf(f, sizeof f, "%s/replicas/r1.ack", dir);
    spit(f, rec, sizeof rec);
}

/* some cell of a query's answer is the text want (SHOW REPLICAS' state column, wherever it is) */
static bool answer_has(imdb_session *s, const char *sql, const char *want)
{
    imdb_result r;
    imdb_err_clear(E);
    if (imdb_exec_one(s, sql, strlen(sql), NULL, 0, &r, E)) return false;
    bool found = false;
    for (uint64_t i = 0; i < r.nrows * r.ncols && !found; i++) {
        const imdb_cell *c = &r.cells[i];
        found = c->v.type == IMDB_T_TEXT && c->v.len == strlen(want) && memcmp(c->v.s, want, c->v.len) == 0;
    }
    imdb_result_free(&r);
    return found;
}

static imdb_repl_state r1_state(imdb_db *db)
{
    imdb_replica_status *v = NULL;
    size_t n = 0;
    imdb_err_clear(E);
    imdb_repl_state st = imdb_replicas_status(db, &v, &n, E) || n != 1 || !v[0].acked ? IMDB_REPL_NONE : v[0].state;
    imdb_free(v);
    return st;
}

/* (c2) a replica heard from within the hold keeps the log it still needs: the policy's RETIRE stops at the segment end
 * at or below its acknowledged commit (here the floor's commit, which SHOW REPLICAS still matches through FLOOR's hash);
 * held back, the policy looks again a second later; a replica silent past the hold no longer holds it, and is then
 * behind the retired log */
static void t_retain_retire_replica(void)
{
    const char *dir = test_tmpdir();
    OK(imdb_init(dir, false, NULL, E));
    imdb_db *db = ropen(dir, false);
    CHECK(db);
    if (!db) return;
    imdb_session s;
    imdb_session_init(&s, db);
    uint8_t seed[IMDB_SEED_LEN];
    memset(seed, 1, sizeof seed);
    imdb_signer k;
    imdb_signer_init(&k, seed);
    OK(imdb_replica_add(dir, "r1", k.pk, false, E));
    OK(ex(&s, "CREATE TABLE a (id INT64 PRIMARY KEY, v INT64) RETENTION 10 SECONDS"));
    OK(ex(&s, "INSERT INTO a VALUES (1, 0), (2, 0), (3, 0), (4, 0)"));
    OK(ex(&s, "UPDATE a SET v = 1 WHERE id >= 1")); /* four end */
    OK(ex(&s, "CHECKPOINT"));
    uint64_t s2 = db->seq + 1;
    uint8_t h1[32];
    const imdb_commit_info *ci = imdb_ci_at(db, s2 - 1, E);
    CHECK(ci);
    if (!ci) return;
    memcpy(h1, ci->hash, 32);
    OK(ex(&s, "UPDATE a SET v = 2 WHERE id >= 1")); /* four more */
    OK(ex(&s, "CHECKPOINT"));
    uint64_t s3 = db->seq + 1;
    OK(ex(&s, "UPDATE a SET v = 3 WHERE id >= 1"));
    OK(ex(&s, "CHECKPOINT"));
    put_ack(dir, db, s2 - 1, h1, 0); /* the replica holds the first segment */
    CHECK(r1_state(db) == IMDB_REPL_SAME_HISTORY);
    imdb_clock_offset(15 * SEC_US);
    OK(ex(&s, "SELECT COUNT(*) FROM a")); /* the expiry to s3; the policy's own RETIRE, s3 - 1, capped at s2 - 1 */
    CHECK(horizon_of(db, "a") == s3 && db->boundary == s2 - 1 && db->log_floor == s2 - 1 && held_of(db, "a") == 16 - 4);
    CHECK(r1_state(db) == IMDB_REPL_SAME_HISTORY && answer_has(&s, "SHOW REPLICAS", "same history")); /* FLOOR's hash */
    OK(ex(&s, "SELECT COUNT(*) FROM a")); /* due at s3 - 1 again, and held back: nothing below s2 - 1 is left */
    CHECK(db->boundary == s2 - 1 && db->retire_held_us);
    put_ack(dir, db, s2 - 1, h1, 25ll * 3600 * 1000); /* silent for longer than the hold */
    imdb_clock_offset(17 * SEC_US);                    /* past the second the policy waits */
    OK(ex(&s, "SELECT COUNT(*) FROM a"));
    CHECK(db->boundary == s3 - 1 && db->log_floor == s3 - 1 && held_of(db, "a") == 16 - 8 && !db->retire_held_us);
    CHECK(r1_state(db) == IMDB_REPL_RETIRED && answer_has(&s, "SHOW REPLICAS", "behind the retired log: seed it again"));
    imdb_verify_report vr;
    memset(&vr, 0, sizeof vr);
    OK(imdb_verify(db, &vr, E));
    imdb_session_close(&s);
    imdb_close(db);
    CHECK(audit_ok(dir));
}

/* (c2) a FLOOR past key changes carries their entries: the engine's open checks them against WRITERS, VERIFY seeds at
 * the floor under the floor's key, the auditor proves them from META's keys alone, and a replica that followed goes on
 * through the RETIRE, a rotation past the floor and its own cut; an entry's signature changed with the checksum made
 * good is refused by the open and by the auditor */
static void t_retain_floor_keys(void)
{
    const char *dir = test_tmpdir();
    char p[700], r[700], sf[700];
    snprintf(p, sizeof p, "%s/p", dir);
    snprintf(r, sizeof r, "%s/r", dir);
    snprintf(sf, sizeof sf, "%s/stream", dir);
    OK(imdb_init(p, false, NULL, E));
    OK(imdb_init(r, true, p, E));
    imdb_db *db = ropen(p, false);
    CHECK(db);
    if (!db) return;
    OK(imdb_rotate_key(db, E)); /* epoch 1, below the floor */
    imdb_session s;
    imdb_session_init(&s, db);
    uint64_t s2 = 0;
    retire_setup(&s, &s2);
    if (!s2) return;
    OK(imdb_rotate_key(db, E)); /* epoch 2, past it */
    OK(ship_to_file(p, 0, sf, E));
    imdb_db *rdb = ropen(r, false);
    CHECK(rdb);
    if (!rdb) return;
    uint64_t applied = 0;
    OK(apply_file(rdb, sf, &applied, E));
    uint64_t rseq = rdb->seq;
    CHECK(imdb_current_epoch(rdb) == 2);
    imdb_close(rdb);
    OK(imdb_retire(db, s2 - 1, E));
    CHECK(db->log_floor == s2 - 1 && imdb_writer_epoch_at(db, s2 - 1) == 1 && imdb_current_epoch(db) == 2);
    OK(ex(&s, "UPDATE a SET v = 7 WHERE id = 2"));
    uint64_t pseq = db->seq;
    imdb_verify_report vr;
    memset(&vr, 0, sizeof vr);
    OK(imdb_verify(db, &vr, E));
    imdb_session_close(&s);
    imdb_close(db);
    db = ropen(p, false); /* the snapshot open: WRITERS, then FLOOR's entry checked against it */
    CHECK(db && db->log_floor == s2 - 1 && db->seq == pseq && imdb_current_epoch(db) == 2 && db->can_sign);
    if (!db) return;
    memset(&vr, 0, sizeof vr);
    OK(imdb_verify(db, &vr, E));
    imdb_close(db);
    OK(ship_to_file(p, rseq, sf, E));
    rdb = ropen(r, false);
    CHECK(rdb);
    if (!rdb) return;
    applied = 0;
    OK(apply_file(rdb, sf, &applied, E));
    CHECK(rdb->seq == pseq && rdb->log_floor == s2 - 1 && imdb_current_epoch(rdb) == 2);
    memset(&vr, 0, sizeof vr);
    OK(imdb_verify(rdb, &vr, E));
    imdb_close(rdb);
    CHECK(audit_ok(p) && audit_ok(r) && audit_says(p, "log floor: commit") && audit_says(r, "log floor: commit"));
    char fp[800];
    snprintf(fp, sizeof fp, "%s/FLOOR", p);
    size_t n = 0;
    uint8_t *b = slurp(fp, &n), *orig = malloc(n ? n : 1);
    CHECK(b && orig && n > 200);
    if (!b || !orig) return;
    memcpy(orig, b, n);
    /* "IMDBFLR1" | db_id | F | u32 hlen | F's header | signature | u32 entries | the entries ... */
    size_t hlen = (size_t)b[32] | (size_t)b[33] << 8 | (size_t)b[34] << 16 | (size_t)b[35] << 24;
    size_t cnt_at = 36 + hlen + 64, e0 = cnt_at + 4;
    CHECK(e0 + 13 < n && b[cnt_at] == 1 && !b[cnt_at + 1] && !b[cnt_at + 2] && !b[cnt_at + 3]); /* epoch 1's alone */
    if (e0 + 13 >= n) return;
    /* an entry: u64 seq | u8 promote | u32 hlen | its header | its signature */
    size_t ehl = (size_t)b[e0 + 9] | (size_t)b[e0 + 10] << 8 | (size_t)b[e0 + 11] << 16 | (size_t)b[e0 + 12] << 24;
    size_t sig_at = e0 + 13 + ehl;
    CHECK(sig_at + 64 < n - 4);
    if (sig_at + 64 >= n - 4) return;
    b[sig_at + 5] ^= 1;
    uint32_t crc = imdb_kern()->crc32c(0, b, n - 4);
    for (int i = 0; i < 4; i++) b[n - 4 + (size_t)i] = (uint8_t)(crc >> (8 * i));
    spit(fp, b, n);
    imdb_open_opts o = {.sync = 0};
    db = NULL;
    imdb_err_clear(E);
    CHECK(imdb_open(p, &o, &db, E) != IMDB_OK && strstr(g_e.msg, "not signed by the keys before it"));
    if (db) imdb_close(db);
    CHECK(audit_fails(p));
    spit(fp, orig, n); /* put back: it opens again */
    free(b);
    free(orig);
    db = ropen(p, false);
    CHECK(db && db->log_floor == s2 - 1);
    if (db) imdb_close(db);
}

/* (c2) WRITERS gone from a cut copy (an operator's mistake): FLOOR's entries alone carry the key changes below the
 * floor, so a copy whose changes all lie there opens on them; one with a change between the floor and its snapshot
 * cannot know that key from FLOOR: refused, saying why the snapshot did not load (never opened under the wrong key) */
static void t_retain_floor_no_writers(void)
{
    for (int between = 0; between < 2; between++) {
        imdb_clock_offset(0); /* retire_setup moves it 15 seconds on from where it stands */
        const char *dir = test_tmpdir();
        char p[700], wf[800];
        snprintf(p, sizeof p, "%s/p%d", dir, between);
        snprintf(wf, sizeof wf, "%s/WRITERS", p);
        OK(imdb_init(p, false, NULL, E));
        imdb_db *db = ropen(p, false);
        CHECK(db);
        if (!db) return;
        OK(imdb_rotate_key(db, E)); /* epoch 1, below the floor */
        imdb_session s;
        imdb_session_init(&s, db);
        uint64_t s2 = 0;
        retire_setup(&s, &s2);
        if (!s2) return;
        if (between) OK(imdb_rotate_key(db, E)); /* epoch 2, before the RETIRE's publish: the snapshot is under it */
        OK(imdb_retire(db, s2 - 1, E));
        CHECK(db->log_floor == s2 - 1 && imdb_current_epoch(db) == 1 + (uint32_t)between);
        uint64_t pseq = db->seq;
        imdb_session_close(&s);
        imdb_close(db);
        CHECK(unlink(wf) == 0);
        db = NULL;
        imdb_open_opts o = {.sync = 0};
        imdb_err_clear(E);
        int rc = imdb_open(p, &o, &db, E);
        if (!between) {
            CHECK(rc == IMDB_OK && db && db->seq == pseq && imdb_current_epoch(db) == 1 && db->can_sign);
            if (db) {
                imdb_verify_report vr;
                memset(&vr, 0, sizeof vr);
                OK(imdb_verify(db, &vr, E));
                imdb_close(db);
            }
            CHECK(audit_ok(p));
        } else { /* refused, with why the snapshot did not load: never open under epoch 1's key */
            CHECK(rc != IMDB_OK && !db && strstr(g_e.msg, "is retired") && strstr(g_e.msg, "did not load ("));
            if (db) imdb_close(db);
        }
    }
}

/* (c2) a later floor whose range reaches below an earlier one: the segment starts the earlier cut took from the disk
 * come from its FLOOR (found by the 10-30 smoke: an EXPIRE past the later floor named a start the first cut had
 * removed, and VERIFY found it nowhere) */
static void t_retain_floor_carry(void)
{
    const char *dir = test_tmpdir();
    OK(imdb_init(dir, false, NULL, E));
    imdb_db *db = ropen(dir, false);
    CHECK(db);
    if (!db) return;
    db->no_auto_retire = true;
    imdb_session s;
    imdb_session_init(&s, db);
    OK(ex(&s, "CREATE TABLE a (id INT64 PRIMARY KEY, v INT64) RETENTION 10 SECONDS"));
    OK(ex(&s, "INSERT INTO a VALUES (1, 0), (2, 0)"));
    OK(ex(&s, "CHECKPOINT")); /* segment A ends */
    uint64_t s2 = db->seq + 1;
    imdb_clock_offset(5 * SEC_US); /* B begins at +5 s: 10 s old only after the second floor is committed */
    OK(ex(&s, "UPDATE a SET v = 1 WHERE id = 1"));
    OK(ex(&s, "CHECKPOINT")); /* B ends: the first floor */
    uint64_t f0 = db->seq;
    imdb_clock_offset(10 * SEC_US);
    OK(ex(&s, "UPDATE a SET v = 2 WHERE id = 1")); /* C begins at +10 s (its statement expires to A's start alone) */
    OK(ex(&s, "CHECKPOINT"));                       /* C ends: the second floor */
    uint64_t f = db->seq;
    OK(ex(&s, "UPDATE a SET v = 3 WHERE id = 1")); /* D begins at +10 s */
    OK(ex(&s, "CHECKPOINT"));
    imdb_clock_offset(16 * SEC_US);
    OK(ex(&s, "SELECT COUNT(*) FROM a")); /* past f: B is 10 s old now, C and D not: the EXPIRE names s2 (<= f0) */
    CHECK(horizon_of(db, "a") == s2);
    imdb_clock_offset(30 * SEC_US);
    OK(ex(&s, "SELECT COUNT(*) FROM a")); /* C and D too: the horizon past f */
    CHECK(horizon_of(db, "a") > f);
    OK(imdb_retire(db, f0, E)); /* the first cut: A and B gone, their starts in its FLOOR */
    CHECK(db->log_floor == f0);
    OK(imdb_retire(db, f, E)); /* the second: its range (0, f] reaches below f0 */
    CHECK(db->log_floor == f && db->nsegs && db->segs[0] == f + 1);
    bool has_s2 = false;
    for (uint32_t i = 0; i < db->nfloor_starts; i++) has_s2 |= imdb_get_le64(db->floor_starts + 16 * i) == s2;
    CHECK(has_s2);
    imdb_verify_report vr;
    memset(&vr, 0, sizeof vr);
    OK(imdb_verify(db, &vr, E)); /* the EXPIRE past f names s2: FLOOR carries it */
    imdb_session_close(&s);
    imdb_close(db);
    CHECK(audit_ok(dir));
}

/* entries in DIR/objects, and whether DIR/FLOOR exists */
static size_t objects_in(const char *dir, bool *floor)
{
    char od[800];
    snprintf(od, sizeof od, "%s/objects", dir);
    DIR *d = opendir(od);
    size_t n = 0;
    for (struct dirent *de; d && (de = readdir(d));) n += strcmp(de->d_name, ".") != 0 && strcmp(de->d_name, "..") != 0;
    if (d) closedir(d);
    snprintf(od, sizeof od, "%s/FLOOR", dir);
    *floor = access(od, F_OK) == 0;
    return n;
}

/* a primary whose log is cut below commit 1 (retire_setup, then RETIRE at s2 - 1), one commit past its snapshot; table c
 * (a SUBJECT column) holds subject 7's 'seed-secret' and subject 8's 'kept', inserted before the cut; a key rotation
 * (epoch 1) comes first, so the seed carries a key change */
static imdb_db *cut_primary(const char *p, imdb_session *s, uint64_t *S)
{
    imdb_db *db = NULL;
    if (imdb_init(p, false, NULL, E) || !(db = ropen(p, false))) {
        test_fail(__FILE__, __LINE__, "cut_primary: init or open");
        return NULL;
    }
    if (imdb_rotate_key(db, E)) { /* epoch 1 below the floor: every seed carries a key change */
        test_fail(__FILE__, __LINE__, "cut_primary: the rotation");
        imdb_close(db);
        return NULL;
    }
    imdb_session_init(s, db);
    if (ex(s, "CREATE TABLE c (id INT64 PRIMARY KEY, u INT64 SUBJECT, memo TEXT) RETENTION 10 SECONDS") ||
        ex(s, "INSERT INTO c VALUES (1, 7, 'seed-secret'), (2, 8, 'kept')")) {
        test_fail(__FILE__, __LINE__, "cut_primary: table c");
        imdb_session_close(s);
        imdb_close(db);
        return NULL;
    }
    uint64_t s2 = 0;
    retire_setup(s, &s2);
    if (!s2 || imdb_retire(db, s2 - 1, E) || db->log_floor != s2 - 1 || !db->nsegs || db->segs[0] != s2) {
        test_fail(__FILE__, __LINE__, "cut_primary: the RETIRE and its cut");
        imdb_session_close(s);
        imdb_close(db);
        return NULL;
    }
    *S = db->lake_seq;
    imdb_clock_offset(20 * SEC_US); /* the segment after the snapshot begins late: an expiry can then name one before */
    if (ex(s, "UPDATE a SET v = 55 WHERE id = 2")) { /* past the snapshot: shipped after the seed */
        test_fail(__FILE__, __LINE__, "cut_primary: a commit past the snapshot");
        imdb_session_close(s);
        imdb_close(db);
        return NULL;
    }
    return db;
}

/* (e) a new replica of a cut primary: ship from 0 sends a seed (a FLOOR at the primary's snapshot, its manifests,
 * its segments); the empty replica takes it into its directory and its handle goes stale; reopened, it holds the
 * snapshot at its floor, VERIFY and the auditor seed there, and it follows from it: an ERASE SUBJECT of rows that came
 * in the seed (in its lake, never in its log: no file of either copy holds them after), a key rotation, and another
 * RETIRE (its own cut) */
static void t_retain_seed(void)
{
    const char *dir = test_tmpdir();
    char p[700], r[700], sf[700];
    snprintf(p, sizeof p, "%s/p", dir);
    snprintf(r, sizeof r, "%s/r", dir);
    snprintf(sf, sizeof sf, "%s/stream", dir);
    imdb_session s;
    uint64_t S = 0;
    imdb_db *db = cut_primary(p, &s, &S);
    if (!db) return;
    OK(imdb_init(r, true, p, E));
    OK(ship_to_file(p, 0, sf, E));
    imdb_db *rdb = ropen(r, false);
    CHECK(rdb);
    if (!rdb) return;
    uint64_t applied = 0;
    OK(apply_file(rdb, sf, &applied, E));
    CHECK(rdb->seeded == S && applied == 0 && rdb->failed); /* stale: the directory moved on */
    imdb_close(rdb);
    CHECK(audit_ok(r)); /* the state apply leaves: FLOOR and LAKE_HEAD, DURABLE still at commit 0, an empty log */
    rdb = ropen(r, false);
    CHECK(rdb && rdb->seq == S && rdb->log_floor == S && rdb->lake_seq == S && rdb->nsegs == 0 &&
          imdb_current_epoch(rdb) == 1); /* the seed's key change, from FLOOR's entries */
    if (!rdb) return;
    imdb_verify_report vr;
    memset(&vr, 0, sizeof vr);
    OK(imdb_verify(rdb, &vr, E));
    imdb_close(rdb);
    CHECK(audit_ok(r) && audit_says(r, "log floor: commit"));
    OK(ship_to_file(p, S, sf, E));
    rdb = ropen(r, false);
    CHECK(rdb);
    if (!rdb) return;
    OK(apply_file(rdb, sf, &applied, E));
    CHECK(rdb->seq == db->seq && memcmp(rdb->head, db->head, 32) == 0 && rdb->nsegs && rdb->segs[0] == S + 1);
    memset(&vr, 0, sizeof vr);
    OK(imdb_verify(rdb, &vr, E));
    imdb_close(rdb);
    CHECK(audit_ok(r));
    /* an EXPIRE naming a segment start below the replica's floor (s3, in (s2, S]), which its own log never held: only
     * the seed's FLOOR knows it began a segment, and when (the starts it carries) */
    uint64_t c0 = db->seq, h0 = horizon_of(db, "a");
    imdb_clock_offset(25 * SEC_US);
    OK(ex(&s, "SELECT COUNT(*) FROM a"));
    CHECK(horizon_of(db, "a") > h0 && horizon_of(db, "a") <= S);
    OK(ship_to_file(p, c0, sf, E));
    rdb = ropen(r, false);
    CHECK(rdb);
    if (!rdb) return;
    OK(apply_file(rdb, sf, &applied, E));
    CHECK(rdb->seq == db->seq && horizon_of(rdb, "a") == horizon_of(db, "a"));
    memset(&vr, 0, sizeof vr);
    OK(imdb_verify(rdb, &vr, E));
    imdb_close(rdb);
    CHECK(audit_ok(r));
    uint64_t caught = db->seq; /* where the replica stands */
    OK(ex(&s, "ERASE SUBJECT 7")); /* rows the replica holds from the seed only */
    OK(ex(&s, "CHECKPOINT"));
    OK(ship_to_file(p, caught, sf, E));
    rdb = ropen(r, false);
    CHECK(rdb);
    if (!rdb) return;
    OK(apply_file(rdb, sf, &applied, E));
    CHECK(rdb->seq == db->seq);
    memset(&vr, 0, sizeof vr);
    OK(imdb_verify(rdb, &vr, E));
    imdb_close(rdb);
    CHECK(!tree_contains(r, "seed-secret") && tree_contains(r, "kept") && !tree_contains(p, "seed-secret"));
    /* the primary goes on: a new key, a RETIRE past the seed's floor (the replica cuts its own log) */
    uint64_t from = db->seq;
    OK(imdb_rotate_key(db, E));
    OK(ex(&s, "UPDATE a SET v = 56 WHERE id = 2"));
    OK(ex(&s, "CHECKPOINT"));
    uint64_t s9 = db->seq + 1;
    OK(ex(&s, "UPDATE a SET v = 57 WHERE id = 2"));
    OK(ex(&s, "CHECKPOINT"));
    imdb_clock_offset(40 * SEC_US); /* past s9's start (t0+25) by the retention */
    OK(ex(&s, "SELECT COUNT(*) FROM a")); /* the horizons move past the seed's floor */
    OK(ship_to_file(p, from, sf, E)); /* the replica follows to the RETIRE: past its cut it could only be seeded */
    rdb = ropen(r, false);
    CHECK(rdb);
    if (!rdb) return;
    OK(apply_file(rdb, sf, &applied, E));
    from = rdb->seq;
    imdb_close(rdb);
    OK(imdb_retire(db, s9 - 1, E));
    CHECK(db->boundary == s9 - 1);
    OK(ship_to_file(p, from, sf, E));
    rdb = ropen(r, false);
    CHECK(rdb);
    if (!rdb) return;
    OK(apply_file(rdb, sf, &applied, E));
    CHECK(rdb->seq == db->seq && memcmp(rdb->head, db->head, 32) == 0 && rdb->boundary == s9 - 1 &&
          rdb->log_floor == s9 - 1 && imdb_current_epoch(rdb) == imdb_current_epoch(db));
    memset(&vr, 0, sizeof vr);
    OK(imdb_verify(rdb, &vr, E));
    imdb_close(rdb);
    imdb_session_close(&s);
    imdb_close(db);
    CHECK(audit_ok(p) && audit_ok(r));
}

static void put_crc_at(uint8_t *b, size_t from, size_t to) /* CRC32C of b[from, to) written at to */
{
    uint32_t c = imdb_kern()->crc32c(0, b + from, to - from);
    for (int i = 0; i < 4; i++) b[to + (size_t)i] = (uint8_t)(c >> (8 * i));
}

/* (e) hostile seeds, each refused into the same empty replica, and each time it is empty again after a reopen (the
 * leftovers removed): a stream cut short, a damaged head, a forged floor header, an object whose bytes are not its
 * name, one the manifest does not name, too few objects; a replica that holds a commit refuses a seed; then the true
 * seed is taken by the replica the refusals left */
static void t_retain_seed_refused(void)
{
    const char *dir = test_tmpdir();
    char p[700], r[700], sf[700], bad[700];
    snprintf(p, sizeof p, "%s/p", dir);
    snprintf(r, sizeof r, "%s/r", dir);
    snprintf(sf, sizeof sf, "%s/stream", dir);
    snprintf(bad, sizeof bad, "%s/bad", dir);
    imdb_session s;
    uint64_t S = 0;
    imdb_db *db = cut_primary(p, &s, &S);
    if (!db) return;
    imdb_session_close(&s);
    imdb_close(db);
    OK(imdb_init(r, true, p, E));
    OK(ship_to_file(p, 0, sf, E));
    size_t n = 0;
    uint8_t *seed = slurp(sf, &n), *b = malloc(n ? n : 1);
    CHECK(seed && b && n > 200 && memcmp(seed, "IMDBSED1", 8) == 0);
    /* the key changes from the primary's FLOOR when WRITERS is gone: the same seed, byte for byte */
    char wf[800], sf2[760];
    snprintf(wf, sizeof wf, "%s/WRITERS", p);
    snprintf(sf2, sizeof sf2, "%s/stream2", dir);
    CHECK(unlink(wf) == 0);
    OK(ship_to_file(p, 0, sf2, E));
    size_t n2 = 0;
    uint8_t *seed2 = slurp(sf2, &n2);
    CHECK(seed2 && n2 == n && memcmp(seed2, seed, n) == 0);
    free(seed2);
    if (!seed || !b) return;
    size_t hl = (size_t)imdb_get_le32(seed + 16), objs = 28 + hl + 4;
    /* the first object of kind .seg, and where its bytes begin */
    size_t at = objs, segat = 0;
    while (at + 41 <= n && !segat) {
        uint64_t len = imdb_get_le64(seed + at + 33);
        if (seed[at] == 1) segat = at;
        at += 41 + (size_t)len;
    }
    CHECK(segat);
    static const struct {
        int what;
        const char *why;
    } cases[] = {{0, "truncated"},          {1, "its FLOOR is damaged"},  {2, "not signed by its writer key"},
                 {3, "not the bytes its name says"}, {4, "does not name"}, {5, "where the manifest names"}};
    for (size_t k = 0; k < sizeof cases / sizeof *cases; k++) {
        memcpy(b, seed, n);
        size_t m = n;
        switch (cases[k].what) {
        case 0: m = segat + 41 + 3; break;           /* inside an object */
        case 1: b[28 + 40] ^= 1; break;               /* the head, its checksum left */
        case 2: b[28 + 36 + 12] ^= 1;                 /* a byte of the floor's time */
                put_crc_at(b, 28, 28 + hl); break;
        case 3: b[segat + 41 + 7] ^= 1; break;        /* a segment's bytes */
        case 4: b[segat + 1] ^= 1; break;             /* a segment's name */
        case 5: imdb_le32(b + 20, imdb_get_le32(b + 20) - 1); /* one object fewer */
                put_crc_at(b, 0, 24); break;
        }
        spit(bad, b, m);
        imdb_db *rdb = ropen(r, false);
        CHECK(rdb);
        if (!rdb) return;
        uint64_t applied = 0;
        imdb_err_clear(E);
        CHECK(apply_file(rdb, bad, &applied, E) != IMDB_OK && strstr(g_e.msg, cases[k].why) && !rdb->seeded);
        imdb_close(rdb);
        rdb = ropen(r, false); /* the reopen removes what the refused seed left */
        bool fl = true;
        CHECK(rdb && rdb->seq == 0 && !rdb->log_floor && objects_in(r, &fl) == 0 && !fl);
        if (rdb) imdb_close(rdb);
    }
    imdb_db *rdb = ropen(r, false);
    CHECK(rdb);
    if (!rdb) return;
    uint64_t applied = 0;
    OK(apply_file(rdb, sf, &applied, E)); /* the true seed, into the replica the refusals left */
    CHECK(rdb->seeded == S);
    imdb_close(rdb);
    rdb = ropen(r, false);
    CHECK(rdb && rdb->seq == S);
    if (!rdb) return;
    imdb_err_clear(E);
    CHECK(apply_file(rdb, sf, &applied, E) == IMDB_ERR_STATE && strstr(g_e.msg, "only by an empty replica"));
    imdb_close(rdb);
    CHECK(audit_ok(r));
    free(seed);
    free(b);
}

static char g_keep_seg[IMDB_LOGSEG_NAME + 1]; /* the log segment no unlink may remove: a cut stopped part way */

static long keep_one_segment(imdb_io_call *c, void *ctx)
{
    (void)ctx;
    if (c->op == IMDB_IO_UNLINK && c->name && strcmp(c->name, g_keep_seg) == 0) {
        errno = EIO;
        return -1;
    }
    return 0;
}

/* (c2) a cut stopped part way: the segment list follows the disk, so ERASE SUBJECT's redaction skips a payload whose
 * segment the cut removed (a live version inserted there: in no file but the lake) and rewrites the one it could not
 * remove; the next writable open finishes the cut */
static void t_retain_cut_partial(void)
{
    const char *dir = test_tmpdir();
    OK(imdb_init(dir, false, NULL, E));
    imdb_db *db = ropen(dir, false);
    CHECK(db);
    if (!db) return;
    db->no_auto_retire = true;
    imdb_session s;
    imdb_session_init(&s, db);
    OK(ex(&s, "CREATE TABLE c (id INT64 PRIMARY KEY, u INT64 SUBJECT, memo TEXT) RETENTION 10 SECONDS"));
    OK(ex(&s, "INSERT INTO c VALUES (1, 7, 'secret-a'), (2, 8, 'other'), (3, 7, 'secret-live')"));
    OK(ex(&s, "CHECKPOINT")); /* the first segment: secret-live's only frame */
    uint64_t s2 = db->seq + 1;
    OK(ex(&s, "UPDATE c SET memo = 'secret-b' WHERE id = 1"));
    OK(ex(&s, "CHECKPOINT")); /* the second: secret-b's, ended in the third (held past the boundary) */
    uint64_t s3 = db->seq + 1;
    OK(ex(&s, "UPDATE c SET memo = 'secret-c' WHERE id = 1"));
    OK(ex(&s, "CHECKPOINT"));
    imdb_clock_offset(15 * SEC_US);
    OK(ex(&s, "SELECT COUNT(*) FROM c"));
    CHECK(horizon_of(db, "c") == s3);
    imdb_logseg_name(s2, g_keep_seg);
    imdb_io_hooks h = {.before = keep_one_segment};
    imdb_io_set_hooks(&h);
    imdb_err_clear(E);
    int rc = imdb_retire(db, s3 - 1, E); /* cuts the first segment, not the second */
    CHECK(rc == IMDB_OK && db->log_floor == s3 - 1 && db->nsegs && db->segs[0] == s2 && db->warning[0]);
    db->warning[0] = 0;
    imdb_err_clear(E);
    if (!rc) rc = ex(&s, "ERASE SUBJECT 7");
    if (!rc) rc = ex(&s, "CHECKPOINT");
    imdb_io_set_hooks(NULL);
    OK_RC(rc);
    CHECK(db->nsegs && db->segs[0] == s2); /* the cut, retried at each publish, still stopped */
    imdb_verify_report vr;
    memset(&vr, 0, sizeof vr);
    OK(imdb_verify(db, &vr, E));
    imdb_session_close(&s);
    imdb_close(db);
    char seg[800];
    snprintf(seg, sizeof seg, "%s/log/%s", dir, g_keep_seg);
    CHECK(access(seg, F_OK) == 0); /* the premise: the second segment is still on disk, redacted */
    static const char *const gone[] = {"secret-a", "secret-b", "secret-c", "secret-live"};
    for (size_t k = 0; k < sizeof gone / sizeof *gone; k++) CHECK(!tree_contains(dir, gone[k]));
    db = ropen(dir, false); /* the open's cleanup finishes the cut */
    CHECK(db && db->nsegs && db->segs[0] == s3 && db->log_floor == s3 - 1);
    if (db) imdb_close(db);
    CHECK(access(seg, F_OK) != 0 && tree_contains(dir, "other") && audit_ok(dir));
}

const test_case retain_tests[] = {
    {"retain_ddl", t_retain_ddl},
    {"retain_persist", t_retain_persist},
    {"retain_log_rules", t_retain_log_rules},
    {"retain_expire", t_retain_expire},
    {"retain_expire_first", t_retain_expire_first},
    {"retain_expire_txn", t_retain_expire_txn},
    {"retain_expire_rules", t_retain_expire_rules},
    {"retain_seg_time", t_retain_seg_time},
    {"retain_retire", t_retain_retire},
    {"retain_retire_rules", t_retain_retire_rules},
    {"retain_retire_chunks", t_retain_retire_chunks},
    {"retain_retire_again", t_retain_retire_again},
    {"retain_retire_purged", t_retain_retire_purged},
    {"retain_retire_txn", t_retain_retire_txn},
    {"retain_retire_policy", t_retain_retire_policy},
    {"retain_floor_forged", t_retain_floor_forged},
    {"retain_retire_erase", t_retain_retire_erase},
    {"retain_retire_replica", t_retain_retire_replica},
    {"retain_floor_keys", t_retain_floor_keys},
    {"retain_cut_partial", t_retain_cut_partial},
    {"retain_floor_no_writers", t_retain_floor_no_writers},
    {"retain_seed", t_retain_seed},
    {"retain_seed_refused", t_retain_seed_refused},
    {"retain_floor_carry", t_retain_floor_carry},
};
const size_t retain_ntests = sizeof retain_tests / sizeof *retain_tests;
