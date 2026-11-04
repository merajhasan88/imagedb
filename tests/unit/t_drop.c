/* DROP TABLE (P0 SQL semantics, 1f; docs/plan-p0.md): the user's (A), history kept. The drop is one commit (op 19,
 * after at most its own table's retention): every live version ends at it, the table becomes a tombstone whose name
 * is free, and a read resolves a name by its snapshot, so AS OF before the drop reads the table as it was. Its
 * history expires by its retention (a FOREVER table is given one at the drop) and RETIRE drops it; ERASE SUBJECT
 * still reaches it. A transaction that wrote or locked the table is doomed by the drop. Replay, a snapshot open, a
 * replica, VERIFY and the auditor re-derive all of it: the view token covers both marks. */
#include <stdlib.h>

#include "../../src/backup.h"
#include "../../src/log.h"
#include "../../src/sql.h"
#include "thelp.h"

#define SEC_US 1000000ll
#define DAY_US (24ull * 3600 * 1000000)

static int ex(imdb_session *s, const char *sql)
{
    imdb_result r;
    imdb_err_clear(E);
    int rc = imdb_exec_one(s, sql, strlen(sql), NULL, 0, &r, E);
    if (!rc) imdb_result_free(&r);
    return rc;
}

/* the first cell of a one-row answer as an integer; INT64_MIN for an error or anything else */
static int64_t one(imdb_session *s, const char *sql)
{
    imdb_result r;
    imdb_err_clear(E);
    if (imdb_exec_one(s, sql, strlen(sql), NULL, 0, &r, E)) return INT64_MIN;
    const imdb_cell *c = r.nrows == 1 ? &r.cells[0] : NULL;
    int64_t v = !c || c->null ? INT64_MIN : c->wide ? (int64_t)c->i128 : c->v.i;
    imdb_result_free(&r);
    return v;
}

static int64_t one_at(imdb_session *s, const char *pre, uint64_t seq, const char *post) /* pre seq post */
{
    char q[300];
    snprintf(q, sizeof q, "%s%llu%s", pre, (unsigned long long)seq, post);
    return one(s, q);
}

static int ex_at(imdb_session *s, const char *pre, uint64_t seq, const char *post)
{
    char q[300];
    snprintf(q, sizeof q, "%s%llu%s", pre, (unsigned long long)seq, post);
    return ex(s, q);
}

static imdb_db *dopen(const char *dir, bool full_replay)
{
    imdb_open_opts o = {.sync = 0, .full_replay = full_replay, .floor_stride = 1};
    imdb_db *db = NULL;
    imdb_err_clear(E);
    return imdb_open(dir, &o, &db, E) ? NULL : db;
}

static int audit_ok(const char *dir) /* 1: no auditor in this build (IMDB_AUDIT_BIN) */
{
    const char *bin = getenv("IMDB_AUDIT_BIN");
    if (!bin || !*bin) return 1;
    char cmd[1600];
    snprintf(cmd, sizeof cmd, "'%s' verify '%s' >/dev/null 2>&1", bin, dir);
    return system(cmd) == 0;
}

static int verify_db(imdb_db *db)
{
    imdb_verify_report vr;
    memset(&vr, 0, sizeof vr);
    imdb_err_clear(E);
    return imdb_verify(db, &vr, E);
}

/* the versions a table keeps, in memory or the lake's alone (what RETIRE drops) */
static uint64_t kept(imdb_table *t)
{
    uint64_t k = 0;
    for (uint64_t vid = 0; vid < t->nver; vid++) {
        imdb_vloc at;
        imdb_err e = {0};
        int where = imdb_v_find(t, vid, &at, &e);
        if (where < 0) return UINT64_MAX;
        k += where != IMDB_VAT_NONE;
    }
    return k;
}

/* The drop itself: gone for every statement now, the table as it was AS OF before the drop by each read path (the
 * key, an index, a unique index, a scan), nothing at the drop's own commit; the same answers and view token after
 * a replaying open and after a snapshot open from a CHECKPOINT that carries the tombstone */
static void t_drop_basics(void)
{
    const char *dir = test_tmpdir();
    OK(imdb_init(dir, false, NULL, E));
    imdb_db *db = dopen(dir, false);
    CHECK(db);
    if (!db) return;
    imdb_session s;
    imdb_session_init(&s, db);
    OK(ex(&s, "CREATE TABLE t (id INT64 PRIMARY KEY, a INT64, s TEXT)"));
    OK(ex(&s, "CREATE INDEX t_a ON t (a)"));
    OK(ex(&s, "CREATE UNIQUE INDEX t_s ON t (s)"));
    OK(ex(&s, "CREATE TABLE u (id INT64 PRIMARY KEY, tid INT64)"));
    OK(ex(&s, "INSERT INTO t VALUES (1, 10, 'x'), (2, 20, 'y'), (3, 30, 'z')"));
    OK(ex(&s, "UPDATE t SET a = 21 WHERE id = 2"));
    OK(ex(&s, "DELETE FROM t WHERE id = 3"));
    OK(ex(&s, "INSERT INTO u VALUES (1, 1), (2, 2)"));
    uint64_t before = db->seq;
    uint8_t t0[32], t1[32], t2[32];
    OK(imdb_view_token(db, t0, E));
    OK(ex(&s, "DROP TABLE t"));
    uint64_t dropped = db->seq;
    CHECK(dropped == before + 1);
    OK(imdb_view_token(db, t1, E));
    CHECK(memcmp(t0, t1, 32) != 0);
    imdb_table *old = imdb_table_at(db, "t", before);
    CHECK(old && old->dropped_at == dropped && old->live == 0 && !imdb_table_by_name(db, "t"));
    CHECK(ex(&s, "SELECT * FROM t") == IMDB_ERR_NOTFOUND);
    CHECK(ex(&s, "INSERT INTO t VALUES (4, 40, 'w')") == IMDB_ERR_NOTFOUND);
    CHECK(ex(&s, "UPDATE t SET a = 1 WHERE id = 1") == IMDB_ERR_NOTFOUND);
    CHECK(ex(&s, "DROP TABLE t") == IMDB_ERR_NOTFOUND);
    CHECK(ex(&s, "SELECT COUNT(*) FROM t JOIN u ON t.id = u.tid") == IMDB_ERR_NOTFOUND);
    CHECK(ex(&s, "CREATE INDEX t_b ON t (a)") != IMDB_OK && strstr(g_e.msg, "no table t"));
    for (int round = 0; round < 3; round++) { /* live, then after a replaying open, then after a snapshot open */
        CHECK(one_at(&s, "SELECT COUNT(*) FROM t AS OF ", before, "") == 2);
        CHECK(one_at(&s, "SELECT a FROM t AS OF ", before, " WHERE id = 2") == 21);
        CHECK(one_at(&s, "SELECT id FROM t AS OF ", before, " WHERE a = 21") == 2);
        CHECK(one_at(&s, "SELECT id FROM t AS OF ", before, " WHERE s = 'x'") == 1);
        CHECK(one_at(&s, "SELECT SUM(a) FROM t AS OF ", before, "") == 31);
        CHECK(one_at(&s, "SELECT COUNT(*) FROM t AS OF ", before - 2, "") == 3); /* before the DELETE */
        CHECK(ex_at(&s, "SELECT COUNT(*) FROM t AS OF ", dropped, "") == IMDB_ERR_NOTFOUND);
        CHECK(ex(&s, "SELECT COUNT(*) FROM t") == IMDB_ERR_NOTFOUND);
        CHECK(one(&s, "SELECT COUNT(*) FROM u") == (round ? 3 : 2)); /* round 0 adds a row below */
        OK(verify_db(db));
        if (round == 0) {
            OK(ex(&s, "CHECKPOINT")); /* the manifest carries the tombstone */
            OK(ex(&s, "INSERT INTO u VALUES (3, 3)"));
            OK(imdb_view_token(db, t1, E));
        }
        imdb_session_close(&s);
        imdb_close(db);
        if (round == 2) break;
        db = dopen(dir, round == 0);
        CHECK(db);
        if (!db) return;
        CHECK(round == 0 || db->snapshot_seq > 0);
        OK(imdb_view_token(db, t2, E));
        CHECK(!memcmp(t1, t2, 32));
        imdb_session_init(&s, db);
    }
    CHECK(audit_ok(dir));
}

/* The rules: a FOREVER table is dropped only with a retention, which the drop's commit sets first (op 16, then
 * 19); a drop runs outside a transaction; the codec keeps op 19 its commit's last op, after at most its own
 * table's SET_RETENTION, in the encoder and the decoder */
static void t_drop_rules(void)
{
    const char *dir = test_tmpdir();
    OK(imdb_init(dir, false, NULL, E));
    imdb_db *db = dopen(dir, false);
    CHECK(db);
    if (!db) return;
    imdb_session s;
    imdb_session_init(&s, db);
    OK(ex(&s, "CREATE TABLE f (id INT64 PRIMARY KEY) RETENTION FOREVER"));
    OK(ex(&s, "CREATE TABLE t (id INT64 PRIMARY KEY)"));
    OK(ex(&s, "INSERT INTO f VALUES (1)"));
    uint64_t seq0 = db->seq;
    CHECK(ex(&s, "DROP TABLE f") == IMDB_ERR_INVALID && strstr(g_e.msg, "FOREVER") && strstr(g_e.msg, "RETENTION"));
    CHECK(ex(&s, "DROP TABLE t RETENTION FOREVER") == IMDB_ERR_INVALID && strstr(g_e.msg, "FOREVER"));
    CHECK(ex(&s, "DROP TABLE nosuch") == IMDB_ERR_NOTFOUND);
    OK(ex(&s, "BEGIN"));
    CHECK(ex(&s, "DROP TABLE f RETENTION 7 DAYS") == IMDB_ERR_STATE);
    OK(ex(&s, "ROLLBACK"));
    CHECK(db->seq == seq0 && imdb_table_by_name(db, "f") && imdb_table_by_name(db, "t"));
    OK(ex(&s, "DROP TABLE f RETENTION 7 DAYS"));
    CHECK(db->seq == seq0 + 1); /* one commit: the retention, then the drop */
    imdb_table *ft = imdb_table_at(db, "f", seq0);
    CHECK(ft && ft->retention_us == 7 * DAY_US && ft->dropped_at == db->seq && !imdb_table_by_name(db, "f"));
    OK(ex(&s, "DROP TABLE t"));
    CHECK(!imdb_table_by_name(db, "t") && imdb_table_at(db, "t", seq0));
    OK(verify_db(db));
    imdb_session_close(&s);
    imdb_close(db);
    db = dopen(dir, true);
    CHECK(db);
    if (!db) return;
    ft = imdb_table_at(db, "f", seq0);
    CHECK(ft && ft->retention_us == 7 * DAY_US && ft->dropped_at == seq0 + 1);
    imdb_close(db);
    CHECK(audit_ok(dir));

    /* the codec: a round trip */
    imdb_op op = {.code = IMDB_OP_DROP_TABLE, .table = 1};
    imdb_commit_rec c = {.seq = 9, .alg = IMDB_DIGEST_ALG_LTHASH16, .ops = &op, .nops = 1};
    imdb_buf b;
    imdb_buf_init(&b);
    imdb_commit_encode_header(&c, &b);
    OK(imdb_buf_check(&b, E));
    CHECK(b.len == 54 + 5 + 32); /* the header to nops, u8 op + u32 table, the digest */
    imdb_commit_rec d;
    memset(&d, 0, sizeof d);
    OK(imdb_commit_decode_header(b.p, b.len, &d, E));
    CHECK(d.nops == 1 && d.ops[0].code == IMDB_OP_DROP_TABLE && d.ops[0].table == 1);
    imdb_commit_free(&d);
    /* two drops, built by hand (the encoder refuses them): the decoder refuses them too */
    imdb_buf h;
    imdb_buf_init(&h);
    imdb_buf_put(&h, b.p, 50);
    imdb_buf_put_u32(&h, 2);
    imdb_buf_put(&h, b.p + 54, 5);
    imdb_buf_put_u8(&h, IMDB_OP_DROP_TABLE);
    imdb_buf_put_u32(&h, 2);
    imdb_buf_put(&h, b.p + b.len - 32, 32);
    OK(imdb_buf_check(&h, E));
    memset(&d, 0, sizeof d);
    imdb_err_clear(E);
    CHECK(imdb_commit_decode_header(h.p, h.len, &d, E) == IMDB_ERR_CORRUPT && strstr(g_e.msg, "DROP_TABLE"));
    imdb_commit_free(&d);
    imdb_buf_free(&h);
    imdb_buf_free(&b);
    /* the encoder: its own table's retention first is the one pair it takes */
    imdb_op ret_same = {.code = IMDB_OP_SET_RETENTION, .table = 1, .retention_us = 7 * DAY_US};
    imdb_op ret_other = {.code = IMDB_OP_SET_RETENTION, .table = 2, .retention_us = 7 * DAY_US};
    imdb_op drop2 = {.code = IMDB_OP_DROP_TABLE, .table = 2};
    imdb_op ok_pair[2] = {ret_same, op}, bad1[2] = {ret_other, op}, bad2[2] = {op, ret_same}, bad3[2] = {op, drop2};
    imdb_op bad4[3] = {ret_same, ret_same, op};
    struct {
        imdb_op *ops;
        uint32_t n;
        bool ok;
    } cases[] = {{ok_pair, 2, true}, {bad1, 2, false}, {bad2, 2, false}, {bad3, 2, false}, {bad4, 3, false}};
    for (size_t i = 0; i < sizeof cases / sizeof *cases; i++) {
        imdb_commit_rec cc = {.seq = 9, .alg = IMDB_DIGEST_ALG_LTHASH16, .ops = cases[i].ops, .nops = cases[i].n};
        imdb_buf eb;
        imdb_buf_init(&eb);
        imdb_commit_encode_header(&cc, &eb);
        CHECK((eb.err == 0) == cases[i].ok);
        if (cases[i].ok && !eb.err) {
            memset(&d, 0, sizeof d);
            OK(imdb_commit_decode_header(eb.p, eb.len, &d, E));
            CHECK(d.nops == 2 && d.ops[0].code == IMDB_OP_SET_RETENTION && d.ops[1].code == IMDB_OP_DROP_TABLE);
            imdb_commit_free(&d);
        }
        imdb_buf_free(&eb);
    }
}

/* A dropped table's name and its index names are free: a new table of the same name (another schema) with an
 * index of the same name; each read resolves the name at its snapshot; SHOW TABLES lists both, the drop's commit
 * on the old; SHOW INDEXES the live table's only; all of it again after a snapshot open */
static void t_drop_names(void)
{
    const char *dir = test_tmpdir();
    OK(imdb_init(dir, false, NULL, E));
    imdb_db *db = dopen(dir, false);
    CHECK(db);
    if (!db) return;
    imdb_session s;
    imdb_session_init(&s, db);
    OK(ex(&s, "CREATE TABLE t (id INT64 PRIMARY KEY, a INT64)"));
    OK(ex(&s, "CREATE UNIQUE INDEX t_a ON t (a)"));
    OK(ex(&s, "INSERT INTO t VALUES (1, 10), (2, 20)"));
    uint64_t old = db->seq;
    OK(ex(&s, "DROP TABLE t"));
    uint64_t dropped = db->seq;
    CHECK(ex(&s, "CREATE TABLE t (id INT64 PRIMARY KEY, s TEXT, a INT64)") == IMDB_OK);
    OK(ex(&s, "CREATE INDEX t_a ON t (a)")); /* the name is free again, and this one not unique */
    OK(ex(&s, "INSERT INTO t VALUES (5, 'new', 50), (6, 'dup', 50)"));
    uint64_t now = db->seq;
    for (int round = 0; round < 2; round++) {
        CHECK(one(&s, "SELECT COUNT(*) FROM t") == 2);
        CHECK(one(&s, "SELECT COUNT(*) FROM t WHERE a = 50") == 2);
        CHECK(one_at(&s, "SELECT COUNT(*) FROM t AS OF ", old, "") == 2);
        CHECK(one_at(&s, "SELECT a FROM t AS OF ", old, " WHERE id = 2") == 20);
        CHECK(one_at(&s, "SELECT id FROM t AS OF ", old, " WHERE a = 20") == 2);
        CHECK(ex_at(&s, "SELECT s FROM t AS OF ", old, "") != IMDB_OK); /* the old table has no column s */
        CHECK(one_at(&s, "SELECT COUNT(*) FROM t AS OF ", now, "") == 2);
        CHECK(one_at(&s, "SELECT id FROM t AS OF ", now, " WHERE s = 'new'") == 5);
        imdb_result r;
        imdb_err_clear(E);
        OK(imdb_exec_one(&s, "SHOW TABLES", 11, NULL, 0, &r, E));
        CHECK(r.ncols == 7 && r.nrows == 2);
        if (r.ncols == 7 && r.nrows == 2) {
            CHECK(!r.cells[6].null && r.cells[6].v.i == (int64_t)dropped && r.cells[2].v.i == 0);
            CHECK(r.cells[7 + 6].null && r.cells[7 + 2].v.i == 2);
        }
        imdb_result_free(&r);
        imdb_err_clear(E);
        OK(imdb_exec_one(&s, "SHOW INDEXES", 12, NULL, 0, &r, E));
        CHECK(r.nrows == 1 && r.ncols == 4 && r.cells[3].v.len == 2 && !memcmp(r.cells[3].v.s, "no", 2));
        imdb_result_free(&r);
        OK(verify_db(db));
        if (round == 0) OK(ex(&s, "CHECKPOINT"));
        imdb_session_close(&s);
        imdb_close(db);
        if (round == 1) break;
        db = dopen(dir, false);
        CHECK(db);
        if (!db) return;
        CHECK(db->snapshot_seq > 0);
        imdb_session_init(&s, db);
    }
    CHECK(audit_ok(dir));
}

/* Transactions across a drop: one that wrote the table (parked when the drop commits) is doomed and can only roll
 * back; a snapshot reader keeps reading the table at its snapshot and commits; a statement after its rollback finds
 * no table */
static void t_drop_txn(void)
{
    const char *dir = test_tmpdir();
    OK(imdb_init(dir, false, NULL, E));
    imdb_db *db = dopen(dir, false);
    CHECK(db);
    if (!db) return;
    imdb_session w, rd, d;
    imdb_session_init(&w, db);
    imdb_session_init(&rd, db);
    imdb_session_init(&d, db);
    OK(ex(&d, "CREATE TABLE t (id INT64 PRIMARY KEY, a INT64)"));
    OK(ex(&d, "CREATE TABLE v (id INT64 PRIMARY KEY)"));
    OK(ex(&d, "INSERT INTO t VALUES (1, 1), (2, 2)"));
    OK(ex(&w, "BEGIN"));
    OK(ex(&w, "INSERT INTO v VALUES (1)"));
    OK(ex(&w, "INSERT INTO t VALUES (3, 3)"));
    OK(ex(&rd, "BEGIN"));
    CHECK(one(&rd, "SELECT COUNT(*) FROM t") == 2);
    OK(ex(&d, "DROP TABLE t"));
    uint64_t dropped = db->seq;
    CHECK(ex(&w, "INSERT INTO v VALUES (2)") == IMDB_ERR_CONFLICT && strstr(g_e.msg, "dropped"));
    CHECK(ex(&w, "COMMIT") == IMDB_ERR_CONFLICT);
    CHECK(one(&rd, "SELECT COUNT(*) FROM t") == 2); /* its snapshot is before the drop */
    CHECK(one(&rd, "SELECT a FROM t WHERE id = 2") == 2);
    OK(ex(&rd, "COMMIT"));
    CHECK(ex(&rd, "SELECT COUNT(*) FROM t") == IMDB_ERR_NOTFOUND);
    CHECK(ex(&w, "SELECT COUNT(*) FROM v") == IMDB_OK && one(&w, "SELECT COUNT(*) FROM v") == 0);
    CHECK(db->seq == dropped); /* nothing of the doomed transaction committed */
    /* a writer of another table is untouched by the drop */
    OK(ex(&d, "CREATE TABLE t2 (id INT64 PRIMARY KEY)"));
    OK(ex(&w, "BEGIN"));
    OK(ex(&w, "INSERT INTO v VALUES (7)"));
    OK(ex(&d, "DROP TABLE t2"));
    OK(ex(&w, "COMMIT"));
    CHECK(one(&d, "SELECT COUNT(*) FROM v") == 1);
    OK(verify_db(db));
    imdb_session_close(&w);
    imdb_session_close(&rd);
    imdb_session_close(&d);
    imdb_close(db);
    CHECK(audit_ok(dir));
}

/* A replica applies the drop and the table after it: the same view token, the same answers at each era, VERIFY
 * on the replica; the logs equal frame for frame */
static void t_drop_replica(void)
{
    const char *dir = test_tmpdir();
    char p[700], r[700], sf[700], why[300];
    snprintf(p, sizeof p, "%s/p", dir);
    snprintf(r, sizeof r, "%s/r", dir);
    snprintf(sf, sizeof sf, "%s/stream", dir);
    OK(imdb_init(p, false, NULL, E));
    OK(imdb_init(r, true, p, E));
    imdb_db *db = dopen(p, false);
    CHECK(db);
    if (!db) return;
    imdb_session s;
    imdb_session_init(&s, db);
    OK(ex(&s, "CREATE TABLE t (id INT64 PRIMARY KEY, a INT64) RETENTION FOREVER"));
    OK(ex(&s, "CREATE INDEX t_a ON t (a)"));
    OK(ex(&s, "INSERT INTO t VALUES (1, 10), (2, 20), (3, 30)"));
    OK(ex(&s, "CHECKPOINT"));
    OK(ex(&s, "UPDATE t SET a = 31 WHERE id = 3"));
    uint64_t old = db->seq;
    OK(ex(&s, "DROP TABLE t RETENTION 1 DAY"));
    OK(ex(&s, "CREATE TABLE t (id INT64 PRIMARY KEY, b INT64)"));
    OK(ex(&s, "INSERT INTO t VALUES (9, 90)"));
    uint8_t tp[32], tr[32];
    OK(imdb_view_token(db, tp, E));
    uint64_t pseq = db->seq;
    imdb_session_close(&s);
    imdb_close(db);
    OK(ship_to_file(p, 0, sf, E));
    imdb_db *rdb = dopen(r, false);
    CHECK(rdb);
    if (!rdb) return;
    uint64_t applied = 0;
    OK(apply_file(rdb, sf, &applied, E));
    CHECK(rdb->seq == pseq);
    OK(imdb_view_token(rdb, tr, E));
    CHECK(!memcmp(tp, tr, 32));
    imdb_session_init(&s, rdb);
    CHECK(one_at(&s, "SELECT SUM(a) FROM t AS OF ", old, "") == 61);
    CHECK(one_at(&s, "SELECT id FROM t AS OF ", old, " WHERE a = 31") == 3);
    CHECK(one(&s, "SELECT b FROM t WHERE id = 9") == 90);
    imdb_session_close(&s);
    OK(verify_db(rdb));
    imdb_close(rdb);
    rdb = dopen(r, true);
    CHECK(rdb);
    if (!rdb) return;
    OK(imdb_view_token(rdb, tr, E));
    CHECK(!memcmp(tp, tr, 32));
    imdb_close(rdb);
    char la[720], lb[720];
    snprintf(la, sizeof la, "%s/log", p);
    snprintf(lb, sizeof lb, "%s/log", r);
    bool same = logs_identical(la, lb, why, sizeof why);
    if (!same) fprintf(stderr, "    logs differ: %s\n", why);
    CHECK(same);
    CHECK(audit_ok(p) && audit_ok(r));
}

/* The history a drop keeps expires by the table's retention, as any table's: the policy's EXPIRE names the dropped
 * table (the commit takes an EXPIRE of a dropped table, nothing else), AS OF below the horizon is a history error,
 * and RETIRE then drops every version the table kept; the tombstone stays, and every check re-derives it */
static void t_drop_expire_retire(void)
{
    const char *dir = test_tmpdir();
    OK(imdb_init(dir, false, NULL, E));
    imdb_db *db = dopen(dir, false);
    CHECK(db);
    if (!db) return;
    db->no_auto_retire = true;
    imdb_session s;
    imdb_session_init(&s, db);
    OK(ex(&s, "CREATE TABLE a (id INT64 PRIMARY KEY, v INT64) RETENTION 10 SECONDS"));
    OK(ex(&s, "CREATE TABLE b (id INT64 PRIMARY KEY, v INT64) RETENTION 10 SECONDS"));
    OK(ex(&s, "INSERT INTO a VALUES (1, 1), (2, 2), (3, 3)"));
    OK(ex(&s, "INSERT INTO b VALUES (1, 1)"));
    uint64_t before = db->seq;
    OK(ex(&s, "DROP TABLE a"));
    OK(ex(&s, "UPDATE b SET v = 2 WHERE id = 1"));
    OK(ex(&s, "CHECKPOINT")); /* the first segment ends */
    uint64_t first = db->seq + 1;
    OK(ex(&s, "UPDATE b SET v = 3 WHERE id = 1"));
    OK(ex(&s, "CHECKPOINT"));
    imdb_table *ta = imdb_table_at(db, "a", before);
    CHECK(ta && kept(ta) == 3 && one_at(&s, "SELECT COUNT(*) FROM a AS OF ", before, "") == 3);
    imdb_clock_offset(15 * SEC_US);
    OK(ex(&s, "SELECT COUNT(*) FROM b")); /* the policy: both horizons to the second segment's start */
    ta = imdb_table_at(db, "a", before);
    imdb_table *tb = imdb_table_by_name(db, "b");
    CHECK(ta && tb && ta->horizon == first && tb->horizon == first);
    CHECK(ex_at(&s, "SELECT COUNT(*) FROM a AS OF ", before, "") == IMDB_ERR_HISTORY);
    OK(verify_db(db));
    OK(imdb_retire(db, first - 1, E));
    ta = imdb_table_at(db, "a", before);
    CHECK(ta && kept(ta) == 0 && ta->dropped_at == before + 1);
    CHECK(one(&s, "SELECT v FROM b WHERE id = 1") == 3);
    OK(verify_db(db));
    OK(ex(&s, "INSERT INTO b VALUES (2, 2)"));
    uint8_t t1[32], t2[32];
    OK(imdb_view_token(db, t1, E));
    imdb_session_close(&s);
    imdb_close(db);
    db = dopen(dir, false);
    CHECK(db);
    if (!db) return;
    OK(imdb_view_token(db, t2, E));
    CHECK(!memcmp(t1, t2, 32));
    ta = imdb_table_at(db, "a", before);
    CHECK(ta && kept(ta) == 0 && ta->horizon == first && ta->dropped_at == before + 1);
    OK(verify_db(db));
    imdb_close(db);
    CHECK(audit_ok(dir));
}

/* ERASE SUBJECT reaches a dropped table's history: AS OF before the drop no longer shows the subject's rows, and
 * their payloads leave the log, the lake and memory */
static void t_drop_erase_subject(void)
{
    const char *dir = test_tmpdir();
    OK(imdb_init(dir, false, NULL, E));
    imdb_db *db = dopen(dir, false);
    CHECK(db);
    if (!db) return;
    imdb_session s;
    imdb_session_init(&s, db);
    OK(ex(&s, "CREATE TABLE p (id INT64 PRIMARY KEY, u INT64 SUBJECT, note TEXT)"));
    OK(ex(&s, "INSERT INTO p VALUES (1, 7, 'dropsecret-seven-1'), (2, 7, 'dropsecret-seven-2'), (3, 8, 'kept-eight')"));
    OK(ex(&s, "CHECKPOINT"));
    uint64_t before = db->seq;
    OK(ex(&s, "DROP TABLE p"));
    CHECK(one_at(&s, "SELECT COUNT(*) FROM p AS OF ", before, "") == 3);
    OK(ex(&s, "ERASE SUBJECT 7"));
    CHECK(one_at(&s, "SELECT COUNT(*) FROM p AS OF ", before, "") == 1);
    CHECK(one_at(&s, "SELECT id FROM p AS OF ", before, "") == 3);
    OK(verify_db(db));
    OK(ex(&s, "CHECKPOINT"));
    imdb_session_close(&s);
    imdb_close(db);
    CHECK(!tree_contains(dir, "dropsecret-seven") && tree_contains(dir, "kept-eight"));
    db = dopen(dir, true);
    CHECK(db);
    if (!db) return;
    imdb_session_init(&s, db);
    CHECK(one_at(&s, "SELECT COUNT(*) FROM p AS OF ", before, "") == 1);
    imdb_session_close(&s);
    OK(verify_db(db));
    imdb_close(db);
    CHECK(audit_ok(dir));
}


/* Hostile logs, made here by unhooking the engine's own refusals for one commit each: a write to a dropped table after
 * its drop, and a drop of a table whose logged retention is FOREVER. VERIFY, a replaying open and the auditor each refuse
 * both (the three keep one rule: ops 2-4, 11 and 14-16 never name a dropped table; a FOREVER table is never dropped) */
static void t_drop_hostile(void)
{
    const char *base = test_tmpdir();
    for (int c = 0; c < 2; c++) {
        char dir[700];
        snprintf(dir, sizeof dir, "%s/h%d", base, c);
        OK(imdb_init(dir, false, NULL, E));
        imdb_db *db = dopen(dir, false);
        CHECK(db);
        if (!db) return;
        imdb_session s;
        imdb_session_init(&s, db);
        if (c == 0) {
            OK(ex(&s, "CREATE TABLE t (id INT64 PRIMARY KEY, v INT64)"));
            OK(ex(&s, "INSERT INTO t VALUES (1, 1)"));
            OK(ex(&s, "DROP TABLE t"));
            imdb_table *t = db->t[0];
            uint64_t d = t->dropped_at;
            CHECK(d == db->seq && ex(&s, "INSERT INTO t VALUES (2, 2)") == IMDB_ERR_NOTFOUND);
            t->dropped_at = 0; /* the hook: the commit's own conflict check would refuse the write */
            OK(ex(&s, "INSERT INTO t VALUES (2, 2)"));
            t->dropped_at = d;
        } else {
            OK(ex(&s, "CREATE TABLE f (id INT64 PRIMARY KEY) RETENTION FOREVER"));
            OK(ex(&s, "INSERT INTO f VALUES (1)"));
            imdb_table *f = db->t[0];
            f->retention_us = 7 * DAY_US; /* the hook: in memory only, so the drop logs no retention of its own */
            OK(ex(&s, "DROP TABLE f"));
            f->retention_us = IMDB_RETAIN_FOREVER;
        }
        imdb_session_close(&s);
        CHECK(verify_db(db) == IMDB_ERR_VERIFY && (strstr(g_e.msg, "dropped") || strstr(g_e.msg, "FOREVER")));
        imdb_close(db);
        imdb_open_opts o = {.sync = 0, .full_replay = true};
        db = NULL;
        imdb_err_clear(E);
        CHECK(imdb_open(dir, &o, &db, E) == IMDB_ERR_CORRUPT && !db);
        if (db) imdb_close(db);
        const char *bin = getenv("IMDB_AUDIT_BIN");
        if (bin && *bin) CHECK(!audit_ok(dir));
    }
}

/* A dropped table through an encrypted backup: dropped in the commits after the backup's snapshot (the restore applies
 * op 19), then carried in the snapshot itself (the seed's manifest has the tombstone); each copy has the source's view
 * token, VERIFY and the auditor pass it, and AS OF before the drop answers on the first, whose history covers it */
static void t_drop_backup(void)
{
    const char *tmp = test_tmpdir();
    char p[600], kf[600], out[2][600], r[2][600];
    snprintf(p, sizeof p, "%s/p", tmp);
    snprintf(kf, sizeof kf, "%s/backup.key", tmp);
    for (int i = 0; i < 2; i++) {
        snprintf(out[i], sizeof out[i], "%s/b%d.bak", tmp, i);
        snprintf(r[i], sizeof r[i], "%s/r%d", tmp, i);
    }
    uint8_t id[32], key[IMDB_BACKUP_KEY_LEN];
    OK(imdb_backup_key_create(kf, id, E));
    OK(imdb_backup_key_load(kf, key, E));
    OK(imdb_init(p, false, NULL, E));
    imdb_db *db = dopen(p, false);
    CHECK(db);
    if (!db) return;
    imdb_session s;
    imdb_session_init(&s, db);
    OK(ex(&s, "CREATE TABLE t (id INT64 PRIMARY KEY, a INT64)"));
    OK(ex(&s, "CREATE INDEX t_a ON t (a)"));
    OK(ex(&s, "CREATE TABLE u (id INT64 PRIMARY KEY)"));
    OK(ex(&s, "INSERT INTO t VALUES (1, 10), (2, 20)"));
    OK(ex(&s, "INSERT INTO u VALUES (1)"));
    OK(ex(&s, "CHECKPOINT"));
    uint64_t before = db->seq;
    OK(ex(&s, "DROP TABLE t"));
    OK(ex(&s, "CREATE TABLE t (id INT64 PRIMARY KEY, b TEXT)"));
    OK(ex(&s, "INSERT INTO t VALUES (7, 'new')"));
    imdb_session_close(&s);
    imdb_close(db);
    imdb_backup_info bi[2], ri;
    OK(imdb_backup_full(p, out[0], key, &bi[0], E)); /* the drop after its snapshot */
    CHECK(bi[0].seed_seq == before && bi[0].parts == 2);
    db = dopen(p, false);
    CHECK(db);
    if (!db) return;
    imdb_session_init(&s, db);
    OK(ex(&s, "CHECKPOINT")); /* the drop inside the next snapshot */
    OK(ex(&s, "INSERT INTO u VALUES (2)"));
    uint8_t vt[2][32], vr[32];
    OK(imdb_view_token(db, vt[1], E));
    imdb_session_close(&s);
    imdb_close(db);
    OK(imdb_backup_full(p, out[1], key, &bi[1], E));
    CHECK(bi[1].seed_seq > before + 1);
    for (int i = 0; i < 2; i++) {
        const char *files[1] = {out[i]};
        OK(imdb_restore(r[i], key, files, 1, &ri, E));
        CHECK(ri.last_seq == bi[i].last_seq);
        imdb_db *c = open_db(r[i]);
        CHECK(c);
        if (!c) return;
        OK(imdb_view_token(c, vr, E));
        if (i == 1) CHECK(!memcmp(vr, vt[1], 32));
        else memcpy(vt[0], vr, 32);
        imdb_table *old = imdb_table_at(c, "t", before);
        CHECK(old && old->dropped_at == before + 1 && old->live == 0);
        imdb_session_init(&s, c);
        CHECK(one(&s, "SELECT COUNT(*) FROM t") == 1);
        if (i == 0) {
            CHECK(one_at(&s, "SELECT COUNT(*) FROM t AS OF ", before, "") == 2);
            CHECK(one_at(&s, "SELECT id FROM t AS OF ", before, " WHERE a = 20") == 2);
        } else {
            CHECK(ex_at(&s, "SELECT COUNT(*) FROM t AS OF ", before, "") != IMDB_OK); /* before the copy's history */
        }
        imdb_session_close(&s);
        OK(verify_db(c));
        imdb_close(c);
        CHECK(audit_ok(r[i]));
    }
    /* the first copy against the source at the same commit: the same token */
    imdb_open_opts ro = {.sync = 0, .read_only = true};
    db = NULL;
    OK(imdb_open(p, &ro, &db, E));
    CHECK(db && db->seq > bi[0].last_seq);
    if (db) imdb_close(db);
    CHECK(memcmp(vt[0], vt[1], 32) != 0); /* the second copy is a commit later (u's row) */
}

const test_case drop_tests[] = {
    {"drop_basics", t_drop_basics},
    {"drop_rules", t_drop_rules},
    {"drop_names", t_drop_names},
    {"drop_txn", t_drop_txn},
    {"drop_replica", t_drop_replica},
    {"drop_expire_retire", t_drop_expire_retire},
    {"drop_erase_subject", t_drop_erase_subject},
    {"drop_hostile", t_drop_hostile},
    {"drop_backup", t_drop_backup},
};
const size_t drop_ntests = sizeof drop_tests / sizeof *drop_tests;
