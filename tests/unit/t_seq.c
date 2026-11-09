/* F2a-2: sequences (design.md section 5, Sequences; docs/plan-p2.md 2026-11-09 15:3x). CREATE and DROP SEQUENCE,
 * nextval, currval, setval and lastval, GENERATED ALWAYS and BY DEFAULT AS IDENTITY and SERIAL (an owned sequence each),
 * DEFAULT nextval('s'), OVERRIDING SYSTEM and USER VALUE, DEFAULT VALUES and VALUES (DEFAULT). A commit whose
 * transaction called nextval logs each sequence's mark (op 26), so after any reopen the next value is past every
 * committed one; a rolled-back transaction's values are gaps. Each against values it states, through a CHECKPOINT
 * (manifest 10), a snapshot open, a full replay, a parked transaction, a replica, a seed past a RETIRE, a backup's
 * restore and a dump's, VERIFY and the auditor. */
#include <stdlib.h>


#include "../../src/backup.h"
#include "../../src/db_internal.h"
#include "../../src/lake.h"
#include "../../src/log.h"
#include "../../src/sql.h"
#include "thelp.h"

static imdb_session g_s;
static char g_out[1 << 16];

static const char *csv(const char *sql)
{
    imdb_result r;
    imdb_err_clear(&g_e);
    if (imdb_exec_one(&g_s, sql, strlen(sql), NULL, 0, &r, &g_e)) {
        snprintf(g_out, sizeof g_out, "ERR %s", g_e.msg);
        return g_out;
    }
    imdb_buf b;
    imdb_buf_init(&b);
    if (r.has_rows) imdb_result_render(&r, true, &b);
    else imdb_buf_put_str(&b, r.status);
    if (imdb_buf_check(&b, &g_e)) snprintf(g_out, sizeof g_out, "ERR render");
    else snprintf(g_out, sizeof g_out, "%.*s", (int)b.len, (const char *)b.p);
    imdb_buf_free(&b);
    imdb_result_free(&r);
    return g_out;
}

static int run(const char *sql)
{
    imdb_result r;
    imdb_err_clear(&g_e);
    int rc = imdb_exec_one(&g_s, sql, strlen(sql), NULL, 0, &r, &g_e);
    if (!rc) imdb_result_free(&r);
    return rc;
}

#define EXPECT(sql, want)                                                                                          \
    do {                                                                                                           \
        const char *got_ = csv(sql);                                                                               \
        bool ok_ = !strncmp((want), "ERR ", 4) ? !strncmp(got_, "ERR ", 4) && strstr(got_ + 4, (want) + 4) != NULL \
                                               : !strcmp(got_, (want));                                            \
        if (!ok_) {                                                                                                \
            char m_[1600];                                                                                         \
            snprintf(m_, sizeof m_, "%s\n      want: %s\n      got:  %.600s", (sql), (want), got_);                \
            test_fail(__FILE__, __LINE__, m_);                                                                     \
        }                                                                                                          \
    } while (0)

static imdb_db *open_at(const char *dir, bool full_replay)
{
    imdb_open_opts o = {.sync = 0, .full_replay = full_replay};
    imdb_db *db = NULL;
    imdb_err e = {0};
    if (imdb_open(dir, &o, &db, &e)) return NULL;
    imdb_session_init(&g_s, db);
    return db;
}

static imdb_db *open_fresh(const char *dir)
{
    imdb_err e = {0};
    if (imdb_init(dir, false, NULL, &e)) return NULL;
    return open_at(dir, false);
}

static void done(imdb_db *db)
{
    imdb_session_close(&g_s);
    imdb_close(db);
}

static int audit_dir(const char *dir)
{
    const char *bin = getenv("IMDB_AUDIT_BIN");
    if (!bin || !*bin) return 0; /* no auditor in this build: said by vectors_auditor */
    char cmd[1600];
    snprintf(cmd, sizeof cmd, "'%s' verify '%s' >/dev/null 2>&1", bin, dir);
    return system(cmd) == 0 ? 0 : 1;
}

static int verify_db(imdb_db *db)
{
    imdb_verify_report vr;
    memset(&vr, 0, sizeof vr);
    imdb_err_clear(&g_e);
    return imdb_verify(db, &vr, &g_e);
}

/* a dump's text, gathered (test memory, not the engine's) */
typedef struct dumpbuf {
    char *p;
    size_t n, cap;
} dumpbuf;

static int dumpbuf_write(void *arg, const char *b, size_t n)
{
    dumpbuf *o = arg;
    if (o->n + n + 1 > o->cap) {
        size_t c = (o->n + n + 1) * 2;
        char *q = realloc(o->p, c);
        if (!q) return -1;
        o->p = q;
        o->cap = c;
    }
    memcpy(o->p + o->n, b, n);
    o->n += n;
    o->p[o->n] = 0;
    return 0;
}

/* the dump of db from its second line (the first names the head), or NULL */
static char *dump_body(imdb_db *db)
{
    dumpbuf d = {0};
    imdb_err e = {0};
    if (imdb_dump(db, 1000, dumpbuf_write, &d, &e) || !d.p) {
        free(d.p);
        return NULL;
    }
    const char *nl = strchr(d.p, '\n');
    char *out = nl ? strdup(nl + 1) : NULL;
    free(d.p);
    return out;
}

/* the first cell of a one-row, one-column answer, as text */
static const char *one(const char *sql)
{
    const char *got = csv(sql);
    const char *nl = strchr(got, '\n');
    static char v[256];
    if (!nl || !strncmp(got, "ERR ", 4)) return got;
    snprintf(v, sizeof v, "%.*s", (int)strcspn(nl + 1, "\n"), nl + 1);
    return v;
}

/* the statements and the options: PostgreSQL's defaults, ascending and descending, the bounds, the refusals, one name
 * space with tables and views */
static void t_seq_basic(void)
{
    const char *dir = test_tmpdir();
    imdb_db *db = open_fresh(dir);
    CHECK(db);
    if (!db) return;
    OK(run("CREATE SEQUENCE s"));
    EXPECT("SELECT nextval('s'), nextval('s'), nextval('S')", "nextval('s'),nextval('s'),nextval('S')\n1,2,3\n");
    EXPECT("SELECT currval('s'), lastval()", "currval('s'),lastval()\n3,3\n");
    OK(run("CREATE SEQUENCE d AS SMALLINT INCREMENT BY -10 MINVALUE -25 MAXVALUE 10 START WITH 5"));
    CHECK(!strcmp(one("SELECT nextval('d')"), "5"));
    CHECK(!strcmp(one("SELECT nextval('d')"), "-5"));
    CHECK(!strcmp(one("SELECT nextval('d')"), "-15"));
    CHECK(!strcmp(one("SELECT nextval('d')"), "-25"));
    EXPECT("SELECT nextval('d')", "ERR reached its minimum value (-25)");
    CHECK(!strcmp(one("SELECT lastval()"), "-25"));
    OK(run("CREATE SEQUENCE m MAXVALUE 2"));
    OK(run("SELECT nextval('m'), nextval('m')"));
    EXPECT("SELECT nextval('m')", "ERR reached its maximum value (2)");
    EXPECT("SELECT currval('x')", "ERR no sequence x");
    OK(run("CREATE SEQUENCE fresh"));
    EXPECT("SELECT currval('fresh')", "ERR no nextval of it in this session yet");
    static const struct {
        const char *sql, *err;
    } bad[] = {
        {"CREATE SEQUENCE b CYCLE", "ERR CYCLE"},
        {"CREATE SEQUENCE b CACHE 20", "ERR CACHE 20"},
        {"CREATE SEQUENCE b OWNED BY t.id", "ERR OWNED BY"},
        {"CREATE SEQUENCE b INCREMENT BY 0", "ERR INCREMENT must not be zero"},
        {"CREATE SEQUENCE b MINVALUE 5 MAXVALUE 5", "ERR MINVALUE below MAXVALUE"},
        {"CREATE SEQUENCE b START WITH 0", "ERR START between them"},
        {"CREATE SEQUENCE b AS SMALLINT MAXVALUE 40000", "ERR within its type"},
        {"CREATE SEQUENCE s", "ERR a table, view or sequence s exists already"},
        {"CREATE TABLE s (id INT64 PRIMARY KEY)", "ERR sequence s exists already"},
        {"CREATE VIEW s AS SELECT 1 AS one", "ERR sequence s exists already"},
        {"DROP SEQUENCE nosuch", "ERR no sequence nosuch"},
        {"DROP SEQUENCE s CASCADE", "ERR CASCADE"},
        {"EXPLAIN SELECT nextval('s')", "ERR EXPLAIN of a statement calling nextval"},
        {"CREATE VIEW vs AS SELECT nextval('s') AS n", "ERR a view's query calls no nextval"},
    };
    for (size_t i = 0; i < sizeof bad / sizeof *bad; i++) EXPECT(bad[i].sql, bad[i].err);
    CHECK(db->nseqs == 4);
    OK(run("CREATE TABLE t (id INT64 PRIMARY KEY)"));
    EXPECT("CREATE SEQUENCE t", "ERR a table, view or sequence t exists already");
    EXPECT("DROP SEQUENCE m", "DROP SEQUENCE m");
    EXPECT("SELECT nextval('m')", "ERR no sequence m");
    OK(run("CREATE SEQUENCE m START WITH 7")); /* the name is free again; a new id */
    CHECK(!strcmp(one("SELECT nextval('m')"), "7") && db->nseqs == 5);
    CHECK(verify_db(db) == 0);
    done(db);
    CHECK(audit_dir(dir) == 0);
}

/* the marks: a transaction's values, a rollback's gaps, a parked transaction's sequences kept (its commit logs them),
 * setval's states (autocommit alone; called or not), each through a reopen, a CHECKPOINT and a full replay */
static void t_seq_txn(void)
{
    const char *dir = test_tmpdir();
    imdb_db *db = open_fresh(dir);
    CHECK(db);
    if (!db) return;
    OK(run("CREATE SEQUENCE s"));
    OK(run("CREATE TABLE t (id INT64 PRIMARY KEY, v INT64)"));
    OK(run("BEGIN"));
    OK(run("INSERT INTO t VALUES (nextval('s'), 1), (nextval('s'), 2)"));
    OK(run("COMMIT"));
    OK(run("BEGIN"));
    OK(run("SELECT nextval('s')")); /* 3: rolled back, a gap */
    OK(run("ROLLBACK"));
    CHECK(!strcmp(one("SELECT nextval('s')"), "4")); /* an autocommit SELECT: a mark-only commit */
    EXPECT("BEGIN", "BEGIN");
    EXPECT("SELECT setval('s', 100)", "ERR setval commits on its own");
    OK(run("ROLLBACK"));
    /* a parked transaction: A takes 5 and 6 and writes, B's statement parks A, A commits: its marks are logged */
    imdb_session b;
    imdb_session_init(&b, db);
    OK(run("BEGIN"));
    OK(run("INSERT INTO t VALUES (nextval('s'), 3)"));
    OK(run("SELECT nextval('s')"));
    imdb_result r;
    imdb_err_clear(&g_e);
    const char *q = "INSERT INTO t VALUES (1000, 0)";
    CHECK(imdb_exec_one(&b, q, strlen(q), NULL, 0, &r, &g_e) == 0); /* parks A */
    if (!g_e.code) imdb_result_free(&r);
    OK(run("COMMIT"));
    imdb_session_close(&b);
    EXPECT("SELECT id FROM t ORDER BY id", "id\n1\n2\n5\n1000\n");
    done(db);
    db = open_at(dir, false);
    CHECK(db);
    if (!db) return;
    CHECK(!strcmp(one("SELECT nextval('s')"), "7")); /* past 6, the parked transaction's last */
    OK(run("SELECT nextval('s'), setval('s', 10, false)")); /* 8, then the state 10 uncalled: its SEQ_SET is the state */
    done(db);
    for (int pass = 0; pass < 3; pass++) {
        db = open_at(dir, pass == 2);
        CHECK(db);
        if (!db) return;
        if (pass == 0) {
            CHECK(!strcmp(one("SELECT nextval('s')"), "10"));
            OK(run("SELECT setval('s', 20)"));
            OK(run("CHECKPOINT"));
        } else {
            char want[8];
            snprintf(want, sizeof want, "%d", 20 + pass);
            CHECK(!strcmp(one("SELECT nextval('s')"), want));
        }
        CHECK(verify_db(db) == 0);
        done(db);
    }
    CHECK(audit_dir(dir) == 0);
}

/* IDENTITY and SERIAL: their sequences, the values each row takes on every write path, the ALWAYS rules, OVERRIDING,
 * DEFAULT VALUES and VALUES (DEFAULT); an owned sequence lives and dies with its column or table; DROP SEQUENCE's
 * RESTRICT; the DEFAULT rules on an identity; cross_check runs a nextval statement's plan once */
static void t_seq_identity(void)
{
    const char *dir = test_tmpdir();
    imdb_db *db = open_fresh(dir);
    CHECK(db);
    if (!db) return;
    OK(run("CREATE TABLE a (id BIGINT GENERATED ALWAYS AS IDENTITY (START WITH 100 INCREMENT BY 10) PRIMARY KEY, v TEXT)"));
    OK(run("CREATE TABLE b (id SERIAL PRIMARY KEY, k SMALLSERIAL, v TEXT)"));
    OK(run("CREATE SEQUENCE g START WITH 1000"));
    OK(run("CREATE TABLE c (id INT64 GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY, x BIGINT DEFAULT nextval('g'), v TEXT)"));
    CHECK(imdb_seq_by_name(db, "a_id_seq") && imdb_seq_by_name(db, "b_id_seq") && imdb_seq_by_name(db, "b_k_seq") &&
          imdb_seq_by_name(db, "c_id_seq"));
    OK(run("INSERT INTO a (v) VALUES ('x'), ('y')"));
    EXPECT("INSERT INTO a VALUES (1, 'z')", "ERR GENERATED ALWAYS AS IDENTITY");
    EXPECT("INSERT INTO a OVERRIDING SYSTEM VALUE VALUES (1, 'z')", "INSERT 1");
    EXPECT("INSERT INTO a OVERRIDING USER VALUE VALUES (7, 'w')", "INSERT 1"); /* the 7 goes, the sequence's comes */
    EXPECT("UPDATE a SET id = 5 WHERE v = 'x'", "ERR primary key");
    OK(run("CREATE TABLE e (k INT64 PRIMARY KEY, n BIGINT GENERATED ALWAYS AS IDENTITY)"));
    OK(run("INSERT INTO e (k) VALUES (1)"));
    EXPECT("UPDATE e SET n = 5", "ERR it is not updated");
    EXPECT("SELECT id, v FROM a ORDER BY id", "id,v\n1,\"z\"\n100,\"x\"\n110,\"y\"\n120,\"w\"\n");
    OK(run("INSERT INTO b DEFAULT VALUES"));
    OK(run("INSERT INTO b VALUES (DEFAULT, DEFAULT, 'two'), (50, DEFAULT, 'given')"));
    OK(run("INSERT INTO b (v) SELECT v FROM a WHERE id >= 110"));
    EXPECT("SELECT id, k, v FROM b ORDER BY id", "id,k,v\n1,1,\n2,2,\"two\"\n3,4,\"y\"\n4,5,\"w\"\n50,3,\"given\"\n");
    OK(run("INSERT INTO c (v) VALUES ('p')"));
    OK(run("INSERT INTO c VALUES (DEFAULT, 5, 'q')"));
    EXPECT("SELECT id, x, v FROM c ORDER BY id", "id,x,v\n1,1000,\"p\"\n2,5,\"q\"\n");
    EXPECT("SELECT currval('a_id_seq'), currval('b_k_seq'), lastval()", "currval('a_id_seq'),currval('b_k_seq'),lastval()\n120,5,2\n");
    /* cross_check: the statement's one plan hands out the values */
    OK(run("SET cross_check = on"));
    OK(run("INSERT INTO c (v) SELECT v FROM a"));
    OK(run("SET cross_check = off"));
    EXPECT("SELECT COUNT(*), MIN(id), MAX(id), MAX(x) FROM c", "count,min_id,max_id,max_x\n6,1,6,1004\n");
    /* the rules */
    EXPECT("ALTER TABLE a ALTER COLUMN id DROP DEFAULT", "ERR is an IDENTITY");
    EXPECT("ALTER TABLE a ALTER COLUMN id SET DEFAULT 5", "ERR is an IDENTITY");
    EXPECT("DROP SEQUENCE a_id_seq", "ERR takes its values from sequence a_id_seq");
    EXPECT("DROP SEQUENCE g", "ERR takes its values from sequence g");
    EXPECT("CREATE TABLE z (id TEXT GENERATED ALWAYS AS IDENTITY PRIMARY KEY)", "ERR an IDENTITY is SMALLINT, INTEGER or BIGINT");
    EXPECT("CREATE TABLE z (id INT64 PRIMARY KEY, n INT64 NULL GENERATED BY DEFAULT AS IDENTITY)", "ERR an IDENTITY is NOT NULL");
    OK(run("ALTER TABLE c ALTER COLUMN x DROP DEFAULT"));
    EXPECT("DROP SEQUENCE g", "DROP SEQUENCE g");
    OK(run("ALTER TABLE b DROP COLUMN k")); /* its sequence with it */
    CHECK(!imdb_seq_by_name(db, "b_k_seq"));
    OK(run("DROP TABLE a RETENTION 1 DAYS")); /* and a table's */
    CHECK(!imdb_seq_by_name(db, "a_id_seq"));
    OK(run("CREATE SEQUENCE a_id_seq")); /* its name free */
    OK(run("CHECKPOINT"));
    CHECK(verify_db(db) == 0);
    done(db);
    for (int pass = 0; pass < 2; pass++) {
        db = open_at(dir, pass == 1);
        CHECK(db);
        if (!db) return;
        char ins[64], want[64];
        snprintf(ins, sizeof ins, "INSERT INTO b (v) VALUES ('r%d')", pass);
        OK(run(ins));
        snprintf(want, sizeof want, "%d", 5 + pass);
        CHECK(!strcmp(one("SELECT MAX(id) FROM b WHERE id < 50"), want));
        CHECK(verify_db(db) == 0);
        done(db);
    }
    CHECK(audit_dir(dir) == 0);
}

/* every copy holds the sequences: a replica by the stream, one seeded past a RETIRE whose cut drops the CREATE's commit
 * (FLOOR's manifest), a backup's restore, a dump restored; each at the primary's digest and states, and each copy's
 * next value past every committed one when it writes (the restore and the dump's) */
static void t_seq_copies(void)
{
    const char *dir = test_tmpdir();
    char p[700], r[700], q[700], sf[700], kf[700], bk[700], dest[700];
    snprintf(p, sizeof p, "%s/p", dir);
    snprintf(r, sizeof r, "%s/r", dir);
    snprintf(q, sizeof q, "%s/q", dir);
    snprintf(sf, sizeof sf, "%s/stream", dir);
    snprintf(kf, sizeof kf, "%s/key", dir);
    snprintf(bk, sizeof bk, "%s/full.bak", dir);
    snprintf(dest, sizeof dest, "%s/restored", dir);
    imdb_err e = {0};
    CHECK(imdb_init(p, false, NULL, &e) == 0 && imdb_init(r, true, p, &e) == 0 && imdb_init(q, true, p, &e) == 0);
    imdb_open_opts o = {.sync = 0, .floor_stride = 1};
    imdb_db *db = NULL;
    if (imdb_open(p, &o, &db, &e)) return;
    imdb_session_init(&g_s, db);
    db->no_auto_retire = true;
    imdb_clock_freeze(1772953198ull * 1000000ull);
    OK(run("CREATE SEQUENCE s START WITH 5 INCREMENT BY 3"));
    OK(run("CREATE TABLE t (id BIGINT GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY, x BIGINT DEFAULT nextval('s'), v TEXT) "
           "RETENTION 10 SECONDS"));
    OK(run("INSERT INTO t (v) VALUES ('a'), ('b')"));
    OK(run("CHECKPOINT"));
    uint64_t first = db->seq + 1;
    OK(run("INSERT INTO t (v) VALUES ('c')"));
    OK(run("SELECT setval('s', 50)"));
    OK(run("CHECKPOINT"));
    uint64_t qseq = 0;
    OK(ship_to_file(p, qseq, sf, &g_e));
    imdb_db *qdb = NULL;
    CHECK(imdb_open(q, &o, &qdb, &e) == 0);
    if (qdb) {
        uint64_t qa = 0;
        OK(apply_file(qdb, sf, &qa, &g_e));
        qseq = qdb->seq;
        imdb_close(qdb);
    }
    imdb_clock_offset(15 * 1000000ll);
    OK(run("SELECT COUNT(*) FROM t"));
    imdb_err_clear(&g_e);
    OK(imdb_retire(db, first - 1, &g_e));
    OK(run("INSERT INTO t (v) VALUES ('d')"));
    EXPECT("SELECT id, x, v FROM t ORDER BY id", "id,x,v\n1,5,\"a\"\n2,8,\"b\"\n3,11,\"c\"\n4,53,\"d\"\n");
    uint8_t kid[32], key[IMDB_BACKUP_KEY_LEN];
    imdb_backup_info bi;
    OK(imdb_backup_key_create(kf, kid, &g_e));
    OK(imdb_backup_key_load(kf, key, &g_e));
    OK(imdb_backup_full(p, bk, key, &bi, &g_e));
    uint8_t dg[32];
    imdb_lthash_digest(db->meta.digest_alg, &db->global, dg);
    char *pd = dump_body(db);
    CHECK(pd && strstr(pd, "CREATE SEQUENCE s AS INT64 INCREMENT BY 3 MINVALUE 1 MAXVALUE 9223372036854775807 START WITH 5;\n") &&
          strstr(pd, "id INT64 PRIMARY KEY GENERATED BY DEFAULT AS IDENTITY (INCREMENT BY 1") &&
          strstr(pd, "x INT64 DEFAULT nextval('s')") && strstr(pd, "SELECT setval('s', 53, true);\n") &&
          strstr(pd, "SELECT setval('t_id_seq', 4, true);\n"));
    CHECK(verify_db(db) == 0);
    done(db);
    CHECK(audit_dir(p) == 0);
    imdb_db *copies[3] = {NULL, NULL, NULL};
    uint64_t qa = 0;
    OK(ship_to_file(p, qseq, sf, &g_e));
    if (imdb_open(q, &o, &copies[0], &e) == 0) OK(apply_file(copies[0], sf, &qa, &g_e));
    OK(ship_to_file(p, 0, sf, &g_e));
    imdb_db *rdb = NULL;
    CHECK(imdb_open(r, &o, &rdb, &e) == 0);
    if (rdb) {
        uint64_t ra = 0;
        OK(apply_file(rdb, sf, &ra, &g_e));
        uint64_t S = rdb->seeded;
        CHECK(S && rdb->failed);
        imdb_close(rdb);
        rdb = NULL;
        CHECK(imdb_open(r, &o, &rdb, &e) == 0);
        OK(ship_to_file(p, S, sf, &g_e));
        if (rdb) OK(apply_file(rdb, sf, &ra, &g_e));
        copies[1] = rdb;
    }
    const char *files[1] = {bk};
    imdb_backup_info ri;
    OK(imdb_restore(dest, key, files, 1, &ri, &g_e));
    CHECK(imdb_open(dest, &o, &copies[2], &e) == 0);
    const char *dirs[3] = {q, r, dest};
    for (int k = 0; k < 3; k++) {
        imdb_db *c = copies[k];
        CHECK(c);
        if (!c) continue;
        uint8_t cd[32];
        imdb_lthash_digest(c->meta.digest_alg, &c->global, cd);
        CHECK(memcmp(cd, dg, 32) == 0);
        imdb_sequence *cs = imdb_seq_by_name(c, "s"), *ct = imdb_seq_by_name(c, "t_id_seq");
        CHECK(cs && cs->last == 53 && cs->called && cs->base == 50 && ct && ct->last == 4 && ct->owner == 0);
        char *cdump = dump_body(c);
        CHECK(pd && cdump && !strcmp(pd, cdump));
        free(cdump);
        CHECK(verify_db(c) == 0);
        imdb_close(c);
        CHECK(audit_dir(dirs[k]) == 0);
    }
    free(pd);
}

/* the codec: ops 24 to 27 round trip; their places (SEQ_ADVANCEs last and by sequence, DROP alone, SEQ_SET beside no
 * row op) refused by the encoder and the decoder alike; a definition's rules; every bit of op 24 flipped: refused or
 * another commit that encodes to exactly those bytes; a manifest of version 9 refused by name */
static void t_seq_codec(void)
{
    imdb_seqdef d = {.id = 0, .width = 32, .inc = 2, .min = 1, .max = 100, .start = 5};
    snprintf(d.name, sizeof d.name, "sq");
    CHECK(imdb_seqdef_ok(&d));
    imdb_seqdef bad[5];
    for (int k = 0; k < 5; k++) bad[k] = d;
    bad[0].inc = 0;
    bad[1].min = 100;
    bad[2].start = 101;
    bad[3].width = 8;
    bad[4].max = (int64_t)INT32_MAX + 1;
    for (int k = 0; k < 5; k++) CHECK(!imdb_seqdef_ok(&bad[k]));
    imdb_op cs = {.code = IMDB_OP_CREATE_SEQUENCE, .sdef = &d, .seq = 0};
    imdb_op adv = {.code = IMDB_OP_SEQ_ADVANCE, .seq = 0, .sval = 7};
    imdb_op adv1 = {.code = IMDB_OP_SEQ_ADVANCE, .seq = 1, .sval = 9};
    imdb_op set = {.code = IMDB_OP_SEQ_SET, .seq = 0, .sval = 11, .scalled = 1};
    imdb_op drop = {.code = IMDB_OP_DROP_SEQUENCE, .seq = 0};
    imdb_op ret = {.code = IMDB_OP_SET_RETENTION, .table = 0, .retention_us = IMDB_RETAIN_DEFAULT_US};
    struct {
        imdb_op ops[3];
        uint32_t n;
        bool ok;
    } cases[] = {
        {{cs}, 1, true},          {{cs, adv}, 2, true},       {{adv, adv1}, 2, true},  {{set, adv}, 2, true},
        {{drop}, 1, true},        {{adv, cs}, 2, false},      {{adv1, adv}, 2, false}, {{adv, adv}, 2, false},
        {{drop, adv}, 2, false},  {{set, ret}, 2, false},     {{set, set}, 2, false},  {{cs, drop}, 2, false},
    };
    for (size_t i = 0; i < sizeof cases / sizeof *cases; i++) {
        imdb_commit_rec c = {.seq = 1, .alg = IMDB_DIGEST_ALG_LTHASH16, .ops = cases[i].ops, .nops = cases[i].n};
        imdb_buf b;
        imdb_buf_init(&b);
        imdb_commit_encode_header(&c, &b);
        CHECK((b.err == 0) == cases[i].ok);
        if (cases[i].ok && !b.err) {
            imdb_commit_rec dc;
            memset(&dc, 0, sizeof dc);
            OK(imdb_commit_decode_header(b.p, b.len, &dc, E));
            CHECK(dc.nops == cases[i].n && dc.ops[0].code == cases[i].ops[0].code && dc.ops[0].seq == cases[i].ops[0].seq &&
                  dc.ops[0].sval == cases[i].ops[0].sval);
            if (dc.ops[0].code == IMDB_OP_CREATE_SEQUENCE)
                CHECK(dc.ops[0].sdef && !strcmp(dc.ops[0].sdef->name, "sq") && dc.ops[0].sdef->inc == 2 &&
                      dc.ops[0].sdef->start == 5 && dc.ops[0].sdef->width == 32);
            imdb_commit_free(&dc);
        }
        imdb_buf_free(&b);
    }
    /* the decoder alike: SEQ_ADVANCE before CREATE, built by hand from two encodings */
    imdb_commit_rec c1 = {.seq = 1, .alg = IMDB_DIGEST_ALG_LTHASH16, .ops = &cs, .nops = 1};
    imdb_commit_rec c2 = {.seq = 1, .alg = IMDB_DIGEST_ALG_LTHASH16, .ops = &adv, .nops = 1};
    imdb_buf b1, b2, h;
    imdb_buf_init(&b1);
    imdb_buf_init(&b2);
    imdb_buf_init(&h);
    imdb_commit_encode_header(&c1, &b1);
    imdb_commit_encode_header(&c2, &b2);
    OK(imdb_buf_check(&b1, E));
    OK(imdb_buf_check(&b2, E));
    imdb_buf_put(&h, b1.p, 50);
    imdb_buf_put_u32(&h, 2);
    imdb_buf_put(&h, b2.p + 54, b2.len - 54 - 32); /* the ADVANCE */
    imdb_buf_put(&h, b1.p + 54, b1.len - 54 - 32); /* then the CREATE */
    imdb_buf_put(&h, b1.p + b1.len - 32, 32);
    OK(imdb_buf_check(&h, E));
    imdb_commit_rec dc;
    memset(&dc, 0, sizeof dc);
    imdb_err_clear(E);
    CHECK(imdb_commit_decode_header(h.p, h.len, &dc, E) == IMDB_ERR_CORRUPT && strstr(g_e.msg, "sequence ops out of their place"));
    imdb_commit_free(&dc);
    /* every bit of op 24's bytes */
    size_t lo = 54, hi = b1.len - 32;
    uint32_t refused = 0, other = 0;
    for (size_t i = lo; i < hi; i++)
        for (int bit = 0; bit < 8; bit++) {
            imdb_buf m;
            imdb_buf_init(&m);
            imdb_buf_put(&m, b1.p, b1.len);
            m.p[i] ^= (uint8_t)(1u << bit);
            memset(&dc, 0, sizeof dc);
            imdb_err e2 = {0};
            if (imdb_commit_decode_header(m.p, m.len, &dc, &e2)) {
                refused++;
            } else {
                imdb_buf re;
                imdb_buf_init(&re);
                imdb_commit_encode_header(&dc, &re);
                CHECK(!re.err && re.len == m.len && !memcmp(re.p, m.p, m.len));
                imdb_buf_free(&re);
                other++;
            }
            imdb_commit_free(&dc);
            imdb_buf_free(&m);
        }
    CHECK(refused > 0 && refused + other == (hi - lo) * 8);
    imdb_buf_free(&b1);
    imdb_buf_free(&b2);
    imdb_buf_free(&h);
    /* a manifest of version 9 (before sequences): refused by name */
    const char *dir = test_tmpdir();
    imdb_db *db = open_fresh(dir);
    CHECK(db);
    if (!db) return;
    OK(run("CREATE SEQUENCE s"));
    OK(run("CREATE TABLE t (id INT64 PRIMARY KEY)"));
    OK(run("CHECKPOINT"));
    char hex[65], path[900];
    imdb_hex(db->lake_manifest, 32, hex);
    snprintf(path, sizeof path, "%s/objects/%s.man", dir, hex);
    done(db);
    FILE *f = fopen(path, "rb");
    CHECK(f);
    if (!f) return;
    static uint8_t man[1 << 16];
    size_t mn = fread(man, 1, sizeof man, f);
    fclose(f);
    imdb_manifest m;
    CHECK(mn > 16 && imdb_manifest_parse(man, mn, &m, E) == 0 && m.nsq == 1 && !strcmp(m.sq[0].d.name, "s"));
    imdb_manifest_free(&m);
    man[8] = 9;
    imdb_err_clear(E);
    CHECK(imdb_manifest_parse(man, mn, &m, E) == IMDB_ERR_UNSUPPORTED && strstr(g_e.msg, "manifest version 9") &&
          strstr(g_e.msg, "sequences"));
}

/* the advisor's two states (16:4x): a ROLLBACK TO SAVEPOINT taken before a CREATE of an IDENTITY table whose sequence a
 * row then used (the sequence leaves the transaction's set with its undo: the commit logs no mark of it); and a sequence
 * published uncalled, then called once and published again (its manifest's state at the start, called) */
static void t_seq_states(void)
{
    const char *dir = test_tmpdir();
    imdb_db *db = open_fresh(dir);
    CHECK(db);
    if (!db) return;
    OK(run("CREATE SEQUENCE s"));
    OK(run("CREATE TABLE t (id INT64 PRIMARY KEY, v INT64)"));
    EXPECT("BEGIN", "BEGIN");
    EXPECT("CREATE SEQUENCE z", "ERR CREATE SEQUENCE commits on its own"); /* DDL, as CREATE TABLE is */
    OK(run("ROLLBACK"));
    /* the engine's: a savepoint before a CREATE SEQUENCE whose value the transaction took, restored */
    OK(imdb_begin(db, E));
    int64_t v = 0;
    OK(imdb_seq_next(db, imdb_seq_by_name(db, "s"), &v, E));
    imdb_savepoint sp = imdb_savepoint_take(db);
    imdb_seqdef qd = {.width = 0, .inc = 1, .min = 1, .max = 100, .start = 1};
    snprintf(qd.name, sizeof qd.name, "q_id_seq");
    OK(imdb_create_sequence(db, &qd, E));
    OK(imdb_seq_next(db, imdb_seq_by_name(db, "q_id_seq"), &v, E));
    CHECK(db->ntxseq == 2);
    imdb_savepoint_restore(db, sp);
    CHECK(db->ntxseq == 1 && db->txseq[0] == 0 && !imdb_seq_by_name(db, "q_id_seq") && db->nseqs == 1);
    OK(imdb_commit(db, E));
    OK(run("INSERT INTO t VALUES (nextval('s'), 2)"));
    OK(run("CREATE SEQUENCE u0 START WITH 4"));
    OK(run("CHECKPOINT")); /* u0 uncalled at the snapshot */
    CHECK(!strcmp(one("SELECT nextval('u0')"), "4"));
    OK(run("CHECKPOINT")); /* called at its start */
    CHECK(verify_db(db) == 0);
    done(db);
    for (int pass = 0; pass < 2; pass++) {
        db = open_at(dir, pass == 1);
        CHECK(db);
        if (!db) return;
        char want[8];
        snprintf(want, sizeof want, "%d", 5 + pass);
        CHECK(!strcmp(one("SELECT nextval('u0')"), want));
        snprintf(want, sizeof want, "%d", 3 + pass); /* 1 the savepoint's transaction's, 2 the INSERT's */
        CHECK(!strcmp(one("SELECT nextval('s')"), want));
        CHECK(!imdb_seq_by_name(db, "q_id_seq") && db->nseqs == 2);
        CHECK(verify_db(db) == 0);
        done(db);
    }
    CHECK(audit_dir(dir) == 0);
}

const test_case seq_tests[] = {
    {"seq_basic", t_seq_basic}, {"seq_txn", t_seq_txn},   {"seq_identity", t_seq_identity},
    {"seq_copies", t_seq_copies}, {"seq_codec", t_seq_codec}, {"seq_states", t_seq_states},
};
const size_t seq_ntests = sizeof seq_tests / sizeof *seq_tests;
