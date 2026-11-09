/* F2b-1: CHECK constraints (design.md section 5, CHECK constraints; docs/plan-p2.md 2026-11-09 18:0x). A column's or
 * a table's [CONSTRAINT name] CHECK (condition) in CREATE TABLE (op 28, right after the CREATE, its retention and its
 * DEFAULTs), ALTER TABLE ... ADD [CONSTRAINT name] CHECK (op 22 kind 11: every live row passes) and DROP CONSTRAINT
 * (kind 12). A row passes when its condition is TRUE or NULL; FALSE refuses the write, an evaluation's error is the
 * statement's. The engine binds each text alone by its own binder within a subset every verifier recomputes; the
 * auditor binds and evaluates it by its own (abind.c), and the differential here holds the two to one verdict on every
 * text of a corpus (fixed and drawn) and every row of a set at the types' edges. */
#include <stdlib.h>

#include "../../src/backup.h"
#include "../../src/db_internal.h"
#include "../../src/lake.h"
#include "../../src/log.h"
#include "../../src/sql.h"
#include "../../tools/audit/abind.h"
#include "thelp.h"

static imdb_session g_s;
static char g_out[1 << 16];

/* COPY FROM STDIN's data from memory */
typedef struct mem_in {
    const char *in;
    size_t inlen, inpos;
} mem_in;
static mem_in g_in;

static long mem_read(void *arg, char *buf, size_t cap)
{
    mem_in *m = arg;
    size_t k = m->inlen - m->inpos;
    if (k > cap) k = cap;
    if (k) memcpy(buf, m->in + m->inpos, k);
    m->inpos += k;
    return (long)k;
}

static int mem_write(void *arg, const char *b, size_t n)
{
    (void)arg;
    (void)b;
    (void)n;
    return 0;
}

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

/* ---- the statements: names (PostgreSQL's), the rules and every refusal ---- */
static void t_check_statements(void)
{
    const char *dir = test_tmpdir();
    imdb_db *db = open_fresh(dir);
    CHECK(db);
    if (!db) return;
    OK(run("CREATE TABLE t (id INT64 PRIMARY KEY, a INT64 CHECK (a > 0), b TEXT CONSTRAINT b_short CHECK (length(b) < 5), "
           "c INTEGER, CHECK (a < c), CHECK (c >= 0), CHECK (1 = 1), CHECK (c <> 7))"));
    imdb_table *t = imdb_table_by_name(db, "t");
    CHECK(t && t->hist.nchk == 6);
    if (t && t->hist.nchk == 6) { /* by name: one column's t_c_check, then a number past a taken one */
        const char *want[6] = {"b_short", "t_a_check", "t_c_check", "t_c_check1", "t_check", "t_check1"};
        for (int k = 0; k < 6; k++) CHECK(!strcmp(t->hist.chk[k].name, want[k]));
    }
    EXPECT("INSERT INTO t VALUES (1, 1, 'ab', 5)", "INSERT 1");
    EXPECT("INSERT INTO t VALUES (2, 0, 'ab', 5)", "ERR new row for table t violates check constraint t_a_check");
    EXPECT("INSERT INTO t VALUES (3, 9, 'ab', 5)", "ERR violates check constraint t_check"); /* a < c */
    EXPECT("INSERT INTO t VALUES (4, 1, 'abcdef', 5)", "ERR violates check constraint b_short");
    EXPECT("INSERT INTO t VALUES (5, NULL, NULL, NULL)", "INSERT 1"); /* NULL passes every one */
    EXPECT("INSERT INTO t VALUES (6, 1, 'a', 7)", "ERR violates check constraint t_c_check1");
    EXPECT("INSERT INTO t VALUES (6, 0, 'abcdef', -1)", "ERR violates check constraint b_short"); /* by name: the first */
    /* explicit names: one each; a generated name avoids those taken before it in the statement */
    /* with an IDENTITY and a DEFAULT: ops 24, 1, 16, 23 and 28 in one commit (op 28 after op 23, both decoders' rule) */
    OK(run("CREATE TABLE idc (id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY, a INT64 DEFAULT 5 CHECK (a > 0))"));
    EXPECT("INSERT INTO idc (a) VALUES (1)", "INSERT 1");
    EXPECT("INSERT INTO idc (a) VALUES (-1)", "ERR violates check constraint idc_a_check");
    EXPECT("INSERT INTO idc DEFAULT VALUES", "INSERT 1");
    EXPECT("SELECT id, a FROM idc ORDER BY id", "id,a\n1,1\n3,5\n"); /* 2 the failed row's: a gap */
    EXPECT("CREATE TABLE u (id INT64 PRIMARY KEY, CONSTRAINT x CHECK (id > 0), CONSTRAINT x CHECK (id < 9))",
           "ERR constraint x for table u already exists");
    EXPECT("CREATE TABLE u (id INT64 PRIMARY KEY CHECK (id > 0), CONSTRAINT u_id_check CHECK (id < 9))",
           "ERR constraint u_id_check for table u already exists");
    OK(run("CREATE TABLE u (id INT64 PRIMARY KEY, CONSTRAINT u_id_check CHECK (id < 9), CHECK (id > 0))"));
    imdb_table *u = imdb_table_by_name(db, "u");
    CHECK(u && u->hist.nchk == 2 && !strcmp(u->hist.chk[0].name, "u_id_check") && !strcmp(u->hist.chk[1].name, "u_id_check1"));
    /* a long table and column name: shortened, the longer first, to 63 bytes with the label */
    OK(run("CREATE TABLE abcdefghijabcdefghijabcdefghijabcdefghijabcdefghij (id INT64 PRIMARY KEY, "
           "klmnopqrstklmnopqrstklmnopqrstkl INT64 CHECK (klmnopqrstklmnopqrstklmnopqrstkl > 0))"));
    imdb_table *lt = imdb_table_by_name(db, "abcdefghijabcdefghijabcdefghijabcdefghijabcdefghij");
    CHECK(lt && lt->hist.nchk == 1 && strlen(lt->hist.chk[0].name) == 63 &&
          !strcmp(lt->hist.chk[0].name, "abcdefghijabcdefghijabcdefgh_klmnopqrstklmnopqrstklmnopqr_check"));
    /* the subset's refusals, each with its reason; the table is not made */
    EXPECT("CREATE TABLE v (id INT64 PRIMARY KEY, f FLOAT64 CHECK (f > 0))", "ERR FLOAT64");
    EXPECT("CREATE TABLE v (id INT64 PRIMARY KEY, a INT64 CHECK (a > 1.5e0))", "ERR literal");
    EXPECT("CREATE TABLE v (id INT64 PRIMARY KEY, a INT64 CHECK (a > (SELECT 1)))", "ERR no subquery");
    EXPECT("CREATE TABLE v (id INT64 PRIMARY KEY, a INT64 CHECK (a IN (SELECT 1)))", "ERR no subquery");
    EXPECT("CREATE TABLE v (id INT64 PRIMARY KEY, a TIMESTAMPTZ CHECK (a > now()))", "ERR a clock");
    EXPECT("CREATE TABLE v (id INT64 PRIMARY KEY, a DATE CHECK (a > CURRENT_DATE))", "ERR a clock");
    EXPECT("CREATE TABLE v (id INT64 PRIMARY KEY, a INT64 CHECK (a < nextval('s')))", "ERR ");
    EXPECT("CREATE TABLE v (id INT64 PRIMARY KEY, a INT64 CHECK (v.a > 0))", "ERR bare");
    EXPECT("CREATE TABLE v (id INT64 PRIMARY KEY, a INT64 CHECK (a))", "ERR its value a BOOL");
    EXPECT("CREATE TABLE v (id INT64 PRIMARY KEY, a TIMESTAMPTZ CHECK (a > '2020-01-01 00:00:00+00'))", "ERR TIMESTAMPTZ literal");
    EXPECT("CREATE TABLE v (id INT64 PRIMARY KEY, a INT64 CHECK (CAST(a AS TEXT) <> ''))", "ERR CAST");
    EXPECT("CREATE TABLE v (id INT64 PRIMARY KEY, a INT64 CHECK (COUNT(a) > 0))", "ERR ");
    EXPECT("CREATE TABLE v (id INT64 PRIMARY KEY, a INT64 CHECK (a > $1))", "ERR parameter");
    EXPECT("CREATE TABLE v (id INT64 PRIMARY KEY, a INT64 CHECK (b > 0))", "ERR no column b");
    EXPECT("CREATE TABLE v (id INT64 PRIMARY KEY, a INT64 CHECK (a > 0) NOT VALID)", "ERR NOT VALID");
    EXPECT("CREATE TABLE v (id INT64 PRIMARY KEY, a INT64 CHECK ())", "ERR no condition");
    EXPECT("CREATE TABLE v (id INT64 PRIMARY KEY, a TEXT CHECK (a > 1))", "ERR not converted");
    EXPECT("CREATE TABLE v (id INT64 PRIMARY KEY, a INT64 CHECK (round(a) > 0))", "ERR calls ABS");
    EXPECT("CREATE TABLE v (id INT64 PRIMARY KEY, a TEXT CHECK (a = NULL))", "ERR NULL cannot be an operand");
    CHECK(!imdb_table_by_name(db, "v"));
    /* the limits: 32 a table, 8 KiB of texts together */
    char big[16384];
    int o = snprintf(big, sizeof big, "CREATE TABLE w (id INT64 PRIMARY KEY");
    for (int k = 0; k < 33; k++) o += snprintf(big + o, sizeof big - (size_t)o, ", CHECK (id <> %d)", k);
    snprintf(big + o, sizeof big - (size_t)o, ")");
    EXPECT(big, "ERR at most 32 CHECK constraints");
    o = snprintf(big, sizeof big, "CREATE TABLE w (id INT64 PRIMARY KEY, CHECK (id IN (0");
    for (int k = 1; k < 2000; k++) o += snprintf(big + o, sizeof big - (size_t)o, ", %d", k);
    snprintf(big + o, sizeof big - (size_t)o, ")))");
    EXPECT(big, "ERR more than 8192 bytes");
    /* ALTER: ADD over the live rows, DROP CONSTRAINT, the RESTRICT of a rename and a drop of a named column */
    EXPECT("ALTER TABLE t ADD CHECK (c < 5)", "ERR check constraint t_c_check2 of table t is violated by some row");
    EXPECT("ALTER TABLE t ADD CONSTRAINT b_short CHECK (c < 50)", "ERR constraint b_short for table t already exists");
    EXPECT("ALTER TABLE t ADD CONSTRAINT c50 CHECK (c < 50)", "ALTER TABLE t");
    EXPECT("INSERT INTO t VALUES (7, 1, 'a', 60)", "ERR violates check constraint c50");
    EXPECT("ALTER TABLE t DROP CONSTRAINT c50", "ALTER TABLE t");
    EXPECT("INSERT INTO t VALUES (7, 1, 'a', 60)", "INSERT 1");
    EXPECT("ALTER TABLE t DROP CONSTRAINT c50", "ERR constraint c50 of table t does not exist");
    EXPECT("ALTER TABLE t RENAME COLUMN a TO aa", "ERR check constraint t_a_check names column a");
    EXPECT("ALTER TABLE t DROP COLUMN b", "ERR check constraint b_short names column b");
    EXPECT("ALTER TABLE t DROP CONSTRAINT b_short", "ALTER TABLE t");
    EXPECT("ALTER TABLE t DROP COLUMN b", "ALTER TABLE t"); /* the columns after it close up: the CHECKs bind again */
    EXPECT("INSERT INTO t VALUES (8, 2, 1)", "ERR violates check constraint t_check");
    EXPECT("INSERT INTO t VALUES (8, 1, 2)", "INSERT 1");
    EXPECT("ALTER TABLE t ADD COLUMN z INT64", "ALTER TABLE t");
    EXPECT("INSERT INTO t VALUES (9, 1, 2, 3)", "INSERT 1");
    EXPECT("ALTER TABLE t ADD CHECK (z IS NULL OR z > 2)", "ALTER TABLE t");
    EXPECT("INSERT INTO t VALUES (10, 1, 2, 1)", "ERR violates check constraint t_z_check");
    EXPECT("ALTER TABLE t ALTER COLUMN c TYPE BIGINT", "ALTER TABLE t"); /* a widening keeps every CHECK's type */
    EXPECT("SELECT id, a, c, z FROM t ORDER BY id", "id,a,c,z\n1,1,5,\n5,,,\n7,1,60,\n8,1,2,\n9,1,2,3\n");
    CHECK(verify_db(db) == 0);
    done(db);
    CHECK(audit_dir(dir) == 0);
}

/* every path that writes a row: INSERT, its SELECT form, UPDATE and its FROM form, ON CONFLICT's both sides, COPY, the
 * API; a statement refused whole (its earlier rows undone); an evaluation's error is the statement's */
static void t_check_writes(void)
{
    const char *dir = test_tmpdir();
    imdb_db *db = open_fresh(dir);
    CHECK(db);
    if (!db) return;
    OK(run("CREATE TABLE t (id INT64 PRIMARY KEY, q INT64 NOT NULL CHECK (q BETWEEN 0 AND 100), "
           "s TEXT CHECK (s LIKE 'k%'), d DECIMAL(6,2) CHECK (d * 2 < 1000), CHECK (q * 3037000500 > -1))"));
    OK(run("CREATE TABLE src (id INT64 PRIMARY KEY, q INT64)"));
    OK(run("INSERT INTO src VALUES (1, 5), (2, 500), (3, 50)"));
    EXPECT("INSERT INTO t VALUES (1, 10, 'k1', 1.5), (2, 101, 'k2', 1)", "ERR violates check constraint t_q_check");
    EXPECT("SELECT COUNT(*) FROM t", "count\n0\n"); /* the statement whole */
    EXPECT("INSERT INTO t (id, q) SELECT id, q FROM src", "ERR violates check constraint t_q_check");
    EXPECT("INSERT INTO t (id, q) SELECT id, q FROM src WHERE q < 100", "INSERT 2");
    EXPECT("UPDATE t SET q = q + 96", "ERR violates check constraint t_q_check"); /* 50 + 96 */
    EXPECT("UPDATE t SET q = q + 49", "UPDATE 2");
    EXPECT("UPDATE t SET s = 'x' WHERE id = 1", "ERR violates check constraint t_s_check");
    EXPECT("UPDATE t SET d = 500 WHERE id = 1", "ERR violates check constraint t_d_check");
    EXPECT("UPDATE t SET q = src.q FROM src WHERE t.id = src.id", "UPDATE 2"); /* 5 and 50 */
    OK(run("UPDATE src SET q = 200 WHERE id = 3"));
    EXPECT("UPDATE t SET q = src.q FROM src WHERE t.id = src.id", "ERR violates check constraint t_q_check");
    EXPECT("INSERT INTO t VALUES (1, 7, 'k', 1) ON CONFLICT (id) DO UPDATE SET q = 1000",
           "ERR violates check constraint t_q_check");
    EXPECT("INSERT INTO t VALUES (9, 700, 'k', 1) ON CONFLICT (id) DO NOTHING", "ERR violates check constraint t_q_check");
    /* the proposed row is checked before its conflict, whichever way it resolves (PostgreSQL's and SQLite's order) */
    EXPECT("INSERT INTO t VALUES (1, 700, 'k', 1) ON CONFLICT (id) DO UPDATE SET q = 8", "ERR violates check constraint t_q_check");
    EXPECT("INSERT INTO t VALUES (1, 700, 'k', 1) ON CONFLICT (id) DO NOTHING", "ERR violates check constraint t_q_check");
    EXPECT("INSERT INTO t VALUES (1, 7, 'x', 1) ON CONFLICT DO NOTHING", "ERR violates check constraint t_s_check");
    EXPECT("INSERT INTO t VALUES (1, 7, 'k', 1) ON CONFLICT (id) DO UPDATE SET q = 8", "INSERT 1");
    /* an evaluation's error, the statement's: q * 3037000500 past INT64 for q above 3037000499 cannot be written, and a
     * q in range never errs */
    EXPECT("SELECT id, q, s FROM t ORDER BY id", "id,q,s\n1,8,\n3,50,\n");
    /* the API's write is checked too */
    imdb_table *t = imdb_table_by_name(db, "t");
    CHECK(t);
    if (t) {
        imdb_value v[4] = {{.type = IMDB_T_INT64, .i = 20}, {.type = IMDB_T_INT64, .i = 200}, {.type = IMDB_T_TEXT, .null = true},
                           {.type = IMDB_T_DECIMAL, .scale = 2, .null = true}};
        imdb_err e = {0};
        OK(imdb_begin(db, &e));
        CHECK(imdb_insert(db, t, v, &e) == IMDB_ERR_CONSTRAINT && strstr(e.msg, "t_q_check"));
        v[1].i = 20;
        imdb_err_clear(&e);
        OK(imdb_insert(db, t, v, &e));
        OK(imdb_commit(db, &e));
    }
    /* COPY: a row refused stops the load, the rows before it undone */
    imdb_session_copy_io(&g_s, mem_read, mem_write, &g_in);
    g_in = (mem_in){"30,1,k,1.00\n31,500,k,1.00\n", 26, 0};
    EXPECT("COPY t FROM STDIN", "ERR violates check constraint t_q_check");
    g_in = (mem_in){"30,1,k,1.00\n31,5,k,1.00\n", 24, 0};
    EXPECT("COPY t FROM STDIN", "COPY 2");
    imdb_session_copy_io(&g_s, NULL, NULL, NULL);
    /* an evaluation's error is the statement's */
    OK(run("CREATE TABLE ov (id INT64 PRIMARY KEY, x INT64 CHECK (x * 2 <> 0))"));
    EXPECT("INSERT INTO ov VALUES (1, 9223372036854775807)", "ERR overflow");
    EXPECT("INSERT INTO ov VALUES (1, 4611686018427387903)", "INSERT 1");
    EXPECT("SELECT COUNT(*) FROM t", "count\n5\n");
    CHECK(verify_db(db) == 0);
    done(db);
    CHECK(audit_dir(dir) == 0);
}

/* the CHECKs survive what the table does: CHECKPOINTs, a snapshot open, a full replay, a reopen after an ALTER, a
 * replica by the stream, a backup's restore, the dump and its restore: each copy refuses what the primary refuses */
static void t_check_copies(void)
{
    const char *dir = test_tmpdir();
    char p[700], q[700], sf[700], kf[700], bk[700], dest[700], dd[700];
    snprintf(p, sizeof p, "%s/p", dir);
    snprintf(q, sizeof q, "%s/q", dir);
    snprintf(sf, sizeof sf, "%s/stream", dir);
    snprintf(kf, sizeof kf, "%s/key", dir);
    snprintf(bk, sizeof bk, "%s/full.bak", dir);
    snprintf(dest, sizeof dest, "%s/restored", dir);
    snprintf(dd, sizeof dd, "%s/dumped", dir);
    imdb_err e = {0};
    CHECK(imdb_init(p, false, NULL, &e) == 0 && imdb_init(q, true, p, &e) == 0);
    imdb_db *db = open_at(p, false);
    CHECK(db);
    if (!db) return;
    OK(run("CREATE TABLE t (id INT64 PRIMARY KEY, a INT64 CHECK (a >= 0), s TEXT, dt DATE, CONSTRAINT s_ok CHECK "
           "(s IS NULL OR s IN ('x', 'y', 'it''s')), CHECK (dt >= '2000-01-01'))"));
    OK(run("INSERT INTO t VALUES (1, 1, 'x', '2001-01-01'), (2, 2, 'it''s', NULL)"));
    OK(run("CHECKPOINT"));
    OK(run("ALTER TABLE t ADD CONSTRAINT a_small CHECK (a < 10)"));
    OK(run("INSERT INTO t VALUES (3, 3, NULL, '2000-01-01')"));
    OK(run("ALTER TABLE t DROP CONSTRAINT s_ok"));
    OK(run("INSERT INTO t VALUES (4, 4, 'zzz', NULL)"));
    OK(run("CHECKPOINT"));
    char *pd = dump_body(db);
    CHECK(pd && strstr(pd, "CONSTRAINT a_small CHECK (a < 10), CONSTRAINT t_a_check CHECK (a >= 0), "
                           "CONSTRAINT t_dt_check CHECK (dt >= '2000-01-01')) RETENTION"));
    uint8_t dg[32];
    imdb_lthash_digest(db->meta.digest_alg, &db->global, dg);
    uint8_t kid[32], key[IMDB_BACKUP_KEY_LEN];
    imdb_backup_info bi;
    OK(imdb_backup_key_create(kf, kid, &g_e));
    OK(imdb_backup_key_load(kf, key, &g_e));
    OK(imdb_backup_full(p, bk, key, &bi, &g_e));
    CHECK(verify_db(db) == 0);
    done(db);
    CHECK(audit_dir(p) == 0);
    /* a snapshot open, then a full replay: the same CHECKs, the same refusals */
    for (int pass = 0; pass < 2; pass++) {
        db = open_at(p, pass == 1);
        CHECK(db);
        if (!db) return;
        EXPECT("INSERT INTO t VALUES (10, 10, NULL, NULL)", "ERR violates check constraint a_small");
        EXPECT("INSERT INTO t VALUES (10, 10, NULL, '1999-12-31')", "ERR violates check constraint a_small"); /* the first by name */
        EXPECT("INSERT INTO t VALUES (10, 5, NULL, '1999-12-31')", "ERR violates check constraint t_dt_check");
        EXPECT("INSERT INTO t VALUES (10, 5, 'any', NULL)", "INSERT 1");
        EXPECT("DELETE FROM t WHERE id = 10", "DELETE 1");
        char *d1 = dump_body(db);
        const char *c0 = pd ? strstr(pd, "CREATE TABLE") : NULL, *c1 = d1 ? strstr(d1, "CREATE TABLE") : NULL;
        CHECK(c0 && c1 && !strncmp(c0, c1, (size_t)(strchr(c0, '\n') - c0) + 1));
        free(d1);
        CHECK(verify_db(db) == 0);
        done(db);
    }
    CHECK(audit_dir(p) == 0);
    /* a replica by the stream: the primary's digest and CHECKs */
    OK(ship_to_file(p, 0, sf, &g_e));
    imdb_open_opts o = {.sync = 0};
    imdb_db *qdb = NULL;
    CHECK(imdb_open(q, &o, &qdb, &e) == 0);
    if (qdb) {
        uint64_t qa = 0;
        OK(apply_file(qdb, sf, &qa, &g_e));
        imdb_table *qt = imdb_table_by_name(qdb, "t");
        CHECK(qt && qt->hist.nchk == 3 && !strcmp(qt->hist.chk[0].name, "a_small"));
        imdb_close(qdb);
    }
    CHECK(audit_dir(q) == 0);
    /* a backup's restore */
    const char *files[1] = {bk};
    imdb_backup_info ri;
    OK(imdb_restore(dest, key, files, 1, &ri, &g_e));
    imdb_db *rdb = NULL;
    CHECK(imdb_open(dest, &o, &rdb, &e) == 0);
    if (rdb) {
        uint8_t rd[32];
        imdb_lthash_digest(rdb->meta.digest_alg, &rdb->global, rd);
        CHECK(memcmp(rd, dg, 32) == 0);
        char *rdump = dump_body(rdb);
        CHECK(pd && rdump && !strcmp(pd, rdump));
        free(rdump);
        imdb_close(rdb);
    }
    /* the dump run into a fresh database: the same CREATE (CHECKs by name, texts as written) */
    db = open_fresh(dd);
    CHECK(db);
    if (db && pd) {
        char *line = strstr(pd, "CREATE TABLE t");
        char *nl = line ? strchr(line, '\n') : NULL;
        if (nl) {
            *nl = 0;
            OK(run(line));
            *nl = '\n';
        }
        char *d2 = dump_body(db);
        const char *c2 = d2 ? strstr(d2, "CREATE TABLE") : NULL;
        CHECK(line && c2 && !strncmp(line, c2, (size_t)(nl - line)));
        free(d2);
        EXPECT("INSERT INTO t VALUES (1, 11, NULL, NULL)", "ERR violates check constraint a_small");
        done(db);
    }
    free(pd);
}

/* 2026-03-08 06:59:58 UTC: the frozen clock (t_def's) */
#define T0_US (1772953198ull * 1000000ull)

/* past a cut: a RETIRE drops the log below the first CHECKPOINT, so op 28 and the ADD are gone and F's manifest is the
 * CHECKs' one source: VERIFY seeds its model from FLOOR, the auditor its own, a replica is seeded past the cut; each
 * holds the primary's live CHECKs, and the primary still refuses by them */
static void t_check_cut(void)
{
    const char *dir = test_tmpdir();
    char p[700], r[700], sf[700];
    snprintf(p, sizeof p, "%s/p", dir);
    snprintf(r, sizeof r, "%s/r", dir);
    snprintf(sf, sizeof sf, "%s/stream", dir);
    imdb_err e = {0};
    CHECK(imdb_init(p, false, NULL, &e) == 0 && imdb_init(r, true, p, &e) == 0);
    imdb_open_opts o = {.sync = 0, .floor_stride = 1};
    imdb_db *db = NULL;
    if (imdb_open(p, &o, &db, &e)) return;
    imdb_session_init(&g_s, db);
    db->no_auto_retire = true;
    imdb_clock_freeze(T0_US);
    OK(run("CREATE TABLE t (id INT64 PRIMARY KEY, a INT64 CHECK (a > 0), s TEXT, CONSTRAINT s_ok CHECK (s <> 'bad')) "
           "RETENTION 10 SECONDS"));
    OK(run("INSERT INTO t VALUES (1, 1, 'x'), (2, 2, NULL)"));
    OK(run("ALTER TABLE t ADD CONSTRAINT a_small CHECK (a < 100)"));
    OK(run("CHECKPOINT"));
    uint64_t first = db->seq + 1;
    OK(run("ALTER TABLE t DROP CONSTRAINT s_ok"));
    OK(run("UPDATE t SET s = 'bad' WHERE id = 2"));
    OK(run("CHECKPOINT"));
    imdb_clock_offset(15 * 1000000ll);
    OK(run("SELECT COUNT(*) FROM t")); /* the policy moves the horizon past the second CHECKPOINT */
    imdb_err_clear(&g_e);
    OK(imdb_retire(db, first - 1, &g_e));
    EXPECT("INSERT INTO t VALUES (3, 200, NULL)", "ERR violates check constraint a_small");
    EXPECT("INSERT INTO t VALUES (3, 0, NULL)", "ERR violates check constraint t_a_check");
    EXPECT("INSERT INTO t VALUES (3, 3, 'bad')", "INSERT 1");
    CHECK(db->log_floor > 0);
    CHECK(verify_db(db) == 0); /* from FLOOR */
    uint8_t dg[32];
    imdb_lthash_digest(db->meta.digest_alg, &db->global, dg);
    done(db);
    CHECK(audit_dir(p) == 0); /* its own floor seed */
    db = open_at(p, false); /* a snapshot open of a copy past its cut */
    CHECK(db);
    if (db) {
        EXPECT("INSERT INTO t VALUES (4, 400, NULL)", "ERR violates check constraint a_small");
        EXPECT("DELETE FROM t WHERE id = 3", "DELETE 1");
        imdb_lthash_digest(db->meta.digest_alg, &db->global, dg);
        done(db);
    }
    OK(ship_to_file(p, 0, sf, &g_e)); /* a replica seeded past the cut, then the commits after it */
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
    }
    if (rdb) {
        uint8_t rd[32];
        imdb_lthash_digest(rdb->meta.digest_alg, &rdb->global, rd);
        CHECK(memcmp(rd, dg, 32) == 0);
        imdb_table *rt = imdb_table_by_name(rdb, "t");
        CHECK(rt && rt->hist.nchk == 2 && !strcmp(rt->hist.chk[0].name, "a_small") && !strcmp(rt->hist.chk[1].name, "t_a_check"));
        imdb_close(rdb);
    }
    CHECK(audit_dir(r) == 0);
}

/* ---- the differential: the engine's binder and evaluator against the auditor's (abind.c), one verdict ---- */

typedef struct gen {
    uint64_t s;
    char *b;
    size_t n, cap;
} gen;

static uint32_t rnd(gen *g, uint32_t n)
{
    g->s ^= g->s << 13;
    g->s ^= g->s >> 7;
    g->s ^= g->s << 17;
    return (uint32_t)(g->s % n);
}

static void put(gen *g, const char *s)
{
    size_t l = strlen(s);
    if (g->n + l + 1 > g->cap) return;
    memcpy(g->b + g->n, s, l);
    g->n += l;
    g->b[g->n] = 0;
}

enum { G_NUM, G_TEXT, G_BOOL, G_DATE, G_TIME, G_TS, G_TZ, G_ANY };

static void g_expr(gen *g, int ty, int d);

static void g_atom(gen *g, int ty)
{
    static const char *num[] = {"i", "j", "d", "e", "0", "1", "-1", "7", "100", "9223372036854775807",
                                "-9223372036854775808", "3037000500", "1.5", "-0.25", "0.001", "99999999.99",
                                "12345678901234567890.123456789", "2", "-3", "0.5"};
    static const char *text[] = {"s", "v", "'a'", "''", "'abc'", "'ABC'", "'%'", "'k%'", "'_b%'", "'it''s'", "'\xc3\xa9'",
                                 "'a%b'", "'x\\y'", "'hello'"};
    static const char *bools[] = {"b", "TRUE", "FALSE"};
    static const char *dates[] = {"dt", "DATE '2000-01-01'", "'2020-02-29'", "'2021-02-29'", "DATE '0001-01-01'", "'9999-12-31'"};
    static const char *times[] = {"tm", "TIME '12:00:00'", "'23:59:59.999999'", "'24:00:00'", "TIME '00:00:00.5'"};
    static const char *tss[] = {"ts", "TIMESTAMP '2000-01-01 00:00:00'", "'2000-01-01'", "'2000-01-01T10:00:00Z'",
                                "'1999-13-01 00:00:00'"};
    static const char *tzs[] = {"tz", "'2000-01-01 00:00:00+00'", "TIMESTAMPTZ '2000-01-01 00:00:00+00'"};
    switch (ty) {
    case G_NUM: put(g, num[rnd(g, sizeof num / sizeof *num)]); return;
    case G_TEXT: put(g, text[rnd(g, sizeof text / sizeof *text)]); return;
    case G_BOOL: put(g, bools[rnd(g, sizeof bools / sizeof *bools)]); return;
    case G_DATE: put(g, dates[rnd(g, sizeof dates / sizeof *dates)]); return;
    case G_TIME: put(g, times[rnd(g, sizeof times / sizeof *times)]); return;
    case G_TS: put(g, tss[rnd(g, sizeof tss / sizeof *tss)]); return;
    case G_TZ: put(g, tzs[rnd(g, sizeof tzs / sizeof *tzs)]); return;
    default:
        if (!rnd(g, 6)) put(g, rnd(g, 2) ? "NULL" : "f");
        else g_atom(g, (int)rnd(g, G_ANY));
    }
}

/* a type, now and then another (the refusals are compared too) */
static int g_ty(gen *g, int ty) { return rnd(g, 12) ? ty : (int)rnd(g, G_ANY + 1); }

static void g_expr(gen *g, int ty, int d)
{
    if (d <= 0 || !rnd(g, 3)) {
        g_atom(g, ty);
        return;
    }
    switch (ty) {
    case G_NUM:
        switch (rnd(g, 9)) {
        case 0: {
            static const char *op[] = {" + ", " - ", " * ", " / ", " % "};
            put(g, "(");
            g_expr(g, g_ty(g, G_NUM), d - 1);
            put(g, op[rnd(g, 5)]);
            g_expr(g, g_ty(g, G_NUM), d - 1);
            put(g, ")");
            return;
        }
        case 1: put(g, "-"); g_expr(g, G_NUM, d - 1); return;
        case 2: put(g, "ABS("); g_expr(g, g_ty(g, G_NUM), d - 1); put(g, ")"); return;
        case 3: put(g, "LENGTH("); g_expr(g, g_ty(g, G_TEXT), d - 1); put(g, ")"); return;
        case 4: put(g, "(dt - "); g_expr(g, rnd(g, 2) ? G_DATE : G_NUM, d - 1); put(g, ")"); return;
        default: break;
        }
        break;
    case G_TEXT:
        switch (rnd(g, 5)) {
        case 0: g_expr(g, G_TEXT, d - 1); put(g, " || "); g_expr(g, g_ty(g, G_TEXT), d - 1); return;
        case 1: put(g, rnd(g, 2) ? "LOWER(" : "UPPER("); g_expr(g, g_ty(g, G_TEXT), d - 1); put(g, ")"); return;
        default: break;
        }
        break;
    case G_DATE:
        if (!rnd(g, 2)) {
            put(g, "(");
            g_expr(g, G_DATE, d - 1);
            put(g, rnd(g, 2) ? " + " : " - ");
            g_expr(g, g_ty(g, G_NUM), d - 1);
            put(g, ")");
            return;
        }
        break;
    case G_TS:
        if (!rnd(g, 3)) {
            put(g, "(dt + ");
            g_expr(g, g_ty(g, G_TIME), d - 1);
            put(g, ")");
            return;
        }
        break;
    case G_BOOL: {
        int t = (int)rnd(g, G_TZ + 1);
        switch (rnd(g, 11)) {
        case 0:
        case 1: {
            static const char *op[] = {" = ", " <> ", " < ", " <= ", " > ", " >= ", " != "};
            g_expr(g, t, d - 1);
            put(g, op[rnd(g, 7)]);
            g_expr(g, g_ty(g, t), d - 1);
            return;
        }
        case 2: put(g, "("); g_expr(g, G_BOOL, d - 1); put(g, rnd(g, 2) ? " AND " : " OR "); g_expr(g, G_BOOL, d - 1); put(g, ")"); return;
        case 3: put(g, "NOT "); g_expr(g, G_BOOL, d - 1); return;
        case 4: g_expr(g, g_ty(g, t), d - 1); put(g, rnd(g, 2) ? " IS NULL" : " IS NOT NULL"); return;
        case 5:
            g_expr(g, t, d - 1);
            put(g, rnd(g, 3) ? " BETWEEN " : " NOT BETWEEN ");
            g_expr(g, g_ty(g, t), d - 1);
            put(g, " AND ");
            g_expr(g, g_ty(g, t), d - 1);
            return;
        case 6: {
            g_expr(g, t, d - 1);
            put(g, rnd(g, 3) ? " IN (" : " NOT IN (");
            int n = 1 + (int)rnd(g, 4);
            for (int k = 0; k < n; k++) {
                if (k) put(g, ", ");
                if (!rnd(g, 6)) put(g, "NULL");
                else g_expr(g, g_ty(g, t), d - 1);
            }
            put(g, ")");
            return;
        }
        case 7:
            g_expr(g, g_ty(g, G_TEXT), d - 1);
            put(g, rnd(g, 3) ? " LIKE " : " NOT LIKE ");
            g_expr(g, g_ty(g, G_TEXT), d - 1);
            if (!rnd(g, 3)) put(g, rnd(g, 2) ? " ESCAPE '\\'" : " ESCAPE ''");
            return;
        default: break;
        }
        break;
    }
    default: break;
    }
    switch (rnd(g, 4)) { /* every type: CASE, COALESCE, NULLIF */
    case 0: {
        put(g, "CASE");
        bool simple = rnd(g, 2);
        int st = (int)rnd(g, G_TZ + 1);
        if (simple) {
            put(g, " ");
            g_expr(g, st, d - 1);
        }
        int n = 1 + (int)rnd(g, 3);
        for (int k = 0; k < n; k++) {
            put(g, " WHEN ");
            g_expr(g, simple ? g_ty(g, st) : G_BOOL, d - 1);
            put(g, " THEN ");
            if (!rnd(g, 6)) put(g, "NULL");
            else g_expr(g, g_ty(g, ty), d - 1);
        }
        if (rnd(g, 2)) {
            put(g, " ELSE ");
            g_expr(g, g_ty(g, ty), d - 1);
        }
        put(g, " END");
        return;
    }
    case 1: {
        put(g, "COALESCE(");
        int n = 1 + (int)rnd(g, 3);
        for (int k = 0; k < n; k++) {
            if (k) put(g, ", ");
            if (!rnd(g, 5)) put(g, "NULL");
            else g_expr(g, g_ty(g, ty), d - 1);
        }
        put(g, ")");
        return;
    }
    case 2:
        put(g, "NULLIF(");
        g_expr(g, ty, d - 1);
        put(g, ", ");
        if (!rnd(g, 5)) put(g, "NULL");
        else g_expr(g, g_ty(g, ty), d - 1);
        put(g, ")");
        return;
    default: g_atom(g, ty); return;
    }
}

/* the fixed corpus: every form at its edges, and the subset's refusals */
static const char *const kCorpus[] = {
    "i > 0", "i >= -9223372036854775808", "i * 2 > 0", "i * i >= 0", "i + 9223372036854775807 > 0", "-i > 0", "ABS(i) > 5",
    "i / 0 = 1", "i % 0 = 1", "i / -1 > 0", "i % -1 = 0", "(i - 1) * 3037000500 > 0", "j * 32767 > 0",
    "d > 0", "d * d > 1", "d / 3 > 0.333333", "d / 0.00 > 1", "d % 0.07 > 0", "d + e > 0", "e * e > 0", "e * 10 > e",
    "d = 1.5", "d = 1.50", "d <> 1.500000", "d > i", "e / 7 < 1", "d / 7 * 7 = d", "-d < 0", "ABS(d) <= 99999999.99",
    "e + 0.000000000000000000000000000001 > e", "e * 100000000000000000000 > 0", "e / 0.0000000001 > 0",
    "s = 'a'", "s < 'b'", "s >= ''", "s LIKE 'a%'", "s LIKE '_'", "s NOT LIKE '%b%'", "s LIKE '%\\%' ESCAPE '\\'",
    "s LIKE 'a\\' ESCAPE '\\'", "s LIKE 'a' ESCAPE 'ab'", "s LIKE 'x' ESCAPE ''", "s LIKE '\xc3\xa9'", "s LIKE '_'",
    "LENGTH(s) = 1", "LENGTH(s || v) > 3", "LOWER(s) = s", "UPPER(s) <> s", "s || 'x' = 'ax'", "v || s > s",
    "b", "NOT b", "b = TRUE", "b <> FALSE", "b < TRUE", "b IS NULL", "b IN (TRUE, NULL)", "b AND i > 0", "b OR i > 0",
    "dt > '2000-01-01'", "dt >= DATE '0001-01-01'", "dt - 1 > dt", "dt + 1 > dt", "dt - dt = 0", "dt + tm > ts",
    "dt + 2932896 > dt", "dt - 719162 < dt", "'2000-01-01' < dt", "dt BETWEEN '2000-01-01' AND '2030-12-31'",
    "'2000-01-01' BETWEEN dt AND '2030-12-31'", "dt IN ('2000-01-01', NULL, '2020-01-01')", "dt NOT IN ('2000-01-01')",
    "tm < '12:00:00'", "tm >= TIME '00:00:00'", "ts > '2000-01-01'", "ts > '2000-01-01T10:00:00Z'", "ts < TIMESTAMP '2000-01-01 00:00:00'",
    "tz > tz", "tz IS NULL", "tz = tz", "tz > '2000-01-01 00:00:00+00'",
    "CASE WHEN i > 0 THEN 1 ELSE 0 END = 1", "CASE i WHEN 1 THEN TRUE WHEN 2 THEN FALSE END",
    "CASE WHEN b THEN d ELSE i END > 1", "CASE dt WHEN '2000-01-01' THEN TRUE ELSE FALSE END", "CASE WHEN b THEN NULL END",
    "CASE WHEN b THEN NULL ELSE 1 END > 0", "CASE WHEN i > 0 THEN 'x' ELSE dt END IS NULL",
    "COALESCE(i, 0) >= 0", "COALESCE(d, i, 1) > 0", "COALESCE(NULL, s) = 'a'", "COALESCE(NULL, NULL) IS NULL",
    "COALESCE(dt, '2000-01-01') >= '2000-01-01'", "COALESCE(e, 99999999999999999999999999999999999999) > 0",
    "NULLIF(i, 0) > 0", "NULLIF(s, '') IS NOT NULL", "NULLIF(i, NULL) IS NULL", "NULLIF(NULL, 1) IS NULL", "NULLIF(d, i) > 0",
    "NULLIF(dt, '2000-01-01') IS NULL",
    "i IN (1, 2, NULL)", "i NOT IN (1, 2, NULL)", "i IN (1.5, 2)", "i IN ('a')", "i BETWEEN 1 AND NULL", "NULL IS NULL",
    "i = NULL", "s > 1", "i + s > 0", "s || 1 = 's'", "LENGTH(i) > 0", "ABS(s) > 0", "LOWER(i) = 'a'", "i AND b",
    "NOT i", "f > 0", "i > 1.5e0", "round(i) > 0", "now() > ts", "CURRENT_DATE > dt", "t.i > 0", "x > 0", "(SELECT 1) = 1",
    "EXISTS (SELECT 1)", "COUNT(i) > 0", "CAST(i AS TEXT) = '1'", "i > $1", "i", "s", "i > 0 AND", "i > 0)", "(i > 0",
    "i > 0; DROP TABLE t", "i > 0, i < 9", "dt > '2021-02-29'", "tm > '24:00:00'", "ts > '1999-13-01'", "i > 99999999999999999999",
    "d > 123456789012345678901234567890123456789", "d > 0.123456789012345678901234567890123456789", "-- a comment\ni > 0",
    "i > 0 -- a comment", "dt + tm > TIMESTAMP '9999-12-31 23:59:59'", "dt - 2932897 IS NULL", "dt * 2 > dt", "tm + 1 > tm",
};

static void ival(imdb_value *v, uint8_t t, uint8_t s, bool null, int64_t i, const char *txt)
{
    memset(v, 0, sizeof *v);
    v->type = t;
    v->scale = s;
    v->null = null;
    v->i = i;
    if (t == IMDB_T_TEXT && !null) {
        v->s = (const uint8_t *)txt;
        v->len = (uint32_t)strlen(txt);
    }
}

static void t_check_differential(void)
{
    const char *dir = test_tmpdir();
    imdb_db *db = open_fresh(dir);
    CHECK(db);
    if (!db) return;
    OK(run("CREATE TABLE t (id INT64 PRIMARY KEY, i INT64, j SMALLINT, d DECIMAL(10,2), e DECIMAL(18,0), s TEXT, "
           "v VARCHAR(10), b BOOL, dt DATE, tm TIME, ts TIMESTAMP, tz TIMESTAMPTZ, f FLOAT64)"));
    imdb_table *t = imdb_table_by_name(db, "t");
    CHECK(t);
    if (!t) {
        done(db);
        return;
    }
    const imdb_schema *s = &t->s;
    ab_col cols[IMDB_MAX_COLS];
    for (uint16_t c = 0; c < s->ncols; c++) {
        memset(&cols[c], 0, sizeof cols[c]);
        snprintf(cols[c].name, sizeof cols[c].name, "%s", s->cols[c].name);
        cols[c].type = s->cols[c].type;
        cols[c].scale = s->cols[c].type == IMDB_T_DECIMAL ? s->cols[c].scale : 0;
    }
    /* the rows: each column's edges, combined by strides so every pair meets; the first row every column NULL */
    static const int64_t VI[] = {0, 1, -1, 7, 100, INT64_MAX, INT64_MIN, 3037000500, -9};
    static const int64_t VJ[] = {0, 32767, -32768, 5};
    static const int64_t VD[] = {0, 150, -1, 9999999999LL, -9999999999LL, 5};
    static const int64_t VE[] = {0, 999999999999999999LL, -999999999999999999LL, 12};
    static const char *VS[] = {"", "a", "abc", "ABC", "\xc3\xa9", "100%", "_x", "it's", "a%b", "x\\y", "k1"};
    static const char *VV[] = {"", "hello", "H\xc3\x89"};
    static const int64_t VDT[] = {IMDB_DATE_MIN, IMDB_DATE_MAX, 0, 10957, 18262};
    static const int64_t VTM[] = {0, IMDB_TIME_MAX, 43200000000LL};
    static const int64_t VTS[] = {-62135596800000000LL, 253402300799999999LL, 0, 946684800000000LL};
    enum { NR = 48 };
    imdb_value *rows = calloc((size_t)NR * s->ncols, sizeof *rows);
    ab_val *arows = calloc((size_t)NR * s->ncols, sizeof *arows);
    CHECK(rows && arows);
    if (!rows || !arows) {
        free(rows);
        free(arows);
        done(db);
        return;
    }
    for (uint32_t r = 0; r < NR; r++) {
        imdb_value *v = rows + (size_t)r * s->ncols;
        bool nul = r == 0;
#define PICK(arr, k) arr[(r * (k)) % (sizeof arr / sizeof *arr)]
        ival(&v[0], IMDB_T_INT64, 0, false, r, NULL);
        ival(&v[1], IMDB_T_INT64, 0, nul || r % 7 == 3, PICK(VI, 1), NULL);
        ival(&v[2], IMDB_T_INT64, 0, nul || r % 11 == 5, PICK(VJ, 3), NULL);
        ival(&v[3], IMDB_T_DECIMAL, 2, nul || r % 9 == 4, PICK(VD, 5), NULL);
        ival(&v[4], IMDB_T_DECIMAL, 0, nul || r % 13 == 6, PICK(VE, 7), NULL);
        ival(&v[5], IMDB_T_TEXT, 0, nul || r % 8 == 7, 0, PICK(VS, 1));
        ival(&v[6], IMDB_T_TEXT, 0, nul || r % 5 == 2, 0, PICK(VV, 2));
        ival(&v[7], IMDB_T_BOOL, 0, nul || r % 6 == 1, r & 1, NULL);
        ival(&v[8], IMDB_T_DATE, 0, nul || r % 10 == 8, PICK(VDT, 3), NULL);
        ival(&v[9], IMDB_T_TIME, 0, nul || r % 4 == 3, PICK(VTM, 1), NULL);
        ival(&v[10], IMDB_T_TIMESTAMP, 0, nul || r % 9 == 7, PICK(VTS, 3), NULL);
        ival(&v[11], IMDB_T_TIMESTAMPTZ, 0, nul || r % 3 == 2, PICK(VTS, 1), NULL);
        ival(&v[12], IMDB_T_FLOAT64, 0, true, 0, NULL);
#undef PICK
        for (uint16_t c = 0; c < s->ncols; c++)
            arows[(size_t)r * s->ncols + c] = (ab_val){.i = v[c].i, .s = v[c].s, .len = v[c].len, .null = v[c].null};
    }
    char buf[4096];
    gen g = {0x9E3779B97F4A7C15ull, buf, 0, sizeof buf};
    unsigned ntext = 0, nbound = 0, nevals = 0, mism = 0, nfail = 0, nerr = 0;
    size_t nfixed = sizeof kCorpus / sizeof *kCorpus;
    int seeds = getenv("IMDB_CHECK_DRAWS") ? atoi(getenv("IMDB_CHECK_DRAWS")) : 6000;
    for (size_t k = 0; k < nfixed + (size_t)seeds && mism < 8; k++) {
        const char *text;
        if (k < nfixed) {
            text = kCorpus[k];
        } else {
            g.n = 0;
            buf[0] = 0;
            g_expr(&g, G_BOOL, 1 + (int)rnd(&g, 4));
            text = buf;
        }
        ntext++;
        uint32_t len = (uint32_t)strlen(text);
        int out[NR];
        imdb_err e = {0};
        int erc = imdb_check_eval_text(s, text, len, rows, NR, out, &e);
        ab_check *ac = NULL;
        char aerr[256];
        int arc = ab_check_bind(text, len, cols, s->ncols, &ac, aerr, sizeof aerr);
        if ((erc != 0) != (arc != 0)) {
            char m[1024];
            snprintf(m, sizeof m, "binding differs on: %s\n      engine: %s\n      auditor: %s", text, erc ? e.msg : "bound",
                     arc ? aerr : "bound");
            test_fail(__FILE__, __LINE__, m);
            mism++;
        }
        if (!erc && !arc) {
            nbound++;
            for (uint32_t r = 0; r < NR; r++) {
                char er[256];
                int av = ab_check_eval(ac, arows + (size_t)r * s->ncols, er, sizeof er);
                int ev = out[r] < 0 ? -1 : out[r];
                nevals++;
                nfail += ev == 0;
                nerr += ev < 0;
                if (av != ev) {
                    char m[1024];
                    snprintf(m, sizeof m, "verdict differs on row %u of: %s\n      engine %d, auditor %d (%s)", r, text, ev, av,
                             av < 0 ? er : "");
                    test_fail(__FILE__, __LINE__, m);
                    mism++;
                    break;
                }
            }
        }
        ab_check_free(ac);
    }
    /* the corpus reaches every verdict: bound and refused texts, rows passing, failing and erring */
    CHECK(nbound > ntext / 8 && nbound < ntext && nfail > 100 && nerr > 20 && nevals > nbound * (NR - 1));
    if (getenv("IMDB_CHECK_STATS"))
        fprintf(stderr, "check_differential: %u texts, %u bound, %u evaluations (%u FALSE, %u errors)\n", ntext, nbound,
                nevals, nfail, nerr);
    free(rows);
    free(arows);
    done(db);
}

/* ---- the codec: op 28 and op 22's kinds 11 and 12, their places, every bit of op 28 flipped; manifest 10 refused ---- */
static void t_check_codec(void)
{
    imdb_check c[2] = {{.name = "a_check", .len = 5, .text = "a > 0"}, {.name = "b", .len = 9, .text = "b <> 'x'"}};
    c[1].len = (uint32_t)strlen(c[1].text);
    imdb_schema s;
    memset(&s, 0, sizeof s);
    s.id = 0;
    snprintf(s.name, sizeof s.name, "t");
    s.ncols = 2;
    snprintf(s.cols[0].name, sizeof s.cols[0].name, "a");
    s.cols[0].type = IMDB_T_INT64;
    s.cols[0].flags = IMDB_COL_PK;
    snprintf(s.cols[1].name, sizeof s.cols[1].name, "b");
    s.cols[1].type = IMDB_T_TEXT;
    s.cols[1].flags = IMDB_COL_NULLABLE;
    s.subject = -1;
    s.npk = 1;
    s.key[0] = 0;
    imdb_op ops[3];
    memset(ops, 0, sizeof ops);
    ops[0].code = IMDB_OP_CREATE_TABLE;
    ops[0].schema = &s;
    ops[1].code = IMDB_OP_SET_RETENTION;
    ops[1].retention_us = IMDB_RETAIN_FOREVER;
    ops[2].code = IMDB_OP_TABLE_CHECKS;
    ops[2].chk = c;
    ops[2].nchk = 2;
    imdb_commit_rec rec;
    memset(&rec, 0, sizeof rec);
    rec.seq = 1;
    rec.alg = 2;
    rec.ops = ops;
    rec.nops = 3;
    imdb_buf b;
    imdb_buf_init(&b);
    imdb_commit_encode_header(&rec, &b);
    CHECK(!b.err);
    imdb_commit_rec d;
    memset(&d, 0, sizeof d);
    imdb_err_clear(&g_e);
    CHECK(imdb_commit_decode_header(b.p, b.len, &d, &g_e) == 0 && d.nops == 3 && d.ops[2].nchk == 2 &&
          !strcmp(d.ops[2].chk[1].name, "b") && d.ops[2].chk[1].len == c[1].len &&
          !memcmp(d.ops[2].chk[1].text, c[1].text, c[1].len));
    imdb_commit_free(&d);
    /* every bit flipped: refused, or another valid list (a name's letter, a text's byte: never a crash or a leak) */
    for (size_t bit = 0; bit < b.len * 8; bit++) {
        b.p[bit / 8] ^= (uint8_t)(1u << (bit % 8));
        imdb_commit_rec x;
        memset(&x, 0, sizeof x);
        imdb_err ex = {0};
        if (imdb_commit_decode_header(b.p, b.len, &x, &ex) == 0)
            for (uint32_t k = 0; k < x.nops; k++)
                if (x.ops[k].code == IMDB_OP_TABLE_CHECKS) CHECK(imdb_checks_ok(x.ops[k].chk, x.ops[k].nchk));
        imdb_commit_free(&x);
        b.p[bit / 8] ^= (uint8_t)(1u << (bit % 8));
    }
    /* its places: alone, before the retention, a list out of name order, twice the same name: refused by the encoder */
    imdb_op alone[1] = {ops[2]};
    rec.ops = alone;
    rec.nops = 1;
    b.len = 0;
    b.err = 0;
    imdb_commit_encode_header(&rec, &b);
    CHECK(b.err == IMDB_ERR_INVALID);
    imdb_check rev[2] = {c[1], c[0]};
    ops[2].chk = rev;
    rec.ops = ops;
    rec.nops = 3;
    b.len = 0;
    b.err = 0;
    imdb_commit_encode_header(&rec, &b);
    CHECK(b.err == IMDB_ERR_INVALID);
    imdb_check two[2] = {c[0], c[0]};
    ops[2].chk = two;
    b.len = 0;
    b.err = 0;
    imdb_commit_encode_header(&rec, &b);
    CHECK(b.err == IMDB_ERR_INVALID);
    /* op 22: ADD CHECK and DROP CHECK round trip; a text with a NUL refused */
    imdb_op a;
    memset(&a, 0, sizeof a);
    a.akind = IMDB_ALTER_ADD_CHECK;
    a.chk = c;
    a.nchk = 1;
    b.len = 0;
    b.err = 0;
    OK(imdb_alter_put(&b, &a));
    imdb_rd r;
    imdb_rd_init(&r, b.p, b.len);
    imdb_op g2;
    memset(&g2, 0, sizeof g2);
    imdb_err_clear(&g_e);
    CHECK(imdb_alter_get(&r, &g2, "commit", &g_e) == 0 && !r.err && !imdb_rd_left(&r) && g2.nchk == 1 &&
          !strcmp(g2.chk[0].name, "a_check") && g2.chk[0].len == 5);
    imdb_free(g2.chk);
    a.akind = IMDB_ALTER_DROP_CHECK;
    char nm[IMDB_MAX_IDENT + 1] = "a_check";
    a.aname = nm;
    b.len = 0;
    b.err = 0;
    OK(imdb_alter_put(&b, &a));
    imdb_rd_init(&r, b.p, b.len);
    memset(&g2, 0, sizeof g2);
    CHECK(imdb_alter_get(&r, &g2, "commit", &g_e) == 0 && !r.err && !imdb_rd_left(&r) && g2.aname && !strcmp(g2.aname, "a_check"));
    imdb_free(g2.aname);
    imdb_check nul = {.name = "n", .len = 3, .text = "a\0b"};
    a.akind = IMDB_ALTER_ADD_CHECK;
    a.chk = &nul;
    b.len = 0;
    b.err = 0;
    CHECK(imdb_alter_put(&b, &a) == IMDB_ERR_INVALID);
    imdb_buf_free(&b);
    /* a manifest of version 10, before CHECKs: refused by name */
    const char *dir = test_tmpdir();
    imdb_db *db = open_fresh(dir);
    CHECK(db);
    if (!db) return;
    OK(run("CREATE TABLE t (id INT64 PRIMARY KEY CHECK (id > 0))"));
    OK(run("INSERT INTO t VALUES (1)"));
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
    imdb_err_clear(&g_e);
    CHECK(mn > 16 && imdb_manifest_parse(man, mn, &m, &g_e) == 0 && m.nt == 1 && m.t[0].hist.nchk0 == 1 && m.t[0].hist.nchk == 1);
    if (mn > 16) imdb_manifest_free(&m);
    man[8] = 10;
    imdb_err_clear(&g_e);
    CHECK(imdb_manifest_parse(man, mn, &m, &g_e) == IMDB_ERR_UNSUPPORTED && strstr(g_e.msg, "manifest version 10") &&
          strstr(g_e.msg, "CHECK"));
}

const test_case check_tests[] = {
    {"check_statements", t_check_statements}, {"check_writes", t_check_writes},   {"check_copies", t_check_copies},
    {"check_differential", t_check_differential}, {"check_codec", t_check_codec}, {"check_cut", t_check_cut},
};
const size_t check_ntests = sizeof check_tests / sizeof *check_tests;
