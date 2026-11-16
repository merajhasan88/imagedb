/* F2c: generated columns (design.md section 5, Generated columns; docs/plan-p2.md 2026-11-09 19:4x). A column's
 * GENERATED ALWAYS AS (expression) STORED in CREATE TABLE (op 23 kind 9: its text as written, among the CREATE's
 * DEFAULTs). The expression is CHECK's subset bound alone against the table's columns, naming no generated column, its
 * value of a type its column takes; every write computes it once the row is otherwise whole (after the DEFAULTs and the
 * sequences, before the CHECKs and RETURNING) and assigns it by INSERT's rules, and the engine, replay and the auditor
 * each hold the row's stored value to what the expression gives. A write naming the column is refused (but VALUES'
 * DEFAULT); COPY and the dump leave it out both ways. The differential holds the engine's binder, evaluator and
 * assignment to the auditor's own (abind.c): one verdict of four (refused, an evaluation's error, an assignment's error,
 * a value) and the same value on every text of a corpus (fixed and drawn) and every row of a set at the types' edges. */
#include <stdlib.h>

#include "../../src/backup.h"
#include "../../src/db_internal.h"
#include "../../src/lake.h"
#include "../../src/log.h"
#include "../../src/sql.h"
#include "../../src/sql_internal.h"
#include "../../tools/audit/abind.h"
#include "thelp.h"

static imdb_session g_s;
static char g_out[1 << 16];

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

static char g_copy[1 << 14];
static size_t g_copyn;
static int mem_write(void *arg, const char *b, size_t n)
{
    (void)arg;
    if (g_copyn + n >= sizeof g_copy) return -1;
    memcpy(g_copy + g_copyn, b, n);
    g_copyn += n;
    g_copy[g_copyn] = 0;
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

#define GEN_T                                                                                                          \
    "CREATE TABLE g (id INT64 PRIMARY KEY, a INT64, b TEXT, w INT64 NOT NULL GENERATED ALWAYS AS (COALESCE(a, 0) * 2) " \
    "STORED, s VARCHAR(4) GENERATED ALWAYS AS (b || '!') STORED, d DECIMAL(9,2) GENERATED ALWAYS AS (a / 3.0) STORED, " \
    "q SMALLINT GENERATED ALWAYS AS (a + 1) STORED, CHECK (w < 1000))"

/* ---- the statements: the forms, every write path, the rules and every refusal ---- */
static void t_gen_statements(void)
{
    const char *dir = test_tmpdir();
    imdb_db *db = open_fresh(dir);
    CHECK(db);
    if (!db) return;
    /* CREATE TABLE's refusals */
    EXPECT("CREATE TABLE h (id INT64 PRIMARY KEY, w INT64 GENERATED ALWAYS AS (id) VIRTUAL)", "ERR VIRTUAL");
    EXPECT("CREATE TABLE h (id INT64 PRIMARY KEY, w INT64 GENERATED ALWAYS AS (id))", "ERR STORED");
    EXPECT("CREATE TABLE h (id INT64 GENERATED ALWAYS AS (1) STORED PRIMARY KEY)", "ERR key or SUBJECT");
    EXPECT("CREATE TABLE h (id INT64 PRIMARY KEY, w INT64 DEFAULT 1 GENERATED ALWAYS AS (id) STORED)", "ERR no DEFAULT or IDENTITY");
    EXPECT("CREATE TABLE h (id INT64 PRIMARY KEY, w INT64 GENERATED ALWAYS AS (v) STORED, v INT64 GENERATED ALWAYS AS (id) "
           "STORED)", "ERR names a generated column");
    EXPECT("CREATE TABLE h (id INT64 PRIMARY KEY, w INT64 GENERATED ALWAYS AS (w + 1) STORED)", "ERR names a generated column");
    EXPECT("CREATE TABLE h (id INT64 PRIMARY KEY, w TEXT GENERATED ALWAYS AS (id) STORED)", "ERR does not take");
    EXPECT("CREATE TABLE h (id INT64 PRIMARY KEY, w INT64 GENERATED ALWAYS AS (id * 1.5) STORED)", "ERR does not take");
    EXPECT("CREATE TABLE h (id INT64 PRIMARY KEY, w FLOAT64 GENERATED ALWAYS AS (1) STORED)", "ERR FLOAT64");
    EXPECT("CREATE TABLE h (id INT64 PRIMARY KEY, w TIMESTAMPTZ GENERATED ALWAYS AS (now()) STORED)", "ERR calls");
    EXPECT("CREATE TABLE h (id INT64 PRIMARY KEY, w INT64 GENERATED ALWAYS AS ((SELECT 1)) STORED)", "ERR reads its row alone");
    EXPECT("CREATE TABLE h (id INT64 PRIMARY KEY, w INT64 GENERATED ALWAYS AS (nextval('s')) STORED)", "ERR calls");
    EXPECT("CREATE TABLE h (id INT64 PRIMARY KEY, w INT64 GENERATED ALWAYS AS (x) STORED)", "ERR no column");
    EXPECT("CREATE TABLE h (id INT64 PRIMARY KEY, w INT64 GENERATED ALWAYS AS (id, id) STORED)", "ERR outside its parentheses");
    EXPECT("CREATE TABLE h (id INT64 PRIMARY KEY, w INT64 GENERATED ALWAYS AS () STORED)", "ERR empty");
    EXPECT("CREATE TABLE h (id INT64 PRIMARY KEY, w INT64 GENERATED ALWAYS AS ($1) STORED)", "ERR parameter");
    EXPECT("SELECT COUNT(*) FROM h", "ERR no table h");
    OK(run(GEN_T));
    /* INSERT: left out, DEFAULT, DEFAULT VALUES-like rows; a value refused, VALUES' DEFAULT alone taken */
    EXPECT("INSERT INTO g (id, a, b) VALUES (1, 5, 'x')", "INSERT 1");
    EXPECT("INSERT INTO g VALUES (2, 6, 'y', DEFAULT, DEFAULT, DEFAULT, DEFAULT)", "INSERT 1");
    EXPECT("INSERT INTO g (id) VALUES (3)", "INSERT 1");
    EXPECT("INSERT INTO g VALUES (4, 1, 'z', 2, DEFAULT, DEFAULT, DEFAULT)", "ERR column w is generated");
    EXPECT("INSERT INTO g (id, w) VALUES (4, 2)", "ERR column w is generated");
    EXPECT("INSERT INTO g (id, w) VALUES (4, DEFAULT)", "INSERT 1");
    EXPECT("INSERT INTO g SELECT * FROM g", "ERR column w is generated");
    EXPECT("INSERT INTO g (id, a, b) SELECT id + 10, a, b FROM g WHERE id < 3", "INSERT 2");
    EXPECT("SELECT * FROM g ORDER BY id", "id,a,b,w,s,d,q\n1,5,\"x\",10,\"x!\",1.67,6\n2,6,\"y\",12,\"y!\",2.00,7\n3,,,0,,,\n"
                                          "4,,,0,,,\n11,5,\"x\",10,\"x!\",1.67,6\n12,6,\"y\",12,\"y!\",2.00,7\n");
    /* the assignment's rules: a VARCHAR's length, a SMALLINT's range, a DECIMAL's precision and its rounding (half
     * away from zero, both signs); the CHECK reads the generated value; the statement whole */
    EXPECT("INSERT INTO g (id, b) VALUES (5, 'abcd')", "ERR longer than VARCHAR(4)");
    EXPECT("INSERT INTO g (id, a) VALUES (5, 32767)", "ERR SMALLINT");
    EXPECT("INSERT INTO g (id, a) VALUES (5, 3000000)", "ERR SMALLINT");
    EXPECT("INSERT INTO g (id, a) VALUES (5, 499)", "INSERT 1");
    EXPECT("INSERT INTO g (id, a) VALUES (6, 500)", "ERR violates check constraint g_w_check");
    EXPECT("INSERT INTO g (id, a) VALUES (6, 4611686018427387904)", "ERR overflow");
    EXPECT("INSERT INTO g (id, a) VALUES (6, -1), (7, 1), (8, 32767)", "ERR SMALLINT");
    EXPECT("SELECT id, d FROM g WHERE id BETWEEN 5 AND 8 ORDER BY id", "id,d\n5,166.33\n");
    EXPECT("INSERT INTO g (id, a) VALUES (6, -1), (7, 1)", "INSERT 2");
    EXPECT("SELECT id, w, d, q FROM g WHERE id IN (6, 7) ORDER BY id", "id,w,d,q\n6,-2,-0.33,0\n7,2,0.33,2\n");
    OK(run("CREATE TABLE r (id INT64 PRIMARY KEY, x DECIMAL(6,3), h DECIMAL(6,2) GENERATED ALWAYS AS (x) STORED)"));
    OK(run("INSERT INTO r (id, x) VALUES (1, 0.005), (2, -0.005), (3, 1.234), (4, -1.235), (5, 0.004)"));
    EXPECT("SELECT id, h FROM r ORDER BY id", "id,h\n1,0.01\n2,-0.01\n3,1.23\n4,-1.24\n5,0.00\n");
    /* UPDATE recomputes from the row as updated; SET of a generated column refused on every form */
    EXPECT("UPDATE g SET a = 10 WHERE id = 1", "UPDATE 1");
    EXPECT("UPDATE g SET w = 1", "ERR column w is generated");
    EXPECT("UPDATE g SET a = a + 1, b = 'q' WHERE id = 2 RETURNING w, s", "w,s\n14,\"q!\"\n");
    EXPECT("SELECT id, a, w, s, d, q FROM g WHERE id IN (1, 2) ORDER BY id", "id,a,w,s,d,q\n1,10,20,\"x!\",3.33,11\n2,7,14,\"q!\",2.33,8\n");
    EXPECT("UPDATE g SET b = 'long' WHERE id = 1", "ERR longer than VARCHAR(4)");
    EXPECT("UPDATE g SET a = 600 WHERE id = 1", "ERR violates check constraint g_w_check");
    /* ON CONFLICT DO UPDATE: the proposed row's and the updated row's */
    EXPECT("INSERT INTO g (id, a) VALUES (1, 3) ON CONFLICT (id) DO UPDATE SET a = EXCLUDED.a + 1 RETURNING id, a, w",
           "id,a,w\n1,4,8\n");
    EXPECT("INSERT INTO g (id, a) VALUES (1, 3) ON CONFLICT (id) DO UPDATE SET w = 1", "ERR column w is generated");
    EXPECT("INSERT INTO g (id, a) VALUES (50, 3) RETURNING w, q", "w,q\n6,4\n");
    /* UPDATE ... FROM and DELETE ... USING */
    OK(run("CREATE TABLE src (id INT64 PRIMARY KEY, v INT64)"));
    OK(run("INSERT INTO src VALUES (1, 40), (2, 41)"));
    EXPECT("UPDATE g SET a = src.v FROM src WHERE g.id = src.id", "UPDATE 2");
    EXPECT("SELECT id, w, q FROM g WHERE id IN (1, 2) ORDER BY id", "id,w,q\n1,80,41\n2,82,42\n");
    EXPECT("UPDATE g SET w = src.v FROM src WHERE g.id = src.id", "ERR column w is generated");
    /* COPY: the generated columns out of both directions without a list; a FROM list naming one refused */
    imdb_session_copy_io(&g_s, mem_read, mem_write, &g_in);
    g_in = (mem_in){"60,2,ab\n61,,\n", 13, 0};
    EXPECT("COPY g FROM STDIN", "COPY 2");
    g_in = (mem_in){"62,2\n", 5, 0};
    EXPECT("COPY g (id, w) FROM STDIN", "ERR column w is generated");
    g_in = (mem_in){"62,1,abcde\n", 11, 0};
    EXPECT("COPY g FROM STDIN", "ERR longer than VARCHAR(4)");
    g_copyn = 0;
    EXPECT("COPY (SELECT 1) TO STDOUT", "COPY 1");
    g_copyn = 0;
    EXPECT("COPY g TO STDOUT", "COPY 12");
    CHECK(strstr(g_copy, "60,2,ab\n") && strstr(g_copy, "61,,\n"));
    g_copyn = 0;
    EXPECT("COPY g (id, w, s) TO STDOUT", "COPY 12");
    CHECK(strstr(g_copy, "60,4,ab!\n") && strstr(g_copy, "61,0,\n"));
    imdb_session_copy_io(&g_s, NULL, NULL, NULL);
    /* ALTER: no DEFAULT on a generated column; RESTRICT for a column an expression names; the generated column itself
     * renamed, widened and dropped; a widening of a column it reads */
    EXPECT("ALTER TABLE g ALTER COLUMN w SET DEFAULT 3", "ERR takes no DEFAULT");
    EXPECT("ALTER TABLE g ALTER COLUMN w DROP DEFAULT", "ERR takes no DEFAULT");
    EXPECT("ALTER TABLE g ALTER COLUMN w SET DEFAULT CURRENT_DATE", "ERR column w");
    EXPECT("ALTER TABLE g DROP COLUMN a", "ERR generated column w names column a");
    EXPECT("ALTER TABLE g RENAME COLUMN b TO bb", "ERR generated column s names column b");
    EXPECT("ALTER TABLE g ADD COLUMN z INT64 GENERATED ALWAYS AS (id) STORED", "ERR ADD COLUMN ... GENERATED");
    EXPECT("ALTER TABLE g RENAME COLUMN s TO s2", "ALTER TABLE g");
    EXPECT("ALTER TABLE g ALTER COLUMN q TYPE INTEGER", "ALTER TABLE g");
    EXPECT("INSERT INTO g (id, a) VALUES (70, 32767)", "ERR violates check constraint g_w_check"); /* q fits now; w doesn't */
    EXPECT("ALTER TABLE g DROP CONSTRAINT g_w_check", "ALTER TABLE g");
    EXPECT("INSERT INTO g (id, a, b) VALUES (70, 32767, 'k')", "INSERT 1");
    EXPECT("SELECT w, s2, q FROM g WHERE id = 70", "w,s2,q\n65534,\"k!\",32768\n");
    EXPECT("ALTER TABLE g ALTER COLUMN d TYPE DECIMAL(12,2)", "ALTER TABLE g");
    EXPECT("ALTER TABLE g DROP COLUMN s2", "ALTER TABLE g");
    EXPECT("ALTER TABLE g RENAME COLUMN b TO bb", "ALTER TABLE g"); /* nothing names it now */
    EXPECT("INSERT INTO g (id, a, bb) VALUES (71, 1, 'longer than four')", "INSERT 1");
    EXPECT("ALTER TABLE g DROP COLUMN w", "ALTER TABLE g");
    EXPECT("ALTER TABLE g DROP COLUMN d", "ALTER TABLE g");
    EXPECT("ALTER TABLE g DROP COLUMN q", "ALTER TABLE g");
    EXPECT("ALTER TABLE g DROP COLUMN a", "ALTER TABLE g"); /* every generated column gone */
    EXPECT("INSERT INTO g VALUES (72, 'v')", "INSERT 1");
    EXPECT("UPDATE g SET bb = 'u' WHERE id = 72", "UPDATE 1");
    CHECK(verify_db(db) == 0);
    done(db);
    CHECK(audit_dir(dir) == 0);
}

/* ---- the API: the caller passes every generated column's value; another one is refused, at the write and the
 * replay ---- */
static void t_gen_api(void)
{
    const char *dir = test_tmpdir();
    imdb_db *db = open_fresh(dir);
    CHECK(db);
    if (!db) return;
    OK(run("CREATE TABLE t (id INT64 PRIMARY KEY, a INT64, s TEXT, w INT64 GENERATED ALWAYS AS (a * 3) STORED, "
           "u TEXT GENERATED ALWAYS AS (UPPER(s)) STORED)"));
    imdb_table *t = imdb_table_by_name(db, "t");
    CHECK(t);
    if (!t) {
        done(db);
        return;
    }
    imdb_value v[5] = {{.type = IMDB_T_INT64, .i = 1}, {.type = IMDB_T_INT64, .i = 4}, {.type = IMDB_T_TEXT, .s = (const uint8_t *)"ab", .len = 2},
                       {.type = IMDB_T_INT64, .i = 13}, {.type = IMDB_T_TEXT, .s = (const uint8_t *)"AB", .len = 2}};
    imdb_err e = {0};
    OK(imdb_begin(db, &e));
    CHECK(imdb_insert(db, t, v, &e) == IMDB_ERR_CONSTRAINT && strstr(e.msg, "generated column w"));
    v[3].i = 12;
    v[4].s = (const uint8_t *)"Ab";
    imdb_err_clear(&e);
    CHECK(imdb_insert(db, t, v, &e) == IMDB_ERR_CONSTRAINT && strstr(e.msg, "generated column u"));
    v[4].s = (const uint8_t *)"AB";
    imdb_err_clear(&e);
    OK(imdb_insert(db, t, v, &e));
    v[3].null = true; /* NULL where the expression gives 12 */
    v[0].i = 2;
    imdb_err_clear(&e);
    CHECK(imdb_insert(db, t, v, &e) == IMDB_ERR_CONSTRAINT);
    v[1].null = true; /* a NULL a: w NULL too */
    imdb_err_clear(&e);
    OK(imdb_insert(db, t, v, &e));
    OK(imdb_commit(db, &e));
    EXPECT("SELECT * FROM t ORDER BY id", "id,a,s,w,u\n1,4,\"ab\",12,\"AB\"\n2,,\"ab\",,\"AB\"\n");
    imdb_value k = {.type = IMDB_T_INT64, .i = 1};
    uint64_t vid = imdb_lookup_pk(db, t, &k, imdb_read_snapshot(db));
    CHECK(vid != IMDB_NONE);
    v[0].i = 1;
    v[1].null = false;
    v[1].i = 5;
    v[3].null = false;
    v[3].i = 12; /* a moved, w did not */
    OK(imdb_begin(db, &e));
    CHECK(imdb_update(db, t, vid, v, &e) == IMDB_ERR_CONSTRAINT);
    v[3].i = 15;
    imdb_err_clear(&e);
    OK(imdb_update(db, t, vid, v, &e));
    OK(imdb_commit(db, &e));
    CHECK(verify_db(db) == 0);
    done(db);
    CHECK(audit_dir(dir) == 0);
    db = open_at(dir, true); /* the replay holds each row to its expression too */
    CHECK(db);
    if (db) {
        EXPECT("SELECT * FROM t ORDER BY id", "id,a,s,w,u\n1,5,\"ab\",15,\"AB\"\n2,,\"ab\",,\"AB\"\n");
        done(db);
    }
}

/* ---- the copies: a CHECKPOINT and a snapshot open, a full replay, a replica by the stream, a backup's restore and the
 * dump run into a fresh database: each holds the primary's rows, digest and expressions, and computes as it does ---- */
static void t_gen_copies(void)
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
    OK(run("CREATE TABLE t (id INT64 PRIMARY KEY, a INTEGER, s TEXT, dt DATE, w INT64 GENERATED ALWAYS AS (a * 2 + id) STORED, "
           "x TEXT GENERATED ALWAYS AS (LOWER(s) || '-' || s) STORED, n DATE GENERATED ALWAYS AS (dt + 1) STORED, "
           "y BOOL GENERATED ALWAYS AS (a IS NULL OR a > 2) STORED)"));
    OK(run("INSERT INTO t (id, a, s, dt) VALUES (1, 1, 'Ab', '2001-01-01'), (2, NULL, 'it''s', NULL)"));
    OK(run("CHECKPOINT"));
    OK(run("UPDATE t SET a = 7 WHERE id = 1"));
    OK(run("INSERT INTO t (id, a, s, dt) VALUES (3, 3, NULL, '2024-02-28')"));
    OK(run("ALTER TABLE t ALTER COLUMN a TYPE BIGINT"));
    OK(run("CHECKPOINT"));
    OK(run("INSERT INTO t (id, a) VALUES (4, 0)"));
    const char *want = "id,a,s,dt,w,x,n,y\n1,7,\"Ab\",2001-01-01,15,\"ab-Ab\",2001-01-02,true\n2,,\"it's\",,,\"it's-it's\",,true\n"
                       "3,3,,2024-02-28,9,,2024-02-29,true\n4,0,,,4,,,false\n";
    EXPECT("SELECT * FROM t ORDER BY id", want);
    char *pd = dump_body(db);
    CHECK(pd && strstr(pd, "w INT64 GENERATED ALWAYS AS (a * 2 + id) STORED") &&
          strstr(pd, "x TEXT GENERATED ALWAYS AS (LOWER(s) || '-' || s) STORED") && strstr(pd, "COPY t FROM STDIN") &&
          strstr(pd, "\n1,7,Ab,2001-01-01\n"));
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
    for (int pass = 0; pass < 2; pass++) { /* a snapshot open, then a full replay */
        db = open_at(p, pass == 1);
        CHECK(db);
        if (!db) return;
        EXPECT("SELECT * FROM t ORDER BY id", want);
        EXPECT("INSERT INTO t (id, a, s) VALUES (9, 1, 'Q') RETURNING w, x, y", "w,x,y\n11,\"q-Q\",false\n");
        EXPECT("INSERT INTO t (id, w) VALUES (10, 1)", "ERR column w is generated");
        EXPECT("DELETE FROM t WHERE id = 9", "DELETE 1");
        char *d1 = dump_body(db);
        CHECK(pd && d1 && !strcmp(pd, d1));
        free(d1);
        CHECK(verify_db(db) == 0);
        done(db);
    }
    CHECK(audit_dir(p) == 0);
    OK(ship_to_file(p, 0, sf, &g_e)); /* a replica: the primary's digest and expressions */
    imdb_open_opts o = {.sync = 0};
    imdb_db *qdb = NULL;
    CHECK(imdb_open(q, &o, &qdb, &e) == 0);
    if (qdb) {
        uint64_t qa = 0;
        OK(apply_file(qdb, sf, &qa, &g_e));
        imdb_table *qt = imdb_table_by_name(qdb, "t");
        CHECK(qt && qt->hist.ngen == 4 && imdb_col_generated(qt, 4) && !imdb_col_generated(qt, 3));
        uint8_t qd[32];
        imdb_lthash_digest(qdb->meta.digest_alg, &qdb->global, qd);
        imdb_close(qdb);
    }
    CHECK(audit_dir(q) == 0);
    const char *files[1] = {bk}; /* a backup's restore */
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
    CHECK(audit_dir(dest) == 0);
    /* the dump run into a fresh database: the same CREATE, the rows computed again, the same dump */
    db = open_fresh(dd);
    CHECK(db);
    if (db && pd) {
        imdb_result r;
        imdb_err_clear(&g_e);
        imdb_session_copy_io(&g_s, mem_read, mem_write, &g_in);
        const char *create = strstr(pd, "CREATE TABLE t");
        const char *cnl = create ? strchr(create, '\n') : NULL;
        const char *copy = strstr(pd, "COPY t FROM STDIN");
        const char *data = copy ? strchr(copy, '\n') : NULL;
        const char *end = data ? strstr(data, "\\.\n") : NULL;
        CHECK(create && cnl && copy && data && end);
        if (create && cnl && copy && data && end) {
            OK(imdb_exec_one(&g_s, create, (size_t)(cnl - create), NULL, 0, &r, &g_e));
            imdb_result_free(&r);
            g_in = (mem_in){data + 1, (size_t)(end - data - 1), 0};
            OK(imdb_exec_one(&g_s, copy, (size_t)(data - copy), NULL, 0, &r, &g_e));
            imdb_result_free(&r);
        }
        imdb_session_copy_io(&g_s, NULL, NULL, NULL);
        EXPECT("SELECT * FROM t ORDER BY id", want);
        char *d2 = dump_body(db);
        CHECK(d2 && !strcmp(pd, d2));
        free(d2);
        done(db);
        CHECK(audit_dir(dd) == 0);
    } else if (db) {
        done(db);
    }
    free(pd);
}

/* 2026-03-08 06:59:58 UTC: the frozen clock (t_def's, t_check's) */
#define T0_US (1772953198ull * 1000000ull)

/* past a cut: a RETIRE drops the log below the second CHECKPOINT, so op 23 is gone and F's manifest is the expressions'
 * one source: VERIFY seeds its model from FLOOR, the auditor its own, a snapshot open and a replica seeded past the cut
 * each hold the primary's expressions, compute as it does and refuse what it refuses */
static void t_gen_cut(void)
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
    OK(run("CREATE TABLE t (id INT64 PRIMARY KEY, a INT64, s TEXT, w INT64 GENERATED ALWAYS AS (a * 3) STORED, "
           "u VARCHAR(5) GENERATED ALWAYS AS (s || '!') STORED) RETENTION 10 SECONDS"));
    OK(run("INSERT INTO t (id, a, s) VALUES (1, 1, 'x'), (2, 2, NULL)"));
    OK(run("CHECKPOINT"));
    uint64_t first = db->seq + 1;
    OK(run("UPDATE t SET a = 7, s = 'yy' WHERE id = 2"));
    OK(run("ALTER TABLE t RENAME COLUMN u TO shout"));
    OK(run("CHECKPOINT"));
    imdb_clock_offset(15 * 1000000ll);
    OK(run("SELECT COUNT(*) FROM t")); /* the policy moves the horizon past the second CHECKPOINT */
    imdb_err_clear(&g_e);
    OK(imdb_retire(db, first - 1, &g_e));
    CHECK(db->log_floor > 0);
    EXPECT("INSERT INTO t (id, a, s) VALUES (3, 4, 'zzzzz')", "ERR longer than VARCHAR(5)");
    EXPECT("INSERT INTO t (id, a, s, w) VALUES (3, 4, 'z', 12)", "ERR column w is generated");
    EXPECT("INSERT INTO t (id, a, s) VALUES (3, 4, 'z') RETURNING w, shout", "w,shout\n12,\"z!\"\n");
    CHECK(verify_db(db) == 0); /* from FLOOR */
    uint8_t dg[32];
    imdb_lthash_digest(db->meta.digest_alg, &db->global, dg);
    done(db);
    CHECK(audit_dir(p) == 0); /* its own floor seed */
    db = open_at(p, false); /* a snapshot open of a copy past its cut */
    CHECK(db);
    if (db) {
        EXPECT("SELECT id, w, shout FROM t ORDER BY id", "id,w,shout\n1,3,\"x!\"\n2,21,\"yy!\"\n3,12,\"z!\"\n");
        EXPECT("UPDATE t SET a = 5 WHERE id = 1 RETURNING w", "w\n15\n");
        EXPECT("DELETE FROM t WHERE id = 3", "DELETE 1");
        imdb_lthash_digest(db->meta.digest_alg, &db->global, dg);
        CHECK(verify_db(db) == 0);
        done(db);
    }
    CHECK(audit_dir(p) == 0);
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
        CHECK(rt && rt->hist.ngen == 2 && imdb_col_generated(rt, 3) && imdb_col_generated(rt, 4) && !imdb_col_generated(rt, 2));
        imdb_close(rdb);
    }
    CHECK(audit_dir(r) == 0);
}

/* ---- the differential: the engine's binder, evaluator and assignment against the auditor's (abind.c) ---- */

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
    static const char *num[] = {"i", "j", "d", "e", "0", "1", "-1", "7", "100", "9223372036854775807", "-9223372036854775808",
                                "3037000500", "1.5", "-0.25", "0.005", "-0.005", "99999999.995", "0.5", "2", "-3", "32767", "0.125", "w", "w",
                                "99999999999999999999999999999999.999999", "18446744073709551616", "-18446744073709551616.005"}; /* F3e */
    static const char *text[] = {"s", "v", "'a'", "''", "'abc'", "'ABC'", "'it''s'", "'\xc3\xa9'", "'hello'", "'\xc3\xa9\xc3\xa9\xc3\xa9\xc3\xa9'"};
    static const char *bools[] = {"b", "TRUE", "FALSE"};
    static const char *dates[] = {"dt", "DATE '2000-01-01'", "DATE '0001-01-01'", "DATE '9999-12-31'"};
    static const char *times[] = {"tm", "TIME '12:00:00'", "TIME '00:00:00.5'"};
    static const char *tss[] = {"ts", "TIMESTAMP '2000-01-01 00:00:00'"};
    static const char *tzs[] = {"tz"};
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

static int g_ty(gen *g, int ty) { return rnd(g, 14) ? ty : (int)rnd(g, G_ANY + 1); }

static void g_expr(gen *g, int ty, int d)
{
    if (d <= 0 || !rnd(g, 3)) {
        g_atom(g, ty);
        return;
    }
    switch (ty) {
    case G_NUM:
        switch (rnd(g, 8)) {
        case 0:
        case 1: {
            static const char *op[] = {" + ", " - ", " * ", " / ", " % "};
            put(g, "(");
            g_expr(g, g_ty(g, G_NUM), d - 1);
            put(g, op[rnd(g, 5)]);
            g_expr(g, g_ty(g, G_NUM), d - 1);
            put(g, ")");
            return;
        }
        case 2: put(g, "-"); g_expr(g, G_NUM, d - 1); return;
        case 3: put(g, "ABS("); g_expr(g, g_ty(g, G_NUM), d - 1); put(g, ")"); return;
        case 4: put(g, "LENGTH("); g_expr(g, g_ty(g, G_TEXT), d - 1); put(g, ")"); return;
        case 5: put(g, "(dt - "); g_expr(g, rnd(g, 2) ? G_DATE : G_NUM, d - 1); put(g, ")"); return;
        default: break;
        }
        break;
    case G_TEXT:
        switch (rnd(g, 4)) {
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
        if (!rnd(g, 2)) {
            put(g, "(dt + ");
            g_expr(g, g_ty(g, G_TIME), d - 1);
            put(g, ")");
            return;
        }
        break;
    case G_BOOL: {
        int t = (int)rnd(g, G_TZ + 1);
        switch (rnd(g, 6)) {
        case 0:
        case 1: {
            static const char *op[] = {" = ", " <> ", " < ", " <= ", " > ", " >= "};
            g_expr(g, t, d - 1);
            put(g, op[rnd(g, 6)]);
            g_expr(g, g_ty(g, t), d - 1);
            return;
        }
        case 2: put(g, "("); g_expr(g, G_BOOL, d - 1); put(g, rnd(g, 2) ? " AND " : " OR "); g_expr(g, G_BOOL, d - 1); put(g, ")"); return;
        case 3: g_expr(g, g_ty(g, t), d - 1); put(g, rnd(g, 2) ? " IS NULL" : " IS NOT NULL"); return;
        default: break;
        }
        break;
    }
    default: break;
    }
    switch (rnd(g, 4)) { /* every type: CASE, COALESCE, NULLIF */
    case 0: {
        put(g, "CASE");
        int n = 1 + (int)rnd(g, 2);
        for (int k = 0; k < n; k++) {
            put(g, " WHEN ");
            g_expr(g, G_BOOL, d - 1);
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
        g_expr(g, g_ty(g, ty), d - 1);
        put(g, ")");
        return;
    default: g_atom(g, ty); return;
    }
}

/* the schema's sources (id 0 to f 12) and its targets (13 on), which no expression names */
/* F3e: gw DECIMAL(38,6) and gx DECIMAL(20,2), wide targets, and w DECIMAL(38,6), a source after them (no target names it) */
enum { C_GI = 13, C_GN, C_GJ, C_GD, C_GE, C_GS, C_GV, C_GB, C_GDT, C_GTM, C_GTS, C_GTZ, C_GW, C_GX, C_W, C_NCOLS };

/* the fixed corpus: each by its target; the assignment's rules at their edges, then the refusals */
static const struct {
    int col;
    const char *text;
} kCorpus[] = {
    {C_GI, "i"}, {C_GI, "COALESCE(i, 0)"}, {C_GN, "i"}, {C_GJ, "i"}, {C_GJ, "j"}, {C_GJ, "j + 1"}, {C_GJ, "-j"},
    {C_GI, "i * 2"}, {C_GI, "i / 0"}, {C_GI, "j * 32767 * 32767"}, {C_GI, "LENGTH(s)"}, {C_GI, "dt - DATE '2000-01-01'"},
    {C_GD, "d"}, {C_GD, "e"}, {C_GD, "d * 0.5"}, {C_GD, "-d * 0.5"}, {C_GD, "d / 3"}, {C_GD, "i"}, {C_GD, "j / 7.0"},
    {C_GD, "0.005"}, {C_GD, "-0.005"}, {C_GD, "0.004999"}, {C_GD, "99999999.995"}, {C_GD, "-99999999.995"},
    {C_GD, "99999999.994"}, {C_GE, "d * 0.5"}, {C_GE, "e"}, {C_GE, "j"}, {C_GE, "0.05"}, {C_GE, "-0.05"}, {C_GE, "999.95"},
    {C_GE, "-999.94"}, {C_GD, "d + e"}, {C_GD, "e * 100000000000000000000"}, {C_GD, "CASE WHEN b THEN d ELSE i END"},
    {C_GS, "s"}, {C_GS, "s || v"}, {C_GS, "UPPER(s)"}, {C_GS, "LOWER(v) || '!'"}, {C_GS, "''"}, {C_GV, "v"}, {C_GV, "s"},
    {C_GV, "s || s"}, {C_GV, "'\xc3\xa9\xc3\xa9\xc3\xa9\xc3\xa9'"}, {C_GV, "'abcde'"}, {C_GV, "NULLIF(s, '')"},
    {C_GB, "b"}, {C_GB, "i > 0"}, {C_GB, "s LIKE 'a%'"}, {C_GB, "b AND i > 0"}, {C_GB, "i IN (1, 7, NULL)"},
    {C_GDT, "dt"}, {C_GDT, "dt + 1"}, {C_GDT, "dt - 1"}, {C_GDT, "COALESCE(dt, DATE '2000-01-01')"}, {C_GTM, "tm"},
    {C_GTS, "ts"}, {C_GTS, "dt + tm"}, {C_GTZ, "tz"}, {C_GTS, "COALESCE(ts, dt + tm)"},
    /* the refusals: a type the column does not take, a generated column named, outside the subset */
    {C_GI, "d"}, {C_GI, "1.5"}, {C_GI, "s"}, {C_GS, "i"}, {C_GB, "i"}, {C_GDT, "ts"}, {C_GTS, "dt"}, {C_GTZ, "ts"},
    {C_GDT, "'2000-01-01'"}, {C_GTZ, "'2000-01-01 00:00:00+00'"}, {C_GI, "NULL"}, {C_GI, "gn"}, {C_GI, "gi + 1"},
    {C_GI, "f"}, {C_GI, "now()"}, {C_GI, "(SELECT 1)"}, {C_GI, "COUNT(i)"}, {C_GI, "CAST(i AS INT64)"}, {C_GI, "t.i"},
    {C_GI, "i, j"}, {C_GI, "i)"}, {C_GI, "$1"}, {C_GI, "x"},
    /* F3e: into a wide target from wide, narrow and integer sources; a wide source into narrower targets (rounded half
     * away from zero, refused past their digits, never cut to 64 bits); literals past 18 digits */
    {C_GW, "w"}, {C_GW, "w * 2"}, {C_GW, "w + d"}, {C_GW, "e"}, {C_GW, "d * 0.5"}, {C_GW, "i"}, {C_GW, "-w"},
    {C_GW, "w / 3"}, {C_GW, "w * 0.0000001"}, {C_GW, "99999999999999999999999999999999.999999"},
    {C_GW, "100000000000000000000000000000000"}, {C_GW, "18446744073709551616"}, {C_GW, "COALESCE(w, e, 0)"},
    {C_GW, "CASE WHEN b THEN w ELSE d END"}, {C_GW, "e * 100000000000000000000"}, {C_GX, "w"}, {C_GX, "w * 0.5"},
    {C_GX, "18446744073709551616.005"}, {C_GX, "-18446744073709551616.005"}, {C_GX, "999999999999999999.994"},
    {C_GX, "999999999999999999.995"}, {C_GX, "e"}, {C_GD, "w"}, {C_GD, "w / 1000000000000000000000000"}, {C_GE, "w"},
    {C_GJ, "w"}, {C_GI, "w"}, {C_GW, "gw"}, {C_GW, "s"},
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

static void t_gen_differential(void)
{
    const char *dir = test_tmpdir();
    imdb_db *db = open_fresh(dir);
    CHECK(db);
    if (!db) return;
    OK(run("CREATE TABLE t (id INT64 PRIMARY KEY, i INT64, j SMALLINT, d DECIMAL(10,2), e DECIMAL(18,0), s TEXT, "
           "v VARCHAR(10), b BOOL, dt DATE, tm TIME, ts TIMESTAMP, tz TIMESTAMPTZ, f FLOAT64, gi INT64 NOT NULL, gn INT64, "
           "gj SMALLINT, gd DECIMAL(10,2), ge DECIMAL(4,1), gs TEXT, gv VARCHAR(4), gb BOOL NOT NULL, gdt DATE, gtm TIME, "
           "gts TIMESTAMP, gtz TIMESTAMPTZ, gw DECIMAL(38,6), gx DECIMAL(20,2), w DECIMAL(38,6))"));
    imdb_table *t = imdb_table_by_name(db, "t");
    CHECK(t && t->s.ncols == C_NCOLS);
    if (!t || t->s.ncols != C_NCOLS) {
        if (db) done(db);
        return;
    }
    const imdb_schema *s = &t->s;
    uint64_t gm = 0;
    for (int c = C_GI; c <= C_GX; c++) gm |= 1ull << c;
    ab_col cols[IMDB_MAX_COLS];
    for (uint16_t c = 0; c < s->ncols; c++) {
        memset(&cols[c], 0, sizeof cols[c]);
        snprintf(cols[c].name, sizeof cols[c].name, "%s", s->cols[c].name);
        cols[c].type = s->cols[c].type;
        cols[c].scale = s->cols[c].type == IMDB_T_DECIMAL ? s->cols[c].scale : 0;
    }
    static const int64_t VI[] = {0, 1, -1, 7, 100, INT64_MAX, INT64_MIN, 3037000500, -9, 32767, 32768};
    static const int64_t VJ[] = {0, 32767, -32768, 5, -7};
    static const int64_t VD[] = {0, 150, -1, 9999999999LL, -9999999999LL, 5, 1, -5};
    static const int64_t VE[] = {0, 999999999999999999LL, -999999999999999999LL, 12, -999};
    static const char *VS[] = {"", "a", "abc", "ABC", "\xc3\xa9", "it's", "k1", "abcd", "\xc3\xa9\xc3\xa9"};
    static const char *VV[] = {"", "hello", "H\xc3\x89", "ab"};
    static const int64_t VDT[] = {IMDB_DATE_MIN, IMDB_DATE_MAX, 0, 10957, 18262};
    static const int64_t VTM[] = {0, IMDB_TIME_MAX, 43200000000LL};
    static const int64_t VTS[] = {-62135596800000000LL, 253402300799999999LL, 0, 946684800000000LL};
    const __int128 P38 = (__int128)10000000000000000000ull * 10000000000000000000ull, P64 = (__int128)1 << 64; /* 10^38 */
    const __int128 VW[] = {0, 1, -1, P38 - 1, -(P38 - 1), P64, -P64, 3 * P64 + 7, (__int128)5000000000000000000ll * 1000000,
                           (__int128)123456789012345678ll * 1000000000000000000ll + 901234567890123456ll, 5000, -5000, 4999};
    enum { NR = 48 };
    imdb_value *rows = calloc((size_t)NR * s->ncols, sizeof *rows), *vals = calloc(NR, sizeof *vals);
    ab_val *arows = calloc((size_t)NR * s->ncols, sizeof *arows);
    CHECK(rows && arows && vals);
    if (!rows || !arows || !vals) {
        free(rows);
        free(arows);
        free(vals);
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
        ival(&v[C_W], IMDB_T_DECIMAL, 6, nul || r % 7 == 5, 0, NULL); /* F3e: w, its 128 bits */
        if (!v[C_W].null) imdb_dec_set(&v[C_W], VW[(r * 3) % (sizeof VW / sizeof *VW)], true);
        for (int c = C_GI; c <= C_GX; c++) /* never read: the expressions name no target */
            ival(&v[c], s->cols[c].type, s->cols[c].type == IMDB_T_DECIMAL ? s->cols[c].scale : 0, true, 0, NULL);
#undef PICK
        for (uint16_t c = 0; c < s->ncols; c++)
            arows[(size_t)r * s->ncols + c] = (ab_val){.i = v[c].i, .s = v[c].type == IMDB_T_TEXT ? v[c].s : NULL, .len = v[c].len,
                                                       .null = v[c].null, .wide = v[c].wide, .hi = v[c].wide ? v[c].hi : 0};
    }
    static const int tnum[] = {C_GI, C_GN, C_GJ, C_GD, C_GE, C_GW, C_GX};
    static const int ttext[] = {C_GS, C_GV};
    char buf[4096];
    gen g = {0xD1B54A32D192ED03ull, buf, 0, sizeof buf};
    unsigned ntext = 0, nbound = 0, nevals = 0, mism = 0, nval = 0, neval = 0, nasg = 0;
    size_t nfixed = sizeof kCorpus / sizeof *kCorpus;
    int seeds = getenv("IMDB_GEN_DRAWS") ? atoi(getenv("IMDB_GEN_DRAWS")) : 6000;
    for (size_t k = 0; k < nfixed + (size_t)seeds && mism < 8; k++) {
        const char *text;
        int tc;
        if (k < nfixed) {
            text = kCorpus[k].text;
            tc = kCorpus[k].col;
        } else {
            int ty = (int)rnd(&g, G_TZ + 1);
            tc = ty == G_NUM ? tnum[rnd(&g, 7)] : ty == G_TEXT ? ttext[rnd(&g, 2)] : ty == G_BOOL ? C_GB : ty == G_DATE ? C_GDT
                 : ty == G_TIME ? C_GTM : ty == G_TS ? C_GTS : C_GTZ;
            g.n = 0;
            buf[0] = 0;
            g_expr(&g, ty, 1 + (int)rnd(&g, 4));
            text = buf;
        }
        ntext++;
        uint32_t len = (uint32_t)strlen(text);
        int out[NR];
        imdb_err e = {0};
        imdb_xarena ar = {0};
        int erc = imdb_gen_eval_text(s, (uint16_t)tc, gm, text, len, rows, NR, out, vals, &ar, &e);
        ab_check *ac = NULL;
        char aerr[256];
        int arc = ab_gen_bind(text, len, cols, s->ncols, (uint16_t)tc, gm, &ac, aerr, sizeof aerr);
        if ((erc != 0) != (arc != 0)) {
            char m[1024];
            snprintf(m, sizeof m, "binding differs on: %s (into %s)\n      engine: %s\n      auditor: %s", text, s->cols[tc].name,
                     erc ? e.msg : "bound", arc ? aerr : "bound");
            test_fail(__FILE__, __LINE__, m);
            mism++;
        }
        if (!erc && !arc) {
            nbound++;
            const imdb_column *col = &s->cols[tc];
            ab_gcol gc = {.type = col->type, .prec = col->precision, .scale = col->scale, .vlen = imdb_text_max(col),
                          .nullable = (col->flags & IMDB_COL_NULLABLE) != 0};
            for (uint32_t r = 0; r < NR; r++) {
                char er[256];
                ab_val av;
                uint8_t *tb = NULL;
                int a = ab_gen_eval(ac, arows + (size_t)r * s->ncols, &gc, &av, &tb, er, sizeof er);
                int ae = a == 0 ? 0 : a == -1 ? 1 : 2;
                nevals++;
                nval += out[r] == 0;
                neval += out[r] == 1;
                nasg += out[r] == 2;
                bool same = ae == out[r];
                if (same && !ae) {
                    const imdb_value *ev = &vals[r];
                    same = ev->null == av.null &&
                           (ev->null || (col->type == IMDB_T_TEXT ? ev->len == av.len && (!av.len || !memcmp(ev->s, av.s, av.len))
                                                                  : ev->i == av.i && ev->wide == av.wide &&
                                                                        (!ev->wide || ev->hi == av.hi))); /* F3e */
                }
                free(tb);
                if (!same) {
                    char m[1024];
                    snprintf(m, sizeof m, "verdict differs on row %u of: %s (into %s)\n      engine %d, auditor %d (%s)", r, text,
                             s->cols[tc].name, out[r], ae, ae ? er : "a value");
                    test_fail(__FILE__, __LINE__, m);
                    mism++;
                    break;
                }
            }
        }
        ab_check_free(ac);
        imdb_xarena_free(&ar);
    }
    /* the corpus reaches every verdict: texts bound and refused, rows giving values, failing to evaluate and refused by
     * their columns */
    CHECK(nbound > ntext / 8 && nbound < ntext && nval > 1000 && neval > 20 && nasg > 20 && nevals > nbound * (NR - 1));
    if (getenv("IMDB_GEN_STATS"))
        fprintf(stderr, "gen_differential: %u texts, %u bound, %u evaluations (%u values, %u evaluation errors, %u refused "
                        "by their columns)\n", ntext, nbound, nevals, nval, neval, nasg);
    free(rows);
    free(arows);
    free(vals);
    done(db);
}

/* ---- the codec: op 23's kind 9, every bit flipped; the rules at the encoder; manifest 11 refused by name ---- */
static void t_gen_codec(void)
{
    imdb_schema s;
    memset(&s, 0, sizeof s);
    snprintf(s.name, sizeof s.name, "t");
    s.ncols = 4;
    s.subject = -1;
    const char *nm[4] = {"id", "a", "w", "x"};
    const uint8_t ty[4] = {IMDB_T_INT64, IMDB_T_INT64, IMDB_T_INT64, IMDB_T_TEXT};
    for (int c = 0; c < 4; c++) {
        snprintf(s.cols[c].name, sizeof s.cols[c].name, "%s", nm[c]);
        s.cols[c].type = ty[c];
        s.cols[c].flags = c ? IMDB_COL_NULLABLE : IMDB_COL_PK;
    }
    s.npk = 1;
    imdb_coldef cd[2] = {{.col = 2, .kind = IMDB_DEFK_GENERATED, .text = "a * 2", .tlen = 5},
                         {.col = 3, .kind = IMDB_DEFK_GENERATED, .text = "'x' || 'y'", .tlen = 10}};
    imdb_op ops[3] = {{.code = IMDB_OP_CREATE_TABLE, .table = 0, .schema = &s},
                      {.code = IMDB_OP_SET_RETENTION, .table = 0, .retention_us = IMDB_RETAIN_DEFAULT_US},
                      {.code = IMDB_OP_COLUMN_DEFAULTS, .table = 0, .defs = cd, .ndefs = 2}};
    imdb_commit_rec c = {.seq = 1, .alg = IMDB_DIGEST_ALG_LTHASH16_TREE, .ops = ops, .nops = 3};
    imdb_buf b, b2;
    imdb_buf_init(&b);
    imdb_buf_init(&b2);
    imdb_commit_encode_header(&c, &b);
    c.nops = 2;
    imdb_commit_encode_header(&c, &b2);
    OK(imdb_buf_check(&b, E));
    OK(imdb_buf_check(&b2, E));
    imdb_commit_rec d;
    memset(&d, 0, sizeof d);
    OK(imdb_commit_decode_header(b.p, b.len, &d, E));
    CHECK(d.nops == 3 && d.ops[2].ndefs == 2 && d.ops[2].defs[0].kind == IMDB_DEFK_GENERATED && d.ops[2].defs[0].tlen == 5 &&
          !memcmp(d.ops[2].defs[0].text, "a * 2", 5) && d.ops[2].defs[1].tlen == 10);
    imdb_commit_free(&d);
    size_t lo = b2.len - 32, hi = b.len - 32;
    uint32_t refused = 0, other = 0;
    for (size_t i = lo; i < hi; i++)
        for (int bit = 0; bit < 8; bit++) {
            imdb_buf m;
            imdb_buf_init(&m);
            imdb_buf_put(&m, b.p, b.len);
            m.p[i] ^= (uint8_t)(1u << bit);
            memset(&d, 0, sizeof d);
            imdb_err e2 = {0};
            if (imdb_commit_decode_header(m.p, m.len, &d, &e2)) {
                refused++;
            } else {
                imdb_buf re;
                imdb_buf_init(&re);
                imdb_commit_encode_header(&d, &re);
                CHECK(!re.err && re.len == m.len && !memcmp(re.p, m.p, m.len));
                imdb_buf_free(&re);
                other++;
            }
            imdb_commit_free(&d);
            imdb_buf_free(&m);
        }
    CHECK(refused > 0 && refused + other == (hi - lo) * 8);
    imdb_buf_free(&b);
    imdb_buf_free(&b2);
    /* the rules at the encoder: a key column, a FLOAT64, an empty text, a text with a NUL, past the bound together */
    static char big[IMDB_MAX_CHECK_TEXT + 2];
    memset(big, 'a', sizeof big - 1);
    imdb_coldef bad[5] = {{.col = 0, .kind = IMDB_DEFK_GENERATED, .text = "1", .tlen = 1},
                          {.col = 2, .kind = IMDB_DEFK_GENERATED, .text = "", .tlen = 0},
                          {.col = 2, .kind = IMDB_DEFK_GENERATED, .text = "a\0b", .tlen = 3},
                          {.col = 2, .kind = IMDB_DEFK_GENERATED, .text = big, .tlen = IMDB_MAX_CHECK_TEXT + 1},
                          {.col = 2, .kind = IMDB_DEFK_GENERATED, .text = NULL, .tlen = 4}};
    for (int k = 0; k < 5; k++) CHECK(!imdb_coldefs_ok(&s, &bad[k], 1));
    imdb_coldef two[2] = {{.col = 2, .kind = IMDB_DEFK_GENERATED, .text = big, .tlen = 5000},
                          {.col = 3, .kind = IMDB_DEFK_GENERATED, .text = big, .tlen = 5000}};
    CHECK(imdb_coldefs_ok(&s, two, 1) && !imdb_coldefs_ok(&s, two, 2));
    s.cols[2].type = IMDB_T_FLOAT64;
    CHECK(!imdb_coldefs_ok(&s, cd, 1));
    s.cols[2].type = IMDB_T_INT64;
    /* a manifest of version 11, before generated columns: refused by name */
    const char *dir = test_tmpdir();
    imdb_db *db = open_fresh(dir);
    CHECK(db);
    if (!db) return;
    OK(run("CREATE TABLE t (id INT64 PRIMARY KEY, a INT64, w INT64 GENERATED ALWAYS AS (a + 1) STORED)"));
    OK(run("INSERT INTO t (id, a) VALUES (1, 1)"));
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
    CHECK(mn > 16 && imdb_manifest_parse(man, mn, &m, &g_e) == 0 && m.nt == 1 && m.t[0].hist.ngen == 1 &&
          m.t[0].hist.tcol[2].gtext && m.t[0].hist.tcol[2].glen == 5 && !memcmp(m.t[0].hist.tcol[2].gtext, "a + 1", 5));
    if (mn > 16) imdb_manifest_free(&m);
    man[8] = 11;
    imdb_err_clear(&g_e);
    CHECK(imdb_manifest_parse(man, mn, &m, &g_e) == IMDB_ERR_UNSUPPORTED && strstr(g_e.msg, "manifest version 11") &&
          strstr(g_e.msg, "generated columns"));
}

const test_case gen_tests[] = {
    {"gen_statements", t_gen_statements}, {"gen_api", t_gen_api}, {"gen_copies", t_gen_copies}, {"gen_cut", t_gen_cut},
    {"gen_differential", t_gen_differential}, {"gen_codec", t_gen_codec},
};
const size_t gen_ntests = sizeof gen_tests / sizeof *gen_tests;
