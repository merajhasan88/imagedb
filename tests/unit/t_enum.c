/* F3g: ENUM types (docs/f3g-design.md). The codec (a definition's bounds and its round trip, each label's commit and the
 * prefix a read point sees, the schema's id in the precision and scale bytes, the row's four bytes, the value's id a
 * tripwire); the statements and every refusal by name; the typing rules (a string beside an ENUM a label, read at
 * binding; two types with the same labels in opposite order refused across every form and taken within one); results
 * that outlive DDL; parameters declared and the API's; AS OF reading labels as they stood; then a table of ENUMs against
 * a twin holding each value's ordinal as an INT64 on every path: in memory, cross-checked, after a CHECKPOINT, at a
 * segment budget of none, after a reopen and a full replay at the same digest, labels appended after a CHECKPOINT; and
 * labels that test the text forms ('', 'a,b', 'x"y', 'it''s', one holding a newline) through the CSV renderer, COPY both
 * ways, the dump restored, a replica at the primary's digest, VERIFY and the auditor. */
#include <stdlib.h>

#include "../../src/codec.h"
#include "../../src/db_internal.h"
#include "../../src/log.h"
#include "../../src/lthash.h"
#include "../../src/sql.h"
#include "thelp.h"

static imdb_session g_s;
#define XQ(s) s, strlen(s) /* a statement's text and its length */
static char g_out[1 << 17];

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

static char g_copy[1 << 17];
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

static const char *render(const imdb_result *r)
{
    imdb_buf b;
    imdb_buf_init(&b);
    if (r->has_rows) imdb_result_render(r, true, &b);
    else imdb_buf_put_str(&b, r->status);
    if (imdb_buf_check(&b, &g_e)) snprintf(g_out, sizeof g_out, "ERR render");
    else snprintf(g_out, sizeof g_out, "%.*s", (int)b.len, (const char *)b.p);
    imdb_buf_free(&b);
    return g_out;
}

static const char *csv(const char *sql)
{
    imdb_result r;
    imdb_err_clear(&g_e);
    if (imdb_exec_one(&g_s, sql, strlen(sql), NULL, 0, &r, &g_e)) {
        snprintf(g_out, sizeof g_out, "ERR %s", g_e.msg);
        return g_out;
    }
    render(&r);
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
            char m_[3000];                                                                                         \
            snprintf(m_, sizeof m_, "%.900s\n      want: %.900s\n      got:  %.900s", (sql), (want), got_);        \
            test_fail(__FILE__, __LINE__, m_);                                                                     \
        }                                                                                                          \
    } while (0)

static imdb_db *open_with(const char *dir, bool full_replay, uint64_t budget)
{
    imdb_open_opts o = {.sync = 0, .full_replay = full_replay, .seg_cache_bytes = budget};
    imdb_db *db = NULL;
    imdb_err e = {0};
    if (imdb_open(dir, &o, &db, &e)) {
        fprintf(stderr, "    open%s: %s\n", full_replay ? " (a full replay)" : "", e.msg);
        return NULL;
    }
    imdb_session_init(&g_s, db);
    imdb_session_copy_io(&g_s, mem_read, mem_write, &g_in);
    return db;
}

static void done(imdb_db *db)
{
    imdb_session_close(&g_s);
    imdb_close(db);
}

static int audit_dir(const char *dir)
{
    const char *bin = getenv("IMDB_AUDIT_BIN");
    if (!bin || !*bin) return 0;
    char cmd[1600];
    snprintf(cmd, sizeof cmd, "'%s' verify '%s' > '%s.audit' 2>&1", bin, dir, dir);
    if (system(cmd) == 0) return 0;
    snprintf(cmd, sizeof cmd, "tail -2 '%s.audit' >&2", dir); /* the auditor's reason, in the test's output */
    if (system(cmd)) return 1;
    return 1;
}

static int verify_db(imdb_db *db)
{
    imdb_verify_report vr;
    memset(&vr, 0, sizeof vr);
    imdb_err_clear(&g_e);
    int rc = imdb_verify(db, &vr, &g_e);
    if (rc) fprintf(stderr, "    verify: %s\n", g_e.msg);
    return rc;
}

static void digest_of(imdb_db *db, uint8_t out[32]) { imdb_lthash_digest(db->meta.digest_alg, &db->global, out); }

static uint16_t eid_of(imdb_db *db, const char *name)
{
    imdb_enum *t = imdb_enum_by_name(db, name);
    return t ? (uint16_t)t->def->id : 0;
}

/* ---- the codec --------------------------------------------------------------------------------------------------- */

static void t_enum_codec(void)
{
    imdb_err e = {0};
    const char *lab[3] = {"sad", "", "h\xc3\xa4ppy"};
    size_t len[3] = {3, 0, 6};
    imdb_enumdef *d = NULL;
    CHECK(imdb_enumdef_make(1, "mood", lab, len, 3, &d, &e) == 0 && d && d->n == 3);
    if (!d) return;
    CHECK(imdb_enumdef_find(d, "", 0) == 1 && imdb_enumdef_find(d, "sad", 3) == 0 && imdb_enumdef_find(d, "Sad", 3) < 0);
    /* its encoding read back, and every proper prefix refused */
    imdb_buf b;
    imdb_buf_init(&b);
    imdb_enumdef_encode(d, &b);
    CHECK(imdb_buf_check(&b, &e) == 0);
    imdb_rd r = {b.p, b.len, 0, 0};
    imdb_enumdef *d2 = NULL;
    CHECK(imdb_enumdef_decode(&r, &d2, "test", &e) == 0 && d2 && !r.err && r.off == b.len);
    if (d2) {
        imdb_enumdef_stamp(d2, 0, 0);
        CHECK(imdb_enumdef_same(d, d2));
        imdb_enumdef_free(d2);
    }
    for (size_t cut = 0; cut < b.len; cut++) {
        imdb_rd rc = {b.p, cut, 0, 0};
        imdb_enumdef *d3 = NULL;
        imdb_err e3 = {0};
        int rr = imdb_enumdef_decode(&rc, &d3, "test", &e3);
        CHECK(rr != 0 || rc.err);
        imdb_enumdef_free(d3);
    }
    imdb_buf_free(&b);
    /* the bounds: a 63-byte label taken, 64 refused; a duplicate, a NUL, bad UTF-8, a built-in name's id 0 refused */
    char l63[64], l64[65];
    memset(l63, 'a', 63);
    memset(l64, 'a', 64);
    const char *one[1] = {l63};
    size_t n63[1] = {63}, n64[1] = {64};
    imdb_enumdef *x = NULL;
    CHECK(imdb_enumdef_make(2, "e", one, n63, 1, &x, &e) == 0);
    imdb_enumdef_free(x);
    one[0] = l64;
    CHECK(imdb_enumdef_make(2, "e", one, n64, 1, &x, &e) != 0);
    const char *dup[2] = {"a", "a"}, *nul[1] = {"a\0b"}, *bad[1] = {"\xc3"};
    size_t n11[2] = {1, 1}, n3[1] = {3}, n1[1] = {1};
    CHECK(imdb_enumdef_make(2, "e", dup, n11, 2, &x, &e) != 0);
    CHECK(imdb_enumdef_make(2, "e", nul, n3, 1, &x, &e) != 0);
    CHECK(imdb_enumdef_make(2, "e", bad, n1, 1, &x, &e) != 0);
    CHECK(imdb_enumdef_make(0, "e", dup, n11, 1, &x, &e) != 0);
    CHECK(imdb_enumdef_make(IMDB_MAX_ENUMS + 1, "e", dup, n11, 1, &x, &e) != 0);
    /* labels appended: each its commit, a read point sees a prefix */
    imdb_enumdef_stamp(d, 0, 10);
    imdb_enumdef *d4 = NULL;
    CHECK(imdb_enumdef_append(d, "ecstatic", 8, &d4, &e) == 0 && d4 && d4->n == 4);
    if (d4) {
        imdb_enumdef_stamp(d4, 3, 20);
        CHECK(imdb_enumdef_count_at(d4, 9) == 0 && imdb_enumdef_count_at(d4, 10) == 3 && imdb_enumdef_count_at(d4, 19) == 3 &&
              imdb_enumdef_count_at(d4, 20) == 4);
        CHECK(imdb_enumdef_at_ok(d4, 10) && !imdb_enumdef_at_ok(d4, 11));
        d4->at[3] = 9; /* an appended label before the CREATE's commit: not well formed */
        CHECK(!imdb_enumdef_at_ok(d4, 10));
        imdb_enumdef *d5 = NULL;
        CHECK(imdb_enumdef_append(d4, "sad", 3, &d5, &e) != 0); /* a label it holds */
        imdb_enumdef_free(d4);
    }
    imdb_enumdef_free(d);
    /* the schema: an ENUM column names its type in the precision and scale bytes; no other column does */
    imdb_schema s;
    memset(&s, 0, sizeof s);
    s.id = 1;
    snprintf(s.name, sizeof s.name, "t");
    s.ncols = 2;
    snprintf(s.cols[0].name, sizeof s.cols[0].name, "id");
    s.cols[0].type = IMDB_T_INT64;
    s.cols[0].flags = IMDB_COL_PK;
    snprintf(s.cols[1].name, sizeof s.cols[1].name, "m");
    s.cols[1].type = IMDB_T_ENUM;
    s.cols[1].eid = 300;
    s.cols[1].flags = IMDB_COL_NULLABLE;
    s.npk = 1;
    s.key[0] = 0;
    s.subject = -1;
    CHECK(imdb_schema_check(&s, &e) == 0);
    imdb_buf sb;
    imdb_buf_init(&sb);
    imdb_schema_encode(&s, &sb);
    CHECK(imdb_buf_check(&sb, &e) == 0);
    imdb_schema s2;
    imdb_rd sr = {sb.p, sb.len, 0, 0};
    CHECK(imdb_schema_decode(&sr, &s2, &e) == 0 && s2.cols[1].type == IMDB_T_ENUM && s2.cols[1].eid == 300);
    imdb_buf_free(&sb);
    s.cols[1].eid = 0;
    CHECK(imdb_schema_check(&s, &e) != 0);
    s.cols[1].eid = 300;
    s.cols[0].eid = 1; /* an INT64 naming a type */
    CHECK(imdb_schema_check(&s, &e) != 0);
    s.cols[0].eid = 0;
    /* the row: an ordinal of four bytes, its id the column's; the value's id a tripwire */
    imdb_value v[2];
    memset(v, 0, sizeof v);
    v[0].type = IMDB_T_INT64;
    v[0].i = 7;
    v[1].type = IMDB_T_ENUM;
    v[1].i = 2;
    v[1].eid = 300;
    imdb_buf rb;
    imdb_buf_init(&rb);
    CHECK(imdb_row_encode(&s, v, &rb, &e) == 0);
    CHECK(rb.len == 1 + 8 + 4); /* a NULL bitmap byte, the key, the ordinal */
    imdb_value o[2];
    CHECK(imdb_row_decode(&s, rb.p, rb.len, o, &e) == 0 && o[1].type == IMDB_T_ENUM && o[1].i == 2 && o[1].eid == 300);
    imdb_buf_free(&rb);
    v[1].eid = 301;
    CHECK(imdb_value_check(&s.cols[1], &v[1], &e) != 0);
    v[1].eid = 0;
    CHECK(imdb_value_check(&s.cols[1], &v[1], &e) != 0);
    v[1].eid = 300;
    CHECK(imdb_value_check(&s.cols[1], &v[1], &e) == 0);
}

/* ---- the statements, the rules and every refusal ------------------------------------------------------------------ */

static void t_enum_sql(void)
{
    const char *dir = test_tmpdir();
    imdb_err e = {0};
    CHECK(imdb_init(dir, false, NULL, &e) == 0);
    imdb_db *db = open_with(dir, false, 0);
    CHECK(db);
    if (!db) return;
    EXPECT("CREATE TYPE mood AS ENUM ('sad', 'ok', 'happy')", "CREATE TYPE mood");
    EXPECT("CREATE TYPE none AS ENUM ()", "CREATE TYPE none");
    EXPECT("CREATE TYPE int AS ENUM ('a')", "ERR a built-in type's name");
    EXPECT("CREATE TYPE serial AS ENUM ('a')", "ERR a built-in type's name"); /* CREATE TABLE reads it as SERIAL */
    EXPECT("CREATE TYPE mood AS ENUM ('a')", "ERR exists already");
    EXPECT("CREATE TYPE e AS ENUM ('a', 'a')", "ERR given twice");
    EXPECT("CREATE TYPE e AS ENUM ('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa')", "ERR 0 to 63 bytes");
    EXPECT("CREATE TYPE e AS ENUM ('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa')", "CREATE TYPE e");
    EXPECT("CREATE TYPE r AS RANGE (subtype = int)", "ERR AS ENUM alone");
    EXPECT("CREATE TYPE r AS ENUM (1)", "ERR a label");
    EXPECT("BEGIN", "BEGIN");
    EXPECT("CREATE TYPE q AS ENUM ('a')", "ERR commits on its own");
    EXPECT("ROLLBACK", "ROLLBACK");
    /* two types with the same labels in opposite order: never compared, joined or unified across */
    OK(run("CREATE TYPE ab AS ENUM ('a', 'b')"));
    OK(run("CREATE TYPE ba AS ENUM ('b', 'a')"));
    EXPECT("CREATE TABLE t (id INT64 PRIMARY KEY, m mood, n mood NOT NULL DEFAULT 'ok', x ab, y ba)", "CREATE TABLE t");
    EXPECT("CREATE TABLE bad (id INT64 PRIMARY KEY, m nosuch)", "ERR no type nosuch");
    EXPECT("CREATE TABLE bad (id INT64 PRIMARY KEY, m mood DEFAULT 'nope')", "ERR not a label of type mood");
    EXPECT("CREATE TABLE bad (id INT64 PRIMARY KEY, m mood SUBJECT)", "ERR SUBJECT column must be INT64 or TEXT");
    EXPECT("CREATE TABLE bad (id INT64 PRIMARY KEY, m mood CHECK (m <> 'sad'))", "ERR reads no ENUM value yet");
    EXPECT("CREATE TABLE bad (id INT64 PRIMARY KEY, m mood, g BOOL GENERATED ALWAYS AS (m IS NULL) STORED)", "ERR reads no ENUM value yet");
    EXPECT("CREATE TABLE bad (id INT64 PRIMARY KEY, m mood, g BOOL GENERATED ALWAYS AS (m = 'ok') STORED)", "ERR reads no ENUM value yet");
    OK(run("INSERT INTO t VALUES (1, 'happy', 'sad', 'a', 'a'), (2, 'sad', 'ok', 'b', 'b'), (3, NULL, 'happy', 'a', 'b')"));
    OK(run("INSERT INTO t (id, m, x, y) VALUES (4, 'ok', 'b', 'a')"));
    EXPECT("INSERT INTO t VALUES (5, 'nope', 'ok', 'a', 'a')", "ERR not a label of type mood");
    EXPECT("INSERT INTO t VALUES (5, 1, 'ok', 'a', 'a')", "ERR expects a label of its ENUM type");
    EXPECT("SELECT * FROM t ORDER BY id", "id,m,n,x,y\n1,\"happy\",\"sad\",\"a\",\"a\"\n2,\"sad\",\"ok\",\"b\",\"b\"\n3,,\"happy\",\"a\",\"b\"\n"
                                         "4,\"ok\",\"ok\",\"b\",\"a\"\n");
    /* declaration order, never the text's */
    EXPECT("SELECT id FROM t ORDER BY m, id", "id\n2\n4\n1\n3\n");
    EXPECT("SELECT id FROM t ORDER BY m DESC NULLS LAST, id", "id\n1\n4\n2\n3\n");
    EXPECT("SELECT id FROM t WHERE m > 'sad' ORDER BY id", "id\n1\n4\n");
    EXPECT("SELECT id FROM t WHERE 'ok' < m ORDER BY id", "id\n1\n");
    EXPECT("SELECT id FROM t WHERE m BETWEEN 'ok' AND 'happy' ORDER BY id", "id\n1\n4\n");
    EXPECT("SELECT id FROM t WHERE m IN ('sad', 'happy') ORDER BY id", "id\n1\n2\n");
    EXPECT("SELECT id FROM t WHERE m NOT IN ('sad') ORDER BY id", "id\n1\n4\n");
    EXPECT("SELECT id FROM t WHERE m = n ORDER BY id", "id\n4\n");
    EXPECT("SELECT MIN(m) AS a, MAX(m) AS b, MIN(n) AS c, MAX(n) AS d, COUNT(m) AS k, COUNT(DISTINCT n) AS dn FROM t",
           "a,b,c,d,k,dn\n\"sad\",\"happy\",\"sad\",\"happy\",3,3\n");
    EXPECT("SELECT n, COUNT(*) AS c FROM t GROUP BY n ORDER BY n", "n,c\n\"sad\",1\n\"ok\",2\n\"happy\",1\n");
    EXPECT("SELECT DISTINCT x FROM t ORDER BY x", "x\n\"a\"\n\"b\"\n");
    EXPECT("SELECT DISTINCT y FROM t ORDER BY y", "y\n\"b\"\n\"a\"\n");
    EXPECT("SELECT id, COALESCE(m, 'ok') AS c FROM t ORDER BY id", "id,c\n1,\"happy\"\n2,\"sad\"\n3,\"ok\"\n4,\"ok\"\n");
    EXPECT("SELECT id, CASE WHEN id < 3 THEN m ELSE 'happy' END AS c FROM t ORDER BY id",
           "id,c\n1,\"happy\"\n2,\"sad\"\n3,\"happy\"\n4,\"happy\"\n");
    EXPECT("SELECT id, NULLIF(n, 'ok') AS c FROM t ORDER BY id", "id,c\n1,\"sad\"\n2,\n3,\"happy\"\n4,\n");
    EXPECT("SELECT id, CAST(m AS TEXT) || '!' AS c FROM t WHERE id < 3 ORDER BY id", "id,c\n1,\"happy!\"\n2,\"sad!\"\n");
    EXPECT("SELECT COUNT(*) AS c FROM t WHERE n = CAST('ok' AS mood)", "c\n2\n");
    EXPECT("SELECT CAST('nope' AS mood) AS c", "ERR not a label of type mood");
    EXPECT("SELECT CAST(CAST('ok' AS mood) AS mood) AS c", "c\n\"ok\"\n");
    EXPECT("SELECT id FROM t WHERE x = y ORDER BY id", "ERR values are not converted");
    EXPECT("SELECT id FROM t WHERE x = CAST('a' AS ba)", "ERR values are not converted");
    EXPECT("SELECT CASE WHEN id = 1 THEN x ELSE y END AS c FROM t", "ERR two ENUM types");
    EXPECT("SELECT COALESCE(x, y) AS c FROM t", "ERR two ENUM types");
    EXPECT("SELECT x FROM t UNION SELECT y FROM t", "ERR two ENUM types");
    EXPECT("SELECT id FROM t WHERE x IN (SELECT y FROM t)", "ERR values are not converted");
    EXPECT("SELECT a.id FROM t AS a JOIN t AS b ON a.x = b.y", "ERR values are not converted");
    EXPECT("SELECT CAST(x AS ba) AS c FROM t", "ERR CAST to ENUM type ba takes a TEXT or that type");
    EXPECT("SELECT x FROM t UNION SELECT x FROM t ORDER BY 1", "x\n\"a\"\n\"b\"\n");
    EXPECT("SELECT a.id, b.id AS j FROM t AS a JOIN t AS b ON a.x = b.x WHERE a.id = 1 ORDER BY 2", "id,j\n1,1\n1,3\n");
    EXPECT("SELECT id FROM t WHERE x IN (SELECT x FROM t WHERE id = 2) ORDER BY id", "id\n2\n4\n");
    EXPECT("SELECT m FROM t WHERE m = 'nope'", "ERR not a label of type mood");
    EXPECT("SELECT m FROM t WHERE m = 'Sad'", "ERR not a label of type mood"); /* byte-exact, case-sensitive */
    EXPECT("SELECT m || 'x' AS c FROM t", "ERR of an ENUM: CAST it to TEXT first");
    EXPECT("SELECT m + 1 AS c FROM t", "ERR arithmetic takes");
    EXPECT("SELECT SUM(m) AS c FROM t", "ERR SUM needs");
    EXPECT("SELECT AVG(m) AS c FROM t", "ERR AVG needs");
    EXPECT("SELECT LENGTH(m) AS c FROM t", "ERR takes a TEXT value");
    EXPECT("SELECT id FROM t WHERE m LIKE 's%'", "ERR LIKE takes TEXT values");
    EXPECT("SELECT CAST(m AS INT64) AS c FROM t", "ERR CAST of an ENUM to INT64 is not defined");
    EXPECT("SELECT CAST(1 AS mood) AS c", "ERR CAST to ENUM type mood takes a TEXT or that type");
    EXPECT("SELECT id FROM t WHERE m = CAST('ok' AS TEXT)", "ERR values are not converted");
    /* windows, a derived table, a CTE, a view over a view */
    EXPECT("SELECT id, LAG(m) OVER (ORDER BY id) AS p, FIRST_VALUE(n) OVER (ORDER BY n, id) AS f FROM t ORDER BY id",
           "id,p,f\n1,,\"sad\"\n2,\"happy\",\"sad\"\n3,\"sad\",\"sad\"\n4,,\"sad\"\n");
    EXPECT("SELECT id, MAX(m) OVER (PARTITION BY n) AS w FROM t ORDER BY id", "id,w\n1,\"happy\"\n2,\"ok\"\n3,\n4,\"ok\"\n");
    /* two CASTs alike but for their types' names are two trees (ab orders a first, ba b first): a window's keys and
     * arguments (ex_alike: one hidden column served both), a GROUP BY key (x_same: the other CAST read from its slot) */
    EXPECT("SELECT id, ROW_NUMBER() OVER (ORDER BY CAST(CAST(x AS TEXT) AS ab), id) AS r1, "
           "ROW_NUMBER() OVER (ORDER BY CAST(CAST(x AS TEXT) AS ba), id) AS r2 FROM t ORDER BY id",
           "id,r1,r2\n1,1,3\n2,3,1\n3,2,4\n4,4,2\n");
    EXPECT("SELECT id, FIRST_VALUE(CAST('a' AS ab)) OVER (ORDER BY id) AS p, FIRST_VALUE(CAST('a' AS ba)) OVER (ORDER BY id) AS q "
           "FROM t WHERE id < 3 ORDER BY id",
           "id,p,q\n1,\"a\",\"a\"\n2,\"a\",\"a\"\n");
    EXPECT("SELECT CAST(CAST(x AS TEXT) AS ba) AS c, COUNT(*) AS k FROM t GROUP BY CAST(CAST(x AS TEXT) AS ab)",
           "ERR column x must be a GROUP BY key");
    EXPECT("SELECT CAST(CAST(x AS TEXT) AS ab) AS c, COUNT(*) AS k FROM t GROUP BY CAST(CAST(x AS TEXT) AS ab) ORDER BY 1",
           "c,k\n\"a\",2\n\"b\",2\n");
    EXPECT("SELECT d.m FROM (SELECT m FROM t WHERE m > 'sad') AS d ORDER BY d.m", "m\n\"ok\"\n\"happy\"\n");
    EXPECT("WITH c AS (SELECT n FROM t) SELECT MAX(n) AS h FROM c", "h\n\"happy\"\n");
    EXPECT("CREATE VIEW v AS SELECT id, m, CAST('ok' AS mood) AS k FROM t WHERE n > 'sad'", "CREATE VIEW v");
    EXPECT("CREATE VIEW vv AS SELECT id, m FROM v WHERE m < k", "CREATE VIEW vv");
    EXPECT("SELECT * FROM v ORDER BY id", "id,m,k\n2,\"sad\",\"ok\"\n3,,\"ok\"\n4,\"ok\",\"ok\"\n");
    EXPECT("SELECT * FROM vv ORDER BY id", "id,m\n2,\"sad\"\n");
    /* writes: UPDATE, RETURNING, INSERT ... SELECT, ON CONFLICT on an ENUM key */
    EXPECT("UPDATE t SET m = 'ok' WHERE id = 3 RETURNING id, m", "id,m\n3,\"ok\"\n");
    OK(run("CREATE TABLE k (m mood PRIMARY KEY, c INT64)"));
    OK(run("INSERT INTO k SELECT n, COUNT(*) FROM t GROUP BY n"));
    EXPECT("INSERT INTO k VALUES ('ok', 9) ON CONFLICT (m) DO UPDATE SET c = k.c + EXCLUDED.c RETURNING m, c", "m,c\n\"ok\",11\n");
    EXPECT("SELECT * FROM k WHERE m = 'ok'", "m,c\n\"ok\",11\n");
    EXPECT("INSERT INTO k VALUES ('ok', 1)", "ERR duplicate primary key");
    OK(run("CREATE INDEX kc ON t (n)"));
    EXPECT("SELECT id FROM t WHERE n = 'happy'", "id\n3\n");
    /* ADD VALUE: appended, IF NOT EXISTS, and every refusal */
    EXPECT("ALTER TYPE mood ADD VALUE 'ecstatic'", "ALTER TYPE mood");
    uint64_t added = db->seq; /* the commit that made the label */
    EXPECT("ALTER TYPE mood ADD VALUE IF NOT EXISTS 'ok'", "ALTER TYPE mood");
    EXPECT("ALTER TYPE mood ADD VALUE 'ok'", "ERR holds that label already");
    EXPECT("ALTER TYPE mood ADD VALUE 'meh' BEFORE 'ok'", "ERR a label is appended");
    EXPECT("ALTER TYPE mood ADD VALUE 'meh' AFTER 'ok'", "ERR a label is appended");
    EXPECT("ALTER TYPE mood RENAME VALUE 'ok' TO 'fine'", "ERR ADD VALUE alone");
    EXPECT("ALTER TYPE nosuch ADD VALUE 'a'", "ERR no type nosuch");
    OK(run("INSERT INTO t VALUES (5, 'ecstatic', 'ecstatic', 'a', 'a')"));
    EXPECT("SELECT id FROM t WHERE m > 'happy'", "id\n5\n");
    EXPECT("SELECT MAX(m) AS h FROM t", "h\n\"ecstatic\"\n");
    /* AS OF reads the labels as they stood: one appended since is no label there */
    char q[200];
    snprintf(q, sizeof q, "SELECT COUNT(*) AS c FROM t AS OF %llu WHERE m = 'happy'", (unsigned long long)added);
    EXPECT(q, "c\n1\n");
    snprintf(q, sizeof q, "SELECT COUNT(*) AS c FROM t AS OF %llu WHERE m = 'ecstatic'", (unsigned long long)added - 1);
    EXPECT(q, "ERR not a label of type mood");
    /* parameters: declared by name, and the API's */
    OK(run("PREPARE p (mood) AS SELECT id FROM t WHERE n = $1 ORDER BY id"));
    EXPECT("EXECUTE p ('ok')", "id\n2\n4\n");
    EXPECT("EXECUTE p ('nope')", "ERR not a label of type mood");
    OK(run("PREPARE p2 AS SELECT id FROM t WHERE n = $1"));
    /* N1b: an undeclared EXECUTE's string, a TEXT, binds into the ENUM column as its literal would: a label */
    EXPECT("EXECUTE p2 ('ok')", "id\n2\n4\n");
    EXPECT("EXECUTE p2 ('nope')", "ERR not a label of type mood");
    imdb_value pv = {.type = IMDB_T_ENUM, .i = 2, .eid = eid_of(db, "mood")};
    imdb_result r;
    CHECK(imdb_exec_one(&g_s, XQ("SELECT COUNT(*) AS c FROM t WHERE n = $1"), &pv, 1, &r, &g_e) == 0);
    CHECK(!strcmp(render(&r), "c\n1\n"));
    imdb_result_free(&r);
    pv.eid = eid_of(db, "ab");
    CHECK(imdb_exec_one(&g_s, XQ("SELECT COUNT(*) AS c FROM t WHERE n = $1"), &pv, 1, &r, &g_e) != 0);
    pv.eid = eid_of(db, "mood");
    pv.i = 9; /* no such label */
    CHECK(imdb_exec_one(&g_s, XQ("SELECT COUNT(*) AS c FROM t WHERE n = $1"), &pv, 1, &r, &g_e) != 0);
    pv.i = 1;
    CHECK(imdb_exec_one(&g_s, XQ("INSERT INTO t VALUES (6, $1, $1, 'b', 'b')"), &pv, 1, &r, &g_e) == 0);
    if (!g_e.code) imdb_result_free(&r);
    EXPECT("SELECT m, n FROM t WHERE id = 6", "m,n\n\"ok\",\"ok\"\n");
    /* a result outlives DDL: its labels its own */
    imdb_result kept;
    CHECK(imdb_exec_one(&g_s, XQ("SELECT id, x FROM t WHERE id < 3 ORDER BY id"), NULL, 0, &kept, &g_e) == 0);
    CHECK(kept.clab[1] != NULL);
    /* DEFAULTs: an ADD's and a SET DEFAULT's, labels of the column's type */
    EXPECT("ALTER TABLE t ADD COLUMN z mood DEFAULT 'happy'", "ALTER TABLE t");
    EXPECT("SELECT COUNT(*) AS c FROM t WHERE z = 'happy'", "c\n6\n");
    EXPECT("ALTER TABLE t ALTER COLUMN z SET DEFAULT 'sad'", "ALTER TABLE t");
    OK(run("INSERT INTO t (id, n, x, y) VALUES (7, 'ok', 'a', 'a')"));
    EXPECT("SELECT z FROM t WHERE id = 7", "z\n\"sad\"\n");
    EXPECT("ALTER TABLE t ALTER COLUMN z SET DEFAULT 'nope'", "ERR not a label of type mood");
    EXPECT("ALTER TABLE t ADD COLUMN w nosuch", "ERR no type nosuch");
    EXPECT("ALTER TABLE t ALTER COLUMN id TYPE mood", "ERR SET TYPE to an ENUM type is not in imagedb yet");
    /* the API's CREATE TABLE: a DEFAULT's ordinal a label of its type at the statement, the replay's op 23 rule (one past
     * the labels was signed, then refused by the next open); mood holds four labels now */
    {
        imdb_schema as;
        memset(&as, 0, sizeof as);
        snprintf(as.name, sizeof as.name, "apit");
        as.ncols = 2;
        snprintf(as.cols[0].name, sizeof as.cols[0].name, "id");
        as.cols[0].type = IMDB_T_INT64;
        as.cols[0].flags = IMDB_COL_PK;
        snprintf(as.cols[1].name, sizeof as.cols[1].name, "m");
        as.cols[1].type = IMDB_T_ENUM;
        as.cols[1].eid = eid_of(db, "mood");
        as.cols[1].flags = IMDB_COL_NULLABLE;
        as.npk = 1;
        as.key[0] = 0;
        as.subject = -1;
        imdb_coldef ad = {.col = 1, .kind = IMDB_DEFK_VALUE, .v = {.type = IMDB_T_ENUM, .i = 4, .eid = eid_of(db, "mood")}};
        imdb_err ae = {0};
        imdb_schema as2 = as;
        OK(imdb_begin(db, &ae));
        CHECK(imdb_create_table_defs(db, &as2, IMDB_RETAIN_DEFAULT_US, &ad, 1, &ae) == IMDB_ERR_INVALID &&
              strstr(ae.msg, "no label of its ENUM type"));
        imdb_rollback(db);
        CHECK(imdb_table_by_name(db, "apit") == NULL);
        ad.v.i = 3;
        as2 = as;
        imdb_err_clear(&ae);
        OK(imdb_begin(db, &ae));
        OK(imdb_create_table_defs(db, &as2, IMDB_RETAIN_DEFAULT_US, &ad, 1, &ae));
        imdb_rollback(db); /* a CREATE with its DEFAULTs rolled back leaves nothing (the heap's counter too) */
        CHECK(imdb_table_by_name(db, "apit") == NULL);
        as2 = as;
        OK(imdb_begin(db, &ae));
        OK(imdb_create_table_defs(db, &as2, IMDB_RETAIN_DEFAULT_US, &ad, 1, &ae));
        OK(imdb_commit(db, &ae));
        OK(run("INSERT INTO apit (id) VALUES (1)"));
        EXPECT("SELECT m FROM apit", "m\n\"ecstatic\"\n");
    }
    /* DROP TYPE: RESTRICT by a live table, a dropped table's history, a view's CAST; IF EXISTS; CASCADE refused */
    EXPECT("DROP TYPE mood", "ERR has a column of type mood");
    EXPECT("DROP TYPE mood CASCADE", "ERR CASCADE");
    EXPECT("DROP TYPE IF EXISTS nosuch", "DROP TYPE nosuch");
    EXPECT("DROP TYPE nosuch", "ERR no type nosuch");
    OK(run("CREATE TYPE gone AS ENUM ('g')"));
    OK(run("CREATE TABLE g (id INT64 PRIMARY KEY, c gone)"));
    OK(run("DROP TABLE g"));
    EXPECT("DROP TYPE gone", "ERR (dropped, its history still kept)");
    OK(run("CREATE TYPE tomb AS ENUM ('a', 'b')"));
    EXPECT("CREATE VIEW vt AS SELECT id FROM t WHERE CAST('a' AS tomb) IS NOT NULL", "CREATE VIEW vt");
    EXPECT("DROP TYPE tomb", "ERR view vt uses type tomb");
    OK(run("DROP VIEW vt"));
    uint64_t live = db->seq;
    EXPECT("DROP TYPE tomb", "DROP TYPE tomb");
    EXPECT("SELECT CAST('a' AS tomb) AS c", "ERR no type tomb");
    snprintf(q, sizeof q, "SELECT CAST('b' AS tomb) AS c FROM k AS OF %llu WHERE m = 'ok'", (unsigned long long)live);
    EXPECT(q, "c\n\"b\"\n"); /* the tombstone, below its drop */
    EXPECT("CREATE TYPE tomb AS ENUM ('z')", "CREATE TYPE tomb"); /* the name free again: a new id */
    EXPECT("SELECT CAST('z' AS tomb) AS c", "c\n\"z\"\n");
    /* the kept result renders its labels after it all */
    CHECK(!strcmp(render(&kept), "id,x\n1,\"a\"\n2,\"b\"\n"));
    imdb_result_free(&kept);
    CHECK(strstr(csv("SHOW TABLES"), "id INT64 PK, m mood, n mood, x ab, y ba, z mood") != NULL);
    CHECK(verify_db(db) == 0);
    done(db);
    CHECK(audit_dir(dir) == 0);
    /* a full replay builds the same catalog */
    db = open_with(dir, true, 0);
    CHECK(db);
    if (!db) return;
    EXPECT("SELECT MAX(m) AS h, MIN(n) AS l FROM t", "h,l\n\"ecstatic\",\"sad\"\n");
    EXPECT("SELECT CAST('z' AS tomb) AS c", "c\n\"z\"\n");
    CHECK(verify_db(db) == 0);
    done(db);
}

/* ---- every path against a twin of ordinals -------------------------------------------------------------------------- */

#define ENN 400

/* an ENUM result's text with each label lK as the number K, quotes and all: the twin's text */
static void unlabel(const char *in, char *out, size_t cap)
{
    size_t o = 0;
    for (size_t i = 0; in[i] && o + 1 < cap;) {
        if (in[i] == '"' && in[i + 1] == 'l' && in[i + 2] >= '0' && in[i + 2] <= '9') {
            size_t j = i + 2;
            while (in[j] >= '0' && in[j] <= '9') j++;
            if (in[j] == '"') {
                for (size_t k = i + 2; k < j && o + 1 < cap; k++) out[o++] = in[k];
                i = j + 1;
                continue;
            }
        }
        out[o++] = in[i++];
    }
    out[o] = 0;
}

static const char *const g_q[][2] = {
    {"SELECT id FROM t WHERE m = 'l3' ORDER BY id", "SELECT id FROM tw WHERE m = 3 ORDER BY id"},
    {"SELECT id FROM t WHERE m < 'l5' ORDER BY id", "SELECT id FROM tw WHERE m < 5 ORDER BY id"},
    {"SELECT id FROM t WHERE m >= 'l7' AND id < 300 ORDER BY id", "SELECT id FROM tw WHERE m >= 7 AND id < 300 ORDER BY id"},
    {"SELECT id FROM t WHERE m BETWEEN 'l2' AND 'l4' ORDER BY id", "SELECT id FROM tw WHERE m BETWEEN 2 AND 4 ORDER BY id"},
    {"SELECT id FROM t WHERE m IN ('l1', 'l9') ORDER BY id", "SELECT id FROM tw WHERE m IN (1, 9) ORDER BY id"},
    {"SELECT id FROM t WHERE m IS NULL ORDER BY id", "SELECT id FROM tw WHERE m IS NULL ORDER BY id"},
    {"SELECT id FROM t WHERE m <> 'l0' AND n = 'l2' ORDER BY id", "SELECT id FROM tw WHERE m <> 0 AND n = 2 ORDER BY id"},
    {"SELECT m, COUNT(*) AS c FROM t GROUP BY m ORDER BY m", "SELECT m, COUNT(*) AS c FROM tw GROUP BY m ORDER BY m"},
    {"SELECT DISTINCT n FROM t ORDER BY n", "SELECT DISTINCT n FROM tw ORDER BY n"},
    {"SELECT MIN(m) AS a, MAX(m) AS b, MIN(n) AS c, MAX(n) AS d, COUNT(m) AS k FROM t",
     "SELECT MIN(m) AS a, MAX(m) AS b, MIN(n) AS c, MAX(n) AS d, COUNT(m) AS k FROM tw"},
    {"SELECT id, m FROM t ORDER BY m DESC, id LIMIT 25", "SELECT id, m FROM tw ORDER BY m DESC, id LIMIT 25"},
    {"SELECT id FROM t WHERE m = n ORDER BY id", "SELECT id FROM tw WHERE m = n ORDER BY id"},
    {"SELECT a.id, b.id AS j FROM t AS a JOIN t AS b ON a.m = b.n WHERE a.id < 40 AND b.id < 40 ORDER BY 1, 2",
     "SELECT a.id, b.id AS j FROM tw AS a JOIN tw AS b ON a.m = b.n WHERE a.id < 40 AND b.id < 40 ORDER BY 1, 2"},
    {"SELECT id, LAG(m) OVER (ORDER BY id) AS p FROM t WHERE id < 40 ORDER BY id",
     "SELECT id, LAG(m) OVER (ORDER BY id) AS p FROM tw WHERE id < 40 ORDER BY id"},
    {"SELECT id, MAX(m) OVER (PARTITION BY n) AS w FROM t WHERE id < 60 ORDER BY id",
     "SELECT id, MAX(m) OVER (PARTITION BY n) AS w FROM tw WHERE id < 60 ORDER BY id"},
    {"SELECT COUNT(*) AS c FROM (SELECT m FROM t WHERE m > 'l4') AS d", "SELECT COUNT(*) AS c FROM (SELECT m FROM tw WHERE m > 4) AS d"},
    {"SELECT m FROM t WHERE id < 50 UNION SELECT n FROM t WHERE id < 50 ORDER BY 1",
     "SELECT m FROM tw WHERE id < 50 UNION SELECT n FROM tw WHERE id < 50 ORDER BY 1"},
    {"SELECT id FROM t WHERE m IN (SELECT n FROM t WHERE id < 10) ORDER BY id",
     "SELECT id FROM tw WHERE m IN (SELECT n FROM tw WHERE id < 10) ORDER BY id"},
    {"SELECT id, CASE WHEN x > 50 THEN m ELSE 'l0' END AS c FROM t WHERE id < 30 ORDER BY id",
     "SELECT id, CASE WHEN x > 50 THEN m ELSE 0 END AS c FROM tw WHERE id < 30 ORDER BY id"},
    {"SELECT id, COALESCE(m, 'l11') AS c FROM t WHERE id < 30 ORDER BY id",
     "SELECT id, COALESCE(m, 11) AS c FROM tw WHERE id < 30 ORDER BY id"},
    {"SELECT n, MIN(m) AS lo, MAX(m) AS hi FROM t GROUP BY n ORDER BY n",
     "SELECT n, MIN(m) AS lo, MAX(m) AS hi FROM tw GROUP BY n ORDER BY n"},
    {"SELECT COUNT(*) AS c FROM t WHERE m > n", "SELECT COUNT(*) AS c FROM tw WHERE m > n"},
    {"SELECT id FROM t WHERE m = 'l12' ORDER BY id", "SELECT id FROM tw WHERE m = 12 ORDER BY id"},
};

static int g_nq; /* the queries to run: the last needs label l12 */

static void check_twin(const char *what)
{
    static char a[1 << 16], b[1 << 16];
    for (int i = 0; i < g_nq; i++) {
        if (!g_q[i][1]) continue;
        snprintf(b, sizeof b, "%s", csv(g_q[i][1]));
        unlabel(csv(g_q[i][0]), a, sizeof a);
        if (strcmp(a, b) || !strncmp(b, "ERR", 3)) {
            char m[3000];
            snprintf(m, sizeof m, "%s: %.400s\n      enum: %.900s\n      twin: %.900s", what, g_q[i][0], a, b);
            test_fail(__FILE__, __LINE__, m);
        }
    }
}

static uint64_t g_rs;
static uint64_t rnd(void)
{
    g_rs ^= g_rs << 13;
    g_rs ^= g_rs >> 7;
    g_rs ^= g_rs << 17;
    return g_rs;
}

static void t_enum_paths(void)
{
    const char *dir = test_tmpdir();
    char p[700];
    snprintf(p, sizeof p, "%s/p", dir);
    imdb_err e = {0};
    CHECK(imdb_init(p, false, NULL, &e) == 0);
    imdb_db *db = open_with(p, false, 0);
    CHECK(db);
    if (!db) return;
    OK(run("CREATE TYPE e AS ENUM ('l0', 'l1', 'l2', 'l3', 'l4', 'l5', 'l6', 'l7', 'l8', 'l9', 'l10', 'l11')"));
    OK(run("CREATE TABLE t (id INT64 PRIMARY KEY, m e, n e NOT NULL, x INT64 NOT NULL)"));
    OK(run("CREATE TABLE tw (id INT64 PRIMARY KEY, m INT64, n INT64 NOT NULL, x INT64 NOT NULL)"));
    OK(run("CREATE INDEX tm ON t (m)"));
    OK(run("CREATE INDEX twm ON tw (m)"));
    g_rs = 0x9e3779b97f4a7c15ull;
    char sql[200], sqw[200];
    for (int i = 0; i < ENN; i++) {
        int m = (int)(rnd() % 13), n = (int)(rnd() % 12), x = (int)(rnd() % 100); /* m 12: NULL */
        if (m == 12) {
            snprintf(sql, sizeof sql, "INSERT INTO t VALUES (%d, NULL, 'l%d', %d)", i, n, x);
            snprintf(sqw, sizeof sqw, "INSERT INTO tw VALUES (%d, NULL, %d, %d)", i, n, x);
        } else {
            snprintf(sql, sizeof sql, "INSERT INTO t VALUES (%d, 'l%d', 'l%d', %d)", i, m, n, x);
            snprintf(sqw, sizeof sqw, "INSERT INTO tw VALUES (%d, %d, %d, %d)", i, m, n, x);
        }
        OK(run(sql));
        OK(run(sqw));
    }
    g_nq = (int)(sizeof g_q / sizeof *g_q) - 1;
    OK(run("SET cross_check = on"));
    uint8_t d0[32], d1[32];
    digest_of(db, d0);
    for (int pass = 0; pass < 5; pass++) {
        static const char *const what[5] = {"in memory", "after a CHECKPOINT", "at a budget of none", "after a reopen",
                                            "after a full replay"};
        if (pass == 1) OK(run("CHECKPOINT"));
        if (pass == 2) db->segcache.budget = 0;
        if (pass >= 3) {
            done(db);
            db = open_with(p, pass == 4, 0);
            CHECK(db);
            if (!db) return;
            OK(run("SET cross_check = on"));
            digest_of(db, d1);
            CHECK(memcmp(d0, d1, 32) == 0);
        }
        check_twin(what[pass]);
    }
    /* a label appended after a CHECKPOINT: the older segments' ordinals unchanged, the new one read from memory and lake */
    OK(run("ALTER TYPE e ADD VALUE 'l12'"));
    for (int i = ENN; i < ENN + 40; i++) {
        snprintf(sql, sizeof sql, "INSERT INTO t VALUES (%d, 'l12', 'l%d', %d)", i, i % 12, i % 100);
        snprintf(sqw, sizeof sqw, "INSERT INTO tw VALUES (%d, 12, %d, %d)", i, i % 12, i % 100);
        OK(run(sql));
        OK(run(sqw));
    }
    OK(run("UPDATE t SET m = 'l12' WHERE id % 17 = 0"));
    OK(run("UPDATE tw SET m = 12 WHERE id % 17 = 0"));
    g_nq = (int)(sizeof g_q / sizeof *g_q);
    check_twin("labels appended, in memory");
    OK(run("CHECKPOINT"));
    check_twin("labels appended, from the lake");
    db->segcache.budget = 0;
    check_twin("labels appended, at a budget of none");
    CHECK(verify_db(db) == 0);
    digest_of(db, d0);
    done(db);
    db = open_with(p, true, 0);
    CHECK(db);
    if (!db) return;
    digest_of(db, d1);
    CHECK(memcmp(d0, d1, 32) == 0);
    OK(run("SET cross_check = on"));
    check_twin("labels appended, after a full replay");
    done(db);
    CHECK(audit_dir(p) == 0);
}

/* ---- the text forms through every copy ------------------------------------------------------------------------------- */

typedef struct outb {
    char *p;
    size_t n, cap;
} outb;

static int outb_write(void *arg, const char *b, size_t n)
{
    outb *o = arg;
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

/* a dump restored as imagedb sql -f restores it: a statement its lines until its quotes close (a label may hold a
 * newline), a COPY's data the lines up to a \. line */
static int restore_text(const char *s, size_t n)
{
    static char st[1 << 15];
    size_t at = 0;
    while (at < n) {
        size_t sl = 0;
        int quotes = 0;
        if (n - at >= 2 && s[at] == '-' && s[at + 1] == '-') { /* a comment line, whole (its apostrophes are no quotes) */
            while (at < n && s[at] != '\n') at++;
            at += at < n;
            continue;
        }
        for (;;) { /* a statement's lines while a string is open */
            size_t eol = at;
            while (eol < n && s[eol] != '\n') eol++;
            if (sl + (eol - at) + 2 >= sizeof st) return -1;
            if (sl) st[sl++] = '\n';
            memcpy(st + sl, s + at, eol - at);
            for (size_t k = at; k < eol; k++) quotes += s[k] == '\'';
            sl += eol - at;
            at = eol < n ? eol + 1 : n;
            if (!(quotes & 1) || at >= n) break;
        }
        st[sl] = 0;
        if (!sl || !strncmp(st, "--", 2)) continue;
        if (strncmp(st, "COPY ", 5)) {
            if (run(st)) {
                fprintf(stderr, "    restore: %s: %.200s\n", g_e.msg, st);
                return -1;
            }
            continue;
        }
        size_t k = at;
        bool bol = true, inq = false;
        for (; k < n; k++) {
            if (bol && !inq && s[k] == '\\' && k + 1 < n && s[k + 1] == '.' && (k + 2 == n || s[k + 2] == '\n')) break;
            if (s[k] == '"') inq = !inq;
            bol = s[k] == '\n';
        }
        g_in = (mem_in){s + at, k - at, 0};
        if (run(st)) return -1;
        at = k + 3 <= n ? k + 3 : n;
    }
    return 0;
}

static void t_enum_copies(void)
{
    const char *dir = test_tmpdir();
    char p[700], q[700], r[700], sf[760];
    snprintf(p, sizeof p, "%s/p", dir);
    snprintf(q, sizeof q, "%s/q", dir);
    snprintf(r, sizeof r, "%s/r", dir);
    snprintf(sf, sizeof sf, "%s/stream", dir);
    imdb_err e = {0};
    CHECK(imdb_init(p, false, NULL, &e) == 0);
    imdb_db *db = open_with(p, false, 0);
    CHECK(db);
    if (!db) return;
    OK(run("CREATE TYPE e4 AS ENUM ('', 'a,b', 'x\"y', 'it''s', 'l\nm', 'plain')"));
    OK(run("CREATE TABLE u (id INT64 PRIMARY KEY, e e4, f e4 NOT NULL DEFAULT 'it''s')"));
    OK(run("INSERT INTO u VALUES (1, '', 'plain'), (2, 'a,b', ''), (3, 'x\"y', 'l\nm'), (4, 'it''s', 'a,b'), (5, 'l\nm', 'x\"y')"));
    OK(run("INSERT INTO u (id) VALUES (6)"));
    static const char want[] = "id,e,f\n1,\"\",\"plain\"\n2,\"a,b\",\"\"\n3,\"x\"\"y\",\"l\nm\"\n4,\"it's\",\"a,b\"\n"
                               "5,\"l\nm\",\"x\"\"y\"\n6,,\"it's\"\n";
    EXPECT("SELECT * FROM u ORDER BY id", want);
    /* COPY both ways: '' quoted (an unquoted empty field is NULL), the rest as TEXT's */
    g_copyn = 0;
    g_copy[0] = 0;
    EXPECT("COPY u TO STDOUT", "COPY 6");
    CHECK(!strcmp(g_copy, "1,\"\",plain\n2,\"a,b\",\"\"\n3,\"x\"\"y\",\"l\nm\"\n4,it's,\"a,b\"\n5,\"l\nm\",\"x\"\"y\"\n6,,it's\n"));
    OK(run("CREATE TABLE u2 (id INT64 PRIMARY KEY, e e4, f e4 NOT NULL)"));
    static char data[1 << 14];
    snprintf(data, sizeof data, "%s", g_copy);
    g_in = (mem_in){data, strlen(data), 0};
    EXPECT("COPY u2 FROM STDIN", "COPY 6");
    EXPECT("SELECT * FROM u2 ORDER BY id", want);
    g_in = (mem_in){"7,nope,plain\n", 13, 0};
    EXPECT("COPY u2 FROM STDIN", "ERR not a label of type e4");
    OK(run("CHECKPOINT"));
    EXPECT("SELECT * FROM u ORDER BY id", want);
    CHECK(verify_db(db) == 0);
    /* the dump, restored into a fresh database and dumped again alike */
    outb o1 = {0};
    OK(imdb_dump(db, 0, outb_write, &o1, &e));
    CHECK(o1.p && strstr(o1.p, "CREATE TYPE e4 AS ENUM ('', 'a,b', 'x\"y', 'it''s', 'l\nm', 'plain');") &&
          strstr(o1.p, "f e4 NOT NULL DEFAULT 'it''s'"));
    uint8_t d0[32], d1[32];
    digest_of(db, d0);
    done(db);
    CHECK(audit_dir(p) == 0);
    /* a replica at the primary's digest */
    imdb_identity id;
    OK(imdb_identity_read(p, &id, NULL, &g_e));
    OK(imdb_init_replica(q, &id, &g_e));
    OK(ship_to_file(p, 0, sf, &g_e));
    imdb_open_opts ro = {.sync = 0};
    imdb_db *rep = NULL;
    CHECK(imdb_open(q, &ro, &rep, &e) == 0);
    if (rep) {
        uint64_t applied = 0;
        OK(apply_file(rep, sf, &applied, &g_e));
        digest_of(rep, d1);
        CHECK(memcmp(d0, d1, 32) == 0);
        imdb_close(rep);
    }
    CHECK(audit_dir(q) == 0);
    CHECK(imdb_init(r, false, NULL, &e) == 0);
    imdb_db *rdb = open_with(r, false, 0);
    CHECK(rdb);
    if (rdb && o1.p) {
        CHECK(restore_text(o1.p, o1.n) == 0);
        outb o2 = {0};
        OK(imdb_dump(rdb, 0, outb_write, &o2, &e));
        CHECK(o2.p && strchr(o1.p, '\n') && strchr(o2.p, '\n') && !strcmp(strchr(o1.p, '\n'), strchr(o2.p, '\n')));
        EXPECT("SELECT * FROM u ORDER BY id", want);
        CHECK(verify_db(rdb) == 0);
        free(o2.p);
    }
    if (rdb) done(rdb);
    CHECK(audit_dir(r) == 0);
    free(o1.p);
}


/* the advisor's (16:5x): an ENUM column added with a DEFAULT after a CHECKPOINT, read from older segments, flushed and read
 * at a budget of none; labels' commits read back from a manifest by a snapshot open (AS OF before an ADD VALUE refusing the
 * label); FOREIGN KEYs and a UNIQUE index on ENUM columns; a derived table over a UNION of ENUMs (its type in the
 * bind-only pass, a view's probe too); a replica seeded past a RETIRE whose cut drops the CREATE TYPE (FLOOR's types) */
static void t_enum_more(void)
{
    const char *dir = test_tmpdir();
    char p[700], r[700], sf[760];
    snprintf(p, sizeof p, "%s/p", dir);
    snprintf(r, sizeof r, "%s/r", dir);
    snprintf(sf, sizeof sf, "%s/stream", dir);
    imdb_err e = {0};
    CHECK(imdb_init(p, false, NULL, &e) == 0 && imdb_init(r, true, p, &e) == 0);
    imdb_open_opts o = {.sync = 0, .floor_stride = 1};
    imdb_db *db = NULL;
    if (imdb_open(p, &o, &db, &e)) return;
    imdb_session_init(&g_s, db);
    imdb_session_copy_io(&g_s, mem_read, mem_write, &g_in);
    db->no_auto_retire = true;
    imdb_clock_freeze(1772953198ull * 1000000ull);
    OK(run("CREATE TYPE mood AS ENUM ('sad', 'ok', 'happy')"));
    OK(run("CREATE TYPE ab AS ENUM ('a', 'b')"));
    OK(run("CREATE TABLE t (id INT64 PRIMARY KEY, v INT64) RETENTION 10 SECONDS"));
    OK(run("INSERT INTO t VALUES (1, 10), (2, 20), (3, 30)"));
    OK(run("CHECKPOINT"));
    uint64_t first = db->seq + 1;
    /* an ADD with a DEFAULT after the CHECKPOINT: the older segment's rows read it as their missing value */
    OK(run("ALTER TABLE t ADD COLUMN m mood NOT NULL DEFAULT 'happy'"));
    OK(run("INSERT INTO t (id, v, m) VALUES (4, 40, 'sad')"));
    EXPECT("SELECT id, m FROM t ORDER BY id", "id,m\n1,\"happy\"\n2,\"happy\"\n3,\"happy\"\n4,\"sad\"\n");
    OK(run("UPDATE t SET v = v + 1 WHERE id = 2")); /* an older segment's row written whole, its m the missing value */
    OK(run("ALTER TYPE mood ADD VALUE 'ecstatic'"));
    uint64_t added = db->seq;
    OK(run("ALTER TABLE t ALTER COLUMN m SET DEFAULT 'ecstatic'"));
    OK(run("INSERT INTO t (id, v) VALUES (5, 50)"));
    OK(run("CHECKPOINT"));
    db->segcache.budget = 0;
    EXPECT("SELECT id, v, m FROM t ORDER BY id", "id,v,m\n1,10,\"happy\"\n2,21,\"happy\"\n3,30,\"happy\"\n4,40,\"sad\"\n5,50,\"ecstatic\"\n");
    EXPECT("SELECT m, COUNT(*) AS c FROM t GROUP BY m ORDER BY m", "m,c\n\"sad\",1\n\"happy\",3\n\"ecstatic\",1\n");
    /* FOREIGN KEYs between ENUM columns of one type; across two refused; a UNIQUE index on one */
    OK(run("CREATE TABLE par (k mood PRIMARY KEY, w INT64) RETENTION 10 SECONDS"));
    OK(run("INSERT INTO par VALUES ('ok', 1), ('happy', 2)"));
    EXPECT("CREATE TABLE ch (id INT64 PRIMARY KEY, k mood REFERENCES par (k)) RETENTION 10 SECONDS", "CREATE TABLE ch");
    EXPECT("CREATE TABLE ch2 (id INT64 PRIMARY KEY, k ab REFERENCES par (k))", "ERR foreign key");
    OK(run("INSERT INTO ch VALUES (1, 'ok')"));
    EXPECT("INSERT INTO ch VALUES (2, 'sad')", "ERR violates foreign key");
    EXPECT("DELETE FROM par WHERE k = 'ok'", "ERR violates foreign key");
    OK(run("CREATE TABLE uq (id INT64 PRIMARY KEY, x ab) RETENTION 10 SECONDS"));
    OK(run("CREATE UNIQUE INDEX uqx ON uq (x)"));
    OK(run("INSERT INTO uq VALUES (1, 'a'), (2, 'b'), (3, NULL)"));
    EXPECT("INSERT INTO uq VALUES (4, 'a')", "ERR duplicate key");
    EXPECT("SELECT id FROM uq WHERE x = 'b'", "id\n2\n");
    /* a derived table over a UNION of ENUMs, and a view of it */
    EXPECT("SELECT q.m FROM (SELECT m FROM t UNION SELECT k FROM par) AS q ORDER BY q.m", "m\n\"sad\"\n\"ok\"\n\"happy\"\n\"ecstatic\"\n");
    EXPECT("CREATE VIEW vu AS SELECT q.m FROM (SELECT m FROM t UNION SELECT k FROM par) AS q", "CREATE VIEW vu");
    EXPECT("SELECT MAX(m) AS h FROM vu", "h\n\"ecstatic\"\n");
    OK(run("DROP VIEW vu"));
    /* a snapshot open reads each label's commit from the manifest: AS OF before the ADD VALUE refuses its label */
    done(db);
    db = NULL;
    CHECK(imdb_open(p, &o, &db, &e) == 0);
    if (!db) return;
    imdb_session_init(&g_s, db);
    imdb_session_copy_io(&g_s, mem_read, mem_write, &g_in);
    db->no_auto_retire = true;
    char q[200];
    snprintf(q, sizeof q, "SELECT COUNT(*) AS c FROM t AS OF %llu WHERE m = 'ecstatic'", (unsigned long long)added - 1);
    EXPECT(q, "ERR not a label of type mood");
    snprintf(q, sizeof q, "SELECT COUNT(*) AS c FROM t AS OF %llu WHERE m = 'ecstatic'", (unsigned long long)added);
    EXPECT(q, "c\n0\n");
    /* a RETIRE whose cut drops the CREATE TYPEs: a replica seeded from FLOOR holds them, at the primary's digest */
    imdb_clock_offset(15 * 1000000ll);
    OK(run("SELECT COUNT(*) FROM t"));
    imdb_err_clear(&g_e);
    OK(imdb_retire(db, first - 1, &g_e));
    OK(run("ALTER TYPE ab ADD VALUE 'c'"));
    OK(run("INSERT INTO uq VALUES (5, 'c')"));
    uint8_t d0[32], d1[32];
    digest_of(db, d0);
    CHECK(verify_db(db) == 0);
    done(db);
    CHECK(audit_dir(p) == 0);
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
    }
    if (rdb) {
        digest_of(rdb, d1);
        CHECK(memcmp(d0, d1, 32) == 0);
        CHECK(rdb->nenums == 2 && rdb->enums[0].def->n == 4 && rdb->enums[1].def->n == 3);
        imdb_close(rdb);
    }
    CHECK(audit_dir(r) == 0);
}


/* the advisor's (18:4x): keys of several columns holding an ENUM, the engine's key encoding and the auditor's own key maps
 * apart: PRIMARY KEY (m, id), a UNIQUE index on (x, v), a join on two pairs (both plans, cross-checked), ON CONFLICT on the
 * key; through a CHECKPOINT, at a budget of none, a transaction older than an eviction searching the lake for its key
 * (refused where its view holds the key in the lake alone, taken for a key sharing a held one's first column), a full
 * replay at the same digest, VERIFY and the auditor */
static void t_enum_ckey(void)
{
    const char *dir = test_tmpdir();
    char p[700];
    snprintf(p, sizeof p, "%s/p", dir);
    imdb_err e = {0};
    CHECK(imdb_init(p, false, NULL, &e) == 0);
    imdb_db *db = open_with(p, false, 0);
    CHECK(db);
    if (!db) return;
    OK(run("CREATE TYPE mood AS ENUM ('sad', 'ok', 'happy')"));
    OK(run("CREATE TYPE ab AS ENUM ('b', 'a')"));
    OK(run("CREATE TABLE ck (m mood, id INT64, v INT64, x ab, PRIMARY KEY (m, id))"));
    OK(run("CREATE UNIQUE INDEX ckx ON ck (x, v)"));
    OK(run("CREATE TABLE cq (m mood, id INT64, w INT64, PRIMARY KEY (id, m))"));
    OK(run("INSERT INTO ck VALUES ('ok', 1, 10, 'a'), ('ok', 2, 20, 'a'), ('happy', 1, 30, 'b'), ('sad', 1, 10, 'b')"));
    OK(run("INSERT INTO cq VALUES ('ok', 2, 200), ('happy', 1, 100), ('sad', 9, 900)"));
    OK(run("SET cross_check = on"));
    static const char *const Q[][2] = {
        {"SELECT v FROM ck WHERE m = 'ok' AND id = 2", "v\n20\n"},
        {"SELECT m, id FROM ck WHERE x = 'b' AND v = 10", "m,id\n\"sad\",1\n"},
        {"SELECT m, id, v FROM ck ORDER BY m, id", "m,id,v\n\"sad\",1,10\n\"ok\",1,10\n\"ok\",2,20\n\"happy\",1,30\n"},
        {"SELECT ck.v, cq.w FROM ck JOIN cq ON ck.m = cq.m AND ck.id = cq.id ORDER BY 1", "v,w\n20,200\n30,100\n"},
        {"SELECT x, v FROM ck ORDER BY x, v", "x,v\n\"b\",10\n\"b\",30\n\"a\",10\n\"a\",20\n"},
    };
    for (int pass = 0; pass < 3; pass++) {
        if (pass == 1) OK(run("CHECKPOINT"));
        if (pass == 2) db->segcache.budget = 0;
        for (size_t i = 0; i < sizeof Q / sizeof *Q; i++) EXPECT(Q[i][0], Q[i][1]);
    }
    EXPECT("INSERT INTO ck VALUES ('ok', 1, 99, 'b')", "ERR duplicate primary key");
    EXPECT("INSERT INTO ck VALUES ('ok', 3, 10, 'a')", "ERR duplicate key");
    EXPECT("INSERT INTO ck VALUES ('ok', 1, 11, 'a') ON CONFLICT (id, m) DO UPDATE SET v = ck.v + 1 RETURNING m, id, v",
           "m,id,v\n\"ok\",1,11\n");
    /* a transaction older than an eviction: its key search reaches the lake, every key column compared */
    imdb_session s2;
    imdb_session_init(&s2, db);
    imdb_result r;
    CHECK(imdb_exec_one(&s2, XQ("BEGIN"), NULL, 0, &r, &g_e) == 0);
    imdb_result_free(&r);
    CHECK(imdb_exec_one(&s2, XQ("SELECT v FROM ck WHERE m = 'ok' AND id = 1"), NULL, 0, &r, &g_e) == 0);
    imdb_result_free(&r);
    OK(run("UPDATE ck SET v = 40 WHERE m = 'happy' AND id = 1"));
    OK(run("DELETE FROM ck WHERE m = 'sad' AND id = 1"));
    OK(run("CHECKPOINT"));
    CHECK(imdb_evict(db, db->lake_seq, &e) == 0 && s2.txn.snap < db->mem_floor);
    CHECK(imdb_exec_one(&s2, XQ("INSERT INTO ck VALUES ('sad', 1, 77, 'a')"), NULL, 0, &r, &g_e) == IMDB_ERR_CONSTRAINT);
    CHECK(imdb_exec_one(&s2, XQ("INSERT INTO ck VALUES ('sad', 2, 78, 'a')"), NULL, 0, &r, &g_e) == 0);
    if (!g_e.code) imdb_result_free(&r);
    CHECK(imdb_exec_one(&s2, XQ("COMMIT"), NULL, 0, &r, &g_e) == 0);
    if (!g_e.code) imdb_result_free(&r);
    imdb_session_close(&s2);
    EXPECT("SELECT m, id, v FROM ck ORDER BY m, id", "m,id,v\n\"sad\",2,78\n\"ok\",1,11\n\"ok\",2,20\n\"happy\",1,40\n");
    uint8_t d0[32], d1[32];
    digest_of(db, d0);
    CHECK(verify_db(db) == 0);
    done(db);
    CHECK(audit_dir(p) == 0);
    db = open_with(p, true, 0);
    CHECK(db);
    if (!db) return;
    digest_of(db, d1);
    CHECK(memcmp(d0, d1, 32) == 0);
    OK(run("SET cross_check = on"));
    EXPECT("SELECT ck.v, cq.w FROM ck JOIN cq ON ck.m = cq.m AND ck.id = cq.id ORDER BY 1", "v,w\n20,200\n40,100\n");
    EXPECT("SELECT m, id FROM ck WHERE x = 'a' AND v = 78", "m,id\n\"sad\",2\n");
    done(db);
}

const test_case enum_tests[] = {
    {"enum_codec", t_enum_codec},
    {"enum_sql", t_enum_sql},
    {"enum_paths", t_enum_paths},
    {"enum_copies", t_enum_copies},
    {"enum_more", t_enum_more},
    {"enum_ckey", t_enum_ckey},
};
const size_t enum_ntests = sizeof enum_tests / sizeof *enum_tests;
