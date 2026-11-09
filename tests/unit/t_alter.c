/* F1: ALTER TABLE's schema versions (docs/format-design-v7.md section 3; docs/plan-p2.md 2026-11-07 19:1x-20:4x). Rows keep
 * the bytes of the version their begin had; a segment is the version that built it, an image laid out for the table's
 * last (a column it lacks a constant of its missing value); the manifest carries each table's history. Each test
 * against an answer it does not derive: a twin table created with the final schema and given the same rows, the
 * rules' messages, VERIFY and the auditor. */
#include <stdlib.h>

#include "../../src/backup.h"
#include "../../src/db_internal.h"
#include "../../src/lake.h"
#include "../../src/sql.h"
#include "thelp.h"

static imdb_session g_s;
static char g_out[1 << 20];

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

/* tmpl with every {T} replaced by tbl */
static void qfor(const char *tmpl, const char *tbl, char *out, size_t n)
{
    size_t o = 0;
    for (const char *p = tmpl; *p && o + 1 < n; p++) {
        if (p[0] == '{' && p[1] == 'T' && p[2] == '}') {
            for (const char *q = tbl; *q && o + 1 < n; q++) out[o++] = *q;
            p += 2;
        } else {
            out[o++] = *p;
        }
    }
    out[o] = 0;
}

/* both tables answer each query alike, under every access path with cross_check on */
static const char *const kQueries[] = {
    "SELECT * FROM {T} ORDER BY id",
    "SELECT id FROM {T} WHERE n = 5 ORDER BY id",
    "SELECT id FROM {T} WHERE n > 6 ORDER BY id",
    "SELECT id FROM {T} WHERE n BETWEEN 4 AND 8 ORDER BY id",
    "SELECT id FROM {T} WHERE n <> 5 ORDER BY id",
    "SELECT id FROM {T} WHERE c = 'dflt' ORDER BY id",
    "SELECT id FROM {T} WHERE c IS NULL ORDER BY id",
    "SELECT id FROM {T} WHERE c > 'd' ORDER BY id",
    "SELECT id FROM {T} WHERE b IS NULL ORDER BY id",
    "SELECT id FROM {T} WHERE b IS NOT NULL ORDER BY id",
    "SELECT id FROM {T} WHERE b ORDER BY id",
    "SELECT id FROM {T} WHERE f = 1.5 ORDER BY id",
    "SELECT id FROM {T} WHERE f > 2.0 ORDER BY id",
    "SELECT id FROM {T} WHERE d > 2.00 ORDER BY id",
    "SELECT id FROM {T} WHERE d = 2.50 ORDER BY id",
    "SELECT id FROM {T} WHERE ts IS NULL AND n = 5 ORDER BY id",
    "SELECT id FROM {T} WHERE n = 5 AND xx = 3 ORDER BY id",
    "SELECT id, n, c FROM {T} WHERE id = 450",
    "SELECT id, n, c FROM {T} WHERE id = 120",
    "SELECT COUNT(*), COUNT(n), SUM(n), COUNT(c), COUNT(b), SUM(f), SUM(d), MIN(n), MAX(n) FROM {T}",
    "SELECT COUNT(*), SUM(n) FROM {T} WHERE n = 5",
    "SELECT COUNT(c), SUM(f) FROM {T} WHERE xx IS NULL",
    "SELECT n, COUNT(*) FROM {T} GROUP BY n ORDER BY n",
    "SELECT c, COUNT(*), SUM(n) FROM {T} GROUP BY c ORDER BY c",
    "SELECT xx, SUM(n), MAX(c) FROM {T} WHERE xx IS NOT NULL GROUP BY xx ORDER BY xx",
    "SELECT DISTINCT n FROM {T} ORDER BY n",
    "SELECT id, n FROM {T} ORDER BY n DESC, id LIMIT 20",
    "SELECT {T}.id, k.v FROM {T} JOIN k ON {T}.n = k.n ORDER BY {T}.id, k.v",
    "SELECT id, SUM(n) OVER (ORDER BY id ROWS BETWEEN 2 PRECEDING AND CURRENT ROW) AS s FROM {T} ORDER BY id LIMIT 60",
    "SELECT id, n || c AS nc FROM {T} WHERE id < 30 OR id > 790 ORDER BY id",
};

static void compare_all(const char *phase)
{
    static const char *const paths[] = {"auto", "scan", "store", "index"};
    char qt[600], qw[600], set[64];
    OK(run("SET cross_check = on"));
    for (size_t pi = 0; pi < sizeof paths / sizeof *paths; pi++) {
        snprintf(set, sizeof set, "SET access_path = %s", paths[pi]);
        OK(run(set));
        for (size_t i = 0; i < sizeof kQueries / sizeof *kQueries; i++) {
            qfor(kQueries[i], "t", qt, sizeof qt);
            qfor(kQueries[i], "w", qw, sizeof qw);
            const char *a = csv(qt);
            char *ta = strdup(a);
            const char *b = csv(qw);
            if (!ta || strcmp(ta, b) != 0) {
                char m[1800];
                snprintf(m, sizeof m, "%s, access_path %s: %s\n      t: %.500s\n      w: %.500s", phase, paths[pi], qt,
                         ta ? ta : "?", b);
                test_fail(__FILE__, __LINE__, m);
            }
            free(ta);
        }
    }
    OK(run("SET access_path = auto"));
    OK(run("SET cross_check = off"));
}

/* rows [lo, hi] into t with the columns t has now (ncols of them), and into w with every column, the ones t lacks
 * their missing values (n 5, c 'dflt', f 1.5, b NULL, d 2.50, ts NULL) */
static void put_rows(int lo, int hi, int ncols)
{
    char qt[1 << 14], qw[1 << 14];
    for (int s = lo; s <= hi; s += 40) {
        size_t ot = (size_t)snprintf(qt, sizeof qt, "INSERT INTO t VALUES "), ow = (size_t)snprintf(qw, sizeof qw, "INSERT INTO w VALUES ");
        for (int id = s; id <= hi && id < s + 40; id++) {
            char x[16], n[16], c[24], f[16], b[8], d[16], ts[40];
            if (id % 5 == 0) snprintf(x, sizeof x, "NULL");
            else snprintf(x, sizeof x, "%d", id % 7);
            snprintf(n, sizeof n, "%d", ncols >= 4 ? id % 11 : 5);
            if (ncols >= 5) snprintf(c, sizeof c, id % 3 ? "'c%d'" : "NULL", id % 4);
            else snprintf(c, sizeof c, "'dflt'");
            snprintf(f, sizeof f, ncols >= 6 ? "%d.25" : "1.5", id % 6);
            snprintf(b, sizeof b, ncols >= 7 ? (id % 2 ? "TRUE" : "FALSE") : "NULL");
            snprintf(d, sizeof d, ncols >= 8 ? "%d.75" : "2.50", id % 9);
            snprintf(ts, sizeof ts, ncols >= 9 && id % 4 ? "'2026-11-07 10:%02d:00'" : "NULL", id % 60);
            const char *sep = id == s ? "" : ", ";
            ot += (size_t)snprintf(qt + ot, sizeof qt - ot, "%s(%d, 'a%d', %s", sep, id, id, x);
            if (ncols >= 4) ot += (size_t)snprintf(qt + ot, sizeof qt - ot, ", %s", n);
            if (ncols >= 5) ot += (size_t)snprintf(qt + ot, sizeof qt - ot, ", %s", c);
            if (ncols >= 6) ot += (size_t)snprintf(qt + ot, sizeof qt - ot, ", %s", f);
            if (ncols >= 7) ot += (size_t)snprintf(qt + ot, sizeof qt - ot, ", %s", b);
            if (ncols >= 8) ot += (size_t)snprintf(qt + ot, sizeof qt - ot, ", %s", d);
            if (ncols >= 9) ot += (size_t)snprintf(qt + ot, sizeof qt - ot, ", %s", ts);
            ot += (size_t)snprintf(qt + ot, sizeof qt - ot, ")");
            ow += (size_t)snprintf(qw + ow, sizeof qw - ow, "%s(%d, 'a%d', %s, %s, %s, %s, %s, %s, %s)", sep, id, id, x, n, c, f,
                                   b, d, ts);
        }
        OK(run(qt));
        OK(run(qw));
    }
}

/* both tables through the same writes; t's schema made by ALTERs between them, so that its lake holds segments of four
 * versions (and rows of older versions in a segment of a later one), w created whole */
static void build_twins(void)
{
    OK(run("CREATE TABLE t (id INT64 PRIMARY KEY, a TEXT, x INT64)"));
    OK(run("CREATE TABLE w (id INT64 PRIMARY KEY, a TEXT, xx INT64, n INT64 NOT NULL, c TEXT, f FLOAT64, b BOOL, "
           "d DECIMAL(8,2), ts TIMESTAMP)"));
    OK(run("CREATE TABLE k (kid INT64 PRIMARY KEY, n INT64, v TEXT)"));
    OK(run("INSERT INTO k VALUES (1, 5, 'five'), (2, 77, 'seventy-seven'), (3, 3, 'three'), (4, 5, 'cinq')"));
    put_rows(1, 400, 3);
    OK(run("CHECKPOINT"));                                    /* segment A: version 1 */
    put_rows(401, 600, 3);                                    /* the memtable at version 1 */
    OK(run("ALTER TABLE t ADD n INT64 NOT NULL DEFAULT 5"));  /* version 2 */
    put_rows(601, 700, 4);
    OK(run("CHECKPOINT"));                                    /* segment B: version 2, rows 401-600 of version 1 */
    OK(run("CREATE INDEX tn ON t (n)"));                      /* over every version's rows: the old read 5 */
    OK(run("CREATE INDEX wn ON w (n)"));
    OK(run("ALTER TABLE t ADD COLUMN c TEXT DEFAULT 'dflt'")); /* 3 */
    put_rows(701, 720, 5);
    OK(run("ALTER TABLE t ADD f FLOAT64 DEFAULT 1.5"));       /* 4 */
    put_rows(721, 750, 6);
    OK(run("CHECKPOINT"));                                    /* segment C: version 4, rows of 3 and 4 */
    OK(run("ALTER TABLE t ADD b BOOL"));                      /* 5: nullable, no DEFAULT: NULL */
    OK(run("ALTER TABLE t ADD d DECIMAL(8,2) DEFAULT 2.50")); /* 6 */
    OK(run("ALTER TABLE t ADD ts TIMESTAMP"));                /* 7 */
    OK(run("ALTER TABLE t RENAME COLUMN x TO xx"));           /* 8 */
    put_rows(751, 800, 9);
    for (int k = 0; k < 2; k++) { /* the same writes on both: rows of every version end, new ones at version 8 */
        const char *tb = k ? "w" : "t";
        char q[200];
        snprintf(q, sizeof q, "UPDATE %s SET n = 77 WHERE id %% 13 = 0", tb);
        OK(run(q));
        snprintf(q, sizeof q, "DELETE FROM %s WHERE id %% 17 = 0", tb);
        OK(run(q));
        snprintf(q, sizeof q, "UPDATE %s SET c = NULL, b = TRUE WHERE id %% 19 = 0", tb);
        OK(run(q));
        snprintf(q, sizeof q, "UPDATE %s SET xx = 3 WHERE id %% 23 = 0", tb);
        OK(run(q));
    }
}

/* the differential: t's answers are w's in memory, after a CHECKPOINT, after a reopen from the snapshot (the
 * manifest's history), after COMPACT (old versions' segments rewritten at the last), after a full replay; VERIFY and
 * the auditor pass on it */
static void t_alter_differential(void)
{
    const char *dir = test_tmpdir();
    imdb_db *db = open_fresh(dir);
    CHECK(db);
    if (!db) return;
    build_twins();
    imdb_table *t = imdb_table_by_name(db, "t");
    CHECK(t && t->hist.nvers == 8 && t->s.ncols == 9 && t->nseg == 3);
    if (t) { /* the lake holds segments of versions 1, 2 and 4 */
        bool v[8] = {false};
        for (uint32_t i = 0; i < t->nseg; i++)
            if (t->seg[i]->gver < 8) v[t->seg[i]->gver] = true;
        CHECK(v[0] && v[1] && v[3]);
    }
    compare_all("in memory");
    OK(run("CHECKPOINT"));
    compare_all("after a CHECKPOINT");
    CHECK(verify_db(db) == 0);
    done(db);
    db = open_at(dir, false);
    CHECK(db);
    if (!db) return;
    CHECK(db->t[0]->hist.nvers == 8); /* the manifest's history: no log below it read */
    compare_all("after a reopen");
    OK(run("COMPACT t"));
    OK(run("COMPACT w"));
    compare_all("after COMPACT");
    t = imdb_table_by_name(db, "t");
    if (t)
        for (uint32_t i = 0; i < t->nseg; i++) CHECK(t->seg[i]->gver == 7); /* every segment rewritten at the last */
    CHECK(verify_db(db) == 0);
    done(db);
    db = open_at(dir, true);
    CHECK(db);
    if (!db) return;
    compare_all("after a full replay");
    CHECK(verify_db(db) == 0);
    done(db);
    CHECK(audit_dir(dir) == 0);
}

/* the rules, each refused with its reason and the table unchanged; then the ones that pass, through a reopen */
static void t_alter_rules(void)
{
    const char *dir = test_tmpdir();
    imdb_db *db = open_fresh(dir);
    CHECK(db);
    if (!db) return;
    OK(run("CREATE TABLE t (id INT64 PRIMARY KEY, a TEXT, u INT64)"));
    OK(run("CREATE TABLE u (id INT64 PRIMARY KEY, x INT64)"));
    OK(run("INSERT INTO t VALUES (1, 'x', 1)"));
    OK(run("INSERT INTO u VALUES (1, 7)"));
    EXPECT("ALTER TABLE t ADD a INT64", "ERR column a of table t already exists");
    EXPECT("ALTER TABLE t ADD z INT64 NOT NULL", "ERR NOT NULL");
    EXPECT("ALTER TABLE t ADD z INT64 PRIMARY KEY", "ERR ");
    EXPECT("ALTER TABLE nosuch ADD z INT64", "ERR ");
    EXPECT("ALTER TABLE t RENAME COLUMN a TO u", "ERR column u of table t already exists");
    EXPECT("ALTER TABLE t RENAME COLUMN nosuch TO q", "ERR ");
    EXPECT("ALTER TABLE t RENAME TO u", "ERR a table or view u already exists");
    OK(run("BEGIN"));
    EXPECT("ALTER TABLE t ADD z INT64", "ERR ");
    OK(run("ROLLBACK"));
    /* views: a rename of a table one names is RESTRICTed; an ADD of a name one reading the table holds, through other
     * views too, is refused (its text would bind the name otherwise); an ADD of another name passes */
    OK(run("CREATE VIEW v AS SELECT t.id, a FROM t JOIN u ON t.id = u.id"));
    OK(run("CREATE VIEW vv AS SELECT id AS q FROM v"));
    EXPECT("ALTER TABLE u ADD a INT64", "ERR view v reads table u and names a");
    EXPECT("ALTER TABLE t ADD q INT64", "ERR view vv reads table t and names q");
    EXPECT("ALTER TABLE t RENAME COLUMN u TO uu", "ERR view v names table t");
    EXPECT("ALTER TABLE t RENAME TO tt", "ERR view v names table t");
    imdb_table *t = imdb_table_by_name(db, "t");
    CHECK(t && t->hist.nvers == 1 && t->s.ncols == 3);
    EXPECT("ALTER TABLE u ADD b INT64", "ALTER TABLE u");
    EXPECT("SELECT * FROM v", "id,a\n1,\"x\"\n");
    OK(run("DROP VIEW vv"));
    OK(run("DROP VIEW v"));
    EXPECT("ALTER TABLE u ADD a INT64", "ALTER TABLE u");
    EXPECT("ALTER TABLE t RENAME COLUMN u TO uu", "ALTER TABLE t");
    EXPECT("ALTER TABLE t RENAME TO tt", "ALTER TABLE t");
    EXPECT("SELECT * FROM u", "id,x,b,a\n1,7,,\n");
    EXPECT("SELECT id, uu FROM tt", "id,uu\n1,1\n");
    done(db);
    db = open_at(dir, false); /* the log */
    CHECK(db);
    if (!db) return;
    EXPECT("SELECT id, uu FROM tt", "id,uu\n1,1\n");
    EXPECT("SELECT * FROM u", "id,x,b,a\n1,7,,\n");
    OK(run("CHECKPOINT"));
    done(db);
    db = open_at(dir, false); /* the lake */
    CHECK(db);
    if (!db) return;
    EXPECT("SELECT * FROM u", "id,x,b,a\n1,7,,\n");
    CHECK(verify_db(db) == 0);
    /* 64 positions at most, 256 versions at most */
    OK(run("CREATE TABLE m (id INT64 PRIMARY KEY)"));
    char q[160];
    for (int i = 1; i < 64; i++) {
        snprintf(q, sizeof q, "ALTER TABLE m ADD c%d INT64", i);
        OK(run(q));
    }
    EXPECT("ALTER TABLE m ADD c64 INT64", "ERR ");
    for (int i = 0; i < 192; i++) { /* versions 65 to 256 */
        snprintf(q, sizeof q, "ALTER TABLE m RENAME COLUMN %s", i % 2 ? "r1 TO c1" : "c1 TO r1");
        OK(run(q));
    }
    imdb_table *m = imdb_table_by_name(db, "m");
    CHECK(m && m->hist.nvers == 256);
    EXPECT("ALTER TABLE m RENAME COLUMN c1 TO r1", "ERR 256 schema versions");
    OK(run("CHECKPOINT"));
    done(db);
    db = open_at(dir, false);
    CHECK(db);
    if (!db) return;
    m = imdb_table_by_name(db, "m");
    CHECK(m && m->hist.nvers == 256);
    CHECK(verify_db(db) == 0);
    done(db);
    CHECK(audit_dir(dir) == 0);
}

/* a transaction that wrote the table before an ALTER's commit cannot commit after it; one that wrote another table
 * commits */
static void t_alter_txn(void)
{
    const char *dir = test_tmpdir();
    imdb_db *db = open_fresh(dir);
    CHECK(db);
    if (!db) return;
    OK(run("CREATE TABLE t (id INT64 PRIMARY KEY, a TEXT)"));
    OK(run("CREATE TABLE o (id INT64 PRIMARY KEY)"));
    OK(run("INSERT INTO t VALUES (1, 'x')"));
    OK(run("CHECKPOINT")); /* the lake's commit before the ALTER: VERIFY and the auditor check its history there */
    imdb_session s2, s3;
    imdb_session_init(&s2, db);
    imdb_session_init(&s3, db);
    imdb_result r;
    imdb_err e2 = {0};
    const char *b = "BEGIN", *w = "INSERT INTO t VALUES (2, 'y')", *w3 = "INSERT INTO o VALUES (9)", *c = "COMMIT";
    OK(imdb_exec_one(&s2, b, strlen(b), NULL, 0, &r, &e2));
    imdb_result_free(&r);
    OK(imdb_exec_one(&s2, w, strlen(w), NULL, 0, &r, &e2));
    imdb_result_free(&r);
    OK(imdb_exec_one(&s3, b, strlen(b), NULL, 0, &r, &e2));
    imdb_result_free(&r);
    OK(imdb_exec_one(&s3, w3, strlen(w3), NULL, 0, &r, &e2));
    imdb_result_free(&r);
    EXPECT("ALTER TABLE t ADD n INT64 DEFAULT 4", "ALTER TABLE t");
    imdb_err_clear(&e2);
    CHECK(imdb_exec_one(&s2, c, strlen(c), NULL, 0, &r, &e2) != 0 && strstr(e2.msg, "altered") != NULL);
    imdb_err_clear(&e2);
    OK(imdb_exec_one(&s3, c, strlen(c), NULL, 0, &r, &e2));
    imdb_result_free(&r);
    imdb_session_close(&s2);
    imdb_session_close(&s3);
    EXPECT("SELECT * FROM t ORDER BY id", "id,a,n\n1,\"x\",4\n");
    EXPECT("SELECT * FROM o", "id\n9\n");
    EXPECT("INSERT INTO t VALUES (2, 'y', 8)", "INSERT 1");
    EXPECT("SELECT * FROM t ORDER BY id", "id,a,n\n1,\"x\",4\n2,\"y\",8\n");
    CHECK(verify_db(db) == 0);
    done(db);
    CHECK(audit_dir(dir) == 0);
}

/* past a RETIRE whose cut drops the ALTERs' commits, the snapshot open, VERIFY and the auditor take the history from
 * FLOOR's manifest alone */
static void t_alter_retire(void)
{
    const char *dir = test_tmpdir();
    imdb_db *db = NULL;
    {
        imdb_err e = {0};
        if (imdb_init(dir, false, NULL, &e)) return;
        imdb_open_opts o = {.sync = 0, .floor_stride = 1};
        if (imdb_open(dir, &o, &db, &e)) return;
        imdb_session_init(&g_s, db);
    }
    db->no_auto_retire = true;
    OK(run("CREATE TABLE t (id INT64 PRIMARY KEY, v INT64) RETENTION 10 SECONDS"));
    OK(run("INSERT INTO t VALUES (1, 0), (2, 0)"));
    OK(run("ALTER TABLE t ADD n INT64 NOT NULL DEFAULT 5"));
    OK(run("ALTER TABLE t ADD c TEXT DEFAULT 'old'"));
    for (int i = 1; i <= 3; i++) {
        char q[100];
        snprintf(q, sizeof q, "UPDATE t SET v = %d WHERE id = 1", i);
        OK(run(q));
    }
    OK(run("CHECKPOINT"));
    uint64_t first = db->seq + 1;
    OK(run("UPDATE t SET v = 100 WHERE id = 1"));
    OK(run("CHECKPOINT"));
    imdb_clock_offset(15 * 1000000ll);
    OK(run("SELECT COUNT(*) FROM t")); /* the policy moves the horizon to the second segment's start */
    imdb_err_clear(&g_e);
    OK(imdb_retire(db, first - 1, &g_e));
    EXPECT("SELECT id, v, n, c FROM t ORDER BY id", "id,v,n,c\n1,100,5,\"old\"\n2,0,5,\"old\"\n");
    done(db);
    imdb_open_opts o = {.sync = 0, .floor_stride = 1};
    imdb_err e = {0};
    CHECK(imdb_open(dir, &o, &db, &e) == 0);
    if (!db) return;
    imdb_session_init(&g_s, db);
    CHECK(db->log_floor > 0 && db->t[0]->hist.nvers == 3);
    EXPECT("SELECT id, v, n, c FROM t ORDER BY id", "id,v,n,c\n1,100,5,\"old\"\n2,0,5,\"old\"\n");
    EXPECT("INSERT INTO t VALUES (3, 3, 6, 'new')", "INSERT 1");
    /* past the cut: an ALTER, then COMPACT rewrites the rows begun before F at the new version (the floor seeds of
     * VERIFY and the auditor read segments of a version F's history lacks), a UNIQUE index and an UPDATE (the
     * auditor decodes the seeded rows' payloads by their own version) */
    EXPECT("ALTER TABLE t ADD z INT64 DEFAULT 1", "ALTER TABLE t");
    OK(run("COMPACT t"));
    EXPECT("CREATE UNIQUE INDEX tv ON t (v)", "CREATE UNIQUE INDEX tv");
    EXPECT("UPDATE t SET v = 7 WHERE id = 2", "UPDATE 1");
    EXPECT("SELECT id, v, n, c, z FROM t ORDER BY id", "id,v,n,c,z\n1,100,5,\"old\",1\n2,7,5,\"old\",1\n3,3,6,\"new\",1\n");
    CHECK(verify_db(db) == 0);
    done(db);
    CHECK(audit_dir(dir) == 0);
}

/* the manifest's history refused when it does not hold: a count past its ALTERs, an ALTER at the CREATE's commit or
 * past the snapshot's, one that does not end at the table's schema */
static void t_alter_manifest(void)
{
    const char *dir = test_tmpdir();
    imdb_db *db = open_fresh(dir);
    CHECK(db);
    if (!db) return;
    OK(run("CREATE TABLE t (id INT64 PRIMARY KEY, a TEXT)"));
    OK(run("INSERT INTO t VALUES (1, 'x')"));
    OK(run("ALTER TABLE t ADD zqn INT64 NOT NULL DEFAULT 5"));
    OK(run("ALTER TABLE t RENAME COLUMN a TO zqa"));
    OK(run("CHECKPOINT"));
    size_t n = db->lake_mlen;
    uint8_t *b = malloc(n), *w = malloc(n);
    CHECK(b && w);
    if (!b || !w) {
        free(b);
        free(w);
        done(db);
        return;
    }
    memcpy(b, db->lake_mbytes, n);
    imdb_manifest m;
    imdb_err_clear(&g_e);
    OK(imdb_manifest_parse(b, n, &m, &g_e));
    CHECK(m.nt == 1 && m.t[0].hist.nvers == 3);
    uint64_t seq = m.seq, created = m.t[0].created_at;
    imdb_manifest_free(&m);
    /* the ADD's body: u8 kind 1, u8 3, "zqn": its u64 commit just before it, the u32 count before version 1's schema */
    size_t add = 0, ren = 0;
    for (size_t i = n - 4; i > 0; i--) { /* the last: the table's schema, before its history, holds both names too */
        if (!add && b[i] == 1 && b[i + 1] == 3 && memcmp(b + i + 2, "zqn", 3) == 0) add = i;
        if (!ren && b[i] == 3 && memcmp(b + i + 1, "zqa", 3) == 0) ren = i;
    }
    CHECK(add > 8 && ren > add);
    if (add > 8 && ren > add) {
        uint64_t at = imdb_get_le64(b + add - 8);
        CHECK(at > created && at < seq);
        memcpy(w, b, n); /* at the CREATE's commit */
        imdb_le64(w + add - 8, created);
        imdb_err_clear(&g_e);
        CHECK(imdb_manifest_parse(w, n, &m, &g_e) == IMDB_ERR_CORRUPT);
        memcpy(w, b, n); /* past the snapshot */
        imdb_le64(w + add - 8, seq + 1);
        imdb_err_clear(&g_e);
        CHECK(imdb_manifest_parse(w, n, &m, &g_e) == IMDB_ERR_CORRUPT);
        memcpy(w, b, n); /* the rename's new name another: the history ends elsewhere than the schema */
        w[ren + 3] = 'b';
        imdb_err_clear(&g_e);
        CHECK(imdb_manifest_parse(w, n, &m, &g_e) == IMDB_ERR_CORRUPT);
        memcpy(w, b, n); /* the ADD's DEFAULT gone (has 0): a NOT NULL column without one */
        w[add + 2 + 3 + 4] = 0;
        imdb_err_clear(&g_e);
        CHECK(imdb_manifest_parse(w, n, &m, &g_e) == IMDB_ERR_CORRUPT);
    }
    free(b);
    free(w);
    done(db);
}


/* an ADD's DEFAULT is the column's for the writes after it too (PostgreSQL's): INSERT, INSERT ... SELECT and COPY
 * leaving the column out write it; NULL for a column without one, refused when NOT NULL (a CREATE's columns have none) */
static void t_alter_default(void)
{
    const char *dir = test_tmpdir();
    imdb_db *db = open_fresh(dir);
    CHECK(db);
    if (!db) return;
    OK(run("CREATE TABLE t (id INT64 PRIMARY KEY, a TEXT, z INT64 NOT NULL)"));
    OK(run("INSERT INTO t VALUES (1, 'x', 0)"));
    OK(run("ALTER TABLE t ADD s TEXT DEFAULT 'q'"));
    OK(run("ALTER TABLE t ADD n INT64 NOT NULL DEFAULT 5"));
    OK(run("ALTER TABLE t ADD m INT64"));
    EXPECT("INSERT INTO t (id, a) VALUES (2, 'y')", "ERR column z needs a value: it is NOT NULL");
    EXPECT("INSERT INTO t (id, z) VALUES (2, 1)", "INSERT 1");
    EXPECT("INSERT INTO t (id, z, s, n) VALUES (3, 1, NULL, 9)", "INSERT 1");
    EXPECT("INSERT INTO t (id, a, z, m) SELECT id + 10, a, z, 7 FROM t", "INSERT 3");
    const char *want = "id,a,z,s,n,m\n1,\"x\",0,\"q\",5,\n2,,1,\"q\",5,\n3,,1,,9,\n11,\"x\",0,\"q\",5,7\n12,,1,\"q\",5,7\n"
                       "13,,1,\"q\",5,7\n"; /* 13 copies 3, but the list leaves s out: its DEFAULT */
    EXPECT("SELECT * FROM t ORDER BY id", want);
    OK(run("CHECKPOINT"));
    done(db);
    db = open_at(dir, false);
    CHECK(db);
    if (!db) return;
    EXPECT("SELECT * FROM t ORDER BY id", want);
    EXPECT("INSERT INTO t (id, z) VALUES (4, 2)", "INSERT 1"); /* the DEFAULT through a reopen from the snapshot */
    EXPECT("SELECT s, n, m FROM t WHERE id = 4", "s,n,m\n\"q\",5,\n");
    CHECK(verify_db(db) == 0);
    done(db);
    CHECK(audit_dir(dir) == 0);
}


/* the table's rows as text, read by a session of its own on db */
static char *rows_of(imdb_db *db, const char *sql)
{
    imdb_session s;
    imdb_session_init(&s, db);
    imdb_result r;
    imdb_err e = {0};
    char *out = NULL;
    int xrc = imdb_exec_one(&s, sql, strlen(sql), NULL, 0, &r, &e);
    if (!xrc) {
        imdb_buf b;
        imdb_buf_init(&b);
        imdb_result_render(&r, true, &b);
        if (!imdb_buf_check(&b, &e) && (out = malloc(b.len + 1))) {
            memcpy(out, b.p, b.len);
            out[b.len] = 0;
        }
        imdb_buf_free(&b);
        imdb_result_free(&r);
    }
    imdb_session_close(&s);
    return out;
}

/* an altered table through every copy: ERASE SUBJECT (segments rebuilt from images of older versions), a UNIQUE index
 * on an added column (refused when the older rows read one DEFAULT, allowed over NULLs), a RETIRE past the ALTERs, a
 * replica seeded past that cut (FLOOR's history: seed.c), and a backup's restore; each copy reads the same rows, at the
 * primary's digest, under VERIFY and the auditor */
static void t_alter_copies(void)
{
    const char *dir = test_tmpdir();
    char p[700], r[700], sf[700], kf[700], bk[700], dest[700];
    snprintf(p, sizeof p, "%s/p", dir);
    snprintf(r, sizeof r, "%s/r", dir);
    snprintf(sf, sizeof sf, "%s/stream", dir);
    snprintf(kf, sizeof kf, "%s/key", dir);
    snprintf(bk, sizeof bk, "%s/full.bak", dir);
    snprintf(dest, sizeof dest, "%s/restored", dir);
    imdb_err e = {0};
    CHECK(imdb_init(p, false, NULL, &e) == 0 && imdb_init(r, true, p, &e) == 0);
    imdb_open_opts o = {.sync = 0, .floor_stride = 1};
    imdb_db *db = NULL;
    if (imdb_open(p, &o, &db, &e)) return;
    imdb_session_init(&g_s, db);
    db->no_auto_retire = true;
    OK(run("CREATE TABLE t (id INT64 PRIMARY KEY, u INT64 SUBJECT, a TEXT) RETENTION 10 SECONDS"));
    OK(run("INSERT INTO t VALUES (1, 42, 'x'), (2, 7, 'y'), (3, 42, 'z'), (4, 9, 'w')"));
    OK(run("ALTER TABLE t ADD n INT64 NOT NULL DEFAULT 5"));
    OK(run("ALTER TABLE t ADD s TEXT DEFAULT 'q'"));
    OK(run("ALTER TABLE t ADD m INT64"));
    OK(run("CHECKPOINT")); /* a segment of the last version holding rows of the first */
    EXPECT("CREATE UNIQUE INDEX tn ON t (n)", "ERR ");                     /* the four older rows read 5 */
    EXPECT("CREATE UNIQUE INDEX tm ON t (m)", "CREATE UNIQUE INDEX tm"); /* NULLs are no key */
    EXPECT("INSERT INTO t (id, u, a) VALUES (5, 42, 'v')", "INSERT 1");
    OK(run("ERASE SUBJECT 42"));
    const char *want = "id,u,a,n,s,m\n2,7,\"y\",5,\"q\",\n4,9,\"w\",5,\"q\",\n";
    EXPECT("SELECT * FROM t ORDER BY id", want);
    OK(run("CHECKPOINT"));
    uint64_t first = db->seq + 1;
    OK(run("UPDATE t SET a = 'yy' WHERE id = 2"));
    OK(run("CHECKPOINT"));
    imdb_clock_offset(15 * 1000000ll);
    OK(run("SELECT COUNT(*) FROM t")); /* the policy moves the horizon past the second CHECKPOINT */
    imdb_err_clear(&g_e);
    OK(imdb_retire(db, first - 1, &g_e));
    want = "id,u,a,n,s,m\n2,7,\"yy\",5,\"q\",\n4,9,\"w\",5,\"q\",\n";
    EXPECT("SELECT * FROM t ORDER BY id", want);
    uint8_t kid[32], key[IMDB_BACKUP_KEY_LEN];
    imdb_backup_info bi;
    OK(imdb_backup_key_create(kf, kid, &g_e));
    OK(imdb_backup_key_load(kf, key, &g_e));
    OK(imdb_backup_full(p, bk, key, &bi, &g_e));
    uint8_t dg[32];
    imdb_lthash_digest(db->meta.digest_alg, &db->global, dg);
    CHECK(verify_db(db) == 0);
    done(db);
    CHECK(audit_dir(p) == 0);
    /* a replica seeded past the cut: FLOOR's head, the snapshot's objects and its manifest's history */
    OK(ship_to_file(p, 0, sf, &g_e));
    imdb_db *rdb = NULL;
    CHECK(imdb_open(r, &o, &rdb, &e) == 0);
    if (rdb) {
        uint64_t applied = 0;
        OK(apply_file(rdb, sf, &applied, &g_e));
        uint64_t S = rdb->seeded; /* the seed taken, the handle stops: reopened from it, then the commits after F */
        CHECK(S && rdb->failed);
        imdb_close(rdb);
        rdb = NULL;
        CHECK(imdb_open(r, &o, &rdb, &e) == 0);
        OK(ship_to_file(p, S, sf, &g_e));
        if (rdb) OK(apply_file(rdb, sf, &applied, &g_e));
    }
    if (rdb) {
        char *got = rows_of(rdb, "SELECT * FROM t ORDER BY id");
        CHECK(got && strcmp(got, want) == 0);
        free(got);
        uint8_t rd[32];
        imdb_lthash_digest(rdb->meta.digest_alg, &rdb->global, rd);
        CHECK(memcmp(rd, dg, 32) == 0 && rdb->t[0]->hist.nvers == 4);
        CHECK(verify_db(rdb) == 0);
        imdb_close(rdb);
        CHECK(audit_dir(r) == 0);
    }
    /* the backup restored */
    const char *files[1] = {bk};
    imdb_backup_info ri;
    OK(imdb_restore(dest, key, files, 1, &ri, &g_e));
    imdb_db *xdb = NULL;
    CHECK(imdb_open(dest, &o, &xdb, &e) == 0);
    if (xdb) {
        char *got = rows_of(xdb, "SELECT * FROM t ORDER BY id");
        CHECK(got && strcmp(got, want) == 0);
        free(got);
        CHECK(xdb->t[0]->hist.nvers == 4 && verify_db(xdb) == 0);
        imdb_close(xdb);
        CHECK(audit_dir(dest) == 0);
    }
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

/* ---- F1 stage 4 (docs/plan-p2.md 2026-11-08 20:5x-21:5x): DROP COLUMN, the NULL rules, the defaults, a widening ---- */

/* t's and w's answers: t dropped a column before the key, the SUBJECT and both indexed columns (so every index's
 * columns shift) and one among them, then added e; w was created with t's last columns */
static const char *const kDropQueries[] = {
    "SELECT * FROM {T} ORDER BY id",
    "SELECT id, s FROM {T} WHERE n = 3 ORDER BY id",
    "SELECT id FROM {T} WHERE x > 1200 ORDER BY id",
    "SELECT id, n, x, e FROM {T} WHERE x = 231",
    "SELECT id, n, x FROM {T} WHERE id = 77",
    "SELECT COUNT(*), SUM(n), SUM(x), COUNT(e), MIN(s), MAX(s) FROM {T}",
    "SELECT n, COUNT(*) FROM {T} GROUP BY n ORDER BY n",
    "SELECT s, COUNT(*), SUM(x) FROM {T} GROUP BY s ORDER BY s",
    "SELECT id FROM {T} WHERE e IS NULL AND n = 4 ORDER BY id",
    "SELECT id, e FROM {T} WHERE e = 9 ORDER BY id",
    "SELECT DISTINCT n FROM {T} ORDER BY n",
    "SELECT id, n FROM {T} ORDER BY n DESC, id LIMIT 25",
};

static void compare_drop(const char *phase)
{
    static const char *const paths[] = {"auto", "scan", "store", "index"};
    char qt[600], qw[600], set[64];
    OK(run("SET cross_check = on"));
    for (size_t pi = 0; pi < sizeof paths / sizeof *paths; pi++) {
        snprintf(set, sizeof set, "SET access_path = %s", paths[pi]);
        OK(run(set));
        for (size_t i = 0; i < sizeof kDropQueries / sizeof *kDropQueries; i++) {
            qfor(kDropQueries[i], "t", qt, sizeof qt);
            qfor(kDropQueries[i], "w", qw, sizeof qw);
            char *ta = strdup(csv(qt));
            const char *b = csv(qw);
            if (!ta || strcmp(ta, b) != 0) {
                char m[1800];
                snprintf(m, sizeof m, "%s, access_path %s: %s\n      t: %.500s\n      w: %.500s", phase, paths[pi], qt,
                         ta ? ta : "?", b);
                test_fail(__FILE__, __LINE__, m);
            }
            free(ta);
        }
    }
    OK(run("SET access_path = auto"));
    OK(run("SET cross_check = off"));
}

/* rows [lo, hi]: t's with the columns its phase has (0: g1 and g2 too, 1: g2, 2: e), w's with e (NULL before phase 2,
 * the value e reads for t's older rows) */
static void put_drop_rows(int lo, int hi, int phase)
{
    char qt[1 << 14], qw[1 << 14];
    for (int s = lo; s <= hi; s += 40) {
        size_t ot = (size_t)snprintf(qt, sizeof qt, "INSERT INTO t (id, s, n, x%s) VALUES ",
                                     phase == 0 ? ", g1, g2" : phase == 1 ? ", g2" : ", e");
        size_t ow = (size_t)snprintf(qw, sizeof qw, "INSERT INTO w (id, s, n, x, e) VALUES ");
        for (int id = s; id <= hi && id < s + 40; id++) {
            const char *sep = id == s ? "" : ", ";
            char e[16];
            snprintf(e, sizeof e, phase == 2 && id % 3 ? "%d" : "NULL", id % 4 + 8);
            ot += (size_t)snprintf(qt + ot, sizeof qt - ot, "%s(%d, %d, %d, %d", sep, id, id % 5, id % 9, id * 3);
            if (phase == 0) ot += (size_t)snprintf(qt + ot, sizeof qt - ot, ", %d, 'g%d')", id * 2, id);
            else if (phase == 1) ot += (size_t)snprintf(qt + ot, sizeof qt - ot, ", 'g%d')", id);
            else ot += (size_t)snprintf(qt + ot, sizeof qt - ot, ", %s)", e);
            ow += (size_t)snprintf(qw + ow, sizeof qw - ow, "%s(%d, %d, %d, %d, %s)", sep, id, id % 5, id % 9, id * 3, e);
        }
        OK(run(qt));
        OK(run(qw));
    }
}

/* the number of t's segments built at each version (by index) */
static void seg_versions(const imdb_table *t, uint32_t *count, uint32_t n)
{
    memset(count, 0, n * sizeof *count);
    for (uint32_t i = 0; t && i < t->nseg; i++)
        if (t->seg[i]->gver < n) count[t->seg[i]->gver]++;
}

/* DROP COLUMN against a twin: the flush of a memtable holding rows from both sides of a DROP cuts it into a segment
 * of each version, COMPACT keeps the cut, and t reads as w on every path in memory, after a CHECKPOINT, an ERASE
 * SUBJECT, a reopen, COMPACT and a full replay; AS OF before the drop reads no dropped column; VERIFY and the
 * auditor pass */
static void t_alter_drop_differential(void)
{
    const char *dir = test_tmpdir();
    imdb_db *db = open_fresh(dir);
    CHECK(db);
    if (!db) return;
    OK(run("CREATE TABLE t (g1 INT64, id INT64 PRIMARY KEY, s INT64 SUBJECT, g2 TEXT, n INT64, x INT64)"));
    OK(run("CREATE TABLE w (id INT64 PRIMARY KEY, s INT64 SUBJECT, n INT64, x INT64, e INT64)"));
    OK(run("CREATE INDEX tn ON t (n)"));
    OK(run("CREATE UNIQUE INDEX tx ON t (x)"));
    OK(run("CREATE INDEX wn ON w (n)"));
    OK(run("CREATE UNIQUE INDEX wx ON w (x)"));
    put_drop_rows(1, 300, 0);
    OK(run("CHECKPOINT")); /* a segment of version 1 */
    put_drop_rows(301, 400, 0);
    uint64_t before = db->seq;
    EXPECT("ALTER TABLE t DROP COLUMN g1", "ALTER TABLE t"); /* version 2: every column after g1 one index down */
    put_drop_rows(401, 450, 1);
    OK(run("CHECKPOINT")); /* the memtable holds rows of versions 1 and 2: a segment of each */
    imdb_table *t = imdb_table_by_name(db, "t");
    uint32_t cnt[8];
    seg_versions(t, cnt, 8);
    CHECK(t && t->nseg == 3 && cnt[0] == 2 && cnt[1] == 1);
    CHECK(t && t->idx[0].d.cols[0] == 3 && t->idx[1].d.cols[0] == 4 && t->s.subject == 1 && t->s.key[0] == 0);
    char q[200];
    snprintf(q, sizeof q, "SELECT * FROM t AS OF %llu WHERE id = 2", (unsigned long long)before);
    EXPECT(q, "id,s,g2,n,x\n2,2,\"g2\",2,6\n"); /* stage 3's rule: the current schema, the history's rows */
    EXPECT("ALTER TABLE t DROP g2", "ALTER TABLE t");     /* 3 */
    EXPECT("ALTER TABLE t ADD e INT64", "ALTER TABLE t"); /* 4: position 6 */
    put_drop_rows(451, 500, 2);
    for (int k = 0; k < 2; k++) { /* the same writes on both: rows of every version end, new ones at version 4 */
        const char *tb = k ? "w" : "t";
        snprintf(q, sizeof q, "UPDATE %s SET n = n + 1 WHERE id %% 7 = 0", tb);
        OK(run(q));
        snprintf(q, sizeof q, "DELETE FROM %s WHERE id %% 11 = 0", tb);
        OK(run(q));
        snprintf(q, sizeof q, "UPDATE %s SET e = 9 WHERE id %% 13 = 0", tb);
        OK(run(q));
    }
    compare_drop("in memory");
    OK(run("CHECKPOINT"));
    compare_drop("after a CHECKPOINT");
    EXPECT("SELECT * FROM t WHERE id = 2", "id,s,n,x,e\n2,2,2,6,\n");
    OK(run("ERASE SUBJECT 3")); /* segments of versions 1, 2 and 4 rewritten, each at its own */
    compare_drop("after ERASE SUBJECT");
    CHECK(verify_db(db) == 0);
    done(db);
    db = open_at(dir, false);
    CHECK(db);
    if (!db) return;
    compare_drop("after a reopen");
    OK(run("COMPACT t"));
    OK(run("COMPACT w"));
    compare_drop("after COMPACT");
    t = imdb_table_by_name(db, "t");
    seg_versions(t, cnt, 8);
    CHECK(t && cnt[0] >= 1 && cnt[1] >= 1 && cnt[3] >= 1 && cnt[2] == 0); /* the cut kept: g1's rows, g2's, the rest */
    CHECK(verify_db(db) == 0);
    done(db);
    db = open_at(dir, true);
    CHECK(db);
    if (!db) return;
    compare_drop("after a full replay");
    CHECK(verify_db(db) == 0);
    done(db);
    CHECK(audit_dir(dir) == 0);
}

/* DROP then ADD of the same last column: the old schema's encoding again, at another position, so the versions'
 * hashes differ and no read, from memory or a segment of the first version, shows the dropped values */
static void t_alter_drop_add(void)
{
    const char *dir = test_tmpdir();
    imdb_db *db = open_fresh(dir);
    CHECK(db);
    if (!db) return;
    OK(run("CREATE TABLE t (id INT64 PRIMARY KEY, a INT64, c INT64)"));
    OK(run("INSERT INTO t VALUES (1, 1, 100), (2, 2, 200), (3, 3, 300)"));
    OK(run("CHECKPOINT")); /* its segment holds c */
    OK(run("INSERT INTO t VALUES (4, 4, 400)"));
    OK(run("ALTER TABLE t DROP COLUMN c"));
    OK(run("ALTER TABLE t ADD COLUMN c INT64"));
    imdb_table *t = imdb_table_by_name(db, "t");
    CHECK(t && t->hist.nvers == 3);
    if (t && t->hist.nvers == 3) {
        uint8_t a[32], b[32];
        OK(imdb_schema_hash(&t->hist.vers[0].s, a, E));
        OK(imdb_schema_hash(&t->hist.vers[2].s, b, E));
        CHECK(memcmp(a, b, 32) == 0);                                        /* one encoding */
        CHECK(memcmp(t->hist.vers[0].hash, t->hist.vers[2].hash, 32) != 0); /* two layouts */
    }
    const char *want = "id,a,c\n1,1,\n2,2,\n3,3,\n4,4,\n5,5,500\n";
    OK(run("INSERT INTO t VALUES (5, 5, 500)"));
    EXPECT("SELECT * FROM t ORDER BY id", want);
    EXPECT("SELECT id FROM t WHERE c = 100 OR c = 400", "id\n");
    OK(run("CHECKPOINT")); /* the memtable: row 4 of version 1 (with c's old value), row 5 of version 3 */
    EXPECT("SELECT * FROM t ORDER BY id", want);
    done(db);
    db = open_at(dir, false); /* each segment by its version's hash */
    CHECK(db);
    if (!db) return;
    EXPECT("SELECT * FROM t ORDER BY id", want);
    EXPECT("SELECT COUNT(c), SUM(c) FROM t", "count_c,sum_c\n1,500\n");
    OK(run("COMPACT t"));
    EXPECT("SELECT * FROM t ORDER BY id", want);
    CHECK(verify_db(db) == 0);
    done(db);
    db = open_at(dir, true);
    CHECK(db);
    if (!db) return;
    EXPECT("SELECT * FROM t ORDER BY id", want);
    done(db);
    CHECK(audit_dir(dir) == 0);
}

/* equal hashes, equal layouts: a RENAME and back gives version 1's hash again and a SET DEFAULT its predecessor's;
 * segments built under each read alike through every reopen */
static void t_alter_same_layout(void)
{
    const char *dir = test_tmpdir();
    imdb_db *db = open_fresh(dir);
    CHECK(db);
    if (!db) return;
    OK(run("CREATE TABLE t (id INT64 PRIMARY KEY, a INT64)"));
    OK(run("INSERT INTO t VALUES (1, 10), (2, 20)"));
    OK(run("CHECKPOINT"));
    OK(run("ALTER TABLE t RENAME COLUMN a TO b"));
    OK(run("INSERT INTO t VALUES (3, 30)"));
    OK(run("CHECKPOINT"));
    OK(run("ALTER TABLE t RENAME COLUMN b TO a"));
    OK(run("ALTER TABLE t ALTER COLUMN a SET DEFAULT 7"));
    OK(run("INSERT INTO t (id) VALUES (4)"));
    imdb_table *t = imdb_table_by_name(db, "t");
    CHECK(t && t->hist.nvers == 4);
    if (t && t->hist.nvers == 4) {
        CHECK(memcmp(t->hist.vers[0].hash, t->hist.vers[2].hash, 32) == 0);
        CHECK(memcmp(t->hist.vers[2].hash, t->hist.vers[3].hash, 32) == 0);
        CHECK(memcmp(t->hist.vers[0].hash, t->hist.vers[1].hash, 32) != 0);
    }
    const char *want = "id,a\n1,10\n2,20\n3,30\n4,7\n";
    EXPECT("SELECT * FROM t ORDER BY id", want);
    OK(run("CHECKPOINT"));
    done(db);
    db = open_at(dir, false);
    CHECK(db);
    if (!db) return;
    EXPECT("SELECT * FROM t ORDER BY id", want);
    EXPECT("INSERT INTO t (id) VALUES (5)", "INSERT 1"); /* the write default through the manifest's history */
    EXPECT("SELECT a FROM t WHERE id = 5", "a\n7\n");
    CHECK(verify_db(db) == 0);
    done(db);
    db = open_at(dir, true);
    CHECK(db);
    if (!db) return;
    EXPECT("SELECT * FROM t WHERE id < 5 ORDER BY id", want);
    done(db);
    CHECK(audit_dir(dir) == 0);
}

/* the NULL rules: SET NOT NULL refused while a live row reads NULL, then allowed with an ended row holding one, whose
 * flush cuts it into a segment of the version before; DROP NOT NULL; the key and the SUBJECT never change */
static void t_alter_not_null(void)
{
    const char *dir = test_tmpdir();
    imdb_db *db = open_fresh(dir);
    CHECK(db);
    if (!db) return;
    OK(run("CREATE TABLE t (id INT64 PRIMARY KEY, s INT64 SUBJECT, a INT64, b TEXT)"));
    OK(run("INSERT INTO t VALUES (1, 1, 10, 'x'), (2, 2, NULL, 'y'), (3, 3, 30, NULL)"));
    OK(run("ALTER TABLE t ADD c INT64"));          /* the three rows read NULL there */
    OK(run("ALTER TABLE t ADD k INT64 DEFAULT 5")); /* and 5 there */
    EXPECT("ALTER TABLE t ALTER COLUMN a SET NOT NULL", "ERR column a of table t is NULL in a row");
    EXPECT("ALTER TABLE t ALTER COLUMN c SET NOT NULL", "ERR column c of table t is NULL in a row");
    EXPECT("ALTER TABLE t ALTER COLUMN k SET NOT NULL", "ALTER TABLE t"); /* the missing value 5 is a value */
    EXPECT("ALTER TABLE t ALTER COLUMN k SET NOT NULL", "ERR NOT NULL already");
    EXPECT("ALTER TABLE t ALTER COLUMN id DROP NOT NULL", "ERR never NULL");
    EXPECT("ALTER TABLE t ALTER COLUMN s DROP NOT NULL", "ERR never NULL");
    EXPECT("ALTER TABLE t ALTER COLUMN nosuch SET NOT NULL", "ERR no column nosuch");
    uint64_t was = db->seq;
    OK(run("DELETE FROM t WHERE id = 2")); /* an ended version holding a NULL in a */
    EXPECT("ALTER TABLE t ALTER COLUMN a SET NOT NULL", "ALTER TABLE t");
    EXPECT("INSERT INTO t VALUES (4, 4, NULL, 'z', 1, 1)", "ERR ");
    OK(run("INSERT INTO t VALUES (5, 5, 50, 'w', 1, 1)"));
    OK(run("CHECKPOINT")); /* rows 1-3 (version 1, a nullable: they reach the version before the SET) and row 5 */
    imdb_table *t = imdb_table_by_name(db, "t");
    uint32_t cnt[8];
    seg_versions(t, cnt, 8);
    CHECK(t && t->nseg == 2 && cnt[3] == 1 && cnt[4] == 1);
    char q[200];
    snprintf(q, sizeof q, "SELECT a, b FROM t AS OF %llu WHERE id = 2", (unsigned long long)was);
    EXPECT(q, "a,b\n,\"y\"\n");
    EXPECT("ALTER TABLE t ALTER COLUMN a DROP NOT NULL", "ALTER TABLE t");
    EXPECT("ALTER TABLE t ALTER COLUMN a DROP NOT NULL", "ERR takes NULL already");
    EXPECT("INSERT INTO t VALUES (6, 6, NULL, 'v', NULL, 2)", "INSERT 1");
    const char *want = "id,s,a,b,c,k\n1,1,10,\"x\",,5\n3,3,30,,,5\n5,5,50,\"w\",1,1\n6,6,,\"v\",,2\n";
    EXPECT("SELECT * FROM t ORDER BY id", want);
    OK(run("CHECKPOINT"));
    done(db);
    db = open_at(dir, false);
    CHECK(db);
    if (!db) return;
    EXPECT("SELECT * FROM t ORDER BY id", want);
    OK(run("COMPACT t"));
    EXPECT("SELECT * FROM t ORDER BY id", want);
    CHECK(verify_db(db) == 0);
    done(db);
    db = open_at(dir, true);
    CHECK(db);
    if (!db) return;
    EXPECT("SELECT * FROM t ORDER BY id", want);
    done(db);
    CHECK(audit_dir(dir) == 0);
}

/* the write default parted from what older rows read: SET DEFAULT and DROP DEFAULT through INSERT, a reopen and a
 * full replay; the refusals; the dump's lines */
static void t_alter_set_default(void)
{
    const char *dir = test_tmpdir();
    imdb_db *db = open_fresh(dir);
    CHECK(db);
    if (!db) return;
    OK(run("CREATE TABLE t (id INT64 PRIMARY KEY, a TEXT)"));
    OK(run("INSERT INTO t VALUES (1, 'x')"));
    OK(run("ALTER TABLE t ADD c TEXT DEFAULT 'old'"));
    OK(run("INSERT INTO t (id) VALUES (2)"));
    EXPECT("ALTER TABLE t ALTER COLUMN c SET DEFAULT 'new'", "ALTER TABLE t");
    OK(run("INSERT INTO t (id) VALUES (3)"));
    OK(run("ALTER TABLE t ADD n INT64 DEFAULT 1"));
    OK(run("ALTER TABLE t ALTER COLUMN n SET DEFAULT 2"));
    OK(run("INSERT INTO t (id) VALUES (4)"));
    const char *want = "id,a,c,n\n1,\"x\",\"old\",1\n2,,\"old\",1\n3,,\"new\",1\n4,,\"new\",2\n";
    EXPECT("SELECT * FROM t ORDER BY id", want);
    EXPECT("ALTER TABLE t ALTER COLUMN c SET DEFAULT NULL", "ERR DROP DEFAULT");
    EXPECT("ALTER TABLE t ALTER COLUMN n SET DEFAULT 'q'", "ERR ");
    EXPECT("ALTER TABLE t ALTER COLUMN a DROP DEFAULT", "ERR column a has no DEFAULT");
    OK(run("CHECKPOINT"));
    done(db);
    db = open_at(dir, false);
    CHECK(db);
    if (!db) return;
    EXPECT("SELECT * FROM t ORDER BY id", want);
    OK(run("INSERT INTO t (id) VALUES (5)"));
    EXPECT("SELECT c, n FROM t WHERE id = 5", "c,n\n\"new\",2\n");
    EXPECT("ALTER TABLE t ALTER COLUMN c DROP DEFAULT", "ALTER TABLE t");
    OK(run("INSERT INTO t (id) VALUES (6)"));
    EXPECT("SELECT c, n FROM t WHERE id = 6", "c,n\n,2\n");
    EXPECT("SELECT c FROM t WHERE id = 1", "c\n\"old\"\n"); /* what the rows before the ADD read stays */
    dumpbuf d = {0};
    OK(imdb_dump(db, 1000, dumpbuf_write, &d, E));
    CHECK(d.p && strstr(d.p, "CREATE TABLE t (id INT64 PRIMARY KEY, a TEXT, c TEXT, n INT64 DEFAULT 2) RETENTION") && /* F2a */
          !strstr(d.p, "SET DEFAULT") && !strstr(d.p, "c TEXT DEFAULT"));
    free(d.p);
    CHECK(verify_db(db) == 0);
    done(db);
    db = open_at(dir, true);
    CHECK(db);
    if (!db) return;
    OK(run("INSERT INTO t (id) VALUES (7)"));
    EXPECT("SELECT c, n FROM t WHERE id = 7", "c,n\n,2\n");
    done(db);
    CHECK(audit_dir(dir) == 0);
}

/* a widening: DECIMAL(6,2) to DECIMAL(10,2), its stored values valid as they are, a view over the column unchanged
 * (its logged types carry a scale, not a precision); a narrowing, another scale, another type refused */
static void t_alter_widen(void)
{
    const char *dir = test_tmpdir();
    imdb_db *db = open_fresh(dir);
    CHECK(db);
    if (!db) return;
    OK(run("CREATE TABLE t (id INT64 PRIMARY KEY, d DECIMAL(6,2))"));
    OK(run("INSERT INTO t VALUES (1, 1234.56)"));
    EXPECT("INSERT INTO t VALUES (2, 123456.78)", "ERR ");
    OK(run("CREATE VIEW v AS SELECT id, d FROM t"));
    OK(run("CHECKPOINT"));
    EXPECT("ALTER TABLE t ALTER COLUMN d TYPE DECIMAL(10,2)", "ALTER TABLE t");
    EXPECT("INSERT INTO t VALUES (2, 123456.78)", "INSERT 1");
    EXPECT("ALTER TABLE t ALTER COLUMN d SET DATA TYPE DECIMAL(8,2)", "ERR wider DECIMAL");
    EXPECT("ALTER TABLE t ALTER COLUMN d TYPE DECIMAL(12,3)", "ERR wider DECIMAL");
    EXPECT("ALTER TABLE t ALTER COLUMN d TYPE INT64", "ERR wider DECIMAL");
    EXPECT("ALTER TABLE t ALTER COLUMN id TYPE DECIMAL(12,0)", "ERR wider DECIMAL");
    const char *want = "id,d\n1,1234.56\n2,123456.78\n";
    EXPECT("SELECT * FROM v ORDER BY id", want);
    OK(run("CHECKPOINT"));
    done(db);
    db = open_at(dir, false);
    CHECK(db);
    if (!db) return;
    EXPECT("SELECT * FROM v ORDER BY id", want);
    dumpbuf d = {0};
    OK(imdb_dump(db, 1000, dumpbuf_write, &d, E));
    CHECK(d.p && strstr(d.p, "CREATE TABLE t (id INT64 PRIMARY KEY, d DECIMAL(10,2)) RETENTION"));
    free(d.p);
    CHECK(verify_db(db) == 0);
    done(db);
    db = open_at(dir, true); /* the view re-bound after the widening */
    CHECK(db);
    if (!db) return;
    EXPECT("SELECT * FROM v ORDER BY id", want);
    done(db);
    CHECK(audit_dir(dir) == 0);
}

/* DROP COLUMN's rules: the key (a composite one's columns too), the SUBJECT, an indexed column, a name a view reading
 * the table holds, a column that is not there; CASCADE is not spelled */
static void t_alter_drop_rules(void)
{
    const char *dir = test_tmpdir();
    imdb_db *db = open_fresh(dir);
    CHECK(db);
    if (!db) return;
    OK(run("CREATE TABLE t (id INT64 PRIMARY KEY, s INT64 SUBJECT, a INT64, b INT64, c INT64)"));
    OK(run("CREATE TABLE k (a INT64, b INT64, c INT64, PRIMARY KEY (b, a))"));
    OK(run("CREATE INDEX ta ON t (a)"));
    OK(run("CREATE VIEW v AS SELECT id, b FROM t"));
    OK(run("INSERT INTO t VALUES (1, 1, 1, 1, 1)"));
    EXPECT("ALTER TABLE t DROP COLUMN id", "ERR primary key");
    EXPECT("ALTER TABLE k DROP COLUMN a", "ERR primary key");
    EXPECT("ALTER TABLE t DROP COLUMN s", "ERR SUBJECT");
    EXPECT("ALTER TABLE t DROP COLUMN a", "ERR index ta names column a");
    EXPECT("ALTER TABLE t DROP COLUMN b", "ERR view v reads table t and names b");
    EXPECT("ALTER TABLE t DROP COLUMN nosuch", "ERR no column nosuch");
    EXPECT("ALTER TABLE t DROP COLUMN c CASCADE", "ERR ");
    imdb_table *t = imdb_table_by_name(db, "t");
    CHECK(t && t->hist.nvers == 1);
    EXPECT("ALTER TABLE t DROP COLUMN c", "ALTER TABLE t");
    EXPECT("ALTER TABLE t DROP c", "ERR no column c");
    EXPECT("ALTER TABLE k DROP c", "ALTER TABLE k");
    OK(run("DROP INDEX ta"));
    EXPECT("ALTER TABLE t DROP a RESTRICT", "ALTER TABLE t");
    EXPECT("SELECT * FROM t", "id,s,b\n1,1,1\n");
    EXPECT("SELECT * FROM v", "id,b\n1,1\n");
    OK(run("CHECKPOINT"));
    CHECK(verify_db(db) == 0);
    done(db);
    CHECK(audit_dir(dir) == 0);
}


/* a row's reach is a contiguous span: rows older than a SET NOT NULL then DROP NOT NULL reach only the version before
 * the SET, though the last could hold them again, so their flush builds them there and the newer row apart */
static void t_alter_reach(void)
{
    const char *dir = test_tmpdir();
    imdb_db *db = open_fresh(dir);
    CHECK(db);
    if (!db) return;
    OK(run("CREATE TABLE t (id INT64 PRIMARY KEY, a INT64)"));
    OK(run("INSERT INTO t VALUES (1, 10), (2, 20)"));
    OK(run("ALTER TABLE t ALTER COLUMN a SET NOT NULL"));
    OK(run("ALTER TABLE t ALTER COLUMN a DROP NOT NULL"));
    OK(run("INSERT INTO t VALUES (3, NULL)"));
    OK(run("CHECKPOINT"));
    imdb_table *t = imdb_table_by_name(db, "t");
    uint32_t cnt[8];
    seg_versions(t, cnt, 8);
    CHECK(t && t->hist.nvers == 3 && t->nseg == 2 && cnt[0] == 1 && cnt[2] == 1);
    const char *want = "id,a\n1,10\n2,20\n3,\n";
    EXPECT("SELECT * FROM t ORDER BY id", want);
    done(db);
    db = open_at(dir, false);
    CHECK(db);
    if (!db) return;
    EXPECT("SELECT * FROM t ORDER BY id", want);
    OK(run("COMPACT t")); /* the same cut: the rows of version 1 and the one of version 3 */
    t = imdb_table_by_name(db, "t");
    seg_versions(t, cnt, 8);
    CHECK(t && t->nseg == 2 && cnt[0] == 1 && cnt[2] == 1);
    EXPECT("SELECT * FROM t ORDER BY id", want);
    CHECK(verify_db(db) == 0);
    done(db);
    CHECK(audit_dir(dir) == 0);
}

const test_case alter_tests[] = {
    {"alter_differential", t_alter_differential},
    {"alter_rules", t_alter_rules},
    {"alter_txn", t_alter_txn},
    {"alter_retire", t_alter_retire},
    {"alter_manifest", t_alter_manifest},
    {"alter_default", t_alter_default},
    {"alter_copies", t_alter_copies},
    {"alter_drop_differential", t_alter_drop_differential}, /* F1 stage 4 */
    {"alter_drop_add", t_alter_drop_add},
    {"alter_same_layout", t_alter_same_layout},
    {"alter_not_null", t_alter_not_null},
    {"alter_set_default", t_alter_set_default},
    {"alter_widen", t_alter_widen},
    {"alter_drop_rules", t_alter_drop_rules},
    {"alter_reach", t_alter_reach},
};
const size_t alter_ntests = sizeof alter_tests / sizeof *alter_tests;
