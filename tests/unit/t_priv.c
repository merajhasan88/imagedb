/* N1e (docs/n1-design.md §8e): privileges enforced on a session the server marks (imdb_session.enforce, .role). Each
 * statement form as a role without and with what it needs: Gate A's kinds (every kind classified; superuser-only
 * statements and SET names refused), Gate B's reads (every nested form, views with the invoker's rights, branches no row
 * takes, AS OF by the object at the snapshot, FOR UPDATE, COPY TO, SHOW HISTORY, EXPLAIN, EXECUTE checked at each run),
 * Gate C's writes (the target's privilege, and SELECT whenever a column of it may be read: fail closed), membership
 * inherited transitively, the principal (none, a dropped role, a superuser). A refusal is IMDB_ERR_PRIVILEGE and its
 * message names the relation, never a privilege or a value. */
#include <stdlib.h>

#include "../../src/db_internal.h"
#include "../../src/role.h"
#include "../../src/sql.h"
#include "../../src/sql_internal.h"
#include "thelp.h"

static imdb_session g_a, g_r; /* a superuser's (not enforced: the embedded API's), the role's (enforced) */
static char g_msg[512];

static int run_on(imdb_session *s, const char *sql)
{
    imdb_result r;
    imdb_err e = {0};
    int rc = imdb_exec_one(s, sql, strlen(sql), NULL, 0, &r, &e);
    snprintf(g_msg, sizeof g_msg, "%s", rc ? e.msg : "");
    if (!rc) imdb_result_free(&r);
    return rc;
}

#define ADMIN(sql)                                                                                                     \
    do {                                                                                                               \
        if (run_on(&g_a, (sql))) {                                                                                     \
            char m_[900];                                                                                              \
            snprintf(m_, sizeof m_, "admin: %s: %s", (sql), g_msg);                                                    \
            test_fail(__FILE__, __LINE__, m_);                                                                         \
        }                                                                                                              \
    } while (0)

#define TAKEN(sql)                                                                                                     \
    do {                                                                                                               \
        int rc_ = run_on(&g_r, (sql));                                                                                 \
        if (rc_) {                                                                                                     \
            char m_[900];                                                                                              \
            snprintf(m_, sizeof m_, "refused, want taken: %s: %d %s", (sql), rc_, g_msg);                              \
            test_fail(__FILE__, __LINE__, m_);                                                                         \
        }                                                                                                              \
    } while (0)

/* refused by a gate, its message holding want ("permission denied for table u", ...) */
#define REFUSED(sql, want)                                                                                             \
    do {                                                                                                               \
        int rc_ = run_on(&g_r, (sql));                                                                                 \
        if (rc_ != IMDB_ERR_PRIVILEGE || !strstr(g_msg, (want))) {                                                     \
            char m_[900];                                                                                              \
            snprintf(m_, sizeof m_, "want refused (%s): %s: %d %s", (want), (sql), rc_, g_msg);                        \
            test_fail(__FILE__, __LINE__, m_);                                                                         \
        }                                                                                                              \
    } while (0)

/* the role's COPY stream: FROM reads two rows, TO drops what it is given */
static long cp_rd(void *arg, char *buf, size_t cap)
{
    int *k = arg;
    static const char rows[] = "9,90,nine\n10,100,ten\n";
    if ((*k)++ || cap < sizeof rows) return 0;
    memcpy(buf, rows, sizeof rows - 1);
    return (long)(sizeof rows - 1);
}

static int cp_wr(void *arg, const char *buf, size_t len)
{
    (void)arg, (void)buf, (void)len;
    return 0;
}

static int g_cpk;

static imdb_db *setup(void)
{
    const char *dir = test_tmpdir();
    imdb_err e = {0};
    if (imdb_init(dir, false, NULL, &e)) return NULL;
    imdb_db *db = open_db(dir);
    if (!db) return NULL;
    imdb_session_init(&g_a, db);
    imdb_session_init(&g_r, db);
    ADMIN("CREATE TABLE t (id INT64 PRIMARY KEY, a INT64, s TEXT)");
    ADMIN("CREATE TABLE u (id INT64 PRIMARY KEY, x INT64)");
    ADMIN("INSERT INTO t VALUES (1, 10, 'one'), (2, 20, 'two'), (3, 30, 'three')");
    ADMIN("INSERT INTO u VALUES (1, 100), (2, 200)");
    ADMIN("CREATE VIEW v (id, a) AS SELECT id, a FROM t");
    ADMIN("CREATE VIEW w (id, x) AS SELECT id, x FROM u");
    ADMIN("CREATE ROLE r");
    g_r.enforce = true;
    g_cpk = 0;
    imdb_session_copy_io(&g_r, cp_rd, cp_wr, &g_cpk);
    g_r.role = imdb_role_by_name(db, "r")->id;
    return db;
}

static void teardown(imdb_db *db)
{
    imdb_session_close(&g_r);
    imdb_session_close(&g_a);
    imdb_close(db);
}

/* every statement kind classified (a later kind refused until it is) */
static void t_priv_kinds(void)
{
    for (int k = 1; k < ST__END; k++) {
        if (imdb_priv_kind_need(k) < 0) {
            char m[64];
            snprintf(m, sizeof m, "statement kind %d not classified", k);
            test_fail(__FILE__, __LINE__, m);
        }
    }
    SOFT(imdb_priv_kind_need(ST__END) < 0 && imdb_priv_kind_need(0) < 0);
}

/* the principal: none, a superuser's, a dropped role */
static void t_priv_principal(void)
{
    imdb_db *db = setup();
    CHECK(db);
    uint32_t rid = g_r.role;
    g_r.role = 0;
    REFUSED("SELECT 1", "acts as no role");
    g_r.role = rid;
    TAKEN("SELECT 1");
    ADMIN("CREATE ROLE su SUPERUSER");
    g_r.role = imdb_role_by_name(db, "su")->id;
    TAKEN("CREATE TABLE z (id INT64 PRIMARY KEY)");
    TAKEN("SELECT COUNT(*) FROM u");
    TAKEN("CHECKPOINT");
    ADMIN("ALTER ROLE su NOSUPERUSER"); /* applies at its next statement */
    REFUSED("SELECT COUNT(*) FROM u", "permission denied for table u");
    REFUSED("DROP TABLE z", "needs a superuser");
    /* a role dropped under a live session: refused by name at its next statement; its transaction can roll back */
    ADMIN("CREATE ROLE d");
    ADMIN("GRANT SELECT ON t TO d");
    g_r.role = imdb_role_by_name(db, "d")->id;
    TAKEN("BEGIN");
    TAKEN("SELECT COUNT(*) FROM t");
    ADMIN("REVOKE SELECT ON t FROM d");
    ADMIN("DROP ROLE d");
    REFUSED("SELECT 1", "was dropped");
    TAKEN("ROLLBACK");
    REFUSED("BEGIN", "was dropped");
    /* erased since (ERASE ROLE takes a dropped role holding nothing out of the catalog): the same rule */
    ADMIN("CREATE ROLE e");
    g_r.role = imdb_role_by_name(db, "e")->id;
    TAKEN("BEGIN");
    ADMIN("DROP ROLE e");
    ADMIN("ERASE ROLE e");
    REFUSED("SELECT 1", "was dropped");
    REFUSED("SHOW GRANTS", "was dropped");
    TAKEN("ROLLBACK");
    g_r.role = rid;
    teardown(db);
}

/* Gate A: a superuser's statements and SET names */
static void t_priv_super(void)
{
    imdb_db *db = setup();
    CHECK(db);
    static const char *const su[] = {"CREATE TABLE z (id INT64 PRIMARY KEY)", "DROP TABLE u", "ALTER TABLE t ADD COLUMN q INT64",
                                     "CREATE INDEX ta ON t (a)", "CREATE VIEW vz (id) AS SELECT id FROM t", "DROP VIEW v",
                                     "CREATE SEQUENCE sq", "CREATE TYPE mood AS ENUM ('a')", "CREATE ROLE x", "ALTER ROLE r LOGIN",
                                     "DROP ROLE r", "GRANT SELECT ON u TO r", "REVOKE SELECT ON t FROM r", "CHECKPOINT",
                                     "COMPACT t", "VERIFY", "ERASE SUBJECT 1", "SHOW DIGEST", "SHOW LAKE", "SHOW STATS",
                                     "SHOW MEMORY", "SHOW REPLICAS", "SHOW ERASURE", "SHOW LOG", "SHOW TRANSACTIONS",
                                     "SHOW ROLES", "SET slow_statement_ms = 1", "SET cross_check = on",
                                     "SET sync_replicas = 1", "SET sync_timeout_ms = 10"};
    ADMIN("GRANT ALL ON t TO r");
    ADMIN("GRANT ALL ON u TO r");
    for (size_t i = 0; i < sizeof su / sizeof su[0]; i++) {
        int rc = run_on(&g_r, su[i]);
        if (rc != IMDB_ERR_PRIVILEGE) {
            char m[600];
            snprintf(m, sizeof m, "a superuser's statement taken or refused otherwise: %s: %d %s", su[i], rc, g_msg);
            test_fail(__FILE__, __LINE__, m);
        }
    }
    /* anyone's: the session's own settings, transactions, names */
    static const char *const any[] = {"SET statement_timeout = 5000", "SET TIME ZONE 'America/New_York'", "SHOW TIME ZONE",
                                      "SET statement_row_limit = 0", "SET identity = on", "SHOW TABLES", "SHOW VIEWS",
                                      "SHOW INDEXES", "SHOW RETENTION", "SHOW IDENTITY", "SHOW PREPARED", "BEGIN",
                                      "SAVEPOINT a", "ROLLBACK TO a", "RELEASE a", "COMMIT", "SHOW GRANTS", "SHOW GRANTS FOR r"};
    for (size_t i = 0; i < sizeof any / sizeof any[0]; i++) TAKEN(any[i]);
    REFUSED("SHOW GRANTS FOR nobody", "another role");
    /* statement_memory: down from the default, never past it */
    TAKEN("SET statement_memory = 16777216");
    char q[96];
    snprintf(q, sizeof q, "SET statement_memory = %llu", (unsigned long long)imdb_query_share(db->mem_limit) + 1);
    REFUSED(q, "needs a superuser");
    /* sequence functions a superuser's; a SERIAL's value in an INSERT the engine's */
    ADMIN("CREATE TABLE sr (id SERIAL PRIMARY KEY, v INT64)");
    ADMIN("CREATE SEQUENCE sq");
    ADMIN("GRANT INSERT ON sr TO r");
    TAKEN("INSERT INTO sr (v) VALUES (1), (2)");
    REFUSED("SELECT nextval('sq')", "sequence");
    REFUSED("INSERT INTO sr (id, v) VALUES (nextval('sq'), 3)", "sequence");
    SOFT(run_on(&g_a, "SELECT COUNT(*) FROM sr") == 0);
    teardown(db);
}

/* Gate B: every form that reads a table names it to the check, nested ones and branches no row takes included */
static void t_priv_reads(void)
{
    imdb_db *db = setup();
    CHECK(db);
    ADMIN("GRANT SELECT ON t TO r");
    uint64_t before = db->seq;
    TAKEN("SELECT * FROM t");
    TAKEN("SELECT COUNT(*) FROM t");
    static const char *const nu[] = {
        "SELECT * FROM u",
        "SELECT COUNT(*) FROM u",
        "SELECT t.id FROM t JOIN u ON t.id = u.id",
        "SELECT t.id FROM t LEFT JOIN u ON t.id = u.id",
        "SELECT t.id FROM t, u",
        "SELECT id FROM t WHERE EXISTS (SELECT 1 FROM u WHERE u.id = t.id)",
        "SELECT id FROM t WHERE id IN (SELECT id FROM u)",
        "SELECT id, (SELECT MAX(x) FROM u) FROM t",
        "SELECT q.id FROM (SELECT id FROM u) AS q",
        "WITH c AS (SELECT id FROM u) SELECT id FROM c",
        "WITH c AS (SELECT id FROM u) SELECT id FROM t", /* a CTE nothing references: refused (fail closed) */
        "SELECT id FROM t UNION SELECT id FROM u",
        "SELECT id FROM t WHERE id = 1 OR id IN (SELECT id FROM u)",
        "SELECT CASE WHEN id > 0 THEN 1 ELSE (SELECT COUNT(*) FROM u) END FROM t", /* a branch no row takes */
        "SELECT COALESCE(a, (SELECT MAX(x) FROM u)) FROM t",                     /* never reached: a is never NULL */
        "SELECT id FROM t WHERE id < 0 AND EXISTS (SELECT 1 FROM u)",
        "SELECT id FROM t WHERE EXISTS (SELECT 1 FROM u WHERE u.x = t.a)", /* correlated */
        "COPY u TO STDOUT",
        "COPY (SELECT id FROM u) TO STDOUT",
        "SHOW HISTORY u (1)",
        "EXPLAIN SELECT * FROM u",
        "SELECT * FROM w", /* no grant on w */
    };
    for (size_t i = 0; i < sizeof nu / sizeof nu[0]; i++) {
        int rc = run_on(&g_r, nu[i]);
        if (rc != IMDB_ERR_PRIVILEGE || (!strstr(g_msg, "for table u") && !strstr(g_msg, "for view w"))) {
            char m[700];
            snprintf(m, sizeof m, "want refused for u: %s: %d %s", nu[i], rc, g_msg);
            test_fail(__FILE__, __LINE__, m);
        }
    }
    /* views: SELECT on the view, its body with the invoker's rights */
    REFUSED("SELECT * FROM v", "permission denied for view v");
    ADMIN("GRANT SELECT ON v TO r");
    TAKEN("SELECT * FROM v");
    ADMIN("GRANT SELECT ON w TO r");
    REFUSED("SELECT * FROM w", "permission denied for table u"); /* the view's body: the invoker lacks u */
    /* FOR UPDATE: UPDATE too */
    REFUSED("SELECT * FROM t WHERE id = 1 FOR UPDATE", "permission denied for table t");
    ADMIN("GRANT UPDATE ON t TO r");
    TAKEN("SELECT * FROM t WHERE id = 1 FOR UPDATE");
    /* AS OF: the object at the snapshot, under the current grants */
    char q[128];
    snprintf(q, sizeof q, "SELECT COUNT(*) FROM t AS OF %llu", (unsigned long long)before);
    TAKEN(q);
    snprintf(q, sizeof q, "SELECT COUNT(*) FROM u AS OF %llu", (unsigned long long)before);
    REFUSED(q, "for table u");
    /* EXECUTE checked at each run; PREPARE parses only */
    TAKEN("PREPARE p AS SELECT COUNT(*) FROM u");
    REFUSED("EXECUTE p", "for table u");
    ADMIN("GRANT SELECT ON u TO r");
    TAKEN("EXECUTE p");
    for (size_t i = 0; i < sizeof nu / sizeof nu[0]; i++) {

        int rc = run_on(&g_r, nu[i]);
        if (rc) {
            char m[700];
            snprintf(m, sizeof m, "granted, still refused: %s: %d %s", nu[i], rc, g_msg);
            test_fail(__FILE__, __LINE__, m);
        }
    }
    ADMIN("REVOKE SELECT ON u FROM r");
    REFUSED("EXECUTE p", "for table u");
    teardown(db);
}

/* membership: a group's privileges, transitively, and gone with the membership */
static void t_priv_member(void)
{
    imdb_db *db = setup();
    CHECK(db);
    ADMIN("CREATE ROLE g1");
    ADMIN("CREATE ROLE g2");
    ADMIN("GRANT SELECT ON u TO g2");
    ADMIN("GRANT g2 TO g1");
    REFUSED("SELECT * FROM u", "for table u");
    ADMIN("GRANT g1 TO r");
    TAKEN("SELECT * FROM u"); /* r -> g1 -> g2 */
    ADMIN("REVOKE g2 FROM g1");
    REFUSED("SELECT * FROM u", "for table u");
    ADMIN("GRANT g2 TO r");
    TAKEN("SELECT * FROM u");
    /* SUPERUSER is never inherited */
    ADMIN("CREATE ROLE boss SUPERUSER");
    ADMIN("GRANT boss TO r");
    REFUSED("CHECKPOINT", "needs a superuser");
    teardown(db);
}

/* Gate C: the target's privilege, and SELECT whenever a column of it may be read */
static void t_priv_writes(void)
{
    imdb_db *db = setup();
    CHECK(db);
    REFUSED("INSERT INTO t VALUES (9, 90, 'nine')", "for table t");
    ADMIN("GRANT INSERT ON t TO r");
    TAKEN("INSERT INTO t VALUES (9, 90, 'nine')");
    REFUSED("INSERT INTO t VALUES (10, 1, 'x') RETURNING id", "for table t");
    REFUSED("INSERT INTO t VALUES (9, 1, 'x') ON CONFLICT DO NOTHING", "for table t");
    REFUSED("INSERT INTO t SELECT id + 100, x, 'u' FROM u", "for table u"); /* its query: Gate B */
    REFUSED("UPDATE t SET a = 0", "for table t");
    REFUSED("DELETE FROM t", "for table t");
    ADMIN("GRANT UPDATE ON t TO r");
    TAKEN("UPDATE t SET a = 0");
    TAKEN("UPDATE t SET a = 7, s = 'k'");
    REFUSED("UPDATE t SET a = 0 WHERE id = 1", "for table t"); /* its count would tell */
    /* a WHERE as a tree, whatever its form (each counted in nwhere: a residual, an OR, a NOT, a constant) */
    static const char *const wt[] = {"UPDATE t SET a = 0 WHERE id = 1 OR id = 2", "UPDATE t SET a = 0 WHERE NOT (id = 1)",
                                     "UPDATE t SET a = 0 WHERE a + 1 > 0", "UPDATE t SET a = 0 WHERE true",
                                     "UPDATE t SET a = 0 WHERE s LIKE 'o%'", "UPDATE t SET a = 0 WHERE id IN (1, 2)",
                                     "UPDATE t SET a = 0 WHERE a IS NULL"};
    for (size_t i = 0; i < sizeof wt / sizeof wt[0]; i++) REFUSED(wt[i], "for table t");
    REFUSED("UPDATE t SET a = a + 1", "for table t");
    REFUSED("UPDATE t SET a = 1 + 1", "for table t"); /* any expression: fail closed */
    REFUSED("UPDATE t SET a = 0 RETURNING id", "for table t");
    REFUSED("EXPLAIN UPDATE t SET a = 0 WHERE id = 1", "for table t");
    ADMIN("GRANT DELETE ON t TO r");
    TAKEN("DELETE FROM t");
    ADMIN("INSERT INTO t VALUES (1, 10, 'one'), (2, 20, 'two')");
    REFUSED("DELETE FROM t WHERE id = 1", "for table t");
    REFUSED("DELETE FROM t WHERE id = 1 OR a > 5", "for table t");
    REFUSED("DELETE FROM t WHERE true", "for table t");
    ADMIN("GRANT SELECT ON t TO r");
    TAKEN("UPDATE t SET a = a + 1 WHERE id = 1");
    TAKEN("EXPLAIN UPDATE t SET a = 0 WHERE id = 1");
    TAKEN("INSERT INTO t VALUES (1, 1, 'x') ON CONFLICT (id) DO UPDATE SET a = 5");
    TAKEN("DELETE FROM t WHERE id = 2 RETURNING id");
    REFUSED("UPDATE t SET a = u.x FROM u WHERE u.id = t.id", "for table u");
    REFUSED("DELETE FROM t USING u WHERE u.id = t.id", "for table u");
    ADMIN("GRANT SELECT ON u TO r");
    TAKEN("UPDATE t SET a = u.x FROM u WHERE u.id = t.id");
    /* a write to a view is the view's own refusal, never a privilege's */
    SOFT(run_on(&g_r, "INSERT INTO v VALUES (5, 5)") == IMDB_ERR_INVALID);
    /* nothing was written by a refused statement */
    SOFT(run_on(&g_a, "SELECT COUNT(*) FROM t WHERE id >= 9") == 0);
    teardown(db);
}

/* AS OF a dropped table: its grants ended at the drop, so its history is a superuser's; a name reused is another
 * object both ways */
static void t_priv_dropped(void)
{
    imdb_db *db = setup();
    CHECK(db);
    ADMIN("CREATE TABLE x (id INT64 PRIMARY KEY)");
    ADMIN("INSERT INTO x VALUES (1)");
    ADMIN("GRANT SELECT ON x TO r");
    uint64_t old = db->seq;
    char q[96];
    snprintf(q, sizeof q, "SELECT COUNT(*) FROM x AS OF %llu", (unsigned long long)old);
    TAKEN(q);
    ADMIN("DROP TABLE x");
    REFUSED(q, "for table x");
    SOFT(run_on(&g_a, q) == 0);
    ADMIN("CREATE TABLE x (id INT64 PRIMARY KEY)");
    ADMIN("INSERT INTO x VALUES (1), (2)");
    ADMIN("GRANT SELECT ON x TO r");
    TAKEN("SELECT COUNT(*) FROM x");
    REFUSED(q, "for table x"); /* the new x's grant never reaches the old one's history */
    teardown(db);
}


/* COPY FROM's data is asked for only once its gates pass (the server's COPY_IN: imdb_copy_in_open), so a role without
 * INSERT never spools a byte; the run then refused the same; not enforced, any COPY FROM opens */
static void t_priv_copy_open(void)
{
    imdb_db *db = setup();
    CHECK(db);
    static const char cp[] = "COPY t FROM STDIN";
    SOFT(!imdb_copy_in_open(&g_r, cp, sizeof cp - 1));
    SOFT(imdb_copy_in_open(&g_a, cp, sizeof cp - 1));
    SOFT(!imdb_copy_in_open(&g_r, "SELECT 1", 8) && !imdb_copy_in_open(&g_a, "SELECT 1", 8));
    REFUSED(cp, "for table t");
    ADMIN("GRANT INSERT ON t TO r");
    SOFT(imdb_copy_in_open(&g_r, cp, sizeof cp - 1));
    TAKEN(cp);
    SOFT(run_on(&g_a, "SELECT COUNT(*) FROM t WHERE id >= 9") == 0);
    uint32_t rid = g_r.role;
    g_r.role = 0; /* Gate A's verdict too */
    SOFT(!imdb_copy_in_open(&g_r, cp, sizeof cp - 1));
    g_r.role = rid;
    teardown(db);
}

/* N1e's review: every relation a statement names is checked before anything runs, whatever path the run would take
 * (EXISTS with LIMIT 0 or no FROM, an item EXISTS never computes, a view read in a branch no row takes): each nested
 * SELECT is bound before the first row, and the bind reaches read_table (a pre-pass over the statement's names, tried,
 * was a second lock no test could tell from the first: removed); and
 * a name no table holds (or a view) gets no COPY_IN; SHOW TABLES and SHOW RETENTION give a role no counts for a table
 * it cannot read */
static void t_priv_unrun(void)
{
    imdb_db *db = setup();
    CHECK(db);
    ADMIN("GRANT SELECT ON t TO r");
    static const char *const nu[] = {
        "SELECT id FROM t WHERE EXISTS (SELECT 1 FROM u LIMIT 0)",
        "SELECT id FROM t WHERE EXISTS (SELECT (SELECT MAX(x) FROM u))",
        "SELECT id FROM t WHERE NOT EXISTS (SELECT 1 FROM u WHERE 1 = 0)",
        "SELECT (SELECT COUNT(*) FROM u LIMIT 0) FROM t",
        "SELECT CASE WHEN id > 0 THEN 0 ELSE (SELECT COUNT(*) FROM w) END FROM t", /* w: SELECT not granted */
    };
    for (size_t i = 0; i < sizeof nu / sizeof nu[0]; i++) {
        int rc = run_on(&g_r, nu[i]);
        if (rc != IMDB_ERR_PRIVILEGE) {
            char m[700];
            snprintf(m, sizeof m, "want refused: %s: %d %s", nu[i], rc, g_msg);
            test_fail(__FILE__, __LINE__, m);
        }
    }
    /* a view granted whose body reads a table not granted, in a branch no row takes: the invoker's rights, before any
     * row */
    ADMIN("GRANT SELECT ON w TO r");
    REFUSED("SELECT CASE WHEN id > 0 THEN 0 ELSE (SELECT COUNT(*) FROM w) END FROM t", "permission denied for table u");
    /* a WITH's name shadowing a table: the row set, never the table (no false refusal) */
    TAKEN("WITH u AS (SELECT id FROM t) SELECT COUNT(*) FROM u");
    TAKEN("SELECT q.id FROM (SELECT id FROM t) AS q");
    /* COPY into nothing, or into a view: no COPY_IN, whoever asks */
    SOFT(!imdb_copy_in_open(&g_r, "COPY nosuch FROM STDIN", 22) && !imdb_copy_in_open(&g_a, "COPY nosuch FROM STDIN", 22));
    SOFT(!imdb_copy_in_open(&g_a, "COPY v FROM STDIN", 17));
    /* SHOW TABLES and SHOW RETENTION: counts and history for the tables the role reads alone */
    imdb_result res;
    imdb_err e = {0};
    SOFT(imdb_exec_one(&g_r, "SHOW TABLES", 11, NULL, 0, &res, &e) == 0);
    for (uint64_t i = 0; i < res.nrows; i++) {
        const imdb_cell *row = &res.cells[i * res.ncols];
        bool is_t = row[0].v.len == 1 && row[0].v.s[0] == 't';
        for (int c = 2; c <= 5; c++) {
            bool null = row[c].null;
            if (null == is_t) {
                char m[160];
                snprintf(m, sizeof m, "SHOW TABLES row %llu column %d: null %d", (unsigned long long)i, c, (int)null);
                test_fail(__FILE__, __LINE__, m);
            }
        }
    }
    imdb_result_free(&res);
    SOFT(imdb_exec_one(&g_r, "SHOW RETENTION", 14, NULL, 0, &res, &e) == 0);
    for (uint64_t i = 0; i < res.nrows; i++) {
        const imdb_cell *row = &res.cells[i * res.ncols];
        bool is_t = row[0].v.len == 1 && row[0].v.s[0] == 't';
        SOFT(row[2].null != is_t);
    }
    imdb_result_free(&res);
    teardown(db);
}

/* the same verdicts read from the lake: versions ended by an UPDATE and published by a CHECKPOINT, read AS OF before it
 * (under IMDB_EVICT=eager, the matrix's mode, from the segments alone; under IMDB_SEGCACHE=tiny each image read again),
 * and the live rows after it: refused for a table not granted, answered alike for one granted */
static void t_priv_lake(void)
{
    imdb_db *db = setup();
    CHECK(db);
    ADMIN("GRANT SELECT ON t TO r");
    uint64_t before = db->seq;
    ADMIN("UPDATE t SET a = a + 1");
    ADMIN("UPDATE u SET x = x + 1");
    ADMIN("CHECKPOINT");
    char q[128];
    snprintf(q, sizeof q, "SELECT SUM(a) FROM t AS OF %llu", (unsigned long long)before);
    imdb_result ra, rr;
    imdb_err e = {0};
    SOFT(imdb_exec_one(&g_a, q, strlen(q), NULL, 0, &ra, &e) == 0);
    imdb_err_clear(&e);
    SOFT(imdb_exec_one(&g_r, q, strlen(q), NULL, 0, &rr, &e) == 0);
    __int128 sa = ra.nrows == 1 ? (ra.cells[0].wide ? ra.cells[0].i128 : ra.cells[0].v.i) : -1;
    __int128 sr = rr.nrows == 1 ? (rr.cells[0].wide ? rr.cells[0].i128 : rr.cells[0].v.i) : -2;
    SOFT(sa == 60 && sr == 60); /* (10 + 20 + 30, before the UPDATE) */
    imdb_result_free(&ra);
    imdb_result_free(&rr);
    snprintf(q, sizeof q, "SELECT SUM(x) FROM u AS OF %llu", (unsigned long long)before);
    REFUSED(q, "for table u");
    REFUSED("SELECT COUNT(*) FROM u", "for table u");
    TAKEN("SELECT COUNT(*) FROM t");
    teardown(db);
}
const test_case priv_tests[] = {
    {"priv_kinds", t_priv_kinds},     {"priv_principal", t_priv_principal}, {"priv_super", t_priv_super},
    {"priv_reads", t_priv_reads},     {"priv_member", t_priv_member},       {"priv_writes", t_priv_writes},
    {"priv_dropped", t_priv_dropped}, {"priv_copy_open", t_priv_copy_open}, {"priv_unrun", t_priv_unrun}, {"priv_lake", t_priv_lake},
};
const size_t priv_ntests = sizeof priv_tests / sizeof *priv_tests;
