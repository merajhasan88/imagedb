/* N1e (docs/n1-design.md §8e): privileges enforced on a session the server marks (imdb_session.enforce, .role). Each
 * statement form as a role without and with what it needs: Gate A's kinds (every kind classified; superuser-only
 * statements and SET names refused), Gate B's reads (every nested form, views with the invoker's rights, branches no row
 * takes, AS OF by the object at the snapshot, FOR UPDATE, COPY TO, SHOW HISTORY, EXPLAIN, EXECUTE checked at each run),
 * Gate C's writes (the target's privilege, and SELECT whenever a column of it may be read: fail closed), membership
 * inherited transitively, the principal (none, a dropped role, a superuser). A refusal is IMDB_ERR_PRIVILEGE and its
 * message names the relation, never a privilege or a value. */
#include <stdlib.h>
#include <unistd.h>

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

/* N1e stage two: a role's caps (the server's options; here set on the session as the server sets them). Each held while
 * the role is not a superuser, read where it is checked: the statement timeout and the row limit at a statement's start,
 * the transaction's two at each check (a role demoted mid-transaction held at once, one promoted released at once); SET
 * of each to 0 (none) or past its cap refused for the role, a lower value taken; a session's prepared bytes. Each section
 * sets the one cap it tests (another's clock never decides its message under a slow build); the capped join is 16
 * million pairs, seconds uncapped, so a 150 ms cap always cuts it */
static void t_priv_caps(void)
{
    imdb_db *db = setup();
    CHECK(db);
    ADMIN("CREATE TABLE big (id INT64 PRIMARY KEY, v INT64)");
    static char ins[80000];
    size_t o = (size_t)snprintf(ins, sizeof ins, "INSERT INTO big VALUES (0, 0)");
    for (int i = 1; i < 4000; i++) o += (size_t)snprintf(ins + o, sizeof ins - o, ", (%d, %d)", i, i % 7);
    ADMIN(ins);
    ADMIN("GRANT SELECT ON big TO r");
    ADMIN("GRANT SELECT ON t TO r");
    static const char join[] = "SELECT COUNT(*) FROM big AS a, big AS b WHERE a.v + b.v = 99";
    /* the statement cap: its own value none, so the cap governs */
    g_r.caps = (imdb_caps){.stmt_ms = 150};
    int rc = run_on(&g_r, join);
    SOFT(rc == IMDB_ERR_CANCELLED && strstr(g_msg, "150 ms") && strstr(g_msg, "--role-statement-timeout"));
    if (rc != IMDB_ERR_CANCELLED) fprintf(stderr, "    the capped statement: %d %s\n", rc, g_msg);
    REFUSED("SET statement_timeout = 0", "the server's cap for a role (150)");
    REFUSED("SET statement_timeout = 151", "the server's cap for a role (150)");
    TAKEN("SET statement_timeout = 120");
    rc = run_on(&g_r, join);
    SOFT(rc == IMDB_ERR_CANCELLED && strstr(g_msg, "120 ms") && strstr(g_msg, "SET statement_timeout"));
    /* the row limit (D8 #4: the rows past the scan's plain predicates) */
    g_r.caps = (imdb_caps){.row_limit = 1000};
    rc = run_on(&g_r, "SELECT COUNT(*) FROM big WHERE v >= 0");
    SOFT(rc == IMDB_ERR_LIMIT && strstr(g_msg, "1000 rows") && strstr(g_msg, "--role-row-limit"));
    if (rc != IMDB_ERR_LIMIT) fprintf(stderr, "    the capped rows: %d %s\n", rc, g_msg);
    REFUSED("SET statement_row_limit = 0", "the server's cap for a role (1000)");
    REFUSED("SET statement_row_limit = 5000", "the server's cap for a role (1000)");
    TAKEN("SET statement_row_limit = 10");
    TAKEN("SELECT COUNT(*) FROM t");
    /* idle in transaction */
    g_r.caps = (imdb_caps){.idle_ms = 200};
    TAKEN("BEGIN");
    TAKEN("SELECT COUNT(*) FROM t");
    usleep(300000);
    rc = run_on(&g_r, "SELECT COUNT(*) FROM t");
    SOFT(rc == IMDB_ERR_CANCELLED && strstr(g_msg, "--role-idle-in-transaction"));
    TAKEN("ROLLBACK");
    REFUSED("SET idle_in_transaction_timeout = 0", "the server's cap for a role (200)");
    /* the transaction's age (statements every 50 ms; no idle cap) */
    g_r.caps = (imdb_caps){.txn_ms = 700};
    TAKEN("BEGIN");
    rc = 0;
    for (int k = 0; k < 400 && !rc; k++) {
        usleep(50000);
        rc = run_on(&g_r, "SELECT COUNT(*) FROM t");
    }
    SOFT(rc == IMDB_ERR_CANCELLED && strstr(g_msg, "700 ms") && strstr(g_msg, "--role-transaction-timeout"));
    TAKEN("ROLLBACK");
    REFUSED("SET transaction_timeout = 701", "the server's cap for a role (700)");
    /* a superuser: unbounded, its SET of none taken; demoted inside a transaction, held at the next check */
    g_r.caps = (imdb_caps){.idle_ms = 200};
    ADMIN("ALTER ROLE r SUPERUSER");
    TAKEN("SET idle_in_transaction_timeout = 0");
    TAKEN("BEGIN");
    TAKEN("SELECT COUNT(*) FROM t");
    usleep(300000);
    TAKEN("SELECT COUNT(*) FROM t"); /* a superuser's: none */
    ADMIN("ALTER ROLE r NOSUPERUSER");
    usleep(300000);
    rc = run_on(&g_r, "SELECT COUNT(*) FROM t");
    SOFT(rc == IMDB_ERR_CANCELLED && strstr(g_msg, "--role-idle-in-transaction"));
    TAKEN("ROLLBACK");
    /* promoted inside one: released at once */
    TAKEN("BEGIN");
    TAKEN("SELECT COUNT(*) FROM t");
    ADMIN("ALTER ROLE r SUPERUSER");
    usleep(300000);
    TAKEN("SELECT COUNT(*) FROM t");
    TAKEN("COMMIT");
    ADMIN("ALTER ROLE r NOSUPERUSER");
    /* the prepared statements' bytes */
    g_r.caps = (imdb_caps){.prep_bytes = 64u << 10};
    static char big[70000];
    o = (size_t)snprintf(big, sizeof big, "PREPARE p AS SELECT 1");
    while (o + 8 < sizeof big - 16) o += (size_t)snprintf(big + o, sizeof big - o, " + 1");
    rc = run_on(&g_r, big);
    SOFT(rc == IMDB_ERR_LIMIT && strstr(g_msg, "65536"));
    if (rc != IMDB_ERR_LIMIT) fprintf(stderr, "    a large PREPARE: %d %s\n", rc, g_msg);
    TAKEN("PREPARE q AS SELECT COUNT(*) FROM t");
    g_r.caps = (imdb_caps){0};
    teardown(db);
}

/* N1e stage two: a superuser's session SETs what only a superuser may (cross_check, slow_statement_ms, sync_replicas,
 * sync_timeout_ms, statement_memory past a role's share), is demoted by another session, and runs: from that statement
 * on it holds none of them (Gate A resets them: demoted_reset), as the caps are read where they are checked; promoted
 * again, it SETs them again */
static void t_priv_demoted(void)
{
    imdb_db *db = setup();
    CHECK(db);
    ADMIN("GRANT SELECT ON t TO r");
    ADMIN("ALTER ROLE r SUPERUSER");
    TAKEN("SET cross_check = on");
    TAKEN("SET slow_statement_ms = 5");
    TAKEN("SET sync_replicas = 1");
    TAKEN("SET sync_timeout_ms = 5000");
    TAKEN("SET statement_memory = 2147483648"); /* 2 GiB: past the share without a budget (1 GiB) */
    CHECK(g_r.cross_check && g_r.slow_ms == 5 && g_r.sync_replicas == 1 && g_r.sync_wait_ms == 5000 &&
          g_r.stmt_memory == 2147483648ull);
    TAKEN("SET sync_replicas = 0");
    TAKEN("SET sync_replicas = 1"); /* (a primary without replicas: a commit would wait; this session commits nothing) */
    ADMIN("ALTER ROLE r NOSUPERUSER");
    TAKEN("SELECT COUNT(*) FROM t");
    SOFT(!g_r.cross_check && g_r.slow_ms == 0 && g_r.sync_replicas == 0 && g_r.sync_wait_ms == 0 && g_r.stmt_memory == 0);
    REFUSED("SET cross_check = on", "needs a superuser");
    TAKEN("SET statement_memory = 1048576"); /* within the share: a role's own, kept */
    TAKEN("SELECT COUNT(*) FROM t");
    SOFT(g_r.stmt_memory == 1048576);
    ADMIN("ALTER ROLE r SUPERUSER");
    TAKEN("SET cross_check = on");
    TAKEN("SELECT COUNT(*) FROM t");
    SOFT(g_r.cross_check);
    /* a field a harness sets on the session directly (the oracle's --privs battery cross-checks its role's session) is
     * not the session's SET: demoted, the reset takes back the SET (above), never the harness's field */
    ADMIN("ALTER ROLE r NOSUPERUSER");
    TAKEN("SELECT COUNT(*) FROM t"); /* the SET above taken back */
    SOFT(!g_r.cross_check);
    g_r.cross_check = true;
    TAKEN("SELECT COUNT(*) FROM t");
    TAKEN("SELECT COUNT(*) FROM t");
    SOFT(g_r.cross_check);
    /* and beside a SET the reset does take back: the harness's field stays, the SET goes */
    ADMIN("ALTER ROLE r SUPERUSER");
    TAKEN("SET slow_statement_ms = 7");
    ADMIN("ALTER ROLE r NOSUPERUSER");
    TAKEN("SELECT COUNT(*) FROM t");
    SOFT(g_r.cross_check && g_r.slow_ms == 0);
    g_r.cross_check = false;
    teardown(db);
}


/* refused by the disk headroom: a LIMIT naming --disk-headroom, never a privilege refusal */
#define DISKLOW(sql)                                                                                                   \
    do {                                                                                                               \
        int rc_ = run_on(&g_r, (sql));                                                                                 \
        if (rc_ != IMDB_ERR_LIMIT || !strstr(g_msg, "--disk-headroom")) {                                              \
            char m_[900];                                                                                              \
            snprintf(m_, sizeof m_, "want refused by the headroom: %s: %d %s", (sql), rc_, g_msg);                     \
            test_fail(__FILE__, __LINE__, m_);                                                                         \
        }                                                                                                              \
    } while (0)

/* 2b-3: --disk-headroom at the engine (the server sets disk_low before each statement): a role holding every privilege
 * on t and u refused every form of row write by name, COPY FROM's data never asked, nothing logged (the commit sequence
 * unmoved but by its COMMIT), no privilege refusal counted; reads, EXPLAIN, SET, PREPARE, BEGIN and ROLLBACK taken, a
 * refusal inside a transaction leaving it as a privilege refusal does, and a COMMIT of what it wrote before taken; a
 * superuser's enforced session and an embedded caller's write */
static void t_priv_disk(void)
{
    imdb_db *db = setup();
    CHECK(db);
    ADMIN("GRANT SELECT, INSERT, UPDATE, DELETE ON t TO r");
    ADMIN("GRANT SELECT, INSERT, UPDATE, DELETE ON u TO r");
    ADMIN("CREATE ROLE boss SUPERUSER");
    TAKEN("PREPARE ins AS INSERT INTO t VALUES (50, 1, 'p')");
    TAKEN("BEGIN");
    TAKEN("INSERT INTO t VALUES (40, 1, 'b')");
    g_r.disk_low = true;
    uint64_t seq = db->seq, pr = db->stats.priv_refused[0] + db->stats.priv_refused[1] + db->stats.priv_refused[2];
    DISKLOW("INSERT INTO t VALUES (41, 1, 'x')");
    SOFT(g_r.disk_refused);
    TAKEN("SELECT COUNT(*) FROM t WHERE id = 40"); /* its transaction goes on */
    TAKEN("COMMIT");                                /* what it wrote before: a margin, not a quota */
    SOFT(db->seq == seq + 1);
    seq = db->seq;
    static const char *const w[] = {"INSERT INTO t VALUES (41, 1, 'x')",
                                    "INSERT INTO t VALUES (42, 1, 'x') RETURNING id",
                                    "INSERT INTO t VALUES (1, 1, 'x') ON CONFLICT (id) DO UPDATE SET a = 5",
                                    "INSERT INTO t VALUES (1, 1, 'x') ON CONFLICT DO NOTHING",
                                    "INSERT INTO t SELECT id + 100, x, 'u' FROM u",
                                    "UPDATE t SET a = 0",
                                    "UPDATE u SET x = x + 1 WHERE id = 1 RETURNING x",
                                    "UPDATE t SET a = u.x FROM u WHERE u.id = t.id",
                                    "DELETE FROM t WHERE id = 1",
                                    "DELETE FROM t USING u WHERE u.id = t.id",
                                    "EXECUTE ins",
                                    "COPY t FROM STDIN"};
    for (size_t i = 0; i < sizeof w / sizeof w[0]; i++) DISKLOW(w[i]);
    SOFT(g_cpk == 0); /* COPY's data never asked for */
    SOFT(!imdb_copy_in_open(&g_r, "COPY t FROM STDIN", 17));
    static const char *const ok[] = {"SELECT COUNT(*) FROM t", "EXPLAIN UPDATE t SET a = 0 WHERE id = 1",
                                     "SET statement_timeout = 1000", "SELECT id FROM t WHERE id = 1 FOR UPDATE",
                                     "BEGIN", "SELECT x FROM u WHERE id = 2", "ROLLBACK"};
    for (size_t i = 0; i < sizeof ok / sizeof ok[0]; i++) TAKEN(ok[i]);
    SOFT(db->seq == seq); /* nothing logged */
    SOFT(db->stats.priv_refused[0] + db->stats.priv_refused[1] + db->stats.priv_refused[2] == pr);
    uint32_t rid = g_r.role;
    g_r.role = imdb_role_by_name(db, "boss")->id; /* a superuser's enforced session writes */
    TAKEN("INSERT INTO t VALUES (60, 1, 's')");
    g_r.role = rid;
    g_a.disk_low = true; /* an embedded caller's too (never enforced) */
    ADMIN("INSERT INTO t VALUES (61, 1, 's')");
    g_r.disk_low = g_a.disk_low = false;
    TAKEN("INSERT INTO t VALUES (62, 1, 's')");
    SOFT(run_on(&g_a, "SELECT COUNT(*) FROM t WHERE id IN (40, 60, 61, 62)") == 0);
    imdb_result res;
    imdb_err e = {0};
    static const char cnt[] = "SELECT COUNT(*) FROM t WHERE id IN (40, 41, 42, 50, 60, 61, 62)";
    if (!imdb_exec_one(&g_a, cnt, sizeof cnt - 1, NULL, 0, &res, &e)) {
        SOFT(res.nrows == 1 && res.cells[0].v.i == 4);
        imdb_result_free(&res);
    } else {
        SOFT(false);
    }
    teardown(db);
}
/* N1e stage two: each gate's refusal counted (A: a kind or a SET past a cap, B: a read, C: a write's target) and an
 * event "privilege" (the role's id, never its name; the gate; the relation's id; the shape, no value), at most 4 a second
 * a role: a burst's events and its dropped count add to its refusals */
static void t_priv_events(void)
{
    const char *dir = test_tmpdir();
    char db_dir[600], ev[600];
    snprintf(db_dir, sizeof db_dir, "%s/db", dir);
    snprintf(ev, sizeof ev, "%s/events.jsonl", dir);
    imdb_err e = {0};
    CHECK_OK(imdb_init(db_dir, false, NULL, &e));
    imdb_open_opts o = {.sync = 0, .events_path = ev};
    imdb_db *db = NULL;
    CHECK_OK(imdb_open(db_dir, &o, &db, &e));
    imdb_session_init(&g_a, db);
    imdb_session_init(&g_r, db);
    ADMIN("CREATE TABLE secret (id INT64 PRIMARY KEY, v INT64)");
    ADMIN("CREATE ROLE prober");
    ADMIN("CREATE ROLE admin SUPERUSER"); /* named by the prober's refused statements */
    g_r.enforce = true;
    g_r.role = imdb_role_by_name(db, "prober")->id;
    g_r.caps = (imdb_caps){.stmt_ms = 1000};
    uint32_t rel = imdb_table_by_name(db, "secret")->s.id;
    uint64_t r0[3] = {db->stats.priv_refused[0], db->stats.priv_refused[1], db->stats.priv_refused[2]};
    uint64_t t0 = imdb_mono_ns() / 1000000000u, d00 = db->stats.priv_events_dropped;
    REFUSED("CREATE TABLE x (id INT64 PRIMARY KEY)", "needs a superuser");     /* A */
    REFUSED("SET statement_timeout = 0", "the server's cap for a role");        /* A: a SET past a cap */
    REFUSED("SELECT v FROM secret WHERE id = 42", "permission denied for table secret"); /* B */
    REFUSED("INSERT INTO secret VALUES (1, 2)", "permission denied for table secret");   /* C */
    REFUSED("SHOW GRANTS FOR admin", "needs a superuser");                     /* A (no gate: kind's count) */
    REFUSED("ALTER ROLE admin PASSWORD 'pw-x'", "needs a superuser");            /* A: a role's name and a secret */
    SOFT(db->stats.priv_refused[0] == r0[0] + 4 && db->stats.priv_refused[1] == r0[1] + 1 &&
         db->stats.priv_refused[2] == r0[2] + 1);
    uint64_t d0 = db->stats.priv_events_dropped;
    for (int k = 0; k < 12; k++) REFUSED("SELECT v FROM secret", "permission denied");
    uint64_t secs = imdb_mono_ns() / 1000000000u - t0 + 1;
    uint64_t dropped = db->stats.priv_events_dropped - d00;
    (void)d0;
    imdb_session_close(&g_r);
    imdb_session_close(&g_a);
    CHECK_OK(imdb_close(db));
    /* the log: every privilege event's fields, and the burst's count */
    static char buf[1u << 20];
    FILE *f = fopen(ev, "r");
    size_t got = f ? fread(buf, 1, sizeof buf - 1, f) : 0;
    if (f) fclose(f);
    buf[got] = 0;
    int n = 0, gb = 0;
    char want_b[96], want_c[96];
    snprintf(want_b, sizeof want_b, "\"gate\":\"B\",\"relation\":%u,", rel);
    snprintf(want_c, sizeof want_c, "\"gate\":\"C\",\"relation\":%u,", rel);
    for (char *p = buf; (p = strstr(p, "\"ev\":\"privilege\"")); p++) {
        char *eol = strchr(p, '\n');
        if (eol) *eol = 0;
        n++;
        gb += strstr(p, want_b) != NULL;
        /* the role's id, never a role's name (its own, or one a statement names: SHOW GRANTS FOR, ALTER ROLE keep their
         * leading keywords alone), never a value (the shape's ?), never a password */
        SOFT(!strstr(p, "prober") && !strstr(p, "admin") && !strstr(p, "pw-x") && !strstr(p, "42"));
        if (eol) *eol = '\n';
    }
    SOFT(strstr(buf, want_c) != NULL && strstr(buf, "\"gate\":\"A\"") && gb >= 1);
    /* 18 refusals: 6 before the burst, 12 in it; events and the dropped count add to them, at most 4 a second */
    SOFT((uint64_t)n + dropped == 18);
    SOFT((uint64_t)n <= 4 * (secs + 1));
    if ((uint64_t)n + dropped != 18) fprintf(stderr, "    privilege events %d, dropped %llu, of 18\n", n, (unsigned long long)dropped);
}
const test_case priv_tests[] = {
    {"priv_kinds", t_priv_kinds},     {"priv_principal", t_priv_principal}, {"priv_super", t_priv_super},
    {"priv_reads", t_priv_reads},     {"priv_member", t_priv_member},       {"priv_writes", t_priv_writes},
    {"priv_dropped", t_priv_dropped}, {"priv_copy_open", t_priv_copy_open}, {"priv_unrun", t_priv_unrun}, {"priv_lake", t_priv_lake},
    {"priv_caps", t_priv_caps},
    {"priv_demoted", t_priv_demoted},
    {"priv_events", t_priv_events},
    {"priv_disk", t_priv_disk},
};
const size_t priv_ntests = sizeof priv_tests / sizeof *priv_tests;
