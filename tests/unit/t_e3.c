/* E3: SERIALIZABLE, stage 1 (docs/e3-design.md): a SERIALIZABLE writer commits only if no table it read was written
 * since its snapshot; a read-only one is not validated; an ERASE dooms a SERIALIZABLE reader of a table it touches.
 * The anomalies SNAPSHOT allows (write skew, a phantom, Fekete's read-only anomaly) refused or made serial; every read
 * path recording its table (a scan, the primary key, an index, COUNT(*), an aggregate, a join, a view, a nested
 * SELECT, the lake at a budget of none, ON CONFLICT's probe, a key found absent); the read set kept through a parked
 * transaction and ROLLBACK TO; DDL as a write; AS OF recording nothing; the level's statements and the session's
 * default. */
#include <stdlib.h>

#include "../../src/db_internal.h"
#include "../../src/sql.h"
#include "thelp.h"

static int srun(imdb_session *s, const char *sql)
{
    imdb_result r;
    imdb_err_clear(&g_e);
    int rc = imdb_exec_one(s, sql, strlen(sql), NULL, 0, &r, &g_e);
    if (!rc) imdb_result_free(&r);
    return rc;
}

static int64_t sval(imdb_session *s, const char *sql)
{
    imdb_result r;
    imdb_err_clear(&g_e);
    if (imdb_exec_one(s, sql, strlen(sql), NULL, 0, &r, &g_e) || r.nrows != 1) return INT64_MIN;
    const imdb_cell *c = &r.cells[0];
    int64_t v = c->null ? INT64_MIN : c->wide ? (int64_t)c->i128 : c->v.i;
    imdb_result_free(&r);
    return v;
}

#define SRUN(s, sql)                                                                                                   \
    do {                                                                                                               \
        if (srun(s, sql)) {                                                                                            \
            char m_[900];                                                                                              \
            snprintf(m_, sizeof m_, "%s -> %s", sql, g_e.msg);                                                         \
            test_fail(__FILE__, __LINE__, m_);                                                                         \
            return;                                                                                                    \
        }                                                                                                              \
    } while (0)

/* the commit fails with CONFLICT (and the transaction is gone), or the test fails */
#define CONFLICTS(s, sql)                                                                                              \
    do {                                                                                                               \
        int rc_ = srun(s, sql);                                                                                        \
        if (rc_ != IMDB_ERR_CONFLICT || (s)->txn.open) {                                                               \
            char m_[900];                                                                                              \
            snprintf(m_, sizeof m_, "%s: want CONFLICT, got %d (%s)", sql, rc_, g_e.msg);                              \
            test_fail(__FILE__, __LINE__, m_);                                                                         \
            return;                                                                                                    \
        }                                                                                                              \
    } while (0)

static char g_dir[600]; /* the last ser_setup's directory */

static imdb_db *ser_setup(imdb_session *a, imdb_session *b, uint64_t budget)
{
    const char *dir = test_tmpdir();
    snprintf(g_dir, sizeof g_dir, "%s", dir);
    imdb_err e = {0};
    if (imdb_init(dir, false, NULL, &e)) return NULL;
    imdb_open_opts o = {.sync = 0, .seg_cache_bytes = budget};
    imdb_db *db = NULL;
    if (imdb_open(dir, &o, &db, &e)) return NULL;
    imdb_session_init(a, db);
    imdb_session_init(b, db);
    if (srun(a, "CREATE TABLE t (id INT64 PRIMARY KEY, u INT64 SUBJECT, v INT64)") ||
        srun(a, "CREATE TABLE w (id INT64 PRIMARY KEY, v INT64)") || srun(a, "CREATE INDEX t_v ON t (v)") ||
        srun(a, "INSERT INTO t VALUES (1, 1, 10), (2, 2, 20)") || srun(a, "INSERT INTO w VALUES (1, 0)")) {
        imdb_close(db);
        return NULL;
    }
    return db;
}

static void ser_close(imdb_db *db, imdb_session *a, imdb_session *b)
{
    imdb_session_close(a);
    imdb_session_close(b);
    imdb_close(db);
}

/* Write skew (two doctors on call): each reads both rows and changes a different one. SNAPSHOT lets both commit
 * (t_txn's write_skew_allowed); SERIALIZABLE refuses the second, and the rule holds after it */
static void t_ser_write_skew(void)
{
    imdb_session a, b;
    imdb_db *db = ser_setup(&a, &b, 0);
    CHECK(db);
    if (!db) return;
    uint64_t c0 = db->stats.ser_conflicts;
    SRUN(&a, "BEGIN ISOLATION LEVEL SERIALIZABLE");
    SRUN(&b, "BEGIN ISOLATION LEVEL SERIALIZABLE");
    CHECK(sval(&a, "SELECT SUM(v) FROM t") == 30 && sval(&b, "SELECT SUM(v) FROM t") == 30);
    SRUN(&a, "UPDATE t SET v = 0 WHERE id = 1");
    SRUN(&b, "UPDATE t SET v = 0 WHERE id = 2");
    SRUN(&a, "COMMIT");
    CONFLICTS(&b, "COMMIT");
    CHECK(sval(&a, "SELECT SUM(v) FROM t") == 20 && db->stats.ser_conflicts == c0 + 1);
    ser_close(db, &a, &b);
}

/* A phantom: a counts the rows with v above 5 (a range by the index), b inserts one and commits, a writes from its
 * count: refused. And a lost update stays refused (first committer wins) */
static void t_ser_phantom(void)
{
    imdb_session a, b;
    imdb_db *db = ser_setup(&a, &b, 0);
    CHECK(db);
    if (!db) return;
    SRUN(&a, "BEGIN ISOLATION LEVEL SERIALIZABLE");
    CHECK(sval(&a, "SELECT COUNT(*) FROM t WHERE v > 5") == 2);
    SRUN(&b, "INSERT INTO t VALUES (3, 3, 30)");
    SRUN(&a, "UPDATE w SET v = 2 WHERE id = 1");
    CONFLICTS(&a, "COMMIT");
    SRUN(&a, "BEGIN ISOLATION LEVEL SERIALIZABLE");
    SRUN(&b, "BEGIN ISOLATION LEVEL SERIALIZABLE");
    CHECK(sval(&a, "SELECT v FROM t WHERE id = 1") == 10 && sval(&b, "SELECT v FROM t WHERE id = 1") == 10);
    SRUN(&a, "UPDATE t SET v = 11 WHERE id = 1");
    SRUN(&a, "COMMIT");
    CHECK(srun(&b, "UPDATE t SET v = 12 WHERE id = 1") == IMDB_ERR_CONFLICT || srun(&b, "COMMIT") == IMDB_ERR_CONFLICT);
    if (b.txn.open) SRUN(&b, "ROLLBACK");
    CHECK(sval(&a, "SELECT v FROM t WHERE id = 1") == 11);
    ser_close(db, &a, &b);
}

/* Fekete's read-only anomaly (checking x = row 1, savings y = row 2): T2 reads both and withdraws from x, T3 deposits
 * into y and commits, T1 (read-only) reads both, T2 commits. Under SNAPSHOT T1 saw T3 but not T2 while T2 must precede
 * T3: no serial order. Here T1 commits (read-only, its snapshot a serial point) and T2, which read a table T3 wrote, is
 * refused */
static void t_ser_read_only(void)
{
    imdb_session a, b, c;
    imdb_db *db = ser_setup(&a, &b, 0);
    CHECK(db);
    if (!db) return;
    imdb_session_init(&c, db);
    SRUN(&b, "BEGIN ISOLATION LEVEL SERIALIZABLE"); /* T2 */
    CHECK(sval(&b, "SELECT SUM(v) FROM t") == 30);
    SRUN(&c, "BEGIN ISOLATION LEVEL SERIALIZABLE"); /* T3 */
    SRUN(&c, "UPDATE t SET v = v + 20 WHERE id = 2");
    SRUN(&c, "COMMIT");
    SRUN(&a, "BEGIN ISOLATION LEVEL SERIALIZABLE"); /* T1, read-only */
    CHECK(sval(&a, "SELECT SUM(v) FROM t") == 50);
    SRUN(&b, "UPDATE t SET v = v - 11 WHERE id = 1");
    CONFLICTS(&b, "COMMIT");
    SRUN(&a, "COMMIT");
    imdb_session_close(&c);
    ser_close(db, &a, &b);
}

/* every read path records its table: a's read by FORM, b's write to t, then a's write to w: refused; a's read of w
 * alone (a control) and b's write to t: committed */
static void ser_path(imdb_db *db, imdb_session *a, imdb_session *b, const char *form, int *k, bool *ok)
{
    char q[160];
    *ok = false;
    if (srun(a, "BEGIN ISOLATION LEVEL SERIALIZABLE")) return;
    imdb_result r;
    imdb_err_clear(&g_e);
    if (imdb_exec_one(a, form, strlen(form), NULL, 0, &r, &g_e)) {
        fprintf(stderr, "    %s: %s\n", form, g_e.msg);
        return;
    }
    imdb_result_free(&r);
    snprintf(q, sizeof q, "INSERT INTO t VALUES (%d, 9, 9)", 100 + (*k)++);
    if (srun(b, q)) return;
    if (srun(a, "UPDATE w SET v = v + 1 WHERE id = 1")) return;
    uint64_t c0 = db->stats.ser_conflicts;
    int rc = srun(a, "COMMIT");
    /* the validation's refusal, not a key's (its count moves by one) */
    *ok = rc == IMDB_ERR_CONFLICT && !a->txn.open && db->stats.ser_conflicts == c0 + 1;
    if (!*ok) fprintf(stderr, "    %s: the commit gave %d (%s)\n", form, rc, g_e.msg);
}

static long nul_read(void *arg, char *buf, size_t cap)
{
    (void)arg, (void)buf, (void)cap;
    return 0;
}

static int nul_write(void *arg, const char *buf, size_t len)
{
    (void)arg, (void)buf, (void)len;
    return 0;
}

static void t_ser_paths(void)
{
    imdb_session a, b;
    imdb_db *db = ser_setup(&a, &b, 0);
    CHECK(db);
    if (!db) return;
    imdb_session_copy_io(&a, nul_read, nul_write, NULL);
    SRUN(&a, "CREATE VIEW tv AS SELECT id, v FROM t WHERE v > 0");
    SRUN(&a, "PREPARE pt (INT64) AS SELECT v FROM t WHERE id = $1");
    static const char *const forms[] = {
        "SELECT * FROM t",                                 /* a scan */
        "SELECT v FROM t WHERE id = 1",                    /* the primary key */
        "SELECT id FROM t WHERE id = 99",                  /* a key found absent */
        "SELECT id FROM t WHERE v = 10",                   /* an index */
        "SELECT id FROM t WHERE v BETWEEN 11 AND 19",      /* an index range finding nothing */
        "SELECT COUNT(*) FROM t",                          /* COUNT(*) */
        "SELECT MAX(v), SUM(v) FROM t",                    /* an aggregate */
        "SELECT w.id FROM w JOIN t ON t.id = w.id",        /* a join */
        "SELECT * FROM tv",                                /* a view */
        "SELECT id FROM w WHERE v IN (SELECT v FROM t)",   /* a nested SELECT */
        "SELECT * FROM (SELECT id FROM t) AS d",           /* a derived table */
        "SELECT id, (SELECT v FROM t WHERE t.id = w.id) FROM w",          /* a correlated value subquery */
        "SELECT id FROM w WHERE EXISTS (SELECT 1 FROM t WHERE t.id = w.id)", /* a correlated EXISTS */
        "SELECT id FROM w UNION SELECT id FROM t",         /* a set operation */
        "WITH RECURSIVE r (n) AS (SELECT MIN(id) FROM t UNION ALL SELECT n + 1 FROM r WHERE n < 3) SELECT n FROM r",
        "SELECT id, SUM(v) OVER (ORDER BY id) FROM t",     /* a window */
        "EXECUTE pt (1)",                                  /* a prepared statement */
        "SELECT id FROM t WHERE id = 1 FOR UPDATE",        /* FOR UPDATE */
        "COPY t TO STDOUT",                                /* COPY's walk */
        "UPDATE t SET v = v WHERE v > 1000",               /* a write's predicate meeting no row */
        "DELETE FROM t WHERE v > 1000",
        "UPDATE w SET v = t.v FROM t WHERE t.id = w.id + 1000",  /* UPDATE ... FROM, no pair */
        "DELETE FROM w USING t WHERE t.id = w.id + 1000",        /* DELETE ... USING, no pair */
        "INSERT INTO w SELECT id + 1000, v FROM t",        /* a write's read */
        "INSERT INTO t VALUES (1, 1, 10) ON CONFLICT (id) DO NOTHING", /* ON CONFLICT's probe */
        "EXPLAIN SELECT * FROM t WHERE id = 1",            /* EXPLAIN passes the view's check (its nested SELECTs read rows) */
    };
    int k = 0;
    for (size_t i = 0; i < sizeof forms / sizeof *forms; i++) {
        bool ok = false;
        ser_path(db, &a, &b, forms[i], &k, &ok);
        if (!ok) test_fail(__FILE__, __LINE__, forms[i]);
        if (a.txn.open) SRUN(&a, "ROLLBACK");
    }
    /* the controls: what a reads only of w, or of t AS OF, a write to t does not touch */
    static const char *const free_[] = {"SELECT * FROM w", "SELECT * FROM t AS OF 3", "SELECT 1"};
    for (size_t i = 0; i < sizeof free_ / sizeof *free_; i++) {
        char q[96];
        SRUN(&a, "BEGIN ISOLATION LEVEL SERIALIZABLE");
        SRUN(&a, free_[i]);
        snprintf(q, sizeof q, "INSERT INTO t VALUES (%d, 9, 9)", 200 + (int)i);
        SRUN(&b, q);
        SRUN(&a, "UPDATE w SET v = v + 1 WHERE id = 1");
        uint64_t c0 = db->stats.ser_conflicts;
        if (srun(&a, "COMMIT") || db->stats.ser_conflicts != c0) test_fail(__FILE__, __LINE__, free_[i]);
        if (a.txn.open) SRUN(&a, "ROLLBACK");
    }
    ser_close(db, &a, &b);
}

/* an ERASE after a SERIALIZABLE transaction's snapshot and before its first read of a table it touches: that read is
 * refused (check_view: the table's last erase above the snapshot) and the transaction doomed, read-only or a writer; a
 * snapshot taken after the ERASE reads as usual; a SNAPSHOT reader answers (the rule is SERIALIZABLE's) */
static void t_ser_erase_order(void)
{
    imdb_session a, b;
    imdb_db *db = ser_setup(&a, &b, 0);
    CHECK(db);
    if (!db) return;
    SRUN(&a, "INSERT INTO t VALUES (3, 3, 30), (4, 4, 40)");
    SRUN(&a, "BEGIN ISOLATION LEVEL SERIALIZABLE"); /* read-only */
    CHECK(sval(&a, "SELECT COUNT(*) FROM w") == 1);
    SRUN(&b, "ERASE SUBJECT 3");
    CHECK(srun(&a, "SELECT COUNT(*) FROM t") == IMDB_ERR_CONFLICT);
    CONFLICTS(&a, "COMMIT");
    SRUN(&a, "BEGIN ISOLATION LEVEL SERIALIZABLE"); /* a writer */
    SRUN(&a, "UPDATE w SET v = 7 WHERE id = 1");
    SRUN(&b, "ERASE SUBJECT 4");
    CHECK(srun(&a, "SELECT SUM(v) FROM t") == IMDB_ERR_CONFLICT);
    CONFLICTS(&a, "COMMIT");
    CHECK(sval(&a, "SELECT v FROM w WHERE id = 1") == 0); /* its write went */
    SRUN(&a, "BEGIN"); /* SNAPSHOT */
    CHECK(sval(&a, "SELECT COUNT(*) FROM w") == 1);
    SRUN(&b, "ERASE SUBJECT 2");
    CHECK(sval(&a, "SELECT COUNT(*) FROM t") != INT64_MIN);
    SRUN(&a, "COMMIT");
    SRUN(&a, "BEGIN ISOLATION LEVEL SERIALIZABLE"); /* a snapshot after every ERASE */
    CHECK(sval(&a, "SELECT COUNT(*) FROM t") == 1);
    SRUN(&a, "UPDATE w SET v = 8 WHERE id = 1");
    SRUN(&a, "COMMIT");
    ser_close(db, &a, &b);
}

/* the lake at a budget of none: a read of t's segments records t as any read does */
static void t_ser_lake(void)
{
    imdb_session a, b;
    imdb_db *db = ser_setup(&a, &b, 1);
    CHECK(db);
    if (!db) return;
    SRUN(&a, "CHECKPOINT");
    db->segcache.budget = 0;
    SRUN(&a, "BEGIN ISOLATION LEVEL SERIALIZABLE");
    CHECK(sval(&a, "SELECT SUM(v) FROM t") == 30);
    SRUN(&b, "UPDATE t SET v = 1 WHERE id = 2");
    SRUN(&a, "UPDATE w SET v = 5 WHERE id = 1");
    CONFLICTS(&a, "COMMIT");
    ser_close(db, &a, &b);
}

/* the read set survives a parked transaction and ROLLBACK TO; DDL on a read table is a write of it; an ERASE dooms a
 * read-only SERIALIZABLE reader of a table it touches; a read-only one otherwise commits whatever was written */
static void t_ser_rules(void)
{
    imdb_session a, b;
    imdb_db *db = ser_setup(&a, &b, 0);
    CHECK(db);
    if (!db) return;
    /* parked: a writes w (active), b writes w's other row (a swapped out), b writes t; a commits: refused (it read t) */
    SRUN(&a, "BEGIN ISOLATION LEVEL SERIALIZABLE");
    CHECK(sval(&a, "SELECT COUNT(*) FROM t") == 2);
    SRUN(&a, "UPDATE w SET v = 1 WHERE id = 1");
    SRUN(&b, "INSERT INTO w VALUES (2, 2)");
    SRUN(&b, "INSERT INTO t VALUES (5, 5, 5)");
    CONFLICTS(&a, "COMMIT");
    /* ROLLBACK TO keeps the read */
    SRUN(&a, "BEGIN ISOLATION LEVEL SERIALIZABLE");
    SRUN(&a, "SAVEPOINT s");
    CHECK(sval(&a, "SELECT COUNT(*) FROM t") == 3);
    SRUN(&a, "ROLLBACK TO s");
    SRUN(&a, "UPDATE w SET v = 3 WHERE id = 1");
    SRUN(&b, "DELETE FROM t WHERE id = 5");
    CONFLICTS(&a, "COMMIT");
    /* DDL on a read table */
    SRUN(&a, "BEGIN ISOLATION LEVEL SERIALIZABLE");
    CHECK(sval(&a, "SELECT COUNT(*) FROM t") == 2);
    SRUN(&b, "CREATE INDEX t_u ON t (u)");
    SRUN(&a, "UPDATE w SET v = 4 WHERE id = 1");
    CONFLICTS(&a, "COMMIT");
    /* a read-only SERIALIZABLE transaction commits whatever was written since */
    SRUN(&a, "BEGIN ISOLATION LEVEL SERIALIZABLE");
    CHECK(sval(&a, "SELECT COUNT(*) FROM t") == 2);
    SRUN(&b, "INSERT INTO t VALUES (6, 6, 6)");
    SRUN(&a, "COMMIT");
    /* ERASE: a read-only reader of t is doomed (its next statement and its commit refused) */
    SRUN(&a, "BEGIN ISOLATION LEVEL SERIALIZABLE");
    CHECK(sval(&a, "SELECT COUNT(*) FROM t") == 3);
    SRUN(&b, "ERASE SUBJECT 6");
    CHECK(srun(&a, "SELECT COUNT(*) FROM w") == IMDB_ERR_CONFLICT);
    CONFLICTS(&a, "COMMIT");
    /* and a SNAPSHOT reader of t is not (the rule is SERIALIZABLE's) */
    SRUN(&a, "BEGIN");
    CHECK(sval(&a, "SELECT COUNT(*) FROM t") == 2);
    SRUN(&b, "ERASE SUBJECT 2");
    SRUN(&a, "COMMIT");
    ser_close(db, &a, &b);
}

/* the level: SET TRANSACTION right after BEGIN only; default_transaction_isolation (a word or a quoted phrase) for a
 * BEGIN naming none; SHOW TRANSACTIONS; an autocommit statement is never refused */
static void t_ser_level(void)
{
    imdb_session a, b;
    imdb_db *db = ser_setup(&a, &b, 0);
    CHECK(db);
    if (!db) return;
    SRUN(&a, "BEGIN");
    SRUN(&a, "SET TRANSACTION ISOLATION LEVEL SERIALIZABLE");
    CHECK(a.txn.iso == IMDB_ISO_SERIALIZABLE);
    CHECK(sval(&a, "SELECT COUNT(*) FROM t") == 2);
    CHECK(srun(&a, "SET TRANSACTION ISOLATION LEVEL SNAPSHOT") == IMDB_ERR_STATE);
    SRUN(&a, "ROLLBACK");
    SRUN(&a, "SET default_transaction_isolation = serializable");
    SRUN(&a, "BEGIN");
    CHECK(a.txn.iso == IMDB_ISO_SERIALIZABLE);
    SRUN(&a, "ROLLBACK");
    SRUN(&a, "SET default_transaction_isolation = 'read committed'");
    SRUN(&a, "BEGIN");
    CHECK(a.txn.iso == IMDB_ISO_READ_COMMITTED);
    SRUN(&a, "ROLLBACK");
    SRUN(&a, "SET default_transaction_isolation TO 'REPEATABLE READ'");
    SRUN(&a, "BEGIN");
    CHECK(a.txn.iso == IMDB_ISO_SNAPSHOT);
    SRUN(&a, "ROLLBACK");
    CHECK(srun(&a, "SET default_transaction_isolation = 'chaos'") == IMDB_ERR_INVALID);
    CHECK(srun(&a, "SET statement_timeout = 'serializable'") != IMDB_OK); /* a quoted value is this setting's alone */
    SRUN(&a, "SET default_transaction_isolation = serializable");
    SRUN(&a, "BEGIN");
    imdb_result r;
    imdb_err_clear(&g_e);
    CHECK(imdb_exec_one(&b, "SHOW TRANSACTIONS", 17, NULL, 0, &r, &g_e) == 0);
    bool named = false;
    for (uint64_t i = 0; i < r.nrows * r.ncols; i++)
        named |= r.cells[i].v.s && r.cells[i].v.len == 12 && !memcmp(r.cells[i].v.s, "serializable", 12);
    imdb_result_free(&r);
    CHECK(named);
    SRUN(&a, "ROLLBACK");
    for (int i = 0; i < 20; i++) SRUN(&a, "UPDATE t SET v = v + 1 WHERE id = 1"); /* autocommit: serial by construction */
    ser_close(db, &a, &b);
}

/* a replica: an ERASE it applies dooms a SERIALIZABLE reader of a table it touches there too (replay.c, as commit_body
 * on the primary), refuses one whose snapshot is older at its first read of that table, and leaves a reader of
 * another table alone */
static void t_ser_replica(void)
{
    imdb_session a, b;
    imdb_db *db = ser_setup(&a, &b, 0);
    CHECK(db);
    if (!db) return;
    char rdir[700], f[760];
    snprintf(rdir, sizeof rdir, "%s-replica", g_dir);
    snprintf(f, sizeof f, "%s-stream", g_dir);
    imdb_identity id;
    OK(imdb_identity_read(g_dir, &id, NULL, &g_e));
    OK(imdb_init_replica(rdir, &id, &g_e));
    OK(ship_to_file(g_dir, 0, f, &g_e));
    imdb_db *rdb = open_db(rdir);
    CHECK(rdb);
    if (!rdb) {
        ser_close(db, &a, &b);
        return;
    }
    uint64_t applied = 0;
    OK(apply_file(rdb, f, &applied, &g_e));
    imdb_session r1, r2, r3;
    imdb_session_init(&r1, rdb);
    imdb_session_init(&r2, rdb);
    imdb_session_init(&r3, rdb);
    SRUN(&r1, "BEGIN ISOLATION LEVEL SERIALIZABLE");
    CHECK(sval(&r1, "SELECT COUNT(*) FROM t") == 2);
    SRUN(&r2, "BEGIN ISOLATION LEVEL SERIALIZABLE");
    CHECK(sval(&r2, "SELECT COUNT(*) FROM w") == 1);
    SRUN(&r3, "BEGIN ISOLATION LEVEL SERIALIZABLE");
    CHECK(sval(&r3, "SELECT COUNT(*) FROM w") == 1); /* its snapshot, before the ERASE; t not read yet */
    uint64_t at = rdb->seq;
    SRUN(&a, "ERASE SUBJECT 2");
    OK(ship_to_file(g_dir, at, f, &g_e));
    OK(apply_file(rdb, f, &applied, &g_e));
    CHECK(rdb->seq == db->seq);
    CHECK(srun(&r1, "SELECT COUNT(*) FROM w") == IMDB_ERR_CONFLICT);
    CHECK(srun(&r1, "COMMIT") == IMDB_ERR_CONFLICT && !r1.txn.open);
    CHECK(sval(&r2, "SELECT COUNT(*) FROM w") == 1);
    SRUN(&r2, "COMMIT");
    CHECK(srun(&r3, "SELECT COUNT(*) FROM t") == IMDB_ERR_CONFLICT);
    CHECK(srun(&r3, "COMMIT") == IMDB_ERR_CONFLICT && !r3.txn.open);
    imdb_session_close(&r1);
    imdb_session_close(&r2);
    imdb_session_close(&r3);
    imdb_close(rdb);
    ser_close(db, &a, &b);
}

/* the catalog. A view and a type's labels resolve by the snapshot: a view dropped after it is still read (its tables
 * unchanged) and a label added after it is unknown, so a SERIALIZABLE writer is refused when any DDL committed after
 * its snapshot (coarse: DDL is rare), the message naming the catalog. A table or a view created after it (which
 * read_table answers by the live one) is refused at the first read and the transaction doomed, read-only too, while
 * SNAPSHOT still reads such a table as empty. A read-only one across DDL it never meets, and a SNAPSHOT writer across
 * DDL, commit */
static void t_ser_catalog(void)
{
    imdb_session a, b;
    imdb_db *db = ser_setup(&a, &b, 0);
    CHECK(db);
    if (!db) return;
    SRUN(&a, "CREATE VIEW tv AS SELECT id, v FROM t WHERE v > 0");
    SRUN(&a, "CREATE TYPE mood AS ENUM ('a', 'b')");
    uint64_t c0 = db->stats.ser_conflicts;
    SRUN(&a, "BEGIN ISOLATION LEVEL SERIALIZABLE"); /* first: the case the table rule cannot see */
    CHECK(sval(&a, "SELECT COUNT(*) FROM tv") == 2);
    SRUN(&b, "DROP VIEW tv");
    CHECK(sval(&a, "SELECT COUNT(*) FROM tv") == 2); /* its snapshot's view; t unchanged */
    SRUN(&a, "UPDATE w SET v = 2 WHERE id = 1");
    CONFLICTS(&a, "COMMIT");
    CHECK(strstr(g_e.msg, "catalog") != NULL && db->stats.ser_conflicts == c0 + 1);
    SRUN(&a, "BEGIN ISOLATION LEVEL SERIALIZABLE"); /* a label added after the snapshot */
    CHECK(sval(&a, "SELECT COUNT(*) FROM w") == 1);
    SRUN(&b, "ALTER TYPE mood ADD VALUE 'c'");
    CHECK(srun(&a, "SELECT CAST('c' AS mood)") != IMDB_OK); /* not a label at its snapshot */
    SRUN(&a, "UPDATE w SET v = 4 WHERE id = 1");
    CONFLICTS(&a, "COMMIT");
    CHECK(strstr(g_e.msg, "catalog") != NULL && db->stats.ser_conflicts == c0 + 2);
    SRUN(&a, "BEGIN ISOLATION LEVEL SERIALIZABLE"); /* a table created after the snapshot, read-only */
    CHECK(sval(&a, "SELECT COUNT(*) FROM w") == 1);
    SRUN(&b, "CREATE TABLE n (id INT64 PRIMARY KEY)");
    CHECK(srun(&a, "SELECT COUNT(*) FROM n") == IMDB_ERR_CONFLICT && strstr(g_e.msg, "created after"));
    CHECK(srun(&a, "SELECT COUNT(*) FROM w") == IMDB_ERR_CONFLICT); /* doomed */
    CONFLICTS(&a, "COMMIT");
    SRUN(&a, "BEGIN ISOLATION LEVEL SERIALIZABLE"); /* a view created after it, read-only */
    CHECK(sval(&a, "SELECT COUNT(*) FROM w") == 1);
    SRUN(&b, "CREATE VIEW tv3 AS SELECT id FROM w");
    CHECK(srun(&a, "SELECT COUNT(*) FROM tv3") == IMDB_ERR_CONFLICT && strstr(g_e.msg, "created after"));
    CONFLICTS(&a, "COMMIT");
    SRUN(&a, "BEGIN"); /* SNAPSHOT: such a table reads as empty, as it always did */
    CHECK(sval(&a, "SELECT COUNT(*) FROM w") == 1);
    SRUN(&b, "CREATE TABLE n2 (id INT64 PRIMARY KEY)");
    SRUN(&b, "INSERT INTO n2 VALUES (1)");
    CHECK(sval(&a, "SELECT COUNT(*) FROM n2") == 0);
    SRUN(&a, "COMMIT");
    SRUN(&a, "BEGIN ISOLATION LEVEL SERIALIZABLE"); /* read-only across DDL it never meets */
    CHECK(sval(&a, "SELECT COUNT(*) FROM w") == 1);
    SRUN(&b, "CREATE VIEW tv2 AS SELECT id FROM w");
    SRUN(&a, "COMMIT");
    SRUN(&a, "BEGIN"); /* a SNAPSHOT writer: not checked */
    SRUN(&a, "UPDATE w SET v = 3 WHERE id = 1");
    SRUN(&b, "DROP VIEW tv2");
    SRUN(&a, "COMMIT");
    CHECK(sval(&a, "SELECT v FROM w WHERE id = 1") == 3 && db->stats.ser_conflicts == c0 + 2);
    ser_close(db, &a, &b);
}

/* ALTER TABLE: a read takes the table's last shape, never its snapshot's (an ADD's value in older rows, a rename, a
 * column gone), so a SERIALIZABLE read of a table altered after the snapshot is refused and the transaction doomed,
 * read-only too, whether the table was read before the ALTER or not; a snapshot after it reads as usual; AS OF is not
 * this rule's; SNAPSHOT keeps reading the last shape */
static void t_ser_alter(void)
{
    imdb_session a, b;
    imdb_db *db = ser_setup(&a, &b, 0);
    CHECK(db);
    if (!db) return;
    uint64_t before = db->seq;
    SRUN(&a, "BEGIN ISOLATION LEVEL SERIALIZABLE"); /* ADD after the snapshot, t not read yet */
    CHECK(sval(&a, "SELECT COUNT(*) FROM w") == 1);
    SRUN(&b, "ALTER TABLE t ADD COLUMN z INT64 DEFAULT 7");
    CHECK(srun(&a, "SELECT * FROM t") == IMDB_ERR_CONFLICT && strstr(g_e.msg, "altered after"));
    CHECK(srun(&a, "SELECT COUNT(*) FROM w") == IMDB_ERR_CONFLICT); /* doomed */
    CONFLICTS(&a, "COMMIT");
    SRUN(&a, "BEGIN ISOLATION LEVEL SERIALIZABLE"); /* t read before a RENAME, then again */
    CHECK(sval(&a, "SELECT z FROM t WHERE id = 1") == 7);
    SRUN(&b, "ALTER TABLE t RENAME COLUMN z TO zz");
    CHECK(srun(&a, "SELECT COUNT(*) FROM t") == IMDB_ERR_CONFLICT);
    CONFLICTS(&a, "COMMIT");
    SRUN(&a, "BEGIN ISOLATION LEVEL SERIALIZABLE"); /* a DROP COLUMN */
    CHECK(sval(&a, "SELECT COUNT(*) FROM w") == 1);
    SRUN(&b, "ALTER TABLE t DROP COLUMN zz");
    CHECK(srun(&a, "SELECT id FROM t") == IMDB_ERR_CONFLICT);
    CONFLICTS(&a, "COMMIT");
    SRUN(&a, "BEGIN ISOLATION LEVEL SERIALIZABLE"); /* AS OF before the ALTERs: its own history, not this rule's */
    CHECK(sval(&a, "SELECT COUNT(*) FROM w") == 1);
    SRUN(&b, "ALTER TABLE t ADD COLUMN y INT64 DEFAULT 9");
    char q[96];
    snprintf(q, sizeof q, "SELECT COUNT(*) FROM t AS OF %llu", (unsigned long long)before);
    CHECK(sval(&a, q) == 2);
    SRUN(&a, "COMMIT");
    SRUN(&a, "BEGIN ISOLATION LEVEL SERIALIZABLE"); /* a snapshot after every ALTER */
    CHECK(sval(&a, "SELECT SUM(y) FROM t") == 18);
    SRUN(&a, "UPDATE w SET v = 6 WHERE id = 1");
    SRUN(&a, "COMMIT");
    SRUN(&a, "BEGIN"); /* SNAPSHOT: the last shape, as it always did */
    CHECK(sval(&a, "SELECT COUNT(*) FROM w") == 1);
    SRUN(&b, "ALTER TABLE t ADD COLUMN x INT64 DEFAULT 5");
    CHECK(sval(&a, "SELECT SUM(x) FROM t") == 10);
    SRUN(&a, "COMMIT");
    ser_close(db, &a, &b);
}

/* E3b: a row set's pseudo table (a derived table, a WITH, a view's expansion) is no catalog table: a SERIALIZABLE writer
 * reading w through each notes w alone (not table 0, t), so a write of t leaves it committing; reading t through a view
 * still notes t, and a write of t refuses it */
static void t_ser_rset(void)
{
    imdb_session a, b;
    imdb_db *db = ser_setup(&a, &b, 0); /* t is table 0, w table 1 */
    CHECK(db);
    if (!db) return;
    SRUN(&a, "CREATE VIEW wv AS SELECT id, v FROM w");
    SRUN(&a, "CREATE VIEW tv AS SELECT id, v FROM t");
    static const char *const over_w[] = {"SELECT COUNT(*) FROM (SELECT id FROM w) AS d",
                                         "WITH x AS (SELECT id FROM w) SELECT COUNT(*) FROM x", "SELECT COUNT(*) FROM wv"};
    char q[96];
    for (int i = 0; i < 3; i++) {
        SRUN(&a, "BEGIN ISOLATION LEVEL SERIALIZABLE");
        CHECK(sval(&a, over_w[i]) == 1);
        CHECK(!(a.txn.rd[0] & 1u) && (a.txn.rd[0] >> 1 & 1u)); /* w noted, t not */
        snprintf(q, sizeof q, "INSERT INTO t VALUES (%d, 5, 5)", 60 + i);
        SRUN(&b, q);
        SRUN(&a, "UPDATE w SET v = v + 1 WHERE id = 1");
        if (srun(&a, "COMMIT")) test_fail(__FILE__, __LINE__, over_w[i]);
        if (a.txn.open) SRUN(&a, "ROLLBACK");
    }
    SRUN(&a, "BEGIN ISOLATION LEVEL SERIALIZABLE"); /* t through a view: noted */
    CHECK(sval(&a, "SELECT COUNT(*) FROM tv") == 5);
    SRUN(&b, "INSERT INTO t VALUES (70, 5, 5)");
    SRUN(&a, "UPDATE w SET v = v + 1 WHERE id = 1");
    CONFLICTS(&a, "COMMIT");
    ser_close(db, &a, &b);
}

const test_case e3_tests[] = {
    {"e3_write_skew", t_ser_write_skew}, {"e3_phantom", t_ser_phantom}, {"e3_read_only", t_ser_read_only},
    {"e3_paths", t_ser_paths},           {"e3_lake", t_ser_lake},       {"e3_rules", t_ser_rules},
    {"e3_level", t_ser_level},         {"e3_replica", t_ser_replica}, {"e3_erase_order", t_ser_erase_order},
    {"e3_catalog", t_ser_catalog},     {"e3_alter", t_ser_alter},       {"e3_rset", t_ser_rset},
};
const size_t e3_ntests = sizeof e3_tests / sizeof *e3_tests;
