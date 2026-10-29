/* Session transactions (db.h, docs/txn-design.md): several sessions on one
 * database, each reading committed data at its snapshot plus its own writes,
 * with suspended write sets replayed (and re-validated) on the way back in. */
#include <signal.h>
#include <stdlib.h>
#include <sys/resource.h>

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

/* the first cell of a one-row result, or INT64_MIN on any error */
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

#define SRUN(s, sql)                                                            \
    do {                                                                        \
        if (srun(s, sql)) {                                                     \
            char m_[900];                                                       \
            snprintf(m_, sizeof m_, "%s -> %s", sql, g_e.msg);                  \
            test_fail(__FILE__, __LINE__, m_);                                  \
            return;                                                             \
        }                                                                       \
    } while (0)

static imdb_db *setup(imdb_session *a, imdb_session *b)
{
    const char *dir = test_tmpdir();
    imdb_err e = {0};
    if (imdb_init(dir, false, NULL, &e)) return NULL;
    imdb_db *db = open_db(dir);
    if (!db) return NULL;
    imdb_session_init(a, db);
    imdb_session_init(b, db);
    if (srun(a, "CREATE TABLE t (id INT64 PRIMARY KEY, u INT64 SUBJECT, v INT64)") ||
        srun(a, "INSERT INTO t VALUES (1, 1, 10), (2, 2, 20)")) {
        imdb_close(db);
        return NULL;
    }
    a->cross_check = b->cross_check = true; /* every read: two access paths must agree */
    return db;
}

/* A's uncommitted inserts, updates and deletes are invisible to B, while A is
 * the active transaction (no switch happens for B's plain reads). */
static void t_txn_no_dirty_reads(void)
{
    imdb_session a, b;
    imdb_db *db = setup(&a, &b);
    CHECK(db);
    SRUN(&a, "BEGIN");
    SRUN(&a, "INSERT INTO t VALUES (3, 1, 30)");
    SRUN(&a, "UPDATE t SET v = 11 WHERE id = 1");
    SRUN(&a, "DELETE FROM t WHERE id = 2");
    CHECK(db->active == &a.txn);
    CHECK(sval(&b, "SELECT COUNT(*) FROM t") == 2 && sval(&b, "SELECT SUM(v) FROM t") == 30);
    CHECK(sval(&b, "SELECT v FROM t WHERE id = 1") == 10 && sval(&b, "SELECT COUNT(*) FROM t WHERE id = 3") == 0);
    CHECK(sval(&b, "SELECT COUNT(*) FROM t WHERE u = 1") == 1); /* the subject index path too */
    CHECK(db->active == &a.txn); /* B's reads did not switch */
    CHECK(sval(&a, "SELECT COUNT(*) FROM t") == 2 && sval(&a, "SELECT SUM(v) FROM t") == 41);
    SRUN(&a, "COMMIT");
    CHECK(sval(&b, "SELECT SUM(v) FROM t") == 41);
    imdb_session_close(&a);
    imdb_session_close(&b);
    imdb_close(db);
}

/* Interleaved writers: each switch saves one write set and replays the other,
 * including updates of a transaction's own pending rows (their version ids move
 * when the other side commits) and a failing statement after a switch. */
static void t_txn_interleaved(void)
{
    imdb_session a, b, c;
    imdb_db *db = setup(&a, &b);
    CHECK(db);
    imdb_session_init(&c, db);
    SRUN(&a, "BEGIN");
    SRUN(&a, "INSERT INTO t VALUES (3, 1, 30)");
    SRUN(&a, "UPDATE t SET v = 11 WHERE id = 1");
    SRUN(&b, "BEGIN");
    SRUN(&b, "INSERT INTO t VALUES (4, 2, 40)"); /* A is suspended */
    CHECK(db->active == &b.txn && a.txn.nops == 2);
    CHECK(sval(&a, "SELECT SUM(v) FROM t") == 61); /* A is back: 11 + 20 + 30, not B's row */
    CHECK(db->active == &a.txn && b.txn.nops == 1);
    SRUN(&a, "UPDATE t SET v = 31 WHERE id = 3"); /* its own pending row */
    CHECK(srun(&a, "INSERT INTO t VALUES (2, 2, 99)") == IMDB_ERR_CONSTRAINT); /* fails alone */
    CHECK(sval(&a, "SELECT SUM(v) FROM t") == 62);
    SRUN(&c, "INSERT INTO t VALUES (5, 3, 50)"); /* an autocommit write: A suspended again */
    CHECK(db->active == NULL);
    CHECK(sval(&b, "SELECT SUM(v) FROM t") == 70); /* B's snapshot predates C's commit: 10 + 20 + 40 */
    SRUN(&a, "UPDATE t SET v = 32 WHERE id = 3"); /* replayed after C's commit moved the version ids */
    CHECK(sval(&a, "SELECT SUM(v) FROM t") == 63);
    SRUN(&a, "COMMIT");
    SRUN(&b, "COMMIT");
    CHECK(sval(&c, "SELECT COUNT(*) FROM t") == 5);
    CHECK(sval(&c, "SELECT SUM(v) FROM t") == 11 + 20 + 32 + 40 + 50);
    CHECK(sval(&c, "SELECT v FROM t WHERE id = 3") == 32);
    imdb_verify_report vr;
    OK(imdb_verify(db, &vr, E));
    imdb_session_close(&a);
    imdb_session_close(&b);
    imdb_session_close(&c);
    char dir[600];
    snprintf(dir, sizeof dir, "%s", db->path);
    imdb_close(db);
    db = open_db(dir); /* and the log replays to the same state */
    CHECK(db);
    imdb_session_init(&c, db);
    CHECK(sval(&c, "SELECT SUM(v) FROM t") == 11 + 20 + 32 + 40 + 50);
    imdb_session_close(&c);
    imdb_close(db);
}

/* First committer wins: a suspended write set whose base row was changed by a
 * later commit cannot be replayed; the transaction is doomed until ROLLBACK. */
static void t_txn_conflict_on_replay(void)
{
    imdb_session a, b;
    imdb_db *db = setup(&a, &b);
    CHECK(db);
    SRUN(&a, "BEGIN");
    SRUN(&a, "UPDATE t SET v = 11 WHERE id = 1");
    SRUN(&b, "UPDATE t SET v = 12 WHERE id = 1"); /* autocommit: commits first */
    CHECK(srun(&a, "SELECT v FROM t WHERE id = 1") == IMDB_ERR_CONFLICT);
    CHECK(strstr(g_e.msg, "could not serialize"));
    CHECK(srun(&a, "SELECT COUNT(*) FROM t") == IMDB_ERR_CONFLICT); /* still doomed */
    CHECK(srun(&a, "COMMIT") == IMDB_ERR_CONFLICT && !a.txn.open);
    CHECK(sval(&a, "SELECT v FROM t WHERE id = 1") == 12);
    imdb_verify_report vr;
    OK(imdb_verify(db, &vr, E));
    imdb_session_close(&a);
    imdb_session_close(&b);
    imdb_close(db);
}

/* A suspended write set built on a row that another session deletes and erases
 * is doomed at once, and its saved copy of the row's bytes is wiped. */
static void t_txn_erase_dooms_suspended(void)
{
    imdb_session a, b;
    imdb_db *db = setup(&a, &b);
    CHECK(db);
    SRUN(&a, "BEGIN");
    SRUN(&a, "UPDATE t SET v = 11 WHERE id = 1");
    SRUN(&b, "DELETE FROM t WHERE id = 1"); /* A suspended: its saved UPDATE copies row 1 */
    CHECK(a.txn.nops == 1 && a.txn.ops && a.txn.ops[0].row);
    SRUN(&b, "ERASE SUBJECT 1");
    CHECK(a.txn.doomed && a.txn.nops == 0 && a.txn.ops == NULL); /* doomed, bytes released (wiped) */
    CHECK(srun(&a, "SELECT COUNT(*) FROM t") == IMDB_ERR_CONFLICT);
    SRUN(&a, "ROLLBACK");
    CHECK(sval(&a, "SELECT COUNT(*) FROM t") == 1);
    imdb_verify_report vr;
    OK(imdb_verify(db, &vr, E));
    imdb_session_close(&a);
    imdb_session_close(&b);
    imdb_close(db);
}

/* An UPDATE of a row a later commit changed: the first committer won. The
 * transaction is doomed, so nothing it does can commit any more. */
static void t_txn_conflict_statement_time(void)
{
    imdb_session a, b;
    imdb_db *db = setup(&a, &b);
    CHECK(db);
    SRUN(&a, "BEGIN");
    CHECK(sval(&a, "SELECT v FROM t WHERE id = 1") == 10); /* the snapshot is taken here */
    SRUN(&b, "UPDATE t SET v = 12 WHERE id = 1");
    CHECK(sval(&a, "SELECT v FROM t WHERE id = 1") == 10); /* snapshot isolation: no non-repeatable read */
    CHECK(srun(&a, "UPDATE t SET v = 11 WHERE id = 1") == IMDB_ERR_CONFLICT);
    CHECK(a.txn.doomed);
    CHECK(srun(&a, "SELECT COUNT(*) FROM t") == IMDB_ERR_CONFLICT);
    CHECK(srun(&a, "COMMIT") == IMDB_ERR_CONFLICT && !a.txn.open);
    CHECK(sval(&a, "SELECT v FROM t WHERE id = 1") == 12); /* B's update stands: no lost update */
    imdb_session_close(&a);
    imdb_session_close(&b);
    imdb_close(db);
}

/* A primary key held only by a row committed after the snapshot: conflict. Held
 * by a row the snapshot sees (even one deleted since): an ordinary duplicate,
 * and the transaction goes on. */
static void t_txn_duplicate_vs_conflict(void)
{
    imdb_session a, b;
    imdb_db *db = setup(&a, &b);
    CHECK(db);
    SRUN(&a, "BEGIN");
    CHECK(sval(&a, "SELECT COUNT(*) FROM t") == 2);
    SRUN(&b, "DELETE FROM t WHERE id = 2");
    CHECK(srun(&a, "INSERT INTO t VALUES (1, 1, 1)") == IMDB_ERR_CONSTRAINT);
    CHECK(srun(&a, "INSERT INTO t VALUES (2, 2, 2)") == IMDB_ERR_CONSTRAINT); /* A still sees row 2 */
    CHECK(!a.txn.doomed);
    SRUN(&a, "INSERT INTO t VALUES (7, 7, 70)");
    SRUN(&b, "INSERT INTO t VALUES (9, 9, 90)");
    CHECK(srun(&a, "INSERT INTO t VALUES (9, 9, 99)") == IMDB_ERR_CONFLICT && a.txn.doomed);
    SRUN(&a, "ROLLBACK");
    CHECK(sval(&a, "SELECT COUNT(*) FROM t") == 2 && sval(&a, "SELECT v FROM t WHERE id = 9") == 90);
    imdb_session_close(&a);
    imdb_session_close(&b);
    imdb_close(db);
}

/* Two transactions read the same row and both update it: the second to commit
 * gets a conflict instead of silently overwriting the first (no lost update),
 * whichever of them wrote first. */
static void t_txn_lost_update_prevented(void)
{
    imdb_session a, b;
    imdb_db *db = setup(&a, &b);
    CHECK(db);
    SRUN(&a, "BEGIN");
    SRUN(&b, "BEGIN");
    CHECK(sval(&a, "SELECT v FROM t WHERE id = 1") == 10 && sval(&b, "SELECT v FROM t WHERE id = 1") == 10);
    SRUN(&a, "UPDATE t SET v = 11 WHERE id = 1");
    SRUN(&b, "UPDATE t SET v = 12 WHERE id = 1"); /* both write: A is suspended, B active */
    SRUN(&b, "COMMIT");
    CHECK(srun(&a, "COMMIT") == IMDB_ERR_CONFLICT);
    CHECK(sval(&a, "SELECT v FROM t WHERE id = 1") == 12);
    imdb_verify_report vr;
    OK(imdb_verify(db, &vr, E));
    imdb_session_close(&a);
    imdb_session_close(&b);
    imdb_close(db);
}

/* A snapshot below a table's purge horizon cannot be answered exactly. A transaction whose own
 * snapshot fell below it (it outlived the history the table keeps) conflicts, at a read and at the
 * row selection of a write, and can only roll back: a retry's fresh snapshot is above the horizon.
 * AS OF that far back is a history error. */
static void t_txn_snapshot_below_horizon(void)
{
    imdb_session a, b;
    imdb_db *db = setup(&a, &b);
    CHECK(db);
    SRUN(&a, "BEGIN");
    CHECK(sval(&a, "SELECT COUNT(*) FROM t") == 2); /* snapshot at commit 2 */
    SRUN(&b, "UPDATE t SET v = 21 WHERE id = 2");
    SRUN(&b, "UPDATE t SET v = 22 WHERE id = 2");
    char sql[100];
    snprintf(sql, sizeof sql, "COMPACT t PURGE BEFORE %llu", (unsigned long long)db->seq);
    SRUN(&b, sql);
    CHECK(srun(&a, "SELECT COUNT(*) FROM t") == IMDB_ERR_CONFLICT);
    CHECK(strstr(g_e.msg, "roll back and retry") != NULL);
    CHECK(srun(&a, "UPDATE t SET v = 0 WHERE id = 1") == IMDB_ERR_CONFLICT); /* doomed */
    SRUN(&a, "ROLLBACK");
    CHECK(sval(&a, "SELECT SUM(v) FROM t") == 32);
    CHECK(srun(&a, "SELECT COUNT(*) FROM t AS OF 2") == IMDB_ERR_HISTORY);
    SRUN(&a, "BEGIN");
    SRUN(&a, "UPDATE t SET v = 0 WHERE id = 1"); /* the retry */
    SRUN(&a, "COMMIT");
    CHECK(sval(&b, "SELECT SUM(v) FROM t") == 22);
    imdb_session_close(&a);
    imdb_session_close(&b);
    imdb_close(db);
}

/* A commit whose log write fails (here: the file size limit, as on a full disk)
 * leaves no partial frame, no change in the store or the digest, and nothing
 * visible to anyone; the database keeps working. */
static void t_txn_failed_commit_untouched(void)
{
    imdb_log_set_tagged(false); /* RLIMIT_FSIZE stops an append; a tagged write lands inside the fill (the fault tests fail its writes) */
    imdb_session a, b;
    imdb_db *db = setup(&a, &b);
    CHECK(db);
    SRUN(&a, "BEGIN");
    SRUN(&a, "UPDATE t SET v = 11 WHERE id = 1");
    SRUN(&a, "INSERT INTO t VALUES (3, 3, 30)");
    uint64_t seq = db->seq;
    uint8_t head[32], d0[32], d1[32];
    memcpy(head, db->head, 32);
    imdb_state_digest(db, NULL, d0);
    char seg[700];
    snprintf(seg, sizeof seg, "%s", seg_path(db->path, -1));
    long size = file_size(seg);
    CHECK(size > 0);
    struct rlimit old, lim;
    CHECK(getrlimit(RLIMIT_FSIZE, &old) == 0);
    void (*prev)(int) = signal(SIGXFSZ, SIG_IGN);
    lim = old;
    lim.rlim_cur = (rlim_t)size + 16; /* the frame is larger: it stops part way */
    CHECK(setrlimit(RLIMIT_FSIZE, &lim) == 0);
    int rc = srun(&a, "COMMIT");
    setrlimit(RLIMIT_FSIZE, &old);
    signal(SIGXFSZ, prev);
    CHECK(rc == IMDB_ERR_IO && !a.txn.open && !db->failed);
    CHECK(file_size(seg) == size); /* no partial frame */
    imdb_state_digest(db, NULL, d1);
    CHECK(db->seq == seq && memcmp(db->head, head, 32) == 0 && memcmp(d0, d1, 32) == 0);
    CHECK(sval(&b, "SELECT SUM(v) FROM t") == 30 && sval(&b, "SELECT COUNT(*) FROM t") == 2);
    imdb_verify_report vr;
    OK(imdb_verify(db, &vr, E));
    SRUN(&a, "INSERT INTO t VALUES (3, 3, 30)"); /* and it still commits */
    CHECK(sval(&b, "SELECT COUNT(*) FROM t") == 3);
    imdb_session_close(&a);
    imdb_session_close(&b);
    imdb_close(db);
}

static void t_txn_sql_surface(void)
{
    imdb_session a, b;
    imdb_db *db = setup(&a, &b);
    CHECK(db);
    CHECK(srun(&a, "BEGIN ISOLATION LEVEL SERIALIZABLE") == IMDB_ERR_UNSUPPORTED && !a.txn.open);
    SRUN(&a, "BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ");
    CHECK(a.txn.iso == IMDB_ISO_SNAPSHOT);
    SRUN(&a, "SET TRANSACTION ISOLATION LEVEL READ UNCOMMITTED"); /* = READ COMMITTED, never dirty */
    CHECK(a.txn.iso == IMDB_ISO_READ_COMMITTED);
    CHECK(sval(&a, "SELECT COUNT(*) FROM t") == 2);
    CHECK(srun(&a, "SET TRANSACTION ISOLATION LEVEL SNAPSHOT") == IMDB_ERR_STATE); /* too late */
    SRUN(&a, "COMMIT WORK");
    SRUN(&a, "BEGIN WORK");
    SRUN(&a, "ROLLBACK TRANSACTION");
    CHECK(srun(&a, "SAVEPOINT s") == IMDB_ERR_STATE);           /* needs a transaction */
    CHECK(srun(&a, "CREATE TABLE u (k INT64 PRIMARY KEY)") == 0); /* fine outside */
    SRUN(&a, "BEGIN");
    CHECK(srun(&a, "CREATE TABLE w (k INT64 PRIMARY KEY)") == IMDB_ERR_STATE); /* DDL commits on its own */
    CHECK(srun(&a, "CHECKPOINT") == IMDB_ERR_STATE && srun(&a, "VERIFY") == IMDB_ERR_STATE);
    SRUN(&a, "ROLLBACK");
    /* READ COMMITTED: every statement sees the latest commit (a non-repeatable read) */
    SRUN(&a, "BEGIN ISOLATION LEVEL READ COMMITTED");
    CHECK(sval(&a, "SELECT v FROM t WHERE id = 1") == 10);
    SRUN(&b, "UPDATE t SET v = 12 WHERE id = 1");
    CHECK(sval(&a, "SELECT v FROM t WHERE id = 1") == 12);
    SRUN(&a, "COMMIT");
    /* WITH (NOLOCK): accepted, and still never shows another session's uncommitted rows */
    SRUN(&b, "BEGIN");
    SRUN(&b, "INSERT INTO t VALUES (8, 8, 80)");
    CHECK(sval(&a, "SELECT COUNT(*) FROM t WITH (NOLOCK)") == 2);
    CHECK(sval(&a, "SELECT COUNT(*) FROM t WITH (NOLOCK) WHERE id = 8") == 0);
    SRUN(&b, "ROLLBACK");
    imdb_session_close(&a);
    imdb_session_close(&b);
    imdb_close(db);
}

/* Savepoints are positions in the op list: they survive a switch, whether the
 * transaction is rolled back to one while suspended or while active. */
static void t_txn_savepoints(void)
{
    imdb_session a, b;
    imdb_db *db = setup(&a, &b);
    CHECK(db);
    SRUN(&a, "BEGIN");
    SRUN(&a, "INSERT INTO t VALUES (3, 3, 30)");
    SRUN(&a, "SAVEPOINT s1");
    SRUN(&a, "INSERT INTO t VALUES (4, 4, 40)");
    SRUN(&a, "UPDATE t SET v = 31 WHERE id = 3");
    SRUN(&b, "INSERT INTO t VALUES (9, 9, 90)"); /* A suspended */
    CHECK(a.txn.nops == 3);
    SRUN(&a, "ROLLBACK TO SAVEPOINT s1");          /* while suspended: the saved list is cut */
    CHECK(a.txn.nops == 1);
    CHECK(sval(&a, "SELECT SUM(v) FROM t") == 60); /* 10 + 20 + 30: back in, 4 gone, 3 not updated */
    SRUN(&a, "INSERT INTO t VALUES (5, 5, 50)");
    SRUN(&a, "SAVEPOINT s2");
    SRUN(&a, "UPDATE t SET v = 32 WHERE id = 3");
    SRUN(&a, "DELETE FROM t WHERE id = 1");
    SRUN(&a, "ROLLBACK TO s2");                    /* while active: undo recomputed from the prefix */
    CHECK(sval(&a, "SELECT SUM(v) FROM t") == 110);
    SRUN(&a, "UPDATE t SET v = 33 WHERE id = 3");  /* s2 stays usable */
    SRUN(&a, "ROLLBACK TO s2");
    SRUN(&a, "RELEASE SAVEPOINT s1");              /* s1 and s2 forgotten, the writes kept */
    CHECK(srun(&a, "ROLLBACK TO s2") == IMDB_ERR_NOTFOUND);
    SRUN(&a, "COMMIT");
    CHECK(sval(&b, "SELECT SUM(v) FROM t") == 10 + 20 + 30 + 50 + 90);
    CHECK(sval(&b, "SELECT v FROM t WHERE id = 3") == 30);
    imdb_verify_report vr;
    OK(imdb_verify(db, &vr, E));
    imdb_session_close(&a);
    imdb_session_close(&b);
    imdb_close(db);
}

/* FOR UPDATE: a locked row that another commit changes makes this commit a
 * conflict (read-only or not); a row already changed when it is locked
 * conflicts at once. Outside a transaction the clause changes nothing. */
static void t_txn_for_update(void)
{
    imdb_session a, b;
    imdb_db *db = setup(&a, &b);
    CHECK(db);
    CHECK(sval(&a, "SELECT v FROM t WHERE id = 1 FOR UPDATE") == 10);
    CHECK(srun(&a, "SELECT COUNT(*) FROM t FOR UPDATE") == IMDB_ERR_INVALID);
    SRUN(&a, "BEGIN");
    CHECK(sval(&a, "SELECT v FROM t WHERE id = 1 FOR UPDATE") == 10);
    SRUN(&b, "UPDATE t SET v = 12 WHERE id = 1");
    CHECK(srun(&a, "COMMIT") == IMDB_ERR_CONFLICT); /* nothing written, but the lock was broken */
    SRUN(&a, "BEGIN");
    CHECK(sval(&a, "SELECT v FROM t WHERE id = 2 FOR UPDATE") == 20);
    SRUN(&a, "UPDATE t SET v = 13 WHERE id = 1");
    SRUN(&b, "UPDATE t SET v = 22 WHERE id = 2");
    CHECK(srun(&a, "COMMIT") == IMDB_ERR_CONFLICT);
    CHECK(sval(&a, "SELECT SUM(v) FROM t") == 12 + 22); /* A's update did not happen */
    SRUN(&a, "BEGIN");
    CHECK(sval(&a, "SELECT COUNT(*) FROM t") == 2);  /* snapshot */
    SRUN(&b, "UPDATE t SET v = 23 WHERE id = 2");
    CHECK(srun(&a, "SELECT v FROM t WHERE id = 2 FOR UPDATE") == IMDB_ERR_CONFLICT && a.txn.doomed);
    SRUN(&a, "ROLLBACK");
    imdb_session_close(&a);
    imdb_session_close(&b);
    imdb_close(db);
}

/* Write skew is what SNAPSHOT isolation allows and SERIALIZABLE would refuse:
 * each transaction reads both rows and changes a different one. Pinned here so
 * that the documented behaviour cannot change by accident. */
static void t_txn_write_skew_allowed(void)
{
    imdb_session a, b;
    imdb_db *db = setup(&a, &b);
    CHECK(db);
    SRUN(&a, "BEGIN");
    SRUN(&b, "BEGIN");
    CHECK(sval(&a, "SELECT SUM(v) FROM t") == 30 && sval(&b, "SELECT SUM(v) FROM t") == 30);
    SRUN(&a, "UPDATE t SET v = 0 WHERE id = 1");
    SRUN(&b, "UPDATE t SET v = 0 WHERE id = 2");
    SRUN(&a, "COMMIT");
    SRUN(&b, "COMMIT");
    CHECK(sval(&a, "SELECT SUM(v) FROM t") == 0);
    imdb_session_close(&a);
    imdb_session_close(&b);
    imdb_close(db);
}

/* The size-triggered CHECKPOINT runs after the commit, between transactions:
 * COMMIT reports the commit's own number. */
static void t_txn_maintenance_after_commit(void)
{
    const char *dir = test_tmpdir();
    OK(imdb_init(dir, false, NULL, E));
    imdb_open_opts small = {.sync = 0, .checkpoint_bytes = 1500};
    imdb_db *db = NULL;
    OK(imdb_open(dir, &small, &db, E));
    imdb_session a;
    imdb_session_init(&a, db);
    SRUN(&a, "CREATE TABLE t (id INT64 PRIMARY KEY, s TEXT)");
    char sql[200];
    for (int i = 0; i < 30 && db->lake_seq == 0; i++) {
        SRUN(&a, "BEGIN");
        snprintf(sql, sizeof sql, "INSERT INTO t VALUES (%d, 'a row long enough to fill the segment soon')", i);
        SRUN(&a, sql);
        imdb_result r;
        imdb_err_clear(&g_e);
        CHECK(imdb_exec_one(&a, "COMMIT", 6, NULL, 0, &r, &g_e) == 0);
        uint64_t reported = strtoull(strstr(r.status, "commit ") + 7, NULL, 10);
        imdb_result_free(&r);
        CHECK(reported == db->seq - (db->lake_seq == db->seq ? 1 : 0)); /* a checkpoint may follow it */
    }
    CHECK(db->lake_seq > 0);
    imdb_session_close(&a);
    imdb_close(db);
}

/* ---- randomized interleavings against an independent model ---------------------
 *
 * The model keeps every committed state (one per commit, so snapshots can be read
 * back), and per session: its snapshot, its own writes, the committed versions it
 * based writes on, the keys it inserted without seeing them, and savepoints as
 * copies. Its conflict rules are the documented ones, not the code's:
 *   - first committer wins: a session whose bases changed, or one of whose blind
 *     inserts now exists, gets CONFLICT at its next statement (any statement once it
 *     has writes, since they must come back into the store) or at COMMIT;
 *   - an UPDATE or DELETE of a row changed since the snapshot, and an INSERT of a
 *     key committed since it, conflict at once; a key the session sees is an
 *     ordinary duplicate;
 *   - ERASE SUBJECT removes that subject's versions from every snapshot and dooms
 *     the sessions with a base of that subject. */

#define MNID 48     /* ids the arrays hold; a round draws from the first nid of them */
#define MNS 3

typedef struct mrow {
    bool exists;
    int u;
    int64_t v;
    uint64_t ver;
} mrow;

typedef struct mcore {
    int own[MNID];       /* 0 none, 1 its row, 2 it deleted the row */
    mrow ownrow[MNID];
    bool has_base[MNID]; /* it changed the committed version base_ver */
    uint64_t base_ver[MNID];
    int base_u[MNID];
    bool blind[MNID];    /* it inserted a key it did not see in committed state */
    bool writes;
} mcore;

typedef struct msp {
    int name;            /* 1 or 2: s1, s2 */
    mcore c;
} msp;

typedef struct mtx {
    bool open, doomed, rc, started;
    size_t snap;         /* state index of its snapshot: taken at its first statement */
    mcore c;
    msp sps[64];
    int nsps;
} mtx;

typedef struct model {
    mrow (*st)[MNID];    /* committed states */
    size_t nst, capst;
    uint64_t vctr;
    mtx tx[MNS];
} model;

static void m_push(model *m, const mrow *cur)
{
    if (m->nst == m->capst) {
        m->capst = m->capst ? m->capst * 2 : 64;
        m->st = realloc(m->st, m->capst * sizeof *m->st);
    }
    memcpy(m->st[m->nst++], cur, sizeof *m->st);
}

static const mrow *m_cur(const model *m) { return m->st[m->nst - 1]; }

/* the row a session sees: its own write, or its snapshot */
static mrow m_view(const model *m, const mtx *t, int id)
{
    mrow none = {0};
    if (t && t->open) {
        if (t->c.own[id] == 1) return t->c.ownrow[id];
        if (t->c.own[id] == 2) return none;
        return m->st[t->snap][id];
    }
    return m_cur(m)[id];
}

static bool m_conflicted(const model *m, const mtx *t)
{
    const mrow *cur = m_cur(m);
    for (int id = 0; id < MNID; id++) {
        if (t->c.has_base[id] && (!cur[id].exists || cur[id].ver != t->c.base_ver[id])) return true;
        if (t->c.blind[id] && cur[id].exists && !(t->c.has_base[id] && cur[id].ver == t->c.base_ver[id])) return true;
    }
    return false;
}

static void m_close(mtx *t) { memset(t, 0, sizeof *t); }

/* a statement of session t that enters its transaction: a conflict surfaces here */
static int m_enter(const model *m, mtx *t)
{
    if (t->doomed) return IMDB_ERR_CONFLICT;
    if (t->rc || !t->started) t->snap = m->nst - 1;
    t->started = true;
    if (t->c.writes && m_conflicted(m, t)) {
        t->doomed = true;
        return IMDB_ERR_CONFLICT;
    }
    return IMDB_OK;
}

static int engine_view_ok(imdb_session *s, const model *m, const mtx *t, int64_t *want_count, int64_t *want_sum)
{
    (void)s;
    int64_t n = 0, sum = 0;
    for (int id = 0; id < MNID; id++) {
        mrow r = m_view(m, t, id);
        if (r.exists) n++, sum += r.v;
    }
    *want_count = n;
    *want_sum = n ? sum : INT64_MIN;
    return 0;
}

typedef struct mstats {
    int commits, conflicts, checks;
    int phys_parked; /* CHECKPOINT / COMPACT / VERIFY run while another session held saved writes */
} mstats;

static void random_model_round(int nid, mstats *st)
{
    imdb_session ss[MNS];
    imdb_db *db = setup(&ss[0], &ss[1]);
    CHECK(db);
    imdb_session_init(&ss[2], db);
    ss[1].cross_check = false; /* one session reads along a single path */
    model m;
    memset(&m, 0, sizeof m);
    mrow cur[MNID];
    memset(cur, 0, sizeof cur);
    cur[1] = (mrow){true, 1, 10, ++m.vctr}; /* setup's rows: ids 1 and 2 */
    cur[2] = (mrow){true, 2, 20, ++m.vctr};
    m_push(&m, cur);
    char sql[200];
    int steps = 4000, checks = 0, conflicts = 0, commits = 0;
    bool trace = getenv("IMDB_TXN_TRACE") != NULL;
    for (int step = 0; step < steps && !g_test_failed; step++) {
        int si = (int)(test_rand() % MNS);
        imdb_session *s = &ss[si];
        mtx *t = &m.tx[si];
        uint64_t r = test_rand() % 100;
        int id = (int)(test_rand() % (uint64_t)nid), u = (int)(test_rand() % 4);
        int64_t v = (int64_t)(test_rand() % 1000);
        int want = IMDB_OK, got;
        if (!t->open) {
            if (r < 15) { /* BEGIN */
                bool rcl = test_rand() % 2;
                snprintf(sql, sizeof sql, "%s", rcl ? "BEGIN ISOLATION LEVEL READ COMMITTED" : "BEGIN");
                got = srun(s, sql);
                memset(t, 0, sizeof *t);
                t->open = true;
                t->rc = rcl;
            } else if (r < 45) { /* an autocommit write */
                mrow cv = m_cur(&m)[id];
                int kind = (int)(test_rand() % 3);
                if (kind == 0) {
                    snprintf(sql, sizeof sql, "INSERT INTO t VALUES (%d, %d, %lld)", id, u, (long long)v);
                    want = cv.exists ? IMDB_ERR_CONSTRAINT : IMDB_OK;
                    if (!want) cur[id] = (mrow){true, u, v, ++m.vctr};
                } else if (kind == 1) {
                    snprintf(sql, sizeof sql, "UPDATE t SET u = %d, v = %lld WHERE id = %d", u, (long long)v, id);
                    if (cv.exists) cur[id] = (mrow){true, u, v, ++m.vctr};
                } else {
                    snprintf(sql, sizeof sql, "DELETE FROM t WHERE id = %d", id);
                    cur[id].exists = false;
                }
                got = srun(s, sql);
                if (!want) m_push(&m, cur);
                else memcpy(cur, m_cur(&m), sizeof cur);
            } else if (r < 48) { /* physical operations park whichever transaction is active */
                snprintf(sql, sizeof sql, "%s", r < 46 ? "CHECKPOINT" : r < 47 ? "COMPACT t" : "VERIFY");
                got = srun(s, sql);
                if (!got && r < 47) m_push(&m, cur); /* CHECKPOINT and COMPACT commit; VERIFY does not */
                for (int o = 0; !got && o < MNS; o++)
                    if (o != si && m.tx[o].open && m.tx[o].c.writes) {
                        st->phys_parked++;
                        break;
                    }
            } else if (r < 50) { /* ERASE SUBJECT u: gone from every snapshot; bases of u doomed */
                snprintf(sql, sizeof sql, "ERASE SUBJECT %d", u);
                got = srun(s, sql);
                if (!got) {
                    for (size_t k = 0; k < m.nst; k++)
                        for (int j = 0; j < MNID; j++)
                            if (m.st[k][j].exists && m.st[k][j].u == u) m.st[k][j].exists = false;
                    for (int j = 0; j < MNID; j++)
                        if (cur[j].exists && cur[j].u == u) cur[j].exists = false;
                    m_push(&m, cur);
                    for (int o = 0; o < MNS; o++)
                        for (int j = 0; m.tx[o].open && !m.tx[o].doomed && j < MNID; j++)
                            if (m.tx[o].c.has_base[j] && m.tx[o].c.base_u[j] == u) m.tx[o].doomed = true;
                }
            } else { /* an autocommit read */
                int64_t wc, ws;
                engine_view_ok(s, &m, NULL, &wc, &ws);
                if (r % 2) {
                    snprintf(sql, sizeof sql, "SELECT v FROM t WHERE id = %d", id);
                    mrow cv = m_cur(&m)[id];
                    int64_t gv = sval(s, sql);
                    if (gv != (cv.exists ? cv.v : INT64_MIN)) {
                        fprintf(stderr, "    step %d: autocommit point read id %d: got %lld\n", step, id, (long long)gv);
                        CHECK(false);
                    }
                } else {
                    CHECK(sval(s, "SELECT COUNT(*) FROM t") == wc && sval(s, "SELECT SUM(v) FROM t") == ws);
                }
                checks++;
                continue;
            }
        } else if (r < 25) { /* a read inside the transaction */
            want = m_enter(&m, t);
            snprintf(sql, sizeof sql, "(read %s)", r % 2 ? "point" : "count/sum");
            int64_t wc, ws;
            engine_view_ok(s, &m, t, &wc, &ws);
            if (want) {
                got = srun(s, "SELECT COUNT(*) FROM t");
            } else if (r % 2) {
                snprintf(sql, sizeof sql, "SELECT v FROM t WHERE id = %d", id);
                mrow cv = m_view(&m, t, id);
                int64_t gv = sval(s, sql);
                got = g_e.code == IMDB_ERR_CONFLICT ? IMDB_ERR_CONFLICT : IMDB_OK;
                if (!got && gv != (cv.exists ? cv.v : INT64_MIN)) {
                    fprintf(stderr, "    step %d: session %d point read id %d: got %lld want %lld\n", step, si, id,
                            (long long)gv, (long long)(cv.exists ? cv.v : INT64_MIN));
                    CHECK(false);
                }
            } else {
                int64_t gc = sval(s, "SELECT COUNT(*) FROM t");
                got = g_e.code == IMDB_ERR_CONFLICT ? IMDB_ERR_CONFLICT : IMDB_OK;
                int64_t gs = got ? 0 : sval(s, "SELECT SUM(v) FROM t");
                if (!got && (gc != wc || gs != ws)) {
                    fprintf(stderr, "    step %d: session %d count/sum %lld/%lld, want %lld/%lld\n", step, si, (long long)gc,
                            (long long)gs, (long long)wc, (long long)ws);
                    CHECK(false);
                }
            }
            checks++;
        } else if (r < 65) { /* a write inside the transaction */
            want = m_enter(&m, t);
            int kind = (int)(test_rand() % 3);
            if (kind == 0) snprintf(sql, sizeof sql, "INSERT INTO t VALUES (%d, %d, %lld)", id, u, (long long)v);
            else if (kind == 1) snprintf(sql, sizeof sql, "UPDATE t SET u = %d, v = %lld WHERE id = %d", u, (long long)v, id);
            else snprintf(sql, sizeof sql, "DELETE FROM t WHERE id = %d", id);
            if (!want) {
                mrow vw = m_view(&m, t, id);
                const mrow *c = m_cur(&m);
                if (kind == 0) {
                    if (vw.exists) want = IMDB_ERR_CONSTRAINT;
                    else if (t->c.own[id] != 2 && c[id].exists) want = IMDB_ERR_CONFLICT;
                    else {
                        if (t->c.own[id] != 2 || !t->c.has_base[id]) t->c.blind[id] = true;
                        t->c.own[id] = 1;
                        t->c.ownrow[id] = (mrow){true, u, v, 0};
                        t->c.writes = true;
                    }
                } else if (vw.exists) {
                    if (t->c.own[id] != 1 && (!c[id].exists || c[id].ver != vw.ver)) {
                        want = IMDB_ERR_CONFLICT;
                    } else {
                        if (t->c.own[id] != 1) {
                            t->c.has_base[id] = true;
                            t->c.base_ver[id] = vw.ver;
                            t->c.base_u[id] = vw.u;
                        }
                        if (kind == 1) {
                            t->c.own[id] = 1;
                            t->c.ownrow[id] = (mrow){true, u, v, 0};
                        } else {
                            t->c.own[id] = 2;
                        }
                        t->c.writes = true;
                    }
                }
                if (want == IMDB_ERR_CONFLICT) t->doomed = true;
            }
            got = srun(s, sql);
        } else if (r < 75) { /* COMMIT */
            want = t->doomed ? IMDB_ERR_CONFLICT : t->c.writes && m_conflicted(&m, t) ? IMDB_ERR_CONFLICT : IMDB_OK;
            snprintf(sql, sizeof sql, "COMMIT");
            got = srun(s, sql);
            if (!want && t->c.writes) {
                for (int j = 0; j < MNID; j++) {
                    if (t->c.own[j] == 1) cur[j] = (mrow){true, t->c.ownrow[j].u, t->c.ownrow[j].v, ++m.vctr};
                    else if (t->c.own[j] == 2) cur[j].exists = false;
                }
                m_push(&m, cur);
                commits++;
            }
            m_close(t);
        } else if (r < 80) {
            snprintf(sql, sizeof sql, "ROLLBACK");
            got = srun(s, sql);
            m_close(t);
        } else if (r < 86) { /* SAVEPOINT s1 / s2 */
            int nm = 1 + (int)(test_rand() % 2);
            snprintf(sql, sizeof sql, "SAVEPOINT s%d", nm);
            if (t->doomed) want = IMDB_ERR_CONFLICT;
            else if (t->nsps < 64) t->sps[t->nsps++] = (msp){nm, t->c};
            else CHECK(!"the model's savepoint list is full"); /* never silently diverge */
            got = srun(s, sql);
        } else if (r < 92) { /* ROLLBACK TO s1 / s2 */
            int nm = 1 + (int)(test_rand() % 2), k = -1;
            snprintf(sql, sizeof sql, "ROLLBACK TO s%d", nm);
            for (int i = t->nsps; i-- > 0;)
                if (t->sps[i].name == nm) {
                    k = i;
                    break;
                }
            if (t->doomed) want = IMDB_ERR_CONFLICT;
            else if (k < 0) want = IMDB_ERR_NOTFOUND;
            else {
                t->c = t->sps[k].c;
                t->nsps = k + 1;
            }
            got = srun(s, sql);
        } else if (r < 95) { /* RELEASE s1 / s2 */
            int nm = 1 + (int)(test_rand() % 2), k = -1;
            snprintf(sql, sizeof sql, "RELEASE s%d", nm);
            for (int i = t->nsps; i-- > 0;)
                if (t->sps[i].name == nm) {
                    k = i;
                    break;
                }
            if (t->doomed) want = IMDB_ERR_CONFLICT;
            else if (k < 0) want = IMDB_ERR_NOTFOUND;
            else t->nsps = k;
            got = srun(s, sql);
        } else {
            continue;
        }
        if (trace) fprintf(stderr, "  %4d s%d %-55s -> %d (model %d)\n", step, si, sql, got, want);
        if (got == IMDB_ERR_CONFLICT) conflicts++;
        if (got != want) {
            fprintf(stderr, "    step %d: session %d: \"%s\" -> %d (%s), the model says %d\n", step, si, sql, got,
                    g_e.msg, want);
            CHECK(got == want);
        }
    }
    st->commits += commits;
    st->conflicts += conflicts;
    st->checks += checks;
    for (int i = 0; i < MNS; i++) imdb_session_close(&ss[i]);
    /* the committed state, by a fresh session, then VERIFY, then the same after a replay */
    imdb_session z;
    imdb_session_init(&z, db);
    int64_t wc, ws;
    engine_view_ok(&z, &m, NULL, &wc, &ws);
    CHECK(sval(&z, "SELECT COUNT(*) FROM t") == wc && sval(&z, "SELECT SUM(v) FROM t") == ws);
    imdb_verify_report vr;
    OK(imdb_verify(db, &vr, E));
    imdb_session_close(&z);
    char dir[600];
    snprintf(dir, sizeof dir, "%s", db->path);
    imdb_close(db);
    db = open_db(dir);
    CHECK(db);
    imdb_session_init(&z, db);
    CHECK(sval(&z, "SELECT COUNT(*) FROM t") == wc && sval(&z, "SELECT SUM(v) FROM t") == ws);
    imdb_session_close(&z);
    imdb_close(db);
    free(m.st);
}

/* Several independent rounds (IMDB_TXN_SEEDS overrides the count). */
static void t_txn_random_model(void)
{
    const char *env = getenv("IMDB_TXN_SEEDS");
    int seeds = env && atoi(env) > 0 ? atoi(env) : 4;
    mstats st[2] = {{0}};
    for (int k = 0; k < seeds && !g_test_failed; k++) { /* odd rounds: 48 ids, far less contention */
        test_seed(1000 + (uint64_t)k);
        random_model_round(k % 2 ? 48 : 10, &st[k % 2]);
    }
    for (int c = 0; c < 2; c++)
        fprintf(stderr,
                "    %d rounds of 4000 steps over %d ids: %d commits, %d conflicts, %d reads checked, %d physical "
                "operations over saved writes\n",
                (seeds + 1 - c) / 2, c ? 48 : 10, st[c].commits, st[c].conflicts, st[c].checks, st[c].phys_parked);
    CHECK(st[0].commits > 50 && st[0].conflicts > 10 && st[0].checks > 500 && st[0].phys_parked > 5);
    CHECK(seeds < 2 || (st[1].commits > st[0].commits / 2 && st[1].checks > 500));
}

/* INSERT n rows from id `from`, each with an slen-byte TEXT (a row is 20 + slen bytes). */
static int ins_rows(imdb_session *s, int from, int n, int slen)
{
    imdb_buf q;
    imdb_buf_init(&q);
    char pad[200], cell[300];
    memset(pad, 'x', (size_t)slen);
    pad[slen] = '\0';
    imdb_buf_put(&q, "INSERT INTO t VALUES ", 21);
    for (int i = 0; i < n; i++) {
        int k = snprintf(cell, sizeof cell, "%s(%d, %d, '%s')", i ? ", " : "", from + i, from + i, pad);
        imdb_buf_put(&q, cell, (size_t)k);
    }
    imdb_buf_put_u8(&q, 0);
    int rc = srun(s, (const char *)q.p);
    imdb_buf_free(&q);
    return rc;
}

/* Each per-transaction limit fails the statement with LIMIT, undoes all of it, and
 * leaves the transaction usable: row operations; row bytes (exact across statement
 * rollback, ROLLBACK TO and a switch); FOR UPDATE rows (a repeated lock counts once);
 * savepoints, at the real maximum. Limits above the maxima are refused at open. */
static void t_txn_limits(void)
{
    const char *dir = test_tmpdir();
    OK(imdb_init(dir, false, NULL, E));
    imdb_db *db = NULL;
    imdb_open_opts big = {.sync = 0, .txn_ops = IMDB_MAX_OPS_PER_COMMIT + 1};
    CHECK(imdb_open(dir, &big, &db, E) == IMDB_ERR_INVALID && !db);
    imdb_open_opts o = {.sync = 0, .txn_ops = 40, .txn_bytes = 2000, .txn_locks = 8};
    OK(imdb_open(dir, &o, &db, E));
    imdb_session a, b;
    imdb_session_init(&a, db);
    imdb_session_init(&b, db);
    SRUN(&a, "CREATE TABLE t (id INT64 PRIMARY KEY, u INT64 SUBJECT, s TEXT NOT NULL)"); /* no null bitmap */

    /* row operations: 40 */
    SRUN(&a, "BEGIN");
    CHECK(ins_rows(&a, 1, 30, 0) == IMDB_OK);
    CHECK(ins_rows(&a, 31, 11, 0) == IMDB_ERR_LIMIT && strstr(g_e.msg, "40 operations"));
    CHECK(sval(&a, "SELECT COUNT(*) FROM t") == 30); /* none of the failed statement's rows */
    CHECK(ins_rows(&a, 31, 10, 0) == IMDB_OK);
    CHECK(srun(&a, "DELETE FROM t WHERE id = 1") == IMDB_ERR_LIMIT);
    SRUN(&a, "COMMIT");
    CHECK(sval(&b, "SELECT COUNT(*) FROM t") == 40);

    /* row bytes: 2000, i.e. 20 rows of 100 bytes */
    SRUN(&a, "BEGIN");
    SRUN(&a, "SAVEPOINT p");
    CHECK(ins_rows(&a, 100, 15, 80) == IMDB_OK);
    CHECK(ins_rows(&a, 115, 6, 80) == IMDB_ERR_LIMIT && strstr(g_e.msg, "2000 bytes"));
    CHECK(ins_rows(&a, 115, 5, 80) == IMDB_OK); /* exactly at the limit */
    CHECK(ins_rows(&a, 120, 1, 0) == IMDB_ERR_LIMIT);
    SRUN(&a, "ROLLBACK TO p"); /* gives the bytes back */
    CHECK(ins_rows(&a, 200, 20, 80) == IMDB_OK);
    SRUN(&b, "UPDATE t SET s = 'b' WHERE id = 2"); /* a's writes are saved, then replayed */
    CHECK(ins_rows(&a, 220, 1, 0) == IMDB_ERR_LIMIT);
    CHECK(srun(&a, "UPDATE t SET s = '' WHERE id = 200") == IMDB_ERR_LIMIT); /* a new version is new bytes */
    CHECK(srun(&a, "DELETE FROM t WHERE id = 3") == IMDB_OK);                 /* a DELETE carries no row */
    CHECK(sval(&a, "SELECT COUNT(*) FROM t") == 59);
    SRUN(&a, "COMMIT");
    CHECK(sval(&b, "SELECT COUNT(*) FROM t") == 59);

    /* FOR UPDATE rows: 8 */
    SRUN(&a, "BEGIN");
    CHECK(sval(&a, "SELECT COUNT(*) FROM t WHERE id <= 9") == 8); /* ids 1, 2, 4..9 */
    SRUN(&a, "SELECT id FROM t WHERE id <= 9 FOR UPDATE");
    SRUN(&a, "SELECT id FROM t WHERE id <= 9 FOR UPDATE"); /* the same rows: nothing new */
    SRUN(&a, "SELECT id FROM t WHERE id = 4 FOR UPDATE");
    CHECK(srun(&a, "SELECT id FROM t WHERE id <= 10 FOR UPDATE") == IMDB_ERR_LIMIT &&
          strstr(g_e.msg, "8 rows selected FOR UPDATE"));
    CHECK(sval(&a, "SELECT COUNT(*) FROM t") == 59);
    SRUN(&a, "COMMIT");

    /* savepoints: the real maximum */
    SRUN(&a, "BEGIN");
    for (uint32_t i = 0; i < IMDB_MAX_SAVEPOINTS && !g_test_failed; i++) SRUN(&a, "SAVEPOINT p");
    CHECK(srun(&a, "SAVEPOINT q") == IMDB_ERR_LIMIT && strstr(g_e.msg, "savepoints"));
    SRUN(&a, "RELEASE p"); /* the latest p */
    SRUN(&a, "SAVEPOINT q");
    CHECK(srun(&a, "SAVEPOINT r") == IMDB_ERR_LIMIT);
    SRUN(&a, "UPDATE t SET s = 'a' WHERE id = 5");
    SRUN(&a, "ROLLBACK TO p"); /* keeps p, destroys q (set after it) and undoes the UPDATE */
    CHECK(sval(&a, "SELECT COUNT(*) FROM t WHERE s = 'a'") == 0);
    SRUN(&a, "SAVEPOINT r");
    CHECK(srun(&a, "SAVEPOINT s") == IMDB_ERR_LIMIT);
    SRUN(&a, "ROLLBACK TO p");
    SRUN(&a, "COMMIT");
    imdb_session_close(&a);
    imdb_session_close(&b);
    imdb_verify_report vr;
    OK(imdb_verify(db, &vr, E));
    imdb_close(db);
}

/* ROLLBACK TO a savepoint before every write of a suspended transaction leaves it
 * with no saved list at all, so becoming active again (no replay) and being saved
 * once more cannot lose an array (found by LeakSanitizer in the random test). */
static void t_txn_rollback_to_suspended_empty(void)
{
    imdb_session a, b;
    imdb_db *db = setup(&a, &b);
    CHECK(db);
    SRUN(&a, "BEGIN");
    SRUN(&a, "SAVEPOINT p");
    SRUN(&a, "INSERT INTO t VALUES (3, 3, 30)");
    SRUN(&b, "INSERT INTO t VALUES (4, 4, 40)"); /* a is saved */
    CHECK(a.txn.nops == 1 && a.txn.ops);
    SRUN(&a, "ROLLBACK TO p"); /* while suspended */
    CHECK(a.txn.nops == 0 && !a.txn.ops);
    SRUN(&a, "INSERT INTO t VALUES (5, 5, 50)"); /* active again without a replay */
    SRUN(&b, "INSERT INTO t VALUES (6, 6, 60)"); /* saved again */
    CHECK(a.txn.nops == 1 && a.txn.ops);
    SRUN(&a, "COMMIT");
    CHECK(sval(&b, "SELECT COUNT(*) FROM t") == 5 && sval(&b, "SELECT COUNT(*) FROM t WHERE id = 3") == 0);
    imdb_session_close(&a);
    imdb_session_close(&b);
    imdb_close(db);
}

/* Per-statement salts (2026-10-26): a statement's salts come from one seed, a fresh one for each
 * statement; every version's salt is distinct; a parked transaction's rows keep theirs when it is
 * replayed. (The seed's wipe at the statement's end is by construction: xfree, the one exit.) */
static int cmp16(const void *a, const void *b) { return memcmp(a, b, 16); }

/* the salts of table t's versions that begin after commit `after`, sorted */
static size_t salts_after(imdb_db *db, uint64_t after, uint8_t (*out)[16], size_t cap)
{
    imdb_table *t = imdb_table_by_name(db, "t");
    size_t n = 0;
    for (uint64_t vid = 0; t && vid < t->nver && n < cap; vid++)
        if (imdb_vh(t, vid)->begin > after) memcpy(out[n++], imdb_vc(t, vid)->salt, 16);
    qsort(out, n, 16, cmp16);
    return n;
}

static bool distinct16(uint8_t (*s)[16], size_t n)
{
    for (size_t i = 1; i < n; i++)
        if (memcmp(s[i - 1], s[i], 16) == 0) return false;
    return true;
}

static void t_txn_salts(void)
{
    enum { CAP = 1200 };
    static uint8_t s[CAP][16], p[8][16];
    static char q[16384];
    imdb_session a, b;
    imdb_db *db = setup(&a, &b);
    CHECK(db);
    if (!db) return;
    uint64_t base = db->seq;
    size_t n = (size_t)snprintf(q, sizeof q, "INSERT INTO t VALUES ");
    for (int i = 100; i < 300; i++) n += (size_t)snprintf(q + n, sizeof q - n, "%s(%d, 1, 0)", i > 100 ? ", " : "", i);
    SRUN(&a, q); /* 200 rows, one statement: 50 ChaCha20 blocks of one seed */
    CHECK(salts_after(db, base, s, CAP) == 200 && distinct16(s, 200));
    for (int i = 300; i < 600; i++) { /* 300 statements, a seed each */
        snprintf(q, sizeof q, "INSERT INTO t VALUES (%d, 2, 0)", i);
        SRUN(&a, q);
    }
    SRUN(&a, "UPDATE t SET v = 7 WHERE u = 1"); /* 201 new versions (setup's row 1 too), one statement */
    CHECK(salts_after(db, base, s, CAP) == 701 && distinct16(s, 701));
    /* A parked: its three rows are replayed with the salts they had */
    SRUN(&a, "BEGIN");
    SRUN(&a, "INSERT INTO t VALUES (900, 3, 0), (901, 3, 0), (902, 3, 0)");
    uint64_t before = db->seq;
    CHECK(salts_after(db, before, p, 8) == 3);
    SRUN(&b, "BEGIN");
    SRUN(&b, "INSERT INTO t VALUES (950, 4, 0)");
    CHECK(db->active == &b.txn);
    SRUN(&b, "COMMIT");
    SRUN(&a, "INSERT INTO t VALUES (903, 3, 0)"); /* A resumes: its saved writes replayed first */
    SRUN(&a, "COMMIT");
    size_t m = salts_after(db, before + 1, s, CAP); /* A's commit follows B's */
    CHECK(m == 4 && distinct16(s, m));
    for (int i = 0; i < 3 && m == 4; i++) CHECK(bsearch(p[i], s, m, 16, cmp16) != NULL);
    imdb_session_close(&a);
    imdb_session_close(&b);
    imdb_close(db);
}

const test_case txn_tests[] = {
    {"txn_salts", t_txn_salts},
    {"txn_rollback_to_suspended_empty", t_txn_rollback_to_suspended_empty},
    {"txn_limits", t_txn_limits},
    {"txn_random_model", t_txn_random_model},
    {"txn_sql_surface", t_txn_sql_surface},
    {"txn_savepoints", t_txn_savepoints},
    {"txn_for_update", t_txn_for_update},
    {"txn_write_skew_allowed", t_txn_write_skew_allowed},
    {"txn_maintenance_after_commit", t_txn_maintenance_after_commit},
    {"txn_conflict_statement_time", t_txn_conflict_statement_time},
    {"txn_duplicate_vs_conflict", t_txn_duplicate_vs_conflict},
    {"txn_lost_update_prevented", t_txn_lost_update_prevented},
    {"txn_snapshot_below_horizon", t_txn_snapshot_below_horizon},
    {"txn_failed_commit_untouched", t_txn_failed_commit_untouched},
    {"txn_no_dirty_reads", t_txn_no_dirty_reads},
    {"txn_interleaved", t_txn_interleaved},
    {"txn_conflict_on_replay", t_txn_conflict_on_replay},
    {"txn_erase_dooms_suspended", t_txn_erase_dooms_suspended},
};
const size_t txn_ntests = sizeof txn_tests / sizeof *txn_tests;
