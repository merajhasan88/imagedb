/* F2b-2: FOREIGN KEYs (docs/fk-design.md). A column's REFERENCES and a table's [CONSTRAINT name] FOREIGN KEY ...
 * REFERENCES in CREATE TABLE (op 29), ALTER TABLE ... ADD (op 22 kind 13: every live row then) and DROP CONSTRAINT (kind
 * 14); the parent's whole primary key; ON DELETE NO ACTION, RESTRICT, CASCADE, SET NULL, SET DEFAULT; MATCH SIMPLE.
 * Checked at each statement's end and again at the commit (the API's writes have no statement end; a parked
 * transaction's replay meets the commits since): what the transaction can see is CONSTRAINT, what a commit after its
 * snapshot did CONFLICT. Replay and the auditor hold every commit to referential integrity at its end. */
#include <stdlib.h>

#include "../../src/backup.h"
#include "../../src/db_internal.h"
#include "../../src/lake.h"
#include "../../src/log.h"
#include "../../src/sql.h"
#include "thelp.h"

static imdb_session g_s;
static char g_out[1 << 16];

/* COPY FROM's stream (g_in), and COPY TO's, discarded */
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

static const char *csv_in(imdb_session *s, const char *sql)
{
    imdb_result r;
    imdb_err_clear(&g_e);
    if (imdb_exec_one(s, sql, strlen(sql), NULL, 0, &r, &g_e)) {
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

#define EXPECT_IN(s, sql, want)                                                                                    \
    do {                                                                                                           \
        const char *got_ = csv_in((s), (sql));                                                                     \
        bool ok_ = !strncmp((want), "ERR ", 4) ? !strncmp(got_, "ERR ", 4) && strstr(got_ + 4, (want) + 4) != NULL \
                                               : !strcmp(got_, (want));                                            \
        if (!ok_) {                                                                                                \
            char m_[1600];                                                                                         \
            snprintf(m_, sizeof m_, "%s\n      want: %s\n      got:  %.600s", (sql), (want), got_);                \
            test_fail(__FILE__, __LINE__, m_);                                                                     \
        }                                                                                                          \
    } while (0)
#define EXPECT(sql, want) EXPECT_IN(&g_s, sql, want)

static imdb_db *open_at(const char *dir, bool full_replay)
{
    imdb_open_opts o = {.sync = 0, .full_replay = full_replay};
    imdb_db *db = NULL;
    imdb_err e = {0};
    if (imdb_open(dir, &o, &db, &e)) return NULL;
    imdb_session_init(&g_s, db);
    imdb_session_copy_io(&g_s, mem_read, mem_write, &g_in);
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
    if (!bin || !*bin) return 0;
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

/* ---- the statements: names, the actions, the statement's end, every refusal ---- */
static void t_fk_statements(void)
{
    const char *dir = test_tmpdir();
    imdb_db *db = open_fresh(dir);
    CHECK(db);
    if (!db) return;
    OK(run("CREATE TABLE p (id INT64 PRIMARY KEY, n TEXT)"));
    OK(run("CREATE TABLE p2 (a INT64, b TEXT, PRIMARY KEY (a, b))"));
    EXPECT("CREATE TABLE x (id INT64 PRIMARY KEY, pid INT64 REFERENCES nope)", "ERR no table nope");
    EXPECT("CREATE TABLE x (id INT64 PRIMARY KEY, pid TEXT REFERENCES p)", "ERR column pid is TEXT");
    EXPECT("CREATE TABLE x (id INT64 PRIMARY KEY, pid INT64 REFERENCES p2)", "ERR whose primary key has 2");
    EXPECT("CREATE TABLE x (id INT64 PRIMARY KEY, pid INT64 REFERENCES p (n))", "ERR is not in it");
    EXPECT("CREATE TABLE x (id INT64 PRIMARY KEY, pid INT64 NOT NULL REFERENCES p ON DELETE SET NULL)", "ERR SET NULL of NOT NULL");
    EXPECT("CREATE TABLE x (id INT64 PRIMARY KEY, pid INT64 REFERENCES p ON UPDATE CASCADE)", "ERR ON UPDATE takes NO ACTION or RESTRICT");
    EXPECT("CREATE TABLE x (id INT64 PRIMARY KEY, pid INT64 REFERENCES p MATCH FULL)", "ERR MATCH FULL");
    EXPECT("CREATE TABLE x (id INT64 PRIMARY KEY, pid INT64 REFERENCES p DEFERRABLE)", "ERR deferrable");
    OK(run("CREATE TABLE c (id INT64 PRIMARY KEY, pid INT64 REFERENCES p ON DELETE CASCADE ON UPDATE RESTRICT MATCH SIMPLE "
           "NOT DEFERRABLE, s TEXT)"));
    OK(run("CREATE TABLE d (id INT64 PRIMARY KEY, pid INT64 DEFAULT 2, CONSTRAINT d_p FOREIGN KEY (pid) REFERENCES p (id) "
           "ON DELETE SET DEFAULT)"));
    OK(run("CREATE TABLE n (id INT64 PRIMARY KEY, pid INT64, FOREIGN KEY (pid) REFERENCES p ON DELETE SET NULL)"));
    OK(run("CREATE TABLE r (id INT64 PRIMARY KEY, pid INT64 REFERENCES p ON DELETE RESTRICT)"));
    OK(run("CREATE TABLE m (id INT64 PRIMARY KEY, b TEXT, a INT64, FOREIGN KEY (b, a) REFERENCES p2 (b, a))"));
    EXPECT("SELECT COUNT(*) FROM c", "count\n0\n");
    /* the names: PostgreSQL's when none is given */
    imdb_table *t = imdb_table_by_name(db, "c");
    CHECK(t && t->hist.nfk == 1 && !strcmp(t->hist.fk[0].name, "c_pid_fkey") && t->hist.fk[0].on_delete == IMDB_FK_CASCADE &&
          t->hist.fk[0].on_update == IMDB_FK_RESTRICT);
    t = imdb_table_by_name(db, "m");
    CHECK(t && t->hist.nfk == 1 && !strcmp(t->hist.fk[0].name, "m_b_a_fkey") && t->hist.fk[0].cols[0] == 2 &&
          t->hist.fk[0].cols[1] == 1); /* the key's order: a, then b */
    OK(run("INSERT INTO p VALUES (1, 'a'), (2, 'b'), (3, 'c'), (4, 'd')"));
    OK(run("INSERT INTO p2 VALUES (1, 'x')"));
    /* a child before its parent in one statement: the statement's end decides (PostgreSQL's NO ACTION timing) */
    EXPECT("INSERT INTO c VALUES (10, 1, 'a'), (11, 9, 'no parent')", "ERR violates foreign key constraint c_pid_fkey");
    EXPECT("SELECT COUNT(*) FROM c", "count\n0\n");
    EXPECT("INSERT INTO c VALUES (10, 1, 'a'), (11, 1, 'b'), (12, 2, 'c'), (13, NULL, 'none')", "INSERT 4");
    EXPECT("INSERT INTO m VALUES (1, 'x', 1), (2, NULL, 7)", "INSERT 2"); /* MATCH SIMPLE: a NULL, unchecked */
    EXPECT("INSERT INTO m VALUES (3, 'y', 1)", "ERR violates foreign key constraint m_b_a_fkey");
    OK(run("INSERT INTO d VALUES (20, 1), (21, 3)"));
    OK(run("INSERT INTO n VALUES (30, 1), (31, 3)"));
    OK(run("INSERT INTO r VALUES (40, 4)"));
    EXPECT("UPDATE c SET pid = 8 WHERE id = 10", "ERR violates foreign key constraint c_pid_fkey");
    EXPECT("UPDATE c SET s = 'kept' WHERE id = 10", "UPDATE 1");
    /* the actions: CASCADE, SET DEFAULT (2), SET NULL; RESTRICT refuses */
    EXPECT("DELETE FROM p WHERE id = 4", "ERR violates foreign key constraint r_pid_fkey on table r");
    EXPECT("DELETE FROM p WHERE id = 1", "DELETE 1");
    EXPECT("SELECT id, pid FROM c ORDER BY id", "id,pid\n12,2\n13,\n");
    EXPECT("SELECT id, pid FROM d ORDER BY id", "id,pid\n20,2\n21,3\n");
    EXPECT("SELECT id, pid FROM n ORDER BY id", "id,pid\n30,\n31,3\n");
    /* SET DEFAULT to a key that is gone: the statement's end refuses it */
    EXPECT("DELETE FROM p WHERE id = 2", "ERR violates foreign key constraint d_p");
    EXPECT("SELECT COUNT(*) FROM p", "count\n3\n");
    /* a tree: its rows in any order in one statement, a CASCADE down it */
    OK(run("CREATE TABLE tr (id INT64 PRIMARY KEY, up INT64 REFERENCES tr ON DELETE CASCADE)"));
    EXPECT("INSERT INTO tr VALUES (4, 3), (3, 2), (2, 1), (1, NULL), (5, 1)", "INSERT 5");
    EXPECT("DELETE FROM tr WHERE id = 2", "DELETE 1");
    EXPECT("SELECT id FROM tr ORDER BY id", "id\n1\n5\n");
    /* catalog rules: DROP TABLE of a referenced parent, DROP COLUMN of an FK column, names in one space */
    EXPECT("DROP TABLE p", "ERR foreign key");
    EXPECT("ALTER TABLE c DROP COLUMN pid", "ERR foreign key c_pid_fkey names column pid");
    EXPECT("ALTER TABLE c ADD CONSTRAINT c_pid_fkey CHECK (id > 0)", "ERR already exists");
    EXPECT("ALTER TABLE c DROP CONSTRAINT c_pid_fkey", "ALTER TABLE c");
    EXPECT("INSERT INTO c VALUES (50, 99, 'free now')", "INSERT 1");
    EXPECT("ALTER TABLE c ADD FOREIGN KEY (pid) REFERENCES p", "ERR violates foreign key constraint c_pid_fkey");
    EXPECT("DELETE FROM c WHERE id = 50", "DELETE 1");
    EXPECT("ALTER TABLE c ADD FOREIGN KEY (pid) REFERENCES p", "ALTER TABLE c");
    EXPECT("DROP TABLE tr", "DROP TABLE tr"); /* a self-reference goes with its table */
    CHECK(verify_db(db) == 0);
    done(db);
    CHECK(audit_dir(dir) == 0);
    db = open_at(dir, true); /* a full replay holds every commit to integrity */
    CHECK(db);
    if (db) {
        EXPECT("SELECT id, pid FROM c ORDER BY id", "id,pid\n12,2\n13,\n");
        EXPECT("INSERT INTO c VALUES (60, 77, 'x')", "ERR violates foreign key constraint c_pid_fkey");
        done(db);
    }
}

/* ---- the API: no statement end, so the commit checks; a refused commit leaves nothing ---- */
static void t_fk_api(void)
{
    const char *dir = test_tmpdir();
    imdb_db *db = open_fresh(dir);
    CHECK(db);
    if (!db) return;
    OK(run("CREATE TABLE p (id INT64 PRIMARY KEY)"));
    OK(run("CREATE TABLE c (id INT64 PRIMARY KEY, pid INT64 REFERENCES p)"));
    OK(run("INSERT INTO p VALUES (1)"));
    imdb_table *c = imdb_table_by_name(db, "c");
    CHECK(c);
    if (!c) {
        done(db);
        return;
    }
    imdb_value v[2] = {{.type = IMDB_T_INT64, .i = 5}, {.type = IMDB_T_INT64, .i = 9}};
    imdb_err e = {0};
    OK(imdb_begin(db, &e));
    OK(imdb_insert(db, c, v, &e));
    CHECK(imdb_commit(db, &e) == IMDB_ERR_CONSTRAINT && strstr(e.msg, "c_pid_fkey"));
    CHECK(!db->in_txn);
    EXPECT("SELECT COUNT(*) FROM c", "count\n0\n");
    v[1].i = 1;
    imdb_err_clear(&e);
    OK(imdb_begin(db, &e));
    OK(imdb_insert(db, c, v, &e));
    OK(imdb_commit(db, &e));
    EXPECT("SELECT id, pid FROM c", "id,pid\n5,1\n");
    imdb_table *p = imdb_table_by_name(db, "p"); /* the parent's delete through the API: refused at the commit */
    imdb_value k = {.type = IMDB_T_INT64, .i = 1};
    uint64_t vid = p ? imdb_lookup_pk(db, p, &k, imdb_read_snapshot(db)) : IMDB_NONE;
    CHECK(vid != IMDB_NONE);
    OK(imdb_begin(db, &e));
    OK(imdb_delete(db, p, vid, &e));
    CHECK(imdb_commit(db, &e) == IMDB_ERR_CONSTRAINT && strstr(e.msg, "c_pid_fkey"));
    EXPECT("SELECT COUNT(*) FROM p", "count\n1\n");
    CHECK(verify_db(db) == 0);
    done(db);
    CHECK(audit_dir(dir) == 0);
}

/* ---- two sessions: a child's insert and its parent's delete, each committing first; a non-key update ---- */
static void t_fk_sessions(void)
{
    const char *dir = test_tmpdir();
    imdb_db *db = open_fresh(dir);
    CHECK(db);
    if (!db) return;
    imdb_session a, b;
    imdb_session_init(&a, db);
    imdb_session_init(&b, db);
    EXPECT_IN(&a, "CREATE TABLE p (id INT64 PRIMARY KEY, v INT64)", "CREATE TABLE p");
    EXPECT_IN(&a, "CREATE TABLE c (id INT64 PRIMARY KEY, pid INT64 REFERENCES p)", "CREATE TABLE c");
    EXPECT_IN(&a, "INSERT INTO p VALUES (1, 0), (2, 0), (3, 0)", "INSERT 3");
    /* the child's insert commits first: the parent's delete, begun before it, is a conflict */
    EXPECT_IN(&b, "BEGIN", "BEGIN");
    EXPECT_IN(&b, "SELECT COUNT(*) FROM c", "count\n0\n"); /* its snapshot */
    EXPECT_IN(&a, "BEGIN", "BEGIN");
    EXPECT_IN(&a, "INSERT INTO c VALUES (10, 1)", "INSERT 1");
    CHECK(!strncmp(csv_in(&a, "COMMIT"), "COMMIT", 6));
    const char *g1 = csv_in(&b, "DELETE FROM p WHERE id = 1");
    char got[600];
    snprintf(got, sizeof got, "%s", g1);
    if (strncmp(got, "ERR", 3)) {
        g1 = csv_in(&b, "COMMIT");
        snprintf(got, sizeof got, "%s", g1);
    } else {
        csv_in(&b, "ROLLBACK");
    }
    CHECK(!strncmp(got, "ERR", 3) && (strstr(got, "could not serialize") || strstr(got, "violates foreign key")));
    EXPECT_IN(&a, "SELECT COUNT(*) FROM p WHERE id = 1", "count\n1\n");
    /* the parent's delete commits first: the child's insert, begun before it, is a conflict */
    EXPECT_IN(&b, "BEGIN", "BEGIN");
    EXPECT_IN(&b, "SELECT COUNT(*) FROM p", "count\n3\n");
    EXPECT_IN(&a, "DELETE FROM p WHERE id = 2", "DELETE 1");
    g1 = csv_in(&b, "INSERT INTO c VALUES (11, 2)");
    snprintf(got, sizeof got, "%s", g1);
    if (strncmp(got, "ERR", 3)) {
        g1 = csv_in(&b, "COMMIT");
        snprintf(got, sizeof got, "%s", g1);
    } else {
        csv_in(&b, "ROLLBACK");
    }
    CHECK(!strncmp(got, "ERR", 3) && strstr(got, "could not serialize"));
    EXPECT_IN(&a, "SELECT COUNT(*) FROM c WHERE pid = 2", "count\n0\n");
    /* a non-key update of the parent beside a child's insert: no conflict (a key check, not a row lock) */
    EXPECT_IN(&b, "BEGIN", "BEGIN");
    EXPECT_IN(&b, "INSERT INTO c VALUES (12, 3)", "INSERT 1");
    EXPECT_IN(&a, "UPDATE p SET v = 5 WHERE id = 3", "UPDATE 1");
    CHECK(!strncmp(csv_in(&b, "COMMIT"), "COMMIT", 6));
    EXPECT_IN(&a, "SELECT id, pid FROM c ORDER BY id", "id,pid\n10,1\n12,3\n");
    imdb_session_close(&a);
    imdb_session_close(&b);
    CHECK(verify_db(db) == 0);
    done(db);
    CHECK(audit_dir(dir) == 0);
}

/* ---- the copies: a CHECKPOINT and a snapshot open, a full replay, a replica, the dump into a fresh database ---- */
static void t_fk_copies(void)
{
    const char *dir = test_tmpdir();
    char p[700], q[700], sf[700];
    snprintf(p, sizeof p, "%s/p", dir);
    snprintf(q, sizeof q, "%s/q", dir);
    snprintf(sf, sizeof sf, "%s/stream", dir);
    imdb_err e = {0};
    CHECK(imdb_init(p, false, NULL, &e) == 0 && imdb_init(q, true, p, &e) == 0);
    imdb_db *db = open_at(p, false);
    CHECK(db);
    if (!db) return;
    OK(run("CREATE TABLE a (id INT64 PRIMARY KEY)"));
    OK(run("CREATE TABLE b (id INT64 PRIMARY KEY, aid INT64 REFERENCES a ON DELETE CASCADE)"));
    OK(run("INSERT INTO a VALUES (1), (2), (3)"));
    OK(run("INSERT INTO b VALUES (10, 1), (11, 2), (12, 2)"));
    OK(run("CHECKPOINT"));
    OK(run("CREATE TABLE z (id INT64 PRIMARY KEY, bid INT64)"));
    OK(run("INSERT INTO z VALUES (100, 11)"));
    OK(run("ALTER TABLE z ADD CONSTRAINT z_b FOREIGN KEY (bid) REFERENCES b ON DELETE SET NULL"));
    OK(run("DELETE FROM a WHERE id = 2")); /* b 11 and 12 go, z 100's bid NULL */
    OK(run("CHECKPOINT"));
    EXPECT("SELECT id, bid FROM z", "id,bid\n100,\n");
    EXPECT("SELECT id FROM b ORDER BY id", "id\n10\n");
    CHECK(verify_db(db) == 0);
    done(db);
    CHECK(audit_dir(p) == 0);
    for (int pass = 0; pass < 2; pass++) { /* a snapshot open, then a full replay */
        db = open_at(p, pass == 1);
        CHECK(db);
        if (!db) return;
        EXPECT("INSERT INTO b VALUES (20, 9)", "ERR violates foreign key constraint b_aid_fkey");
        EXPECT("INSERT INTO z VALUES (101, 99)", "ERR violates foreign key constraint z_b");
        EXPECT("DELETE FROM a WHERE id = 1", "DELETE 1");
        EXPECT("SELECT COUNT(*) FROM b", "count\n0\n");
        OK(run("INSERT INTO a VALUES (1)"));
        OK(run("INSERT INTO b VALUES (10, 1)"));
        CHECK(verify_db(db) == 0);
        done(db);
    }
    CHECK(audit_dir(p) == 0);
    OK(ship_to_file(p, 0, sf, &g_e)); /* a replica by the stream */
    imdb_open_opts o = {.sync = 0};
    imdb_db *qdb = NULL;
    CHECK(imdb_open(q, &o, &qdb, &e) == 0);
    if (qdb) {
        uint64_t qa = 0;
        OK(apply_file(qdb, sf, &qa, &g_e));
        imdb_table *qt = imdb_table_by_name(qdb, "z");
        CHECK(qt && qt->hist.nfk == 1 && !strcmp(qt->hist.fk[0].name, "z_b"));
        imdb_close(qdb);
    }
    CHECK(audit_dir(q) == 0);
}


static const char *copy_in(const char *stmt, const char *data, size_t len)
{
    g_in = (mem_in){data, len, 0};
    return csv_in(&g_s, stmt);
}

/* ---- every write path of the child and the parent ---- */
static void t_fk_paths(void)
{
    const char *dir = test_tmpdir();
    imdb_db *db = open_fresh(dir);
    CHECK(db);
    if (!db) return;
    OK(run("CREATE TABLE p (id INT64 PRIMARY KEY, n TEXT)"));
    OK(run("CREATE TABLE c (id INT64 PRIMARY KEY, pid INT64 REFERENCES p ON DELETE CASCADE, s TEXT)"));
    OK(run("CREATE TABLE m (k INT64 PRIMARY KEY, np INT64)"));
    OK(run("INSERT INTO p VALUES (1, 'a'), (2, 'b'), (3, 'c')"));
    /* INSERT ... SELECT: one orphan refuses the statement whole */
    EXPECT("INSERT INTO c SELECT id + 10, id, n FROM p", "INSERT 3");
    EXPECT("INSERT INTO c SELECT id + 20, id + 1, n FROM p", "ERR violates foreign key constraint c_pid_fkey");
    EXPECT("SELECT COUNT(*) FROM c", "count\n3\n");
    EXPECT("INSERT INTO c VALUES (30, 9, 'x') RETURNING id", "ERR violates foreign key constraint c_pid_fkey");
    /* ON CONFLICT DO UPDATE: the row it writes is checked */
    EXPECT("INSERT INTO c VALUES (11, 1, 'y') ON CONFLICT (id) DO UPDATE SET pid = 7", "ERR violates foreign key constraint c_pid_fkey");
    OK(run("INSERT INTO c VALUES (11, 1, 'y') ON CONFLICT (id) DO UPDATE SET pid = 3"));
    EXPECT("SELECT pid FROM c WHERE id = 11", "pid\n3\n");
    /* UPDATE ... FROM */
    OK(run("INSERT INTO m VALUES (11, 9)"));
    EXPECT("UPDATE c SET pid = m.np FROM m WHERE c.id = m.k", "ERR violates foreign key constraint c_pid_fkey");
    OK(run("UPDATE m SET np = 2 WHERE k = 11"));
    EXPECT("UPDATE c SET pid = m.np FROM m WHERE c.id = m.k", "UPDATE 1");
    /* DELETE ... USING the parent: its CASCADE */
    EXPECT("DELETE FROM p USING m WHERE p.id = m.np", "DELETE 1");
    EXPECT("SELECT id, pid FROM c ORDER BY id", "id,pid\n13,3\n");
    /* COPY: an orphan refuses the statement whole; BATCH commits the batches before the one that holds it */
    static const char d1[] = "40,1,x\n41,8,y\n", d2[] = "40,1,x\n41,3,y\n", d3[] = "50,1,a\n51,9,b\n52,1,c\n";
    const char *got = copy_in("COPY c FROM STDIN (FORMAT csv)", d1, sizeof d1 - 1);
    CHECK(!strncmp(got, "ERR", 3) && strstr(got, "c_pid_fkey"));
    EXPECT("SELECT COUNT(*) FROM c", "count\n1\n");
    got = copy_in("COPY c FROM STDIN (FORMAT csv)", d2, sizeof d2 - 1);
    CHECK(!strcmp(got, "COPY 2"));
    got = copy_in("COPY c FROM STDIN (FORMAT csv, BATCH 1)", d3, sizeof d3 - 1);
    CHECK(!strncmp(got, "ERR", 3) && strstr(got, "c_pid_fkey"));
    EXPECT("SELECT id FROM c WHERE id >= 50 ORDER BY id", "id\n50\n");
    /* prepared */
    OK(run("PREPARE ins (INT64, INT64) AS INSERT INTO c VALUES ($1, $2, 'p')"));
    EXPECT("EXECUTE ins (60, 9)", "ERR violates foreign key constraint c_pid_fkey");
    EXPECT("EXECUTE ins (60, 1)", "INSERT 1");
    /* a transaction: a parent, its child and the parent's delete with its CASCADE, committed */
    OK(run("BEGIN"));
    OK(run("INSERT INTO p VALUES (9, 'z')"));
    OK(run("INSERT INTO c VALUES (70, 9, 'x')"));
    EXPECT("DELETE FROM p WHERE id = 9", "DELETE 1");
    OK(run("COMMIT"));
    EXPECT("SELECT COUNT(*) FROM c WHERE id = 70", "count\n0\n");
    /* a refused statement inside a transaction leaves its earlier writes and is refused alone */
    OK(run("BEGIN"));
    OK(run("INSERT INTO c VALUES (71, 1, 'kept')"));
    EXPECT("INSERT INTO c VALUES (72, 99, 'refused')", "ERR violates foreign key constraint c_pid_fkey");
    csv_in(&g_s, "COMMIT");
    csv_in(&g_s, "ROLLBACK");
    EXPECT("SELECT COUNT(*) FROM c WHERE id = 72", "count\n0\n");
    CHECK(verify_db(db) == 0);
    done(db);
    CHECK(audit_dir(dir) == 0);
    db = open_at(dir, true);
    CHECK(db);
    if (db) done(db);
}

/* ---- cascades over three levels, SET NULL and RESTRICT among them, a statement refused whole; a cycle ---- */
static void t_fk_levels(void)
{
    const char *dir = test_tmpdir();
    imdb_db *db = open_fresh(dir);
    CHECK(db);
    if (!db) return;
    OK(run("CREATE TABLE a (id INT64 PRIMARY KEY)"));
    OK(run("CREATE TABLE b (id INT64 PRIMARY KEY, aid INT64 REFERENCES a ON DELETE CASCADE)"));
    OK(run("CREATE TABLE c (id INT64 PRIMARY KEY, bid INT64 REFERENCES b ON DELETE SET NULL, aid INT64 REFERENCES a ON DELETE "
           "CASCADE)"));
    OK(run("CREATE TABLE d (id INT64 PRIMARY KEY, cid INT64 REFERENCES c ON DELETE RESTRICT)"));
    OK(run("INSERT INTO a VALUES (1), (2)"));
    OK(run("INSERT INTO b VALUES (10, 1), (11, 1), (12, 2)"));
    OK(run("INSERT INTO c VALUES (20, 10, 2), (21, 11, 2), (22, 12, 1)"));
    OK(run("INSERT INTO d VALUES (30, 20)"));
    EXPECT("DELETE FROM a WHERE id = 1", "DELETE 1");
    EXPECT("SELECT id FROM b ORDER BY id", "id\n12\n");
    EXPECT("SELECT id, bid, aid FROM c ORDER BY id", "id,bid,aid\n20,,2\n21,,2\n");
    EXPECT("DELETE FROM a WHERE id = 2", "ERR violates foreign key constraint d_cid_fkey on table d");
    EXPECT("SELECT (SELECT COUNT(*) FROM a) AS na, (SELECT COUNT(*) FROM b) AS nb, (SELECT COUNT(*) FROM c) AS nc", "na,nb,nc\n1,1,2\n");
    EXPECT("DELETE FROM d", "DELETE 1");
    EXPECT("DELETE FROM a WHERE id = 2", "DELETE 1");
    EXPECT("SELECT (SELECT COUNT(*) FROM a) AS na, (SELECT COUNT(*) FROM b) AS nb, (SELECT COUNT(*) FROM c) AS nc", "na,nb,nc\n0,0,0\n");
    /* a cycle of two tables, each CASCADE */
    OK(run("CREATE TABLE x (id INT64 PRIMARY KEY, yid INT64)"));
    OK(run("CREATE TABLE y (id INT64 PRIMARY KEY, xid INT64 REFERENCES x ON DELETE CASCADE)"));
    OK(run("ALTER TABLE x ADD FOREIGN KEY (yid) REFERENCES y ON DELETE CASCADE"));
    OK(run("INSERT INTO x VALUES (1, NULL)"));
    OK(run("INSERT INTO y VALUES (5, 1)"));
    OK(run("UPDATE x SET yid = 5 WHERE id = 1"));
    OK(run("INSERT INTO x VALUES (2, 5)"));
    EXPECT("INSERT INTO y VALUES (6, 3)", "ERR violates foreign key constraint y_xid_fkey");
    EXPECT("DROP TABLE x", "ERR foreign key");
    EXPECT("DELETE FROM y WHERE id = 5", "DELETE 1");
    EXPECT("SELECT (SELECT COUNT(*) FROM x) AS nx, (SELECT COUNT(*) FROM y) AS ny", "nx,ny\n0,0\n");
    /* a cycle in one table, inserted in one statement */
    OK(run("CREATE TABLE r (id INT64 PRIMARY KEY, nx INT64 REFERENCES r ON DELETE CASCADE)"));
    EXPECT("INSERT INTO r VALUES (1, 2), (2, 3), (3, 1)", "INSERT 3");
    EXPECT("DELETE FROM r WHERE id = 2", "DELETE 1");
    EXPECT("SELECT COUNT(*) FROM r", "count\n0\n");
    CHECK(verify_db(db) == 0);
    done(db);
    CHECK(audit_dir(dir) == 0);
    db = open_at(dir, true);
    CHECK(db);
    if (db) done(db);
}

/* ---- a parked transaction: its writes undone while another session commits, replayed at its COMMIT ---- */
static void t_fk_parked(void)
{
    const char *dir = test_tmpdir();
    imdb_db *db = open_fresh(dir);
    CHECK(db);
    if (!db) return;
    imdb_session a, b;
    imdb_session_init(&a, db);
    imdb_session_init(&b, db);
    EXPECT_IN(&a, "CREATE TABLE p (id INT64 PRIMARY KEY)", "CREATE TABLE p");
    EXPECT_IN(&a, "CREATE TABLE c (id INT64 PRIMARY KEY, pid INT64 REFERENCES p)", "CREATE TABLE c");
    EXPECT_IN(&a, "INSERT INTO p VALUES (1), (2), (3)", "INSERT 3");
    /* b's child waits parked; a deletes its parent and commits; b's COMMIT is the conflict */
    EXPECT_IN(&b, "BEGIN", "BEGIN");
    EXPECT_IN(&b, "INSERT INTO c VALUES (10, 1)", "INSERT 1");
    EXPECT_IN(&a, "DELETE FROM p WHERE id = 1", "DELETE 1");
    EXPECT_IN(&b, "COMMIT", "ERR could not serialize");
    EXPECT_IN(&a, "SELECT COUNT(*) FROM c", "count\n0\n");
    /* a's delete waits parked; b inserts a child of it and commits; a's COMMIT is the conflict */
    EXPECT_IN(&a, "BEGIN", "BEGIN");
    EXPECT_IN(&a, "DELETE FROM p WHERE id = 2", "DELETE 1");
    EXPECT_IN(&b, "INSERT INTO c VALUES (11, 2)", "INSERT 1");
    EXPECT_IN(&a, "COMMIT", "ERR could not serialize");
    EXPECT_IN(&b, "SELECT id, pid FROM c", "id,pid\n11,2\n");
    EXPECT_IN(&b, "SELECT COUNT(*) FROM p", "count\n2\n");
    imdb_session_close(&a);
    imdb_session_close(&b);
    CHECK(verify_db(db) == 0);
    done(db);
    CHECK(audit_dir(dir) == 0);
}

/* ---- ERASE SUBJECT runs no action and is never refused: a child keeps its erased parent's key, a new one is refused ---- */
static void t_fk_erase(void)
{
    const char *dir = test_tmpdir();
    imdb_db *db = open_fresh(dir);
    CHECK(db);
    if (!db) return;
    OK(run("CREATE TABLE p (id INT64 PRIMARY KEY, who INT64 SUBJECT)"));
    OK(run("CREATE TABLE c (id INT64 PRIMARY KEY, pid INT64 REFERENCES p ON DELETE CASCADE)"));
    OK(run("INSERT INTO p VALUES (1, 7), (2, 8)"));
    OK(run("INSERT INTO c VALUES (10, 1), (11, 2)"));
    OK(run("CHECKPOINT"));
    CHECK(!strncmp(csv_in(&g_s, "ERASE SUBJECT 7"), "ERASE 1 versions (1 were live)", 30));
    EXPECT("SELECT id, pid FROM c ORDER BY id", "id,pid\n10,1\n11,2\n");
    EXPECT("INSERT INTO c VALUES (12, 1)", "ERR violates foreign key constraint c_pid_fkey");
    EXPECT("DELETE FROM p WHERE id = 2", "DELETE 1");
    EXPECT("SELECT id FROM c ORDER BY id", "id\n10\n");
    CHECK(verify_db(db) == 0);
    done(db);
    CHECK(audit_dir(dir) == 0);
    db = open_at(dir, true); /* a full replay: the ERASE's ends are no parent's delete */
    CHECK(db);
    if (db) {
        imdb_table *pt = imdb_table_by_name(db, "p"); /* commit 4's child met a live erased parent: its key unknown */
        CHECK(pt && pt->live_stubs == 0); /* the ERASE ended it */
        EXPECT("SELECT id FROM c ORDER BY id", "id\n10\n");
        done(db);
    }
}


/* ---- the ERASE exemption is per version: only the deletes an ERASE op names (its own) end no parent key; a commit
 * carrying an ERASE of another version and a referenced parent's DELETE is refused by the commit's check and by
 * replay's (white-box: the ops as a forged commit would carry them; the auditor's side by its own fk_commit_check) ---- */
static void t_fk_erase_exempt(void)
{
    const char *dir = test_tmpdir();
    imdb_db *db = open_fresh(dir);
    CHECK(db);
    if (!db) return;
    OK(run("CREATE TABLE p (id INT64 PRIMARY KEY, who INT64 SUBJECT)"));
    OK(run("CREATE TABLE c (id INT64 PRIMARY KEY, pid INT64 REFERENCES p)"));
    OK(run("INSERT INTO p VALUES (1, 7), (2, 8)"));
    OK(run("INSERT INTO c VALUES (10, 1)"));
    imdb_table *p = imdb_table_by_name(db, "p");
    CHECK(p);
    if (!p) {
        done(db);
        return;
    }
    imdb_value k = {.type = IMDB_T_INT64, .i = 1};
    uint64_t v1 = imdb_lookup_pk(db, p, &k, imdb_read_snapshot(db));
    k.i = 2;
    uint64_t v2 = imdb_lookup_pk(db, p, &k, imdb_read_snapshot(db));
    CHECK(v1 != IMDB_NONE && v2 != IMDB_NONE);
    imdb_err e = {0};
    for (int own = 0; own < 2; own++) {
        OK(imdb_begin(db, &e));
        OK(imdb_delete(db, p, v1, &e)); /* parent key 1 ended (pending); child 10 references it */
        imdb_erase_ent *ents = imdb_alloc_array(1, sizeof *ents, &e);
        CHECK(ents);
        if (!ents) break;
        ents[0].table = p->s.id;
        ents[0].vid = own ? v1 : v2;
        uint8_t mh[32] = {0};
        OK(imdb_tx_add_erase(db, ents, 1, NULL, 0, mh, &e)); /* the transaction's op list owns it now */
        imdb_err_clear(&e);
        int rc = imdb_fk_check(db, 0, &e); /* the commit's check */
        CHECK(own ? rc == IMDB_OK : rc == IMDB_ERR_CONSTRAINT && strstr(e.msg, "c_pid_fkey"));
        imdb_commit_rec c; /* replay's, over the same ops */
        memset(&c, 0, sizeof c);
        c.ops = db->tx;
        c.nops = db->ntx;
        imdb_err_clear(&e);
        rc = imdb_fk_verify_commit(db, &c, db->seq + 1, &e);
        CHECK(own ? rc == IMDB_OK : rc == IMDB_ERR_CORRUPT && strstr(e.msg, "c_pid_fkey"));
        c.nops = 1; /* the DELETE alone: refused */
        imdb_err_clear(&e);
        CHECK(imdb_fk_verify_commit(db, &c, db->seq + 1, &e) == IMDB_ERR_CORRUPT);
        imdb_rollback(db);
    }
    EXPECT("SELECT COUNT(*) FROM p", "count\n2\n");
    done(db);
}
/* a dump's bytes */
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

/* a dump restored as imagedb sql -f restores it (t_copy.c's restore_text): each line a statement, a COPY's data the
 * lines up to a \. line outside quotes */
static int restore_text(const char *s, size_t n)
{
    static char line[1 << 14];
    size_t at = 0;
    while (at < n) {
        size_t eol = at;
        while (eol < n && s[eol] != '\n') eol++;
        size_t ll = eol - at;
        if (ll >= sizeof line) return -1;
        memcpy(line, s + at, ll);
        line[ll] = 0;
        at = eol < n ? eol + 1 : n;
        if (!ll || !strncmp(line, "--", 2)) continue;
        if (strncmp(line, "COPY ", 5)) {
            if (run(line)) return -1;
            continue;
        }
        size_t k = at;
        bool bol = true, inq = false;
        for (; k < n; k++) {
            if (bol && !inq && s[k] == '\\' && k + 1 < n && s[k + 1] == '.' && (k + 2 == n || s[k + 2] == '\n')) break;
            if (s[k] == '"') inq = !inq;
            bol = s[k] == '\n';
        }
        if (k >= n || strncmp(copy_in(line, s + at, k - at), "COPY ", 5)) return -1;
        at = k + 2 < n ? k + 3 : n;
    }
    return 0;
}

/* ---- the dump (each FK after every table's rows) restored and dumped again the same; a backup's restore ---- */
static void t_fk_dump(void)
{
    const char *dir = test_tmpdir();
    char p[700], kf[700], bk[700], dest[700], dd[700], bad_dir[700];
    snprintf(p, sizeof p, "%s/p", dir);
    snprintf(bad_dir, sizeof bad_dir, "%s/bad", dir);
    snprintf(kf, sizeof kf, "%s/key", dir);
    snprintf(bk, sizeof bk, "%s/full.bak", dir);
    snprintf(dest, sizeof dest, "%s/restored", dir);
    snprintf(dd, sizeof dd, "%s/dumped", dir);
    imdb_db *db = open_fresh(p);
    CHECK(db);
    if (!db) return;
    OK(run("CREATE TABLE c (id INT64 PRIMARY KEY, x TEXT, y INT64)")); /* the child made first: the dump's order is the id's */
    OK(run("CREATE TABLE pp (a INT64, b TEXT, PRIMARY KEY (a, b))"));
    OK(run("ALTER TABLE c ADD CONSTRAINT c_p FOREIGN KEY (x, y) REFERENCES pp (b, a) ON DELETE SET NULL"));
    OK(run("CREATE TABLE s (id INT64 PRIMARY KEY, up INT64 REFERENCES s ON DELETE CASCADE ON UPDATE RESTRICT)"));
    OK(run("INSERT INTO pp VALUES (1, 'x'), (2, 'y')"));
    OK(run("INSERT INTO c VALUES (10, 'x', 1), (11, 'y', 2), (12, NULL, 5)"));
    OK(run("INSERT INTO s VALUES (3, 2), (2, 1), (1, NULL)"));
    outb d1 = {0}, d2 = {0}, d3 = {0};
    imdb_err e = {0};
    OK(imdb_dump(db, 0, outb_write, &d1, &e));
    CHECK(d1.p && strstr(d1.p, "ALTER TABLE c ADD CONSTRAINT c_p FOREIGN KEY (y, x) REFERENCES pp (a, b) ON DELETE SET NULL;\n") &&
          strstr(d1.p, "ALTER TABLE s ADD CONSTRAINT s_up_fkey FOREIGN KEY (up) REFERENCES s (id) ON DELETE CASCADE;\n") &&
          strstr(d1.p, "ALTER TABLE c ADD CONSTRAINT") > strstr(d1.p, "COPY s FROM STDIN"));
    uint8_t dg[32];
    imdb_lthash_digest(db->meta.digest_alg, &db->global, dg);
    uint8_t kid[32], key[IMDB_BACKUP_KEY_LEN];
    imdb_backup_info bi;
    OK(imdb_backup_key_create(kf, kid, &g_e));
    OK(imdb_backup_key_load(kf, key, &g_e));
    OK(imdb_backup_full(p, bk, key, &bi, &g_e));
    done(db);
    const char *files[1] = {bk};
    imdb_backup_info ri;
    OK(imdb_restore(dest, key, files, 1, &ri, &g_e));
    db = open_at(dest, false); /* a restore is a replica of the backup's database: its digest, FKs and dump */
    CHECK(db);
    if (db) {
        uint8_t rd[32];
        imdb_lthash_digest(db->meta.digest_alg, &db->global, rd);
        CHECK(memcmp(rd, dg, 32) == 0);
        imdb_table *rc = imdb_table_by_name(db, "c"), *rs = imdb_table_by_name(db, "s");
        CHECK(rc && rc->hist.nfk == 1 && rc->hist.nfk0 == 0 && rs && rs->hist.nfk == 1 && rs->hist.nfk0 == 1 &&
              rs->hist.fk[0].on_update == IMDB_FK_RESTRICT);
        OK(imdb_dump(db, 0, outb_write, &d3, &e));
        CHECK(d1.p && d3.p && !strcmp(strchr(d1.p, '\n'), strchr(d3.p, '\n')));
        done(db);
    }
    CHECK(audit_dir(dest) == 0);
    db = open_fresh(dd); /* the dump run into a fresh database, then dumped again: the same text */
    CHECK(db);
    if (db && d1.p) {
        CHECK(restore_text(d1.p, d1.n) == 0);
        OK(imdb_dump(db, 0, outb_write, &d2, &e));
        CHECK(d2.p && !strcmp(strchr(d1.p, '\n'), strchr(d2.p, '\n')));
        EXPECT("INSERT INTO s VALUES (9, 8)", "ERR violates foreign key constraint s_up_fkey");
        CHECK(verify_db(db) == 0);
        done(db);
        CHECK(audit_dir(dd) == 0);
    } else if (db) {
        done(db);
    }
    /* a dump's restore whose rows break a key: the ALTER refuses it */
    db = open_fresh(bad_dir);
    CHECK(db);
    if (db) {
        static const char bad[] = "CREATE TABLE q (id INT64 PRIMARY KEY);\nCREATE TABLE r (id INT64 PRIMARY KEY, qid INT64);\n"
                                  "INSERT INTO r VALUES (1, 5);\nALTER TABLE r ADD CONSTRAINT r_q FOREIGN KEY (qid) REFERENCES q (id) "
                                  "ON DELETE NO ACTION;\n";
        CHECK(restore_text(bad, sizeof bad - 1) != 0);
        EXPECT("SELECT COUNT(*) FROM r", "count\n1\n");
        done(db);
    }
    free(d1.p);
    free(d2.p);
    free(d3.p);
}

/* 2026-03-08 06:59:58 UTC: the frozen clock (t_gen's) */
#define T0_US (1772953198ull * 1000000ull)

/* ---- past a cut: op 29 below it, F's manifest the FKs' one source: VERIFY from FLOOR, the auditor's floor seed, a
 * snapshot open and a replica seeded past the cut each hold the FK and refuse what it refuses ---- */
static void t_fk_cut(void)
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
    imdb_session_copy_io(&g_s, mem_read, mem_write, &g_in);
    db->no_auto_retire = true;
    imdb_clock_freeze(T0_US);
    OK(run("CREATE TABLE p (id INT64 PRIMARY KEY) RETENTION 10 SECONDS"));
    OK(run("CREATE TABLE c (id INT64 PRIMARY KEY, pid INT64 REFERENCES p ON DELETE CASCADE) RETENTION 10 SECONDS"));
    OK(run("INSERT INTO p VALUES (1), (2), (3)"));
    OK(run("INSERT INTO c VALUES (10, 1), (11, 2)"));
    OK(run("CHECKPOINT"));
    uint64_t first = db->seq + 1;
    OK(run("DELETE FROM p WHERE id = 2"));
    OK(run("ALTER TABLE c ADD CONSTRAINT c_again FOREIGN KEY (pid) REFERENCES p ON DELETE CASCADE"));
    OK(run("CHECKPOINT"));
    imdb_clock_offset(15 * 1000000ll);
    OK(run("SELECT COUNT(*) FROM c"));
    imdb_err_clear(&g_e);
    OK(imdb_retire(db, first - 1, &g_e));
    CHECK(db->log_floor > 0);
    EXPECT("INSERT INTO c VALUES (12, 9)", "ERR violates foreign key constraint c_again");
    EXPECT("INSERT INTO c VALUES (12, 3)", "INSERT 1");
    CHECK(verify_db(db) == 0); /* from FLOOR */
    done(db);
    CHECK(audit_dir(p) == 0);
    db = open_at(p, false); /* a snapshot open of a copy past its cut */
    CHECK(db);
    uint8_t dg[32] = {0};
    if (db) {
        imdb_table *t = imdb_table_by_name(db, "c");
        CHECK(t && t->hist.nfk == 2 && t->hist.nfk0 == 1);
        EXPECT("INSERT INTO c VALUES (13, 9)", "ERR violates foreign key constraint c_again");
        EXPECT("DELETE FROM p WHERE id = 3", "DELETE 1");
        EXPECT("SELECT id FROM c ORDER BY id", "id\n10\n");
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
        imdb_table *rt = imdb_table_by_name(rdb, "c");
        CHECK(rt && rt->hist.nfk == 2);
        imdb_close(rdb);
    }
    CHECK(audit_dir(r) == 0);
}
const test_case fk_tests[] = {
    {"fk_statements", t_fk_statements}, {"fk_api", t_fk_api}, {"fk_sessions", t_fk_sessions}, {"fk_copies", t_fk_copies},
    {"fk_paths", t_fk_paths},           {"fk_levels", t_fk_levels}, {"fk_parked", t_fk_parked},     {"fk_erase", t_fk_erase},
    {"fk_dump", t_fk_dump},             {"fk_cut", t_fk_cut},       {"fk_erase_exempt", t_fk_erase_exempt},
};
const size_t fk_ntests = sizeof fk_tests / sizeof *fk_tests;
