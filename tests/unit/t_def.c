/* F2a: clock values and column DEFAULTs (design.md section 5, Clock values and DEFAULTs; docs/plan-p2.md 2026-11-09
 * 14:2x). now(), CURRENT_TIMESTAMP, LOCALTIMESTAMP, CURRENT_DATE and LOCALTIME read the transaction's start (an
 * autocommit statement's own), PostgreSQL's rule, by the engine's clock, so a frozen clock makes every value exact.
 * A column's DEFAULT is a constant or a clock kind: CREATE TABLE logs its columns' (op 23, right after the CREATE and
 * its retention), ALTER TABLE's SET DEFAULT a clock (kind 10) and ADD COLUMN one (the rows before it read the clock's
 * value at the ALTER, a write the clock's at the write). Each against values it states, through a CHECKPOINT, a
 * snapshot open, a full replay, a replica, a seed past a RETIRE and a backup's restore, VERIFY and the auditor. */
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

/* 2026-03-08 06:59:58 UTC, two seconds before New York's clocks went from 02:00 EST to 03:00 EDT */
#define T0_US (1772953198ull * 1000000ull)

/* the constants: every type's DEFAULT (DEFAULT NULL none), written by INSERT and INSERT ... SELECT leaving the
 * columns out, a value given in their place, through a CHECKPOINT, a snapshot open and a full replay; the dump's
 * CREATE TABLE */
static void t_def_values(void)
{
    const char *dir = test_tmpdir();
    imdb_db *db = open_fresh(dir);
    CHECK(db);
    if (!db) return;
    OK(run("CREATE TABLE t (id INT64 PRIMARY KEY, a INT64 DEFAULT -7, sm SMALLINT DEFAULT 32767, ig INTEGER NOT NULL "
           "DEFAULT -2147483648, d DECIMAL(6,2) DEFAULT 12.5, s TEXT DEFAULT 'it''s', v VARCHAR(4) DEFAULT 'abcd', "
           "b BOOL DEFAULT FALSE, f FLOAT64 DEFAULT 0.25, ts TIMESTAMP DEFAULT '2001-02-03 04:05:06.5', "
           "tz TIMESTAMPTZ DEFAULT '2001-02-03 04:05:06+02', dd DATE DEFAULT DATE '0001-01-01', "
           "tm TIME DEFAULT TIME '23:59:59.999999', z TEXT DEFAULT NULL, nn INT64)"));
    imdb_table *t = imdb_table_by_name(db, "t");
    CHECK(t && t->hist.nvers == 1 && t->hist.tcol[1].cdef.i == -7 && !t->hist.tcol[13].cclock && t->hist.tcol[13].cdef.null);
    const char *row1 = "1,-7,32767,-2147483648,12.50,\"it's\",\"abcd\",false,0.25,2001-02-03 04:05:06.500000,"
                       "2001-02-03 02:05:06+00,0001-01-01,23:59:59.999999,,\n";
    char want[2048];
    OK(run("INSERT INTO t (id) VALUES (1)"));
    snprintf(want, sizeof want, "id,a,sm,ig,d,s,v,b,f,ts,tz,dd,tm,z,nn\n%s", row1);
    EXPECT("SELECT * FROM t", want);
    OK(run("INSERT INTO t (id, a, s, z) VALUES (2, NULL, 'x', 'y')")); /* a value given, NULL too, is the row's */
    OK(run("INSERT INTO t (id, nn) SELECT id + 10, id FROM t"));       /* INSERT ... SELECT leaves the rest out */
    EXPECT("SELECT id, a, s, z, nn, ig FROM t ORDER BY id",
           "id,a,s,z,nn,ig\n1,-7,\"it's\",,,-2147483648\n2,,\"x\",\"y\",,-2147483648\n11,-7,\"it's\",,1,-2147483648\n"
           "12,-7,\"it's\",,2,-2147483648\n");
    char *d0 = dump_body(db);
    CHECK(d0 && strstr(d0, "CREATE TABLE t (id INT64 PRIMARY KEY, a INT64 DEFAULT -7, sm SMALLINT DEFAULT 32767, "
                           "ig INTEGER NOT NULL DEFAULT -2147483648, d DECIMAL(6,2) DEFAULT 12.50, s TEXT DEFAULT 'it''s', "
                           "v VARCHAR(4) DEFAULT 'abcd', b BOOL DEFAULT false, f FLOAT64 DEFAULT 0.25, "
                           "ts TIMESTAMP DEFAULT '2001-02-03 04:05:06.500000', tz TIMESTAMPTZ DEFAULT '2001-02-03 02:05:06+00', "
                           "dd DATE DEFAULT '0001-01-01', tm TIME DEFAULT '23:59:59.999999', z TEXT, nn INT64) RETENTION"));
    OK(run("CHECKPOINT"));
    done(db);
    for (int pass = 0; pass < 2; pass++) { /* a snapshot open, then a full replay */
        db = open_at(dir, pass == 1);
        CHECK(db);
        if (!db) return;
        char ins[80];
        snprintf(ins, sizeof ins, "INSERT INTO t (id) VALUES (%d)", 20 + pass);
        OK(run(ins));
        char q[80];
        snprintf(q, sizeof q, "SELECT * FROM t WHERE id = %d", 20 + pass);
        snprintf(want, sizeof want, "id,a,sm,ig,d,s,v,b,f,ts,tz,dd,tm,z,nn\n%d%s", 20 + pass, row1 + 1);
        EXPECT(q, want);
        char *d1 = dump_body(db);
        const char *c0 = d0 ? strstr(d0, "CREATE TABLE") : NULL, *c1 = d1 ? strstr(d1, "CREATE TABLE") : NULL;
        CHECK(c0 && c1 && !strncmp(c0, c1, (size_t)(strchr(c0, '\n') - c0) + 1)); /* the same DEFAULTs */
        free(d1);
        CHECK(verify_db(db) == 0);
        done(db);
    }
    free(d0);
    CHECK(audit_dir(dir) == 0);
}

/* the clock values: one per transaction (its start), an autocommit statement's own, by the engine's clock (frozen,
 * so exact), the wall-clock kinds in the session's zone across New York's spring change, as functions and as
 * DEFAULTs; a view of now() is typed at CREATE VIEW and reads its clock at each run */
static void t_def_clock(void)
{
    const char *dir = test_tmpdir();
    imdb_db *db = open_fresh(dir);
    CHECK(db);
    if (!db) return;
    imdb_clock_freeze(T0_US);
    OK(run("CREATE TABLE c (id INT64 PRIMARY KEY, tz TIMESTAMPTZ DEFAULT now(), ct TIMESTAMP DEFAULT CURRENT_TIMESTAMP, "
           "lt TIMESTAMP DEFAULT LOCALTIMESTAMP, d DATE DEFAULT CURRENT_DATE, tm TIME NOT NULL DEFAULT LOCALTIME, "
           "x INT64)"));
    OK(run("CREATE VIEW vn AS SELECT now() AS n, CURRENT_DATE AS d"));
    EXPECT("SELECT now(), CURRENT_TIMESTAMP, LOCALTIMESTAMP, CURRENT_DATE, LOCALTIME",
           "now(),CURRENT_TIMESTAMP,LOCALTIMESTAMP,CURRENT_DATE,LOCALTIME\n2026-03-08 06:59:58+00,2026-03-08 06:59:58+00,"
           "2026-03-08 06:59:58,2026-03-08,06:59:58\n");
    OK(run("SET TIME ZONE 'America/New_York'"));
    EXPECT("SELECT LOCALTIMESTAMP, CURRENT_DATE, LOCALTIME, now()",
           "LOCALTIMESTAMP,CURRENT_DATE,LOCALTIME,now()\n2026-03-08 01:59:58,2026-03-08,01:59:58,2026-03-08 01:59:58-05\n");
    OK(run("INSERT INTO c (id) VALUES (1)"));
    imdb_clock_offset(2000000); /* 07:00:00 UTC: 03:00:00 EDT */
    OK(run("INSERT INTO c (id) VALUES (2)"));
    EXPECT("SELECT * FROM vn", "n,d\n2026-03-08 03:00:00-04,2026-03-08\n");
    imdb_clock_offset(12000000);
    OK(run("BEGIN"));
    OK(run("INSERT INTO c (id) VALUES (3)"));
    imdb_clock_offset(3612000000ll); /* an hour later, inside the transaction: its values stay its start's */
    OK(run("INSERT INTO c (id, x) VALUES (4, 1)"));
    EXPECT("SELECT now(), LOCALTIME", "now(),LOCALTIME\n2026-03-08 03:00:10-04,03:00:10\n");
    EXPECT("SELECT * FROM vn", "n,d\n2026-03-08 03:00:10-04,2026-03-08\n");
    OK(run("COMMIT"));
    OK(run("INSERT INTO c (id) VALUES (5)"));
    const char *want = "id,tz,ct,lt,d,tm,x\n"
                       "1,2026-03-08 01:59:58-05,2026-03-08 01:59:58,2026-03-08 01:59:58,2026-03-08,01:59:58,\n"
                       "2,2026-03-08 03:00:00-04,2026-03-08 03:00:00,2026-03-08 03:00:00,2026-03-08,03:00:00,\n"
                       "3,2026-03-08 03:00:10-04,2026-03-08 03:00:10,2026-03-08 03:00:10,2026-03-08,03:00:10,\n"
                       "4,2026-03-08 03:00:10-04,2026-03-08 03:00:10,2026-03-08 03:00:10,2026-03-08,03:00:10,1\n"
                       "5,2026-03-08 04:00:10-04,2026-03-08 04:00:10,2026-03-08 04:00:10,2026-03-08,04:00:10,\n";
    EXPECT("SELECT * FROM c ORDER BY id", want);
    OK(run("SET TIME ZONE 'UTC'")); /* the instants stay; the wall clocks written are what they were */
    EXPECT("SELECT id, tz, lt FROM c WHERE id IN (1, 5) ORDER BY id",
           "id,tz,lt\n1,2026-03-08 06:59:58+00,2026-03-08 01:59:58\n5,2026-03-08 08:00:10+00,2026-03-08 04:00:10\n");
    imdb_clock_offset(18 * 3600000000ll); /* 2026-03-09 00:59:58 UTC: the 8th still in New York */
    OK(run("SET TIME ZONE 'America/New_York'"));
    OK(run("INSERT INTO c (id) VALUES (6)"));
    OK(run("SET TIME ZONE 'UTC'"));
    OK(run("INSERT INTO c (id) VALUES (7)"));
    EXPECT("SELECT id, d, tm FROM c WHERE id >= 6 ORDER BY id", "id,d,tm\n6,2026-03-08,20:59:58\n7,2026-03-09,00:59:58\n");
    EXPECT("SELECT CURRENT_TIME", "ERR CURRENT_TIME is a time with a zone");
    EXPECT("SELECT now(1)", "ERR ");
    OK(run("CHECKPOINT"));
    CHECK(verify_db(db) == 0);
    done(db);
    db = open_at(dir, true); /* replay writes nothing of its own: the rows hold their values */
    CHECK(db);
    if (!db) return;
    OK(run("SET TIME ZONE 'America/New_York'"));
    EXPECT("SELECT * FROM c WHERE id <= 5 ORDER BY id", want);
    CHECK(verify_db(db) == 0);
    done(db);
    CHECK(audit_dir(dir) == 0);
}

/* ALTER TABLE's clock forms: ADD COLUMN ... DEFAULT now() (the rows before it read the ALTER's instant, a write its
 * own), SET DEFAULT a clock on a column with a constant and back, DROP DEFAULT of a clock, through a CHECKPOINT, a
 * snapshot open and a full replay; the dump spells each */
static void t_def_alter(void)
{
    const char *dir = test_tmpdir();
    imdb_db *db = open_fresh(dir);
    CHECK(db);
    if (!db) return;
    imdb_clock_freeze(T0_US);
    OK(run("CREATE TABLE t (id INT64 PRIMARY KEY, ts TIMESTAMP DEFAULT '2000-01-01 00:00:00', d DATE)"));
    OK(run("INSERT INTO t (id) VALUES (1), (2)"));
    imdb_clock_offset(1000000);
    OK(run("ALTER TABLE t ADD COLUMN at TIMESTAMPTZ NOT NULL DEFAULT now()"));
    OK(run("ALTER TABLE t ADD COLUMN ad DATE DEFAULT CURRENT_DATE"));
    imdb_table *t = imdb_table_by_name(db, "t");
    CHECK(t && t->hist.nvers == 3 && t->hist.vers[1].aclock == IMDB_DEFK_CURRENT_TIMESTAMP &&
          t->hist.tcol[3].wclock == IMDB_DEFK_CURRENT_TIMESTAMP && !t->hist.tcol[3].missing.null &&
          t->hist.tcol[3].missing.i == (int64_t)(T0_US + 1000000));
    imdb_clock_offset(5000000);
    OK(run("INSERT INTO t (id) VALUES (3)"));
    OK(run("ALTER TABLE t ALTER COLUMN ts SET DEFAULT LOCALTIMESTAMP")); /* a constant, then a clock */
    OK(run("ALTER TABLE t ALTER COLUMN d SET DEFAULT CURRENT_DATE"));
    imdb_clock_offset(9000000);
    OK(run("INSERT INTO t (id) VALUES (4)"));
    OK(run("ALTER TABLE t ALTER COLUMN d SET DEFAULT '1999-12-31'")); /* a clock, then a constant */
    OK(run("ALTER TABLE t ALTER COLUMN ad DROP DEFAULT"));
    EXPECT("ALTER TABLE t ALTER COLUMN ad DROP DEFAULT", "ERR column ad has no DEFAULT");
    OK(run("INSERT INTO t (id) VALUES (5)"));
    const char *want = "id,ts,d,at,ad\n"
                       "1,2000-01-01 00:00:00,,2026-03-08 06:59:59+00,2026-03-08\n"
                       "2,2000-01-01 00:00:00,,2026-03-08 06:59:59+00,2026-03-08\n"
                       "3,2000-01-01 00:00:00,,2026-03-08 07:00:03+00,2026-03-08\n"
                       "4,2026-03-08 07:00:07,2026-03-08,2026-03-08 07:00:07+00,2026-03-08\n"
                       "5,2026-03-08 07:00:07,1999-12-31,2026-03-08 07:00:07+00,\n";
    EXPECT("SELECT * FROM t ORDER BY id", want);
    char *d0 = dump_body(db);
    CHECK(d0 && strstr(d0, "CREATE TABLE t (id INT64 PRIMARY KEY, ts TIMESTAMP DEFAULT LOCALTIMESTAMP, d DATE DEFAULT "
                           "'1999-12-31', at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP, ad DATE) RETENTION"));
    free(d0);
    OK(run("CHECKPOINT"));
    done(db);
    for (int pass = 0; pass < 2; pass++) {
        db = open_at(dir, pass == 1);
        CHECK(db);
        if (!db) return;
        EXPECT("SELECT * FROM t WHERE id <= 5 ORDER BY id", want);
        imdb_clock_offset(20000000 + pass * 1000000);
        char ins[80], q[96], w[160];
        snprintf(ins, sizeof ins, "INSERT INTO t (id) VALUES (%d)", 10 + pass);
        OK(run(ins));
        snprintf(q, sizeof q, "SELECT * FROM t WHERE id = %d", 10 + pass);
        snprintf(w, sizeof w, "id,ts,d,at,ad\n%d,2026-03-08 07:00:%02d,1999-12-31,2026-03-08 07:00:%02d+00,\n", 10 + pass,
                 18 + pass, 18 + pass);
        EXPECT(q, w);
        CHECK(verify_db(db) == 0);
        done(db);
    }
    CHECK(audit_dir(dir) == 0);
}

/* the rules: a DEFAULT of the column's type (its range, its length), a clock its type takes, one DEFAULT, no
 * CURRENT_TIME nor a precision; nothing made by a refused statement */
static void t_def_rules(void)
{
    const char *dir = test_tmpdir();
    imdb_db *db = open_fresh(dir);
    CHECK(db);
    if (!db) return;
    static const struct {
        const char *sql, *err;
    } bad[] = {
        {"CREATE TABLE r (id INT64 PRIMARY KEY, n INT64 DEFAULT 'x')", "ERR "},
        {"CREATE TABLE r (id INT64 PRIMARY KEY, n SMALLINT DEFAULT 32768)", "ERR "},
        {"CREATE TABLE r (id INT64 PRIMARY KEY, v VARCHAR(2) DEFAULT 'abc')", "ERR "},
        {"CREATE TABLE r (id INT64 PRIMARY KEY, d DECIMAL(4,2) DEFAULT 123.45)", "ERR "},
        {"CREATE TABLE r (id INT64 PRIMARY KEY, t TIME DEFAULT '24:00:00')", "ERR "},
        {"CREATE TABLE r (id INT64 PRIMARY KEY, t TIMESTAMP DEFAULT CURRENT_DATE)", "ERR its DEFAULT's clock value is not of its type"},
        {"CREATE TABLE r (id INT64 PRIMARY KEY, t TIMESTAMPTZ DEFAULT LOCALTIMESTAMP)", "ERR its DEFAULT's clock value is not of its type"},
        {"CREATE TABLE r (id INT64 PRIMARY KEY, t DATE DEFAULT LOCALTIME)", "ERR its DEFAULT's clock value is not of its type"},
        {"CREATE TABLE r (id INT64 PRIMARY KEY, t TEXT DEFAULT now())", "ERR its DEFAULT's clock value is not of its type"},
        {"CREATE TABLE r (id INT64 PRIMARY KEY, t TIME DEFAULT CURRENT_TIME)", "ERR CURRENT_TIME is a time with a zone"},
        {"CREATE TABLE r (id INT64 PRIMARY KEY, t TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP(3))", "ERR a clock value's precision"},
        {"CREATE TABLE r (id INT64 PRIMARY KEY, n INT64 DEFAULT 1 DEFAULT 2)", "ERR one DEFAULT"},
        {"CREATE TABLE r (id INT64 PRIMARY KEY, t TIMESTAMPTZ DEFAULT now)", "ERR "},
        {"CREATE TABLE r (id INT64 PRIMARY KEY, n INT64 DEFAULT 1 + 1)", "ERR "},
    };
    for (size_t i = 0; i < sizeof bad / sizeof *bad; i++) {
        EXPECT(bad[i].sql, bad[i].err);
        CHECK(!imdb_table_by_name(db, "r"));
    }
    OK(run("CREATE TABLE t (id INT64 PRIMARY KEY, a TIME, b TEXT, k INT64 NOT NULL)"));
    EXPECT("ALTER TABLE t ALTER COLUMN a SET DEFAULT CURRENT_DATE", "ERR its DEFAULT's clock value is not of its type");
    EXPECT("ALTER TABLE t ALTER COLUMN b SET DEFAULT now()", "ERR its DEFAULT's clock value is not of its type");
    EXPECT("ALTER TABLE t ADD COLUMN c DATE DEFAULT LOCALTIME", "ERR its DEFAULT's clock value is not of its type");
    EXPECT("ALTER TABLE t ALTER COLUMN a SET DEFAULT NULL", "ERR write DROP DEFAULT");
    EXPECT("ALTER TABLE t ALTER COLUMN a DROP DEFAULT", "ERR column a has no DEFAULT");
    imdb_table *t = imdb_table_by_name(db, "t");
    CHECK(t && t->hist.nvers == 1);
    EXPECT("INSERT INTO t (id) VALUES (1)", "ERR column k needs a value: it is NOT NULL");
    OK(run("CREATE TABLE p (k INT64 PRIMARY KEY DEFAULT 1, a TIME DEFAULT LOCALTIME)")); /* a key's DEFAULT too */
    EXPECT("INSERT INTO p (a) VALUES (NULL)", "INSERT 1");
    EXPECT("INSERT INTO p (a) VALUES (NULL)", "ERR ");
    EXPECT("SELECT k, a FROM p", "k,a\n1,\n");
    CHECK(verify_db(db) == 0);
    done(db);
    CHECK(audit_dir(dir) == 0);
}

/* every copy holds the DEFAULTs: a replica by the stream, one seeded past a RETIRE whose cut drops the CREATE's commit
 * (FLOOR's manifest: version 1's DEFAULTs), a backup's restore; each dumps as the primary, at its digest */
static void t_def_copies(void)
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
    imdb_clock_freeze(T0_US);
    OK(run("CREATE TABLE t (id INT64 PRIMARY KEY, s TEXT NOT NULL DEFAULT 'dflt', at TIMESTAMPTZ DEFAULT now(), "
           "n INT64) RETENTION 10 SECONDS"));
    OK(run("INSERT INTO t (id) VALUES (1), (2)"));
    OK(run("ALTER TABLE t ADD COLUMN d DATE DEFAULT CURRENT_DATE"));
    OK(run("ALTER TABLE t ALTER COLUMN n SET DEFAULT 5"));
    /* a replica by the stream from commit 0, kept up through the cut's boundary (the log below it leaves) */
    uint64_t qseq = 0;
    OK(run("CHECKPOINT"));
    uint64_t first = db->seq + 1;
    OK(run("UPDATE t SET n = 9 WHERE id = 2"));
    OK(run("CHECKPOINT"));
    OK(ship_to_file(p, qseq, sf, &g_e));
    imdb_db *qdb = NULL;
    CHECK(imdb_open(q, &o, &qdb, &e) == 0);
    if (qdb) {
        uint64_t qa = 0;
        OK(apply_file(qdb, sf, &qa, &g_e));
        qseq = qdb->seq;
        imdb_close(qdb);
    }
    CHECK(qseq == db->seq);
    imdb_clock_offset(15 * 1000000ll);
    OK(run("SELECT COUNT(*) FROM t")); /* the policy moves the horizon past the second CHECKPOINT */
    imdb_err_clear(&g_e);
    OK(imdb_retire(db, first - 1, &g_e));
    OK(run("INSERT INTO t (id) VALUES (3)"));
    const char *want = "id,s,at,n,d\n1,\"dflt\",2026-03-08 06:59:58+00,,2026-03-08\n"
                       "2,\"dflt\",2026-03-08 06:59:58+00,9,2026-03-08\n3,\"dflt\",2026-03-08 07:00:13+00,5,2026-03-08\n";
    EXPECT("SELECT * FROM t ORDER BY id", want);
    uint8_t kid[32], key[IMDB_BACKUP_KEY_LEN];
    imdb_backup_info bi;
    OK(imdb_backup_key_create(kf, kid, &g_e));
    OK(imdb_backup_key_load(kf, key, &g_e));
    OK(imdb_backup_full(p, bk, key, &bi, &g_e));
    uint8_t dg[32];
    imdb_lthash_digest(db->meta.digest_alg, &db->global, dg);
    char *pd = dump_body(db);
    CHECK(pd && strstr(pd, "s TEXT NOT NULL DEFAULT 'dflt', at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP, n INT64 DEFAULT 5, "
                           "d DATE DEFAULT CURRENT_DATE) RETENTION 10 SECONDS"));
    CHECK(verify_db(db) == 0);
    done(db);
    CHECK(audit_dir(p) == 0);
    /* the stream's replica catches up past the cut; r is seeded past it: FLOOR's head and the snapshot's history */
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
        imdb_table *ct = imdb_table_by_name(c, "t");
        CHECK(ct && ct->hist.tcol[1].cdef.len == 4 && ct->hist.tcol[2].cclock == IMDB_DEFK_CURRENT_TIMESTAMP &&
              ct->hist.tcol[4].wclock == IMDB_DEFK_CURRENT_DATE);
        char *cdump = dump_body(c);
        CHECK(pd && cdump && !strcmp(pd, cdump));
        free(cdump);
        CHECK(verify_db(c) == 0);
        imdb_close(c);
        CHECK(audit_dir(dirs[k]) == 0);
    }
    free(pd);
}

/* op 23's codec: a round trip, the encoder's placement and validity rules, and every byte of its encoding changed:
 * refused, or another commit that encodes to exactly those bytes (strict: one encoding); ALTER kind 10 and an ADD's
 * clock form through imdb_alter_put and imdb_alter_get; a manifest of version 8 refused by name */
static void t_def_codec(void)
{
    imdb_schema s;
    memset(&s, 0, sizeof s);
    snprintf(s.name, sizeof s.name, "t");
    s.id = 0;
    s.ncols = 4;
    s.subject = -1;
    const char *nm[4] = {"id", "s", "at", "d"};
    const uint8_t ty[4] = {IMDB_T_INT64, IMDB_T_TEXT, IMDB_T_TIMESTAMPTZ, IMDB_T_DATE};
    for (int c = 0; c < 4; c++) {
        snprintf(s.cols[c].name, sizeof s.cols[c].name, "%s", nm[c]);
        s.cols[c].type = ty[c];
        s.cols[c].flags = c ? IMDB_COL_NULLABLE : IMDB_COL_PK;
    }
    s.npk = 1;
    imdb_coldef cd[3] = {{.col = 1, .kind = IMDB_DEFK_VALUE, .v = {.type = IMDB_T_TEXT, .s = (const uint8_t *)"ab", .len = 2}},
                         {.col = 2, .kind = IMDB_DEFK_CURRENT_TIMESTAMP},
                         {.col = 3, .kind = IMDB_DEFK_CURRENT_DATE}};
    imdb_op ops[3] = {{.code = IMDB_OP_CREATE_TABLE, .table = 0, .schema = &s},
                      {.code = IMDB_OP_SET_RETENTION, .table = 0, .retention_us = IMDB_RETAIN_DEFAULT_US},
                      {.code = IMDB_OP_COLUMN_DEFAULTS, .table = 0, .defs = cd, .ndefs = 3}};
    imdb_commit_rec c = {.seq = 1, .alg = IMDB_DIGEST_ALG_LTHASH16, .ops = ops, .nops = 3};
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
    CHECK(d.nops == 3 && d.ops[2].code == IMDB_OP_COLUMN_DEFAULTS && d.ops[2].ndefs == 3 && d.ops[2].defs[0].col == 1 &&
          d.ops[2].defs[0].v.len == 2 && !memcmp(d.ops[2].defs[0].v.s, "ab", 2) &&
          d.ops[2].defs[1].kind == IMDB_DEFK_CURRENT_TIMESTAMP && d.ops[2].defs[2].kind == IMDB_DEFK_CURRENT_DATE);
    imdb_commit_free(&d);
    /* op 23's bytes: from where the two-op commit's ops end to the digest */
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
    /* the encoder: op 23 right after its CREATE and its retention, each DEFAULT valid, its columns in order */
    imdb_coldef wrong[2] = {{.col = 2, .kind = IMDB_DEFK_LOCALTIME}, {.col = 1, .kind = IMDB_DEFK_VALUE}};
    imdb_coldef nullv = {.col = 1, .kind = IMDB_DEFK_VALUE, .v = {.type = IMDB_T_TEXT, .null = true}};
    imdb_coldef order[2] = {{.col = 3, .kind = IMDB_DEFK_CURRENT_DATE}, {.col = 2, .kind = IMDB_DEFK_CURRENT_TIMESTAMP}};
    imdb_coldef intv = {.col = 1, .kind = IMDB_DEFK_VALUE, .v = {.type = IMDB_T_INT64, .i = 1}};
    imdb_op alone = {.code = IMDB_OP_COLUMN_DEFAULTS, .table = 0, .defs = cd, .ndefs = 1};
    struct {
        imdb_op ops[3];
        uint32_t n;
    } cases[] = {
        {{alone}, 1},
        {{ops[0], alone, ops[1]}, 3},
        {{ops[0], ops[1], {.code = IMDB_OP_COLUMN_DEFAULTS, .table = 0, .defs = wrong, .ndefs = 1}}, 3},
        {{ops[0], ops[1], {.code = IMDB_OP_COLUMN_DEFAULTS, .table = 0, .defs = &nullv, .ndefs = 1}}, 3},
        {{ops[0], ops[1], {.code = IMDB_OP_COLUMN_DEFAULTS, .table = 0, .defs = order, .ndefs = 2}}, 3},
        {{ops[0], ops[1], {.code = IMDB_OP_COLUMN_DEFAULTS, .table = 0, .defs = &intv, .ndefs = 1}}, 3},
        {{ops[0], ops[1], {.code = IMDB_OP_COLUMN_DEFAULTS, .table = 0, .defs = cd, .ndefs = 0}}, 3},
        {{ops[0], ops[1], {.code = IMDB_OP_COLUMN_DEFAULTS, .table = 1, .defs = cd, .ndefs = 1}}, 3},
    };
    for (size_t i = 0; i < sizeof cases / sizeof *cases; i++) {
        imdb_commit_rec cc = {.seq = 1, .alg = IMDB_DIGEST_ALG_LTHASH16, .ops = cases[i].ops, .nops = cases[i].n};
        imdb_buf eb;
        imdb_buf_init(&eb);
        imdb_commit_encode_header(&cc, &eb);
        CHECK(eb.err != 0);
        imdb_buf_free(&eb);
    }
    /* op 22: kind 10 and an ADD's clock DEFAULT (its value, the clock's at the ALTER, for the rows before it) */
    imdb_op k10 = {.akind = IMDB_ALTER_SET_DEFAULT_CLOCK, .apos = 3, .aclock = IMDB_DEFK_LOCALTIME};
    imdb_op add = {.akind = IMDB_ALTER_ADD_COLUMN, .aclock = IMDB_DEFK_CURRENT_DATE,
                   .adef = {.type = IMDB_T_DATE, .i = 20520}};
    snprintf(add.acol.name, sizeof add.acol.name, "e");
    add.acol.type = IMDB_T_DATE;
    add.acol.flags = IMDB_COL_NULLABLE;
    imdb_op *alt[2] = {&k10, &add};
    for (int k = 0; k < 2; k++) {
        imdb_buf ab;
        imdb_buf_init(&ab);
        OK(imdb_alter_put(&ab, alt[k]));
        OK(imdb_buf_check(&ab, E));
        imdb_rd rd;
        imdb_rd_init(&rd, ab.p, ab.len);
        imdb_op g;
        memset(&g, 0, sizeof g);
        OK(imdb_alter_get(&rd, &g, "test", E));
        CHECK(!rd.err && !imdb_rd_left(&rd) && g.akind == alt[k]->akind && g.aclock == alt[k]->aclock);
        if (k == 1) CHECK(!g.adef.null && g.adef.i == 20520 && g.acol.type == IMDB_T_DATE);
        imdb_free(g.aname);
        imdb_buf_free(&ab);
    }
    imdb_op badk = {.akind = IMDB_ALTER_SET_DEFAULT_CLOCK, .apos = 1, .aclock = IMDB_DEFK_VALUE};
    imdb_op badadd = add;
    badadd.aclock = IMDB_DEFK_LOCALTIME; /* a TIME's clock for a DATE column */
    imdb_buf xb;
    imdb_buf_init(&xb);
    CHECK(imdb_alter_put(&xb, &badk) != 0);
    imdb_buf_free(&xb);
    imdb_buf_init(&xb);
    CHECK(imdb_alter_put(&xb, &badadd) != 0);
    imdb_buf_free(&xb);
    /* a manifest of version 8 (before a CREATE's DEFAULTs): refused by name */
    const char *dir = test_tmpdir();
    imdb_db *db = open_fresh(dir);
    CHECK(db);
    if (!db) return;
    OK(run("CREATE TABLE t (id INT64 PRIMARY KEY, n INT64 DEFAULT 1)"));
    OK(run("CHECKPOINT"));
    imdb_buf mb;
    imdb_buf_init(&mb);
    uint8_t mh[32];
    memcpy(mh, db->lake_manifest, 32);
    char hex[65], path[900];
    imdb_hex(mh, 32, hex);
    snprintf(path, sizeof path, "%s/objects/%s.man", dir, hex);
    done(db);
    FILE *f = fopen(path, "rb");
    CHECK(f);
    if (!f) return;
    static uint8_t man[1 << 16];
    size_t mn = fread(man, 1, sizeof man, f);
    fclose(f);
    imdb_manifest m;
    CHECK(mn > 16 && imdb_manifest_parse(man, mn, &m, E) == 0);
    imdb_manifest_free(&m);
    man[8] = 8;
    imdb_err_clear(E);
    CHECK(imdb_manifest_parse(man, mn, &m, E) == IMDB_ERR_UNSUPPORTED && strstr(g_e.msg, "manifest version 8") &&
          strstr(g_e.msg, "DEFAULTs"));
    imdb_buf_free(&mb);
}

const test_case def_tests[] = {
    {"def_values", t_def_values}, {"def_clock", t_def_clock}, {"def_alter", t_def_alter},
    {"def_rules", t_def_rules},   {"def_copies", t_def_copies}, {"def_codec", t_def_codec},
};
const size_t def_ntests = sizeof def_tests / sizeof *def_tests;
