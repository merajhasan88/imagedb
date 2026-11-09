/* F3a: SMALLINT and INTEGER as checked INT64 (docs/format-design-v7.md section 5; docs/plan-p2.md 2026-11-08 22:3x).
 * An INT64 column's precision is its width (16, 32, or 0 for INT64 and BIGINT, each spelled one way); its values are
 * INT64 in every expression, its range checked at every write and decode, a CAST to it refused past it, and a widening
 * SET TYPE's metadata change. Each answer checked against the rule, through a reopen, a full replay, a replica, VERIFY
 * and the auditor. */
#include <stdlib.h>

#include "../../src/codec.h"
#include "../../src/db_internal.h"
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

/* the spellings, the schema's encoding, SHOW TABLES and the refusals of a width an INT64 does not take */
static void t_intw_types(void)
{
    imdb_column c;
    memset(&c, 0, sizeof c);
    c.type = IMDB_T_INT64;
    for (unsigned w = 0; w < 256; w++) {
        c.precision = (uint8_t)w;
        CHECK(imdb_int_width_ok(c.precision) == (w == 0 || w == 16 || w == 32));
    }
    CHECK(imdb_int_fits(16, 32767) && imdb_int_fits(16, -32768) && !imdb_int_fits(16, 32768) && !imdb_int_fits(16, -32769));
    CHECK(imdb_int_fits(32, INT32_MAX) && imdb_int_fits(32, INT32_MIN) && !imdb_int_fits(32, (int64_t)INT32_MAX + 1) &&
          !imdb_int_fits(32, (int64_t)INT32_MIN - 1));
    CHECK(imdb_int_fits(0, INT64_MAX) && imdb_int_fits(0, INT64_MIN));
    const char *dir = test_tmpdir();
    imdb_err e = {0};
    CHECK(imdb_init(dir, false, NULL, &e) == 0);
    imdb_db *db = open_at(dir, false);
    CHECK(db);
    if (!db) return;
    OK(run("CREATE TABLE t (id SMALLINT PRIMARY KEY, a INT2, b INTEGER, c INT, d INT4, e BIGINT, f INT8, g INT64)"));
    imdb_table *t = imdb_table_by_name(db, "t");
    static const uint8_t want[] = {16, 16, 32, 32, 32, 0, 0, 0};
    for (int k = 0; t && k < 8; k++) CHECK(t->s.cols[k].type == IMDB_T_INT64 && t->s.cols[k].precision == want[k]);
    EXPECT("SHOW TABLES", "table,columns,live_rows,versions,segments,history_from,dropped_at\n\"t\",\"id SMALLINT PK, a "
                          "SMALLINT, b INTEGER, c INTEGER, d INTEGER, e INT64, f INT64, g INT64\",0,0,0,0,\n");
    imdb_schema s = t->s; /* a width INT64 does not take, refused by the schema's check */
    s.cols[1].precision = 64;
    CHECK(imdb_schema_check(&s, &e) != 0);
    s.cols[1].precision = 8;
    CHECK(imdb_schema_check(&s, &e) != 0);
    s.cols[1].precision = 16;
    s.cols[1].scale = 1;
    CHECK(imdb_schema_check(&s, &e) != 0);
    done(db);
}

/* every write path checks the width: INSERT, UPDATE (also by arithmetic), INSERT ... SELECT, ON CONFLICT, COPY, a
 * DEFAULT; an expression's values are INT64 (a SMALLINT sum past 32767 is a value); a comparison takes any literal */
static void t_intw_writes(void)
{
    const char *dir = test_tmpdir();
    imdb_err e = {0};
    CHECK(imdb_init(dir, false, NULL, &e) == 0);
    imdb_db *db = open_at(dir, false);
    CHECK(db);
    if (!db) return;
    OK(run("CREATE TABLE t (id INT64 PRIMARY KEY, s SMALLINT, i INTEGER)"));
    EXPECT("INSERT INTO t VALUES (1, 32767, 2147483647), (2, -32768, -2147483648)", "INSERT 2");
    EXPECT("INSERT INTO t VALUES (3, 32768, 0)", "ERR column s: a value out of SMALLINT's range");
    EXPECT("INSERT INTO t VALUES (3, 0, 2147483648)", "ERR column i: a value out of INTEGER's range");
    EXPECT("INSERT INTO t VALUES (3, -32769, 0)", "ERR SMALLINT");
    EXPECT("SELECT s + 1, i + 1, s * s FROM t WHERE id = 1", "s + 1,i + 1,s * s\n32768,2147483648,1073676289\n");
    EXPECT("SELECT SUM(s), SUM(i) FROM t", "sum_s,sum_i\n-1,-1\n");
    EXPECT("UPDATE t SET s = s + 1 WHERE id = 1", "ERR SMALLINT");
    EXPECT("UPDATE t SET s = s - 1, i = i - 1 WHERE id = 1", "UPDATE 1");
    EXPECT("SELECT id FROM t WHERE s = 100000", "id\n"); /* a comparison, never a refusal */
    EXPECT("SELECT id FROM t WHERE s < 40000 ORDER BY id", "id\n1\n2\n");
    EXPECT("SELECT id FROM t WHERE i > -3000000000 ORDER BY id", "id\n1\n2\n");
    OK(run("CREATE TABLE u (id INT64 PRIMARY KEY, v INT64)"));
    OK(run("INSERT INTO u VALUES (10, 7), (11, 40000)"));
    EXPECT("INSERT INTO t (id, s, i) SELECT id, v, v FROM u", "ERR SMALLINT");
    EXPECT("SELECT COUNT(*) FROM t", "count\n2\n"); /* the statement refused whole */
    EXPECT("INSERT INTO t (id, s, i) SELECT id, v, v FROM u WHERE v < 100", "INSERT 1");
    EXPECT("INSERT INTO t VALUES (10, 1, 1) ON CONFLICT (id) DO UPDATE SET s = EXCLUDED.s + 40000", "ERR SMALLINT");
    EXPECT("INSERT INTO t VALUES (10, 1, 1) ON CONFLICT (id) DO UPDATE SET s = EXCLUDED.s + 4", "INSERT 1");
    EXPECT("SELECT s FROM t WHERE id = 10", "s\n5\n");
    OK(run("ALTER TABLE t ADD k SMALLINT DEFAULT 40"));
    EXPECT("ALTER TABLE t ADD k2 SMALLINT DEFAULT 40000", "ERR ");
    EXPECT("ALTER TABLE t ALTER COLUMN k SET DEFAULT 99999", "ERR ");
    OK(run("INSERT INTO t (id) VALUES (20)"));
    EXPECT("SELECT s, i, k FROM t WHERE id = 20", "s,i,k\n,,40\n");
    done(db);
}

/* CAST to a width: PostgreSQL's refusal past it, from every source type, at bind and at run */
static void t_intw_cast(void)
{
    const char *dir = test_tmpdir();
    imdb_err e = {0};
    CHECK(imdb_init(dir, false, NULL, &e) == 0);
    imdb_db *db = open_at(dir, false);
    CHECK(db);
    if (!db) return;
    EXPECT("SELECT CAST(32767 AS SMALLINT), CAST(-2147483648 AS INTEGER), CAST(2147483648 AS BIGINT)",
           "CAST(32767 AS SMALLINT),CAST(-2147483648 AS INTEGER),CAST(2147483648 AS BIGINT)\n32767,-2147483648,2147483648\n");
    EXPECT("SELECT CAST(32768 AS SMALLINT)", "ERR CAST: the value exceeds SMALLINT");
    EXPECT("SELECT CAST(2147483648 AS INT)", "ERR CAST: the value exceeds INTEGER");
    EXPECT("SELECT CAST('40000' AS INT2)", "ERR CAST: the value exceeds SMALLINT");
    EXPECT("SELECT CAST('-40000' AS INTEGER) AS c", "c\n-40000\n");
    EXPECT("SELECT CAST(32767.0 AS SMALLINT) AS a, CAST(1.5e4 AS SMALLINT) AS b", "a,b\n32767,15000\n");
    EXPECT("SELECT CAST(3.0e4 * 2 AS SMALLINT)", "ERR SMALLINT");
    OK(run("CREATE TABLE t (id INT64 PRIMARY KEY, v INT64)"));
    OK(run("INSERT INTO t VALUES (1, 30000), (2, 40000)"));
    EXPECT("SELECT CAST(v AS SMALLINT) AS c FROM t WHERE id = 1", "c\n30000\n");
    EXPECT("SELECT CAST(v AS SMALLINT) FROM t ORDER BY id", "ERR CAST: the value exceeds SMALLINT");
    done(db);
}

/* a widening is SET TYPE's metadata change: SMALLINT to INTEGER to BIGINT, the old rows' bytes and segments as they
 * were, the new range taken from the commit; the reverse refused; through a reopen, a full replay, VERIFY, the
 * auditor, a view over the column and the dump */
static void t_intw_widen(void)
{
    const char *dir = test_tmpdir();
    imdb_err e = {0};
    CHECK(imdb_init(dir, false, NULL, &e) == 0);
    imdb_db *db = open_at(dir, false);
    CHECK(db);
    if (!db) return;
    OK(run("CREATE TABLE t (id SMALLINT PRIMARY KEY, s SMALLINT)"));
    OK(run("INSERT INTO t VALUES (1, 30000), (2, -30000)"));
    OK(run("CREATE VIEW v AS SELECT id, s FROM t"));
    OK(run("CHECKPOINT")); /* a segment of the SMALLINT version */
    EXPECT("INSERT INTO t VALUES (3, 40000)", "ERR SMALLINT");
    EXPECT("ALTER TABLE t ALTER COLUMN s TYPE INTEGER", "ALTER TABLE t");
    EXPECT("INSERT INTO t VALUES (3, 40000)", "INSERT 1");
    EXPECT("INSERT INTO t VALUES (4, 3000000000)", "ERR INTEGER");
    EXPECT("ALTER TABLE t ALTER COLUMN s TYPE SMALLINT", "ERR wider integer");
    EXPECT("ALTER TABLE t ALTER COLUMN s TYPE INTEGER", "ERR wider integer");
    EXPECT("ALTER TABLE t ALTER COLUMN s TYPE DECIMAL(18,0)", "ERR wider integer");
    EXPECT("ALTER TABLE t ALTER COLUMN s TYPE BIGINT", "ALTER TABLE t");
    EXPECT("INSERT INTO t VALUES (4, 3000000000)", "INSERT 1");
    EXPECT("ALTER TABLE t ALTER COLUMN id SET DATA TYPE INTEGER", "ALTER TABLE t"); /* a key column widens too */
    EXPECT("INSERT INTO t VALUES (70000, 1)", "INSERT 1");
    const char *want = "id,s\n1,30000\n2,-30000\n3,40000\n4,3000000000\n70000,1\n";
    EXPECT("SELECT * FROM v ORDER BY id", want);
    imdb_table *t = imdb_table_by_name(db, "t");
    CHECK(t && t->hist.nvers == 4 && t->s.cols[0].precision == 32 && t->s.cols[1].precision == 0);
    OK(run("CHECKPOINT"));
    done(db);
    db = open_at(dir, false);
    CHECK(db);
    if (!db) return;
    EXPECT("SELECT * FROM v ORDER BY id", want);
    EXPECT("SHOW TABLES", "table,columns,live_rows,versions,segments,history_from,dropped_at\n\"t\",\"id INTEGER PK, s INT64\",5,5,2,0,\n");
    OK(run("COMPACT t"));
    EXPECT("SELECT * FROM t ORDER BY id", want);
    CHECK(verify_db(db) == 0);
    done(db);
    db = open_at(dir, true);
    CHECK(db);
    if (!db) return;
    EXPECT("SELECT * FROM v ORDER BY id", want);
    done(db);
    CHECK(audit_dir(dir) == 0);
}

const test_case intw_tests[] = {
    {"intw_types", t_intw_types},
    {"intw_writes", t_intw_writes},
    {"intw_cast", t_intw_cast},
    {"intw_widen", t_intw_widen},
};
const size_t intw_ntests = sizeof intw_tests / sizeof *intw_tests;
