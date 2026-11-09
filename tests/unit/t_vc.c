/* F3c: VARCHAR(n) (docs/format-design-v7.md section 5; design.md section 5, VARCHAR). A TEXT column with a length in
 * characters (its vlen, written in the schema encoding's precision and scale bytes): every write path refuses a longer
 * value, a CAST to VARCHAR(n) refuses one, a lengthening (or TEXT) is SET TYPE's metadata change and a shortening is
 * refused; through a CHECKPOINT, a reopen, COMPACT, a full replay, VERIFY, the auditor and a replica. */
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

static imdb_db *fresh(void)
{
    const char *dir = test_tmpdir();
    imdb_err e = {0};
    if (imdb_init(dir, false, NULL, &e)) return NULL;
    return open_at(dir, false);
}

/* the spellings, SHOW TABLES, the bounds, and the schema's encoding: the length in the precision and scale bytes, read
 * back into vlen with precision and scale 0 */
static void t_vc_types(void)
{
    imdb_db *db = fresh();
    CHECK(db);
    if (!db) return;
    OK(run("CREATE TABLE v (id INT64 PRIMARY KEY, a VARCHAR(3), b CHARACTER VARYING(300), c VARCHAR, d varchar(65535), t TEXT)"));
    EXPECT("SHOW TABLES", "table,columns,live_rows,versions,segments,history_from,dropped_at\n\"v\",\"id INT64 PK, a VARCHAR(3), "
                          "b VARCHAR(300), c TEXT, d VARCHAR(65535), t TEXT\",0,0,0,0,\n");
    EXPECT("CREATE TABLE z (id INT64 PRIMARY KEY, a VARCHAR(0))", "ERR VARCHAR(n) needs 1 <= n <= 65535");
    EXPECT("CREATE TABLE z (id INT64 PRIMARY KEY, a VARCHAR(65536))", "ERR VARCHAR(n) needs 1 <= n <= 65535");
    EXPECT("CREATE TABLE z (id INT64 PRIMARY KEY, a VARCHAR(3, 1))", "ERR ");
    imdb_table *t = imdb_table_by_name(db, "v");
    CHECK(t && t->s.cols[1].vlen == 3 && t->s.cols[2].vlen == 300 && t->s.cols[3].vlen == 0 && t->s.cols[4].vlen == 65535 &&
          !t->s.cols[2].precision && !t->s.cols[2].scale);
    if (t) {
        imdb_buf b;
        imdb_buf_init(&b);
        imdb_schema_encode(&t->s, &b);
        imdb_err e = {0};
        CHECK(imdb_buf_check(&b, &e) == 0);
        imdb_rd r;
        imdb_rd_init(&r, b.p, b.len);
        imdb_schema back;
        CHECK(imdb_schema_decode(&r, &back, &e) == 0 && back.cols[2].vlen == 300 && back.cols[2].precision == 0 &&
              back.cols[2].scale == 0 && back.cols[4].vlen == 65535);
        imdb_buf_free(&b);
        imdb_schema bad = t->s; /* in memory a TEXT's precision and scale stay 0, a non-TEXT has no length */
        bad.cols[2].scale = 1;
        CHECK(imdb_schema_check(&bad, &e) != 0);
    }
    done(db);
}

/* every write path counts characters against the length: INSERT, UPDATE, COPY, INSERT ... SELECT, ON CONFLICT, a
 * DEFAULT; a statement refused whole; four 4-byte characters fit VARCHAR(4) */
static void t_vc_writes(void)
{
    imdb_db *db = fresh();
    CHECK(db);
    if (!db) return;
    OK(run("CREATE TABLE v (id INT64 PRIMARY KEY, a VARCHAR(4), s TEXT)"));
    EXPECT("INSERT INTO v VALUES (1, 'abcd', 'x'), (2, '\xf0\x9f\x98\x80\xf0\x9f\x98\x80\xf0\x9f\x98\x80\xf0\x9f\x98\x80', 'y'), "
           "(3, '', 'z'), (4, NULL, 'abcdefgh')",
           "INSERT 4");
    EXPECT("INSERT INTO v VALUES (5, 'abcde', NULL)", "ERR column a: a value longer than VARCHAR(4)");
    EXPECT("INSERT INTO v VALUES (5, 'ab', NULL), (6, '\xf0\x9f\x98\x80\xf0\x9f\x98\x80\xf0\x9f\x98\x80\xf0\x9f\x98\x80x', NULL)",
           "ERR VARCHAR(4)");
    EXPECT("SELECT COUNT(*) AS c FROM v", "c\n4\n"); /* the statement refused whole */
    EXPECT("UPDATE v SET a = a || 'x' WHERE id = 1", "ERR VARCHAR(4)");
    EXPECT("UPDATE v SET a = a || 'x' WHERE id = 3", "UPDATE 1");
    EXPECT("INSERT INTO v (id, a) SELECT id + 10, s FROM v", "ERR VARCHAR(4)");
    EXPECT("INSERT INTO v (id, a) SELECT id + 10, s FROM v WHERE id < 4", "INSERT 3");
    EXPECT("INSERT INTO v VALUES (1, 'q', NULL) ON CONFLICT (id) DO UPDATE SET a = EXCLUDED.a || 'rstu'", "ERR VARCHAR(4)");
    EXPECT("INSERT INTO v VALUES (1, 'q', NULL) ON CONFLICT (id) DO UPDATE SET a = EXCLUDED.a || 'rst'", "INSERT 1");
    EXPECT("SELECT a FROM v WHERE id = 1", "a\n\"qrst\"\n");
    EXPECT("ALTER TABLE v ADD k VARCHAR(2) DEFAULT 'abc'", "ERR VARCHAR(2)");
    OK(run("ALTER TABLE v ADD k VARCHAR(2) DEFAULT 'ab'"));
    EXPECT("ALTER TABLE v ALTER COLUMN k SET DEFAULT 'abc'", "ERR ");
    OK(run("INSERT INTO v (id) VALUES (20)"));
    EXPECT("SELECT k FROM v WHERE id = 20", "k\n\"ab\"\n");
    EXPECT("SELECT a FROM v WHERE a = 'abcdefgh'", "a\n"); /* a comparison, never a refusal */
    done(db);
}

/* CAST to VARCHAR(n): refused past n, from every source type; a view's column of one is a TEXT */
static void t_vc_cast(void)
{
    imdb_db *db = fresh();
    CHECK(db);
    if (!db) return;
    EXPECT("SELECT CAST('abc' AS VARCHAR(3)) AS a, CAST(12345 AS VARCHAR(5)) AS b, CAST(1.50 AS CHARACTER VARYING(4)) AS c, "
           "CAST(DATE '2026-11-09' AS VARCHAR(10)) AS d",
           "a,b,c,d\n\"abc\",\"12345\",\"1.50\",\"2026-11-09\"\n");
    EXPECT("SELECT CAST('abcd' AS VARCHAR(3))", "ERR CAST: the value is longer than VARCHAR(3)");
    EXPECT("SELECT CAST(123456 AS VARCHAR(5))", "ERR VARCHAR(5)");
    EXPECT("SELECT CAST(TIMESTAMP '2026-11-09 12:00:00' AS VARCHAR(10))", "ERR VARCHAR(10)");
    OK(run("CREATE TABLE v (id INT64 PRIMARY KEY, s TEXT)"));
    OK(run("INSERT INTO v VALUES (1, 'ab'), (2, 'abcdef')"));
    OK(run("CREATE VIEW w AS SELECT id, CAST(s AS VARCHAR(10)) AS s10 FROM v"));
    EXPECT("SELECT s10 FROM w ORDER BY id", "s10\n\"ab\"\n\"abcdef\"\n");
    EXPECT("SELECT CAST(s AS VARCHAR(3)) FROM v ORDER BY id", "ERR VARCHAR(3)");
    done(db);
}

/* a lengthening is SET TYPE's metadata change (VARCHAR(3) to VARCHAR(5) to TEXT), a shortening refused (and TEXT to any
 * VARCHAR); the old rows' bytes and segments as they were; through a CHECKPOINT, a reopen, COMPACT, a full replay,
 * VERIFY, the auditor, the dump's spelling and a replica at the primary's digest */
static void t_vc_widen(void)
{
    const char *dir = test_tmpdir();
    imdb_err e = {0};
    CHECK(imdb_init(dir, false, NULL, &e) == 0);
    imdb_db *db = open_at(dir, false);
    CHECK(db);
    if (!db) return;
    OK(run("CREATE TABLE v (id INT64 PRIMARY KEY, a VARCHAR(3), t TEXT)"));
    OK(run("INSERT INTO v VALUES (1, 'abc', 'x'), (2, 'é', NULL)"));
    OK(run("CREATE VIEW vv AS SELECT id, a FROM v")); /* a view over the column, made before it lengthens */
    OK(run("CHECKPOINT")); /* a segment of the VARCHAR(3) version */
    EXPECT("INSERT INTO v VALUES (3, 'abcd', NULL)", "ERR VARCHAR(3)");
    EXPECT("ALTER TABLE v ALTER COLUMN a TYPE VARCHAR(2)", "ERR a longer VARCHAR or TEXT");
    EXPECT("ALTER TABLE v ALTER COLUMN a TYPE VARCHAR(3)", "ERR a longer VARCHAR or TEXT");
    EXPECT("ALTER TABLE v ALTER COLUMN t TYPE VARCHAR(100)", "ERR a longer VARCHAR or TEXT");
    EXPECT("ALTER TABLE v ALTER COLUMN a TYPE VARCHAR(5)", "ALTER TABLE v");
    EXPECT("INSERT INTO v VALUES (3, 'abcd', NULL)", "INSERT 1");
    EXPECT("INSERT INTO v VALUES (4, 'abcdef', NULL)", "ERR VARCHAR(5)");
    OK(run("CHECKPOINT"));
    EXPECT("ALTER TABLE v ALTER COLUMN a SET DATA TYPE CHARACTER VARYING", "ALTER TABLE v"); /* unbounded: a TEXT */
    EXPECT("INSERT INTO v VALUES (4, 'abcdef', NULL)", "INSERT 1");
    const char *want = "id,a,t\n1,\"abc\",\"x\"\n2,\"\xc3\xa9\",\n3,\"abcd\",\n4,\"abcdef\",\n";
    EXPECT("SELECT * FROM v ORDER BY id", want);
    EXPECT("SELECT * FROM vv ORDER BY id", "id,a\n1,\"abc\"\n2,\"\xc3\xa9\"\n3,\"abcd\"\n4,\"abcdef\"\n"); /* read after the lengthenings */
    OK(run("CHECKPOINT"));
    done(db);
    db = open_at(dir, false);
    CHECK(db);
    if (!db) return;
    EXPECT("SELECT * FROM v ORDER BY id", want);
    EXPECT("SHOW TABLES", "table,columns,live_rows,versions,segments,history_from,dropped_at\n\"v\",\"id INT64 PK, a TEXT, t TEXT\",4,4,3,0,\n");
    OK(run("COMPACT v"));
    EXPECT("SELECT * FROM v ORDER BY id", want);
    CHECK(imdb_verify(db, &(imdb_verify_report){0}, &g_e) == 0);
    char dig[2048];
    snprintf(dig, sizeof dig, "%s", csv("SHOW DIGEST"));
    done(db);
    db = open_at(dir, true);
    CHECK(db);
    if (!db) return;
    EXPECT("SELECT * FROM v ORDER BY id", want);
    done(db);
    CHECK(audit_dir(dir) == 0);
    char rp[700], sf[760];
    snprintf(rp, sizeof rp, "%s-replica", dir);
    snprintf(sf, sizeof sf, "%s-stream", dir);
    imdb_identity id;
    OK(imdb_identity_read(dir, &id, NULL, &g_e));
    OK(imdb_init_replica(rp, &id, &g_e));
    OK(ship_to_file(dir, 0, sf, &g_e));
    imdb_db *rep = NULL;
    imdb_open_opts ro = {.sync = 0};
    CHECK(imdb_open(rp, &ro, &rep, &e) == 0);
    if (!rep) return;
    uint64_t applied = 0;
    OK(apply_file(rep, sf, &applied, &g_e));
    imdb_session_init(&g_s, rep);
    EXPECT("SELECT * FROM v ORDER BY id", want);
    CHECK(!strcmp(csv("SHOW DIGEST"), dig));
    done(rep);
    CHECK(audit_dir(rp) == 0);
}

const test_case vc_tests[] = {
    {"vc_types", t_vc_types},
    {"vc_writes", t_vc_writes},
    {"vc_cast", t_vc_cast},
    {"vc_widen", t_vc_widen},
};
const size_t vc_ntests = sizeof vc_tests / sizeof *vc_tests;
