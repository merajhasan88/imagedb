/* P2 S2 (docs/plan-p2.md): GROUP BY several keys and expressions, COUNT/SUM/AVG/MIN/MAX of DISTINCT, FILTER (WHERE).
 * Every key type (-0.0 with 0.0, '' apart from NULL, (NULL, 1) apart from (1, NULL), a tuple's texts never run
 * together), the default order (each key ascending, NULL last), which subtrees match a key (t.g is g, 1 + a is not
 * a + 1) and every refusal; DISTINCT with NULLs and FILTER with UNKNOWN, grouped by one column, by trees and not at
 * all; each access path with cross_check, in memory and in the lake, and joins under both plans grouped by a key no
 * item names (the columns a join keeps); computed keys and DISTINCT's set under a statement's memory ceiling. */
#include <stdlib.h>

#include "../../src/db.h"
#include "../../src/sql.h"
#include "thelp.h"

static imdb_session g_s;
static char g_out[1 << 16];

/* a statement's result as CSV (the CLI's rendering), or "ERR <message>" */
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

static const char *body(const char *s) /* the rows: the header line (the items' texts) is not what is checked */
{
    const char *n = strchr(s, '\n');
    return n ? n + 1 : s;
}

/* sql's CSV rows are want's (want's header line documents them); a refusal: want begins "ERR " and the message
 * contains the rest */
#define EXPECT(sql, want)                                                                                          \
    do {                                                                                                           \
        const char *got_ = csv(sql);                                                                               \
        bool ok_ = !strncmp((want), "ERR ", 4) ? !strncmp(got_, "ERR ", 4) && strstr(got_ + 4, (want) + 4) != NULL \
                                               : !strcmp(body(got_), body(want));                                  \
        if (!ok_) {                                                                                                \
            char m_[1600];                                                                                         \
            snprintf(m_, sizeof m_, "%s\n      want: %s\n      got:  %s", (sql), (want), got_);                    \
            test_fail(__FILE__, __LINE__, m_);                                                                     \
        }                                                                                                          \
    } while (0)

static imdb_db *open_fresh(void)
{
    const char *dir = test_tmpdir();
    imdb_err e = {0};
    if (imdb_init(dir, false, NULL, &e)) return NULL;
    imdb_open_opts o = {.sync = 0};
    imdb_db *db = NULL;
    if (imdb_open(dir, &o, &db, &e)) return NULL;
    imdb_session_init(&g_s, db);
    return db;
}

static void done(imdb_db *db)
{
    imdb_session_close(&g_s);
    imdb_close(db);
}

/* every key type, NULLs and their order; a tuple's parts kept apart */
static void t_group_keys(void)
{
    imdb_db *db = open_fresh();
    CHECK(db != NULL);
    if (!db) return;
    CHECK(run("CREATE TABLE v (id INT64 PRIMARY KEY, i INT64, d DECIMAL(9,2), f FLOAT64, s TEXT, b BOOL, ts TIMESTAMP)") == 0);
    CHECK(run("INSERT INTO v VALUES (1, 1, 1.50, 0.0e0, '', TRUE, '2026-01-01'), (2, 1, 1.50, -0.0e0, NULL, FALSE, '2026-01-01'), "
              "(3, NULL, NULL, 0.5e0, '', NULL, NULL), (4, 2, 2.50, 0.5e0, 'a', TRUE, '2026-01-02'), "
              "(5, NULL, 1.50, NULL, NULL, TRUE, '2026-01-01'), (6, 1, NULL, 0.0e0, 'a', NULL, NULL)") == 0);
    for (int pass = 0; pass < 2; pass++) { /* in memory, then in the lake */
        EXPECT("SELECT i, s, COUNT(*) FROM v GROUP BY i, s", "i,s,count\n1,\"\",1\n1,\"a\",1\n1,,1\n2,\"a\",1\n,\"\",1\n,,1\n");
        EXPECT("SELECT f, b, COUNT(*) FROM v GROUP BY f, b",
               "f,b,count\n0,false,1\n0,true,1\n0,,1\n0.5,true,1\n0.5,,1\n,true,1\n"); /* -0.0 is 0.0's group */
        EXPECT("SELECT d, ts, COUNT(*), MIN(id) FROM v GROUP BY d, ts",
               "d,ts,count,min_id\n1.50,2026-01-01 00:00:00,3,1\n2.50,2026-01-02 00:00:00,1,4\n,,2,3\n");
        EXPECT("SELECT LOWER(s), COUNT(*) FROM v GROUP BY LOWER(s)", "LOWER(s),count\n\"\",2\n\"a\",2\n,2\n"); /* '' is no NULL */
        if (!pass) CHECK(run("CHECKPOINT") == 0);
    }
    CHECK(run("CREATE TABLE w (id INT64 PRIMARY KEY, a INT64, b INT64, x TEXT, y TEXT)") == 0);
    CHECK(run("INSERT INTO w VALUES (1, NULL, 1, 'ab', 'c'), (2, 1, NULL, 'a', 'bc'), (3, NULL, 1, 'ab', 'c')") == 0);
    EXPECT("SELECT a, b, COUNT(*) FROM w GROUP BY a, b", "a,b,count\n1,,1\n,1,2\n");
    EXPECT("SELECT x, y, COUNT(*) FROM w GROUP BY x, y", "x,y,count\n\"a\",\"bc\",1\n\"ab\",\"c\",2\n");
    done(db);
}

/* which subtrees are a key's, the boundary between one column's path and the trees', and every refusal */
static void t_group_match(void)
{
    imdb_db *db = open_fresh();
    CHECK(db != NULL);
    if (!db) return;
    CHECK(run("CREATE TABLE m (id INT64 PRIMARY KEY, g INT64, s TEXT)") == 0);
    CHECK(run("INSERT INTO m VALUES (1, 1, 'x'), (2, 1, 'y'), (3, 1, 'x'), (4, 2, 'x'), (5, 2, 'x'), (6, 3, NULL)") == 0);
    EXPECT("SELECT m.g, COUNT(*) FROM m GROUP BY g, s", "g,count\n1,2\n1,1\n2,2\n3,1\n");
    EXPECT("SELECT g, s, COUNT(*) FROM m GROUP BY m.g, m.s", "g,s,count\n1,\"x\",2\n1,\"y\",1\n2,\"x\",2\n3,,1\n");
    EXPECT("SELECT g, COUNT(*) FROM m GROUP BY g", "g,count\n1,3\n2,2\n3,1\n"); /* one column: its own path */
    EXPECT("SELECT g + 1, COUNT(*) FROM m GROUP BY g + 1", "g + 1,count\n2,3\n3,2\n4,1\n");
    EXPECT("SELECT (g + 1) * 2, COUNT(*) FROM m GROUP BY g + 1", "x,count\n4,3\n6,2\n8,1\n");
    EXPECT("SELECT 1 + g FROM m GROUP BY g + 1", "ERR column g must be a GROUP BY key");
    EXPECT("SELECT UPPER(LOWER(s)), COUNT(*) FROM m GROUP BY LOWER(s)", "x,count\n\"X\",4\n\"Y\",1\n,1\n");
    EXPECT("SELECT UPPER(s) FROM m GROUP BY LOWER(s)", "ERR column s must be a GROUP BY key");
    /* keys no item names, ordered by and in HAVING */
    EXPECT("SELECT COUNT(*) FROM m GROUP BY g, s ORDER BY g DESC, s", "count\n1\n2\n2\n1\n");
    EXPECT("SELECT COUNT(*) FROM m GROUP BY g, s HAVING s IS NULL OR g = 2", "count\n2\n1\n");
    /* a plain aggregate of a column (its accumulator per item) beside tree aggregates (theirs per slot) */
    EXPECT("SELECT g % 2, MIN(s), COUNT(DISTINCT s), MAX(id) FROM m GROUP BY g % 2",
           "g % 2,min_s,COUNT(DISTINCT s),max_id\n0,\"x\",1,5\n1,\"x\",2,6\n");
    EXPECT("SELECT s FROM m GROUP BY g, LOWER(s)", "ERR column s must be a GROUP BY key");
    EXPECT("SELECT COUNT(*) FROM m GROUP BY 1", "ERR GROUP BY key 1 reads no column");
    EXPECT("SELECT g, COUNT(*) FROM m GROUP BY g, COUNT(*)", "ERR an aggregate stands only in a SELECT list");
    EXPECT("SELECT * FROM m GROUP BY g, s", "ERR SELECT * cannot be grouped");
    EXPECT("SELECT COUNT(*) FROM m GROUP BY g, s, id, g + 1, g + 2, g + 3, g + 4, g + 5, g + 6", "ERR GROUP BY has more than 8 keys");
    EXPECT("EXPLAIN SELECT g, LOWER(s), COUNT(*) FROM m GROUP BY g, LOWER(s)",
           "item,detail\n\"table\",\"m\"\n\"snapshot\",\"commit 2 (the latest)\"\n\"path\",\"scan\"\n"
           "\"why\",\"no index serves the conditions\"\n\"conditions\",\"none: every visible row\"\n"
           "\"estimate\",\"at most 6 versions read (an upper bound from the indexes and the store: no statistics)\"\n"
           "\"segments\",\"0 of 0 read (0 skipped by their zone maps); 6 versions in memory\"\n"
           "\"output\",\"a row for each group of g, LOWER(s)\"\n");
    done(db);
}

/* DISTINCT with NULLs, FILTER with UNKNOWN: grouped by one column, by a tree, and not grouped; the refusals */
static void t_group_distinct_filter(void)
{
    imdb_db *db = open_fresh();
    CHECK(db != NULL);
    if (!db) return;
    CHECK(run("CREATE TABLE n (id INT64 PRIMARY KEY, g INT64, x INT64, d DECIMAL(9,2))") == 0);
    CHECK(run("INSERT INTO n VALUES (1, 1, 5, 1.00), (2, 1, 5, 2.00), (3, 1, NULL, 1.00), (4, 2, 7, NULL), (5, 2, 7, 3.00), "
              "(6, 2, 8, 3.00)") == 0);
    EXPECT("SELECT g, COUNT(DISTINCT x), SUM(DISTINCT x), AVG(DISTINCT x), COUNT(x), SUM(DISTINCT d), MIN(DISTINCT d), "
           "MAX(DISTINCT d) FROM n GROUP BY g",
           "g,...\n1,1,5,5.000000,2,3.00,1.00,2.00\n2,2,15,7.500000,3,3.00,3.00,3.00\n");
    EXPECT("SELECT g, COUNT(*) FILTER (WHERE x > 5), SUM(d) FILTER (WHERE x = 5), COUNT(DISTINCT d) FILTER (WHERE x IS NOT NULL) "
           "FROM n GROUP BY g",
           "g,...\n1,0,3.00,2\n2,3,,1\n"); /* x > 5 UNKNOWN at a NULL x: not counted */
    EXPECT("SELECT g - g, COUNT(DISTINCT x), COUNT(*) FILTER (WHERE x > 5) FROM n GROUP BY g - g", "x,...\n0,3,3\n");
    EXPECT("SELECT COUNT(DISTINCT x), COUNT(*) FILTER (WHERE d IS NULL), COUNT(ALL x) FROM n", "x,...\n3,1,5\n");
    EXPECT("SELECT g FROM n GROUP BY g HAVING COUNT(DISTINCT x) > 1", "g\n2\n");
    EXPECT("SELECT g FROM n GROUP BY g ORDER BY SUM(x) FILTER (WHERE x < 8) DESC", "g\n2\n1\n");
    EXPECT("SELECT COUNT(*) FILTER (WHERE x) FROM n", "ERR FILTER takes a condition");
    EXPECT("SELECT COUNT(DISTINCT *) FROM n", "ERR COUNT(DISTINCT *) is not SQL");
    EXPECT("SELECT SUM(x) FILTER (WHERE COUNT(*) > 0) FROM n", "ERR an aggregate inside an aggregate");
    done(db);
}

enum { N = 3000 };

/* each access path with cross_check, rows in segments and in memory; joins under both plans, grouped by keys no item
 * names (a join keeps only the columns something reads: the keys' too) */
static void t_group_paths(void)
{
    imdb_db *db = open_fresh();
    CHECK(db != NULL);
    if (!db) return;
    CHECK(run("CREATE TABLE t (id INT64 PRIMARY KEY, g INT64, d DECIMAL(9,2), s TEXT)") == 0);
    CHECK(run("CREATE TABLE u (id INT64 PRIMARY KEY, tid INT64, w TEXT)") == 0);
    imdb_buf b;
    imdb_buf_init(&b);
    imdb_buf_put_str(&b, "INSERT INTO t VALUES ");
    for (int i = 1; i <= N; i++)
        imdb_buf_printf(&b, "%s(%d, %d, %d.%02d, %s)", i > 1 ? ", " : "", i, i % 11, i % 97, i % 100,
                        i % 13 ? (i % 2 ? "'Abc def'" : "'xyz_Q'") : "NULL");
    imdb_buf_put_u8(&b, 0);
    CHECK(!imdb_buf_check(&b, &g_e) && !run((const char *)b.p));
    b.len = 0;
    imdb_buf_put_str(&b, "INSERT INTO u VALUES ");
    for (int i = 1; i <= 300; i++) imdb_buf_printf(&b, "%s(%d, %d, 'W%d')", i > 1 ? ", " : "", i, i * 7, i % 5);
    imdb_buf_put_u8(&b, 0);
    CHECK(!imdb_buf_check(&b, &g_e) && !run((const char *)b.p));
    imdb_buf_free(&b);
    CHECK(run("CREATE INDEX t_g ON t (g)") == 0);
    CHECK(run("CHECKPOINT") == 0);
    CHECK(run("UPDATE t SET s = 'Fresh' WHERE id % 10 = 0") == 0);
    CHECK(run("SET cross_check = on") == 0);
    static const char *const q[] = {
        "SELECT g % 3, LOWER(s), COUNT(*), COUNT(DISTINCT d), SUM(d) FILTER (WHERE id % 2 = 0) FROM t GROUP BY g % 3, LOWER(s)",
        "SELECT g, s, MIN(id), MAX(d) FROM t WHERE g IN (1, 2, 3) GROUP BY g, s HAVING COUNT(*) > 5",
        "SELECT COUNT(DISTINCT g), COUNT(*) FILTER (WHERE s LIKE '%Q'), SUM(DISTINCT g) FROM t WHERE id > 100",
        "SELECT g, COUNT(DISTINCT s), COUNT(*) FILTER (WHERE d > 50) FROM t WHERE g BETWEEN 2 AND 5 GROUP BY g",
        "SELECT COUNT(*) FROM t JOIN u ON t.id = u.tid GROUP BY LOWER(u.w)",
        "SELECT SUM(t.d), COUNT(DISTINCT t.g) FROM t JOIN u ON t.id = u.tid GROUP BY LOWER(u.w), t.g % 2",
        "SELECT LOWER(u.w), COUNT(*) FILTER (WHERE t.s IS NULL) FROM t LEFT JOIN u ON t.id = u.tid GROUP BY LOWER(u.w)",
    };
    static const char *const paths[] = {"auto", "scan", "store", "ordered", "index"};
    static char first[sizeof q / sizeof *q][8192];
    for (size_t p = 0; p < sizeof paths / sizeof *paths; p++) {
        char set[64];
        snprintf(set, sizeof set, "SET access_path = %s", paths[p]);
        CHECK(run(set) == 0);
        for (int plan = 0; plan < 2; plan++) {
            CHECK(run(plan ? "SET join_plan = index" : "SET join_plan = hash") == 0);
            for (size_t i = 0; i < sizeof q / sizeof *q; i++) {
                const char *got = csv(q[i]);
                if (!strncmp(got, "ERR ", 4)) {
                    char m[1200];
                    snprintf(m, sizeof m, "%s under %s, plan %d: %s", q[i], paths[p], plan, got);
                    test_fail(__FILE__, __LINE__, m);
                    continue;
                }
                if (!p && !plan) snprintf(first[i], sizeof first[i], "%s", got);
                else CHECK(!strcmp(first[i], got)); /* every path and plan the same answer, each cross-checked within */
            }
        }
    }
    /* u's tids are 7, 14, ... 2100: every one a t row; W0 .. W4 sixty each */
    EXPECT("SELECT COUNT(*) FROM t JOIN u ON t.id = u.tid GROUP BY LOWER(u.w)", "count\n60\n60\n60\n60\n60\n");
    CHECK(run("SET access_path = auto") == 0);
    done(db);
}

/* a computed key costs one row's memory, whatever the rows' count (the arena released per row); DISTINCT's set and
 * many groups are charged, so a 1 MiB ceiling refuses what 256 MiB answers */
static void t_group_memory(void)
{
    imdb_db *db = open_fresh();
    CHECK(db != NULL);
    if (!db) return;
    CHECK(run("CREATE TABLE k (id INT64 PRIMARY KEY, s TEXT)") == 0);
    imdb_buf b;
    imdb_buf_init(&b);
    for (int base = 0; base < 60000 && !g_e.code; base += 5000) {
        b.len = 0;
        imdb_buf_put_str(&b, "INSERT INTO k VALUES ");
        for (int i = base + 1; i <= base + 5000; i++)
            imdb_buf_printf(&b, "%s(%d, 'Some Mixed Case Text Of Forty Bytes %04d')", i > base + 1 ? ", " : "", i, i % 10000);
        imdb_buf_put_u8(&b, 0);
        CHECK(!imdb_buf_check(&b, &g_e) && !run((const char *)b.p));
    }
    imdb_buf_free(&b);
    CHECK(run("SET statement_memory = 1048576") == 0);
    EXPECT("SELECT SUBSTR(LOWER(s), 1, 4), COUNT(*) FROM k GROUP BY SUBSTR(LOWER(s), 1, 4)", "x,count\n\"some\",60000\n");
    EXPECT("SELECT COUNT(DISTINCT LOWER(s) || CAST(id AS TEXT)) FROM k", "ERR statement memory");
    EXPECT("SELECT LOWER(s), COUNT(*) FROM k GROUP BY LOWER(s), id % 3", "ERR statement memory");
    CHECK(run("SET statement_memory = 268435456") == 0);
    EXPECT("SELECT COUNT(DISTINCT LOWER(s) || CAST(id AS TEXT)), COUNT(DISTINCT LOWER(s)) FROM k", "x,y\n60000,10000\n");
    imdb_result r;
    imdb_err_clear(&g_e);
    static const char q[] = "SELECT LOWER(s), COUNT(*) FROM k GROUP BY LOWER(s), id % 3";
    CHECK(imdb_exec_one(&g_s, q, strlen(q), NULL, 0, &r, &g_e) == 0);
    if (!g_e.code) {
        CHECK(r.nrows == 30000); /* a text's six ids: two in each residue of 3 */
        imdb_result_free(&r);
    }
    CHECK(run("SET statement_memory = 0") == 0);
    done(db);
}

const test_case group_tests[] = {
    {"group_keys", t_group_keys},
    {"group_match", t_group_match},
    {"group_distinct_filter", t_group_distinct_filter},
    {"group_paths", t_group_paths},
    {"group_memory", t_group_memory},
};
const size_t group_ntests = sizeof group_tests / sizeof *group_tests;
