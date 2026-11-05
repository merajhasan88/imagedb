/* P2 S1 (docs/plan-p2.md): functions, CASE, CAST, IN, LIKE, ||, SELECT without FROM and select-list aliases. Each
 * form at its edges (NULLs, types, UTF-8, the rounding rules), every refusal with its message, the forms in WHERE
 * under each access path with cross_check on and in a join, computed TEXT under a 1 MiB statement ceiling (the
 * arena released per row), and a LIKE stopped inside one long match by statement_timeout. */
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

/* sql's CSV rows are want's exactly (want's header line documents them; EXPECT_H compares it too); a refusal: want
 * begins "ERR " and the message contains the rest */
#define EXPECT_X(sql, want, whole)                                                                                 \
    do {                                                                                                           \
        const char *got_ = csv(sql);                                                                               \
        bool ok_ = !strncmp((want), "ERR ", 4) ? !strncmp(got_, "ERR ", 4) && strstr(got_ + 4, (want) + 4) != NULL \
                   : (whole) ? !strcmp(got_, (want)) : !strcmp(body(got_), body(want));                             \
        if (!ok_) {                                                                                                \
            char m_[1600];                                                                                         \
            snprintf(m_, sizeof m_, "%s\n      want: %s\n      got:  %s", (sql), (want), got_);                    \
            test_fail(__FILE__, __LINE__, m_);                                                                     \
        }                                                                                                          \
    } while (0)
#define EXPECT(sql, want) EXPECT_X(sql, want, false)
#define EXPECT_H(sql, want) EXPECT_X(sql, want, true)

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

/* numbers: ABS, SIGN, ROUND (DECIMAL half away from zero, to a constant's places), CEIL, FLOOR, MOD; NULL in, NULL out */
static void t_sqlfn_numeric(void)
{
    imdb_db *db = open_fresh();
    CHECK(db != NULL);
    if (!db) return;
    EXPECT("SELECT ABS(-5), ABS(5), ABS(-2.50), ABS(-0.0e0), SIGN(-3), SIGN(0), SIGN(2.5e0)",
           "ABS(-5),ABS(5),ABS(-2.50),ABS(-0.0e0),SIGN(-3),SIGN(0),SIGN(2.5e0)\n5,5,2.50,0,-1,0,1\n");
    EXPECT("SELECT ROUND(2.345, 2), ROUND(-2.345, 2), ROUND(2.5), ROUND(-2.5), ROUND(2.4999), ROUND(7), ROUND(1.23, 5)",
           "ROUND(2.345, 2),ROUND(-2.345, 2),ROUND(2.5),ROUND(-2.5),ROUND(2.4999),ROUND(7),ROUND(1.23, 5)\n"
           "2.35,-2.35,3,-3,2,7,1.23\n");
    EXPECT("SELECT ROUND(2.5e0), ROUND(-2.5e0), ROUND(0.49999999999999994e0), CEIL(-0.5e0), FLOOR(-0.5e0)",
           "ROUND(2.5e0),ROUND(-2.5e0),ROUND(0.49999999999999994e0),CEIL(-0.5e0),FLOOR(-0.5e0)\n3,-3,0,0,-1\n");
    EXPECT("SELECT CEIL(2.001), CEIL(-2.999), FLOOR(2.999), FLOOR(-2.001), CEIL(5), FLOOR(-5)",
           "CEIL(2.001),CEIL(-2.999),FLOOR(2.999),FLOOR(-2.001),CEIL(5),FLOOR(-5)\n3,-2,2,-3,5,-5\n");
    EXPECT("SELECT MOD(-7, 3), MOD(7, -3), MOD(7.5, 2), 7 % 3", "MOD(-7, 3),MOD(7, -3),MOD(7.5, 2),7 % 3\n-1,1,1.5,1\n");
    CHECK(run("CREATE TABLE n (id INT64 PRIMARY KEY, a INT64, d DECIMAL(9,3), f FLOAT64)") == 0);
    CHECK(run("INSERT INTO n VALUES (1, NULL, NULL, NULL)") == 0);
    EXPECT("SELECT ABS(a), SIGN(d), ROUND(d, 1), CEIL(f), FLOOR(a), MOD(a, 2) FROM n",
           "ABS(a),SIGN(d),ROUND(d, 1),CEIL(f),FLOOR(a),MOD(a, 2)\n,,,,,\n");
    EXPECT("SELECT ABS(-9223372036854775807 - 1)", "ERR INT64 overflow");
    EXPECT("SELECT ROUND(2.5e0, 1)", "ERR ROUND of a FLOAT64 rounds to an integer");
    EXPECT("SELECT ROUND(2.5, -1)", "ERR ROUND's places are 0 to");
    EXPECT("SELECT ROUND(d, a) FROM n", "ERR ROUND's places are an integer constant");
    EXPECT("SELECT MOD(1, 0)", "ERR division by zero");
    /* a SUM wider than INT64 (exact under 10^38) through ROUND, CEIL or FLOOR is checked as arithmetic is (fuzz_expr) */
    CHECK(run("CREATE TABLE w (id INT64 PRIMARY KEY, x INT64)") == 0);
    CHECK(run("INSERT INTO w VALUES (1, 9223372036854775807), (2, 9223372036854775807)") == 0);
    EXPECT("SELECT SUM(x) FROM w", "SUM(x)\n18446744073709551614\n");
    EXPECT("SELECT ROUND(SUM(x)) FROM w", "ERR INT64 overflow");
    EXPECT("SELECT CEIL(SUM(x)) FROM w", "ERR INT64 overflow");
    EXPECT("SELECT ABS(SUM(x)) FROM w", "ERR INT64 overflow");
    EXPECT("SELECT SIGN(SUM(x)) FROM w", "SIGN(SUM(x))\n1\n");
    EXPECT("SELECT ABS('x')", "ERR ABS takes a number");
    EXPECT("SELECT ABS(1, 2)", "ERR ABS takes 1 argument");
    done(db);
}

/* text: characters, not bytes; positions as PostgreSQL's; LOWER and UPPER on ASCII letters only; REPLACE; || */
static void t_sqlfn_text(void)
{
    imdb_db *db = open_fresh();
    CHECK(db != NULL);
    if (!db) return;
    EXPECT("SELECT LENGTH('héllo'), CHAR_LENGTH(''), LENGTH('日本語')", "LENGTH('héllo'),CHAR_LENGTH(''),LENGTH('日本語')\n5,0,3\n");
    EXPECT("SELECT SUBSTR('héllo', 2, 3), SUBSTR('abc', 0, 2), SUBSTR('abc', -1, 3), SUBSTR('abc', 2), SUBSTR('abc', 5), "
           "SUBSTRING('abc', 2, 0)",
           "\"SUBSTR('héllo', 2, 3)\",\"SUBSTR('abc', 0, 2)\",\"SUBSTR('abc', -1, 3)\",\"SUBSTR('abc', 2)\","
           "\"SUBSTR('abc', 5)\",\"SUBSTRING('abc', 2, 0)\"\n\"éll\",\"a\",\"a\",\"bc\",\"\",\"\"\n");
    EXPECT("SELECT '[' || TRIM('  a b  ') || ']', '[' || LTRIM('  a ') || ']', '[' || RTRIM(' a  ') || ']'",
           "\"'[' || TRIM('  a b  ') || ']'\",\"'[' || LTRIM('  a ') || ']'\",\"'[' || RTRIM(' a  ') || ']'\"\n"
           "\"[a b]\",\"[a ]\",\"[ a]\"\n");
    EXPECT("SELECT POSITION('lo' IN 'héllo'), POSITION('x' IN 'abc'), POSITION('' IN 'abc')",
           "\"POSITION('lo' IN 'héllo')\",\"POSITION('x' IN 'abc')\",\"POSITION('' IN 'abc')\"\n4,0,1\n");
    EXPECT("SELECT LOWER('ÀBC def'), UPPER('àbc DEF')", "\"LOWER('ÀBC def')\",\"UPPER('àbc DEF')\"\n\"Àbc def\",\"àBC DEF\"\n");
    EXPECT("SELECT REPLACE('aaa', 'a', 'bb'), REPLACE('abcabc', 'bc', ''), REPLACE('abc', '', 'x'), REPLACE('a', 'a', 'a')",
           "\"REPLACE('aaa', 'a', 'bb')\",\"REPLACE('abcabc', 'bc', '')\",\"REPLACE('abc', '', 'x')\",\"REPLACE('a', 'a', 'a')\"\n"
           "\"bbbbbb\",\"aa\",\"abc\",\"a\"\n");
    EXPECT("SELECT 'a' || 'b' || 'c', 'x' || CAST(1 + 2 AS TEXT)", "\"'a' || 'b' || 'c'\",\"'x' || CAST(1 + 2 AS TEXT)\"\n\"abc\",\"x3\"\n");
    CHECK(run("CREATE TABLE s (id INT64 PRIMARY KEY, v TEXT)") == 0);
    CHECK(run("INSERT INTO s VALUES (1, NULL)") == 0);
    EXPECT("SELECT LENGTH(v), SUBSTR(v, 1, 2), TRIM(v), POSITION('a' IN v), LOWER(v), REPLACE(v, 'a', 'b'), v || 'x' FROM s",
           "LENGTH(v),\"SUBSTR(v, 1, 2)\",TRIM(v),\"POSITION('a' IN v)\",LOWER(v),\"REPLACE(v, 'a', 'b')\",\"v || 'x'\"\n"
           ",,,,,,\n");
    EXPECT("SELECT SUBSTR('abc', 1, -1)", "ERR SUBSTR's length is negative");
    EXPECT("SELECT 'a' || 1", "ERR || takes TEXT values");
    EXPECT("SELECT LENGTH(5)", "ERR LENGTH takes a TEXT value");
    EXPECT("SELECT SUBSTR('a')", "ERR SUBSTR takes 2 to 3 arguments");
    /* a computed TEXT past the TEXT limit is refused, as a stored one would be */
    static char big[300];
    snprintf(big, sizeof big, "SELECT LENGTH(REPLACE(REPLACE(REPLACE('%s', 'a', 'aaaaaaaaaa'), 'a', 'aaaaaaaaaa'), 'a', 'aaaaaaaaaa'))",
             "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    EXPECT(big, "ERR a computed TEXT of more than 65535 bytes");
    done(db);
}

/* COALESCE (lazy, widened), NULLIF, CASE (searched and simple, widened, no ELSE), IN and NOT IN (three-valued),
 * LIKE (characters, escapes) and NOT LIKE, NOT BETWEEN */
static void t_sqlfn_cond(void)
{
    imdb_db *db = open_fresh();
    CHECK(db != NULL);
    if (!db) return;
    EXPECT("SELECT COALESCE(NULL, 2, 3), COALESCE(1, 1 / 0), COALESCE(NULL, 1.5, 2), NULLIF(3, 3), NULLIF(3, 4), NULLIF(3, NULL)",
           "\"COALESCE(NULL, 2, 3)\",\"COALESCE(1, 1 / 0)\",\"COALESCE(NULL, 1.5, 2)\",\"NULLIF(3, 3)\",\"NULLIF(3, 4)\","
           "\"NULLIF(3, NULL)\"\n2,1,1.5,,3,3\n");
    EXPECT("SELECT CASE WHEN 1 > 2 THEN 'a' WHEN 2 > 1 THEN 'b' ELSE 'c' END, CASE 2 WHEN 1 THEN 10 WHEN 2 THEN 2.5 END, "
           "CASE WHEN 1 > 2 THEN 1 END, CASE 3 WHEN 4 THEN 1 ELSE 0 END",
           "\"CASE WHEN 1 > 2 THEN 'a' WHEN 2 > 1 THEN 'b' ELSE 'c' END\",\"CASE 2 WHEN 1 THEN 10 WHEN 2 THEN 2.5 END\","
           "\"CASE WHEN 1 > 2 THEN 1 END\",\"CASE 3 WHEN 4 THEN 1 ELSE 0 END\"\n\"b\",2.5,,0\n");
    EXPECT("SELECT CASE NULL WHEN 1 THEN 1 END", "ERR NULL cannot be an operand"); /* as NULL = 1 is refused */
    EXPECT("SELECT 2 IN (1, 2), 3 IN (1, 2), 3 IN (1, NULL), 1 IN (1, NULL), 3 NOT IN (1, 2), 3 NOT IN (1, NULL)",
           "\"2 IN (1, 2)\",\"3 IN (1, 2)\",\"3 IN (1, NULL)\",\"1 IN (1, NULL)\",\"3 NOT IN (1, 2)\",\"3 NOT IN (1, NULL)\"\n"
           "true,false,,true,true,\n");
    EXPECT("SELECT 'héllo' LIKE 'h_llo', 'hello' LIKE 'h%o', 'hello' LIKE 'H%', 'a%b' LIKE 'a!%b' ESCAPE '!', "
           "'axb' LIKE 'a!%b' ESCAPE '!', '' LIKE '%', 'abc' NOT LIKE '%c', 'ab' LIKE 'a_c'",
           "\"'héllo' LIKE 'h_llo'\",\"'hello' LIKE 'h%o'\",\"'hello' LIKE 'H%'\",\"'a%b' LIKE 'a!%b' ESCAPE '!'\","
           "\"'axb' LIKE 'a!%b' ESCAPE '!'\",\"'' LIKE '%'\",\"'abc' NOT LIKE '%c'\",\"'ab' LIKE 'a_c'\"\n"
           "true,true,false,true,false,true,false,false\n");
    EXPECT("SELECT 'a\\b' LIKE 'a\\b', 5 NOT BETWEEN 1 AND 3, 2 NOT BETWEEN 1 AND 3",
           "\"'a\\b' LIKE 'a\\b'\",\"5 NOT BETWEEN 1 AND 3\",\"2 NOT BETWEEN 1 AND 3\"\ntrue,true,false\n"); /* no default escape */
    CHECK(run("CREATE TABLE c (id INT64 PRIMARY KEY, s TEXT, ts TIMESTAMP)") == 0);
    CHECK(run("INSERT INTO c VALUES (1, NULL, '2026-01-02'), (2, 'x', NULL)") == 0);
    EXPECT("SELECT id, s LIKE '%', COALESCE(ts, '2026-05-06'), ts IN ('2026-01-02', '2027-01-01') FROM c ORDER BY id",
           "id,\"s LIKE '%'\",\"COALESCE(ts, '2026-05-06')\",\"ts IN ('2026-01-02', '2027-01-01')\"\n"
           "1,,2026-01-02 00:00:00,true\n2,true,2026-05-06 00:00:00,\n");
    EXPECT("SELECT COALESCE(NULL, NULL)", "ERR COALESCE of NULL alone has no type");
    EXPECT("SELECT CASE WHEN 1 > 0 THEN 1 ELSE 'x' END", "ERR a CASE of INT64 and TEXT");
    EXPECT("SELECT CASE WHEN 1 THEN 2 END", "ERR CASE WHEN takes a condition");
    EXPECT("SELECT 1 IN (1, 'a')", "ERR IN compares INT64 with TEXT");
    EXPECT("SELECT 'a' LIKE 'a!' ESCAPE '!'", "ERR a LIKE pattern ends in its escape character");
    EXPECT("SELECT 'b' LIKE 'a!' ESCAPE '!'", "ERR a LIKE pattern ends in its escape character"); /* whatever the text */
    EXPECT("SELECT 'a' LIKE 'a' ESCAPE 'xy'", "ERR a LIKE's ESCAPE is one character");
    EXPECT("SELECT 1 LIKE 1", "ERR LIKE takes TEXT values");
    EXPECT("SELECT 1 = NULL", "ERR NULL cannot be an operand");
    EXPECT("SELECT id FROM c WHERE id IN (SELECT id FROM c)", "id\n1\n2\n"); /* P2 S4: answered now (t_rset) */
    done(db);
}

/* CAST: exact or refused; a DECIMAL to fewer places rounds half away from zero (as the engines agree); text read by
 * the literal's own syntax; to TEXT the CLI's rendering */
static void t_sqlfn_cast(void)
{
    imdb_db *db = open_fresh();
    CHECK(db != NULL);
    if (!db) return;
    EXPECT("SELECT CAST(5 AS DECIMAL(5,2)), CAST(2.345 AS DECIMAL(5,2)), CAST(-2.345 AS DECIMAL(5,2)), CAST(4.00 AS INT64), "
           "CAST(3 AS FLOAT64), CAST(0.1e0 AS DECIMAL(18,17)), CAST(2.0e0 AS INT64)",
           "\"CAST(5 AS DECIMAL(5,2))\",\"CAST(2.345 AS DECIMAL(5,2))\",\"CAST(-2.345 AS DECIMAL(5,2))\",\"CAST(4.00 AS INT64)\","
           "\"CAST(3 AS FLOAT64)\",\"CAST(0.1e0 AS DECIMAL(18,17))\",\"CAST(2.0e0 AS INT64)\"\n"
           "5.00,2.35,-2.35,4,3,0.10000000000000001,2\n");
    EXPECT("SELECT CAST('42' AS INT64), CAST('-1.5' AS DECIMAL(4,2)), CAST('2.5e1' AS FLOAT64), CAST('TRUE' AS BOOL), "
           "CAST('2026-01-02 03:04:05' AS TIMESTAMP), CAST(NULL AS INT64)",
           "\"CAST('42' AS INT64)\",\"CAST('-1.5' AS DECIMAL(4,2))\",\"CAST('2.5e1' AS FLOAT64)\",\"CAST('TRUE' AS BOOL)\","
           "\"CAST('2026-01-02 03:04:05' AS TIMESTAMP)\",\"CAST(NULL AS INT64)\"\n42,-1.50,25,true,2026-01-02 03:04:05,\n");
    EXPECT("SELECT CAST(-5 AS TEXT) || '|' || CAST(1.50 AS TEXT) || '|' || CAST(FALSE AS TEXT) || '|' || CAST(2.5e0 AS TEXT)",
           "\"CAST(-5 AS TEXT) || '|' || CAST(1.50 AS TEXT) || '|' || CAST(FALSE AS TEXT) || '|' || CAST(2.5e0 AS TEXT)\"\n"
           "\"-5|1.50|false|2.5\"\n");
    EXPECT("SELECT CAST(2.5 AS INT64)", "ERR CAST to INT64 of a value with a fraction");
    EXPECT("SELECT CAST(2.5e0 AS INT64)", "ERR CAST to INT64 of a value with a fraction");
    EXPECT("SELECT CAST(123.45 AS DECIMAL(4,2))", "ERR exceeds DECIMAL(4,2)");
    EXPECT("SELECT CAST(' 42' AS INT64)", "ERR CAST: a text that is not a valid INT64");
    EXPECT("SELECT CAST('yes' AS BOOL)", "ERR CAST: a text that is not a valid BOOL");
    EXPECT("SELECT CAST(TRUE AS INT64)", "ERR CAST of BOOL to INT64 is not defined");
    EXPECT("SELECT CAST(1e300 AS INT64)", "ERR INT64 overflow");
    done(db);
}

/* SELECT without FROM (one row; a NULL item a TEXT NULL; no column, no aggregate), aliases (AS or not, the result's
 * name, ORDER BY by one, never WHERE), EXPLAIN SELECT 1 */
static void t_sqlfn_alias_nofrom(void)
{
    imdb_db *db = open_fresh();
    CHECK(db != NULL);
    if (!db) return;
    EXPECT_H("SELECT 1 AS x, NULL AS n, 'q' q", "x,n,q\n1,,\"q\"\n");
    EXPECT_H("SELECT a", "ERR a column needs FROM");
    EXPECT_H("SELECT COUNT(*)", "ERR an aggregate or a column needs FROM");
    EXPECT_H("SELECT * ", "ERR expected FROM");
    EXPECT_H("SELECT 1 ORDER BY 1", "ERR a SELECT without FROM computes one row");
    EXPECT_H("SELECT 1 x LIMIT 1", "ERR a SELECT without FROM computes one row");
    CHECK(run("CREATE TABLE t (id INT64 PRIMARY KEY, g INT64, s TEXT)") == 0);
    CHECK(run("INSERT INTO t VALUES (1, 2, 'b'), (2, 1, 'a'), (3, 1, NULL)") == 0);
    EXPECT_H("SELECT id AS k, UPPER(s) AS u FROM t ORDER BY u DESC", "k,u\n3,\n1,\"B\"\n2,\"A\"\n");
    EXPECT_H("SELECT g AS grp, COUNT(*) AS n, MAX(LOWER(s)) AS m FROM t GROUP BY g ORDER BY grp", "grp,n,m\n1,2,\"a\"\n2,1,\"b\"\n");
    EXPECT_H("SELECT id AS x FROM t WHERE x = 1", "ERR no column x");
    EXPECT_H("SELECT COUNT(*) AS total, SUM(g) AS s2 FROM t", "total,s2\n3,4\n");
    EXPECT_H("EXPLAIN SELECT 1", "item,detail\n\"path\",\"constant\"\n\"why\",\"no FROM: the expressions alone, computed once\"\n"
                               "\"estimate\",\"no row read\"\n\"output\",\"one row\"\n");
    done(db);
}

enum { N = 3000 };

/* every form in WHERE under each access path with cross_check on (the plans compared on every statement), rows in
 * segments and in memory, in a join too */
static void t_sqlfn_paths(void)
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
    imdb_buf_put_u8(&b, 0); /* a C string for run() */
    CHECK(!imdb_buf_check(&b, &g_e) && !run((const char *)b.p));
    b.len = 0;
    imdb_buf_put_str(&b, "INSERT INTO u VALUES ");
    for (int i = 1; i <= 300; i++) imdb_buf_printf(&b, "%s(%d, %d, 'w%d')", i > 1 ? ", " : "", i, i * 7, i % 5);
    imdb_buf_put_u8(&b, 0); /* a C string for run() */
    CHECK(!imdb_buf_check(&b, &g_e) && !run((const char *)b.p));
    imdb_buf_free(&b);
    CHECK(run("CREATE INDEX t_g ON t (g)") == 0);
    CHECK(run("CHECKPOINT") == 0);
    CHECK(run("UPDATE t SET s = 'Fresh' WHERE id % 10 = 0") == 0); /* versions in memory beside the segments */
    CHECK(run("SET cross_check = on") == 0);
    static const char *const q[] = {
        "SELECT COUNT(*) FROM t WHERE LOWER(s) LIKE 'abc%'",
        "SELECT COUNT(*) FROM t WHERE g IN (1, 3, 5) AND s NOT LIKE '%Q'",
        "SELECT COUNT(*) FROM t WHERE COALESCE(s, 'none') = 'none'",
        "SELECT COUNT(*) FROM t WHERE CASE WHEN g > 5 THEN d ELSE -d END > 10",
        "SELECT COUNT(*) FROM t WHERE ROUND(d, 1) BETWEEN 10 AND 20 OR LENGTH(s) = 5",
        "SELECT SUM(CAST(d AS DECIMAL(9,1))), MIN(UPPER(s)), MAX(SUBSTR(s, 2, 3)) FROM t WHERE g NOT IN (0, 2)",
        "SELECT g, COUNT(*), MAX(REPLACE(s, ' ', '_')) FROM t WHERE POSITION('c' IN s) > 0 GROUP BY g",
        "SELECT id, s || '!' FROM t WHERE id IN (5, 50, 500, 2999) ORDER BY LOWER(s), id",
        "SELECT COUNT(*) FROM t JOIN u ON t.id = u.tid WHERE UPPER(u.w) IN ('W1', 'W3') AND t.s LIKE '_bc%'",
    };
    static const char *const paths[] = {"auto", "scan", "store", "ordered", "index"};
    char first[sizeof q / sizeof *q][2048];
    for (size_t p = 0; p < sizeof paths / sizeof *paths; p++) {
        char set[64];
        snprintf(set, sizeof set, "SET access_path = %s", paths[p]);
        CHECK(run(set) == 0);
        for (size_t i = 0; i < sizeof q / sizeof *q; i++) {
            const char *got = csv(q[i]);
            if (!strncmp(got, "ERR ", 4)) {
                char m[1200];
                snprintf(m, sizeof m, "%s under %s: %s", q[i], paths[p], got);
                test_fail(__FILE__, __LINE__, m);
                continue;
            }
            if (!p) snprintf(first[i], sizeof first[i], "%s", got);
            else CHECK(!strcmp(first[i], got)); /* every path the same answer, each cross-checked within */
        }
    }
    CHECK(run("SET access_path = auto") == 0);
    done(db);
}

/* computed TEXT under a 1 MiB statement ceiling: per-row work never accumulates (the arena is released per row; an
 * aggregate's TEXT extreme is its own copy), whatever the rows' count */
static void t_sqlfn_memory(void)
{
    imdb_db *db = open_fresh();
    CHECK(db != NULL);
    if (!db) return;
    CHECK(run("CREATE TABLE m (id INT64 PRIMARY KEY, s TEXT)") == 0);
    imdb_buf b;
    imdb_buf_init(&b);
    for (int base = 0; base < 60000 && !g_e.code; base += 5000) {
        b.len = 0;
        imdb_buf_put_str(&b, "INSERT INTO m VALUES ");
        for (int i = base + 1; i <= base + 5000; i++)
            imdb_buf_printf(&b, "%s(%d, 'Some Mixed Case Text Of Forty Bytes %04d')", i > base + 1 ? ", " : "", i, i % 10000);
        imdb_buf_put_u8(&b, 0); /* a C string for run() */
    CHECK(!imdb_buf_check(&b, &g_e) && !run((const char *)b.p));
    }
    imdb_buf_free(&b);
    CHECK(run("SET statement_memory = 1048576") == 0); /* 60,000 lowered copies would be 2.4 MB */
    EXPECT("SELECT SUM(LENGTH(LOWER(s))) FROM m", "SUM(LENGTH(LOWER(s)))\n2400000\n");
    EXPECT("SELECT COUNT(CASE WHEN UPPER(s) LIKE '%0007' THEN 1 END) FROM m", "COUNT(CASE WHEN UPPER(s) LIKE '%0007' THEN 1 END)\n6\n");
    EXPECT("SELECT MIN(LOWER(s)), MAX(UPPER(s)) FROM m",
           "MIN(LOWER(s)),MAX(UPPER(s))\n\"some mixed case text of forty bytes 0000\",\"SOME MIXED CASE TEXT OF FORTY BYTES 9999\"\n");
    EXPECT("SELECT COUNT(*) FROM m WHERE LOWER(s) || '!' LIKE '%9!'", "COUNT(*)\n6000\n");
    CHECK(run("SET statement_memory = 0") == 0);
    done(db);
}

/* one LIKE whose match takes long (a % then 2,000 characters against 60,000): statement_timeout stops it inside the
 * match (the evaluator asks every 2^16 steps), and without the timeout it answers */
static void t_sqlfn_like_cancel(void)
{
    imdb_db *db = open_fresh();
    CHECK(db != NULL);
    if (!db) return;
    CHECK(run("CREATE TABLE l (id INT64 PRIMARY KEY, s TEXT)") == 0);
    imdb_buf b;
    imdb_buf_init(&b);
    imdb_buf_put_str(&b, "INSERT INTO l VALUES (1, '");
    for (int i = 0; i < 60000; i++) imdb_buf_put_u8(&b, 'a');
    imdb_buf_put_str(&b, "')");
    imdb_buf_put_u8(&b, 0); /* a C string for run() */
    CHECK(!imdb_buf_check(&b, &g_e) && !run((const char *)b.p));
    b.len = 0;
    imdb_buf_put_str(&b, "SELECT COUNT(*) FROM l WHERE s LIKE '%");
    for (int i = 0; i < 2000; i++) imdb_buf_put_u8(&b, 'a');
    imdb_buf_put_str(&b, "b'");
    imdb_buf_put_u8(&b, 0);
    CHECK(!imdb_buf_check(&b, &g_e));
    CHECK(run("SET statement_timeout = 1") == 0);
    int rc = run((const char *)b.p);
    CHECK(rc == IMDB_ERR_CANCELLED && strstr(g_e.msg, "statement timeout"));
    CHECK(run("SET statement_timeout = 0") == 0);
    CHECK(!strcmp(body(csv((const char *)b.p)), "0\n")); /* the rows: the header is "count" */
    imdb_buf_free(&b);
    done(db);
}

/* computed TEXT that outlives its row: ORDER BY and DISTINCT keys, OFFSET's window, a group's extreme, a join's keys,
 * a transaction's writes, each over 60,000 rows (a reset arena would still hold a small table's old bytes); an empty
 * extreme; answers known from the data (s's number is id % 10000, g is id % 7) */
static void t_sqlfn_keys(void)
{
    imdb_db *db = open_fresh();
    CHECK(db != NULL);
    if (!db) return;
    CHECK(run("CREATE TABLE k (id INT64 PRIMARY KEY, g INT64, s TEXT)") == 0);
    CHECK(run("CREATE TABLE j (id INT64 PRIMARY KEY, kid INT64)") == 0);
    imdb_buf b;
    imdb_buf_init(&b);
    for (int base = 0; base < 60000 && !g_e.code; base += 5000) {
        b.len = 0;
        imdb_buf_put_str(&b, "INSERT INTO k VALUES ");
        for (int i = base + 1; i <= base + 5000; i++)
            imdb_buf_printf(&b, "%s(%d, %d, 'Some Mixed Case Text Of Forty Bytes %04d')", i > base + 1 ? ", " : "", i, i % 7,
                            i % 10000);
        imdb_buf_put_u8(&b, 0);
        CHECK(!imdb_buf_check(&b, &g_e) && !run((const char *)b.p));
    }
    b.len = 0;
    imdb_buf_put_str(&b, "INSERT INTO j VALUES ");
    for (int i = 1; i <= 300; i++) imdb_buf_printf(&b, "%s(%d, %d)", i > 1 ? ", " : "", i, i * 199);
    imdb_buf_put_u8(&b, 0);
    CHECK(!imdb_buf_check(&b, &g_e) && !run((const char *)b.p));
    for (int pass = 0; pass < 2; pass++) { /* in memory, then in the lake (every image reloaded under tiny) */
        EXPECT("SELECT id FROM k ORDER BY LOWER(s) DESC, id LIMIT 6", "id\n9999\n19999\n29999\n39999\n49999\n59999\n");
        EXPECT("SELECT id FROM k ORDER BY LOWER(s), id OFFSET 59990",
               "id\n29998\n39998\n49998\n59998\n9999\n19999\n29999\n39999\n49999\n59999\n");
        EXPECT("SELECT DISTINCT UPPER(s) FROM k ORDER BY 1 LIMIT 2",
               "UPPER(s)\n\"SOME MIXED CASE TEXT OF FORTY BYTES 0000\"\n\"SOME MIXED CASE TEXT OF FORTY BYTES 0001\"\n");
        EXPECT("SELECT DISTINCT UPPER(s) FROM k ORDER BY 1 OFFSET 9998",
               "UPPER(s)\n\"SOME MIXED CASE TEXT OF FORTY BYTES 9998\"\n\"SOME MIXED CASE TEXT OF FORTY BYTES 9999\"\n");
        imdb_result r;
        imdb_err_clear(&g_e);
        CHECK(imdb_exec_one(&g_s, "SELECT DISTINCT LOWER(s) FROM k", strlen("SELECT DISTINCT LOWER(s) FROM k"), NULL, 0, &r,
                            &g_e) == 0);
        if (!g_e.code) {
            CHECK(r.nrows == 10000);
            imdb_result_free(&r);
        }
        /* a group's extreme, ordered: groups 0..5 hold a 9999, group 6's largest is 9998 (19998 = 7 * 2856 + 6) */
        static char want[1024];
        size_t o = (size_t)snprintf(want, sizeof want, "g,mx\n");
        for (int g = 0; g < 6; g++) o += (size_t)snprintf(want + o, sizeof want - o, "%d,\"some mixed case text of forty bytes 9999\"\n", g);
        snprintf(want + o, sizeof want - o, "6,\"some mixed case text of forty bytes 9998\"\n");
        EXPECT("SELECT g, MAX(LOWER(s)) AS mx FROM k GROUP BY g ORDER BY mx DESC, g", want);
        /* a join's keys: j's kid = 199 i; the three largest kid % 10000, ties by k.id */
        int best[3] = {0, 0, 0};
        for (int i = 1; i <= 300; i++) {
            int kid = 199 * i, c = kid;
            for (int t = 0; t < 3; t++) {
                int bk = best[t];
                if (!bk || c % 10000 > bk % 10000 || (c % 10000 == bk % 10000 && c < bk)) {
                    best[t] = c;
                    c = bk;
                    if (!c) break;
                }
            }
        }
        snprintf(want, sizeof want, "id\n%d\n%d\n%d\n", best[0], best[1], best[2]);
        CHECK(run("SET cross_check = on") == 0); /* both join plans compute the keys (the hash join's build side too) */
        EXPECT("SELECT k.id FROM k JOIN j ON k.id = j.kid ORDER BY LOWER(k.s) DESC, k.id LIMIT 3", want);
        CHECK(run("SET cross_check = off") == 0);
        EXPECT("SELECT MIN(CASE WHEN id = 1 THEN '' ELSE s END), MAX(CASE WHEN id > 0 THEN '' END) FROM k",
               "x,y\n\"\",\"\"\n"); /* an empty extreme */
        if (!pass) {
            CHECK(run("CHECKPOINT") == 0);
        }
    }
    /* a transaction's writes of computed TEXT, read back after statements that churn the arena, and after COMMIT */
    CHECK(run("BEGIN") == 0);
    CHECK(run("UPDATE k SET s = UPPER(s) || '!' WHERE id <= 100") == 0);
    EXPECT("SELECT COUNT(*) FROM k WHERE LOWER(s) LIKE '%9'", "COUNT(*)\n5990\n");
    EXPECT("SELECT s FROM k WHERE id IN (1, 100, 101) ORDER BY id",
           "s\n\"SOME MIXED CASE TEXT OF FORTY BYTES 0001!\"\n\"SOME MIXED CASE TEXT OF FORTY BYTES 0100!\"\n"
           "\"Some Mixed Case Text Of Forty Bytes 0101\"\n");
    CHECK(run("COMMIT") == 0);
    EXPECT("SELECT s FROM k WHERE id IN (1, 100, 101) ORDER BY id",
           "s\n\"SOME MIXED CASE TEXT OF FORTY BYTES 0001!\"\n\"SOME MIXED CASE TEXT OF FORTY BYTES 0100!\"\n"
           "\"Some Mixed Case Text Of Forty Bytes 0101\"\n");
    imdb_buf_free(&b);
    done(db);
}

const test_case sqlfn_tests[] = {
    {"sqlfn_numeric", t_sqlfn_numeric},
    {"sqlfn_text", t_sqlfn_text},
    {"sqlfn_cond", t_sqlfn_cond},
    {"sqlfn_cast", t_sqlfn_cast},
    {"sqlfn_alias_nofrom", t_sqlfn_alias_nofrom},
    {"sqlfn_paths", t_sqlfn_paths},
    {"sqlfn_memory", t_sqlfn_memory},
    {"sqlfn_like_cancel", t_sqlfn_like_cancel},
    {"sqlfn_keys", t_sqlfn_keys},
};
const size_t sqlfn_ntests = sizeof sqlfn_tests / sizeof *sqlfn_tests;
