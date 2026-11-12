/* P2 S7b: the auditor's view binder (tools/audit/abind.c) against the engine. Each body of a corpus that reaches every
 * typing rule at its edges (literals, arithmetic's scales, every function, CASE, COALESCE, NULLIF and CAST, aggregates
 * plain, DISTINCT, FILTERed and over windows, every window function, comparisons as items, joins of every kind and
 * USING's kept side, set operations unified, WITH, WITH RECURSIVE and column lists, derived tables, subqueries of every
 * kind and depth, correlated ones, views over views, a WITH or a derived table named as a table) is created as a view by
 * the engine; the binder, given the view's logged text and the engine's catalog, must yield exactly the columns' types
 * and scales and the dependencies the engine logged. Then the binder's own refusals: what the engine refuses in a view,
 * and a column list's count of names. */
#include <stdarg.h>
#include <stdlib.h>

#include "../../src/db.h"
#include "../../src/log.h"
#include "../../src/sql.h"
#include "../../tools/audit/abind.h"
#include "thelp.h"

static imdb_session g_s;

static int run(const char *sql)
{
    imdb_result r;
    imdb_err_clear(&g_e);
    int rc = imdb_exec_one(&g_s, sql, strlen(sql), NULL, 0, &r, &g_e);
    if (!rc) imdb_result_free(&r);
    return rc;
}

/* the engine's catalog, as the auditor's model holds it: a live table's columns, a live view's logged ones */
static bool eng_lookup(void *arg, const char *name, ab_rel *out)
{
    imdb_db *db = arg;
    static ab_col cols[IMDB_MAX_COLS];
    imdb_table *t = imdb_table_by_name(db, name);
    if (t) {
        for (uint16_t c = 0; c < t->s.ncols; c++) {
            snprintf(cols[c].name, sizeof cols[c].name, "%s", t->s.cols[c].name);
            cols[c].type = t->s.cols[c].type;
            cols[c].scale = t->s.cols[c].type == IMDB_T_DECIMAL ? t->s.cols[c].scale : 0;
        }
        *out = (ab_rel){IMDB_VIEWDEP_TABLE, t->s.id, t->s.ncols, cols};
        return true;
    }
    imdb_view *v = imdb_view_by_name(db, name);
    if (v && v->def) {
        for (uint16_t c = 0; c < v->def->ncols; c++) {
            snprintf(cols[c].name, sizeof cols[c].name, "%s", v->def->cols[c].name);
            cols[c].type = v->def->cols[c].type;
            cols[c].scale = v->def->cols[c].scale;
        }
        *out = (ab_rel){IMDB_VIEWDEP_VIEW, v->id, v->def->ncols, cols};
        return true;
    }
    return false;
}

static int mis(char *why, size_t n, const char *fmt, ...) __attribute__((format(printf, 3, 4)));
static int mis(char *why, size_t n, const char *fmt, ...) /* the reason, and -1 */
{
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(why, n, fmt, ap);
    va_end(ap);
    return -1;
}

/* the view the engine made, bound by the binder: the same types, scales and dependencies (0), else a reason */
static int same(imdb_db *db, const char *name, char *why, size_t n)
{
    imdb_view *v = imdb_view_by_name(db, name);
    if (!v || !v->def) return mis(why, n, "no view %s", name);
    const imdb_viewdef *d = v->def;
    ab_result *r = calloc(1, sizeof *r);
    char e[256];
    int rc = 0;
    if (!r) return mis(why, n, "out of memory");
    if (ab_bind(d->text, d->text_len, eng_lookup, db, r, e, sizeof e)) rc = mis(why, n, "the binder refused it: %s", e);
    else if (r->ncols != d->ncols) rc = mis(why, n, "%u columns, the engine's %u", r->ncols, d->ncols);
    for (uint16_t c = 0; !rc && c < d->ncols; c++)
        if (r->cols[c].type != d->cols[c].type || r->cols[c].scale != d->cols[c].scale)
            rc = mis(why, n, "column %u (%s): type %u scale %u, the engine's type %u scale %u", c + 1u, d->cols[c].name,
                          r->cols[c].type, r->cols[c].scale, d->cols[c].type, d->cols[c].scale);
    if (!rc && r->ndeps != d->ndeps) rc = mis(why, n, "%u dependencies, the engine's %u", r->ndeps, d->ndeps);
    for (uint16_t k = 0; !rc && k < d->ndeps; k++)
        if (r->dep_kind[k] != d->deps[k].kind || r->dep_id[k] != d->deps[k].id)
            rc = mis(why, n, "dependency %u: %u/%u, the engine's %u/%u", k + 1u, r->dep_kind[k], r->dep_id[k],
                          d->deps[k].kind, d->deps[k].id);
    free(r);
    return rc;
}

static const char *const g_body[] = {
    /* literals and columns */
    "SELECT 1 AS a, 1.50 AS b, 1e3 AS c, 'x' AS d, TRUE AS e, TIMESTAMP '2026-01-01 00:00:00' AS f, NULL AS g",
    "SELECT id, g, d, f, s, k, ts, e FROM t",
    "SELECT t.id, t.e AS x FROM t",
    "SELECT g x, s y FROM t",
    "SELECT 0.000 AS z, 00012.5 AS w, -7 AS m, -1.25 AS n, +3 AS p",
    /* arithmetic's types and scales */
    "SELECT g + 1 AS a, g + d AS b, d * e AS c, d / e AS q, d % 2 AS r, f + g AS s2, -d AS n, g / 2 AS i, d / 3 AS j FROM t",
    "SELECT e * e AS a, (d + e) * 2 AS b, d - 0.125 AS c, g * 1.0 AS m, g % 3 AS r, (g + 1) * (g - 1) AS p FROM t",
    "SELECT d / e / 2 AS deep FROM t",
    /* functions */
    "SELECT ABS(d) AS a, ABS(g) AS b, ABS(f) AS c, SIGN(d) AS sd, CEIL(d) AS ce, CEILING(e) AS cg, FLOOR(f) AS fl FROM t",
    "SELECT ROUND(d) AS a, ROUND(d, 1) AS b, ROUND(e, 6) AS c, ROUND(f) AS r, ROUND(g, 2) AS i, MOD(g, 3) AS m, MOD(d, e) AS md FROM t",
    "SELECT LENGTH(s) AS l, CHAR_LENGTH(s) AS cl, SUBSTR(s, 1, 2) AS ss, SUBSTRING(s, 2) AS s2, LOWER(s) AS lo, UPPER(s) AS up FROM t",
    "SELECT TRIM(s) AS a, LTRIM(s) AS b, RTRIM(s) AS c, REPLACE(s, 'a', 'b') AS r, POSITION('a' IN s) AS p, s || 'x' AS cc FROM t",
    "SELECT COALESCE(g, 0) AS a, COALESCE(d, 0) AS b, COALESCE(NULL, g) AS c, COALESCE(g, d, 2) AS m, NULLIF(g, 0) AS n, NULLIF(s, 'x') AS ns FROM t",
    "SELECT COALESCE(ts, '2026-01-01 00:00:00') AS a, NULLIF(ts, '2026-01-01 00:00:00') AS b FROM t",
    /* CASE and CAST */
    "SELECT CASE WHEN g > 0 THEN g ELSE d END AS a, CASE WHEN g > 0 THEN 1.5 END AS b, CASE g WHEN 1 THEN 'a' ELSE 'b' END AS c FROM t",
    "SELECT CASE WHEN k THEN ts ELSE '2026-01-01 00:00:00' END AS a, CASE WHEN g = 1 THEN NULL ELSE e END AS b FROM t",
    "SELECT CAST(g AS DECIMAL(10,3)) AS a, CAST(d AS INT64) AS b, CAST(g AS TEXT) AS c, CAST(s AS BIGINT) AS i, CAST(NULL AS FLOAT64) AS f FROM t",
    "SELECT CAST(k AS TEXT) AS a, CAST(ts AS TEXT) AS b, CAST(f AS DECIMAL(18,6)) AS c, CAST(d AS DOUBLE PRECISION) AS dp, CAST(g AS NUMERIC(5)) AS n FROM t",
    /* comparisons as values */
    "SELECT g > 0 AS a, s LIKE 'a%' AS b, g IN (1, 2) AS c, g BETWEEN 1 AND 2 AS d2, s IS NULL AS e2, NOT k AS f2, g NOT IN (3) AS g2 FROM t",
    "SELECT EXISTS (SELECT 1 FROM u) AS ex, g IN (SELECT tid FROM u) AS ins, (g > 1 AND k) OR s IS NOT NULL AS c FROM t",
    /* aggregates */
    "SELECT COUNT(*) AS c, SUM(g) AS sg, SUM(d) AS sd, SUM(f) AS sf, MIN(s) AS ms, MAX(ts) AS mt, COUNT(g) AS cg FROM t",
    "SELECT AVG(g) AS ag, AVG(d) AS ad, AVG(e) AS ae, AVG(f) AS af FROM t",
    "SELECT COUNT(DISTINCT g) AS a, SUM(g) FILTER (WHERE g > 0) AS b, SUM(d * 2) AS c, SUM(d * d) AS dd, MAX(d + e) AS me FROM t",
    "SELECT g, COUNT(*) AS c FROM t GROUP BY g",
    "SELECT g % 2 AS p, SUM(d) AS sd, AVG(d) AS a FROM t GROUP BY g % 2",
    "SELECT g, MAX(d) AS md FROM t GROUP BY g HAVING COUNT(*) > 1",
    "SELECT LOWER(s) AS ls, COUNT(*) AS n FROM t GROUP BY LOWER(s)",
    /* windows */
    "SELECT id, ROW_NUMBER() OVER (ORDER BY id) AS rn, RANK() OVER (PARTITION BY g ORDER BY id) AS rk, DENSE_RANK() OVER (ORDER BY g) AS dr, NTILE(3) OVER (ORDER BY id) AS nt FROM t",
    "SELECT LAG(d) OVER (ORDER BY id) AS a, LAG(g, 1, 0.5) OVER (ORDER BY id) AS b, LEAD(s) OVER (ORDER BY id) AS c, FIRST_VALUE(f) OVER (ORDER BY id) AS fv, LAST_VALUE(e) OVER (ORDER BY id) AS lv FROM t",
    "SELECT SUM(d) OVER (PARTITION BY g) AS a, AVG(g) OVER () AS b, COUNT(*) OVER () AS c, MIN(s) OVER (ORDER BY id ROWS BETWEEN 1 PRECEDING AND 1 FOLLOWING) AS m, AVG(e) OVER (ORDER BY id) AS ae FROM t",
    "SELECT LAG(NULL) OVER (ORDER BY id) AS a, LEAD(g, 2, NULL) OVER (ORDER BY id) AS b FROM t",
    /* joins */
    "SELECT t.id, u.v FROM t JOIN u ON u.tid = t.id",
    "SELECT t.id, u.v, u.d FROM t LEFT JOIN u ON u.tid = t.id",
    "SELECT t.id, u.v FROM t RIGHT OUTER JOIN u ON u.tid = t.id",
    "SELECT t.id AS ti, u.id AS ui FROM t FULL JOIN u ON u.tid = t.id",
    "SELECT t.g, u.v FROM t CROSS JOIN u",
    "SELECT a.id, b.v FROM t AS a, u AS b WHERE b.tid = a.id",
    "SELECT s, t.g, u.d FROM t JOIN u USING (s)",
    "SELECT s, u.v FROM t RIGHT JOIN u USING (s)",
    "SELECT id, t.d AS td FROM t LEFT JOIN u USING (id)",
    "SELECT t.id, w.v FROM t INNER JOIN u AS w ON w.tid = t.id AND w.v > 1",
    /* set operations */
    "SELECT g FROM t UNION SELECT v FROM u",
    "SELECT d FROM t UNION SELECT tid FROM u",
    "SELECT d FROM t UNION ALL SELECT d FROM u",
    "SELECT g AS x FROM t INTERSECT SELECT v FROM u",
    "SELECT g FROM t EXCEPT SELECT v FROM u",
    "(SELECT g FROM t) UNION (SELECT v FROM u) ORDER BY 1 LIMIT 5",
    "SELECT g AS x FROM t UNION SELECT v FROM u INTERSECT SELECT tid FROM u ORDER BY x",
    "SELECT e FROM t UNION SELECT d FROM t UNION SELECT 1 FROM u",
    /* WITH */
    "WITH a AS (SELECT g, d FROM t) SELECT g, d FROM a",
    "WITH a (x, y) AS (SELECT g, d FROM t) SELECT x, y FROM a",
    "WITH a AS (SELECT g FROM t), b AS (SELECT g FROM a) SELECT g FROM b",
    "WITH RECURSIVE r (n) AS (SELECT 1 UNION ALL SELECT n + 1 FROM r WHERE n < 5) SELECT n FROM r",
    "WITH RECURSIVE w (id, depth) AS (SELECT id, 0 FROM t WHERE id = 1 UNION ALL SELECT u.id, w.depth + 1 FROM u JOIN w ON u.tid = w.id WHERE w.depth < 3) SELECT id, depth FROM w",
    "WITH a AS (SELECT d FROM t) SELECT d FROM a UNION SELECT e FROM t",
    "WITH t AS (SELECT v AS g FROM u) SELECT g FROM t",
    /* derived tables */
    "SELECT x FROM (SELECT g AS x FROM t) AS q",
    "SELECT q.m FROM (SELECT MAX(d) AS m FROM t) q",
    "SELECT a.id, b.v FROM (SELECT id FROM t) AS a JOIN (SELECT tid, v FROM u) AS b ON b.tid = a.id",
    "SELECT COUNT(*) AS n FROM (SELECT g + 1, s FROM t) AS q",
    "SELECT t.v FROM (SELECT v FROM u) AS t",
    "SELECT n FROM (SELECT AVG(d) AS n FROM t) AS q",
    "SELECT avg_d FROM (SELECT AVG(d), COUNT(*) FROM t) AS q",
    "SELECT sum_g FROM (SELECT SUM(g) FROM t) AS q",
    /* subqueries */
    "SELECT id, (SELECT MAX(u.v) FROM u WHERE u.tid = t.id) AS m FROM t",
    "SELECT id, (SELECT MAX(d) FROM u) AS md FROM t",
    "SELECT id FROM t WHERE EXISTS (SELECT * FROM u WHERE u.tid = t.id)",
    "SELECT id FROM t WHERE g IN (SELECT tid FROM u WHERE v IN (SELECT g FROM t WHERE id > 1))",
    "SELECT id, CASE WHEN id < 0 THEN (SELECT MAX(v) FROM u) ELSE 0 END AS c FROM t",
    "SELECT id FROM t WHERE g > (SELECT COUNT(*) FROM u) OR NOT EXISTS (SELECT 1 FROM u WHERE u.v = t.g)",
    "SELECT (SELECT COUNT(*) FROM t) AS ct, (SELECT MIN(s) FROM u) AS mu",
    /* the rest */
    "SELECT DISTINCT s FROM t",
    "SELECT id FROM t ORDER BY id DESC LIMIT 3 OFFSET 1",
    "SELECT id FROM t WITH (NOLOCK) WHERE g = 1",
    "SELECT id, s FROM t WHERE s LIKE 'a!%%' ESCAPE '!' -- a comment\n  AND g BETWEEN -1 AND 9",
    /* F3b: DATE and TIME: literals, arithmetic, CASTs each way, aggregates, a string literal typed by its neighbour */
    "SELECT DATE '2026-11-09' AS a, TIME '01:02:03.5' AS b",
    "SELECT id, d, tm, d + 1 AS n, 1 + d AS n2, d - 1 AS p, d - d AS z, d + tm AS at, tm + d AS at2 FROM dt",
    "SELECT CAST(ts AS DATE) AS a, CAST(ts AS TIME) AS b, CAST(d AS TIMESTAMP) AS c, CAST(d AS TEXT) AS e2, "
    "CAST('2026-01-01' AS DATE) AS f, CAST('01:00:00' AS TIME) AS g2 FROM dt",
    "SELECT MIN(d) AS a, MAX(tm) AS b, COUNT(DISTINCT d) AS c FROM dt",
    "SELECT id FROM dt WHERE d BETWEEN '2026-01-01' AND '2026-12-31' AND tm > '12:00:00'",
    "SELECT COALESCE(d, '2000-01-01') AS c, CASE WHEN id > 0 THEN tm ELSE '00:00:00' END AS t2 FROM dt",
    "SELECT d FROM dt UNION SELECT DATE '2026-01-01'",
    "SELECT d, LAG(d) OVER (ORDER BY id) AS pd, MAX(tm) OVER (PARTITION BY d) AS mt FROM dt",
    /* F3c: a CAST to VARCHAR(n) types a TEXT (the length the run's rule) */
    "SELECT CAST(s AS VARCHAR(10)) AS a, CAST(g AS CHARACTER VARYING(3)) AS b, CAST(s AS VARCHAR) AS c FROM t",
    /* F3f: INTERVAL: every + and - rule both ways round with TIMESTAMP and DATE, TIMESTAMP - TIMESTAMP and TIMESTAMPTZ -
     * TIMESTAMPTZ, the negation; a string beside one in a comparison, CASE, COALESCE, NULLIF and IN; MIN, MAX, SUM, LAG,
     * a moving SUM, CAST both ways; a derived table and UNION ALL carry it */
    "SELECT iv + iv AS a, iv - INTERVAL '1 day' AS b, -iv AS c, ts + iv AS d, iv + ts AS e2, ts - iv AS f, d + iv AS g2, "
    "iv + d AS h, d - iv AS i2, ts - ts AS j, tz - tz AS k2 FROM ivt",
    "SELECT INTERVAL '1 mon 2 days' AS a, CAST('1 day' AS INTERVAL) AS b, CAST(iv AS TEXT) AS c FROM ivt",
    "SELECT id FROM ivt WHERE iv > '1 day' AND iv IN ('1 mon', INTERVAL '30 days') AND iv BETWEEN '0 days' AND '1 year'",
    "SELECT CASE WHEN id > 0 THEN iv ELSE '0 days' END AS a, COALESCE(iv, '1 day') AS b, NULLIF(iv, '30 days') AS c FROM ivt",
    "SELECT MIN(iv) AS a, MAX(iv) AS b, SUM(iv) AS c, COUNT(iv) AS e2, SUM(iv + INTERVAL '1 day') AS f FROM ivt",
    "SELECT id, LAG(iv) OVER (ORDER BY id) AS a, SUM(iv) OVER (ORDER BY id ROWS BETWEEN 1 PRECEDING AND CURRENT ROW) AS b, "
    "MIN(iv) OVER (ORDER BY id) AS c FROM ivt",
    "SELECT x FROM (SELECT iv AS x FROM ivt UNION ALL SELECT INTERVAL '1 day') AS q",
    "SELECT a.id FROM ivt AS a JOIN ivt AS b ON a.iv = b.iv",
};
#define NBODY (sizeof g_body / sizeof *g_body)

static imdb_db *setup(void)
{
    const char *dir = test_tmpdir();
    imdb_err e = {0};
    if (imdb_init(dir, false, NULL, &e)) return NULL;
    imdb_db *db = open_db(dir);
    if (!db) return NULL;
    imdb_session_init(&g_s, db);
    if (run("CREATE TABLE t (id INT64 PRIMARY KEY, g INT64, d DECIMAL(12,2), f FLOAT64, s TEXT, k BOOL, ts TIMESTAMP, e DECIMAL(18,4))") ||
        run("CREATE TABLE u (id INT64 PRIMARY KEY, tid INT64, v INT64, s TEXT, d DECIMAL(10,3))") ||
        run("CREATE TABLE dt (id INT64 PRIMARY KEY, d DATE, tm TIME, ts TIMESTAMP)") || /* F3b */
        run("CREATE TABLE ivt (id INT64 PRIMARY KEY, iv INTERVAL, ts TIMESTAMP, tz TIMESTAMPTZ, d DATE)") || /* F3f */
        run("INSERT INTO ivt VALUES (1, '1 mon', '2026-01-31 00:00:00', '2026-01-31 00:00:00+00', '2026-01-31')") ||
        run("INSERT INTO dt VALUES (1, '2026-11-09', '12:30:00', '2026-11-09 12:30:00')") ||
        run("INSERT INTO t VALUES (1, 1, 1.25, 0.5, 'ab', TRUE, TIMESTAMP '2026-01-01 00:00:00', 2.5)") ||
        run("INSERT INTO u VALUES (1, 1, 7, 'x', 1.125)")) {
        imdb_session_close(&g_s);
        imdb_close(db);
        return NULL;
    }
    return db;
}

static void t_abind_corpus(void)
{
    imdb_db *db = setup();
    CHECK(db);
    if (!db) return;
    char why[512], q[1024], m[1600];
    unsigned made = 0;
    for (size_t i = 0; i < NBODY; i++) {
        char name[32];
        snprintf(name, sizeof name, "cv%zu", i);
        snprintf(q, sizeof q, "CREATE VIEW %s AS %s", name, g_body[i]);
        if (run(q)) { /* the corpus holds what the engine takes: a body it refuses is the corpus's fault */
            snprintf(m, sizeof m, "the engine refused: %s\n      %s", g_body[i], g_e.msg);
            test_fail(__FILE__, __LINE__, m);
            continue;
        }
        made++;
        if (same(db, name, why, sizeof why)) {
            snprintf(m, sizeof m, "%s\n      %s", g_body[i], why);
            test_fail(__FILE__, __LINE__, m);
        }
        snprintf(q, sizeof q, "DROP VIEW %s", name);
        CHECK(run(q) == 0);
    }
    CHECK(made == NBODY);
    imdb_session_close(&g_s);
    imdb_close(db);
}

/* views over views: a view's columns are its logged ones, its dependencies direct (the views it names, never theirs) */
static void t_abind_views_over_views(void)
{
    imdb_db *db = setup();
    CHECK(db);
    if (!db) return;
    static const char *const V[][2] = {
        {"base1", "SELECT id, d, s FROM t"},
        {"over1", "SELECT b.id, b.d * 2 AS d2, u.v FROM base1 AS b JOIN u ON u.tid = b.id"},
        {"over2", "SELECT d2, (SELECT MAX(d) FROM base1) AS mx FROM over1"},
        {"over3", "WITH base1 AS (SELECT 1.5 AS d) SELECT d FROM base1"},
        {"over4", "SELECT x.d2 + over2.mx AS z FROM over1 AS x, over2"},
    };
    char why[512], q[1024], m[1600];
    for (size_t i = 0; i < sizeof V / sizeof *V; i++) {
        snprintf(q, sizeof q, "CREATE VIEW %s AS %s", V[i][0], V[i][1]);
        if (run(q)) {
            snprintf(m, sizeof m, "the engine refused: %s\n      %s", V[i][1], g_e.msg);
            test_fail(__FILE__, __LINE__, m);
            continue;
        }
        if (same(db, V[i][0], why, sizeof why)) {
            snprintf(m, sizeof m, "%s\n      %s", V[i][1], why);
            test_fail(__FILE__, __LINE__, m);
        }
    }
    CHECK(run("CREATE VIEW listed (a, b, c) AS SELECT id, d, s FROM base1") == 0); /* the names are the list's */
    CHECK(same(db, "listed", why, sizeof why) == 0);
    imdb_session_close(&g_s);
    imdb_close(db);
}

/* what the engine refuses in a view the binder refuses too, each for its reason */
static void t_abind_refusals(void)
{
    imdb_db *db = setup();
    CHECK(db);
    if (!db) return;
    static const char *const R[][2] = {
        {"SELECT * FROM t", "*"},
        {"SELECT id FROM t FOR UPDATE", "FOR UPDATE"},
        {"SELECT id FROM t AS OF 1", "AS OF"},
        {"SELECT $1 AS p", "parameter"},
        {"SELECT id FROM nosuch", "no table nosuch"},
        {"SELECT nosuch FROM t", "no column nosuch"},
        {"SELECT e * e * e * e * e * e * e * e * e * e AS x FROM t", "more than 38 decimal places"}, /* F3e: 38 places a row set's */
        {"SELECT x FROM (SELECT g AS x, d AS x FROM t) AS q", "two columns x"},
        {"SELECT s + 1 AS x FROM t", "arithmetic"},
        {"SELECT f % 2 AS x FROM t", "FLOAT64"},
        {"SELECT CASE WHEN g > 0 THEN s ELSE g END AS x FROM t", "not converted"},
        {"SELECT g FROM t UNION SELECT s FROM u", "not converted"},
        {"SELECT g FROM t UNION SELECT v, s FROM u", "columns"},
        {"SELECT id FROM t JOIN u ON u.tid = t.id", "both tables"},
        {"SELECT CAST(k AS INT64) AS x FROM t", "CAST"},
        {"SELECT COALESCE(NULL, NULL) AS x", "no type"},
        {"INSERT INTO t VALUES (9)", "query"},
        {"SELECT id FROM t; SELECT 1", "end of the query"},
        {"SELECT ROUND(f, 2) AS x FROM t", "ROUND"},
        {"SELECT 1 AS a WHERE 1 = 1", "one row"},
        {"SELECT tm - tm AS x FROM dt", "date arithmetic"}, /* F3b */
        {"SELECT d * 2 AS x FROM dt", "date arithmetic"},
        {"SELECT d + 1.5 AS x FROM dt", "date arithmetic"},
        {"SELECT CAST(tm AS DATE) AS x FROM dt", "CAST"},
        {"SELECT CAST(d AS TIME) AS x FROM dt", "CAST"},
        {"SELECT CAST(d AS INT64) AS x FROM dt", "CAST"},
        {"SELECT date_trunc('day', d) AS x FROM dt", "date_trunc"},
        {"SELECT CASE WHEN id > 0 THEN d ELSE ts END AS x FROM dt", "not converted"},
        {"SELECT CAST(s AS VARCHAR(0)) AS x FROM t", "VARCHAR(n) needs"}, /* F3c */
        {"SELECT CAST(s AS VARCHAR(65536)) AS x FROM t", "VARCHAR(n) needs"},
        {"SELECT iv * 2 AS x FROM ivt", "interval arithmetic"}, /* F3f */
        {"SELECT iv + 1 AS x FROM ivt", "interval arithmetic"},
        {"SELECT iv - ts AS x FROM ivt", "interval arithmetic"},
        {"SELECT tz + iv AS x FROM ivt", "interval arithmetic"},
        {"SELECT CAST(iv AS INT64) AS x FROM ivt", "CAST"},
        {"SELECT CASE WHEN id > 0 THEN iv ELSE ts END AS x FROM ivt", "not converted"},
        {"SELECT AVG(iv) AS x FROM ivt", "SUM and AVG"},
        /* fuzz_abind's find (2026-11-09): a window function inside a window's keys overflowed them */
        {"SELECT LAG(d, 1) OVER (PARTITION BY s, LAG(d, 6) OVER (PARTITION BY g)) AS x FROM t",
         "a window function inside a window's definition"},
    };
    char e[256], m[600];
    ab_result *r = calloc(1, sizeof *r);
    CHECK(r);
    if (!r) return;
    for (size_t i = 0; i < sizeof R / sizeof *R; i++) {
        int rc = ab_bind(R[i][0], strlen(R[i][0]), eng_lookup, db, r, e, sizeof e);
        if (rc == 0 || !strstr(e, R[i][1])) {
            snprintf(m, sizeof m, "%s\n      want a refusal holding: %s\n      got: %s", R[i][0], R[i][1], rc ? e : "(bound)");
            test_fail(__FILE__, __LINE__, m);
        }
    }
    /* bounds: a hostile text costs what its length allows, and an expression 65 high is refused, not recursed */
    char deep[4096];
    size_t k = 0;
    k += (size_t)snprintf(deep + k, sizeof deep - k, "SELECT ");
    for (int i = 0; i < 70; i++) deep[k++] = '(';
    deep[k++] = '1';
    for (int i = 0; i < 70; i++) deep[k++] = ')';
    k += (size_t)snprintf(deep + k, sizeof deep - k, " AS x");
    CHECK(ab_bind(deep, k, eng_lookup, db, r, e, sizeof e) != 0 && strstr(e, "deeper"));
    char *many = calloc(1, 70000);
    CHECK(many);
    if (many) { /* 65,536 bytes is a view's largest text; past it refused before any parse */
        memset(many, ' ', 69999);
        memcpy(many, "SELECT 1 AS x", 13);
        CHECK(ab_bind(many, 69999, eng_lookup, db, r, e, sizeof e) != 0);
        CHECK(ab_bind(many, 65536, eng_lookup, db, r, e, sizeof e) == 0 && r->ncols == 1 && r->cols[0].type == IMDB_T_INT64);
        free(many);
    }
    free(r);
    imdb_session_close(&g_s);
    imdb_close(db);
}

const test_case abind_tests[] = {
    {"abind_corpus", t_abind_corpus},
    {"abind_views_over_views", t_abind_views_over_views},
    {"abind_refusals", t_abind_refusals},
};
const size_t abind_ntests = sizeof abind_tests / sizeof *abind_tests;
