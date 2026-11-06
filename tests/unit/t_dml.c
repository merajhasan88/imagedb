/* P2 S8 (docs/plan-p2.md): INSERT ... query. Each form inserts exactly the rows its query answers at the statement's
 * snapshot (a differential: the query's answer before, the target's rows after), in memory and after a CHECKPOINT,
 * cross-checked; the assignment rules at their edges; a source reading the target, the transaction's own rows, a
 * failed statement leaving nothing; a write's reading under the statement's memory ceiling, never left set after it;
 * every refusal. */
#include <stdlib.h>

#include "../../src/db.h"
#include "../../src/sql.h"
#include "thelp.h"

static imdb_session g_s;
static char g_out[1 << 18], g_out2[1 << 18];

static const char *csv_to(const char *sql, char *out, size_t cap)
{
    imdb_result r;
    imdb_err_clear(&g_e);
    if (imdb_exec_one(&g_s, sql, strlen(sql), NULL, 0, &r, &g_e)) {
        snprintf(out, cap, "ERR %s", g_e.msg);
        return out;
    }
    imdb_buf b;
    imdb_buf_init(&b);
    if (r.has_rows) imdb_result_render(&r, true, &b);
    else imdb_buf_put_str(&b, r.status);
    if (imdb_buf_check(&b, &g_e)) snprintf(out, cap, "ERR render");
    else snprintf(out, cap, "%.*s", (int)b.len, (const char *)b.p);
    imdb_buf_free(&b);
    imdb_result_free(&r);
    return out;
}
static const char *csv(const char *sql) { return csv_to(sql, g_out, sizeof g_out); }

static int run(const char *sql)
{
    imdb_result r;
    imdb_err_clear(&g_e);
    int rc = imdb_exec_one(&g_s, sql, strlen(sql), NULL, 0, &r, &g_e);
    if (!rc) imdb_result_free(&r);
    return rc;
}

static const char *body(const char *s)
{
    const char *n = strchr(s, '\n');
    return n ? n + 1 : s;
}

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

enum { UN = 240 };

/* u: UN rows, every column but the key NULL somewhere; t: u's schema, empty */
static void load_u(void)
{
    CHECK(run("CREATE TABLE u (id INT64 PRIMARY KEY, g INT64, d DECIMAL(10,2), s TEXT, f FLOAT64, ts TIMESTAMP)") == 0);
    CHECK(run("CREATE TABLE t (id INT64 PRIMARY KEY, g INT64, d DECIMAL(10,2), s TEXT, f FLOAT64, ts TIMESTAMP)") == 0);
    imdb_buf b;
    imdb_buf_init(&b);
    imdb_buf_put_str(&b, "INSERT INTO u VALUES ");
    for (int i = 1; i <= UN; i++) {
        imdb_buf_printf(&b, "%s(%d, ", i > 1 ? ", " : "", i);
        if (i % 11 == 0) imdb_buf_put_str(&b, "NULL, ");
        else imdb_buf_printf(&b, "%d, ", i % 7);
        if (i % 13 == 0) imdb_buf_put_str(&b, "NULL, ");
        else imdb_buf_printf(&b, "%d.%02d, ", i / 4 - 20, (i * 37) % 100);
        if (i % 17 == 0) imdb_buf_put_str(&b, "NULL, ");
        else imdb_buf_printf(&b, "'r%03d', ", (i * 29) % 211);
        if (i % 19 == 0) imdb_buf_put_str(&b, "NULL, ");
        else imdb_buf_printf(&b, "%d.25, ", i - 100);
        if (i % 23 == 0) imdb_buf_put_str(&b, "NULL)");
        else imdb_buf_printf(&b, "'2026-01-01 %02d:%02d:%02d')", i / 60, i % 60, (i * 7) % 60);
    }
    imdb_buf_put_u8(&b, 0);
    CHECK(!imdb_buf_check(&b, &g_e) && run((const char *)b.p) == 0);
    imdb_buf_free(&b);
}

/* the query forms (@: the ids' offset), each answering t's six columns */
static const char *const g_forms[] = {
    "SELECT id + @, g, d, s, f, ts FROM u",
    "SELECT id + @, g, d, s, f, ts FROM u WHERE g = 3 OR s >= 'r150'",
    "SELECT id + @, g * 2, d + 1, s || 'x', f * 2, ts FROM u WHERE id % 2 = 0",
    "SELECT u.id + @, v.g, u.d, v.s, u.f, v.ts FROM u JOIN u AS v ON v.id = u.id + 1",
    "SELECT u.id + @, v.g, u.d, v.s, u.f, v.ts FROM u LEFT JOIN u AS v ON v.id = u.g",
    "SELECT g + @, COUNT(*), SUM(d), MIN(s), MAX(f), MIN(ts) FROM u WHERE g IS NOT NULL GROUP BY g",
    "SELECT id + @, g, d, s, f, ts FROM u WHERE id < 50 UNION SELECT id + @, g, d, s, f, ts FROM u WHERE id >= 40 AND "
    "id < 90",
    "WITH a AS (SELECT * FROM u WHERE g > 2) SELECT id + @, g, d, s, f, ts FROM a",
    "SELECT id + @, ROW_NUMBER() OVER (PARTITION BY g ORDER BY id), d, s, f, ts FROM u",
    "SELECT id + @, g, d, s, f, ts FROM (SELECT * FROM u ORDER BY id DESC LIMIT 25) AS q",
    "WITH RECURSIVE r(n) AS (SELECT 1 UNION ALL SELECT n + 1 FROM r WHERE n < 300) SELECT n + @, n % 5, NULL, NULL, "
    "NULL, NULL FROM r",
    "SELECT id + @, (SELECT COUNT(*) FROM u AS c WHERE c.g = u.g), d, s, f, ts FROM u",
    "SELECT id + @, g, d, s, f, ts FROM u WHERE id IN (SELECT id * 3 FROM u) AND NOT EXISTS (SELECT 1 FROM u AS c WHERE "
    "c.id = u.id + 1000)",
    "SELECT DISTINCT g + @, g, NULL, NULL, NULL, NULL FROM u WHERE g IS NOT NULL",
    "SELECT id + @, g, d, s, f, ts FROM u WHERE id > 200 EXCEPT SELECT id + @, g, d, s, f, ts FROM u WHERE g = 1",
};

/* form with each @ the offset (a format string is a literal: the code rule) */
static void subst(const char *form, long long off, char *out, size_t cap)
{
    size_t n = 0;
    for (const char *p = form; *p && n + 24 < cap; p++) {
        if (*p != '@') out[n++] = *p;
        else n += (size_t)snprintf(out + n, cap - n, "%lld", off);
    }
    out[n] = 0;
}

/* each form: its answer before, then INSERT INTO t with it, then t's rows in its range: the same rows */
static void forms_pass(long long base)
{
    for (size_t k = 0; k < sizeof g_forms / sizeof *g_forms; k++) {
        long long off = base + (long long)(k + 1) * 100000;
        char q[1024], sql[1200];
        subst(g_forms[k], off, q, sizeof q);
        snprintf(sql, sizeof sql, "%s ORDER BY 1", q);
        csv_to(sql, g_out2, sizeof g_out2);
        CHECK(strncmp(g_out2, "ERR", 3) != 0);
        snprintf(sql, sizeof sql, "INSERT INTO t %s", q);
        if (run(sql) != 0) {
            char m[1500];
            snprintf(m, sizeof m, "%s: %s", sql, g_e.msg);
            test_fail(__FILE__, __LINE__, m);
            continue;
        }
        snprintf(sql, sizeof sql, "SELECT * FROM t WHERE id >= %lld AND id < %lld ORDER BY 1", off, off + 100000);
        const char *got = csv(sql);
        if (strcmp(body(got), body(g_out2)) != 0) {
            char m[1600];
            snprintf(m, sizeof m, "form %zu inserted other rows than it answers:\n      query: %.300s\n      got:  %.300s", k,
                     body(g_out2), body(got));
            test_fail(__FILE__, __LINE__, m);
        }
    }
}

static void t_dml_insert_forms(void)
{
    imdb_db *db = open_fresh();
    CHECK(db);
    if (!db) return;
    load_u();
    forms_pass(0); /* in memory */
    CHECK(run("CHECKPOINT") == 0);
    CHECK(run("SET cross_check = on") == 0);
    forms_pass(10000000); /* from the lake (IMDB_EVICT=eager: below the floor), both plans compared */
    CHECK(run("SET join_plan = index") == 0);
    forms_pass(20000000);
    CHECK(run("SET join_plan = auto") == 0 && run("SET cross_check = off") == 0);
    /* WITH before INSERT reads its names the same way */
    EXPECT("WITH a AS (SELECT id, g FROM u WHERE id <= 3) INSERT INTO t (id, g) SELECT id + 30000000, g FROM a", "INSERT 3");
    EXPECT("SELECT id, g FROM t WHERE id > 30000000 ORDER BY id", "id,g\n30000001,1\n30000002,2\n30000003,3\n");
    CHECK(run("VERIFY") == 0);
    done(db);
}

static void t_dml_insert_rules(void)
{
    imdb_db *db = open_fresh();
    CHECK(db);
    if (!db) return;
    CHECK(run("CREATE TABLE w (id INT64 PRIMARY KEY, v TEXT NOT NULL, n INT64, d DECIMAL(6,2), f FLOAT64, ts TIMESTAMP)") == 0);
    CHECK(run("CREATE UNIQUE INDEX w_n ON w (n)") == 0);
    CHECK(run("INSERT INTO w (id, v, n) VALUES (1, 'a', 1), (2, 'b', 2), (3, 'c', NULL)") == 0);
    /* reading its own table: the rows as they were before the statement, three times over */
    for (int i = 0; i < 3; i++) {
        char sql[160];
        snprintf(sql, sizeof sql, "INSERT INTO w (id, v) SELECT id + %d, v || '%d' FROM w", 3 << i, i);
        CHECK(run(sql) == 0);
    }
    EXPECT("SELECT COUNT(*), COUNT(DISTINCT v), MAX(id) FROM w", "count,count_v,max_id\n24,24,24\n");
    /* columns by position, in the list's order; the rest NULL */
    EXPECT("INSERT INTO w (v, id) SELECT 'p', 100", "INSERT 1");
    EXPECT("INSERT INTO w (SELECT 101, 'q', 101, 1, 2, CAST('2026-03-04 05:06:07' AS TIMESTAMP))", "INSERT 1");
    EXPECT("SELECT id, v, n, d, f, ts FROM w WHERE id >= 100 ORDER BY id",
           "id,v,n,d,f,ts\n100,\"p\",,,,\n101,\"q\",101,1.00,2,2026-03-04 05:06:07\n");
    /* the assignment: an integer into a DECIMAL exactly, a DECIMAL rounded half away from zero to the column's
     * places; a fraction never into an integer; a number into a FLOAT64; nothing else converted */
    EXPECT("INSERT INTO w (id, v, d) SELECT 200, 'x', 1.005 UNION ALL SELECT 201, 'x', -1.005 UNION ALL SELECT 202, 'x', 1.004",
           "INSERT 3");
    EXPECT("SELECT id, d FROM w WHERE id >= 200 ORDER BY id", "id,d\n200,1.01\n201,-1.01\n202,1.00\n");
    EXPECT("INSERT INTO w (id, v, n) SELECT 210, 'x', 1.5", "ERR row 1: column n expects an integer");
    EXPECT("INSERT INTO w (id, v, n) SELECT 210, 'x', CAST(1 AS FLOAT64)", "ERR row 1: column n expects an integer");
    EXPECT("INSERT INTO w (id, v, ts) SELECT 210, 'x', '2026-01-01'", "ERR row 1: column ts expects a TIMESTAMP");
    EXPECT("INSERT INTO w (id, v, d) SELECT 210, 'x', 10000", "ERR row 1: column d: value exceeds DECIMAL(6,2)");
    EXPECT("INSERT INTO w (id, v, f) SELECT 210, 'x', 3", "INSERT 1");
    EXPECT("SELECT f FROM w WHERE id = 210", "f\n3\n");
    /* NULL: a TEXT NULL item into any nullable column; never into a NOT NULL one */
    EXPECT("INSERT INTO w (id, v, n, d, f, ts) SELECT 211, 'x', NULL, NULL, NULL, NULL", "INSERT 1");
    EXPECT("INSERT INTO w (id, v) SELECT id + 300, NULL FROM w WHERE id = 1", "ERR NOT NULL");
    EXPECT("INSERT INTO w (id) SELECT 400", "ERR column v needs a value: it is NOT NULL");
    /* a failed statement leaves nothing: a duplicate key at the second row, a unique index's at the third */
    EXPECT("SELECT COUNT(*) FROM w", "count\n31\n");
    EXPECT("INSERT INTO w (id, v) SELECT 500, 'x' UNION ALL SELECT 500, 'y'", "ERR row 2: duplicate primary key");
    EXPECT("INSERT INTO w (id, v, n) SELECT 500, 'x', 7 UNION ALL SELECT 501, 'y', 8 UNION ALL SELECT 502, 'z', 7",
           "ERR row 3:");
    EXPECT("SELECT COUNT(*) FROM w", "count\n31\n");
    /* in a transaction: its own rows read; a failed statement undone alone; ROLLBACK undoes the rest */
    CHECK(run("BEGIN") == 0);
    CHECK(run("INSERT INTO w (id, v) VALUES (600, 'tx')") == 0);
    EXPECT("INSERT INTO w (id, v) SELECT id + 1, v || '2' FROM w WHERE id >= 600", "INSERT 1");
    EXPECT("INSERT INTO w (id, v) SELECT id, v FROM w WHERE id = 601", "ERR duplicate primary key");
    EXPECT("SELECT id, v FROM w WHERE id >= 600 ORDER BY id", "id,v\n600,\"tx\"\n601,\"tx2\"\n");
    CHECK(run("ROLLBACK") == 0);
    EXPECT("SELECT COUNT(*) FROM w WHERE id >= 600", "count\n0\n");
    /* the refusals */
    EXPECT("INSERT INTO w (id, v) SELECT id + 700 FROM w", "ERR INSERT's query returns 1 column, table w needs 2");
    EXPECT("INSERT INTO w SELECT id + 700, v FROM w", "ERR INSERT's query returns 2 columns, table w needs 6");
    EXPECT("INSERT INTO w (id, v) SELECT x.id, 'a' FROM w", "ERR no table x in this statement");
    EXPECT("INSERT INTO w (id, v) SELECT id + 700, v FROM w FOR UPDATE", "ERR FOR UPDATE locks a statement's own rows");
    EXPECT("INSERT INTO w (id, v) SELECT", "ERR syntax error");
    EXPECT("INSERT INTO w (id, v) DELETE FROM w", "ERR expected VALUES or a query");
    EXPECT("EXPLAIN INSERT INTO w (id, v) SELECT 900, 'x'", "ERR EXPLAIN explains SELECT, UPDATE and DELETE");
    EXPECT("SELECT COUNT(*) FROM w", "count\n31\n");
    CHECK(run("VERIFY") == 0);
    done(db);
}

/* a write's reading is under the statement's memory ceiling (P2 S8: the gap S4 left): its nested SELECTs, INSERT's
 * query and the rows UPDATE and DELETE select are refused at 1 MiB and answered at the default; the write itself is
 * not bounded by it; the ceiling is never left set after one, refused or not */
static void t_dml_write_ceiling(void)
{
    imdb_db *db = open_fresh();
    CHECK(db);
    if (!db) return;
    CHECK(run("CREATE TABLE big (id INT64 PRIMARY KEY, n INT64, s TEXT)") == 0);
    CHECK(run("CREATE TABLE cp (id INT64 PRIMARY KEY, n INT64, s TEXT)") == 0);
    for (int base = 0; base < 20000; base += 5000) {
        imdb_buf b;
        imdb_buf_init(&b);
        imdb_buf_put_str(&b, "INSERT INTO big VALUES ");
        for (int i = base + 1; i <= base + 5000; i++)
            imdb_buf_printf(&b, "%s(%d, %d, 'row %05d of a table wide enough to pass one MiB in a sort')", i > base + 1 ? ", " : "",
                            i, i % 10, (i * 7919) % 20000);
        imdb_buf_put_u8(&b, 0);
        CHECK(!imdb_buf_check(&b, &g_e) && !run((const char *)b.p));
        imdb_buf_free(&b);
    }
    static const char *const reads[] = {
        "UPDATE big SET n = n + 1 WHERE id IN (SELECT id FROM big ORDER BY s DESC)",
        "DELETE FROM big WHERE id IN (SELECT id FROM big ORDER BY s DESC)",
        "INSERT INTO cp SELECT * FROM big",
        "INSERT INTO cp SELECT id, n, s FROM big ORDER BY s",
        "UPDATE big SET n = (SELECT MAX(s) FROM (SELECT s FROM big ORDER BY s) AS q) IS NOT NULL WHERE id = 1",
    };
    CHECK(run("SET statement_memory = 1048576") == 0);
    for (size_t i = 0; i < sizeof reads / sizeof *reads; i++) {
        const char *got = csv(reads[i]);
        if (strncmp(got, "ERR ", 4) != 0 || !strstr(got, "statement memory")) {
            char m[600];
            snprintf(m, sizeof m, "%s: refused for its memory? got %.200s", reads[i], got);
            test_fail(__FILE__, __LINE__, m);
        }
        CHECK(imdb_heap_ceiling() == 0);
        EXPECT("SELECT COUNT(*), SUM(n) FROM big", "count,sum_n\n20000,90000\n");
        EXPECT("SELECT COUNT(*) FROM cp", "count\n0\n");
    }
    /* in a transaction too, which goes on */
    CHECK(run("BEGIN") == 0);
    EXPECT("INSERT INTO cp SELECT * FROM big", "ERR statement memory");
    CHECK(imdb_heap_ceiling() == 0);
    EXPECT("INSERT INTO cp SELECT * FROM big WHERE id <= 10", "INSERT 10");
    CHECK(run("COMMIT") == 0);
    /* RETURNING's rows are a result, under the result's cap (the statement's workspace): refused, the table unchanged */
    EXPECT("UPDATE big SET n = n + 1 RETURNING *", "ERR result over its cap of 1048576 bytes");
    CHECK(imdb_heap_ceiling() == 0);
    EXPECT("SELECT COUNT(*), SUM(n) FROM big", "count,sum_n\n20000,90000\n");
    /* writes far past the ceiling, reading little: never bounded by it */
    EXPECT("UPDATE big SET s = s || ' and a little more'", "UPDATE 20000");
    EXPECT("DELETE FROM cp", "DELETE 10");
    CHECK(imdb_heap_ceiling() == 0);
    /* at the default: each answered */
    CHECK(run("SET statement_memory = 0") == 0);
    EXPECT("INSERT INTO cp SELECT id, n, s FROM big ORDER BY s", "INSERT 20000");
    EXPECT("UPDATE big SET n = n + 1 WHERE id IN (SELECT id FROM big ORDER BY s DESC)", "UPDATE 20000");
    EXPECT("DELETE FROM cp WHERE id IN (SELECT id FROM big ORDER BY s DESC)", "DELETE 20000");
    CHECK(imdb_heap_ceiling() == 0);
    CHECK(run("UPDATE big SET n = n + 1 RETURNING *") == 0); /* at the default, answered */
    EXPECT("SELECT COUNT(*), SUM(n) FROM big", "count,sum_n\n20000,130000\n");
    CHECK(run("VERIFY") == 0);
    done(db);
}


static int cmp_line(const void *a, const void *b) { return strcmp(*(char *const *)a, *(char *const *)b); }

/* s's lines after its header, sorted, into out: RETURNING's rows come in the order they are written */
static void sorted_body(const char *s, char *out, size_t cap)
{
    static char buf[1 << 18];
    static char *lines[1 << 14];
    snprintf(buf, sizeof buf, "%s", body(s));
    size_t n = 0;
    for (char *p = strtok(buf, "\n"); p && n < sizeof lines / sizeof *lines; p = strtok(NULL, "\n")) lines[n++] = p;
    qsort(lines, n, sizeof *lines, cmp_line);
    size_t k = 0;
    out[0] = 0;
    for (size_t i = 0; i < n && k < cap; i++) k += (size_t)snprintf(out + k, cap - k, "%s\n", lines[i]);
}

static char g_s1[1 << 18], g_s2[1 << 18];

/* the statement's RETURNING rows and the query's answer, the same rows (sorted) */
static void same_rows(const char *stmt, const char *query, int line)
{
    sorted_body(csv(stmt), g_s1, sizeof g_s1);
    sorted_body(csv(query), g_s2, sizeof g_s2);
    if (strcmp(g_s1, g_s2) != 0 || !strncmp(g_out, "ERR", 3)) {
        char m[1600];
        snprintf(m, sizeof m, "%s\n      returned: %.400s\n      table:    %.400s", stmt, g_s1, g_s2);
        test_fail(__FILE__, line, m);
    }
}

/* RETURNING: each statement's rows as written (INSERT's and UPDATE's new values, DELETE's old ones) against the table
 * read after (or, for DELETE, before) it; computed items, aliases, NULL, *; in memory and from the lake (DELETE's old
 * rows read there), cross-checked; in a transaction; a statement refused at its last row returns nothing and leaves
 * nothing; every refusal */
static void t_dml_returning(void)
{
    imdb_db *db = open_fresh();
    CHECK(db);
    if (!db) return;
    load_u();
    for (int pass = 0; pass < 2; pass++) {
        long long lo = (pass + 1) * 1000000LL, hi = lo + 1000000;
        char st[600], q[600];
        snprintf(st, sizeof st, "INSERT INTO t SELECT id + %lld, g, d, s, f, ts FROM u WHERE id %% 3 = 0 RETURNING *", lo);
        snprintf(q, sizeof q, "SELECT * FROM t WHERE id >= %lld AND id < %lld", lo, hi);
        same_rows(st, q, __LINE__);
        snprintf(st, sizeof st,
                 "UPDATE t SET g = COALESCE(g, 0) + 5, s = s || 'u' WHERE id >= %lld AND id < %lld AND id %% 2 = 0 RETURNING "
                 "id, g * 2 AS g2, s, NULL AS n",
                 lo, hi);
        snprintf(q, sizeof q, "SELECT id, g * 2, s, NULL FROM t WHERE id >= %lld AND id < %lld AND id %% 2 = 0", lo, hi);
        same_rows(st, q, __LINE__);
        snprintf(q, sizeof q, "SELECT id, s, d * 2, ts FROM t WHERE id >= %lld AND id < %lld AND id %% 5 = 0", lo, hi);
        csv_to(q, g_out2, sizeof g_out2); /* before the DELETE */
        snprintf(st, sizeof st, "DELETE FROM t WHERE id >= %lld AND id < %lld AND id %% 5 = 0 RETURNING id, s, d * 2, ts", lo, hi);
        sorted_body(csv(st), g_s1, sizeof g_s1);
        sorted_body(g_out2, g_s2, sizeof g_s2);
        CHECK(!strcmp(g_s1, g_s2) && strstr(g_s1, "\n") != NULL);
        snprintf(q, sizeof q, "SELECT COUNT(*) FROM t WHERE id >= %lld AND id < %lld AND id %% 5 = 0", lo, hi);
        EXPECT(q, "count\n0\n");
        CHECK(run("CHECKPOINT") == 0 && run("SET cross_check = on") == 0); /* the second pass from the lake */
    }
    CHECK(run("SET cross_check = off") == 0);
    /* the zero rows, the names, the status kept for the table display */
    EXPECT("UPDATE t SET g = 0 WHERE id = -1 RETURNING id, g AS gee", "id,gee\n");
    /* no WHERE; an alias without AS; a token after it a syntax error; WITH reserved (no column of that name) */
    CHECK(run("CREATE TABLE sm (id INT64 PRIMARY KEY, v INT64)") == 0 && run("INSERT INTO sm VALUES (1, 10), (2, 20)") == 0);
    EXPECT("UPDATE sm SET v = v + 1 RETURNING id x, v", "x,v\n1,11\n2,21\n");
    EXPECT("DELETE FROM sm RETURNING *", "id,v\n1,11\n2,21\n");
    EXPECT("INSERT INTO sm VALUES (3, 30) RETURNING id x y", "ERR syntax error");
    EXPECT("SELECT COUNT(*) FROM sm", "count\n0\n");
    EXPECT("CREATE TABLE w2 (with INT64 PRIMARY KEY)", "ERR syntax error");
    /* in a transaction: its own rows; ROLLBACK takes them, the rows returned or not */
    CHECK(run("BEGIN") == 0);
    EXPECT("INSERT INTO t (id, s) VALUES (-5, 'x'), (-6, 'y') RETURNING id, s || '!'", "id,\"s || '!'\"\n-5,\"x!\"\n-6,\"y!\"\n");
    EXPECT("DELETE FROM t WHERE id < 0 RETURNING *", "id,g,d,s,f,ts\n-5,,,\"x\",,\n-6,,,\"y\",,\n"); /* the order written */
    CHECK(run("ROLLBACK") == 0);
    /* refused at its last row: an error, no rows, nothing left */
    EXPECT("INSERT INTO t (id) SELECT 1 UNION ALL SELECT 2 UNION ALL SELECT 2000003 RETURNING id", "ERR row 3: duplicate primary key");
    EXPECT("SELECT COUNT(*) FROM t WHERE id IN (1, 2)", "count\n0\n");
    /* the refusals, before any row */
    EXPECT("INSERT INTO t (id) VALUES (7) RETURNING COUNT(*)", "ERR RETURNING computes on each row written: no aggregate");
    EXPECT("INSERT INTO t (id) VALUES (7) RETURNING (SELECT 1)", "ERR a nested SELECT in RETURNING: a later step");
    EXPECT("INSERT INTO t (id) VALUES (7) RETURNING ROW_NUMBER() OVER ()", "ERR a window function stands only as a SELECT item");
    EXPECT("INSERT INTO t (id) VALUES (7) RETURNING nosuch", "ERR no column nosuch in table t");
    EXPECT("DELETE FROM t RETURNING", "ERR syntax error");
    EXPECT("SELECT COUNT(*) FROM t WHERE id = 7", "count\n0\n");
    /* EXPLAIN plans the write; RETURNING changes nothing of it */
    const char *x1 = csv("EXPLAIN UPDATE t SET g = 1 WHERE id = 3000003 RETURNING id");
    CHECK(!strncmp(x1, "item,detail\n", 12) && strstr(x1, "\"path\",\"index(primary key)\"") != NULL);
    CHECK(run("VERIFY") == 0);
    done(db);
}

/* a query too large for the transaction's room is refused before any row is written: the limit's own refusal,
 * not 100 rows written and undone */
static void t_dml_insert_room(void)
{
    const char *dir = test_tmpdir();
    imdb_err e = {0};
    CHECK(imdb_init(dir, false, NULL, &e) == 0);
    imdb_open_opts o = {.sync = 0, .txn_ops = 100};
    imdb_db *db = NULL;
    CHECK(imdb_open(dir, &o, &db, &e) == 0);
    if (!db) return;
    imdb_session_init(&g_s, db);
    CHECK(run("CREATE TABLE r (id INT64 PRIMARY KEY)") == 0);
    EXPECT("INSERT INTO r WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < 100) SELECT i FROM n", "INSERT 100");
    EXPECT("INSERT INTO r WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < 101) SELECT i + 100 FROM n",
           "ERR transaction exceeds 100 operations: INSERT's query returns 101 rows");
    CHECK(run("BEGIN") == 0);
    CHECK(run("INSERT INTO r VALUES (1000), (1001)") == 0);
    EXPECT("INSERT INTO r SELECT id + 2000 FROM r WHERE id <= 99", "ERR transaction exceeds 100 operations: INSERT's query returns 99 rows");
    EXPECT("INSERT INTO r SELECT id + 2000 FROM r WHERE id <= 98", "INSERT 98");
    CHECK(run("COMMIT") == 0);
    EXPECT("SELECT COUNT(*) FROM r", "count\n200\n");
    done(db);
}

/* ON CONFLICT against a model: random proposals over 40 keys (some present, some new, some repeated within one
 * statement), DO NOTHING and DO UPDATE (EXCLUDED's value, the existing row's count plus one, a WHERE that keeps the
 * larger value), from VALUES and from a query; after every statement the table and the RETURNING rows are the model's;
 * in memory, then from the lake cross-checked */
enum { UK = 40 };
typedef struct mrow {
    bool on;
    int64_t v, n;
} mrow;
static mrow g_m[UK];

static void model_table(char *out, size_t cap)
{
    size_t k = (size_t)snprintf(out, cap, "k,v,n\n");
    for (int i = 0; i < UK && k < cap; i++)
        if (g_m[i].on) k += (size_t)snprintf(out + k, cap - k, "%d,%lld,%lld\n", i, (long long)g_m[i].v, (long long)g_m[i].n);
}

static void t_dml_upsert(void)
{
    imdb_db *db = open_fresh();
    CHECK(db);
    if (!db) return;
    CHECK(run("CREATE TABLE kv (k INT64 PRIMARY KEY, v INT64, n INT64)") == 0);
    CHECK(run("CREATE TABLE src (id INT64 PRIMARY KEY, k INT64, v INT64)") == 0);
    memset(g_m, 0, sizeof g_m);
    test_seed(808);
    for (int step = 0; step < 240; step++) {
        if (step == 120) CHECK(run("CHECKPOINT") == 0 && run("SET cross_check = on") == 0);
        int mode = (int)(test_rand() % 3), np = 1 + (int)(test_rand() % 4);
        bool where = test_rand() % 2, query = test_rand() % 4 == 0;
        int pk[4];
        int64_t pv[4];
        char sql[600];
        size_t o = 0;
        if (query) { /* the proposals from a query: src holds them, in its key order */
            CHECK(run("DELETE FROM src") == 0);
        }
        o += (size_t)snprintf(sql + o, sizeof sql - o, query ? "INSERT INTO src VALUES " : "INSERT INTO kv (k, v, n) VALUES ");
        for (int i = 0; i < np; i++) {
            pk[i] = (int)(test_rand() % UK);
            pv[i] = (int64_t)(test_rand() % 1000);
            o += (size_t)(query ? snprintf(sql + o, sizeof sql - o, "%s(%d, %d, %lld)", i ? ", " : "", i, pk[i], (long long)pv[i])
                                : snprintf(sql + o, sizeof sql - o, "%s(%d, %lld, 1)", i ? ", " : "", pk[i], (long long)pv[i]));
        }
        if (query) {
            CHECK(run(sql) == 0);
            o = (size_t)snprintf(sql, sizeof sql, "INSERT INTO kv (k, v, n) SELECT k, v, 1 FROM src ORDER BY id");
        }
        o += (size_t)snprintf(sql + o, sizeof sql - o, "%s",
                              mode == 0 ? " ON CONFLICT DO NOTHING"
                              : mode == 1 ? " ON CONFLICT (k) DO NOTHING"
                                          : " ON CONFLICT (k) DO UPDATE SET v = excluded.v, n = kv.n + 1");
        if (mode == 2 && where) o += (size_t)snprintf(sql + o, sizeof sql - o, " WHERE excluded.v > kv.v");
        snprintf(sql + o, sizeof sql - o, " RETURNING k, v, n");
        /* the model: rows in proposal order; a key this statement wrote again: DO NOTHING keeps it, DO UPDATE refuses */
        bool wrote[UK] = {false}, refused = false;
        char want[4096];
        size_t w = (size_t)snprintf(want, sizeof want, "k,v,n\n");
        mrow before[UK];
        memcpy(before, g_m, sizeof g_m);
        for (int i = 0; i < np && !refused; i++) {
            int k = pk[i];
            if (!g_m[k].on) {
                g_m[k].on = true, g_m[k].v = pv[i], g_m[k].n = 1, wrote[k] = true;
            } else if (mode == 2) {
                if (wrote[k]) {
                    refused = true;
                    break;
                }
                if (where && !(pv[i] > g_m[k].v)) continue;
                g_m[k].v = pv[i], g_m[k].n++, wrote[k] = true;
            } else {
                continue;
            }
            w += (size_t)snprintf(want + w, sizeof want - w, "%d,%lld,%lld\n", k, (long long)g_m[k].v, (long long)g_m[k].n);
        }
        const char *got = csv(sql);
        if (refused) {
            memcpy(g_m, before, sizeof g_m);
            if (strncmp(got, "ERR ", 4) || !strstr(got, "would change a row twice")) {
                char m[1200];
                snprintf(m, sizeof m, "step %d: %s\n      want the refusal, got %.300s", step, sql, got);
                test_fail(__FILE__, __LINE__, m);
            }
        } else if (strcmp(got, want) != 0) {
            char m[1600];
            snprintf(m, sizeof m, "step %d: %s\n      want: %.400s\n      got:  %.400s", step, sql, want, got);
            test_fail(__FILE__, __LINE__, m);
        }
        model_table(want, sizeof want);
        got = csv("SELECT k, v, n FROM kv ORDER BY k");
        if (strcmp(got, want) != 0) {
            char m[1600];
            snprintf(m, sizeof m, "step %d: the table after %s\n      want: %.400s\n      got:  %.400s", step, sql, want, got);
            test_fail(__FILE__, __LINE__, m);
            break;
        }
    }
    CHECK(run("SET cross_check = off") == 0);
    /* in a transaction: a row an earlier statement of it wrote is updated, never refused; ROLLBACK takes it all */
    CHECK(run("BEGIN") == 0);
    CHECK(run("INSERT INTO kv VALUES (100, 1, 1)") == 0);
    EXPECT("INSERT INTO kv VALUES (100, 2, 1) ON CONFLICT (k) DO UPDATE SET v = excluded.v + kv.v RETURNING v", "v\n3\n");
    CHECK(run("ROLLBACK") == 0);
    EXPECT("SELECT COUNT(*) FROM kv WHERE k = 100", "count\n0\n");
    /* the refusals, before any row */
    EXPECT("INSERT INTO kv VALUES (1, 1, 1) ON CONFLICT (k) DO UPDATE SET v = v + 1", "ERR column v is in both tables: qualify it");
    EXPECT("INSERT INTO kv VALUES (1, 1, 1) ON CONFLICT DO UPDATE SET v = 1", "ERR ON CONFLICT DO UPDATE names its key");
    EXPECT("INSERT INTO kv VALUES (1, 1, 1) ON CONFLICT (v) DO NOTHING", "ERR ON CONFLICT's columns are no key of table kv");
    EXPECT("INSERT INTO kv VALUES (1, 1, 1) ON CONFLICT (k) DO UPDATE SET k = 9", "ERR cannot change the primary key");
    EXPECT("INSERT INTO kv VALUES (1, 1, 1) ON CONFLICT (k) DO UPDATE SET v = 1 WHERE kv.v", "ERR WHERE takes a condition");
    EXPECT("INSERT INTO kv VALUES (1, 1, 1) ON CONFLICT (k) DO UPDATE SET v = SUM(kv.v)", "ERR an aggregate stands only in a SELECT list");
    /* a unique index: as the target a later step; DO NOTHING without one resolves the primary key alone, so a row
     * whose key is new but whose unique key is taken fails as a plain INSERT does (PostgreSQL would skip it) */
    CHECK(run("CREATE TABLE uq (k INT64 PRIMARY KEY, v INT64)") == 0 && run("CREATE UNIQUE INDEX uq_v ON uq (v)") == 0);
    CHECK(run("INSERT INTO uq VALUES (1, 10)") == 0);
    EXPECT("INSERT INTO uq VALUES (2, 10) ON CONFLICT (v) DO NOTHING", "ERR ON CONFLICT on unique index uq_v: a later step");
    EXPECT("INSERT INTO uq VALUES (2, 10) ON CONFLICT DO NOTHING", "ERR row 1: duplicate key in unique index uq_v");
    EXPECT("INSERT INTO uq VALUES (1, 11) ON CONFLICT DO NOTHING", "INSERT 0");
    EXPECT("INSERT INTO src VALUES (1000, 1, 1) ON CONFLICT (id, k) DO NOTHING", "ERR ON CONFLICT's columns are no key of table src");
    /* ON right after a FROM item and after a WHERE: ON CONFLICT's, never a join's */
    CHECK(run("CREATE TABLE s2 (id INT64 PRIMARY KEY, k INT64, v INT64)") == 0 && run("INSERT INTO s2 VALUES (1, 1, 5), (2, 50, 6)") == 0);
    CHECK(run("CREATE TABLE kv2 (k INT64 PRIMARY KEY, v INT64)") == 0 && run("INSERT INTO kv2 VALUES (1, 0)") == 0);
    EXPECT("INSERT INTO kv2 SELECT k, v FROM s2 ON CONFLICT DO NOTHING", "INSERT 1");
    EXPECT("INSERT INTO kv2 SELECT k, v FROM s2 WHERE k > 3 ON CONFLICT (k) DO UPDATE SET v = excluded.v + 100 RETURNING k, v",
           "k,v\n50,106\n");
    CHECK(run("VERIFY") == 0);
    done(db);
}

/* ON CONFLICT resolves what the statement's view holds: a key another session committed after this transaction's
 * snapshot is not in it, and the insert meets that row (first committer wins) */
static void t_dml_upsert_concurrent(void)
{
    imdb_db *db = open_fresh();
    CHECK(db);
    if (!db) return;
    CHECK(run("CREATE TABLE kv (k INT64 PRIMARY KEY, v INT64)") == 0);
    CHECK(run("INSERT INTO kv VALUES (1, 10)") == 0);
    imdb_session b;
    imdb_session_init(&b, db);
    CHECK(run("BEGIN") == 0);
    EXPECT("SELECT COUNT(*) FROM kv", "count\n1\n"); /* the snapshot */
    imdb_result r;
    imdb_err e2 = {0};
    CHECK(imdb_exec_one(&b, "INSERT INTO kv VALUES (2, 20)", 29, NULL, 0, &r, &e2) == 0);
    imdb_result_free(&r);
    /* refused at the statement, as PostgreSQL's REPEATABLE READ refuses it: never a silent second row 2, never a skip
     * of a row the view does not hold */
    EXPECT("INSERT INTO kv VALUES (2, 99) ON CONFLICT DO NOTHING",
           "ERR could not serialize access: a concurrent commit inserted the same primary key in table kv");
    CHECK(run("ROLLBACK") == 0);
    EXPECT("SELECT k, v FROM kv ORDER BY k", "k,v\n1,10\n2,20\n");
    /* a key in the view: resolved as asked */
    CHECK(run("BEGIN") == 0);
    EXPECT("INSERT INTO kv VALUES (2, 99) ON CONFLICT (k) DO UPDATE SET v = excluded.v", "INSERT 1");
    CHECK(run("COMMIT") == 0);
    EXPECT("SELECT v FROM kv WHERE k = 2", "v\n99\n");
    /* READ COMMITTED: each statement's view is new, so a key committed before the statement is in it, and resolved */
    CHECK(run("BEGIN ISOLATION LEVEL READ COMMITTED") == 0);
    EXPECT("SELECT COUNT(*) FROM kv", "count\n2\n");
    CHECK(imdb_exec_one(&b, "INSERT INTO kv VALUES (3, 30)", 29, NULL, 0, &r, &e2) == 0);
    imdb_result_free(&r);
    EXPECT("INSERT INTO kv VALUES (3, 99) ON CONFLICT DO NOTHING", "INSERT 0");
    EXPECT("INSERT INTO kv VALUES (3, 98) ON CONFLICT (k) DO UPDATE SET v = excluded.v", "INSERT 1");
    CHECK(run("COMMIT") == 0);
    EXPECT("SELECT k, v FROM kv ORDER BY k", "k,v\n1,10\n2,99\n3,98\n");
    imdb_session_close(&b);
    done(db);
}

/* UPDATE ... FROM and DELETE ... USING against a model: t's 30 rows and u rebuilt before each statement (10 rows,
 * their tid over 34 values: a t row matched by none, one or two), SET from the pair, a filter on either side; after each
 * statement the table, and its RETURNING rows in t's key order, are the model's (a t row two pairs name refuses the
 * UPDATE, the DELETE removes it once); in memory, then from the lake cross-checked under both join plans */
enum { TN = 30, UN2 = 10 };

static void t_dml_update_from(void)
{
    imdb_db *db = open_fresh();
    CHECK(db);
    if (!db) return;
    CHECK(run("CREATE TABLE t (id INT64 PRIMARY KEY, g INT64, v INT64)") == 0);
    CHECK(run("CREATE TABLE u (id INT64 PRIMARY KEY, tid INT64, w INT64)") == 0);
    bool on[TN];
    int64_t g[TN], v[TN];
    for (int i = 0; i < TN; i++) on[i] = false;
    test_seed(909);
    int uid = 0;
    for (int step = 0; step < 150; step++) {
        if (step == 70) CHECK(run("CHECKPOINT") == 0 && run("SET cross_check = on") == 0);
        if (step == 110) CHECK(run("SET join_plan = index") == 0);
        char sql[700];
        if (step % 10 == 0) { /* the deleted t rows back */
            size_t o = (size_t)snprintf(sql, sizeof sql, "INSERT INTO t VALUES ");
            for (int i = 0; i < TN; i++) o += (size_t)snprintf(sql + o, sizeof sql - o, "%s(%d, %d, %d)", i ? ", " : "", i, i % 5, i);
            snprintf(sql + o, sizeof sql - o, " ON CONFLICT DO NOTHING");
            CHECK(run(sql) == 0);
            for (int i = 0; i < TN; i++)
                if (!on[i]) on[i] = true, g[i] = i % 5, v[i] = i;
        }
        int ut[UN2];
        int64_t uw[UN2];
        CHECK(run("DELETE FROM u") == 0);
        size_t o = (size_t)snprintf(sql, sizeof sql, "INSERT INTO u VALUES ");
        for (int j = 0; j < UN2; j++) {
            ut[j] = (int)(test_rand() % 34);
            uw[j] = (int64_t)(test_rand() % 100);
            o += (size_t)snprintf(sql + o, sizeof sql - o, "%s(%d, %d, %lld)", j ? ", " : "", uid++, ut[j], (long long)uw[j]);
        }
        CHECK(run(sql) == 0);
        bool upd = test_rand() % 3 != 0;
        int filt = (int)(test_rand() % 3), k = (int)(test_rand() % 100), jg = (int)(test_rand() % 5);
        const char *fs = filt == 1 ? " AND u.w > " : filt == 2 ? " AND t.g = " : "";
        int fv = filt == 1 ? k : jg;
        char ftxt[40] = "";
        if (filt) snprintf(ftxt, sizeof ftxt, "%s%d", fs, fv);
        if (upd) snprintf(sql, sizeof sql, "UPDATE t SET v = t.v + u.w, g = u.w %% 7 FROM u WHERE u.tid = t.id%s RETURNING t.id AS id, t.g AS g, t.v AS v", ftxt);
        else snprintf(sql, sizeof sql, "DELETE FROM t USING u WHERE u.tid = t.id%s RETURNING t.id AS id, t.v AS v", ftxt);
        /* the model */
        int cnt[TN] = {0}, last[TN];
        for (int j = 0; j < UN2; j++) {
            int i = ut[j];
            if (i >= TN || !on[i]) continue;
            if (filt == 1 && !(uw[j] > k)) continue;
            if (filt == 2 && g[i] != jg) continue;
            cnt[i]++, last[i] = j;
        }
        bool refused = false;
        for (int i = 0; upd && i < TN; i++) refused |= cnt[i] > 1;
        char want[4096];
        size_t w = (size_t)snprintf(want, sizeof want, upd ? "id,g,v\n" : "id,v\n");
        for (int i = 0; !refused && i < TN; i++) {
            if (!cnt[i]) continue;
            if (upd) {
                v[i] += uw[last[i]], g[i] = uw[last[i]] % 7;
                w += (size_t)snprintf(want + w, sizeof want - w, "%d,%lld,%lld\n", i, (long long)g[i], (long long)v[i]);
            } else {
                w += (size_t)snprintf(want + w, sizeof want - w, "%d,%lld\n", i, (long long)v[i]);
                on[i] = false;
            }
        }
        const char *got = csv(sql);
        bool ok = refused ? !strncmp(got, "ERR ", 4) && strstr(got, "with two rows of u") : !strcmp(got, want);
        if (!ok) {
            char m[1600];
            snprintf(m, sizeof m, "step %d: %s\n      want: %.300s\n      got:  %.300s", step, sql, refused ? "the refusal" : want, got);
            test_fail(__FILE__, __LINE__, m);
            break;
        }
        w = (size_t)snprintf(want, sizeof want, "id,g,v\n");
        for (int i = 0; i < TN; i++)
            if (on[i]) w += (size_t)snprintf(want + w, sizeof want - w, "%d,%lld,%lld\n", i, (long long)g[i], (long long)v[i]);
        got = csv("SELECT id, g, v FROM t ORDER BY id");
        if (strcmp(got, want) != 0) {
            char m[1600];
            snprintf(m, sizeof m, "step %d: the table after %s\n      want: %.300s\n      got:  %.300s", step, sql, want, got);
            test_fail(__FILE__, __LINE__, m);
            break;
        }
    }
    CHECK(run("SET join_plan = auto") == 0 && run("SET cross_check = off") == 0);
    /* in a transaction: its own rows read and written; ROLLBACK takes them */
    CHECK(run("BEGIN") == 0);
    CHECK(run("DELETE FROM u") == 0 && run("INSERT INTO u VALUES (5000, 3, 1000)") == 0);
    EXPECT("UPDATE t SET v = u.w FROM u WHERE u.tid = t.id RETURNING id, v", "ERR column id is in both tables: qualify it");
    EXPECT("UPDATE t SET v = u.w FROM u WHERE u.tid = t.id RETURNING t.id AS id, v, u.w * 2 AS w2", "id,v,w2\n3,1000,2000\n");
    EXPECT("UPDATE t SET v = u.w FROM u WHERE u.tid = t.id RETURNING *", "id,g,v,id,tid,w\n3,3,1000,5000,3,1000\n"); /* both rows */
    EXPECT("SELECT v FROM t WHERE id = 3", "v\n1000\n");
    CHECK(run("ROLLBACK") == 0);
    /* an unqualified column of both is ambiguous; the refusals, before any row */
    EXPECT("UPDATE t SET v = id FROM u WHERE u.tid = t.id", "ERR column id is in both tables: qualify it");
    EXPECT("UPDATE t SET id = 1 FROM u WHERE u.tid = t.id", "ERR UPDATE cannot change the primary key");
    EXPECT("UPDATE t SET v = 1 FROM t WHERE t.id = 1", "ERR UPDATE ... FROM t again: name it with AS");
    EXPECT("UPDATE t SET v = 1 FROM (SELECT 1) AS q", "ERR UPDATE ... FROM a nested SELECT: a later step");
    EXPECT("DELETE FROM t USING u, t AS b", "ERR DELETE ... USING one table (more: a later step)");
    EXPECT("UPDATE t SET v = 1 FROM nosuch WHERE 1 = 1", "ERR no table nosuch");
    EXPECT("EXPLAIN UPDATE t SET v = 1 FROM u WHERE u.tid = t.id", "ERR EXPLAIN of UPDATE ... FROM: a later step");
    EXPECT("EXPLAIN DELETE FROM t USING u WHERE u.tid = t.id", "ERR EXPLAIN of DELETE ... USING: a later step");
    /* a self-join by an alias; no WHERE: every pair (one row of u: each t row once) */
    CHECK(run("DELETE FROM u") == 0 && run("INSERT INTO u VALUES (6000, 0, 1)") == 0);
    CHECK(run("UPDATE t SET v = 7 FROM u") == 0);
    EXPECT("SELECT COUNT(*) FROM t WHERE v <> 7", "count\n0\n");
    CHECK(run("UPDATE t SET v = b.g FROM t AS b WHERE b.id = t.id") == 0);
    EXPECT("SELECT COUNT(*) FROM t WHERE v <> g", "count\n0\n");
    CHECK(run("VERIFY") == 0);
    done(db);
}

const test_case dml_tests[] = {
    {"dml_insert_forms", t_dml_insert_forms},
    {"dml_insert_rules", t_dml_insert_rules},
    {"dml_write_ceiling", t_dml_write_ceiling},
    {"dml_returning", t_dml_returning},
    {"dml_insert_room", t_dml_insert_room},
    {"dml_upsert", t_dml_upsert},
    {"dml_upsert_concurrent", t_dml_upsert_concurrent},
    {"dml_update_from", t_dml_update_from},
};
const size_t dml_ntests = sizeof dml_tests / sizeof dml_tests[0];
