/* P2 S5 (docs/plan-p2.md): set operations. UNION, INTERSECT and EXCEPT, with and without ALL, against a model computed
 * here over rows with duplicates and NULLs on both sides and a column INT64 in one SELECT and DECIMAL in the other
 * (unified, so 1 and 1.00 are one row); precedence and parentheses; the tail (ORDER BY an output column, OFFSET,
 * LIMIT) against the same statement over a derived table; set operations in IN, EXISTS, a value, FROM and WITH;
 * the limits; every refusal; WITH RECURSIVE. */
#include <stdlib.h>

#include "../../src/db.h"
#include "../../src/sql.h"
#include "thelp.h"

static imdb_session g_s;
static char g_out[1 << 16], g_out2[1 << 16];


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


/* tmpl with each @T replaced by with */


/* ---- the model: rows (x, y), x scaled by 100 (p's INT64 and q's DECIMAL(9,2) unified as DECIMAL(9,2)), y a code */
typedef struct mrow {
    bool xn;   /* x NULL */
    int64_t x; /* x * 100 */
    int y;     /* -1 NULL, 0 'a', 1 'b' */
} mrow;

enum { MP = 40, MQ = 30 };
enum { OP_UNION, OP_UNION_ALL, OP_INTERSECT, OP_INTERSECT_ALL, OP_EXCEPT, OP_EXCEPT_ALL };
static const char *const OPS[] = {"UNION", "UNION ALL", "INTERSECT", "INTERSECT ALL", "EXCEPT", "EXCEPT ALL"};

static bool meq(const mrow *a, const mrow *b) { return a->xn == b->xn && (a->xn || a->x == b->x) && a->y == b->y; }

static bool min_rows(const mrow *r, int n, const mrow *v)
{
    for (int i = 0; i < n; i++)
        if (meq(&r[i], v)) return true;
    return false;
}

/* a op b as the engine folds it: UNION's rows a's then b's, the first alike alone; INTERSECT's and EXCEPT's a's rows in
 * order, kept where b has (or has not) one alike, once (ALL: each of b's rows matching one of a's at most) */
static int mfold(const mrow *a, int na, const mrow *b, int nb, int op, mrow *out)
{
    int no = 0;
    bool used[MP + MQ + MP];
    memset(used, 0, sizeof used);
    if (op == OP_UNION || op == OP_UNION_ALL) {
        for (int s = 0; s < 2; s++)
            for (int i = 0; i < (s ? nb : na); i++) {
                const mrow *v = s ? &b[i] : &a[i];
                if (op == OP_UNION_ALL || !min_rows(out, no, v)) out[no++] = *v;
            }
        return no;
    }
    for (int i = 0; i < na; i++) {
        int m = -1;
        for (int j = 0; j < nb && m < 0; j++)
            if (!used[j] && meq(&a[i], &b[j])) m = j;
        bool all = op == OP_INTERSECT_ALL || op == OP_EXCEPT_ALL, in = m >= 0;
        if (all && in) used[m] = true;
        bool keep = op == OP_INTERSECT || op == OP_INTERSECT_ALL ? in : !in;
        if (keep && !all && min_rows(out, no, &a[i])) keep = false;
        if (keep) out[no++] = a[i];
    }
    return no;
}

/* the rows as the CLI's CSV prints them: x at two places, y quoted */
static void mcsv(const mrow *r, int n, char *out, size_t cap)
{
    size_t o = (size_t)snprintf(out, cap, "x,y\n");
    for (int i = 0; i < n && o < cap; i++) {
        char xs[32] = "", ys[8] = "";
        if (!r[i].xn) {
            int64_t a = r[i].x < 0 ? -r[i].x : r[i].x;
            snprintf(xs, sizeof xs, "%s%lld.%02lld", r[i].x < 0 ? "-" : "", (long long)(a / 100), (long long)(a % 100));
        }
        if (r[i].y >= 0) snprintf(ys, sizeof ys, "\"%c\"", 'a' + r[i].y);
        o += (size_t)snprintf(out + o, cap - o, "%s,%s\n", xs, ys);
    }
}

static void check_fold(const char *sql, const mrow *want, int n, int line)
{
    static char w[1 << 15];
    mcsv(want, n, w, sizeof w);
    const char *got = csv(sql);
    if (strcmp(body(got), body(w)) != 0) {
        char m[1600];
        snprintf(m, sizeof m, "%s\n      want: %.600s\n      got:  %.600s", sql, w, got);
        test_fail(__FILE__, line, m);
    }
}

/* every operator, both ways round, against the model: duplicates and NULLs on both sides, an INT64 column against a
 * DECIMAL one (so 2 and 2.00 are one row, 2.50 another); a fold of three; INTERSECT before UNION; in memory,
 * cross-checked and in the lake */
static void t_setop_model(void)
{
    imdb_db *db = open_fresh();
    CHECK(db != NULL);
    if (!db) return;
    CHECK(run("CREATE TABLE p (id INT64 PRIMARY KEY, x INT64, y TEXT)") == 0);
    CHECK(run("CREATE TABLE q (id INT64 PRIMARY KEY, x DECIMAL(9,2), y TEXT)") == 0);
    mrow pr[MP], qr[MQ], plo[MP];
    int nlo = 0;
    imdb_buf b;
    imdb_buf_init(&b);
    imdb_buf_put_str(&b, "INSERT INTO p VALUES ");
    for (int i = 1; i <= MP; i++) {
        mrow *r = &pr[i - 1];
        r->xn = i % 9 == 0;
        r->x = ((i * 7) % 11 - 3) * 100;
        r->y = i % 3 == 0 ? -1 : i % 3 == 1 ? 0 : 1;
        imdb_buf_printf(&b, "%s(%d, ", i > 1 ? ", " : "", i);
        if (r->xn) imdb_buf_put_str(&b, "NULL, ");
        else imdb_buf_printf(&b, "%lld, ", (long long)(r->x / 100));
        imdb_buf_put_str(&b, r->y < 0 ? "NULL)" : r->y ? "'b')" : "'a')");
        if (i < 10) plo[nlo++] = *r;
    }
    imdb_buf_put_u8(&b, 0);
    CHECK(!imdb_buf_check(&b, &g_e) && !run((const char *)b.p));
    b.len = 0;
    imdb_buf_put_str(&b, "INSERT INTO q VALUES ");
    for (int j = 1; j <= MQ; j++) {
        mrow *r = &qr[j - 1];
        r->xn = j % 7 == 0;
        r->x = ((j * 5) % 13 - 4) * 100 + (j % 4 == 0 ? 50 : 0);
        r->y = j % 4 == 0 ? -1 : j % 2 ? 0 : 1;
        imdb_buf_printf(&b, "%s(%d, ", j > 1 ? ", " : "", j);
        if (r->xn) {
            imdb_buf_put_str(&b, "NULL, ");
        } else {
            int64_t a = r->x < 0 ? -r->x : r->x;
            imdb_buf_printf(&b, "%s%lld.%02lld, ", r->x < 0 ? "-" : "", (long long)(a / 100), (long long)(a % 100));
        }
        imdb_buf_put_str(&b, r->y < 0 ? "NULL)" : r->y ? "'b')" : "'a')");
    }
    imdb_buf_put_u8(&b, 0);
    CHECK(!imdb_buf_check(&b, &g_e) && !run((const char *)b.p));
    imdb_buf_free(&b);
    static mrow out[MP + MQ + MP], in[MP + MQ + MP];
    char sql[512];
    for (int pass = 0; pass < 3; pass++) {
        if (pass == 1) CHECK(run("SET cross_check = on") == 0);
        if (pass == 2) CHECK(run("CHECKPOINT") == 0);
        for (int op = 0; op < 6; op++) {
            snprintf(sql, sizeof sql, "SELECT x, y FROM p %s SELECT x, y FROM q", OPS[op]);
            check_fold(sql, out, mfold(pr, MP, qr, MQ, op, out), __LINE__);
            snprintf(sql, sizeof sql, "SELECT x, y FROM q %s SELECT x, y FROM p", OPS[op]);
            check_fold(sql, out, mfold(qr, MQ, pr, MP, op, out), __LINE__);
        }
        /* a fold of three, left to right */
        int n = mfold(pr, MP, qr, MQ, OP_UNION, in);
        check_fold("SELECT x, y FROM p UNION SELECT x, y FROM q EXCEPT ALL SELECT x, y FROM p WHERE id < 10", out,
                   mfold(in, n, plo, nlo, OP_EXCEPT_ALL, out), __LINE__);
        /* INTERSECT first: p UNION ALL (q INTERSECT p) */
        n = mfold(qr, MQ, pr, MP, OP_INTERSECT, in);
        check_fold("SELECT x, y FROM p UNION ALL SELECT x, y FROM q INTERSECT SELECT x, y FROM p", out,
                   mfold(pr, MP, in, n, OP_UNION_ALL, out), __LINE__);
        n = mfold(pr, MP, qr, MQ, OP_UNION_ALL, in);
        check_fold("(SELECT x, y FROM p UNION ALL SELECT x, y FROM q) INTERSECT SELECT x, y FROM p", out,
                   mfold(in, n, pr, MP, OP_INTERSECT, out), __LINE__);
    }
    CHECK(run("SET cross_check = off") == 0);
    done(db);
}

static void same_body(const char *a, const char *b, int line)
{
    csv_to(a, g_out, sizeof g_out);
    csv_to(b, g_out2, sizeof g_out2);
    if (!strncmp(g_out, "ERR", 3) || strcmp(body(g_out), body(g_out2)) != 0) {
        char m[1600];
        snprintf(m, sizeof m, "%s\n      vs %s\n      got:  %.300s\n      want: %.300s", a, b, g_out, g_out2);
        test_fail(__FILE__, line, m);
    }
}
#define SAME(a, b) same_body((a), (b), __LINE__)

/* the tail against the same statement over a derived table; set operations in IN, EXISTS, a value, FROM and WITH (every
 * arm reading the WITH); a parenthesized query's own tail; the arms' limit; the transaction's own rows; the memory
 * ceiling; EXPLAIN and the path; every refusal */
static void t_setop_forms(void)
{
    imdb_db *db = open_fresh();
    CHECK(db != NULL);
    if (!db) return;
    CHECK(run("CREATE TABLE t (id INT64 PRIMARY KEY, g INT64, s TEXT)") == 0);
    CHECK(run("CREATE TABLE u (id INT64 PRIMARY KEY, g INT64, s TEXT)") == 0);
    imdb_buf b;
    imdb_buf_init(&b);
    imdb_buf_put_str(&b, "INSERT INTO t VALUES ");
    for (int i = 1; i <= 50; i++) {
        char g[8];
        snprintf(g, sizeof g, "%d", i % 7);
        imdb_buf_printf(&b, "%s(%d, %s, %s)", i > 1 ? ", " : "", i, i % 10 == 0 ? "NULL" : g,
                        i % 3 == 0 ? "NULL" : i % 2 ? "'a'" : "'b'");
    }
    imdb_buf_put_u8(&b, 0);
    CHECK(!imdb_buf_check(&b, &g_e) && !run((const char *)b.p));
    b.len = 0;
    imdb_buf_put_str(&b, "INSERT INTO u VALUES ");
    for (int i = 1; i <= 30; i++) imdb_buf_printf(&b, "%s(%d, %d, %s)", i > 1 ? ", " : "", i, i % 5 + 3, i % 2 ? "'a'" : "'c'");
    imdb_buf_put_u8(&b, 0);
    CHECK(!imdb_buf_check(&b, &g_e) && !run((const char *)b.p));
    /* the tail: ORDER BY output columns, OFFSET, LIMIT, as the same rows sorted as a derived table */
    SAME("SELECT g, s FROM t UNION SELECT g, s FROM u ORDER BY 2 DESC, g LIMIT 7 OFFSET 3",
         "SELECT * FROM (SELECT g, s FROM t UNION SELECT g, s FROM u) AS q ORDER BY s DESC, g LIMIT 7 OFFSET 3");
    SAME("SELECT g AS k, s FROM t EXCEPT ALL SELECT g, s FROM u ORDER BY k NULLS FIRST, s DESC",
         "SELECT * FROM (SELECT g AS k, s FROM t EXCEPT ALL SELECT g, s FROM u) AS q ORDER BY k NULLS FIRST, s DESC");
    /* in IN, EXISTS, a value, FROM and WITH */
    SAME("SELECT id FROM t WHERE g IN (SELECT g FROM u UNION SELECT 0) ORDER BY id",
         "SELECT id FROM t WHERE g IN (SELECT g FROM u) OR g = 0 ORDER BY id");
    EXPECT("SELECT COUNT(*) FROM t WHERE EXISTS (SELECT g FROM u INTERSECT SELECT 3)", "count\n50\n");
    EXPECT("SELECT (SELECT MAX(g) FROM t UNION SELECT 100 ORDER BY 1 DESC LIMIT 1)", "x\n100\n");
    EXPECT("SELECT COUNT(*) FROM (SELECT g FROM t UNION ALL SELECT g FROM u) AS q", "count\n80\n");
    EXPECT("WITH c AS (SELECT g FROM t WHERE g > 4) SELECT g FROM c UNION SELECT g + 100 FROM c ORDER BY 1", "g\n5\n6\n105\n106\n");
    /* a parenthesized query's own tail, then the outer one */
    EXPECT("(SELECT g FROM t ORDER BY g DESC NULLS LAST LIMIT 3) UNION ALL (SELECT g FROM u ORDER BY g LIMIT 2)",
           "g\n6\n6\n6\n3\n3\n");
    EXPECT("(SELECT g FROM t ORDER BY g DESC NULLS LAST LIMIT 3) ORDER BY g LIMIT 2", "g\n6\n6\n");
    /* 64 SELECTs, not 65 */
    imdb_buf_free(&b);
    imdb_buf_init(&b);
    imdb_buf_put_str(&b, "SELECT COUNT(*) FROM (SELECT 1 AS v");
    for (int i = 2; i <= 64; i++) imdb_buf_printf(&b, " UNION ALL SELECT %d", i);
    imdb_buf_put_str(&b, ") AS q");
    imdb_buf_put_u8(&b, 0);
    CHECK(!imdb_buf_check(&b, &g_e));
    EXPECT((const char *)b.p, "count\n64\n");
    b.len--;
    imdb_buf_put_str(&b, " UNION ALL SELECT 65");
    imdb_buf_put_u8(&b, 0);
    CHECK(!imdb_buf_check(&b, &g_e));
    EXPECT((const char *)b.p, "ERR more than 64 SELECTs");
    imdb_buf_free(&b);
    /* the transaction's own rows */
    CHECK(run("BEGIN") == 0 && run("INSERT INTO u VALUES (1000, 77, 'q')") == 0);
    EXPECT("SELECT g FROM t INTERSECT SELECT g FROM u WHERE g > 50 UNION SELECT g FROM u WHERE g = 77", "g\n77\n");
    CHECK(run("ROLLBACK") == 0);
    /* EXPLAIN runs the arms and names the operation; the run reports it as its path */
    const char *x = csv("EXPLAIN SELECT g FROM t UNION ALL SELECT g FROM u");
    CHECK(strstr(x, "\"set\",\"2 SELECTs, each run first (EXPLAIN reads them): 50 rows; 30 rows\"") != NULL);
    CHECK(strstr(x, "\"path\",\"union all\"") != NULL);
    imdb_result r;
    imdb_err_clear(&g_e);
    CHECK(imdb_exec_one(&g_s, "SELECT g FROM t INTERSECT SELECT g FROM u", 41, NULL, 0, &r, &g_e) == 0);
    if (!g_e.code) {
        CHECK(!strcmp(r.path, "intersect"));
        imdb_result_free(&r);
    }
    /* the memory ceiling reaches the fold */
    CHECK(run("SET statement_memory = 1048576") == 0);
    CHECK(run("CREATE TABLE big (id INT64 PRIMARY KEY, s TEXT)") == 0);
    for (int base = 0; base < 20000; base += 5000) {
        imdb_buf_init(&b);
        imdb_buf_put_str(&b, "INSERT INTO big VALUES ");
        for (int i = base + 1; i <= base + 5000; i++) imdb_buf_printf(&b, "%s(%d, 'r%d')", i > base + 1 ? ", " : "", i, i);
        imdb_buf_put_u8(&b, 0);
        CHECK(!imdb_buf_check(&b, &g_e) && !run((const char *)b.p));
        imdb_buf_free(&b);
    }
    EXPECT("SELECT id, s FROM big UNION SELECT id + 1, s FROM big", "ERR statement memory");
    CHECK(run("SET statement_memory = 0") == 0);
    /* refused, each with its reason */
    EXPECT("SELECT g FROM t UNION SELECT g, s FROM u", "ERR return 1 and 2 columns");
    EXPECT("SELECT s FROM t UNION SELECT g FROM u", "ERR a set operation's column 1 is TEXT and INT64");
    EXPECT("SELECT g FROM t UNION SELECT NULL", "ERR a set operation's column 1 is INT64 and TEXT"); /* CAST it */
    EXPECT("SELECT g FROM t UNION SELECT CAST(NULL AS INT64)", "g\n1\n2\n3\n4\n5\n6\n0\n\n");
    EXPECT("SELECT g FROM t UNION SELECT g FROM u ORDER BY g + 1", "ERR names an output column or its position");
    EXPECT("SELECT g FROM t UNION SELECT g FROM u ORDER BY t.g", "ERR names an output column or its position");
    EXPECT("SELECT g FROM t UNION SELECT g FROM u ORDER BY 2", "ERR ORDER BY 2: the set operation returns 1 column");
    EXPECT("SELECT g FROM t UNION SELECT g FROM u ORDER BY zz", "ERR no output column of the set operation is named so");
    EXPECT("SELECT g AS k, s AS k FROM t UNION SELECT g, s FROM u ORDER BY k", "ERR two output columns are named so");
    EXPECT("SELECT g FROM t UNION SELECT g FROM u FOR UPDATE", "ERR not a set operation's");
    EXPECT("SELECT g FROM t ORDER BY g UNION SELECT g FROM u", "ERR expected end of statement"); /* an arm's own tail: in parentheses only */
    EXPECT("SELECT id FROM t WHERE EXISTS (SELECT 1 FROM u WHERE u.g = t.g UNION SELECT 2)",
           "ERR correlated set operations are a later step");
    EXPECT("SELECT 1 UNION SELECT 2 ORDER BY 1 FOR UPDATE", "ERR not a set operation's");
    done(db);
}


/* WITH RECURSIVE against models computed here: reachability by UNION over a graph with cycles (a breadth-first
 * search), paths by UNION ALL over an acyclic one (each path a row: counts by depth), a count of 50,000 rounds; the row
 * limit stopping a cycle under UNION ALL; the transaction's own rows; EXPLAIN; column lists; every refusal */
static void t_setop_recursive(void)
{
    imdb_db *db = open_fresh();
    CHECK(db != NULL);
    if (!db) return;
    enum { NODES = 200, EDGES = 400, DN = 25, DEDGES = 60, DEPTH = 6 };
    CHECK(run("CREATE TABLE e (id INT64 PRIMARY KEY, src INT64, dst INT64)") == 0);
    CHECK(run("CREATE TABLE d (id INT64 PRIMARY KEY, src INT64, dst INT64)") == 0);
    static int es[EDGES + 1], ed[EDGES + 1], ds[DEDGES + 1], dd[DEDGES + 1];
    imdb_buf b;
    imdb_buf_init(&b);
    imdb_buf_put_str(&b, "INSERT INTO e VALUES ");
    for (int i = 1; i <= EDGES; i++) {
        es[i] = (i * 37) % NODES + 1;
        ed[i] = (i * 91 + 7) % NODES + 1;
        imdb_buf_printf(&b, "%s(%d, %d, %d)", i > 1 ? ", " : "", i, es[i], ed[i]);
    }
    imdb_buf_put_u8(&b, 0);
    CHECK(!imdb_buf_check(&b, &g_e) && !run((const char *)b.p));
    b.len = 0;
    imdb_buf_put_str(&b, "INSERT INTO d VALUES ");
    for (int i = 1; i <= DEDGES; i++) { /* lower to higher: no cycle; parallel edges counted as paths */
        ds[i] = i % 20 + 1;
        dd[i] = ds[i] + i % 3 + 1;
        imdb_buf_printf(&b, "%s(%d, %d, %d)", i > 1 ? ", " : "", i, ds[i], dd[i]);
    }
    imdb_buf_put_u8(&b, 0);
    CHECK(!imdb_buf_check(&b, &g_e) && !run((const char *)b.p));
    imdb_buf_free(&b);
    /* reachability from node 1: a breadth-first search */
    static bool seen[NODES + 1];
    static int queue[NODES + 1];
    int qh = 0, qt = 0, nreach = 0;
    long sum = 0;
    seen[1] = true;
    queue[qt++] = 1;
    while (qh < qt) {
        int v = queue[qh++];
        nreach++;
        sum += v;
        for (int i = 1; i <= EDGES; i++)
            if (es[i] == v && !seen[ed[i]]) seen[ed[i]] = true, queue[qt++] = ed[i];
    }
    char want[128];
    snprintf(want, sizeof want, "x,y\n%d,%ld\n", nreach, sum);
    /* paths of at most DEPTH edges from node 1, by depth: paths[k][v] */
    static long paths[DEPTH + 1][DN + 4];
    long npaths = 1;
    paths[0][1] = 1;
    for (int k = 1; k <= DEPTH; k++)
        for (int i = 1; i <= DEDGES; i++) {
            paths[k][dd[i]] += paths[k - 1][ds[i]];
            npaths += paths[k - 1][ds[i]];
        }
    char wantp[64];
    snprintf(wantp, sizeof wantp, "count\n%ld\n", npaths);
    for (int pass = 0; pass < 3; pass++) { /* in memory, cross-checked, in the lake */
        if (pass == 1) CHECK(run("SET cross_check = on") == 0);
        if (pass == 2) CHECK(run("CHECKPOINT") == 0);
        EXPECT("WITH RECURSIVE r(node) AS (SELECT 1 UNION SELECT e.dst FROM r JOIN e ON e.src = r.node) "
               "SELECT COUNT(*), SUM(node) FROM r", want);
        EXPECT("WITH RECURSIVE p(node, depth) AS (SELECT 1, 0 UNION ALL SELECT d.dst, p.depth + 1 FROM p JOIN d ON d.src = p.node "
               "WHERE p.depth < 6) SELECT COUNT(*) FROM p", wantp);
    }
    CHECK(run("SET cross_check = off") == 0);
    EXPECT("WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < 50000) SELECT COUNT(*), SUM(i), MAX(i) FROM n",
           "x,y,z\n50000,1250025000,50000\n");
    EXPECT("WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < 5), m AS (SELECT i * 10 AS j FROM n) "
           "SELECT a.i, b.j FROM n AS a JOIN m AS b ON b.j = a.i * 10 ORDER BY a.i",
           "i,j\n1,10\n2,20\n3,30\n4,40\n5,50\n"); /* read twice, and by a later WITH */
    /* a cycle under UNION ALL runs until a limit stops it; under UNION it ends */
    CHECK(run("SET statement_row_limit = 5000") == 0);
    EXPECT("WITH RECURSIVE r(node) AS (SELECT 1 UNION ALL SELECT e.dst FROM r JOIN e ON e.src = r.node) SELECT COUNT(*) FROM r",
           "ERR statement row limit");
    CHECK(run("SET statement_row_limit = 0") == 0);
    /* the transaction's own rows */
    CHECK(run("BEGIN") == 0 && run("INSERT INTO d VALUES (1000, 1, 99)") == 0);
    EXPECT("WITH RECURSIVE r(node) AS (SELECT 1 UNION SELECT d.dst FROM r JOIN d ON d.src = r.node) SELECT MAX(node) FROM r",
           "max\n99\n");
    CHECK(run("ROLLBACK") == 0);
    /* EXPLAIN runs the WITH (its rows are what the rest is planned over) */
    CHECK(strstr(csv("EXPLAIN WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < 7) SELECT i FROM n"),
                 "n 7 rows") != NULL);
    /* column lists */
    EXPECT("WITH c(a, b) AS (SELECT 1, 2) SELECT b, a FROM c", "b,a\n2,1\n");
    EXPECT("WITH c(a, b) AS (SELECT 1) SELECT a FROM c", "ERR WITH c names 2 columns: its SELECT returns 1");
    EXPECT("WITH c(a, a) AS (SELECT 1, 2) SELECT a FROM c", "ERR names its column a twice");
    /* refused, each with its reason */
    EXPECT("WITH n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < 5) SELECT i FROM n", "ERR write WITH RECURSIVE");
    EXPECT("WITH RECURSIVE n(i) AS (SELECT i FROM n UNION SELECT 1) SELECT i FROM n", "ERR its first SELECT cannot read n");
    EXPECT("WITH RECURSIVE n(i) AS (SELECT 1 UNION SELECT COUNT(*) FROM n) SELECT i FROM n", "ERR takes no aggregate");
    EXPECT("WITH RECURSIVE n(i) AS (SELECT 1 UNION SELECT DISTINCT i FROM n) SELECT i FROM n", "ERR takes no aggregate");
    EXPECT("WITH RECURSIVE n(i) AS (SELECT 1 UNION SELECT a.i FROM n AS a JOIN n AS b ON a.i = b.i) SELECT i FROM n",
           "ERR reads n once, in its own FROM");
    EXPECT("WITH RECURSIVE n(i) AS (SELECT 1 UNION SELECT i FROM e WHERE i IN (SELECT i FROM n)) SELECT i FROM n",
           "ERR reads n once, in its own FROM");
    EXPECT("WITH RECURSIVE n(i) AS (SELECT 1 UNION SELECT i + 0.5 FROM n WHERE i < 3) SELECT i FROM n", "ERR wider than its first's");
    EXPECT("WITH RECURSIVE n(i) AS (SELECT 1 UNION SELECT 2 UNION SELECT i + 1 FROM n WHERE i < 3) SELECT i FROM n",
           "ERR is SELECT ... UNION [ALL] SELECT ...");
    EXPECT("WITH RECURSIVE n(i) AS (SELECT 1 INTERSECT SELECT i FROM n) SELECT i FROM n", "ERR is SELECT ... UNION [ALL] SELECT ...");
    EXPECT("WITH RECURSIVE n(i) AS (SELECT 1 UNION SELECT i + 1 FROM n WHERE i < 3 ORDER BY 1) SELECT i FROM n",
           "ERR is SELECT ... UNION [ALL] SELECT ...");
    EXPECT("WITH RECURSIVE c(a) AS (SELECT 7) SELECT a FROM c", "a\n7\n"); /* RECURSIVE that reads nothing of its own */
    done(db);
}


/* SHOW TRANSACTIONS' lock count of g_s's own transaction (-1: none listed) */
static int64_t own_locks(void)
{
    imdb_result r;
    int64_t n = -1;
    imdb_err_clear(&g_e);
    if (imdb_exec_one(&g_s, "SHOW TRANSACTIONS", 17, NULL, 0, &r, &g_e) == 0) {
        for (uint64_t i = 0; i < r.nrows; i++)
            if (r.ncols == 7 && r.cells[7 * i + 6].v.i == 1) n = r.cells[7 * i + 5].v.i;
        imdb_result_free(&r);
    }
    return n;
}

/* the S5 review's points (08:0x): parenthesized queries bounded (the parser's recursion, a client's text); a WITH
 * before a set operation whose first SELECT has nested SELECTs of its own (setop_open renumbers them); a correlated
 * subquery inside an arm; FOR UPDATE below a statement's top level refused (EXPLAIN runs nested SELECTs, and must lock
 * nothing), and EXPLAIN of a WITH and a set operation locking nothing */
static void t_setop_review(void)
{
    imdb_db *db = open_fresh();
    CHECK(db != NULL);
    if (!db) return;
    CHECK(run("CREATE TABLE t (id INT64 PRIMARY KEY, g INT64, s TEXT)") == 0);
    CHECK(run("CREATE TABLE u (id INT64 PRIMARY KEY, g INT64, s TEXT)") == 0);
    CHECK(run("INSERT INTO t VALUES (1, 1, 'a'), (2, 2, 'b'), (3, NULL, 'c')") == 0);
    CHECK(run("INSERT INTO u VALUES (1, 2, 'b'), (2, 5, 'z')") == 0);
    char q[256];
    for (int depth = 30; depth <= 33; depth += 3) {
        int n = 0;
        for (int i = 0; i < depth; i++) q[n++] = '(';
        n += snprintf(q + n, sizeof q - (size_t)n, "SELECT 1");
        for (int i = 0; i < depth; i++) q[n++] = ')';
        q[n] = 0;
        EXPECT(q, depth <= 32 ? "x\n1\n" : "ERR queries parenthesized deeper than 32");
    }
    EXPECT("WITH c AS (SELECT 1 AS v) SELECT v FROM c WHERE v IN (SELECT 1) UNION SELECT 2", "v\n1\n2\n");
    EXPECT("WITH c AS (SELECT 1 AS v) SELECT w FROM (SELECT v + 5 AS w FROM c) AS d UNION SELECT 2", "w\n6\n2\n");
    EXPECT("WITH c AS (SELECT 3 AS v), e AS (SELECT 4 AS v) SELECT v FROM c WHERE v IN (SELECT v FROM e UNION SELECT 3) "
           "AND EXISTS (SELECT 1) UNION SELECT v FROM e",
           "v\n3\n4\n");
    for (int pass = 0; pass < 2; pass++) {
        if (pass) CHECK(run("SET cross_check = on") == 0);
        SAME("SELECT id FROM t WHERE EXISTS (SELECT 1 FROM u WHERE u.g = t.g) UNION SELECT 100",
             "SELECT id FROM t WHERE g IN (SELECT g FROM u) UNION SELECT 100");
        SAME("SELECT s FROM u INTERSECT SELECT s FROM t WHERE (SELECT COUNT(*) FROM u WHERE u.s = t.s) > 0",
             "SELECT s FROM t WHERE s IN (SELECT s FROM u)");
    }
    CHECK(run("SET cross_check = off") == 0);
    EXPECT("SELECT COUNT(*) FROM (SELECT id FROM t FOR UPDATE) AS q", "ERR at its top level only");
    EXPECT("(SELECT g FROM t FOR UPDATE) UNION SELECT g FROM u", "ERR at its top level only");
    EXPECT("SELECT id FROM t WHERE id IN (SELECT id FROM t FOR UPDATE)", "ERR at its top level only");
    CHECK(run("BEGIN") == 0);
    CHECK(strstr(csv("EXPLAIN WITH c AS (SELECT g FROM t) SELECT g FROM c UNION SELECT g FROM u"), "\"nested\"") != NULL);
    CHECK(own_locks() == 0);
    CHECK(run("SELECT id FROM t WHERE id = 1 FOR UPDATE") == 0 && own_locks() == 1); /* the top level's still locks */
    CHECK(run("ROLLBACK") == 0);
    done(db);
}

const test_case setop_tests[] = {
    {"setop_model", t_setop_model},
    {"setop_forms", t_setop_forms},
    {"setop_recursive", t_setop_recursive},
    {"setop_review", t_setop_review},
};
const size_t setop_ntests = sizeof setop_tests / sizeof setop_tests[0];
