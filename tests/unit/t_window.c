/* P2 S6 (docs/plan-p2.md): window functions against a model computed here: partitions with a NULL one, an order key
 * with ties and NULLs, values with NULLs; every function under its default frame and ROWS / RANGE frames (the peers of
 * the default frame, an empty frame), in memory, cross-checked and in the lake; a grouped statement's windows; the
 * tail over them; every refusal. */
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

enum { WN = 60 };
typedef struct wrow {
    int64_t id, g, o, v;
    bool gn, on, vn; /* NULL */
} wrow;
static wrow W[WN + 1];

/* the model's frames, for the row at p in its partition's sorted rows P[0..m): the default (to the last peer), the
 * whole partition, ROWS from p + lo to p + hi (UNB: unbounded), RANGE from the first peer to the end */
enum { F_DEFAULT, F_WHOLE, F_ROWS, F_RANGE_CUR_UNB };
enum { UNB = 1 << 20 };

static bool o_eq(const wrow *a, const wrow *b) { return a->on == b->on && (a->on || a->o == b->o); }

/* the rows of partition g (gn: the NULL one) sorted by o ASC NULLS LAST (desc: DESC NULLS FIRST), ties by id */
static int part_rows(bool gn, int64_t g, bool desc, int *P)
{
    int m = 0;
    for (int i = 1; i <= WN; i++)
        if (W[i].gn == gn && (gn || W[i].g == g)) P[m++] = i;
    for (int a = 1; a < m; a++) /* insertion sort, stable: ties keep id order */
        for (int b = a; b > 0; b--) {
            const wrow *x = &W[P[b - 1]], *y = &W[P[b]];
            int d; /* x after y? */
            if (x->on != y->on) d = x->on ? 1 : -1; /* NULL last ascending ... */
            else d = x->on ? 0 : (x->o > y->o) - (x->o < y->o);
            if (desc) d = -d; /* ... first descending */
            if (d <= 0) break;
            int t = P[b - 1];
            P[b - 1] = P[b];
            P[b] = t;
        }
    return m;
}

static char *wcsv(char *out, size_t cap, const int64_t *val, const bool *null)
{
    size_t o = (size_t)snprintf(out, cap, "id,r\n");
    for (int i = 1; i <= WN && o < cap; i++) {
        if (null[i]) o += (size_t)snprintf(out + o, cap - o, "%d,\n", i);
        else o += (size_t)snprintf(out + o, cap - o, "%d,%lld\n", i, (long long)val[i]);
    }
    return out;
}

enum { M_RN, M_RANK, M_DENSE, M_NTILE3, M_LAG, M_LAG2, M_LEAD, M_FIRST, M_LAST, M_SUM, M_COUNT, M_COUNTS, M_MIN, M_MAX };

/* function f on every row, its window PARTITION BY g ORDER BY o [DESC] and frame (kind, lo, hi) */
static void model(int f, bool desc, int kind, int lo, int hi, int64_t *val, bool *null)
{
    int P[WN + 1];
    for (int gi = -1; gi < 3; gi++) {
        int m = part_rows(gi < 0, gi, desc, P), dense = 0;
        for (int p = 0; p < m; p++) {
            int i = P[p], gs = p, ge = p;
            while (gs > 0 && o_eq(&W[P[gs - 1]], &W[i])) gs--;
            while (ge + 1 < m && o_eq(&W[P[ge + 1]], &W[i])) ge++;
            if (gs == p) dense++;
            null[i] = false;
            val[i] = 0;
            if (f == M_RN) val[i] = p + 1;
            else if (f == M_RANK) val[i] = gs + 1;
            else if (f == M_DENSE) val[i] = dense;
            else if (f == M_NTILE3) {
                int q = m / 3, rem = m % 3;
                val[i] = p < rem * (q + 1) ? p / (q + 1) + 1 : rem + (p - rem * (q + 1)) / q + 1;
            } else if (f == M_LAG || f == M_LAG2 || f == M_LEAD) {
                int t = f == M_LEAD ? p + 1 : f == M_LAG ? p - 1 : p - 2;
                if (t < 0 || t >= m) null[i] = f != M_LAG2; /* LAG(v, 2, 0): the default */
                else null[i] = W[P[t]].vn, val[i] = W[P[t]].v;
            } else {
                int fs = 0, fe = m - 1;
                if (kind == F_DEFAULT) fe = ge;
                else if (kind == F_RANGE_CUR_UNB) fs = gs;
                else if (kind == F_ROWS) {
                    fs = lo == -UNB ? 0 : p + lo;
                    fe = hi == UNB ? m - 1 : p + hi;
                    if (fs < 0) fs = 0;
                    if (fe > m - 1) fe = m - 1;
                }
                if (f == M_FIRST || f == M_LAST) {
                    if (fs > fe) null[i] = true;
                    else null[i] = W[P[f == M_FIRST ? fs : fe]].vn, val[i] = W[P[f == M_FIRST ? fs : fe]].v;
                    continue;
                }
                int64_t s = 0, c = 0, cs = 0, mn = 0, mx = 0;
                for (int q = fs; q <= fe; q++) {
                    cs++;
                    if (W[P[q]].vn) continue;
                    int64_t x = W[P[q]].v;
                    if (!c || x < mn) mn = x;
                    if (!c || x > mx) mx = x;
                    s += x;
                    c++;
                }
                val[i] = f == M_SUM ? s : f == M_COUNT ? c : f == M_COUNTS ? cs : f == M_MIN ? mn : mx;
                null[i] = (f == M_SUM || f == M_MIN || f == M_MAX) && !c;
            }
        }
    }
}

/* every function, under its default frame and ROWS and RANGE frames (the default's peers, LAST_VALUE's last peer,
 * empty frames at a partition's first rows), against the model; in memory, cross-checked and in the lake */
static void t_window_model(void)
{
    imdb_db *db = open_fresh();
    CHECK(db != NULL);
    if (!db) return;
    CHECK(run("CREATE TABLE w (id INT64 PRIMARY KEY, g INT64, o INT64, v INT64)") == 0);
    imdb_buf b;
    imdb_buf_init(&b);
    imdb_buf_put_str(&b, "INSERT INTO w VALUES ");
    for (int i = 1; i <= WN; i++) {
        wrow *r = &W[i];
        *r = (wrow){.id = i, .g = i % 4, .o = (i * 7) % 5, .v = (i * 13) % 17 - 5, .gn = i % 4 == 3, .on = i % 9 == 0, .vn = i % 7 == 0};
        char g[24], o[24], v[24];
        snprintf(g, sizeof g, "%lld", (long long)r->g);
        snprintf(o, sizeof o, "%lld", (long long)r->o);
        snprintf(v, sizeof v, "%lld", (long long)r->v);
        imdb_buf_printf(&b, "%s(%d, %s, %s, %s)", i > 1 ? ", " : "", i, r->gn ? "NULL" : g, r->on ? "NULL" : o, r->vn ? "NULL" : v);
    }
    imdb_buf_put_u8(&b, 0);
    CHECK(!imdb_buf_check(&b, &g_e) && !run((const char *)b.p));
    imdb_buf_free(&b);
    static const struct {
        const char *fn, *frame;
        int f, kind, lo, hi;
        bool desc;
    } Q[] = {
        {"ROW_NUMBER()", "", M_RN, F_DEFAULT, 0, 0, false},
        {"RANK()", "", M_RANK, F_DEFAULT, 0, 0, false},
        {"DENSE_RANK()", "", M_DENSE, F_DEFAULT, 0, 0, true},
        {"NTILE(3)", "", M_NTILE3, F_DEFAULT, 0, 0, false},
        {"LAG(v)", "", M_LAG, F_DEFAULT, 0, 0, false},
        {"LAG(v, 2, 0)", "", M_LAG2, F_DEFAULT, 0, 0, true},
        {"LEAD(v)", "", M_LEAD, F_DEFAULT, 0, 0, false},
        {"FIRST_VALUE(v)", "", M_FIRST, F_DEFAULT, 0, 0, false},
        {"LAST_VALUE(v)", "", M_LAST, F_DEFAULT, 0, 0, false}, /* the last peer, not the row */
        {"SUM(v)", "", M_SUM, F_DEFAULT, 0, 0, false},         /* running, peers included */
        {"COUNT(*)", "", M_COUNTS, F_DEFAULT, 0, 0, true},
        {"COUNT(v)", " ROWS BETWEEN 2 PRECEDING AND CURRENT ROW", M_COUNT, F_ROWS, -2, 0, false},
        {"SUM(v)", " ROWS BETWEEN 1 PRECEDING AND 1 FOLLOWING", M_SUM, F_ROWS, -1, 1, false},
        {"MIN(v)", " ROWS BETWEEN CURRENT ROW AND UNBOUNDED FOLLOWING", M_MIN, F_ROWS, 0, UNB, false},
        {"MAX(v)", " ROWS BETWEEN UNBOUNDED PRECEDING AND 1 PRECEDING", M_MAX, F_ROWS, -UNB, -1, false}, /* empty first */
        {"SUM(v)", " ROWS BETWEEN 3 PRECEDING AND 2 PRECEDING", M_SUM, F_ROWS, -3, -2, true},
        {"COUNT(*)", " ROWS BETWEEN 1 FOLLOWING AND 2 FOLLOWING", M_COUNTS, F_ROWS, 1, 2, false},
        {"LAST_VALUE(v)", " ROWS BETWEEN UNBOUNDED PRECEDING AND UNBOUNDED FOLLOWING", M_LAST, F_WHOLE, 0, 0, false},
        {"FIRST_VALUE(v)", " RANGE BETWEEN CURRENT ROW AND UNBOUNDED FOLLOWING", M_FIRST, F_RANGE_CUR_UNB, 0, 0, false},
        {"SUM(v)", " RANGE BETWEEN CURRENT ROW AND UNBOUNDED FOLLOWING", M_SUM, F_RANGE_CUR_UNB, 0, 0, true},
    };
    static char sql[512], want[1 << 13];
    int64_t val[WN + 1];
    bool null[WN + 1];
    for (int pass = 0; pass < 3; pass++) {
        if (pass == 1) CHECK(run("SET cross_check = on") == 0);
        if (pass == 2) CHECK(run("CHECKPOINT") == 0);
        for (size_t q = 0; q < sizeof Q / sizeof *Q; q++) {
            snprintf(sql, sizeof sql, "SELECT id, %s OVER (PARTITION BY g ORDER BY o%s%s) AS r FROM w ORDER BY id", Q[q].fn,
                     Q[q].desc ? " DESC" : "", Q[q].frame);
            model(Q[q].f, Q[q].desc, Q[q].kind, Q[q].lo, Q[q].hi, val, null);
            EXPECT(sql, wcsv(want, sizeof want, val, null));
        }
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

/* windows over a grouped statement; the tail over the rows with their windows (ORDER BY a window item, OFFSET, LIMIT,
 * DISTINCT); computing on a window from a derived table; windows in a nested SELECT and a set operation's arm; the
 * transaction's own rows; EXPLAIN (a window row, nothing computed, no row tested); every refusal */
static void t_window_forms(void)
{
    imdb_db *db = open_fresh();
    CHECK(db != NULL);
    if (!db) return;
    CHECK(run("CREATE TABLE t (id INT64 PRIMARY KEY, g INT64, x INT64, s TEXT)") == 0);
    CHECK(run("INSERT INTO t VALUES (1, 1, 10, 'a'), (2, 1, 20, 'b'), (3, 1, 20, 'c'), (4, 2, 5, 'd'), (5, 2, NULL, 'e'), "
              "(6, 2, 7, 'f'), (7, 3, 1, 'g')") == 0);
    EXPECT("SELECT g, SUM(x) AS sx, RANK() OVER (ORDER BY SUM(x) DESC) AS r, SUM(SUM(x)) OVER () AS tot FROM t GROUP BY g",
           "ERR an aggregate inside a window function's arguments");
    EXPECT("SELECT g, SUM(x) AS sx, RANK() OVER (ORDER BY SUM(x) DESC) AS r FROM t GROUP BY g ORDER BY r",
           "g,sx,r\n1,50,1\n2,12,2\n3,1,3\n");
    EXPECT("SELECT g, COUNT(*) AS n, ROW_NUMBER() OVER (ORDER BY g DESC) AS rn FROM t GROUP BY g", "g,n,rn\n1,3,3\n2,3,2\n3,1,1\n");
    /* the tail: ORDER BY a window item (by its alias and by position), OFFSET, LIMIT, DISTINCT */
    EXPECT("SELECT id, ROW_NUMBER() OVER (ORDER BY x DESC, id) AS rn FROM t ORDER BY rn LIMIT 3", "id,rn\n5,1\n2,2\n3,3\n");
    EXPECT("SELECT id, ROW_NUMBER() OVER (ORDER BY x DESC, id) AS rn FROM t ORDER BY 2 DESC OFFSET 1 LIMIT 2", "id,rn\n4,6\n6,5\n");
    EXPECT("SELECT DISTINCT g, COUNT(*) OVER (PARTITION BY g) AS n FROM t ORDER BY g", "g,n\n1,3\n2,3\n3,1\n");
    EXPECT("SELECT id, s FROM t ORDER BY x NULLS FIRST, id LIMIT 2", "id,s\n5,\"e\"\n7,\"g\"\n");
    EXPECT("SELECT id, LAG(s) OVER (ORDER BY id) AS p FROM t ORDER BY x DESC, id LIMIT 2", "id,p\n5,\"d\"\n2,\"a\"\n");
    /* computing on a window: from a derived table */
    EXPECT("SELECT id, x - p AS d FROM (SELECT id, x, LAG(x) OVER (ORDER BY id) AS p FROM t) AS q WHERE x IS NOT NULL ORDER BY id",
           "id,d\n1,\n2,10\n3,0\n4,-15\n6,\n7,-6\n");
    /* in a nested SELECT and a set operation's arm */
    EXPECT("SELECT COUNT(*) FROM t WHERE id IN (SELECT id FROM (SELECT id, ROW_NUMBER() OVER (PARTITION BY g ORDER BY id) AS rn "
           "FROM t) AS q WHERE rn = 1)",
           "count\n3\n");
    EXPECT("SELECT id, RANK() OVER (ORDER BY g) FROM t WHERE id < 3 UNION ALL SELECT id, 0 FROM t WHERE id = 7", "id,x\n1,1\n2,1\n7,0\n");
    for (int pass = 0; pass < 2; pass++) { /* the same with cross_check */
        if (pass) CHECK(run("SET cross_check = on") == 0);
        SAME("SELECT id, MAX(x) OVER (PARTITION BY g) AS m FROM t ORDER BY id",
             "SELECT t.id, q.m FROM t JOIN (SELECT g, MAX(x) AS m FROM t GROUP BY g) AS q ON q.g = t.g ORDER BY t.id");
    }
    CHECK(run("SET cross_check = off") == 0);
    /* the transaction's own rows */
    CHECK(run("BEGIN") == 0 && run("INSERT INTO t VALUES (8, 3, 99, 'h')") == 0);
    EXPECT("SELECT id, ROW_NUMBER() OVER (PARTITION BY g ORDER BY x DESC) AS rn FROM t WHERE g = 3 ORDER BY id", "id,rn\n7,2\n8,1\n");
    CHECK(run("ROLLBACK") == 0);
    /* EXPLAIN: a window row; nothing computed, no row tested, nothing written */
    uint64_t seq = db->seq;
    const char *xp = csv("EXPLAIN SELECT id, ROW_NUMBER() OVER (ORDER BY x) FROM t");
    CHECK(strstr(xp, "\"window\",\"1 window function") != NULL && g_s.rows_tested == 0 && db->seq == seq);
    /* refused, each with its reason */
    EXPECT("SELECT id, x - LAG(x) OVER (ORDER BY id) FROM t", "ERR stands only as a SELECT item, alone");
    EXPECT("SELECT id FROM t WHERE ROW_NUMBER() OVER () > 1", "ERR stands only as a SELECT item");
    EXPECT("SELECT id FROM t ORDER BY RANK() OVER (ORDER BY x)", "ERR stands only as a SELECT item");
    EXPECT("SELECT id, SUM(DISTINCT x) OVER () FROM t", "ERR DISTINCT or FILTER with OVER");
    EXPECT("SELECT id, NTILE(0) OVER () FROM t", "ERR NTILE takes a positive integer");
    EXPECT("SELECT id, NTILE(x) OVER () FROM t", "ERR NTILE takes a positive integer");
    EXPECT("SELECT id, LAG(x, -1) OVER () FROM t", "ERR offset is an integer, 0 or more");
    EXPECT("SELECT id, LAG(x, 1, 'q') OVER (ORDER BY id) FROM t", "ERR LAG's and LEAD's value and default are INT64 and TEXT");
    EXPECT("SELECT id, SUM(s) OVER () FROM t", "ERR SUM needs");
    EXPECT("SELECT id, RANK() OVER (ORDER BY x RANGE BETWEEN 1 PRECEDING AND CURRENT ROW) FROM t", "ERR RANGE with an offset");
    EXPECT("SELECT id, SUM(x) OVER (ROWS BETWEEN 1 FOLLOWING AND CURRENT ROW) FROM t", "ERR cannot end before the row it starts at");
    EXPECT("SELECT id, SUM(x) OVER (ROWS UNBOUNDED FOLLOWING) FROM t", "ERR cannot start UNBOUNDED FOLLOWING");
    EXPECT("SELECT id, ROW_NUMBER() OVER w FROM t", "ERR expected (");
    EXPECT("SELECT id, ROW_NUMBER() FROM t", "ERR OVER (...) after a window function");
    EXPECT("SELECT id, ROW_NUMBER() OVER () FROM t FOR UPDATE", "ERR FOR UPDATE with window functions");
    EXPECT("SELECT DISTINCT id, ROW_NUMBER() OVER () FROM t ORDER BY x", "ERR ORDER BY names an item");
    EXPECT("SELECT COUNT(*) over FROM t", "ERR expected ("); /* OVER is reserved: not an alias */
    /* a join's rows (its hidden items through the join's sink, kept on the build side) and a row set's, under each plan
     * and with cross_check: as the same sums by GROUP BY */
    CHECK(run("CREATE TABLE u (id INT64 PRIMARY KEY, tid INT64, v INT64)") == 0);
    CHECK(run("INSERT INTO u VALUES (1, 1, 4), (2, 1, 6), (3, 2, 1), (4, 4, 9), (5, 6, NULL), (6, 9, 3)") == 0);
    for (int jp = 0; jp < 2; jp++)
        for (int cc = 0; cc < 2; cc++) {
            CHECK(run(jp ? "SET join_plan = index" : "SET join_plan = hash") == 0);
            CHECK(run(cc ? "SET cross_check = on" : "SET cross_check = off") == 0);
            SAME("SELECT t.id, u.id, SUM(u.v) OVER (PARTITION BY t.g) AS s FROM t LEFT JOIN u ON u.tid = t.id ORDER BY t.id, u.id",
                 "SELECT a.tid, a.uid, b.s FROM (SELECT t.id AS tid, u.id AS uid, t.g AS g FROM t LEFT JOIN u ON u.tid = t.id) AS a "
                 "JOIN (SELECT t.g AS g, SUM(u.v) AS s FROM t LEFT JOIN u ON u.tid = t.id GROUP BY t.g) AS b ON b.g = a.g "
                 "ORDER BY a.tid, a.uid");
            SAME("SELECT t.id, ROW_NUMBER() OVER (PARTITION BY t.g ORDER BY u.v DESC NULLS LAST, t.id, u.id) AS rn FROM t JOIN u "
                 "ON u.tid = t.id ORDER BY t.id, rn",
                 "SELECT t.id, ROW_NUMBER() OVER (PARTITION BY g ORDER BY v DESC NULLS LAST, id, uid) AS rn FROM (SELECT t.id, t.g, "
                 "u.v, u.id AS uid FROM t JOIN u ON u.tid = t.id) AS t ORDER BY t.id, rn");
        }
    CHECK(run("SET join_plan = auto") == 0 && run("SET cross_check = off") == 0);
    SAME("SELECT id, ROW_NUMBER() OVER (ORDER BY x DESC, id) AS rn FROM (SELECT id, x FROM t WHERE x IS NOT NULL) AS q ORDER BY id",
         "SELECT id, ROW_NUMBER() OVER (ORDER BY x DESC, id) AS rn FROM t WHERE x IS NOT NULL ORDER BY id");
    /* every row is computed before the tail: LIMIT 5 over 20,000 rows holds the 20,000 (the memory ceiling) */
    CHECK(run("CREATE TABLE big (id INT64 PRIMARY KEY, s TEXT)") == 0);
    for (int base = 0; base < 20000; base += 5000) {
        imdb_buf b;
        imdb_buf_init(&b);
        imdb_buf_put_str(&b, "INSERT INTO big VALUES ");
        for (int i = base + 1; i <= base + 5000; i++) imdb_buf_printf(&b, "%s(%d, 'r%d')", i > base + 1 ? ", " : "", i, i);
        imdb_buf_put_u8(&b, 0);
        CHECK(!imdb_buf_check(&b, &g_e) && !run((const char *)b.p));
        imdb_buf_free(&b);
    }
    CHECK(run("SET statement_memory = 1048576") == 0);
    EXPECT("SELECT id, s, ROW_NUMBER() OVER (ORDER BY id DESC) AS rn FROM big ORDER BY rn LIMIT 2", "ERR statement memory");
    CHECK(run("SET statement_memory = 0") == 0);
    EXPECT("SELECT id, s, ROW_NUMBER() OVER (ORDER BY id DESC) AS rn FROM big ORDER BY rn LIMIT 2",
           "id,s,rn\n20000,\"r20000\",1\n19999,\"r19999\",2\n");
    EXPECT("SELECT ROW_NUMBER() OVER ()", "ERR a window function needs FROM");
    done(db);
}

const test_case window_tests[] = {
    {"window_model", t_window_model},
    {"window_forms", t_window_forms},
};
const size_t window_ntests = sizeof window_tests / sizeof window_tests[0];
