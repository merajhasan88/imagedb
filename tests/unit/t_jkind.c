/* P2 S3 (docs/plan-p2.md): every join kind (INNER, LEFT, RIGHT, FULL, CROSS, FROM a, b) and ON's forms (key pairs,
 * other conditions on either side or across them, USING), against a model that tries every pair of two small tables
 * with NULL keys on both sides: each statement's rows, in the default order (side 1's key, the NULL-extended rows
 * last, then side 2's), under both join plans with cross_check on (the second plan builds the other side: FULL's two
 * orientations), in memory and in the lake; WHERE on a NULL-extended side (applied after the join: an anti-join);
 * aggregates over every kind. */
#include <stdlib.h>

#include "../../src/db.h"
#include "../../src/sql.h"
#include "thelp.h"

static imdb_session g_s;
static char g_out[1 << 17];

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

static const char *body(const char *s)
{
    const char *n = strchr(s, '\n');
    return n ? n + 1 : s;
}

/* the model's rows: two tables of small domains, NULLs among the keys */
enum { NA = 24, NB = 21 };
typedef struct mrow {
    int id;
    int k1; /* -1: NULL */
    int k2; /* 0 'p', 1 'q', -1 NULL */
    int z;
} mrow;
static mrow g_a[NA], g_b[NB];

static uint64_t g_seed;
static int rnd(int n)
{
    g_seed ^= g_seed << 13;
    g_seed ^= g_seed >> 7;
    g_seed ^= g_seed << 17;
    return (int)(g_seed % (uint64_t)n);
}

static void fill(mrow *t, int n, int base)
{
    for (int i = 0; i < n; i++) {
        t[i].id = base + i;
        t[i].k1 = rnd(6) == 0 ? -1 : rnd(5);
        t[i].k2 = rnd(5) == 0 ? -1 : rnd(2);
        t[i].z = rnd(10);
    }
}

/* ON's forms, as the model tests a pair; each 1 (TRUE) or 0 (FALSE or UNKNOWN) */
enum { ON_K1, ON_K1K2, ON_K1_BZ, ON_K1_ZLT, ON_USING_K1, ON_CROSS, ON_COMMA_K1, NON };
static const char *const ON_SQL[NON] = {"ON a.k1 = b.k1", "ON a.k1 = b.k1 AND a.k2 = b.k2", "ON a.k1 = b.k1 AND b.z > 4",
                                        "ON a.k1 = b.k1 AND a.z < b.z", "USING (k1)", "", ""};
static bool on_ok(int on, const mrow *x, const mrow *y)
{
    bool k1 = x->k1 >= 0 && y->k1 >= 0 && x->k1 == y->k1;
    switch (on) {
    case ON_K1:
    case ON_USING_K1:
    case ON_COMMA_K1: return k1;
    case ON_K1K2: return k1 && x->k2 >= 0 && y->k2 >= 0 && x->k2 == y->k2;
    case ON_K1_BZ: return k1 && y->z > 4;
    case ON_K1_ZLT: return k1 && x->z < y->z;
    default: return true; /* CROSS */
    }
}

enum { K_INNER, K_LEFT, K_RIGHT, K_FULL };
static const char *const KIND_SQL[] = {"JOIN", "LEFT JOIN", "RIGHT JOIN", "FULL JOIN"};

/* WHERE after the join: none, a.z > 3 (drops NULL-extended a), a.id IS NULL (only b rows nothing matched) */
enum { W_NONE, W_AZ, W_ANULL, NW };
static const char *const WHERE_SQL[NW] = {"", " WHERE a.z > 3", " WHERE a.id IS NULL"};
static bool where_ok(int w, const mrow *x)
{
    if (w == W_AZ) return x && x->z > 3;
    if (w == W_ANULL) return !x;
    return true;
}

typedef struct pair {
    int a, b; /* -1: NULL-extended */
} pair;

static int cmp_pair(const void *p, const void *q)
{
    const pair *x = p, *y = q;
    if ((x->a < 0) != (y->a < 0)) return x->a < 0 ? 1 : -1; /* side 1's key, NULL last */
    if (x->a != y->a) return x->a < y->a ? -1 : 1;
    if ((x->b < 0) != (y->b < 0)) return x->b < 0 ? 1 : -1;
    return x->b < y->b ? -1 : x->b > y->b;
}

/* the model's answer to SELECT a.id, b.id FROM a <kind> b <on> <where>, rendered as the CLI renders it */
static void model(int kind, int on, int w, char *out, size_t cap)
{
    static pair pr[NA * NB + NA + NB];
    int n = 0;
    bool bm[NB] = {false};
    for (int i = 0; i < NA; i++) {
        bool am = false;
        for (int j = 0; j < NB; j++) {
            if (!on_ok(on, &g_a[i], &g_b[j])) continue;
            am = bm[j] = true;
            if (where_ok(w, &g_a[i])) pr[n++] = (pair){g_a[i].id, g_b[j].id};
        }
        if (!am && (kind == K_LEFT || kind == K_FULL) && where_ok(w, &g_a[i])) pr[n++] = (pair){g_a[i].id, -1};
    }
    for (int j = 0; j < NB; j++)
        if (!bm[j] && (kind == K_RIGHT || kind == K_FULL) && where_ok(w, NULL)) pr[n++] = (pair){-1, g_b[j].id};
    qsort(pr, (size_t)n, sizeof *pr, cmp_pair);
    size_t o = (size_t)snprintf(out, cap, "id,id\n");
    for (int i = 0; i < n && o < cap; i++) {
        char a[16] = "", b[16] = "";
        if (pr[i].a >= 0) snprintf(a, sizeof a, "%d", pr[i].a);
        if (pr[i].b >= 0) snprintf(b, sizeof b, "%d", pr[i].b);
        o += (size_t)snprintf(out + o, cap - o, "%s,%s\n", a, b);
    }
}

static void put_rows(const mrow *t, int n, const char *name)
{
    imdb_buf b;
    imdb_buf_init(&b);
    imdb_buf_printf(&b, "INSERT INTO %s VALUES ", name);
    for (int i = 0; i < n; i++) {
        char k1[16], k2[8];
        if (t[i].k1 < 0) snprintf(k1, sizeof k1, "NULL");
        else snprintf(k1, sizeof k1, "%d", t[i].k1);
        snprintf(k2, sizeof k2, "%s", t[i].k2 < 0 ? "NULL" : t[i].k2 ? "'q'" : "'p'");
        imdb_buf_printf(&b, "%s(%d, %s, %s, %d)", i ? ", " : "", t[i].id, k1, k2, t[i].z);
    }
    imdb_buf_put_u8(&b, 0);
    CHECK(!imdb_buf_check(&b, &g_e) && !run((const char *)b.p));
    imdb_buf_free(&b);
}

static void t_jkind_model(void)
{
    const char *dir = test_tmpdir();
    imdb_err e = {0};
    CHECK(imdb_init(dir, false, NULL, &e) == 0);
    imdb_open_opts op = {.sync = 0};
    imdb_db *db = NULL;
    CHECK(imdb_open(dir, &op, &db, &e) == 0);
    if (!db) return;
    imdb_session_init(&g_s, db);
    g_seed = 0x9E3779B97F4A7C15ull;
    fill(g_a, NA, 1);
    fill(g_b, NB, 101);
    CHECK(run("CREATE TABLE a (id INT64 PRIMARY KEY, k1 INT64, k2 TEXT, z INT64)") == 0);
    CHECK(run("CREATE TABLE b (id INT64 PRIMARY KEY, k1 INT64, k2 TEXT, z INT64)") == 0);
    put_rows(g_a, NA, "a");
    put_rows(g_b, NB, "b");
    CHECK(run("CREATE INDEX a_k1 ON a (k1)") == 0); /* plan C may probe either side */
    CHECK(run("CREATE INDEX b_k1 ON b (k1)") == 0);
    CHECK(run("SET cross_check = on") == 0);
    static char want[1 << 16], q[512];
    int checked = 0;
    for (int pass = 0; pass < 2; pass++) { /* in memory, then in the lake */
        for (int plan = 0; plan < 2; plan++) {
            CHECK(run(plan ? "SET join_plan = index" : "SET join_plan = hash") == 0);
            for (int kind = K_INNER; kind <= K_FULL; kind++)
                for (int on = 0; on <= ON_USING_K1; on++)
                    for (int w = 0; w < NW; w++) {
                        if (w == W_ANULL && kind != K_RIGHT && kind != K_FULL) continue;
                        snprintf(q, sizeof q, "SELECT a.id, b.id FROM a %s b %s%s", KIND_SQL[kind], ON_SQL[on], WHERE_SQL[w]);
                        model(kind, on, w, want, sizeof want);
                        const char *got = csv(q);
                        checked++;
                        if (strcmp(body(got), body(want))) {
                            char m[600];
                            snprintf(m, sizeof m, "%s (pass %d, plan %d)\n      want: %.200s\n      got:  %.200s", q, pass,
                                     plan, body(want), got);
                            test_fail(__FILE__, __LINE__, m);
                        }
                    }
            /* CROSS and FROM a, b */
            model(K_INNER, ON_CROSS, W_NONE, want, sizeof want);
            CHECK(!strcmp(body(csv("SELECT a.id, b.id FROM a CROSS JOIN b")), body(want)));
            model(K_INNER, ON_COMMA_K1, W_NONE, want, sizeof want);
            CHECK(!strcmp(body(csv("SELECT a.id, b.id FROM a, b WHERE a.k1 = b.k1")), body(want)));
            checked += 2;
        }
        if (!pass) CHECK(run("CHECKPOINT") == 0);
    }
    CHECK(checked == 2 * 2 * (4 * 5 * 2 + 2 * 5 * 1) + 2 * 2 * 2);
    imdb_session_close(&g_s);
    imdb_close(db);
}

/* aggregates over each kind (the joined rows fed to a sink, NULL-extended ones too), against the model's counts */
static void t_jkind_aggregates(void)
{
    const char *dir = test_tmpdir();
    imdb_err e = {0};
    CHECK(imdb_init(dir, false, NULL, &e) == 0);
    imdb_open_opts op = {.sync = 0};
    imdb_db *db = NULL;
    CHECK(imdb_open(dir, &op, &db, &e) == 0);
    if (!db) return;
    imdb_session_init(&g_s, db);
    g_seed = 0xD1B54A32D192ED03ull;
    fill(g_a, NA, 1);
    fill(g_b, NB, 101);
    CHECK(run("CREATE TABLE a (id INT64 PRIMARY KEY, k1 INT64, k2 TEXT, z INT64)") == 0);
    CHECK(run("CREATE TABLE b (id INT64 PRIMARY KEY, k1 INT64, k2 TEXT, z INT64)") == 0);
    put_rows(g_a, NA, "a");
    put_rows(g_b, NB, "b");
    CHECK(run("SET cross_check = on") == 0);
    static char q[512], want[256];
    for (int kind = K_INNER; kind <= K_FULL; kind++)
        for (int on = 0; on <= ON_K1_ZLT; on++) {
            long rows = 0, bids = 0, asum = 0;
            bool bm[NB] = {false};
            for (int i = 0; i < NA; i++) {
                bool am = false;
                for (int j = 0; j < NB; j++)
                    if (on_ok(on, &g_a[i], &g_b[j])) {
                        am = bm[j] = true;
                        rows++, bids++, asum += g_a[i].z;
                    }
                if (!am && (kind == K_LEFT || kind == K_FULL)) rows++, asum += g_a[i].z;
            }
            for (int j = 0; j < NB; j++)
                if (!bm[j] && (kind == K_RIGHT || kind == K_FULL)) rows++, bids++;
            snprintf(q, sizeof q, "SELECT COUNT(*), COUNT(b.id), SUM(a.z) FROM a %s b %s", KIND_SQL[kind], ON_SQL[on]);
            snprintf(want, sizeof want, "x\n%ld,%ld,%ld\n", rows, bids, asum);
            const char *got = csv(q);
            if (strcmp(body(got), body(want))) {
                char m[600];
                snprintf(m, sizeof m, "%s\n      want: %s      got:  %s", q, body(want), got);
                test_fail(__FILE__, __LINE__, m);
            }
        }
    CHECK(!strcmp(body(csv("SELECT COUNT(*) FROM a CROSS JOIN b")), "504\n"));
    imdb_session_close(&g_s);
    imdb_close(db);
}

const test_case jkind_tests[] = {
    {"jkind_model", t_jkind_model},
    {"jkind_aggregates", t_jkind_aggregates},
};
const size_t jkind_ntests = sizeof jkind_tests / sizeof *jkind_tests;
