/* Joins (E2 stages 3 and 4): INNER and LEFT, two tables, one equality, by the hash join and by the
 * index nested-loop join (plan C). Every result is checked against a nested-loop oracle computed
 * here from the two tables' own SELECT results (one-table reads, which the engine cross-checks on
 * their own), and inside the engine against the hash join building the other side with each side
 * read by scan (cross_check). */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../../src/db_internal.h"
#include "../../src/sql.h"
#include "thelp.h"

static int ex(imdb_session *s, const char *sql)
{
    imdb_result r;
    imdb_err_clear(E);
    int rc = imdb_exec_one(s, sql, strlen(sql), NULL, 0, &r, E);
    if (!rc) imdb_result_free(&r);
    return rc;
}

static imdb_db *jopen(const char *dir, bool full_replay)
{
    imdb_open_opts o = {.sync = 0, .full_replay = full_replay};
    imdb_db *db = NULL;
    imdb_err_clear(E);
    return imdb_open(dir, &o, &db, E) ? NULL : db;
}

/* a row as the oracle sees it (both tables: id, k INT64 NULL, v INT64 NOT NULL, s TEXT NULL, d DECIMAL NULL) */
typedef struct orow {
    int64_t id, k, v, d;
    bool knull, snull, dnull;
    char s[16];
} orow;

enum { MAXR = 2048, MAXP = MAXR * 16 };
static orow g_a[MAXR], g_b[MAXR], g_bw[MAXR];
static int64_t g_want[MAXP][2], g_got[MAXP][2];
static uint64_t g_joined, g_extended; /* not vacuous: rows the cases compared, NULL-extended among them */
static uint64_t g_plans[3];            /* the cases' plans: join(build 2), join(index 2), join(index 1) */

/* SELECT id, k, v, s, d ... as oracle rows (in primary-key order) */
static size_t fetch(imdb_session *s, const char *q, orow *out)
{
    imdb_result r;
    imdb_err_clear(E);
    if (imdb_exec_one(s, q, strlen(q), NULL, 0, &r, E)) { /* a helper with a value: test_fail, not OK */
        test_fail(__FILE__, __LINE__, g_e.msg);
        return 0;
    }
    size_t n = 0;
    for (uint64_t i = 0; i < r.nrows && n < MAXR; i++, n++) {
        const imdb_cell *c = &r.cells[i * r.ncols];
        orow *o = &out[n];
        memset(o, 0, sizeof *o);
        o->id = c[0].v.i;
        o->knull = c[1].null;
        o->k = c[1].v.i;
        o->v = c[2].v.i;
        o->snull = c[3].null;
        if (!c[3].null) snprintf(o->s, sizeof o->s, "%.*s", (int)c[3].v.len, (const char *)c[3].v.s);
        o->dnull = c[4].null;
        o->d = c[4].v.i;
    }
    if (r.nrows >= MAXR) test_fail(__FILE__, __LINE__, "more rows than the oracle holds");
    imdb_result_free(&r);
    return n;
}

enum { KEY_K, KEY_S, KEY_D, KEY_V, KEY_AID, KEY_BID };

/* ON of each kind: a.k = b.k, a.s = b.s, b.d = a.d, a.v = b.v, a.id = b.k, b.id = a.k */
static bool key_eq(const orow *a, const orow *b, int kind)
{
    switch (kind) {
    case KEY_K: return !a->knull && !b->knull && a->k == b->k;
    case KEY_S: return !a->snull && !b->snull && strcmp(a->s, b->s) == 0;
    case KEY_D: return !a->dnull && !b->dnull && a->d == b->d;
    case KEY_V: return a->v == b->v;
    case KEY_AID: return !b->knull && a->id == b->k;
    default: return !a->knull && a->k == b->id;
    }
}

/* The join by nested loops: A' is side 0 after its own WHERE, B side 1 whole and B' side 1 after
 * its WHERE (a joined row passes when its side-1 row is in B'). LEFT keeps an A' row with no ON
 * match as (id, -1) when side 1's WHERE holds for NULLs (b_null). The pairs come out in the
 * engine's order: A' is in id order, B too, and the NULL row is an A' row's only one. */
static size_t oracle(size_t na, size_t nb, size_t nbw, int kind, bool left, bool b_null)
{
    size_t n = 0;
    for (size_t i = 0; i < na; i++) {
        bool any = false;
        for (size_t j = 0; j < nb; j++) {
            if (!key_eq(&g_a[i], &g_b[j], kind)) continue;
            any = true;
            bool pass = false;
            for (size_t w = 0; w < nbw && !pass; w++) pass = g_bw[w].id == g_b[j].id;
            if (pass && n < MAXP) g_want[n][0] = g_a[i].id, g_want[n][1] = g_b[j].id, n++;
        }
        if (left && !any && b_null && n < MAXP) g_want[n][0] = g_a[i].id, g_want[n][1] = -1, n++;
    }
    if (n >= MAXP) test_fail(__FILE__, __LINE__, "more pairs than the oracle holds");
    return n;
}

static const orow *by_id(const orow *rows, size_t n, int64_t id)
{
    for (size_t i = 0; i < n; i++)
        if (rows[i].id == id) return &rows[i];
    return NULL;
}

/* a pair's group key (false: the NULL group) */
typedef bool (*gkey_fn)(const orow *x, const orow *y, int64_t *k);
static bool gk_ak(const orow *x, const orow *y, int64_t *k)
{
    (void)y;
    if (!x || x->knull) return false;
    *k = x->k;
    return true;
}
static bool gk_bk(const orow *x, const orow *y, int64_t *k)
{
    (void)x;
    if (!y || y->knull) return false;
    *k = y->k;
    return true;
}
static bool gk_bv(const orow *x, const orow *y, int64_t *k) /* b.v is NOT NULL: only a missing b is NULL */
{
    (void)x;
    if (!y) return false;
    *k = y->v;
    return true;
}

typedef struct ogroup {
    bool null, has_sum;
    int64_t key, cnt, sum; /* COUNT(*), SUM(b.v) */
} ogroup;

static int cmp_ogroup(const void *a, const void *b) /* by COUNT, then SUM: a multiset's order */
{
    const ogroup *x = a, *y = b;
    if (x->cnt != y->cnt) return x->cnt < y->cnt ? -1 : 1;
    if (x->has_sum != y->has_sum) return x->has_sum ? 1 : -1;
    return x->sum < y->sum ? -1 : x->sum > y->sum;
}

/* q groups the join by fn's key, selecting the key (with_key) or not, then COUNT(*), SUM(b.v):
 * its groups against the oracle's, matched by key, or as a multiset when the key is not selected */
static void group_case(imdb_session *s, const char *q, bool with_key, gkey_fn fn, size_t na, size_t nb, size_t nw)
{
    ogroup want[32], got[32];
    size_t nwant = 0, ngot = 0;
    for (size_t i = 0; i < nw && nwant <= 32; i++) {
        const orow *x = by_id(g_a, na, g_want[i][0]), *y = g_want[i][1] < 0 ? NULL : by_id(g_b, nb, g_want[i][1]);
        int64_t k = 0;
        bool has = fn(x, y, &k);
        size_t j = 0;
        while (j < nwant && !(want[j].null == !has && (!has || want[j].key == k))) j++;
        if (j == nwant && nwant++ < 32) want[j] = (ogroup){.null = !has, .key = k};
        if (j < 32) {
            want[j].cnt++;
            if (y) want[j].sum += y->v, want[j].has_sum = true;
        }
    }
    CHECK(nwant <= 32);
    imdb_result r;
    imdb_err_clear(E);
    OK(imdb_exec_one(s, q, strlen(q), NULL, 0, &r, E));
    uint64_t nrows = r.nrows;
    bool ok = nrows == nwant && strstr(r.path, "(cross-checked)") != NULL;
    for (uint64_t i = 0; ok && i < nrows; i++) {
        const imdb_cell *c = &r.cells[i * r.ncols];
        int o = with_key ? 1 : 0;
        got[ngot++] = (ogroup){.null = with_key && c[0].null, .key = with_key ? c[0].v.i : 0, .cnt = c[o].v.i,
                               .sum = (int64_t)c[o + 1].i128, .has_sum = !c[o + 1].null};
    }
    imdb_result_free(&r);
    if (ok && with_key) {
        for (size_t i = 0; ok && i < ngot; i++) {
            size_t j = 0;
            while (j < nwant && !(want[j].null == got[i].null && (got[i].null || want[j].key == got[i].key))) j++;
            ok = j < nwant && cmp_ogroup(&want[j], &got[i]) == 0;
        }
    } else if (ok) {
        qsort(want, nwant, sizeof *want, cmp_ogroup);
        qsort(got, ngot, sizeof *got, cmp_ogroup);
        for (size_t i = 0; ok && i < ngot; i++) ok = cmp_ogroup(&want[i], &got[i]) == 0;
    }
    if (!ok) fprintf(stderr, "    %s: %llu groups, the oracle %zu\n", q, (unsigned long long)nrows, nwant);
    CHECK(ok);
}

/* The engine's join of the same query, as pairs (it selects a.id, b.id), and its aggregates
 * against the oracle's pairs: COUNT(*), SUM(b.v), MIN(a.v), MAX(b.v), and COUNT(*) grouped by a.v */
static void join_case(imdb_session *s, const char *on, int kind, bool left, const char *aw, const char *bw, bool b_null,
                      const char *asof)
{
    char q[640], where[400] = "";
    snprintf(q, sizeof q, "SELECT id, k, v, s, d FROM a%s%s%s", asof, aw[0] ? " WHERE " : "", aw);
    size_t na = fetch(s, q, g_a);
    snprintf(q, sizeof q, "SELECT id, k, v, s, d FROM b%s", asof);
    size_t nb = fetch(s, q, g_b);
    snprintf(q, sizeof q, "SELECT id, k, v, s, d FROM b%s%s%s", asof, bw[0] ? " WHERE " : "", bw);
    size_t nbw = fetch(s, q, g_bw);
    size_t nw = oracle(na, nb, nbw, kind, left, b_null);
    if (aw[0] || bw[0]) snprintf(where, sizeof where, " WHERE %s%s%s", aw, aw[0] && bw[0] ? " AND " : "", bw);
    const char *lj = left ? "LEFT " : "";
    snprintf(q, sizeof q, "SELECT a.id, b.id FROM a %sJOIN b ON %s%s%s", lj, on, asof, where);
    imdb_result r;
    imdb_err_clear(E);
    int rc = imdb_exec_one(s, q, strlen(q), NULL, 0, &r, E);
    OK_RC(rc);
    if (rc) return;
    CHECK(strstr(r.path, "(cross-checked)") != NULL);
    g_plans[strncmp(r.path, "join(index 2)", 13) == 0 ? 1 : strncmp(r.path, "join(index 1)", 13) == 0 ? 2 : 0]++;
    size_t ng = 0;
    for (uint64_t i = 0; i < r.nrows && ng < MAXP; i++, ng++) {
        g_got[ng][0] = r.cells[i * 2].v.i;
        g_got[ng][1] = r.cells[i * 2 + 1].null ? -1 : r.cells[i * 2 + 1].v.i;
    }
    imdb_result_free(&r);
    CHECK(ng == nw && (!ng || memcmp(g_got, g_want, ng * sizeof *g_got) == 0));
    g_joined += nw;
    for (size_t i = 0; i < nw; i++) g_extended += g_want[i][1] < 0;
    /* the aggregates of the oracle's pairs */
    int64_t sum = 0, mina = 0, maxb = 0;
    bool hasa = false, hasb = false;
    const char *maxs = NULL;
    for (size_t i = 0; i < nw; i++) {
        const orow *x = by_id(g_a, na, g_want[i][0]), *y = g_want[i][1] < 0 ? NULL : by_id(g_b, nb, g_want[i][1]);
        if (x && (!hasa || x->v < mina)) mina = x->v, hasa = true;
        if (y) {
            sum += y->v;
            if (!hasb || y->v > maxb) maxb = y->v, hasb = true;
            if (!y->snull && (!maxs || strcmp(y->s, maxs) > 0)) maxs = y->s;
        }
    }
    snprintf(q, sizeof q, "SELECT COUNT(*), SUM(b.v), MIN(a.v), MAX(b.v), MAX(b.s) FROM a %sJOIN b ON %s%s%s", lj, on, asof,
             where);
    imdb_err_clear(E);
    rc = imdb_exec_one(s, q, strlen(q), NULL, 0, &r, E);
    OK_RC(rc);
    if (!rc) {
        const imdb_cell *c = r.cells;
        CHECK(r.nrows == 1 && c[0].v.i == (int64_t)nw);
        CHECK(hasb ? !c[1].null && (int64_t)c[1].i128 == sum : c[1].null);
        CHECK(hasa ? !c[2].null && c[2].v.i == mina : c[2].null);
        CHECK(hasb ? !c[3].null && c[3].v.i == maxb : c[3].null);
        CHECK(maxs ? !c[4].null && c[4].v.len == strlen(maxs) && (!c[4].v.len || memcmp(c[4].v.s, maxs, c[4].v.len) == 0)
                   : c[4].null);
        imdb_result_free(&r);
    }
    /* GROUP BY a TEXT column of side 1: kept, copied, from the build side under plan A */
    snprintf(q, sizeof q, "SELECT b.s, COUNT(*) FROM a %sJOIN b ON %s%s%s GROUP BY b.s", lj, on, asof, where);
    imdb_err_clear(E);
    rc = imdb_exec_one(s, q, strlen(q), NULL, 0, &r, E);
    OK_RC(rc);
    if (!rc) {
        uint64_t total = 0;
        for (uint64_t g = 0; g < r.nrows; g++) {
            const imdb_cell *c = &r.cells[g * 2];
            int64_t want = 0;
            for (size_t i = 0; i < nw; i++) {
                const orow *y = g_want[i][1] < 0 ? NULL : by_id(g_b, nb, g_want[i][1]);
                bool ynull = !y || y->snull;
                want += c[0].null ? ynull
                                  : !ynull && strlen(y->s) == c[0].v.len &&
                                        (!c[0].v.len || memcmp(y->s, c[0].v.s, c[0].v.len) == 0);
            }
            CHECK(c[1].v.i == want);
            total += (uint64_t)c[1].v.i;
        }
        CHECK(total == nw);
        imdb_result_free(&r);
    }
    snprintf(q, sizeof q, "SELECT a.v, COUNT(*) FROM a %sJOIN b ON %s%s%s GROUP BY a.v", lj, on, asof, where);
    imdb_err_clear(E);
    rc = imdb_exec_one(s, q, strlen(q), NULL, 0, &r, E);
    OK_RC(rc);
    if (!rc) {
        uint64_t total = 0;
        for (uint64_t g = 0; g < r.nrows; g++) {
            int64_t v = r.cells[g * 2].v.i, cnt = r.cells[g * 2 + 1].v.i, want = 0;
            for (size_t i = 0; i < nw; i++) {
                const orow *x = by_id(g_a, na, g_want[i][0]);
                want += x && x->v == v;
            }
            CHECK(cnt == want);
            total += (uint64_t)cnt;
        }
        CHECK(total == nw);
        imdb_result_free(&r);
    }
    /* GROUP BY a nullable column of side 1: NULL-extended rows and NULL keys are one group */
    snprintf(q, sizeof q, "SELECT b.k, COUNT(*) FROM a %sJOIN b ON %s%s%s GROUP BY b.k", lj, on, asof, where);
    imdb_err_clear(E);
    rc = imdb_exec_one(s, q, strlen(q), NULL, 0, &r, E);
    OK_RC(rc);
    if (!rc) {
        uint64_t total = 0;
        for (uint64_t g = 0; g < r.nrows; g++) {
            bool gnull = r.cells[g * 2].null;
            int64_t kv = r.cells[g * 2].v.i, cnt = r.cells[g * 2 + 1].v.i, want = 0;
            for (size_t i = 0; i < nw; i++) {
                const orow *y = g_want[i][1] < 0 ? NULL : by_id(g_b, nb, g_want[i][1]);
                bool ynull = !y || y->knull;
                want += gnull ? ynull : !ynull && y->k == kv;
            }
            CHECK(cnt == want);
            total += (uint64_t)cnt;
        }
        CHECK(total == nw);
        imdb_result_free(&r);
    }
    /* GROUP BY b.v, NOT NULL in b and yet a NULL group under LEFT; and keys not selected, which
     * only the group column makes a read column of the build side */
    char gq[640];
    snprintf(gq, sizeof gq, "SELECT b.v, COUNT(*), SUM(b.v) FROM a %sJOIN b ON %s%s%s GROUP BY b.v", lj, on, asof, where);
    group_case(s, gq, true, gk_bv, na, nb, nw);
    snprintf(gq, sizeof gq, "SELECT COUNT(*), SUM(b.v) FROM a %sJOIN b ON %s%s%s GROUP BY a.k", lj, on, asof, where);
    group_case(s, gq, false, gk_ak, na, nb, nw);
    snprintf(gq, sizeof gq, "SELECT COUNT(*), SUM(b.v) FROM a %sJOIN b ON %s%s%s GROUP BY b.k", lj, on, asof, where);
    group_case(s, gq, false, gk_bk, na, nb, nw);
    /* LIMIT: the first rows of the same order */
    snprintf(q, sizeof q, "SELECT a.id, b.id FROM a %sJOIN b ON %s%s%s LIMIT 7", lj, on, asof, where);
    imdb_err_clear(E);
    rc = imdb_exec_one(s, q, strlen(q), NULL, 0, &r, E);
    OK_RC(rc);
    if (!rc) {
        CHECK(r.nrows == (nw < 7 ? nw : 7));
        for (uint64_t i = 0; i < r.nrows; i++) {
            CHECK(r.cells[i * 2].v.i == g_want[i][0]);
            CHECK((r.cells[i * 2 + 1].null ? -1 : r.cells[i * 2 + 1].v.i) == g_want[i][1]);
        }
        imdb_result_free(&r);
    }
    if (g_test_failed) fprintf(stderr, "    the join: %s (oracle %zu rows, engine %zu)\n", q, nw, ng);
}

/* n rows into table tb from id base: k in 0..7 or NULL, v in -4..4, s from a few words or NULL,
 * d from three values or NULL: duplicate keys on both sides, on purpose. Two words share their
 * first 8 bytes, an index word: only the key's own check tells them apart */
static void load(imdb_session *s, const char *tb, int base, int n)
{
    static const char *const words[] = {"'x'", "'y'", "'xy'", "''", "'x'", "NULL", "'prefix-a'", "'prefix-ab'"};
    static const char *const decs[] = {"1.00", "2.50", "-3.25", "NULL"};
    char q[256], k[16];
    for (int i = 0; i < n; i++) {
        if (test_rand() % 8) snprintf(k, sizeof k, "%d", (int)(test_rand() % 8));
        else snprintf(k, sizeof k, "NULL");
        snprintf(q, sizeof q, "INSERT INTO %s VALUES (%d, %s, %d, %s, %s)", tb, base + i, k, (int)(test_rand() % 9) - 4,
                 words[test_rand() % 8], decs[test_rand() % 4]);
        OK(ex(s, q));
    }
}

static const struct {
    const char *aw, *bw;
    bool b_null; /* side 1's WHERE holds for a NULL-extended row */
} kWhere[] = {
    {"", "", true},
    {"a.v BETWEEN -2 AND 2", "", true},
    {"", "b.v > 0", false},
    {"a.v < 0", "b.v != 1", false},
    {"", "b.s IS NULL", true},
    {"a.k = 3", "b.d >= 1.00", false},
    {"a.s >= 'x'", "b.s IS NOT NULL", false},
    {"", "b.v IS NULL", true}, /* b.v is NOT NULL: in a LEFT join, the rows without a match (an anti-join), which only a post-join test keeps */
};

static const struct {
    const char *on;
    int kind;
} kKeys[] = {
    {"a.k = b.k", KEY_K}, {"a.s = b.s", KEY_S}, {"b.d = a.d", KEY_D}, {"a.v = b.v", KEY_V}, {"a.id = b.k", KEY_AID}, {"b.id = a.k", KEY_BID},
};

/* every key and WHERE shape, INNER and LEFT, by the hash join and by plan C (each key has a probe
 * on side 2, and all but s and d one on side 1 too: join_plan = index never falls back here) */
static void all_cases(imdb_session *s, const char *asof)
{
    for (int plan = IMDB_JOIN_HASH; plan <= IMDB_JOIN_INDEX && !g_test_failed; plan++) {
        s->join_plan = plan;
        for (size_t w = 0; w < sizeof kWhere / sizeof *kWhere && !g_test_failed; w++)
            for (int left = 0; left < 2; left++)
                for (size_t k = 0; k < sizeof kKeys / sizeof *kKeys; k++)
                    join_case(s, kKeys[k].on, kKeys[k].kind, left, kWhere[w].aw, kWhere[w].bw, kWhere[w].b_null, asof);
    }
    s->join_plan = IMDB_JOIN_AUTO;
}

/* INNER and LEFT on INT64, TEXT and DECIMAL keys with NULLs and duplicates, pushed and post-join
 * predicates, through updates and deletes on both sides, AS OF an earlier commit, a checkpoint
 * (segments on one side, rows in memory on the other), indexes on a join column and a predicate
 * column, a transaction's own rows on both sides, and both kinds of reopen. Plan C probes every
 * kind of lookup: primary keys (a.id, b.id), b's subject (v), single-column indexes (b.k, a.v), a
 * unique one (b.d, through its ordered structure), and two-column indexes whose later column is
 * NULL in some rows (a (k, s), b (s, k)): the rows a NULL there once left out of the index */
static void t_join_oracle(void)
{
    const char *dir = test_tmpdir();
    OK(imdb_init(dir, false, NULL, E));
    imdb_db *db = jopen(dir, false);
    CHECK(db);
    if (!db) return;
    imdb_session s;
    imdb_session_init(&s, db);
    s.cross_check = true;
    OK(ex(&s, "CREATE TABLE a (id INT64 PRIMARY KEY, k INT64 NULL, v INT64 NOT NULL, s TEXT NULL, d DECIMAL(8,2) NULL)"));
    OK(ex(&s, "CREATE TABLE b (id INT64 PRIMARY KEY, k INT64 NULL, v INT64 SUBJECT, s TEXT NULL, d DECIMAL(8,2) NULL)"));
    load(&s, "a", 1, 60);
    /* rows that a_ks (k, s) holds by k alone, read through it under a.k = 3 by either plan: the NULL
     * bug of 2026-10-26 hid them, and the hash join's cross-check passed while it read side 1
     * through a_ks too */
    OK(ex(&s, "INSERT INTO a VALUES (90, 3, 1, NULL, 1.00), (91, 3, -2, NULL, NULL)"));
    load(&s, "b", 1, 80);
    OK(ex(&s, "CREATE INDEX b_k ON b (k)"));
    OK(ex(&s, "CREATE INDEX a_v ON a (v)"));
    OK(ex(&s, "CREATE INDEX a_ks ON a (k, s)"));
    OK(ex(&s, "CREATE INDEX b_sk ON b (s, k)"));
    OK(ex(&s, "CREATE UNIQUE INDEX b_du ON b (d, id)"));
    uint64_t before = 0;
    char q[256];
    for (int round = 0; round < 3 && !g_test_failed; round++) {
        all_cases(&s, "");
        for (int plan = IMDB_JOIN_HASH; before && plan <= IMDB_JOIN_INDEX; plan++) {
            s.join_plan = plan;
            snprintf(q, sizeof q, " AS OF %llu", (unsigned long long)before);
            join_case(&s, "a.k = b.k", KEY_K, true, "a.v BETWEEN -2 AND 2", "b.v > 0", false, q);
            join_case(&s, "a.s = b.s", KEY_S, false, "", "", true, q);
            join_case(&s, "b.id = a.k", KEY_BID, true, "", "", true, q);   /* side 2's primary-key chain */
            join_case(&s, "a.v = b.v", KEY_V, false, "a.k = 3", "", true, q); /* b's subject list, a through a_ks */
            s.join_plan = IMDB_JOIN_AUTO;
        }
        before = db->seq;
        snprintf(q, sizeof q, "UPDATE b SET k = %d WHERE id BETWEEN %d AND %d", round, round * 20 + 1, round * 20 + 8);
        OK(ex(&s, q));
        snprintf(q, sizeof q, "DELETE FROM a WHERE id BETWEEN %d AND %d", round * 15 + 1, round * 15 + 4);
        OK(ex(&s, q));
        load(&s, "a", 100 + round * 10, 10);
        if (round == 0) OK(ex(&s, "CHECKPOINT"));
    }
    /* a transaction's own rows on both sides, and its own delete */
    OK(ex(&s, "BEGIN"));
    OK(ex(&s, "INSERT INTO a VALUES (1000, 3, 1, 'x', 1.00)"));
    OK(ex(&s, "INSERT INTO b VALUES (1000, 3, 2, 'x', 1.00)"));
    OK(ex(&s, "DELETE FROM b WHERE id = 30"));
    OK(ex(&s, "UPDATE a SET s = NULL WHERE id = 1000")); /* its own row, a NULL later column of a_ks */
    for (int plan = IMDB_JOIN_HASH; plan <= IMDB_JOIN_INDEX; plan++) { /* plan C: the own rows past idx_upto */
        s.join_plan = plan;
        join_case(&s, "a.k = b.k", KEY_K, false, "", "", true, "");
        join_case(&s, "a.k = b.k", KEY_K, true, "", "b.v > 0", false, "");
        join_case(&s, "b.id = a.k", KEY_BID, false, "a.k = 3", "", true, "");
        join_case(&s, "a.v = b.v", KEY_V, true, "", "", true, "");
    }
    s.join_plan = IMDB_JOIN_AUTO;
    OK(ex(&s, "ROLLBACK"));
    /* a self-join: two names for one table; under plan C with x.k = 3 both sides range a_ks, the
     * probe inside the outer side's own range */
    static const char *const self[] = {"SELECT COUNT(*) FROM a AS x JOIN a AS y ON x.k = y.k",
                                       "SELECT COUNT(*) FROM a AS x JOIN a AS y ON x.k = y.k WHERE x.k = 3"};
    for (int plan = IMDB_JOIN_AUTO; plan <= IMDB_JOIN_INDEX && !g_test_failed; plan++)
        for (int i = 0; i < 2; i++) {
            s.join_plan = plan;
            imdb_result r;
            imdb_err_clear(E);
            OK(imdb_exec_one(&s, self[i], strlen(self[i]), NULL, 0, &r, E));
            if (r.nrows == 1) {
                size_t na = fetch(&s, "SELECT id, k, v, s, d FROM a", g_a);
                int64_t want = 0;
                for (size_t x = 0; x < na; x++)
                    for (size_t y = 0; y < na; y++) want += key_eq(&g_a[x], &g_a[y], KEY_K) && (!i || g_a[x].k == 3);
                CHECK(r.cells[0].v.i == want && strstr(r.path, "(cross-checked)"));
                if (plan == IMDB_JOIN_INDEX && i) CHECK(strncmp(r.path, "join(index", 10) == 0);
                imdb_result_free(&r);
            }
        }
    s.join_plan = IMDB_JOIN_AUTO;
    imdb_session_close(&s);
    imdb_close(db);
    CHECK(g_joined > 5000 && g_extended > 100);
    /* not vacuous, and join_plan = index never fell back here: every case ran once by each plan, plan C
     * in both orientations (300 = 268 + 32 with the measured costs; the orientation is the cost
     * rule's, so the floor of the second is a little under its count) */
    CHECK(g_plans[1] + g_plans[2] == g_plans[0] && g_plans[0] >= 300 && g_plans[2] >= 25);
    fprintf(stderr, "    plans: build 2 %llu, index 2 %llu, index 1 %llu\n", (unsigned long long)g_plans[0],
            (unsigned long long)g_plans[1], (unsigned long long)g_plans[2]);
    for (int full = 1; full >= 0 && !g_test_failed; full--) {
        db = jopen(dir, full);
        CHECK(db);
        if (!db) return;
        imdb_session_init(&s, db);
        s.cross_check = true;
        for (int plan = IMDB_JOIN_HASH; plan <= IMDB_JOIN_INDEX; plan++) { /* the structures built at open */
            s.join_plan = plan;
            join_case(&s, "a.k = b.k", KEY_K, true, "a.v < 0", "b.v != 1", false, "");
            join_case(&s, "b.d = a.d", KEY_D, false, "", "b.s IS NOT NULL", false, "");
            join_case(&s, "a.s = b.s", KEY_S, true, "", "", true, "");
            join_case(&s, "a.id = b.k", KEY_AID, false, "", "", true, "");
        }
        s.join_plan = IMDB_JOIN_AUTO;
        if (full) OK(ex(&s, "CHECKPOINT"));
        imdb_session_close(&s);
        imdb_close(db);
    }
}

/* what a join refuses, each with its reason */
static void t_join_refusals(void)
{
    const char *dir = test_tmpdir();
    OK(imdb_init(dir, false, NULL, E));
    imdb_db *db = jopen(dir, false);
    CHECK(db);
    if (!db) return;
    imdb_session s;
    imdb_session_init(&s, db);
    OK(ex(&s, "CREATE TABLE a (id INT64 PRIMARY KEY, k INT64, t TEXT)"));
    OK(ex(&s, "CREATE TABLE b (id INT64 PRIMARY KEY, k INT64, t TEXT, d DECIMAL(6,2), e DECIMAL(6,3))"));
    OK(ex(&s, "CREATE TABLE c (id INT64 PRIMARY KEY, k INT64)"));
    static const struct {
        const char *q, *msg;
    } bad[] = {
        {"SELECT * FROM a RIGHT JOIN b ON a.k = b.k", "only INNER and LEFT"},
        {"SELECT * FROM a FULL JOIN b ON a.k = b.k", "only INNER and LEFT"},
        {"SELECT * FROM a JOIN b ON a.k = b.k JOIN c ON b.k = c.k", "two tables"},
        {"SELECT * FROM a JOIN b ON a.k = b.k AND a.id = b.id", "one equality"},
        {"SELECT * FROM a JOIN b ON a.k = a.id", "a column of each table"},
        {"SELECT * FROM a JOIN b ON a.k = b.t", "values are not converted"},
        {"SELECT * FROM b AS x JOIN b AS y ON x.d = y.e", "values are not converted"},
        {"SELECT id FROM a JOIN b ON a.k = b.k", "in both tables"},
        {"SELECT a.id FROM a JOIN b ON a.k = b.k WHERE z.k = 1", "no table z"},
        {"SELECT a.id FROM a JOIN b ON a.k = b.nope", "no column nope"},
        {"SELECT a.id FROM a JOIN a ON a.k = a.k", "two names"},
        {"SELECT a.id FROM a JOIN b ON a.k = b.k FOR UPDATE", "FOR UPDATE"},
        {"SELECT a.id, COUNT(*) FROM a JOIN b ON a.k = b.k", "needs GROUP BY"},
        {"SELECT x.id FROM a WHERE x.k = 1", "no table x"},
    };
    for (size_t i = 0; i < sizeof bad / sizeof *bad; i++) {
        imdb_result r;
        imdb_err_clear(E);
        int rc = imdb_exec_one(&s, bad[i].q, strlen(bad[i].q), NULL, 0, &r, E);
        CHECK(rc != IMDB_OK && strstr(g_e.msg, bad[i].msg));
        if (rc == IMDB_OK) imdb_result_free(&r);
        if (!(rc != IMDB_OK && strstr(g_e.msg, bad[i].msg))) fprintf(stderr, "    %s: %s\n", bad[i].q, g_e.msg);
    }
    /* a one-table statement may qualify with its table's name or its alias */
    OK(ex(&s, "INSERT INTO a VALUES (1, 2, 'x')"));
    OK(ex(&s, "SELECT a.id, a.t FROM a WHERE a.k = 2"));
    OK(ex(&s, "SELECT x.id FROM a AS x WHERE x.k = 2 GROUP BY x.id"));
    OK(ex(&s, "UPDATE a SET t = 'y' WHERE a.id = 1"));
    imdb_session_close(&s);
    imdb_close(db);
}

/* the build side and the joined rows count against the result's cap: a join of every row with
 * every row under a small budget is refused, not grown into memory */
static void t_join_budget(void)
{
    const char *dir = test_tmpdir();
    OK(imdb_init(dir, false, NULL, E));
    imdb_db *db = jopen(dir, false);
    CHECK(db);
    if (!db) return;
    imdb_session s;
    imdb_session_init(&s, db);
    OK(ex(&s, "CREATE TABLE a (id INT64 PRIMARY KEY, k INT64)"));
    OK(ex(&s, "CREATE TABLE b (id INT64 PRIMARY KEY, k INT64)"));
    char q[64];
    OK(ex(&s, "BEGIN"));
    for (int i = 1; i <= 2000; i++) {
        snprintf(q, sizeof q, "INSERT INTO a VALUES (%d, 1)", i);
        OK(ex(&s, q));
        snprintf(q, sizeof q, "INSERT INTO b VALUES (%d, 1)", i);
        OK(ex(&s, q));
    }
    OK(ex(&s, "COMMIT"));
    imdb_mem_report m;
    imdb_mem(db, &m);
    db->mem_limit = m.total + (512u << 10); /* a result, and a join's working set, may hold a quarter of it */
    imdb_result r;
    imdb_err_clear(E);
    int rc = imdb_exec_one(&s, "SELECT a.id, b.id FROM a JOIN b ON a.k = b.k", 44, NULL, 0, &r, E);
    CHECK(rc == IMDB_ERR_LIMIT && strstr(g_e.msg, "a join over its cap")); /* 4,000,000 joined rows: refused while
                                                                           counted, not once kept */
    if (!rc) imdb_result_free(&r);
    imdb_err_clear(E);
    OK(imdb_exec_one(&s, "SELECT COUNT(*) FROM a JOIN b ON a.k = b.k", 42, NULL, 0, &r, E)); /* no pairs kept */
    if (r.nrows == 1) CHECK(r.cells[0].v.i == 4000000);
    imdb_result_free(&r);
    /* plan C keeps no hash, only the pairs: the same cap refuses them */
    OK(ex(&s, "CREATE INDEX b_k ON b (k)"));
    s.join_plan = IMDB_JOIN_INDEX;
    imdb_err_clear(E);
    rc = imdb_exec_one(&s, "SELECT a.id, b.id FROM a JOIN b ON a.k = b.k", 44, NULL, 0, &r, E);
    CHECK(rc == IMDB_ERR_LIMIT && strstr(g_e.msg, "a join over its cap"));
    if (!rc) imdb_result_free(&r);
    imdb_err_clear(E);
    OK(imdb_exec_one(&s, "SELECT COUNT(*) FROM a JOIN b ON a.k = b.k", 42, NULL, 0, &r, E));
    if (r.nrows == 1) CHECK(r.cells[0].v.i == 4000000 && strncmp(r.path, "join(index", 10) == 0);
    imdb_result_free(&r);
    db->mem_limit = 0;
    imdb_session_close(&s);
    imdb_close(db);
}

/* q's rows as (a.id, b.id or -1 for NULL), in order, from the cross-checked path */
static void want_pairs(imdb_session *s, const char *q, const int64_t (*want)[2], size_t n)
{
    imdb_result r;
    imdb_err_clear(E);
    OK(imdb_exec_one(s, q, strlen(q), NULL, 0, &r, E));
    bool ok = r.nrows == n && strstr(r.path, "(cross-checked)") != NULL;
    for (uint64_t i = 0; ok && i < r.nrows; i++)
        ok = r.cells[i * 2].v.i == want[i][0] && (r.cells[i * 2 + 1].null ? -1 : r.cells[i * 2 + 1].v.i) == want[i][1];
    if (!ok) fprintf(stderr, "    %s: %llu rows [%s]\n", q, (unsigned long long)r.nrows, r.path);
    imdb_result_free(&r);
    CHECK(ok);
}

/* FLOAT64, BOOL and TIMESTAMP keys: each is held as an int64 whose equality is the value's own
 * (FLOAT64 is finite and stores -0.0 as +0.0), so hashing .i agrees with the engine's = */
static void t_join_types(void)
{
    const char *dir = test_tmpdir();
    OK(imdb_init(dir, false, NULL, E));
    imdb_db *db = jopen(dir, false);
    CHECK(db);
    if (!db) return;
    imdb_session s;
    imdb_session_init(&s, db);
    s.cross_check = true;
    OK(ex(&s, "CREATE TABLE a (id INT64 PRIMARY KEY, fl FLOAT64 NULL, bo BOOL NULL, ts TIMESTAMP NULL)"));
    OK(ex(&s, "CREATE TABLE b (id INT64 PRIMARY KEY, fl FLOAT64 NULL, bo BOOL NULL, ts TIMESTAMP NULL)"));
    OK(ex(&s, "INSERT INTO a VALUES (1, 0.0, TRUE, TIMESTAMP '2026-10-25 12:00:00'), (2, -1.5, FALSE, NULL), "
              "(3, NULL, NULL, TIMESTAMP '1970-01-01 00:00:00')"));
    OK(ex(&s, "INSERT INTO b VALUES (1, -0.0, TRUE, TIMESTAMP '2026-10-25 12:00:00'), "
              "(2, -1.5, TRUE, TIMESTAMP '1970-01-01 00:00:00'), (3, 12345.25, NULL, NULL)"));
    static const int64_t fl[][2] = {{1, 1}, {2, 2}}, fl_left[][2] = {{1, 1}, {2, 2}, {3, -1}};
    static const int64_t bo[][2] = {{1, 1}, {1, 2}}, bo_left[][2] = {{1, 1}, {1, 2}, {2, -1}, {3, -1}};
    static const int64_t ts[][2] = {{1, 1}, {3, 2}};
    OK(ex(&s, "CREATE INDEX b_fl ON b (fl)")); /* plan C probes each type through an index */
    OK(ex(&s, "CREATE INDEX b_bo ON b (bo)"));
    OK(ex(&s, "CREATE INDEX b_ts ON b (ts)"));
    for (int pass = 0; pass < 4 && !g_test_failed; pass++) { /* rows in memory, then in segments; each plan */
        s.join_plan = pass & 1 ? IMDB_JOIN_INDEX : IMDB_JOIN_HASH;
        want_pairs(&s, "SELECT a.id, b.id FROM a JOIN b ON a.fl = b.fl", fl, 2);
        want_pairs(&s, "SELECT a.id, b.id FROM a LEFT JOIN b ON a.fl = b.fl", fl_left, 3);
        want_pairs(&s, "SELECT a.id, b.id FROM a JOIN b ON a.bo = b.bo", bo, 2);
        want_pairs(&s, "SELECT a.id, b.id FROM a LEFT JOIN b ON b.bo = a.bo", bo_left, 4);
        want_pairs(&s, "SELECT a.id, b.id FROM a JOIN b ON a.ts = b.ts", ts, 2);
        if (pass & 1) OK(ex(&s, "CHECKPOINT"));
    }
    /* TEXT primary keys: the rows come in side 0's key order, then side 1's (bytes, shorter first) */
    OK(ex(&s, "CREATE TABLE ta (name TEXT PRIMARY KEY, k INT64)"));
    OK(ex(&s, "CREATE TABLE tb (code TEXT PRIMARY KEY, k INT64 NULL)"));
    OK(ex(&s, "INSERT INTO ta VALUES ('b', 1), ('a', 2), ('c', 9), ('bb', 1)"));
    OK(ex(&s, "INSERT INTO tb VALUES ('y', 1), ('x', 1), ('z', 2), ('xx', 1), ('w', NULL)"));
    static const char *const tw[][2] = {{"a", "z"},  {"b", "x"},  {"b", "xx"}, {"b", "y"},
                                        {"bb", "x"}, {"bb", "xx"}, {"bb", "y"}, {"c", NULL}};
    OK(ex(&s, "CREATE INDEX tb_k ON tb (k)"));
    for (int pass = 0; pass < 4 && !g_test_failed; pass++) {
        s.join_plan = pass & 1 ? IMDB_JOIN_INDEX : IMDB_JOIN_HASH;
        imdb_result r;
        imdb_err_clear(E);
        OK(imdb_exec_one(&s, "SELECT ta.name, tb.code FROM ta LEFT JOIN tb ON ta.k = tb.k", 59, NULL, 0, &r, E));
        bool ok = r.nrows == 8 && strstr(r.path, "(cross-checked)") != NULL;
        for (uint64_t i = 0; ok && i < r.nrows; i++) {
            const imdb_cell *c = &r.cells[i * 2];
            ok = c[0].v.len == strlen(tw[i][0]) && memcmp(c[0].v.s, tw[i][0], c[0].v.len) == 0 &&
                 (tw[i][1] ? !c[1].null && c[1].v.len == strlen(tw[i][1]) && memcmp(c[1].v.s, tw[i][1], c[1].v.len) == 0
                           : c[1].null);
        }
        imdb_result_free(&r);
        CHECK(ok);
        if (pass & 1) OK(ex(&s, "CHECKPOINT")); /* then from segments */
    }
    imdb_session_close(&s);
    imdb_close(db);
}

/* a join reads both tables at one snapshot: below either table's purge horizon it is an error,
 * never a partial answer (the history check runs for each table a read touches) */
static void t_join_history(void)
{
    const char *dir = test_tmpdir();
    OK(imdb_init(dir, false, NULL, E));
    imdb_db *db = jopen(dir, false);
    CHECK(db);
    if (!db) return;
    imdb_session s;
    imdb_session_init(&s, db);
    OK(ex(&s, "CREATE TABLE a (id INT64 PRIMARY KEY, k INT64)"));
    OK(ex(&s, "CREATE TABLE b (id INT64 PRIMARY KEY, k INT64)"));
    OK(ex(&s, "INSERT INTO a VALUES (1, 1), (2, 2)"));
    OK(ex(&s, "INSERT INTO b VALUES (1, 1), (2, 2)"));
    uint64_t before = db->seq;
    OK(ex(&s, "CHECKPOINT"));
    OK(ex(&s, "UPDATE b SET k = 2 WHERE id = 1"));
    OK(ex(&s, "CHECKPOINT"));
    char q[160];
    snprintf(q, sizeof q, "COMPACT b PURGE BEFORE %llu", (unsigned long long)db->seq);
    OK(ex(&s, q));
    imdb_table *tb = imdb_table_by_name(db, "b");
    CHECK(tb && tb->horizon > before);
    snprintf(q, sizeof q, "SELECT COUNT(*) FROM a AS OF %llu", (unsigned long long)before);
    OK(ex(&s, q)); /* side 1's own history is still there */
    static const char *const shapes[] = {
        "SELECT a.id, b.id FROM a JOIN b ON a.k = b.k", /* b is side 2 */
        "SELECT COUNT(*) FROM a LEFT JOIN b ON a.k = b.k",
        "SELECT b.id, a.id FROM b JOIN a ON b.k = a.k", /* b is side 1 */
    };
    OK(ex(&s, "CREATE INDEX b_k ON b (k)")); /* plan C would probe b below its horizon: refused first */
    for (size_t i = 0; i < 2 * (sizeof shapes / sizeof *shapes); i++) {
        s.join_plan = i % 2 ? IMDB_JOIN_INDEX : IMDB_JOIN_HASH;
        snprintf(q, sizeof q, "%s AS OF %llu", shapes[i / 2], (unsigned long long)before);
        imdb_result r;
        imdb_err_clear(E);
        int rc = imdb_exec_one(&s, q, strlen(q), NULL, 0, &r, E);
        if (!rc) imdb_result_free(&r);
        if (rc != IMDB_ERR_HISTORY) fprintf(stderr, "    %s -> %d\n", q, rc);
        CHECK(rc == IMDB_ERR_HISTORY);
    }
    OK(ex(&s, "SELECT a.id, b.id FROM a JOIN b ON a.k = b.k")); /* the current snapshot is above it */
    imdb_session_close(&s);
    imdb_close(db);
}

/* one statement's first cell (a COUNT or a SUM) and its path, cross-checked */
static int64_t planned(imdb_session *s, const char *q, const char *path)
{
    imdb_result r;
    imdb_err_clear(E);
    if (imdb_exec_one(s, q, strlen(q), NULL, 0, &r, E)) { /* a helper with a value: test_fail, not OK */
        test_fail(__FILE__, __LINE__, g_e.msg);
        return -1;
    }
    int64_t n = r.nrows != 1 ? -1 : r.cells[0].wide ? (int64_t)r.cells[0].i128 : r.cells[0].v.i;
    bool ok = strncmp(r.path, path, strlen(path)) == 0 && strstr(r.path, "(cross-checked)") != NULL;
    if (!ok) fprintf(stderr, "    %s: [%s], want %s\n", q, r.path, path);
    if (!ok) test_fail(__FILE__, __LINE__, "the plan");
    imdb_result_free(&r);
    return n;
}

/* The cost rule (join_choose) where the choice is real: 3,500 customers, 9,000 orders, in segments.
 * One row or a few on one side and a primary key or an index on the other side's join column:
 * plan C, in either orientation for INNER; neither: the hash join. The answers are computed here
 * from the rows' formulas, and each is cross-checked against the hash join reading both sides by
 * scan. join_plan = index without an index on either join column falls back to the hash join; a
 * forced access_path keeps the hash join too. */
static void t_join_planner(void)
{
    const char *dir = test_tmpdir();
    OK(imdb_init(dir, false, NULL, E));
    imdb_db *db = jopen(dir, false);
    CHECK(db);
    if (!db) return;
    imdb_session s;
    imdb_session_init(&s, db);
    s.cross_check = true;
    OK(ex(&s, "CREATE TABLE c (id INT64 PRIMARY KEY, name TEXT, region INT64)"));
    OK(ex(&s, "CREATE TABLE o (id INT64 PRIMARY KEY, cust INT64, amount INT64, note TEXT)"));
    OK(ex(&s, "CREATE INDEX c_region ON c (region)"));
    OK(ex(&s, "CREATE INDEX o_cust ON o (cust, note)")); /* note is NULL in a third of the orders */
    enum { NC = 3500, NO = 9000 };
    static char q[8192];
    for (int b = 0; b < NC / 100 && !g_test_failed; b++) {
        size_t n = (size_t)snprintf(q, sizeof q, "INSERT INTO c VALUES ");
        for (int i = b * 100 + 1; i <= b * 100 + 100; i++)
            n += (size_t)snprintf(q + n, sizeof q - n, "%s(%d, 'c%d', %d)", i > b * 100 + 1 ? ", " : "", i, i, i % 50);
        OK(ex(&s, q));
    }
    for (int b = 0; b < NO / 100 && !g_test_failed; b++) {
        size_t n = (size_t)snprintf(q, sizeof q, "INSERT INTO o VALUES ");
        for (int i = b * 100 + 1; i <= b * 100 + 100; i++)
            n += (size_t)snprintf(q + n, sizeof q - n, "%s(%d, %d, %d, %s)", i > b * 100 + 1 ? ", " : "", i, i * 7 % 3000 + 1,
                                  i % 100, i % 3 ? "'n'" : "NULL");
        OK(ex(&s, q));
    }
    OK(ex(&s, "CHECKPOINT"));
    /* the answers from the formulas: every customer up to 3,000 has three orders, the rest none */
    int64_t of7 = 0, sum5 = 0, none5 = 0, by_region = 0;
    for (int i = 1; i <= NO; i++) {
        int cust = i * 7 % 3000 + 1;
        of7 += cust == 7;
        sum5 += cust % 50 == 5 ? i % 100 : 0;
    }
    for (int i = 1; i <= NC; i++) none5 += i % 50 == 5 && i > 3000;
    for (int i = 1; i <= NO; i++) /* amount = i % 100 meets region = id % 50 (70 customers each) below 50 */
        by_region += i % 100 < 50 ? NC / 50 : 0;
    CHECK(of7 == 3 && none5 == 10);
    CHECK(planned(&s, "SELECT COUNT(*) FROM o JOIN c ON o.cust = c.id WHERE o.id = 5", "join(index 2)") == 1);
    CHECK(planned(&s, "SELECT COUNT(*) FROM o JOIN c ON o.cust = c.id WHERE o.cust = 7", "join(index 2)") == of7);
    CHECK(planned(&s, "SELECT COUNT(*) FROM c JOIN o ON c.id = o.cust WHERE c.id = 7", "join(index 2)") == of7);
    CHECK(planned(&s, "SELECT COUNT(*) FROM c LEFT JOIN o ON c.id = o.cust WHERE c.id = 7", "join(index 2)") == of7);
    CHECK(planned(&s, "SELECT COUNT(*) FROM o JOIN c ON o.cust = c.id WHERE c.id = 7", "join(index 1)") == of7);
    CHECK(planned(&s, "SELECT SUM(o.amount) FROM c JOIN o ON c.id = o.cust WHERE c.region = 5", "join(index 2)") == sum5);
    CHECK(planned(&s, "SELECT COUNT(*) FROM c LEFT JOIN o ON c.id = o.cust WHERE c.region = 5 AND o.id IS NULL",
                  "join(index 2)") == none5); /* the anti-join */
    /* 9,000 primary-key probes against hashing 3,500 rows: close, so only the answer; and a shape the
     * hash join wins by a wide margin: an index probe (c_region, ordered, not unique) per order */
    CHECK(planned(&s, "SELECT COUNT(*) FROM o JOIN c ON o.cust = c.id", "join(") == NO);
    CHECK(planned(&s, "SELECT COUNT(*) FROM o JOIN c ON o.amount = c.region", "join(build 2)") == by_region);
    /* 3,500 probes against hashing 9,000 rows: near the line, so only the answer is asserted */
    CHECK(planned(&s, "SELECT COUNT(*) FROM c LEFT JOIN o ON c.id = o.cust", "join(") == NO + (NC - 3000));
    s.join_plan = IMDB_JOIN_INDEX; /* no index on either side's join column: the hash join */
    CHECK(planned(&s, "SELECT COUNT(*) FROM o JOIN c ON o.note = c.name", "join(build 2)") == 0);
    CHECK(planned(&s, "SELECT COUNT(*) FROM o JOIN c ON o.cust = c.id", "join(index") == NO); /* forced */
    s.join_plan = IMDB_JOIN_AUTO;
    s.access_path = IMDB_PATH_SCAN; /* a forced path is every table read's: no probes */
    CHECK(planned(&s, "SELECT COUNT(*) FROM o JOIN c ON o.cust = c.id WHERE o.id = 5", "join(build 2)") == 1);
    s.access_path = IMDB_PATH_AUTO;
    imdb_session_close(&s);
    imdb_close(db);
}

const test_case join_tests[] = {
    {"join_oracle", t_join_oracle},
    {"join_refusals", t_join_refusals},
    {"join_budget", t_join_budget},
    {"join_types", t_join_types},
    {"join_history", t_join_history},
    {"join_planner", t_join_planner},
};
const size_t join_ntests = sizeof join_tests / sizeof *join_tests;
