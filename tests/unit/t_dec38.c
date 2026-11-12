/* F3e: NUMERIC to 38 digits (docs/f3e-design.md). The codec at its edges (each form, its checks, the row codec, the key
 * encoding's order against numeric order over both forms, the hash of a number in either form); a table of wide DECIMALs
 * against a model of its rows (values sharing their low 64 bits, both signs, NULLs, the bound) on every path: in memory,
 * cross-checked, after a CHECKPOINT, after writes and a second CHECKPOINT, at a segment budget of one byte, after a reopen
 * and a full replay at the same digest, VERIFY and the auditor; the arithmetic and SUM at the bound; the rules (no index
 * on a wide column, no FOREIGN KEY across forms, SET TYPE within a form, 39 digits refused); CHECKs, generated columns
 * and a DEFAULT over wide values (the auditor evaluating each write by its own code); the copies (COPY both ways,
 * a replica at the primary's digest, the dump restored at the same rows). */
#include <stdlib.h>

#include "../../src/db_internal.h"
#include "../../src/lake.h"
#include "../../src/log.h"
#include "../../src/sql.h"
#include "thelp.h"

static imdb_session g_s;
static char g_out[1 << 17];

typedef struct mem_in {
    const char *in;
    size_t inlen, inpos;
} mem_in;
static mem_in g_in;

static long mem_read(void *arg, char *buf, size_t cap)
{
    mem_in *m = arg;
    size_t k = m->inlen - m->inpos;
    if (k > cap) k = cap;
    if (k) memcpy(buf, m->in + m->inpos, k);
    m->inpos += k;
    return (long)k;
}

static char g_copy[1 << 16];
static size_t g_copyn;
static int mem_write(void *arg, const char *b, size_t n)
{
    (void)arg;
    if (g_copyn + n >= sizeof g_copy) return -1;
    memcpy(g_copy + g_copyn, b, n);
    g_copyn += n;
    g_copy[g_copyn] = 0;
    return 0;
}

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
            char m_[3000];                                                                                         \
            snprintf(m_, sizeof m_, "%.900s\n      want: %.900s\n      got:  %.900s", (sql), (want), got_);        \
            test_fail(__FILE__, __LINE__, m_);                                                                     \
        }                                                                                                          \
    } while (0)

static imdb_db *open_with(const char *dir, bool full_replay, uint64_t budget)
{
    imdb_open_opts o = {.sync = 0, .full_replay = full_replay, .seg_cache_bytes = budget};
    imdb_db *db = NULL;
    imdb_err e = {0};
    if (imdb_open(dir, &o, &db, &e)) {
        fprintf(stderr, "    open%s: %s\n", full_replay ? " (a full replay)" : "", e.msg); /* the CHECK after says where */
        return NULL;
    }
    imdb_session_init(&g_s, db);
    imdb_session_copy_io(&g_s, mem_read, mem_write, &g_in);
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

/* a number's text at a scale, into one of a few rotating buffers (several in one expression) */
static const char *num(__int128 x, int scale)
{
    static char b[8][64];
    static int k;
    char *o = b[k++ & 7];
    imdb_buf t;
    imdb_buf_init(&t);
    imdb_format_i128(x, scale, &t);
    snprintf(o, 64, "%.*s", (int)t.len, (const char *)t.p);
    imdb_buf_free(&t);
    return o;
}

static __int128 p10(int n)
{
    __int128 v = 1;
    while (n-- > 0) v *= 10;
    return v;
}

#define P64 ((__int128)1 << 64)

/* ---- the codec: each form, its checks, the row codec, the key's order, the hash and the maps ---- */
static void t_dec38_codec(void)
{
    imdb_err e = {0};
    imdb_column w = {.type = IMDB_T_DECIMAL, .precision = 38, .scale = 4}, n = {.type = IMDB_T_DECIMAL, .precision = 18, .scale = 4};
    snprintf(w.name, sizeof w.name, "w");
    snprintf(n.name, sizeof n.name, "n");
    imdb_value v = {.type = IMDB_T_DECIMAL, .scale = 4};
    __int128 lim = p10(38) - 1;
    static const __int128 ok[] = {0, 1, -1, P64, -P64, P64 + 1, ((__int128)1 << 100), -((__int128)1 << 100)};
    for (size_t i = 0; i < sizeof ok / sizeof *ok; i++) {
        imdb_dec_set(&v, ok[i], true);
        CHECK(imdb_value_check(&w, &v, &e) == IMDB_OK && imdb_dec_value(&v) == ok[i]);
    }
    imdb_dec_set(&v, lim, true);
    CHECK(imdb_value_check(&w, &v, &e) == IMDB_OK);
    imdb_dec_set(&v, -lim, true);
    CHECK(imdb_value_check(&w, &v, &e) == IMDB_OK);
    imdb_dec_set(&v, lim + 1, true);
    CHECK(imdb_value_check(&w, &v, &e) == IMDB_ERR_LIMIT);
    imdb_dec_set(&v, 5, false); /* a narrow value in a wide column, and the reverse: the form is the column's */
    CHECK(imdb_value_check(&w, &v, &e) == IMDB_ERR_INVALID);
    imdb_dec_set(&v, 5, true);
    CHECK(imdb_value_check(&n, &v, &e) == IMDB_ERR_INVALID);
    imdb_dec_set(&v, 5, false);
    v.hi = 1; /* a narrow value with a high half: a stale pointer's tripwire */
    CHECK(imdb_value_check(&n, &v, &e) == IMDB_ERR_INVALID);
    CHECK(sizeof(imdb_value) == 24);
    /* the parsers */
    __int128 x = 0;
    CHECK(imdb_parse_decimal128("-99999999999999999999999999999999.9999", 38, 36, 4, &x, &e) == IMDB_OK &&
          x == -(p10(36) - 1));
    CHECK(imdb_parse_decimal128("100000000000000000000000000000000.0", 35, 36, 4, &x, &e) == IMDB_ERR_LIMIT);
    CHECK(imdb_parse_decimal128("1.00001", 7, 38, 4, &x, &e) == IMDB_ERR_INVALID);
    CHECK(imdb_parse_decimal128("1.25000", 7, 38, 4, &x, &e) == IMDB_OK && x == 12500);
    CHECK(imdb_parse_decimal128("1", 1, 39, 0, &x, &e) == IMDB_ERR_INVALID);
    int64_t i64 = 0;
    CHECK(imdb_parse_decimal("1", 1, 19, 0, &i64, &e) == IMDB_ERR_INVALID); /* the narrow parser: 18 at most */
    imdb_value pv;
    CHECK(imdb_parse_decimal_col("18446744073709551616", 20, &w, &pv, &e) == IMDB_OK && pv.wide &&
          imdb_dec_value(&pv) == P64 * 10000);
    /* the row codec: 16 bytes a wide value, 8 a narrow one; a cut one refused */
    imdb_schema s;
    memset(&s, 0, sizeof s);
    snprintf(s.name, sizeof s.name, "d");
    s.ncols = 3;
    s.subject = -1;
    s.cols[0] = w;
    s.cols[0].flags = IMDB_COL_PK;
    s.cols[1] = n;
    s.cols[1].flags = IMDB_COL_NULLABLE;
    s.cols[2] = w;
    snprintf(s.cols[2].name, sizeof s.cols[2].name, "z");
    s.cols[2].flags = IMDB_COL_NULLABLE;
    s.npk = 1;
    OK(imdb_schema_check(&s, &e));
    imdb_value r3[3] = {{.type = IMDB_T_DECIMAL, .scale = 4}, {.type = IMDB_T_DECIMAL, .scale = 4},
                        {.type = IMDB_T_DECIMAL, .scale = 4, .null = true}};
    imdb_dec_set(&r3[0], -lim, true);
    imdb_dec_set(&r3[1], -123456789, false);
    imdb_buf row;
    imdb_buf_init(&row);
    OK(imdb_row_encode(&s, r3, &row, &e));
    CHECK(row.len == 1 + 16 + 8);
    imdb_value d3[3];
    OK(imdb_row_decode(&s, row.p, row.len, d3, &e));
    CHECK(d3[0].wide && imdb_dec_value(&d3[0]) == -lim && !d3[1].wide && d3[1].i == -123456789 && d3[2].null);
    CHECK(imdb_row_decode(&s, row.p, row.len - 1, d3, &e) == IMDB_ERR_CORRUPT);
    imdb_value g1;
    imdb_row_get(&s, row.p, row.len, 0, &g1);
    CHECK(g1.wide && imdb_dec_value(&g1) == -lim);
    imdb_buf_free(&row);
    s.cols[2].precision = 39;
    CHECK(imdb_schema_check(&s, &e) == IMDB_ERR_INVALID);
    s.cols[2].precision = 38;
    /* the key encoding: memcmp order is numeric order over both forms; a number in either form one encoding */
    uint64_t rs = 0x9e3779b97f4a7c15ull;
    for (int k = 0; k < 4000; k++) {
        __int128 a[2];
        for (int j = 0; j < 2; j++) {
            rs ^= rs << 13, rs ^= rs >> 7, rs ^= rs << 17;
            uint64_t lo = rs;
            rs ^= rs << 13, rs ^= rs >> 7, rs ^= rs << 17;
            __int128 t = (__int128)(((unsigned __int128)(rs >> (k % 3 == 0 ? 0 : 1 + k % 60)) << 64) | lo) % lim;
            a[j] = (k & 1) ? -t : t;
            if (k % 5 == 0) a[j] = (int64_t)lo; /* an int64: either form */
        }
        imdb_value kv[2][1];
        uint8_t eb[2][16];
        for (int j = 0; j < 2; j++) {
            memset(kv[j], 0, sizeof kv[j]);
            kv[j][0].type = IMDB_T_DECIMAL;
            kv[j][0].scale = 4;
            bool fits = a[j] >= INT64_MIN && a[j] <= INT64_MAX;
            imdb_dec_set(&kv[j][0], a[j], !(fits && (k & 2))); /* a narrow form where it fits, at times */
            CHECK(imdb_key_len(&s, kv[j]) == 16);
            imdb_key_write(&s, kv[j], eb[j]);
        }
        int c = memcmp(eb[0], eb[1], 16);
        if ((c < 0) != (a[0] < a[1]) || (c == 0) != (a[0] == a[1])) {
            test_fail(__FILE__, __LINE__, "the key encoding's order is not numeric order");
            break;
        }
        imdb_value one[1] = {{.type = IMDB_T_DECIMAL, .scale = 4}}, two[1] = {{.type = IMDB_T_DECIMAL, .scale = 4}};
        bool fits0 = a[0] >= INT64_MIN && a[0] <= INT64_MAX;
        imdb_dec_set(&one[0], a[0], true);
        imdb_dec_set(&two[0], a[0], !fits0);
        uint8_t o1[16], o2[16];
        imdb_key_write(&s, one, o1);
        imdb_key_write(&s, two, o2);
        CHECK(!memcmp(o1, o2, 16) && imdb_value_hash(&one[0], 7) == imdb_value_hash(&two[0], 7) &&
              imdb_value_cmp(&one[0], &two[0]) == 0);
    }
    /* a map keyed by DECIMALs: two numbers sharing their low 64 bits are two keys; either form finds a key */
    imdb_hmap m;
    OK(imdb_hmap_init(&m, IMDB_T_DECIMAL, &e));
    imdb_value k1 = {.type = IMDB_T_DECIMAL}, k2 = {.type = IMDB_T_DECIMAL}, k3 = {.type = IMDB_T_DECIMAL};
    imdb_dec_set(&k1, P64 + 7, true);
    imdb_dec_set(&k2, 7, true);
    imdb_dec_set(&k3, 7, false);
    OK(imdb_hmap_put(&m, &k1, 1, &e));
    OK(imdb_hmap_put(&m, &k2, 2, &e));
    CHECK(m.count == 2 && imdb_hmap_get(&m, &k1) && *imdb_hmap_get(&m, &k1) == 1 && imdb_hmap_get(&m, &k3) &&
          *imdb_hmap_get(&m, &k3) == 2);
    imdb_hmap_free(&m);
}

/* ---- a table against its model on every path ---- */
#define NROWS 400
typedef struct mrow {
    __int128 id; /* at scale 6 */
    bool wnull;
    __int128 w;
    int64_t g;
    bool gone;
} mrow;
static mrow g_m[NROWS];

static __int128 bval(int k)
{
    static const int SEL[13] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12};
    switch (SEL[k % 13]) {
    case 0: return p10(30) - 1;
    case 1: return -(p10(30) - 1);
    case 2: return P64;
    case 3: return P64 + 1;
    case 4: return 3 * P64;
    case 5: return -P64;
    case 6: return 0;
    case 7: return 1;
    case 8: return -1;
    case 9: return (__int128)1 << 63;
    case 10: return -((__int128)1 << 63) - 1;
    case 11: return p10(29) + 12345;
    default: return 5 * p10(29) + P64;
    }
}

static void model_init(void)
{
    for (int i = 0; i < NROWS; i++) {
        mrow *r = &g_m[i];
        memset(r, 0, sizeof *r);
        r->id = ((__int128)(i - NROWS / 2) * 3 * p10(29) + i) * p10(6) + (i % 3 == 0 ? 500000 : 0);
        r->wnull = i % 7 == 3;
        r->w = r->wnull ? 0 : bval(i * 5);
        r->g = i % 5;
    }
}

static int cmp_i128(const void *a, const void *b)
{
    __int128 x = *(const __int128 *)a, y = *(const __int128 *)b;
    return x < y ? -1 : x > y;
}

/* every query, its answer from the model */
static void model_queries(const char *phase)
{
    char sql[600], want[1 << 14];
    size_t o;
    (void)phase;
    for (int k = 0; k < 13; k++) { /* each value: by equality, then the ranges around it */
        __int128 b = bval(k);
        int eq = 0, gt = 0, le = 0;
        for (int i = 0; i < NROWS; i++)
            if (!g_m[i].gone && !g_m[i].wnull) eq += g_m[i].w == b, gt += g_m[i].w > b, le += g_m[i].w <= b;
        snprintf(sql, sizeof sql, "SELECT COUNT(*) FROM d WHERE w = %s", num(b, 0));
        snprintf(want, sizeof want, "count\n%d\n", eq);
        EXPECT(sql, want);
        snprintf(sql, sizeof sql, "SELECT COUNT(*) FROM d WHERE w > %s", num(b, 0));
        snprintf(want, sizeof want, "count\n%d\n", gt);
        EXPECT(sql, want);
        snprintf(sql, sizeof sql, "SELECT COUNT(*) FROM d WHERE %s >= w", num(b, 0));
        snprintf(want, sizeof want, "count\n%d\n", le);
        EXPECT(sql, want);
    }
    { /* BETWEEN and IN */
        int bt = 0, in = 0;
        for (int i = 0; i < NROWS; i++) {
            if (g_m[i].gone || g_m[i].wnull) continue;
            bt += g_m[i].w >= P64 && g_m[i].w <= 3 * P64;
            in += g_m[i].w == P64 || g_m[i].w == P64 + 1 || g_m[i].w == -1;
        }
        snprintf(sql, sizeof sql, "SELECT COUNT(*) FROM d WHERE w BETWEEN %s AND %s", num(P64, 0), num(3 * P64, 0));
        snprintf(want, sizeof want, "count\n%d\n", bt);
        EXPECT(sql, want);
        snprintf(sql, sizeof sql, "SELECT COUNT(*) FROM d WHERE w IN (%s, %s, -1)", num(P64, 0), num(P64 + 1, 0));
        snprintf(want, sizeof want, "count\n%d\n", in);
        EXPECT(sql, want);
    }
    { /* GROUP BY the wide column, ORDER BY it; the extremes, the counts */
        __int128 vs[NROWS];
        int nv = 0, nn = 0;
        for (int i = 0; i < NROWS; i++)
            if (!g_m[i].gone && !g_m[i].wnull) vs[nv++] = g_m[i].w;
        for (int i = 0; i < NROWS; i++) nn += !g_m[i].gone;
        qsort(vs, (size_t)nv, sizeof *vs, cmp_i128);
        o = (size_t)snprintf(want, sizeof want, "w,count\n");
        int nd = 0;
        for (int i = 0; i < nv;) {
            int j = i;
            while (j < nv && vs[j] == vs[i]) j++;
            o += (size_t)snprintf(want + o, sizeof want - o, "%s,%d\n", num(vs[i], 0), j - i);
            nd++;
            i = j;
        }
        EXPECT("SELECT w, COUNT(*) FROM d WHERE w IS NOT NULL GROUP BY w ORDER BY w", want);
        snprintf(want, sizeof want, "mn,mx,n,d,rows\n%s,%s,%d,%d,%d\n", num(vs[0], 0), num(vs[nv - 1], 0), nv, nd, nn);
        EXPECT("SELECT MIN(w) AS mn, MAX(w) AS mx, COUNT(w) AS n, COUNT(DISTINCT w) AS d, COUNT(*) AS rows FROM d", want);
    }
    { /* SUM: whole (the plain path), by group, and a tree's */
        __int128 tot = 0, by[5] = {0};
        for (int i = 0; i < NROWS; i++)
            if (!g_m[i].gone && !g_m[i].wnull) tot += g_m[i].w, by[g_m[i].g] += g_m[i].w;
        snprintf(want, sizeof want, "tot\n%s\n", num(tot, 0));
        EXPECT("SELECT SUM(w) AS tot FROM d", want);
        snprintf(want, sizeof want, "s\n%s\n", num(2 * tot, 0));
        EXPECT("SELECT SUM(w * 2) AS s FROM d", want);
        o = (size_t)snprintf(want, sizeof want, "g,s\n");
        for (int g = 0; g < 5; g++) o += (size_t)snprintf(want + o, sizeof want - o, "%d,%s\n", g, num(by[g], 0));
        EXPECT("SELECT g, SUM(w) AS s FROM d GROUP BY g ORDER BY g", want);
    }
    for (int i = 0; i < NROWS; i += 57) { /* the key path, by the whole key */
        snprintf(sql, sizeof sql, "SELECT w FROM d WHERE id = %s", num(g_m[i].id, 6));
        if (g_m[i].gone) snprintf(want, sizeof want, "w\n");
        else snprintf(want, sizeof want, "w\n%s\n", g_m[i].wnull ? "" : num(g_m[i].w, 0));
        EXPECT(sql, want);
    }
    { /* ORDER BY the wide column, a key breaking ties, LIMIT */
        int idx[NROWS], n = 0;
        for (int i = 0; i < NROWS; i++)
            if (!g_m[i].gone && !g_m[i].wnull) idx[n++] = i;
        for (int i = 1; i < n; i++) /* by w descending, then id ascending */
            for (int j = i; j > 0; j--) {
                const mrow *a = &g_m[idx[j - 1]], *b = &g_m[idx[j]];
                if (a->w > b->w || (a->w == b->w && a->id < b->id)) break;
                int t = idx[j - 1];
                idx[j - 1] = idx[j];
                idx[j] = t;
            }
        o = (size_t)snprintf(want, sizeof want, "id,w\n");
        for (int i = 0; i < 5 && i < n; i++)
            o += (size_t)snprintf(want + o, sizeof want - o, "%s,%s\n", num(g_m[idx[i]].id, 6), num(g_m[idx[i]].w, 0));
        EXPECT("SELECT id, w FROM d WHERE w IS NOT NULL ORDER BY w DESC, id LIMIT 5", want);
    }
    { /* joins: wide with wide (e's key), narrow with wide (h's), a derived table */
        int per[13] = {0}, total = 0, small = 0, mid = 0;
        for (int i = 0; i < NROWS; i++) {
            if (g_m[i].gone || g_m[i].wnull) continue;
            for (int k = 0; k < 13; k++)
                if (g_m[i].w == bval(k)) per[k]++, total++;
            small += g_m[i].w == 0 || g_m[i].w == 1 || g_m[i].w == -1;
            mid += g_m[i].w > 0 && g_m[i].w < 2 * P64;
        }
        snprintf(want, sizeof want, "count\n%d\n", total);
        EXPECT("SELECT COUNT(*) FROM d JOIN e ON d.w = e.w", want);
        o = (size_t)snprintf(want, sizeof want, "tag,count\n");
        for (int k = 0; k < 13; k++)
            if (per[k]) o += (size_t)snprintf(want + o, sizeof want - o, "%d,%d\n", k, per[k]);
        EXPECT("SELECT e.tag, COUNT(*) FROM d JOIN e ON d.w = e.w GROUP BY e.tag ORDER BY e.tag", want);
        snprintf(want, sizeof want, "count\n%d\n", small);
        EXPECT("SELECT COUNT(*) FROM d JOIN h ON d.w = h.x", want);
        EXPECT("SELECT COUNT(*) FROM h JOIN d ON h.x = d.w", want);
        snprintf(sql, sizeof sql, "SELECT COUNT(*) FROM (SELECT w FROM d WHERE w > 0) AS s WHERE w < %s", num(2 * P64, 0));
        snprintf(want, sizeof want, "count\n%d\n", mid);
        EXPECT(sql, want);
        snprintf(sql, sizeof sql, "WITH s AS (SELECT w FROM d WHERE w > 0) SELECT COUNT(*) FROM s WHERE w < %s", num(2 * P64, 0));
        EXPECT(sql, want);
    }
}

static void insert_model(void)
{
    char sql[1 << 14];
    for (int i = 0; i < NROWS; i += 20) {
        size_t o = (size_t)snprintf(sql, sizeof sql, "INSERT INTO d VALUES ");
        for (int j = i; j < i + 20 && j < NROWS; j++)
            o += (size_t)snprintf(sql + o, sizeof sql - o, "%s(%s, %s, %lld.25, %lld)", j > i ? ", " : "", num(g_m[j].id, 6),
                                  g_m[j].wnull ? "NULL" : num(g_m[j].w, 0), (long long)(j % 101 - 50), (long long)g_m[j].g);
        if (run(sql)) {
            test_fail(__FILE__, __LINE__, g_e.msg);
            return;
        }
    }
}

static void t_dec38_model(void)
{
    const char *dir = test_tmpdir();
    imdb_err e = {0};
    CHECK(imdb_init(dir, false, NULL, &e) == 0);
    imdb_db *db = open_with(dir, false, 0);
    CHECK(db);
    if (!db) return;
    OK(run("CREATE TABLE d (id DECIMAL(38,6) PRIMARY KEY, w DECIMAL(30,0), n DECIMAL(10,2), g INT64)"));
    OK(run("CREATE TABLE e (w DECIMAL(30,0) PRIMARY KEY, tag INT64)"));
    OK(run("CREATE TABLE h (x DECIMAL(10,0) PRIMARY KEY)"));
    char sql[1 << 12];
    for (int k = 0; k < 13; k++) {
        snprintf(sql, sizeof sql, "INSERT INTO e VALUES (%s, %d)", num(bval(k), 0), k);
        OK(run(sql));
    }
    OK(run("INSERT INTO h VALUES (0), (1), (-1), (12345), (99)"));
    model_init();
    insert_model();
    model_queries("memory");
    OK(run("SET cross_check = on"));
    model_queries("cross_check");
    OK(run("CHECKPOINT"));
    model_queries("lake");
    /* writes: an UPDATE of the wide column by a predicate on it, a DELETE by the whole key, a refusal past the bound */
    snprintf(sql, sizeof sql, "UPDATE d SET w = w + 1 WHERE g = 2 AND w < %s", num(p10(29), 0));
    OK(run(sql));
    for (int i = 0; i < NROWS; i++)
        if (g_m[i].g == 2 && !g_m[i].wnull && g_m[i].w < p10(29)) g_m[i].w += 1;
    for (int i = 5; i < NROWS; i += 61) {
        snprintf(sql, sizeof sql, "DELETE FROM d WHERE id = %s", num(g_m[i].id, 6));
        OK(run(sql));
        g_m[i].gone = true;
    }
    EXPECT("UPDATE d SET w = w + 1 WHERE w > 999999999999999999999999999998", "ERR exceeds DECIMAL(30,0)");
    model_queries("written");
    OK(run("CHECKPOINT"));
    model_queries("lake2");
    uint8_t dg[32];
    imdb_lthash_digest(db->meta.digest_alg, &db->global, dg);
    CHECK(verify_db(db) == 0);
    done(db);
    CHECK(audit_dir(dir) == 0);
    db = open_with(dir, false, 1); /* a segment budget of one byte: every image read again at its use */
    CHECK(db);
    if (db) {
        model_queries("budget");
        done(db);
    }
    db = open_with(dir, true, 0); /* the whole log replayed: the same digest, the same answers */
    CHECK(db);
    if (db) {
        uint8_t d2[32];
        imdb_lthash_digest(db->meta.digest_alg, &db->global, d2);
        CHECK(memcmp(dg, d2, 32) == 0);
        model_queries("replay");
        done(db);
    }
}

/* ---- the arithmetic at the bound, and the rules ---- */
static void t_dec38_rules(void)
{
    const char *dir = test_tmpdir();
    imdb_err e = {0};
    CHECK(imdb_init(dir, false, NULL, &e) == 0);
    imdb_db *db = open_with(dir, false, 0);
    CHECK(db);
    if (!db) return;
    OK(run("CREATE TABLE a (id INT64 PRIMARY KEY, x DECIMAL(38,0), y DECIMAL(38,2))"));
    OK(run("INSERT INTO a VALUES (1, 99999999999999999999999999999999999999, 1.25), "
           "(2, -99999999999999999999999999999999999999, -1.25), (3, 10000000000000000000000000000000000000, 0)"));
    EXPECT("SELECT x + 1 AS s FROM a WHERE id = 2", "s\n-99999999999999999999999999999999999998\n");
    EXPECT("SELECT x + 1 AS s FROM a WHERE id = 1", "ERR more than 38 digits");
    EXPECT("SELECT x * 10 AS s FROM a WHERE id = 3", "ERR more than 38 digits");
    EXPECT("SELECT SUM(x) AS tot FROM a", "tot\n10000000000000000000000000000000000000\n"); /* wraps cancel: the total is exact */
    EXPECT("SELECT SUM(x) FROM a WHERE id <> 2", "ERR a SUM of more than 38 digits");
    EXPECT("SELECT SUM(x + 0) FROM a WHERE id <> 2", "ERR a SUM of more than 38 digits");
    EXPECT("SELECT CAST(x AS DECIMAL(38,0)) AS c FROM a WHERE id = 3", "c\n10000000000000000000000000000000000000\n");
    EXPECT("SELECT CAST(x AS DECIMAL(20,0)) AS c FROM a WHERE id = 3", "ERR exceeds DECIMAL(20,0)");
    EXPECT("SELECT CAST('12345678901234567890123456789.5' AS DECIMAL(38,1)) AS c", "c\n12345678901234567890123456789.5\n");
    EXPECT("SELECT y * 2 AS z FROM a WHERE id = 1", "z\n2.50\n");
    EXPECT("SELECT COUNT(*) FROM a WHERE x > 1.5", "count\n2\n"); /* compared exactly with a DECIMAL of another scale */
    EXPECT("INSERT INTO a VALUES (4, 100000000000000000000000000000000000000, 0)", "ERR exceeds DECIMAL(38,0)");
    EXPECT("CREATE TABLE b (id DECIMAL(39,0) PRIMARY KEY)", "ERR 1 <= p <= 38");
    EXPECT("CREATE INDEX ax ON a (x)", "ERR a DECIMAL of more than 18 digits: not yet");
    OK(run("CREATE TABLE p (k DECIMAL(10,0) PRIMARY KEY)"));
    EXPECT("CREATE TABLE c (id INT64 PRIMARY KEY, k DECIMAL(30,0) REFERENCES p)", "ERR one of 18 digits or fewer and one of more");
    OK(run("CREATE TABLE q (k DECIMAL(30,0) PRIMARY KEY)"));
    OK(run("CREATE TABLE c (id INT64 PRIMARY KEY, k DECIMAL(34,0) REFERENCES q)"));
    OK(run("INSERT INTO q VALUES (18446744073709551616)"));
    EXPECT("INSERT INTO c VALUES (1, 18446744073709551616)", "INSERT 1");
    EXPECT("INSERT INTO c VALUES (2, 18446744073709551617)", "ERR violates foreign key");
    EXPECT("ALTER TABLE a ALTER COLUMN y TYPE DECIMAL(36,2)", "ERR only a widening"); /* SET DATA TYPE's other spelling: a narrowing anyway */
    OK(run("CREATE TABLE s (id INT64 PRIMARY KEY, n DECIMAL(10,2), w DECIMAL(20,2))"));
    OK(run("INSERT INTO s VALUES (1, 1.5, 12345678901234567.25)"));
    OK(run("ALTER TABLE s ALTER COLUMN w SET DATA TYPE DECIMAL(38,2)")); /* within the wide form: metadata */
    EXPECT("ALTER TABLE s ALTER COLUMN n SET DATA TYPE DECIMAL(19,2)", "ERR re-encodes every row: not yet"); /* across 18 */
    OK(run("ALTER TABLE s ALTER COLUMN n SET DATA TYPE DECIMAL(18,2)"));
    EXPECT("SELECT w FROM s", "w\n12345678901234567.25\n");
    /* a view of wide values and of places past 18 (a row set's 38) */
    OK(run("CREATE VIEW v AS SELECT id, x, AVG(y) AS m FROM a GROUP BY id, x"));
    EXPECT("SELECT x FROM v WHERE id = 1", "x\n99999999999999999999999999999999999999\n");
    EXPECT("SELECT COUNT(*) FROM v WHERE x = -99999999999999999999999999999999999999", "count\n1\n");
    /* the API: a wide value as a parameter, either form; a value past the column's form refused, never cut */
    imdb_value pv[2];
    memset(pv, 0, sizeof pv);
    pv[0].type = IMDB_T_INT64;
    pv[0].i = 9;
    pv[1].type = IMDB_T_DECIMAL;
    imdb_dec_set(&pv[1], P64 * 5, true);
    imdb_result r;
    imdb_err_clear(&g_e);
    static const char ins[] = "INSERT INTO a (id, x, y) VALUES ($1, $2, 0)";
    OK(imdb_exec_one(&g_s, ins, sizeof ins - 1, pv, 2, &r, &g_e));
    imdb_result_free(&r);
    snprintf(g_out, sizeof g_out, "x\n%s\n", num(P64 * 5, 0));
    char want[128];
    snprintf(want, sizeof want, "%s", g_out);
    EXPECT("SELECT x FROM a WHERE id = 9", want);
    imdb_value pq[1];
    memset(pq, 0, sizeof pq);
    pq[0].type = IMDB_T_DECIMAL;
    imdb_dec_set(&pq[0], P64 * 5, true);
    imdb_err_clear(&g_e);
    static const char sel[] = "SELECT COUNT(*) FROM p WHERE k = $1";
    CHECK(imdb_exec_one(&g_s, sel, sizeof sel - 1, pq, 1, &r, &g_e) != IMDB_OK ||
          (imdb_result_free(&r), false)); /* a narrow column: 2^64 * 5 is past it, refused */
    CHECK(verify_db(db) == 0);
    done(db);
    CHECK(audit_dir(dir) == 0);
}

/* a dump's bytes */
typedef struct outb {
    char *p;
    size_t n, cap;
} outb;

static int outb_write(void *arg, const char *b, size_t n)
{
    outb *o = arg;
    if (o->n + n + 1 > o->cap) {
        size_t c = (o->n + n + 1) * 2;
        char *q = realloc(o->p, c);
        if (!q) return -1;
        o->p = q;
        o->cap = c;
    }
    memcpy(o->p + o->n, b, n);
    o->n += n;
    o->p[o->n] = 0;
    return 0;
}

/* a dump restored as imagedb sql -f restores it (t_fk.c's): each line a statement, a COPY's data the lines up to a \.
 * line outside quotes */
static int restore_text(const char *s, size_t n)
{
    static char line[1 << 14];
    size_t at = 0;
    while (at < n) {
        size_t eol = at;
        while (eol < n && s[eol] != '\n') eol++;
        size_t ll = eol - at;
        if (ll >= sizeof line) return -1;
        memcpy(line, s + at, ll);
        line[ll] = 0;
        at = eol < n ? eol + 1 : n;
        if (!ll || !strncmp(line, "--", 2)) continue;
        if (strncmp(line, "COPY ", 5)) {
            if (run(line)) return -1;
            continue;
        }
        size_t k = at;
        bool bol = true, inq = false;
        for (; k < n; k++) {
            if (bol && !inq && s[k] == '\\' && k + 1 < n && s[k + 1] == '.' && (k + 2 == n || s[k + 2] == '\n')) break;
            if (s[k] == '"') inq = !inq;
            bol = s[k] == '\n';
        }
        if (k >= n) return -1;
        g_in = (mem_in){s + at, k - at, 0};
        if (strncmp(csv(line), "COPY ", 5)) return -1;
        at = k + 2 < n ? k + 3 : n;
    }
    return 0;
}

/* a dump run into a fresh database at DIR and dumped again: the same text past its first line (the commit); VERIFY
 * and the auditor on the copy */
static void dump_restored(const outb *d1, const char *dir)
{
    imdb_err e = {0};
    CHECK(d1->p != NULL);
    CHECK(imdb_init(dir, false, NULL, &e) == 0);
    imdb_db *db = open_with(dir, false, 0);
    CHECK(db);
    if (!db || !d1->p) {
        if (db) done(db);
        return;
    }
    CHECK(restore_text(d1->p, d1->n) == 0);
    outb d2 = {0};
    OK(imdb_dump(db, 0, outb_write, &d2, &e));
    CHECK(d2.p && strchr(d1->p, '\n') && strchr(d2.p, '\n') && !strcmp(strchr(d1->p, '\n'), strchr(d2.p, '\n')));
    CHECK(verify_db(db) == 0);
    done(db);
    CHECK(audit_dir(dir) == 0);
    free(d2.p);
}

/* ---- CHECK constraints, generated columns and a DEFAULT over wide values (the design's 7.4): each write held to the
 * engine's rules and, through the auditor, to its own evaluation; refusals by a CHECK, by the arithmetic's 38 digits
 * and by a column's precision; an ADD CHECK over the rows; through a CHECKPOINT, an UPDATE recomputing, a segment
 * budget of one byte and a full replay at the same digest; the dump spelling them, restored and dumped again ---- */
static void t_dec38_constraints(void)
{
    const char *dir = test_tmpdir();
    char p[700], r[700];
    snprintf(p, sizeof p, "%s/p", dir);
    snprintf(r, sizeof r, "%s/r", dir);
    imdb_err e = {0};
    CHECK(imdb_init(p, false, NULL, &e) == 0);
    imdb_db *db = open_with(p, false, 0);
    CHECK(db);
    if (!db) return;
    OK(run("CREATE TABLE g (id INT64 PRIMARY KEY, w DECIMAL(38,6) CHECK (w <> 0), n DECIMAL(12,2), "
           "x DECIMAL(30,1) DEFAULT 12345678901234567890123456789.5, "
           "m DECIMAL(38,6) GENERATED ALWAYS AS (w * 2) STORED, d DECIMAL(38,6) GENERATED ALWAYS AS (w + n) STORED, "
           "h DECIMAL(24,2) GENERATED ALWAYS AS (w / 100000000000) STORED, "
           "CONSTRAINT lim CHECK (w < 40000000000000000000000000000000), CONSTRAINT wn CHECK (w > n - 1))"));
    /* h: the quotient at 12 places, then the column's 2, each rounded half away from zero (0.005 to 0.01) */
    OK(run("INSERT INTO g (id, w, n) VALUES (1, 39999999999999999999999999999999.999999, 99999999.99), "
           "(2, 0.000001, -1.25), (3, 500000000, 0), (4, -500000000, -9999999999.99), (5, NULL, NULL)"));
    EXPECT("SELECT id, m, d, h, x FROM g ORDER BY id",
           "id,m,d,h,x\n"
           "1,79999999999999999999999999999999.999998,40000000000000000000000099999999.989999,400000000000000000000.00,"
           "12345678901234567890123456789.5\n"
           "2,0.000002,-1.249999,0.00,12345678901234567890123456789.5\n"
           "3,1000000000.000000,500000000.000000,0.01,12345678901234567890123456789.5\n"
           "4,-1000000000.000000,-10499999999.990000,-0.01,12345678901234567890123456789.5\n"
           "5,,,,12345678901234567890123456789.5\n");
    EXPECT("INSERT INTO g (id, w, n) VALUES (6, 0, 0)", "ERR violates check constraint g_w_check");
    EXPECT("INSERT INTO g (id, w, n) VALUES (6, 45000000000000000000000000000000, 0)", "ERR violates check constraint lim");
    EXPECT("INSERT INTO g (id, w, n) VALUES (6, -10, 0)", "ERR violates check constraint wn");
    EXPECT("INSERT INTO g (id, w, n) VALUES (6, 50000000000000000000000000000000, 0)", "ERR more than 38 digits"); /* m's */
    EXPECT("INSERT INTO g (id, w, n, x) VALUES (6, 1, 0, 1234567890123456789012345678901)", "ERR exceeds DECIMAL(30,1)");
    EXPECT("INSERT INTO g (id, w, n, m) VALUES (6, 1, 0, 2)", "ERR generated");
    EXPECT("ALTER TABLE g ADD CONSTRAINT pos CHECK (w > -1)", "ERR check constraint pos of table g is violated by some row");
    EXPECT("SELECT COUNT(*) FROM g", "count\n5\n");
    OK(run("CHECKPOINT"));
    EXPECT("UPDATE g SET w = w - 1 WHERE id = 3", "UPDATE 1");
    EXPECT("UPDATE g SET w = w + 10000000000000000000000000000000 WHERE id = 1", "ERR violates check constraint lim");
    OK(run("INSERT INTO g (id, w, n) VALUES (7, 12345678901234567890.123456, 1)"));
    OK(run("ALTER TABLE g ADD CONSTRAINT big CHECK (w > -99999999999999999999999999999999.999999)"));
    static const char want[] =
        "id,w,m,d,h\n"
        "1,39999999999999999999999999999999.999999,79999999999999999999999999999999.999998,"
        "40000000000000000000000099999999.989999,400000000000000000000.00\n"
        "2,0.000001,0.000002,-1.249999,0.00\n"
        "3,499999999.000000,999999998.000000,499999999.000000,0.00\n"
        "4,-500000000.000000,-1000000000.000000,-10499999999.990000,-0.01\n"
        "5,,,,\n"
        "7,12345678901234567890.123456,24691357802469135780.246912,12345678901234567891.123456,123456789.01\n";
    EXPECT("SELECT id, w, m, d, h FROM g ORDER BY id", want);
    EXPECT("SELECT COUNT(*) FROM g WHERE m <> w * 2 OR d <> w + n", "count\n0\n");
    uint8_t dg[32];
    imdb_lthash_digest(db->meta.digest_alg, &db->global, dg);
    outb d1 = {0};
    OK(imdb_dump(db, 0, outb_write, &d1, &e));
    CHECK(d1.p && strstr(d1.p, "DEFAULT 12345678901234567890123456789.5") && strstr(d1.p, "GENERATED ALWAYS AS (w * 2) STORED") &&
          strstr(d1.p, "CHECK (w < 40000000000000000000000000000000)") &&
          strstr(d1.p, "CHECK (w > -99999999999999999999999999999999.999999)"));
    CHECK(verify_db(db) == 0);
    done(db);
    db = open_with(p, false, 1); /* a segment budget of one byte: every image read again at its use */
    CHECK(db);
    if (db) {
        EXPECT("SELECT id, w, m, d, h FROM g ORDER BY id", want);
        done(db);
    }
    db = open_with(p, true, 0); /* the whole log replayed: each write's CHECKs and expressions again, the same digest */
    CHECK(db);
    if (db) {
        uint8_t d2[32];
        imdb_lthash_digest(db->meta.digest_alg, &db->global, d2);
        CHECK(memcmp(dg, d2, 32) == 0);
        EXPECT("SELECT id, w, m, d, h FROM g ORDER BY id", want);
        CHECK(verify_db(db) == 0);
        done(db);
    }
    CHECK(audit_dir(p) == 0);
    dump_restored(&d1, r);
    free(d1.p);
}

/* ---- wide columns added after a CHECKPOINT, one with a DEFAULT (op 22's 16-byte value, the history's missing value in
 * manifest 15, read by the older segment's rows as a constant column) and one given a wide SET DEFAULT; ERASE SUBJECT of
 * rows holding wide cells, in a segment of each version and in memory (an erased row keeps no cell: the engine's load
 * and the auditor's rule); each state through a CHECKPOINT, a budget of one byte, a full replay at the same digest,
 * VERIFY, the auditor and the dump ---- */
static void t_dec38_alter_erase(void)
{
    const char *dir = test_tmpdir();
    char p[700], r[700];
    snprintf(p, sizeof p, "%s/p", dir);
    snprintf(r, sizeof r, "%s/r", dir);
    imdb_err e = {0};
    CHECK(imdb_init(p, false, NULL, &e) == 0);
    imdb_db *db = open_with(p, false, 0);
    CHECK(db);
    if (!db) return;
    OK(run("CREATE TABLE s (id INT64 PRIMARY KEY, u INT64 SUBJECT, w DECIMAL(38,4), n DECIMAL(10,2))"));
    OK(run("INSERT INTO s VALUES (1, 7, 1234567890123456789012345678901234.5678, 1.5), "
           "(2, 7, -18446744073709551616.0001, 2.5), (3, 8, 18446744073709551616, 3.5), (4, 9, NULL, 4.5)"));
    OK(run("CHECKPOINT")); /* the four rows in a segment of version 1 */
    /* m's rows in memory at its ADD, so the next CHECKPOINT builds them into a segment of the last version: each older
     * row's missing value written as a 16-byte cell (src_get's missing value, the auditor's check of it) */
    OK(run("CREATE TABLE m (id INT64 PRIMARY KEY, n INT64)"));
    OK(run("INSERT INTO m VALUES (1, 1), (2, 2)"));
    OK(run("ALTER TABLE m ADD COLUMN a DECIMAL(30,2) DEFAULT -9876543210987654321098765432.1"));
    OK(run("INSERT INTO m (id, n) VALUES (3, 3)"));
    static const char wm[] = "id,n,a\n1,1,-9876543210987654321098765432.10\n2,2,-9876543210987654321098765432.10\n"
                             "3,3,-9876543210987654321098765432.10\n";
    EXPECT("SELECT * FROM m ORDER BY id", wm);
    OK(run("ALTER TABLE s ADD COLUMN a DECIMAL(30,2) DEFAULT 123456789012345678901234567.89"));
    OK(run("ALTER TABLE s ADD COLUMN b DECIMAL(25,0)"));
    OK(run("ALTER TABLE s ALTER COLUMN b SET DEFAULT -18446744073709551617"));
    OK(run("INSERT INTO s (id, u, w) VALUES (5, 8, 5), (6, 7, -5)"));
    OK(run("UPDATE s SET b = 3 * 18446744073709551616 WHERE id = 4")); /* an older row written under the last version */
    EXPECT("SELECT * FROM s ORDER BY id",
           "id,u,w,n,a,b\n"
           "1,7,1234567890123456789012345678901234.5678,1.50,123456789012345678901234567.89,\n"
           "2,7,-18446744073709551616.0001,2.50,123456789012345678901234567.89,\n"
           "3,8,18446744073709551616.0000,3.50,123456789012345678901234567.89,\n"
           "4,9,,4.50,123456789012345678901234567.89,55340232221128654848\n"
           "5,8,5.0000,,123456789012345678901234567.89,-18446744073709551617\n"
           "6,7,-5.0000,,123456789012345678901234567.89,-18446744073709551617\n");
    EXPECT("SELECT COUNT(*) FROM s WHERE a = 123456789012345678901234567.89 AND b IS NULL", "count\n3\n");
    OK(run("CHECKPOINT")); /* rows 4 to 6 in a segment of the last version; 1 to 3 stay in version 1's */
    imdb_table *mt = imdb_table_by_name(db, "m");
    CHECK(mt && mt->nseg == 1 && mt->seg[0]->gver == 1 && mt->seg[0]->nrows == 3); /* version 1's rows at version 2 */
    EXPECT("SELECT * FROM m ORDER BY id", wm);
    EXPECT("SELECT COUNT(*) FROM m WHERE a < -9876543210987654321098765432", "count\n3\n");
    OK(run("ERASE SUBJECT 7")); /* rows 1 and 2 in the older segment, 6 in the newer: each rewritten without their cells */
    OK(run("INSERT INTO s (id, u, w, a, b) VALUES (7, 9, 0.0001, -0.01, 0)"));
    OK(run("ERASE SUBJECT 8")); /* row 3 in the older segment, 5 in the newer */
    static const char want[] = "id,u,w,n,a,b\n"
                               "4,9,,4.50,123456789012345678901234567.89,55340232221128654848\n"
                               "7,9,0.0001,,-0.01,0\n";
    EXPECT("SELECT * FROM s ORDER BY id", want);
    OK(run("CHECKPOINT"));
    OK(run("COMPACT s")); /* segments of both versions merged, stubs and wide cells among them (seg_runs: stubs by their version) */
    EXPECT("SELECT * FROM s ORDER BY id", want);
    uint8_t dg[32];
    imdb_lthash_digest(db->meta.digest_alg, &db->global, dg);
    outb d1 = {0};
    OK(imdb_dump(db, 0, outb_write, &d1, &e));
    CHECK(d1.p && strstr(d1.p, "DEFAULT 123456789012345678901234567.89") && strstr(d1.p, "DEFAULT -18446744073709551617"));
    CHECK(verify_db(db) == 0);
    done(db);
    db = open_with(p, false, 1); /* a segment budget of one byte: every image read again at its use */
    CHECK(db);
    if (db) {
        EXPECT("SELECT * FROM s ORDER BY id", want);
        EXPECT("SELECT COUNT(*) FROM s WHERE b > 18446744073709551616", "count\n1\n");
        EXPECT("SELECT * FROM m ORDER BY id", wm);
        done(db);
    }
    db = open_with(p, true, 0); /* the whole log replayed: the ALTERs' values and the erasures again, the same digest */
    CHECK(db);
    if (db) {
        uint8_t d2[32];
        imdb_lthash_digest(db->meta.digest_alg, &db->global, d2);
        CHECK(memcmp(dg, d2, 32) == 0);
        EXPECT("SELECT * FROM s ORDER BY id", want);
        EXPECT("SELECT * FROM m ORDER BY id", wm);
        CHECK(verify_db(db) == 0);
        done(db);
    }
    CHECK(audit_dir(p) == 0);
    dump_restored(&d1, r);
    free(d1.p);
}

/* ---- keys of several parts (the advisor, 23:4x): every row set's DECIMAL is 38 digits, so a narrow column meets a
 * wide one in everyday queries. Joins on two pairs (narrow with wide, wide with wide) under both plans, against a
 * derived table and a view; GROUP BY two keys, DISTINCT rows, COUNT(DISTINCT), the set operations; a PRIMARY KEY (g, w)
 * through lookups, ON CONFLICT naming the key in another order, a refused duplicate, a CHECKPOINT, a budget of one
 * byte, a full replay, VERIFY, a replica and the auditor. Values share their low 64 bits (2^64 and 2^64 + 1, 2^65 and
 * 2^65 + 1), so any encoding that kept 64 bits would merge them; every read cross-checked ---- */
static void t_dec38_multikey(void)
{
    const char *dir = test_tmpdir();
    char p[700], q[700], sf[700];
    snprintf(p, sizeof p, "%s/p", dir);
    snprintf(q, sizeof q, "%s/q", dir);
    snprintf(sf, sizeof sf, "%s/stream", dir);
    imdb_err e = {0};
    CHECK(imdb_init(p, false, NULL, &e) == 0 && imdb_init(q, true, p, &e) == 0);
    imdb_db *db = open_with(p, false, 0);
    CHECK(db);
    if (!db) return;
    OK(run("CREATE TABLE a (id INT64 PRIMARY KEY, g INT64, n DECIMAL(12,2), w DECIMAL(38,2))"));
    OK(run("CREATE TABLE b (id INT64 PRIMARY KEY, g INT64, n DECIMAL(12,2), w DECIMAL(38,2))"));
    OK(run("CREATE INDEX bg ON b (g)")); /* the index nested-loop plan's probe */
    OK(run("INSERT INTO a VALUES (1, 1, 1, 18446744073709551616), (2, 1, 2, 18446744073709551617), (3, 2, 1, 1), "
           "(4, 2, 5, 36893488147419103232), (5, 1, NULL, NULL), (6, 1, 1, 18446744073709551616)"));
    OK(run("INSERT INTO b VALUES (1, 1, 1, 1), (2, 1, 2, 18446744073709551616), (3, 2, 5, 5), (4, 2, 1, 36893488147419103233), "
           "(5, 1, 7, 18446744073709551617), (6, 2, 9, 36893488147419103232)"));
    OK(run("CREATE VIEW vb AS SELECT g, w FROM b"));
    OK(run("SET cross_check = on"));
    for (int plan = 0; plan < 2; plan++) {
        OK(run(plan ? "SET join_plan = index" : "SET join_plan = hash"));
        EXPECT("SELECT a.id, b.id FROM a JOIN b ON a.g = b.g AND a.n = b.w ORDER BY a.id, b.id", "id,id\n1,1\n4,3\n6,1\n");
        EXPECT("SELECT a.id, b.id FROM a JOIN b ON a.g = b.g AND a.w = b.w ORDER BY a.id, b.id", "id,id\n1,2\n2,5\n4,6\n6,2\n");
        EXPECT("SELECT a.id, s.g FROM a JOIN (SELECT g, n, w FROM b) AS s ON a.g = s.g AND a.w = s.w ORDER BY a.id",
               "id,g\n1,1\n2,1\n4,2\n6,1\n");
        EXPECT("SELECT a.id, vb.g FROM a JOIN vb ON a.g = vb.g AND a.n = vb.w ORDER BY a.id", "id,g\n1,1\n4,2\n6,1\n");
    }
    OK(run("SET join_plan = auto"));
    EXPECT("SELECT g, w, COUNT(*) AS c FROM a GROUP BY g, w ORDER BY g, w",
           "g,w,c\n1,18446744073709551616.00,2\n1,18446744073709551617.00,1\n1,,1\n2,1.00,1\n2,36893488147419103232.00,1\n");
    EXPECT("SELECT DISTINCT g, w FROM a ORDER BY g, w",
           "g,w\n1,18446744073709551616.00\n1,18446744073709551617.00\n1,\n2,1.00\n2,36893488147419103232.00\n");
    EXPECT("SELECT g, COUNT(DISTINCT w) AS d FROM a GROUP BY g ORDER BY g", "g,d\n1,2\n2,2\n");
    EXPECT("SELECT n AS v FROM a WHERE n IS NOT NULL UNION SELECT w FROM b ORDER BY v",
           "v\n1.00\n2.00\n5.00\n18446744073709551616.00\n18446744073709551617.00\n36893488147419103232.00\n"
           "36893488147419103233.00\n");
    EXPECT("SELECT w AS v FROM a INTERSECT SELECT w FROM b ORDER BY v",
           "v\n1.00\n18446744073709551616.00\n18446744073709551617.00\n36893488147419103232.00\n");
    EXPECT("SELECT w AS v FROM a EXCEPT SELECT w FROM b ORDER BY v", "v\n\n");
    EXPECT("SELECT g, w FROM a INTERSECT SELECT g, w FROM b ORDER BY g, w",
           "g,w\n1,18446744073709551616.00\n1,18446744073709551617.00\n2,36893488147419103232.00\n");
    /* a key of two parts, one wide */
    OK(run("CREATE TABLE k (g INT64, w DECIMAL(38,2), v TEXT, PRIMARY KEY (g, w))"));
    OK(run("INSERT INTO k VALUES (1, 18446744073709551616, 'a'), (1, 18446744073709551617, 'b'), (2, 18446744073709551616, 'c'), "
           "(1, -18446744073709551616, 'd')"));
    EXPECT("INSERT INTO k VALUES (1, 18446744073709551616, 'x') ON CONFLICT (w, g) DO UPDATE SET v = 'a2'", "INSERT 1");
    EXPECT("INSERT INTO k VALUES (1, 18446744073709551617, 'dup')", "ERR duplicate primary key");
    OK(run("CHECKPOINT"));
    OK(run("INSERT INTO k VALUES (1, 36893488147419103232.5, 'e')"));
    uint64_t before = db->seq; /* the history before the UPDATE: AS OF reads it by the whole key */
    OK(run("UPDATE k SET v = 'b2' WHERE g = 1 AND w = 18446744073709551617"));
    OK(run("CHECKPOINT")); /* the ended version in the lake (and, evicting eagerly, there alone: the lake's key search) */
    /* the transaction forms: a rollback, a savepoint rolled back to, a statement refused at its second row, and two
     * sessions updating one wide-keyed row (the first committer wins) */
    OK(run("BEGIN"));
    EXPECT("UPDATE k SET v = 'r' WHERE g = 1 AND w = 18446744073709551616", "UPDATE 1");
    OK(run("ROLLBACK"));
    OK(run("BEGIN"));
    OK(run("INSERT INTO k VALUES (3, 18446744073709551616, 's')"));
    OK(run("SAVEPOINT s1"));
    OK(run("UPDATE k SET v = 't' WHERE g = 3 AND w = 18446744073709551616"));
    OK(run("ROLLBACK TO s1"));
    OK(run("COMMIT"));
    EXPECT("INSERT INTO k VALUES (4, 18446744073709551616, 'ok'), (1, 18446744073709551617, 'dup')", "ERR duplicate primary key");
    EXPECT("SELECT COUNT(*) FROM k WHERE g = 4", "count\n0\n");
    imdb_session sb;
    imdb_session_init(&sb, db);
    OK(run("BEGIN"));
    EXPECT("UPDATE k SET v = 'A' WHERE g = 2 AND w = 18446744073709551616", "UPDATE 1");
    imdb_result rr;
    imdb_err_clear(&g_e);
    static const char bb[] = "BEGIN", bu[] = "UPDATE k SET v = 'B' WHERE g = 2 AND w = 18446744073709551616", bc[] = "COMMIT";
    CHECK(imdb_exec_one(&sb, bb, sizeof bb - 1, NULL, 0, &rr, &g_e) == 0);
    imdb_result_free(&rr);
    static const char bs[] = "SELECT COUNT(*) FROM k"; /* B's snapshot, taken by its first statement, before A commits */
    CHECK(imdb_exec_one(&sb, bs, sizeof bs - 1, NULL, 0, &rr, &g_e) == 0);
    imdb_result_free(&rr);
    OK(run("COMMIT"));
    imdb_err_clear(&g_e);
    int urc = imdb_exec_one(&sb, bu, sizeof bu - 1, NULL, 0, &rr, &g_e), crc = -1;
    if (!urc) {
        imdb_result_free(&rr);
        imdb_err_clear(&g_e);
        crc = imdb_exec_one(&sb, bc, sizeof bc - 1, NULL, 0, &rr, &g_e);
        if (!crc) imdb_result_free(&rr);
    }
    if (!((urc || crc) && strstr(g_e.msg, "could not serialize"))) { /* B began before A committed: a conflict */
        char m[700];
        snprintf(m, sizeof m, "the second session: update %d, commit %d: %.500s", urc, crc, g_e.msg);
        test_fail(__FILE__, __LINE__, m);
    }
    imdb_session_close(&sb);
    OK(run("DELETE FROM k WHERE g = 3")); /* the transactions' rows gone again: the state below is the same */
    OK(run("UPDATE k SET v = 'c' WHERE g = 2 AND w = 18446744073709551616"));
    static const char wk[] = "g,w,v\n1,-18446744073709551616.00,\"d\"\n1,18446744073709551616.00,\"a2\"\n"
                             "1,18446744073709551617.00,\"b2\"\n1,36893488147419103232.50,\"e\"\n2,18446744073709551616.00,\"c\"\n";
    EXPECT("SELECT * FROM k ORDER BY g, w", wk);
    char asof[300];
    snprintf(asof, sizeof asof, "SELECT v FROM k AS OF %llu WHERE g = 1 AND w = 18446744073709551617", (unsigned long long)before);
    EXPECT(asof, "v\n\"b\"\n");
    OK(run("SET cross_check = off"));
    const char *hist = csv("SHOW HISTORY k (1, 18446744073709551617)");
    CHECK(strstr(hist, ",\"b\"\n") && strstr(hist, ",\"b2\"\n"));
    OK(run("SET cross_check = on"));
    uint8_t dg[32];
    imdb_lthash_digest(db->meta.digest_alg, &db->global, dg);
    CHECK(verify_db(db) == 0);
    done(db);
    for (int pass = 0; pass < 2; pass++) { /* a budget of one byte, then the whole log replayed */
        db = open_with(p, pass == 1, pass ? 0 : 1);
        CHECK(db);
        if (!db) return;
        OK(run("SET cross_check = on"));
        EXPECT("SELECT v FROM k WHERE g = 1 AND w = 18446744073709551616", "v\n\"a2\"\n");
        EXPECT("SELECT v FROM k WHERE g = 1 AND w = 18446744073709551617", "v\n\"b2\"\n");
        EXPECT("SELECT COUNT(*) FROM k WHERE g = 2 AND w = 18446744073709551617", "count\n0\n");
        EXPECT("SELECT * FROM k ORDER BY g, w", wk);
        EXPECT(asof, "v\n\"b\"\n"); /* below the floor after a reopen: the lake's key search */
        uint8_t d2[32];
        imdb_lthash_digest(db->meta.digest_alg, &db->global, d2);
        CHECK(memcmp(dg, d2, 32) == 0);
        done(db);
    }
    CHECK(audit_dir(p) == 0);
    OK(ship_to_file(p, 0, sf, &g_e));
    imdb_open_opts o = {.sync = 0};
    imdb_db *qdb = NULL;
    CHECK(imdb_open(q, &o, &qdb, &e) == 0);
    if (qdb) {
        uint64_t qa = 0;
        OK(apply_file(qdb, sf, &qa, &g_e));
        uint8_t qd[32];
        imdb_lthash_digest(qdb->meta.digest_alg, &qdb->global, qd);
        CHECK(memcmp(qd, dg, 32) == 0);
        imdb_close(qdb);
    }
    CHECK(audit_dir(q) == 0);
}

/* ---- a twin (the advisor, 00:2x): each statement form run over a narrow table and over a wide one holding every value
 * times 2^64, so order and equality are kept and every low half is zero (a cut that keeps only the low half merges
 * every row; one that keeps only the high half passes here unseen, and dec38_multikey's values one apart, 2^64 and
 * 2^64 + 1, catch it); only ids, counts, ranks and booleans selected, the two outputs one string, neither an error.
 * Windows (RANGE peers, a ROWS frame of an offset, its sum compared with a scaled literal), IN and NOT IN, correlated
 * subqueries, EXISTS, WITH RECURSIVE, HAVING, CASE, BETWEEN, LIMIT and OFFSET, a self-join, PREPARE and EXECUTE (a
 * declared and an undeclared parameter), then the writes (UPDATE ... FROM, DELETE ... USING, INSERT ... SELECT, each
 * with RETURNING), every read cross-checked, in memory and after a CHECKPOINT at a segment budget of one byte ---- */

/* tmpl with {T}, {U}, {K1}, {K2} and {P} replaced by one side's names and literals */
static void twin_text(const char *tmpl, bool wide, char *out, size_t n)
{
    const char *rep[5][2] = {{"{T}", wide ? "tw" : "tn"}, {"{U}", wide ? "uw" : "un"},
                             {"{K1}", wide ? "27670116110564327424.00" : "1.50"},
                             {"{K2}", wide ? "36893488147419103232.00" : "2.00"}, {"{P}", wide ? "w" : "n"}};
    size_t o = 0;
    for (const char *s = tmpl; *s && o + 1 < n;) {
        int hit = -1;
        for (int k = 0; k < 5 && hit < 0; k++)
            if (!strncmp(s, rep[k][0], strlen(rep[k][0]))) hit = k;
        if (hit < 0) {
            out[o++] = *s++;
            continue;
        }
        size_t l = strlen(rep[hit][1]);
        if (o + l + 1 >= n) break;
        memcpy(out + o, rep[hit][1], l);
        o += l;
        s += strlen(rep[hit][0]);
    }
    out[o] = 0;
}

/* the template on both sides: the same answer, never an error */
static void twin(const char *tmpl, const char *phase)
{
    static char a[1 << 14], sn[2048], sw[2048];
    twin_text(tmpl, false, sn, sizeof sn);
    twin_text(tmpl, true, sw, sizeof sw);
    snprintf(a, sizeof a, "%s", csv(sn));
    const char *b = csv(sw);
    if (!strncmp(a, "ERR", 3) || !strncmp(b, "ERR", 3) || strcmp(a, b)) {
        char m[3000];
        snprintf(m, sizeof m, "%s, the twins differ on: %.500s\n      narrow: %.700s\n      wide:   %.700s", phase, tmpl, a, b);
        test_fail(__FILE__, __LINE__, m);
    }
}

static const char *const kTwinReads[] = {
    "SELECT id, RANK() OVER (ORDER BY x) AS r, DENSE_RANK() OVER (PARTITION BY g ORDER BY x DESC) AS dr, "
    "ROW_NUMBER() OVER (ORDER BY x, id) AS rn FROM {T} ORDER BY id",
    "SELECT id, c, s > {K2} AS big FROM (SELECT id, COUNT(*) OVER (ORDER BY x RANGE BETWEEN UNBOUNDED PRECEDING AND CURRENT "
    "ROW) AS c, SUM(x) OVER (ORDER BY x, id ROWS BETWEEN 2 PRECEDING AND CURRENT ROW) AS s FROM {T} WHERE x IS NOT NULL) AS q "
    "ORDER BY id",
    "SELECT id, LAG(id) OVER (ORDER BY x, id) AS lg, FIRST_VALUE(id) OVER (PARTITION BY g ORDER BY x, id) AS fv FROM {T} "
    "ORDER BY id",
    "SELECT id, NTILE(3) OVER (ORDER BY x, id) AS nt, SUM(g) OVER (ORDER BY x, id ROWS BETWEEN 1 PRECEDING AND 1 FOLLOWING) "
    "AS sg FROM {T} WHERE x IS NOT NULL ORDER BY id",
    "SELECT id FROM {T} WHERE x IN (SELECT x FROM {T} WHERE g = 1) ORDER BY id",
    "SELECT id FROM {T} WHERE x NOT IN (SELECT x FROM {T} WHERE g = 3 AND x IS NOT NULL) ORDER BY id",
    "SELECT id FROM {T} WHERE x IN ({K1}, {K2}) ORDER BY id",
    "SELECT id FROM {T} AS t1 WHERE x > (SELECT AVG(x) FROM {T} AS t2 WHERE t2.g = t1.g) ORDER BY id",
    "SELECT id, EXISTS (SELECT 1 FROM {T} AS t2 WHERE t2.x = t1.x AND t2.id <> t1.id) AS dup FROM {T} AS t1 ORDER BY id",
    "WITH RECURSIVE r(v, k) AS (SELECT x, 1 FROM {T} WHERE id = 1 UNION ALL SELECT v + {K1}, k + 1 FROM r WHERE k < 5) "
    "SELECT k, v IN (SELECT x FROM {T}) AS hit FROM r ORDER BY k",
    "SELECT g, COUNT(*) AS c FROM {T} GROUP BY g HAVING MAX(x) > {K2} ORDER BY g",
    "SELECT id FROM {T} ORDER BY x DESC, id LIMIT 5 OFFSET 2",
    "SELECT id, CASE WHEN x > {K1} THEN 1 WHEN x < 0 THEN -1 ELSE 0 END AS s FROM {T} ORDER BY id",
    "SELECT g, MAX(x) = (SELECT MAX(x) FROM {T}) AS top, MIN(x) < 0 AS neg FROM {T} GROUP BY g ORDER BY g",
    "SELECT a.id, b.id FROM {T} AS a JOIN {T} AS b ON a.x = b.x AND a.id < b.id ORDER BY a.id, b.id",
    "SELECT id, x = {K1} AS eq, x BETWEEN {K1} AND {K2} AS bt FROM {T} ORDER BY id",
    "SELECT COUNT(DISTINCT x) AS d, COUNT(x) AS c FROM {T}",
    "SELECT {T}.id FROM {T} JOIN {U} ON {T}.x = {U}.x ORDER BY {T}.id",
};

static void t_dec38_twin(void)
{
    const char *dir = test_tmpdir();
    imdb_err e = {0};
    CHECK(imdb_init(dir, false, NULL, &e) == 0);
    imdb_db *db = open_with(dir, false, 0);
    CHECK(db);
    if (!db) return;
    OK(run("CREATE TABLE tn (id INT64 PRIMARY KEY, x DECIMAL(10,2), g INT64)"));
    OK(run("CREATE TABLE tw (id INT64 PRIMARY KEY, x DECIMAL(38,2), g INT64)"));
    OK(run("CREATE TABLE un (id INT64 PRIMARY KEY, x DECIMAL(10,2), g INT64)"));
    OK(run("CREATE TABLE uw (id INT64 PRIMARY KEY, x DECIMAL(38,2), g INT64)"));
    OK(run("INSERT INTO tn VALUES (1, 1.50, 1), (2, 2.00, 2), (3, -1.25, 1), (4, 0.00, 2), (5, 1.50, 1), (6, 3.75, 3), "
           "(7, NULL, 1), (8, 2.00, 2), (9, -5.00, 3), (10, 10.25, 1), (11, 1.50, 2), (12, 7.00, 3)"));
    OK(run("INSERT INTO un VALUES (1, 1.50, 1), (2, -5.00, 1), (3, 7.00, 2)"));
    OK(run("INSERT INTO tw SELECT id, x * 18446744073709551616, g FROM tn"));
    OK(run("INSERT INTO uw SELECT id, x * 18446744073709551616, g FROM un"));
    EXPECT("SELECT COUNT(*) FROM tw AS w JOIN tn AS n ON w.id = n.id AND w.x = n.x * 18446744073709551616", "count\n11\n");
    OK(run("SET cross_check = on"));
    for (size_t k = 0; k < sizeof kTwinReads / sizeof *kTwinReads; k++) twin(kTwinReads[k], "in memory");
    /* PREPARE and EXECUTE: a declared parameter and an undeclared one (the literal's own type) */
    OK(run("PREPARE pdn (DECIMAL(38,2)) AS SELECT id FROM tn WHERE x > $1 ORDER BY id"));
    OK(run("PREPARE pdw (DECIMAL(38,2)) AS SELECT id FROM tw WHERE x > $1 ORDER BY id"));
    twin("EXECUTE pd{P}({K1})", "a declared parameter");
    OK(run("PREPARE pun AS SELECT COUNT(*) AS c FROM tn WHERE x = $1"));
    OK(run("PREPARE puw AS SELECT COUNT(*) AS c FROM tw WHERE x = $1"));
    twin("EXECUTE pu{P}({K1})", "an undeclared parameter");
    /* the writes, each with RETURNING; then the tables' states */
    twin("UPDATE {T} SET g = {T}.g + 100 FROM {U} WHERE {T}.x = {U}.x AND {U}.g = 1 RETURNING {T}.id AS id", "UPDATE ... FROM");
    twin("DELETE FROM {T} USING {U} WHERE {T}.x = {U}.x AND {U}.id = 3 RETURNING {T}.id AS id", "DELETE ... USING");
    twin("INSERT INTO {T} (id, x, g) SELECT id + 100, x, g FROM {U} RETURNING id, x > {K1} AS big", "INSERT ... SELECT");
    twin("UPDATE {T} SET x = x + {K2} WHERE id = 4 RETURNING id, x > {K1} AS big", "UPDATE");
    twin("SELECT id, g FROM {T} ORDER BY id", "after the writes");
    EXPECT("SELECT COUNT(*) FROM tn", "count\n14\n");
    OK(run("CHECKPOINT"));
    done(db);
    db = open_with(dir, false, 1); /* a segment budget of one byte: every image read again at its use */
    CHECK(db);
    if (!db) return;
    OK(run("SET cross_check = on"));
    for (size_t k = 0; k < sizeof kTwinReads / sizeof *kTwinReads; k++) twin(kTwinReads[k], "from the lake");
    CHECK(verify_db(db) == 0);
    done(db);
    CHECK(audit_dir(dir) == 0);
}

/* ---- the auditor's own queries over wide columns (the advisor, 00:5x): count's filters parsed to 128 bits (a 39-digit
 * value refused, where it used to overflow an int128 and match nothing; and, older than F3e, an INT64 filter from 2^63
 * up refused, where it wrapped onto INT64_MIN's or 0's rows), its sums counting their wraps (partial sums past 2^127
 * and back give the exact total, a total past 38 digits "out-of-range" where the engine refuses the SUM), each against
 * the engine's COUNT and SUM, from the log, --lake and --as-of; digest over a wide table ---- */

/* the auditor's first line for its arguments (IMDB_AUDIT_BIN), cut before " (commit"; NULL without an auditor */
static const char *audit_line(const char *args)
{
    const char *bin = getenv("IMDB_AUDIT_BIN");
    if (!bin || !*bin) return NULL;
    static char out[1024];
    char cmd[2048];
    snprintf(cmd, sizeof cmd, "'%s' %s 2>&1", bin, args);
    FILE *f = popen(cmd, "r");
    if (!f) return NULL;
    if (!fgets(out, sizeof out, f)) out[0] = 0;
    pclose(f);
    char *c = strstr(out, " (commit");
    if (c) *c = 0;
    size_t l = strlen(out);
    while (l && out[l - 1] == '\n') out[--l] = 0;
    return out;
}

#define AUDIT_IS(dir, args, want)                                                                                  \
    do {                                                                                                           \
        char a_[1600];                                                                                             \
        snprintf(a_, sizeof a_, args, dir);                                                                        \
        const char *got_ = audit_line(a_);                                                                         \
        if (got_ && strcmp(got_, (want))) {                                                                        \
            char m_[3000];                                                                                         \
            snprintf(m_, sizeof m_, "auditor %.800s\n      want: %.800s\n      got:  %.800s", a_, (want), got_);   \
            test_fail(__FILE__, __LINE__, m_);                                                                     \
        }                                                                                                          \
    } while (0)

static void t_dec38_audit_queries(void)
{
    const char *dir = test_tmpdir();
    char p[700];
    snprintf(p, sizeof p, "%s/p", dir);
    imdb_err e = {0};
    CHECK(imdb_init(p, false, NULL, &e) == 0);
    imdb_db *db = open_with(p, false, 0);
    CHECK(db);
    if (!db) return;
    OK(run("CREATE TABLE a (id INT64 PRIMARY KEY, x DECIMAL(38,0), y DECIMAL(38,2))"));
    OK(run("INSERT INTO a VALUES (1, 99999999999999999999999999999999999999, 1.25), (2, -99999999999999999999999999999999999999, "
           "-1.25), (3, 10000000000000000000000000000000000000, 0), (4, 18446744073709551616, 18446744073709551616.5), "
           "(5, -18446744073709551617, NULL), (6, 18446744073709551616, -0.01)"));
    uint64_t before = db->seq;
    OK(run("CHECKPOINT"));
    OK(run("UPDATE a SET y = y + 1 WHERE id = 4"));
    OK(run("DELETE FROM a WHERE id = 6"));
    EXPECT("SELECT COUNT(*), SUM(x), SUM(y) FROM a WHERE x = 18446744073709551616",
           "count,sum_x,sum_y\n1,18446744073709551616,18446744073709551617.50\n");
    OK(run("CREATE TABLE s (id INT64 PRIMARY KEY, g INT64, x DECIMAL(38,0))"));
    OK(run("INSERT INTO s VALUES (1, 1, 99999999999999999999999999999999999999), (2, 1, 99999999999999999999999999999999999999), "
           "(3, 1, -99999999999999999999999999999999999999), (4, 1, -99999999999999999999999999999999999999), (5, 1, 5), "
           "(6, 2, 99999999999999999999999999999999999999), (7, 2, 10000000000000000000000000000000000000)"));
    EXPECT("SELECT COUNT(*), SUM(x) FROM s WHERE g = 1", "count,sum_x\n5,5\n"); /* partial sums past 2^127 and back */
    EXPECT("SELECT SUM(x) FROM s WHERE g = 2", "ERR a SUM of more than 38 digits");
    static char eng[1024]; /* the engine's digest of s, its store's and its scan's: the auditor's must be it */
    snprintf(eng, sizeof eng, "%s", csv("SHOW DIGEST s"));
    CHECK(verify_db(db) == 0);
    done(db);
    AUDIT_IS(p, "count '%s' a x=18446744073709551616", "count=1 sum(x)=18446744073709551616 sum(y)=18446744073709551617.50");
    AUDIT_IS(p, "count '%s' a x=18446744073709551616 --lake",
             "count=2 sum(x)=36893488147419103232 sum(y)=18446744073709551616.49");
    char asof[1700];
    snprintf(asof, sizeof asof, "count '%s' a y=18446744073709551616.5 --as-of %llu", p, (unsigned long long)before);
    const char *ga = audit_line(asof); /* the history before the CHECKPOINT's writes */
    CHECK(!ga || !strcmp(ga, "count=1 sum(x)=18446744073709551616 sum(y)=18446744073709551616.50"));
    AUDIT_IS(p, "count '%s' a y=18446744073709551617.5", "count=1 sum(x)=18446744073709551616 sum(y)=18446744073709551617.50");
    AUDIT_IS(p, "count '%s' a x=-18446744073709551617", "count=1 sum(x)=-18446744073709551617 sum(y)=null");
    AUDIT_IS(p, "count '%s' a x=99999999999999999999999999999999999999",
             "count=1 sum(x)=99999999999999999999999999999999999999 sum(y)=1.25");
    AUDIT_IS(p, "count '%s' a", "count=5 sum(x)=9999999999999999999999999999999999999 sum(y)=18446744073709551617.50");
    AUDIT_IS(p, "count '%s' a x=999999999999999999999999999999999999999",
             "imagedb-audit: FAILED: number out of range in filter x=999999999999999999999999999999999999999");
    AUDIT_IS(p, "count '%s' a x=100000000000000000000000000000000000000",
             "imagedb-audit: FAILED: number out of range in filter x=100000000000000000000000000000000000000");
    AUDIT_IS(p, "count '%s' a y=1.255", "imagedb-audit: FAILED: too many fractional digits in filter y=1.255");
    AUDIT_IS(p, "count '%s' a id=9223372036854775808", "imagedb-audit: FAILED: number out of range in filter id=9223372036854775808");
    AUDIT_IS(p, "count '%s' a id=18446744073709551616", "imagedb-audit: FAILED: number out of range in filter id=18446744073709551616");
    AUDIT_IS(p, "count '%s' a id=-9223372036854775808", "count=0 sum(x)=null sum(y)=null");
    AUDIT_IS(p, "count '%s' s g=1", "count=5 sum(g)=5 sum(x)=5");
    AUDIT_IS(p, "count '%s' s g=2", "count=2 sum(g)=4 sum(x)=out-of-range");
    char da[1600];
    snprintf(da, sizeof da, "digest '%s' s g=1", p);
    const char *d = audit_line(da);
    CHECK(!d || !strncmp(d, "rows=5 digest=", 14));
    snprintf(da, sizeof da, "digest '%s' s", p);
    d = audit_line(da);
    const char *hx = d ? strstr(d, "digest=") : NULL;
    CHECK(!d || (hx && strlen(hx + 7) == 64 && strstr(eng, hx + 7) && strstr(eng, "yes")));
    CHECK(audit_dir(p) == 0);
}

/* ---- a wide key below the memory floor (the advisor, 01:2x): imdb_lookup_pk_at's lake search, the key normalized to
 * its columns' forms and the zone check passing over the wide column, which keeps no zone map. AS OF below the floor
 * scans the lake and never meets it; a transaction older than an eviction does, at its INSERT's duplicate check: a key
 * its view holds only in the lake is refused, keys it never held are taken, two of them sharing their low 64 bits with
 * a held one ---- */
static int exs(imdb_session *s, const char *sql)
{
    imdb_result r;
    imdb_err_clear(&g_e);
    int rc = imdb_exec_one(s, sql, strlen(sql), NULL, 0, &r, &g_e);
    if (!rc) imdb_result_free(&r);
    return rc;
}

static void t_dec38_old_txn(void)
{
    const char *dir = test_tmpdir();
    imdb_err e = {0};
    CHECK(imdb_init(dir, false, NULL, &e) == 0);
    imdb_db *db = open_with(dir, false, 0);
    CHECK(db);
    if (!db) return;
    imdb_session s2;
    imdb_session_init(&s2, db);
    OK(run("CREATE TABLE k (g INT64, w DECIMAL(38,2), v INT64, PRIMARY KEY (g, w))"));
    OK(run("INSERT INTO k VALUES (1, 18446744073709551616, 10), (1, -18446744073709551616, 11), (2, 18446744073709551616, 12)"));
    OK(run("CHECKPOINT"));
    CHECK(exs(&s2, "BEGIN") == 0 && exs(&s2, "SELECT v FROM k WHERE g = 1 AND w = 18446744073709551616") == 0); /* its snapshot */
    OK(run("UPDATE k SET v = 20 WHERE g = 1 AND w = 18446744073709551616"));
    OK(run("DELETE FROM k WHERE g = 1 AND w = -18446744073709551616"));
    OK(run("CHECKPOINT"));
    CHECK(imdb_evict(db, db->lake_seq, &e) == 0 && s2.txn.snap < db->mem_floor);
    CHECK(exs(&s2, "INSERT INTO k VALUES (1, -18446744073709551616, 77)") == IMDB_ERR_CONSTRAINT); /* in its view, the lake's alone */
    CHECK(exs(&s2, "INSERT INTO k VALUES (1, 0, 78)") == 0);                     /* the low half of a held key's */
    CHECK(exs(&s2, "INSERT INTO k VALUES (1, 36893488147419103232, 79)") == 0); /* 2^65: that low half too */
    CHECK(exs(&s2, "INSERT INTO k VALUES (2, -18446744073709551616, 80)") == 0); /* the deleted key's w, another g */
    CHECK(exs(&s2, "COMMIT") == 0);
    imdb_session_close(&s2);
    EXPECT("SELECT g, w, v FROM k ORDER BY g, w",
           "g,w,v\n1,0.00,78\n1,18446744073709551616.00,20\n1,36893488147419103232.00,79\n2,-18446744073709551616.00,80\n"
           "2,18446744073709551616.00,12\n");
    CHECK(verify_db(db) == 0);
    done(db);
    CHECK(audit_dir(dir) == 0);
}

/* ---- the copies: COPY both ways, a replica at the primary's digest, the dump restored ---- */
static void t_dec38_copies(void)
{
    const char *dir = test_tmpdir();
    char p[700], q[700], sf[700];
    snprintf(p, sizeof p, "%s/p", dir);
    snprintf(q, sizeof q, "%s/q", dir);
    snprintf(sf, sizeof sf, "%s/stream", dir);
    imdb_err e = {0};
    CHECK(imdb_init(p, false, NULL, &e) == 0 && imdb_init(q, true, p, &e) == 0);
    imdb_db *db = open_with(p, false, 0);
    CHECK(db);
    if (!db) return;
    OK(run("CREATE TABLE c (id DECIMAL(25,3) PRIMARY KEY, w DECIMAL(38,10), n DECIMAL(5,1))"));
    static const char data[] = "1234567890123456789012.125,9999999999999999999999999999.9999999999,1.5\n"
                               "-1234567890123456789012.125,-9999999999999999999999999999.9999999999,\n"
                               "0.000,,-9999.9\n"
                               "18446744073709551616.001,18446744073709551616.0000000001,0.0\n";
    g_in = (mem_in){data, sizeof data - 1, 0};
    EXPECT("COPY c FROM STDIN", "COPY 4");
    OK(run("CHECKPOINT"));
    OK(run("INSERT INTO c VALUES (5, 5, 5)"));
    g_copyn = 0;
    EXPECT("COPY (SELECT * FROM c ORDER BY id) TO STDOUT", "COPY 5");
    CHECK(!strcmp(g_copy, "-1234567890123456789012.125,-9999999999999999999999999999.9999999999,\n"
                          "0.000,,-9999.9\n"
                          "5.000,5.0000000000,5.0\n"
                          "18446744073709551616.001,18446744073709551616.0000000001,0.0\n"
                          "1234567890123456789012.125,9999999999999999999999999999.9999999999,1.5\n"));
    static const char bad[] = "1,99999999999999999999999999999.0,1\n"; /* 29 integer digits in DECIMAL(38,10)'s 28 */
    g_in = (mem_in){bad, sizeof bad - 1, 0};
    EXPECT("COPY c FROM STDIN", "ERR line 1");
    uint8_t dg[32];
    imdb_lthash_digest(db->meta.digest_alg, &db->global, dg);
    outb d1 = {0};
    OK(imdb_dump(db, 0, outb_write, &d1, &e));
    CHECK(verify_db(db) == 0);
    done(db);
    CHECK(audit_dir(p) == 0);
    OK(ship_to_file(p, 0, sf, &g_e));
    imdb_open_opts o = {.sync = 0};
    imdb_db *qdb = NULL;
    CHECK(imdb_open(q, &o, &qdb, &e) == 0);
    if (qdb) {
        uint64_t qa = 0;
        OK(apply_file(qdb, sf, &qa, &g_e));
        uint8_t qd[32];
        imdb_lthash_digest(qdb->meta.digest_alg, &qdb->global, qd);
        CHECK(memcmp(qd, dg, 32) == 0);
        imdb_close(qdb);
    }
    CHECK(audit_dir(q) == 0);
    char rd[700];
    snprintf(rd, sizeof rd, "%s/dumped", dir);
    dump_restored(&d1, rd); /* a wide key and wide values through the dump's COPY data */
    free(d1.p);
}

const test_case dec38_tests[] = {
    {"dec38_codec", t_dec38_codec},     {"dec38_model", t_dec38_model},   {"dec38_rules", t_dec38_rules},
    {"dec38_constraints", t_dec38_constraints}, {"dec38_alter_erase", t_dec38_alter_erase}, {"dec38_multikey", t_dec38_multikey},
    {"dec38_twin", t_dec38_twin}, {"dec38_audit_queries", t_dec38_audit_queries}, {"dec38_old_txn", t_dec38_old_txn},
    {"dec38_copies", t_dec38_copies},
};
const size_t dec38_ntests = sizeof dec38_tests / sizeof *dec38_tests;
