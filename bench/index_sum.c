/* CREATE INDEX measured (docs/bench-2026-10-23.md, the addendum of 2026-10-24): R8 finding 4's range SUM
 * before and after a checkpoint, without and with an index; the build, its memory, the open.
 * Same rows, ranges and statement text as bench/whole.c's W1, W2, W2b and W4; p50/p95/p99 as R8.
 *   index_sum DIR   (DIR must not exist; sync off: the loads are not what it measures) */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "../src/db_internal.h"
#include "../src/sql.h"
enum { SUMS = 1000 };
static imdb_session s;
static imdb_err e;
static double now(void) { struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t); return t.tv_sec + t.tv_nsec / 1e9; }
static int ex(const char *q, const imdb_value *p, uint32_t np, imdb_result *out)
{
    imdb_result r;
    if (imdb_exec_one(&s, q, strlen(q), p, np, &r, &e)) { fprintf(stderr, "%s: %s\n", q, e.msg); return 1; }
    if (out) *out = r; else imdb_result_free(&r);
    return 0;
}
static int ins(int64_t id, int64_t user, int64_t amount)
{
    static const char *memo = "a memo of a typical length for a row in this table";
    imdb_value p[4] = {{.type = IMDB_T_INT64, .i = id}, {.type = IMDB_T_INT64, .i = user}, {.type = IMDB_T_INT64, .i = amount},
                       {.type = IMDB_T_TEXT, .s = (const uint8_t *)memo, .len = (uint32_t)strlen(memo)}};
    return ex("INSERT INTO t VALUES ($1, $2, $3, $4)", p, 4, NULL);
}
static int cmp_d(const void *a, const void *b)
{
    double x = *(const double *)a, y = *(const double *)b;
    return x < y ? -1 : x > y;
}
/* the 1,000 SUMs; got[i] gets each answer (these sums fit in 64 bits), checked against its closed form:
 * amount = id for ids 1..100,000 (W1's ids, from 1,000,000, are never in a range) */
static int sums(const char *label, int64_t *got)
{
    static double lat[SUMS];
    char path[64] = "";
    int ordered = 0;
    double t0 = now();
    for (int i = 0; i < SUMS; i++) {
        int64_t lo = (int64_t)(i * 487) % (100000 - 1000) + 1;
        imdb_value p[2] = {{.type = IMDB_T_INT64, .i = lo}, {.type = IMDB_T_INT64, .i = lo + 999}};
        imdb_result r;
        double a = now();
        if (ex("SELECT SUM(amount) FROM t WHERE id BETWEEN $1 AND $2", p, 2, &r)) return 1;
        lat[i] = now() - a;
        if (r.nrows != 1 || r.ncols != 1) { fprintf(stderr, "unexpected result shape\n"); return 1; }
        got[i] = r.cells[0].wide ? (int64_t)r.cells[0].i128 : r.cells[0].v.i;
        if (got[i] != 1000 * lo + 499500) { fprintf(stderr, "sum %d is wrong\n", i); return 1; }
        if (strstr(r.path, "index(ordered")) ordered++; /* either kind */
        if (i == 0) snprintf(path, sizeof path, "%s", r.path);
        imdb_result_free(&r);
    }
    double mean = (now() - t0) / SUMS;
    qsort(lat, SUMS, sizeof *lat, cmp_d);
    printf("%-24s p50 %9.1f us, p95 %9.1f, p99 %9.1f, mean %9.1f; path %s (index(ordered) %d of %d)\n", label, lat[SUMS / 2] * 1e6,
           lat[SUMS * 95 / 100] * 1e6, lat[SUMS * 99 / 100] * 1e6, mean * 1e6, path, ordered, SUMS);
    return 0;
}
/* the median of five opens and closes, in ms */
static double opens(const char *dir, const imdb_open_opts *o)
{
    double t[5];
    for (int i = 0; i < 5; i++) {
        imdb_db *db;
        double a = now();
        if (imdb_open(dir, o, &db, &e)) return -1;
        t[i] = now() - a;
        imdb_close(db);
    }
    qsort(t, 5, sizeof *t, cmp_d);
    return t[2] * 1e3;
}
/* N SUMs over all of W2's 100,000 ids: the cost rule's case (sql_exec.c scan_cheaper; before it, the
 * planner took a matching index whatever the range) */
static int wide(const char *label, int n)
{
    double t[20];
    char path[64] = "";
    for (int i = 0; i < n; i++) {
        imdb_value p[2] = {{.type = IMDB_T_INT64, .i = 1}, {.type = IMDB_T_INT64, .i = 100000}};
        imdb_result r;
        double a = now();
        if (ex("SELECT SUM(amount) FROM t WHERE id BETWEEN $1 AND $2", p, 2, &r)) return 1;
        t[i] = now() - a;
        int64_t got = r.cells[0].wide ? (int64_t)r.cells[0].i128 : r.cells[0].v.i;
        if (got != 5000050000) { fprintf(stderr, "wide sum is wrong\n"); return 1; }
        snprintf(path, sizeof path, "%s", r.path);
        imdb_result_free(&r);
    }
    qsort(t, (size_t)n, sizeof *t, cmp_d);
    printf("%-26s p50 %9.1f us; path %s\n", label, t[n / 2] * 1e6, path);
    return 0;
}
static uint64_t mem_indexes(imdb_db *db, uint64_t *total)
{
    imdb_mem_report m;
    imdb_mem(db, &m);
    *total = m.total;
    return m.indexes;
}
int main(int argc, char **argv)
{
    static int64_t a[SUMS], b[SUMS];
    if (argc != 2 || imdb_init(argv[1], false, NULL, &e)) return 1;
    imdb_open_opts o = {.sync = 0};
    imdb_db *db;
    if (imdb_open(argv[1], &o, &db, &e)) return 1;
    imdb_session_init(&s, db);
    if (ex("CREATE TABLE t (id INT64 PRIMARY KEY, user_id INT64 SUBJECT, amount INT64, memo TEXT)", NULL, 0, NULL)) return 1;
    for (int64_t i = 0; i < 500; i++) if (ins(1000000 + i, i % 97, i)) return 1;                  /* W1 */
    for (int64_t k = 0; k < 1000; k++) {                                                    /* W2 */
        if (ex("BEGIN", NULL, 0, NULL)) return 1;
        for (int64_t i = 0; i < 100; i++) if (ins(k * 100 + i + 1, (k * 100 + i + 1) % 97, k * 100 + i + 1)) return 1;
        if (ex("COMMIT", NULL, 0, NULL)) return 1;
    }
    for (int64_t k = 0; k < 5; k++) {                                                       /* W2b */
        if (ex("BEGIN", NULL, 0, NULL)) return 1;
        for (int64_t i = 0; i < 10000; i++) { int64_t id = 5000000 + k * 10000 + i; if (ins(id, id % 97, id)) return 1; }
        if (ex("COMMIT", NULL, 0, NULL)) return 1;
    }
    printf("rows: %llu versions, no checkpoint\n", (unsigned long long)db->t[0]->nver);
    if (sums("range SUM, no index", a)) return 1;
    uint64_t tot0, ix0 = mem_indexes(db, &tot0);
    double t0 = now();
    if (ex("CREATE INDEX t_id ON t (id)", NULL, 0, NULL)) return 1;
    double build = now() - t0;
    uint64_t tot1, ix1 = mem_indexes(db, &tot1);
    printf("CREATE INDEX t_id: %.1f ms; memory: indexes %.2f -> %.2f MB, total %.2f -> %.2f MB (+%.1f bytes per row)\n",
           build * 1e3, ix0 / 1e6, ix1 / 1e6, tot0 / 1e6, tot1 / 1e6, (double)(tot1 - tot0) / db->t[0]->nver);
    if (sums("range SUM, index on id", b)) return 1;
    for (int i = 0; i < SUMS; i++)
        if (a[i] != b[i]) { fprintf(stderr, "sum %d differs: %lld vs %lld\n", i, (long long)a[i], (long long)b[i]); return 1; }
    printf("the 1,000 answers agree, and each is 1000 * lo + 499500\n");
    if (wide("in memory, 100k ids, auto", 20)) return 1;
    if (ex("SET access_path = scan", NULL, 0, NULL)) return 1;
    if (wide("in memory, 100k ids, scan", 20)) return 1;
    if (ex("SET access_path = auto", NULL, 0, NULL)) return 1;
    imdb_session_close(&s);
    imdb_close(db);
    printf("open with the index (log replay + build), median of 5: %.1f ms\n", opens(argv[1], &o));
    if (imdb_open(argv[1], &o, &db, &e)) return 1;
    imdb_session_init(&s, db);
    if (ex("DROP INDEX t_id", NULL, 0, NULL)) return 1;
    imdb_session_close(&s);
    imdb_close(db);
    printf("open without it (log replay), median of 5:          %.1f ms\n", opens(argv[1], &o));
    /* after a checkpoint: the lake scan (R8: 0.21 ms) against the index, which the planner prefers */
    if (imdb_open(argv[1], &o, &db, &e)) return 1;
    imdb_session_init(&s, db);
    if (ex("CHECKPOINT", NULL, 0, NULL)) return 1;
    if (sums("checkpointed, no index", a)) return 1;
    if (ex("CREATE INDEX t_id ON t (id)", NULL, 0, NULL)) return 1;
    if (sums("checkpointed, index on id", b)) return 1;
    if (ex("SET access_path = scan", NULL, 0, NULL)) return 1;
    if (sums("checkpointed, index, scan", a)) return 1;
    if (wide("checkpointed, 100k ids, scan", 20)) return 1;
    if (ex("SET access_path = auto", NULL, 0, NULL)) return 1;
    if (wide("checkpointed, 100k ids, auto", 20)) return 1;
    imdb_session_close(&s);
    imdb_close(db);
    return 0;
}
