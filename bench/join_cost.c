/* The join planner's costs measured (sql_exec.c join_choose, design.md §5 Joins): a row of the hash
 * join's build side and of its probe side, and an outer row of plan C through a primary key and
 * through an index (one match, then ten), each against the vectorised scan's row (COST_VEC). Rows in
 * segments (after a CHECKPOINT), cross_check off; each statement REPS times, the median, its plan and
 * its answer checked. Only the ratios are used.
 *   join_cost DIR   (DIR must not exist; sync off: the loads are not what it measures) */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "../src/db_internal.h"
#include "../src/sql.h"
enum { N = 100000, REPS = 15, BATCH = 500 };
static imdb_session s;
static imdb_err e;
static double now(void) { struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t); return t.tv_sec + t.tv_nsec / 1e9; }
static int ex(const char *q)
{
    imdb_result r;
    if (imdb_exec_one(&s, q, strlen(q), NULL, 0, &r, &e)) { fprintf(stderr, "%s: %s\n", q, e.msg); return 1; }
    imdb_result_free(&r);
    return 0;
}
static int cmp_d(const void *a, const void *b)
{
    double x = *(const double *)a, y = *(const double *)b;
    return x < y ? -1 : x > y;
}
/* the median time of q, whose path must start with path and whose one cell must be want */
static double med(const char *q, const char *path, int64_t want)
{
    static double t[REPS];
    for (int i = 0; i < REPS; i++) {
        imdb_result r;
        double a = now();
        if (imdb_exec_one(&s, q, strlen(q), NULL, 0, &r, &e)) { fprintf(stderr, "%s: %s\n", q, e.msg); exit(1); }
        t[i] = now() - a;
        int64_t got = r.nrows == 1 ? (r.cells[0].wide ? (int64_t)r.cells[0].i128 : r.cells[0].v.i) : -1;
        /* a cross-checked statement would time both plans; its name still starts with the first */
        if (strncmp(r.path, path, strlen(path)) != 0 || strstr(r.path, "cross-checked") || got != want) {
            fprintf(stderr, "%s: [%s] %lld, want [%s] %lld\n", q, r.path, (long long)got, path, (long long)want);
            exit(1);
        }
        if (i == 0) printf("[%s] %s\n", r.path, q);
        imdb_result_free(&r);
    }
    qsort(t, REPS, sizeof *t, cmp_d);
    return t[REPS / 2];
}
/* n rows into tb from the row formula: id, id, id / 10, id % 1000 */
static int load(const char *tb, int n)
{
    static char q[BATCH * 48 + 64];
    for (int b = 0; b < n / BATCH; b++) {
        size_t len = (size_t)snprintf(q, sizeof q, "INSERT INTO %s VALUES ", tb);
        for (int i = b * BATCH + 1; i <= (b + 1) * BATCH; i++)
            len += (size_t)snprintf(q + len, sizeof q - len, "%s(%d, %d, %d, %d)", i > b * BATCH + 1 ? ", " : "", i, i, i / 10, i % 1000);
        if (ex(q)) return 1;
    }
    return 0;
}
int main(int argc, char **argv)
{
    if (argc != 2) { fprintf(stderr, "usage: join_cost DIR (a new directory)\n"); return 2; }
    imdb_db *db = NULL;
    imdb_open_opts o = {.sync = 0};
    if (imdb_init(argv[1], false, NULL, &e) || imdb_open(argv[1], &o, &db, &e)) { fprintf(stderr, "%s\n", e.msg); return 1; }
    imdb_session_init(&s, db);
    s.cross_check = false;
    if (ex("CREATE TABLE a (id INT64 PRIMARY KEY, k INT64, m INT64, v INT64)") ||
        ex("CREATE TABLE b (id INT64 PRIMARY KEY, k INT64, m INT64, v INT64)") || ex("CREATE INDEX b_k ON b (k)") ||
        ex("CREATE INDEX b_m ON b (m)") || load("a", N) || load("b", N) || ex("CHECKPOINT"))
        return 1;
    int64_t vsum = 0;
    for (int i = 1; i <= N; i++) vsum += i % 1000;

    double scan = med("SELECT SUM(v) FROM a WHERE v >= 0", "scan", vsum) / N;
    s.join_plan = IMDB_JOIN_HASH;
    double build = med("SELECT COUNT(*) FROM a JOIN b ON a.k = b.k WHERE a.id = 1", "join(build 2)", 1) / N;
    double hprobe = med("SELECT COUNT(*) FROM a JOIN b ON a.k = b.k WHERE b.id = 1", "join(build 2)", 1) / N;
    s.join_plan = IMDB_JOIN_INDEX;
    double pk = med("SELECT COUNT(*) FROM a JOIN b ON a.k = b.id", "join(index 2)", N) / N;
    double ord1 = med("SELECT COUNT(*) FROM a JOIN b ON a.k = b.k", "join(index 2)", N) / N;
    /* m = id / 10: each row of a matches about ten of b (the ends fewer), read whole as for ord1 */
    static int64_t per[N / 10 + 1];
    int64_t pairs = 0;
    for (int i = 1; i <= N; i++) per[i / 10]++;
    for (int m = 0; m <= N / 10; m++) pairs += per[m] * per[m];
    double ord10 = med("SELECT COUNT(*) FROM a JOIN b ON a.m = b.m", "join(index 2)", pairs) / N;
    double cand = (ord10 - ord1) / ((double)pairs / N - 1);
    printf("per row, ns: scan %.2f; hash build %.1f, hash probe %.1f; plan C: primary key %.1f, index %.1f, index of ten %.1f "
           "(a candidate %.1f)\n",
           scan * 1e9, build * 1e9, hprobe * 1e9, pk * 1e9, ord1 * 1e9, ord10 * 1e9, cand * 1e9);
    printf("in scanned rows: COST_JBUILD %.0f, COST_JHPROBE %.0f, COST_JPK %.0f, COST_JORD %.0f, COST_JCAND %.0f\n", build / scan,
           hprobe / scan, pk / scan, ord1 / scan, cand / scan);
    imdb_session_close(&s);
    imdb_close(db);
    return 0;
}
