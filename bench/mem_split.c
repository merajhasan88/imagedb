/* Where imagedb's memory goes (docs/bench-2026-10-24.md): the head-to-head's workload in one
 * process (bench/whole.c's W1, W2, W2b, the checkpoint, W5's churn and W5b's delete churn, with the
 * index on id), by imdb_mem's kinds against the process's RSS. Sync off: memory does not depend
 * on it.
 *   mem_split DIR   (DIR must not exist) */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../src/db_internal.h"
#include "../src/sql.h"
static imdb_session s;
static imdb_err e;
static void ex(const char *q, const imdb_value *p, uint32_t np)
{
    imdb_result r;
    if (imdb_exec_one(&s, q, strlen(q), p, np, &r, &e)) { fprintf(stderr, "%s: %s\n", q, e.msg); exit(1); }
    imdb_result_free(&r);
}
static void ins(int64_t id, int64_t user, int64_t amount)
{
    static const char *memo = "a memo of a typical length for a row in this table";
    imdb_value p[4] = {{.type = IMDB_T_INT64, .i = id}, {.type = IMDB_T_INT64, .i = user}, {.type = IMDB_T_INT64, .i = amount},
                       {.type = IMDB_T_TEXT, .s = (const uint8_t *)memo, .len = (uint32_t)strlen(memo)}};
    ex("INSERT INTO t VALUES ($1, $2, $3, $4)", p, 4);
}
static long rss_kb(void)
{
    FILE *f = fopen("/proc/self/status", "r");
    char line[256];
    long kb = 0;
    while (f && fgets(line, sizeof line, f)) sscanf(line, "VmRSS: %ld kB", &kb);
    if (f) fclose(f);
    return kb;
}
static void report(imdb_db *db, const char *when)
{
    imdb_mem_report m;
    imdb_mem(db, &m);
    imdb_table *t = db->t[0];
    double n = (double)t->nver;
    printf("-- %s: %llu versions (%llu live), RSS %.1f MB, imdb_mem total %.1f MB = %.0f B per version\n", when,
           (unsigned long long)t->nver, (unsigned long long)t->live, rss_kb() / 1024.0, m.total / 1e6, m.total / n);
    printf("   versions %7.1f MB (%5.0f B/version)   rows %7.1f MB (%5.0f)   indexes %7.1f MB (%5.0f)\n", m.versions / 1e6,
           m.versions / n, m.rows / 1e6, m.rows / n, m.indexes / 1e6, m.indexes / n);
    printf("   segments %7.1f MB (%5.0f B/version)   commits %6.1f MB (%5.0f)   txns %6.1f MB\n", m.segments / 1e6,
           m.segments / n, m.commits / 1e6, m.commits / n, m.txns / 1e6);
}
int main(int argc, char **argv)
{
    if (argc != 2 || imdb_init(argv[1], false, NULL, &e)) return 1;
    imdb_open_opts o = {.sync = 0};
    imdb_db *db;
    if (imdb_open(argv[1], &o, &db, &e)) return 1;
    imdb_session_init(&s, db);
    printf("sizeof(imdb_version) = %zu B (the hot part), sizeof(imdb_version_cold) = %zu B, chunks of %llu versions\n",
           sizeof(imdb_version), sizeof(imdb_version_cold), (unsigned long long)IMDB_VCHUNK);
    ex("CREATE TABLE t (id INT64 PRIMARY KEY, user_id INT64 SUBJECT, amount INT64 NOT NULL, memo TEXT NOT NULL)", NULL, 0);
    ex("CREATE INDEX t_id ON t (id)", NULL, 0);
    for (int i = 0; i < 500; i++) ins(1000000 + i, i % 97, i);                         /* W1 */
    for (int k = 0; k < 1000; k++) {                                                    /* W2 */
        ex("BEGIN", NULL, 0);
        for (int i = 0; i < 100; i++) { int64_t id = (int64_t)k * 100 + i + 1; ins(id, id % 97, id); }
        ex("COMMIT", NULL, 0);
    }
    for (int k = 0; k < 5; k++) {                                                       /* W2b */
        ex("BEGIN", NULL, 0);
        for (int i = 0; i < 10000; i++) { int64_t id = 5000000 + (int64_t)k * 10000 + i; ins(id, id % 97, id); }
        ex("COMMIT", NULL, 0);
    }
    report(db, "after the load");
    ex("CHECKPOINT", NULL, 0);
    report(db, "after the checkpoint");
    for (int r = 0; r < 5; r++)                                                         /* W5 */
        for (int k = 0; k < 100; k++) {
            int64_t lo = (int64_t)k * 1000 + 1;
            imdb_value p[3] = {{.type = IMDB_T_INT64, .i = r}, {.type = IMDB_T_INT64, .i = lo}, {.type = IMDB_T_INT64, .i = lo + 999}};
            ex("BEGIN", NULL, 0);
            ex("UPDATE t SET amount = $1 WHERE id BETWEEN $2 AND $3", p, 3);
            ex("COMMIT", NULL, 0);

        }
    report(db, "after the churn (500,000 updates)");
    for (int k = 0; k < 50; k++) {                                                      /* W5b */
        int64_t lo = (int64_t)k * 1000 + 1;
        imdb_value p[2] = {{.type = IMDB_T_INT64, .i = lo}, {.type = IMDB_T_INT64, .i = lo + 999}};
        ex("BEGIN", NULL, 0);
        ex("DELETE FROM t WHERE id BETWEEN $1 AND $2", p, 2);
        ex("COMMIT", NULL, 0);
        ex("BEGIN", NULL, 0);
        for (int64_t id = lo; id <= lo + 999; id++) ins(id, id % 97, id);
        ex("COMMIT", NULL, 0);

    }
    report(db, "after the delete churn");
    imdb_session_close(&s);
    imdb_close(db);
    return 0;
}
