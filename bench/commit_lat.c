/* What a durable commit costs, one at a time, measured through the engine (preallocated log
 * segments, docs/commit-speed.md §1; the same source builds against the tree before them):
 *   commit_lat MODE DIR N K   N rows in transactions of K. MODE sync: each commit waits for its flush;
 *                             durable-ack: and for the watermark's fsync; nosync: the close syncs. One-row
 *                             synchronous commits get a CHECKPOINT halfway, so the next commit makes a
 *                             segment (a rotation); the worst commit's wall-clock time is printed (devstall)
 * DIR is made anew. Then the database is reopened, timed. One line per measure:
 * "commit_lat case metric value unit". */
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>

#include "db.h" /* -I src: built against either tree (the one before tagged segments too) */
#include "lake.h"

static double now(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

static int cmp_d(const void *a, const void *b)
{
    double x = *(const double *)a, y = *(const double *)b;
    return x < y ? -1 : x > y;
}

static void schema(imdb_schema *s)
{
    memset(s, 0, sizeof *s);
    strcpy(s->name, "txns");
    s->ncols = 4;
    strcpy(s->cols[0].name, "id");
    s->cols[0].type = IMDB_T_INT64;
    s->cols[0].flags = IMDB_COL_PK;
    strcpy(s->cols[1].name, "user_id");
    s->cols[1].type = IMDB_T_INT64;
    s->cols[1].flags = IMDB_COL_SUBJECT;
    strcpy(s->cols[2].name, "amount");
    s->cols[2].type = IMDB_T_DECIMAL;
    s->cols[2].precision = 12;
    s->cols[2].scale = 2;
    strcpy(s->cols[3].name, "memo");
    s->cols[3].type = IMDB_T_TEXT;
    s->pk = 0;
    s->subject = 1;
}

/* the log's files: their bytes and how many */
static void log_bytes(const char *dir, unsigned long long *bytes, int *segs)
{
    char p[1100];
    snprintf(p, sizeof p, "%s/log", dir);
    DIR *d = opendir(p);
    *bytes = 0;
    *segs = 0;
    struct dirent *de;
    while (d && (de = readdir(d))) {
        if (de->d_name[0] == '.') continue;
        char f[1400];
        snprintf(f, sizeof f, "%s/%s", p, de->d_name);
        struct stat st;
        if (stat(f, &st) == 0) {
            *bytes += (unsigned long long)st.st_size;
            (*segs)++;
        }
    }
    if (d) closedir(d);
}

static int die(const char *what, const imdb_err *e)
{
    fprintf(stderr, "commit_lat: %s: %s\n", what, e->msg);
    return 1;
}

int main(int argc, char **argv)
{
    if (argc != 5 || (strcmp(argv[1], "sync") && strcmp(argv[1], "durable-ack") && strcmp(argv[1], "nosync"))) {
        fprintf(stderr, "usage: commit_lat sync|durable-ack|nosync DIR N K   (N rows, K a transaction)\n");
        return 2;
    }
    const char *what = argv[1], *dir = argv[2];
    bool nosync = !strcmp(what, "nosync");
    long n = atol(argv[3]), k = atol(argv[4]) > 0 ? atol(argv[4]) : 1;
    char cmd[1200];
    snprintf(cmd, sizeof cmd, "rm -rf '%s'", dir);
    if (system(cmd) != 0) return 1;
    imdb_err e = {0};
    if (imdb_init(dir, false, NULL, &e)) return die("init", &e);
    imdb_open_opts o = {.sync = nosync ? 0 : 1, .durable_ack = !strcmp(what, "durable-ack"), .checkpoint_bytes = UINT64_MAX};
    imdb_db *db;
    if (imdb_open(dir, &o, &db, &e)) return die("open", &e);
    imdb_schema sc;
    schema(&sc);
    if (imdb_begin(db, &e) || imdb_create_table(db, &sc, &e) || imdb_commit(db, &e)) return die("create", &e);
    imdb_table *t = imdb_table_by_name(db, "txns");
    imdb_value v[4] = {{.type = IMDB_T_INT64}, {.type = IMDB_T_INT64}, {.type = IMDB_T_DECIMAL, .scale = 2},
                       {.type = IMDB_T_TEXT, .s = (const uint8_t *)"card payment", .len = 12}};
    double *lat = malloc(sizeof *lat * (size_t)(n / k + 1)), after_rot = 0, ckpt = 0, t0 = now(), worst = 0;
    struct timespec worst_at = {0, 0};
    long nc = 0;
    for (long i = 0; i < n; i += k, nc++) {
        if (!nosync && k == 1 && i == n / 2) { /* a CHECKPOINT ends the segment: the next commit makes one */
            double c0 = now();
            if (imdb_checkpoint(db, &e)) return die("checkpoint", &e);
            ckpt = now() - c0;
        }
        double c0 = now();
        if (imdb_begin(db, &e)) return die("begin", &e);
        for (long j = i; j < i + k && j < n; j++) {
            v[0].i = j;
            v[1].i = j % 1000;
            v[2].i = j * 37 % 100000;
            if (imdb_insert(db, t, v, &e)) return die("insert", &e);
        }
        if (imdb_commit(db, &e)) return die("commit", &e);
        lat[nc] = now() - c0;
        if (lat[nc] > worst) { /* when, by the wall clock, to match the lines bench/devstall prints */
            worst = lat[nc];
            clock_gettime(CLOCK_REALTIME, &worst_at);
        }
        if (!nosync && k == 1 && i == n / 2) after_rot = lat[nc];
    }
    double total = now() - t0;
    double c0 = now();
    imdb_close(db);
    double close_s = now() - c0;
    unsigned long long bytes;
    int segs;
    log_bytes(dir, &bytes, &segs);
    printf("commit_lat %s rows_per_s %.0f rows/s\n", what, (double)n / total);
    printf("commit_lat %s close %.1f ms\n", what, close_s * 1e3);
    if (!nosync) {
        double sum = 0;
        long over5 = 0, over10 = 0;
        for (long i = 0; i < nc; i++) {
            sum += lat[i];
            over5 += lat[i] > 5e-3;
            over10 += lat[i] > 10e-3;
        }
        if (k == 1) printf("commit_lat %s after_rotation %.0f us\n", what, after_rot * 1e6);
        if (k == 1) printf("commit_lat %s checkpoint %.1f ms\n", what, ckpt * 1e3);
        qsort(lat, (size_t)nc, sizeof *lat, cmp_d);
        printf("commit_lat %s commits %ld\n", what, nc);
        printf("commit_lat %s mean %.0f us\n", what, sum / (double)nc * 1e6);
        static const struct {
            const char *name;
            double q;
        } qs[] = {{"p50", 0.50}, {"p90", 0.90}, {"p99", 0.99}, {"p99.9", 0.999}};
        for (size_t i = 0; i < sizeof qs / sizeof *qs; i++)
            printf("commit_lat %s %s %.0f us\n", what, qs[i].name, lat[(size_t)((double)nc * qs[i].q)] * 1e6);
        printf("commit_lat %s max %.0f us\n", what, lat[nc - 1] * 1e6);
        struct tm tm;
        localtime_r(&worst_at.tv_sec, &tm);
        printf("commit_lat %s worst_at %02d:%02d:%02d.%03ld\n", what, tm.tm_hour, tm.tm_min, tm.tm_sec, worst_at.tv_nsec / 1000000);
        printf("commit_lat %s over_5ms %ld\n", what, over5);
        printf("commit_lat %s over_10ms %ld\n", what, over10);
    }
    printf("commit_lat %s log_bytes %llu bytes\n", what, bytes);
    printf("commit_lat %s log_segments %d\n", what, segs);
    imdb_open_opts ro = {.sync = 1, .checkpoint_bytes = UINT64_MAX};
    c0 = now();
    if (imdb_open(dir, &ro, &db, &e)) return die("reopen", &e);
    printf("commit_lat %s reopen %.1f ms\n", what, (now() - c0) * 1e3);
    imdb_close(db);
    free(lat);
    return 0;
}
