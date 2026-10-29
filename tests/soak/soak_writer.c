/* The soak test's writer (soak.sh): one open, then churn over a fixed live set until its time is up
 * or it is killed. Every statement that commits appends "seq head" to the acknowledgement file with
 * one write(2), so a SIGKILL never loses an acknowledged line; at its start a churn run checks that
 * the last acknowledged commit survived the kill with its hash (exit 3 if not). Every 10 s it appends
 * a stats line: seconds, commits, the engine's memory report (imdb_mem) and the process's RSS.
 *   soak_writer DIR load LIVE ACKS [--retention SECONDS]
 *   soak_writer DIR churn LIVE SECONDS SEED ACKS STATS [--nosync] [--checkpoint N] [--erase N]
 *                                                      [--events FILE]
 * The live set: ids 1..LIVE, a SUBJECT among LIVE/10 people (id % people), a memo of 16-200 bytes; the table
 * keeps its history --retention seconds (its RETENTION; the engine's default when absent), past which the
 * engine expires it and retires it, log segments included (stage 3a).
 * Churn, from a seeded generator: an UPDATE of a random id (85%), a DELETE and re-INSERT of one in a
 * transaction (10%), a transaction of ten UPDATEs (5%); a CHECKPOINT each time the log's sequence passes a
 * multiple of N (--checkpoint, 50,000; the engine checkpoints on its own too), and at each multiple of N
 * (--erase, 20,000; 0: never) an ERASE SUBJECT of a random person, their rows inserted again in one
 * transaction. The sequence, not this run's statements: a run lasts one kill interval, far fewer
 * statements than N, so a count that starts again at each restart never fired (the 10-27 baseline).
 * --events appends "erase|checkpoint start SEQ" before each and "... done SEQ SECONDS" after it, and "open
 * done SEQ SECONDS" at a churn run's start (the engine's open: the recovery a restart costs), one write(2)
 * each, so soak.sh counts the ones that ran, the ones a kill cut short, and the reopen times. */
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "../../src/db.h"
#include "../../src/sql.h"

static uint64_t rng;
static uint64_t next(void) /* xorshift64* */
{
    rng ^= rng >> 12;
    rng ^= rng << 25;
    rng ^= rng >> 27;
    return rng * 2685821657736338717ull;
}

static double now(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + ts.tv_nsec / 1e9;
}

static void memo(char *out) /* 16-200 lowercase letters */
{
    int n = 16 + (int)(next() % 185);
    for (int i = 0; i < n; i++) out[i] = (char)('a' + next() % 26);
    out[n] = 0;
}

static int append_line(int fd, const char *line)
{
    size_t n = strlen(line);
    return write(fd, line, n) == (ssize_t)n ? 0 : -1;
}

static int ack(int fd, imdb_db *db, uint64_t *last)
{
    if (db->seq == *last) return 0; /* nothing committed (an UPDATE that matched no row) */
    char hex[65], line[100];
    imdb_hex(db->head, 32, hex);
    snprintf(line, sizeof line, "%llu %s\n", (unsigned long long)db->seq, hex);
    *last = db->seq;
    return append_line(fd, line);
}

static int event(int fd, const char *what, uint64_t seq, double secs) /* an --events line (secs < 0: a start) */
{
    if (fd < 0) return 0;
    char line[100];
    if (secs < 0) snprintf(line, sizeof line, "%s start %llu\n", what, (unsigned long long)seq);
    else snprintf(line, sizeof line, "%s done %llu %.3f\n", what, (unsigned long long)seq, secs);
    return append_line(fd, line);
}

static int run(imdb_session *s, const char *sql)
{
    imdb_result r;
    imdb_err e = {0};
    if (imdb_exec_one(s, sql, strlen(sql), NULL, 0, &r, &e)) {
        fprintf(stderr, "soak_writer: %.60s: %s\n", sql, e.msg);
        return -1;
    }
    imdb_result_free(&r);
    return 0;
}

static long rss_kb(void)
{
    FILE *f = fopen("/proc/self/status", "r");
    char line[256];
    long kb = -1;
    while (f && fgets(line, sizeof line, f))
        if (strncmp(line, "VmRSS:", 6) == 0) kb = atol(line + 6);
    if (f) fclose(f);
    return kb;
}

/* the last "seq head" line of the acknowledgement file (0 when it has none) */
static uint64_t last_ack(const char *path, char hex[65])
{
    FILE *f = fopen(path, "r");
    char line[200];
    uint64_t seq = 0;
    hex[0] = 0;
    while (f && fgets(line, sizeof line, f)) {
        unsigned long long q;
        char h[65];
        size_t len = strlen(line); /* a whole line only: one write(2) each, but be strict anyway */
        if (len && line[len - 1] == '\n' && sscanf(line, "%llu %64s", &q, h) == 2 && strlen(h) == 64) {
            seq = q;
            memcpy(hex, h, 65);
        }
    }
    if (f) fclose(f);
    return seq;
}

int main(int argc, char **argv)
{
    if (argc < 5) {
        fprintf(stderr, "usage: soak_writer DIR load LIVE ACKS [--retention SECONDS] | DIR churn LIVE SECONDS SEED ACKS "
                        "STATS [--nosync] [--checkpoint N] [--erase N] [--events FILE]\n");
        return 2;
    }
    const char *dir = argv[1];
    bool load = strcmp(argv[2], "load") == 0;
    long live = atol(argv[3]), people = live / 10 > 0 ? live / 10 : 1;
    if (!load && (strcmp(argv[2], "churn") != 0 || argc < 8)) return 2;
    double seconds = load ? 0 : atof(argv[4]);
    const char *acks = load ? argv[4] : argv[6], *stats = load ? NULL : argv[7];
    imdb_open_opts o = {.sync = 1};
    uint64_t every_ckpt = 50000, every_erase = 20000;
    const char *events = NULL;
    long retention = 0; /* the table's RETENTION in seconds (load; 0: the engine's default) */
    for (int i = load ? 5 : 8; i < argc; i++) {
        if (load) {
            if (strcmp(argv[i], "--retention") == 0 && i + 1 < argc && (retention = atol(argv[++i])) > 0) continue;
            return 2;
        }
        if (strcmp(argv[i], "--nosync") == 0) o.sync = 0;
        else if (strcmp(argv[i], "--checkpoint") == 0 && i + 1 < argc) every_ckpt = strtoull(argv[++i], NULL, 10);
        else if (strcmp(argv[i], "--erase") == 0 && i + 1 < argc) every_erase = strtoull(argv[++i], NULL, 10);
        else if (strcmp(argv[i], "--events") == 0 && i + 1 < argc) events = argv[++i];
        else return 2;
    }
    rng = load ? 1 : strtoull(argv[5], NULL, 10) * 2654435761u + 1;
    imdb_db *db;
    imdb_err e = {0};
    double topen = now();
    if (imdb_open(dir, &o, &db, &e)) {
        fprintf(stderr, "soak_writer: open: %s\n", e.msg);
        return 1;
    }
    double open_s = now() - topen; /* the recovery a restart costs: the engine's open alone, not the checks after it */
    char want[65];
    uint64_t acked = last_ack(acks, want);
    if (!load && acked) { /* the kill must not have taken an acknowledged commit, nor changed it */
        imdb_err e2 = {0};
        const imdb_commit_info *ci = acked <= db->seq ? imdb_ci_at(db, acked, &e2) : NULL;
        char got[65] = "";
        if (ci) imdb_hex(ci->hash, 32, got);
        if (!ci || strcmp(got, want) != 0) {
            fprintf(stderr, "soak_writer: LOST: acknowledged commit %llu (%s) is %s after the reopen (log at %llu)\n",
                    (unsigned long long)acked, want, ci ? "changed" : "missing", (unsigned long long)db->seq);
            imdb_close(db);
            return 3;
        }
    }
    int afd = open(acks, O_WRONLY | O_APPEND | O_CREAT | O_CLOEXEC, 0644);
    int efd = events ? open(events, O_WRONLY | O_APPEND | O_CREAT | O_CLOEXEC, 0644) : -1;
    FILE *sf = stats ? fopen(stats, "a") : NULL;
    if (afd < 0 || (events && efd < 0) || (stats && !sf)) {
        fprintf(stderr, "soak_writer: %s: %s\n", afd < 0 ? acks : events && efd < 0 ? events : stats, strerror(errno));
        return 1;
    }
    imdb_session s;
    imdb_session_init(&s, db);
    uint64_t last = db->seq;
    int rc = load ? 0 : event(efd, "open", db->seq, open_s);
    char sql[512], m[256];
    if (load) {
        char ct[160];
        if (retention)
            snprintf(ct, sizeof ct, "CREATE TABLE t (id INT64 PRIMARY KEY, user_id INT64 SUBJECT, memo TEXT) RETENTION %ld SECONDS",
                     retention);
        else
            snprintf(ct, sizeof ct, "CREATE TABLE t (id INT64 PRIMARY KEY, user_id INT64 SUBJECT, memo TEXT)");
        rc = run(&s, ct) || ack(afd, db, &last);
        for (long id = 1; id <= live && !rc; id += 1000) {
            rc = run(&s, "BEGIN");
            for (long k = id; k < id + 1000 && k <= live && !rc; k++) {
                memo(m);
                snprintf(sql, sizeof sql, "INSERT INTO t VALUES (%ld, %ld, '%s')", k, k % people, m);
                rc = run(&s, sql);
            }
            rc = rc || run(&s, "COMMIT") || ack(afd, db, &last);
        }
    } else {
        double t0 = now(), next_stats = t0;
        /* the multiple of N the sequence last passed: a restart neither repeats one nor waits N again */
        uint64_t erase_mark = every_erase ? db->seq / every_erase : 0, ckpt_mark = every_ckpt ? db->seq / every_ckpt : 0;
        while (!rc && now() - t0 < seconds) {
            long k = 1 + (long)(next() % (uint64_t)live);
            uint64_t p = next() % 100;
            if (every_erase && db->seq / every_erase > erase_mark) { /* a person erased, then their rows again */
                erase_mark = db->seq / every_erase;
                long who = (long)(next() % (uint64_t)people);
                double ts = now();
                snprintf(sql, sizeof sql, "ERASE SUBJECT %ld", who);
                rc = event(efd, "erase", db->seq, -1) || run(&s, sql) || ack(afd, db, &last) ||
                     event(efd, "erase", db->seq, now() - ts) || run(&s, "BEGIN");
                for (long id = who ? who : people; id <= live && !rc; id += people) {
                    memo(m);
                    snprintf(sql, sizeof sql, "INSERT INTO t VALUES (%ld, %ld, '%s')", id, who, m);
                    rc = run(&s, sql);
                }
                rc = rc || run(&s, "COMMIT");
            } else if (every_ckpt && db->seq / every_ckpt > ckpt_mark) {
                ckpt_mark = db->seq / every_ckpt;
                double ts = now();
                rc = event(efd, "checkpoint", db->seq, -1) || run(&s, "CHECKPOINT") ||
                     event(efd, "checkpoint", db->seq, now() - ts);
            } else if (p < 85) {
                memo(m);
                snprintf(sql, sizeof sql, "UPDATE t SET memo = '%s' WHERE id = %ld", m, k);
                rc = run(&s, sql);
            } else if (p < 95) {
                memo(m);
                rc = run(&s, "BEGIN");
                snprintf(sql, sizeof sql, "DELETE FROM t WHERE id = %ld", k);
                rc = rc || run(&s, sql);
                snprintf(sql, sizeof sql, "INSERT INTO t VALUES (%ld, %ld, '%s')", k, k % people, m);
                rc = rc || run(&s, sql) || run(&s, "COMMIT");
            } else {
                rc = run(&s, "BEGIN");
                for (int j = 0; j < 10 && !rc; j++) {
                    memo(m);
                    snprintf(sql, sizeof sql, "UPDATE t SET memo = '%s' WHERE id = %ld", m,
                             1 + (long)(next() % (uint64_t)live));
                    rc = run(&s, sql);
                }
                rc = rc || run(&s, "COMMIT");
            }
            rc = rc || ack(afd, db, &last);
            if (now() >= next_stats) {
                imdb_mem_report r;
                imdb_mem(db, &r);
                fprintf(sf, "%.1f %llu %llu %llu %llu %llu %llu %llu %llu %ld\n", now() - t0,
                        (unsigned long long)db->seq, (unsigned long long)r.versions, (unsigned long long)r.rows,
                        (unsigned long long)r.indexes, (unsigned long long)r.segments,
                        (unsigned long long)r.commits, (unsigned long long)r.txns, (unsigned long long)r.total,
                        rss_kb());
                fflush(sf);
                next_stats = now() + 10;
            }
        }
    }
    imdb_session_close(&s);
    if (sf) fclose(sf);
    close(afd);
    if (efd >= 0) close(efd);
    if (imdb_close(db)) rc = 1;
    return rc ? 1 : 0;
}
