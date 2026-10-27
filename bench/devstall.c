/* What the disk itself was doing during a benchmark run (docs/open-items-2026-10-26.md, item A): the
 * head-to-heads' multi-second stalls were this machine's SSD holding queued writes and cache flushes
 * for up to 1.9 s each, found by tracing the ATA commands. This keeps a cheap record of such pauses
 * for every run, so a report's stall lines can say "device" where they said "unexplained".
 * Every 100 ms it reads /sys/block/DEV/stat and prints:
 *   - a pause: requests were in flight and none completed in two or more whole samples running (the
 *     figure is a lower bound, to 100 ms);
 *   - slow flushes: the time the kernel accounts to completed cache flushes grew by at least 200 ms
 *     within one 100 ms sample (a flush is accounted whole when it completes, and flushes do not
 *     overlap on a SATA disk, so at least one of them took over 100 ms).
 * Both carry the wall-clock time at which they were seen to end, so they can be matched against the
 * driver's stall lines. It runs until killed.
 *   devstall DEV            (DEV as in /sys/block, e.g. sda)
 * stdout: "devstall pause HH:MM:SS.mmm 0.412 s, 7 in flight" or "devstall flush HH:MM:SS.mmm 0.887 s"
 * (the flush time completed in that sample) */
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static int read_stat(const char *path, long long f[17])
{
    char buf[512];
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    ssize_t n = read(fd, buf, sizeof buf - 1);
    close(fd);
    if (n <= 0) return -1;
    buf[n] = 0;
    memset(f, 0, 17 * sizeof *f);
    int got = sscanf(buf, "%lld %lld %lld %lld %lld %lld %lld %lld %lld %lld %lld %lld %lld %lld %lld %lld %lld", &f[0],
                     &f[1], &f[2], &f[3], &f[4], &f[5], &f[6], &f[7], &f[8], &f[9], &f[10], &f[11], &f[12], &f[13],
                     &f[14], &f[15], &f[16]);
    return got >= 11 ? 0 : -1;
}

static double mono(void)
{
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (double)t.tv_sec + (double)t.tv_nsec / 1e9;
}

static void wall(char out[16])
{
    struct timespec t;
    clock_gettime(CLOCK_REALTIME, &t);
    struct tm tm;
    localtime_r(&t.tv_sec, &tm);
    snprintf(out, 16, "%02d:%02d:%02d.%03d", tm.tm_hour, tm.tm_min, tm.tm_sec, (int)(t.tv_nsec / 1000000));
}

int main(int argc, char **argv)
{
    if (argc != 2 || strchr(argv[1], '/')) {
        fprintf(stderr, "usage: devstall DEV\n");
        return 2;
    }
    char path[300];
    snprintf(path, sizeof path, "/sys/block/%s/stat", argv[1]);
    long long f[17], p[17];
    if (read_stat(path, p)) {
        fprintf(stderr, "devstall: cannot read %s\n", path);
        return 1;
    }
    setvbuf(stdout, NULL, _IOLBF, 0);
    double since = 0; /* the first sample that saw no completion with requests in flight; 0: none */
    long long most = 0;
    for (;;) {
        usleep(100000);
        if (read_stat(path, f)) return 1;
        /* completions: reads, writes, discards and flushes (fields 1, 5, 12 and 16) */
        long long done = f[0] + f[4] + f[11] + f[15], pdone = p[0] + p[4] + p[11] + p[15];
        double t = mono();
        char w[16];
        if (done == pdone && f[8] > 0) {
            if (!since) since = t;
            if (f[8] > most) most = f[8];
        } else {
            if (since && t - since >= 0.2) {
                wall(w);
                printf("devstall pause %s %.3f s, %lld in flight\n", w, t - since, most);
            }
            since = 0;
            most = 0;
        }
        if (f[16] - p[16] >= 200) { /* milliseconds accounted to flushes completed in this sample */
            wall(w);
            printf("devstall flush %s %.3f s\n", w, (double)(f[16] - p[16]) / 1000);
        }
        memcpy(p, f, sizeof p);
    }
}
