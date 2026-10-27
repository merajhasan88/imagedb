/* What one durable 4 KiB write costs on this disk, four ways (deferred.md R8, finding 1): an
 * append that grows the file (imagedb's log, SQLite's WAL), an overwrite inside a file whose
 * blocks were already written and synced (PostgreSQL's recycled, zero-filled WAL segments), and a
 * first write into space reserved with fallocate (unwritten extents). A growing size, or an
 * extent turning from unwritten to written, is metadata fdatasync must also make durable, so
 * ext4 commits its journal; an overwrite of written blocks changes only data. A fourth case
 * writes the overwrite with O_DIRECT | O_DSYNC (no page cache, durable on return: one FUA write
 * where the disk supports it, else a write and a cache flush; /sys/block/<dev>/queue/fua).
 *   fsync_probe DIR [N]   (N synced writes per case, default 500)
 * One line per measure: "probe case metric value unit"; bench/whole.sh runs it first. */
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

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

static void report(const char *what, double *lat, int n)
{
    qsort(lat, (size_t)n, sizeof *lat, cmp_d);
    printf("probe %s p50 %.1f us\n", what, lat[n / 2] * 1e6);
    printf("probe %s p99 %.1f us\n", what, lat[n * 99 / 100] * 1e6);
}

static int fail(const char *what)
{
    fprintf(stderr, "fsync_probe: %s: %s\n", what, strerror(errno));
    return 1;
}

/* N synced 4 KiB writes into PATH, at the end (append) or at block i of a file prepared by PREP */
static int run(const char *dir, const char *name, int prep, int n, double *lat)
{
    static char buf[4096], zero[4096];
    char path[4096];
    memset(buf, 0xa5, sizeof buf);
    snprintf(path, sizeof path, "%s/%s.dat", dir, name);
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (fd < 0) return fail(path);
    if (prep == 1) { /* written and synced: later writes change no metadata fdatasync needs */
        for (int i = 0; i < n; i++)
            if (write(fd, zero, sizeof zero) != (ssize_t)sizeof zero) return fail("fill");
        if (fsync(fd)) return fail("fsync");
    } else if (prep == 2) { /* reserved, not written: each first write converts an extent */
        int rc = posix_fallocate(fd, 0, (off_t)n * 4096);
        if (rc) {
            errno = rc;
            return fail("posix_fallocate");
        }
        if (fsync(fd)) return fail("fsync");
    }
    for (int i = 0; i < n; i++) {
        double a = now();
        ssize_t w = prep ? pwrite(fd, buf, sizeof buf, (off_t)i * 4096) : write(fd, buf, sizeof buf);
        if (w != (ssize_t)sizeof buf) return fail("write");
        if (fdatasync(fd)) return fail("fdatasync");
        lat[i] = now() - a;
    }
    close(fd);
    unlink(path);
    report(name, lat, n);
    return 0;
}

/* the overwrite case again, each write O_DIRECT | O_DSYNC from an aligned buffer, no fdatasync */
static int run_direct(const char *dir, int n, double *lat)
{
    static char zero[4096];
    char path[4096];
    snprintf(path, sizeof path, "%s/direct_dsync.dat", dir);
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (fd < 0) return fail(path);
    for (int i = 0; i < n; i++)
        if (write(fd, zero, sizeof zero) != (ssize_t)sizeof zero) return fail("fill");
    if (fsync(fd)) return fail("fsync");
    close(fd);
    fd = open(path, O_WRONLY | O_DIRECT | O_DSYNC | O_CLOEXEC);
    if (fd < 0) return fail("open O_DIRECT | O_DSYNC");
    void *buf;
    if (posix_memalign(&buf, 4096, 4096)) return fail("posix_memalign");
    memset(buf, 0xa5, 4096);
    for (int i = 0; i < n; i++) {
        double a = now();
        if (pwrite(fd, buf, 4096, (off_t)i * 4096) != 4096) return fail("direct write");
        lat[i] = now() - a;
    }
    free(buf);
    close(fd);
    unlink(path);
    report("direct_dsync_overwrite", lat, n);
    return 0;
}

int main(int argc, char **argv)
{
    if (argc < 2 || argc > 3) {
        fprintf(stderr, "usage: fsync_probe DIR [N]\n");
        return 2;
    }
    int n = argc == 3 ? atoi(argv[2]) : 500;
    if (n < 10 || n > 100000) {
        fprintf(stderr, "fsync_probe: N must be 10..100000\n");
        return 2;
    }
    double *lat = calloc((size_t)n, sizeof *lat);
    if (!lat) return 1;
    int rc = run(argv[1], "append_fdatasync", 0, n, lat) || run(argv[1], "overwrite_fdatasync", 1, n, lat) ||
             run(argv[1], "fallocated_fdatasync", 2, n, lat) || run_direct(argv[1], n, lat);
    free(lat);
    return rc;
}
