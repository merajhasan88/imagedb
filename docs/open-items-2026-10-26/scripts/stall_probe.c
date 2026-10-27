/* throwaway (2026-10-26, open item A: the head-to-heads' 2.4-4.7 s stalls): a timeline of durable
 * 4 KiB writes, one every INTERVAL ms, each with what the kernel and the disk were doing at that
 * moment: dirty and writeback memory (/proc/vmstat), the disk's written sectors and completed cache
 * flushes (/sys/block/DISK/stat), IO pressure (/proc/pressure/io, "full" total), the package
 * temperature and the mean CPU clock.
 *   stall_probe DIR SECONDS append|overwrite [INTERVAL_MS [DISK]]
 * append grows the file, as imagedb's log does today: a size change is metadata, so ext4 must commit
 * its journal, and in data=ordered mode that commit first writes the data of every file with blocks
 * allocated in the same transaction. overwrite rewrites 4 KiB blocks of a 16 MiB region written and
 * synced first (as PostgreSQL's recycled WAL, or preallocated segments): no metadata changes, so
 * fdatasync is the data and a cache flush.
 * stdout, one line per sample:
 *   t_ms lat_us dirty_kb writeback_kb sectors_written flushes io_full_us temp_mc khz
 * stderr: each sample over 100 ms with its wall-clock time, then a summary. */
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define REGION (16u << 20)

static double mono(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

static int slurp(const char *path, char *buf, size_t cap)
{
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    ssize_t n = read(fd, buf, cap - 1);
    close(fd);
    if (n < 0) return -1;
    buf[n] = 0;
    return 0;
}

static long long vmstat(const char *buf, const char *key)
{
    size_t kl = strlen(key);
    for (const char *p = buf; (p = strstr(p, key)); p += kl)
        if ((p == buf || p[-1] == '\n') && p[kl] == ' ') return atoll(p + kl + 1);
    return -1;
}

static char g_temp[256], g_disk[64];
static int g_ncpu;

static void sample(long long *dirty, long long *wb, long long *sect, long long *flush, long long *iofull,
                   long long *temp, long long *khz)
{
    static char buf[16384];
    *dirty = *wb = *sect = *flush = *iofull = *temp = *khz = -1;
    if (!slurp("/proc/vmstat", buf, sizeof buf)) {
        *dirty = vmstat(buf, "nr_dirty") * 4;
        *wb = vmstat(buf, "nr_writeback") * 4;
    }
    char path[128];
    snprintf(path, sizeof path, "/sys/block/%s/stat", g_disk);
    if (!slurp(path, buf, sizeof buf)) {
        long long f[17] = {0};
        int n = sscanf(buf, "%lld %lld %lld %lld %lld %lld %lld %lld %lld %lld %lld %lld %lld %lld %lld %lld %lld", &f[0],
                       &f[1], &f[2], &f[3], &f[4], &f[5], &f[6], &f[7], &f[8], &f[9], &f[10], &f[11], &f[12], &f[13],
                       &f[14], &f[15], &f[16]);
        if (n >= 7) *sect = f[6];
        if (n >= 16) *flush = f[15];
    }
    if (!slurp("/proc/pressure/io", buf, sizeof buf)) {
        char *p = strstr(buf, "full ");
        if (p && (p = strstr(p, "total="))) *iofull = atoll(p + 6);
    }
    if (g_temp[0] && !slurp(g_temp, buf, sizeof buf)) *temp = atoll(buf);
    long long sum = 0;
    int got = 0;
    for (int c = 0; c < g_ncpu; c++) {
        snprintf(path, sizeof path, "/sys/devices/system/cpu/cpu%d/cpufreq/scaling_cur_freq", c);
        if (!slurp(path, buf, sizeof buf)) {
            sum += atoll(buf);
            got++;
        }
    }
    if (got) *khz = sum / got;
}

static void find_temp(void)
{
    char path[256], buf[64];
    for (int z = 0; z < 64; z++) {
        snprintf(path, sizeof path, "/sys/class/thermal/thermal_zone%d/type", z);
        if (slurp(path, buf, sizeof buf)) continue;
        if (!strncmp(buf, "x86_pkg_temp", 12)) {
            snprintf(g_temp, sizeof g_temp, "/sys/class/thermal/thermal_zone%d/temp", z);
            return;
        }
    }
}

static int cmp_d(const void *a, const void *b)
{
    double x = *(const double *)a, y = *(const double *)b;
    return x < y ? -1 : x > y;
}

int main(int argc, char **argv)
{
    if (argc < 4) {
        fprintf(stderr, "usage: stall_probe DIR SECONDS append|overwrite [INTERVAL_MS [DISK]]\n");
        return 2;
    }
    double secs = atof(argv[2]);
    int over = !strcmp(argv[3], "overwrite");
    if (!over && strcmp(argv[3], "append")) return 2;
    int ims = argc > 4 ? atoi(argv[4]) : 50;
    snprintf(g_disk, sizeof g_disk, "%s", argc > 5 ? argv[5] : "sda");
    g_ncpu = (int)sysconf(_SC_NPROCESSORS_CONF);
    find_temp();
    setvbuf(stdout, NULL, _IOLBF, 0);
    char path[4096];
    snprintf(path, sizeof path, "%s/probe.dat", argv[1]);
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC | (over ? 0 : O_APPEND), 0600);
    if (fd < 0) {
        perror("open");
        return 1;
    }
    static char blk[4096];
    for (size_t i = 0; i < sizeof blk; i++) blk[i] = (char)(i * 131 + 7);
    if (over) { /* every block written and synced first, so each later write only overwrites */
        for (unsigned off = 0; off < REGION; off += sizeof blk)
            if (pwrite(fd, blk, sizeof blk, off) != (ssize_t)sizeof blk) return 1;
        if (fdatasync(fd)) return 1;
        int dfd = open(argv[1], O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        if (dfd < 0 || fsync(dfd)) return 1;
        close(dfd);
    }
    size_t cap = (size_t)(secs * 1000 / ims) + 16, n = 0;
    double *lat = calloc(cap, sizeof *lat);
    if (!lat) return 1;
    struct timespec next;
    clock_gettime(CLOCK_MONOTONIC, &next);
    double t0 = mono();
    unsigned slot = 0;
    while (n < cap && mono() - t0 < secs) {
        blk[0] = (char)n;
        double a = mono();
        ssize_t w = over ? pwrite(fd, blk, sizeof blk, (off_t)(slot++ % (REGION / sizeof blk)) * (off_t)sizeof blk)
                         : write(fd, blk, sizeof blk);
        if (w != (ssize_t)sizeof blk || fdatasync(fd)) {
            perror("write/fdatasync");
            return 1;
        }
        double b = mono();
        lat[n++] = b - a;
        long long d, wb, s, f, io, tc, khz;
        sample(&d, &wb, &s, &f, &io, &tc, &khz);
        printf("%.0f %.0f %lld %lld %lld %lld %lld %lld %lld\n", (a - t0) * 1e3, (b - a) * 1e6, d, wb, s, f, io, tc, khz);
        if (b - a > 0.1) {
            struct timespec rt;
            clock_gettime(CLOCK_REALTIME, &rt);
            struct tm tm;
            localtime_r(&rt.tv_sec, &tm);
            fprintf(stderr, "slow: %02d:%02d:%02d.%03ld %.3f s at t=%.1f s, dirty %lld MB, writeback %lld MB\n", tm.tm_hour,
                    tm.tm_min, tm.tm_sec, rt.tv_nsec / 1000000, b - a, (a - t0), d / 1024, wb / 1024);
        }
        next.tv_nsec += (long)ims * 1000000L;
        while (next.tv_nsec >= 1000000000L) {
            next.tv_nsec -= 1000000000L;
            next.tv_sec++;
        }
        clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &next, NULL);
    }
    close(fd);
    qsort(lat, n, sizeof *lat, cmp_d);
    size_t over100 = 0, over1s = 0;
    for (size_t i = 0; i < n; i++) {
        over100 += lat[i] > 0.1;
        over1s += lat[i] > 1.0;
    }
    fprintf(stderr, "summary %s: %zu writes, p50 %.2f ms, p99 %.2f ms, max %.3f s, %zu over 100 ms, %zu over 1 s\n",
            over ? "overwrite" : "append", n, lat[n / 2] * 1e3, lat[n * 99 / 100] * 1e3, lat[n - 1], over100, over1s);
    free(lat);
    return 0;
}
