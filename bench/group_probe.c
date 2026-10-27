/* Preallocation's two layouts as write patterns on this disk (docs/commit-speed.md §1): a write
 * group of N frames of S bytes lands in zeros written and synced ahead, then one fdatasync. P (the
 * user's choice) packs the group's frames into ceil(N*S/504) sectors; F would put each frame on
 * fresh sectors of its own, ceil(S/504) apiece. This is not imagedb's writer, only the bytes and
 * sectors each layout would write: N = 1 is a synchronous commit (the two alike, a control), larger
 * N a --nosync session's or a replica's group, or a group-commit round. The two alternate, ABBA.
 *   group_probe DIR [R [S]]   (R groups a case, default 200; S bytes a frame, default 330)
 * One line per measure: "group_probe layout N metric value unit". */
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

enum { SEC = 512, PAY = 504 };
#define SPACE (256ull << 20) /* written ahead and synced, then overwritten group by group */

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

/* The group's sectors, tag then payload, the frames' bytes a pattern that is never zero. */
static size_t lay(uint8_t *b, int f_layout, long n, long s)
{
    size_t secs = f_layout ? (size_t)n * (size_t)((s + PAY - 1) / PAY) : (size_t)((n * s + PAY - 1) / PAY);
    memset(b, 0, secs * SEC);
    for (size_t i = 0; i < secs; i++) {
        memset(b + i * SEC, 0x7f, 8);
        size_t used = f_layout ? (size_t)s % PAY ? (size_t)s % PAY : PAY : PAY;
        memset(b + i * SEC + 8, 0x5a, used);
    }
    return secs * SEC;
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "usage: group_probe DIR [R [S]]\n");
        return 2;
    }
    long r = argc > 2 ? atol(argv[2]) : 200, s = argc > 3 ? atol(argv[3]) : 330;
    char path[1100];
    snprintf(path, sizeof path, "%s/group_probe.bin", argv[1]);
    int fd = open(path, O_RDWR | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (fd < 0) return 1;
    uint8_t *zeros = calloc(1, 1u << 20);
    for (uint64_t off = 0; off < SPACE; off += 1u << 20)
        if (pwrite(fd, zeros, 1u << 20, (off_t)off) != 1 << 20) return 1;
    if (fdatasync(fd) != 0) return 1;
    static const long ns[] = {1, 2, 10, 100, 1000};
    uint8_t *buf = malloc((size_t)1000 * (size_t)((s + PAY - 1) / PAY + 1) * SEC + (size_t)s * 1000 + SEC);
    double *lat[2];
    lat[0] = malloc(sizeof(double) * (size_t)r);
    lat[1] = malloc(sizeof(double) * (size_t)r);
    uint64_t pos = 0;
    for (size_t c = 0; c < sizeof ns / sizeof *ns; c++) {
        size_t bytes[2] = {0, 0};
        for (long i = 0; i < r; i++) {
            for (int k = 0; k < 2; k++) {
                int f = (i & 1) ? 1 - k : k; /* ABBA */
                size_t len = lay(buf, f, ns[c], s);
                if (pos + len > SPACE) pos = 0;
                double t0 = now();
                if (pwrite(fd, buf, len, (off_t)pos) != (ssize_t)len || fdatasync(fd) != 0) return 1;
                lat[f][i] = now() - t0;
                pos += len;
                bytes[f] = len;
            }
        }
        for (int f = 0; f < 2; f++) {
            qsort(lat[f], (size_t)r, sizeof(double), cmp_d);
            printf("group_probe %s %ld p50 %.0f us\n", f ? "F" : "P", ns[c], lat[f][r / 2] * 1e6);
            printf("group_probe %s %ld p99 %.0f us\n", f ? "F" : "P", ns[c], lat[f][r * 99 / 100] * 1e6);
            printf("group_probe %s %ld bytes %zu bytes\n", f ? "F" : "P", ns[c], bytes[f]);
        }
    }
    close(fd);
    unlink(path);
    free(zeros);
    free(buf);
    free(lat[0]);
    free(lat[1]);
    return 0;
}
