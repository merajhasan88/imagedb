/* throwaway (2026-10-26, open item A): where a process waits. Every INTERVAL ms, for each process whose
 * comm is COMM, count its threads by state (R running, S sleeping, D uninterruptible: usually I/O) and,
 * for each thread in D, print its wchan and the top of its kernel stack. Runs until killed.
 *   dstate COMM INTERVAL_MS
 * stdout: "t_ms pid R S D [| tid wchan: frame; frame; ...]" per sample with a matching process. */
#define _GNU_SOURCE
#include <ctype.h>
#include <dirent.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

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

static double mono(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

int main(int argc, char **argv)
{
    if (argc < 3) return 2;
    const char *comm = argv[1];
    int ims = atoi(argv[2]);
    setvbuf(stdout, NULL, _IOLBF, 0);
    double t0 = mono();
    char path[1100], buf[8192], line[8192];
    for (;;) {
        DIR *pd = opendir("/proc");
        if (!pd) return 1;
        struct dirent *pe;
        while ((pe = readdir(pd))) {
            if (!isdigit((unsigned char)pe->d_name[0])) continue;
            snprintf(path, sizeof path, "/proc/%s/comm", pe->d_name);
            if (slurp(path, buf, sizeof buf)) continue;
            buf[strcspn(buf, "\n")] = 0;
            if (strcmp(buf, comm)) continue;
            int r = 0, s = 0, d = 0;
            size_t ll = 0;
            line[0] = 0;
            snprintf(path, sizeof path, "/proc/%s/task", pe->d_name);
            DIR *td = opendir(path);
            if (!td) continue;
            struct dirent *te;
            while ((te = readdir(td))) {
                if (!isdigit((unsigned char)te->d_name[0])) continue;
                snprintf(path, sizeof path, "/proc/%s/task/%s/stat", pe->d_name, te->d_name);
                if (slurp(path, buf, sizeof buf)) continue;
                char *p = strrchr(buf, ')');
                if (!p || !p[1] || !p[2]) continue;
                char st = p[2];
                if (st == 'R') r++;
                else if (st == 'D') d++;
                else s++;
                if (st != 'D' || ll > sizeof line - 600) continue;
                char wchan[128] = "?", stack[4096] = "";
                snprintf(path, sizeof path, "/proc/%s/task/%s/wchan", pe->d_name, te->d_name);
                if (!slurp(path, buf, sizeof buf)) snprintf(wchan, sizeof wchan, "%.127s", buf);
                snprintf(path, sizeof path, "/proc/%s/task/%s/stack", pe->d_name, te->d_name);
                if (!slurp(path, buf, sizeof buf)) { /* "[<0>] func+0x1/0x2" lines: keep the first five names */
                    int k = 0;
                    size_t sl = 0;
                    for (char *q = buf; *q && k < 5; k++) {
                        char *e = strchr(q, '\n');
                        if (e) *e = 0;
                        char *f = strchr(q, ']');
                        f = f ? f + 2 : q;
                        char *plus = strchr(f, '+');
                        if (plus) *plus = 0;
                        sl += (size_t)snprintf(stack + sl, sizeof stack - sl, "%s%s", k ? "; " : "", f);
                        if (!e || sl >= sizeof stack - 64) break;
                        q = e + 1;
                    }
                }
                ll += (size_t)snprintf(line + ll, sizeof line - ll, " | %s %s: %s", te->d_name, wchan, stack);
            }
            closedir(td);
            struct timespec rt;
            clock_gettime(CLOCK_REALTIME, &rt);
            struct tm tm;
            localtime_r(&rt.tv_sec, &tm);
            printf("%02d:%02d:%02d.%03ld %.0f %s %d %d %d%s\n", tm.tm_hour, tm.tm_min, tm.tm_sec, rt.tv_nsec / 1000000,
                   (mono() - t0) * 1e3, pe->d_name, r, s, d, line);
        }
        closedir(pd);
        usleep((useconds_t)ims * 1000);
    }
}
