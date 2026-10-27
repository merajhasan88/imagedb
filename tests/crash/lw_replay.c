/*
 * lw_replay: replays a dm-log-writes log onto an image (tests/crash, deferred.md R7d).
 *
 *   lw_replay LOG --list               one line per entry: index, flags, sector, sectors, mark
 *   lw_replay LOG TARGET --upto N      applies the writes (and discards) of entries 0..N to TARGET
 *
 * The format (drivers/md/dm-log-writes.c): a superblock at byte 0 (u64 magic
 * 0x6a736677736872, u64 version 1, u64 number of entries, u32 sector size), then
 * from byte `sectorsize` one entry after another: a header block of sectorsize
 * bytes (u64 sector, u64 nr_sectors, u64 flags, u64 data_len, little-endian; a
 * mark's text inline after them), then nr_sectors * sectorsize bytes of data. A
 * flush, a mark and a discard carry no data. sector and nr_sectors count
 * sectorsize units. The kernel logs a flush after the writes it covers, so the
 * image after the entries up to a flush is a state the device was guaranteed to
 * hold at that point; any prefix is a state it may have held.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define LW_MAGIC 0x6a736677736872ull
#define F_FLUSH 1u
#define F_FUA 2u
#define F_DISCARD 4u
#define F_MARK 8u
#define F_META 16u

static uint64_t le64(const uint8_t *p)
{
    uint64_t v = 0;
    for (int i = 7; i >= 0; i--) v = v << 8 | p[i];
    return v;
}

static void die(const char *what)
{
    fprintf(stderr, "lw_replay: %s%s%s\n", what, errno ? ": " : "", errno ? strerror(errno) : "");
    exit(2);
}

static void pread_all(int fd, void *b, size_t n, uint64_t off)
{
    size_t got = 0;
    while (got < n) {
        ssize_t r = pread(fd, (uint8_t *)b + got, n - got, (off_t)(off + got));
        if (r <= 0) {
            if (r == 0) errno = 0;
            die("short read of the log");
        }
        got += (size_t)r;
    }
}

static void pwrite_all(int fd, const void *b, size_t n, uint64_t off)
{
    size_t done = 0;
    while (done < n) {
        ssize_t w = pwrite(fd, (const uint8_t *)b + done, n - done, (off_t)(off + done));
        if (w <= 0) die("write to the target");
        done += (size_t)w;
    }
}

int main(int argc, char **argv)
{
    bool list = argc == 3 && strcmp(argv[2], "--list") == 0;
    bool replay = argc == 5 && strcmp(argv[3], "--upto") == 0;
    if (!list && !replay) {
        fputs("usage: lw_replay LOG --list | lw_replay LOG TARGET --upto N\n", stderr);
        return 2;
    }
    int lfd = open(argv[1], O_RDONLY | O_CLOEXEC);
    if (lfd < 0) die("open the log");
    uint8_t sb[28];
    pread_all(lfd, sb, sizeof sb, 0);
    uint64_t nent = le64(sb + 16);
    uint32_t ss = (uint32_t)sb[24] | (uint32_t)sb[25] << 8 | (uint32_t)sb[26] << 16 | (uint32_t)sb[27] << 24;
    if (le64(sb) != LW_MAGIC || le64(sb + 8) != 1 || ss < 512 || ss > 65536 || (ss & (ss - 1))) {
        errno = 0;
        die("not a dm-log-writes log (magic, version or sector size)");
    }
    uint64_t upto = 0;
    int tfd = -1;
    if (replay) {
        char *end;
        errno = 0;
        upto = strtoull(argv[4], &end, 10);
        if (errno || *end || end == argv[4]) die("--upto N: a number");
        tfd = open(argv[2], O_WRONLY | O_CLOEXEC);
        if (tfd < 0) die("open the target");
    }
    uint8_t *hdr = malloc(ss), *buf = NULL, *zero = calloc(1, ss);
    size_t cap = 0;
    if (!hdr || !zero) die("malloc");
    uint64_t pos = ss;
    for (uint64_t i = 0; i < nent && (!replay || i <= upto); i++) {
        pread_all(lfd, hdr, ss, pos);
        uint64_t sector = le64(hdr), nsec = le64(hdr + 8), flags = le64(hdr + 16), dlen = le64(hdr + 24);
        pos += ss;
        bool data = nsec && !(flags & F_DISCARD);
        if (list) {
            char mark[256] = "";
            if ((flags & F_MARK) && dlen < sizeof mark && dlen <= ss - 32) {
                memcpy(mark, hdr + 32, dlen);
                mark[dlen] = 0;
            }
            printf("%" PRIu64 " %s%s%s%s%s %" PRIu64 " %" PRIu64 " %s\n", i, flags & F_FLUSH ? "F" : "-",
                   flags & F_FUA ? "U" : "-", flags & F_DISCARD ? "D" : "-", flags & F_MARK ? "M" : "-",
                   flags & F_META ? "m" : "-", sector, nsec, mark);
        } else if (data) {
            if (nsec > (1ull << 32) / ss) {
                errno = 0;
                die("an entry larger than 4 GiB");
            }
            size_t n = (size_t)(nsec * ss);
            if (n > cap) {
                free(buf);
                buf = malloc(n);
                if (!buf) die("malloc");
                cap = n;
            }
            pread_all(lfd, buf, n, pos);
            pwrite_all(tfd, buf, n, sector * ss);
        } else if (nsec && (flags & F_DISCARD)) {
            for (uint64_t k = 0; k < nsec; k++) pwrite_all(tfd, zero, ss, (sector + k) * ss); /* read back as zeros */
        }
        if (data) pos += nsec * ss;
    }
    if (tfd >= 0 && (fsync(tfd) != 0 || close(tfd) != 0)) die("sync the target");
    free(buf);
    free(hdr);
    free(zero);
    close(lfd);
    return 0;
}
