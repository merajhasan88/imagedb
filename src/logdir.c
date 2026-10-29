/* Log segments: naming, listing (see logdir.h). */
#include "logdir.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "fsio.h"

void imdb_logseg_name(uint64_t first, char out[IMDB_LOGSEG_NAME + 1])
{
    snprintf(out, IMDB_LOGSEG_NAME + 1, "%020llu.ilg", (unsigned long long)first);
}

bool imdb_logseg_parse(const char *name, uint64_t *first)
{
    if (strnlen(name, IMDB_LOGSEG_NAME + 1) != IMDB_LOGSEG_NAME || strcmp(name + 20, ".ilg") != 0) return false;
    uint64_t v = 0;
    for (int i = 0; i < 20; i++) {
        if (name[i] < '0' || name[i] > '9') return false;
        unsigned d = (unsigned)(name[i] - '0');
        if (v > (UINT64_MAX - d) / 10) return false;
        v = v * 10 + d;
    }
    if (v == 0) return false;
    *first = v;
    return true;
}

static int cmp_u64(const void *a, const void *b)
{
    uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;
    return x < y ? -1 : x > y;
}

/* A redaction rewrite's temporary: "<segment name>.tmp". 1 if name is one and
 * both it and its segment are regular files, 0 if it is not that name, and an
 * error if it is but either file is not regular (or the segment is missing). */
static int redaction_temp(int logfd, const char *name, imdb_err *e)
{
    if (strlen(name) != IMDB_LOGSEG_NAME + 4 || strcmp(name + IMDB_LOGSEG_NAME, ".tmp") != 0) return 0;
    char base[IMDB_LOGSEG_NAME + 1];
    memcpy(base, name, IMDB_LOGSEG_NAME);
    base[IMDB_LOGSEG_NAME] = '\0';
    uint64_t first;
    if (!imdb_logseg_parse(base, &first)) return 0;
    struct stat old, tmp;
    if (imdb_io_fstatat(logfd, base, &old, AT_SYMLINK_NOFOLLOW) != 0 || !S_ISREG(old.st_mode) ||
        imdb_io_fstatat(logfd, name, &tmp, AT_SYMLINK_NOFOLLOW) != 0 || !S_ISREG(tmp.st_mode))
        return imdb_fail(e, IMDB_ERR_CORRUPT, "log: redaction temporary file has no regular segment or is not regular");
    return 1;
}

int imdb_logdir_cleanup_temps(int logfd, imdb_err *e)
{
    int fd = imdb_io_openat(logfd, ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    DIR *d = fd >= 0 ? imdb_io_fdopendir(fd) : NULL;
    if (!d) {
        if (fd >= 0) close(fd);
        return imdb_fail(e, IMDB_ERR_IO, "log: cannot inspect redaction temporary files");
    }
    int rc = IMDB_OK;
    bool changed = false;
    for (;;) {
        errno = 0;
        struct dirent *de = imdb_io_readdir(d);
        if (!de) {
            if (errno) rc = imdb_fail(e, IMDB_ERR_IO, "log: directory read failed: %s", strerror(errno));
            break;
        }
        int t = redaction_temp(logfd, de->d_name, e);
        if (t < 0) {
            rc = t;
            break;
        }
        if (!t) continue;
        /* The old name is still authoritative until rename. Replay will
         * recover the committed ERASE and regenerate this unfinished output. */
        if (imdb_io_unlinkat(logfd, de->d_name, 0) != 0) {
            rc = imdb_fail(e, IMDB_ERR_IO, "log: cannot remove redaction temporary file: %s", strerror(errno));
            break;
        }
        changed = true;
    }
    closedir(d);
    if (!rc && changed) rc = imdb_sync_dir(logfd, e);
    return rc;
}

int imdb_logdir_list(int logfd, uint64_t **firsts, size_t *n, imdb_err *e)
{
    *firsts = NULL;
    *n = 0;
    int dfd = dup(logfd);
    DIR *d = dfd >= 0 ? imdb_io_fdopendir(dfd) : NULL;
    if (!d) {
        if (dfd >= 0) close(dfd);
        return imdb_fail(e, IMDB_ERR_IO, "log: cannot list the directory");
    }
    rewinddir(d);
    uint64_t *v = NULL;
    size_t cnt = 0, cap = 0;
    int rc = IMDB_OK;
    struct dirent *de;
    while (!rc) {
        errno = 0;
        de = imdb_io_readdir(d);
        if (!de) {
            if (errno) rc = imdb_fail(e, IMDB_ERR_IO, "log: directory read failed: %s", strerror(errno));
            break;
        }
        if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0) continue;
        uint64_t first;
        struct stat st;
        int t = redaction_temp(logfd, de->d_name, e);
        if (t < 0) {
            rc = t;
            break;
        }
        if (t) continue;
        if (!imdb_logseg_parse(de->d_name, &first)) {
            rc = imdb_fail(e, IMDB_ERR_CORRUPT, "log: unexpected file in log/");
            break;
        }
        if (imdb_io_fstatat(logfd, de->d_name, &st, AT_SYMLINK_NOFOLLOW) != 0 || !S_ISREG(st.st_mode)) {
            rc = imdb_fail(e, IMDB_ERR_CORRUPT, "log: segment is not a regular file (refusing to follow a symlink)");
            break;
        }
        if (cnt == cap) {
            size_t nc = cap ? cap * 2 : 16;
            uint64_t *nv = imdb_realloc_array(v, cap, nc, sizeof *nv, e);
            if (!nv) {
                rc = e->code;
                break;
            }
            v = nv;
            cap = nc;
        }
        v[cnt++] = first;
    }
    closedir(d);
    if (rc) {
        imdb_free(v);
        return rc;
    }
    if (cnt) qsort(v, cnt, sizeof *v, cmp_u64);
    *firsts = v;
    *n = cnt;
    return IMDB_OK;
}

size_t imdb_logseg_find(const uint64_t *firsts, size_t n, uint64_t seq)
{
    size_t lo = 0, hi = n; /* first index with firsts[i] > seq */
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        if (firsts[mid] <= seq) lo = mid + 1;
        else hi = mid;
    }
    return lo ? lo - 1 : n;
}

int imdb_logseg_read(int logfd, uint64_t first, uint8_t **buf, size_t *len, imdb_err *e)
{
    char name[IMDB_LOGSEG_NAME + 1];
    imdb_logseg_name(first, name);
    return imdb_read_file_at(logfd, name, buf, len, IMDB_MAX_OBJECT, e);
}

int imdb_logseg_load(int logfd, uint64_t first, imdb_logseg *s, imdb_err *e)
{
    memset(s, 0, sizeof *s);
    s->first = first;
    s->tail = IMDB_SCAN_END;
    if (imdb_logseg_read(logfd, first, &s->buf, &s->size, e)) return e->code;
    s->len = s->size;
    if (!imdb_tseg_is_tagged(s->buf, s->size)) return IMDB_OK;
    s->tagged = true;
    imdb_err et = {0};
    s->tail = imdb_tseg_scan(s->buf, s->size, first, &s->len, &s->end, &et);
    if (s->tail != IMDB_SCAN_END) snprintf(s->tail_msg, sizeof s->tail_msg, "%s", et.msg);
    imdb_wipe(s->buf + s->len, s->size - s->len); /* what is left of the sectors: callers wipe only the frames */
    return IMDB_OK;
}

bool imdb_logseg_blank(const imdb_logseg *s)
{
    if (s->tagged) return false;
    for (size_t i = 0; i < s->len; i++)
        if (s->buf[i]) return false;
    return true;
}

void imdb_logseg_free(imdb_logseg *s)
{
    if (s->buf) {
        imdb_wipe(s->buf, s->size);
        imdb_free(s->buf);
    }
    s->buf = NULL;
}

imdb_scan_status imdb_logseg_scan(const imdb_logseg *s, size_t off, size_t *flen, imdb_err *e)
{
    if (s->tagged && off >= s->len) {
        if (s->tail != IMDB_SCAN_END) imdb_fail(e, IMDB_ERR_CORRUPT, "%s", s->tail_msg);
        return s->tail;
    }
    return imdb_frame_scan(s->buf, s->len, off, flen, e);
}

/* n bytes at off, fewer only at the end of the file */
static int pread_upto(int fd, uint8_t *p, size_t n, uint64_t off, size_t *got, imdb_err *e)
{
    *got = 0;
    while (*got < n) {
        ssize_t r = imdb_io_pread(fd, p + *got, n - *got, (off_t)(off + *got));
        if (r < 0 && errno == EINTR) continue;
        if (r < 0) return imdb_fail(e, IMDB_ERR_IO, "read log segment: %s", strerror(errno));
        if (r == 0) break;
        *got += (size_t)r;
    }
    return IMDB_OK;
}

int imdb_logseg_first_time(int logfd, uint64_t first, uint64_t *time_us, imdb_err *e)
{
    char name[IMDB_LOGSEG_NAME + 1];
    imdb_logseg_name(first, name);
    int fd = imdb_io_openat(logfd, name, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return imdb_fail(e, IMDB_ERR_IO, "log segment %s: %s", name, strerror(errno));
    imdb_buf b, fr;
    imdb_buf_init(&b);
    imdb_buf_init(&fr);
    int rc = IMDB_OK;
    struct stat st;
    if (imdb_io_fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) {
        rc = imdb_fail(e, IMDB_ERR_CORRUPT, "log segment %s is not a regular file", name);
        goto out;
    }
    uint64_t size = (uint64_t)st.st_size;
    const uint8_t *f = NULL;
    size_t flen = 0;
    /* a few sectors first, then twice as many until the first frame is whole: a read never goes past
     * the file, so a frame's claimed length costs at most the file's own size */
    for (size_t want = 8 * IMDB_TSEG_SECTOR;; want *= 2) {
        size_t n = want < size ? want : (size_t)size, got = 0;
        b.len = 0;
        if (!imdb_buf_reserve(&b, n ? n : 1)) {
            rc = imdb_fail(e, IMDB_ERR_NOMEM, "out of memory");
            goto out;
        }
        if ((rc = pread_upto(fd, b.p, n, 0, &got, e))) goto out;
        b.len = got;
        bool more = true;
        if (imdb_tseg_is_tagged(b.p, b.len)) {
            /* the first group begins at sector 1, its first frame at its first byte */
            imdb_tseg_pos pos = {.sector = 1, .byte = 0, .tag = 0, .next = first};
            size_t whole = b.len / IMDB_TSEG_SECTOR * IMDB_TSEG_SECTOR;
            if (whole > IMDB_TSEG_SECTOR &&
                imdb_tseg_next(b.p + IMDB_TSEG_SECTOR, whole - IMDB_TSEG_SECTOR, 1, &pos, &fr, &more) == IMDB_SCAN_FRAME) {
                f = fr.p;
                flen = fr.len;
                break;
            }
            if (imdb_buf_check(&fr, e)) {
                rc = e->code;
                goto out;
            }
            more = more || whole <= IMDB_TSEG_SECTOR;
        } else {
            imdb_err e2 = {0};
            imdb_scan_status s = imdb_frame_scan(b.p, b.len, 0, &flen, &e2);
            if (s == IMDB_SCAN_FRAME) {
                f = b.p;
                break;
            }
            more = s == IMDB_SCAN_TORN; /* a frame longer than the read, or a prefix not read whole yet */
        }
        if (!more || n == size) {
            rc = imdb_fail(e, IMDB_ERR_CORRUPT, "log segment %s: no whole first frame", name);
            goto out;
        }
    }
    imdb_commit_rec c;
    if ((rc = imdb_frame_decode_body(f + IMDB_FRAME_HDR, flen - IMDB_FRAME_HDR, &c, e))) goto out;
    if (c.seq != first) rc = imdb_fail(e, IMDB_ERR_CORRUPT, "log segment %s: its first frame is commit %llu", name,
                                       (unsigned long long)c.seq);
    else *time_us = c.time_us; /* the header's hash matched the descriptor's: the time its signature covers */
    imdb_commit_free(&c);
out:
    close(fd);
    imdb_wipe(b.p, b.cap); /* payloads: an erased one may be here until redaction */
    imdb_free(b.p);
    imdb_wipe(fr.p, fr.cap);
    imdb_free(fr.p);
    return rc;
}

int imdb_durable_read(int dirfd, imdb_durable *w, bool *present, imdb_err *e)
{
    memset(w, 0, sizeof *w);
    *present = false;
    int fd = imdb_io_openat(dirfd, IMDB_DURABLE_NAME, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) {
        if (errno == ENOENT) return IMDB_OK;
        return imdb_fail(e, IMDB_ERR_IO, "DURABLE: %s", strerror(errno));
    }
    struct stat st;
    if (imdb_io_fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) {
        close(fd);
        return imdb_fail(e, IMDB_ERR_CORRUPT, "DURABLE is not a regular file");
    }
    int rc = IMDB_OK;
    for (int attempt = 0;; attempt++) {
        uint8_t b[IMDB_DURABLE_LEN + 1];
        ssize_t n = imdb_io_pread(fd, b, sizeof b, 0);
        if (n == 0) break; /* created, never written */
        imdb_err e2 = {0};
        if (n > 0 && imdb_durable_decode(b, (size_t)n, w, &e2) == IMDB_OK) {
            *present = true;
            break;
        }
        if (attempt == 4) {
            rc = n < 0 ? imdb_fail(e, IMDB_ERR_IO, "DURABLE: %s", strerror(errno)) : imdb_fail(e, e2.code, "%s", e2.msg);
            break;
        }
        struct timespec ts = {0, 1000 * 1000}; /* a torn read of an in-place rewrite: read it again */
        nanosleep(&ts, NULL);
    }
    close(fd);
    return rc;
}

int imdb_logseg_drop_tail(int logfd, const imdb_logseg *s, imdb_err *e)
{
    static const uint8_t zeros[65536];
    char name[IMDB_LOGSEG_NAME + 1];
    imdb_logseg_name(s->first, name);
    int fd = imdb_io_openat(logfd, name, O_RDWR | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return imdb_fail(e, IMDB_ERR_IO, "cannot drop the torn log tail: %s", strerror(errno));
    int rc = IMDB_OK;
    uint64_t z = s->end.keep_sector;
    if (s->end.keep_bytes) { /* E's sector keeps its tag and the bytes before E */
        uint8_t sec[IMDB_TSEG_SECTOR];
        if (imdb_io_pread(fd, sec, sizeof sec, (off_t)(z * IMDB_TSEG_SECTOR)) != (ssize_t)sizeof sec) {
            rc = imdb_fail(e, IMDB_ERR_IO, "cannot read the torn log tail");
        } else {
            memset(sec + 8 + s->end.keep_bytes, 0, IMDB_TSEG_PAYLOAD - s->end.keep_bytes);
            rc = imdb_pwrite_all(fd, sec, sizeof sec, (int64_t)(z * IMDB_TSEG_SECTOR), e);
        }
        z++;
    }
    for (uint64_t at = z * IMDB_TSEG_SECTOR, stop = s->end.dirty * IMDB_TSEG_SECTOR; !rc && at < stop;) {
        size_t k = stop - at < sizeof zeros ? (size_t)(stop - at) : sizeof zeros;
        rc = imdb_pwrite_all(fd, zeros, k, (int64_t)at, e);
        at += k;
    }
    if (!rc && imdb_io_fsync(fd) != 0) rc = imdb_fail(e, IMDB_ERR_IO, "cannot drop the torn log tail: %s", strerror(errno));
    close(fd);
    return rc;
}
