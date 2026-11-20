/* N1d: COPY's spool files (spool.h). */
#include "spool.h"

#include <errno.h>
#include <fcntl.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "wire.h"

struct imdbsp {
    int fd;
};

static _Atomic int64_t g_live;
static _Atomic int64_t g_fail_at;
static _Atomic bool g_no_tmpfile;
static _Atomic bool g_no_release;

void imdbsp_fail_at(int64_t n) { atomic_store_explicit(&g_fail_at, n, memory_order_relaxed); }
int64_t imdbsp_live(void) { return atomic_load_explicit(&g_live, memory_order_relaxed); }
void imdbsp_no_tmpfile(bool on) { atomic_store_explicit(&g_no_tmpfile, on, memory_order_relaxed); }
void imdbsp_no_release(bool on) { atomic_store_explicit(&g_no_release, on, memory_order_relaxed); }

/* the call the hook fails (counted down to it) */
static bool failing(void)
{
    return atomic_load_explicit(&g_fail_at, memory_order_relaxed) > 0 &&
           atomic_fetch_sub_explicit(&g_fail_at, 1, memory_order_relaxed) == 1;
}

int imdbsp_dir(const char *path, int *dfd, imdb_err *e)
{
    *dfd = -1;
    if (mkdir(path, 0700) && errno != EEXIST) return imdb_fail(e, IMDB_ERR_IO, "spool directory %s: %s", path, strerror(errno));
    int fd = open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return imdb_fail(e, IMDB_ERR_IO, "spool directory %s: %s", path, strerror(errno));
    struct stat st;
    if (fstat(fd, &st) || !S_ISDIR(st.st_mode) || (st.st_mode & 077)) {
        close(fd);
        return imdb_fail(e, IMDB_ERR_STATE, "spool directory %s: not a directory, or open to its group or the world (chmod 700)",
                         path);
    }
    *dfd = fd;
    return IMDB_OK;
}

int imdbsp_open(int dfd, imdbsp **out, imdb_err *e)
{
    *out = NULL;
    if (failing()) return imdb_fail(e, IMDB_ERR_IO, "a COPY's spool file: %s", strerror(ENOSPC));
    int fd = -1;
    if (!atomic_load_explicit(&g_no_tmpfile, memory_order_relaxed))
        fd = openat(dfd, ".", O_TMPFILE | O_RDWR | O_CLOEXEC, 0600);
    if (fd < 0) { /* no O_TMPFILE here (or the tests' refusal): a random name, unlinked at once */
        for (int k = 0; k < 8 && fd < 0; k++) {
            uint8_t r[16];
            char name[48];
            if (imdb_random(r, sizeof r, e)) return e->code;
            memcpy(name, "copy-", 5);
            imdb_hex(r, sizeof r, name + 5);
            fd = openat(dfd, name, O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
            if (fd >= 0 && unlinkat(dfd, name, 0)) {
                int err = errno;
                close(fd);
                return imdb_fail(e, IMDB_ERR_IO, "a COPY's spool file: unlink: %s", strerror(err));
            }
            if (fd < 0 && errno != EEXIST) break;
        }
        if (fd < 0) return imdb_fail(e, IMDB_ERR_IO, "a COPY's spool file: %s", strerror(errno));
    }
    imdbsp *sp = imdbw_alloc(1, sizeof *sp);
    if (!sp) {
        close(fd);
        return imdb_fail(e, IMDB_ERR_NOMEM, "out of memory for a COPY's spool");
    }
    sp->fd = fd;
    atomic_fetch_add_explicit(&g_live, 1, memory_order_relaxed);
    *out = sp;
    return IMDB_OK;
}

int imdbsp_write(imdbsp *sp, uint64_t off, const void *p, size_t n, imdb_err *e)
{
    const uint8_t *q = p;
    if (failing()) return imdb_fail(e, IMDB_ERR_IO, "writing a COPY's spool: %s", strerror(ENOSPC));
    while (n) {
        ssize_t k = pwrite(sp->fd, q, n, (off_t)off);
        if (k < 0 && errno == EINTR) continue;
        if (k <= 0) return imdb_fail(e, IMDB_ERR_IO, "writing a COPY's spool: %s", k < 0 ? strerror(errno) : "nothing written");
        q += k, off += (uint64_t)k, n -= (size_t)k;
    }
    return IMDB_OK;
}

ssize_t imdbsp_read(imdbsp *sp, uint64_t off, void *p, size_t n)
{
    if (failing()) {
        errno = EIO;
        return -1;
    }
    for (;;) {
        ssize_t k = pread(sp->fd, p, n, (off_t)off);
        if (k < 0 && errno == EINTR) continue;
        return k;
    }
}

bool imdbsp_release(imdbsp *sp, uint64_t off, uint64_t n)
{
    if (!n) return true;
    if (atomic_load_explicit(&g_no_release, memory_order_relaxed) || off > INT64_MAX || n > INT64_MAX - off) return false;
    for (;;) {
        if (!fallocate(sp->fd, FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE, (off_t)off, (off_t)n)) return true;
        if (errno != EINTR) return false;
    }
}

void imdbsp_close(imdbsp *sp)
{
    if (!sp) return;
    close(sp->fd);
    imdbw_free(sp);
    atomic_fetch_sub_explicit(&g_live, 1, memory_order_relaxed);
}
