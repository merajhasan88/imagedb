#include "fsio.h"

#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

/* ---- the system-call layer -------------------------------------------------- */

const imdb_io_hooks *imdb_io_hooks_on;

void imdb_io_set_hooks(const imdb_io_hooks *h) { imdb_io_hooks_on = h; }

/* Only reached with hooks installed. */
static long io_before(imdb_io_call *c)
{
    const imdb_io_hooks *h = imdb_io_hooks_on;
    return h && h->before ? h->before(c, h->ctx) : 0;
}

static void io_after(const imdb_io_call *c, long result)
{
    const imdb_io_hooks *h = imdb_io_hooks_on;
    if (!h || !h->after) return;
    int saved = errno;
    h->after(c, result, h->ctx);
    errno = saved;
}

#define HOOKED __builtin_expect(imdb_io_hooks_on != NULL, 0)
static imdb_io_call call_of(int op)
{
    return (imdb_io_call){.op = op, .fd = -1, .dirfd = -1, .dirfd2 = -1, .off = -1};
}

bool imdb_io_fail_alloc(size_t n)
{
    if (!HOOKED) return false;
    imdb_io_call c = call_of(IMDB_IO_ALLOC);
    c.len = n;
    return io_before(&c) < 0;
}

static int mode_arg(int flags, va_list ap) { return flags & O_CREAT ? va_arg(ap, int) : 0; }

int imdb_io_open(const char *path, int flags, ...)
{
    va_list ap;
    va_start(ap, flags);
    int mode = mode_arg(flags, ap);
    va_end(ap);
    if (!HOOKED) return open(path, flags, mode);
    imdb_io_call c = call_of(IMDB_IO_OPEN);
    c.dirfd = AT_FDCWD, c.name = path, c.flags = flags;
    if (io_before(&c) < 0) return -1;
    int r = open(path, flags, mode);
    io_after(&c, r);
    return r;
}

int imdb_io_openat(int dirfd, const char *name, int flags, ...)
{
    va_list ap;
    va_start(ap, flags);
    int mode = mode_arg(flags, ap);
    va_end(ap);
    if (!HOOKED) return openat(dirfd, name, flags, mode);
    imdb_io_call c = call_of(IMDB_IO_OPEN);
    c.dirfd = dirfd, c.name = name, c.flags = flags;
    if (io_before(&c) < 0) return -1;
    int r = openat(dirfd, name, flags, mode);
    io_after(&c, r);
    return r;
}

ssize_t imdb_io_read(int fd, void *p, size_t n)
{
    if (!HOOKED) return read(fd, p, n);
    imdb_io_call c = call_of(IMDB_IO_READ);
    c.fd = fd, c.len = n;
    if (io_before(&c) < 0) return -1;
    ssize_t r = read(fd, p, n);
    io_after(&c, (long)r);
    return r;
}

ssize_t imdb_io_pread(int fd, void *p, size_t n, off_t off)
{
    if (!HOOKED) return pread(fd, p, n, off);
    imdb_io_call c = call_of(IMDB_IO_READ);
    c.fd = fd, c.len = n, c.off = off;
    if (io_before(&c) < 0) return -1;
    ssize_t r = pread(fd, p, n, off);
    io_after(&c, (long)r);
    return r;
}

/* A hook may shorten a write: what reaches the file is then a prefix. */
static size_t write_len(imdb_io_call *c, long v) { return v > 0 && (size_t)v < c->len ? (size_t)v : c->len; }

ssize_t imdb_io_write(int fd, const void *p, size_t n)
{
    if (!HOOKED) return write(fd, p, n);
    imdb_io_call c = call_of(IMDB_IO_WRITE);
    c.fd = fd, c.buf = p, c.len = n;
    long v = io_before(&c);
    if (v < 0) return -1;
    c.len = write_len(&c, v);
    ssize_t r = write(fd, p, c.len);
    io_after(&c, (long)r);
    return r;
}

ssize_t imdb_io_pwrite(int fd, const void *p, size_t n, off_t off)
{
    if (!HOOKED) return pwrite(fd, p, n, off);
    imdb_io_call c = call_of(IMDB_IO_WRITE);
    c.fd = fd, c.buf = p, c.len = n, c.off = off;
    long v = io_before(&c);
    if (v < 0) return -1;
    c.len = write_len(&c, v);
    ssize_t r = pwrite(fd, p, c.len, off);
    io_after(&c, (long)r);
    return r;
}

int imdb_io_fsync(int fd)
{
    if (!HOOKED) return fsync(fd);
    imdb_io_call c = call_of(IMDB_IO_FSYNC);
    c.fd = fd;
    if (io_before(&c) < 0) return -1;
    int r = fsync(fd);
    io_after(&c, r);
    return r;
}

int imdb_io_fdatasync(int fd)
{
    if (!HOOKED) return fdatasync(fd);
    imdb_io_call c = call_of(IMDB_IO_FDATASYNC);
    c.fd = fd;
    if (io_before(&c) < 0) return -1;
    int r = fdatasync(fd);
    io_after(&c, r);
    return r;
}

int imdb_io_ftruncate(int fd, off_t len)
{
    if (!HOOKED) return ftruncate(fd, len);
    imdb_io_call c = call_of(IMDB_IO_TRUNCATE);
    c.fd = fd, c.len = (size_t)len;
    if (io_before(&c) < 0) return -1;
    int r = ftruncate(fd, len);
    io_after(&c, r);
    return r;
}

int imdb_io_renameat(int olddirfd, const char *oldname, int newdirfd, const char *newname)
{
    if (!HOOKED) return renameat(olddirfd, oldname, newdirfd, newname);
    imdb_io_call c = call_of(IMDB_IO_RENAME);
    c.dirfd = olddirfd, c.name = oldname, c.dirfd2 = newdirfd, c.name2 = newname;
    if (io_before(&c) < 0) return -1;
    int r = renameat(olddirfd, oldname, newdirfd, newname);
    io_after(&c, r);
    return r;
}

int imdb_io_unlinkat(int dirfd, const char *name, int flags)
{
    if (!HOOKED) return unlinkat(dirfd, name, flags);
    imdb_io_call c = call_of(IMDB_IO_UNLINK);
    c.dirfd = dirfd, c.name = name, c.flags = flags;
    if (io_before(&c) < 0) return -1;
    int r = unlinkat(dirfd, name, flags);
    io_after(&c, r);
    return r;
}

int imdb_io_mkdir(const char *path, int mode) { return imdb_io_mkdirat(AT_FDCWD, path, mode); }

int imdb_io_mkdirat(int dirfd, const char *name, int mode)
{
    if (!HOOKED) return mkdirat(dirfd, name, (mode_t)mode);
    imdb_io_call c = call_of(IMDB_IO_MKDIR);
    c.dirfd = dirfd, c.name = name;
    if (io_before(&c) < 0) return -1;
    int r = mkdirat(dirfd, name, (mode_t)mode);
    io_after(&c, r);
    return r;
}

int imdb_io_fstat(int fd, struct stat *st)
{
    if (!HOOKED) return fstat(fd, st);
    imdb_io_call c = call_of(IMDB_IO_STAT);
    c.fd = fd;
    if (io_before(&c) < 0) return -1;
    int r = fstat(fd, st);
    io_after(&c, r);
    return r;
}

int imdb_io_fstatat(int dirfd, const char *name, struct stat *st, int flags)
{
    if (!HOOKED) return fstatat(dirfd, name, st, flags);
    imdb_io_call c = call_of(IMDB_IO_STAT);
    c.dirfd = dirfd, c.name = name, c.flags = flags;
    if (io_before(&c) < 0) return -1;
    int r = fstatat(dirfd, name, st, flags);
    io_after(&c, r);
    return r;
}

int imdb_io_flock(int fd, int op)
{
    if (!HOOKED) return flock(fd, op);
    imdb_io_call c = call_of(IMDB_IO_LOCK);
    c.fd = fd, c.flags = op;
    if (io_before(&c) < 0) return -1;
    int r = flock(fd, op);
    io_after(&c, r);
    return r;
}

DIR *imdb_io_fdopendir(int fd)
{
    if (!HOOKED) return fdopendir(fd);
    imdb_io_call c = call_of(IMDB_IO_OPENDIR);
    c.fd = fd;
    if (io_before(&c) < 0) return NULL;
    DIR *d = fdopendir(fd);
    io_after(&c, d ? 0 : -1);
    return d;
}

struct dirent *imdb_io_readdir(DIR *d)
{
    errno = 0;
    if (!HOOKED) return readdir(d);
    imdb_io_call c = call_of(IMDB_IO_READDIR);
    c.fd = dirfd(d);
    if (io_before(&c) < 0) return NULL; /* errno set: a failed read of the directory */
    errno = 0;
    struct dirent *de = readdir(d);
    io_after(&c, de ? 1 : 0);
    return de;
}

/* ---- helpers ------------------------------------------------------------------ */

int imdb_write_all(int fd, const void *p, size_t n, imdb_err *e)
{
    const uint8_t *q = p;
    while (n) {
        ssize_t w = imdb_io_write(fd, q, n > (1u << 30) ? (1u << 30) : n);
        if (w < 0) {
            if (errno == EINTR) continue;
            return imdb_fail(e, IMDB_ERR_IO, "write failed: %s", strerror(errno));
        }
        q += w;
        n -= (size_t)w;
    }
    return IMDB_OK;
}

int imdb_pwrite_all(int fd, const void *p, size_t n, int64_t off, imdb_err *e)
{
    const uint8_t *q = p;
    while (n) {
        ssize_t w = imdb_io_pwrite(fd, q, n, (off_t)off);
        if (w < 0) {
            if (errno == EINTR) continue;
            return imdb_fail(e, IMDB_ERR_IO, "write failed: %s", strerror(errno));
        }
        if (w == 0) return imdb_fail(e, IMDB_ERR_IO, "write failed: no progress");
        q += w;
        off += w;
        n -= (size_t)w;
    }
    return IMDB_OK;
}

int imdb_read_all(int fd, void *p, size_t n, size_t *got, imdb_err *e)
{
    uint8_t *q = p;
    size_t done = 0;
    while (done < n) {
        ssize_t r = imdb_io_read(fd, q + done, n - done);
        if (r < 0) {
            if (errno == EINTR) continue;
            return imdb_fail(e, IMDB_ERR_IO, "read failed: %s", strerror(errno));
        }
        if (r == 0) break;
        done += (size_t)r;
    }
    *got = done;
    return IMDB_OK;
}

int imdb_read_file_at(int dirfd, const char *name, uint8_t **out, size_t *len, size_t max, imdb_err *e)
{
    *out = NULL;
    *len = 0;
    int fd = imdb_io_openat(dirfd, name, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) {
        if (errno == ENOENT) return imdb_fail(e, IMDB_ERR_NOTFOUND, "%s: not found", name);
        if (errno == ELOOP) return imdb_fail(e, IMDB_ERR_INVALID, "%s: refusing to follow a symlink", name);
        return imdb_fail(e, IMDB_ERR_IO, "%s: open failed: %s", name, strerror(errno));
    }
    struct stat st;
    if (imdb_io_fstat(fd, &st) != 0) {
        close(fd);
        return imdb_fail(e, IMDB_ERR_IO, "%s: fstat failed: %s", name, strerror(errno));
    }
    if (!S_ISREG(st.st_mode)) {
        close(fd);
        return imdb_fail(e, IMDB_ERR_INVALID, "%s: not a regular file", name);
    }
    if ((uint64_t)st.st_size > max) {
        close(fd);
        return imdb_fail(e, IMDB_ERR_LIMIT, "%s: file larger than %zu bytes", name, max);
    }
    size_t n = (size_t)st.st_size;
    uint8_t *buf = imdb_alloc(n ? n : 1, e);
    if (!buf) {
        close(fd);
        return e->code;
    }
    size_t got;
    int rc = imdb_read_all(fd, buf, n, &got, e);
    close(fd);
    if (rc) {
        imdb_free(buf);
        return rc;
    }
    *out = buf;
    *len = got; /* a concurrently growing file is read up to its size at fstat */
    return IMDB_OK;
}

int imdb_sync_dir(int dirfd, imdb_err *e)
{
    if (imdb_io_fsync(dirfd) != 0) return imdb_fail(e, IMDB_ERR_IO, "fsync(dir) failed: %s", strerror(errno));
    return IMDB_OK;
}

int imdb_create_file_excl(int dirfd, const char *name, const void *p, size_t n, int mode, imdb_err *e)
{
    int fd = imdb_io_openat(dirfd, name, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, mode);
    if (fd < 0) return imdb_fail(e, IMDB_ERR_IO, "%s: create failed: %s", name, strerror(errno));
    int rc = imdb_write_all(fd, p, n, e);
    if (!rc && imdb_io_fsync(fd) != 0) rc = imdb_fail(e, IMDB_ERR_IO, "%s: fsync failed: %s", name, strerror(errno));
    close(fd);
    return rc;
}

int imdb_write_file_atomic(int dirfd, const char *name, const void *p, size_t n, int mode, imdb_err *e)
{
    char tmp[128];
    int len = snprintf(tmp, sizeof tmp, "%s.tmp", name);
    if (len < 0 || (size_t)len >= sizeof tmp) return imdb_fail(e, IMDB_ERR_INVALID, "file name too long");
    imdb_io_unlinkat(dirfd, tmp, 0); /* stale temp from a crash; never a symlink target */
    int fd = imdb_io_openat(dirfd, tmp, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, mode);
    if (fd < 0) return imdb_fail(e, IMDB_ERR_IO, "%s: create failed: %s", tmp, strerror(errno));
    int rc = imdb_write_all(fd, p, n, e);
    if (!rc && imdb_io_fsync(fd) != 0) rc = imdb_fail(e, IMDB_ERR_IO, "%s: fsync failed: %s", tmp, strerror(errno));
    close(fd);
    if (!rc && imdb_io_renameat(dirfd, tmp, dirfd, name) != 0)
        rc = imdb_fail(e, IMDB_ERR_IO, "%s: rename failed: %s", name, strerror(errno));
    if (rc) {
        imdb_io_unlinkat(dirfd, tmp, 0);
        return rc;
    }
    return imdb_sync_dir(dirfd, e);
}

int imdb_open_dir_at(int dirfd, const char *name, imdb_err *e)
{
    int fd = imdb_io_openat(dirfd, name, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return imdb_fail(e, IMDB_ERR_IO, "%s: cannot open directory: %s", name, strerror(errno));
    return fd;
}

int imdb_open_parent(const char *path, const char **base, imdb_err *e)
{
    char dir[4096];
    size_t n = strlen(path);
    const char *slash = strrchr(path, '/');
    if (!n || n >= sizeof dir || (slash && !slash[1])) return imdb_fail(e, IMDB_ERR_INVALID, "not a file path: \"%s\"", path);
    if (slash == path) memcpy(dir, "/", 2);
    else if (slash) snprintf(dir, sizeof dir, "%.*s", (int)(slash - path), path);
    else memcpy(dir, ".", 2);
    int fd = imdb_io_open(dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (fd < 0) return imdb_fail(e, IMDB_ERR_IO, "the directory of %s: %s", path, strerror(errno));
    *base = slash ? slash + 1 : path;
    return fd;
}
