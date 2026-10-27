/*
 * File-system helpers. Every path is resolved relative to the data-directory
 * fd with O_NOFOLLOW, names are fixed strings or validated object ids, and
 * replacement is always write-temp -> fsync -> rename -> fsync(dir).
 * (PostgreSQL CVE-2026-6475: pg_basebackup/pg_rewind followed symlinks.)
 */
#ifndef IMDB_FSIO_H
#define IMDB_FSIO_H

#include <dirent.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "util.h"

/* Every system call the engine makes on files goes through these wrappers
 * (`make lint` refuses the raw calls elsewhere in src/), so the tests can fail,
 * shorten or crash any one of them deterministically (deferred.md R7). Each
 * behaves exactly like the call it wraps. */
int imdb_io_open(const char *path, int flags, ...);
int imdb_io_openat(int dirfd, const char *name, int flags, ...);
ssize_t imdb_io_read(int fd, void *p, size_t n);
ssize_t imdb_io_pread(int fd, void *p, size_t n, off_t off);
ssize_t imdb_io_write(int fd, const void *p, size_t n);
ssize_t imdb_io_pwrite(int fd, const void *p, size_t n, off_t off);
int imdb_io_fsync(int fd);
int imdb_io_fdatasync(int fd);
int imdb_io_ftruncate(int fd, off_t len);
int imdb_io_renameat(int olddirfd, const char *oldname, int newdirfd, const char *newname);
int imdb_io_unlinkat(int dirfd, const char *name, int flags);
int imdb_io_mkdir(const char *path, int mode);
int imdb_io_mkdirat(int dirfd, const char *name, int mode);
int imdb_io_fstat(int fd, struct stat *st);
int imdb_io_fstatat(int dirfd, const char *name, struct stat *st, int flags);
int imdb_io_flock(int fd, int op);
DIR *imdb_io_fdopendir(int fd);
/* NULL at the end, or on an error with errno set (errno is cleared first). */
struct dirent *imdb_io_readdir(DIR *d);

/* ---- fault injection (tests only; deferred.md R7) ------------------------------
 * With hooks installed, every wrapped call above and every allocation by util.c's
 * helpers is described to `before` first. It returns 0 to let the call happen, or
 * -1 with errno set to fail it without making it; for a write, a length below
 * c->len makes a short write of that many bytes. It may also end the process: a
 * crash at that call. `after` sees each call that was made, with its result.
 * Production installs none: each wrapper then costs one load and one branch.
 * Install hooks only while no other thread uses the engine (the tests do it in a
 * forked child, where the worker pool runs inline). */
enum {
    IMDB_IO_OPEN = 1,
    IMDB_IO_READ,
    IMDB_IO_WRITE,
    IMDB_IO_FSYNC,
    IMDB_IO_FDATASYNC,
    IMDB_IO_TRUNCATE,
    IMDB_IO_RENAME,
    IMDB_IO_UNLINK,
    IMDB_IO_MKDIR,
    IMDB_IO_STAT,
    IMDB_IO_LOCK,
    IMDB_IO_OPENDIR,
    IMDB_IO_READDIR,
    IMDB_IO_ALLOC,
};

typedef struct imdb_io_call {
    int op;
    int fd;            /* the file or directory acted on, or -1 */
    int dirfd;         /* the directory of name (AT_FDCWD for a path), or -1 */
    const char *name;  /* a name or path, or NULL */
    int dirfd2;        /* rename: the new name's directory */
    const char *name2; /* rename: the new name */
    const void *buf;   /* write: the bytes */
    size_t len;        /* read and write: the length; truncate: the new size; alloc: the bytes */
    int64_t off;       /* pread and pwrite: the offset, else -1 */
    int flags;         /* open and unlinkat flags, the flock operation */
} imdb_io_call;

typedef struct imdb_io_hooks {
    long (*before)(imdb_io_call *c, void *ctx);
    void (*after)(const imdb_io_call *c, long result, void *ctx);
    void *ctx;
} imdb_io_hooks;

/* NULL removes the hooks. */
void imdb_io_set_hooks(const imdb_io_hooks *h);
extern const imdb_io_hooks *imdb_io_hooks_on;
/* For util.c: true if the hooks fail an allocation of n bytes. */
bool imdb_io_fail_alloc(size_t n);

int imdb_write_all(int fd, const void *p, size_t n, imdb_err *e);
/* All n bytes at off: a short write continues where it stopped. */
int imdb_pwrite_all(int fd, const void *p, size_t n, int64_t off, imdb_err *e);
int imdb_read_all(int fd, void *p, size_t n, size_t *got, imdb_err *e);
/* Reads a whole regular file (not a symlink, not a device) of at most max bytes. */
int imdb_read_file_at(int dirfd, const char *name, uint8_t **out, size_t *len, size_t max, imdb_err *e);
/* Atomically replaces dirfd/name with the given bytes. */
int imdb_write_file_atomic(int dirfd, const char *name, const void *p, size_t n, int mode, imdb_err *e);
/* Creates dirfd/name exclusively; fails if it exists. */
int imdb_create_file_excl(int dirfd, const char *name, const void *p, size_t n, int mode, imdb_err *e);
int imdb_sync_dir(int dirfd, imdb_err *e);
/* Opens a subdirectory without following symlinks. */
int imdb_open_dir_at(int dirfd, const char *name, imdb_err *e);
/* The directory holding an operator's path outside the data directory (the anchor, the root key
 * and its ledger, recover's saved tail), to create the file in and to sync its new name; *base is
 * the path's last component, which the caller opens O_NOFOLLOW. The directory itself may be
 * reached through a symlink: it is the operator's choice. */
int imdb_open_parent(const char *path, const char **base, imdb_err *e);

#endif
