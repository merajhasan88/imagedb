/* N1d: COPY's spool (docs/n1-design.md §8d): a nameless file per COPY in the server's spool directory, so the engine
 * thread never waits on a client's network: COPY ... FROM STDIN's data is written here whole before the statement runs,
 * and COPY ... TO STDOUT's output is written here as it runs while the connection's thread sends it. The one file of
 * server/ that makes its own file system calls: never fsio's imdb_io_* (whose fault hook is one pointer for the
 * process: a test failing the engine's calls while a server runs never sees a spool's), with a failure hook of its own. */
#ifndef IMDB_SPOOL_H
#define IMDB_SPOOL_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#include "../src/util.h"

typedef struct imdbsp imdbsp;

/* the spool directory: made 0700 when missing, its descriptor returned (one refused when its group or the world may
 * enter it: the spool holds rows) */
int imdbsp_dir(const char *path, int *dfd, imdb_err *e);
/* a file in it with no name (O_TMPFILE; on a file system without it, created under a random name and unlinked at once):
 * a crash leaves nothing */
int imdbsp_open(int dfd, imdbsp **out, imdb_err *e);
/* n bytes at off, whole (a short write retried; a failure an error) */
int imdbsp_write(imdbsp *sp, uint64_t off, const void *p, size_t n, imdb_err *e);
/* up to n bytes at off: > 0 read, 0 past the end, < 0 a failure */
ssize_t imdbsp_read(imdbsp *sp, uint64_t off, void *p, size_t n);
void imdbsp_close(imdbsp *sp);

/* tests: the nth spool call from now fails (an open, a write, a read: ENOSPC, or EIO for a read; 0: none); spools open
 * now; the O_TMPFILE path refused, so the named fallback runs */
void imdbsp_fail_at(int64_t n);
int64_t imdbsp_live(void);
void imdbsp_no_tmpfile(bool on);

#endif
