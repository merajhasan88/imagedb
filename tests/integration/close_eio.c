/* The 2026-11-18 review's close probe (its checks/close_eio.c, taken as given): a test binary's src/main.c or
 * server/main.c is built with -Dimdb_close=review_close, so every close main.c makes comes here, and this one fails the
 * close's first fsync of DURABLE (its last sync) with EIO; every close inside the engine stays real. close_status.sh
 * then holds the CLI and the server to a failed close: exit 1, said, no success printed. Never installed. */
#include "db.h"
#include "fsio.h"
#include <errno.h>
#include <stdio.h>
struct fault { int target; bool fired; };
static long once(imdb_io_call *c, void *ctx)
{
    struct fault *f = ctx;
    if (!f->fired && c->op == IMDB_IO_FSYNC && c->fd == f->target) {
        f->fired = true;
        errno = EIO;
        return -1;
    }
    return 0;
}
int review_close(imdb_db *db);
int review_close(imdb_db *db)
{
    struct fault f = {.target = db->durfd};
    imdb_io_hooks hooks = {.before = once, .ctx = &f};
    imdb_io_set_hooks(&hooks);
    int rc = imdb_close(db);
    imdb_io_set_hooks(NULL);
    if (f.fired) fprintf(stderr, "probe: final DURABLE fsync returned EIO (close rc=%d)\n", rc);
    return rc;
}
