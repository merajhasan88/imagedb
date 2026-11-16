/* N1b: imagedb-server DIR --socket PATH --server-dir SDIR [--max-conns N] [--nosync] [--durable-ack]
 *                      [--events FILE] [--stats FILE]
 * Serves the database DIR on a Unix-domain socket (srv.h; docs/n1-design.md §5). SDIR is the server's own directory,
 * outside DIR (format 1 gains no file): its secret, 32 random bytes made once (0600, synced with its directory) behind
 * an unknown name's salt. SIGTERM or SIGINT stops it: no new connection, running statements end (a second signal
 * cancels them), open transactions rolled back, the database closed durable. A failed handle (a failed sync) stops it with exit status 1, for its
 * supervisor to restart it (the reopen decides, as the watermark rules say). A replica's directory is refused. */
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "../src/db.h"
#include "../src/fsio.h"
#include "srv.h"

static int usage(void)
{
    fputs("usage: imagedb-server DIR --socket PATH --server-dir SDIR [--max-conns N] [--nosync] [--durable-ack]\n"
          "                      [--events FILE] [--stats FILE]\n", stderr);
    return 2;
}

/* SDIR/secret: read when it is there (exactly 32 bytes), else made exclusively (0600) and its directory synced */
static int load_secret(const char *sdir, uint8_t out[IMDBW_KEY], imdb_err *e)
{
    char path[4096];
    if ((size_t)snprintf(path, sizeof path, "%s/secret", sdir) >= sizeof path) return imdb_fail(e, IMDB_ERR_INVALID, "--server-dir too long");
    const char *base;
    int dfd = imdb_open_parent(path, &base, e);
    if (dfd < 0) return e->code;
    uint8_t *buf = NULL;
    size_t len = 0;
    int rc = imdb_read_file_at(dfd, base, &buf, &len, 64, e);
    if (!rc) {
        if (len != IMDBW_KEY) rc = imdb_fail(e, IMDB_ERR_CORRUPT, "%s: not a server secret (%zu bytes, not 32)", path, len);
        else memcpy(out, buf, IMDBW_KEY);
        imdb_wipe(buf, len);
        imdb_free(buf);
    } else if (rc == IMDB_ERR_NOTFOUND) {
        imdb_err_clear(e);
        rc = imdb_random(out, IMDBW_KEY, e);
        if (!rc) rc = imdb_create_file_excl(dfd, base, out, IMDBW_KEY, 0600, e);
        if (!rc) rc = imdb_sync_dir(dfd, e);
    }
    close(dfd);
    return rc;
}

int main(int argc, char **argv)
{
    const char *dir = NULL, *sock = NULL, *sdir = NULL, *events = NULL, *stats = NULL;
    imdbs_opts so;
    memset(&so, 0, sizeof so);
    int sync = 1;
    bool durable_ack = false;
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--socket") && i + 1 < argc) sock = argv[++i];
        else if (!strcmp(argv[i], "--server-dir") && i + 1 < argc) sdir = argv[++i];
        else if (!strcmp(argv[i], "--events") && i + 1 < argc) events = argv[++i]; /* the engine's event log (P1 M2) */
        else if (!strcmp(argv[i], "--stats") && i + 1 < argc) stats = argv[++i];   /* the engine's stats export (P1 M1) */
        else if (!strcmp(argv[i], "--max-conns") && i + 1 < argc) {
            char *end;
            unsigned long v = strtoul(argv[++i], &end, 10);
            if (*end || !v || v > 65536) return usage();
            so.max_conns = (uint32_t)v;
        } else if (!strcmp(argv[i], "--nosync")) sync = 0;
        else if (!strcmp(argv[i], "--durable-ack")) durable_ack = true;
        else if (argv[i][0] == '-' || dir) return usage();
        else dir = argv[i];
    }
    if (!dir || !sock || !sdir) return usage();
    /* every thread the server starts inherits these blocked: the main thread alone takes them, by sigtimedwait */
    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, SIGTERM);
    sigaddset(&set, SIGINT);
    pthread_sigmask(SIG_BLOCK, &set, NULL);
    signal(SIGPIPE, SIG_IGN);
    imdb_err e = {0};
    if (load_secret(sdir, so.secret, &e)) {
        fprintf(stderr, "imagedb-server: the server directory's secret: %s\n", e.msg);
        return 1;
    }
    imdb_open_opts o = {.sync = sync, .durable_ack = durable_ack, .events_path = events, .stats_path = stats};
    imdb_db *db = NULL;
    if (imdb_open(dir, &o, &db, &e)) {
        fprintf(stderr, "imagedb-server: %s\n", e.msg);
        return 1;
    }
    if (db->replica) {
        fprintf(stderr, "imagedb-server: %s is a replica: a read-only server of one is a later step\n", dir);
        imdb_close(db);
        return 1;
    }
    so.socket_path = sock;
    imdbs *s = NULL;
    if (imdbs_start(db, &so, &s, &e)) {
        fprintf(stderr, "imagedb-server: %s\n", e.msg);
        imdb_close(db);
        return 1;
    }
    printf("imagedb-server: listening on %s\n", sock);
    fflush(stdout);
    bool failed = false, stopping = false;
    for (;;) { /* the first signal begins the stop (the running statement ends at its own end); a second cancels it */
        struct timespec ts = {0, 200 * 1000000L};
        int sig = sigtimedwait(&set, NULL, &ts);
        if (sig == SIGTERM || sig == SIGINT) {
            if (!stopping) imdbs_stop_begin(s);
            else imdbs_cancel_all(s);
            stopping = true;
        }
        if (stopping && imdbs_stop_ready(s)) break;
        if (!stopping && imdbs_failed(s)) {
            failed = true;
            break;
        }
    }
    imdb_err es = {0};
    if (imdbs_stop(s, &es)) failed = true;
    imdb_close(db);
    if (failed) fprintf(stderr, "imagedb-server: %s\n", es.msg[0] ? es.msg : "the database handle failed");
    return failed ? 1 : 0;
}
