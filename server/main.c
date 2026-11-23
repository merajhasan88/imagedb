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
#include <sys/resource.h>
#include <sys/stat.h>
#include <unistd.h>

#include "../src/db.h"
#include "../cli/size.h"
#include "../src/fsio.h"
#include "srv.h"
#include "tls.h"

static int usage(void)
{
    fputs("usage: imagedb-server DIR --socket PATH --server-dir SDIR [--max-conns N] [--nosync] [--durable-ack]\n"
          "                      [--events FILE] [--stats FILE] [--tcp ADDR:PORT] [--spool-dir DIR]\n"
          "                      [--mem-limit BYTES] [--seg-cache BYTES|all] [--iceberg] [--anchor FILE]\n"
          "                      [--copy-spool BYTES] [--copy-ring BYTES] [--copy-wait MS] [--copy-idle MS]\n"
          "                      [--channel-binding exporter|any] [--role-statement-timeout MS]\n"
          "                      [--role-transaction-timeout MS] [--role-idle-in-transaction MS] [--role-row-limit N]\n"
          "                      [--role-prepared-bytes BYTES] [--role-conns N] [--superuser-reserve N]\n"
          "                      [--role-queue-bytes BYTES] [--role-reply-bytes BYTES] [--preauth-max N]\n"
          "                      [--preauth-timeout MS] [--preauth-per-addr N] [--socket-reserve N] [--slice-ms MS]\n"
          "                      [--queue-max N] [--send-timeout MS] [--conn-cap BYTES] [--reply-budget BYTES]\n"
          "                      [--role-copy-spool BYTES] [--role-slow-statement-ms MS] [--role-idle-session MS]\n"
          "                      [--disk-headroom BYTES]\n"
          "       imagedb-server cert SDIR [--name NAME]... [--renew]\n", stderr);
    return 2;
}

/* N1d: a size: digits, then K, M or G (binary) or none: within [lo, hi] */
static bool parse_bytes(const char *s, uint64_t lo, uint64_t hi, uint64_t *out)
{
    char *end;
    errno = 0;
    unsigned long long v = strtoull(s, &end, 10);
    if (errno || end == s || *s == '-') return false;
    unsigned sh = *end == 'K' ? 10 : *end == 'M' ? 20 : *end == 'G' ? 30 : 0;
    if (sh) end++;
    if (*end || v > (UINT64_MAX >> sh)) return false;
    v <<= sh;
    if (v < lo || v > hi) return false;
    *out = v;
    return true;
}

/* N1d: milliseconds within [lo, hi] */
static bool parse_ms(const char *s, uint32_t lo, uint32_t hi, uint32_t *out)
{
    char *end;
    errno = 0;
    unsigned long v = strtoul(s, &end, 10);
    if (errno || end == s || *end || *s == '-' || v < lo || v > hi) return false;
    *out = (uint32_t)v;
    return true;
}

/* SDIR/secret: read when it is there (exactly 32 bytes), else made exclusively (0600) and its directory synced */
static int load_secret(const char *sdir, uint8_t out[IMDBW_KEY], imdb_err *e)
{
    char path[4096];
    if ((size_t)snprintf(path, sizeof path, "%s/secret", sdir) >= sizeof path) return imdb_fail(e, IMDB_ERR_INVALID, "--server-dir too long");
    const char *base;
    int dfd = imdb_open_parent(path, &base, e);
    if (dfd < 0) return e->code;
    int rc = IMDB_OK;
    int fd = imdb_io_openat(dfd, base, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd >= 0) { /* the one opened, read by its descriptor: 32 bytes, refused when its group or the world may read it */
        struct stat st;
        size_t got = 0;
        if (imdb_io_fstat(fd, &st) || !S_ISREG(st.st_mode) || st.st_size != IMDBW_KEY)
            rc = imdb_fail(e, IMDB_ERR_CORRUPT, "%s: not a server secret (32 bytes)", path);
        else if (st.st_mode & 077)
            rc = imdb_fail(e, IMDB_ERR_STATE, "%s: readable by its group or the world (chmod 600)", path);
        else if (!(rc = imdb_read_all(fd, out, IMDBW_KEY, &got, e)) && got != IMDBW_KEY)
            rc = imdb_fail(e, IMDB_ERR_IO, "%s: read short", path);
        close(fd);
    } else if (errno == ENOENT) { /* made once: 32 random bytes, 0600, its directory synced */
        rc = imdb_random(out, IMDBW_KEY, e);
        if (!rc) rc = imdb_create_file_excl(dfd, base, out, IMDBW_KEY, 0600, e);
        if (!rc) rc = imdb_sync_dir(dfd, e);
    } else {
        rc = imdb_fail(e, IMDB_ERR_IO, "%s: %s", path, strerror(errno));
    }
    close(dfd);
    return rc;
}


/* N1c: imagedb-server cert SDIR [--name NAME]... [--renew]: the private CA and the server's certificate (tls.h), or the
 * certificate made again under the same CA from the same key; prints the pin either way (the server key's SPKI SHA-256,
 * unchanged by a renewal) */
static int cert_cmd(int argc, char **argv)
{
    const char *sdir = NULL, *names[64];
    size_t n = 0;
    bool renew = false;
    for (int i = 2; i < argc; i++) {
        if (!strcmp(argv[i], "--name") && i + 1 < argc && n < 64) names[n++] = argv[++i];
        else if (!strcmp(argv[i], "--renew")) renew = true;
        else if (argv[i][0] == '-' || sdir) return usage();
        else sdir = argv[i];
    }
    if (!sdir || (renew && n)) return usage();
    uint8_t pin[32];
    imdb_err e = {0};
    if (renew ? imdbt_cert_renew(sdir, pin, &e) : imdbt_cert_make(sdir, names, n, pin, &e)) {
        fprintf(stderr, "imagedb-server cert: %s\n", e.msg);
        return 1;
    }
    char hex[65];
    for (int k = 0; k < 32; k++) snprintf(hex + 2 * k, 3, "%02x", pin[k]);
    printf("%s %s/tls/server.crt; its pin (the key's SPKI SHA-256): %s\n", renew ? "renewed" : "made", sdir, hex);
    return 0;
}
int main(int argc, char **argv)
{
    if (argc >= 2 && !strcmp(argv[1], "cert")) return cert_cmd(argc, argv);
    const char *dir = NULL, *sock = NULL, *sdir = NULL, *events = NULL, *stats = NULL, *tcp = NULL;
    imdbs_opts so;
    memset(&so, 0, sizeof so);
    so.disk_headroom = 1ull << 30; /* 2b-3: imagedb-server's default (the API's none) */
    so.say_disk = true;
    int sync = 1;
    bool durable_ack = false;
    uint64_t mem_limit = 0, seg_cache = 0;
    bool iceberg = false;
    const char *anchor = NULL;
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--socket") && i + 1 < argc) sock = argv[++i];
        else if (!strcmp(argv[i], "--server-dir") && i + 1 < argc) sdir = argv[++i];
        else if (!strcmp(argv[i], "--tcp") && i + 1 < argc) tcp = argv[++i]; /* N1c: TLS 1.3 on TCP beside the socket */
        else if (!strcmp(argv[i], "--events") && i + 1 < argc) events = argv[++i]; /* the engine's event log (P1 M2) */
        else if (!strcmp(argv[i], "--stats") && i + 1 < argc) stats = argv[++i];   /* the engine's stats export (P1 M1) */
        else if (!strcmp(argv[i], "--max-conns") && i + 1 < argc) {
            char *end;
            unsigned long v = strtoul(argv[++i], &end, 10);
            if (*end || !v || v > 65536) return usage();
            so.max_conns = (uint32_t)v;
        } else if (!strcmp(argv[i], "--spool-dir") && i + 1 < argc) so.spool_dir = argv[++i]; /* N1d: COPY's spool */
        else if (!strcmp(argv[i], "--copy-spool") && i + 1 < argc) {
            if (!parse_bytes(argv[++i], 1u << 20, 1ull << 40, &so.copy_spool)) return usage();
        } else if (!strcmp(argv[i], "--copy-ring") && i + 1 < argc) {
            if (!parse_bytes(argv[++i], 64u << 10, 64ull << 30, &so.copy_ring)) return usage();
        } else if (!strcmp(argv[i], "--copy-wait") && i + 1 < argc) {
            if (!parse_ms(argv[++i], 1, 3600000, &so.copy_wait_ms)) return usage();
        } else if (!strcmp(argv[i], "--copy-idle") && i + 1 < argc) {
            if (!parse_ms(argv[++i], 100, 3600000, &so.copy_idle_ms)) return usage();
        } else if (!strcmp(argv[i], "--channel-binding") && i + 1 < argc) { /* §8f: the exporter alone by default */
            const char *v = argv[++i];
            if (!strcmp(v, "any")) so.cb_any = true;
            else if (strcmp(v, "exporter")) return usage();
        } else if ((!strcmp(argv[i], "--role-statement-timeout") || !strcmp(argv[i], "--role-transaction-timeout") ||
                    !strcmp(argv[i], "--role-idle-in-transaction")) &&
                   i + 1 < argc) { /* N1e stage two: a role's caps; 0 none */
            uint32_t *f = argv[i][7] == 's' ? &so.role_stmt_ms : argv[i][7] == 't' ? &so.role_txn_ms : &so.role_idle_ms;
            if (!parse_ms(argv[++i], 0, 86400000, f)) return usage();
            if (!*f) *f = IMDBS_NONE;
        } else if (!strcmp(argv[i], "--role-slow-statement-ms") && i + 1 < argc) { /* 2b-2b: 0 none */
            if (!parse_ms(argv[++i], 0, 86400000, &so.role_slow_ms)) return usage();
        } else if (!strcmp(argv[i], "--role-idle-session") && i + 1 < argc) { /* 2b-2b: 0 none, else 1 s at least */
            if (!parse_ms(argv[++i], 0, 86400000, &so.role_sess_idle_ms) || (so.role_sess_idle_ms && so.role_sess_idle_ms < 1000))
                return usage();
        } else if (!strcmp(argv[i], "--role-row-limit") && i + 1 < argc) {
            if (!parse_bytes(argv[++i], 0, 1000000000000ull, &so.role_row_limit) || strpbrk(argv[i], "KMG")) return usage();
        } else if (!strcmp(argv[i], "--role-prepared-bytes") && i + 1 < argc) {
            if (!parse_bytes(argv[++i], 64u << 10, 64ull << 20, &so.role_prep_bytes)) return usage();
        } else if ((!strcmp(argv[i], "--role-conns") || !strcmp(argv[i], "--superuser-reserve")) && i + 1 < argc) {
            uint32_t *f = argv[i][2] == 'r' ? &so.role_conns : &so.su_reserve; /* N1e stage two; 0: none */
            if (!parse_ms(argv[++i], 0, 65536, f)) return usage();
            if (!*f) *f = IMDBS_NONE;
        } else if ((!strcmp(argv[i], "--role-queue-bytes") || !strcmp(argv[i], "--role-reply-bytes")) && i + 1 < argc) {
            uint64_t *f = argv[i][7] == 'q' ? &so.role_queue_bytes : &so.role_reply_bytes; /* 0: none */
            if (!parse_bytes(argv[++i], 0, 64ull << 30, f)) return usage();
            if (!*f) *f = IMDBS_NONE;
        } else if (!strcmp(argv[i], "--disk-headroom") && i + 1 < argc) { /* 2b-3; 0: none */
            if (!parse_bytes(argv[++i], 0, 1ull << 50, &so.disk_headroom)) return usage();
        } else if (!strcmp(argv[i], "--role-copy-spool") && i + 1 < argc) { /* 2b-2a; 0: none */
            if (!parse_bytes(argv[++i], 0, 1ull << 40, &so.role_copy_spool)) return usage();
            if (!so.role_copy_spool) so.role_copy_spool = IMDBS_NONE;
        } else if (!strcmp(argv[i], "--preauth-max") && i + 1 < argc) { /* N1e stage two: the server's constants */
            if (!parse_ms(argv[++i], 1, 4096, &so.preauth_max)) return usage();
        } else if (!strcmp(argv[i], "--preauth-timeout") && i + 1 < argc) {
            if (!parse_ms(argv[++i], 100, 600000, &so.preauth_ms)) return usage();
        } else if (!strcmp(argv[i], "--preauth-per-addr") && i + 1 < argc) {
            if (!parse_ms(argv[++i], 1, 4096, &so.preauth_per_addr)) return usage();
        } else if (!strcmp(argv[i], "--socket-reserve") && i + 1 < argc) {
            if (!parse_ms(argv[++i], 1, 65536, &so.socket_reserve)) return usage();
        } else if (!strcmp(argv[i], "--slice-ms") && i + 1 < argc) {
            if (!parse_ms(argv[++i], 1, 10000, &so.slice_ms)) return usage();
        } else if (!strcmp(argv[i], "--queue-max") && i + 1 < argc) {
            if (!parse_ms(argv[++i], 1, 4096, &so.queue_max)) return usage();
        } else if (!strcmp(argv[i], "--send-timeout") && i + 1 < argc) {
            if (!parse_ms(argv[++i], 1000, 3600000, &so.send_timeout_ms)) return usage();
        } else if (!strcmp(argv[i], "--conn-cap") && i + 1 < argc) {
            if (!parse_bytes(argv[++i], 64u << 10, 64ull << 30, &so.conn_cap)) return usage();
        } else if (!strcmp(argv[i], "--reply-budget") && i + 1 < argc) {
            if (!parse_bytes(argv[++i], 1u << 20, 64ull << 30, &so.reply_budget)) return usage();
        } else if (!strcmp(argv[i], "--mem-limit") && i + 1 < argc) {
            if (!parse_size(argv[++i], &mem_limit)) return usage();
        } else if (!strcmp(argv[i], "--seg-cache") && i + 1 < argc) {
            if (!parse_seg_cache(argv[++i], &seg_cache)) return usage();
        } else if (!strcmp(argv[i], "--iceberg")) iceberg = true;
        else if (!strcmp(argv[i], "--anchor") && i + 1 < argc) anchor = argv[++i];
        else if (!strcmp(argv[i], "--nosync")) sync = 0;
        else if (!strcmp(argv[i], "--durable-ack")) durable_ack = true;
        else if (argv[i][0] == '-' || dir) return usage();
        else dir = argv[i];
    }
    if (!dir || !sock || !sdir) return usage();
    /* 2b-2b: the descriptors its connections may hold (imdbs_fds_needed): a soft limit short of them raised to the hard
     * one (a unit's default is often 1,024), a hard one short of them a refusal before anything is opened, so a full
     * server never fails an accept or a spool for want of a descriptor */
    {
        uint64_t need = imdbs_fds_needed(&so);
        struct rlimit rl;
        if (getrlimit(RLIMIT_NOFILE, &rl)) {
            fprintf(stderr, "imagedb-server: RLIMIT_NOFILE: %s\n", strerror(errno));
            return 1;
        }
        if (rl.rlim_cur != RLIM_INFINITY && rl.rlim_cur < need) {
            if (rl.rlim_max != RLIM_INFINITY && rl.rlim_max < need) {
                fprintf(stderr, "imagedb-server: --max-conns %u needs about %llu file descriptors, and RLIMIT_NOFILE allows %llu: "
                                "raise it (ulimit -n, a unit's LimitNOFILE=) or lower --max-conns\n",
                        so.max_conns ? so.max_conns : 256u, (unsigned long long)need, (unsigned long long)rl.rlim_max);
                return 1;
            }
            rl.rlim_cur = rl.rlim_max;
            if (setrlimit(RLIMIT_NOFILE, &rl)) {
                fprintf(stderr, "imagedb-server: raising RLIMIT_NOFILE to %llu: %s\n", (unsigned long long)rl.rlim_max, strerror(errno));
                return 1;
            }
        }
    }
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
    imdb_open_opts o = {.sync = sync, .durable_ack = durable_ack, .events_path = events, .stats_path = stats,
                        .mem_limit = mem_limit, .seg_cache_bytes = seg_cache, .iceberg = iceberg, .anchor = anchor};
    imdb_db *db = NULL;
    if (imdb_open(dir, &o, &db, &e)) {
        fprintf(stderr, "imagedb-server: %s\n", e.msg);
        return 1;
    }
    /* the open's warnings, as the CLI's open_anchored prints them (the anchor's, an oversized segment's): a daemon's
     * operator sees them only here */
    if (db->warning[0]) fprintf(stderr, "imagedb-server: warning: %s\n", db->warning);
    if (!db->mem_limit) /* 2c: a role's bounds are charged against the budget: without one, superusers alone log in */
        fprintf(stderr, "imagedb-server: no --mem-limit: only superusers log in (a role that is not a superuser needs the "
                        "memory budget its bounds are charged against)\n");
    /* 2b-3: a reserve below what one automatic CHECKPOINT writes (about the log's checkpoint size and a fill of the log)
     * may not hold the publish an operator's recovery needs */
    uint64_t pub = db->checkpoint_bytes == UINT64_MAX ? 0 : db->checkpoint_bytes + IMDB_LOG_FILL_CHUNK;
    if (so.disk_headroom && so.disk_headroom < pub)
        fprintf(stderr, "imagedb-server: warning: --disk-headroom %llu is below what one automatic CHECKPOINT may write "
                        "(about %llu bytes): the reserve may not hold an operator's recovery\n",
                (unsigned long long)so.disk_headroom, (unsigned long long)pub);
    if (db->replica) {
        fprintf(stderr, "imagedb-server: %s is a replica: a read-only server of one is a later step\n", dir);
        imdb_close(db);
        return 1;
    }
    so.socket_path = sock;
    so.tcp = tcp;
    so.server_dir = sdir;
    imdbs *s = NULL;
    if (imdbs_start(db, &so, &s, &e)) {
        fprintf(stderr, "imagedb-server: %s\n", e.msg);
        imdb_close(db);
        return 1;
    }
    printf("imagedb-server: listening on %s\n", sock);
    if (tcp) {
        printf("imagedb-server: listening on tcp port %u (TLS 1.3)\n", (unsigned)imdbs_tcp_port(s));
        if (imdbs_cert_days(s) < 30)
            fprintf(stderr, "imagedb-server: warning: server.crt has %d days left (imagedb-server cert SDIR --renew)\n",
                    imdbs_cert_days(s));
    }
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
    if (failed) fprintf(stderr, "imagedb-server: %s\n", es.msg[0] ? es.msg : "the database handle failed");
    if (imdb_close(db) != IMDB_OK) {
        fputs("imagedb-server: final database close failed; durability at shutdown is not confirmed\n", stderr);
        failed = true;
    }
    return failed ? 1 : 0;
}
