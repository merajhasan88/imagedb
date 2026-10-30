/* imagedb command-line tool. */
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include "cpu.h"
#include "db.h"
#include "fsio.h"
#include "lake.h"
#include "repl.h"
#include "sql.h"
#include "writer.h"

static int usage(void)
{
    fputs("usage:\n"
          "  imagedb init <dir> [--root KEY] [--digest-alg N]\n"
          "                                             create a primary database (KEY: a root key that may\n"
          "                                             certify a promotion; imagedb root-key makes one; N: the\n"
          "                                             state digest's algorithm, 1 or 2, default IMDB_DIGEST_ALG or 2)\n"
          "  imagedb init-replica <dir> <primary-dir>   create a replica (copies the db id and writer public key)\n"
          "  imagedb init-replica <dir> --identity FILE create a replica from a primary's identity file\n"
          "  imagedb identity <dir>                     print the db id and writer public key (no secrets)\n"
          "  imagedb sql <dir> [-c SQL]... [-f FILE] [--csv] [--cross-check] [--nosync] [--lake-sync]\n"
          "                    [--anchor FILE [--accept-rollback]] [--read-only] [--durable-ack] [--mem-limit BYTES]\n"
          "                    [--mem-window SECONDS|none]\n"
          "                                             run SQL (interactive when no -c/-f and stdin is a tty);\n"
          "                                             --durable-ack: the watermark synced as each commit returns,\n"
          "                                             so a damaged last frame past it is known unacknowledged;\n"
          "  imagedb ship <primary-dir> [--after N] [--follow] [--acks]\n"
          "                                             write commits after N to stdout (--acks: read the\n"
          "                                             replica's acknowledgements on stdin)\n"
          "  imagedb apply <replica-dir> [--durable-ack] [--mem-limit BYTES] [--mem-window SECONDS|none]\n"
          "                                             apply a commit stream from stdin\n"
          "  imagedb follow <replica-dir> [--mem-limit BYTES] [--mem-window SECONDS|none] -- CMD [ARG...]\n"
          "                                             run CMD ({after}: the replica's commit), apply its stream,\n"
          "                                             acknowledge on its stdin; run it again when it ends\n"
          "  imagedb replica-key <replica-dir> [--new]  print the replica's public key (made if missing); --new: a\n"
          "                                             new key, a new incarnation (after a restore from a copy)\n"
          "  imagedb replica-add <primary-dir> NAME KEY [--replace]\n"
          "                                             allowlist a replica's key for acknowledgements\n"
          "  imagedb verify <dir> [--anchor FILE]       re-verify log, chain, signatures, digests, erasure, lake\n"
          "  imagedb info <dir>                         head, digest, tables, lake\n"
          "  imagedb recover <dir> [--discard-tail --save FILE]\n"
          "                                             inspect a damaged end of the log; with --discard-tail, cut it\n"
          "                                             (its bytes saved to FILE first) and lower DURABLE to match\n"
          "  imagedb root-key FILE                      make an offline root key (secret, 0400) and print its public key\n"
          "  imagedb rotate-key <dir>                   a new writer key, signed into the log by the current one\n"
          "  imagedb promote <replica-dir> --root-key FILE (--anchor FILE [--abandon] | --old-writer-stopped)\n"
          "                                             make the replica the writer of the next epoch, certified\n"
          "                                             by the root key, on top of its last commit; the old writer\n"
          "                                             must be stopped: the anchor's lock proves it, or you say so\n"
          "  imagedb version\n",
          stderr);
    return 2;
}

static void print_err(const char *what, const imdb_err *e)
{
    fprintf(stderr, "imagedb: %s: %s (%s)\n", what, e->msg[0] ? e->msg : "error", imdb_err_name(e->code));
}

static uint64_t g_mem_limit; /* --mem-limit (db.h: the memory budget), for the command's open */
static uint64_t g_mem_window; /* --mem-window (db.h: the memory window, stage 3b; 0: the default) */

/* SECONDS: decimal digits, no leading zero, at most a century; or none: no version leaves memory */
static bool parse_window(const char *s, uint64_t *out)
{
    if (strcmp(s, "none") == 0) {
        *out = UINT64_MAX;
        return true;
    }
    uint64_t v = 0;
    if (s[0] < '1' || s[0] > '9') return false;
    for (size_t i = 0; s[i]; i++) {
        if (s[i] < '0' || s[i] > '9' || v > 3155760000u) return false;
        v = v * 10 + (uint64_t)(s[i] - '0');
    }
    if (v > 3155760000u) return false;
    *out = v * 1000000u;
    return true;
}

/* BYTES: decimal digits, no leading zero, optionally K, M or G (binary); 0 is no budget, so refused */
static bool parse_size(const char *s, uint64_t *out)
{
    uint64_t v = 0;
    size_t i = 0;
    if (s[0] < '1' || s[0] > '9') return false;
    for (; s[i] >= '0' && s[i] <= '9'; i++) {
        if (v > (UINT64_MAX - 9) / 10) return false;
        v = v * 10 + (uint64_t)(s[i] - '0');
    }
    unsigned shift = s[i] == 'K' ? 10 : s[i] == 'M' ? 20 : s[i] == 'G' ? 30 : 0;
    if (shift) i++;
    if (s[i] || (shift && v > (UINT64_MAX >> shift))) return false;
    *out = v << shift;
    return true;
}

static imdb_db *open_anchored(const char *dir, bool ro, int sync, const char *anchor, bool accept_rollback,
                              bool durable_ack)
{
    imdb_open_opts o = {.sync = sync, .read_only = ro, .anchor = anchor, .accept_rollback = accept_rollback,
                        .durable_ack = durable_ack, .mem_limit = g_mem_limit, .mem_window_us = g_mem_window};
    imdb_db *db;
    imdb_err e = {0};
    if (imdb_open(dir, &o, &db, &e)) {
        print_err("open", &e);
        return NULL;
    }
    if (db->warning[0]) fprintf(stderr, "imagedb: warning: %s\n", db->warning);
    return db;
}

static imdb_db *open_or_die(const char *dir, bool ro, int sync) { return open_anchored(dir, ro, sync, NULL, false, false); }

typedef struct runner {
    imdb_session *ss;
    bool csv;
    int failures;
    bool timing;
    bool stop_on_error;
} runner;

static double now_s(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec * 1e-9;
}

static int run_stmt(void *arg, const char *sql, size_t len)
{
    runner *rn = arg;
    imdb_result r;
    imdb_err e = {0};
    char before[512];
    snprintf(before, sizeof before, "%s", rn->ss->db->warning);
    double t0 = now_s();
    int rc = imdb_exec_one(rn->ss, sql, len, NULL, 0, &r, &e);
    double dt = now_s() - t0;
    if (rc) {
        print_err("error", &e);
        rn->failures++;
        return rn->stop_on_error ? rc : 0;
    }
    imdb_buf out;
    imdb_buf_init(&out);
    imdb_result_render(&r, rn->csv, &out);
    if (out.len) fwrite(out.p, 1, out.len, stdout);
    if (rn->timing) printf("Time: %.3f ms\n", dt * 1000);
    fflush(stdout);
    imdb_buf_free(&out);
    imdb_result_free(&r);
    if (strcmp(before, rn->ss->db->warning) != 0 && rn->ss->db->warning[0])
        fprintf(stderr, "imagedb: warning: %s\n", rn->ss->db->warning);
    return 0;
}

static int run_text(runner *rn, const char *text, size_t len)
{
    imdb_err e = {0};
    int rc = imdb_split_statements(text, len, run_stmt, rn, &e);
    if (rc && e.code) print_err("error", &e);
    return rc;
}

static char *read_all(FILE *f, size_t *len)
{
    size_t cap = 1 << 16, n = 0;
    char *b = imdb_alloc(cap, &(imdb_err){0}); /* the helpers' throughout: imdb_realloc_array credits the old block */
    if (!b) return NULL;
    for (;;) {
        if (n == cap) {
            if (cap >= IMDB_MAX_SQL * 4u) break;
            char *nb = imdb_realloc_array(b, cap, cap * 2, 1, &(imdb_err){0}); /* wipes the old block */
            if (!nb) {
                imdb_wipe(b, cap);
                imdb_free(b);
                return NULL;
            }
            cap *= 2;
            b = nb;
        }
        size_t got = fread(b + n, 1, cap - n, f);
        if (got == 0) break;
        n += got;
    }
    *len = n;
    return b;
}

/* Interactive loop: accumulate lines until a statement-terminating ';'. */
static int repl(runner *rn)
{
    char line[8192];
    imdb_buf acc;
    imdb_buf_init(&acc);
    rn->stop_on_error = false;
    printf("imagedb %s  (\\q to quit, statements end with ;)\n", "0.1");
    for (;;) {
        fputs(acc.len ? "   -> " : "imagedb> ", stdout);
        fflush(stdout);
        if (!fgets(line, sizeof line, stdin)) break;
        if (!acc.len && (strncmp(line, "\\q", 2) == 0 || strncmp(line, "quit", 4) == 0)) break;
        if (!acc.len && strncmp(line, "\\timing", 7) == 0) {
            rn->timing = !rn->timing;
            printf("timing is %s\n", rn->timing ? "on" : "off");
            continue;
        }
        imdb_buf_put_str(&acc, line);
        /* run once the buffer ends with ';' outside a string literal */
        bool in_str = false, done = false;
        for (size_t i = 0; i < acc.len; i++) {
            if (acc.p[i] == '\'') in_str = !in_str;
            if (!in_str && acc.p[i] == ';') done = true;
            if (!in_str && acc.p[i] == '-' && i + 1 < acc.len && acc.p[i + 1] == '-')
                while (i < acc.len && acc.p[i] != '\n') i++;
        }
        if (done && !in_str) {
            run_text(rn, (const char *)acc.p, acc.len);
            acc.len = 0;
        }
    }
    imdb_buf_free(&acc);
    return 0;
}

static int cmd_sql(int argc, char **argv)
{
    if (argc < 3) return usage();
    const char *dir = argv[2];
    bool csv = false, cross = false, lake_sync = false, accept_rollback = false, ro = false, durable_ack = false;
    const char *anchor = NULL;
    int sync = 1;
    for (int i = 3; i < argc; i++) {
        if ((strcmp(argv[i], "-c") == 0 || strcmp(argv[i], "-f") == 0) && i + 1 < argc) i++; /* run below, in order */
        else if (strcmp(argv[i], "--csv") == 0) csv = true;
        else if (strcmp(argv[i], "--cross-check") == 0) cross = true;
        else if (strcmp(argv[i], "--nosync") == 0) sync = 0;
        else if (strcmp(argv[i], "--lake-sync") == 0) lake_sync = true;
        else if (strcmp(argv[i], "--anchor") == 0 && i + 1 < argc) anchor = argv[++i];
        else if (strcmp(argv[i], "--accept-rollback") == 0) accept_rollback = true;
        else if (strcmp(argv[i], "--durable-ack") == 0) durable_ack = true;
        else if (strcmp(argv[i], "--mem-limit") == 0 && i + 1 < argc) {
            if (!parse_size(argv[++i], &g_mem_limit)) {
                fprintf(stderr, "imagedb: sql: --mem-limit takes BYTES (digits, then K, M or G)\n");
                return 2;
            }
        }
        else if (strcmp(argv[i], "--mem-window") == 0 && i + 1 < argc) {
            if (!parse_window(argv[++i], &g_mem_window)) {
                fprintf(stderr, "imagedb: sql: --mem-window takes SECONDS (digits) or none\n");
                return 2;
            }
        }
        else if (strcmp(argv[i], "--read-only") == 0) ro = true; /* e.g. a replica that follow keeps writing */
        else {
            fprintf(stderr, "imagedb: sql: unknown option %s\n", argv[i]);
            return usage();
        }
    }
    imdb_db *db = open_anchored(dir, ro, sync, anchor, accept_rollback, durable_ack);
    if (!db) return 1;
    db->lake_sync = lake_sync && !db->replica; /* replicas follow the primary's logged CHECKPOINTs */
    imdb_session ss;
    imdb_session_init(&ss, db);
    ss.cross_check = cross;
    runner rn = {&ss, csv, 0, false, true};
    int rc = 0;
    bool ran = false;
    for (int i = 3; i < argc && !rc; i++) {
        if (strcmp(argv[i], "-c") == 0 && i + 1 < argc) {
            const char *q = argv[++i];
            rc = run_text(&rn, q, strlen(q));
            ran = true;
        } else if (strcmp(argv[i], "-f") == 0 && i + 1 < argc) {
            FILE *f = strcmp(argv[i + 1], "-") == 0 ? stdin : fopen(argv[i + 1], "rb");
            i++;
            if (!f) {
                fprintf(stderr, "imagedb: cannot open %s: %s\n", argv[i], strerror(errno));
                rc = 1;
                break;
            }
            size_t len;
            char *text = read_all(f, &len);
            if (f != stdin) fclose(f);
            if (!text) {
                rc = 1;
                break;
            }
            rc = run_text(&rn, text, len);
            imdb_wipe(text, len); /* SQL text carries row values */
            imdb_free(text);
            ran = true;
        }
    }
    if (!ran && !rc) {
        if (isatty(0)) {
            repl(&rn);
        } else {
            size_t len;
            char *text = read_all(stdin, &len);
            if (text) {
                rc = run_text(&rn, text, len);
                imdb_wipe(text, len);
            }
            imdb_free(text);
        }
    }
    if (ss.txn.open) fprintf(stderr, "imagedb: open transaction rolled back at exit\n");
    imdb_session_close(&ss);
    if (imdb_close(db) != IMDB_OK) {
        fprintf(stderr, "imagedb: --nosync commits were not made durable at close (the handle had failed or the sync "
                        "failed); an OS crash can lose them\n");
        rc = 1;
    }
    return rc || rn.failures ? 1 : 0;
}

/* ---- follow: a replica that keeps applying, and acknowledges -------------------------------- */

static volatile sig_atomic_t g_stop, g_child;

static void on_stop(int sig)
{
    (void)sig;
    g_stop = 1;
    if (g_child > 0) kill((pid_t)g_child, SIGTERM); /* its stream then ends, and the loop with it */
}

typedef struct follow_ctx {
    int ackfd; /* the shipper's stdin, non-blocking */
    const imdb_signer *key;
    const imdb_apply_opts *ao; /* the session's challenge, once its record arrived */
    bool warned;
} follow_ctx;

/* One acknowledgement (repl.h), signed over the shipping session's challenge: none without one (a
 * shipper without --acks). A full pipe drops it: each one supersedes the last, and the next
 * acknowledgement point sends another; a write of at most PIPE_BUF bytes is never split. */
static int send_ack(void *ctx, imdb_db *db)
{
    follow_ctx *f = ctx;
    if (!f->ao->has_session) {
        if (!f->warned)
            fprintf(stderr, "imagedb: follow: warning: the shipper started no session (is it ship --acks?): no "
                            "acknowledgements\n");
        f->warned = true;
        return 0;
    }
    imdb_ack a = {.seq = db->seq, .cleanup = imdb_cleanup_seq(db), .epoch = imdb_writer_epoch_at(db, db->seq)};
    memcpy(a.nonce, f->ao->nonce, IMDB_NONCE_LEN);
    memcpy(a.db_id, db->db_id, 16);
    memcpy(a.replica, f->key->pk, IMDB_PUBKEY_LEN);
    memcpy(a.head, db->head, 32);
    uint8_t raw[IMDB_ACK_LEN];
    imdb_ack_sign(&a, f->key, raw);
    ssize_t r;
    do r = write(f->ackfd, raw, sizeof raw);
    while (r < 0 && errno == EINTR);
    return 0;
}

/* arg with every {after} replaced by the replica's commit */
static char *subst_after(const char *arg, uint64_t seq)
{
    char num[24];
    int nl = snprintf(num, sizeof num, "%llu", (unsigned long long)seq);
    size_t n = 0;
    for (const char *p = arg; *p;) {
        if (strncmp(p, "{after}", 7) == 0) {
            n += (size_t)nl;
            p += 7;
        } else {
            n++;
            p++;
        }
    }
    char *out = malloc(n + 1), *q = out;
    if (!out) return NULL;
    for (const char *p = arg; *p;) {
        if (strncmp(p, "{after}", 7) == 0) {
            memcpy(q, num, (size_t)nl);
            q += nl;
            p += 7;
        } else {
            *q++ = *p++;
        }
    }
    *q = 0;
    return out;
}

static void describe_exit(int status, char *buf, size_t n)
{
    if (WIFEXITED(status)) snprintf(buf, n, "exited with status %d", WEXITSTATUS(status));
    else if (WIFSIGNALED(status)) snprintf(buf, n, "was killed by signal %d", WTERMSIG(status));
    else snprintf(buf, n, "ended");
}

/* imagedb follow REPLICA -- CMD [ARGS...]: runs CMD (a shipper: `imagedb ship PRIMARY --follow --acks
 * --after {after}`, locally or through ssh), applies what it sends and acknowledges on its stdin;
 * when it ends, runs it again from the replica's commit, backing off from 1 to 30 seconds while
 * nothing arrives. A stream that fails authentication, or a failed handle, stops it. */
static int cmd_follow(int argc, char **argv)
{
    int dd = 3; /* where "--" is, past the options */
    while (dd + 1 < argc && strcmp(argv[dd], "--") != 0) {
        if (strcmp(argv[dd], "--mem-limit") == 0 && parse_size(argv[dd + 1], &g_mem_limit)) dd += 2;
        else if (strcmp(argv[dd], "--mem-window") == 0 && parse_window(argv[dd + 1], &g_mem_window)) dd += 2;
        else if (strcmp(argv[dd], "--mem-limit") != 0 && strcmp(argv[dd], "--mem-window") != 0) return usage();
        else {
            fprintf(stderr, "imagedb: follow: --mem-limit takes BYTES (digits, then K, M or G), --mem-window SECONDS "
                            "or none\n");
            return 2;
        }
    }
    if (argc < dd + 2 || strcmp(argv[dd], "--") != 0) return usage();
    const char *dir = argv[2];
    int ncmd = argc - dd - 1;
    bool has_after = false;
    for (int i = dd + 1; i < argc; i++) has_after |= strstr(argv[i], "{after}") != NULL;
    if (!has_after)
        fprintf(stderr, "imagedb: follow: warning: the command has no {after}; it must start after the replica's commit\n");
    imdb_err e = {0};
    imdb_signer key;
    bool created;
    if (imdb_replica_key(dir, false, &key, &created, &e)) {
        print_err("follow", &e);
        return 1;
    }
    imdb_db *db = open_or_die(dir, false, 0); /* --nosync: every acknowledgement point syncs first */
    if (!db || !db->replica) {
        if (db) fprintf(stderr, "imagedb: follow: %s is not a replica\n", dir);
        imdb_close(db);
        imdb_signer_wipe(&key);
        return 1;
    }
    signal(SIGPIPE, SIG_IGN);
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_stop;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    unsigned backoff = 1;
    int rc = 0;
    while (!g_stop) {
        char **av = calloc((size_t)ncmd + 1, sizeof *av);
        bool ok = av != NULL;
        for (int i = 0; ok && i < ncmd; i++) ok = (av[i] = subst_after(argv[dd + 1 + i], db->seq)) != NULL;
        int in[2] = {-1, -1}, out[2] = {-1, -1};
        if (!ok || pipe2(in, O_CLOEXEC) != 0 || pipe2(out, O_CLOEXEC) != 0) {
            fprintf(stderr, "imagedb: follow: %s\n", ok ? strerror(errno) : "out of memory");
            rc = 1;
        }
        pid_t pid = rc ? -1 : fork();
        if (pid == 0) {
            signal(SIGPIPE, SIG_DFL);
            signal(SIGINT, SIG_DFL);
            signal(SIGTERM, SIG_DFL);
            if (dup2(in[1], 1) < 0 || dup2(out[0], 0) < 0) _exit(127);
            execvp(av[0], av);
            fprintf(stderr, "imagedb: follow: cannot run %s: %s\n", av[0], strerror(errno));
            _exit(127);
        }
        if (!rc && pid < 0) {
            fprintf(stderr, "imagedb: follow: fork: %s\n", strerror(errno));
            rc = 1;
        }
        for (int i = 0; av && i < ncmd; i++) free(av[i]);
        free(av);
        if (rc) {
            for (int i = 0; i < 2; i++) {
                if (in[i] >= 0) close(in[i]);
                if (out[i] >= 0) close(out[i]);
            }
            break;
        }
        g_child = pid;
        close(in[1]);
        close(out[0]);
        (void)fcntl(out[1], F_SETFL, O_NONBLOCK);
        imdb_apply_opts ao = {.applied = send_ack}; /* its first point: right after the session record */
        follow_ctx f = {.ackfd = out[1], .key = &key, .ao = &ao};
        ao.ctx = &f;
        uint64_t applied = 0;
        imdb_err ea = {0};
        int arc = imdb_apply_stream_ex(db, in[0], &applied, &ao, &ea);
        if (arc) kill(pid, SIGTERM);
        close(in[0]);
        close(out[1]);
        int status = 0;
        while (waitpid(pid, &status, 0) < 0 && errno == EINTR) {
        }
        g_child = 0;
        if (ao.seeded || (arc && ao.truncated && db->failed && !db->seq)) {
            /* a seed taken (or cut short: the reopen removes what it left): its snapshot, then ship from there */
            if (ao.seeded) fprintf(stderr, "imagedb: follow: seeded at commit %llu\n", (unsigned long long)ao.seeded);
            if (imdb_close(db)) rc = 1;
            db = open_or_die(dir, false, 0);
            if (!db) {
                rc = 1;
                break;
            }
            if (ao.seeded) continue;
        }
        if (arc && (!ao.truncated || db->failed)) { /* hostile, diverged, or a failed handle: not a dropped connection */
            print_err("follow", &ea);
            rc = 1;
            break;
        }
        if (g_stop) break;
        char how[64];
        describe_exit(status, how, sizeof how);
        if (applied) backoff = 1;
        fprintf(stderr, "imagedb: follow: the shipper %s%s%s; replica at commit %llu (%llu applied); again in %us\n", how,
                arc ? ": " : "", arc ? ea.msg : "", (unsigned long long)db->seq, (unsigned long long)applied, backoff);
        struct timespec ts = {(time_t)backoff, 0};
        nanosleep(&ts, NULL); /* a signal cuts it short */
        backoff = backoff >= 16 ? 30 : backoff * 2;
    }
    imdb_signer_wipe(&key);
    if (imdb_close(db)) rc = 1;
    return rc;
}

static void print_info(imdb_db *db)
{
    char hex[65];
    imdb_hex(db->head, 32, hex);
    printf("commit     %llu\nhead       %s\n", (unsigned long long)db->seq, hex);
    uint8_t d[32];
    imdb_state_digest(db, NULL, d);
    imdb_hex(d, 32, hex);
    printf("digest     %s\nrole       %s\n", hex, db->replica ? "replica" : "primary");
    printf("algorithm  digest_alg %u (%s)\n", (unsigned)db->meta.digest_alg,
           db->meta.digest_alg == IMDB_DIGEST_ALG_LTHASH16_TREE ? "LtHash16 by ChaCha20, the digest a tree of SHA-256"
                                                             : "LtHash16 by MGF1-SHA256, the digest SHA-256");
    imdb_hex(db->writer_pk, IMDB_PUBKEY_LEN, hex);
    printf("writer     epoch %u, key %s%s\n", imdb_current_epoch(db), hex, db->meta.has_root ? " (a root key may promote)" : "");
    if (db->lake_seq) {
        imdb_hex(db->lake_manifest, 32, hex);
        printf("lake       commit %llu, manifest %s\n", (unsigned long long)db->lake_seq, hex);
    } else {
        printf("lake       (no checkpoint yet)\n");
    }
    for (uint32_t i = 0; i < db->nt; i++) {
        imdb_table *t = db->t[i];
        imdb_state_digest(db, t, d);
        imdb_hex(d, 32, hex);
        printf("table      %-20s live %-10llu versions %-10llu segments %-4u digest %.16s\n", t->s.name,
               (unsigned long long)t->live, (unsigned long long)t->nver, t->nseg, hex);
    }
    const imdb_kernels *k = imdb_kern();
    printf("kernels    crc32c=%s lthash=%s expand=%s expand2=%s sha256x8=%s utf8=%s filter=%s sum=%s\n", k->crc32c_name,
           k->lthash_name, k->expand_name, k->expand2_name, k->sha8_name, k->utf8_name, k->filter_name, k->sum_name);
}

int main(int argc, char **argv)
{
    if (argc < 2) return usage();
    const char *cmd = argv[1];
    imdb_err e = {0};
    if (strcmp(cmd, "version") == 0) {
        puts("imagedb 0.1");
        return 0;
    }
    if (strcmp(cmd, "init") == 0 && argc >= 3 && argc % 2 == 1) {
        uint8_t root[IMDB_PUBKEY_LEN], alg = 0;
        const char *rk = NULL, *ak = NULL;
        for (int i = 3; i + 1 < argc; i += 2) {
            if (strcmp(argv[i], "--root") == 0 && !rk) rk = argv[i + 1];
            else if (strcmp(argv[i], "--digest-alg") == 0 && !ak) ak = argv[i + 1];
            else return usage();
        }
        if (rk && (strlen(rk) != 2 * IMDB_PUBKEY_LEN || !imdb_unhex(rk, 2 * IMDB_PUBKEY_LEN, root, IMDB_PUBKEY_LEN))) {
            fprintf(stderr, "imagedb: init: the root key is 64 hex digits (imagedb root-key FILE prints it)\n");
            return 2;
        }
        if (ak && strcmp(ak, "1") != 0 && strcmp(ak, "2") != 0) {
            fprintf(stderr, "imagedb: init: --digest-alg is 1 or 2\n");
            return 2;
        }
        if ((!ak && imdb_default_digest_alg(&alg, &e)) ||
            imdb_init_primary_alg(argv[2], rk ? root : NULL, ak ? (uint8_t)(ak[0] - '0') : alg, &e)) {
            print_err("init", &e);
            return 1;
        }
        printf("initialized primary %s%s\n", argv[2], rk ? " (promotions certified by that root key)" : "");
        return 0;
    }
    if (strcmp(cmd, "init-replica") == 0 && argc == 5 && strcmp(argv[3], "--identity") == 0) {
        FILE *f = fopen(argv[4], "rb");
        char buf[512];
        size_t n = f ? fread(buf, 1, sizeof buf, f) : 0;
        if (f) fclose(f);
        imdb_identity id;
        if (!f) imdb_fail(&e, IMDB_ERR_IO, "cannot read %s", argv[4]);
        if (!f || imdb_identity_parse(buf, n, &id, &e) || imdb_init_replica(argv[2], &id, &e)) {
            print_err("init-replica", &e);
            return 1;
        }
        printf("initialized replica %s\n", argv[2]);
        return 0;
    }
    if (strcmp(cmd, "identity") == 0 && argc == 3) {
        imdb_identity id;
        char buf[512];
        if (imdb_identity_read(argv[2], &id, NULL, &e)) {
            print_err("identity", &e);
            return 1;
        }
        int n = imdb_identity_format(&id, buf, sizeof buf);
        fwrite(buf, 1, (size_t)n, stdout);
        return 0;
    }
    if (strcmp(cmd, "root-key") == 0 && argc == 3) { /* the offline key that may certify a promotion */
        uint8_t seed[IMDB_SEED_LEN];
        imdb_signer s;
        const char *base;
        int dfd = -1; /* its name synced too: a power cut must not take the only copy of a new root key */
        if (imdb_random(seed, sizeof seed, &e) || (dfd = imdb_open_parent(argv[2], &base, &e)) < 0 ||
            imdb_create_file_excl(dfd, base, seed, sizeof seed, 0400, &e) || imdb_sync_dir(dfd, &e)) {
            if (dfd >= 0) close(dfd);
            imdb_wipe(seed, sizeof seed);
            print_err("root-key", &e);
            return 1;
        }
        close(dfd);
        imdb_signer_init(&s, seed);
        imdb_wipe(seed, sizeof seed);
        char hex[2 * IMDB_PUBKEY_LEN + 1];
        imdb_hex(s.pk, IMDB_PUBKEY_LEN, hex);
        imdb_signer_wipe(&s);
        fprintf(stderr, "imagedb: root-key: wrote %s; keep it offline (imagedb promote needs it)\n", argv[2]);
        printf("%s\n", hex);
        return 0;
    }
    if (strcmp(cmd, "rotate-key") == 0 && argc == 3) {
        imdb_db *db = open_or_die(argv[2], false, 1);
        if (!db) return 1;
        int rc = imdb_rotate_key(db, &e);
        if (rc) {
            print_err("rotate-key", &e);
        } else {
            char hex[2 * IMDB_PUBKEY_LEN + 1];
            imdb_hex(db->writer_pk, IMDB_PUBKEY_LEN, hex);
            printf("writer key rotated at commit %llu: epoch %u, key %s\n", (unsigned long long)db->seq,
                   imdb_current_epoch(db), hex);
            if (db->warning[0]) fprintf(stderr, "imagedb: warning: %s\n", db->warning);
        }
        if (imdb_close(db) && !rc) rc = 1;
        return rc ? 1 : 0;
    }
    if (strcmp(cmd, "promote") == 0 && argc >= 5 && strcmp(argv[3], "--root-key") == 0) {
        imdb_promote_opts po = {0};
        for (int i = 5; i < argc; i++) {
            if (strcmp(argv[i], "--anchor") == 0 && i + 1 < argc) po.anchor = argv[++i];
            else if (strcmp(argv[i], "--abandon") == 0) po.abandon = true;
            else if (strcmp(argv[i], "--old-writer-stopped") == 0) po.old_writer_stopped = true;
            else return usage();
        }
        int fd = open(argv[4], O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
        struct stat st;
        uint8_t seed[IMDB_SEED_LEN];
        ssize_t got = -1;
        if (fd >= 0 && fstat(fd, &st) == 0 && S_ISREG(st.st_mode) && st.st_size == IMDB_SEED_LEN && !(st.st_mode & 077))
            got = read(fd, seed, sizeof seed);
        if (fd >= 0) close(fd);
        if (got != (ssize_t)sizeof seed) {
            fprintf(stderr, "imagedb: promote: %s is not a root key (32 bytes, readable by its owner only)\n", argv[4]);
            imdb_wipe(seed, sizeof seed);
            return 1;
        }
        char ledger[4200];
        snprintf(ledger, sizeof ledger, "%s.ledger", argv[4]); /* kept with the root key */
        po.ledger = ledger;
        imdb_promote_result pr;
        int rc = imdb_promote(argv[2], seed, &po, &pr, &e);
        imdb_wipe(seed, sizeof seed);
        if (pr.committed)
            printf("promoted %s: writer epoch %u from commit %llu (the cut: commit %llu)%s\n", argv[2], pr.epoch,
                   (unsigned long long)pr.seq, (unsigned long long)pr.seq - 1,
                   pr.anchor_published ? "; the anchor names the new epoch" : "");
        if (pr.abandoned_to)
            printf("abandoned: the old writer's commits %llu..%llu (they are not in this history)\n",
                   (unsigned long long)pr.seq, (unsigned long long)pr.abandoned_to);
        if (rc) {
            print_err("promote", &e);
            if (pr.recovery_required)
                fprintf(stderr, "imagedb: promote: the promotion is committed; open %s for writing once to finish it\n",
                        argv[2]);
            return 1;
        }
        printf("point the other replicas at %s\n", argv[2]);
        return 0;
    }
    if (strcmp(cmd, "init-replica") == 0 && argc == 4) {
        if (imdb_init(argv[2], true, argv[3], &e)) {
            print_err("init-replica", &e);
            return 1;
        }
        printf("initialized replica %s of %s\n", argv[2], argv[3]);
        return 0;
    }
    if (strcmp(cmd, "sql") == 0) return cmd_sql(argc, argv);
    if (strcmp(cmd, "ship") == 0 && argc >= 3) {
        uint64_t after = 0;
        bool follow = false, acks = false;
        for (int i = 3; i < argc; i++) {
            if (strcmp(argv[i], "--after") == 0 && i + 1 < argc) {
                int64_t v; /* strictly a commit number: "abc" must not mean 0 and ship everything */
                if (imdb_parse_int64(argv[i + 1], strlen(argv[i + 1]), &v, &e) || v < 0) return usage();
                after = (uint64_t)v;
                i++;
            } else if (strcmp(argv[i], "--follow") == 0) {
                follow = true;
            } else if (strcmp(argv[i], "--acks") == 0) {
                acks = true;
            } else {
                return usage();
            }
        }
        signal(SIGPIPE, SIG_IGN); /* a closed reader becomes an EPIPE error, not a kill */
        imdb_ship_opts so = {.follow = follow, .ackfd = acks ? 0 : -1};
        if (imdb_ship_ex(argv[2], after, 1, &so, &e)) {
            print_err("ship", &e);
            return 1;
        }
        return 0;
    }
    if (strcmp(cmd, "follow") == 0) return cmd_follow(argc, argv);
    if (strcmp(cmd, "replica-key") == 0 && (argc == 3 || (argc == 4 && strcmp(argv[3], "--new") == 0))) {
        bool replica = false, created = false, renew = argc == 4;
        imdb_signer s;
        if (imdb_read_role(argv[2], &replica, &e) || !replica) {
            if (!e.code) fprintf(stderr, "imagedb: replica-key: %s is a primary (its replicas have keys)\n", argv[2]);
            else print_err("replica-key", &e);
            return 1;
        }
        if (renew ? imdb_replica_key_new(argv[2], &s, &e) : imdb_replica_key(argv[2], true, &s, &created, &e)) {
            print_err("replica-key", &e);
            return 1;
        }
        char hex[2 * IMDB_PUBKEY_LEN + 1];
        imdb_hex(s.pk, IMDB_PUBKEY_LEN, hex);
        imdb_signer_wipe(&s);
        if (created) fprintf(stderr, "imagedb: replica-key: made %s/replica.key\n", argv[2]);
        if (renew)
            fprintf(stderr, "imagedb: replica-key: a new incarnation of %s; on the primary: imagedb replica-add PRIMARY "
                            "NAME %s --replace\n", argv[2], hex);
        printf("%s\n", hex);
        return 0;
    }
    if (strcmp(cmd, "replica-add") == 0 && (argc == 5 || (argc == 6 && strcmp(argv[5], "--replace") == 0))) {
        uint8_t pub[IMDB_PUBKEY_LEN];
        if (strlen(argv[4]) != 2 * IMDB_PUBKEY_LEN || !imdb_unhex(argv[4], 2 * IMDB_PUBKEY_LEN, pub, IMDB_PUBKEY_LEN)) {
            fprintf(stderr, "imagedb: replica-add: the key is 64 hex digits (imagedb replica-key REPLICA prints it)\n");
            return 2;
        }
        if (imdb_replica_add(argv[2], argv[3], pub, argc == 6, &e)) {
            print_err("replica-add", &e);
            return 1;
        }
        printf("replica %s allowlisted on %s\n", argv[3], argv[2]);
        return 0;
    }
    if (strcmp(cmd, "apply") == 0 && argc >= 3) {
        bool durable_ack = false;
        for (int i = 3; i < argc; i++) {
            if (strcmp(argv[i], "--durable-ack") == 0) durable_ack = true;
            else if (strcmp(argv[i], "--mem-limit") == 0 && i + 1 < argc && parse_size(argv[i + 1], &g_mem_limit)) i++;
            else if (strcmp(argv[i], "--mem-window") == 0 && i + 1 < argc && parse_window(argv[i + 1], &g_mem_window)) i++;
            else return usage();
        }
        imdb_db *db = open_anchored(argv[2], false, 1, NULL, false, durable_ack);
        if (!db) return 1;
        uint64_t applied = 0;
        int rc = imdb_apply_stream(db, 0, &applied, &e);
        if (rc) print_err("apply", &e);
        else if (db->seeded)
            fprintf(stderr, "seeded at commit %llu (its log begins after it): ship --after %llu to go on\n",
                    (unsigned long long)db->seeded, (unsigned long long)db->seeded);
        else fprintf(stderr, "applied %llu commits; replica at commit %llu\n", (unsigned long long)applied,
                     (unsigned long long)db->seq);
        imdb_close(db);
        return rc ? 1 : 0;
    }
    if (strcmp(cmd, "verify") == 0 && (argc == 3 || (argc == 5 && strcmp(argv[3], "--anchor") == 0))) {
        imdb_db *db = open_anchored(argv[2], true, 0, argc == 5 ? argv[4] : NULL, false, false); /* the anchor checked, not moved */
        if (!db) return 1;
        imdb_verify_report vr;
        int rc = imdb_verify(db, &vr, &e);
        if (rc) {
            print_err("verify", &e);
        } else {
            char hex[65];
            imdb_hex(vr.digest, 32, hex);
            printf("VERIFY ok\n  commits            %llu (hash chain, %llu Ed25519 signatures)\n  payloads re-hashed %llu\n"
                   "  versions           %llu (%llu live, %llu erased stubs)\n  lake               %llu segments, %llu rows "
                   "re-derived from files\n  digest             %s\n",
                   (unsigned long long)vr.commits, (unsigned long long)vr.sigs_checked,
                   (unsigned long long)vr.payload_rows_checked, (unsigned long long)vr.versions,
                   (unsigned long long)vr.live, (unsigned long long)vr.stubs, (unsigned long long)vr.segments_checked,
                   (unsigned long long)vr.lake_rows_checked, hex);
            if (vr.note[0]) printf("  note               %s\n", vr.note);
        }
        imdb_close(db);
        return rc ? 1 : 0;
    }
    if (strcmp(cmd, "recover") == 0 && argc >= 3) {
        bool apply = false;
        const char *save = NULL;
        for (int i = 3; i < argc; i++) {
            if (strcmp(argv[i], "--discard-tail") == 0) apply = true;
            else if (strcmp(argv[i], "--save") == 0 && i + 1 < argc) save = argv[++i];
            else return usage();
        }
        imdb_recover_report r;
        if (imdb_recover_tail(argv[2], apply, save, &r, &e)) {
            print_err("recover", &e);
            return 1;
        }
        printf("log        intact through commit %llu\n", (unsigned long long)r.last);
        if (r.have_durable)
            printf("durable    commit %llu %s\n", (unsigned long long)r.durable,
                   r.durable_strict ? "acknowledged as durable (strict: synced before each acknowledgement)"
                   : r.durable_synced ? "acknowledged as durable (it may lag the log after a crash: not synced per commit)"
                                      : "written under --nosync (it acknowledges nothing)");
        else if (r.durable_ignored) printf("durable    DURABLE is damaged: ignored (nothing says what was acknowledged)\n");
        else printf("durable    no DURABLE watermark\n");
        if (r.damaged)
            printf("damage     segment %llu from byte %llu: %llu bytes (%s)\n", (unsigned long long)r.segment,
                   (unsigned long long)r.offset, (unsigned long long)r.bytes, r.what);
        if (r.acked_lost)
            printf("lost       commits %llu..%llu were acknowledged as durable but are not intact in the log\n",
                   (unsigned long long)(r.last + 1), (unsigned long long)r.durable);
        if (r.maybe_acked)
            printf("unknown    the damaged frame after commit %llu is complete: an append that never finished, or an "
                   "acknowledged commit damaged later; nothing here can tell which (--durable-ack makes the watermark "
                   "exact)\n", (unsigned long long)r.last);
        if (r.lake_ahead)
            printf("lake       LAKE_HEAD names commit %llu, past the intact log: --discard-tail removes it (the next "
                   "writable open rebuilds the lake from the log)\n", (unsigned long long)r.lake_seq);
        if (!r.damaged && !r.acked_lost && !r.lake_ahead) {
            puts("nothing to recover");
            return 0;
        }
        if (r.applied) {
            printf("discarded  %s%s; DURABLE is now commit %llu. Next: %s %s%s\n",
                   r.damaged ? "the damaged tail (its bytes are in the --save file)" : "nothing in the log",
                   r.lake_ahead ? ", and LAKE_HEAD" : "", (unsigned long long)r.last,
                   r.lake_ahead ? "imagedb sql" : "imagedb verify", argv[2],
                   r.lake_ahead ? " -c 'VERIFY;' (a writable open rebuilds the lake from the log)" : "");
            return 0;
        }
        printf("to keep those commits, restore the segment from a replica; to drop them:\n"
               "  imagedb recover %s --discard-tail --save FILE\n", argv[2]);
        return 1;
    }
    if (strcmp(cmd, "info") == 0 && argc == 3) {
        imdb_db *db = open_or_die(argv[2], true, 0);
        if (!db) return 1;
        print_info(db);
        imdb_close(db);
        return 0;
    }
    return usage();
}
