/* imagedb command-line tool. */
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include "backup.h"
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
          "                    [--mem-window SECONDS|none] [--seg-cache BYTES|all] [--stats FILE] [--events FILE]\n"
          "                                             run SQL (interactive when no -c/-f and stdin is a tty);\n"
          "                                             --durable-ack: the watermark synced as each commit returns,\n"
          "                                             so a damaged last frame past it is known unacknowledged;\n"
          "  imagedb ship <primary-dir> [--after N] [--follow] [--acks]\n"
          "                                             write commits after N to stdout (--acks: read the\n"
          "                                             replica's acknowledgements on stdin)\n"
          "  imagedb apply <replica-dir> [--durable-ack] [--mem-limit BYTES] [--mem-window SECONDS|none]\n"
          "                    [--seg-cache BYTES|all] [--stats FILE] [--events FILE]\n"
          "                                             apply a commit stream from stdin\n"
          "  imagedb follow <replica-dir> [--mem-limit BYTES] [--mem-window SECONDS|none] [--seg-cache BYTES|all]\n"
          "                    [--stats FILE] [--events FILE] -- CMD [ARG...]\n"
          "                                             run CMD ({after}: the replica's commit), apply its stream,\n"
          "                                             acknowledge on its stdin; run it again when it ends\n"
          "  imagedb replica-key <replica-dir> [--new]  print the replica's public key (made if missing); --new: a\n"
          "                                             new key, a new incarnation (after a restore from a copy)\n"
          "  imagedb replica-add <primary-dir> NAME KEY [--replace]\n"
          "                                             allowlist a replica's key for acknowledgements\n"
          "  imagedb verify <dir> [--anchor FILE]       re-verify log, chain, signatures, digests, erasure, lake\n"
          "  imagedb info <dir>                         head, digest, tables, lake\n"
          "  imagedb dump <dir> [--batch N]             a logical dump on stdout: every table's CREATE TABLE, rows\n"
          "                                             (COPY ... FROM STDIN, BATCH N rows a commit; 10000) and\n"
          "                                             indexes at one commit; imagedb sql NEW -f FILE restores it\n"
          "  imagedb stats <file>                       a running copy's export (--stats FILE on sql, apply, follow)\n"
          "  imagedb health <dir> [--stats FILE] [--max-statement-s N]   0 healthy; 1 slow or unreadable; 2 failed; 3 damaged\n"
          "  imagedb recover <dir> [--discard-tail --save FILE]\n"
          "                                             inspect a damaged end of the log; with --discard-tail, cut it\n"
          "                                             (its bytes saved to FILE first) and lower DURABLE to match\n"
          "  imagedb root-key FILE                      make an offline root key (secret, 0400) and print its public key\n"
          "  imagedb backup-key FILE                    make a backup key (secret, 0400) and print its id\n"
          "  imagedb backup <dir> --key FILE --out FILE [--after PREV]\n"
          "                                             a full backup, encrypted: the last published snapshot and the\n"
          "                                             commits after it, while the database runs; with --after, an\n"
          "                                             incremental one: the commits after backup PREV's last\n"
          "  imagedb backup-verify --key FILE --scratch DIR BACKUP...\n"
          "                                             a test restore under DIR, VERIFY on it, then removed\n"
          "  imagedb restore <new-dir> --key FILE [--until N | --until-time TS] BACKUP...\n"
          "                                             a read-only copy (a full backup, then its incrementals in\n"
          "                                             order), through commit N or the last at or before TS; imagedb\n"
          "                                             promote makes it writable\n"
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
static uint64_t g_seg_cache; /* --seg-cache (db.h: the segment cache, stage 3c-1; 0: the default) */
static const char *g_stats_path; /* --stats FILE (P1 M1: the stats export), for the command's open */
static const char *g_events_path; /* --events FILE (P1 M2: the event log), for the command's open */

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

/* BYTES as --mem-limit takes them, or all: every segment image kept in memory */
static bool parse_seg_cache(const char *s, uint64_t *out)
{
    if (strcmp(s, "all") == 0) {
        *out = UINT64_MAX;
        return true;
    }
    return parse_size(s, out);
}

/* P1 M2: an open past two seconds says how far it has come, on stderr, at most once a second (the engine's rate) */
static uint64_t g_open_began_ns;
static void open_progress(void *ctx, const char *phase, uint64_t done, uint64_t total)
{
    (void)ctx;
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    uint64_t now = (uint64_t)ts.tv_sec * 1000000000u + (uint64_t)ts.tv_nsec;
    if (now - g_open_began_ns < 2000000000u) return;
    fprintf(stderr, "imagedb: opening: %s %llu of %llu\n", strcmp(phase, "lake") == 0 ? "lake segments" : "commits replayed",
            (unsigned long long)done, (unsigned long long)total);
}

static imdb_db *open_anchored(const char *dir, bool ro, int sync, const char *anchor, bool accept_rollback,
                              bool durable_ack)
{
    imdb_open_opts o = {.sync = sync, .read_only = ro, .anchor = anchor, .accept_rollback = accept_rollback,
                        .durable_ack = durable_ack, .mem_limit = g_mem_limit, .mem_window_us = g_mem_window,
                        .seg_cache_bytes = g_seg_cache, .stats_path = g_stats_path, .events_path = g_events_path,
                        .progress = open_progress};
    imdb_db *db;
    imdb_err e = {0};
    struct timespec t0; /* open_progress prints once the open passes two seconds from here */
    clock_gettime(CLOCK_MONOTONIC, &t0);
    g_open_began_ns = (uint64_t)t0.tv_sec * 1000000000u + (uint64_t)t0.tv_nsec;
    if (imdb_open(dir, &o, &db, &e)) {
        print_err("open", &e);
        return NULL;
    }
    if (db->warning[0]) fprintf(stderr, "imagedb: warning: %s\n", db->warning);
    return db;
}

static imdb_db *open_or_die(const char *dir, bool ro, int sync) { return open_anchored(dir, ro, sync, NULL, false, false); }

/* P2 S10: where COPY ... FROM STDIN's data comes from, as psql serves it: a script's text after the statement (the
 * buffer the script's statements are split from, then more of its file), or stdin (-c, the REPL). The engine gets the
 * bytes up to a line \. outside quotes (psql's end of data) or the file's end, and sees the end there; a script's next
 * statement starts on the line after the \. line. The quotes are followed as CSV's: "" inside them toggles twice */
typedef struct copy_src {
    FILE *f;
    char *b;          /* the bytes: the script's buffer, or stdin's own */
    size_t n, cap;    /* filled, and its size */
    size_t pos;       /* the first byte the engine has not had */
    bool eof, err;    /* f ended, or failed */
    bool tty;         /* f a terminal: a line at a time, nothing read past the line asked for */
    bool bol, inq;    /* the scan: at a line's start, inside quotes */
    bool done;        /* the data's end was reached (\. or the file's end) */
} copy_src;

typedef struct runner {
    imdb_session *ss;
    bool csv;
    int failures;
    bool timing;
    bool stop_on_error;
    copy_src *script;   /* P2 S10: the stream being run (run_stream): COPY's data inline, after the statement */
    copy_src *in;       /* stdin's, made at the first COPY ... FROM STDIN outside a script (-c, the REPL) */
    copy_src *active;   /* the running COPY's: the session's reader reads it */
} runner;

enum { COPY_TOOK_DATA = 1 }; /* run_stmt to the splitter: a COPY took the data after it; resume at script->pos */

/* room to read into: two bytes at least (a terminal's line and its NUL) */
static bool src_full(const copy_src *s) { return s->cap - s->n < 2; }

/* more bytes after n: a line from a terminal, else what one read gives; 0 at the end (or a failure: err), or when
 * full (the caller makes room first) */
static size_t src_read(copy_src *s)
{
    if (s->eof || src_full(s)) return 0;
    size_t got = 0;
    if (s->tty) {
        if (fgets(s->b + s->n, (int)(s->cap - s->n > INT32_MAX ? INT32_MAX : s->cap - s->n), s->f)) got = strlen(s->b + s->n);
    } else {
        got = fread(s->b + s->n, 1, s->cap - s->n, s->f);
    }
    if (!got) {
        s->eof = true;
        s->err = ferror(s->f) != 0;
    }
    s->n += got;
    return got;
}

/* the bytes before pos are spent: dropped, wiped (SQL text and data carry row values) */
static void src_drop(copy_src *s, size_t k)
{
    memmove(s->b, s->b + k, s->n - k);
    imdb_wipe(s->b + s->n - k, k);
    s->n -= k;
    s->pos -= k < s->pos ? k : s->pos;
}

/* at least k bytes from pos, unless the file ends first: how many there are */
static size_t src_need(copy_src *s, size_t k)
{
    while (s->n - s->pos < k && !s->eof) {
        if (src_full(s)) {
            if (!s->pos) break; /* the buffer is the lookahead's: never more than a few bytes */
            src_drop(s, s->pos);
        }
        src_read(s);
    }
    return s->n - s->pos;
}

/* the session's reader (imdb_session_copy_io): the running COPY's data, stopped before a \. line */
static long copy_read(void *arg, char *out, size_t cap)
{
    runner *rn = arg;
    copy_src *s = rn->active;
    if (!s) return -1;
    size_t k = 0;
    while (k < cap && !s->done) {
        if (!src_need(s, 1)) {
            if (s->err) return -1;
            s->done = true; /* the file's end ends the data */
            break;
        }
        char ch = s->b[s->pos];
        if (s->bol && !s->inq && ch == '\\') { /* "\." alone on its line ends the data */
            /* three bytes, a fourth only after a CR: never past the marker's own line, which from a terminal (a line a
             * read) would take the REPL's next statement into this buffer */
            size_t have = src_need(s, 3), mark = 0;
            if (have >= 2 && s->b[s->pos + 1] == '.') {
                if (have == 2) mark = s->eof ? 2 : 0;
                else if (s->b[s->pos + 2] == '\n') mark = 3;
                else if (s->b[s->pos + 2] == '\r' && src_need(s, 4) >= 4 && s->b[s->pos + 3] == '\n') mark = 4;
            }
            if (mark) {
                s->pos += mark;
                s->done = true;
                break;
            }
        }
        out[k++] = ch;
        s->pos++;
        if (ch == '"') s->inq = !s->inq;
        s->bol = ch == '\n';
    }
    return (long)k;
}

/* the session's writer: COPY ... TO STDOUT's bytes */
static int copy_write(void *arg, const char *b, size_t n)
{
    (void)arg;
    return fwrite(b, 1, n, stdout) == n ? 0 : -1;
}

/* the statement's first word is COPY (the cheap test before parsing it as one) */
static bool starts_copy(const char *s, size_t n)
{
    size_t i = 0;
    for (;;) {
        while (i < n && (s[i] == ' ' || s[i] == '\t' || s[i] == '\r' || s[i] == '\n')) i++;
        if (i + 1 < n && s[i] == '-' && s[i + 1] == '-') {
            while (i < n && s[i] != '\n') i++;
            continue;
        }
        break;
    }
    return n - i >= 4 && strncasecmp(s + i, "copy", 4) == 0;
}

/* a script's COPY: its data begins on the line after the statement; what follows on the statement's line may be spaces,
 * tabs and a comment, nothing else */
static int skip_rest_of_line(copy_src *s)
{
    for (;;) {
        if (!src_need(s, 1)) return s->err ? -1 : 0;
        char ch = s->b[s->pos];
        if (ch == ' ' || ch == '\t') {
            s->pos++;
            continue;
        }
        if (ch == '-' && src_need(s, 2) >= 2 && s->b[s->pos + 1] == '-') {
            while (src_need(s, 1) && s->b[s->pos] != '\n') s->pos++;
            continue;
        }
        if (ch == '\r' && src_need(s, 2) >= 2 && s->b[s->pos + 1] == '\n') {
            s->pos += 2;
            return 0;
        }
        if (ch == '\n') {
            s->pos++;
            return 0;
        }
        return 1;
    }
}

static double now_s(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec * 1e-9;
}

/* the session whose statement runs (run_stmt): SIGINT cancels that statement (R1). An atomic pointer and the session's
 * atomic flag, both lock-free: the handler does nothing a signal handler may not */
static _Atomic(imdb_session *) g_cancel_ss;
_Static_assert(ATOMIC_POINTER_LOCK_FREE == 2, "the handler reads this pointer: it must be lock-free");

static void on_cancel(int sig)
{
    (void)sig;
    imdb_session *ss = atomic_load_explicit(&g_cancel_ss, memory_order_relaxed);
    if (ss) imdb_session_cancel(ss);
}

static int run_stmt(void *arg, const char *sql, size_t len)
{
    runner *rn = arg;
    imdb_result r;
    imdb_err e = {0};
    char before[512];
    snprintf(before, sizeof before, "%s", rn->ss->db->warning);
    /* P2 S10: COPY ... FROM STDIN: its data from the script after it (on the next line), or from stdin */
    char *own = NULL;
    copy_src *src = NULL;
    if (starts_copy(sql, len) && imdb_copy_in_stmt(sql, len)) {
        if (!(own = imdb_alloc(len, &e))) {
            print_err("error", &e);
            rn->failures++;
            return e.code;
        }
        memcpy(own, sql, len); /* the script's buffer moves under the data's reads */
        if (rn->script) {
            src = rn->script;
            src->pos = (size_t)(sql + len - src->b);
            int k = skip_rest_of_line(src);
            if (k) {
                imdb_wipe(own, len);
                imdb_free(own);
                fprintf(stderr, "imagedb: error: %s\n", k < 0 ? "reading the script failed"
                                                           : "COPY ... FROM STDIN: its data starts on the line after it");
                rn->failures++;
                return IMDB_ERR_INVALID;
            }
        } else {
            if (!rn->in) {
                if (!(rn->in = imdb_alloc(sizeof *rn->in, &e)) ||
                    (memset(rn->in, 0, sizeof *rn->in), !(rn->in->b = imdb_alloc(IMDB_COPY_BUF, &e)))) {
                    imdb_free(rn->in);
                    rn->in = NULL;
                    imdb_wipe(own, len);
                    imdb_free(own);
                    print_err("error", &e);
                    rn->failures++;
                    return e.code;
                }
                rn->in->f = stdin;
                rn->in->cap = IMDB_COPY_BUF;
                rn->in->tty = isatty(0);
            }
            src = rn->in;
            if (src->tty) fprintf(stderr, "Enter the data, then a line \\. (or end the input)\n");
        }
        src->done = false;
        src->bol = true;
        src->inq = false;
        rn->active = src;
        sql = own;
    }
    /* Ctrl-C while a statement runs cancels it; at the prompt and between statements it does what it always did */
    struct sigaction sa, old;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_cancel;
    sa.sa_flags = SA_RESTART; /* a COMMIT blocked in flock (a receipt, the anchor) or a read goes on: never an EINTR */
    sigemptyset(&sa.sa_mask);
    atomic_store_explicit(&g_cancel_ss, rn->ss, memory_order_relaxed);
    sigaction(SIGINT, &sa, &old);
    double t0 = now_s();
    int rc = imdb_exec_one(rn->ss, sql, len, NULL, 0, &r, &e);
    double dt = now_s() - t0;
    sigaction(SIGINT, &old, NULL);
    atomic_store_explicit(&g_cancel_ss, NULL, memory_order_relaxed);
    if (src) { /* a COPY that stopped before its data's end: the rest is skipped to it, so the script goes on after */
        char sink[4096];
        while (!src->done && copy_read(rn, sink, sizeof sink) > 0) {}
        imdb_wipe(sink, sizeof sink);
        rn->active = NULL;
        imdb_wipe(own, len);
        imdb_free(own);
    }
    int took = src && rn->script ? COPY_TOOK_DATA : 0; /* the splitter resumes after the data */
    if (rc) {
        print_err("error", &e);
        rn->failures++;
        /* a cancel stops what remains of the input too: Ctrl-C asked for the run to stop, not for its next statement */
        return rn->stop_on_error || rc == IMDB_ERR_CANCELLED ? rc : took;
    }
    if (r.copy_out) { /* P2 S10: stdout holds COPY TO's data alone; its count goes beside it */
        fflush(stdout);
        fprintf(stderr, "%s\n", r.status);
    } else {
        imdb_buf out;
        imdb_buf_init(&out);
        imdb_result_render(&r, rn->csv, &out);
        if (out.len) fwrite(out.p, 1, out.len, stdout);
        imdb_buf_free(&out);
    }
    if (rn->timing) printf("Time: %.3f ms\n", dt * 1000);
    fflush(stdout);
    imdb_result_free(&r);
    if (strcmp(before, rn->ss->db->warning) != 0 && rn->ss->db->warning[0])
        fprintf(stderr, "imagedb: warning: %s\n", rn->ss->db->warning);
    return took;
}

static int run_text(runner *rn, const char *text, size_t len)
{
    imdb_err e = {0};
    int rc = imdb_split_statements(text, len, run_stmt, rn, &e);
    if (rc && e.code) print_err("error", &e);
    return rc;
}

/* A script read in chunks (-f FILE, -f -, piped input): each complete statement runs as it arrives, so a script of any
 * size runs in the memory of its longest statement (IMDB_MAX_SQL) and a chunk; at the end of the stream the rest runs
 * as imdb_split_statements runs a text (an unterminated literal is the error it is). Before 2026-11-04 the whole input
 * was read first, and only its first 16 MiB: a longer script was cut, silently. */
static int run_stream(runner *rn, FILE *f)
{
    enum { CHUNK = 1 << 20 };
    imdb_err e = {0};
    copy_src s; /* the script's buffer, which a COPY in it reads its data from too (P2 S10) */
    memset(&s, 0, sizeof s);
    s.f = f;
    s.cap = CHUNK;
    s.tty = isatty(fileno(f));
    if (!(s.b = imdb_alloc(s.cap, &e))) { /* the helpers' throughout: imdb_realloc_array credits the old block */
        print_err("error", &e);
        return 1;
    }
    copy_src *outer = rn->script;
    rn->script = &s;
    int rc = 0;
    for (;;) {
        if (s.n) {
            size_t used = 0;
            imdb_err es = {0};
            rc = imdb_split_complete(s.b, s.n, run_stmt, rn, &used, &es);
            if (rc == COPY_TOOK_DATA) { /* a COPY took the data after it: the text goes on after the data's end */
                src_drop(&s, s.pos);
                rc = 0;
                continue;
            }
            if (rc) {
                if (es.code) print_err("error", &es);
                break;
            }
            if (used) src_drop(&s, used);
        }
        if (src_full(&s)) {
            if (s.cap >= (size_t)IMDB_MAX_SQL + CHUNK) {
                fprintf(stderr, "imagedb: error: a statement longer than %u bytes (no ';' ends it)\n", IMDB_MAX_SQL);
                rc = 1;
                break;
            }
            char *nb = imdb_realloc_array(s.b, s.cap, s.cap * 2, 1, &e); /* wipes the old block */
            if (!nb) {
                print_err("error", &e);
                rc = 1;
                break;
            }
            s.b = nb;
            s.cap *= 2;
        }
        if (!src_read(&s)) {
            if (s.err) {
                fprintf(stderr, "imagedb: error: reading the script: %s\n", strerror(errno));
                rc = 1;
                break;
            }
            /* the end: the rest runs as a text does (an unterminated literal is the error it is), a COPY's data and what
             * follows it included */
            while (s.n) {
                s.pos = 0;
                rc = imdb_split_statements(s.b, s.n, run_stmt, rn, &e);
                if (rc != COPY_TOOK_DATA) {
                    if (rc && e.code) print_err("error", &e);
                    break;
                }
                src_drop(&s, s.pos);
                rc = 0;
            }
            break;
        }
    }
    rn->script = outer;
    imdb_wipe(s.b, s.cap);
    imdb_free(s.b);
    return rc;
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
        else if (strcmp(argv[i], "--stats") == 0 && i + 1 < argc) g_stats_path = argv[++i];
        else if (strcmp(argv[i], "--events") == 0 && i + 1 < argc) g_events_path = argv[++i];
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
        else if (strcmp(argv[i], "--seg-cache") == 0 && i + 1 < argc) {
            if (!parse_seg_cache(argv[++i], &g_seg_cache)) {
                fprintf(stderr, "imagedb: sql: --seg-cache takes BYTES (digits, then K, M or G) or all\n");
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
    runner rn = {.ss = &ss, .csv = csv, .stop_on_error = true};
    imdb_session_copy_io(&ss, copy_read, copy_write, &rn); /* P2 S10: COPY's data through the CLI's streams */
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
            rc = run_stream(&rn, f);
            if (f != stdin) fclose(f);
            ran = true;
        }
    }
    if (!ran && !rc) {
        if (isatty(0)) {
            repl(&rn);
        } else {
            rc = run_stream(&rn, stdin);
        }
    }
    if (rn.in) { /* P2 S10 */
        imdb_wipe(rn.in->b, rn.in->cap);
        imdb_free(rn.in->b);
        imdb_free(rn.in);
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
        else if (strcmp(argv[dd], "--events") == 0) {
            g_events_path = argv[dd + 1];
            dd += 2;
        }
        else if (strcmp(argv[dd], "--stats") == 0) {
            g_stats_path = argv[dd + 1];
            dd += 2;
        }
        else if (strcmp(argv[dd], "--mem-window") == 0 && parse_window(argv[dd + 1], &g_mem_window)) dd += 2;
        else if (strcmp(argv[dd], "--seg-cache") == 0 && parse_seg_cache(argv[dd + 1], &g_seg_cache)) dd += 2;
        else if (strcmp(argv[dd], "--mem-limit") != 0 && strcmp(argv[dd], "--mem-window") != 0 && strcmp(argv[dd], "--stats") != 0 &&
                 strcmp(argv[dd], "--events") != 0 &&
                 strcmp(argv[dd], "--seg-cache") != 0)
            return usage();
        else {
            fprintf(stderr, "imagedb: follow: --mem-limit takes BYTES (digits, then K, M or G), --mem-window SECONDS "
                            "or none, --seg-cache BYTES or all\n");
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
        char dropped[48] = ""; /* a tombstone (1f): AS OF before the drop still reads it */
        if (t->dropped_at) snprintf(dropped, sizeof dropped, "  dropped at commit %llu", (unsigned long long)t->dropped_at);
        printf("table      %-20s live %-10llu versions %-10llu segments %-4u digest %.16s%s\n", t->s.name,
               (unsigned long long)t->live, (unsigned long long)t->nver, t->nseg, hex, dropped);
    }
    const imdb_kernels *k = imdb_kern();
    printf("kernels    crc32c=%s lthash=%s expand=%s expand2=%s sha256x8=%s utf8=%s filter=%s sum=%s\n", k->crc32c_name,
           k->lthash_name, k->expand_name, k->expand2_name, k->sha8_name, k->utf8_name, k->filter_name, k->sum_name);
}

static uint64_t wall_us(void) /* the export's age: its time_us against this clock */
{
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (uint64_t)ts.tv_sec * 1000000u + (uint64_t)ts.tv_nsec / 1000u;
}

/* P1 M1: the stats export (--stats FILE) read whole and checked by its CRC32C, the copy a writer was rewriting read
 * again (it is rewritten in place, never fsynced): 0, or 1 torn or malformed, 2 missing */
static int read_stats(const char *path, char *buf, size_t cap, size_t *len)
{
    for (int attempt = 0; attempt < 5; attempt++) {
        if (attempt) {
            struct timespec ts = {0, 20 * 1000000L};
            nanosleep(&ts, NULL);
        }
        imdb_err e = {0};
        const char *base = NULL;
        int pfd = imdb_open_parent(path, &base, &e);
        int fd = pfd < 0 ? -1 : openat(pfd, base, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
        int err = errno;
        if (pfd >= 0) close(pfd);
        if (fd < 0) return err == ENOENT ? 2 : 1;
        ssize_t n = read(fd, buf, cap - 1);
        close(fd);
        if (n <= 0) continue;
        buf[n] = 0;
        char *last = n >= 2 ? memrchr(buf, '\n', (size_t)n - 1) : NULL; /* the CRC line is the last */
        size_t body = last ? (size_t)(last + 1 - buf) : 0;
        unsigned crc;
        if (last && sscanf(last + 1, "crc32c %8x\n", &crc) == 1 && imdb_kern()->crc32c(0, buf, body) == crc &&
            strncmp(buf, "imagedb.stats 1\n", 16) == 0) {
            *len = body;
            return 0;
        }
    }
    return 1;
}

/* a value from read_stats' lines (INT64_MIN: absent) */
static long long stats_value(const char *buf, const char *name)
{
    size_t n = strlen(name);
    for (const char *p = buf; p && *p; p = strchr(p, '\n') ? strchr(p, '\n') + 1 : NULL)
        if (strncmp(p, name, n) == 0 && p[n] == ' ') return strtoll(p + n + 1, NULL, 10);
    return LLONG_MIN;
}

static char g_stats_buf[IMDB_STATS_EXPORT_MAX + 64];

/* imagedb stats FILE: the export's rows, its age last */
static int cmd_stats(const char *path)
{
    size_t len = 0;
    int r = read_stats(path, g_stats_buf, sizeof g_stats_buf, &len);
    if (r) {
        fprintf(stderr, "imagedb: stats: %s: %s\n", path, r == 2 ? "no such file" : "torn or not an export (read 5 times)");
        return r;
    }
    fwrite(g_stats_buf, 1, len, stdout);
    long long t = stats_value(g_stats_buf, "time_us");
    unsigned long long now = wall_us();
    printf("age.s %lld\n", t > 0 && now > (unsigned long long)t ? (long long)((now - (unsigned long long)t) / 1000000u) : 0);
    return 0;
}

/* imagedb health DIR [--stats FILE] [--max-statement-s N]: 0 healthy; 1 a statement running longer than N seconds (60)
 * or the export unreadable; 2 the writer's handle failed (reopen it); 3 the directory damaged or unreadable, or a
 * replica incident recorded. Cheap: no open, no replay (META, DURABLE, replicas/; then the export) */
static int cmd_health(int argc, char **argv)
{
    const char *stats = NULL;
    long long max_s = 60;
    for (int i = 3; i < argc; i++) {
        if (strcmp(argv[i], "--stats") == 0 && i + 1 < argc) stats = argv[++i];
        else if (strcmp(argv[i], "--max-statement-s") == 0 && i + 1 < argc) max_s = atoll(argv[++i]);
        else return usage();
    }
    imdb_err e = {0};
    if (imdb_health_dir(argv[2], &e)) {
        printf("unhealthy: %s\n", e.msg);
        return 3;
    }
    if (!stats) {
        printf("healthy: META, DURABLE and replicas/ checked (no export given)\n");
        return 0;
    }
    size_t len = 0;
    int r = read_stats(stats, g_stats_buf, sizeof g_stats_buf, &len);
    if (r) {
        printf("unknown: the export %s is %s\n", stats, r == 2 ? "missing" : "torn or not an export");
        return 1;
    }
    long long t = stats_value(g_stats_buf, "time_us"), now = (long long)wall_us();
    long long age = t > 0 && now > t ? (now - t) / 1000000 : 0;
    if (stats_value(g_stats_buf, "failed") == 1) {
        printf("failed: the writer's handle stopped (reopen it; the export is %lld s old)\n", age);
        return 2;
    }
    long long run = stats_value(g_stats_buf, "statement.running_ms");
    if (stats_value(g_stats_buf, "statement.running") == 1 && run / 1000 + age > max_s) {
        printf("slow: a statement has run %lld s (more than %lld)\n", run / 1000 + age, max_s);
        return 1;
    }
    printf("healthy: the export is %lld s old, commit %lld\n", age, stats_value(g_stats_buf, "commit"));
    return 0;
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
    if (strcmp(cmd, "backup-key") == 0 && argc == 3) {
        uint8_t id[32];
        if (imdb_backup_key_create(argv[2], id, &e)) {
            print_err("backup-key", &e);
            return 1;
        }
        char hex[65];
        imdb_hex(id, sizeof id, hex);
        fprintf(stderr, "imagedb: backup-key: wrote %s; keep it apart from the backups: without it they cannot be "
                        "restored\n", argv[2]);
        printf("%s\n", hex);
        return 0;
    }
    if (strcmp(cmd, "backup") == 0 && (argc == 7 || argc == 9)) {
        const char *keyf = NULL, *out = NULL, *after = NULL;
        for (int i = 3; i + 1 < argc; i += 2) {
            if (strcmp(argv[i], "--key") == 0) keyf = argv[i + 1];
            else if (strcmp(argv[i], "--out") == 0) out = argv[i + 1];
            else if (strcmp(argv[i], "--after") == 0) after = argv[i + 1];
            else return usage();
        }
        if (!keyf || !out) return usage();
        uint8_t key[IMDB_BACKUP_KEY_LEN];
        imdb_backup_info bi;
        int rc = imdb_backup_key_load(keyf, key, &e) ||
                 (after ? imdb_backup_incremental(argv[2], after, out, key, &bi, &e) : imdb_backup_full(argv[2], out, key, &bi, &e));
        imdb_wipe(key, sizeof key);
        if (rc) {
            print_err("backup", &e);
            return 1;
        }
        printf("backup %s: commits %llu to %llu%s, %llu bytes of stream in %llu chunks\n", out,
               (unsigned long long)bi.first_seq, (unsigned long long)bi.last_seq,
               bi.seed_seq ? " (a seed, then the commits after it)" : "", (unsigned long long)bi.payload_bytes,
               (unsigned long long)bi.chunks);
        return 0;
    }
    if (strcmp(cmd, "restore") == 0 && argc >= 6 && strcmp(argv[3], "--key") == 0) {
        uint8_t key[IMDB_BACKUP_KEY_LEN];
        imdb_backup_info bi;
        imdb_restore_opts ro = {0, 0};
        int first = 5;
        if (argc >= 8 && strcmp(argv[5], "--until") == 0) {
            int64_t v;
            if (imdb_parse_int64(argv[6], strlen(argv[6]), &v, &e) || v < 1) return usage();
            ro.until_seq = (uint64_t)v;
            first = 7;
        } else if (argc >= 8 && strcmp(argv[5], "--until-time") == 0) {
            int64_t t;
            if (imdb_parse_timestamp(argv[6], strlen(argv[6]), &t, &e) || t < 1) {
                print_err("restore", &e);
                return 1;
            }
            ro.until_time = (uint64_t)t;
            first = 7;
        }
        int rc = imdb_backup_key_load(argv[4], key, &e) ||
                 imdb_restore_ex(argv[2], key, (const char *const *)argv + first, (size_t)(argc - first), &ro, &bi, &e);
        imdb_wipe(key, sizeof key);
        if (rc) {
            print_err("restore", &e);
            return 1;
        }
        printf("restored %s through commit %llu: a read-only replica\n", argv[2], (unsigned long long)bi.last_seq);
        if (bi.id.has_root)
            fprintf(stderr, "imagedb: restore: to write to it: imagedb promote %s --root-key FILE (--anchor FILE | "
                            "--old-writer-stopped); then enrol replicas again (replica-add) and give it a new anchor\n",
                    argv[2]);
        else
            fprintf(stderr, "imagedb: restore: the database has no root key, so the copy stays read-only (init --root "
                            "makes promotion possible)\n");
        return 0;
    }
    if (strcmp(cmd, "backup-verify") == 0 && argc >= 7 && strcmp(argv[2], "--key") == 0 &&
        strcmp(argv[4], "--scratch") == 0) {
        uint8_t key[IMDB_BACKUP_KEY_LEN];
        imdb_backup_info bi;
        imdb_verify_report vr;
        int rc = imdb_backup_key_load(argv[3], key, &e) ||
                 imdb_backup_verify(argv[5], key, (const char *const *)argv + 6, (size_t)(argc - 6), &bi, &vr, &e);
        imdb_wipe(key, sizeof key);
        if (rc) {
            print_err("backup-verify", &e);
            return 1;
        }
        printf("backup verified: restored through commit %llu and VERIFY passed (%llu commits, %llu signatures, %llu "
               "versions, %llu segments)\n", (unsigned long long)bi.last_seq, (unsigned long long)vr.commits,
               (unsigned long long)vr.sigs_checked, (unsigned long long)vr.versions,
               (unsigned long long)vr.segments_checked);
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
            else if (strcmp(argv[i], "--stats") == 0 && i + 1 < argc) g_stats_path = argv[++i];
            else if (strcmp(argv[i], "--events") == 0 && i + 1 < argc) g_events_path = argv[++i];
            else if (strcmp(argv[i], "--mem-window") == 0 && i + 1 < argc && parse_window(argv[i + 1], &g_mem_window)) i++;
            else if (strcmp(argv[i], "--seg-cache") == 0 && i + 1 < argc && parse_seg_cache(argv[i + 1], &g_seg_cache)) i++;
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
    if (strcmp(cmd, "stats") == 0 && argc == 3) return cmd_stats(argv[2]); /* P1 M1 */
    if (strcmp(cmd, "health") == 0 && argc >= 3) return cmd_health(argc, argv);
    if (strcmp(cmd, "dump") == 0 && (argc == 3 || (argc == 5 && strcmp(argv[3], "--batch") == 0))) { /* P2 S17 */
        uint32_t batch = 0;
        if (argc == 5) {
            char *end = NULL;
            unsigned long v = strtoul(argv[4], &end, 10);
            if (!end || *end || !v || v > UINT32_MAX) return usage();
            batch = (uint32_t)v;
        }
        imdb_db *db = open_or_die(argv[2], true, 0); /* read-only: a live primary's or a replica's, never the writer's */
        if (!db) return 1;
        imdb_err de = {0};
        int rc = imdb_dump(db, batch, copy_write, NULL, &de);
        if (!rc && fflush(stdout) != 0) rc = imdb_fail(&de, IMDB_ERR_IO, "dump: writing stdout failed");
        imdb_close(db);
        if (rc) {
            fprintf(stderr, "imagedb: error: %s (what was written is not a whole dump)\n", de.msg);
            return 1;
        }
        return 0;
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
