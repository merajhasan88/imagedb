/* N1d-2: imagedb-client, the network shell (docs/n1-design.md §8d): `imagedb sql`'s runner (cli/run.h) over the C client,
 * on the server's socket or on TCP with TLS 1.3. Each result is rebuilt from COLUMNS, ROWS and DONE as an imdb_result
 * and printed by the engine's own renderer, so its output is the embedded CLI's but what the wire does not carry: the
 * access path ("[scan]" after a status or a row count: a session's plan detail, which EXPLAIN gives) and SET identity's
 * line (the server session's own setting: --identity prints it from DONE's read point). A TIMESTAMPTZ is the instant on
 * the wire; the shell keeps its session's zone itself (SHOW TIME ZONE at the start and after each SET or RESET it sends)
 * and computes each cell's offset as the engine does, from its own zoneinfo. Links libimagedb.a for the runner's
 * splitter, the renderer and the zones; never opens a database. */
#include <errno.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <termios.h>
#include <unistd.h>

#include "netres.h"
#include "run.h"
#include "../server/conv.h"
#include "../src/sql.h"
#include "../src/tz.h"
#include "../client/imagedb_client.h"

typedef struct shell {
    imdbc *c;
    const char *zoneinfo;
    imdb_tz *zone;           /* the session's zone (NULL: UTC) */
    bool identity;           /* --identity: each read point's line */
    uint8_t state;           /* the last READY's: a transaction open at the end is rolled back, as the CLI says */
} shell;

static _Atomic(imdbc *) g_cancel_c;
_Static_assert(ATOMIC_POINTER_LOCK_FREE == 2, "the handler reads this pointer: it must be lock-free");

/* Ctrl-C while a statement runs: CANCEL (imdbc_cancel: a flag and a wake-up, what a handler may do) */
static void on_int(int sig)
{
    (void)sig;
    imdbc *c = atomic_load_explicit(&g_cancel_c, memory_order_relaxed);
    if (c) imdbc_cancel(c);
}

static int usage(void)
{
    fputs("usage: imagedb-client (--socket PATH | --host HOST --port PORT (--ca FILE | --pin HEX)) --user NAME\n"
          "                      [-c SQL]... [-f FILE]... [--csv] [--identity] [--zoneinfo DIR]\n"
          "  the password from IMAGEDB_PASSWORD, or asked for on the terminal\n",
          stderr);
    return 2;
}

static double now_s(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec * 1e-9;
}

/* COPY ... FROM STDIN's data, after COPY_IN: the runner's source to its end, then COPY_DONE (a failed read: COPY_FAIL) */
static int send_copy(cli_runner *rn, shell *sh, imdb_err *e)
{
    char *buf = imdb_alloc(1u << 16, e);
    if (!buf) return e->code;
    int rc = IMDB_OK;
    for (;;) {
        long k = cli_copy_read(rn, buf, 1u << 16);
        if (k == 0) {
            rc = imdbc_copy_done(sh->c, e);
            break;
        }
        if (k < 0) {
            rc = imdbc_copy_fail(sh->c, "reading the data failed", e);
            break;
        }
        if ((rc = imdbc_copy_data(sh->c, buf, (size_t)k, e))) break;
    }
    imdb_wipe(buf, 1u << 16);
    imdb_free(buf);
    return rc;
}

/* the statement through the server: its replies to READY; its result printed as the CLI prints one */
static int net_stmt(cli_runner *rn, const char *sql, size_t len, bool copy_in)
{
    (void)copy_in; /* the server says (COPY_IN) */
    shell *sh = rn->ctx;
    imdb_err e = {0};
    imdbc_stmt st = {sql, len, NULL, 0};
    imdb_result r;
    imdb_result_init(&r);
    char warn[IMDBW_MESSAGE_MAX + 1] = "";
    int rc = IMDB_OK;
    bool copy_out = false;
    cli_order ord = {0};
    double t0 = now_s(), dt = 0;
    struct sigaction sa, old;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_int;
    sa.sa_flags = SA_RESTART;
    sigemptyset(&sa.sa_mask);
    atomic_store_explicit(&g_cancel_c, sh->c, memory_order_relaxed);
    sigaction(SIGINT, &sa, &old);
    if (imdbc_query(sh->c, &st, 1, &e)) {
        rc = e.code;
        cli_print_err("error", &e);
        goto out;
    }
    for (;;) {
        imdbw_msg m;
        if (imdbc_next(sh->c, &m, &e)) { /* the connection: nothing more can come */
            rc = e.code;
            cli_print_err("error", &e);
            goto out;
        }
        imdb_err oe = {0};
        if (cli_order_next(&ord, m.type, &oe)) { /* the server's fault: refused before it reaches the result (netres.h) */
            cli_print_err("error", &oe);
            if (!rc) rc = oe.code; /* (a READY so refused renders nothing) */
        }
        if (m.type == IMDBW_READY) {
            sh->state = m.state;
            break;
        }
        if (oe.code) continue; /* the rest read to READY, so the connection stays in step */
        int k = IMDB_OK;
        switch (m.type) {
        case IMDBW_COLUMNS: k = cli_res_cols(&r, &m, &e); break;
        case IMDBW_ROWS: k = cli_res_rows(&r, imdbc_columns(sh->c), &m, sh->zone, &e); break;
        case IMDBW_COPY_IN: k = send_copy(rn, sh, &e); break;
        case IMDBW_COPY_OUT:
            copy_out = true;
            if (fwrite(m.data, 1, m.dlen, stdout) != m.dlen) k = imdb_fail(&e, IMDB_ERR_IO, "writing COPY's data failed");
            break;
        case IMDBW_DONE: cli_res_done(&r, &m); dt = now_s() - t0; break;
        case IMDBW_WARNING:
            snprintf(warn, sizeof warn, "%.*s", (int)m.texts[0].len, (const char *)m.texts[0].p);
            break;
        case IMDBW_ERROR: {
            imdb_err se = {0};
            rc = cli_res_code(m.code);
            snprintf(se.msg, sizeof se.msg, "%.*s", (int)m.texts[0].len, (const char *)m.texts[0].p);
            se.code = rc;
            cli_print_err("error", &se);
            break;
        }
        default: break;
        }
        if (k) { /* the shell's own failure: the rest read to READY, so the connection stays in step */
            cli_print_err("error", &e);
            if (!rc) rc = k;
        }
    }
    if (!rc) {
        if (copy_out) { /* stdout holds COPY TO's data alone; its count goes beside it, as the CLI's */
            fflush(stdout);
            fprintf(stderr, "%s\n", r.status);
        } else {
            r.show_identity = sh->identity;
            imdb_buf o;
            imdb_buf_init(&o);
            imdb_result_render(&r, rn->csv, &o);
            if (o.len) fwrite(o.p, 1, o.len, stdout);
            imdb_buf_free(&o);
        }
        if (rn->timing) printf("Time: %.3f ms\n", dt * 1000);
        fflush(stdout);
        if (warn[0]) fprintf(stderr, "imagedb: warning: %s\n", warn);
    }
out:
    sigaction(SIGINT, &old, NULL);
    atomic_store_explicit(&g_cancel_c, NULL, memory_order_relaxed);
    imdb_result_free(&r);
    return rc;
}

/* the session's zone, as SHOW TIME ZONE gives it: loaded from the shell's own zoneinfo (UTC built in) */
static int zone_take(shell *sh, imdb_err *e)
{
    imdbc_stmt st = {"SHOW TIME ZONE", 14, NULL, 0};
    if (imdbc_query(sh->c, &st, 1, e)) return e->code;
    char name[256] = "";
    int rc = IMDB_OK;
    for (;;) {
        imdbw_msg m;
        if (imdbc_next(sh->c, &m, e)) return e->code;
        if (m.type == IMDBW_READY) break;
        if (m.type == IMDBW_ERROR) rc = imdb_fail(e, cli_res_code(m.code), "SHOW TIME ZONE: %.*s", (int)m.texts[0].len, (const char *)m.texts[0].p);
        if (m.type == IMDBW_ROWS && m.nsets == 1) {
            imdb_rd rd;
            imdbw_value v;
            imdbw_span_begin(&m.vals, &rd);
            if (imdbw_span_next(&rd, &v) && !v.null && v.type == IMDBW_T_TEXT && v.len < sizeof name)
                memcpy(name, v.s, v.len), name[v.len] = 0;
        }
    }
    if (rc) return rc;
    if (sh->zone) {
        imdb_tz_free(sh->zone);
        imdb_free(sh->zone);
        sh->zone = NULL;
    }
    if (!name[0] || imdb_tz_builtin_utc(name, strlen(name))) return IMDB_OK;
    return imdb_tz_load(sh->zoneinfo, name, strlen(name), &sh->zone, e);
}

/* the statement's first word is SET or RESET: the session's zone may have changed */
static bool sets_something(const char *s, size_t n)
{
    size_t i = 0;
    while (i < n && (s[i] == ' ' || s[i] == '\t' || s[i] == '\r' || s[i] == '\n')) i++;
    return (n - i >= 3 && !strncasecmp(s + i, "set", 3)) || (n - i >= 5 && !strncasecmp(s + i, "reset", 5));
}

static int shell_stmt(cli_runner *rn, const char *sql, size_t len, bool copy_in)
{
    shell *sh = rn->ctx;
    int rc = net_stmt(rn, sql, len, copy_in);
    if (!rc && sets_something(sql, len)) {
        imdb_err e = {0};
        if (zone_take(sh, &e)) cli_print_err("error", &e);
    }
    return rc;
}

/* the terminal's state while the password is read without echo: a Ctrl-C there puts it back before the default action
 * ends the process (tcsetattr and raise are async-signal-safe), so the terminal never stays without echo */
static int g_pw_fd = -1;
static struct termios g_pw_t;

static void on_int_pw(int sig)
{
    if (g_pw_fd >= 0) tcsetattr(g_pw_fd, TCSAFLUSH, &g_pw_t);
    signal(sig, SIG_DFL);
    raise(sig);
}

/* the password: IMAGEDB_PASSWORD, or the terminal's, read without echo (through a buffer of the shell's own, wiped
 * after, so no copy stays in stdio's) */
static int password_of(char *out, size_t cap, size_t *len)
{
    const char *env = getenv("IMAGEDB_PASSWORD");
    if (env) {
        size_t n = strlen(env);
        if (n >= cap) return -1;
        memcpy(out, env, n);
        *len = n;
        return 0;
    }
    FILE *tty = fopen("/dev/tty", "r+");
    if (!tty) return -1;
    static char iobuf[1024];
    setvbuf(tty, iobuf, _IOFBF, sizeof iobuf);
    struct termios t, quiet;
    struct sigaction sa, old;
    bool echo_off = !tcgetattr(fileno(tty), &t);
    if (echo_off) {
        g_pw_t = t;
        g_pw_fd = fileno(tty);
        memset(&sa, 0, sizeof sa);
        sa.sa_handler = on_int_pw;
        sigemptyset(&sa.sa_mask);
        sigaction(SIGINT, &sa, &old);
        quiet = t;
        quiet.c_lflag &= ~(tcflag_t)ECHO;
        tcsetattr(fileno(tty), TCSAFLUSH, &quiet);
    }
    fputs("Password: ", tty);
    fflush(tty);
    bool ok = fgets(out, (int)cap, tty) != NULL;
    if (echo_off) {
        tcsetattr(fileno(tty), TCSAFLUSH, &t);
        sigaction(SIGINT, &old, NULL);
        g_pw_fd = -1;
    }
    fputs("\n", tty);
    fclose(tty);
    imdb_wipe(iobuf, sizeof iobuf);
    if (!ok) return -1;
    size_t n = strcspn(out, "\r\n");
    out[n] = 0;
    *len = n;
    return 0;
}

static bool pin_of(const char *hex, uint8_t pin[32])
{
    return strlen(hex) == 64 && imdb_unhex(hex, 64, pin, 32);
}

int main(int argc, char **argv)
{
    const char *sock = NULL, *host = NULL, *port = NULL, *ca = NULL, *pinhex = NULL, *user = NULL;
    shell sh;
    memset(&sh, 0, sizeof sh);
    sh.zoneinfo = "/usr/share/zoneinfo";
    bool csv = false;
    for (int i = 1; i < argc; i++) {
        if ((!strcmp(argv[i], "-c") || !strcmp(argv[i], "-f")) && i + 1 < argc) i++; /* run below, in order */
        else if (!strcmp(argv[i], "--socket") && i + 1 < argc) sock = argv[++i];
        else if (!strcmp(argv[i], "--host") && i + 1 < argc) host = argv[++i];
        else if (!strcmp(argv[i], "--port") && i + 1 < argc) port = argv[++i];
        else if (!strcmp(argv[i], "--ca") && i + 1 < argc) ca = argv[++i];
        else if (!strcmp(argv[i], "--pin") && i + 1 < argc) pinhex = argv[++i];
        else if (!strcmp(argv[i], "--user") && i + 1 < argc) user = argv[++i];
        else if (!strcmp(argv[i], "--zoneinfo") && i + 1 < argc) sh.zoneinfo = argv[++i];
        else if (!strcmp(argv[i], "--csv")) csv = true;
        else if (!strcmp(argv[i], "--identity")) sh.identity = true;
        else return usage();
    }
    if (!user || !!sock == !!host || (host && (!port || !!ca == !!pinhex))) return usage();
    uint8_t pin[32];
    if (pinhex && !pin_of(pinhex, pin)) {
        fprintf(stderr, "imagedb-client: --pin takes the 64 hex digits imagedb-server cert printed\n");
        return 2;
    }
    char pw[1024];
    size_t pwlen = 0;
    if (password_of(pw, sizeof pw, &pwlen)) {
        fprintf(stderr, "imagedb-client: no password: set IMAGEDB_PASSWORD, or run on a terminal\n");
        return 2;
    }
    signal(SIGPIPE, SIG_IGN);
    imdb_err e = {0};
    int rc;
    if (sock) {
        rc = imdbc_connect(sock, user, pw, pwlen, &sh.c, &e);
    } else {
        imdbc_tls t = {ca, pinhex ? pin : NULL};
        rc = imdbc_connect_tcp(host, port, &t, user, pw, pwlen, &sh.c, &e);
    }
    imdb_wipe(pw, sizeof pw);
    if (rc) {
        fprintf(stderr, "imagedb-client: %s\n", e.msg);
        return 1;
    }
    if (zone_take(&sh, &e)) {
        fprintf(stderr, "imagedb-client: the session's time zone: %s\n", e.msg);
        imdbc_close(sh.c);
        return 1;
    }
    cli_runner rn = {.stmt = shell_stmt, .ctx = &sh, .csv = csv, .stop_on_error = true};
    rc = 0;
    bool ran = false;
    for (int i = 1; i < argc && !rc; i++) {
        if (!strcmp(argv[i], "-c") && i + 1 < argc) {
            const char *q = argv[++i];
            rc = cli_run_text(&rn, q, strlen(q));
            ran = true;
        } else if (!strcmp(argv[i], "-f") && i + 1 < argc) {
            FILE *f = !strcmp(argv[i + 1], "-") ? stdin : fopen(argv[i + 1], "rb");
            i++;
            if (!f) {
                fprintf(stderr, "imagedb: cannot open %s: %s\n", argv[i], strerror(errno));
                rc = 1;
                break;
            }
            rc = cli_run_stream(&rn, f);
            if (f != stdin) fclose(f);
            ran = true;
        } else if (argv[i][0] == '-' && strcmp(argv[i], "--csv") && strcmp(argv[i], "--identity")) {
            i++; /* an option's value */
        }
    }
    if (!ran && !rc) {
        if (isatty(0)) cli_repl(&rn);
        else rc = cli_run_stream(&rn, stdin);
    }
    cli_runner_end(&rn);
    if (sh.state != IMDBW_IDLE) fprintf(stderr, "imagedb: open transaction rolled back at exit\n");
    imdb_err te = {0};
    if (imdbc_terminate(sh.c, &te) == 0) { /* the session's end (an open transaction rolled back) */
        imdbw_msg m;
        while (imdbc_next(sh.c, &m, &te) == 0) {}
    }
    imdbc_close(sh.c);
    if (sh.zone) {
        imdb_tz_free(sh.zone);
        imdb_free(sh.zone);
    }
    return rc || rn.failures ? 1 : 0;
}
