/* N1d-2: the SQL shell's runner (run.h), moved from src/main.c whole: the splitting, COPY's data source and the REPL;
 * the statement itself through the backend. */
#include "run.h"

#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>

#include "../src/limits.h"
#include "../src/sql.h"

void cli_print_err(const char *what, const imdb_err *e)
{
    fprintf(stderr, "imagedb: %s: %s (%s)\n", what, e->msg[0] ? e->msg : "error", imdb_err_name(e->code));
}

/* P2 S10: where COPY ... FROM STDIN's data comes from, as psql serves it: a script's text after the statement (the
 * buffer the script's statements are split from, then more of its file), or stdin (-c, the REPL). The engine gets the
 * bytes up to a line \. outside quotes (psql's end of data) or the file's end, and sees the end there; a script's next
 * statement starts on the line after the \. line. The quotes are followed as CSV's: "" inside them toggles twice */
struct cli_src {
    FILE *f;
    char *b;          /* the bytes: the script's buffer, or stdin's own */
    size_t n, cap;    /* filled, and its size */
    size_t pos;       /* the first byte the engine has not had */
    bool eof, err;    /* f ended, or failed */
    bool tty;         /* f a terminal: a line at a time, nothing read past the line asked for */
    bool bol, inq;    /* the scan: at a line's start, inside quotes */
    bool done;        /* the data's end was reached (\. or the file's end) */
};


enum { COPY_TOOK_DATA = 1 }; /* run_one to the splitter: a COPY took the data after it; resume at script->pos */

/* room to read into: two bytes at least (a terminal's line and its NUL) */
static bool src_full(const cli_src *s) { return s->cap - s->n < 2; }

/* more bytes after n: a line from a terminal, else what one read gives; 0 at the end (or a failure: err), or when
 * full (the caller makes room first) */
static size_t src_read(cli_src *s)
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
static void src_drop(cli_src *s, size_t k)
{
    memmove(s->b, s->b + k, s->n - k);
    imdb_wipe(s->b + s->n - k, k);
    s->n -= k;
    s->pos -= k < s->pos ? k : s->pos;
}

/* at least k bytes from pos, unless the file ends first: how many there are */
static size_t src_need(cli_src *s, size_t k)
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
long cli_copy_read(void *arg, char *out, size_t cap)
{
    cli_runner *rn = arg;
    cli_src *s = rn->active;
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
int cli_copy_write(void *arg, const char *b, size_t n)
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
static int skip_rest_of_line(cli_src *s)
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

/* one statement from the splitter: a COPY ... FROM STDIN's data source made ready (the script after it, on the next line,
 * or stdin), the statement through the backend, then a COPY's data skipped to its end, so the script goes on after it */
static int run_one(void *arg, const char *sql, size_t len)
{
    cli_runner *rn = arg;
    imdb_err e = {0};
    char *own = NULL;
    cli_src *src = NULL;
    if (starts_copy(sql, len) && imdb_copy_in_stmt(sql, len)) {
        if (!(own = imdb_alloc(len, &e))) {
            cli_print_err("error", &e);
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
                    cli_print_err("error", &e);
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
    int rc = rn->stmt(rn, sql, len, src != NULL);
    if (src) { /* a COPY that stopped before its data's end: the rest is skipped to it, so the script goes on after */
        char sink[4096];
        while (!src->done && cli_copy_read(rn, sink, sizeof sink) > 0) {}
        imdb_wipe(sink, sizeof sink);
        rn->active = NULL;
        imdb_wipe(own, len);
        imdb_free(own);
    }
    int took = src && rn->script ? COPY_TOOK_DATA : 0; /* the splitter resumes after the data */
    if (rc) {
        rn->failures++;
        /* a cancel stops what remains of the input too: Ctrl-C asked for the run to stop, not for its next statement */
        return rn->stop_on_error || rc == IMDB_ERR_CANCELLED ? rc : took;
    }
    return took;
}

void cli_runner_end(cli_runner *rn)
{
    if (!rn->in) return;
    imdb_wipe(rn->in->b, rn->in->cap);
    imdb_free(rn->in->b);
    imdb_free(rn->in);
    rn->in = NULL;
}

int cli_run_text(cli_runner *rn, const char *text, size_t len)
{
    imdb_err e = {0};
    int rc = imdb_split_statements(text, len, run_one, rn, &e);
    if (rc && e.code) cli_print_err("error", &e);
    return rc;
}

/* A script read in chunks (-f FILE, -f -, piped input): each complete statement runs as it arrives, so a script of any
 * size runs in the memory of its longest statement (IMDB_MAX_SQL) and a chunk; at the end of the stream the rest runs
 * as imdb_split_statements runs a text (an unterminated literal is the error it is). Before 2026-11-04 the whole input
 * was read first, and only its first 16 MiB: a longer script was cut, silently. */
int cli_run_stream(cli_runner *rn, FILE *f)
{
    enum { CHUNK = 1 << 20 };
    imdb_err e = {0};
    cli_src s; /* the script's buffer, which a COPY in it reads its data from too (P2 S10) */
    memset(&s, 0, sizeof s);
    s.f = f;
    s.cap = CHUNK;
    s.tty = isatty(fileno(f));
    if (!(s.b = imdb_alloc(s.cap, &e))) { /* the helpers' throughout: imdb_realloc_array credits the old block */
        cli_print_err("error", &e);
        return 1;
    }
    cli_src *outer = rn->script;
    rn->script = &s;
    int rc = 0;
    for (;;) {
        if (s.n) {
            size_t used = 0;
            imdb_err es = {0};
            rc = imdb_split_complete(s.b, s.n, run_one, rn, &used, &es);
            if (rc == COPY_TOOK_DATA) { /* a COPY took the data after it: the text goes on after the data's end */
                src_drop(&s, s.pos);
                rc = 0;
                continue;
            }
            if (rc) {
                if (es.code) cli_print_err("error", &es);
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
                cli_print_err("error", &e);
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
                rc = imdb_split_statements(s.b, s.n, run_one, rn, &e);
                if (rc != COPY_TOOK_DATA) {
                    if (rc && e.code) cli_print_err("error", &e);
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
int cli_repl(cli_runner *rn)
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
        if (!acc.len && line[0] == '\\' && rn->meta && rn->meta(rn, line)) continue; /* N1e stage two: the client's */
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
            cli_run_text(rn, (const char *)acc.p, acc.len);
            acc.len = 0;
        }
    }
    imdb_buf_free(&acc);
    return 0;
}
