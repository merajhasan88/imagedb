#include "csv.h"

#include <stdio.h>
#include <string.h>

int imdb_csv_init(imdb_csv *c, imdb_csv_read_fn rd, void *arg, char delim, imdb_err *e)
{
    memset(c, 0, sizeof *c);
    c->rd = rd;
    c->arg = arg;
    c->delim = delim;
    c->line = 1;
    if (!(c->in = imdb_alloc(IMDB_COPY_BUF, e))) return e->code;
    c->fbcap = 4096;
    if (!(c->fb = imdb_alloc(c->fbcap, e))) {
        imdb_free(c->in);
        c->in = NULL;
        return e->code;
    }
    return IMDB_OK;
}

void imdb_csv_free(imdb_csv *c)
{
    if (c->in) imdb_wipe(c->in, IMDB_COPY_BUF), imdb_free(c->in);
    if (c->fb) imdb_wipe(c->fb, c->fbcap), imdb_free(c->fb);
    c->in = c->fb = NULL;
}

static int bad(imdb_csv *c, imdb_err *e, const char *what)
{
    return imdb_fail(e, IMDB_ERR_INVALID, "COPY line %llu, field %u: %s", (unsigned long long)c->rec_line, c->nf, what);
}

/* the next byte into *ch: 1, 0 at the stream's end, < 0 the stream failed */
static int get(imdb_csv *c, int *ch, imdb_err *e)
{
    if (c->ipos == c->ilen) {
        if (c->eof) return 0;
        long n = c->rd(c->arg, c->in, IMDB_COPY_BUF);
        if (n < 0) return imdb_fail(e, IMDB_ERR_IO, "COPY line %llu: reading the data failed", (unsigned long long)c->line);
        if (n == 0) {
            c->eof = true;
            return 0;
        }
        if ((unsigned long)n > IMDB_COPY_BUF)
            return imdb_fail(e, IMDB_ERR_STATE, "COPY: the data's reader returned more bytes than it had room for");
        c->ipos = 0;
        c->ilen = (size_t)n;
    }
    *ch = (unsigned char)c->in[c->ipos++];
    return 1;
}

/* the byte after, left unread: the one get just returned is still in the buffer */
static int peek(imdb_csv *c, int *ch, imdb_err *e)
{
    int r = get(c, ch, e);
    if (r == 1) c->ipos--;
    return r;
}

/* room for n more bytes: a record's fields at most (IMDB_MAX_COLS of IMDB_MAX_TEXT bytes and a NUL each) */
static int room(imdb_csv *c, size_t n, imdb_err *e)
{
    while (c->fblen + n > c->fbcap) {
        char *nb = imdb_realloc_array(c->fb, c->fbcap, c->fbcap * 2, 1, e); /* wipes the old block */
        if (!nb) return e->code;
        c->fb = nb;
        c->fbcap *= 2;
    }
    return IMDB_OK;
}

static int put(imdb_csv *c, int ch, size_t start, imdb_err *e)
{
    if (c->fblen - start >= IMDB_MAX_TEXT) {
        char what[64];
        snprintf(what, sizeof what, "a field longer than %u bytes", IMDB_MAX_TEXT);
        return bad(c, e, what);
    }
    if (room(c, 1, e)) return e->code;
    c->fb[c->fblen++] = (char)ch;
    return IMDB_OK;
}

static int end_field(imdb_csv *c, uint16_t f, size_t start, imdb_err *e)
{
    if (room(c, 1, e)) return e->code;
    c->flen[f] = (uint32_t)(c->fblen - start);
    c->fb[c->fblen++] = 0;
    return IMDB_OK;
}

static const char BOM_MSG[] = "the data begins with a byte-order mark (U+FEFF): write it without one";

/* ch, a CR or an LF outside quotes, ends the record: CR must be CR LF, and the stream keeps one style */
static int line_end(imdb_csv *c, int ch, imdb_err *e)
{
    uint8_t style = 1;
    if (ch == '\r') {
        int nx, r = get(c, &nx, e);
        if (r < 0) return r;
        if (r == 0 || nx != '\n') return bad(c, e, "a CR outside quotes not followed by LF");
        style = 2;
    }
    if (c->eol && c->eol != style) return bad(c, e, "line ends mixed: CR LF and LF in one stream");
    c->eol = style;
    c->line++;
    return IMDB_OK;
}

int imdb_csv_next(imdb_csv *c, imdb_err *e)
{
    c->nf = 0;
    c->fblen = 0;
    int ch, r = get(c, &ch, e);
    if (r <= 0) return r; /* the end, between records */
    c->rec_line = c->line;
    bool first = c->records == 0;
    for (;;) { /* a field, its first byte in ch */
        if (c->nf == IMDB_MAX_COLS) {
            char what[64];
            snprintf(what, sizeof what, "more than %u fields", IMDB_MAX_COLS);
            return bad(c, e, what);
        }
        uint16_t f = c->nf++;
        size_t start = c->fblen;
        c->foff[f] = (uint32_t)start;
        c->fquoted[f] = ch == '"';
        bool more = false; /* a delimiter ended the field: another follows */
        if (ch == '"') {
            for (;;) {
                if ((r = get(c, &ch, e)) < 0) return r;
                if (r == 0) return bad(c, e, "a quoted field the data ends inside");
                if (ch == '"') {
                    int nx;
                    if ((r = peek(c, &nx, e)) < 0) return r;
                    if (r == 0 || nx != '"') break; /* the closing quote */
                    c->ipos++;                      /* "" inside quotes: a quote */
                } else if (ch == '\n') {
                    c->line++;
                }
                if ((r = put(c, ch, start, e))) return r;
            }
            if ((r = get(c, &ch, e)) < 0) return r;
            if (r == 1 && ch != c->delim && ch != '\r' && ch != '\n')
                return bad(c, e, "a byte after a closing quote (a delimiter or a line end must follow it)");
        } else {
            while (r == 1 && ch != c->delim && ch != '\r' && ch != '\n') {
                if (ch == '"') {
                    if (first && f == 0 && c->fblen == 3 && memcmp(c->fb, "\xEF\xBB\xBF", 3) == 0) return bad(c, e, BOM_MSG);
                    return bad(c, e, "a quote inside an unquoted field (quote the whole field)");
                }
                if ((r = put(c, ch, start, e))) return r;
                if ((r = get(c, &ch, e)) < 0) return r;
            }
        }
        if (end_field(c, f, start, e)) return e->code;
        if (first && f == 0 && !c->fquoted[0] && c->flen[0] >= 3 && memcmp(c->fb, "\xEF\xBB\xBF", 3) == 0)
            return bad(c, e, BOM_MSG);
        if (r == 0) break; /* the stream ended the record */
        if (ch == c->delim) more = true;
        else if ((r = line_end(c, ch, e))) return r;
        if (!more) break;
        if ((r = get(c, &ch, e)) < 0) return r;
        if (r == 0) { /* a delimiter, then the end: one empty field more */
            if (c->nf == IMDB_MAX_COLS) {
                char what[64];
                snprintf(what, sizeof what, "more than %u fields", IMDB_MAX_COLS);
                return bad(c, e, what);
            }
            uint16_t g = c->nf++;
            c->foff[g] = (uint32_t)c->fblen;
            c->fquoted[g] = false;
            if (end_field(c, g, c->fblen, e)) return e->code;
            break;
        }
    }
    c->records++;
    return 1;
}
