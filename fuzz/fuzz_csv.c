/* P2 S10: COPY's CSV reader (src/csv.c) on any bytes, read in pieces, against a reference that reads the whole input at
 * once by the same rules (csv.h): both must give the same records (each field's bytes and whether it was quoted) and
 * stop at the same record, refused or at the end. The first byte is a read's size (1..256), the second picks the
 * delimiter; the rest is the stream. A disagreement aborts. */
#include <stdio.h>

#include "../src/csv.h"
#include "fuzz_common.h"

typedef struct src {
    const uint8_t *s;
    size_t n, i, piece;
} src;

static long src_rd(void *arg, char *buf, size_t cap)
{
    src *p = arg;
    size_t k = p->n - p->i;
    if (k > cap) k = cap;
    if (k > p->piece) k = p->piece;
    memcpy(buf, p->s + p->i, k);
    p->i += k;
    return (long)k;
}

/* the reference: a record from s at *i, its fields into fb (each followed by a NUL); 1, 0 at the end, -1 refused */
typedef struct ref {
    const uint8_t *s;
    size_t n, i;
    char d;
    int eol;
    uint64_t recs;
    char *fb;
    size_t fbl;
    uint32_t off[IMDB_MAX_COLS], len[IMDB_MAX_COLS];
    bool q[IMDB_MAX_COLS];
    uint16_t nf;
} ref;

static int ref_next(ref *r)
{
    r->nf = 0;
    r->fbl = 0;
    if (r->i == r->n) return 0;
    bool first = r->recs == 0;
    for (;;) {
        if (r->nf == IMDB_MAX_COLS) return -1;
        uint16_t f = r->nf++;
        size_t start = r->fbl;
        r->off[f] = (uint32_t)start;
        r->q[f] = r->s[r->i] == '"';
        if (r->q[f]) {
            r->i++;
            for (;;) {
                if (r->i == r->n) return -1; /* the data ends inside quotes */
                uint8_t ch = r->s[r->i++];
                if (ch == '"') {
                    if (r->i < r->n && r->s[r->i] == '"') r->i++;
                    else break;
                }
                if (r->fbl - start >= IMDB_MAX_TEXT) return -1;
                r->fb[r->fbl++] = (char)ch;
            }
            if (r->i < r->n && r->s[r->i] != (uint8_t)r->d && r->s[r->i] != '\r' && r->s[r->i] != '\n') return -1;
        } else {
            while (r->i < r->n) {
                uint8_t ch = r->s[r->i];
                if (ch == (uint8_t)r->d || ch == '\r' || ch == '\n') break;
                if (ch == '"') return -1;
                if (r->fbl - start >= IMDB_MAX_TEXT) return -1;
                r->fb[r->fbl++] = (char)ch;
                r->i++;
            }
        }
        r->len[f] = (uint32_t)(r->fbl - start);
        r->fb[r->fbl++] = 0;
        if (first && f == 0 && !r->q[0] && r->len[0] >= 3 && memcmp(r->fb, "\xEF\xBB\xBF", 3) == 0) return -1;
        if (r->i == r->n) break; /* the end ends the record */
        uint8_t ch = r->s[r->i++];
        if (ch == (uint8_t)r->d) {
            if (r->i < r->n) continue;
            if (r->nf == IMDB_MAX_COLS) return -1; /* a delimiter, then the end: one empty field more */
            uint16_t g = r->nf++;
            r->off[g] = (uint32_t)r->fbl;
            r->len[g] = 0;
            r->q[g] = false;
            r->fb[r->fbl++] = 0;
            break;
        }
        int style = 1;
        if (ch == '\r') {
            if (r->i == r->n || r->s[r->i] != '\n') return -1;
            r->i++;
            style = 2;
        }
        if (r->eol && r->eol != style) return -1;
        r->eol = style;
        break;
    }
    r->recs++;
    return 1;
}

static char g_fb[IMDB_MAX_COLS * (IMDB_MAX_TEXT + 1) + 64];

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < 2) return 0;
    static const char D[] = {',', ';', '\t', '|'};
    src p = {.s = data + 2, .n = size - 2, .piece = (size_t)data[0] + 1};
    ref r = {.s = data + 2, .n = size - 2, .d = D[data[1] & 3], .fb = g_fb};
    imdb_csv c;
    imdb_err e = {0};
    if (imdb_csv_init(&c, src_rd, &p, D[data[1] & 3], &e)) return 0;
    for (;;) {
        imdb_err_clear(&e);
        int a = imdb_csv_next(&c, &e), b = ref_next(&r);
        if ((a > 0) != (b > 0) || (a == 0) != (b == 0)) abort(); /* one read a record the other refused, or ended */
        if (a <= 0) break;
        if (c.nf != r.nf || c.records != r.recs || c.rec_line < 1 || c.rec_line > c.line) abort();
        for (uint16_t i = 0; i < c.nf; i++) {
            if (c.flen[i] != r.len[i] || c.fquoted[i] != r.q[i] || c.flen[i] > IMDB_MAX_TEXT) abort();
            if (memcmp(imdb_csv_field(&c, i), r.fb + r.off[i], c.flen[i]) != 0 || imdb_csv_field(&c, i)[c.flen[i]] != 0) abort();
        }
    }
    imdb_csv_free(&c);
    return 0;
}
