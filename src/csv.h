/* Strict CSV (RFC 4180) records read from a byte stream: P2 S10's COPY ... FROM STDIN. A field is quoted or not;
 * inside quotes "" is a quote and every other byte, CR and LF included, is data; outside them a quote is refused.
 * Records end with LF or CR LF, one style a stream (its first record's), and the last may end with the stream instead.
 * An unquoted empty field and a quoted one are told apart (COPY reads them as NULL and the empty string). Memory is a
 * fixed input buffer and one record's fields (at most IMDB_MAX_COLS of at most IMDB_MAX_TEXT bytes), never the
 * stream's size. An error names the line the record starts on and the field, never a value. The stream's end is its
 * reader's 0: psql's "\." line is the client's to see (main.c), so no byte the client sends after the data is read. */
#ifndef IMDB_CSV_H
#define IMDB_CSV_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "limits.h"
#include "util.h"

/* the stream: > 0 the bytes put in buf (at most cap), 0 its end, < 0 it failed */
typedef long (*imdb_csv_read_fn)(void *arg, char *buf, size_t cap);

typedef struct imdb_csv {
    imdb_csv_read_fn rd;
    void *arg;
    char delim;
    char *in;          /* IMDB_COPY_BUF bytes */
    size_t ipos, ilen;
    bool eof;
    uint8_t eol;       /* the stream's line end: 0 none yet, 1 LF, 2 CR LF */
    uint64_t line;     /* the line the next record starts on (1-based) */
    uint64_t rec_line; /* the line the record read last started on */
    uint64_t records;  /* records read */
    char *fb;          /* the record's fields, each followed by a NUL (a field may hold one too: flen says) */
    size_t fblen, fbcap;
    uint32_t foff[IMDB_MAX_COLS], flen[IMDB_MAX_COLS];
    bool fquoted[IMDB_MAX_COLS];
    uint16_t nf;
} imdb_csv;

/* delim: one byte, not a quote, CR or LF (the caller checks) */
int imdb_csv_init(imdb_csv *c, imdb_csv_read_fn rd, void *arg, char delim, imdb_err *e);
/* The next record into c's fields: 1 one was read, 0 the stream ended before one, < 0 refused or failed */
int imdb_csv_next(imdb_csv *c, imdb_err *e);
/* Wipes what it read (row values) and frees it */
void imdb_csv_free(imdb_csv *c);

static inline const char *imdb_csv_field(const imdb_csv *c, uint16_t i) { return c->fb + c->foff[i]; }

#endif
