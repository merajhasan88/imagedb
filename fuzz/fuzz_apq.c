/* F5: the auditor's Parquet reader (tools/audit/apq.c, its own code) against the engine's (src/parquet.c) on the same
 * bytes, with fuzz_parquet's four sets of shapes and its seeds (a byte picking the set, then the file). The engine
 * accepting (its footer, its read and every chunk's SHA-256) means the auditor accepts; the auditor accepting means the
 * engine does, but for the engine's DOUBLE rule (imagedb's FLOAT64, which the auditor's own value check applies after
 * the read). An allocation refused gives no verdict. A disagreement aborts. */
#include <stdio.h>

#include "../src/parquet.h"
#include "../tools/audit/apq.h"
#include "fuzz_common.h"

enum { MAXC = 26, NSETS = 4 };

static void shape23(int c, pq_col *p)
{
    static const char *const nm[MAXC] = {"imdb$vid", "imdb$begin", "imdb$flags", "imdb$salt", "imdb$commit", "k", "i",
                                         "s", "d", "w", "t", "b", "ts", "tz", "dt", "tm", "u", "by", "f", "iv", "en",
                                         "rt", "zn", "d9", "d19", "d30"};
    memset(p, 0, sizeof *p);
    p->name = nm[c];
    p->field_id = c == 0 ? 2147483540 : c == 1 ? 2147483539 : c < 5 ? 2147483000 + c : c + 1; /* F5b: the lake's */
    switch (c) {
    case 0: case 1: p->phys = PQ_INT64; break;
    case 2: p->phys = PQ_INT32; break;
    case 3: p->phys = PQ_FLBA; p->type_length = 16; break;
    case 4: p->phys = PQ_FLBA; p->type_length = 32; break;
    case 5: p->phys = PQ_INT64; p->logical = PQL_INT; p->int_bits = 64; p->stats = true; break;
    case 6: p->phys = PQ_INT32; p->logical = PQL_INT; p->int_bits = 32; p->stats = true; p->optional = true; break;
    case 7: p->phys = PQ_INT32; p->logical = PQL_INT; p->int_bits = 16; p->stats = true; p->optional = true; break;
    case 8: p->phys = PQ_INT64; p->logical = PQL_DECIMAL; p->scale = 2; p->precision = 10; p->stats = true; p->optional = true; break;
    case 9: p->phys = PQ_FLBA; p->type_length = 16; p->logical = PQL_DECIMAL; p->scale = 6; p->precision = 38; p->optional = true; break;
    case 10: p->phys = PQ_BYTE_ARRAY; p->logical = PQL_STRING; p->optional = true; break;
    case 11: p->phys = PQ_BOOLEAN; p->stats = true; p->optional = true; break;
    case 12: p->phys = PQ_INT64; p->logical = PQL_TIMESTAMP; p->stats = true; p->optional = true; break;
    case 13: p->phys = PQ_INT64; p->logical = PQL_TIMESTAMP; p->utc = true; p->stats = true; p->optional = true; break;
    case 14: p->phys = PQ_INT32; p->logical = PQL_DATE; p->stats = true; p->optional = true; break;
    case 15: p->phys = PQ_INT64; p->logical = PQL_TIME; p->stats = true; p->optional = true; break;
    case 16: p->phys = PQ_FLBA; p->type_length = 16; p->logical = PQL_UUID; p->optional = true; break;
    case 17: p->phys = PQ_BYTE_ARRAY; p->optional = true; break;
    case 18: p->phys = PQ_DOUBLE; p->stats = true; p->optional = true; break;
    case 19: p->phys = PQ_FLBA; p->type_length = 16; p->optional = true; break;
    case 20: p->phys = PQ_INT64; p->stats = true; p->optional = true; break;
    case 21: p->phys = PQ_BYTE_ARRAY; p->logical = PQL_STRING; break;
    case 22: p->phys = PQ_INT64; p->logical = PQL_INT; p->int_bits = 64; p->stats = true; p->optional = true; break;
    /* F5b: a DECIMAL by Iceberg's widths (fuzz_parquet's set 3) */
    case 23: p->phys = PQ_INT32; p->logical = PQL_DECIMAL; p->scale = 2; p->precision = 9; p->stats = true; p->optional = true; break;
    case 24: p->phys = PQ_FLBA; p->type_length = 9; p->logical = PQL_DECIMAL; p->precision = 19; break;
    case 25: p->phys = PQ_FLBA; p->type_length = 13; p->logical = PQL_DECIMAL; p->scale = 4; p->precision = 30; p->optional = true; break;
    }
}

static uint32_t shapes(int k, pq_col *sh)
{
    static const int pick[NSETS][MAXC] = {{0}, {0, 10, 21}, {0, 11, 14, 16}, {0, 23, 24, 25}};
    static const uint32_t nc[NSETS] = {23, 3, 4, 4};
    for (uint32_t c = 0; c < nc[k]; c++) shape23(k == 0 ? (int)c : pick[k][c], &sh[c]);
    if (k == 2) sh[2].optional = false; /* a REQUIRED DATE */
    return nc[k];
}

/* the same shape in the auditor's terms (its enums are parquet.thrift's types and the subset's annotations) */
static void to_apq(const pq_col *p, apq_shape *a)
{
    static const uint8_t lg[] = {[PQL_NONE] = APQ_L_NONE,       [PQL_STRING] = APQ_L_STRING, [PQL_DECIMAL] = APQ_L_DECIMAL,
                                 [PQL_DATE] = APQ_L_DATE,       [PQL_TIME] = APQ_L_TIME,     [PQL_TIMESTAMP] = APQ_L_TIMESTAMP,
                                 [PQL_INT] = APQ_L_INT,         [PQL_UUID] = APQ_L_UUID};
    memset(a, 0, sizeof *a);
    a->name = p->name;
    a->id = p->field_id;
    a->phys = p->phys;
    a->logical = lg[p->logical];
    a->opt = p->optional;
    a->utc = p->utc;
    a->stats = p->stats;
    a->bits = p->int_bits;
    a->tlen = p->type_length;
    a->scale = p->scale;
    a->prec = p->precision;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < 1) return 0;
    int k = data[0] % NSETS;
    size_t len = size - 1;
    uint8_t *f = malloc(len ? len : 1); /* exactly the file */
    memcpy(f, data + 1, len);
    pq_col sh[PQ_MAX_COLUMNS];
    apq_shape ash[APQ_MAX_COLS];
    uint32_t nc = shapes(k, sh);
    for (uint32_t c = 0; c < nc; c++) to_apq(&sh[c], &ash[c]);
    /* the engine: its footer, its read, each chunk's hash */
    pq_footer ft;
    pq_rcol r[PQ_MAX_COLUMNS];
    imdb_err e = {0};
    int er = imdb_pq_footer(f, len, &ft, &e);
    if (!er) {
        er = imdb_pq_read(f, len, &ft, sh, nc, r, &e);
        if (!er) {
            er = imdb_pq_chunks_verify(f, &ft, &e);
            imdb_pq_free_read(r, nc);
        }
    }
    bool no_verdict = er == IMDB_ERR_NOMEM || er == IMDB_ERR_LIMIT;
    /* the auditor's */
    apq_file af;
    const char *why = NULL;
    int ar = apq_read(f, len, ash, nc, &af, &why);
    if (!ar) apq_free(&af);
    if (!no_verdict) {
        if (!er && ar) abort(); /* the engine took what the auditor refuses */
        if (er && !ar && !strstr(e.msg, "a DOUBLE not finite")) abort(); /* the auditor took what the engine refuses */
    }
    free(f);
    return 0;
}
