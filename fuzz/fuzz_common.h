/* Shared helpers for the libFuzzer harnesses (built with -fsanitize=fuzzer,address,undefined). */
#ifndef IMDB_FUZZ_COMMON_H
#define IMDB_FUZZ_COMMON_H

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "../src/codec.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

/* The fixed schemas that seed segments and rows can belong to; they must match
 * the tables fuzz/make_corpus.sh creates, in order (table id = which). */
#define FUZZ_NSCHEMAS 3
static inline void fuzz_schema(int which, imdb_schema *s)
{
    memset(s, 0, sizeof *s);
    s->id = (uint32_t)which;
    s->subject = -1;
    if (which == 0) { /* txns: the demo table */
        strcpy(s->name, "txns");
        s->ncols = 5;
        strcpy(s->cols[0].name, "id");
        s->cols[0].type = IMDB_T_INT64;
        s->cols[0].flags = IMDB_COL_PK;
        strcpy(s->cols[1].name, "user_id");
        s->cols[1].type = IMDB_T_INT64;
        s->cols[1].flags = IMDB_COL_SUBJECT;
        strcpy(s->cols[2].name, "amount");
        s->cols[2].type = IMDB_T_DECIMAL;
        s->cols[2].precision = 12;
        s->cols[2].scale = 2;
        strcpy(s->cols[3].name, "memo");
        s->cols[3].type = IMDB_T_TEXT;
        strcpy(s->cols[4].name, "at");
        s->cols[4].type = IMDB_T_TIMESTAMP;
        s->pk = 0;
        s->subject = 1;
    } else if (which == 1) { /* flags: TEXT key, BOOL */
        strcpy(s->name, "flags");
        s->ncols = 3;
        strcpy(s->cols[0].name, "k");
        s->cols[0].type = IMDB_T_TEXT;
        s->cols[0].flags = IMDB_COL_PK | IMDB_COL_SUBJECT;
        strcpy(s->cols[1].name, "b");
        s->cols[1].type = IMDB_T_BOOL;
        strcpy(s->cols[2].name, "n");
        s->cols[2].type = IMDB_T_INT64;
        s->pk = 0;
        s->subject = 0;
    } else { /* meas: FLOAT64 and nullable columns (null bitmaps, VALID sections) */
        strcpy(s->name, "meas");
        s->ncols = 5;
        strcpy(s->cols[0].name, "id");
        s->cols[0].type = IMDB_T_INT64;
        s->cols[0].flags = IMDB_COL_PK;
        strcpy(s->cols[1].name, "u");
        s->cols[1].type = IMDB_T_INT64;
        s->cols[1].flags = IMDB_COL_SUBJECT;
        strcpy(s->cols[2].name, "x");
        s->cols[2].type = IMDB_T_FLOAT64;
        s->cols[2].flags = IMDB_COL_NULLABLE;
        strcpy(s->cols[3].name, "note");
        s->cols[3].type = IMDB_T_TEXT;
        s->cols[3].flags = IMDB_COL_NULLABLE;
        strcpy(s->cols[4].name, "ok");
        s->cols[4].type = IMDB_T_BOOL;
        s->pk = 0;
        s->subject = 1;
    }
}

#endif
