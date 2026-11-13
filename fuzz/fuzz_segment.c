/* Segment files (F5: imagedb's Parquet subset, lake.h): byte 0 picks the schema; the rest is the file image. */
#include "../src/db_internal.h"
#include "../src/lake.h"
#include "fuzz_common.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < 1) return 0;
    imdb_schema s;
    fuzz_schema(data[0] % FUZZ_NSCHEMAS, &s);
    imdb_schema_hist h; /* F1: one version, the schema's (the commitment check re-encodes a row by its version) */
    memset(&h, 0, sizeof h);
    imdb_err he = {0};
    if (imdb_hist_first(&h, &s, &he)) return 0;
    size_t n = size - 1;
    uint8_t *b = aligned_alloc(8, (n + 7) & ~(size_t)7 ? (n + 7) & ~(size_t)7 : 8);
    memcpy(b, data + 1, n);
    imdb_segment *g;
    imdb_err e = {0};
    if (imdb_segment_parse(&h.vers[0], b, n, NULL, &g, &e) == 0) { /* F5: a Parquet segment of that version */
        imdb_err e2 = {0};
        imdb_segimg *gi = imdb_seg_pin(NULL, g, &e2); /* a parse of its own: apart from any table, resident */
        if (gi) (void)imdb_segment_check_commitments(&h, g, gi, &e2);
        imdb_segment_free(g);
    } else {
        free(b);
    }
    imdb_hist_free(&h);
    return 0;
}
