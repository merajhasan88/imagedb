/* Segment files: byte 0 picks the schema; the rest is the file image. */
#include "../src/lake.h"
#include "fuzz_common.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < 1) return 0;
    imdb_schema s;
    fuzz_schema(data[0] % FUZZ_NSCHEMAS, &s);
    size_t n = size - 1;
    uint8_t *b = aligned_alloc(8, (n + 7) & ~(size_t)7 ? (n + 7) & ~(size_t)7 : 8);
    memcpy(b, data + 1, n);
    imdb_segment *g;
    imdb_err e = {0};
    if (imdb_segment_parse(&s, b, n, &g, &e) == 0) {
        imdb_err e2 = {0};
        (void)imdb_segment_check_commitments(&s, g, &e2);
        imdb_segment_free(g);
    } else {
        free(b);
    }
    return 0;
}
