/* Manifests and deletion vectors. */
#include "../src/lake.h"
#include "fuzz_common.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    uint8_t *b = malloc(size ? size : 1);
    memcpy(b, data, size);
    imdb_manifest m;
    imdb_err e = {0};
    if (imdb_manifest_parse(b, size, &m, &e) == 0) imdb_manifest_free(&m);
    uint8_t h[32];
    imdb_dv_ent *ents;
    uint32_t n;
    uint32_t nrows = size >= 4 ? (uint32_t)(data[0] | data[1] << 8) : 7;
    imdb_err e2 = {0};
    if (imdb_dv_parse(b, size, h, &ents, &n, nrows, &e2) == 0) free(ents);
    free(b);
    return 0;
}
