/* L (N2's records): SCRAM verifiers' text (PostgreSQL's) and bytes (a payload entry's), and manifest 18's roles section
 * with its roles object, from any bytes: never undefined behaviour, and whatever is taken has one encoding (each read
 * back and written again is the input). The first byte picks the reader. */
#include "../src/role.h"
#include "../src/scram.h"
#include "fuzz_common.h"

static void scram_text(const uint8_t *d, size_t n)
{
    imdb_scram v, w;
    imdb_err e = {0};
    if (imdb_scram_parse((const char *)d, n, &v, &e)) return;
    char t[IMDB_SCRAM_TEXT_MAX + 1];
    size_t k = imdb_scram_format(&v, t, sizeof t);
    if (k != n || memcmp(t, d, n)) abort(); /* the canonical text alone parses */
    uint8_t b[IMDB_SCRAM_BYTES_MAX];
    size_t bl = imdb_scram_encode(&v, b);
    if (imdb_scram_decode(b, bl, &w, &e) || memcmp(&v, &w, sizeof v)) abort();
}

static void scram_bytes(const uint8_t *d, size_t n)
{
    imdb_scram v;
    imdb_err e = {0};
    if (imdb_scram_decode(d, n, &v, &e)) return;
    uint8_t b[IMDB_SCRAM_BYTES_MAX];
    size_t bl = imdb_scram_encode(&v, b);
    if (bl != n || memcmp(b, d, n)) abort();
}

/* u32 the section's length | section 5's bytes | the roles object's: parsed at a commit far on, then the object filled
 * both ways; what is taken is written again byte for byte */
static void roles(const uint8_t *d, size_t n)
{
    if (n < 4) return;
    uint32_t l5 = (uint32_t)d[0] | (uint32_t)d[1] << 8 | (uint32_t)d[2] << 16 | (uint32_t)d[3] << 24;
    if (l5 > n - 4) return;
    const uint8_t *s5 = d + 4, *obj = d + 4 + l5;
    size_t ol = n - 4 - l5;
    for (int strict = 0; strict < 2; strict++) {
        imdb_rd r;
        imdb_rd_init(&r, s5, l5);
        imdb_rcat c;
        uint8_t oh[32];
        imdb_err e = {0};
        if (imdb_rcat_get_roles(&r, UINT64_MAX / 2, &c, oh, &e)) return;
        if (imdb_rd_left(&r)) {
            imdb_rcat_free(&c);
            return;
        }
        imdb_buf b;
        imdb_buf_init(&b);
        imdb_rcat_put_roles(&b, &c, oh);
        if (b.err || b.len != l5 || memcmp(b.p, s5, l5)) abort(); /* one encoding of a section */
        imdb_buf_free(&b);
        if (imdb_rcat_fill(&c, ol ? obj : NULL, ol, strict, &e) == 0 && strict) {
            imdb_buf o;
            imdb_buf_init(&o);
            uint8_t h[32];
            if (imdb_rcat_object(&c, &o, h, &e) == 0 && (o.len != ol || (ol && memcmp(o.p, obj, ol)))) abort();
            imdb_buf_free(&o);
        }
        imdb_rcat_free(&c);
    }
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (!size) return 0;
    uint8_t *b = malloc(size);
    memcpy(b, data, size);
    if (data[0] % 3 == 0) scram_text(b + 1, size - 1);
    else if (data[0] % 3 == 1) scram_bytes(b + 1, size - 1);
    else roles(b + 1, size - 1);
    free(b);
    return 0;
}
