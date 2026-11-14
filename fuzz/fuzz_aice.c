/* F5c: the auditor's readers of the Iceberg layer (tools/audit/aice.c, its own code: JSON, Avro object container files,
 * Puffin, deletion-vector-v1 blobs and 64-bit roaring bitmaps) on any bytes, a first byte picking one: no crash, no
 * undefined behaviour, allocation within the input's bounds. A deletion vector it takes is the engine's own encoding of
 * its positions byte for byte (the layer's form is canonical: a container's kind by its cardinality, no runs); and what
 * the engine's writers make (src/icecodec.c) from the bytes, a vector of positions and a JSON string, it takes whole, the
 * same positions and the same string. A disagreement aborts. */
#include <stdio.h>

#include "../src/icecodec.h"
#include "../tools/audit/aice.h"
#include "fuzz_common.h"

static void walk(const aj *v, int depth)
{
    if (depth > 64) abort(); /* the parser's own bound is lower */
    if (v->kind == AJ_ARR || v->kind == AJ_OBJ)
        for (size_t k = 0; k < v->n; k++) walk(&v->v[k], depth + 1);
    if (v->kind == AJ_OBJ && v->n) (void)aj_get(v, v->key[0]);
}

static void dv_canonical(const uint8_t *b, size_t n)
{
    uint64_t *pos = NULL;
    size_t np = 0;
    const char *why;
    if (adv_read(b, n, &pos, &np, &why)) return;
    for (size_t k = 1; k < np; k++)
        if (pos[k] <= pos[k - 1]) abort(); /* positions ascend */
    imdb_buf o;
    imdb_buf_init(&o);
    imdb_err e = {0};
    if (!imdb_dv_blob(&o, pos, np, &e) && (o.len != n || memcmp(o.p, b, n))) abort(); /* one encoding */
    imdb_buf_free(&o);
    free(pos);
}

static void dv_round(const uint8_t *b, size_t n)
{
    size_t np = n / 3;
    uint64_t *pos = malloc((np ? np : 1) * sizeof *pos), at = 0;
    for (size_t k = 0; k < np; k++) { /* ascending: each a step of 1 to 2^16 and, now and then, a jump to the next 2^32 */
        uint32_t step = (uint32_t)b[3 * k] | (uint32_t)b[3 * k + 1] << 8;
        if (b[3 * k + 2] == 0xff) at = ((at >> 32) + 1) << 32;
        at += (uint64_t)step + 1;
        pos[k] = at;
    }
    imdb_buf o;
    imdb_buf_init(&o);
    imdb_err e = {0};
    if (!imdb_dv_blob(&o, pos, np, &e)) {
        uint64_t *got = NULL;
        size_t gn = 0;
        const char *why;
        if (adv_read(o.p, o.len, &got, &gn, &why) || gn != np || (np && memcmp(got, pos, np * sizeof *pos))) abort();
        free(got);
    }
    imdb_buf_free(&o);
    free(pos);
}

static void json_round(const uint8_t *b, size_t n)
{
    size_t bad;
    if (memchr(b, 0, n) || !imdb_utf8_valid(b, n, &bad)) return; /* a TEXT: UTF-8 without NUL */
    imdb_buf o;
    imdb_buf_init(&o);
    ij j;
    ij_begin(&j, &o);
    ij_obj(&j);
    ij_key(&j, "s");
    ij_str(&j, (const char *)b, n);
    ij_key(&j, "a");
    ij_arr(&j);
    ij_i64(&j, (int64_t)n);
    ij_end_arr(&j);
    ij_end_obj(&j);
    aj v;
    const char *why;
    if (!o.err) {
        if (aj_parse((const char *)o.p, o.len, &v, &why)) abort();
        const aj *s = aj_get(&v, "s");
        if (!s || s->kind != AJ_STR || strlen(s->s) != n || memcmp(s->s, b, n)) abort();
        aj_free(&v);
    }
    imdb_buf_free(&o);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (!size) return 0;
    const uint8_t *b = data + 1;
    size_t n = size - 1;
    const char *why;
    switch (data[0] % 6) {
    case 0: {
        aj v;
        if (!aj_parse((const char *)b, n, &v, &why)) {
            walk(&v, 0);
            aj_free(&v);
        }
        break;
    }
    case 1: {
        aocf o;
        if (!aocf_read(b, n, &o, &why)) {
            arr r = {o.records, o.rlen, 0, false};
            for (uint64_t k = 0; k < 4 * o.nrec + 4 && !r.bad && r.at < r.n; k++) {
                size_t l;
                if (k % 3 == 2) (void)ar_bytes(&r, &l);
                else (void)ar_long(&r);
            }
            size_t ml;
            (void)aocf_meta(&o, "schema", &ml);
        }
        break;
    }
    case 2: {
        aj f;
        if (!apuf_read(b, n, &f, &why)) {
            walk(&f, 0);
            aj_free(&f);
        }
        break;
    }
    case 3: dv_canonical(b, n); break;
    case 4: dv_round(b, n); break;
    default: json_round(b, n); break;
    }
    return 0;
}
