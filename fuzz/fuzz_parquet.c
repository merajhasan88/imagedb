/* F5: the canonical Parquet subset's reader (src/parquet.c) on any bytes. The first byte picks a set of shapes (the
 * caller's: every type the lake writes; two byte arrays and an INT64; a BOOLEAN, a DATE and a UUID beside an INT64; F5b:
 * a DECIMAL of each form, an INT32, a FIXED of 9 and of 13 bytes, beside an INT64);
 * the rest is the file, read from a buffer of its exact size. Each input is refused (IMDB_ERR_CORRUPT, or an allocation
 * refused), or what the reader took is the writer's file for what it read but for the chunks' hashes (imagedb.chunks,
 * which the read does not hash): a disagreement aborts. F5b: the file named by its tail, its authentication in memory and
 * streamed in pieces give one verdict (code and message), and one accepted is a footer the reader takes whose every
 * chunk hashes to its entry. IMDB_FUZZ_PARQUET_SEEDS=DIR writes seeds there and exits
 * (fuzz/make_corpus.sh: the writer's own files, each set at a few row counts). */
#include <stdio.h>

#include "../src/parquet.h"
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
    /* F5b: a DECIMAL by Iceberg's widths: an INT32 to 9 digits, a FIXED of the least bytes past 18 */
    case 23: p->phys = PQ_INT32; p->logical = PQL_DECIMAL; p->scale = 2; p->precision = 9; p->stats = true; p->optional = true; break;
    case 24: p->phys = PQ_FLBA; p->type_length = 9; p->logical = PQL_DECIMAL; p->precision = 19; break;
    case 25: p->phys = PQ_FLBA; p->type_length = 13; p->logical = PQL_DECIMAL; p->scale = 4; p->precision = 30; p->optional = true; break;
    }
}

/* set k's shapes; returns its column count */
static uint32_t shapes(int k, pq_col *sh)
{
    static const int pick[NSETS][MAXC] = {{0}, {0, 10, 21}, {0, 11, 14, 16}, {0, 23, 24, 25}};
    static const uint32_t nc[NSETS] = {23, 3, 4, 4};
    for (uint32_t c = 0; c < nc[k]; c++) shape23(k == 0 ? (int)c : pick[k][c], &sh[c]);
    if (k == 2) sh[2].optional = false; /* a REQUIRED DATE */
    return nc[k];
}

static unsigned width(const pq_col *p)
{
    return p->phys == PQ_BOOLEAN ? 1 : p->phys == PQ_INT32 ? 4 : p->phys == PQ_FLBA ? (unsigned)p->type_length : 8;
}

/* f (accepted) is the writer's file for what was read from it, but for the chunks' hashes */
static bool same_but_hashes(const uint8_t *f, size_t len, const pq_footer *ft, const pq_rcol *r, uint32_t nc)
{
    pq_col cols[PQ_MAX_COLUMNS];
    for (uint32_t c = 0; c < nc; c++) cols[c] = r[c].c;
    char *ks[PQ_MAX_KV], *vs[PQ_MAX_KV];
    pq_kv kv[PQ_MAX_KV];
    uint32_t n = ft->nkv - 1;
    for (uint32_t k = 0; k < n; k++) { /* the reader refused a NUL in either: each a C string */
        ks[k] = calloc(ft->klen[k + 1] + 1, 1);
        vs[k] = calloc(ft->vlen[k + 1] + 1, 1);
        memcpy(ks[k], ft->key[k + 1], ft->klen[k + 1]);
        memcpy(vs[k], ft->val[k + 1], ft->vlen[k + 1]);
        kv[k].key = ks[k];
        kv[k].value = vs[k];
    }
    imdb_buf w;
    imdb_buf_init(&w);
    imdb_err e = {0};
    pq_footer wf;
    bool same = false;
    int rc = imdb_pq_write(cols, nc, ft->nrows, kv, n, &w, &e);
    if (rc && rc != IMDB_ERR_NOMEM && rc != IMDB_ERR_LIMIT) abort(); /* the reader took what the writer refuses */
    if (!rc && w.len == len && !imdb_pq_footer(w.p, w.len, &wf, &e) && wf.ncols == ft->ncols) {
        uint8_t *t = malloc(len);
        memcpy(t, f, len);
        for (uint32_t ci = 0; ci < ft->ncols; ci++) memcpy(t + (ft->chunk_hex[ci] - f), wf.chunk_hex[ci], 64);
        same = !memcmp(t, w.p, len);
        free(t);
    } else if (rc) {
        same = true; /* an allocation refused: nothing to compare */
    }
    imdb_buf_free(&w);
    for (uint32_t k = 0; k < n; k++) {
        free(ks[k]);
        free(vs[k]);
    }
    return same;
}

/* F5b: the streamed check's pieces, from the input */
typedef struct {
    const uint8_t *p;
    uint64_t len;
} mrd;

static int mrd_read(void *ctx, uint64_t off, uint8_t *buf, size_t n, imdb_err *e)
{
    const mrd *m = ctx;
    if (off > m->len || n > m->len - off) return imdb_fail(e, IMDB_ERR_IO, "fuzz: a read past the end");
    memcpy(buf, m->p + off, n);
    return IMDB_OK;
}

/* F5b: the file against its own name (its tail's hash, when it has a tail) and against a name one bit off: in memory
 * and streamed one verdict; an accepted one's footer the reader's and its chunks their entries' */
static void authenticate_both(const uint8_t *f, size_t len)
{
    uint8_t name[32], piece[4096];
    imdb_err e = {0};
    if (imdb_pq_name(f, len, name, &e)) {
        if (e.code != IMDB_ERR_CORRUPT) abort();
        memset(name, 0, sizeof name);
    }
    for (int round = 0; round < 2; round++) {
        if (round) name[31] ^= 1;
        pq_footer ft;
        imdb_err a = {0}, b = {0};
        int ra = imdb_pq_authenticate(f, len, name, &ft, &a);
        mrd m = {f, len};
        int rb = imdb_pq_authenticate_stream(mrd_read, &m, len, name, piece, sizeof piece, &b);
        if (rb == IMDB_ERR_NOMEM) continue;            /* the streamed check alone allocates (its tail): no verdict */
        if (ra != rb || strcmp(a.msg, b.msg)) abort(); /* two verdicts for one file */
        if (ra && ra != IMDB_ERR_CORRUPT && ra != IMDB_ERR_VERIFY && ra != IMDB_ERR_NOMEM) abort();
        if (!ra) {
            pq_footer f2;
            imdb_err c = {0};
            if (round || imdb_pq_footer(f, len, &f2, &c) || imdb_pq_chunks_verify(f, &f2, &c)) abort();
        }
    }
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < 1) return 0;
    int k = data[0] % NSETS;
    size_t len = size - 1;
    uint8_t *f = malloc(len ? len : 1); /* exactly the file: a read past it is the sanitizer's */
    memcpy(f, data + 1, len);
    authenticate_both(f, len);
    pq_col sh[PQ_MAX_COLUMNS];
    uint32_t nc = shapes(k, sh);
    pq_footer ft;
    imdb_err e = {0};
    if (!imdb_pq_footer(f, len, &ft, &e)) {
        (void)imdb_pq_chunks_verify(f, &ft, &e);
        pq_rcol r[PQ_MAX_COLUMNS];
        int rc = imdb_pq_read(f, len, &ft, sh, nc, r, &e);
        if (!rc) {
            if (!same_but_hashes(f, len, &ft, r, nc)) abort(); /* accepted, and not the writer's for what it holds */
            imdb_pq_free_read(r, nc);
        } else if (rc != IMDB_ERR_CORRUPT && rc != IMDB_ERR_NOMEM && rc != IMDB_ERR_LIMIT) {
            abort();
        }
    } else if (e.code != IMDB_ERR_CORRUPT) {
        abort();
    }
    free(f);
    return 0;
}

/* ---- seeds: each set at a few row counts, written by the writer ---- */

static uint64_t rng = 0x9e3779b97f4a7c15ull;
static uint64_t next(void)
{
    rng ^= rng << 13;
    rng ^= rng >> 7;
    rng ^= rng << 17;
    return rng;
}

/* t_pq's pq_read_past_end on a seed: the last chunk (a REQUIRED BYTE_ARRAY: set 1's rt) bent past the file's end, its
 * page header, its last value's length, its size in the footer and in imagedb.chunks (zero hashes) all claiming bytes
 * past the end, each number within the footer's bound, so the engine's footer takes it and its chunk check and read
 * refuse it. Random mutation never makes the footer's numbers and imagedb.chunks' text agree: both harnesses start
 * from it (make_corpus.sh copies these seeds to fuzz_apq's). 0, the file in g */
static int bend_past_end(const pq_col *c, uint32_t nc, uint64_t n, const imdb_buf *b, imdb_buf *g)
{
    uint32_t L = nc - 1;
    if (c[L].phys != PQ_BYTE_ARRAY || c[L].optional || n < 1) return -1;
    pq_col sh[PQ_MAX_COLUMNS];
    for (uint32_t k = 0; k < nc; k++) {
        sh[k] = c[k];
        sh[k].fixed = sh[k].data = sh[k].present = NULL;
        sh[k].off = NULL;
    }
    pq_footer ft;
    pq_rcol r[PQ_MAX_COLUMNS];
    imdb_err e = {0};
    if (imdb_pq_footer(b->p, b->len, &ft, &e) || imdb_pq_read(b->p, b->len, &ft, sh, nc, r, &e)) return -1;
    int rc = -1;
    uint64_t last = r[L].c.off[n] - r[L].c.off[n - 1];
    uint64_t psize = 4 * n + r[L].c.off[n], claim = (b->len - ft.meta_at) + 64;
    imdb_buf h0, h1;
    imdb_buf_init(&h0);
    imdb_buf_init(&h1);
    imdb_pq_page_header_encode(&h0, (uint32_t)psize, n);
    imdb_pq_page_header_encode(&h1, (uint32_t)(psize + claim), n);
    if (ft.size[L] + claim <= ft.meta_at && h0.len == h1.len && h0.len + psize == ft.size[L]) {
        imdb_buf_put(g, b->p, ft.off[L]);
        imdb_buf_put(g, h1.p, h1.len);
        imdb_buf_put(g, b->p + ft.off[L] + h0.len, psize);
        if (!imdb_buf_check(g, &e)) imdb_le32(g->p + ft.off[L] + h1.len + psize - (4 + last), (uint32_t)(claim + last));
        uint64_t size[PQ_MAX_COLUMNS];
        memcpy(size, ft.size, sizeof size);
        size[L] += claim;
        char list[PQ_MAX_COLUMNS * 112];
        size_t at = 0;
        for (uint32_t ci = 0; ci < nc; ci++)
            at += (size_t)snprintf(list + at, sizeof list - at, "%llu,%llu,%064d;", (unsigned long long)ft.off[ci],
                                   (unsigned long long)size[ci], 0);
        const uint8_t *val[PQ_MAX_KV + 1];
        uint32_t vlen[PQ_MAX_KV + 1];
        memcpy(val, ft.val, sizeof val);
        memcpy(vlen, ft.vlen, sizeof vlen);
        val[0] = (const uint8_t *)list;
        vlen[0] = (uint32_t)at;
        pq_col cols[PQ_MAX_COLUMNS];
        for (uint32_t k = 0; k < nc; k++) cols[k] = r[k].c;
        size_t meta = g->len;
        imdb_pq_footer_encode(g, cols, nc, n, ft.off, size, ft.key, ft.klen, val, vlen, ft.nkv);
        imdb_buf_put_u32(g, (uint32_t)(g->len - meta));
        imdb_buf_put(g, "PAR1", 4);
        rc = imdb_buf_check(g, &e) ? -1 : 0;
    }
    imdb_buf_free(&h0);
    imdb_buf_free(&h1);
    imdb_pq_free_read(r, nc);
    return rc;
}

static void seed(const char *dir, int k, uint64_t n, bool bend)
{
    pq_col c[PQ_MAX_COLUMNS];
    uint32_t nc = shapes(k, c);
    void *own[3 * PQ_MAX_COLUMNS];
    int no = 0;
    for (uint32_t ci = 0; ci < nc; ci++) {
        pq_col *p = &c[ci];
        if (p->optional) {
            uint8_t *pr = calloc(n / 8 + 1, 1);
            for (uint64_t i = 0; i < n; i++)
                if (next() % 3) pr[i >> 3] |= (uint8_t)(1u << (i & 7));
            p->present = pr;
            own[no++] = pr;
        }
        if (p->phys == PQ_BYTE_ARRAY) {
            uint64_t *off = calloc(n + 1, 8);
            uint8_t *d = calloc(n * 8 + 1, 1);
            for (uint64_t i = 0; i < n; i++) {
                uint64_t l = next() % 8;
                for (uint64_t j = 0; j < l; j++) d[off[i] + j] = (uint8_t)('a' + next() % 26);
                off[i + 1] = off[i] + l;
            }
            p->off = off;
            p->data = d;
            own[no++] = off;
            own[no++] = d;
            continue;
        }
        unsigned w = width(p);
        uint8_t *v = calloc(n, w);
        for (uint64_t i = 0; i < n; i++) {
            uint8_t *x = v + i * w;
            if (p->phys == PQ_BOOLEAN) x[0] = (uint8_t)(next() & 1);
            else if (p->phys == PQ_DOUBLE) {
                double dv = (double)(int64_t)(next() % 2001) - 1000.0;
                memcpy(x, &dv, 8);
            } else if (ci == 0 && p->phys == PQ_INT64) {
                uint64_t u = i + 1;
                memcpy(x, &u, 8);
            } else {
                for (unsigned j = 0; j < w; j++) x[j] = (uint8_t)next();
            }
        }
        p->fixed = v;
        own[no++] = v;
    }
    pq_kv kv[] = {{"imagedb.format", "1"}, {"imagedb.table", "7"}};
    imdb_buf b;
    imdb_buf_init(&b);
    imdb_err e = {0};
    imdb_buf g;
    imdb_buf_init(&g);
    if (!imdb_pq_write(c, nc, n, kv, 2, &b, &e) && (!bend || !bend_past_end(c, nc, n, &b, &g))) {
        const imdb_buf *f = bend ? &g : &b;
        char path[4096];
        snprintf(path, sizeof path, "%s/set%d-rows%llu%s", dir, k, (unsigned long long)n, bend ? "-past-end" : "");
        FILE *out = fopen(path, "wb");
        uint8_t sel = (uint8_t)k;
        if (out) {
            fwrite(&sel, 1, 1, out);
            fwrite(f->p, 1, f->len, out);
            fclose(out);
        }
    }
    imdb_buf_free(&b);
    imdb_buf_free(&g);
    for (int i = 0; i < no; i++) free(own[i]);
}

int LLVMFuzzerInitialize(int *argc, char ***argv);
int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    const char *dir = getenv("IMDB_FUZZ_PARQUET_SEEDS");
    if (!dir) return 0;
    static const uint64_t ns[] = {1, 7, 9, 40};
    for (int k = 0; k < NSETS; k++)
        for (size_t i = 0; i < sizeof ns / sizeof *ns; i++) seed(dir, k, ns[i], false);
    seed(dir, 1, 40, true); /* t_pq's past-end file in set 1's shapes */
    exit(0);
}
