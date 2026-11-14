/* F5 (docs/f5-design.md): the canonical Parquet subset's codec alone (src/parquet.c). The definition levels' hybrid:
 * every pattern of every length to 16 and drawn run patterns to 300, each encoded, decoded strictly and encoded again
 * the same; every other encoding of the same levels refused (a short RLE run, a bit-packed run where an RLE run belongs,
 * nonzero padding, a cut, trailing bytes, a level not 0 or 1, a run past n). The writer: the frame (PAR1, the footer's
 * length), imagedb.chunks naming each chunk's range and SHA-256, and one output for one content. */
#include <stdlib.h>

#include "../../src/parquet.h"
#include "../../tools/audit/apq.h" /* the auditor's reader, given the files the engine refuses */
#include "../../src/sha256.h"
#include "thelp.h"

static int roundtrip(const uint8_t *lv, uint64_t n)
{
    imdb_buf b;
    imdb_buf_init(&b);
    imdb_pq_levels_encode(lv, n, &b);
    uint8_t *got = calloc(n ? n : 1, 1);
    imdb_err e = {0};
    int rc = imdb_buf_check(&b, &e) || imdb_pq_levels_decode(b.p, b.len, n, got, &e) || (n && memcmp(got, lv, n));
    free(got);
    imdb_buf_free(&b);
    return rc;
}

static void t_pq_levels_exhaustive(void)
{
    uint8_t lv[300];
    for (uint64_t n = 0; n <= 16; n++)
        for (uint64_t bits = 0; bits < (1ull << n); bits++) {
            for (uint64_t i = 0; i < n; i++) lv[i] = (uint8_t)(bits >> i & 1);
            if (roundtrip(lv, n)) {
                char m[96];
                snprintf(m, sizeof m, "levels of length %llu, pattern %llx", (unsigned long long)n, (unsigned long long)bits);
                test_fail(__FILE__, __LINE__, m);
                return;
            }
        }
    test_seed(5);
    for (int k = 0; k < 20000; k++) { /* runs of 1 to 20, lengths to 300 */
        uint64_t n = 17 + test_rand() % 284, i = 0;
        uint8_t v = (uint8_t)(test_rand() & 1);
        while (i < n) {
            uint64_t run = 1 + test_rand() % 20;
            for (uint64_t r = 0; r < run && i < n; r++) lv[i++] = v;
            v ^= 1;
        }
        if (roundtrip(lv, n)) {
            test_fail(__FILE__, __LINE__, "a drawn run pattern");
            return;
        }
    }
}

static int refused(const uint8_t *p, size_t len, uint64_t n)
{
    uint8_t lv[64];
    imdb_err e = {0};
    return imdb_pq_levels_decode(p, len, n, lv, &e) == IMDB_ERR_CORRUPT;
}

static void t_pq_levels_refused(void)
{
    /* eight 1s: canonical is RLE (header 16, value 1) */
    static const uint8_t rle8[] = {16, 1}, bp8[] = {3, 0xff}, split[] = {8, 1, 8, 1}, two[] = {16, 2};
    uint8_t lv[8];
    imdb_err e = {0};
    CHECK(imdb_pq_levels_decode(rle8, 2, 8, lv, &e) == 0 && lv[0] == 1 && lv[7] == 1);
    CHECK(refused(bp8, 2, 8));    /* the same levels bit-packed: not canonical */
    CHECK(refused(split, 4, 8));  /* two RLE runs of 4 */
    CHECK(refused(two, 2, 8));    /* a level of 2 */
    CHECK(refused(rle8, 1, 8));   /* cut */
    static const uint8_t extra[] = {16, 1, 0};
    CHECK(refused(extra, 3, 8));  /* a trailing byte */
    CHECK(refused(rle8, 2, 7));   /* a run past n */
    /* three levels 1 0 1, canonical one bit-packed group with zero padding: 0x05; its padding set: refused */
    static const uint8_t bp3[] = {3, 0x05}, pad[] = {3, 0x85}, zero[] = {1, 0};
    CHECK(imdb_pq_levels_decode(bp3, 2, 3, lv, &e) == 0 && lv[0] == 1 && lv[1] == 0 && lv[2] == 1);
    CHECK(refused(pad, 2, 3));
    CHECK(refused(zero, 2, 3));   /* a bit-packed run of no group */
}

static void t_pq_writer_frame(void)
{
    enum { N = 1000 };
    int64_t *k = calloc(N, 8);
    uint64_t *off = calloc(N + 1, 8);
    char *txt = calloc(N * 4, 1);
    uint8_t pres[N / 8 + 1];
    memset(pres, 0, sizeof pres);
    for (int i = 0; i < N; i++) {
        k[i] = i * 3 - 500;
        memcpy(txt + i * 3, "abc", 3);
        off[i + 1] = (uint64_t)(i + 1) * 3;
        if (i % 3) pres[i / 8] |= (uint8_t)(1u << (i % 8));
    }
    pq_col cols[2] = {
        {.name = "k", .field_id = 1, .phys = PQ_INT64, .logical = PQL_INT, .int_bits = 64, .stats = true, .fixed = (const uint8_t *)k},
        {.name = "t", .field_id = 2, .phys = PQ_BYTE_ARRAY, .logical = PQL_STRING, .optional = true, .off = off,
         .data = (const uint8_t *)txt, .present = pres},
    };
    pq_kv kv[] = {{"imagedb.format", "1"}};
    imdb_buf a, b;
    imdb_buf_init(&a);
    imdb_buf_init(&b);
    OK(imdb_pq_write(cols, 2, N, kv, 1, &a, E));
    OK(imdb_pq_write(cols, 2, N, kv, 1, &b, E));
    CHECK(a.len == b.len && !memcmp(a.p, b.p, a.len)); /* one output for one content */
    CHECK(a.len > 12 && !memcmp(a.p, "PAR1", 4) && !memcmp(a.p + a.len - 4, "PAR1", 4));
    uint32_t flen = imdb_get_le32(a.p + a.len - 8);
    CHECK(flen < a.len - 12);
    /* imagedb.chunks names each chunk: its range's SHA-256 as written */
    const char *key = "imagedb.chunks";
    const uint8_t *at = a.p + a.len - 8 - flen, *end = a.p + a.len - 8;
    const uint8_t *hit = NULL;
    for (const uint8_t *q = at; q + strlen(key) < end && !hit; q++)
        if (!memcmp(q, key, strlen(key))) hit = q;
    CHECK(hit);
    const uint8_t *q = hit + strlen(key) + 1; /* past the key and the value's field header: its length, a varint */
    while (*q & 0x80) q++;
    const char *v = (const char *)q + 1;
    for (int c = 0; c < 2; c++) {
        unsigned long long o, l;
        char hx[65];
        CHECK(sscanf(v, "%llu,%llu,%64[0-9a-f];", &o, &l, hx) == 3);
        CHECK(o + l <= a.len);
        uint8_t h[32];
        char want[65];
        imdb_sha256(a.p + o, l, h);
        for (int i = 0; i < 32; i++) snprintf(want + 2 * i, 3, "%02x", h[i]);
        CHECK(!strcmp(hx, want));
        v = strchr(v, ';') + 1;
    }
    imdb_buf_free(&a);
    imdb_buf_free(&b);
    free(k);
    free(off);
    free(txt);
}

/* ---- the reader: a set of every type the lake writes, round trips, flips and cuts ---- */

enum { TNC = 23 };

static void tshape(int c, pq_col *p)
{
    static const char *const nm[TNC] = {"imdb$vid", "imdb$begin", "imdb$flags", "imdb$salt", "imdb$commit",
                                        "k", "i", "s", "d", "w", "t", "b", "ts", "tz", "dt", "tm", "u", "by", "f", "iv",
                                        "en", "rt", "zn"};
    memset(p, 0, sizeof *p);
    p->name = nm[c];
    p->field_id = c < 5 ? 2147483000 + c : c + 1;
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
    }
}

static unsigned twidth(const pq_col *p)
{
    return p->phys == PQ_BOOLEAN ? 1 : p->phys == PQ_INT32 ? 4 : p->phys == PQ_FLBA ? (unsigned)p->type_length : 8;
}

static bool thas(const pq_col *p, uint64_t i) { return !p->present || (p->present[i >> 3] >> (i & 7) & 1); }

/* a set of columns and their values: the shapes picked from tshape by index */
typedef struct tset {
    uint64_t n;
    uint32_t nc;
    pq_col col[TNC];
    uint8_t *fixed[TNC], *data[TNC], *pres[TNC];
    uint64_t *off[TNC];
} tset;

/* long: a 3,000-byte value now and then; short values are 0 to 8 bytes */
static void tset_make_of(tset *s, const int *pick, uint32_t nc, uint64_t n, unsigned seed, bool longv)
{
    test_seed(seed);
    memset(s, 0, sizeof *s);
    s->n = n;
    s->nc = nc;
    for (uint32_t c = 0; c < nc; c++) {
        pq_col *p = &s->col[c];
        tshape(pick[c], p);
        unsigned w = twidth(p);
        if (p->optional) { /* runs of 1 to 20; zn NULL in every row */
            s->pres[c] = calloc(n / 8 + 1, 1);
            uint64_t i = 0;
            int v = (int)(test_rand() & 1);
            while (i < n) {
                uint64_t run = 1 + test_rand() % 20;
                for (uint64_t k = 0; k < run && i < n; k++, i++)
                    if (v && pick[c] != 22) s->pres[c][i >> 3] |= (uint8_t)(1u << (i & 7));
                v = !v;
            }
        }
        if (p->phys == PQ_BYTE_ARRAY) {
            s->off[c] = calloc(n + 1, sizeof(uint64_t));
            size_t cap = 4096 + n * 9, len = 0;
            s->data[c] = malloc(cap);
            for (uint64_t i = 0; i < n; i++) {
                size_t vl = (size_t)(test_rand() % 9);
                if (longv && i % 2000 == 1 && len + 3000 <= cap) vl = 3000;
                if (len + vl > cap) vl = 0;
                for (size_t k = 0; k < vl; k++) s->data[c][len + k] = (uint8_t)test_rand();
                len += vl;
                s->off[c][i + 1] = len;
            }
        } else {
            s->fixed[c] = calloc(n ? n : 1, w);
            for (uint64_t i = 0; i < n; i++) {
                uint8_t *v = s->fixed[c] + i * w;
                if (p->phys == PQ_BOOLEAN) {
                    v[0] = (uint8_t)(test_rand() & 1);
                } else if (p->phys == PQ_DOUBLE) { /* imagedb's FLOAT64: finite, its zero +0.0 */
                    double f = (double)(int64_t)(test_rand() % 2000001) / 7.0 - 100000.0;
                    if (i % 7 == 3) f = 0.0;
                    memcpy(v, &f, 8);
                } else {
                    for (unsigned k = 0; k < w; k++) v[k] = (uint8_t)test_rand();
                }
            }
        }
        p->fixed = s->fixed[c];
        p->off = s->off[c];
        p->data = s->data[c];
        p->present = s->pres[c];
    }
}

static void tset_make(tset *s, uint64_t n, unsigned seed, bool longv)
{
    int pick[TNC];
    for (int c = 0; c < TNC; c++) pick[c] = c;
    tset_make_of(s, pick, TNC, n, seed, longv);
}

static void tset_free(tset *s)
{
    for (uint32_t c = 0; c < s->nc; c++) {
        free(s->fixed[c]);
        free(s->data[c]);
        free(s->pres[c]);
        free(s->off[c]);
    }
}

static const pq_kv tkv[] = {{"imagedb.format", "1"}, {"imagedb.table", "7"}};

/* the set's shapes, its values left out */
static void tshapes_of(const tset *s, pq_col *sh)
{
    for (uint32_t c = 0; c < s->nc; c++) {
        sh[c] = s->col[c];
        sh[c].fixed = sh[c].data = sh[c].present = NULL;
        sh[c].off = NULL;
    }
}

/* the read columns hold the set's values: every row's presence and every present value */
static bool tset_same(const tset *s, const pq_rcol *r)
{
    for (uint32_t c = 0; c < s->nc; c++) {
        const pq_col *a = &s->col[c], *b = &r[c].c;
        unsigned w = twidth(a);
        for (uint64_t i = 0; i < s->n; i++) {
            if (thas(a, i) != thas(b, i)) return false;
            if (!thas(a, i)) continue;
            if (a->phys == PQ_BYTE_ARRAY) {
                uint64_t la = a->off[i + 1] - a->off[i], lb = b->off[i + 1] - b->off[i];
                if (la != lb || memcmp(a->data + a->off[i], b->data + b->off[i], la)) return false;
            } else if (memcmp(a->fixed + i * w, b->fixed + i * w, w)) {
                return false;
            }
        }
    }
    return true;
}

static void t_pq_read_roundtrip(void)
{
    static const uint64_t sizes[] = {1, 7, 8, 9, 100, 16383, 16384, 16385, 40000};
    for (size_t z = 0; z < sizeof sizes / sizeof *sizes; z++) {
        tset s;
        tset_make(&s, sizes[z], 11 + (unsigned)z, true);
        imdb_buf b;
        imdb_buf_init(&b);
        OK(imdb_pq_write(s.col, TNC, s.n, tkv, 2, &b, E));
        pq_footer ft;
        pq_col sh[TNC];
        pq_rcol r[TNC];
        tshapes_of(&s, sh);
        OK(imdb_pq_footer(b.p, b.len, &ft, E));
        CHECK(ft.nrows == s.n && ft.ncols == TNC && ft.nkv == 3);
        OK(imdb_pq_read(b.p, b.len, &ft, sh, TNC, r, E));
        CHECK(tset_same(&s, r));
        OK(imdb_pq_chunks_verify(b.p, &ft, E));
        for (int c = 0; c < TNC; c++) /* a REQUIRED fixed-width column is the file's own bytes, 8-byte aligned */
            if (!sh[c].optional && sh[c].phys != PQ_BOOLEAN && sh[c].phys != PQ_BYTE_ARRAY) {
                CHECK(r[c].c.fixed >= b.p && r[c].c.fixed < b.p + b.len && (r[c].c.fixed - b.p) % 8 == 0);
                CHECK(!r[c].own_fixed);
            }
        uint32_t vl;
        const uint8_t *v = imdb_pq_kv(&ft, "imagedb.table", &vl);
        CHECK(v && vl == 1 && v[0] == '7');
        CHECK(!imdb_pq_kv(&ft, "imagedb.schema", &vl));
        imdb_pq_free_read(r, TNC);
        /* the caller's shapes are the file's: another nullability, name, statistics, precision or column count is
         * refused (a column with no value writes no min or max, so its statistics flag shows only where it holds one) */
        bool en_value = false;
        for (uint64_t i = 0; i < s.n; i++) en_value |= thas(&s.col[20], i);
        for (int k = 0; k < 5; k++) {
            tshapes_of(&s, sh);
            uint32_t nc = TNC;
            if (k == 0) sh[6].optional = false;
            if (k == 1) sh[7].name = "s2";
            if (k == 2) {
                if (!en_value) continue;
                sh[20].stats = false;
            }
            if (k == 3) sh[8].precision = 11;
            if (k == 4) nc = TNC - 1;
            imdb_err e2 = {0};
            int rc = imdb_pq_read(b.p, b.len, &ft, sh, nc, r, &e2);
            if (!rc) imdb_pq_free_read(r, nc);
            if (rc != IMDB_ERR_CORRUPT) {
                char m[96];
                snprintf(m, sizeof m, "a shape lie %d over %llu rows: %d", k, (unsigned long long)s.n, rc);
                test_fail(__FILE__, __LINE__, m);
                imdb_buf_free(&b);
                tset_free(&s);
                return;
            }
        }
        imdb_buf_free(&b);
        tset_free(&s);
    }
}

/* the writer refuses what the subset does not hold, and the reader what the writer cannot write */
static int write_rc(const pq_col *cols, uint32_t nc, uint64_t n)
{
    imdb_buf b;
    imdb_buf_init(&b);
    imdb_err e = {0};
    int rc = imdb_pq_write(cols, nc, n, tkv, 2, &b, &e);
    imdb_buf_free(&b);
    return rc;
}

static void t_pq_subset_rules(void)
{
    enum { N = 6 };
    int64_t v[N] = {1, 2, 3, 4, 5, 6};
    uint8_t bo[N] = {0, 1, 0, 1, 1, 0}, pres[1] = {0x2d};
    double f[N] = {1.0, 2.0, 0.5, 3.0, 0.0, -1.0};
    uint64_t off[N + 1] = {0, 1, 2, 3, 4, 5, 6};
    uint8_t *big = calloc(IMDB_MAX_TEXT + 1, 1);
    uint64_t boff[N + 1] = {0, IMDB_MAX_TEXT, IMDB_MAX_TEXT, IMDB_MAX_TEXT, IMDB_MAX_TEXT, IMDB_MAX_TEXT, IMDB_MAX_TEXT};
    uint64_t bover[N + 1] = {0, IMDB_MAX_TEXT + 1, IMDB_MAX_TEXT + 1, IMDB_MAX_TEXT + 1, IMDB_MAX_TEXT + 1, IMDB_MAX_TEXT + 1,
                             IMDB_MAX_TEXT + 1};
    const pq_col base[3] = {
        {.name = "v", .field_id = 1, .phys = PQ_INT64, .fixed = (const uint8_t *)v},
        {.name = "b", .field_id = 2, .phys = PQ_BOOLEAN, .stats = true, .optional = true, .present = pres, .fixed = bo},
        {.name = "f", .field_id = 3, .phys = PQ_DOUBLE, .stats = true, .fixed = (const uint8_t *)f},
    };
    pq_col c[3];
    memcpy(c, base, sizeof c);
    CHECK(write_rc(c, 3, N) == 0);
    CHECK(write_rc(c, 3, 0) == IMDB_ERR_STATE); /* no rows */
    CHECK(write_rc(c, 3, IMDB_MAX_SEGMENT_ROWS + 1ull) == IMDB_ERR_STATE);
    for (int k = 0; k < 19; k++) {
        memcpy(c, base, sizeof c);
        uint8_t bo2[N];
        double f2[N];
        memcpy(bo2, bo, N);
        memcpy(f2, f, sizeof f2);
        uint32_t nc = 3;
        switch (k) {
        case 0: bo2[0] = 2; c[1].fixed = bo2; break; /* row 0 present: a BOOLEAN of 2 */
        case 1: c[0].present = pres; break;           /* REQUIRED with presence bits */
        case 2: c[1].present = NULL; break;           /* OPTIONAL without */
        case 3: f2[1] = __builtin_nan(""); c[2].fixed = (const uint8_t *)f2; break;
        case 4: f2[1] = __builtin_inf(); c[2].fixed = (const uint8_t *)f2; break;
        case 5: f2[4] = -0.0; c[2].fixed = (const uint8_t *)f2; break;
        case 6: c[0].stats = false; c[0].phys = PQ_BYTE_ARRAY; c[0].stats = true; c[0].off = off; c[0].data = big; c[0].fixed = NULL; break;
        case 7: c[0].phys = PQ_FLBA; c[0].type_length = 8; break;
        case 8: c[0].logical = PQL_STRING; break;
        case 9: c[0].logical = PQL_DECIMAL; c[0].precision = 19; break;
        case 10: c[0].logical = PQL_UUID; break;
        case 11: c[0].logical = PQL_INT; c[0].int_bits = 32; break;
        case 12: c[1].name = "v"; break;              /* two of one name */
        case 13: c[1].field_id = 1; break;            /* two of one field id */
        case 14: /* the only REQUIRED column a BOOLEAN: no REQUIRED column of four bytes a row */
            c[0].optional = true; c[0].present = pres; c[2].optional = true; c[2].present = pres;
            c[1].optional = false; c[1].present = NULL;
            break;
        case 15: c[0].name = "a234567890123456789012345678901234567890123456789012345678901234"; break; /* 64 bytes */
        case 16: c[0].field_id = 0; break;
        case 17: c[1].utc = true; break;              /* utc on a BOOLEAN */
        case 18: /* a value one byte past IMDB_MAX_TEXT (at the bound: written) */
            c[0].phys = PQ_BYTE_ARRAY; c[0].off = bover; c[0].data = big; c[0].fixed = NULL;
            nc = 3;
            break;
        }
        if (write_rc(c, nc, N) != IMDB_ERR_STATE) {
            char m[64];
            snprintf(m, sizeof m, "rule %d not refused by the writer", k);
            test_fail(__FILE__, __LINE__, m);
            free(big);
            return;
        }
    }
    /* a value of IMDB_MAX_TEXT bytes: at the bound, written */
    memcpy(c, base, sizeof c);
    c[0].phys = PQ_BYTE_ARRAY;
    c[0].off = boff;
    c[0].data = big;
    c[0].fixed = NULL;
    CHECK(write_rc(c, 3, N) == 0);
    free(big);
    /* the reader: a DOUBLE patched to NaN or -0.0 where the statistics do not move (min -1.0, max 3.0), and the file's
     * row count patched to 0 (FileMetaData's num_rows: zigzag 2 to 0, one byte either way) */
    memcpy(c, base, sizeof c);
    imdb_buf b;
    imdb_buf_init(&b);
    OK(imdb_pq_write(c, 3, N, tkv, 2, &b, E));
    pq_footer ft;
    OK(imdb_pq_footer(b.p, b.len, &ft, E));
    pq_col sh[3];
    memcpy(sh, base, sizeof sh);
    for (int k = 0; k < 3; k++) sh[k].fixed = sh[k].present = NULL;
    size_t fv = ft.off[2] + ft.size[2] - N * 8; /* f's values close its chunk (REQUIRED, one page) */
    for (int k = 0; k < 2; k++) {
        uint8_t *g = malloc(b.len);
        memcpy(g, b.p, b.len);
        double bad = k ? -0.0 : __builtin_nan("");
        memcpy(g + fv + (k ? 4 : 1) * 8, &bad, 8);
        pq_footer gf;
        pq_rcol r[3];
        imdb_err e = {0};
        int rc = imdb_pq_footer(g, b.len, &gf, &e);
        if (!rc) rc = imdb_pq_read(g, b.len, &gf, sh, 3, r, &e);
        if (!rc) imdb_pq_free_read(r, 3);
        free(g);
        CHECK(rc == IMDB_ERR_CORRUPT);
    }
    { /* FileMetaData: the schema list, then field 3 (delta 1, i64: 0x16) num_rows, then field 4's list of one struct */
        const uint8_t pat[] = {0x16, (uint8_t)(N * 2), 0x19, 0x1c};
        size_t at = SIZE_MAX;
        for (size_t i = ft.meta_at; i + sizeof pat <= ft.meta_at + ft.meta_len && at == SIZE_MAX; i++)
            if (!memcmp(b.p + i, pat, sizeof pat)) at = i;
        CHECK(at != SIZE_MAX);
        uint8_t was = b.p[at + 1];
        b.p[at + 1] = 0;
        pq_footer gf;
        imdb_err e = {0};
        CHECK(imdb_pq_footer(b.p, b.len, &gf, &e) == IMDB_ERR_CORRUPT);
        b.p[at + 1] = was;
    }
    { /* a NUL in a pair's value (imagedb.table's "7"): no flip of the masks makes one, so it is made here */
        const char *key = "imagedb.table";
        size_t at = SIZE_MAX, kl = strlen(key);
        for (size_t i = ft.meta_at; i + kl + 3 <= ft.meta_at + ft.meta_len && at == SIZE_MAX; i++)
            if (!memcmp(b.p + i, key, kl)) at = i + kl + 2; /* past the key, the value's field header and its length */
        CHECK(at != SIZE_MAX && b.p[at] == '7');
        b.p[at] = 0;
        pq_footer gf;
        pq_rcol r[3];
        imdb_err e = {0};
        int rc = imdb_pq_footer(b.p, b.len, &gf, &e);
        if (!rc) rc = imdb_pq_read(b.p, b.len, &gf, sh, 3, r, &e);
        if (!rc) imdb_pq_free_read(r, 3);
        CHECK(rc == IMDB_ERR_CORRUPT);
    }
    imdb_buf_free(&b);
}

/* the footer's walk is bounded: a list of lists (none in the subset) refused at once, never recursed into; and a read
 * claiming more rows than the REQUIRED columns' bytes allow refused before it allocates */
static void t_pq_read_bounds(void)
{
    tset s;
    tset_make(&s, 9, 4, false);
    imdb_buf b;
    imdb_buf_init(&b);
    OK(imdb_pq_write(s.col, TNC, s.n, tkv, 2, &b, E));
    pq_footer ft;
    OK(imdb_pq_footer(b.p, b.len, &ft, E));
    /* FileMetaData's last field is 7 (column_orders), then its STOP: field 8 (delta 1, a list: 0x19) inserted before the
     * STOP, a list of one list, a million deep, then an empty list of i32 */
    enum { DEEP = 1000000 };
    size_t ml = ft.meta_len - 1 + 1 + DEEP + 1 + 1, at = ft.meta_at;
    uint8_t *g = malloc(at + ml + 8);
    memcpy(g, b.p, at + ft.meta_len - 1);
    size_t p = at + ft.meta_len - 1;
    g[p++] = 0x19;
    for (int i = 0; i < DEEP; i++) g[p++] = 0x19; /* a list of one element, a list */
    g[p++] = 0x05;                                  /* an empty list of i32 */
    g[p++] = 0;                                     /* FileMetaData's STOP */
    imdb_le32(g + p, (uint32_t)ml);
    memcpy(g + p + 4, "PAR1", 4);
    {
        pq_footer gf;
        imdb_err e = {0};
        CHECK(imdb_pq_footer(g, p + 8, &gf, &e) == IMDB_ERR_CORRUPT);
    }
    free(g);
    { /* eight zero bytes between the last chunk and the footer (no flip makes room): every chunk and the footer as they
       * were, the file not the writer's */
        g = malloc(b.len + 8);
        memcpy(g, b.p, ft.meta_at);
        memset(g + ft.meta_at, 0, 8);
        memcpy(g + ft.meta_at + 8, b.p + ft.meta_at, b.len - ft.meta_at);
        pq_col sh2[TNC];
        pq_rcol r2[TNC];
        tshapes_of(&s, sh2);
        pq_footer gf;
        imdb_err e = {0};
        int rc = imdb_pq_footer(g, b.len + 8, &gf, &e);
        if (!rc) rc = imdb_pq_read(g, b.len + 8, &gf, sh2, TNC, r2, &e);
        if (!rc) imdb_pq_free_read(r2, TNC);
        free(g);
        CHECK(rc == IMDB_ERR_CORRUPT);
    }
    /* structs nested past the walk's depth (the subset's deepest is six): field 8 a struct holding a struct, 64 deep */
    enum { NEST = 64 };
    ml = ft.meta_len - 1 + 1 + NEST + NEST + 1;
    g = malloc(at + ml + 8);
    memcpy(g, b.p, at + ft.meta_len - 1);
    p = at + ft.meta_len - 1;
    g[p++] = 0x1c;                                  /* field 8 (delta 1), a struct */
    for (int i = 0; i < NEST; i++) g[p++] = 0x1c;   /* its field 1, a struct */
    for (int i = 0; i < NEST; i++) g[p++] = 0;      /* each one's STOP */
    g[p++] = 0;                                     /* FileMetaData's STOP */
    imdb_le32(g + p, (uint32_t)ml);
    memcpy(g + p + 4, "PAR1", 4);
    {
        pq_footer gf;
        imdb_err e = {0};
        CHECK(imdb_pq_footer(g, p + 8, &gf, &e) == IMDB_ERR_CORRUPT);
    }
    free(g);
    /* the row count: the caller's footer claims as many rows as the file has bytes; under a ceiling that refuses any
     * allocation, the read is refused as a lie and asks for nothing */
    pq_col sh[TNC];
    pq_rcol r[TNC];
    tshapes_of(&s, sh);
    pq_footer lie = ft;
    lie.nrows = b.len;
    uint64_t refusals = imdb_heap_ceiling_refusals();
    imdb_heap_ceiling_set(imdb_heap_bytes(), 0);
    imdb_err e = {0};
    int rc = imdb_pq_read(b.p, b.len, &lie, sh, TNC, r, &e);
    imdb_heap_ceiling_set(0, 0);
    if (!rc) imdb_pq_free_read(r, TNC);
    CHECK(rc == IMDB_ERR_CORRUPT && imdb_heap_ceiling_refusals() == refusals);
    imdb_buf_free(&b);
    tset_free(&s);
}

/* g (accepted) is the writer's file for what was read from it, but for the chunks' hashes */
static bool same_but_hashes(const uint8_t *g, size_t glen, const pq_footer *gf, const pq_rcol *r, uint32_t nc)
{
    pq_col cols[TNC];
    for (uint32_t c = 0; c < nc; c++) cols[c] = r[c].c;
    char kbuf[PQ_MAX_KV][64], vbuf[PQ_MAX_KV][64];
    pq_kv kv[PQ_MAX_KV];
    for (uint32_t k = 1; k < gf->nkv; k++) {
        if (gf->klen[k] >= 64 || gf->vlen[k] >= 64) return false;
        memcpy(kbuf[k - 1], gf->key[k], gf->klen[k]);
        kbuf[k - 1][gf->klen[k]] = 0;
        memcpy(vbuf[k - 1], gf->val[k], gf->vlen[k]);
        vbuf[k - 1][gf->vlen[k]] = 0;
        kv[k - 1].key = kbuf[k - 1];
        kv[k - 1].value = vbuf[k - 1];
    }
    imdb_buf f;
    imdb_buf_init(&f);
    imdb_err e = {0};
    pq_footer ff;
    bool same = false;
    if (!imdb_pq_write(cols, nc, gf->nrows, kv, gf->nkv - 1, &f, &e) && f.len == glen &&
        !imdb_pq_footer(f.p, f.len, &ff, &e) && ff.ncols == gf->ncols) {
        uint8_t *t = malloc(glen);
        memcpy(t, g, glen);
        for (uint32_t ci = 0; ci < gf->ncols; ci++) memcpy(t + (gf->chunk_hex[ci] - g), ff.chunk_hex[ci], 64);
        same = !memcmp(t, f.p, glen);
        free(t);
    }
    imdb_buf_free(&f);
    return same;
}

/* every flip of a byte at a position pos(i) of the file (i < npos): refused, or the file accepted is the writer's for
 * what was read but for the chunks' hashes, and the hash check fails exactly when the flip is in a chunk or a hash */
static int flips(const tset *s, const imdb_buf *b, const size_t *pos, size_t npos, uint64_t *acc, uint64_t *ref)
{
    pq_col sh[TNC];
    tshapes_of(s, sh);
    uint8_t *g = malloc(b->len);
    static const uint8_t masks[] = {0x01, 0x80, 0xff};
    int bad = 0;
    for (size_t pi = 0; pi < npos && !bad; pi++)
        for (size_t mk = 0; mk < sizeof masks && !bad; mk++) {
            size_t at = pos[pi];
            memcpy(g, b->p, b->len);
            g[at] ^= masks[mk];
            pq_footer ft;
            pq_rcol r[TNC];
            imdb_err e = {0};
            if (imdb_pq_footer(g, b->len, &ft, &e) || imdb_pq_read(g, b->len, &ft, sh, s->nc, r, &e)) {
                if (e.code != IMDB_ERR_CORRUPT) bad = 1;
                (*ref)++;
                continue;
            }
            (*acc)++;
            if (!same_but_hashes(g, b->len, &ft, r, s->nc)) bad = 2;
            bool in_chunk = false;
            for (uint32_t ci = 0; ci < ft.ncols; ci++) {
                if (at >= ft.off[ci] && at < ft.off[ci] + ft.size[ci]) in_chunk = true;
                size_t h = (size_t)(ft.chunk_hex[ci] - g);
                if (at >= h && at < h + 64) in_chunk = true;
            }
            if (!bad && in_chunk != (imdb_pq_chunks_verify(g, &ft, &e) != 0)) bad = 3;
            imdb_pq_free_read(r, s->nc);
            if (bad) fprintf(stderr, "    flip at byte %zu (mask %02x): %d\n", at, masks[mk], bad);
        }
    free(g);
    return bad;
}

static void t_pq_read_flips(void)
{
    tset s;
    tset_make(&s, 9, 3, false); /* no long values: the structure is most of the file */
    imdb_buf b;
    imdb_buf_init(&b);
    OK(imdb_pq_write(s.col, TNC, s.n, tkv, 2, &b, E));
    size_t *pos = malloc(b.len * sizeof *pos);
    for (size_t i = 0; i < b.len; i++) pos[i] = i;
    uint64_t acc = 0, ref = 0;
    int bad = flips(&s, &b, pos, b.len, &acc, &ref);
    free(pos);
    CHECK(!bad && acc > 0 && ref > acc); /* values flip unseen by the structure; the structure never */
    pq_col sh[TNC];
    tshapes_of(&s, sh);
    for (size_t cut = 0; cut < b.len; cut++) { /* every cut, and a byte more */
        pq_footer ft;
        pq_rcol r[TNC];
        imdb_err e = {0};
        CHECK(imdb_pq_footer(b.p, cut, &ft, &e) || imdb_pq_read(b.p, cut, &ft, sh, TNC, r, &e));
    }
    imdb_buf_put_u8(&b, 0);
    {
        pq_footer ft;
        imdb_err e = {0};
        CHECK(imdb_pq_footer(b.p, b.len, &ft, &e) != 0);
    }
    imdb_buf_free(&b);
    tset_free(&s);
}

/* two pages a byte-array chunk (16,385 rows): every flip in each chunk's first 48 bytes and the 8 before them, its last
 * 128 bytes (the second page whole, its header and the end of the first), and the footer */
static void t_pq_read_flips_pages(void)
{
    static const int pick[] = {0, 10, 21}; /* a REQUIRED INT64, an OPTIONAL STRING, a REQUIRED STRING */
    tset s;
    tset_make_of(&s, pick, 3, 16385, 6, false);
    imdb_buf b;
    imdb_buf_init(&b);
    OK(imdb_pq_write(s.col, 3, s.n, tkv, 2, &b, E));
    pq_footer ft;
    OK(imdb_pq_footer(b.p, b.len, &ft, E));
    size_t *pos = malloc((3 * (56 + 128) + ft.meta_len + 8) * sizeof *pos), np = 0;
    for (uint32_t ci = 0; ci < 3; ci++) {
        size_t a = ft.off[ci] >= 8 ? ft.off[ci] - 8 : 0;
        for (size_t i = a; i < ft.off[ci] + 48; i++) pos[np++] = i;
        for (size_t i = ft.off[ci] + ft.size[ci] - 128; i < ft.off[ci] + ft.size[ci]; i++) pos[np++] = i;
    }
    for (size_t i = ft.meta_at; i < b.len; i++) pos[np++] = i;
    uint64_t acc = 0, ref = 0;
    int bad = flips(&s, &b, pos, np, &acc, &ref);
    free(pos);
    CHECK(!bad && acc > 0 && ref > acc);
    imdb_buf_free(&b);
    tset_free(&s);
}

/* ---- crafted files: a lie no flip makes, its sizes and footer made consistent (as forge.c will) ---- */

static void hex64(const uint8_t *h, char *out)
{
    for (int i = 0; i < 32; i++) snprintf(out + 2 * i, 3, "%02x", h[i]);
}

/* f with its LAST chunk (one page, REQUIRED) moved pre bytes later, zeros before it (still 8-aligned when pre is), and
 * with k bytes after its values: its page header, offsets, sizes, chunk list and footer as the writer would make them,
 * so the reader's rule for that lie (the padding's offset, a page's exact size) alone stands between it and a read */
static int rebuild_last(const uint8_t *f, size_t len, const pq_col *sh, uint32_t nc, size_t pre, size_t k, imdb_buf *out)
{
    pq_footer ft;
    pq_rcol r[TNC];
    imdb_err e = {0};
    if (imdb_pq_footer(f, len, &ft, &e) || imdb_pq_read(f, len, &ft, sh, nc, r, &e)) return -1;
    uint32_t last = nc - 1;
    const pq_col *c = &r[last].c;
    uint64_t n = ft.nrows, psize;
    if (c->phys == PQ_BYTE_ARRAY) psize = 4 * n + c->off[n];
    else if (c->phys == PQ_BOOLEAN) psize = (n + 7) / 8;
    else psize = n * (c->phys == PQ_INT32 ? 4 : c->phys == PQ_FLBA ? (uint64_t)c->type_length : 8);
    imdb_buf h0, h1;
    imdb_buf_init(&h0);
    imdb_buf_init(&h1);
    imdb_pq_page_header_encode(&h0, (uint32_t)psize, n);
    imdb_pq_page_header_encode(&h1, (uint32_t)(psize + k), n);
    int rc = -1;
    /* the header's length kept, so the values stay where the padding put them */
    if (h0.len == h1.len && h0.len + psize == ft.size[last] && !memcmp(f + ft.off[last], h0.p, h0.len)) {
        uint64_t size[TNC];
        memcpy(size, ft.size, sizeof(uint64_t) * nc);
        size[last] = h1.len + psize + k;
        out->len = 0;
        uint64_t offs[TNC];
        memcpy(offs, ft.off, sizeof(uint64_t) * nc);
        offs[last] += pre;
        imdb_buf_put(out, f, ft.off[last]);
        imdb_buf_put_zeros(out, pre);
        imdb_buf_put(out, h1.p, h1.len);
        imdb_buf_put(out, f + ft.off[last] + h0.len, psize);
        imdb_buf_put_zeros(out, k);
        char list[TNC * 120];
        size_t at = 0;
        for (uint32_t ci = 0; ci < nc; ci++) {
            uint8_t h[32];
            char hx[65];
            imdb_sha256(out->p + offs[ci], size[ci], h);
            hex64(h, hx);
            at += (size_t)snprintf(list + at, sizeof list - at, "%llu,%llu,%s;", (unsigned long long)offs[ci],
                                   (unsigned long long)size[ci], hx);
        }
        const uint8_t *val[PQ_MAX_KV + 1];
        uint32_t vlen[PQ_MAX_KV + 1];
        memcpy(val, ft.val, sizeof val);
        memcpy(vlen, ft.vlen, sizeof vlen);
        val[0] = (const uint8_t *)list;
        vlen[0] = (uint32_t)at;
        pq_col cols[TNC];
        for (uint32_t ci = 0; ci < nc; ci++) cols[ci] = r[ci].c;
        size_t meta = out->len;
        imdb_pq_footer_encode(out, cols, nc, n, offs, size, ft.key, ft.klen, val, vlen, ft.nkv);
        imdb_buf_put_u32(out, (uint32_t)(out->len - meta));
        imdb_buf_put(out, "PAR1", 4);
        rc = imdb_buf_check(out, &e);
    }
    imdb_buf_free(&h0);
    imdb_buf_free(&h1);
    imdb_pq_free_read(r, nc);
    return rc;
}

static void put_varint(imdb_buf *b, uint64_t v)
{
    while (v >= 0x80) {
        imdb_buf_put_u8(b, (uint8_t)(v | 0x80));
        v >>= 7;
    }
    imdb_buf_put_u8(b, (uint8_t)v);
}

static void t_pq_read_crafted(void)
{
    enum { N = 5 };
    int64_t v[N] = {10, -20, 30, 40, -50};
    uint8_t bo[N] = {1, 0, 1, 1, 0};
    const char *txt = "abcdefghi";
    uint64_t off[N + 1] = {0, 3, 3, 5, 6, 9};
    const pq_col base[3] = {
        {.name = "v", .field_id = 1, .phys = PQ_INT64, .stats = true, .fixed = (const uint8_t *)v},
        {.name = "b", .field_id = 2, .phys = PQ_BOOLEAN, .stats = true, .fixed = bo},
        {.name = "t", .field_id = 3, .phys = PQ_BYTE_ARRAY, .logical = PQL_STRING, .off = off, .data = (const uint8_t *)txt},
    };
    /* the last chunk a fixed-width page (v alone), a BOOLEAN's (v, b), a BYTE_ARRAY's (v, t) */
    static const int pick[3][2] = {{0, -1}, {0, 1}, {0, 2}};
    for (int k = 0; k < 3; k++) {
        pq_col c[2], sh[2];
        uint32_t nc = pick[k][1] < 0 ? 1 : 2;
        for (uint32_t i = 0; i < nc; i++) {
            c[i] = base[pick[k][i]];
            sh[i] = c[i];
            sh[i].fixed = sh[i].data = NULL;
            sh[i].off = NULL;
        }
        imdb_buf b, g;
        imdb_buf_init(&b);
        imdb_buf_init(&g);
        OK(imdb_pq_write(c, nc, N, tkv, 2, &b, E));
        CHECK(rebuild_last(b.p, b.len, sh, nc, 0, 0, &g) == 0); /* the helper is faithful: no junk, the same file */
        CHECK(g.len == b.len && !memcmp(g.p, b.p, b.len));
        CHECK(rebuild_last(b.p, b.len, sh, nc, 0, 8, &g) == 0);
        pq_footer ft;
        pq_rcol r[2];
        imdb_err e = {0};
        int rc = imdb_pq_footer(g.p, g.len, &ft, &e);
        if (!rc) rc = imdb_pq_read(g.p, g.len, &ft, sh, nc, r, &e);
        if (!rc) imdb_pq_free_read(r, nc);
        if (rc != IMDB_ERR_CORRUPT) {
            char m[80];
            snprintf(m, sizeof m, "eight bytes after the last page's values (case %d): %d", k, rc);
            test_fail(__FILE__, __LINE__, m);
            imdb_buf_free(&b);
            imdb_buf_free(&g);
            return;
        }
        CHECK(rebuild_last(b.p, b.len, sh, nc, 8, 0, &g) == 0); /* the last chunk eight bytes later: aligned, misplaced */
        rc = imdb_pq_footer(g.p, g.len, &ft, &e);
        if (!rc) rc = imdb_pq_read(g.p, g.len, &ft, sh, nc, r, &e);
        if (!rc) imdb_pq_free_read(r, nc);
        if (rc != IMDB_ERR_CORRUPT) {
            char m[80];
            snprintf(m, sizeof m, "the last chunk eight bytes after its padding (case %d): %d", k, rc);
            test_fail(__FILE__, __LINE__, m);
            imdb_buf_free(&b);
            imdb_buf_free(&g);
            return;
        }
        if (k == 0) { /* FileMetaData's num_rows past the file's length (a varint of three bytes): the footer refuses */
            const uint8_t pat[] = {0x16, (uint8_t)(N * 2), 0x19, 0x1c};
            size_t at = SIZE_MAX;
            OK(imdb_pq_footer(b.p, b.len, &ft, E));
            for (size_t i = ft.meta_at; i + sizeof pat <= ft.meta_at + ft.meta_len && at == SIZE_MAX; i++)
                if (!memcmp(b.p + i, pat, sizeof pat)) at = i;
            CHECK(at != SIZE_MAX);
            g.len = 0;
            imdb_buf_put(&g, b.p, at + 1);
            put_varint(&g, 2u * 100000u); /* zigzag */
            imdb_buf_put(&g, b.p + at + 2, b.len - 8 - (at + 2));
            imdb_buf_put_u32(&g, (uint32_t)(ft.meta_len + 2));
            imdb_buf_put(&g, "PAR1", 4);
            CHECK(g.len > 0 && 100000 > g.len);
            pq_footer gf;
            CHECK(imdb_pq_footer(g.p, g.len, &gf, &e) == IMDB_ERR_CORRUPT);
        }
        imdb_buf_free(&b);
        imdb_buf_free(&g);
    }
}

/* the last chunk's page and size claiming bytes past the file's end (its page header, footer size and chunk list all
 * agreeing; each of offset and size within the footer's bound): refused as out of place before any page is read. Read
 * from a buffer of the file's exact size, so a sanitizer sees a read past it */
static void t_pq_read_past_end(void)
{
    enum { N = 200 };
    int64_t *v = calloc(N, 8);
    char *txt = malloc(N * 8);
    uint64_t off[N + 1];
    off[0] = 0;
    for (int i = 0; i < N; i++) {
        v[i] = i;
        memcpy(txt + off[i], "abcdefgh", (size_t)(i % 8));
        off[i + 1] = off[i] + (uint64_t)(i % 8);
    }
    pq_col c[2] = {
        {.name = "v", .field_id = 1, .phys = PQ_INT64, .fixed = (const uint8_t *)v},
        {.name = "t", .field_id = 2, .phys = PQ_BYTE_ARRAY, .logical = PQL_STRING, .off = off, .data = (const uint8_t *)txt},
    };
    pq_col sh[2];
    memcpy(sh, c, sizeof sh);
    for (int k = 0; k < 2; k++) {
        sh[k].fixed = sh[k].data = NULL;
        sh[k].off = NULL;
    }
    imdb_buf b, g;
    imdb_buf_init(&b);
    imdb_buf_init(&g);
    OK(imdb_pq_write(c, 2, N, tkv, 2, &b, E));
    pq_footer ft;
    pq_rcol r[2];
    OK(imdb_pq_footer(b.p, b.len, &ft, E));
    OK(imdb_pq_read(b.p, b.len, &ft, sh, 2, r, E));
    uint64_t psize = 4 * N + r[1].c.off[N], claim = (b.len - ft.meta_at) + 64; /* past the file's end */
    CHECK(ft.size[1] + claim <= ft.meta_at);                                  /* within the footer's bound */
    imdb_buf h0, h1;
    imdb_buf_init(&h0);
    imdb_buf_init(&h1);
    imdb_pq_page_header_encode(&h0, (uint32_t)psize, N);
    imdb_pq_page_header_encode(&h1, (uint32_t)(psize + claim), N);
    CHECK(h0.len == h1.len && h0.len + psize == ft.size[1]);
    imdb_buf_put(&g, b.p, ft.off[1]);
    imdb_buf_put(&g, h1.p, h1.len);
    imdb_buf_put(&g, b.p + ft.off[1] + h0.len, psize);
    /* the last value ("abcdefg") claims the page's every claimed byte after it: without the chunk's bound it would be
     * read from past the file's end */
    size_t lastp = ft.off[1] + h1.len + psize - 11;
    CHECK(g.len == lastp + 11 && imdb_get_le32(g.p + lastp) == 7);
    imdb_le32(g.p + lastp, (uint32_t)(claim + 7));
    uint64_t size[2] = {ft.size[0], ft.size[1] + claim};
    char list[300];
    size_t at = 0;
    for (int ci = 0; ci < 2; ci++) /* the hashes are not read at a load: zeros */
        at += (size_t)snprintf(list + at, sizeof list - at, "%llu,%llu,%064d;", (unsigned long long)ft.off[ci],
                               (unsigned long long)size[ci], 0);
    const uint8_t *val[PQ_MAX_KV + 1];
    uint32_t vlen[PQ_MAX_KV + 1];
    memcpy(val, ft.val, sizeof val);
    memcpy(vlen, ft.vlen, sizeof vlen);
    val[0] = (const uint8_t *)list;
    vlen[0] = (uint32_t)at;
    pq_col cols[2] = {r[0].c, r[1].c};
    size_t meta = g.len;
    imdb_pq_footer_encode(&g, cols, 2, N, ft.off, size, ft.key, ft.klen, val, vlen, ft.nkv);
    imdb_buf_put_u32(&g, (uint32_t)(g.len - meta));
    imdb_buf_put(&g, "PAR1", 4);
    imdb_pq_free_read(r, 2);
    OK(imdb_buf_check(&g, E));
    uint8_t *exact = malloc(g.len);
    memcpy(exact, g.p, g.len);
    pq_footer gf;
    imdb_err e = {0};
    int rc = imdb_pq_footer(exact, g.len, &gf, &e);
    CHECK(rc == 0 && gf.off[1] + gf.size[1] > g.len); /* the footer takes it: the read must refuse */
    imdb_err ev = {0}; /* and VERIFY's chunk check, which runs after the footer and before the read, refuses it unread */
    CHECK(imdb_pq_chunks_verify(exact, &gf, &ev) == IMDB_ERR_CORRUPT && strstr(ev.msg, "past the footer"));
    /* the auditor's own reader (tools/audit/apq.c) takes the honest file by the same shapes and refuses this one at
     * its footer, before any chunk is read, from the same exact buffer */
    apq_shape ash[2] = {{.name = "v", .id = 1, .phys = APQ_INT64}, {.name = "t", .id = 2, .phys = APQ_BYTES, .logical = APQ_L_STRING}};
    apq_file af;
    const char *why = NULL;
    int ar = apq_read(b.p, b.len, ash, 2, &af, &why);
    if (!ar) apq_free(&af);
    CHECK(ar == 0);
    why = NULL;
    ar = apq_read(exact, g.len, ash, 2, &af, &why);
    if (!ar) apq_free(&af);
    CHECK(ar != 0 && why && strstr(why, "footer"));
    rc = imdb_pq_read(exact, g.len, &gf, sh, 2, r, &e);
    if (!rc) imdb_pq_free_read(r, 2);
    free(exact);
    imdb_buf_free(&h0);
    imdb_buf_free(&h1);
    imdb_buf_free(&b);
    imdb_buf_free(&g);
    free(v);
    free(txt);
    CHECK(rc == IMDB_ERR_CORRUPT);
}

/* the writer a column at a time: the same file as imdb_pq_write's, byte for byte; a column out of its order or of
 * another shape, an end before the last column and a column past the last refused */
static void t_pq_writer_stream(void)
{
    tset s;
    tset_make(&s, 100, 21, true);
    pq_col sh[TNC];
    tshapes_of(&s, sh);
    imdb_buf a, b;
    imdb_buf_init(&a);
    imdb_buf_init(&b);
    OK(imdb_pq_write(s.col, TNC, s.n, tkv, 2, &a, E));
    pq_writer *w = calloc(1, sizeof *w);
    uint64_t bound = imdb_pq_frame_bound(tkv, 2);
    for (int c = 0; c < TNC; c++)
        bound += imdb_pq_col_bound(&sh[c], s.n, s.col[c].phys == PQ_BYTE_ARRAY ? s.col[c].off[s.n] : 0);
    OK(imdb_pq_writer_begin(w, &b, sh, TNC, s.n, bound, E));
    for (int c = 0; c < TNC; c++) OK(imdb_pq_writer_column(w, &s.col[c], E));
    OK(imdb_pq_writer_end(w, tkv, 2, E));
    CHECK(a.len == b.len && !memcmp(a.p, b.p, a.len) && b.len <= bound);
    imdb_err e2 = {0};
    OK(imdb_pq_writer_begin(w, &b, sh, TNC, s.n, 0, E));
    CHECK(imdb_pq_writer_column(w, &s.col[1], &e2) == IMDB_ERR_STATE); /* out of its order */
    OK(imdb_pq_writer_column(w, &s.col[0], E));
    CHECK(imdb_pq_writer_end(w, tkv, 2, &e2) == IMDB_ERR_STATE); /* before the last column */
    pq_col other = s.col[1];
    other.name = "x";
    CHECK(imdb_pq_writer_column(w, &other, &e2) == IMDB_ERR_STATE); /* another shape */
    for (int c = 1; c < TNC; c++) OK(imdb_pq_writer_column(w, &s.col[c], E));
    CHECK(imdb_pq_writer_column(w, &s.col[0], &e2) == IMDB_ERR_STATE); /* past the last */
    OK(imdb_pq_writer_end(w, tkv, 2, E));
    CHECK(a.len == b.len && !memcmp(a.p, b.p, a.len)); /* the refusals wrote nothing */
    free(w);
    imdb_buf_free(&a);
    imdb_buf_free(&b);
    tset_free(&s);
}

/* the writer's hashes past PQ_PAR_HASH (1 MiB) run on the pool (parquet.c hash_run): the name it hands its caller is
 * the file's SHA-256, its chunk list every chunk's, and imdb_pq_chunks_verify (the pool's too) refuses a byte flipped
 * in each chunk; under IMDB_THREADS=1 the same items run inline */
static void t_pq_writer_large(void)
{
    tset s;
    tset_make(&s, 30000, 23, true);
    pq_col sh[TNC];
    tshapes_of(&s, sh);
    imdb_buf b;
    imdb_buf_init(&b);
    pq_writer *w = calloc(1, sizeof *w);
    uint64_t bound = imdb_pq_frame_bound(tkv, 2);
    for (int c = 0; c < TNC; c++)
        bound += imdb_pq_col_bound(&sh[c], s.n, s.col[c].phys == PQ_BYTE_ARRAY ? s.col[c].off[s.n] : 0);
    OK(imdb_pq_writer_begin(w, &b, sh, TNC, s.n, bound, E));
    for (int c = 0; c < TNC; c++) OK(imdb_pq_writer_column(w, &s.col[c], E));
    OK(imdb_pq_writer_end(w, tkv, 2, E));
    CHECK(b.len > (1u << 20)); /* the pool's branch */
    uint8_t h[32];
    imdb_sha256(b.p, b.len, h);
    CHECK(!memcmp(h, w->hash, 32));
    pq_footer ft;
    OK(imdb_pq_footer(b.p, b.len, &ft, E));
    OK(imdb_pq_chunks_verify(b.p, &ft, E));
    uint32_t flipped = 0;
    for (uint32_t c = 0; c < ft.ncols; c++) {
        if (!ft.size[c]) continue;
        size_t at = ft.off[c] + ft.size[c] / 2;
        b.p[at] ^= 1;
        imdb_err e2 = {0};
        CHECK(imdb_pq_chunks_verify(b.p, &ft, &e2) == IMDB_ERR_CORRUPT);
        b.p[at] ^= 1;
        flipped++;
    }
    CHECK(flipped == TNC);
    OK(imdb_pq_chunks_verify(b.p, &ft, E));
    free(w);
    imdb_buf_free(&b);
    tset_free(&s);
}

/* imdb_pq_value_at's bound: a file whose last chunk (an INT64) claims bytes past the file's end in its footer's size
 * and imagedb.chunks (each number within the footer's bound, so imdb_pq_footer takes it): value_at refuses a row there,
 * even row 0, whose value lies inside the file, since its page header would be read from a range the file lacks */
static void t_pq_value_at_bound(void)
{
    enum { N = 200 };
    int64_t *v = calloc(N, 8);
    char *txt = malloc(N * 8);
    uint64_t off[N + 1];
    off[0] = 0;
    for (int i = 0; i < N; i++) {
        v[i] = i * 7;
        memcpy(txt + off[i], "abcdefgh", (size_t)(i % 8));
        off[i + 1] = off[i] + (uint64_t)(i % 8);
    }
    pq_col c[2] = {
        {.name = "t", .field_id = 1, .phys = PQ_BYTE_ARRAY, .logical = PQL_STRING, .off = off, .data = (const uint8_t *)txt},
        {.name = "v", .field_id = 2, .phys = PQ_INT64, .fixed = (const uint8_t *)v},
    };
    pq_col sh[2];
    memcpy(sh, c, sizeof sh);
    for (int k = 0; k < 2; k++) {
        sh[k].fixed = sh[k].data = NULL;
        sh[k].off = NULL;
    }
    imdb_buf b, g;
    imdb_buf_init(&b);
    imdb_buf_init(&g);
    OK(imdb_pq_write(c, 2, N, tkv, 2, &b, E));
    pq_footer ft;
    pq_rcol r[2];
    OK(imdb_pq_footer(b.p, b.len, &ft, E));
    OK(imdb_pq_read(b.p, b.len, &ft, sh, 2, r, E));
    size_t at0 = 0;
    OK(imdb_pq_value_at(b.p, b.len, &ft, 1, &sh[1], NULL, 0, &at0, E)); /* the honest file: row 0's value */
    CHECK(imdb_get_le64(b.p + at0) == 0);
    uint64_t claim = (b.len - ft.meta_at) + 64; /* past the file's end */
    CHECK(ft.size[1] + claim <= ft.meta_at);   /* within the footer's bound */
    imdb_buf_put(&g, b.p, ft.meta_at);        /* the chunks as they were */
    uint64_t size[2] = {ft.size[0], ft.size[1] + claim};
    char list[300];
    size_t at = 0;
    for (int ci = 0; ci < 2; ci++)
        at += (size_t)snprintf(list + at, sizeof list - at, "%llu,%llu,%064d;", (unsigned long long)ft.off[ci],
                               (unsigned long long)size[ci], 0);
    const uint8_t *val[PQ_MAX_KV + 1];
    uint32_t vlen[PQ_MAX_KV + 1];
    memcpy(val, ft.val, sizeof val);
    memcpy(vlen, ft.vlen, sizeof vlen);
    val[0] = (const uint8_t *)list;
    vlen[0] = (uint32_t)at;
    pq_col cols[2] = {r[0].c, r[1].c};
    size_t meta = g.len;
    imdb_pq_footer_encode(&g, cols, 2, N, ft.off, size, ft.key, ft.klen, val, vlen, ft.nkv);
    imdb_buf_put_u32(&g, (uint32_t)(g.len - meta));
    imdb_buf_put(&g, "PAR1", 4);
    imdb_pq_free_read(r, 2);
    OK(imdb_buf_check(&g, E));
    uint8_t *exact = malloc(g.len);
    memcpy(exact, g.p, g.len);
    pq_footer gf;
    imdb_err e = {0};
    CHECK(imdb_pq_footer(exact, g.len, &gf, &e) == 0 && gf.off[1] + gf.size[1] > g.len); /* the footer takes it */
    size_t at1 = 0;
    imdb_err e2 = {0};
    CHECK(imdb_pq_value_at(exact, g.len, &gf, 1, &sh[1], NULL, 0, &at1, &e2) == IMDB_ERR_STATE); /* refused: the bound */
    free(exact);
    imdb_buf_free(&b);
    imdb_buf_free(&g);
    free(v);
    free(txt);
}

const test_case pq_tests[] = {
    {"pq_levels_exhaustive", t_pq_levels_exhaustive},
    {"pq_levels_refused", t_pq_levels_refused},
    {"pq_writer_frame", t_pq_writer_frame},
    {"pq_writer_stream", t_pq_writer_stream},
    {"pq_writer_large", t_pq_writer_large},
    {"pq_read_roundtrip", t_pq_read_roundtrip},
    {"pq_subset_rules", t_pq_subset_rules},
    {"pq_read_bounds", t_pq_read_bounds},
    {"pq_read_flips", t_pq_read_flips},
    {"pq_read_flips_pages", t_pq_read_flips_pages},
    {"pq_read_crafted", t_pq_read_crafted},
    {"pq_read_past_end", t_pq_read_past_end},
    {"pq_value_at_bound", t_pq_value_at_bound},
};
const size_t pq_ntests = sizeof pq_tests / sizeof *pq_tests;
