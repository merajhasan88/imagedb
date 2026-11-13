/* The auditor's reader and writer of imagedb's Parquet subset (apq.h), from docs/f5-design.md and parquet.thrift's
 * compact protocol; no line of it is src/'s. */
#include "apq.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "acrypto.h"

/* ---- bytes out -------------------------------------------------------------------------------------------- */

typedef struct ob {
    uint8_t *p;
    size_t n, cap;
} ob;

static void ob_room(ob *b, size_t k)
{
    if (b->n + k <= b->cap) return;
    size_t c = b->cap ? b->cap : 4096;
    while (c < b->n + k) c *= 2;
    uint8_t *q = realloc(b->p, c);
    if (!q) {
        fputs("imagedb-audit: out of memory\n", stderr);
        exit(2);
    }
    b->p = q;
    b->cap = c;
}

static void ob_put(ob *b, const void *s, size_t k)
{
    if (!k) return;
    ob_room(b, k);
    memcpy(b->p + b->n, s, k);
    b->n += k;
}

static void ob_u8(ob *b, uint8_t x) { ob_put(b, &x, 1); }

static void ob_le32(ob *b, uint32_t x)
{
    uint8_t q[4] = {(uint8_t)x, (uint8_t)(x >> 8), (uint8_t)(x >> 16), (uint8_t)(x >> 24)};
    ob_put(b, q, 4);
}

static void ob_uv(ob *b, uint64_t v) /* ULEB128 */
{
    do {
        uint8_t x = v & 0x7f;
        v >>= 7;
        ob_u8(b, (uint8_t)(x | (v ? 0x80 : 0)));
    } while (v);
}

static uint32_t get32(const uint8_t *p) { return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24; }

/* ---- the compact protocol, writing ------------------------------------------------------------------------ */

enum { CT_STOP = 0, CT_TRUE = 1, CT_FALSE = 2, CT_BYTE = 3, CT_I32 = 5, CT_I64 = 6, CT_BIN = 8, CT_LIST = 9, CT_STRUCT = 12 };

typedef struct cw {
    ob *b;
    int16_t last[12];
    int d;
} cw;

static void cw_head(cw *w, int16_t id, uint8_t t)
{
    int d = id - w->last[w->d];
    if (d >= 1 && d <= 15) {
        ob_u8(w->b, (uint8_t)(d << 4 | t));
    } else {
        ob_u8(w->b, t);
        ob_uv(w->b, (uint64_t)(((int64_t)id << 1) ^ ((int64_t)id >> 63)));
    }
    w->last[w->d] = id;
}

static void cw_open(cw *w) { w->last[++w->d] = 0; }

static void cw_close(cw *w)
{
    ob_u8(w->b, CT_STOP);
    w->d--;
}

static uint64_t zz(int64_t v) { return (uint64_t)(v << 1) ^ (uint64_t)(v >> 63); }

static void cw_i32(cw *w, int16_t id, int32_t v)
{
    cw_head(w, id, CT_I32);
    ob_uv(w->b, zz(v));
}

static void cw_i64(cw *w, int16_t id, int64_t v)
{
    cw_head(w, id, CT_I64);
    ob_uv(w->b, zz(v));
}

static void cw_bin(cw *w, int16_t id, const void *p, size_t n)
{
    cw_head(w, id, CT_BIN);
    ob_uv(w->b, n);
    ob_put(w->b, p, n);
}

static void cw_struct(cw *w, int16_t id)
{
    cw_head(w, id, CT_STRUCT);
    cw_open(w);
}

static void cw_empty(cw *w, int16_t id) /* a struct of no fields */
{
    cw_struct(w, id);
    cw_close(w);
}

static void cw_list(cw *w, int16_t id, uint8_t et, uint32_t n)
{
    cw_head(w, id, CT_LIST);
    if (n < 15) {
        ob_u8(w->b, (uint8_t)(n << 4 | et));
    } else {
        ob_u8(w->b, (uint8_t)(0xf0 | et));
        ob_uv(w->b, n);
    }
}

/* ---- the compact protocol, reading (bounded; what it reads is written again and compared) --------------------- */

typedef struct cr {
    const uint8_t *p;
    size_t n, at;
    int16_t last[12];
    int d;
} cr;

static int cr_uv(cr *r, uint64_t *v)
{
    uint64_t x = 0;
    for (int s = 0; s < 70; s += 7) {
        if (r->at >= r->n) return -1;
        uint8_t c = r->p[r->at++];
        x |= (uint64_t)(c & 0x7f) << (s < 64 ? s : 63);
        if (!(c & 0x80)) {
            *v = x;
            return 0;
        }
    }
    return -1;
}

static int cr_zz(cr *r, int64_t *v)
{
    uint64_t u;
    if (cr_uv(r, &u)) return -1;
    *v = (int64_t)(u >> 1) ^ -(int64_t)(u & 1);
    return 0;
}

static int cr_open(cr *r)
{
    if (r->d >= 10) return -1;
    r->last[++r->d] = 0;
    return 0;
}

/* the next field (type 0 at a struct's end, which is left) */
static int cr_field(cr *r, int16_t *id, uint8_t *t)
{
    if (r->at >= r->n) return -1;
    uint8_t h = r->p[r->at++];
    *t = h & 15;
    if (!*t) {
        if (h || r->d < 1) return -1;
        r->d--;
        return 0;
    }
    if (h >> 4) {
        *id = (int16_t)(r->last[r->d] + (h >> 4));
    } else {
        int64_t v;
        if (cr_zz(r, &v) || v < -32768 || v > 32767) return -1;
        *id = (int16_t)v;
    }
    r->last[r->d] = *id;
    return 0;
}

static int cr_list(cr *r, uint8_t *et, uint64_t *n)
{
    if (r->at >= r->n) return -1;
    uint8_t h = r->p[r->at++];
    *et = h & 15;
    *n = h >> 4;
    if (*n == 15 && cr_uv(r, n)) return -1;
    return *n > r->n - r->at ? -1 : 0; /* a byte an element at least */
}

static int cr_bin(cr *r, const uint8_t **p, uint32_t *n)
{
    uint64_t k;
    if (cr_uv(r, &k) || k > r->n - r->at || k > 0xffffffffu) return -1;
    *p = r->p + r->at;
    *n = (uint32_t)k;
    r->at += k;
    return 0;
}

static int cr_skip(cr *r, uint8_t t);

static int cr_skip_struct(cr *r)
{
    if (cr_open(r)) return -1;
    for (;;) {
        int16_t id;
        uint8_t t;
        if (cr_field(r, &id, &t)) return -1;
        if (!t) return 0;
        if (cr_skip(r, t)) return -1;
    }
}

static int cr_skip(cr *r, uint8_t t)
{
    uint64_t u;
    const uint8_t *p;
    uint32_t n;
    switch (t) {
    case CT_TRUE:
    case CT_FALSE: return 0;
    case CT_BYTE: return r->at < r->n ? (r->at++, 0) : -1;
    case CT_I32:
    case CT_I64: return cr_uv(r, &u);
    case CT_BIN: return cr_bin(r, &p, &n);
    case CT_STRUCT: return cr_skip_struct(r);
    case CT_LIST: {
        uint8_t et;
        if (cr_list(r, &et, &u) || et == CT_LIST || et == CT_TRUE || et == CT_FALSE) return -1; /* none in the subset */
        for (uint64_t i = 0; i < u; i++)
            if (cr_skip(r, et)) return -1;
        return 0;
    }
    default: return -1;
    }
}

/* ---- the footer, as far as a read needs it: the rows, each chunk's place, the pairs ---------------------------- */

typedef struct foot {
    uint64_t nrows;
    uint32_t ncols, nkv;
    uint64_t off[APQ_MAX_COLS], size[APQ_MAX_COLS];
    const uint8_t *key[APQ_MAX_KV], *val[APQ_MAX_KV];
    uint32_t klen[APQ_MAX_KV], vlen[APQ_MAX_KV];
    size_t meta; /* where it begins */
} foot;

static int read_foot(const uint8_t *f, size_t len, foot *ft, const char **why)
{
    memset(ft, 0, sizeof *ft);
    *why = "not a Parquet file of the subset";
    if (len < 12 || memcmp(f, "PAR1", 4) || memcmp(f + len - 4, "PAR1", 4)) return -1;
    uint32_t ml = get32(f + len - 8);
    if (ml > len - 12) return -1;
    ft->meta = len - 8 - ml;
    cr r = {f + ft->meta, ml, 0, {0}, 0};
    *why = "a footer that does not decode";
    if (cr_open(&r)) return -1;
    for (;;) {
        int16_t id;
        uint8_t t, et;
        uint64_t n;
        if (cr_field(&r, &id, &t)) return -1;
        if (!t) break;
        if (id == 3 && t == CT_I64) {
            int64_t v;
            if (cr_zz(&r, &v) || v < 1 || (uint64_t)v > len || v > (1 << 22)) return -1; /* a row costs bytes; 2^22 at most */
            ft->nrows = (uint64_t)v;
        } else if (id == 4 && t == CT_LIST) {
            if (cr_list(&r, &et, &n) || et != CT_STRUCT || n != 1 || cr_open(&r)) return -1;
            for (;;) { /* the row group */
                if (cr_field(&r, &id, &t)) return -1;
                if (!t) break;
                if (id != 1 || t != CT_LIST) {
                    if (cr_skip(&r, t)) return -1;
                    continue;
                }
                if (cr_list(&r, &et, &n) || et != CT_STRUCT || !n || n > APQ_MAX_COLS) return -1;
                ft->ncols = (uint32_t)n;
                for (uint32_t c = 0; c < ft->ncols; c++) {
                    if (cr_open(&r)) return -1;
                    for (;;) { /* a chunk */
                        if (cr_field(&r, &id, &t)) return -1;
                        if (!t) break;
                        if (id != 3 || t != CT_STRUCT) {
                            if (cr_skip(&r, t)) return -1;
                            continue;
                        }
                        if (cr_open(&r)) return -1;
                        for (;;) { /* its metadata: the size and the first page's offset */
                            if (cr_field(&r, &id, &t)) return -1;
                            if (!t) break;
                            int64_t v;
                            if ((id == 7 || id == 9) && t == CT_I64) {
                                if (cr_zz(&r, &v) || v < 0 || (uint64_t)v > ft->meta) return -1;
                                if (id == 7) ft->size[c] = (uint64_t)v;
                                else ft->off[c] = (uint64_t)v;
                            } else if (cr_skip(&r, t)) {
                                return -1;
                            }
                        }
                    }
                }
            }
        } else if (id == 5 && t == CT_LIST) {
            if (cr_list(&r, &et, &n) || et != CT_STRUCT || !n || n > APQ_MAX_KV) return -1;
            ft->nkv = (uint32_t)n;
            for (uint32_t k = 0; k < ft->nkv; k++) {
                if (cr_open(&r)) return -1;
                for (;;) {
                    if (cr_field(&r, &id, &t)) return -1;
                    if (!t) break;
                    if (id == 1 && t == CT_BIN) {
                        if (cr_bin(&r, &ft->key[k], &ft->klen[k])) return -1;
                    } else if (id == 2 && t == CT_BIN) {
                        if (cr_bin(&r, &ft->val[k], &ft->vlen[k])) return -1;
                    } else if (cr_skip(&r, t)) {
                        return -1;
                    }
                }
                if (!ft->key[k] || !ft->val[k]) return -1;
            }
        } else if (cr_skip(&r, t)) {
            return -1;
        }
    }
    if (r.at != r.n || !ft->nrows || !ft->ncols || !ft->nkv) return -1;
    /* the pairs: imagedb.chunks first, then by key (bytes, the shorter first), none twice, no NUL in a key or value */
    *why = "a footer's pairs out of their order, or holding a NUL";
    for (uint32_t k = 0; k < ft->nkv; k++) {
        if (memchr(ft->key[k], 0, ft->klen[k]) || memchr(ft->val[k], 0, ft->vlen[k])) return -1;
        if (!k) {
            if (ft->klen[0] != 14 || memcmp(ft->key[0], "imagedb.chunks", 14)) return -1;
            continue;
        }
        uint32_t m = ft->klen[k - 1] < ft->klen[k] ? ft->klen[k - 1] : ft->klen[k];
        int o = memcmp(ft->key[k - 1], ft->key[k], m);
        if (o > 0 || (o == 0 && ft->klen[k - 1] >= ft->klen[k])) return -1;
    }
    *why = "a footer that does not decode";
    for (uint32_t c = 0; c < ft->ncols; c++)
        if (ft->off[c] < 4 || ft->size[c] > ft->meta - ft->off[c]) return -1; /* each chunk inside the file */
    return 0;
}

const uint8_t *apq_peek(const uint8_t *f, size_t len, const char *key, uint32_t *vlen, const char **why)
{
    foot ft;
    if (read_foot(f, len, &ft, why)) return NULL;
    size_t kl = strlen(key);
    for (uint32_t k = 0; k < ft.nkv; k++)
        if (ft.klen[k] == kl && !memcmp(ft.key[k], key, kl)) {
            *vlen = ft.vlen[k];
            return ft.val[k];
        }
    return NULL;
}

/* ---- the definition levels' hybrid (bit width 1) --------------------------------------------------------------- */

static uint64_t run_at(const uint8_t *lv, uint64_t n, uint64_t i)
{
    uint64_t r = 1;
    while (i + r < n && lv[i + r] == lv[i]) r++;
    return r;
}

/* docs/f5-design.md: a run of 8 or more equal levels is an RLE run (its count shifted once, then the level in a
 * byte); otherwise groups of 8 are bit-packed (their count shifted once, plus one, then a byte a group, LSB first),
 * until the next group would begin a run of 8 or more, or the levels end (the last group's missing levels zero) */
static void levels_out(ob *b, const uint8_t *lv, uint64_t n)
{
    for (uint64_t i = 0; i < n;) {
        uint64_t r = run_at(lv, n, i);
        if (r >= 8) {
            ob_uv(b, r << 1);
            ob_u8(b, lv[i]);
            i += r;
            continue;
        }
        uint64_t g = 0, j = i;
        for (;;) {
            g++;
            j += 8;
            if (j >= n || run_at(lv, n, j) >= 8) break;
        }
        ob_uv(b, g << 1 | 1);
        for (uint64_t k = 0; k < g; k++) {
            uint8_t x = 0;
            for (unsigned q = 0; q < 8; q++)
                if (i + 8 * k + q < n && lv[i + 8 * k + q]) x |= (uint8_t)(1u << q);
            ob_u8(b, x);
        }
        i = j;
    }
}

static int levels_in(const uint8_t *p, size_t len, uint64_t n, uint8_t *lv)
{
    cr r = {p, len, 0, {0}, 0};
    uint64_t got = 0;
    while (got < n) {
        uint64_t h;
        if (cr_uv(&r, &h)) return -1;
        uint64_t k = h >> 1;
        if (h & 1) {
            if (!k || k > (n - got + 7) / 8 || k > r.n - r.at) return -1;
            for (uint64_t g = 0; g < k; g++) {
                uint8_t x = p[r.at++];
                for (unsigned q = 0; q < 8 && got < n; q++) lv[got++] = (uint8_t)(x >> q & 1);
            }
        } else {
            if (!k || k > n - got || r.at >= r.n || p[r.at] > 1) return -1;
            uint8_t v = p[r.at++];
            for (uint64_t g = 0; g < k; g++) lv[got++] = v;
        }
    }
    return r.at == r.n ? 0 : -1;
}

/* ---- columns: a value's width; the statistics -------------------------------------------------------------------- */

static unsigned width(const apq_shape *s)
{
    switch (s->phys) {
    case APQ_BOOLEAN: return 1;
    case APQ_INT32: return 4;
    case APQ_FIXED: return (unsigned)s->tlen;
    case APQ_BYTES: return 0;
    default: return 8;
    }
}

static bool has(const apq_shape *s, const apq_col *c, uint64_t i)
{
    return !s->opt || (c->pres[i >> 3] >> (i & 7) & 1);
}

static int order(const apq_shape *s, const uint8_t *a, const uint8_t *b) /* -1, 0, 1 */
{
    if (s->phys == APQ_BOOLEAN) return (a[0] > b[0]) - (a[0] < b[0]);
    if (s->phys == APQ_INT32) {
        int32_t x = (int32_t)get32(a), y = (int32_t)get32(b);
        return (x > y) - (x < y);
    }
    uint64_t ux = (uint64_t)get32(a) | (uint64_t)get32(a + 4) << 32, uy = (uint64_t)get32(b) | (uint64_t)get32(b + 4) << 32;
    if (s->phys == APQ_DOUBLE) {
        double x, y;
        memcpy(&x, &ux, 8);
        memcpy(&y, &uy, 8);
        return (x > y) - (x < y);
    }
    return ((int64_t)ux > (int64_t)uy) - ((int64_t)ux < (int64_t)uy);
}

/* ---- the writer: the file a shape and a column a chunk ------------------------------------------------------------ */

static void schema_el(cw *w, const apq_shape *s)
{
    static const int conv[] = {[APQ_L_STRING] = 0, [APQ_L_DECIMAL] = 5, [APQ_L_DATE] = 6, [APQ_L_TIME] = 8, [APQ_L_TIMESTAMP] = 10};
    cw_open(w);
    cw_i32(w, 1, s->phys);
    if (s->phys == APQ_FIXED) cw_i32(w, 2, s->tlen);
    cw_i32(w, 3, s->opt ? 1 : 0); /* OPTIONAL or REQUIRED */
    cw_bin(w, 4, s->name, strlen(s->name));
    if (s->logical == APQ_L_INT) cw_i32(w, 6, s->bits == 16 ? 16 : s->bits == 32 ? 17 : 18); /* INT_16, INT_32, INT_64 */
    else if (s->logical != APQ_L_NONE && s->logical != APQ_L_UUID) cw_i32(w, 6, conv[s->logical]);
    if (s->logical == APQ_L_DECIMAL) {
        cw_i32(w, 7, s->scale);
        cw_i32(w, 8, s->prec);
    }
    cw_i32(w, 9, s->id);
    if (s->logical != APQ_L_NONE) {
        cw_struct(w, 10); /* LogicalType, a union */
        switch (s->logical) {
        case APQ_L_STRING: cw_empty(w, 1); break;
        case APQ_L_DECIMAL:
            cw_struct(w, 5);
            cw_i32(w, 1, s->scale);
            cw_i32(w, 2, s->prec);
            cw_close(w);
            break;
        case APQ_L_DATE: cw_empty(w, 6); break;
        case APQ_L_TIME:
        case APQ_L_TIMESTAMP:
            cw_struct(w, s->logical == APQ_L_TIME ? 7 : 8);
            cw_head(w, 1, s->utc ? CT_TRUE : CT_FALSE); /* isAdjustedToUTC */
            cw_struct(w, 2);                             /* its unit, a union: MICROS */
            cw_empty(w, 2);
            cw_close(w);
            cw_close(w);
            break;
        case APQ_L_INT:
            cw_struct(w, 10);
            cw_head(w, 1, CT_BYTE);
            ob_u8(w->b, s->bits);
            cw_head(w, 2, CT_TRUE); /* signed */
            cw_close(w);
            break;
        default: cw_empty(w, 14); break; /* UUID */
        }
        cw_close(w);
    }
    cw_close(w);
}

static void hex(const uint8_t *h, char *out)
{
    static const char x[] = "0123456789abcdef";
    for (int i = 0; i < 32; i++) {
        out[2 * i] = x[h[i] >> 4];
        out[2 * i + 1] = x[h[i] & 15];
    }
    out[64] = 0;
}

typedef struct stat1 {
    uint64_t nulls;
    const uint8_t *mn, *mx;
} stat1;

static void write_file(ob *b, const apq_shape *sh, uint32_t nc, uint64_t n, const apq_col *cols, const foot *src)
{
    uint64_t off[APQ_MAX_COLS], size[APQ_MAX_COLS];
    stat1 st[APQ_MAX_COLS];
    uint8_t *lv = malloc(n ? n : 1);
    if (!lv) exit(2);
    ob_put(b, "PAR1", 4);
    for (uint32_t c = 0; c < nc; c++) {
        const apq_shape *s = &sh[c];
        const apq_col *col = &cols[c];
        unsigned w = width(s);
        uint64_t per = s->phys == APQ_BYTES ? APQ_PAGE_ROWS : n;
        memset(&st[c], 0, sizeof st[c]);
        for (uint64_t r0 = 0; r0 < n; r0 += per) {
            uint64_t r1 = r0 + per < n ? r0 + per : n, m = 0, vb = 0;
            ob lb = {0}, hb = {0};
            for (uint64_t i = r0; i < r1; i++) {
                lv[i - r0] = has(s, col, i);
                if (!lv[i - r0]) continue;
                m++;
                if (s->phys == APQ_BYTES) vb += 4 + (uint64_t)(col->off[i + 1] - col->off[i]);
            }
            if (s->phys == APQ_BOOLEAN) vb = (m + 7) / 8;
            else if (s->phys != APQ_BYTES) vb = m * w;
            if (s->opt) levels_out(&lb, lv, r1 - r0);
            uint64_t lev = s->opt ? 4 + lb.n : 0, psize = lev + vb;
            cw hw = {&hb, {0}, 0};
            cw_open(&hw); /* the page header */
            cw_i32(&hw, 1, 0);                /* DATA_PAGE */
            cw_i32(&hw, 2, (int32_t)psize);   /* its size, uncompressed */
            cw_i32(&hw, 3, (int32_t)psize);   /* and compressed: the same */
            cw_struct(&hw, 5);                /* DataPageHeader */
            cw_i32(&hw, 1, (int32_t)(r1 - r0));
            cw_i32(&hw, 2, 0);                /* PLAIN */
            cw_i32(&hw, 3, 3);                /* the levels' RLE */
            cw_i32(&hw, 4, 3);
            cw_close(&hw);
            cw_close(&hw);
            if (r0 == 0) { /* zeros before the chunk: its first page's values on an 8-byte boundary */
                while ((b->n + hb.n + lev) % 8) ob_u8(b, 0);
                off[c] = b->n;
            }
            ob_put(b, hb.p, hb.n);
            if (s->opt) {
                ob_le32(b, (uint32_t)lb.n);
                ob_put(b, lb.p, lb.n);
            }
            uint8_t x = 0;
            unsigned q = 0;
            for (uint64_t i = r0; i < r1; i++) {
                if (!has(s, col, i)) continue;
                if (s->phys == APQ_BOOLEAN) {
                    x |= (uint8_t)((col->fixed[i] & 1) << q);
                    if (++q == 8) {
                        ob_u8(b, x);
                        x = 0;
                        q = 0;
                    }
                } else if (s->phys == APQ_BYTES) {
                    uint32_t a = col->off[i], z = col->off[i + 1];
                    ob_le32(b, z - a);
                    ob_put(b, col->data + a, z - a);
                } else {
                    ob_put(b, col->fixed + i * w, w);
                }
            }
            if (q) ob_u8(b, x);
            free(lb.p);
            free(hb.p);
        }
        size[c] = b->n - off[c];
        for (uint64_t i = 0; i < n; i++) { /* the statistics: the NULLs, and the least and greatest present value */
            if (!has(s, col, i)) {
                st[c].nulls++;
                continue;
            }
            if (!s->stats) continue;
            const uint8_t *v = col->fixed + i * w;
            if (!st[c].mn || order(s, v, st[c].mn) < 0) st[c].mn = v;
            if (!st[c].mx || order(s, v, st[c].mx) > 0) st[c].mx = v;
        }
    }
    free(lv);
    /* imagedb.chunks: each chunk's offset, size and SHA-256, the writer's own */
    char *list = malloc((size_t)nc * 112 + 1);
    if (!list) exit(2);
    size_t at = 0;
    for (uint32_t c = 0; c < nc; c++) {
        uint8_t h[32];
        char hx[65];
        a_sha256_ctx sc;
        a_sha256_init(&sc);
        a_sha256_update(&sc, b->p + off[c], size[c]);
        a_sha256_final(&sc, h);
        hex(h, hx);
        at += (size_t)snprintf(list + at, (size_t)nc * 112 + 1 - at, "%llu,%llu,%s;", (unsigned long long)off[c],
                               (unsigned long long)size[c], hx);
    }
    size_t meta = b->n;
    cw w = {b, {0}, 0};
    cw_open(&w); /* FileMetaData */
    cw_i32(&w, 1, 2);
    cw_list(&w, 2, CT_STRUCT, nc + 1);
    cw_open(&w); /* the root */
    cw_bin(&w, 4, "schema", 6);
    cw_i32(&w, 5, (int32_t)nc);
    cw_close(&w);
    for (uint32_t c = 0; c < nc; c++) schema_el(&w, &sh[c]);
    cw_i64(&w, 3, (int64_t)n);
    cw_list(&w, 4, CT_STRUCT, 1);
    cw_open(&w); /* the row group */
    cw_list(&w, 1, CT_STRUCT, nc);
    uint64_t total = 0;
    for (uint32_t c = 0; c < nc; c++) {
        const apq_shape *s = &sh[c];
        unsigned wd = width(s);
        total += size[c];
        cw_open(&w); /* ColumnChunk */
        cw_i64(&w, 2, (int64_t)off[c]);
        cw_struct(&w, 3); /* ColumnMetaData */
        cw_i32(&w, 1, s->phys);
        cw_list(&w, 2, CT_I32, 2);
        ob_uv(b, zz(0)); /* PLAIN */
        ob_uv(b, zz(3)); /* RLE */
        cw_list(&w, 3, CT_BIN, 1);
        ob_uv(b, strlen(s->name));
        ob_put(b, s->name, strlen(s->name));
        cw_i32(&w, 4, 0); /* UNCOMPRESSED */
        cw_i64(&w, 5, (int64_t)n);
        cw_i64(&w, 6, (int64_t)size[c]);
        cw_i64(&w, 7, (int64_t)size[c]);
        cw_i64(&w, 9, (int64_t)off[c]);
        cw_struct(&w, 12); /* Statistics */
        cw_i64(&w, 3, (int64_t)st[c].nulls);
        if (st[c].mx) {
            uint8_t hi[8], lo[8];
            memcpy(hi, st[c].mx, wd);
            memcpy(lo, st[c].mn, wd);
            if (s->phys == APQ_DOUBLE) { /* a zero max written +0.0, a zero min -0.0 (parquet.thrift's rule) */
                double x;
                memcpy(&x, hi, 8);
                if (x == 0) memset(hi, 0, 8);
                memcpy(&x, lo, 8);
                if (x == 0) {
                    memset(lo, 0, 8);
                    lo[7] = 0x80;
                }
            }
            cw_bin(&w, 5, hi, wd);
            cw_bin(&w, 6, lo, wd);
        }
        cw_close(&w);
        cw_close(&w);
        cw_close(&w);
    }
    cw_i64(&w, 2, (int64_t)total);
    cw_i64(&w, 3, (int64_t)n);
    cw_close(&w);
    cw_list(&w, 5, CT_STRUCT, src->nkv);
    for (uint32_t k = 0; k < src->nkv; k++) { /* imagedb.chunks this writer's, then the pairs as read */
        cw_open(&w);
        if (!k) {
            cw_bin(&w, 1, "imagedb.chunks", 14);
            cw_bin(&w, 2, list, at);
        } else {
            cw_bin(&w, 1, src->key[k], src->klen[k]);
            cw_bin(&w, 2, src->val[k], src->vlen[k]);
        }
        cw_close(&w);
    }
    cw_bin(&w, 6, "imagedb", 7);
    cw_list(&w, 7, CT_STRUCT, nc);
    for (uint32_t c = 0; c < nc; c++) { /* ColumnOrder: TYPE_ORDER */
        cw_open(&w);
        cw_empty(&w, 1);
        cw_close(&w);
    }
    cw_close(&w);
    ob_le32(b, (uint32_t)(b->n - meta));
    ob_put(b, "PAR1", 4);
    free(list);
}

/* ---- the reader -------------------------------------------------------------------------------------------- */

void apq_free(apq_file *a)
{
    for (uint32_t c = 0; c < APQ_MAX_COLS; c++) {
        free(a->col[c].pres);
        free(a->col[c].fixed);
        free(a->col[c].data);
        free(a->col[c].off);
    }
    memset(a, 0, sizeof *a);
}

/* chunk c's pages, decoded into col (bounded by the chunk; their exact layout the comparison's) */
static int read_chunk(const uint8_t *f, const foot *ft, uint32_t c, const apq_shape *s, apq_col *col, uint8_t *lv)
{
    uint64_t n = ft->nrows, end = ft->off[c] + ft->size[c], pos = ft->off[c], dl = 0;
    unsigned w = width(s);
    if (s->opt && !(col->pres = calloc((n + 7) / 8 + 8, 1))) return -1;
    if (s->phys == APQ_BYTES) {
        if (!(col->off = calloc(n + 1, 4)) || !(col->data = malloc(ft->size[c] ? ft->size[c] : 1))) return -1;
    } else if (!(col->fixed = calloc(n, w))) {
        return -1;
    }
    for (uint64_t r0 = 0; r0 < n;) {
        cr r = {f + pos, end - pos, 0, {0}, 0};
        int64_t psize = -1, nv = -1;
        int16_t id;
        uint8_t t;
        if (cr_open(&r)) return -1;
        for (;;) { /* the page header: its size and its rows */
            if (cr_field(&r, &id, &t)) return -1;
            if (!t) break;
            if (id == 3 && t == CT_I32) {
                if (cr_zz(&r, &psize)) return -1;
            } else if (id == 5 && t == CT_STRUCT) {
                if (cr_open(&r)) return -1;
                for (;;) {
                    if (cr_field(&r, &id, &t)) return -1;
                    if (!t) break;
                    if (id == 1 && t == CT_I32) {
                        if (cr_zz(&r, &nv)) return -1;
                    } else if (cr_skip(&r, t)) {
                        return -1;
                    }
                }
            } else if (cr_skip(&r, t)) {
                return -1;
            }
        }
        uint64_t data = pos + r.at;
        if (psize < 0 || nv < 1 || (uint64_t)nv > n - r0 || (uint64_t)psize > end - data) return -1;
        uint64_t k = (uint64_t)nv, dend = data + (uint64_t)psize, v = data, m = k;
        if (s->opt) {
            if (dend - data < 4) return -1;
            uint32_t L = get32(f + data);
            if (L > dend - data - 4 || levels_in(f + data + 4, L, k, lv)) return -1;
            m = 0;
            for (uint64_t i = 0; i < k; i++)
                if (lv[i]) {
                    col->pres[(r0 + i) >> 3] |= (uint8_t)(1u << ((r0 + i) & 7));
                    m++;
                }
            v = data + 4 + L;
        }
        uint64_t q = 0; /* the present values in order */
        for (uint64_t i = 0; i < k; i++) {
            if (s->opt && !lv[i]) {
                if (col->off) col->off[r0 + i + 1] = (uint32_t)dl;
                continue;
            }
            if (s->phys == APQ_BOOLEAN) {
                if ((q >> 3) >= dend - v) return -1;
                col->fixed[r0 + i] = (uint8_t)(f[v + (q >> 3)] >> (q & 7) & 1);
            } else if (s->phys == APQ_BYTES) {
                if (dend - v < 4) return -1;
                uint32_t l = get32(f + v);
                v += 4;
                if (l > dend - v || l > 65535u) return -1;
                memcpy(col->data + dl, f + v, l);
                v += l;
                dl += l;
                col->off[r0 + i + 1] = (uint32_t)dl;
            } else {
                if (w > dend - v) return -1;
                memcpy(col->fixed + (r0 + i) * w, f + v, w);
                v += w;
            }
            q++;
        }
        (void)m;
        pos = dend;
        r0 += k;
    }
    return pos == end ? 0 : -1;
}

int apq_read(const uint8_t *f, size_t len, const apq_shape *sh, uint32_t ncols, apq_file *out, const char **why)
{
    memset(out, 0, sizeof *out);
    foot ft;
    if (read_foot(f, len, &ft, why)) return -1;
    *why = "another column count than the schema version's";
    if (ft.ncols != ncols) return -1;
    /* the REQUIRED columns' bytes for the rows claimed, before anything is sized by them */
    uint64_t need = 0;
    for (uint32_t c = 0; c < ncols; c++)
        if (!sh[c].opt) need += sh[c].phys == APQ_BOOLEAN ? (ft.nrows + 7) / 8 : sh[c].phys == APQ_BYTES ? 4 * ft.nrows : ft.nrows * width(&sh[c]);
    *why = "more rows than the file holds";
    if (need > len) return -1;
    out->nrows = ft.nrows;
    out->ncols = ncols;
    out->nkv = ft.nkv;
    for (uint32_t k = 0; k < ft.nkv; k++) {
        out->key[k] = ft.key[k];
        out->klen[k] = ft.klen[k];
        out->val[k] = ft.val[k];
        out->vlen[k] = ft.vlen[k];
    }
    uint8_t *lv = malloc(ft.nrows);
    if (!lv) exit(2);
    *why = "a chunk that does not decode";
    for (uint32_t c = 0; c < ncols; c++)
        if (read_chunk(f, &ft, c, &sh[c], &out->col[c], lv)) {
            free(lv);
            apq_free(out);
            return -1;
        }
    free(lv);
    /* every byte the writer's for what was read: written again and compared */
    ob b = {0};
    write_file(&b, sh, ncols, ft.nrows, out->col, &ft);
    bool same = b.n == len && !memcmp(b.p, f, len);
    free(b.p);
    if (!same) {
        *why = "not the file its content gives (its structure, statistics or a chunk's SHA-256)";
        apq_free(out);
        return -1;
    }
    return 0;
}
