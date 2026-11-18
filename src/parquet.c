/* F5 (docs/f5-design.md): imagedb's canonical Parquet subset: the writer and the definition levels' codec. */
#include "parquet.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "limits.h"
#include "pool.h"
#include "sha256.h"

/* ---- Thrift's compact protocol, the subset the footer and the page headers need ------------------------------- */

enum { TC_TRUE = 1, TC_FALSE = 2, TC_BYTE = 3, TC_I16 = 4, TC_I32 = 5, TC_I64 = 6, TC_BINARY = 8, TC_LIST = 9, TC_STRUCT = 12 };

typedef struct tw {
    imdb_buf *b;
    int16_t last[8]; /* each open struct's last field id (a struct's ids restart from 0) */
    int depth;
} tw;

static void tw_varint(imdb_buf *b, uint64_t v)
{
    while (v >= 0x80) {
        imdb_buf_put_u8(b, (uint8_t)(v | 0x80));
        v >>= 7;
    }
    imdb_buf_put_u8(b, (uint8_t)v);
}

static uint64_t zz64(int64_t v) { return ((uint64_t)v << 1) ^ (uint64_t)(v >> 63); }

static void tw_field(tw *w, int16_t id, uint8_t type)
{
    int16_t d = (int16_t)(id - w->last[w->depth]);
    if (d > 0 && d <= 15) {
        imdb_buf_put_u8(w->b, (uint8_t)(d << 4 | type));
    } else {
        imdb_buf_put_u8(w->b, type);
        tw_varint(w->b, zz64(id));
    }
    w->last[w->depth] = id;
}

static void tw_begin(tw *w) /* a struct's fields begin (a field header written before, or a list element) */
{
    w->depth++;
    w->last[w->depth] = 0;
}

static void tw_end(tw *w) /* STOP */
{
    imdb_buf_put_u8(w->b, 0);
    w->depth--;
}

static void tw_struct(tw *w, int16_t id) /* a struct field: its header, then its fields up to tw_end */
{
    tw_field(w, id, TC_STRUCT);
    tw_begin(w);
}

static void tw_i32(tw *w, int16_t id, int32_t v)
{
    tw_field(w, id, TC_I32);
    tw_varint(w->b, zz64(v));
}

static void tw_i64(tw *w, int16_t id, int64_t v)
{
    tw_field(w, id, TC_I64);
    tw_varint(w->b, zz64(v));
}

static void tw_byte(tw *w, int16_t id, int8_t v)
{
    tw_field(w, id, TC_BYTE);
    imdb_buf_put_u8(w->b, (uint8_t)v);
}

static void tw_bool(tw *w, int16_t id, bool v) { tw_field(w, id, v ? TC_TRUE : TC_FALSE); }

static void tw_bin(tw *w, int16_t id, const void *p, size_t n)
{
    tw_field(w, id, TC_BINARY);
    tw_varint(w->b, n);
    imdb_buf_put(w->b, p, n);
}

static void tw_str(tw *w, int16_t id, const char *s) { tw_bin(w, id, s, strlen(s)); }

static void tw_list(tw *w, int16_t id, uint8_t elem, uint32_t n)
{
    tw_field(w, id, TC_LIST);
    if (n < 15) {
        imdb_buf_put_u8(w->b, (uint8_t)(n << 4 | elem));
    } else {
        imdb_buf_put_u8(w->b, (uint8_t)(0xf0 | elem));
        tw_varint(w->b, n);
    }
}

/* ---- the definition levels' hybrid (bit width 1) --------------------------------------------------------------- */

static uint64_t run_len(const uint8_t *lv, uint64_t n, uint64_t i)
{
    uint64_t j = i + 1;
    while (j < n && lv[j] == lv[i]) j++;
    return j - i;
}

/* docs/f5-design.md's algorithm: a run of 8 or more equal levels is an RLE run; otherwise whole groups of 8 bit-packed
 * from here, until a group boundary begins a run of 8 or more (or the levels end, the last group padded with zeros) */
void imdb_pq_levels_encode(const uint8_t *lv, uint64_t n, imdb_buf *out)
{
    uint64_t i = 0;
    while (i < n) {
        uint64_t r = run_len(lv, n, i);
        if (r >= 8) {
            tw_varint(out, r << 1);
            imdb_buf_put_u8(out, lv[i]);
            i += r;
            continue;
        }
        uint64_t s = i;
        for (;;) {
            i += 8;
            if (i >= n || run_len(lv, n, i) >= 8) break;
        }
        uint64_t groups = (i - s) / 8;
        tw_varint(out, groups << 1 | 1);
        for (uint64_t g = 0; g < groups; g++) {
            uint8_t byte = 0;
            for (unsigned k = 0; k < 8; k++) {
                uint64_t at = s + g * 8 + k;
                if (at < n && lv[at]) byte |= (uint8_t)(1u << k);
            }
            imdb_buf_put_u8(out, byte);
        }
    }
}

static int rd_varint(const uint8_t *p, size_t len, size_t *at, uint64_t *v)
{
    uint64_t x = 0;
    for (unsigned sh = 0; sh < 64; sh += 7) {
        if (*at >= len) return -1;
        uint8_t c = p[(*at)++];
        x |= (uint64_t)(c & 0x7f) << sh;
        if (!(c & 0x80)) {
            *v = x;
            return 0;
        }
    }
    return -1;
}

int imdb_pq_levels_decode(const uint8_t *p, size_t len, uint64_t n, uint8_t *lv, imdb_err *e)
{
    size_t at = 0;
    uint64_t got = 0;
    while (got < n) {
        uint64_t h;
        if (rd_varint(p, len, &at, &h)) return imdb_fail(e, IMDB_ERR_CORRUPT, "parquet: a levels header is cut");
        if (h & 1) {
            uint64_t groups = h >> 1;
            if (!groups || groups > (n - got + 7) / 8 || groups > len - at)
                return imdb_fail(e, IMDB_ERR_CORRUPT, "parquet: a bit-packed levels run is out of bounds");
            for (uint64_t g = 0; g < groups; g++) {
                uint8_t byte = p[at++];
                for (unsigned k = 0; k < 8; k++) {
                    if (got < n) lv[got++] = (uint8_t)(byte >> k & 1);
                    else if (byte >> k & 1) return imdb_fail(e, IMDB_ERR_CORRUPT, "parquet: levels padding not zero");
                }
            }
        } else {
            uint64_t count = h >> 1;
            if (!count || count > n - got || at >= len) return imdb_fail(e, IMDB_ERR_CORRUPT, "parquet: an RLE levels run is out of bounds");
            uint8_t v = p[at++];
            if (v > 1) return imdb_fail(e, IMDB_ERR_CORRUPT, "parquet: a level is not 0 or 1");
            for (uint64_t k = 0; k < count; k++) lv[got++] = v;
        }
    }
    if (at != len) return imdb_fail(e, IMDB_ERR_CORRUPT, "parquet: bytes after the levels");
    /* canonical: the one encoding the writer makes (any other of the same levels refused) */
    imdb_buf b;
    imdb_buf_init(&b);
    imdb_pq_levels_encode(lv, n, &b);
    int rc = imdb_buf_check(&b, e);
    if (!rc && (b.len != len || (len && memcmp(b.p, p, len) != 0))) /* len 0: both may be NULL (memcmp may not see one) */
        rc = imdb_fail(e, IMDB_ERR_CORRUPT, "parquet: the levels are not in their canonical encoding");
    imdb_buf_free(&b);
    return rc;
}

/* ---- the writer ------------------------------------------------------------------------------------------------ */

static unsigned fixed_width(const pq_col *c)
{
    switch (c->phys) {
    case PQ_BOOLEAN: return 1;
    case PQ_INT32: return 4;
    case PQ_INT64:
    case PQ_DOUBLE: return 8;
    case PQ_FLBA: return (unsigned)c->type_length;
    default: return 0;
    }
}

static bool has_value(const pq_col *c, uint64_t i) { return !c->present || (c->present[i >> 3] >> (i & 7) & 1); }

static void page_header(tw *w, uint32_t size, uint64_t nvalues)
{
    tw_begin(w);
    tw_i32(w, 1, 0); /* DATA_PAGE */
    tw_i32(w, 2, (int32_t)size);
    tw_i32(w, 3, (int32_t)size);
    tw_struct(w, 5);
    tw_i32(w, 1, (int32_t)nvalues);
    tw_i32(w, 2, 0); /* PLAIN */
    tw_i32(w, 3, 3); /* RLE */
    tw_i32(w, 4, 3); /* RLE */
    tw_end(w);
    tw_end(w);
}

/* a page of rows [r0, r1) straight into out (no page buffer: a chunk's bytes are written once): its header, then for
 * an OPTIONAL column the levels' u32 length and hybrid, then the present rows' values in PLAIN. The chunk's first page
 * after its padding (its values 8-byte aligned), whose first byte *first gets */
static int page_put(imdb_buf *out, const pq_col *c, uint64_t r0, uint64_t r1, uint64_t *first, imdb_err *e)
{
    unsigned w = fixed_width(c);
    uint64_t m = 0, vbytes = 0;
    for (uint64_t i = r0; i < r1; i++) {
        if (!has_value(c, i)) continue;
        m++;
        if (c->phys == PQ_BYTE_ARRAY) vbytes += 4 + (c->off[i + 1] - c->off[i]);
    }
    if (c->phys == PQ_BOOLEAN) vbytes = (m + 7) / 8;
    else if (c->phys != PQ_BYTE_ARRAY) vbytes = m * w;
    imdb_buf lb, hb;
    imdb_buf_init(&lb);
    imdb_buf_init(&hb);
    int rc = IMDB_OK;
    if (c->optional) {
        uint64_t n = r1 - r0;
        uint8_t *lv = imdb_alloc_array(n ? n : 1, 1, e);
        if (!lv) return e->code;
        for (uint64_t i = r0; i < r1; i++) lv[i - r0] = has_value(c, i);
        imdb_pq_levels_encode(lv, n, &lb);
        imdb_free(lv);
        if ((rc = imdb_buf_check(&lb, e))) goto out;
    }
    uint64_t lev = c->optional ? 4 + lb.len : 0, psize = lev + vbytes;
    if (psize > INT32_MAX) {
        rc = imdb_fail(e, IMDB_ERR_LIMIT, "parquet: a page past 2 GiB");
        goto out;
    }
    tw hw = {&hb, {0}, 0};
    page_header(&hw, (uint32_t)psize, r1 - r0);
    if ((rc = imdb_buf_check(&hb, e))) goto out;
    if (r0 == 0) { /* the chunk's padding: its first page's values begin 8-byte aligned */
        imdb_buf_put_zeros(out, (8 - (out->len + hb.len + lev) % 8) % 8);
        *first = out->len;
    }
    imdb_buf_put(out, hb.p, hb.len);
    if (c->optional) {
        imdb_buf_put_u32(out, (uint32_t)lb.len);
        imdb_buf_put(out, lb.p, lb.len);
    }
    if (c->phys == PQ_BOOLEAN) { /* bit-packed, LSB first, the present rows only */
        uint8_t byte = 0;
        unsigned k = 0;
        for (uint64_t i = r0; i < r1; i++) {
            if (!has_value(c, i)) continue;
            if (c->fixed[i]) byte |= (uint8_t)(1u << k);
            if (++k == 8) {
                imdb_buf_put_u8(out, byte);
                byte = 0;
                k = 0;
            }
        }
        if (k) imdb_buf_put_u8(out, byte);
    } else if (c->phys == PQ_BYTE_ARRAY) {
        for (uint64_t i = r0; i < r1; i++) {
            if (!has_value(c, i)) continue;
            uint64_t len = c->off[i + 1] - c->off[i];
            imdb_buf_put_u32(out, (uint32_t)len);
            if (len) imdb_buf_put(out, c->data + c->off[i], len); /* none: data may be NULL (no arithmetic on it) */
        }
    } else if (!c->optional) {
        imdb_buf_put(out, c->fixed + r0 * w, (r1 - r0) * w); /* every row: the values as they lie */
    } else {
        for (uint64_t i = r0; i < r1; i++)
            if (has_value(c, i)) imdb_buf_put(out, c->fixed + i * w, w);
    }
out:
    imdb_buf_free(&lb);
    imdb_buf_free(&hb);
    return rc;
}

/* a chunk's statistics: its NULLs, and where asked the least and greatest present value (DOUBLE by value, BOOLEAN
 * 0 < 1, the integers signed): the writer's as it writes a column, the reader's from what it read */
/* A column's nulls and, where it keeps statistics, its least and greatest values: a loop a type (a call and a switch a
 * value were 5% of a load's time, 2026-11-13). Equal values have one encoding (values_check: no -0.0, no NaN), so
 * which of them is kept is never seen. */
static void stat_of(const pq_col *c, uint64_t nrows, pq_stat *st)
{
    memset(st, 0, sizeof *st);
    if (c->present) {
        uint64_t have = 0, i = 0;
        for (; i + 64 <= nrows; i += 64) {
            uint64_t w;
            memcpy(&w, c->present + i / 8, 8);
            have += (uint64_t)__builtin_popcountll(w);
        }
        for (; i < nrows; i++) have += has_value(c, i);
        st->nulls = nrows - have;
    }
    if (!c->stats || st->nulls == nrows) return;
    uint64_t i = 0;
    while (!has_value(c, i)) i++; /* the first value: there is one */
    const uint8_t *f = c->fixed;
    switch (c->phys) {
    case PQ_BOOLEAN: {
        uint8_t lo = f[i], hi = f[i];
        for (i++; i < nrows; i++)
            if (has_value(c, i)) {
                lo = f[i] < lo ? f[i] : lo;
                hi = f[i] > hi ? f[i] : hi;
            }
        st->mn[0] = lo;
        st->mx[0] = hi;
        break;
    }
    case PQ_INT32: {
        int32_t lo = (int32_t)imdb_get_le32(f + 4 * i), hi = lo;
        for (i++; i < nrows; i++)
            if (has_value(c, i)) {
                int32_t v = (int32_t)imdb_get_le32(f + 4 * i);
                lo = v < lo ? v : lo;
                hi = v > hi ? v : hi;
            }
        imdb_le32(st->mn, (uint32_t)lo);
        imdb_le32(st->mx, (uint32_t)hi);
        break;
    }
    case PQ_INT64: {
        int64_t lo = (int64_t)imdb_get_le64(f + 8 * i), hi = lo;
        for (i++; i < nrows; i++)
            if (has_value(c, i)) {
                int64_t v = (int64_t)imdb_get_le64(f + 8 * i);
                lo = v < lo ? v : lo;
                hi = v > hi ? v : hi;
            }
        imdb_le64(st->mn, (uint64_t)lo);
        imdb_le64(st->mx, (uint64_t)hi);
        break;
    }
    case PQ_DOUBLE: {
        uint64_t ulo = imdb_get_le64(f + 8 * i), uhi = ulo;
        double lo, hi;
        memcpy(&lo, &ulo, 8);
        hi = lo;
        for (i++; i < nrows; i++)
            if (has_value(c, i)) {
                uint64_t u = imdb_get_le64(f + 8 * i);
                double v;
                memcpy(&v, &u, 8);
                if (v < lo) lo = v, ulo = u;
                if (v > hi) hi = v, uhi = u;
            }
        imdb_le64(st->mn, ulo);
        imdb_le64(st->mx, uhi);
        break;
    }
    default: return; /* shapes_check: statistics only where a value orders */
    }
    st->has = true;
}

static void stat_put(tw *w, const pq_col *c, const pq_stat *st)
{
    unsigned wd = fixed_width(c);
    tw_struct(w, 12);
    tw_i64(w, 3, (int64_t)st->nulls);
    if (st->has) {
        uint8_t hi[8], lo[8];
        memcpy(hi, st->mx, wd);
        memcpy(lo, st->mn, wd);
        if (c->phys == PQ_DOUBLE) { /* Parquet's rule: a zero max written +0.0, a zero min -0.0 */
            double x;
            uint64_t u = imdb_get_le64(hi);
            memcpy(&x, &u, 8);
            if (x == 0) imdb_le64(hi, 0);
            u = imdb_get_le64(lo);
            memcpy(&x, &u, 8);
            if (x == 0) imdb_le64(lo, 0x8000000000000000ull);
        }
        tw_bin(w, 5, hi, wd);
        tw_bin(w, 6, lo, wd);
    }
    tw_end(w);
}

static void schema_element(tw *w, const pq_col *c)
{
    tw_begin(w);
    tw_i32(w, 1, c->phys);
    if (c->phys == PQ_FLBA) tw_i32(w, 2, c->type_length);
    tw_i32(w, 3, c->optional ? 1 : 0);
    tw_str(w, 4, c->name);
    int32_t conv = -1; /* the ConvertedType kept for older readers, where one is compatible */
    switch (c->logical) {
    case PQL_STRING: conv = 0; break;
    case PQL_DECIMAL: conv = 5; break;
    case PQL_DATE: conv = 6; break;
    case PQL_TIME: conv = 8; break;       /* TIME_MICROS, local times too (LogicalTypes.md) */
    case PQL_TIMESTAMP: conv = 10; break; /* TIMESTAMP_MICROS, local timestamps too: "must" */
    case PQL_INT: conv = c->int_bits == 16 ? 16 : c->int_bits == 32 ? 17 : 18; break;
    default: break;
    }
    if (conv >= 0) tw_i32(w, 6, conv);
    if (c->logical == PQL_DECIMAL) {
        tw_i32(w, 7, c->scale);
        tw_i32(w, 8, c->precision);
    }
    tw_i32(w, 9, c->field_id);
    if (c->logical != PQL_NONE) {
        tw_struct(w, 10);
        switch (c->logical) {
        case PQL_STRING: tw_struct(w, 1); tw_end(w); break;
        case PQL_DECIMAL:
            tw_struct(w, 5);
            tw_i32(w, 1, c->scale);
            tw_i32(w, 2, c->precision);
            tw_end(w);
            break;
        case PQL_DATE: tw_struct(w, 6); tw_end(w); break;
        case PQL_TIME:
        case PQL_TIMESTAMP:
            tw_struct(w, c->logical == PQL_TIME ? 7 : 8);
            tw_bool(w, 1, c->utc);
            tw_struct(w, 2);
            tw_struct(w, 2); /* MICROS */
            tw_end(w);
            tw_end(w);
            tw_end(w);
            break;
        case PQL_INT:
            tw_struct(w, 10);
            tw_byte(w, 1, (int8_t)c->int_bits);
            tw_bool(w, 2, true);
            tw_end(w);
            break;
        case PQL_UUID: tw_struct(w, 14); tw_end(w); break;
        default: break;
        }
        tw_end(w);
    }
    tw_end(w);
}

static void hex(const uint8_t *h, size_t n, char *out)
{
    static const char x[] = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) {
        out[2 * i] = x[h[i] >> 4];
        out[2 * i + 1] = x[h[i] & 15];
    }
    out[2 * n] = 0;
}

/* the footer (FileMetaData), from the columns' shapes, their statistics, the chunks' offsets and sizes and the
 * key-value pairs as bytes (imagedb.chunks first): the writer's and the reader's, which writes it again to compare */
static void footer_encode(imdb_buf *out, const pq_col *cols, uint32_t ncols, uint64_t nrows, const uint64_t *off,
                          const uint64_t *size, const pq_stat *st, const uint8_t *const *key, const uint32_t *klen,
                          const uint8_t *const *val, const uint32_t *vlen, uint32_t nkv)
{
    tw w = {out, {0}, 0};
    tw_begin(&w);
    tw_i32(&w, 1, 2);
    tw_list(&w, 2, TC_STRUCT, ncols + 1);
    tw_begin(&w); /* the root */
    tw_str(&w, 4, "schema");
    tw_i32(&w, 5, (int32_t)ncols);
    tw_end(&w);
    for (uint32_t ci = 0; ci < ncols; ci++) schema_element(&w, &cols[ci]);
    tw_i64(&w, 3, (int64_t)nrows);
    tw_list(&w, 4, TC_STRUCT, 1);
    tw_begin(&w); /* the row group */
    tw_list(&w, 1, TC_STRUCT, ncols);
    uint64_t total = 0;
    for (uint32_t ci = 0; ci < ncols; ci++) {
        const pq_col *c = &cols[ci];
        total += size[ci];
        tw_begin(&w); /* ColumnChunk */
        tw_i64(&w, 2, (int64_t)off[ci]);
        tw_struct(&w, 3); /* ColumnMetaData */
        tw_i32(&w, 1, c->phys);
        tw_list(&w, 2, TC_I32, 2);
        tw_varint(out, zz64(0)); /* PLAIN */
        tw_varint(out, zz64(3)); /* RLE */
        tw_list(&w, 3, TC_BINARY, 1);
        tw_varint(out, strlen(c->name));
        imdb_buf_put(out, c->name, strlen(c->name));
        tw_i32(&w, 4, 0); /* UNCOMPRESSED */
        tw_i64(&w, 5, (int64_t)nrows);
        tw_i64(&w, 6, (int64_t)size[ci]);
        tw_i64(&w, 7, (int64_t)size[ci]);
        tw_i64(&w, 9, (int64_t)off[ci]);
        stat_put(&w, c, &st[ci]);
        tw_end(&w);
        tw_end(&w);
    }
    tw_i64(&w, 2, (int64_t)total);
    tw_i64(&w, 3, (int64_t)nrows);
    tw_end(&w);
    tw_list(&w, 5, TC_STRUCT, nkv);
    for (uint32_t k = 0; k < nkv; k++) {
        tw_begin(&w);
        tw_bin(&w, 1, key[k], klen[k]);
        tw_bin(&w, 2, val[k], vlen[k]);
        tw_end(&w);
    }
    tw_str(&w, 6, "imagedb");
    tw_list(&w, 7, TC_STRUCT, ncols);
    for (uint32_t ci = 0; ci < ncols; ci++) {
        tw_begin(&w); /* ColumnOrder: TYPE_ORDER */
        tw_struct(&w, 1);
        tw_end(&w);
        tw_end(&w);
    }
    tw_end(&w);
}

/* ---- the subset's rules: the writer's input and the reader's result alike (one rule for both sides) --------------- */

/* Iceberg's TypeUtil.decimalRequiredBytes for 19 to 38 digits: the least b with 10^P <= 2^(8b - 1) (t_pq checks the
 * table against a 128-bit computation of that rule) */
unsigned imdb_pq_dec_bytes(int32_t precision)
{
    static const uint8_t kBytes[39 - 19] = {9, 9, 9, 10, 10, 11, 11, 11, 12, 12, 13, 13, 13, 14, 14, 15, 15, 16, 16, 16};
    return precision >= 19 && precision <= 38 ? kBytes[precision - 19] : 0;
}

/* a column's shape: a type of the subset with its annotations' fields, and nothing else set */
static bool shape_ok(const pq_col *c)
{
    size_t nl = c->name ? strnlen(c->name, IMDB_MAX_IDENT + 1) : 0;
    if (!nl || nl > IMDB_MAX_IDENT || c->field_id < 1) return false;
    switch (c->phys) {
    case PQ_BOOLEAN:
    case PQ_INT32:
    case PQ_INT64:
    case PQ_DOUBLE:
    case PQ_BYTE_ARRAY:
        if (c->type_length) return false;
        break;
    case PQ_FLBA: /* 16 or 32 bytes, or a DECIMAL's width (its rule below) */
        if (c->type_length != 16 && c->type_length != 32 && (c->logical != PQL_DECIMAL || c->type_length < 9 || c->type_length > 16))
            return false;
        break;
    default: return false;
    }
    if (c->stats && (c->phys == PQ_BYTE_ARRAY || c->phys == PQ_FLBA)) return false; /* min and max where a value orders */
    if (c->utc && c->logical != PQL_TIME && c->logical != PQL_TIMESTAMP) return false;
    if (c->logical != PQL_DECIMAL && (c->scale || c->precision)) return false;
    if (c->logical != PQL_INT && c->int_bits) return false;
    switch (c->logical) {
    case PQL_NONE: return true;
    case PQL_STRING: return c->phys == PQ_BYTE_ARRAY;
    case PQL_DECIMAL: /* Iceberg's mapping (F5b): one physical type and width a precision */
        if (c->scale < 0 || c->scale > c->precision || c->precision < 1 || c->precision > 38) return false;
        if (c->precision <= 9) return c->phys == PQ_INT32;
        if (c->precision <= 18) return c->phys == PQ_INT64;
        return c->phys == PQ_FLBA && (unsigned)c->type_length == imdb_pq_dec_bytes(c->precision);
    case PQL_DATE: return c->phys == PQ_INT32;
    case PQL_TIME:
    case PQL_TIMESTAMP: return c->phys == PQ_INT64;
    case PQL_INT:
        return (c->phys == PQ_INT32 && (c->int_bits == 16 || c->int_bits == 32)) ||
               (c->phys == PQ_INT64 && c->int_bits == 64);
    case PQL_UUID: return c->phys == PQ_FLBA && c->type_length == 16;
    default: return false;
    }
}

static int shapes_check(const pq_col *cols, uint32_t ncols, imdb_err *e)
{
    if (!ncols || ncols > PQ_MAX_COLUMNS) return imdb_fail(e, IMDB_ERR_STATE, "parquet: a column count outside the subset");
    bool wide = false;
    for (uint32_t ci = 0; ci < ncols; ci++) {
        const pq_col *c = &cols[ci];
        if (!shape_ok(c)) return imdb_fail(e, IMDB_ERR_STATE, "parquet: a column's shape outside the subset");
        for (uint32_t cj = 0; cj < ci; cj++)
            if (!strcmp(cols[cj].name, c->name) || cols[cj].field_id == c->field_id)
                return imdb_fail(e, IMDB_ERR_STATE, "parquet: two columns of one name or field id");
        if (!c->optional && (c->phys == PQ_BYTE_ARRAY || fixed_width(c) >= 4)) wide = true;
    }
    /* a REQUIRED column of four bytes or more a row: a file holds more bytes than rows (the reader's first bound) */
    if (!wide) return imdb_fail(e, IMDB_ERR_STATE, "parquet: no REQUIRED column of four bytes or more a row");
    return IMDB_OK;
}

/* the values: present exactly where OPTIONAL; a BOOLEAN 0 or 1; a DOUBLE imagedb's FLOAT64 (finite and never -0.0: one
 * encoding a value, so no NaN reaches the statistics); a BYTE_ARRAY's offsets from 0, ascending, each value at most
 * IMDB_MAX_TEXT bytes. A NULL row's slot is ignored (the reader's holds zeros, or an empty value). */
static int values_check(const pq_col *cols, uint32_t ncols, uint64_t nrows, int code, imdb_err *e)
{
    for (uint32_t ci = 0; ci < ncols; ci++) {
        const pq_col *c = &cols[ci];
        if (c->optional != (c->present != NULL))
            return imdb_fail(e, code, "parquet: a column's presence bits are not its nullability");
        if (c->phys == PQ_BYTE_ARRAY) {
            if (!c->off || c->off[0]) return imdb_fail(e, code, "parquet: a byte array's offsets do not begin at 0");
            for (uint64_t i = 0; i < nrows; i++)
                if (c->off[i + 1] < c->off[i] || c->off[i + 1] - c->off[i] > IMDB_MAX_TEXT)
                    return imdb_fail(e, code, "parquet: a byte array's value out of bounds");
            if (c->off[nrows] && !c->data) return imdb_fail(e, code, "parquet: a byte array without its bytes");
            continue;
        }
        if (!c->fixed) return imdb_fail(e, code, "parquet: a column without its values");
        if (c->phys != PQ_BOOLEAN && c->phys != PQ_DOUBLE) continue;
        for (uint64_t i = 0; i < nrows; i++) {
            if (!has_value(c, i)) continue;
            if (c->phys == PQ_BOOLEAN && c->fixed[i] > 1) return imdb_fail(e, code, "parquet: a BOOLEAN not 0 or 1");
            if (c->phys == PQ_DOUBLE) {
                uint64_t b = imdb_get_le64(c->fixed + i * 8);
                if (((b >> 52) & 0x7ff) == 0x7ff || b == 0x8000000000000000ull)
                    return imdb_fail(e, code, "parquet: a DOUBLE not finite, or -0.0");
            }
        }
    }
    return IMDB_OK;
}

#ifdef IMDB_STORE_CHECKS
static void readback_check(const pq_col *cols, uint32_t ncols, uint64_t nrows, const imdb_buf *out);
#endif

/* ---- the writer: a column at a time (a caller gathers one, writes it, frees it: lake.c's build) --------------- */

static bool shape_same(const pq_col *a, const pq_col *b)
{
    return !strcmp(a->name, b->name) && a->field_id == b->field_id && a->phys == b->phys && a->logical == b->logical &&
           a->optional == b->optional && a->utc == b->utc && a->stats == b->stats && a->int_bits == b->int_bits &&
           a->type_length == b->type_length && a->scale == b->scale && a->precision == b->precision;
}

/* upper bounds on the file's size, so the output is allocated once (no doubling and copying of a segment's bytes):
 * per chunk its padding, page headers (29 bytes at most), levels (at most a byte a row, and each page's length and a
 * run's header) and values, with its footer's share (a schema element, a chunk's metadata with statistics, its entry in
 * imagedb.chunks) generously; the frame (the magic twice, the footer's length, its fixed fields and the pairs) */
uint64_t imdb_pq_col_bound(const pq_col *c, uint64_t nrows, uint64_t bytes)
{
    uint64_t pages = c->phys == PQ_BYTE_ARRAY ? (nrows + PQ_PAGE_ROWS - 1) / PQ_PAGE_ROWS : 1;
    uint64_t z = 8 + pages * 48;
    if (c->optional) z += pages * (4 + 16) + nrows;
    z += c->phys == PQ_BYTE_ARRAY ? 4 * nrows + bytes : c->phys == PQ_BOOLEAN ? nrows / 8 + 1 : nrows * fixed_width(c);
    return z + 2 * strlen(c->name) + 256 + 2 * 32 + 64 + 20 + 20;
}

uint64_t imdb_pq_frame_bound(const pq_kv *kv, uint32_t nkv)
{
    uint64_t z = 12 + 256;
    for (uint32_t k = 0; k < nkv; k++) z += strlen(kv[k].key) + strlen(kv[k].value) + 16;
    return z;
}

int imdb_pq_writer_begin(pq_writer *w, imdb_buf *out, const pq_col *shapes, uint32_t ncols, uint64_t nrows,
                         uint64_t bound, imdb_err *e)
{
    memset(w, 0, sizeof *w);
    int rc = shapes_check(shapes, ncols, e);
    if (rc) return rc;
    if (!nrows || nrows > IMDB_MAX_SEGMENT_ROWS) /* a segment holds a row at least (every builder's) */
        return imdb_fail(e, IMDB_ERR_STATE, "parquet: a row count outside the subset");
    w->out = out;
    w->nrows = nrows;
    w->ncols = ncols;
    for (uint32_t ci = 0; ci < ncols; ci++) {
        w->shape[ci] = shapes[ci];
        w->shape[ci].fixed = w->shape[ci].data = w->shape[ci].present = NULL;
        w->shape[ci].off = NULL;
    }
    out->len = 0;
    w->bound = bound;
    /* exactly the bound (imdb_buf_reserve would double from 256 and zero the rest: a segment's file twice over); a
     * failure stays in the buffer's sticky error */
    if (bound > out->cap) imdb_buf_reserve_limit(out, bound, bound);
    imdb_buf_put(out, "PAR1", 4);
    return IMDB_OK;
}

int imdb_pq_writer_column(pq_writer *w, const pq_col *c, imdb_err *e)
{
    if (w->done >= w->ncols || !shape_same(c, &w->shape[w->done]))
        return imdb_fail(e, IMDB_ERR_STATE, "parquet: a column not the next one's shape");
    int rc = values_check(c, 1, w->nrows, IMDB_ERR_STATE, e);
    if (rc) return rc;
    uint64_t per = c->phys == PQ_BYTE_ARRAY ? PQ_PAGE_ROWS : w->nrows, first = 0;
    for (uint64_t r0 = 0; r0 < w->nrows && !rc; r0 += per)
        rc = page_put(w->out, c, r0, r0 + per < w->nrows ? r0 + per : w->nrows, &first, e);
    if (!rc) rc = imdb_buf_check(w->out, e);
    if (rc) return rc;
    w->off[w->done] = first;
    w->size[w->done] = w->out->len - first;
    stat_of(c, w->nrows, &w->st[w->done]);
    w->done++;
    return IMDB_OK;
}

/* The chunks' hashes (imagedb.chunks; F5b: the name is the tail's, so a chunk's hash is the only pass over its bytes),
 * imdb_par_for's items, each into its own slot (a write's and an authentication's alike). Below PQ_PAR_HASH bytes the
 * items run inline: waking the pool costs more. */
enum { PQ_PAR_HASH = 1 << 20 };

typedef struct {
    const uint8_t *p;
    const uint64_t *off, *size;
    uint8_t (*h)[32];
} hash_job;

static void hash_item(void *arg, size_t i)
{
    hash_job *j = arg;
    imdb_sha256(j->p + j->off[i], j->size[i], j->h[i]);
}

static void hash_run(hash_job *j, uint32_t nchunks, uint64_t bytes)
{
    if (bytes >= PQ_PAR_HASH) imdb_par_for(nchunks, hash_item, j);
    else
        for (size_t i = 0; i < nchunks; i++) hash_item(j, i);
}

int imdb_pq_writer_end(pq_writer *w, const pq_kv *kv, uint32_t nkv, imdb_err *e)
{
    imdb_buf *out = w->out;
    if (w->done != w->ncols) return imdb_fail(e, IMDB_ERR_STATE, "parquet: a file ended before its last column");
    if (nkv > PQ_MAX_KV) return imdb_fail(e, IMDB_ERR_STATE, "parquet: too many key-value pairs");
    for (uint32_t k = 0; k < nkv; k++)
        if (strcmp(kv[k].key, k ? kv[k - 1].key : "imagedb.chunks") <= 0)
            return imdb_fail(e, IMDB_ERR_STATE, "parquet: key-value pairs not sorted after imagedb.chunks");
    int rc = imdb_buf_check(out, e); /* a reservation or a put refused: no whole file to hash */
    if (rc) return rc;
    /* the chunks' hashes */
    uint8_t h[PQ_MAX_COLUMNS][32];
    hash_job j = {.p = out->p, .off = w->off, .size = w->size, .h = h};
    hash_run(&j, w->ncols, out->len);
    /* the chunks' ranges and hashes, for imagedb.chunks */
    size_t cap = (size_t)w->ncols * (2 * 20 + 64 + 3) + 1, at = 0, meta = out->len;
    char *chunks = imdb_alloc_array(cap, 1, e);
    if (!chunks) {
        imdb_wipe(h, sizeof h);
        return e->code;
    }
    for (uint32_t ci = 0; ci < w->ncols && !rc; ci++) {
        char hx[65];
        hex(h[ci], 32, hx);
        int n = snprintf(chunks + at, cap - at, "%llu,%llu,%s;", (unsigned long long)w->off[ci],
                         (unsigned long long)w->size[ci], hx);
        if (n < 0 || (size_t)n >= cap - at) rc = imdb_fail(e, IMDB_ERR_STATE, "parquet: the chunk list overflowed");
        else at += (size_t)n;
        imdb_wipe(hx, sizeof hx);
    }
    if (!rc) {
        const uint8_t *key[PQ_MAX_KV + 1], *val[PQ_MAX_KV + 1];
        uint32_t klen[PQ_MAX_KV + 1], vlen[PQ_MAX_KV + 1];
        key[0] = (const uint8_t *)"imagedb.chunks";
        klen[0] = 14;
        val[0] = (const uint8_t *)chunks;
        vlen[0] = (uint32_t)at;
        for (uint32_t k = 0; k < nkv; k++) {
            key[k + 1] = (const uint8_t *)kv[k].key;
            klen[k + 1] = (uint32_t)strlen(kv[k].key);
            val[k + 1] = (const uint8_t *)kv[k].value;
            vlen[k + 1] = (uint32_t)strlen(kv[k].value);
        }
        footer_encode(out, w->shape, w->ncols, w->nrows, w->off, w->size, w->st, key, klen, val, vlen, nkv + 1);
        uint64_t mlen = out->len - meta;
        if (mlen > PQ_MAX_FOOTER) rc = imdb_fail(e, IMDB_ERR_LIMIT, "parquet: footer too large");
        else {
            imdb_buf_put_u32(out, (uint32_t)mlen);
            imdb_buf_put(out, "PAR1", 4);
        }
    }
    imdb_wipe(chunks, cap); /* unsalted hashes of columns: an oracle for guesses once rows are erased (f5-design) */
    imdb_free(chunks);
    if (!rc) rc = imdb_buf_check(out, e);
    if (!rc) imdb_sha256(out->p + meta, out->len - meta, w->hash); /* the name: the tail's hash (F5b) */
    imdb_wipe(h, sizeof h);
#ifdef IMDB_STORE_CHECKS
    if (!rc && w->bound && out->len > w->bound) { /* the bound is an upper bound, or its allocation doubles */
        fprintf(stderr, "imagedb: parquet: a file of %zu bytes past its bound of %llu\n", out->len, (unsigned long long)w->bound);
        abort();
    }
    if (!rc) { /* every file written authenticates against its name: the writer's tail and frame are the check's */
        pq_footer ft;
        imdb_err ea = {0};
        if (imdb_pq_authenticate(out->p, out->len, w->hash, &ft, &ea)) { /* it allocates nothing: no fault reaches it */
            fprintf(stderr, "imagedb: parquet: a file written does not authenticate against its name: %s\n", ea.msg);
            abort();
        }
    }
#endif
    return rc;
}

int imdb_pq_write(const pq_col *cols, uint32_t ncols, uint64_t nrows, const pq_kv *kv, uint32_t nkv, imdb_buf *out,
                  imdb_err *e)
{
    pq_writer *w = imdb_alloc(sizeof *w, e);
    if (!w) return e->code;
    int rc = imdb_pq_writer_begin(w, out, cols, ncols, nrows, 0, e);
    if (!rc) { /* its bound, the rows counted and the offsets there (values_check reads them next) */
        uint64_t bound = imdb_pq_frame_bound(kv, nkv);
        for (uint32_t ci = 0; ci < ncols; ci++)
            bound += imdb_pq_col_bound(&cols[ci], nrows, cols[ci].phys == PQ_BYTE_ARRAY && cols[ci].off ? cols[ci].off[nrows] : 0);
        w->bound = bound;
        if (out->len + bound > out->cap) imdb_buf_reserve_limit(out, bound, out->len + bound); /* exactly (writer_begin) */
    }
    for (uint32_t ci = 0; ci < ncols && !rc; ci++) rc = imdb_pq_writer_column(w, &cols[ci], e);
    if (!rc) rc = imdb_pq_writer_end(w, kv, nkv, e);
    imdb_wipe(w, sizeof *w); /* its statistics: row values */
    imdb_free(w);
#ifdef IMDB_STORE_CHECKS
    if (!rc) readback_check(cols, ncols, nrows, out);
#endif
    return rc;
}

/* ---- the strict reader ----------------------------------------------------------------------------------------- */

typedef struct tr {
    const uint8_t *p;
    size_t len, at;
    int16_t last[8];
    int depth;
} tr;

static int tr_u8(tr *r, uint8_t *b)
{
    if (r->at >= r->len) return -1;
    *b = r->p[r->at++];
    return 0;
}

static int tr_zz(tr *r, int64_t *v)
{
    uint64_t u;
    if (rd_varint(r->p, r->len, &r->at, &u)) return -1;
    *v = (int64_t)(u >> 1) ^ -(int64_t)(u & 1);
    return 0;
}

static int tr_enter(tr *r)
{
    if (r->depth + 1 >= 8) return -1;
    r->depth++;
    r->last[r->depth] = 0;
    return 0;
}

/* the next field's id and type; STOP gives type 0 and leaves the struct */
static int tr_field(tr *r, int16_t *id, uint8_t *type)
{
    uint8_t b;
    if (tr_u8(r, &b)) return -1;
    if (!b) {
        *type = 0;
        r->depth--;
        return r->depth < 0 ? -1 : 0;
    }
    *type = b & 15;
    if (b >> 4) {
        *id = (int16_t)(r->last[r->depth] + (b >> 4));
    } else {
        int64_t v;
        if (tr_zz(r, &v) || v < INT16_MIN || v > INT16_MAX) return -1;
        *id = (int16_t)v;
    }
    r->last[r->depth] = *id;
    return 0;
}

static int tr_list(tr *r, uint8_t *elem, uint64_t *n)
{
    uint8_t b;
    if (tr_u8(r, &b)) return -1;
    *elem = b & 15;
    *n = b >> 4;
    if (*n == 15 && rd_varint(r->p, r->len, &r->at, n)) return -1;
    if (*n > r->len - r->at) return -1; /* each element takes a byte at least */
    return 0;
}

static int tr_bin(tr *r, const uint8_t **p, uint32_t *n)
{
    uint64_t u;
    if (rd_varint(r->p, r->len, &r->at, &u) || u > r->len - r->at || u > UINT32_MAX) return -1;
    *p = r->p + r->at;
    *n = (uint32_t)u;
    r->at += u;
    return 0;
}

static int tr_skip(tr *r, uint8_t type);

static int tr_struct_skip(tr *r)
{
    if (tr_enter(r)) return -1;
    int d = r->depth;
    for (;;) {
        int16_t id;
        uint8_t t;
        if (tr_field(r, &id, &t)) return -1;
        if (!t) return r->depth == d - 1 ? 0 : -1;
        if (tr_skip(r, t)) return -1;
    }
}

static int tr_skip(tr *r, uint8_t type)
{
    uint64_t u;
    const uint8_t *p;
    uint32_t n;
    switch (type) {
    case TC_TRUE:
    case TC_FALSE: return 0;
    case TC_BYTE: return r->at < r->len ? (r->at++, 0) : -1;
    case TC_I16:
    case TC_I32:
    case TC_I64: return rd_varint(r->p, r->len, &r->at, &u);
    case TC_BINARY: return tr_bin(r, &p, &n);
    case TC_LIST: {
        uint8_t el;
        /* the subset has no list of booleans or of lists: a list nests only through a struct, so tr_enter bounds the depth */
        if (tr_list(r, &el, &u) || el == TC_TRUE || el == TC_FALSE || el == TC_LIST) return -1;
        for (uint64_t i = 0; i < u; i++)
            if (tr_skip(r, el)) return -1;
        return 0;
    }
    case TC_STRUCT: return tr_struct_skip(r);
    default: return -1; /* a double, a set or a map: none in the subset */
    }
}

/* F5b: the footer's length from a len-byte file's last eight bytes (the length, the closing magic), bounded */
static int tail_len(const uint8_t last8[8], uint64_t len, uint32_t *ml, imdb_err *e)
{
    if (len < 12 || memcmp(last8 + 4, "PAR1", 4)) return imdb_fail(e, IMDB_ERR_CORRUPT, "parquet: not a Parquet file");
    *ml = imdb_get_le32(last8);
    if (*ml > len - 12 || *ml > PQ_MAX_FOOTER)
        return imdb_fail(e, IMDB_ERR_CORRUPT, "parquet: the footer's length is out of bounds");
    return IMDB_OK;
}

static int footer_walk(const uint8_t *mb, uint32_t ml, uint64_t len, pq_footer *ft, imdb_err *e);

int imdb_pq_footer(const uint8_t *f, size_t len, pq_footer *ft, imdb_err *e)
{
    memset(ft, 0, sizeof *ft);
    uint32_t ml;
    if (len < 12 || memcmp(f, "PAR1", 4)) return imdb_fail(e, IMDB_ERR_CORRUPT, "parquet: not a Parquet file");
    int rc = tail_len(f + len - 8, len, &ml, e);
    return rc ? rc : footer_walk(f + len - 8 - ml, ml, len, ft, e);
}

/* the footer's ml bytes at mb, a len-byte file's (its pointers into m: the in-memory file's, or the streamed check's tail) */
static int footer_walk(const uint8_t *mb, uint32_t ml, uint64_t len, pq_footer *ft, imdb_err *e)
{
    memset(ft, 0, sizeof *ft);
    ft->meta_at = len - 8 - ml;
    ft->meta_len = ml;
    tr r = {mb, ml, 0, {0}, 0};
    bool rows = false, rg = false;
    uint64_t nschema = 0;
    int16_t id;
    uint8_t t, el;
    uint64_t n;
    if (tr_enter(&r)) goto bad;
    for (;;) { /* FileMetaData */
        if (tr_field(&r, &id, &t)) goto bad;
        if (!t) break;
        if (id == 2 && t == TC_LIST) {
            if (tr_list(&r, &el, &nschema) || el != TC_STRUCT || nschema < 2 || nschema > PQ_MAX_COLUMNS + 1) goto bad;
            for (uint64_t i = 0; i < nschema; i++)
                if (tr_struct_skip(&r)) goto bad;
        } else if (id == 3 && t == TC_I64) {
            int64_t v;
            if (tr_zz(&r, &v) || v < 1 || v > (int64_t)IMDB_MAX_SEGMENT_ROWS) goto bad; /* a row at least */
            ft->nrows = (uint64_t)v;
            rows = true;
        } else if (id == 4 && t == TC_LIST) {
            if (tr_list(&r, &el, &n) || el != TC_STRUCT || n != 1 || tr_enter(&r)) goto bad;
            for (;;) { /* RowGroup */
                if (tr_field(&r, &id, &t)) goto bad;
                if (!t) break;
                if (id != 1 || t != TC_LIST) {
                    if (tr_skip(&r, t)) goto bad;
                    continue;
                }
                if (tr_list(&r, &el, &n) || el != TC_STRUCT || !n || n > PQ_MAX_COLUMNS) goto bad;
                ft->ncols = (uint32_t)n;
                for (uint32_t ci = 0; ci < ft->ncols; ci++) {
                    bool got_off = false, got_size = false;
                    if (tr_enter(&r)) goto bad;
                    for (;;) { /* ColumnChunk */
                        if (tr_field(&r, &id, &t)) goto bad;
                        if (!t) break;
                        if (id != 3 || t != TC_STRUCT) {
                            if (tr_skip(&r, t)) goto bad;
                            continue;
                        }
                        if (tr_enter(&r)) goto bad;
                        for (;;) { /* ColumnMetaData */
                            if (tr_field(&r, &id, &t)) goto bad;
                            if (!t) break;
                            int64_t v;
                            if ((id == 7 || id == 9) && t == TC_I64) {
                                if (tr_zz(&r, &v) || v < 0 || (uint64_t)v > ft->meta_at) goto bad;
                                if (id == 7) ft->size[ci] = (uint64_t)v, got_size = true;
                                else ft->off[ci] = (uint64_t)v, got_off = true;
                            } else if (tr_skip(&r, t)) {
                                goto bad;
                            }
                        }
                    }
                    if (!got_off || !got_size) goto bad;
                }
            }
            rg = true;
        } else if (id == 5 && t == TC_LIST) {
            if (tr_list(&r, &el, &n) || el != TC_STRUCT || !n || n > PQ_MAX_KV + 1) goto bad;
            ft->nkv = (uint32_t)n;
            for (uint32_t k = 0; k < ft->nkv; k++) {
                bool gk = false, gv = false;
                if (tr_enter(&r)) goto bad;
                for (;;) { /* KeyValue */
                    if (tr_field(&r, &id, &t)) goto bad;
                    if (!t) break;
                    if (id == 1 && t == TC_BINARY && !gk) {
                        if (tr_bin(&r, &ft->key[k], &ft->klen[k])) goto bad;
                        gk = true;
                    } else if (id == 2 && t == TC_BINARY && !gv) {
                        if (tr_bin(&r, &ft->val[k], &ft->vlen[k])) goto bad;
                        gv = true;
                    } else {
                        goto bad;
                    }
                }
                if (!gk || !gv) goto bad;
            }
        } else if (tr_skip(&r, t)) {
            goto bad;
        }
    }
    if (r.at != r.len || !rows || !rg || nschema != (uint64_t)ft->ncols + 1 || !ft->nkv) goto bad;
    if (ft->nrows > len) goto bad; /* every row of ours costs bytes in its system columns: the read's allocations follow */
    /* the pairs as the writer writes them: imagedb.chunks first, then by key, none repeated, no NUL in either */
    for (uint32_t k = 0; k < ft->nkv; k++) {
        if (memchr(ft->key[k], 0, ft->klen[k]) || memchr(ft->val[k], 0, ft->vlen[k])) goto bad;
        if (!k) {
            if (ft->klen[0] != 14 || memcmp(ft->key[0], "imagedb.chunks", 14)) goto bad;
            continue;
        }
        uint32_t m = ft->klen[k] < ft->klen[k - 1] ? ft->klen[k] : ft->klen[k - 1];
        int c = memcmp(ft->key[k - 1], ft->key[k], m);
        if (c > 0 || (c == 0 && ft->klen[k - 1] >= ft->klen[k])) goto bad;
    }
    /* imagedb.chunks: "offset,length,sha256;" a chunk, its numbers the footer's, in the one decimal form */
    size_t at = 0;
    for (uint32_t ci = 0; ci < ft->ncols; ci++) {
        char num[48];
        int nn = snprintf(num, sizeof num, "%llu,%llu,", (unsigned long long)ft->off[ci], (unsigned long long)ft->size[ci]);
        if (nn < 0 || (size_t)nn > ft->vlen[0] - at || memcmp(ft->val[0] + at, num, (size_t)nn)) goto bad;
        at += (size_t)nn;
        if (ft->vlen[0] - at < 65) goto bad;
        for (unsigned h = 0; h < 64; h++) {
            uint8_t ch = ft->val[0][at + h];
            if (!((ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f'))) goto bad;
        }
        ft->chunk_hex[ci] = ft->val[0] + at;
        at += 64;
        if (ft->val[0][at++] != ';') goto bad;
    }
    if (at != ft->vlen[0]) goto bad;
    return IMDB_OK;
bad:
    return imdb_fail(e, IMDB_ERR_CORRUPT, "parquet: the footer does not parse");
}

const uint8_t *imdb_pq_kv(const pq_footer *ft, const char *key, uint32_t *len)
{
    size_t kl = strlen(key);
    for (uint32_t k = 0; k < ft->nkv; k++)
        if (ft->klen[k] == kl && !memcmp(ft->key[k], key, kl)) {
            *len = ft->vlen[k];
            return ft->val[k];
        }
    return NULL;
}

void imdb_pq_free_read(pq_rcol *cols, uint32_t ncols)
{
    for (uint32_t ci = 0; cols && ci < ncols; ci++) { /* row values: wiped (an erasure cannot reach freed memory) */
        if (cols[ci].own_fixed) imdb_wipe(cols[ci].own_fixed, cols[ci].own_fixed_n);
        if (cols[ci].own_data) imdb_wipe(cols[ci].own_data, cols[ci].own_data_n);
        if (cols[ci].own_present) imdb_wipe(cols[ci].own_present, cols[ci].own_present_n);
        imdb_free(cols[ci].own_fixed);
        imdb_free(cols[ci].own_data);
        imdb_free(cols[ci].own_present);
        imdb_free(cols[ci].own_off);
        memset(&cols[ci], 0, sizeof cols[ci]);
    }
}

/* one chunk by its shape: the padding before it, each page header written again and compared, the levels, the values */
static int read_chunk(const uint8_t *f, uint64_t prev_end, uint64_t off, uint64_t size, uint64_t nrows,
                      const pq_col *s, pq_rcol *out, uint8_t *lv, imdb_err *e)
{
    const char *why = "parquet: a chunk does not parse";
    unsigned w = fixed_width(s);
    out->c = *s;
    /* whole 64-bit words, zero past the last row: readers take a bitmap a word at a time (sql_exec.c's fast paths) */
    if (s->optional && !(out->own_present = imdb_alloc_array(out->own_present_n = (nrows + 63) / 64 * 8, 1, e))) return e->code;
    if (s->phys == PQ_BYTE_ARRAY) {
        if (!(out->own_off = imdb_alloc_array(nrows + 1, sizeof(uint64_t), e)) ||
            !(out->own_data = imdb_alloc_array(out->own_data_n = size ? size : 1, 1, e)))
            return e->code;
    } else if (s->optional || s->phys == PQ_BOOLEAN) {
        if (!(out->own_fixed = imdb_alloc_array(nrows, w, e))) return e->code;
        out->own_fixed_n = nrows * w;
    }
    uint64_t end = off + size, pos = off, r0 = 0, dlen = 0;
    uint64_t per = s->phys == PQ_BYTE_ARRAY ? PQ_PAGE_ROWS : nrows;
    imdb_buf hb;
    imdb_buf_init(&hb);
    int rc = IMDB_OK;
    for (bool first = true; r0 < nrows; first = false) { /* nrows >= 1: the footer's rule */
        uint64_t want = nrows - r0 < per ? nrows - r0 : per;
        tr hr = {f + pos, end - pos, 0, {0}, 0};
        int16_t id;
        uint8_t t;
        int64_t psize = -1;
        if (tr_enter(&hr)) goto bad;
        for (;;) { /* PageHeader: its length and its page's size; the rest (the row count too) compared as written again */
            if (tr_field(&hr, &id, &t)) goto bad;
            if (!t) break;
            if (id == 2 && t == TC_I32) {
                if (tr_zz(&hr, &psize) || psize < 0 || psize > INT32_MAX) goto bad;
            } else if (tr_skip(&hr, t)) {
                goto bad;
            }
        }
        if (psize < 0) goto bad;
        hb.len = 0;
        tw hw = {&hb, {0}, 0};
        page_header(&hw, (uint32_t)psize, want);
        if (imdb_buf_check(&hb, e)) {
            rc = e->code;
            break;
        }
        if (hb.len != hr.at || memcmp(hb.p, f + pos, hb.len)) goto bad; /* the header the writer writes */
        uint64_t data = pos + hr.at;
        if ((uint64_t)psize > end - data) goto bad;
        uint64_t dend = data + (uint64_t)psize, vals = data, m = want;
        if (s->optional) {
            if (dend - data < 4) goto bad;
            uint32_t L = imdb_get_le32(f + data);
            if (L > dend - data - 4) goto bad;
            if ((rc = imdb_pq_levels_decode(f + data + 4, L, want, lv, e))) break;
            m = 0;
            for (uint64_t i = 0; i < want; i++)
                if (lv[i]) {
                    out->own_present[(r0 + i) >> 3] |= (uint8_t)(1u << ((r0 + i) & 7));
                    m++;
                }
            vals = data + 4 + L;
        }
        if (first) { /* the writer's padding: zeros, so the first page's values begin 8-byte aligned */
            uint64_t pad = (8 - (prev_end + hr.at + (vals - data)) % 8) % 8;
            if (off != prev_end + pad) goto bad;
            for (uint64_t i = prev_end; i < off; i++)
                if (f[i]) goto bad;
        }
        uint64_t rem = dend - vals;
        if (s->phys == PQ_BOOLEAN) {
            if (rem != (m + 7) / 8) goto bad;
            uint64_t k = 0;
            for (uint64_t i = 0; i < want; i++)
                if (!s->optional || lv[i]) {
                    out->own_fixed[r0 + i] = (uint8_t)(f[vals + k / 8] >> (k % 8) & 1);
                    k++;
                }
            if (k % 8 && (f[vals + k / 8] >> (k % 8))) goto bad; /* the last byte's padding bits zero */
        } else if (s->phys == PQ_BYTE_ARRAY) {
            uint64_t at = vals;
            for (uint64_t i = 0; i < want; i++) {
                out->own_off[r0 + i + 1] = dlen;
                if (s->optional && !lv[i]) continue;
                if (dend - at < 4) goto bad;
                uint32_t l = imdb_get_le32(f + at);
                at += 4;
                if (l > dend - at || l > IMDB_MAX_TEXT) goto bad;
                memcpy(out->own_data + dlen, f + at, l);
                dlen += l;
                at += l;
                out->own_off[r0 + i + 1] = dlen;
            }
            if (at != dend) goto bad;
        } else {
            if (m > rem / w || m * w != rem) goto bad;
            if (!s->optional) {
                out->c.fixed = f + vals; /* REQUIRED, one page: the image's array is the file's */
            } else {
                uint64_t k = 0;
                for (uint64_t i = 0; i < want; i++)
                    if (lv[i]) memcpy(out->own_fixed + (r0 + i) * w, f + vals + (k++) * w, w);
            }
        }
        pos = dend;
        r0 += want;
    }
    imdb_buf_free(&hb);
    if (rc) return rc;
    if (pos != end) return imdb_fail(e, IMDB_ERR_CORRUPT, "%s", why);
    if (out->own_fixed) out->c.fixed = out->own_fixed;
    if (s->phys == PQ_BYTE_ARRAY) {
        out->c.off = out->own_off;
        out->c.data = out->own_data;
    }
    out->c.present = out->own_present;
    return IMDB_OK;
bad:
    imdb_buf_free(&hb);
    return imdb_fail(e, IMDB_ERR_CORRUPT, "%s", why);
}

int imdb_pq_read(const uint8_t *f, size_t len, const pq_footer *ft, const pq_col *shapes, uint32_t ncols, pq_rcol *out,
                 imdb_err *e)
{
    memset(out, 0, sizeof *out * ncols); /* the caller's count: the file's is checked against it, never used to size */
    int rc = shapes_check(shapes, ncols, e);
    if (rc) return rc;
    if (ncols != ft->ncols) return imdb_fail(e, IMDB_ERR_CORRUPT, "parquet: another column count than the schema's");
    if (len != ft->meta_at + ft->meta_len + 8) return imdb_fail(e, IMDB_ERR_STATE, "parquet: a footer of another file");
    /* the bytes the REQUIRED columns take for nrows rows: more than the file holds is a lie, refused before any
     * allocation (an OPTIONAL column's NULLs cost bits: the REQUIRED ones bound what a read allocates) */
    uint64_t need = 0;
    for (uint32_t ci = 0; ci < ft->ncols; ci++) {
        const pq_col *s = &shapes[ci];
        if (s->optional) continue;
        need += s->phys == PQ_BOOLEAN ? (ft->nrows + 7) / 8 : ft->nrows * (s->phys == PQ_BYTE_ARRAY ? 4 : fixed_width(s));
    }
    if (need > len) return imdb_fail(e, IMDB_ERR_CORRUPT, "parquet: more rows than the file holds");
    uint8_t *lv = imdb_alloc_array(ft->nrows, 1, e); /* a page's levels: at most every row */
    if (!lv) return e->code;
    uint64_t prev = 4;
    for (uint32_t ci = 0; ci < ft->ncols && !rc; ci++) {
        /* inside the file (each of off and size is at most meta_at, the footer's rule; the sum is checked here); the
         * order of the chunks is the padding rule's: each begins at its predecessor's end and the zeros after it */
        if (ft->size[ci] > ft->meta_at - ft->off[ci]) {
            rc = imdb_fail(e, IMDB_ERR_CORRUPT, "parquet: a chunk out of place");
            break;
        }
        rc = read_chunk(f, prev, ft->off[ci], ft->size[ci], ft->nrows, &shapes[ci], &out[ci], lv, e);
        prev = ft->off[ci] + ft->size[ci];
    }
    imdb_free(lv);
    if (!rc && prev != ft->meta_at) rc = imdb_fail(e, IMDB_ERR_CORRUPT, "parquet: bytes between the chunks and the footer");
    pq_col cols[PQ_MAX_COLUMNS] = {0};
    for (uint32_t ci = 0; ci < ncols && !rc; ci++) cols[ci] = out[ci].c;
    if (!rc) rc = values_check(cols, ncols, ft->nrows, IMDB_ERR_CORRUPT, e); /* the writer's rules, before statistics */
    if (!rc) { /* the footer the writer writes for what was read */
        imdb_buf b;
        imdb_buf_init(&b);
        pq_stat st[PQ_MAX_COLUMNS];
        for (uint32_t ci = 0; ci < ncols; ci++) stat_of(&cols[ci], ft->nrows, &st[ci]);
        footer_encode(&b, cols, ft->ncols, ft->nrows, ft->off, ft->size, st, ft->key, ft->klen, ft->val, ft->vlen, ft->nkv);
        if (!(rc = imdb_buf_check(&b, e)) && (b.len != ft->meta_len || memcmp(b.p, f + ft->meta_at, b.len)))
            rc = imdb_fail(e, IMDB_ERR_CORRUPT, "parquet: the footer is not the one its content gives");
        imdb_buf_wipe_free(&b); /* the statistics: row values */
    }
    if (rc) imdb_pq_free_read(out, ncols);
    return rc;
}

static int chunks_check(const uint8_t *f, const pq_footer *ft, int code, imdb_err *e)
{
    uint8_t h[PQ_MAX_COLUMNS][32];
    uint64_t bytes = 0;
    /* imdb_pq_footer bounds a chunk's offset and its size each by the footer's start, not their sum (imdb_pq_read
     * refuses a chunk past it, but VERIFY runs this first): each range before the footer, or nothing is hashed */
    for (uint32_t ci = 0; ci < ft->ncols; ci++) {
        if (ft->off[ci] > ft->meta_at || ft->size[ci] > ft->meta_at - ft->off[ci])
            return imdb_fail(e, IMDB_ERR_CORRUPT, "parquet: a chunk past the footer's start");
        bytes += ft->size[ci];
    }
    hash_job j = {.p = f, .off = ft->off, .size = ft->size, .h = h};
    hash_run(&j, ft->ncols, bytes);
    int rc = IMDB_OK;
    for (uint32_t ci = 0; ci < ft->ncols && !rc; ci++) { /* in column order, whatever order the items ran in */
        char hx[65];
        hex(h[ci], 32, hx);
        if (memcmp(hx, ft->chunk_hex[ci], 64)) rc = imdb_fail(e, code, "parquet: a chunk is not the one its footer names");
        imdb_wipe(hx, sizeof hx);
    }
    imdb_wipe(h, sizeof h);
    return rc;
}

int imdb_pq_chunks_verify(const uint8_t *f, const pq_footer *ft, imdb_err *e)
{
    return chunks_check(f, ft, IMDB_ERR_CORRUPT, e);
}

/* ---- F5b: a file's name and its authentication ---------------------------------------------------------------- */

int imdb_pq_name(const uint8_t *f, size_t len, uint8_t out[32], imdb_err *e)
{
    uint32_t ml;
    if (len < 12) return imdb_fail(e, IMDB_ERR_CORRUPT, "parquet: not a Parquet file");
    int rc = tail_len(f + len - 8, len, &ml, e);
    if (!rc) imdb_sha256(f + len - 8 - ml, (size_t)ml + 8, out);
    return rc;
}

/* the frame over the walked footer, both checks' one rule: the chunks in column order, each at or past its
 * predecessor's end (the opening magic's first) and inside the file, the last ending at the footer; gap refuses a byte
 * not zero in [from, to) */
typedef int (*gap_fn)(void *ctx, uint64_t from, uint64_t to, imdb_err *e);

static int frame_check(const pq_footer *ft, gap_fn gap, void *ctx, imdb_err *e)
{
    uint64_t prev = 4;
    for (uint32_t ci = 0; ci < ft->ncols; ci++) {
        if (ft->off[ci] < prev || ft->off[ci] > ft->meta_at || ft->size[ci] > ft->meta_at - ft->off[ci])
            return imdb_fail(e, IMDB_ERR_CORRUPT, "parquet: a chunk out of place");
        int rc = gap(ctx, prev, ft->off[ci], e);
        if (rc) return rc;
        prev = ft->off[ci] + ft->size[ci];
    }
    if (prev != ft->meta_at) return imdb_fail(e, IMDB_ERR_CORRUPT, "parquet: bytes between the chunks and the footer");
    return IMDB_OK;
}

static int gap_mem(void *ctx, uint64_t from, uint64_t to, imdb_err *e)
{
    const uint8_t *f = ctx;
    for (uint64_t i = from; i < to; i++)
        if (f[i]) return imdb_fail(e, IMDB_ERR_CORRUPT, "parquet: a byte between the chunks not zero");
    return IMDB_OK;
}

int imdb_pq_authenticate(const uint8_t *f, size_t len, const uint8_t name[32], pq_footer *ft, imdb_err *e)
{
    uint8_t h[32];
    memset(ft, 0, sizeof *ft);
    int rc = imdb_pq_name(f, len, h, e); /* the tail, before anything is parsed */
    if (rc) return rc;
    if (memcmp(h, name, 32)) return imdb_fail(e, IMDB_ERR_VERIFY, "parquet: a file whose tail does not hash to its name");
    if ((rc = imdb_pq_footer(f, len, ft, e)) || (rc = frame_check(ft, gap_mem, (void *)(uintptr_t)f, e))) return rc;
    return chunks_check(f, ft, IMDB_ERR_VERIFY, e);
}

typedef struct {
    pq_read_fn rd;
    void *ctx;
    uint8_t *buf;
    size_t bufsz;
} stream_gap;

static int gap_stream(void *ctx, uint64_t from, uint64_t to, imdb_err *e)
{
    stream_gap *s = ctx;
    while (from < to) {
        size_t k = to - from < s->bufsz ? (size_t)(to - from) : s->bufsz;
        int rc = s->rd(s->ctx, from, s->buf, k, e);
        if (rc) return rc;
        for (size_t i = 0; i < k; i++)
            if (s->buf[i]) return imdb_fail(e, IMDB_ERR_CORRUPT, "parquet: a byte between the chunks not zero");
        from += k;
    }
    return IMDB_OK;
}

/* imdb_pq_authenticate's rule and order over pieces (the tail, the opening magic, the footer, the frame, each chunk in
 * column order), so one file gets one verdict either way (t_pq compares them) */
int imdb_pq_authenticate_stream(pq_read_fn rd, void *ctx, uint64_t len, const uint8_t name[32], uint8_t *buf,
                                size_t bufsz, imdb_err *e)
{
    if (bufsz < 4096) return imdb_fail(e, IMDB_ERR_INVALID, "parquet: a piece buffer under 4096 bytes");
    if (len < 12) return imdb_fail(e, IMDB_ERR_CORRUPT, "parquet: not a Parquet file");
    uint8_t last[8], h[32];
    uint32_t ml;
    int rc = rd(ctx, len - 8, last, 8, e);
    if (rc || (rc = tail_len(last, len, &ml, e))) return rc;
    size_t tl = (size_t)ml + 8;
    uint8_t *tail = imdb_alloc(tl, e);
    if (!tail) return e->code;
    pq_footer ft;
    memset(&ft, 0, sizeof ft);
    if (!(rc = rd(ctx, len - tl, tail, tl, e))) {
        imdb_sha256(tail, tl, h);
        if (memcmp(h, name, 32)) rc = imdb_fail(e, IMDB_ERR_VERIFY, "parquet: a file whose tail does not hash to its name");
    }
    if (!rc && !(rc = rd(ctx, 0, buf, 4, e)) && memcmp(buf, "PAR1", 4))
        rc = imdb_fail(e, IMDB_ERR_CORRUPT, "parquet: not a Parquet file");
    if (!rc) rc = footer_walk(tail, ml, len, &ft, e);
    stream_gap sg = {rd, ctx, buf, bufsz};
    if (!rc) rc = frame_check(&ft, gap_stream, &sg, e);
    for (uint32_t ci = 0; !rc && ci < ft.ncols; ci++) {
        imdb_sha256_ctx c;
        imdb_sha256_init(&c);
        for (uint64_t at = ft.off[ci], end = at + ft.size[ci]; !rc && at < end;) {
            size_t k = end - at < bufsz ? (size_t)(end - at) : bufsz;
            if (!(rc = rd(ctx, at, buf, k, e))) imdb_sha256_update(&c, buf, k);
            at += k;
        }
        if (!rc) {
            char hx[65];
            imdb_sha256_final(&c, h);
            hex(h, 32, hx);
            if (memcmp(hx, ft.chunk_hex[ci], 64)) rc = imdb_fail(e, IMDB_ERR_VERIFY, "parquet: a chunk is not the one its footer names");
            imdb_wipe(hx, sizeof hx);
        }
        imdb_wipe(&c, sizeof c);
    }
    imdb_wipe(h, sizeof h);
    imdb_wipe(tail, tl); /* the footer's statistics and its chunks' unsalted hashes (f5-design.md section 2) */
    imdb_free(tail);
    return rc;
}

#ifdef IMDB_STORE_CHECKS
/* a checked build reads back every file it writes: its reader takes it (a refusal stops the build: the writer and the
 * reader disagree on the subset) and gives back the writer's values (an allocation refused skips the comparison) */
static void readback_check(const pq_col *cols, uint32_t ncols, uint64_t nrows, const imdb_buf *out)
{
    pq_col sh[PQ_MAX_COLUMNS];
    pq_rcol r[PQ_MAX_COLUMNS];
    pq_footer ft;
    imdb_err e = {0};
    for (uint32_t ci = 0; ci < ncols; ci++) {
        sh[ci] = cols[ci];
        sh[ci].fixed = sh[ci].data = sh[ci].present = NULL;
        sh[ci].off = NULL;
    }
    int rc = imdb_pq_footer(out->p, out->len, &ft, &e);
    if (!rc) rc = imdb_pq_read(out->p, out->len, &ft, sh, ncols, r, &e);
    if (rc == IMDB_ERR_CORRUPT) {
        fprintf(stderr, "imagedb: parquet: the reader refuses the writer's file: %s\n", e.msg);
        abort();
    }
    if (rc) return;
    for (uint32_t ci = 0; ci < ncols; ci++) {
        const pq_col *a = &cols[ci], *b = &r[ci].c;
        unsigned w = fixed_width(a);
        for (uint64_t i = 0; i < nrows; i++) {
            bool same = has_value(a, i) == has_value(b, i);
            if (same && has_value(a, i)) {
                if (a->phys == PQ_BYTE_ARRAY)
                    same = a->off[i + 1] - a->off[i] == b->off[i + 1] - b->off[i] &&
                           (a->off[i + 1] == a->off[i] || /* an empty value: a column of none may have no bytes */
                            !memcmp(a->data + a->off[i], b->data + b->off[i], a->off[i + 1] - a->off[i]));
                else if (a->phys == PQ_BOOLEAN)
                    same = a->fixed[i] == b->fixed[i];
                else
                    same = !memcmp(a->fixed + i * w, b->fixed + i * w, w);
            }
            if (!same) {
                fprintf(stderr, "imagedb: parquet: the reader gives another value than the writer's (column %u)\n", ci);
                abort();
            }
        }
    }
    imdb_pq_free_read(r, ncols);
}
#endif

/* the footer and a page header as the writer encodes them, for tools that build hostile files (forge.c, the tests):
 * a file's sizes and footer made consistent with a lie, so only the reader's rule for that lie can refuse it */
void imdb_pq_footer_encode(imdb_buf *out, const pq_col *cols, uint32_t ncols, uint64_t nrows, const uint64_t *off,
                           const uint64_t *size, const uint8_t *const *key, const uint32_t *klen,
                           const uint8_t *const *val, const uint32_t *vlen, uint32_t nkv)
{
    pq_stat st[PQ_MAX_COLUMNS];
    for (uint32_t ci = 0; ci < ncols && ci < PQ_MAX_COLUMNS; ci++) stat_of(&cols[ci], nrows, &st[ci]);
    footer_encode(out, cols, ncols, nrows, off, size, st, key, klen, val, vlen, nkv);
}

void imdb_pq_page_header_encode(imdb_buf *out, uint32_t size, uint64_t nvalues)
{
    tw w = {out, {0}, 0};
    page_header(&w, size, nvalues);
}

/* for tools that build hostile files (forge.c): the byte offset in f of row's value in column ci, a fixed-width column
 * other than BOOLEAN (its chunk one page), its present bits as read */
int imdb_pq_value_at(const uint8_t *f, size_t len, const pq_footer *ft, uint32_t ci, const pq_col *shape,
                     const uint8_t *present, uint64_t row, size_t *at, imdb_err *e)
{
    unsigned w = fixed_width(shape);
    if (ci >= ft->ncols || row >= ft->nrows || !w || shape->phys == PQ_BOOLEAN || ft->off[ci] >= len ||
        ft->size[ci] > len - ft->off[ci]) /* its header read within the file (imdb_pq_footer bounds neither sum) */
        return imdb_fail(e, IMDB_ERR_STATE, "parquet: no fixed-width value there");
    tr hr = {f + ft->off[ci], ft->size[ci], 0, {0}, 0};
    int16_t id;
    uint8_t t;
    if (tr_enter(&hr)) goto bad;
    for (;;) { /* the page header's length */
        if (tr_field(&hr, &id, &t)) goto bad;
        if (!t) break;
        if (tr_skip(&hr, t)) goto bad;
    }
    uint64_t v = ft->off[ci] + hr.at, rank = 0;
    if (shape->optional) {
        if (v + 4 > len) goto bad;
        v += 4 + imdb_get_le32(f + v);
        for (uint64_t i = 0; i < row; i++) rank += present[i >> 3] >> (i & 7) & 1;
    } else {
        rank = row;
    }
    *at = (size_t)(v + rank * w);
    return *at + w <= len ? IMDB_OK : imdb_fail(e, IMDB_ERR_STATE, "parquet: a value past the file");
bad:
    return imdb_fail(e, IMDB_ERR_CORRUPT, "parquet: a page header that does not parse");
}
