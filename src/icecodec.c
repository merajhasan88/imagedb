/* F5c (docs/f5c-design.md section 8): the Iceberg v3 layer's codecs, writers only (icecodec.h). */
#include "icecodec.h"

#include <string.h>

/* ---- JSON ------------------------------------------------------------------------------------------------- */

void ij_begin(ij *j, imdb_buf *b)
{
    memset(j, 0, sizeof *j);
    j->b = b;
}

/* a value's separator: a comma after an earlier member of its object or array, none after its key */
static void ij_sep(ij *j)
{
    if (j->key) {
        j->key = false;
        return;
    }
    if (j->depth && j->more[j->depth]) imdb_buf_put_u8(j->b, ',');
    if (j->depth) j->more[j->depth] = true;
}

static void ij_open(ij *j, uint8_t c)
{
    ij_sep(j);
    imdb_buf_put_u8(j->b, c);
    if (j->depth + 1 < (int)(sizeof j->more / sizeof j->more[0])) j->depth++;
    j->more[j->depth] = false;
}

static void ij_close(ij *j, uint8_t c)
{
    imdb_buf_put_u8(j->b, c);
    if (j->depth) j->depth--;
}

void ij_obj(ij *j) { ij_open(j, '{'); }
void ij_end_obj(ij *j) { ij_close(j, '}'); }
void ij_arr(ij *j) { ij_open(j, '['); }
void ij_end_arr(ij *j) { ij_close(j, ']'); }

static void ij_quoted(imdb_buf *b, const char *s, size_t n)
{
    static const char hx[] = "0123456789abcdef";
    imdb_buf_put_u8(b, '"');
    for (size_t i = 0; i < n; i++) {
        uint8_t c = (uint8_t)s[i];
        if (c == '"' || c == '\\') {
            imdb_buf_put_u8(b, '\\');
            imdb_buf_put_u8(b, c);
        } else if (c < 0x20) { /* one form for every control character */
            uint8_t u[6] = {'\\', 'u', '0', '0', (uint8_t)hx[c >> 4], (uint8_t)hx[c & 15]};
            imdb_buf_put(b, u, sizeof u);
        } else {
            imdb_buf_put_u8(b, c);
        }
    }
    imdb_buf_put_u8(b, '"');
}

void ij_key(ij *j, const char *k)
{
    ij_sep(j);
    ij_quoted(j->b, k, strlen(k));
    imdb_buf_put_u8(j->b, ':');
    j->key = true;
}

void ij_str(ij *j, const char *s, size_t n)
{
    ij_sep(j);
    ij_quoted(j->b, s, n);
}

void ij_cstr(ij *j, const char *s) { ij_str(j, s, strlen(s)); }

void ij_i64(ij *j, int64_t v)
{
    ij_sep(j);
    imdb_buf_printf(j->b, "%lld", (long long)v);
}

void ij_bool(ij *j, bool v)
{
    ij_sep(j);
    imdb_buf_put_str(j->b, v ? "true" : "false");
}

void ij_null(ij *j)
{
    ij_sep(j);
    imdb_buf_put_str(j->b, "null");
}

void ij_raw(ij *j, const char *s)
{
    ij_sep(j);
    imdb_buf_put_str(j->b, s);
}

/* ---- Avro ------------------------------------------------------------------------------------------------- */

void imdb_av_long(imdb_buf *b, int64_t v)
{
    uint64_t z = ((uint64_t)v << 1) ^ (uint64_t)(v >> 63);
    while (z >= 0x80) {
        imdb_buf_put_u8(b, (uint8_t)(z | 0x80));
        z >>= 7;
    }
    imdb_buf_put_u8(b, (uint8_t)z);
}

void imdb_av_bytes(imdb_buf *b, const void *p, size_t n)
{
    imdb_av_long(b, (int64_t)n);
    if (n) imdb_buf_put(b, p, n);
}

void imdb_av_str(imdb_buf *b, const char *s) { imdb_av_bytes(b, s, strlen(s)); }

void imdb_av_file(imdb_buf *out, const char *schema, const char *const *meta, uint32_t nmeta, const uint8_t sync[16],
                  uint64_t nrec, const uint8_t *records, size_t rlen)
{
    imdb_buf_put(out, "Obj\x01", 4);
    imdb_av_long(out, (int64_t)nmeta + 2); /* the metadata map: one block of every pair, then the end */
    imdb_av_str(out, "avro.schema");
    imdb_av_str(out, schema);
    imdb_av_str(out, "avro.codec");
    imdb_av_str(out, "null");
    for (uint32_t k = 0; k < nmeta; k++) {
        imdb_av_str(out, meta[2 * k]);
        imdb_av_str(out, meta[2 * k + 1]);
    }
    imdb_av_long(out, 0);
    imdb_buf_put(out, sync, 16);
    imdb_av_long(out, (int64_t)nrec);
    imdb_av_long(out, (int64_t)rlen);
    if (rlen) imdb_buf_put(out, records, rlen);
    imdb_buf_put(out, sync, 16);
}

/* ---- the 64-bit roaring bitmap ---------------------------------------------------------------------------- */

enum { RB_COOKIE_NO_RUN = 12346, RB_ARRAY_MAX = 4096, RB_BITSET_BYTES = 8192 };

/* one 32-bit bitmap: the low halves lo[0..n), strictly ascending */
static void rb32_put(imdb_buf *out, const uint32_t *lo, size_t n)
{
    size_t nc = 0;
    for (size_t i = 0; i < n; i++) nc += !i || (lo[i] >> 16) != (lo[i - 1] >> 16);
    imdb_buf_put_u32(out, RB_COOKIE_NO_RUN);
    imdb_buf_put_u32(out, (uint32_t)nc);
    for (size_t i = 0; i < n;) { /* the descriptive header: each container's key and its cardinality - 1 */
        size_t k = i;
        while (k < n && (lo[k] >> 16) == (lo[i] >> 16)) k++;
        imdb_buf_put_u16(out, (uint16_t)(lo[i] >> 16));
        imdb_buf_put_u16(out, (uint16_t)(k - i - 1));
        i = k;
    }
    uint32_t off = 8 + 8 * (uint32_t)nc; /* the offsets, from this bitmap's cookie */
    for (size_t i = 0; i < n;) {
        size_t k = i;
        while (k < n && (lo[k] >> 16) == (lo[i] >> 16)) k++;
        imdb_buf_put_u32(out, off);
        off += k - i <= RB_ARRAY_MAX ? 2 * (uint32_t)(k - i) : RB_BITSET_BYTES;
        i = k;
    }
    for (size_t i = 0; i < n;) { /* the containers */
        size_t k = i;
        while (k < n && (lo[k] >> 16) == (lo[i] >> 16)) k++;
        if (k - i <= RB_ARRAY_MAX) {
            for (size_t m = i; m < k; m++) imdb_buf_put_u16(out, (uint16_t)lo[m]);
        } else {
            uint64_t w[RB_BITSET_BYTES / 8];
            memset(w, 0, sizeof w);
            for (size_t m = i; m < k; m++) w[(lo[m] & 0xffff) >> 6] |= 1ull << (lo[m] & 63);
            for (size_t m = 0; m < RB_BITSET_BYTES / 8; m++) imdb_buf_put_u64(out, w[m]);
        }
        i = k;
    }
}

int imdb_roaring64_put(imdb_buf *out, const uint64_t *pos, size_t n, imdb_err *e)
{
    for (size_t i = 0; i < n; i++)
        if (pos[i] >> 63 || (i && pos[i] <= pos[i - 1]))
            return imdb_fail(e, IMDB_ERR_STATE, "roaring: positions not ascending below 2^63");
    size_t nk = 0;
    for (size_t i = 0; i < n; i++) nk += !i || (pos[i] >> 32) != (pos[i - 1] >> 32);
    imdb_buf_put_u64(out, (uint64_t)nk);
    uint32_t *lo = n ? imdb_alloc_array(n, sizeof *lo, e) : NULL;
    if (n && !lo) return e->code;
    for (size_t i = 0; i < n;) {
        size_t k = i;
        while (k < n && (pos[k] >> 32) == (pos[i] >> 32)) k++;
        imdb_buf_put_u32(out, (uint32_t)(pos[i] >> 32));
        for (size_t m = i; m < k; m++) lo[m - i] = (uint32_t)pos[m];
        rb32_put(out, lo, k - i);
        i = k;
    }
    imdb_free(lo);
    return imdb_buf_check(out, e);
}

/* ---- Puffin ----------------------------------------------------------------------------------------------- */

uint32_t imdb_crc32_iso(const uint8_t *p, size_t n)
{
    uint32_t c = 0xffffffffu;
    for (size_t i = 0; i < n; i++) {
        c ^= p[i];
        for (int k = 0; k < 8; k++) c = c >> 1 ^ (0xedb88320u & (0u - (c & 1)));
    }
    return c ^ 0xffffffffu;
}

static void put_be32(imdb_buf *b, uint32_t v)
{
    uint8_t t[4] = {(uint8_t)(v >> 24), (uint8_t)(v >> 16), (uint8_t)(v >> 8), (uint8_t)v};
    imdb_buf_put(b, t, 4);
}

int imdb_dv_blob(imdb_buf *out, const uint64_t *pos, size_t n, imdb_err *e)
{
    imdb_buf v; /* the magic and the bitmap: what the length counts and the CRC covers */
    imdb_buf_init(&v);
    static const uint8_t magic[4] = {0xd1, 0xd3, 0x39, 0x64};
    imdb_buf_put(&v, magic, 4);
    int rc = imdb_roaring64_put(&v, pos, n, e);
    if (!rc && v.len > UINT32_MAX) rc = imdb_fail(e, IMDB_ERR_LIMIT, "puffin: a deletion vector past 4 GiB");
    if (!rc) {
        put_be32(out, (uint32_t)v.len);
        imdb_buf_put(out, v.p, v.len);
        put_be32(out, imdb_crc32_iso(v.p, v.len));
        rc = imdb_buf_check(out, e);
    }
    imdb_buf_free(&v);
    return rc;
}

void imdb_puffin_file(imdb_buf *out, const uint8_t *blobs, size_t blen, const char *footer, size_t flen)
{
    imdb_buf_put(out, "PFA1", 4);
    if (blen) imdb_buf_put(out, blobs, blen);
    imdb_buf_put(out, "PFA1", 4);
    if (flen) imdb_buf_put(out, footer, flen);
    imdb_buf_put_u32(out, (uint32_t)flen);
    imdb_buf_put_zeros(out, 4);
    imdb_buf_put(out, "PFA1", 4);
}
