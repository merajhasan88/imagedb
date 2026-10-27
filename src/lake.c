/* Lake: segments, deletion vectors, manifests; CHECKPOINT / COMPACT / ERASE. */
#include "lake.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

#include "db_internal.h"
#include "fsio.h"
#include "logdir.h"
#include "writer.h"

static const uint8_t kSegMagic[8] = {'I', 'M', 'D', 'B', 'S', 'E', 'G', '1'};
static const uint8_t kDvMagic[8] = {'I', 'M', 'D', 'B', 'D', 'V', '0', '1'};
static const uint8_t kManMagic[8] = {'I', 'M', 'D', 'B', 'M', 'A', 'N', '1'};

#define TS_MIN (-62135596800000000LL)
#define TS_MAX (253402300799999999LL)

static size_t align8(size_t x) { return (x + 7) & ~(size_t)7; }

static bool is_int_col(uint8_t type)
{
    return type == IMDB_T_INT64 || type == IMDB_T_DECIMAL || type == IMDB_T_TIMESTAMP || type == IMDB_T_FLOAT64;
}

static bool nullable(const imdb_column *c) { return (c->flags & IMDB_COL_NULLABLE) != 0; }

static bool valid_bit(const uint8_t *v, uint32_t i) { return v[i >> 3] >> (i & 7) & 1; }

#define SEG_MAX_SECTIONS (5 + 3 * IMDB_MAX_COLS + 1)

/* ---- canonical section layout ------------------------------------------- */

typedef struct secdesc {
    uint32_t kind, col;
    uint64_t len;
} secdesc;

/* Fills the canonical section list for a schema; text_len[c] gives TEXT_DATA
 * lengths. Returns the count (5 + per-column, VALID after a NULLABLE column's data, + 1). */
static uint32_t seg_layout(const imdb_schema *s, uint32_t n, const uint64_t *text_len, secdesc *d)
{
    uint32_t k = 0;
    d[k++] = (secdesc){SEG_VID, 0, 8ull * n};
    d[k++] = (secdesc){SEG_BEGIN, 0, 8ull * n};
    d[k++] = (secdesc){SEG_FLAGS, 0, n};
    d[k++] = (secdesc){SEG_SALT, 0, 16ull * n};
    d[k++] = (secdesc){SEG_COMMIT, 0, 32ull * n};
    for (uint32_t c = 0; c < s->ncols; c++) {
        uint8_t t = s->cols[c].type;
        if (is_int_col(t)) d[k++] = (secdesc){SEG_I64, c, 8ull * n};
        else if (t == IMDB_T_BOOL) d[k++] = (secdesc){SEG_U8, c, n};
        else {
            d[k++] = (secdesc){SEG_TEXT_OFF, c, 4ull * ((uint64_t)n + 1)};
            d[k++] = (secdesc){SEG_TEXT_DATA, c, text_len ? text_len[c] : 0};
        }
        if (nullable(&s->cols[c])) d[k++] = (secdesc){SEG_VALID, c, ((uint64_t)n + 7) / 8};
    }
    d[k++] = (secdesc){SEG_ZONEMAP, 0, 24ull * s->ncols};
    return k;
}

/* Fails rather than hash a short encoding: the hash goes into segments, and from them into signed manifests. */
static int schema_hash(const imdb_schema *s, uint8_t out[32], imdb_err *e)
{
    imdb_buf b;
    imdb_buf_init(&b);
    imdb_schema_encode(s, &b);
    int rc = imdb_buf_check(&b, e);
    if (!rc) imdb_sha256(b.p, b.len, out);
    imdb_buf_free(&b);
    return rc;
}

/* ---- segment parse ------------------------------------------------------------ */

void imdb_segment_free(imdb_segment *g)
{
    if (!g) return;
    if (g->bytes) imdb_wipe(g->bytes, g->len);
    free(g->bytes);
    free(g->end);
    free(g->stubmask);
    free(g);
}

static bool all_zero(const uint8_t *p, size_t n)
{
    for (size_t i = 0; i < n; i++)
        if (p[i]) return false;
    return true;
}

/* Whether a row with these flags keeps column c's value (lake.h). */
static bool seg_keeps(uint8_t flags, const imdb_schema *s, uint32_t c)
{
    return flags == 0 || (flags == IMDB_SEG_PURGED && (int)c == s->subject);
}

int imdb_segment_parse(const imdb_schema *s, uint8_t *b, size_t len, imdb_segment **out, imdb_err *e)
{
    *out = NULL;
    if (len < IMDB_SEG_HEADER || memcmp(b, kSegMagic, 8) != 0) return imdb_fail(e, IMDB_ERR_CORRUPT, "segment: bad magic");
    if (((uintptr_t)b & 7) != 0) return imdb_fail(e, IMDB_ERR_INVALID, "segment: buffer not 8-byte aligned");
    uint32_t ver = imdb_get_le32(b + 8), table = imdb_get_le32(b + 12);
    uint32_t n = imdb_get_le32(b + 48), ncols = imdb_get_le32(b + 52), nsec = imdb_get_le32(b + 56);
    if (ver != 2) return imdb_fail(e, IMDB_ERR_CORRUPT, "segment: unsupported version");
    if (table != s->id) return imdb_fail(e, IMDB_ERR_CORRUPT, "segment: belongs to another table");
    uint8_t sh[32];
    if (schema_hash(s, sh, e)) return e->code;
    if (memcmp(sh, b + 16, 32) != 0) return imdb_fail(e, IMDB_ERR_CORRUPT, "segment: schema hash mismatch");
    if (n > IMDB_MAX_SEGMENT_ROWS) return imdb_fail(e, IMDB_ERR_CORRUPT, "segment: too many rows");
    if (ncols != s->ncols || imdb_get_le32(b + 60) != 0) return imdb_fail(e, IMDB_ERR_CORRUPT, "segment: bad header");
    secdesc want[SEG_MAX_SECTIONS];
    uint32_t nwant = seg_layout(s, n, NULL, want);
    if (nsec != nwant) return imdb_fail(e, IMDB_ERR_CORRUPT, "segment: wrong section count");
    size_t dir_end = IMDB_SEG_HEADER + 24u * (size_t)nsec;
    if (dir_end > len) return imdb_fail(e, IMDB_ERR_CORRUPT, "segment: truncated directory");
    size_t pos = dir_end;
    const uint8_t *sec[SEG_MAX_SECTIONS];
    uint64_t seclen[SEG_MAX_SECTIONS];
    for (uint32_t k = 0; k < nsec; k++) {
        const uint8_t *d = b + IMDB_SEG_HEADER + 24u * k;
        uint32_t kind = imdb_get_le32(d), col = imdb_get_le32(d + 4);
        uint64_t off = imdb_get_le64(d + 8), sl = imdb_get_le64(d + 16);
        if (kind != want[k].kind || col != want[k].col)
            return imdb_fail(e, IMDB_ERR_CORRUPT, "segment: section %u out of canonical order", k);
        if (kind != SEG_TEXT_DATA && sl != want[k].len)
            return imdb_fail(e, IMDB_ERR_CORRUPT, "segment: section %u has wrong length", k);
        size_t expect = align8(pos);
        if (expect > len || off != expect || sl > len - off)
            return imdb_fail(e, IMDB_ERR_CORRUPT, "segment: section %u misplaced", k);
        if (!all_zero(b + pos, expect - pos)) return imdb_fail(e, IMDB_ERR_CORRUPT, "segment: non-zero padding");
        sec[k] = b + off;
        seclen[k] = sl;
        pos = (size_t)(off + sl);
    }
    if (pos != len) return imdb_fail(e, IMDB_ERR_CORRUPT, "segment: trailing bytes");

    imdb_segment *g = imdb_alloc(sizeof *g, e);
    if (!g) return e->code;
    g->table = table;
    g->nrows = n;
    g->vid = (const uint64_t *)(const void *)sec[0];
    g->begin = (const uint64_t *)(const void *)sec[1];
    g->flags = sec[2];
    g->salt = sec[3];
    g->commit = sec[4];
    int rc = IMDB_OK;
    for (uint32_t i = 0; i < n && !rc; i++) {
        if (i && g->vid[i] <= g->vid[i - 1]) rc = imdb_fail(e, IMDB_ERR_CORRUPT, "segment: version ids not ascending");
        else if (g->flags[i] > (IMDB_SEG_STUB | IMDB_SEG_PURGED)) rc = imdb_fail(e, IMDB_ERR_CORRUPT, "segment: bad row flags");
        else if (g->flags[i] && !all_zero(g->salt + 16u * i, 16)) rc = imdb_fail(e, IMDB_ERR_CORRUPT, "segment: erased or purged row keeps a salt");
        else if (g->begin[i] == 0 || g->begin[i] >= IMDB_LIVE) rc = imdb_fail(e, IMDB_ERR_CORRUPT, "segment: bad begin");
    }
    uint32_t k = 5;
    for (uint32_t c = 0; c < s->ncols && !rc; c++) {
        const imdb_column *col = &s->cols[c];
        imdb_segcol *sc = &g->col[c];
        /* VALID follows the column's data; a row keeps a value only if it keeps the column and,
         * when NULLABLE, has its bit set: every other row holds zero data */
        const uint8_t *vb = NULL;
        if (nullable(col)) {
            uint32_t vk = k + (col->type == IMDB_T_TEXT ? 2 : 1);
            vb = sec[vk];
            if ((n & 7) && (vb[n >> 3] >> (n & 7)) != 0) rc = imdb_fail(e, IMDB_ERR_CORRUPT, "segment: VALID padding");
            for (uint32_t i = 0; i < n && !rc; i++)
                if (valid_bit(vb, i) && g->flags[i])
                    rc = imdb_fail(e, IMDB_ERR_CORRUPT, "segment: erased or purged row marked VALID in column %s", col->name);
            sc->valid = vb;
        }
        if (is_int_col(col->type)) {
            sc->i64 = (const int64_t *)(const void *)sec[k++];
            int64_t lim = col->type == IMDB_T_DECIMAL ? imdb_pow10(col->precision) - 1 : 0;
            for (uint32_t i = 0; i < n && !rc; i++) {
                int64_t v = sc->i64[i];
                if (!seg_keeps(g->flags[i], s, c) || (vb && !valid_bit(vb, i))) {
                    if (v) rc = imdb_fail(e, IMDB_ERR_CORRUPT, "segment: a row without a value in column %s keeps data", col->name);
                } else if ((col->type == IMDB_T_DECIMAL && (v > lim || v < -lim)) ||
                           (col->type == IMDB_T_TIMESTAMP && (v < TS_MIN || v > TS_MAX)) ||
                           (col->type == IMDB_T_FLOAT64 && !imdb_f64_key_valid(v))) {
                    rc = imdb_fail(e, IMDB_ERR_CORRUPT, "segment: value out of range in column %s", col->name);
                }
            }
        } else if (col->type == IMDB_T_BOOL) {
            sc->u8 = sec[k++];
            for (uint32_t i = 0; i < n && !rc; i++)
                if (sc->u8[i] > 1 || ((g->flags[i] || (vb && !valid_bit(vb, i))) && sc->u8[i]))
                    rc = imdb_fail(e, IMDB_ERR_CORRUPT, "segment: bad BOOL in column %s", col->name);
        } else {
            sc->off = (const uint32_t *)(const void *)sec[k++];
            sc->data = sec[k];
            uint64_t dlen = seclen[k++];
            if (sc->off[0] != 0 || sc->off[n] != dlen) rc = imdb_fail(e, IMDB_ERR_CORRUPT, "segment: bad TEXT offsets");
            for (uint32_t i = 0; i < n && !rc; i++) {
                uint32_t a = sc->off[i], z = sc->off[i + 1];
                size_t bad;
                if (z < a || z > dlen || z - a > IMDB_MAX_TEXT) rc = imdb_fail(e, IMDB_ERR_CORRUPT, "segment: bad TEXT length");
                else if ((!seg_keeps(g->flags[i], s, c) || (vb && !valid_bit(vb, i))) && z != a)
                    rc = imdb_fail(e, IMDB_ERR_CORRUPT, "segment: a row without a value in column %s keeps text", col->name);
                else if (z > a && !imdb_utf8_valid(sc->data + a, z - a, &bad))
                    rc = imdb_fail(e, IMDB_ERR_CORRUPT, "segment: invalid UTF-8 in column %s", col->name);
            }
        }
        if (vb) k++;
    }
    /* zone maps must be exactly the recomputed ones (canonical) */
    const uint8_t *zm = rc ? NULL : sec[k];
    for (uint32_t c = 0; c < s->ncols && !rc; c++) {
        const uint8_t *z = zm + 24u * c;
        imdb_segcol *sc = &g->col[c];
        bool has = false, has_null = false;
        int64_t mn = 0, mx = 0;
        for (uint32_t i = 0; sc->valid && i < n; i++) has_null |= !g->flags[i] && !valid_bit(sc->valid, i);
        if (s->cols[c].type != IMDB_T_TEXT)
            for (uint32_t i = 0; i < n; i++) {
                if (g->flags[i] || (sc->valid && !valid_bit(sc->valid, i))) continue;
                int64_t v = sc->i64 ? sc->i64[i] : sc->u8[i];
                if (!has || v < mn) mn = v;
                if (!has || v > mx) mx = v;
                has = true;
            }
        if (z[0] != has || z[1] != has_null || !all_zero(z + 2, 6) || (int64_t)imdb_get_le64(z + 8) != mn ||
            (int64_t)imdb_get_le64(z + 16) != mx)
            rc = imdb_fail(e, IMDB_ERR_CORRUPT, "segment: zone map does not match data");
        sc->has = has;
        sc->has_null = has_null;
        sc->min = mn;
        sc->max = mx;
    }
    if (!rc) {
        g->end = imdb_alloc_array(n ? n : 1, sizeof *g->end, e);
        g->stubmask = imdb_alloc_array((n + 63) / 64 + 1, sizeof *g->stubmask, e);
        if (!g->end || !g->stubmask) rc = e->code;
        for (uint32_t i = 0; !rc && i < n; i++) {
            g->end[i] = IMDB_LIVE;
            if (g->flags[i]) g->stubmask[i >> 6] |= 1ull << (i & 63);
        }
    }
    if (rc) {
        free(g->end);
        free(g->stubmask);
        free(g);
        return rc;
    }
    g->bytes = b;
    g->len = len;
    imdb_sha256(b, len, g->hash);
    *out = g;
    return IMDB_OK;
}

static void seg_get(const imdb_schema *s, const imdb_segment *g, uint32_t row, uint32_t c, imdb_value *v)
{
    memset(v, 0, sizeof *v);
    v->type = s->cols[c].type;
    v->scale = s->cols[c].scale;
    const imdb_segcol *sc = &g->col[c];
    if (sc->valid && !valid_bit(sc->valid, row)) {
        v->null = true;
        return;
    }
    if (sc->i64) v->i = sc->i64[row];
    else if (sc->u8) v->i = sc->u8[row];
    else {
        v->s = sc->data + sc->off[row];
        v->len = sc->off[row + 1] - sc->off[row];
    }
}

int imdb_segment_row(const imdb_schema *s, const imdb_segment *g, uint32_t row, imdb_buf *out, imdb_err *e)
{
    imdb_value vals[IMDB_MAX_COLS];
    for (uint32_t c = 0; c < s->ncols; c++) seg_get(s, g, row, c, &vals[c]);
    return imdb_row_encode(s, vals, out, e);
}

int imdb_segment_check_commitments(const imdb_schema *s, const imdb_segment *g, imdb_err *e)
{
    imdb_buf row;
    imdb_buf_init(&row);
    int rc = IMDB_OK;
    for (uint32_t i = 0; i < g->nrows && !rc; i++) {
        if (g->flags[i]) continue;
        row.len = 0;
        if ((rc = imdb_segment_row(s, g, i, &row, e))) break;
        uint8_t c[32];
        imdb_row_commit(s->id, g->salt + 16u * i, row.p, row.len, c);
        if (memcmp(c, g->commit + 32u * i, 32) != 0)
            rc = imdb_fail(e, IMDB_ERR_VERIFY, "segment: row %u does not match its commitment", i);
    }
    imdb_buf_wipe_free(&row);
    return rc;
}

/* ---- segment build -------------------------------------------------------- */

typedef struct erased_set {
    const imdb_erase_ent *e;
    uint32_t n;
} erased_set;

static bool erased_has(const erased_set *es, uint32_t table, uint64_t vid)
{
    uint32_t lo = 0, hi = es ? es->n : 0;
    while (lo < hi) {
        uint32_t mid = lo + (hi - lo) / 2;
        const imdb_erase_ent *m = &es->e[mid];
        if (m->table == table && m->vid == vid) return true;
        if (m->table < table || (m->table == table && m->vid < vid)) lo = mid + 1;
        else hi = mid;
    }
    return false;
}

static bool row_is_stub(const imdb_table *t, uint64_t vid, const erased_set *es)
{
    return (t->ver[vid].flags & IMDB_V_STUB) || erased_has(es, t->s.id, vid);
}

/* Value of column c of a (non-stub) version, wherever it lives. */
static void ver_get(const imdb_table *t, uint64_t vid, uint32_t c, imdb_value *v)
{
    const imdb_version *ver = &t->ver[vid];
    if (ver->flags & IMDB_V_SEG) seg_get(&t->s, t->seg[ver->seg], ver->seg_row, c, v);
    else imdb_row_get(&t->s, t->arena.p + ver->row_off, ver->row_len, (int)c, v);
}

/* Row flags of a version in a segment being built (lake.h): erased now or
 * by this ERASE, purged before or by this COMPACT ... PURGE. */
static uint8_t row_flags(const imdb_table *t, uint64_t vid, const erased_set *es, uint64_t purge_before)
{
    const imdb_version *v = &t->ver[vid];
    uint8_t f = row_is_stub(t, vid, es) ? IMDB_SEG_STUB : 0;
    if ((v->flags & IMDB_V_PURGED) || (purge_before && v->end != IMDB_LIVE && v->end <= purge_before))
        f |= IMDB_SEG_PURGED;
    return f;
}

static int seg_build(const imdb_table *t, const uint64_t *vids, uint32_t n, const erased_set *es,
                     uint64_t purge_before, imdb_segment **out, imdb_err *e)
{
    const imdb_schema *s = &t->s;
    if (n > IMDB_MAX_SEGMENT_ROWS) return imdb_fail(e, IMDB_ERR_LIMIT, "segment would exceed %u rows", IMDB_MAX_SEGMENT_ROWS);
    uint8_t *fl = imdb_alloc(n ? n : 1, e);
    if (!fl) return e->code;
    for (uint32_t i = 0; i < n; i++) fl[i] = row_flags(t, vids[i], es, purge_before);
    uint64_t text_len[IMDB_MAX_COLS] = {0};
    for (uint32_t c = 0; c < s->ncols; c++) {
        if (s->cols[c].type != IMDB_T_TEXT) continue;
        for (uint32_t i = 0; i < n; i++) {
            if (!seg_keeps(fl[i], s, c)) continue;
            imdb_value v;
            ver_get(t, vids[i], c, &v);
            text_len[c] += v.len;
        }
        if (text_len[c] > UINT32_MAX) {
            free(fl);
            return imdb_fail(e, IMDB_ERR_LIMIT, "segment text column too large");
        }
    }
    secdesc d[SEG_MAX_SECTIONS];
    uint32_t nsec = seg_layout(s, n, text_len, d);
    size_t pos = IMDB_SEG_HEADER + 24u * nsec;
    uint64_t off[SEG_MAX_SECTIONS];
    for (uint32_t k = 0; k < nsec; k++) {
        pos = align8(pos);
        off[k] = pos;
        if (d[k].len > IMDB_MAX_OBJECT - pos) {
            free(fl);
            return imdb_fail(e, IMDB_ERR_LIMIT, "segment too large");
        }
        pos += (size_t)d[k].len;
    }
    uint8_t *b = imdb_alloc_aligned(1, pos, e);
    if (!b) {
        free(fl);
        return e->code;
    }
    memcpy(b, kSegMagic, 8);
    imdb_le32(b + 8, 2);
    imdb_le32(b + 12, s->id);
    if (schema_hash(s, b + 16, e)) {
        free(b);
        free(fl);
        return e->code;
    }
    imdb_le32(b + 48, n);
    imdb_le32(b + 52, s->ncols);
    imdb_le32(b + 56, nsec);
    for (uint32_t k = 0; k < nsec; k++) {
        uint8_t *de = b + IMDB_SEG_HEADER + 24u * k;
        imdb_le32(de, d[k].kind);
        imdb_le32(de + 4, d[k].col);
        imdb_le64(de + 8, off[k]);
        imdb_le64(de + 16, d[k].len);
    }
    for (uint32_t i = 0; i < n; i++) {
        const imdb_version *v = &t->ver[vids[i]];
        imdb_le64(b + off[0] + 8u * i, vids[i]);
        imdb_le64(b + off[1] + 8u * i, v->begin);
        b[off[2] + i] = fl[i];
        if (!fl[i]) memcpy(b + off[3] + 16u * i, v->salt, 16);
        memcpy(b + off[4] + 32u * i, v->commit, 32);
    }
    uint32_t k = 5;
    uint8_t *zm = b + off[nsec - 1];
    for (uint32_t c = 0; c < s->ncols; c++) {
        bool has = false, has_null = false;
        int64_t mn = 0, mx = 0;
        uint8_t *vb = nullable(&s->cols[c]) ? b + off[k + (s->cols[c].type == IMDB_T_TEXT ? 2 : 1)] : NULL;
        if (s->cols[c].type == IMDB_T_TEXT) {
            uint8_t *o = b + off[k], *data = b + off[k + 1];
            uint32_t at = 0;
            for (uint32_t i = 0; i < n; i++) {
                imdb_le32(o + 4u * i, at);
                if (!seg_keeps(fl[i], s, c)) continue;
                imdb_value v;
                ver_get(t, vids[i], c, &v);
                if (v.null) {
                    has_null |= !fl[i];
                    continue;
                }
                if (vb) vb[i >> 3] |= (uint8_t)(1u << (i & 7));
                if (v.len) memcpy(data + at, v.s, v.len);
                at += v.len;
            }
            imdb_le32(o + 4u * n, at);
            k += 2;
        } else {
            for (uint32_t i = 0; i < n; i++) {
                if (!seg_keeps(fl[i], s, c)) continue;
                imdb_value v;
                ver_get(t, vids[i], c, &v);
                if (v.null) {
                    has_null |= !fl[i];
                    continue;
                }
                if (vb) vb[i >> 3] |= (uint8_t)(1u << (i & 7));
                if (s->cols[c].type == IMDB_T_BOOL) b[off[k] + i] = (uint8_t)v.i;
                else imdb_le64(b + off[k] + 8u * i, (uint64_t)v.i);
                if (fl[i]) continue; /* a tombstone's subject is not part of the zone map */
                if (!has || v.i < mn) mn = v.i;
                if (!has || v.i > mx) mx = v.i;
                has = true;
            }
            k++;
        }
        if (vb) k++;
        zm[24u * c] = has;
        zm[24u * c + 1] = has_null;
        imdb_le64(zm + 24u * c + 8, (uint64_t)mn);
        imdb_le64(zm + 24u * c + 16, (uint64_t)mx);
    }
    free(fl);
    /* Parse our own output: the encoder is always checked by the strict decoder. */
    imdb_segment *g;
    int rc = imdb_segment_parse(s, b, pos, &g, e);
    if (rc) {
        free(b);
        return rc;
    }
    for (uint32_t i = 0; i < n; i++) g->end[i] = t->ver[vids[i]].end;
    *out = g;
    return IMDB_OK;
}

/* ---- deletion vectors ----------------------------------------------------- */

static void dv_build(const imdb_segment *g, uint64_t snap, imdb_buf *out)
{
    uint32_t cnt = 0;
    for (uint32_t i = 0; i < g->nrows; i++) cnt += g->end[i] != IMDB_LIVE && g->end[i] <= snap;
    out->len = 0;
    if (!cnt) return;
    imdb_buf_put(out, kDvMagic, 8);
    imdb_buf_put(out, g->hash, 32);
    imdb_buf_put_u32(out, cnt);
    imdb_buf_put_u32(out, 0);
    for (uint32_t i = 0; i < g->nrows; i++) {
        if (g->end[i] == IMDB_LIVE || g->end[i] > snap) continue;
        imdb_buf_put_u32(out, i);
        imdb_buf_put_u32(out, 0);
        imdb_buf_put_u64(out, g->end[i]);
    }
}

int imdb_dv_parse(const uint8_t *b, size_t len, uint8_t seg_hash[32], imdb_dv_ent **ents, uint32_t *n,
                  uint32_t nrows, imdb_err *e)
{
    *ents = NULL;
    *n = 0;
    imdb_rd r;
    imdb_rd_init(&r, b, len);
    const uint8_t *m = imdb_rd_bytes(&r, 8);
    if (!m || memcmp(m, kDvMagic, 8) != 0) return imdb_fail(e, IMDB_ERR_CORRUPT, "dv: bad magic");
    imdb_rd_copy(&r, seg_hash, 32);
    uint32_t cnt = imdb_rd_u32(&r);
    if (imdb_rd_u32(&r) != 0 || r.err || cnt == 0 || cnt > nrows || cnt > imdb_rd_left(&r) / 16)
        return imdb_fail(e, IMDB_ERR_CORRUPT, "dv: bad count");
    imdb_dv_ent *v = imdb_alloc_array(cnt, sizeof *v, e);
    if (!v) return e->code;
    for (uint32_t i = 0; i < cnt; i++) {
        v[i].row = imdb_rd_u32(&r);
        uint32_t pad = imdb_rd_u32(&r);
        v[i].end = imdb_rd_u64(&r);
        if (pad || v[i].row >= nrows || v[i].end == 0 || v[i].end >= IMDB_LIVE || (i && v[i].row <= v[i - 1].row)) {
            free(v);
            return imdb_fail(e, IMDB_ERR_CORRUPT, "dv: bad entry");
        }
    }
    if (r.err || imdb_rd_left(&r)) {
        free(v);
        return imdb_fail(e, IMDB_ERR_CORRUPT, "dv: trailing or truncated");
    }
    *ents = v;
    *n = cnt;
    return IMDB_OK;
}

/* ---- manifest -------------------------------------------------------------- */

void imdb_manifest_free(imdb_manifest *m)
{
    for (uint32_t i = 0; i < m->nt; i++) free(m->t[i].seg);
    free(m->t);
    memset(m, 0, sizeof *m);
}

static int cmp_name_ptr(const void *a, const void *b) { return strcmp(*(const char *const *)a, *(const char *const *)b); }

/* version 3: at least one index (else version 2 is the encoding), and names unique across
 * tables (sorted, so a hostile manifest cannot make this quadratic). IMDB_ERR_CORRUPT, or the
 * allocation's own error: a check that cannot run is never reported as corruption */
static int manifest_index_names(const imdb_manifest *m, imdb_err *e)
{
    size_t n = 0;
    for (uint32_t i = 0; i < m->nt; i++) n += m->t[i].nidx;
    if (!n) return IMDB_ERR_CORRUPT;
    const char **p = imdb_alloc_array(n, sizeof *p, e);
    if (!p) return e->code;
    size_t k = 0;
    for (uint32_t i = 0; i < m->nt; i++)
        for (uint32_t j = 0; j < m->t[i].nidx; j++) p[k++] = m->t[i].idx[j].d.name;
    qsort(p, n, sizeof *p, cmp_name_ptr);
    bool dup = false;
    for (size_t i = 1; i < n && !dup; i++) dup = strcmp(p[i - 1], p[i]) == 0;
    free(p);
    return dup ? IMDB_ERR_CORRUPT : IMDB_OK;
}

int imdb_manifest_parse(const uint8_t *b, size_t len, imdb_manifest *m, imdb_err *e)
{
    memset(m, 0, sizeof *m);
    imdb_rd r;
    imdb_rd_init(&r, b, len);
    const uint8_t *mg = imdb_rd_bytes(&r, 8);
    if (!mg || memcmp(mg, kManMagic, 8) != 0) return imdb_fail(e, IMDB_ERR_CORRUPT, "manifest: bad magic");
    uint32_t ver = imdb_rd_u32(&r);
    if (ver != 2 && ver != 3) return imdb_fail(e, IMDB_ERR_CORRUPT, "manifest: unsupported version");
    uint32_t nt = imdb_rd_u32(&r);
    imdb_rd_copy(&r, m->db_id, 16);
    m->seq = imdb_rd_u64(&r);
    imdb_rd_copy(&r, m->prev, 32);
    imdb_rd_copy(&r, m->state, 32);
    imdb_rd_copy(&r, m->prev_manifest, 32);
    if (r.err || nt > IMDB_MAX_TABLES || nt > imdb_rd_left(&r) / 64) return imdb_fail(e, IMDB_ERR_CORRUPT, "manifest: bad table count");
    m->t = imdb_alloc_array(nt ? nt : 1, sizeof *m->t, e);
    if (!m->t) return e->code;
    m->nt = nt;
    for (uint32_t i = 0; i < nt; i++) {
        imdb_manifest_tab *t = &m->t[i];
        uint32_t sl = imdb_rd_u32(&r);
        const uint8_t *sb = imdb_rd_bytes(&r, sl);
        if (!sb) goto bad;
        imdb_rd sr;
        imdb_rd_init(&sr, sb, sl);
        imdb_err e2 = {0};
        if (imdb_schema_decode(&sr, &t->s, &e2) || imdb_rd_left(&sr) || t->s.id != i) goto bad;
        t->horizon = imdb_rd_u64(&r);
        t->live = imdb_rd_u64(&r);
        t->versions = imdb_rd_u64(&r);
        imdb_rd_copy(&r, (uint8_t *)t->digest.v, IMDB_LTHASH_BYTES);
        t->nseg = imdb_rd_u32(&r);
        if (r.err || t->nseg > IMDB_MAX_SEGMENTS || t->nseg > imdb_rd_left(&r) / 68 || t->live > t->versions) goto bad;
        t->seg = imdb_alloc_array(t->nseg ? t->nseg : 1, sizeof *t->seg, e);
        if (!t->seg) {
            imdb_manifest_free(m);
            return e->code;
        }
        for (uint32_t k = 0; k < t->nseg; k++) {
            imdb_rd_copy(&r, t->seg[k].seg, 32);
            imdb_rd_copy(&r, t->seg[k].dv, 32);
            t->seg[k].nrows = imdb_rd_u32(&r);
        }
        if (ver == 3) {
            t->nidx = imdb_rd_u32(&r);
            if (r.err || t->nidx > IMDB_MAX_INDEXES) goto bad;
            for (uint32_t k = 0; k < t->nidx; k++) {
                imdb_index_def *d = &t->idx[k].d;
                imdb_err ei = {0};
                if (imdb_rd_ident(&r, d->name, &ei)) goto bad;
                d->flags = imdb_rd_u8(&r);
                d->ncols = imdb_rd_u8(&r);
                for (uint8_t c = 0; c < d->ncols && c < IMDB_MAX_INDEX_COLS; c++) d->cols[c] = imdb_rd_u16(&r);
                if (r.err || !imdb_index_def_ok(d, t->s.ncols)) goto bad;
                if (k && strcmp(t->idx[k - 1].d.name, d->name) >= 0) goto bad; /* sorted, unique */
            }
        }
        if (r.err) goto bad;
    }
    if (imdb_rd_left(&r)) goto bad;
    if (ver == 3) {
        int nrc = manifest_index_names(m, e);
        if (nrc && nrc != IMDB_ERR_CORRUPT) {
            imdb_manifest_free(m);
            return nrc;
        }
        if (nrc) goto bad;
    }
    return IMDB_OK;
bad:
    imdb_manifest_free(m);
    return imdb_fail(e, IMDB_ERR_CORRUPT, "manifest: malformed");
}

bool imdb_object_name_valid(const char *name)
{
    size_t n = strnlen(name, 80);
    if (n < 64 + 3 || n > 64 + 4) return false;
    for (int i = 0; i < 64; i++)
        if (!((name[i] >= '0' && name[i] <= '9') || (name[i] >= 'a' && name[i] <= 'f'))) return false;
    const char *x = name + 64;
    return strcmp(x, ".seg") == 0 || strcmp(x, ".dv") == 0 || strcmp(x, ".man") == 0;
}

static void obj_name(const uint8_t h[32], const char *ext, char out[80])
{
    imdb_hex(h, 32, out);
    strcpy(out + 64, ext);
}

bool imdb_pin_name_valid(const char *name)
{
    if (strnlen(name, 80) != 64 + 4 || strcmp(name + 64, ".pin") != 0) return false;
    for (int i = 0; i < 64; i++)
        if (!((name[i] >= '0' && name[i] <= '9') || (name[i] >= 'a' && name[i] <= 'f'))) return false;
    return true;
}

/* Best effort by design: a reader without its pin reads unpinned and retries (lake.h), so no
 * failure here may stop an open: every one leaves *fd = -1. */
int imdb_lake_pin(int dirfd, const uint8_t manifest[32], int *fd, imdb_err *e)
{
    (void)e;
    *fd = -1;
    int pfd = imdb_io_openat(dirfd, IMDB_PINS_DIR, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (pfd < 0) return IMDB_OK;
    char name[80];
    obj_name(manifest, ".pin", name);
    for (int attempt = 0; attempt < 3 && *fd < 0; attempt++) {
        int f = imdb_io_openat(pfd, name, O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0600);
        if (f < 0) break; /* not ours to write, or failing: unpinned */
        /* GC unlinks a stale pin while it holds it exclusively: a lock on that file pins nothing */
        struct stat a, b;
        if (imdb_io_flock(f, LOCK_SH) == 0 && imdb_io_fstat(f, &a) == 0 &&
            imdb_io_fstatat(pfd, name, &b, AT_SYMLINK_NOFOLLOW) == 0 && a.st_ino == b.st_ino && a.st_dev == b.st_dev)
            *fd = f;
        else
            close(f);
    }
    close(pfd);
    return IMDB_OK;
}

void imdb_lake_unpin(int fd)
{
    if (fd >= 0) close(fd); /* the lease ends with the descriptor */
}

static int read_obj(int ofd, const uint8_t h[32], const char *ext, uint8_t **out, size_t *len, imdb_err *e);

/* GC's view of pins/ (lake.h): the generations held pins keep, and the stale pins it holds
 * exclusively until their files are gone. One entry per pin file, grown as pins/ is read. */
typedef struct pinent {
    imdb_manifest m; /* kept: its generation, parsed */
    uint8_t h[32];
    bool kept;
    int fd;          /* stale: held with LOCK_EX until the pin file goes */
    char name[69];
} pinent;
typedef struct pinset {
    pinent *p;
    size_t n, cap;
} pinset;

static void pinset_free(pinset *P)
{
    for (size_t i = 0; i < P->n; i++) {
        if (P->p[i].kept) imdb_manifest_free(&P->p[i].m);
        if (P->p[i].fd >= 0) close(P->p[i].fd);
    }
    free(P->p);
    memset(P, 0, sizeof *P);
}

/* Reads pins/ (at most IMDB_MAX_PIN_FILES entries). A pin is held when its file cannot be locked
 * exclusively; its generation is kept when its manifest is still there, is this database's, and
 * is at or past the pin floor (an ERASE's own commit sets it before its publication's GC: the
 * revocation), within pin_max_lag of the current commit: the IMDB_MAX_PINNED newest of those.
 * Errors only lose retention (GC then keeps less), never fail the publish. */
static void pins_collect(imdb_db *db, int ofd, pinset *P)
{
    memset(P, 0, sizeof *P);
    int pfd = imdb_io_openat(db->dirfd, IMDB_PINS_DIR, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (pfd < 0) return;
    int dfd = imdb_io_openat(pfd, ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    DIR *d = dfd >= 0 ? imdb_io_fdopendir(dfd) : NULL;
    if (!d) {
        if (dfd >= 0) close(dfd);
        close(pfd);
        return;
    }
    imdb_err e = {0};
    uint64_t floor = db->snapshot_seq > db->last_erase ? db->snapshot_seq : db->last_erase;
    size_t seen = 0, kept = 0;
    struct dirent *de;
    while (seen < IMDB_MAX_PIN_FILES && (de = imdb_io_readdir(d))) {
        if (!imdb_pin_name_valid(de->d_name)) continue;
        seen++;
        if (P->n == P->cap) {
            size_t nc = P->cap ? 2 * P->cap : 8;
            pinent *np = imdb_realloc_array(P->p, P->cap, nc, sizeof *np, &e);
            if (!np) break;
            P->p = np;
            P->cap = nc;
        }
        pinent *x = &P->p[P->n];
        memset(x, 0, sizeof *x);
        x->fd = -1;
        int f = imdb_io_openat(pfd, de->d_name, O_RDWR | O_CLOEXEC | O_NOFOLLOW);
        if (f < 0) continue;
        if (imdb_io_flock(f, LOCK_EX | LOCK_NB) == 0) { /* stale: no reader holds it */
            x->fd = f;
            memcpy(x->name, de->d_name, sizeof x->name);
            P->n++;
            continue;
        }
        close(f);
        uint8_t *mb = NULL;
        size_t ml = 0;
        if (!imdb_unhex(de->d_name, 64, x->h, 32) || read_obj(ofd, x->h, ".man", &mb, &ml, &e) ||
            imdb_manifest_parse(mb, ml, &x->m, &e)) {
            free(mb);
            imdb_err_clear(&e);
            continue;
        }
        free(mb);
        if (memcmp(x->m.db_id, db->db_id, 16) != 0 || x->m.seq < floor || x->m.seq > db->lake_seq ||
            db->lake_seq - x->m.seq > db->pin_max_lag) {
            imdb_manifest_free(&x->m);
            continue;
        }
        x->kept = true;
        P->n++;
        kept++;
    }
    closedir(d);
    close(pfd);
    for (; kept > IMDB_MAX_PINNED; kept--) { /* the IMDB_MAX_PINNED newest: the oldest go */
        size_t old = SIZE_MAX;
        for (size_t i = 0; i < P->n; i++)
            if (P->p[i].kept && (old == SIZE_MAX || P->p[i].m.seq < P->p[old].m.seq)) old = i;
        imdb_manifest_free(&P->p[old].m);
        P->p[old].kept = false;
    }
}

/* ---- planning -------------------------------------------------------------- */

typedef struct plan_tab {
    imdb_segment **seg;
    bool *owned;
    imdb_buf *dv;            /* DV bytes per segment (len 0 = none) */
    uint32_t nseg;
    uint64_t horizon;
    bool flushed;
    bool compacted;
} plan_tab;

typedef struct imdb_lake_plan {
    uint8_t kind;
    uint64_t seq;
    plan_tab *tab;
    uint32_t nt;
    imdb_buf manifest;
    uint8_t mhash[32];
    imdb_rewrite *rw;
    uint32_t nrw;
} imdb_lake_plan;

static void plan_free(imdb_lake_plan *p)
{
    if (!p) return;
    for (uint32_t i = 0; i < p->nt; i++) {
        plan_tab *pt = &p->tab[i];
        for (uint32_t k = 0; k < pt->nseg; k++) {
            if (pt->owned && pt->owned[k]) imdb_segment_free(pt->seg[k]);
            if (pt->dv) imdb_buf_free(&pt->dv[k]);
        }
        free(pt->seg);
        free(pt->owned);
        free(pt->dv);
    }
    free(p->tab);
    imdb_buf_free(&p->manifest);
    free(p->rw);
    free(p);
}

static int pt_push(plan_tab *pt, imdb_segment *g, bool owned, imdb_err *e)
{
    imdb_segment **ns = imdb_realloc_array(pt->seg, pt->nseg, pt->nseg + 1, sizeof *ns, e);
    if (!ns) return e->code;
    pt->seg = ns;
    bool *no = imdb_realloc_array(pt->owned, pt->nseg, pt->nseg + 1, sizeof *no, e);
    if (!no) return e->code;
    pt->owned = no;
    pt->seg[pt->nseg] = g;
    pt->owned[pt->nseg] = owned;
    pt->nseg++;
    return IMDB_OK;
}

static int cmp_rw(const void *a, const void *b)
{
    const imdb_rewrite *x = a, *y = b;
    if (x->table != y->table) return x->table < y->table ? -1 : 1;
    return memcmp(x->old_hash, y->old_hash, 32);
}

/* Builds the complete lake state for commit `seq` from the in-memory state.
 * kind: CHECKPOINT (flush), COMPACT (flush + merge target), ERASE (rewrite
 * segments holding erased rows + flush). post: per-table digests after the commit. */
static int plan_build(imdb_db *db, uint8_t kind, uint32_t ctable, uint64_t purge_before, const erased_set *es,
                      const imdb_lthash *post, const imdb_lthash *post_global, uint64_t seq, const uint8_t prev[32],
                      imdb_lake_plan **out, imdb_err *e)
{
    *out = NULL;
    imdb_lake_plan *p = imdb_alloc(sizeof *p, e);
    if (!p) return e->code;
    p->kind = kind;
    p->seq = seq;
    imdb_buf_init(&p->manifest);
    p->tab = imdb_alloc_array(db->nt ? db->nt : 1, sizeof *p->tab, e);
    if (!p->tab) {
        free(p);
        return e->code;
    }
    p->nt = db->nt;
    int rc = IMDB_OK;
    uint64_t *vids = NULL;
    for (uint32_t ti = 0; ti < db->nt && !rc; ti++) {
        imdb_table *t = db->t[ti];
        plan_tab *pt = &p->tab[ti];
        pt->horizon = t->horizon;
        /* existing segments, rewritten if they hold rows being erased */
        for (uint32_t k = 0; k < t->nseg && !rc; k++) {
            imdb_segment *g = t->seg[k];
            bool hit = false;
            for (uint32_t i = 0; es && i < g->nrows && !hit; i++)
                hit = !(g->flags[i] & IMDB_SEG_STUB) && erased_has(es, ti, g->vid[i]);
            if (!hit) {
                rc = pt_push(pt, g, false, e);
                continue;
            }
            imdb_segment *ng;
            if ((rc = seg_build(t, g->vid, g->nrows, es, 0, &ng, e))) break;
            if ((rc = pt_push(pt, ng, true, e))) {
                imdb_segment_free(ng);
                break;
            }
            imdb_rewrite *nr = imdb_realloc_array(p->rw, p->nrw, p->nrw + 1, sizeof *nr, e);
            if (!nr) {
                rc = e->code;
                break;
            }
            p->rw = nr;
            p->rw[p->nrw].table = ti;
            memcpy(p->rw[p->nrw].old_hash, g->hash, 32);
            memcpy(p->rw[p->nrw].new_hash, ng->hash, 32);
            p->nrw++;
        }
        if (rc) break;
        /* flush the memtable */
        if (t->mem_first < t->nver) {
            uint64_t cnt = t->nver - t->mem_first;
            if (cnt > IMDB_MAX_SEGMENT_ROWS) {
                rc = imdb_fail(e, IMDB_ERR_LIMIT, "memtable of %s exceeds one segment; checkpoint more often", t->s.name);
                break;
            }
            free(vids);
            vids = imdb_alloc_array(cnt, sizeof *vids, e);
            if (!vids) {
                rc = e->code;
                break;
            }
            for (uint64_t i = 0; i < cnt; i++) vids[i] = t->mem_first + i;
            imdb_segment *ng;
            if ((rc = seg_build(t, vids, (uint32_t)cnt, es, 0, &ng, e))) break;
            if ((rc = pt_push(pt, ng, true, e))) {
                imdb_segment_free(ng);
                break;
            }
            pt->flushed = true;
        }
        /* compaction: merge every version into as few segments as the row limit
         * allows; versions ended at or before purge_before keep only a tombstone
         * (lake.h), so ERASE SUBJECT still reaches their payloads in the log */
        if (kind == IMDB_OP_COMPACT && ti == ctable) {
            uint64_t total = 0;
            for (uint32_t k = 0; k < pt->nseg; k++) total += pt->seg[k]->nrows;
            free(vids);
            vids = imdb_alloc_array(total ? total : 1, sizeof *vids, e);
            if (!vids) {
                rc = e->code;
                break;
            }
            uint64_t m = 0;
            for (uint32_t k = 0; k < pt->nseg; k++) {
                const imdb_segment *g = pt->seg[k];
                for (uint32_t i = 0; i < g->nrows; i++) vids[m++] = g->vid[i]; /* disjoint, vid-ordered */
            }
            imdb_segment **merged = imdb_alloc_array(m / IMDB_MAX_SEGMENT_ROWS + 1, sizeof *merged, e);
            if (!merged) {
                rc = e->code;
                break;
            }
            uint32_t nm = 0;
            for (uint64_t at = 0; at < m && !rc; at += IMDB_MAX_SEGMENT_ROWS) {
                uint64_t cnt = m - at < IMDB_MAX_SEGMENT_ROWS ? m - at : IMDB_MAX_SEGMENT_ROWS;
                rc = seg_build(t, vids + at, (uint32_t)cnt, es, purge_before, &merged[nm], e);
                if (!rc) nm++;
            }
            for (uint32_t k = 0; k < pt->nseg; k++)
                if (pt->owned[k]) imdb_segment_free(pt->seg[k]);
            pt->nseg = 0;
            for (uint32_t k = 0; k < nm; k++) {
                if (!rc && !(rc = pt_push(pt, merged[k], true, e))) continue;
                imdb_segment_free(merged[k]); /* the one pt_push failed to take (it stays the caller's), and the rest */
            }
            free(merged);
            if (rc) break;
            pt->compacted = true;
            if (purge_before > pt->horizon) pt->horizon = purge_before;
        }
        /* deletion vectors as of seq */
        pt->dv = imdb_alloc_array(pt->nseg ? pt->nseg : 1, sizeof *pt->dv, e);
        if (!pt->dv) {
            rc = e->code;
            break;
        }
        for (uint32_t k = 0; k < pt->nseg; k++) {
            imdb_buf_init(&pt->dv[k]);
            dv_build(pt->seg[k], seq, &pt->dv[k]);
            if ((rc = imdb_buf_check(&pt->dv[k], e))) break;
        }
    }
    free(vids);
    if (rc) {
        plan_free(p);
        return rc;
    }
    if (p->nrw) qsort(p->rw, p->nrw, sizeof *p->rw, cmp_rw);
    /* manifest */
    imdb_buf *mb = &p->manifest;
    bool v3 = false; /* indexes make it version 3; without one, version 2 as before (lake.h) */
    for (uint32_t ti = 0; ti < db->nt; ti++) v3 |= db->t[ti]->nidx > 0;
    imdb_buf_put(mb, kManMagic, 8);
    imdb_buf_put_u32(mb, v3 ? 3 : 2);
    imdb_buf_put_u32(mb, db->nt);
    imdb_buf_put(mb, db->db_id, 16);
    imdb_buf_put_u64(mb, seq);
    imdb_buf_put(mb, prev, 32);
    uint8_t sd[32];
    imdb_lthash_digest(db->meta.digest_alg, post_global, sd);
    imdb_buf_put(mb, sd, 32);
    static const uint8_t none[32];
    imdb_buf_put(mb, kind == IMDB_OP_ERASE || !db->lake_seq ? none : db->lake_manifest, 32); /* GC's retained generation */
    imdb_buf sch;
    imdb_buf_init(&sch);
    for (uint32_t ti = 0; ti < db->nt; ti++) {
        imdb_table *t = db->t[ti];
        plan_tab *pt = &p->tab[ti];
        sch.len = 0;
        imdb_schema_encode(&t->s, &sch);
        if ((rc = imdb_buf_check(&sch, e))) break; /* an empty schema would be signed into the log */
        imdb_buf_put_u32(mb, (uint32_t)sch.len);
        imdb_buf_put(mb, sch.p, sch.len);
        imdb_buf_put_u64(mb, pt->horizon);
        imdb_buf_put_u64(mb, t->live);
        imdb_buf_put_u64(mb, t->nver);
        imdb_buf_put(mb, post[ti].v, IMDB_LTHASH_BYTES);
        imdb_buf_put_u32(mb, pt->nseg);
        for (uint32_t k = 0; k < pt->nseg; k++) {
            imdb_buf_put(mb, pt->seg[k]->hash, 32);
            uint8_t dh[32] = {0};
            if (pt->dv[k].len) imdb_sha256(pt->dv[k].p, pt->dv[k].len, dh);
            imdb_buf_put(mb, dh, 32);
            imdb_buf_put_u32(mb, pt->seg[k]->nrows);
        }
        if (v3) {
            imdb_buf_put_u32(mb, t->nidx);
            for (uint32_t k = 0; k < t->nidx; k++) {
                const imdb_index_def *d = &t->idx[k].d;
                size_t nl = strlen(d->name);
                imdb_buf_put_u8(mb, (uint8_t)nl);
                imdb_buf_put(mb, d->name, nl);
                imdb_buf_put_u8(mb, d->flags);
                imdb_buf_put_u8(mb, d->ncols);
                for (uint8_t c = 0; c < d->ncols; c++) imdb_buf_put_u16(mb, d->cols[c]);
            }
        }
    }
    imdb_buf_free(&sch);
    if (rc || (rc = imdb_buf_check(mb, e))) {
        plan_free(p);
        return rc;
    }
    imdb_sha256(mb->p, mb->len, p->mhash);
    *out = p;
    return IMDB_OK;
}

/* ---- install / persist ------------------------------------------------------- */

/* Swaps the planned segments in; afterwards the table owns them. */
static int plan_install(imdb_db *db, imdb_lake_plan *p, imdb_err *e)
{
    for (uint32_t ti = 0; ti < p->nt; ti++) {
        imdb_table *t = db->t[ti];
        plan_tab *pt = &p->tab[ti];
        /* versions this plan purges leave their key chains now, while the key is
         * still readable from their old location (a tombstone keeps no key) */
        for (uint32_t k = 0; pt->compacted && k < pt->nseg; k++) {
            const imdb_segment *g = pt->seg[k];
            for (uint32_t i = 0; i < g->nrows; i++) {
                if (!(g->flags[i] & IMDB_SEG_PURGED) || (t->ver[g->vid[i]].flags & (IMDB_V_PURGED | IMDB_V_STUB))) continue;
                imdb_value key;
                if (imdb_version_key(t, g->vid[i], t->s.pk, &key) == IMDB_OK) imdb_pk_unlink(t, g->vid[i], &key);
            }
        }
        imdb_segment **ns = imdb_alloc_array(pt->nseg ? pt->nseg : 1, sizeof *ns, e);
        if (!ns) {
            db->failed = true; /* earlier tables are already swapped: fail-stop, replay rebuilds */
            return e->code;
        }
        /* old segments not carried over are freed */
        for (uint32_t k = 0; k < t->nseg; k++) {
            bool kept = false;
            for (uint32_t j = 0; j < pt->nseg && !kept; j++) kept = pt->seg[j] == t->seg[k];
            if (!kept) imdb_segment_free(t->seg[k]);
        }
        free(t->seg);
        t->seg = ns;
        t->nseg = t->capseg = pt->nseg;
        for (uint32_t k = 0; k < pt->nseg; k++) {
            t->seg[k] = pt->seg[k];
            pt->owned[k] = false;
            if (pt->dv[k].len) imdb_sha256(pt->dv[k].p, pt->dv[k].len, t->seg[k]->dv_hash);
            else memset(t->seg[k]->dv_hash, 0, 32);
        }
        if (pt->flushed) {
            imdb_buf_wipe_free(&t->arena);
            imdb_buf_init(&t->arena);
            t->mem_first = t->nver;
        }
        /* map every version to its (possibly new) location */
        for (uint64_t vid = 0; vid < t->nver; vid++) t->ver[vid].flags &= (uint8_t)~IMDB_V_SEG;
        for (uint32_t k = 0; k < t->nseg; k++) {
            imdb_segment *g = t->seg[k];
            for (uint32_t i = 0; i < g->nrows; i++) {
                imdb_version *v = &t->ver[g->vid[i]];
                v->flags |= IMDB_V_SEG;
                v->seg = k;
                v->seg_row = i;
                if ((g->flags[i] & IMDB_SEG_PURGED) && !(v->flags & IMDB_V_PURGED)) {
                    /* purged now: its tombstone keeps vid, begin, commitment, subject */
                    v->flags |= IMDB_V_PURGED;
                    imdb_wipe(v->salt, sizeof v->salt);
                    v->row_len = 0;
                }
            }
        }
        if (pt->compacted) {
            bool purged = pt->horizon > t->horizon;
            if (purged) t->ended = 0; /* automatic retention counts afresh */
            t->horizon = pt->horizon;
            if (purged) imdb_index_rebuild_table(db, t); /* the purged versions leave the indexes */
        }
    }
    free(db->lake_mbytes);
    db->lake_mbytes = p->manifest.p;
    db->lake_mlen = p->manifest.len;
    imdb_buf_init(&p->manifest);
    memcpy(db->lake_manifest, p->mhash, 32);
    db->lake_seq = p->seq;
    db->lake_dirty = false;
    return IMDB_OK;
}

static int open_objects(imdb_db *db, imdb_err *e)
{
    int fd = imdb_open_dir_at(db->dirfd, "objects", e);
    return fd < 0 ? -1 : fd;
}

/* Ensures objects/<hash><ext> holds exactly these bytes. An existing file is
 * read back and compared: the engine holds the authoritative bytes (rebuilt
 * from the log), so a corrupted or truncated object is repaired here. */
static int obj_put(imdb_db *db, int ofd, const uint8_t h[32], const char *ext, const uint8_t *p, size_t n, imdb_err *e)
{
    char name[80];
    obj_name(h, ext, name);
    struct stat st;
    if (imdb_io_fstatat(ofd, name, &st, AT_SYMLINK_NOFOLLOW) == 0) {
        if (S_ISREG(st.st_mode) && (size_t)st.st_size == n) {
            uint8_t *cur;
            size_t len;
            imdb_err e2 = {0};
            bool same = imdb_read_file_at(ofd, name, &cur, &len, IMDB_MAX_OBJECT, &e2) == IMDB_OK && len == n &&
                        memcmp(cur, p, n) == 0;
            if (!e2.code) free(cur);
            if (same) return IMDB_OK;
        }
        snprintf(db->warning, sizeof db->warning, "repaired lake object %s (it did not match the log)", name);
        return imdb_write_file_atomic(ofd, name, p, n, 0600, e);
    }
    return imdb_create_file_excl(ofd, name, p, n, 0600, e);
}

static int write_head(imdb_db *db, imdb_err *e)
{
    char hex[65], buf[200];
    imdb_hex(db->lake_manifest, 32, hex);
    int n = snprintf(buf, sizeof buf, "imagedb-lake 1\nseq %llu\nmanifest %s\n", (unsigned long long)db->lake_seq, hex);
    return imdb_write_file_atomic(db->dirfd, "LAKE_HEAD", buf, (size_t)n, 0600, e);
}

static bool manifest_refs(const imdb_manifest *m, const uint8_t h[32])
{
    for (uint32_t ti = 0; ti < m->nt; ti++)
        for (uint32_t k = 0; k < m->t[ti].nseg; k++)
            if (memcmp(h, m->t[ti].seg[k].seg, 32) == 0 || memcmp(h, m->t[ti].seg[k].dv, 32) == 0) return true;
    return false;
}

static bool pinned_refs(const pinset *P, const uint8_t h[32])
{
    for (size_t i = 0; i < P->n; i++)
        if (P->p[i].kept && (memcmp(h, P->p[i].h, 32) == 0 || manifest_refs(&P->p[i].m, h))) return true;
    return false;
}

/* Deletes every object not referenced by the current manifest (and, when keep is given, by that
 * previous manifest: one generation of retention for lake readers that are mid-snapshot), nor by a
 * generation a reader pins (lake.h). Manifests go first, so a reader arriving at a generation
 * that is going fails at once; the stale pins GC holds go last. */
static int lake_gc(imdb_db *db, int ofd, const uint8_t *keep, size_t keeplen, imdb_err *e)
{
    imdb_manifest cur, old;
    memset(&old, 0, sizeof old);
    if (imdb_manifest_parse(db->lake_mbytes, db->lake_mlen, &cur, e)) return e->code;
    if (keep && imdb_manifest_parse(keep, keeplen, &old, e)) {
        imdb_manifest_free(&cur);
        return e->code;
    }
    uint8_t old_hash[32] = {0};
    if (keep) imdb_sha256(keep, keeplen, old_hash);
    pinset P;
    pins_collect(db, ofd, &P);
    int rc = IMDB_OK;
    int dfd = dup(ofd); /* one stream, rewound: a second dup would share the first one's offset */
    DIR *d = dfd >= 0 ? imdb_io_fdopendir(dfd) : NULL;
    if (!d) {
        if (dfd >= 0) close(dfd);
        rc = imdb_fail(e, IMDB_ERR_IO, "objects: cannot list directory");
    }
    for (int pass = 0; d && pass < 2; pass++) { /* manifests, then everything else */
        if (pass) rewinddir(d);
        for (;;) {
            errno = 0;
            struct dirent *de = imdb_io_readdir(d);
            if (!de) {
                if (errno && !rc) rc = imdb_fail(e, IMDB_ERR_IO, "objects: directory read failed: %s", strerror(errno));
                break;
            }
            if (de->d_name[0] == '.') continue;
            uint8_t h[32];
            bool valid = imdb_object_name_valid(de->d_name) && imdb_unhex(de->d_name, 64, h, 32);
            if (valid && (strcmp(de->d_name + 64, ".man") == 0) != (pass == 0)) continue;
            if (!valid && pass == 0) continue;
            bool ref = valid && (memcmp(h, db->lake_manifest, 32) == 0 || manifest_refs(&cur, h) ||
                                 (keep && (memcmp(h, old_hash, 32) == 0 || manifest_refs(&old, h))) ||
                                 pinned_refs(&P, h));
            /* one failure must not stop the rest: after an ERASE every other file may hold erased rows */
            if (!ref && imdb_io_unlinkat(ofd, de->d_name, 0) != 0 && !rc)
                rc = imdb_fail(e, IMDB_ERR_IO, "objects: cannot remove unreferenced file: %s", strerror(errno));
        }
    }
    if (d) closedir(d);
    /* the stale pins, still held exclusively: a reader that locked one meanwhile finds its name gone */
    int pfd = P.n ? imdb_io_openat(db->dirfd, IMDB_PINS_DIR, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW) : -1;
    for (size_t i = 0; pfd >= 0 && i < P.n; i++)
        if (P.p[i].fd >= 0) (void)imdb_io_unlinkat(pfd, P.p[i].name, 0);
    if (pfd >= 0) close(pfd);
    pinset_free(&P);
    imdb_manifest_free(&cur);
    imdb_manifest_free(&old);
    imdb_err se = {0};
    int src = imdb_sync_dir(ofd, &se); /* the removals that did succeed must be durable too */
    if (!rc && src) rc = imdb_fail(e, se.code, "%s", se.msg);
    return rc;
}

/* Writes every object of the current lake state, LAKE_HEAD, then GC.
 * Invariant: LAKE_HEAD at seq S implies that every ERASE up to S has been
 * applied to the log files (snapshot open relies on it to skip the log
 * before S). So while a redaction is pending nothing is published; the
 * publication is retried once the log is redacted (imdb_lake_publish_pending). */
static int lake_persist(imdb_db *db, const uint8_t *keep, size_t keeplen, imdb_err *e)
{
    if (!db->lake_seq) return IMDB_OK;
    /* Pending until the objects and LAKE_HEAD are written (a successful log
     * rewrite alone does not publish anything). A replica withholds a lake whose
     * redactions no ERASE has authorised yet. */
    db->lake_pending = true;
    if (db->needs_redaction || db->pending_auth || db->lake_unverified) return IMDB_OK;
    int ofd = open_objects(db, e);
    if (ofd < 0) return e->code;
    int rc = IMDB_OK;
    imdb_buf dv;
    imdb_buf_init(&dv);
    for (uint32_t ti = 0; ti < db->nt && !rc; ti++) {
        imdb_table *t = db->t[ti];
        for (uint32_t k = 0; k < t->nseg && !rc; k++) {
            imdb_segment *g = t->seg[k];
            rc = obj_put(db, ofd, g->hash, ".seg", g->bytes, g->len, e);
            if (!rc && !all_zero(g->dv_hash, 32)) {
                dv_build(g, db->lake_seq, &dv);
                if (!(rc = imdb_buf_check(&dv, e))) rc = obj_put(db, ofd, g->dv_hash, ".dv", dv.p, dv.len, e);
            }
        }
    }
    if (!rc) rc = obj_put(db, ofd, db->lake_manifest, ".man", db->lake_mbytes, db->lake_mlen, e);
    if (!rc) rc = imdb_sync_dir(ofd, e);
    if (!rc) rc = imdb_log_sync(db, e); /* LAKE_HEAD must never name a commit the log could still lose */
    if (!rc) rc = write_head(db, e);
    if (!rc) {
        db->lake_pending = false;
        /* Published. Removing what no retained manifest references is cleanup: a
         * failure leaves files behind (VERIFY reports them, and after an ERASE they
         * may hold erased rows, so the ERASE stays pending), is retried at the next
         * publication and at open, and never makes either fail. */
        imdb_err ge = {0};
        db->gc_pending = lake_gc(db, ofd, keep, keeplen, &ge) != IMDB_OK;
        if (db->gc_pending)
            imdb_warn(db, "lake published at commit %llu, but old objects could not all be removed (%s); retried at the "
                      "next publication and at open", (unsigned long long)db->lake_seq, ge.msg);
    }
    imdb_buf_free(&dv);
    close(ofd);
    return rc;
}

/* The manifest being replaced becomes the retained previous generation; an
 * ERASE retains nothing. Tracked identically on primary, replicas and replay,
 * so GC (and therefore the set of object files) never depends on restarts. */
static void rotate_prev(imdb_db *db, uint8_t *prev, size_t prevlen, bool erase)
{
    free(db->lake_prev);
    db->lake_prev = erase ? NULL : prev;
    db->lake_prevlen = erase ? 0 : prevlen;
    if (erase) free(prev);
}

/* ---- primary operations ------------------------------------------------------ */

static int lake_writable(imdb_db *db, imdb_err *e)
{
    if (db->failed) return imdb_fail(e, IMDB_ERR_STATE, "database is in a failed state; reopen it to recover");
    if (db->replica) return imdb_fail(e, IMDB_ERR_STATE, "replicas are read-only; lake changes arrive through apply");
    if (db->in_txn) return imdb_fail(e, IMDB_ERR_STATE, "lake operations run outside explicit transactions");
    if (db->read_only) return imdb_fail(e, IMDB_ERR_STATE, "database opened read-only");
    return IMDB_OK;
}

static int physical_commit(imdb_db *db, uint8_t kind, uint32_t table, uint64_t purge_before, imdb_err *e)
{
    if (lake_writable(db, e)) return e->code;
    imdb_lthash *post = imdb_alloc_aligned(db->nt ? db->nt : 1, sizeof *post, e);
    if (!post) return e->code;
    for (uint32_t i = 0; i < db->nt; i++) post[i] = db->t[i]->digest;
    imdb_lake_plan *p;
    int rc = plan_build(db, kind, table, purge_before, NULL, post, &db->global, db->seq + 1, db->head, &p, e);
    free(post);
    if (rc) return rc;
    /* write the new segments first: once the commit is durable the lake is complete */
    int ofd = open_objects(db, e);
    if (ofd < 0) {
        plan_free(p);
        return e->code;
    }
    for (uint32_t ti = 0; ti < p->nt && !rc; ti++)
        for (uint32_t k = 0; k < p->tab[ti].nseg && !rc; k++) {
            plan_tab *pt = &p->tab[ti];
            if (pt->owned[k]) rc = obj_put(db, ofd, pt->seg[k]->hash, ".seg", pt->seg[k]->bytes, pt->seg[k]->len, e);
        }
    if (!rc) rc = imdb_sync_dir(ofd, e);
    close(ofd);
    if (!rc) rc = imdb_begin(db, e);
    if (!rc) {
        rc = imdb_tx_add_physical(db, kind, table, purge_before, p->mhash, e);
        rc = rc ? rc : imdb_commit(db, e);
        if (rc && db->in_txn) imdb_rollback(db);
    }
    if (rc) {
        plan_free(p);
        return rc;
    }
    uint8_t *prev = db->lake_mbytes;
    size_t prevlen = db->lake_mlen;
    db->lake_mbytes = NULL;
    rc = plan_install(db, p, e);
    rotate_prev(db, prev, prevlen, false);
    if (!rc) rc = lake_persist(db, db->lake_prev, db->lake_prevlen, e);
    if (rc) {
        db->failed = true; /* committed; reopen rebuilds and rewrites the lake */
        db->lake_pending = true;
        snprintf(db->warning, sizeof db->warning,
                 "physical operation committed at %llu but lake publication failed (%s); reopen to recover",
                 (unsigned long long)db->seq, e->msg);
        imdb_err_clear(e);
        rc = IMDB_OK; /* retrying a committed operation as though it rolled back is unsafe */
    }
    else if (db->lake_pending)
        snprintf(db->warning, sizeof db->warning,
                 "lake state of commit %llu committed but not yet published: a log redaction is pending "
                 "(LAKE_HEAD moves once it completes)", (unsigned long long)db->lake_seq);
    plan_free(p);
    return rc;
}

int imdb_checkpoint(imdb_db *db, imdb_err *e)
{
    if (lake_writable(db, e)) return e->code;
    bool mem = false;
    for (uint32_t i = 0; i < db->nt; i++) mem |= db->t[i]->mem_first < db->t[i]->nver;
    if (db->lake_seq && !db->lake_dirty && !mem) return IMDB_OK; /* nothing new since the last manifest */
    if (!db->nt) return IMDB_OK;
    return physical_commit(db, IMDB_OP_CHECKPOINT, 0, 0, e);
}

int imdb_compact(imdb_db *db, imdb_table *t, uint64_t purge_before, imdb_err *e)
{
    if (purge_before > db->seq)
        return imdb_fail(e, IMDB_ERR_INVALID, "PURGE BEFORE %llu is in the future", (unsigned long long)purge_before);
    if (purge_before && purge_before < t->horizon) purge_before = t->horizon;
    return physical_commit(db, IMDB_OP_COMPACT, t->s.id, purge_before, e);
}

int imdb_lake_plan_erase(imdb_db *db, const imdb_erase_ent *ents, uint32_t n, imdb_rewrite **rw, uint32_t *nrw,
                         uint8_t manifest[32], imdb_err *e)
{
    *rw = NULL;
    *nrw = 0;
    /* post-commit digests: this transaction's pending DELETEs */
    imdb_lthash *post = imdb_alloc_aligned(db->nt ? db->nt : 1, sizeof *post, e);
    imdb_lthash *delta = imdb_alloc_aligned(db->nt ? db->nt : 1, sizeof *delta, e);
    bool *touched = imdb_alloc_array(db->nt ? db->nt : 1, sizeof *touched, e);
    int rc = (!post || !delta || !touched) ? e->code : imdb_digest_delta(db->meta.digest_alg, db->tx, db->ntx, db->nt, delta, touched, e);
    imdb_lthash global = db->global;
    for (uint32_t t = 0; !rc && t < db->nt; t++) {
        post[t] = db->t[t]->digest;
        if (touched[t]) {
            imdb_lthash_add(&post[t], &delta[t]);
            imdb_lthash_add(&global, &delta[t]);
        }
    }
    erased_set es = {ents, n};
    imdb_lake_plan *p = NULL;
    if (!rc) rc = plan_build(db, IMDB_OP_ERASE, 0, 0, &es, post, &global, db->seq + 1, db->head, &p, e);
    free(post);
    free(delta);
    free(touched);
    if (rc) return rc;
    if (p->nrw) {
        *rw = imdb_alloc_array(p->nrw, sizeof **rw, e);
        if (!*rw) {
            plan_free(p);
            return e->code;
        }
        memcpy(*rw, p->rw, p->nrw * sizeof **rw);
        *nrw = p->nrw;
    }
    memcpy(manifest, p->mhash, 32);
    plan_free(db->erase_plan);
    db->erase_plan = p;
    return IMDB_OK;
}

int imdb_lake_after_erase(imdb_db *db, imdb_err *e)
{
    imdb_lake_plan *p = db->erase_plan;
    if (!p) return IMDB_OK;
    db->erase_plan = NULL;
    uint8_t *prev = db->lake_mbytes;
    size_t prevlen = db->lake_mlen;
    db->lake_mbytes = NULL;
    int rc = plan_install(db, p, e);
    /* no retention after an erasure: older snapshots reference erased bytes */
    rotate_prev(db, prev, prevlen, true);
    if (!rc) rc = lake_persist(db, NULL, 0, e);
    plan_free(p);
    return rc;
}

/* ---- replay ------------------------------------------------------------------- */

int imdb_lake_apply_physical(imdb_db *db, const imdb_commit_rec *c, const imdb_op *op, const imdb_lthash *post,
                             const imdb_lthash *post_global, imdb_err *e)
{
    erased_set es = {op->erase, op->n_erase};
    imdb_lake_plan *p;
    int rc = plan_build(db, op->code, op->table, op->purge_before, op->code == IMDB_OP_ERASE ? &es : NULL, post,
                        post_global, c->seq, c->prev, &p, e);
    if (rc) return rc;
    if (memcmp(p->mhash, op->manifest, 32) != 0) {
        if (!db->pending_auth) {
            plan_free(p);
            return imdb_fail(e, IMDB_ERR_VERIFY,
                             "commit %llu: rebuilt lake does not match the recorded manifest (physical divergence)",
                             (unsigned long long)c->seq);
        }
        /* rows erased by a later ERASE are already stubs here, so this
         * manifest cannot be reproduced; that ERASE's manifest re-checks it */
        db->lake_unverified = true;
    } else if (!db->pending_auth) {
        db->lake_unverified = false;
    }
    uint8_t *prev = db->lake_mbytes;
    size_t prevlen = db->lake_mlen;
    db->lake_mbytes = NULL;
    rc = plan_install(db, p, e);
    rotate_prev(db, prev, prevlen, op->code == IMDB_OP_ERASE);
    /* Stream apply validates and installs before appending its frame. The
     * caller publishes only after that append; replay publishes at open's end. */
    if (!rc && !db->replaying && !db->read_only) db->lake_pending = true;
    plan_free(p);
    return rc;
}

static int read_head(imdb_db *db, bool *present, uint64_t *seq, uint8_t mh[32], imdb_err *e);

/* The log publishes no manifest, so no lake may be published: a LAKE_HEAD left by commits a
 * crash took from a --nosync log, and the objects of a publication that never completed, are
 * removed. Like GC, a failure here is cleanup (gc_pending and a warning), never an open error. */
static int lake_clear(imdb_db *db, imdb_err *e)
{
    (void)e;
    bool present = false;
    uint64_t s = 0;
    uint8_t mh[32];
    imdb_err ge = {0};
    int rc = read_head(db, &present, &s, mh, &ge);
    if (!rc && present && (imdb_io_unlinkat(db->dirfd, "LAKE_HEAD", 0) != 0 || imdb_sync_dir(db->dirfd, &ge)))
        rc = imdb_fail(&ge, IMDB_ERR_IO, "LAKE_HEAD: cannot remove: %s", strerror(errno));
    int ofd = rc ? -1 : imdb_io_openat(db->dirfd, "objects", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    int dfd = ofd >= 0 ? dup(ofd) : -1;
    DIR *d = dfd >= 0 ? imdb_io_fdopendir(dfd) : NULL;
    if (!d && dfd >= 0) close(dfd);
    bool removed = false;
    for (struct dirent *de; d && (de = imdb_io_readdir(d));) {
        if (de->d_name[0] == '.') continue;
        if (imdb_io_unlinkat(ofd, de->d_name, 0) != 0) {
            if (!rc) rc = imdb_fail(&ge, IMDB_ERR_IO, "objects: cannot remove a file no manifest names: %s", strerror(errno));
        } else {
            removed = true;
        }
    }
    if (d) closedir(d);
    if (removed && imdb_sync_dir(ofd, &ge) && !rc) rc = ge.code;
    if (ofd >= 0) close(ofd);
    db->gc_pending = rc != IMDB_OK;
    if (rc) imdb_warn(db, "the log publishes no lake, but old lake files could not all be removed (%s)", ge.msg);
    return IMDB_OK;
}

/* A writable open completes the last logged publish: objects, LAKE_HEAD, then
 * GC. After a crash between LAKE_HEAD and GC this removes the generation GC
 * never reached (after an ERASE: segments that still hold the erased rows). */
int imdb_lake_finish_open(imdb_db *db, imdb_err *e)
{
    if (!db->lake_seq) return lake_clear(db, e);
    return lake_persist(db, db->lake_prev, db->lake_prevlen, e);
}

/* Not for a GC that failed after its publication: lake_persist re-reads every
 * object, and a replica calls this after each applied commit. GC is retried
 * by the next publication and by open instead. */
int imdb_lake_publish_pending(imdb_db *db, imdb_err *e)
{
    if (!db->lake_pending || db->needs_redaction || db->read_only) return IMDB_OK;
    return lake_persist(db, db->lake_prev, db->lake_prevlen, e);
}

int imdb_lake_open(imdb_db *db, imdb_err *e)
{
    (void)db;
    (void)e;
    return IMDB_OK;
}

void imdb_lake_db_free(imdb_db *db)
{
    plan_free(db->erase_plan);
    db->erase_plan = NULL;
    free(db->lake_mbytes);
    db->lake_mbytes = NULL;
    free(db->lake_prev);
    db->lake_prev = NULL;
}

void imdb_lake_table_free(imdb_table *t)
{
    for (uint32_t k = 0; k < t->nseg; k++) imdb_segment_free(t->seg[k]);
    free(t->seg);
    t->seg = NULL;
    t->nseg = 0;
}

/* ---- version access -------------------------------------------------------------- */

int imdb_seg_values(imdb_table *t, const imdb_version *v, imdb_value *vals, imdb_err *e)
{
    if (v->seg >= t->nseg) return imdb_fail(e, IMDB_ERR_STATE, "version maps to a missing segment");
    for (uint32_t c = 0; c < t->s.ncols; c++) seg_get(&t->s, t->seg[v->seg], v->seg_row, c, &vals[c]);
    return IMDB_OK;
}

int imdb_seg_value(imdb_table *t, const imdb_version *v, int col, imdb_value *out)
{
    if (v->seg >= t->nseg) return IMDB_ERR_STATE;
    seg_get(&t->s, t->seg[v->seg], v->seg_row, (uint32_t)col, out);
    return IMDB_OK;
}

void imdb_seg_set_end(imdb_table *t, const imdb_version *v, uint64_t end)
{
    if ((v->flags & IMDB_V_SEG) && v->seg < t->nseg) t->seg[v->seg]->end[v->seg_row] = end;
}

/* ---- verification of the on-disk lake ------------------------------------------- */

static int read_obj(int ofd, const uint8_t h[32], const char *ext, uint8_t **out, size_t *len, imdb_err *e)
{
    char name[80];
    obj_name(h, ext, name);
    if (imdb_read_file_at(ofd, name, out, len, IMDB_MAX_OBJECT, e)) return e->code;
    uint8_t got[32];
    imdb_sha256(*out, *len, got);
    if (memcmp(got, h, 32) != 0) {
        free(*out);
        *out = NULL;
        return imdb_fail(e, IMDB_ERR_VERIFY, "lake: object %s does not hash to its name", name);
    }
    return IMDB_OK;
}

/* For VERIFY, which checks the files against its own log-derived state. */
int imdb_lake_objects_open(imdb_db *db, imdb_err *e) { return open_objects(db, e); }

int imdb_lake_read_object(int ofd, const uint8_t h[32], const char *ext, uint8_t **out, size_t *len, imdb_err *e)
{
    return read_obj(ofd, h, ext, out, len, e);
}

/* ---- snapshot open ----------------------------------------------------------------- */

int imdb_lake_head(int dirfd, bool *present, uint64_t *seq, uint8_t mh[32], imdb_err *e)
{
    *present = false;
    if (faccessat(dirfd, "LAKE_HEAD", F_OK, AT_SYMLINK_NOFOLLOW) != 0) return IMDB_OK;
    uint8_t *b;
    size_t n;
    if (imdb_read_file_at(dirfd, "LAKE_HEAD", &b, &n, 256, e)) return e->code;
    static const char a[] = "imagedb-lake 1\nseq ";
    static const char m[] = "\nmanifest ";
    const char *s = (const char *)b;
    size_t i = sizeof a - 1, d0 = i;
    uint64_t v = 0;
    int rc = IMDB_OK;
    if (n < i || memcmp(s, a, i) != 0) rc = imdb_fail(e, IMDB_ERR_CORRUPT, "LAKE_HEAD: malformed");
    while (!rc && i < n && s[i] >= '0' && s[i] <= '9' && i - d0 < 19) v = v * 10 + (uint64_t)(s[i++] - '0');
    if (!rc && (i == d0 || (s[d0] == '0' && i - d0 > 1) || n - i != sizeof m - 1 + 64 + 1 ||
                memcmp(s + i, m, sizeof m - 1) != 0 || !imdb_unhex(s + i + sizeof m - 1, 64, mh, 32) || s[n - 1] != '\n'))
        rc = imdb_fail(e, IMDB_ERR_CORRUPT, "LAKE_HEAD: malformed");
    free(b);
    if (!rc) {
        *present = true;
        *seq = v;
    }
    return rc;
}

/* "imagedb-lake 1\nseq <n>\nmanifest <64 hex>\n", nothing else. */
static int read_head(imdb_db *db, bool *present, uint64_t *seq, uint8_t mh[32], imdb_err *e)
{
    return imdb_lake_head(db->dirfd, present, seq, mh, e);
}

/* The segment that holds a snapshot's commit, as the writer needs it when no replay follows it. */
typedef struct snap_seg {
    bool tagged, last;
    uint64_t next, size; /* tagged: the sector after its last group; the file's bytes */
} snap_seg;

/* Commit seq, which must be the last frame of its segment, decoded and its
 * signature checked. */
static int snapshot_commit(imdb_db *db, uint64_t seq, imdb_commit_rec *c, uint8_t **buf, size_t *len, snap_seg *ss,
                           imdb_err *e)
{
    size_t si = imdb_logseg_find(db->segs, db->nsegs, seq);
    if (si == db->nsegs) return imdb_fail(e, IMDB_ERR_STATE, "no log segment holds commit %llu", (unsigned long long)seq);
    if (si + 1 < db->nsegs && db->segs[si + 1] != seq + 1)
        return imdb_fail(e, IMDB_ERR_STATE, "commit %llu does not end its segment", (unsigned long long)seq);
    imdb_logseg seg;
    if (imdb_logseg_load(db->logdirfd, db->segs[si], &seg, e)) return e->code;
    ss->tagged = seg.tagged;
    ss->last = si + 1 == db->nsegs;
    ss->next = seg.end.next;
    ss->size = seg.size;
    *buf = seg.buf; /* the caller frees it; its bytes past the frames are already wiped */
    *len = seg.len;
    size_t off = 0, last = SIZE_MAX, lastlen = 0;
    for (;;) {
        size_t flen = 0;
        imdb_err e2 = {0};
        if (imdb_logseg_scan(&seg, off, &flen, &e2) != IMDB_SCAN_FRAME) break;
        last = off;
        lastlen = flen;
        off += flen;
    }
    if (last == SIZE_MAX || off != *len || seg.tail != IMDB_SCAN_END || imdb_frame_seq(*buf + last) != seq)
        return imdb_fail(e, IMDB_ERR_STATE, "commit %llu is not the last frame of its segment", (unsigned long long)seq);
    if (imdb_frame_decode_body(*buf + last + IMDB_FRAME_HDR, lastlen - IMDB_FRAME_HDR, c, e)) return e->code;
    if (c->alg != db->meta.digest_alg)
        return imdb_fail(e, IMDB_ERR_CORRUPT, "commit %llu: digest algorithm %u, but this database's is %u",
                         (unsigned long long)seq, c->alg, db->meta.digest_alg);
    if (c->promote || !imdb_commit_sig_valid(imdb_writer_key_at(db, seq), c->seq, c->hlen, c->hash, c->sig))
        return imdb_fail(e, IMDB_ERR_AUTH, "commit %llu: signature invalid (under the writer key of epoch %u)",
                         (unsigned long long)seq, imdb_writer_epoch_at(db, seq));
    return IMDB_OK;
}

static int load_table(imdb_db *db, int ofd, const imdb_manifest_tab *mt, uint32_t ti, uint64_t seq, imdb_err *e)
{
    imdb_schema s = mt->s;
    if (imdb_table_new(db, &s, e)) return e->code;
    imdb_table *t = db->t[ti];
    t->horizon = mt->horizon;
    t->digest = mt->digest;
    memcpy(t->idx, mt->idx, sizeof t->idx);
    t->nidx = mt->nidx;
    if (mt->nseg) {
        t->seg = imdb_alloc_array(mt->nseg, sizeof *t->seg, e);
        if (!t->seg) return e->code;
        t->capseg = mt->nseg;
    }
    for (uint32_t k = 0; k < mt->nseg; k++) {
        uint8_t *sb;
        size_t sl;
        if (read_obj(ofd, mt->seg[k].seg, ".seg", &sb, &sl, e)) return e->code;
        uint8_t *al = imdb_alloc_aligned(1, sl, e);
        if (!al) {
            free(sb);
            return e->code;
        }
        memcpy(al, sb, sl);
        imdb_wipe(sb, sl);
        free(sb);
        imdb_segment *g;
        if (imdb_segment_parse(&t->s, al, sl, &g, e)) {
            free(al);
            return e->code;
        }
        t->seg[t->nseg++] = g;
        if (g->nrows != mt->seg[k].nrows) return imdb_fail(e, IMDB_ERR_CORRUPT, "snapshot: segment row count");
        if (!all_zero(mt->seg[k].dv, 32)) {
            uint8_t *dvb, sh[32];
            size_t dl;
            imdb_dv_ent *ents;
            uint32_t n;
            if (read_obj(ofd, mt->seg[k].dv, ".dv", &dvb, &dl, e)) return e->code;
            int rc = imdb_dv_parse(dvb, dl, sh, &ents, &n, g->nrows, e);
            free(dvb);
            if (rc) return rc;
            for (uint32_t i = 0; i < n && !rc; i++) {
                if (ents[i].end > seq) rc = imdb_fail(e, IMDB_ERR_CORRUPT, "snapshot: DV records a later delete");
                else g->end[ents[i].row] = ents[i].end;
            }
            free(ents);
            if (rc) return rc;
            if (memcmp(sh, g->hash, 32) != 0) return imdb_fail(e, IMDB_ERR_CORRUPT, "snapshot: DV names another segment");
            memcpy(g->dv_hash, mt->seg[k].dv, 32);
        }
    }
    /* every version of the table is in exactly one segment (tombstones included) */
    if (mt->versions > IMDB_MAX_ALLOC / sizeof *t->ver) return imdb_fail(e, IMDB_ERR_LIMIT, "snapshot: too many versions");
    t->ver = imdb_alloc_array(mt->versions ? mt->versions : 1, sizeof *t->ver, e);
    uint8_t *seen = imdb_alloc(mt->versions / 8 + 1, e);
    if (!t->ver || !seen) {
        free(seen);
        return e->code;
    }
    t->capver = mt->versions ? mt->versions : 1;
    t->nver = mt->versions;
    int rc = IMDB_OK;
    uint64_t live = 0;
    for (uint32_t k = 0; k < t->nseg && !rc; k++) {
        const imdb_segment *g = t->seg[k];
        for (uint32_t i = 0; i < g->nrows && !rc; i++) {
            uint64_t vid = g->vid[i];
            if (vid >= t->nver || (seen[vid >> 3] & (1u << (vid & 7))) || g->begin[i] > seq) {
                rc = imdb_fail(e, IMDB_ERR_CORRUPT, "snapshot: segments do not hold each version once");
                break;
            }
            seen[vid >> 3] |= (uint8_t)(1u << (vid & 7));
            imdb_version *v = &t->ver[vid];
            v->begin = g->begin[i];
            v->end = g->end[i];
            v->pk_prev = IMDB_NONE;
            v->seg = k;
            v->seg_row = i;
            v->flags = IMDB_V_SEG | ((g->flags[i] & IMDB_SEG_STUB) ? IMDB_V_STUB : 0) |
                       ((g->flags[i] & IMDB_SEG_PURGED) ? IMDB_V_PURGED : 0);
            if (!g->flags[i]) memcpy(v->salt, g->salt + 16u * i, 16);
            memcpy(v->commit, g->commit + 32u * i, 32);
            live += v->end == IMDB_LIVE;
        }
    }
    for (uint64_t vid = 0; !rc && vid < t->nver; vid++)
        if (!(seen[vid >> 3] & (1u << (vid & 7))))
            rc = imdb_fail(e, IMDB_ERR_CORRUPT, "snapshot: version %llu is in no segment", (unsigned long long)vid);
    free(seen);
    if (rc) return rc;
    if (live != mt->live) return imdb_fail(e, IMDB_ERR_CORRUPT, "snapshot: live count differs from the manifest");
    t->live = live;
    t->mem_first = t->nver;
    /* indexes in version order, as incremental insertion builds them */
    for (uint64_t vid = 0; vid < t->nver && !rc; vid++) {
        const imdb_version *v = &t->ver[vid];
        if (!(v->flags & (IMDB_V_STUB | IMDB_V_PURGED))) {
            rc = imdb_index_version(t, vid, NULL, e);
        } else if (!(v->flags & IMDB_V_STUB) && t->s.subject >= 0) {
            imdb_value sv; /* purged history: the tombstone names its subject */
            if (imdb_seg_value(t, v, t->s.subject, &sv) == IMDB_OK) rc = imdb_index_subject(t, vid, &sv, NULL, e);
        }
    }
    /* the unique chains from the live versions, before the log's tail is replayed (it is checked
     * against them); the ordered structures are built at the open's end */
    for (uint32_t k = 0; k < t->nidx && !rc; k++)
        if ((rc = imdb_index_unique_build(t, &t->idx[k], e)) == IMDB_ERR_CONSTRAINT)
            rc = imdb_fail(e, IMDB_ERR_CORRUPT, "snapshot: two live rows of table %s share a key of unique index %s",
                           t->s.name, t->idx[k].d.name);
    return rc;
}

int imdb_lake_load_snapshot(imdb_db *db, uint64_t *seq, bool *moved, imdb_err *e)
{
    *seq = 0;
    *moved = false;
    bool present;
    uint64_t S;
    uint8_t mh[32];
    if (read_head(db, &present, &S, mh, e)) return e->code;
    if (!present) return IMDB_OK;
    if (S == 0) return imdb_fail(e, IMDB_ERR_CORRUPT, "LAKE_HEAD names commit 0");
    int pin;
    if (imdb_lake_pin(db->dirfd, mh, &pin, e)) return e->code;
    int ofd = open_objects(db, e);
    if (ofd < 0) {
        imdb_lake_unpin(pin);
        return e->code;
    }
    uint8_t *mb = NULL, *cbuf = NULL, *pb = NULL;
    size_t ml = 0, clen = 0, pl = 0;
    imdb_manifest m;
    memset(&m, 0, sizeof m);
    imdb_commit_rec c;
    memset(&c, 0, sizeof c);
    snap_seg ss;
    memset(&ss, 0, sizeof ss);
    int rc = read_obj(ofd, mh, ".man", &mb, &ml, e);
    if (!rc) rc = imdb_manifest_parse(mb, ml, &m, e);
    if (!rc && (m.seq != S || memcmp(m.db_id, db->db_id, 16) != 0))
        rc = imdb_fail(e, IMDB_ERR_STATE, "snapshot: manifest names another commit or database");
    /* the manifest is authenticated by the signed commit that recorded it */
    if (!rc) rc = snapshot_commit(db, S, &c, &cbuf, &clen, &ss, e);
    bool recorded = false;
    for (uint32_t i = 0; !rc && i < c.nops; i++)
        recorded |= imdb_op_publishes_manifest(c.ops[i].code) && memcmp(c.ops[i].manifest, mh, 32) == 0;
    if (!rc && !recorded)
        rc = imdb_fail(e, IMDB_ERR_STATE, "snapshot: commit %llu does not record the manifest LAKE_HEAD names",
                       (unsigned long long)S);
    if (!rc && (memcmp(m.prev, c.prev, 32) != 0 || memcmp(m.state, c.digest, 32) != 0))
        rc = imdb_fail(e, IMDB_ERR_STATE, "snapshot: manifest disagrees with commit %llu", (unsigned long long)S);
    if (!rc && !all_zero(m.prev_manifest, 32)) rc = read_obj(ofd, m.prev_manifest, ".man", &pb, &pl, e);
    for (uint32_t ti = 0; !rc && ti < m.nt; ti++) rc = load_table(db, ofd, &m.t[ti], ti, S, e);
    if (!rc) {
        imdb_lthash sum;
        imdb_lthash_zero(&sum);
        for (uint32_t ti = 0; ti < db->nt; ti++) imdb_lthash_add(&sum, &db->t[ti]->digest);
        uint8_t d[32];
        imdb_lthash_digest(db->meta.digest_alg, &sum, d);
        if (memcmp(d, c.digest, 32) != 0) rc = imdb_fail(e, IMDB_ERR_STATE, "snapshot: table digests do not sum to commit %llu",
                                                         (unsigned long long)S);
        db->global = sum;
    }
    if (!rc) {
        /* the replay begins after this segment (commit S ends it): the format rule continues from it,
         * and if it is the last, the next append ends it from here as if it had been replayed
         * (log_new_segment: its fill goes) */
        db->log_tagged = ss.tagged;
        if (ss.last) {
            db->log_phys = ss.next;
            db->log_fill = ss.size;
            db->log_group = false;
        }
        db->seq = S;
        memcpy(db->head, c.hash, 32);
        db->last_hlen = c.hlen;
        memcpy(db->last_sig, c.sig, IMDB_SIG_LEN);
        db->last_time = c.time_us;
        db->ci_first = S;
        db->nci = 0;
        rc = imdb_ci_push(db, c.time_us, c.hash, c.digest, e);
    }
    if (!rc) {
        db->lake_seq = S;
        memcpy(db->lake_manifest, mh, 32);
        db->lake_mbytes = mb;
        db->lake_mlen = ml;
        mb = NULL;
        db->lake_prev = pb;
        db->lake_prevlen = pl;
        pb = NULL;
        db->lake_dirty = false;
        db->lake_unverified = false;
        *seq = S;
    }
    if (rc == IMDB_ERR_NOTFOUND) { /* an object went: did a newer generation replace this one? */
        bool now;
        uint64_t S2;
        uint8_t mh2[32];
        imdb_err e2 = {0};
        *moved = read_head(db, &now, &S2, mh2, &e2) == IMDB_OK && now && memcmp(mh2, mh, 32) != 0;
    }
    imdb_commit_free(&c);
    imdb_manifest_free(&m);
    if (cbuf) imdb_wipe(cbuf, clen);
    free(cbuf);
    free(mb);
    free(pb);
    close(ofd);
    imdb_lake_unpin(pin); /* the segments are in memory now: the files are no longer read */
    return rc;
}
