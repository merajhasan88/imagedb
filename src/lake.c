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

/* What an image holds in memory (imdb_segment_parse's allocations): the cache charges and credits exactly this. */
static uint64_t seg_img_bytes(const imdb_segment *g, const imdb_segimg *gi)
{
    return sizeof *gi + gi->len + (uint64_t)(g->nrows ? g->nrows : 1) * sizeof *gi->end +
           ((uint64_t)g->nrows + 63) / 64 * sizeof *gi->stubmask + sizeof *gi->stubmask;
}

static void seg_img_free(imdb_segimg *gi)
{
    if (!gi) return;
    if (gi->bytes) imdb_wipe(gi->bytes, gi->len); /* rows: whatever erasure later reaches them, no copy stays behind */
    imdb_free(gi->bytes);
    imdb_free(gi->end);
    imdb_free(gi->stubmask);
    imdb_free(gi);
}

/* g's image leaves memory (a trim, or g freed), crediting the cache it was charged to. Never inside an operation's
 * work on g: imdb_op_leave (the outermost) and the frees of a segment no table holds any more. */
static void seg_img_drop(imdb_segment *g)
{
    imdb_segimg *gi = g->img_;
    if (!gi) return;
    if (g->cache) g->cache->resident -= seg_img_bytes(g, gi);
    g->img_ = NULL;
    seg_img_free(gi);
}

/* the bytes g's image holds while resident (0 when it is not): tests bound an open's peak by them */
uint64_t imdb_seg_image_bytes(const imdb_segment *g)
{
    return g->img_ ? seg_img_bytes(g, g->img_) : 0;
}

/* g's image becomes the table's: charged to its cache (a trim may then drop it, once g is ondisk) */
static void seg_charge(imdb_segcache *c, imdb_segment *g)
{
    if (!c || g->cache || !g->img_) return;
    g->cache = c;
    g->touched = c->clock;
    c->resident += seg_img_bytes(g, g->img_);
    if (c->resident > c->peak) c->peak = c->resident;
}

void imdb_segment_free(imdb_segment *g)
{
    if (!g) return;
    seg_img_drop(g);
    imdb_free(g->ld_err); /* P2 S14: a failed load's error kept for its operation */
    imdb_free(g);
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

int imdb_segment_parse(const imdb_schema *s, uint8_t *b, size_t len, const uint8_t known[32], imdb_segment **out,
                       imdb_err *e)
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
    imdb_segimg *gi = imdb_alloc(sizeof *gi, e); /* apart from the descriptor: the cache drops it alone */
    if (!gi) {
        imdb_free(g);
        return e->code;
    }
    g->img_ = gi;
    g->table = table;
    g->nrows = n;
    gi->vid = (const uint64_t *)(const void *)sec[0];
    gi->begin = (const uint64_t *)(const void *)sec[1];
    gi->flags = sec[2];
    gi->salt = sec[3];
    gi->commit = sec[4];
    int rc = IMDB_OK;
    for (uint32_t i = 0; i < n && !rc; i++) {
        if (i && gi->vid[i] <= gi->vid[i - 1]) rc = imdb_fail(e, IMDB_ERR_CORRUPT, "segment: version ids not ascending");
        else if (gi->flags[i] > (IMDB_SEG_STUB | IMDB_SEG_PURGED)) rc = imdb_fail(e, IMDB_ERR_CORRUPT, "segment: bad row flags");
        else if (gi->flags[i] && !all_zero(gi->salt + 16u * i, 16)) rc = imdb_fail(e, IMDB_ERR_CORRUPT, "segment: erased or purged row keeps a salt");
        else if (gi->begin[i] == 0 || gi->begin[i] >= IMDB_LIVE) rc = imdb_fail(e, IMDB_ERR_CORRUPT, "segment: bad begin");
    }
    uint32_t k = 5;
    for (uint32_t c = 0; c < s->ncols && !rc; c++) {
        const imdb_column *col = &s->cols[c];
        imdb_segcol *sc = &gi->col[c];
        /* VALID follows the column's data; a row keeps a value only if it keeps the column and,
         * when NULLABLE, has its bit set: every other row holds zero data */
        const uint8_t *vb = NULL;
        if (nullable(col)) {
            uint32_t vk = k + (col->type == IMDB_T_TEXT ? 2 : 1);
            vb = sec[vk];
            if ((n & 7) && (vb[n >> 3] >> (n & 7)) != 0) rc = imdb_fail(e, IMDB_ERR_CORRUPT, "segment: VALID padding");
            for (uint32_t i = 0; i < n && !rc; i++)
                if (valid_bit(vb, i) && gi->flags[i])
                    rc = imdb_fail(e, IMDB_ERR_CORRUPT, "segment: erased or purged row marked VALID in column %s", col->name);
            sc->valid = vb;
        }
        if (is_int_col(col->type)) {
            sc->i64 = (const int64_t *)(const void *)sec[k++];
            int64_t lim = col->type == IMDB_T_DECIMAL ? imdb_pow10(col->precision) - 1 : 0;
            for (uint32_t i = 0; i < n && !rc; i++) {
                int64_t v = sc->i64[i];
                if (!seg_keeps(gi->flags[i], s, c) || (vb && !valid_bit(vb, i))) {
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
                if (sc->u8[i] > 1 || ((gi->flags[i] || (vb && !valid_bit(vb, i))) && sc->u8[i]))
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
                else if ((!seg_keeps(gi->flags[i], s, c) || (vb && !valid_bit(vb, i))) && z != a)
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
        imdb_segcol *sc = &gi->col[c];
        bool has = false, has_null = false;
        int64_t mn = 0, mx = 0;
        for (uint32_t i = 0; sc->valid && i < n; i++) has_null |= !gi->flags[i] && !valid_bit(sc->valid, i);
        if (s->cols[c].type != IMDB_T_TEXT)
            for (uint32_t i = 0; i < n; i++) {
                if (gi->flags[i] || (sc->valid && !valid_bit(sc->valid, i))) continue;
                int64_t v = sc->i64 ? sc->i64[i] : sc->u8[i];
                if (!has || v < mn) mn = v;
                if (!has || v > mx) mx = v;
                has = true;
            }
        if (z[0] != has || z[1] != has_null || !all_zero(z + 2, 6) || (int64_t)imdb_get_le64(z + 8) != mn ||
            (int64_t)imdb_get_le64(z + 16) != mx)
            rc = imdb_fail(e, IMDB_ERR_CORRUPT, "segment: zone map does not match data");
        g->zone[c].has = has;
        g->zone[c].has_null = has_null;
        g->zone[c].min = mn;
        g->zone[c].max = mx;
    }
    if (!rc) {
        gi->end = imdb_alloc_array(n ? n : 1, sizeof *gi->end, e);
        gi->stubmask = imdb_alloc_array((n + 63) / 64 + 1, sizeof *gi->stubmask, e);
        if (!gi->end || !gi->stubmask) rc = e->code;
        for (uint32_t i = 0; !rc && i < n; i++) {
            gi->end[i] = IMDB_LIVE;
            if (gi->flags[i]) gi->stubmask[i >> 6] |= 1ull << (i & 63);
        }
    }
    if (rc) {
        imdb_free(gi->end); /* the bytes stay the caller's */
        imdb_free(gi->stubmask);
        imdb_free(gi);
        imdb_free(g);
        return rc;
    }
    gi->bytes = b;
    gi->len = len;
    if (n) { /* the descriptor's vid range: rows are in vid order (checked above) */
        g->vid_first = gi->vid[0];
        g->vid_last = gi->vid[n - 1];
    }
    if (known) memcpy(g->hash, known, 32); /* checked by the caller against its name */
    else imdb_sha256(b, len, g->hash);
    *out = g;
    return IMDB_OK;
}

static void seg_get(const imdb_schema *s, const imdb_segimg *gi, uint32_t row, uint32_t c, imdb_value *v)
{
    memset(v, 0, sizeof *v);
    v->type = s->cols[c].type;
    v->scale = s->cols[c].scale;
    const imdb_segcol *sc = &gi->col[c];
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

void imdb_seg_get(const imdb_schema *s, const imdb_segimg *gi, uint32_t row, uint32_t c, imdb_value *v)
{
    seg_get(s, gi, row, c, v);
}

void imdb_seg_row_values(const imdb_schema *s, const imdb_segimg *gi, uint32_t row, imdb_value *vals)
{
    for (uint32_t c = 0; c < s->ncols; c++) seg_get(s, gi, row, c, &vals[c]);
}

int imdb_segment_row(const imdb_schema *s, const imdb_segimg *gi, uint32_t row, imdb_buf *out, imdb_err *e)
{
    imdb_value vals[IMDB_MAX_COLS];
    for (uint32_t c = 0; c < s->ncols; c++) seg_get(s, gi, row, c, &vals[c]);
    return imdb_row_encode(s, vals, out, e);
}

int imdb_segment_check_commitments(const imdb_schema *s, const imdb_segment *g, const imdb_segimg *gi, imdb_err *e)
{
    imdb_buf row;
    imdb_buf_init(&row);
    int rc = IMDB_OK;
    for (uint32_t i = 0; i < g->nrows && !rc; i++) {
        if (gi->flags[i]) continue;
        row.len = 0;
        if ((rc = imdb_segment_row(s, gi, i, &row, e))) break;
        uint8_t c[32];
        imdb_row_commit(s->id, gi->salt + 16u * i, row.p, row.len, c);
        if (memcmp(c, gi->commit + 32u * i, 32) != 0)
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

/* Where a row of a segment being built comes from (stage 3b): a row of a segment (g, r), read there whether the
 * store holds its version or not, or the memtable (g NULL: the store's version vid, which it always holds). A row
 * of a segment carries everything the new row needs: its flags are its version's (an ERASE rewrites the segments
 * of the versions it stubs, a purge those it purges, each in the same publish), and its end is current
 * (imdb_seg_set_end at every commit), so the lake rebuilds itself without the store. */
typedef struct seg_src { /* g: the row's segment image, pinned for the publish (NULL: the memtable) */
    const imdb_segimg *g;
    uint32_t r;
    uint64_t vid;
} seg_src;

static uint64_t src_begin(const imdb_table *t, const seg_src *s)
{
    return s->g ? s->g->begin[s->r] : imdb_vh(t, s->vid)->begin;
}

static uint64_t src_end(const imdb_table *t, const seg_src *s)
{
    return s->g ? s->g->end[s->r] : imdb_vh(t, s->vid)->end;
}

static const uint8_t *src_salt(const imdb_table *t, const seg_src *s)
{
    return s->g ? s->g->salt + 16u * s->r : imdb_vc(t, s->vid)->salt;
}

static const uint8_t *src_commit(const imdb_table *t, const seg_src *s)
{
    return s->g ? s->g->commit + 32u * s->r : imdb_vc(t, s->vid)->commit;
}

/* column c of a (non-stub) row */
static void src_get(const imdb_table *t, const seg_src *s, uint32_t c, imdb_value *v)
{
    if (s->g) {
        seg_get(&t->s, s->g, s->r, c, v);
        return;
    }
    const imdb_version *ver = imdb_vh(t, s->vid);
    imdb_row_get(&t->s, t->arena.p + ver->row_off, ver->row_len, (int)c, v);
}

/* Row flags of a version in a segment being built (lake.h): erased before or by this ERASE, purged before or by
 * this COMPACT ... PURGE. */
static uint8_t src_flags(const imdb_table *t, const seg_src *s, const erased_set *es, uint64_t purge_before)
{
    uint8_t f = s->g ? s->g->flags[s->r]
                     : (uint8_t)(((imdb_vh(t, s->vid)->flags & IMDB_V_STUB) ? IMDB_SEG_STUB : 0) |
                                 ((imdb_vh(t, s->vid)->flags & IMDB_V_PURGED) ? IMDB_SEG_PURGED : 0));
    uint8_t erased = erased_has(es, t->s.id, s->vid) ? IMDB_SEG_STUB : 0;
#ifdef IMDB_STORE_CHECKS
    /* the store agrees with the row it holds the version of; a replica stubs the ERASE's versions in the store before
     * this plan rewrites their rows, so the ERASE's own bit is on both sides */
    if (s->g && imdb_v_held(t, s->vid)) {
        const imdb_version *v = imdb_vh(t, s->vid);
        uint8_t held = (uint8_t)(((v->flags & IMDB_V_STUB) ? IMDB_SEG_STUB : 0) | ((v->flags & IMDB_V_PURGED) ? IMDB_SEG_PURGED : 0));
        if ((held | erased) != (f | erased) || v->end != s->g->end[s->r] || v->begin != s->g->begin[s->r])
            imdb_v_misuse(t, s->vid, "the store's flags, begin or end differ from its segment row's");
    }
#endif
    f |= erased;
    uint64_t end = src_end(t, s);
    if (purge_before && end != IMDB_LIVE && end <= purge_before) f |= IMDB_SEG_PURGED;
    return f;
}

/* g's marks from its image's ends: where an image's ends are first made (a build, the snapshot load); after, the
 * writes keep them (imdb_seg_set_end) */
static void seg_marks(imdb_segment *g, const imdb_segimg *gi)
{
    g->nended = 0;
    g->end_lo = UINT64_MAX;
    g->end_hi = 0;
    for (uint32_t i = 0; i < g->nrows; i++) {
        if (gi->end[i] == IMDB_LIVE) continue;
        g->nended++;
        if (gi->end[i] < g->end_lo) g->end_lo = gi->end[i];
        if (gi->end[i] > g->end_hi) g->end_hi = gi->end[i];
    }
}

/* the checked builds: g's marks agree with an image of it (the count exact, the bounds bounds) */
static void seg_marks_check(const imdb_segment *g, const imdb_segimg *gi)
{
#ifdef IMDB_STORE_CHECKS
    uint32_t n = 0;
    bool out = false;
    for (uint32_t i = 0; i < g->nrows; i++) {
        if (gi->end[i] == IMDB_LIVE) continue;
        n++;
        out = out || gi->end[i] < g->end_lo || gi->end[i] > g->end_hi;
    }
    if (n != g->nended || out) {
        fprintf(stderr, "imagedb: a segment's end marks disagree with its rows (%u ended, marks %u)\n", n, g->nended);
        abort();
    }
#else
    (void)g;
    (void)gi;
#endif
}

int64_t imdb_seg_ended_by(const imdb_segment *g, uint64_t b)
{
    if (!g->nended || g->end_lo > b) return 0;
    if (g->end_hi <= b) return g->nended;
    return -1;
}

/* RETIRE below b drops a row ended at or before b */
static bool ended_by(uint64_t end, uint64_t b)
{
    return end != IMDB_LIVE && end <= b;
}

/* every row of g (its image gi), as sources (n = g->nrows) */
static void src_rows(const imdb_segment *g, const imdb_segimg *gi, seg_src *out)
{
    for (uint32_t i = 0; i < g->nrows; i++) out[i] = (seg_src){gi, i, gi->vid[i]};
}

static int seg_build(const imdb_table *t, const seg_src *src, uint32_t n, const erased_set *es,
                     uint64_t purge_before, imdb_segment **out, imdb_err *e)
{
    const imdb_schema *s = &t->s;
    if (n > IMDB_MAX_SEGMENT_ROWS) return imdb_fail(e, IMDB_ERR_LIMIT, "segment would exceed %u rows", IMDB_MAX_SEGMENT_ROWS);
    uint8_t *fl = imdb_alloc(n ? n : 1, e);
    if (!fl) return e->code;
    for (uint32_t i = 0; i < n; i++) fl[i] = src_flags(t, &src[i], es, purge_before);
    uint64_t text_len[IMDB_MAX_COLS] = {0};
    for (uint32_t c = 0; c < s->ncols; c++) {
        if (s->cols[c].type != IMDB_T_TEXT) continue;
        for (uint32_t i = 0; i < n; i++) {
            if (!seg_keeps(fl[i], s, c)) continue;
            imdb_value v;
            src_get(t, &src[i], c, &v);
            text_len[c] += v.len;
        }
        if (text_len[c] > UINT32_MAX) {
            imdb_free(fl);
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
            imdb_free(fl);
            return imdb_fail(e, IMDB_ERR_LIMIT, "segment too large");
        }
        pos += (size_t)d[k].len;
    }
    uint8_t *b = imdb_alloc_aligned(1, pos, e);
    if (!b) {
        imdb_free(fl);
        return e->code;
    }
    memcpy(b, kSegMagic, 8);
    imdb_le32(b + 8, 2);
    imdb_le32(b + 12, s->id);
    if (schema_hash(s, b + 16, e)) {
        imdb_free(b);
        imdb_free(fl);
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
        const seg_src *si = &src[i];
        imdb_le64(b + off[0] + 8u * i, si->vid);
        imdb_le64(b + off[1] + 8u * i, src_begin(t, si));
        b[off[2] + i] = fl[i];
        if (!fl[i]) memcpy(b + off[3] + 16u * i, src_salt(t, si), 16);
        memcpy(b + off[4] + 32u * i, src_commit(t, si), 32);
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
                src_get(t, &src[i], c, &v);
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
                src_get(t, &src[i], c, &v);
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
    imdb_free(fl);
    /* Parse our own output: the encoder is always checked by the strict decoder. */
    imdb_segment *g;
    int rc = imdb_segment_parse(s, b, pos, NULL, &g, e); /* built here: hashed here */
    if (rc) {
        imdb_free(b);
        return rc;
    }
    imdb_segimg *gi = imdb_seg_pin(NULL, g, e); /* a segment just built: apart from any table, resident */
    for (uint32_t i = 0; i < n; i++) gi->end[i] = src_end(t, &src[i]);
    seg_marks(g, gi);
    *out = g;
    return IMDB_OK;
}

/* ---- deletion vectors ----------------------------------------------------- */

static void dv_build(const imdb_segment *g, const imdb_segimg *gi, uint64_t snap, imdb_buf *out)
{
    uint32_t cnt = 0;
    for (uint32_t i = 0; i < g->nrows; i++) cnt += gi->end[i] != IMDB_LIVE && gi->end[i] <= snap;
    out->len = 0;
    if (!cnt) return;
    imdb_buf_put(out, kDvMagic, 8);
    imdb_buf_put(out, g->hash, 32);
    imdb_buf_put_u32(out, cnt);
    imdb_buf_put_u32(out, 0);
    for (uint32_t i = 0; i < g->nrows; i++) {
        if (gi->end[i] == IMDB_LIVE || gi->end[i] > snap) continue;
        imdb_buf_put_u32(out, i);
        imdb_buf_put_u32(out, 0);
        imdb_buf_put_u64(out, gi->end[i]);
    }
}

/* The hash of the vector dv_build would make at snap (all zero: none), streamed: a publish needs only the hash, so
 * no buffer is made (lake_persist makes the bytes it writes, and checks them against this hash) */
static void dv_hash(const imdb_segment *g, const imdb_segimg *gi, uint64_t snap, uint8_t out[32])
{
    uint32_t cnt = 0;
    for (uint32_t i = 0; i < g->nrows; i++) cnt += gi->end[i] != IMDB_LIVE && gi->end[i] <= snap;
    memset(out, 0, 32);
    if (!cnt) return;
    imdb_sha256_ctx c;
    imdb_sha256_init(&c);
    uint8_t h[48];
    memcpy(h, kDvMagic, 8);
    memcpy(h + 8, g->hash, 32);
    imdb_le32(h + 40, cnt);
    imdb_le32(h + 44, 0);
    imdb_sha256_update(&c, h, sizeof h);
    for (uint32_t i = 0; i < g->nrows; i++) {
        if (gi->end[i] == IMDB_LIVE || gi->end[i] > snap) continue;
        uint8_t en[16];
        imdb_le32(en, i);
        imdb_le32(en + 4, 0);
        imdb_le64(en + 8, gi->end[i]);
        imdb_sha256_update(&c, en, sizeof en);
    }
    imdb_sha256_final(&c, out);
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
            imdb_free(v);
            return imdb_fail(e, IMDB_ERR_CORRUPT, "dv: bad entry");
        }
    }
    if (r.err || imdb_rd_left(&r)) {
        imdb_free(v);
        return imdb_fail(e, IMDB_ERR_CORRUPT, "dv: trailing or truncated");
    }
    *ents = v;
    *n = cnt;
    return IMDB_OK;
}

/* ---- manifest -------------------------------------------------------------- */

void imdb_manifest_free(imdb_manifest *m)
{
    for (uint32_t i = 0; i < m->nv; i++) imdb_viewdef_free(m->v[i].def); /* P2 S7 */
    imdb_free(m->v);
    for (uint32_t i = 0; i < m->nt; i++) imdb_free(m->t[i].seg);
    imdb_free(m->t);
    memset(m, 0, sizeof *m);
}

static int cmp_name_ptr(const void *a, const void *b) { return strcmp(*(const char *const *)a, *(const char *const *)b); }

/* index names unique across tables (sorted, so a hostile manifest cannot make this quadratic).
 * IMDB_ERR_CORRUPT, or the allocation's own error: a check that cannot run is never reported as
 * corruption */
static int manifest_index_names(const imdb_manifest *m, imdb_err *e)
{
    size_t n = 0;
    for (uint32_t i = 0; i < m->nt; i++) n += m->t[i].dropped_at ? 0 : m->t[i].nidx; /* a dropped table's names are free */
    if (!n) return IMDB_OK;
    const char **p = imdb_alloc_array(n, sizeof *p, e);
    if (!p) return e->code;
    size_t k = 0;
    for (uint32_t i = 0; i < m->nt; i++)
        for (uint32_t j = 0; !m->t[i].dropped_at && j < m->t[i].nidx; j++) p[k++] = m->t[i].idx[j].d.name;
    qsort(p, n, sizeof *p, cmp_name_ptr);
    bool dup = false;
    for (size_t i = 1; i < n && !dup; i++) dup = strcmp(p[i - 1], p[i]) == 0;
    imdb_free(p);
    return dup ? IMDB_ERR_CORRUPT : IMDB_OK;
}

/* a manifest of an older format, refused by name (no reader is kept for one before the format freeze) */
/* P2 S7: a manifest's views against its tables: each live view's name is no other live relation's (sorted, so a
 * hostile manifest cannot make this quadratic), each live view names only live tables and live earlier views.
 * IMDB_ERR_CORRUPT, or the allocation's own error */
static int manifest_views_ok(const imdb_manifest *m, imdb_err *e)
{
    size_t n = 0;
    for (uint32_t i = 0; i < m->nt; i++) n += !m->t[i].dropped_at;
    for (uint32_t i = 0; i < m->nv; i++) n += !m->v[i].dropped_at;
    const char **p = imdb_alloc_array(n ? n : 1, sizeof *p, e);
    if (!p) return e->code;
    size_t k = 0;
    for (uint32_t i = 0; i < m->nt; i++)
        if (!m->t[i].dropped_at) p[k++] = m->t[i].s.name;
    int rc = IMDB_OK;
    for (uint32_t i = 0; i < m->nv && !rc; i++) {
        const imdb_manifest_view *v = &m->v[i];
        if (v->dropped_at) continue;
        p[k++] = v->name;
        for (uint16_t d = 0; d < v->def->ndeps && !rc; d++) {
            const imdb_viewdep *dp = &v->def->deps[d];
            bool live = dp->kind == IMDB_VIEWDEP_TABLE ? dp->id < m->nt && !m->t[dp->id].dropped_at
                                                       : dp->id < i && !m->v[dp->id].dropped_at;
            if (!live) rc = imdb_fail(e, IMDB_ERR_CORRUPT, "manifest: a live view names a table or view that is not live");
        }
    }
    if (!rc) qsort(p, k, sizeof *p, cmp_name_ptr);
    for (size_t i = 1; !rc && i < k; i++)
        if (!strcmp(p[i - 1], p[i])) rc = imdb_fail(e, IMDB_ERR_CORRUPT, "manifest: two live tables or views of one name");
    imdb_free(p);
    return rc;
}

static int old_manifest(uint32_t ver, imdb_err *e)
{
    if (ver < 5)
        return imdb_fail(e, IMDB_ERR_UNSUPPORTED, "manifest version %u: this lake was written by an imagedb before DROP "
                         "TABLE's format (manifest 5), which this version does not read", ver);
    return imdb_fail(e, IMDB_ERR_UNSUPPORTED, "manifest version %u: this lake was written by an imagedb before views' "
                     "format (manifest 6, P2 S7), which this version does not read", ver);
}

int imdb_manifest_parse(const uint8_t *b, size_t len, imdb_manifest *m, imdb_err *e)
{
    memset(m, 0, sizeof *m);
    imdb_rd r;
    imdb_rd_init(&r, b, len);
    const uint8_t *mg = imdb_rd_bytes(&r, 8);
    if (!mg || memcmp(mg, kManMagic, 8) != 0) return imdb_fail(e, IMDB_ERR_CORRUPT, "manifest: bad magic");
    uint32_t ver = imdb_rd_u32(&r); /* 6: every table's indexes, retention, creation and drop; the views (P2 S7; no
                                     * reader for 2-5) */
    if (ver >= 2 && ver <= 5) return old_manifest(ver, e);
    if (ver != 6) return imdb_fail(e, IMDB_ERR_CORRUPT, "manifest: unsupported version");
    uint32_t nt = imdb_rd_u32(&r);
    imdb_rd_copy(&r, m->db_id, 16);
    m->seq = imdb_rd_u64(&r);
    imdb_rd_copy(&r, m->prev, 32);
    imdb_rd_copy(&r, m->state, 32);
    imdb_rd_copy(&r, m->prev_manifest, 32);
    m->boundary = imdb_rd_u64(&r);
    if (!r.err && m->boundary >= m->seq) return imdb_fail(e, IMDB_ERR_CORRUPT, "manifest: boundary not below its commit");
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
        t->retention_us = imdb_rd_u64(&r);
        if (r.err || !imdb_retention_ok(t->retention_us)) goto bad;
        t->created_at = imdb_rd_u64(&r);
        t->dropped_at = imdb_rd_u64(&r);
        /* created by its commit, before any drop, which leaves it nothing live; both at or before this snapshot */
        if (r.err || !t->created_at || t->created_at > m->seq || (t->dropped_at && (t->dropped_at <= t->created_at ||
                                                                            t->dropped_at > m->seq || t->live)))
            goto bad;
    }
    uint32_t nv = imdb_rd_u32(&r); /* P2 S7: each view by id, a live one's definition after it */
    if (r.err || nv > IMDB_MAX_VIEWS || nv > imdb_rd_left(&r) / 22) goto bad;
    if (nv && !(m->v = imdb_alloc_array(nv, sizeof *m->v, e))) {
        imdb_manifest_free(m);
        return e->code;
    }
    m->nv = nv;
    for (uint32_t i = 0; i < nv; i++) {
        imdb_manifest_view *v = &m->v[i];
        imdb_err ev = {0};
        v->id = imdb_rd_u32(&r);
        if (imdb_rd_ident(&r, v->name, &ev)) goto bad;
        v->created_at = imdb_rd_u64(&r);
        v->dropped_at = imdb_rd_u64(&r);
        bool lower = true;
        for (const char *q = v->name; *q; q++) lower &= !(*q >= 'A' && *q <= 'Z');
        if (r.err || v->id != i || !lower || !v->created_at || v->created_at > m->seq ||
            (v->dropped_at && (v->dropped_at <= v->created_at || v->dropped_at > m->seq)))
            goto bad;
        if (v->dropped_at) continue;
        int vrc = imdb_viewdef_decode(&r, &v->def, e);
        if (vrc && vrc != IMDB_ERR_CORRUPT) {
            imdb_manifest_free(m);
            return vrc;
        }
        if (vrc || v->def->id != i || strcmp(v->def->name, v->name)) goto bad;
    }
    if (imdb_rd_left(&r)) goto bad;
    int nrc = manifest_index_names(m, e);
    if (nrc && nrc != IMDB_ERR_CORRUPT) {
        imdb_manifest_free(m);
        return nrc;
    }
    if (nrc) goto bad;
    int vrc = manifest_views_ok(m, e);
    if (vrc && vrc != IMDB_ERR_CORRUPT) {
        imdb_manifest_free(m);
        return vrc;
    }
    if (vrc) goto bad;
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
    imdb_free(P->p);
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
            imdb_free(mb);
            imdb_err_clear(&e);
            continue;
        }
        imdb_free(mb);
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
    uint8_t (*dvh)[32];      /* each segment's deletion vector hash at seq (zero: none): made, or kept */
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
    uint64_t boundary; /* the manifest's: a RETIRE's new one, else the database's */
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
        }
        imdb_free(pt->seg);
        imdb_free(pt->owned);
        imdb_free(pt->dvh);
    }
    imdb_free(p->tab);
    imdb_buf_free(&p->manifest);
    imdb_free(p->rw);
    imdb_free(p);
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
    p->boundary = kind == IMDB_OP_RETIRE ? purge_before : db->boundary;
    imdb_buf_init(&p->manifest);
    p->tab = imdb_alloc_array(db->nt ? db->nt : 1, sizeof *p->tab, e);
    if (!p->tab) {
        imdb_free(p);
        return e->code;
    }
    p->nt = db->nt;
    int rc = IMDB_OK;
    seg_src *srcs = NULL;
    for (uint32_t ti = 0; ti < db->nt && !rc; ti++) {
        imdb_table *t = db->t[ti];
        plan_tab *pt = &p->tab[ti];
        pt->horizon = t->horizon;
        /* existing segments, rewritten if they hold rows being erased, or (RETIRE) without the rows of the
         * versions it drops, a segment left with none dropped */
        for (uint32_t k = 0; k < t->nseg && !rc; k++) {
            imdb_segment *g = t->seg[k];
            imdb_segimg *gi = NULL; /* only RETIRE and an ERASE read a segment's rows: a plain publish keeps it whole */
            /* RETIRE: a segment the boundary does not split is kept whole or dropped whole from its marks, unread
             * (stage 3c-1 (b2)); only one whose ends straddle it, or that keeps part, is read */
            int64_t gone = kind == IMDB_OP_RETIRE ? imdb_seg_ended_by(g, purge_before) : -1;
            bool whole = gone == 0 || gone == (int64_t)g->nrows;
            if (((kind == IMDB_OP_RETIRE && !whole) || es) && !(gi = imdb_seg_pin(t, g, e))) {
                rc = e->code;
                break;
            }
            if (kind == IMDB_OP_RETIRE) {
                uint32_t keep = whole ? (uint32_t)(g->nrows - gone) : 0;
                for (uint32_t i = 0; !whole && i < g->nrows; i++) keep += !ended_by(gi->end[i], purge_before);
                if (gi) seg_marks_check(g, gi);
                if (keep == g->nrows) {
                    rc = pt_push(pt, g, false, e);
                    continue;
                }
                if (!keep) continue; /* every row dropped: the segment leaves the lake */
                imdb_free(srcs);
                if (!(srcs = imdb_alloc_array(keep, sizeof *srcs, e))) {
                    rc = e->code;
                    break;
                }
                for (uint32_t i = 0, n = 0; i < g->nrows; i++)
                    if (!ended_by(gi->end[i], purge_before)) srcs[n++] = (seg_src){gi, i, gi->vid[i]}; /* vid order kept */
                imdb_segment *ng;
                if ((rc = seg_build(t, srcs, keep, NULL, 0, &ng, e))) break;
                if ((rc = pt_push(pt, ng, true, e))) {
                    imdb_segment_free(ng);
                    break;
                }
                continue;
            }
            bool hit = false;
            for (uint32_t i = 0; es && i < g->nrows && !hit; i++)
                hit = !(gi->flags[i] & IMDB_SEG_STUB) && erased_has(es, ti, gi->vid[i]);
            if (!hit) {
                rc = pt_push(pt, g, false, e);
                continue;
            }
            imdb_free(srcs);
            if (!(srcs = imdb_alloc_array(g->nrows ? g->nrows : 1, sizeof *srcs, e))) {
                rc = e->code;
                break;
            }
            src_rows(g, gi, srcs);
            imdb_segment *ng;
            if ((rc = seg_build(t, srcs, g->nrows, es, 0, &ng, e))) break;
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
        /* a version the boundary drops was begun at or before it, so the publish that ends there flushed it
         * (every publish flushes): never in a memtable */
        for (uint64_t vid = t->mem_first; kind == IMDB_OP_RETIRE && vid < t->nver && !rc; vid++)
            if (ended_by(imdb_vh(t, vid)->end, purge_before))
                rc = imdb_fail(e, IMDB_ERR_STATE, "RETIRE: version %llu of %s, which ends at or before the boundary, is not "
                               "in the lake", (unsigned long long)vid, t->s.name);
        if (rc) break;
        /* flush the memtable */
        if (t->mem_first < t->nver) {
            uint64_t cnt = t->nver - t->mem_first;
            if (cnt > IMDB_MAX_SEGMENT_ROWS) {
                rc = imdb_fail(e, IMDB_ERR_LIMIT, "memtable of %s exceeds one segment; checkpoint more often", t->s.name);
                break;
            }
            imdb_free(srcs);
            srcs = imdb_alloc_array(cnt, sizeof *srcs, e);
            if (!srcs) {
                rc = e->code;
                break;
            }
            for (uint64_t i = 0; i < cnt; i++) srcs[i] = (seg_src){NULL, 0, t->mem_first + i};
            imdb_segment *ng;
            if ((rc = seg_build(t, srcs, (uint32_t)cnt, es, 0, &ng, e))) break;
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
            imdb_free(srcs);
            srcs = imdb_alloc_array(total ? total : 1, sizeof *srcs, e);
            if (!srcs) {
                rc = e->code;
                break;
            }
            uint64_t m = 0;
            for (uint32_t k = 0; k < pt->nseg; k++) { /* disjoint, vid-ordered */
                const imdb_segimg *gk = imdb_seg_pin(pt->owned[k] ? NULL : t, pt->seg[k], e); /* a built one: apart */
                if (!gk) {
                    rc = e->code;
                    break;
                }
                src_rows(pt->seg[k], gk, srcs + m);
                m += pt->seg[k]->nrows;
            }
            imdb_segment **merged = imdb_alloc_array(m / IMDB_MAX_SEGMENT_ROWS + 1, sizeof *merged, e);
            if (!merged) {
                rc = e->code;
                break;
            }
            uint32_t nm = 0;
            for (uint64_t at = 0; at < m && !rc; at += IMDB_MAX_SEGMENT_ROWS) {
                uint64_t cnt = m - at < IMDB_MAX_SEGMENT_ROWS ? m - at : IMDB_MAX_SEGMENT_ROWS;
                rc = seg_build(t, srcs + at, (uint32_t)cnt, es, purge_before, &merged[nm], e);
                if (!rc) nm++;
            }
            for (uint32_t k = 0; k < pt->nseg; k++)
                if (pt->owned[k]) imdb_segment_free(pt->seg[k]);
            pt->nseg = 0;
            for (uint32_t k = 0; k < nm; k++) {
                if (!rc && !(rc = pt_push(pt, merged[k], true, e))) continue;
                imdb_segment_free(merged[k]); /* the one pt_push failed to take (it stays the caller's), and the rest */
            }
            imdb_free(merged);
            if (rc) break;
            pt->compacted = true;
            if (purge_before > pt->horizon) pt->horizon = purge_before;
        }
        /* deletion vectors as of seq */
        pt->dvh = imdb_alloc_array(pt->nseg ? pt->nseg : 1, sizeof *pt->dvh, e);
        if (!pt->dvh) {
            rc = e->code;
            break;
        }
        for (uint32_t k = 0; k < pt->nseg; k++) {
            imdb_segment *g = pt->seg[k];
            if (!pt->owned[k] && !g->dv_stale) { /* no end of its rows changed since its vector was made: it stands, and
                                                   * the image is not needed (stage 3c-1 (b2)) */
                memcpy(pt->dvh[k], g->dv_hash, 32);
#ifdef IMDB_STORE_CHECKS
                const imdb_segimg *gr = imdb_seg_resident(t, g); /* where it is in memory, never a load: a missed mark */
                uint8_t ck[32];
                if (gr) dv_hash(g, gr, seq, ck);
                if (gr && memcmp(ck, g->dv_hash, 32) != 0) {
                    fprintf(stderr, "imagedb: a segment of table %s kept a deletion vector its ends no longer make\n",
                            t->s.name);
                    abort();
                }
#endif
                continue;
            }
            const imdb_segimg *gk = imdb_seg_pin(pt->owned[k] ? NULL : t, pt->seg[k], e);
            if (!gk) {
                rc = e->code;
                break;
            }
            dv_hash(g, gk, seq, pt->dvh[k]);
        }
    }
    imdb_free(srcs);
    if (rc) {
        plan_free(p);
        return rc;
    }
    if (p->nrw) qsort(p->rw, p->nrw, sizeof *p->rw, cmp_rw);
    /* manifest */
    imdb_buf *mb = &p->manifest;
    imdb_buf_put(mb, kManMagic, 8);
    imdb_buf_put_u32(mb, 6); /* lake.h: every table's indexes, retention, creation and drop; the views (P2 S7) */
    imdb_buf_put_u32(mb, db->nt);
    imdb_buf_put(mb, db->db_id, 16);
    imdb_buf_put_u64(mb, seq);
    imdb_buf_put(mb, prev, 32);
    uint8_t sd[32];
    imdb_lthash_digest(db->meta.digest_alg, post_global, sd);
    imdb_buf_put(mb, sd, 32);
    static const uint8_t none[32];
    imdb_buf_put(mb, kind == IMDB_OP_ERASE || !db->lake_seq ? none : db->lake_manifest, 32); /* GC's retained generation */
    imdb_buf_put_u64(mb, p->boundary);
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
            imdb_buf_put(mb, pt->dvh[k], 32);
            imdb_buf_put_u32(mb, pt->seg[k]->nrows);
        }
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
        imdb_buf_put_u64(mb, t->retention_us);
        imdb_buf_put_u64(mb, t->created_at);
        imdb_buf_put_u64(mb, t->dropped_at);
    }
    imdb_buf_put_u32(mb, db->nviews); /* P2 S7: each view by id; a live one's definition after it (lake.h) */
    for (uint32_t i = 0; i < db->nviews; i++) {
        const imdb_view *v = &db->views[i];
        size_t nl = strlen(v->name);
        imdb_buf_put_u32(mb, v->id);
        imdb_buf_put_u8(mb, (uint8_t)nl);
        imdb_buf_put(mb, v->name, nl);
        imdb_buf_put_u64(mb, v->created_at);
        imdb_buf_put_u64(mb, v->dropped_at);
        if (!v->dropped_at) imdb_viewdef_encode(v->def, mb);
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

/* a table's segments hold rows, their vid ranges ascending and disjoint (each segment's own ascend: parse) */
static bool segs_in_order(const imdb_table *t)
{
    for (uint32_t k = 0; k < t->nseg; k++)
        if (!t->seg[k]->nrows || (k && t->seg[k - 1]->vid_last >= t->seg[k]->vid_first)) return false;
    return true;
}

int imdb_lake_find(const imdb_table *t, uint64_t vid, uint32_t *seg, uint32_t *row, bool *found, imdb_err *e)
{
    *found = false;
    uint32_t lo = 0, hi = t->nseg;
    while (lo < hi) { /* the first segment whose last vid is at or past vid: the descriptors, no image */
        uint32_t mid = lo + (hi - lo) / 2;
        if (t->seg[mid]->vid_last < vid) lo = mid + 1;
        else hi = mid;
    }
    if (lo == t->nseg || t->seg[lo]->vid_first > vid) return IMDB_OK;
    imdb_segment *g = t->seg[lo];
    const imdb_segimg *gi = imdb_seg_pin(t, g, e); /* its row: the image */
    if (!gi) return e->code;
    uint32_t a = 0, b = g->nrows;
    while (a < b) {
        uint32_t mid = a + (b - a) / 2;
        if (gi->vid[mid] < vid) a = mid + 1;
        else b = mid;
    }
    if (a == g->nrows || gi->vid[a] != vid) return IMDB_OK;
    *found = true;
    *seg = lo;
    *row = a;
    return IMDB_OK;
}

/* Swaps the planned segments in; afterwards the table owns them. */
static int plan_install(imdb_db *db, imdb_lake_plan *p, imdb_err *e)
{
    for (uint32_t ti = 0; ti < p->nt; ti++) {
        imdb_table *t = db->t[ti];
        plan_tab *pt = &p->tab[ti];
        /* versions this plan purges leave their key chains now, while the key is
         * still readable from their old location (a tombstone keeps no key) */
        for (uint32_t k = 0; pt->compacted && k < pt->nseg; k++) {
            imdb_segment *g = pt->seg[k];
            const imdb_segimg *gi = imdb_seg_pin(pt->owned[k] ? NULL : t, g, e); /* a built one: apart */
            if (!gi) {
                db->failed = true; /* earlier tables are already swapped: fail-stop, replay rebuilds */
                return e->code;
            }
            for (uint32_t i = 0; i < g->nrows; i++) {
                if (!(gi->flags[i] & IMDB_SEG_PURGED) || !imdb_v_held(t, gi->vid[i]) ||
                    (imdb_vh(t, gi->vid[i])->flags & (IMDB_V_PURGED | IMDB_V_STUB)))
                    continue;
                imdb_value key;
                if (imdb_version_key(t, gi->vid[i], t->s.pk, &key) == IMDB_OK) imdb_pk_unlink(t, gi->vid[i], &key);
            }
        }
        imdb_segment **ns = imdb_alloc_array(pt->nseg ? pt->nseg : 1, sizeof *ns, e);
        if (!ns) {
            db->failed = true; /* earlier tables are already swapped: fail-stop, replay rebuilds */
            return e->code;
        }
        /* Every held version keeps its place through the new list, without an image (stage 3c-1 (b2)): one in a kept
         * segment takes the segment's new position (the same row); one whose segment was rewritten or dropped loses
         * it, and the rows of the segments this plan built give it back below. Through the OLD list, before it goes. */
        for (uint32_t k = 0; k < t->nseg; k++) t->seg[k]->pos = UINT32_MAX;
        for (uint32_t j = 0; j < pt->nseg; j++) pt->seg[j]->pos = j;
        for (uint64_t vid = imdb_v_next(t, 0); vid < t->nver; vid = imdb_v_next(t, vid + 1)) {
            imdb_version *v = imdb_vh(t, vid);
            if (!(v->flags & IMDB_V_SEG)) continue;
            uint32_t np = v->seg < t->nseg ? t->seg[v->seg]->pos : UINT32_MAX;
            if (np == UINT32_MAX) v->flags &= (uint8_t)~IMDB_V_SEG;
            else v->seg = np;
        }
        /* old segments not carried over are freed */
        for (uint32_t k = 0; k < t->nseg; k++)
            if (t->seg[k]->pos == UINT32_MAX) imdb_segment_free(t->seg[k]);
        imdb_free(t->seg);
        t->seg = ns;
        t->nseg = t->capseg = pt->nseg;
        for (uint32_t k = 0; k < pt->nseg; k++) {
            imdb_segment *g = pt->seg[k];
            t->seg[k] = g;
            if (pt->owned[k]) seg_charge(t->segcache, g); /* built by this plan: the table's now, not yet on disk */
            if (memcmp(pt->dvh[k], g->dv_hash, 32) != 0) g->ondisk = false; /* a new vector: on disk once published */
            memcpy(g->dv_hash, pt->dvh[k], 32);
            g->dv_stale = false; /* the vector at seq: no end in the store is past it at a publish */
        }
        bool newly = false; /* versions this install made tombstones */
        /* the built segments' rows (resident: just built) place their held versions; pt->owned says which they are
         * until here, and is cleared on every way out: the table owns them all now, and plan_free must not free them */
        int brc = IMDB_OK;
        for (uint32_t k = 0; k < t->nseg && !brc; k++) {
            if (!pt->owned[k]) continue;
            imdb_segment *g = t->seg[k];
            const imdb_segimg *gi = imdb_seg_pin(t, g, e);
            if (!gi) {
                brc = e->code;
                break;
            }
            for (uint32_t i = 0; i < g->nrows; i++) {
                if (!imdb_v_held(t, gi->vid[i])) continue; /* the lake's alone */
                imdb_version *v = imdb_vh(t, gi->vid[i]);
                v->flags |= IMDB_V_SEG;
                v->seg = k;
                v->seg_row = i;
                if ((gi->flags[i] & IMDB_SEG_PURGED) && !(v->flags & IMDB_V_PURGED)) {
                    /* purged now: its tombstone keeps vid, begin, commitment, subject */
                    newly = true;
                    v->flags |= IMDB_V_PURGED;
                    v->row_len = 0;
                }
            }
        }
        for (uint32_t k = 0; k < pt->nseg; k++) pt->owned[k] = false; /* the table's, on every way out from here */
        if (brc) {
            db->failed = true; /* half placed: fail-stop, replay rebuilds */
            return brc;
        }
        if (!segs_in_order(t)) { /* every plan keeps them so; imdb_lake_find relies on it */
            db->failed = true;
            return imdb_fail(e, IMDB_ERR_STATE, "lake: the segments of %s are not in vid order", t->s.name);
        }
        if (pt->flushed) {
            imdb_buf_wipe_free(&t->arena);
            imdb_buf_init(&t->arena);
            imdb_ver_flushed(t); /* the cold parts are the new segment's rows now */
        }
        if (pt->compacted) {
            /* an EXPIRE may have moved the horizon already: what decides is whether rows were purged */
            t->horizon = pt->horizon;
            if (newly) imdb_index_rebuild_table(db, t); /* the purged versions leave the indexes */
        }
        if (p->kind == IMDB_OP_RETIRE) { /* their rows are gone from the lake: now from the store and the indexes */
            if (imdb_retire_table(t, p->boundary, e)) {
                db->failed = true; /* half retired: fail-stop, replay rebuilds */
                return e->code;
            }
            imdb_index_after_retire(db, t); /* by vid: no key read (stage 3c-1 (b2)) */
        }
    }
    if (p->kind == IMDB_OP_RETIRE) {
        db->retire_cand[0] = db->retire_cand[1] = 0; /* their counts held what this one dropped */
        db->boundary = p->boundary;
        imdb_txn_doom_retired(db, p->boundary);
        imdb_ci_retire(db, p->boundary);
    }
    imdb_free(db->lake_mbytes);
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
            if (!e2.code) imdb_free(cur);
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
/* ---- keepers (stage 3a (c2)): the manifests a future FLOOR may embed ------------------------- */

struct imdb_keeper {
    uint8_t hash[32];
    uint64_t seq;
};

static int cmp_keeper(const void *a, const void *b)
{
    return memcmp(((const struct imdb_keeper *)a)->hash, ((const struct imdb_keeper *)b)->hash, 32);
}

/* none while a table is kept FOREVER: it blocks RETIRE, so no floor will need one */
static bool keep_mans(const imdb_db *db)
{
    bool all = db->nt > 0;
    for (uint32_t i = 0; i < db->nt; i++) all &= db->t[i]->retention_us != IMDB_RETAIN_FOREVER;
    return all;
}

static bool keep_has(const imdb_db *db, const uint8_t h[32])
{
    struct imdb_keeper k;
    memcpy(k.hash, h, 32);
    return db->nkeep && bsearch(&k, db->keep, db->nkeep, sizeof *db->keep, cmp_keeper) != NULL;
}

static int keep_add(imdb_db *db, uint64_t seq, const uint8_t h[32], imdb_err *e)
{
    if (keep_has(db, h)) return IMDB_OK;
    if (db->nkeep == db->capkeep) {
        size_t nc = db->capkeep ? db->capkeep * 2 : 16;
        struct imdb_keeper *n = imdb_realloc_array(db->keep, db->capkeep, nc, sizeof *n, e);
        if (!n) return e->code;
        db->keep = n;
        db->capkeep = nc;
    }
    size_t at = 0;
    while (at < db->nkeep && memcmp(db->keep[at].hash, h, 32) < 0) at++;
    memmove(db->keep + at + 1, db->keep + at, (db->nkeep - at) * sizeof *db->keep);
    memcpy(db->keep[at].hash, h, 32);
    db->keep[at].seq = seq;
    db->nkeep++;
    return IMDB_OK;
}

/* those at or below the boundary go: no later floor is there */
static void keep_trim(imdb_db *db)
{
    size_t w = 0;
    for (size_t r = 0; r < db->nkeep; r++)
        if (db->keep[r].seq > db->boundary) db->keep[w++] = db->keep[r];
    db->nkeep = w;
}

static uint64_t man_seq(const imdb_db *db, int ofd, const char *name);

int imdb_lake_keepers_load(imdb_db *db, imdb_err *e)
{
    db->nkeep = 0;
    if (db->read_only || !keep_mans(db) || !db->nsegs) return IMDB_OK;
    int ofd = open_objects(db, e);
    if (ofd < 0) return e->code;
    int dfd = dup(ofd);
    DIR *d = dfd >= 0 ? imdb_io_fdopendir(dfd) : NULL;
    int rc = IMDB_OK;
    if (!d) {
        if (dfd >= 0) close(dfd);
        rc = imdb_fail(e, IMDB_ERR_IO, "objects: cannot list directory");
    }
    for (struct dirent *de; d && !rc && (errno = 0, de = imdb_io_readdir(d));) {
        uint8_t h[32];
        if (!imdb_object_name_valid(de->d_name) || strcmp(de->d_name + 64, ".man") != 0 || !imdb_unhex(de->d_name, 64, h, 32))
            continue;
        uint64_t p = man_seq(db, ofd, de->d_name);
        size_t si = p ? imdb_logseg_find(db->segs, db->nsegs, p) : db->nsegs;
        if (p > db->boundary && si < db->nsegs && imdb_is_keeper(db->floor_stride, db->segs[si], p))
            rc = keep_add(db, p, h, e);
    }
    if (d) closedir(d);
    close(ofd);
    return rc;
}

/* The commit of manifest object name (0 when it is not a manifest of this database) */
static uint64_t man_seq(const imdb_db *db, int ofd, const char *name)
{
    /* its header alone: every writable open reads each manifest in objects/, and one can be large; the keeper set
     * only ever keeps a file, so a forged commit number costs space, never data */
    uint8_t p[40];
    int fd = imdb_io_openat(ofd, name, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return 0;
    ssize_t n = imdb_io_pread(fd, p, sizeof p, 0);
    close(fd);
    if (n != (ssize_t)sizeof p || memcmp(p, kManMagic, 8) != 0 || memcmp(p + 16, db->db_id, 16) != 0) return 0;
    return imdb_get_le64(p + 32);
}

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
    /* the keepers' manifests stay (their segments go as ever): a future FLOOR embeds one (stage 3a (c2)) */
    if (keep_mans(db)) keep_trim(db);
    else db->nkeep = 0;
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
            if (!ref && pass == 0 && valid && keep_has(db, h)) ref = true;
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
/* The boundary becomes this copy's floor (stage 3a (c2)): FLOOR written from commit boundary's own header and
 * signature, while its segment still exists, before LAKE_HEAD names the RETIRE's manifest; the segments below
 * go only after that (imdb_log_cut). */
static int floor_advance(imdb_db *db, int ofd, imdb_err *e)
{
    imdb_buf h, starts;
    imdb_buf_init(&h);
    imdb_buf_init(&starts);
    uint8_t sig[IMDB_SIG_LEN], *man = NULL;
    size_t manlen = 0;
    uint32_t nstarts = 0;
    imdb_commit_rec c;
    memset(&c, 0, sizeof c);
    int rc = imdb_log_commit_header(db, db->boundary, &h, sig, e);
    if (!rc) rc = imdb_commit_decode_header(h.p, h.len, &c, e);
    const uint8_t *mh = NULL; /* the floor's own manifest: the tables at the floor, for a verifier seeded there */
    for (uint32_t i = 0; !rc && i < c.nops && !mh; i++)
        if (imdb_op_publishes_manifest(c.ops[i].code)) mh = c.ops[i].manifest;
    imdb_err me = {0};
    if (!rc && (!mh || imdb_lake_read_object(ofd, mh, ".man", &man, &manlen, &me))) {
        /* gone (a table was kept FOREVER while it was published, so GC kept no manifest): no cut this time; the
         * next RETIRE's floor will have one */
        imdb_warn(db, "the log below commit %llu stays: its manifest is gone (%s)", (unsigned long long)db->boundary + 1,
                  mh ? me.msg : "it published none");
        goto out;
    }
    imdb_manifest m;
    if (!rc && !(rc = imdb_manifest_parse(man, manlen, &m, e))) {
        uint64_t hmin = m.nt ? UINT64_MAX : 0; /* an EXPIRE past the floor names a start above the lowest horizon */
        for (uint32_t i = 0; i < m.nt; i++)
            if (m.t[i].horizon < hmin) hmin = m.t[i].horizon;
        imdb_manifest_free(&m);
        rc = imdb_seg_starts(db, hmin, db->boundary, &starts, &nstarts, e);
    }
    if (!rc) rc = imdb_floor_write(db, db->boundary, h.p, (uint32_t)h.len, sig, starts.p, nstarts, man, manlen, e);
    if (!rc) rc = imdb_floor_read(db, e); /* the record as an open will find it: what VERIFY is seeded from */
out:
    imdb_commit_free(&c);
    imdb_free(man);
    imdb_buf_free(&h);
    imdb_buf_free(&starts);
    return rc;
}

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
            if (g->ondisk) continue; /* both its objects are written: neither loaded nor read back (stage 3c-1 (b2)) */
            const imdb_segimg *gi = imdb_seg_pin(t, g, e); /* resident: an image not on disk never leaves memory */
            if (!gi) {
                rc = e->code;
                break;
            }
            if (!g->seg_ondisk && !(rc = obj_put(db, ofd, g->hash, ".seg", gi->bytes, gi->len, e))) g->seg_ondisk = true;
            if (!rc && !all_zero(g->dv_hash, 32)) {
                dv_build(g, gi, db->lake_seq, &dv);
                uint8_t dh[32]; /* made from the image's ends: a reload that missed one would misname the file */
                if (!(rc = imdb_buf_check(&dv, e))) imdb_sha256(dv.p, dv.len, dh);
                if (!rc && memcmp(dh, g->dv_hash, 32) != 0) {
                    db->failed = true;
                    rc = imdb_fail(e, IMDB_ERR_STATE, "lake: a deletion vector made from its segment's image does not hash "
                                                    "to its name");
                }
                if (!rc) rc = obj_put(db, ofd, g->dv_hash, ".dv", dv.p, dv.len, e);
            }
            if (!rc) g->ondisk = true; /* its image may leave memory now: both objects can be read again */
        }
    }
    if (!rc) rc = obj_put(db, ofd, db->lake_manifest, ".man", db->lake_mbytes, db->lake_mlen, e);
    if (!rc) rc = imdb_sync_dir(ofd, e);
    if (!rc) rc = imdb_log_sync(db, e); /* LAKE_HEAD must never name a commit the log could still lose */
    if (!rc && db->boundary > db->log_floor) rc = floor_advance(db, ofd, e); /* FLOOR first: the cut below needs it */
    if (!rc) rc = write_head(db, e);
    if (!rc && keep_mans(db)) { /* a keeper's manifest stays for a future FLOOR (keepers: db_internal.h) */
        size_t si = imdb_logseg_find(db->segs, db->nsegs, db->lake_seq);
        imdb_err ke = {0};
        if (si < db->nsegs && imdb_is_keeper(db->floor_stride, db->segs[si], db->lake_seq) &&
            keep_add(db, db->lake_seq, db->lake_manifest, &ke))
            imdb_warn(db, "a manifest kept for a later log floor could not be noted (%s)", ke.msg);
    }
    if (!rc && db->log_floor) { /* cleanup, as GC is: a writable open repeats it */
        imdb_err ce = {0};
        if (imdb_log_cut(db, &ce))
            imdb_warn(db, "the log below commit %llu could not all be removed (%s); retried at open",
                      (unsigned long long)db->log_floor + 1, ce.msg);
    }
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
    imdb_free(db->lake_prev);
    db->lake_prev = erase ? NULL : prev;
    db->lake_prevlen = erase ? 0 : prevlen;
    if (erase) imdb_free(prev);
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

static int physical_commit_body(imdb_db *db, uint8_t kind, uint32_t table, uint64_t purge_before, imdb_err *e)
{
    if (lake_writable(db, e)) return e->code;
    imdb_lthash *post = imdb_alloc_aligned(db->nt ? db->nt : 1, sizeof *post, e);
    if (!post) return e->code;
    for (uint32_t i = 0; i < db->nt; i++) post[i] = db->t[i]->digest;
    imdb_lake_plan *p;
    int rc = plan_build(db, kind, table, purge_before, NULL, post, &db->global, db->seq + 1, db->head, &p, e);
    imdb_free(post);
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
            if (!pt->owned[k]) continue;
            const imdb_segimg *gi = imdb_seg_pin(NULL, pt->seg[k], e); /* built by this plan: apart, resident */
            rc = gi ? obj_put(db, ofd, pt->seg[k]->hash, ".seg", gi->bytes, gi->len, e) : e->code;
            if (!rc) pt->seg[k]->seg_ondisk = true; /* lake_persist need not put it again (its vector may still wait) */
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
    imdb_evict_policy(db); /* between transactions: what this publish lets go may leave memory */
    return rc;
}

/* one operation (stage 3c-1): the segment cache trims when the outermost ends */
static int physical_commit(imdb_db *db, uint8_t kind, uint32_t table, uint64_t purge_before, imdb_err *e)
{
    uint64_t t0 = imdb_mono_ns(); /* P1 M1: each kind's count and time, done or refused alike */
    imdb_op_enter(db);
    int rc = physical_commit_body(db, kind, table, purge_before, e);
    imdb_op_leave(db);
    imdb_stats_maint(db, kind == IMDB_OP_CHECKPOINT ? IMDB_MT_CHECKPOINT : kind == IMDB_OP_COMPACT ? IMDB_MT_COMPACT : IMDB_MT_RETIRE, t0);
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

int imdb_retire(imdb_db *db, uint64_t boundary, imdb_err *e)
{
    if (boundary <= db->boundary || boundary >= db->seq)
        return imdb_fail(e, IMDB_ERR_INVALID, "RETIRE %llu: the boundary must be past %llu and below commit %llu",
                         (unsigned long long)boundary, (unsigned long long)db->boundary, (unsigned long long)db->seq);
    /* the commit after it begins a segment (so it published a manifest): every copy can check that from its own log */
    size_t si = imdb_logseg_find(db->segs, db->nsegs, boundary + 1);
    bool ends = si < db->nsegs && db->segs[si] == boundary + 1;
    if (!ends) return imdb_fail(e, IMDB_ERR_INVALID, "RETIRE %llu: that commit does not end a log segment", (unsigned long long)boundary);
    for (uint32_t i = 0; i < db->nt; i++)
        if (boundary >= db->t[i]->horizon)
            return imdb_fail(e, IMDB_ERR_INVALID, "RETIRE %llu: table %s still answers history from commit %llu",
                             (unsigned long long)boundary, db->t[i]->s.name, (unsigned long long)db->t[i]->horizon);
    return physical_commit(db, IMDB_OP_RETIRE, 0, boundary, e);
}

int imdb_retire_unchecked(imdb_db *db, uint64_t boundary, imdb_err *e)
{
    return physical_commit(db, IMDB_OP_RETIRE, 0, boundary, e);
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
    imdb_free(post);
    imdb_free(delta);
    imdb_free(touched);
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
    imdb_evict_policy(db); /* after the ERASE's commit: no transaction is open */
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
static int publish_pending_body(imdb_db *db, imdb_err *e)
{
    if (!db->lake_pending || db->needs_redaction || db->read_only) return IMDB_OK;
    return lake_persist(db, db->lake_prev, db->lake_prevlen, e);
}

/* one operation (stage 3c-1): the segment cache trims when the outermost ends */
int imdb_lake_publish_pending(imdb_db *db, imdb_err *e)
{
    imdb_op_enter(db);
    int rc = publish_pending_body(db, e);
    imdb_op_leave(db);
    return rc;
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
    imdb_free(db->lake_mbytes);
    db->lake_mbytes = NULL;
    imdb_free(db->lake_prev);
    db->lake_prev = NULL;
}

void imdb_lake_table_free(imdb_table *t)
{
    for (uint32_t k = 0; k < t->nseg; k++) imdb_segment_free(t->seg[k]);
    imdb_free(t->seg);
    t->seg = NULL;
    t->nseg = 0;
}

/* ---- version access -------------------------------------------------------------- */

int imdb_seg_values(imdb_table *t, const imdb_version *v, imdb_value *vals, imdb_err *e)
{
    if (v->seg >= t->nseg) return imdb_fail(e, IMDB_ERR_STATE, "version maps to a missing segment");
    const imdb_segimg *gi = imdb_seg_pin(t, t->seg[v->seg], e);
    if (!gi) return e->code;
    for (uint32_t c = 0; c < t->s.ncols; c++) seg_get(&t->s, gi, v->seg_row, c, &vals[c]);
    return IMDB_OK;
}

int imdb_seg_value(imdb_table *t, const imdb_version *v, int col, imdb_value *out)
{
    if (v->seg >= t->nseg) return IMDB_ERR_STATE;
    imdb_err e = {0};
    const imdb_segimg *gi = imdb_seg_pin(t, t->seg[v->seg], &e);
    if (!gi) return e.code;
    seg_get(&t->s, gi, v->seg_row, (uint32_t)col, out);
    return IMDB_OK;
}

void imdb_seg_set_end(imdb_table *t, const imdb_version *v, uint64_t end)
{
    if (!(v->flags & IMDB_V_SEG) || v->seg >= t->nseg) return;
    imdb_segment *g = t->seg[v->seg];
    g->dv_stale = true; /* its vector is made again at the next publish (in memory or not); an unmarked one stands */
    if (end == IMDB_LIVE) { /* an undo: a version's end comes and goes once; the bounds stay, loose but bounds */
        if (g->nended) g->nended--;
    } else if (g->nended++) {
        if (end < g->end_lo) g->end_lo = end;
        if (end > g->end_hi) g->end_hi = end;
    } else {
        g->end_lo = g->end_hi = end;
    }
    imdb_segimg *gi = imdb_seg_resident(t, g); /* never a load: one loaded later takes its ends from the held versions
                                                * (the floor never passes a publish) */
    if (gi) gi->end[v->seg_row] = end;
}

/* ---- verification of the on-disk lake ------------------------------------------- */

static int read_obj(int ofd, const uint8_t h[32], const char *ext, uint8_t **out, size_t *len, imdb_err *e)
{
    char name[80];
    obj_name(h, ext, name);
    /* A segment parser takes ownership of this buffer. Read directly into its
     * final aligned allocation, avoiding a second full segment, copy and wipe. */
    int rc = !strcmp(ext, ".seg") ? imdb_read_file_aligned_at(ofd, name, out, len, IMDB_MAX_OBJECT, e)
                                 : imdb_read_file_at(ofd, name, out, len, IMDB_MAX_OBJECT, e);
    if (rc) return rc;
    uint8_t got[32];
    imdb_sha256(*out, *len, got);
    if (memcmp(got, h, 32) != 0) {
        imdb_free(*out);
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

/* ---- the segment cache (stage 3c-1) -------------------------------------------------- */

/* The images of the database's segments under a budget (db.h: imdb_segcache). A pin loads an image that is not in
 * memory; the outermost operation's end drops the least recently pinned until the rest fit the budget. An image
 * leaves only once its objects are on disk (ondisk): one a publish built and has not written yet, or whose
 * deletion vector it has not, is the only copy. */

imdb_segimg *imdb_seg_resident(const imdb_table *t, imdb_segment *g)
{
    (void)t;
    return __atomic_load_n(&g->img_, __ATOMIC_ACQUIRE);
}

/* g's image read again (it left memory, so its objects are on disk): the rows by the segment's name, the published
 * ends by its deletion vector's, then each held version's own end, which is later or a running transaction's (an
 * end goes into a resident image only: imdb_seg_set_end). The bytes hash to the descriptor's name, so the
 * descriptor stands. P2 S14: outside the cache's lock, g marked loading (one worker reads it); it reads only what
 * changes between operations, never within one: the descriptor, the store, the copy's commit. Its object bytes in
 * *bytes; seg_publish then charges and shows the image under the lock */
static int seg_load_body(imdb_segcache *c, const imdb_table *t, imdb_segment *g, imdb_segimg **out, uint64_t *bytes,
                         imdb_err *e)
{
    *out = NULL;
    if (!g->ondisk || g->cache != c)
        return imdb_fail(e, IMDB_ERR_STATE, "lake: a segment's image left memory before its objects were written");
    int ofd = open_objects(c->db, e);
    if (ofd < 0) return e->code;
    uint8_t *sb = NULL;
    size_t sl = 0;
    imdb_segment *tmp = NULL;
    int rc = read_obj(ofd, g->hash, ".seg", &sb, &sl, e);
    if (!rc && (rc = imdb_segment_parse(&t->s, sb, sl, g->hash, &tmp, e))) imdb_free(sb); /* read_obj checked it */
    if (!rc && (tmp->nrows != g->nrows || tmp->table != g->table || tmp->vid_first != g->vid_first ||
                tmp->vid_last != g->vid_last))
        rc = imdb_fail(e, IMDB_ERR_STATE, "lake: a segment read again differs from its descriptor");
    imdb_segimg *gi = rc ? NULL : tmp->img_;
    uint64_t read = sl;
    if (!rc && !all_zero(g->dv_hash, 32)) {
        uint8_t *dvb, sh[32];
        size_t dl;
        imdb_dv_ent *ents;
        uint32_t n;
        if (!(rc = read_obj(ofd, g->dv_hash, ".dv", &dvb, &dl, e))) {
            read += dl;
            rc = imdb_dv_parse(dvb, dl, sh, &ents, &n, g->nrows, e);
            imdb_free(dvb);
            if (!rc) {
                if (memcmp(sh, g->hash, 32) != 0) rc = imdb_fail(e, IMDB_ERR_STATE, "lake: a deletion vector names another segment");
                for (uint32_t i = 0; !rc && i < n; i++) /* published, so never past this copy's commit */
                    if (ents[i].end > (c->snap_seq > c->db->seq ? c->snap_seq : c->db->seq)) /* a seeded copy: seq is its floor */
                        rc = imdb_fail(e, IMDB_ERR_STATE, "lake: a deletion vector records a later end");
                    else gi->end[ents[i].row] = ents[i].end;
                imdb_free(ents);
            }
        }
    }
    close(ofd);
    for (uint64_t vid = imdb_v_next(t, g->vid_first); !rc && vid <= g->vid_last && vid < t->nver;
         vid = imdb_v_next(t, vid + 1)) {
        const imdb_version *v = imdb_vh(t, vid); /* held: its end is the store's, later than any published */
        if (!(v->flags & IMDB_V_SEG) || v->seg >= t->nseg || t->seg[v->seg] != g) continue;
        if (v->seg_row >= g->nrows || gi->vid[v->seg_row] != vid)
            rc = imdb_fail(e, IMDB_ERR_STATE, "lake: a held version maps to another row of its segment");
        else
            gi->end[v->seg_row] = v->end;
    }
    if (!rc) seg_marks_check(g, gi); /* the checked builds: what the writes kept agrees with the rows */
    if (rc) {
        imdb_segment_free(tmp); /* apart (no cache): nothing charged */
        return rc;
    }
    tmp->img_ = NULL;
    imdb_free(tmp);
    *bytes = read;
    *out = gi;
    return IMDB_OK;
}

/* An image is the segment cache's, under its own budget, not a read statement's workspace (P0 R2, util.h): its
 * load is exempt from the statement's ceiling, which its allocations raise and its temporaries' frees lower again
 * (the exemption is the thread's own: each worker's load is) */
static int seg_load(imdb_segcache *c, const imdb_table *t, imdb_segment *g, imdb_segimg **out, uint64_t *bytes,
                    imdb_err *e)
{
    imdb_heap_exempt_begin();
    int rc = seg_load_body(c, t, g, out, bytes, e);
    imdb_heap_exempt_end();
    return rc;
}

/* Under the cache's lock: a load read gi (bytes of objects); charged, stamped, then shown to every pin (the release
 * store: a reader of img_ sees the whole image) */
static void seg_publish(imdb_segcache *c, imdb_segment *g, imdb_segimg *gi, uint64_t bytes)
{
    c->loads++;
    c->load_bytes += bytes;
    c->resident += seg_img_bytes(g, gi);
    if (c->resident > c->peak) c->peak = c->resident;
    __atomic_store_n(&g->touched, c->clock, __ATOMIC_RELAXED);
    __atomic_store_n(&g->img_, gi, __ATOMIC_RELEASE);
}

/* P2 S14, tests only: called between a load's read and its publication, with no lock held, so a test can hold a load
 * there while other workers pin the same segment (they wait) or others (they load), and let loads end in any order */
static void (*g_load_hook)(const imdb_segment *g, void *ctx);
static void *g_load_hook_ctx;
void imdb_seg_load_hook(void (*fn)(const imdb_segment *g, void *ctx), void *ctx)
{
    g_load_hook = fn;
    g_load_hook_ctx = ctx;
}

/* The pin of an image not stamped in this operation. P2 S14 (the 2026-11-05 review's O4): a cold image is read outside
 * the cache's lock, so imdb_par_for's workers read different segments at once rather than queue behind one read; one
 * load an image: a worker finding it loading waits for that load (the cache's condition), then takes its image, or,
 * when it failed in this operation, its error whole (what this worker's own read would have said: messages do not
 * depend on which worker read, nor on the thread count); a later operation reads again. Nothing drops an image while
 * a load runs: trims and the open's releases run only when no parallel loop does */
imdb_segimg *imdb_seg_pin_slow(const imdb_table *t, imdb_segment *g, imdb_err *e)
{
    imdb_segimg *gi = __atomic_load_n(&g->img_, __ATOMIC_ACQUIRE);
    imdb_segcache *c = t ? t->segcache : NULL;
    if (gi) {
        if (c) __atomic_fetch_add(&c->db->stats.seg_hits, 1, __ATOMIC_RELAXED); /* P1 M1: an operation's first pin, resident */
        if (c && __atomic_load_n(&g->touched, __ATOMIC_RELAXED) != c->clock) /* the clock moves between operations */
            __atomic_store_n(&g->touched, c->clock, __ATOMIC_RELAXED);
        return gi;
    }
    if (!c) {
        imdb_fail(e, IMDB_ERR_STATE, "lake: a segment apart from any table has no image");
        return NULL;
    }
    pthread_mutex_lock(&c->lock);
    for (;;) {
        gi = __atomic_load_n(&g->img_, __ATOMIC_ACQUIRE); /* another worker's load, while this one waited */
        if (gi) {
            pthread_mutex_unlock(&c->lock);
            return gi;
        }
        if (g->ld_fail == c->clock && g->ld_err) { /* that load failed in this operation: its error, whole */
            imdb_fail(e, g->ld_err->code, "%s", g->ld_err->msg);
            pthread_mutex_unlock(&c->lock);
            return NULL;
        }
        if (!g->loading) break; /* nobody reads it: this worker does */
        c->load_waits++;
        pthread_cond_wait(&c->loaded, &c->lock);
    }
    g->loading = true;
    pthread_mutex_unlock(&c->lock);
    uint64_t bytes = 0;
    int rc = seg_load(c, t, g, &gi, &bytes, e);
    if (g_load_hook) g_load_hook(g, g_load_hook_ctx);
    imdb_err *kept = NULL;
    if (rc) { /* kept for the workers waiting, and any that pins it later in this operation; none if it cannot be made */
        imdb_err ke = {0};
        imdb_heap_exempt_begin();
        if ((kept = imdb_alloc(sizeof *kept, &ke))) *kept = *e;
        imdb_heap_exempt_end();
    }
    pthread_mutex_lock(&c->lock);
    imdb_free(g->ld_err); /* an earlier operation's */
    g->ld_err = kept;
    g->ld_fail = rc ? c->clock : 0;
    if (!rc) seg_publish(c, g, gi, bytes);
    g->loading = false;
    pthread_cond_broadcast(&c->loaded);
    pthread_mutex_unlock(&c->lock);
    return rc ? NULL : gi;
}

void imdb_seg_cache_check(const imdb_db *db)
{
#ifdef IMDB_STORE_CHECKS
    uint64_t sum = 0;
    for (uint32_t ti = 0; ti < db->nt; ti++)
        for (uint32_t k = 0; k < db->t[ti]->nseg; k++) {
            const imdb_segment *g = db->t[ti]->seg[k];
            const imdb_segimg *gi = __atomic_load_n(&g->img_, __ATOMIC_ACQUIRE);
            if (!gi) continue;
            if (g->cache != &db->segcache) {
                fprintf(stderr, "imagedb: a segment of table %s holds an image its cache was not charged for\n",
                        db->t[ti]->s.name);
                abort();
            }
            sum += seg_img_bytes(g, gi);
        }
    if (sum != db->segcache.resident) {
        fprintf(stderr, "imagedb: the segment cache counts %llu bytes, its images hold %llu\n",
                (unsigned long long)db->segcache.resident, (unsigned long long)sum);
        abort();
    }
#else
    (void)db;
#endif
}

typedef struct trim_ent {
    uint64_t touched;
    uint32_t ti, k;
} trim_ent;

static int cmp_trim(const void *a, const void *b)
{
    const trim_ent *x = a, *y = b;
    if (x->touched != y->touched) return x->touched < y->touched ? -1 : 1;
    if (x->ti != y->ti) return x->ti < y->ti ? -1 : 1;
    return x->k < y->k ? -1 : x->k > y->k;
}

static bool seg_droppable(const imdb_segcache *c, const imdb_segment *g)
{
    return g->img_ && g->ondisk && g->cache == c;
}

/* The outermost operation ended: nothing pinned is in use. Past the budget, the least recently pinned images leave
 * until the rest fit (ties: in table and segment order). Without room to order them, every one that may leave does:
 * still correct, only colder. */
static void seg_trim(imdb_db *db)
{
    imdb_segcache *c = &db->segcache;
    imdb_seg_cache_check(db);
    if (c->resident <= c->budget) return;
    size_t n = 0;
    for (uint32_t ti = 0; ti < db->nt; ti++)
        for (uint32_t k = 0; k < db->t[ti]->nseg; k++) n += seg_droppable(c, db->t[ti]->seg[k]);
    if (!n) return;
    imdb_err e = {0};
    trim_ent *v = imdb_alloc_array(n, sizeof *v, &e);
    if (!v) {
        for (uint32_t ti = 0; ti < db->nt && c->resident > c->budget; ti++)
            for (uint32_t k = 0; k < db->t[ti]->nseg && c->resident > c->budget; k++)
                if (seg_droppable(c, db->t[ti]->seg[k])) seg_img_drop(db->t[ti]->seg[k]);
        return;
    }
    size_t m = 0;
    for (uint32_t ti = 0; ti < db->nt; ti++)
        for (uint32_t k = 0; k < db->t[ti]->nseg; k++)
            if (seg_droppable(c, db->t[ti]->seg[k]))
                v[m++] = (trim_ent){__atomic_load_n(&db->t[ti]->seg[k]->touched, __ATOMIC_RELAXED), ti, k};
    qsort(v, m, sizeof *v, cmp_trim);
    for (size_t i = 0; i < m && c->resident > c->budget; i++) seg_img_drop(db->t[v[i].ti]->seg[v[i].k]);
    imdb_free(v);
}

/* The open's streaming (3c-2): a pass that has finished with g lets its image go while the cache is over its budget, so
 * an open holds what it keeps, the budget and the images in hand, not the whole lake. Only while the open streams (the
 * flag), only on the engine thread with no parallel loop running, and only for an image no pointer of the caller's
 * still reads: the passes call it for a segment their walk has left (vid order: none comes back to it in that pass). */
void imdb_seg_release_one(imdb_segment *g)
{
    imdb_segcache *c = g ? g->cache : NULL;
    if (c && c->streaming && c->resident > c->budget && seg_droppable(c, g)) seg_img_drop(g);
}

/* P2 S15 (the 2026-11-05 review's O3, its first step): a releasing statement's path has left g and keeps no pointer into
 * its image (sql_exec.c: exec_select's allow-list): while the cache is over its budget, the image leaves now, not when
 * the operation ends. On the engine thread, no parallel loop running (a statement's paths), so no load is in flight;
 * the loading flag is checked all the same. One the cache did not charge, or whose objects are not on disk, stays */
void imdb_seg_done(const imdb_table *t, imdb_segment *g)
{
    imdb_segcache *c = t ? t->segcache : NULL;
    if (!c || !g || g->cache != c || c->resident <= c->budget || g->loading || !seg_droppable(c, g)) return;
    seg_img_drop(g);
    c->released++;
}

/* Between the open's replayed commits: no pointer into an image is held, so the cache trims as at an operation's end */
void imdb_seg_trim_streaming(imdb_db *db)
{
    if (!db->segcache.streaming) return;
    seg_trim(db);
    db->segcache.clock++; /* the open is one operation, one stamp: each commit's pins outrank the last's, so the trim
                           * drops the least recently used, not the lowest-numbered segments */
}

void imdb_op_enter(imdb_db *db)
{
    if (db->segcache.depth++ == 0) db->segcache.clock++;
}

void imdb_op_leave(imdb_db *db)
{
    if (!db->segcache.depth) return;
    if (--db->segcache.depth == 0) seg_trim(db);
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
    imdb_free(b);
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

/* the snapshot commit's algorithm and signature, under the key in effect at it */
static int snapshot_checked(imdb_db *db, uint64_t seq, const imdb_commit_rec *c, imdb_err *e)
{
    if (c->alg != db->meta.digest_alg)
        return imdb_fail(e, IMDB_ERR_CORRUPT, "commit %llu: digest algorithm %u, but this database's is %u",
                         (unsigned long long)seq, c->alg, db->meta.digest_alg);
    if (c->promote || !imdb_commit_sig_valid(imdb_writer_key_at(db, seq), c->seq, c->hlen, c->hash, c->sig))
        return imdb_fail(e, IMDB_ERR_AUTH, "commit %llu: signature invalid (under the writer key of epoch %u)",
                         (unsigned long long)seq, imdb_writer_epoch_at(db, seq));
    return IMDB_OK;
}

/* Commit seq, which must be the last frame of its segment, decoded and its
 * signature checked. */
static int snapshot_commit(imdb_db *db, uint64_t seq, imdb_commit_rec *c, uint8_t **buf, size_t *len, snap_seg *ss,
                           imdb_err *e)
{
    size_t si = imdb_logseg_find(db->segs, db->nsegs, seq);
    if (si == db->nsegs && db->floor_hdr && seq == db->log_floor) {
        /* a seeded copy's snapshot: its log begins after the floor, whose header and signature FLOOR holds (the open
         * checked them); the next append begins a segment */
        if (imdb_commit_decode_header(db->floor_hdr, db->floor_hlen, c, e)) return e->code;
        c->hlen = db->floor_hlen;
        memcpy(c->sig, db->floor_sig, IMDB_SIG_LEN);
        ss->last = false;
        return snapshot_checked(db, seq, c, e);
    }
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
    return snapshot_checked(db, seq, c, e);
}

static int load_table(imdb_db *db, int ofd, const imdb_manifest_tab *mt, uint32_t ti, uint64_t seq, uint64_t boundary,
                      imdb_err *e)
{
    imdb_schema s = mt->s;
    if (imdb_table_new(db, &s, e)) return e->code;
    imdb_table *t = db->t[ti];
    t->horizon = mt->horizon;
    t->retention_us = mt->retention_us;
    t->created_at = mt->created_at;
    t->dropped_at = mt->dropped_at; /* now: a later table of the same name finds it free */
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
        imdb_segment *g;
        if (imdb_segment_parse(&t->s, sb, sl, mt->seg[k].seg, &g, e)) { /* read_obj checked the name */
            imdb_free(sb);
            return e->code;
        }
        g->pos = t->nseg; /* its place in the list (plan_install keeps it) */
        t->seg[t->nseg++] = g;
        seg_charge(t->segcache, g); /* the snapshot's images: the open's end trims them to the budget */
        imdb_segimg *gi = imdb_seg_pin(t, g, e); /* the deletion vector's ends go into its image */
        if (!gi) return e->code;
        if (g->nrows != mt->seg[k].nrows || !g->nrows) /* a segment is never empty (segs_in_order) */
            return imdb_fail(e, IMDB_ERR_CORRUPT, "snapshot: segment row count");
        if (!all_zero(mt->seg[k].dv, 32)) {
            uint8_t *dvb, sh[32];
            size_t dl;
            imdb_dv_ent *ents;
            uint32_t n;
            if (read_obj(ofd, mt->seg[k].dv, ".dv", &dvb, &dl, e)) return e->code;
            int rc = imdb_dv_parse(dvb, dl, sh, &ents, &n, g->nrows, e);
            imdb_free(dvb);
            if (rc) return rc;
            for (uint32_t i = 0; i < n && !rc; i++) {
                if (ents[i].end > seq) rc = imdb_fail(e, IMDB_ERR_CORRUPT, "snapshot: DV records a later delete");
                else gi->end[ents[i].row] = ents[i].end;
            }
            imdb_free(ents);
            if (rc) return rc;
            if (memcmp(sh, g->hash, 32) != 0) return imdb_fail(e, IMDB_ERR_CORRUPT, "snapshot: DV names another segment");
            memcpy(g->dv_hash, mt->seg[k].dv, 32);
        }
        seg_marks(g, gi); /* the published ends: the replay of the log past the snapshot keeps them (imdb_seg_set_end) */
        g->ondisk = g->seg_ondisk = true; /* the segment and its deletion vector were read from objects/ */
        imdb_seg_release_one(g); /* 3c-2: its marks and descriptor stand; phase 2 reads it again if it left */
    }
    /* The rows are authenticated (each segment by its name, the manifest by the log's hash of it): every version
     * they hold, once, in vid order: each segment's vids ascend (imdb_segment_parse) and each segment's first is past
     * the last of the one before it, checked here, which also proves no version twice. A database never retired holds
     * every vid below the count, so the count is the rows'; past a boundary the others are those a RETIRE dropped.
     * The store gets a chunk only where a row lands (and the last, where vids are appended), dense or, past a
     * boundary, sparse: what was read bounds what is allocated, the count only the chunk directory (limits.h). */
    uint64_t held = 0;
    for (uint32_t k = 0; k < t->nseg; k++) held += t->seg[k]->nrows;
    if (mt->versions < held || (!boundary && mt->versions != held) || mt->versions > IMDB_MAX_VERSIONS)
        return imdb_fail(e, IMDB_ERR_CORRUPT, "snapshot: the version count does not fit the segments' rows");
    if (imdb_ver_load_begin(t, mt->versions, e)) return e->code;
    int rc = IMDB_OK;
    uint64_t live = 0, last = 0;
    bool any = false;
    uint32_t sk = 0, si = 0; /* the next row: segment sk, row si */
    uint64_t floor = db->mem_floor; /* a row ended at or before it stays the lake's alone (stage 3b) */
    for (uint32_t k = 0; k < t->nchunk && !rc; k++) {
        uint64_t rows = 0, cnt = 0; /* chunk k's rows, the run from the cursor, and those the store takes */
        for (uint32_t ck = sk, ci = si; ck < t->nseg;) {
            imdb_segment *g = t->seg[ck];
            const imdb_segimg *gi = imdb_seg_pin(t, g, e);
            if (!gi) {
                rc = e->code;
                break;
            }
            if (ci >= g->nrows) {
                ck++;
                ci = 0;
            } else if (gi->vid[ci] >> IMDB_VCHUNK_BITS == k) {
                rows++;
                cnt += !ended_by(gi->end[ci], floor);
                ci++;
            } else {
                break;
            }
        }
        if (!rows && k + 1 < t->nchunk) continue;
        if ((cnt || k + 1 == t->nchunk) && (rc = imdb_ver_load_chunk(t, k, cnt, e))) break;
        for (uint64_t j = 0, i = 0; j < rows && !rc;) {
            imdb_segment *g = t->seg[sk];
            const imdb_segimg *gi = imdb_seg_pin(t, g, e);
            if (!gi) {
                rc = e->code;
                break;
            }
            if (si >= g->nrows) {
                imdb_seg_release_one(g); /* wholly behind the cursor: placed (3c-2) */
                sk++;
                si = 0;
                continue;
            }
            uint64_t vid = gi->vid[si];
            if (vid >= t->nver || (any && vid <= last) || gi->begin[si] > seq ||
                (gi->end[si] != IMDB_LIVE && gi->end[si] <= boundary)) {
                rc = imdb_fail(e, IMDB_ERR_CORRUPT, "snapshot: segments do not hold each version once, past the boundary");
                break;
            }
            live += gi->end[si] == IMDB_LIVE;
            last = vid;
            any = true;
            if (!ended_by(gi->end[si], floor)) {
                imdb_version *v = imdb_ver_load_put(t, vid, (uint32_t)i++); /* its salt and commitment stay its row's */
                v->begin = gi->begin[si];
                v->end = gi->end[si];
                v->pk_prev = IMDB_NONE;
                v->seg = sk;
                v->seg_row = si;
                v->flags = IMDB_V_SEG | ((gi->flags[si] & IMDB_SEG_STUB) ? IMDB_V_STUB : 0) |
                           ((gi->flags[si] & IMDB_SEG_PURGED) ? IMDB_V_PURGED : 0);
            }
            si++;
            j++;
        }
    }
    while (!rc && sk < t->nseg && si >= t->seg[sk]->nrows) {
        imdb_seg_release_one(t->seg[sk]);
        sk++;
        si = 0;
    }
    if (!rc && sk < t->nseg) /* a row in no chunk: past the count, or out of order */
        rc = imdb_fail(e, IMDB_ERR_CORRUPT, "snapshot: segments do not hold each version once, past the boundary");
    if (rc) return rc;
    if (live != mt->live) return imdb_fail(e, IMDB_ERR_CORRUPT, "snapshot: live count differs from the manifest");
    t->live = live;
    t->mem_first = t->nver;
    rc = imdb_table_reindex(t, e); /* in version order, as incremental insertion builds them (RETIRE's too) */
    /* the unique chains from the live versions, before the log's tail is replayed (it is checked
     * against them); the ordered structures are built at the open's end */
    for (uint32_t k = 0; k < t->nidx && !rc; k++)
        if ((rc = imdb_index_unique_build(t, &t->idx[k], e)) == IMDB_ERR_CONSTRAINT)
            rc = imdb_fail(e, IMDB_ERR_CORRUPT, "snapshot: two live rows of table %s share a key of unique index %s",
                           t->s.name, t->idx[k].d.name);
    return rc;
}

/* Before a full replay (1f): a lake whose head manifest is of an older format is refused by name, as the snapshot
 * load refuses it, not rebuilt by the replay into another version's manifest and then reported as a divergence.
 * Only that answer is an error here; anything else the replay meets on its own terms. */
int imdb_lake_format_check(imdb_db *db, imdb_err *e)
{
    bool present;
    uint64_t S;
    uint8_t mh[32];
    imdb_err e2 = {0};
    if (read_head(db, &present, &S, mh, &e2) || !present) return IMDB_OK;
    int ofd = open_objects(db, &e2);
    if (ofd < 0) return IMDB_OK;
    uint8_t *mb = NULL;
    size_t ml = 0;
    int rc = IMDB_OK;
    if (!read_obj(ofd, mh, ".man", &mb, &ml, &e2)) {
        imdb_rd r;
        imdb_rd_init(&r, mb, ml);
        const uint8_t *mg = imdb_rd_bytes(&r, 8);
        uint32_t ver = imdb_rd_u32(&r);
        if (mg && !r.err && memcmp(mg, kManMagic, 8) == 0 && ver >= 2 && ver <= 5) rc = old_manifest(ver, e); /* P2 S7: 5 */
    }
    imdb_free(mb);
    close(ofd);
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
    db->mem_floor = imdb_window_floor(db, S); /* stage 3b: the store takes no row ended at or before it */
    db->segcache.snap_seq = S; /* a segment the open read again: its vector's ends are bounded by S (db->seq is 0) */
    uint64_t nsegs = 0, segs_done = 0; /* P1 M2: the open's progress through the lake, table by table */
    for (uint32_t ti = 0; ti < m.nt; ti++) nsegs += m.t[ti].nseg;
    for (uint32_t ti = 0; !rc && ti < m.nt; ti++) {
        rc = load_table(db, ofd, &m.t[ti], ti, S, m.boundary, e);
        segs_done += m.t[ti].nseg;
        if (!rc) imdb_progress(db, "lake", segs_done, nsegs, false);
    }
    if (!rc) imdb_progress(db, "lake", nsegs, nsegs, true);
    if (!rc && m.nv) { /* P2 S7: the views, every definition the manifest's catalog's now */
        if (!(db->views = imdb_alloc_array(m.nv, sizeof *db->views, e))) rc = e->code;
        for (uint32_t i = 0; !rc && i < m.nv; i++) {
            imdb_view *v = &db->views[i];
            v->id = m.v[i].id;
            memcpy(v->name, m.v[i].name, sizeof v->name);
            v->created_at = m.v[i].created_at;
            v->dropped_at = m.v[i].dropped_at;
            v->def = m.v[i].def;
            m.v[i].def = NULL;
        }
        if (!rc) db->nviews = db->capviews = m.nv;
    }
    db->segcache.snap_seq = 0;
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
        db->boundary = m.boundary;
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
    imdb_free(cbuf);
    imdb_free(mb);
    imdb_free(pb);
    close(ofd);
    imdb_lake_unpin(pin); /* the segments are in memory now: the files are no longer read */
    return rc;
}
