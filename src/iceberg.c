/* F5c (docs/f5c-design.md section 8): the Iceberg v3 layer per copy (iceberg.h): each live table's snapshots of the
 * lake's kept generations (the head and the one GC keeps beside it), written whole or compared with the files. */
#include "iceberg.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "db_internal.h"
#include "fsio.h"
#include "icecodec.h"
#include "lake.h"
#include "limits.h"
#include "sha256.h"

/* a path in the layer: a table's location (the database directory's, bounded at the entry), its metadata directory, a file
 * in it: each buffer sized by its parts */
enum { ICE_PATH = 4096, ICE_MPATH = ICE_PATH + 16, ICE_FPATH = ICE_MPATH + 320 };

static int g_lie;        /* tests only (imdb_iceberg_set_lie): the writer's lie, 0 none */

/* Iceberg v3's manifest entry and manifest file records (spec.md "Manifests" and "Manifest Lists"), the fields this
 * layer writes, in the order of the Java implementation's schemas; readers match them by field id */
static const char kEntrySchema[] =
    "{\"type\":\"record\",\"name\":\"manifest_entry\",\"fields\":["
    "{\"name\":\"status\",\"type\":\"int\",\"field-id\":0},"
    "{\"name\":\"snapshot_id\",\"type\":[\"null\",\"long\"],\"default\":null,\"field-id\":1},"
    "{\"name\":\"sequence_number\",\"type\":[\"null\",\"long\"],\"default\":null,\"field-id\":3},"
    "{\"name\":\"file_sequence_number\",\"type\":[\"null\",\"long\"],\"default\":null,\"field-id\":4},"
    "{\"name\":\"data_file\",\"type\":{\"type\":\"record\",\"name\":\"r2\",\"fields\":["
    "{\"name\":\"content\",\"type\":\"int\",\"field-id\":134},"
    "{\"name\":\"file_path\",\"type\":\"string\",\"field-id\":100},"
    "{\"name\":\"file_format\",\"type\":\"string\",\"field-id\":101},"
    "{\"name\":\"partition\",\"type\":{\"type\":\"record\",\"name\":\"r102\",\"fields\":[]},\"field-id\":102},"
    "{\"name\":\"record_count\",\"type\":\"long\",\"field-id\":103},"
    "{\"name\":\"file_size_in_bytes\",\"type\":\"long\",\"field-id\":104},"
    "{\"name\":\"first_row_id\",\"type\":[\"null\",\"long\"],\"default\":null,\"field-id\":142},"
    "{\"name\":\"referenced_data_file\",\"type\":[\"null\",\"string\"],\"default\":null,\"field-id\":143},"
    "{\"name\":\"content_offset\",\"type\":[\"null\",\"long\"],\"default\":null,\"field-id\":144},"
    "{\"name\":\"content_size_in_bytes\",\"type\":[\"null\",\"long\"],\"default\":null,\"field-id\":145}"
    "]},\"field-id\":2}]}";

static const char kListSchema[] =
    "{\"type\":\"record\",\"name\":\"manifest_file\",\"fields\":["
    "{\"name\":\"manifest_path\",\"type\":\"string\",\"field-id\":500},"
    "{\"name\":\"manifest_length\",\"type\":\"long\",\"field-id\":501},"
    "{\"name\":\"partition_spec_id\",\"type\":\"int\",\"field-id\":502},"
    "{\"name\":\"content\",\"type\":\"int\",\"field-id\":517},"
    "{\"name\":\"sequence_number\",\"type\":\"long\",\"field-id\":515},"
    "{\"name\":\"min_sequence_number\",\"type\":\"long\",\"field-id\":516},"
    "{\"name\":\"added_snapshot_id\",\"type\":\"long\",\"field-id\":503},"
    "{\"name\":\"added_files_count\",\"type\":\"int\",\"field-id\":504},"
    "{\"name\":\"existing_files_count\",\"type\":\"int\",\"field-id\":505},"
    "{\"name\":\"deleted_files_count\",\"type\":\"int\",\"field-id\":506},"
    "{\"name\":\"added_rows_count\",\"type\":\"long\",\"field-id\":512},"
    "{\"name\":\"existing_rows_count\",\"type\":\"long\",\"field-id\":513},"
    "{\"name\":\"deleted_rows_count\",\"type\":\"long\",\"field-id\":514},"
    "{\"name\":\"first_row_id\",\"type\":[\"null\",\"long\"],\"default\":null,\"field-id\":520}"
    "]}";

enum { POS_FIELD = 2147483645 }; /* Iceberg's _pos: the field a deletion vector's positions are of */

/* an Iceberg type for column c, or NULL for one left out of the Iceberg schema (ENUM, INTERVAL) */
static const char *ice_type(const imdb_column *c, char *buf, size_t cap)
{
    switch (c->type) {
    case IMDB_T_INT64: return c->precision == 16 || c->precision == 32 ? "int" : "long";
    case IMDB_T_DECIMAL: snprintf(buf, cap, "decimal(%u,%u)", (unsigned)c->precision, (unsigned)c->scale); return buf;
    case IMDB_T_TEXT: return "string";
    case IMDB_T_BYTEA: return "binary";
    case IMDB_T_BOOL: return "boolean";
    case IMDB_T_FLOAT64: return "double";
    case IMDB_T_DATE: return "date";
    case IMDB_T_TIME: return "time";
    case IMDB_T_TIMESTAMP: return "timestamp";
    case IMDB_T_TIMESTAMPTZ: return "timestamptz";
    case IMDB_T_UUID: return "uuid";
    default: return NULL;
    }
}

/* microseconds since midnight as Iceberg's ISO-8601 time, always six fractional digits */
static void put_tod(imdb_buf *b, int64_t us)
{
    imdb_buf_printf(b, "%02d:%02d:%02d.%06d", (int)(us / 3600000000), (int)(us / 60000000 % 60), (int)(us / 1000000 % 60),
                    (int)(us % 1000000));
}

/* a value in Iceberg's JSON single-value serialization (spec.md Appendix D), for column c's Iceberg type */
static void put_value(ij *j, const imdb_column *c, const imdb_value *v)
{
    imdb_buf b;
    imdb_buf_init(&b);
    switch (c->type) {
    case IMDB_T_INT64: ij_i64(j, v->i); break;
    case IMDB_T_BOOL: ij_bool(j, v->i != 0); break;
    case IMDB_T_FLOAT64: /* imagedb's text of a finite double is a JSON number: a fraction or an exponent always, a double's */
        imdb_format_value(v, &b);
        if (!b.err && !memchr(b.p, '.', b.len) && !memchr(b.p, 'e', b.len) && !memchr(b.p, 'E', b.len)) imdb_buf_put_str(&b, ".0");
        imdb_buf_put_u8(&b, 0);
        if (!b.err) ij_raw(j, (const char *)b.p);
        break;
    case IMDB_T_TEXT: ij_str(j, (const char *)v->s, v->len); break;
    case IMDB_T_UUID: imdb_format_uuid(v->s, &b); break;
    case IMDB_T_BYTEA: /* hexadecimal, as Appendix D's example writes it, lower case (its case is undefined: Java writes upper and
                        * reads either, iceberg-go writes lower; apache/iceberg issue 18352) */
        for (uint32_t k = 0; k < v->len; k++) imdb_buf_printf(&b, "%02x", v->s[k]);
        break;
    case IMDB_T_DATE: imdb_format_date(v->i, &b); break;
    case IMDB_T_TIME: put_tod(&b, v->i); break;
    case IMDB_T_TIMESTAMP:
    case IMDB_T_TIMESTAMPTZ: {
        int64_t days = v->i / 86400000000, tod = v->i % 86400000000;
        if (tod < 0) {
            tod += 86400000000;
            days--;
        }
        imdb_format_date(days, &b);
        imdb_buf_put_u8(&b, 'T');
        put_tod(&b, tod);
        if (c->type == IMDB_T_TIMESTAMPTZ) imdb_buf_put_str(&b, "+00:00"); /* the instant, in UTC: the spec's one offset */
        break;
    }
    default: imdb_format_value(v, &b); break; /* DECIMAL: its digits to its scale, a string */
    }
    if (c->type != IMDB_T_INT64 && c->type != IMDB_T_BOOL && c->type != IMDB_T_FLOAT64 && c->type != IMDB_T_TEXT && !b.err)
        ij_str(j, (const char *)b.p, b.len);
    if (b.err) j->b->err = true; /* the value lost: the file it was for never written */
    imdb_buf_free(&b);
}

/* tests only (iceberg.h) */
void imdb_iceberg_value_json(const imdb_column *c, const imdb_value *v, imdb_buf *out)
{
    ij j;
    ij_begin(&j, out);
    put_value(&j, c, v);
}

/* schema version vi of table t as an Iceberg schema object: each live column Iceberg types, its id its position + 1,
 * required when NOT NULL, and a column an ALTER added with a DEFAULT its initial-default (what an older file's rows
 * answer for it: F1's missing value) */
static void put_schema(ij *j, const imdb_table *t, uint32_t vi)
{
    const imdb_sver *v = &t->hist.vers[vi];
    char tb[40];
    ij_obj(j);
    ij_key(j, "type");
    ij_cstr(j, "struct");
    ij_key(j, "schema-id");
    ij_i64(j, vi);
    ij_key(j, "fields");
    ij_arr(j);
    for (uint16_t c = 0; c < v->s.ncols; c++) {
        const imdb_column *col = &v->s.cols[c];
        const char *ty = ice_type(col, tb, sizeof tb);
        if (!ty) continue;
        const imdb_tcol *tc = &t->hist.tcol[v->pos[c]];
        ij_obj(j);
        ij_key(j, "id");
        ij_i64(j, (int64_t)v->pos[c] + 1);
        ij_key(j, "name");
        ij_cstr(j, col->name);
        ij_key(j, "required");
        bool req = !(col->flags & IMDB_COL_NULLABLE); /* optional once nullable: optional to required is no evolution */
        for (uint32_t vj = 0; req && vj < vi; vj++) {
            int8_t at = v->pos[c] < t->hist.vers[vj].npos ? t->hist.vers[vj].at[v->pos[c]] : -1;
            if (at >= 0 && (t->hist.vers[vj].s.cols[at].flags & IMDB_COL_NULLABLE)) req = false;
        }
        if (g_lie == ICE_LIE_REQUIRED && c == 0) req = !req; /* tests: each version's first field's required flipped */
        ij_bool(j, req);
        ij_key(j, "type");
        ij_cstr(j, ty);
        if (tc->added > 1 && !tc->missing.null) {
            ij_key(j, "initial-default");
            imdb_value mv = tc->missing;
            if (g_lie == ICE_LIE_DEFAULT && col->type == IMDB_T_INT64) mv.i ^= 1; /* tests: an initial-default another */
            put_value(j, col, &mv);
        }
        ij_end_obj(j);
    }
    ij_end_arr(j);
    ij_end_obj(j);
}

static void hex32(const uint8_t h[32], char out[65])
{
    static const char hx[] = "0123456789abcdef";
    for (int i = 0; i < 32; i++) {
        out[2 * i] = hx[h[i] >> 4];
        out[2 * i + 1] = hx[h[i] & 15];
    }
    out[64] = 0;
}

/* a directory of the layer, made where missing. Its entry in its parent is synced by every layer write (a table's and
 * iceberg/ before the sidecar; the sidecar's own write syncs iceberg/'s entries), never only when made: a sync that failed
 * once would otherwise leave an entry no later write syncs (fault_iceberg, boundary call 28) */
static int mkdir_at(int dirfd, const char *name, int *out, imdb_err *e)
{
    if (imdb_io_mkdirat(dirfd, name, 0700) != 0 && errno != EEXIST)
        return imdb_fail(e, IMDB_ERR_IO, "iceberg: mkdir %s: %s", name, strerror(errno));
    *out = imdb_open_dir_at(dirfd, name, e);
    return *out < 0 ? e->code : IMDB_OK;
}

static int cmp_u64(const void *a, const void *b)
{
    uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;
    return (x > y) - (x < y);
}

/* tests only (iceberg.h): the writer's lie, 0 none */
void imdb_iceberg_set_lie(int kind) { g_lie = kind; }
uint64_t imdb_iceberg_reads(const imdb_db *db) { return db->ice_reads; }

/* ---- what a layer found, kept for the next (db->ice_seen): a vector is its segment's and its deletion vector's alone
 * (the rows the vector ends, all at or before the generation that wrote it, and the flagged rows), so a pair the last
 * layer found needs no read, and its Puffin file, named by the pair, no write. VERIFY never reads it ---- */

typedef struct icache {
    const imdb_ice_seen *old; /* the last layer's, sorted by (seg, dv), each pair once */
    uint32_t nold;
    imdb_ice_seen *nw;        /* this one's (a pair in both snapshots twice until the end), the next layer's */
    uint32_t nnew, capnew;
} icache;

static int seen_cmp(const void *a, const void *b)
{
    const imdb_ice_seen *x = a, *y = b;
    int c = memcmp(x->seg, y->seg, 32);
    return c ? c : memcmp(x->dv, y->dv, 32);
}

static const imdb_ice_seen *seen_find(const icache *cx, const imdb_manifest_seg *ms)
{
    if (!cx || !cx->nold) return NULL;
    imdb_ice_seen key;
    memcpy(key.seg, ms->seg, 32);
    memcpy(key.dv, ms->dv, 32);
    return bsearch(&key, cx->old, cx->nold, sizeof key, seen_cmp);
}

static int seen_add(icache *cx, const imdb_manifest_seg *ms, uint64_t ndead, uint64_t psize, uint64_t blen, imdb_err *e)
{
    if (!cx) return IMDB_OK;
    if (cx->nnew == cx->capnew) {
        if (cx->capnew > UINT32_MAX / 2) return imdb_fail(e, IMDB_ERR_LIMIT, "iceberg: too many segments");
        uint32_t cap = cx->capnew ? cx->capnew * 2 : 64;
        imdb_ice_seen *nn = imdb_alloc_array(cap, sizeof *nn, e);
        if (!nn) return e->code;
        if (cx->nnew) memcpy(nn, cx->nw, sizeof *nn * cx->nnew);
        imdb_free(cx->nw);
        cx->nw = nn;
        cx->capnew = cap;
    }
    imdb_ice_seen *s = &cx->nw[cx->nnew++];
    memcpy(s->seg, ms->seg, 32);
    memcpy(s->dv, ms->dv, 32);
    s->ndead = ndead;
    s->psize = psize;
    s->blen = blen;
    return IMDB_OK;
}

/* ---- a layer's output: its files written whole (temporary, synced, renamed), or compared with those on disk ---- */

typedef struct iout {
    bool verify;  /* VERIFY: each file compared with the one on disk, nothing written */
    bool dirsync_later; /* a table's files: its directory synced once after the last (write_table) */
    char (*names)[96];
    uint32_t nnames, capnames; /* the files this table's layer names (the rest of its directory goes) */
} iout;

static int name_cmp(const void *a, const void *b) { return strcmp(a, b); }

static int name_add(iout *o, const char *name, imdb_err *e)
{
    if (o->nnames == o->capnames) {
        uint32_t cap = o->capnames ? o->capnames * 2 : 16;
        char(*nn)[96] = imdb_alloc_array(cap, sizeof *nn, e);
        if (!nn) return e->code;
        if (o->nnames) memcpy(nn, o->names, sizeof *nn * o->nnames);
        imdb_free(o->names);
        o->names = nn;
        o->capnames = cap;
    }
    snprintf(o->names[o->nnames++], sizeof o->names[0], "%s", name);
    return IMDB_OK;
}

/* a file of the layer: written (keep_same: a file already there with these bytes kept, unwritten: a Puffin file, named by
 * what it holds), or under VERIFY compared */
static int out_file(iout *o, int dirfd, const char *name, const imdb_buf *b, bool keep_same, imdb_err *e)
{
    int rc = imdb_buf_check(b, e);
    if (!rc) rc = name_add(o, name, e);
    if (rc) return rc;
    if (!o->verify && !keep_same) return o->dirsync_later ? imdb_write_file_renamed(dirfd, name, b->p, b->len, 0600, e)
                                                     : imdb_write_file_atomic(dirfd, name, b->p, b->len, 0600, e);
    uint8_t *cur = NULL;
    size_t len = 0;
    imdb_err e2 = {0};
    rc = imdb_read_file_at(dirfd, name, &cur, &len, IMDB_MAX_OBJECT, &e2);
    bool same = !rc && len == b->len && !memcmp(cur, b->p, len);
    imdb_free(cur);
    if (!o->verify && same) return IMDB_OK;
    if (!o->verify) return o->dirsync_later ? imdb_write_file_renamed(dirfd, name, b->p, b->len, 0600, e)
                                            : imdb_write_file_atomic(dirfd, name, b->p, b->len, 0600, e);
    return same ? IMDB_OK : imdb_fail(e, IMDB_ERR_VERIFY, "iceberg: %s is not the file the lake gives", name);
}

/* ---- what a snapshot holds -------------------------------------------------------------------------------- */

typedef struct ifile {
    const imdb_manifest_seg *ms; /* its segment and deletion vector, as its generation's manifest names them */
    uint64_t size;               /* the segment file's bytes */
    bool existing;               /* in the older kept generation too: EXISTING, carrying the older snapshot's values */
    const struct ifile *twin;    /* EXISTING: the older snapshot's file of this segment (its vector made already) */
    uint64_t first_row;          /* its first_row_id: inherited where ADDED, written where EXISTING */
    char puffin[80];             /* its vector's Puffin file ("": no row dead at the snapshot) */
    uint64_t ndead, psize, blen; /* the vector's rows, its Puffin file's bytes, its blob's bytes */
} ifile;

typedef struct isnap {
    uint64_t S;          /* its label: its id and sequence number, the table's last change in its generation (manifest 21) */
    uint64_t at;         /* its read point: its generation's commit (the label may lie below a horizon or the boundary) */
    uint32_t ver;        /* the table's schema version at its read point */
    int64_t ms;          /* its time, milliseconds: the label's changed_us (the last commit its publication includes) */
    const imdb_manifest_tab *mt;
    ifile *f;            /* its data files, the manifest's segments in order */
    uint64_t first_row;  /* the snapshot's first-row-id, its data manifest's first_row_id */
    uint64_t added_rows, existing_rows;
    uint32_t nadded, nexisting, ndel;
    uint64_t delrows;
} isnap;

/* the positions of a segment's rows not live at its generation S: ended at or before S (that generation's deletion
 * vector) and flagged (a stub, purged): from the image only when the segment holds any (a resident descriptor's ndata
 * says so; a segment the table no longer holds is read from its file) */
static int dead_rows(imdb_db *db, imdb_table *t, const imdb_manifest_seg *ms, int ofd, uint64_t S, uint64_t **pos,
                     size_t *n, imdb_err *e)
{
    *pos = NULL;
    *n = 0;
    imdb_dv_ent *ents = NULL;
    uint32_t ne = 0;
    int rc = IMDB_OK;
    if (memcmp(ms->dv, (uint8_t[32]){0}, 32) != 0) {
        uint8_t *b = NULL, sh[32];
        size_t bl = 0;
        db->ice_reads++;
        if (!(rc = imdb_lake_read_object(ofd, ms->dv, ".dv", &b, &bl, e))) rc = imdb_dv_parse(b, bl, sh, &ents, &ne, ms->nrows, e);
        imdb_free(b);
        if (rc) return rc;
    }
    uint64_t *p = imdb_alloc_array(2 * (size_t)ms->nrows + 1, sizeof *p, e); /* a row both ended and flagged: twice, then one */
    if (!p) {
        imdb_free(ents);
        return e->code;
    }
    size_t k = 0;
    for (uint32_t i = 0; i < ne; i++)
        if (ents[i].end && ents[i].end <= S && ents[i].row < ms->nrows) p[k++] = ents[i].row;
    imdb_free(ents);
    imdb_segment *g = NULL;
    for (uint32_t s = 0; s < t->nseg && !g; s++)
        if (!memcmp(t->seg[s]->hash, ms->seg, 32)) g = t->seg[s];
    if (g && g->ndata < g->nrows) { /* a held segment with flagged rows: their positions from its image */
        imdb_op_enter(db);
        db->ice_reads++;
        const imdb_segimg *gi = imdb_seg_pin(t, g, e);
        if (gi)
            for (uint32_t i = 0; i < g->nrows; i++)
                if (gi->flags[i]) p[k++] = i;
        imdb_op_leave(db);
        if (!gi) rc = e->code;
    } else if (!g) { /* a segment of the older generation alone: its own parse, apart from the table */
        uint8_t *sb = NULL;
        size_t sl = 0;
        imdb_segment *x = NULL;
        if (!(rc = imdb_lake_read_object(ofd, ms->seg, ".seg", &sb, &sl, e)) &&
            !(rc = imdb_segment_parse_h(&t->hist, sb, sl, ms->seg, &x, e))) {
            db->ice_reads++;
            const imdb_segimg *xi = imdb_seg_pin(NULL, x, e);
            if (!xi) rc = e->code;
            for (uint32_t i = 0; xi && i < x->nrows; i++)
                if (xi->flags[i]) p[k++] = i;
            imdb_segment_free(x); /* it owns the bytes now */
        } else {
            imdb_free(sb);
        }
    }
    if (rc) {
        imdb_free(p);
        return rc;
    }
    qsort(p, k, sizeof *p, cmp_u64);
    size_t u = 0;
    for (size_t i = 0; i < k; i++)
        if (!u || p[i] != p[u - 1]) p[u++] = p[i];
    *pos = p;
    *n = u;
    return IMDB_OK;
}

/* a manifest entry: ADDED with its snapshot and sequence numbers and first_row_id inherited (null), or EXISTING with
 * each written; a data file (ref NULL) or a deletion vector (ref its data file, off and len its blob).
 * No column statistics (lower_bounds, upper_bounds, null and value counts): the layer holds no row's value (its vectors
 * positions, its manifests paths and counts, its schemas' initial-defaults a DDL's constants), and that is why a handle
 * with the layer off may leave a stale layer as it is, its ERASE included (design 8.8, item 1). A bound added here is a
 * row's value: then every handle must make or remove the layer at an ERASE, whatever its option */
static void put_entry(imdb_buf *r, bool existing, uint64_t S0, uint64_t frid, int content, const char *path,
                      const char *format, uint64_t count, uint64_t size, const char *ref, int64_t off, int64_t len)
{
    imdb_av_long(r, existing ? 0 : 1); /* status: EXISTING or ADDED */
    for (int k = 0; k < 3; k++) {      /* snapshot_id, sequence_number, file_sequence_number */
        imdb_av_long(r, existing);
        if (existing) imdb_av_long(r, (int64_t)S0);
    }
    imdb_av_long(r, content);
    imdb_av_str(r, path);
    imdb_av_str(r, format);
    /* partition: an empty record, nothing written */
    imdb_av_long(r, (int64_t)count);
    imdb_av_long(r, (int64_t)size);
    imdb_av_long(r, existing); /* first_row_id: an EXISTING data file's, else null */
    if (existing) imdb_av_long(r, (int64_t)frid);
    if (ref) {
        imdb_av_long(r, 1);
        imdb_av_str(r, ref);
        imdb_av_long(r, 1);
        imdb_av_long(r, off);
        imdb_av_long(r, 1);
        imdb_av_long(r, len);
    } else {
        imdb_av_long(r, 0);
        imdb_av_long(r, 0);
        imdb_av_long(r, 0);
    }
}

/* a manifest list's entry for a manifest */
static void put_mfile(imdb_buf *r, const char *path, uint64_t mlen, int content, uint64_t S, uint64_t minseq, uint32_t nadded, uint32_t nexist,
                      uint64_t arows, uint64_t erows, bool frid, uint64_t first_row)
{
    imdb_av_str(r, path);
    imdb_av_long(r, (int64_t)mlen);
    imdb_av_long(r, 0); /* partition_spec_id */
    imdb_av_long(r, content);
    imdb_av_long(r, (int64_t)S); /* sequence_number */
    imdb_av_long(r, (int64_t)minseq); /* min_sequence_number: an EXISTING file's is the older S */
    imdb_av_long(r, (int64_t)S); /* added_snapshot_id */
    imdb_av_long(r, nadded);
    imdb_av_long(r, nexist);
    imdb_av_long(r, 0);
    imdb_av_long(r, (int64_t)arows);
    imdb_av_long(r, (int64_t)erows);
    imdb_av_long(r, 0);
    imdb_av_long(r, frid);
    if (frid) imdb_av_long(r, (int64_t)first_row);
}

static void sync_of(uint32_t tid, uint64_t S, uint64_t H, const char *kind, uint8_t out[16])
{
    imdb_sha256_ctx c;
    uint8_t b[20], h[32];
    imdb_sha256_init(&c);
    imdb_sha256_update(&c, "imagedb.iceberg.sync", 20);
    imdb_le32(b, tid);
    imdb_le64(b + 4, S);
    imdb_le64(b + 12, H);
    imdb_sha256_update(&c, b, sizeof b);
    imdb_sha256_update(&c, kind, strlen(kind));
    imdb_sha256_final(&c, h);
    memcpy(out, h, 16);
}

/* the table's schema version at commit S: the last that began at or before it */
static uint32_t ver_at(const imdb_table *t, uint64_t S)
{
    uint32_t v = 0;
    for (uint32_t k = 0; k < t->hist.nvers; k++)
        if (t->hist.vers[k].since <= S) v = k;
    return v;
}

/* a data file's vector's Puffin file name: the SHA-256 of its segment's name and its deletion vector's, one name one content */
static void puffin_name(const imdb_manifest_seg *ms, char out[80])
{
    uint8_t ph[32];
    imdb_sha256_ctx pc;
    imdb_sha256_init(&pc);
    imdb_sha256_update(&pc, ms->seg, 32);
    imdb_sha256_update(&pc, ms->dv, 32);
    imdb_sha256_final(&pc, ph);
    char px[65];
    hex32(ph, px);
    snprintf(out, 80, "dv-%s.puffin", px);
}

/* the Puffin file of a data file's deletion vector (positions pos, ascending): its blob, then its footer naming the data file */
static int put_puffin(const char *name, const char *path, const uint64_t *pos, size_t np, int mfd, iout *o, uint64_t *psize,
                      uint64_t *blen, imdb_err *e)
{
    imdb_buf puf, blob, foot;
    imdb_buf_init(&puf);
    imdb_buf_init(&blob);
    imdb_buf_init(&foot);
    int rc = imdb_dv_blob(&blob, pos, np, e);
    if (!rc) {
        ij j;
        char card[24];
        snprintf(card, sizeof card, "%zu", np);
        ij_begin(&j, &foot);
        ij_obj(&j);
        ij_key(&j, "blobs");
        ij_arr(&j);
        ij_obj(&j);
        ij_key(&j, "type");
        ij_cstr(&j, "deletion-vector-v1");
        ij_key(&j, "fields");
        ij_arr(&j);
        ij_i64(&j, POS_FIELD);
        ij_end_arr(&j);
        ij_key(&j, "snapshot-id");
        ij_i64(&j, -1);
        ij_key(&j, "sequence-number");
        ij_i64(&j, -1);
        ij_key(&j, "offset");
        ij_i64(&j, 4);
        ij_key(&j, "length");
        ij_i64(&j, (int64_t)blob.len);
        ij_key(&j, "properties");
        ij_obj(&j);
        ij_key(&j, "referenced-data-file");
        ij_cstr(&j, path);
        ij_key(&j, "cardinality");
        ij_cstr(&j, card);
        ij_end_obj(&j);
        ij_end_obj(&j);
        ij_end_arr(&j);
        ij_key(&j, "properties");
        ij_obj(&j);
        ij_key(&j, "created-by");
        ij_cstr(&j, "imagedb");
        ij_end_obj(&j);
        ij_end_obj(&j);
        if (!(rc = imdb_buf_check(&foot, e))) { /* a short footer never becomes a file's bytes */
            imdb_puffin_file(&puf, blob.p, blob.len, (const char *)foot.p, foot.len);
            /* written, never kept by name: only what this handle's last layer wrote and synced (db->ice_seen) is
             * trusted unwritten, so a file whose sync once failed is never taken for durable */
            rc = out_file(o, mfd, name, &puf, false, e);
        }
        *psize = puf.len;
        *blen = blob.len;
    }
    imdb_buf_free(&puf);
    imdb_buf_free(&blob);
    imdb_buf_free(&foot);
    return rc;
}

/* one snapshot's Puffin files (one a data file holding a row not live at S), its manifests and its manifest list; a
 * vector the last layer found (cx) is neither read nor written again while its Puffin file is there */
static int write_snap(imdb_db *db, imdb_table *t, isnap *sn, const isnap *older, bool head, const char *loc,
                      const char *mloc, int mfd, int ofd, icache *cx, iout *o, imdb_err *e)
{
    char hx[65], path[ICE_FPATH];
    imdb_buf data, dels;
    imdb_buf_init(&data);
    imdb_buf_init(&dels);
    int rc = IMDB_OK;
    uint64_t next_added = sn->first_row; /* an ADDED file's inherited first_row_id */
    bool lied = false;
    uint32_t nput = sn->mt->nseg;
    if (g_lie == ICE_LIE_FILE_OUT && head && nput > 1) nput--; /* tests: the head's data manifest leaves its last file out */
    for (uint32_t k = 0; !rc && k < nput; k++) {
        ifile *f = &sn->f[k];
        hex32(f->ms->seg, hx);
        snprintf(path, sizeof path, "%s/objects/%s.seg", loc, hx);
        bool existing = f->existing;
        if (g_lie == ICE_LIE_ADDED && head && existing && !lied) existing = false, lied = true; /* tests */
        if (existing) {
            sn->nexisting++;
            sn->existing_rows += f->ms->nrows;
        } else {
            f->first_row = next_added;
            next_added += f->ms->nrows;
            sn->nadded++;
            sn->added_rows += f->ms->nrows;
        }
        uint64_t frid = f->first_row;
        if (g_lie == ICE_LIE_FRID && head && existing && !lied) frid++, lied = true; /* tests: an EXISTING file's first row another */
        put_entry(&data, existing, older ? older->S : 0, frid, 0, path, "PARQUET", f->ms->nrows, f->size, NULL, 0, 0);
        puffin_name(f->ms, f->puffin);
        const imdb_ice_seen *hit = seen_find(cx, f->ms);
        if (hit && hit->ndead) { /* its Puffin file still there, of the size it was written */
            struct stat st;
            if (imdb_io_fstatat(mfd, f->puffin, &st, AT_SYMLINK_NOFOLLOW) != 0 || (uint64_t)st.st_size != hit->psize) hit = NULL;
        }
        if (!hit && f->twin && !memcmp(f->twin->ms->dv, f->ms->dv, 32) && !(g_lie && head)) {
            /* the older snapshot's file of this segment, its vector the same: its Puffin file made by this layer already */
            f->ndead = f->twin->ndead;
            f->psize = f->twin->psize;
            f->blen = f->twin->blen;
        } else if (hit) {
            f->ndead = hit->ndead;
            f->psize = hit->psize;
            f->blen = hit->blen;
            if (f->ndead) rc = name_add(o, f->puffin, e);
        } else {
            uint64_t *pos;
            size_t np;
            if ((rc = dead_rows(db, t, f->ms, ofd, sn->at, &pos, &np, e))) break; /* at its read point */
            if (head && !lied && g_lie == ICE_LIE_DV_MISSING && np >= 2) { /* tests: a vector without its first dead row */
                memmove(pos, pos + 1, (np - 1) * sizeof *pos);
                np--;
                lied = true;
            }
            bool swap = g_lie == ICE_LIE_DV_SWAP; /* tests: a dead row given for a live one, the count kept */
            if (head && !lied && (g_lie == ICE_LIE_DV_LIVE || swap) && np && np < f->ms->nrows) { /* tests: a live row in it */
                uint64_t r = 0;
                size_t at = 0;
                while (at < np && pos[at] == r) at++, r++; /* the first row not in it, and where it goes */
                memmove(pos + at + 1, pos + at, (np - at) * sizeof *pos); /* dead_rows' array has room for it */
                pos[at] = r;
                np++;
                lied = true;
                if (swap) { /* and its first dead row out */
                    size_t d0 = at == 0 ? 1 : 0;
                    memmove(pos + d0, pos + d0 + 1, (np - d0 - 1) * sizeof *pos);
                    np--;
                }
            }
            f->ndead = np;
            f->psize = f->blen = 0;
            if (np) rc = put_puffin(f->puffin, path, pos, np, mfd, o, &f->psize, &f->blen, e);
            imdb_free(pos);
        }
        if (!rc) rc = seen_add(cx, f->ms, f->ndead, f->psize, f->blen, e);
        if (!rc && f->ndead) {
            char ppath[ICE_FPATH];
            snprintf(ppath, sizeof ppath, "%s/%s", mloc, f->puffin);
            put_entry(&dels, false, 0, 0, 1, ppath, "PUFFIN", f->ndead, f->psize, path, 4, (int64_t)f->blen);
            sn->ndel++;
            sn->delrows += f->ndead;
        }
    }
    imdb_buf schema;
    imdb_buf_init(&schema);
    ij js;
    ij_begin(&js, &schema);
    put_schema(&js, t, sn->ver);
    imdb_buf_put_u8(&schema, 0);
    char sid[16], seqs[24], frs[24], par[24], mdata[96], mdel[96], lname[96];
    snprintf(sid, sizeof sid, "%u", (unsigned)sn->ver);
    snprintf(seqs, sizeof seqs, "%llu", (unsigned long long)sn->S);
    snprintf(frs, sizeof frs, "%llu", (unsigned long long)sn->first_row);
    snprintf(par, sizeof par, "%llu", older ? (unsigned long long)older->S : 0ull);
    /* names carry only what fixes their content (f5c-design 9.1): a lone snapshot c its own, a head c with an older p
     * both in its data manifest's (EXISTING entries are p's) and its list's; a delete manifest c alone (ADDED entries) */
    uint64_t p = older ? older->S : 0;
    if (older) snprintf(mdata, sizeof mdata, "m-%llu-%llu-data.avro", (unsigned long long)sn->S, (unsigned long long)p);
    else snprintf(mdata, sizeof mdata, "m-%llu-data.avro", (unsigned long long)sn->S);
    snprintf(mdel, sizeof mdel, "m-%llu-dv.avro", (unsigned long long)sn->S);
    if (older) snprintf(lname, sizeof lname, "snap-%llu-%llu.avro", (unsigned long long)sn->S, (unsigned long long)p);
    else snprintf(lname, sizeof lname, "snap-%llu.avro", (unsigned long long)sn->S);
    uint64_t mdlen = 0, mvlen = 0;
    imdb_buf fb;
    imdb_buf_init(&fb);
    if (!rc) rc = imdb_buf_check(&data, e); /* the entries, whole before they become a manifest's */
    if (!rc) rc = imdb_buf_check(&dels, e);
    if (!rc && !(rc = imdb_buf_check(&schema, e))) { /* the manifests */
        const char *md[] = {"schema", (const char *)schema.p, "schema-id", sid, "partition-spec", "[]",
                            "partition-spec-id", "0", "format-version", "3", "content", "data"};
        uint8_t sync[16];
        sync_of(t->s.id, sn->S, p, "data", sync);
        imdb_av_file(&fb, kEntrySchema, md, 6, sync, nput, data.p, data.len);
        mdlen = fb.len + (g_lie == ICE_LIE_MLEN && head); /* tests: a manifest_length another */
        rc = out_file(o, mfd, mdata, &fb, false, e);
        if (!rc && sn->ndel) {
            md[11] = "deletes";
            fb.len = 0;
            sync_of(t->s.id, sn->S, 0, "deletes", sync); /* the snapshot's alone, as its name */
            imdb_av_file(&fb, kEntrySchema, md, 6, sync, sn->ndel, dels.p, dels.len);
            mvlen = fb.len;
            rc = out_file(o, mfd, mdel, &fb, false, e);
        }
    }
    if (!rc) { /* the manifest list */
        imdb_buf r;
        imdb_buf_init(&r);
        snprintf(path, sizeof path, "%s/%s", mloc, mdata);
        put_mfile(&r, path, mdlen, 0, sn->S, sn->nexisting && older ? older->S : sn->S, sn->nadded, sn->nexisting,
                  sn->added_rows + (g_lie == ICE_LIE_COUNTS && head), /* tests: a count another */
                  sn->existing_rows, true, sn->first_row);
        if (sn->ndel) {
            snprintf(path, sizeof path, "%s/%s", mloc, mdel);
            put_mfile(&r, path, mvlen, 1, sn->S, sn->S, sn->ndel, 0, sn->delrows, 0, false, 0);
        }
        const char *lm[10]; /* the pairs Iceberg names, the parent's only where there is one */
        uint32_t nl = 0;
        lm[2 * nl] = "snapshot-id", lm[2 * nl++ + 1] = seqs;
        if (older) lm[2 * nl] = "parent-snapshot-id", lm[2 * nl++ + 1] = par;
        lm[2 * nl] = "sequence-number", lm[2 * nl++ + 1] = seqs;
        lm[2 * nl] = "first-row-id", lm[2 * nl++ + 1] = frs;
        lm[2 * nl] = "format-version", lm[2 * nl++ + 1] = "3";
        uint8_t sync[16];
        fb.len = 0;
        sync_of(t->s.id, sn->S, p, "list", sync);
        rc = imdb_buf_check(&r, e);
        if (!rc) {
            imdb_av_file(&fb, kListSchema, lm, nl, sync, sn->ndel ? 2 : 1, r.p, r.len);
            rc = out_file(o, mfd, lname, &fb, false, e);
        }
        imdb_buf_free(&r);
    }
    imdb_buf_free(&fb);
    imdb_buf_free(&schema);
    imdb_buf_free(&data);
    imdb_buf_free(&dels);
    return rc;
}

/* a manifest's entry for table id tid, or NULL */
static const imdb_manifest_tab *man_tab(const imdb_manifest *m, uint32_t tid)
{
    for (uint32_t i = 0; i < m->nt; i++)
        if (m->t[i].s.id == tid) return &m->t[i];
    return NULL;
}

/* the older kept generation's objects of table entry pt, each on disk: a seed brings the head generation's alone (its
 * retained manifest, not that generation's segments and vectors), so a copy seeded or restored offers the head alone */
static int older_present(const imdb_manifest_tab *pt, int ofd, bool *present, imdb_err *e)
{
    *present = true;
    for (uint32_t q = 0; q < pt->nseg && *present; q++)
        for (int z = 0; z < 2 && *present; z++) {
            const uint8_t *h = z ? pt->seg[q].dv : pt->seg[q].seg;
            if (z && !memcmp(h, (uint8_t[32]){0}, 32)) continue;
            char hx[65], nm[80];
            hex32(h, hx);
            snprintf(nm, sizeof nm, "%s%s", hx, z ? ".dv" : ".seg");
            struct stat st;
            if (imdb_io_fstatat(ofd, nm, &st, AT_SYMLINK_NOFOLLOW) == 0) continue;
            if (errno != ENOENT) return imdb_fail(e, IMDB_ERR_IO, "iceberg: objects/%s: %s", nm, strerror(errno));
            *present = false;
        }
    return IMDB_OK;
}

typedef struct hidx { /* a segment hash and its file's index: the older snapshot's files sorted for an EXISTING one's search */
    uint8_t h[32];
    uint32_t k;
} hidx;
static int hidx_cmp(const void *a, const void *b) { return memcmp(((const hidx *)a)->h, ((const hidx *)b)->h, 32); }

/* table t's layer (f5c-design 9.1): its head snapshot, labelled by its last change in the head generation m (manifest 21)
 * and read at m's commit; and, where pm_ok and the table changed at m (its label in pm, the generation m retains, lower),
 * the older snapshot, labelled by its last change in pm and read at pm's commit. skip_ok: the sidecar names pm and this
 * location (the layer was whole at pm): a table whose state is pm's (unchanged at m, and alone at pm) is not touched */
static int write_table(imdb_db *db, imdb_table *t, const imdb_manifest *m, const imdb_manifest *pm, bool pm_ok, bool skip_ok,
                       const char *loc, int icefd, int ofd, icache *cx, iout *o, imdb_err *e)
{
    const imdb_manifest_tab *mt = man_tab(m, t->s.id), *pt = pm ? man_tab(pm, t->s.id) : NULL;
    if (!mt || mt->dropped_at || !mt->nseg) return IMDB_OK;
    if (pt && (pt->dropped_at || !pt->nseg)) pt = NULL;
    char tname[24], tloc[ICE_PATH], mloc[ICE_MPATH], name[96];
    snprintf(tname, sizeof tname, "%u", (unsigned)t->s.id);
    if (!o->verify && skip_ok && pt && pt->changed == mt->changed && pt->changed != pm->seq) {
        /* unchanged at m and alone at pm: its files are the ones pm's layer wrote (each synced before that sidecar), so
         * none is read or written; its version hint still there, else written again (a hand that removed it) */
        char hp[64];
        snprintf(hp, sizeof hp, "%s/metadata/version-hint.text", tname);
        struct stat st;
        if (imdb_io_fstatat(icefd, hp, &st, AT_SYMLINK_NOFOLLOW) == 0) {
            /* what the last layer found for its vectors carried forward (the advisor, 22:1x): a table idle for several
             * publications, then written, reads and writes only what changed */
            int crc = IMDB_OK;
            for (uint32_t k = 0; k < mt->nseg && !crc; k++) {
                const imdb_ice_seen *hit = seen_find(cx, &mt->seg[k]);
                if (hit) crc = seen_add(cx, &mt->seg[k], hit->ndead, hit->psize, hit->blen, e);
            }
            return crc;
        }
    }
    if (pt && !(pm_ok && pt->changed < mt->changed)) pt = NULL; /* no older snapshot: none kept, or unchanged since */
    /* nor below the table's horizon at the head (a COMPACT's PURGE BEFORE past pm's commit): imagedb answers no AS OF
     * there (imdb_check_history), and pm's files still hold the versions purged, so the layer offers none either */
    if (pt && pm->seq < mt->horizon) pt = NULL;
    bool present = true;
    int rc = pt ? older_present(pt, ofd, &present, e) : IMDB_OK;
    if (rc) return rc;
    if (!present) pt = NULL;
    snprintf(tloc, sizeof tloc, "%s/iceberg/%s", loc, tname);
    snprintf(mloc, sizeof mloc, "%s/metadata", tloc);
    int tfd = -1, mfd = -1;
    if (o->verify) {
        tfd = imdb_open_dir_at(icefd, tname, e);
        mfd = tfd < 0 ? -1 : imdb_open_dir_at(tfd, "metadata", e);
        if (mfd < 0) rc = e->code;
    } else if (!(rc = mkdir_at(icefd, tname, &tfd, e))) {
        rc = mkdir_at(tfd, "metadata", &mfd, e);
    }
    isnap sn[2];
    memset(sn, 0, sizeof sn);
    uint32_t ns = 0;
    hidx *oidx = NULL; /* the older snapshot's files by segment hash: an EXISTING file's search */
    const imdb_manifest_tab *gens[2] = {pt, mt};
    const imdb_manifest *mans[2] = {pm, m};
    for (int k = 0; k < 2 && !rc; k++) {
        if (!gens[k]) continue;
        isnap *s = &sn[ns++];
        s->S = gens[k]->changed;
        s->at = mans[k]->seq;
        s->ver = ver_at(t, s->at);
        s->mt = gens[k];
        s->ms = (int64_t)(gens[k]->changed_us / 1000);
        s->f = imdb_alloc_array(gens[k]->nseg, sizeof *s->f, e);
        if (!s->f) rc = e->code;
        if (!rc && ns == 2) {
            if (!(oidx = imdb_alloc_array(sn[0].mt->nseg, sizeof *oidx, e))) rc = e->code;
            for (uint32_t r = 0; !rc && r < sn[0].mt->nseg; r++) {
                memcpy(oidx[r].h, sn[0].mt->seg[r].seg, 32);
                oidx[r].k = r;
            }
            if (!rc) {
                qsort(oidx, sn[0].mt->nseg, sizeof *oidx, hidx_cmp);
            }
        }
        for (uint32_t q = 0; !rc && q < gens[k]->nseg; q++) {
            ifile *f = &s->f[q];
            f->ms = &gens[k]->seg[q];
            char hx[65];
            hex32(f->ms->seg, hx);
            snprintf(name, sizeof name, "%s.seg", hx);
            struct stat st;
            if (imdb_io_fstatat(ofd, name, &st, AT_SYMLINK_NOFOLLOW) != 0) {
                rc = imdb_fail(e, IMDB_ERR_IO, "iceberg: objects/%s: %s", name, strerror(errno));
                break;
            }
            f->size = (uint64_t)st.st_size;
            if (ns == 2) { /* the head's: EXISTING where the older snapshot holds it, with that one's first_row_id */
                size_t lo = 0, hi = sn[0].mt->nseg;
                while (lo < hi) {
                    size_t mid = lo + (hi - lo) / 2;
                    int c = memcmp(oidx[mid].h, f->ms->seg, 32);
                    if (!c) {
                        f->existing = true;
                        f->first_row = sn[0].f[oidx[mid].k].first_row;
                        f->twin = &sn[0].f[oidx[mid].k];
                        break;
                    }
                    if (c < 0) lo = mid + 1;
                    else hi = mid;
                }
            }
        }
        /* the row-id ranges, each fixed by what its names carry: a lone or older snapshot's its own generation's vid count
         * (above every vid it holds); a head's with an older the greater of its own vid count and past the older's rows */
        uint64_t past = ns == 2 ? sn[0].first_row + sn[0].added_rows + sn[0].existing_rows : 0;
        s->first_row = ns == 1 ? gens[k]->versions : (gens[k]->versions > past ? gens[k]->versions : past);
        if (!rc) rc = write_snap(db, t, s, ns == 2 ? &sn[0] : NULL, k == 1, loc, mloc, mfd, ofd, cx, o, e);
    }
    imdb_free(oidx);
    imdb_buf meta;
    imdb_buf_init(&meta);
    if (!rc) { /* the table metadata at H, then the version hint */
        const isnap *head = &sn[ns - 1];
        uint8_t u[32], tb[4];
        imdb_sha256_ctx c;
        imdb_sha256_init(&c);
        imdb_sha256_update(&c, "imagedb.iceberg.table", 21);
        imdb_sha256_update(&c, db->db_id, 16);
        imdb_le32(tb, t->s.id);
        imdb_sha256_update(&c, tb, 4);
        imdb_sha256_final(&c, u);
        u[6] = (uint8_t)((u[6] & 0x0f) | 0x80); /* a version 8 UUID */
        u[8] = (uint8_t)((u[8] & 0x3f) | 0x80);
        char uuid[40];
        snprintf(uuid, sizeof uuid, "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x", u[0], u[1], u[2],
                 u[3], u[4], u[5], u[6], u[7], u[8], u[9], u[10], u[11], u[12], u[13], u[14], u[15]);
        int64_t lastcol = 0;
        for (uint32_t vi = 0; vi <= head->ver; vi++)
            for (uint16_t k = 0; k < t->hist.vers[vi].s.ncols; k++)
                if ((int64_t)t->hist.vers[vi].pos[k] + 1 > lastcol) lastcol = (int64_t)t->hist.vers[vi].pos[k] + 1;
        ij j;
        ij_begin(&j, &meta);
        ij_obj(&j);
        ij_key(&j, "format-version");
        ij_i64(&j, 3);
        ij_key(&j, "table-uuid");
        ij_cstr(&j, uuid);
        ij_key(&j, "location");
        ij_cstr(&j, tloc);
        ij_key(&j, "last-sequence-number");
        ij_i64(&j, (int64_t)head->S);
        ij_key(&j, "last-updated-ms");
        ij_i64(&j, head->ms);
        ij_key(&j, "last-column-id");
        ij_i64(&j, lastcol);
        ij_key(&j, "current-schema-id");
        ij_i64(&j, head->ver);
        ij_key(&j, "schemas");
        ij_arr(&j);
        for (uint32_t vi = 0; vi <= head->ver; vi++) put_schema(&j, t, vi); /* every version to H: an older file's by its ids */
        ij_end_arr(&j);
        ij_key(&j, "default-spec-id");
        ij_i64(&j, 0);
        ij_key(&j, "partition-specs");
        ij_raw(&j, "[{\"spec-id\":0,\"fields\":[]}]");
        ij_key(&j, "last-partition-id");
        ij_i64(&j, 999);
        ij_key(&j, "default-sort-order-id");
        ij_i64(&j, 0);
        ij_key(&j, "sort-orders");
        ij_raw(&j, "[{\"order-id\":0,\"fields\":[]}]");
        ij_key(&j, "properties");
        ij_obj(&j);
        ij_key(&j, "imagedb.table");
        ij_cstr(&j, mt->s.name);
        ij_end_obj(&j);
        ij_key(&j, "current-snapshot-id");
        ij_i64(&j, (int64_t)head->S);
        ij_key(&j, "refs");
        ij_obj(&j);
        ij_key(&j, "main");
        ij_obj(&j);
        ij_key(&j, "snapshot-id");
        ij_i64(&j, (int64_t)head->S);
        ij_key(&j, "type");
        ij_cstr(&j, "branch");
        ij_end_obj(&j);
        ij_end_obj(&j);
        ij_key(&j, "snapshots");
        ij_arr(&j);
        for (uint32_t k = 0; k < ns; k++) {
            char lpath[ICE_FPATH];
            if (k) snprintf(lpath, sizeof lpath, "%s/snap-%llu-%llu.avro", mloc, (unsigned long long)sn[k].S, (unsigned long long)sn[0].S);
            else snprintf(lpath, sizeof lpath, "%s/snap-%llu.avro", mloc, (unsigned long long)sn[k].S);
            ij_obj(&j);
            ij_key(&j, "snapshot-id");
            ij_i64(&j, (int64_t)sn[k].S);
            if (k) {
                ij_key(&j, "parent-snapshot-id");
                ij_i64(&j, (int64_t)sn[k - 1].S);
            }
            ij_key(&j, "sequence-number");
            ij_i64(&j, (int64_t)sn[k].S);
            ij_key(&j, "timestamp-ms");
            ij_i64(&j, sn[k].ms);
            ij_key(&j, "manifest-list");
            ij_cstr(&j, lpath);
            ij_key(&j, "summary");
            ij_obj(&j);
            ij_key(&j, "operation");
            ij_cstr(&j, k ? "overwrite" : "append");
            ij_end_obj(&j);
            ij_key(&j, "schema-id");
            ij_i64(&j, sn[k].ver);
            ij_key(&j, "first-row-id");
            ij_i64(&j, (int64_t)sn[k].first_row);
            ij_key(&j, "added-rows");
            ij_i64(&j, (int64_t)sn[k].added_rows);
            ij_end_obj(&j);
        }
        ij_end_arr(&j);
        ij_key(&j, "snapshot-log");
        ij_arr(&j);
        for (uint32_t k = 0; k < ns; k++) {
            ij_obj(&j);
            ij_key(&j, "timestamp-ms");
            ij_i64(&j, sn[k].ms);
            ij_key(&j, "snapshot-id");
            ij_i64(&j, (int64_t)sn[k].S);
            ij_end_obj(&j);
        }
        ij_end_arr(&j);
        ij_key(&j, "metadata-log");
        ij_arr(&j);
        ij_end_arr(&j);
        ij_key(&j, "next-row-id");
        ij_i64(&j, (int64_t)(head->first_row + head->added_rows + head->existing_rows));
        ij_end_obj(&j);
        /* its name K: 2c + 1 alone, 2c with an older (numeric and growing: the next publication makes such a table alone,
         * K + 1, and its next change is 2c' > 2c + 1), the version hint K */
        uint64_t K = 2 * head->S + (ns == 1);
        snprintf(name, sizeof name, "v%llu.metadata.json", (unsigned long long)K);
        rc = out_file(o, mfd, name, &meta, false, e);
        if (!rc) {
            imdb_buf h;
            imdb_buf_init(&h);
            imdb_buf_printf(&h, "%llu", (unsigned long long)K);
            rc = out_file(o, mfd, "version-hint.text", &h, false, e);
            imdb_buf_free(&h);
        }
    }
    if (!rc) { /* the directory holds exactly the files the layer names: the rest goes (an older head's, a vector no longer
                * held, a temporary a crash left, a dotfile), or under VERIFY is refused (as the auditor refuses it) */
        if (o->nnames) qsort(o->names, o->nnames, sizeof *o->names, name_cmp); /* each entry's search */
        int lfd = imdb_open_dir_at(tfd, "metadata", e); /* the listing's own descriptor: closedir closes it */
        DIR *d = lfd >= 0 ? imdb_io_fdopendir(lfd) : NULL;
        if (lfd >= 0 && !d) close(lfd);
        for (struct dirent *de; d && (errno = 0, de = imdb_io_readdir(d));) {
            if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, "..")) continue;
            bool kept = false;
            kept = o->nnames && bsearch(de->d_name, o->names, o->nnames, sizeof *o->names, name_cmp);
            if (kept) continue;
            if (o->verify) {
                rc = imdb_fail(e, IMDB_ERR_VERIFY, "iceberg: table %u: metadata/%s is no file of its layer", (unsigned)t->s.id, de->d_name);
                break;
            }
            if (imdb_io_unlinkat(mfd, de->d_name, 0) != 0) { /* never a current sidecar over a file it names not */
                rc = imdb_fail(e, IMDB_ERR_IO, "iceberg: table %u: metadata/%s cannot be removed: %s", (unsigned)t->s.id, de->d_name,
                               strerror(errno));
                break;
            }
        }
        if (d && !rc && errno) /* a listing cut short is no clean-up (errno set before each readdir) */
            rc = imdb_fail(e, IMDB_ERR_IO, "iceberg: metadata/ cannot be listed: %s", strerror(errno));
        if (d) closedir(d);
        if (!d && !rc) rc = e->code ? e->code : imdb_fail(e, IMDB_ERR_IO, "iceberg: metadata/ cannot be listed");
        if (!rc && !o->verify && imdb_io_fsync(mfd) != 0)
            rc = imdb_fail(e, IMDB_ERR_IO, "iceberg: metadata/ could not be synced: %s", strerror(errno));
        if (!rc && !o->verify && imdb_io_fsync(tfd) != 0) /* metadata's entry in the table's directory, every write */
            rc = imdb_fail(e, IMDB_ERR_IO, "iceberg: table %u's directory could not be synced: %s", (unsigned)t->s.id,
                           strerror(errno));
    }
    imdb_buf_free(&meta);
    for (uint32_t k = 0; k < ns; k++) imdb_free(sn[k].f);
    if (mfd >= 0) close(mfd);
    if (tfd >= 0) close(tfd);
    return rc;
}

/* a table's layer removed whole (its metadata's files, that directory, the table's), each removal checked: a layer that
 * cannot go never stands under a current sidecar */
static int remove_table_layer(int icefd, const char *tname, imdb_err *e)
{
    int tfd = imdb_open_dir_at(icefd, tname, e);
    if (tfd < 0) return e->code;
    int rc = IMDB_OK, mfd = imdb_io_openat(tfd, "metadata", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW, 0);
    if (mfd >= 0) {
        int ld = imdb_open_dir_at(tfd, "metadata", e); /* the listing's own descriptor: closedir closes it */
        DIR *md = ld >= 0 ? imdb_io_fdopendir(ld) : NULL;
        if (ld >= 0 && !md) close(ld);
        if (!md) rc = e->code ? e->code : imdb_fail(e, IMDB_ERR_IO, "iceberg: %s/metadata cannot be listed", tname);
        for (struct dirent *fe; !rc && md && (errno = 0, fe = imdb_io_readdir(md));) {
            if (!strcmp(fe->d_name, ".") || !strcmp(fe->d_name, "..")) continue;
            if (imdb_io_unlinkat(mfd, fe->d_name, 0) != 0)
                rc = imdb_fail(e, IMDB_ERR_IO, "iceberg: %s/metadata/%s cannot be removed: %s", tname, fe->d_name, strerror(errno));
        }
        if (md && !rc && errno) rc = imdb_fail(e, IMDB_ERR_IO, "iceberg: %s/metadata cannot be listed: %s", tname, strerror(errno));
        if (md) closedir(md);
        close(mfd);
        if (!rc && imdb_io_unlinkat(tfd, "metadata", AT_REMOVEDIR) != 0)
            rc = imdb_fail(e, IMDB_ERR_IO, "iceberg: %s/metadata cannot be removed: %s", tname, strerror(errno));
    } else if (errno != ENOENT) {
        rc = imdb_fail(e, IMDB_ERR_IO, "iceberg: %s/metadata: %s", tname, strerror(errno));
    }
    close(tfd);
    if (!rc && imdb_io_unlinkat(icefd, tname, AT_REMOVEDIR) != 0)
        rc = imdb_fail(e, IMDB_ERR_IO, "iceberg: %s cannot be removed: %s", tname, strerror(errno));
    return rc;
}

/* the sidecar: the head a layer was written at, by its commit and its manifest's hash (a commit number alone may name
 * another history's head after a rewind), and the location its paths name */
static void sidecar(imdb_buf *b, uint64_t H, const uint8_t mh[32], const char *loc)
{
    char hx[65];
    hex32(mh, hx);
    imdb_buf_printf(b, "imagedb-iceberg 2\nhead %llu %s\nlocation %s\n", (unsigned long long)H, hx, loc); /* 2: stage 2's form */
}

static int layer(imdb_db *db, const char *location, bool verify, imdb_err *e)
{
    if (!db->lake_seq || !db->lake_mbytes) return IMDB_OK; /* no lake yet: nothing to describe */
    if (!location || location[0] != '/' || strnlen(location, ICE_PATH) >= ICE_PATH - 64)
        return imdb_fail(e, IMDB_ERR_LIMIT, "iceberg: the database's location is not an absolute path within %d bytes", ICE_PATH - 64);
    imdb_manifest m, pm;
    memset(&m, 0, sizeof m);
    memset(&pm, 0, sizeof pm);
    bool have_pm = false;
    int rc = imdb_manifest_parse(db->lake_mbytes, db->lake_mlen, &m, e);
    if (!rc && db->lake_prev) {
        if (!(rc = imdb_manifest_parse(db->lake_prev, db->lake_prevlen, &pm, e))) have_pm = true;
    }
    /* the older snapshot is offered where the generation the head retains lies above the head's boundary (its time travels
     * in its manifest, so a seed's or a RETIRE's log floor no longer matters; its objects on disk, write_table); a table
     * is left untouched only where the sidecar names that generation and this location: the layer was whole at it
     * (f5c-design 9.1, the advisor's rule: a version hint alone never licenses a skip) */
    bool pm_ok = have_pm && pm.seq > m.boundary, skip_ok = false;
    if (!rc && !verify && have_pm && !g_lie) {
        imdb_err e2 = {0};
        int sfd = imdb_open_dir_at(db->dirfd, "iceberg", &e2);
        if (sfd >= 0) {
            uint8_t *sb = NULL;
            size_t sn = 0;
            imdb_buf want;
            imdb_buf_init(&want);
            sidecar(&want, pm.seq, m.prev_manifest, location);
            skip_ok = !imdb_read_file_at(sfd, "LAYER", &sb, &sn, 4096, &e2) && !want.err && sn == want.len &&
                      !memcmp(sb, want.p, sn);
            imdb_free(sb);
            imdb_buf_free(&want);
            close(sfd);
        }
    }
    int icefd = -1, ofd = -1;
    if (!rc) {
        if (verify) {
            if ((icefd = imdb_open_dir_at(db->dirfd, "iceberg", e)) < 0) rc = e->code;
        } else {
            rc = mkdir_at(db->dirfd, "iceberg", &icefd, e);
        }
    }
    if (!rc && (ofd = imdb_open_dir_at(db->dirfd, "objects", e)) < 0) rc = e->code;
    if (!rc && !verify) { /* the sidecar removed, durably, before any table is touched: a sidecar naming the retained generation
                          * then means untouched since it (a write cut short, a writer rewound onto another history: the
                          * advisor, 22:1x), so the skip (write_table) never stands on a table half written */
        if (imdb_io_unlinkat(icefd, "LAYER", 0) != 0 && errno != ENOENT)
            rc = imdb_fail(e, IMDB_ERR_IO, "iceberg/LAYER cannot be removed: %s", strerror(errno));
        else if (imdb_sync_dir(icefd, e))
            rc = e->code;
    }
    /* the vectors the last layer found; none under VERIFY (it makes every file again) or a test's lie (which forgets
     * them, so the next layer makes its files again) */
    icache cache = {.old = db->ice_seen, .nold = db->nice_seen}, *cx = verify || g_lie ? NULL : &cache;
    if (g_lie) {
        imdb_free(db->ice_seen);
        db->ice_seen = NULL;
        db->nice_seen = 0;
    }
    for (uint32_t ti = 0; !rc && ti < db->nt; ti++) {
        imdb_table *t = db->t[ti];
        if (!t) continue;
        iout o = {.verify = verify, .dirsync_later = true}; /* its directory synced once, at its end */
        rc = write_table(db, t, &m, have_pm ? &pm : NULL, pm_ok, skip_ok, location, icefd, ofd, cx, &o, e);
        imdb_free(o.names);
    }
    if (!rc) { /* a table the head gives no layer (dropped, or no segment): none stands for it */
        bool removed = false;
        int lfd = imdb_open_dir_at(db->dirfd, "iceberg", e);
        DIR *d = lfd >= 0 ? imdb_io_fdopendir(lfd) : NULL;
        if (lfd >= 0 && !d) close(lfd);
        if (!d) rc = e->code ? e->code : imdb_fail(e, IMDB_ERR_IO, "iceberg/: cannot be listed");
        for (struct dirent *de; !rc && d && (errno = 0, de = imdb_io_readdir(d));) {
            char *end = NULL;
            unsigned long id = strtoul(de->d_name, &end, 10);
            if (de->d_name[0] < '0' || de->d_name[0] > '9' || !end || *end || id > UINT32_MAX) continue;
            const imdb_manifest_tab *mt = man_tab(&m, (uint32_t)id);
            if (mt && !mt->dropped_at && mt->nseg) continue;
            if (verify) {
                rc = imdb_fail(e, IMDB_ERR_VERIFY, "iceberg: table %lu's layer stands where the head gives none", id);
                break;
            }
            if (!(rc = remove_table_layer(icefd, de->d_name, e))) removed = true;
        }
        if (d && !rc && errno) rc = imdb_fail(e, IMDB_ERR_IO, "iceberg/ cannot be listed: %s", strerror(errno));
        if (d) closedir(d);
        if (!rc && removed && imdb_sync_dir(icefd, e)) rc = e->code;
    }
    /* no sync of the data directory: the layer never syncs the database's own directories (a failed sync there would be
     * the handle's), and iceberg/'s entry needs none: lost to a power cut, the layer, its sidecar too, is absent */
    if (!rc) { /* the sidecar last: a layer whole for this head and this location */
        imdb_buf b;
        imdb_buf_init(&b);
        sidecar(&b, m.seq, db->lake_manifest, location);
        iout o = {.verify = verify};
        rc = out_file(&o, icefd, "LAYER", &b, false, e);
        imdb_free(o.names);
        imdb_buf_free(&b);
    }
    if (!rc && cx) { /* what this layer found, each pair once: the next one's */
        if (cache.nnew) qsort(cache.nw, cache.nnew, sizeof *cache.nw, seen_cmp);
        uint32_t u = 0;
        for (uint32_t k = 0; k < cache.nnew; k++)
            if (!u || seen_cmp(&cache.nw[u - 1], &cache.nw[k])) cache.nw[u++] = cache.nw[k];
        imdb_free(db->ice_seen);
        db->ice_seen = cache.nw;
        db->nice_seen = u;
        cache.nw = NULL;
    }
    if (rc && !verify) { /* a layer that failed (a sync, say): nothing it or the one before wrote is trusted unwritten */
        imdb_free(db->ice_seen);
        db->ice_seen = NULL;
        db->nice_seen = 0;
    }
    imdb_free(cache.nw);
    if (ofd >= 0) close(ofd);
    if (icefd >= 0) close(icefd);
    imdb_manifest_free(&m);
    if (have_pm) imdb_manifest_free(&pm);
    return rc;
}

int imdb_iceberg_write(imdb_db *db, const char *location, imdb_err *e) { return layer(db, location, false, e); }

/* the sidecar names the lake's head and this location: 1; another (or none): 0; no layer at all: -1 */
static int layer_current(imdb_db *db, const char *location)
{
    imdb_err e2 = {0};
    int fd = imdb_open_dir_at(db->dirfd, "iceberg", &e2);
    if (fd < 0) return -1;
    uint8_t *b = NULL;
    size_t n = 0;
    int rc = imdb_read_file_at(fd, "LAYER", &b, &n, 4096, &e2);
    close(fd);
    imdb_buf want;
    imdb_buf_init(&want);
    sidecar(&want, db->lake_seq, db->lake_manifest, location);
    bool current = !rc && !want.err && n == want.len && !memcmp(b, want.p, n);
    imdb_free(b);
    imdb_buf_free(&want);
    return current;
}

int imdb_iceberg_refresh(imdb_db *db, imdb_err *e)
{
    if (!db->location || !db->lake_seq || !db->lake_mbytes || layer_current(db, db->location) == 1) return IMDB_OK;
    return imdb_iceberg_write(db, db->location, e);
}

int imdb_iceberg_verify(imdb_db *db, const char *location, imdb_err *e)
{
    /* a layer written for this head and this location must be the one the lake gives; an absent or stale one is
     * reported by the caller, never a failure (a read-only open cannot write it again) */
    int cur = layer_current(db, location);
    if (cur < 0) return IMDB_ERR_NOTFOUND;
    if (!cur) return IMDB_ERR_STATE; /* written for another head or location: stale */
    return layer(db, location, true, e);
}
