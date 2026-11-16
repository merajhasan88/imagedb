/* N1b: the engine's results and parameters to and from IMDBWIR1 (conv.h; docs/n1-design.md §4). */
#include "conv.h"

#include <stdio.h>
#include <string.h>

#include "../src/codec.h"
#include "../src/log.h"

/* the two tag spaces, side by side: the wire's numbering is its own contract, the engine's its codec's */
static const struct {
    uint8_t engine, wire;
} kTypes[] = {
    {IMDB_T_INT64, IMDBW_T_INT64},       {IMDB_T_DECIMAL, IMDBW_T_DECIMAL},         {IMDB_T_TEXT, IMDBW_T_TEXT},
    {IMDB_T_BOOL, IMDBW_T_BOOL},         {IMDB_T_TIMESTAMP, IMDBW_T_TIMESTAMP},     {IMDB_T_FLOAT64, IMDBW_T_FLOAT64},
    {IMDB_T_TIMESTAMPTZ, IMDBW_T_TIMESTAMPTZ}, {IMDB_T_DATE, IMDBW_T_DATE},         {IMDB_T_TIME, IMDBW_T_TIME},
    {IMDB_T_UUID, IMDBW_T_UUID},         {IMDB_T_BYTEA, IMDBW_T_BYTEA},             {IMDB_T_INTERVAL, IMDBW_T_INTERVAL},
    {IMDB_T_ENUM, IMDBW_T_ENUM},
};
_Static_assert(sizeof kTypes / sizeof *kTypes == (int)IMDB_T_LAST && (int)IMDBW_T_LAST == (int)IMDB_T_LAST, "every type, both ways");

uint8_t imdbw_type_of_engine(uint8_t t)
{
    for (size_t i = 0; i < sizeof kTypes / sizeof *kTypes; i++)
        if (kTypes[i].engine == t) return kTypes[i].wire;
    return IMDBW_T_NONE;
}

uint8_t imdbw_engine_type_of(uint8_t t)
{
    for (size_t i = 0; i < sizeof kTypes / sizeof *kTypes; i++)
        if (kTypes[i].wire == t) return kTypes[i].engine;
    return 0;
}

int imdbw_columns_of(const imdb_result *r, imdbw_msg *cols, imdb_err *e)
{
    memset(cols, 0, sizeof *cols);
    cols->type = IMDBW_COLUMNS;
    if (r->ncols < 1 || r->ncols > IMDBW_VALUES_MAX)
        return imdb_fail(e, IMDB_ERR_LIMIT, "a result of %u columns: 1 to %u go on the wire", r->ncols, IMDBW_VALUES_MAX);
    if (!(cols->cols = imdbw_alloc(r->ncols, sizeof *cols->cols))) return imdb_fail(e, IMDB_ERR_NOMEM, "wire: out of memory");
    cols->ncols = r->ncols;
    for (uint16_t i = 0; i < r->ncols; i++) {
        imdbw_col *c = &cols->cols[i];
        size_t nl = imdbw_utf8_fit((const uint8_t *)r->names[i], strnlen(r->names[i], sizeof r->names[i]), IMDBW_COLNAME_MAX);
        if (!nl) snprintf(c->name, sizeof c->name, "?column?"); /* PostgreSQL's name for a column with none */
        else memcpy(c->name, r->names[i], nl);
        c->type = imdbw_type_of_engine(r->ctype[i]);
        if (r->ctype[i] && !c->type) return imdb_fail(e, IMDB_ERR_STATE, "a result column of engine type %u", r->ctype[i]);
        if (r->cwide[i] && (c->type == IMDBW_T_INT64 || c->type == IMDBW_T_DECIMAL)) c->type = IMDBW_T_DECIMAL;
        if (c->type == IMDBW_T_DECIMAL) c->scale = r->cscale[i]; /* precision 0: not known (38 digits) */
        if (c->type == IMDBW_T_ENUM) {
            const imdb_enumdef *d = r->clab[i];
            if (!d) return imdb_fail(e, IMDB_ERR_STATE, "a result's ENUM column %u without its labels", i + 1u);
            /* the labels the result's read point sees (an AS OF below an ADD VALUE: a prefix), not the type's today */
            uint16_t nlab = r->has_snap ? imdb_enumdef_count_at(d, r->snap) : d->n;
            if (!(c->labels = imdbw_alloc(nlab, sizeof *c->labels))) return imdb_fail(e, IMDB_ERR_NOMEM, "wire: out of memory");
            c->nlabels = nlab;
            for (uint16_t k = 0; k < nlab; k++)
                c->labels[k] = (imdbw_text){(const uint8_t *)d->text + d->off[k], d->off[k + 1] - d->off[k]};
        }
    }
    int ix = imdbw_cols_index(cols);
    if (ix) return ix == -2 ? imdb_fail(e, IMDB_ERR_NOMEM, "wire: out of memory")
                            : imdb_fail(e, IMDB_ERR_STATE, "a result's ENUM labels not as the wire takes them");
    return IMDB_OK;
}

int imdbw_value_of(const imdb_result *r, uint64_t row, uint16_t col, const imdbw_col *c, imdbw_value *v, imdb_err *e)
{
    const imdb_cell *cl = &r->cells[row * r->ncols + col];
    memset(v, 0, sizeof *v);
    uint8_t et = cl->v.type, wt = imdbw_type_of_engine(et);
    if (cl->null || cl->v.null) { /* a NULL of its column's type (or its own, under a column of none) */
        v->null = true;
        v->type = c->type ? c->type : wt;
        return IMDB_OK;
    }
    /* a DECIMAL: under its column, a SUM's INT64 column, or a column of no known type (SHOW HISTORY's rows: each value its
     * own type; a wide column's value or a SUM's a wide cell, an INT64 one past INT64 sent as a DECIMAL) */
    bool as_dec = (c->type == IMDBW_T_DECIMAL && (et == IMDB_T_INT64 || et == IMDB_T_DECIMAL)) ||
                  (c->type == IMDBW_T_NONE && (et == IMDB_T_DECIMAL || (et == IMDB_T_INT64 && cl->wide)));
    if (as_dec) {
        v->type = IMDBW_T_DECIMAL; /* a DECIMAL, or a top-level SUM's INT64 column (wide or not, one arm's 1) */
        v->scale = et == IMDB_T_DECIMAL ? cl->v.scale : 0;
        v->d = cl->wide ? cl->i128 : et == IMDB_T_DECIMAL ? imdb_dec_value(&cl->v) : (__int128)cl->v.i;
    } else {
        if (cl->wide) return imdb_fail(e, IMDB_ERR_STATE, "result column %u: a value past its type's range", col + 1u);
        v->type = wt;
        switch (et) {
        case IMDB_T_INT64:
        case IMDB_T_BOOL:
        case IMDB_T_TIMESTAMP:
        case IMDB_T_TIMESTAMPTZ:
        case IMDB_T_TIME: v->i = cl->v.i; break;
        case IMDB_T_DATE:
            if (cl->v.i < INT32_MIN || cl->v.i > INT32_MAX) return imdb_fail(e, IMDB_ERR_STATE, "a DATE past its range");
            v->day = (int32_t)cl->v.i;
            break;
        case IMDB_T_FLOAT64: {
            double d = imdb_f64_value(cl->v.i);
            memcpy(&v->f, &d, 8);
            break;
        }
        case IMDB_T_TEXT:
        case IMDB_T_BYTEA:
        case IMDB_T_UUID:
            v->s = cl->v.s;
            v->len = cl->v.len;
            break;
        case IMDB_T_INTERVAL:
            v->mon = cl->v.iv.mon;
            v->day = cl->v.iv.day;
            v->i = cl->v.i;
            break;
        case IMDB_T_ENUM: {
            const imdb_enumdef *d = r->clab[col];
            if (!d || cl->v.i < 0 || cl->v.i >= d->n)
                return imdb_fail(e, IMDB_ERR_STATE, "result column %u: an ENUM ordinal its labels lack", col + 1u);
            v->s = (const uint8_t *)d->text + d->off[cl->v.i];
            v->len = d->off[cl->v.i + 1] - d->off[cl->v.i];
            break;
        }
        default: return imdb_fail(e, IMDB_ERR_STATE, "result column %u: a value of engine type %u", col + 1u, et);
        }
    }
    if (!imdbw_value_fits(c, v)) /* a cell its column does not take: the server's bug, never sent */
        return imdb_fail(e, IMDB_ERR_STATE, "result column %u: a value its column's type does not take", col + 1u);
    return IMDB_OK;
}

int imdbw_rows_of(const imdb_result *r, const imdbw_msg *cols, uint64_t *next, size_t target, imdbw_buf *b, imdb_err *e)
{
    while (*next < r->nrows && b->len < target) {
        imdbw_rows w;
        imdbw_rows_begin(&w, b, cols);
        while (*next < r->nrows) {
            for (uint16_t c = 0; c < r->ncols; c++) {
                imdbw_value v;
                int rc = imdbw_value_of(r, *next, c, &cols->cols[c], &v, e);
                if (rc) return rc;
                imdbw_rows_value(&w, &v);
            }
            if (b->err) /* the buffer says which: memory, or a row past what a frame holds (each value fit its column) */
                return b->nomem ? imdb_fail(e, IMDB_ERR_NOMEM, "wire: out of memory")
                                : imdb_fail(e, IMDB_ERR_LIMIT, "row %llu: more than a frame holds", (unsigned long long)*next + 1);
            ++*next;
            if (imdbw_rows_len(&w) >= target) break;
        }
        imdbw_rows_end(&w);
        if (b->err)
            return b->nomem ? imdb_fail(e, IMDB_ERR_NOMEM, "wire: out of memory")
                            : imdb_fail(e, IMDB_ERR_STATE, "wire: a ROWS frame not written");
    }
    return IMDB_OK;
}

void imdbw_done_of(const imdb_result *r, imdbw_msg *d)
{
    memset(d, 0, sizeof *d);
    d->type = IMDBW_DONE;
    size_t n = imdbw_utf8_fit((const uint8_t *)r->status, strnlen(r->status, sizeof r->status), IMDBW_STATUS_MAX);
    d->status = (imdbw_text){(const uint8_t *)r->status, (uint32_t)n};
    d->count = r->has_count ? r->count : r->nrows;
    if ((d->has_read = r->has_snap)) {
        d->read_commit = r->snap;
        memcpy(d->read_hash, r->head, 32);
        memcpy(d->digest, r->digest, 32);
        d->lake_commit = r->lake_seq;
        memcpy(d->lake_manifest, r->lake_manifest, 32);
        memcpy(d->db_id, r->db_id, 16);
        d->own = r->snap_own;
    }
    if ((d->has_write = r->has_commit)) { /* the statement's own commit (imdb_result.commit: never a maintenance one) */
        d->write_commit = r->commit;
        memcpy(d->write_hash, r->commit_hash, 32);
    }
}

int imdbw_param_of(const imdbw_value *w, imdb_value *out, imdb_err *e)
{
    memset(out, 0, sizeof *out);
    if (!imdbw_value_ok(w)) return imdb_fail(e, IMDB_ERR_INVALID, "a parameter outside its type's rules");
    out->type = imdbw_engine_type_of(w->type);
    if (w->null) {
        out->null = true; /* its type kept (0: none, which the engine refuses where a type is wanted) */
        return IMDB_OK;
    }
    switch (w->type) {
    case IMDBW_T_INT64:
    case IMDBW_T_BOOL:
    case IMDBW_T_TIMESTAMP:
    case IMDBW_T_TIMESTAMPTZ:
    case IMDBW_T_TIME: out->i = w->i; break;
    case IMDBW_T_DATE: out->i = w->day; break;
    case IMDBW_T_FLOAT64: {
        double d;
        memcpy(&d, &w->f, 8);
        out->i = imdb_f64_key(d);
        break;
    }
    case IMDBW_T_DECIMAL:
        out->scale = w->scale;
        imdb_dec_set(out, w->d, w->d < INT64_MIN || w->d > INT64_MAX); /* the narrow form when it fits, as xval_param */
        break;
    case IMDBW_T_TEXT:
    case IMDBW_T_BYTEA:
    case IMDBW_T_UUID:
        out->s = w->s;
        out->len = w->len;
        break;
    case IMDBW_T_INTERVAL: imdb_iv_set(out, w->mon, w->day, w->i); break;
    default: /* ENUM: a label, which the engine binds only once N1b's rule is in */
        return imdb_fail(e, IMDB_ERR_UNSUPPORTED, "an ENUM parameter by its label: not yet (send NULL, or the statement's text)");
    }
    return IMDB_OK;
}
