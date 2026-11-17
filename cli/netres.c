/* N1d-2: an engine result rebuilt from the wire's replies (netres.h). */
#include "netres.h"

#include <stdio.h>
#include <string.h>

#include "../server/conv.h"
#include "../src/codec.h"
#include "../src/limits.h"


int cli_res_cols(imdb_result *r, const imdbw_msg *m, imdb_err *e)
{
    if (r->has_rows || r->has_count) return imdb_fail(e, IMDB_ERR_CORRUPT, "a second COLUMNS for one statement, or one past its DONE");
    if (!m->ncols || m->ncols > IMDB_MAX_COLS + 4)
        return imdb_fail(e, IMDB_ERR_CORRUPT, "a COLUMNS of %u columns (a result holds 1 to %u)", (unsigned)m->ncols,
                         (unsigned)(IMDB_MAX_COLS + 4));
    r->ncols = m->ncols;
    r->has_rows = true;
    for (uint16_t k = 0; k < m->ncols; k++) {
        const imdbw_col *col = &m->cols[k];
        snprintf(r->names[k], sizeof r->names[k], "%s", col->name);
        r->ctype[k] = imdbw_engine_type_of(col->type);
        r->cscale[k] = col->scale <= UINT8_MAX ? (uint8_t)col->scale : 0;
    }
    return IMDB_OK;
}

static imdb_cell *row_add(imdb_result *r, imdb_err *e)
{
    /* the engine's own cap on a result (res_row's): a server's rows never take the shell's memory with them, a NULL a
     * byte on the wire and a cell here (N1d's review) */
    uint64_t cap = r->byte_cap ? r->byte_cap : IMDB_MAX_RESULT_BYTES;
    uint64_t rows = r->nrows == r->caprows ? (r->caprows ? 2 * r->caprows : 64) : r->caprows; /* as allocated */
    if (r->text.err == IMDB_ERR_LIMIT || rows * r->ncols * sizeof(imdb_cell) + r->text.cap > cap) {
        imdb_fail(e, IMDB_ERR_LIMIT, "the server's result over the shell's cap of %llu bytes after %llu rows",
                  (unsigned long long)cap, (unsigned long long)r->nrows);
        return NULL;
    }
    if (r->nrows == r->caprows) {
        uint64_t nc = r->caprows ? r->caprows * 2 : 64;
        imdb_cell *c = imdb_realloc_array(r->cells, r->caprows * r->ncols, nc * r->ncols, sizeof *c, e);
        if (!c) return NULL;
        r->cells = c;
        r->caprows = nc;
    }
    imdb_cell *row = &r->cells[r->nrows * r->ncols];
    memset(row, 0, sizeof *row * r->ncols);
    r->nrows++;
    return row;
}

/* a wire value as the engine's cell, by res_put's rules (bytes into the result's text, placed at the end) */
static int cell_of(imdb_result *r, const imdbw_col *col, const imdbw_value *w, const imdb_tz *zone, imdb_cell *c,
                   imdb_err *e)
{
    if (w->null) {
        c->null = true;
        c->v.type = imdbw_engine_type_of(w->type != IMDBW_T_NONE ? w->type : col->type);
        c->v.scale = w->scale;
        return IMDB_OK;
    }
    imdbw_value tw = *w;
    if (w->type == IMDBW_T_ENUM) { /* a label: the renderer prints an ENUM as a TEXT of its label (left, quoted in CSV), so
                                    * its cell is that TEXT; a typed column's own labels name it */
        bool known = col->type != IMDBW_T_ENUM; /* (a column of no known type: each value its own type, no labels) */
        for (uint32_t j = 0; j < col->nlabels && !known; j++)
            known = col->labels[j].len == w->len && !memcmp(col->labels[j].p, w->s, w->len);
        if (!known) return imdb_fail(e, IMDB_ERR_CORRUPT, "an ENUM value no label of its column names");
        tw.type = IMDBW_T_TEXT;
    }
    imdb_value v;
    if (imdbw_param_of(&tw, &v, e)) return e->code;
    c->v = v;
    if (v.type == IMDB_T_DECIMAL && v.wide) {
        c->wide = true;
        c->i128 = imdb_dec_value(&v);
        return IMDB_OK;
    }
    if (v.type == IMDB_T_TIMESTAMPTZ) c->tz_off = zone ? imdb_tz_offset(zone, v.i) : 0;
    if (imdb_type_bytes(v.type)) {
        c->v.i = (int64_t)r->text.len;
        c->v.s = NULL;
        imdb_buf_put(&r->text, v.s, v.len);
        if (imdb_buf_check(&r->text, e)) return e->code;
    }
    return IMDB_OK;
}

int cli_res_rows(imdb_result *r, const imdbw_msg *cols, const imdbw_msg *m, const imdb_tz *zone, imdb_err *e)
{
    if (!r->has_rows || !cols || cols->ncols != r->ncols) return imdb_fail(e, IMDB_ERR_CORRUPT, "ROWS without its COLUMNS");
    /* (a ROWS past DONE: its cells would keep offsets DONE never made pointers, N1d's review) */
    if (r->has_count) return imdb_fail(e, IMDB_ERR_CORRUPT, "ROWS past its statement's DONE");
    imdb_rd rd;
    imdbw_span_begin(&m->vals, &rd);
    for (uint32_t i = 0; i < m->nsets; i++) {
        imdb_cell *row = row_add(r, e);
        if (!row) return e->code;
        for (uint16_t k = 0; k < r->ncols; k++) {
            imdbw_value w;
            if (!imdbw_span_next(&rd, &w)) return imdb_fail(e, IMDB_ERR_CORRUPT, "a ROWS frame ended early");
            if (cell_of(r, &cols->cols[k], &w, zone, &row[k], e)) return e->code;
        }
    }
    return IMDB_OK;
}

void cli_res_done(imdb_result *r, const imdbw_msg *m)
{
    snprintf(r->status, sizeof r->status, "%.*s", (int)m->status.len, (const char *)m->status.p);
    r->has_count = true;
    r->count = m->count;
    if ((r->has_snap = m->has_read)) {
        r->snap = m->read_commit;
        r->snap_own = m->own;
        memcpy(r->head, m->read_hash, 32);
        memcpy(r->digest, m->digest, 32);
        memcpy(r->db_id, m->db_id, 16);
        r->lake_seq = m->lake_commit;
        memcpy(r->lake_manifest, m->lake_manifest, 32);
    }
    for (uint64_t i = 0; i < r->nrows * r->ncols; i++)
        if (imdb_type_bytes(r->cells[i].v.type) && !r->cells[i].null)
            r->cells[i].v.s = r->text.p ? r->text.p + r->cells[i].v.i : (const uint8_t *)"";
}

int cli_order_next(cli_order *o, uint8_t type, imdb_err *e)
{
    if (type == IMDBW_READY)
        return o->ended ? IMDB_OK : imdb_fail(e, IMDB_ERR_CORRUPT, "the server's reply ended without its statement's DONE or ERROR");
    if (o->ended && type != IMDBW_WARNING) return imdb_fail(e, IMDB_ERR_CORRUPT, "the server's reply: a message after its statement's end");
    if (type == IMDBW_DONE || type == IMDBW_ERROR) o->ended = true;
    return IMDB_OK;
}

int cli_res_code(uint32_t code) { return code && code <= 4096 ? -(int)code : IMDB_ERR_INVALID; }
