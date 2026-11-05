/* SQL executor: binding, the three read paths, cross-checking, DML, admin. */
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include "cpu.h"
#include "db_internal.h"
#include "fsio.h"
#include "fsum.h"
#include "lake.h"
#include "oidx.h"
#include "repl.h"
#include "sha256.h"
#include "sql_internal.h"

/* ---- results ---------------------------------------------------------------- */

void imdb_session_init(imdb_session *s, imdb_db *db)
{
    memset(s, 0, sizeof *s);
    s->db = db;
    atomic_init(&s->cancel, false);
}

_Static_assert(ATOMIC_BOOL_LOCK_FREE == 2, "the cancel flag is set from a signal handler: it must be lock-free");

void imdb_session_cancel(imdb_session *s) { atomic_store_explicit(&s->cancel, true, memory_order_relaxed); }

void imdb_session_close(imdb_session *s)
{
    if (s->txn.open) imdb_txn_rollback(s->db, &s->txn);
}

void imdb_result_init(imdb_result *r)
{
    memset(r, 0, sizeof *r);
    imdb_buf_init(&r->text);
}

void imdb_result_free(imdb_result *r)
{
    if (r->cells) imdb_wipe(r->cells, (size_t)(r->caprows * r->ncols) * sizeof *r->cells); /* result values */
    imdb_free(r->cells);
    imdb_buf_wipe_free(&r->text);
    memset(r, 0, sizeof *r);
}

static int res_cols(imdb_result *r, uint16_t n)
{
    r->ncols = n;
    r->has_rows = true;
    return IMDB_OK;
}

static imdb_cell *res_row(imdb_result *r, imdb_err *e)
{
    /* the result's own cap (limits.h): a statement never takes the process's memory with it */
    uint64_t cap = r->byte_cap ? r->byte_cap : IMDB_MAX_RESULT_BYTES;
    uint64_t rows = r->nrows == r->caprows ? (r->caprows ? 2 * r->caprows : 64) : r->caprows; /* as allocated */
    if (r->text.err == IMDB_ERR_LIMIT || rows * r->ncols * sizeof(imdb_cell) + r->text.cap > cap) {
        imdb_fail(e, IMDB_ERR_LIMIT, "result over its cap of %llu bytes after %llu rows: narrow it, or add LIMIT",
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

/* TEXT is copied into the result; the pointer is fixed up by res_finish. */
static void res_put(imdb_result *r, imdb_cell *c, const imdb_value *v)
{
    if (v->null) {
        c->null = true;
        c->v.type = v->type;
        c->v.scale = v->scale;
        return;
    }
    c->v = *v;
    if (v->type == IMDB_T_TEXT) {
        c->v.i = (int64_t)r->text.len;
        c->v.s = NULL;
        uint64_t cap = r->byte_cap ? r->byte_cap : IMDB_MAX_RESULT_BYTES;
        uint64_t cells = r->caprows * r->ncols * sizeof *r->cells;
        if (cells > cap) r->text.err = IMDB_ERR_LIMIT;
        else if (imdb_buf_reserve_limit(&r->text, v->len, (size_t)(cap - cells)))
            imdb_buf_put(&r->text, v->s, v->len);
    }
}

static void res_put_int(imdb_result *r, imdb_cell *c, int64_t x)
{
    imdb_value v = {.type = IMDB_T_INT64, .i = x};
    res_put(r, c, &v);
}

static void res_put_str(imdb_result *r, imdb_cell *c, const char *s)
{
    imdb_value v = {.type = IMDB_T_TEXT, .s = (const uint8_t *)s, .len = (uint32_t)strlen(s)};
    res_put(r, c, &v);
}

static int res_finish(imdb_result *r, imdb_err *e)
{
    if (r->text.err == IMDB_ERR_LIMIT)
        return imdb_fail(e, IMDB_ERR_LIMIT, "result over its cap of %llu bytes after %llu rows: narrow it, or add LIMIT",
                         (unsigned long long)(r->byte_cap ? r->byte_cap : IMDB_MAX_RESULT_BYTES),
                         (unsigned long long)r->nrows);
    if (imdb_buf_check(&r->text, e)) return e->code;
    for (uint64_t i = 0; i < r->nrows * r->ncols; i++)
        if (r->cells[i].v.type == IMDB_T_TEXT && !r->cells[i].null)
            r->cells[i].v.s = r->text.p ? r->text.p + r->cells[i].v.i : (const uint8_t *)"";
    return IMDB_OK;
}

static void res_name(imdb_result *r, uint16_t i, const char *n) { snprintf(r->names[i], sizeof r->names[i], "%s", n); }

/* ---- execution context -------------------------------------------------------- */

typedef struct xctx {
    imdb_session *ss;
    imdb_db *db;
    const char *sql;
    const imdb_value *params;
    uint32_t nparams;
    void **allocs;
    uint32_t nallocs, capallocs;
    imdb_salts salts; /* the statement's (db.h): wiped by xfree, the one exit */
    imdb_xnode *xn;   /* the statement's trees bound (xbind), parallel to st->ex; NULL until one is */
    const sql_stmt *st;
    bool fb[IMDB_MAX_PREDICATES]; /* WHERE's plain conjuncts that fell back to residuals (falls_back) */
    uint64_t ticks, next_check;   /* rows passed, and the count at the next check (R1: xcheck) */
    uint64_t tested, row_limit;   /* rows tested and SET statement_row_limit (D8 #4: xtested) */
    uint64_t deadline_ns;         /* CLOCK_MONOTONIC: the statement's timeout; 0: none */
    bool checks;                  /* false for what runs to its end: COMMIT and the physical statements */
    char vpath[80];               /* select_vids' path: an UPDATE's or DELETE's result's (P1 Q1) */
} xctx;

enum { TICK_ROWS = 4096 }; /* rows between two looks at the clock and the cancel flag: tens of microseconds of work */

static uint64_t mono_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000u + (uint64_t)ts.tv_nsec;
}

/* R1: the session cancelled the statement, or its deadline passed. A timeout depends on time, so on the machine and on
 * where versions live; nothing derived depends on it: a cancelled statement fails like any failed one, and leaves
 * nothing behind (its savepoint undoes its writes) */
static int xcheck(xctx *x, imdb_err *e)
{
    x->next_check = x->ticks + TICK_ROWS;
    imdb_stats_tick(x->db, false); /* P1 M1: a long statement still reports (at most once a second) */
    if (!x->checks) return IMDB_OK;
    if (atomic_load_explicit(&x->ss->cancel, memory_order_relaxed))
        return imdb_fail(e, IMDB_ERR_CANCELLED, "statement cancelled");
    if (x->deadline_ns && mono_ns() >= x->deadline_ns)
        return imdb_fail(e, IMDB_ERR_CANCELLED, "statement timeout: it ran past %u ms (SET statement_timeout)",
                         x->ss->stmt_timeout_ms);
    return IMDB_OK;
}

/* D8 #4, the work limit: n more rows tested, each a row reaching a table's sink (visible, past every bound predicate,
 * before WHERE's trees), a pair a join forms (both sides past their predicates, or a LEFT row without a match), or a
 * match the fast aggregate sums without a sink. Every path and every placement of the versions tests the same rows
 * (eviction is invisible: so is this limit), and each plan counts from zero (cross_check's second too). Unlike the
 * deadline it depends on nothing but the statement and the data, so it trips at the same row on every copy. */
static int xtested(xctx *x, uint64_t n, imdb_err *e)
{
    x->tested += n;
    if (!x->row_limit || x->tested <= x->row_limit || !x->checks) return IMDB_OK;
    return imdb_fail(e, IMDB_ERR_LIMIT, "statement row limit: it tested more than %llu rows (SET statement_row_limit); "
                                        "narrow it", (unsigned long long)x->row_limit);
}

/* n more rows passed (examined, tested, joined or written): an error once the statement must stop */
static inline int xtick(xctx *x, uint64_t n, imdb_err *e)
{
    x->ticks += n;
    return x->ticks < x->next_check ? IMDB_OK : xcheck(x, e);
}

static void *xalloc(xctx *x, size_t n, imdb_err *e)
{
    if (x->nallocs == x->capallocs) {
        uint32_t nc = x->capallocs ? x->capallocs * 2 : 32;
        void **na = imdb_realloc_array(x->allocs, x->capallocs, nc, sizeof *na, e);
        if (!na) return NULL;
        x->allocs = na;
        x->capallocs = nc;
    }
    void *p = imdb_alloc(n ? n : 1, e);
    if (p) x->allocs[x->nallocs++] = p;
    return p;
}

static void xfree(xctx *x)
{
    for (uint32_t i = 0; i < x->nallocs; i++) imdb_free(x->allocs[i]);
    imdb_free(x->allocs);
    imdb_salts_wipe(&x->salts);
}

/* Copies a TEXT value into context-owned memory (stable across writes). */
static int xpin(xctx *x, imdb_value *v, imdb_err *e)
{
    if (v->type != IMDB_T_TEXT || !v->len) return IMDB_OK;
    uint8_t *p = xalloc(x, v->len, e);
    if (!p) return e->code;
    memcpy(p, v->s, v->len);
    v->s = p;
    return IMDB_OK;
}

/* ---- binding literals ----------------------------------------------------------- */

static int bind_const_tree(xctx *x, const sql_stmt *st, uint16_t k, const imdb_column *c, imdb_value *out, imdb_err *e);

static int bind_lit(xctx *x, const sql_lit *l, const imdb_column *c, bool compare, imdb_value *out, imdb_err *e)
{
    memset(out, 0, sizeof *out);
    out->type = c->type;
    out->scale = c->scale;
    if (l->kind == LIT_EXPR) return bind_const_tree(x, x->st, l->ex, c, out, e); /* VALUES (1 + 2): computed, assigned */
    if (l->kind == LIT_PARAM) {
        if (l->param > x->nparams) return imdb_fail(e, IMDB_ERR_INVALID, "parameter $%u was not supplied", (unsigned)l->param);
        const imdb_value *pv = &x->params[l->param - 1];
        if (pv->type != c->type || (c->type == IMDB_T_DECIMAL && pv->scale != c->scale))
            return imdb_fail(e, IMDB_ERR_INVALID, "parameter $%u does not have the type of column %s", (unsigned)l->param, c->name);
        *out = *pv;
    } else {
        char num[IMDB_MAX_NUMERIC + 2];
        const char *txt = x->sql + l->off;
        size_t tl = l->len;
        if (l->kind == LIT_NULL) {
            out->null = true;
            return imdb_value_check(c, out, e);
        }
        if (l->kind == LIT_INT || l->kind == LIT_DEC || l->kind == LIT_FLOAT) {
            if (tl + 2 > sizeof num) return imdb_fail(e, IMDB_ERR_LIMIT, "numeric literal too long");
            num[0] = '-';
            memcpy(num + 1, txt, tl);
            txt = l->neg ? num : num + 1;
            tl += l->neg;
        }
        switch (c->type) {
        case IMDB_T_INT64:
            if (l->kind != LIT_INT) return imdb_fail(e, IMDB_ERR_INVALID, "column %s expects an integer", c->name);
            if (imdb_parse_int64(txt, tl, &out->i, e)) return e->code;
            break;
        case IMDB_T_DECIMAL:
            if (l->kind != LIT_INT && l->kind != LIT_DEC) return imdb_fail(e, IMDB_ERR_INVALID, "column %s expects a number", c->name);
            if (imdb_parse_decimal(txt, tl, compare ? 18 : c->precision, c->scale, &out->i, e)) return e->code;
            break;
        case IMDB_T_BOOL:
            if (l->kind != LIT_BOOL) return imdb_fail(e, IMDB_ERR_INVALID, "column %s expects TRUE or FALSE", c->name);
            out->i = l->bval;
            break;
        case IMDB_T_TIMESTAMP:
            if (l->kind != LIT_TS && l->kind != LIT_STR)
                return imdb_fail(e, IMDB_ERR_INVALID, "column %s expects TIMESTAMP '...'", c->name);
            if (imdb_parse_timestamp(txt, tl, &out->i, e)) return e->code;
            break;
        case IMDB_T_FLOAT64:
            if (l->kind != LIT_INT && l->kind != LIT_DEC && l->kind != LIT_FLOAT)
                return imdb_fail(e, IMDB_ERR_INVALID, "column %s expects a number", c->name);
            if (imdb_parse_float64(txt, tl, &out->i, e)) return e->code;
            break;
        case IMDB_T_TEXT: {
            if (l->kind != LIT_STR) return imdb_fail(e, IMDB_ERR_INVALID, "column %s expects a string", c->name);
            uint8_t *buf = xalloc(x, tl, e);
            if (!buf) return e->code;
            size_t k = 0;
            for (size_t i = 0; i < tl; i++) {
                buf[k++] = (uint8_t)txt[i];
                if (txt[i] == '\'') i++; /* '' -> ' */
            }
            out->s = buf;
            out->len = (uint32_t)k;
            break;
        }
        }
    }
    if (compare && c->type == IMDB_T_DECIMAL) return IMDB_OK; /* ranges may exceed the column precision */
    return imdb_value_check(c, out, e);
}

/* ---- expressions: binding (docs/plan-p0.md 1b; sql_expr.c computes) ------------------------------------------
 * Each tree is bound once per statement: its columns resolved, its constants converted, every node's type fixed by
 * the rules in sql_expr.c, so no row decides a type. Where a tree stands decides what it may read: VALUES takes
 * constants, SET and WHERE a row's columns, a SELECT list aggregates too (and, grouped, a column outside one only
 * if it is the GROUP BY column). */

typedef struct xscope {
    const sql_stmt *st;
    const imdb_schema *s;    /* the row's columns: one table's, or a join's combined */
    imdb_table *t;           /* one table's statement (one_col) */
    imdb_table *const *jt;   /* a join's two (join_col), else NULL */
    uint16_t nc0;            /* a join: side 0's columns, before side 1's */
    bool cols, aggs;         /* columns may be read; aggregates may stand */
    int group_col;           /* grouped: the only column outside an aggregate, else -1 */
    bool in_agg;
    uint16_t nslot;          /* aggregates bound so far: each one's accumulator */
    uint16_t *agg_nodes;     /* a SELECT list's: slot -> its EX_AGG node (IMDB_MAX_COLS of them) */
} xscope;

static int one_col(const sql_stmt *st, const imdb_table *t, const char *qual, const char *name, imdb_err *e);
static int join_col(const sql_stmt *st, imdb_table *const t[2], const char *qual, const char *name, int *side, int *col,
                    imdb_err *e);

static int xnodes(xctx *x, const sql_stmt *st, imdb_err *e)
{
    if (!x->xn && !(x->xn = xalloc(x, ((size_t)st->nex + 1) * sizeof *x->xn, e))) return e->code;
    return IMDB_OK;
}

/* a literal in a tree: typed by what it is written as (an integer INT64, a point DECIMAL at its scale, an exponent
 * FLOAT64), not by a column; $n by the value supplied */
static int bind_xlit(xctx *x, const sql_lit *l, imdb_xval *v, imdb_err *e)
{
    memset(v, 0, sizeof *v);
    if (l->kind == LIT_PARAM) {
        if (l->param > x->nparams) return imdb_fail(e, IMDB_ERR_INVALID, "parameter $%u was not supplied", (unsigned)l->param);
        const imdb_value *pv = &x->params[l->param - 1];
        if (pv->type < IMDB_T_INT64 || pv->type > IMDB_T_FLOAT64 || (pv->type == IMDB_T_DECIMAL && pv->scale > 18))
            return imdb_fail(e, IMDB_ERR_INVALID, "parameter $%u: not a value of a column type", (unsigned)l->param);
        imdb_x_from_value(pv, v); /* a NULL keeps its type: NULL + 1 is NULL */
        return IMDB_OK;
    }
    char num[IMDB_MAX_NUMERIC + 2];
    const char *txt = x->sql + l->off;
    size_t tl = l->len;
    if (l->kind == LIT_INT || l->kind == LIT_DEC || l->kind == LIT_FLOAT) {
        if (tl + 2 > sizeof num) return imdb_fail(e, IMDB_ERR_LIMIT, "numeric literal too long");
        num[0] = '-';
        memcpy(num + 1, txt, tl);
        txt = l->neg ? num : num + 1;
        tl += l->neg;
    }
    int64_t i;
    switch (l->kind) {
    case LIT_INT:
        if (imdb_parse_int64(txt, tl, &i, e)) return e->code;
        v->type = IMDB_T_INT64;
        v->i = i;
        return IMDB_OK;
    case LIT_DEC: return imdb_x_parse_decimal(txt, tl, v, e);
    case LIT_FLOAT:
        if (imdb_parse_float64(txt, tl, &i, e)) return e->code;
        v->type = IMDB_T_FLOAT64;
        v->f = imdb_f64_value(i);
        return IMDB_OK;
    case LIT_BOOL:
        v->type = IMDB_T_BOOL;
        v->i = l->bval;
        return IMDB_OK;
    case LIT_TS:
        if (imdb_parse_timestamp(txt, tl, &i, e)) return e->code;
        v->type = IMDB_T_TIMESTAMP;
        v->i = i;
        return IMDB_OK;
    case LIT_STR: {
        uint8_t *buf = xalloc(x, tl, e);
        if (!buf) return e->code;
        size_t k = 0;
        for (size_t j = 0; j < tl; j++) {
            buf[k++] = (uint8_t)txt[j];
            if (txt[j] == '\'') j++; /* '' -> ' */
        }
        v->type = IMDB_T_TEXT;
        v->s = buf;
        v->len = (uint32_t)k;
        return IMDB_OK;
    }
    default: /* LIT_NULL: as a comparison with NULL is refused */
        return imdb_fail(e, IMDB_ERR_INVALID, "NULL cannot be an operand: the result would always be unknown (use IS NULL)");
    }
}

/* node k, if a string literal, read again as a TIMESTAMP (a malformed one is the parse's error) */
static int ts_lit(xctx *x, const sql_stmt *st, uint16_t k, imdb_err *e)
{
    const sql_expr *n = &st->ex[k];
    if (n->op != EX_LIT || n->lit.kind != LIT_STR) return IMDB_OK;
    int64_t us;
    if (imdb_parse_timestamp(x->sql + n->lit.off, n->lit.len, &us, e)) return e->code;
    imdb_xnode *b = &x->xn[k];
    memset(&b->k, 0, sizeof b->k);
    b->k.type = b->type = IMDB_T_TIMESTAMP;
    b->k.i = us;
    return IMDB_OK;
}

static int xbind(xctx *x, xscope *sc, uint16_t k, imdb_err *e)
{
    const sql_expr *n = &sc->st->ex[k];
    imdb_xnode *b = &x->xn[k];
    switch (n->op) {
    case EX_LIT:
        if (bind_xlit(x, &n->lit, &b->k, e)) return e->code;
        b->type = b->k.type;
        b->scale = b->k.scale;
        return IMDB_OK;
    case EX_COL: {
        if (!sc->cols) return imdb_fail(e, IMDB_ERR_INVALID, "column %s cannot be read here: VALUES takes constants", n->col);
        int c, side;
        if (sc->jt) {
            if (join_col(sc->st, sc->jt, n->qual, n->col, &side, &c, e)) return e->code;
            c = side ? sc->nc0 + c : c;
        } else if ((c = one_col(sc->st, sc->t, n->qual, n->col, e)) < 0) {
            return c;
        }
        if (sc->group_col >= 0 && !sc->in_agg && c != sc->group_col)
            return imdb_fail(e, IMDB_ERR_INVALID, "column %s must be the GROUP BY column or inside an aggregate", n->col);
        b->col = (int16_t)c;
        b->type = sc->s->cols[c].type;
        b->scale = sc->s->cols[c].scale;
        return IMDB_OK;
    }
    case EX_AGG: {
        if (!sc->aggs || sc->in_agg)
            return imdb_fail(e, IMDB_ERR_INVALID, sc->in_agg ? "an aggregate inside an aggregate"
                                                            : "an aggregate stands only in a SELECT list");
        b->type = IMDB_T_INT64; /* COUNT */
        if (n->l) {
            sc->in_agg = true;
            int rc = xbind(x, sc, n->l, e);
            sc->in_agg = false;
            if (rc) return rc;
            const imdb_xnode *a = &x->xn[n->l];
            bool num = a->type == IMDB_T_INT64 || a->type == IMDB_T_DECIMAL || a->type == IMDB_T_FLOAT64;
            if ((n->agg == AGG_SUM || n->agg == AGG_AVG) && !num)
                return imdb_fail(e, IMDB_ERR_INVALID, n->agg == AGG_SUM ? "SUM needs an INT64, DECIMAL or FLOAT64 value"
                                                                      : "AVG needs an INT64, DECIMAL or FLOAT64 value");
            if (n->agg != AGG_COUNT) b->type = a->type, b->scale = a->scale;
            if (n->agg == AGG_AVG && a->type != IMDB_T_FLOAT64) { /* 1e: SUM / COUNT by the division rule: six more places */
                unsigned s = (a->type == IMDB_T_DECIMAL ? a->scale : 0u) + 6u;
                if (s > IMDB_X_MAX_SCALE)
                    return imdb_fail(e, IMDB_ERR_LIMIT, "AVG of a DECIMAL past %u decimal places", IMDB_X_MAX_SCALE - 6);
                b->type = IMDB_T_DECIMAL;
                b->scale = (uint8_t)s;
            }
        }
        if (sc->nslot >= IMDB_MAX_COLS)
            return imdb_fail(e, IMDB_ERR_LIMIT, "more than %u aggregates in expressions of one SELECT list", IMDB_MAX_COLS);
        if (sc->agg_nodes) sc->agg_nodes[sc->nslot] = k;
        b->slot = sc->nslot++;
        return IMDB_OK;
    }
    case EX_NEG:
        if (xbind(x, sc, n->l, e)) return e->code;
        b->type = x->xn[n->l].type;
        b->scale = x->xn[n->l].scale;
        if (b->type != IMDB_T_INT64 && b->type != IMDB_T_DECIMAL && b->type != IMDB_T_FLOAT64)
            return imdb_fail(e, IMDB_ERR_INVALID, "arithmetic takes INT64, DECIMAL and FLOAT64 values");
        return IMDB_OK;
    case EX_CMP: { /* a BOOL (1c): the operands comparable (two numbers, or one type), never converted */
        b->type = IMDB_T_BOOL;
        if (xbind(x, sc, n->l, e)) return e->code;
        if (n->cmp == CMP_ISNULL || n->cmp == CMP_NOTNULL) return IMDB_OK;
        uint16_t ops[2] = {n->r, n->x3};
        for (int i = 0; i < (n->cmp == CMP_BETWEEN ? 2 : 1); i++) {
            if (xbind(x, sc, ops[i], e)) return e->code;
            /* a string literal against a TIMESTAMP is a timestamp, as against a TIMESTAMP column in today's form
             * (ts >= '2026-01-01' OR k): read as one, never compared as text */
            if (x->xn[n->l].type == IMDB_T_TIMESTAMP && ts_lit(x, sc->st, ops[i], e)) return e->code;
            if (x->xn[ops[i]].type == IMDB_T_TIMESTAMP && ts_lit(x, sc->st, n->l, e)) return e->code;
            uint8_t ta = x->xn[n->l].type, tb = x->xn[ops[i]].type;
            if (!imdb_x_comparable(ta, tb))
                return imdb_fail(e, IMDB_ERR_INVALID, "a comparison of %s with %s: values are not converted",
                                 imdb_type_name(ta), imdb_type_name(tb));
            if (ta == IMDB_T_BOOL && n->cmp != CMP_EQ && n->cmp != CMP_NE) /* as a BOOL column's own predicates */
                return imdb_fail(e, IMDB_ERR_INVALID, "BOOL values support only = and !=");
        }
        return IMDB_OK;
    }
    case EX_AND:
    case EX_OR:
    case EX_NOT:
        b->type = IMDB_T_BOOL;
        for (int i = 0; i < (n->op == EX_NOT ? 1 : 2); i++) {
            uint16_t o = i ? n->r : n->l;
            if (xbind(x, sc, o, e)) return e->code;
            if (x->xn[o].type != IMDB_T_BOOL)
                return imdb_fail(e, IMDB_ERR_INVALID, "AND, OR and NOT take conditions: comparisons, IS NULL or BOOL values");
        }
        return IMDB_OK;
    default:
        if (xbind(x, sc, n->l, e) || xbind(x, sc, n->r, e)) return e->code;
        return imdb_x_type(n->op, x->xn[n->l].type, x->xn[n->l].scale, x->xn[n->r].type, x->xn[n->r].scale, &b->type,
                           &b->scale, e);
    }
}

/* a tree of constants (VALUES) bound, computed and stored by assignment into column c */
static int bind_const_tree(xctx *x, const sql_stmt *st, uint16_t k, const imdb_column *c, imdb_value *out, imdb_err *e)
{
    xscope sc = {.st = st, .group_col = -1};
    imdb_xval v;
    if (xnodes(x, st, e) || xbind(x, &sc, k, e) || imdb_x_eval(st, x->xn, k, NULL, NULL, &v, e)) return e->code;
    return imdb_x_assign(c, &v, out, e);
}

/* ---- predicates ------------------------------------------------------------------ */

typedef struct bpred {
    uint16_t col;
    uint8_t type;
    uint8_t op;
    bool neg;
    int64_t lo, hi;          /* int-like: inclusive range */
    imdb_value a, b;         /* TEXT */
} bpred;

typedef struct qspec {
    imdb_table *t;
    uint64_t snap;
    uint64_t pend;           /* the reader's pending marker (seq + 1 in its transaction), 0 for none */
    bpred p[IMDB_MAX_PREDICATES];
    uint16_t np;
    bool never;              /* an empty range: nothing can match */
    int pk_pred, subj_pred;  /* index of an equality predicate on PK / SUBJECT, -1 */
    int ord_pred;            /* a predicate an ordered index serves (choose_ordered), -1 */
    const imdb_index *ord_idx;
    uint8_t ord_neq;         /* its first ord_neq columns are equalities (predicates ord_eq), */
    int16_t ord_eq[IMDB_MAX_INDEX_COLS], ord_rng; /* then a range on the next (ord_rng), or -1 */
    bool all_versions;       /* ERASE: match every non-stub version regardless of snapshot */
    bool ord_only;           /* the ordered index alone answers (ordered_only) */
} qspec;

/* An ordered index for the bound predicates: equalities on its first columns, then perhaps a
 * range (not a negation) on the next. The one with the most equalities wins, then one with the
 * range, then the first by name (a table keeps its indexes sorted). lead >= 0: only an index whose
 * first column is lead (plan C's probe of a join key), else any. */
static void choose_ordered(qspec *q, int lead)
{
    const imdb_table *t = q->t;
    q->ord_pred = q->ord_rng = -1;
    q->ord_idx = NULL;
    q->ord_neq = 0;
    for (uint32_t k = 0; k < t->nidx; k++) {
        const imdb_index *ix = &t->idx[k];
        if (!ix->ox || (lead >= 0 && ix->d.cols[0] != lead)) continue;
        int16_t eq[IMDB_MAX_INDEX_COLS] = {0}, rng = -1;
        uint8_t neq = 0;
        for (uint8_t c = 0; c < ix->d.ncols; c++) {
            int16_t pe = -1, pr = -1;
            for (uint16_t i = 0; i < q->np; i++) {
                const bpred *b = &q->p[i];
                if (b->col != ix->d.cols[c] || b->neg) continue;
                if (b->op == CMP_EQ && pe < 0) pe = (int16_t)i;
                else if ((b->op == CMP_LT || b->op == CMP_LE || b->op == CMP_GT || b->op == CMP_GE || b->op == CMP_BETWEEN) &&
                         pr < 0)
                    pr = (int16_t)i;
            }
            if (pe >= 0) {
                eq[neq++] = pe;
                continue;
            }
            rng = pr;
            break;
        }
        if (!neq && rng < 0) continue;
        if (q->ord_idx && (neq < q->ord_neq || (neq == q->ord_neq && (rng < 0 || q->ord_rng >= 0)))) continue;
        q->ord_idx = ix;
        q->ord_neq = neq;
        memcpy(q->ord_eq, eq, sizeof eq);
        q->ord_rng = rng;
        q->ord_pred = neq ? eq[0] : rng;
    }
}

/* a column of a one-table statement: a qualifier must name the table, or its alias */
static int one_col(const sql_stmt *st, const imdb_table *t, const char *qual, const char *name, imdb_err *e)
{
    if (qual[0] && strcmp(qual, st->alias[0] ? st->alias : t->s.name) != 0)
        return imdb_fail(e, IMDB_ERR_NOTFOUND, "no table %s in this statement", qual);
    int col = imdb_schema_col(&t->s, name);
    if (col < 0) return imdb_fail(e, IMDB_ERR_NOTFOUND, "no column %s in table %s", name, t->s.name);
    return col;
}

/* One predicate on column col of q's table. post: evaluated on a row a LEFT join may have
 * NULL-extended, so IS NULL is a real test even on a NOT NULL column. */
static int bind_pred(xctx *x, const sql_cmp *c, int col, bool post, qspec *q, imdb_err *e)
{
    imdb_table *t = q->t;
    const imdb_column *cd = &t->s.cols[col];
    bpred *b = &q->p[q->np++];
    memset(b, 0, sizeof *b);
    b->col = (uint16_t)col;
    b->type = cd->type;
    b->op = c->op;
    if (c->op == CMP_ISNULL || c->op == CMP_NOTNULL) {
        if (!post && !(cd->flags & IMDB_COL_NULLABLE)) { /* never NULL: IS NULL matches nothing, IS NOT NULL everything */
            if (c->op == CMP_ISNULL) q->never = true;
            q->np--;
        }
        return IMDB_OK;
    }
    if (c->a.kind == LIT_NULL || (c->op == CMP_BETWEEN && c->b.kind == LIT_NULL))
        return imdb_fail(e, IMDB_ERR_INVALID, "a comparison with NULL is never true; use IS NULL or IS NOT NULL");
    if (bind_lit(x, &c->a, cd, true, &b->a, e)) return e->code;
    if (c->op == CMP_BETWEEN && bind_lit(x, &c->b, cd, true, &b->b, e)) return e->code;
    /* Parameters obey the same rule as literal NULL. Never interpret a
     * NULL's unused value bytes as a numeric bound or a TEXT key. */
    if (b->a.null || (c->op == CMP_BETWEEN && b->b.null))
        return imdb_fail(e, IMDB_ERR_INVALID, "a comparison with NULL is never true; use IS NULL or IS NOT NULL");
    if (cd->type == IMDB_T_BOOL && c->op != CMP_EQ && c->op != CMP_NE)
        return imdb_fail(e, IMDB_ERR_INVALID, "BOOL column %s supports only = and !=", cd->name);
    if (cd->type != IMDB_T_TEXT) {
        int64_t v = b->a.i;
        b->lo = INT64_MIN;
        b->hi = INT64_MAX;
        switch (c->op) {
        case CMP_EQ: b->lo = b->hi = v; break;
        case CMP_NE: b->lo = b->hi = v; b->neg = true; break;
        case CMP_LT: if (v == INT64_MIN) q->never = true; else b->hi = v - 1; break;
        case CMP_LE: b->hi = v; break;
        case CMP_GT: if (v == INT64_MAX) q->never = true; else b->lo = v + 1; break;
        case CMP_GE: b->lo = v; break;
        case CMP_BETWEEN: b->lo = v; b->hi = b->b.i; if (b->lo > b->hi) q->never = true; break;
        }
    } else if (c->op == CMP_BETWEEN && imdb_value_cmp(&b->a, &b->b) > 0) {
        q->never = true;
    }
    if (c->op == CMP_EQ && col == t->s.pk && q->pk_pred < 0) q->pk_pred = q->np - 1;
    if (c->op == CMP_EQ && col == t->s.subject && q->subj_pred < 0) q->subj_pred = q->np - 1;
    return IMDB_OK;
}

static bool falls_back(const sql_cmp *c, const imdb_column *cd);

static int bind_preds(xctx *x, const sql_stmt *st, qspec *q, imdb_err *e)
{
    q->pk_pred = q->subj_pred = q->ord_pred = -1;
    for (uint16_t i = 0; i < st->nwhere; i++) {
        if (st->where[i].lx) continue; /* a tree's: the sink's (bind_resid) */
        int col = one_col(st, q->t, st->where[i].qual, st->where[i].col, e);
        if (col < 0) return col;
        uint16_t np = q->np;
        if (bind_pred(x, &st->where[i], col, false, q, e)) {
            if (!falls_back(&st->where[i], &q->t->s.cols[col])) return e->code;
            q->np = np; /* the literal is another numeric kind: a residual (bind_resid) */
            x->fb[i] = true;
            imdb_err_clear(e);
        }
    }
    choose_ordered(q, -1);
    return IMDB_OK;
}

static bool pred_ok(const bpred *b, const imdb_value *v)
{
    if (b->op == CMP_ISNULL) return v->null;
    if (b->op == CMP_NOTNULL) return !v->null;
    if (v->null) return false; /* a comparison with NULL is not true (WHERE is a conjunction) */
    if (b->type != IMDB_T_TEXT) {
        bool in = v->i >= b->lo && v->i <= b->hi;
        return b->neg ? !in : in;
    }
    int c = imdb_value_cmp(v, &b->a);
    switch (b->op) {
    case CMP_EQ: return c == 0;
    case CMP_NE: return c != 0;
    case CMP_LT: return c < 0;
    case CMP_LE: return c <= 0;
    case CMP_GT: return c > 0;
    case CMP_GE: return c >= 0;
    case CMP_BETWEEN: return c >= 0 && imdb_value_cmp(v, &b->b) <= 0;
    }
    return false;
}

static bool preds_ok(const qspec *q, const imdb_value *vals)
{
    for (uint16_t i = 0; i < q->np; i++)
        if (!pred_ok(&q->p[i], &vals[q->p[i].col])) return false;
    return true;
}

/* ---- sinks: what a read path feeds matching rows into ----------------------------- */

typedef struct agg_acc {
    uint64_t count;          /* COUNT(*): rows; otherwise non-null values */
    __int128 sum;
    imdb_fsum fsum;          /* SUM of a FLOAT64 column, exact */
    bool has;
    imdb_value mn, mx;
} agg_acc;

/* an aggregate inside a tree item (an EX_AGG node's slot): its argument is a tree, its values expression values */
typedef struct xacc {
    uint64_t count;
    __int128 sum;            /* INT64, DECIMAL at the argument's scale: checked under 10^38 */
    imdb_fsum fsum;          /* FLOAT64, exact */
    bool has;
    imdb_xval mn, mx;        /* never a pointer into a row: a tree's TEXT is a literal's or a parameter's */
} xacc;

static int xacc_add(xacc *a, uint8_t agg, const imdb_xval *v, imdb_err *e)
{
    if (agg == AGG_COUNT_STAR) {
        a->count++;
        return IMDB_OK;
    }
    if (v->null) return IMDB_OK;
    a->count++;
    bool sum = agg == AGG_SUM || agg == AGG_AVG; /* AVG: the same sum, divided at the end (1e) */
    if (sum && v->type == IMDB_T_FLOAT64) {
        if (imdb_fsum_add(&a->fsum, imdb_f64_key(v->f), e)) return e->code;
    } else if (sum) {
        const __int128 lim = (__int128)10000000000000000000ull * 10000000000000000000ull; /* 10^38 */
        if (__builtin_add_overflow(a->sum, v->i, &a->sum) || a->sum >= lim || a->sum <= -lim)
            return imdb_fail(e, IMDB_ERR_LIMIT, agg == AGG_AVG ? "an AVG's sum of more than 38 digits" : "a SUM of more than 38 digits");
    } else if (agg == AGG_MIN || agg == AGG_MAX) {
        if (!a->has || imdb_x_cmp(v, &a->mn) < 0) a->mn = *v;
        if (!a->has || imdb_x_cmp(v, &a->mx) > 0) a->mx = *v;
    }
    a->has = true;
    return IMDB_OK;
}

/* an accumulator's final value, typed as the node was bound (an AVG's sum by its argument's type, ta and sa) */
static int xacc_value(xacc *a, uint8_t agg, const imdb_xnode *b, uint8_t ta, uint8_t sa, imdb_xval *out, imdb_err *e)
{
    memset(out, 0, sizeof *out);
    out->type = b->type;
    out->scale = b->scale;
    if (agg == AGG_COUNT_STAR || agg == AGG_COUNT) {
        out->i = (__int128)a->count;
        return IMDB_OK;
    }
    if (!a->has) {
        out->null = true;
        return IMDB_OK;
    }
    if (agg == AGG_AVG) { /* SUM / COUNT once, by the division rule (sql_expr.c): DECIMAL six places past, or FLOAT64 */
        imdb_xval s = {.type = ta, .scale = sa}, n = {.type = IMDB_T_INT64, .i = (__int128)a->count};
        if (ta == IMDB_T_FLOAT64) {
            int64_t key;
            if (imdb_fsum_result(&a->fsum, &key, e)) return e->code;
            s.f = imdb_f64_value(key);
        } else {
            s.i = a->sum;
        }
        return imdb_x_arith(EX_DIV, &s, &n, b->type, b->scale, out, e);
    }
    if (agg != AGG_SUM) {
        *out = agg == AGG_MIN ? a->mn : a->mx;
        return IMDB_OK;
    }
    if (b->type != IMDB_T_FLOAT64) {
        out->i = a->sum;
        return IMDB_OK;
    }
    int64_t key;
    if (imdb_fsum_result(&a->fsum, &key, e)) return e->code;
    out->f = imdb_f64_value(key);
    return IMDB_OK;
}

typedef struct group {
    imdb_value key;
} group;

enum { SINK_VIDS = 1, SINK_AGG, SINK_GROUP, SINK_DIGEST, SINK_JBUILD, SINK_JPROBE, SINK_JOUTER, SINK_JINNER };

typedef struct sink {
    int mode;
    xctx *x;
    const sql_stmt *st;
    imdb_table *t;
    int item_col[IMDB_MAX_COLS];
    uint64_t *vids;
    uint64_t nvids, capvids;
    agg_acc acc[IMDB_MAX_COLS];
    imdb_hmap gmap;
    bool has_null_group;     /* GROUP BY: the NULL key's group, kept outside gmap */
    uint64_t null_group;
    group *groups;
    agg_acc *gacc;           /* ngroups x nitems, flat */
    uint64_t ngroups, capgroups;
    int gcol;
    imdb_lthash digest;
    uint64_t digest_rows;
    int err;
    imdb_err *e;
    struct jctx *j;          /* SINK_JBUILD, SINK_JPROBE, SINK_JOUTER, SINK_JINNER: the join they feed */
    bool joined;             /* a join's output: its rows are pairs, tested where the join forms them (xtested) */
    uint16_t resid[IMDB_MAX_PREDICATES]; /* WHERE's tree conjuncts (st->where), tested on every row fed: the one door */
    uint16_t nresid;
    bool trees;              /* a SELECT item is a tree: no path that answers without the rows (fast_aggregate,
                              * ordered_only) */
    uint16_t nxa;            /* the trees' aggregates: slot s is node xa_node[s], its accumulator xa[s] (grouped: */
    uint16_t xa_node[IMDB_MAX_COLS]; /* gxa[g * nxa + s]) */
    xacc *xa;                /* allocated only when a tree holds one (xalloc): a sink lives on the caller's stack */
    xacc *gxa;
} sink;

/* xtick for a sink's loop: its error set, so the path stops there (every path loop tests k->err) */
static inline bool ktick(sink *k, uint64_t n)
{
    int rc = xtick(k->x, n, k->e);
    if (rc) k->err = rc;
    return rc != 0;
}

/* every tree aggregate of a row: its argument computed, then accumulated */
static int xa_row(sink *k, xacc *acc, const imdb_value *vals)
{
    const sql_stmt *st = k->st;
    for (uint16_t s = 0; s < k->nxa; s++) {
        const sql_expr *n = &st->ex[k->xa_node[s]];
        imdb_xval v = {.null = false};
        if (n->agg != AGG_COUNT_STAR && imdb_x_eval(st, k->x->xn, n->l, vals, NULL, &v, k->e)) return k->e->code;
        if (xacc_add(&acc[s], n->agg, &v, k->e)) return k->e->code;
    }
    return IMDB_OK;
}

/* a residual's boolean tree: a tree conjunct's own, or today's form's comparison node when it fell back */
static uint16_t cmp_root(const sql_cmp *c) { return c->lx ? c->lx : c->nl; }

/* col op literal whose literal is a number of another kind than its numeric column's (1.25 for an INT64, 1.005 for a
 * DECIMAL of scale 2, 2.5e0 for either): compared exactly as a tree, as col + 0 op 1.25 is (a residual: no index
 * serves it), where binding the literal to the column's type would refuse it. Nothing is converted. */
static bool falls_back(const sql_cmp *c, const imdb_column *cd)
{
    bool num_a = c->a.kind == LIT_INT || c->a.kind == LIT_DEC || c->a.kind == LIT_FLOAT;
    bool num_b = c->op != CMP_BETWEEN || c->b.kind == LIT_INT || c->b.kind == LIT_DEC || c->b.kind == LIT_FLOAT;
    return !c->lx && c->nl && c->op != CMP_ISNULL && c->op != CMP_NOTNULL && num_a && num_b &&
           (cd->type == IMDB_T_INT64 || cd->type == IMDB_T_DECIMAL || cd->type == IMDB_T_FLOAT64);
}

/* WHERE's residual conjuncts ri[0..n) on a row: *ok when every one is TRUE (FALSE and UNKNOWN are not), in WHERE's
 * order, each tree three-valued and left to right (sql_expr.c). A row reaches them only past every bound predicate,
 * on any path, and the tree fixes what is computed, so whether an operation fails (a zero divisor) never depends on
 * the plan. */
static int resid_ok(const xctx *x, const sql_stmt *st, const uint16_t *ri, uint16_t n, const imdb_value *row, bool *ok,
                    imdb_err *e)
{
    *ok = false;
    for (uint16_t i = 0; i < n; i++) {
        imdb_xval v;
        if (imdb_x_eval(st, x->xn, cmp_root(&st->where[ri[i]]), row, NULL, &v, e)) return e->code;
        if (!imdb_x_true(&v)) return IMDB_OK;
    }
    *ok = true;
    return IMDB_OK;
}

/* WHERE's residual conjuncts bound to the row a scope reads (each a condition), their indexes into out */
static int bind_resid(xctx *x, xscope *sc, uint16_t *out, uint16_t *n, imdb_err *e)
{
    const sql_stmt *st = sc->st;
    *n = 0;
    for (uint16_t i = 0; i < st->nwhere; i++) {
        const sql_cmp *c = &st->where[i];
        if (!c->lx && !x->fb[i]) continue;
        uint16_t k = cmp_root(c);
        if (xnodes(x, st, e) || xbind(x, sc, k, e)) return e->code;
        if (x->xn[k].type != IMDB_T_BOOL)
            return imdb_fail(e, IMDB_ERR_INVALID, "WHERE takes a condition: a comparison, IS NULL, AND, OR, NOT or a BOOL");
        out[(*n)++] = i;
    }
    return IMDB_OK;
}

/* the columns a tree reads, marked in use[c - off] for c in [off, off + n) */
static void x_cols(const sql_stmt *st, const imdb_xnode *xn, uint16_t k, bool *use, int off, int n)
{
    if (!k) return;
    const sql_expr *x = &st->ex[k];
    if (x->op == EX_COL && xn[k].col >= off && xn[k].col < off + n) use[xn[k].col - off] = true;
    x_cols(st, xn, x->l, use, off, n); /* height-bounded */
    x_cols(st, xn, x->r, use, off, n);
    x_cols(st, xn, x->x3, use, off, n);
}

static void join_build_row(sink *k, uint64_t vid, const imdb_value *vals);
static void join_probe_row(sink *k, uint64_t vid, const imdb_value *vals);
static void join_outer_row(sink *k, uint64_t vid, const imdb_value *vals);
static void join_inner_row(sink *k, uint64_t vid, const imdb_value *vals);

static int acc_add(agg_acc *a, uint8_t agg, const imdb_value *v, imdb_err *e)
{
    if (agg == AGG_COUNT_STAR) {
        a->count++;
        return IMDB_OK;
    }
    if (v->null) return IMDB_OK; /* aggregates ignore NULLs */
    a->count++;
    if (agg == AGG_SUM && v->type == IMDB_T_FLOAT64 && imdb_fsum_add(&a->fsum, v->i, e)) return e->code;
    if (agg == AGG_SUM && v->type != IMDB_T_FLOAT64) a->sum += v->i;
    if (agg == AGG_MIN || agg == AGG_MAX) {
        if (!a->has || imdb_value_cmp(v, &a->mn) < 0) a->mn = *v;
        if (!a->has || imdb_value_cmp(v, &a->mx) > 0) a->mx = *v;
    }
    a->has = true;
    return IMDB_OK;
}

static void sink_row(sink *k, uint64_t vid, const imdb_value *vals)
{
    if (k->err) return;
    if (k->mode < SINK_JBUILD && !k->joined && k->x && xtested(k->x, 1, k->e)) { /* a join side's rows are not: its pairs are */
        k->err = k->e->code;
        return;
    }
    if (k->nresid) {
        bool ok;
        if (resid_ok(k->x, k->st, k->resid, k->nresid, vals, &ok, k->e)) {
            k->err = k->e->code;
            return;
        }
        if (!ok) return;
    }
    switch (k->mode) {
    case SINK_VIDS:
        if (k->nvids == k->capvids) {
            uint64_t nc = k->capvids ? k->capvids * 2 : 256;
            uint64_t *nv = imdb_realloc_array(k->vids, k->capvids, nc, sizeof *nv, k->e);
            if (!nv) {
                k->err = k->e->code;
                return;
            }
            k->vids = nv;
            k->capvids = nc;
        }
        k->vids[k->nvids++] = vid;
        return;
    case SINK_AGG:
        for (uint16_t i = 0; i < k->st->nitems; i++) {
            if (k->st->items[i].expr) continue; /* a tree: its aggregates are slots (xa_row) */
            int c = k->item_col[i];
            if (acc_add(&k->acc[i], k->st->items[i].agg, c >= 0 ? &vals[c] : NULL, k->e)) {
                k->err = k->e->code;
                return;
            }
        }
        if (k->nxa && xa_row(k, k->xa, vals)) k->err = k->e->code;
        return;
    case SINK_JBUILD: join_build_row(k, vid, vals); return;
    case SINK_JPROBE: join_probe_row(k, vid, vals); return;
    case SINK_JOUTER: join_outer_row(k, vid, vals); return;
    case SINK_JINNER: join_inner_row(k, vid, vals); return;
    case SINK_DIGEST: {
        const uint8_t *cm;
        if (imdb_v_commit(k->t, vid, &cm, k->e)) {
            k->err = k->e->code;
            return;
        }
        imdb_lthash_add_commit(k->x->db->meta.digest_alg, &k->digest, cm);
        k->digest_rows++;
        return;
    }
    case SINK_GROUP: {
        const imdb_value *key = &vals[k->gcol];
        uint64_t *gi = key->null ? (k->has_null_group ? &k->null_group : NULL) : imdb_hmap_get(&k->gmap, key);
        uint64_t g;
        if (gi) {
            g = *gi;
        } else {
            if (k->ngroups >= IMDB_MAX_GROUPS) {
                k->err = imdb_fail(k->e, IMDB_ERR_LIMIT, "GROUP BY produced more than %u groups", IMDB_MAX_GROUPS);
                return;
            }
            uint16_t ni = k->st->nitems;
            if (k->ngroups == k->capgroups) {
                uint64_t nc = k->capgroups ? k->capgroups * 2 : 64;
                group *ng = imdb_realloc_array(k->groups, k->capgroups, nc, sizeof *ng, k->e);
                if (!ng) {
                    k->err = k->e->code;
                    return;
                }
                k->groups = ng;
                agg_acc *na = imdb_realloc_array(k->gacc, k->capgroups * ni, nc * ni, sizeof *na, k->e);
                if (!na) {
                    k->err = k->e->code;
                    return;
                }
                k->gacc = na;
                if (k->nxa) {
                    xacc *nx = imdb_realloc_array(k->gxa, k->capgroups * k->nxa, nc * k->nxa, sizeof *nx, k->e);
                    if (!nx) {
                        k->err = k->e->code;
                        return;
                    }
                    k->gxa = nx;
                }
                k->capgroups = nc;
            }
            g = k->ngroups++;
            memset(&k->groups[g], 0, sizeof k->groups[g]);
            memset(&k->gacc[g * ni], 0, sizeof *k->gacc * ni);
            if (k->nxa) memset(&k->gxa[g * k->nxa], 0, sizeof *k->gxa * k->nxa);
            k->groups[g].key = *key;
            if (key->null) {
                k->has_null_group = true;
                k->null_group = g;
            } else if (xpin(k->x, &k->groups[g].key, k->e) || imdb_hmap_put(&k->gmap, key, g, k->e)) {
                k->err = k->e->code;
                return;
            }
        }
        for (uint16_t i = 0; i < k->st->nitems; i++) {
            if (k->st->items[i].agg == AGG_NONE) continue;
            int c = k->item_col[i];
            if (acc_add(&k->gacc[g * k->st->nitems + i], k->st->items[i].agg, c >= 0 ? &vals[c] : NULL, k->e)) {
                k->err = k->e->code;
                return;
            }
        }
        if (k->nxa && xa_row(k, &k->gxa[g * k->nxa], vals)) k->err = k->e->code;
        return;
    }
    }
}

/* MIN/MAX TEXT values must outlive the rows they came from. */
static int sink_pin(sink *k)
{
    for (uint16_t i = 0; i < IMDB_MAX_COLS; i++) {
        if (xpin(k->x, &k->acc[i].mn, k->e) || xpin(k->x, &k->acc[i].mx, k->e)) return k->e->code;
    }
    return IMDB_OK;
}

static void sink_free(sink *k)
{
    for (uint16_t i = 0; i < IMDB_MAX_COLS; i++) imdb_fsum_free(&k->acc[i].fsum);
    for (uint64_t i = 0; k->gacc && k->st && i < k->ngroups * k->st->nitems; i++) imdb_fsum_free(&k->gacc[i].fsum);
    for (uint16_t s = 0; k->xa && s < k->nxa; s++) imdb_fsum_free(&k->xa[s].fsum); /* xa itself: the statement's */
    for (uint64_t i = 0; k->gxa && i < k->ngroups * k->nxa; i++) imdb_fsum_free(&k->gxa[i].fsum);
    imdb_free(k->vids);
    imdb_free(k->groups);
    imdb_free(k->gacc);
    imdb_free(k->gxa);
    if (k->gmap.slots) imdb_hmap_free(&k->gmap);
}

/* ---- the three read paths --------------------------------------------------------- */

static int fetch_row(xctx *x, imdb_table *t, uint64_t vid, imdb_value *vals, imdb_err *e)
{
    return imdb_version_values(x->db, t, vid, vals, e);
}

/* A walk's pinned segment (stage 3c-1): the held versions of a segment come together in vid order, so a walk pins
 * each segment once and reads its rows from the image directly, not through a pin a row. Good for the walk only
 * (nothing drops an image, and no publish replaces the segments, inside an operation). */
typedef struct walk_pin {
    uint32_t seg; /* t->seg index of gi (UINT32_MAX: none yet) */
    const imdb_segimg *gi;
} walk_pin;

static int walk_values(imdb_table *t, const imdb_version *v, walk_pin *wp, imdb_value *vals, imdb_err *e)
{
    if ((v->flags & (IMDB_V_SEG | IMDB_V_STUB | IMDB_V_PURGED)) != IMDB_V_SEG) return imdb_version_values_v(t, v, vals, e);
    if (v->seg != wp->seg) {
        if (v->seg >= t->nseg) return imdb_fail(e, IMDB_ERR_STATE, "version maps to a missing segment");
        if (!(wp->gi = imdb_seg_pin(t, t->seg[v->seg], e))) return e->code;
        wp->seg = v->seg;
    }
    imdb_seg_row_values(&t->s, wp->gi, v->seg_row, vals);
    return IMDB_OK;
}

static bool visible_q(const qspec *q, const imdb_version *v)
{
    if (q->all_versions) return !(v->flags & (IMDB_V_STUB | IMDB_V_PURGED));
    return imdb_visible_at(v, q->snap, q->pend);
}

static int path_store(xctx *x, const qspec *q, sink *k, imdb_err *e)
{
    imdb_table *t = q->t;
    imdb_value vals[IMDB_MAX_COLS];
    walk_pin wp = {UINT32_MAX, NULL};
    for (uint64_t vid = imdb_v_next(t, 0); vid < t->nver && !k->err; vid = imdb_v_next(t, vid + 1)) {
        if (ktick(k, 1)) break;
        const imdb_version *v = imdb_vh(t, vid); /* held: the walk has its entry */
        if (!visible_q(q, v)) continue;
        if (walk_values(t, v, &wp, vals, e)) return e->code;
        if (preds_ok(q, vals)) sink_row(k, vid, vals);
    }
    return k->err;
}

static int path_index(xctx *x, const qspec *q, sink *k, imdb_err *e)
{
    imdb_table *t = q->t;
    imdb_value vals[IMDB_MAX_COLS];
    if (q->pk_pred >= 0 && !q->all_versions) {
        uint64_t vid;
        if (imdb_lookup_pk_at(x->db, t, &q->p[q->pk_pred].a, q->snap, q->pend, &vid, e)) return e->code;
        if (vid == IMDB_NONE) return IMDB_OK;
        if (fetch_row(x, t, vid, vals, e)) return e->code;
        if (preds_ok(q, vals)) sink_row(k, vid, vals);
        return k->err;
    }
    if (q->subj_pred >= 0) {
        walk_pin wp = {UINT32_MAX, NULL};
        const imdb_vlist *l = imdb_subject_versions(t, &q->p[q->subj_pred].a);
        for (uint32_t i = 0; l && i < l->n && !k->err; i++) {
            if (ktick(k, 1)) break;
            uint64_t vid = l->v[i];
            const imdb_version *v = imdb_vh(t, vid); /* held: the walk has its entry */
            if (!visible_q(q, v)) continue;
            if (walk_values(t, v, &wp, vals, e)) return e->code;
            if (preds_ok(q, vals)) sink_row(k, vid, vals);
        }
        return k->err;
    }
    return path_store(x, q, k, e);
}

/* ---- the ordered path (CREATE INDEX): candidates from the index, checked like any row --------- */

/* one predicate as one key word's range (db.h imdb_index_key_of); a TEXT word is the 8-byte
 * prefix, so the range is a superset and every predicate is checked again on each row */
static void word_bounds(const bpred *b, uint64_t *lo, uint64_t *hi)
{
    if (b->type != IMDB_T_TEXT) {
        *lo = (uint64_t)b->lo ^ (1ull << 63);
        *hi = (uint64_t)b->hi ^ (1ull << 63);
        return;
    }
    uint64_t ka = 0, kb = UINT64_MAX;
    imdb_index_key_of(&b->a, &ka);
    *lo = 0;
    *hi = UINT64_MAX;
    if (b->op == CMP_EQ || b->op == CMP_GT || b->op == CMP_GE || b->op == CMP_BETWEEN) *lo = ka;
    if (b->op == CMP_EQ || b->op == CMP_LT || b->op == CMP_LE) *hi = ka;
    if (b->op == CMP_BETWEEN && imdb_index_key_of(&b->b, &kb)) *hi = kb;
}

/* the chosen index's key range: its equalities, then the range, then any value of the rest */
static void ord_bounds(const qspec *q, uint64_t *lo, uint64_t *hi)
{
    uint8_t nk = q->ord_idx->d.ncols, c = 0;
    for (; c < q->ord_neq; c++) word_bounds(&q->p[q->ord_eq[c]], &lo[c], &hi[c]);
    if (q->ord_rng >= 0 && c < nk) word_bounds(&q->p[q->ord_rng], &lo[c], &hi[c]), c++;
    for (; c < nk; c++) lo[c] = 0, hi[c] = UINT64_MAX;
}

typedef struct octx {
    xctx *x;
    const qspec *q;
    sink *k;
    imdb_value *vals;
    imdb_err *e;
} octx;

static int ord_fetch(octx *o, uint64_t vid)
{
    imdb_table *t = o->q->t;
    if (ktick(o->k, 1)) return o->k->err;
    if (vid >= t->nver || !visible_q(o->q, imdb_vh(t, vid))) return IMDB_OK;
    if (fetch_row(o->x, t, vid, o->vals, o->e)) return o->e->code;
    if (preds_ok(o->q, o->vals)) sink_row(o->k, vid, o->vals);
    return o->k->err;
}

static int ord_visit(void *ctx, const uint64_t *key, uint64_t vid)
{
    (void)key;
    return ord_fetch(ctx, vid);
}

/* index-only: the row is never read; its value is the key's (db.c imdb_index_key_of: every type
 * but TEXT is an order-preserving int64, and the key is that int64 with the sign bit flipped) */
static int ord_only_visit(void *ctx, const uint64_t *key, uint64_t vid)
{
    octx *o = ctx;
    imdb_table *t = o->q->t;
    if (ktick(o->k, 1)) return o->k->err;
    if (vid >= t->nver || !visible_q(o->q, imdb_vh(t, vid))) return IMDB_OK;
    const imdb_index *ix = o->q->ord_idx;
    for (uint8_t c = 0; c < ix->d.ncols; c++)
        if (t->s.cols[ix->d.cols[c]].type != IMDB_T_TEXT) o->vals[ix->d.cols[c]].i = (int64_t)(key[c] ^ (1ull << 63));
    if (preds_ok(o->q, o->vals)) sink_row(o->k, vid, o->vals);
    return o->k->err;
}

static int path_ordered(xctx *x, const qspec *q, sink *k, imdb_err *e)
{
    if (q->ord_pred < 0 || q->all_versions) return path_store(x, q, k, e); /* nothing it can serve */
    imdb_table *t = q->t;
    uint64_t lo[IMDB_MAX_INDEX_COLS], hi[IMDB_MAX_INDEX_COLS];
    ord_bounds(q, lo, hi);
    imdb_value vals[IMDB_MAX_COLS];
    octx o = {x, q, k, vals, e};
    for (uint8_t c = 0; q->ord_only && c < q->ord_idx->d.ncols; c++) { /* the columns the predicates and items read */
        const imdb_column *cd = &t->s.cols[q->ord_idx->d.cols[c]];
        memset(&vals[q->ord_idx->d.cols[c]], 0, sizeof vals[0]);
        vals[q->ord_idx->d.cols[c]].type = cd->type;
        vals[q->ord_idx->d.cols[c]].scale = cd->scale;
    }
    int rc = imdb_oidx_range(q->ord_idx->ox, lo, hi, q->ord_only ? ord_only_visit : ord_visit, &o);
    /* the reader's own pending versions are not in the structure yet (db.h idx_upto) */
    for (uint64_t vid = t->idx_upto; vid < t->nver && !rc; vid++) rc = ord_fetch(&o, vid);
    return rc ? rc : k->err;
}

static void mask_tail(uint64_t *bits, uint32_t n)
{
    if (n & 63) bits[n >> 6] &= (1ull << (n & 63)) - 1;
}

static bool s_is_f64(const imdb_table *t, int col) { return t->s.cols[col].type == IMDB_T_FLOAT64; }

static bool fast_aggregate(const sink *k)
{
    if (k->mode != SINK_AGG || k->nresid || k->trees) return false;
    for (uint16_t i = 0; i < k->st->nitems; i++) {
        uint8_t a = k->st->items[i].agg;
        if (a == AGG_SUM || a == AGG_COUNT || a == AGG_COUNT_STAR) continue;
        return false;
    }
    return true;
}

/* column col is one of the index's and not TEXT: its value is in the key (a TEXT word is an
 * 8-byte prefix, not the value). A nullable column after the first is not: its NULL is the word
 * 0, which is also the type's lowest value (db.c imdb_index_version_key). */
static bool in_key(const imdb_table *t, const imdb_index *ix, int col)
{
    for (uint8_t c = 0; c < ix->d.ncols; c++)
        if (ix->d.cols[c] == col)
            return t->s.cols[col].type != IMDB_T_TEXT && (c == 0 || !(t->s.cols[col].flags & IMDB_COL_NULLABLE));
    return false;
}

/* The ordered index alone answers when every predicate and every item reads a column whose value
 * its key holds (or is COUNT(*)): plain aggregates, or GROUP BY such a column. Not with IS NULL
 * (NULLs are not indexed). No row is read: visibility comes from the version array, the values
 * from the key. */
static bool ordered_only(const qspec *q, const sink *k)
{
    if (q->ord_pred < 0 || q->all_versions || k->nresid || k->trees) return false; /* a tree reads the row */
    const imdb_table *t = q->t;
    const imdb_index *ix = q->ord_idx;
    if (k->mode != SINK_AGG && !(k->mode == SINK_GROUP && in_key(t, ix, k->gcol))) return false;
    for (uint16_t i = 0; i < q->np; i++)
        if (!in_key(t, ix, q->p[i].col) || q->p[i].op == CMP_ISNULL) return false;
    for (uint16_t i = 0; i < k->st->nitems; i++)
        if (k->item_col[i] >= 0 && !in_key(t, ix, k->item_col[i])) return false;
    return true;
}

/* the zone maps prove no row of g can match (the scan skips it, and the planner counts it out) */
static bool seg_skipped(const qspec *q, const imdb_segment *g)
{
    bool skip = false;
    for (uint16_t i = 0; i < q->np && !skip; i++) {
        const bpred *b = &q->p[i];
        const imdb_segzone *zc = &g->zone[b->col]; /* the descriptor's: no image */
        if (b->op == CMP_ISNULL) skip = !zc->has_null;
        else if (b->type == IMDB_T_TEXT) continue; /* TEXT has no min/max */
        else if (b->op == CMP_NOTNULL || b->neg) skip = !zc->has;
        else skip = !zc->has || b->hi < zc->min || b->lo > zc->max;
    }
    return skip;
}

/* Vectorised: SIMD range filters over whole columns produce selection
 * bitmaps; visibility is itself two range filters over begin/end. */
static int path_scan(xctx *x, const qspec *q, sink *k, imdb_err *e)
{
    imdb_table *t = q->t;
    const imdb_kernels *K = imdb_kern();
    imdb_value vals[IMDB_MAX_COLS];
    uint64_t *bits = NULL, *tmp = NULL;
    size_t capw = 0;
    bool fast = fast_aggregate(k);
    int rc = IMDB_OK;
    for (uint32_t s = 0; s < t->nseg && !rc && !k->err; s++) {
        imdb_segment *g = t->seg[s];
        uint32_t n = g->nrows;
        if (!n) continue;
        if (!q->all_versions && seg_skipped(q, g)) continue;
        if (ktick(k, n)) break; /* the kernels filter the whole segment */
        const imdb_segimg *gi = imdb_seg_pin(t, g, e); /* only a segment the zone maps did not skip */
        if (!gi) {
            rc = e->code;
            break;
        }
        size_t words = (n + 63) / 64;
        if (words > capw) {
            imdb_free(bits);
            imdb_free(tmp);
            bits = imdb_alloc_array(words, sizeof *bits, e);
            tmp = imdb_alloc_array(words, sizeof *tmp, e);
            if (!bits || !tmp) {
                rc = e->code;
                break;
            }
            capw = words;
        }
        if (q->all_versions) {
            for (size_t w = 0; w < words; w++) bits[w] = ~0ull;
            mask_tail(bits, n);
        } else {
            K->filter_range_i64((const int64_t *)gi->begin, n, 1, (int64_t)q->snap, bits);
            K->filter_range_i64((const int64_t *)gi->end, n, (int64_t)q->snap + 1, INT64_MAX, tmp);
            for (size_t w = 0; w < words; w++) bits[w] &= tmp[w];
            if (q->pend) { /* rows the reader itself has ended (segments hold no pending inserts) */
                K->filter_range_i64((const int64_t *)gi->end, n, (int64_t)q->pend, (int64_t)q->pend, tmp);
                for (size_t w = 0; w < words; w++) bits[w] &= ~tmp[w];
            }
        }
        for (size_t w = 0; w < words; w++) bits[w] &= ~gi->stubmask[w];
        for (uint16_t i = 0; i < q->np; i++) {
            const bpred *b = &q->p[i];
            const imdb_segcol *c = &gi->col[b->col];
            /* VALID is whole 64-bit words: the section is 8-byte aligned and its padding is zero */
            const uint64_t *vw = (const uint64_t *)(const void *)c->valid;
            if (b->op == CMP_ISNULL || b->op == CMP_NOTNULL) {
                for (size_t w = 0; w < words; w++) bits[w] &= b->op == CMP_NOTNULL ? vw[w] : ~vw[w];
            } else if (c->i64) {
                K->filter_range_i64(c->i64, n, b->lo, b->hi, tmp);
                if (b->neg) {
                    for (size_t w = 0; w < words; w++) tmp[w] = ~tmp[w];
                    mask_tail(tmp, n);
                }
                for (size_t w = 0; w < words; w++) bits[w] &= vw ? tmp[w] & vw[w] : tmp[w]; /* stored zeros never match */
            } else {
                for (size_t w = 0; w < words; w++) {
                    uint64_t m = bits[w];
                    while (m) {
                        uint32_t r = (uint32_t)(w * 64 + (uint64_t)__builtin_ctzll(m));
                        m &= m - 1;
                        imdb_value v;
                        imdb_seg_get(&t->s, gi, r, b->col, &v);
                        if (!pred_ok(b, &v)) bits[w] &= ~(1ull << (r & 63));
                    }
                }
            }
        }
        if (fast) {
            uint64_t matched = 0; /* what the sink would have been given: the rows past visibility and the predicates */
            for (size_t w = 0; w < words; w++) matched += (uint64_t)__builtin_popcountll(bits[w]);
            if ((rc = xtested(x, matched, e))) break;
            for (uint16_t i = 0; i < k->st->nitems && !rc; i++) {
                agg_acc *a = &k->acc[i];
                uint8_t ag = k->st->items[i].agg;
                const imdb_segcol *sc = ag == AGG_COUNT_STAR ? NULL : &gi->col[k->item_col[i]];
                const uint64_t *m = bits, *vw = sc ? (const uint64_t *)(const void *)sc->valid : NULL;
                if (vw) { /* NULLs are neither counted nor summed */
                    for (size_t w = 0; w < words; w++) tmp[w] = bits[w] & vw[w];
                    m = tmp;
                }
                uint64_t cnt = 0;
                for (size_t w = 0; w < words; w++) cnt += (uint64_t)__builtin_popcountll(m[w]);
                a->count += cnt;
                if (cnt) a->has = true;
                if (ag == AGG_SUM && sc->i64 && s_is_f64(t, k->item_col[i])) {
                    for (size_t w = 0; w < words && !rc; w++)
                        for (uint64_t mw = m[w]; mw && !rc; mw &= mw - 1)
                            rc = imdb_fsum_add(&a->fsum, sc->i64[w * 64 + (uint64_t)__builtin_ctzll(mw)], e);
                } else if (ag == AGG_SUM) {
                    int64_t r2[2];
                    K->sum_masked_i64(sc->i64, m, n, r2);
                    a->sum += (__int128)(((unsigned __int128)(uint64_t)r2[1] << 64) | (uint64_t)r2[0]);
                }
            }
            continue;
        }
        for (size_t w = 0; w < words && !k->err; w++) {
            uint64_t m = bits[w];
            while (m) {
                if (ktick(k, 1)) break;
                uint32_t r = (uint32_t)(w * 64 + (uint64_t)__builtin_ctzll(m));
                m &= m - 1;
                uint64_t vid = gi->vid[r];
                for (uint32_t c = 0; c < t->s.ncols; c++) imdb_seg_get(&t->s, gi, r, c, &vals[c]); /* the row itself */
                sink_row(k, vid, vals);
            }
        }
    }
    imdb_free(bits);
    imdb_free(tmp);
    if (rc || k->err) return rc ? rc : k->err;
    /* memtable rows (not yet in a segment) */
    for (uint64_t vid = t->mem_first; vid < t->nver && !k->err; vid++) {
        if (ktick(k, 1)) break;
        const imdb_version *v = imdb_vh(t, vid); /* held: the walk has its entry */
        if (!visible_q(q, v)) continue;
        if (imdb_version_values_v(t, v, vals, e)) return e->code;
        if (preds_ok(q, vals)) sink_row(k, vid, vals);
    }
    return k->err;
}

/* The lake read row by row (stage 3b): each segment's rows decoded and checked like any row, then the memtable.
 * Below the memory floor it is the scan's cross-check: the scan reads the same rows through range filters over
 * whole columns and zone maps, this one value by value. */
static int path_rows(xctx *x, const qspec *q, sink *k, imdb_err *e)
{
    imdb_table *t = q->t;
    imdb_value vals[IMDB_MAX_COLS];
    for (uint32_t s = 0; s < t->nseg && !k->err; s++) {
        imdb_segment *g = t->seg[s];
        const imdb_segimg *gi = imdb_seg_pin(t, g, e);
        if (!gi) return e->code;
        for (uint32_t r = 0; r < g->nrows && !k->err; r++) {
            if (ktick(k, 1)) break;
            if (gi->flags[r]) continue; /* a stub or a tombstone: no values (visible_q's rule) */
            if (!q->all_versions && (gi->begin[r] > q->snap || gi->end[r] <= q->snap || (q->pend && gi->end[r] == q->pend)))
                continue;
            for (uint32_t c = 0; c < t->s.ncols; c++) imdb_seg_get(&t->s, gi, r, c, &vals[c]);
            if (preds_ok(q, vals)) sink_row(k, gi->vid[r], vals);
        }
    }
    for (uint64_t vid = t->mem_first; vid < t->nver && !k->err; vid++) { /* the memtable: always held */
        if (ktick(k, 1)) break;
        const imdb_version *v = imdb_vh(t, vid); /* held: the walk has its entry */
        if (!visible_q(q, v)) continue;
        if (imdb_version_values_v(t, v, vals, e)) return e->code;
        if (preds_ok(q, vals)) sink_row(k, vid, vals);
    }
    return k->err;
}

/* A read the memory window does not answer (stage 3b): a snapshot below the floor, where versions ended before it may
 * be the lake's alone, or every version there is (ERASE's selection). Only the lake's paths serve it. */
static bool below_floor(const imdb_db *db, const qspec *q)
{
    return q->all_versions || q->snap < db->mem_floor;
}

static int run_path(xctx *x, int path, const qspec *q, sink *k, imdb_err *e)
{
    if (q->never) return IMDB_OK;
    if (below_floor(x->db, q) && path != IMDB_PATH_SCAN && path != IMDB_PATH_ROWS) {
#ifdef IMDB_STORE_CHECKS /* the one choke point: every planner chose the lake for it, so a miss is a bug */
        imdb_v_misuse(q->t, q->snap, "a read below the memory floor was planned through memory");
#endif
        path = IMDB_PATH_SCAN; /* never a wrong answer for a missed plan */
    }
    switch (path) {
    case IMDB_PATH_INDEX: return path_index(x, q, k, e);
    case IMDB_PATH_SCAN: return path_scan(x, q, k, e);
    case IMDB_PATH_ORDERED: return path_ordered(x, q, k, e);
    case IMDB_PATH_ROWS: return path_rows(x, q, k, e);
    default: return path_store(x, q, k, e);
    }
}

static const char *path_name(int p, const qspec *q)
{
    if (p == IMDB_PATH_INDEX) return q->pk_pred >= 0 ? "index(primary key)" : q->subj_pred >= 0 ? "index(subject)" : "store";
    if (p == IMDB_PATH_SCAN) return "scan";
    if (p == IMDB_PATH_ROWS) return "rows";
    if (p == IMDB_PATH_ORDERED && q->ord_pred >= 0 && !q->all_versions)
        return q->ord_only ? "index(ordered, only)" : "index(ordered)";
    return "store";
}

/* ---- EXPLAIN (P1 Q1) ----------------------------------------------------------------------------------------------
 * The plan of a SELECT, UPDATE or DELETE as the planner makes it, stopped before any path runs: the same steps (the
 * table, the snapshot, the predicates bound, the sink planned, the path or the join's plan chosen), then rows of
 * (item, detail). Nothing is read but what the planner reads (index range counts, zone maps, the store's counts): no
 * row is tested. The plan is this copy's: its memory floor and store are its own, never logged, so two copies may
 * explain one statement differently and answer it identically (a result's path may differ the same way). */
enum { XP_ROWS = 20, XP_ITEM = 16, XP_DETAIL = 768 };
typedef struct xplain {
    uint16_t n;
    char item[XP_ROWS][XP_ITEM];
    char detail[XP_ROWS][XP_DETAIL];
} xplain;

static void xp_add(xplain *xp, const char *item, const char *fmt, ...) __attribute__((format(printf, 3, 4)));
static void xp_add(xplain *xp, const char *item, const char *fmt, ...)
{
    if (xp->n >= XP_ROWS) return;
    snprintf(xp->item[xp->n], XP_ITEM, "%s", item);
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(xp->detail[xp->n], XP_DETAIL, fmt, ap);
    va_end(ap);
    xp->n++;
}

/* appends to a detail being built (cut at its end) */
static void xcat(char *o, size_t cap, size_t *n, const char *fmt, ...) __attribute__((format(printf, 4, 5)));
static void xcat(char *o, size_t cap, size_t *n, const char *fmt, ...)
{
    if (*n + 1 >= cap) return;
    va_list ap;
    va_start(ap, fmt);
    int k = vsnprintf(o + *n, cap - *n, fmt, ap);
    va_end(ap);
    if (k > 0) *n = *n + (size_t)k < cap ? *n + (size_t)k : cap - 1;
}

static unsigned long long price_u64(unsigned __int128 v) /* a price as printed (the planner's fit 64 bits) */
{
    return v > UINT64_MAX ? (unsigned long long)UINT64_MAX : (unsigned long long)v;
}

static const char *access_word(int p) /* SET access_path's value */
{
    return p == IMDB_PATH_INDEX ? "index" : p == IMDB_PATH_SCAN ? "scan" : p == IMDB_PATH_STORE ? "store"
         : p == IMDB_PATH_ORDERED ? "ordered" : "auto";
}

/* Relative costs per row, from bench/index_sum.c (2026-10-24, i7-8550U; only the ratios are
 * used): the vectorised scan filters and sums a segment row in about 2 ns, the ordered path
 * reads a candidate from its segment in about 33 ns (imdb_seg_values), and either path decodes a
 * memtable row in about 110 ns (imdb_row_decode). An index-only candidate costs 16-20 ns (the
 * version's visibility and the aggregate, through the range callback; 42 ns for a SUM over
 * versions spread across the version array): ten scanned rows. Below COST_FLOOR, a few
 * microseconds, either path is fast and the index is kept, so the plans of small tables do not
 * flip. */
enum { COST_VEC = 1, COST_ONLY = 10, COST_SEG_FETCH = 16, COST_MEM_ROW = 55, COST_FLOOR = 4096 };

/* A plain SUM or COUNT (fast_aggregate) is the one case where the scan can beat a matching
 * index: it sums segment rows without reading them one by one, while the index reads every
 * candidate. Every other sink reads each match on the scan path too, so the index is kept there.
 * The candidates are every indexed version in the key range, dead ones too: under churn without
 * purges the estimate overstates the index and leaves it early, for a scan whose cost is the
 * table's size. */
/* the two prices scan_cheaper compares (EXPLAIN prints them); false where none applies (not a plain aggregate) */
static bool scan_price(const qspec *q, const sink *k, unsigned __int128 *ordp, unsigned __int128 *scanp)
{
    if (!fast_aggregate(k)) return false;
    const imdb_table *t = q->t;
    uint64_t lo[IMDB_MAX_INDEX_COLS], hi[IMDB_MAX_INDEX_COLS];
    ord_bounds(q, lo, hi);
    uint64_t c = imdb_oidx_count(q->ord_idx->ox, lo, hi), mem = t->nver - t->mem_first, segrows = 0;
    for (uint32_t s = 0; s < t->nseg; s++)
        if (!seg_skipped(q, t->seg[s])) segrows += t->seg[s]->nrows;
    /* the candidates split like the versions: those below mem_first are read from segments (an
     * index-only candidate is not read at all); the reader's own pending versions (past idx_upto)
     * are visited one by one */
    unsigned __int128 cmem = t->nver ? (unsigned __int128)c * mem / t->nver : 0;
    unsigned __int128 ord = q->ord_only ? (unsigned __int128)c * COST_ONLY
                                        : (c - cmem) * COST_SEG_FETCH + cmem * COST_MEM_ROW;
    ord += (unsigned __int128)(t->nver - t->idx_upto) * COST_MEM_ROW;
    unsigned __int128 scan = (unsigned __int128)segrows * COST_VEC + (unsigned __int128)mem * COST_MEM_ROW;
    *ordp = ord;
    *scanp = scan;
    return true;
}

static bool scan_cheaper(const qspec *q, const sink *k)
{
    unsigned __int128 ord, scan;
    return scan_price(q, k, &ord, &scan) && ord >= COST_FLOOR && scan < ord;
}

static int choose_path(const imdb_session *ss, const qspec *q, const sink *k)
{
    if (below_floor(ss->db, q)) return IMDB_PATH_SCAN; /* before SET access_path: memory cannot answer it */
    if (ss->access_path != IMDB_PATH_AUTO) return ss->access_path;
    if (q->pk_pred >= 0 || q->subj_pred >= 0) return IMDB_PATH_INDEX;
    if (q->ord_pred >= 0 && !q->all_versions) return scan_cheaper(q, k) ? IMDB_PATH_SCAN : IMDB_PATH_ORDERED;
    return IMDB_PATH_SCAN;
}

/* ---- SELECT ----------------------------------------------------------------------- */

typedef struct keyed {
    imdb_value key;
    uint64_t vid;
} keyed;

static int cmp_keyed(const void *a, const void *b)
{
    const keyed *x = a, *y = b;
    int c = imdb_value_cmp(&x->key, &y->key);
    if (c) return c;
    return x->vid < y->vid ? -1 : x->vid > y->vid;
}

static int cmp_group_idx(const void *a, const void *b, void *arg)
{
    const group *g = arg;
    return imdb_value_cmp(&g[*(const uint64_t *)a].key, &g[*(const uint64_t *)b].key);
}

static int cmp_u64(const void *a, const void *b)
{
    uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;
    return x < y ? -1 : x > y;
}

/* ---- ORDER BY, OFFSET, DISTINCT (P0 1d) --------------------------------------------------------------------------
 * Rows are first in the default order (the primary key's; groups by their key; a join's pairs by both keys), then
 * sorted by ORDER BY's keys, the default order breaking every tie, so any order is total and no plan changes it. */

typedef struct ordctx {
    const sql_stmt *st;
    const imdb_xval *keys;   /* rows x st->norder, row i's in the default order's place i */
} ordctx;

static int cmp_order(const void *pa, const void *pb, void *arg)
{
    const ordctx *c = arg;
    uint64_t a = *(const uint64_t *)pa, b = *(const uint64_t *)pb, nk = c->st->norder;
    for (uint8_t o = 0; o < nk; o++) {
        const imdb_xval *x = &c->keys[a * nk + o], *y = &c->keys[b * nk + o];
        if (x->null || y->null) {
            if (x->null == y->null) continue;
            int r = x->null ? 1 : -1; /* NULLs last, or first: whatever the direction */
            return c->st->ord_nulls_first[o] ? -r : r;
        }
        int r = imdb_x_cmp(x, y); /* one type per key (bound), or two numbers */
        if (r) return c->st->ord_desc[o] ? -r : r;
    }
    return a < b ? -1 : a > b;
}

/* a built cell as a value (TEXT points into r's text: read only once every row is built) */
static void cell_x(const imdb_result *r, const imdb_cell *c, imdb_xval *v)
{
    memset(v, 0, sizeof *v);
    v->type = c->v.type;
    v->scale = c->v.scale;
    v->null = c->null;
    if (c->null) return;
    if (c->wide) v->i = c->i128;
    else if (c->v.type == IMDB_T_FLOAT64) v->f = imdb_f64_value(c->v.i);
    else if (c->v.type == IMDB_T_TEXT) v->s = r->text.p + c->v.i, v->len = c->v.len;
    else v->i = c->v.i;
}

/* a built row's identity for DISTINCT: SHA-256 of its cells (NULL, type, scale, the value as __int128 or its bytes) */
static void row_digest(const imdb_result *r, const imdb_cell *row, uint8_t out[IMDB_HASH_LEN])
{
    imdb_sha256_ctx h;
    imdb_sha256_init(&h);
    for (uint16_t i = 0; i < r->ncols; i++) {
        const imdb_cell *c = &row[i];
        uint8_t tag[3] = {c->null, c->v.type, c->v.scale};
        imdb_sha256_update(&h, tag, sizeof tag);
        if (c->null) continue;
        if (c->v.type == IMDB_T_TEXT) {
            uint32_t n = c->v.len;
            imdb_sha256_update(&h, &n, sizeof n);
            imdb_sha256_update(&h, r->text.p + c->v.i, n);
        } else {
            __int128 v = c->wide ? c->i128 : (__int128)c->v.i; /* a FLOAT64's key: one per value (-0.0 is 0.0) */
            imdb_sha256_update(&h, &v, sizeof v);
        }
    }
    imdb_sha256_final(&h, out);
}

/* the rows a result keeps once ordered: OFFSET's skipped, DISTINCT's repeats taken back, LIMIT's end */
typedef struct window {
    uint64_t skip, left;     /* OFFSET still to skip; LIMIT still to keep (UINT64_MAX: none) */
    bool distinct;
    imdb_hmap seen;          /* DISTINCT: the kept rows' digests */
} window;

static int window_init(window *w, const sql_stmt *st, imdb_err *e)
{
    memset(w, 0, sizeof *w);
    w->skip = st->has_offset ? st->offset : 0;
    w->left = st->has_limit ? st->limit : UINT64_MAX;
    w->distinct = st->distinct;
    return w->distinct ? imdb_hmap_init(&w->seen, IMDB_T_TEXT, e) : IMDB_OK;
}

static void window_free(window *w)
{
    if (w->seen.slots) imdb_hmap_free(&w->seen);
}

/* the row just put at r's end, whose text began at tl: kept, or taken back with its text */
static int window_take(window *w, imdb_result *r, size_t tl, imdb_err *e)
{
    if (w->distinct) {
        uint8_t d[IMDB_HASH_LEN];
        row_digest(r, &r->cells[(r->nrows - 1) * r->ncols], d);
        imdb_value key = {.type = IMDB_T_TEXT, .s = d, .len = sizeof d};
        if (imdb_hmap_get(&w->seen, &key)) goto back;
        if (imdb_hmap_put(&w->seen, &key, 0, e)) return e->code;
    }
    if (w->skip) {
        w->skip--;
        goto back;
    }
    w->left--;
    return IMDB_OK;
back:
    r->nrows--;
    r->text.len = tl;
    return IMDB_OK;
}

/* a row statement's ORDER BY key o on a row (a table's, or a join's combined): its tree, or the item at its position */
static int order_key(xctx *x, const sql_stmt *st, const sink *k, uint8_t o, const imdb_value *vals, imdb_xval *out,
                     imdb_err *e)
{
    if (!st->ord_pos[o]) return imdb_x_eval(st, x->xn, st->ord_ex[o], vals, NULL, out, e);
    uint16_t p = (uint16_t)(st->ord_pos[o] - 1);
    if (st->star) imdb_x_from_value(&vals[p], out);
    else if (st->items[p].expr) return imdb_x_eval(st, x->xn, st->items[p].expr, vals, NULL, out, e);
    else imdb_x_from_value(&vals[k->item_col[p]], out);
    return IMDB_OK;
}

/* the sort's keys, n rows x nk keys, under the result's cap as a join's working set is (join_charge) */
static imdb_xval *order_keys_alloc(const imdb_result *r, const sql_stmt *st, uint64_t n, imdb_err *e)
{
    uint64_t cap = r->byte_cap ? r->byte_cap : IMDB_MAX_RESULT_BYTES;
    if (n && (uint64_t)st->norder * sizeof(imdb_xval) > cap / n) {
        imdb_fail(e, IMDB_ERR_LIMIT, "ORDER BY over %llu rows: the sort's keys pass the result's cap of %llu bytes; narrow it",
                  (unsigned long long)n, (unsigned long long)cap);
        return NULL;
    }
    return imdb_alloc_array(n ? n * st->norder : 1, sizeof(imdb_xval), e);
}

static int put_agg(imdb_result *r, imdb_cell *c, agg_acc *a, uint8_t agg, const imdb_column *col, imdb_err *e)
{
    switch (agg) {
    case AGG_COUNT_STAR:
    case AGG_COUNT: res_put_int(r, c, (int64_t)a->count); break;
    case AGG_SUM:
        if (!a->has) {
            c->null = true;
            c->v.type = col->type;
            break;
        }
        if (col->type == IMDB_T_FLOAT64) {
            c->v.type = IMDB_T_FLOAT64;
            if (imdb_fsum_result(&a->fsum, &c->v.i, e)) return e->code;
            break;
        }
        c->wide = true;
        c->i128 = a->sum;
        c->v.type = col->type;
        c->v.scale = col->scale;
        break;
    case AGG_MIN:
    case AGG_MAX:
        if (!a->has) {
            c->null = true;
            c->v.type = col->type;
            break;
        }
        res_put(r, c, agg == AGG_MIN ? &a->mn : &a->mx);
        break;
    }
    return IMDB_OK;
}

/* the tree reads a column outside any aggregate */
static bool ex_reads(const sql_stmt *st, uint16_t k)
{
    if (!k) return false;
    const sql_expr *x = &st->ex[k];
    if (x->op == EX_COL) return true;
    if (x->op == EX_AGG) return false;
    return ex_reads(st, x->l) || ex_reads(st, x->r) || ex_reads(st, x->x3); /* height-bounded */
}

/* a tree item bound into the statement's sink: its aggregates become slots (xa_row); an aggregate item when it
 * holds one, a plain one when it reads a column outside one (grouped: the GROUP BY column alone, xbind's rule); a
 * tree of constants is neither and stands beside either */
static int bind_item(xctx *x, sink *k, xscope *si, uint16_t root, bool *any_agg, bool *any_plain, imdb_err *e)
{
    k->trees = true;
    if (xnodes(x, si->st, e) || xbind(x, si, root, e)) return e->code;
    if (imdb_sql_has_agg(si->st, root)) *any_agg = true;
    else if (ex_reads(si->st, root)) *any_plain = true;
    return IMDB_OK;
}

/* under DISTINCT, an ORDER BY tree must be a select item: a bare column the list names (or any, under SELECT *) */
static bool distinct_key(const sql_stmt *st, uint16_t k)
{
    const sql_expr *n = &st->ex[k];
    if (n->op != EX_COL) return false;
    if (st->star) return true;
    for (uint16_t i = 0; i < st->nitems; i++) {
        const sql_item *it = &st->items[i];
        if (!it->expr && it->agg == AGG_NONE && !strcmp(it->col, n->col) &&
            (!it->qual[0] || !n->qual[0] || !strcmp(it->qual, n->qual)))
            return true;
    }
    return false;
}

/* ORDER BY's keys bound with the SELECT list's scope (a key may hold aggregates where an item may, and its columns
 * count as an item's do); a position within the list (nout items, or the columns under SELECT *) */
static int bind_order(xctx *x, const sql_stmt *st, sink *k, xscope *si, uint16_t nout, bool *any_agg, bool *any_plain,
                      imdb_err *e);

static int alloc_xa(xctx *x, sink *k, const xscope *si, imdb_err *e)
{
    k->nxa = si->nslot;
    if (k->nxa && !(k->xa = xalloc(x, k->nxa * sizeof *k->xa, e))) return e->code;
    return IMDB_OK;
}

static int bind_order(xctx *x, const sql_stmt *st, sink *k, xscope *si, uint16_t nout, bool *any_agg, bool *any_plain,
                      imdb_err *e)
{
    for (uint8_t o = 0; o < st->norder; o++) {
        if (st->ord_pos[o]) {
            if (st->ord_pos[o] > nout)
                return imdb_fail(e, IMDB_ERR_INVALID, "ORDER BY %u: the SELECT list has %u items", (unsigned)st->ord_pos[o],
                                 (unsigned)nout);
            continue;
        }
        if (st->distinct && !distinct_key(st, st->ord_ex[o]))
            return imdb_fail(e, IMDB_ERR_INVALID, "with DISTINCT, ORDER BY names select items: a position, or a column the list names");
        if (bind_item(x, k, si, st->ord_ex[o], any_agg, any_plain, e)) return e->code;
    }
    return IMDB_OK;
}

/* HAVING (1e): a condition with the SELECT list's scope (aggregates, and the GROUP BY column outside them), applied to
 * each group, or to the one aggregate row, before DISTINCT, ORDER BY and the window (materialize) */
static int bind_having(xctx *x, const sql_stmt *st, sink *k, xscope *si, bool *any_agg, bool *any_plain, imdb_err *e)
{
    if (!st->having) return IMDB_OK;
    if (bind_item(x, k, si, st->having, any_agg, any_plain, e)) return e->code;
    if (x->xn[st->having].type != IMDB_T_BOOL)
        return imdb_fail(e, IMDB_ERR_INVALID, "HAVING takes a condition: a comparison, IS NULL, AND, OR, NOT or a BOOL");
    return IMDB_OK;
}

static int plan_select(xctx *x, const sql_stmt *st, imdb_table *t, sink *k, imdb_err *e)
{
    memset(k, 0, sizeof *k);
    k->x = x;
    k->st = st;
    k->t = t;
    k->e = e;
    if (st->has_group) {
        k->gcol = one_col(st, t, st->group_qual, st->group_col, e);
        if (k->gcol < 0) return k->gcol;
        if (st->star) return imdb_fail(e, IMDB_ERR_INVALID, "SELECT * cannot be grouped");
    }
    xscope sc = {.st = st, .s = &t->s, .t = t, .cols = true, .group_col = -1};
    if (bind_resid(x, &sc, k->resid, &k->nresid, e)) return e->code;
    xscope si = {.st = st, .s = &t->s, .t = t, .cols = true, .aggs = true, .group_col = st->has_group ? k->gcol : -1,
                 .agg_nodes = k->xa_node};
    bool any_agg = false, any_plain = st->star; /* every column of *, plain: an aggregate in HAVING or ORDER BY is mixing */
    for (uint16_t i = 0; i < st->nitems; i++) {
        const sql_item *it = &st->items[i];
        k->item_col[i] = -1;
        if (it->expr) { /* a tree: per row (materialize), or over its aggregates' slots */
            if (bind_item(x, k, &si, it->expr, &any_agg, &any_plain, e)) return e->code;
            continue;
        }
        if (it->agg == AGG_COUNT_STAR) {
            any_agg = true;
            continue;
        }
        int c = one_col(st, t, it->qual, it->col, e);
        if (c < 0) return c;
        k->item_col[i] = c;
        if (it->agg == AGG_NONE) {
            any_plain = true;
            if (st->has_group && strcmp(it->col, st->group_col) != 0)
                return imdb_fail(e, IMDB_ERR_INVALID, "column %s must be the GROUP BY column or inside an aggregate", it->col);
        } else {
            any_agg = true;
            uint8_t ct = t->s.cols[c].type;
            if (it->agg == AGG_SUM && ct != IMDB_T_INT64 && ct != IMDB_T_DECIMAL && ct != IMDB_T_FLOAT64)
                return imdb_fail(e, IMDB_ERR_INVALID, "SUM needs an INT64, DECIMAL or FLOAT64 column");
        }
    }
    if (bind_having(x, st, k, &si, &any_agg, &any_plain, e) ||
        bind_order(x, st, k, &si, st->star ? t->s.ncols : st->nitems, &any_agg, &any_plain, e))
        return e->code;
    if (alloc_xa(x, k, &si, e)) return e->code;
    if (st->has_group) {
        k->mode = SINK_GROUP;
        uint8_t kt = t->s.cols[k->gcol].type == IMDB_T_TEXT ? IMDB_T_TEXT : IMDB_T_INT64;
        if (imdb_hmap_init(&k->gmap, kt, e)) return e->code;
    } else if (any_agg) {
        if (any_plain) return imdb_fail(e, IMDB_ERR_INVALID, "mixing aggregates and columns needs GROUP BY");
        k->mode = SINK_AGG;
    } else {
        k->mode = SINK_VIDS;
        if (st->having) return imdb_fail(e, IMDB_ERR_INVALID, "HAVING needs GROUP BY or an aggregate");
    }
    return IMDB_OK;
}

/* Turns a sink into a result set (sorted, deterministic). */
/* a computed value into a cell: a DECIMAL always wide (its scale may pass 18), FLOAT64 as its key */
static void res_put_x(imdb_result *r, imdb_cell *c, const imdb_xval *v)
{
    imdb_value iv = {.type = v->type, .scale = v->scale, .null = v->null};
    if (!v->null && (v->type == IMDB_T_DECIMAL || (v->type == IMDB_T_INT64 && (v->i < INT64_MIN || v->i > INT64_MAX)))) {
        c->wide = true;
        c->i128 = v->i;
        c->v.type = v->type;
        c->v.scale = v->scale;
        return;
    }
    if (v->type == IMDB_T_FLOAT64) iv.i = imdb_f64_key(v->f);
    else if (v->type == IMDB_T_TEXT) iv.s = v->s, iv.len = v->len;
    else iv.i = (int64_t)v->i;
    res_put(r, c, &iv);
}

/* a result column's name: a column's, or a tree item's text (whitespace folded, cut at a character's end) */
static void item_name(const xctx *x, const sql_item *it, char *out, size_t n)
{
    if (!it->expr) {
        snprintf(out, n, "%s", it->col);
        return;
    }
    size_t k = 0, bad;
    for (uint32_t i = 0; i < it->len && k + 1 < n; i++) {
        char c = x->sql[it->off + i];
        if ((unsigned char)c < 0x20) c = ' ';
        if (c != ' ' || (k && out[k - 1] != ' ')) out[k++] = c;
    }
    while (k && out[k - 1] == ' ') k--;
    while (k && !imdb_utf8_valid((const uint8_t *)out, k, &bad)) k--; /* a character the cut split */
    out[k] = 0;
}

/* the trees' aggregates' final values (acc: the statement's, or one group's) */
static int xa_values(sink *k, xacc *acc, imdb_xval *sv, imdb_err *e)
{
    for (uint16_t s = 0; s < k->nxa; s++) {
        uint16_t node = k->xa_node[s];
        uint16_t l = k->st->ex[node].l; /* the argument (none for COUNT(*)) */
        uint8_t ta = l ? k->x->xn[l].type : 0, sa = l ? k->x->xn[l].scale : 0;
        if (xacc_value(&acc[s], k->st->ex[node].agg, &k->x->xn[node], ta, sa, &sv[s], e)) return e->code;
    }
    return IMDB_OK;
}

/* a row statement's output row from a row's values (a table's, or a join's combined): only the rows the result keeps
 * are computed, so past LIMIT no item fails */
static int put_row(xctx *x, const sql_stmt *st, const sink *k, const imdb_value *vals, uint16_t nc, imdb_result *r,
                   imdb_err *e)
{
    imdb_cell *row = res_row(r, e);
    if (!row) return e->code;
    for (uint16_t c = 0; c < nc; c++) {
        if (st->star || !st->items[c].expr) {
            res_put(r, &row[c], &vals[st->star ? c : k->item_col[c]]);
            continue;
        }
        imdb_xval v;
        if (imdb_x_eval(st, x->xn, st->items[c].expr, vals, NULL, &v, e)) return e->code;
        res_put_x(r, &row[c], &v);
    }
    return IMDB_OK;
}

static bool plain_order(const sql_stmt *st) { return !st->norder && !st->distinct && !st->has_offset && !st->having; }

/* rows built in the default order (rows[0..n)), now ordered, deduplicated and cut to OFFSET and LIMIT: the cells
 * rebuilt in that order (grouped statements, whose rows are few: IMDB_MAX_GROUPS) */
static int reorder_rows(const sql_stmt *st, imdb_xval *keys, imdb_result *r, imdb_err *e)
{
    uint64_t n = r->nrows, *ord = imdb_alloc_array(n ? n : 1, sizeof *ord, e), *keep = NULL;
    if (!ord) return e->code;
    for (uint64_t i = 0; i < n; i++) ord[i] = i;
    for (uint64_t i = 0; i < n && keys; i++) /* positional keys: the built cells, the text whole now */
        for (uint8_t o = 0; o < st->norder; o++)
            if (st->ord_pos[o]) cell_x(r, &r->cells[i * r->ncols + st->ord_pos[o] - 1], &keys[i * st->norder + o]);
    if (st->norder) {
        ordctx c = {st, keys};
        qsort_r(ord, n, sizeof *ord, cmp_order, &c);
    }
    window w;
    int rc = window_init(&w, st, e);
    imdb_cell *cells = NULL;
    uint64_t nk = 0;
    if (!rc && !(keep = imdb_alloc_array(n ? n : 1, sizeof *keep, e))) rc = e->code;
    for (uint64_t j = 0; !rc && j < n && w.left; j++) {
        if (w.distinct) {
            uint8_t d[IMDB_HASH_LEN];
            row_digest(r, &r->cells[ord[j] * r->ncols], d);
            imdb_value key = {.type = IMDB_T_TEXT, .s = d, .len = sizeof d};
            if (imdb_hmap_get(&w.seen, &key)) continue;
            if ((rc = imdb_hmap_put(&w.seen, &key, 0, e))) break;
        }
        if (w.skip) {
            w.skip--;
            continue;
        }
        keep[nk++] = ord[j];
        w.left--;
    }
    if (!rc && !(cells = imdb_alloc_array(nk ? nk * r->ncols : 1, sizeof *cells, e))) rc = e->code;
    for (uint64_t j = 0; !rc && j < nk; j++) memcpy(&cells[j * r->ncols], &r->cells[keep[j] * r->ncols], r->ncols * sizeof *cells);
    if (!rc) {
        imdb_free(r->cells);
        r->cells = cells;
        r->nrows = r->caprows = nk;
    }
    window_free(&w);
    imdb_free(keep);
    imdb_free(ord);
    return rc;
}

static int materialize(xctx *x, const sql_stmt *st, imdb_table *t, sink *k, imdb_result *r, imdb_err *e)
{
    if (k->mode == SINK_VIDS) {
        uint16_t nc = st->star ? t->s.ncols : st->nitems;
        res_cols(r, nc);
        for (uint16_t i = 0; i < nc; i++) {
            char nm[IMDB_MAX_IDENT + 8];
            if (st->star) snprintf(nm, sizeof nm, "%s", t->s.cols[i].name);
            else item_name(x, &st->items[i], nm, sizeof nm);
            res_name(r, i, nm);
        }
        keyed *kv = imdb_alloc_array(k->nvids ? k->nvids : 1, sizeof *kv, e);
        if (!kv) return e->code;
        for (uint64_t i = 0; i < k->nvids; i++) {
            imdb_version_key(t, k->vids[i], t->s.pk, &kv[i].key);
            kv[i].vid = k->vids[i];
        }
        qsort(kv, k->nvids, sizeof *kv, cmp_keyed);
        imdb_value vals[IMDB_MAX_COLS];
        int rc = IMDB_OK;
        if (plain_order(st)) { /* the primary key's order, the first LIMIT rows */
            uint64_t lim = st->has_limit && st->limit < k->nvids ? st->limit : k->nvids;
            for (uint64_t i = 0; i < lim && !rc; i++)
                if (!(rc = xtick(x, 1, e)) && !(rc = fetch_row(x, t, kv[i].vid, vals, e))) rc = put_row(x, st, k, vals, nc, r, e);
            imdb_free(kv);
            return rc ? rc : res_finish(r, e);
        }
        /* ORDER BY's keys for every matching row (a key that fails fails the statement: the matching set is every
         * plan's), sorted with the primary key's order breaking ties; then OFFSET, DISTINCT and LIMIT */
        uint64_t n = k->nvids, *ord = imdb_alloc_array(n ? n : 1, sizeof *ord, e);
        imdb_xval *keys = NULL;
        window w;
        memset(&w, 0, sizeof w);
        if (!ord) rc = e->code;
        for (uint64_t i = 0; !rc && i < n; i++) ord[i] = i;
        if (!rc && st->norder && !(keys = order_keys_alloc(r, st, n, e))) rc = e->code;
        for (uint64_t i = 0; !rc && keys && i < n; i++) {
            if ((rc = xtick(x, 1, e)) || (rc = fetch_row(x, t, kv[i].vid, vals, e))) break;
            for (uint8_t o = 0; !rc && o < st->norder; o++) rc = order_key(x, st, k, o, vals, &keys[i * st->norder + o], e);
        }
        if (!rc && keys) {
            ordctx c = {st, keys};
            qsort_r(ord, n, sizeof *ord, cmp_order, &c);
            rc = xcheck(x, e); /* a sort runs to its end (the result cap bounds it): the check after it */
        }
        if (!rc) rc = window_init(&w, st, e);
        for (uint64_t j = 0; !rc && j < n && w.left; j++) {
            if (!w.distinct && w.skip) { /* OFFSET without DISTINCT: skipped unread */
                w.skip--;
                continue;
            }
            size_t tl = r->text.len;
            if (!(rc = xtick(x, 1, e)) && !(rc = fetch_row(x, t, kv[ord[j]].vid, vals, e)) && !(rc = put_row(x, st, k, vals, nc, r, e)))
                rc = window_take(&w, r, tl, e);
        }
        window_free(&w);
        imdb_free(keys);
        imdb_free(ord);
        imdb_free(kv);
        return rc ? rc : res_finish(r, e);
    }
    res_cols(r, st->nitems);
    for (uint16_t i = 0; i < st->nitems; i++) {
        const sql_item *it = &st->items[i];
        static const char *const an[] = {"", "count", "count", "sum", "min", "max", "avg"};
        char nm[IMDB_MAX_IDENT + 8];
        const sql_expr *ax = it->expr ? &st->ex[it->expr] : NULL; /* AVG(a): avg_a, as SUM(a) is sum_a */
        if (ax && ax->op == EX_AGG && ax->agg == AGG_AVG && ax->l && st->ex[ax->l].op == EX_COL)
            snprintf(nm, sizeof nm, "avg_%s", st->ex[ax->l].col);
        else if (it->expr) item_name(x, it, nm, sizeof nm);
        else if (it->agg == AGG_NONE) snprintf(nm, sizeof nm, "%s", it->col);
        else if (it->agg == AGG_COUNT_STAR) snprintf(nm, sizeof nm, "count");
        else snprintf(nm, sizeof nm, "%s_%s", an[it->agg], it->col);
        res_name(r, i, nm);
    }
    imdb_xval sv[IMDB_MAX_COLS], v;
    if (k->mode == SINK_AGG) {
        if (xa_values(k, k->xa, sv, e)) return e->code;
        if (st->having) { /* 1e: the one row, kept when its condition is TRUE */
            if (imdb_x_eval(st, x->xn, st->having, NULL, sv, &v, e)) return e->code;
            if (!imdb_x_true(&v)) return res_finish(r, e);
        }
        imdb_cell *row = res_row(r, e);
        if (!row) return e->code;
        for (uint16_t i = 0; i < st->nitems; i++) {
            if (st->items[i].expr) { /* over the slots: no column outside an aggregate (plan_select) */
                if (imdb_x_eval(st, x->xn, st->items[i].expr, NULL, sv, &v, e)) return e->code;
                res_put_x(r, &row[i], &v);
                continue;
            }
            int c = k->item_col[i];
            if (put_agg(r, &row[i], &k->acc[i], st->items[i].agg, c >= 0 ? &t->s.cols[c] : &t->s.cols[0], e)) return e->code;
        }
        if ((st->has_limit && st->limit == 0) || (st->has_offset && st->offset > 0)) { /* the one row, cut (1d) */
            r->nrows = 0;
            r->text.len = 0;
        }
        return res_finish(r, e);
    }
    uint64_t *order = imdb_alloc_array(k->ngroups ? k->ngroups : 1, sizeof *order, e);
    if (!order) return e->code;
    for (uint64_t g = 0; g < k->ngroups; g++) order[g] = g;
    qsort_r(order, k->ngroups, sizeof *order, cmp_group_idx, k->groups);
    bool plain = plain_order(st); /* else every group's row is built, then ordered and cut (reorder_rows) */
    uint64_t lim = plain && st->has_limit && st->limit < k->ngroups ? st->limit : k->ngroups;
    imdb_xval *keys = NULL;
    if (st->norder && !(keys = order_keys_alloc(r, st, lim, e))) {
        imdb_free(order);
        return e->code;
    }
    imdb_value grow[IMDB_MAX_COLS]; /* a group's row: its key; a tree reads no other column outside an aggregate */
    memset(grow, 0, sizeof grow);
    int xrc = IMDB_OK;
    uint64_t nr = 0; /* the rows built: a group HAVING drops has none, so a key's index is its row's */
    for (uint64_t gi = 0; gi < lim && !xrc; gi++) {
        uint64_t g = order[gi];
        if ((xrc = xa_values(k, k->nxa ? &k->gxa[g * k->nxa] : NULL, sv, e))) break;
        grow[k->gcol] = k->groups[g].key;
        if (st->having) { /* 1e: before the row, so an item's error on a dropped group is never raised */
            if ((xrc = imdb_x_eval(st, x->xn, st->having, grow, sv, &v, e))) break;
            if (!imdb_x_true(&v)) continue;
        }
        imdb_cell *row = res_row(r, e);
        if (!row) {
            xrc = e->code;
            break;
        }
        uint64_t ri = nr++;
        for (uint16_t i = 0; i < st->nitems && !xrc; i++) {
            if (!st->items[i].expr) continue;
            if (!(xrc = imdb_x_eval(st, x->xn, st->items[i].expr, grow, sv, &v, e))) res_put_x(r, &row[i], &v);
        }
        for (uint8_t o = 0; o < st->norder && !xrc; o++) /* a key's tree over the group (positional keys: the cells) */
            if (!st->ord_pos[o]) xrc = imdb_x_eval(st, x->xn, st->ord_ex[o], grow, sv, &keys[ri * st->norder + o], e);
        for (uint16_t i = 0; i < st->nitems && !xrc; i++) {
            if (st->items[i].expr) continue;
            int c = k->item_col[i];
            if (st->items[i].agg == AGG_NONE) res_put(r, &row[i], &k->groups[g].key);
            else xrc = put_agg(r, &row[i], &k->gacc[g * st->nitems + i], st->items[i].agg, c >= 0 ? &t->s.cols[c] : &t->s.cols[0], e);
        }
    }
    if (!xrc && !plain) xrc = reorder_rows(st, keys, r, e);
    imdb_free(keys);
    imdb_free(order);
    return xrc ? xrc : res_finish(r, e);
}

static bool cells_equal(const imdb_cell *a, const imdb_cell *b)
{
    if (a->null != b->null || a->wide != b->wide) return false;
    if (a->null) return true;
    if (a->wide) return a->i128 == b->i128;
    if (a->v.type != b->v.type) return false;
    return imdb_value_cmp(&a->v, &b->v) == 0;
}

static bool results_equal(const imdb_result *a, const imdb_result *b)
{
    if (a->ncols != b->ncols || a->nrows != b->nrows) return false;
    for (uint64_t i = 0; i < a->nrows * a->ncols; i++)
        if (!cells_equal(&a->cells[i], &b->cells[i])) return false;
    return true;
}

/* The session's snapshot and its own pending versions (db.h, session
 * transactions); AS OF asks for a committed state, so it sees no pending ones. */
static void read_view(const xctx *x, uint64_t *snap, uint64_t *pend)
{
    imdb_txn_view(x->db, x->ss->txn.open ? &x->ss->txn : NULL, snap, pend);
}

/* imdb_check_history for a statement's view. A transaction's own snapshot below the table's horizon
 * means the transaction has outlived the history that table keeps (its retention: db.c's expiry):
 * the transaction is doomed, and a retry with a fresh snapshot succeeds. AS OF asks for that history
 * itself: HISTORY. */
static int check_view(xctx *x, const imdb_table *t, uint64_t snap, bool asof, imdb_err *e)
{
    int rc = imdb_check_history(x->db, t, snap, e);
    imdb_txn *tx = &x->ss->txn;
    if (rc != IMDB_ERR_HISTORY || asof || !tx->open) return rc;
    imdb_err_clear(e); /* the first error wins: this one replaces it */
    imdb_fail(e, IMDB_ERR_CONFLICT,
              "the history of %s that this transaction's snapshot (commit %llu) reads is no longer kept (expired by "
              "its retention, or purged); roll back and retry the transaction",
              t->s.name, (unsigned long long)snap);
    imdb_txn_doom(tx, e->msg);
    return IMDB_ERR_CONFLICT;
}

/* a statement's read point: the session's view, or AS OF's commit or time (no table checked yet) */
static int snapshot_of(xctx *x, const sql_stmt *st, uint64_t *snap, uint64_t *pend, imdb_err *e)
{
    imdb_db *db = x->db;
    read_view(x, snap, pend);
    if (st->has_asof) {
        *pend = 0;
        if (st->asof.kind == LIT_INT) {
            int64_t v;
            if (imdb_parse_int64(x->sql + st->asof.off, st->asof.len, &v, e)) return e->code;
            *snap = (uint64_t)v;
        } else {
            int64_t ts;
            if (imdb_parse_timestamp(x->sql + st->asof.off, st->asof.len, &ts, e)) return e->code;
            if (imdb_seq_at_time(db, (uint64_t)ts, snap, e)) return e->code;
        }
    }
    return IMDB_OK;
}

static int resolve_snapshot(xctx *x, const sql_stmt *st, imdb_table *t, uint64_t *snap, uint64_t *pend, imdb_err *e)
{
    if (snapshot_of(x, st, snap, pend, e)) return e->code;
    return check_view(x, t, *snap, st->has_asof, e);
}

/* The table a read names, at its read point (1f): the live one if it existed then; else the one dropped since that
 * the read point still sees (AS OF before the drop, or a transaction older than it). Before its creation the live
 * table answers, with no row, as it always did. */
static int read_table(xctx *x, const sql_stmt *st, const char *name, imdb_table **out, imdb_err *e)
{
    uint64_t snap, pend;
    if (snapshot_of(x, st, &snap, &pend, e)) return e->code;
    imdb_table *t = imdb_table_by_name(x->db, name);
    if (!t || t->created_at > snap) {
        imdb_table *old = imdb_table_at(x->db, name, snap);
        if (old) t = old;
    }
    if (!t) return imdb_fail(e, IMDB_ERR_NOTFOUND, "no table %s", name);
    *out = t;
    return IMDB_OK;
}

/* SELECT ... FOR UPDATE: every selected committed row must still be live when the
 * transaction commits (optimistic: a concurrent writer wins, this commit then
 * conflicts). The transaction's own pending rows need no lock. */
static int lock_rows(xctx *x, imdb_table *t, const sink *k, imdb_err *e)
{
    int rc = imdb_txn_lock_rows(x->db, &x->ss->txn, t, k->vids, k->nvids, e);
    if (rc == IMDB_ERR_CONFLICT) imdb_txn_doom(&x->ss->txn, e->msg);
    return rc;
}

/* The rest of a result's read point (snap is set): db id, commit snap's hash and recorded digest
 * (the commit index, loaded on demand below the snapshot it opened from), the lake then. */
static int read_point(xctx *x, imdb_result *r, imdb_err *e)
{
    imdb_db *db = x->db;
    memcpy(r->db_id, db->db_id, 16);
    if (r->snap == 0) {
        imdb_genesis_hash(db->db_id, r->head);
        imdb_lthash z;
        imdb_lthash_zero(&z);
        imdb_lthash_digest(x->db->meta.digest_alg, &z, r->digest);
    } else {
        const imdb_commit_info *ci = imdb_ci_at(db, r->snap, e);
        if (!ci) return e->code;
        memcpy(r->head, ci->hash, 32);
        memcpy(r->digest, ci->digest, 32);
    }
    r->lake_seq = db->lake_seq;
    memcpy(r->lake_manifest, db->lake_manifest, 32);
    r->show_identity = x->ss->show_identity;
    return IMDB_OK;
}

/* ---- joins: two tables, one equality (design.md §5, "Joins") ------------------------------------
 * Each side runs its own read path (index, ordered, scan) with its own predicates. The hash join
 * puts one side's rows into a hash of the join key (the build side) and the other's probe it. The
 * index nested-loop join (plan C) runs, for each row of one side, the other side's own read path
 * with ON's equality as one more predicate, served by that side's primary key, its subject or an
 * index whose first column is the key: the probe is an existing read path, every candidate checked
 * like any row. A joined row is side 0's columns, then side 1's. LEFT keeps every side-0 row,
 * NULL-extended where nothing matched. The cross-check runs the hash join building side 0 with
 * each side read by scan (by store where the first plan read it by scan), so it shares no read
 * path and no lookup with the first plan; emit, the post-join filter, the order and the projection
 * are common to every plan and are checked by the tests' nested-loop oracle instead (t_join.c).
 * Every read path feeds its sink on the statement's thread (the executor has no parallel loop), so
 * the sinks below write the join's state without locks. */

typedef struct jctx {
    xctx *x;
    imdb_table *t[2];
    imdb_table *ct;              /* the combined columns, for the statement's sink and its result */
    int key[2];                  /* the ON column of each side */
    uint16_t nc[2];
    bool left;
    qspec post;                  /* LEFT: WHERE on side 1, applied to joined rows (np 0: none) */
    int build;                   /* the side hashed; the other probes it */
    imdb_hmap map;               /* join key -> list */
    imdb_vlist *lists;           /* per key: build entries */
    uint32_t nlists, caplists;
    uint64_t *ent;               /* build entry -> its vid */
    uint8_t *matched;            /* LEFT with side 0 built: entries ON matched */
    uint64_t nent, capent;
    uint16_t need[IMDB_MAX_COLS]; /* the build side's columns read after the build (join_need) */
    uint16_t nneed;
    imdb_value *kept;            /* build entry o's need columns, at kept[o * nneed] */
    uint64_t capkept;            /* the entries kept has room for */
    uint8_t **chunks;            /* their TEXT bytes, in chunks of JOIN_CHUNK that never move */
    uint32_t nchunks, capchunks, chunk_used;
    imdb_value brow[IMDB_MAX_COLS]; /* a build row as the probe reads it: its need columns */
    imdb_value nulls[IMDB_MAX_COLS]; /* side 1 NULL-extended */
    int outer;                   /* plan C: the side whose rows probe the other */
    qspec probe;                 /* plan C: the other side's predicates and ON's equality, at p[kp] */
    uint16_t kp;
    int probe_path;              /* IMDB_PATH_INDEX or IMDB_PATH_ORDERED (join_probe_setup), never another */
    sink *inner;                 /* the probe's sink, one for every outer row */
    uint64_t ovid;               /* the outer row a probe is for, and its values */
    const imdb_value *ovals;
    bool omatched;               /* the probe found a row ON matches (LEFT: else NULL-extended) */
    int ran[2];                  /* each side's read path in the last plan (the cross-check's rule) */
    sink *out;                   /* aggregates and groups take joined rows; rows are kept as pairs */
    bool rows;
    uint64_t (*pairs)[2];
    uint64_t npairs, cappairs;
    uint64_t budget, used;       /* the build side and the pairs count against the result's cap */
    uint16_t resid[IMDB_MAX_PREDICATES]; /* WHERE's tree conjuncts, on the joined row (join_emit), any plan's */
    uint16_t nresid;
} jctx;

enum { JOIN_CHUNK = 1u << 16 }; /* more than IMDB_MAX_TEXT: a chunk holds any value whole */

/* a join key as the map takes it: TEXT itself, every other type its int64; false: NULL */
static bool join_key(const imdb_value *v, imdb_value *k)
{
    if (v->null) return false;
    *k = v->type == IMDB_T_TEXT ? *v : (imdb_value){.type = IMDB_T_INT64, .i = v->i};
    return true;
}

/* The working set's charges count what it uses, not what its arrays have allocated: doubling
 * leaves up to as much again uncounted (imdb_mem and res_row count capacities) */
static int join_charge(jctx *j, uint64_t bytes, imdb_err *e)
{
    j->used += bytes;
    if (j->used > j->budget)
        return imdb_fail(e, IMDB_ERR_LIMIT, "a join over its cap of %llu bytes: narrow it with WHERE",
                         (unsigned long long)j->budget);
    return IMDB_OK;
}

static void join_free(jctx *j)
{
    if (j->map.slots) imdb_hmap_free(&j->map);
    for (uint32_t i = 0; i < j->nlists; i++) imdb_free(j->lists[i].v);
    imdb_free(j->lists);
    imdb_free(j->ent);
    imdb_free(j->matched);
    imdb_free(j->pairs);
    if (j->kept) imdb_wipe(j->kept, (size_t)(j->capkept * j->nneed) * sizeof *j->kept); /* row values */
    imdb_free(j->kept);
    for (uint32_t i = 0; i < j->nchunks; i++) {
        imdb_wipe(j->chunks[i], JOIN_CHUNK);
        imdb_free(j->chunks[i]);
    }
    imdb_free(j->chunks);
    imdb_wipe(j->brow, sizeof j->brow);
    j->lists = NULL;
    j->ent = NULL;
    j->matched = NULL;
    j->pairs = NULL;
    j->kept = NULL;
    j->chunks = NULL;
    j->nlists = j->caplists = 0;
    j->nent = j->capent = j->npairs = j->cappairs = j->capkept = 0;
    j->nchunks = j->capchunks = j->chunk_used = 0;
    j->used = 0;
}

/* The build side's columns read after the build: the statement's sink's (aggregates, groups) and,
 * with side 1 built, the post-join filter's. Kept pairs read none: the result fetches its rows. */
static void join_need(jctx *j)
{
    bool use[IMDB_MAX_COLS] = {false};
    int off = j->build ? j->nc[0] : 0, n = j->nc[j->build];
    const sql_stmt *st = j->x->st;
    if (!j->rows) {
        const sink *k = j->out;
        for (uint16_t i = 0; i < k->st->nitems; i++) {
            if (k->item_col[i] >= off && k->item_col[i] < off + n) use[k->item_col[i] - off] = true;
            x_cols(st, j->x->xn, st->items[i].expr, use, off, n);
        }
        if (k->mode == SINK_GROUP && k->gcol >= off && k->gcol < off + n) use[k->gcol - off] = true;
        x_cols(st, j->x->xn, st->having, use, off, n); /* HAVING's aggregates (1e) and ORDER BY's (1d) read it too */
        for (uint8_t o = 0; o < st->norder; o++)
            if (!st->ord_pos[o]) x_cols(st, j->x->xn, st->ord_ex[o], use, off, n);
    }
    for (uint16_t i = 0; i < j->nresid; i++) { /* the trees in WHERE read the joined row, kept pairs' too */
        x_cols(st, j->x->xn, cmp_root(&st->where[j->resid[i]]), use, off, n);
    }
    for (uint16_t i = 0; j->build == 1 && i < j->post.np; i++) use[j->post.p[i].col] = true;
    j->nneed = 0;
    for (int c = 0; c < n; c++)
        if (use[c]) j->need[j->nneed++] = (uint16_t)c;
}

/* a kept TEXT value's bytes, copied: what a read path hands a sink need not outlive the row */
static int join_keep_text(jctx *j, imdb_value *v, imdb_err *e)
{
    if (v->type != IMDB_T_TEXT || v->null || !v->len) return IMDB_OK;
    if (!j->nchunks || v->len > JOIN_CHUNK - j->chunk_used) {
        /* charged whole: under a result cap below 64 KiB (a memory budget below 256 KiB), a join
         * that keeps any TEXT is refused */
        if (join_charge(j, JOIN_CHUNK, e)) return e->code;
        if (j->nchunks == j->capchunks) {
            uint32_t nc = j->capchunks ? 2 * j->capchunks : 16;
            uint8_t **np = imdb_realloc_array(j->chunks, j->capchunks, nc, sizeof *np, e);
            if (!np) return e->code;
            j->chunks = np;
            j->capchunks = nc;
        }
        if (!(j->chunks[j->nchunks] = imdb_alloc(JOIN_CHUNK, e))) return e->code;
        j->nchunks++;
        j->chunk_used = 0;
    }
    uint8_t *p = j->chunks[j->nchunks - 1] + j->chunk_used;
    memcpy(p, v->s, v->len);
    j->chunk_used += v->len;
    v->s = p;
    return IMDB_OK;
}

/* build entry o as the probe reads it */
static const imdb_value *join_kept(jctx *j, uint64_t o)
{
    if (!j->nneed) return j->brow; /* nothing of it is read */
    const imdb_value *kv = &j->kept[o * j->nneed];
    for (uint16_t i = 0; i < j->nneed; i++) j->brow[j->need[i]] = kv[i];
    return j->brow;
}

/* a joined row: past the post-join predicates, into the statement's sink or the pairs */
static void join_emit(sink *k, uint64_t va, uint64_t vb, const imdb_value *a, const imdb_value *b)
{
    jctx *j = k->j;
    if (xtested(j->x, 1, k->e)) { /* every pair formed: the same pairs under every plan */
        k->err = k->e->code;
        return;
    }
    if (j->post.never || (j->post.np && !preds_ok(&j->post, b))) return;
    imdb_value cv[IMDB_MAX_COLS];
    if (!j->rows || j->nresid) {
        memcpy(cv, a, j->nc[0] * sizeof *cv);
        memcpy(cv + j->nc[0], b, j->nc[1] * sizeof *cv);
    }
    if (j->nresid) { /* WHERE's trees, after the join as SQL says, for kept pairs as for aggregates */
        bool ok;
        if (resid_ok(j->x, j->x->st, j->resid, j->nresid, cv, &ok, k->e)) { /* a side's sink has no st */
            k->err = k->e->code;
            return;
        }
        if (!ok) return;
    }
    if (!j->rows) {
        sink_row(j->out, 0, cv);
        if (j->out->err) k->err = j->out->err;
        return;
    }
    if (j->npairs >= IMDB_MAX_JOIN_ROWS) {
        k->err = imdb_fail(k->e, IMDB_ERR_LIMIT, "a join of more than %u rows: narrow it with WHERE", IMDB_MAX_JOIN_ROWS);
        return;
    }
    if (join_charge(j, sizeof *j->pairs, k->e)) {
        k->err = k->e->code;
        return;
    }
    if (j->npairs == j->cappairs) {
        uint64_t nc = j->cappairs ? 2 * j->cappairs : 256;
        uint64_t (*np)[2] = imdb_realloc_array(j->pairs, j->cappairs, nc, sizeof *np, k->e);
        if (!np) {
            k->err = k->e->code;
            return;
        }
        j->pairs = np;
        j->cappairs = nc;
    }
    j->pairs[j->npairs][0] = va;
    j->pairs[j->npairs][1] = vb;
    j->npairs++;
}

/* the build side's rows: kept by join key (a NULL key matches nothing, but LEFT keeps side 0's) */
static void join_build_row(sink *k, uint64_t vid, const imdb_value *vals)
{
    jctx *j = k->j;
    imdb_value key;
    bool has_key = join_key(&vals[j->key[j->build]], &key);
    if (!has_key && !(j->left && j->build == 0)) return;
    if (j->nent >= IMDB_MAX_JOIN_ROWS) {
        k->err = imdb_fail(k->e, IMDB_ERR_LIMIT, "a join side of more than %u rows: narrow it with WHERE", IMDB_MAX_JOIN_ROWS);
        return;
    }
    if (join_charge(j, 2 * sizeof(uint64_t) + 1 + (uint64_t)j->nneed * sizeof(imdb_value), k->e)) {
        k->err = k->e->code;
        return;
    }
    if (j->nent == j->capent) {
        uint64_t nc = j->capent ? 2 * j->capent : 256;
        uint64_t *ne = imdb_realloc_array(j->ent, j->capent, nc, sizeof *ne, k->e);
        if (!ne) {
            k->err = k->e->code;
            return;
        }
        j->ent = ne;
        j->capent = nc;
    }
    uint64_t o = j->nent++;
    j->ent[o] = vid;
    if (j->nneed) {
        if (o == j->capkept) {
            uint64_t nc = j->capkept ? 2 * j->capkept : 256;
            imdb_value *nk = imdb_realloc_array(j->kept, j->capkept * j->nneed, nc * j->nneed, sizeof *nk, k->e);
            if (!nk) {
                k->err = k->e->code;
                return;
            }
            j->kept = nk;
            j->capkept = nc;
        }
        imdb_value *kv = &j->kept[o * j->nneed];
        for (uint16_t i = 0; i < j->nneed; i++) {
            kv[i] = vals[j->need[i]];
            if (join_keep_text(j, &kv[i], k->e)) {
                k->err = k->e->code;
                return;
            }
        }
    }
    if (!has_key) return; /* only for LEFT's NULL-extended rows */
    uint64_t *li = imdb_hmap_get(&j->map, &key);
    uint32_t l;
    if (li) {
        l = (uint32_t)*li;
    } else {
        if (join_charge(j, sizeof(imdb_hslot) + sizeof(imdb_vlist) + (key.type == IMDB_T_TEXT ? key.len : 0), k->e)) {
            k->err = k->e->code;
            return;
        }
        if (j->nlists == j->caplists) {
            uint32_t nc = j->caplists ? 2 * j->caplists : 64;
            imdb_vlist *nl = imdb_realloc_array(j->lists, j->caplists, nc, sizeof *nl, k->e);
            if (!nl) {
                k->err = k->e->code;
                return;
            }
            j->lists = nl;
            j->caplists = nc;
        }
        l = j->nlists++;
        memset(&j->lists[l], 0, sizeof j->lists[l]);
        if (imdb_hmap_put(&j->map, &key, l, k->e)) {
            k->err = k->e->code;
            return;
        }
    }
    imdb_vlist *v = &j->lists[l];
    if (v->n == v->cap) {
        uint32_t nc = v->cap ? 2 * v->cap : 4;
        uint64_t *nv = imdb_realloc_array(v->v, v->cap, nc, sizeof *nv, k->e);
        if (!nv) {
            k->err = k->e->code;
            return;
        }
        v->v = nv;
        v->cap = nc;
    }
    v->v[v->n++] = o;
}

/* the probe side's rows: each joined with the build rows of its key, whose read columns were kept
 * when they were built (join_need): no build row is fetched again */
static void join_probe_row(sink *k, uint64_t vid, const imdb_value *vals)
{
    jctx *j = k->j;
    int p = 1 - j->build;
    imdb_value key;
    const imdb_vlist *l = NULL;
    if (join_key(&vals[j->key[p]], &key)) {
        uint64_t *li = imdb_hmap_get(&j->map, &key);
        if (li) l = &j->lists[*li];
    }
    for (uint32_t i = 0; l && i < l->n && !k->err; i++) {
        if (ktick(k, 1)) break; /* a key of many matches: each pair */
        uint64_t o = l->v[i], bvid = j->ent[o];
        const imdb_value *other = join_kept(j, o);
        if (j->matched) j->matched[o] = 1;
        if (p == 0) join_emit(k, vid, bvid, vals, other);
        else join_emit(k, bvid, vid, other, vals);
    }
    if (!l && j->left && p == 0) join_emit(k, vid, IMDB_NONE, vals, j->nulls);
}

/* Plan C's probe of side `in`: its own predicates, then ON's equality on its key column, whose value
 * each outer row sets (join_outer_row). Only the primary key, the subject or an index whose first
 * column is the key may serve it, so the path is fixed here and never choose_path's (SET
 * access_path = scan would make every probe a scan), nor path_ordered without an index (it falls
 * back to the version store: every probe a walk of the whole table, right answers in quadratic
 * time that no test's answer shows). false: no such probe, and plan C is not used. */
static bool join_probe_setup(jctx *j, const qspec q[2], int in)
{
    qspec *p = &j->probe;
    *p = q[in];
    if (p->np >= IMDB_MAX_PREDICATES) return false; /* no room for the key's */
    const imdb_table *t = p->t;
    int col = j->key[in];
    bpred *b = &p->p[p->np];
    memset(b, 0, sizeof *b);
    b->col = (uint16_t)col;
    b->type = t->s.cols[col].type;
    b->op = CMP_EQ;
    j->kp = p->np++;
    p->ord_only = false;
    if (col == t->s.pk && p->pk_pred < 0) p->pk_pred = j->kp;
    if (col == t->s.subject && p->subj_pred < 0) p->subj_pred = j->kp;
    if (p->pk_pred >= 0 || p->subj_pred >= 0) {
        j->probe_path = IMDB_PATH_INDEX;
        return true;
    }
    choose_ordered(p, col);
    j->probe_path = IMDB_PATH_ORDERED;
    return p->ord_pred >= 0;
}

/* plan C: an outer row looks up the rows ON matches on the other side; a NULL key matches nothing
 * and never becomes a bound (bind_pred's rule: a NULL's value bytes are not a key) */
static void join_outer_row(sink *k, uint64_t vid, const imdb_value *vals)
{
    jctx *j = k->j;
    const imdb_value *v = &vals[j->key[j->outer]];
    j->omatched = false;
    if (!v->null) {
        bpred *b = &j->probe.p[j->kp];
        b->a = *v; /* the outer row's own bytes: read only while it is the row being probed for */
        if (b->type != IMDB_T_TEXT) b->lo = b->hi = v->i;
        j->ovid = vid;
        j->ovals = vals;
        j->inner->err = 0;
        int rc = run_path(k->x, j->probe_path, &j->probe, j->inner, k->e);
        if (rc || j->inner->err) {
            k->err = rc ? rc : j->inner->err;
            return;
        }
    }
    if (!j->omatched && j->left) join_emit(k, vid, IMDB_NONE, vals, j->nulls); /* LEFT: side 0 is the outer one */
}

/* plan C: a row the probe found; its read path checked it against the side's predicates and ON */
static void join_inner_row(sink *k, uint64_t vid, const imdb_value *vals)
{
    jctx *j = k->j;
    j->omatched = true;
    if (j->outer == 0) join_emit(k, j->ovid, vid, j->ovals, vals);
    else join_emit(k, vid, j->ovid, vals, j->ovals);
}

/* each side's read path in a plan (the runners' j->ran, and EXPLAIN's): the hash join's built side (side) and its
 * probing side, or plan C's outer side (side) and the probed one (join_probe_setup's probe_path, set before); path[s] >= 0
 * forces side s's (the cross-check's), else choose_path's with the sink kind the plan gives that side, the one thing it
 * reads of a sink (a join's side is never a plain aggregate: no price is compared) */
static void join_side_paths(const xctx *x, const jctx *j, const qspec q[2], bool index, int side, const int path[2],
                            int out[2])
{
    sink k;
    memset(&k, 0, sizeof k);
    k.mode = index ? SINK_JOUTER : SINK_JBUILD;
    out[side] = path[side] >= 0 ? path[side] : choose_path(x->ss, &q[side], &k);
    if (index) {
        out[1 - side] = j->probe_path;
        return;
    }
    k.mode = SINK_JPROBE;
    out[1 - side] = path[1 - side] >= 0 ? path[1 - side] : choose_path(x->ss, &q[1 - side], &k);
}

/* plan C: side `outer` read by path (-1: choose_path's), each of its rows probing the other side */
static int join_index_plan(jctx *j, qspec q[2], int outer, int path, imdb_err *e)
{
    xctx *x = j->x;
    join_free(j);
    j->outer = outer;
    if (!join_probe_setup(j, q, 1 - outer)) /* join_choose checked it: a planning error */
        return imdb_fail(e, IMDB_ERR_STATE, "a join planned on an index the other table does not have");
    sink ko, ki;
    memset(&ko, 0, sizeof ko);
    ko.mode = SINK_JOUTER;
    ko.x = x;
    ko.t = j->t[outer];
    ko.e = e;
    ko.j = j;
    memset(&ki, 0, sizeof ki);
    ki.mode = SINK_JINNER;
    ki.x = x;
    ki.t = j->t[1 - outer];
    ki.e = e;
    ki.j = j;
    j->inner = &ki;
    int forced[2] = {path, path};
    join_side_paths(x, j, q, true, outer, forced, j->ran);
    int rc = run_path(x, j->ran[outer], &q[outer], &ko, e);
    j->inner = NULL;
    return rc ? rc : ko.err;
}

/* the hash join: side `build` hashed, the other probing, each side read by path[s] (-1:
 * choose_path's); LEFT with side 0 built emits its unmatched rows after the probe */
static int join_hash_plan(jctx *j, qspec q[2], int build, const int path[2], imdb_err *e)
{
    xctx *x = j->x;
    join_free(j);
    j->build = build;
    join_need(j);
    uint8_t kt = j->t[build]->s.cols[j->key[build]].type == IMDB_T_TEXT ? IMDB_T_TEXT : IMDB_T_INT64;
    if (imdb_hmap_init(&j->map, kt, e)) return e->code;
    sink kb, kp;
    memset(&kb, 0, sizeof kb);
    kb.mode = SINK_JBUILD;
    kb.x = x;
    kb.t = j->t[build];
    kb.e = e;
    kb.j = j;
    memset(&kp, 0, sizeof kp);
    kp.mode = SINK_JPROBE;
    kp.x = x;
    kp.t = j->t[1 - build];
    kp.e = e;
    kp.j = j;
    join_side_paths(x, j, q, false, build, path, j->ran);
    int rc = run_path(x, j->ran[build], &q[build], &kb, e);
    if (!rc) rc = kb.err;
    if (!rc && j->left && build == 0 && !(j->matched = imdb_alloc_array(j->nent ? j->nent : 1, 1, e))) rc = e->code;
    if (!rc) rc = run_path(x, j->ran[1 - build], &q[1 - build], &kp, e);
    if (!rc) rc = kp.err;
    if (!rc && j->left && build == 0) {
        for (uint64_t o = 0; o < j->nent && !rc; o++) {
            if (j->matched[o]) continue;
            join_emit(&kp, j->ent[o], IMDB_NONE, join_kept(j, o), j->nulls);
            rc = kp.err;
        }
    }
    return rc;
}

enum { JP_HASH = 1, JP_INDEX };

/* a join's plan: the hash join building side `side`, or plan C with `side` the outer one; path[s]:
 * side s's read path, -1 for choose_path's (the cross-check reads each side by scan or store) */
typedef struct jplan {
    int kind, side;
    int path[2];
} jplan;

/* Relative costs in COST_VEC's units, from bench/join_cost.c (2026-10-26, i7-8550U at about 3.8 GHz:
 * the performance profile and governor; 100,000 rows a side in segments; the medians of three runs'
 * ratios, one IMDB_THREADS=1 run within 1.1x of them): a scanned row 1.7 ns; a build row of the hash
 * join 218 ns (its read, its key and kept columns, the hash's insert), a probe row of it 49 ns (its
 * read and the hash's lookup); plan C's outer row with its lookup through a primary key 183 ns and
 * through an index 405 ns (the range's search, the first candidate read), and each further
 * candidate 40 ns (its visibility, its values, its predicates). */
enum { COST_JBUILD = 127, COST_JHPROBE = 29, COST_JPK = 107, COST_JORD = 237, COST_JCAND = 23 };

/* an upper bound of the rows q's read path returns, from the structures (there are no statistics):
 * a primary-key equality one, a subject its versions, an index its range's entries and the
 * reader's own versions past idx_upto, a scan the table's versions */
static uint64_t join_est_rows(const qspec *q)
{
    imdb_table *t = q->t;
    if (q->never) return 0;
    if (q->pk_pred >= 0) return 1;
    if (q->subj_pred >= 0) {
        const imdb_vlist *l = imdb_subject_versions(t, &q->p[q->subj_pred].a);
        return l ? l->n : 0;
    }
    if (q->ord_pred >= 0) {
        uint64_t lo[IMDB_MAX_INDEX_COLS], hi[IMDB_MAX_INDEX_COLS];
        ord_bounds(q, lo, hi);
        return imdb_oidx_count(q->ord_idx->ox, lo, hi) + (t->nver - t->idx_upto);
    }
    return t->nver;
}

/* one probe of plan C (join_probe_setup ran), its first candidate included (as measured): a primary
 * key's chain gives its newest visible version first; an index's range holds every version of
 * the key, so a candidate per version of a live row (the table's versions per live row, rounded
 * up), and the reader's own versions past idx_upto, visited on every probe; a subject's list holds
 * all its versions, the table's per subject on average */
static uint64_t join_probe_cost(const jctx *j)
{
    const qspec *p = &j->probe;
    const imdb_table *t = p->t;
    if (p->pk_pred >= 0) return COST_JPK;
    if (p->subj_pred >= 0) return COST_JPK + t->nver / (t->nsubj ? t->nsubj : 1) * COST_JCAND;
    uint64_t amp = t->live ? (t->nver + t->live - 1) / t->live : t->nver;
    return COST_JORD + (amp > 1 ? amp - 1 : 0) * COST_JCAND + (t->nver - t->idx_upto) * COST_MEM_ROW;
}

/* the prices the planner compares, kept for EXPLAIN (join_choose fills them) */
typedef struct jprice {
    bool priced;                  /* join_choose ran */
    uint64_t est[2];              /* each side's rows, at most */
    unsigned __int128 hash, c[2]; /* the hash join (side 2 built); plan C with side s outer, where has[s] */
    bool has[2];
} jprice;

/* The plan (design.md §5, Joins): the hash join building side 1, or plan C where it costs less. The
 * hash join reads the build side whole after its own predicates; plan C costs a probe per outer
 * row instead. Every count is an upper bound, so plan C is chosen only when a bound on its probes
 * is small; below COST_FLOOR either plan is fast and the hash join stays, so small tables keep
 * their plans. force (SET join_plan = index): plan C wherever a probe exists, in the cheaper
 * orientation; where none does, the hash join, and the path name says so. LEFT: side 0 is the
 * outer side (its unmatched rows are NULL-extended as they are read). */
static jplan join_choose(jctx *j, const qspec q[2], bool force, jprice *pr)
{
    jplan p = {JP_HASH, 1, {-1, -1}};
    uint64_t n[2] = {join_est_rows(&q[0]), join_est_rows(&q[1])};
    unsigned __int128 hash = (unsigned __int128)n[1] * COST_JBUILD + (unsigned __int128)n[0] * COST_JHPROBE, best = 0;
    if (pr) { /* EXPLAIN's (P1 Q1) */
        memset(pr, 0, sizeof *pr);
        pr->priced = true;
        pr->est[0] = n[0];
        pr->est[1] = n[1];
        pr->hash = hash;
    }
    int side = -1;
    for (int outer = 0; outer < (j->left ? 1 : 2); outer++) {
        if (!join_probe_setup(j, q, 1 - outer)) continue;
        unsigned __int128 c = (unsigned __int128)n[outer] * join_probe_cost(j);
        if (pr) {
            pr->c[outer] = c;
            pr->has[outer] = true;
        }
        if (side >= 0 && c >= best) continue;
        best = c;
        side = outer;
    }
    if (side >= 0 && (force || (hash >= COST_FLOOR && best < hash))) {
        p.kind = JP_INDEX;
        p.side = side;
    }
    return p;
}

/* the plan as the result names it: join(build 2), join(index 2) (side 2 probed for each side-1
 * row), and the cross-check's join(build 1; scan, scan) */
static const char *join_path_word(int path)
{
    return path == IMDB_PATH_SCAN ? "scan" : path == IMDB_PATH_ROWS ? "rows" : "store";
}

static void join_plan_name(const jplan *p, char *out, size_t n)
{
    if (p->kind == JP_INDEX) snprintf(out, n, "join(index %c)", p->side ? '1' : '2');
    else if (p->path[0] < 0) snprintf(out, n, "join(build %c)", p->side ? '2' : '1');
    else
        snprintf(out, n, "join(build %c; %s, %s)", p->side ? '2' : '1', join_path_word(p->path[0]), join_path_word(p->path[1]));
}

/* a column reference of a join: its side and column; an unqualified name must be in one table */
static int join_col(const sql_stmt *st, imdb_table *const t[2], const char *qual, const char *name, int *side, int *col,
                    imdb_err *e)
{
    const char *nm[2] = {st->alias[0] ? st->alias : st->table, st->alias2[0] ? st->alias2 : st->table2};
    if (qual[0] && strcmp(qual, nm[0]) != 0 && strcmp(qual, nm[1]) != 0)
        return imdb_fail(e, IMDB_ERR_NOTFOUND, "no table %s in this statement", qual);
    int found = 0;
    for (int s = 0; s < 2; s++) {
        if (qual[0] && strcmp(qual, nm[s]) != 0) continue;
        int c = imdb_schema_col(&t[s]->s, name);
        if (c < 0) continue;
        if (found++) return imdb_fail(e, IMDB_ERR_INVALID, "column %s is in both tables: qualify it", name);
        *side = s;
        *col = c;
    }
    if (!found) return imdb_fail(e, IMDB_ERR_NOTFOUND, "no column %s in the joined tables", name);
    return IMDB_OK;
}

/* the statement's sink over joined rows (plan_select's rules, on combined column numbers) */
static int plan_join_sink(xctx *x, const sql_stmt *st, jctx *j, sink *k, imdb_err *e)
{
    memset(k, 0, sizeof *k);
    k->x = x;
    k->st = st;
    k->t = j->ct;
    k->e = e;
    int side, c, gcol = -1;
    if (st->has_group) {
        if (join_col(st, j->t, st->group_qual, st->group_col, &side, &c, e)) return e->code;
        gcol = side ? j->nc[0] + c : c;
    }
    bool any_agg = false, any_plain = st->star; /* every column of *, plain: an aggregate in HAVING or ORDER BY is mixing */
    xscope si = {.st = st, .s = &j->ct->s, .jt = j->t, .nc0 = j->nc[0], .cols = true, .aggs = true, .group_col = gcol,
                 .agg_nodes = k->xa_node};
    for (uint16_t i = 0; i < st->nitems; i++) {
        const sql_item *it = &st->items[i];
        k->item_col[i] = -1;
        if (it->expr) { /* a tree: per row (materialize), or over its aggregates' slots */
            if (bind_item(x, k, &si, it->expr, &any_agg, &any_plain, e)) return e->code;
            continue;
        }
        if (it->agg == AGG_COUNT_STAR) {
            any_agg = true;
            continue;
        }
        if (join_col(st, j->t, it->qual, it->col, &side, &c, e)) return e->code;
        int cc = side ? j->nc[0] + c : c;
        k->item_col[i] = cc;
        if (it->agg == AGG_NONE) {
            any_plain = true;
            if (st->has_group && cc != gcol)
                return imdb_fail(e, IMDB_ERR_INVALID, "column %s must be the GROUP BY column or inside an aggregate", it->col);
        } else {
            any_agg = true;
            uint8_t ct = j->ct->s.cols[cc].type;
            if (it->agg == AGG_SUM && ct != IMDB_T_INT64 && ct != IMDB_T_DECIMAL && ct != IMDB_T_FLOAT64)
                return imdb_fail(e, IMDB_ERR_INVALID, "SUM needs an INT64, DECIMAL or FLOAT64 column");
        }
    }
    if (bind_having(x, st, k, &si, &any_agg, &any_plain, e) ||
        bind_order(x, st, k, &si, st->star ? (uint16_t)(j->nc[0] + j->nc[1]) : st->nitems, &any_agg, &any_plain, e))
        return e->code;
    if (alloc_xa(x, k, &si, e)) return e->code;
    if (st->has_group) {
        if (st->star) return imdb_fail(e, IMDB_ERR_INVALID, "SELECT * cannot be grouped");
        k->mode = SINK_GROUP;
        k->gcol = gcol;
        uint8_t kt = j->ct->s.cols[gcol].type == IMDB_T_TEXT ? IMDB_T_TEXT : IMDB_T_INT64;
        if (imdb_hmap_init(&k->gmap, kt, e)) return e->code;
    } else if (any_agg) {
        if (any_plain) return imdb_fail(e, IMDB_ERR_INVALID, "mixing aggregates and columns needs GROUP BY");
        k->mode = SINK_AGG;
    } else {
        k->mode = SINK_VIDS;
        if (st->having) return imdb_fail(e, IMDB_ERR_INVALID, "HAVING needs GROUP BY or an aggregate");
    }
    return IMDB_OK;
}

typedef struct jkeyed {
    imdb_value ka, kb;
    uint64_t va, vb;
} jkeyed;

/* side 0's primary key, then side 1's, a NULL-extended row after: one order whatever the plan */
static int cmp_jkeyed(const void *a, const void *b)
{
    const jkeyed *x = a, *y = b;
    int c = imdb_value_cmp(&x->ka, &y->ka);
    if (c) return c;
    if ((x->vb == IMDB_NONE) != (y->vb == IMDB_NONE)) return x->vb == IMDB_NONE ? 1 : -1;
    return x->vb == IMDB_NONE ? 0 : imdb_value_cmp(&x->kb, &y->kb);
}

/* pair i's joined row into cv: side 0's columns, then side 1's (NULL-extended where nothing matched) */
static int join_pair(xctx *x, jctx *j, const jkeyed *p, imdb_value *cv, imdb_err *e)
{
    if (fetch_row(x, j->t[0], p->va, cv, e)) return e->code;
    if (p->vb == IMDB_NONE) memcpy(cv + j->nc[0], j->nulls, j->nc[1] * sizeof *cv);
    else if (fetch_row(x, j->t[1], p->vb, cv + j->nc[0], e)) return e->code;
    return IMDB_OK;
}

static int join_materialize(xctx *x, const sql_stmt *st, jctx *j, sink *k, imdb_result *r, imdb_err *e)
{
    if (!j->rows) return materialize(x, st, j->ct, k, r, e);
    uint16_t nc = st->star ? (uint16_t)(j->nc[0] + j->nc[1]) : st->nitems;
    res_cols(r, nc);
    for (uint16_t i = 0; i < nc; i++) {
        char nm[IMDB_MAX_IDENT + 8];
        if (st->star) snprintf(nm, sizeof nm, "%s", j->ct->s.cols[i].name);
        else item_name(x, &st->items[i], nm, sizeof nm);
        res_name(r, i, nm);
    }
    if (join_charge(j, (j->npairs ? j->npairs : 1) * sizeof(jkeyed), e)) return e->code; /* the sort's keys too */
    jkeyed *kv = imdb_alloc_array(j->npairs ? j->npairs : 1, sizeof *kv, e);
    if (!kv) return e->code;
    for (uint64_t i = 0; i < j->npairs; i++) {
        kv[i].va = j->pairs[i][0];
        kv[i].vb = j->pairs[i][1];
        imdb_version_key(j->t[0], kv[i].va, j->t[0]->s.pk, &kv[i].ka);
        if (kv[i].vb != IMDB_NONE) imdb_version_key(j->t[1], kv[i].vb, j->t[1]->s.pk, &kv[i].kb);
    }
    qsort(kv, j->npairs, sizeof *kv, cmp_jkeyed);
    int rc = IMDB_OK;
    imdb_value cv[IMDB_MAX_COLS];
    if (plain_order(st)) { /* side 0's key, then side 1's: the first LIMIT pairs */
        uint64_t lim = st->has_limit && st->limit < j->npairs ? st->limit : j->npairs;
        for (uint64_t i = 0; i < lim && !rc; i++)
            if (!(rc = xtick(x, 1, e)) && !(rc = join_pair(x, j, &kv[i], cv, e))) rc = put_row(x, st, k, cv, nc, r, e);
        imdb_free(kv);
        return rc ? rc : res_finish(r, e);
    }
    /* ORDER BY's keys for every joined row, the pairs' order breaking ties; then OFFSET, DISTINCT and LIMIT */
    uint64_t n = j->npairs, *ord = imdb_alloc_array(n ? n : 1, sizeof *ord, e);
    imdb_xval *keys = NULL;
    window w;
    memset(&w, 0, sizeof w);
    if (!ord) rc = e->code;
    for (uint64_t i = 0; !rc && i < n; i++) ord[i] = i;
    if (!rc && st->norder &&
        (join_charge(j, (n ? n : 1) * st->norder * sizeof(imdb_xval), e) || !(keys = order_keys_alloc(r, st, n, e))))
        rc = e->code;
    for (uint64_t i = 0; !rc && keys && i < n; i++) {
        if ((rc = xtick(x, 1, e)) || (rc = join_pair(x, j, &kv[i], cv, e))) break;
        for (uint8_t o = 0; !rc && o < st->norder; o++) rc = order_key(x, st, k, o, cv, &keys[i * st->norder + o], e);
    }
    if (!rc && keys) {
        ordctx c = {st, keys};
        qsort_r(ord, n, sizeof *ord, cmp_order, &c);
        rc = xcheck(x, e); /* a sort runs to its end: the check after it */
    }
    if (!rc) rc = window_init(&w, st, e);
    for (uint64_t jx = 0; !rc && jx < n && w.left; jx++) {
        if (!w.distinct && w.skip) {
            w.skip--;
            continue;
        }
        size_t tl = r->text.len;
        if (!(rc = xtick(x, 1, e)) && !(rc = join_pair(x, j, &kv[ord[jx]], cv, e)) && !(rc = put_row(x, st, k, cv, nc, r, e)))
            rc = window_take(&w, r, tl, e);
    }
    window_free(&w);
    imdb_free(keys);
    imdb_free(ord);
    imdb_free(kv);
    return rc ? rc : res_finish(r, e);
}

/* ---- EXPLAIN's rows (P1 Q1) ---------------------------------------------------------------------------------------- */

static void xp_snapshot(const xctx *x, const sql_stmt *st, uint64_t snap, uint64_t pend, xplain *xp)
{
    xp_add(xp, "snapshot", "commit %llu%s%s", (unsigned long long)snap,
           st->has_asof ? " (AS OF)" : x->ss->txn.open ? " (the transaction's)" : " (the latest)",
           pend ? ", and this transaction's own writes" : "");
}

/* what the statement makes of the rows read: the sink's kind, then ORDER BY, DISTINCT, OFFSET, LIMIT, FOR UPDATE */
static void xp_output(xplain *xp, const sql_stmt *st, const sink *k, const imdb_schema *s)
{
    char o[XP_DETAIL];
    size_t n = 0;
    o[0] = 0;
    if (st->explained != ST_SELECT)
        xcat(o, sizeof o, &n, "%s", st->explained == ST_UPDATE ? "each row matched gets a new version (UPDATE)"
                                                                : "each row matched is ended (DELETE)");
    else if (k->mode == SINK_GROUP) xcat(o, sizeof o, &n, "a row for each group of %s", s->cols[k->gcol].name);
    else if (k->mode == SINK_AGG) xcat(o, sizeof o, &n, "one row of aggregates");
    else if (st->star) xcat(o, sizeof o, &n, "the rows, every column");
    else xcat(o, sizeof o, &n, "the rows, %u item%s", st->nitems, st->nitems == 1 ? "" : "s");
    if (st->having) xcat(o, sizeof o, &n, "; HAVING on each group");
    if (st->distinct) xcat(o, sizeof o, &n, "; DISTINCT");
    if (st->norder) xcat(o, sizeof o, &n, "; ordered by %u key%s", st->norder, st->norder == 1 ? "" : "s");
    if (st->has_offset) xcat(o, sizeof o, &n, "; OFFSET %llu", (unsigned long long)st->offset);
    if (st->has_limit) xcat(o, sizeof o, &n, "; LIMIT %llu", (unsigned long long)st->limit);
    if (st->for_update) xcat(o, sizeof o, &n, "; FOR UPDATE (locks taken when it runs, none by EXPLAIN)");
    xp_add(xp, "output", "%s", o);
}

/* one table's read: the path choose_path chose (path) and from what, in choose_path's order */
static void xp_single(const xctx *x, const sql_stmt *st, const qspec *q, const sink *k, int path, xplain *xp)
{
    const imdb_table *t = q->t;
    const imdb_schema *s = &t->s;
    xp_add(xp, "table", "%s", s->name);
    xp_snapshot(x, st, q->snap, q->pend, xp);
    xp_add(xp, "path", "%s", path_name(path, q));
    unsigned __int128 po = 0, ps = 0;
    bool ordered = q->ord_pred >= 0 && !q->all_versions;
    if (q->never) xp_add(xp, "why", "an empty range: no row can match, none is read");
    else if (below_floor(x->db, q))
        xp_add(xp, "why", "below this copy's memory floor (commit %llu): the lake answers, by its scan",
               (unsigned long long)x->db->mem_floor);
    else if (x->ss->access_path != IMDB_PATH_AUTO) xp_add(xp, "why", "SET access_path = %s", access_word(x->ss->access_path));
    else if (q->pk_pred >= 0) xp_add(xp, "why", "an equality on the primary key");
    else if (q->subj_pred >= 0) xp_add(xp, "why", "an equality on the subject");
    else if (ordered && !scan_price(q, k, &po, &ps))
        xp_add(xp, "why", "an ordered index serves the conditions (prices are compared only for a plain COUNT or SUM, "
                          "whose scan sums segment rows without reading each)");
    else if (ordered && po < COST_FLOOR)
        xp_add(xp, "why", "the price: ordered %llu, scan %llu; under %u the index is kept", price_u64(po), price_u64(ps),
               (unsigned)COST_FLOOR);
    else if (ordered && ps < po) xp_add(xp, "why", "the price: scan %llu, below ordered %llu", price_u64(ps), price_u64(po));
    else if (ordered) xp_add(xp, "why", "the price: ordered %llu, at most scan %llu", price_u64(po), price_u64(ps));
    else xp_add(xp, "why", "no index serves the conditions");
    unsigned by = 0;
    if (path == IMDB_PATH_INDEX && q->pk_pred >= 0) {
        xp_add(xp, "index", "the primary key (%s)", s->cols[s->pk].name);
        by = 1;
    } else if (path == IMDB_PATH_INDEX && q->subj_pred >= 0) {
        xp_add(xp, "index", "the subject's (%s)", s->cols[s->subject].name);
        by = 1;
    } else if (path == IMDB_PATH_ORDERED && ordered) {
        const imdb_index *ix = q->ord_idx;
        char d[XP_DETAIL];
        size_t n = 0;
        d[0] = 0;
        xcat(d, sizeof d, &n, "%s (", ix->d.name);
        for (uint8_t c = 0; c < ix->d.ncols; c++) xcat(d, sizeof d, &n, "%s%s", c ? ", " : "", s->cols[ix->d.cols[c]].name);
        xcat(d, sizeof d, &n, "):");
        for (uint8_t c = 0; c < q->ord_neq; c++)
            xcat(d, sizeof d, &n, "%s%s", c ? ", " : " equality on ", s->cols[ix->d.cols[c]].name);
        if (q->ord_rng >= 0) xcat(d, sizeof d, &n, "%sa range on %s", q->ord_neq ? ", then " : " ", s->cols[ix->d.cols[q->ord_neq]].name);
        if (q->ord_only) xcat(d, sizeof d, &n, "; the index alone answers: no row is read");
        xp_add(xp, "index", "%s", d);
        by = q->ord_neq + (q->ord_rng >= 0);
    }
    unsigned all = q->np + k->nresid;
    if (all) xp_add(xp, "conditions", "%u: %u by the index, %u tested on each row read", all, by, all - by);
    else xp_add(xp, "conditions", "none: every visible row");
    uint64_t est = join_est_rows(q);
    xp_add(xp, "estimate", "at most %llu version%s read (an upper bound from the indexes and the store: no statistics)",
           (unsigned long long)est, est == 1 ? "" : "s");
    if ((path == IMDB_PATH_SCAN || path == IMDB_PATH_ROWS) && !q->never) {
        uint32_t rd = 0;
        for (uint32_t i = 0; i < t->nseg; i++) rd += !seg_skipped(q, t->seg[i]);
        xp_add(xp, "segments", "%u of %u read (%u skipped by their zone maps); %llu versions in memory", rd, t->nseg,
               t->nseg - rd, (unsigned long long)(t->nver - t->mem_first));
    }
    xp_output(xp, st, k, s);
}

/* a join's plan (exec_join's choice, p, named pname) and why; the prices join_choose compared; each side's path */
static int xp_join(xctx *x, const sql_stmt *st, jctx *j, qspec q[2], const jplan *p, const jprice *pr, const char *pname,
                   xplain *xp, imdb_err *e)
{
    sink k;
    int rc = plan_join_sink(x, st, j, &k, e); /* the select list bound as the run binds it: it fails the same way */
    if (rc) {
        sink_free(&k);
        return rc;
    }
    const imdb_schema *s0 = &j->t[0]->s, *s1 = &j->t[1]->s;
    xp_add(xp, "join", "%s %s %s, on %s.%s = %s.%s", s0->name, j->left ? "LEFT JOIN" : "JOIN", s1->name, s0->name,
           s0->cols[j->key[0]].name, s1->name, s1->cols[j->key[1]].name);
    xp_snapshot(x, st, q[0].snap, q[0].pend, xp);
    xp_add(xp, "plan", "%s", pname);
    int jp = x->ss->join_plan;
    char side = p->side ? '2' : '1';
    if (below_floor(x->db, &q[0]))
        xp_add(xp, "why", "below this copy's memory floor (commit %llu): the hash join, each side read from the lake",
               (unsigned long long)x->db->mem_floor);
    else if (jp == IMDB_JOIN_HASH) xp_add(xp, "why", "SET join_plan = hash");
    else if (jp == IMDB_JOIN_AUTO && x->ss->access_path != IMDB_PATH_AUTO)
        xp_add(xp, "why", "SET access_path = %s is every table's read: the hash join", access_word(x->ss->access_path));
    else if (jp == IMDB_JOIN_INDEX)
        xp_add(xp, "why", "%s", p->kind == JP_INDEX ? "SET join_plan = index, in the cheaper orientation"
                                                     : "SET join_plan = index, but no index serves a side's key: the hash join");
    else if (p->kind == JP_INDEX) xp_add(xp, "why", "the price: plan C with side %c outer, below the hash join's", side);
    else if (!pr->has[0] && !pr->has[1]) xp_add(xp, "why", "no index serves a side's key: the hash join");
    else if (pr->hash < COST_FLOOR) xp_add(xp, "why", "the hash join's price is under %u: it is kept", (unsigned)COST_FLOOR);
    else xp_add(xp, "why", "the price: the hash join is the cheapest");
    if (pr->priced) {
        char d[XP_DETAIL];
        size_t n = 0;
        d[0] = 0;
        xcat(d, sizeof d, &n, "hash join %llu (side 2 built: at most %llu rows; side 1 probing: at most %llu)",
             price_u64(pr->hash), (unsigned long long)pr->est[1], (unsigned long long)pr->est[0]);
        for (int o = 0; o < 2; o++) {
            if (pr->has[o]) xcat(d, sizeof d, &n, "; plan C, side %d outer: %llu", o + 1, price_u64(pr->c[o]));
            else if (o && j->left) xcat(d, sizeof d, &n, "; plan C, side 2 outer: none (LEFT keeps side 1 outer)");
            else xcat(d, sizeof d, &n, "; plan C, side %d outer: none (no index on side %d's key)", o + 1, 2 - o);
        }
        xp_add(xp, "price", "%s", d);
    }
    if (p->kind == JP_INDEX && !join_probe_setup(j, q, 1 - p->side)) { /* join_choose found it: as join_index_plan */
        sink_free(&k);
        return imdb_fail(e, IMDB_ERR_STATE, "a join planned on an index the other table does not have");
    }
    int ran[2];
    join_side_paths(x, j, q, p->kind == JP_INDEX, p->side, p->path, ran);
    for (int sd = 0; sd < 2; sd++) {
        bool probed = p->kind == JP_INDEX && sd != p->side;
        const char *role = p->kind == JP_INDEX ? (probed ? "probed by its key for each outer row" : "outer: each row probes")
                                               : (sd == p->side ? "built into the hash" : "probing the hash");
        if (probed)
            xp_add(xp, sd ? "side 2" : "side 1", "%s: %s, %s", j->t[sd]->s.name, path_name(ran[sd], &j->probe), role);
        else
            xp_add(xp, sd ? "side 2" : "side 1", "%s: %s, %s, at most %llu versions", j->t[sd]->s.name,
                   path_name(ran[sd], &q[sd]), role, (unsigned long long)join_est_rows(&q[sd]));
    }
    xp_output(xp, st, &k, &j->ct->s);
    sink_free(&k);
    return IMDB_OK;
}

/* one plan into r: the statement's sink, the plan, its result */
static int join_run(xctx *x, const sql_stmt *st, jctx *j, qspec q[2], const jplan *p, imdb_result *r, imdb_err *e)
{
    sink k;
    int rc = plan_join_sink(x, st, j, &k, e);
    j->out = &k;
    k.joined = true;
    j->rows = k.mode == SINK_VIDS;
    j->budget = r->byte_cap ? r->byte_cap : IMDB_MAX_RESULT_BYTES;
    if (!rc)
        rc = p->kind == JP_INDEX ? join_index_plan(j, q, p->side, p->path[p->side], e) : join_hash_plan(j, q, p->side, p->path, e);
    if (!rc) rc = sink_pin(&k);
    if (!rc) rc = join_materialize(x, st, j, &k, r, e);
    sink_free(&k);
    join_free(j);
    j->out = NULL;
    return rc;
}

static int exec_join(xctx *x, const sql_stmt *st, imdb_result *r, xplain *xp, imdb_err *e)
{
    imdb_table *t[2]; /* each at the read point (1f: a table dropped since, for AS OF before the drop) */
    if (read_table(x, st, st->table, &t[0], e) || read_table(x, st, st->table2, &t[1], e)) return e->code;
    if (strcmp(st->alias[0] ? st->alias : st->table, st->alias2[0] ? st->alias2 : st->table2) == 0)
        return imdb_fail(e, IMDB_ERR_INVALID, "the two sides of a join need two names: give one an alias (AS)");
    if ((unsigned)t[0]->s.ncols + t[1]->s.ncols > IMDB_MAX_COLS)
        return imdb_fail(e, IMDB_ERR_LIMIT, "a join reads at most %u columns of its two tables", IMDB_MAX_COLS);
    jctx *j = imdb_alloc(sizeof *j, e);
    if (!j) return e->code;
    int rc = IMDB_OK;
    j->x = x;
    j->t[0] = t[0];
    j->t[1] = t[1];
    j->nc[0] = t[0]->s.ncols;
    j->nc[1] = t[1]->s.ncols;
    j->left = st->join_left;
    if (!(j->ct = imdb_alloc(sizeof *j->ct, e))) {
        imdb_free(j);
        return e->code;
    }
    j->ct->s.ncols = (uint16_t)(j->nc[0] + j->nc[1]);
    memcpy(j->ct->s.cols, t[0]->s.cols, j->nc[0] * sizeof *t[0]->s.cols);
    memcpy(j->ct->s.cols + j->nc[0], t[1]->s.cols, j->nc[1] * sizeof *t[1]->s.cols);
    if (j->left) /* side 1's columns are NULL where nothing matched, whatever its table declares */
        for (uint16_t c = 0; c < j->nc[1]; c++) j->ct->s.cols[j->nc[0] + c].flags |= IMDB_COL_NULLABLE;
    snprintf(j->ct->s.name, sizeof j->ct->s.name, "%s", t[0]->s.name);
    for (uint16_t c = 0; c < j->nc[1]; c++)
        j->nulls[c] = (imdb_value){.type = t[1]->s.cols[c].type, .scale = t[1]->s.cols[c].scale, .null = true};
    /* ON: a column of each side, of one type (values are tagged: never converted) */
    int s0 = 0, c0 = 0, s1 = 0, c1 = 0;
    if (join_col(st, t, st->on_qual[0], st->on_col[0], &s0, &c0, e) || join_col(st, t, st->on_qual[1], st->on_col[1], &s1, &c1, e))
        rc = e->code;
    else if (s0 == s1)
        rc = imdb_fail(e, IMDB_ERR_INVALID, "a join's ON compares a column of each table");
    if (!rc) {
        j->key[s0] = c0;
        j->key[s1] = c1;
        const imdb_column *k0 = &t[0]->s.cols[j->key[0]], *k1 = &t[1]->s.cols[j->key[1]];
        if (k0->type != k1->type || (k0->type == IMDB_T_DECIMAL && k0->scale != k1->scale))
            rc = imdb_fail(e, IMDB_ERR_INVALID, "a join's ON compares %s with %s: values are not converted",
                           imdb_type_name(k0->type), imdb_type_name(k1->type));
    }
    /* one snapshot for both sides, below neither table's purge horizon */
    uint64_t snap = 0, pend = 0;
    if (!rc && (resolve_snapshot(x, st, t[0], &snap, &pend, e) || check_view(x, t[1], snap, st->has_asof, e))) rc = e->code;
    qspec q[2];
    memset(q, 0, sizeof q);
    for (int s = 0; s < 2; s++) {
        q[s].t = t[s];
        q[s].snap = snap;
        q[s].pend = pend;
        q[s].pk_pred = q[s].subj_pred = q[s].ord_pred = -1;
    }
    j->post.t = t[1];
    j->post.snap = snap;
    j->post.pend = pend;
    /* WHERE: each predicate to its side; LEFT keeps side 1's for after the join, as SQL says */
    for (uint16_t i = 0; !rc && i < st->nwhere; i++) {
        int side = 0, col = 0;
        if (st->where[i].lx) continue; /* a tree's: on the joined row (join_emit) */
        if (join_col(st, t, st->where[i].qual, st->where[i].col, &side, &col, e)) rc = e->code;
        else {
            qspec *bq = j->left && side == 1 ? &j->post : &q[side];
            uint16_t np = bq->np;
            rc = bind_pred(x, &st->where[i], col, j->left && side == 1, bq, e);
            if (rc && falls_back(&st->where[i], &t[side]->s.cols[col])) { /* a residual on the joined row */
                bq->np = np;
                x->fb[i] = true;
                imdb_err_clear(e);
                rc = IMDB_OK;
            }
        }
    }
    xscope sc = {.st = st, .s = &j->ct->s, .jt = t, .nc0 = j->nc[0], .cols = true, .group_col = -1};
    if (!rc && bind_resid(x, &sc, j->resid, &j->nresid, e)) rc = e->code;
    if (!rc) {
        choose_ordered(&q[0], -1);
        choose_ordered(&q[1], -1);
    }
    /* the hash join building side 1, or plan C (join_choose; only under access_path auto: a forced
     * path is every table read's) */
    jplan p = {JP_HASH, 1, {-1, -1}};
    jprice jpr;
    memset(&jpr, 0, sizeof jpr);
    int jp = x->ss->join_plan;
    if (!rc && !below_floor(x->db, &q[0]) && /* below the memory floor: the hash join over the lake (stage 3b) */
        (jp == IMDB_JOIN_INDEX || (jp == IMDB_JOIN_AUTO && x->ss->access_path == IMDB_PATH_AUTO)))
        p = join_choose(j, q, jp == IMDB_JOIN_INDEX, &jpr);
    char n1[28]; /* the longest name: join(build 1; store, store) */
    join_plan_name(&p, n1, sizeof n1);
    if (xp) { /* P1 Q1: the plan, not run */
        if (!rc) rc = xp_join(x, st, j, q, &p, &jpr, n1, xp, e);
        join_free(j);
        imdb_free(j->ct);
        imdb_free(j);
        return rc;
    }
    if (!rc) rc = join_run(x, st, j, q, &p, r, e);
    if (!rc) {
        snprintf(r->path, sizeof r->path, "%s", n1);
        r->snap = snap;
        r->has_snap = true;
        r->snap_own = pend != 0;
        rc = read_point(x, r, e);
    }
    if (!rc && x->ss->cross_check) {
        /* the hash join building side 0, each side read by scan, or by store where the first plan
         * read it by scan: no read path or lookup in common with the first plan */
        jplan m = {JP_HASH, 0, {0, 0}};
        for (int s = 0; s < 2; s++) /* below the memory floor the scan's twin is the lake row by row (stage 3b) */
            m.path[s] = below_floor(x->db, &q[s]) ? IMDB_PATH_ROWS : j->ran[s] == IMDB_PATH_SCAN ? IMDB_PATH_STORE : IMDB_PATH_SCAN;
        char n2[28];
        join_plan_name(&m, n2, sizeof n2);
        imdb_result r2;
        imdb_result_init(&r2);
        r2.byte_cap = r->byte_cap;
        uint64_t first = x->tested; /* the second plan counts from zero (xtested) */
        x->tested = 0;
        rc = join_run(x, st, j, q, &m, &r2, e);
        x->tested = first;
        if (!rc && !results_equal(r, &r2))
            rc = imdb_fail(e, IMDB_ERR_VERIFY, "cross-check FAILED: %s returned %llu rows, %s returned %llu rows (or values differ)",
                           n1, (unsigned long long)r->nrows, n2, (unsigned long long)r2.nrows);
        imdb_result_free(&r2);
        if (!rc) {
            x->ss->cross_checks_run++;
            snprintf(r->path, sizeof r->path, "%s = %s (cross-checked)", n1, n2);
        }
    }
    join_free(j);
    imdb_free(j->ct);
    imdb_free(j);
    return rc;
}

static int exec_select(xctx *x, const sql_stmt *st, imdb_result *r, xplain *xp, imdb_err *e)
{
    if (st->has_join) return exec_join(x, st, r, xp, e);
    imdb_table *t;
    if (read_table(x, st, st->table, &t, e)) return e->code;
    qspec q;
    memset(&q, 0, sizeof q);
    q.t = t;
    if (resolve_snapshot(x, st, t, &q.snap, &q.pend, e) || bind_preds(x, st, &q, e)) return e->code;
    sink k;
    int rc = plan_select(x, st, t, &k, e);
    if (!rc) q.ord_only = ordered_only(&q, &k);
    int p1 = rc ? IMDB_PATH_SCAN : choose_path(x->ss, &q, &k); /* the sink's kind is part of the cost */
    if (xp) { /* P1 Q1: the plan, not run */
        if (!rc) xp_single(x, st, &q, &k, p1, xp);
        sink_free(&k);
        return rc;
    }
    if (!rc) rc = run_path(x, p1, &q, &k, e);
    if (!rc && st->for_update && x->ss->txn.open) rc = lock_rows(x, t, &k, e);
    if (!rc) rc = sink_pin(&k);
    if (!rc) rc = materialize(x, st, t, &k, r, e);
    sink_free(&k);
    if (rc) return rc;
    snprintf(r->path, sizeof r->path, "%s", path_name(p1, &q));
    r->snap = q.snap;
    r->has_snap = true;
    r->snap_own = q.pend != 0;
    if ((rc = read_point(x, r, e))) return rc;
    if (!x->ss->cross_check) return IMDB_OK;
    /* the same query along a different path must give the identical result; a scan the cost rule
     * chose over an index is checked against that index */
    int p2 = below_floor(x->db, &q)              ? IMDB_PATH_ROWS /* the lake alone answers it (stage 3b) */
             : p1 != IMDB_PATH_SCAN               ? IMDB_PATH_SCAN
             : q.pk_pred >= 0 || q.subj_pred >= 0 ? IMDB_PATH_INDEX
             : q.ord_pred >= 0                    ? IMDB_PATH_ORDERED
                                                  : IMDB_PATH_STORE;
    imdb_result r2;
    imdb_result_init(&r2);
    uint64_t first = x->tested; /* the second plan counts from zero (xtested) */
    x->tested = 0;
    rc = plan_select(x, st, t, &k, e);
    if (!rc) rc = run_path(x, p2, &q, &k, e);
    if (!rc) rc = sink_pin(&k);
    if (!rc) rc = materialize(x, st, t, &k, &r2, e);
    sink_free(&k);
    x->tested = first;
    if (!rc && !results_equal(r, &r2))
        rc = imdb_fail(e, IMDB_ERR_VERIFY, "cross-check FAILED: %s returned %llu rows, %s returned %llu rows (or values differ)",
                       path_name(p1, &q), (unsigned long long)r->nrows, path_name(p2, &q), (unsigned long long)r2.nrows);
    imdb_result_free(&r2);
    if (rc) return rc;
    x->ss->cross_checks_run++;
    snprintf(r->path, sizeof r->path, "%s = %s (cross-checked)", path_name(p1, &q), path_name(p2, &q));
    return IMDB_OK;
}

/* Matching versions for DML/ERASE, sorted by vid, cross-checked when enabled. */
static int select_vids(xctx *x, const sql_stmt *st, imdb_table *t, bool all_versions, uint64_t **out, uint64_t *n,
                       xplain *xp, imdb_err *e)
{
    qspec q;
    memset(&q, 0, sizeof q);
    q.t = t;
    read_view(x, &q.snap, &q.pend);
    q.all_versions = all_versions;
    /* a transaction's snapshot may be old: below the purge horizon the rows to change are unknown */
    if (!all_versions && check_view(x, t, q.snap, false, e)) return e->code;
    if (bind_preds(x, st, &q, e)) return e->code;
    sink k;
    memset(&k, 0, sizeof k);
    k.mode = SINK_VIDS;
    k.x = x;
    k.st = st;
    k.t = t;
    k.e = e;
    xscope sc = {.st = st, .s = &t->s, .t = t, .cols = true, .group_col = -1};
    if (bind_resid(x, &sc, k.resid, &k.nresid, e)) return e->code;
    int p1 = choose_path(x->ss, &q, &k);
    if (xp) { /* P1 Q1: the plan, not run */
        xp_single(x, st, &q, &k, p1, xp);
        sink_free(&k);
        *out = NULL;
        *n = 0;
        return IMDB_OK;
    }
    int rc = run_path(x, p1, &q, &k, e);
    if (rc) {
        sink_free(&k);
        return rc;
    }
    if (k.nvids) qsort(k.vids, k.nvids, sizeof *k.vids, cmp_u64);
    if (x->ss->cross_check) {
        sink k2;
        memset(&k2, 0, sizeof k2);
        k2.mode = SINK_VIDS;
        k2.x = x;
        k2.st = st;
        k2.t = t;
        k2.e = e;
        memcpy(k2.resid, k.resid, sizeof k.resid);
        k2.nresid = k.nresid;
        int p2 = below_floor(x->db, &q) ? IMDB_PATH_ROWS : p1 == IMDB_PATH_SCAN ? IMDB_PATH_STORE : IMDB_PATH_SCAN;
        uint64_t first = x->tested; /* the second plan counts from zero (xtested) */
        x->tested = 0;
        rc = run_path(x, p2, &q, &k2, e);
        x->tested = first;
        if (!rc && k2.nvids) qsort(k2.vids, k2.nvids, sizeof *k2.vids, cmp_u64);
        if (!rc && (k.nvids != k2.nvids || (k.nvids && memcmp(k.vids, k2.vids, k.nvids * sizeof *k.vids) != 0)))
            rc = imdb_fail(e, IMDB_ERR_VERIFY, "cross-check FAILED selecting rows to change: %s and %s disagree",
                           path_name(p1, &q), path_name(p2, &q));
        sink_free(&k2);
        if (rc) {
            sink_free(&k);
            return rc;
        }
        x->ss->cross_checks_run++;
        snprintf(x->vpath, sizeof x->vpath, "%s = %s (cross-checked)", path_name(p1, &q), path_name(p2, &q));
    }
    if (!x->ss->cross_check) snprintf(x->vpath, sizeof x->vpath, "%s", path_name(p1, &q)); /* P1 Q1: the result's */
    *out = k.vids;
    *n = k.nvids;
    return IMDB_OK;
}

/* ---- DML ---------------------------------------------------------------------------- */

static int exec_insert(xctx *x, const sql_stmt *st, imdb_result *r, imdb_err *e)
{
    imdb_table *t = imdb_table_by_name(x->db, st->table);
    if (!t) return imdb_fail(e, IMDB_ERR_NOTFOUND, "no table %s", st->table);
    int map[IMDB_MAX_COLS];
    uint16_t width = st->ncols ? st->ncols : t->s.ncols;
    if (st->rowlen != width)
        return imdb_fail(e, IMDB_ERR_INVALID, "INSERT supplies %u values per row, table %s needs %u", st->rowlen,
                         t->s.name, width);
    imdb_value vals[IMDB_MAX_COLS];
    if (st->ncols) {
        bool seen[IMDB_MAX_COLS] = {false};
        for (uint16_t i = 0; i < st->ncols; i++) {
            int c = imdb_schema_col(&t->s, st->cols[i]);
            if (c < 0) return imdb_fail(e, IMDB_ERR_NOTFOUND, "no column %s in table %s", st->cols[i], t->s.name);
            if (seen[c]) return imdb_fail(e, IMDB_ERR_INVALID, "column %s listed twice", st->cols[i]);
            seen[c] = true;
            map[i] = c;
        }
        for (uint16_t c = 0; c < t->s.ncols; c++) { /* a column left out is NULL */
            if (seen[c]) continue;
            if (!(t->s.cols[c].flags & IMDB_COL_NULLABLE))
                return imdb_fail(e, IMDB_ERR_CONSTRAINT, "column %s needs a value: it is NOT NULL", t->s.cols[c].name);
            vals[c] = (imdb_value){.type = t->s.cols[c].type, .scale = t->s.cols[c].scale, .null = true};
        }
    } else {
        for (uint16_t i = 0; i < width; i++) map[i] = i;
    }
    for (uint32_t row = 0; row < st->nrows; row++) {
        for (uint16_t i = 0; i < width; i++) {
            const imdb_column *c = &t->s.cols[map[i]];
            imdb_err e2 = {0};
            if (bind_lit(x, &st->vals[(size_t)row * width + i], c, false, &vals[map[i]], &e2))
                return imdb_fail(e, e2.code, "row %u: %s", row + 1, e2.msg);
        }
        imdb_err e2 = {0};
        uint8_t salt[16];
        int irc = imdb_salt_next(&x->salts, salt, &e2) || imdb_insert_salt(x->db, t, vals, salt, &e2);
        imdb_wipe(salt, sizeof salt);
        if (irc) return imdb_fail(e, e2.code, "row %u: %s", row + 1, e2.msg);
    }
    snprintf(r->status, sizeof r->status, "INSERT %u", st->nrows);
    return IMDB_OK;
}

static int exec_update(xctx *x, const sql_stmt *st, imdb_result *r, xplain *xp, imdb_err *e)
{
    imdb_table *t = imdb_table_by_name(x->db, st->table);
    if (!t) return imdb_fail(e, IMDB_ERR_NOTFOUND, "no table %s", st->table);
    int cols[IMDB_MAX_COLS];
    imdb_value newv[IMDB_MAX_COLS];
    bool trees = false;
    xscope sc = {.st = st, .s = &t->s, .t = t, .cols = true, .group_col = -1};
    for (uint16_t i = 0; i < st->nset; i++) {
        cols[i] = imdb_schema_col(&t->s, st->set_cols[i]);
        if (cols[i] < 0) return imdb_fail(e, IMDB_ERR_NOTFOUND, "no column %s in table %s", st->set_cols[i], t->s.name);
        if (cols[i] == t->s.pk) return imdb_fail(e, IMDB_ERR_INVALID, "UPDATE cannot change the primary key (use DELETE + INSERT)");
        for (uint16_t j = 0; j < i; j++)
            if (cols[j] == cols[i]) return imdb_fail(e, IMDB_ERR_INVALID, "column %s is set twice", st->set_cols[i]);
        if (st->set_vals[i].kind == LIT_EXPR) { /* computed per row, from the row's old values */
            if (xnodes(x, st, e) || xbind(x, &sc, st->set_vals[i].ex, e)) return e->code;
            trees = true;
        } else if (bind_lit(x, &st->set_vals[i], &t->s.cols[cols[i]], false, &newv[i], e)) {
            return e->code;
        }
    }
    uint64_t *vids, n;
    if (select_vids(x, st, t, false, &vids, &n, xp, e)) return e->code;
    if (xp) return IMDB_OK; /* P1 Q1: the plan, not run */
    int rc = IMDB_OK;
    imdb_value vals[IMDB_MAX_COLS];
    for (uint64_t i = 0; i < n && !rc; i++) {
        if ((rc = xtick(x, 64, e)) || (rc = fetch_row(x, t, vids[i], vals, e))) break; /* a write weighs more than a read */
        for (uint16_t c = 0; c < t->s.ncols && !rc; c++) rc = xpin(x, &vals[c], e);
        for (uint16_t k = 0; k < st->nset && trees && !rc; k++) { /* every tree before any column changes: SET a = b,
                                                                    * b = a swaps them */
            imdb_xval v;
            if (st->set_vals[k].kind != LIT_EXPR) continue;
            if ((rc = imdb_x_eval(st, x->xn, st->set_vals[k].ex, vals, NULL, &v, e))) break;
            rc = imdb_x_assign(&t->s.cols[cols[k]], &v, &newv[k], e);
        }
        if (rc) break;
        for (uint16_t k = 0; k < st->nset; k++) vals[cols[k]] = newv[k];
        uint8_t salt[16];
        if (!rc && !(rc = imdb_salt_next(&x->salts, salt, e))) rc = imdb_update_salt(x->db, t, vids[i], vals, salt, e);
        imdb_wipe(salt, sizeof salt);
    }
    imdb_free(vids);
    if (!rc) snprintf(r->status, sizeof r->status, "UPDATE %llu", (unsigned long long)n);
    if (!rc) snprintf(r->path, sizeof r->path, "%s", x->vpath); /* P1 Q1: how the rows were found */
    return rc;
}

static int exec_delete(xctx *x, const sql_stmt *st, imdb_result *r, xplain *xp, imdb_err *e)
{
    imdb_table *t = imdb_table_by_name(x->db, st->table);
    if (!t) return imdb_fail(e, IMDB_ERR_NOTFOUND, "no table %s", st->table);
    uint64_t *vids, n;
    if (select_vids(x, st, t, false, &vids, &n, xp, e)) return e->code;
    if (xp) return IMDB_OK; /* P1 Q1: the plan, not run */
    int rc = IMDB_OK;
    for (uint64_t i = 0; i < n && !rc; i++)
        if (!(rc = xtick(x, 64, e))) rc = imdb_delete(x->db, t, vids[i], e);
    imdb_free(vids);
    if (!rc) snprintf(r->status, sizeof r->status, "DELETE %llu", (unsigned long long)n);
    if (!rc) snprintf(r->path, sizeof r->path, "%s", x->vpath); /* P1 Q1: how the rows were found */
    return rc;
}

/* EXPLAIN (P1 Q1): the explained statement's own executor, stopped at its plan (xp), then the plan's rows */
static int exec_explain(xctx *x, const sql_stmt *st, imdb_result *r, imdb_err *e)
{
    xplain *xp = imdb_alloc(sizeof *xp, e);
    if (!xp) return e->code;
    int rc = st->explained == ST_SELECT   ? exec_select(x, st, r, xp, e)
             : st->explained == ST_UPDATE ? exec_update(x, st, r, xp, e)
                                          : exec_delete(x, st, r, xp, e);
    if (!rc) {
        res_cols(r, 2);
        res_name(r, 0, "item");
        res_name(r, 1, "detail");
        for (uint16_t i = 0; i < xp->n && !rc; i++) {
            imdb_cell *row = res_row(r, e);
            if (!row) {
                rc = e->code;
                break;
            }
            res_put_str(r, &row[0], xp->item[i]);
            res_put_str(r, &row[1], xp->detail[i]);
        }
        if (!rc) rc = res_finish(r, e);
    }
    imdb_free(xp);
    return rc;
}


static void erase_status(imdb_result *r, const imdb_erase_report *er, const imdb_db *db)
{
    snprintf(r->status, sizeof r->status,
             "ERASE %llu versions (%llu were live) in %u tables at commit %llu; %u lake segments rewritten; %s",
             (unsigned long long)er->versions, (unsigned long long)er->live_deleted, er->tables,
             (unsigned long long)db->seq, er->segments_rewritten,
             er->redaction_pending ? "committed; physical cleanup pending, see warning"
                                   : "payloads removed from log, lake and memory here (SHOW ERASURE: elsewhere)");
}

/* ---- admin ------------------------------------------------------------------------- */

/* a retention as SQL writes it: its largest whole unit, or FOREVER */
static void retention_text(uint64_t us, char *out, size_t n)
{
    static const struct {
        uint64_t us;
        const char *one, *many;
    } u[] = {{86400ull * 1000000, "DAY", "DAYS"}, {3600ull * 1000000, "HOUR", "HOURS"},
             {60ull * 1000000, "MINUTE", "MINUTES"}, {1000000ull, "SECOND", "SECONDS"}};
    if (us == IMDB_RETAIN_FOREVER) {
        snprintf(out, n, "FOREVER");
        return;
    }
    for (size_t i = 0; i < sizeof u / sizeof *u; i++)
        if (us % u[i].us == 0) {
            snprintf(out, n, "%llu %s", (unsigned long long)(us / u[i].us), us / u[i].us == 1 ? u[i].one : u[i].many);
            return;
        }
    snprintf(out, n, "%llu MICROSECONDS", (unsigned long long)us); /* the C API takes any count above a second */
}

typedef struct stat_rows {
    imdb_result *r;
    imdb_err *e;
} stat_rows;

static int stat_row(void *ctx, const char *name, int64_t v) /* SHOW STATS: a row of imdb_stats_each's */
{
    stat_rows *s = ctx;
    imdb_cell *row = res_row(s->r, s->e);
    if (!row) return s->e->code;
    res_put_str(s->r, &row[0], name);
    res_put_int(s->r, &row[1], v);
    return 0;
}

static int exec_show(xctx *x, const sql_stmt *st, imdb_result *r, imdb_err *e)
{
    imdb_db *db = x->db;
    char hex[65];
    if (st->kind == ST_SHOW_RETENTION) {
        res_cols(r, 3);
        const char *nm[] = {"table", "retention", "history_from"};
        for (int i = 0; i < 3; i++) res_name(r, (uint16_t)i, nm[i]);
        for (uint32_t i = 0; i < db->nt; i++) {
            const imdb_table *t = db->t[i];
            char ret[48];
            retention_text(t->retention_us, ret, sizeof ret);
            imdb_cell *row = res_row(r, e);
            if (!row) return e->code;
            res_put_str(r, &row[0], t->s.name);
            res_put_str(r, &row[1], ret);
            res_put_int(r, &row[2], (int64_t)t->horizon);
        }
        return res_finish(r, e);
    }
    if (st->kind == ST_SHOW_INDEXES) {
        res_cols(r, 4);
        const char *nm[] = {"index", "table", "columns", "unique"};
        for (int i = 0; i < 4; i++) res_name(r, (uint16_t)i, nm[i]);
        for (uint32_t i = 0; i < db->nt; i++) /* a dropped table's indexes are gone with its name (1f) */
            for (uint32_t k = 0; !db->t[i]->dropped_at && k < db->t[i]->nidx; k++) {
                const imdb_table *t = db->t[i];
                const imdb_index_def *d = &t->idx[k].d;
                char cols[IMDB_MAX_INDEX_COLS * (IMDB_MAX_IDENT + 2)];
                size_t at = 0;
                for (uint8_t c = 0; c < d->ncols; c++)
                    at += (size_t)snprintf(cols + at, sizeof cols - at, "%s%s", c ? ", " : "", t->s.cols[d->cols[c]].name);
                imdb_cell *row = res_row(r, e);
                if (!row) return e->code;
                res_put_str(r, &row[0], d->name);
                res_put_str(r, &row[1], t->s.name);
                res_put_str(r, &row[2], cols);
                res_put_str(r, &row[3], d->flags & IMDB_INDEX_UNIQUE ? "yes" : "no");
            }
        snprintf(r->status, sizeof r->status, "%llu indexes", (unsigned long long)r->nrows);
        return res_finish(r, e); /* TEXT cells hold offsets until then */
    }
    if (st->kind == ST_SHOW_TABLES) {
        res_cols(r, 7); /* dropped_at (1f): the commit that dropped it, NULL while it lives; AS OF before it still reads it */
        const char *nm[] = {"table", "columns", "live_rows", "versions", "segments", "history_from", "dropped_at"};
        for (int i = 0; i < 7; i++) res_name(r, (uint16_t)i, nm[i]);
        for (uint32_t i = 0; i < db->nt; i++) {
            imdb_table *t = db->t[i];
            imdb_cell *row = res_row(r, e);
            if (!row) return e->code;
            imdb_buf cols;
            imdb_buf_init(&cols);
            for (int c = 0; c < t->s.ncols; c++) {
                const imdb_column *cd = &t->s.cols[c];
                imdb_buf_printf(&cols, "%s%s %s", c ? ", " : "", cd->name, imdb_type_name(cd->type));
                if (cd->type == IMDB_T_DECIMAL) imdb_buf_printf(&cols, "(%u,%u)", cd->precision, cd->scale);
                if (cd->flags & IMDB_COL_PK) imdb_buf_put_str(&cols, " PK");
                if (cd->flags & IMDB_COL_SUBJECT) imdb_buf_put_str(&cols, " SUBJECT");
            }
            imdb_buf_put_u8(&cols, 0);
            if (imdb_buf_check(&cols, e)) {
                imdb_buf_free(&cols);
                return e->code;
            }
            res_put_str(r, &row[0], t->s.name);
            res_put_str(r, &row[1], cols.p ? (const char *)cols.p : "");
            imdb_buf_free(&cols);
            res_put_int(r, &row[2], (int64_t)t->live);
            res_put_int(r, &row[3], (int64_t)t->nver);
            res_put_int(r, &row[4], (int64_t)t->nseg);
            res_put_int(r, &row[5], (int64_t)t->horizon);
            imdb_value dv = {.type = IMDB_T_INT64, .i = (int64_t)t->dropped_at, .null = !t->dropped_at};
            res_put(r, &row[6], &dv);
        }
        return res_finish(r, e);
    }
    if (st->kind == ST_SHOW_IDENTITY) { /* the database's latest state, with the view token */
        static const char *const nm[] = {"db_id", "commit", "head", "digest", "lake_commit", "lake_manifest", "view_token"};
        res_cols(r, 7);
        for (int i = 0; i < 7; i++) res_name(r, (uint16_t)i, nm[i]);
        imdb_cell *row = res_row(r, e);
        if (!row) return e->code;
        uint8_t d[32], tok[32];
        char h[65];
        if (imdb_view_token(db, tok, e)) return e->code;
        imdb_hex(db->db_id, 16, h);
        res_put_str(r, &row[0], h);
        res_put_int(r, &row[1], (int64_t)db->seq);
        imdb_hex(db->head, 32, h);
        res_put_str(r, &row[2], h);
        imdb_state_digest(db, NULL, d);
        imdb_hex(d, 32, h);
        res_put_str(r, &row[3], h);
        res_put_int(r, &row[4], (int64_t)db->lake_seq);
        imdb_hex(db->lake_manifest, 32, h);
        res_put_str(r, &row[5], db->lake_seq ? h : "");
        imdb_hex(tok, 32, h);
        res_put_str(r, &row[6], h);
        return res_finish(r, e);
    }
    if (st->kind == ST_SHOW_STATS) { /* P1 M1: what this copy has done since its open: imdb_stats_each's rows (db.c) */
        res_cols(r, 2);
        res_name(r, 0, "name");
        res_name(r, 1, "value");
        stat_rows sr = {r, e};
        int rc = imdb_stats_each(db, stat_row, &sr, true);
        if (rc) return rc;
        snprintf(r->status, sizeof r->status, "since the open; process.* counts every database this process opened");
        return res_finish(r, e);
    }
    if (st->kind == ST_SHOW_TRANSACTIONS) { /* P1 M1: this copy's open transactions, every session's (db->txns) */
        uint64_t now = mono_ns();
        uint32_t n = 0;
        static const char *const names[7] = {"state", "isolation", "age_ms", "idle_ms", "writes", "locks", "mine"};
        res_cols(r, 7);
        for (int i = 0; i < 7; i++) res_name(r, i, names[i]);
        for (const imdb_txn *t = db->txns; t; t = t->next) {
            if (!t->open) continue;
            imdb_cell *row = res_row(r, e);
            if (!row) return e->code;
            n++;
            res_put_str(r, &row[0], t->doomed ? "doomed" : db->active == t ? "active" : t->started ? "parked" : "begun");
            res_put_str(r, &row[1], t->iso == IMDB_ISO_READ_COMMITTED ? "read committed" : "snapshot");
            res_put_int(r, &row[2], (int64_t)((now - t->begin_ns) / 1000000u));
            res_put_int(r, &row[3], (int64_t)((now - t->last_ns) / 1000000u));
            res_put_int(r, &row[4], (int64_t)(db->active == t ? db->ntx : t->nops));
            res_put_int(r, &row[5], (int64_t)t->nlocks);
            res_put_int(r, &row[6], t == &x->ss->txn ? 1 : 0);
        }
        snprintf(r->status, sizeof r->status, "%u open", n);
        return res_finish(r, e);
    }
    if (st->kind == ST_SHOW_MEMORY) { /* what the database holds, by kind, against its budget (db.h) */
        imdb_mem_report m;
        imdb_mem(db, &m);
        const char *kinds[] = {"versions", "rows", "indexes", "segments", "commits", "transactions", "total"};
        const uint64_t v[] = {m.versions, m.rows, m.indexes, m.segments, m.commits, m.txns, m.total};
        res_cols(r, 2);
        res_name(r, 0, "kind");
        res_name(r, 1, "bytes");
        for (int i = 0; i < 7; i++) {
            imdb_cell *row = res_row(r, e);
            if (!row) return e->code;
            res_put_str(r, &row[0], kinds[i]);
            res_put_int(r, &row[1], (int64_t)v[i]);
        }
        if (m.limit && m.reserve) /* D8 #2: writes leave a query's share of the budget free */
            snprintf(r->status, sizeof r->status, "%llu bytes held, budget %llu, %llu of it kept for queries%s",
                     (unsigned long long)m.total, (unsigned long long)m.limit, (unsigned long long)m.reserve,
                     m.total + m.reserve > m.limit ? ": writes that grow are refused" : "");
        else if (m.limit)
            snprintf(r->status, sizeof r->status, "%llu bytes held, budget %llu%s", (unsigned long long)m.total,
                     (unsigned long long)m.limit, m.total > m.limit ? ": over it, writes that grow are refused" : "");
        else snprintf(r->status, sizeof r->status, "%llu bytes held, no budget", (unsigned long long)m.total);
        uint64_t held = 0, kept = 0; /* stage 3b: the versions in memory, and those every table keeps (the lake's too) */
        for (uint32_t i = 0; i < db->nt; i++) {
            const imdb_table *t = db->t[i];
            held += t->nheld;
            kept += t->nver - t->mem_first;
            for (uint32_t k = 0; k < t->nseg; k++) kept += t->seg[k]->nrows;
        }
        size_t at = strlen(r->status);
        if (db->mem_window_us == UINT64_MAX)
            snprintf(r->status + at, sizeof r->status - at, "; no memory window: %llu versions held",
                     (unsigned long long)held);
        else
            snprintf(r->status + at, sizeof r->status - at, "; memory window %llu s, floor commit %llu: %llu versions held of %llu",
                     (unsigned long long)(db->mem_window_us / 1000000), (unsigned long long)db->mem_floor,
                     (unsigned long long)held, (unsigned long long)kept);
        at = strlen(r->status); /* stage 3c-1: the lake's images in memory, and those read again since the open */
        if (m.seg_budget == UINT64_MAX)
            snprintf(r->status + at, sizeof r->status - at, "; segment images %llu bytes, every one kept",
                     (unsigned long long)m.seg_images);
        else
            snprintf(r->status + at, sizeof r->status - at, "; segment images %llu bytes, budget %llu",
                     (unsigned long long)m.seg_images, (unsigned long long)m.seg_budget);
        at = strlen(r->status);
        snprintf(r->status + at, sizeof r->status - at, "; %llu loaded since the open (%llu bytes read)",
                 (unsigned long long)m.seg_loads, (unsigned long long)m.seg_load_bytes);
        return res_finish(r, e);
    }
    if (st->kind == ST_SHOW_REPLICATION) { /* the session's last commit: what is known beyond this database */
        static const char *const kn[] = {"local only", "confirmed", "unknown", "not checked"};
        const imdb_repl_outcome *o = &x->ss->last_repl;
        res_cols(r, 5);
        res_name(r, 0, "commit");
        res_name(r, 1, "sync_replicas");
        res_name(r, 2, "confirmed");
        res_name(r, 3, "waited_ms");
        res_name(r, 4, "outcome");
        if (o->seq) {
            imdb_cell *row = res_row(r, e);
            if (!row) return e->code;
            res_put_int(r, &row[0], (int64_t)o->seq);
            res_put_int(r, &row[1], o->wanted);
            res_put_int(r, &row[2], o->confirmed);
            res_put_int(r, &row[3], o->waited_ms);
            res_put_str(r, &row[4], kn[o->kind]);
        }
        snprintf(r->status, sizeof r->status, "%s", o->seq ? "durable here in every case; outcome: what the replicas "
                                                             "acknowledged" : "no commit in this session yet");
        return res_finish(r, e);
    }
    if (st->kind == ST_SHOW_ERASURE) { /* the review's completion states, kept apart (repl.h: what each claim is) */
        uint64_t at = st->n ? st->n : db->seq;
        if (at > db->seq)
            return imdb_fail(e, IMDB_ERR_INVALID, "commit %llu is past this database's last (%llu)", (unsigned long long)at,
                             (unsigned long long)db->seq);
        imdb_replica_status *v = NULL;
        size_t n = 0;
        if (!db->replica && imdb_replicas_status(db, &v, &n, e)) return e->code;
        res_cols(r, 4);
        res_name(r, 0, "scope");
        res_name(r, 1, "state");
        res_name(r, 2, "through_commit");
        res_name(r, 3, "detail");
        imdb_cell *row = res_row(r, e);
        if (!row) {
            imdb_free(v);
            return e->code;
        }
        char d[256];
        uint64_t mine = imdb_cleanup_seq(db);
        snprintf(d, sizeof d, "%s%s%s%s%s", mine >= at ? "no file of this directory holds what an ERASE removed" : "pending:",
                 mine < at && db->needs_redaction ? " the log's redaction" : "",
                 mine < at && (db->lake_pending || db->lake_unverified) ? " the lake's rewrite" : "",
                 mine < at && db->gc_pending ? " removing old lake objects" : "",
                 mine < at && db->failed ? " (the handle failed: reopen)" : "");
        res_put_str(r, &row[0], "this database");
        res_put_str(r, &row[1], mine >= at ? "complete" : "pending");
        res_put_int(r, &row[2], (int64_t)mine);
        res_put_str(r, &row[3], d);
        uint32_t done = 0;
        for (size_t i = 0; i < n; i++) {
            const imdb_replica_status *s = &v[i];
            if (!(row = res_row(r, e))) {
                imdb_free(v);
                return e->code;
            }
            char sc[64], sess[17];
            snprintf(sc, sizeof sc, "replica %s", s->who.name);
            imdb_hex(s->ack.nonce, 8, sess);
            const char *state = "unknown";
            bool usable = s->acked && !s->incident && s->state == IMDB_REPL_SAME_HISTORY;
            if (!usable)
                snprintf(d, sizeof d, "%s", s->incident ? "refused: see SHOW REPLICAS"
                                            : s->state == IMDB_REPL_RETIRED ? "behind the retired log: seed it again"
                                            : s->acked ? "its acknowledgement is not of this history"
                                                       : "no acknowledgement received");
            else {
                state = s->ack.cleanup >= at ? "reported complete" : s->ack.seq >= at ? "reported pending" : "not reached";
                snprintf(d, sizeof d, "as it reported %lld ms ago (session %s), at commit %llu; not its state now", (long long)s->age_ms,
                         sess, (unsigned long long)s->ack.seq);
                done += s->ack.cleanup >= at;
            }
            res_put_str(r, &row[0], sc);
            res_put_str(r, &row[1], state);
            res_put_int(r, &row[2], usable ? (int64_t)s->ack.cleanup : -1);
            res_put_str(r, &row[3], d);
        }
        imdb_free(v);
        static const char *const out[][3] = {
            {"backups and copies", "not tracked", "copies made outside imagedb (backups, file system snapshots, a replica "
                                                  "restored from one) may hold the bytes"},
            {"freed disk blocks", "not guaranteed", "the file system and the device may keep freed blocks until they are "
                                                    "overwritten (crypto-shredding: deferred.md R6)"}};
        for (int i = 0; i < 2; i++) {
            if (!(row = res_row(r, e))) return e->code;
            res_put_str(r, &row[0], out[i][0]);
            res_put_str(r, &row[1], out[i][1]);
            res_put_int(r, &row[2], -1);
            res_put_str(r, &row[3], out[i][2]);
        }
        snprintf(r->status, sizeof r->status, "erasure through commit %llu: %s here; %u of %zu replicas report it complete; "
                 "backups and freed blocks are not covered", (unsigned long long)at, mine >= at ? "complete" : "pending",
                 done, n);
        return res_finish(r, e);
    }
    if (st->kind == ST_SHOW_REPLICAS) { /* each allowlisted replica's latest acknowledgement, against this history */
        /* received_utc and age_ms say when: an acknowledgement is what the replica held then (repl.h) */
        static const char *const nm[] = {"replica", "key",          "commit", "epoch",   "lag",
                                         "cleanup_commit", "received_utc", "age_ms", "session", "state"};
        static const char *const sn[] = {"no acknowledgement", "same history", "diverged", "ahead of this log",
                                         "behind the retired log: seed it again"};
        enum { NCOL = sizeof nm / sizeof *nm };
        imdb_replica_status *v;
        size_t n;
        if (imdb_replicas_status(db, &v, &n, e)) return e->code;
        res_cols(r, NCOL);
        for (int i = 0; i < NCOL; i++) res_name(r, (uint16_t)i, nm[i]);
        for (size_t i = 0; i < n; i++) {
            imdb_cell *row = res_row(r, e);
            if (!row) {
                imdb_free(v);
                return e->code;
            }
            imdb_replica_status *s = &v[i];
            char k[17], sess[17], state[128];
            imdb_hex(s->who.pub, 8, k);
            imdb_hex(s->ack.nonce, 8, sess);
            if (s->incident && s->why == IMDB_REFUSED_BACK)
                snprintf(state, sizeof state, "refused: went back to commit %llu after %llu (restored? re-enrol it with a "
                         "new key)", (unsigned long long)s->refused.seq, (unsigned long long)s->earlier);
            else if (s->incident && s->why != IMDB_REFUSED_UNKNOWN)
                snprintf(state, sizeof state, s->why == IMDB_REFUSED_AHEAD ? "refused: ahead of this log at commit %llu"
                                                                           : "refused: another history at commit %llu",
                         (unsigned long long)s->refused.seq);
            else if (s->incident) snprintf(state, sizeof state, "refused (its incident record cannot be read)");
            else snprintf(state, sizeof state, "%s", sn[s->state]);
            res_put_str(r, &row[0], s->who.name);
            res_put_str(r, &row[1], k);
            res_put_int(r, &row[2], s->acked ? (int64_t)s->ack.seq : -1);
            res_put_int(r, &row[3], s->acked ? (int64_t)s->ack.epoch : -1);
            res_put_int(r, &row[4], s->acked && s->ack.seq <= db->seq ? (int64_t)(db->seq - s->ack.seq) : -1);
            res_put_int(r, &row[5], s->acked ? (int64_t)s->ack.cleanup : -1);
            imdb_value tv = {.type = IMDB_T_TIMESTAMP, .i = s->received_ms * 1000};
            if (s->acked) res_put(r, &row[6], &tv);
            else {
                row[6].v.type = IMDB_T_TIMESTAMP;
                row[6].null = true;
            }
            res_put_int(r, &row[7], s->age_ms);
            res_put_str(r, &row[8], s->acked ? sess : "");
            res_put_str(r, &row[9], state);
        }
        imdb_free(v);
        snprintf(r->status, sizeof r->status, "%zu replicas allowlisted; this primary at commit %llu", n,
                 (unsigned long long)db->seq);
        return res_finish(r, e);
    }
    if (st->kind == ST_SHOW_LOG) {
        res_cols(r, 3);
        res_name(r, 0, "commit");
        res_name(r, 1, "time_utc");
        res_name(r, 2, "hash");
        uint64_t from = db->seq > st->n ? db->seq - st->n + 1 : 1;
        for (uint64_t s = from; s <= db->seq; s++) {
            const imdb_commit_info *ci = imdb_ci_at(db, s, e);
            if (!ci) return e->code;
            imdb_cell *row = res_row(r, e);
            if (!row) return e->code;
            res_put_int(r, &row[0], (int64_t)s);
            imdb_value tv = {.type = IMDB_T_TIMESTAMP, .i = (int64_t)ci->time_us};
            res_put(r, &row[1], &tv);
            imdb_hex(ci->hash, 32, hex);
            res_put_str(r, &row[2], hex);
        }
        return res_finish(r, e);
    }
    if (st->kind == ST_SHOW_LAKE) {
        res_cols(r, 5);
        const char *nm[] = {"table", "segments", "rows_in_segments", "memtable_rows", "manifest"};
        for (int i = 0; i < 5; i++) res_name(r, (uint16_t)i, nm[i]);
        imdb_hex(db->lake_manifest, 32, hex);
        for (uint32_t i = 0; i < db->nt; i++) {
            imdb_table *t = db->t[i];
            uint64_t rows = 0;
            for (uint32_t k = 0; k < t->nseg; k++) rows += t->seg[k]->nrows;
            imdb_cell *row = res_row(r, e);
            if (!row) return e->code;
            res_put_str(r, &row[0], t->s.name);
            res_put_int(r, &row[1], (int64_t)t->nseg);
            res_put_int(r, &row[2], (int64_t)rows);
            res_put_int(r, &row[3], (int64_t)(t->nver - t->mem_first));
            res_put_str(r, &row[4], db->lake_seq ? hex : "(none)");
        }
        snprintf(r->status, sizeof r->status, "lake snapshot at commit %llu", (unsigned long long)db->lake_seq);
        return res_finish(r, e);
    }
    if (st->kind == ST_SHOW_HISTORY) {
        imdb_table *t;
        if (read_table(x, st, st->table, &t, e)) return e->code;
        imdb_value key;
        if (bind_lit(x, &st->key, &t->s.cols[t->s.pk], true, &key, e)) return e->code;
        res_cols(r, (uint16_t)(3 + t->s.ncols));
        res_name(r, 0, "_version");
        res_name(r, 1, "_from_commit");
        res_name(r, 2, "_until_commit");
        for (int c = 0; c < t->s.ncols; c++) res_name(r, (uint16_t)(3 + c), t->s.cols[c].name);
        /* the key's chain (the versions held), and its rows only the lake holds (stage 3b: past the memory window) */
        uint64_t *head = imdb_hmap_get(&t->pk, &key);
        uint64_t nch = 0;
        for (int pass = 0; pass < 2; pass++) {
            uint64_t *chain = pass ? xalloc(x, nch * sizeof *chain, e) : NULL, n = 0;
            if (pass && !chain) return e->code;
            for (uint64_t vid = head ? *head : IMDB_NONE; vid != IMDB_NONE; vid = imdb_vh(t, vid)->pk_prev, n++)
                if (pass) chain[n] = vid;
            for (uint32_t s = 0; s < t->nseg; s++) {
                imdb_segment *g = t->seg[s];
                const imdb_segimg *gi = imdb_seg_pin(t, g, e);
                if (!gi) return e->code;
                for (uint32_t i = 0; i < g->nrows; i++) {
                    imdb_value v;
                    if (gi->flags[i] || imdb_v_held(t, gi->vid[i])) continue;
                    imdb_seg_get(&t->s, gi, i, (uint32_t)t->s.pk, &v);
                    if (imdb_value_cmp(&v, &key) == 0 && pass) chain[n] = gi->vid[i];
                    n += imdb_value_cmp(&v, &key) == 0;
                }
            }
            if (!pass) {
                nch = n;
                continue;
            }
            qsort(chain, nch, sizeof *chain, cmp_u64); /* oldest first: vids are handed out in order */
            imdb_value vals[IMDB_MAX_COLS];
            for (uint64_t i = 0; i < nch; i++) {
                imdb_vloc at;
                int where = imdb_v_find(t, chain[i], &at, e);
                if (where < 0) return where;
                const imdb_segimg *gi = where == IMDB_VAT_LAKE ? imdb_seg_pin(t, at.g, e) : NULL;
                if (where == IMDB_VAT_LAKE && !gi) return e->code;
                if (where == IMDB_VAT_HELD && (at.v->flags & IMDB_V_PURGED)) continue;
                uint64_t begin = where == IMDB_VAT_HELD ? at.v->begin : gi->begin[at.row];
                uint64_t end = where == IMDB_VAT_HELD ? at.v->end : gi->end[at.row];
                if (fetch_row(x, t, chain[i], vals, e)) return e->code;
                imdb_cell *row = res_row(r, e);
                if (!row) return e->code;
                res_put_int(r, &row[0], (int64_t)chain[i]);
                res_put_int(r, &row[1], (int64_t)begin);
                if (end == IMDB_LIVE) res_put_str(r, &row[2], "live");
                else res_put_int(r, &row[2], (int64_t)end);
                for (int c = 0; c < t->s.ncols; c++) res_put(r, &row[3 + c], &vals[c]);
            }
        }
        return res_finish(r, e);
    }
    /* SHOW DIGEST */
    if (!st->table[0]) {
        res_cols(r, 4);
        res_name(r, 0, "scope");
        res_name(r, 1, "live_rows");
        res_name(r, 2, "at_commit");
        res_name(r, 3, "lthash_digest");
        uint64_t total = 0;
        for (uint32_t i = 0; i < db->nt; i++) {
            imdb_cell *row = res_row(r, e);
            if (!row) return e->code;
            uint8_t d[32];
            imdb_state_digest(db, db->t[i], d);
            imdb_hex(d, 32, hex);
            res_put_str(r, &row[0], db->t[i]->s.name);
            res_put_int(r, &row[1], (int64_t)db->t[i]->live);
            res_put_int(r, &row[2], (int64_t)db->seq);
            res_put_str(r, &row[3], hex);
            total += db->t[i]->live;
        }
        imdb_cell *row = res_row(r, e);
        if (!row) return e->code;
        uint8_t d[32];
        imdb_state_digest(db, NULL, d);
        imdb_hex(d, 32, hex);
        res_put_str(r, &row[0], "(database)");
        res_put_int(r, &row[1], (int64_t)total);
        res_put_int(r, &row[2], (int64_t)db->seq);
        res_put_str(r, &row[3], hex);
        return res_finish(r, e);
    }
    imdb_table *t;
    if (read_table(x, st, st->table, &t, e)) return e->code;
    qspec q;
    memset(&q, 0, sizeof q);
    q.t = t;
    if (resolve_snapshot(x, st, t, &q.snap, &q.pend, e)) return e->code;
    q.pk_pred = q.subj_pred = -1;
    if (st->has_subject) {
        if (t->s.subject < 0) return imdb_fail(e, IMDB_ERR_INVALID, "table %s has no SUBJECT column", t->s.name);
        bpred *b = &q.p[q.np++];
        memset(b, 0, sizeof *b);
        b->col = (uint16_t)t->s.subject;
        b->type = t->s.cols[t->s.subject].type;
        b->op = CMP_EQ;
        if (bind_lit(x, &st->subject, &t->s.cols[t->s.subject], true, &b->a, e)) return e->code;
        b->lo = b->hi = b->a.i;
        q.subj_pred = 0;
    }
    /* the digest of the same rows along two independent paths */
    sink k1, k2;
    memset(&k1, 0, sizeof k1);
    memset(&k2, 0, sizeof k2);
    k1.mode = k2.mode = SINK_DIGEST;
    k1.t = k2.t = t;
    k1.e = k2.e = e;
    k1.x = k2.x = x;
    imdb_lthash_zero(&k1.digest);
    imdb_lthash_zero(&k2.digest);
    int pa = below_floor(x->db, &q) ? IMDB_PATH_ROWS : st->has_subject ? IMDB_PATH_INDEX : IMDB_PATH_STORE;
    if (run_path(x, pa, &q, &k1, e) || run_path(x, IMDB_PATH_SCAN, &q, &k2, e)) return e->code;
    res_cols(r, 5);
    res_name(r, 0, "path");
    res_name(r, 1, "rows");
    res_name(r, 2, "at_commit");
    res_name(r, 3, "lthash_digest");
    res_name(r, 4, "equal");
    bool eq = memcmp(&k1.digest, &k2.digest, sizeof k1.digest) == 0 && k1.digest_rows == k2.digest_rows;
    for (int i = 0; i < 2; i++) {
        sink *k = i ? &k2 : &k1;
        imdb_cell *row = res_row(r, e);
        if (!row) return e->code;
        uint8_t d[32];
        imdb_lthash_digest(x->db->meta.digest_alg, &k->digest, d);
        imdb_hex(d, 32, hex);
        res_put_str(r, &row[0], i ? "scan (lake segments)" : pa == IMDB_PATH_ROWS ? "rows (lake segments)" : st->has_subject ? "index (subject)" : "store");
        res_put_int(r, &row[1], (int64_t)k->digest_rows);
        res_put_int(r, &row[2], (int64_t)q.snap);
        res_put_str(r, &row[3], hex);
        res_put_str(r, &row[4], eq ? "yes" : "NO");
    }
    if (!eq) return imdb_fail(e, IMDB_ERR_VERIFY, "digest cross-check FAILED: index and scan paths disagree");
    return res_finish(r, e);
}

static int exec_verify(xctx *x, imdb_result *r, imdb_err *e)
{
    imdb_verify_report vr;
    if (imdb_verify(x->db, &vr, e)) return e->code;
    char hex[65];
    imdb_hex(vr.digest, 32, hex);
    snprintf(r->status, sizeof r->status,
             "VERIFY ok: %llu commits (chain + %llu signatures), %llu payloads re-hashed, %llu versions (%llu live, %llu erased), "
             "%llu lake segments / %llu rows re-derived from files; digest %.16s%s%s",
             (unsigned long long)vr.commits, (unsigned long long)vr.sigs_checked, (unsigned long long)vr.payload_rows_checked,
             (unsigned long long)vr.versions, (unsigned long long)vr.live, (unsigned long long)vr.stubs,
             (unsigned long long)vr.segments_checked, (unsigned long long)vr.lake_rows_checked, hex,
             vr.note[0] ? "; " : "", vr.note);
    return IMDB_OK;
}

/* ---- statement dispatch --------------------------------------------------------------- */

/* SERIALIZABLE needs read-set validation, which stage 1 does not have: refused, not weakened. */
static int check_iso(const sql_stmt *st, imdb_err *e)
{
    if (st->iso != SQL_ISO_SERIALIZABLE) return IMDB_OK;
    return imdb_fail(e, IMDB_ERR_UNSUPPORTED,
                     "SERIALIZABLE is not available yet: SNAPSHOT (the default) prevents dirty and non-repeatable "
                     "reads, phantoms and lost updates, but not write skew");
}

static bool is_write(uint8_t k)
{
    return k == ST_CREATE || k == ST_INSERT || k == ST_UPDATE || k == ST_DELETE || k == ST_CREATE_INDEX ||
           k == ST_DROP_INDEX || k == ST_ALTER_RETENTION || k == ST_DROP_TABLE;
}

/* A read statement's workspace (P0 R2): what SET statement_memory says, else a quarter of the memory budget, at most
 * IMDB_MAX_RESULT_BYTES (the result cap before R2, which this replaces: the result is part of the workspace) */
/* P1 M1: a statement's class in SHOW STATS */
static const char *const stmt_class_name[IMDB_SC_N] = {"read", "write", "transaction", "ddl", "physical", "show", "other"};

static int stmt_class(int kind)
{
    switch (kind) {
    case ST_SELECT: return IMDB_SC_READ;
    case ST_INSERT: case ST_UPDATE: case ST_DELETE: return IMDB_SC_WRITE;
    case ST_BEGIN: case ST_COMMIT: case ST_ROLLBACK: case ST_SAVEPOINT: case ST_ROLLBACK_TO: case ST_RELEASE:
    case ST_SET_TXN: return IMDB_SC_TXN;
    case ST_CREATE: case ST_CREATE_INDEX: case ST_DROP_INDEX: case ST_DROP_TABLE: case ST_ALTER_RETENTION:
        return IMDB_SC_DDL;
    case ST_CHECKPOINT: case ST_COMPACT: case ST_ERASE_SUBJECT: case ST_ERASE_WHERE: case ST_VERIFY: return IMDB_SC_PHYSICAL;
    case ST_SHOW_TABLES: case ST_SHOW_DIGEST: case ST_SHOW_HISTORY: case ST_SHOW_LOG: case ST_SHOW_LAKE:
    case ST_SHOW_IDENTITY: case ST_SHOW_REPLICAS: case ST_SHOW_REPLICATION: case ST_SHOW_ERASURE: case ST_SHOW_MEMORY:
    case ST_SHOW_INDEXES: case ST_SHOW_RETENTION: case ST_SHOW_STATS: case ST_SHOW_TRANSACTIONS: case ST_EXPLAIN:
        return IMDB_SC_SHOW;
    default: return IMDB_SC_OTHER;
    }
}

static uint64_t workspace_of(const imdb_session *ss)
{
    if (ss->stmt_memory) return ss->stmt_memory;
    return imdb_query_share(ss->db->mem_limit); /* D8 #2: the share the budget keeps from writes (db.h) */
}

static int exec_one_body(imdb_session *ss, const char *sql, size_t len, const imdb_value *params, uint32_t nparams,
                  imdb_result *r, imdb_err *e)
{
    imdb_result_init(r);
    r->byte_cap = workspace_of(ss);
    sql_stmt *st = imdb_alloc(sizeof *st, e);
    if (!st) return e->code;
    int rc = imdb_sql_parse(sql, len, st, e);
    if (rc) {
        imdb_free(st);
        return rc;
    }
    if (nparams > IMDB_MAX_PARAMS) {
        imdb_sql_stmt_free(st);
        imdb_free(st);
        return imdb_fail(e, IMDB_ERR_LIMIT, "too many parameters");
    }
    xctx x = {.ss = ss, .db = ss->db, .sql = sql, .params = params, .nparams = nparams, .st = st, .row_limit = ss->row_limit};
    imdb_db *db = ss->db;
    uint64_t seq_before = db->seq;
    if (db->failed) {
        /* in-memory state may be half-installed: no answers until reopen + replay */
        imdb_sql_stmt_free(st);
        imdb_free(st);
        imdb_stats_tick(db, !db->stats_said_failed); /* P1 M1: a monitor learns the handle failed */
        imdb_event_failed(db, db->warning); /* P1 M2: the failure's event, if no statement logged it */
        return imdb_fail(e, IMDB_ERR_STATE, "database is in a failed state; reopen it to recover");
    }
    if ((db->pending_auth || db->lake_unverified) && st->kind != ST_VERIFY) {
        imdb_sql_stmt_free(st);
        imdb_free(st);
        return imdb_fail(e, IMDB_ERR_STATE,
                         "replica has unauthorised redactions or an unverified lake; resume apply before querying");
    }
    /* read-your-writes across copies: a session that needs commit N refuses one not there yet */
    bool reads = st->kind == ST_SELECT || st->kind == ST_SHOW_DIGEST || st->kind == ST_SHOW_HISTORY || st->kind == ST_SHOW_IDENTITY ||
                 (st->kind == ST_EXPLAIN && st->explained == ST_SELECT); /* a plan of what that read would see */
    if (reads && ss->min_commit > db->seq) {
        rc = imdb_fail(e, IMDB_ERR_STATE, "this database is at commit %llu; the session requires commit %llu (SET min_commit)",
                       (unsigned long long)db->seq, (unsigned long long)ss->min_commit);
        imdb_sql_stmt_free(st);
        imdb_free(st);
        return rc;
    }
    bool autocommit = false, txn = ss->txn.open, ceiling = false; /* ceiling: R2's, below */
    /* R4: a transaction past its SET transaction_timeout, or idle past its SET idle_in_transaction_timeout, can only
     * roll back: this statement fails (cancelled) unless it is the ROLLBACK, and what the transaction holds goes now;
     * every other session's transaction past its limits, active or parked, goes the same way, whether or not its session
     * ever comes back (imdb_txn_expire) */
    uint64_t now_ns = mono_ns();
    if (txn && st->kind != ST_ROLLBACK && !ss->txn.doomed) {
        char why[200];
        if (imdb_txn_expired(&ss->txn, now_ns, why, sizeof why)) {
            imdb_txn_expire(db, &ss->txn, why);
            bool ends = st->kind == ST_COMMIT; /* a COMMIT ends it either way, as a doomed COMMIT does */
            if (ends) imdb_txn_rollback(db, &ss->txn);
            imdb_sql_stmt_free(st);
            imdb_free(st);
            if (ends) return imdb_fail(e, IMDB_ERR_CANCELLED, "%s; the transaction rolled back", why);
            return imdb_fail(e, IMDB_ERR_CANCELLED, "%s; roll back", why);
        }
    }
    imdb_txn_timeouts(db, now_ns, &ss->txn);
    db->stmt_start_ns = now_ns; /* P1 M1: long-running work, as the export shows it */
    imdb_stats_tick(db, false);
    imdb_savepoint sp = {0, 0};
    bool physical = st->kind == ST_CHECKPOINT || st->kind == ST_COMPACT || st->kind == ST_ERASE_SUBJECT ||
                    st->kind == ST_ERASE_WHERE || st->kind == ST_VERIFY;
    bool control = st->kind == ST_BEGIN || st->kind == ST_COMMIT || st->kind == ST_ROLLBACK || st->kind == ST_SET ||
                   st->kind == ST_EMPTY || st->kind == ST_SAVEPOINT || st->kind == ST_ROLLBACK_TO ||
                   st->kind == ST_RELEASE || st->kind == ST_SET_TXN;
    /* R1: a cancel asked for before this statement is dropped; what runs to its end (COMMIT, the statements that commit
     * on their own, the physical ones) is never checked, so neither a cancel nor the deadline cuts a logged op part
     * way */
    atomic_store_explicit(&ss->cancel, false, memory_order_relaxed);
    x.checks = !physical && st->kind != ST_COMMIT && st->kind != ST_CREATE && st->kind != ST_CREATE_INDEX &&
               st->kind != ST_DROP_INDEX && st->kind != ST_ALTER_RETENTION && st->kind != ST_DROP_TABLE; /* each commits on
                                                                                                       * its own */
    x.next_check = TICK_ROWS;
    if (x.checks && ss->stmt_timeout_ms) x.deadline_ns = mono_ns() + (uint64_t)ss->stmt_timeout_ms * 1000000u;
    if (txn && (st->kind == ST_CREATE || st->kind == ST_CREATE_INDEX || st->kind == ST_DROP_INDEX ||
                st->kind == ST_ALTER_RETENTION || st->kind == ST_DROP_TABLE)) {
        rc = imdb_fail(e, IMDB_ERR_STATE, "%s commits on its own: run it outside the transaction",
                       st->kind == ST_CREATE         ? "CREATE TABLE"
                       : st->kind == ST_CREATE_INDEX ? "CREATE INDEX"
                       : st->kind == ST_DROP_INDEX   ? "DROP INDEX"
                       : st->kind == ST_DROP_TABLE   ? "DROP TABLE"
                                                     : "ALTER TABLE");
        goto done;
    }
    if (txn && physical) {
        rc = imdb_fail(e, IMDB_ERR_STATE, st->kind == ST_ERASE_SUBJECT || st->kind == ST_ERASE_WHERE
                                              ? "ERASE runs outside explicit transactions"
                                              : "CHECKPOINT, COMPACT and VERIFY run outside explicit transactions");
        goto done;
    }
    if (physical) { /* its own transaction, with nobody's pending writes in the store */
        if ((rc = imdb_txn_park(db, e))) goto done;
    } else if (txn && !control) {
        if ((rc = imdb_txn_enter(db, &ss->txn, is_write(st->kind) ? IMDB_TXN_WRITE : IMDB_TXN_READ, e))) goto done;
    } else if (!txn && is_write(st->kind)) {
        if ((rc = imdb_txn_park(db, e)) || (rc = imdb_begin(db, e))) goto done;
        autocommit = true;
    }
    if (is_write(st->kind)) sp = imdb_savepoint_take(db); /* after the swap-in: it indexes this op list */
    /* R2: a read statement's memory has a hard ceiling (util.h): set after the swap-in above (a parked transaction's
     * writes replayed are the store's, not this statement's), cleared at the switch's end and at done, before the
     * policies between transactions (expiry's commit, eviction's rebuild). Set once: an inner statement never moves
     * an outer one's base. */
    ceiling = !imdb_heap_ceiling() && (st->kind == ST_SELECT || st->kind == ST_SHOW_TABLES ||
                                           st->kind == ST_SHOW_DIGEST || st->kind == ST_SHOW_HISTORY ||
                                           st->kind == ST_SHOW_LOG || st->kind == ST_SHOW_LAKE ||
                                           st->kind == ST_SHOW_IDENTITY || st->kind == ST_SHOW_REPLICAS ||
                                           st->kind == ST_SHOW_REPLICATION || st->kind == ST_SHOW_ERASURE ||
                                           st->kind == ST_SHOW_MEMORY || st->kind == ST_SHOW_INDEXES ||
                                           st->kind == ST_SHOW_RETENTION || st->kind == ST_SHOW_STATS ||
                                           st->kind == ST_SHOW_TRANSACTIONS || st->kind == ST_EXPLAIN);
    if (ceiling) imdb_heap_ceiling_set(imdb_heap_bytes() + workspace_of(ss), workspace_of(ss));
    switch (st->kind) {
    case ST_EMPTY: break;
    case ST_CREATE:
        rc = imdb_create_table_ex(db, &st->schema, st->has_retention ? st->retention_us : IMDB_RETAIN_DEFAULT_US, e);
        if (!rc) snprintf(r->status, sizeof r->status, "CREATE TABLE %s", st->schema.name);
        break;
    case ST_ALTER_RETENTION: {
        imdb_table *t = imdb_table_by_name(db, st->table);
        rc = t ? imdb_set_retention(db, t, st->retention_us, e) : imdb_fail(e, IMDB_ERR_INVALID, "no table %s", st->table);
        if (!rc) snprintf(r->status, sizeof r->status, "ALTER TABLE %s", st->table);
        break;
    }
    case ST_CREATE_INDEX: {
        imdb_table *t = imdb_table_by_name(db, st->table);
        imdb_index_def d;
        memset(&d, 0, sizeof d);
        snprintf(d.name, sizeof d.name, "%s", st->index_name);
        d.flags = st->index_unique ? IMDB_INDEX_UNIQUE : 0;
        d.ncols = st->index_ncols;
        if (!t) rc = imdb_fail(e, IMDB_ERR_INVALID, "no table %s", st->table);
        for (uint8_t c = 0; !rc && c < d.ncols; c++) {
            int col = imdb_schema_col(&t->s, st->index_cols[c]);
            if (col < 0) rc = imdb_fail(e, IMDB_ERR_INVALID, "table %s has no column %s", st->table, st->index_cols[c]);
            else d.cols[c] = (uint16_t)col;
        }
        if (!rc) rc = imdb_create_index(db, t, &d, e);
        if (!rc) snprintf(r->status, sizeof r->status, "CREATE %sINDEX %s", st->index_unique ? "UNIQUE " : "", st->index_name);
        break;
    }
    case ST_DROP_TABLE: { /* 1f: its history kept for its retention (RETENTION here sets one first) */
        imdb_table *t = imdb_table_by_name(db, st->table);
        rc = t ? imdb_drop_table(db, t, st->has_retention ? st->retention_us : 0, e)
               : imdb_fail(e, IMDB_ERR_NOTFOUND, "no table %s", st->table);
        if (!rc) snprintf(r->status, sizeof r->status, "DROP TABLE %s", st->table);
        break;
    }
    case ST_DROP_INDEX:
        rc = imdb_drop_index(db, st->index_name, e);
        if (!rc) snprintf(r->status, sizeof r->status, "DROP INDEX %s", st->index_name);
        break;
    case ST_INSERT: rc = exec_insert(&x, st, r, e); break;
    case ST_UPDATE: rc = exec_update(&x, st, r, NULL, e); break;
    case ST_DELETE: rc = exec_delete(&x, st, r, NULL, e); break;
    case ST_SELECT: rc = exec_select(&x, st, r, NULL, e); break;
    case ST_EXPLAIN: rc = exec_explain(&x, st, r, e); break;
    case ST_BEGIN:
        if (txn) {
            rc = imdb_fail(e, IMDB_ERR_STATE, "transaction already open");
            break;
        }
        if ((rc = check_iso(st, e))) break;
        imdb_txn_begin(db, &ss->txn, st->iso == SQL_ISO_READ_COMMITTED ? IMDB_ISO_READ_COMMITTED : IMDB_ISO_SNAPSHOT);
        ss->txn.begin_ns = ss->txn.last_ns = now_ns; /* R4 */
        ss->txn.timeout_ms = ss->txn_timeout_ms;
        ss->txn.idle_ms = ss->idle_timeout_ms;
        snprintf(r->status, sizeof r->status, "BEGIN");
        break;
    case ST_SET_TXN:
        if (!txn || ss->txn.started) {
            rc = imdb_fail(e, IMDB_ERR_STATE, "SET TRANSACTION goes right after BEGIN, before the first statement");
            break;
        }
        if ((rc = check_iso(st, e))) break;
        ss->txn.iso = st->iso == SQL_ISO_READ_COMMITTED ? IMDB_ISO_READ_COMMITTED : IMDB_ISO_SNAPSHOT;
        snprintf(r->status, sizeof r->status, "SET TRANSACTION");
        break;
    case ST_SAVEPOINT:
    case ST_ROLLBACK_TO:
    case ST_RELEASE:
        if (!txn) {
            rc = imdb_fail(e, IMDB_ERR_STATE, "savepoints need a transaction (BEGIN)");
            break;
        }
        rc = st->kind == ST_SAVEPOINT     ? imdb_txn_savepoint(db, &ss->txn, st->savepoint, e)
             : st->kind == ST_ROLLBACK_TO ? imdb_txn_rollback_to(db, &ss->txn, st->savepoint, e)
                                          : imdb_txn_release(db, &ss->txn, st->savepoint, e);
        if (!rc)
            snprintf(r->status, sizeof r->status, "%s",
                     st->kind == ST_SAVEPOINT ? "SAVEPOINT" : st->kind == ST_ROLLBACK_TO ? "ROLLBACK" : "RELEASE");
        break;
    case ST_COMMIT:
        if (!txn) {
            rc = imdb_fail(e, IMDB_ERR_STATE, "no transaction is open");
            break;
        }
        rc = imdb_txn_commit(db, &ss->txn, e);
        if (!rc) snprintf(r->status, sizeof r->status, "COMMIT (commit %llu)", (unsigned long long)db->seq);
        break;
    case ST_ROLLBACK:
        if (!txn) {
            rc = imdb_fail(e, IMDB_ERR_STATE, "no transaction is open");
            break;
        }
        imdb_txn_rollback(db, &ss->txn);
        snprintf(r->status, sizeof r->status, "ROLLBACK");
        break;
    case ST_CHECKPOINT: {
        uint64_t before = db->seq;
        rc = imdb_checkpoint(db, e);
        if (!rc) {
            char hex[65];
            imdb_hex(db->lake_manifest, 32, hex);
            if (db->seq == before)
                snprintf(r->status, sizeof r->status, "CHECKPOINT: lake already current (commit %llu)",
                         (unsigned long long)db->lake_seq);
            else if (db->failed || db->lake_pending)
                snprintf(r->status, sizeof r->status,
                         "CHECKPOINT: lake snapshot at commit %llu committed; publication pending, see warning",
                         (unsigned long long)db->lake_seq);
            else
                snprintf(r->status, sizeof r->status, "CHECKPOINT: lake snapshot at commit %llu, manifest %.16s%s",
                         (unsigned long long)db->lake_seq, hex,
                         db->gc_pending ? "; old objects not yet removed, see warning" : "");
        }
        break;
    }
    case ST_COMPACT: {
        imdb_table *t = imdb_table_by_name(db, st->table);
        if (!t) {
            rc = imdb_fail(e, IMDB_ERR_NOTFOUND, "no table %s", st->table);
            break;
        }
        rc = imdb_compact(db, t, st->has_purge ? st->purge_before : 0, e);
        if (!rc && db->failed)
            snprintf(r->status, sizeof r->status, "COMPACT %s committed at %llu; publication pending, reopen to recover",
                     t->s.name, (unsigned long long)db->seq);
        else if (!rc)
            snprintf(r->status, sizeof r->status, "COMPACT %s: %u segment(s); history available from commit %llu",
                     t->s.name, t->nseg, (unsigned long long)t->horizon);
        break;
    }
    case ST_ERASE_SUBJECT: {
        imdb_value v;
        memset(&v, 0, sizeof v);
        if (st->subject.kind == LIT_INT) {
            imdb_column c = {.type = IMDB_T_INT64};
            strcpy(c.name, "subject");
            rc = bind_lit(&x, &st->subject, &c, true, &v, e);
        } else if (st->subject.kind == LIT_STR || st->subject.kind == LIT_PARAM) {
            imdb_column c = {.type = st->subject.kind == LIT_STR ? IMDB_T_TEXT : (uint8_t)(params && st->subject.param <= nparams ? params[st->subject.param - 1].type : IMDB_T_TEXT)};
            strcpy(c.name, "subject");
            rc = bind_lit(&x, &st->subject, &c, true, &v, e);
        } else {
            rc = imdb_fail(e, IMDB_ERR_INVALID, "ERASE SUBJECT takes an integer or a string");
        }
        imdb_erase_report er;
        if (!rc) rc = imdb_erase_subject(db, &v, &er, e);
        if (!rc) erase_status(r, &er, db);
        break;
    }
    case ST_ERASE_WHERE: {
        imdb_table *t = imdb_table_by_name(db, st->table);
        if (!t) {
            rc = imdb_fail(e, IMDB_ERR_NOTFOUND, "no table %s", st->table);
            break;
        }
        uint64_t *vids, n;
        if ((rc = select_vids(&x, st, t, true, &vids, &n, NULL, e))) break;
        imdb_erase_ent *ents = n ? imdb_alloc_array(n, sizeof *ents, e) : NULL;
        if (n && !ents) {
            imdb_free(vids);
            rc = e->code;
            break;
        }
        for (uint64_t i = 0; i < n; i++) {
            ents[i].table = t->s.id;
            ents[i].vid = vids[i];
        }
        imdb_free(vids);
        imdb_erase_report er;
        rc = imdb_erase_versions(db, ents, (uint32_t)n, &er, e);
        if (!rc) erase_status(r, &er, db);
        break;
    }
    case ST_VERIFY: rc = exec_verify(&x, r, e); break;
    case ST_SHOW_TABLES:
    case ST_SHOW_INDEXES:
    case ST_SHOW_RETENTION:
    case ST_SHOW_DIGEST:
    case ST_SHOW_HISTORY:
    case ST_SHOW_LOG:
    case ST_SHOW_LAKE:
    case ST_SHOW_IDENTITY:
    case ST_SHOW_REPLICAS:
    case ST_SHOW_REPLICATION:
    case ST_SHOW_ERASURE:
    case ST_SHOW_MEMORY:
    case ST_SHOW_STATS:
    case ST_SHOW_TRANSACTIONS: rc = exec_show(&x, st, r, e); break;
    case ST_SET:
        if (strcmp(st->set_name, "cross_check") == 0) {
            if (strcmp(st->set_value, "on") == 0 || strcmp(st->set_value, "1") == 0 || strcmp(st->set_value, "true") == 0) ss->cross_check = true;
            else if (strcmp(st->set_value, "off") == 0 || strcmp(st->set_value, "0") == 0 || strcmp(st->set_value, "false") == 0) ss->cross_check = false;
            else rc = imdb_fail(e, IMDB_ERR_INVALID, "cross_check is on or off");
        } else if (strcmp(st->set_name, "access_path") == 0) {
            if (strcmp(st->set_value, "auto") == 0) ss->access_path = IMDB_PATH_AUTO;
            else if (strcmp(st->set_value, "index") == 0) ss->access_path = IMDB_PATH_INDEX;
            else if (strcmp(st->set_value, "scan") == 0) ss->access_path = IMDB_PATH_SCAN;
            else if (strcmp(st->set_value, "store") == 0) ss->access_path = IMDB_PATH_STORE;
            else if (strcmp(st->set_value, "ordered") == 0) ss->access_path = IMDB_PATH_ORDERED;
            else rc = imdb_fail(e, IMDB_ERR_INVALID, "access_path is auto, index, scan, store or ordered");
        } else if (strcmp(st->set_name, "join_plan") == 0) {
            if (strcmp(st->set_value, "auto") == 0) ss->join_plan = IMDB_JOIN_AUTO;
            else if (strcmp(st->set_value, "hash") == 0) ss->join_plan = IMDB_JOIN_HASH;
            else if (strcmp(st->set_value, "index") == 0) ss->join_plan = IMDB_JOIN_INDEX;
            else rc = imdb_fail(e, IMDB_ERR_INVALID, "join_plan is auto, hash or index");
        } else if (strcmp(st->set_name, "identity") == 0) {
            if (strcmp(st->set_value, "on") == 0 || strcmp(st->set_value, "1") == 0 || strcmp(st->set_value, "true") == 0) ss->show_identity = true;
            else if (strcmp(st->set_value, "off") == 0 || strcmp(st->set_value, "0") == 0 || strcmp(st->set_value, "false") == 0) ss->show_identity = false;
            else rc = imdb_fail(e, IMDB_ERR_INVALID, "identity is on or off");
        } else if (strcmp(st->set_name, "sync_replicas") == 0 || strcmp(st->set_name, "sync_timeout_ms") == 0) {
            bool k = strcmp(st->set_name, "sync_replicas") == 0;
            int64_t v;
            imdb_err ep = {0}; /* the range is the message, whatever the literal was */
            if (db->replica) rc = imdb_fail(e, IMDB_ERR_STATE, "%s is a primary's setting", st->set_name);
            else if (imdb_parse_int64(st->set_value, strlen(st->set_value), &v, &ep) || v < (k ? 0 : 1) ||
                     v > (k ? IMDB_MAX_SYNC_REPLICAS : IMDB_MAX_SYNC_TIMEOUT_MS))
                rc = imdb_fail(e, IMDB_ERR_INVALID, k ? "sync_replicas is 0 to %u" : "sync_timeout_ms is 1 to %u",
                               k ? IMDB_MAX_SYNC_REPLICAS : IMDB_MAX_SYNC_TIMEOUT_MS);
            else if (k) ss->sync_replicas = (uint32_t)v;
            else ss->sync_wait_ms = (uint32_t)v;
        } else if (strcmp(st->set_name, "statement_memory") == 0) { /* R2: bytes; 0: the default */
            int64_t v;
            imdb_err ep = {0}; /* the range is the message, whatever the literal was */
            if (imdb_parse_int64(st->set_value, strlen(st->set_value), &v, &ep) || v < 0 ||
                (v && ((uint64_t)v < IMDB_MIN_STATEMENT_MEMORY || (uint64_t)v > IMDB_MAX_STATEMENT_MEMORY)))
                rc = imdb_fail(e, IMDB_ERR_INVALID, "statement_memory is 0 (the default) or %llu to %llu bytes",
                               (unsigned long long)IMDB_MIN_STATEMENT_MEMORY, (unsigned long long)IMDB_MAX_STATEMENT_MEMORY);
            else ss->stmt_memory = (uint64_t)v;
        } else if (strcmp(st->set_name, "slow_statement_ms") == 0) { /* P1 M2: the event log's slow statements */
            int64_t v;
            imdb_err ep = {0};
            if (imdb_parse_int64(st->set_value, strlen(st->set_value), &v, &ep) || v < 0 || v > IMDB_MAX_STATEMENT_TIMEOUT_MS)
                rc = imdb_fail(e, IMDB_ERR_INVALID, "slow_statement_ms is 0 (none) to %u milliseconds", IMDB_MAX_STATEMENT_TIMEOUT_MS);
            else ss->slow_ms = (uint32_t)v;
        } else if (strcmp(st->set_name, "statement_row_limit") == 0) { /* D8 #4: rows tested; 0: none */
            int64_t v;
            imdb_err ep = {0};
            if (imdb_parse_int64(st->set_value, strlen(st->set_value), &v, &ep) || v < 0 || (uint64_t)v > IMDB_MAX_STATEMENT_ROW_LIMIT)
                rc = imdb_fail(e, IMDB_ERR_INVALID, "statement_row_limit is 0 (none) to %llu rows", (unsigned long long)IMDB_MAX_STATEMENT_ROW_LIMIT);
            else ss->row_limit = (uint64_t)v;
        } else if (strcmp(st->set_name, "transaction_timeout") == 0 || strcmp(st->set_name, "idle_in_transaction_timeout") == 0) {
            bool idle = st->set_name[0] == 'i'; /* R4: milliseconds; 0: none; at the next BEGIN */
            int64_t v;
            imdb_err ep = {0}; /* the range is the message, whatever the literal was */
            if (imdb_parse_int64(st->set_value, strlen(st->set_value), &v, &ep) || v < 0 || v > IMDB_MAX_STATEMENT_TIMEOUT_MS)
                rc = imdb_fail(e, IMDB_ERR_INVALID, "%s is 0 (none) to %u milliseconds", st->set_name, IMDB_MAX_STATEMENT_TIMEOUT_MS);
            else if (idle) ss->idle_timeout_ms = (uint32_t)v;
            else ss->txn_timeout_ms = (uint32_t)v;
        } else if (strcmp(st->set_name, "statement_timeout") == 0) { /* R1: milliseconds; 0: none */
            int64_t v;
            imdb_err ep = {0}; /* the range is the message, whatever the literal was */
            if (imdb_parse_int64(st->set_value, strlen(st->set_value), &v, &ep) || v < 0 || v > IMDB_MAX_STATEMENT_TIMEOUT_MS)
                rc = imdb_fail(e, IMDB_ERR_INVALID, "statement_timeout is 0 (none) to %u milliseconds",
                               IMDB_MAX_STATEMENT_TIMEOUT_MS);
            else ss->stmt_timeout_ms = (uint32_t)v;
        } else if (strcmp(st->set_name, "min_commit") == 0) {
            int64_t v;
            if (imdb_parse_int64(st->set_value, strlen(st->set_value), &v, e) || v < 0)
                rc = imdb_fail(e, IMDB_ERR_INVALID, "min_commit is a commit number (0: no requirement)");
            else ss->min_commit = (uint64_t)v;
        } else {
            rc = imdb_fail(e, IMDB_ERR_NOTFOUND, "unknown setting %s (cross_check, access_path, join_plan, identity, min_commit, idle_in_transaction_timeout, statement_memory, statement_row_limit, statement_timeout, slow_statement_ms, sync_replicas, transaction_timeout, sync_timeout_ms)",
                           st->set_name);
        }
        if (!rc) snprintf(r->status, sizeof r->status, "SET %s = %s", st->set_name, st->set_value);
        break;
    }
    if (ceiling) imdb_heap_ceiling_set(0, 0);
    if (is_write(st->kind)) {
        if (rc) {
            imdb_savepoint_restore(db, sp);
            if (autocommit) imdb_rollback(db);
            else if (rc == IMDB_ERR_CONFLICT) imdb_txn_doom(&ss->txn, e->msg); /* first committer won */
        } else if (autocommit) {
            rc = imdb_commit(db, e);
        }
    }
    if (ss->txn.open && ss->txn.doomed) imdb_txn_discard(db, &ss->txn); /* it can only roll back now */
    if (!db->in_txn && !db->active) imdb_maintain(db, e); /* between transactions only */
    if (!rc && db->seq > seq_before && !db->failed) {
        /* the commit is durable here whatever the replicas say: they change only what the caller is told */
        imdb_repl_outcome *o = &ss->last_repl;
        memset(o, 0, sizeof *o);
        o->seq = db->seq;
        o->wanted = ss->sync_replicas;
        if (ss->sync_replicas) {
            uint32_t got = 0, wait = ss->sync_wait_ms ? ss->sync_wait_ms : 10000;
            struct timespec t0, t1;
            clock_gettime(CLOCK_MONOTONIC, &t0);
            imdb_err ew = {0};
            int wrc = imdb_replicas_wait(db, db->seq, ss->sync_replicas, wait, &got, &ew);
            clock_gettime(CLOCK_MONOTONIC, &t1);
            o->confirmed = got;
            o->waited_ms = (uint32_t)((t1.tv_sec - t0.tv_sec) * 1000 + (t1.tv_nsec - t0.tv_nsec) / 1000000);
            o->kind = wrc ? IMDB_REPL_UNCHECKED : got < ss->sync_replicas ? IMDB_REPL_UNKNOWN : IMDB_REPL_CONFIRMED;
            if (wrc)
                imdb_warn(db, "commit %llu is durable here, but its replicas could not be checked: %s",
                          (unsigned long long)db->seq, ew.msg);
            else if (got < ss->sync_replicas)
                imdb_warn(db, "commit %llu is durable here, but only %u of %u replicas acknowledged it within %u ms",
                          (unsigned long long)db->seq, got, ss->sync_replicas, wait);
            size_t used = strlen(r->status);
            snprintf(r->status + used, sizeof r->status - used, "%scommit %llu %s %u of %u replicas", used ? "; " : "",
                     (unsigned long long)db->seq,
                     o->kind == IMDB_REPL_CONFIRMED ? "replicated: confirmed by"
                     : o->kind == IMDB_REPL_UNKNOWN ? "durable here; replication unknown: acknowledged by"
                                                    : "durable here; replication not checked:",
                     got, ss->sync_replicas);
        }
    }
done:
    { /* P1 M1: the statement's class, time and outcome (from the point it starts to run) */
        int k = stmt_class(st->kind);
        db->stats.stmts[k]++;
        imdb_hist_add(&db->stats.stmt_lat[k], (mono_ns() - now_ns) / 1000u);
        if (rc)
            db->stats.fails[rc == IMDB_ERR_CONFLICT ? IMDB_SF_CONFLICT : rc == IMDB_ERR_LIMIT ? IMDB_SF_LIMIT
                            : rc == IMDB_ERR_CANCELLED ? IMDB_SF_CANCELLED : IMDB_SF_OTHER]++;
    }
    ss->rows_tested = x.tested; /* D8 #4: the first plan's count, for the caller and the tests */
    if (ss->txn.open) ss->txn.last_ns = mono_ns(); /* R4: idle from here */
    if (ceiling) imdb_heap_ceiling_set(0, 0);
    { /* P1 M2: a slow statement (its shape: no row value) and the handle's failure, once, in the event log */
        uint64_t us = (mono_ns() - now_ns) / 1000u;
        if (ss->slow_ms && us >= (uint64_t)ss->slow_ms * 1000u && db->events_fd >= 0) {
            char shape[1024];
            imdb_sql_shape(sql, len, shape, sizeof shape);
            const char *cn = stmt_class_name[stmt_class(st->kind)];
            imdb_event_begin(db, "slow");
            imdb_event_str(db, "class", cn, strlen(cn));
            imdb_event_int(db, "ms", (int64_t)(us / 1000u));
            imdb_event_str(db, "path", r->path, strlen(r->path));
            imdb_event_int(db, "rows_tested", (int64_t)x.tested);
            imdb_event_int(db, "rc", rc);
            imdb_event_int(db, "cross_check", ss->cross_check ? 1 : 0); /* both plans' time when 1 */
            imdb_event_str(db, "shape", shape, strlen(shape));
            imdb_event_end(db);
        }
        if (db->failed) imdb_event_failed(db, rc ? e->msg : db->warning);
    }
    /* P1 M1: the end is exported at once when an export during the statement said it runs (else an idle copy would
     * show it running until its next statement), or when the handle failed and no export has said so yet */
    bool said_running = db->stmt_start_ns && db->stats_last_ns >= db->stmt_start_ns;
    db->stmt_start_ns = 0;
    imdb_stats_tick(db, said_running || (db->failed && !db->stats_said_failed));
    if (rc) imdb_result_free(r);
    xfree(&x);
    imdb_sql_stmt_free(st);
    imdb_free(st);
    return rc;
}

/* One operation (stage 3c-1): the segment cache trims when the outermost ends, so a statement's result holds no
 * pointer into a segment's image (res_put copies TEXT). */
int imdb_exec_one(imdb_session *ss, const char *sql, size_t len, const imdb_value *params, uint32_t nparams,
                  imdb_result *r, imdb_err *e)
{
    imdb_db *db = ss->db;
    imdb_op_enter(db);
    int rc = exec_one_body(ss, sql, len, params, nparams, r, e);
    imdb_op_leave(db);
    return rc;
}

int imdb_split_statements(const char *s, size_t n, imdb_stmt_cb cb, void *arg, imdb_err *e)
{
    size_t start = 0, i = 0;
    while (i < n) {
        char c = s[i];
        if (c == '\'') {
            i++;
            while (i < n) {
                if (s[i] == '\'') {
                    if (i + 1 < n && s[i + 1] == '\'') {
                        i += 2;
                        continue;
                    }
                    break;
                }
                i++;
            }
            if (i >= n) return imdb_fail(e, IMDB_ERR_SYNTAX, "unterminated string literal");
            i++;
            continue;
        }
        if (c == '-' && i + 1 < n && s[i + 1] == '-') {
            while (i < n && s[i] != '\n') i++;
            continue;
        }
        if (c == ';') {
            int rc = cb(arg, s + start, i + 1 - start);
            if (rc) return rc;
            start = i + 1;
        }
        i++;
    }
    bool blank = true;
    for (size_t k = start; k < n; k++)
        if (s[k] != ' ' && s[k] != '\n' && s[k] != '\t' && s[k] != '\r') blank = false;
    if (!blank) return cb(arg, s + start, n - start);
    return IMDB_OK;
}


/* The stream's form (the CLI's -f and piped input, read in chunks): the complete statements at the front of s, each
 * ending in a ';' outside a string literal and a comment, through cb; *used: the bytes they took, the rest being a
 * statement still arriving. A quote or a '-' at the very end stops it too: the next byte decides whether it is '' (a
 * quote inside the literal) or -- (a comment). At the end of the stream the rest goes to imdb_split_statements. */
int imdb_split_complete(const char *s, size_t n, imdb_stmt_cb cb, void *arg, size_t *used, imdb_err *e)
{
    size_t start = 0, i = 0;
    *used = 0;
    while (i < n) {
        char c = s[i];
        if (c == '\'') {
            i++;
            while (i < n) {
                if (s[i] == '\'') {
                    if (i + 1 == n) return IMDB_OK; /* '' or the end of the literal: the next chunk says */
                    if (s[i + 1] == '\'') {
                        i += 2;
                        continue;
                    }
                    break;
                }
                i++;
            }
            if (i >= n) return IMDB_OK; /* the literal goes on in the next chunk */
            i++;
            continue;
        }
        if (c == '-') {
            if (i + 1 == n) return IMDB_OK;
            if (s[i + 1] == '-') {
                while (i < n && s[i] != '\n') i++;
                if (i >= n) return IMDB_OK; /* the comment goes on in the next chunk */
                continue;
            }
        }
        if (c == ';') {
            int rc = cb(arg, s + start, i + 1 - start);
            if (rc) return rc;
            start = i + 1;
            *used = start;
        }
        i++;
    }
    (void)e;
    return IMDB_OK;
}

/* ---- rendering ---------------------------------------------------------------------- */

static void cell_text(const imdb_cell *c, imdb_buf *out, bool safe)
{
    if (c->null) {
        imdb_buf_put_str(out, "null");
        return;
    }
    if (c->wide) {
        imdb_format_i128(c->i128, c->v.type == IMDB_T_DECIMAL ? c->v.scale : 0, out);
        return;
    }
    if (safe) imdb_format_value_safe(&c->v, out);
    else imdb_format_value(&c->v, out);
}

/* Display width in code points (approximate for East Asian wide characters). */
static size_t disp_width(const uint8_t *p, size_t n)
{
    size_t w = 0;
    for (size_t i = 0; i < n; i++)
        if ((p[i] & 0xC0) != 0x80) w++;
    return w;
}

void imdb_result_render(const imdb_result *r, bool csv, imdb_buf *out)
{
    if (!r->has_rows) {
        if (r->status[0]) /* a write's path: how its rows were found (P1 Q1) */
            imdb_buf_printf(out, "%s%s%s%s\n", r->status, r->path[0] ? "  [" : "", r->path, r->path[0] ? "]" : "");
        return;
    }
    uint16_t nc = r->ncols;
    imdb_buf tmp;
    imdb_buf_init(&tmp);
    if (csv) {
        for (uint16_t c = 0; c < nc; c++) imdb_buf_printf(out, "%s%s", c ? "," : "", r->names[c]);
        imdb_buf_put_u8(out, '\n');
        for (uint64_t i = 0; i < r->nrows; i++) {
            for (uint16_t c = 0; c < nc; c++) {
                if (c) imdb_buf_put_u8(out, ',');
                if (r->cells[i * nc + c].null) continue; /* NULL: an empty field (TEXT is always quoted) */
                tmp.len = 0;
                cell_text(&r->cells[i * nc + c], &tmp, false);
                bool quote = r->cells[i * nc + c].v.type == IMDB_T_TEXT;
                if (quote) imdb_buf_put_u8(out, '"');
                for (size_t k = 0; k < tmp.len; k++) {
                    if (tmp.p[k] == '"') imdb_buf_put_u8(out, '"');
                    imdb_buf_put_u8(out, tmp.p[k]);
                }
                if (quote) imdb_buf_put_u8(out, '"');
            }
            imdb_buf_put_u8(out, '\n');
        }
        imdb_buf_free(&tmp);
        return;
    }
    size_t w[IMDB_MAX_COLS + 4];
    for (uint16_t c = 0; c < nc; c++) w[c] = strlen(r->names[c]);
    for (uint64_t i = 0; i < r->nrows; i++)
        for (uint16_t c = 0; c < nc; c++) {
            tmp.len = 0;
            cell_text(&r->cells[i * nc + c], &tmp, true);
            size_t dw = disp_width(tmp.p, tmp.len);
            if (dw > w[c]) w[c] = dw > 60 ? 60 : dw;
        }
    for (uint16_t c = 0; c < nc; c++) imdb_buf_printf(out, "%s %-*s", c ? " |" : "", (int)w[c], r->names[c]);
    imdb_buf_put_u8(out, '\n');
    for (uint16_t c = 0; c < nc; c++) {
        imdb_buf_put_str(out, c ? "-+-" : "-");
        for (size_t k = 0; k < w[c]; k++) imdb_buf_put_u8(out, '-');
    }
    imdb_buf_put_str(out, "-\n");
    for (uint64_t i = 0; i < r->nrows; i++) {
        for (uint16_t c = 0; c < nc; c++) {
            tmp.len = 0;
            const imdb_cell *cell = &r->cells[i * nc + c];
            cell_text(cell, &tmp, true);
            size_t dw = disp_width(tmp.p, tmp.len);
            bool right = !cell->null && cell->v.type != IMDB_T_TEXT && cell->v.type != IMDB_T_TIMESTAMP;
            imdb_buf_put_str(out, c ? " | " : " ");
            if (right)
                for (size_t k = dw; k < w[c]; k++) imdb_buf_put_u8(out, ' ');
            if (dw > 60) {
                imdb_buf_put(out, tmp.p, tmp.len); /* long values are printed in full, unpadded */
            } else {
                imdb_buf_put(out, tmp.p, tmp.len);
                if (!right)
                    for (size_t k = dw; k < w[c]; k++) imdb_buf_put_u8(out, ' ');
            }
        }
        imdb_buf_put_u8(out, '\n');
    }
    imdb_buf_printf(out, "(%llu row%s)", (unsigned long long)r->nrows, r->nrows == 1 ? "" : "s");
    if (r->path[0]) imdb_buf_printf(out, "  [%s]", r->path);
    if (r->has_snap)
        imdb_buf_printf(out, "  at commit %llu%s", (unsigned long long)r->snap,
                        r->snap_own ? " + this transaction's writes" : "");
    imdb_buf_put_u8(out, '\n');
    if (r->has_snap && r->show_identity) { /* SET identity = on */
        char id[33], hd[65], dg[65], mf[65];
        imdb_hex(r->db_id, 16, id);
        imdb_hex(r->head, 32, hd);
        imdb_hex(r->digest, 32, dg);
        imdb_hex(r->lake_manifest, 32, mf);
        imdb_buf_printf(out, "read point: db %s commit %llu head %s digest %s lake %llu %s\n", id,
                        (unsigned long long)r->snap, hd, dg, (unsigned long long)r->lake_seq, r->lake_seq ? mf : "-");
    }
    if (r->status[0]) imdb_buf_printf(out, "%s\n", r->status);
    imdb_buf_free(&tmp);
}
