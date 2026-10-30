/* SQL executor: binding, the three read paths, cross-checking, DML, admin. */
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include "cpu.h"
#include "db_internal.h"
#include "fsum.h"
#include "lake.h"
#include "oidx.h"
#include "repl.h"
#include "sql_internal.h"

/* ---- results ---------------------------------------------------------------- */

void imdb_session_init(imdb_session *s, imdb_db *db)
{
    memset(s, 0, sizeof *s);
    s->db = db;
}

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
} xctx;

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

static int bind_lit(xctx *x, const sql_lit *l, const imdb_column *c, bool compare, imdb_value *out, imdb_err *e)
{
    memset(out, 0, sizeof *out);
    out->type = c->type;
    out->scale = c->scale;
    if (l->kind == LIT_PARAM) {
        if (l->param > x->nparams) return imdb_fail(e, IMDB_ERR_INVALID, "parameter $%u was not supplied", l->param);
        const imdb_value *pv = &x->params[l->param - 1];
        if (pv->type != c->type || (c->type == IMDB_T_DECIMAL && pv->scale != c->scale))
            return imdb_fail(e, IMDB_ERR_INVALID, "parameter $%u does not have the type of column %s", l->param, c->name);
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

static int bind_preds(xctx *x, const sql_stmt *st, qspec *q, imdb_err *e)
{
    q->pk_pred = q->subj_pred = q->ord_pred = -1;
    for (uint16_t i = 0; i < st->nwhere; i++) {
        int col = one_col(st, q->t, st->where[i].qual, st->where[i].col, e);
        if (col < 0) return col;
        if (bind_pred(x, &st->where[i], col, false, q, e)) return e->code;
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
} sink;

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
            int c = k->item_col[i];
            if (acc_add(&k->acc[i], k->st->items[i].agg, c >= 0 ? &vals[c] : NULL, k->e)) {
                k->err = k->e->code;
                return;
            }
        }
        return;
    case SINK_JBUILD: join_build_row(k, vid, vals); return;
    case SINK_JPROBE: join_probe_row(k, vid, vals); return;
    case SINK_JOUTER: join_outer_row(k, vid, vals); return;
    case SINK_JINNER: join_inner_row(k, vid, vals); return;
    case SINK_DIGEST:
        imdb_lthash_add_commit(k->x->db->meta.digest_alg, &k->digest, imdb_v_commit(k->t, vid));
        k->digest_rows++;
        return;
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
                k->capgroups = nc;
            }
            g = k->ngroups++;
            memset(&k->groups[g], 0, sizeof k->groups[g]);
            memset(&k->gacc[g * ni], 0, sizeof *k->gacc * ni);
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
    imdb_free(k->vids);
    imdb_free(k->groups);
    imdb_free(k->gacc);
    if (k->gmap.slots) imdb_hmap_free(&k->gmap);
}

/* ---- the three read paths --------------------------------------------------------- */

static int fetch_row(xctx *x, imdb_table *t, uint64_t vid, imdb_value *vals, imdb_err *e)
{
    return imdb_version_values(x->db, t, vid, vals, e);
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
    for (uint64_t vid = imdb_v_next(t, 0); vid < t->nver && !k->err; vid = imdb_v_next(t, vid + 1)) {
        const imdb_version *v = imdb_vh(t, vid); /* held: the walk has its entry */
        if (!visible_q(q, v)) continue;
        if (imdb_version_values_v(t, v, vals, e)) return e->code;
        if (preds_ok(q, vals)) sink_row(k, vid, vals);
    }
    return k->err;
}

static int path_index(xctx *x, const qspec *q, sink *k, imdb_err *e)
{
    imdb_table *t = q->t;
    imdb_value vals[IMDB_MAX_COLS];
    if (q->pk_pred >= 0 && !q->all_versions) {
        uint64_t vid = imdb_lookup_pk_at(x->db, t, &q->p[q->pk_pred].a, q->snap, q->pend);
        if (vid == IMDB_NONE) return IMDB_OK;
        if (fetch_row(x, t, vid, vals, e)) return e->code;
        if (preds_ok(q, vals)) sink_row(k, vid, vals);
        return k->err;
    }
    if (q->subj_pred >= 0) {
        const imdb_vlist *l = imdb_subject_versions(t, &q->p[q->subj_pred].a);
        for (uint32_t i = 0; l && i < l->n && !k->err; i++) {
            uint64_t vid = l->v[i];
            const imdb_version *v = imdb_vh(t, vid); /* held: the walk has its entry */
            if (!visible_q(q, v)) continue;
            if (imdb_version_values_v(t, v, vals, e)) return e->code;
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
    if (k->mode != SINK_AGG) return false;
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
    if (q->ord_pred < 0 || q->all_versions) return false;
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
        const imdb_segcol *zc = &g->col[b->col];
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
        const imdb_segment *g = t->seg[s];
        uint32_t n = g->nrows;
        if (!n) continue;
        if (!q->all_versions && seg_skipped(q, g)) continue;
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
            K->filter_range_i64((const int64_t *)g->begin, n, 1, (int64_t)q->snap, bits);
            K->filter_range_i64((const int64_t *)g->end, n, (int64_t)q->snap + 1, INT64_MAX, tmp);
            for (size_t w = 0; w < words; w++) bits[w] &= tmp[w];
            if (q->pend) { /* rows the reader itself has ended (segments hold no pending inserts) */
                K->filter_range_i64((const int64_t *)g->end, n, (int64_t)q->pend, (int64_t)q->pend, tmp);
                for (size_t w = 0; w < words; w++) bits[w] &= ~tmp[w];
            }
        }
        for (size_t w = 0; w < words; w++) bits[w] &= ~g->stubmask[w];
        for (uint16_t i = 0; i < q->np; i++) {
            const bpred *b = &q->p[i];
            const imdb_segcol *c = &g->col[b->col];
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
                        imdb_seg_get(&t->s, g, r, b->col, &v);
                        if (!pred_ok(b, &v)) bits[w] &= ~(1ull << (r & 63));
                    }
                }
            }
        }
        if (fast) {
            for (uint16_t i = 0; i < k->st->nitems && !rc; i++) {
                agg_acc *a = &k->acc[i];
                uint8_t ag = k->st->items[i].agg;
                const imdb_segcol *sc = ag == AGG_COUNT_STAR ? NULL : &g->col[k->item_col[i]];
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
                uint32_t r = (uint32_t)(w * 64 + (uint64_t)__builtin_ctzll(m));
                m &= m - 1;
                uint64_t vid = g->vid[r];
                for (uint32_t c = 0; c < t->s.ncols; c++) imdb_seg_get(&t->s, g, r, c, &vals[c]); /* the row itself */
                sink_row(k, vid, vals);
            }
        }
    }
    imdb_free(bits);
    imdb_free(tmp);
    if (rc || k->err) return rc ? rc : k->err;
    /* memtable rows (not yet in a segment) */
    for (uint64_t vid = t->mem_first; vid < t->nver && !k->err; vid++) {
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
        const imdb_segment *g = t->seg[s];
        for (uint32_t r = 0; r < g->nrows && !k->err; r++) {
            if (g->flags[r]) continue; /* a stub or a tombstone: no values (visible_q's rule) */
            if (!q->all_versions && (g->begin[r] > q->snap || g->end[r] <= q->snap || (q->pend && g->end[r] == q->pend)))
                continue;
            for (uint32_t c = 0; c < t->s.ncols; c++) imdb_seg_get(&t->s, g, r, c, &vals[c]);
            if (preds_ok(q, vals)) sink_row(k, g->vid[r], vals);
        }
    }
    for (uint64_t vid = t->mem_first; vid < t->nver && !k->err; vid++) { /* the memtable: always held */
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
static bool scan_cheaper(const qspec *q, const sink *k)
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
    return ord >= COST_FLOOR && scan < ord;
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

static int plan_select(xctx *x, const sql_stmt *st, imdb_table *t, sink *k, imdb_err *e)
{
    memset(k, 0, sizeof *k);
    k->x = x;
    k->st = st;
    k->t = t;
    k->e = e;
    bool any_agg = false, any_plain = false;
    for (uint16_t i = 0; i < st->nitems; i++) {
        const sql_item *it = &st->items[i];
        k->item_col[i] = -1;
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
    if (st->has_group) {
        k->gcol = one_col(st, t, st->group_qual, st->group_col, e);
        if (k->gcol < 0) return k->gcol;
        if (st->star) return imdb_fail(e, IMDB_ERR_INVALID, "SELECT * cannot be grouped");
        k->mode = SINK_GROUP;
        uint8_t kt = t->s.cols[k->gcol].type == IMDB_T_TEXT ? IMDB_T_TEXT : IMDB_T_INT64;
        if (imdb_hmap_init(&k->gmap, kt, e)) return e->code;
    } else if (any_agg) {
        if (any_plain) return imdb_fail(e, IMDB_ERR_INVALID, "mixing aggregates and columns needs GROUP BY");
        k->mode = SINK_AGG;
    } else {
        k->mode = SINK_VIDS;
    }
    return IMDB_OK;
}

/* Turns a sink into a result set (sorted, deterministic). */
static int materialize(xctx *x, const sql_stmt *st, imdb_table *t, sink *k, imdb_result *r, imdb_err *e)
{
    if (k->mode == SINK_VIDS) {
        uint16_t nc = st->star ? t->s.ncols : st->nitems;
        res_cols(r, nc);
        for (uint16_t i = 0; i < nc; i++) res_name(r, i, st->star ? t->s.cols[i].name : st->items[i].col);
        keyed *kv = imdb_alloc_array(k->nvids ? k->nvids : 1, sizeof *kv, e);
        if (!kv) return e->code;
        for (uint64_t i = 0; i < k->nvids; i++) {
            imdb_version_key(t, k->vids[i], t->s.pk, &kv[i].key);
            kv[i].vid = k->vids[i];
        }
        qsort(kv, k->nvids, sizeof *kv, cmp_keyed);
        uint64_t lim = st->has_limit && st->limit < k->nvids ? st->limit : k->nvids;
        imdb_value vals[IMDB_MAX_COLS];
        for (uint64_t i = 0; i < lim; i++) {
            if (fetch_row(x, t, kv[i].vid, vals, e)) {
                imdb_free(kv);
                return e->code;
            }
            imdb_cell *row = res_row(r, e);
            if (!row) {
                imdb_free(kv);
                return e->code;
            }
            for (uint16_t c = 0; c < nc; c++) res_put(r, &row[c], &vals[st->star ? c : k->item_col[c]]);
        }
        imdb_free(kv);
        return res_finish(r, e);
    }
    res_cols(r, st->nitems);
    for (uint16_t i = 0; i < st->nitems; i++) {
        const sql_item *it = &st->items[i];
        static const char *const an[] = {"", "count", "count", "sum", "min", "max"};
        char nm[IMDB_MAX_IDENT + 8];
        if (it->agg == AGG_NONE) snprintf(nm, sizeof nm, "%s", it->col);
        else if (it->agg == AGG_COUNT_STAR) snprintf(nm, sizeof nm, "count");
        else snprintf(nm, sizeof nm, "%s_%s", an[it->agg], it->col);
        res_name(r, i, nm);
    }
    if (k->mode == SINK_AGG) {
        imdb_cell *row = res_row(r, e);
        if (!row) return e->code;
        for (uint16_t i = 0; i < st->nitems; i++) {
            int c = k->item_col[i];
            if (put_agg(r, &row[i], &k->acc[i], st->items[i].agg, c >= 0 ? &t->s.cols[c] : &t->s.cols[0], e)) return e->code;
        }
        return res_finish(r, e);
    }
    uint64_t *order = imdb_alloc_array(k->ngroups ? k->ngroups : 1, sizeof *order, e);
    if (!order) return e->code;
    for (uint64_t g = 0; g < k->ngroups; g++) order[g] = g;
    qsort_r(order, k->ngroups, sizeof *order, cmp_group_idx, k->groups);
    uint64_t lim = st->has_limit && st->limit < k->ngroups ? st->limit : k->ngroups;
    for (uint64_t gi = 0; gi < lim; gi++) {
        uint64_t g = order[gi];
        imdb_cell *row = res_row(r, e);
        if (!row) {
            imdb_free(order);
            return e->code;
        }
        for (uint16_t i = 0; i < st->nitems; i++) {
            int c = k->item_col[i];
            if (st->items[i].agg == AGG_NONE) res_put(r, &row[i], &k->groups[g].key);
            else if (put_agg(r, &row[i], &k->gacc[g * st->nitems + i], st->items[i].agg, c >= 0 ? &t->s.cols[c] : &t->s.cols[0], e)) {
                imdb_free(order);
                return e->code;
            }
        }
    }
    imdb_free(order);
    return res_finish(r, e);
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

static int resolve_snapshot(xctx *x, const sql_stmt *st, imdb_table *t, uint64_t *snap, uint64_t *pend, imdb_err *e)
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
    return check_view(x, t, *snap, st->has_asof, e);
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
    if (!j->rows) {
        const sink *k = j->out;
        for (uint16_t i = 0; i < k->st->nitems; i++)
            if (k->item_col[i] >= off && k->item_col[i] < off + n) use[k->item_col[i] - off] = true;
        if (k->mode == SINK_GROUP && k->gcol >= off && k->gcol < off + n) use[k->gcol - off] = true;
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
    if (j->post.never || (j->post.np && !preds_ok(&j->post, b))) return;
    if (!j->rows) {
        imdb_value cv[IMDB_MAX_COLS];
        memcpy(cv, a, j->nc[0] * sizeof *cv);
        memcpy(cv + j->nc[0], b, j->nc[1] * sizeof *cv);
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
    j->ran[outer] = path >= 0 ? path : choose_path(x->ss, &q[outer], &ko);
    j->ran[1 - outer] = j->probe_path;
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
    j->ran[build] = path[build] >= 0 ? path[build] : choose_path(x->ss, &q[build], &kb);
    j->ran[1 - build] = path[1 - build] >= 0 ? path[1 - build] : choose_path(x->ss, &q[1 - build], &kp);
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

/* The plan (design.md §5, Joins): the hash join building side 1, or plan C where it costs less. The
 * hash join reads the build side whole after its own predicates; plan C costs a probe per outer
 * row instead. Every count is an upper bound, so plan C is chosen only when a bound on its probes
 * is small; below COST_FLOOR either plan is fast and the hash join stays, so small tables keep
 * their plans. force (SET join_plan = index): plan C wherever a probe exists, in the cheaper
 * orientation; where none does, the hash join, and the path name says so. LEFT: side 0 is the
 * outer side (its unmatched rows are NULL-extended as they are read). */
static jplan join_choose(jctx *j, const qspec q[2], bool force)
{
    jplan p = {JP_HASH, 1, {-1, -1}};
    uint64_t n[2] = {join_est_rows(&q[0]), join_est_rows(&q[1])};
    unsigned __int128 hash = (unsigned __int128)n[1] * COST_JBUILD + (unsigned __int128)n[0] * COST_JHPROBE, best = 0;
    int side = -1;
    for (int outer = 0; outer < (j->left ? 1 : 2); outer++) {
        if (!join_probe_setup(j, q, 1 - outer)) continue;
        unsigned __int128 c = (unsigned __int128)n[outer] * join_probe_cost(j);
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
    bool any_agg = false, any_plain = false;
    for (uint16_t i = 0; i < st->nitems; i++) {
        const sql_item *it = &st->items[i];
        k->item_col[i] = -1;
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

static int join_materialize(xctx *x, const sql_stmt *st, jctx *j, sink *k, imdb_result *r, imdb_err *e)
{
    if (!j->rows) return materialize(x, st, j->ct, k, r, e);
    uint16_t nc = st->star ? (uint16_t)(j->nc[0] + j->nc[1]) : st->nitems;
    res_cols(r, nc);
    for (uint16_t i = 0; i < nc; i++) res_name(r, i, st->star ? j->ct->s.cols[i].name : st->items[i].col);
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
    uint64_t lim = st->has_limit && st->limit < j->npairs ? st->limit : j->npairs;
    int rc = IMDB_OK;
    imdb_value cv[IMDB_MAX_COLS];
    for (uint64_t i = 0; i < lim && !rc; i++) {
        if (fetch_row(x, j->t[0], kv[i].va, cv, e)) rc = e->code;
        else if (kv[i].vb == IMDB_NONE) memcpy(cv + j->nc[0], j->nulls, j->nc[1] * sizeof *cv);
        else if (fetch_row(x, j->t[1], kv[i].vb, cv + j->nc[0], e)) rc = e->code;
        imdb_cell *row = rc ? NULL : res_row(r, e);
        if (!rc && !row) rc = e->code;
        for (uint16_t c = 0; !rc && c < nc; c++) res_put(r, &row[c], &cv[st->star ? c : k->item_col[c]]);
    }
    imdb_free(kv);
    return rc ? rc : res_finish(r, e);
}

/* one plan into r: the statement's sink, the plan, its result */
static int join_run(xctx *x, const sql_stmt *st, jctx *j, qspec q[2], const jplan *p, imdb_result *r, imdb_err *e)
{
    sink k;
    int rc = plan_join_sink(x, st, j, &k, e);
    j->out = &k;
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

static int exec_join(xctx *x, const sql_stmt *st, imdb_result *r, imdb_err *e)
{
    imdb_db *db = x->db;
    imdb_table *t[2] = {imdb_table_by_name(db, st->table), imdb_table_by_name(db, st->table2)};
    for (int s = 0; s < 2; s++)
        if (!t[s]) return imdb_fail(e, IMDB_ERR_NOTFOUND, "no table %s", s ? st->table2 : st->table);
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
        if (join_col(st, t, st->where[i].qual, st->where[i].col, &side, &col, e)) rc = e->code;
        else if (j->left && side == 1) rc = bind_pred(x, &st->where[i], col, true, &j->post, e);
        else rc = bind_pred(x, &st->where[i], col, false, &q[side], e);
    }
    if (!rc) {
        choose_ordered(&q[0], -1);
        choose_ordered(&q[1], -1);
    }
    /* the hash join building side 1, or plan C (join_choose; only under access_path auto: a forced
     * path is every table read's) */
    jplan p = {JP_HASH, 1, {-1, -1}};
    int jp = x->ss->join_plan;
    if (!rc && !below_floor(x->db, &q[0]) && /* below the memory floor: the hash join over the lake (stage 3b) */
        (jp == IMDB_JOIN_INDEX || (jp == IMDB_JOIN_AUTO && x->ss->access_path == IMDB_PATH_AUTO)))
        p = join_choose(j, q, jp == IMDB_JOIN_INDEX);
    char n1[28]; /* the longest name: join(build 1; store, store) */
    join_plan_name(&p, n1, sizeof n1);
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
        rc = join_run(x, st, j, q, &m, &r2, e);
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

static int exec_select(xctx *x, const sql_stmt *st, imdb_result *r, imdb_err *e)
{
    if (st->has_join) return exec_join(x, st, r, e);
    imdb_table *t = imdb_table_by_name(x->db, st->table);
    if (!t) return imdb_fail(e, IMDB_ERR_NOTFOUND, "no table %s", st->table);
    qspec q;
    memset(&q, 0, sizeof q);
    q.t = t;
    if (resolve_snapshot(x, st, t, &q.snap, &q.pend, e) || bind_preds(x, st, &q, e)) return e->code;
    sink k;
    int rc = plan_select(x, st, t, &k, e);
    if (!rc) q.ord_only = ordered_only(&q, &k);
    int p1 = rc ? IMDB_PATH_SCAN : choose_path(x->ss, &q, &k); /* the sink's kind is part of the cost */
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
    rc = plan_select(x, st, t, &k, e);
    if (!rc) rc = run_path(x, p2, &q, &k, e);
    if (!rc) rc = sink_pin(&k);
    if (!rc) rc = materialize(x, st, t, &k, &r2, e);
    sink_free(&k);
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
                       imdb_err *e)
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
    int p1 = choose_path(x->ss, &q, &k);
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
        int p2 = below_floor(x->db, &q) ? IMDB_PATH_ROWS : p1 == IMDB_PATH_SCAN ? IMDB_PATH_STORE : IMDB_PATH_SCAN;
        rc = run_path(x, p2, &q, &k2, e);
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
    }
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

static int exec_update(xctx *x, const sql_stmt *st, imdb_result *r, imdb_err *e)
{
    imdb_table *t = imdb_table_by_name(x->db, st->table);
    if (!t) return imdb_fail(e, IMDB_ERR_NOTFOUND, "no table %s", st->table);
    int cols[IMDB_MAX_COLS];
    imdb_value newv[IMDB_MAX_COLS];
    for (uint16_t i = 0; i < st->nset; i++) {
        cols[i] = imdb_schema_col(&t->s, st->set_cols[i]);
        if (cols[i] < 0) return imdb_fail(e, IMDB_ERR_NOTFOUND, "no column %s in table %s", st->set_cols[i], t->s.name);
        if (cols[i] == t->s.pk) return imdb_fail(e, IMDB_ERR_INVALID, "UPDATE cannot change the primary key (use DELETE + INSERT)");
        if (bind_lit(x, &st->set_vals[i], &t->s.cols[cols[i]], false, &newv[i], e)) return e->code;
    }
    uint64_t *vids, n;
    if (select_vids(x, st, t, false, &vids, &n, e)) return e->code;
    int rc = IMDB_OK;
    imdb_value vals[IMDB_MAX_COLS];
    for (uint64_t i = 0; i < n && !rc; i++) {
        if ((rc = fetch_row(x, t, vids[i], vals, e))) break;
        for (uint16_t c = 0; c < t->s.ncols && !rc; c++) rc = xpin(x, &vals[c], e);
        for (uint16_t k = 0; k < st->nset; k++) vals[cols[k]] = newv[k];
        uint8_t salt[16];
        if (!rc && !(rc = imdb_salt_next(&x->salts, salt, e))) rc = imdb_update_salt(x->db, t, vids[i], vals, salt, e);
        imdb_wipe(salt, sizeof salt);
    }
    imdb_free(vids);
    if (!rc) snprintf(r->status, sizeof r->status, "UPDATE %llu", (unsigned long long)n);
    return rc;
}

static int exec_delete(xctx *x, const sql_stmt *st, imdb_result *r, imdb_err *e)
{
    imdb_table *t = imdb_table_by_name(x->db, st->table);
    if (!t) return imdb_fail(e, IMDB_ERR_NOTFOUND, "no table %s", st->table);
    uint64_t *vids, n;
    if (select_vids(x, st, t, false, &vids, &n, e)) return e->code;
    int rc = IMDB_OK;
    for (uint64_t i = 0; i < n && !rc; i++) rc = imdb_delete(x->db, t, vids[i], e);
    imdb_free(vids);
    if (!rc) snprintf(r->status, sizeof r->status, "DELETE %llu", (unsigned long long)n);
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
        for (uint32_t i = 0; i < db->nt; i++)
            for (uint32_t k = 0; k < db->t[i]->nidx; k++) {
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
        res_cols(r, 6);
        const char *nm[] = {"table", "columns", "live_rows", "versions", "segments", "history_from"};
        for (int i = 0; i < 6; i++) res_name(r, (uint16_t)i, nm[i]);
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
        if (m.limit)
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
        imdb_table *t = imdb_table_by_name(db, st->table);
        if (!t) return imdb_fail(e, IMDB_ERR_NOTFOUND, "no table %s", st->table);
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
                const imdb_segment *g = t->seg[s];
                for (uint32_t i = 0; i < g->nrows; i++) {
                    imdb_value v;
                    if (g->flags[i] || imdb_v_held(t, g->vid[i])) continue;
                    imdb_seg_get(&t->s, g, i, (uint32_t)t->s.pk, &v);
                    if (imdb_value_cmp(&v, &key) == 0 && pass) chain[n] = g->vid[i];
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
                int where = imdb_v_find(t, chain[i], &at);
                if (where == IMDB_VAT_HELD && (at.v->flags & IMDB_V_PURGED)) continue;
                uint64_t begin = where == IMDB_VAT_HELD ? at.v->begin : at.g->begin[at.row];
                uint64_t end = where == IMDB_VAT_HELD ? at.v->end : at.g->end[at.row];
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
    imdb_table *t = imdb_table_by_name(db, st->table);
    if (!t) return imdb_fail(e, IMDB_ERR_NOTFOUND, "no table %s", st->table);
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
           k == ST_DROP_INDEX || k == ST_ALTER_RETENTION;
}

int imdb_exec_one(imdb_session *ss, const char *sql, size_t len, const imdb_value *params, uint32_t nparams,
                  imdb_result *r, imdb_err *e)
{
    imdb_result_init(r);
    uint64_t share = ss->db->mem_limit / 4;
    r->byte_cap = share && share < IMDB_MAX_RESULT_BYTES ? share : IMDB_MAX_RESULT_BYTES;
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
    xctx x = {.ss = ss, .db = ss->db, .sql = sql, .params = params, .nparams = nparams};
    imdb_db *db = ss->db;
    uint64_t seq_before = db->seq;
    if (db->failed) {
        /* in-memory state may be half-installed: no answers until reopen + replay */
        imdb_sql_stmt_free(st);
        imdb_free(st);
        return imdb_fail(e, IMDB_ERR_STATE, "database is in a failed state; reopen it to recover");
    }
    if ((db->pending_auth || db->lake_unverified) && st->kind != ST_VERIFY) {
        imdb_sql_stmt_free(st);
        imdb_free(st);
        return imdb_fail(e, IMDB_ERR_STATE,
                         "replica has unauthorised redactions or an unverified lake; resume apply before querying");
    }
    /* read-your-writes across copies: a session that needs commit N refuses one not there yet */
    bool reads = st->kind == ST_SELECT || st->kind == ST_SHOW_DIGEST || st->kind == ST_SHOW_HISTORY || st->kind == ST_SHOW_IDENTITY;
    if (reads && ss->min_commit > db->seq) {
        rc = imdb_fail(e, IMDB_ERR_STATE, "this database is at commit %llu; the session requires commit %llu (SET min_commit)",
                       (unsigned long long)db->seq, (unsigned long long)ss->min_commit);
        imdb_sql_stmt_free(st);
        imdb_free(st);
        return rc;
    }
    bool autocommit = false, txn = ss->txn.open;
    imdb_savepoint sp = {0, 0};
    bool physical = st->kind == ST_CHECKPOINT || st->kind == ST_COMPACT || st->kind == ST_ERASE_SUBJECT ||
                    st->kind == ST_ERASE_WHERE || st->kind == ST_VERIFY;
    bool control = st->kind == ST_BEGIN || st->kind == ST_COMMIT || st->kind == ST_ROLLBACK || st->kind == ST_SET ||
                   st->kind == ST_EMPTY || st->kind == ST_SAVEPOINT || st->kind == ST_ROLLBACK_TO ||
                   st->kind == ST_RELEASE || st->kind == ST_SET_TXN;
    if (txn && (st->kind == ST_CREATE || st->kind == ST_CREATE_INDEX || st->kind == ST_DROP_INDEX ||
                st->kind == ST_ALTER_RETENTION)) {
        rc = imdb_fail(e, IMDB_ERR_STATE, "%s commits on its own: run it outside the transaction",
                       st->kind == ST_CREATE         ? "CREATE TABLE"
                       : st->kind == ST_CREATE_INDEX ? "CREATE INDEX"
                       : st->kind == ST_DROP_INDEX   ? "DROP INDEX"
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
    case ST_DROP_INDEX:
        rc = imdb_drop_index(db, st->index_name, e);
        if (!rc) snprintf(r->status, sizeof r->status, "DROP INDEX %s", st->index_name);
        break;
    case ST_INSERT: rc = exec_insert(&x, st, r, e); break;
    case ST_UPDATE: rc = exec_update(&x, st, r, e); break;
    case ST_DELETE: rc = exec_delete(&x, st, r, e); break;
    case ST_SELECT: rc = exec_select(&x, st, r, e); break;
    case ST_BEGIN:
        if (txn) {
            rc = imdb_fail(e, IMDB_ERR_STATE, "transaction already open");
            break;
        }
        if ((rc = check_iso(st, e))) break;
        imdb_txn_begin(db, &ss->txn, st->iso == SQL_ISO_READ_COMMITTED ? IMDB_ISO_READ_COMMITTED : IMDB_ISO_SNAPSHOT);
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
        if ((rc = select_vids(&x, st, t, true, &vids, &n, e))) break;
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
    case ST_SHOW_MEMORY: rc = exec_show(&x, st, r, e); break;
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
        } else if (strcmp(st->set_name, "min_commit") == 0) {
            int64_t v;
            if (imdb_parse_int64(st->set_value, strlen(st->set_value), &v, e) || v < 0)
                rc = imdb_fail(e, IMDB_ERR_INVALID, "min_commit is a commit number (0: no requirement)");
            else ss->min_commit = (uint64_t)v;
        } else {
            rc = imdb_fail(e, IMDB_ERR_NOTFOUND, "unknown setting %s (cross_check, access_path, join_plan, identity, min_commit, sync_replicas, sync_timeout_ms)",
                           st->set_name);
        }
        if (!rc) snprintf(r->status, sizeof r->status, "SET %s = %s", st->set_name, st->set_value);
        break;
    }
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
    if (rc) imdb_result_free(r);
    xfree(&x);
    imdb_sql_stmt_free(st);
    imdb_free(st);
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
        if (r->status[0]) imdb_buf_printf(out, "%s\n", r->status);
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
