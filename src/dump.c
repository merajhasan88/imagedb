/* P2 S17 (deferred.md D10): a logical dump. Every live table at one commit, by name: its CREATE TABLE, its rows as the
 * data of a COPY ... FROM STDIN (a table's COPY TO, walked: never held), ended by a \. line, then its indexes. One
 * script that `imagedb sql -f` restores into an empty database (design.md §5, Import and export). The rows are a table's
 * current ones: a dump carries no history, no dropped table, no key and no retention clock; its commit is named in its
 * first line, its totals in its last (a dump cut short has none). P2 S7: after the tables, each live view by id (each
 * names only earlier ones), its CREATE VIEW naming its columns as logged, its query's text as written. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "db_internal.h"
#include "log.h"
#include "sql.h"
#include "util.h"

typedef struct dumper {
    imdb_session s;
    imdb_copy_write_fn wr;
    void *arg;
    imdb_buf b; /* the next statement's text */
} dumper;

static int put(dumper *d, imdb_err *e)
{
    if (imdb_buf_check(&d->b, e)) return e->code;
    if (d->b.len && d->wr(d->arg, (const char *)d->b.p, d->b.len) < 0) return imdb_fail(e, IMDB_ERR_IO, "dump: writing failed");
    d->b.len = 0;
    return IMDB_OK;
}

static int run(dumper *d, const char *sql, imdb_result *r, imdb_err *e)
{
    imdb_result_init(r);
    return imdb_exec_one(&d->s, sql, strlen(sql), NULL, 0, r, e);
}

/* RETENTION as CREATE TABLE spells it: FOREVER, or the largest unit that holds it whole (an API's retention that is not
 * whole seconds has no spelling: refused, never rounded) */
static int retention_text(const imdb_table *t, char *out, size_t n, imdb_err *e)
{
    static const struct {
        uint64_t us;
        const char *unit;
    } units[] = {{86400000000ull, "DAYS"}, {3600000000ull, "HOURS"}, {60000000ull, "MINUTES"}, {1000000ull, "SECONDS"}};
    uint64_t us = t->retention_us;
    if (us == IMDB_RETAIN_FOREVER) {
        snprintf(out, n, "FOREVER");
        return IMDB_OK;
    }
    for (size_t i = 0; i < sizeof units / sizeof *units; i++)
        if (us % units[i].us == 0) {
            snprintf(out, n, "%llu %s", (unsigned long long)(us / units[i].us), units[i].unit);
            return IMDB_OK;
        }
    return imdb_fail(e, IMDB_ERR_UNSUPPORTED, "table %s keeps its history %llu microseconds: RETENTION spells whole seconds",
                     t->s.name, (unsigned long long)us);
}

/* F1: a column's DEFAULT (an ADD's: what the rows before it read, and what an INSERT leaving the column out writes),
 * NULL when it has none: a CREATE TABLE column has none before F2 */
static const imdb_value *dump_default(const imdb_table *t, uint16_t c)
{
    if (!t->hist.nvers) return NULL;
    const imdb_value *v = &t->hist.tcol[t->hist.vers[t->hist.nvers - 1].pos[c]].missing;
    return v->null ? NULL : v;
}

/* a value as a literal the column's type reads back: its text (COPY's), TEXT and TIMESTAMP quoted with '' */
static int literal_text(dumper *d, const imdb_value *v, imdb_err *e)
{
    if (v->type != IMDB_T_TEXT && v->type != IMDB_T_TIMESTAMP) {
        imdb_format_value(v, &d->b);
        return IMDB_OK;
    }
    imdb_buf s;
    imdb_buf_init(&s);
    imdb_format_value(v, &s);
    int rc = imdb_buf_check(&s, e);
    imdb_buf_put_str(&d->b, "'");
    for (size_t i = 0; !rc && i < s.len; i++) imdb_buf_put(&d->b, s.p[i] == '\'' ? (const uint8_t *)"''" : &s.p[i], s.p[i] == '\'' ? 2 : 1);
    imdb_buf_put_str(&d->b, "'");
    imdb_buf_free(&s);
    return rc;
}

static void column_text(dumper *d, const imdb_table *t, const imdb_column *c)
{
    imdb_buf_printf(&d->b, "%s ", c->name);
    if (c->type == IMDB_T_DECIMAL) imdb_buf_printf(&d->b, "DECIMAL(%u,%u)", c->precision, c->scale);
    else imdb_buf_put_str(&d->b, imdb_type_name(c->type));
    if ((c->flags & IMDB_COL_PK) && t->s.npk == 1) imdb_buf_put_str(&d->b, " PRIMARY KEY");
    if (c->flags & IMDB_COL_SUBJECT) imdb_buf_put_str(&d->b, " SUBJECT");
    if (!(c->flags & (IMDB_COL_PK | IMDB_COL_SUBJECT | IMDB_COL_NULLABLE))) imdb_buf_put_str(&d->b, " NOT NULL");
}

/* the table as CREATE TABLE made it: each name where the statement read it (a name the parser took there it takes
 * again: unreserved and folded), the type, PRIMARY KEY, SUBJECT, NOT NULL where a column is neither and not NULL;
 * a key of several columns (F4) as the table's constraint after them, PRIMARY KEY (a, b), in key order; F1: the
 * columns from the first with a DEFAULT on as ALTER TABLE ... ADD after it, in order, each with its DEFAULT (a key
 * column is never added: all are the CREATE's) */
static int create_text(dumper *d, const imdb_table *t, imdb_err *e)
{
    char ret[64];
    if (retention_text(t, ret, sizeof ret, e)) return e->code;
    uint16_t nc = t->s.ncols; /* F1: the CREATE's columns: those before the first with a DEFAULT */
    for (uint16_t i = 0; i < t->s.ncols; i++)
        if (dump_default(t, i)) {
            nc = i;
            break;
        }
    imdb_buf_printf(&d->b, "CREATE TABLE %s (", t->s.name);
    for (uint16_t i = 0; i < nc; i++) {
        if (i) imdb_buf_put_str(&d->b, ", ");
        column_text(d, t, &t->s.cols[i]);
    }
    if (t->s.npk > 1) {
        imdb_buf_put_str(&d->b, ", PRIMARY KEY (");
        for (int k = 0; k < t->s.npk; k++) imdb_buf_printf(&d->b, "%s%s", k ? ", " : "", t->s.cols[t->s.key[k]].name);
        imdb_buf_put_str(&d->b, ")");
    }
    imdb_buf_printf(&d->b, ") RETENTION %s;\n", ret);
    for (uint16_t i = nc; i < t->s.ncols; i++) { /* F1 */
        imdb_buf_printf(&d->b, "ALTER TABLE %s ADD ", t->s.name);
        column_text(d, t, &t->s.cols[i]);
        const imdb_value *dv = dump_default(t, i);
        if (dv) {
            imdb_buf_put_str(&d->b, " DEFAULT ");
            if (literal_text(d, dv, e)) return e->code;
        }
        imdb_buf_put_str(&d->b, ";\n");
    }
    return put(d, e);
}

/* its indexes, by name (a table keeps them sorted), after its rows: each built once, over the whole table */
static int index_text(dumper *d, const imdb_table *t, imdb_err *e)
{
    for (uint32_t k = 0; k < t->nidx; k++) {
        const imdb_index_def *x = &t->idx[k].d;
        imdb_buf_printf(&d->b, "CREATE %sINDEX %s ON %s (", x->flags & IMDB_INDEX_UNIQUE ? "UNIQUE " : "", x->name, t->s.name);
        for (uint8_t c = 0; c < x->ncols; c++) imdb_buf_printf(&d->b, "%s%s", c ? ", " : "", t->s.cols[x->cols[c]].name);
        imdb_buf_put_str(&d->b, ");\n");
        if (put(d, e)) return e->code;
    }
    return IMDB_OK;
}

static int by_name(const void *a, const void *b)
{
    return strcmp((*(imdb_table *const *)a)->s.name, (*(imdb_table *const *)b)->s.name);
}

int imdb_dump(imdb_db *db, uint32_t batch, imdb_copy_write_fn wr, void *arg, imdb_err *e)
{
    if (batch > IMDB_MAX_OPS_PER_COMMIT)
        return imdb_fail(e, IMDB_ERR_INVALID, "a dump's BATCH is 1 to %u rows", (unsigned)IMDB_MAX_OPS_PER_COMMIT);
    if (!batch) batch = IMDB_DUMP_BATCH;
    dumper *d = imdb_alloc(sizeof *d, e); /* a session is large: not on the stack */
    if (!d) return e->code;
    memset(d, 0, sizeof *d);
    d->wr = wr;
    d->arg = arg;
    imdb_buf_init(&d->b);
    imdb_session_init(&d->s, db);
    imdb_session_copy_io(&d->s, NULL, wr, arg);
    imdb_table **ts = NULL;
    uint32_t n = 0;
    uint64_t rows = 0;
    imdb_result r;
    /* one snapshot for every table: a transaction, its first statement taking the commit the dump names */
    int rc = run(d, "BEGIN ISOLATION LEVEL SNAPSHOT", &r, e);
    imdb_result_free(&r);
    if (!rc) {
        rc = run(d, "SELECT 1", &r, e);
        imdb_result_free(&r);
    }
    if (!rc && (!d->s.txn.started || d->s.txn.snap != db->seq))
        rc = imdb_fail(e, IMDB_ERR_STATE, "dump: the database moved while the dump began: run it again");
    if (!rc && !(ts = imdb_alloc_array(db->nt ? db->nt : 1, sizeof *ts, e))) rc = e->code;
    for (uint32_t i = 0; !rc && i < db->nt; i++)
        if (!db->t[i]->dropped_at) ts[n++] = db->t[i];
    if (!rc) qsort(ts, n, sizeof *ts, by_name);
    if (!rc) {
        char head[65];
        imdb_hex(db->head, 32, head);
        imdb_buf_printf(&d->b,
                        "-- imagedb dump of commit %llu (head %s, digest algorithm %u): its tables' rows now, no history; "
                        "restore it into an empty database with imagedb sql DIR -f FILE\n",
                        (unsigned long long)d->s.txn.snap, head, (unsigned)db->meta.digest_alg);
        rc = put(d, e);
    }
    for (uint32_t i = 0; !rc && i < n; i++) {
        const imdb_table *t = ts[i];
        if (create_text(d, t, e)) {
            rc = e->code;
            break;
        }
        imdb_buf_printf(&d->b, "COPY %s FROM STDIN (BATCH %u);\n", t->s.name, (unsigned)batch);
        if ((rc = put(d, e))) break;
        char q[IMDB_MAX_IDENT + 32];
        snprintf(q, sizeof q, "COPY %s TO STDOUT", t->s.name);
        if ((rc = run(d, q, &r, e))) break;
        unsigned long long k = 0;
        if (sscanf(r.status, "COPY %llu", &k) == 1) rows += k;
        imdb_result_free(&r);
        imdb_buf_put_str(&d->b, "\\.\n");
        if ((rc = put(d, e)) || (rc = index_text(d, t, e))) break;
    }
    uint32_t nviews = 0; /* P2 S7: the live views by id, after every table: each names only earlier ones */
    for (uint32_t i = 0; !rc && i < db->nviews; i++) {
        const imdb_view *v = &db->views[i];
        if (v->dropped_at || !v->def) continue;
        imdb_buf_printf(&d->b, "CREATE VIEW %s (", v->name);
        for (uint16_t c = 0; c < v->def->ncols; c++) imdb_buf_printf(&d->b, "%s%s", c ? ", " : "", v->def->cols[c].name);
        imdb_buf_put_str(&d->b, ") AS ");
        imdb_buf_put(&d->b, v->def->text, v->def->text_len);
        imdb_buf_put_str(&d->b, ";\n");
        rc = put(d, e);
        nviews++;
    }
    if (!rc) {
        imdb_buf_printf(&d->b, "-- the end of the dump: %u tables, %u views, %llu rows\n", (unsigned)n, (unsigned)nviews,
                        (unsigned long long)rows);
        rc = put(d, e);
    }
    imdb_free(ts);
    imdb_session_close(&d->s); /* the transaction rolled back: it wrote nothing */
    imdb_buf_free(&d->b);
    imdb_free(d);
    return rc;
}
