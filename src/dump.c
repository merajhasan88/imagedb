/* P2 S17 (deferred.md D10): a logical dump. Every live table at one commit, by name: its CREATE TABLE, its rows as the
 * data of a COPY ... FROM STDIN (a table's COPY TO, walked: never held), ended by a \. line, then its indexes. One
 * script that `imagedb sql -f` restores into an empty database (design.md §5, Import and export). The rows are a table's
 * current ones: a dump carries no history, no dropped table, no key and no retention clock; its commit is named in its
 * first line, its totals in its last (a dump cut short has none). */
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

/* the table as CREATE TABLE made it: each name where the statement read it (a name the parser took there it takes
 * again: unreserved and folded), the type, PRIMARY KEY, SUBJECT, NOT NULL where a column is neither and not NULL */
static int create_text(dumper *d, const imdb_table *t, imdb_err *e)
{
    char ret[64];
    if (retention_text(t, ret, sizeof ret, e)) return e->code;
    imdb_buf_printf(&d->b, "CREATE TABLE %s (", t->s.name);
    for (uint16_t i = 0; i < t->s.ncols; i++) {
        const imdb_column *c = &t->s.cols[i];
        imdb_buf_printf(&d->b, "%s%s ", i ? ", " : "", c->name);
        if (c->type == IMDB_T_DECIMAL) imdb_buf_printf(&d->b, "DECIMAL(%u,%u)", c->precision, c->scale);
        else imdb_buf_put_str(&d->b, imdb_type_name(c->type));
        if (c->flags & IMDB_COL_PK) imdb_buf_put_str(&d->b, " PRIMARY KEY");
        if (c->flags & IMDB_COL_SUBJECT) imdb_buf_put_str(&d->b, " SUBJECT");
        if (!(c->flags & (IMDB_COL_PK | IMDB_COL_SUBJECT | IMDB_COL_NULLABLE))) imdb_buf_put_str(&d->b, " NOT NULL");
    }
    imdb_buf_printf(&d->b, ") RETENTION %s;\n", ret);
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
    if (!rc) {
        imdb_buf_printf(&d->b, "-- the end of the dump: %u tables, %llu rows\n", (unsigned)n, (unsigned long long)rows);
        rc = put(d, e);
    }
    imdb_free(ts);
    imdb_session_close(&d->s); /* the transaction rolled back: it wrote nothing */
    imdb_buf_free(&d->b);
    imdb_free(d);
    return rc;
}
