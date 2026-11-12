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


/* a value as a literal the column's type reads back: its text (COPY's), TEXT, TIMESTAMP and TIMESTAMPTZ (in UTC, +00:
 * never the session's zone) quoted with '' */
/* F3g: bytes as a string literal, ' doubled */
static void quoted(dumper *d, const char *p, size_t n)
{
    imdb_buf_put_str(&d->b, "'");
    for (size_t i = 0; i < n; i++) imdb_buf_put(&d->b, p[i] == '\'' ? "''" : &p[i], p[i] == '\'' ? 2 : 1);
    imdb_buf_put_str(&d->b, "'");
}

static int literal_text(dumper *d, const imdb_value *v, imdb_err *e)
{
    if (v->type == IMDB_T_ENUM) { /* F3g: its label, quoted */
        const imdb_enumdef *ed = imdb_enum_def(d->s.db, v->eid);
        if (!ed || v->i < 0 || v->i >= ed->n) return imdb_fail(e, IMDB_ERR_STATE, "dump: an ENUM value of no label");
        quoted(d, ed->text + ed->off[v->i], ed->off[v->i + 1] - ed->off[v->i]);
        return IMDB_OK;
    }
    if (!imdb_type_bytes(v->type) && v->type != IMDB_T_TIMESTAMP && v->type != IMDB_T_TIMESTAMPTZ && v->type != IMDB_T_DATE &&
        v->type != IMDB_T_TIME && v->type != IMDB_T_INTERVAL) { /* F3b: a DATE and a TIME quoted, as their literals are
                                                                * strings; F3d: a UUID and a BYTEA; F3f: an INTERVAL */
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

/* F2a: a column's write default as CREATE TABLE spells it (an INSERT leaving the column out writes it: a CREATE's, an
 * ADD's or a SET DEFAULT's), nothing when it has none: a literal, or the clock's name */
/* F2a-2: a sequence's options as CREATE SEQUENCE and an IDENTITY spell them, each written out */
static void seq_opts_text(dumper *d, const imdb_sequence *s)
{
    imdb_buf_printf(&d->b, "INCREMENT BY %lld MINVALUE %lld MAXVALUE %lld START WITH %lld", (long long)s->d.inc,
                    (long long)s->d.min, (long long)s->d.max, (long long)s->d.start);
}

static int default_text(dumper *d, const imdb_table *t, uint16_t c, imdb_err *e)
{
    static const char *const clock[] = {[IMDB_DEFK_CURRENT_TIMESTAMP] = "CURRENT_TIMESTAMP",
                                        [IMDB_DEFK_LOCALTIMESTAMP] = "LOCALTIMESTAMP",
                                        [IMDB_DEFK_CURRENT_DATE] = "CURRENT_DATE", [IMDB_DEFK_LOCALTIME] = "LOCALTIME"};
    if (!t->hist.nvers) return IMDB_OK;
    const imdb_tcol *tc = &t->hist.tcol[t->hist.vers[t->hist.nvers - 1].pos[c]];
    if (tc->gtext) { /* F2c: its expression as written; no DEFAULT beside it */
        imdb_buf_put_str(&d->b, " GENERATED ALWAYS AS (");
        imdb_buf_put(&d->b, tc->gtext, tc->glen);
        imdb_buf_put_str(&d->b, ") STORED");
        return IMDB_OK;
    }
    const imdb_sequence *s = tc->wclock >= IMDB_DEFK_IDENTITY_ALWAYS && tc->wclock <= IMDB_DEFK_NEXTVAL && tc->wseq < d->s.db->nseqs
                                 ? &d->s.db->seqs[tc->wseq]
                                 : NULL; /* F3d: kind 10 is no sequence's */
    if (tc->wclock == IMDB_DEFK_RANDOM_UUID) { /* F3d */
        imdb_buf_put_str(&d->b, " DEFAULT gen_random_uuid()");
        return IMDB_OK;
    }
    if (s && tc->wclock != IMDB_DEFK_NEXTVAL) { /* F2a-2: an IDENTITY, its sequence's options written out */
        imdb_buf_printf(&d->b, " GENERATED %s AS IDENTITY (", tc->wclock == IMDB_DEFK_IDENTITY_ALWAYS ? "ALWAYS" : "BY DEFAULT");
        seq_opts_text(d, s);
        imdb_buf_put_str(&d->b, ")");
        return IMDB_OK;
    }
    if (s) { /* DEFAULT nextval('s') */
        imdb_buf_printf(&d->b, " DEFAULT nextval('%s')", s->d.name);
        return IMDB_OK;
    }
    if (tc->wclock > IMDB_DEFK_VALUE && tc->wclock <= IMDB_DEFK_CLOCK_LAST) {
        imdb_buf_printf(&d->b, " DEFAULT %s", clock[tc->wclock]);
        return IMDB_OK;
    }
    if (tc->wdef.null) return IMDB_OK;
    imdb_buf_put_str(&d->b, " DEFAULT ");
    return literal_text(d, &tc->wdef, e);
}

static int column_text(dumper *d, const imdb_table *t, uint16_t i, imdb_err *e)
{
    const imdb_column *c = &t->s.cols[i];
    imdb_buf_printf(&d->b, "%s ", c->name);
    if (c->type == IMDB_T_DECIMAL) imdb_buf_printf(&d->b, "DECIMAL(%u,%u)", c->precision, c->scale);
    else if (c->type == IMDB_T_TEXT && c->vlen) imdb_buf_printf(&d->b, "VARCHAR(%u)", c->vlen); /* F3c */
    else if (c->type == IMDB_T_ENUM && imdb_enum_def(d->s.db, c->eid)) imdb_buf_put_str(&d->b, imdb_enum_def(d->s.db, c->eid)->name); /* F3g */
    else imdb_buf_put_str(&d->b, c->type == IMDB_T_INT64 ? imdb_int_name(c->precision) : imdb_type_name(c->type)); /* F3a */
    if ((c->flags & IMDB_COL_PK) && t->s.npk == 1) imdb_buf_put_str(&d->b, " PRIMARY KEY");
    if (c->flags & IMDB_COL_SUBJECT) imdb_buf_put_str(&d->b, " SUBJECT");
    if (!(c->flags & (IMDB_COL_PK | IMDB_COL_SUBJECT | IMDB_COL_NULLABLE))) imdb_buf_put_str(&d->b, " NOT NULL");
    return default_text(d, t, i, e);
}

/* the table as CREATE TABLE made it: each name where the statement read it (a name the parser took there it takes
 * again: unreserved and folded), the type, PRIMARY KEY, SUBJECT, NOT NULL where a column is neither and not NULL;
 * a key of several columns (F4) as the table's constraint after them, PRIMARY KEY (a, b), in key order; F1: every
 * live column in the CREATE (a dropped one is in no row the dump writes), each with its write default (F2a: CREATE
 * TABLE's DEFAULT, a literal or a clock; the restore's rows are all written whole, so the value an older row read for
 * an added column is never needed); F2b-1: then each live CHECK, CONSTRAINT name CHECK (its text as written) */
static int create_text(dumper *d, const imdb_table *t, imdb_err *e)
{
    char ret[64];
    if (retention_text(t, ret, sizeof ret, e)) return e->code;
    imdb_buf_printf(&d->b, "CREATE TABLE %s (", t->s.name);
    for (uint16_t i = 0; i < t->s.ncols; i++) {
        if (i) imdb_buf_put_str(&d->b, ", ");
        if (column_text(d, t, i, e)) return e->code;
    }
    if (t->s.npk > 1) {
        imdb_buf_put_str(&d->b, ", PRIMARY KEY (");
        for (int k = 0; k < t->s.npk; k++) imdb_buf_printf(&d->b, "%s%s", k ? ", " : "", t->s.cols[t->s.key[k]].name);
        imdb_buf_put_str(&d->b, ")");
    }
    for (uint16_t k = 0; k < t->hist.nchk; k++) { /* F2b-1: each live CHECK by name, its text as written */
        imdb_buf_printf(&d->b, ", CONSTRAINT %s CHECK (", t->hist.chk[k].name);
        imdb_buf_put(&d->b, t->hist.chk[k].text, t->hist.chk[k].len);
        imdb_buf_put_str(&d->b, ")");
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

/* L: the live roles (CREATE ROLE, their verifiers' texts only when asked), then the memberships (GRANT role TO role): before
 * everything, as pg_dumpall's globals come first */
static int roles_text(dumper *d, imdb_db *db, bool passwords, imdb_err *e)
{
    bool any = false;
    for (uint32_t i = 0; i < db->rc.n; i++) any |= !db->rc.roles[i]->dropped_at; /* the note whatever they hold: a dump
                                                                                * restored dumps again the same */
    if (any && !passwords) {
        imdb_buf_put_str(&d->b, "-- the roles come without passwords (imagedb dump --role-passwords writes their SCRAM-SHA-256 "
                                "verifiers: an offline-guessing target, keep such a dump as a secret)\n");
        if (put(d, e)) return e->code;
    }
    for (uint32_t i = 0; i < db->rc.n; i++) {
        const imdb_role *r = db->rc.roles[i];
        if (r->dropped_at) continue;
        imdb_buf_printf(&d->b, "CREATE ROLE %s%s%s", r->name, (r->attrs & IMDB_RA_LOGIN) ? " LOGIN" : "",
                        (r->attrs & IMDB_RA_SUPERUSER) ? " SUPERUSER" : "");
        imdb_scram v;
        imdb_err e2 = {0};
        char t[IMDB_SCRAM_TEXT_MAX];
        if (passwords && r->has_ver && r->vent.bytes && !imdb_scram_decode(r->vent.bytes, r->vent.len, &v, &e2) &&
            imdb_scram_format(&v, t, sizeof t))
            imdb_buf_printf(&d->b, " PASSWORD '%s'", t);
        imdb_wipe(&v, sizeof v);
        imdb_buf_put_str(&d->b, ";\n");
        if (put(d, e)) return e->code;
    }
    for (uint32_t i = 0; i < db->rc.n; i++)
        for (uint32_t k = 0; k < db->rc.roles[i]->ngroups; k++) {
            const imdb_role *g = imdb_role_by_id(db, db->rc.roles[i]->groups[k]);
            if (!g) continue;
            imdb_buf_printf(&d->b, "GRANT %s TO %s;\n", g->name, db->rc.roles[i]->name);
            if (put(d, e)) return e->code;
        }
    return IMDB_OK;
}

typedef struct gname { /* a privilege of a role's, by its object's name: a restore renumbers the objects, not their names */
    const char *obj;
    uint32_t privs;
} gname;

static int by_obj(const void *a, const void *b) { return strcmp(((const gname *)a)->obj, ((const gname *)b)->obj); }

/* L: each role's privileges, after every table and view, by role and then by object name */
static int grants_text(dumper *d, imdb_db *db, imdb_err *e)
{
    static const char *const pn[] = {"SELECT", "INSERT", "UPDATE", "DELETE"};
    gname *gs = NULL;
    uint32_t capg = 0;
    int rc = IMDB_OK;
    for (uint32_t i = 0; !rc && i < db->rc.n; i++) {
        const imdb_role *r = db->rc.roles[i];
        if (r->nprivs > capg) {
            imdb_free(gs);
            if (!(gs = imdb_alloc_array(r->nprivs, sizeof *gs, e))) return e->code;
            capg = r->nprivs;
        }
        uint32_t ng = 0;
        for (uint32_t k = 0; k < r->nprivs; k++) {
            const imdb_rpriv *p = &r->privs[k];
            const imdb_table *t = p->okind == IMDB_OBJ_TABLE ? imdb_table_by_id(db, p->oid) : NULL;
            const char *obj = t ? t->s.name : p->okind == IMDB_OBJ_VIEW && p->oid < db->nviews ? db->views[p->oid].name : NULL;
            if (obj) gs[ng++] = (gname){.obj = obj, .privs = p->privs};
        }
        if (ng) qsort(gs, ng, sizeof *gs, by_obj); /* gs is NULL until a role holds a privilege */
        for (uint32_t k = 0; !rc && k < ng; k++) {
            imdb_buf_put_str(&d->b, "GRANT ");
            for (int b = 0, n = 0; b < 4; b++)
                if (gs[k].privs & (1u << b)) imdb_buf_printf(&d->b, "%s%s", n++ ? ", " : "", pn[b]);
            imdb_buf_printf(&d->b, " ON %s TO %s;\n", gs[k].obj, r->name);
            rc = put(d, e);
        }
    }
    imdb_free(gs);
    return rc;
}

int imdb_dump(imdb_db *db, uint32_t batch, imdb_copy_write_fn wr, void *arg, imdb_err *e)
{
    return imdb_dump_ex(db, batch, 0, wr, arg, e);
}

int imdb_dump_ex(imdb_db *db, uint32_t batch, uint32_t flags, imdb_copy_write_fn wr, void *arg, imdb_err *e)
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
    if (!rc) rc = roles_text(d, db, (flags & IMDB_DUMP_ROLE_PASSWORDS) != 0, e); /* L */
    for (uint32_t i = 0; !rc && i < db->nenums; i++) { /* F3g: each live ENUM type, its labels as they are now, before the tables */
        const imdb_enum *t = &db->enums[i];
        if (t->dropped_at || !t->def) continue;
        imdb_buf_printf(&d->b, "CREATE TYPE %s AS ENUM (", t->def->name);
        for (uint16_t k = 0; k < t->def->n; k++) {
            if (k) imdb_buf_put_str(&d->b, ", ");
            quoted(d, t->def->text + t->def->off[k], t->def->off[k + 1] - t->def->off[k]);
        }
        imdb_buf_put_str(&d->b, ");\n");
        rc = put(d, e);
    }
    for (uint32_t i = 0; !rc && i < db->nseqs; i++) { /* F2a-2: the sequences no column owns, before the tables naming them */
        const imdb_sequence *s = &db->seqs[i];
        if (s->dropped_at || s->owner != UINT32_MAX) continue;
        imdb_buf_printf(&d->b, "CREATE SEQUENCE %s AS %s ", s->d.name, imdb_int_name(s->d.width));
        seq_opts_text(d, s);
        imdb_buf_put_str(&d->b, ";\n");
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
    for (uint32_t i = 0; !rc && i < n; i++) { /* F2b-2: each FOREIGN KEY after every table's rows (pg_dump's order): the
                                               * restore never meets a child before its parent, and checks each whole */
        static const char *const act[] = {"NO ACTION", "RESTRICT", "CASCADE", "SET NULL", "SET DEFAULT"};
        const imdb_table *t = ts[i];
        const imdb_sver *cur = &t->hist.vers[t->hist.nvers - 1];
        for (uint16_t k = 0; k < t->hist.nfk; k++) {
            const imdb_fk *f = &t->hist.fk[k];
            const imdb_table *p = f->parent < db->nt ? db->t[f->parent] : NULL;
            if (!p) continue;
            const imdb_sver *pc = &p->hist.vers[p->hist.nvers - 1];
            imdb_buf_printf(&d->b, "ALTER TABLE %s ADD CONSTRAINT %s FOREIGN KEY (", t->s.name, f->name);
            for (uint8_t c = 0; c < f->ncols; c++) imdb_buf_printf(&d->b, "%s%s", c ? ", " : "", t->s.cols[cur->at[f->cols[c]]].name);
            imdb_buf_printf(&d->b, ") REFERENCES %s (", p->s.name);
            for (uint8_t c = 0; c < f->ncols; c++) imdb_buf_printf(&d->b, "%s%s", c ? ", " : "", p->s.cols[pc->at[f->pcols[c]]].name);
            imdb_buf_printf(&d->b, ") ON DELETE %s;\n", act[f->on_delete]);
            if ((rc = put(d, e))) break;
        }
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
    for (uint32_t i = 0; !rc && i < db->nseqs; i++) { /* F2a-2: each sequence's state, after the rows (pg_dump's form) */
        const imdb_sequence *s = &db->seqs[i];
        if (s->dropped_at) continue;
        imdb_buf_printf(&d->b, "SELECT setval('%s', %lld, %s);\n", s->d.name, (long long)s->last, s->called ? "true" : "false");
        rc = put(d, e);
    }
    if (!rc) rc = grants_text(d, db, e); /* L: after every table and view */
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
