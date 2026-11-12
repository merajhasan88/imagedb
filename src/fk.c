/* F2b-2: FOREIGN KEYs at run time (docs/fk-design.md): each child table's maps from a live FK's key to the child's
 * versions holding it, and the check of a transaction's writes (a statement's at its end, every one at the commit).
 *
 * The write set is the transaction's op list (db->tx): every INSERT, UPDATE and DELETE with its versions, truncated by
 * a failed statement's mark and ROLLBACK TO, saved and replayed with a parked transaction, so the checks need no list
 * of their own. A child version written and still live must find a live parent version of its key now; a parent key
 * the writes delete must have no live child now. What the transaction can see is CONSTRAINT, what a commit after its
 * snapshot did is CONFLICT (a retry sees it), as unique_check sorts a key's two cases. */
#include <stdio.h>
#include <string.h>

#include "db_internal.h"

typedef struct fkvec {
    uint64_t *v;
    uint32_t n, cap;
} fkvec;

/* one live FK's map: the parent key's map key (imdb_pkey's v, the parent's primary key encoding) to a vector of the
 * child versions holding it: the live ones, and ended ones until a later write of the key compacts them out */
typedef struct fkmap {
    char name[IMDB_MAX_IDENT + 1];
    imdb_hmap map;
    fkvec *vecs;
    uint32_t nvecs, capvecs;
} fkmap;

struct imdb_fkm {
    uint32_t ver;       /* the history length the maps were built for */
    uint64_t nver_seen; /* the table's versions they cover: a version added by a path without the hook makes them stale */
    uint16_t n;
    fkmap m[IMDB_MAX_FKS];
};

static bool v_live(const imdb_version *v)
{
    return v->end == IMDB_LIVE && !(v->flags & (IMDB_V_STUB | IMDB_V_PURGED));
}

static void fkm_free_maps(struct imdb_fkm *f)
{
    for (uint16_t i = 0; i < f->n; i++) {
        imdb_hmap_free(&f->m[i].map);
        for (uint32_t k = 0; k < f->m[i].nvecs; k++) imdb_free(f->m[i].vecs[k].v);
        imdb_free(f->m[i].vecs);
    }
    memset(f, 0, sizeof *f);
}

void imdb_fk_free(imdb_table *t)
{
    if (!t->fkm) return;
    fkm_free_maps(t->fkm);
    imdb_free(t->fkm);
    t->fkm = NULL;
}

/* the FK's key from a child row's values (by t's current columns): the parent's primary key encoding of them, so a
 * lookup from either side meets; false: a NULL in an FK column (MATCH SIMPLE: not checked) */
static int fk_key(imdb_db *db, const imdb_table *t, const imdb_fk *f, const imdb_value *vals, imdb_pkey *key, bool *null,
                  imdb_err *e)
{
    *null = false;
    const imdb_table *p = f->parent < db->nt ? db->t[f->parent] : NULL;
    if (!p || p->s.npk != f->ncols) return imdb_fail(e, IMDB_ERR_STATE, "foreign key %s: its parent is gone", f->name);
    const imdb_sver *cur = &t->hist.vers[t->hist.nvers - 1];
    imdb_value pv[IMDB_MAX_COLS];
    memset(pv, 0, sizeof pv);
    for (uint8_t i = 0; i < f->ncols; i++) {
        int c = f->cols[i] < cur->npos ? cur->at[f->cols[i]] : -1;
        if (c < 0) return imdb_fail(e, IMDB_ERR_STATE, "foreign key %s names a column table %s does not have", f->name, t->s.name);
        if (vals[c].null) {
            *null = true;
            return IMDB_OK;
        }
        pv[p->s.key[i]] = vals[c];
        pv[p->s.key[i]].scale = p->s.cols[p->s.key[i]].scale;
    }
    return imdb_pkey_of_values(&p->s, pv, key, e);
}

static int fkmap_add(fkmap *m, const imdb_table *t, uint64_t seq, const imdb_value *k, uint64_t vid, imdb_err *e)
{
    uint64_t *slot = imdb_hmap_get(&m->map, k);
    fkvec *vec;
    if (slot) {
        vec = &m->vecs[*slot];
    } else {
        if (m->nvecs == m->capvecs) {
            uint32_t nc = m->capvecs ? m->capvecs * 2 : 16;
            fkvec *nv = imdb_realloc_array(m->vecs, m->capvecs, nc, sizeof *nv, e);
            if (!nv) return e->code;
            memset(nv + m->capvecs, 0, (size_t)(nc - m->capvecs) * sizeof *nv);
            m->vecs = nv;
            m->capvecs = nc;
        }
        if (imdb_hmap_put(&m->map, k, m->nvecs, e)) return e->code;
        vec = &m->vecs[m->nvecs++];
    }
    uint32_t w = 0; /* the ended ones out first: a committed end is final (a pending one may still be undone) */
    for (uint32_t r = 0; r < vec->n; r++) {
        uint64_t x = vec->v[r];
        const imdb_version *xv = imdb_v_held(t, x) ? imdb_vh(t, x) : NULL;
        if (xv && (xv->end == IMDB_LIVE || xv->end > seq) && !(xv->flags & IMDB_V_STUB)) /* live, or a pending end */
            vec->v[w++] = x;
    }
    vec->n = w;
    if (vec->n == vec->cap) {
        uint32_t nc = vec->cap ? vec->cap * 2 : 4;
        uint64_t *nv = imdb_realloc_array(vec->v, vec->cap, nc, sizeof *nv, e);
        if (!nv) return e->code;
        vec->v = nv;
        vec->cap = nc;
    }
    vec->v[vec->n++] = vid;
    return IMDB_OK;
}

static void fkmap_remove(fkmap *m, const imdb_value *k, uint64_t vid)
{
    uint64_t *slot = imdb_hmap_get(&m->map, k);
    if (!slot) return;
    fkvec *vec = &m->vecs[*slot];
    for (uint32_t r = 0; r < vec->n; r++)
        if (vec->v[r] == vid) {
            vec->v[r] = vec->v[--vec->n];
            return;
        }
}

/* t's maps for its live FKs as its history now holds them, built from the live versions (a live one is always held)
 * when the history changed since; the table's, outside a statement's memory ceiling */
static int fkm_ready(imdb_db *db, imdb_table *t, imdb_err *e)
{
    const imdb_schema_hist *h = &t->hist;
    if (!h->nfk) {
        imdb_fk_free(t);
        return IMDB_OK;
    }
    if (t->fkm && t->fkm->ver == h->nvers && t->fkm->nver_seen == t->nver) return IMDB_OK;
    imdb_heap_exempt_begin();
    int rc = IMDB_OK;
    if (!t->fkm && !(t->fkm = imdb_alloc(sizeof *t->fkm, e))) rc = e->code;
    if (!rc) fkm_free_maps(t->fkm);
    imdb_value vals[IMDB_MAX_COLS];
    for (uint16_t i = 0; i < h->nfk && !rc; i++) {
        fkmap *m = &t->fkm->m[i];
        snprintf(m->name, sizeof m->name, "%s", h->fk[i].name);
        const imdb_table *p = h->fk[i].parent < db->nt ? db->t[h->fk[i].parent] : NULL;
        if (!p) rc = imdb_fail(e, IMDB_ERR_STATE, "foreign key %s: its parent is gone", h->fk[i].name);
        else if (!(rc = imdb_hmap_init(&m->map, imdb_pk_map_type(&p->s), e))) t->fkm->n = (uint16_t)(i + 1);
    }
    for (uint64_t vid = imdb_v_next(t, 0); vid < t->nver && !rc; vid = imdb_v_next(t, vid + 1)) {
        const imdb_version *v = imdb_vh(t, vid);
        if (!v_live(v)) continue;
        if ((rc = imdb_version_values_v(t, v, vals, e))) break;
        for (uint16_t i = 0; i < h->nfk && !rc; i++) {
            imdb_pkey k;
            bool null;
            if ((rc = fk_key(db, t, &h->fk[i], vals, &k, &null, e)) || null) continue;
            rc = fkmap_add(&t->fkm->m[i], t, db->seq, &k.v, vid, e);
            imdb_pkey_done(&k);
        }
    }
    imdb_heap_exempt_end();
    if (rc) {
        imdb_fk_free(t);
        return rc;
    }
    t->fkm->ver = h->nvers;
    t->fkm->nver_seen = t->nver;
    return IMDB_OK;
}

int imdb_fk_index_add(imdb_db *db, imdb_table *t, uint64_t vid, const imdb_value *vals, imdb_err *e)
{
    /* built for this history and every version before this one: add it; else the next use builds them whole */
    if (!t->hist.nfk || !t->fkm || t->fkm->ver != t->hist.nvers || t->fkm->nver_seen != vid) return IMDB_OK;
    t->fkm->nver_seen = vid + 1;
    if (!vals) return IMDB_OK; /* a version with no payload (an erased row): no entry */
    int rc = IMDB_OK;
    imdb_heap_exempt_begin();
    for (uint16_t i = 0; i < t->hist.nfk && !rc; i++) {
        imdb_pkey k;
        bool null;
        if ((rc = fk_key(db, t, &t->hist.fk[i], vals, &k, &null, e)) || null) continue;
        rc = fkmap_add(&t->fkm->m[i], t, db->seq, &k.v, vid, e);
        imdb_pkey_done(&k);
    }
    imdb_heap_exempt_end();
    if (rc) imdb_fk_free(t); /* a map short of this version: built again at its next use */
    return IMDB_OK;         /* the maps are derived: their failure is never the write's */
}

void imdb_fk_index_remove(imdb_db *db, imdb_table *t, uint64_t vid, const imdb_value *vals)
{
    if (!t->fkm || t->fkm->ver != t->hist.nvers || t->fkm->nver_seen != t->nver) return; /* none, or stale */
    if (vid + 1 == t->nver) t->fkm->nver_seen = vid; /* an undone insert: the newest, popped next */
    for (uint16_t i = 0; i < t->hist.nfk && i < t->fkm->n; i++) {
        imdb_pkey k;
        bool null;
        imdb_err e2 = {0};
        if (fk_key(db, t, &t->hist.fk[i], vals, &k, &null, &e2) || null) continue;
        fkmap_remove(&t->fkm->m[i], &k.v, vid);
        imdb_pkey_done(&k);
    }
}

/* the live version of a key in the parent now (the current state with the transaction's pending versions) */
static uint64_t parent_live(imdb_table *p, const imdb_value *k)
{
    uint64_t *head = imdb_hmap_get(&p->pk, k);
    if (!head) return IMDB_NONE;
    const imdb_version *v = imdb_vh(p, *head);
    return v_live(v) ? *head : IMDB_NONE;
}

/* an ERASE op's entries name (table, vid) (sorted by both, log.c's rule): its own deletes, the only ones a commit's
 * erasure excuses from the parent check (an ERASE ends no parent key: it is never refused and runs no action) */
static bool erase_names(const imdb_op *er, uint32_t table, uint64_t vid)
{
    if (!er) return false;
    uint32_t lo = 0, hi = er->n_erase;
    while (lo < hi) {
        uint32_t mid = lo + (hi - lo) / 2;
        const imdb_erase_ent *x = &er->erase[mid];
        if (x->table < table || (x->table == table && x->vid < vid)) lo = mid + 1;
        else hi = mid;
    }
    return lo < er->n_erase && er->erase[lo].table == table && er->erase[lo].vid == vid;
}

static bool visible(const imdb_db *db, const imdb_version *v, uint64_t snap)
{
    return v->begin > db->seq || v->begin <= snap; /* its own pending version, or committed by its snapshot */
}

/* a child version written: its parent */
static int check_child(imdb_db *db, imdb_table *t, const imdb_fk *f, const imdb_value *vals, uint64_t snap, uint64_t pend,
                       imdb_err *e)
{
    imdb_pkey k;
    bool null;
    if (fk_key(db, t, f, vals, &k, &null, e)) return e->code;
    if (null) return IMDB_OK;
    imdb_table *p = db->t[f->parent];
    uint64_t now = parent_live(p, &k.v);
    int rc = IMDB_OK;
    if (now != IMDB_NONE) {
        if (!visible(db, imdb_vh(p, now), snap)) { /* the key in its view too (a non-key update since): fine */
            uint64_t seen = IMDB_NONE;
            imdb_value kv[IMDB_MAX_KEY_COLS];
            for (int c = 0; c < p->s.npk; c++) kv[c] = k.kv[c];
            if (!(rc = imdb_lookup_pk_at(db, p, kv, snap, pend, &seen, e)) && seen == IMDB_NONE)
                rc = imdb_fail(e, IMDB_ERR_CONFLICT, "could not serialize access: the row foreign key %s references was "
                               "inserted by a commit after this transaction's snapshot; retry the transaction", f->name);
        }
    } else {
        uint64_t seen = IMDB_NONE;
        imdb_value kv[IMDB_MAX_KEY_COLS];
        for (int c = 0; c < p->s.npk; c++) kv[c] = k.kv[c];
        if (!(rc = imdb_lookup_pk_at(db, p, kv, snap, pend, &seen, e)))
            rc = seen != IMDB_NONE
                     ? imdb_fail(e, IMDB_ERR_CONFLICT, "could not serialize access: the row foreign key %s references was "
                                 "deleted by a commit after this transaction's snapshot; retry the transaction", f->name)
                     : imdb_fail(e, IMDB_ERR_CONSTRAINT, "insert or update on table %s violates foreign key constraint %s",
                                 t->s.name, f->name);
    }
    imdb_pkey_done(&k);
    return rc;
}

/* a parent key the writes deleted, with no live version left: no live child of it in any FK referencing p */
static int check_parent(imdb_db *db, imdb_table *p, const imdb_value *k, uint64_t snap, imdb_err *e)
{
    for (uint32_t ci = 0; ci < db->nt; ci++) {
        imdb_table *c = db->t[ci];
        if (!c || c->dropped_at || !c->hist.nfk) continue;
        for (uint16_t i = 0; i < c->hist.nfk; i++) {
            const imdb_fk *f = &c->hist.fk[i];
            if (f->parent != p->s.id) continue;
            if (fkm_ready(db, c, e)) return e->code;
            uint64_t *slot = imdb_hmap_get(&c->fkm->m[i].map, k);
            if (!slot) continue;
            const fkvec *vec = &c->fkm->m[i].vecs[*slot];
            for (uint32_t r = 0; r < vec->n; r++) {
                if (!imdb_v_held(c, vec->v[r])) continue;
                const imdb_version *v = imdb_vh(c, vec->v[r]);
                if (!v_live(v)) continue;
                if (visible(db, v, snap))
                    return imdb_fail(e, IMDB_ERR_CONSTRAINT, "update or delete on table %s violates foreign key constraint %s "
                                     "on table %s", p->s.name, f->name, c->s.name);
                return imdb_fail(e, IMDB_ERR_CONFLICT, "could not serialize access: a row referencing table %s by foreign key "
                                 "%s was inserted by a commit after this transaction's snapshot; retry the transaction",
                                 p->s.name, f->name);
            }
        }
    }
    return IMDB_OK;
}

static bool referenced(const imdb_db *db, uint32_t pid)
{
    for (uint32_t ci = 0; ci < db->nt; ci++) {
        const imdb_table *c = db->t[ci];
        if (!c || c->dropped_at) continue;
        for (uint16_t i = 0; i < c->hist.nfk; i++)
            if (c->hist.fk[i].parent == pid) return true;
    }
    return false;
}

int imdb_fk_check(imdb_db *db, uint32_t from, imdb_err *e)
{
    uint64_t snap = 0, pend = 0;
    imdb_txn_write_view(db, &snap, &pend);
    imdb_value vals[IMDB_MAX_COLS], old[IMDB_MAX_COLS];
    int rc = IMDB_OK;
    const imdb_op *er = NULL; /* an ERASE's own deletes end no parent key (erase_names) */
    for (uint32_t i = 0; i < db->ntx; i++)
        if (db->tx[i].code == IMDB_OP_ERASE) er = &db->tx[i];
    for (uint32_t i = from; i < db->ntx && !rc; i++) {
        const imdb_op *o = &db->tx[i];
        if (o->code != IMDB_OP_INSERT && o->code != IMDB_OP_UPDATE && o->code != IMDB_OP_DELETE) continue;
        imdb_table *t = o->table < db->nt ? db->t[o->table] : NULL;
        if (!t) continue;
        if (o->code != IMDB_OP_DELETE && t->hist.nfk) { /* a child version written */
            uint64_t nv = o->code == IMDB_OP_INSERT ? o->vid : o->new_vid;
            if (!imdb_v_held(t, nv) || !v_live(imdb_vh(t, nv))) continue; /* ended since in this transaction */
            if ((rc = imdb_version_values_v(t, imdb_vh(t, nv), vals, e))) break;
            bool own_old = false, have_old = false;
            if (o->code == IMDB_OP_UPDATE && imdb_v_held(t, o->vid)) {
                const imdb_version *ov = imdb_vh(t, o->vid);
                own_old = ov->begin > db->seq; /* written in this transaction: its own check was skipped (not live) */
                have_old = !own_old && !(ov->flags & (IMDB_V_STUB | IMDB_V_PURGED)) &&
                           imdb_version_values_v(t, ov, old, e) == IMDB_OK;
            }
            for (uint16_t k = 0; k < t->hist.nfk && !rc; k++) {
                const imdb_fk *f = &t->hist.fk[k];
                if (have_old) { /* PostgreSQL's rule: an update leaving the FK's columns as they were is not checked */
                    const imdb_sver *cur = &t->hist.vers[t->hist.nvers - 1];
                    bool same = true;
                    for (uint8_t c = 0; c < f->ncols && same; c++) {
                        int col = cur->at[f->cols[c]];
                        same = imdb_value_cmp(&vals[col], &old[col]) == 0 && vals[col].null == old[col].null;
                    }
                    if (same) continue;
                }
                rc = check_child(db, t, f, vals, snap, pend, e);
            }
        }
        if (o->code == IMDB_OP_DELETE && !erase_names(er, o->table, o->vid) && referenced(db, t->s.id)) { /* a parent key deleted */
            imdb_pkey k;
            if (!imdb_v_held(t, o->vid) || imdb_version_pkey(t, o->vid, &k) != IMDB_OK) continue;
            if (parent_live(t, &k.v) == IMDB_NONE) rc = check_parent(db, t, &k.v, snap, e);
            imdb_pkey_done(&k);
        }
    }
    return rc;
}

/* ---- the catalog's rules (the engine's CREATE and ALTER, replay and VERIFY alike) ---- */

int imdb_fk_def_check(const imdb_sver *ccur, const imdb_sver *pcur, bool parent_live, const imdb_fk *f, imdb_err *e)
{
    const imdb_schema *cs = &ccur->s, *ps = pcur ? &pcur->s : NULL;
    if (!imdb_fks_ok(f, 1)) return imdb_fail(e, IMDB_ERR_INVALID, "foreign key %s: a name, 1 to %u columns, an action", f->name, IMDB_MAX_KEY_COLS);
    if (!ps || !parent_live) return imdb_fail(e, IMDB_ERR_INVALID, "foreign key %s references no live table", f->name);
    if (ps->npk != f->ncols)
        return imdb_fail(e, IMDB_ERR_INVALID, "foreign key %s: %u columns referencing a key of %u", f->name, f->ncols, ps->npk);
    for (uint8_t i = 0; i < f->ncols; i++) {
        int cc = f->cols[i] < ccur->npos ? ccur->at[f->cols[i]] : -1;
        if (cc < 0) return imdb_fail(e, IMDB_ERR_INVALID, "foreign key %s names a column table %s does not have", f->name, cs->name);
        int pc = ps->key[i];
        if (f->pcols[i] != pcur->pos[pc])
            return imdb_fail(e, IMDB_ERR_INVALID, "foreign key %s references other columns than table %s's primary key, in its "
                             "order", f->name, ps->name);
        const imdb_column *a = &cs->cols[cc], *b = &ps->cols[pc];
        if (a->type != b->type || (a->type == IMDB_T_DECIMAL && a->scale != b->scale))
            return imdb_fail(e, IMDB_ERR_INVALID, "foreign key %s: column %s is %s, the key column %s it references %s (a "
                             "DECIMAL's scale its own)", f->name, a->name, imdb_type_name(a->type), b->name, imdb_type_name(b->type));
        if (a->type == IMDB_T_DECIMAL && imdb_dec_wide(a->precision) != imdb_dec_wide(b->precision)) /* F3e: deferred.md D25 */
            return imdb_fail(e, IMDB_ERR_UNSUPPORTED, "foreign key %s: column %s and the key column %s it references are DECIMALs, "
                             "one of 18 digits or fewer and one of more: not yet", f->name, a->name, b->name);
        if (f->on_delete == IMDB_FK_SET_NULL && !(a->flags & IMDB_COL_NULLABLE))
            return imdb_fail(e, IMDB_ERR_INVALID, "foreign key %s: ON DELETE SET NULL of NOT NULL column %s", f->name, a->name);
    }
    return IMDB_OK;
}

int imdb_fk_rows_check(imdb_db *db, imdb_table *t, const imdb_fk *f, imdb_err *e)
{
    imdb_table *p = f->parent < db->nt ? db->t[f->parent] : NULL;
    if (!p) return imdb_fail(e, IMDB_ERR_INVALID, "foreign key %s references no live table", f->name);
    imdb_value vals[IMDB_MAX_COLS];
    int rc = IMDB_OK;
    for (uint64_t vid = imdb_v_next(t, 0); vid < t->nver && !rc; vid = imdb_v_next(t, vid + 1)) {
        const imdb_version *v = imdb_vh(t, vid);
        if (!v_live(v)) continue;
        if ((rc = imdb_version_values_v(t, v, vals, e))) break;
        imdb_pkey k;
        bool null;
        if ((rc = fk_key(db, t, f, vals, &k, &null, e)) || null) continue;
        if (parent_live(p, &k.v) == IMDB_NONE && !p->live_stubs) /* replay before an ERASE: an erased row's key, unknown */
            rc = imdb_fail(e, IMDB_ERR_CONSTRAINT, "insert or update on table %s violates foreign key constraint %s: a row "
                           "references a key table %s does not hold", t->s.name, f->name, p->s.name);
        imdb_pkey_done(&k);
    }
    return rc;
}

bool imdb_fk_referenced(const imdb_db *db, uint32_t pid, const char **which)
{
    for (uint32_t ci = 0; ci < db->nt; ci++) {
        const imdb_table *c = db->t[ci];
        if (!c || c->dropped_at || ci == pid) continue; /* a self-reference goes with its table */
        for (uint16_t i = 0; i < c->hist.nfk; i++)
            if (c->hist.fk[i].parent == pid) {
                if (which) *which = c->hist.fk[i].name;
                return true;
            }
    }
    return false;
}

int imdb_fk_children(imdb_db *db, imdb_table *c, uint16_t fki, const imdb_value *k, uint64_t **out, uint32_t *n, imdb_err *e)
{
    *out = NULL;
    *n = 0;
    if (fki >= c->hist.nfk) return IMDB_OK;
    if (fkm_ready(db, c, e)) return e->code;
    uint64_t *slot = imdb_hmap_get(&c->fkm->m[fki].map, k);
    if (!slot) return IMDB_OK;
    const fkvec *vec = &c->fkm->m[fki].vecs[*slot];
    uint64_t *v = vec->n ? imdb_alloc_array(vec->n, sizeof *v, e) : NULL;
    if (vec->n && !v) return e->code;
    for (uint32_t r = 0; r < vec->n; r++)
        if (imdb_v_held(c, vec->v[r]) && v_live(imdb_vh(c, vec->v[r]))) v[(*n)++] = vec->v[r];
    *out = v;
    return IMDB_OK;
}

/* ---- replay's and a replica's apply (docs/fk-design.md section 5): referential integrity at a commit's end, by the
 * versions it wrote and ended: a child version live at the end, new or with its FK key other than the version before
 * the commit's (its chain of ends followed back through the commit), has a live parent of its key; a parent key the
 * commit ended with none of its versions live at the end has no live child. A forged commit is refused (CORRUPT) ---- */

/* the version vid replaced before the commit: follow op 4's chain back through the commit's own versions (IMDB_NONE:
 * a row the commit made) */
static uint64_t ancestor(const imdb_commit_rec *c, uint32_t table, uint64_t vid)
{
    for (;;) {
        uint64_t prev = IMDB_NONE;
        bool made_here = false;
        for (uint32_t i = 0; i < c->nops; i++) {
            const imdb_op *o = &c->ops[i];
            if (o->table != table) continue;
            if (o->code == IMDB_OP_UPDATE && o->new_vid == vid) prev = o->vid;
            if (o->code == IMDB_OP_INSERT && o->vid == vid) made_here = true;
        }
        if (made_here || prev == IMDB_NONE) return made_here ? IMDB_NONE : vid;
        bool prev_here = false; /* the old side one of this commit's own new versions? then on back */
        for (uint32_t i = 0; i < c->nops && !prev_here; i++) {
            const imdb_op *o = &c->ops[i];
            prev_here = o->table == table && ((o->code == IMDB_OP_INSERT && o->vid == prev) || (o->code == IMDB_OP_UPDATE && o->new_vid == prev));
        }
        if (!prev_here) return prev;
        vid = prev;
    }
}

int imdb_fk_verify_commit(imdb_db *db, const imdb_commit_rec *c, uint64_t seq, imdb_err *e)
{
    imdb_value vals[IMDB_MAX_COLS], old[IMDB_MAX_COLS];
    int rc = IMDB_OK;
    const imdb_op *er = NULL; /* the deletes its ERASE names are the erasure's: no parent key's delete (design.md §5) */
    for (uint32_t i = 0; i < c->nops; i++)
        if (c->ops[i].code == IMDB_OP_ERASE) er = &c->ops[i];
    for (uint32_t i = 0; i < c->nops && !rc; i++) {
        const imdb_op *o = &c->ops[i];
        if (o->code != IMDB_OP_INSERT && o->code != IMDB_OP_UPDATE && o->code != IMDB_OP_DELETE) continue;
        imdb_table *t = o->table < db->nt ? db->t[o->table] : NULL;
        if (!t) continue;
        if (o->code != IMDB_OP_DELETE && t->hist.nfk) {
            uint64_t nv = o->code == IMDB_OP_INSERT ? o->vid : o->new_vid;
            if (!imdb_v_held(t, nv) || !v_live(imdb_vh(t, nv))) continue;
            if ((rc = imdb_version_values_v(t, imdb_vh(t, nv), vals, e))) break;
            uint64_t anc = ancestor(c, o->table, nv);
            bool have_old = anc != IMDB_NONE && imdb_v_held(t, anc) && !(imdb_vh(t, anc)->flags & (IMDB_V_STUB | IMDB_V_PURGED)) &&
                            imdb_version_values_v(t, imdb_vh(t, anc), old, e) == IMDB_OK;
            const imdb_sver *cur = &t->hist.vers[t->hist.nvers - 1];
            for (uint16_t k = 0; k < t->hist.nfk && !rc; k++) {
                const imdb_fk *f = &t->hist.fk[k];
                if (have_old) {
                    bool same = true;
                    for (uint8_t q = 0; q < f->ncols && same; q++) {
                        int col = cur->at[f->cols[q]];
                        same = vals[col].null == old[col].null && (vals[col].null || imdb_value_cmp(&vals[col], &old[col]) == 0);
                    }
                    if (same) continue;
                }
                imdb_pkey key;
                bool null;
                if ((rc = fk_key(db, t, f, vals, &key, &null, e)) || null) continue;
                if (parent_live(db->t[f->parent], &key.v) == IMDB_NONE && !db->t[f->parent]->live_stubs) /* an erased row's key: unknown */
                    rc = imdb_fail(e, IMDB_ERR_CORRUPT, "commit %llu: a row of table %s violates foreign key %s: its parent key is "
                                   "not live", (unsigned long long)seq, t->s.name, f->name);
                imdb_pkey_done(&key);
            }
        }
        if (o->code == IMDB_OP_DELETE && !erase_names(er, o->table, o->vid) && referenced(db, t->s.id)) {
            imdb_pkey key;
            if (!imdb_v_held(t, o->vid) || imdb_version_pkey(t, o->vid, &key) != IMDB_OK) continue;
            if (parent_live(t, &key.v) == IMDB_NONE) {
                imdb_err e2 = {0};
                if (check_parent(db, t, &key.v, UINT64_MAX, &e2))
                    rc = e2.code == IMDB_ERR_NOMEM ? imdb_fail(e, e2.code, "%s", e2.msg)
                                                   : imdb_fail(e, IMDB_ERR_CORRUPT, "commit %llu: %s", (unsigned long long)seq, e2.msg);
            }
            imdb_pkey_done(&key);
        }
    }
    return rc;
}
