/* ERASE: removal of a data subject's payloads from all history, everywhere. */
#include <stdlib.h>

#include "cpu.h"
#include "db_internal.h"
#include "lake.h"

static int cmp_ent(const void *a, const void *b)
{
    const imdb_erase_ent *x = a, *y = b;
    if (x->table != y->table) return x->table < y->table ? -1 : 1;
    return x->vid < y->vid ? -1 : x->vid > y->vid;
}


int imdb_erase_versions(imdb_db *db, imdb_erase_ent *ents, uint32_t n, imdb_erase_report *rep, imdb_err *e)
{
    memset(rep, 0, sizeof *rep);
    if (db->in_txn) {
        imdb_free(ents);
        return imdb_fail(e, IMDB_ERR_STATE, "ERASE must run outside an explicit transaction");
    }
    if (n == 0) {
        imdb_free(ents);
        return IMDB_OK;
    }
    /* sorted, unique, existing, not yet erased: the log entry must be a pure
     * function of the state so replicas and verifiers recompute it exactly */
    qsort(ents, n, sizeof *ents, cmp_ent);
    uint32_t last_table = UINT32_MAX;
    for (uint32_t i = 0; i < n; i++) {
        imdb_table *t = imdb_table_by_id(db, ents[i].table);
        imdb_vloc at;
        int where = t ? imdb_v_find(t, ents[i].vid, &at) : IMDB_VAT_NONE;
        bool stub = where == IMDB_VAT_HELD ? (at.v->flags & IMDB_V_STUB) != 0
                                           : where == IMDB_VAT_LAKE && (at.g->flags[at.row] & IMDB_SEG_STUB);
        if (where == IMDB_VAT_NONE || (i && cmp_ent(&ents[i - 1], &ents[i]) == 0) || stub) {
            imdb_free(ents);
            return imdb_fail(e, IMDB_ERR_INVALID, "ERASE: invalid or duplicate version");
        }
        memcpy(ents[i].commit, imdb_v_commit(t, ents[i].vid), 32);
        if (ents[i].table != last_table) {
            rep->tables++;
            last_table = ents[i].table;
        }
    }
    if (imdb_begin(db, e)) {
        imdb_free(ents);
        return e->code;
    }
    for (uint32_t i = 0; i < n; i++) {
        imdb_table *t = db->t[ents[i].table];
        if (imdb_v_held(t, ents[i].vid) && imdb_vh(t, ents[i].vid)->end == IMDB_LIVE) { /* a live one is always held */
            if (imdb_delete(db, t, ents[i].vid, e)) {
                imdb_rollback(db);
                imdb_free(ents);
                return e->code;
            }
            rep->live_deleted++;
        }
    }
    imdb_rewrite *rw = NULL;
    uint32_t nrw = 0;
    uint8_t manifest[32];
    if (imdb_lake_plan_erase(db, ents, n, &rw, &nrw, manifest, e) ||
        imdb_tx_add_erase(db, ents, n, rw, nrw, manifest, e)) {
        imdb_rollback(db);
        imdb_free(ents);
        imdb_free(rw);
        return e->code;
    }
    rep->versions = n;
    rep->segments_rewritten = nrw;
    int rc = imdb_commit(db, e);
    rep->redaction_pending = !rc && (db->needs_redaction || db->lake_pending || db->gc_pending || db->failed);
    return rc;
}

static int ent_push(imdb_erase_ent **ents, size_t *n, size_t *cap, uint32_t table, uint64_t vid, imdb_err *e)
{
    if (*n == *cap) {
        size_t ncap = *cap ? *cap * 2 : 64;
        if (ncap > IMDB_MAX_ERASE_ENTRIES)
            return imdb_fail(e, IMDB_ERR_LIMIT, "ERASE touches more than %u versions", IMDB_MAX_ERASE_ENTRIES);
        imdb_erase_ent *ne = imdb_realloc_array(*ents, *cap, ncap, sizeof *ne, e);
        if (!ne) return e->code;
        *ents = ne;
        *cap = ncap;
    }
    memset(&(*ents)[*n], 0, sizeof **ents);
    (*ents)[*n].table = table;
    (*ents)[(*n)++].vid = vid;
    return IMDB_OK;
}

#ifdef IMDB_STORE_CHECKS
/* the subject index holds exactly the subject's versions the store holds and the lake path found (sorted) */
static void subject_cross_check(imdb_table *t, const imdb_value *subject, const imdb_erase_ent *found, size_t n)
{
    const imdb_vlist *l = imdb_subject_versions(t, subject);
    size_t held = 0;
    for (size_t i = 0; i < n; i++) held += imdb_v_held(t, found[i].vid);
    size_t listed = 0;
    for (uint32_t i = 0; l && i < l->n; i++) {
        if (imdb_vh(t, l->v[i])->flags & IMDB_V_STUB) continue;
        bool in = false;
        for (size_t j = 0; j < n && !in; j++) in = found[j].vid == l->v[i];
        if (!in) imdb_v_misuse(t, l->v[i], "in the subject index but not found by ERASE SUBJECT's lake path");
        listed++;
    }
    if (listed != held) imdb_v_misuse(t, t->nver, "ERASE SUBJECT's lake path found a held version the subject index lacks");
}
#endif

/* Table t's versions of the subject that are not erased, from the lake (every segment's subject column: what the
 * store holds is not all of them past stage 3b's memory window) and the memtable; a purged version counts, its
 * tombstone keeps the subject, as the subject index does */
static int subject_versions(imdb_table *t, const imdb_value *subject, imdb_erase_ent **ents, size_t *n, size_t *cap,
                            imdb_err *e)
{
    if (t->s.subject < 0 || subject->null || subject->type != t->s.cols[t->s.subject].type) return IMDB_OK;
    const imdb_kernels *K = imdb_kern();
    uint64_t *bits = NULL;
    size_t capw = 0, n0 = *n;
    int rc = IMDB_OK;
    for (uint32_t k = 0; k < t->nseg && !rc; k++) {
        const imdb_segment *g = t->seg[k];
        const imdb_segcol *c = &g->col[t->s.subject];
        size_t words = ((size_t)g->nrows + 63) / 64;
        if (c->i64) { /* the column's int64s: one range filter */
            if (words > capw) {
                imdb_free(bits);
                if (!(bits = imdb_alloc_array(words, sizeof *bits, e))) return e->code;
                capw = words;
            }
            K->filter_range_i64(c->i64, g->nrows, subject->i, subject->i, bits);
            for (size_t w = 0; w < words && !rc; w++)
                for (uint64_t m = bits[w]; m && !rc; m &= m - 1) { /* not the stub mask: it covers tombstones too */
                    uint64_t r = w * 64 + (uint64_t)__builtin_ctzll(m);
                    if (!(g->flags[r] & IMDB_SEG_STUB)) rc = ent_push(ents, n, cap, t->s.id, g->vid[r], e);
                }
            continue;
        }
        for (uint32_t r = 0; r < g->nrows && !rc; r++) {
            if (g->flags[r] & IMDB_SEG_STUB) continue;
            imdb_value v;
            imdb_seg_get(&t->s, g, r, (uint32_t)t->s.subject, &v);
            if (imdb_value_cmp(&v, subject) == 0) rc = ent_push(ents, n, cap, t->s.id, g->vid[r], e);
        }
    }
    imdb_free(bits);
    for (uint64_t vid = imdb_v_next(t, t->mem_first); vid < t->nver && !rc; vid = imdb_v_next(t, vid + 1)) {
        imdb_value v;
        if (imdb_version_key(t, vid, t->s.subject, &v) == IMDB_OK && imdb_value_cmp(&v, subject) == 0)
            rc = ent_push(ents, n, cap, t->s.id, vid, e);
    }
#ifdef IMDB_STORE_CHECKS
    if (!rc) subject_cross_check(t, subject, *ents + n0, *n - n0);
#else
    (void)n0;
#endif
    return rc;
}

int imdb_erase_subject(imdb_db *db, const imdb_value *subject, imdb_erase_report *rep, imdb_err *e)
{
    memset(rep, 0, sizeof *rep);
    if (subject->null) return imdb_fail(e, IMDB_ERR_INVALID, "ERASE SUBJECT needs a value, not NULL");
    size_t n = 0, cap = 0;
    imdb_erase_ent *ents = NULL;
    for (uint32_t ti = 0; ti < db->nt; ti++) {
        if (subject_versions(db->t[ti], subject, &ents, &n, &cap, e)) {
            imdb_free(ents);
            return e->code;
        }
    }
    return imdb_erase_versions(db, ents, (uint32_t)n, rep, e);
}
