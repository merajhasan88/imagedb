/* ERASE: removal of a data subject's payloads from all history, everywhere. */
#include <stdlib.h>

#include "db_internal.h"

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
        if (!t || ents[i].vid >= t->nver || (i && cmp_ent(&ents[i - 1], &ents[i]) == 0) ||
            (imdb_vh(t, ents[i].vid)->flags & IMDB_V_STUB)) {
            imdb_free(ents);
            return imdb_fail(e, IMDB_ERR_INVALID, "ERASE: invalid or duplicate version");
        }
        memcpy(ents[i].commit, imdb_vc(t, ents[i].vid)->commit, 32);
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
        if (imdb_vh(t, ents[i].vid)->end == IMDB_LIVE) {
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

int imdb_erase_subject(imdb_db *db, const imdb_value *subject, imdb_erase_report *rep, imdb_err *e)
{
    memset(rep, 0, sizeof *rep);
    if (subject->null) return imdb_fail(e, IMDB_ERR_INVALID, "ERASE SUBJECT needs a value, not NULL");
    size_t n = 0, cap = 0;
    imdb_erase_ent *ents = NULL;
    for (uint32_t ti = 0; ti < db->nt; ti++) {
        imdb_table *t = db->t[ti];
        const imdb_vlist *l = imdb_subject_versions(t, subject);
        if (!l) continue;
        for (uint32_t i = 0; i < l->n; i++) {
            if (imdb_vh(t, l->v[i])->flags & IMDB_V_STUB) continue;
            if (n == cap) {
                size_t ncap = cap ? cap * 2 : 64;
                if (ncap > IMDB_MAX_ERASE_ENTRIES) {
                    imdb_free(ents);
                    return imdb_fail(e, IMDB_ERR_LIMIT, "ERASE touches more than %u versions", IMDB_MAX_ERASE_ENTRIES);
                }
                imdb_erase_ent *ne = imdb_realloc_array(ents, cap, ncap, sizeof *ne, e);
                if (!ne) {
                    imdb_free(ents);
                    return e->code;
                }
                ents = ne;
                cap = ncap;
            }
            ents[n].table = ti;
            ents[n].vid = l->v[i];
            n++;
        }
    }
    return imdb_erase_versions(db, ents, (uint32_t)n, rep, e);
}
