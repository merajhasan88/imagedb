/*
 * Session transactions over one engine thread (db.h, docs/txn-design.md).
 *
 * The active transaction's writes are ordinary pending versions (begin or end =
 * seq + 1), with the op list in db->tx and the undo log in db->undo. Switching
 * to another transaction saves the op list (row bytes copied out of the arena
 * before the undo wipes them; a base that is one of its own pending versions is
 * saved as its ordinal among the table's pending versions) and undoes it.
 * Coming back replays the list through the same insert/update/delete checks,
 * so a replay that no longer applies is exactly a write-write conflict.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "db_internal.h"

static void release_ops(imdb_txn *x)
{
    for (uint32_t i = 0; i < x->nops; i++) {
        if (x->ops[i].row) imdb_wipe(x->ops[i].row, x->ops[i].row_len);
        imdb_free(x->ops[i].row);
    }
    if (x->ops) imdb_wipe(x->ops, (size_t)x->capops * sizeof *x->ops);
    imdb_free(x->ops);
    x->ops = NULL;
    x->nops = x->capops = 0;
}

static void doom(imdb_txn *x, const char *why)
{
    x->doomed = true;
    snprintf(x->doom, sizeof x->doom, "could not serialize access: %s; roll back and retry the transaction", why);
}

static void unlink_txn(imdb_db *db, imdb_txn *x)
{
    for (imdb_txn **p = &db->txns; *p; p = &(*p)->next)
        if (*p == x) {
            *p = x->next;
            break;
        }
    x->next = NULL;
}

void imdb_txn_begin(imdb_db *db, imdb_txn *x, uint8_t iso)
{
    memset(x, 0, sizeof *x);
    x->open = true;
    x->iso = iso;
    x->next = db->txns;
    db->txns = x;
}

bool imdb_txn_has_writes(const imdb_db *db, const imdb_txn *x)
{
    return x->open && (db->active == x ? db->ntx > 0 : x->nops > 0);
}

void imdb_txn_view(const imdb_db *db, const imdb_txn *x, uint64_t *snap, uint64_t *pend)
{
    if (x && x->open) {
        *snap = x->started ? x->stmt_snap : db->seq;
        *pend = db->active == x && db->in_txn ? db->seq + 1 : 0;
    } else { /* an autocommit statement: its own engine transaction, if it writes */
        *snap = db->seq;
        *pend = db->in_txn && !db->active ? db->seq + 1 : 0;
    }
}

/* Saves the active transaction's op list and undoes its pending versions. */
static int swap_out(imdb_db *db, imdb_err *e)
{
    imdb_txn *x = db->active;
    if (!x) return IMDB_OK;
    uint32_t n = db->ntx;
    /* the copies are new memory (the arena keeps its capacity for the next writer): admitted like
     * any growth (db.h), so a parked transaction cannot hold its size twice past the budget */
    uint64_t copy = (uint64_t)n * sizeof(imdb_saved_op);
    for (uint32_t i = 0; i < n; i++)
        if (db->tx[i].code == IMDB_OP_INSERT || db->tx[i].code == IMDB_OP_UPDATE) copy += db->tx[i].row_len;
    int arc = imdb_mem_admit(db, copy, e);
    if (arc) return arc;
    uint64_t *pend = imdb_alloc_array(db->nt ? db->nt : 1, sizeof *pend, e);
    imdb_saved_op *ops = n ? imdb_alloc_array(n, sizeof *ops, e) : NULL;
    if (!pend || (n && !ops)) {
        imdb_free(pend);
        imdb_free(ops);
        return e->code;
    }
    for (uint32_t i = 0; i < n; i++) { /* pending versions per table: one per INSERT, one per UPDATE */
        const imdb_op *o = &db->tx[i];
        if (o->code == IMDB_OP_INSERT || o->code == IMDB_OP_UPDATE) pend[o->table]++;
    }
    int rc = IMDB_OK;
    for (uint32_t i = 0; i < n && !rc; i++) {
        const imdb_op *o = &db->tx[i];
        imdb_saved_op *so = &ops[i];
        if (o->code != IMDB_OP_INSERT && o->code != IMDB_OP_DELETE && o->code != IMDB_OP_UPDATE) {
            rc = imdb_fail(e, IMDB_ERR_STATE, "a transaction holding DDL or a physical operation cannot be suspended");
            break;
        }
        const imdb_table *t = db->t[o->table];
        uint64_t first = t->nver - pend[o->table]; /* pending versions are the newest */
        so->code = o->code;
        so->table = o->table;
        if (o->code != IMDB_OP_INSERT) {
            so->base_pending = o->vid >= first;
            so->base = so->base_pending ? o->vid - first : o->vid;
        }
        if (o->code != IMDB_OP_DELETE) {
            memcpy(so->salt, o->salt, 16);
            so->row_len = o->row_len;
            so->row = imdb_alloc(o->row_len ? o->row_len : 1, e);
            if (!so->row) {
                rc = e->code;
                break;
            }
            memcpy(so->row, t->arena.p + db->tx_row_off[i], o->row_len);
        }
    }
    imdb_free(pend);
    if (rc) {
        imdb_txn tmp = {.ops = ops, .nops = n, .capops = n};
        release_ops(&tmp);
        return rc;
    }
    imdb_rollback(db); /* the pending versions go; their bytes are saved above */
    x->ops = ops;
    x->nops = x->capops = n;
    db->active = NULL;
    return IMDB_OK;
}

static bool locks_live(const imdb_db *db, const imdb_txn *x)
{
    for (uint32_t i = 0; i < x->nlocks; i++) {
        const imdb_table *t = db->t[x->locks[i].table];
        const imdb_version *v = imdb_vh(t, x->locks[i].vid);
        /* seq+1 is an uncommitted end, including our own UPDATE/DELETE.
         * Only a committed change can break an optimistic observation. */
        if (v->end <= db->seq || (v->flags & (IMDB_V_STUB | IMDB_V_PURGED))) return false;
    }
    return true;
}

/* Replays x's saved op list with the checks of the statements that made it. */
static int swap_in(imdb_db *db, imdb_txn *x, imdb_err *e)
{
    if (imdb_begin(db, e)) return e->code;
    db->active = x;
    uint64_t *start = imdb_alloc_array(db->nt ? db->nt : 1, sizeof *start, e);
    if (!start) {
        imdb_rollback(db);
        db->active = NULL;
        return e->code;
    }
    for (uint32_t t = 0; t < db->nt; t++) start[t] = db->t[t]->nver;
    imdb_err e2 = {0};
    int rc = IMDB_OK;
    for (uint32_t i = 0; i < x->nops && !rc; i++) {
        const imdb_saved_op *so = &x->ops[i];
        imdb_table *t = imdb_table_by_id(db, so->table);
        uint64_t base = so->base_pending ? start[so->table] + so->base : so->base;
        switch (so->code) {
        case IMDB_OP_INSERT: rc = imdb_insert_row(db, t, so->row, so->row_len, so->salt, &e2); break;
        case IMDB_OP_DELETE: rc = imdb_delete(db, t, base, &e2); break;
        default: rc = imdb_update_row(db, t, base, so->row, so->row_len, so->salt, &e2); break;
        }
    }
    imdb_free(start);
    if (!rc && !locks_live(db, x)) rc = imdb_fail(&e2, IMDB_ERR_CONFLICT, "a locked row changed");
    if (rc) {
        imdb_rollback(db);
        db->active = NULL;
        if (rc == IMDB_ERR_NOMEM || rc == IMDB_ERR_LIMIT) return imdb_fail(e, rc, "%s", e2.msg);
        char why[384];
        snprintf(why, sizeof why, "a row this transaction writes was changed by a commit after its snapshot (%s)", e2.msg);
        doom(x, why);
        release_ops(x);
        return imdb_fail(e, IMDB_ERR_CONFLICT, "%s", x->doom);
    }
    release_ops(x);
    return IMDB_OK;
}

int imdb_txn_park(imdb_db *db, imdb_err *e) { return swap_out(db, e); }

int imdb_txn_enter(imdb_db *db, imdb_txn *x, int need, imdb_err *e)
{
    if (!x->open) return imdb_fail(e, IMDB_ERR_STATE, "no transaction is open");
    if (x->doomed) return imdb_fail(e, IMDB_ERR_CONFLICT, "%s", x->doom);
    if (!x->started) {
        x->snap = db->seq;
        x->started = true;
    }
    x->stmt_snap = x->iso == IMDB_ISO_READ_COMMITTED ? db->seq : x->snap;
    if (db->active == x) return IMDB_OK;
    /* a reader with no pending marker sees nobody's pending versions: no switch needed */
    if (need == IMDB_TXN_READ && x->nops == 0) return IMDB_OK;
    if (db->in_txn && !db->active)
        return imdb_fail(e, IMDB_ERR_STATE, "the engine transaction of another caller is open");
    if (swap_out(db, e)) return e->code;
    if (x->nops) return swap_in(db, x, e);
    if (imdb_begin(db, e)) return e->code;
    db->active = x;
    return IMDB_OK;
}

static void close_txn(imdb_db *db, imdb_txn *x)
{
    release_ops(x);
    imdb_free(x->locks);
    x->locks = NULL;
    x->nlocks = x->caplocks = 0;
    imdb_free(x->sps);
    x->sps = NULL;
    x->nsps = x->capsps = 0;
    unlink_txn(db, x);
    x->open = x->started = x->doomed = false;
}

void imdb_txn_rollback(imdb_db *db, imdb_txn *x)
{
    if (!x->open) return;
    if (db->active == x) {
        imdb_rollback(db);
        db->active = NULL;
    }
    close_txn(db, x);
}

int imdb_txn_commit(imdb_db *db, imdb_txn *x, imdb_err *e)
{
    if (!x->open) return imdb_fail(e, IMDB_ERR_STATE, "no transaction is open");
    if (x->doomed) {
        char why[sizeof x->doom];
        snprintf(why, sizeof why, "%s", x->doom);
        imdb_txn_rollback(db, x);
        return imdb_fail(e, IMDB_ERR_CONFLICT, "%s", why);
    }
    int rc = IMDB_OK;
    if (!imdb_txn_has_writes(db, x)) { /* read-only: its locks must still hold */
        if (db->active == x) {
            imdb_rollback(db);
            db->active = NULL;
        }
        if (!locks_live(db, x)) rc = imdb_fail(e, IMDB_ERR_CONFLICT, "could not serialize access: a row locked FOR UPDATE changed; retry the transaction");
        close_txn(db, x);
        return rc;
    }
    if ((rc = imdb_txn_enter(db, x, IMDB_TXN_WRITE, e))) {
        imdb_txn_rollback(db, x);
        return rc;
    }
    if (!locks_live(db, x)) {
        imdb_txn_rollback(db, x);
        return imdb_fail(e, IMDB_ERR_CONFLICT, "could not serialize access: a row locked FOR UPDATE changed; retry the transaction");
    }
    rc = imdb_commit(db, e); /* on failure the engine undoes every pending version */
    db->active = NULL;
    close_txn(db, x);
    return rc;
}

static int cmp_lock(const void *a, const void *b)
{
    const imdb_txn_lock *x = a, *y = b;
    if (x->table != y->table) return x->table < y->table ? -1 : 1;
    return x->vid < y->vid ? -1 : x->vid > y->vid;
}

/* x->locks is kept sorted and unique, so one statement's rows join it in
 * O((locks + rows) log) rather than a scan per row; all of them or none. */
int imdb_txn_lock_rows(imdb_db *db, imdb_txn *x, const imdb_table *t, const uint64_t *vids, uint64_t n,
                       imdb_err *e)
{
    imdb_txn_lock *add = imdb_alloc_array(n ? n : 1, sizeof *add, e);
    if (!add) return e->code;
    uint64_t na = 0;
    int rc = IMDB_OK;
    for (uint64_t i = 0; i < n && !rc; i++) {
        const imdb_version *v = imdb_vh(t, vids[i]);
        imdb_txn_lock k = {t->s.id, vids[i]};
        if (v->begin == db->seq + 1) continue; /* its own pending row needs no lock */
        if (v->end <= db->seq || (v->flags & (IMDB_V_STUB | IMDB_V_PURGED)))
            rc = imdb_fail(e, IMDB_ERR_CONFLICT,
                           "could not serialize access: a row selected FOR UPDATE was changed by a commit after the "
                           "snapshot; retry the transaction");
        else if (!x->nlocks || !bsearch(&k, x->locks, x->nlocks, sizeof k, cmp_lock))
            add[na++] = k;
    }
    uint64_t u = 0;
    if (!rc && na) {
        qsort(add, na, sizeof *add, cmp_lock);
        for (uint64_t i = 0; i < na; i++)
            if (!u || cmp_lock(&add[u - 1], &add[i]) != 0) add[u++] = add[i];
        if (u > db->lim_txn_locks - x->nlocks)
            rc = imdb_fail(e, IMDB_ERR_LIMIT, "transaction exceeds %u rows selected FOR UPDATE", db->lim_txn_locks);
    }
    imdb_txn_lock *m = !rc && u ? imdb_alloc_array(x->nlocks + u, sizeof *m, e) : NULL;
    if (!rc && u && !m) rc = e->code;
    if (m) {
        uint64_t i = 0, j = 0, o = 0;
        while (i < x->nlocks || j < u)
            m[o++] = j == u || (i < x->nlocks && cmp_lock(&x->locks[i], &add[j]) < 0) ? x->locks[i++] : add[j++];
        imdb_free(x->locks);
        x->locks = m;
        x->nlocks = x->caplocks = (uint32_t)o;
    }
    imdb_free(add);
    return rc;
}

static int cmp_ent(const void *a, const void *b)
{
    const imdb_erase_ent *x = a, *y = b;
    if (x->table != y->table) return x->table < y->table ? -1 : 1;
    return x->vid < y->vid ? -1 : x->vid > y->vid;
}

static bool erased(const imdb_erase_ent *ents, uint32_t n, uint32_t table, uint64_t vid)
{
    imdb_erase_ent k = {.table = table, .vid = vid};
    return n && bsearch(&k, ents, n, sizeof k, cmp_ent) != NULL;
}

void imdb_txn_doom_erased(imdb_db *db, const imdb_erase_ent *ents, uint32_t n)
{
    for (imdb_txn *x = db->txns; x; x = x->next) {
        bool hit = false;
        for (uint32_t i = 0; i < x->nops && !hit; i++)
            hit = x->ops[i].code != IMDB_OP_INSERT && !x->ops[i].base_pending &&
                  erased(ents, n, x->ops[i].table, x->ops[i].base);
        for (uint32_t i = 0; i < x->nlocks && !hit; i++) hit = erased(ents, n, x->locks[i].table, x->locks[i].vid);
        if (!hit) continue;
        if (!x->doomed) doom(x, "a row this transaction writes or locked was erased");
        release_ops(x); /* the saved bytes may be the erased row's last copy */
    }
}

void imdb_txn_discard(imdb_db *db, imdb_txn *x)
{
    if (!x->open || !x->doomed) return;
    if (db->active == x) {
        imdb_rollback(db);
        db->active = NULL;
    }
    release_ops(x);
}

void imdb_txn_write_view(const imdb_db *db, uint64_t *snap, uint64_t *pend)
{
    *snap = db->active ? db->active->stmt_snap : db->seq;
    *pend = db->seq + 1;
}

void imdb_txn_doom(imdb_txn *x, const char *why)
{
    if (x->doomed) return;
    x->doomed = true;
    snprintf(x->doom, sizeof x->doom, "%s", why);
}

static uint32_t op_count(const imdb_db *db, const imdb_txn *x) { return db->active == x ? db->ntx : x->nops; }

static int live_txn(const imdb_txn *x, imdb_err *e)
{
    if (!x->open) return imdb_fail(e, IMDB_ERR_STATE, "savepoints need a transaction (BEGIN)");
    if (x->doomed) return imdb_fail(e, IMDB_ERR_CONFLICT, "%s", x->doom);
    return IMDB_OK;
}

static int find_sp(const imdb_txn *x, const char *name, imdb_err *e)
{
    for (uint32_t i = x->nsps; i-- > 0;) /* the latest of that name */
        if (strcmp(x->sps[i].name, name) == 0) return (int)i;
    return imdb_fail(e, IMDB_ERR_NOTFOUND, "no savepoint %s", name);
}

int imdb_txn_savepoint(imdb_db *db, imdb_txn *x, const char *name, imdb_err *e)
{
    if (live_txn(x, e)) return e->code;
    if (strlen(name) > IMDB_MAX_IDENT) return imdb_fail(e, IMDB_ERR_LIMIT, "savepoint name too long");
    if (x->nsps >= IMDB_MAX_SAVEPOINTS)
        return imdb_fail(e, IMDB_ERR_LIMIT, "transaction holds %u savepoints; RELEASE some first", IMDB_MAX_SAVEPOINTS);
    if (x->nsps == x->capsps) {
        uint32_t nc = x->capsps ? x->capsps * 2 : 8;
        imdb_txn_sp *n = imdb_realloc_array(x->sps, x->capsps, nc, sizeof *n, e);
        if (!n) return e->code;
        x->sps = n;
        x->capsps = nc;
    }
    imdb_txn_sp *sp = &x->sps[x->nsps++];
    snprintf(sp->name, sizeof sp->name, "%s", name);
    sp->pos = op_count(db, x);
    return IMDB_OK;
}

int imdb_txn_rollback_to(imdb_db *db, imdb_txn *x, const char *name, imdb_err *e)
{
    if (live_txn(x, e)) return e->code;
    int k = find_sp(x, name, e);
    if (k < 0) return e->code;
    uint32_t pos = x->sps[k].pos;
    if (db->active == x) {
        /* the undo log of the op prefix: one entry per INSERT or DELETE, two per UPDATE */
        imdb_savepoint sp = {pos, 0};
        for (uint32_t i = 0; i < pos; i++) sp.nundo += db->tx[i].code == IMDB_OP_UPDATE ? 2 : 1;
        imdb_savepoint_restore(db, sp);
    } else {
        for (uint32_t i = pos; i < x->nops; i++) {
            if (x->ops[i].row) imdb_wipe(x->ops[i].row, x->ops[i].row_len);
            imdb_free(x->ops[i].row);
            memset(&x->ops[i], 0, sizeof x->ops[i]);
        }
        if (pos < x->nops) x->nops = pos;
        if (!x->nops) release_ops(x); /* an empty list holds no array: entering then skips swap_in */
    }
    x->nsps = (uint32_t)k + 1; /* later savepoints go; this one stays */
    return IMDB_OK;
}

int imdb_txn_release(imdb_db *db, imdb_txn *x, const char *name, imdb_err *e)
{
    (void)db;
    if (live_txn(x, e)) return e->code;
    int k = find_sp(x, name, e);
    if (k < 0) return e->code;
    x->nsps = (uint32_t)k;
    return IMDB_OK;
}
