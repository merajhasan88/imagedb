/* L (N2's records): roles, privileges and memberships (role.h, docs/roles-design.md). The writer's statements check,
 * build their op and reserve every room the install needs before the frame, so the install after the durable commit
 * allocates nothing; the replay and VERIFY apply the same rules to their catalog, an op past one CORRUPT (no writer
 * signs it). */
#include "role.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "db_internal.h"

/* ---- lookups --------------------------------------------------------------------------------------------------- */

imdb_role *imdb_rcat_by_name(const imdb_rcat *c, const char *name)
{
    for (uint32_t i = 0; i < c->n; i++) /* IMDB_MAX_ROLES bounds the walk, as the tables' and types' */
        if (!c->roles[i]->dropped_at && !strcmp(c->roles[i]->name, name)) return c->roles[i];
    return NULL;
}

static uint32_t role_index(const imdb_rcat *c, uint32_t id) /* its place in roles, or where it would go */
{
    uint32_t lo = 0, hi = c->n;
    while (lo < hi) {
        uint32_t m = lo + (hi - lo) / 2;
        if (c->roles[m]->id < id) lo = m + 1;
        else hi = m;
    }
    return lo;
}

imdb_role *imdb_rcat_by_id(const imdb_rcat *c, uint32_t id)
{
    uint32_t k = role_index(c, id);
    return k < c->n && c->roles[k]->id == id ? c->roles[k] : NULL;
}

imdb_role *imdb_role_by_name(imdb_db *db, const char *name) { return imdb_rcat_by_name(&db->rc, name); }
imdb_role *imdb_role_by_id(imdb_db *db, uint32_t id) { return imdb_rcat_by_id(&db->rc, id); }

static imdb_role *role_live(const imdb_rcat *c, uint32_t id)
{
    imdb_role *r = imdb_rcat_by_id(c, id);
    return r && !r->dropped_at ? r : NULL;
}

static uint32_t priv_find(const imdb_role *r, uint8_t okind, uint32_t oid)
{
    uint32_t lo = 0, hi = r->nprivs;
    while (lo < hi) {
        uint32_t m = lo + (hi - lo) / 2;
        const imdb_rpriv *p = &r->privs[m];
        if (p->okind < okind || (p->okind == okind && p->oid < oid)) lo = m + 1;
        else hi = m;
    }
    return lo;
}

uint32_t imdb_role_privs(const imdb_role *r, uint8_t okind, uint32_t oid)
{
    uint32_t k = priv_find(r, okind, oid);
    return k < r->nprivs && r->privs[k].okind == okind && r->privs[k].oid == oid ? r->privs[k].privs : 0;
}

static uint32_t group_find(const imdb_role *r, uint32_t g)
{
    uint32_t lo = 0, hi = r->ngroups;
    while (lo < hi) {
        uint32_t m = lo + (hi - lo) / 2;
        if (r->groups[m] < g) lo = m + 1;
        else hi = m;
    }
    return lo;
}

bool imdb_role_member(const imdb_role *r, uint32_t group)
{
    uint32_t k = group_find(r, group);
    return k < r->ngroups && r->groups[k] == group;
}

bool imdb_db_obj_live(const void *arg, uint8_t okind, uint32_t oid)
{
    imdb_db *db = (imdb_db *)(uintptr_t)arg;
    if (okind == IMDB_OBJ_TABLE) {
        imdb_table *t = imdb_table_by_id(db, oid);
        return t && !t->dropped_at;
    }
    return okind == IMDB_OBJ_VIEW && oid < db->nviews && !db->views[oid].dropped_at;
}

/* ---- entries ----------------------------------------------------------------------------------------------------- */

static void ent_free(imdb_rent *x)
{
    if (x->bytes) {
        imdb_wipe(x->bytes, x->len);
        imdb_free(x->bytes);
    }
    memset(x, 0, sizeof *x);
}

/* a statement's new entry: its own random salt (a kept entry's says nothing of an erased one's), its commitment */
static int ent_make(uint32_t role, uint8_t what, const void *bytes, uint32_t len, imdb_rent *x, imdb_err *e)
{
    memset(x, 0, sizeof *x);
    if (!(x->bytes = imdb_alloc(len ? len : 1, e))) return e->code;
    if (len) memcpy(x->bytes, bytes, len);
    x->len = len;
    if (imdb_random(x->salt, sizeof x->salt, e)) {
        ent_free(x);
        return e->code;
    }
    imdb_role_commit(role, what, x->salt, x->bytes, len, x->commit);
    return IMDB_OK;
}

/* a replayed op's entry: the decoder checked its commitment and its shape */
static int ent_take(const imdb_rpay *p, imdb_rent *x, imdb_err *e)
{
    memset(x, 0, sizeof *x);
    memcpy(x->commit, p->commit, 32);
    if (p->pkind != IMDB_PAYLOAD_ROW) return IMDB_OK;
    if (!(x->bytes = imdb_alloc(p->len ? p->len : 1, e))) return e->code;
    if (p->len) memcpy(x->bytes, p->bytes, p->len);
    x->len = p->len;
    memcpy(x->salt, p->salt, 16);
    return IMDB_OK;
}

static void rpay_of(imdb_rpay *p, const imdb_rent *x)
{
    p->pkind = IMDB_PAYLOAD_ROW;
    memcpy(p->salt, x->salt, 16);
    p->bytes = x->bytes;
    p->len = x->len;
    memcpy(p->commit, x->commit, 32);
}

static int verifier_ent(uint32_t id, const imdb_scram *ver, imdb_rent *x, imdb_err *e)
{
    if (!imdb_scram_ok(ver)) return imdb_fail(e, IMDB_ERR_INVALID, "a SCRAM verifier out of its bounds");
    uint8_t vb[IMDB_SCRAM_BYTES_MAX];
    size_t vl = imdb_scram_encode(ver, vb);
    int rc = ent_make(id, IMDB_RPAY_VERIFIER, vb, (uint32_t)vl, x, e);
    imdb_wipe(vb, sizeof vb);
    return rc;
}

void imdb_role_free(imdb_role *r)
{
    if (!r) return;
    ent_free(&r->nent);
    ent_free(&r->vent);
    imdb_free(r->hist);
    imdb_free(r->privs);
    imdb_free(r->groups);
    imdb_wipe(r, sizeof *r);
    imdb_free(r);
}

void imdb_rcat_free(imdb_rcat *c)
{
    for (uint32_t i = 0; i < c->n; i++) imdb_role_free(c->roles[i]);
    imdb_free(c->roles);
    memset(c, 0, sizeof *c);
}

/* ---- room, reserved before the frame ----------------------------------------------------------------------------- */

static int roles_reserve(imdb_rcat *c, imdb_err *e)
{
    if (c->n < c->cap) return IMDB_OK;
    if (c->n >= IMDB_MAX_ROLES)
        return imdb_fail(e, IMDB_ERR_LIMIT,
                         "a database holds at most %u roles, the dropped ones not yet erased counted (ERASE ROLE frees a "
                         "dropped role's place)", IMDB_MAX_ROLES);
    uint32_t cap = c->cap ? c->cap * 2 : 8;
    if (cap > IMDB_MAX_ROLES) cap = IMDB_MAX_ROLES;
    imdb_role **n = imdb_realloc_array(c->roles, c->cap, cap, sizeof *n, e);
    if (!n) return e->code;
    c->roles = n;
    c->cap = cap;
    return IMDB_OK;
}

/* an array's room for need entries, its capacity doubling up to max: the new block, or NULL (e says why) */
static void *grow_arr(void *p, uint32_t *cap, uint32_t need, uint32_t max, size_t size, imdb_err *e)
{
    if (need > max) {
        imdb_fail(e, IMDB_ERR_LIMIT, "a role's records past %u", max);
        return NULL;
    }
    uint32_t c = *cap ? *cap : 4;
    while (c < need) c = c > max / 2 ? max : c * 2;
    void *n = imdb_realloc_array(p, *cap, c, size, e);
    if (n) *cap = c;
    return n;
}

static int hist_reserve(imdb_role *r, uint32_t k, imdb_err *e)
{
    if (r->nhist + k > IMDB_MAX_ROLE_HISTORY)
        return imdb_fail(e, IMDB_ERR_LIMIT, "role %s keeps %u earlier names and passwords: ERASE ROLE %s first", r->name,
                         IMDB_MAX_ROLE_HISTORY, r->name);
    if (r->nhist + k <= r->caphist) return IMDB_OK;
    imdb_rhist *n = grow_arr(r->hist, &r->caphist, r->nhist + k, IMDB_MAX_ROLE_HISTORY, sizeof *r->hist, e);
    if (!n) return e->code;
    r->hist = n;
    return IMDB_OK;
}

/* an earlier entry into its place by (commit, what): the order manifest 18 keeps and an ERASE names (an ALTER
 * supersedes entries set at any earlier commit, so its own order is not theirs) */
static void hist_push(imdb_role *r, const imdb_rent *x, uint8_t what)
{
    uint32_t i = r->nhist; /* hist_reserve made the room */
    while (i && (r->hist[i - 1].at > x->at || (r->hist[i - 1].at == x->at && r->hist[i - 1].what > what))) i--;
    memmove(&r->hist[i + 1], &r->hist[i], (r->nhist - i) * sizeof *r->hist);
    r->hist[i].at = x->at;
    r->hist[i].what = what;
    r->hist[i].pending = x->pending; /* stage 2: a redacted copy's debt moves with the entry */
    r->hist[i].doomed = false;
    memcpy(r->hist[i].commit, x->commit, 32);
    r->nhist++;
}

/* the earlier entries an ALTER makes: its name, and its verifier when the role holds one */
static uint32_t alter_hist(const imdb_role *r, uint32_t fields)
{
    return ((fields & IMDB_RF_NAME) ? 1u : 0u) + ((fields & IMDB_RF_VERIFIER) && r->has_ver ? 1u : 0u);
}

/* ---- the statements ---------------------------------------------------------------------------------------------- */

/* the transaction's next op, its role fields allocated: NULL (e set) and nothing pushed on a failure */
static imdb_op *role_op(imdb_db *db, uint8_t code, imdb_err *e)
{
    imdb_roleop *ro = imdb_alloc(sizeof *ro, e);
    imdb_op *op = ro ? imdb_tx_push(db, e) : NULL;
    if (!op) {
        imdb_free(ro);
        return NULL;
    }
    op->code = code;
    op->ro = ro;
    return op;
}

static int role_ddl_alone(imdb_db *db, const char *what, imdb_err *e)
{
    if (!db->in_txn) return imdb_fail(e, IMDB_ERR_STATE, "no transaction");
    if (db->ntx || db->ntxseq) return imdb_fail(e, IMDB_ERR_STATE, "%s commits on its own", what);
    return IMDB_OK;
}

static int name_check(const imdb_rcat *c, const char *name, imdb_err *e)
{
    size_t ln = strlen(name);
    if (!imdb_ident_valid(name, ln))
        return imdb_fail(e, IMDB_ERR_INVALID, "a role's name is an identifier of 1 to %u bytes", IMDB_MAX_IDENT);
    for (size_t i = 0; i < ln; i++)
        if (name[i] >= 'A' && name[i] <= 'Z') return imdb_fail(e, IMDB_ERR_INVALID, "a role's name is lower case, as SQL folds it");
    if (!imdb_role_name_ok((const uint8_t *)name, ln))
        return imdb_fail(e, IMDB_ERR_INVALID,
                         "role %s: a reserved name (public, none, current_user, session_user, current_role, pg_*)", name);
    if (imdb_rcat_by_name(c, name)) return imdb_fail(e, IMDB_ERR_INVALID, "role %s exists already", name);
    return IMDB_OK;
}

int imdb_create_role(imdb_db *db, const char *name, uint32_t attrs, const imdb_scram *ver, imdb_err *e)
{
    imdb_rcat *c = &db->rc;
    if (role_ddl_alone(db, "CREATE ROLE", e) || name_check(c, name, e)) return e->code;
    if (attrs & ~(uint32_t)IMDB_RA_KNOWN) return imdb_fail(e, IMDB_ERR_INVALID, "CREATE ROLE: unknown attributes");
    if (c->last >= UINT32_MAX - 1) return imdb_fail(e, IMDB_ERR_LIMIT, "the database's role ids are spent");
    if (roles_reserve(c, e)) return e->code;
    imdb_role *nr = imdb_alloc(sizeof *nr, e);
    if (!nr) return e->code;
    nr->id = c->last + 1;
    nr->attrs = attrs;
    snprintf(nr->name, sizeof nr->name, "%s", name);
    imdb_op *op = NULL;
    if (ent_make(nr->id, IMDB_RPAY_NAME, name, (uint32_t)strlen(name), &nr->nent, e) ||
        (ver && verifier_ent(nr->id, ver, &nr->vent, e)) || !(op = role_op(db, IMDB_OP_CREATE_ROLE, e))) {
        imdb_role_free(nr);
        return e->code;
    }
    nr->has_ver = ver != NULL;
    op->ro->rid = nr->id;
    op->ro->rfields = IMDB_RF_ATTRS | IMDB_RF_NAME | (ver ? (uint32_t)IMDB_RF_VERIFIER : 0u);
    op->ro->rattrs = attrs;
    rpay_of(&op->ro->rname, &nr->nent);
    if (ver) rpay_of(&op->ro->rver, &nr->vent);
    op->ro->rnew = nr; /* the install links it in */
    return IMDB_OK;
}

int imdb_alter_role(imdb_db *db, imdb_role *r, uint32_t fields, uint32_t attrs, const char *name, const imdb_scram *ver,
                    imdb_err *e)
{
    if (role_ddl_alone(db, "ALTER ROLE", e)) return e->code;
    if (r->dropped_at) return imdb_fail(e, IMDB_ERR_NOTFOUND, "role %s was dropped", r->name);
    if (!fields || (fields & ~(uint32_t)IMDB_RF_KNOWN) || ((fields & IMDB_RF_ATTRS) && (attrs & ~(uint32_t)IMDB_RA_KNOWN)))
        return imdb_fail(e, IMDB_ERR_INVALID, "ALTER ROLE: unknown fields or attributes");
    /* one encoding of a change: a field that changes nothing is not logged, and none at all commits nothing (as a GRANT
     * of what is held); the replay refuses such a field */
    if ((fields & IMDB_RF_ATTRS) && attrs == r->attrs) fields &= ~(uint32_t)IMDB_RF_ATTRS;
    if ((fields & IMDB_RF_VERIFIER) && !ver && !r->has_ver) fields &= ~(uint32_t)IMDB_RF_VERIFIER;
    if (!fields) return IMDB_OK;
    if ((fields & IMDB_RF_NAME) && name_check(&db->rc, name, e)) return e->code;
    if (hist_reserve(r, alter_hist(r, fields), e)) return e->code;
    imdb_role *c = imdb_alloc(sizeof *c, e); /* the carrier of the new entries, until the install */
    if (!c) return e->code;
    c->id = r->id;
    imdb_op *op = NULL;
    if (((fields & IMDB_RF_NAME) && ent_make(r->id, IMDB_RPAY_NAME, name, (uint32_t)strlen(name), &c->nent, e)) ||
        ((fields & IMDB_RF_VERIFIER) && ver && verifier_ent(r->id, ver, &c->vent, e)) || !(op = role_op(db, IMDB_OP_ALTER_ROLE, e))) {
        imdb_role_free(c);
        return e->code;
    }
    if (fields & IMDB_RF_NAME) snprintf(c->name, sizeof c->name, "%s", name);
    c->has_ver = (fields & IMDB_RF_VERIFIER) && ver;
    op->ro->rid = r->id;
    op->ro->rfields = fields;
    op->ro->rattrs = (fields & IMDB_RF_ATTRS) ? attrs : 0;
    if (fields & IMDB_RF_NAME) rpay_of(&op->ro->rname, &c->nent);
    op->ro->rvnone = (fields & IMDB_RF_VERIFIER) && !ver;
    if (c->has_ver) rpay_of(&op->ro->rver, &c->vent);
    op->ro->rnew = c;
    return IMDB_OK;
}

/* DROP ROLE's RESTRICT (the statement's and the replay's one rule): no privilege, no membership either way */
static int drop_rule(const imdb_rcat *c, const imdb_role *r, imdb_err *e)
{
    if (r->nprivs) return imdb_fail(e, IMDB_ERR_INVALID, "role %s holds privileges: REVOKE them first", r->name);
    if (r->ngroups) return imdb_fail(e, IMDB_ERR_INVALID, "role %s is a member of a role: REVOKE that first", r->name);
    for (uint32_t i = 0; i < c->n; i++)
        if (imdb_role_member(c->roles[i], r->id))
            return imdb_fail(e, IMDB_ERR_INVALID, "role %s has a member, %s: REVOKE that first", r->name, c->roles[i]->name);
    return IMDB_OK;
}

int imdb_drop_role(imdb_db *db, imdb_role *r, imdb_err *e)
{
    if (role_ddl_alone(db, "DROP ROLE", e)) return e->code;
    if (r->dropped_at) return imdb_fail(e, IMDB_ERR_NOTFOUND, "role %s was dropped already", r->name);
    if (drop_rule(&db->rc, r, e)) return e->code;
    imdb_op *op = role_op(db, IMDB_OP_DROP_ROLE, e);
    if (!op) return e->code;
    op->ro->rid = r->id;
    return IMDB_OK;
}

/* would member a joining group g close a cycle: a reached from g by the memberships held, and by the op's own earlier
 * records (recs[0, k), memberships) */
static bool closes_cycle(const imdb_rcat *c, const imdb_grant_rec *recs, uint32_t k, uint32_t a, uint32_t g,
                         uint8_t *seen, uint32_t *stack)
{
    memset(seen, 0, c->n);
    uint32_t top = 0, gi = role_index(c, g);
    if (gi >= c->n || c->roles[gi]->id != g) return false;
    stack[top++] = gi;
    seen[gi] = 1;
    while (top) {
        const imdb_role *x = c->roles[stack[--top]];
        if (x->id == a) return true;
        for (uint32_t j = 0; j < x->ngroups; j++) {
            uint32_t yi = role_index(c, x->groups[j]);
            if (yi < c->n && c->roles[yi]->id == x->groups[j] && !seen[yi]) seen[yi] = 1, stack[top++] = yi;
        }
        uint32_t lo = 0, hi = k; /* the op's earlier memberships of x: a run of recs[0, k), sorted by member */
        while (lo < hi) {
            uint32_t mid = lo + (hi - lo) / 2;
            if (recs[mid].a < x->id) lo = mid + 1;
            else hi = mid;
        }
        for (uint32_t j = lo; j < k && recs[j].a == x->id; j++) {
            uint32_t yi = role_index(c, recs[j].b);
            if (yi < c->n && c->roles[yi]->id == recs[j].b && !seen[yi]) seen[yi] = 1, stack[top++] = yi;
        }
    }
    return false;
}

static int grant_cycles(const imdb_rcat *c, const imdb_grant_rec *recs, uint32_t n, imdb_err *e)
{
    uint32_t first = n;
    for (uint32_t k = 0; k < n && first == n; k++)
        if (recs[k].kind == IMDB_GRANT_MEMBER) first = k;
    if (first == n || !c->n) return IMDB_OK;
    uint8_t *seen = imdb_alloc(c->n, e);
    uint32_t *stack = seen ? imdb_alloc_array(c->n, sizeof *stack, e) : NULL;
    int rc = stack ? IMDB_OK : e->code;
    for (uint32_t k = first; k < n && !rc; k++)
        if (closes_cycle(c, recs + first, k - first, recs[k].a, recs[k].b, seen, stack)) {
            const imdb_role *ra = imdb_rcat_by_id(c, recs[k].a), *rb = imdb_rcat_by_id(c, recs[k].b);
            rc = imdb_fail(e, IMDB_ERR_INVALID, "role %s is a member of role %s already: the membership would close a cycle",
                           rb ? rb->name : "?", ra ? ra->name : "?");
        }
    imdb_free(seen);
    imdb_free(stack);
    return rc;
}

/* the room the install of a GRANT needs, each role's arrays (records sorted by kind and role) */
static int grant_reserve(const imdb_rcat *c, const imdb_grant_rec *recs, uint32_t n, imdb_err *e)
{
    for (uint32_t k = 0; k < n;) {
        uint32_t j = k, more = 0;
        imdb_role *r = imdb_rcat_by_id(c, recs[k].a);
        for (; j < n && recs[j].kind == recs[k].kind && recs[j].a == recs[k].a; j++)
            more += r && (recs[j].kind == IMDB_GRANT_PRIV ? !imdb_role_privs(r, recs[j].okind, recs[j].b)
                                                         : !imdb_role_member(r, recs[j].b));
        if (r && more && recs[k].kind == IMDB_GRANT_PRIV && r->nprivs + more > r->capprivs) {
            imdb_rpriv *np = grow_arr(r->privs, &r->capprivs, r->nprivs + more, IMDB_MAX_GRANTS, sizeof *r->privs, e);
            if (!np) return e->code;
            r->privs = np;
        }
        if (r && more && recs[k].kind == IMDB_GRANT_MEMBER && r->ngroups + more > r->capgroups) {
            uint32_t *ng = grow_arr(r->groups, &r->capgroups, r->ngroups + more, IMDB_MAX_GRANTS, sizeof *r->groups, e);
            if (!ng) return e->code;
            r->groups = ng;
        }
        k = j;
    }
    return IMDB_OK;
}

/* op 36's or 37's records against the catalog before them: the replay's rules, which the writer's canonical form meets
 * (each record exactly what it adds or removes; a GRANT within the limit and closing no cycle) */
static int grant_check(const imdb_rcat *c, imdb_obj_live_fn live, const void *arg, const imdb_grant_rec *recs, uint32_t n,
                       bool revoke, imdb_err *e)
{
    const char *what = revoke ? "REVOKE" : "GRANT";
    uint32_t newrecs = 0;
    for (uint32_t k = 0; k < n; k++) {
        const imdb_grant_rec *g = &recs[k];
        imdb_role *ra = role_live(c, g->a);
        if (!ra) return imdb_fail(e, IMDB_ERR_INVALID, "a %s names a role that is not live", what);
        if (g->kind == IMDB_GRANT_PRIV) {
            if (!live(arg, g->okind, g->b)) return imdb_fail(e, IMDB_ERR_INVALID, "a %s names a table or view that is not live", what);
            uint32_t held = imdb_role_privs(ra, g->okind, g->b);
            if (revoke ? (g->privs & ~held) != 0 : (g->privs & held) != 0)
                return imdb_fail(e, IMDB_ERR_INVALID, "a %s record's privileges are not exactly those it %s", what,
                                 revoke ? "removes" : "adds");
            newrecs += !revoke && !held;
        } else {
            if (!role_live(c, g->b)) return imdb_fail(e, IMDB_ERR_INVALID, "a %s names a role that is not live", what);
            if (imdb_role_member(ra, g->b) != revoke)
                return imdb_fail(e, IMDB_ERR_INVALID, "a %s record's membership %s", what, revoke ? "is not held" : "is held already");
            newrecs += !revoke;
        }
    }
    if (!revoke && c->ngrants + newrecs > IMDB_MAX_GRANTS)
        return imdb_fail(e, IMDB_ERR_LIMIT, "a database holds at most %u privilege and membership records", IMDB_MAX_GRANTS);
    return revoke ? IMDB_OK : grant_cycles(c, recs, n, e);
}

static int cmp_rec(const void *x, const void *y) { return imdb_grant_cmp(x, y); }

int imdb_grant_revoke(imdb_db *db, bool revoke, imdb_grant_rec *recs, uint32_t n, uint32_t *logged, imdb_err *e)
{
    const char *what = revoke ? "REVOKE" : "GRANT";
    imdb_rcat *c = &db->rc;
    *logged = 0;
    if (role_ddl_alone(db, what, e)) return e->code;
    if (n > IMDB_MAX_GRANT_RECORDS)
        return imdb_fail(e, IMDB_ERR_LIMIT, "a %s makes at most %u records (objects times roles)", what, IMDB_MAX_GRANT_RECORDS);
    if (!n) return IMDB_OK;
    qsort(recs, n, sizeof *recs, cmp_rec);
    uint32_t m = 0;
    for (uint32_t i = 0; i < n; i++) { /* one record a key: repeats merged */
        if (recs[i].kind == IMDB_GRANT_MEMBER && recs[i].a == recs[i].b)
            return imdb_fail(e, IMDB_ERR_INVALID, "a role is never a member of itself");
        if (m && !imdb_grant_cmp(&recs[m - 1], &recs[i])) recs[m - 1].privs |= recs[i].privs;
        else recs[m++] = recs[i];
    }
    uint32_t out = 0;
    for (uint32_t i = 0; i < m; i++) { /* what each changes: none that changes nothing (PostgreSQL's no-op) */
        imdb_grant_rec g = recs[i];
        imdb_role *ra = role_live(c, g.a);
        if (!ra) return imdb_fail(e, IMDB_ERR_INVALID, "a %s names a role that is not live", what);
        if (g.kind == IMDB_GRANT_PRIV) {
            if (!imdb_db_obj_live(db, g.okind, g.b))
                return imdb_fail(e, IMDB_ERR_INVALID, "a %s names a table or view that is not live", what);
            uint32_t held = imdb_role_privs(ra, g.okind, g.b);
            g.privs = revoke ? g.privs & held : g.privs & ~held;
            if (!g.privs) continue;
        } else {
            if (!role_live(c, g.b)) return imdb_fail(e, IMDB_ERR_INVALID, "a %s names a role that is not live", what);
            if (imdb_role_member(ra, g.b) == !revoke) continue;
        }
        recs[out++] = g;
    }
    if (!out) return IMDB_OK;
    if (grant_check(c, imdb_db_obj_live, db, recs, out, revoke, e) || (!revoke && grant_reserve(c, recs, out, e))) return e->code;
    imdb_grant_rec *own = imdb_alloc_array(out, sizeof *own, e);
    imdb_op *op = own ? role_op(db, revoke ? IMDB_OP_REVOKE : IMDB_OP_GRANT, e) : NULL;
    if (!op) {
        imdb_free(own);
        return e->code;
    }
    memcpy(own, recs, out * sizeof *own);
    op->ro->grants = own;
    op->ro->ngrants = out;
    *logged = out;
    return IMDB_OK;
}

/* ---- installs: after the commit, into the room reserved ------------------------------------------------------------ */

static bool priv_add(imdb_rcat *c, imdb_role *r, uint8_t okind, uint32_t oid, uint32_t bits, bool revoke)
{
    uint32_t i = priv_find(r, okind, oid);
    bool has = i < r->nprivs && r->privs[i].okind == okind && r->privs[i].oid == oid;
    if (has) {
        r->privs[i].privs = revoke ? r->privs[i].privs & ~bits : r->privs[i].privs | bits;
        if (!r->privs[i].privs) {
            memmove(&r->privs[i], &r->privs[i + 1], (r->nprivs - i - 1) * sizeof *r->privs);
            r->nprivs--;
            c->ngrants--;
        }
        return true;
    }
    if (revoke) return true;
    if (r->nprivs >= r->capprivs) return false;
    memmove(&r->privs[i + 1], &r->privs[i], (r->nprivs - i) * sizeof *r->privs);
    r->privs[i] = (imdb_rpriv){.okind = okind, .oid = oid, .privs = bits};
    r->nprivs++;
    c->ngrants++;
    return true;
}

static bool group_add(imdb_rcat *c, imdb_role *r, uint32_t g, bool revoke)
{
    uint32_t i = group_find(r, g);
    bool has = i < r->ngroups && r->groups[i] == g;
    if (revoke && has) {
        memmove(&r->groups[i], &r->groups[i + 1], (r->ngroups - i - 1) * sizeof *r->groups);
        r->ngroups--;
        c->ngrants--;
    } else if (!revoke && !has) {
        if (r->ngroups >= r->capgroups) return false;
        memmove(&r->groups[i + 1], &r->groups[i], (r->ngroups - i) * sizeof *r->groups);
        r->groups[i] = g;
        r->ngroups++;
        c->ngrants++;
    }
    return true;
}

static bool grant_install(imdb_rcat *c, const imdb_op *o)
{
    bool revoke = o->code == IMDB_OP_REVOKE;
    for (uint32_t k = 0; k < o->ro->ngrants; k++) {
        const imdb_grant_rec *g = &o->ro->grants[k];
        imdb_role *r = imdb_rcat_by_id(c, g->a);
        if (r && !(g->kind == IMDB_GRANT_PRIV ? priv_add(c, r, g->okind, g->b, g->privs, revoke) : group_add(c, r, g->b, revoke)))
            return false;
    }
    return true;
}

bool imdb_role_install(imdb_rcat *c, const imdb_op *o, uint64_t seq)
{
    imdb_role *x = o->ro->rnew;
    o->ro->rnew = NULL;
    if (o->code == IMDB_OP_CREATE_ROLE) {
        if (!x || c->n >= c->cap || x->id != c->last + 1 || (c->n && c->roles[c->n - 1]->id >= x->id)) {
            imdb_role_free(x);
            return false;
        }
        x->created_at = x->nent.at = seq;
        if (x->has_ver) x->vent.at = seq;
        c->roles[c->n++] = x;
        c->last = x->id;
        return true;
    }
    if (o->code == IMDB_OP_ALTER_ROLE) {
        imdb_role *r = imdb_rcat_by_id(c, o->ro->rid);
        if (!r || !x || r->nhist + alter_hist(r, o->ro->rfields) > r->caphist) {
            imdb_role_free(x);
            return false;
        }
        if (o->ro->rfields & IMDB_RF_ATTRS) r->attrs = o->ro->rattrs;
        if (o->ro->rfields & IMDB_RF_NAME) {
            hist_push(r, &r->nent, IMDB_RPAY_NAME);
            ent_free(&r->nent);
            r->nent = x->nent;
            r->nent.at = seq;
            memset(&x->nent, 0, sizeof x->nent);
            memcpy(r->name, x->name, sizeof r->name);
        }
        if (o->ro->rfields & IMDB_RF_VERIFIER) {
            if (r->has_ver) {
                hist_push(r, &r->vent, IMDB_RPAY_VERIFIER);
                ent_free(&r->vent);
            }
            r->has_ver = x->has_ver;
            if (x->has_ver) {
                r->vent = x->vent;
                r->vent.at = seq;
                memset(&x->vent, 0, sizeof x->vent);
            }
        }
        imdb_role_free(x);
        return true;
    }
    imdb_role_free(x);
    if (o->code == IMDB_OP_DROP_ROLE) {
        imdb_role *r = imdb_rcat_by_id(c, o->ro->rid);
        if (r) r->dropped_at = seq;
        return r != NULL;
    }
    return o->code == IMDB_OP_GRANT || o->code == IMDB_OP_REVOKE ? grant_install(c, o) : true;
}

void imdb_grants_end_object(imdb_rcat *c, uint8_t okind, uint32_t oid)
{
    for (uint32_t i = 0; i < c->n; i++) {
        imdb_role *r = c->roles[i];
        uint32_t k = priv_find(r, okind, oid);
        if (k < r->nprivs && r->privs[k].okind == okind && r->privs[k].oid == oid) {
            memmove(&r->privs[k], &r->privs[k + 1], (r->nprivs - k - 1) * sizeof *r->privs);
            r->nprivs--;
            c->ngrants--;
        }
    }
}

/* ---- replay and VERIFY --------------------------------------------------------------------------------------------- */

static int corrupt(imdb_err *e, uint64_t seq, const imdb_err *why)
{
    if (why->code == IMDB_ERR_NOMEM) return imdb_fail(e, why->code, "%s", why->msg);
    return imdb_fail(e, IMDB_ERR_CORRUPT, "commit %llu: %s", (unsigned long long)seq, why->msg);
}

int imdb_role_apply(imdb_rcat *c, imdb_obj_live_fn live, const void *arg, const imdb_op *o, uint64_t seq, imdb_err *e)
{
    imdb_err e2 = {0};
    char nm[IMDB_MAX_IDENT + 1] = "";
    if (o->code == IMDB_OP_CREATE_ROLE || o->code == IMDB_OP_ALTER_ROLE) {
        bool create = o->code == IMDB_OP_CREATE_ROLE;
        imdb_role *r = create ? NULL : role_live(c, o->ro->rid);
        if (create ? o->ro->rid != c->last + 1 : !r)
            return imdb_fail(e, IMDB_ERR_CORRUPT, "commit %llu: %s", (unsigned long long)seq,
                             create ? "a role's id out of sequence" : "ALTER ROLE of a role that is not live");
        if (!create && (((o->ro->rfields & IMDB_RF_ATTRS) && o->ro->rattrs == r->attrs) ||
                        ((o->ro->rfields & IMDB_RF_VERIFIER) && o->ro->rvnone && !r->has_ver)))
            return imdb_fail(e, IMDB_ERR_CORRUPT, "commit %llu: ALTER ROLE of a field that changes nothing", (unsigned long long)seq);
        /* stage 2: a redacted entry is a redacted copy's: erased, pending the ERASE that names it (counted; a debt left at
         * the end is the caller's CORRUPT). Its name unknown, a CREATE's or a rename's is no name: its uniqueness unchecked */
        bool nred = (o->ro->rfields & IMDB_RF_NAME) && o->ro->rname.pkind != IMDB_PAYLOAD_ROW;
        bool vred = (o->ro->rfields & IMDB_RF_VERIFIER) && !o->ro->rvnone && o->ro->rver.pkind != IMDB_PAYLOAD_ROW;
        if ((o->ro->rfields & IMDB_RF_NAME) && !nred) {
            memcpy(nm, o->ro->rname.bytes, o->ro->rname.len); /* the decoder checked its shape and length */
            nm[o->ro->rname.len] = '\0';
            if (imdb_rcat_by_name(c, nm))
                return imdb_fail(e, IMDB_ERR_CORRUPT, "commit %llu: role %u takes a live role's name", (unsigned long long)seq, o->ro->rid);
        }
        if (create ? roles_reserve(c, &e2) : hist_reserve(r, alter_hist(r, o->ro->rfields), &e2)) return corrupt(e, seq, &e2);
        imdb_role *x = imdb_alloc(sizeof *x, e);
        if (!x) return e->code;
        x->id = o->ro->rid;
        x->attrs = o->ro->rattrs;
        if (((o->ro->rfields & IMDB_RF_NAME) && ent_take(&o->ro->rname, &x->nent, e)) ||
            ((o->ro->rfields & IMDB_RF_VERIFIER) && !o->ro->rvnone && ent_take(&o->ro->rver, &x->vent, e))) {
            imdb_role_free(x);
            return e->code;
        }
        memcpy(x->name, nm, sizeof x->name);
        x->nent.erased = x->nent.pending = nred;
        x->vent.erased = x->vent.pending = vred;
        c->npending += (uint64_t)nred + vred;
        x->has_ver = (o->ro->rfields & IMDB_RF_VERIFIER) && !o->ro->rvnone;
        o->ro->rnew = x;
        return imdb_role_install(c, o, seq) ? IMDB_OK
                                            : imdb_fail(e, IMDB_ERR_CORRUPT, "commit %llu: a role's install failed", (unsigned long long)seq);
    }
    if (o->code == IMDB_OP_DROP_ROLE) {
        imdb_role *r = role_live(c, o->ro->rid);
        if (!r) return imdb_fail(e, IMDB_ERR_CORRUPT, "commit %llu: DROP ROLE of a role that is not live", (unsigned long long)seq);
        if (drop_rule(c, r, &e2)) return corrupt(e, seq, &e2);
        r->dropped_at = seq;
        return IMDB_OK;
    }
    bool revoke = o->code == IMDB_OP_REVOKE;
    if (grant_check(c, live, arg, o->ro->grants, o->ro->ngrants, revoke, &e2) || (!revoke && grant_reserve(c, o->ro->grants, o->ro->ngrants, &e2)))
        return corrupt(e, seq, &e2);
    return grant_install(c, o) ? IMDB_OK
                               : imdb_fail(e, IMDB_ERR_CORRUPT, "commit %llu: a GRANT's install failed", (unsigned long long)seq);
}

/* ---- stage 2: ERASE ROLE (docs/roles-design.md §11) ------------------------------------------------------------------ */

static bool ent_gone(const imdb_rent *x) { return (x->erased && !x->pending) || x->doomed; }

/* a role the catalog no longer holds once its doomed entries are erased: dropped, nothing current, nothing earlier. The
 * one rule of the encoder (with the writer's doomed entries) and the apply (after them) */
static bool role_gone(const imdb_role *r)
{
    if (!r->dropped_at || !ent_gone(&r->nent) || (r->has_ver && !ent_gone(&r->vent))) return false;
    for (uint32_t k = 0; k < r->nhist; k++)
        if (!r->hist[k].doomed) return false;
    return true;
}

static uint32_t hist_find(const imdb_role *r, uint64_t at, uint8_t what) /* its place, or nhist */
{
    uint32_t lo = 0, hi = r->nhist;
    while (lo < hi) {
        uint32_t mid = lo + (hi - lo) / 2;
        const imdb_rhist *h = &r->hist[mid];
        if (h->at < at || (h->at == at && h->what < what)) lo = mid + 1;
        else hi = mid;
    }
    return lo < r->nhist && r->hist[lo].at == at && r->hist[lo].what == what ? lo : r->nhist;
}

/* the current entry an op set at commit at, or NULL */
static imdb_rent *cur_find(imdb_role *r, uint64_t at, uint8_t what)
{
    imdb_rent *x = what == IMDB_RPAY_NAME ? &r->nent : r->has_ver ? &r->vent : NULL;
    return x && x->at == at ? x : NULL;
}

static void collect_push(imdb_rerase *out, uint32_t *n, uint32_t role, uint64_t seq, uint8_t what, const uint8_t commit[32])
{
    out[*n].role = role;
    out[*n].seq = seq;
    out[*n].what = what;
    memcpy(out[*n].commit, commit, 32);
    (*n)++;
}

static int cmp_rerase(const void *a, const void *b) { return imdb_rerase_cmp(a, b); }

int imdb_role_erase_collect(const imdb_rcat *c, const char *name, imdb_rerase **out, uint32_t *n, imdb_err *e)
{
    *out = NULL;
    *n = 0;
    uint64_t k = 0;
    bool known = false;
    for (uint32_t i = 0; i < c->n; i++) { /* the live role of the name, and each dropped role it was the last name of */
        const imdb_role *r = c->roles[i];
        if (!r->name[0] || strcmp(r->name, name)) continue;
        known = true;
        k += r->nhist;
        if (r->dropped_at) k += !r->nent.erased + (r->has_ver && !r->vent.erased);
    }
    if (!known)
        return imdb_fail(e, IMDB_ERR_NOTFOUND,
                         "ERASE ROLE: no role, live or dropped, holds the name %s (a renamed role is erased under its current "
                         "name: its earlier names go with it)", name);
    if (!k) return IMDB_OK; /* nothing left to erase: nothing commits */
    if (k > IMDB_MAX_ROLE_ERASE) return imdb_fail(e, IMDB_ERR_LIMIT, "ERASE ROLE: past %u entries", IMDB_MAX_ROLE_ERASE);
    imdb_rerase *x = imdb_alloc_array(k, sizeof *x, e);
    if (!x) return e->code;
    uint32_t m = 0;
    for (uint32_t i = 0; i < c->n; i++) {
        const imdb_role *r = c->roles[i];
        if (!r->name[0] || strcmp(r->name, name)) continue;
        for (uint32_t h = 0; h < r->nhist; h++) collect_push(x, &m, r->id, r->hist[h].at, r->hist[h].what, r->hist[h].commit);
        if (r->dropped_at && !r->nent.erased) collect_push(x, &m, r->id, r->nent.at, IMDB_RPAY_NAME, r->nent.commit);
        if (r->dropped_at && r->has_ver && !r->vent.erased) collect_push(x, &m, r->id, r->vent.at, IMDB_RPAY_VERIFIER, r->vent.commit);
    }
    qsort(x, m, sizeof *x, cmp_rerase);
    *out = x;
    *n = m;
    return IMDB_OK;
}

void imdb_role_doom(imdb_rcat *c, const imdb_rerase *x, uint32_t n)
{
    for (uint32_t k = 0; k < n; k++) {
        imdb_role *r = imdb_rcat_by_id(c, x[k].role);
        if (!r) continue;
        imdb_rent *cur = cur_find(r, x[k].seq, x[k].what);
        uint32_t h = cur ? r->nhist : hist_find(r, x[k].seq, x[k].what);
        if (cur) cur->doomed = true;
        else if (h < r->nhist) r->hist[h].doomed = true;
    }
}

void imdb_role_undoom(imdb_rcat *c)
{
    for (uint32_t i = 0; i < c->n; i++) {
        imdb_role *r = c->roles[i];
        r->nent.doomed = r->vent.doomed = false;
        for (uint32_t k = 0; k < r->nhist; k++) r->hist[k].doomed = false;
    }
}

/* what an ERASE ROLE of r names: a live role's earlier entries, a dropped role's every one held (a pending one too) */
static uint32_t erasable(const imdb_role *r)
{
    if (!r->dropped_at) return r->nhist;
    return r->nhist + !(r->nent.erased && !r->nent.pending) + (r->has_ver && !(r->vent.erased && !r->vent.pending));
}

int imdb_role_erase_apply(imdb_rcat *c, const imdb_rerase *x, uint32_t n, uint64_t seq, imdb_rerase_fn cb, void *arg,
                          imdb_err *e)
{
    uint32_t run = 0; /* entries of the role so far in its run */
    for (uint32_t k = 0; k < n; k++) { /* every rule first: nothing changes for a list refused part way */
        imdb_role *r = imdb_rcat_by_id(c, x[k].role);
        /* a role's entries all at once, never a part (the writer names them all; a part would strand the rest under no
         * name): the count of each role's run, checked at its last entry (the list is by role) */
        run = k && x[k - 1].role == x[k].role ? run + 1 : 1;
        imdb_rent *cur = r ? cur_find(r, x[k].seq, x[k].what) : NULL;
        uint32_t h = r && !cur ? hist_find(r, x[k].seq, x[k].what) : 0;
        const uint8_t *cm = cur ? cur->commit : r && h < r->nhist ? r->hist[h].commit : NULL;
        if (!cm)
            return imdb_fail(e, IMDB_ERR_CORRUPT, "commit %llu: an ERASE names a role entry no role keeps", (unsigned long long)seq);
        if (memcmp(cm, x[k].commit, 32) != 0)
            return imdb_fail(e, IMDB_ERR_CORRUPT, "commit %llu: an ERASE's role entry with another commitment", (unsigned long long)seq);
        if (cur && !r->dropped_at)
            return imdb_fail(e, IMDB_ERR_CORRUPT, "commit %llu: an ERASE of a live role's current name or verifier",
                             (unsigned long long)seq);
        if (cur && cur->erased && !cur->pending)
            return imdb_fail(e, IMDB_ERR_CORRUPT, "commit %llu: an ERASE of a role entry erased already", (unsigned long long)seq);
        if (r && (k + 1 == n || x[k + 1].role != x[k].role) && run != erasable(r)) /* after each entry's own rules */
            return imdb_fail(e, IMDB_ERR_CORRUPT, "commit %llu: an ERASE names part of role %u's entries (a writer names them "
                             "all: a live role's earlier ones, a dropped role's every one)", (unsigned long long)seq, x[k].role);
    }
    for (uint32_t k = 0; k < n; k++) {
        imdb_role *r = imdb_rcat_by_id(c, x[k].role);
        imdb_rent *cur = cur_find(r, x[k].seq, x[k].what);
        uint32_t h = cur ? 0 : hist_find(r, x[k].seq, x[k].what);
        bool pending = cur ? cur->pending : r->hist[h].pending;
        if (cb) {
            int rc = cb(arg, &x[k], pending, e);
            if (rc) return rc;
        }
        if (pending) c->npending--;
        if (cur) {
            if (cur->bytes) imdb_wipe(cur->bytes, cur->len);
            imdb_free(cur->bytes);
            cur->bytes = NULL;
            cur->len = 0;
            imdb_wipe(cur->salt, sizeof cur->salt);
            cur->erased = true;
            cur->pending = cur->doomed = false;
            if (x[k].what == IMDB_RPAY_NAME) imdb_wipe(r->name, sizeof r->name); /* its current name: "" once erased */
        } else {
            memmove(&r->hist[h], &r->hist[h + 1], (r->nhist - h - 1) * sizeof *r->hist);
            r->nhist--;
            imdb_wipe(&r->hist[r->nhist], sizeof *r->hist);
        }
    }
    for (uint32_t k = 0; k < n; k++) { /* a dropped role holding nothing more leaves: its id stays spent (last) */
        if (k && x[k].role == x[k - 1].role) continue;
        uint32_t i = role_index(c, x[k].role);
        if (i < c->n && c->roles[i]->id == x[k].role && role_gone(c->roles[i])) {
            imdb_role_free(c->roles[i]);
            memmove(&c->roles[i], &c->roles[i + 1], (c->n - i - 1) * sizeof *c->roles);
            c->n--;
        }
    }
    return IMDB_OK;
}

bool imdb_rcat_entry_erased(const imdb_rcat *c, uint32_t role, uint64_t seq, uint8_t what)
{
    imdb_role *r = imdb_rcat_by_id(c, role);
    if (!r) return true; /* erased whole */
    const imdb_rent *cur = cur_find(r, seq, what);
    if (cur) return cur->erased;
    return hist_find(r, seq, what) == r->nhist; /* neither current nor kept: erased */
}

/* ---- manifest 18's sections 5 and 6, and the roles object ----------------------------------------------------------- */

static const uint8_t kRolObj[8] = {'I', 'M', 'D', 'B', 'R', 'L', 'O', '1'};

static void ent_put(imdb_buf *b, const imdb_rent *x)
{
    imdb_buf_put_u64(b, x->at);
    imdb_buf_put(b, x->commit, 32);
    imdb_buf_put_u8(b, x->erased || x->doomed ? 1 : 0); /* stage 2: a doomed entry is the plan's erased one */
}

/* the roles object: "IMDBRLO1" | u32 n | n entries by (role, what), each a current entry not erased: u32 role | u8 what
 * | salt16 | u32 len | bytes */
int imdb_rcat_object(const imdb_rcat *c, imdb_buf *obj, uint8_t hash[32], imdb_err *e)
{
    uint32_t n = 0;
    for (uint32_t i = 0; i < c->n; i++)
        n += (c->roles[i]->nent.bytes && !c->roles[i]->nent.doomed) +
             (c->roles[i]->has_ver && c->roles[i]->vent.bytes && !c->roles[i]->vent.doomed);
    memset(hash, 0, 32);
    if (!n) return IMDB_OK; /* none: no object, a zero hash */
    imdb_buf_put(obj, kRolObj, 8);
    imdb_buf_put_u32(obj, n);
    for (uint32_t i = 0; i < c->n; i++)
        for (uint8_t w = IMDB_RPAY_NAME; w <= IMDB_RPAY_VERIFIER; w++) {
            const imdb_role *r = c->roles[i];
            const imdb_rent *x = w == IMDB_RPAY_NAME ? &r->nent : r->has_ver ? &r->vent : NULL;
            if (!x || !x->bytes || x->doomed) continue;
            imdb_buf_put_u32(obj, r->id);
            imdb_buf_put_u8(obj, w);
            imdb_buf_put(obj, x->salt, 16);
            imdb_buf_put_u32(obj, x->len);
            imdb_buf_put(obj, x->bytes, x->len);
        }
    if (imdb_buf_check(obj, e)) return e->code;
    imdb_sha256(obj->p, obj->len, hash);
    return IMDB_OK;
}

void imdb_rcat_put_roles(imdb_buf *b, const imdb_rcat *c, const uint8_t objhash[32])
{
    imdb_buf_put(b, objhash, 32);
    imdb_buf_put_u32(b, c->last);
    uint32_t n = 0;
    for (uint32_t i = 0; i < c->n; i++) n += !role_gone(c->roles[i]); /* stage 2: a role erased whole is not listed */
    imdb_buf_put_u32(b, n);
    for (uint32_t i = 0; i < c->n; i++) {
        const imdb_role *r = c->roles[i];
        if (role_gone(r)) continue;
        imdb_buf_put_u32(b, r->id);
        imdb_buf_put_u64(b, r->created_at);
        imdb_buf_put_u64(b, r->dropped_at);
        imdb_buf_put_u32(b, r->attrs);
        ent_put(b, &r->nent);
        imdb_buf_put_u8(b, r->has_ver);
        if (r->has_ver) ent_put(b, &r->vent);
        uint32_t nh = 0;
        for (uint32_t k = 0; k < r->nhist; k++) nh += !r->hist[k].doomed;
        imdb_buf_put_u32(b, nh);
        for (uint32_t k = 0; k < r->nhist; k++) {
            if (r->hist[k].doomed) continue;
            imdb_buf_put_u64(b, r->hist[k].at);
            imdb_buf_put_u8(b, r->hist[k].what);
            imdb_buf_put(b, r->hist[k].commit, 32);
        }
    }
}

void imdb_rcat_put_grants(imdb_buf *b, const imdb_rcat *c)
{
    uint32_t n = 0;
    for (uint32_t i = 0; i < c->n; i++) n += c->roles[i]->nprivs + c->roles[i]->ngroups;
    imdb_buf_put_u32(b, n);
    for (uint32_t i = 0; i < c->n; i++) /* kind 1, by grantee, then object: the log's order */
        for (uint32_t k = 0; k < c->roles[i]->nprivs; k++) {
            const imdb_rpriv *p = &c->roles[i]->privs[k];
            imdb_grant_rec g = {.kind = IMDB_GRANT_PRIV, .okind = p->okind, .a = c->roles[i]->id, .b = p->oid, .privs = p->privs};
            imdb_grant_put(b, &g);
        }
    for (uint32_t i = 0; i < c->n; i++) /* kind 2, by member, then group */
        for (uint32_t k = 0; k < c->roles[i]->ngroups; k++) {
            imdb_grant_rec g = {.kind = IMDB_GRANT_MEMBER, .a = c->roles[i]->id, .b = c->roles[i]->groups[k]};
            imdb_grant_put(b, &g);
        }
}

/* a current entry of a manifest's role: its commit within the role's life, erased or in the roles object; false: bad */
static bool ent_get(imdb_rd *r, const imdb_role *ro, uint64_t seq, imdb_rent *x)
{
    x->at = imdb_rd_u64(r);
    imdb_rd_copy(r, x->commit, 32);
    uint8_t kind = imdb_rd_u8(r);
    x->erased = kind == 1; /* a dropped role's, or a redacted copy's pending its ERASE: a live one's too (the advisor) */
    return !r->err && kind <= 1 && x->at >= ro->created_at && x->at <= seq && (!ro->dropped_at || x->at < ro->dropped_at);
}

int imdb_rcat_get_roles(imdb_rd *r, uint64_t seq, imdb_rcat *c, uint8_t objhash[32], imdb_err *e)
{
    memset(c, 0, sizeof *c);
    imdb_rd_copy(r, objhash, 32);
    c->last = imdb_rd_u32(r);
    uint32_t n = imdb_rd_u32(r);
    if (r->err || c->last >= UINT32_MAX || n > IMDB_MAX_ROLES || n > c->last || n > imdb_rd_left(r) / 70) goto bad;
    if (n && !(c->roles = imdb_alloc_array(n, sizeof *c->roles, e))) return e->code;
    c->cap = n;
    for (uint32_t i = 0; i < n; i++) {
        imdb_role *ro = imdb_alloc(sizeof *ro, e);
        if (!ro) goto fail;
        c->roles[c->n++] = ro;
        ro->id = imdb_rd_u32(r);
        ro->created_at = imdb_rd_u64(r);
        ro->dropped_at = imdb_rd_u64(r);
        ro->attrs = imdb_rd_u32(r);
        if (r->err || !ro->id || ro->id > c->last || (i && ro->id <= c->roles[i - 1]->id) || !ro->created_at ||
            ro->created_at > seq || (ro->dropped_at && (ro->dropped_at <= ro->created_at || ro->dropped_at > seq)) ||
            (ro->attrs & ~(uint32_t)IMDB_RA_KNOWN) || !ent_get(r, ro, seq, &ro->nent))
            goto bad;
        uint8_t hv = imdb_rd_u8(r);
        if (r->err || hv > 1 || (hv && !ent_get(r, ro, seq, &ro->vent))) goto bad;
        ro->has_ver = hv;
        uint32_t nh = imdb_rd_u32(r);
        if (r->err || nh > IMDB_MAX_ROLE_HISTORY || nh > imdb_rd_left(r) / 41) goto bad;
        if (nh && !(ro->hist = imdb_alloc_array(nh, sizeof *ro->hist, e))) goto fail;
        ro->caphist = nh;
        for (uint32_t k = 0; k < nh; k++) {
            imdb_rhist *h = &ro->hist[ro->nhist++];
            h->at = imdb_rd_u64(r);
            h->what = imdb_rd_u8(r);
            imdb_rd_copy(r, h->commit, 32);
            /* by (commit, what), within the role's life, each before the current entry of its kind */
            if (r->err || (h->what != IMDB_RPAY_NAME && h->what != IMDB_RPAY_VERIFIER) || h->at < ro->created_at ||
                (k && (h->at < ro->hist[k - 1].at || (h->at == ro->hist[k - 1].at && h->what <= ro->hist[k - 1].what))) ||
                (h->what == IMDB_RPAY_NAME ? h->at >= ro->nent.at : ro->has_ver ? h->at >= ro->vent.at : h->at > seq))
                goto bad;
        }
        if (role_gone(ro)) goto bad; /* stage 2: a role erased whole is not listed (one encoding) */
    }
    return IMDB_OK;
bad:
    imdb_rcat_free(c);
    return imdb_fail(e, IMDB_ERR_CORRUPT, "manifest: a bad roles section");
fail:
    imdb_rcat_free(c);
    return e->code;
}

/* the roles object's entries into the catalog's current entries (by role and what, each its commitment's and its shape);
 * strict: every current entry not erased filled, nothing else in the object, a live name once among the live roles */
int imdb_rcat_fill(imdb_rcat *c, const uint8_t *obj, size_t len, bool strict, imdb_err *e)
{
    if (!obj) goto checks; /* no object (a zero hash): every current entry must be erased */
    imdb_rd r;
    imdb_rd_init(&r, obj, len);
    uint8_t mg[8];
    imdb_rd_copy(&r, mg, 8);
    uint32_t n = imdb_rd_u32(&r);
    uint32_t prole = 0, pwhat = 0;
    if (!r.err && imdb_later_magic(mg, 8, "IMDBRLO1")) /* format 1: a later imagedb's, by name */
        return imdb_fail(e, IMDB_ERR_UNSUPPORTED, "manifest: a roles object %.8s, written by a later imagedb, which "
                         "format 1 does not read", (const char *)mg);
    if (r.err || memcmp(mg, kRolObj, 8) || !n || n > imdb_rd_left(&r) / 25) goto bad;
    for (uint32_t k = 0; k < n; k++) {
        uint32_t id = imdb_rd_u32(&r);
        uint8_t w = imdb_rd_u8(&r), salt[16];
        imdb_rd_copy(&r, salt, 16);
        uint32_t l = imdb_rd_u32(&r);
        if (r.err || (w != IMDB_RPAY_NAME && w != IMDB_RPAY_VERIFIER) || (k && (id < prole || (id == prole && w <= pwhat))) ||
            l > (w == IMDB_RPAY_NAME ? IMDB_MAX_IDENT : IMDB_SCRAM_BYTES_MAX))
            goto bad;
        const uint8_t *p = imdb_rd_bytes(&r, l);
        if (!p) goto bad;
        prole = id, pwhat = w;
        imdb_role *ro = imdb_rcat_by_id(c, id);
        imdb_rent *x = !ro ? NULL : w == IMDB_RPAY_NAME ? &ro->nent : ro->has_ver ? &ro->vent : NULL;
        uint8_t cm[32];
        imdb_role_commit(id, w, salt, p, l, cm);
        imdb_scram v;
        imdb_err e2 = {0};
        bool ok = x && !x->erased && !x->bytes && !memcmp(cm, x->commit, 32) &&
                  (w == IMDB_RPAY_NAME ? imdb_role_name_ok(p, l) : imdb_scram_decode(p, l, &v, &e2) == 0);
        if (!ok) {
            if (strict) goto bad;
            continue; /* a FLOOR seed: the current lake's entry, not F's */
        }
        if (!(x->bytes = imdb_alloc(l ? l : 1, e))) return e->code;
        memcpy(x->bytes, p, l);
        x->len = l;
        memcpy(x->salt, salt, 16);
        if (w == IMDB_RPAY_NAME) {
            memcpy(ro->name, p, l);
            ro->name[l] = '\0';
        }
    }
    if (imdb_rd_left(&r)) goto bad;
checks:
    for (uint32_t i = 0; strict && i < c->n; i++) {
        const imdb_role *ro = c->roles[i];
        if ((!ro->nent.erased && !ro->nent.bytes) || (ro->has_ver && !ro->vent.erased && !ro->vent.bytes)) goto bad;
        for (uint32_t k = 0; k < i && !ro->dropped_at && ro->name[0]; k++) /* a live name once among the live roles */
            if (!c->roles[k]->dropped_at && !strcmp(c->roles[k]->name, ro->name)) goto bad;
    }
    return IMDB_OK;
bad:
    return imdb_fail(e, IMDB_ERR_CORRUPT, "manifest: a bad roles object");
}

/* no role reaches itself by its memberships (an iterative walk, each role once a start); *rc an allocation's error */
static bool grants_acyclic(const imdb_rcat *c, imdb_err *e, int *rc)
{
    bool any = false;
    for (uint32_t i = 0; i < c->n && !any; i++) any = c->roles[i]->ngroups != 0;
    *rc = IMDB_OK;
    if (!any) return true; /* no membership: nothing allocated (every manifest parse passes here) */
    uint32_t m = c->n ? c->n : 1;
    uint8_t *color = imdb_alloc(m, e); /* 0 unseen, 1 on the path, 2 done */
    uint32_t *stack = color ? imdb_alloc_array(m, sizeof *stack, e) : NULL;
    uint32_t *next = stack ? imdb_alloc_array(m, sizeof *next, e) : NULL;
    bool ok = true;
    *rc = next ? IMDB_OK : e->code;
    for (uint32_t s = 0; next && ok && s < c->n; s++) {
        if (color[s]) continue;
        uint32_t top = 0;
        stack[top++] = s;
        next[s] = 0;
        color[s] = 1;
        while (top && ok) {
            uint32_t x = stack[top - 1];
            const imdb_role *r = c->roles[x];
            if (next[x] == r->ngroups) {
                color[x] = 2;
                top--;
                continue;
            }
            uint32_t gid = r->groups[next[x]++], y = role_index(c, gid);
            if (y >= c->n || c->roles[y]->id != gid) continue;
            if (color[y] == 1) ok = false;
            else if (!color[y]) {
                color[y] = 1;
                next[y] = 0;
                stack[top++] = y;
            }
        }
    }
    imdb_free(color);
    imdb_free(stack);
    imdb_free(next);
    return ok;
}

int imdb_rcat_get_grants(imdb_rd *r, imdb_obj_live_fn live, const void *arg, imdb_rcat *c, imdb_err *e)
{
    uint32_t n = imdb_rd_u32(r);
    if (r->err || n > IMDB_MAX_GRANTS || n > imdb_rd_left(r) / IMDB_GRANT_REC_MEMBER) goto bad;
    imdb_grant_rec prev;
    memset(&prev, 0, sizeof prev);
    for (uint32_t k = 0; k < n; k++) {
        imdb_grant_rec g;
        imdb_grant_get(r, &g);
        if (r->err || !imdb_grants_ok(&g, 1) || (k && imdb_grant_cmp(&prev, &g) >= 0)) goto bad;
        prev = g;
        imdb_role *ra = role_live(c, g.a);
        if (!ra || (g.kind == IMDB_GRANT_PRIV ? !live(arg, g.okind, g.b) : !role_live(c, g.b))) goto bad;
        if (g.kind == IMDB_GRANT_PRIV) {
            if (ra->nprivs == ra->capprivs) {
                imdb_rpriv *np = grow_arr(ra->privs, &ra->capprivs, ra->nprivs + 1, IMDB_MAX_GRANTS, sizeof *ra->privs, e);
                if (!np) goto fail;
                ra->privs = np;
            }
            ra->privs[ra->nprivs++] = (imdb_rpriv){.okind = g.okind, .oid = g.b, .privs = g.privs}; /* in order: appended */
        } else {
            if (ra->ngroups == ra->capgroups) {
                uint32_t *ng = grow_arr(ra->groups, &ra->capgroups, ra->ngroups + 1, IMDB_MAX_GRANTS, sizeof *ra->groups, e);
                if (!ng) goto fail;
                ra->groups = ng;
            }
            ra->groups[ra->ngroups++] = g.b;
        }
        c->ngrants++;
    }
    int rc = IMDB_OK;
    if (!grants_acyclic(c, e, &rc) && !rc) goto bad;
    if (rc) goto fail;
    return IMDB_OK;
bad:
    imdb_rcat_free(c);
    return imdb_fail(e, IMDB_ERR_CORRUPT, "manifest: a bad grants section");
fail:
    imdb_rcat_free(c);
    return e->code;
}
