/* L (N2's records): roles, their privileges and memberships (docs/roles-design.md). The catalog only: no session
 * carries a role yet (N1's will), so nothing here grants or refuses a read or a write. A catalog (imdb_rcat) is the
 * engine's (db->rc) or VERIFY's model, the same rules applied to each. */
#ifndef IMDB_ROLE_H
#define IMDB_ROLE_H

#include <stdbool.h>
#include <stdint.h>

#include "limits.h"
#include "log.h"
#include "scram.h"
#include "util.h"

typedef struct imdb_db imdb_db;

/* a role's name or verifier as the catalog holds it: the payload entry a commit set */
typedef struct imdb_rent {
    uint64_t at;          /* the commit that set it */
    uint8_t commit[32];
    uint8_t salt[16];
    uint8_t *bytes;       /* allocated, wiped at its free; NULL when erased, or (a FLOOR seed's) when no lake holds them */
    bool erased;          /* stage 2: erased (an ERASE named it), or a redacted copy's pending its ERASE */
    bool pending;         /* a redacted copy's: its op's entry redacted, the ERASE naming it not yet applied (erased too) */
    bool doomed;          /* the writer's ERASE ROLE between its plan and its commit: the encoder's erased */
    uint32_t len;
} imdb_rent;

/* an earlier entry, superseded by a later op: what an ERASE ROLE may name (never its bytes) */
typedef struct imdb_rhist {
    uint64_t at;
    uint8_t what;         /* IMDB_RPAY_* */
    bool pending, doomed; /* as an imdb_rent's (stage 2) */
    uint8_t commit[32];
} imdb_rhist;

typedef struct imdb_rpriv { /* a privilege record the role holds: an object and its bits */
    uint8_t okind;
    uint32_t oid, privs;
} imdb_rpriv;

typedef struct imdb_role {
    uint32_t id;
    uint64_t created_at, dropped_at; /* dropped_at 0: live */
    uint32_t attrs;                  /* IMDB_RA_* */
    char name[IMDB_MAX_IDENT + 1];   /* its current name ("" once erased) */
    imdb_rent nent, vent;            /* its name's and its verifier's entries (vent only with has_ver) */
    bool has_ver;
    imdb_rhist *hist;                /* earlier entries, by (commit, what) */
    uint32_t nhist, caphist;
    imdb_rpriv *privs;               /* by (okind, oid) */
    uint32_t nprivs, capprivs;
    uint32_t *groups;                /* the roles it is a member of, ascending */
    uint32_t ngroups, capgroups;
} imdb_role;

typedef struct imdb_rcat {
    imdb_role **roles;  /* the roles held, by id ascending: live, and dropped ones not yet erased */
    uint32_t n, cap;
    uint32_t last;      /* the last role id made (0: none) */
    uint32_t ngrants;   /* live privilege and membership records (IMDB_MAX_GRANTS) */
    uint64_t npending;  /* stage 2: entries a redacted copy holds pending their ERASE (the engine's db->pending_auth counts
                         * them too) */
} imdb_rcat;

/* whether a table or view is live, by the catalog's owner (the engine's, VERIFY's model, a manifest's) */
typedef bool (*imdb_obj_live_fn)(const void *arg, uint8_t okind, uint32_t oid);
bool imdb_db_obj_live(const void *arg, uint8_t okind, uint32_t oid); /* the engine's: arg its imdb_db */

imdb_role *imdb_rcat_by_name(const imdb_rcat *c, const char *name); /* the live role of a name */
imdb_role *imdb_rcat_by_id(const imdb_rcat *c, uint32_t id);        /* a role held, live or dropped */
imdb_role *imdb_role_by_name(imdb_db *db, const char *name);         /* the engine's */
imdb_role *imdb_role_by_id(imdb_db *db, uint32_t id);
uint32_t imdb_role_privs(const imdb_role *r, uint8_t okind, uint32_t oid);
bool imdb_role_member(const imdb_role *r, uint32_t group);

/* The statements' engine (each commits on its own; the install after the commit allocates nothing). ver NULL: no
 * verifier (CREATE), or PASSWORD NULL (ALTER with IMDB_RF_VERIFIER). */
int imdb_create_role(imdb_db *db, const char *name, uint32_t attrs, const imdb_scram *ver, imdb_err *e);
int imdb_alter_role(imdb_db *db, imdb_role *r, uint32_t fields, uint32_t attrs, const char *name, const imdb_scram *ver,
                    imdb_err *e);
int imdb_drop_role(imdb_db *db, imdb_role *r, imdb_err *e);
/* GRANT or REVOKE of a statement's records (privileges by object, memberships), in any order with repeats: made
 * canonical here (sorted, merged, each the bits it adds or removes, none that changes nothing); *logged the records
 * the op holds (0: nothing changed, no op) */
int imdb_grant_revoke(imdb_db *db, bool revoke, imdb_grant_rec *recs, uint32_t n, uint32_t *logged, imdb_err *e);

/* after the commit: the op's change into the catalog (the writer's from its carrier, into the room reserved); false:
 * no room (the caller stops its handle) */
bool imdb_role_install(imdb_rcat *c, const imdb_op *o, uint64_t seq);
/* replay's and VERIFY's ops 33 to 37: the rules (an op past one is CORRUPT: no writer signs it), then the install */
int imdb_role_apply(imdb_rcat *c, imdb_obj_live_fn live, const void *arg, const imdb_op *o, uint64_t seq, imdb_err *e);
/* a DROP TABLE's or DROP VIEW's: the grants on it end (no op: every copy applies it at the drop's commit) */
void imdb_grants_end_object(imdb_rcat *c, uint8_t okind, uint32_t oid);
/* stage 2: ERASE ROLE (docs/roles-design.md §11). The entries ERASE ROLE name reaches: the live role of that name, its
 * earlier entries; every dropped role whose last name it was, everything it holds; by (role, seq, what). A name no
 * role holds is an error; *n 0: a known role with nothing left */
int imdb_role_erase_collect(const imdb_rcat *c, const char *name, imdb_rerase **out, uint32_t *n, imdb_err *e);
/* the writer's plan: its entries doomed (the one encoder takes them as erased); undoom clears every mark */
void imdb_role_doom(imdb_rcat *c, const imdb_rerase *x, uint32_t n);
void imdb_role_undoom(imdb_rcat *c);
/* op 12's role entries at commit seq: the rules (each an entry the role keeps, by its commitment; a current one a
 * dropped role's; erased already only as a redacted copy's pending one), then each erased (its bytes wiped; an earlier
 * entry leaves the list; a dropped role holding nothing more leaves the catalog, its id spent). cb is told each entry
 * and whether it was pending (settled now) or held its bytes (its payload in the log at x->seq unless a cut took it):
 * the redaction's note, VERIFY's erasure incomplete; its error stops the apply. Allocates nothing: the writer's install
 * too (every rule met by its own list) */
typedef int (*imdb_rerase_fn)(void *arg, const imdb_rerase *x, bool pending, imdb_err *e);
int imdb_role_erase_apply(imdb_rcat *c, const imdb_rerase *x, uint32_t n, uint64_t seq, imdb_rerase_fn cb, void *arg,
                          imdb_err *e);
/* the redaction's question: whether role's entry set at commit seq is erased (a role no longer held: erased whole) */
bool imdb_rcat_entry_erased(const imdb_rcat *c, uint32_t role, uint64_t seq, uint8_t what);
void imdb_role_free(imdb_role *r);
void imdb_rcat_free(imdb_rcat *c);

/* manifest 18's sections 5 and 6, and the roles' object (docs/roles-design.md §10). Section 5: the roles object's hash, the
 * last id, then each role held by id, its current name's and verifier's commits and commitments (erased or not), its
 * earlier entries; never a name's or a verifier's bytes: a manifest is kept (a keeper, FLOOR's F) past any ERASE, so
 * the bytes are in the roles object (<hash>.rol), which GC removes as it removes a rewritten segment. Section 6: the
 * live grants in the log's order. The parse strict; the object's fill strict for a snapshot open (every current entry
 * not erased there, nothing more), lenient for a FLOOR seed (the current lake's object: F's entries it still holds) */
int imdb_rcat_object(const imdb_rcat *c, imdb_buf *obj, uint8_t hash[32], imdb_err *e); /* empty: none, a zero hash */
void imdb_rcat_put_roles(imdb_buf *b, const imdb_rcat *c, const uint8_t objhash[32]);
void imdb_rcat_put_grants(imdb_buf *b, const imdb_rcat *c);
int imdb_rcat_get_roles(imdb_rd *r, uint64_t seq, imdb_rcat *c, uint8_t objhash[32], imdb_err *e);
int imdb_rcat_get_grants(imdb_rd *r, imdb_obj_live_fn live, const void *arg, imdb_rcat *c, imdb_err *e);
int imdb_rcat_fill(imdb_rcat *c, const uint8_t *obj, size_t len, bool strict, imdb_err *e);

#endif
