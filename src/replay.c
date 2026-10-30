/* Log replay, replica apply, shipping and log redaction. */
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "cpu.h"
#include "db_internal.h"
#include "fsio.h"
#include "lake.h"
#include "pool.h"
#include "stream.h"

#include "logdir.h"
#include "repl.h"
#include "seed.h"
#include "writer.h"

/* ---- applying one commit (replay and replicas) ---------------------------- */

static int apply_insert(imdb_db *db, imdb_table *t, const imdb_op *op, uint64_t vid, const uint8_t commit[32],
                        uint64_t seq, uint64_t pk_link, bool commit_checked, imdb_err *e)
{
    if (vid != t->nver)
        return imdb_fail(e, IMDB_ERR_CORRUPT, "commit %llu: version id out of sequence in table %s",
                         (unsigned long long)seq, t->s.name);
    if (op->pkind == IMDB_PAYLOAD_ROW) {
        if (!commit_checked) {
            uint8_t check[32];
            imdb_row_commit(t->s.id, op->salt, op->row, op->row_len, check);
            if (memcmp(check, commit, 32) != 0)
                return imdb_fail(e, IMDB_ERR_VERIFY, "commit %llu: row payload does not match its commitment (table %s)",
                                 (unsigned long long)seq, t->s.name);
        }
        imdb_value vals[IMDB_MAX_COLS];
        imdb_err e2 = {0};
        if (imdb_row_decode(&t->s, op->row, op->row_len, vals, &e2))
            return imdb_fail(e, IMDB_ERR_CORRUPT, "commit %llu: %s", (unsigned long long)seq, e2.msg);
        uint64_t *head = imdb_hmap_get(&t->pk, &vals[t->s.pk]);
        if (head && imdb_vh(t, *head)->end == IMDB_LIVE)
            return imdb_fail(e, IMDB_ERR_CORRUPT, "commit %llu: duplicate live primary key in table %s",
                             (unsigned long long)seq, t->s.name);
        if (imdb_index_unique_replay(t, vals, seq, e)) return e->code; /* an UPDATE's old version ended already */
    }
    if (imdb_ver_push(t, e)) return e->code;
    imdb_version *v = imdb_vh(t, vid);
    v->begin = seq;
    memcpy(imdb_vc(t, vid)->commit, commit, 32);
    t->live++;
    if (op->pkind == IMDB_PAYLOAD_REDACTED) {
        v->flags = IMDB_V_STUB | IMDB_V_PENDING_AUTH;
        db->pending_auth++;
        return IMDB_OK;
    }
    memcpy(imdb_vc(t, vid)->salt, op->salt, 16);
    v->row_off = t->arena.len;
    v->row_len = op->row_len;
    imdb_buf_put(&t->arena, op->row, op->row_len);
    if (imdb_buf_check(&t->arena, e)) return e->code;
    if (imdb_index_version(t, vid, NULL, e)) return e->code;
    (void)pk_link;
    return IMDB_OK;
}

/* A RETIRE's rule, from this copy's own state (lake.h imdb_retire): past the boundary it has, the commit after
 * it beginning one of its log segments, below every table's horizon. */
static int retire_rule(const imdb_db *db, uint64_t b, uint64_t seq, imdb_err *e)
{
    size_t si = imdb_logseg_find(db->segs, db->nsegs, b + 1);
    if (b <= db->boundary || si == db->nsegs || db->segs[si] != b + 1)
        return imdb_fail(e, IMDB_ERR_CORRUPT, "commit %llu: RETIRE's boundary %llu is not past %llu, or does not end a "
                         "log segment", (unsigned long long)seq, (unsigned long long)b, (unsigned long long)db->boundary);
    for (uint32_t i = 0; i < db->nt; i++)
        if (b >= db->t[i]->horizon)
            return imdb_fail(e, IMDB_ERR_CORRUPT, "commit %llu: RETIRE's boundary is not below table %s's horizon",
                             (unsigned long long)seq, db->t[i]->s.name);
    return IMDB_OK;
}

static int apply_end(imdb_table *t, uint64_t vid, const uint8_t commit[32], uint64_t seq, imdb_err *e)
{
    imdb_vloc at; /* unknown, or retired: a log never ends one twice; the lake's alone (stage 3b): it ended */
    int where = imdb_v_find(t, vid, &at);
    if (where == IMDB_VAT_NONE)
        return imdb_fail(e, IMDB_ERR_CORRUPT, "commit %llu: delete of unknown version", (unsigned long long)seq);
    imdb_version *v = at.v;
    if (!v || v->end != IMDB_LIVE)
        return imdb_fail(e, IMDB_ERR_CORRUPT, "commit %llu: delete of a version that is not live (table %s)",
                         (unsigned long long)seq, t->s.name);
    if (memcmp(imdb_v_commit(t, vid), commit, 32) != 0)
        return imdb_fail(e, IMDB_ERR_VERIFY, "commit %llu: delete precondition failed: version commitment differs",
                         (unsigned long long)seq);
    v->end = seq;
    imdb_seg_set_end(t, v, seq);
    t->live--;
    return IMDB_OK;
}

/* a version's end, and whether it began at seq, wherever it is (held, or the lake's alone: stage 3b), for the checks
 * after a commit's ops, which must not read the store alone (0, false: it is nowhere) */
static uint64_t v_end(const imdb_table *t, uint64_t vid)
{
    imdb_vloc at;
    int where = imdb_v_find(t, vid, &at);
    return where == IMDB_VAT_HELD ? at.v->end : where == IMDB_VAT_LAKE ? at.g->end[at.row] : 0;
}

static bool v_begun(const imdb_table *t, uint64_t vid, uint64_t seq)
{
    imdb_vloc at;
    int where = imdb_v_find(t, vid, &at);
    return where == IMDB_VAT_HELD ? at.v->begin == seq : where == IMDB_VAT_LAKE && at.g->begin[at.row] == seq;
}

int imdb_apply_commit(imdb_db *db, imdb_commit_rec *c, const imdb_commit_pre *pre, imdb_err *e)
{
    if (c->seq != db->seq + 1)
        return imdb_fail(e, IMDB_ERR_VERIFY, "commit %llu out of order (expected %llu)", (unsigned long long)c->seq,
                         (unsigned long long)(db->seq + 1));
    if (memcmp(c->prev, db->head, 32) != 0)
        return imdb_fail(e, IMDB_ERR_VERIFY, "hash chain broken at commit %llu", (unsigned long long)c->seq);
    if (!c->sig_ok && c->promote && !imdb_commit_authentic(c, db->writer_pk, db->db_id, db->meta.has_root ? db->meta.root : NULL))
        return imdb_fail(e, IMDB_ERR_AUTH, "commit %llu: a promotion without this database's root certificate",
                         (unsigned long long)c->seq);
    if (!c->sig_ok && !c->promote && !imdb_commit_sig_valid(db->writer_pk, c->seq, c->hlen, c->hash, c->sig))
        return imdb_fail(e, IMDB_ERR_AUTH, "commit %llu: signature invalid (not signed by the writer key of epoch %u)",
                         (unsigned long long)c->seq, imdb_current_epoch(db));
    if (c->time_us <= db->last_time)
        return imdb_fail(e, IMDB_ERR_CORRUPT, "commit %llu: commit time not increasing", (unsigned long long)c->seq);
    if (c->alg != db->meta.digest_alg) /* a log never mixes them: the digests below are META's algorithm's */
        return imdb_fail(e, IMDB_ERR_CORRUPT, "commit %llu: digest algorithm %u, but this database's is %u",
                         (unsigned long long)c->seq, c->alg, db->meta.digest_alg);

    /* 1. state digest, from the header alone, before touching any state */
    uint32_t creates = 0;
    for (uint32_t i = 0; i < c->nops; i++) creates += c->ops[i].code == IMDB_OP_CREATE_TABLE;
    uint32_t nt = db->nt + creates;
    for (uint32_t i = 0; i < c->nops; i++) {
        const imdb_op *o = &c->ops[i];
        bool dml = o->code == IMDB_OP_INSERT || o->code == IMDB_OP_DELETE || o->code == IMDB_OP_UPDATE;
        if (dml && o->table >= nt)
            return imdb_fail(e, IMDB_ERR_CORRUPT, "commit %llu: unknown table %u", (unsigned long long)c->seq, o->table);
    }
    int rc = IMDB_OK;
    imdb_lthash *post = NULL;
    imdb_lthash *delta = imdb_alloc_aligned(nt ? nt : 1, sizeof *delta, e);
    bool *touched = imdb_alloc_array(nt ? nt : 1, sizeof *touched, e);
    if (!delta || !touched) {
        rc = e->code;
        goto out;
    }
    if (pre && pre->deltas) { /* computed by replay's parallel pre-pass */
        for (uint32_t t = 0; t < nt; t++) touched[t] = false;
        for (uint32_t k = 0; k < pre->nd; k++) {
            uint32_t t = pre->tab[k];
            if (t >= nt) {
                rc = imdb_fail(e, IMDB_ERR_CORRUPT, "commit %llu: unknown table %u", (unsigned long long)c->seq, t);
                goto out;
            }
            if (!touched[t]) imdb_lthash_zero(&delta[t]);
            touched[t] = true;
            imdb_lthash_add(&delta[t], &pre->delta[k]);
        }
    } else if ((rc = imdb_digest_delta(db->meta.digest_alg, c->ops, c->nops, nt, delta, touched, e))) {
        goto out;
    }
    imdb_lthash global = db->global;
    for (uint32_t t = 0; t < nt; t++)
        if (touched[t]) imdb_lthash_add(&global, &delta[t]);
    post = imdb_alloc_aligned(nt ? nt : 1, sizeof *post, e);
    if (!post) {
        rc = e->code;
        goto out;
    }
    for (uint32_t t = 0; t < nt; t++) {
        if (t < db->nt) post[t] = db->t[t]->digest;
        else imdb_lthash_zero(&post[t]);
        if (touched[t]) imdb_lthash_add(&post[t], &delta[t]);
    }
    bool digest_ok;
    if (pre && pre->deltas) {
        digest_ok = pre->digest_ok;
    } else {
        uint8_t digest[32];
        imdb_lthash_digest(db->meta.digest_alg, &global, digest);
        digest_ok = memcmp(digest, c->digest, 32) == 0;
    }
    if (!digest_ok) {
        rc = imdb_fail(e, IMDB_ERR_VERIFY, "commit %llu: state digest mismatch (replica diverged or log tampered)",
                       (unsigned long long)c->seq);
        goto out;
    }

    /* 2. apply operations in log order */
    uint64_t seq = c->seq;
    for (uint32_t i = 0; i < c->nops && !rc; i++) {
        imdb_op *o = &c->ops[i];
        imdb_table *t = (o->code == IMDB_OP_CREATE_TABLE || o->code == IMDB_OP_CHECKPOINT || o->code == IMDB_OP_ERASE ||
                         o->code == IMDB_OP_RETIRE)
                            ? NULL
                            : imdb_table_by_id(db, o->table);
        if (!t && (o->code == IMDB_OP_INSERT || o->code == IMDB_OP_DELETE || o->code == IMDB_OP_UPDATE ||
                   o->code == IMDB_OP_COMPACT || o->code == IMDB_OP_CREATE_INDEX || o->code == IMDB_OP_DROP_INDEX ||
                   o->code == IMDB_OP_SET_RETENTION || o->code == IMDB_OP_EXPIRE)) {
            rc = imdb_fail(e, IMDB_ERR_CORRUPT, "commit %llu: unknown table %u", (unsigned long long)seq, o->table);
            break;
        }
        switch (o->code) {
        case IMDB_OP_CREATE_TABLE:
            if (o->table != db->nt) rc = imdb_fail(e, IMDB_ERR_CORRUPT, "commit %llu: table id out of sequence", (unsigned long long)seq);
            else rc = imdb_table_new(db, o->schema, e);
            break;
        case IMDB_OP_SET_RETENTION:
            t->retention_us = o->retention_us;
            break;
        case IMDB_OP_EXPIRE: /* the retention's time rule is VERIFY's: it needs the segments' first times */
            if (t->retention_us == IMDB_RETAIN_FOREVER)
                rc = imdb_fail(e, IMDB_ERR_CORRUPT, "commit %llu: EXPIRE of table %u, which is kept FOREVER",
                               (unsigned long long)seq, o->table);
            else if (o->purge_before <= t->horizon)
                rc = imdb_fail(e, IMDB_ERR_CORRUPT, "commit %llu: EXPIRE does not move table %u's horizon",
                               (unsigned long long)seq, o->table);
            else t->horizon = o->purge_before;
            break;
        case IMDB_OP_INSERT:
            rc = apply_insert(db, t, o, o->vid, o->commit, seq, IMDB_NONE, pre && pre->payloads_checked, e);
            break;
        case IMDB_OP_DELETE:
            rc = apply_end(t, o->vid, o->commit, seq, e);
            break;
        case IMDB_OP_UPDATE: {
            if ((rc = apply_end(t, o->vid, o->commit, seq, e))) break;
            imdb_value oldk = {0};
            bool old_known = imdb_version_key(t, o->vid, t->s.pk, &oldk) == IMDB_OK;
            if (old_known && o->pkind == IMDB_PAYLOAD_ROW) {
                imdb_value newk;
                imdb_row_get(&t->s, o->row, o->row_len, t->s.pk, &newk);
                if (imdb_value_cmp(&oldk, &newk) != 0) {
                    rc = imdb_fail(e, IMDB_ERR_CORRUPT, "commit %llu: UPDATE changes the primary key", (unsigned long long)seq);
                    break;
                }
            }
            rc = apply_insert(db, t, o, o->new_vid, o->new_commit, seq, o->vid, pre && pre->payloads_checked, e);
            break;
        }
        case IMDB_OP_RETIRE:
            if (o->code == IMDB_OP_RETIRE && (rc = retire_rule(db, o->purge_before, seq, e))) break;
            /* fall through */
        case IMDB_OP_CHECKPOINT:
        case IMDB_OP_COMPACT:
            rc = imdb_lake_apply_physical(db, c, o, post, &global, e);
            break;
        case IMDB_OP_ERASE:
            for (uint32_t k = 0; k < o->n_erase && !rc; k++) {
                const imdb_erase_ent *en = &o->erase[k];
                imdb_table *et = imdb_table_by_id(db, en->table);
                imdb_vloc at; /* held, or (stage 3b) the lake's alone: an ended version past the memory window */
                int where = et ? imdb_v_find(et, en->vid, &at) : IMDB_VAT_NONE;
                if (where == IMDB_VAT_NONE) {
                    rc = imdb_fail(e, IMDB_ERR_CORRUPT, "commit %llu: ERASE names an unknown version", (unsigned long long)seq);
                    break;
                }
                if (memcmp(imdb_v_commit(et, en->vid), en->commit, 32) != 0) {
                    rc = imdb_fail(e, IMDB_ERR_VERIFY, "commit %llu: ERASE commitment mismatch", (unsigned long long)seq);
                    break;
                }
                imdb_version *v = at.v;
                if (v ? v->end == IMDB_LIVE : at.g->end[at.row] == IMDB_LIVE) {
                    rc = imdb_fail(e, IMDB_ERR_CORRUPT, "commit %llu: ERASE of a live version", (unsigned long long)seq);
                    break;
                }
                if (v && (v->flags & IMDB_V_PENDING_AUTH)) {
                    db->pending_auth--;
                } else if (v ? !(v->flags & IMDB_V_STUB) : !(at.g->flags[at.row] & IMDB_SEG_STUB)) {
                    db->needs_redaction = true; /* its payload is still in the segment of commit begin */
                    if ((rc = imdb_redact_note(db, v ? v->begin : at.g->begin[at.row], e))) break;
                }
                if (v) imdb_stub_version(et, en->vid); /* the lake's alone: its segment is rewritten below */
            }
            if (!rc) rc = imdb_lake_apply_physical(db, c, o, post, &global, e);
            break;
        case IMDB_OP_WRITER_KEY: break; /* installed with the commit (4.) */
        case IMDB_OP_CREATE_INDEX: {
            imdb_index_def d;
            memset(&d, 0, sizeof d);
            snprintf(d.name, sizeof d.name, "%s", o->iname);
            d.flags = o->iflags;
            d.ncols = o->incols;
            memcpy(d.cols, o->icols, sizeof d.cols);
            uint32_t at = 0;
            if (!imdb_index_def_ok(&d, t->s.ncols))
                rc = imdb_fail(e, IMDB_ERR_CORRUPT, "commit %llu: an index on a column table %s does not have",
                               (unsigned long long)seq, t->s.name);
            else if (imdb_index_find(db, o->iname, NULL))
                rc = imdb_fail(e, IMDB_ERR_CORRUPT, "commit %llu: an index name already in use", (unsigned long long)seq);
            else if (imdb_index_add(t, &d, e))
                rc = imdb_fail(e, IMDB_ERR_CORRUPT, "commit %llu: more indexes than a table may have", (unsigned long long)seq);
            if (rc) break;
            imdb_index_find(db, d.name, &at);
            rc = imdb_index_unique_build(t, &t->idx[at], e); /* now, in an open too: the inserts after it are checked */
            if (rc == IMDB_ERR_CONSTRAINT)
                rc = imdb_fail(e, IMDB_ERR_CORRUPT, "commit %llu: a unique index over keys two live rows share (table %s)",
                               (unsigned long long)seq, t->s.name);
            else if (!rc)
                imdb_index_rebuild_table(db, t); /* a replica builds it now; an open, at its end */
            break;
        }
        case IMDB_OP_DROP_INDEX: {
            uint32_t pos = 0;
            if (imdb_index_find(db, o->iname, &pos) != t)
                rc = imdb_fail(e, IMDB_ERR_CORRUPT, "commit %llu: DROP INDEX of an index table %s does not have",
                               (unsigned long long)seq, t->s.name);
            else
                imdb_index_remove(t, pos);
            break;
        }
        default:
            rc = imdb_fail(e, IMDB_ERR_CORRUPT, "commit %llu: unexpected op", (unsigned long long)seq);
        }
    }
    if (rc) goto out;

    /* 3. the version store must now reflect every op (catches apply bugs that
     *    header-level checks cannot see) */
    for (uint32_t i = 0; i < c->nops && !rc; i++) {
        const imdb_op *o = &c->ops[i];
        imdb_table *t = imdb_table_by_id(db, o->table);
        bool ok = true;
        switch (o->code) {
        case IMDB_OP_INSERT:
            ok = t && v_begun(t, o->vid, seq) && !memcmp(imdb_v_commit(t, o->vid), o->commit, 32) &&
                 (v_end(t, o->vid) == IMDB_LIVE || v_end(t, o->vid) == seq);
            break;
        case IMDB_OP_DELETE:
            ok = t && v_end(t, o->vid) == seq;
            break;
        case IMDB_OP_UPDATE:
            ok = t && v_end(t, o->vid) == seq && v_begun(t, o->new_vid, seq) &&
                 !memcmp(imdb_v_commit(t, o->new_vid), o->new_commit, 32);
            break;
        case IMDB_OP_ERASE:
            for (uint32_t k = 0; k < o->n_erase && ok; k++) {
                imdb_table *et = imdb_table_by_id(db, o->erase[k].table);
                imdb_vloc at;
                int where = et ? imdb_v_find(et, o->erase[k].vid, &at) : IMDB_VAT_NONE;
                ok = where == IMDB_VAT_HELD ? (at.v->flags & IMDB_V_STUB) != 0
                                            : where == IMDB_VAT_LAKE && (at.g->flags[at.row] & IMDB_SEG_STUB);
            }
            break;
        default:
            break;
        }
        if (!ok)
            rc = imdb_fail(e, IMDB_ERR_VERIFY, "commit %llu: version store does not reflect op %u", (unsigned long long)seq, i);
    }
    if (rc) goto out;

    /* 4. install */
    if (imdb_commit_writer_op(c) && (rc = imdb_writer_apply(db, c, e))) goto out; /* later commits verify under its key */
    for (uint32_t i = 0; i < c->nops; i++) {
        uint8_t code = c->ops[i].code;
        if (code == IMDB_OP_INSERT || code == IMDB_OP_DELETE || code == IMDB_OP_UPDATE || code == IMDB_OP_CREATE_TABLE ||
            code == IMDB_OP_CREATE_INDEX || code == IMDB_OP_DROP_INDEX || code == IMDB_OP_SET_RETENTION ||
            code == IMDB_OP_EXPIRE)
            db->lake_dirty = true; /* the manifest records the definitions, the retentions and the horizons */
        if (code == IMDB_OP_ERASE) db->last_erase = seq; /* a pin from before it never keeps the files (lake.h) */
        db->ended_pass += code == IMDB_OP_DELETE || code == IMDB_OP_UPDATE; /* the memory window's trigger */
    }
    db->seq = seq;
    memcpy(db->head, c->hash, 32);
    imdb_index_catch_up(db); /* a replica's structures follow each applied commit (an open: at its end) */
    for (uint32_t i = 0; i < c->nops; i++)
        if (c->ops[i].code == IMDB_OP_ERASE)
            for (uint32_t ti = 0; ti < db->nt; ti++) imdb_index_rebuild_table(db, db->t[ti]); /* stubs out */
    db->last_hlen = c->hlen;
    memcpy(db->last_sig, c->sig, IMDB_SIG_LEN);
    db->last_time = c->time_us;
    for (uint32_t t = 0; t < nt && t < db->nt; t++)
        if (touched[t]) imdb_lthash_add(&db->t[t]->digest, &delta[t]);
    db->global = global;
    rc = imdb_ci_push(db, c->time_us, c->hash, c->digest, e);
    if (!rc) imdb_evict_policy(db); /* between commits, as the primary's between transactions */
out:
    imdb_free(post);
    imdb_free(delta);
    imdb_free(touched);
    return rc;
}

/* ---- replay at open --------------------------------------------------------- */

/* Frames are replayed in batches (the bounds VERIFY uses). A parallel pre-pass
 * decodes each frame and checks its signature, its row commitments, its digest
 * deltas and (by prefix sums from the state before the batch) its recorded
 * digest; imdb_apply_commit then applies the frames in log order, with every
 * check in the same order and with the same messages as one frame at a time. */

#define RCHUNK_OPS 4096u
#define RCHUNK_TABLES 16u /* tables one chunk keeps deltas for (2 KiB each): bounded memory */

typedef struct rframe {
    const uint8_t *p;
    size_t len;
    imdb_commit_rec c;
    bool decoded, payloads_ok, digest_ok;
    bool deltas;       /* deltas and digest_ok below are valid (else apply computes them) */
    uint32_t known;    /* table ids that can exist by this commit */
    imdb_err err;      /* why it does not decode */
    size_t ch0, nch;   /* its delta chunks */
    uint32_t nd;       /* the chunks' deltas, concatenated */
    uint32_t *tab;
    imdb_lthash *delta;
} rframe;

typedef struct rchunk {
    uint32_t frame, lo, hi;
    uint32_t nd;
    uint32_t *tab;
    imdb_lthash *delta;
    bool nomem, overflow;
} rchunk;

typedef struct rbatch {
    rframe *f;
    size_t nf;
    rchunk *ch;
    size_t nch;
    const uint8_t *db_id, *root; /* a promotion's certificate names the database; root: META's, or NULL */
    uint8_t gkey[(IMDB_VERIFY_BATCH + 63) / 64][IMDB_PUBKEY_LEN]; /* the key in effect at each group's start */
    imdb_lthash *states; /* the global state after each frame (prefix sums) */
    uint8_t alg;         /* the database's digest algorithm (META) */
} rbatch;

static void rpre_frame(void *ctx, size_t i)
{
    rbatch *b = ctx;
    rframe *f = &b->f[i];
    if (imdb_frame_decode_body(f->p + IMDB_FRAME_HDR, f->len - IMDB_FRAME_HDR, &f->c, &f->err)) return;
    f->decoded = true; /* the signature is checked by rpre_sigs; an invalid one is left for imdb_apply_commit to report */
    f->payloads_ok = true;
    for (uint32_t k = 0; k < f->c.nops && f->payloads_ok; k++) {
        const imdb_op *o = &f->c.ops[k];
        if (!imdb_op_has_payload(o->code) || o->pkind != IMDB_PAYLOAD_ROW) continue;
        uint8_t chk[32]; /* the decoder enforces schema id == table, so o->table is the commitment's id */
        imdb_row_commit(o->table, o->salt, o->row, o->row_len, chk);
        f->payloads_ok = memcmp(chk, o->code == IMDB_OP_INSERT ? o->commit : o->new_commit, 32) == 0;
    }
}

/* The signatures of frames [64 g, 64 g + 64), in batches of one writer key each (a WRITER_KEY
 * commit inside the group starts the next). */
static void rpre_sigs(void *ctx, size_t g)
{
    rbatch *b = ctx;
    imdb_commit_rec *recs[64] = {0};
    size_t n = 0;
    for (size_t i = 64 * g; i < b->nf && i < 64 * g + 64; i++)
        if (b->f[i].decoded) recs[n++] = &b->f[i].c;
    uint8_t key[IMDB_PUBKEY_LEN];
    memcpy(key, b->gkey[g], sizeof key);
    imdb_commit_sigs_check(key, b->db_id, b->root, recs, n);
}

static imdb_lthash *rchunk_slot(rchunk *ch, uint32_t table)
{
    for (uint32_t i = 0; i < ch->nd; i++)
        if (ch->tab[i] == table) return &ch->delta[i];
    if (ch->nd == RCHUNK_TABLES) {
        ch->overflow = true;
        return NULL;
    }
    imdb_err ge = {0};
    uint32_t *nt = imdb_realloc_array(ch->tab, ch->nd, ch->nd + 1, sizeof *nt, &ge);
    if (!nt) {
        ch->nomem = true;
        return NULL;
    }
    ch->tab = nt;
    imdb_lthash *nd = imdb_alloc_aligned(ch->nd + 1, sizeof *nd, &ge);
    if (!nd) {
        ch->nomem = true;
        return NULL;
    }
    if (ch->nd) memcpy(nd, ch->delta, ch->nd * sizeof *nd);
    imdb_free(ch->delta);
    ch->delta = nd;
    ch->tab[ch->nd] = table;
    imdb_lthash_zero(&ch->delta[ch->nd]);
    return &ch->delta[ch->nd++];
}

static void rpre_chunk(void *ctx, size_t i)
{
    rbatch *b = ctx;
    rchunk *ch = &b->ch[i];
    const rframe *f = &b->f[ch->frame];
    imdb_lthash el;
    for (uint32_t k = ch->lo; k < ch->hi; k++) {
        const imdb_op *o = &f->c.ops[k];
        if (o->code != IMDB_OP_INSERT && o->code != IMDB_OP_DELETE && o->code != IMDB_OP_UPDATE) continue;
        if (o->table >= f->known) continue; /* imdb_apply_commit reports the unknown table */
        imdb_lthash *d = rchunk_slot(ch, o->table);
        if (!d) return; /* out of memory, or too many tables: the commit sums its own */
        imdb_lthash_element(b->alg, o->commit, &el);
        if (o->code == IMDB_OP_INSERT) imdb_lthash_add(d, &el);
        else imdb_lthash_sub(d, &el);
        if (o->code == IMDB_OP_UPDATE) {
            imdb_lthash_element(b->alg, o->new_commit, &el);
            imdb_lthash_add(d, &el);
        }
    }
}

static void rpre_digest(void *ctx, size_t i)
{
    rbatch *b = ctx;
    rframe *f = &b->f[i];
    uint8_t d[32];
    imdb_lthash_digest(b->alg, &b->states[i], d);
    f->digest_ok = memcmp(d, f->c.digest, 32) == 0;
}

static void rbatch_free(rbatch *b)
{
    for (size_t i = 0; i < b->nf; i++) {
        if (b->f[i].decoded) imdb_commit_free(&b->f[i].c);
        imdb_free(b->f[i].tab);
        imdb_free(b->f[i].delta);
    }
    for (size_t i = 0; i < b->nch; i++) {
        imdb_free(b->ch[i].tab);
        imdb_free(b->ch[i].delta);
    }
    imdb_free(b->ch);
}

/* The pre-pass over frames f[0..nf). Only allocation failures are errors here;
 * everything it finds wrong is reported later by the ordered pass. */
static int rbatch_prepare(imdb_db *db, rbatch *b, imdb_err *e)
{
    imdb_par_for(b->nf, rpre_frame, b);
    /* each group's starting key, from the WRITER_KEY ops before it (an unsigned one is rejected at
     * its own commit, before anything after it counts) */
    uint8_t key[IMDB_PUBKEY_LEN];
    memcpy(key, db->writer_pk, sizeof key);
    for (size_t i = 0; i < b->nf; i++) {
        if (i % 64 == 0) memcpy(b->gkey[i / 64], key, sizeof key);
        const imdb_op *w = b->f[i].decoded ? imdb_commit_writer_op(&b->f[i].c) : NULL;
        if (w) memcpy(key, w->new_pk, sizeof key);
    }
    imdb_par_for((b->nf + 63) / 64, rpre_sigs, b);
    size_t nch = 0;
    uint32_t known = db->nt;
    for (size_t i = 0; i < b->nf; i++) {
        rframe *f = &b->f[i];
        for (uint32_t k = 0; f->decoded && k < f->c.nops; k++) known += f->c.ops[k].code == IMDB_OP_CREATE_TABLE;
        f->known = known;
        if (f->decoded && f->c.sig_ok) nch += (f->c.nops + RCHUNK_OPS - 1) / RCHUNK_OPS;
    }
    b->ch = imdb_alloc_array(nch ? nch : 1, sizeof *b->ch, e);
    if (!b->ch) return e->code;
    for (size_t i = 0; i < b->nf; i++) {
        rframe *f = &b->f[i];
        f->ch0 = b->nch;
        if (!f->decoded || !f->c.sig_ok) continue; /* left for imdb_apply_commit to reject */
        for (uint32_t lo = 0; lo < f->c.nops; lo += RCHUNK_OPS) {
            uint32_t hi = f->c.nops - lo < RCHUNK_OPS ? f->c.nops : lo + RCHUNK_OPS;
            b->ch[b->nch++] = (rchunk){.frame = (uint32_t)i, .lo = lo, .hi = hi};
        }
        f->nch = b->nch - f->ch0;
    }
    imdb_par_for(b->nch, rpre_chunk, b);
    /* each frame's deltas in one list, and the running state after it; the chain stops at the
     * first frame without them (undecodable, unsigned, or too many tables in a chunk) */
    imdb_lthash run = db->global;
    size_t chained = 0;
    for (size_t i = 0; i < b->nf; i++) {
        rframe *f = &b->f[i];
        uint32_t nd = 0;
        bool usable = f->decoded && f->c.sig_ok;
        for (size_t k = 0; k < f->nch; k++) {
            if (b->ch[f->ch0 + k].nomem) return imdb_fail(e, IMDB_ERR_NOMEM, "replay: out of memory");
            usable = usable && !b->ch[f->ch0 + k].overflow;
            nd += b->ch[f->ch0 + k].nd;
        }
        if (!usable) break;
        f->tab = imdb_alloc_array(nd ? nd : 1, sizeof *f->tab, e);
        f->delta = imdb_alloc_aligned(nd ? nd : 1, sizeof *f->delta, e);
        if (!f->tab || !f->delta) return e->code;
        for (size_t k = 0; k < f->nch; k++) {
            const rchunk *ch = &b->ch[f->ch0 + k];
            for (uint32_t j = 0; j < ch->nd; j++) {
                f->tab[f->nd] = ch->tab[j];
                f->delta[f->nd] = ch->delta[j];
                imdb_lthash_add(&run, &ch->delta[j]);
                f->nd++;
            }
        }
        b->states[i] = run;
        f->deltas = true;
        chained = i + 1;
    }
    imdb_par_for(chained, rpre_digest, b);
    return IMDB_OK;
}

/* Replays one segment's frames. Only the last segment may end in a torn
 * frame (truncated unless read-only) or be empty; every other segment must
 * end with a commit that publishes a manifest, and none may contain one
 * before its end (logdir.h). */
static int replay_segment(imdb_db *db, size_t si, bool ro, imdb_err *e)
{
    uint64_t first = db->segs[si];
    bool last = si + 1 == db->nsegs;
    imdb_logseg seg;
    if (imdb_logseg_load(db->logdirfd, first, &seg, e)) return e->code;
    if (!seg.tagged && db->log_tagged && !(last && imdb_logseg_blank(&seg))) { /* the format only moves forward */
        imdb_logseg_free(&seg);
        return imdb_fail(e, IMDB_ERR_CORRUPT, "segment %llu is untagged, after a tagged one", (unsigned long long)first);
    }
    db->log_tagged = seg.tagged;
    uint8_t *buf = seg.buf;
    rframe *fr = imdb_alloc_array(IMDB_VERIFY_BATCH, sizeof *fr, e);
    imdb_lthash *states = imdb_alloc_aligned(IMDB_VERIFY_BATCH, sizeof *states, e);
    size_t off = 0;
    uint64_t frames = 0;
    bool ended = false; /* the previous frame published a manifest */
    int rc = !fr || !states ? e->code : IMDB_OK;
    bool done = false;
    while (!rc && !done) {
        /* a batch of whole frames, stopping at the end, a torn tail or damage */
        size_t nf = 0, bytes = 0, scan_off = off;
        imdb_scan_status st = IMDB_SCAN_END;
        imdb_err e2 = {0};
        while (nf < IMDB_VERIFY_BATCH && (nf == 0 || bytes < IMDB_VERIFY_BATCH_BYTES)) {
            size_t flen = 0;
            st = imdb_logseg_scan(&seg, scan_off, &flen, &e2);
            if (st != IMDB_SCAN_FRAME) break;
            memset(&fr[nf], 0, sizeof fr[nf]);
            fr[nf].p = buf + scan_off;
            fr[nf].len = flen;
            nf++;
            bytes += flen;
            scan_off += flen;
        }
        rbatch b = {.f = fr, .nf = nf, .db_id = db->db_id, .root = db->meta.has_root ? db->meta.root : NULL, .states = states,
                    .alg = db->meta.digest_alg};
        if (nf) rc = rbatch_prepare(db, &b, e);
        for (size_t i = 0; i < nf && !rc; i++) {
            rframe *f = &fr[i];
            if (ended) {
                rc = imdb_fail(e, IMDB_ERR_CORRUPT, "segment %llu continues past a commit that publishes a manifest",
                               (unsigned long long)first);
                break;
            }
            if (!f->decoded) {
                rc = imdb_fail(e, f->err.code ? f->err.code : IMDB_ERR_CORRUPT, "%s", f->err.msg);
                break;
            }
            if (frames == 0 && f->c.seq != first)
                rc = imdb_fail(e, IMDB_ERR_CORRUPT, "segment %llu begins with commit %llu", (unsigned long long)first,
                               (unsigned long long)f->c.seq);
            imdb_commit_pre pre = {.payloads_checked = f->payloads_ok, .deltas = f->deltas, .digest_ok = f->digest_ok,
                                   .nd = f->nd, .tab = f->tab, .delta = f->delta};
            if (!rc) rc = imdb_apply_commit(db, &f->c, &pre, e);
            for (uint32_t k = 0; k < f->c.nops; k++) ended |= imdb_op_publishes_manifest(f->c.ops[k].code);
            if (rc) break;
            off += f->len;
            frames++;
        }
        rbatch_free(&b);
        if (rc || st == IMDB_SCAN_FRAME) continue; /* a full batch: on to the next one */
        done = true;
        if (st == IMDB_SCAN_END) break;
        if (st == IMDB_SCAN_CORRUPT || !last) {
            rc = imdb_fail(e, IMDB_ERR_CORRUPT, "segment %llu: %s", (unsigned long long)first, e2.msg);
            break;
        }
        /* the end of the last segment, after every frame before it was applied:
         * an append that never finished, unless the writer had acknowledged it */
        if ((rc = imdb_tail_check(&db->dur, db->have_dur, db->seq, st, e2.msg, e))) break;
        snprintf(db->warning, sizeof db->warning, "torn tail (%s); last good commit %llu%s", e2.msg,
                 (unsigned long long)db->seq, ro ? " (not truncated: read-only)" : "; tail truncated");
        if (!ro) {
            char name[IMDB_LOGSEG_NAME + 1];
            imdb_logseg_name(first, name);
            if (seg.tagged) {
                rc = imdb_logseg_drop_tail(db->logdirfd, &seg, e);
            } else {
                int fd = imdb_io_openat(db->logdirfd, name, O_WRONLY | O_CLOEXEC | O_NOFOLLOW);
                if (fd < 0 || imdb_io_ftruncate(fd, (off_t)off) != 0 || imdb_io_fsync(fd) != 0)
                    rc = imdb_fail(e, IMDB_ERR_IO, "cannot truncate torn log tail: %s", strerror(errno));
                if (fd >= 0) close(fd);
            }
        }
    }
    imdb_free(fr);
    imdb_free(states);
    imdb_logseg_free(&seg);
    if (rc) return rc;
    if (!last && !ended)
        return imdb_fail(e, IMDB_ERR_CORRUPT, "segment %llu ends without a commit that publishes a manifest",
                         (unsigned long long)first);
    if (last && frames == 0 && first != db->seq + 1)
        return imdb_fail(e, IMDB_ERR_CORRUPT, "empty last segment %llu does not follow commit %llu",
                         (unsigned long long)first, (unsigned long long)db->seq);
    if (last) {
        db->log_size = off;
        db->log_rotate = ended;
        db->log_phys = seg.end.next; /* tagged: where the next group begins, past a dropped tail too */
        db->log_fill = seg.size;
        db->log_group = false;
    }
    return IMDB_OK;
}

/* Open: the published lake snapshot at commit S is the starting state when it
 * is usable (its manifest recorded by the signed commit S, every object
 * present and well-formed), and only the segments after S are replayed with
 * every check. Anything else falls back to replaying the whole log. */
/* Has the log grown past what this open replayed: a segment it did not list, or a last segment
 * longer than what it read? A tagged one does not grow by its size (its fill is there already):
 * it grew when the sector its next group would begin at is no longer zero. */
static bool log_grew(imdb_db *db)
{
    uint64_t *segs = NULL;
    size_t n = 0;
    imdb_err e = {0};
    if (imdb_logdir_list(db->logdirfd, &segs, &n, &e)) return false;
    bool grew = n > db->nsegs;
    if (!grew && n && db->nsegs && segs[n - 1] == db->segs[db->nsegs - 1]) {
        char name[IMDB_LOGSEG_NAME + 1];
        imdb_logseg_name(segs[n - 1], name);
        if (db->log_tagged) {
            int fd = imdb_io_openat(db->logdirfd, name, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
            uint8_t s[IMDB_TSEG_SECTOR];
            ssize_t r = fd < 0 ? -1 : imdb_io_pread(fd, s, sizeof s, (off_t)(db->log_phys * IMDB_TSEG_SECTOR));
            for (ssize_t i = 0; i < r && !grew; i++) grew = s[i] != 0;
            if (fd >= 0) close(fd);
        } else {
            struct stat st;
            grew = imdb_io_fstatat(db->logdirfd, name, &st, AT_SYMLINK_NOFOLLOW) == 0 && (uint64_t)st.st_size > db->log_size;
        }
    }
    imdb_free(segs);
    return grew;
}

int imdb_replay(imdb_db *db, bool ro, imdb_err *e)
{
    size_t start = 0;
    imdb_err why = {0}; /* the last snapshot's failure: past a cut it is the open's own */
    for (unsigned attempt = 1;; attempt++) {
        if (imdb_logdir_list(db->logdirfd, &db->segs, &db->nsegs, e)) return e->code;
        db->capsegs = db->nsegs;
        /* each segment's first commit time, read when first needed (db.c: expiry, and the window's floor, which the
         * snapshot load below takes: stage 3b), recorded as segments begin; again on a retry's new listing */
        imdb_free(db->seg_time);
        db->seg_time = imdb_alloc_array(db->capsegs ? db->capsegs : 1, sizeof *db->seg_time, e);
        if (!db->seg_time) return e->code;
        db->log_rotate = true; /* no segment yet: the first append creates one */
        db->log_tagged = false; /* a retry reads the segments again from the first */
        if (db->full_replay) break;
        uint64_t S = 0;
        bool moved = false;
        imdb_err e2 = {0};
        if (imdb_lake_load_snapshot(db, &S, &moved, &e2) == IMDB_OK) {
            if (S) {
                size_t si = imdb_logseg_find(db->segs, db->nsegs, S);
                /* commit S ends its segment; past a cut its segment may be gone, the log beginning at S + 1 */
                start = si < db->nsegs ? si + 1 : 0;
                db->snapshot_seq = S;
            }
            break;
        }
        imdb_reset_state(db);
        if (moved && attempt < IMDB_PIN_RETRIES) { /* its generation went while it was read: as things are now */
            imdb_free(db->segs);
            db->segs = NULL;
            db->nsegs = db->capsegs = 0;
            continue;
        }
        why = e2;
        snprintf(db->warning, sizeof db->warning, "lake snapshot not used (%s); replayed the whole log", e2.msg);
        break;
    }
    /* the epochs WRITERS (or FLOOR) proved past the snapshot are re-derived from the tail; with no snapshot, all of them
     * from commit 1 (a seeded copy has its snapshot and no segment holding it: start 0, the schedule kept to it) */
    if (start || db->snapshot_seq) imdb_writers_cut(db, db->snapshot_seq);
    else imdb_writers_reset(db);
    /* past a cut (FLOOR) only a snapshot can start the replay: the state at the log's first commit is nowhere else */
    /* no frame from commit 1 to replay: a log beginning past it, or FLOOR with no log at all (a seeded copy's) */
    bool cut = (db->nsegs && db->segs[0] != 1) || (db->log_floor && !db->nsegs);
    uint64_t first = db->nsegs ? db->segs[0] : db->log_floor + 1;
    if (cut && db->snapshot_seq && db->snapshot_seq + 1 < first)
        return imdb_fail(e, IMDB_ERR_STATE, "the log before commit %llu is retired: an open needs a lake snapshot at or "
                         "past it, which is older; restore the lake from a replica or a backup", (unsigned long long)first);
    if (cut && !db->snapshot_seq)
        return imdb_fail(e, IMDB_ERR_STATE, "the log before commit %llu is retired: an open needs a lake snapshot at or "
                         "past it, which did not load (%s); restore what it lacks from a replica or a backup",
                         (unsigned long long)first, why.msg[0] ? why.msg : "none is published");
    for (size_t si = start; si < db->nsegs; si++) {
        int rc = replay_segment(db, si, ro, e);
        if (rc) return rc;
    }
    if (db->have_dur) { /* the log must still hold every commit the writer acknowledged, and that very commit */
        if (imdb_tail_check(&db->dur, true, db->seq, IMDB_SCAN_END, "the log ends at a frame boundary", e))
            return e->code;
        uint8_t h[32];
        bool known = db->dur.seq <= db->seq && (db->dur.seq == 0 || db->dur.seq >= db->ci_first);
        if (known && db->dur.seq == 0) imdb_genesis_hash(db->db_id, h);
        else if (known) memcpy(h, db->ci[db->dur.seq - db->ci_first].hash, 32);
        if (known && memcmp(h, db->dur.head, 32) != 0)
            return imdb_fail(e, IMDB_ERR_CORRUPT, "DURABLE names commit %llu with another hash: it belongs to a different "
                             "history than this log", (unsigned long long)db->dur.seq);
        if (!db->dur.synced && db->dur.seq > db->seq) /* the loss --nosync accepts, but never silently */
            imdb_warn(db, "commits %llu..%llu were written under --nosync and are not in the log (lost in a crash)",
                      (unsigned long long)(db->seq + 1), (unsigned long long)db->dur.seq);
    }
    if (db->pending_auth && !db->replica)
        return imdb_fail(e, IMDB_ERR_CORRUPT, "log contains %llu redacted payloads that no ERASE authorises",
                         (unsigned long long)db->pending_auth);
    /* A published lake at a commit the log no longer holds. LAKE_HEAD waits for the log to be
     * durable through its commit, so that commit was on disk, unless an older writer published
     * it under --nosync (the watermark then says unsynced): that loss is reported and the lake
     * rebuilt from the log; any other is refused like a synced watermark past the end. */
    bool lake_present = false;
    uint64_t ls = 0;
    uint8_t lm[32];
    imdb_err el = {0};
    if (imdb_lake_head(db->dirfd, &lake_present, &ls, lm, &el) == IMDB_OK && lake_present && ls > db->seq) {
        /* A read-only open racing its writer: LAKE_HEAD was published after this open listed the
         * log, from commits the listing did not reach. If the log grew since, nothing is lost and
         * this handle stays at its own consistent prefix; a log that did not grow lost them. */
        if (ro && log_grew(db)) return IMDB_OK;
        if (!db->have_dur || db->dur.synced)
            return imdb_fail(e, IMDB_ERR_CORRUPT,
                             "LAKE_HEAD names commit %llu, past the end of the log (commit %llu): the lake was published "
                             "from commits that are lost; restore the log from a replica, or drop them with imagedb "
                             "recover", (unsigned long long)ls, (unsigned long long)db->seq);
        db->lake_ahead = true;
        imdb_warn(db, "the published lake (commit %llu) is ahead of the log (commit %llu): commits written under "
                  "--nosync were lost in a crash; %s", (unsigned long long)ls, (unsigned long long)db->seq,
                  ro ? "a writable open rebuilds the lake from the log" : "the lake is rebuilt from the log");
    }
    return IMDB_OK;
}

/* ---- redaction ------------------------------------------------------------------- */

int imdb_redact_note(imdb_db *db, uint64_t seq, imdb_err *e)
{
    if (db->nsegs && seq < db->segs[0]) return IMDB_OK; /* in no segment here (cut below FLOOR): gone with it */
    if (db->nredact == db->capredact) {
        size_t nc = db->capredact ? db->capredact * 2 : 64;
        uint64_t *n = imdb_realloc_array(db->redact_seqs, db->capredact, nc, sizeof *n, e);
        if (!n) return e->code;
        db->redact_seqs = n;
        db->capredact = nc;
    }
    db->redact_seqs[db->nredact++] = seq;
    return IMDB_OK;
}

/* Rewrites one segment with every payload of a stubbed version replaced by
 * the redaction marker. Descriptors, headers and signatures are unchanged
 * (they never contained the payload). Idempotent. */
static int redact_segment(imdb_db *db, size_t si, imdb_err *e)
{
    uint64_t first = db->segs[si];
    char name[IMDB_LOGSEG_NAME + 1];
    imdb_logseg_name(first, name);
    imdb_logseg seg;
    if (imdb_logseg_load(db->logdirfd, first, &seg, e)) return e->code;
    const uint8_t *buf = seg.buf;
    size_t len = seg.len;
    imdb_buf out, pay, whole;
    imdb_buf_init(&out);
    imdb_buf_init(&pay);
    imdb_buf_init(&whole);
    int rc = IMDB_OK;
    bool any = false;
    size_t off = 0;
    while (!rc) {
        size_t flen = 0;
        imdb_err e2 = {0};
        imdb_scan_status st = imdb_logseg_scan(&seg, off, &flen, &e2);
        if (st == IMDB_SCAN_END) break;
        if (st != IMDB_SCAN_FRAME) {
            rc = imdb_fail(e, IMDB_ERR_CORRUPT, "redaction: %s", e2.msg);
            break;
        }
        const uint8_t *body = buf + off + IMDB_FRAME_HDR;
        imdb_commit_rec c;
        if ((rc = imdb_frame_decode_body(body, flen - IMDB_FRAME_HDR, &c, e))) break;
        bool changed = false;
        for (uint32_t i = 0; i < c.nops; i++) {
            imdb_op *o = &c.ops[i];
            if (!imdb_op_has_payload(o->code) || o->pkind != IMDB_PAYLOAD_ROW) continue;
            imdb_table *t = imdb_table_by_id(db, o->table);
            uint64_t vid = o->code == IMDB_OP_INSERT ? o->vid : o->new_vid;
            imdb_vloc at; /* a stub the store holds, or one only the lake does (stage 3b) */
            int where = t ? imdb_v_find(t, vid, &at) : IMDB_VAT_NONE;
            if (where == IMDB_VAT_HELD ? (at.v->flags & IMDB_V_STUB) != 0
                                       : where == IMDB_VAT_LAKE && (at.g->flags[at.row] & IMDB_SEG_STUB)) {
                o->pkind = IMDB_PAYLOAD_REDACTED;
                changed = true;
            }
        }
        if (changed) {
            pay.len = 0;
            imdb_commit_encode_payload(&c, &pay);
            if (!(rc = imdb_buf_check(&pay, e))) {
                imdb_frame_build(body + IMDB_BODY_DESC, c.hlen, c.seq, c.hash, c.sig, pay.p, pay.len, &out);
                rc = imdb_buf_check(&out, e);
            }
            any = true;
        } else {
            imdb_buf_put(&out, buf + off, flen);
        }
        imdb_commit_free(&c);
        off += flen;
    }
    if (!rc && off != len) rc = imdb_fail(e, IMDB_ERR_CORRUPT, "redaction: trailing bytes in segment");
    if (!rc) rc = imdb_buf_check(&out, e);
    /* a tagged segment is written whole again: its frames as one group, no fill (design.md §3) */
    const imdb_buf *w = &out;
    if (!rc && any && seg.tagged) {
        imdb_tseg_build(first, out.p, out.len, &whole);
        rc = imdb_buf_check(&whole, e);
        w = &whole;
    }
    bool is_last = si + 1 == db->nsegs;
    int oldfd = -1;
    if (!rc && any) {
        /* keep the old inode open so its bytes can be scrubbed after the swap */
        oldfd = imdb_io_openat(db->logdirfd, name, O_WRONLY | O_CLOEXEC | O_NOFOLLOW);
        rc = imdb_write_file_atomic(db->logdirfd, name, w->p, w->len, 0600, e);
        if (!rc && is_last && !db->read_only && !db->log_rotate) {
            if (db->logfd >= 0) close(db->logfd);
            db->logfd = imdb_io_openat(db->logdirfd, name, seg.tagged ? O_RDWR | O_CLOEXEC | O_NOFOLLOW
                                                                    : O_WRONLY | O_APPEND | O_CLOEXEC | O_NOFOLLOW);
            if (db->logfd < 0) rc = imdb_fail(e, IMDB_ERR_IO, "reopen log segment: %s", strerror(errno));
        }
        if (!rc && is_last) {
            db->log_size = out.len;
            if (seg.tagged) { /* the next group after the rewritten frames; the fill is extended as needed */
                db->log_phys = w->len / IMDB_TSEG_SECTOR;
                db->log_fill = w->len;
                db->log_group = false;
            }
        }
    }
    if (oldfd >= 0) {
        /* best-effort scrub of the replaced file; not a guarantee on SSD/COW media */
        static const uint8_t zeros[4096];
        /* a tagged one's fill is zeros already: up to its last non-zero sector */
        size_t used = seg.tagged ? (size_t)seg.end.dirty * IMDB_TSEG_SECTOR : seg.size;
        for (size_t z = 0; !rc && z < used; z += sizeof zeros) {
            size_t n = used - z < sizeof zeros ? used - z : sizeof zeros;
            if (imdb_io_pwrite(oldfd, zeros, n, (off_t)z) != (ssize_t)n) break;
        }
        if (imdb_io_fdatasync(oldfd) != 0) { /* best effort */ }
        close(oldfd);
    }
    imdb_logseg_free(&seg);
    imdb_buf_wipe_free(&out);
    imdb_buf_wipe_free(&pay);
    imdb_buf_wipe_free(&whole);
    return rc;
}

static int cmp_u64(const void *a, const void *b)
{
    uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;
    return x < y ? -1 : x > y;
}

/* Rewrites only the segments that hold payloads of versions stubbed since the
 * last redaction (their creating commits were noted), then publishes a lake
 * state that waited for it. With nothing noted (state from a crash before the
 * notes existed), every segment is checked. */
int imdb_redact_log(imdb_db *db, imdb_err *e)
{
    if (db->read_only) return imdb_fail(e, IMDB_ERR_STATE, "database opened read-only");
    int rc = IMDB_OK;
    if (db->nredact) {
        qsort(db->redact_seqs, db->nredact, sizeof *db->redact_seqs, cmp_u64);
        size_t prev = SIZE_MAX;
        for (size_t i = 0; i < db->nredact && !rc; i++) {
            size_t si = imdb_logseg_find(db->segs, db->nsegs, db->redact_seqs[i]);
            if (si == db->nsegs) {
                rc = imdb_fail(e, IMDB_ERR_STATE, "redaction: commit %llu is in no log segment",
                               (unsigned long long)db->redact_seqs[i]);
                break;
            }
            if (si != prev) rc = redact_segment(db, si, e);
            prev = si;
        }
    } else {
        for (size_t si = 0; si < db->nsegs && !rc; si++) rc = redact_segment(db, si, e);
    }
    if (rc) return rc;
    db->nredact = 0;
    db->needs_redaction = false;
    return imdb_lake_publish_pending(db, e);
}

/* ---- shipping --------------------------------------------------------------------- */

/* Streams every frame with seq > after_seq, in order, across segments, but
 * none past the writer's durable watermark (DURABLE): a frame whose fdatasync
 * has not returned could still be truncated, and a replica must never hold a
 * commit its primary does not. In follow mode it keeps polling; a segment
 * rewritten by redaction (new inode) is rescanned from its start, frames
 * already sent being skipped by seq. */
/* ship --acks: the replica's acknowledgements, checked against this primary's history. */
typedef struct ship_acks {
    int fd; /* -1 once the replica closed its side */
    int dirfd, logfd;
    uint8_t db_id[16];
    imdb_allow *allow;
    size_t nallow;
    uint8_t nonce[IMDB_NONCE_LEN]; /* this session's challenge (repl.h) */
    uint8_t buf[IMDB_ACK_LEN]; /* one arriving in pieces */
    size_t have;
    uint64_t base;   /* the window: hashes of the commits shipped since the last acknowledgement, */
    uint8_t (*h)[32]; /* base .. base + (hi - lo) - 1 in h[lo .. hi) */
    size_t lo, hi, cap;
    imdb_err lookup; /* why a log lookup failed */
} ship_acks;

/* The rare case (the first acknowledgement of a session, or one beyond the window): the commit's
 * hash from the log itself. 1, 0 when the log does not hold it, -1 on error (a->lookup). */
static int log_hash_at(ship_acks *a, uint64_t seq, uint8_t out[32])
{
    imdb_err *e = &a->lookup;
    if (seq == 0) {
        imdb_genesis_hash(a->db_id, out);
        return 1;
    }
    uint64_t *segs;
    size_t nsegs;
    if (imdb_logdir_list(a->logfd, &segs, &nsegs, e)) return -1;
    size_t si = imdb_logseg_find(segs, nsegs, seq);
    int found = 0;
    if (si < nsegs) {
        imdb_logseg seg;
        if (imdb_logseg_load(a->logfd, segs[si], &seg, e)) {
            imdb_free(segs);
            return -1;
        }
        for (size_t off = 0, flen = 0; !found; off += flen) {
            imdb_err e2 = {0};
            if (imdb_logseg_scan(&seg, off, &flen, &e2) != IMDB_SCAN_FRAME) break;
            if (imdb_frame_seq(seg.buf + off) == seq) {
                memcpy(out, imdb_frame_hash(seg.buf + off), 32);
                found = 1;
            }
        }
        imdb_logseg_free(&seg);
    }
    imdb_free(segs);
    return found;
}

static int ship_hash_at(void *ctx, uint64_t seq, uint8_t out[32])
{
    ship_acks *a = ctx;
    if (seq >= a->base && seq - a->base < a->hi - a->lo) {
        memcpy(out, a->h[a->lo + (seq - a->base)], 32);
        return 1;
    }
    return log_hash_at(a, seq, out);
}

static int win_push(ship_acks *a, uint64_t seq, const uint8_t hash[32], imdb_err *e)
{
    if (a->hi == a->lo) a->base = seq;
    else if (seq != a->base + (a->hi - a->lo)) return imdb_fail(e, IMDB_ERR_STATE, "ship: commits out of order");
    if (a->hi == a->cap && a->lo) {
        memmove(a->h, a->h + a->lo, (a->hi - a->lo) * sizeof *a->h);
        a->hi -= a->lo;
        a->lo = 0;
    } else if (a->hi == a->cap) {
        size_t nc = a->cap ? 2 * a->cap : 1024;
        if (nc > IMDB_MAX_UNACKED) nc = IMDB_MAX_UNACKED;
        uint8_t(*nh)[32] = imdb_realloc_array(a->h, a->cap, nc, sizeof *a->h, e);
        if (!nh) return e->code;
        a->h = nh;
        a->cap = nc;
    }
    memcpy(a->h[a->hi++], hash, 32);
    return IMDB_OK;
}

static bool win_full(const ship_acks *a) { return a && a->hi - a->lo >= IMDB_MAX_UNACKED; }

/* Every acknowledgement that has arrived (at most 1024 at a time, so shipping goes on). */
static int acks_drain(ship_acks *a, imdb_err *e)
{
    for (int k = 0; a->fd >= 0 && k < 1024;) {
        struct pollfd p = {.fd = a->fd, .events = POLLIN};
        int pr = poll(&p, 1, 0);
        if (pr < 0 && errno == EINTR) continue;
        if (pr <= 0) return IMDB_OK;
        ssize_t r = imdb_io_read(a->fd, a->buf + a->have, IMDB_ACK_LEN - a->have);
        if (r < 0 && errno == EINTR) continue;
        if (r < 0) return imdb_fail(e, IMDB_ERR_IO, "acknowledgements: read: %s", strerror(errno));
        if (r == 0) { /* the replica closed its side: shipping goes on without them */
            a->fd = -1;
            return IMDB_OK;
        }
        a->have += (size_t)r;
        if (a->have < IMDB_ACK_LEN) continue;
        a->have = 0;
        k++;
        imdb_ack ack;
        imdb_err_clear(&a->lookup);
        if (imdb_ack_receive(a->dirfd, a->db_id, a->nonce, &a->allow, &a->nallow, a->buf, ship_hash_at, a, &ack, e)) {
            if (a->lookup.code) *e = a->lookup;
            return e->code;
        }
        if (ack.seq > a->base) { /* later acknowledgements are at ack.seq or past it */
            uint64_t d = ack.seq - a->base < a->hi - a->lo ? ack.seq - a->base : a->hi - a->lo;
            a->lo += d;
            a->base += d;
        }
    }
    return IMDB_OK;
}

int imdb_ship_ex(const char *path, uint64_t after_seq, int outfd, const imdb_ship_opts *o, imdb_err *e)
{
    bool follow = o && o->follow;
    int dirfd = imdb_io_open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (dirfd < 0) return imdb_fail(e, IMDB_ERR_IO, "open %s: %s", path, strerror(errno));
    int logfd = imdb_open_dir_at(dirfd, IMDB_LOG_DIR, e);
    if (logfd < 0) {
        close(dirfd);
        return e->code;
    }
    ship_acks A, *acks = NULL;
    memset(&A, 0, sizeof A);
    int rc = IMDB_OK;
    if (o && o->ackfd >= 0) {
        uint8_t writer[IMDB_PUBKEY_LEN];
        A.fd = o->ackfd;
        A.dirfd = dirfd;
        A.logfd = logfd;
        if (!(rc = imdb_read_identity(path, A.db_id, writer, e))) rc = imdb_allowlist_load(dirfd, &A.allow, &A.nallow, e);
        /* the session's challenge, ahead of the first frame: only acknowledgements signed over it count */
        if (!rc) rc = imdb_random(A.nonce, sizeof A.nonce, e);
        uint8_t sr[IMDB_SESSION_LEN];
        imdb_session_encode(A.db_id, A.nonce, sr);
        if (!rc) rc = imdb_write_all(outfd, sr, sizeof sr, e);
        acks = &A;
    }
    bool seeded = false;
    if (!rc && after_seq == 0) { /* a primary cut below commit 1 begins a new replica with a seed (seed.h) */
        uint64_t *fs = NULL, S = 0;
        size_t nfs = 0;
        rc = imdb_logdir_list(logfd, &fs, &nfs, e);
        if (!rc && nfs && fs[0] > 1) {
            rc = imdb_seed_send(path, dirfd, logfd, outfd, &S, e);
            seeded = true; /* the stream ends with it: the replica comes back from S */
        }
        imdb_free(fs);
    }
    uint64_t last = after_seq, cur_first = 0, cur_ino = 0, cur_off = 0, cur_prev = 0;
    imdb_tseg_pos cur_pos = {0}; /* where reading a tagged segment goes on (cur_off: an untagged one) */
    bool cur_tagged = false;
    for (uint32_t nship = 0; !rc && !seeded;) {
        if (win_full(acks)) { /* the replica is this far behind: nothing more until it acknowledges */
            if ((rc = acks_drain(acks, e))) break;
            if (acks->fd < 0) {
                rc = imdb_fail(e, IMDB_ERR_STATE, "ship --acks: the replica closed its acknowledgements %u commits behind",
                               IMDB_MAX_UNACKED);
                break;
            }
            if (win_full(acks)) {
                struct pollfd p = {.fd = acks->fd, .events = POLLIN};
                (void)poll(&p, 1, 2);
                continue;
            }
        }
        imdb_durable w;
        bool have_w;
        if ((rc = imdb_durable_read(dirfd, &w, &have_w, e))) break;
        if (!have_w) {
            rc = imdb_fail(e, IMDB_ERR_STATE, "ship: %s has no DURABLE watermark yet; open it for writing once with this "
                           "version (it records which commits are durable)", path);
            break;
        }
        bool progressed = false, stalled = false;
        uint64_t *segs = NULL;
        size_t nsegs = 0;
        if (w.seq > last && (rc = imdb_logdir_list(logfd, &segs, &nsegs, e))) break; /* else nothing new to send */
        size_t si = imdb_logseg_find(segs, nsegs, last + 1);
        if (si == nsegs && nsegs) si = 0; /* everything after last is in the first segment or later */
        if (nsegs && segs[0] > last + 1) /* cut below (FLOOR): what the replica lacks is in no file here */
            rc = imdb_fail(e, IMDB_ERR_STATE, "ship: the log before commit %llu is retired here, and the replica holds commit "
                           "%llu: seed it again", (unsigned long long)segs[0], (unsigned long long)last);
        for (; si < nsegs && !rc; si++) {
            char name[IMDB_LOGSEG_NAME + 1];
            imdb_logseg_name(segs[si], name);
            int fd = imdb_io_openat(logfd, name, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
            struct stat st;
            if (fd < 0 || imdb_io_fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) {
                if (fd >= 0) close(fd);
                rc = imdb_fail(e, IMDB_ERR_IO, "ship: cannot read log segment");
                break;
            }
            bool resume = segs[si] == cur_first && (uint64_t)st.st_ino == cur_ino;
            uint64_t from = resume ? cur_off : 0, prev = resume ? cur_prev : segs[si] - 1;
            uint8_t hd[IMDB_TSEG_SECTOR];
            bool tagged = resume ? cur_tagged
                                 : imdb_io_pread(fd, hd, sizeof hd, 0) >= 4 && imdb_tseg_is_tagged(hd, sizeof hd);
            if (tagged) {
                /* frame by frame from where the last poll stopped, a window of sectors at a time; its
                 * size says nothing, the fill being there already (design.md §3, live readers) */
                imdb_tseg_pos pos = resume ? cur_pos : (imdb_tseg_pos){.sector = 1, .next = segs[si]};
                uint8_t want[IMDB_TSEG_SECTOR];
                imdb_tseg_header(segs[si], want);
                if (!resume && memcmp(hd, want, sizeof want) != 0)
                    rc = imdb_fail(e, IMDB_ERR_CORRUPT, "ship: tagged segment %llu: a malformed header",
                                   (unsigned long long)segs[si]);
                size_t win = 64u << 10, got = 0;
                uint64_t base = 0;
                uint8_t *buf = NULL;
                imdb_buf fb;
                imdb_buf_init(&fb);
                bool whole = true, reload = true;
                while (!rc) {
                    if (reload) {
                        imdb_free(buf);
                        base = pos.sector;
                        uint64_t at = base * IMDB_TSEG_SECTOR, size = (uint64_t)st.st_size;
                        size_t n = size > at ? (size_t)(size - at < win ? size - at : win) : 0;
                        n -= n % IMDB_TSEG_SECTOR;
                        buf = n ? imdb_alloc(n, e) : NULL;
                        if (n && !buf) {
                            rc = e->code;
                            break;
                        }
                        got = 0;
                        while (got < n) {
                            ssize_t r = imdb_io_pread(fd, buf + got, n - got, (off_t)(at + got));
                            if (r < 0 && errno == EINTR) continue;
                            if (r <= 0) break;
                            got += (size_t)r;
                        }
                        got -= got % IMDB_TSEG_SECTOR;
                        reload = false;
                    }
                    bool more = false;
                    imdb_tseg_pos save = pos;
                    if (imdb_tseg_next(buf, got, base, &pos, &fb, &more) != IMDB_SCAN_FRAME) {
                        if (more && (base * IMDB_TSEG_SECTOR + got < (uint64_t)st.st_size)) {
                            win *= 2;
                            reload = true;
                            continue;
                        }
                        /* nothing whole past here now: the writer is mid-append, unless a commit it
                         * acknowledged is damaged (a frame the watermark names is never written again) */
                        if (si + 1 == nsegs && prev + 1 <= w.seq)
                            rc = imdb_fail(e, IMDB_ERR_CORRUPT, "ship: commit %llu was acknowledged as durable, but its "
                                           "frame in tagged segment %llu is damaged or incomplete",
                                           (unsigned long long)(prev + 1), (unsigned long long)segs[si]);
                        whole = si + 1 < nsegs; /* a later segment is made only once this one ended */
                        break;
                    }
                    uint64_t seq = imdb_frame_seq(fb.p);
                    if (seq > w.seq) { /* not yet durable: the next poll sends it */
                        pos = save;
                        whole = false;
                        break;
                    }
                    if (seq > last) {
                        if (seq != last + 1) {
                            rc = imdb_fail(e, IMDB_ERR_CORRUPT, "ship: gap in log before commit %llu", (unsigned long long)seq);
                            break;
                        }
                        if (win_full(acks)) {
                            pos = save;
                            whole = false;
                            stalled = true;
                            break;
                        }
                        if ((rc = imdb_write_all(outfd, fb.p, fb.len, e))) break;
                        if (acks && (rc = win_push(acks, seq, imdb_frame_hash(fb.p), e))) break;
                        last = seq;
                        progressed = true;
                        if (acks && ++nship % 256 == 0 && (rc = acks_drain(acks, e))) break;
                    }
                    prev = seq;
                }
                cur_first = segs[si];
                cur_ino = (uint64_t)st.st_ino;
                cur_pos = pos;
                cur_prev = prev;
                cur_tagged = true;
                if (buf) imdb_wipe(buf, got);
                imdb_free(buf);
                imdb_buf_wipe_free(&fb);
                close(fd);
                if (!whole) break;
                continue;
            }
            size_t n = (uint64_t)st.st_size > from ? (size_t)((uint64_t)st.st_size - from) : 0;
            uint8_t *buf = n ? imdb_alloc(n, e) : NULL;
            size_t got = 0;
            if (n && !buf) {
                close(fd);
                rc = e->code;
                break;
            }
            while (got < n) {
                ssize_t r = imdb_io_pread(fd, buf + got, n - got, (off_t)(from + got));
                if (r < 0 && errno == EINTR) continue;
                if (r <= 0) break;
                got += (size_t)r;
            }
            close(fd);
            size_t off = 0;
            bool whole = true;
            while (!rc) {
                size_t flen = 0;
                imdb_err e2 = {0};
                imdb_scan_status sc = imdb_frame_scan(buf, got, off, &flen, &e2);
                if (sc == IMDB_SCAN_END) break;
                if (sc != IMDB_SCAN_FRAME) {
                    /* the writer is mid-append, unless a commit it acknowledged is damaged */
                    if (sc == IMDB_SCAN_CORRUPT)
                        rc = imdb_fail(e, IMDB_ERR_CORRUPT, "ship: %s", e2.msg);
                    else if (prev + 1 <= w.seq)
                        rc = imdb_fail(e, IMDB_ERR_CORRUPT, "ship: commit %llu was acknowledged as durable, but its frame is "
                                       "damaged or incomplete (%s)", (unsigned long long)(prev + 1), e2.msg);
                    whole = false;
                    break;
                }
                uint64_t seq = imdb_frame_seq(buf + off);
                if (seq > w.seq) { /* not yet durable: the next poll sends it */
                    whole = false;
                    break;
                }
                if (seq > last) {
                    if (seq != last + 1) {
                        rc = imdb_fail(e, IMDB_ERR_CORRUPT, "ship: gap in log before commit %llu", (unsigned long long)seq);
                        break;
                    }
                    if (win_full(acks)) { /* the replica is this far behind: its acknowledgements first */
                        whole = false;
                        stalled = true;
                        break;
                    }
                    if ((rc = imdb_write_all(outfd, buf + off, flen, e))) break;
                    if (acks && (rc = win_push(acks, seq, imdb_frame_hash(buf + off), e))) break;
                    last = seq;
                    progressed = true;
                    if (acks && ++nship % 256 == 0 && (rc = acks_drain(acks, e))) break;
                }
                prev = seq;
                off += flen;
            }
            cur_first = segs[si];
            cur_ino = (uint64_t)st.st_ino;
            cur_off = from + off;
            cur_prev = prev;
            cur_tagged = false;
            if (buf) imdb_wipe(buf, got);
            imdb_free(buf);
            if (!whole) break; /* later segments cannot exist past a partial or undurable frame */
        }
        imdb_free(segs);
        if (!rc && acks) rc = acks_drain(acks, e);
        if (rc || !follow) break;
        if (!progressed || stalled) {
            if (acks && acks->fd >= 0) { /* an acknowledgement, or 2 ms: a synchronous commit waits on both */
                struct pollfd p = {.fd = acks->fd, .events = POLLIN};
                (void)poll(&p, 1, 2);
            } else {
                struct timespec ts = {0, 200 * 1000 * 1000};
                nanosleep(&ts, NULL);
            }
        }
    }
    imdb_free(A.allow);
    imdb_free(A.h);
    close(logfd);
    close(dirfd);
    return rc;
}

int imdb_ship(const char *path, uint64_t after_seq, int outfd, bool follow, imdb_err *e)
{
    imdb_ship_opts o = {.follow = follow, .ackfd = -1};
    return imdb_ship_ex(path, after_seq, outfd, &o, e);
}

/* ---- replica apply --------------------------------------------------------------- */

/* More stream bytes ready now (buffered, or readable without blocking; a hang-up counts: the next
 * read sees the end). */
static bool input_ready(const imdb_fdsrc *src)
{
    if (src->off < src->len) return true;
    struct pollfd p = {.fd = src->fd, .events = POLLIN};
    return poll(&p, 1, 0) > 0;
}

/* An acknowledgement point: everything applied is made durable first (fdatasync'd appends, or
 * imdb_log_sync under --nosync, which fails the handle if it cannot), so db->seq is durable when
 * the caller's callback reports it. */
static int ack_point(imdb_db *db, imdb_apply_opts *o, imdb_err *e)
{
    if (imdb_log_sync(db, e)) return e->code;
    return o->applied(o->ctx, db);
}

int imdb_apply_stream_ex(imdb_db *db, int fd, uint64_t *applied, imdb_apply_opts *o, imdb_err *e)
{
    *applied = 0;
    if (o) {
        o->truncated = false;
        o->has_session = false;
        o->seeded = 0;
    }
    if (db->read_only) return imdb_fail(e, IMDB_ERR_STATE, "database opened read-only");
    if (!db->replica) return imdb_fail(e, IMDB_ERR_STATE, "apply is only allowed on a replica");
    if (db->failed) return imdb_fail(e, IMDB_ERR_STATE, "replica is in a failed state; reopen it");
    imdb_fdsrc *src = imdb_alloc(sizeof *src, e);
    if (!src) return e->code;
    imdb_fdsrc_init(src, fd);
    imdb_stream s;
    imdb_stream_init(&s, db->writer_pk, imdb_fdsrc_read, src);
    imdb_stream_set_trust(&s, db->db_id, db->meta.has_root ? db->meta.root : NULL);
    uint32_t since = 0, every = o && o->every ? o->every : 64; /* commits since the last acknowledgement point */
    bool session = false;
    uint8_t nonce[16];
    int rc = imdb_stream_session(&s, nonce, &session, e);
    if (rc && o) o->truncated = s.truncated;
    if (!rc && session && o) {
        memcpy(o->nonce, nonce, sizeof nonce);
        o->has_session = true;
        if (o->applied) rc = ack_point(db, o, e); /* where this replica stands, before anything arrives */
    }
    uint8_t sp[IMDB_SEED_PREFIX];
    bool seed = false;
    if (!rc) rc = imdb_stream_seed(&s, sp, &seed, e);
    if (!rc && seed) { /* taken into the directory; the frames come on the next connection, from its commit */
        rc = imdb_seed_take(db, &s, sp, e);
        if (o) {
            o->truncated = rc && s.truncated;
            o->seeded = rc ? 0 : db->seeded;
        }
        imdb_stream_free(&s);
        imdb_wipe(src, sizeof *src);
        imdb_free(src);
        return rc;
    }
    for (; !rc;) {
        bool eof;
        if ((rc = imdb_stream_next(&s, db->seq + 1, db->head, &eof, e))) {
            if (o) o->truncated = s.truncated;
            break;
        }
        if (eof) {
            /* A redacted payload is not authorised by its INSERT signature.
             * Keep the durable prefix for resumption, but never serve its
             * incomplete rows as a verified snapshot. */
            if (db->pending_auth || db->lake_unverified) {
                rc = imdb_fail(e, IMDB_ERR_AUTH,
                               "stream ended before ERASE authorised every redaction; resume apply before querying");
                if (o) o->truncated = true; /* resumable: the next stream continues it */
                break;
            }
            /* end of stream: recompute every table from the version store */
            if (*applied && (rc = imdb_check_state(db, e))) db->failed = true;
            if (!rc && o && o->applied && since) rc = ack_point(db, o, e);
            break;
        }
        if (db->mem_limit) { /* over its budget: stop before this commit, consistent (db.h) */
            imdb_mem_report mr;
            imdb_mem(db, &mr);
            if (mr.total > mr.limit) {
                rc = imdb_fail(e, IMDB_ERR_LIMIT, "memory budget: this replica holds %llu bytes, past its budget of %llu; "
                               "it stops before commit %llu, consistent: reopen it with a larger budget",
                               (unsigned long long)mr.total, (unsigned long long)mr.limit, (unsigned long long)(db->seq + 1));
                break;
            }
        }
        /* every byte of s.frame is authenticated; decode it strictly anyway */
        imdb_commit_rec c;
        rc = imdb_frame_decode_body(s.frame.p + IMDB_FRAME_HDR, s.frame.len - IMDB_FRAME_HDR, &c, e);
        if (!rc) {
            /* the stream reader verified the signature and every row against its commitment */
            c.sig_ok = true;
            imdb_commit_pre pre = {.payloads_checked = true};
            if ((rc = imdb_apply_commit(db, &c, &pre, e))) db->failed = true;
            if (!rc && (rc = imdb_log_append(db, s.frame.p, s.frame.len, e))) db->failed = true;
            for (uint32_t i = 0; !rc && i < c.nops; i++)
                if (imdb_op_publishes_manifest(c.ops[i].code)) db->log_rotate = true; /* same layout as the primary */
            imdb_err ew = {0}; /* derived: a failure costs a later snapshot open its speed, never its checks */
            if (!rc && imdb_commit_writer_op(&c) && imdb_writers_publish(db, &ew))
                imdb_warn(db, "commit %llu changed the writer key, but WRITERS could not be written (%s)",
                          (unsigned long long)c.seq, ew.msg);
            imdb_commit_free(&c);
        }
        if (rc) break;
        (*applied)++;
        if (db->needs_redaction && (rc = imdb_redact_log(db, e))) {
            db->failed = true;
            break;
        }
        /* The log frame is durable now. Publishing (and GC) before append
         * could expose a snapshot whose authorising commit never persisted. */
        if ((rc = imdb_lake_publish_pending(db, e))) {
            db->failed = true;
            break;
        }
        /* acknowledge when caught up with the stream, and at least every so many commits while catching up */
        if (o && o->applied && (++since >= every || !input_ready(src))) {
            since = 0;
            if ((rc = ack_point(db, o, e))) break;
        }
    }
    imdb_stream_free(&s);
    imdb_wipe(src, sizeof *src);
    imdb_free(src);
    return rc;
}

int imdb_apply_stream(imdb_db *db, int fd, uint64_t *applied, imdb_err *e)
{
    return imdb_apply_stream_ex(db, fd, applied, NULL, e);
}
