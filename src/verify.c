/*
 * VERIFY: an independent second pass over the on-disk log and lake. It
 * rebuilds the commitment-level state machine from the log alone (no engine
 * data structures), checks every invariant, then compares that state with
 * the live engine and with the lake files.
 *
 * One pass over the log segments, in batches of commits (IMDB_VERIFY_BATCH
 * frames or IMDB_VERIFY_BATCH_BYTES, whichever comes first):
 *   a. parallel, per commit: decode, Ed25519 signature, every row payload
 *      against its commitment;
 *   b. sequential: the schemas created inside the batch (for c);
 *   c. parallel, per chunk of ops: row decode against its schema, subject
 *      keys, LtHash deltas;
 *   d. in log order: segment layout, seq, chain, time, the version state
 *      machine, erasure rules, COMPACT horizons, running digests;
 *   e. parallel: each commit's recorded digest against the state after it.
 * The results of a, c and e are kept per commit and consumed in log order,
 * and an ordered failure at commit j still loses to a digest failure at some
 * i < j, so the verdict and its message never depend on thread timing.
 */
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "cpu.h"
#include "db_internal.h"
#include "fsio.h"
#include "lake.h"
#include "logdir.h"
#include "pool.h"
#include "writer.h"

#define VCHUNK_OPS 4096u /* ops per stage-c work item (splits large commits) */
#define VCHUNK_TABLES 16u /* tables one chunk keeps deltas for (2 KiB each): bounded memory */
#define NO_OP UINT32_MAX

typedef struct vver {
    uint8_t commit[32];
    uint8_t subj[32];  /* subject key of its payload, when has_subj */
    uint64_t begin, end;
    bool stub;         /* named by an ERASE */
    bool payload;      /* its row is still in the log */
    bool redacted;     /* the log holds a redaction marker instead */
    bool has_subj;
    bool held;         /* a version this model holds (vv) */
    bool seen;         /* the lake check met its row */
} vver;

typedef struct vtab {
    imdb_schema s;
    vver **vc;         /* versions in chunks of 2^16 as the store's (db.h): one only where a vid this model holds lands */
    uint32_t nchunk;
    uint64_t cap0;     /* chunk 0's entries: it grows from 64, so a small table stays small */
    uint64_t n;        /* vids handed out */
    uint64_t floor_n;  /* at the log floor: its vids below it the floor's RETIRE may have dropped (FLOOR) */
    uint64_t live;
    uint64_t horizon;  /* AS OF below it is refused: the highest PURGE BEFORE of its COMPACTs, or EXPIRE */
    uint64_t purged;   /* the highest PURGE BEFORE: versions ended at or before it are tombstones */
    uint64_t retention_us; /* its last op 16 */
    imdb_lthash *d;    /* separate: LtHash needs 32-byte alignment */
    imdb_index idx[IMDB_MAX_INDEXES]; /* the log's index definitions, sorted by name */
    uint32_t nidx;
} vtab;

typedef struct vsnap_tab {
    imdb_lthash d;
    uint64_t n, live, horizon, purged, retention_us;
    imdb_index idx[IMDB_MAX_INDEXES];
    uint32_t nidx;
} vsnap_tab;

/* The log's state right after the lake snapshot's commit S. */
typedef struct vsnap {
    bool seen;
    uint32_t nt;
    vsnap_tab *t;      /* aligned */
    imdb_lthash global;
    uint8_t prev[32], manifest[32], prev_manifest[32];
    uint64_t boundary; /* the log's retirement boundary at that commit (0 until RETIRE, stage 3a's step (c)) */
} vsnap;

typedef struct vstart { /* a log segment's first commit, and its time: what an EXPIRE may name (log.h) */
    uint64_t seq, time_us;
} vstart;

typedef struct vctx {
    vtab *t;
    uint32_t nt;
    imdb_lthash global;
    uint8_t head[32];
    uint64_t seq, last_time;
    bool ended;              /* the previous commit published a manifest */
    uint64_t lake_seq;       /* the engine's lake snapshot S (0: none) */
    uint64_t last_publish;   /* the latest commit that published a manifest */
    uint8_t last_manifest[32];
    vsnap at_s;
    imdb_verify_report *rep;
    const imdb_db *db;       /* its writer epochs must be the ones this log yields */
    uint64_t last_erase;     /* the last commit with an ERASE */
    uint8_t (*pin)[32];      /* the generations pins/ names (lake.h), sorted */
    uint64_t *pin_at;        /* the commit of this log that published each (0: none) */
    size_t npin;
    uint8_t key[IMDB_PUBKEY_LEN]; /* the writer key in effect, from META's on (WRITER_KEY moves it) */
    uint32_t epoch;
    vstart *starts;          /* every segment start so far, by seq */
    size_t nstarts, capstarts;
    uint64_t boundary;       /* its last RETIRE's: versions ended at or before it are gone from the engine and the lake */
    vstart *pubs;            /* every publish of the log read, its manifest's hash in place of a time (the keepers) */
    uint8_t (*pubhash)[32];
    size_t npubs, cappubs;
} vctx;

/* ---- per-batch work --------------------------------------------------------------- */

typedef struct vframe {
    const uint8_t *p;        /* frame (prefix + body) inside its segment */
    size_t len;
    bool first_of_seg;
    bool decoded, sig_ok;
    imdb_commit_rec c;
    imdb_err err;            /* why it does not decode */
    uint32_t bad_commit_op;  /* first payload that does not match its commitment */
    uint32_t bad_row_op;     /* first row that does not decode against its schema */
    imdb_err row_err;
    size_t ch0, nch;         /* its stage-c chunks */
    uint32_t known;          /* table ids that can exist by this commit (stage b) */
    bool dense;              /* a chunk hit VCHUNK_TABLES: the ordered stage sums this commit itself */
    bool digest_bad;
} vframe;

typedef struct vchunk {
    uint32_t frame, lo, hi;  /* ops [lo, hi) of that frame */
    uint32_t *tab;           /* tables touched, and their deltas */
    imdb_lthash *delta;
    uint32_t nd;
    uint8_t *st;             /* per op: 1 = row decoded (and subj filled) */
    uint8_t (*subj)[32];
    uint32_t bad_op;
    imdb_err err;
    bool nomem, overflow;
} vchunk;

typedef struct vnewtab {     /* a table created inside the batch */
    const imdb_schema *s;
    uint32_t frame, op;
} vnewtab;

typedef struct vbatch {
    vframe *f;
    size_t nf;
    vchunk *ch;
    size_t nch;
    const vctx *x;
    uint32_t nt0;            /* tables before the batch */
    vnewtab *nt_new;
    uint32_t nnew;
    const imdb_lthash *states; /* the running global state after each commit */
    const uint8_t *db_id, *root; /* for a promotion's certificate; root: META's, or NULL */
    uint8_t gkey[(IMDB_VERIFY_BATCH + 63) / 64][IMDB_PUBKEY_LEN]; /* the key at each group's start */
} vbatch;

static double vnow(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec * 1e-9;
}

/* The subject key of a value: INT64 as 8 little-endian bytes, TEXT as its SHA-256. */
static void subj_key(const imdb_value *v, uint8_t out[32])
{
    memset(out, 0, 32);
    if (v->type == IMDB_T_TEXT) {
        imdb_sha256(v->s, v->len, out);
        return;
    }
    for (int b = 0; b < 8; b++) out[b] = (uint8_t)((uint64_t)v->i >> (8 * b));
}

/* a. decode, commitments (the decoder enforces schema id == table, so o->table is
 * the id the commitment was made under); the signatures follow in stage_sigs */
static void stage_frame(void *ctx, size_t i)
{
    vbatch *b = ctx;
    vframe *f = &b->f[i];
    if (imdb_frame_decode_body(f->p + IMDB_FRAME_HDR, f->len - IMDB_FRAME_HDR, &f->c, &f->err)) return;
    f->decoded = true;
    for (uint32_t k = 0; k < f->c.nops; k++) {
        const imdb_op *o = &f->c.ops[k];
        if (!imdb_op_has_payload(o->code) || o->pkind != IMDB_PAYLOAD_ROW) continue;
        uint8_t chk[32];
        imdb_row_commit(o->table, o->salt, o->row, o->row_len, chk);
        if (memcmp(chk, o->code == IMDB_OP_INSERT ? o->commit : o->new_commit, 32) != 0) {
            f->bad_commit_op = k;
            return;
        }
    }
}

/* a2. the signatures of frames [64 g, 64 g + 64), in batches of one writer key each */
static void stage_sigs(void *ctx, size_t g)
{
    vbatch *b = ctx;
    imdb_commit_rec *recs[64] = {0};
    size_t n = 0;
    for (size_t i = 64 * g; i < b->nf && i < 64 * g + 64; i++)
        if (b->f[i].decoded) recs[n++] = &b->f[i].c;
    uint8_t key[IMDB_PUBKEY_LEN];
    memcpy(key, b->gkey[g], sizeof key);
    imdb_commit_sigs_check(key, b->db_id, b->root, recs, n);
    for (size_t i = 64 * g; i < b->nf && i < 64 * g + 64; i++) b->f[i].sig_ok = b->f[i].decoded && b->f[i].c.sig_ok;
}

static const imdb_schema *batch_schema(const vbatch *b, uint32_t table, uint32_t frame, uint32_t op)
{
    if (table < b->nt0) return &b->x->t[table].s;
    uint32_t k = table - b->nt0;
    if (k >= b->nnew) return NULL;
    const vnewtab *n = &b->nt_new[k];
    return n->frame < frame || (n->frame == frame && n->op < op) ? n->s : NULL;
}

static imdb_lthash *chunk_slot(vchunk *ch, uint32_t table)
{
    for (uint32_t i = 0; i < ch->nd; i++)
        if (ch->tab[i] == table) return &ch->delta[i];
    if (ch->nd == VCHUNK_TABLES) {
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

/* c. rows against their schemas, subject keys, LtHash deltas */
static void stage_chunk(void *ctx, size_t i)
{
    vbatch *b = ctx;
    vchunk *ch = &b->ch[i];
    const vframe *f = &b->f[ch->frame];
    uint32_t n = ch->hi - ch->lo;
    imdb_err ge = {0};
    ch->st = imdb_alloc_array(n ? n : 1, 1, &ge);
    ch->subj = imdb_alloc_array(n ? n : 1, 32, &ge);
    if (!ch->st || !ch->subj) {
        ch->nomem = true;
        return;
    }
    imdb_lthash el;
    for (uint32_t k = ch->lo; k < ch->hi; k++) {
        const imdb_op *o = &f->c.ops[k];
        if (o->code != IMDB_OP_INSERT && o->code != IMDB_OP_DELETE && o->code != IMDB_OP_UPDATE) continue;
        if (imdb_op_has_payload(o->code) && o->pkind == IMDB_PAYLOAD_ROW && ch->bad_op == NO_OP) {
            const imdb_schema *s = batch_schema(b, o->table, ch->frame, k);
            if (s) { /* else the ordered stage reports the unknown table */
                imdb_value vals[IMDB_MAX_COLS];
                imdb_err e2 = {0};
                if (imdb_row_decode(s, o->row, o->row_len, vals, &e2)) {
                    ch->bad_op = k;
                    imdb_fail(&ch->err, IMDB_ERR_VERIFY, "%s", e2.msg);
                } else {
                    if (s->subject >= 0) subj_key(&vals[s->subject], ch->subj[k - ch->lo]);
                    ch->st[k - ch->lo] = 1;
                }
            }
        }
        if (o->table >= f->known) continue; /* the ordered stage reports the unknown table */
        imdb_lthash *d = chunk_slot(ch, o->table);
        if (!d) return; /* out of memory, or too many tables: see vframe.dense */
        imdb_lthash_element(b->x->db->meta.digest_alg, o->commit, &el);
        if (o->code == IMDB_OP_INSERT) imdb_lthash_add(d, &el);
        else imdb_lthash_sub(d, &el);
        if (o->code == IMDB_OP_UPDATE) {
            imdb_lthash_element(b->x->db->meta.digest_alg, o->new_commit, &el);
            imdb_lthash_add(d, &el);
        }
    }
}

/* e. recorded digests */
static void stage_digest(void *ctx, size_t i)
{
    vbatch *b = ctx;
    vframe *f = &b->f[i];
    uint8_t d[32];
    imdb_lthash_digest(b->x->db->meta.digest_alg, &b->states[i], d);
    f->digest_bad = memcmp(d, f->c.digest, 32) != 0;
}

static void batch_free(vbatch *b)
{
    for (size_t i = 0; i < b->nf; i++)
        if (b->f[i].decoded) imdb_commit_free(&b->f[i].c);
    for (size_t i = 0; i < b->nch; i++) {
        imdb_free(b->ch[i].tab);
        imdb_free(b->ch[i].delta);
        imdb_free(b->ch[i].st);
        imdb_free(b->ch[i].subj);
    }
    imdb_free(b->ch);
    imdb_free(b->nt_new);
    b->ch = NULL;
    b->nt_new = NULL;
    b->nch = b->nnew = 0;
}

/* ---- d: the ordered state machine ------------------------------------------------- */

/* version vid of the model, NULL when it holds none there */
static vver *vv(const vtab *t, uint64_t vid)
{
    uint64_t k = vid >> IMDB_VCHUNK_BITS;
    if (vid >= t->n || k >= t->nchunk || !t->vc[k] || (!k && vid >= t->cap0)) return NULL;
    vver *v = &t->vc[k][vid & (IMDB_VCHUNK - 1)];
    return v->held ? v : NULL;
}

/* the model's entry for vid, its chunk allocated (the entry zeroed, live, held); vid at or past t->n moves the count */
static vver *vv_need(vtab *t, uint64_t vid, imdb_err *e)
{
    uint64_t k = vid >> IMDB_VCHUNK_BITS;
    if (vid >= IMDB_MAX_VERSIONS) {
        imdb_fail(e, IMDB_ERR_LIMIT, "verify: a table of more than %llu versions", IMDB_MAX_VERSIONS);
        return NULL;
    }
    if (k >= t->nchunk) {
        uint64_t nc = t->nchunk ? (uint64_t)t->nchunk * 2 : 4;
        if (nc <= k) nc = k + 1;
        vver **n = imdb_realloc_array(t->vc, t->nchunk, nc, sizeof *n, e);
        if (!n) return NULL;
        t->vc = n;
        t->nchunk = (uint32_t)nc;
    }
    if (!k && vid >= t->cap0) { /* chunk 0 doubles (from 64) up to a whole chunk; the new entries zeroed */
        uint64_t to = t->cap0 ? t->cap0 : 64;
        while (to <= vid) to *= 2;
        if (to > IMDB_VCHUNK) to = IMDB_VCHUNK;
        vver *g = imdb_realloc_array(t->vc[0], t->cap0, to, sizeof *g, e);
        if (!g) return NULL;
        t->vc[0] = g;
        t->cap0 = to;
    } else if (k && !t->vc[k] && !(t->vc[k] = imdb_alloc_array(IMDB_VCHUNK, sizeof **t->vc, e))) {
        return NULL;
    }
    vver *v = &t->vc[k][vid & (IMDB_VCHUNK - 1)];
    memset(v, 0, sizeof *v);
    v->end = IMDB_LIVE;
    v->held = true;
    if (vid >= t->n) t->n = vid + 1;
    return v;
}

static int vt_push(vtab *t, imdb_err *e)
{
    return vv_need(t, t->n, e) ? IMDB_OK : e->code;
}

static void vt_free(vtab *t)
{
    for (uint32_t k = 0; k < t->nchunk; k++) imdb_free(t->vc[k]);
    imdb_free(t->vc);
    t->vc = NULL;
    t->nchunk = 0;
    t->cap0 = 0;
}

static int v_insert(vctx *x, vtab *t, const vbatch *b, size_t fi, uint32_t k, uint64_t vid, const uint8_t commit[32],
                    imdb_err *e)
{
    const vframe *f = &b->f[fi];
    const imdb_op *o = &f->c.ops[k];
    uint64_t seq = f->c.seq;
    if (vid != t->n) return imdb_fail(e, IMDB_ERR_VERIFY, "verify: commit %llu: version id out of sequence", (unsigned long long)seq);
    uint8_t subj[32] = {0};
    if (o->pkind == IMDB_PAYLOAD_ROW) {
        if (k == f->bad_commit_op)
            return imdb_fail(e, IMDB_ERR_VERIFY, "verify: commit %llu: payload/commitment mismatch", (unsigned long long)seq);
        if (k == f->bad_row_op)
            return imdb_fail(e, IMDB_ERR_VERIFY, "verify: commit %llu: %s", (unsigned long long)seq, f->row_err.msg);
        const vchunk *ch = f->nch ? &b->ch[f->ch0 + k / VCHUNK_OPS] : NULL;
        if (ch && ch->st && ch->subj && ch->st[k - ch->lo]) {
            memcpy(subj, ch->subj[k - ch->lo], 32);
        } else { /* not decoded in parallel (an earlier failure in this commit, or no chunk) */
            imdb_value vals[IMDB_MAX_COLS];
            imdb_err e2 = {0};
            if (imdb_row_decode(&t->s, o->row, o->row_len, vals, &e2))
                return imdb_fail(e, IMDB_ERR_VERIFY, "verify: commit %llu: %s", (unsigned long long)seq, e2.msg);
            if (t->s.subject >= 0) subj_key(&vals[t->s.subject], subj);
        }
        x->rep->payload_rows_checked++;
    }
    if (vt_push(t, e)) return e->code;
    vver *v = vv(t, vid);
    memcpy(v->commit, commit, 32);
    v->begin = seq;
    v->payload = o->pkind == IMDB_PAYLOAD_ROW;
    v->redacted = !v->payload;
    v->has_subj = v->payload && t->s.subject >= 0;
    if (v->has_subj) memcpy(v->subj, subj, 32);
    t->live++;
    return IMDB_OK;
}

static int v_end(vtab *t, uint64_t vid, const uint8_t commit[32], uint64_t seq, imdb_err *e)
{
    vver *v = vv(t, vid);
    if (!v || v->end != IMDB_LIVE || memcmp(v->commit, commit, 32) != 0)
        return imdb_fail(e, IMDB_ERR_VERIFY, "verify: commit %llu: delete precondition fails", (unsigned long long)seq);
    v->end = seq;
    t->live--;
    return IMDB_OK;
}

/* the log's index definitions, re-derived apart from the engine's (db.c imdb_index_add) */
static bool v_index_taken(const vctx *x, const char *name)
{
    for (uint32_t i = 0; i < x->nt; i++)
        for (uint32_t j = 0; j < x->t[i].nidx; j++)
            if (strcmp(x->t[i].idx[j].d.name, name) == 0) return true;
    return false;
}

static bool same_indexes(const imdb_index *a, uint32_t na, const imdb_index *b, uint32_t nb)
{
    if (na != nb) return false;
    for (uint32_t i = 0; i < na; i++) {
        const imdb_index_def *x = &a[i].d, *y = &b[i].d;
        if (strcmp(x->name, y->name) != 0 || x->flags != y->flags || x->ncols != y->ncols ||
            memcmp(x->cols, y->cols, x->ncols * sizeof *x->cols) != 0)
            return false;
    }
    return true;
}

static const vstart *find_start(const vctx *x, uint64_t seq)
{
    size_t lo = 0, hi = x->nstarts;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        if (x->starts[mid].seq < seq) lo = mid + 1;
        else hi = mid;
    }
    return lo < x->nstarts && x->starts[lo].seq == seq ? &x->starts[lo] : NULL;
}

/* The ops of one commit; *published = the manifest it records, if any. */
static int v_ops(vctx *x, const vbatch *b, size_t fi, const uint8_t **published, bool *erase, imdb_err *e)
{
    const imdb_commit_rec *c = &b->f[fi].c;
    uint64_t seq = c->seq;
    *published = NULL;
    *erase = false;
    for (uint32_t k = 0; k < c->nops; k++) {
        const imdb_op *o = &c->ops[k];
        bool on_table = o->code == IMDB_OP_INSERT || o->code == IMDB_OP_DELETE || o->code == IMDB_OP_UPDATE ||
                        o->code == IMDB_OP_COMPACT || o->code == IMDB_OP_CREATE_INDEX || o->code == IMDB_OP_DROP_INDEX ||
                        o->code == IMDB_OP_SET_RETENTION || o->code == IMDB_OP_EXPIRE;
        vtab *t = on_table && o->table < x->nt ? &x->t[o->table] : NULL;
        if (on_table && !t) return imdb_fail(e, IMDB_ERR_VERIFY, "verify: unknown table");
        if (imdb_op_publishes_manifest(o->code)) *published = o->manifest;
        int rc = IMDB_OK;
        switch (o->code) {
        case IMDB_OP_CREATE_TABLE: {
            if (o->table != x->nt) return imdb_fail(e, IMDB_ERR_VERIFY, "verify: table id out of sequence");
            vtab *nt = imdb_realloc_array(x->t, x->nt, x->nt + 1, sizeof *nt, e);
            if (!nt) return e->code;
            x->t = nt;
            memset(&x->t[x->nt], 0, sizeof x->t[x->nt]);
            x->t[x->nt].s = *o->schema;
            x->t[x->nt].d = imdb_alloc_aligned(1, sizeof *x->t[x->nt].d, e);
            if (!x->t[x->nt].d) return e->code;
            x->nt++;
            break;
        }
        case IMDB_OP_CREATE_INDEX: {
            imdb_index_def d;
            memset(&d, 0, sizeof d);
            snprintf(d.name, sizeof d.name, "%s", o->iname);
            d.flags = o->iflags;
            d.ncols = o->incols;
            memcpy(d.cols, o->icols, sizeof d.cols);
            if (!imdb_index_def_ok(&d, t->s.ncols) || t->nidx >= IMDB_MAX_INDEXES || v_index_taken(x, o->iname))
                return imdb_fail(e, IMDB_ERR_VERIFY, "verify: commit %llu: CREATE INDEX on a column the table lacks, "
                                 "past the limit, or with a name in use", (unsigned long long)seq);
            uint32_t p = 0;
            while (p < t->nidx && strcmp(t->idx[p].d.name, o->iname) < 0) p++;
            memmove(&t->idx[p + 1], &t->idx[p], (t->nidx - p) * sizeof *t->idx);
            memset(&t->idx[p], 0, sizeof t->idx[p]);
            t->idx[p].d = d;
            t->nidx++;
            break;
        }
        case IMDB_OP_DROP_INDEX: {
            uint32_t p = 0;
            while (p < t->nidx && strcmp(t->idx[p].d.name, o->iname) != 0) p++;
            if (p == t->nidx)
                return imdb_fail(e, IMDB_ERR_VERIFY, "verify: commit %llu: DROP INDEX of an index the table lacks",
                                 (unsigned long long)seq);
            memmove(&t->idx[p], &t->idx[p + 1], (t->nidx - p - 1) * sizeof *t->idx);
            t->nidx--;
            memset(&t->idx[t->nidx], 0, sizeof t->idx[t->nidx]);
            break;
        }
        case IMDB_OP_INSERT: rc = v_insert(x, t, b, fi, k, o->vid, o->commit, e); break;
        case IMDB_OP_DELETE: rc = v_end(t, o->vid, o->commit, seq, e); break;
        case IMDB_OP_UPDATE:
            if (!(rc = v_end(t, o->vid, o->commit, seq, e))) rc = v_insert(x, t, b, fi, k, o->new_vid, o->new_commit, e);
            break;
        case IMDB_OP_ERASE:
            *erase = true;
            for (uint32_t j = 0; j < o->n_erase && !rc; j++) {
                const imdb_erase_ent *en = &o->erase[j];
                vver *v = en->table < x->nt ? vv(&x->t[en->table], en->vid) : NULL;
                if (!v && en->table < x->nt && en->vid < x->t[en->table].floor_n) { /* below the floor (FLOOR) */
                    x->rep->erase_below_floor++; /* ended there, dropped by the floor's RETIRE: its commitment unknowable */
                    continue;
                }
                if (!v || memcmp(v->commit, en->commit, 32) != 0 || v->end == IMDB_LIVE)
                    rc = imdb_fail(e, IMDB_ERR_VERIFY, "verify: commit %llu: invalid ERASE entry", (unsigned long long)seq);
                else if (v->payload)
                    rc = imdb_fail(e, IMDB_ERR_VERIFY,
                                   "verify: erasure incomplete: payload of erased version %llu of table %s is still in the log",
                                   (unsigned long long)en->vid, x->t[en->table].s.name);
                else
                    v->stub = true;
            }
            break;
        case IMDB_OP_COMPACT:
            /* the engine raises a PURGE BEFORE to the table's horizon and never past the last commit */
            if (o->purge_before >= seq)
                rc = imdb_fail(e, IMDB_ERR_VERIFY, "verify: commit %llu: PURGE BEFORE is not in the past", (unsigned long long)seq);
            else if (o->purge_before && o->purge_before < t->horizon)
                rc = imdb_fail(e, IMDB_ERR_VERIFY, "verify: commit %llu: PURGE BEFORE moves the horizon back",
                               (unsigned long long)seq);
            else if (o->purge_before)
                t->horizon = t->purged = o->purge_before;
            break;
        case IMDB_OP_SET_RETENTION:
            t->retention_us = o->retention_us; /* the decoder checked its range and its place after CREATE_TABLE */
            break;
        case IMDB_OP_RETIRE: { /* past the last, ending a segment before this commit, below every horizon */
            uint64_t bnd = o->purge_before;
            if (bnd <= x->boundary || !find_start(x, bnd + 1)) {
                rc = imdb_fail(e, IMDB_ERR_VERIFY, "verify: commit %llu: RETIRE's boundary %llu is not past %llu or ends no "
                               "log segment", (unsigned long long)seq, (unsigned long long)bnd, (unsigned long long)x->boundary);
                break;
            }
            for (uint32_t ti = 0; ti < x->nt && !rc; ti++)
                if (bnd >= x->t[ti].horizon)
                    rc = imdb_fail(e, IMDB_ERR_VERIFY, "verify: commit %llu: RETIRE's boundary is not below table %s's "
                                   "horizon", (unsigned long long)seq, x->t[ti].s.name);
            if (!rc) x->boundary = bnd; /* the versions ended at or before it: gone (the lake and engine checks) */
            break;
        }
        case IMDB_OP_EXPIRE: { /* the retention honoured: a segment start at least the table's retention older */
            const vstart *s = find_start(x, o->purge_before);
            if (t->retention_us == IMDB_RETAIN_FOREVER)
                rc = imdb_fail(e, IMDB_ERR_VERIFY, "verify: commit %llu: EXPIRE of a table kept FOREVER", (unsigned long long)seq);
            else if (o->purge_before <= t->horizon)
                rc = imdb_fail(e, IMDB_ERR_VERIFY, "verify: commit %llu: EXPIRE does not move the horizon", (unsigned long long)seq);
            else if (!s)
                rc = imdb_fail(e, IMDB_ERR_VERIFY, "verify: commit %llu: EXPIRE names commit %llu, which begins no log segment",
                               (unsigned long long)seq, (unsigned long long)o->purge_before);
            else if (s->time_us > c->time_us || c->time_us - s->time_us < t->retention_us)
                rc = imdb_fail(e, IMDB_ERR_VERIFY, "verify: commit %llu: EXPIRE of history younger than the table's retention",
                               (unsigned long long)seq);
            else
                t->horizon = o->purge_before;
            break;
        }
        case IMDB_OP_WRITER_KEY: { /* the next epoch, and the engine must hold the same one */
            const imdb_db *db = x->db;
            uint32_t ep = o->epoch;
            if (ep != x->epoch + 1)
                rc = imdb_fail(e, IMDB_ERR_VERIFY, "verify: commit %llu: WRITER_KEY names epoch %u after epoch %u",
                               (unsigned long long)seq, ep, x->epoch);
            else if (ep >= db->nwep || db->wep[ep].seq != seq || db->wep[ep].promote != c->promote ||
                     memcmp(db->wep[ep].k.pk, o->new_pk, IMDB_PUBKEY_LEN) != 0)
                rc = imdb_fail(e, IMDB_ERR_VERIFY, "verify: commit %llu: the engine's writer epoch %u differs from the log's",
                               (unsigned long long)seq, ep);
            else {
                x->epoch = ep;
                memcpy(x->key, o->new_pk, IMDB_PUBKEY_LEN);
            }
            break;
        }
        default: break; /* CHECKPOINT: physical, checked against the lake files */
        }
        if (rc) return rc;
    }
    return IMDB_OK;
}

static int snapshot_at_s(vctx *x, const imdb_commit_rec *c, const uint8_t *published, bool erase, imdb_err *e)
{
    vsnap *s = &x->at_s;
    if (!published)
        return imdb_fail(e, IMDB_ERR_VERIFY, "lake: the snapshot's commit %llu does not publish a manifest",
                         (unsigned long long)c->seq);
    s->seen = true;
    s->nt = x->nt;
    s->t = imdb_alloc_aligned(x->nt ? x->nt : 1, sizeof *s->t, e);
    if (!s->t) return e->code;
    for (uint32_t ti = 0; ti < x->nt; ti++) {
        s->t[ti].d = *x->t[ti].d;
        s->t[ti].n = x->t[ti].n;
        s->t[ti].live = x->t[ti].live;
        s->t[ti].horizon = x->t[ti].horizon;
        s->t[ti].purged = x->t[ti].purged;
        s->t[ti].retention_us = x->t[ti].retention_us;
        memcpy(s->t[ti].idx, x->t[ti].idx, sizeof s->t[ti].idx);
        s->t[ti].nidx = x->t[ti].nidx;
    }
    s->boundary = x->boundary;
    s->global = x->global;
    memcpy(s->prev, c->prev, 32);
    memcpy(s->manifest, published, 32);
    /* GC keeps the generation this manifest replaced; none after an ERASE */
    if (erase) memset(s->prev_manifest, 0, 32);
    else memcpy(s->prev_manifest, x->last_manifest, 32);
    return IMDB_OK;
}

static int cmp_hash32(const void *a, const void *b) { return memcmp(a, b, 32); }

/* Every check of one commit that needs log order. */
static int ordered_frame(vctx *x, vbatch *b, size_t i, uint64_t seg_first, bool log_start, imdb_err *e)
{
    vframe *f = &b->f[i];
    if (!log_start && f->first_of_seg != x->ended)
        return imdb_fail(e, IMDB_ERR_VERIFY, "verify: log segments do not end exactly at the commits that publish manifests");
    if (!f->decoded) return imdb_fail(e, f->err.code ? f->err.code : IMDB_ERR_VERIFY, "%s", f->err.msg);
    const imdb_commit_rec *c = &f->c;
    if (f->first_of_seg && c->seq != seg_first)
        return imdb_fail(e, IMDB_ERR_VERIFY, "verify: segment %llu begins with commit %llu", (unsigned long long)seg_first,
                         (unsigned long long)c->seq);
    if (c->seq != x->seq + 1)
        return imdb_fail(e, IMDB_ERR_VERIFY, "verify: commit %llu out of sequence", (unsigned long long)c->seq);
    if (memcmp(c->prev, x->head, 32) != 0)
        return imdb_fail(e, IMDB_ERR_VERIFY, "verify: hash chain broken at commit %llu", (unsigned long long)c->seq);
    if (c->time_us <= x->last_time)
        return imdb_fail(e, IMDB_ERR_VERIFY, "verify: commit %llu time not increasing", (unsigned long long)c->seq);
    if (c->alg != x->db->meta.digest_alg)
        return imdb_fail(e, IMDB_ERR_VERIFY, "verify: commit %llu: digest algorithm %u, but this database's is %u",
                         (unsigned long long)c->seq, c->alg, x->db->meta.digest_alg);
    if (!f->sig_ok) return imdb_fail(e, IMDB_ERR_AUTH, "verify: commit %llu signature invalid", (unsigned long long)c->seq);
    x->rep->sigs_checked++;
    if (f->first_of_seg) { /* its time, for the EXPIREs that may name it */
        if (x->nstarts == x->capstarts) {
            size_t nc = x->capstarts ? x->capstarts * 2 : 64;
            vstart *ns = imdb_realloc_array(x->starts, x->capstarts, nc, sizeof *ns, e);
            if (!ns) return e->code;
            x->starts = ns;
            x->capstarts = nc;
        }
        x->starts[x->nstarts++] = (vstart){c->seq, c->time_us};
    }
    for (size_t k = 0; k < f->nch; k++) {
        if (b->ch[f->ch0 + k].nomem) return imdb_fail(e, IMDB_ERR_NOMEM, "verify: out of memory");
        if (b->ch[f->ch0 + k].overflow) f->dense = true;
    }
    const uint8_t *published;
    bool erase;
    int rc = v_ops(x, b, i, &published, &erase, e);
    if (rc) return rc;
    if (f->dense) { /* many tables in one chunk: sum here, without per-chunk deltas */
        imdb_lthash el;
        for (uint32_t k = 0; k < c->nops; k++) {
            const imdb_op *o = &c->ops[k];
            if (o->code != IMDB_OP_INSERT && o->code != IMDB_OP_DELETE && o->code != IMDB_OP_UPDATE) continue;
            imdb_lthash *d = x->t[o->table].d; /* v_ops checked every table */
            imdb_lthash_element(x->db->meta.digest_alg, o->commit, &el);
            if (o->code == IMDB_OP_INSERT) imdb_lthash_add(d, &el), imdb_lthash_add(&x->global, &el);
            else imdb_lthash_sub(d, &el), imdb_lthash_sub(&x->global, &el);
            if (o->code == IMDB_OP_UPDATE) {
                imdb_lthash_element(x->db->meta.digest_alg, o->new_commit, &el);
                imdb_lthash_add(d, &el);
                imdb_lthash_add(&x->global, &el);
            }
        }
    }
    for (size_t k = 0; !f->dense && k < f->nch; k++) {
        const vchunk *ch = &b->ch[f->ch0 + k];
        for (uint32_t j = 0; j < ch->nd; j++) {
            if (ch->tab[j] >= x->nt)
                return imdb_fail(e, IMDB_ERR_VERIFY, "verify: unknown table"); /* unreachable: v_ops checked every op */
            imdb_lthash_add(x->t[ch->tab[j]].d, &ch->delta[j]);
            imdb_lthash_add(&x->global, &ch->delta[j]);
        }
    }
    if (c->seq == x->lake_seq && (rc = snapshot_at_s(x, c, published, erase, e))) return rc;
    if (erase) x->last_erase = c->seq;
    if (published && x->npin) {
        uint8_t (*p)[32] = bsearch(published, x->pin, x->npin, sizeof *x->pin, cmp_hash32);
        if (p) x->pin_at[p - x->pin] = c->seq;
    }
    if (published) { /* its manifest may stay as a keeper (lake.c): the objects check allows it past the boundary */
        if (x->npubs == x->cappubs) {
            size_t nc = x->cappubs ? x->cappubs * 2 : 64;
            uint8_t(*nh)[32] = imdb_realloc_array(x->pubhash, x->cappubs, nc, sizeof *nh, e);
            if (!nh) return e->code;
            x->pubhash = nh;
            vstart *np = imdb_realloc_array(x->pubs, x->cappubs, nc, sizeof *np, e);
            if (!np) return e->code;
            x->pubs = np;
            x->cappubs = nc;
        }
        x->pubs[x->npubs] = (vstart){c->seq, 0};
        memcpy(x->pubhash[x->npubs++], published, 32);
        memcpy(x->last_manifest, published, 32);
        x->last_publish = c->seq;
    }
    x->ended = published != NULL;
    x->seq = c->seq;
    memcpy(x->head, c->hash, 32);
    x->last_time = c->time_us;
    x->rep->commits++;
    return IMDB_OK;
}

/* One batch: frames f[0..nf) of one segment. */
static int run_batch(vctx *x, vbatch *b, imdb_lthash *states, uint64_t seg_first, bool batch_at_log_start, double *t_par,
                     double *t_seq, imdb_err *e)
{
    double t0 = vnow();
    for (size_t i = 0; i < b->nf; i++) {
        b->f[i].bad_commit_op = b->f[i].bad_row_op = NO_OP;
        b->f[i].ch0 = SIZE_MAX;
    }
    imdb_par_for(b->nf, stage_frame, b);
    uint8_t key[IMDB_PUBKEY_LEN]; /* each group's starting key, from the WRITER_KEY ops before it */
    memcpy(key, x->key, sizeof key);
    for (size_t i = 0; i < b->nf; i++) {
        if (i % 64 == 0) memcpy(b->gkey[i / 64], key, sizeof key);
        const imdb_op *w = b->f[i].decoded ? imdb_commit_writer_op(&b->f[i].c) : NULL;
        if (w) memcpy(key, w->new_pk, sizeof key);
    }
    imdb_par_for((b->nf + 63) / 64, stage_sigs, b);
    /* b. tables created inside the batch, in log order, up to the first irregularity */
    b->nt0 = x->nt;
    for (size_t i = 0; i < b->nf; i++) b->f[i].known = b->nt0;
    for (size_t i = 0, stop = 0; i < b->nf && !stop; i++) {
        vframe *f = &b->f[i];
        if (!f->decoded || !f->sig_ok || f->bad_commit_op != NO_OP) break;
        for (uint32_t k = 0; k < f->c.nops; k++) {
            const imdb_op *o = &f->c.ops[k];
            if (o->code != IMDB_OP_CREATE_TABLE) continue;
            if (o->table != b->nt0 + b->nnew) {
                stop = 1;
                break;
            }
            vnewtab *nn = imdb_realloc_array(b->nt_new, b->nnew, b->nnew + 1, sizeof *nn, e);
            if (!nn) return e->code;
            b->nt_new = nn;
            b->nt_new[b->nnew++] = (vnewtab){o->schema, (uint32_t)i, k};
        }
        for (size_t j = i; j < b->nf; j++) b->f[j].known = b->nt0 + b->nnew;
    }
    /* c. chunks for every frame that passed a */
    size_t nch = 0;
    for (size_t i = 0; i < b->nf; i++) {
        const vframe *f = &b->f[i];
        if (f->decoded && f->sig_ok && f->bad_commit_op == NO_OP) nch += (f->c.nops + VCHUNK_OPS - 1) / VCHUNK_OPS;
    }
    b->ch = imdb_alloc_array(nch ? nch : 1, sizeof *b->ch, e);
    if (!b->ch) return e->code;
    for (size_t i = 0; i < b->nf; i++) {
        vframe *f = &b->f[i];
        if (!f->decoded || !f->sig_ok || f->bad_commit_op != NO_OP) continue;
        f->ch0 = b->nch;
        for (uint32_t lo = 0; lo < f->c.nops; lo += VCHUNK_OPS) {
            uint32_t hi = f->c.nops - lo < VCHUNK_OPS ? f->c.nops : lo + VCHUNK_OPS;
            b->ch[b->nch++] = (vchunk){.frame = (uint32_t)i, .lo = lo, .hi = hi, .bad_op = NO_OP};
        }
        f->nch = b->nch - f->ch0;
    }
    imdb_par_for(b->nch, stage_chunk, b);
    for (size_t i = 0; i < b->nf; i++) { /* first undecodable row of each commit */
        vframe *f = &b->f[i];
        for (size_t k = 0; k < f->nch && f->bad_row_op == NO_OP; k++) {
            const vchunk *ch = &b->ch[f->ch0 + k];
            if (ch->bad_op != NO_OP) {
                f->bad_row_op = ch->bad_op;
                f->row_err = ch->err;
            }
        }
    }
    double t1 = vnow();
    *t_par += t1 - t0;
    /* d. in log order; stop at the first failure (j) */
    imdb_err oe = {0};
    int orc = IMDB_OK;
    size_t j = 0;
    for (; j < b->nf; j++) {
        if ((orc = ordered_frame(x, b, j, seg_first, batch_at_log_start && j == 0, &oe))) break;
        states[j] = x->global;
    }
    double t2 = vnow();
    *t_seq += t2 - t1;
    /* e. digests of the commits before j; an earlier wrong digest wins */
    vbatch eb = *b;
    eb.nf = j;
    eb.states = states;
    imdb_par_for(j, stage_digest, &eb);
    *t_par += vnow() - t2;
    for (size_t i = 0; i < j; i++)
        if (b->f[i].digest_bad)
            return imdb_fail(e, IMDB_ERR_VERIFY, "verify: commit %llu: recorded state digest is wrong",
                             (unsigned long long)b->f[i].c.seq);
    if (orc) return imdb_fail(e, oe.code, "%s", oe.msg);
    return IMDB_OK;
}

/* The whole log, segment by segment (memory: one segment and one batch). */
static int verify_log(imdb_db *db, vctx *x, double *t_read, double *t_par, double *t_seq, imdb_err *e)
{
    uint64_t *sfirst = NULL;
    size_t nseg = 0;
    if (imdb_logdir_list(db->logdirfd, &sfirst, &nseg, e)) return e->code;
    imdb_lthash *states = imdb_alloc_aligned(IMDB_VERIFY_BATCH, sizeof *states, e);
    vframe *fr = imdb_alloc_array(IMDB_VERIFY_BATCH, sizeof *fr, e);
    int rc = !states || !fr ? e->code : IMDB_OK;
    bool log_start = true;
    bool tagged_before = false; /* the format only moves forward (design.md §3) */
    for (size_t si = 0; si < nseg && !rc; si++) {
        if (si + 1 < nseg && sfirst[si + 1] - 1 <= x->seq) continue; /* below the floor, not yet cut */
        double t0 = vnow();
        imdb_logseg seg;
        if ((rc = imdb_logseg_load(db->logdirfd, sfirst[si], &seg, e))) break;
        uint8_t *buf = seg.buf;
        size_t len = seg.len;
        bool tail_left = seg.tagged && seg.tail != IMDB_SCAN_END; /* a tagged segment: its verdict after the frames */
        if (!seg.tagged && tagged_before && !(si + 1 == nseg && imdb_logseg_blank(&seg))) {
            rc = imdb_fail(e, IMDB_ERR_VERIFY, "verify: log segment %llu is untagged, after a tagged one",
                           (unsigned long long)sfirst[si]);
            imdb_logseg_free(&seg);
            break;
        }
        tagged_before = seg.tagged;
        *t_read += vnow() - t0;
        if (len == 0) {
            if (si + 1 < nseg) rc = imdb_fail(e, IMDB_ERR_VERIFY, "verify: empty log segment before the last");
            else if (sfirst[si] != x->seq + 1 || (x->seq && !x->ended))
                rc = imdb_fail(e, IMDB_ERR_VERIFY, "verify: log segment %llu does not follow the last commit",
                               (unsigned long long)sfirst[si]);
        }
        size_t off = 0;
        bool first = true;
        while (!rc && (off < len || tail_left)) {
            /* one batch: up to IMDB_VERIFY_BATCH frames and IMDB_VERIFY_BATCH_BYTES (at least one frame) */
            size_t nf = 0, bytes = 0;
            imdb_err se = {0}; /* a damaged frame after this batch: reported only if the batch is sound */
            bool bad = false;
            imdb_scan_status bad_st = IMDB_SCAN_FRAME;
            while ((off < len || tail_left) && nf < IMDB_VERIFY_BATCH && (nf == 0 || bytes < IMDB_VERIFY_BATCH_BYTES)) {
                size_t flen = 0;
                imdb_scan_status st = imdb_logseg_scan(&seg, off, &flen, &se);
                if (st == IMDB_SCAN_END) {
                    off = len;
                    break;
                }
                if (st != IMDB_SCAN_FRAME) {
                    bad = true;
                    bad_st = st;
                    tail_left = false;
                    break;
                }
                memset(&fr[nf], 0, sizeof fr[nf]);
                fr[nf].p = buf + off;
                fr[nf].len = flen;
                fr[nf].first_of_seg = first;
                first = false;
                nf++;
                bytes += flen;
                off += flen;
            }
            if (nf) {
                vbatch b = {.f = fr, .nf = nf, .x = x, .db_id = db->db_id, .root = db->meta.has_root ? db->meta.root : NULL};
                rc = run_batch(x, &b, states, sfirst[si], log_start, t_par, t_seq, e);
                batch_free(&b);
                log_start = false;
            }
            if (!rc && bad && si + 1 == nseg && bad_st != IMDB_SCAN_CORRUPT) {
                /* the end of the last segment: an append that never finished (a writable open
                 * truncates it), unless the writer had acknowledged that commit */
                if ((rc = imdb_tail_check(&db->dur, db->have_dur, x->seq, bad_st, se.msg, e))) break;
                snprintf(x->rep->note, sizeof x->rep->note, "torn tail after commit %llu (%.180s); a writable open truncates it",
                         (unsigned long long)x->seq, se.msg);
                break;
            }
            if (!rc && bad)
                rc = imdb_fail(e, IMDB_ERR_VERIFY,
                               si + 1 < nseg ? "verify: a frame crosses a segment boundary or is damaged: %s" : "verify: %s",
                               se.msg);
            if (!nf && !bad) break;
        }
        imdb_logseg_free(&seg);
    }
    /* every commit the writer acknowledged must still be in the log */
    if (!rc && db->have_dur) rc = imdb_tail_check(&db->dur, true, x->seq, IMDB_SCAN_END, "the log ends at a frame boundary", e);
    imdb_free(fr);
    imdb_free(states);
    imdb_free(sfirst);
    return rc;
}

/* ---- the lake files against the log's state at S ---------------------------------- */

typedef struct litem {
    uint32_t table, k;
    uint64_t size; /* of its file, to bound the bytes held at once */
    imdb_segment *g;
    int rc;
    imdb_err err;
} litem;

typedef struct lctx {
    int ofd;
    const vctx *x;
    const imdb_manifest *m;
    litem *it;
} lctx;

static void lake_item(void *ctx, size_t i)
{
    lctx *L = ctx;
    litem *it = &L->it[i];
    imdb_err *e = &it->err;
    const imdb_manifest_tab *mt = &L->m->t[it->table];
    const vtab *vt = &L->x->t[it->table];
    const vsnap_tab *st = &L->x->at_s.t[it->table];
    uint64_t S = L->m->seq;
    uint8_t *sb;
    size_t sl;
    if ((it->rc = imdb_lake_read_object(L->ofd, mt->seg[it->k].seg, ".seg", &sb, &sl, e))) return;
    uint8_t *al = imdb_alloc_aligned(1, sl, e);
    if (!al) {
        imdb_free(sb);
        it->rc = e->code;
        return;
    }
    memcpy(al, sb, sl);
    imdb_free(sb);
    if ((it->rc = imdb_segment_parse(&vt->s, al, sl, &it->g, e))) {
        imdb_free(al);
        return;
    }
    imdb_segment *g = it->g;
    if (g->nrows != mt->seg[it->k].nrows) {
        it->rc = imdb_fail(e, IMDB_ERR_VERIFY, "lake: segment row count mismatch");
        return;
    }
    if ((it->rc = imdb_segment_check_commitments(&vt->s, g, e))) return;
    if (memcmp(mt->seg[it->k].dv, (uint8_t[32]){0}, 32) != 0) {
        uint8_t *dvb = NULL;
        size_t dl;
        if ((it->rc = imdb_lake_read_object(L->ofd, mt->seg[it->k].dv, ".dv", &dvb, &dl, e))) return;
        uint8_t sh[32];
        imdb_dv_ent *ents;
        uint32_t n;
        if (!(it->rc = imdb_dv_parse(dvb, dl, sh, &ents, &n, g->nrows, e))) {
            if (memcmp(sh, g->hash, 32) != 0) it->rc = imdb_fail(e, IMDB_ERR_VERIFY, "lake: DV names another segment");
            for (uint32_t r = 0; r < n && !it->rc; r++)
                if (ents[r].end > S) it->rc = imdb_fail(e, IMDB_ERR_VERIFY, "lake: DV records a future delete");
                else g->end[ents[r].row] = ents[r].end;
            imdb_free(ents);
        }
        imdb_free(dvb);
        if (it->rc) return;
    }
    int subj = vt->s.subject;
    for (uint32_t r = 0; r < g->nrows; r++) {
        uint64_t vid = g->vid[r];
        if (vid >= st->n) {
            it->rc = imdb_fail(e, IMDB_ERR_VERIFY, "lake: version %llu of table %s is outside the manifest or twice in it",
                               (unsigned long long)vid, vt->s.name);
            return;
        }
        const vver *v = vv(vt, vid);
        if (!v) {
            it->rc = imdb_fail(e, IMDB_ERR_VERIFY, "lake: a segment of table %s holds version %llu, which the log never made",
                               vt->s.name, (unsigned long long)vid);
            return;
        }
        uint64_t vend = v->end <= S ? v->end : IMDB_LIVE; /* the log may have moved on */
        if (vend != IMDB_LIVE && vend <= L->x->at_s.boundary) {
            it->rc = imdb_fail(e, IMDB_ERR_VERIFY, "lake: a segment of table %s holds version %llu, which its boundary retired",
                               vt->s.name, (unsigned long long)vid);
            return;
        }
        bool purged = vend != IMDB_LIVE && vend <= st->purged; /* an EXPIRE purges nothing */
        uint8_t want = (uint8_t)((v->stub ? IMDB_SEG_STUB : 0u) | (purged ? IMDB_SEG_PURGED : 0u));
        if (memcmp(v->commit, g->commit + 32u * r, 32) != 0 || v->begin != g->begin[r] || vend != g->end[r] ||
            g->flags[r] != want) {
            it->rc = imdb_fail(e, IMDB_ERR_VERIFY, "lake: segment row disagrees with the log (table %s)", vt->s.name);
            return;
        }
        if (want == IMDB_SEG_PURGED && subj >= 0) { /* the tombstone's subject is what ERASE SUBJECT will look for */
            imdb_value sv = {.type = vt->s.cols[subj].type};
            const imdb_segcol *sc = &g->col[subj];
            if (sv.type == IMDB_T_TEXT) {
                sv.s = sc->data + sc->off[r];
                sv.len = sc->off[r + 1] - sc->off[r];
            } else {
                sv.i = sc->i64[r];
            }
            uint8_t key[32];
            subj_key(&sv, key);
            if (!v->has_subj || memcmp(key, v->subj, 32) != 0) {
                it->rc = imdb_fail(e, IMDB_ERR_VERIFY, "lake: tombstone of version %llu of table %s names another subject",
                                   (unsigned long long)vid, vt->s.name);
                return;
            }
        }
    }
}

/* Object references: hash then a kind byte ('m', 's' or 'd'), so a name only
 * matches with its own extension. */
typedef uint8_t vref[33];

static int cmp_ref(const void *a, const void *b) { return memcmp(a, b, sizeof(vref)); }

static void put_ref(vref *r, const uint8_t h[32], char kind)
{
    memcpy(*r, h, 32);
    (*r)[32] = (uint8_t)kind;
}

static int add_refs(vref **refs, size_t *n, size_t *cap, const uint8_t mh[32], const imdb_manifest *m, imdb_err *e)
{
    size_t need = 1;
    for (uint32_t ti = 0; ti < m->nt; ti++) need += 2u * m->t[ti].nseg;
    if (*n + need > *cap) {
        size_t nc = *n + need;
        vref *nr = imdb_realloc_array(*refs, *cap, nc, sizeof *nr, e);
        if (!nr) return e->code;
        *refs = nr;
        *cap = nc;
    }
    put_ref(&(*refs)[(*n)++], mh, 'm');
    for (uint32_t ti = 0; ti < m->nt; ti++)
        for (uint32_t k = 0; k < m->t[ti].nseg; k++) {
            put_ref(&(*refs)[(*n)++], m->t[ti].seg[k].seg, 's');
            if (memcmp(m->t[ti].seg[k].dv, (uint8_t[32]){0}, 32) != 0) put_ref(&(*refs)[(*n)++], m->t[ti].seg[k].dv, 'd');
        }
    return IMDB_OK;
}

static int same_schema(const imdb_schema *a, const imdb_schema *b)
{
    imdb_buf x, y;
    imdb_buf_init(&x);
    imdb_buf_init(&y);
    imdb_schema_encode(a, &x);
    imdb_schema_encode(b, &y);
    int same = x.len == y.len && !x.err && !y.err && memcmp(x.p, y.p, x.len) == 0;
    imdb_buf_free(&x);
    imdb_buf_free(&y);
    return same;
}

static int verify_lake(imdb_db *db, const vctx *x, imdb_verify_report *rep, imdb_err *e)
{
    const vsnap *at = &x->at_s;
    if (!db->lake_seq) {
        if (x->last_publish)
            return imdb_fail(e, IMDB_ERR_VERIFY, "lake: the log publishes manifests but the database has no lake");
        /* and nothing outside the log may claim one: external readers trust LAKE_HEAD */
        bool present = false;
        uint64_t ls = 0;
        uint8_t lm[32];
        if (imdb_lake_head(db->dirfd, &present, &ls, lm, e)) return e->code;
        if (present)
            return imdb_fail(e, IMDB_ERR_VERIFY, "lake: LAKE_HEAD names commit %llu, but the log publishes no manifest",
                             (unsigned long long)ls);
        int ofd = imdb_io_openat(db->dirfd, "objects", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
        int dfd = ofd >= 0 ? dup(ofd) : -1;
        DIR *d = dfd >= 0 ? imdb_io_fdopendir(dfd) : NULL;
        if (!d && dfd >= 0) close(dfd);
        int rc = IMDB_OK;
        for (struct dirent *de; !rc && d && (de = imdb_io_readdir(d));)
            if (de->d_name[0] != '.')
                rc = imdb_fail(e, IMDB_ERR_VERIFY, "lake: objects/ holds files, but the log publishes no manifest");
        if (d) closedir(d);
        if (ofd >= 0) close(ofd);
        return rc;
    }
    if (db->lake_unverified)
        return imdb_fail(e, IMDB_ERR_VERIFY, "lake: rebuilt state awaits an ERASE record (%llu stubs pending)",
                         (unsigned long long)db->pending_auth);
    uint8_t *hb;
    size_t hl;
    if (imdb_read_file_at(db->dirfd, "LAKE_HEAD", &hb, &hl, 256, e)) return e->code;
    char want[200], hex[65];
    imdb_hex(db->lake_manifest, 32, hex);
    int wl = snprintf(want, sizeof want, "imagedb-lake 1\nseq %llu\nmanifest %s\n", (unsigned long long)db->lake_seq, hex);
    bool head_ok = (size_t)wl == hl && memcmp(hb, want, hl) == 0;
    imdb_free(hb);
    if (!head_ok) return imdb_fail(e, IMDB_ERR_VERIFY, "lake: LAKE_HEAD does not name the current manifest");
    if (!at->seen || db->lake_seq != x->last_publish || memcmp(at->manifest, db->lake_manifest, 32) != 0)
        return imdb_fail(e, IMDB_ERR_VERIFY, "lake: the manifest is not the one the last publishing commit (%llu) records",
                         (unsigned long long)x->last_publish);
    int ofd = imdb_lake_objects_open(db, e);
    if (ofd < 0) return e->code;
    uint8_t *mb = NULL, *pb = NULL;
    size_t ml = 0, pl = 0;
    imdb_manifest m, pm;
    memset(&m, 0, sizeof m);
    memset(&pm, 0, sizeof pm);
    uint8_t digest[32];
    imdb_lthash_digest(db->meta.digest_alg, &at->global, digest);
    int rc = imdb_lake_read_object(ofd, db->lake_manifest, ".man", &mb, &ml, e);
    if (!rc && (ml != db->lake_mlen || memcmp(mb, db->lake_mbytes, ml) != 0))
        rc = imdb_fail(e, IMDB_ERR_VERIFY, "lake: manifest on disk differs from the engine's");
    if (!rc) rc = imdb_manifest_parse(mb, ml, &m, e);
    if (!rc && (m.seq != db->lake_seq || memcmp(m.db_id, db->db_id, 16) != 0 || m.nt != at->nt ||
                memcmp(m.prev, at->prev, 32) != 0 || m.boundary != at->boundary))
        rc = imdb_fail(e, IMDB_ERR_VERIFY, "lake: manifest identity mismatch");
    if (!rc && memcmp(m.state, digest, 32) != 0)
        rc = imdb_fail(e, IMDB_ERR_VERIFY, "lake: manifest digest differs from the log at commit %llu", (unsigned long long)m.seq);
    if (!rc && memcmp(m.prev_manifest, at->prev_manifest, 32) != 0)
        rc = imdb_fail(e, IMDB_ERR_VERIFY, "lake: manifest names the wrong retained generation (prev_manifest)");
    if (!rc) { /* the generation the engine's next GC keeps must be that one too */
        uint8_t ph[32] = {0};
        if (db->lake_prev) imdb_sha256(db->lake_prev, db->lake_prevlen, ph);
        if (memcmp(ph, m.prev_manifest, 32) != 0)
            rc = imdb_fail(e, IMDB_ERR_VERIFY, "lake: the engine retains another generation than the manifest names");
    }
    for (uint32_t ti = 0; ti < m.nt && !rc; ti++) {
        const imdb_manifest_tab *mt = &m.t[ti];
        const vsnap_tab *st = &at->t[ti];
        if (!same_schema(&mt->s, &x->t[ti].s))
            rc = imdb_fail(e, IMDB_ERR_VERIFY, "lake: manifest schema of table %s differs from the log", x->t[ti].s.name);
        else if (mt->versions != st->n || mt->live != st->live || mt->horizon != st->horizon ||
                 mt->retention_us != st->retention_us || memcmp(&mt->digest, &st->d, sizeof st->d) != 0)
            rc = imdb_fail(e, IMDB_ERR_VERIFY, "lake: table %s in the manifest differs from the log at commit %llu",
                           x->t[ti].s.name, (unsigned long long)m.seq);
        else if (!same_indexes(mt->idx, mt->nidx, st->idx, st->nidx))
            rc = imdb_fail(e, IMDB_ERR_VERIFY, "lake: the manifest's indexes of table %s differ from the log's",
                           x->t[ti].s.name);
    }
    /* every segment against the log, in parallel windows; the seen-once marks in item order */
    size_t nitems = 0;
    for (uint32_t ti = 0; ti < m.nt; ti++) nitems += m.t[ti].nseg;
    litem *items = !rc ? imdb_alloc_array(nitems ? nitems : 1, sizeof *items, e) : NULL;
    if (!rc && !items) rc = e->code;
    size_t ni = 0;
    for (uint32_t ti = 0; ti < m.nt && !rc; ti++)
        for (uint32_t k = 0; k < m.t[ti].nseg; k++) items[ni++] = (litem){.table = ti, .k = k};
    for (size_t i = 0; i < ni; i++) { /* a missing file is reported by its item */
        char name[80];
        struct stat st;
        imdb_hex(m.t[items[i].table].seg[items[i].k].seg, 32, name);
        strcat(name, ".seg");
        items[i].size = imdb_io_fstatat(ofd, name, &st, AT_SYMLINK_NOFOLLOW) == 0 ? (uint64_t)st.st_size : 0;
    }
    /* windows of at most 2 per thread and IMDB_VERIFY_LAKE_BYTES (at least one segment) */
    size_t window = 2u * imdb_pool_threads();
    lctx L = {ofd, x, &m, items};
    for (size_t w0 = 0, wn = 0; w0 < ni && !rc; w0 += wn) {
        uint64_t bytes = 0;
        for (wn = 0; w0 + wn < ni && wn < window && (wn == 0 || bytes + items[w0 + wn].size <= IMDB_VERIFY_LAKE_BYTES); wn++)
            bytes += items[w0 + wn].size;
        L.it = items + w0;
        imdb_par_for(wn, lake_item, &L);
        for (size_t i = 0; i < wn; i++) {
            litem *it = &items[w0 + i];
            if (!rc && it->rc) rc = imdb_fail(e, it->rc, "%s", it->err.msg);
            for (uint32_t r = 0; !rc && it->g && r < it->g->nrows; r++) {
                uint64_t vid = it->g->vid[r];
                vver *v = vv(&x->t[it->table], vid); /* lake_item found every row's version held */
                if (!v || v->seen)
                    rc = imdb_fail(e, IMDB_ERR_VERIFY, "lake: version %llu of table %s is outside the manifest or twice in it",
                                   (unsigned long long)vid, x->t[it->table].s.name);
                else v->seen = true;
            }
            if (it->g) {
                rep->lake_rows_checked += it->g->nrows;
                rep->segments_checked++;
                imdb_segment_free(it->g);
                it->g = NULL;
            }
        }
    }
    for (size_t i = 0; items && i < ni; i++) /* after an early stop */
        if (items[i].g) imdb_segment_free(items[i].g);
    /* every version of the snapshot is in exactly one segment (tombstones included), but those its boundary retired */
    for (uint32_t ti = 0; ti < m.nt && !rc; ti++)
        for (uint64_t vid = 0; vid < at->t[ti].n; vid++) {
            const vver *v = vv(&x->t[ti], vid);
            if (!v) { /* not held: a whole absent chunk passes at once */
                if (!x->t[ti].vc || (vid >> IMDB_VCHUNK_BITS) >= x->t[ti].nchunk || !x->t[ti].vc[vid >> IMDB_VCHUNK_BITS])
                    vid |= IMDB_VCHUNK - 1;
                continue;
            }
            if (!v->seen && v->begin <= m.seq && !(v->end <= at->boundary && v->end <= m.seq)) {
                rc = imdb_fail(e, IMDB_ERR_VERIFY, "lake: version %llu of table %s is missing from the snapshot",
                               (unsigned long long)vid, x->t[ti].s.name);
                break;
            }
        }
    /* objects/ holds exactly the current generation and the retained one */
    vref *refs = NULL;
    size_t nrefs = 0, caprefs = 0;
    if (!rc) rc = add_refs(&refs, &nrefs, &caprefs, db->lake_manifest, &m, e);
    if (!rc && memcmp(m.prev_manifest, (uint8_t[32]){0}, 32) != 0) {
        imdb_err e2 = {0};
        if (imdb_lake_read_object(ofd, m.prev_manifest, ".man", &pb, &pl, &e2))
            rc = e2.code == IMDB_ERR_NOTFOUND
                     ? imdb_fail(e, IMDB_ERR_VERIFY, "lake: the retained generation the manifest names is missing")
                     : imdb_fail(e, e2.code, "%s", e2.msg);
        else if (!(rc = imdb_manifest_parse(pb, pl, &pm, e)))
            rc = add_refs(&refs, &nrefs, &caprefs, m.prev_manifest, &pm, e);
    }
    /* and what a pinned generation references, if this log published it at or after its last
     * ERASE (lake.h): never one from before (its files may hold erased rows) nor one it never
     * published. A stale pin counts too: its files stay until the next publication's GC. */
    for (size_t i = 0; !rc && i < x->npin; i++) {
        if (!x->pin_at[i] || x->pin_at[i] < x->last_erase) continue;
        uint8_t *qb = NULL;
        size_t ql = 0;
        imdb_manifest qm;
        memset(&qm, 0, sizeof qm);
        imdb_err e2 = {0};
        if (imdb_lake_read_object(ofd, x->pin[i], ".man", &qb, &ql, &e2)) {
            if (e2.code != IMDB_ERR_NOTFOUND) rc = imdb_fail(e, e2.code, "%s", e2.msg); /* gone: nothing kept */
        } else if (!(rc = imdb_manifest_parse(qb, ql, &qm, e))) {
            rc = add_refs(&refs, &nrefs, &caprefs, x->pin[i], &qm, e);
        }
        imdb_manifest_free(&qm);
        imdb_free(qb);
    }
    if (!rc) {
        size_t extra = 0; /* the keepers past the boundary: manifests a retained publish names */
        for (size_t i = 0; i < x->npubs; i++) extra += x->pubs[i].seq > x->boundary;
        vref *nr = extra ? imdb_realloc_array(refs, caprefs, nrefs + extra, sizeof *nr, e) : refs;
        if (!nr) {
            rc = e->code;
        } else {
            refs = nr;
            caprefs = extra ? nrefs + extra : caprefs;
            for (size_t i = 0; i < x->npubs; i++)
                if (x->pubs[i].seq > x->boundary) put_ref(&refs[nrefs++], x->pubhash[i], 'm');
        }
        qsort(refs, nrefs, sizeof *refs, cmp_ref);
        int dfd = dup(ofd);
        DIR *d = dfd >= 0 ? imdb_io_fdopendir(dfd) : NULL;
        if (!d) {
            if (dfd >= 0) close(dfd);
            rc = imdb_fail(e, IMDB_ERR_IO, "lake: cannot list objects/");
        }
        struct dirent *de;
        while (!rc && d && (de = imdb_io_readdir(d))) {
            if (de->d_name[0] == '.') continue;
            vref k;
            if (!imdb_object_name_valid(de->d_name) || !imdb_unhex(de->d_name, 64, k, 32)) {
                rc = imdb_fail(e, IMDB_ERR_VERIFY, "lake: unexpected file in objects/");
                break;
            }
            k[32] = (uint8_t)de->d_name[65]; /* <hash>.man | .seg | .dv */
            if (!bsearch(k, refs, nrefs, sizeof *refs, cmp_ref))
                rc = imdb_fail(e, IMDB_ERR_VERIFY,
                               "lake: objects/ holds a file no retained manifest references (an interrupted publish: a "
                               "writable open completes it)");
        }
        if (d) closedir(d);
    }
    imdb_free(refs);
    imdb_free(items);
    imdb_manifest_free(&pm);
    imdb_manifest_free(&m);
    imdb_free(pb);
    imdb_free(mb);
    close(ofd);
    return rc;
}

/* ---- the engine against the log --------------------------------------------------- */

static int verify_engine(imdb_db *db, const vctx *x, imdb_verify_report *rep, imdb_err *e)
{
    if (x->seq != db->seq || memcmp(x->head, db->head, 32) != 0)
        return imdb_fail(e, IMDB_ERR_VERIFY, "verify: engine head differs from the log");
    if (memcmp(&x->global, &db->global, sizeof x->global) != 0)
        return imdb_fail(e, IMDB_ERR_VERIFY, "verify: engine state digest differs from the log");
    if (x->nt != db->nt) return imdb_fail(e, IMDB_ERR_VERIFY, "verify: table count differs");
    if (db->boundary != x->boundary)
        return imdb_fail(e, IMDB_ERR_VERIFY, "verify: the engine's retirement boundary differs from the log's");
    for (uint32_t ti = 0; ti < x->nt; ti++) {
        imdb_table *et = db->t[ti];
        const vtab *vt = &x->t[ti];
        if (vt->n != et->nver || vt->live != et->live || vt->horizon != et->horizon ||
            vt->retention_us != et->retention_us || memcmp(vt->d, &et->digest, sizeof *vt->d) != 0)
            return imdb_fail(e, IMDB_ERR_VERIFY, "verify: table %s differs from the log", et->s.name);
        if (!same_indexes(vt->idx, vt->nidx, et->idx, et->nidx))
            return imdb_fail(e, IMDB_ERR_VERIFY, "verify: the engine's indexes of table %s differ from the log's", et->s.name);
        /* from scratch, independent of the delta arithmetic */
        imdb_lthash re;
        if (imdb_recompute_digest(db, et, db->seq, &re, e)) return e->code;
        if (memcmp(&re, &et->digest, sizeof re) != 0)
            return imdb_fail(e, IMDB_ERR_VERIFY, "verify: table %s incremental digest drifted", et->s.name);
        for (uint64_t vid = 0; vid < vt->n; vid++) {
            const vver *v = vv(vt, vid);
            if (!v) { /* below the floor and dropped there: the engine holds none of it either */
                uint64_t k = vid >> IMDB_VCHUNK_BITS;
                if (imdb_v_held(et, vid))
                    return imdb_fail(e, IMDB_ERR_VERIFY, "verify: table %s holds version %llu, which the log does not",
                                     et->s.name, (unsigned long long)vid);
                if ((k >= vt->nchunk || !vt->vc[k]) && !et->ch[k]) vid |= IMDB_VCHUNK - 1; /* both chunks absent */
                continue;
            }
            bool retired = v->end != IMDB_LIVE && v->end <= x->boundary; /* exactly these are gone */
            bool held = imdb_v_held(et, vid), purged = v->end != IMDB_LIVE && v->end <= vt->purged;
            imdb_vloc at; /* not held and not retired: past the memory window (stage 3b), the lake's alone */
            bool lake = !held && !retired && v->end != IMDB_LIVE && v->end <= db->mem_floor &&
                        imdb_v_find(et, vid, &at) == IMDB_VAT_LAKE;
            if (retired ? held : !held && !lake)
                return imdb_fail(e, IMDB_ERR_VERIFY, "verify: table %s version %llu is %s, but the log's boundary %s it",
                                 et->s.name, (unsigned long long)vid, retired ? "still held" : "gone",
                                 retired ? "retired" : "keeps");
            if (retired) continue;
            if (lake) { /* its row is the log's version: the lake check reads every row, this one by vid */
                uint8_t f = at.g->flags[at.row];
                if (at.g->begin[at.row] != v->begin || at.g->end[at.row] != v->end || v->stub != ((f & IMDB_SEG_STUB) != 0) ||
                    purged != ((f & IMDB_SEG_PURGED) != 0) || memcmp(v->commit, at.g->commit + 32u * at.row, 32) != 0)
                    return imdb_fail(e, IMDB_ERR_VERIFY, "verify: table %s version %llu differs", et->s.name,
                                     (unsigned long long)vid);
                if (f & IMDB_SEG_STUB) rep->stubs++;
                continue;
            }
            const imdb_version *ev = imdb_vh(et, vid);
            bool estub = (ev->flags & IMDB_V_STUB) != 0;
            if (v->end != ev->end || v->begin != ev->begin || v->stub != (estub && !(ev->flags & IMDB_V_PENDING_AUTH)) ||
                purged != ((ev->flags & IMDB_V_PURGED) != 0) || memcmp(v->commit, imdb_v_commit(et, vid), 32) != 0)
                return imdb_fail(e, IMDB_ERR_VERIFY, "verify: table %s version %llu differs", et->s.name,
                                 (unsigned long long)vid);
            if (estub) {
                /* an erased version must not keep any payload in memory */
                for (size_t k = 0; k < 16; k++) /* the memtable's cold part, or its row's (zeros once flagged) */
                    if (imdb_v_salt(et, vid)[k]) return imdb_fail(e, IMDB_ERR_VERIFY, "verify: erased version still holds its salt");
                if (!(ev->flags & IMDB_V_SEG) && ev->row_len) {
                    const uint8_t *p = imdb_mem_row(et, ev);
                    for (uint32_t k = 0; k < ev->row_len; k++)
                        if (p[k]) return imdb_fail(e, IMDB_ERR_VERIFY, "verify: erased version still holds row bytes in memory");
                }
                rep->stubs++;
            }
        }
        rep->versions += vt->n;
        rep->live += vt->live;
    }
    return IMDB_OK;
}

/* Past a cut (FLOOR, stage 3a (d)): the model starts at the floor F, not at the genesis. The tables at F come from
 * FLOOR's copy of F's manifest (its hash is in F's signed publish op); the versions at F from the current lake's rows
 * begun at or before F, all live at F (F's RETIRE dropped every row ended at or before it), a row's stub flag as the
 * lake has it (an ERASE in the retained log sets it again: VERIFY's ERASE takes a stub); each table's LtHash and live
 * count must be F's manifest's, and their sum F's signed state digest, so the seed is the state at F. A version that
 * ended at or before F is in no file any more: an ERASE in the retained log naming one is counted, not checked. */
static int verify_seed(imdb_db *db, vctx *x, imdb_err *e)
{
    imdb_manifest fm, m;
    memset(&m, 0, sizeof m);
    if (imdb_manifest_parse(db->floor_man, db->floor_manlen, &fm, e)) return e->code;
    uint64_t F = db->log_floor;
    int rc = IMDB_OK;
    if (!(x->t = imdb_alloc_array(fm.nt ? fm.nt : 1, sizeof *x->t, e))) rc = e->code;
    for (uint32_t i = 0; !rc && i < fm.nt; i++) {
        vtab *t = &x->t[i];
        t->s = fm.t[i].s;
        if (!(t->d = imdb_alloc_aligned(1, sizeof *t->d, e))) {
            rc = e->code;
            break;
        }
        imdb_lthash_zero(t->d);
        x->nt = i + 1;
        t->n = t->floor_n = fm.t[i].versions;
        t->horizon = fm.t[i].horizon;
        t->retention_us = fm.t[i].retention_us;
        memcpy(t->idx, fm.t[i].idx, sizeof t->idx);
        t->nidx = fm.t[i].nidx;
    }
    x->boundary = fm.boundary;
    uint8_t *mb = NULL, *sb = NULL;
    size_t ml = 0, sl = 0;
    int ofd = rc ? -1 : imdb_open_dir_at(db->dirfd, "objects", e);
    if (!rc && ofd < 0) rc = e->code;
    if (!rc && !(rc = imdb_lake_read_object(ofd, db->lake_manifest, ".man", &mb, &ml, e))) rc = imdb_manifest_parse(mb, ml, &m, e);
    for (uint32_t ti = 0; !rc && ti < m.nt && ti < fm.nt; ti++) { /* a table made past F holds no row begun by F */
        vtab *t = &x->t[ti];
        for (uint32_t k = 0; !rc && k < m.t[ti].nseg; k++) {
            if ((rc = imdb_lake_read_object(ofd, m.t[ti].seg[k].seg, ".seg", &sb, &sl, e))) break;
            uint8_t *al = imdb_alloc_aligned(1, sl, e);
            imdb_segment *g = NULL;
            if (!al) rc = e->code;
            else memcpy(al, sb, sl);
            imdb_free(sb);
            sb = NULL;
            if (!rc && (rc = imdb_segment_parse(&t->s, al, sl, &g, e))) imdb_free(al);
            /* the ends its deletion vector records at or before F: a seed's floor is its snapshot, whose lake still
             * holds history (a RETIRE's has dropped all of it); later ends are the replay's */
            if (!rc && memcmp(m.t[ti].seg[k].dv, (uint8_t[32]){0}, 32) != 0) {
                uint8_t *dvb = NULL, sh[32];
                size_t dl = 0;
                imdb_dv_ent *ents = NULL;
                uint32_t ne = 0;
                if (!(rc = imdb_lake_read_object(ofd, m.t[ti].seg[k].dv, ".dv", &dvb, &dl, e)) &&
                    !(rc = imdb_dv_parse(dvb, dl, sh, &ents, &ne, g->nrows, e))) {
                    if (memcmp(sh, g->hash, 32) != 0) rc = imdb_fail(e, IMDB_ERR_VERIFY, "lake: DV names another segment");
                    for (uint32_t q = 0; !rc && q < ne; q++)
                        if (ents[q].end <= F) g->end[ents[q].row] = ents[q].end;
                    imdb_free(ents);
                }
                imdb_free(dvb);
            }
            for (uint32_t r = 0; !rc && r < g->nrows; r++) {
                if (g->begin[r] > F) continue;
                uint64_t vid = g->vid[r];
                if (vid >= t->floor_n || vv(t, vid)) {
                    rc = imdb_fail(e, IMDB_ERR_VERIFY, "verify: the lake's version %llu of table %s is not one the floor had",
                                   (unsigned long long)vid, t->s.name);
                    break;
                }
                vver *v = vv_need(t, vid, e);
                if (!v) {
                    rc = e->code;
                    break;
                }
                memcpy(v->commit, g->commit + 32u * r, 32);
                v->begin = g->begin[r];
                v->end = g->end[r]; /* LIVE, or an end at or before F */
                if ((g->flags[r] & IMDB_SEG_PURGED) && v->end != IMDB_LIVE && v->end > t->purged)
                    t->purged = v->end; /* purged by F: every version ended before a purge is, so its highest end divides */
                v->stub = (g->flags[r] & IMDB_SEG_STUB) != 0;
                if (!v->stub && t->s.subject >= 0) {
                    imdb_value sv = {.type = t->s.cols[t->s.subject].type};
                    const imdb_segcol *sc = &g->col[t->s.subject];
                    if (sv.type == IMDB_T_TEXT) {
                        sv.s = sc->data + sc->off[r];
                        sv.len = sc->off[r + 1] - sc->off[r];
                    } else {
                        sv.i = sc->i64[r];
                    }
                    subj_key(&sv, v->subj);
                    v->has_subj = true;
                }
                x->rep->seeded++;
                if (v->end != IMDB_LIVE) continue; /* history at F: not in its digest */
                imdb_lthash el;
                imdb_lthash_element(db->meta.digest_alg, v->commit, &el);
                imdb_lthash_add(t->d, &el);
                t->live++;
            }
            if (g) imdb_segment_free(g);
        }
    }
    imdb_lthash_zero(&x->global);
    for (uint32_t i = 0; !rc && i < x->nt; i++) {
        if (memcmp(x->t[i].d, &fm.t[i].digest, sizeof fm.t[i].digest) != 0 || x->t[i].live != fm.t[i].live)
            rc = imdb_fail(e, IMDB_ERR_VERIFY, "verify: the lake's rows of table %s at the floor (commit %llu) are not the floor's",
                           x->t[i].s.name, (unsigned long long)F);
        else imdb_lthash_add(&x->global, x->t[i].d);
    }
    uint8_t d[32];
    imdb_lthash_digest(db->meta.digest_alg, &x->global, d);
    if (!rc && memcmp(d, db->floor_digest, 32) != 0)
        rc = imdb_fail(e, IMDB_ERR_VERIFY, "verify: the state at the floor (commit %llu) is not the one its commit signed",
                       (unsigned long long)F);
    if (!rc && db->nfloor_starts) { /* the segment starts below the floor an EXPIRE past it may name */
        if (!(x->starts = imdb_alloc_array(db->nfloor_starts, sizeof *x->starts, e))) rc = e->code;
        for (uint32_t i = 0; !rc && i < db->nfloor_starts; i++)
            x->starts[i] = (vstart){imdb_get_le64(db->floor_starts + 16 * i), imdb_get_le64(db->floor_starts + 16 * i + 8)};
        x->nstarts = x->capstarts = rc ? 0 : db->nfloor_starts;
    }
    if (!rc) {
        x->seq = F;
        memcpy(x->head, db->floor_hash, 32);
        x->ended = true; /* the floor published a manifest: the retained log begins a segment */
        x->last_time = db->floor_time;
        x->epoch = imdb_writer_epoch_at(db, F);
        memcpy(x->key, imdb_writer_key_at(db, F), IMDB_PUBKEY_LEN);
        /* the floor published a manifest (FLOOR requires it): the last publish so far; and a seeded copy's lake is
         * still the floor's, so the snapshot its lake check compares is taken here, never in the replay */
        uint8_t pubm[32];
        imdb_sha256(db->floor_man, db->floor_manlen, pubm);
        memcpy(x->last_manifest, pubm, 32);
        x->last_publish = F;
        imdb_commit_rec fc;
        if (db->lake_seq == F && !(rc = imdb_commit_decode_header(db->floor_hdr, db->floor_hlen, &fc, e))) {
            rc = snapshot_at_s(x, &fc, pubm, false, e);
            memcpy(x->at_s.prev_manifest, fm.prev_manifest, 32); /* what GC kept, as the manifest records it */
            imdb_commit_free(&fc);
        }
        x->rep->floor = F;
    }
    if (ofd >= 0) close(ofd);
    imdb_free(mb);
    imdb_manifest_free(&m);
    imdb_manifest_free(&fm);
    return rc;
}

/* The generations pins/ names, before the log pass learns which of them it published. */
static int vpins_collect(imdb_db *db, vctx *x, imdb_err *e)
{
    int pfd = imdb_io_openat(db->dirfd, IMDB_PINS_DIR, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (pfd < 0) return errno == ENOENT ? IMDB_OK : imdb_fail(e, IMDB_ERR_IO, "pins/: %s", strerror(errno));
    DIR *d = imdb_io_fdopendir(pfd);
    if (!d) {
        close(pfd);
        return imdb_fail(e, IMDB_ERR_IO, "pins/: cannot list");
    }
    int rc = IMDB_OK;
    struct dirent *de;
    for (;;) {
        errno = 0;
        if (!(de = imdb_io_readdir(d))) {
            if (errno) rc = imdb_fail(e, IMDB_ERR_IO, "pins/: directory read failed: %s", strerror(errno));
            break;
        }
        if (de->d_name[0] == '.') continue;
        if (!imdb_pin_name_valid(de->d_name)) {
            rc = imdb_fail(e, IMDB_ERR_VERIFY, "pins/: unexpected file %s", de->d_name);
            break;
        }
        if (x->npin == IMDB_MAX_PIN_FILES) {
            rc = imdb_fail(e, IMDB_ERR_LIMIT, "pins/: more than %u pins", IMDB_MAX_PIN_FILES);
            break;
        }
        if (!x->pin && (!(x->pin = imdb_alloc_array(IMDB_MAX_PIN_FILES, sizeof *x->pin, e)) ||
                        !(x->pin_at = imdb_alloc_array(IMDB_MAX_PIN_FILES, sizeof *x->pin_at, e)))) {
            rc = e->code;
            break;
        }
        (void)imdb_unhex(de->d_name, 64, x->pin[x->npin++], 32);
    }
    closedir(d);
    if (!rc && x->npin) qsort(x->pin, x->npin, sizeof *x->pin, cmp_hash32);
    return rc;
}

int imdb_verify(imdb_db *db, imdb_verify_report *rep, imdb_err *e)
{
    memset(rep, 0, sizeof *rep);
    if (db->in_txn) return imdb_fail(e, IMDB_ERR_STATE, "VERIFY cannot run inside a transaction");
    if (db->failed) return imdb_fail(e, IMDB_ERR_STATE, "database is in a failed state; reopen it to recover");
    vctx x;
    memset(&x, 0, sizeof x);
    x.rep = rep;
    x.db = db;
    memcpy(x.key, db->meta.writer, IMDB_PUBKEY_LEN);
    x.lake_seq = db->lake_seq;
    imdb_genesis_hash(db->db_id, x.head);
    imdb_lthash_zero(&x.global);
    double t_read = 0, t_par = 0, t_seq = 0;
    int rc = vpins_collect(db, &x, e);
    if (!rc && db->log_floor) rc = verify_seed(db, &x, e); /* past a cut: from the floor (FLOOR) */
    if (!rc) rc = verify_log(db, &x, &t_read, &t_par, &t_seq, e);
    if (!rc && x.epoch + 1 != db->nwep)
        rc = imdb_fail(e, IMDB_ERR_VERIFY, "verify: the engine holds %u writer epochs, the log %u", db->nwep, x.epoch + 1);
    /* a redaction marker must be authorised by an ERASE somewhere in the log */
    for (uint32_t ti = 0; ti < x.nt && !rc; ti++)
        for (uint64_t vid = 0; vid < x.t[ti].n; vid++) {
            const vver *v = vv(&x.t[ti], vid);
            if (!v) { /* not held: an absent chunk passes whole */
                uint64_t k = vid >> IMDB_VCHUNK_BITS;
                if (k >= x.t[ti].nchunk || !x.t[ti].vc[k]) vid |= IMDB_VCHUNK - 1;
                continue;
            }
            if (v->redacted && !v->stub) {
                rc = imdb_fail(e, IMDB_ERR_VERIFY,
                               "verify: redacted payload of version %llu of table %s not authorised by any ERASE",
                               (unsigned long long)vid, x.t[ti].s.name);
                break;
            }
        }
    rep->t_read = t_read;
    rep->t_par = t_par;
    rep->t_log = t_seq;
    double t0 = vnow();
    if (!rc) rc = verify_engine(db, &x, rep, e);
    rep->pending_auth = db->pending_auth;
    if (!rc && db->pending_auth)
        snprintf(rep->note, sizeof rep->note, "%llu redacted versions await their ERASE record from the primary",
                 (unsigned long long)db->pending_auth);
    rep->t_state = vnow() - t0;
    t0 = vnow();
    if (!rc) rc = verify_lake(db, &x, rep, e);
    rep->t_lake = vnow() - t0;
    memcpy(rep->head, x.head, 32);
    imdb_lthash_digest(db->meta.digest_alg, &x.global, rep->digest);
    for (uint32_t i = 0; i < x.nt; i++) {
        vt_free(&x.t[i]);
        imdb_free(x.t[i].d);
    }
    imdb_free(x.t);
    imdb_free(x.at_s.t);
    imdb_free(x.pin);
    imdb_free(x.starts);
    imdb_free(x.pubs);
    imdb_free(x.pubhash);
    imdb_free(x.pin_at);
    return rc;
}
