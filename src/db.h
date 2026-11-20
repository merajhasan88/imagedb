/*
 * imagedb engine: version store, transactions, commit log, replay,
 * replication apply, erasure and verification.
 *
 * Single writer. Every state change is a commit in the hash-chained log;
 * replicas, the lake (segments + manifests) and external verifiers are all
 * deterministic functions of that log, and each commit carries the LtHash
 * digest of the resulting logical state, so "same data everywhere" is
 * checked by comparing 32 bytes instead of reconciling rows.
 */
#ifndef IMDB_DB_H
#define IMDB_DB_H

#include <stdbool.h>
#include <stdint.h>
#include <pthread.h>

#include "codec.h"
#include "hashmap.h"
#include "log.h"
#include "role.h"
#include "lthash.h"
#include "sign.h"
#include "stream.h"

/* "Not deleted" marker for version.end. INT64_MAX (not UINT64_MAX) so the
 * same bits compare correctly as signed int64 in the SIMD range filters. It
 * never appears on disk: deletion vectors store only real commit numbers. */
#define IMDB_LIVE ((uint64_t)INT64_MAX)
#define IMDB_NONE UINT64_MAX

enum {
    IMDB_V_STUB = 1,          /* payload erased; only the commitment remains            */
    IMDB_V_PENDING_AUTH = 2,  /* stub seen before the ERASE that authorises it (replica) */
    IMDB_V_PURGED = 4,        /* physically removed by COMPACT ... PURGE                  */
    IMDB_V_SEG = 8,           /* row bytes live in a segment                              */
    IMDB_V_GONE = 16,         /* a slot of a dense chunk that holds no version (RETIRE dropped it) */
};

/* A version is stored in two parts, so that visibility checks, scans, joins and index maintenance
 * walk only the hot one (48 bytes) and the commitment and salt, read for verification, erasure and
 * the digest, stay in the cold one (48 bytes). The hot parts live in the table's chunked store (imdb_vh);
 * a cold part only while its version is in the memtable (imdb_vc): once flushed, the salt and commitment
 * are its segment row's (imdb_v_commit, imdb_v_salt), so the store holds 48 bytes a version (stage 3b). */
typedef struct imdb_version {
    uint64_t begin;           /* commit seq that created it                 */
    uint64_t end;             /* commit seq that deleted it, IMDB_LIVE      */
    uint64_t pk_prev;         /* older non-stub version with the same key   */
    uint64_t row_off;         /* arena offset (memtable rows)               */
    uint32_t row_len;
    uint32_t seg;             /* segment index (IMDB_V_SEG)                 */
    uint32_t seg_row;
    uint8_t flags;
} imdb_version;

typedef struct imdb_version_cold {
    uint8_t salt[16];
    uint8_t commit[32];
} imdb_version_cold;

/* The version store's chunks: 2^16 entries each, so growth never copies more than chunk 0 (which
 * grows from 64 entries to a whole chunk, keeping a small table small) and leaves at most one chunk
 * part empty, where one doubling array copied itself at each step and kept up to half of it empty. */
#define IMDB_VCHUNK_BITS 16
#define IMDB_VCHUNK ((uint64_t)1 << IMDB_VCHUNK_BITS)
/* A chunk other than the last that holds fewer versions than this keeps only those (sparse), so a few survivors
 * among versions RETIRE dropped cost their entries, not the chunk's 6 MB (stage 3b) */
#define IMDB_VSPARSE (IMDB_VCHUNK / 16)

/* One chunk: vids k << IMDB_VCHUNK_BITS onwards. Dense, a slot for each (n slots: chunk 0 grows to a whole chunk; a
 * slot holding no version flagged IMDB_V_GONE), or sparse, only the versions it holds (n of them, off[i] the offset
 * in the chunk of h[i]'s vid, ascending). */
typedef struct imdb_vchunk {
    uint16_t *off;            /* sparse: n offsets, in this allocation after h; NULL: dense */
    uint32_t n;
    uint32_t pad;
    imdb_version h[];
} imdb_vchunk;

typedef struct imdb_vlist {
    uint64_t *v;
    uint32_t n, cap;
} imdb_vlist;

struct imdb_segment;

/* an index's definition, as op 14 and manifest version 3 carry it */
typedef struct imdb_index_def {
    char name[IMDB_MAX_IDENT + 1];
    uint8_t flags;                      /* IMDB_INDEX_UNIQUE (log.h) */
    uint8_t ncols;                      /* 1..IMDB_MAX_INDEX_COLS */
    uint16_t cols[IMDB_MAX_INDEX_COLS]; /* the key's columns in order, distinct */
} imdb_index_def;

/* CREATE INDEX: a table's ordered index (a table keeps them sorted by name) */
struct imdb_oidx;
struct imdb_uidx;
struct imdb_tz;
typedef struct imdb_index {
    imdb_index_def d;
    struct imdb_oidx *ox; /* the ordered structure (oidx.h): engine tables only, NULL in models */
    struct imdb_uidx *ux; /* a unique index's key chains (db.c): engine tables only, else NULL */
} imdb_index;

/* The lake's segment images in memory (stage 3c-1): one cache for the database, each table pointing at it. An image
 * loads when an operation pins it (imdb_seg_pin, lake.h) and the least recently pinned are dropped when the outermost
 * operation ends, past the budget (imdb_op_leave), so the lake's memory follows the budget, not the retention.
 * Nothing is in use then: a pointer into an image lives until its operation ends. */
typedef struct imdb_segcache {
    uint64_t budget;          /* bytes of images kept between operations (imdb_open_opts.seg_cache_bytes;
                                 IMDB_SEGCACHE=tiny: 0, every image dropped as every operation ends) */
    uint64_t resident;        /* the images' bytes now: charged as an image becomes a table's or loads, credited
                                 as it leaves (lake.c: seg_img_bytes) */
    uint64_t loads, load_bytes; /* images loaded since the open and the object bytes read for them (SHOW MEMORY) */
    uint64_t clock;           /* outermost operations begun: a pin stamps its segment with it, a trim drops the oldest first */
    uint32_t depth;           /* operations open: a trim only when the outermost ends */
    bool streaming;           /* the open (3c-2): its passes release each image they have finished while over the budget
                                 (imdb_seg_release_one), and its replay trims between commits */
    uint64_t peak;            /* the most resident has been (since the open: tests and SHOW MEMORY's judge) */
    uint64_t snap_seq;        /* a snapshot load's commit S while it runs (db->seq is still 0 then): a reload's bound for its
                                 deletion vector's ends (3c-2: the open's passes read a segment again) */
    struct imdb_db *db;       /* the database it belongs to: a load opens its objects/ */
    pthread_mutex_t lock;     /* a segment's load state (lake.h: loading, ld_fail, ld_err), the counters a load moves, the
                                 publication of an image: never held while a load reads (P2 S14) */
    pthread_cond_t loaded;    /* P2 S14: broadcast as each load ends, read or failed: the workers waiting for that image */
    uint64_t load_waits;      /* P2 S14: pins that waited for another worker's load of their image (under the lock) */
    uint64_t released;        /* P2 S15: images a releasing statement let go before its operation ended (imdb_seg_done) */
} imdb_segcache;

/* F1 (design.md §5, Schema versions): a table's column positions, every one ever used. A column keeps its position
 * for its life, and a dropped one keeps it after, so a row of any version maps onto any later version position by
 * position; a position a row's version lacks (added after it) reads its missing value */
/* F2b-1: a live CHECK constraint: its name, and its text where a version keeps it (imdb_schema_hist) */
typedef struct imdb_chkref {
    char name[IMDB_MAX_IDENT + 1];
    const char *text;
    uint32_t len;
} imdb_chkref;

typedef struct imdb_tcol {
    imdb_value missing;      /* its ADD's DEFAULT, or NULL (a CREATE's columns: NULL, never read) */
    uint8_t *missing_text;   /* a TEXT DEFAULT's own bytes (missing.s points here) */
    uint32_t added, dropped; /* the versions that added it (1: the CREATE) and dropped it (0: live) */
    int16_t wver;            /* F1 stage 4: the SET DEFAULT version whose atext wdef's TEXT is (-1: the ADD's missing_text) */
    imdb_value wdef;         /* F1 stage 4: its write default, what an INSERT or COPY leaving it out writes (NULL: none):
                                the ADD's DEFAULT until a SET or DROP DEFAULT; its TEXT bytes are the ADD's
                                (missing_text) or a SET DEFAULT version's (imdb_sver.atext), never moved or freed
                                while the history lives */
    imdb_value cdef;         /* F2a: its CREATE's DEFAULT when a constant (its TEXT in missing_text; NULL: none or a clock) */
    uint8_t cclock;          /* F2a: its CREATE's DEFAULT when a clock (IMDB_DEFK_*), else 0 */
    uint8_t wclock;          /* F2a: the write default a kind past a value (IMDB_DEFK_*: a clock read at the write, F2a-2's
                                IDENTITY and nextval kinds a sequence's next value); 0: wdef is the default */
    uint32_t cseq, wseq;     /* F2a-2: the CREATE's and the write default's sequence (the IDENTITY and nextval kinds) */
    char *gtext;             /* F2c: GENERATED ALWAYS AS (gtext) STORED, its CREATE's (op 23 kind 9): glen bytes, the history's own;
                                NULL: not generated */
    uint32_t glen;
} imdb_tcol;

/* F1: a schema version. Rows begun at or after `since` (up to the next version's) are encoded under s, the columns
 * live at it in position order; a version's rows are never re-encoded */
typedef struct imdb_sver {
    uint64_t since;              /* the commit it began at: the CREATE's, or an ALTER's (op 22) */
    imdb_schema s;
    uint16_t pos[IMDB_MAX_COLS]; /* s's column i is position pos[i] */
    int8_t at[IMDB_MAX_COLS];    /* position p is s's column at[p], or -1: not live at this version */
    uint8_t hash[32];            /* s's hash (imdb_schema_hash): a segment built under it names it */
    uint8_t akind;               /* the ALTER that made it (0: version 1, the CREATE), and the position it named: a
                                    manifest writes the op again from these and s (lake.c) */
    uint16_t apos;
    uint16_t npos;               /* F1 stage 4: the positions used up to it (an ADD takes position npos) */
    imdb_value adef;             /* F1 stage 4: SET DEFAULT's value (a manifest writes the op again from it) */
    uint8_t *atext;              /* its TEXT bytes, the version's own (adef.s and a write default point here) */
    uint8_t aclock;              /* F2a: SET DEFAULT's clock kind (IMDB_ALTER_SET_DEFAULT_CLOCK), or an ADD's write default's
                                    (its missing value then the clock's at the ALTER); 0: none */
    char cname[IMDB_MAX_IDENT + 1]; /* F2b-1: ADD CHECK's and DROP CHECK's name; F2b-2: DROP FK's */
    imdb_fk afk;                 /* F2b-2: ADD FK's definition */
    char *ctext;                 /* F2b-1: ADD CHECK's text, the version's own (len bytes and a NUL), as live while the
                                    history lives: a live check's text is one of these or version 1's */
    uint32_t clen;
} imdb_sver;

/* F1: a table's schema history: its positions and versions (a table embeds one; so does VERIFY's model, which parses
 * and checks segments of every version as the engine does) */
typedef struct imdb_schema_hist {
    imdb_tcol tcol[IMDB_MAX_COLS]; /* the positions ever used, ntcol of them */
    uint16_t ntcol;
    imdb_sver *vers;               /* by since, nvers of them; the last is the current */
    uint32_t nvers, capvers;
    uint8_t *staged;               /* F1 stage 4: a SET DEFAULT's TEXT bytes between its prepare and its install (a
                                      rollback leaves them for the next prepare or the free) */
    /* F2b-1: CHECK constraints: version 1's (op 23's CREATE, a manifest's version 1: one allocation, by name), and the
     * live ones by name (version 1's or an ADD CHECK version's text, never moved or freed while the history lives);
     * cstaged: an ADD CHECK's text between its prepare and its install (a rollback leaves it, as staged) */
    imdb_check *chk0;
    uint16_t nchk0;
    uint16_t nchk;
    imdb_chkref chk[IMDB_MAX_CHECKS];
    uint32_t chkbytes;            /* the live texts' bytes together: IMDB_MAX_CHECK_TEXT at most */
    uint16_t ngen;                /* F2c: the columns the CREATE generated, ever (a DROP COLUMN leaves it: 0 means no write
                                     computes or verifies one; the live ones are those whose tcol has a gtext) */
    /* F2b-2: FOREIGN KEYs (docs/fk-design.md): version 1's (op 29's CREATE, a manifest's version 1: by name, one
     * allocation) and the live ones by name, copies (each version 1's or an ADD FK version's) */
    imdb_fk *fk0;
    uint16_t nfk0;
    uint16_t nfk;
    imdb_fk fk[IMDB_MAX_FKS];
    char *cstaged;
} imdb_schema_hist;

typedef struct imdb_table {
    imdb_schema s;
    imdb_vchunk **ch;         /* the version store: chunk k holds vids from k << IMDB_VCHUNK_BITS (NULL: it holds none) */
    uint32_t nchunk, capchunk; /* chunks in the directory, its room */
    uint64_t nver, capver;    /* versions (vids handed out); the vids the chunks' slots cover */
    uint64_t nheld;           /* versions the store holds: nver less those RETIRE dropped */
    uint64_t vbytes;          /* the store's bytes: its chunks and its directory */
    imdb_version_cold *mcold; /* the memtable's cold parts: vid v's at mcold[v - mem_first], until the flush */
    uint64_t capcold;
    imdb_buf arena;           /* canonical bytes of memtable rows          */
    uint64_t mem_first;       /* first vid not yet flushed to a segment    */
    imdb_hmap pk;             /* key -> newest non-stub version            */
    imdb_hmap subj;           /* subject -> index into subj_lists          */
    imdb_vlist *subj_lists;
    uint32_t nsubj, capsubj;
    imdb_lthash digest;       /* over live versions                        */
    uint64_t live;
    uint64_t live_stubs;      /* F2b-2: live versions whose payload an ERASE redacted (a replay before that ERASE, a snapshot
                               * loaded before it): their keys unknown, a child's missing parent key is not refuted */
    /* lake (segments) */
    struct imdb_segment **seg;
    imdb_segcache *segcache;  /* the database's (stage 3c-1): where its segments' images are loaded and kept */
    uint32_t nseg, capseg;
    uint64_t horizon;         /* AS OF below this seq is unavailable (purged) */
    uint64_t last_write;      /* E3: the commit that last wrote it (a row, or DDL: an index, its schema, its retention, its
                               * drop), the writer's runtime state: a SERIALIZABLE transaction that read it since fails */
    uint64_t last_erase;      /* E3: the commit that last erased from it: a SERIALIZABLE snapshot below it reads it no more
                               * (check_view: what it would read never was a state) */
    uint64_t retention_us;    /* op 16: how long a version stays answerable after it ends; IMDB_RETAIN_FOREVER */
    uint64_t created_at;      /* the commit that created it (a name resolves by a snapshot: imdb_table_at) */
    uint64_t dropped_at;      /* op 19 (1f): the commit that dropped it, its live versions ended there; 0: live */
    imdb_index idx[IMDB_MAX_INDEXES];
    uint32_t nidx;
    imdb_schema_hist hist;    /* F1: its schema history; hist.vers[hist.nvers - 1].s is s */
    struct imdb_chkc *chkc;   /* F2b-1: its live CHECKs compiled (sql_exec.c), for the history length it names; NULL: none yet */
    struct imdb_chkc *genc;   /* F2c: its live generated columns' expressions compiled, likewise */
    struct imdb_fkm *fkm;     /* F2b-2: its live FOREIGN KEYs' child maps (fk.c), built when a check first needs them */
    uint64_t idx_upto;        /* versions below are in the indexes' structures; the rest are the */
                              /* active transaction's own (versions are only appended) */
} imdb_table;

/* P2 S7: a view (design.md §5, Views). Its definition is logged (op 20) and kept in the manifest while it lives; a
 * dropped one is a tombstone, its id, name and two commits (a manifest keeps no more), its definition held only until
 * the handle closes, for a transaction older than the drop: def is NULL for a tombstone a manifest gave. Views live
 * in one array, reserved before a commit (imdb_view_reserve), so the install allocates nothing and a pointer to one is
 * good until the next CREATE VIEW. */
/* F2a-2: a sequence (design.md §5, Sequences): its definition and state. last is the value nextval handed out last,
 * or, while !called, the one it hands out next; a commit that called nextval logs it as the mark (op 26) */
typedef struct imdb_sequence {
    imdb_seqdef d;
    int64_t last;
    bool called;
    int64_t base;                  /* the start, or the last setval's value: what a mark's alignment counts from */
    uint64_t created_at, dropped_at; /* dropped_at 0: live */
    uint32_t owner;                /* UINT32_MAX: none; else the table whose IDENTITY column (owner_pos) owns it */
    uint16_t owner_pos;
} imdb_sequence;

typedef struct imdb_view {
    imdb_viewdef *def; /* allocated */
    char name[IMDB_MAX_IDENT + 1];
    uint32_t id;
    uint64_t created_at, dropped_at; /* dropped_at 0: live */
} imdb_view;

/* F3g: an ENUM type (design.md §5, ENUM; docs/f3g-design.md): its definition (ADD VALUE swaps in the definition with
 * one more label: labels only grow, so a reader of an older snapshot finds every label it holds) and its life; a
 * dropped one a tombstone keeping its labels, resolved by snapshot (imdb_enum_at) as a dropped view is. Its id is
 * its index + 1 (an ENUM column's eid; 0 none) */
typedef struct imdb_enum {
    imdb_enumdef *def; /* allocated */
    uint64_t created_at, dropped_at; /* dropped_at 0: live */
} imdb_enum;

/* vid's entry in sparse chunk c (UINT32_MAX: none) */
static inline uint32_t imdb_vchunk_find(const imdb_vchunk *c, uint64_t vid)
{
    uint32_t o = (uint32_t)(vid & (IMDB_VCHUNK - 1)), lo = 0, hi = c->n;
    while (lo < hi) {
        uint32_t mid = lo + (hi - lo) / 2;
        if (c->off[mid] < o) lo = mid + 1;
        else hi = mid;
    }
    return lo < c->n && c->off[lo] == o ? lo : UINT32_MAX;
}
/* The one held rule (stage 3a's presence rule): a vid below t->nver names a version the store holds unless RETIRE
 * dropped it, its chunk then freed (a NULL slot), sparse without it, or holding its slot flagged IMDB_V_GONE. Every
 * walk over vids and every vid read from the log asks this first; imdb_vh and imdb_vc are for held versions only,
 * and abort on any other in the checked builds (IMDB_STORE_CHECKS: SAN and fuzz), where a sparse chunk's
 * neighbouring entry would otherwise be read in silence. */
static inline bool imdb_v_held(const imdb_table *t, uint64_t vid)
{
    if (vid >= t->nver) return false;
    const imdb_vchunk *c = t->ch[vid >> IMDB_VCHUNK_BITS];
    if (!c) return false;
    if (!c->off) return !(c->h[vid & (IMDB_VCHUNK - 1)].flags & IMDB_V_GONE);
    uint32_t i = imdb_vchunk_find(c, vid);
    return i != UINT32_MAX && !(c->h[i].flags & IMDB_V_GONE);
}
/* the checked builds' stop when the store breaks its contract (what: which check) */
void imdb_v_misuse(const imdb_table *t, uint64_t vid, const char *what) __attribute__((noreturn));
/* vid's entry in its chunk: its slot (dense) or its place among the held (sparse) */
static inline uint32_t imdb_v_entry(const imdb_table *t, uint64_t vid)
{
#ifdef IMDB_STORE_CHECKS
    if (!imdb_v_held(t, vid)) imdb_v_misuse(t, vid, "read but not held (db.h: the held rule)");
#endif
    const imdb_vchunk *c = t->ch[vid >> IMDB_VCHUNK_BITS];
    return c->off ? imdb_vchunk_find(c, vid) : (uint32_t)(vid & (IMDB_VCHUNK - 1));
}
/* A held version's parts. A pointer into chunk 0 moves while chunk 0 grows, and one into any chunk when a RETIRE
 * frees it or makes it sparse: take it again after an append or a RETIRE. */
static inline imdb_version *imdb_vh(const imdb_table *t, uint64_t vid)
{
    return &t->ch[vid >> IMDB_VCHUNK_BITS]->h[imdb_v_entry(t, vid)];
}
/* A memtable version's cold part (vid at or past t->mem_first); a flushed one's are its segment row's. */
static inline imdb_version_cold *imdb_vc(const imdb_table *t, uint64_t vid)
{
#ifdef IMDB_STORE_CHECKS
    if (vid < t->mem_first || vid >= t->nver) imdb_v_misuse(t, vid, "cold part of a version not in the memtable");
#endif
    return &t->mcold[vid - t->mem_first];
}
/* Where version vid is (stage 3b): IMDB_VAT_HELD, the store holds it (at->v; at->g and at->row too once it is in a
 * segment); IMDB_VAT_LAKE, a segment of the lake holds it (at->g, at->row) and the store does not; IMDB_VAT_NONE,
 * neither: past the count, or RETIRE dropped it. The one check for a vid from the log or an API (replay's ops,
 * ERASE's entries, a transaction's writes and locks), so that what it decides never depends on what the store
 * holds, only where the answer is read. Negative (e set): the lake's image of the segment holding it could not be had
 * (stage 3c-1: a read error, a corrupt object, memory). A caller reading at->g's row pins it first (imdb_seg_pin). */
enum { IMDB_VAT_NONE = 0, IMDB_VAT_HELD = 1, IMDB_VAT_LAKE = 2 };
typedef struct imdb_vloc {
    imdb_version *v;
    struct imdb_segment *g;
    uint32_t row;
} imdb_vloc;
int imdb_v_find(const imdb_table *t, uint64_t vid, imdb_vloc *at, imdb_err *e);
/* A version's commitment and salt, wherever they are: the memtable's cold part, or its segment row's
 * (*out NULL: IMDB_VAT_NONE; a flagged row's salt is zeros); negative as imdb_v_find */
int imdb_v_commit(const imdb_table *t, uint64_t vid, const uint8_t **out, imdb_err *e);
int imdb_v_salt(const imdb_table *t, uint64_t vid, const uint8_t **out, imdb_err *e);
uint64_t imdb_v_next_slow(const imdb_table *t, uint64_t vid);
/* The first held vid at or after vid (t->nver: none). A walk passes a freed chunk at once and a sparse one by its
 * entries, so walking a store whose old chunks are retired costs what it holds, not every vid it ever had (14
 * billion a year at the soak's rate). Walks: for (vid = imdb_v_next(t, 0); vid < t->nver; vid = imdb_v_next(t,
 * vid + 1)). */
static inline uint64_t imdb_v_next(const imdb_table *t, uint64_t vid)
{
    if (vid < t->nver) {
        const imdb_vchunk *c = t->ch[vid >> IMDB_VCHUNK_BITS];
        if (c && !c->off && !(c->h[vid & (IMDB_VCHUNK - 1)].flags & IMDB_V_GONE)) return vid;
    }
    return imdb_v_next_slow(t, vid);
}

typedef struct imdb_commit_info {
    uint64_t time_us;
    uint8_t hash[32];
    uint8_t digest[32];
} imdb_commit_info;

typedef struct imdb_undo {
    uint8_t kind;
    uint32_t table;
    uint64_t vid;
    uint64_t prev_head;       /* INSERT: previous pk head (IMDB_NONE)      */
    uint64_t arena_len;       /* INSERT: arena length before               */
    uint32_t subj_list;       /* INSERT: list appended to (UINT32_MAX none) */
    bool subj_created;
} imdb_undo;

/* What META pins and a replica copies: the database, the writer key of epoch 0 and, optionally,
 * the root key that may certify a promotion (deferred.md R2b). Nothing secret. */
typedef struct imdb_identity {
    uint8_t db_id[16];
    uint8_t writer[IMDB_PUBKEY_LEN];
    bool has_root;
    uint8_t root[IMDB_PUBKEY_LEN];
    uint8_t digest_alg;       /* IMDB_DIGEST_ALG_* (log.h): every commit names it, every digest is computed by it */
} imdb_identity;

/* P1 M1: what a copy has done since its open, for SHOW STATS and the export (--stats FILE). Per copy, in memory,
 * never logged and never derived: nothing a replica recomputes reads it. Statements by class and their latency;
 * failures by kind; commits (imdb_commit), rollbacks, the log's bytes; the segment cache's hits (first pins of an
 * image already in memory in an operation; its misses are segcache.loads); each maintenance op's count and time;
 * the open's. Moved on the engine thread but seg_hits (the workers' pins: atomic). */
enum { IMDB_SC_READ, IMDB_SC_WRITE, IMDB_SC_TXN, IMDB_SC_DDL, IMDB_SC_PHYSICAL, IMDB_SC_SHOW, IMDB_SC_OTHER, IMDB_SC_N };
enum { IMDB_SF_CONFLICT, IMDB_SF_LIMIT, IMDB_SF_CANCELLED, IMDB_SF_OTHER, IMDB_SF_N };
enum { IMDB_MT_CHECKPOINT, IMDB_MT_COMPACT, IMDB_MT_EXPIRE, IMDB_MT_RETIRE, IMDB_MT_EVICT, IMDB_MT_N };
typedef struct imdb_stats {
    uint64_t stmts[IMDB_SC_N], fails[IMDB_SF_N];
    imdb_hist stmt_lat[IMDB_SC_N];
    uint64_t commits, rollbacks, log_bytes, applied; /* applied: a replica's commits taken from a stream (apply) */
    uint64_t ser_conflicts;   /* E3: SERIALIZABLE commits refused because a table they read was written since their snapshot */
    uint64_t priv_refused[3]; /* N1e stage two: statements a gate refused (A its kind or SET, B a read, C a write's target) */
    uint64_t priv_events_dropped; /* N1e stage two: their events past a role's rate (at most 4 a second a role) */
    imdb_hist commit_lat;
    uint64_t seg_hits;
    uint64_t maint_n[IMDB_MT_N], maint_ns[IMDB_MT_N], maint_max_ns[IMDB_MT_N], maint_last_ns[IMDB_MT_N];
    uint64_t opened_us, open_ns, open_replayed; /* the open's wall time, its length, the commits it replayed */
    uint64_t repl_heard_ns, repl_primary_seq; /* R1.2: a replica's last record from its primary (imdb_mono_ns; 0: none
                                              * yet) and the latest commit the primary named (a keep-alive, a frame) */
} imdb_stats;

typedef struct imdb_db {
    char *path;
    char *location;           /* F5c: the directory's absolute path (resolved at the open), the Iceberg layer's; NULL: off */
    struct imdb_ice_seen *ice_seen; /* F5c: each segment of the kept generations and its flagged rows, as the last layer
                                       found them (iceberg.c: by hash, sorted), so a layer reads no segment twice */
    uint32_t nice_seen;
    uint64_t ice_reads;       /* F5c: the vectors, images and segments its layers read (the tests' measure: imdb_iceberg_reads) */
    int dirfd, logfd, lockfd;
    int durfd;                /* DURABLE (writable opens): the watermark, rewritten per append */
    int anchorfd;             /* the external anchor (writable opens with an anchor), else -1 */
    char *anchor_path;        /* and its path: fencing reads whatever file is there now */
    int anchor_lockfd;        /* the anchor's writer lock (FILE.lock, flock), held for the handle's life: one writer */
    int anchor_slot;          /* the record the next anchor rewrite goes to (log.h: two slots) */
    imdb_durable dur;         /* the watermark: as found at open, then as last published */
    bool have_dur;            /* DURABLE existed and parsed (open), or has been written */
    uint64_t unsynced_from;   /* first commit appended without fdatasync (--nosync) since the watermark was synced */
    int logdirfd;             /* log/: the segments (see logdir.h)        */
    uint64_t *segs;           /* first seq of every segment, ascending     */
    size_t nsegs, capsegs;
    uint64_t *seg_time;       /* each one's first commit's time (0: not read yet; expiry reads it), capsegs long */
    bool log_rotate;          /* the next append starts a new segment       */
    bool log_tagged;          /* the last segment is tagged (log.h): appends overwrite its zero fill */
    bool log_group;           /* tagged: a write group is open (frames appended since the last fdatasync) */
    uint64_t log_phys;        /* tagged, no group open: the sector the next group begins at */
    uint64_t log_fill;        /* tagged: the end of its zero fill (the file's size, as far as known) */
    imdb_tgroup log_tg;       /* tagged: the open group's layout */
    uint64_t *redact_seqs;    /* commits whose payloads await redaction    */
    size_t nredact, capredact;
    bool redact_known;        /* a note was taken (L stage 2): nredact 0 then means nothing in this log, not a crash's unknown */
    bool lake_pending;        /* objects + LAKE_HEAD of the lake state not yet written */
    bool gc_pending;          /* published, but unreferenced objects could not all be removed */
    bool lake_ahead;          /* open: LAKE_HEAD named a commit the log no longer holds (a --nosync loss) */
    bool full_replay;         /* open: ignore the lake snapshot             */
    uint64_t snapshot_seq;    /* open started from the lake snapshot at this commit (0: full replay) */
    uint64_t last_erase;      /* the last commit with an ERASE this handle applied (replayed or its own) */
    uint64_t boundary;        /* RETIRE's: versions ended at or before it are gone (the same on every copy) */
    uint64_t log_floor;       /* this copy's own: its log begins at log_floor + 1 (FLOOR; 0: at the genesis) */
    uint8_t floor_hash[32];   /* commit log_floor's hash (its successor's prev) and its signed state digest */
    uint8_t floor_digest[32];
    uint64_t floor_time;      /* commit log_floor's time: its successor's must be later */
    uint8_t *floor_starts;    /* FLOOR's segment starts below the floor, u64 seq | u64 time each (VERIFY's) */
    uint32_t nfloor_starts;
    uint8_t *floor_man;       /* FLOOR's copy of commit log_floor's manifest: the tables at the floor (VERIFY's) */
    size_t floor_manlen;
    uint8_t *floor_hdr;       /* FLOOR's copy of commit log_floor's header, and its signature: a snapshot at the floor */
    uint32_t floor_hlen;      /* (a seeded copy's, whose log begins after it) is authenticated by them (lake.c) */
    uint8_t floor_sig[64];
    uint64_t seeded;          /* apply took a seed at this commit (seed.c): the handle is stale, reopen it */
    uint32_t floor_stride;    /* keepers: a publish p is one iff p / stride > (the previous segment's end) / stride */
    struct imdb_keeper *keep; /* the keepers' manifests past the boundary, by hash (GC keeps them; lake.c) */
    size_t nkeep, capkeep;
    uint64_t retire_cand[2], retire_cand_n[2]; /* the RETIRE policy's candidates (0 its own, 1 a replica's cap) and the
                                                * versions each would drop; reset by every RETIRE */
    uint64_t retire_held_us; /* when a replica last held the policy back (0: none): it looks again a second later */
    bool no_auto_retire;      /* tests that RETIRE by hand turn the policy off for their handle */
    uint64_t pin_max_lag;     /* IMDB_PIN_MAX_LAG (tests lower it) */
    uint64_t mem_limit;       /* the memory budget (imdb_open_opts.mem_limit; 0: none) */
    uint64_t prep_bytes;      /* P2 S9: what every session's prepared statements hold (sql_exec.c), in imdb_mem's total */
    uint64_t mem_reserve;     /* D8 #2: the budget's part kept from writes for a query (imdb_query_share; 0: none) */
    uint64_t mem_window_us;   /* stage 3b: a version ended within it stays in memory (imdb_open_opts.mem_window_us) */
    uint64_t mem_floor;       /* every version ended past it is held; one ended at or before it may be the lake's alone,
                                 so a read below it goes to the lake (sql_exec.c); it only rises, and is never logged */
    uint64_t ended_pass;      /* versions ended since the last eviction pass: its trigger */
    bool evict_eager;         /* every publish evicts to its own commit (IMDB_EVICT=eager: the matrix's third unit pass) */
    imdb_segcache segcache;   /* stage 3c-1: the lake's segment images in memory, under a budget */
    imdb_stats stats;         /* P1 M1: counters and latencies since the open (SHOW STATS) */
    int stats_fd;             /* P1 M1: the export's file (imdb_open_opts.stats_path; -1: none) */
    uint64_t stats_last_ns, stats_exports, stats_errors; /* the last export, the writes and the failures */
    uint64_t stats_disk_ns, stats_log_b, stats_lake_b;   /* the export's walk of log/ and objects/, once a minute */
    bool stats_disk_ok;
    bool stats_said_failed;   /* an export has said the handle failed: until then a failed handle exports at once */
    uint64_t stmt_start_ns;   /* the running statement's start (0: none): long-running work in the export */
    char stats_buf[IMDB_STATS_EXPORT_MAX];
    int events_fd, events_dirfd; /* P1 M2: the event log and its directory (rotation: FILE.1); -1: none */
    char events_base[256];    /* FILE's name in that directory */
    uint64_t events_bytes, events_lines, events_errors, events_cap; /* events_cap: tests lower it */
    bool events_said_failed, ev_open, ev_full;
    size_t ev_len;
    pthread_mutex_t events_lock; /* a line is built and appended whole */
    /* P2's zones (tz.h): each loaded at its first use (imdb_db_zone), then read by any thread, freed at close; the lock
     * guards the table and a load (two sessions naming a new zone at once load it once) */
    pthread_mutex_t tz_lock;
    char tz_root[IMDB_MAX_PATH];  /* the zoneinfo directory: --zoneinfo, else /usr/share/zoneinfo */
    struct imdb_tz *tz[IMDB_MAX_TZ_ZONES];
    uint32_t ntz;
    char events_buf[IMDB_EVENTS_LINE_MAX];
    void (*progress)(void *ctx, const char *phase, uint64_t done, uint64_t total);
    void *progress_ctx;
    uint64_t progress_last_ns; /* the open's start, then the last report */
    bool progress_said;        /* a report since the last phase ended */
    uint64_t checkpoint_bytes; /* primary: auto-CHECKPOINT past this segment size (0 = off) */
    bool lake_sync;           /* primary: CHECKPOINT after every commit that changed data (imdb_open_opts) */
    bool strict;              /* durable_ack with sync: every DURABLE record fsynced before its commit returns */
    uint8_t db_id[16];
    bool replica;
    bool following;           /* R1.2: a follower (imagedb follow) runs on this handle: the export counts its silence
                               * (replication.last_heard_ms, from stats.repl_heard_ns; -1 while not following) */
    bool failed;              /* a write/apply failed: reopen to recover   */
    uint8_t writer_pk[IMDB_PUBKEY_LEN]; /* the current writer key (writer.h): the last epoch's */
    imdb_identity meta;       /* META: the db id, the epoch-0 writer key, the root key if any */
    struct imdb_wep *wep;     /* the writer epochs so far, wep[0] from META (writer.h) */
    uint32_t nwep, capwep;
    bool can_sign;            /* primary with signing.key                  */
    imdb_signer signer;
    int sync;                 /* 1 = fdatasync every commit                */
    uint64_t seq;
    uint8_t head[32];
    /* N1b: a statement's own commit for the server's DONE: each commit's number and hash but imdb_maintain's (a
     * size-triggered CHECKPOINT, an expiry, a RETIRE: between statements, never one's own), which sets maintaining */
    uint64_t stmt_seq;
    uint8_t stmt_head[32];
    bool maintaining;
    uint64_t role_gen;        /* N1b: moves at every install and erasure of a role's entries, privileges or memberships:
                               * the server makes its logins again when it moves (a password, NOLOGIN, a rename, DROP, ERASE) */
    uint64_t last_time;
    uint64_t tx_time;         /* set: the next commit's time (expiry checked its rule against it) */
    uint32_t last_hlen;       /* commit seq's signed descriptor (header length, signature): an anchor names it */
    uint8_t last_sig[IMDB_SIG_LEN];
    imdb_commit_info *ci;     /* ci[i] is commit ci_first + i (see db.c)   */
    imdb_commit_info *ci_old; /* stage 3b: one log segment's commits below ci_first, read on demand (imdb_ci_at) */
    uint64_t ci_old_first, nci_old;
    uint64_t nci, capci, ci_first;
    imdb_table **t;
    uint32_t nt;
    imdb_view *views; /* P2 S7: views[i] is view i, a dropped one a tombstone */
    uint32_t nviews, capviews;
    imdb_enum *enums; /* F3g: enums[id - 1] is type id, a dropped one a tombstone */
    uint32_t nenums, capenums;
    imdb_rcat rc;           /* L: the roles, their privileges and memberships (role.h) */
    struct {                /* N1e stage two: privilege events by role, at most 4 a second each (sql_exec.c priv_note; the
                             * least recent entry replaced: 64 roles at once) */
        uint32_t role, n;
        uint64_t sec;
    } priv_ev[64];
    imdb_sequence *seqs; /* F2a-2: seqs[i] is sequence i, a dropped one a tombstone */
    uint32_t nseqs, capseqs;
    uint32_t *txseq;     /* F2a-2: the active transaction's sequences nextval touched, by id (SEQ_ADVANCE at its commit) */
    uint32_t ntxseq, captxseq;
    imdb_lthash global;
    /* transaction */
    bool in_txn;
    uint64_t last_ddl;  /* E3: the last commit that changed the catalog (a name, a table's shape or index, a view's
                         * or a type's definition), which every statement reads by its snapshot: a SERIALIZABLE
                         * writer whose snapshot is below it is refused (txn.c ser_reads_current) */
    uint64_t begin_seq; /* E3: db->seq at imdb_begin: no commit lands inside an engine transaction (the checked builds
                         * abort at the commit otherwise), so an autocommit statement is serial by construction */
    imdb_op *tx;
    uint64_t *tx_row_off;
    uint32_t ntx, captx;
    uint64_t tx_bytes;        /* row bytes of the pending commit's ops     */
    imdb_undo *undo;
    size_t nundo, capundo;
    uint64_t lim_txn_bytes;   /* the open options' limits (imdb_open_opts) */
    uint32_t lim_txn_ops, lim_txn_locks;
    /* status */
    uint64_t log_size;        /* bytes in the current (last) segment       */
    uint64_t pending_auth;    /* stubs awaiting authorisation              */
    bool needs_redaction;
    uint64_t clean_seq;       /* imdb_cleanup_seq: the last commit seen with no cleanup outstanding */
    char warning[512];        /* e.g. torn-tail truncation at open         */
    uint64_t lake_seq;        /* seq of the newest published lake snapshot */
    uint8_t lake_manifest[32];
    uint8_t *lake_mbytes;     /* that manifest's bytes                     */
    size_t lake_mlen;
    uint8_t *lake_robj;       /* L: the roles object it names (lake_rhash; none: zero) */
    size_t lake_robjlen;
    uint8_t lake_rhash[32];
    uint8_t *lake_prev;       /* previous manifest (GC keeps its objects); */
    size_t lake_prevlen;      /* NULL after an ERASE                       */
    bool lake_dirty;          /* logical changes since the last manifest   */
    bool lake_unverified;     /* a rebuilt manifest awaits a later ERASE   */
    bool replaying;           /* inside imdb_replay (objects written at end) */
    bool read_only;
    struct imdb_lake_plan *erase_plan; /* planned with an ERASE, installed after commit */
    /* session transactions (txn.c) */
    struct imdb_txn *txns;    /* every open one */
    struct imdb_txn *active;  /* the one whose pending versions are in the store (tx, undo) */
} imdb_db;

typedef struct imdb_open_opts {
    int sync;                 /* default 1 */
    bool read_only;           /* verification tools: never truncate/redact */
    uint64_t checkpoint_bytes; /* 0: the default (IMDB_CHECKPOINT_BYTES); UINT64_MAX: never */
    uint32_t floor_stride;     /* 0: the default (IMDB_FLOOR_STRIDE): which publishes' manifests a future FLOOR may use */
    bool full_replay;         /* replay the whole log instead of starting from the lake snapshot */
    bool lake_sync;           /* publish the lake after every commit that changed data (a CHECKPOINT each: priced) */
    const char *anchor;       /* the external anchor file (log.h), outside the data directory; NULL: none */
    const char *stats_path;   /* P1 M1: the stats export (--stats FILE), outside the data directory; NULL: none */
    const char *events_path;  /* P1 M2: the event log (--events FILE), outside the data directory; NULL: none */
    const char *zoneinfo;     /* P2: the zoneinfo directory zones are read from (--zoneinfo DIR); NULL: /usr/share/zoneinfo */
    /* P1 M2: the open's progress, at most once a second: its phase ("lake" segments, "replay" commits), done of total */
    void (*progress)(void *ctx, const char *phase, uint64_t done, uint64_t total);
    void *progress_ctx;
    bool accept_rollback;     /* an anchor newer than the log: continue from the log and rewrite the anchor */
    bool durable_ack;         /* fsync DURABLE before each durable commit returns (log.h: strict): a damaged frame past
                                 it is then provably unacknowledged and recovery may drop it; +1 device flush
                                 per commit (measured +3.3 ms on the test machine) */
    uint64_t mem_limit;       /* bytes the database may hold in memory (0: no budget); see imdb_mem */
    uint64_t mem_window_us;   /* stage 3b: a version ended within this stays in memory, an older one in the lake alone
                                 (each copy its own, never logged: 0, IMDB_MEM_WINDOW_US; UINT64_MAX, none leaves) */
    uint64_t seg_cache_bytes; /* stage 3c-1: the lake's segment images kept in memory between operations (0:
                                 IMDB_SEG_CACHE_BYTES; UINT64_MAX: every image kept) */
    /* per-transaction limits, at most the limits.h maxima (0: the maximum); a statement that
     * would exceed one fails with IMDB_ERR_LIMIT and the transaction stays usable */
    uint64_t txn_bytes;       /* row bytes written (IMDB_MAX_TXN_BYTES) */
    uint32_t txn_ops;         /* row operations (IMDB_MAX_OPS_PER_COMMIT) */
    uint32_t txn_locks;       /* rows selected FOR UPDATE (IMDB_MAX_TXN_LOCKS) */
    bool iceberg;             /* F5c: write the Iceberg v3 layer per copy after every publish (iceberg.h; the CLI's --iceberg;
                                 off at the API so that the fault tables do not move) */
} imdb_open_opts;

/* ---- lifecycle ---------------------------------------------------------- */
/* Primary: fresh db id and writer key (signing.key). Replica: copies the
 * identity from a local primary directory. */
int imdb_init(const char *path, bool replica, const char *from_primary, imdb_err *e);
/* A primary whose promotions root (NULL: none) may certify, of digest_alg 2 (format 1's one algorithm). */
int imdb_init_primary(const char *path, const uint8_t *root, imdb_err *e);
/* Replica of a remote primary, from its identity (see imagedb identity). */
int imdb_init_replica(const char *path, const imdb_identity *id, imdb_err *e);
int imdb_read_identity(const char *dir, uint8_t db_id[16], uint8_t writer[IMDB_PUBKEY_LEN], imdb_err *e);
int imdb_identity_read(const char *dir, imdb_identity *id, bool *replica, imdb_err *e);
/* Whether META names the directory a replica. */
int imdb_read_role(const char *dir, bool *replica, imdb_err *e);
/* "imagedb-identity 1\ndb_id <hex>\nwriter <hex>\n" (2, with "root <hex>", when there is a root
 * key); returns its length or -1. */
int imdb_identity_format(const imdb_identity *id, char *out, size_t cap);
int imdb_identity_parse(const char *s, size_t n, imdb_identity *id, imdb_err *e);
int imdb_open(const char *path, const imdb_open_opts *o, imdb_db **out, imdb_err *e);
/* P2: the zone a name names (tz.h): UTC and its aliases built in, any other a file under the zoneinfo directory, loaded
 * once outside any statement's memory ceiling; INVALID for an unknown one (its message never naming it) */
int imdb_db_zone(imdb_db *db, const char *name, size_t len, const struct imdb_tz **out, imdb_err *e);
/* Frees the handle. IMDB_OK when every commit it acknowledged is durable: always
 * with sync on; under --nosync only if the closing fdatasync succeeded (a failed
 * handle skips it). IMDB_ERR_IO otherwise: --nosync commits since the last sync
 * may be lost in an OS crash. */
int imdb_close(imdb_db *db);

/* ---- schema --------------------------------------------------------------- */
/* A table with the default retention (IMDB_RETAIN_DEFAULT_US), or the one given; either is logged with it (op 16). */
int imdb_create_table(imdb_db *db, imdb_schema *s, imdb_err *e);
int imdb_create_table_ex(imdb_db *db, imdb_schema *s, uint64_t retention_us, imdb_err *e);
/* F2a: the same with column DEFAULTs (op 23 in its commit) */
int imdb_create_table_defs(imdb_db *db, imdb_schema *s, uint64_t retention_us, const struct imdb_coldef *defs,
                           uint16_t ndefs, imdb_err *e);
/* F2a-2: sequences (design.md §5, Sequences). CREATE SEQUENCE installs it at the statement (an undo removes it, op 24
 * at the commit); DROP SEQUENCE alone, refused while a column takes values from it; nextval hands out the next value
 * and puts the sequence in the transaction's set, whose marks its commit logs (op 26); setval in a commit of setvals,
 * in effect at once (an undo puts the state back) */
imdb_sequence *imdb_seq_by_name(imdb_db *db, const char *name);
int imdb_seq_install(imdb_db *db, const imdb_seqdef *d, uint64_t seq, imdb_err *e);
int imdb_create_sequence(imdb_db *db, imdb_seqdef *d, imdb_err *e);
int imdb_drop_sequence(imdb_db *db, imdb_sequence *s, imdb_err *e);
int imdb_seq_next(imdb_db *db, imdb_sequence *s, int64_t *out, imdb_err *e);
int imdb_txseq_load(imdb_db *db, const uint32_t *ids, uint32_t n, imdb_err *e); /* a parked transaction's set, active again */
int imdb_seq_set(imdb_db *db, imdb_sequence *s, int64_t v, bool called, imdb_err *e);
bool imdb_seq_mark_ok(const imdb_sequence *s, int64_t mark);
int imdb_seq_own(imdb_db *db, uint32_t table, const struct imdb_coldef *defs, uint16_t n, uint64_t seq, imdb_err *e);
void imdb_seq_drop_owned(imdb_db *db, uint32_t table, uint16_t pos, uint64_t seq);
int imdb_seq_apply(imdb_db *db, const imdb_op *o, uint64_t seq, imdb_err *e);
/* ALTER TABLE t SET RETENTION: logged in the transaction, in effect from its commit. */
int imdb_set_retention(imdb_db *db, imdb_table *t, uint64_t retention_us, imdb_err *e);
/* CREATE INDEX / DROP INDEX, each the only op of its transaction; names are unique per database;
 * a unique index is refused over live duplicates */
int imdb_create_index(imdb_db *db, imdb_table *t, const imdb_index_def *d, imdb_err *e);
int imdb_drop_index(imdb_db *db, const char *name, imdb_err *e);
/* the table holding index NAME and its position there, or NULL */
imdb_table *imdb_index_find(const imdb_db *db, const char *name, uint32_t *pos);
/* a definition's own rules, whatever its table: a name, known flags, 1..IMDB_MAX_INDEX_COLS
 * distinct columns of s, none a DECIMAL past 18 digits (F3e: D25) (the decoders' strictness and CREATE INDEX share it) */
bool imdb_index_def_ok(const imdb_index_def *d, const imdb_schema *s);
/* adds or removes a definition, kept sorted by name (shared by the commit path and replay) */
int imdb_index_add(imdb_table *t, const imdb_index_def *d, imdb_err *e);
void imdb_index_remove(imdb_table *t, uint32_t pos);
/* the structures: built at the end of an open (one sort each), caught up after each commit and
 * each applied commit, rebuilt after an ERASE or a purge (stubs and purged versions out, the old
 * runs wiped); a failure after a durable commit stops the handle (db->failed) */
int imdb_index_build_all(imdb_db *db, imdb_err *e);
void imdb_index_catch_up(imdb_db *db);
void imdb_index_rebuild_table(imdb_db *db, imdb_table *t);
/* After RETIRE dropped versions: the unique maps and the ordered structures keep what stays, by vid, reading no key
 * (what imdb_index_rebuild_table makes from the keys; a failure fails the handle, as the rebuild's does) */
void imdb_index_after_retire(imdb_db *db, imdb_table *t);
/* the value as one word of the structure's unsigned key (a TEXT's 8-byte prefix); false: NULL */
bool imdb_index_key_of(const imdb_value *v, uint64_t *key);
/* version vid's key in index ix, one word per column, a later column's NULL as 0; false: the first
 * column is NULL (not indexed) */
bool imdb_index_version_key(imdb_table *t, uint64_t vid, const imdb_index *ix, uint64_t *key);
/* a unique index's chains, built from the versions live now (CREATE UNIQUE INDEX, the replayed op,
 * a snapshot open, after ERASE and purges); IMDB_ERR_CONSTRAINT: two live versions share a key */
int imdb_index_unique_build(imdb_table *t, imdb_index *ix, imdb_err *e);
/* replay: a new row (its decoded values) whose key a live version holds already is IMDB_ERR_CORRUPT */
int imdb_index_unique_replay(imdb_table *t, const imdb_value *row, uint64_t seq, imdb_err *e);
uint64_t imdb_index_unique_bytes(const imdb_index *ix); /* for imdb_mem */
/* a live table by name (a dropped one is a tombstone: its name is free); imdb_table_at: the table a read at snapshot
 * snap sees by that name, dropped since or not (created at or before snap, dropped after it) */
imdb_table *imdb_table_by_name(imdb_db *db, const char *name);
imdb_table *imdb_table_at(imdb_db *db, const char *name, uint64_t snap);
/* DROP TABLE (op 19, 1f): in a transaction holding nothing else; retention_us, when not 0, is logged first (op 16:
 * DROP TABLE t RETENTION r), and a table kept FOREVER needs one, so its history can expire. The commit ends every
 * live version and makes the table a tombstone (imdb_table_drop_install, after its frame is durable) */
int imdb_drop_table(imdb_db *db, imdb_table *t, uint64_t retention_us, imdb_err *e);
/* ALTER TABLE (F1, op 22), alone in its transaction: proto's akind and payload (acol and adef, apos, aname), checked
 * against the table now; the next schema version from the commit */
int imdb_alter_table(imdb_db *db, imdb_table *t, const imdb_op *proto, imdb_err *e);
void imdb_table_drop_install(imdb_db *db, imdb_table *t, uint64_t seq);
/* each DROP_TABLE of ops: minus its table's lanes into delta (touched), beside imdb_digest_delta's */
void imdb_digest_drops(const imdb_db *db, const imdb_op *ops, uint32_t nops, uint32_t nt, imdb_lthash *delta, bool *touched);
imdb_table *imdb_table_by_id(imdb_db *db, uint32_t id);

/* P2 S7: views. imdb_view_by_name: a live view; imdb_view_at: the view a read at snapshot snap sees by that name
 * (created at or before snap, dropped after it); imdb_view_dependent: a live view naming the table or view (kind
 * IMDB_VIEWDEP_*), or NULL. Tables and views share one name space among the live ones. */
imdb_view *imdb_view_by_name(imdb_db *db, const char *name);
imdb_view *imdb_view_at(imdb_db *db, const char *name, uint64_t snap);
const imdb_view *imdb_view_dependent(const imdb_db *db, uint8_t kind, uint32_t id);
/* CREATE VIEW (op 20), alone in its transaction: def is taken, freed on a failure too; its id is assigned here. DROP
 * VIEW (op 21), alone: refused while a live view names it (DROP TABLE likewise). Each installs once its frame is
 * durable (imdb_view_install, imdb_view_drop_install: no allocation; replay calls them too) */
int imdb_create_view(imdb_db *db, imdb_viewdef *def, imdb_err *e);
int imdb_drop_view(imdb_db *db, imdb_view *v, imdb_err *e);

/* F3g: ENUM types. imdb_enum_by_name: a live type; imdb_enum_at: the type a read at snapshot snap sees by that name;
 * imdb_enum_def: type id's definition, a tombstone's too (NULL: no such id). CREATE TYPE (op 30), DROP TYPE (op 31) and
 * ADD VALUE (op 32), each alone in its transaction, install once their frame is durable (no allocation: ADD VALUE's
 * definition is made beforehand); DROP TYPE refused while a table, live or dropped and still retained, has a column of
 * it in any version of its history, or a live view names it (IMDB_VIEWDEP_TYPE). One name space with tables, views
 * and sequences; no built-in type's name */
imdb_enum *imdb_enum_by_name(imdb_db *db, const char *name);
imdb_enum *imdb_enum_at(imdb_db *db, const char *name, uint64_t snap);
const imdb_enumdef *imdb_enum_def(const imdb_db *db, uint32_t id);
bool imdb_enum_name_builtin(const char *name);
int imdb_create_enum(imdb_db *db, const char *name, const char *const *lab, const size_t *len, uint16_t n, imdb_err *e);
int imdb_drop_enum(imdb_db *db, imdb_enum *en, imdb_err *e);
int imdb_enum_add_value(imdb_db *db, imdb_enum *en, const char *lab, size_t len, bool if_not_exists, imdb_err *e);
int imdb_enum_cols_live(const imdb_db *db, const imdb_schema *s, imdb_err *e); /* each ENUM column names a live type */
int imdb_enum_apply(imdb_db *db, imdb_op *o, uint64_t seq, imdb_err *e); /* replay's ops 30 to 32, by the catalog's rules */
int imdb_enum_reserve(imdb_db *db, imdb_err *e);
void imdb_enum_install(imdb_db *db, imdb_enumdef *def, uint64_t seq);
void imdb_enum_drop_install(imdb_db *db, uint32_t id, uint64_t seq);
void imdb_enum_add_install(imdb_db *db, uint32_t id, imdb_enumdef *def, uint64_t seq);
/* a row's ENUM values against their types' labels (an ordinal past the count refused): every write's, replay's too */
int imdb_enum_row_check(const imdb_db *db, const imdb_schema *s, const imdb_value *vals, imdb_err *e);
/* F3g: an ordinal a label of type eid now; a CREATE's constant DEFAULTs (op 23) of ENUM columns labels; a history's every ENUM
 * DEFAULT (version 1's, an ADD's missing value, a SET DEFAULT's) a label at its version's commit (count: the labels then) */
bool imdb_enum_ord_ok(const imdb_db *db, uint32_t eid, int64_t ord);
int imdb_coldefs_enum_ok(const imdb_db *db, const imdb_schema *s, const imdb_coldef *defs, uint16_t n, imdb_err *e);
bool imdb_hist_enum_ok(const imdb_schema_hist *h, uint64_t created_at, uint16_t (*count)(const void *arg, uint32_t eid, uint64_t at),
                       const void *arg); /* version 1 at created_at (its since is 0) */
int imdb_view_reserve(imdb_db *db, imdb_err *e);
void imdb_view_install(imdb_db *db, imdb_viewdef *def, uint64_t seq);
void imdb_view_drop_install(imdb_db *db, imdb_view *v, uint64_t seq);
/* every dependency of def a live table or view of db (replay's and the writer's rule) */
bool imdb_view_deps_live(const imdb_db *db, const imdb_viewdef *def);
/* replay's and VERIFY's check of a view's text (sql_exec.c): bound against db's catalog now, it must yield def's
 * columns and dependencies exactly; IMDB_ERR_CORRUPT when it does not, or does not bind; a resource's error as it is */
int imdb_view_rebind(imdb_db *db, const imdb_viewdef *def, imdb_err *e);
/* F1: an ADD COLUMN's rule on the views: *name the first live view that reads table (directly or through views) and
 * whose text holds col as an identifier, NULL when none. A view keeps its text, not a bound tree, and views refuse *:
 * a name its text never holds cannot bind otherwise, but an added column of a name it holds could capture it (a bare
 * name made ambiguous, an outer reference of a subquery bound inside). imdb_sql_names_ident: whether text holds
 * ident as an identifier token (unquoted, folded to lowercase) */
int imdb_view_names_col(const imdb_db *db, uint32_t table, const char *col, const char **name, imdb_err *e);
int imdb_sql_names_ident(const char *text, size_t len, const char *ident, bool *out, imdb_err *e);

/* ---- F2b-1: CHECK constraints (design.md §5, CHECK constraints): bound and evaluated by the SQL layer (sql_exec.c) */
struct imdb_chkc; /* a table's live CHECKs compiled (imdb_table.chkc) */
void imdb_check_free(struct imdb_chkc *c);
/* text alone against schema s: a CHECK of the subset, IMDB_ERR_INVALID with the reason otherwise; *cols (when not
 * NULL) the columns it reads, a bit each */
int imdb_check_bind(const imdb_schema *s, const char *text, uint32_t len, uint64_t *cols, imdb_err *e);
/* a row (s's values, t's current schema) against t's live CHECKs by name: IMDB_ERR_CONSTRAINT at the first FALSE; an
 * evaluation's own error (an overflow, a zero divisor) as it is */
int imdb_check_row(imdb_db *db, imdb_table *t, const imdb_value *vals, imdb_err *e);
/* every live row of t against one CHECK (an ADD's): IMDB_ERR_CONSTRAINT at a FALSE */
int imdb_check_rows(imdb_db *db, imdb_table *t, const char *name, const char *text, uint32_t len, imdb_err *e);
struct imdb_xarena; /* F2c: sql_internal.h's, a statement's computed TEXT */
/* F2c, the tests': text as column c's generation expression of s (genmask: its generated columns) on nrows rows: out[r] 0
 * and vals[r] the value assigned (a TEXT in ar), 1 its evaluation failed, 2 its assignment */
int imdb_gen_eval_text(const imdb_schema *s, uint16_t c, uint64_t genmask, const char *text, uint32_t len, const imdb_value *rows,
                       uint32_t nrows, int *out, imdb_value *vals, struct imdb_xarena *ar, imdb_err *e);
/* the tests': text bound alone against s (its error), then evaluated on nrows rows of s's values (rows[r * ncols + c]):
 * out[r] 1 (TRUE or NULL), 0 (FALSE) or the evaluation's negative error code */
int imdb_check_eval_text(const imdb_schema *s, const char *text, uint32_t len, const imdb_value *rows, uint32_t nrows,
                         int *out, imdb_err *e);
/* a CREATE's CHECKs (op 28, a valid list by name), pushed after its CREATE (and its defaults) and installed at once */
int imdb_create_table_checks(imdb_db *db, uint32_t table, const imdb_check *c, uint16_t n, imdb_err *e);
/* version 1's CHECKs into a history (op 28, a manifest's version 1): copied, made the live ones */
int imdb_hist_create_checks(imdb_schema_hist *h, const imdb_check *c, uint16_t n, imdb_err *e);
/* the live CHECK of that name's index in h->chk, or -1 */
int imdb_hist_check(const imdb_schema_hist *h, const char *name);
/* the first live CHECK whose text holds ident as an identifier (a RENAME's or DROP COLUMN's rule), or NULL */
int imdb_checks_name_col(const imdb_schema_hist *h, const char *ident, const char **which, imdb_err *e);
/* F2b-2: a history's FOREIGN KEYs: a live one by name (its index, or -1); version 1's installed (op 29, a manifest's); the
 * first live one holding position pos, or NULL (DROP COLUMN's RESTRICT) */
int imdb_hist_fk(const imdb_schema_hist *h, const char *name);
int imdb_hist_create_fks(imdb_schema_hist *h, const imdb_fk *f, uint16_t n, imdb_err *e);
const char *imdb_fks_name_pos(const imdb_schema_hist *h, uint16_t pos);
/* F2c: the first live generated column but the one at position self whose expression holds ident, or NULL */
int imdb_gens_name_col(const imdb_schema_hist *h, const char *ident, uint16_t self, const char **which, imdb_err *e);
/* F2c: generated columns, computed and verified by the SQL layer (sql_exec.c): the expression at position's column c of
 * s (genmask: s's generated columns, which it may not name) bound alone, its value assignable to the column's type */
int imdb_gen_bind(const imdb_schema *s, uint16_t c, uint64_t genmask, const char *text, uint32_t len, imdb_err *e);
/* every generated column of t's row (vals, t's current schema) computed from the rest and assigned to its column, a
 * computed TEXT in ar (it lives as long as ar's mark) */
int imdb_gen_compute(imdb_db *db, imdb_table *t, imdb_value *vals, struct imdb_xarena *ar, imdb_err *e);
/* every generated column of the row holding the value its expression gives: IMDB_ERR_CONSTRAINT otherwise */
int imdb_gen_verify(imdb_db *db, imdb_table *t, const imdb_value *vals, imdb_err *e);
/* F2b-2 (fk.c, docs/fk-design.md): FOREIGN KEYs at run time: a table's child maps freed; a version added to them (its
 * values, the table's current columns) and taken out (an undone insert, an erased row: before its bytes are wiped); the
 * transaction's writes from op index from on checked against the current state (a statement's at its end, every one
 * at the commit): CONSTRAINT what it can see, CONFLICT what a commit after its snapshot did */
void imdb_fk_free(imdb_table *t);
int imdb_fk_index_add(imdb_db *db, imdb_table *t, uint64_t vid, const imdb_value *vals, imdb_err *e);
void imdb_fk_index_remove(imdb_db *db, imdb_table *t, uint64_t vid, const imdb_value *vals);
int imdb_fk_check(imdb_db *db, uint32_t from, imdb_err *e);
/* the catalog's rules of an FK (docs/fk-design.md section 2): the child's version now ccur, the parent's pcur (NULL: none) */
int imdb_fk_def_check(const imdb_sver *ccur, const imdb_sver *pcur, bool parent_live, const imdb_fk *f, imdb_err *e);
/* every live row of t referencing a live key of f's parent (an ADD FOREIGN KEY's scan): CONSTRAINT otherwise */
int imdb_fk_rows_check(imdb_db *db, imdb_table *t, const imdb_fk *f, imdb_err *e);
/* a live FK of another live table references table pid (DROP TABLE's RESTRICT); *which its name */
bool imdb_fk_referenced(const imdb_db *db, uint32_t pid, const char **which);
/* the live versions of child table c holding key k (the parent's primary key encoding) in its FK fki: *out allocated */
int imdb_fk_children(imdb_db *db, imdb_table *c, uint16_t fki, const imdb_value *k, uint64_t **out, uint32_t *n, imdb_err *e);
/* replay's check of a commit just applied (seq): referential integrity at its end, by its versions (CORRUPT) */
int imdb_fk_verify_commit(imdb_db *db, const imdb_commit_rec *c, uint64_t seq, imdb_err *e);
/* a CREATE's FOREIGN KEYs (op 29, a valid list by name), pushed after its CREATE (and its defaults and checks) */
int imdb_create_table_fks(imdb_db *db, uint32_t table, const imdb_fk *f, uint16_t n, imdb_err *e);
/* column c of t's current schema generated */
bool imdb_col_generated(const imdb_table *t, uint16_t c);

/* ---- transactions --------------------------------------------------------- */
int imdb_begin(imdb_db *db, imdb_err *e);
int imdb_commit(imdb_db *db, imdb_err *e);
/* Due work between transactions (the size-triggered CHECKPOINT). The SQL layer calls
 * it after each statement; engine-API callers call it between their transactions. */
int imdb_maintain(imdb_db *db, imdb_err *e);
void imdb_rollback(imdb_db *db);
/* Statement-level atomicity inside a transaction. */
typedef struct imdb_savepoint {
    uint32_t ntx;
    size_t nundo;
} imdb_savepoint;
imdb_savepoint imdb_savepoint_take(const imdb_db *db);
void imdb_savepoint_restore(imdb_db *db, imdb_savepoint sp);

/* ---- session transactions (docs/txn-design.md) --------------------------- */
/* Many sessions share one database and one engine thread. At most one
 * transaction is active: its uncommitted writes are pending versions in the
 * store (begin or end = seq + 1). The others keep their op lists saved and are
 * replayed (and so re-validated) when they next write or read their own writes.
 * A transaction sees committed data at its snapshot plus its own writes. */
enum { IMDB_ISO_SNAPSHOT = 0, IMDB_ISO_READ_COMMITTED = 1, IMDB_ISO_SERIALIZABLE = 2 }; /* E3: docs/e3-design.md */
enum { IMDB_TXN_READ = 0, IMDB_TXN_WRITE = 1 };

typedef struct imdb_saved_op {
    uint8_t code;              /* IMDB_OP_INSERT, IMDB_OP_DELETE or IMDB_OP_UPDATE */
    bool base_pending;         /* the base is one of the transaction's own pending versions */
    uint32_t table;
    uint64_t base;             /* DELETE / UPDATE: a vid, or the pending version's ordinal in its table */
    uint8_t salt[16];          /* INSERT / UPDATE: the new version's */
    uint8_t *row;              /* its canonical bytes (wiped when released) */
    uint32_t row_len;
} imdb_saved_op;

typedef struct imdb_txn_lock { /* SELECT ... FOR UPDATE: must still be live at commit */
    uint32_t table;
    uint64_t vid;
} imdb_txn_lock;

typedef struct imdb_txn_sp { /* SAVEPOINT: a position in the op list */
    char name[IMDB_MAX_IDENT + 1];
    uint32_t pos;
} imdb_txn_sp;

/* N1e stage two: a role's caps, the server's options (0: none), applied while its session's role is not a superuser (read
 * where each is checked, so an ALTER ROLE another session committed applies at once): the statement and transaction
 * timeouts, the idle-in-transaction bound, the rows a statement tests, its prepared statements' bytes. An embedded caller
 * and the CLI leave them zero */
typedef struct imdb_caps {
    uint32_t stmt_ms, txn_ms, idle_ms;
    uint64_t row_limit, prep_bytes;
    uint32_t slow_ms; /* 2b-2b: a role's slow-statement default (the session's slow_ms at its start; what a demoted superuser's
                       * SET slow_statement_ms returns to): its statements past it events in the log (0: none) */
} imdb_caps;

typedef struct imdb_txn {
    struct imdb_txn *next;     /* in db->txns */
    bool open, started, doomed;
    uint8_t iso;
    uint64_t snap;             /* the commit its first statement saw */
    uint64_t snap_us;          /* that commit's time: a table's expiry passes it once older than the retention */
    uint64_t stmt_snap;        /* the current statement's snapshot */
    imdb_saved_op *ops;        /* its op list while it is not active */
    uint32_t nops, capops;
    imdb_txn_lock *locks;
    uint32_t nlocks, caplocks;
    imdb_txn_sp *sps;
    uint32_t nsps, capsps;
    uint64_t begin_ns, last_ns; /* R4: its BEGIN and the end of its last statement (CLOCK_MONOTONIC) */
    uint64_t begin_us;          /* F2a: its BEGIN by imdb's clock (imdb_now_us): now() and the other clock values in it */
    uint32_t timeout_ms, idle_ms; /* SET transaction_timeout and idle_in_transaction_timeout at its BEGIN (0: none) */
    const imdb_caps *caps;     /* N1e stage two: its session's caps (NULL: none) and role, at its BEGIN: imdb_txn_expired reads
                                * the role's superuser attribute at each check */
    uint32_t role;
    bool busy;                 /* N1d: its session's statement is under way outside the engine (a COPY's data arriving through
                                * the server): never idle (idle_ms), its age (timeout_ms) still counted */
    uint32_t *seqs;            /* F2a-2: its sequences nextval touched, while it is not active (db->txseq when it is) */
    uint32_t nseqs;
    uint32_t rd[IMDB_MAX_TABLES / 32]; /* E3: SERIALIZABLE, the tables it read (by id; never shrunk: ROLLBACK TO keeps it) */
    bool rd_any;               /* it read a table: the commit's check has work to do */
    char doom[512];            /* why it can only roll back */
} imdb_txn;

void imdb_txn_begin(imdb_db *db, imdb_txn *x, uint8_t iso);
/* N1e stage two: a session's own value (0: none) held to its role's cap while the role is not a superuser now (caps NULL
 * or cap 0: the own value): the own value when set and within the cap, else the cap */
uint64_t imdb_cap_eff(const imdb_db *db, const imdb_caps *caps, uint32_t role, uint64_t own, uint64_t cap);
/* R4: x is past its transaction timeout, or idle past its limit, at now_ns (why says which; doomed or not); N1e stage
 * two: each held to its role's cap (imdb_cap_eff) */
bool imdb_txn_expired(const imdb_db *db, const imdb_txn *x, uint64_t now_ns, char *why, size_t n);
/* R4: x can only roll back (doomed with why, unless it already was), and what it holds goes now: the active one's
 * pending versions are undone, a parked one's saved writes and its locks freed; it stays open, so its session's next
 * statement fails and only ROLLBACK ends it */
void imdb_txn_expire(imdb_db *db, imdb_txn *x, const char *why);
/* R4: imdb_txn_expire for every open transaction but self past its limits: what a session that never comes back
 * held goes at any session's next statement */
void imdb_txn_timeouts(imdb_db *db, uint64_t now_ns, const imdb_txn *self);
/* Before each statement of x: takes the statement's snapshot and, for a write
 * (or a read of its own saved writes), makes x the active transaction.
 * IMDB_ERR_CONFLICT when x is doomed or a replay of its writes fails. */
int imdb_txn_enter(imdb_db *db, imdb_txn *x, int need, imdb_err *e);
/* Makes no transaction active (before autocommit writes, physical operations,
 * VERIFY and maintenance). */
int imdb_txn_park(imdb_db *db, imdb_err *e);
int imdb_txn_commit(imdb_db *db, imdb_txn *x, imdb_err *e);
void imdb_txn_rollback(imdb_db *db, imdb_txn *x);
bool imdb_txn_has_writes(const imdb_db *db, const imdb_txn *x);
/* A statement's view: snapshot, and the pending marker of its own writes (0: none). */
void imdb_txn_view(const imdb_db *db, const imdb_txn *x, uint64_t *snap, uint64_t *pend);
/* SELECT ... FOR UPDATE: locks the committed rows among vids (they must still be live). */
int imdb_txn_lock_rows(imdb_db *db, imdb_txn *x, const imdb_table *t, const uint64_t *vids, uint64_t n,
                       imdb_err *e);
/* After a committed ERASE: dooms every transaction whose saved writes or locks
 * name an erased version, and wipes its saved row bytes at once. */
void imdb_txn_doom_erased(imdb_db *db, const imdb_erase_ent *ents, uint32_t n, uint64_t seq);
/* After a RETIRE below boundary: dooms every transaction whose snapshot is at or below it (every table's
 * horizon is past it, so none of its reads could be answered). */
void imdb_txn_doom_retired(imdb_db *db, uint64_t boundary);
/* DROP TABLE (1f): every open transaction that wrote or locked rows of the table is doomed at its install */
void imdb_txn_doom_dropped(imdb_db *db, uint32_t table, uint64_t seq);
void imdb_txn_doom_altered(imdb_db *db, uint32_t table, uint64_t seq); /* F1: those that wrote or locked it */
/* After a statement of x lost a write-write race: it can only roll back. */
void imdb_txn_doom(imdb_txn *x, const char *why);
/* A doomed transaction drops its writes at once (pending versions undone and wiped, saved
 * row copies released): they can never commit, and no copy of a row should outlive its
 * purpose. It stays open, and doomed, until ROLLBACK or COMMIT. */
void imdb_txn_discard(imdb_db *db, imdb_txn *x);
/* SAVEPOINT name; ROLLBACK TO name (undoes the writes after it, keeps it); RELEASE name
 * (forgets it and every later one, keeps the writes). A doomed transaction stays doomed. */
int imdb_txn_savepoint(imdb_db *db, imdb_txn *x, const char *name, imdb_err *e);
int imdb_txn_rollback_to(imdb_db *db, imdb_txn *x, const char *name, imdb_err *e);
int imdb_txn_release(imdb_db *db, imdb_txn *x, const char *name, imdb_err *e);

/* DML (inside a transaction). New versions get begin = seq+1 (pending). */
int imdb_insert(imdb_db *db, imdb_table *t, const imdb_value *vals, imdb_err *e);
int imdb_delete(imdb_db *db, imdb_table *t, uint64_t vid, imdb_err *e);
int imdb_update(imdb_db *db, imdb_table *t, uint64_t vid, const imdb_value *vals, imdb_err *e);
/* The same with the new version's salt given (imdb_salt_next's); NULL draws one alone. */
int imdb_insert_salt(imdb_db *db, imdb_table *t, const imdb_value *vals, const uint8_t salt[16], imdb_err *e);
int imdb_update_salt(imdb_db *db, imdb_table *t, uint64_t vid, const imdb_value *vals, const uint8_t salt[16], imdb_err *e);

/* A statement's salts: one getrandom seeds ChaCha20 (nonce "IMDBSALT" and four zeros), each block
 * gives four 16-byte salts. Salts must be unpredictable (they hide a row's commitment) and an erased
 * row's must be gone for good, so the seed lives only while its statement runs and is wiped when
 * it ends (imdb_salts_wipe); a resumed transaction's next statement draws its own. Zeroed: unseeded. */
typedef struct imdb_salts {
    uint8_t seed[32], block[64];
    uint32_t ctr;  /* the next block */
    uint8_t taken; /* salts taken from block */
    bool seeded;
} imdb_salts;
int imdb_salt_next(imdb_salts *s, uint8_t out[16], imdb_err *e);
void imdb_salts_wipe(imdb_salts *s);

/* ---- reads ---------------------------------------------------------------- */
static inline bool imdb_visible(const imdb_version *v, uint64_t snap)
{
    return !(v->flags & (IMDB_V_STUB | IMDB_V_PURGED)) && v->begin <= snap && snap < v->end;
}
/* The same for a reader whose own pending versions carry the marker pend (seq + 1
 * inside its transaction; 0 for none): born by snap or its own pending insert, and
 * alive at snap unless the reader itself has ended it. */
static inline bool imdb_visible_at(const imdb_version *v, uint64_t snap, uint64_t pend)
{
    if (v->flags & (IMDB_V_STUB | IMDB_V_PURGED)) return false;
    bool born = v->begin <= snap || (pend && v->begin == pend);
    return born && snap < v->end && !(pend && v->end == pend);
}
/* Snapshot for reads issued by this session (sees its own pending writes). */
uint64_t imdb_read_snapshot(const imdb_db *db);
/* Values of a version. A TEXT value points into the memtable or a segment's image: it stays valid until the next
 * statement, write or commit (any operation, stage 3c-1: the outermost one's end may drop the image; a write may move
 * the memtable). Copy what is kept longer, as a query's result does. A read itself drops nothing. */
int imdb_version_values(imdb_db *db, imdb_table *t, uint64_t vid, imdb_value *vals, imdb_err *e);
/* A held version's values, by its entry (imdb_vh): a walk over the held (imdb_v_next) has it already */
int imdb_version_values_v(imdb_table *t, const imdb_version *v, imdb_value *vals, imdb_err *e);
/* Version of key visible at snap, or IMDB_NONE (and IMDB_NONE when the lake's image could not be had below the memory
 * floor: the handle then stops, db->failed; this is the API's convenience, the engine's paths take imdb_lookup_pk_at). */
uint64_t imdb_lookup_pk(imdb_db *db, imdb_table *t, const imdb_value *key, uint64_t snap);
/* The same as seen by a reader with pending end pend; *vid IMDB_NONE when none; negative (e) when a lake image could
 * not be had (stage 3c-1) */
int imdb_lookup_pk_at(imdb_db *db, imdb_table *t, const imdb_value *key, uint64_t snap, uint64_t pend, uint64_t *vid,
                      imdb_err *e);
/* All versions ever recorded for a subject value (index path). */
const imdb_vlist *imdb_subject_versions(imdb_table *t, const imdb_value *subject);
/* Required before a snapshot read (including low-level C lookup/scan calls):
 * checks the purge horizon and refuses failed or unauthorised replica state. */
int imdb_check_history(const imdb_db *db, const imdb_table *t, uint64_t snap, imdb_err *e);
/* Commit seq in effect at a wall-clock time (0 = before the first commit). */
int imdb_seq_at_time(imdb_db *db, uint64_t time_us, uint64_t *seq, imdb_err *e);
/* Commit seq's time, hash and digest; loads the older part of the index on demand. */
const imdb_commit_info *imdb_ci_at(imdb_db *db, uint64_t seq, imdb_err *e);
int imdb_ci_load_all(imdb_db *db, imdb_err *e);

/* ---- erasure -------------------------------------------------------------- */
typedef struct imdb_erase_report {
    uint64_t versions;        /* versions erased (all history)             */
    uint64_t live_deleted;    /* of which were live and got deleted        */
    uint32_t tables;
    uint32_t segments_rewritten;
    bool redaction_pending;   /* committed; physical rewrite deferred (see db->warning) */
    uint32_t role_entries;    /* L stage 2: ERASE ROLE's names and verifiers erased (0: a known role with nothing left) */
    uint32_t roles_removed;   /* of the roles reached, dropped ones erased whole (the catalog holds them no more) */
} imdb_erase_report;
/* ERASE SUBJECT: every version, in every table with a SUBJECT column of the
 * value's type, whose subject equals the value. */
int imdb_erase_subject(imdb_db *db, const imdb_value *subject, imdb_erase_report *rep, imdb_err *e);
/* ERASE an explicit set of versions (sorted, unique (table, vid)). */
int imdb_erase_versions(imdb_db *db, imdb_erase_ent *ents, uint32_t n, imdb_erase_report *rep, imdb_err *e);
/* L stage 2: ERASE ROLE name (docs/roles-design.md §11): the live role of the name, its earlier names and verifiers;
 * every dropped role whose last name it was, everything it holds. Outside a transaction; a name no role holds is an
 * error; nothing to erase commits nothing */
int imdb_erase_role(imdb_db *db, const char *name, imdb_erase_report *rep, imdb_err *e);

/* ---- replication ---------------------------------------------------------- */
/* Writes every frame with seq > after_seq to fd. follow: keep polling. */
int imdb_ship(const char *path, uint64_t after_seq, int fd, bool follow, imdb_err *e);
/* ackfd >= 0 (ship --acks): the replica's acknowledgements arrive on it, each checked against this log and
 * recorded (repl.h); one that is refused (a divergence among them) ends the shipping with its error. */
typedef struct imdb_ship_opts {
    bool follow;
    int ackfd;
    uint32_t keepalive_ms; /* R1.2: with follow and ackfd, a keep-alive (repl.h) once nothing was sent for this long; 0:
                            * none */
} imdb_ship_opts;
int imdb_ship_ex(const char *path, uint64_t after_seq, int fd, const imdb_ship_opts *o, imdb_err *e);
/* What a shipping sent (imdb_ship_to). */
typedef struct imdb_ship_result {
    uint64_t seeded;          /* a seed was sent (the log cut below commit 1), taken at this commit: the stream ended there */
    uint8_t seeded_hash[32];  /* that commit's hash */
    uint64_t last_seq;        /* the last commit sent (0: none) */
    uint8_t last_hash[32];
    bool cut;                 /* refused: the log before what was asked for is cut here (the replica must be seeded) */
    uint64_t alives;          /* R1.2: the keep-alives sent */
} imdb_ship_result;
/* imdb_ship_ex into a sink (stream.h: a backup's sealing writer), reporting what it sent (res may be NULL). */
int imdb_ship_to(const char *path, uint64_t after_seq, const imdb_sink *out, const imdb_ship_opts *o,
                 imdb_ship_result *res, imdb_err *e);
/* Applies frames read from fd; returns after EOF. *applied gets the durable
 * prefix count, even on error. EOF before redaction authorisation returns
 * IMDB_ERR_AUTH; resume from db->seq, and do not read until authorisation is
 * complete. A read-only handle is never writable through this interface. */
int imdb_apply_stream(imdb_db *db, int fd, uint64_t *applied, imdb_err *e);
/* As imdb_apply_stream, with acknowledgement points: once the stream has no more bytes ready (and at
 * least every 64 commits, and at its clean end) everything applied is made durable, then applied(ctx,
 * db) runs (db->seq is durable; imdb_cleanup_seq says what is cleaned up). A nonzero return stops the
 * apply with that error. truncated: the stream ended inside a frame, or before an ERASE authorised
 * its redactions (a dropped connection: the next stream resumes it). A stream from ship --acks
 * begins with a session record (repl.h): its challenge is in nonce (has_session) before the first
 * point, and a point runs right after it, before any frame (where this replica stands). */
typedef int (*imdb_applied_fn)(void *ctx, imdb_db *db);
typedef struct imdb_apply_opts {
    imdb_applied_fn applied;
    void *ctx;
    uint32_t every; /* a point at least every this many commits (0: 64; 1: after each, as the fault tests need) */
    bool truncated; /* out */
    bool has_session; /* out */
    uint8_t nonce[16]; /* out */
    uint64_t seeded; /* out: the stream was a seed, taken at this commit (seed.h): the handle is stale, reopen */
    uint64_t until_seq, until_time; /* point-in-time (a restore's --until, P0 backup slice 2): apply stops before a commit
                                     * past this one, or one made after this time (microseconds; commit times rise); 0: none */
    bool stopped; /* out: it stopped there, as at a stream's end (the state checked, a point made) */
    uint32_t silent_ms; /* R1.2: past its session record, a stream that sends nothing for this long is a dropped connection
                         * (truncated, and silent): its shipper sends a keep-alive every second (repl.h); 0: it waits */
    bool silent; /* out: it was */
} imdb_apply_opts;
int imdb_apply_stream_ex(imdb_db *db, int fd, uint64_t *applied, imdb_apply_opts *o, imdb_err *e);
/* imdb_apply_stream_ex from a caller's source (stream.h; its end is the stream's): a source cannot tell whether more is
 * ready now, so its points come every o->every commits and at its end (a restore's). */
int imdb_apply_source(imdb_db *db, imdb_read_fn read, void *ctx, uint64_t *applied, imdb_apply_opts *o, imdb_err *e);
/* The last commit through which physical cleanup is complete: every ERASE up to it has left this
 * directory's files (the log redacted, the lake rewritten and published, the old objects removed;
 * free disk blocks may still hold the bytes, until crypto-shredding, deferred.md R6). */
uint64_t imdb_cleanup_seq(imdb_db *db);

/* ---- the memory budget (deferred.md R4) --------------------------------------
 * What the database holds in memory, by kind, from the capacities its structures hold (allocated,
 * so at least what is resident): version arrays, memtable rows, the PK and subject indexes (TEXT
 * key copies too), the segments held in memory, the commit index, the transaction's undo log and
 * ops, and the saved session transactions. With a budget (imdb_open_opts.mem_limit), a write on
 * the primary that would grow a structure past it is refused at that growth step (a capacity
 * doubling counts whole), before anything is logged, and so is a commit that would grow the
 * commit index; nothing else is refused: an open, replay, CHECKPOINT, COMPACT and ERASE (the ways
 * down) never are. A replica over its budget refuses its next commit before applying it (its
 * state stays consistent), until the budget is raised. Results have their own cap
 * (IMDB_MAX_RESULT_BYTES, a quarter of the budget when there is one). */
typedef struct imdb_mem_report {
    uint64_t versions, rows, indexes, segments, commits, txns, prepared, total, limit, reserve; /* reserve: db->mem_reserve;
                                                                     * prepared: every session's (P2 S9) */
    /* the segment cache (stage 3c-1): its images' bytes (in segments), its budget, the images loaded since the open and
     * the object bytes read for them */
    uint64_t seg_images, seg_budget, seg_loads, seg_load_bytes;
} imdb_mem_report;
void imdb_mem(const imdb_db *db, imdb_mem_report *r);
/* D8 #2: a query's default workspace (SET statement_memory 0): a quarter of the budget, at most IMDB_MAX_RESULT_BYTES (that,
 * without a budget). With a budget, writes leave as much of it free (db->mem_reserve: imdb_mem_admit refuses a write
 * past the budget less it), so the store and one query's workspace fit in the budget together */
uint64_t imdb_query_share(uint64_t mem_limit);

/* ---- the memory window (stage 3b) --------------------------------------------------------------
 * A copy keeps in memory every version live, ended within its window (imdb_open_opts.mem_window_us), or not yet in a
 * segment; an older one leaves the store and every index, and the lake answers for it: a read at a snapshot below
 * the floor (db->mem_floor), or of ALL VERSIONS, goes to the lake (the segments and the memtable; sql_exec.c), so
 * nothing anyone reads and nothing derived depends on what was evicted. The policy, between transactions, moves the
 * floor to the end of a log segment at least the window old once enough versions have ended; imdb_evict moves it
 * (tests too): every held version ended at or before floor, in a segment and not awaiting its ERASE, leaves memory.
 * A table whose new structures cannot be made keeps what it holds (the error says so) and the floor moves anyway:
 * every version ended past it is held either way. A no-op inside a transaction. */
int imdb_evict(imdb_db *db, uint64_t floor, imdb_err *e);

/* ---- recovery (imagedb recover) -------------------------------------------- */
typedef struct imdb_recover_report {
    bool damaged;             /* the last segment ends in a damaged or incomplete frame */
    bool acked_lost;          /* a synced DURABLE says commits past the intact end were acknowledged */
    bool applied;             /* the tail was discarded (apply) */
    uint64_t last;            /* the last intact commit */
    uint64_t durable;         /* DURABLE's commit (0 when absent) */
    bool have_durable;
    bool durable_ignored;     /* DURABLE was malformed: treated as absent, as an open does */
    bool durable_synced;      /* it names a synced commit (not a --nosync record) */
    bool durable_strict;      /* and was synced before that commit was acknowledged (--durable-ack) */
    bool maybe_acked;         /* the damage is a complete frame past a watermark that may lag: an
                                 acknowledged commit, or an append that never finished */
    bool lake_ahead;          /* LAKE_HEAD names a commit past the intact log (apply: it is removed) */
    uint64_t lake_seq;        /* that commit */
    uint64_t segment, offset; /* where the damage starts: segment (first seq) and byte offset */
    uint64_t bytes;           /* bytes from there to the end of the segment */
    char what[256];
} imdb_recover_report;
/* Inspects the end of the log; with apply, the operator's explicit decision to
 * discard it: the bytes go to save_path first (created, never overwritten), then
 * the segment is cut at the last intact commit and DURABLE lowered to it. Only a
 * damaged END is handled (damage followed by data is refused: restore that
 * segment from a replica). Takes the writer lock. */
int imdb_recover_tail(const char *path, bool apply, const char *save_path, imdb_recover_report *r, imdb_err *e);

/* ---- verification ---------------------------------------------------------- */
typedef struct imdb_verify_report {
    uint64_t commits;
    uint64_t versions;
    uint64_t live;
    uint64_t stubs;
    uint64_t pending_auth;
    uint64_t payload_rows_checked;
    uint64_t segments_checked;
    uint64_t lake_rows_checked;
    uint64_t sigs_checked;    /* Ed25519 commit signatures verified */
    uint64_t floor;           /* the log floor VERIFY began at (0: the genesis) */
    uint64_t seeded;          /* versions it took from the lake at the floor, checked against the floor's digests */
    uint64_t erase_below_floor; /* ERASE entries for versions the floor's RETIRE dropped: their commitments unknowable */
    double t_read, t_par, t_log, t_state, t_lake; /* seconds: reading, parallel stages, ordered stage, engine, lake */
    uint8_t head[32];
    uint8_t digest[32];
    char note[256];
    bool iceberg;             /* F5c: an Iceberg layer stood for the head and this location, and was the one the lake gives */
    bool iceberg_stale;       /* F5c: one stood for another head or location: not checked, reported */
} imdb_verify_report;
/* Independent re-verification of the on-disk log against the open state:
 * framing, chain, MACs, commitments, per-commit digests, erasure
 * authorisation and completeness, then the lake (segments, manifest). */
int imdb_verify(imdb_db *db, imdb_verify_report *rep, imdb_err *e);

/* Digest (32 bytes) of one table, or of all tables when t == NULL. */
void imdb_state_digest(const imdb_db *db, const imdb_table *t, uint8_t out[32]);
/* The view token: SHA-256("IMDBVIEW3" || db id || u64 seq || head || u32 tables || for each table in
 * id order: u32 id || u32 schema length || its encoding || u64 horizon || u64 live || u64 created || u64 dropped
 * (0: live) || LtHash lanes) || u32 views || for each view in id order (P2 S7): u32 id || u32 name length || its name ||
 * u64 created || u64 dropped (0: live) || a live one's definition's SHA-256 (imdb_viewdef_encode, log.h)).
 * Equal tokens: the same database, chain position, schemas, horizons and rows (a digest alone says
 * nothing about which database or history). imagedb-audit identity computes it from files. */
int imdb_view_token(const imdb_db *db, uint8_t out[32], imdb_err *e);
/* LtHash over versions visible at snap (recomputed from scratch). */
int imdb_recompute_digest(imdb_db *db, imdb_table *t, uint64_t snap, imdb_lthash *out, imdb_err *e);

/* Internal hooks shared with lake.c */
int imdb_log_append(imdb_db *db, const uint8_t *frame, size_t len, imdb_err *e);
/* Tests only: the engine's clock (commit times, expiry) moved by us from the wall clock's; reset to 0
 * before every test. */
void imdb_clock_offset(int64_t us);
/* Tests only: the engine's clock reads us, frozen, until imdb_clock_freeze(0) (reset before every test): a test whose
 * margins are measured on the clock steps it itself (a commit still takes the last commit's time + 1 at the least), so
 * no margin depends on how long a step took (retain_floor_carry, retain_retire_replica: 2026-11-06, a loaded machine) */
void imdb_clock_freeze(uint64_t us);
uint64_t imdb_clock_frozen(void); /* tests: the frozen base (0: the wall clock); imdb_clock_offset moves a frozen clock too */
/* In an open transaction: an EXPIRE of table to the horizon before (log.h). Expiry's (db.c), which
 * chooses before by the rule VERIFY checks; tests commit ones that break it. */
int imdb_expire_op(imdb_db *db, uint32_t table, uint64_t before, imdb_err *e);
int imdb_redact_log(imdb_db *db, imdb_err *e);
/* Records that the payload written by commit seq must be redacted. */
int imdb_redact_note(imdb_db *db, uint64_t seq, imdb_err *e);
int imdb_sync_dir(int dirfd, imdb_err *e);
/* P1 M1: the bytes of log/'s and objects/'s regular files (SHOW STATS: storage on disk) */
int imdb_disk_bytes(imdb_db *db, uint64_t *log, uint64_t *lake, imdb_err *e);

/* P1 M1: every SHOW STATS row, in order, the export's too (one list, so the two never differ): fn's nonzero stops the
 * walk and is returned. walk_disk: list log/ and objects/ now (SHOW STATS), else the export's last walk */
typedef int (*imdb_stat_fn)(void *ctx, const char *name, int64_t value);
int imdb_stats_each(imdb_db *db, imdb_stat_fn fn, void *ctx, bool walk_disk);
/* P1 M1: the export (imdb_open_opts.stats_path): every row as `name value` lines with the writer's pid and time and a
 * CRC32C last, rewritten in place, never fsynced, advisory (a reader takes a torn copy by its CRC and reads again); at
 * most once a second unless force; from a fixed buffer; never an error: a failed write is counted and tried again */
void imdb_stats_tick(imdb_db *db, bool force);
/* P1 M1: a data directory's cheap health (imagedb health): META and DURABLE read and checked, and no replica incident
 * recorded (replicas/NAME.diverged); no open, no replay */
int imdb_health_dir(const char *path, imdb_err *e);

/* P1 M2: the event log (imdb_open_opts.events_path): JSON lines, one an event, appended whole under events_lock,
 * never synced, advisory (a failed append is counted, never an error), FILE.1 past events_cap. An event is begun,
 * given fields (keys are the engine's own words; strings are escaped: quotes, backslashes, control bytes, and invalid
 * UTF-8 as U+FFFD, cut between sequences to fit), and ended; with no log they cost a test of events_fd. Never a row
 * value: engine messages carry none, and a slow statement's text is its shape (imdb_sql_shape). */
void imdb_event_begin(imdb_db *db, const char *ev);
void imdb_event_int(imdb_db *db, const char *key, int64_t v);
void imdb_event_str(imdb_db *db, const char *key, const char *s, size_t n);
void imdb_event_end(imdb_db *db);
/* P1 M2: the open's progress (phase, done of total): the opener's callback and an event, at most once a second from the
 * open's start, and at the end (last) of a phase that reported */
void imdb_progress(imdb_db *db, const char *phase, uint64_t done, uint64_t total, bool last);
extern uint64_t imdb_progress_every_ns; /* a second; tests lower it */
/* P1 M2: the handle failed: its event, once (a statement's end, a refused statement, the close) */
void imdb_event_failed(imdb_db *db, const char *reason);

void imdb_event_maint(imdb_db *db, int k, uint64_t ns); /* P1 M2: its event (db.c) */
/* P1 M1: a maintenance op of kind k that began at t0 (imdb_mono_ns) has ended: its count and time */
static inline void imdb_stats_maint(imdb_db *db, int k, uint64_t t0)
{
    uint64_t d = imdb_mono_ns() - t0;
    db->stats.maint_n[k]++;
    db->stats.maint_ns[k] += d;
    db->stats.maint_last_ns[k] = d;
    if (d > db->stats.maint_max_ns[k]) db->stats.maint_max_ns[k] = d;
    imdb_event_maint(db, k, d); /* P1 M2 */
}

#endif
