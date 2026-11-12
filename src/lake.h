/*
 * The lake: immutable columnar segments, deletion vectors and manifests,
 * all content-addressed (file name = SHA-256 of the bytes) and written in one
 * canonical encoding, so the same logical content always produces the same
 * bytes on the primary, on every replica, and in any re-encoding.
 *
 * Segment ("IMDBSEG1", version 3: F1 stage 4), little-endian:
 *   header (64 B): magic[8] u32 version (3) u32 table version_hash[32] (imdb_sver_hash: the schema version that built
 *                  it, its encoding and positions) u32 nrows
 *                  u32 ncols u32 nsections u32 reserved
 *   directory: nsections x { u32 kind, u32 col, u64 offset, u64 length }
 *   sections in canonical order, each 8-byte aligned, zero padding:
 *     VID u64[n] | BEGIN u64[n] | FLAGS u8[n] | SALT [16]u8[n] | COMMIT [32]u8[n] |
 *     per column: I64 i64[n] (INT64, DECIMAL, TIMESTAMP, FLOAT64 keys)  or  U8 u8[n]  or
 *       TEXT_OFF u32[n+1] + TEXT_DATA, then for a NULLABLE column VALID u8[ceil(n/8)]
 *       (bit i: row i has a value; padding zero) |
 *     ZONEMAP ncols x { u8 has, u8 has_null, pad[6], i64 min, i64 max } over the flag-0 rows,
 *       min/max over their values (NULLs excluded)
 *   Row flags: 0 a version with its data; 1 (stub) erased: vid, begin, commitment only;
 *   2 (purged) dropped by COMPACT ... PURGE: vid, begin, commitment and the SUBJECT value
 *   (so ERASE SUBJECT still finds purged history, whose payloads remain in the log);
 *   3 purged and erased: vid, begin, commitment only. Every column a row does not keep is
 *   zero (TEXT: empty) with its VALID bit clear, a NULL is zero data with its VALID bit clear,
 *   salt is zero for every flagged row, zone maps cover flag-0 rows only.
 *   Every version of a table is in exactly one segment of the manifest.
 *
 * Deletion vector ("IMDBDV01"): seg_hash[32] u32 count u32 0 | count x { u32 row, u32 0, u64 end }
 * Manifest ("IMDBMAN1"): u32 version (8) u32 nsections (11) db_id[16] u64 seq prev_hash[32] state_digest[32]
 *   prev_manifest[32] (the generation GC keeps beside this one; zero for the first manifest and
 *   after an ERASE, which keeps nothing) u64 boundary (the commit at or below which the log is retired; 0: none)
 *   then nsections sections, each u32 kind | u64 length | its bytes, the kinds 1 to 11 in order, each once (the format
 *   design, docs/format-design-v7.md section 8):
 *   1 tables: u32 ntables, then per table:
 *              u32 len | schema | u64 horizon | u64 live | u64 versions | lthash[2048] |
 *              u32 nseg | nseg x { seg_hash[32], dv_hash[32] (zero = none), u32 nrows } |
 *              u32 nidx | nidx x { u8 len | name | u8 flags | u8 ncols | ncols x u16 column } (names
 *              strictly increasing per table and unique across tables) | u64 retention_us (op 16) |
 *              u64 created_at | u64 dropped_at (version 5, 1f: the commits that created and dropped it; 0: live)
 *   2 views: u32 nviews, each view by id (u32 id | u8 len | name | u64 created_at | u64 dropped_at | a live one's
 *     definition, log.h imdb_viewdef);
 *   3 sequences, 4 enums, 5 roles, 6 grants, 7 the replica set, 8 partition specs, 9 materialized views, 10 procedures,
 *     11 triggers: each u32 0 until its slice fills it (a non-zero count is a later format's: refused);
 *   nothing after the last. Versions 2 to 7 are refused by name (no reader before the freeze; 7 named its segments'
 *   versions by the schema alone, F1 stage 4).
 * LAKE_HEAD: "imagedb-lake 1\nseq <n>\nmanifest <64 hex>\n"
 */
#ifndef IMDB_LAKE_H
#define IMDB_LAKE_H

/* a manifest's sections (since version 7), in their order (above) */
enum {
    IMDB_MAN_TABLES = 1,
    IMDB_MAN_VIEWS,
    IMDB_MAN_SEQUENCES,
    IMDB_MAN_ENUMS,
    IMDB_MAN_ROLES,
    IMDB_MAN_GRANTS,
    IMDB_MAN_REPLICA_SET,
    IMDB_MAN_PARTITIONS,
    IMDB_MAN_MATVIEWS,
    IMDB_MAN_PROCEDURES,
    IMDB_MAN_TRIGGERS,
    IMDB_MAN_SECTIONS = IMDB_MAN_TRIGGERS,
};

#include "db.h"

enum {
    SEG_VID = 1, SEG_BEGIN = 2, SEG_FLAGS = 3, SEG_SALT = 4, SEG_COMMIT = 5,
    SEG_I64 = 16, SEG_U8 = 17, SEG_TEXT_OFF = 18, SEG_TEXT_DATA = 19, SEG_VALID = 20,
    SEG_ZONEMAP = 32,
};

#define IMDB_SEG_HEADER 64u
#define IMDB_SEG_VERSION 3u /* F1 stage 4: the header names its schema version by imdb_sver_hash (2: by the schema alone) */
#define IMDB_MANIFEST_VERSION 18u /* L: roles and grants (sections 5 and 6 filled); 17 before them (F3g: ENUM types, the
                                   enums section, ENUM columns); 16 before those (F3f: INTERVAL columns,
                                   16-byte cells and DEFAULTs); 15 before those (F3e: DECIMAL columns to 38
                                   digits, a wide one's 16-byte cells); 14 before those (F3d: UUID and
                                   BYTEA columns and op 23's kind 10 (gen_random_uuid) in version 1's
                                   DEFAULTs (13 before them: F2b-2, version 1's FOREIGN KEYs; 12: F2c, a CREATE's generated
                                   columns; 11: F2b-1, version 1's CHECKs; 10: F2a-2, the sequences section; 9: F2a, a
                                   CREATE's DEFAULTs; 8; 7: segment format 2); 2 to 16 refused by name (old_manifest) */
#define IMDB_SEG_STUB 1u   /* erased: vid, begin and commitment only */
#define IMDB_SEG_PURGED 2u /* purged by COMPACT ... PURGE: vid, begin, commitment and the SUBJECT value */

typedef struct imdb_segcol {
    const int64_t *i64;      /* INT64 / DECIMAL / TIMESTAMP */
    const uint8_t *u8;       /* BOOL */
    const uint32_t *off;     /* TEXT offsets (n+1) */
    const uint8_t *data;     /* TEXT bytes */
    const uint8_t *valid;    /* NULLABLE: bit i set = row i has a value; NULL for NOT NULL columns */
    bool is_cst;             /* F1: a column the segment lacks: every row reads cst (its missing value), no array set */
    imdb_value cst;          /* its TEXT bytes the table's (imdb_tcol.missing_text), never the image's */
} imdb_segcol;

typedef struct imdb_segzone { /* a column's zone map, kept with the descriptor: a scan skips a segment without its image */
    bool has;                /* a data row with a value */
    bool has_null;           /* a data row that is NULL */
    int64_t min, max;
} imdb_segzone;

/* A segment's IMAGE (stage 3c-1): the file and the views into it, the per-row end times and the stubmask, all that grows
 * with its rows. Reached only through imdb_seg_pin, which pins it for the current operation (a statement, an engine
 * call, a commit's apply, VERIFY, a publish): a pointer into it (a TEXT value) stays valid until that operation ends. */
typedef struct imdb_segimg {
    uint8_t *bytes;          /* owned file image; views point into it */
    size_t len;
    const uint64_t *vid;
    const uint64_t *begin;
    const uint8_t *flags;
    const uint8_t *salt;     /* 16 bytes per row */
    const uint8_t *commit;   /* 32 bytes per row */
    imdb_segcol col[IMDB_MAX_COLS];
    uint64_t *end;           /* mutable: end seq per row (IMDB_LIVE) */
    uint64_t *stubmask;      /* bit i set iff row i is flagged, a stub or a tombstone: no values (immutable) */
    /* F1: col[] is laid out for the table's version `laid`, in its compact order: a position the file carries points
     * into its sections (ocol[], the file's own layout, under version gver, which built it), one it lacks is a
     * constant (is_cst: no memory, nothing to fail); imdb_seg_pin lays it out again when laid is not the table's last
     * version. Every row a segment holds predates any position it lacks, so the constant is what each one reads.
     * A re-layout never meets a reader of the old one: a table's versions grow only at an ALTER's install, alone in
     * its commit on the engine thread (one serves every session) with no walk open, and an operation's first pin of
     * the image after it lays it out under the cache's lock before any worker reads col[]. */
    imdb_segcol ocol[IMDB_MAX_COLS];
    uint32_t gver, laid;
} imdb_segimg;

/* A segment's DESCRIPTOR: what stays resident whatever the retention (a few hundred bytes); its image is img_ (NULL:
 * not in memory), read only by imdb_seg_pin and imdb_seg_resident (stage 3c-1: loaded on a pin, dropped by a trim). */
typedef struct imdb_segment {
    uint8_t hash[32];
    uint32_t table;
    uint32_t nrows;
    uint64_t vid_first, vid_last; /* its rows' vids, the first and the last: rows are in vid order */
    uint32_t gver;           /* F1: the schema version that built it (its zone[] is in that version's compact order) */
    uint32_t ndata;          /* F1: its rows with values (flag 0): what reads a column it lacks (imdb_seg_zone) */
    imdb_segzone zone[IMDB_MAX_COLS];
    uint8_t dv_hash[32];     /* deletion vector at the last manifest (zero if none) */
    uint64_t touched;        /* the cache's clock at its last pin: a trim drops the least recent first */
    bool ondisk;             /* its object and its deletion vector's are in objects/: the image may leave memory
                                and load again (loaded from disk, or written by the publish; a new one is not) */
    bool seg_ondisk;         /* its .seg object is in objects/ (loaded from it, or put by physical_commit before its
                                commit, or by lake_persist); never cleared: a descriptor's bytes never change. With
                                ondisk, what lake_persist skips (stage 3c-1 (b2)) */
    bool dv_stale;           /* an end of its rows changed since its deletion vector was made (imdb_seg_set_end, any
                                residency): the next publish makes the vector again; any other keeps it, and its hash,
                                whole, without the image (stage 3c-1 (b2)) */
    uint32_t pos;            /* its index in its table's segment list (plan_install keeps it): a held version's v->seg
                                is re-pointed through it when a publish changes the list */
    uint32_t nended;         /* its rows with an end, and bounds on those ends (end_lo <= every one <= end_hi; an
                                undo leaves them loose, still bounds): RETIRE counts a segment's rows ended at or
                                before a boundary from these alone unless they straddle it (imdb_seg_ended_by) */
    uint64_t end_lo, end_hi;
    imdb_segcache *cache;    /* the cache its image is charged to (NULL: apart from any table, never dropped) */
    imdb_segimg *img_;
    /* P2 S14 (the 2026-11-05 review's O4): a load reads outside the cache's lock, one load an image. Under that lock:
     * loading while one worker reads it (the others wait on the cache's condition); ld_fail the operation (the cache's
     * clock) whose load of it failed, and ld_err that failure whole, so a pin in the same operation reports what its
     * own read would have, whichever worker read (the message never depends on the thread count); a later operation
     * reads again (ld_fail 0: none; ld_err NULL when its copy could not be made: a waiter then reads itself) */
    bool loading;
    uint64_t ld_fail;
    imdb_err *ld_err;
} imdb_segment;

/* The rest of imdb_seg_pin (lake.c): the stamp of a segment first pinned in this operation, or the load. */
imdb_segimg *imdb_seg_pin_slow(const imdb_table *t, imdb_segment *g, imdb_err *e);
/* P2 S14, tests only: fn(g, ctx) runs between each load's read and its publication, no lock held (NULL: none) */
void imdb_seg_load_hook(void (*fn)(const imdb_segment *g, void *ctx), void *ctx);
/* The open streams (3c-2, lake.c): a pass lets go of a segment it has left while the cache is over its budget; the
 * replay trims between commits. No-ops outside the open. */
void imdb_seg_release_one(imdb_segment *g);
/* P2 S15 (O3's first step): a releasing statement's path has left g, keeping no pointer into its image: it leaves now
 * while the cache is over its budget (sql_exec.c decides which statements release) */
void imdb_seg_done(const imdb_table *t, imdb_segment *g);
void imdb_seg_trim_streaming(imdb_db *db);
uint64_t imdb_seg_image_bytes(const imdb_segment *g); /* a resident image's bytes, else 0 */
/* Segment g's image, pinned for the current operation (t: g's table; NULL for a segment parsed apart from any table,
 * as VERIFY's and a seed's checks parse them, always resident). NULL with e set when it cannot be had. Inline: a walk
 * pins at every row, and the common case (in memory, pinned already in this operation) is two loads and a compare. */
static inline imdb_segimg *imdb_seg_pin(const imdb_table *t, imdb_segment *g, imdb_err *e)
{
    imdb_segimg *gi = __atomic_load_n(&g->img_, __ATOMIC_ACQUIRE);
    if (gi && t && __atomic_load_n(&g->touched, __ATOMIC_ACQUIRE) == t->segcache->clock &&
        __atomic_load_n(&gi->laid, __ATOMIC_ACQUIRE) + 1 >= t->hist.nvers) /* F1: laid out for the last version */
        return gi;
    return imdb_seg_pin_slow(t, g, e);
}
/* F1: segment g's zone map for column c of t's last version: its own (in the order of the version that built it), or,
 * for a column it lacks, what every flag-0 row there reads (its missing value): so pruning never drops rows that read
 * a DEFAULT the segment does not store; tmp holds a made one */
static inline const imdb_segzone *imdb_seg_zone(const imdb_table *t, const imdb_segment *g, uint32_t c, imdb_segzone *tmp)
{
    if (t->hist.nvers <= 1 || g->gver + 1 >= t->hist.nvers) return &g->zone[c];
    const imdb_sver *cur = &t->hist.vers[t->hist.nvers - 1], *gv = &t->hist.vers[g->gver];
    int k = gv->at[cur->pos[c]];
    if (k >= 0) return &g->zone[k];
    /* a column with no zone map (TEXT, F3d's UUID and BYTEA, F3e's wide DECIMAL, F3f's INTERVAL: lake.c seg_bytes) never sets has: a
     * missing value's i is no bound of theirs (latent: every reader passes their zones over; 2026-11-11) */
    const imdb_column *cc = &cur->s.cols[c];
    bool any = g->ndata > 0, text = imdb_type_bytes(cc->type) || imdb_col_fixed16(cc);
    const imdb_value *m = &t->hist.tcol[cur->pos[c]].missing;
    memset(tmp, 0, sizeof *tmp);
    tmp->has = any && !m->null && !text; /* as a file's own: a TEXT column's has is never set */
    tmp->has_null = any && m->null;
    tmp->min = tmp->max = m->null || text ? 0 : m->i;
    return tmp;
}

/* Segment g's image if it is in memory, else NULL: never a load, and no stamp either (a commit's end goes in only where
 * the image is resident, and writing it is not a use the trim's order counts) */
imdb_segimg *imdb_seg_resident(const imdb_table *t, imdb_segment *g);
/* Rows of g ended at or before b, from its marks alone; -1 when they straddle b (only its image can say) */
int64_t imdb_seg_ended_by(const imdb_segment *g, uint64_t b);
/* The checked builds (IMDB_STORE_CHECKS: SAN and fuzz): the cache's count is its images' bytes, by a walk of every
 * table's segments (each image a table holds charged to its cache); aborts otherwise. Nothing in the others. */
void imdb_seg_cache_check(const imdb_db *db);

/* Strict parse of a segment file image against the table schema. Takes
 * ownership of bytes on success. Every structural rule of the canonical
 * encoding is enforced; nothing outside [bytes, bytes+len) is read. known: the bytes' SHA-256 when the caller checked
 * it already (an object read by its name: hashing a lake twice was most of a load's time); NULL: computed here. */
/* F1: the hash of a schema's encoding alone (the manifest's "history ends at its schema") */
int imdb_schema_hash(const imdb_schema *s, uint8_t out[32], imdb_err *e);
/* F1 stage 4: a version's identity, the hash a segment's header names it by: SHA-256 over "IMDBSVR1", the schema's
 * encoding and each column's position (u16; pos NULL: version 1's, column c at position c). Equal hashes mean equal
 * layouts: a DROP COLUMN then an ADD COLUMN of the same column gives the old encoding at another position */
int imdb_sver_hash(const imdb_schema *s, const uint16_t *pos, uint8_t out[32], imdb_err *e);
/* F1: the same, by the version of h whose hash the header names: its image laid out for h's last version */
int imdb_segment_parse_h(const imdb_schema_hist *h, uint8_t *bytes, size_t len, const uint8_t known[32], imdb_segment **out,
                         imdb_err *e);
/* vhash: the version hash the header must carry (imdb_sver_hash of the version s is) */
int imdb_segment_parse(const imdb_schema *s, const uint8_t vhash[32], uint8_t *bytes, size_t len, const uint8_t known[32],
                       imdb_segment **out, imdb_err *e);
void imdb_segment_free(imdb_segment *g);
/* Recomputes every non-stub row's commitment from the columns. */
int imdb_segment_check_commitments(const imdb_schema_hist *h, const imdb_segment *g, const imdb_segimg *gi, imdb_err *e);
/* Column c of row `row` (non-stub; a TEXT value points into the segment). */
void imdb_seg_get(const imdb_schema *s, const imdb_segimg *gi, uint32_t row, uint32_t c, imdb_value *v);
/* Every column of row `row` (non-stub) of a pinned image: a walk that pinned the segment once reads its rows so */
void imdb_seg_row_values(const imdb_schema *s, const imdb_segimg *gi, uint32_t row, imdb_value *vals);
/* Canonical row bytes of one segment row (non-stub). */
int imdb_segment_row(const imdb_schema_hist *h, const imdb_segimg *gi, uint32_t row, imdb_buf *out, imdb_err *e);

typedef struct imdb_dv_ent {
    uint32_t row;
    uint64_t end;
} imdb_dv_ent;
int imdb_dv_parse(const uint8_t *b, size_t len, uint8_t seg_hash[32], imdb_dv_ent **ents, uint32_t *n,
                  uint32_t nrows, imdb_err *e);

typedef struct imdb_manifest_seg {
    uint8_t seg[32], dv[32];
    uint32_t nrows;
} imdb_manifest_seg;
typedef struct imdb_manifest_tab {
    imdb_schema s;
    uint64_t horizon, live, versions;
    imdb_lthash digest;
    imdb_manifest_seg *seg;
    uint32_t nseg;
    imdb_index idx[IMDB_MAX_INDEXES]; /* the table's index definitions, sorted by name */
    uint32_t nidx;
    uint64_t retention_us;
    uint64_t created_at, dropped_at; /* version 5 (1f): the commits that created and dropped it (0: live) */
    /* F1: its schema history, made by the parse from version 1 and each ALTER at its commit (the table's entry ends
     * with u32 nalter; when not 0, version 1's schema as u32 length and bytes; F2a (manifest 9): then version 1's
     * DEFAULTs, the CREATE's (op 23's encoding, imdb_coldefs_put: n may be 0); then each ALTER as u64 commit and
     * op 22's body: imdb_alter_put), which wants each ALTER valid on the version before it (imdb_sver_next),
     * after the CREATE, at or before the snapshot and before a drop, and the last version to be s. A consumer may
     * take it whole (and zero it): imdb_manifest_free frees what is left */
    imdb_schema_hist hist;
} imdb_manifest_tab;
/* P2 S7: a view in a manifest (version 6): a live one's definition, a dropped one's tombstone (def NULL) */
typedef struct imdb_manifest_view {
    uint32_t id;
    char name[IMDB_MAX_IDENT + 1];
    uint64_t created_at, dropped_at;
    imdb_viewdef *def;
} imdb_manifest_view;
typedef struct imdb_manifest {
    uint8_t db_id[16];
    uint64_t seq;
    uint8_t prev[32], state[32], prev_manifest[32];
    uint64_t boundary; /* the commit at or below which the log is retired (0: none) */
    imdb_manifest_tab *t;
    uint32_t nt;
    imdb_manifest_view *v; /* P2 S7: every view ever created, by id */
    imdb_sequence *sq;     /* F2a-2 (manifest 10): every sequence ever created, by id, its state at the snapshot */
    imdb_enum *en;         /* F3g (manifest 17): every ENUM type ever created, by id (en[id - 1]), a tombstone its labels */
    imdb_rcat rc;          /* L (manifest 18): the roles held and their grants at the snapshot (role.h); the snapshot
                            * open takes it whole (and zeroes it) */
    uint8_t rhash[32];     /* L: section 5's roles object (zero: none), its bytes the current entries' */
    uint32_t nen;
    uint32_t nsq;
    uint32_t nv;
} imdb_manifest;
int imdb_manifest_parse(const uint8_t *b, size_t len, imdb_manifest *m, imdb_err *e);
void imdb_manifest_free(imdb_manifest *m);

/* Object names: exactly 64 lowercase hex digits + ".seg" | ".dv" | ".man". */
bool imdb_object_name_valid(const char *name);
/* Reader pins (deferred.md R3). A reader of a lake generation holds flock(LOCK_SH) on
 * pins/<manifest hash>.pin while it reads that generation's files; GC keeps what a pinned
 * generation references, within bounds: the IMDB_MAX_PINNED newest, within IMDB_PIN_MAX_LAG
 * commits of the current one, and none from before the writer's pin floor (an ERASE it
 * published, or the snapshot it opened from: an ERASE before it may have come between), so a
 * pin never keeps erased bytes. GC removes a stale pin (no reader holds it) while holding it
 * exclusively, the generation's manifest first, then its other objects, then the pin file: a
 * reader checks that the file it locked is still the one the name gives, and wraps its whole
 * read in a retry (IMDB_PIN_RETRIES) for a generation that vanished all the same. imdb_lake_pin
 * never fails: *fd = -1 is no pin (no pins/, no permission, read-only media, an I/O error), and
 * the read goes on unpinned, with the retry. */
#define IMDB_PINS_DIR "pins"
int imdb_lake_pin(int dirfd, const uint8_t manifest[32], int *fd, imdb_err *e);
void imdb_lake_unpin(int fd);
/* pins/<64 hex>.pin */
bool imdb_pin_name_valid(const char *name);
/* objects/ of an open database, and one object read whole and checked against its name. */
int imdb_lake_objects_open(imdb_db *db, imdb_err *e);
int imdb_lake_read_object(int ofd, const uint8_t h[32], const char *ext, uint8_t **out, size_t *len, imdb_err *e);

/* ---- operations (primary) ------------------------------------------------- */
/* Flush every memtable into segments and publish a manifest (CHECKPOINT op). */
int imdb_checkpoint(imdb_db *db, imdb_err *e);
/* Merge a table's segments into one; drop versions that ended at or before
 * purge_before (0 = keep all history) and raise the history horizon. */
int imdb_compact(imdb_db *db, imdb_table *t, uint64_t purge_before, imdb_err *e);
/* RETIRE below boundary (stage 3a): every version ended at or before it leaves the lake, the version store
 * and the indexes. boundary must end a log segment (the next commit begins one), be past the database's and
 * below every table's horizon (so nothing still answered is dropped): INVALID otherwise, nothing signed. */
int imdb_retire(imdb_db *db, uint64_t boundary, imdb_err *e);
/* Tests only: the same op without those checks, so that VERIFY, the auditor and replay can be shown to refuse
 * what the engine never signs. */
int imdb_retire_unchecked(imdb_db *db, uint64_t boundary, imdb_err *e);

#endif
