/*
 * The lake: immutable columnar segments, deletion vectors and manifests,
 * all content-addressed (file name = SHA-256 of the bytes; a segment's of its tail, F5b) and written in one
 * canonical encoding, so the same logical content always produces the same
 * bytes on the primary, on every replica, and in any re-encoding.
 *
 * Segment (F5: imagedb's canonical Parquet subset, src/parquet.h, docs/f5-design.md): a Parquet file of one row group
 *   of at least one row, its rows in vid order, a chunk a column: imdb$vid INT64, imdb$begin INT64, imdb$flags INT32,
 *   imdb$salt FIXED_LEN_BYTE_ARRAY(16), imdb$commit FIXED_LEN_BYTE_ARRAY(32), each REQUIRED (F5b: field ids 2147483540
 *   and 2147483539, Iceberg v3's _row_id and _last_updated_sequence_number, then 2147483002 to 2147483004, below
 *   Iceberg's reserved range; a '$' in each name, which no imagedb identifier holds), then the live
 *   columns of the schema version that built it in its compact order (field id: the column's position + 1), OPTIONAL
 *   when NULLABLE: BIGINT INT64 INT(64), INTEGER INT32 INT(32), SMALLINT INT32 INT(16), a DECIMAL by Iceberg's mapping
 *   (F5b): to 9 digits INT32, to 18 INT64, past them FIXED_LEN_BYTE_ARRAY of imdb_pq_dec_bytes (9 to 16) big-endian,
 *   each DECIMAL, TEXT BYTE_ARRAY STRING, BYTEA BYTE_ARRAY, BOOL
 *   BOOLEAN, TIMESTAMP INT64 TIMESTAMP(MICROS) local and TIMESTAMPTZ UTC, DATE INT32 DATE, TIME INT64 TIME(MICROS)
 *   local, UUID FIXED_LEN_BYTE_ARRAY(16) UUID, FLOAT64 DOUBLE (IEEE; the image holds its key), INTERVAL
 *   FIXED_LEN_BYTE_ARRAY(16) (months LE32, days LE32, microseconds LE64; no annotation), ENUM INT64 (its ordinal).
 *   The footer's key-value pairs: imagedb.chunks (the writer's), imagedb.format "2" (F5b; "1" refused by name),
 *   imagedb.interval (the INTERVAL
 *   columns' field ids, decimal, comma-separated; only when any), imagedb.schema (the version's imdb_sver_hash, 64
 *   lowercase hex), imagedb.table (the table's id, decimal): exactly these. Statistics wherever a zone map exists (not
 *   seg_bytes), bounding every value, a placeholder too; the zone maps are computed at the load. A file in the format
 *   before (magic "IMDBSEG1") is refused by name. Its name (F5b) is the SHA-256 of its tail (the footer, its length,
 *   the closing magic); a file read is authenticated by that, its frame and each chunk's hash (parquet.h).
 *   Row flags: 0 a version with its data; 1 (stub) erased: vid, begin, commitment only;
 *   2 (purged) dropped by COMPACT ... PURGE: vid, begin, commitment and the SUBJECT value
 *   (so ERASE SUBJECT still finds purged history, whose payloads remain in the log);
 *   3 purged and erased: vid, begin, commitment only. A row that keeps no value in a column is NULL where the column is
 *   OPTIONAL and the type's zero where it is REQUIRED (TEXT and BYTEA empty, FLOAT64 +0.0, a fixed-length value zeros); a
 *   flagged row's salt is zero; zone maps cover flag-0 rows only.
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

#define IMDB_SEG_NSYS 5u            /* F5: a segment's system columns, before the schema version's */
#define IMDB_SEG_FIELD_VID 2147483540   /* F5b: imdb$vid, Iceberg v3's _row_id */
#define IMDB_SEG_FIELD_BEGIN 2147483539 /* F5b: imdb$begin, Iceberg v3's _last_updated_sequence_number */
#define IMDB_SEG_SYS_FIELD 2147483000   /* F5: the other three's, this + their index (2 to 4) */
#define IMDB_MANIFEST_VERSION 20u /* F5b: segments named by their tail, Iceberg's field ids and DECIMAL widths; 19
                                   before them (F5: segments in imagedb's Parquet subset); 18 before those (L: roles and grants,
                                   sections 5 and 6 filled); 17 before those (F3g: ENUM types, the
                                   enums section, ENUM columns); 16 before those (F3f: INTERVAL columns,
                                   16-byte cells and DEFAULTs); 15 before those (F3e: DECIMAL columns to 38
                                   digits, a wide one's 16-byte cells); 14 before those (F3d: UUID and
                                   BYTEA columns and op 23's kind 10 (gen_random_uuid) in version 1's
                                   DEFAULTs (13 before them: F2b-2, version 1's FOREIGN KEYs; 12: F2c, a CREATE's generated
                                   columns; 11: F2b-1, version 1's CHECKs; 10: F2a-2, the sequences section; 9: F2a, a
                                   CREATE's DEFAULTs; 8; 7: segment format 2); 2 to 18 refused by name (old_manifest) */
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
    /* F5: the arrays the load made (a pass from the file's form to the image's, an OPTIONAL column spread to n slots,
     * the flags narrowed); every other view points into bytes. Each holds row values: wiped and freed with the image,
     * and charged to the cache with it. At most the flags, the four other system columns' (a settled image's) and three a
     * column (values or offsets, bytes, validity) */
    struct {
        void *p;
        size_t n;
    } own[IMDB_SEG_NSYS + 3 * IMDB_MAX_COLS];
    bool viewless; /* F5: no view points into bytes (seg_settle): a built image drops them once its object is written */
    uint32_t nown;
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
/* F1: the same, by the version of h whose hash the footer names (imagedb.schema): its image laid out for h's last
 * version */
int imdb_segment_parse_h(const imdb_schema_hist *h, uint8_t *bytes, size_t len, const uint8_t known[32], imdb_segment **out,
                         imdb_err *e);
/* a segment of version v (its schema, hash and positions: the footer must name it, its columns be v's). bytes 8-byte
 * aligned, the caller's on a refusal and the image's on success (its views point into them) */
int imdb_segment_parse(const imdb_sver *v, uint8_t *bytes, size_t len, const uint8_t known[32], imdb_segment **out,
                       imdb_err *e);
void imdb_segment_free(imdb_segment *g);
/* F5, for tools that build hostile files (forge.c): a segment's Parquet shapes under version v */
struct pq_col;
void imdb_seg_shapes(const imdb_sver *v, struct pq_col *sh);
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
