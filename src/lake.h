/*
 * The lake: immutable columnar segments, deletion vectors and manifests,
 * all content-addressed (file name = SHA-256 of the bytes) and written in one
 * canonical encoding, so the same logical content always produces the same
 * bytes on the primary, on every replica, and in any re-encoding.
 *
 * Segment ("IMDBSEG1", version 2), little-endian:
 *   header (64 B): magic[8] u32 version (2) u32 table schema_hash[32] u32 nrows
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
 * Manifest ("IMDBMAN1"): u32 version (4) u32 ntables db_id[16] u64 seq prev_hash[32] state_digest[32]
 *   prev_manifest[32] (the generation GC keeps beside this one; zero for the first manifest and
 *   after an ERASE, which keeps nothing) u64 boundary (the commit at or below which the log is retired; 0: none)
 *   per table: u32 len | schema | u64 horizon | u64 live | u64 versions | lthash[2048] |
 *              u32 nseg | nseg x { seg_hash[32], dv_hash[32] (zero = none), u32 nrows } |
 *              u32 nidx | nidx x { u8 len | name | u8 flags | u8 ncols | ncols x u16 column } (names
 *              strictly increasing per table and unique across tables) | u64 retention_us (op 16)
 *   Versions 2 and 3 (before the retention, 2026-10-29) are not read.
 * LAKE_HEAD: "imagedb-lake 1\nseq <n>\nmanifest <64 hex>\n"
 */
#ifndef IMDB_LAKE_H
#define IMDB_LAKE_H

#include "db.h"

enum {
    SEG_VID = 1, SEG_BEGIN = 2, SEG_FLAGS = 3, SEG_SALT = 4, SEG_COMMIT = 5,
    SEG_I64 = 16, SEG_U8 = 17, SEG_TEXT_OFF = 18, SEG_TEXT_DATA = 19, SEG_VALID = 20,
    SEG_ZONEMAP = 32,
};

#define IMDB_SEG_HEADER 64u
#define IMDB_SEG_STUB 1u   /* erased: vid, begin and commitment only */
#define IMDB_SEG_PURGED 2u /* purged by COMPACT ... PURGE: vid, begin, commitment and the SUBJECT value */

typedef struct imdb_segcol {
    const int64_t *i64;      /* INT64 / DECIMAL / TIMESTAMP */
    const uint8_t *u8;       /* BOOL */
    const uint32_t *off;     /* TEXT offsets (n+1) */
    const uint8_t *data;     /* TEXT bytes */
    const uint8_t *valid;    /* NULLABLE: bit i set = row i has a value; NULL for NOT NULL columns */
    bool has;                /* zone map: a data row with a value */
    bool has_null;           /* zone map: a data row that is NULL */
    int64_t min, max;
} imdb_segcol;

typedef struct imdb_segment {
    uint8_t hash[32];
    uint32_t table;
    uint32_t nrows;
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
    uint8_t dv_hash[32];     /* deletion vector at the last manifest (zero if none) */
} imdb_segment;

/* Strict parse of a segment file image against the table schema. Takes
 * ownership of bytes on success. Every structural rule of the canonical
 * encoding is enforced; nothing outside [bytes, bytes+len) is read. */
int imdb_segment_parse(const imdb_schema *s, uint8_t *bytes, size_t len, imdb_segment **out, imdb_err *e);
void imdb_segment_free(imdb_segment *g);
/* Recomputes every non-stub row's commitment from the columns. */
int imdb_segment_check_commitments(const imdb_schema *s, const imdb_segment *g, imdb_err *e);
/* Column c of row `row` (non-stub; a TEXT value points into the segment). */
void imdb_seg_get(const imdb_schema *s, const imdb_segment *g, uint32_t row, uint32_t c, imdb_value *v);
/* Canonical row bytes of one segment row (non-stub). */
int imdb_segment_row(const imdb_schema *s, const imdb_segment *g, uint32_t row, imdb_buf *out, imdb_err *e);

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
} imdb_manifest_tab;
typedef struct imdb_manifest {
    uint8_t db_id[16];
    uint64_t seq;
    uint8_t prev[32], state[32], prev_manifest[32];
    uint64_t boundary; /* the commit at or below which the log is retired (0: none) */
    imdb_manifest_tab *t;
    uint32_t nt;
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
