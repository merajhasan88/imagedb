/*
 * F5c (docs/f5c-design.md section 8): the Iceberg v3 layer, per copy. Under iceberg/<table id>/metadata/, each live table
 * with segments: the table metadata v<H>.metadata.json and version-hint.text at the lake's head H, and a snapshot of each
 * generation the lake keeps (the head's; the retained one's where this copy can give it: its commit above the boundary
 * and in this copy's log, its objects on disk, so a seeded or restored copy and one past a RETIRE's cut offer the head
 * alone): its manifest list snap-<S>-h<H>.avro, its data manifest m-<S>-h<H>-data.avro and delete manifest
 * m-<S>-h<H>-dv.avro, and a Puffin file per data file holding rows not visible at S, dv-<SHA-256 of the segment's and the
 * deletion vector's names>.puffin (one name, one content: kept unwritten while there). Data files are the segments where
 * they lie (location/objects/<hash>.seg, location an absolute path). The sidecar iceberg/LAYER names the head and the
 * location it was written for, last. Derived, never signed, never shipped; a failure to write it is a warning, and a
 * writable open writes a stale one again.
 */
#ifndef IMDB_ICEBERG_H
#define IMDB_ICEBERG_H

#include "db.h"

/* what a layer found for a segment and its deletion vector (db->ice_seen, sorted by the pair): the next layer's, so it
 * reads and writes only what changed (a handle's first reads every kept vector once) */
typedef struct imdb_ice_seen {
    uint8_t seg[32], dv[32];
    uint64_t ndead, psize, blen; /* the rows its vector holds (0: none, no Puffin file), its Puffin file's bytes, its blob's */
} imdb_ice_seen;

/* every live table's layer for the kept generations; location: the database directory's absolute path */
int imdb_iceberg_write(imdb_db *db, const char *location, imdb_err *e);
/* VERIFY: a layer written for the lake's head and this location (its sidecar, iceberg/LAYER, says so) compared with the one the
 * lake gives, file by file, each made again from the lake; IMDB_ERR_NOTFOUND when there is none, IMDB_ERR_STATE when it is
 * stale (each reported, never a failure) */
int imdb_iceberg_verify(imdb_db *db, const char *location, imdb_err *e);
/* a writable open: the layer written again when its sidecar names another head or location (a failed or interrupted
 * write, a moved directory, the layer just turned on); a failure is a warning */
int imdb_iceberg_refresh(imdb_db *db, imdb_err *e);

/* tests only: the writer's lie (0 none), each well formed but for one rule the auditor's check of the layer holds:
 * the head's first vector of two rows or more without its first, its first vector holding a live row too, its data
 * manifest without its last file, its first EXISTING entry written ADDED, each version's first field's required
 * flipped, an INT64 column's initial-default another. A lie forgets what the last layer found, so the next is made whole */
enum {
    ICE_LIE_DV_MISSING = 1, ICE_LIE_DV_LIVE, ICE_LIE_FILE_OUT, ICE_LIE_ADDED, ICE_LIE_REQUIRED, ICE_LIE_DEFAULT,
    ICE_LIE_DV_SWAP, /* its first vector holding a live row for a dead one, its count kept */
    ICE_LIE_COUNTS,  /* its manifest list's added rows one more */
    ICE_LIE_MLEN,    /* its manifest list's manifest_length of the data manifest one more */
    ICE_LIE_FRID     /* its first EXISTING data file's first_row_id one more */
};
void imdb_iceberg_set_lie(int kind);
/* tests only: the vectors, images and segments the handle's layers read (what changed, after its first) */
uint64_t imdb_iceberg_reads(const imdb_db *db);
/* tests only: a value in Iceberg's JSON single-value serialization (spec Appendix D) for column c's type */
void imdb_iceberg_value_json(const imdb_column *c, const imdb_value *v, imdb_buf *out);

#endif
