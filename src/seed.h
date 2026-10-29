/*
 * Seeding a replica past a cut (round 4, stage 3a (e); design.md §8, "The log a replica still needs").
 *
 * A replica recomputes its lake from the publishes it replays, so once a primary has cut its log below
 * commit 1 a new replica can only begin from a snapshot, sent with what authenticates it. `ship --after 0`
 * (its default) to such a primary sends a seed after the session record, then ends the stream:
 *
 *   "IMDBSED1" | u64 S | u32 head length | u32 objects | u32 CRC32C of the 24 bytes before
 *   head: FLOOR's own format up to its manifest (writer.h), for the floor S = the primary's published
 *         snapshot (LAKE_HEAD) | u32 CRC32C of the head
 *   objects: S's manifest first, then every segment and deletion vector it names, in hash order, each
 *            u8 kind (1 .seg, 2 .dv, 3 .man) | hash | u64 length | the bytes
 *
 * The replica takes it only empty (init-replica, nothing applied). It checks the head as an open checks
 * FLOOR (the key changes from META's keys, S's header under the key at S) before it trusts the manifest
 * hash S's publish op names, then takes each object only if the manifest names it, once, and its bytes
 * hash to its name (streamed to a temporary file: nothing is allocated from a length the stream claims).
 * It writes the objects, then FLOOR (head and manifest), then LAKE_HEAD, and leaves its handle stale: the
 * next open loads the snapshot at its floor, and ship goes on after S. A seed cut short leaves only
 * objects, or FLOOR without LAKE_HEAD; a writable open of a replica with no LAKE_HEAD and an empty log
 * removes them (imdb_seed_leftovers), so it is empty again.
 */
#ifndef IMDB_SEED_H
#define IMDB_SEED_H
#include <stdbool.h>
#include <stdint.h>
#include "db.h"
#include "stream.h"
#include "util.h"

#define IMDB_SEED_PREFIX 28

/* The primary's side: the seed of the snapshot LAKE_HEAD names (its generation pinned while it is read),
 * written to outfd. *seq: S, the commit the replica then holds. */
int imdb_seed_send(const char *path, int dirfd, int logfd, int outfd, uint64_t *seq, imdb_err *e);

/* The replica's side, its prefix already read (imdb_stream_seed): see above. db->seeded is S after it. */
int imdb_seed_take(imdb_db *db, imdb_stream *s, const uint8_t prefix[IMDB_SEED_PREFIX], imdb_err *e);

/* A writable replica's open, before FLOOR is read: a seed cut short removed (no LAKE_HEAD, no log segment). */
int imdb_seed_leftovers(imdb_db *db, imdb_err *e);
#endif
