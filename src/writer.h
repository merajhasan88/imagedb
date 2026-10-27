/*
 * Writer epochs (deferred.md R2b, log.h WRITER_KEY): the key schedule every
 * verifier follows, the WRITERS file that gives a snapshot open the keys up to
 * its commit, and the writer's side: key rotation and promotion.
 *
 * WRITERS (derived, replaced atomically when an epoch is added, the same bytes on
 * every copy of the history):
 *   "IMDBWRS1" | db_id[16] | u32 n |
 *   n x ( u64 seq | u8 promote | u32 header_len | header | sig[64] | root_sig[64] if promote ) |
 *   u32 CRC32C of everything before it
 * Entry i is epoch i's WRITER_KEY commit: its header hashes to the hash its
 * signature covers, holds only WRITER_KEY(epoch i), and verifies under key i-1
 * (rotation) or under the root key and key i (promotion), all from META. Entries
 * cannot be forged without those keys; a missing, damaged or stale file makes a
 * snapshot fail to authenticate, and the open replays the whole log instead
 * (closed, and slower), after which a writable open rewrites it.
 */
#ifndef IMDB_WRITER_H
#define IMDB_WRITER_H

#include "db.h"
#include "log.h"

#define IMDB_WRITERS_NAME "WRITERS"
#define IMDB_SIGNING_NEXT_NAME "signing.key.next"

typedef struct imdb_wep {
    imdb_writer_epoch k;
    uint64_t seq;            /* its WRITER_KEY commit (0: epoch 0, from META) */
    bool promote;
    uint8_t *hdr;            /* that commit's header, signature and certificate */
    uint32_t hlen;
    uint8_t sig[IMDB_SIG_LEN];
    uint8_t root_sig[IMDB_SIG_LEN];
} imdb_wep;

/* Epoch 0 from META, then the epochs WRITERS proves (a file that does not verify is ignored, with
 * a warning). */
int imdb_writers_init(imdb_db *db, imdb_err *e);
/* The same from bytes already read (tests and the fuzzers): the epochs they prove, on db->meta. */
int imdb_writers_parse(imdb_db *db, const uint8_t *p, size_t n, imdb_err *e);
/* Back to epoch 0 (a full replay re-derives the rest). */
void imdb_writers_reset(imdb_db *db);
void imdb_writers_free(imdb_db *db);
/* Forgets the epochs whose WRITER_KEY commit comes after seq (the tail replay re-derives them). */
void imdb_writers_cut(imdb_db *db, uint64_t seq);
/* The key that signs commit seq, and the epoch it belongs to. */
const uint8_t *imdb_writer_key_at(const imdb_db *db, uint64_t seq);
uint32_t imdb_writer_epoch_at(const imdb_db *db, uint64_t seq);
uint32_t imdb_current_epoch(const imdb_db *db);
/* A WRITER_KEY commit being applied (its signature and certificate already checked): the next
 * epoch, or an error when it is not. */
int imdb_writer_apply(imdb_db *db, const imdb_commit_rec *c, imdb_err *e);
/* WRITERS, replaced atomically when it differs from the schedule (writable handles). */
int imdb_writers_publish(imdb_db *db, imdb_err *e);
/* A writable primary's signing.key against the log's current key, after replay: a rotation or
 * promotion that reached the log is completed (signing.key.next renamed), one that did not is
 * dropped; any other mismatch is an error. */
int imdb_writer_settle(imdb_db *db, imdb_err *e);

/* imagedb rotate-key: a new writer key, its WRITER_KEY commit signed by the current one. */
int imdb_rotate_key(imdb_db *db, imdb_err *e);
/* imagedb promote: the replica becomes the writer of the next epoch, certified by the root key
 * (its seed), on top of the replica's last commit (the cut). The old writer must be stopped first,
 * and promotion proves it: with an anchor, by taking the anchor's writer lock (refused while any
 * writer holds it), refusing an anchor already at a newer epoch (an earlier promotion), and
 * requiring abandon when the anchor shows old-writer commits past the cut; then the anchor names
 * the new epoch. Without one, the operator says so (old_writer_stopped). The ledger (beside the root
 * key) serializes and durably reserves an epoch once, refusing identical retries too
 * (a cloned replica has the same identity but generates a different writer key).
 * Interrupted reservations require operator recovery after ruling out a committed copy. */
typedef struct imdb_promote_opts {
    const char *anchor;      /* the shared anchor, or NULL */
    bool old_writer_stopped; /* without an anchor: the old writer is stopped and fenced (the operator's word) */
    bool abandon;            /* the anchor names commits past the cut: promote anyway, abandoning them */
    const char *ledger;      /* the root key's ledger file, or NULL */
} imdb_promote_opts;

/* What happened, filled even when an error is returned: a caller never infers it from the error. */
typedef struct imdb_promote_result {
    bool committed;          /* the promotion commit is in the replica's log, durably */
    uint32_t epoch;          /* its epoch */
    uint64_t seq;            /* its commit: the cut is the one before */
    uint64_t abandoned_to;   /* the anchor showed the old writer's commits up to this one past the cut (0: none) */
    bool anchor_published;   /* the anchor names the new epoch */
    bool recovery_required;  /* committed, but a later step failed: a writable open of the replica finishes it */
} imdb_promote_result;

int imdb_promote(const char *dir, const uint8_t root_seed[IMDB_SEED_LEN], const imdb_promote_opts *o,
                 imdb_promote_result *r, imdb_err *e);

#endif
