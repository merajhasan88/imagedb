/*
 * Replica acknowledgements (deferred.md R2). A replica tells its primary, signed
 * with its own key, which commit it holds durably (seq and hash, after its own
 * fdatasync'd append: `follow` syncs at each acknowledgement point) and through which commit
 * its physical cleanup is complete (imdb_cleanup_seq: no file in its data
 * directory still holds the bytes of an ERASE up to there; free disk blocks may,
 * until crypto-shredding, R6).
 *
 *   session = "IMDBSES1" | db id[16] | nonce[16] | CRC32C of the 40 bytes before it (44 bytes)
 *   ack     = "IMDBACK2" | db id[16] | replica key[32] | u32 epoch | u32 0 | nonce[16] | u64 seq |
 *             head[32] | u64 cleanup | Ed25519 signature by the replica key over the 128 bytes
 *             before it (192 bytes)
 *
 * `imagedb ship --acks` (the primary) draws a random nonce per session and sends it in a session
 * record ahead of its first frame; `imagedb follow` (the replica) signs it into every
 * acknowledgement it sends back on the shipping command's stdin, and ship accepts only those
 * carrying its own: the challenge, so a record signed in another session (retained, logged,
 * replayed) never counts in this one. epoch: the writer epoch of the replica's commit at seq.
 * The head hash binds an acknowledgement to one history (the epoch follows from it, as the chain
 * holds every key change); the epoch is checked where the key schedule is known (status and the
 * wait), ship checks the head. The transport (ssh) is trusted to deliver; the signature
 * attributes each one to an allowlisted replica.
 *
 * Ship records the latest per replica. Refused and recorded durably (if recording succeeds) as an
 * incident, until the replica is re-enrolled: a head that differs from the primary's commit at
 * that seq, or commits beyond the primary's log (diverged); and a commit below the one recorded
 * for the same key (it went back: the replica lost acknowledged commits, restored from an older
 * copy or damaged). The incarnation is the replica's key: a replica restored from a copy is
 * re-enrolled with a new one (`imagedb replica-key DIR --new`, then `replica-add NAME KEY
 * --replace`), and that check catches the restores that skip it, at their first acknowledgement
 * (follow sends one before anything arrives), as far as NAME.ack shows the earlier one (it is not
 * fsynced: a primary's OS crash can tear it or leave an older one). The cleanup claim may go down (a reopened replica
 * with work outstanding restarts it), which only understates.
 *
 * Freshness: a recorded acknowledgement is the last one received, with the time the primary
 * received it; it says what the replica held then, never what it holds now (SHOW REPLICAS and
 * SHOW ERASURE give its age). The wait for sync_replicas counts only an acknowledgement of the
 * commit just made or later, which can only have been signed after that commit existed.
 *
 * Files: the replica's seed in replica.key (0600: init-replica, `imagedb replica-key` for a
 * replica made before it, `--new` for a new incarnation); on the primary, replicas/NAME.pub (the
 * allowlist: 64 hex digits and a newline), replicas/NAME.ack (the latest acknowledgement as
 * received, then the receipt time and a CRC: advisory, rewritten in place without fsync, see
 * CLAUDE.md) and replicas/NAME.diverged (the refused one and why, written atomically).
 * replica-add and every receipt hold flock(LOCK_EX) on replicas/: a replaced key cannot be
 * used by an overlapping receipt, and two shippers cannot race the check/update of its watermark.
 */
#ifndef IMDB_REPL_H
#define IMDB_REPL_H

#include <stdbool.h>
#include <stdint.h>

#include "limits.h"
#include "sign.h"
#include "util.h"

#define IMDB_ACK_LEN 192
#define IMDB_SESSION_LEN 44
#define IMDB_NONCE_LEN 16
#define IMDB_REPLICA_KEY_NAME "replica.key"
#define IMDB_REPLICAS_DIR "replicas"
#define IMDB_REPLICA_NAME_MAX 32

struct imdb_db;

typedef struct imdb_ack {
    uint8_t db_id[16];
    uint8_t replica[IMDB_PUBKEY_LEN];
    uint32_t epoch;                /* the writer epoch of the commit at seq */
    uint8_t nonce[IMDB_NONCE_LEN]; /* the shipping session's challenge */
    uint64_t seq;
    uint8_t head[32];
    uint64_t cleanup; /* no file of the replica holds what an ERASE up to this commit removed */
} imdb_ack;

void imdb_session_encode(const uint8_t db_id[16], const uint8_t nonce[IMDB_NONCE_LEN], uint8_t out[IMDB_SESSION_LEN]);
/* 1 and the nonce when b is a session record of db_id, 0 when it is not a session record (its
 * magic), -1 (e) when it is one but damaged or another database's. */
int imdb_session_decode(const uint8_t b[IMDB_SESSION_LEN], const uint8_t db_id[16], uint8_t nonce[IMDB_NONCE_LEN],
                        imdb_err *e);

void imdb_ack_sign(const imdb_ack *a, const imdb_signer *s, uint8_t out[IMDB_ACK_LEN]);
/* Decodes and checks the signature against the key the record names. */
int imdb_ack_open(const uint8_t b[IMDB_ACK_LEN], imdb_ack *a, imdb_err *e);

/* The replica's own key (replica.key in its data directory): loaded, or with create made first
 * when it is missing (*created). */
int imdb_replica_key_create(int dirfd, imdb_err *e);
int imdb_replica_key(const char *dir, bool create, imdb_signer *s, bool *created, imdb_err *e);
/* A new incarnation: replica.key replaced by a new seed (atomically), loaded into s. */
int imdb_replica_key_new(const char *dir, imdb_signer *s, imdb_err *e);

typedef struct imdb_allow {
    char name[IMDB_REPLICA_NAME_MAX + 1];
    uint8_t pub[IMDB_PUBKEY_LEN];
} imdb_allow;

/* The primary's allowlist: replicas/NAME.pub. NAME is [a-z0-9_-], 1 to 32 characters. replace:
 * a new key for NAME (a re-initialised replica), dropping its acknowledgement and divergence. */
int imdb_replica_add(const char *primary, const char *name, const uint8_t pub[IMDB_PUBKEY_LEN], bool replace,
                     imdb_err *e);
/* Every allowlisted replica, sorted by name (n == 0, out NULL: none). */
int imdb_allowlist_load(int dirfd, imdb_allow **out, size_t *n, imdb_err *e);

/* Ship's view of the primary's history: 1 with *hash set, 0 when seq is beyond the primary's log,
 * -1 when this session cannot say (before what it has seen). */
typedef int (*imdb_hash_at_fn)(void *ctx, uint64_t seq, uint8_t hash[32]);

/* ship --acks: one acknowledgement as received in the session whose challenge is nonce. Refused: a
 * bad signature, another database's, another session's, a key not allowlisted (reload on a cache
 * miss; recheck the current binding before use), a replica with a recorded incident; a new
 * divergence or a commit below the recorded one is recorded (replicas/NAME.diverged) and refused.
 * Otherwise it becomes NAME.ack, with the time it was received. */
int imdb_ack_receive(int dirfd, const uint8_t db_id[16], const uint8_t nonce[IMDB_NONCE_LEN], imdb_allow **allow,
                     size_t *nallow, const uint8_t raw[IMDB_ACK_LEN], imdb_hash_at_fn hash_at, void *ctx, imdb_ack *out,
                     imdb_err *e);

typedef enum {
    IMDB_REPL_NONE,     /* no acknowledgement recorded */
    IMDB_REPL_SAME_HISTORY, /* its head is this primary's commit at its seq: the same history (not caught up: see lag) */
    IMDB_REPL_DIVERGED, /* another history at its seq, or a recorded divergence */
    IMDB_REPL_AHEAD     /* it holds commits beyond this log (lost here in a --nosync crash, or another primary) */
} imdb_repl_state;

typedef enum {
    IMDB_REFUSED_UNKNOWN = 0, /* an incident record that cannot be read */
    IMDB_REFUSED_HISTORY = 1, /* another history at its commit */
    IMDB_REFUSED_AHEAD = 2,   /* commits beyond this log */
    IMDB_REFUSED_BACK = 3     /* a commit below the one recorded for its key: it lost acknowledged commits */
} imdb_refusal;

typedef struct imdb_replica_status {
    imdb_allow who;
    bool acked;
    imdb_ack ack;
    int64_t received_ms; /* when the primary received it (unix ms) */
    int64_t age_ms;      /* since then; -1 if unknown */
    bool incident;       /* replicas/NAME.diverged exists */
    imdb_ack refused;    /* its refused acknowledgement */
    imdb_refusal why;
    uint64_t earlier;    /* IMDB_REFUSED_BACK: the commit it had acknowledged before */
    imdb_repl_state state;
} imdb_replica_status;

/* SHOW REPLICAS: every allowlisted replica, its latest acknowledgement (re-verified) and its state
 * against db's own history. */
int imdb_replicas_status(struct imdb_db *db, imdb_replica_status **out, size_t *n, imdb_err *e);

/* COMMIT under SET sync_replicas = k: waits until k replicas acknowledge holding commit seq (an
 * acknowledgement at seq or later, of db's history at its epoch), or until timeout_ms.
 * *got: how many did. Fresh by construction: commit seq did not exist before the wait's commit,
 * so no acknowledgement of it can be retained or replayed from earlier. Never an error for the
 * commit: the caller reports the outcome (sql.h, imdb_repl_outcome). */
int imdb_replicas_wait(struct imdb_db *db, uint64_t seq, uint32_t k, uint32_t timeout_ms, uint32_t *got, imdb_err *e);

#endif
