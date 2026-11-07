/*
 * P2 R1.3: a diverged copy put back on its primary's history (design.md §8, "Rewind").
 *
 * A copy diverges when it holds commits its primary does not: the old primary after a promotion (its commits past the
 * promoted replica's last), a replica that applied commits a promoted one never had, or a replica of a primary whose
 * damaged end `recover` cut. Its primary refuses it (replicas/NAME.diverged). Rewinding it finds the fork point F, the
 * last commit both histories hold, saves the copy's commits past F, and cuts it back to F, so it follows its primary
 * from there instead of being seeded again.
 *
 * The primary's side, `imagedb ship PRIMARY --hashes --after N`: its durable commits' hashes from N on, never a row:
 *   header  = "IMDBHSH1" | db id[16] | u64 N | the hash of commit N[32] (the genesis hash for 0; zeros past L) |
 *             u64 L (its last durable commit) | the hash of commit L[32] | CRC32C of the 104 bytes before it (108)
 *   entries = (L - N) x (u64 seq | hash[32]): commits N + 1 to L in order (none when L <= N)
 *   trailer = CRC32C of the entries (4 bytes)
 * N must be in its log, or its floor (the log's first commit less one, its hash the first frame's prev).
 *
 * The copy's side (`imagedb rewind COPY --save FILE [--demote] -- CMD`, CMD the primary's ship --hashes as follow's
 * shipper, {after} the commit to start from): begin takes the copy's lock and says where it stands and the lowest
 * commit it can be rewound to (0, or for a copy whose log is cut its lake's commit: the lake cannot go below it);
 * run reads the hashes, compares them with its own, and rewinds to F. It refuses, the copy untouched: another
 * database's hashes; a start not the one asked for; histories that already differ at the start (start lower); no
 * commit past F (its history is the primary's: nothing to rewind); a primary without --demote, a replica with it; an
 * ERASE or a RETIRE past F (what they took from below F cannot be put back: seed it again); a torn or damaged end of
 * its log (open it once, or recover it); a pending key change; a reader holding a pin.
 *
 * The rewind, in this order, each step durable before the next, so a crash leaves the copy untouched, or with its log
 * a prefix of its own at least through F (run rewind again, with another FILE: the first holds every commit past F):
 *   FILE (an operator's path, made exclusively): the frames past F, a stream `imagedb apply` takes on a copy at F
 *        (to reconcile what they held), synced with its directory;
 *   --demote: signing.key renamed signing.key.demoted (it signed the abandoned commits; nothing signs with it again),
 *        replicas/ renamed replicas.demoted (its replicas' records: their incidents are not this copy's), then META
 *        made a replica's, each step skipped once done (a crash between them leaves a primary that cannot sign: run
 *        rewind --demote again); then a new replica.key (a new incarnation: the copy lost commits it may have
 *        acknowledged);
 *   LAKE_HEAD removed when its commit is past F (the lake is derived: the next writable open rebuilds it from the log,
 *        as after recover);
 *   the kept segments synced, DURABLE set to F (synced);
 *   the segments wholly past F removed, newest first, each with the directory synced; the one holding F + 1 cut after
 *        F (untagged: truncated; tagged: written whole again, its frames to F as one group, atomically).
 * WRITERS is left: an open forgets the epochs past what it replays and a writable open writes it again.
 */
#ifndef IMDB_REWIND_H
#define IMDB_REWIND_H

#include "db.h"
#include "stream.h"

#define IMDB_HASHES_HDR 108
#define IMDB_HASHES_ENTRY 40
/* The default start's distance below the copy's last commit (a fork is near the head; --from goes further). */
#define IMDB_REWIND_WINDOW 1000000u

int imdb_ship_hashes(const char *path, uint64_t after, const imdb_sink *out, imdb_err *e);

typedef struct imdb_rewind imdb_rewind;
typedef struct imdb_rewind_report {
    uint64_t last;    /* the copy's last commit */
    uint64_t lowest;  /* the lowest commit it can be rewound to */
    uint64_t primary; /* the primary's last durable commit */
    uint64_t fork;    /* F: the last commit both hold */
    uint64_t saved;   /* the commits past F written to FILE */
    bool replica;     /* the copy was a replica */
    bool nothing;     /* its history is the primary's, behind it or equal: refused, nothing to rewind */
    bool lake_dropped; /* LAKE_HEAD was past F: removed (the next writable open rebuilds the lake from the log) */
    bool demoted;     /* a primary made a replica */
    uint8_t replica_pk[IMDB_PUBKEY_LEN]; /* its new replica key */
    bool applied;     /* rewound */
} imdb_rewind_report;

/* Takes the copy's lock and reads where it stands (r->last, r->lowest, r->replica); nothing changes. */
int imdb_rewind_begin(const char *path, imdb_rewind **out, imdb_rewind_report *r, imdb_err *e);
/* The primary's hashes from after on (rfn: what ship --hashes wrote), compared with the copy's; the rewind to F. */
int imdb_rewind_run(imdb_rewind *rw, uint64_t after, imdb_read_fn rfn, void *ctx, const char *save, bool demote,
                    imdb_rewind_report *r, imdb_err *e);
/* The lock released, everything freed. */
void imdb_rewind_end(imdb_rewind *rw);

#endif
