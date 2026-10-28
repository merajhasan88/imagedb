/* Engine-internal interfaces shared between db.c, replay.c, erase.c, verify.c, lake.c. */
#ifndef IMDB_DB_INTERNAL_H
#define IMDB_DB_INTERNAL_H

#include "db.h"

enum { UNDO_INSERT = 1, UNDO_END = 2, UNDO_CREATE = 3, UNDO_INDEX = 4, UNDO_UNINDEX = 5 };

/* tables / versions */
int imdb_table_new(imdb_db *db, const imdb_schema *s, imdb_err *e);
void imdb_table_free(imdb_table *t);
int imdb_ver_push(imdb_table *t, imdb_err *e);
/* An empty store with room for exactly n versions (chunk 0 sized to n when n fits one chunk), for an
 * open that knows the count (the snapshot). */
int imdb_ver_reserve(imdb_table *t, uint64_t n, imdb_err *e);
/* What the store holds in memory, and what its next growth step adds (both parts and the directories). */
uint64_t imdb_ver_bytes(const imdb_table *t);
uint64_t imdb_ver_growth(const imdb_table *t);
/* the capacity in versions after the next growth step */
uint64_t imdb_ver_next_cap(const imdb_table *t);
const uint8_t *imdb_mem_row(const imdb_table *t, const imdb_version *v);
int imdb_version_key(imdb_table *t, uint64_t vid, int col, imdb_value *out);
/* DML on canonical row bytes; salt is a replayed op's (its commitment stays the same) or NULL. */
int imdb_insert_row(imdb_db *db, imdb_table *t, const uint8_t *row, size_t len, const uint8_t *salt, imdb_err *e);
/* The snapshot and pending marker writes are checked against (the active session's, else the latest). */
void imdb_txn_write_view(const imdb_db *db, uint64_t *snap, uint64_t *pend);
int imdb_update_row(imdb_db *db, imdb_table *t, uint64_t vid, const uint8_t *row, size_t len, const uint8_t *salt,
                    imdb_err *e);
int imdb_index_version(imdb_table *t, uint64_t vid, imdb_undo *u, imdb_err *e);
int imdb_index_subject(imdb_table *t, uint64_t vid, const imdb_value *sv, imdb_undo *u, imdb_err *e);
/* Drops all loaded state (tables, lake, commit index) back to an empty database. */
void imdb_reset_state(imdb_db *db);
/* The memory budget's admission (db.h): IMDB_ERR_LIMIT when growing by growth bytes would cross it. */
int imdb_mem_admit(imdb_db *db, uint64_t growth, imdb_err *e);
/* Loads the published lake snapshot (LAKE_HEAD) as the starting state, its generation pinned
 * (lake.h); *seq gets its commit, 0 when there is none. On error the caller resets, and replays the
 * whole log, unless *moved: an object vanished and LAKE_HEAD now names another generation (a
 * writer's GC after newer publications), so it tries again, from a new listing of the log. */
int imdb_lake_load_snapshot(imdb_db *db, uint64_t *seq, bool *moved, imdb_err *e);
/* LAKE_HEAD as it is on disk (present false: none). */
int imdb_lake_head(int dirfd, bool *present, uint64_t *seq, uint8_t manifest[32], imdb_err *e);
/* Makes every commit appended so far durable (the --nosync ones too) and the watermark say so.
 * Before a lake state names a commit, that commit must be on disk (S1: the log before what
 * depends on it). A failed sync stops the handle. */
int imdb_log_sync(imdb_db *db, imdb_err *e);
/* writer.c: the writer's seed files, META, the WRITER_KEY op of a rotation, the commit clock. */
int imdb_seed_read(int dirfd, const char *name, imdb_signer *sg, bool *has, imdb_err *e);
/* The external anchor's writer lock (FILE.lock beside it, never replaced): exclusive, non-blocking. */
int imdb_anchor_lock(const char *anchor, int *fd, imdb_err *e);
/* Its newest authentic record (*present false: no anchor yet), *ahead when its epoch is past db's. */
int imdb_anchor_load(imdb_db *db, const char *path, imdb_anchor *a, bool *present, bool *ahead, imdb_err *e);
/* The anchor at path names db's current commit from now on (both records, fsynced). */
int imdb_anchor_adopt(imdb_db *db, const char *path, imdb_err *e);
/* An anchor record's commit (seq <= db->seq) is this history's (hash and epoch); or it is an older
 * epoch's commit past the cut a later promotion made: abandoned by it. */
int imdb_anchor_in_history(imdb_db *db, const char *path, const imdb_anchor *a, imdb_err *e);
bool imdb_anchor_abandoned(const imdb_db *db, const imdb_anchor *a);
int imdb_meta_write(imdb_db *db, bool replica, imdb_err *e);
int imdb_tx_add_writer(imdb_db *db, uint32_t epoch, const uint8_t new_pk[IMDB_PUBKEY_LEN], uint8_t how, imdb_err *e);
uint64_t imdb_now_us(void);
void imdb_stub_version(imdb_table *t, uint64_t vid);
void imdb_pk_unlink(imdb_table *t, uint64_t vid, const imdb_value *key);
int imdb_ci_push(imdb_db *db, uint64_t time_us, const uint8_t hash[32], const uint8_t digest[32], imdb_err *e);
int imdb_digest_delta(uint8_t alg, const imdb_op *ops, uint32_t nops, uint32_t nt, imdb_lthash *out, bool *touched, imdb_err *e);

/* transaction helpers for erase/lake */
int imdb_tx_add_erase(imdb_db *db, imdb_erase_ent *ents, uint32_t n, imdb_rewrite *rw, uint32_t nrw,
                      const uint8_t manifest[32], imdb_err *e);
int imdb_tx_add_physical(imdb_db *db, uint8_t code, uint32_t table, uint64_t purge_before,
                         const uint8_t manifest[32], imdb_err *e);

int imdb_check_state(imdb_db *db, imdb_err *e);
int imdb_lthash_sum_commits(uint8_t alg, const uint8_t *const *ptrs, size_t n, imdb_lthash *out, imdb_err *e);

/* replay.c */
int imdb_replay(imdb_db *db, bool read_only, imdb_err *e);
/* What a caller already established about a commit, so imdb_apply_commit can skip
 * that work (NULL: check everything). The checks, their order and their messages
 * stay the same. */
typedef struct imdb_commit_pre {
    bool payloads_checked;   /* every row payload matches its commitment */
    bool deltas;             /* nd, tab, delta: the commit's digest deltas (a table may repeat) */
    bool digest_ok;          /* with deltas: the recorded digest is the state after them */
    uint32_t nd;
    const uint32_t *tab;
    const imdb_lthash *delta;
} imdb_commit_pre;
int imdb_apply_commit(imdb_db *db, imdb_commit_rec *c, const imdb_commit_pre *pre, imdb_err *e);

/* lake.c (segments, deletion vectors, manifests) */
int imdb_lake_open(imdb_db *db, imdb_err *e);
void imdb_lake_table_free(imdb_table *t);
int imdb_seg_values(imdb_table *t, const imdb_version *v, imdb_value *vals, imdb_err *e);
int imdb_seg_value(imdb_table *t, const imdb_version *v, int col, imdb_value *out);
void imdb_seg_set_end(imdb_table *t, const imdb_version *v, uint64_t end);
int imdb_lake_after_erase(imdb_db *db, imdb_err *e);
/* Replay of CHECKPOINT / COMPACT / ERASE: rebuild deterministically, compare
 * with the recorded manifest, install. post = per-table digests after the
 * commit (nt entries), post_global = their sum. */
int imdb_lake_apply_physical(imdb_db *db, const imdb_commit_rec *c, const imdb_op *op, const imdb_lthash *post,
                             const imdb_lthash *post_global, imdb_err *e);
int imdb_lake_finish_open(imdb_db *db, imdb_err *e);
/* Publishes a lake state that waited (for the log redaction, or after a failure); a
 * no-op otherwise (a failed GC is retried by the next publication and by open). */
int imdb_lake_publish_pending(imdb_db *db, imdb_err *e);
void imdb_lake_db_free(imdb_db *db);
/* Adds to db->warning ("; " between messages) unless that exact message is already there. */
void imdb_warn(imdb_db *db, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
int imdb_lake_plan_erase(imdb_db *db, const imdb_erase_ent *ents, uint32_t n, imdb_rewrite **rw, uint32_t *nrw,
                         uint8_t manifest[32], imdb_err *e);

#endif
