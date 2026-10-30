/* Engine-internal interfaces shared between db.c, replay.c, erase.c, verify.c, lake.c. */
#ifndef IMDB_DB_INTERNAL_H
#define IMDB_DB_INTERNAL_H

#include "db.h"

enum { UNDO_INSERT = 1, UNDO_END = 2, UNDO_CREATE = 3, UNDO_INDEX = 4, UNDO_UNINDEX = 5 };

/* tables / versions */
int imdb_table_new(imdb_db *db, const imdb_schema *s, imdb_err *e);
void imdb_table_free(imdb_table *t);
int imdb_ver_push(imdb_table *t, imdb_err *e);
/* The newest version leaves the store again (a rollback, an insert that failed): its parts wiped. */
void imdb_ver_pop(imdb_table *t);
/* An empty store with room for exactly n versions (chunk 0 sized to n when n fits one chunk), for an
 * open that knows the count (the snapshot). */
int imdb_ver_reserve(imdb_table *t, uint64_t n, imdb_err *e);
/* The snapshot's store (lake.c load_table), its rows in vid order: imdb_ver_load_begin makes the directory for vids
 * [0, n), no chunk yet; then for each chunk a row lands in, imdb_ver_load_chunk with the number of its rows, and
 * imdb_ver_load_put for each of them in turn (i counts them from 0), whose entries the caller fills; the last chunk
 * is made too when no row lands in it (vids are appended there). A database never retired holds every vid, so its
 * chunks come out dense (each slot IMDB_V_GONE until its row fills it); past a boundary, a chunk other than the last
 * that holds fewer than IMDB_VSPARSE rows comes out sparse: what was read bounds what is allocated, the count only
 * the directory. */
int imdb_ver_load_begin(imdb_table *t, uint64_t n, imdb_err *e);
int imdb_ver_load_chunk(imdb_table *t, uint32_t k, uint64_t cnt, imdb_err *e);
imdb_version *imdb_ver_load_put(imdb_table *t, uint64_t vid, uint32_t i);
/* The memtable was flushed (a publish): its cold parts go, wiped, and mem_first moves to the count. */
void imdb_ver_flushed(imdb_table *t);
/* After versions left the store (their entries flagged IMDB_V_GONE): every chunk but the last is freed when it holds
 * none, and kept sparse when it holds fewer than IMDB_VSPARSE. A chunk that cannot be remade (memory) stays as it
 * is, which is no error: no reader takes an entry flagged gone. */
void imdb_ver_compact(imdb_table *t);
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
/* The key map with its chains and the subject index, from the versions present, in vid order as incremental
 * insertion builds them: the snapshot load, and RETIRE (the CREATE INDEX structures are the caller's). */
int imdb_table_reindex(imdb_table *t, imdb_err *e);
/* RETIRE in the version store (stage 3a): every version ended at or before boundary leaves it (wiped,
 * flagged IMDB_V_GONE), the chunks are compacted (imdb_ver_compact), and the table is reindexed. Its rows
 * have left the lake already (the RETIRE's plan). */
int imdb_retire_table(imdb_table *t, uint64_t boundary, imdb_err *e);
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
/* RETIRE: the commit index keeps the commits past boundary only (an AS OF at or below it is refused: every horizon is
 * past it), and gives its room back. Stage 3b's eviction calls it with the memory floor: the commits at or below it
 * are read from the log on demand then (imdb_ci_at). */
void imdb_ci_retire(imdb_db *db, uint64_t boundary);
/* Commit seq's header (replaced into hdr) and signature, read from its log segment (FLOOR's). */
int imdb_log_commit_header(imdb_db *db, uint64_t seq, imdb_buf *hdr, uint8_t sig[IMDB_SIG_LEN], imdb_err *e);
/* Stage 3a (c2): unlinks the log segments that end at or below both the floor and the published snapshot, oldest
 * first, then syncs the directory; db->segs and seg_time follow. Cleanup: a writable open repeats it. */
int imdb_log_cut(imdb_db *db, imdb_err *e);
/* The boundary the RETIRE policy would choose now (the lowest horizon less one, lowered to a segment end): 0 if
 * none (a table kept FOREVER, or nothing expired past the boundary). */
/* A publish p, the end of the log segment that begins at seg_start, is a keeper (its manifest kept for a future
 * FLOOR, lake.c) iff it is the first publish of its block of stride commits: absolute, so the set only shrinks
 * as the boundary rises, and every copy of the log agrees on it. */
static inline bool imdb_is_keeper(uint32_t stride, uint64_t seg_start, uint64_t p)
{
    uint64_t k = stride ? stride : 1;
    return p / k > (seg_start - 1) / k;
}
/* The keepers' manifests past the boundary (lake.c): those objects/ holds, at a writable open. */
int imdb_lake_keepers_load(imdb_db *db, imdb_err *e);
uint64_t imdb_retire_candidate(const imdb_db *db, uint64_t cap); /* at or below cap, too */
/* The log segment starts s with lo < s <= hi, each as u64 seq | u64 its first commit's time, appended to out (*n
 * of them): what a FLOOR carries for the EXPIREs after it to name. */
int imdb_seg_starts(imdb_db *db, uint64_t lo, uint64_t hi, imdb_buf *out, uint32_t *n, imdb_err *e);
int imdb_digest_delta(uint8_t alg, const imdb_op *ops, uint32_t nops, uint32_t nt, imdb_lthash *out, bool *touched, imdb_err *e);

/* transaction helpers for erase/lake */
int imdb_tx_add_erase(imdb_db *db, imdb_erase_ent *ents, uint32_t n, imdb_rewrite *rw, uint32_t nrw,
                      const uint8_t manifest[32], imdb_err *e);
int imdb_tx_add_physical(imdb_db *db, uint8_t code, uint32_t table, uint64_t purge_before,
                         const uint8_t manifest[32], imdb_err *e);

int imdb_check_state(imdb_db *db, imdb_err *e);
/* The memory window's policy (db.h imdb_evict), between transactions: the primary's imdb_maintain, every applied commit. */
void imdb_evict_policy(imdb_db *db);
/* The floor the window allows now (stage 3b): the end of the newest log segment whose successor began at least the
 * window ago, at most cap (0: none; the eager mode, cap itself). The snapshot open takes it, capped at its commit. */
uint64_t imdb_window_floor(imdb_db *db, uint64_t cap);
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
/* The segment and row of the lake holding vid, whether the store holds it or not (false: none). A table's segments
 * hold rows in ascending, disjoint vid ranges: the snapshot open checks it, and every install. */
bool imdb_lake_find(const imdb_table *t, uint64_t vid, uint32_t *seg, uint32_t *row);
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
