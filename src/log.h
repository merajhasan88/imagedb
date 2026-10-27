/*
 * Commit log: framing, commit-record codec, chain hashing, signatures.
 *
 * Frame:  u32 magic "ILG2" | u32 body_len | u32 body_crc | u32 head_crc | body
 *         (head_crc covers the first 12 bytes, so a corrupted length field is
 *          detected instead of silently swallowing the rest of the log)
 * Body:   descriptor (109 bytes, signed) | header | u32 payload_len | payload
 *   descriptor: u8 kind(2) | u32 header_len | u64 seq | commit_hash[32] | sig[64]
 *
 * header  (chained; never rewritten):
 *         u8 version(2) | u8 digest_alg (1 or 2, below: META's) | u64 seq | u64 time_us | prev[32] |
 *         u32 n_ops | ops... | state_digest[32]
 * commit_hash = SHA256("IMDBCHN2" || header)               -- hash(prev || transaction)
 * sig         = Ed25519(writer key, "IMDBSIG2" || u64 seq || u32 header_len || commit_hash)
 *
 * The descriptor comes first and carries everything the signature covers,
 * so a stream reader authenticates a frame after 125 bytes and before it
 * allocates or decodes anything; header_len and seq are signed, so a replayed
 * descriptor can neither inflate the read nor move a commit.
 *
 * payload (redactable): for each INSERT/UPDATE op, in op order:
 *         u8 kind (0 row | 1 redacted) [ salt[16] | u32 row_len | row ]
 * Row bytes are bound to the chain through the row commitment stored in the
 * op, so payloads can be erased later without breaking the chain or the
 * signature.
 *
 * Ops (all integers little-endian):
 *   1 CREATE_TABLE u32 table | schema
 *   2 INSERT       u32 table | u64 vid | commit[32]
 *   3 DELETE       u32 table | u64 vid | commit[32]          (precondition)
 *   4 UPDATE       u32 table | u64 old_vid | old_commit[32] | u64 new_vid | new_commit[32]
 *  10 CHECKPOINT   manifest[32]
 *  11 COMPACT      u32 table | u64 purge_before | manifest[32]
 *  12 ERASE        u32 n | n x (u32 table | u64 vid | commit[32]) sorted |
 *                  u32 m | m x (u32 table | old_seg[32] | new_seg[32]) sorted | manifest[32]
 *  13 WRITER_KEY   u32 epoch | new_pk[32] | u8 how      (the only op of its commit)
 *                  how 1 (rotation, a planned handover): signed by the current key;
 *                  every later commit by new_pk.
 *                  how 2 (promotion: the old key is gone): signed by new_pk, in a
 *                  body of kind 3, whose descriptor is followed by
 *                  u32 epoch | new_pk[32] | root_sig[64]
 *                  root_sig = Ed25519(root key from META, "IMDBPRO1" || db_id ||
 *                             u32 epoch || u64 seq || prev[32] || new_pk)
 *                  so a stream reader authenticates it (root, then new key) before
 *                  decoding anything; the header's op must repeat epoch and new_pk.
 *                  Epochs count up from 0 (META's writer key) by one.
 */
#ifndef IMDB_LOG_H
#define IMDB_LOG_H

#include <stdbool.h>
#include <stdint.h>

#include "codec.h"
#include "sha256.h"
#include "sign.h"
#include "util.h"

#define IMDB_FRAME_MAGIC 0x32474C49u /* "ILG2" */
#define IMDB_FRAME_HDR   16u
#define IMDB_BODY_KIND   2u
#define IMDB_BODY_KIND_PROMOTE 3u     /* a promotion commit: the descriptor and its root certificate */
#define IMDB_BODY_DESC   109u         /* kind + header_len + seq + commit_hash + sig */
#define IMDB_BODY_EXT    100u         /* kind 3: epoch + new_pk + root_sig */
#define IMDB_PROMOTE_MSG_LEN 100u     /* the root-signed bytes of a promotion */
#define IMDB_SIGMSG_LEN  52u
#define IMDB_HEADER_MIN  86u          /* header with no ops */
#define IMDB_LOG_VERSION 2
#define IMDB_DIGEST_ALG_LTHASH16 1      /* LtHash16 elements by MGF1-SHA256; the state digest SHA-256 over the lanes */
#define IMDB_DIGEST_ALG_LTHASH16_TREE 2 /* elements by ChaCha20 keyed by the commitment; the digest a tree of eight leaves */

enum {
    IMDB_OP_CREATE_TABLE = 1,
    IMDB_OP_INSERT = 2,
    IMDB_OP_DELETE = 3,
    IMDB_OP_UPDATE = 4,
    IMDB_OP_CHECKPOINT = 10,
    IMDB_OP_COMPACT = 11,
    IMDB_OP_ERASE = 12,
    IMDB_OP_WRITER_KEY = 13,
    IMDB_OP_CREATE_INDEX = 14, /* alone in its commit: u32 table, u8 flags (IMDB_INDEX_UNIQUE), u8 ncols,
                                  ncols u16 columns, the index name */
    IMDB_OP_DROP_INDEX = 15,   /* alone in its commit: u32 table, the index name */
};

enum { IMDB_WRITER_ROTATE = 1, IMDB_WRITER_PROMOTE = 2 };

enum { IMDB_PAYLOAD_ROW = 0, IMDB_PAYLOAD_REDACTED = 1 };

typedef struct imdb_erase_ent {
    uint32_t table;
    uint64_t vid;
    uint8_t commit[32];
} imdb_erase_ent;

typedef struct imdb_rewrite {
    uint32_t table;
    uint8_t old_hash[32];
    uint8_t new_hash[32];
} imdb_rewrite;

#define IMDB_INDEX_UNIQUE 1u /* op 14's one flag (and manifest version 3's); the others are zero */

typedef struct imdb_op {
    uint8_t code;
    uint32_t table;
    uint64_t vid;              /* INSERT: new vid; DELETE/UPDATE: old vid  */
    uint8_t commit[32];        /* INSERT: new commit; DELETE/UPDATE: old  */
    uint64_t new_vid;          /* UPDATE */
    uint8_t new_commit[32];    /* UPDATE */
    /* payload of the new version (INSERT/UPDATE) */
    uint8_t pkind;
    uint8_t salt[16];
    const uint8_t *row;
    uint32_t row_len;
    /* CREATE_TABLE */
    imdb_schema *schema;
    /* CHECKPOINT / COMPACT */
    uint8_t manifest[32];
    uint64_t purge_before;
    /* ERASE */
    imdb_erase_ent *erase;
    uint32_t n_erase;
    imdb_rewrite *rewrites;
    uint32_t n_rewrites;
    /* CREATE_INDEX / DROP_INDEX (table above) */
    uint8_t iflags, incols;
    uint16_t icols[IMDB_MAX_INDEX_COLS];
    char *iname;               /* allocated: IMDB_MAX_IDENT + 1 */
    /* WRITER_KEY */
    uint32_t epoch;
    uint8_t new_pk[IMDB_PUBKEY_LEN];
    uint8_t how;
} imdb_op;

typedef struct imdb_commit_rec {
    uint64_t seq;
    uint64_t time_us;
    uint8_t alg;               /* IMDB_DIGEST_ALG_*: the database's, which the digest below is computed by */
    uint8_t prev[32];
    uint8_t digest[32];
    uint8_t hash[32];          /* computed, equal to the descriptor's */
    uint8_t sig[IMDB_SIG_LEN];
    uint32_t hlen;
    bool sig_ok;               /* signature (and a promotion's root certificate) already verified */
    bool promote;              /* body kind 3: its op is WRITER_KEY how 2, root_sig certifies it */
    uint8_t root_sig[IMDB_SIG_LEN];
    imdb_op *ops;
    uint32_t nops;
} imdb_commit_rec;

void imdb_commit_free(imdb_commit_rec *c);
void imdb_genesis_hash(const uint8_t db_id[16], uint8_t out[32]);

static inline bool imdb_op_has_payload(uint8_t code) { return code == IMDB_OP_INSERT || code == IMDB_OP_UPDATE; }
static inline bool imdb_op_publishes_manifest(uint8_t code)
{
    return code == IMDB_OP_CHECKPOINT || code == IMDB_OP_COMPACT || code == IMDB_OP_ERASE;
}

/* Encoding (writer side). */
void imdb_commit_encode_header(const imdb_commit_rec *c, imdb_buf *b);
void imdb_commit_hash(const uint8_t *header, size_t len, uint8_t out[32]);
/* The 52 signed bytes: "IMDBSIG2" || u64 seq || u32 header_len || commit_hash. */
void imdb_commit_sigmsg(uint64_t seq, uint32_t hlen, const uint8_t hash[32], uint8_t out[IMDB_SIGMSG_LEN]);
bool imdb_commit_sig_valid(const uint8_t writer_pk[IMDB_PUBKEY_LEN], uint64_t seq, uint32_t hlen,
                           const uint8_t hash[32], const uint8_t sig[IMDB_SIG_LEN]);
/* The root-signed bytes of a promotion: "IMDBPRO1" || db_id || u32 epoch || u64 seq || prev || new_pk. */
void imdb_promote_msg(const uint8_t db_id[16], uint32_t epoch, uint64_t seq, const uint8_t prev[32],
                      const uint8_t new_pk[IMDB_PUBKEY_LEN], uint8_t out[IMDB_PROMOTE_MSG_LEN]);
/* c's WRITER_KEY op, or NULL. */
const imdb_op *imdb_commit_writer_op(const imdb_commit_rec *c);
/* The key that signed c, given the one in effect before it: a promotion's new key, else that one. */
const uint8_t *imdb_commit_signer(const imdb_commit_rec *c, const uint8_t current[IMDB_PUBKEY_LEN]);
/* c's signature under the key it needs and, for a promotion, its root certificate (root NULL: the
 * database has no root key, so no promotion is authentic). */
bool imdb_commit_authentic(const imdb_commit_rec *c, const uint8_t current[IMDB_PUBKEY_LEN], const uint8_t db_id[16],
                           const uint8_t *root);
/* Sets sig_ok of n decoded commits in log order, checking them in batches of one key each: current
 * is the key in effect before recs[0] and ends as the one after recs[n-1] (WRITER_KEY ops followed). */
void imdb_commit_sigs_check(uint8_t current[IMDB_PUBKEY_LEN], const uint8_t db_id[16], const uint8_t *root,
                            imdb_commit_rec *const recs[], size_t n);
void imdb_commit_encode_payload(const imdb_commit_rec *c, imdb_buf *b);
/* Assembles a full frame from the encoded header (hash and signature already
 * computed over it) and the payload. ext: NULL, or a promotion's descriptor
 * extension (epoch, new key, root signature: body kind 3). */
void imdb_frame_build(const uint8_t *header, size_t hlen, uint64_t seq, const uint8_t hash[32],
                      const uint8_t sig[IMDB_SIG_LEN], const uint8_t *payload, size_t plen, imdb_buf *out);
void imdb_frame_build_ext(const uint8_t *header, size_t hlen, uint64_t seq, const uint8_t hash[32],
                          const uint8_t sig[IMDB_SIG_LEN], const uint8_t ext[IMDB_BODY_EXT], const uint8_t *payload,
                          size_t plen, imdb_buf *out);
/* Bytes before the header in a body: the descriptor (and a promotion's extension). */
static inline size_t imdb_body_desc_len(const uint8_t *body)
{
    return body[0] == IMDB_BODY_KIND_PROMOTE ? IMDB_BODY_DESC + IMDB_BODY_EXT : IMDB_BODY_DESC;
}

/* Writer epochs (deferred.md R2b): epoch 0 is META's writer key, each WRITER_KEY commit adds the
 * next. first: the first commit that key signs (a rotation's next commit, a promotion itself). */
typedef struct imdb_writer_epoch {
    uint32_t epoch;
    uint64_t first;
    uint8_t pk[IMDB_PUBKEY_LEN];
} imdb_writer_epoch;

/* Decoding (reader side). Strict: every field is range-checked, every list
 * length is bounded before allocation, trailing bytes are an error, and the
 * descriptor must agree with the header (seq, length, hash). The signature
 * is NOT checked here: callers hold the writer key. Row pointers reference
 * `body` (caller keeps it alive). */
int imdb_frame_decode_body(const uint8_t *body, size_t len, imdb_commit_rec *c, imdb_err *e);
int imdb_commit_decode_header(const uint8_t *h, size_t hlen, imdb_commit_rec *c, imdb_err *e);
/* seq from a frame's descriptor (frame = prefix + body, at least prefix+13 bytes). */
static inline uint64_t imdb_frame_seq(const uint8_t *frame) { return imdb_get_le64(frame + IMDB_FRAME_HDR + 5); }
/* The commit hash from a frame's descriptor (the frame passed imdb_frame_scan). */
static inline const uint8_t *imdb_frame_hash(const uint8_t *frame) { return frame + IMDB_FRAME_HDR + 13; }

typedef enum imdb_scan_status {
    IMDB_SCAN_FRAME = 0,   /* a valid frame at [off, off+len) */
    IMDB_SCAN_END = 1,     /* clean end of data */
    IMDB_SCAN_TORN = 2,    /* incomplete tail (short frame, or zeros): an unfinished append */
    IMDB_SCAN_DAMAGED = 3, /* a complete final frame failing its checksum (nothing but zeros after it):
                            * an unfinished append OR damage to a committed frame; imdb_tail_check decides */
    IMDB_SCAN_CORRUPT = 4, /* bad frame followed by non-zero data: hard error */
} imdb_scan_status;

/* Classifies the frame starting at off in buf[0..len). TORN and DAMAGED are
 * only ever the end of the data; anything else bad is CORRUPT. */
imdb_scan_status imdb_frame_scan(const uint8_t *buf, size_t len, size_t off, size_t *frame_len,
                                 imdb_err *e);

/* Tagged segments (design.md §3, "Tagged, preallocated segments"): 512-byte sectors, sector 0 the
 * header, every other one a u64 tag and 504 bytes of payload. A write group's sectors carry the
 * seq of its first frame, its first sector with the top bit too; their payloads are its frames back
 * to back, then zeros. An all-zero sector was never written. */
#define IMDB_TSEG_SECTOR 512u
#define IMDB_TSEG_PAYLOAD 504u
#define IMDB_TSEG_TOP (1ull << 63)
#define IMDB_TSEG_VERSION 1u

/* Sector 0 of the tagged segment named first. */
void imdb_tseg_header(uint64_t first, uint8_t out[IMDB_TSEG_SECTOR]);
/* A segment whose bytes begin "ILT1" is tagged; any other is untagged (frames back to back). */
bool imdb_tseg_is_tagged(const uint8_t *b, size_t n);

/* A write group as the writer lays it out (every frame appended since the log's last fdatasync). */
typedef struct imdb_tgroup {
    uint64_t tag;    /* the seq of its first frame */
    uint64_t sector; /* the index of its first sector */
    uint64_t len;    /* payload bytes so far */
    uint8_t last[IMDB_TSEG_SECTOR]; /* the sector its bytes end in, as written, while len % 504 != 0 */
} imdb_tgroup;
void imdb_tgroup_begin(imdb_tgroup *g, uint64_t tag, uint64_t sector);
/* Adding frame[0..n) touches imdb_tgroup_sectors(g, n) sectors, from imdb_tgroup_at(g) on, each
 * written whole: the first one with the bytes the group already had in it. imdb_tgroup_fill builds
 * count of them, from the from-th, into dst (a large frame is written in pieces); imdb_tgroup_advance
 * then moves the group past the frame. */
uint64_t imdb_tgroup_at(const imdb_tgroup *g);
size_t imdb_tgroup_sectors(const imdb_tgroup *g, size_t n);
void imdb_tgroup_fill(const imdb_tgroup *g, const uint8_t *frame, size_t n, size_t from, size_t count, uint8_t *dst);
void imdb_tgroup_advance(imdb_tgroup *g, const uint8_t *frame, size_t n);
/* All of them in out (replaced), then the advance; on an allocation failure (out's sticky error)
 * the group is unchanged. */
void imdb_tgroup_put(imdb_tgroup *g, const uint8_t *frame, size_t n, imdb_buf *out);
/* The sector after the group's last: where the next group begins. */
uint64_t imdb_tgroup_end(const imdb_tgroup *g);
/* A whole segment for frames[0..len) (whole frames, the first one first): its header, the frames as
 * one group, no fill. Redaction writes a segment so, and tests build them. */
void imdb_tseg_build(uint64_t first, const uint8_t *frames, size_t len, imdb_buf *out);

/* Where a tagged segment's scan ended. E = (keep_sector, keep_bytes): the last kept frame ends after
 * keep_bytes payload bytes of sector keep_sector (keep_bytes 0: at that sector's start). */
typedef struct imdb_tseg_end {
    uint64_t frames; /* frames kept */
    uint64_t last;   /* the last kept frame's seq (first - 1 when none) */
    uint64_t keep_sector;
    uint32_t keep_bytes;
    uint64_t next;   /* the sector the next group begins at, once everything past E is zero */
    uint64_t dirty;  /* one past the last non-zero sector: what dropping a tail zeroes up to */
} imdb_tseg_end;
/* A tagged segment's frames, back to back, moved to the front of b (its untagged form, *len bytes:
 * a frame never lies further on than it was, so no second copy), and the verdict for what follows
 * them: END, TORN, DAMAGED or CORRUPT, by the scan's rules (design.md §3). first is the seq the
 * segment's name gives. b's bytes past *len are no longer the segment's: read the file again for
 * them (recover's saved tail). */
imdb_scan_status imdb_tseg_scan(uint8_t *b, size_t n, uint64_t first, size_t *len, imdb_tseg_end *end, imdb_err *e);

/* A reader that follows a tagged segment as it grows (ship): the next frame begins at payload byte
 * `byte` of sector `sector`, in group `tag` (0: at a sector, between groups); its seq is `next`. */
typedef struct imdb_tseg_pos {
    uint64_t sector;
    uint32_t byte;
    uint64_t tag;
    uint64_t next;
} imdb_tseg_pos;
/* b holds the segment's sectors from sector base on (n bytes, whole sectors). FRAME: the frame at pos,
 * whole and valid, copied to out (replaced), and pos moved past it. END: nothing whole there yet, as
 * far as b shows (a zero sector anywhere on the way, a sector still being rewritten); *more when
 * reading on past b might find it. Never a verdict on what follows: the watermark decides whether
 * stopping short of a commit is an error (a frame it names is never written again). */
imdb_scan_status imdb_tseg_next(const uint8_t *b, size_t n, uint64_t base, imdb_tseg_pos *pos, imdb_buf *out, bool *more);

/* The writer's durable watermark (the DURABLE file at the data directory root):
 * the last commit whose frame the writer saw persisted (fdatasync returned), and
 * that commit's hash. Written in place after every append without its own fsync
 * (it is fsynced at open and close), so after an OS crash it can be older than
 * the true durable point, never newer. synced = false: written under --nosync,
 * where it bounds shipping but proves nothing about durability. strict (--durable-ack): the
 * record was fsynced before any commit it names was acknowledged, so it cannot lag them, and a
 * frame past it was never acknowledged. Flags word: bit 0 synced, bit 1 strict (only with synced). */
#define IMDB_DURABLE_NAME "DURABLE"
#define IMDB_DURABLE_LEN 60
typedef struct imdb_durable {
    uint64_t seq;
    uint8_t head[32];
    bool synced;
    bool strict; /* --durable-ack: fsynced before the commit it names returned (synced too) */
} imdb_durable;
void imdb_durable_encode(const imdb_durable *w, uint8_t out[IMDB_DURABLE_LEN]);
int imdb_durable_decode(const uint8_t *b, size_t n, imdb_durable *w, imdb_err *e);

/* The end of the last segment is damaged or incomplete right after commit
 * `last`. IMDB_OK when that is an unfinished append that recovery may drop; an
 * error when it is damage to (or loss of) a commit the writer acknowledged as
 * durable, or when that cannot be ruled out (a complete frame failing its
 * checksum with no watermark to say it was never acknowledged). */
int imdb_tail_check(const imdb_durable *w, bool have_w, uint64_t last, imdb_scan_status st, const char *what,
                    imdb_err *e);

/* The external anchor (deferred.md R5): a file outside the data directory, on
 * another device or host, naming the latest commit the writer appended, so a
 * directory restored to an older, still valid state is detected at open.
 *   "IMDBANC1" | db id[16] | the commit's own signed descriptor: u64 seq, u32 header
 *   length, commit hash, Ed25519 signature | u32 epoch | u32 0 | CRC32C of the 140 bytes
 * The descriptor is the commit's own, so the writer key in META authenticates it
 * without a signature of its own; commit 0 is the genesis hash, length 0 and no
 * signature. The file holds two such records, at offsets 0 and IMDB_ANCHOR_SLOT: each
 * rewrite goes in place to the other one, so a torn write damages only the record being
 * written and the newest authentic one is the anchor (an older one is a lag, which is
 * safe). It is created atomically (temp, fsync, rename, fsync of its directory), and
 * rewritten after every durable append without an fsync of its own (fsynced at open and
 * close), so after an OS crash it can lag the log, never lead it. */
#define IMDB_ANCHOR_LEN 144
#define IMDB_ANCHOR_SLOT 512
#define IMDB_ANCHOR_FILE (IMDB_ANCHOR_SLOT + IMDB_ANCHOR_LEN)
typedef struct imdb_anchor {
    uint8_t db_id[16];
    uint64_t seq;
    uint32_t hlen;
    uint8_t hash[32];
    uint8_t sig[IMDB_SIG_LEN];
    uint32_t epoch; /* the writer epoch (0 until promotions exist, deferred.md R2) */
} imdb_anchor;
void imdb_anchor_encode(const imdb_anchor *a, uint8_t out[IMDB_ANCHOR_LEN]);
int imdb_anchor_decode(const uint8_t *b, size_t n, imdb_anchor *a, imdb_err *e);
/* The writer signed it (commit 0: the genesis hash of db_id). */
bool imdb_anchor_authentic(const imdb_anchor *a, const uint8_t writer_pk[IMDB_PUBKEY_LEN]);
/* key_of(ctx, epoch): the writer key of that epoch, or NULL when this history has not reached it. */
typedef const uint8_t *(*imdb_anchor_key_fn)(void *ctx, uint32_t epoch);
/* The anchor file's content (n bytes): the newest authentic record (*slot: which), each checked
 * under the key of the epoch it names; false with *bad set when a record decodes but fails
 * authentication, or when none decodes. *ahead: the newest names an epoch key_of does not know
 * (unverifiable here: a newer writer made it). */
bool imdb_anchor_pick(const uint8_t *b, size_t n, imdb_anchor_key_fn key_of, void *ctx, imdb_anchor *a, int *slot,
                      bool *bad, bool *ahead);

#endif
