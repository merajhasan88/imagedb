/* Encrypted backups (P0; docs/plan-p0.md, design.md "Backup and restore").
 *
 * A backup is the replication stream in a file: what `ship` sends a new replica (from commit 1, or a seed past a
 * log cut and then the commits after it), sealed in chunks with XChaCha20-Poly1305 (Monocypher's crypto_aead_lock,
 * the standard construction) under a key file. Restore is a replica's apply of those bytes into a new directory,
 * so every commit's signature, chain and digest is checked as a replica checks it. The copy is a replica: it holds
 * no writer key (none is in a backup); `imagedb promote` with the offline root key makes it writable.
 *
 * The file, every integer little-endian, decoded strictly:
 *   PROLOGUE (IMDB_BACKUP_PROLOGUE bytes, in the clear):
 *     magic "IMDBBAK1" | u32 version 1 | u32 kind (1 full, 2 incremental) | db_id[16] | u8 digest_alg | u8 has_root
 *     | 6 zero bytes | writer[32] (META's epoch-0 key) | root[32] (zeros when none) | u64 prev_seq | prev_hash[32]
 *     (an incremental's previous backup's last commit; zeros in a full) | nonce_prefix[16] | key_id[32] | u32 chunk
 *     maximum (IMDB_BACKUP_CHUNK) | u32 0
 *   CHUNKS, each: u32 plaintext length | u8 flags | 3 zero bytes | ciphertext | tag[16]
 *     nonce = nonce_prefix || le64(index); additional data = SHA-256(prologue) || le64(index) || flags || le32(length)
 *     flags: END_PART (the last chunk of a part), END_FILE (the summary, alone, after the last part's END_PART)
 *   SUMMARY (the END_FILE chunk's plaintext): u32 version 1 | u32 parts | u64 first_seq | u64 last_seq |
 *     last_hash[32] | u64 seed_seq (0: none) | u64 chunks (before the summary) | u64 payload bytes
 *   Nothing after the summary. A chunk moved, dropped, repeated or taken from another file fails its tag; a file
 *   that ends before its summary is incomplete, never a shorter backup.
 * Parts: a full backup is one part (the frames from commit 1), or two past a log cut (the seed, then the frames
 * after its commit), each applied by its own apply call with a reopen between; an incremental is one part. */
#ifndef IMDB_BACKUP_H
#define IMDB_BACKUP_H

#include <stdbool.h>
#include <stdint.h>

#include "db.h"
#include "util.h"

#define IMDB_BACKUP_KEY_LEN   32u
#define IMDB_BACKUP_PROLOGUE  200u
#define IMDB_BACKUP_CHUNK_HDR 8u
#define IMDB_BACKUP_TAG       16u
#define IMDB_BACKUP_SUMMARY   80u
#define IMDB_BACKUP_END_PART  1u
#define IMDB_BACKUP_END_FILE  2u

typedef struct imdb_backup_info {
    imdb_identity id;           /* from the prologue */
    bool incremental;
    uint64_t prev_seq;          /* an incremental's previous backup's last commit */
    uint8_t prev_hash[32];
    uint64_t first_seq, last_seq; /* the commits it holds (first_seq the seed's, past a cut); last 0: none */
    uint8_t last_hash[32];
    uint64_t seed_seq;          /* 0: no seed */
    uint32_t parts;
    uint64_t chunks, payload_bytes;
} imdb_backup_info;

/* A new key file at path (32 random bytes, 0400, created exclusively, its directory synced: an operator's path,
 * imdb_open_parent); id: the key's identifier, printed for the operator. */
int imdb_backup_key_create(const char *path, uint8_t id[32], imdb_err *e);
/* Reads a key file: a regular file of exactly IMDB_BACKUP_KEY_LEN bytes, not a symlink. */
int imdb_backup_key_load(const char *path, uint8_t key[IMDB_BACKUP_KEY_LEN], imdb_err *e);
/* The key's identifier: SHA-256 of a domain string and the key (it names the key, it reveals nothing of it). */
void imdb_backup_key_id(const uint8_t key[IMDB_BACKUP_KEY_LEN], uint8_t id[32]);

/* A full backup of the database at src (a primary or a replica; online: what is durable while it runs) into out,
 * written as out.tmp, synced, renamed, its directory synced. An existing out is refused. */
int imdb_backup_full(const char *src, const char *out, const uint8_t key[IMDB_BACKUP_KEY_LEN], imdb_backup_info *info,
                     imdb_err *e);

/* Reads and checks a whole backup file without applying it: the prologue, every chunk's tag, the order and the
 * summary. info: what it holds. */
int imdb_backup_check(const char *file, const uint8_t key[IMDB_BACKUP_KEY_LEN], imdb_backup_info *info, imdb_err *e);

/* Restores backups (a full one, then incrementals in order) into dest, a new directory: every file is checked
 * whole first (imdb_backup_check), then applied into dest.tmp as a replica applies a stream, made durable, and
 * renamed to dest. dest or dest.tmp existing is refused. *info: the last file's, with the restored commit. */
int imdb_restore(const char *dest, const uint8_t key[IMDB_BACKUP_KEY_LEN], const char *const *files, size_t nfiles,
                 imdb_backup_info *info, imdb_err *e);

/* Tests only: fn runs between a seeded backup's two parts (where a RETIRE's log cut makes the backup try again). */
void imdb_backup_test_between(void (*fn)(void *ctx), void *ctx);

/* A test restore (the backup's verification): the files restored into a new directory under scratch, VERIFY run
 * on the copy (rep), the copy removed whatever happened. */
int imdb_backup_verify(const char *scratch, const uint8_t key[IMDB_BACKUP_KEY_LEN], const char *const *files,
                       size_t nfiles, imdb_backup_info *info, imdb_verify_report *rep, imdb_err *e);

#endif
