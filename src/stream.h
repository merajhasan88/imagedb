/*
 * Staged, authenticate-before-decode reader for commit streams
 * (`imagedb ship | imagedb apply`, and the daemon's follower).
 *
 * v0.1 allocated a whole frame from an unauthenticated length and decoded it
 * before checking its MAC (CVE class I: pre-authentication processing). Here
 * every byte is authenticated before anything depends on it:
 *
 *   1. 16-byte prefix: magic and its own CRC; nothing is allocated.
 *   2. 109-byte descriptor (kind, header length, seq, commit hash, signature):
 *      the header length must be in range and seq must be the expected
 *      commit, then the Ed25519 signature is verified, under the current
 *      writer key (a WRITER_KEY commit moves it for the next one). A
 *      promotion (kind 3) adds 100 bytes: its root certificate is verified
 *      first, then the signature under the key it certifies. This is the only
 *      work done on unauthenticated bytes (125 of them, 225 for a promotion).
 *   3. The header (its length is now signed) must hash to the signed commit
 *      hash before it is decoded; its prev must be the replica's head.
 *   4. The payload length must fit the authenticated header's ops.
 *   5. Payload rows are read one at a time (each <= IMDB_MAX_ROW) and each
 *      must match its signed row commitment before the next is read.
 *   6. The frame CRC from the prefix must match the authenticated bytes.
 *
 * Residual risk (documented): payloads are redactable, so an on-path attacker
 * can replace a row by a "redacted" marker. The replica then holds a stub
 * awaiting an ERASE that never comes; VERIFY fails while any such stub
 * exists, and apply reports them.
 */
#ifndef IMDB_STREAM_H
#define IMDB_STREAM_H

#include <stdbool.h>
#include <stdint.h>

#include "log.h"
#include "util.h"

/* Reads up to n bytes; *got < n only at end of input. */
typedef int (*imdb_read_fn)(void *ctx, void *buf, size_t n, size_t *got, imdb_err *e);

typedef struct imdb_stream {
    imdb_read_fn read;
    void *ctx;
    uint8_t writer_pk[IMDB_PUBKEY_LEN]; /* the current writer key: a WRITER_KEY commit moves it */
    uint8_t db_id[16];        /* imdb_stream_set_trust: what a promotion's root certificate names */
    bool has_root;
    uint8_t root[IMDB_PUBKEY_LEN];
    imdb_buf frame;           /* the current frame: prefix + body, all authenticated */
    uint64_t frames;
    uint64_t preauth_bytes;   /* bytes read before the last signature check (tests) */
    bool truncated;           /* the last error: the input ended inside a frame (a dropped connection) */
    uint8_t back[IMDB_FRAME_HDR]; /* bytes imdb_stream_session read ahead: the first frame's */
    size_t nback;
} imdb_stream;

void imdb_stream_init(imdb_stream *s, const uint8_t writer_pk[IMDB_PUBKEY_LEN], imdb_read_fn read, void *ctx);
void imdb_stream_free(imdb_stream *s);
/* The database and its root key (NULL: none), without which a promotion (body kind 3) is refused. */
void imdb_stream_set_trust(imdb_stream *s, const uint8_t db_id[16], const uint8_t *root);
/* First, on a stream that may begin with one (ship --acks, repl.h): its session record, before
 * any frame (db_id from imdb_stream_set_trust). *have: there was one, and nonce is set; otherwise
 * the bytes read belong to the first frame, and imdb_stream_next starts with them. A damaged
 * record, or another database's, is an error. */
int imdb_stream_session(imdb_stream *s, uint8_t nonce[16], bool *have, imdb_err *e);
/* Reads the next frame, which must be commit expect_seq chaining to prev.
 * *eof is set at a clean end of stream (between frames). */
int imdb_stream_next(imdb_stream *s, uint64_t expect_seq, const uint8_t prev[32], bool *eof, imdb_err *e);

/* imdb_read_fn over a file descriptor (ctx = int *). */
int imdb_stream_fd_read(void *ctx, void *buf, size_t n, size_t *got, imdb_err *e);

/* The same, buffered: one fixed buffer, refilled by a single read() at a time,
 * so a follower never waits for more than the pipe holds and a row costs no
 * system call of its own. Read-ahead lands only in this buffer: the reader still
 * parses and allocates nothing before a frame is authenticated. */
typedef struct imdb_fdsrc {
    int fd;
    size_t off, len;
    uint8_t buf[1u << 16];
} imdb_fdsrc;
void imdb_fdsrc_init(imdb_fdsrc *s, int fd);
int imdb_fdsrc_read(void *ctx, void *buf, size_t n, size_t *got, imdb_err *e);

#endif
