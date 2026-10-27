/*
 * LtHash16-1024: a homomorphic multiset hash (Bellare–Micciancio lattice hash,
 * parameters as Facebook/Folly's LtHash16_1024, quoted there as ">200 bits of
 * security"). imagedb instantiates the element hash itself, in one of two ways a
 * database chooses once (its digest algorithm, META and every commit header):
 *   digest_alg 1: an element is MGF1-SHA256 of the commitment, and the state's
 *     32-byte digest SHA-256 over the 2048 lane bytes, so independent verifiers
 *     need only SHA-256;
 *   digest_alg 2: an element is ChaCha20's keystream under SHA-256 of the
 *     commitment, and the digest a tree of SHA-256: eight leaves of 256 lane
 *     bytes, hashed side by side, then their root (ten SHA-256 blocks on the
 *     digest's critical path instead of 33; docs/plan-round3.md has the measures).
 *
 *   H(multiset) = sum over elements x of  expand(x)  (1024 lanes, mod 2^16)
 *
 * add/sub are element-wise, so the digest of a set of row versions does not
 * depend on order, segment layout, or compaction: that is what lets the DB
 * view, the lake view, a replica and an external verifier agree on one value.
 */
#ifndef IMDB_LTHASH_H
#define IMDB_LTHASH_H

#include <stdbool.h>
#include <stdint.h>

#include "sha256.h"

#define IMDB_LTHASH_LANES 1024
#define IMDB_LTHASH_BYTES 2048

typedef struct imdb_lthash {
    _Alignas(32) uint16_t v[IMDB_LTHASH_LANES];
} imdb_lthash;

void imdb_lthash_zero(imdb_lthash *h);
bool imdb_lthash_is_zero(const imdb_lthash *h);
/* element = a 32-byte row commitment, expanded by digest algorithm alg (IMDB_DIGEST_ALG_*, log.h):
 *   1: the lanes are MGF1-SHA256("IMDBLT16" || commit), 2048 bytes
 *   2: the lanes are ChaCha20 (RFC 8439) under the commitment itself as the key, nonce "IMDBLT20"
 *      then four zero bytes, blocks 0..31
 * (lanes little-endian u16 over the bytes, in both) */
void imdb_lthash_element(uint8_t alg, const uint8_t commit[IMDB_HASH_LEN], imdb_lthash *out);
void imdb_lthash_add(imdb_lthash *acc, const imdb_lthash *x);
void imdb_lthash_sub(imdb_lthash *acc, const imdb_lthash *x);
void imdb_lthash_add_commit(uint8_t alg, imdb_lthash *acc, const uint8_t commit[IMDB_HASH_LEN]);
void imdb_lthash_sub_commit(uint8_t alg, imdb_lthash *acc, const uint8_t commit[IMDB_HASH_LEN]);
/* 32-byte summary of the lanes (as little-endian u16):
 *   1: SHA256("IMDBLTD1" || lanes)
 *   2: SHA256("IMDBLTR2" || leaf_0 || ... || leaf_7), leaf_i = SHA256("IMDBLTL2" || u32 i
 *      little-endian || lane bytes 256 i .. 256 i + 255) */
void imdb_lthash_digest(uint8_t alg, const imdb_lthash *h, uint8_t out[IMDB_HASH_LEN]);
void imdb_lthash_to_bytes(const imdb_lthash *h, uint8_t out[IMDB_LTHASH_BYTES]);
void imdb_lthash_from_bytes(imdb_lthash *h, const uint8_t in[IMDB_LTHASH_BYTES]);

#endif
