/*
 * Ed25519 (RFC 8032, SHA-512) commit signatures.
 *
 * Two implementations, which must agree byte for byte: the engine's fast path
 * (src/ed25519.c, the default) and the vendored Monocypher 4.0.3 (the
 * reference, src/vendor/monocypher; its README states the verification rule).
 * IMDB_NO_SIMD=1 selects Monocypher, like every other reference kernel. Signing
 * is deterministic, so either writes the same signature, and both accept and
 * reject exactly the same inputs (tests/unit/t_ed25519.c). The fast path checks
 * itself against an RFC 8032 vector at first use and stops the process if it
 * disagrees.
 *
 * The writer's 32-byte seed lives only on the primary (signing.key, 0600).
 * Replicas, auditors and the replica handshake need only public keys, so no
 * holder of a copy can forge a commit (gap 4 of v0.1: a shared HMAC key).
 */
#ifndef IMDB_SIGN_H
#define IMDB_SIGN_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define IMDB_SEED_LEN 32
#define IMDB_PUBKEY_LEN 32
#define IMDB_SIG_LEN 64

typedef struct imdb_signer {
    uint8_t sk[64];     /* seed || public key (Monocypher's layout) */
    uint8_t pk[IMDB_PUBKEY_LEN];
    uint8_t a[32];      /* clamped secret scalar (fast path) */
    uint8_t prefix[32]; /* nonce key (fast path) */
} imdb_signer;

/* Derives the key pair; seed is left untouched (a copy is wiped). */
void imdb_signer_init(imdb_signer *s, const uint8_t seed[IMDB_SEED_LEN]);
void imdb_signer_wipe(imdb_signer *s);
void imdb_sign(const imdb_signer *s, const void *msg, size_t n, uint8_t sig[IMDB_SIG_LEN]);
/* True iff sig is a valid signature of msg under pk. Variable time: only
 * public data is involved. */
bool imdb_sig_verify(const uint8_t pk[IMDB_PUBKEY_LEN], const void *msg, size_t n,
                     const uint8_t sig[IMDB_SIG_LEN]);
/* n signatures under one key; ok[i] gets each verdict, as imdb_sig_verify would give it
 * (the fast path batches them: ed25519.h states the bound; the reference checks each). */
bool imdb_sig_verify_batch(const uint8_t pk[IMDB_PUBKEY_LEN], size_t n, const uint8_t *const msgs[], const size_t lens[],
                           const uint8_t *const sigs[], bool ok[]);
void imdb_sha512(const void *p, size_t n, uint8_t out[64]);

#endif
