/*
 * Verification-only cryptography for imagedb-audit, written from the
 * specifications (FIPS 180-4, RFC 8032, RFC 8439, Castagnoli CRC) and sharing no code
 * with the engine (src/ uses its own SHA-256 and the vendored Monocypher).
 * Nothing here handles secrets, so nothing needs to be constant-time.
 * tests/unit/t_audit_crypto.c checks every function against OpenSSL and
 * against the engine's implementations.
 */
#ifndef AUDIT_ACRYPTO_H
#define AUDIT_ACRYPTO_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct a_sha256 {
    uint32_t h[8];
    uint64_t n;
    uint8_t buf[64];
    size_t used;
} a_sha256_ctx;

void a_sha256_init(a_sha256_ctx *c);
void a_sha256_update(a_sha256_ctx *c, const void *p, size_t n);
void a_sha256_final(a_sha256_ctx *c, uint8_t out[32]);
void a_sha256(const void *p, size_t n, uint8_t out[32]);

typedef struct a_sha512 {
    uint64_t h[8];
    uint64_t n;
    uint8_t buf[128];
    size_t used;
} a_sha512_ctx;

void a_sha512_init(a_sha512_ctx *c);
void a_sha512_update(a_sha512_ctx *c, const void *p, size_t n);
void a_sha512_final(a_sha512_ctx *c, uint8_t out[64]);

uint32_t a_crc32c(const void *p, size_t n);

/* Ed25519 verification with the rule imagedb's engine uses (Monocypher 4):
 * S < L; A and R must decode to curve points (non-canonical encodings are
 * accepted); [8]([S]B - [h]A - R) must be the identity. */
bool a_ed25519_verify(const uint8_t pk[32], const void *msg, size_t n, const uint8_t sig[64]);

/* ChaCha20's block function (RFC 8439, section 2.3): the 64 keystream bytes of block counter. */
void a_chacha20_block(const uint8_t key[32], uint32_t counter, const uint8_t nonce[12], uint8_t out[64]);

/* LtHash16-1024 element, 2048 bytes read as 1024 little-endian 16-bit lanes, by the database's
 * digest algorithm: 1, MGF1-SHA256 of "IMDBLT16" || commitment; 2, ChaCha20 under the commitment
 * itself as the key, nonce "IMDBLT20" then four zero bytes, blocks 0..31. */
void a_lthash_element(uint8_t alg, const uint8_t commit[32], uint16_t lanes[1024]);

#endif
