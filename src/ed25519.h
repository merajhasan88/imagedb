/*
 * Ed25519 (RFC 8032, SHA-512): the engine's fast implementation.
 *
 * Monocypher (src/vendor/monocypher) is the reference: signatures must be
 * byte-identical to it (Ed25519 signing is deterministic) and verification
 * must give the same verdict on every input, including the non-canonical
 * encodings Monocypher accepts (see its README). IMDB_NO_SIMD=1 makes
 * sign.c use Monocypher instead, and the tests compare the two directly.
 *
 * Signing runs in constant time: no branch or memory index depends on the
 * secret scalar, the nonce or their intermediate values. Verification uses
 * only public data and is variable time.
 */
#ifndef IMDB_ED25519_H
#define IMDB_ED25519_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* seed -> clamped secret scalar a, nonce prefix, public key A = [a]B. */
void imdb_ed25519_expand(const uint8_t seed[32], uint8_t a[32], uint8_t prefix[32], uint8_t pk[32]);
void imdb_ed25519_sign(uint8_t sig[64], const uint8_t a[32], const uint8_t prefix[32], const uint8_t pk[32],
                       const void *msg, size_t n);
bool imdb_ed25519_verify(const uint8_t sig[64], const uint8_t pk[32], const void *msg, size_t n);
/* n signatures under one key: ok[i] is imdb_ed25519_verify's verdict on signature i;
 * true iff all are valid. One multi-scalar multiplication per group of 64 with
 * random 128-bit coefficients (getrandom); a group that fails is re-checked one
 * signature at a time. A rejection is therefore always exact, and an acceptance is
 * wrong with probability at most 2^-127 per group, over the coefficients: a design
 * claim, the standard bound for random linear combinations under the assumptions
 * ed25519.c states (uniform 128-bit coefficients, the cofactored equation), not
 * independently proven or reviewed by a specialist (review of 2026-10-22). Without
 * randomness every signature is checked alone; IMDB_NO_SIMD=1 checks each one alone
 * with the Monocypher reference. */
bool imdb_ed25519_verify_batch(size_t n, const uint8_t *const sigs[], const uint8_t pk[32], const uint8_t *const msgs[],
                               const size_t lens[], bool ok[]);
/* Tests: false runs the batch on the scalar field even where AVX2 exists. */
void imdb_ed25519_set_fe4(bool on);
/* The same with the caller's coefficients (16 bytes each, n of them; tests only). */
bool imdb_ed25519_verify_batch_z(size_t n, const uint8_t *const sigs[], const uint8_t pk[32],
                                 const uint8_t *const msgs[], const size_t lens[], const uint8_t *z, bool ok[]);

/* ---- exposed for the tests (differential checks layer by layer) ------------- */
enum { IMDB_FE_MUL, IMDB_FE_SQ, IMDB_FE_ADD, IMDB_FE_SUB, IMDB_FE_NEG, IMDB_FE_INV, IMDB_FE_POW22523, IMDB_FE_CARRY };
/* Raw field arithmetic on 5 limbs of 51 bits (inputs within each op's bounds). */
void imdb_fe25519_op(int op, uint64_t h[5], const uint64_t f[5], const uint64_t g[5]);
void imdb_fe25519_tobytes(uint8_t s[32], const uint64_t f[5]);
void imdb_fe25519_frombytes(uint64_t h[5], const uint8_t s[32]);
/* The four-way AVX2 field (radix 2^25.5, lane k = element k: [lane][limb]); false without AVX2. */
bool imdb_fe4_available(void);
bool imdb_fe4_op(int op, uint64_t h[4][10], const uint64_t f[4][10], const uint64_t g[4][10]);
/* Four radix-2^51 elements packed into the lanes and back. */
bool imdb_fe4_roundtrip(uint64_t out[4][5], const uint64_t in[4][5]);
/* P + Q, P - Q and 2P by the vertical four-way formulas (false without AVX2 or if P or Q does not decode). */
bool imdb_ed25519_gev_ops(uint8_t sum[32], uint8_t dif[32], uint8_t dbl[32], const uint8_t p[32], const uint8_t q[32]);
/* The derived constants, canonical little-endian: d, sqrt(-1), B's y and x. */
void imdb_ed25519_constants(uint8_t d[32], uint8_t sqrtm1[32], uint8_t by[32], uint8_t bx[32]);
/* [k]B encoded: by the constant-time comb (k < 2^255) and by plain double-and-add. */
void imdb_ed25519_scalarbase(uint8_t out[32], const uint8_t k[32]);
void imdb_ed25519_scalarbase_slow(uint8_t out[32], const uint8_t k[32]);
/* [k]P for an encoded point P (decoded as verification does; false if it does not decode). */
bool imdb_ed25519_scalarmult_slow(uint8_t out[32], const uint8_t k[32], const uint8_t p[32]);
/* Width-w NAF of s (257 digits; returns the top nonzero position), and [s]B + [h]P. */
int imdb_ed25519_wnaf(int8_t r[257], const uint8_t s[32], int w);
bool imdb_ed25519_double_scalarmult(uint8_t out[32], const uint8_t s[32], const uint8_t h[32], const uint8_t p[32]);
/* Scalars mod L: out = in mod L (64-byte input), and s = (a*b + c) mod L. */
void imdb_sc25519_reduce(uint8_t out[32], const uint8_t in[64]);
void imdb_sc25519_muladd(uint8_t s[32], const uint8_t a[32], const uint8_t b[32], const uint8_t c[32]);

#endif
