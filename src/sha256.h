/* SHA-256 (FIPS 180-4) and HMAC-SHA256 (RFC 2104). Portable C; no dependencies. */
#ifndef IMDB_SHA256_H
#define IMDB_SHA256_H

#include <stddef.h>
#include <stdint.h>

#define IMDB_HASH_LEN 32

typedef struct imdb_sha256_ctx {
    uint32_t h[8];
    uint64_t nbytes;
    uint8_t buf[64];
    size_t buflen;
} imdb_sha256_ctx;

extern const uint32_t imdb_sha256_k[64];
extern const uint32_t imdb_sha256_iv[8];

void imdb_sha256_init(imdb_sha256_ctx *c);
void imdb_sha256_update(imdb_sha256_ctx *c, const void *p, size_t n);
void imdb_sha256_final(imdb_sha256_ctx *c, uint8_t out[IMDB_HASH_LEN]);
void imdb_sha256(const void *p, size_t n, uint8_t out[IMDB_HASH_LEN]);
/* One compression of a 64-byte block (big-endian words) into state h. */
void imdb_sha256_compress(uint32_t h[8], const uint8_t block[64]);

typedef struct imdb_hmac {
    imdb_sha256_ctx inner, outer;
} imdb_hmac;

void imdb_hmac_init(imdb_hmac *m, const uint8_t *key, size_t keylen);
void imdb_hmac_update(imdb_hmac *m, const void *p, size_t n);
void imdb_hmac_final(imdb_hmac *m, uint8_t out[IMDB_HASH_LEN]);
void imdb_hmac_sha256(const uint8_t *key, size_t keylen, const void *p, size_t n,
                      uint8_t out[IMDB_HASH_LEN]);

#endif
