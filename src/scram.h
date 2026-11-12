/* L (N2's records): SCRAM-SHA-256 verifiers as PostgreSQL makes, stores and dumps them (RFC 5802, RFC 7677):
 * PBKDF2-HMAC-SHA-256 (RFC 8018), StoredKey and ServerKey, PostgreSQL's verifier text and a role payload entry's bytes.
 * A password is never kept: the engine's copies of it and every intermediate are wiped (imdb_wipe). */
#ifndef IMDB_SCRAM_H
#define IMDB_SCRAM_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "util.h"

#define IMDB_SCRAM_KEY 32
#define IMDB_SCRAM_SALT_MIN 8
#define IMDB_SCRAM_SALT_MAX 64
#define IMDB_SCRAM_SALT_NEW 16    /* a verifier the engine makes: PostgreSQL's salt length */
#define IMDB_SCRAM_ITER_MIN 1000u
#define IMDB_SCRAM_ITER_MAX 1000000u
#define IMDB_SCRAM_ITER_NEW 4096u /* PostgreSQL's default */
#define IMDB_SCRAM_PW_MAX 1024u   /* a password's bytes */
/* the longest text: "SCRAM-SHA-256$" 14, iterations 7, ":" 1, a 64-byte salt's base64 88, "$" 1, two keys' 44 and ":" 1:
 * 200 bytes, and a NUL */
#define IMDB_SCRAM_TEXT_MAX 208u
/* a payload entry's bytes: u32 iterations | u8 salt length | salt | StoredKey | ServerKey */
#define IMDB_SCRAM_BYTES_MAX (4u + 1u + IMDB_SCRAM_SALT_MAX + 2u * IMDB_SCRAM_KEY)

typedef struct imdb_scram {
    uint32_t iter;
    uint8_t salt_len;
    uint8_t salt[IMDB_SCRAM_SALT_MAX];
    uint8_t stored[IMDB_SCRAM_KEY];
    uint8_t server[IMDB_SCRAM_KEY];
} imdb_scram;

/* PBKDF2-HMAC-SHA-256, one block (dkLen 32): any iteration count (the tests' vectors take 1) */
void imdb_pbkdf2_sha256(const uint8_t *pw, size_t pwlen, const uint8_t *salt, size_t saltlen, uint32_t iter,
                        uint8_t out[IMDB_SCRAM_KEY]);
/* a verifier from a password of 1 to IMDB_SCRAM_PW_MAX printable ASCII bytes (SASLprep's normalization is not in
 * imagedb yet), never an MD5 verifier's text; iterations within the bounds; salt NULL: IMDB_SCRAM_SALT_NEW random bytes */
int imdb_scram_make(const char *pw, size_t len, uint32_t iter, const uint8_t *salt, size_t saltlen, imdb_scram *v,
                    imdb_err *e);
/* PASSWORD's text taken as a verifier, never as a password: it begins "SCRAM-SHA-256$" */
bool imdb_scram_looks_text(const char *s, size_t len);
/* PostgreSQL's MD5 verifier ("md5" and 32 lowercase hex digits), refused by name: hashed as a password, the hash would
 * become one */
bool imdb_scram_looks_md5(const char *s, size_t len);
/* PostgreSQL's text, strictly: SCRAM-SHA-256$<iterations>:<salt>$<StoredKey>:<ServerKey>, base64 with its padding and
 * no other bits, iterations without a leading zero; no message holds the text */
int imdb_scram_parse(const char *s, size_t len, imdb_scram *v, imdb_err *e);
/* the text, NUL-terminated (cap >= IMDB_SCRAM_TEXT_MAX); its length */
size_t imdb_scram_format(const imdb_scram *v, char *out, size_t cap);
bool imdb_scram_ok(const imdb_scram *v);
/* a payload entry's bytes and back (strict: exact length, the bounds) */
size_t imdb_scram_encode(const imdb_scram *v, uint8_t out[IMDB_SCRAM_BYTES_MAX]);
int imdb_scram_decode(const uint8_t *p, size_t len, imdb_scram *v, imdb_err *e);

#endif
