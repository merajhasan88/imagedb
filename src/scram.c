/* L (N2's records): SCRAM-SHA-256 verifiers (scram.h). */
#include "scram.h"

#include <stdio.h>
#include <string.h>

#include "sha256.h"

static const char b64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static size_t b64_encode(const uint8_t *in, size_t n, char *out)
{
    size_t o = 0;
    for (size_t i = 0; i < n; i += 3) {
        uint32_t w = (uint32_t)in[i] << 16;
        if (i + 1 < n) w |= (uint32_t)in[i + 1] << 8;
        if (i + 2 < n) w |= in[i + 2];
        out[o++] = b64[(w >> 18) & 63];
        out[o++] = b64[(w >> 12) & 63];
        out[o++] = i + 1 < n ? b64[(w >> 6) & 63] : '=';
        out[o++] = i + 2 < n ? b64[w & 63] : '=';
    }
    return o;
}

static int b64_val(char c)
{
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

/* the canonical form alone (one encoding of each byte string): a length a multiple of four, '=' only as the last one
 * or two characters, the bits past the data zero; false otherwise */
static bool b64_decode(const char *in, size_t n, uint8_t *out, size_t cap, size_t *outlen)
{
    if (n == 0 || n % 4) return false;
    size_t pad = in[n - 1] == '=' ? (in[n - 2] == '=' ? 2 : 1) : 0;
    size_t len = n / 4 * 3 - pad;
    if (len > cap) return false;
    size_t o = 0;
    for (size_t i = 0; i < n; i += 4) {
        int v[4];
        for (int k = 0; k < 4; k++) {
            bool padded = i + 4 == n && (size_t)k >= 4 - pad;
            v[k] = padded ? (in[i + k] == '=' ? 0 : -1) : b64_val(in[i + k]);
            if (v[k] < 0) return false;
        }
        uint32_t w = (uint32_t)v[0] << 18 | (uint32_t)v[1] << 12 | (uint32_t)v[2] << 6 | (uint32_t)v[3];
        if (i + 4 == n && pad == 2 && (w & 0xffff)) return false; /* bits past the one byte */
        if (i + 4 == n && pad == 1 && (w & 0xff)) return false;
        out[o++] = (uint8_t)(w >> 16);
        if (o < len) out[o++] = (uint8_t)(w >> 8);
        if (o < len) out[o++] = (uint8_t)w;
    }
    *outlen = len;
    return true;
}

/* HMAC-SHA-256 with its state wiped (its key is a secret here) */
static void hmac_wiped(const uint8_t *key, size_t keylen, const void *msg, size_t n, uint8_t out[32])
{
    imdb_hmac m;
    imdb_hmac_init(&m, key, keylen);
    imdb_hmac_update(&m, msg, n);
    imdb_hmac_final(&m, out);
    imdb_wipe(&m, sizeof m);
}

void imdb_pbkdf2_sha256(const uint8_t *pw, size_t pwlen, const uint8_t *salt, size_t saltlen, uint32_t iter,
                        uint8_t out[IMDB_SCRAM_KEY])
{
    static const uint8_t block1[4] = {0, 0, 0, 1}; /* INT(1): one block of 32 bytes */
    imdb_hmac base, m;
    uint8_t u[32], t[32];
    imdb_hmac_init(&base, pw, pwlen); /* the key's pads once; each iteration copies them */
    m = base;
    imdb_hmac_update(&m, salt, saltlen);
    imdb_hmac_update(&m, block1, sizeof block1);
    imdb_hmac_final(&m, u);
    memcpy(t, u, sizeof t);
    for (uint32_t i = 1; i < iter; i++) {
        m = base;
        imdb_hmac_update(&m, u, sizeof u);
        imdb_hmac_final(&m, u);
        for (int k = 0; k < 32; k++) t[k] ^= u[k];
    }
    memcpy(out, t, sizeof t);
    imdb_wipe(&base, sizeof base);
    imdb_wipe(&m, sizeof m);
    imdb_wipe(u, sizeof u);
    imdb_wipe(t, sizeof t);
}

bool imdb_scram_looks_text(const char *s, size_t len) { return len >= 14 && !memcmp(s, "SCRAM-SHA-256$", 14); }

bool imdb_scram_looks_md5(const char *s, size_t len)
{
    if (len != 35 || memcmp(s, "md5", 3)) return false;
    for (size_t i = 3; i < len; i++)
        if (!((s[i] >= '0' && s[i] <= '9') || (s[i] >= 'a' && s[i] <= 'f'))) return false;
    return true;
}

bool imdb_scram_ok(const imdb_scram *v)
{
    return v->iter >= IMDB_SCRAM_ITER_MIN && v->iter <= IMDB_SCRAM_ITER_MAX && v->salt_len >= IMDB_SCRAM_SALT_MIN &&
           v->salt_len <= IMDB_SCRAM_SALT_MAX;
}

int imdb_scram_make(const char *pw, size_t len, uint32_t iter, const uint8_t *salt, size_t saltlen, imdb_scram *v,
                    imdb_err *e)
{
    if (!len) return imdb_fail(e, IMDB_ERR_INVALID, "an empty password: PASSWORD NULL clears one");
    if (len > IMDB_SCRAM_PW_MAX) return imdb_fail(e, IMDB_ERR_LIMIT, "a password is at most %u bytes", IMDB_SCRAM_PW_MAX);
    for (size_t i = 0; i < len; i++)
        if ((unsigned char)pw[i] < 0x20 || (unsigned char)pw[i] > 0x7e)
            return imdb_fail(e, IMDB_ERR_INVALID,
                             "a password is printable ASCII in imagedb yet (SASLprep's normalization is not in it)");
    if (imdb_scram_looks_md5(pw, len))
        return imdb_fail(e, IMDB_ERR_INVALID,
                         "an MD5 verifier is not taken (it would become the password): give the password or a SCRAM-SHA-256 verifier");
    if (iter < IMDB_SCRAM_ITER_MIN || iter > IMDB_SCRAM_ITER_MAX || saltlen < IMDB_SCRAM_SALT_MIN || saltlen > IMDB_SCRAM_SALT_MAX)
        return imdb_fail(e, IMDB_ERR_INVALID, "a SCRAM verifier takes %u to %u iterations and a salt of %u to %u bytes",
                         IMDB_SCRAM_ITER_MIN, IMDB_SCRAM_ITER_MAX, IMDB_SCRAM_SALT_MIN, IMDB_SCRAM_SALT_MAX);
    memset(v, 0, sizeof *v);
    v->iter = iter;
    v->salt_len = (uint8_t)saltlen;
    if (salt) memcpy(v->salt, salt, saltlen);
    else if (imdb_random(v->salt, saltlen, e)) return e->code;
    uint8_t sp[32], ck[32];
    imdb_pbkdf2_sha256((const uint8_t *)pw, len, v->salt, saltlen, iter, sp);
    hmac_wiped(sp, sizeof sp, "Client Key", 10, ck);
    imdb_sha256_ctx sc; /* the client key passes through the hash's buffer: its context wiped too */
    imdb_sha256_init(&sc);
    imdb_sha256_update(&sc, ck, sizeof ck);
    imdb_sha256_final(&sc, v->stored);
    imdb_wipe(&sc, sizeof sc);
    hmac_wiped(sp, sizeof sp, "Server Key", 10, v->server);
    imdb_wipe(sp, sizeof sp);
    imdb_wipe(ck, sizeof ck);
    return IMDB_OK;
}

static int text_bad(imdb_err *e)
{
    return imdb_fail(e, IMDB_ERR_INVALID,
                     "a SCRAM-SHA-256 verifier is SCRAM-SHA-256$<iterations>:<salt>$<StoredKey>:<ServerKey> (iterations %u to "
                     "%u, a salt of %u to %u bytes, keys of 32, each in base64 with its padding)",
                     IMDB_SCRAM_ITER_MIN, IMDB_SCRAM_ITER_MAX, IMDB_SCRAM_SALT_MIN, IMDB_SCRAM_SALT_MAX);
}

/* the next field: up to stop (or the end when stop is 0), past it */
static bool field(const char *s, size_t len, size_t *at, char stop, size_t *fo, size_t *fn)
{
    size_t i = *at;
    while (i < len && s[i] != stop) i++;
    if (stop ? i == len : false) return false;
    *fo = *at;
    *fn = i - *at;
    *at = stop ? i + 1 : i;
    return true;
}

int imdb_scram_parse(const char *s, size_t len, imdb_scram *v, imdb_err *e)
{
    memset(v, 0, sizeof *v);
    if (!imdb_scram_looks_text(s, len) || len >= IMDB_SCRAM_TEXT_MAX) return text_bad(e);
    size_t at = 14, fo, fn;
    if (!field(s, len, &at, ':', &fo, &fn) || fn == 0 || fn > 7 || s[fo] == '0') return text_bad(e);
    uint32_t it = 0;
    for (size_t i = 0; i < fn; i++) {
        if (s[fo + i] < '0' || s[fo + i] > '9') return text_bad(e);
        it = it * 10 + (uint32_t)(s[fo + i] - '0');
    }
    v->iter = it;
    size_t n = 0;
    if (!field(s, len, &at, '$', &fo, &fn) || !b64_decode(s + fo, fn, v->salt, sizeof v->salt, &n)) return text_bad(e);
    v->salt_len = (uint8_t)n;
    if (!field(s, len, &at, ':', &fo, &fn) || !b64_decode(s + fo, fn, v->stored, sizeof v->stored, &n) || n != 32)
        return text_bad(e);
    if (!field(s, len, &at, 0, &fo, &fn) || !b64_decode(s + fo, fn, v->server, sizeof v->server, &n) || n != 32 || at != len)
        return text_bad(e);
    if (!imdb_scram_ok(v)) return text_bad(e);
    return IMDB_OK;
}

size_t imdb_scram_format(const imdb_scram *v, char *out, size_t cap)
{
    char salt[92], sk[48], vk[48];
    salt[b64_encode(v->salt, v->salt_len, salt)] = '\0';
    sk[b64_encode(v->stored, 32, sk)] = '\0';
    vk[b64_encode(v->server, 32, vk)] = '\0';
    int n = snprintf(out, cap, "SCRAM-SHA-256$%u:%s$%s:%s", v->iter, salt, sk, vk);
    return n < 0 || (size_t)n >= cap ? 0 : (size_t)n;
}

size_t imdb_scram_encode(const imdb_scram *v, uint8_t out[IMDB_SCRAM_BYTES_MAX])
{
    size_t o = 0;
    for (int k = 0; k < 4; k++) out[o++] = (uint8_t)(v->iter >> (8 * k));
    out[o++] = v->salt_len;
    memcpy(out + o, v->salt, v->salt_len);
    o += v->salt_len;
    memcpy(out + o, v->stored, 32);
    o += 32;
    memcpy(out + o, v->server, 32);
    return o + 32;
}

int imdb_scram_decode(const uint8_t *p, size_t len, imdb_scram *v, imdb_err *e)
{
    memset(v, 0, sizeof *v);
    if (len < 5) return imdb_fail(e, IMDB_ERR_CORRUPT, "a role's verifier: truncated");
    v->iter = (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
    v->salt_len = p[4];
    if (!imdb_scram_ok(v) || len != 5u + v->salt_len + 64u)
        return imdb_fail(e, IMDB_ERR_CORRUPT, "a role's verifier: its iterations, salt or length out of bounds");
    memcpy(v->salt, p + 5, v->salt_len);
    memcpy(v->stored, p + 5 + v->salt_len, 32);
    memcpy(v->server, p + 5 + v->salt_len + 32, 32);
    return IMDB_OK;
}
