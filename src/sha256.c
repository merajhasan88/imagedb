#include "sha256.h"

#include <string.h>

#include "util.h"

/* Constants generated from integer cube/square roots of the first primes
 * (see FIPS 180-4 §4.2.2, §5.3.3); verified against OpenSSL in tests. */
const uint32_t imdb_sha256_k[64] = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u, 0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u,
    0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u, 0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u,
    0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu, 0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
    0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u, 0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u,
    0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u, 0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
    0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u, 0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
    0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u, 0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
    0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u, 0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u,
};

const uint32_t imdb_sha256_iv[8] = {
    0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au, 0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u,
};

static inline uint32_t ror(uint32_t x, int n) { return x >> n | x << (32 - n); }

void imdb_sha256_compress(uint32_t h[8], const uint8_t blk[64])
{
    uint32_t w[64];
    for (int i = 0; i < 16; i++)
        w[i] = (uint32_t)blk[4 * i] << 24 | (uint32_t)blk[4 * i + 1] << 16 |
               (uint32_t)blk[4 * i + 2] << 8 | blk[4 * i + 3];
    for (int i = 16; i < 64; i++) {
        uint32_t s0 = ror(w[i - 15], 7) ^ ror(w[i - 15], 18) ^ (w[i - 15] >> 3);
        uint32_t s1 = ror(w[i - 2], 17) ^ ror(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    uint32_t a = h[0], b = h[1], c = h[2], d = h[3], e = h[4], f = h[5], g = h[6], hh = h[7];
    for (int i = 0; i < 64; i++) {
        uint32_t S1 = ror(e, 6) ^ ror(e, 11) ^ ror(e, 25);
        uint32_t ch = (e & f) ^ (~e & g);
        uint32_t t1 = hh + S1 + ch + imdb_sha256_k[i] + w[i];
        uint32_t S0 = ror(a, 2) ^ ror(a, 13) ^ ror(a, 22);
        uint32_t mj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t t2 = S0 + mj;
        hh = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }
    h[0] += a; h[1] += b; h[2] += c; h[3] += d;
    h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
}

void imdb_sha256_init(imdb_sha256_ctx *c)
{
    memcpy(c->h, imdb_sha256_iv, sizeof c->h);
    c->nbytes = 0;
    c->buflen = 0;
    memset(c->buf, 0, sizeof c->buf);
}

void imdb_sha256_update(imdb_sha256_ctx *c, const void *p, size_t n)
{
    const uint8_t *in = p;
    c->nbytes += n;
    if (c->buflen) {
        size_t take = 64 - c->buflen;
        if (take > n) take = n;
        memcpy(c->buf + c->buflen, in, take);
        c->buflen += take;
        in += take;
        n -= take;
        if (c->buflen < 64) return;
        imdb_sha256_compress(c->h, c->buf);
        c->buflen = 0;
    }
    while (n >= 64) {
        imdb_sha256_compress(c->h, in);
        in += 64;
        n -= 64;
    }
    if (n) {
        memcpy(c->buf, in, n);
        c->buflen = n;
    }
}

void imdb_sha256_final(imdb_sha256_ctx *c, uint8_t out[IMDB_HASH_LEN])
{
    uint64_t bits = c->nbytes * 8;
    uint8_t pad = 0x80;
    imdb_sha256_update(c, &pad, 1);
    static const uint8_t zeros[64];
    size_t z = (c->buflen <= 56) ? 56 - c->buflen : 120 - c->buflen;
    imdb_sha256_update(c, zeros, z);
    uint8_t len[8];
    for (int i = 0; i < 8; i++) len[i] = (uint8_t)(bits >> (56 - 8 * i));
    imdb_sha256_update(c, len, 8);
    for (int i = 0; i < 8; i++) {
        out[4 * i] = (uint8_t)(c->h[i] >> 24);
        out[4 * i + 1] = (uint8_t)(c->h[i] >> 16);
        out[4 * i + 2] = (uint8_t)(c->h[i] >> 8);
        out[4 * i + 3] = (uint8_t)c->h[i];
    }
    imdb_wipe(c, sizeof *c);
}

void imdb_sha256(const void *p, size_t n, uint8_t out[IMDB_HASH_LEN])
{
    imdb_sha256_ctx c;
    imdb_sha256_init(&c);
    imdb_sha256_update(&c, p, n);
    imdb_sha256_final(&c, out);
}

void imdb_hmac_init(imdb_hmac *m, const uint8_t *key, size_t keylen)
{
    uint8_t k[64] = {0};
    if (keylen > 64)
        imdb_sha256(key, keylen, k);
    else if (keylen)
        memcpy(k, key, keylen);
    uint8_t ipad[64], opad[64];
    for (int i = 0; i < 64; i++) {
        ipad[i] = k[i] ^ 0x36;
        opad[i] = k[i] ^ 0x5c;
    }
    imdb_sha256_init(&m->inner);
    imdb_sha256_update(&m->inner, ipad, 64);
    imdb_sha256_init(&m->outer);
    imdb_sha256_update(&m->outer, opad, 64);
    imdb_wipe(k, sizeof k);
    imdb_wipe(ipad, sizeof ipad);
    imdb_wipe(opad, sizeof opad);
}

void imdb_hmac_update(imdb_hmac *m, const void *p, size_t n) { imdb_sha256_update(&m->inner, p, n); }

void imdb_hmac_final(imdb_hmac *m, uint8_t out[IMDB_HASH_LEN])
{
    uint8_t ih[IMDB_HASH_LEN];
    imdb_sha256_final(&m->inner, ih);
    imdb_sha256_update(&m->outer, ih, sizeof ih);
    imdb_sha256_final(&m->outer, out);
    imdb_wipe(ih, sizeof ih);
}

void imdb_hmac_sha256(const uint8_t *key, size_t keylen, const void *p, size_t n,
                      uint8_t out[IMDB_HASH_LEN])
{
    imdb_hmac m;
    imdb_hmac_init(&m, key, keylen);
    imdb_hmac_update(&m, p, n);
    imdb_hmac_final(&m, out);
}
