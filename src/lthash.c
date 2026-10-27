#include "lthash.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cpu.h"
#include "log.h"
#include "util.h"

_Static_assert(__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__, "imagedb v0.1 targets little-endian hosts");

static const uint8_t kSeedTag[8] = {'I', 'M', 'D', 'B', 'L', 'T', '1', '6'};
static const uint8_t kDigestTag[8] = {'I', 'M', 'D', 'B', 'L', 'T', 'D', '1'};
static const uint8_t kLeafTag2[8] = {'I', 'M', 'D', 'B', 'L', 'T', 'L', '2'};
static const uint8_t kRootTag2[8] = {'I', 'M', 'D', 'B', 'L', 'T', 'R', '2'};

/* every caller passes its database's algorithm, which META's reader checked: anything else is a bug */
static void alg_check(uint8_t alg)
{
    if (alg != IMDB_DIGEST_ALG_LTHASH16 && alg != IMDB_DIGEST_ALG_LTHASH16_TREE) {
        fputs("imagedb: lthash: no digest algorithm\n", stderr);
        abort();
    }
}

void imdb_lthash_zero(imdb_lthash *h) { memset(h->v, 0, sizeof h->v); }

bool imdb_lthash_is_zero(const imdb_lthash *h)
{
    uint16_t acc = 0;
    for (int i = 0; i < IMDB_LTHASH_LANES; i++) acc |= h->v[i];
    return acc == 0;
}

void imdb_lthash_element(uint8_t alg, const uint8_t commit[IMDB_HASH_LEN], imdb_lthash *out)
{
    alg_check(alg);
    if (alg == IMDB_DIGEST_ALG_LTHASH16_TREE) {
        /* the commitment is the key: it is already a SHA-256 of the salted row, and the nonce
         * carries the domain tag (design.md §4; the first definition hashed it once more) */
        imdb_kern()->lthash_expand2(commit, (uint8_t *)out->v);
        return;
    }
    uint8_t seed[40];
    memcpy(seed, kSeedTag, 8);
    memcpy(seed + 8, commit, IMDB_HASH_LEN);
    /* lanes are little-endian u16 over the MGF1 output bytes */
    imdb_kern()->lthash_expand(seed, (uint8_t *)out->v);
}

void imdb_lthash_add(imdb_lthash *acc, const imdb_lthash *x) { imdb_kern()->lthash_add(acc->v, x->v); }
void imdb_lthash_sub(imdb_lthash *acc, const imdb_lthash *x) { imdb_kern()->lthash_sub(acc->v, x->v); }

void imdb_lthash_add_commit(uint8_t alg, imdb_lthash *acc, const uint8_t commit[IMDB_HASH_LEN])
{
    imdb_lthash e;
    imdb_lthash_element(alg, commit, &e);
    imdb_lthash_add(acc, &e);
}

void imdb_lthash_sub_commit(uint8_t alg, imdb_lthash *acc, const uint8_t commit[IMDB_HASH_LEN])
{
    imdb_lthash e;
    imdb_lthash_element(alg, commit, &e);
    imdb_lthash_sub(acc, &e);
}

void imdb_lthash_to_bytes(const imdb_lthash *h, uint8_t out[IMDB_LTHASH_BYTES])
{
    memcpy(out, h->v, IMDB_LTHASH_BYTES);
}

void imdb_lthash_from_bytes(imdb_lthash *h, const uint8_t in[IMDB_LTHASH_BYTES])
{
    memcpy(h->v, in, IMDB_LTHASH_BYTES);
}

/* digest_alg 2's tree: each leaf's 268 bytes (tag, index, 256 lane bytes) padded to five SHA-256
 * blocks here, the eight hashed side by side, then the root over the eight digests */
static void tree_digest(const imdb_lthash *h, uint8_t out[IMDB_HASH_LEN])
{
    enum { LEAF = 8 + 4 + 256, BLOCKS = 5 };
    _Static_assert(LEAF + 9 <= BLOCKS * 64 && LEAF + 9 > (BLOCKS - 1) * 64, "a leaf is five blocks");
    uint8_t leaf[8][BLOCKS * 64], d[8][32], root[8 + 8 * 32];
    const uint8_t *p[8];
    for (int i = 0; i < 8; i++) {
        memset(leaf[i], 0, sizeof leaf[i]);
        memcpy(leaf[i], kLeafTag2, 8);
        imdb_le32(leaf[i] + 8, (uint32_t)i);
        memcpy(leaf[i] + 12, (const uint8_t *)h->v + 256 * i, 256);
        leaf[i][LEAF] = 0x80;
        leaf[i][BLOCKS * 64 - 2] = (uint8_t)((LEAF * 8) >> 8); /* the bit length, big-endian */
        leaf[i][BLOCKS * 64 - 1] = (uint8_t)(LEAF * 8);
        p[i] = leaf[i];
    }
    imdb_kern()->sha256_x8(p, BLOCKS, d);
    memcpy(root, kRootTag2, 8);
    memcpy(root + 8, d, sizeof d);
    imdb_sha256(root, sizeof root, out);
}

void imdb_lthash_digest(uint8_t alg, const imdb_lthash *h, uint8_t out[IMDB_HASH_LEN])
{
    alg_check(alg);
    if (alg == IMDB_DIGEST_ALG_LTHASH16_TREE) {
        tree_digest(h, out);
        return;
    }
    imdb_sha256_ctx c;
    imdb_sha256_init(&c);
    imdb_sha256_update(&c, kDigestTag, sizeof kDigestTag);
    imdb_sha256_update(&c, h->v, IMDB_LTHASH_BYTES);
    imdb_sha256_final(&c, out);
}
