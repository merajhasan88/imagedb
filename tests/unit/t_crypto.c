/* SHA-256 / HMAC / CRC32C / LtHash correctness, with OpenSSL as the oracle. */
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <stdlib.h>

#include "../../src/cpu.h"
#include "../../src/log.h"
#include "../../src/lthash.h"
#include "../../src/sha256.h"
#include "../../src/sign.h"
#include "../../src/util.h"
#include "test.h"

static void ossl_sha256(const void *p, size_t n, uint8_t out[32])
{
    unsigned len = 32;
    EVP_Digest(p, n, out, &len, EVP_sha256(), NULL);
}

static void t_sha256_known(void)
{
    uint8_t out[32];
    char hex[65];
    imdb_sha256("abc", 3, out);
    imdb_hex(out, 32, hex);
    CHECK(strcmp(hex, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad") == 0);
    imdb_sha256("", 0, out);
    imdb_hex(out, 32, hex);
    CHECK(strcmp(hex, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855") == 0);
}

static void t_sha256_vs_openssl(void)
{
    static uint8_t buf[5000];
    test_rand_bytes(buf, sizeof buf);
    for (size_t n = 0; n <= 1200; n++) {
        uint8_t a[32], b[32];
        imdb_sha256(buf, n, a);
        ossl_sha256(buf, n, b);
        CHECK(memcmp(a, b, 32) == 0);
    }
    /* incremental with random split points */
    for (int it = 0; it < 500; it++) {
        size_t n = test_rand() % sizeof buf;
        imdb_sha256_ctx c;
        imdb_sha256_init(&c);
        size_t off = 0;
        while (off < n) {
            size_t step = 1 + test_rand() % 130;
            if (step > n - off) step = n - off;
            imdb_sha256_update(&c, buf + off, step);
            off += step;
        }
        uint8_t a[32], b[32];
        imdb_sha256_final(&c, a);
        ossl_sha256(buf, n, b);
        CHECK(memcmp(a, b, 32) == 0);
    }
}

static void t_hmac_vs_openssl(void)
{
    uint8_t key[200], msg[300];
    for (int it = 0; it < 400; it++) {
        size_t kl = test_rand() % sizeof key, ml = test_rand() % sizeof msg;
        test_rand_bytes(key, kl);
        test_rand_bytes(msg, ml);
        uint8_t a[32], b[32];
        unsigned bl = 32;
        imdb_hmac_sha256(key, kl, msg, ml, a);
        HMAC(EVP_sha256(), key, (int)kl, msg, ml, b, &bl);
        CHECK(bl == 32 && memcmp(a, b, 32) == 0);
    }
}

static void t_crc32c(void)
{
    CHECK(imdb_crc32c_ref(0, "123456789", 9) == 0xE3069283u);
    CHECK(imdb_kern()->crc32c(0, "123456789", 9) == 0xE3069283u);
    static uint8_t buf[4096 + 64];
    test_rand_bytes(buf, sizeof buf);
    for (int it = 0; it < 3000; it++) {
        size_t off = test_rand() % 64, n = test_rand() % 4096;
        uint32_t seed = (uint32_t)test_rand();
        CHECK(imdb_kern()->crc32c(seed, buf + off, n) == imdb_crc32c_ref(seed, buf + off, n));
    }
    /* chaining: crc(a||b) == crc(crc(a), b) */
    uint32_t whole = imdb_crc32c_ref(0, buf, 1000);
    CHECK(imdb_kern()->crc32c(imdb_kern()->crc32c(0, buf, 333), buf + 333, 667) == whole);
}

/* Independent MGF1-SHA256 via OpenSSL. */
static void ossl_mgf1(const uint8_t seed[40], uint8_t out[2048])
{
    for (uint32_t i = 0; i < 64; i++) {
        uint8_t m[44];
        memcpy(m, seed, 40);
        m[40] = (uint8_t)(i >> 24); m[41] = (uint8_t)(i >> 16); m[42] = (uint8_t)(i >> 8); m[43] = (uint8_t)i;
        ossl_sha256(m, 44, out + 32 * i);
    }
}

static void t_lthash_expand(void)
{
    for (int it = 0; it < 200; it++) {
        uint8_t seed[40], a[2048], b[2048], c[2048];
        test_rand_bytes(seed, sizeof seed);
        imdb_lthash_expand_ref(seed, a);
        ossl_mgf1(seed, b);
        CHECK(memcmp(a, b, sizeof a) == 0);
        if (imdb_cpu_get()->avx2) {
            imdb_lthash_expand_avx2(seed, c);
            CHECK(memcmp(a, c, sizeof a) == 0);
        }
        uint8_t d[2048];
        imdb_kern()->lthash_expand(seed, d);
        CHECK(memcmp(a, d, sizeof a) == 0);
    }
}

/* OpenSSL's ChaCha20 keystream: its 16-byte IV is the block counter (LE32) then the RFC 8439 nonce */
static void ossl_chacha20(const uint8_t key[32], const uint8_t nonce[12], uint8_t *out, size_t n)
{
    uint8_t iv[16] = {0}, *zero = calloc(1, n);
    memcpy(iv + 4, nonce, 12);
    EVP_CIPHER_CTX *c = EVP_CIPHER_CTX_new();
    int len = 0;
    CHECK(c && zero && EVP_EncryptInit_ex(c, EVP_chacha20(), NULL, key, iv) == 1 &&
          EVP_EncryptUpdate(c, out, &len, zero, (int)n) == 1 && (size_t)len == n);
    EVP_CIPHER_CTX_free(c);
    free(zero);
}

/* digest_alg 2's expansion: Monocypher's keystream (the reference), OpenSSL's, the AVX2 kernel and
 * the dispatched one agree */
static void t_lthash_expand2(void)
{
    for (int it = 0; it < 200; it++) {
        uint8_t key[32], a[2048], b[2048], c[2048], d[2048];
        test_rand_bytes(key, sizeof key);
        imdb_lthash_expand2_ref(key, a);
        ossl_chacha20(key, imdb_lthash2_nonce, b, sizeof b);
        CHECK(memcmp(a, b, sizeof a) == 0);
        if (imdb_cpu_get()->avx2) {
            imdb_lthash_expand2_avx2(key, c);
            CHECK(memcmp(a, c, sizeof a) == 0);
        }
        imdb_kern()->lthash_expand2(key, d);
        CHECK(memcmp(a, d, sizeof a) == 0);
    }
    CHECK(memcmp(imdb_lthash2_nonce, "IMDBLT20\0\0\0\0", 12) == 0);
}

/* eight padded messages of nblk blocks; lane l's digest against OpenSSL's of the unpadded bytes */
static void t_sha256_x8(void)
{
    enum { MAXLEN = 600, MAXB = (MAXLEN + 9 + 63) / 64 };
    static uint8_t m[8][MAXLEN], p[8][MAXB * 64];
    for (int it = 0; it < 300; it++) {
        size_t len = it < 100 ? 268 : test_rand() % MAXLEN, nblk = (len + 9 + 63) / 64; /* the leaves' 268, then any */
        const uint8_t *ptr[8];
        for (int l = 0; l < 8; l++) {
            test_rand_bytes(m[l], len);
            memset(p[l], 0, nblk * 64);
            memcpy(p[l], m[l], len);
            p[l][len] = 0x80;
            for (int i = 0; i < 8; i++) p[l][nblk * 64 - 1 - (size_t)i] = (uint8_t)((uint64_t)len * 8 >> (8 * i));
            ptr[l] = p[l];
        }
        uint8_t r[8][32], v[8][32], x[8][32], want[32];
        imdb_sha256_x8_ref(ptr, nblk, r);
        imdb_kern()->sha256_x8(ptr, nblk, x);
        if (imdb_cpu_get()->avx2) imdb_sha256_x8_avx2(ptr, nblk, v);
        for (int l = 0; l < 8; l++) {
            ossl_sha256(m[l], len, want);
            CHECK(memcmp(r[l], want, 32) == 0 && memcmp(x[l], want, 32) == 0);
            if (imdb_cpu_get()->avx2) CHECK(memcmp(v[l], want, 32) == 0);
        }
    }
}

static void t_lthash_algebra(void)
{
    enum { N = 64 };
    uint8_t commits[N][32];
    for (int i = 0; i < N; i++) test_rand_bytes(commits[i], 32);
    for (uint8_t alg = IMDB_DIGEST_ALG_LTHASH16; alg <= IMDB_DIGEST_ALG_LTHASH16_TREE; alg++) {
        imdb_lthash fwd, rev, tmp;
        imdb_lthash_zero(&fwd);
        imdb_lthash_zero(&rev);
        for (int i = 0; i < N; i++) imdb_lthash_add_commit(alg, &fwd, commits[i]);
        for (int i = N - 1; i >= 0; i--) imdb_lthash_add_commit(alg, &rev, commits[i]);
        CHECK(memcmp(&fwd, &rev, sizeof fwd) == 0); /* order independence */
        tmp = fwd;
        for (int i = 0; i < N; i += 2) imdb_lthash_sub_commit(alg, &tmp, commits[i]);
        imdb_lthash odd;
        imdb_lthash_zero(&odd);
        for (int i = 1; i < N; i += 2) imdb_lthash_add_commit(alg, &odd, commits[i]);
        CHECK(memcmp(&tmp, &odd, sizeof tmp) == 0); /* subtraction removes exactly */
        for (int i = 1; i < N; i += 2) imdb_lthash_sub_commit(alg, &tmp, commits[i]);
        CHECK(imdb_lthash_is_zero(&tmp));
    }
    /* asm/C add/sub agree, including wraparound */
    imdb_lthash x, y, r1, r2;
    test_rand_bytes(&x, sizeof x);
    test_rand_bytes(&y, sizeof y);
    r1 = x; r2 = x;
    imdb_lthash_add_ref(r1.v, y.v);
    imdb_kern()->lthash_add(r2.v, y.v);
    CHECK(memcmp(&r1, &r2, sizeof r1) == 0);
    imdb_lthash_sub_ref(r1.v, y.v);
    imdb_kern()->lthash_sub(r2.v, y.v);
    CHECK(memcmp(&r1, &r2, sizeof r1) == 0);
    CHECK(memcmp(&r1, &x, sizeof r1) == 0);
}

/* Both algorithms' elements and digests against their definitions (lthash.h), computed here with
 * OpenSSL alone: alg 1's MGF1 and flat digest, alg 2's ChaCha20 keyed by the commitment and its
 * tree (and not alg 2's first definition, which hashed the key once more) */
static void t_lthash_definitions(void)
{
    for (int it = 0; it < 60; it++) {
        uint8_t commit[32], m[40], key[32], want[2048];
        test_rand_bytes(commit, sizeof commit);
        imdb_lthash got;
        memcpy(m, "IMDBLT16", 8);
        memcpy(m + 8, commit, 32);
        ossl_mgf1(m, want);
        imdb_lthash_element(IMDB_DIGEST_ALG_LTHASH16, commit, &got);
        CHECK(memcmp(got.v, want, sizeof want) == 0);
        ossl_chacha20(commit, (const uint8_t *)"IMDBLT20\0\0\0\0", want, sizeof want);
        imdb_lthash_element(IMDB_DIGEST_ALG_LTHASH16_TREE, commit, &got);
        CHECK(memcmp(got.v, want, sizeof want) == 0);
        memcpy(m, "IMDBLT2K", 8); /* the first definition's key: what the engine must no longer compute */
        ossl_sha256(m, sizeof m, key);
        ossl_chacha20(key, (const uint8_t *)"IMDBLT20\0\0\0\0", want, sizeof want);
        CHECK(memcmp(got.v, want, sizeof want) != 0);
        /* the digests of a random state */
        imdb_lthash st;
        test_rand_bytes(&st, sizeof st);
        uint8_t flat[8 + 2048], d1[32], d2[32], root[8 + 256], leaf[268], dw[32];
        memcpy(flat, "IMDBLTD1", 8);
        memcpy(flat + 8, st.v, 2048);
        ossl_sha256(flat, sizeof flat, dw);
        imdb_lthash_digest(IMDB_DIGEST_ALG_LTHASH16, &st, d1);
        CHECK(memcmp(d1, dw, 32) == 0);
        memcpy(root, "IMDBLTR2", 8);
        for (int i = 0; i < 8; i++) {
            memcpy(leaf, "IMDBLTL2", 8);
            leaf[8] = (uint8_t)i, leaf[9] = leaf[10] = leaf[11] = 0;
            memcpy(leaf + 12, (const uint8_t *)st.v + 256 * i, 256);
            ossl_sha256(leaf, sizeof leaf, root + 8 + 32 * i);
        }
        ossl_sha256(root, sizeof root, dw);
        imdb_lthash_digest(IMDB_DIGEST_ALG_LTHASH16_TREE, &st, d2);
        CHECK(memcmp(d2, dw, 32) == 0 && memcmp(d1, d2, 32) != 0);
    }
}

/* ---- Ed25519 (vendored Monocypher) against RFC 8032 and OpenSSL ---- */

static EVP_PKEY *ossl_ed_priv(const uint8_t seed[32])
{
    return EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL, seed, 32);
}

static void ossl_ed_sign(EVP_PKEY *k, const uint8_t *m, size_t n, uint8_t sig[64])
{
    EVP_MD_CTX *c = EVP_MD_CTX_new();
    size_t sl = 64;
    EVP_DigestSignInit(c, NULL, NULL, NULL, k);
    EVP_DigestSign(c, sig, &sl, m, n);
    EVP_MD_CTX_free(c);
}

static bool ossl_ed_verify(const uint8_t pk[32], const uint8_t *m, size_t n, const uint8_t sig[64])
{
    EVP_PKEY *p = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL, pk, 32);
    EVP_MD_CTX *c = EVP_MD_CTX_new();
    int ok = p && c && EVP_DigestVerifyInit(c, NULL, NULL, NULL, p) == 1 && EVP_DigestVerify(c, sig, 64, m, n) == 1;
    EVP_MD_CTX_free(c);
    EVP_PKEY_free(p);
    return ok;
}

static void t_ed25519_rfc8032(void)
{
    static const struct {
        const char *seed, *pk, *msg, *sig;
    } v[] = {
        {"9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
         "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", "",
         "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595"
         "bbe24655141438e7a100b"},
        {"4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
         "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c", "72",
         "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb43"
         "02aeeb00d291612bb0c00"},
        {"c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
         "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025", "af82",
         "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716"
         "ed28dc027beceea1ec40a"},
    };
    for (size_t i = 0; i < sizeof v / sizeof *v; i++) {
        uint8_t seed[32], pk[32], sig[64], msg[8], got[64];
        size_t ml = strlen(v[i].msg) / 2;
        CHECK(imdb_unhex(v[i].seed, 64, seed, 32) && imdb_unhex(v[i].pk, 64, pk, 32) &&
              imdb_unhex(v[i].sig, 128, sig, 64) && (ml == 0 || imdb_unhex(v[i].msg, 2 * ml, msg, ml)));
        imdb_signer s;
        imdb_signer_init(&s, seed);
        CHECK(memcmp(s.pk, pk, 32) == 0);
        imdb_sign(&s, msg, ml, got);
        CHECK(memcmp(got, sig, 64) == 0);
        CHECK(imdb_sig_verify(pk, msg, ml, sig));
        got[0] ^= 1;
        CHECK(!imdb_sig_verify(pk, msg, ml, got));
        imdb_signer_wipe(&s);
    }
    /* SHA-512 known answer (FIPS 180-2, "abc") */
    uint8_t h[64];
    char hex[129];
    imdb_sha512("abc", 3, h);
    imdb_hex(h, 64, hex);
    CHECK(strcmp(hex, "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd"
                      "454d4423643ce80e2a9ac94fa54ca49f") == 0);
}

/* S + L as 256-bit little-endian integers (S < L < 2^253, so no overflow). */
static void add_l(uint8_t s[32])
{
    static const uint8_t L[32] = {0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7,
                                  0xa2, 0xde, 0xf9, 0xde, 0x14, 0, 0, 0, 0, 0, 0,
                                  0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10};
    unsigned carry = 0;
    for (int i = 0; i < 32; i++) {
        unsigned t = (unsigned)s[i] + L[i] + carry;
        s[i] = (uint8_t)t;
        carry = t >> 8;
    }
}

static void t_ed25519_vs_openssl(void)
{
    static uint8_t msg[700];
    for (int it = 0; it < 300; it++) {
        uint8_t seed[32], sig[64], osig[64], opk[32];
        test_rand_bytes(seed, 32);
        size_t n = (size_t)(test_rand() % sizeof msg);
        test_rand_bytes(msg, n);
        imdb_signer s;
        imdb_signer_init(&s, seed);
        EVP_PKEY *k = ossl_ed_priv(seed);
        size_t pl = 32;
        CHECK(k && EVP_PKEY_get_raw_public_key(k, opk, &pl) == 1 && pl == 32);
        CHECK(memcmp(s.pk, opk, 32) == 0);
        imdb_sign(&s, msg, n, sig);
        ossl_ed_sign(k, msg, n, osig);
        EVP_PKEY_free(k);
        CHECK(memcmp(sig, osig, 64) == 0); /* deterministic: byte-identical */
        CHECK(imdb_sig_verify(s.pk, msg, n, osig) && ossl_ed_verify(s.pk, msg, n, sig));
        /* any single-bit change of signature, message or key is rejected by both */
        uint8_t bad[64];
        memcpy(bad, sig, 64);
        size_t bit = (size_t)(test_rand() % 512);
        bad[bit / 8] ^= (uint8_t)(1u << (bit % 8));
        CHECK(!imdb_sig_verify(s.pk, msg, n, bad) && !ossl_ed_verify(s.pk, msg, n, bad));
        if (n) {
            size_t mb = (size_t)(test_rand() % (n * 8));
            msg[mb / 8] ^= (uint8_t)(1u << (mb % 8));
            CHECK(!imdb_sig_verify(s.pk, msg, n, sig) && !ossl_ed_verify(s.pk, msg, n, sig));
            msg[mb / 8] ^= (uint8_t)(1u << (mb % 8));
        }
        uint8_t pk2[32];
        memcpy(pk2, s.pk, 32);
        pk2[test_rand() % 31] ^= 0x10;
        CHECK(!imdb_sig_verify(pk2, msg, n, sig));
        /* malleability: S + L encodes the same scalar mod L and must be rejected */
        memcpy(bad, sig, 64);
        add_l(bad + 32);
        CHECK(!imdb_sig_verify(s.pk, msg, n, bad) && !ossl_ed_verify(s.pk, msg, n, bad));
        imdb_signer_wipe(&s);
    }
    for (size_t n = 0; n <= 600; n += 7) {
        uint8_t a[64], b[64];
        unsigned bl = 64;
        test_rand_bytes(msg, n);
        imdb_sha512(msg, n, a);
        EVP_Digest(msg, n, b, &bl, EVP_sha512(), NULL);
        CHECK(memcmp(a, b, 64) == 0);
    }
}

static void t_hex_strict(void)
{
    uint8_t out[2];
    CHECK(imdb_unhex("0aff", 4, out, 2) && out[0] == 0x0a && out[1] == 0xff);
    CHECK(!imdb_unhex("0AFF", 4, out, 2)); /* uppercase rejected */
    CHECK(!imdb_unhex("0af", 3, out, 2));
    CHECK(!imdb_unhex("0a/f", 4, out, 2));
}

static void t_checked_alloc(void)
{
    imdb_err e = {0};
    CHECK(imdb_alloc_array(SIZE_MAX / 2, 4, &e) == NULL && e.code == IMDB_ERR_LIMIT);
    imdb_err_clear(&e);
    CHECK(imdb_alloc_array((size_t)1 << 40, (size_t)1 << 30, &e) == NULL && e.code == IMDB_ERR_LIMIT);
    imdb_buf b;
    imdb_buf_init(&b);
    b.len = SIZE_MAX - 4; /* simulate a huge buffer: reserve must fail, not wrap */
    CHECK(!imdb_buf_reserve(&b, 16) && b.err == IMDB_ERR_LIMIT);
    b.len = 0;
    imdb_buf_free(&b);
    /* bounded reader never reads past the end and stays failed */
    uint8_t data[5] = {1, 2, 3, 4, 5};
    imdb_rd r;
    imdb_rd_init(&r, data, sizeof data);
    CHECK(imdb_rd_u32(&r) == 0x04030201u);
    CHECK(imdb_rd_u32(&r) == 0 && r.err);
    CHECK(imdb_rd_u8(&r) == 0 && r.err);
    CHECK(imdb_rd_bytes(&r, 1) == NULL);
    imdb_rd_init(&r, data, sizeof data);
    CHECK(imdb_rd_bytes(&r, SIZE_MAX) == NULL && r.err); /* no off+len wrap */
}

const test_case crypto_tests[] = {
    {"sha256_known", t_sha256_known},
    {"sha256_vs_openssl", t_sha256_vs_openssl},
    {"hmac_vs_openssl", t_hmac_vs_openssl},
    {"crc32c", t_crc32c},
    {"lthash_expand", t_lthash_expand},
    {"lthash_expand2", t_lthash_expand2},
    {"lthash_definitions", t_lthash_definitions},
    {"sha256_x8", t_sha256_x8},
    {"lthash_algebra", t_lthash_algebra},
    {"ed25519_rfc8032", t_ed25519_rfc8032},
    {"ed25519_vs_openssl", t_ed25519_vs_openssl},
    {"hex_strict", t_hex_strict},
    {"checked_alloc", t_checked_alloc},
};
const size_t crypto_ntests = sizeof crypto_tests / sizeof *crypto_tests;
