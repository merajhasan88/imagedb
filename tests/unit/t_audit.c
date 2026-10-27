/* The independent auditor's crypto (tools/audit/acrypto.c) against OpenSSL,
 * the engine's own SHA-256/CRC32C/LtHash, and Monocypher's Ed25519 verdicts. */
#include <openssl/evp.h>
#include <stdlib.h>

#include "../../src/cpu.h"
#include "../../src/log.h"
#include "../../src/lthash.h"
#include "../../src/sha256.h"
#include "../../src/sign.h"
#include "../../src/util.h"
#include "../../tools/audit/acrypto.h"
#include "test.h"

static void t_audit_hashes(void)
{
    static uint8_t buf[3000];
    test_rand_bytes(buf, sizeof buf);
    for (size_t n = 0; n <= sizeof buf; n += (n < 300 ? 1 : 97)) {
        uint8_t a[64], b[64];
        unsigned bl = 64;
        a_sha256(buf, n, a);
        EVP_Digest(buf, n, b, &bl, EVP_sha256(), NULL);
        CHECK(memcmp(a, b, 32) == 0);
        a_sha512_ctx c;
        a_sha512_init(&c);
        size_t half = n / 3;
        a_sha512_update(&c, buf, half);
        a_sha512_update(&c, buf + half, n - half);
        a_sha512_final(&c, a);
        EVP_Digest(buf, n, b, &bl, EVP_sha512(), NULL);
        CHECK(memcmp(a, b, 64) == 0);
        CHECK(a_crc32c(buf, n) == imdb_crc32c_ref(0, buf, n));
    }
    for (int it = 0; it < 40; it++) { /* the element by either algorithm, against the engine's */
        uint8_t commit[32];
        test_rand_bytes(commit, 32);
        for (uint8_t alg = IMDB_DIGEST_ALG_LTHASH16; alg <= IMDB_DIGEST_ALG_LTHASH16_TREE; alg++) {
            uint16_t lanes[1024];
            imdb_lthash ref;
            a_lthash_element(alg, commit, lanes);
            imdb_lthash_element(alg, commit, &ref);
            CHECK(memcmp(lanes, ref.v, sizeof lanes) == 0);
        }
    }
    /* and against OpenSSL alone: ChaCha20's block function (the IV is LE32 counter || nonce), and
     * alg 2's element as its definition states it, so a mistake shared by the engine and the
     * auditor would still show */
    for (int it = 0; it < 40; it++) {
        uint8_t key[32], nonce[12], iv[16], zero[64] = {0}, a[64], b[64];
        uint32_t ctr = it < 20 ? (uint32_t)it : (uint32_t)test_rand();
        test_rand_bytes(key, sizeof key);
        test_rand_bytes(nonce, sizeof nonce);
        for (int i = 0; i < 4; i++) iv[i] = (uint8_t)(ctr >> (8 * i));
        memcpy(iv + 4, nonce, 12);
        EVP_CIPHER_CTX *cx = EVP_CIPHER_CTX_new();
        int len = 0;
        CHECK(cx && EVP_EncryptInit_ex(cx, EVP_chacha20(), NULL, key, iv) == 1 && EVP_EncryptUpdate(cx, b, &len, zero, 64) == 1 &&
              len == 64);
        EVP_CIPHER_CTX_free(cx);
        a_chacha20_block(key, ctr, nonce, a);
        CHECK(memcmp(a, b, 64) == 0);
    }
    for (int it = 0; it < 20; it++) {
        uint8_t commit[32], iv[16] = {0}, want[2048], zero[2048] = {0};
        test_rand_bytes(commit, sizeof commit);
        memcpy(iv + 4, "IMDBLT20\0\0\0\0", 12); /* the key is the commitment itself */
        EVP_CIPHER_CTX *cx = EVP_CIPHER_CTX_new();
        int len = 0;
        CHECK(cx && EVP_EncryptInit_ex(cx, EVP_chacha20(), NULL, commit, iv) == 1 &&
              EVP_EncryptUpdate(cx, want, &len, zero, (int)sizeof zero) == 1 && len == (int)sizeof want);
        EVP_CIPHER_CTX_free(cx);
        uint16_t lanes[1024];
        a_lthash_element(IMDB_DIGEST_ALG_LTHASH16_TREE, commit, lanes);
        CHECK(memcmp(lanes, want, sizeof want) == 0);
    }
}

static bool mono(const uint8_t pk[32], const uint8_t *m, size_t n, const uint8_t sig[64])
{
    return imdb_sig_verify(pk, m, n, sig);
}

static void t_audit_ed25519(void)
{
    static uint8_t msg[300];
    for (int it = 0; it < 150; it++) {
        uint8_t seed[32], sig[64];
        test_rand_bytes(seed, 32);
        size_t n = (size_t)(test_rand() % sizeof msg);
        test_rand_bytes(msg, n);
        imdb_signer s;
        imdb_signer_init(&s, seed);
        imdb_sign(&s, msg, n, sig);
        CHECK(a_ed25519_verify(s.pk, msg, n, sig));
        /* every mutation gets the same verdict as Monocypher (and is a rejection) */
        for (int k = 0; k < 4; k++) {
            uint8_t bad[64], pk[32];
            memcpy(bad, sig, 64);
            memcpy(pk, s.pk, 32);
            size_t bit = (size_t)(test_rand() % (k == 3 ? 256 : 512));
            if (k == 3) pk[bit / 8] ^= (uint8_t)(1u << (bit % 8));
            else bad[bit / 8] ^= (uint8_t)(1u << (bit % 8));
            bool a = a_ed25519_verify(pk, msg, n, bad), b = mono(pk, msg, n, bad);
            CHECK(a == b && !a);
        }
        /* S + L: same scalar mod L, must be rejected */
        uint8_t bad[64];
        memcpy(bad, sig, 64);
        unsigned carry = 0;
        static const uint8_t L[32] = {0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7,
                                      0xa2, 0xde, 0xf9, 0xde, 0x14, 0, 0, 0, 0, 0, 0,
                                      0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10};
        for (int i = 0; i < 32; i++) {
            unsigned t = (unsigned)bad[32 + i] + L[i] + carry;
            bad[32 + i] = (uint8_t)t;
            carry = t >> 8;
        }
        CHECK(!a_ed25519_verify(s.pk, msg, n, bad) && !mono(s.pk, msg, n, bad));
        imdb_signer_wipe(&s);
    }
    /* edge encodings where Ed25519 implementations are known to differ: both
     * verifiers must give the same verdict (the rule in vendor/monocypher/README) */
    static const char *const pts[] = {
        "0100000000000000000000000000000000000000000000000000000000000000",  /* identity, canonical */
        "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",  /* identity, y = 1 + p */
        "0100000000000000000000000000000000000000000000000000000000000080",  /* x = 0 with sign bit set */
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",  /* y = -1: order 2 */
        "0000000000000000000000000000000000000000000000000000000000000000",  /* y = 0: order 4 */
        "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",  /* order 8 */
        "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",  /* order 8 */
        "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",  /* y = p: non-canonical 0 */
    };
    size_t np = sizeof pts / sizeof *pts, accepted = 0;
    for (size_t i = 0; i < np; i++)
        for (size_t j = 0; j < np; j++)
            for (int sz = 0; sz < 2; sz++) {
                uint8_t pk[32], sig[64] = {0};
                CHECK(imdb_unhex(pts[i], 64, pk, 32) && imdb_unhex(pts[j], 64, sig, 32));
                if (sz) sig[32] = 1;
                bool a = a_ed25519_verify(pk, "x", 1, sig), b = mono(pk, (const uint8_t *)"x", 1, sig);
                if (a != b) fprintf(stderr, "    differ: A=%s R=%s S=%d audit=%d monocypher=%d\n", pts[i], pts[j], sz, a, b);
                CHECK(a == b);
                accepted += a;
            }
    /* the cofactored rule accepts small-order A and R with S = 0: the leniency is exercised */
    fprintf(stderr, "    edge encodings: %zu of %zu combinations accepted by both\n", accepted, np * np * 2);
    CHECK(accepted > 0);
}

const test_case audit_tests[] = {
    {"audit_hashes", t_audit_hashes},
    {"audit_ed25519", t_audit_ed25519},
};
const size_t audit_ntests = sizeof audit_tests / sizeof *audit_tests;
