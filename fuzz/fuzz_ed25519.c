/* Ed25519, differential: the engine's fast path against Monocypher (the
 * reference) on arbitrary inputs. Input: mode byte | 32 key bytes | 64
 * signature bytes | message.
 *   mode bit 0 set: the key bytes are a seed; both must derive the same public
 *     key and signature, and the fast path must accept it;
 *   otherwise: both verdicts on (key, signature, message) must agree; mode bit
 *     1 clears S's top bits so the curve checks are reached past S < L.
 *   mode bit 2 set: batch verification. After the 32 key bytes come records of
 *     64 signature bytes and 8 message bytes (up to 9; the unit tests cross the group of 64).
 *     With bit 0 the key is a seed, every record's message is signed, and the
 *     record's bytes are XORed into that valid signature (zero: it stays valid);
 *     without it the records are the signatures. Every batch verdict must be
 *     Monocypher's single one. */
#include "../src/ed25519.h"
#include "../src/vendor/monocypher/monocypher-ed25519.h"
#include "fuzz_common.h"

static void batch(const uint8_t *data, size_t size)
{
    enum { MAXB = 9, REC = 72 }; /* small: the 64-signature group boundary is the unit tests' */
    static uint8_t sig[MAXB][64], msg[MAXB][8];
    const uint8_t *sp[MAXB], *mp[MAXB];
    size_t len[MAXB];
    bool ok[MAXB];
    size_t n = (size - 33) / REC;
    if (n > MAXB) n = MAXB;
    if (n == 0) return;
    uint8_t pk[32], a[32], prefix[32], seed[32];
    if (data[0] & 1) {
        memcpy(seed, data + 1, 32);
        imdb_ed25519_expand(seed, a, prefix, pk);
    } else {
        memcpy(pk, data + 1, 32);
    }
    for (size_t i = 0; i < n; i++) {
        const uint8_t *r = data + 33 + REC * i;
        memcpy(msg[i], r + 64, 8);
        if (data[0] & 1) {
            imdb_ed25519_sign(sig[i], a, prefix, pk, msg[i], 8);
            for (int k = 0; k < 64; k++) sig[i][k] ^= r[k];
        } else {
            memcpy(sig[i], r, 64);
        }
        if (data[0] & 2) sig[i][63] &= 0x0f;
        sp[i] = sig[i];
        mp[i] = msg[i];
        len[i] = 8;
    }
    bool all = imdb_ed25519_verify_batch(n, sp, pk, mp, len, ok), want_all = true;
    for (size_t i = 0; i < n; i++) {
        bool ref = crypto_ed25519_check(sig[i], pk, msg[i], 8) == 0;
        if (ok[i] != ref) abort();
        want_all = want_all && ref;
    }
    if (all != want_all) abort();
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < 97) return 0;
    if (data[0] & 4) {
        batch(data, size);
        return 0;
    }
    const uint8_t *key = data + 1, *msg = data + 97;
    size_t n = size - 97;
    if (data[0] & 1) {
        uint8_t seed[32], a[32], prefix[32], pk[32], s1[64], msk[64], mpk[32], s2[64];
        memcpy(seed, key, 32);
        imdb_ed25519_expand(seed, a, prefix, pk);
        crypto_ed25519_key_pair(msk, mpk, seed); /* wipes seed */
        if (memcmp(pk, mpk, 32) != 0) abort();
        imdb_ed25519_sign(s1, a, prefix, pk, msg, n);
        crypto_ed25519_sign(s2, msk, msg, n);
        if (memcmp(s1, s2, 64) != 0 || !imdb_ed25519_verify(s1, pk, msg, n)) abort();
        return 0;
    }
    uint8_t sig[64];
    memcpy(sig, data + 33, 64);
    if (data[0] & 2) sig[63] &= 0x0f;
    bool fast = imdb_ed25519_verify(sig, key, msg, n);
    bool ref = crypto_ed25519_check(sig, key, msg, n) == 0;
    if (fast != ref) abort();
    return 0;
}
