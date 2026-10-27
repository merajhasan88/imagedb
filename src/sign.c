#include "sign.h"

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cpu.h"
#include "ed25519.h"
#include "util.h"
#include "vendor/monocypher/monocypher-ed25519.h"
#include "vendor/monocypher/monocypher.h"

static bool use_reference(void) { return imdb_cpu_get()->forced_scalar; }

/* RFC 8032 section 7.1, test 1: the fast path must reproduce it, sign and
 * verify, or the process stops (a miscompiled or broken build must not sign). */
static pthread_once_t g_selftest = PTHREAD_ONCE_INIT;

static void selftest(void)
{
    static const char *seed_hex = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
    static const char *pk_hex = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
    static const char *sig_hex =
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe2465"
        "5141438e7a100b";
    uint8_t seed[32], pk[32], want[64], a[32], prefix[32], got_pk[32], sig[64];
    bool ok = imdb_unhex(seed_hex, 64, seed, 32) && imdb_unhex(pk_hex, 64, pk, 32) && imdb_unhex(sig_hex, 128, want, 64);
    imdb_ed25519_expand(seed, a, prefix, got_pk);
    imdb_ed25519_sign(sig, a, prefix, got_pk, "", 0);
    ok = ok && memcmp(got_pk, pk, 32) == 0 && memcmp(sig, want, 64) == 0 && imdb_ed25519_verify(sig, pk, "", 0);
    sig[17] ^= 4;
    ok = ok && !imdb_ed25519_verify(sig, pk, "", 0);
    imdb_wipe(a, sizeof a);
    imdb_wipe(prefix, sizeof prefix);
    if (!ok) {
        fputs("imagedb: the Ed25519 fast path fails its RFC 8032 self-test; refusing to run "
              "(IMDB_NO_SIMD=1 uses the reference implementation)\n",
              stderr);
        abort();
    }
}

static void fast_ready(void) { pthread_once(&g_selftest, selftest); }

void imdb_signer_init(imdb_signer *s, const uint8_t seed[IMDB_SEED_LEN])
{
    uint8_t tmp[IMDB_SEED_LEN];
    memcpy(tmp, seed, sizeof tmp); /* Monocypher wipes the seed it is given */
    crypto_ed25519_key_pair(s->sk, s->pk, tmp);
    imdb_wipe(tmp, sizeof tmp);
    if (use_reference()) {
        memset(s->a, 0, sizeof s->a);
        memset(s->prefix, 0, sizeof s->prefix);
        return;
    }
    fast_ready();
    uint8_t pk[IMDB_PUBKEY_LEN];
    imdb_ed25519_expand(seed, s->a, s->prefix, pk);
    if (memcmp(pk, s->pk, sizeof pk) != 0) { /* both derive A = [a]B from the same seed */
        fputs("imagedb: Ed25519 fast path and reference disagree on a public key; refusing to run\n", stderr);
        abort();
    }
}

void imdb_signer_wipe(imdb_signer *s) { imdb_wipe(s, sizeof *s); }

void imdb_sign(const imdb_signer *s, const void *msg, size_t n, uint8_t sig[IMDB_SIG_LEN])
{
    if (use_reference()) {
        crypto_ed25519_sign(sig, s->sk, msg, n);
        return;
    }
    fast_ready();
    imdb_ed25519_sign(sig, s->a, s->prefix, s->pk, msg, n);
}

bool imdb_sig_verify(const uint8_t pk[IMDB_PUBKEY_LEN], const void *msg, size_t n, const uint8_t sig[IMDB_SIG_LEN])
{
    if (use_reference()) return crypto_ed25519_check(sig, pk, msg, n) == 0;
    fast_ready();
    return imdb_ed25519_verify(sig, pk, msg, n);
}

bool imdb_sig_verify_batch(const uint8_t pk[IMDB_PUBKEY_LEN], size_t n, const uint8_t *const msgs[], const size_t lens[],
                           const uint8_t *const sigs[], bool ok[])
{
    if (use_reference()) {
        bool all = true;
        for (size_t i = 0; i < n; i++) all = (ok[i] = crypto_ed25519_check(sigs[i], pk, msgs[i], lens[i]) == 0) && all;
        return all;
    }
    fast_ready();
    return imdb_ed25519_verify_batch(n, sigs, pk, msgs, lens, ok);
}

void imdb_sha512(const void *p, size_t n, uint8_t out[64]) { crypto_sha512(out, p, n); }
