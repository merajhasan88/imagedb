/*
 * Constant-time check of Ed25519 signing (make ct). MemorySanitizer is used as
 * a taint tracker: the seed is marked uninitialised, so everything derived from
 * it (the secret scalar, the nonce, intermediate points) is too, and MSan
 * reports any conditional branch or memory index that depends on it. Plain
 * arithmetic on tainted values only propagates the taint. Outputs that are
 * public by design (the public key, the signature) are unpoisoned before use.
 *
 * A strong check, not a proof: it sees the instrumented IR, so a branch the
 * backend might introduce when lowering a select is not covered, and only the
 * code paths these inputs take are examined.
 */
#include <sanitizer/msan_interface.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include "../../src/ed25519.h"

/* --canary branches on the secret scalar on purpose: MSan must stop it, which shows
 * the taint really flows from the seed through key expansion. */
int main(int argc, char **argv)
{
    bool canary = argc > 1 && strcmp(argv[1], "--canary") == 0;
    static uint8_t msg[300];
    int bad = 0;
    for (int it = 0; it < 64; it++) {
        uint8_t seed[32], a[32], prefix[32], pk[32], sig[64];
        for (int i = 0; i < 32; i++) seed[i] = (uint8_t)(it * 37 + i * 101 + (it >> 3));
        if (it == 0) memset(seed, 0, 32);
        if (it == 1) memset(seed, 0xff, 32);
        size_t n = (size_t)(it * 13) % sizeof msg;
        for (size_t i = 0; i < n; i++) msg[i] = (uint8_t)(i ^ (size_t)it);
        __msan_poison(seed, sizeof seed);
        imdb_ed25519_expand(seed, a, prefix, pk);
        __msan_unpoison(pk, sizeof pk); /* public */
        if (canary && (a[it % 32] & 1)) puts("unreachable under MSan: a branch on the secret scalar");
        imdb_ed25519_sign(sig, a, prefix, pk, msg, n);
        __msan_unpoison(sig, sizeof sig); /* public */
        bad += !imdb_ed25519_verify(sig, pk, msg, n);
    }
    printf("ed25519 signing: no branch or index on secret data (64 keys); %d invalid signatures\n", bad);
    return bad != 0;
}
