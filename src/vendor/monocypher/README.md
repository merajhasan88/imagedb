# Vendored: Monocypher 4.0.3

imagedb uses Monocypher only for Ed25519 (RFC 8032, SHA-512) commit
signatures. This was decided with the user on 2026-10-20: a small audited
library compiled into the engine (it still links only libc and pthread),
instead of a shared-library dependency or hand-written crypto.

Later the same day the user asked for a faster implementation. The engine now
signs and verifies with its own code (`src/ed25519.c`, about 2.8x faster), and
Monocypher stays compiled in as the **reference**:

- `IMDB_NO_SIMD=1` selects it, as for every other reference kernel, so the
  second pass of the test matrix runs the whole suite on Monocypher.
- `tests/unit/t_ed25519.c` requires byte-identical public keys and signatures
  and identical verdicts (on valid, mutated and random inputs and on the edge
  encodings below), and `fuzz/fuzz_ed25519.c` keeps comparing the two.
- The fast path checks itself against RFC 8032 test 1 at first use and stops
  the process if it disagrees.
- The fast path hashes with Monocypher's SHA-512.

## Provenance

- Release: Monocypher 4.0.3 (2026-06-15). Its changelog entry: "Fixed timing
  leak vulnerability in EdDSA/Ed25519 signatures".
- Fetched 2026-10-20 from two sources, which were byte-identical:
  - <https://monocypher.org/download/monocypher-4.0.3.tar.gz>
  - <https://github.com/LoupVaillant/Monocypher/releases/download/4.0.3/monocypher-4.0.3.tar.gz>
- Tarball SHA-512 (matches the published
  `monocypher-4.0.3.tar.gz.sha512`):
  `40904ada5c7ee4f7741733e38b69a30a4b0561cbffba5ffe7c2dce16136d540251ec0d9056ff606510d3b5b708fb8a40db7e0870d4a0b2dc17ba2bfb880f8965`
- Tarball SHA-256:
  `8cc9bc341a66249016db9bd70e9142d8d0aef9945973744b1ac05dbc55d8ee66`

## Files

These are copied unmodified from the tarball. The two `optional/` files
were moved next to `monocypher.h` so that their `#include` resolves.

| File | From | SHA-256 |
|---|---|---|
| monocypher.c | src/ | `57eb914fc88136119bd41655cccb8c250048bf54d470540625186f8ab16f64be` |
| monocypher.h | src/ | `c494da712122da7ff679fdcf318a5317e84972b6c950fe9d896212947797facd` |
| monocypher-ed25519.c | src/optional/ | `60fce3578fb00b00da96490653d993c4cb427b1e1be38183285c66e04d22cc18` |
| monocypher-ed25519.h | src/optional/ | `abc4fad381879f5c29176ebe014b9189956b3dfe0a3e36459b6990bc57212380` |
| LICENCE.md | / | `5f8360e4c06ddcc584bdb4b210c6af824c4bb301e6a9a521869b6d90795ca4b3` |
| AUTHORS.md | / | `75a4d04559754a1016006f2c0e194cc7b459583cf9b1e2ce4ec10c74cb3de578` |

Licence: dual BSD-2-Clause / CC0-1.0 (see LICENCE.md).

## Verification rule (what `crypto_ed25519_check` accepts)

The rule comes from reading `crypto_eddsa_check_equation` in monocypher.c
and is pinned by tests in `tests/unit/t_crypto.c`:

- S must be below the group order L, so `S + L` is rejected (no
  malleability through S).
- A and R must decode to curve points. Non-canonical encodings are
  accepted on purpose (the "consensus-friendly" rule of Monocypher 4).
- The equation is checked with the cofactor: `[8]([S]B - [h]A - R) = 0`.

imagedb's public keys are trust roots read from META, never values chosen by
an attacker. R is hashed into `h`, so a different R encoding changes `h`
and cannot reuse a signature. An independent verifier must implement this
same rule.

## Updating

Replace the files from a newer release, check the tarball against
monocypher.org's published SHA-512 and against the GitHub release, update
this file, and run the four-configuration test matrix. The crypto tests
compare against RFC 8032 vectors and OpenSSL.
