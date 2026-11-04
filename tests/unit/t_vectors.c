/* The format's canonical vectors (P0 storage integrity; deferred.md D8 #6, 2026-11-04): the definitions a database's
 * bytes depend on, pinned by values an independent implementation can recompute. Each is derived here from fixed
 * inputs and compared with its published value, so a change to a definition (a domain tag, an encoding, a digest
 * algorithm) fails here before it reaches a database. The values were produced by this engine; the independent auditor
 * derives every one of them again with its own code (imagedb-audit vectors: its SHA-256, LtHash and ChaCha20, the
 * commit header encoded by hand), compared line by line by vectors_auditor. IMDB_VECTORS_PRINT=1 prints the values.
 *   c_i = SHA256("imagedb vector i"), i = 1..3
 *   per digest algorithm (1: LtHash16 by MGF1-SHA256, the digest SHA-256; 2: by ChaCha20, the digest a tree of eight):
 *     SHA256 of c_1's element (its 2048 lane bytes), the digests of {}, {c_1}, {c_1, c_2, c_3}, and of that set less c_2
 *   the row commitment of table 7, salt 00..0f, row "imagedb"; the genesis hash of db_id 10..1f;
 *   the commit hash of a header (seq 5, digest algorithm 2, time 1700000000000000 us, prev the genesis above, one op
 *   SET_RETENTION(table 0, 86400000000 us), the digest of {c_1} by algorithm 2), and the 52 bytes its signature covers */
#include <stdlib.h>

#include "../../src/codec.h"
#include "../../src/log.h"
#include "../../src/lthash.h"
#include "../../src/sha256.h"
#include "thelp.h"

/* the published values (2026-11-04); a change here is a format change, made on purpose and said in the plan log */
#define VEC_A1_E1 "50101545a9d5adabc4702c479da75eb9d04fe0c8c278cf141dd2bad7c9f0a934"
#define VEC_A1_EMPTY "951572071daa9b7e0d1ecf9cf0a4266818efc5d0b6c7f914e83316b0898c1bc4"
#define VEC_A1_ONE "3fabbaaea1db805f1a9f3e7508ffbe9a9d896104bc615971f63a06c7252a1430"
#define VEC_A1_THREE "d333649deb6f059232e4ebdd96bf8d2c60d1b7fc3787de61a95f2b1c346dae21"
#define VEC_A1_LESS "0eb5ae3fb60f965baac08bbf55a057bf9cb9093b7af58eb182b8183c5dca3481"
#define VEC_A2_E1 "832ba9fadd80bf6538fd01cd8aeab1e3f039de4574aba4a45bd1104f01ef29c6"
#define VEC_A2_EMPTY "866cd7d3893108b5f18d487839a1354b4991c1820403f626b3ab0d7528062f38"
#define VEC_A2_ONE "0cb0e165b7a149ca518cc4ae1c6ad2c5f4c0388338eb48faf648e950ab38cecb"
#define VEC_A2_THREE "7272e974dffc4bed5e1f9ebf0d716784eb038f5daec2c4c56ce43563fa470cdd"
#define VEC_A2_LESS "8518fe9064e4e2eca6741d15cd251f9681f514b5d986545f11f79ee96916b29e"
#define VEC_ROW "435487928b4a97389dbe29f98777dc1c5dc97821daaaf439564067bd49447f35"
#define VEC_GENESIS "3641988ed1970c1746ac3fbaa891ba4a3a5d2814156d5390f6d486c2cb15fb05"
#define VEC_COMMIT "3c30427caf9d24728cc8f7ab4aab7b94770b99e19b2096b52e2f3fe56e83f9e1"
#define VEC_SIGMSG "494d4442534947320500000000000000630000003c30427caf9d24728cc8f7ab4aab7b94770b99e19b2096b52e2f3fe56e83f9e1"

static void hexs(const uint8_t *b, size_t n, char *out)
{
    static const char d[] = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) {
        out[2 * i] = d[b[i] >> 4];
        out[2 * i + 1] = d[b[i] & 15];
    }
    out[2 * n] = 0;
}

static int g_vec_bad;

static void expect(const char *name, const uint8_t *b, size_t n, const char *want)
{
    char got[2 * 64 + 1];
    hexs(b, n, got);
    if (getenv("IMDB_VECTORS_PRINT")) fprintf(stderr, "    %-24s %s\n", name, got);
    if (strcmp(got, want) != 0) {
        char m[400];
        snprintf(m, sizeof m, "vector %s: %s, published %s", name, got, want);
        test_fail(__FILE__, __LINE__, m);
        g_vec_bad++;
    }
}

static void t_vectors_digests(void)
{
    uint8_t c[3][32];
    for (int i = 0; i < 3; i++) {
        char s[32];
        int n = snprintf(s, sizeof s, "imagedb vector %d", i + 1);
        imdb_sha256((const uint8_t *)s, (size_t)n, c[i]);
    }
    static const char *const want[2][5] = {
        {VEC_A1_E1, VEC_A1_EMPTY, VEC_A1_ONE, VEC_A1_THREE, VEC_A1_LESS},
        {VEC_A2_E1, VEC_A2_EMPTY, VEC_A2_ONE, VEC_A2_THREE, VEC_A2_LESS},
    };
    for (uint8_t alg = 1; alg <= 2; alg++) {
        const char *const *w = want[alg - 1];
        char nm[40];
        imdb_lthash el, acc;
        uint8_t lanes[IMDB_LTHASH_BYTES], d[32];
        imdb_lthash_element(alg, c[0], &el);
        imdb_lthash_to_bytes(&el, lanes);
        imdb_sha256(lanes, sizeof lanes, d);
        snprintf(nm, sizeof nm, "alg%u element(c1)", alg);
        expect(nm, d, 32, w[0]);
        imdb_lthash_zero(&acc);
        imdb_lthash_digest(alg, &acc, d);
        snprintf(nm, sizeof nm, "alg%u digest {}", alg);
        expect(nm, d, 32, w[1]);
        imdb_lthash_add_commit(alg, &acc, c[0]);
        imdb_lthash_digest(alg, &acc, d);
        snprintf(nm, sizeof nm, "alg%u digest {c1}", alg);
        expect(nm, d, 32, w[2]);
        imdb_lthash_add_commit(alg, &acc, c[1]);
        imdb_lthash_add_commit(alg, &acc, c[2]);
        imdb_lthash_digest(alg, &acc, d);
        snprintf(nm, sizeof nm, "alg%u digest {c1,c2,c3}", alg);
        expect(nm, d, 32, w[3]);
        imdb_lthash_sub_commit(alg, &acc, c[1]);
        imdb_lthash_digest(alg, &acc, d);
        snprintf(nm, sizeof nm, "alg%u digest {c1,c3}", alg);
        expect(nm, d, 32, w[4]);
        imdb_lthash other; /* the same set built in another order: the digest is the set's */
        imdb_lthash_zero(&other);
        imdb_lthash_add_commit(alg, &other, c[2]);
        imdb_lthash_add_commit(alg, &other, c[0]);
        uint8_t d2[32];
        imdb_lthash_digest(alg, &other, d2);
        CHECK(!memcmp(d, d2, 32));
    }
}

static void t_vectors_chain(void)
{
    uint8_t salt[16], dbid[16], out[32], g[32], c1[32];
    for (int i = 0; i < 16; i++) {
        salt[i] = (uint8_t)i;
        dbid[i] = (uint8_t)(0x10 + i);
    }
    imdb_row_commit(7, salt, (const uint8_t *)"imagedb", 7, out);
    expect("row commitment", out, 32, VEC_ROW);
    imdb_genesis_hash(dbid, g);
    expect("genesis", g, 32, VEC_GENESIS);
    imdb_sha256((const uint8_t *)"imagedb vector 1", 16, c1);
    imdb_lthash acc;
    imdb_lthash_zero(&acc);
    imdb_lthash_add_commit(IMDB_DIGEST_ALG_LTHASH16_TREE, &acc, c1);
    imdb_op op = {.code = IMDB_OP_SET_RETENTION, .table = 0, .retention_us = 86400000000ull};
    imdb_commit_rec c = {.seq = 5, .time_us = 1700000000000000ull, .alg = IMDB_DIGEST_ALG_LTHASH16_TREE, .ops = &op, .nops = 1};
    memcpy(c.prev, g, 32);
    imdb_lthash_digest(IMDB_DIGEST_ALG_LTHASH16_TREE, &acc, c.digest);
    imdb_buf b;
    imdb_buf_init(&b);
    imdb_commit_encode_header(&c, &b);
    OK(imdb_buf_check(&b, E));
    uint8_t h[32], msg[IMDB_SIGMSG_LEN];
    imdb_commit_hash(b.p, b.len, h);
    expect("commit hash", h, 32, VEC_COMMIT);
    imdb_commit_sigmsg(5, (uint32_t)b.len, h, msg);
    expect("signed message", msg, IMDB_SIGMSG_LEN, VEC_SIGMSG);
    imdb_buf_free(&b);
}


/* The auditor's own derivation of the same vectors (imagedb-audit vectors: its SHA-256, LtHash and ChaCha20, and the
 * commit header encoded by hand; no code shared with src/), line by line against the published values. IMDB_AUDIT_BIN
 * (the Makefile sets it) names the auditor; without it this test says so and compares nothing */
static void t_vectors_auditor(void)
{
    static const struct {
        const char *name, *want;
    } v[] = {
        {"alg1.element.c1", VEC_A1_E1}, {"alg1.digest.empty", VEC_A1_EMPTY}, {"alg1.digest.c1", VEC_A1_ONE},
        {"alg1.digest.c1c2c3", VEC_A1_THREE}, {"alg1.digest.c1c3", VEC_A1_LESS}, {"alg2.element.c1", VEC_A2_E1},
        {"alg2.digest.empty", VEC_A2_EMPTY}, {"alg2.digest.c1", VEC_A2_ONE}, {"alg2.digest.c1c2c3", VEC_A2_THREE},
        {"alg2.digest.c1c3", VEC_A2_LESS}, {"row", VEC_ROW}, {"genesis", VEC_GENESIS}, {"commit", VEC_COMMIT},
        {"sigmsg", VEC_SIGMSG},
    };
    const size_t nv = sizeof v / sizeof *v;
    const char *bin = getenv("IMDB_AUDIT_BIN");
    if (!bin || !*bin) {
        fprintf(stderr, "    (IMDB_AUDIT_BIN unset: the auditor's derivation is not compared)\n");
        return;
    }
    char out[700], cmd[1600];
    snprintf(out, sizeof out, "%s/vectors.txt", test_tmpdir());
    snprintf(cmd, sizeof cmd, "'%s' vectors > '%s'", bin, out);
    CHECK(system(cmd) == 0);
    FILE *f = fopen(out, "r");
    CHECK(f);
    if (!f) return;
    char line[512];
    size_t i = 0;
    bool same = true;
    while (fgets(line, sizeof line, f)) {
        line[strcspn(line, "\n")] = 0;
        char *sp = strchr(line, ' ');
        if (!sp || i >= nv) {
            same = false;
            break;
        }
        *sp = 0;
        if (strcmp(line, v[i].name) != 0 || strcmp(sp + 1, v[i].want) != 0) {
            fprintf(stderr, "    the auditor's %s: %s, published %s\n", line, sp + 1, v[i].want);
            same = false;
        }
        i++;
    }
    fclose(f);
    CHECK(same && i == nv);
}

const test_case vectors_tests[] = {
    {"vectors_digests", t_vectors_digests},
    {"vectors_chain", t_vectors_chain},
    {"vectors_auditor", t_vectors_auditor},
};
const size_t vectors_ntests = sizeof vectors_tests / sizeof *vectors_tests;
