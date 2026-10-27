/* Every dispatched kernel (asm/SIMD when available) against its C reference. */
#include <stdlib.h>
#include <sys/mman.h>
#include <unistd.h>

#include "../../src/cpu.h"
#include "../../src/db.h"
#include "test.h"

static void t_dispatch_report(void)
{
    const imdb_kernels *k = imdb_kern();
    const imdb_cpu *c = imdb_cpu_get();
    printf("    cpu: sse42=%d avx2=%d bmi2=%d forced_scalar=%d\n", c->sse42, c->avx2, c->bmi2, c->forced_scalar);
    uint8_t alg = 0; /* the suite's: the matrix's alg 1 pass shows here that it ran under alg 1 */
    imdb_err ea = {0};
    CHECK(imdb_default_digest_alg(&alg, &ea) == 0);
    const char *env = getenv("IMDB_DIGEST_ALG");
    printf("    new databases: digest_alg %u (IMDB_DIGEST_ALG %s)\n", (unsigned)alg, env ? env : "unset");
    printf("    kernels: crc32c=%s lthash=%s expand=%s expand2=%s sha256x8=%s utf8=%s filter=%s sum=%s\n", k->crc32c_name,
           k->lthash_name, k->expand_name, k->expand2_name, k->sha8_name, k->utf8_name, k->filter_name, k->sum_name);
    if (c->forced_scalar)
        CHECK(k->crc32c == imdb_crc32c_ref && k->filter_range_i64 == imdb_filter_range_i64_ref &&
              k->lthash_expand2 == imdb_lthash_expand2_ref && k->sha256_x8 == imdb_sha256_x8_ref);
}

static void t_ascii_prefix(void)
{
    const imdb_kernels *k = imdb_kern();
    static uint8_t buf[300];
    for (int it = 0; it < 20000; it++) {
        size_t n = test_rand() % 260, off = test_rand() % 32;
        for (size_t i = 0; i < n; i++) buf[off + i] = (uint8_t)(1 + test_rand() % 127);
        if (n && test_rand() % 3) buf[off + test_rand() % n] = (test_rand() & 1) ? 0x00 : (uint8_t)(0x80 | test_rand());
        uint8_t *h = malloc(n ? n : 1); /* exact size: ASan catches over-reads */
        memcpy(h, buf + off, n);
        CHECK(k->ascii_prefix(h, n) == imdb_ascii_prefix_ref(h, n));
        free(h);
    }
    CHECK(imdb_ascii_prefix_ref((const uint8_t *)"ab\0c", 4) == 2);
    CHECK(k->ascii_prefix((const uint8_t *)"ab\0c", 4) == 2);
}

/* Inputs and outputs are exact-size heap blocks so ASan sees any access
 * outside [0, n) values / ceil(n/64) words, in the asm kernels too. */
static void t_filter_range(void)
{
    const imdb_kernels *k = imdb_kern();
    const int64_t edge[] = {INT64_MIN, INT64_MIN + 1, -1, 0, 1, INT64_MAX - 1, INT64_MAX};
    for (int it = 0; it < 3000; it++) {
        size_t n = test_rand() % 700, words = (n + 63) / 64;
        int64_t *col = malloc((n ? n : 1) * sizeof *col);
        uint64_t *a = malloc((words ? words : 1) * sizeof *a), *b = malloc((words ? words : 1) * sizeof *b);
        for (size_t i = 0; i < n; i++)
            col[i] = (test_rand() % 4 == 0) ? edge[test_rand() % 7] : (int64_t)(test_rand() % 200) - 100;
        int64_t lo = (test_rand() % 4 == 0) ? edge[test_rand() % 7] : (int64_t)(test_rand() % 200) - 100;
        int64_t hi = (test_rand() % 4 == 0) ? edge[test_rand() % 7] : (int64_t)(test_rand() % 200) - 100;
        memset(a, 0xAA, (words ? words : 1) * sizeof *a);
        memset(b, 0x55, (words ? words : 1) * sizeof *b);
        imdb_filter_range_i64_ref(col, n, lo, hi, a);
        k->filter_range_i64(col, n, lo, hi, b);
        CHECK(words == 0 || memcmp(a, b, words * sizeof *a) == 0);
        free(col);
        free(a);
        free(b);
    }
}

static void t_sum_masked(void)
{
    const imdb_kernels *k = imdb_kern();
    for (int it = 0; it < 3000; it++) {
        size_t n = test_rand() % 900, words = (n + 63) / 64;
        int64_t *col = malloc((n ? n : 1) * sizeof *col);
        uint64_t *bits = malloc((words ? words : 1) * sizeof *bits);
        for (size_t i = 0; i < n; i++) {
            uint64_t r = test_rand();
            col[i] = (r % 5 == 0) ? INT64_MAX : (r % 5 == 1) ? INT64_MIN : (int64_t)test_rand();
        }
        for (size_t w = 0; w < words; w++) bits[w] = test_rand();
        if (n % 64) bits[n / 64] &= (1ull << (n % 64)) - 1;
        int64_t r1[2], r2[2];
        imdb_sum_masked_i64_ref(col, bits, n, r1);
        k->sum_masked_i64(col, bits, n, r2);
        CHECK(r1[0] == r2[0] && r1[1] == r2[1]);
        __int128 t = 0;
        for (size_t i = 0; i < n; i++)
            if (bits[i / 64] >> (i % 64) & 1) t += col[i];
        CHECK(r1[0] == (int64_t)(uint64_t)t && r1[1] == (int64_t)(t >> 64));
        free(col);
        free(bits);
    }
    /* all-selected worst case: magnitudes near 2^63 summed many times stay exact */
    size_t n = 4096;
    int64_t *col = malloc(n * sizeof *col);
    uint64_t *bits = malloc(n / 64 * sizeof *bits);
    for (size_t i = 0; i < n; i++) col[i] = (i & 1) ? INT64_MAX : INT64_MAX - 1;
    memset(bits, 0xFF, n / 64 * sizeof *bits);
    int64_t r1[2], r2[2];
    imdb_sum_masked_i64_ref(col, bits, n, r1);
    k->sum_masked_i64(col, bits, n, r2);
    CHECK(r1[0] == r2[0] && r1[1] == r2[1] && r1[1] > 0);
    free(col);
    free(bits);
}

static void t_crc_lthash_exact(void)
{
    const imdb_kernels *k = imdb_kern();
    for (int it = 0; it < 500; it++) {
        size_t n = test_rand() % 300;
        uint8_t *b = malloc(n ? n : 1);
        test_rand_bytes(b, n);
        CHECK(k->crc32c(7, b, n) == imdb_crc32c_ref(7, b, n));
        free(b);
    }
    uint16_t *acc = malloc(2048), *x = malloc(2048), *ref = malloc(2048);
    test_rand_bytes(acc, 2048);
    test_rand_bytes(x, 2048);
    memcpy(ref, acc, 2048);
    k->lthash_sub(acc, x);
    imdb_lthash_sub_ref(ref, x);
    CHECK(memcmp(acc, ref, 2048) == 0);
    free(acc);
    free(x);
    free(ref);
}

/* ASan does not instrument hand-written assembly, so exact-size heap blocks
 * prove nothing about the asm kernels. Here each buffer ends exactly at a
 * PROT_NONE page: any read or write past the end faults immediately. */
typedef struct guarded {
    uint8_t *base;
    size_t maplen;
    uint8_t *p; /* n usable bytes ending at the guard page */
} guarded;

static bool gmap(guarded *g, size_t n)
{
    size_t pg = (size_t)sysconf(_SC_PAGESIZE);
    size_t body = (n + pg - 1) / pg * pg;
    if (!body) body = pg;
    g->maplen = body + 2 * pg;
    g->base = mmap(NULL, g->maplen, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (g->base == MAP_FAILED) return false;
    mprotect(g->base, pg, PROT_NONE);                 /* guard before */
    mprotect(g->base + pg + body, pg, PROT_NONE);     /* guard after  */
    g->p = g->base + pg + body - n;
    return true;
}

static void gunmap(guarded *g) { munmap(g->base, g->maplen); }

static void t_guard_pages(void)
{
    const imdb_kernels *k = imdb_kern();
    for (size_t n = 0; n <= 300; n++) {
        guarded in, out;
        CHECK(gmap(&in, n * 8));
        size_t words = (n + 63) / 64;
        CHECK(gmap(&out, words * 8));
        int64_t *col = (int64_t *)(void *)in.p;
        for (size_t i = 0; i < n; i++) col[i] = (int64_t)(test_rand() % 100) - 50;
        uint64_t ref[8] = {0};
        imdb_filter_range_i64_ref(col, n, -10, 10, ref);
        k->filter_range_i64(col, n, -10, 10, (uint64_t *)(void *)out.p);
        CHECK(words == 0 || memcmp(ref, out.p, words * 8) == 0);
        int64_t r1[2], r2[2];
        imdb_sum_masked_i64_ref(col, (const uint64_t *)(void *)out.p, n, r1);
        k->sum_masked_i64(col, (const uint64_t *)(void *)out.p, n, r2);
        CHECK(r1[0] == r2[0] && r1[1] == r2[1]);
        CHECK(k->crc32c(0, in.p, n * 8) == imdb_crc32c_ref(0, in.p, n * 8));
        memset(in.p, 'a', n * 8);
        CHECK(k->ascii_prefix(in.p, n * 8) == n * 8);
        if (n) in.p[n * 8 - 1] = 0x80;
        CHECK(k->ascii_prefix(in.p, n * 8) == (n ? n * 8 - 1 : 0));
        gunmap(&in);
        gunmap(&out);
    }
    /* byte-granular lengths for the byte kernels */
    for (size_t n = 0; n <= 200; n++) {
        guarded b;
        CHECK(gmap(&b, n));
        memset(b.p, 'x', n);
        CHECK(k->ascii_prefix(b.p, n) == n);
        CHECK(k->crc32c(1, b.p, n) == imdb_crc32c_ref(1, b.p, n));
        gunmap(&b);
    }
    guarded l1, l2;
    CHECK(gmap(&l1, 2048) && gmap(&l2, 2048));
    test_rand_bytes(l1.p, 2048);
    test_rand_bytes(l2.p, 2048);
    k->lthash_add((uint16_t *)(void *)l1.p, (const uint16_t *)(void *)l2.p);
    k->lthash_sub((uint16_t *)(void *)l1.p, (const uint16_t *)(void *)l2.p);
    gunmap(&l1);
    gunmap(&l2);
    /* digest_alg 2's kernels: the key, each message and each output end at a guard page */
    guarded key, el;
    CHECK(gmap(&key, 32) && gmap(&el, 2048));
    test_rand_bytes(key.p, 32);
    uint8_t want[2048];
    imdb_lthash_expand2_ref(key.p, want);
    k->lthash_expand2(key.p, el.p);
    CHECK(memcmp(el.p, want, 2048) == 0);
    gunmap(&key);
    gunmap(&el);
    for (size_t nblk = 1; nblk <= 6; nblk++) {
        guarded msg[8], out;
        const uint8_t *ptr[8];
        bool ok = gmap(&out, 8 * 32);
        for (int l = 0; l < 8; l++) {
            ok = gmap(&msg[l], nblk * 64) && ok;
            test_rand_bytes(msg[l].p, nblk * 64);
            ptr[l] = msg[l].p;
        }
        CHECK(ok);
        uint8_t ref[8][32];
        imdb_sha256_x8_ref(ptr, nblk, ref);
        k->sha256_x8(ptr, nblk, (uint8_t(*)[32])(void *)out.p);
        CHECK(memcmp(out.p, ref, sizeof ref) == 0);
        for (int l = 0; l < 8; l++) gunmap(&msg[l]);
        gunmap(&out);
    }
}


const test_case kernels_tests[] = {
    {"dispatch_report", t_dispatch_report},
    {"ascii_prefix", t_ascii_prefix},
    {"filter_range", t_filter_range},
    {"sum_masked", t_sum_masked},
    {"crc_lthash_exact", t_crc_lthash_exact},
    {"guard_pages", t_guard_pages},
};
const size_t kernels_ntests = sizeof kernels_tests / sizeof *kernels_tests;
