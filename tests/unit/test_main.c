#include <errno.h>
#include <ftw.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "../../src/db.h"
#include "test.h"

int g_test_failed;
char g_errmsg[512];
static uint64_t g_rng;
static char g_tmp[512];
static char g_tmproot[400];
static int g_tmpcount;

void test_fail(const char *file, int line, const char *what)
{
    fprintf(stderr, "    FAIL %s:%d: %s\n", file, line, what);
    g_test_failed = 1;
}

void test_seed(uint64_t s) { g_rng = 0x9E3779B97F4A7C15ull ^ (s + 1) * 0xBF58476D1CE4E5B9ull; }

uint64_t test_rand(void)
{
    uint64_t x = g_rng;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    return g_rng = x;
}

void test_rand_bytes(void *p, size_t n)
{
    uint8_t *q = p;
    for (size_t i = 0; i < n; i++) q[i] = (uint8_t)(test_rand() >> 24);
}

static int rm_cb(const char *path, const struct stat *sb, int flag, struct FTW *ftw)
{
    (void)sb; (void)flag; (void)ftw;
    return remove(path);
}

const char *test_tmpdir(void)
{
    snprintf(g_tmp, sizeof g_tmp, "%s/t%04d", g_tmproot, g_tmpcount++);
    nftw(g_tmp, rm_cb, 16, FTW_DEPTH | FTW_PHYS);
    if (mkdir(g_tmp, 0700) != 0) {
        fprintf(stderr, "mkdir %s: %s\n", g_tmp, strerror(errno));
        exit(2);
    }
    return g_tmp;
}

struct group {
    const char *name;
    const test_case *t;
    const size_t *n;
};

int main(int argc, char **argv)
{
    const char *base = getenv("IMDB_TEST_TMP");
    snprintf(g_tmproot, sizeof g_tmproot, "%s/imdb-unit-%d", base ? base : "/tmp", (int)getpid());
    mkdir(g_tmproot, 0700);
    struct group groups[] = {
        {"crypto", crypto_tests, &crypto_ntests},
        {"kernels", kernels_tests, &kernels_ntests},
        {"codec", codec_tests, &codec_ntests},
        {"tseg", tseg_tests, &tseg_ntests},
        {"engine", engine_tests, &engine_ntests},
        {"lake", lake_tests, &lake_ntests},
        {"sql", sql_tests, &sql_ntests},
        {"audit", audit_tests, &audit_ntests},
        {"pool", pool_tests, &pool_ntests},
        {"ed25519", ed25519_tests, &ed25519_ntests},
        {"txn", txn_tests, &txn_ntests},
        {"review", review_tests, &review_ntests},
        {"review26", review26_tests, &review26_ntests},
        {"fault", fault_tests, &fault_ntests},
        {"repl", repl_tests, &repl_ntests},
        {"writer", writer_tests, &writer_ntests},
        {"round3", round3_tests, &round3_ntests},
        {"mem", mem_tests, &mem_ntests},
        {"index", index_tests, &index_ntests},
        {"join", join_tests, &join_ntests},
        {"retain", retain_tests, &retain_ntests},
        {"evict", evict_tests, &evict_ntests},
    };
    int failed = 0, run = 0;
    for (size_t g = 0; g < sizeof groups / sizeof *groups; g++) {
        for (size_t i = 0; i < *groups[g].n; i++) {
            const test_case *tc = &groups[g].t[i];
            if (argc > 1 && !strstr(tc->name, argv[1]) && strcmp(argv[1], groups[g].name) != 0) continue;
            g_rng = 0x9E3779B97F4A7C15ull ^ (uint64_t)(i + 1) * 0xBF58476D1CE4E5B9ull;
            g_test_failed = 0;
            imdb_log_set_tagged(true); /* a test of the untagged format turns it off for itself only */
            imdb_clock_offset(0);      /* a test that moves the clock (expiry) moves it for itself only */
            g_errmsg[0] = 0;
            printf("[%s] %s\n", groups[g].name, tc->name);
            fflush(stdout);
            uint64_t heap = imdb_heap_bytes();
            tc->fn();
            run++;
            /* every block the test's engine calls took is freed by its end (util.h): more left is a leak,
             * or a free that bypassed imdb_free; fewer, imdb_free given a block the helpers never charged */
            uint64_t left = imdb_heap_bytes();
            if (left != heap) {
                fprintf(stderr, "    FAIL heap drift: %+lld bytes held after the test\n", (long long)(left - heap));
                g_test_failed = 1;
            }
            if (g_test_failed) failed++;
        }
    }
    nftw(g_tmproot, rm_cb, 16, FTW_DEPTH | FTW_PHYS);
    printf("%d tests, %d failed\n", run, failed);
    return failed ? 1 : 0;
}
