/* Worker pool: every item runs exactly once, par_for returns only when all
 * have finished, results do not depend on the thread count, nesting runs
 * inline, and a forked child can still use it. */
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>

#include "../../src/pool.h"
#include "../../src/sha256.h"
#include "test.h"

typedef struct hjob {
    uint8_t (*out)[32];
} hjob;

static void hash_item(void *ctx, size_t i)
{
    hjob *j = ctx;
    uint64_t v = (uint64_t)i * 0x9E3779B97F4A7C15ull;
    imdb_sha256(&v, sizeof v, j->out[i]);
}

static void t_pool_deterministic(void)
{
    CHECK(imdb_pool_threads() >= 1);
    enum { N = 5000 };
    uint8_t (*par)[32] = calloc(N, 32), (*seq)[32] = calloc(N, 32);
    CHECK(par && seq);
    hjob j = {par};
    imdb_par_for(N, hash_item, &j);
    hjob k = {seq};
    for (size_t i = 0; i < N; i++) hash_item(&k, i); /* what IMDB_THREADS=1 does */
    CHECK(memcmp(par, seq, (size_t)N * 32) == 0);
    free(par);
    free(seq);
}

typedef struct tjob {
    _Atomic uint32_t *hits;
    _Atomic uint64_t *total;
    uint32_t tag;
    _Atomic uint32_t *last; /* tag of the job that last touched each slot */
} tjob;

static void tiny_item(void *ctx, size_t i)
{
    tjob *j = ctx;
    atomic_fetch_add(&j->hits[i], 1);
    atomic_store(&j->last[i], j->tag);
    atomic_fetch_add(j->total, 1);
}

static void t_pool_back_to_back(void)
{
    enum { JOBS = 10000, MAXN = 17 };
    _Atomic uint32_t hits[MAXN], last[MAXN];
    _Atomic uint64_t total = 0;
    uint64_t want = 0;
    for (uint32_t r = 0; r < JOBS; r++) {
        size_t n = 2 + r % (MAXN - 1);
        for (size_t i = 0; i < MAXN; i++) atomic_store(&hits[i], 0);
        tjob j = {hits, &total, r + 1, last};
        imdb_par_for(n, tiny_item, &j);
        want += n;
        /* returned => every item ran exactly once, and nothing from an earlier job is still running */
        for (size_t i = 0; i < n; i++) {
            CHECK(atomic_load(&hits[i]) == 1);
            CHECK(atomic_load(&last[i]) == r + 1);
        }
        for (size_t i = n; i < MAXN; i++) CHECK(atomic_load(&hits[i]) == 0);
    }
    CHECK(atomic_load(&total) == want);
}

typedef struct ujob {
    uint64_t *out;
} ujob;

static void uneven_item(void *ctx, size_t i)
{
    ujob *j = ctx;
    uint64_t x = i + 1, rounds = (i % 97) * (i % 97) * 8; /* from 0 to ~74K rounds */
    for (uint64_t r = 0; r < rounds; r++) x = x * 6364136223846793005ull + 1442695040888963407ull;
    j->out[i] = x;
}

static void t_pool_uneven(void)
{
    enum { N = 20000 };
    uint64_t *a = calloc(N, sizeof *a), *b = calloc(N, sizeof *b);
    CHECK(a && b);
    ujob ja = {a}, jb = {b};
    imdb_par_for(N, uneven_item, &ja);
    for (size_t i = 0; i < N; i++) uneven_item(&jb, i);
    CHECK(memcmp(a, b, N * sizeof *a) == 0);
    free(a);
    free(b);
}

typedef struct njob {
    pthread_t outer[64];
    _Atomic int bad;
    _Atomic int inner_done[64];
} njob;

typedef struct ninner {
    njob *j;
    size_t outer;
} ninner;

static void inner_item(void *ctx, size_t i)
{
    ninner *n = ctx;
    if (!pthread_equal(pthread_self(), n->j->outer[n->outer])) atomic_store(&n->j->bad, 1);
    (void)i;
    atomic_fetch_add(&n->j->inner_done[n->outer], 1);
}

static void outer_item(void *ctx, size_t i)
{
    njob *j = ctx;
    j->outer[i] = pthread_self();
    ninner n = {j, i};
    imdb_par_for(5, inner_item, &n); /* nested: inline on this thread, done when it returns */
    if (atomic_load(&j->inner_done[i]) != 5) atomic_store(&j->bad, 1);
}

static void t_pool_nested(void)
{
    njob *j = calloc(1, sizeof *j);
    CHECK(j);
    imdb_par_for(64, outer_item, j);
    CHECK(atomic_load(&j->bad) == 0);
    for (size_t i = 0; i < 64; i++) CHECK(atomic_load(&j->inner_done[i]) == 5);
    free(j);
}

static void t_pool_fork(void)
{
    enum { N = 300 };
    uint8_t (*want)[32] = calloc(N, 32);
    CHECK(want);
    hjob w = {want};
    imdb_par_for(N, hash_item, &w); /* the pool is up and has run a job */
    fflush(NULL);
    pid_t pid = fork();
    CHECK(pid >= 0);
    if (pid == 0) {
        alarm(20); /* a deadlock fails the test instead of hanging it */
        uint8_t (*got)[32] = calloc(N, 32);
        hjob g = {got};
        imdb_par_for(N, hash_item, &g);
        _exit(got && memcmp(got, want, (size_t)N * 32) == 0 && imdb_pool_threads() == 1 ? 0 : 1);
    }
    int st = 0;
    CHECK(waitpid(pid, &st, 0) == pid);
    CHECK(WIFEXITED(st) && WEXITSTATUS(st) == 0);
    /* and the parent's pool still works */
    uint8_t (*again)[32] = calloc(N, 32);
    CHECK(again);
    hjob a = {again};
    imdb_par_for(N, hash_item, &a);
    CHECK(memcmp(again, want, (size_t)N * 32) == 0);
    free(again);
    free(want);
}

const test_case pool_tests[] = {
    {"pool_deterministic", t_pool_deterministic},
    {"pool_back_to_back", t_pool_back_to_back},
    {"pool_uneven", t_pool_uneven},
    {"pool_nested", t_pool_nested},
    {"pool_fork", t_pool_fork},
};
const size_t pool_ntests = sizeof pool_tests / sizeof *pool_tests;
