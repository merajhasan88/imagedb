/* Minimal test harness: each t_*.c file exports a table of test cases. */
#ifndef IMDB_TEST_H
#define IMDB_TEST_H

#include <stdint.h>
#include <stdio.h>
#include <string.h>

typedef struct test_case {
    const char *name;
    void (*fn)(void);
} test_case;

extern int g_test_failed;
void test_fail(const char *file, int line, const char *what);
uint64_t test_rand(void);           /* deterministic xorshift, seeded per test */
void test_seed(uint64_t s);         /* reseed (a test that runs several random rounds) */
void test_rand_bytes(void *p, size_t n);
const char *test_tmpdir(void);      /* fresh empty directory per test */

#define CHECK(c)                                                       \
    do {                                                               \
        if (!(c)) {                                                    \
            test_fail(__FILE__, __LINE__, #c);                         \
            return;                                                    \
        }                                                              \
    } while (0)

#define CHECK_OK(expr)                                                 \
    do {                                                               \
        int rc_ = (expr);                                              \
        if (rc_ != 0) {                                                \
            char m_[512];                                              \
            snprintf(m_, sizeof m_, "%s -> %d (%s)", #expr, rc_, g_errmsg); \
            test_fail(__FILE__, __LINE__, m_);                         \
            return;                                                    \
        }                                                              \
    } while (0)

extern char g_errmsg[512];

#define TESTS(group) extern const test_case group##_tests[]; extern const size_t group##_ntests;
TESTS(crypto)
TESTS(kernels)
TESTS(codec)
TESTS(tseg)
TESTS(engine)
TESTS(lake)
TESTS(sql)
TESTS(audit)
TESTS(pool)
TESTS(ed25519)
TESTS(txn)
TESTS(review)
TESTS(review26)
TESTS(fault)
TESTS(repl)
TESTS(writer)
TESTS(round3)
TESTS(mem)
TESTS(index)
TESTS(join)
TESTS(retain)
TESTS(evict)

#endif
