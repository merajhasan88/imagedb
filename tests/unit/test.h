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

/* a check that reports and goes on: between a fork and its kill, or an open and its close, CHECK's return would leave
 * a process running or a handle open (a second, misleading failure: heap drift) */
#define SOFT(c)                                                        \
    do {                                                               \
        if (!(c)) test_fail(__FILE__, __LINE__, #c);                   \
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
TESTS(format1)
TESTS(engine)
TESTS(lake)
TESTS(sql)
TESTS(audit)
TESTS(pool)
TESTS(ed25519)
TESTS(txn)
TESTS(review)
TESTS(review26)
TESTS(reviewmem)
TESTS(review1105)
TESTS(fault)
TESTS(repl)
TESTS(writer)
TESTS(round3)
TESTS(mem)
TESTS(index)
TESTS(join)
TESTS(retain)
TESTS(evict)
TESTS(segcache)
TESTS(relay)
TESTS(rewind)
TESTS(conc)
TESTS(vectors)
TESTS(stats)
TESTS(events)
TESTS(explain)
TESTS(sqlfn)
TESTS(group)
TESTS(jkind)
TESTS(rset)
TESTS(setop)
TESTS(window)
TESTS(dml)
TESTS(prep)
TESTS(copy)
TESTS(lazy)
TESTS(backup)
TESTS(catalogue)
TESTS(expr)
TESTS(cancel)
TESTS(drop)
TESTS(view) /* P2 S7 */
TESTS(abind) /* P2 S7b */
TESTS(qmem)
TESTS(ckey) /* P2 F4 */
TESTS(alter) /* P2 F1 */
TESTS(intw) /* F3a: SMALLINT and INTEGER */
TESTS(dt)   /* F3b: DATE and TIME */
TESTS(vc)   /* F3c: VARCHAR(n) */
TESTS(def)  /* F2a: clock values and column DEFAULTs */
TESTS(seq)  /* F2a-2: sequences, IDENTITY and SERIAL */
TESTS(check) /* F2b-1: CHECK constraints */
TESTS(gen)   /* F2c: generated columns */
TESTS(fk)    /* F2b-2: FOREIGN KEYs */
TESTS(ub)    /* F3d: UUID and BYTEA */
TESTS(dec38) /* F3e: NUMERIC to 38 digits */
TESTS(iv)    /* F3f: INTERVAL */
TESTS(enum) /* F3g: ENUM types */
TESTS(role) /* L: roles and grants */
TESTS(e3) /* E3: SERIALIZABLE */
TESTS(pq) /* F5: the canonical Parquet subset's codec */
TESTS(ice) /* F5c: the Iceberg v3 layer per copy */
TESTS(tz) /* P2: time zones */
TESTS(tzsql) /* P2: time zones through the engine */
TESTS(wire)  /* N1a: IMDBWIR1, the server's own protocol (server/wire.c) */
TESTS(conv)  /* N1b: the engine's results and parameters to and from the wire (server/conv.c) */
TESTS(pbind) /* N1b: a parameter binds as the literal of its value (numbers and NULLs) */

#endif
