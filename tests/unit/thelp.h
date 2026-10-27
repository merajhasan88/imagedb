/* Shared helpers for engine and lake tests. */
#ifndef IMDB_THELP_H
#define IMDB_THELP_H

#include <stdbool.h>
#include <stdint.h>

#include "../../src/cpu.h"
#include "../../src/db.h"
#include "../../src/db_internal.h"
#include "../../src/fsio.h"
#include "../../src/lake.h"
#include "../../src/stream.h"
#include "test.h"

extern imdb_err g_e;

#define E (&g_e)
#define OK(expr)                                                         \
    do {                                                                 \
        imdb_err_clear(&g_e);                                            \
        int rc__ = (expr);                                               \
        if (rc__) {                                                      \
            snprintf(g_errmsg, sizeof g_errmsg, "%s", g_e.msg);          \
            char m_[700];                                                \
            snprintf(m_, sizeof m_, "%s -> %d (%s)", #expr, rc__, g_e.msg); \
            test_fail(__FILE__, __LINE__, m_);                           \
            return;                                                      \
        }                                                                \
    } while (0)
/* OK for a status already returned: OK(rc) would clear the message its call left in g_e */
#define OK_RC(rc_)                                                       \
    do {                                                                 \
        int rc__ = (rc_);                                                \
        if (rc__) {                                                      \
            snprintf(g_errmsg, sizeof g_errmsg, "%s", g_e.msg);          \
            char m_[700];                                                \
            snprintf(m_, sizeof m_, "%s -> %d (%s)", #rc_, rc__, g_e.msg); \
            test_fail(__FILE__, __LINE__, m_);                           \
            return;                                                      \
        }                                                                \
    } while (0)

imdb_db *open_db(const char *dir);
void txn_schema(imdb_schema *s);
void row_vals(imdb_value v[4], int64_t id, int64_t user, int64_t cents, const char *memo);
int make_table(imdb_db *db, imdb_err *e);
int ins1(imdb_db *db, int64_t id, int64_t user, int64_t cents, const char *memo);
uint64_t pk_lookup(imdb_db *db, int64_t id, uint64_t snap);
uint64_t count_subject(imdb_db *db, int64_t user, uint64_t snap);
char *path_join(const char *a, const char *b);
long file_size(const char *p);
uint8_t *slurp(const char *p, size_t *n);
void spit(const char *p, const uint8_t *b, size_t n);
bool mem_contains(const uint8_t *h, size_t hn, const char *needle);
bool mem_contains_n(const uint8_t *h, size_t hn, const uint8_t *needle, size_t nn);
bool tree_contains(const char *dir, const char *needle);
bool tree_contains_n(const char *dir, const uint8_t *needle, size_t nn);
int ship_to_file(const char *primary, uint64_t after, const char *file, imdb_err *e);
int apply_file(imdb_db *rep, const char *file, uint64_t *applied, imdb_err *e);
/* Compares two directories' regular files (names and bytes), recursively. */
bool dirs_identical(const char *a, const char *b, char *why, size_t whylen);
int count_files(const char *dir, const char *suffix);
/* A segment file's frames, either format (log.h); and back, in the format it had (tagged: one group). */
uint8_t *seg_frames(const char *path, size_t *n, uint64_t *first, bool *tagged);
void seg_put_frames(const char *path, uint64_t first, bool tagged, const uint8_t *b, size_t n);
/* Two log directories with the same segments holding the same frames (design.md §1). */
bool logs_identical(const char *a, const char *b, char *why, size_t whylen);
/* Frame bytes added where the writer would put them (a tagged segment: a new group, see thelp.c). */
void seg_append(const char *path, const uint8_t *b, size_t n);
long seg_frames_len(const char *path); /* the bytes of its frames (-1: unreadable) */
char *seg_path(const char *dir, int k);
int log_segments(const char *dir);
void rm_lake(const char *dir);
int copy_tree(const char *src, const char *dst);
/* Rewrites dir/DURABLE as a writer that crashed before publishing later commits would have left it. */
void durable_set(const char *dir, uint64_t seq, const uint8_t head[32], bool synced);

#endif
