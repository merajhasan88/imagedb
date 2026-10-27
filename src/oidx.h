/* The ordered structure behind CREATE INDEX: (key, vid) entries in Bentley-Saxe sorted runs.
 * Level i holds nothing or exactly IMDB_OIDX_BASE << i entries, sorted by (key, vid), and a small
 * unsorted level-0 buffer takes new entries; a full buffer is sorted and carried down, merging
 * like a binary counter. An insert costs O(log n) amortized, a range O(log^2 n + matches).
 * A key is nk 64-bit words, one per indexed column, compared word by word: equality on the first
 * columns and a range on the next is one contiguous range of keys. Each word is the column's value
 * mapped to an unsigned order (imdb_index_key_of in db.c); an index may return a superset of the
 * matches (a TEXT word is an 8-byte prefix), so callers check every predicate again.
 * Derived state: built from a table's versions at open, never written to disk. */
#ifndef IMDB_OIDX_H
#define IMDB_OIDX_H

#include <stdint.h>

#include "util.h"

#define IMDB_OIDX_BASE 64u
#define IMDB_OIDX_LEVELS 48 /* IMDB_OIDX_BASE << 47 is past any version count */

/* An entry is nk + 1 words: the key's nk words, then the vid. */
typedef struct imdb_oidx {
    uint64_t *run[IMDB_OIDX_LEVELS]; /* run[i]: IMDB_OIDX_BASE << i entries, or NULL */
    uint64_t *buf;                   /* level 0, unsorted: nbuf < IMDB_OIDX_BASE entries */
    uint32_t nbuf;
    uint8_t nk;                      /* key words, 1..IMDB_MAX_INDEX_COLS (imdb_oidx_init) */
} imdb_oidx;

void imdb_oidx_init(imdb_oidx *x, uint8_t nk);
int imdb_oidx_insert(imdb_oidx *x, const uint64_t *key, uint64_t vid, imdb_err *e);
/* replaces x's entries by the n entries of all, nk + 1 words each (taken over; sorted here): the
 * build at open, ERASE, PURGE */
int imdb_oidx_build(imdb_oidx *x, uint64_t *all, uint64_t n, imdb_err *e);
void imdb_oidx_free(imdb_oidx *x); /* wipes (an erased version's key is the erased value); keeps nk */
/* f(ctx, key, vid) for every entry with lo <= key <= hi (nk words each, compared word by word),
 * in no particular order; stops at f's error */
int imdb_oidx_range(const imdb_oidx *x, const uint64_t *lo, const uint64_t *hi,
                    int (*f)(void *ctx, const uint64_t *key, uint64_t vid), void *ctx);
/* how many entries that range holds, in O(log^2 n): the planner's estimate (sql_exec.c) */
uint64_t imdb_oidx_count(const imdb_oidx *x, const uint64_t *lo, const uint64_t *hi);
uint64_t imdb_oidx_bytes(const imdb_oidx *x); /* what it holds, for imdb_mem */
/* what k more inserts allocate at most (every carry they set off, counted whole), for admission */
uint64_t imdb_oidx_growth(const imdb_oidx *x, uint64_t k);
/* the bytes one entry takes with nk key words, for admission before the structure exists */
static inline uint64_t imdb_oidx_entry_bytes(uint8_t nk) { return ((uint64_t)nk + 1) * sizeof(uint64_t); }

#endif
