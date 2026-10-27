/*
 * Open-addressing hash map from a key (INT64 or TEXT bytes) to a u64 value.
 * SipHash-2-4 with a per-process random seed: adversarial keys cannot force
 * collisions. Iteration order is never used to produce output or file bytes
 * (determinism rule D1 in docs/DESIGN.md).
 */
#ifndef IMDB_HASHMAP_H
#define IMDB_HASHMAP_H

#include <stdbool.h>
#include <stdint.h>

#include "codec.h"
#include "util.h"

typedef struct imdb_hslot {
    uint64_t hash;   /* 0 = empty */
    uint64_t val;
    int64_t ikey;
    uint8_t *skey;   /* owned copy for TEXT keys */
    uint32_t slen;
} imdb_hslot;

typedef struct imdb_hmap {
    imdb_hslot *slots;
    size_t cap;      /* power of two */
    size_t count;
    size_t key_bytes; /* owned TEXT key copies (the memory budget counts them, R4) */
    uint8_t ktype;   /* IMDB_T_INT64 or IMDB_T_TEXT */
} imdb_hmap;

int imdb_hmap_init(imdb_hmap *m, uint8_t ktype, imdb_err *e);
void imdb_hmap_free(imdb_hmap *m);
/* Returns pointer to the value or NULL. */
uint64_t *imdb_hmap_get(const imdb_hmap *m, const imdb_value *k);
/* Inserts or overwrites. */
int imdb_hmap_put(imdb_hmap *m, const imdb_value *k, uint64_t val, imdb_err *e);
/* Removes the key and wipes its stored copy; true if it existed. */
bool imdb_hmap_del(imdb_hmap *m, const imdb_value *k);
uint64_t imdb_hash_seed(void);

#endif
