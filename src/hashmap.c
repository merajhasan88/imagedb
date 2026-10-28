#include "hashmap.h"

#include <stdlib.h>

static uint64_t g_seed;
static int g_seeded;

uint64_t imdb_hash_seed(void)
{
    if (!__atomic_load_n(&g_seeded, __ATOMIC_ACQUIRE)) {
        uint64_t s = 0;
        imdb_err e = {0};
        if (imdb_random(&s, sizeof s, &e) != IMDB_OK) s = (uint64_t)(uintptr_t)&g_seed * 0x9e3779b97f4a7c15ull;
        g_seed = s | 1;
        __atomic_store_n(&g_seeded, 1, __ATOMIC_RELEASE);
    }
    return g_seed;
}

static uint64_t khash(const imdb_value *k)
{
    uint64_t h = imdb_value_hash(k, imdb_hash_seed());
    return h ? h : 1;
}

static bool keq(const imdb_hmap *m, const imdb_hslot *s, const imdb_value *k)
{
    if (m->ktype == IMDB_T_TEXT) return s->slen == k->len && (k->len == 0 || memcmp(s->skey, k->s, k->len) == 0);
    return s->ikey == k->i;
}

int imdb_hmap_init(imdb_hmap *m, uint8_t ktype, imdb_err *e)
{
    m->cap = 16;
    m->count = m->key_bytes = 0;
    m->ktype = ktype == IMDB_T_TEXT ? IMDB_T_TEXT : IMDB_T_INT64;
    m->slots = imdb_alloc_array(m->cap, sizeof *m->slots, e);
    return m->slots ? IMDB_OK : e->code;
}

void imdb_hmap_free(imdb_hmap *m)
{
    if (!m->slots) return;
    for (size_t i = 0; i < m->cap; i++)
        if (m->slots[i].skey) {
            imdb_wipe(m->slots[i].skey, m->slots[i].slen);
            imdb_free(m->slots[i].skey);
        }
    imdb_wipe(m->slots, m->cap * sizeof *m->slots); /* INT64 keys live in the slots themselves */
    imdb_free(m->slots);
    m->slots = NULL;
    m->cap = m->count = m->key_bytes = 0;
}

static imdb_hslot *find(const imdb_hmap *m, const imdb_value *k, uint64_t h)
{
    size_t mask = m->cap - 1;
    for (size_t i = h & mask;; i = (i + 1) & mask) {
        imdb_hslot *s = &m->slots[i];
        if (!s->hash) return NULL;
        if (s->hash == h && keq(m, s, k)) return s;
    }
}

uint64_t *imdb_hmap_get(const imdb_hmap *m, const imdb_value *k)
{
    imdb_hslot *s = find(m, k, khash(k));
    return s ? &s->val : NULL;
}

static int grow(imdb_hmap *m, imdb_err *e)
{
    size_t ncap;
    if (imdb_mul_ovf(m->cap, (size_t)2, &ncap)) return imdb_fail(e, IMDB_ERR_LIMIT, "hash map too large");
    imdb_hslot *ns = imdb_alloc_array(ncap, sizeof *ns, e);
    if (!ns) return e->code;
    for (size_t i = 0; i < m->cap; i++) {
        imdb_hslot *s = &m->slots[i];
        if (!s->hash) continue;
        size_t j = s->hash & (ncap - 1);
        while (ns[j].hash) j = (j + 1) & (ncap - 1);
        ns[j] = *s;
    }
    imdb_wipe(m->slots, m->cap * sizeof *m->slots); /* the old table holds copies of every key */
    imdb_free(m->slots);
    m->slots = ns;
    m->cap = ncap;
    return IMDB_OK;
}

int imdb_hmap_put(imdb_hmap *m, const imdb_value *k, uint64_t val, imdb_err *e)
{
    uint64_t h = khash(k);
    imdb_hslot *s = find(m, k, h);
    if (s) {
        s->val = val;
        return IMDB_OK;
    }
    if ((m->count + 1) * 4 > m->cap * 3 && grow(m, e)) return e->code;
    size_t mask = m->cap - 1, i = h & mask;
    while (m->slots[i].hash) i = (i + 1) & mask;
    s = &m->slots[i];
    if (m->ktype == IMDB_T_TEXT) {
        s->skey = imdb_alloc(k->len ? k->len : 1, e);
        if (!s->skey) return e->code;
        if (k->len) memcpy(s->skey, k->s, k->len);
        s->slen = k->len;
        m->key_bytes += k->len ? k->len : 1;
    } else {
        s->ikey = k->i;
    }
    s->hash = h;
    s->val = val;
    m->count++;
    return IMDB_OK;
}

bool imdb_hmap_del(imdb_hmap *m, const imdb_value *k)
{
    uint64_t h = khash(k);
    imdb_hslot *s = find(m, k, h);
    if (!s) return false;
    size_t mask = m->cap - 1, i = (size_t)(s - m->slots);
    if (s->skey) {
        imdb_wipe(s->skey, s->slen);
        imdb_free(s->skey);
        m->key_bytes -= s->slen ? s->slen : 1;
    }
    memset(s, 0, sizeof *s);
    m->count--;
    /* backward-shift deletion keeps probe sequences intact without tombstones */
    for (size_t j = (i + 1) & mask; m->slots[j].hash; j = (j + 1) & mask) {
        size_t home = m->slots[j].hash & mask;
        bool between = (i <= j) ? (i < home && home <= j) : (i < home || home <= j);
        if (between) continue;
        m->slots[i] = m->slots[j];
        memset(&m->slots[j], 0, sizeof m->slots[j]);
        i = j;
    }
    return true;
}
