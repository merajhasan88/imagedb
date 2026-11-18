/* Shared command-line sizes for a database's memory and segment-cache budgets. */
#ifndef IMDB_CLI_SIZE_H
#define IMDB_CLI_SIZE_H

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

/* A positive decimal size, no leading zero, optionally K, M or G (binary). */
static inline bool parse_size(const char *s, uint64_t *out)
{
    uint64_t v = 0;
    if (*s < '1' || *s > '9') return false;
    do {
        unsigned digit = (unsigned)(*s++ - '0');
        if (v > (UINT64_MAX - digit) / 10) return false;
        v = v * 10 + digit;
    } while (*s >= '0' && *s <= '9');
    unsigned shift = *s == 'K' ? 10 : *s == 'M' ? 20 : *s == 'G' ? 30 : 0;
    if (shift) s++;
    if (*s || v > (UINT64_MAX >> shift)) return false;
    *out = v << shift;
    return true;
}

static inline bool parse_seg_cache(const char *s, uint64_t *out)
{
    if (strcmp(s, "all") == 0) {
        *out = UINT64_MAX;
        return true;
    }
    return parse_size(s, out);
}

#endif
