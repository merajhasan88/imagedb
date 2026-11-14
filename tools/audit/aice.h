/*
 * The auditor's own readers of the Iceberg v3 layer (F5c, docs/f5c-design.md section 8), sharing no code with src/:
 * a JSON parser (objects, arrays, strings, integers, other numbers as their text, true, false, null; bounded depth and
 * size), Avro's binary values and object container files, Puffin files and their deletion-vector-v1 blobs, and the
 * 64-bit roaring bitmap in the portable format (RoaringFormatSpec). Each refuses what it cannot read exactly; what the
 * layer means is checked against the auditor's own model in audit.c.
 */
#ifndef AICE_H
#define AICE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* ---- JSON ---- */
enum { AJ_NULL, AJ_BOOL, AJ_INT, AJ_NUM, AJ_STR, AJ_ARR, AJ_OBJ };
typedef struct aj {
    int kind;
    int64_t i;          /* AJ_INT, AJ_BOOL (0 or 1) */
    char *s;            /* AJ_STR (NUL-terminated, no NUL inside), AJ_NUM (its text) */
    size_t n;           /* AJ_ARR, AJ_OBJ: members */
    struct aj *v;       /* their values */
    char **key;         /* AJ_OBJ: their keys, in the file's order */
} aj;

/* 0, or -1 with *why: the whole text one JSON value */
int aj_parse(const char *p, size_t len, aj *out, const char **why);
const aj *aj_get(const aj *o, const char *key); /* an object's member, or NULL */
void aj_free(aj *a);

/* ---- Avro ---- */
typedef struct arr {
    const uint8_t *p;
    size_t n, at;
    bool bad;
} arr;
int64_t ar_long(arr *r);
/* a bytes or string value: its length and a pointer into the buffer (NULL when bad) */
const uint8_t *ar_bytes(arr *r, size_t *len);

typedef struct aocf {
    uint32_t nmeta;
    const uint8_t *mkey[16], *mval[16];
    size_t mklen[16], mvlen[16];
    uint64_t nrec;          /* the records of its one block */
    const uint8_t *records; /* their bytes */
    size_t rlen;
} aocf;
/* 0, or -1 with *why: an object container file of one block, codec null, its markers the same */
int aocf_read(const uint8_t *f, size_t len, aocf *out, const char **why);
/* a metadata value by key (NULL: none), its length in *len */
const uint8_t *aocf_meta(const aocf *o, const char *key, size_t *len);

/* ---- Puffin and its deletion vectors ---- */
/* 0, or -1 with *why: a Puffin file's footer JSON (into *footer, which the caller frees with aj_free) */
int apuf_read(const uint8_t *f, size_t len, aj *footer, const char **why);
/* a deletion-vector-v1 blob: its positions (malloc'd, ascending) in *pos, *n of them; 0, or -1 with *why */
int adv_read(const uint8_t *b, size_t len, uint64_t **pos, size_t *n, const char **why);

#endif
