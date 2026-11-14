/*
 * F5c (docs/f5c-design.md section 8): the Iceberg v3 layer's codecs, writers only (the engine never reads the layer
 * back: VERIFY writes it again and compares the bytes; the auditor has its own readers). Each writes one canonical
 * form, so a layer is a function of the lake it describes and the copy's location.
 *
 *   JSON (table metadata, Puffin's footer): keys in the caller's fixed order, no whitespace, integers as integers,
 *   strings escaped one way (", \ and the control characters below 0x20; the rest of UTF-8 as itself).
 *   Avro binary and object container files (manifest lists, manifests): zigzag varint longs and ints, length-prefixed
 *   bytes and strings, a union by its index, an array as one block of n items and then 0; a container's magic, its
 *   metadata map (avro.schema, avro.codec "null", then the caller's pairs in their order), a 16-byte sync marker, one
 *   block (its count, its size, its records, the marker).
 *   The 64-bit roaring bitmap in the portable format (RoaringFormatSpec, .work/ref/roaring-format-spec): a u64 count of
 *   32-bit bitmaps, each its u32 key (the positions' high halves, ascending) and a 32-bit bitmap of cookie 12346 (no run
 *   containers), its container count, the descriptive header, the offsets (always present with this cookie), then each
 *   container: an array of u16 values to 4,096 of them, a bitset of 1,024 u64 words past that: one encoding a set.
 *   Puffin's deletion-vector-v1 blob: a big-endian u32 length of the magic and the bitmap, magic D1 D3 39 64, the bitmap,
 *   a big-endian CRC-32 (ISO-HDLC, zlib's) of the magic and the bitmap; a Puffin file: PFA1, the blobs, then PFA1, the
 *   footer's JSON, its u32 little-endian length, four zero flag bytes, PFA1.
 */
#ifndef IMDB_ICECODEC_H
#define IMDB_ICECODEC_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "util.h"

/* ---- JSON ---- */
typedef struct ij {
    imdb_buf *b;
    int depth;
    bool more[24]; /* each open object's or array's: a member already written in it */
    bool key;      /* a key was just written: its value follows without a comma */
} ij;

void ij_begin(ij *j, imdb_buf *b);
void ij_obj(ij *j);
void ij_end_obj(ij *j);
void ij_arr(ij *j);
void ij_end_arr(ij *j);
void ij_key(ij *j, const char *k); /* a key (ASCII without quotes or backslashes), then its value */
void ij_str(ij *j, const char *s, size_t n);
void ij_cstr(ij *j, const char *s);
void ij_i64(ij *j, int64_t v);
void ij_bool(ij *j, bool v);
void ij_null(ij *j);
void ij_raw(ij *j, const char *s); /* an already encoded JSON value */

/* ---- Avro binary ---- */
void imdb_av_long(imdb_buf *b, int64_t v); /* an int too: Avro's int and long share the zigzag varint */
void imdb_av_bytes(imdb_buf *b, const void *p, size_t n);
void imdb_av_str(imdb_buf *b, const char *s);
/* an object container file: schema the records' Avro schema (JSON text), meta the nmeta pairs written after avro.schema
 * and avro.codec (meta[2k] a key, meta[2k + 1] its value), sync the file's marker, records the one block's nrec records */
void imdb_av_file(imdb_buf *out, const char *schema, const char *const *meta, uint32_t nmeta, const uint8_t sync[16],
                  uint64_t nrec, const uint8_t *records, size_t rlen);

/* ---- the 64-bit roaring bitmap, portable format ---- */
/* pos: n positions, strictly ascending, each below 2^63 (IMDB_ERR_STATE otherwise) */
int imdb_roaring64_put(imdb_buf *out, const uint64_t *pos, size_t n, imdb_err *e);

/* ---- Puffin ---- */
/* a deletion-vector-v1 blob of the n positions (imdb_roaring64_put's rule) */
int imdb_dv_blob(imdb_buf *out, const uint64_t *pos, size_t n, imdb_err *e);
/* CRC-32 (ISO-HDLC: reflected 0xEDB88320, initial and final xor 0xFFFFFFFF), the blob's checksum */
uint32_t imdb_crc32_iso(const uint8_t *p, size_t n);
/* a Puffin file of the blobs (their bytes, in order: the first at offset 4) and the footer's JSON */
void imdb_puffin_file(imdb_buf *out, const uint8_t *blobs, size_t blen, const char *footer, size_t flen);

#endif
