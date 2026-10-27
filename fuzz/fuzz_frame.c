/* Log frames and commit records: framing scan, then strict body decode; DURABLE records; WRITERS. */
#include "../src/log.h"
#include "../src/writer.h"
#include "fuzz_common.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    imdb_err e = {0};
    size_t flen = 0;
    /* treat the input as a log: classify the first frame */
    imdb_scan_status st = imdb_frame_scan(data, size, 0, &flen, &e);
    if (st == IMDB_SCAN_FRAME && flen > IMDB_FRAME_HDR) {
        imdb_commit_rec c;
        imdb_err e2 = {0};
        if (imdb_frame_decode_body(data + IMDB_FRAME_HDR, flen - IMDB_FRAME_HDR, &c, &e2) == 0) imdb_commit_free(&c);
    }
    /* and directly as a body (exact-size copy so ASan sees over-reads) */
    uint8_t *b = malloc(size ? size : 1);
    memcpy(b, data, size);
    imdb_commit_rec c;
    imdb_err e3 = {0};
    if (imdb_frame_decode_body(b, size, &c, &e3) == 0) imdb_commit_free(&c);
    free(b);
    /* and as a DURABLE watermark: decoding is strict, so it must re-encode to the same bytes */
    imdb_durable w;
    imdb_err e4 = {0};
    if (imdb_durable_decode(data, size, &w, &e4) == 0) {
        uint8_t out[IMDB_DURABLE_LEN];
        imdb_durable_encode(&w, out);
        if (memcmp(out, data, IMDB_DURABLE_LEN) != 0) abort();
    }
    /* and as WRITERS (writer.h), after the keys its entries must prove from: writer[32] | root[32] */
    if (size >= 64 + 24) {
        imdb_db *db = calloc(1, sizeof *db);
        memcpy(db->meta.writer, data, 32);
        memcpy(db->meta.root, data + 32, 32);
        db->meta.has_root = true;
        memcpy(db->db_id, data + 64 + 8, 16); /* the file's own, so the proof is what is fuzzed */
        uint8_t *wb = malloc(size - 64);
        memcpy(wb, data + 64, size - 64);
        imdb_err e5 = {0};
        (void)imdb_writers_parse(db, wb, size - 64, &e5);
        imdb_writers_free(db);
        free(wb);
        free(db);
    }
    return 0;
}
