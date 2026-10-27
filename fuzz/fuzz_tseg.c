/* Tagged log segments: the scan, in place on a copy, held to what it promises. Its frames pass the
 * untagged scan one after another from the segment's first seq, and a segment built from them
 * scans back to the same frames. The first 8 bytes name the first seq; the rest is the segment,
 * given a right header when the first byte is odd, so the fuzzer reaches the groups. */
#include "../src/log.h"
#include "fuzz_common.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < 8) return 0;
    uint64_t first = imdb_get_le64(data) % 1000 + 1;
    size_t n = size - 8;
    uint8_t *b = malloc(n ? n : 1);
    memcpy(b, data + 8, n);
    if (n >= IMDB_TSEG_SECTOR && (data[0] & 1)) imdb_tseg_header(first, b);
    size_t len = 0;
    imdb_tseg_end end;
    imdb_err e = {0};
    imdb_scan_status st = imdb_tseg_scan(b, n, first, &len, &end, &e);
    if (st == IMDB_SCAN_FRAME || len > n) abort();
    size_t off = 0;
    uint64_t seq = first;
    while (off < len) {
        size_t flen = 0;
        imdb_err e2 = {0};
        if (imdb_frame_scan(b, len, off, &flen, &e2) != IMDB_SCAN_FRAME || imdb_frame_seq(b + off) != seq) abort();
        seq++;
        off += flen;
    }
    if (end.frames != seq - first || (end.frames && end.last != seq - 1)) abort();
    if (len) {
        imdb_buf o;
        imdb_buf_init(&o);
        imdb_tseg_build(first, b, len, &o);
        if (!o.err) {
            uint8_t *c = malloc(o.len);
            memcpy(c, o.p, o.len);
            size_t l2 = 0;
            imdb_tseg_end e3;
            imdb_err e4 = {0};
            if (imdb_tseg_scan(c, o.len, first, &l2, &e3, &e4) != IMDB_SCAN_END || l2 != len || memcmp(c, b, len) != 0)
                abort();
            free(c);
        }
        imdb_buf_free(&o);
    }
    free(b);
    return 0;
}
