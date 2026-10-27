/* Staged stream reader (authenticate before decode). Input layout:
 *   writer_pk[32] | root_pk[32] (zeros: no root) | db_id[16] | u64 expected seq | prev[32] | stream bytes
 * (the root key and the database let promotions, body kind 3, through to their checks); the
 * stream may begin with a session record (ship --acks)
 * Seeds come from a real database (forge corpus), so genuine signatures get
 * the fuzzer past the descriptor check and mutations explore the rest. */
#include "../src/stream.h"
#include "fuzz_common.h"

typedef struct memrd {
    const uint8_t *p;
    size_t n, off;
} memrd;

static int mem_read(void *ctx, void *buf, size_t n, size_t *got, imdb_err *e)
{
    (void)e;
    memrd *m = ctx;
    size_t k = m->n - m->off < n ? m->n - m->off : n;
    memcpy(buf, m->p + m->off, k);
    m->off += k;
    *got = k;
    return IMDB_OK;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    enum { PRE = 120 };
    if (size < PRE) return 0;
    uint8_t prev[32], zero[32] = {0};
    memcpy(prev, data + 88, 32);
    uint64_t seq = imdb_get_le64(data + 80);
    uint8_t *copy = malloc(size - PRE + 1); /* exact-size heap copy: ASan sees over-reads */
    memcpy(copy, data + PRE, size - PRE);
    memrd m = {copy, size - PRE, 0};
    imdb_stream s;
    imdb_stream_init(&s, data, mem_read, &m);
    imdb_stream_set_trust(&s, data + 64, memcmp(data + 32, zero, 32) ? data + 32 : NULL);
    bool session;
    uint8_t nonce[16];
    imdb_err es = {0};
    int src = imdb_stream_session(&s, nonce, &session, &es); /* ship --acks: a session record first */
    for (int i = 0; i < 16 && !src; i++) {
        bool eof;
        imdb_err e = {0};
        if (imdb_stream_next(&s, seq, prev, &eof, &e) || eof) break;
        imdb_commit_rec c;
        imdb_err e2 = {0};
        if (imdb_frame_decode_body(s.frame.p + IMDB_FRAME_HDR, s.frame.len - IMDB_FRAME_HDR, &c, &e2)) break;
        memcpy(prev, c.hash, 32);
        imdb_commit_free(&c);
        seq++;
    }
    imdb_stream_free(&s);
    free(copy);
    return 0;
}
