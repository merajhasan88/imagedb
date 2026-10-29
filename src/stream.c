/* Staged, authenticate-before-decode commit stream reader (see stream.h). */
#include "stream.h"

#include <errno.h>
#include <stdlib.h>
#include <unistd.h>

#include "cpu.h"
#include "fsio.h"
#include "repl.h"

void imdb_stream_init(imdb_stream *s, const uint8_t writer_pk[IMDB_PUBKEY_LEN], imdb_read_fn read, void *ctx)
{
    memset(s, 0, sizeof *s);
    s->read = read;
    s->ctx = ctx;
    memcpy(s->writer_pk, writer_pk, IMDB_PUBKEY_LEN);
    imdb_buf_init(&s->frame);
}

void imdb_stream_set_trust(imdb_stream *s, const uint8_t db_id[16], const uint8_t *root)
{
    memcpy(s->db_id, db_id, 16);
    s->has_root = root != NULL;
    if (root) memcpy(s->root, root, IMDB_PUBKEY_LEN);
}

void imdb_stream_free(imdb_stream *s) { imdb_buf_wipe_free(&s->frame); }

int imdb_stream_fd_read(void *ctx, void *buf, size_t n, size_t *got, imdb_err *e)
{
    return imdb_read_all(*(const int *)ctx, buf, n, got, e);
}

void imdb_fdsrc_init(imdb_fdsrc *s, int fd)
{
    s->fd = fd;
    s->off = s->len = 0;
}

int imdb_fdsrc_read(void *ctx, void *buf, size_t n, size_t *got, imdb_err *e)
{
    imdb_fdsrc *s = ctx;
    uint8_t *dst = buf;
    size_t done = 0;
    while (done < n) {
        if (s->off == s->len) {
            if (n - done >= sizeof s->buf) { /* a large row goes straight to its destination */
                size_t g = 0;
                if (imdb_read_all(s->fd, dst + done, n - done, &g, e)) return e->code;
                done += g;
                break;
            }
            ssize_t r;
            do r = imdb_io_read(s->fd, s->buf, sizeof s->buf);
            while (r < 0 && errno == EINTR);
            if (r < 0) return imdb_fail(e, IMDB_ERR_IO, "read: %s", strerror(errno));
            if (r == 0) break; /* end of input */
            s->off = 0;
            s->len = (size_t)r;
        }
        size_t k = s->len - s->off < n - done ? s->len - s->off : n - done;
        memcpy(dst + done, s->buf + s->off, k);
        s->off += k;
        done += k;
    }
    *got = done;
    return IMDB_OK;
}

/* Reads exactly n more bytes into dst; a short read is a truncated frame. */
static int need(imdb_stream *s, void *dst, size_t n, imdb_err *e)
{
    size_t got = 0;
    if (s->read(s->ctx, dst, n, &got, e)) return e->code;
    if (got != n) {
        s->truncated = true;
        return imdb_fail(e, IMDB_ERR_CORRUPT, "stream truncated inside a frame");
    }
    return IMDB_OK;
}

int imdb_stream_need(imdb_stream *s, void *dst, size_t n, imdb_err *e)
{
    return need(s, dst, n, e);
}

int imdb_stream_seed(imdb_stream *s, uint8_t p[28], bool *have, imdb_err *e)
{
    *have = false;
    if (!s->nback) { /* after a session record: what follows it, read ahead as imdb_stream_session does */
        size_t got = 0;
        if (s->read(s->ctx, s->back, IMDB_FRAME_HDR, &got, e)) return e->code;
        s->nback = got;
    }
    if (s->nback != IMDB_FRAME_HDR || memcmp(s->back, "IMDBSED1", 8) != 0) return IMDB_OK;
    memcpy(p, s->back, IMDB_FRAME_HDR);
    s->nback = 0;
    if (need(s, p + IMDB_FRAME_HDR, 28 - IMDB_FRAME_HDR, e)) return e->code;
    *have = true;
    return IMDB_OK;
}

int imdb_stream_session(imdb_stream *s, uint8_t nonce[16], bool *have, imdb_err *e)
{
    *have = false;
    uint8_t b[IMDB_SESSION_LEN];
    size_t got = 0;
    if (s->read(s->ctx, b, IMDB_FRAME_HDR, &got, e)) return e->code;
    if (got < 8 || memcmp(b, "IMDBSES1", 8) != 0) { /* the first frame's prefix (or the end) */
        memcpy(s->back, b, got);
        s->nback = got;
        return IMDB_OK;
    }
    if (need(s, b + IMDB_FRAME_HDR, IMDB_SESSION_LEN - IMDB_FRAME_HDR, e)) return e->code;
    if (imdb_session_decode(b, s->db_id, nonce, e) < 0) return e->code;
    *have = true;
    return IMDB_OK;
}

/* Appends exactly n stream bytes to the frame buffer; returns their offset. */
static int need_frame(imdb_stream *s, size_t n, size_t *off, imdb_err *e)
{
    *off = s->frame.len;
    imdb_buf_put_zeros(&s->frame, n);
    if (imdb_buf_check(&s->frame, e)) return e->code;
    return need(s, s->frame.p + *off, n, e);
}

int imdb_stream_next(imdb_stream *s, uint64_t expect_seq, const uint8_t prev[32], bool *eof, imdb_err *e)
{
    *eof = false;
    s->frame.len = 0;
    s->truncated = false;
    uint8_t pre[IMDB_FRAME_HDR + IMDB_BODY_DESC];
    const imdb_kernels *k = imdb_kern();

    /* 1. prefix (it may have begun in what imdb_stream_session read) */
    size_t got = s->nback;
    memcpy(pre, s->back, s->nback);
    s->nback = 0;
    size_t more = 0;
    if (got < IMDB_FRAME_HDR && s->read(s->ctx, pre + got, IMDB_FRAME_HDR - got, &more, e)) return e->code;
    got += more;
    if (got == 0) {
        *eof = true;
        return IMDB_OK;
    }
    if (got < IMDB_FRAME_HDR) {
        s->truncated = true;
        return imdb_fail(e, IMDB_ERR_CORRUPT, "stream truncated inside a frame header");
    }
    if (imdb_get_le32(pre) != IMDB_FRAME_MAGIC || k->crc32c(0, pre, 12) != imdb_get_le32(pre + 12))
        return imdb_fail(e, IMDB_ERR_CORRUPT, "stream: bad frame header before commit %llu", (unsigned long long)expect_seq);
    uint32_t body_len = imdb_get_le32(pre + 4), body_crc = imdb_get_le32(pre + 8);
    if (body_len < IMDB_BODY_DESC + IMDB_HEADER_MIN + 4 || body_len > IMDB_MAX_FRAME)
        return imdb_fail(e, IMDB_ERR_CORRUPT, "stream: frame length out of range");

    /* 2. descriptor, then the signature: the only work on unauthenticated bytes */
    if (need(s, pre + IMDB_FRAME_HDR, IMDB_BODY_DESC, e)) return e->code;
    const uint8_t *d = pre + IMDB_FRAME_HDR;
    uint32_t hlen = imdb_get_le32(d + 1);
    uint64_t seq = imdb_get_le64(d + 5);
    const uint8_t *hash = d + 13, *sig = d + 45;
    bool promote = d[0] == IMDB_BODY_KIND_PROMOTE;
    size_t desc = IMDB_BODY_DESC + (promote ? IMDB_BODY_EXT : 0);
    if ((d[0] != IMDB_BODY_KIND && !promote) || hlen < IMDB_HEADER_MIN || hlen > IMDB_MAX_HEADER ||
        body_len < desc + IMDB_HEADER_MIN + 4 || hlen > body_len - desc - 4)
        return imdb_fail(e, IMDB_ERR_CORRUPT, "stream: bad frame descriptor");
    if (seq != expect_seq)
        return imdb_fail(e, IMDB_ERR_VERIFY, "stream: commit %llu where %llu was expected (replayed or reordered)",
                         (unsigned long long)seq, (unsigned long long)expect_seq);
    uint8_t ext[IMDB_BODY_EXT];
    const uint8_t *signer = s->writer_pk;
    if (promote) { /* a promotion: the root certificate first, then the descriptor under the key it certifies */
        if (need(s, ext, sizeof ext, e)) return e->code;
        uint8_t m[IMDB_PROMOTE_MSG_LEN];
        imdb_promote_msg(s->db_id, imdb_get_le32(ext), seq, prev, ext + 4, m);
        if (!s->has_root || !imdb_sig_verify(s->root, m, sizeof m, ext + 36))
            return imdb_fail(e, IMDB_ERR_AUTH, "stream: commit %llu promotes a writer without this database's root "
                             "certificate", (unsigned long long)seq);
        signer = ext + 4;
    }
    s->preauth_bytes = sizeof pre + (promote ? sizeof ext : 0);
    if (!imdb_commit_sig_valid(signer, seq, hlen, hash, sig))
        return imdb_fail(e, IMDB_ERR_AUTH, "stream: commit %llu is not signed by the writer key",
                         (unsigned long long)seq);

    /* 3. header: signed length, must hash to the signed commit hash */
    imdb_buf_put(&s->frame, pre, sizeof pre);
    if (promote) imdb_buf_put(&s->frame, ext, sizeof ext);
    size_t hoff;
    if (need_frame(s, hlen, &hoff, e)) return e->code;
    uint8_t h2[32];
    imdb_commit_hash(s->frame.p + hoff, hlen, h2);
    if (memcmp(h2, hash, 32) != 0)
        return imdb_fail(e, IMDB_ERR_AUTH, "stream: commit %llu header does not match its signed hash",
                         (unsigned long long)seq);
    imdb_commit_rec c;
    int rc = imdb_commit_decode_header(s->frame.p + hoff, hlen, &c, e);
    if (!rc && (c.seq != seq || memcmp(c.prev, prev, 32) != 0))
        rc = imdb_fail(e, IMDB_ERR_VERIFY, "stream: hash chain broken at commit %llu", (unsigned long long)seq);
    const imdb_op *w = rc ? NULL : imdb_commit_writer_op(&c);
    if (!rc && (w && w->how == IMDB_WRITER_PROMOTE) != promote)
        rc = imdb_fail(e, IMDB_ERR_CORRUPT, "stream: commit %llu: a promotion must come in a body of kind 3",
                       (unsigned long long)seq);
    if (!rc && promote && (w->epoch != imdb_get_le32(ext) || memcmp(w->new_pk, ext + 4, IMDB_PUBKEY_LEN) != 0))
        rc = imdb_fail(e, IMDB_ERR_CORRUPT, "stream: commit %llu: the promotion's certificate names another key",
                       (unsigned long long)seq);
    if (rc) goto out;

    /* 4. payload length, bounded by the authenticated ops */
    uint64_t npay = 0;
    for (uint32_t i = 0; i < c.nops; i++) npay += imdb_op_has_payload(c.ops[i].code);
    size_t poff;
    if ((rc = need_frame(s, 4, &poff, e))) goto out;
    uint32_t plen = imdb_get_le32(s->frame.p + poff);
    if (plen < npay || (uint64_t)plen > npay * (21ull + IMDB_MAX_ROW) ||
        (uint64_t)desc + hlen + 4 + plen != body_len) {
        rc = imdb_fail(e, IMDB_ERR_CORRUPT, "stream: commit %llu payload length disagrees with its header",
                       (unsigned long long)seq);
        goto out;
    }

    /* 5. rows, one at a time, each checked against its signed commitment */
    uint64_t left = plen;
    for (uint32_t i = 0; i < c.nops && !rc; i++) {
        const imdb_op *o = &c.ops[i];
        if (!imdb_op_has_payload(o->code)) continue;
        size_t at;
        if (left < 1 || (rc = need_frame(s, 1, &at, e))) break;
        left--;
        uint8_t kind = s->frame.p[at];
        if (kind == IMDB_PAYLOAD_REDACTED) continue;
        if (kind != IMDB_PAYLOAD_ROW || left < 20) {
            rc = imdb_fail(e, IMDB_ERR_CORRUPT, "stream: commit %llu: bad payload entry", (unsigned long long)seq);
            break;
        }
        if ((rc = need_frame(s, 20, &at, e))) break;
        left -= 20;
        uint32_t rl = imdb_get_le32(s->frame.p + at + 16);
        if (rl > IMDB_MAX_ROW || rl > left) {
            rc = imdb_fail(e, IMDB_ERR_CORRUPT, "stream: commit %llu: bad row length", (unsigned long long)seq);
            break;
        }
        size_t ro;
        if ((rc = need_frame(s, rl, &ro, e))) break;
        left -= rl;
        uint8_t cm[32];
        imdb_row_commit(o->table, s->frame.p + at, s->frame.p + ro, rl, cm);
        if (memcmp(cm, o->code == IMDB_OP_INSERT ? o->commit : o->new_commit, 32) != 0)
            rc = imdb_fail(e, IMDB_ERR_VERIFY, "stream: commit %llu: a row does not match its signed commitment",
                           (unsigned long long)seq);
    }
    if (!rc && left)
        rc = imdb_fail(e, IMDB_ERR_CORRUPT, "stream: commit %llu: trailing payload bytes", (unsigned long long)seq);

    /* 6. the stored frame must be self-consistent for the torn-tail scanner */
    if (!rc && k->crc32c(0, s->frame.p + IMDB_FRAME_HDR, body_len) != body_crc)
        rc = imdb_fail(e, IMDB_ERR_CORRUPT, "stream: commit %llu: frame checksum mismatch", (unsigned long long)seq);
    if (!rc) s->frames++;
    if (!rc && w) memcpy(s->writer_pk, w->new_pk, IMDB_PUBKEY_LEN); /* the next commit is signed by the new key */
out:
    imdb_commit_free(&c);
    return rc;
}
