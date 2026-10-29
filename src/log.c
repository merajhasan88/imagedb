#include "log.h"

#include <stdlib.h>

#include "cpu.h"

static const uint8_t kChainTag[8] = {'I', 'M', 'D', 'B', 'C', 'H', 'N', '2'};
static const uint8_t kSigTag[8] = {'I', 'M', 'D', 'B', 'S', 'I', 'G', '2'};
static const uint8_t kGenesisTag[8] = {'I', 'M', 'D', 'B', 'G', 'E', 'N', '1'};

/* op 14's definition by its own rules: known flags, 1..IMDB_MAX_INDEX_COLS distinct columns (that
 * each column exists is the table's to say, at replay) */
static bool index_cols_ok(uint8_t flags, uint8_t ncols, const uint16_t *cols)
{
    if ((flags & ~IMDB_INDEX_UNIQUE) || !ncols || ncols > IMDB_MAX_INDEX_COLS) return false;
    for (uint8_t i = 0; i < ncols; i++)
        for (uint8_t j = 0; j < i; j++)
            if (cols[i] == cols[j]) return false;
    return true;
}

void imdb_genesis_hash(const uint8_t db_id[16], uint8_t out[32])
{
    imdb_sha256_ctx c;
    imdb_sha256_init(&c);
    imdb_sha256_update(&c, kGenesisTag, 8);
    imdb_sha256_update(&c, db_id, 16);
    imdb_sha256_final(&c, out);
}

void imdb_commit_free(imdb_commit_rec *c)
{
    if (c->ops) {
        for (uint32_t i = 0; i < c->nops; i++) {
            imdb_free(c->ops[i].schema);
            imdb_free(c->ops[i].erase);
            imdb_free(c->ops[i].rewrites);
            imdb_free(c->ops[i].iname);
        }
        imdb_free(c->ops);
    }
    memset(c, 0, sizeof *c);
}

/* ---- encoding ------------------------------------------------------------ */

void imdb_commit_encode_header(const imdb_commit_rec *c, imdb_buf *b)
{
    imdb_buf_put_u8(b, IMDB_LOG_VERSION);
    imdb_buf_put_u8(b, c->alg); /* the database's (META); 0, never decodable, if a caller forgot it */
    imdb_buf_put_u64(b, c->seq);
    imdb_buf_put_u64(b, c->time_us);
    imdb_buf_put(b, c->prev, 32);
    imdb_buf_put_u32(b, c->nops);
    for (uint32_t i = 0; i < c->nops; i++) {
        const imdb_op *o = &c->ops[i];
        imdb_buf_put_u8(b, o->code);
        switch (o->code) {
        case IMDB_OP_CREATE_TABLE:
            if (i + 1 == c->nops || c->ops[i + 1].code != IMDB_OP_SET_RETENTION || c->ops[i + 1].table != o->table) {
                b->err = IMDB_ERR_INVALID; /* the decoder refuses it (log.h): never signed */
                break;
            }
            imdb_buf_put_u32(b, o->table);
            imdb_schema_encode(o->schema, b);
            break;
        case IMDB_OP_INSERT:
        case IMDB_OP_DELETE:
            imdb_buf_put_u32(b, o->table);
            imdb_buf_put_u64(b, o->vid);
            imdb_buf_put(b, o->commit, 32);
            break;
        case IMDB_OP_UPDATE:
            imdb_buf_put_u32(b, o->table);
            imdb_buf_put_u64(b, o->vid);
            imdb_buf_put(b, o->commit, 32);
            imdb_buf_put_u64(b, o->new_vid);
            imdb_buf_put(b, o->new_commit, 32);
            break;
        case IMDB_OP_CHECKPOINT:
            imdb_buf_put(b, o->manifest, 32);
            break;
        case IMDB_OP_COMPACT:
            imdb_buf_put_u32(b, o->table);
            imdb_buf_put_u64(b, o->purge_before);
            imdb_buf_put(b, o->manifest, 32);
            break;
        case IMDB_OP_RETIRE: /* alone; the commit after the boundary comes before it (log.h) */
            if (c->nops != 1 || !o->purge_before || c->seq < 2 || o->purge_before > c->seq - 2) {
                b->err = IMDB_ERR_INVALID;
                break;
            }
            imdb_buf_put_u64(b, o->purge_before);
            imdb_buf_put(b, o->manifest, 32);
            break;
        case IMDB_OP_ERASE:
            imdb_buf_put_u32(b, o->n_erase);
            for (uint32_t k = 0; k < o->n_erase; k++) {
                imdb_buf_put_u32(b, o->erase[k].table);
                imdb_buf_put_u64(b, o->erase[k].vid);
                imdb_buf_put(b, o->erase[k].commit, 32);
            }
            imdb_buf_put_u32(b, o->n_rewrites);
            for (uint32_t k = 0; k < o->n_rewrites; k++) {
                imdb_buf_put_u32(b, o->rewrites[k].table);
                imdb_buf_put(b, o->rewrites[k].old_hash, 32);
                imdb_buf_put(b, o->rewrites[k].new_hash, 32);
            }
            imdb_buf_put(b, o->manifest, 32);
            break;
        case IMDB_OP_CREATE_INDEX:
        case IMDB_OP_DROP_INDEX: {
            size_t nl = o->iname ? strlen(o->iname) : 0;
            if (c->nops != 1 || !nl || nl > IMDB_MAX_IDENT) {
                b->err = IMDB_ERR_INVALID;
                break;
            }
            imdb_buf_put_u32(b, o->table);
            if (o->code == IMDB_OP_CREATE_INDEX) {
                if (!index_cols_ok(o->iflags, o->incols, o->icols)) {
                    b->err = IMDB_ERR_INVALID;
                    break;
                }
                imdb_buf_put_u8(b, o->iflags);
                imdb_buf_put_u8(b, o->incols);
                for (uint8_t k = 0; k < o->incols; k++) imdb_buf_put_u16(b, o->icols[k]);
            }
            imdb_buf_put_u8(b, (uint8_t)nl);
            imdb_buf_put(b, o->iname, nl);
            break;
        }
        case IMDB_OP_WRITER_KEY:
            imdb_buf_put_u32(b, o->epoch);
            imdb_buf_put(b, o->new_pk, IMDB_PUBKEY_LEN);
            imdb_buf_put_u8(b, o->how);
            break;
        case IMDB_OP_SET_RETENTION:
            if (!imdb_retention_ok(o->retention_us)) {
                b->err = IMDB_ERR_INVALID;
                break;
            }
            imdb_buf_put_u32(b, o->table);
            imdb_buf_put_u64(b, o->retention_us);
            break;
        case IMDB_OP_EXPIRE: /* only EXPIREs in its commit, by table, each before its commit (log.h) */
            if (!o->purge_before || o->purge_before >= c->seq ||
                (i && (c->ops[i - 1].code != IMDB_OP_EXPIRE || c->ops[i - 1].table >= o->table)) ||
                (i + 1 < c->nops && c->ops[i + 1].code != IMDB_OP_EXPIRE)) {
                b->err = IMDB_ERR_INVALID;
                break;
            }
            imdb_buf_put_u32(b, o->table);
            imdb_buf_put_u64(b, o->purge_before);
            break;
        default:
            b->err = IMDB_ERR_INVALID;
            break;
        }
    }
    imdb_buf_put(b, c->digest, 32);
}

void imdb_commit_hash(const uint8_t *header, size_t len, uint8_t out[32])
{
    imdb_sha256_ctx c;
    imdb_sha256_init(&c);
    imdb_sha256_update(&c, kChainTag, 8);
    imdb_sha256_update(&c, header, len);
    imdb_sha256_final(&c, out);
}

void imdb_commit_sigmsg(uint64_t seq, uint32_t hlen, const uint8_t hash[32], uint8_t out[IMDB_SIGMSG_LEN])
{
    memcpy(out, kSigTag, 8);
    imdb_le64(out + 8, seq);
    imdb_le32(out + 16, hlen);
    memcpy(out + 20, hash, 32);
}

bool imdb_commit_sig_valid(const uint8_t writer_pk[IMDB_PUBKEY_LEN], uint64_t seq, uint32_t hlen,
                           const uint8_t hash[32], const uint8_t sig[IMDB_SIG_LEN])
{
    uint8_t m[IMDB_SIGMSG_LEN];
    imdb_commit_sigmsg(seq, hlen, hash, m);
    return imdb_sig_verify(writer_pk, m, sizeof m, sig);
}

void imdb_promote_msg(const uint8_t db_id[16], uint32_t epoch, uint64_t seq, const uint8_t prev[32],
                      const uint8_t new_pk[IMDB_PUBKEY_LEN], uint8_t out[IMDB_PROMOTE_MSG_LEN])
{
    memcpy(out, "IMDBPRO1", 8);
    memcpy(out + 8, db_id, 16);
    imdb_le32(out + 24, epoch);
    imdb_le64(out + 28, seq);
    memcpy(out + 36, prev, 32);
    memcpy(out + 68, new_pk, IMDB_PUBKEY_LEN);
}

const imdb_op *imdb_commit_writer_op(const imdb_commit_rec *c)
{
    return c->nops == 1 && c->ops[0].code == IMDB_OP_WRITER_KEY ? &c->ops[0] : NULL;
}

const uint8_t *imdb_commit_signer(const imdb_commit_rec *c, const uint8_t current[IMDB_PUBKEY_LEN])
{
    return c->promote ? c->ops[0].new_pk : current;
}

static bool root_cert_valid(const imdb_commit_rec *c, const uint8_t db_id[16], const uint8_t *root)
{
    if (!root) return false;
    uint8_t m[IMDB_PROMOTE_MSG_LEN];
    imdb_promote_msg(db_id, c->ops[0].epoch, c->seq, c->prev, c->ops[0].new_pk, m);
    return imdb_sig_verify(root, m, sizeof m, c->root_sig);
}

bool imdb_commit_authentic(const imdb_commit_rec *c, const uint8_t current[IMDB_PUBKEY_LEN], const uint8_t db_id[16],
                           const uint8_t *root)
{
    if (c->promote && !root_cert_valid(c, db_id, root)) return false;
    return imdb_commit_sig_valid(imdb_commit_signer(c, current), c->seq, c->hlen, c->hash, c->sig);
}

void imdb_commit_sigs_check(uint8_t current[IMDB_PUBKEY_LEN], const uint8_t db_id[16], const uint8_t *root,
                            imdb_commit_rec *const recs[], size_t n)
{
    enum { G = 64 };
    uint8_t msg[G][IMDB_SIGMSG_LEN];
    const uint8_t *mp[G], *sp[G];
    size_t lens[G];
    bool ok[G];
    for (size_t at = 0; at < n;) {
        /* a run of commits under one key: up to a WRITER_KEY commit (which itself is signed by the
         * key before it, a promotion excepted: that one is checked alone, with its certificate) */
        if (recs[at]->promote) {
            imdb_commit_rec *c = recs[at++];
            c->sig_ok = imdb_commit_authentic(c, current, db_id, root);
            memcpy(current, c->ops[0].new_pk, IMDB_PUBKEY_LEN);
            continue;
        }
        size_t k = 0;
        while (k < G && at + k < n && !recs[at + k]->promote) {
            const imdb_commit_rec *c = recs[at + k];
            imdb_commit_sigmsg(c->seq, c->hlen, c->hash, msg[k]);
            mp[k] = msg[k];
            sp[k] = c->sig;
            lens[k] = IMDB_SIGMSG_LEN;
            k++;
            if (imdb_commit_writer_op(c)) break; /* the next commit is signed by its new key */
        }
        imdb_sig_verify_batch(current, k, mp, lens, sp, ok);
        for (size_t i = 0; i < k; i++) recs[at + i]->sig_ok = ok[i];
        const imdb_op *w = imdb_commit_writer_op(recs[at + k - 1]);
        if (w) memcpy(current, w->new_pk, IMDB_PUBKEY_LEN);
        at += k;
    }
}

void imdb_commit_encode_payload(const imdb_commit_rec *c, imdb_buf *b)
{
    for (uint32_t i = 0; i < c->nops; i++) {
        const imdb_op *o = &c->ops[i];
        if (o->code != IMDB_OP_INSERT && o->code != IMDB_OP_UPDATE) continue;
        imdb_buf_put_u8(b, o->pkind);
        if (o->pkind == IMDB_PAYLOAD_ROW) {
            imdb_buf_put(b, o->salt, 16);
            imdb_buf_put_u32(b, o->row_len);
            imdb_buf_put(b, o->row, o->row_len);
        }
    }
}

void imdb_frame_build(const uint8_t *header, size_t hlen, uint64_t seq, const uint8_t hash[32],
                      const uint8_t sig[IMDB_SIG_LEN], const uint8_t *payload, size_t plen, imdb_buf *out)
{
    imdb_frame_build_ext(header, hlen, seq, hash, sig, NULL, payload, plen, out);
}

void imdb_frame_build_ext(const uint8_t *header, size_t hlen, uint64_t seq, const uint8_t hash[32],
                          const uint8_t sig[IMDB_SIG_LEN], const uint8_t ext[IMDB_BODY_EXT], const uint8_t *payload,
                          size_t plen, imdb_buf *out)
{
    size_t desc = IMDB_BODY_DESC + (ext ? IMDB_BODY_EXT : 0);
    if (hlen > IMDB_MAX_HEADER || plen > IMDB_MAX_FRAME || desc + hlen + 4 + plen > IMDB_MAX_FRAME) {
        out->err = IMDB_ERR_LIMIT;
        return;
    }
    size_t body = desc + hlen + 4 + plen;
    size_t start = out->len;
    imdb_buf_put_zeros(out, IMDB_FRAME_HDR);
    imdb_buf_put_u8(out, ext ? IMDB_BODY_KIND_PROMOTE : IMDB_BODY_KIND);
    imdb_buf_put_u32(out, (uint32_t)hlen);
    imdb_buf_put_u64(out, seq);
    imdb_buf_put(out, hash, 32);
    imdb_buf_put(out, sig, IMDB_SIG_LEN);
    if (ext) imdb_buf_put(out, ext, IMDB_BODY_EXT);
    imdb_buf_put(out, header, hlen);
    imdb_buf_put_u32(out, (uint32_t)plen);
    imdb_buf_put(out, payload, plen);
    if (out->err) return;
    uint8_t *f = out->p + start;
    const imdb_kernels *k = imdb_kern();
    imdb_le32(f, IMDB_FRAME_MAGIC);
    imdb_le32(f + 4, (uint32_t)body);
    imdb_le32(f + 8, k->crc32c(0, f + IMDB_FRAME_HDR, body));
    imdb_le32(f + 12, k->crc32c(0, f, 12));
}

/* ---- decoding ------------------------------------------------------------ */

#define OP_MIN_BYTES 13u /* smallest encoded op among many (SET_RETENTION; a DROP_INDEX's 7 come alone); bounds
                          * n_ops by input size */

static int cmp_erase(const imdb_erase_ent *a, const imdb_erase_ent *b)
{
    if (a->table != b->table) return a->table < b->table ? -1 : 1;
    if (a->vid != b->vid) return a->vid < b->vid ? -1 : 1;
    return 0;
}

static int cmp_rewrite(const imdb_rewrite *a, const imdb_rewrite *b)
{
    if (a->table != b->table) return a->table < b->table ? -1 : 1;
    return memcmp(a->old_hash, b->old_hash, 32);
}

int imdb_commit_decode_header(const uint8_t *h, size_t hlen, imdb_commit_rec *c, imdb_err *e)
{
    memset(c, 0, sizeof *c);
    imdb_rd r;
    imdb_rd_init(&r, h, hlen);
    uint8_t ver = imdb_rd_u8(&r), alg = imdb_rd_u8(&r);
    if (ver != IMDB_LOG_VERSION) return imdb_fail(e, IMDB_ERR_CORRUPT, "commit: unsupported log version %u", ver);
    /* either algorithm decodes; which one a database's commits must name is its META's, which the
     * engine (imdb_apply_commit, VERIFY, the snapshot open) and the auditor compare */
    if (alg != IMDB_DIGEST_ALG_LTHASH16 && alg != IMDB_DIGEST_ALG_LTHASH16_TREE)
        return imdb_fail(e, IMDB_ERR_CORRUPT, "commit: unknown digest algorithm %u", alg);
    c->alg = alg;
    c->seq = imdb_rd_u64(&r);
    c->time_us = imdb_rd_u64(&r);
    imdb_rd_copy(&r, c->prev, 32);
    uint32_t nops = imdb_rd_u32(&r);
    if (r.err) return imdb_fail(e, IMDB_ERR_CORRUPT, "commit: truncated header");
    if (nops > IMDB_MAX_OPS_PER_COMMIT || nops > imdb_rd_left(&r) / OP_MIN_BYTES)
        return imdb_fail(e, IMDB_ERR_CORRUPT, "commit: op count %u out of range", nops);
    c->ops = imdb_alloc_array(nops ? nops : 1, sizeof *c->ops, e);
    if (!c->ops) return e->code;
    c->nops = nops;
    for (uint32_t i = 0; i < nops; i++) {
        imdb_op *o = &c->ops[i];
        o->code = imdb_rd_u8(&r);
        switch (o->code) {
        case IMDB_OP_CREATE_TABLE:
            o->table = imdb_rd_u32(&r);
            o->schema = imdb_alloc(sizeof *o->schema, e);
            if (!o->schema) return e->code;
            if (imdb_schema_decode(&r, o->schema, e)) return e->code;
            if (o->schema->id != o->table) return imdb_fail(e, IMDB_ERR_CORRUPT, "commit: schema id mismatch");
            break;
        case IMDB_OP_INSERT:
        case IMDB_OP_DELETE:
            o->table = imdb_rd_u32(&r);
            o->vid = imdb_rd_u64(&r);
            imdb_rd_copy(&r, o->commit, 32);
            break;
        case IMDB_OP_UPDATE:
            o->table = imdb_rd_u32(&r);
            o->vid = imdb_rd_u64(&r);
            imdb_rd_copy(&r, o->commit, 32);
            o->new_vid = imdb_rd_u64(&r);
            imdb_rd_copy(&r, o->new_commit, 32);
            break;
        case IMDB_OP_CHECKPOINT:
            imdb_rd_copy(&r, o->manifest, 32);
            break;
        case IMDB_OP_COMPACT:
            o->table = imdb_rd_u32(&r);
            o->purge_before = imdb_rd_u64(&r);
            imdb_rd_copy(&r, o->manifest, 32);
            break;
        case IMDB_OP_RETIRE:
            o->purge_before = imdb_rd_u64(&r);
            imdb_rd_copy(&r, o->manifest, 32);
            if (!r.err && (nops != 1 || !o->purge_before || c->seq < 2 || o->purge_before > c->seq - 2))
                return imdb_fail(e, IMDB_ERR_CORRUPT, "commit: RETIRE must be the only op, the commit after its boundary before it");
            break;
        case IMDB_OP_ERASE: {
            uint32_t n = imdb_rd_u32(&r);
            if (r.err || n == 0 || n > IMDB_MAX_ERASE_ENTRIES || n > imdb_rd_left(&r) / 44)
                return imdb_fail(e, IMDB_ERR_CORRUPT, "commit: erase count out of range");
            o->erase = imdb_alloc_array(n ? n : 1, sizeof *o->erase, e);
            if (!o->erase) return e->code;
            o->n_erase = n;
            for (uint32_t k = 0; k < n; k++) {
                o->erase[k].table = imdb_rd_u32(&r);
                o->erase[k].vid = imdb_rd_u64(&r);
                imdb_rd_copy(&r, o->erase[k].commit, 32);
                if (k && cmp_erase(&o->erase[k - 1], &o->erase[k]) >= 0)
                    return imdb_fail(e, IMDB_ERR_CORRUPT, "commit: erase entries not strictly sorted");
            }
            uint32_t m = imdb_rd_u32(&r);
            if (r.err || m > IMDB_MAX_SEGMENTS * 4u || m > imdb_rd_left(&r) / 68)
                return imdb_fail(e, IMDB_ERR_CORRUPT, "commit: rewrite count out of range");
            o->rewrites = imdb_alloc_array(m ? m : 1, sizeof *o->rewrites, e);
            if (!o->rewrites) return e->code;
            o->n_rewrites = m;
            for (uint32_t k = 0; k < m; k++) {
                o->rewrites[k].table = imdb_rd_u32(&r);
                imdb_rd_copy(&r, o->rewrites[k].old_hash, 32);
                imdb_rd_copy(&r, o->rewrites[k].new_hash, 32);
                if (k && cmp_rewrite(&o->rewrites[k - 1], &o->rewrites[k]) >= 0)
                    return imdb_fail(e, IMDB_ERR_CORRUPT, "commit: rewrites not strictly sorted");
            }
            imdb_rd_copy(&r, o->manifest, 32);
            break;
        }
        case IMDB_OP_CREATE_INDEX:
        case IMDB_OP_DROP_INDEX: {
            o->table = imdb_rd_u32(&r);
            if (o->code == IMDB_OP_CREATE_INDEX) {
                o->iflags = imdb_rd_u8(&r);
                o->incols = imdb_rd_u8(&r);
                for (uint8_t k = 0; k < o->incols && k < IMDB_MAX_INDEX_COLS; k++) o->icols[k] = imdb_rd_u16(&r);
                if (!r.err && !index_cols_ok(o->iflags, o->incols, o->icols))
                    return imdb_fail(e, IMDB_ERR_CORRUPT, "commit: bad index definition");
            }
            o->iname = imdb_alloc(IMDB_MAX_IDENT + 1, e);
            if (!o->iname) return e->code;
            imdb_err e2 = {0};
            if (!r.err && imdb_rd_ident(&r, o->iname, &e2)) return imdb_fail(e, IMDB_ERR_CORRUPT, "commit: bad index name");
            if (!r.err && nops != 1) return imdb_fail(e, IMDB_ERR_CORRUPT, "commit: an index op must be the only op");
            break;
        }
        case IMDB_OP_WRITER_KEY:
            o->epoch = imdb_rd_u32(&r);
            imdb_rd_copy(&r, o->new_pk, IMDB_PUBKEY_LEN);
            o->how = imdb_rd_u8(&r);
            if (!r.err && (nops != 1 || o->epoch == 0 || (o->how != IMDB_WRITER_ROTATE && o->how != IMDB_WRITER_PROMOTE)))
                return imdb_fail(e, IMDB_ERR_CORRUPT, "commit: WRITER_KEY must be the only op, with epoch >= 1 and how 1 or 2");
            break;
        case IMDB_OP_SET_RETENTION:
            o->table = imdb_rd_u32(&r);
            o->retention_us = imdb_rd_u64(&r);
            if (!r.err && !imdb_retention_ok(o->retention_us))
                return imdb_fail(e, IMDB_ERR_CORRUPT, "commit: retention out of range");
            break;
        case IMDB_OP_EXPIRE:
            o->table = imdb_rd_u32(&r);
            o->purge_before = imdb_rd_u64(&r);
            if (!r.err && (!o->purge_before || o->purge_before >= c->seq))
                return imdb_fail(e, IMDB_ERR_CORRUPT, "commit: EXPIRE's horizon is not in the past");
            break;
        default:
            return imdb_fail(e, IMDB_ERR_CORRUPT, "commit: unknown op code %u", o->code);
        }
        if (r.err) return imdb_fail(e, IMDB_ERR_CORRUPT, "commit: truncated op");
    }
    /* a commit with an EXPIRE holds only EXPIREs, one a table at most, by table (log.h) */
    for (uint32_t i = 0; i < nops; i++) {
        bool ex = c->ops[i].code == IMDB_OP_EXPIRE, ex0 = c->ops[0].code == IMDB_OP_EXPIRE;
        if (ex != ex0 || (ex && i && c->ops[i - 1].table >= c->ops[i].table))
            return imdb_fail(e, IMDB_ERR_CORRUPT, "commit: EXPIREs must stand alone, one a table, by table");
    }
    /* a table's retention is always logged: its CREATE_TABLE is followed at once by its SET_RETENTION (log.h) */
    for (uint32_t i = 0; i < nops; i++)
        if (c->ops[i].code == IMDB_OP_CREATE_TABLE &&
            (i + 1 == nops || c->ops[i + 1].code != IMDB_OP_SET_RETENTION || c->ops[i + 1].table != c->ops[i].table))
            return imdb_fail(e, IMDB_ERR_CORRUPT, "commit: CREATE_TABLE without its SET_RETENTION");
    imdb_rd_copy(&r, c->digest, 32);
    if (r.err) return imdb_fail(e, IMDB_ERR_CORRUPT, "commit: truncated digest");
    if (imdb_rd_left(&r)) return imdb_fail(e, IMDB_ERR_CORRUPT, "commit: trailing header bytes");
    imdb_commit_hash(h, hlen, c->hash);
    return IMDB_OK;
}

static int decode_payload(const uint8_t *p, size_t plen, imdb_commit_rec *c, imdb_err *e)
{
    imdb_rd r;
    imdb_rd_init(&r, p, plen);
    for (uint32_t i = 0; i < c->nops; i++) {
        imdb_op *o = &c->ops[i];
        if (o->code != IMDB_OP_INSERT && o->code != IMDB_OP_UPDATE) continue;
        o->pkind = imdb_rd_u8(&r);
        if (r.err) return imdb_fail(e, IMDB_ERR_CORRUPT, "commit: payload truncated");
        if (o->pkind == IMDB_PAYLOAD_REDACTED) continue;
        if (o->pkind != IMDB_PAYLOAD_ROW) return imdb_fail(e, IMDB_ERR_CORRUPT, "commit: bad payload kind");
        imdb_rd_copy(&r, o->salt, 16);
        o->row_len = imdb_rd_u32(&r);
        if (r.err || o->row_len > IMDB_MAX_ROW) return imdb_fail(e, IMDB_ERR_CORRUPT, "commit: bad row length");
        o->row = imdb_rd_bytes(&r, o->row_len);
        if (!o->row) return imdb_fail(e, IMDB_ERR_CORRUPT, "commit: row truncated");
    }
    if (imdb_rd_left(&r)) return imdb_fail(e, IMDB_ERR_CORRUPT, "commit: trailing payload bytes");
    return IMDB_OK;
}

int imdb_frame_decode_body(const uint8_t *body, size_t len, imdb_commit_rec *c, imdb_err *e)
{
    memset(c, 0, sizeof *c);
    imdb_rd r;
    imdb_rd_init(&r, body, len);
    uint8_t kind = imdb_rd_u8(&r);
    if (kind != IMDB_BODY_KIND && kind != IMDB_BODY_KIND_PROMOTE)
        return imdb_fail(e, IMDB_ERR_CORRUPT, "frame: unknown body kind");
    uint32_t hlen = imdb_rd_u32(&r);
    uint64_t seq = imdb_rd_u64(&r);
    uint8_t hash[32], sig[IMDB_SIG_LEN], ext_pk[IMDB_PUBKEY_LEN], root_sig[IMDB_SIG_LEN];
    imdb_rd_copy(&r, hash, 32);
    imdb_rd_copy(&r, sig, IMDB_SIG_LEN);
    uint32_t ext_epoch = 0;
    if (kind == IMDB_BODY_KIND_PROMOTE) {
        ext_epoch = imdb_rd_u32(&r);
        imdb_rd_copy(&r, ext_pk, IMDB_PUBKEY_LEN);
        imdb_rd_copy(&r, root_sig, IMDB_SIG_LEN);
    }
    if (r.err || hlen < IMDB_HEADER_MIN || hlen > IMDB_MAX_HEADER)
        return imdb_fail(e, IMDB_ERR_CORRUPT, "frame: bad descriptor");
    const uint8_t *h = imdb_rd_bytes(&r, hlen);
    if (!h) return imdb_fail(e, IMDB_ERR_CORRUPT, "frame: header truncated");
    uint32_t plen = imdb_rd_u32(&r);
    const uint8_t *p = imdb_rd_bytes(&r, plen);
    if (!p) return imdb_fail(e, IMDB_ERR_CORRUPT, "frame: payload truncated");
    if (imdb_rd_left(&r)) return imdb_fail(e, IMDB_ERR_CORRUPT, "frame: trailing body bytes");
    int rc = imdb_commit_decode_header(h, hlen, c, e);
    if (!rc && (c->seq != seq || memcmp(c->hash, hash, 32) != 0))
        rc = imdb_fail(e, IMDB_ERR_CORRUPT, "frame: descriptor does not match its header");
    if (!rc) { /* a promotion, and only a promotion, comes in a kind-3 body, which repeats its op */
        const imdb_op *w = imdb_commit_writer_op(c);
        bool promotes = w && w->how == IMDB_WRITER_PROMOTE;
        if (promotes != (kind == IMDB_BODY_KIND_PROMOTE) ||
            (promotes && (w->epoch != ext_epoch || memcmp(w->new_pk, ext_pk, IMDB_PUBKEY_LEN) != 0)))
            rc = imdb_fail(e, IMDB_ERR_CORRUPT, "frame: a promotion must come in a body of kind 3 that repeats its op");
        c->promote = promotes;
        if (promotes) memcpy(c->root_sig, root_sig, IMDB_SIG_LEN);
    }
    if (!rc) {
        c->hlen = hlen;
        memcpy(c->sig, sig, IMDB_SIG_LEN);
        rc = decode_payload(p, plen, c, e);
    }
    if (rc) imdb_commit_free(c);
    return rc;
}

static bool all_zero(const uint8_t *p, size_t n)
{
    for (size_t i = 0; i < n; i++)
        if (p[i]) return false;
    return true;
}

imdb_scan_status imdb_frame_scan(const uint8_t *buf, size_t len, size_t off, size_t *frame_len, imdb_err *e)
{
    if (off >= len) return IMDB_SCAN_END;
    size_t left = len - off;
    const uint8_t *f = buf + off;
    if (left < IMDB_FRAME_HDR) {
        imdb_fail(e, IMDB_ERR_CORRUPT, "torn tail: %zu-byte partial frame header at offset %zu", left, off);
        return IMDB_SCAN_TORN;
    }
    const imdb_kernels *k = imdb_kern();
    uint32_t magic = imdb_get_le32(f), blen = imdb_get_le32(f + 4);
    uint32_t bcrc = imdb_get_le32(f + 8), hcrc = imdb_get_le32(f + 12);
    if (magic != IMDB_FRAME_MAGIC || k->crc32c(0, f, 12) != hcrc) {
        if (all_zero(f, left)) {
            imdb_fail(e, IMDB_ERR_CORRUPT, "torn tail: zero-filled region at offset %zu", off);
            return IMDB_SCAN_TORN;
        }
        imdb_fail(e, IMDB_ERR_CORRUPT, "log corrupt: bad frame header at offset %zu followed by data", off);
        return IMDB_SCAN_CORRUPT;
    }
    if (blen > IMDB_MAX_FRAME) {
        imdb_fail(e, IMDB_ERR_CORRUPT, "log corrupt: frame length %u exceeds limit at offset %zu", blen, off);
        return IMDB_SCAN_CORRUPT;
    }
    if (blen > left - IMDB_FRAME_HDR) {
        imdb_fail(e, IMDB_ERR_CORRUPT, "torn tail: frame at offset %zu extends past end of log", off);
        return IMDB_SCAN_TORN;
    }
    if (k->crc32c(0, f + IMDB_FRAME_HDR, blen) != bcrc) {
        size_t after = IMDB_FRAME_HDR + (size_t)blen;
        if (all_zero(f + after, left - after)) {
            /* At the end it may be an append that never finished, or damage to an
             * acknowledged commit; only the durable watermark can tell them apart */
            imdb_fail(e, IMDB_ERR_CORRUPT, "complete final frame at offset %zu fails its checksum", off);
            return IMDB_SCAN_DAMAGED;
        }
        imdb_fail(e, IMDB_ERR_CORRUPT, "log corrupt: frame at offset %zu fails its checksum and data follows", off);
        return IMDB_SCAN_CORRUPT;
    }
    *frame_len = IMDB_FRAME_HDR + (size_t)blen;
    return IMDB_SCAN_FRAME;
}

/* ---- tagged segments (design.md §3, "Tagged, preallocated segments") ----------------- */

void imdb_tseg_header(uint64_t first, uint8_t out[IMDB_TSEG_SECTOR])
{
    memset(out, 0, IMDB_TSEG_SECTOR);
    memcpy(out, "ILT1", 4);
    imdb_le32(out + 4, IMDB_TSEG_VERSION);
    imdb_le64(out + 8, first);
    imdb_le32(out + 16, imdb_kern()->crc32c(0, out, 16));
}

bool imdb_tseg_is_tagged(const uint8_t *b, size_t n) { return n >= 4 && memcmp(b, "ILT1", 4) == 0; }

void imdb_tgroup_begin(imdb_tgroup *g, uint64_t tag, uint64_t sector)
{
    memset(g, 0, sizeof *g);
    g->tag = tag;
    g->sector = sector;
}

uint64_t imdb_tgroup_at(const imdb_tgroup *g) { return g->sector + g->len / IMDB_TSEG_PAYLOAD; }

size_t imdb_tgroup_sectors(const imdb_tgroup *g, size_t n)
{
    size_t pre = (size_t)(g->len % IMDB_TSEG_PAYLOAD);
    return (pre + n + IMDB_TSEG_PAYLOAD - 1) / IMDB_TSEG_PAYLOAD;
}

void imdb_tgroup_fill(const imdb_tgroup *g, const uint8_t *frame, size_t n, size_t from, size_t count, uint8_t *dst)
{
    uint64_t s0 = imdb_tgroup_at(g);
    size_t pre = (size_t)(g->len % IMDB_TSEG_PAYLOAD);
    for (size_t i = from; i < from + count; i++, dst += IMDB_TSEG_SECTOR) {
        memset(dst, 0, IMDB_TSEG_SECTOR);
        imdb_le64(dst, s0 + i == g->sector ? g->tag | IMDB_TSEG_TOP : g->tag);
        /* the frame's bytes in this sector: [a, b) of the frame, at payload offset off */
        size_t off = i == 0 ? pre : 0, a = i == 0 ? 0 : i * IMDB_TSEG_PAYLOAD - pre;
        if (i == 0 && pre) memcpy(dst + 8, g->last + 8, pre);
        size_t k = n - a < IMDB_TSEG_PAYLOAD - off ? n - a : IMDB_TSEG_PAYLOAD - off;
        memcpy(dst + 8 + off, frame + a, k);
    }
}

void imdb_tgroup_advance(imdb_tgroup *g, const uint8_t *frame, size_t n)
{
    size_t ns = imdb_tgroup_sectors(g, n);
    if (ns && (g->len + n) % IMDB_TSEG_PAYLOAD) {
        uint8_t last[IMDB_TSEG_SECTOR];
        imdb_tgroup_fill(g, frame, n, ns - 1, 1, last);
        memcpy(g->last, last, sizeof last);
    }
    g->len += n;
}

void imdb_tgroup_put(imdb_tgroup *g, const uint8_t *frame, size_t n, imdb_buf *out)
{
    size_t ns = imdb_tgroup_sectors(g, n);
    out->len = 0;
    if (!imdb_buf_reserve(out, ns * IMDB_TSEG_SECTOR)) return;
    imdb_tgroup_fill(g, frame, n, 0, ns, out->p);
    out->len = ns * IMDB_TSEG_SECTOR;
    imdb_tgroup_advance(g, frame, n);
}

uint64_t imdb_tgroup_end(const imdb_tgroup *g) { return g->sector + (g->len + IMDB_TSEG_PAYLOAD - 1) / IMDB_TSEG_PAYLOAD; }

void imdb_tseg_build(uint64_t first, const uint8_t *frames, size_t len, imdb_buf *out)
{
    uint8_t h[IMDB_TSEG_SECTOR];
    imdb_tseg_header(first, h);
    imdb_tgroup g;
    imdb_tgroup_begin(&g, first, 1);
    size_t ns = imdb_tgroup_sectors(&g, len);
    out->len = 0;
    if (!imdb_buf_reserve(out, IMDB_TSEG_SECTOR + ns * IMDB_TSEG_SECTOR)) return;
    memcpy(out->p, h, sizeof h);
    imdb_tgroup_fill(&g, frames, len, 0, ns, out->p + IMDB_TSEG_SECTOR);
    out->len = IMDB_TSEG_SECTOR + ns * IMDB_TSEG_SECTOR;
}

/* The scan's reader: payload bytes of group tag from (sec, byte) on, copied (memmove: the copy lies
 * before what is read) to b + w. */
typedef struct tseg_rd {
    uint8_t *b;
    uint64_t nsec;
    uint64_t sec;
    size_t byte; /* 0..504; 504: the sector's payload is used up */
    uint64_t tag;
} tseg_rd;

enum { RD_OK, RD_TORN, RD_CORRUPT };

static const uint8_t *tsec(const tseg_rd *r, uint64_t s) { return r->b + s * IMDB_TSEG_SECTOR; }
static bool tsec_zero(const tseg_rd *r, uint64_t s) { return all_zero(tsec(r, s), IMDB_TSEG_SECTOR); }

/* n payload bytes to dst, crossing into the group's next sectors: RD_TORN on an all-zero sector or the
 * end of the file, RD_CORRUPT on a sector that carries another tag. */
static int rd_take(tseg_rd *r, uint8_t *dst, size_t n)
{
    while (n) {
        if (r->byte == IMDB_TSEG_PAYLOAD) {
            if (r->sec + 1 >= r->nsec || tsec_zero(r, r->sec + 1)) return RD_TORN;
            if (imdb_get_le64(tsec(r, r->sec + 1)) != r->tag) return RD_CORRUPT;
            r->sec++;
            r->byte = 0;
        }
        size_t k = n < IMDB_TSEG_PAYLOAD - r->byte ? n : IMDB_TSEG_PAYLOAD - r->byte;
        memmove(dst, tsec(r, r->sec) + 8 + r->byte, k);
        dst += k;
        r->byte += k;
        n -= k;
    }
    return RD_OK;
}

/* From sector s to the end: only zero sectors and sectors tagged t (without the top bit: the torn
 * group's own, landed out of order). *dirty: one past the last non-zero one. */
static bool after_torn(const tseg_rd *r, uint64_t s, uint64_t t, uint64_t *dirty)
{
    for (; s < r->nsec; s++) {
        if (tsec_zero(r, s)) continue;
        if (imdb_get_le64(tsec(r, s)) != t) return false;
        *dirty = s + 1;
    }
    return true;
}

/* The end's verdict once the kept frames are known: where the next group begins (past E). */
static imdb_scan_status tseg_stop(imdb_tseg_end *end, size_t w, size_t *len, imdb_scan_status st)
{
    end->next = end->keep_bytes ? end->keep_sector + 1 : end->keep_sector;
    *len = w;
    return st;
}

imdb_scan_status imdb_tseg_scan(uint8_t *b, size_t n, uint64_t first, size_t *len, imdb_tseg_end *end, imdb_err *e)
{
    memset(end, 0, sizeof *end);
    *len = 0;
    end->last = first - 1;
    end->keep_sector = end->next = end->dirty = 1;
    uint8_t h[IMDB_TSEG_SECTOR];
    imdb_tseg_header(first, h);
    if (n < IMDB_TSEG_SECTOR || n % IMDB_TSEG_SECTOR || memcmp(b, h, sizeof h) != 0) {
        imdb_fail(e, IMDB_ERR_CORRUPT, "log corrupt: tagged segment %llu: %s", (unsigned long long)first,
                  n % IMDB_TSEG_SECTOR ? "its size is not a multiple of 512" : "a malformed header");
        return IMDB_SCAN_CORRUPT;
    }
    const imdb_kernels *k = imdb_kern();
    tseg_rd r = {.b = b, .nsec = n / IMDB_TSEG_SECTOR};
    uint64_t next = first, prev = 0, s = 1; /* prev: the tag of the group that ended, 0 before any */
    size_t w = 0;                            /* where the next kept frame goes */
    for (;;) {
        /* between groups, at sector s */
        uint64_t t = s;
        while (t < r.nsec && tsec_zero(&r, t)) t++;
        if (t == r.nsec) { /* only the fill after the last group */
            end->dirty = s;
            return tseg_stop(end, w, len, IMDB_SCAN_END);
        }
        uint64_t tag = imdb_get_le64(tsec(&r, t)), torn = 0;
        if (t == s && next < IMDB_TSEG_TOP && tag == (next | IMDB_TSEG_TOP)) {
            r.sec = s;
            r.byte = 0;
            r.tag = next;
        } else if (prev && tag == prev) { /* a later part of the group that ended landed, an earlier did not */
            torn = prev;
        } else if (t > s && tag == next) { /* the next group's first sector never landed, a later one did */
            torn = next;
        } else {
            imdb_fail(e, IMDB_ERR_CORRUPT, "log corrupt: tagged segment %llu: sector %llu carries a tag no write "
                      "there could have", (unsigned long long)first, (unsigned long long)t);
            return tseg_stop(end, w, len, IMDB_SCAN_CORRUPT);
        }
        if (torn) {
            end->dirty = t + 1;
            if (!after_torn(&r, t + 1, torn, &end->dirty)) {
                imdb_fail(e, IMDB_ERR_CORRUPT, "log corrupt: tagged segment %llu: another write follows a torn one, "
                          "which was therefore flushed", (unsigned long long)first);
                return tseg_stop(end, w, len, IMDB_SCAN_CORRUPT);
            }
            imdb_fail(e, IMDB_ERR_CORRUPT, "torn tail: tagged segment %llu, after commit %llu", (unsigned long long)first,
                      (unsigned long long)(next - 1));
            return tseg_stop(end, w, len, IMDB_SCAN_TORN);
        }
        /* inside group r.tag: its frames, one after another */
        for (;;) {
            uint8_t pre[IMDB_FRAME_HDR];
            uint32_t blen = 0;
            int rd = rd_take(&r, pre, sizeof pre);
            if (rd == RD_OK) {
                blen = imdb_get_le32(pre + 4);
                if (imdb_get_le32(pre) != IMDB_FRAME_MAGIC || k->crc32c(0, pre, 12) != imdb_get_le32(pre + 12) ||
                    blen > IMDB_MAX_FRAME)
                    rd = RD_CORRUPT;
            }
            if (rd == RD_OK) {
                memcpy(b + w, pre, sizeof pre); /* b + w lies before what was just read */
                rd = rd_take(&r, b + w + sizeof pre, blen);
            }
            imdb_scan_status st = rd == RD_TORN ? IMDB_SCAN_TORN : rd == RD_CORRUPT ? IMDB_SCAN_CORRUPT : IMDB_SCAN_FRAME;
            if (st == IMDB_SCAN_FRAME && k->crc32c(0, b + w + sizeof pre, blen) != imdb_get_le32(pre + 8))
                st = IMDB_SCAN_DAMAGED;
            else if (st == IMDB_SCAN_FRAME && (blen < IMDB_BODY_DESC || imdb_frame_seq(b + w) != next))
                st = IMDB_SCAN_CORRUPT;
            if (st == IMDB_SCAN_FRAME) {
                w += sizeof pre + blen;
                end->frames++;
                end->last = next++;
                end->keep_sector = r.byte == IMDB_TSEG_PAYLOAD ? r.sec + 1 : r.sec;
                end->keep_bytes = r.byte == IMDB_TSEG_PAYLOAD ? 0 : (uint32_t)r.byte;
                /* what follows the frame: the group's next one, or its end */
                if (r.byte < IMDB_TSEG_PAYLOAD) {
                    if (!all_zero(tsec(&r, r.sec) + 8 + r.byte, IMDB_TSEG_PAYLOAD - r.byte)) continue;
                } else if (r.sec + 1 < r.nsec && !tsec_zero(&r, r.sec + 1) && imdb_get_le64(tsec(&r, r.sec + 1)) == r.tag) {
                    continue;
                }
                prev = r.tag;
                s = r.sec + 1;
                break;
            }
            if (st == IMDB_SCAN_DAMAGED) { /* every sector of it there: only zeros may follow */
                bool zeros = r.byte == IMDB_TSEG_PAYLOAD || all_zero(tsec(&r, r.sec) + 8 + r.byte, IMDB_TSEG_PAYLOAD - r.byte);
                for (uint64_t z = r.sec + 1; zeros && z < r.nsec; z++) zeros = tsec_zero(&r, z);
                if (zeros) {
                    end->dirty = r.sec + 1;
                    imdb_fail(e, IMDB_ERR_CORRUPT, "complete final frame in tagged segment %llu, commit %llu, fails its "
                              "checksum", (unsigned long long)first, (unsigned long long)next);
                    return tseg_stop(end, w, len, IMDB_SCAN_DAMAGED);
                }
                imdb_fail(e, IMDB_ERR_CORRUPT, "log corrupt: tagged segment %llu: the frame after commit %llu fails its "
                          "checksum and data follows", (unsigned long long)first, (unsigned long long)(next - 1));
                return tseg_stop(end, w, len, IMDB_SCAN_CORRUPT);
            }
            if (st == IMDB_SCAN_TORN) { /* it ran into a zero sector or the end: only the group's own may follow */
                end->dirty = r.sec + 1;
                if (!after_torn(&r, r.sec + 1, r.tag, &end->dirty)) {
                    imdb_fail(e, IMDB_ERR_CORRUPT, "log corrupt: tagged segment %llu: another write follows a torn one, "
                              "which was therefore flushed", (unsigned long long)first);
                    return tseg_stop(end, w, len, IMDB_SCAN_CORRUPT);
                }
                imdb_fail(e, IMDB_ERR_CORRUPT, "torn tail: tagged segment %llu, commit %llu incomplete",
                          (unsigned long long)first, (unsigned long long)next);
                return tseg_stop(end, w, len, IMDB_SCAN_TORN);
            }
            imdb_fail(e, IMDB_ERR_CORRUPT, "log corrupt: tagged segment %llu: a malformed frame or sector after commit %llu",
                      (unsigned long long)first, (unsigned long long)(next - 1));
            return tseg_stop(end, w, len, IMDB_SCAN_CORRUPT);
        }
    }
}

/* The live reader's sectors: b holds them from base on. */
typedef struct tseg_live {
    const uint8_t *b;
    uint64_t base, nsec;
} tseg_live;

static const uint8_t *live_sec(const tseg_live *l, uint64_t s)
{
    return s >= l->base && s - l->base < l->nsec ? l->b + (s - l->base) * IMDB_TSEG_SECTOR : NULL;
}

/* n payload bytes of group p->tag from p on, to dst: RD_OK, or RD_TORN when not there whole (*more:
 * past the sectors held). */
static int live_take(const tseg_live *l, imdb_tseg_pos *p, uint8_t *dst, size_t n, bool *more)
{
    while (n) {
        if (p->byte == IMDB_TSEG_PAYLOAD) {
            const uint8_t *q = live_sec(l, p->sector + 1);
            if (!q) {
                *more = true;
                return RD_TORN;
            }
            if (all_zero(q, IMDB_TSEG_SECTOR) || imdb_get_le64(q) != p->tag) return RD_TORN;
            p->sector++;
            p->byte = 0;
        }
        const uint8_t *q = live_sec(l, p->sector);
        if (!q) {
            *more = true;
            return RD_TORN;
        }
        size_t k = n < IMDB_TSEG_PAYLOAD - p->byte ? n : IMDB_TSEG_PAYLOAD - p->byte;
        memcpy(dst, q + 8 + p->byte, k);
        dst += k;
        p->byte += (uint32_t)k;
        n -= k;
    }
    return RD_OK;
}

imdb_scan_status imdb_tseg_next(const uint8_t *b, size_t n, uint64_t base, imdb_tseg_pos *pos, imdb_buf *out, bool *more)
{
    *more = false;
    tseg_live l = {.b = b, .base = base, .nsec = n / IMDB_TSEG_SECTOR};
    imdb_tseg_pos p = *pos;
    /* at a sector boundary (between groups, a frame that ended a sector, or only zeros after one):
     * the group goes on into the next sector, or the next group begins there, or nothing yet */
    for (int step = 0; step < 2; step++) {
        const uint8_t *cur = p.tag ? live_sec(&l, p.sector) : NULL;
        bool boundary = !p.tag || p.byte == IMDB_TSEG_PAYLOAD ||
                        (cur && all_zero(cur + 8 + p.byte, IMDB_TSEG_PAYLOAD - p.byte));
        if (p.tag && !cur) {
            *more = true;
            return IMDB_SCAN_END;
        }
        if (!boundary) break;
        uint64_t s = p.tag ? p.sector + 1 : p.sector;
        const uint8_t *q = live_sec(&l, s);
        if (!q) {
            *more = true;
            return IMDB_SCAN_END;
        }
        if (all_zero(q, IMDB_TSEG_SECTOR)) return IMDB_SCAN_END;
        uint64_t t = imdb_get_le64(q);
        if (p.tag && p.byte == IMDB_TSEG_PAYLOAD && t == p.tag) {
            p.sector = s;
            p.byte = 0;
        } else if (p.next < IMDB_TSEG_TOP && t == (p.next | IMDB_TSEG_TOP)) {
            p.sector = s;
            p.byte = 0;
            p.tag = p.next;
        } else {
            return IMDB_SCAN_END; /* not consistent yet (a write in progress), or damage: the watermark judges */
        }
    }
    uint8_t pre[IMDB_FRAME_HDR];
    if (live_take(&l, &p, pre, sizeof pre, more) != RD_OK) return IMDB_SCAN_END;
    const imdb_kernels *k = imdb_kern();
    uint32_t blen = imdb_get_le32(pre + 4);
    if (imdb_get_le32(pre) != IMDB_FRAME_MAGIC || k->crc32c(0, pre, 12) != imdb_get_le32(pre + 12) || blen > IMDB_MAX_FRAME ||
        blen < IMDB_BODY_DESC)
        return IMDB_SCAN_END;
    /* the frame's bytes must be in b before anything is allocated for them */
    uint64_t room = (l.base + l.nsec - p.sector - 1) * IMDB_TSEG_PAYLOAD + (IMDB_TSEG_PAYLOAD - p.byte);
    if (blen > room) {
        *more = true;
        return IMDB_SCAN_END;
    }
    out->len = 0;
    if (!imdb_buf_reserve(out, sizeof pre + blen)) return IMDB_SCAN_END;
    memcpy(out->p, pre, sizeof pre);
    if (live_take(&l, &p, out->p + sizeof pre, blen, more) != RD_OK) return IMDB_SCAN_END;
    if (k->crc32c(0, out->p + sizeof pre, blen) != imdb_get_le32(pre + 8) || imdb_frame_seq(out->p) != p.next)
        return IMDB_SCAN_END;
    out->len = sizeof pre + blen;
    p.next++;
    *pos = p;
    return IMDB_SCAN_FRAME;
}

void imdb_durable_encode(const imdb_durable *w, uint8_t out[IMDB_DURABLE_LEN])
{
    memset(out, 0, IMDB_DURABLE_LEN);
    memcpy(out, "IMDBDUR1", 8);
    imdb_le64(out + 8, w->seq);
    memcpy(out + 16, w->head, 32);
    imdb_le32(out + 48, (w->synced ? 1u : 0u) | (w->synced && w->strict ? 2u : 0u));
    imdb_le32(out + 56, imdb_kern()->crc32c(0, out, 56));
}

int imdb_durable_decode(const uint8_t *b, size_t n, imdb_durable *w, imdb_err *e)
{
    memset(w, 0, sizeof *w);
    if (n != IMDB_DURABLE_LEN || memcmp(b, "IMDBDUR1", 8) != 0 || imdb_kern()->crc32c(0, b, 56) != imdb_get_le32(b + 56))
        return imdb_fail(e, IMDB_ERR_CORRUPT, "DURABLE: malformed");
    uint32_t flags = imdb_get_le32(b + 48), zero = imdb_get_le32(b + 52);
    if ((flags != 0 && flags != 1 && flags != 3) || zero) return imdb_fail(e, IMDB_ERR_CORRUPT, "DURABLE: malformed");
    w->seq = imdb_get_le64(b + 8);
    memcpy(w->head, b + 16, 32);
    w->synced = flags & 1u;
    w->strict = flags == 3;
    return IMDB_OK;
}

int imdb_tail_check(const imdb_durable *w, bool have_w, uint64_t last, imdb_scan_status st, const char *what,
                    imdb_err *e)
{
    if (have_w && w->synced && w->seq > last)
        return imdb_fail(e, IMDB_ERR_CORRUPT,
                         "log damaged: commit %llu was acknowledged as durable, but the log ends with a damaged or "
                         "incomplete frame after commit %llu (%s); restore the segment from a replica, or discard the "
                         "acknowledged commits with imagedb recover",
                         (unsigned long long)w->seq, (unsigned long long)last, what);
    /* A complete frame failing its checksum is a torn append or later damage to it. Only a strict
     * watermark (fsynced before each commit returned) proves it was never acknowledged; any other may
     * lag after an OS crash, so nothing is dropped on its word (the user's contract, 2026-10-22). */
    if (st == IMDB_SCAN_DAMAGED && !have_w)
        return imdb_fail(e, IMDB_ERR_CORRUPT,
                         "log damaged: %s, and no DURABLE watermark says whether commit %llu was ever acknowledged; "
                         "imagedb recover can discard it, or restore the segment from a replica",
                         what, (unsigned long long)(last + 1));
    if (st == IMDB_SCAN_DAMAGED && !w->strict)
        return imdb_fail(e, IMDB_ERR_CORRUPT,
                         "log damaged: %s, and the watermark cannot show that commit %llu was never acknowledged (it "
                         "may lag: see --durable-ack); imagedb recover can discard it, or restore the segment from a "
                         "replica", what, (unsigned long long)(last + 1));
    return IMDB_OK;
}

void imdb_anchor_encode(const imdb_anchor *a, uint8_t out[IMDB_ANCHOR_LEN])
{
    memset(out, 0, IMDB_ANCHOR_LEN);
    memcpy(out, "IMDBANC1", 8);
    memcpy(out + 8, a->db_id, 16);
    imdb_le64(out + 24, a->seq);
    imdb_le32(out + 32, a->hlen);
    memcpy(out + 36, a->hash, 32);
    memcpy(out + 68, a->sig, IMDB_SIG_LEN);
    imdb_le32(out + 132, a->epoch);
    imdb_le32(out + 140, imdb_kern()->crc32c(0, out, 140));
}

int imdb_anchor_decode(const uint8_t *b, size_t n, imdb_anchor *a, imdb_err *e)
{
    memset(a, 0, sizeof *a);
    if (n != IMDB_ANCHOR_LEN || memcmp(b, "IMDBANC1", 8) != 0 || imdb_kern()->crc32c(0, b, 140) != imdb_get_le32(b + 140) ||
        imdb_get_le32(b + 136) != 0)
        return imdb_fail(e, IMDB_ERR_CORRUPT, "anchor: malformed");
    memcpy(a->db_id, b + 8, 16);
    a->seq = imdb_get_le64(b + 24);
    a->hlen = imdb_get_le32(b + 32);
    memcpy(a->hash, b + 36, 32);
    memcpy(a->sig, b + 68, IMDB_SIG_LEN);
    a->epoch = imdb_get_le32(b + 132);
    return IMDB_OK;
}

bool imdb_anchor_authentic(const imdb_anchor *a, const uint8_t writer_pk[IMDB_PUBKEY_LEN])
{
    if (a->seq == 0) {
        uint8_t g[32];
        imdb_genesis_hash(a->db_id, g);
        return memcmp(g, a->hash, 32) == 0;
    }
    return imdb_commit_sig_valid(writer_pk, a->seq, a->hlen, a->hash, a->sig);
}

bool imdb_anchor_pick(const uint8_t *b, size_t n, imdb_anchor_key_fn key_of, void *ctx, imdb_anchor *a, int *slot,
                      bool *bad, bool *ahead)
{
    bool found = false;
    *bad = *ahead = false;
    for (int k = 0; k < 2; k++) {
        size_t off = (size_t)k * IMDB_ANCHOR_SLOT;
        imdb_anchor r;
        imdb_err e = {0};
        if (n < off + IMDB_ANCHOR_LEN || imdb_anchor_decode(b + off, IMDB_ANCHOR_LEN, &r, &e)) continue; /* torn or absent */
        const uint8_t *pk = key_of(ctx, r.epoch);
        if (pk && !imdb_anchor_authentic(&r, pk)) {
            *bad = true; /* decodes but was not signed: tampering, not a torn write */
            continue;
        }
        /* Promotion can abandon a longer old-epoch tail. Authority advances
         * by epoch first; comparing sequence first could hide that promotion. */
        if (!found || r.epoch > a->epoch || (r.epoch == a->epoch && r.seq > a->seq)) {
            *a = r;
            *slot = k;
            *ahead = !pk; /* an epoch this history has not reached: a newer writer signed it */
            found = true;
        }
    }
    if (!found) *bad = true;
    return found && !*bad;
}
