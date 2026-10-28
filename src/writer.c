/* Writer epochs: the key schedule, the WRITERS file, rotation and promotion (see writer.h). */
#include "writer.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

#include "cpu.h"
#include "db_internal.h"
#include "fsio.h"
#include "repl.h"

static imdb_wep *wep_push(imdb_db *db, imdb_err *e)
{
    if (db->nwep >= IMDB_MAX_EPOCHS) {
        imdb_fail(e, IMDB_ERR_LIMIT, "more than %u writer epochs", IMDB_MAX_EPOCHS);
        return NULL;
    }
    if (db->nwep == db->capwep) {
        uint32_t nc = db->capwep ? 2 * db->capwep : 4;
        imdb_wep *n = imdb_realloc_array(db->wep, db->capwep, nc, sizeof *n, e);
        if (!n) return NULL;
        db->wep = n;
        db->capwep = nc;
    }
    imdb_wep *w = &db->wep[db->nwep++];
    memset(w, 0, sizeof *w);
    return w;
}

static void wep_drop_from(imdb_db *db, uint32_t from)
{
    for (uint32_t i = from; i < db->nwep; i++) imdb_free(db->wep[i].hdr);
    if (from < db->nwep) db->nwep = from;
    if (db->nwep) memcpy(db->writer_pk, db->wep[db->nwep - 1].k.pk, IMDB_PUBKEY_LEN);
}

void imdb_writers_reset(imdb_db *db) { wep_drop_from(db, 1); }

void imdb_writers_free(imdb_db *db)
{
    wep_drop_from(db, 0);
    imdb_free(db->wep);
    db->wep = NULL;
    db->nwep = db->capwep = 0;
}

void imdb_writers_cut(imdb_db *db, uint64_t seq)
{
    uint32_t keep = db->nwep;
    while (keep > 1 && db->wep[keep - 1].seq > seq) keep--;
    wep_drop_from(db, keep);
}

static uint32_t wep_index_at(const imdb_db *db, uint64_t seq)
{
    uint32_t i = db->nwep;
    while (i > 1 && db->wep[i - 1].k.first > seq) i--;
    return i - 1;
}

const uint8_t *imdb_writer_key_at(const imdb_db *db, uint64_t seq) { return db->wep[wep_index_at(db, seq)].k.pk; }
uint32_t imdb_writer_epoch_at(const imdb_db *db, uint64_t seq) { return db->wep[wep_index_at(db, seq)].k.epoch; }
uint32_t imdb_current_epoch(const imdb_db *db) { return db->wep[db->nwep - 1].k.epoch; }

/* A WRITER_KEY commit as the next epoch; its header is re-encoded from the record (the decoder
 * is canonical: the same bytes, which the hash confirms) for WRITERS. */
int imdb_writer_apply(imdb_db *db, const imdb_commit_rec *c, imdb_err *e)
{
    const imdb_op *w = imdb_commit_writer_op(c);
    uint32_t cur = imdb_current_epoch(db);
    if (!w) return imdb_fail(e, IMDB_ERR_CORRUPT, "commit %llu: not a WRITER_KEY commit", (unsigned long long)c->seq);
    if (w->epoch != cur + 1)
        return imdb_fail(e, IMDB_ERR_CORRUPT, "commit %llu: WRITER_KEY names epoch %u after epoch %u",
                         (unsigned long long)c->seq, w->epoch, cur);
    if (c->promote != (w->how == IMDB_WRITER_PROMOTE))
        return imdb_fail(e, IMDB_ERR_CORRUPT, "commit %llu: a promotion outside a kind-3 body", (unsigned long long)c->seq);
    if (c->promote && !db->meta.has_root)
        return imdb_fail(e, IMDB_ERR_AUTH, "commit %llu: a promotion, but this database has no root key",
                         (unsigned long long)c->seq);
    imdb_buf h;
    imdb_buf_init(&h);
    imdb_commit_encode_header(c, &h);
    if (imdb_buf_check(&h, e)) {
        imdb_buf_free(&h);
        return e->code;
    }
    uint8_t hh[32];
    imdb_commit_hash(h.p, h.len, hh);
    if (h.len != c->hlen || memcmp(hh, c->hash, 32) != 0) {
        imdb_buf_free(&h);
        return imdb_fail(e, IMDB_ERR_CORRUPT, "commit %llu: WRITER_KEY header does not re-encode to its hash",
                         (unsigned long long)c->seq);
    }
    imdb_wep *n = wep_push(db, e);
    if (!n) {
        imdb_buf_free(&h);
        return e->code;
    }
    n->k.epoch = w->epoch;
    n->k.first = w->how == IMDB_WRITER_ROTATE ? c->seq + 1 : c->seq;
    memcpy(n->k.pk, w->new_pk, IMDB_PUBKEY_LEN);
    n->seq = c->seq;
    n->promote = c->promote;
    n->hdr = h.p; /* owned */
    n->hlen = (uint32_t)h.len;
    memcpy(n->sig, c->sig, IMDB_SIG_LEN);
    memcpy(n->root_sig, c->root_sig, IMDB_SIG_LEN);
    memcpy(db->writer_pk, w->new_pk, IMDB_PUBKEY_LEN);
    return IMDB_OK;
}

/* ---- WRITERS ------------------------------------------------------------------------ */

static void writers_encode(const imdb_db *db, imdb_buf *b)
{
    imdb_buf_put(b, "IMDBWRS1", 8);
    imdb_buf_put(b, db->db_id, 16);
    imdb_buf_put_u32(b, db->nwep - 1);
    for (uint32_t i = 1; i < db->nwep; i++) {
        const imdb_wep *w = &db->wep[i];
        imdb_buf_put_u64(b, w->seq);
        imdb_buf_put_u8(b, w->promote);
        imdb_buf_put_u32(b, w->hlen);
        imdb_buf_put(b, w->hdr, w->hlen);
        imdb_buf_put(b, w->sig, IMDB_SIG_LEN);
        if (w->promote) imdb_buf_put(b, w->root_sig, IMDB_SIG_LEN);
    }
    if (!b->err) imdb_buf_put_u32(b, imdb_kern()->crc32c(0, b->p, b->len));
}

/* Each entry proven from META's keys, in order; the schedule grows as they verify. */
static int writers_load(imdb_db *db, const uint8_t *p, size_t n, imdb_err *e)
{
    if (n < 32 || imdb_kern()->crc32c(0, p, n - 4) != imdb_get_le32(p + n - 4))
        return imdb_fail(e, IMDB_ERR_CORRUPT, "WRITERS: damaged");
    imdb_rd r;
    imdb_rd_init(&r, p, n - 4);
    uint8_t magic[8], id[16];
    imdb_rd_copy(&r, magic, 8);
    imdb_rd_copy(&r, id, 16);
    uint32_t cnt = imdb_rd_u32(&r);
    if (r.err || memcmp(magic, "IMDBWRS1", 8) != 0 || memcmp(id, db->db_id, 16) != 0)
        return imdb_fail(e, IMDB_ERR_CORRUPT, "WRITERS: not this database's");
    if (cnt >= IMDB_MAX_EPOCHS) return imdb_fail(e, IMDB_ERR_LIMIT, "WRITERS: too many epochs");
    uint64_t last = 0;
    for (uint32_t i = 0; i < cnt; i++) {
        uint64_t seq = imdb_rd_u64(&r);
        uint8_t promote = imdb_rd_u8(&r);
        uint32_t hlen = imdb_rd_u32(&r);
        if (r.err || promote > 1 || seq <= last || hlen < IMDB_HEADER_MIN || hlen > IMDB_MAX_HEADER ||
            hlen > imdb_rd_left(&r))
            return imdb_fail(e, IMDB_ERR_CORRUPT, "WRITERS: bad entry %u", i + 1);
        const uint8_t *h = imdb_rd_bytes(&r, hlen);
        imdb_commit_rec c;
        if (!h || imdb_commit_decode_header(h, hlen, &c, e)) return h ? e->code : imdb_fail(e, IMDB_ERR_CORRUPT, "WRITERS: truncated");
        c.hlen = hlen;
        c.promote = promote;
        imdb_rd_copy(&r, c.sig, IMDB_SIG_LEN);
        if (promote) imdb_rd_copy(&r, c.root_sig, IMDB_SIG_LEN);
        const imdb_op *w = imdb_commit_writer_op(&c);
        int rc = IMDB_OK;
        if (r.err || c.seq != seq || !w || (w->how == IMDB_WRITER_PROMOTE) != (bool)promote)
            rc = imdb_fail(e, IMDB_ERR_CORRUPT, "WRITERS: entry %u is not a WRITER_KEY commit", i + 1);
        else if (!imdb_commit_authentic(&c, db->writer_pk, db->db_id, db->meta.has_root ? db->meta.root : NULL))
            rc = imdb_fail(e, IMDB_ERR_AUTH, "WRITERS: entry %u (commit %llu) is not signed by the keys before it", i + 1,
                           (unsigned long long)seq);
        else rc = imdb_writer_apply(db, &c, e);
        imdb_commit_free(&c);
        if (rc) return rc;
        last = seq;
    }
    if (imdb_rd_left(&r)) return imdb_fail(e, IMDB_ERR_CORRUPT, "WRITERS: trailing bytes");
    return IMDB_OK;
}

static int epoch0(imdb_db *db, imdb_err *e)
{
    imdb_writers_free(db);
    imdb_wep *z = wep_push(db, e);
    if (!z) return e->code;
    z->k.epoch = 0;
    z->k.first = 1;
    memcpy(z->k.pk, db->meta.writer, IMDB_PUBKEY_LEN);
    memcpy(db->writer_pk, db->meta.writer, IMDB_PUBKEY_LEN);
    return IMDB_OK;
}

int imdb_writers_parse(imdb_db *db, const uint8_t *p, size_t n, imdb_err *e)
{
    if (epoch0(db, e)) return e->code;
    int rc = writers_load(db, p, n, e);
    if (rc) imdb_writers_reset(db);
    return rc;
}

int imdb_writers_init(imdb_db *db, imdb_err *e)
{
    if (epoch0(db, e)) return e->code;
    uint8_t *p = NULL;
    size_t n = 0;
    imdb_err ew = {0};
    int rc = imdb_read_file_at(db->dirfd, IMDB_WRITERS_NAME, &p, &n, (size_t)IMDB_MAX_EPOCHS * 4096u, &ew);
    if (rc == IMDB_ERR_NOTFOUND) return IMDB_OK;
    if (!rc) rc = writers_load(db, p, n, &ew);
    imdb_free(p);
    if (rc) { /* proves nothing: a snapshot then fails to authenticate and the whole log is replayed */
        imdb_writers_reset(db);
        imdb_warn(db, "WRITERS ignored (%s)", ew.msg);
        if (rc == IMDB_ERR_NOMEM) return imdb_fail(e, rc, "%s", ew.msg);
    }
    return IMDB_OK;
}

int imdb_writers_publish(imdb_db *db, imdb_err *e)
{
    if (db->read_only) return IMDB_OK;
    if (db->nwep == 1) { /* no epochs: a file left by a lost one goes */
        if (imdb_io_unlinkat(db->dirfd, IMDB_WRITERS_NAME, 0) == 0) return imdb_sync_dir(db->dirfd, e);
        return errno == ENOENT ? IMDB_OK : imdb_fail(e, IMDB_ERR_IO, "WRITERS: %s", strerror(errno));
    }
    imdb_buf b;
    imdb_buf_init(&b);
    writers_encode(db, &b);
    int rc = imdb_buf_check(&b, e);
    uint8_t *cur = NULL;
    size_t cn = 0;
    imdb_err er = {0};
    if (!rc && imdb_read_file_at(db->dirfd, IMDB_WRITERS_NAME, &cur, &cn, b.len, &er) == IMDB_OK && cn == b.len &&
        memcmp(cur, b.p, cn) == 0) {
        imdb_free(cur);
        imdb_buf_free(&b);
        return IMDB_OK;
    }
    imdb_free(cur);
    if (!rc) rc = imdb_write_file_atomic(db->dirfd, IMDB_WRITERS_NAME, b.p, b.len, 0600, e);
    imdb_buf_free(&b);
    return rc;
}

/* ---- the writer's keys ---------------------------------------------------------------- */

/* A pending key that is not the log's current one was made and then no epoch change logged it
 * (torn, or a rotation or promotion that stopped before its commit), or was logged and damaged
 * since, when it may be the only copy of the current key. The log shows which: no such change if a
 * primary's current key is signing.key's, or if a replica's log does not end with a promotion (its
 * own would be its last commit). */
static bool next_unused(const imdb_db *db)
{
    const imdb_wep *w = &db->wep[db->nwep - 1];
    if (db->replica) return !(db->nwep > 1 && w->promote && w->seq == db->seq);
    return db->can_sign && imdb_ct_eq(db->signer.pk, db->writer_pk, IMDB_PUBKEY_LEN);
}

int imdb_writer_settle(imdb_db *db, imdb_err *e)
{
    imdb_signer next;
    bool has_next = false;
    imdb_err en = {0};
    int rc = imdb_seed_read(db->dirfd, IMDB_SIGNING_NEXT_NAME, &next, &has_next, &en);
    if (rc && rc != IMDB_ERR_INVALID) return imdb_fail(e, rc, "%s", en.msg);
    bool damaged = rc == IMDB_ERR_INVALID; /* not a 32-byte file: torn while made, or damaged since */
    rc = IMDB_OK;
    if (has_next && imdb_ct_eq(next.pk, db->writer_pk, IMDB_PUBKEY_LEN)) {
        /* the rotation or promotion reached the log: finish it (the logged op completing) */
        if (db->replica && (rc = imdb_meta_write(db, false, e))) goto out;
        db->replica = false;
        if (imdb_io_renameat(db->dirfd, IMDB_SIGNING_NEXT_NAME, db->dirfd, "signing.key") != 0) {
            rc = imdb_fail(e, IMDB_ERR_IO, "signing.key.next: %s", strerror(errno));
            goto out;
        }
        if ((rc = imdb_sync_dir(db->dirfd, e))) goto out;
        imdb_signer_wipe(&db->signer);
        db->signer = next;
        db->can_sign = true;
        return IMDB_OK;
    }
    if (has_next || damaged) {
        if (!next_unused(db)) { /* kept: deleting it could destroy the current key */
            rc = imdb_fail(e, IMDB_ERR_CORRUPT, "signing.key.next %s, and it may hold the writer key of epoch %u, which "
                           "the log names: kept as it is; restore it from a copy, or promote a replica (if this "
                           "directory never made that epoch change, remove the file)",
                           damaged ? "is damaged" : "is not the log's current key", imdb_current_epoch(db));
            goto out;
        }
        if (imdb_io_unlinkat(db->dirfd, IMDB_SIGNING_NEXT_NAME, 0) != 0 && errno != ENOENT) {
            rc = imdb_fail(e, IMDB_ERR_IO, "signing.key.next: %s", strerror(errno));
            goto out;
        }
        if ((rc = imdb_sync_dir(db->dirfd, e))) goto out;
    }
    if (db->can_sign && !imdb_ct_eq(db->signer.pk, db->writer_pk, IMDB_PUBKEY_LEN))
        rc = imdb_fail(e, IMDB_ERR_AUTH, "signing.key does not match the writer key of epoch %u", imdb_current_epoch(db));
out:
    if (has_next) imdb_signer_wipe(&next);
    return rc;
}

static int make_next(imdb_db *db, imdb_signer *next, imdb_err *e)
{
    struct stat st;
    if (imdb_io_fstatat(db->dirfd, IMDB_SIGNING_NEXT_NAME, &st, AT_SYMLINK_NOFOLLOW) == 0)
        return imdb_fail(e, IMDB_ERR_STATE, "signing.key.next exists: an unfinished rotation or promotion (reopen first)");
    uint8_t seed[IMDB_SEED_LEN];
    int rc = imdb_random(seed, sizeof seed, e);
    if (!rc) rc = imdb_create_file_excl(db->dirfd, IMDB_SIGNING_NEXT_NAME, seed, sizeof seed, 0600, e);
    if (!rc) rc = imdb_sync_dir(db->dirfd, e);
    if (!rc) imdb_signer_init(next, seed);
    else (void)imdb_io_unlinkat(db->dirfd, IMDB_SIGNING_NEXT_NAME, 0); /* a partial one: the next open drops it anyway */
    imdb_wipe(seed, sizeof seed);
    return rc;
}

int imdb_rotate_key(imdb_db *db, imdb_err *e)
{
    if (db->replica || db->read_only || !db->can_sign)
        return imdb_fail(e, IMDB_ERR_STATE, "only a writable primary rotates its writer key");
    if (db->failed) return imdb_fail(e, IMDB_ERR_STATE, "database handle failed earlier; reopen to recover");
    if (db->in_txn || db->active) return imdb_fail(e, IMDB_ERR_STATE, "rotate the key between transactions");
    imdb_signer next;
    int rc = make_next(db, &next, e);
    if (rc) return rc;
    if (!(rc = imdb_begin(db, e)) &&
        !(rc = imdb_tx_add_writer(db, imdb_current_epoch(db) + 1, next.pk, IMDB_WRITER_ROTATE, e)))
        rc = imdb_commit(db, e); /* signed by the current key; the schedule moves with it */
    if (!rc) rc = imdb_log_sync(db, e); /* durable before signing.key changes, under --nosync too */
    if (rc) {
        /* not committed: the key goes; maybe committed (a failed sync): the next open decides by the log */
        if (!db->failed && !imdb_ct_eq(db->writer_pk, next.pk, IMDB_PUBKEY_LEN))
            (void)imdb_io_unlinkat(db->dirfd, IMDB_SIGNING_NEXT_NAME, 0);
        imdb_signer_wipe(&next);
        return rc;
    }
    imdb_signer_wipe(&db->signer);
    db->signer = next; /* every later commit is signed by the new key */
    imdb_err e2 = {0};
    if (imdb_io_renameat(db->dirfd, IMDB_SIGNING_NEXT_NAME, db->dirfd, "signing.key") != 0)
        imdb_warn(db, "the key rotated at commit %llu, but signing.key is not replaced yet (the next open does it)",
                  (unsigned long long)db->seq);
    else if (imdb_sync_dir(db->dirfd, &e2)) {
        db->failed = true; /* the commit stands, but key-file durability is uncertain */
        imdb_warn(db, "the key rotated at commit %llu, but syncing signing.key's directory failed; reopen to recover",
                  (unsigned long long)db->seq);
    }
    else if (imdb_writers_publish(db, &e2))
        imdb_warn(db, "the key rotated at commit %llu, but WRITERS could not be written (%s)", (unsigned long long)db->seq,
                  e2.msg);
    return IMDB_OK;
}

/* ---- the root key's ledger ------------------------------------------------------------- */

/* "imagedb-root-ledger 1", then one line per certification: "promote <db id> <epoch> <seq> <prev>
 * <replica key>" (hex). Beside the root key, kept with it: it lets the root key's holder certify
 * each epoch of a database once. A reservation also refuses an identical retry: a copied replica
 * has the same identity, but make_next would give it another writer key and fork the epoch.
 * Interrupted reservations require explicit recovery after ruling out a committed copy. */
#define LEDGER_HEAD "imagedb-root-ledger 1\n"
#define LEDGER_MAX (1u << 20)

static bool ledger_hex(const char *p, size_t n, uint8_t *out)
{
    for (size_t i = 0; i < n; i++)
        if (!((p[i] >= '0' && p[i] <= '9') || (p[i] >= 'a' && p[i] <= 'f'))) return false; /* lowercase only */
    return imdb_unhex(p, n, out, n / 2);
}

/* a canonical decimal: digits only, no sign, no leading zero, at most max */
static bool ledger_num(const char *p, size_t n, uint64_t max, uint64_t *out)
{
    if (n == 0 || n > 20 || (n > 1 && p[0] == '0')) return false;
    uint64_t v = 0;
    for (size_t i = 0; i < n; i++)
        if (p[i] < '0' || p[i] > '9' || imdb_mul_ovf(v, (uint64_t)10, &v) || imdb_add_ovf(v, (uint64_t)(p[i] - '0'), &v))
            return false;
    *out = v;
    return v <= max;
}

/* "promote <db id: 32 hex> <epoch> <seq> <prev: 64 hex> <replica: 64 hex>" (len: without the newline) */
static bool ledger_line(const char *l, size_t len, uint8_t id[16], uint64_t *ep, uint64_t *sq, uint8_t prev[32],
                        uint8_t who[32])
{
    const char *end = l + len, *p = l + 41, *sp1, *sp2;
    if (len < 41 + 1 + 1 + 1 + 1 + 64 + 1 + 64 || memcmp(l, "promote ", 8) != 0 || !ledger_hex(l + 8, 32, id) ||
        l[40] != ' ')
        return false;
    if (!(sp1 = memchr(p, ' ', (size_t)(end - p))) || !ledger_num(p, (size_t)(sp1 - p), UINT32_MAX, ep)) return false;
    p = sp1 + 1;
    if (!(sp2 = memchr(p, ' ', (size_t)(end - p))) || !ledger_num(p, (size_t)(sp2 - p), UINT64_MAX, sq)) return false;
    p = sp2 + 1;
    return end - p == 64 + 1 + 64 && ledger_hex(p, 64, prev) && p[64] == ' ' && ledger_hex(p + 65, 64, who);
}

static int ledger_check(int fd, const char *path, const uint8_t db_id[16], uint32_t epoch, imdb_err *e)
{
    uint8_t *b = imdb_alloc(LEDGER_MAX + 1, e);
    size_t n = 0;
    int rc = b ? imdb_read_all(fd, b, LEDGER_MAX + 1, &n, e) : e->code;
    if (!rc && n > LEDGER_MAX) rc = imdb_fail(e, IMDB_ERR_LIMIT, "ledger %s is too large", path);
    if (!rc && n && (n < sizeof LEDGER_HEAD - 1 || memcmp(b, LEDGER_HEAD, sizeof LEDGER_HEAD - 1) != 0))
        rc = imdb_fail(e, IMDB_ERR_CORRUPT, "ledger %s is not an imagedb root ledger", path);
    for (size_t at = n ? sizeof LEDGER_HEAD - 1 : 0; !rc && at < n;) {
        const char *l = (const char *)b + at;
        const char *nl = memchr(l, '\n', n - at);
        uint8_t id[16], pv[32], who[32];
        uint64_t ep, sq;
        if (!nl || !ledger_line(l, (size_t)(nl - l), id, &ep, &sq, pv, who)) {
            rc = imdb_fail(e, IMDB_ERR_CORRUPT, "ledger %s: a malformed line", path);
            break;
        }
        if (memcmp(id, db_id, 16) == 0 && ep == epoch) {
            rc = imdb_fail(e, IMDB_ERR_STATE,
                           "epoch %u is already certified or reserved; retry may fork. Stop promoters and prove no copy "
                           "committed before you remove its line from %s", epoch, path);
        }
        at = (size_t)(nl - (const char *)b) + 1;
    }
    imdb_free(b);
    return rc;
}

static int ledger_add(int fd, const char *path, const uint8_t db_id[16], uint32_t epoch, uint64_t seq, const uint8_t prev[32],
                      const uint8_t replica[32], imdb_err *e)
{
    struct stat st;
    char line[300], id[33], pv[65], who[65];
    imdb_hex(db_id, 16, id);
    imdb_hex(prev, 32, pv);
    imdb_hex(replica, 32, who);
    int rc = imdb_io_fstat(fd, &st) == 0 ? IMDB_OK : imdb_fail(e, IMDB_ERR_IO, "ledger %s: %s", path, strerror(errno));
    if (!rc && st.st_size == 0) rc = imdb_write_all(fd, LEDGER_HEAD, sizeof LEDGER_HEAD - 1, e);
    int ln = snprintf(line, sizeof line, "promote %s %u %llu %s %s\n", id, epoch, (unsigned long long)seq, pv, who);
    if (!rc) rc = imdb_write_all(fd, line, (size_t)ln, e);
    return rc;
}

/* One locked inode covers check + append. Never replace/unlink a live ledger. Sync
 * both file and directory even if the file already existed: a prior failure may
 * have left an empty/header-only file whose name was never made durable. */
static int ledger_reserve(const char *path, const uint8_t db_id[16], uint32_t epoch, uint64_t seq,
                          const uint8_t prev[32], const uint8_t replica[32], imdb_err *e)
{
    const char *base;
    int dfd = imdb_open_parent(path, &base, e);
    if (dfd < 0) return dfd;
    int fd = imdb_io_openat(dfd, base, O_RDWR | O_APPEND | O_CREAT | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK, 0600);
    int rc = fd < 0 ? imdb_fail(e, IMDB_ERR_IO, "ledger %s: %s", path, strerror(errno)) : IMDB_OK;
    struct stat st;
    if (!rc && imdb_io_fstat(fd, &st) != 0) rc = imdb_fail(e, IMDB_ERR_IO, "ledger %s: stat: %s", path, strerror(errno));
    if (!rc && !S_ISREG(st.st_mode)) rc = imdb_fail(e, IMDB_ERR_INVALID, "ledger %s is not a regular file", path);
    if (!rc && imdb_io_flock(fd, LOCK_EX | LOCK_NB) != 0) {
        int err = errno;
        rc = err == EWOULDBLOCK
                 ? imdb_fail(e, IMDB_ERR_STATE, "ledger %s is held: another promotion is running (stop it first)", path)
                 : imdb_fail(e, IMDB_ERR_IO, "ledger %s: lock: %s", path, strerror(err));
    }
    if (!rc) rc = ledger_check(fd, path, db_id, epoch, e);
    if (!rc) rc = ledger_add(fd, path, db_id, epoch, seq, prev, replica, e);
    if (!rc && imdb_io_fsync(fd) != 0) rc = imdb_fail(e, IMDB_ERR_IO, "ledger %s: fsync failed: %s", path, strerror(errno));
    if (!rc) rc = imdb_sync_dir(dfd, e);
    if (fd >= 0) close(fd);
    close(dfd);
    return rc;
}

/* The anchor before a promotion of db: no newer epoch (an earlier promotion), and old-writer commits
 * past the cut only with abandon (reported in *abandoned_to). */
static int promote_anchor_check(imdb_db *db, const imdb_promote_opts *o, imdb_promote_result *r, imdb_err *e)
{
    imdb_anchor a;
    bool present, ahead;
    if (imdb_anchor_load(db, o->anchor, &a, &present, &ahead, e)) return e->code;
    if (!present) return IMDB_OK;
    if (ahead)
        return imdb_fail(e, IMDB_ERR_STATE, "the anchor %s names writer epoch %u, past this replica's %u: another "
                         "promotion (or a rotation this replica lacks) already happened; follow that writer instead",
                         o->anchor, a.epoch, imdb_current_epoch(db));
    if (a.seq <= db->seq) return imdb_anchor_in_history(db, o->anchor, &a, e);
    if (imdb_anchor_abandoned(db, &a)) return IMDB_OK; /* an earlier promotion already cut it off */
    if (a.epoch != imdb_current_epoch(db))
        return imdb_fail(e, IMDB_ERR_STATE, "the anchor %s names commit %llu of epoch %u, which this replica cannot place",
                         o->anchor, (unsigned long long)a.seq, a.epoch);
    r->abandoned_to = a.seq;
    if (!o->abandon)
        return imdb_fail(e, IMDB_ERR_STATE, "the old writer reached commit %llu (the anchor %s) and this replica only %llu: "
                         "promoting abandons commits %llu..%llu; say so (--abandon), or let the replica catch up first",
                         (unsigned long long)a.seq, o->anchor, (unsigned long long)db->seq,
                         (unsigned long long)db->seq + 1, (unsigned long long)a.seq);
    return IMDB_OK;
}

int imdb_promote(const char *dir, const uint8_t root_seed[IMDB_SEED_LEN], const imdb_promote_opts *o,
                 imdb_promote_result *r, imdb_err *e)
{
    memset(r, 0, sizeof *r);
    if (!o->anchor && !o->old_writer_stopped)
        return imdb_fail(e, IMDB_ERR_STATE, "promotion needs the shared anchor (its writer lock proves the old writer is "
                         "stopped) or the operator's word that the old writer is stopped and fenced (old_writer_stopped)");
    int alock = -1; /* held to the end: no writer opens with this anchor while the epoch changes */
    if (o->anchor && imdb_anchor_lock(o->anchor, &alock, e)) return e->code;
    imdb_open_opts oo = {.sync = 1};
    imdb_db *db;
    if (imdb_open(dir, &oo, &db, e)) {
        if (alock >= 0) close(alock);
        return e->code;
    }
    imdb_signer root, next;
    imdb_signer_init(&root, root_seed);
    int rc = IMDB_OK;
    bool made = false;
    if (!db->replica) rc = imdb_fail(e, IMDB_ERR_STATE, "%s is not a replica", dir);
    else if (!db->meta.has_root) rc = imdb_fail(e, IMDB_ERR_STATE, "this database has no root key: it cannot be promoted");
    else if (!imdb_ct_eq(root.pk, db->meta.root, IMDB_PUBKEY_LEN))
        rc = imdb_fail(e, IMDB_ERR_AUTH, "that root key is not this database's");
    else if (db->pending_auth || db->lake_unverified || db->failed)
        rc = imdb_fail(e, IMDB_ERR_STATE, "the replica has unauthorised redactions or a failed handle: apply first");
    if (!rc && o->anchor) rc = promote_anchor_check(db, o, r, e);
    uint32_t epoch = imdb_current_epoch(db) + 1;
    uint8_t rpk[IMDB_PUBKEY_LEN] = {0};
    if (!rc && o->ledger) { /* the ledger names which replica was promoted: its own key */
        imdb_signer rk;
        bool created;
        if (!(rc = imdb_replica_key(dir, false, &rk, &created, e))) {
            memcpy(rpk, rk.pk, IMDB_PUBKEY_LEN);
            imdb_signer_wipe(&rk);
        }
    }
    if (!rc && o->ledger) rc = ledger_reserve(o->ledger, db->db_id, epoch, db->seq + 1, db->head, rpk, e);
    if (!rc && !(rc = make_next(db, &next, e))) made = true;
    imdb_buf hdr, frame;
    imdb_buf_init(&hdr);
    imdb_buf_init(&frame);
    imdb_op op;
    memset(&op, 0, sizeof op);
    imdb_commit_rec c;
    memset(&c, 0, sizeof c);
    if (!rc) {
        /* the next epoch on top of this replica's last commit, as a follower would receive it */
        op.code = IMDB_OP_WRITER_KEY;
        op.epoch = epoch;
        memcpy(op.new_pk, next.pk, IMDB_PUBKEY_LEN);
        op.how = IMDB_WRITER_PROMOTE;
        c.seq = db->seq + 1;
        c.alg = db->meta.digest_alg;
        c.time_us = imdb_now_us();
        if (c.time_us <= db->last_time) c.time_us = db->last_time + 1;
        memcpy(c.prev, db->head, 32);
        c.ops = &op;
        c.nops = 1;
        imdb_state_digest(db, NULL, c.digest);
        imdb_commit_encode_header(&c, &hdr);
        rc = imdb_buf_check(&hdr, e);
    }
    if (!rc) {
        imdb_commit_hash(hdr.p, hdr.len, c.hash);
        c.hlen = (uint32_t)hdr.len;
        uint8_t msg[IMDB_SIGMSG_LEN], pm[IMDB_PROMOTE_MSG_LEN], ext[IMDB_BODY_EXT];
        imdb_commit_sigmsg(c.seq, c.hlen, c.hash, msg);
        imdb_sign(&next, msg, sizeof msg, c.sig);
        imdb_promote_msg(db->db_id, op.epoch, c.seq, c.prev, op.new_pk, pm);
        imdb_le32(ext, op.epoch);
        memcpy(ext + 4, op.new_pk, IMDB_PUBKEY_LEN);
        imdb_sign(&root, pm, sizeof pm, ext + 36);
        memcpy(c.root_sig, ext + 36, IMDB_SIG_LEN);
        imdb_frame_build_ext(hdr.p, hdr.len, c.seq, c.hash, c.sig, ext, NULL, 0, &frame);
        rc = imdb_buf_check(&frame, e);
    }
    if (!rc) { /* through the replica's own checks, then its log: what every follower does with it */
        imdb_commit_rec d;
        if (!(rc = imdb_frame_decode_body(frame.p + IMDB_FRAME_HDR, frame.len - IMDB_FRAME_HDR, &d, e))) {
            if ((rc = imdb_apply_commit(db, &d, NULL, e))) db->failed = true;
            if (!rc && (rc = imdb_log_append(db, frame.p, frame.len, e))) db->failed = true;
            imdb_commit_free(&d);
        }
        if (!rc) { /* sync on: the frame is durable now, whatever happens next */
            r->committed = true;
            r->epoch = op.epoch;
            r->seq = c.seq;
        }
    }
    if (!rc && (rc = imdb_writer_settle(db, e))) r->recovery_required = true; /* META primary, signing.key the new key */
    imdb_err e2 = {0};
    if (!rc && imdb_writers_publish(db, &e2)) imdb_warn(db, "promoted, but WRITERS could not be written (%s)", e2.msg);
    if (!rc && o->anchor) { /* from now on the anchor names the new epoch: an old writer opening with it is refused */
        if (imdb_anchor_adopt(db, o->anchor, &e2) == IMDB_OK) r->anchor_published = true;
        else imdb_warn(db, "promoted, but the anchor could not name the new epoch (%s): the new writer's first anchored "
                       "open does it", e2.msg);
    }
    if (rc && made && !r->committed && !db->failed) (void)imdb_io_unlinkat(db->dirfd, IMDB_SIGNING_NEXT_NAME, 0);
    if (made) imdb_signer_wipe(&next);
    imdb_signer_wipe(&root);
    imdb_buf_free(&hdr);
    imdb_buf_free(&frame);
    int crc = imdb_close(db);
    if (alock >= 0) close(alock);
    if (!rc && crc) {
        r->recovery_required = true;
        return imdb_fail(e, crc, "promoted at commit %llu, but the close failed: reopen the replica to finish",
                         (unsigned long long)r->seq);
    }
    return rc;
}
