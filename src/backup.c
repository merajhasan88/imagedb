/* Encrypted backups: the replication stream sealed in a file, restored by a replica's apply (backup.h). */
#include "backup.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "cpu.h"
#include "db_internal.h"
#include "fsio.h"
#include "limits.h"
#include "log.h"
#include "logdir.h"
#include "seed.h"
#include "sha256.h"
#include "stream.h"
#include "vendor/monocypher/monocypher.h"

static const char KEY_DOMAIN[] = "imagedb backup key id 1";
static const uint8_t MAGIC[8] = {'I', 'M', 'D', 'B', 'B', 'A', 'K', '1'};
#define AD_LEN 45u /* SHA-256(prologue) || le64(index) || flags || le32(length) */

static bool all_zero(const uint8_t *p, size_t n)
{
    uint8_t x = 0;
    for (size_t i = 0; i < n; i++) x |= p[i];
    return x == 0;
}

/* ---- the key ------------------------------------------------------------------- */

void imdb_backup_key_id(const uint8_t key[IMDB_BACKUP_KEY_LEN], uint8_t id[32])
{
    imdb_sha256_ctx c;
    imdb_sha256_init(&c);
    imdb_sha256_update(&c, KEY_DOMAIN, sizeof KEY_DOMAIN - 1);
    imdb_sha256_update(&c, key, IMDB_BACKUP_KEY_LEN);
    imdb_sha256_final(&c, id);
    imdb_wipe(&c, sizeof c);
}

int imdb_backup_key_create(const char *path, uint8_t id[32], imdb_err *e)
{
    uint8_t key[IMDB_BACKUP_KEY_LEN];
    const char *base;
    int dfd = -1; /* its name synced too: a power cut must not take the only key the backups open with */
    int rc = imdb_random(key, sizeof key, e);
    if (!rc && (dfd = imdb_open_parent(path, &base, e)) < 0) rc = e->code;
    if (!rc) rc = imdb_create_file_excl(dfd, base, key, sizeof key, 0400, e);
    if (!rc) rc = imdb_sync_dir(dfd, e);
    if (!rc) imdb_backup_key_id(key, id);
    if (dfd >= 0) close(dfd);
    imdb_wipe(key, sizeof key);
    return rc;
}

int imdb_backup_key_load(const char *path, uint8_t key[IMDB_BACKUP_KEY_LEN], imdb_err *e)
{
    const char *base;
    int dfd = imdb_open_parent(path, &base, e);
    if (dfd < 0) return e->code;
    uint8_t *p = NULL;
    size_t n = 0;
    int rc = imdb_read_file_at(dfd, base, &p, &n, IMDB_BACKUP_KEY_LEN, e);
    close(dfd);
    if (!rc && n != IMDB_BACKUP_KEY_LEN)
        rc = imdb_fail(e, IMDB_ERR_INVALID, "backup key %s: not a key file (%u bytes expected)", path, IMDB_BACKUP_KEY_LEN);
    if (!rc) memcpy(key, p, IMDB_BACKUP_KEY_LEN);
    if (p) {
        imdb_wipe(p, n);
        imdb_free(p);
    }
    return rc;
}

/* ---- the prologue, a chunk's nonce and additional data, the summary ------------- */

static void prologue_encode(uint8_t p[IMDB_BACKUP_PROLOGUE], const imdb_backup_info *in, const uint8_t prefix[16],
                            const uint8_t key_id[32])
{
    memset(p, 0, IMDB_BACKUP_PROLOGUE);
    memcpy(p, MAGIC, sizeof MAGIC);
    imdb_le32(p + 8, 1);
    imdb_le32(p + 12, in->incremental ? 2 : 1);
    memcpy(p + 16, in->id.db_id, 16);
    p[32] = in->id.digest_alg;
    p[33] = in->id.has_root ? 1 : 0;
    memcpy(p + 40, in->id.writer, IMDB_PUBKEY_LEN);
    if (in->id.has_root) memcpy(p + 72, in->id.root, IMDB_PUBKEY_LEN);
    imdb_le64(p + 104, in->prev_seq);
    memcpy(p + 112, in->prev_hash, 32);
    memcpy(p + 144, prefix, 16);
    memcpy(p + 160, key_id, 32);
    imdb_le32(p + 192, IMDB_BACKUP_CHUNK);
}

static int prologue_decode(const uint8_t p[IMDB_BACKUP_PROLOGUE], imdb_backup_info *out, uint8_t prefix[16],
                           uint8_t key_id[32], imdb_err *e)
{
    memset(out, 0, sizeof *out);
    if (memcmp(p, MAGIC, sizeof MAGIC) != 0) return imdb_fail(e, IMDB_ERR_CORRUPT, "backup: not an imagedb backup file");
    if (imdb_get_le32(p + 8) != 1)
        return imdb_fail(e, IMDB_ERR_UNSUPPORTED, "backup: format version %u (this build reads 1)", imdb_get_le32(p + 8));
    uint32_t kind = imdb_get_le32(p + 12);
    if ((kind != 1 && kind != 2) || (p[32] != IMDB_DIGEST_ALG_LTHASH16 && p[32] != IMDB_DIGEST_ALG_LTHASH16_TREE) ||
        p[33] > 1 || !all_zero(p + 34, 6) || (!p[33] && !all_zero(p + 72, IMDB_PUBKEY_LEN)) ||
        imdb_get_le32(p + 192) != IMDB_BACKUP_CHUNK || imdb_get_le32(p + 196) != 0)
        return imdb_fail(e, IMDB_ERR_CORRUPT, "backup: a malformed prologue");
    out->incremental = kind == 2;
    memcpy(out->id.db_id, p + 16, 16);
    out->id.digest_alg = p[32];
    out->id.has_root = p[33] != 0;
    memcpy(out->id.writer, p + 40, IMDB_PUBKEY_LEN);
    memcpy(out->id.root, p + 72, IMDB_PUBKEY_LEN);
    out->prev_seq = imdb_get_le64(p + 104);
    memcpy(out->prev_hash, p + 112, 32);
    if (out->incremental ? out->prev_seq == 0 : (out->prev_seq != 0 || !all_zero(out->prev_hash, 32)))
        return imdb_fail(e, IMDB_ERR_CORRUPT, "backup: a malformed prologue");
    memcpy(prefix, p + 144, 16);
    memcpy(key_id, p + 160, 32);
    return IMDB_OK;
}

static void chunk_ad(const uint8_t ph[32], uint64_t index, uint8_t flags, uint32_t len, uint8_t ad[AD_LEN])
{
    memcpy(ad, ph, 32);
    imdb_le64(ad + 32, index);
    ad[40] = flags;
    imdb_le32(ad + 41, len);
}

static void chunk_nonce(const uint8_t prefix[16], uint64_t index, uint8_t nonce[24])
{
    memcpy(nonce, prefix, 16);
    imdb_le64(nonce + 16, index);
}

static void summary_encode(uint8_t s[IMDB_BACKUP_SUMMARY], const imdb_backup_info *in)
{
    imdb_le32(s, 1);
    imdb_le32(s + 4, in->parts);
    imdb_le64(s + 8, in->first_seq);
    imdb_le64(s + 16, in->last_seq);
    memcpy(s + 24, in->last_hash, 32);
    imdb_le64(s + 56, in->seed_seq);
    imdb_le64(s + 64, in->chunks);
    imdb_le64(s + 72, in->payload_bytes);
}

/* The summary's own rules; what it says is compared with what the file held by the caller. */
static int summary_decode(const uint8_t s[IMDB_BACKUP_SUMMARY], imdb_backup_info *out, imdb_err *e)
{
    out->parts = imdb_get_le32(s + 4);
    out->first_seq = imdb_get_le64(s + 8);
    out->last_seq = imdb_get_le64(s + 16);
    memcpy(out->last_hash, s + 24, 32);
    out->seed_seq = imdb_get_le64(s + 56);
    out->chunks = imdb_get_le64(s + 64);
    out->payload_bytes = imdb_get_le64(s + 72);
    bool ok = imdb_get_le32(s) == 1 && (out->seed_seq ? out->parts == 2 && !out->incremental : out->parts == 1);
    if (ok && out->seed_seq) ok = out->first_seq == out->seed_seq && out->last_seq >= out->seed_seq;
    else if (ok && out->incremental) ok = out->last_seq ? out->first_seq == out->prev_seq + 1 : out->first_seq == 0;
    else if (ok) ok = out->last_seq ? out->first_seq == 1 : out->first_seq == 0;
    if (ok && !out->last_seq) ok = all_zero(out->last_hash, 32);
    if (!ok) return imdb_fail(e, IMDB_ERR_CORRUPT, "backup: a malformed summary");
    return IMDB_OK;
}

/* ---- the writer: a sink for ship's bytes ----------------------------------------- */

typedef struct bk_writer {
    int fd;
    const uint8_t *key;
    uint8_t ph[32], prefix[16];
    uint64_t index, payload;
    uint32_t parts;
    size_t have;
    uint8_t *plain;  /* IMDB_BACKUP_CHUNK */
    uint8_t *sealed; /* the chunk header, IMDB_BACKUP_CHUNK, the tag */
} bk_writer;

static int seal(bk_writer *w, uint32_t n, uint8_t flags, imdb_err *e)
{
    uint8_t ad[AD_LEN], nonce[24];
    chunk_ad(w->ph, w->index, flags, n, ad);
    chunk_nonce(w->prefix, w->index, nonce);
    uint8_t *s = w->sealed;
    imdb_le32(s, n);
    s[4] = flags;
    s[5] = s[6] = s[7] = 0;
    crypto_aead_lock(s + IMDB_BACKUP_CHUNK_HDR, s + IMDB_BACKUP_CHUNK_HDR + n, w->key, nonce, ad, sizeof ad, w->plain, n);
    w->index++;
    w->have = 0;
    return imdb_write_all(w->fd, s, IMDB_BACKUP_CHUNK_HDR + (size_t)n + IMDB_BACKUP_TAG, e);
}

static int bk_write(void *ctx, const void *p, size_t n, imdb_err *e)
{
    bk_writer *w = ctx;
    const uint8_t *b = p;
    while (n) {
        /* a full chunk is sealed only when more of the part follows, so a part's last byte is always in its END_PART
         * chunk: a reader at the end of what apply took is then at the part's end exactly, or the part holds more */
        if (w->have == IMDB_BACKUP_CHUNK && seal(w, IMDB_BACKUP_CHUNK, 0, e)) return e->code;
        size_t k = IMDB_BACKUP_CHUNK - w->have;
        if (k > n) k = n;
        memcpy(w->plain + w->have, b, k);
        w->have += k;
        w->payload += k;
        b += k;
        n -= k;
    }
    return IMDB_OK;
}

/* A part ends with its END_PART chunk: 1 to IMDB_BACKUP_CHUNK bytes, or none when the part is empty (its only chunk). */
static int end_part(bk_writer *w, imdb_err *e)
{
    w->parts++;
    return seal(w, (uint32_t)w->have, IMDB_BACKUP_END_PART, e);
}

static void writer_free(bk_writer *w)
{
    if (w->plain) imdb_wipe(w->plain, IMDB_BACKUP_CHUNK);
    imdb_free(w->plain);
    imdb_free(w->sealed);
}

/* Tests only: called between a seeded backup's two parts (a log cut there must be retried, not written). */
static void (*g_between)(void *ctx);
static void *g_between_ctx;

void imdb_backup_test_between(void (*fn)(void *ctx), void *ctx)
{
    g_between = fn;
    g_between_ctx = ctx;
}

/* The seed of the snapshot LAKE_HEAD names, as ship sends one past a log cut (seed.h): *have false when no snapshot is
 * published (an empty or never-checkpointed database: its backup is its frames from commit 1). */
static int snapshot_seed(const char *src, const imdb_sink *out, uint64_t *S, uint8_t hash[32], bool *have, imdb_err *e)
{
    *have = false;
    int dirfd = imdb_io_open(src, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (dirfd < 0) return imdb_fail(e, IMDB_ERR_IO, "backup: open %s: %s", src, strerror(errno));
    int logfd = imdb_open_dir_at(dirfd, IMDB_LOG_DIR, e);
    bool present = false;
    uint64_t hs = 0;
    uint8_t mh[32];
    int rc = logfd < 0 ? e->code : imdb_lake_head(dirfd, &present, &hs, mh, e);
    if (!rc && present) {
        rc = imdb_seed_send(src, dirfd, logfd, out, S, hash, e);
        *have = true;
    }
    if (logfd >= 0) close(logfd);
    close(dirfd);
    return rc;
}

/* The file's bytes from its start: the prologue, the parts, the summary. A full backup is a SNAPSHOT when one is
 * published: its seed, then the commits after it, so a restore's time follows the commits since the last CHECKPOINT,
 * not the history. *retry: the seed failed (a generation removed while it was read: its pin is best effort) or the
 * source's log was cut below the seed's commit before the second part (a RETIRE meanwhile): another attempt takes
 * the newer snapshot. */
static int write_backup(int fd, const char *src, const uint8_t key[IMDB_BACKUP_KEY_LEN], imdb_backup_info *info,
                        bool *retry, imdb_err *e)
{
    bk_writer w;
    memset(&w, 0, sizeof w);
    w.fd = fd;
    w.key = key;
    int rc = IMDB_OK;
    if (!(w.plain = imdb_alloc(IMDB_BACKUP_CHUNK, e)) ||
        !(w.sealed = imdb_alloc(IMDB_BACKUP_CHUNK_HDR + IMDB_BACKUP_CHUNK + IMDB_BACKUP_TAG, e)))
        rc = e->code;
    uint8_t pro[IMDB_BACKUP_PROLOGUE], key_id[32];
    if (!rc) rc = imdb_random(w.prefix, sizeof w.prefix, e);
    if (!rc) {
        imdb_backup_key_id(key, key_id);
        prologue_encode(pro, info, w.prefix, key_id);
        imdb_sha256(pro, sizeof pro, w.ph);
        rc = imdb_write_all(fd, pro, sizeof pro, e);
    }
    imdb_sink sink = {bk_write, &w};
    imdb_ship_result r1, r2;
    memset(&r1, 0, sizeof r1);
    memset(&r2, 0, sizeof r2);
    uint64_t S = 0;
    uint8_t sh[32] = {0};
    bool snap = false;
    if (!rc && (rc = snapshot_seed(src, &sink, &S, sh, &snap, e)) && snap) *retry = true;
    if (!rc && !snap) { /* no snapshot: the frames from commit 1 (ship seeds by itself only past a cut, which needs one) */
        rc = imdb_ship_to(src, 0, &sink, NULL, &r1, e);
        if (!rc && r1.seeded) {
            snap = true;
            S = r1.seeded;
            memcpy(sh, r1.seeded_hash, 32);
        }
    }
    if (!rc) rc = end_part(&w, e);
    if (!rc && snap) {
        info->seed_seq = S;
        if (g_between) g_between(g_between_ctx);
        rc = imdb_ship_to(src, S, &sink, NULL, &r2, e);
        if (rc && r2.cut) *retry = true;
        if (!rc) rc = end_part(&w, e);
        if (!rc && !r2.last_seq) { /* nothing after the seed: it is the last commit */
            r2.last_seq = S;
            memcpy(r2.last_hash, sh, 32);
        }
    }
    if (!rc) {
        const imdb_ship_result *r = snap ? &r2 : &r1;
        info->parts = w.parts;
        info->last_seq = r->last_seq;
        memcpy(info->last_hash, r->last_hash, 32);
        info->first_seq = snap ? S : r->last_seq ? 1 : 0;
        info->chunks = w.index;
        info->payload_bytes = w.payload;
        summary_encode(w.plain, info);
        w.have = IMDB_BACKUP_SUMMARY;
        rc = seal(&w, IMDB_BACKUP_SUMMARY, IMDB_BACKUP_END_FILE, e);
    }
    writer_free(&w);
    return rc;
}

int imdb_backup_full(const char *src, const char *out, const uint8_t key[IMDB_BACKUP_KEY_LEN], imdb_backup_info *info,
                     imdb_err *e)
{
    memset(info, 0, sizeof *info);
    imdb_identity id;
    bool replica = false;
    if (imdb_identity_read(src, &id, &replica, e)) return e->code;
    const char *base;
    int dfd = imdb_open_parent(out, &base, e);
    if (dfd < 0) return e->code;
    char tmp[IMDB_MAX_NAME + 1];
    int rc = IMDB_OK;
    struct stat st;
    if (strlen(base) + 4 > IMDB_MAX_NAME) rc = imdb_fail(e, IMDB_ERR_INVALID, "backup: the file name is too long");
    else snprintf(tmp, sizeof tmp, "%s.tmp", base);
    if (!rc && imdb_io_fstatat(dfd, base, &st, AT_SYMLINK_NOFOLLOW) == 0)
        rc = imdb_fail(e, IMDB_ERR_STATE, "backup: %s exists", out);
    for (int attempt = 0; !rc; attempt++) {
        int fd = imdb_io_openat(dfd, tmp, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
        if (fd < 0) {
            rc = errno == EEXIST ? imdb_fail(e, IMDB_ERR_STATE, "backup: %s.tmp exists (an interrupted backup's): remove it", out)
                                 : imdb_fail(e, IMDB_ERR_IO, "backup: create %s.tmp: %s", out, strerror(errno));
            break;
        }
        memset(info, 0, sizeof *info);
        info->id = id;
        bool retry = false;
        rc = write_backup(fd, src, key, info, &retry, e);
        /* the whole file durable before its name says it is complete */
        if (!rc && imdb_io_fsync(fd) != 0) rc = imdb_fail(e, IMDB_ERR_IO, "backup: fsync %s.tmp: %s", out, strerror(errno));
        close(fd);
        if (rc) {
            (void)imdb_io_unlinkat(dfd, tmp, 0); /* this attempt's own file (a crash leaves it: refused next time) */
            if (retry && attempt < 2) { /* the snapshot moved on while it was read: from the newer one */
                imdb_err_clear(e);
                rc = IMDB_OK;
                continue;
            }
            if (retry) { /* three times the snapshot moved on under the backup: say what to do with the last cause */
                char why[sizeof e->msg];
                snprintf(why, sizeof why, "%s", e->msg);
                rc = imdb_fail(e, rc, "backup: three attempts failed while the source published and retired (%s): "
                               "run the backup again", why);
            }
            break;
        }
        if (imdb_io_renameat(dfd, tmp, dfd, base) != 0) {
            rc = imdb_fail(e, IMDB_ERR_IO, "backup: rename to %s: %s", out, strerror(errno));
            (void)imdb_io_unlinkat(dfd, tmp, 0);
        }
        if (!rc) rc = imdb_sync_dir(dfd, e);
        break;
    }
    close(dfd);
    return rc;
}

/* ---- the reader: a source for apply's stream ------------------------------------- */

typedef struct bk_reader {
    int fd;
    const char *name;
    const uint8_t *key;
    uint8_t ph[32], prefix[16];
    uint64_t index;    /* the next chunk's */
    uint8_t *plain, *sealed;
    uint32_t len, off; /* the loaded chunk's plaintext, and how much of it was read */
    uint8_t flags;
    bool loaded;       /* a chunk of the current part is loaded */
    uint64_t payload;
} bk_reader;

static int read_chunk(bk_reader *r, bool part_start, imdb_err *e)
{
    uint8_t *s = r->sealed;
    size_t got = 0;
    if (imdb_read_all(r->fd, s, IMDB_BACKUP_CHUNK_HDR, &got, e)) return e->code;
    if (got != IMDB_BACKUP_CHUNK_HDR)
        return imdb_fail(e, IMDB_ERR_CORRUPT, "backup %s: it ends at chunk %llu, before its summary (incomplete)", r->name,
                         (unsigned long long)r->index);
    uint32_t n = imdb_get_le32(s);
    uint8_t f = s[4];
    /* canonical: a part's chunks are full but its last, which is empty only as an empty part's only chunk; the summary
     * is the summary's size */
    bool ok = !(s[5] | s[6] | s[7]) &&
              (f == 0 ? n == IMDB_BACKUP_CHUNK : f == IMDB_BACKUP_END_PART ? n <= IMDB_BACKUP_CHUNK && (n || part_start)
                                               : f == IMDB_BACKUP_END_FILE && n == IMDB_BACKUP_SUMMARY);
    if (!ok)
        return imdb_fail(e, IMDB_ERR_CORRUPT, "backup %s: chunk %llu: a malformed header", r->name,
                         (unsigned long long)r->index);
    if (imdb_read_all(r->fd, s + IMDB_BACKUP_CHUNK_HDR, (size_t)n + IMDB_BACKUP_TAG, &got, e)) return e->code;
    if (got != (size_t)n + IMDB_BACKUP_TAG)
        return imdb_fail(e, IMDB_ERR_CORRUPT, "backup %s: it ends inside chunk %llu (incomplete)", r->name,
                         (unsigned long long)r->index);
    uint8_t ad[AD_LEN], nonce[24];
    chunk_ad(r->ph, r->index, f, n, ad);
    chunk_nonce(r->prefix, r->index, nonce);
    if (crypto_aead_unlock(r->plain, s + IMDB_BACKUP_CHUNK_HDR + n, r->key, nonce, ad, sizeof ad,
                           s + IMDB_BACKUP_CHUNK_HDR, n) != 0)
        return imdb_fail(e, IMDB_ERR_VERIFY, "backup %s: chunk %llu fails its tag (damaged, moved, or another backup's)",
                         r->name, (unsigned long long)r->index);
    r->index++;
    r->len = n;
    r->off = 0;
    r->flags = f;
    return IMDB_OK;
}

/* imdb_read_fn over the current part: its end is the end of input. */
static int bk_read(void *ctx, void *buf, size_t n, size_t *got, imdb_err *e)
{
    bk_reader *r = ctx;
    uint8_t *b = buf;
    *got = 0;
    while (*got < n) {
        if (r->off == r->len) {
            if (r->loaded && (r->flags & IMDB_BACKUP_END_PART)) break;
            if (read_chunk(r, !r->loaded, e)) return e->code;
            if (r->flags & IMDB_BACKUP_END_FILE)
                return imdb_fail(e, IMDB_ERR_CORRUPT, "backup %s: the summary where a part's bytes belong", r->name);
            r->loaded = true;
            continue;
        }
        size_t k = n - *got < r->len - r->off ? n - *got : r->len - r->off;
        memcpy(b + *got, r->plain + r->off, k);
        r->off += (uint32_t)k;
        r->payload += k;
        *got += k;
    }
    return IMDB_OK;
}

/* After a part's apply: every byte of it was the stream's. Apply stops at a seed's end or at the stream's clean end,
 * and a part's last byte is in its END_PART chunk (the writer seals a full chunk only when more follows), so the
 * reader is then exactly at the end of that chunk; anywhere else, the part holds more than ship wrote. */
static int part_done(bk_reader *r, imdb_err *e)
{
    if (!(r->loaded && r->off == r->len && (r->flags & IMDB_BACKUP_END_PART)))
        return imdb_fail(e, IMDB_ERR_CORRUPT, "backup %s: a part holds bytes past its stream's end", r->name);
    r->loaded = false;
    r->len = r->off = 0;
    return IMDB_OK;
}

static int reader_open(bk_reader *r, const char *file, const uint8_t key[IMDB_BACKUP_KEY_LEN], imdb_backup_info *pro,
                       imdb_err *e)
{
    memset(r, 0, sizeof *r);
    r->fd = -1;
    r->name = file;
    r->key = key;
    const char *base;
    int dfd = imdb_open_parent(file, &base, e);
    if (dfd < 0) return e->code;
    r->fd = imdb_io_openat(dfd, base, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    int err = errno;
    close(dfd);
    struct stat st;
    if (r->fd < 0) return imdb_fail(e, IMDB_ERR_IO, "backup: open %s: %s", file, strerror(err));
    if (imdb_io_fstat(r->fd, &st) != 0 || !S_ISREG(st.st_mode))
        return imdb_fail(e, IMDB_ERR_INVALID, "backup: %s is not a regular file", file);
    if (!(r->plain = imdb_alloc(IMDB_BACKUP_CHUNK, e)) ||
        !(r->sealed = imdb_alloc(IMDB_BACKUP_CHUNK_HDR + IMDB_BACKUP_CHUNK + IMDB_BACKUP_TAG, e)))
        return e->code;
    uint8_t p[IMDB_BACKUP_PROLOGUE], key_id[32], mine[32];
    size_t got = 0;
    if (imdb_read_all(r->fd, p, sizeof p, &got, e)) return e->code;
    if (got != sizeof p) return imdb_fail(e, IMDB_ERR_CORRUPT, "backup %s: shorter than its prologue", file);
    if (prologue_decode(p, pro, r->prefix, key_id, e)) return e->code;
    imdb_backup_key_id(key, mine);
    if (memcmp(mine, key_id, 32) != 0)
        return imdb_fail(e, IMDB_ERR_AUTH, "backup %s: made with another key", file);
    imdb_sha256(p, sizeof p, r->ph);
    return IMDB_OK;
}

static void reader_close(bk_reader *r)
{
    if (r->fd >= 0) close(r->fd);
    if (r->plain) imdb_wipe(r->plain, IMDB_BACKUP_CHUNK);
    imdb_free(r->plain);
    imdb_free(r->sealed);
    r->fd = -1;
    r->plain = r->sealed = NULL;
}

/* The summary, after the last part, and nothing after it. */
static int read_summary(bk_reader *r, imdb_backup_info *info, imdb_err *e)
{
    if (read_chunk(r, true, e)) return e->code;
    if (r->flags != IMDB_BACKUP_END_FILE)
        return imdb_fail(e, IMDB_ERR_CORRUPT, "backup %s: more parts than its summary allows", r->name);
    if (summary_decode(r->plain, info, e)) return e->code;
    uint8_t one;
    size_t got = 0;
    if (imdb_read_all(r->fd, &one, 1, &got, e)) return e->code;
    if (got) return imdb_fail(e, IMDB_ERR_CORRUPT, "backup %s: bytes after its summary", r->name);
    return IMDB_OK;
}

/* ---- the check: every chunk, the frames' order, the summary, nothing applied ------ */

static const uint8_t SEED_MAGIC[8] = {'I', 'M', 'D', 'B', 'S', 'E', 'D', '1'};

typedef struct fwalk {
    const imdb_kernels *k;
    uint8_t hdr[IMDB_FRAME_HDR + 45]; /* the prefix, then the descriptor's kind, header length, seq and hash */
    size_t nh;
    uint32_t body_len, body_crc, crc;
    uint64_t seen, next_seq, last_seq;
    uint8_t last_hash[32];
} fwalk;

/* Frames as the log holds them: each prefix and body checksum, commits in order. Their signatures, rows and
 * digests are a restore's to check (backup-verify). */
static int fwalk_feed(fwalk *w, const uint8_t *p, size_t n, imdb_err *e)
{
    while (n) {
        if (w->nh < IMDB_FRAME_HDR) {
            size_t k = IMDB_FRAME_HDR - w->nh < n ? IMDB_FRAME_HDR - w->nh : n;
            memcpy(w->hdr + w->nh, p, k);
            w->nh += k;
            p += k;
            n -= k;
            if (w->nh < IMDB_FRAME_HDR) break;
            w->body_len = imdb_get_le32(w->hdr + 4);
            w->body_crc = imdb_get_le32(w->hdr + 8);
            if (imdb_get_le32(w->hdr) != IMDB_FRAME_MAGIC || w->k->crc32c(0, w->hdr, 12) != imdb_get_le32(w->hdr + 12) ||
                w->body_len < IMDB_BODY_DESC + IMDB_HEADER_MIN + 4 || w->body_len > IMDB_MAX_FRAME)
                return imdb_fail(e, IMDB_ERR_CORRUPT, "backup: commit %llu: a malformed frame prefix",
                                 (unsigned long long)w->next_seq);
            w->crc = 0;
            w->seen = 0;
            continue;
        }
        size_t k = w->body_len - w->seen < n ? (size_t)(w->body_len - w->seen) : n;
        if (w->seen < 45) {
            size_t c = 45 - w->seen < k ? (size_t)(45 - w->seen) : k;
            memcpy(w->hdr + IMDB_FRAME_HDR + w->seen, p, c);
        }
        w->crc = w->k->crc32c(w->crc, p, k);
        w->seen += k;
        p += k;
        n -= k;
        if (w->seen == w->body_len) {
            uint64_t seq = imdb_get_le64(w->hdr + IMDB_FRAME_HDR + 5);
            if (w->crc != w->body_crc)
                return imdb_fail(e, IMDB_ERR_CORRUPT, "backup: commit %llu fails its checksum", (unsigned long long)w->next_seq);
            if (seq != w->next_seq)
                return imdb_fail(e, IMDB_ERR_CORRUPT, "backup: commit %llu where commit %llu belongs", (unsigned long long)seq,
                                 (unsigned long long)w->next_seq);
            w->last_seq = seq;
            memcpy(w->last_hash, w->hdr + IMDB_FRAME_HDR + 13, 32);
            w->next_seq++;
            w->nh = 0;
        }
    }
    return IMDB_OK;
}

int imdb_backup_check(const char *file, const uint8_t key[IMDB_BACKUP_KEY_LEN], imdb_backup_info *info, imdb_err *e)
{
    memset(info, 0, sizeof *info);
    bk_reader r;
    imdb_backup_info pro;
    int rc = reader_open(&r, file, key, &pro, e);
    uint32_t parts = 0;
    uint64_t seed_seq = 0, payload = 0;
    bool start = true, in_seed = false;
    fwalk w;
    memset(&w, 0, sizeof w);
    w.k = imdb_kern();
    while (!rc) {
        if ((rc = read_chunk(&r, start, e))) break;
        if (r.flags & IMDB_BACKUP_END_FILE) {
            if (!start) rc = imdb_fail(e, IMDB_ERR_CORRUPT, "backup %s: its summary inside a part", file);
            break;
        }
        if (start) { /* a part begins; a full backup's first is a seed when it begins with one (seed.h) */
            parts++;
            in_seed = parts == 1 && !pro.incremental && r.len >= IMDB_SEED_PREFIX && memcmp(r.plain, SEED_MAGIC, 8) == 0;
            if (in_seed && (w.k->crc32c(0, r.plain, 24) != imdb_get_le32(r.plain + 24) ||
                            !(seed_seq = imdb_get_le64(r.plain + 8))))
                rc = imdb_fail(e, IMDB_ERR_CORRUPT, "backup %s: a malformed seed", file);
            w.nh = 0;
            w.next_seq = parts > 1 ? seed_seq + 1 : pro.incremental ? pro.prev_seq + 1 : 1;
        }
        if (!rc && !in_seed) rc = fwalk_feed(&w, r.plain, r.len, e); /* a seed's objects: its restore checks them */
        if (!rc && (r.flags & IMDB_BACKUP_END_PART) && w.nh)
            rc = imdb_fail(e, IMDB_ERR_CORRUPT, "backup %s: a part ends inside a frame", file);
        payload += r.len;
        start = (r.flags & IMDB_BACKUP_END_PART) != 0;
    }
    if (!rc) {
        *info = pro;
        rc = summary_decode(r.plain, info, e);
        uint8_t one;
        size_t got = 0;
        if (!rc && imdb_read_all(r.fd, &one, 1, &got, e)) rc = e->code;
        if (!rc && got) rc = imdb_fail(e, IMDB_ERR_CORRUPT, "backup %s: bytes after its summary", file);
    }
    if (!rc) { /* a seed with no commit after it ends at the seed's commit, whose hash its restore checks */
        uint64_t last = w.last_seq ? w.last_seq : seed_seq;
        if (info->parts != parts || info->chunks != r.index - 1 || info->payload_bytes != payload ||
            info->seed_seq != seed_seq || info->last_seq != last ||
            (w.last_seq && memcmp(info->last_hash, w.last_hash, 32) != 0))
            rc = imdb_fail(e, IMDB_ERR_CORRUPT, "backup %s: its summary disagrees with its contents", file);
    }
    reader_close(&r);
    return rc;
}

/* ---- restore ------------------------------------------------------------------------ */

static bool same_identity(const imdb_identity *a, const imdb_identity *b)
{
    return memcmp(a->db_id, b->db_id, 16) == 0 && memcmp(a->writer, b->writer, IMDB_PUBKEY_LEN) == 0 &&
           a->has_root == b->has_root && memcmp(a->root, b->root, IMDB_PUBKEY_LEN) == 0 && a->digest_alg == b->digest_alg;
}

static int no_point(void *ctx, imdb_db *db)
{
    (void)ctx;
    (void)db;
    return IMDB_OK;
}

/* Durable at apply's points and at close, not at every commit: a crash leaves dest.tmp, and the restore is run
 * again after it is removed. */
static int open_copy(const char *path, imdb_db **db, imdb_err *e)
{
    imdb_open_opts o;
    memset(&o, 0, sizeof o);
    o.sync = 0;
    return imdb_open(path, &o, db, e);
}

static int remove_tree_at(int pfd, const char *name, int depth, imdb_err *e);

int imdb_restore_ex(const char *dest, const uint8_t key[IMDB_BACKUP_KEY_LEN], const char *const *files, size_t nfiles,
                    const imdb_restore_opts *ro, imdb_backup_info *info, imdb_err *e)
{
    memset(info, 0, sizeof *info);
    if (nfiles == 0 || nfiles > IMDB_MAX_BACKUP_FILES)
        return imdb_fail(e, IMDB_ERR_INVALID, "restore: between 1 and %u backup files", IMDB_MAX_BACKUP_FILES);
    size_t dl = strlen(dest);
    if (dl == 0 || dest[dl - 1] == '/' || dl + 5 > IMDB_MAX_PATH)
        return imdb_fail(e, IMDB_ERR_INVALID, "restore: the destination is a new directory's path, without a trailing /");
    imdb_backup_info *in = imdb_alloc_array(nfiles, sizeof *in, e);
    if (!in) return e->code;
    int rc = IMDB_OK;
    /* every file whole first: a damaged or incomplete one is found before anything is applied */
    for (size_t i = 0; !rc && i < nfiles; i++) rc = imdb_backup_check(files[i], key, &in[i], e);
    for (size_t i = 0; !rc && i < nfiles; i++) {
        if (i == 0 ? in[0].incremental : !in[i].incremental)
            rc = imdb_fail(e, IMDB_ERR_INVALID, "restore: %s is not a %s backup", files[i], i ? "incremental" : "full");
        else if (i && (!same_identity(&in[i].id, &in[0].id) || in[i].prev_seq != in[i - 1].last_seq ||
                       memcmp(in[i].prev_hash, in[i - 1].last_hash, 32) != 0))
            rc = imdb_fail(e, IMDB_ERR_INVALID, "restore: %s does not follow %s (another database, or a gap)", files[i],
                           files[i - 1]);
    }
    uint64_t until = ro ? ro->until_seq : 0, until_t = ro ? ro->until_time : 0;
    if (!rc && until && ro->until_time)
        rc = imdb_fail(e, IMDB_ERR_INVALID, "restore: --until or --until-time, not both");
    if (!rc && until && (until > in[nfiles - 1].last_seq || until < (in[0].seed_seq ? in[0].seed_seq : 1)))
        rc = imdb_fail(e, IMDB_ERR_INVALID, "restore: commit %llu is not in these backups (they hold %llu to %llu)",
                       (unsigned long long)until, (unsigned long long)(in[0].seed_seq ? in[0].seed_seq : 1),
                       (unsigned long long)in[nfiles - 1].last_seq);
    bool stopped = false; /* the point in time reached: the rest of the files is not read (each was checked whole) */
    char tmp[IMDB_MAX_PATH], tname[IMDB_MAX_NAME + 1];
    const char *base = NULL;
    int dfd = -1;
    imdb_db *db = NULL;
    struct stat st;
    if (!rc && (dfd = imdb_open_parent(dest, &base, e)) < 0) rc = e->code;
    if (!rc && strlen(base) + 4 > IMDB_MAX_NAME) rc = imdb_fail(e, IMDB_ERR_INVALID, "restore: the destination name is too long");
    if (!rc) {
        snprintf(tmp, sizeof tmp, "%s.tmp", dest);
        snprintf(tname, sizeof tname, "%s.tmp", base);
        if (imdb_io_fstatat(dfd, base, &st, AT_SYMLINK_NOFOLLOW) == 0) rc = imdb_fail(e, IMDB_ERR_STATE, "restore: %s exists", dest);
        else if (imdb_io_fstatat(dfd, tname, &st, AT_SYMLINK_NOFOLLOW) == 0)
            rc = imdb_fail(e, IMDB_ERR_STATE, "restore: %s exists (an interrupted restore's): remove it", tmp);
    }
    bool made = !rc; /* past the checks: whatever is at tname from here on, this call made */
    if (!rc) rc = imdb_init_replica(tmp, &in[0].id, e);
    if (!rc) rc = open_copy(tmp, &db, e);
    for (size_t i = 0; !rc && !stopped && i < nfiles; i++) {
        bk_reader r;
        imdb_backup_info pro, sum;
        rc = reader_open(&r, files[i], key, &pro, e);
        for (uint32_t p = 0; !rc && !stopped && p < in[i].parts; p++) {
            imdb_apply_opts ao;
            memset(&ao, 0, sizeof ao);
            ao.applied = no_point; /* its points make the copy durable now and then: the log synced, the lake published */
            ao.every = IMDB_RESTORE_EVERY;
            ao.until_seq = until;
            ao.until_time = until_t;
            uint64_t applied = 0;
            rc = imdb_apply_source(db, bk_read, &r, &applied, &ao, e);
            stopped = !rc && ao.stopped;
            if (!rc && !stopped) rc = part_done(&r, e);
            if (!rc && ao.seeded) { /* the handle is stale after a seed (seed.h): reopen */
                int c = imdb_close(db);
                db = NULL;
                rc = c ? imdb_fail(e, IMDB_ERR_IO, "restore: the copy could not be made durable after its seed")
                       : open_copy(tmp, &db, e);
            }
        }
        sum = pro;
        if (!rc && !stopped) rc = read_summary(&r, &sum, e);
        /* the file applied is the one checked: the same summary (a file replaced meanwhile is refused) */
        if (!rc && !stopped && (sum.parts != in[i].parts || sum.last_seq != in[i].last_seq || sum.seed_seq != in[i].seed_seq ||
                    sum.chunks != in[i].chunks || memcmp(sum.last_hash, in[i].last_hash, 32) != 0))
            rc = imdb_fail(e, IMDB_ERR_STATE, "restore: %s changed while it was restored", files[i]);
        reader_close(&r);
    }
    const imdb_backup_info *last = &in[nfiles - 1];
    if (!rc && (until || until_t)) { /* point-in-time: the asked commit, or the last at or before the asked time */
        if (until && db->seq != until)
            rc = imdb_fail(e, IMDB_ERR_INVALID, "restore: the copy ends at commit %llu, not the asked %llu",
                           (unsigned long long)db->seq, (unsigned long long)until);
        else if (!until && (db->seq == 0 || db->last_time > until_t))
            rc = imdb_fail(e, IMDB_ERR_INVALID, "restore: no commit at or before the asked time in these backups (the "
                           "copy would begin at commit %llu)", (unsigned long long)db->seq);
    } else if (!rc && (db->seq != last->last_seq || (last->last_seq && memcmp(db->head, last->last_hash, 32) != 0)))
        rc = imdb_fail(e, IMDB_ERR_VERIFY, "restore: the copy ends at commit %llu, its backup at %llu",
                       (unsigned long long)db->seq, (unsigned long long)last->last_seq);
    uint64_t db_seq = db ? db->seq : 0; /* where the copy ends, for info: the asked point, or the backups' last */
    uint8_t db_head[32] = {0};
    if (db) memcpy(db_head, db->head, 32);
    if (db && imdb_close(db) && !rc) rc = imdb_fail(e, IMDB_ERR_IO, "restore: the copy could not be made durable");
    if (!rc && imdb_io_renameat(dfd, tname, dfd, base) != 0)
        rc = imdb_fail(e, IMDB_ERR_IO, "restore: rename %s to %s: %s", tmp, dest, strerror(errno));
    if (!rc) rc = imdb_sync_dir(dfd, e);
    if (rc && made) { /* a failure, not a crash: the copy is this call's own, so it goes, and a restore run again (once
                     * there is room) needs no operator; a crash's DEST.tmp stays for one, as the next restore says */
        imdb_err er = {0};
        if (remove_tree_at(dfd, tname, 0, &er) || imdb_sync_dir(dfd, &er)) {
            size_t l = strlen(e->msg); /* the failure stays the error: the cleanup's own is told beside it */
            snprintf(e->msg + l, sizeof e->msg - l, " (and %s is left: %s; remove it)", tmp, er.msg);
        }
    }
    if (dfd >= 0) close(dfd);
    if (!rc) {
        *info = *last;
        info->last_seq = db_seq;
        memcpy(info->last_hash, db_head, 32);
    }
    imdb_free(in);
    return rc;
}

int imdb_restore(const char *dest, const uint8_t key[IMDB_BACKUP_KEY_LEN], const char *const *files, size_t nfiles,
                 imdb_backup_info *info, imdb_err *e)
{
    return imdb_restore_ex(dest, key, files, nfiles, NULL, info, e);
}

/* ---- incremental backups (P0 backup slice 2) ------------------------------------------------------------------- */

/* The sink an incremental's stream passes through: the first frame's bytes are kept, so the backup can check that it
 * continues the previous backup's history (its sequence, and its link to the commit before it) before the file is
 * named; the restore would refuse a gap or another history later, the backup says so now */
typedef struct link_sink {
    imdb_sink next;
    uint8_t head[IMDB_FRAME_HDR + IMDB_BODY_DESC + IMDB_BODY_EXT + 64];
    size_t have;
} link_sink;

static int link_write(void *ctx, const void *p, size_t n, imdb_err *e)
{
    link_sink *l = ctx;
    if (l->have < sizeof l->head) {
        size_t take = n < sizeof l->head - l->have ? n : sizeof l->head - l->have;
        memcpy(l->head + l->have, p, take);
        l->have += take;
    }
    return l->next.write(l->next.ctx, p, n, e);
}

/* the first frame's commit and the hash it names as the one before it (the header: version, algorithm, seq, time,
 * prev), when the kept bytes hold them */
static bool link_of(const link_sink *l, uint64_t *seq, const uint8_t **prev)
{
    if (l->have < IMDB_FRAME_HDR + IMDB_BODY_DESC || imdb_get_le32(l->head) != IMDB_FRAME_MAGIC) return false;
    size_t at = IMDB_FRAME_HDR + imdb_body_desc_len(l->head + IMDB_FRAME_HDR) + 18;
    if (l->have < at + 32) return false;
    *seq = imdb_frame_seq(l->head);
    *prev = l->head + at;
    return true;
}

static int write_incremental(int fd, const char *src, const uint8_t key[IMDB_BACKUP_KEY_LEN], imdb_backup_info *info,
                             imdb_err *e)
{
    bk_writer w;
    memset(&w, 0, sizeof w);
    w.fd = fd;
    w.key = key;
    int rc = IMDB_OK;
    if (!(w.plain = imdb_alloc(IMDB_BACKUP_CHUNK, e)) ||
        !(w.sealed = imdb_alloc(IMDB_BACKUP_CHUNK_HDR + IMDB_BACKUP_CHUNK + IMDB_BACKUP_TAG, e)))
        rc = e->code;
    uint8_t pro[IMDB_BACKUP_PROLOGUE], key_id[32];
    if (!rc) rc = imdb_random(w.prefix, sizeof w.prefix, e);
    if (!rc) {
        imdb_backup_key_id(key, key_id);
        prologue_encode(pro, info, w.prefix, key_id);
        imdb_sha256(pro, sizeof pro, w.ph);
        rc = imdb_write_all(fd, pro, sizeof pro, e);
    }
    link_sink l;
    memset(&l, 0, sizeof l);
    l.next = (imdb_sink){bk_write, &w};
    imdb_sink sink = {link_write, &l};
    imdb_ship_result r;
    memset(&r, 0, sizeof r);
    if (!rc) rc = imdb_ship_to(src, info->prev_seq, &sink, NULL, &r, e);
    uint64_t fseq = 0;
    const uint8_t *fprev = NULL;
    if ((rc && r.cut) || (!rc && r.seeded)) {
        imdb_err_clear(e);
        rc = imdb_fail(e, IMDB_ERR_STATE, "backup: the source's log no longer holds commit %llu (retired): take a full backup",
                       (unsigned long long)(info->prev_seq + 1));
    } else if (!rc && !r.last_seq) {
        rc = imdb_fail(e, IMDB_ERR_STATE, "backup: nothing was committed after the previous backup's commit %llu: no "
                       "backup written", (unsigned long long)info->prev_seq);
    } else if (!rc && (!link_of(&l, &fseq, &fprev) || fseq != info->prev_seq + 1 || memcmp(fprev, info->prev_hash, 32) != 0)) {
        rc = imdb_fail(e, IMDB_ERR_STATE, "backup: the source's commit %llu is not the previous backup's (another history)",
                       (unsigned long long)info->prev_seq);
    }
    if (!rc) rc = end_part(&w, e);
    if (!rc) {
        info->parts = w.parts;
        info->first_seq = info->prev_seq + 1;
        info->last_seq = r.last_seq;
        memcpy(info->last_hash, r.last_hash, 32);
        info->chunks = w.index;
        info->payload_bytes = w.payload;
        summary_encode(w.plain, info);
        w.have = IMDB_BACKUP_SUMMARY;
        rc = seal(&w, IMDB_BACKUP_SUMMARY, IMDB_BACKUP_END_FILE, e);
    }
    writer_free(&w);
    return rc;
}

int imdb_backup_incremental(const char *src, const char *prev, const char *out, const uint8_t key[IMDB_BACKUP_KEY_LEN],
                            imdb_backup_info *info, imdb_err *e)
{
    memset(info, 0, sizeof *info);
    imdb_backup_info pi;
    if (imdb_backup_check(prev, key, &pi, e)) return e->code;
    if (!pi.last_seq) return imdb_fail(e, IMDB_ERR_STATE, "backup: %s holds no commit: take a full backup", prev);
    imdb_identity id;
    bool replica = false;
    if (imdb_identity_read(src, &id, &replica, e)) return e->code;
    if (!same_identity(&id, &pi.id)) return imdb_fail(e, IMDB_ERR_INVALID, "backup: %s is a backup of another database", prev);
    const char *base;
    int dfd = imdb_open_parent(out, &base, e);
    if (dfd < 0) return e->code;
    char tmp[IMDB_MAX_NAME + 1];
    int rc = IMDB_OK;
    struct stat st;
    if (strlen(base) + 4 > IMDB_MAX_NAME) rc = imdb_fail(e, IMDB_ERR_INVALID, "backup: the file name is too long");
    else snprintf(tmp, sizeof tmp, "%s.tmp", base);
    if (!rc && imdb_io_fstatat(dfd, base, &st, AT_SYMLINK_NOFOLLOW) == 0)
        rc = imdb_fail(e, IMDB_ERR_STATE, "backup: %s exists", out);
    int fd = -1;
    if (!rc && (fd = imdb_io_openat(dfd, tmp, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600)) < 0)
        rc = errno == EEXIST ? imdb_fail(e, IMDB_ERR_STATE, "backup: %s.tmp exists (an interrupted backup's): remove it", out)
                             : imdb_fail(e, IMDB_ERR_IO, "backup: create %s.tmp: %s", out, strerror(errno));
    if (!rc) {
        info->id = id;
        info->incremental = true;
        info->prev_seq = pi.last_seq;
        memcpy(info->prev_hash, pi.last_hash, 32);
        rc = write_incremental(fd, src, key, info, e);
        /* the whole file durable before its name says it is complete */
        if (!rc && imdb_io_fsync(fd) != 0) rc = imdb_fail(e, IMDB_ERR_IO, "backup: fsync %s.tmp: %s", out, strerror(errno));
        close(fd);
        if (rc) (void)imdb_io_unlinkat(dfd, tmp, 0); /* this attempt's own file (a crash leaves it: refused next time) */
        if (!rc && imdb_io_renameat(dfd, tmp, dfd, base) != 0) {
            rc = imdb_fail(e, IMDB_ERR_IO, "backup: rename to %s: %s", out, strerror(errno));
            (void)imdb_io_unlinkat(dfd, tmp, 0);
        }
        if (!rc) rc = imdb_sync_dir(dfd, e);
    }
    close(dfd);
    return rc;
}

/* ---- the test restore ---------------------------------------------------------------- */

/* Removes a directory tree this process made (a test restore's copy): every entry through a directory opened
 * O_NOFOLLOW, so nothing outside it is reached and a symlink inside goes as itself. Passes until it is empty:
 * entries removed while reading a directory may hide others from that read. */
static int remove_tree_at(int pfd, const char *name, int depth, imdb_err *e)
{
    if (depth > 8) return imdb_fail(e, IMDB_ERR_LIMIT, "remove: deeper than a database directory");
    for (int pass = 0; pass < 4; pass++) {
        int fd = imdb_io_openat(pfd, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        if (fd < 0) return errno == ENOENT ? IMDB_OK : imdb_fail(e, IMDB_ERR_IO, "remove %s: %s", name, strerror(errno));
        DIR *d = imdb_io_fdopendir(fd);
        if (!d) {
            close(fd);
            return imdb_fail(e, IMDB_ERR_IO, "remove %s: %s", name, strerror(errno));
        }
        int rc = IMDB_OK;
        for (struct dirent *de; !rc && (errno = 0, de = imdb_io_readdir(d));) {
            if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0) continue;
            struct stat st;
            if (imdb_io_fstatat(fd, de->d_name, &st, AT_SYMLINK_NOFOLLOW) != 0)
                rc = imdb_fail(e, IMDB_ERR_IO, "remove %s: %s", de->d_name, strerror(errno));
            else if (S_ISDIR(st.st_mode)) rc = remove_tree_at(fd, de->d_name, depth + 1, e);
            else if (imdb_io_unlinkat(fd, de->d_name, 0) != 0)
                rc = imdb_fail(e, IMDB_ERR_IO, "remove %s: %s", de->d_name, strerror(errno));
        }
        closedir(d);
        if (rc) return rc;
        if (imdb_io_unlinkat(pfd, name, AT_REMOVEDIR) == 0) return IMDB_OK;
        if (errno != ENOTEMPTY && errno != EEXIST) return imdb_fail(e, IMDB_ERR_IO, "remove %s: %s", name, strerror(errno));
    }
    return imdb_fail(e, IMDB_ERR_IO, "remove %s: not empty after four passes", name);
}

int imdb_backup_verify(const char *scratch, const uint8_t key[IMDB_BACKUP_KEY_LEN], const char *const *files,
                       size_t nfiles, imdb_backup_info *info, imdb_verify_report *rep, imdb_err *e)
{
    memset(rep, 0, sizeof *rep);
    uint8_t rnd[8];
    char name[64], tname[64 + 4], path[IMDB_MAX_PATH];
    if (imdb_random(rnd, sizeof rnd, e)) return e->code;
    char hex[17];
    imdb_hex(rnd, sizeof rnd, hex);
    snprintf(name, sizeof name, "imagedb-verify-%s", hex);
    snprintf(tname, sizeof tname, "%s.tmp", name);
    if (strlen(scratch) + 1 + strlen(name) + 5 > sizeof path)
        return imdb_fail(e, IMDB_ERR_INVALID, "backup-verify: the scratch path is too long");
    snprintf(path, sizeof path, "%s/%s", scratch, name);
    int rc = imdb_restore(path, key, files, nfiles, info, e);
    if (!rc) {
        imdb_db *db = NULL;
        imdb_open_opts o;
        memset(&o, 0, sizeof o);
        o.sync = 1;
        o.read_only = true;
        if (!(rc = imdb_open(path, &o, &db, e))) {
            rc = imdb_verify(db, rep, e);
            imdb_close(db);
        }
    }
    /* the copy goes whatever happened: it is this call's own (and so is its .tmp, after a failed restore) */
    imdb_err er = {0};
    int sfd = imdb_io_open(scratch, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (sfd < 0) {
        if (!rc) rc = imdb_fail(e, IMDB_ERR_IO, "backup-verify: open %s: %s", scratch, strerror(errno));
        return rc;
    }
    if (remove_tree_at(sfd, name, 0, &er) || remove_tree_at(sfd, tname, 0, &er) || imdb_sync_dir(sfd, &er)) {
        if (!rc) {
            *e = er;
            rc = er.code;
        }
    }
    close(sfd);
    return rc;
}
