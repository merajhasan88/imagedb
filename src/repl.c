/* Replica acknowledgements (see repl.h). */
#include "repl.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "cpu.h"
#include "db.h"
#include "fsio.h"
#include "writer.h"

#define ACK_BODY 128u
#define ACK_REC (IMDB_ACK_LEN + 12) /* NAME.ack: the acknowledgement, the receipt time (unix ms), CRC32C */
/* NAME.diverged: the refused acknowledgement, why (imdb_refusal), the commit acknowledged before (BACK) */
#define REFUSED_LEN (IMDB_ACK_LEN + 9)

static void ack_body(const imdb_ack *a, uint8_t b[ACK_BODY])
{
    memcpy(b, "IMDBACK2", 8);
    memcpy(b + 8, a->db_id, 16);
    memcpy(b + 24, a->replica, IMDB_PUBKEY_LEN);
    imdb_le32(b + 56, a->epoch);
    imdb_le32(b + 60, 0);
    memcpy(b + 64, a->nonce, IMDB_NONCE_LEN);
    imdb_le64(b + 80, a->seq);
    memcpy(b + 88, a->head, 32);
    imdb_le64(b + 120, a->cleanup);
}

void imdb_ack_sign(const imdb_ack *a, const imdb_signer *s, uint8_t out[IMDB_ACK_LEN])
{
    ack_body(a, out);
    imdb_sign(s, out, ACK_BODY, out + ACK_BODY);
}

int imdb_ack_open(const uint8_t b[IMDB_ACK_LEN], imdb_ack *a, imdb_err *e)
{
    memset(a, 0, sizeof *a);
    if (memcmp(b, "IMDBACK2", 8) != 0) return imdb_fail(e, IMDB_ERR_CORRUPT, "acknowledgement: bad magic");
    if (imdb_get_le32(b + 60) != 0) return imdb_fail(e, IMDB_ERR_CORRUPT, "acknowledgement: nonzero padding");
    memcpy(a->db_id, b + 8, 16);
    memcpy(a->replica, b + 24, IMDB_PUBKEY_LEN);
    a->epoch = imdb_get_le32(b + 56);
    memcpy(a->nonce, b + 64, IMDB_NONCE_LEN);
    a->seq = imdb_get_le64(b + 80);
    memcpy(a->head, b + 88, 32);
    a->cleanup = imdb_get_le64(b + 120);
    if (a->cleanup > a->seq) return imdb_fail(e, IMDB_ERR_CORRUPT, "acknowledgement: cleanup past its commit");
    if (!imdb_sig_verify(a->replica, b, ACK_BODY, b + ACK_BODY))
        return imdb_fail(e, IMDB_ERR_AUTH, "acknowledgement: not signed by the key it names");
    return IMDB_OK;
}

void imdb_session_encode(const uint8_t db_id[16], const uint8_t nonce[IMDB_NONCE_LEN], uint8_t out[IMDB_SESSION_LEN])
{
    memcpy(out, "IMDBSES1", 8);
    memcpy(out + 8, db_id, 16);
    memcpy(out + 24, nonce, IMDB_NONCE_LEN);
    imdb_le32(out + 40, imdb_kern()->crc32c(0, out, 40));
}

int imdb_session_decode(const uint8_t b[IMDB_SESSION_LEN], const uint8_t db_id[16], uint8_t nonce[IMDB_NONCE_LEN],
                        imdb_err *e)
{
    if (memcmp(b, "IMDBSES1", 8) != 0) return 0;
    if (imdb_kern()->crc32c(0, b, 40) != imdb_get_le32(b + 40)) {
        imdb_fail(e, IMDB_ERR_CORRUPT, "stream: damaged session record");
        return -1;
    }
    if (memcmp(b + 8, db_id, 16) != 0) {
        imdb_fail(e, IMDB_ERR_VERIFY, "stream: a shipping session of another database");
        return -1;
    }
    memcpy(nonce, b + 24, IMDB_NONCE_LEN);
    return 1;
}

/* ---- the replica's key ---------------------------------------------------------- */

int imdb_replica_key_create(int dirfd, imdb_err *e)
{
    uint8_t seed[IMDB_SEED_LEN];
    int rc = imdb_random(seed, sizeof seed, e);
    if (!rc) rc = imdb_create_file_excl(dirfd, IMDB_REPLICA_KEY_NAME, seed, sizeof seed, 0600, e);
    imdb_wipe(seed, sizeof seed);
    return rc;
}

int imdb_replica_key(const char *dir, bool create, imdb_signer *s, bool *created, imdb_err *e)
{
    *created = false;
    int dirfd = imdb_io_open(dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (dirfd < 0) return imdb_fail(e, IMDB_ERR_IO, "open %s: %s", dir, strerror(errno));
    uint8_t *b = NULL;
    size_t n = 0;
    int rc = imdb_read_file_at(dirfd, IMDB_REPLICA_KEY_NAME, &b, &n, IMDB_SEED_LEN, e);
    if (rc == IMDB_ERR_NOTFOUND && create) {
        imdb_err_clear(e);
        rc = imdb_replica_key_create(dirfd, e);
        if (!rc) rc = imdb_sync_dir(dirfd, e);
        if (!rc) rc = imdb_read_file_at(dirfd, IMDB_REPLICA_KEY_NAME, &b, &n, IMDB_SEED_LEN, e);
        if (!rc) *created = true;
    } else if (rc == IMDB_ERR_NOTFOUND) {
        rc = imdb_fail(e, rc, "%s has no replica key (imagedb replica-key %s makes one)", dir, dir);
    }
    close(dirfd);
    if (rc) return rc;
    if (n != IMDB_SEED_LEN) rc = imdb_fail(e, IMDB_ERR_CORRUPT, "replica.key: wrong length");
    else imdb_signer_init(s, b);
    imdb_wipe(b, n);
    free(b);
    return rc;
}

int imdb_replica_key_new(const char *dir, imdb_signer *s, imdb_err *e)
{
    int dirfd = imdb_io_open(dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (dirfd < 0) return imdb_fail(e, IMDB_ERR_IO, "open %s: %s", dir, strerror(errno));
    /* the directory's lock: a running follow signs with the key it loaded, so it must stop first */
    int lockfd = imdb_io_openat(dirfd, "LOCK", O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0600);
    int rc = IMDB_OK;
    if (lockfd < 0 || imdb_io_flock(lockfd, LOCK_EX | LOCK_NB) != 0)
        rc = imdb_fail(e, IMDB_ERR_STATE, "%s is in use by another process (stop its follow first)", dir);
    uint8_t seed[IMDB_SEED_LEN];
    if (!rc) rc = imdb_random(seed, sizeof seed, e);
    if (!rc) rc = imdb_write_file_atomic(dirfd, IMDB_REPLICA_KEY_NAME, seed, sizeof seed, 0600, e);
    if (!rc) imdb_signer_init(s, seed);
    imdb_wipe(seed, sizeof seed);
    if (lockfd >= 0) close(lockfd);
    close(dirfd);
    return rc;
}

/* ---- the allowlist ---------------------------------------------------------------- */

static bool name_ok(const char *n, size_t len)
{
    if (len == 0 || len > IMDB_REPLICA_NAME_MAX) return false;
    for (size_t i = 0; i < len; i++)
        if (!((n[i] >= 'a' && n[i] <= 'z') || (n[i] >= '0' && n[i] <= '9') || n[i] == '_' || n[i] == '-')) return false;
    return true;
}

/* replicas/ (create: made first); -2 when it does not exist yet */
static int replicas_dir(int dirfd, bool create, imdb_err *e)
{
    if (create) {
        if (imdb_io_mkdirat(dirfd, IMDB_REPLICAS_DIR, 0700) == 0) {
            if (imdb_sync_dir(dirfd, e)) return -1;
        } else if (errno != EEXIST) {
            imdb_fail(e, IMDB_ERR_IO, "mkdir replicas: %s", strerror(errno));
            return -1;
        }
    }
    int fd = imdb_io_openat(dirfd, IMDB_REPLICAS_DIR, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0 && errno == ENOENT && !create) return -2;
    if (fd < 0) imdb_fail(e, IMDB_ERR_IO, "replicas/: %s", strerror(errno));
    return fd;
}

static int cmp_allow(const void *a, const void *b)
{
    return strcmp(((const imdb_allow *)a)->name, ((const imdb_allow *)b)->name);
}

int imdb_allowlist_load(int dirfd, imdb_allow **out, size_t *n, imdb_err *e)
{
    *out = NULL;
    *n = 0;
    int rfd = replicas_dir(dirfd, false, e);
    if (rfd == -2) return IMDB_OK;
    if (rfd < 0) return e->code;
    int dfd = imdb_io_openat(rfd, ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    DIR *d = dfd >= 0 ? imdb_io_fdopendir(dfd) : NULL;
    if (!d) {
        if (dfd >= 0) close(dfd);
        close(rfd);
        return imdb_fail(e, IMDB_ERR_IO, "replicas/: cannot list");
    }
    int rc = IMDB_OK;
    size_t cap = 0;
    while (!rc) {
        struct dirent *de = imdb_io_readdir(d);
        if (!de) {
            if (errno) rc = imdb_fail(e, IMDB_ERR_IO, "replicas/: directory read failed: %s", strerror(errno));
            break;
        }
        size_t len = strlen(de->d_name);
        if (len < 5 || strcmp(de->d_name + len - 4, ".pub") != 0 || !name_ok(de->d_name, len - 4)) continue;
        if (*n == IMDB_MAX_REPLICAS) {
            rc = imdb_fail(e, IMDB_ERR_LIMIT, "replicas/: more than %u replicas", IMDB_MAX_REPLICAS);
            break;
        }
        uint8_t *b = NULL;
        size_t bl = 0;
        if ((rc = imdb_read_file_at(rfd, de->d_name, &b, &bl, 65, e))) break;
        imdb_allow a;
        memset(&a, 0, sizeof a);
        memcpy(a.name, de->d_name, len - 4);
        bool ok = bl == 65 && b[64] == '\n' && imdb_unhex((const char *)b, 64, a.pub, IMDB_PUBKEY_LEN);
        free(b);
        if (!ok) {
            rc = imdb_fail(e, IMDB_ERR_CORRUPT, "replicas/%s: not a public key", de->d_name);
            break;
        }
        if (*n == cap) {
            size_t nc = cap ? 2 * cap : 8;
            imdb_allow *na = imdb_realloc_array(*out, cap, nc, sizeof *na, e);
            if (!na) {
                rc = e->code;
                break;
            }
            *out = na;
            cap = nc;
        }
        (*out)[(*n)++] = a;
    }
    closedir(d);
    close(rfd);
    if (rc) {
        free(*out);
        *out = NULL;
        *n = 0;
        return rc;
    }
    if (*n) qsort(*out, *n, sizeof **out, cmp_allow);
    for (size_t i = 0; i < *n && !rc; i++) /* replica-add never makes two names with one key */
        for (size_t j = i + 1; j < *n && !rc; j++)
            if (memcmp((*out)[i].pub, (*out)[j].pub, IMDB_PUBKEY_LEN) == 0)
                rc = imdb_fail(e, IMDB_ERR_CORRUPT, "replicas/: %s and %s hold the same key", (*out)[i].name, (*out)[j].name);
    if (rc) {
        free(*out);
        *out = NULL;
        *n = 0;
    }
    return rc;
}

static const imdb_allow *allow_find(const imdb_allow *a, size_t n, const uint8_t pub[IMDB_PUBKEY_LEN])
{
    for (size_t i = 0; i < n; i++)
        if (memcmp(a[i].pub, pub, IMDB_PUBKEY_LEN) == 0) return &a[i];
    return NULL;
}

static int unlink_quiet(int rfd, const char *name, imdb_err *e)
{
    if (imdb_io_unlinkat(rfd, name, 0) != 0 && errno != ENOENT)
        return imdb_fail(e, IMDB_ERR_IO, "replicas/%s: %s", name, strerror(errno));
    return IMDB_OK;
}

int imdb_replica_add(const char *primary, const char *name, const uint8_t pub[IMDB_PUBKEY_LEN], bool replace,
                     imdb_err *e)
{
    if (!name_ok(name, strlen(name))) return imdb_fail(e, IMDB_ERR_INVALID, "a replica name is 1 to 32 of a-z, 0-9, _ and -");
    int dirfd = imdb_io_open(primary, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (dirfd < 0) return imdb_fail(e, IMDB_ERR_IO, "open %s: %s", primary, strerror(errno));
    /* exclusive against every receipt: none overlaps the change of a binding */
    int rfd = replicas_dir(dirfd, true, e);
    int rc = rfd < 0 ? e->code : IMDB_OK;
    if (!rc && imdb_io_flock(rfd, LOCK_EX) != 0) rc = imdb_fail(e, IMDB_ERR_IO, "replicas/: lock: %s", strerror(errno));
    imdb_allow *list = NULL;
    size_t n = 0;
    if (!rc) rc = imdb_allowlist_load(dirfd, &list, &n, e);
    bool have = false;
    for (size_t i = 0; !rc && i < n; i++) {
        bool same_name = strcmp(list[i].name, name) == 0, same_key = memcmp(list[i].pub, pub, IMDB_PUBKEY_LEN) == 0;
        have |= same_name;
        if (same_key && same_name && replace) /* the incarnation is the key: only a new one clears an incident */
            rc = imdb_fail(e, IMDB_ERR_CONSTRAINT, "--replace needs a new key (imagedb replica-key REPLICA --new): %s "
                           "already has this one", name);
        else if (same_key)
            rc = imdb_fail(e, IMDB_ERR_CONSTRAINT, "that key is already allowlisted as %s", list[i].name);
        else if (same_name && !replace)
            rc = imdb_fail(e, IMDB_ERR_CONSTRAINT, "replica %s is already allowlisted (--replace gives it a new key)", name);
    }
    free(list);
    if (!rc && replace && !have) rc = imdb_fail(e, IMDB_ERR_NOTFOUND, "no replica %s to replace", name);
    char fn[IMDB_REPLICA_NAME_MAX + 16];
    if (!rc && replace) { /* the old key's record and divergence go with it */
        snprintf(fn, sizeof fn, "%s.ack", name);
        rc = unlink_quiet(rfd, fn, e);
        snprintf(fn, sizeof fn, "%s.diverged", name);
        if (!rc) rc = unlink_quiet(rfd, fn, e);
    }
    if (!rc) {
        char line[2 * IMDB_PUBKEY_LEN + 1];
        imdb_hex(pub, IMDB_PUBKEY_LEN, line);
        line[64] = '\n';
        snprintf(fn, sizeof fn, "%s.pub", name);
        rc = imdb_write_file_atomic(rfd, fn, line, 65, 0600, e);
    }
    if (rfd >= 0) close(rfd);
    close(dirfd);
    return rc;
}

/* ---- records ---------------------------------------------------------------------- */

/* A small file's exact bytes: 1 read, 0 absent or another length (a torn in-place rewrite reads
 * as absent), -1 error. */
static int read_exact(int rfd, const char *name, uint8_t *buf, size_t len, struct stat *st, imdb_err *e)
{
    int fd = imdb_io_openat(rfd, name, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) {
        if (errno == ENOENT) return 0;
        imdb_fail(e, IMDB_ERR_IO, "replicas/%s: %s", name, strerror(errno));
        return -1;
    }
    struct stat s = {0};
    ssize_t r = 0;
    int err = 0;
    if (imdb_io_fstat(fd, &s) != 0) err = errno;
    else if (S_ISREG(s.st_mode) && (uint64_t)s.st_size == len) {
        r = imdb_io_pread(fd, buf, len, 0);
        if (r < 0) err = errno;
    }
    close(fd);
    if (err) {
        imdb_fail(e, IMDB_ERR_IO, "replicas/%s: %s", name, strerror(err));
        return -1;
    }
    if (st && r == (ssize_t)len) *st = s;
    return r == (ssize_t)len ? 1 : 0;
}

static int64_t wall_ms(void)
{
    struct timespec t;
    clock_gettime(CLOCK_REALTIME, &t);
    return (int64_t)t.tv_sec * 1000 + t.tv_nsec / 1000000;
}

/* NAME.ack: the acknowledgement, when it was received, a CRC; rewritten in place like DURABLE
 * (advisory: a torn rewrite reads as no acknowledgement until the replica's next one, which it
 * sends after every commit). */
static int ack_store(int rfd, const char *name, const uint8_t raw[IMDB_ACK_LEN], int64_t received, imdb_err *e)
{
    uint8_t rec[ACK_REC];
    memcpy(rec, raw, IMDB_ACK_LEN);
    imdb_le64(rec + IMDB_ACK_LEN, (uint64_t)received);
    imdb_le32(rec + IMDB_ACK_LEN + 8, imdb_kern()->crc32c(0, rec, IMDB_ACK_LEN + 8));
    char fn[IMDB_REPLICA_NAME_MAX + 16];
    snprintf(fn, sizeof fn, "%s.ack", name);
    int fd = imdb_io_openat(rfd, fn, O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (fd < 0) return imdb_fail(e, IMDB_ERR_IO, "replicas/%s: %s", fn, strerror(errno));
    int rc = imdb_pwrite_all(fd, rec, sizeof rec, 0, e);
    close(fd);
    return rc;
}

/* NAME.ack, verified: this database's, signed by key (the name's current binding: one another key
 * left reads as none); false if absent, torn or not that. */
static bool ack_stored(int rfd, const char *name, const uint8_t db_id[16], const uint8_t key[IMDB_PUBKEY_LEN],
                       uint8_t raw[IMDB_ACK_LEN], imdb_ack *a, int64_t *received)
{
    char fn[IMDB_REPLICA_NAME_MAX + 16];
    snprintf(fn, sizeof fn, "%s.ack", name);
    uint8_t rec[ACK_REC];
    imdb_err e = {0};
    if (read_exact(rfd, fn, rec, sizeof rec, NULL, &e) != 1 ||
        imdb_kern()->crc32c(0, rec, IMDB_ACK_LEN + 8) != imdb_get_le32(rec + IMDB_ACK_LEN + 8))
        return false;
    if (imdb_ack_open(rec, a, &e) != IMDB_OK || memcmp(a->db_id, db_id, 16) != 0 ||
        memcmp(a->replica, key, IMDB_PUBKEY_LEN) != 0)
        return false;
    if (raw) memcpy(raw, rec, IMDB_ACK_LEN);
    if (received) *received = (int64_t)imdb_get_le64(rec + IMDB_ACK_LEN);
    return true;
}

int imdb_ack_receive(int dirfd, const uint8_t db_id[16], const uint8_t nonce[IMDB_NONCE_LEN], imdb_allow **allow,
                     size_t *nallow, const uint8_t raw[IMDB_ACK_LEN], imdb_hash_at_fn hash_at, void *ctx, imdb_ack *out,
                     imdb_err *e)
{
    imdb_ack a;
    if (imdb_ack_open(raw, &a, e)) return e->code;
    if (memcmp(a.db_id, db_id, 16) != 0) return imdb_fail(e, IMDB_ERR_VERIFY, "an acknowledgement for another database");
    if (memcmp(a.nonce, nonce, IMDB_NONCE_LEN) != 0)
        return imdb_fail(e, IMDB_ERR_VERIFY, "an acknowledgement signed for another shipping session (retained or replayed)");
    const imdb_allow *who = allow_find(*allow, *nallow, a.replica);
    if (!who) { /* allowlisted since this session started? */
        imdb_allow *nl;
        size_t nn;
        if (imdb_allowlist_load(dirfd, &nl, &nn, e)) return e->code;
        free(*allow);
        *allow = nl;
        *nallow = nn;
        who = allow_find(*allow, *nallow, a.replica);
    }
    if (!who) return imdb_fail(e, IMDB_ERR_AUTH, "an acknowledgement from a replica key no one allowlisted (imagedb replica-add)");
    int rfd = replicas_dir(dirfd, false, e);
    if (rfd < 0) return rfd == -2 ? imdb_fail(e, IMDB_ERR_STATE, "replicas/ disappeared") : e->code;
    char fn[IMDB_REPLICA_NAME_MAX + 16];
    int rc = IMDB_OK;
    /* Serialize receipts as well as enrollment. Otherwise two shippers can both
     * read the old watermark, then overwrite a newer receipt with an older one. */
    if (imdb_io_flock(rfd, LOCK_EX) != 0) {
        rc = imdb_fail(e, IMDB_ERR_IO, "replicas/: lock: %s", strerror(errno));
        goto out;
    }
    /* A long-running shipper may cache a key replaced by replica-add. Check
     * its current binding before writing either an ack or a sticky incident. */
    snprintf(fn, sizeof fn, "%s.pub", who->name);
    uint8_t *pub = NULL, current[IMDB_PUBKEY_LEN];
    size_t plen = 0;
    rc = imdb_read_file_at(rfd, fn, &pub, &plen, 65, e);
    if (rc == IMDB_ERR_NOTFOUND)
        rc = imdb_fail(e, IMDB_ERR_AUTH, "replica %s is no longer allowlisted", who->name);
    if (!rc && (plen != 65 || pub[64] != '\n' || !imdb_unhex((const char *)pub, 64, current, sizeof current)))
        rc = imdb_fail(e, IMDB_ERR_CORRUPT, "replicas/%s: not a public key", fn);
    if (!rc && memcmp(current, a.replica, sizeof current) != 0)
        rc = imdb_fail(e, IMDB_ERR_AUTH, "replica %s's key has been replaced", who->name);
    free(pub);
    if (rc) goto out;
    snprintf(fn, sizeof fn, "%s.diverged", who->name);
    if (imdb_io_fstatat(rfd, fn, &(struct stat){0}, AT_SYMLINK_NOFOLLOW) == 0) {
        rc = imdb_fail(e, IMDB_ERR_STATE, "replica %s has a recorded incident (replicas/%s): re-initialise it, then "
                       "imagedb replica-add --replace", who->name, fn);
        goto out;
    }
    if (errno != ENOENT) {
        rc = imdb_fail(e, IMDB_ERR_IO, "replicas/%s: cannot check divergence: %s", fn, strerror(errno));
        goto out;
    }
    uint8_t h[32];
    int k = hash_at(ctx, a.seq, h);
    if (k < 0) {
        rc = imdb_fail(e, IMDB_ERR_VERIFY, "replica %s acknowledged commit %llu, which this session has not seen",
                       who->name, (unsigned long long)a.seq);
        goto out;
    }
    imdb_refusal why = k == 0 ? IMDB_REFUSED_AHEAD : memcmp(h, a.head, 32) != 0 ? IMDB_REFUSED_HISTORY : IMDB_REFUSED_UNKNOWN;
    imdb_ack before;
    uint64_t earlier = 0;
    if (!why && ack_stored(rfd, who->name, db_id, a.replica, NULL, &before, NULL) && before.seq > a.seq) {
        why = IMDB_REFUSED_BACK; /* the same incarnation cannot unlearn a durable commit */
        earlier = before.seq;
    }
    if (why) {
        uint8_t rec[REFUSED_LEN];
        memcpy(rec, raw, IMDB_ACK_LEN);
        rec[IMDB_ACK_LEN] = (uint8_t)why;
        imdb_le64(rec + IMDB_ACK_LEN + 1, earlier);
        imdb_err ew = {0};
        if (imdb_write_file_atomic(rfd, fn, rec, sizeof rec, 0600, &ew)) {
            rc = imdb_fail(e, IMDB_ERR_IO, "replica %s was refused, but its incident record could not be persisted (%s)",
                           who->name, ew.msg);
            goto out;
        }
        if (why == IMDB_REFUSED_BACK)
            rc = imdb_fail(e, IMDB_ERR_VERIFY, "replica %s acknowledged commit %llu after %llu: it lost acknowledged commits "
                           "(restored from an older copy, or rebuilt after this primary lost them?); refused until "
                           "re-enrolled with a new key", who->name, (unsigned long long)a.seq, (unsigned long long)earlier);
        else
            rc = imdb_fail(e, IMDB_ERR_VERIFY,
                           why == IMDB_REFUSED_AHEAD ? "replica %s holds commit %llu, beyond this primary's log (commits lost "
                                                       "here in a --nosync crash, or another primary): recorded in replicas/%s"
                                                     : "replica %s holds another commit %llu: a different history, recorded "
                                                       "in replicas/%s",
                           who->name, (unsigned long long)a.seq, fn);
        goto out;
    }
    if ((rc = ack_store(rfd, who->name, raw, wall_ms(), e))) goto out;
    if (out) *out = a;
out:
    close(rfd); /* the lock with it */
    return rc;
}

/* ---- the primary's view ----------------------------------------------------------- */

static imdb_repl_state ack_state(imdb_db *db, const imdb_ack *a)
{
    if (a->seq > db->seq) return IMDB_REPL_AHEAD;
    if (imdb_writer_epoch_at(db, a->seq) != a->epoch) return IMDB_REPL_DIVERGED; /* the head fixes it: another history */
    uint8_t h[32];
    if (a->seq == 0) {
        imdb_genesis_hash(db->db_id, h);
    } else {
        imdb_err e = {0};
        const imdb_commit_info *ci = imdb_ci_at(db, a->seq, &e);
        if (!ci) return IMDB_REPL_DIVERGED; /* fail closed: a commit this log cannot show is not a match */
        memcpy(h, ci->hash, 32);
    }
    return memcmp(h, a->head, 32) == 0 ? IMDB_REPL_SAME_HISTORY : IMDB_REPL_DIVERGED;
}

static bool has_incident(int rfd, const imdb_allow *who, imdb_ack *refused, imdb_refusal *why, uint64_t *earlier)
{
    char fn[IMDB_REPLICA_NAME_MAX + 16];
    snprintf(fn, sizeof fn, "%s.diverged", who->name);
    uint8_t rec[REFUSED_LEN];
    imdb_err e = {0};
    int r = read_exact(rfd, fn, rec, sizeof rec, NULL, &e);
    imdb_ack tmp;
    bool ok = r == 1 && rec[IMDB_ACK_LEN] >= IMDB_REFUSED_HISTORY && rec[IMDB_ACK_LEN] <= IMDB_REFUSED_BACK &&
              imdb_ack_open(rec, refused ? refused : &tmp, &e) == IMDB_OK;
    if (why) *why = ok ? (imdb_refusal)rec[IMDB_ACK_LEN] : IMDB_REFUSED_UNKNOWN;
    if (earlier) *earlier = ok ? imdb_get_le64(rec + IMDB_ACK_LEN + 1) : 0;
    return r != 0 || imdb_io_fstatat(rfd, fn, &(struct stat){0}, AT_SYMLINK_NOFOLLOW) == 0;
}

int imdb_replicas_status(imdb_db *db, imdb_replica_status **out, size_t *n, imdb_err *e)
{
    *out = NULL;
    *n = 0;
    imdb_allow *list;
    size_t nl;
    if (imdb_allowlist_load(db->dirfd, &list, &nl, e)) return e->code;
    if (!nl) return IMDB_OK;
    int rfd = replicas_dir(db->dirfd, false, e);
    if (rfd < 0) {
        free(list);
        return rfd == -2 ? IMDB_OK : e->code;
    }
    imdb_replica_status *v = imdb_alloc_array(nl, sizeof *v, e);
    if (!v) {
        close(rfd);
        free(list);
        return e->code;
    }
    int64_t now = wall_ms();
    for (size_t i = 0; i < nl; i++) {
        imdb_replica_status *s = &v[i];
        s->who = list[i];
        s->age_ms = -1;
        s->acked = ack_stored(rfd, list[i].name, db->db_id, list[i].pub, NULL, &s->ack, &s->received_ms);
        if (s->acked) s->age_ms = now > s->received_ms ? now - s->received_ms : 0;
        s->incident = has_incident(rfd, &list[i], &s->refused, &s->why, &s->earlier);
        s->state = s->incident ? IMDB_REPL_DIVERGED : s->acked ? ack_state(db, &s->ack) : IMDB_REPL_NONE;
    }
    close(rfd);
    free(list);
    *out = v;
    *n = nl;
    return IMDB_OK;
}

static int64_t mono_ms(void)
{
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (int64_t)t.tv_sec * 1000 + t.tv_nsec / 1000000;
}

int imdb_replicas_wait(imdb_db *db, uint64_t seq, uint32_t k, uint32_t timeout_ms, uint32_t *got, imdb_err *e)
{
    *got = 0;
    if (!k) return IMDB_OK;
    imdb_allow *list;
    size_t nl;
    if (imdb_allowlist_load(db->dirfd, &list, &nl, e)) return e->code;
    int rfd = nl ? replicas_dir(db->dirfd, false, e) : -2;
    if (rfd == -1) {
        free(list);
        return e->code;
    }
    bool *done = nl ? imdb_alloc_array(nl, sizeof *done, e) : NULL;
    uint8_t (*last)[IMDB_ACK_LEN] = nl ? imdb_alloc_array(nl, IMDB_ACK_LEN, e) : NULL;
    int rc = nl && (!done || !last) ? e->code : IMDB_OK;
    int64_t deadline = mono_ms() + timeout_ms;
    for (size_t i = 0; !rc && rfd >= 0 && i < nl; i++) done[i] = has_incident(rfd, &list[i], NULL, NULL, NULL); /* never counted */
    uint32_t settled = 0;
    for (size_t i = 0; i < nl && done; i++) settled += done[i];
    while (!rc && rfd >= 0 && *got < k && settled < nl) {
        for (size_t i = 0; i < nl; i++) {
            if (done[i]) continue;
            uint8_t raw[IMDB_ACK_LEN];
            imdb_ack a;
            if (!ack_stored(rfd, list[i].name, db->db_id, list[i].pub, raw, &a, NULL) ||
                memcmp(raw, last[i], IMDB_ACK_LEN) == 0)
                continue;
            memcpy(last[i], raw, IMDB_ACK_LEN);
            if (a.seq >= seq && ack_state(db, &a) == IMDB_REPL_SAME_HISTORY) {
                done[i] = true;
                settled++;
                (*got)++;
            }
        }
        if (*got >= k || settled >= nl || mono_ms() >= deadline) break;
        (void)poll(NULL, 0, 1);
    }
    if (rfd >= 0) close(rfd);
    free(done);
    free(last);
    free(list);
    return rc;
}
