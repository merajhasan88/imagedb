/* Engine core: lifecycle, version store, transactions, commit. */
#include "db.h"

#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "cpu.h"
#include "db_internal.h"
#include "fsio.h"
#include "lake.h"
#include "oidx.h"
#include "logdir.h"
#include "pool.h"
#include "repl.h"
#include "writer.h"
#include "vendor/monocypher/monocypher.h"

/* ---- META / keys --------------------------------------------------------- */

#define META_NAME "META"
#define SIGNING_KEY_NAME "signing.key"

/* META pins the writer's public key (epoch 0): replicas and auditors verify every commit against
 * the keys that follow from it (log.h, WRITER_KEY), and only the primary holds signing.key. v3
 * adds the root key that may certify a promotion; without one META stays v2. */
/* Version 4, always: the db id, the role, epoch 0's writer key, the root key if any, and the digest
 * algorithm. Versions 2 and 3 (without it) are digest_alg 1, and become version 4 with "digest 1"
 * at their next rewrite. */
static int write_meta(int dirfd, const imdb_identity *id, bool replica, imdb_err *e)
{
    char hex[33], whex[65], rhex[65] = "", buf[300];
    imdb_hex(id->db_id, 16, hex);
    imdb_hex(id->writer, IMDB_PUBKEY_LEN, whex);
    if (id->has_root) imdb_hex(id->root, IMDB_PUBKEY_LEN, rhex);
    if (id->digest_alg != IMDB_DIGEST_ALG_LTHASH16 && id->digest_alg != IMDB_DIGEST_ALG_LTHASH16_TREE)
        return imdb_fail(e, IMDB_ERR_STATE, "META: no digest algorithm to record");
    int n = snprintf(buf, sizeof buf, "imagedb-meta 4\ndb_id %s\nrole %s\nwriter %s\n%s%s%sdigest %u\n", hex,
                     replica ? "replica" : "primary", whex, id->has_root ? "root " : "", rhex, id->has_root ? "\n" : "",
                     (unsigned)id->digest_alg);
    return imdb_write_file_atomic(dirfd, META_NAME, buf, (size_t)n, 0600, e);
}

/* "digest <1 or 2>\n" at r, the last line of META 4 and identity 3 */
static int meta_alg(const char **r, size_t *left, uint8_t *alg, imdb_err *e)
{
    if (*left != 9 || memcmp(*r, "digest ", 7) != 0 || (*r)[7] < '0' || (*r)[7] > '9' || (*r)[8] != '\n')
        return imdb_fail(e, IMDB_ERR_CORRUPT, "malformed digest line");
    int a = (*r)[7] - '0';
    if (a != IMDB_DIGEST_ALG_LTHASH16 && a != IMDB_DIGEST_ALG_LTHASH16_TREE)
        return imdb_fail(e, IMDB_ERR_UNSUPPORTED, "digest algorithm %d is not one this version knows", a);
    *alg = (uint8_t)a;
    *r += 9;
    *left = 0;
    return IMDB_OK;
}

/* "key <64 hex>\n" at r (left bytes there); advances past it */
static bool meta_key(const char **r, size_t *left, const char *key, uint8_t out[IMDB_PUBKEY_LEN])
{
    size_t kl = strlen(key);
    if (*left < kl + 1 + 64 + 1 || memcmp(*r, key, kl) != 0 || (*r)[kl] != ' ' ||
        !imdb_unhex(*r + kl + 1, 64, out, IMDB_PUBKEY_LEN) || (*r)[kl + 65] != '\n')
        return false;
    *r += kl + 66;
    *left -= kl + 66;
    return true;
}

static int read_meta(int dirfd, imdb_identity *id, bool *replica, imdb_err *e)
{
    uint8_t *p;
    size_t n;
    memset(id, 0, sizeof *id);
    if (imdb_read_file_at(dirfd, META_NAME, &p, &n, 4096, e)) return e->code;
    /* strict, fixed layout */
    static const char v1[] = "imagedb-meta 1\n";
    static const char a2[] = "imagedb-meta 2\ndb_id ", a3[] = "imagedb-meta 3\ndb_id ", a4[] = "imagedb-meta 4\ndb_id ";
    const char *s = (const char *)p;
    int rc = IMDB_OK;
    size_t idend = sizeof a2 - 1 + 32;
    bool v3 = n >= sizeof a3 - 1 && memcmp(s, a3, sizeof a3 - 1) == 0;
    bool v4 = n >= sizeof a4 - 1 && memcmp(s, a4, sizeof a4 - 1) == 0;
    if (n >= sizeof v1 - 1 && memcmp(s, v1, sizeof v1 - 1) == 0) {
        rc = imdb_fail(e, IMDB_ERR_UNSUPPORTED,
                       "META: imagedb-meta 1: this directory was created by imagedb v0.1 (log format 1), "
                       "which this version does not open");
    } else if (n < idend + 1 || (!v3 && !v4 && memcmp(s, a2, sizeof a2 - 1) != 0) ||
               !imdb_unhex(s + sizeof a2 - 1, 32, id->db_id, 16) || s[idend] != '\n') {
        rc = imdb_fail(e, IMDB_ERR_CORRUPT, "META: malformed");
    } else {
        const char *r = s + idend + 1;
        size_t left = n - (idend + 1);
        if (left >= 13 && memcmp(r, "role primary\n", 13) == 0) *replica = false;
        else if (left >= 13 && memcmp(r, "role replica\n", 13) == 0) *replica = true;
        else rc = imdb_fail(e, IMDB_ERR_CORRUPT, "META: malformed role");
        r += 13;
        left = left >= 13 ? left - 13 : 0;
        if (!rc && !meta_key(&r, &left, "writer", id->writer)) rc = imdb_fail(e, IMDB_ERR_CORRUPT, "META: malformed writer key");
        /* version 3 always has a root line; version 4 has one when its key begins the next line */
        bool root = v3 || (v4 && left >= 5 && memcmp(r, "root ", 5) == 0);
        if (!rc && root && !(id->has_root = meta_key(&r, &left, "root", id->root)))
            rc = imdb_fail(e, IMDB_ERR_CORRUPT, "META: malformed root key");
        id->digest_alg = IMDB_DIGEST_ALG_LTHASH16; /* versions 2 and 3 */
        imdb_err ea = {0};
        if (!rc && v4 && meta_alg(&r, &left, &id->digest_alg, &ea)) rc = imdb_fail(e, ea.code, "META: %s", ea.msg);
        if (!rc && left) rc = imdb_fail(e, IMDB_ERR_CORRUPT, "META: trailing bytes");
    }
    imdb_free(p);
    return rc;
}

/* signing.key: the writer's 32-byte Ed25519 seed. Only the primary has one (and
 * signing.key.next while a rotation or promotion is under way, writer.h). */
int imdb_seed_read(int dirfd, const char *name, imdb_signer *sg, bool *has, imdb_err *e)
{
    *has = false;
    int fd = imdb_io_openat(dirfd, name, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) {
        if (errno == ENOENT) return IMDB_OK;
        return imdb_fail(e, IMDB_ERR_IO, "%s: %s", name, strerror(errno));
    }
    struct stat st;
    if (imdb_io_fstat(fd, &st) != 0) {
        int err = errno;
        close(fd);
        return imdb_fail(e, IMDB_ERR_IO, "%s: fstat failed: %s", name, strerror(err));
    }
    if (!S_ISREG(st.st_mode) || st.st_size != IMDB_SEED_LEN) {
        close(fd);
        return imdb_fail(e, IMDB_ERR_INVALID, "%s must be a 32-byte regular file", name);
    }
    if (st.st_mode & 077) {
        close(fd);
        return imdb_fail(e, IMDB_ERR_AUTH, "%s must not be accessible by group/others (chmod 600)", name);
    }
    uint8_t seed[IMDB_SEED_LEN];
    size_t got;
    int rc = imdb_read_all(fd, seed, sizeof seed, &got, e);
    close(fd);
    if (!rc && got != sizeof seed) rc = imdb_fail(e, IMDB_ERR_INVALID, "%s: short read", name);
    if (!rc) {
        imdb_signer_init(sg, seed);
        *has = true;
    }
    imdb_wipe(seed, sizeof seed);
    return rc;
}

/* "imagedb-identity 3\ndb_id <32 hex>\nwriter <64 hex>\n", a "root <64 hex>" line when the database
 * has a root key, then "digest <1 or 2>\n": what a remote replica needs to know about its primary
 * (nothing secret), its digest algorithm included. Versions 1 (no root) and 2 (a root) predate the
 * algorithm and mean digest_alg 1. */
int imdb_identity_format(const imdb_identity *id, char *out, size_t cap)
{
    char hex[33], whex[65], rhex[65] = "";
    imdb_hex(id->db_id, 16, hex);
    imdb_hex(id->writer, IMDB_PUBKEY_LEN, whex);
    if (id->has_root) imdb_hex(id->root, IMDB_PUBKEY_LEN, rhex);
    int n = snprintf(out, cap, "imagedb-identity 3\ndb_id %s\nwriter %s\n%s%s%sdigest %u\n", hex, whex,
                     id->has_root ? "root " : "", rhex, id->has_root ? "\n" : "", (unsigned)id->digest_alg);
    return n > 0 && (size_t)n < cap ? n : -1;
}

int imdb_identity_parse(const char *s, size_t n, imdb_identity *id, imdb_err *e)
{
    static const char a1[] = "imagedb-identity 1\ndb_id ", a2[] = "imagedb-identity 2\ndb_id ",
                      a3[] = "imagedb-identity 3\ndb_id ";
    memset(id, 0, sizeof *id);
    bool v2 = n >= sizeof a2 - 1 && memcmp(s, a2, sizeof a2 - 1) == 0;
    bool v3 = n >= sizeof a3 - 1 && memcmp(s, a3, sizeof a3 - 1) == 0;
    size_t idend = sizeof a1 - 1 + 32;
    const char *r = s + idend + 1;
    size_t left = n > idend + 1 ? n - (idend + 1) : 0;
    bool ok = n >= idend + 1 && (v2 || v3 || memcmp(s, a1, sizeof a1 - 1) == 0) &&
              imdb_unhex(s + sizeof a1 - 1, 32, id->db_id, 16) && s[idend] == '\n' && meta_key(&r, &left, "writer", id->writer);
    bool root = v2 || (v3 && left >= 5 && memcmp(r, "root ", 5) == 0);
    if (ok && root) ok = id->has_root = meta_key(&r, &left, "root", id->root);
    id->digest_alg = IMDB_DIGEST_ALG_LTHASH16; /* versions 1 and 2 */
    imdb_err ea = {0};
    if (ok && v3 && meta_alg(&r, &left, &id->digest_alg, &ea))
        return imdb_fail(e, ea.code == IMDB_ERR_UNSUPPORTED ? ea.code : IMDB_ERR_INVALID, "identity: %s", ea.msg);
    if (!ok || left)
        return imdb_fail(e, IMDB_ERR_INVALID, "identity: malformed (expected imagedb-identity 1, 2 or 3: db_id, writer, root, digest)");
    return IMDB_OK;
}

int imdb_identity_read(const char *dir, imdb_identity *id, bool *replica, imdb_err *e)
{
    int dfd = imdb_io_open(dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (dfd < 0) return imdb_fail(e, IMDB_ERR_IO, "open %s: %s", dir, strerror(errno));
    bool rep;
    int rc = read_meta(dfd, id, replica ? replica : &rep, e);
    close(dfd);
    return rc;
}

int imdb_read_identity(const char *dir, uint8_t db_id[16], uint8_t writer[IMDB_PUBKEY_LEN], imdb_err *e)
{
    imdb_identity id;
    int rc = imdb_identity_read(dir, &id, NULL, e);
    if (!rc) {
        memcpy(db_id, id.db_id, 16);
        memcpy(writer, id.writer, IMDB_PUBKEY_LEN);
    }
    return rc;
}

int imdb_read_role(const char *dir, bool *replica, imdb_err *e)
{
    imdb_identity id;
    return imdb_identity_read(dir, &id, replica, e);
}

static int init_dir(const char *path, bool replica, const imdb_identity *id, const uint8_t *seed, imdb_err *e)
{
    if (imdb_io_mkdir(path, 0700) != 0 && errno != EEXIST)
        return imdb_fail(e, IMDB_ERR_IO, "mkdir %s: %s", path, strerror(errno));
    int dirfd = imdb_io_open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (dirfd < 0) return imdb_fail(e, IMDB_ERR_IO, "open %s: %s", path, strerror(errno));
    int rc = IMDB_OK;
    if (faccessat(dirfd, META_NAME, F_OK, AT_SYMLINK_NOFOLLOW) == 0) {
        rc = imdb_fail(e, IMDB_ERR_STATE, "%s is already an imagedb directory", path);
        goto out;
    }
    if (seed && (rc = imdb_create_file_excl(dirfd, SIGNING_KEY_NAME, seed, IMDB_SEED_LEN, 0600, e))) goto out;
    if (replica && (rc = imdb_replica_key_create(dirfd, e))) goto out; /* signs its acknowledgements (repl.h) */
    if (imdb_io_mkdirat(dirfd, IMDB_LOG_DIR, 0700) != 0) {
        rc = imdb_fail(e, IMDB_ERR_IO, "mkdir log: %s", strerror(errno));
        goto out;
    }
    if (imdb_io_mkdirat(dirfd, "objects", 0700) != 0 && errno != EEXIST) {
        rc = imdb_fail(e, IMDB_ERR_IO, "mkdir objects: %s", strerror(errno));
        goto out;
    }
    if (imdb_io_mkdirat(dirfd, IMDB_PINS_DIR, 0700) != 0 && errno != EEXIST) { /* lake readers' leases (lake.h) */
        rc = imdb_fail(e, IMDB_ERR_IO, "mkdir pins: %s", strerror(errno));
        goto out;
    }
    if ((rc = write_meta(dirfd, id, replica, e))) goto out;
    imdb_durable w = {.seq = 0, .synced = true}; /* nothing to ship, nothing acknowledged */
    imdb_genesis_hash(id->db_id, w.head);
    uint8_t wb[IMDB_DURABLE_LEN];
    imdb_durable_encode(&w, wb);
    if ((rc = imdb_create_file_excl(dirfd, IMDB_DURABLE_NAME, wb, sizeof wb, 0600, e))) goto out;
    rc = imdb_sync_dir(dirfd, e);
out:
    close(dirfd);
    return rc;
}

int imdb_default_digest_alg(uint8_t *alg, imdb_err *e)
{
    const char *s = getenv("IMDB_DIGEST_ALG");
    *alg = IMDB_DIGEST_ALG_LTHASH16_TREE; /* new databases: digest_alg 2 since 2026-10-26 */
    if (!s || !*s) return IMDB_OK;
    if (strcmp(s, "2") == 0) return IMDB_OK;
    if (strcmp(s, "1") == 0) {
        *alg = IMDB_DIGEST_ALG_LTHASH16;
        return IMDB_OK;
    }
    return imdb_fail(e, IMDB_ERR_INVALID, "IMDB_DIGEST_ALG is 1 or 2");
}

int imdb_init_primary(const char *path, const uint8_t *root, imdb_err *e)
{
    uint8_t alg;
    if (imdb_default_digest_alg(&alg, e)) return e->code;
    return imdb_init_primary_alg(path, root, alg, e);
}

int imdb_init_primary_alg(const char *path, const uint8_t *root, uint8_t alg, imdb_err *e)
{
    if (alg != IMDB_DIGEST_ALG_LTHASH16 && alg != IMDB_DIGEST_ALG_LTHASH16_TREE)
        return imdb_fail(e, IMDB_ERR_INVALID, "the digest algorithm is 1 or 2");
    imdb_identity id;
    memset(&id, 0, sizeof id);
    id.digest_alg = alg;
    if (root) {
        id.has_root = true;
        memcpy(id.root, root, IMDB_PUBKEY_LEN);
    }
    uint8_t seed[IMDB_SEED_LEN];
    int rc = imdb_random(id.db_id, sizeof id.db_id, e);
    if (!rc) rc = imdb_random(seed, sizeof seed, e);
    if (!rc) {
        imdb_signer sg;
        imdb_signer_init(&sg, seed);
        memcpy(id.writer, sg.pk, IMDB_PUBKEY_LEN);
        imdb_signer_wipe(&sg);
        rc = init_dir(path, false, &id, seed, e);
    }
    imdb_wipe(seed, sizeof seed);
    return rc;
}

int imdb_init(const char *path, bool replica, const char *from_primary, imdb_err *e)
{
    if (!replica) return imdb_init_primary(path, NULL, e);
    if (!from_primary) return imdb_fail(e, IMDB_ERR_INVALID, "a replica needs its primary's identity");
    imdb_identity id;
    if (imdb_identity_read(from_primary, &id, NULL, e)) return e->code;
    return init_dir(path, true, &id, NULL, e);
}

int imdb_init_replica(const char *path, const imdb_identity *id, imdb_err *e) { return init_dir(path, true, id, NULL, e); }

/* ---- tables ---------------------------------------------------------------- */

imdb_table *imdb_table_by_name(imdb_db *db, const char *name)
{
    for (uint32_t i = 0; i < db->nt; i++)
        if (strcmp(db->t[i]->s.name, name) == 0) return db->t[i];
    return NULL;
}

imdb_table *imdb_table_by_id(imdb_db *db, uint32_t id) { return id < db->nt ? db->t[id] : NULL; }

int imdb_table_new(imdb_db *db, const imdb_schema *s, imdb_err *e)
{
    if (db->nt >= IMDB_MAX_TABLES) return imdb_fail(e, IMDB_ERR_LIMIT, "too many tables");
    if (s->id != db->nt) return imdb_fail(e, IMDB_ERR_CORRUPT, "table id %u out of sequence", s->id);
    if (imdb_schema_check(s, e)) return e->code;
    if (imdb_table_by_name(db, s->name)) return imdb_fail(e, IMDB_ERR_CONSTRAINT, "table %s already exists", s->name);
    imdb_table **nt = imdb_realloc_array(db->t, db->nt, db->nt + 1, sizeof *nt, e);
    if (!nt) return e->code;
    db->t = nt;
    imdb_table *t = imdb_alloc(sizeof *t, e);
    if (!t) return e->code;
    t->s = *s;
    imdb_buf_init(&t->arena);
    if (imdb_hmap_init(&t->pk, s->cols[s->pk].type, e) ||
        (s->subject >= 0 && imdb_hmap_init(&t->subj, s->cols[s->subject].type, e))) {
        imdb_hmap_free(&t->pk);
        imdb_free(t);
        return e->code;
    }
    imdb_lthash_zero(&t->digest);
    db->t[db->nt++] = t;
    return IMDB_OK;
}

static void unique_free(struct imdb_uidx *u);
static void ver_free(imdb_table *t);

void imdb_table_free(imdb_table *t)
{
    if (!t) return;
    imdb_lake_table_free(t);
    imdb_buf_wipe_free(&t->arena);
    imdb_hmap_free(&t->pk);
    imdb_hmap_free(&t->subj);
    for (uint32_t i = 0; i < t->nsubj; i++) imdb_free(t->subj_lists[i].v);
    imdb_free(t->subj_lists);
    for (uint32_t k = 0; k < t->nidx; k++) {
        if (t->idx[k].ox) {
            imdb_oidx_free(t->idx[k].ox);
            imdb_free(t->idx[k].ox);
        }
        if (t->idx[k].ux) {
            unique_free(t->idx[k].ux);
            imdb_free(t->idx[k].ux);
        }
    }
    ver_free(t);
    imdb_free(t);
}

/* ---- version store ---------------------------------------------------------- */

/* chunk k's room: chunk 0 grows until it is whole, and only then does chunk 1 exist */
static uint64_t chunk_cap(const imdb_table *t, uint32_t k)
{
    return k == 0 && t->nchunk <= 1 ? t->capver : IMDB_VCHUNK;
}

/* Every slot of the directory, so a chunk 0 whose cold part failed to grow is freed too (its hot part
 * grew; capver did not, so only capver entries were ever used, and the rest is zeros). */
static void ver_free(imdb_table *t)
{
    for (uint32_t k = 0; k < t->capchunk; k++) {
        uint64_t n = k < t->nchunk ? chunk_cap(t, k) : 0;
        if (t->vh[k]) imdb_wipe(t->vh[k], n * sizeof(imdb_version));
        if (t->vc[k]) imdb_wipe(t->vc[k], n * sizeof(imdb_version_cold));
        imdb_free(t->vh[k]);
        imdb_free(t->vc[k]);
    }
    imdb_free(t->vh);
    imdb_free(t->vc);
    t->vh = NULL;
    t->vc = NULL;
    t->nchunk = t->capchunk = 0;
    t->nver = t->capver = 0;
}

static int dir_room(imdb_table *t, imdb_err *e)
{
    if (t->nchunk < t->capchunk) return IMDB_OK;
    uint32_t nc = t->capchunk ? t->capchunk * 2 : 4;
    if (nc < t->capchunk) return imdb_fail(e, IMDB_ERR_LIMIT, "too many versions");
    imdb_version **h = imdb_realloc_array(t->vh, t->capchunk, nc, sizeof *h, e);
    if (!h) return e->code;
    t->vh = h;
    imdb_version_cold **c = imdb_realloc_array(t->vc, t->capchunk, nc, sizeof *c, e);
    if (!c) return e->code; /* vh has the room already; a retry grows it again from the same count */
    t->vc = c;
    t->capchunk = nc;
    return IMDB_OK;
}

uint64_t imdb_ver_next_cap(const imdb_table *t)
{
    if (t->capver >= IMDB_VCHUNK) return t->capver + IMDB_VCHUNK;
    return t->capver ? (t->capver * 2 < IMDB_VCHUNK ? t->capver * 2 : IMDB_VCHUNK) : 64;
}

uint64_t imdb_ver_bytes(const imdb_table *t)
{
    return t->capver * (sizeof(imdb_version) + sizeof(imdb_version_cold)) +
           (uint64_t)t->capchunk * (sizeof *t->vh + sizeof *t->vc);
}

uint64_t imdb_ver_growth(const imdb_table *t)
{
    uint64_t g = (imdb_ver_next_cap(t) - t->capver) * (sizeof(imdb_version) + sizeof(imdb_version_cold));
    if (t->nchunk == t->capchunk && (t->capver >= IMDB_VCHUNK || !t->nchunk))
        g += (uint64_t)(t->capchunk ? t->capchunk : 4) * (sizeof *t->vh + sizeof *t->vc);
    return g;
}

/* chunk 0 to ncap entries (growing it copies only chunk 0; the old copy is wiped, as before) */
static int chunk0_grow(imdb_table *t, uint64_t ncap, imdb_err *e)
{
    if (!t->nchunk && dir_room(t, e)) return e->code;
    imdb_version *h = imdb_realloc_array(t->vh[0], t->capver, ncap, sizeof *h, e);
    if (!h) return e->code;
    t->vh[0] = h;
    imdb_version_cold *c = imdb_realloc_array(t->vc[0], t->capver, ncap, sizeof *c, e);
    if (!c) return e->code; /* the hot part has the room; capver says what is used (ver_free) */
    t->vc[0] = c;
    t->nchunk = 1;
    t->capver = ncap;
    return IMDB_OK;
}

static int chunk_add(imdb_table *t, imdb_err *e)
{
    if (dir_room(t, e)) return e->code;
    /* malloc + memset, as chunk 0 and the doubling array: resident from its allocation, so RSS follows the
     * accounting (calloc's fresh pages would become resident only as versions are written: mem_churn) */
    imdb_version *h = imdb_realloc_array(NULL, 0, IMDB_VCHUNK, sizeof *h, e);
    imdb_version_cold *c = h ? imdb_realloc_array(NULL, 0, IMDB_VCHUNK, sizeof *c, e) : NULL;
    if (!c) {
        imdb_free(h);
        return e->code;
    }
    t->vh[t->nchunk] = h;
    t->vc[t->nchunk] = c;
    t->nchunk++;
    t->capver += IMDB_VCHUNK;
    return IMDB_OK;
}

int imdb_ver_reserve(imdb_table *t, uint64_t n, imdb_err *e)
{
    if (t->nchunk || t->nver) return imdb_fail(e, IMDB_ERR_STATE, "version store not empty");
    if (n <= IMDB_VCHUNK) return chunk0_grow(t, n ? n : 1, e);
    while (t->capver < n)
        if (chunk_add(t, e)) return e->code; /* chunk 0 whole first, then whole chunks: ver_free frees each */
    return IMDB_OK;
}

int imdb_ver_push(imdb_table *t, imdb_err *e)
{
    if (t->nver == t->capver) {
        int rc = t->capver < IMDB_VCHUNK ? chunk0_grow(t, imdb_ver_next_cap(t), e) : chunk_add(t, e);
        if (rc) return rc;
    }
    imdb_version *v = imdb_vh(t, t->nver);
    memset(v, 0, sizeof *v);
    memset(imdb_vc(t, t->nver), 0, sizeof(imdb_version_cold));
    v->end = IMDB_LIVE;
    v->pk_prev = IMDB_NONE;
    t->nver++;
    return IMDB_OK;
}

const uint8_t *imdb_mem_row(const imdb_table *t, const imdb_version *v)
{
    return t->arena.p + v->row_off;
}

int imdb_version_values(imdb_db *db, imdb_table *t, uint64_t vid, imdb_value *vals, imdb_err *e)
{
    (void)db;
    if (vid >= t->nver) return imdb_fail(e, IMDB_ERR_NOTFOUND, "no such version");
    imdb_version *v = imdb_vh(t, vid);
    if (v->flags & (IMDB_V_STUB | IMDB_V_PURGED)) return imdb_fail(e, IMDB_ERR_NOTFOUND, "version erased or purged");
    if (v->flags & IMDB_V_SEG) return imdb_seg_values(t, v, vals, e);
    return imdb_row_decode(&t->s, imdb_mem_row(t, v), v->row_len, vals, e);
}

int imdb_version_key(imdb_table *t, uint64_t vid, int col, imdb_value *out)
{
    imdb_version *v = imdb_vh(t, vid);
    if (v->flags & (IMDB_V_STUB | IMDB_V_PURGED)) return IMDB_ERR_NOTFOUND;
    if (v->flags & IMDB_V_SEG) return imdb_seg_value(t, v, col, out);
    imdb_row_get(&t->s, imdb_mem_row(t, v), v->row_len, col, out);
    return IMDB_OK;
}

static uint32_t subj_list_new(imdb_table *t, imdb_err *e)
{
    if (t->nsubj == t->capsubj) {
        uint32_t ncap = t->capsubj ? t->capsubj * 2 : 64;
        imdb_vlist *nl = imdb_realloc_array(t->subj_lists, t->capsubj, ncap, sizeof *nl, e);
        if (!nl) return UINT32_MAX;
        t->subj_lists = nl;
        t->capsubj = ncap;
    }
    memset(&t->subj_lists[t->nsubj], 0, sizeof t->subj_lists[t->nsubj]);
    return t->nsubj++;
}

static int vlist_push(imdb_vlist *l, uint64_t vid, imdb_err *e)
{
    if (l->n == l->cap) {
        uint32_t ncap = l->cap ? l->cap * 2 : 4;
        uint64_t *nv = imdb_realloc_array(l->v, l->cap, ncap, sizeof *nv, e);
        if (!nv) return e->code;
        l->v = nv;
        l->cap = ncap;
    }
    l->v[l->n++] = vid;
    return IMDB_OK;
}

/* Adds a non-stub version to the key and subject indexes. */
static int unique_link(imdb_table *t, imdb_index *ix, uint64_t vid, imdb_err *e);
static void unique_unlink_newest(imdb_table *t, imdb_index *ix, uint64_t vid);

int imdb_index_version(imdb_table *t, uint64_t vid, imdb_undo *u, imdb_err *e)
{
    imdb_version *v = imdb_vh(t, vid);
    imdb_value key;
    if (imdb_version_key(t, vid, t->s.pk, &key)) return imdb_fail(e, IMDB_ERR_STATE, "index: key unavailable");
    uint64_t *head = imdb_hmap_get(&t->pk, &key);
    uint64_t prev = head ? *head : IMDB_NONE;
    v->pk_prev = prev;
    if (u) u->prev_head = prev;
    if (imdb_hmap_put(&t->pk, &key, vid, e)) return e->code;
    if (u) {
        u->subj_list = UINT32_MAX;
        u->subj_created = false;
    }
    if (t->s.subject >= 0) {
        imdb_value sv;
        imdb_version_key(t, vid, t->s.subject, &sv);
        if (imdb_index_subject(t, vid, &sv, u, e)) return e->code;
    }
    for (uint32_t k = 0; k < t->nidx; k++) /* the unique chains (the ordered structures catch up after the commit) */
        if (t->idx[k].ux && unique_link(t, &t->idx[k], vid, e)) return e->code;
    return IMDB_OK;
}

/* Appends vid to its subject's list (all versions ever written, for per-user
 * queries and ERASE SUBJECT; purged history is indexed from its tombstone). */
int imdb_index_subject(imdb_table *t, uint64_t vid, const imdb_value *sv, imdb_undo *u, imdb_err *e)
{
    uint64_t *li = imdb_hmap_get(&t->subj, sv);
    uint32_t idx;
    if (li) {
        idx = (uint32_t)*li;
    } else {
        idx = subj_list_new(t, e);
        if (idx == UINT32_MAX) return e->code;
        if (imdb_hmap_put(&t->subj, sv, idx, e)) return e->code;
        if (u) u->subj_created = true;
    }
    if (vlist_push(&t->subj_lists[idx], vid, e)) return e->code;
    if (u) u->subj_list = idx;
    return IMDB_OK;
}

/* Reverses imdb_index_version for the newest version (rollback). */
static void unindex_newest(imdb_table *t, uint64_t vid, const imdb_undo *u)
{
    imdb_value key;
    if (imdb_version_key(t, vid, t->s.pk, &key) == IMDB_OK) {
        if (u->prev_head == IMDB_NONE) imdb_hmap_del(&t->pk, &key);
        else imdb_hmap_put(&t->pk, &key, u->prev_head, NULL);
    }
    if (u->subj_list != UINT32_MAX) {
        imdb_vlist *l = &t->subj_lists[u->subj_list];
        if (l->n) l->n--;
        if (u->subj_created) {
            imdb_value sv;
            if (imdb_version_key(t, vid, t->s.subject, &sv) == IMDB_OK) imdb_hmap_del(&t->subj, &sv);
            if (u->subj_list == t->nsubj - 1) {
                imdb_free(l->v);
                memset(l, 0, sizeof *l);
                t->nsubj--;
            }
        }
    }
    for (uint32_t k = 0; k < t->nidx; k++)
        if (t->idx[k].ux) unique_unlink_newest(t, &t->idx[k], vid);
}

const imdb_vlist *imdb_subject_versions(imdb_table *t, const imdb_value *subject)
{
    /* NOT NULL column: a NULL never matches (its unused value bytes must not be read as a key) */
    if (t->s.subject < 0 || subject->null || subject->type != t->s.cols[t->s.subject].type) return NULL;
    uint64_t *li = imdb_hmap_get(&t->subj, subject);
    return li ? &t->subj_lists[*li] : NULL;
}

/* Removes a version from its key chain and subject list, then wipes its
 * payload. Used by ERASE (primary and replica alike). */
/* Takes vid out of its key's version chain; the last one out removes the
 * entry, which wipes the stored key. */
void imdb_pk_unlink(imdb_table *t, uint64_t vid, const imdb_value *key)
{
    imdb_version *v = imdb_vh(t, vid);
    uint64_t *head = imdb_hmap_get(&t->pk, key);
    if (head && *head == vid) {
        if (v->pk_prev == IMDB_NONE) imdb_hmap_del(&t->pk, key);
        else *head = v->pk_prev;
    } else if (head) {
        for (uint64_t p = *head; p != IMDB_NONE; p = imdb_vh(t, p)->pk_prev)
            if (imdb_vh(t, p)->pk_prev == vid) {
                imdb_vh(t, p)->pk_prev = v->pk_prev;
                break;
            }
    }
    v->pk_prev = IMDB_NONE;
}

/* Drops vid from its subject's list; the last one out removes the entry,
 * which wipes the stored subject value. */
static void subj_remove(imdb_table *t, const imdb_value *sv, uint64_t vid)
{
    uint64_t *li = imdb_hmap_get(&t->subj, sv);
    if (!li) return;
    imdb_vlist *l = &t->subj_lists[*li];
    for (uint32_t i = 0; i < l->n; i++)
        if (l->v[i] == vid) {
            memmove(&l->v[i], &l->v[i + 1], (l->n - i - 1) * sizeof *l->v);
            l->n--;
            break;
        }
    if (l->n == 0) {
        imdb_free(l->v);
        memset(l, 0, sizeof *l);
        imdb_hmap_del(&t->subj, sv); /* wipes the stored subject value */
    }
}

void imdb_stub_version(imdb_table *t, uint64_t vid)
{
    imdb_version *v = imdb_vh(t, vid);
    if (v->flags & IMDB_V_STUB) {
        v->flags &= (uint8_t)~IMDB_V_PENDING_AUTH;
        return;
    }
    imdb_value key;
    if ((v->flags & IMDB_V_PURGED) && t->s.subject >= 0 && (v->flags & IMDB_V_SEG)) {
        /* purged history: its tombstone still names the subject */
        imdb_value sv;
        if (imdb_seg_value(t, v, t->s.subject, &sv) == IMDB_OK) subj_remove(t, &sv, vid);
    } else if (!(v->flags & IMDB_V_PURGED) && imdb_version_key(t, vid, t->s.pk, &key) == IMDB_OK) {
        imdb_pk_unlink(t, vid, &key);
        if (t->s.subject >= 0) {
            imdb_value sv;
            imdb_version_key(t, vid, t->s.subject, &sv);
            subj_remove(t, &sv, vid);
        }
    }
    if (!(v->flags & IMDB_V_SEG) && v->row_len) imdb_wipe(t->arena.p + v->row_off, v->row_len);
    imdb_wipe(imdb_vc(t, vid)->salt, sizeof imdb_vc(t, vid)->salt);
    v->pk_prev = IMDB_NONE;
    v->flags = (uint8_t)((v->flags | IMDB_V_STUB) & ~IMDB_V_PENDING_AUTH);
}

/* ---- digest helpers ----------------------------------------------------------- */
/* Work is split into parts of at least PART_MIN elements, a few per pool
 * thread so uneven parts balance; each part sums into its own accumulator and
 * the parts are added in part order. LtHash addition is exact and
 * commutative, so the split never changes the result. */
#define PART_MIN 256u

static size_t part_count(uint64_t elements)
{
    uint64_t by_size = elements / PART_MIN, by_threads = 4ull * imdb_pool_threads();
    uint64_t n = by_size < by_threads ? by_size : by_threads;
    return n ? (size_t)n : 1;
}

typedef struct dd_part {
    const imdb_op *ops;
    uint32_t lo, hi, nt;
    imdb_lthash **delta; /* per table, lazily allocated */
    uint8_t alg;
    int err;
} dd_part;

static imdb_lthash *dd_slot(dd_part *j, uint32_t table)
{
    if (table >= j->nt) return NULL;
    if (!j->delta[table]) {
        imdb_err ge = {0};
        j->delta[table] = imdb_alloc_aligned(1, sizeof(imdb_lthash), &ge);
        if (!j->delta[table]) return NULL;
        imdb_lthash_zero(j->delta[table]);
    }
    return j->delta[table];
}

static void dd_run(void *ctx, size_t w)
{
    dd_part *j = (dd_part *)ctx + w;
    imdb_lthash el;
    for (uint32_t i = j->lo; i < j->hi; i++) {
        const imdb_op *o = &j->ops[i];
        if (o->code != IMDB_OP_INSERT && o->code != IMDB_OP_DELETE && o->code != IMDB_OP_UPDATE) continue;
        imdb_lthash *d = dd_slot(j, o->table);
        if (!d) {
            j->err = 1;
            return;
        }
        imdb_lthash_element(j->alg, o->commit, &el);
        if (o->code == IMDB_OP_INSERT) imdb_lthash_add(d, &el);
        else imdb_lthash_sub(d, &el);
        if (o->code == IMDB_OP_UPDATE) {
            imdb_lthash_element(j->alg, o->new_commit, &el);
            imdb_lthash_add(d, &el);
        }
    }
}

/* Per-table digest deltas for a list of ops; out[t] valid when touched[t]. */
int imdb_digest_delta(uint8_t alg, const imdb_op *ops, uint32_t nops, uint32_t nt, imdb_lthash *out, bool *touched,
                      imdb_err *e)
{
    size_t np = part_count(nops);
    dd_part *parts = imdb_alloc_array(np, sizeof *parts, e);
    if (!parts) return e->code;
    int rc = IMDB_OK;
    for (size_t w = 0; w < np && !rc; w++) {
        parts[w].ops = ops;
        parts[w].lo = (uint32_t)((uint64_t)nops * w / np);
        parts[w].hi = (uint32_t)((uint64_t)nops * (w + 1) / np);
        parts[w].nt = nt;
        parts[w].alg = alg;
        parts[w].delta = imdb_alloc_array(nt ? nt : 1, sizeof(imdb_lthash *), e);
        if (!parts[w].delta) rc = e->code;
    }
    if (!rc) imdb_par_for(np, dd_run, parts);
    for (uint32_t t = 0; t < nt; t++) touched[t] = false;
    for (size_t w = 0; w < np && !rc; w++) {
        if (parts[w].err) rc = imdb_fail(e, IMDB_ERR_NOMEM, "digest: out of memory");
        for (uint32_t t = 0; t < nt && !rc; t++) {
            if (!parts[w].delta[t]) continue;
            if (!touched[t]) {
                imdb_lthash_zero(&out[t]);
                touched[t] = true;
            }
            imdb_lthash_add(&out[t], parts[w].delta[t]);
        }
    }
    for (size_t w = 0; w < np; w++) {
        if (!parts[w].delta) continue;
        for (uint32_t t = 0; t < nt; t++) imdb_free(parts[w].delta[t]);
        imdb_free(parts[w].delta);
    }
    imdb_free(parts);
    return rc;
}

void imdb_state_digest(const imdb_db *db, const imdb_table *t, uint8_t out[32])
{
    imdb_lthash_digest(db->meta.digest_alg, t ? &t->digest : &db->global, out);
}

int imdb_view_token(const imdb_db *db, uint8_t out[32], imdb_err *e)
{
    imdb_sha256_ctx c;
    uint8_t b[16];
    imdb_sha256_init(&c);
    imdb_sha256_update(&c, "IMDBVIEW1", 9);
    imdb_sha256_update(&c, db->db_id, 16);
    imdb_le64(b, db->seq);
    imdb_sha256_update(&c, b, 8);
    imdb_sha256_update(&c, db->head, 32);
    imdb_le32(b, db->nt);
    imdb_sha256_update(&c, b, 4);
    imdb_buf sb;
    imdb_buf_init(&sb);
    int rc = IMDB_OK;
    for (uint32_t i = 0; i < db->nt && !rc; i++) {
        const imdb_table *t = db->t[i];
        sb.len = 0;
        imdb_schema_encode(&t->s, &sb);
        if ((rc = imdb_buf_check(&sb, e))) break;
        imdb_le32(b, t->s.id);
        imdb_le32(b + 4, (uint32_t)sb.len);
        imdb_sha256_update(&c, b, 8);
        imdb_sha256_update(&c, sb.p, sb.len);
        imdb_le64(b, t->horizon);
        imdb_le64(b + 8, t->live);
        imdb_sha256_update(&c, b, 16);
        uint8_t lanes[IMDB_LTHASH_BYTES];
        imdb_lthash_to_bytes(&t->digest, lanes);
        imdb_sha256_update(&c, lanes, sizeof lanes);
    }
    imdb_buf_free(&sb);
    if (!rc) imdb_sha256_final(&c, out);
    return rc;
}

typedef struct rc_part {
    imdb_lthash acc; /* first: parts are 32-byte aligned and 2 KiB apart */
    const imdb_table *t;
    uint64_t lo, hi, snap;
    uint8_t alg;
} rc_part;

static void rc_run(void *ctx, size_t w)
{
    rc_part *j = (rc_part *)ctx + w;
    imdb_lthash el;
    imdb_lthash_zero(&j->acc);
    for (uint64_t vid = j->lo; vid < j->hi; vid++) {
        const imdb_version *v = imdb_vh(j->t, vid);
        if (v->flags & IMDB_V_PURGED) continue;
        if (v->begin <= j->snap && j->snap < v->end) { /* stubs count: their commitment stays in the digest */
            imdb_lthash_element(j->alg, imdb_vc(j->t, vid)->commit, &el);
            imdb_lthash_add(&j->acc, &el);
        }
    }
}

/* Recomputes a table's digest from the version store alone (the apply-side
 * check: it does not trust the incremental digest maintained from headers). */
int imdb_recompute_digest(imdb_db *db, imdb_table *t, uint64_t snap, imdb_lthash *out, imdb_err *e)
{
    size_t np = part_count(t->nver);
    rc_part *parts = imdb_alloc_aligned(np, sizeof *parts, e);
    if (!parts) return e->code;
    for (size_t w = 0; w < np; w++) {
        parts[w].t = t;
        parts[w].snap = snap;
        parts[w].alg = db->meta.digest_alg;
        parts[w].lo = t->nver * w / np;
        parts[w].hi = t->nver * (w + 1) / np;
    }
    imdb_par_for(np, rc_run, parts);
    imdb_lthash_zero(out);
    for (size_t w = 0; w < np; w++) imdb_lthash_add(out, &parts[w].acc);
    imdb_free(parts);
    return IMDB_OK;
}

typedef struct cs_part {
    imdb_lthash acc;
    const uint8_t *const *ptrs;
    size_t lo, hi;
    uint8_t alg;
} cs_part;

static void cs_run(void *ctx, size_t w)
{
    cs_part *j = (cs_part *)ctx + w;
    imdb_lthash el;
    imdb_lthash_zero(&j->acc);
    for (size_t i = j->lo; i < j->hi; i++) {
        imdb_lthash_element(j->alg, j->ptrs[i], &el);
        imdb_lthash_add(&j->acc, &el);
    }
}

/* out += sum of the elements of n commitments (parallel; order-independent). */
int imdb_lthash_sum_commits(uint8_t alg, const uint8_t *const *ptrs, size_t n, imdb_lthash *out, imdb_err *e)
{
    size_t np = part_count(n);
    cs_part *parts = imdb_alloc_aligned(np, sizeof *parts, e);
    if (!parts) return e->code;
    for (size_t w = 0; w < np; w++) {
        parts[w].ptrs = ptrs;
        parts[w].alg = alg;
        parts[w].lo = n * w / np;
        parts[w].hi = n * (w + 1) / np;
    }
    imdb_par_for(np, cs_run, parts);
    for (size_t w = 0; w < np; w++) imdb_lthash_add(out, &parts[w].acc);
    imdb_free(parts);
    return IMDB_OK;
}

/* Every table's version store, recomputed, must equal its incremental digest. */
int imdb_check_state(imdb_db *db, imdb_err *e)
{
    imdb_lthash re, sum;
    imdb_lthash_zero(&sum);
    for (uint32_t i = 0; i < db->nt; i++) {
        if (imdb_recompute_digest(db, db->t[i], db->seq, &re, e)) return e->code;
        if (memcmp(&re, &db->t[i]->digest, sizeof re) != 0)
            return imdb_fail(e, IMDB_ERR_VERIFY, "state check: table %s version store disagrees with its digest",
                             db->t[i]->s.name);
        imdb_lthash_add(&sum, &re);
    }
    if (memcmp(&sum, &db->global, sizeof sum) != 0)
        return imdb_fail(e, IMDB_ERR_VERIFY, "state check: tables do not sum to the database digest");
    return IMDB_OK;
}

/* ---- commit index -------------------------------------------------------------- */
/* ci[i] describes commit ci_first + i. A snapshot open starts the index at the
 * snapshot's commit; the older entries are read from the log headers only if
 * something asks for them (AS OF TIMESTAMP, SHOW LOG). */

int imdb_ci_push(imdb_db *db, uint64_t time_us, const uint8_t hash[32], const uint8_t digest[32], imdb_err *e)
{
    if (db->nci == db->capci) {
        uint64_t ncap = db->capci ? db->capci * 2 : 256;
        imdb_commit_info *n = imdb_realloc_array(db->ci, db->capci, ncap, sizeof *n, e);
        if (!n) return e->code;
        db->ci = n;
        db->capci = ncap;
    }
    if (db->nci == 0 && db->seq == 0) db->ci_first = 1;
    imdb_commit_info *c = &db->ci[db->nci++];
    c->time_us = time_us;
    memcpy(c->hash, hash, 32);
    memcpy(c->digest, digest, 32);
    return IMDB_OK;
}

typedef struct ci_load {
    imdb_commit_info *v;
    uint64_t n, want;
} ci_load;

/* Reads commits 1 .. ci_first-1 from the log and puts them in front. */
int imdb_ci_load_all(imdb_db *db, imdb_err *e)
{
    if (db->ci_first <= 1) return IMDB_OK;
    uint64_t want = db->ci_first - 1;
    imdb_commit_info *v = imdb_alloc_array(want + db->nci, sizeof *v, e);
    if (!v) return e->code;
    uint64_t got = 0;
    uint64_t last_time = 0;
    uint8_t prev[32];
    imdb_genesis_hash(db->db_id, prev);
    int rc = IMDB_OK;
    /* The older headers are authenticated by the hash chain alone: c.hash is
     * recomputed from each header's bytes, each header names its predecessor, and
     * the walk ends at the snapshot commit, whose signature snapshot open checked
     * (ci[0]). Forging any older timestamp would need a SHA-256 second preimage,
     * so verifying every old signature here again would add ~50 us per commit to
     * the first AS OF TIMESTAMP and nothing else. */
    for (size_t si = 0; si < db->nsegs && got <= want && !rc; si++) {
        if (db->segs[si] > db->ci_first) break;
        imdb_logseg seg;
        if ((rc = imdb_logseg_load(db->logdirfd, db->segs[si], &seg, e))) break;
        const uint8_t *buf = seg.buf;
        for (size_t off = 0; got <= want;) {
            size_t flen = 0;
            imdb_err e2 = {0};
            if (imdb_logseg_scan(&seg, off, &flen, &e2) != IMDB_SCAN_FRAME) break;
            imdb_commit_rec c;
            if ((rc = imdb_frame_decode_body(buf + off + IMDB_FRAME_HDR, flen - IMDB_FRAME_HDR, &c, e))) break;
            if (c.seq != got + 1)
                rc = imdb_fail(e, IMDB_ERR_CORRUPT, "commit index: commit %llu out of sequence", (unsigned long long)c.seq);
            else if (memcmp(c.prev, prev, 32) != 0)
                rc = imdb_fail(e, IMDB_ERR_AUTH, "commit index: commit %llu is not part of the authenticated history "
                               "(hash chain broken)", (unsigned long long)c.seq);
            else if (c.time_us <= last_time)
                rc = imdb_fail(e, IMDB_ERR_CORRUPT, "commit index: commit %llu: time not increasing", (unsigned long long)c.seq);
            else if (got == want && (!db->nci || memcmp(c.hash, db->ci[0].hash, 32) != 0))
                rc = imdb_fail(e, IMDB_ERR_AUTH, "commit index: the log's history does not reach the signed snapshot commit");
            else {
                if (got < want) {
                    v[got].time_us = c.time_us;
                    memcpy(v[got].hash, c.hash, 32);
                    memcpy(v[got].digest, c.digest, 32);
                }
                memcpy(prev, c.hash, 32);
                last_time = c.time_us;
                got++;
            }
            imdb_commit_free(&c);
            if (rc) break;
            off += flen;
        }
        imdb_logseg_free(&seg);
    }
    if (!rc && got != want + 1) rc = imdb_fail(e, IMDB_ERR_CORRUPT, "commit index: the log lacks commits through %llu",
                                            (unsigned long long)db->ci_first);
    if (rc) {
        imdb_free(v);
        return rc;
    }
    if (db->nci) memcpy(v + want, db->ci, db->nci * sizeof *v);
    imdb_free(db->ci);
    db->ci = v;
    db->nci += want;
    db->capci = db->nci;
    db->ci_first = 1;
    return IMDB_OK;
}

const imdb_commit_info *imdb_ci_at(imdb_db *db, uint64_t seq, imdb_err *e)
{
    if (seq == 0 || seq > db->seq) {
        imdb_fail(e, IMDB_ERR_NOTFOUND, "no commit %llu", (unsigned long long)seq);
        return NULL;
    }
    if (seq < db->ci_first && imdb_ci_load_all(db, e)) return NULL;
    return &db->ci[seq - db->ci_first];
}

int imdb_seq_at_time(imdb_db *db, uint64_t time_us, uint64_t *seq, imdb_err *e)
{
    /* commits before ci_first are all older than ci[0]: count them without
     * loading them unless the time falls before ci[0] */
    if (db->ci_first > 1 && (db->nci == 0 || time_us < db->ci[0].time_us) && imdb_ci_load_all(db, e)) return e->code;
    uint64_t lo = 0, hi = db->nci; /* commits in the index with time <= time_us */
    while (lo < hi) {
        uint64_t mid = lo + (hi - lo) / 2;
        if (db->ci[mid].time_us <= time_us) lo = mid + 1;
        else hi = mid;
    }
    *seq = lo ? db->ci_first - 1 + lo : (db->ci_first > 1 ? db->ci_first - 1 : 0);
    return IMDB_OK;
}

uint64_t imdb_read_snapshot(const imdb_db *db) { return db->in_txn ? db->seq + 1 : db->seq; }

int imdb_check_history(const imdb_db *db, const imdb_table *t, uint64_t snap, imdb_err *e)
{
    if (db->failed || db->pending_auth || db->lake_unverified)
        return imdb_fail(e, IMDB_ERR_STATE, "database state is not ready for reads; recover or resume replica apply");
    if (snap > db->seq + (db->in_txn ? 1 : 0))
        return imdb_fail(e, IMDB_ERR_INVALID, "AS OF %llu is in the future (latest commit is %llu)",
                         (unsigned long long)snap, (unsigned long long)db->seq);
    if (t && snap < t->horizon)
        return imdb_fail(e, IMDB_ERR_HISTORY,
                         "history of %s before commit %llu was purged; AS OF %llu cannot be answered exactly",
                         t->s.name, (unsigned long long)t->horizon, (unsigned long long)snap);
    return IMDB_OK;
}

uint64_t imdb_lookup_pk_at(imdb_db *db, imdb_table *t, const imdb_value *key, uint64_t snap, uint64_t pend)
{
    (void)db;
    if (key->null || key->type != t->s.cols[t->s.pk].type) return IMDB_NONE; /* PKs are NOT NULL */
    uint64_t *head = imdb_hmap_get(&t->pk, key);
    for (uint64_t vid = head ? *head : IMDB_NONE; vid != IMDB_NONE; vid = imdb_vh(t, vid)->pk_prev)
        if (imdb_visible_at(imdb_vh(t, vid), snap, pend)) return vid;
    return IMDB_NONE;
}

uint64_t imdb_lookup_pk(imdb_db *db, imdb_table *t, const imdb_value *key, uint64_t snap)
{
    return imdb_lookup_pk_at(db, t, key, snap, 0);
}

/* ---- transactions ----------------------------------------------------------------- */

static int writable(imdb_db *db, imdb_err *e)
{
    if (db->failed) return imdb_fail(e, IMDB_ERR_STATE, "database is in a failed state; reopen it to recover");
    if (db->replica) return imdb_fail(e, IMDB_ERR_STATE, "replicas are read-only; writes arrive through apply");
    if (db->read_only) return imdb_fail(e, IMDB_ERR_STATE, "database opened read-only");
    if (!db->can_sign) return imdb_fail(e, IMDB_ERR_STATE, "no signing.key: this copy cannot sign commits");
    return IMDB_OK;
}

int imdb_begin(imdb_db *db, imdb_err *e)
{
    if (writable(db, e)) return e->code;
    if (db->in_txn) return imdb_fail(e, IMDB_ERR_STATE, "transaction already open");
    db->in_txn = true;
    db->ntx = 0;
    db->tx_bytes = 0;
    db->nundo = 0;
    return IMDB_OK;
}

static int undo_push(imdb_db *db, const imdb_undo *u, imdb_err *e)
{
    if (db->nundo == db->capundo) {
        size_t ncap = db->capundo ? db->capundo * 2 : 64;
        imdb_undo *n = imdb_realloc_array(db->undo, db->capundo, ncap, sizeof *n, e);
        if (!n) return e->code;
        db->undo = n;
        db->capundo = ncap;
    }
    db->undo[db->nundo++] = *u;
    return IMDB_OK;
}

static imdb_op *tx_push(imdb_db *db, imdb_err *e)
{
    if (db->ntx >= db->lim_txn_ops) {
        imdb_fail(e, IMDB_ERR_LIMIT, "transaction exceeds %u operations", db->lim_txn_ops);
        return NULL;
    }
    if (db->ntx == db->captx) {
        uint32_t ncap = db->captx ? db->captx * 2 : 64;
        imdb_op *n = imdb_realloc_array(db->tx, db->captx, ncap, sizeof *n, e);
        if (!n) return NULL;
        db->tx = n;
        uint64_t *o = imdb_realloc_array(db->tx_row_off, db->captx, ncap, sizeof *o, e);
        if (!o) return NULL;
        db->tx_row_off = o;
        db->captx = ncap;
    }
    imdb_op *op = &db->tx[db->ntx];
    memset(op, 0, sizeof *op);
    db->tx_row_off[db->ntx] = 0;
    db->ntx++;
    return op;
}

/* Row bytes the pending commit may still take. The bound keeps every admitted commit
 * inside one frame: an UPDATE, the largest op, adds 85 header and 21 payload bytes. */
_Static_assert((uint64_t)IMDB_MAX_TXN_BYTES + (uint64_t)IMDB_MAX_OPS_PER_COMMIT * (85 + 21) + (1u << 20) <=
                   IMDB_MAX_FRAME,
               "a transaction at its limits must fit one log frame");

static int tx_bytes_check(const imdb_db *db, size_t len, imdb_err *e)
{
    if (len > db->lim_txn_bytes - db->tx_bytes)
        return imdb_fail(e, IMDB_ERR_LIMIT, "transaction exceeds %llu bytes of row data",
                         (unsigned long long)db->lim_txn_bytes);
    return IMDB_OK;
}

static void tx_op_free(imdb_op *o)
{
    imdb_free(o->schema);
    imdb_free(o->erase);
    imdb_free(o->rewrites);
    imdb_free(o->iname);
    o->schema = NULL;
    o->erase = NULL;
    o->rewrites = NULL;
    o->iname = NULL;
}

static int index_build(imdb_table *t, imdb_index *ix, imdb_err *e);
static imdb_index_def op_def(const imdb_op *o);

static void undo_one(imdb_db *db, const imdb_undo *u)
{
    switch (u->kind) {
    case UNDO_INSERT: {
        imdb_table *t = db->t[u->table];
        if (u->vid + 1 != t->nver) break; /* LIFO invariant */
        imdb_version *v = imdb_vh(t, u->vid);
        if (!(v->flags & IMDB_V_STUB)) unindex_newest(t, u->vid, u);
        imdb_wipe(t->arena.p + u->arena_len, t->arena.len - u->arena_len);
        t->arena.len = u->arena_len;
        memset(v, 0, sizeof *v);
        t->nver--;
        t->live--;
        break;
    }
    case UNDO_END: {
        imdb_table *t = db->t[u->table];
        imdb_vh(t, u->vid)->end = IMDB_LIVE;
        imdb_seg_set_end(t, imdb_vh(t, u->vid), IMDB_LIVE);
        t->live++;
        if (t->ended) t->ended--;
        break;
    }
    case UNDO_CREATE:
        if (u->table + 1 == db->nt) {
            imdb_table_free(db->t[u->table]);
            db->nt--;
        }
        break;
    case UNDO_INDEX: { /* this transaction's CREATE INDEX: the definition goes again */
        uint32_t pos = 0;
        if (imdb_index_find(db, db->tx[u->vid].iname, &pos) == db->t[u->table]) imdb_index_remove(db->t[u->table], pos);
        break;
    }
    case UNDO_UNINDEX: { /* its DROP INDEX: the definition comes back (it was there: there is room) */
        imdb_err e2 = {0};
        imdb_table *ut = db->t[u->table];
        uint32_t at = 0;
        imdb_index_def d = op_def(&db->tx[u->vid]);
        if (imdb_index_add(ut, &d, &e2) == IMDB_OK && imdb_index_find(db, d.name, &at) == ut &&
            (index_build(ut, &ut->idx[at], &e2) != IMDB_OK || imdb_index_unique_build(ut, &ut->idx[at], &e2) != IMDB_OK))
            db->failed = true; /* the definition is back but not its structures: reopen */
        break;
    }
    }
}

imdb_savepoint imdb_savepoint_take(const imdb_db *db)
{
    imdb_savepoint sp = {db->ntx, db->nundo};
    return sp;
}

void imdb_savepoint_restore(imdb_db *db, imdb_savepoint sp)
{
    while (db->nundo > sp.nundo) undo_one(db, &db->undo[--db->nundo]);
    while (db->ntx > sp.ntx) {
        imdb_op *o = &db->tx[--db->ntx];
        if (o->code == IMDB_OP_INSERT || o->code == IMDB_OP_UPDATE) db->tx_bytes -= o->row_len;
        tx_op_free(o);
    }
}

void imdb_rollback(imdb_db *db)
{
    imdb_savepoint sp = {0, 0};
    imdb_savepoint_restore(db, sp);
    db->in_txn = false;
}

int imdb_create_table(imdb_db *db, imdb_schema *s, imdb_err *e)
{
    if (!db->in_txn) return imdb_fail(e, IMDB_ERR_STATE, "no transaction");
    s->id = db->nt;
    if (imdb_table_new(db, s, e)) return e->code;
    imdb_undo u = {.kind = UNDO_CREATE, .table = s->id};
    imdb_op *op = tx_push(db, e);
    if (!op || undo_push(db, &u, e)) {
        if (op) db->ntx--;
        imdb_table_free(db->t[--db->nt]);
        return e->code;
    }
    op->code = IMDB_OP_CREATE_TABLE;
    op->table = s->id;
    op->schema = imdb_alloc(sizeof *op->schema, e);
    if (!op->schema) {
        db->nundo--;
        db->ntx--;
        imdb_table_free(db->t[--db->nt]);
        return e->code;
    }
    *op->schema = *s;
    return IMDB_OK;
}

/* ---- CREATE INDEX / DROP INDEX: the definitions (the ordered structure is lake-independent and
 * derived, built from them) -------------------------------------------------------------------- */

imdb_table *imdb_index_find(const imdb_db *db, const char *name, uint32_t *pos)
{
    for (uint32_t i = 0; i < db->nt; i++)
        for (uint32_t k = 0; k < db->t[i]->nidx; k++)
            if (strcmp(db->t[i]->idx[k].d.name, name) == 0) {
                if (pos) *pos = k;
                return db->t[i];
            }
    return NULL;
}

bool imdb_index_def_ok(const imdb_index_def *d, uint16_t ncols)
{
    if (!d->name[0] || (d->flags & ~IMDB_INDEX_UNIQUE) || !d->ncols || d->ncols > IMDB_MAX_INDEX_COLS) return false;
    for (uint8_t i = 0; i < d->ncols; i++) {
        if (d->cols[i] >= ncols) return false;
        for (uint8_t j = 0; j < i; j++)
            if (d->cols[i] == d->cols[j]) return false;
    }
    return true;
}

int imdb_index_add(imdb_table *t, const imdb_index_def *d, imdb_err *e)
{
    if (t->nidx >= IMDB_MAX_INDEXES)
        return imdb_fail(e, IMDB_ERR_LIMIT, "table %s has %u indexes already", t->s.name, IMDB_MAX_INDEXES);
    uint32_t p = 0;
    while (p < t->nidx && strcmp(t->idx[p].d.name, d->name) < 0) p++;
    memmove(&t->idx[p + 1], &t->idx[p], (t->nidx - p) * sizeof *t->idx);
    memset(&t->idx[p], 0, sizeof t->idx[p]);
    t->idx[p].d = *d;
    t->nidx++;
    return IMDB_OK;
}

/* ---- unique indexes: each full key's chain of versions (db.h imdb_index.ux) --------------------
 * The map holds a key's newest version, prev links each version to the one before it with the
 * same key. A chain holds the versions live when the structure was built (CREATE UNIQUE INDEX, the
 * replayed op, a snapshot open, the rebuild after ERASE or a purge) and every version indexed
 * after, so no two of its versions were ever live at once (any overlap would fall where the key
 * is enforced): the newest committed version is the only one that can be live. */
typedef struct imdb_uidx {
    imdb_hmap map;
    uint64_t *prev; /* per vid: the version before it in its chain, or IMDB_NONE */
    uint64_t cap;   /* prev's entries: at least the version array's capacity */
} imdb_uidx;

static void unique_free(imdb_uidx *u)
{
    imdb_hmap_free(&u->map); /* wipes the key copies: a key may be an erased value */
    imdb_free(u->prev);
    memset(u, 0, sizeof *u);
}

void imdb_index_remove(imdb_table *t, uint32_t pos)
{
    imdb_index *ix = &t->idx[pos];
    if (ix->ox) {
        imdb_oidx_free(ix->ox);
        imdb_free(ix->ox);
    }
    if (ix->ux) {
        unique_free(ix->ux);
        imdb_free(ix->ux);
    }
    memmove(&t->idx[pos], &t->idx[pos + 1], (t->nidx - pos - 1) * sizeof *t->idx);
    t->nidx--;
    memset(&t->idx[t->nidx], 0, sizeof t->idx[t->nidx]);
}

/* the index's columns picked from a row's values (indexed by column); false: one is NULL, and a
 * NULL in any column exempts the row from the key (as SQL's UNIQUE) */
static bool ukey_vals(const imdb_index *ix, const imdb_value *row, imdb_value *v)
{
    for (uint8_t c = 0; c < ix->d.ncols; c++) {
        v[c] = row[ix->d.cols[c]];
        if (v[c].null) return false;
    }
    return true;
}

/* the same from version vid */
static bool ukey_vals_version(imdb_table *t, uint64_t vid, const imdb_index *ix, imdb_value *v)
{
    for (uint8_t c = 0; c < ix->d.ncols; c++)
        if (imdb_version_key(t, vid, ix->d.cols[c], &v[c]) != IMDB_OK || v[c].null) return false;
    return true;
}

/* The map's key for those values: one non-TEXT value as its int64, one TEXT as itself, several
 * as one byte string, their canonical encoding (each int64 in 8 bytes, each TEXT as a u32 length
 * and its bytes), built in b and checked (a short key would be another key). */
static int ukey(const imdb_index *ix, const imdb_value *v, imdb_buf *b, imdb_value *out, imdb_err *e)
{
    if (ix->d.ncols == 1) {
        *out = v[0].type == IMDB_T_TEXT ? v[0] : (imdb_value){.type = IMDB_T_INT64, .i = v[0].i};
        return IMDB_OK;
    }
    b->len = 0;
    for (uint8_t c = 0; c < ix->d.ncols; c++) {
        if (v[c].type == IMDB_T_TEXT) {
            imdb_buf_put_u32(b, v[c].len);
            imdb_buf_put(b, v[c].s, v[c].len);
        } else {
            imdb_buf_put_u64(b, (uint64_t)v[c].i);
        }
    }
    if (imdb_buf_check(b, e)) return e->code;
    *out = (imdb_value){.type = IMDB_T_TEXT, .s = b->p, .len = (uint32_t)b->len};
    return IMDB_OK;
}

/* prev's room for vid, following the version array's capacity */
static int unique_reserve(imdb_table *t, imdb_uidx *u, uint64_t vid, imdb_err *e)
{
    if (vid < u->cap) return IMDB_OK;
    uint64_t ncap = t->capver > vid ? t->capver : vid + 1;
    uint64_t *np = imdb_realloc_array(u->prev, u->cap, ncap, sizeof *np, e);
    if (!np) return e->code;
    for (uint64_t i = u->cap; i < ncap; i++) np[i] = IMDB_NONE;
    u->prev = np;
    u->cap = ncap;
    return IMDB_OK;
}

int imdb_index_unique_build(imdb_table *t, imdb_index *ix, imdb_err *e)
{
    if (!(ix->d.flags & IMDB_INDEX_UNIQUE)) return IMDB_OK;
    if (!ix->ux && !(ix->ux = imdb_alloc(sizeof *ix->ux, e))) return e->code;
    imdb_uidx *u = ix->ux;
    unique_free(u);
    uint8_t kt = ix->d.ncols == 1 && t->s.cols[ix->d.cols[0]].type != IMDB_T_TEXT ? IMDB_T_INT64 : IMDB_T_TEXT;
    if (imdb_hmap_init(&u->map, kt, e)) return e->code;
    if (unique_reserve(t, u, t->nver ? t->nver - 1 : 0, e)) return e->code;
    imdb_buf b;
    imdb_buf_init(&b);
    int rc = IMDB_OK;
    for (uint64_t vid = 0; vid < t->nver && !rc; vid++) {
        const imdb_version *v = imdb_vh(t, vid);
        imdb_value vals[IMDB_MAX_INDEX_COLS], k;
        if (v->end != IMDB_LIVE || !ukey_vals_version(t, vid, ix, vals)) continue;
        if ((rc = ukey(ix, vals, &b, &k, e))) break;
        if (imdb_hmap_get(&u->map, &k))
            rc = imdb_fail(e, IMDB_ERR_CONSTRAINT, "table %s holds a key of unique index %s twice", t->s.name, ix->d.name);
        else
            rc = imdb_hmap_put(&u->map, &k, vid, e);
    }
    imdb_buf_wipe_free(&b);
    return rc;
}

/* version vid joins its key's chain (imdb_index_version) */
static int unique_link(imdb_table *t, imdb_index *ix, uint64_t vid, imdb_err *e)
{
    imdb_uidx *u = ix->ux;
    imdb_value vals[IMDB_MAX_INDEX_COLS], k;
    if (!ukey_vals_version(t, vid, ix, vals)) return IMDB_OK;
    if (unique_reserve(t, u, vid, e)) return e->code;
    imdb_buf b;
    imdb_buf_init(&b);
    int rc = ukey(ix, vals, &b, &k, e);
    if (!rc) {
        uint64_t *head = imdb_hmap_get(&u->map, &k);
        u->prev[vid] = head ? *head : IMDB_NONE;
        rc = imdb_hmap_put(&u->map, &k, vid, e);
    }
    imdb_buf_wipe_free(&b);
    return rc;
}

/* the newest version leaves its chain again (rollback) */
static void unique_unlink_newest(imdb_table *t, imdb_index *ix, uint64_t vid)
{
    imdb_uidx *u = ix->ux;
    imdb_value vals[IMDB_MAX_INDEX_COLS], k;
    if (vid >= u->cap || !ukey_vals_version(t, vid, ix, vals)) return;
    imdb_buf b;
    imdb_buf_init(&b);
    imdb_err e2 = {0};
    if (ukey(ix, vals, &b, &k, &e2) == IMDB_OK) {
        uint64_t *head = imdb_hmap_get(&u->map, &k);
        if (head && *head == vid) {
            if (u->prev[vid] == IMDB_NONE) imdb_hmap_del(&u->map, &k);
            else *head = u->prev[vid];
        }
    }
    u->prev[vid] = IMDB_NONE;
    imdb_buf_wipe_free(&b);
}

/* A write's new row against the table's unique indexes. Only live versions block: the writer's
 * own (CONSTRAINT), a committed one it can see (CONSTRAINT) or one committed after its snapshot
 * (CONFLICT, as for the primary key, so that a retry sees it). The walk stops at the first
 * committed version that is not live: no older one in the chain is. */
static int unique_check(imdb_db *db, imdb_table *t, const uint8_t *row, size_t len, imdb_err *e)
{
    uint64_t snap = 0, pend = 0;
    imdb_txn_write_view(db, &snap, &pend);
    imdb_value rv[IMDB_MAX_COLS];
    bool decoded = false;
    int rc = IMDB_OK;
    imdb_buf b;
    imdb_buf_init(&b);
    for (uint32_t k = 0; k < t->nidx && !rc; k++) {
        imdb_index *ix = &t->idx[k];
        if (!ix->ux) continue;
        if (!decoded) {
            for (uint16_t c = 0; c < t->s.ncols; c++) imdb_row_get(&t->s, row, len, c, &rv[c]);
            decoded = true;
        }
        imdb_value vals[IMDB_MAX_INDEX_COLS], key;
        if (!ukey_vals(ix, rv, vals)) continue;
        if ((rc = ukey(ix, vals, &b, &key, e))) break;
        uint64_t *head = imdb_hmap_get(&ix->ux->map, &key);
        for (uint64_t vid = head ? *head : IMDB_NONE; vid != IMDB_NONE && !rc; vid = ix->ux->prev[vid]) {
            const imdb_version *v = imdb_vh(t, vid);
            bool own = v->begin > db->seq;
            if (v->end == IMDB_LIVE && (own || v->begin <= snap))
                rc = imdb_fail(e, IMDB_ERR_CONSTRAINT, "duplicate key in unique index %s (table %s)", ix->d.name,
                               t->s.name);
            else if (v->end == IMDB_LIVE)
                rc = imdb_fail(e, IMDB_ERR_CONFLICT,
                               "could not serialize access: a concurrent commit inserted the same key in unique index "
                               "%s; retry the transaction",
                               ix->d.name);
            else if (!own)
                break;
        }
    }
    imdb_buf_wipe_free(&b);
    return rc;
}

int imdb_index_unique_replay(imdb_table *t, const imdb_value *row, uint64_t seq, imdb_err *e)
{
    int rc = IMDB_OK;
    imdb_buf b;
    imdb_buf_init(&b);
    for (uint32_t k = 0; k < t->nidx && !rc; k++) {
        imdb_index *ix = &t->idx[k];
        imdb_value vals[IMDB_MAX_INDEX_COLS], key;
        if (!ix->ux || !ukey_vals(ix, row, vals)) continue;
        if ((rc = ukey(ix, vals, &b, &key, e))) break;
        uint64_t *head = imdb_hmap_get(&ix->ux->map, &key);
        if (head && imdb_vh(t, *head)->end == IMDB_LIVE)
            rc = imdb_fail(e, IMDB_ERR_CORRUPT, "commit %llu: a duplicate key in unique index %s (table %s)",
                           (unsigned long long)seq, ix->d.name, t->s.name);
    }
    imdb_buf_wipe_free(&b);
    return rc;
}

uint64_t imdb_index_unique_bytes(const imdb_index *ix)
{
    const imdb_uidx *u = ix->ux;
    return u ? u->map.cap * sizeof *u->map.slots + u->map.key_bytes + u->cap * sizeof *u->prev : 0;
}

bool imdb_index_key_of(const imdb_value *v, uint64_t *key)
{
    if (v->null) return false;
    if (v->type == IMDB_T_TEXT) { /* the prefix keeps the order: no TEXT holds a NUL */
        uint64_t k = 0;
        for (uint32_t i = 0; i < 8; i++) k = k << 8 | (i < v->len ? v->s[i] : 0);
        *key = k;
    } else { /* every other type is an order-preserving int64 (FLOAT64's key included) */
        *key = (uint64_t)v->i ^ (1ull << 63);
    }
    return true;
}

/* Every read the index serves has an equality or a range on its first column, which a NULL never
 * satisfies, so a version whose first column is NULL is left out. Not one whose later column is:
 * a query on the first columns alone must find it. That NULL takes the lowest word, 0, which the
 * type's lowest value (or an empty TEXT prefix) shares, so the version may be an extra candidate,
 * checked against every predicate like a TEXT prefix's; index-only never reads such a word as a
 * value (in_key in sql_exec.c). */
bool imdb_index_version_key(imdb_table *t, uint64_t vid, const imdb_index *ix, uint64_t *key)
{
    for (uint8_t c = 0; c < ix->d.ncols; c++) {
        imdb_value v;
        if (imdb_version_key(t, vid, ix->d.cols[c], &v) != IMDB_OK) return false;
        if (!imdb_index_key_of(&v, &key[c])) {
            if (c == 0) return false;
            key[c] = 0;
        }
    }
    return true;
}

/* one index's ordered structure over versions [0, idx_upto): not stubs, not purged, no NULL column */
static int index_build(imdb_table *t, imdb_index *ix, imdb_err *e)
{
    size_t w = (size_t)ix->d.ncols + 1;
    uint64_t *all = imdb_alloc_array(t->idx_upto ? t->idx_upto : 1, imdb_oidx_entry_bytes(ix->d.ncols), e);
    if (!all) return e->code;
    uint64_t n = 0;
    for (uint64_t vid = 0; vid < t->idx_upto; vid++)
        if (imdb_index_version_key(t, vid, ix, all + n * w)) all[n++ * w + ix->d.ncols] = vid;
    if (!ix->ox) {
        if (!(ix->ox = imdb_alloc(sizeof *ix->ox, e))) {
            imdb_free(all);
            return e->code;
        }
        imdb_oidx_init(ix->ox, ix->d.ncols);
    }
    return imdb_oidx_build(ix->ox, all, n, e); /* takes all over */
}

int imdb_index_build_all(imdb_db *db, imdb_err *e)
{
    for (uint32_t i = 0; i < db->nt; i++) {
        imdb_table *t = db->t[i];
        t->idx_upto = t->nver;
        for (uint32_t k = 0; k < t->nidx; k++)
            if (index_build(t, &t->idx[k], e)) return e->code;
    }
    return IMDB_OK;
}

void imdb_index_catch_up(imdb_db *db)
{
    if (db->replaying) return; /* the open builds them at its end */
    for (uint32_t i = 0; i < db->nt && !db->failed; i++) {
        imdb_table *t = db->t[i];
        for (uint64_t vid = t->idx_upto; vid < t->nver && t->nidx && !db->failed; vid++)
            for (uint32_t k = 0; k < t->nidx; k++) {
                uint64_t key[IMDB_MAX_INDEX_COLS];
                if (!imdb_index_version_key(t, vid, &t->idx[k], key)) continue;
                imdb_err e2 = {0};
                if (imdb_oidx_insert(t->idx[k].ox, key, vid, &e2)) {
                    db->failed = true;
                    snprintf(db->warning, sizeof db->warning, "index %s could not take a committed version (%s); reopen",
                             t->idx[k].d.name, e2.msg);
                    break;
                }
            }
        t->idx_upto = t->nver;
    }
}

void imdb_index_rebuild_table(imdb_db *db, imdb_table *t)
{
    /* the unique chains even in a replay: the checks after it need them, and their keys may be
     * erased values (the rebuild wipes the old map) */
    for (uint32_t k = 0; k < t->nidx && !db->failed; k++) {
        imdb_err e2 = {0};
        if (imdb_index_unique_build(t, &t->idx[k], &e2)) {
            db->failed = true;
            snprintf(db->warning, sizeof db->warning, "index %s could not be rebuilt (%s); reopen", t->idx[k].d.name,
                     e2.msg);
        }
    }
    if (db->replaying || !t->nidx) return; /* the ordered structures: the open builds them at its end */
    t->idx_upto = t->nver;
    for (uint32_t k = 0; k < t->nidx && !db->failed; k++) {
        imdb_err e2 = {0};
        if (index_build(t, &t->idx[k], &e2)) {
            db->failed = true;
            snprintf(db->warning, sizeof db->warning, "index %s could not be rebuilt (%s); reopen", t->idx[k].d.name,
                     e2.msg);
        }
    }
}

/* an index op with its undo; the definition changes now, like CREATE TABLE's, and comes back on
 * rollback (undo_one reads the definition from the op, still in db->tx then) */
static int index_op(imdb_db *db, uint8_t code, imdb_table *t, const imdb_index_def *d, imdb_err *e)
{
    imdb_op *op = tx_push(db, e);
    if (!op) return e->code;
    op->code = code;
    op->table = t->s.id;
    op->iflags = d->flags;
    op->incols = d->ncols;
    memcpy(op->icols, d->cols, sizeof op->icols);
    op->iname = imdb_alloc(IMDB_MAX_IDENT + 1, e);
    imdb_undo u = {.kind = code == IMDB_OP_CREATE_INDEX ? UNDO_INDEX : UNDO_UNINDEX, .table = t->s.id, .vid = db->ntx - 1};
    if (!op->iname || undo_push(db, &u, e)) {
        tx_op_free(op);
        db->ntx--;
        return e->code;
    }
    snprintf(op->iname, IMDB_MAX_IDENT + 1, "%s", d->name);
    return IMDB_OK;
}

/* the definition an index op carries */
static imdb_index_def op_def(const imdb_op *o)
{
    imdb_index_def d;
    memset(&d, 0, sizeof d);
    snprintf(d.name, sizeof d.name, "%s", o->iname ? o->iname : "");
    d.flags = o->iflags;
    d.ncols = o->incols;
    memcpy(d.cols, o->icols, sizeof d.cols);
    return d;
}

int imdb_create_index(imdb_db *db, imdb_table *t, const imdb_index_def *d, imdb_err *e)
{
    if (!db->in_txn) return imdb_fail(e, IMDB_ERR_STATE, "no transaction");
    if (db->ntx) return imdb_fail(e, IMDB_ERR_STATE, "CREATE INDEX commits on its own");
    size_t n = strlen(d->name);
    if (!imdb_ident_valid(d->name, n)) return imdb_fail(e, IMDB_ERR_INVALID, "invalid index name");
    for (size_t i = 0; i < n; i++)
        if (d->name[i] >= 'A' && d->name[i] <= 'Z') return imdb_fail(e, IMDB_ERR_INVALID, "index name not folded to lowercase");
    if (!imdb_index_def_ok(d, t->s.ncols))
        return imdb_fail(e, IMDB_ERR_INVALID, "an index takes 1 to %u distinct columns of table %s", IMDB_MAX_INDEX_COLS,
                         t->s.name);
    if (imdb_index_find(db, d->name, NULL)) return imdb_fail(e, IMDB_ERR_INVALID, "index %s exists already", d->name);
    if (imdb_index_add(t, d, e)) return e->code;
    uint32_t at = 0;
    imdb_index_find(db, d->name, &at);
    t->idx_upto = t->nver; /* alone in its transaction: every version is committed */
    /* the build holds the entries twice at its peak (the list, then the runs); a unique index adds
     * its map (a slot a live version, at most twice over) and the links: admitted first */
    uint64_t need = 2 * (t->nver + IMDB_OIDX_BASE) * imdb_oidx_entry_bytes(d->ncols) + sizeof(imdb_oidx);
    if (d->flags & IMDB_INDEX_UNIQUE)
        need += 4 * (t->live + 16) * sizeof(imdb_hslot) + (t->capver + 1) * sizeof(uint64_t) + sizeof(imdb_uidx);
    if (imdb_mem_admit(db, need, e)) {
        imdb_index_remove(t, at);
        return e->code;
    }
    int rc = index_build(t, &t->idx[at], e);
    if (!rc && (rc = imdb_index_unique_build(t, &t->idx[at], e)) == IMDB_ERR_CONSTRAINT)
        rc = imdb_fail(e, IMDB_ERR_CONSTRAINT, "could not create unique index %s: two live rows of table %s share a key",
                       d->name, t->s.name);
    if (rc || index_op(db, IMDB_OP_CREATE_INDEX, t, d, e)) {
        uint32_t pos = 0;
        if (imdb_index_find(db, d->name, &pos)) imdb_index_remove(t, pos);
        return e->code;
    }
    return IMDB_OK;
}

int imdb_drop_index(imdb_db *db, const char *name, imdb_err *e)
{
    if (!db->in_txn) return imdb_fail(e, IMDB_ERR_STATE, "no transaction");
    if (db->ntx) return imdb_fail(e, IMDB_ERR_STATE, "DROP INDEX commits on its own");
    uint32_t pos = 0;
    imdb_table *t = imdb_index_find(db, name, &pos);
    if (!t) return imdb_fail(e, IMDB_ERR_INVALID, "no index %s", name);
    imdb_index_def d = t->idx[pos].d;
    if (index_op(db, IMDB_OP_DROP_INDEX, t, &d, e)) return e->code;
    imdb_index_remove(t, pos);
    return IMDB_OK;
}

/* What one insert would grow, at the growth steps of the structures it appends to (a doubling
 * counts whole; conservative where a step may not come): the budget's admission (db.h). 0: it fits
 * what is held already. */
static uint64_t insert_growth(const imdb_db *db, const imdb_table *t, size_t len)
{
    uint64_t g = 0;
    if (t->nver == t->capver) g += imdb_ver_growth(t); /* chunk 0 to its next size, or a whole chunk */
    if (t->arena.len + len > t->arena.cap) {
        uint64_t c = t->arena.cap ? t->arena.cap : 256;
        while (c < (uint64_t)t->arena.len + len && c < (1ull << 62)) c *= 2;
        g += c - t->arena.cap;
    }
    if ((t->pk.count + 1) * 4 > t->pk.cap * 3) g += t->pk.cap * sizeof(imdb_hslot);
    if (t->s.subject >= 0 && (t->subj.count + 1) * 4 > t->subj.cap * 3) g += t->subj.cap * sizeof(imdb_hslot);
    if (db->nundo == db->capundo) g += (db->capundo ? db->capundo : 64) * sizeof(imdb_undo);
    if (db->ntx == db->captx) g += (db->captx ? db->captx : 16) * sizeof(imdb_op);
    for (uint32_t k = 0; k < t->nidx; k++) { /* a unique index: its links, its map, a TEXT key's copy */
        const imdb_uidx *u = t->idx[k].ux;
        if (!u) continue;
        if (t->nver >= u->cap) g += (t->capver > t->nver ? t->capver : imdb_ver_next_cap(t)) * sizeof(uint64_t);
        if ((u->map.count + 1) * 4 > u->map.cap * 3) g += u->map.cap * sizeof(imdb_hslot);
        if (u->map.ktype == IMDB_T_TEXT) g += len + 4 * IMDB_MAX_INDEX_COLS;
    }
    return g;
}

/* Appends a new pending version holding row bytes; fills undo + op payload. salt: a replayed op's, or
 * the statement's (imdb_salt_next), or NULL to draw one here (the direct API, tests). */
static int add_version(imdb_db *db, imdb_table *t, const uint8_t *row, size_t len, const uint8_t *salt,
                       uint64_t *vid_out, imdb_err *e)
{
    int rc = imdb_mem_admit(db, insert_growth(db, t, len), e); /* refused before anything moves */
    if (rc) return rc;
    imdb_undo u = {.kind = UNDO_INSERT, .table = t->s.id, .arena_len = t->arena.len};
    if (imdb_ver_push(t, e)) return e->code;
    uint64_t vid = t->nver - 1;
    imdb_version *v = imdb_vh(t, vid);
    imdb_version_cold *c = imdb_vc(t, vid);
    v->begin = db->seq + 1;
    v->row_off = t->arena.len;
    v->row_len = (uint32_t)len;
    imdb_buf_put(&t->arena, row, len);
    if (imdb_buf_check(&t->arena, e)) goto fail;
    if (salt) memcpy(c->salt, salt, 16);
    else if (imdb_random(c->salt, 16, e)) goto fail;
    imdb_row_commit(t->s.id, c->salt, row, len, c->commit);
    u.vid = vid;
    if (imdb_index_version(t, vid, &u, e)) {
        /* indexes may be half-updated (OOM): fail-stop, replay rebuilds them */
        db->failed = true;
        goto fail;
    }
    if (undo_push(db, &u, e)) {
        unindex_newest(t, vid, &u);
        goto fail;
    }
    t->live++;
    *vid_out = vid;
    return IMDB_OK;
fail:
    t->arena.err = IMDB_OK;
    t->arena.len = u.arena_len;
    t->nver--;
    return e->code;
}

static int check_live_for_write(imdb_db *db, imdb_table *t, uint64_t vid, imdb_err *e)
{
    if (vid >= t->nver) return imdb_fail(e, IMDB_ERR_NOTFOUND, "no such row version");
    imdb_version *v = imdb_vh(t, vid);
    if (v->end != IMDB_LIVE && v->end <= db->seq) /* a commit after the writer's snapshot got there first */
        return imdb_fail(e, IMDB_ERR_CONFLICT,
                         "could not serialize access: a concurrent commit changed the row; retry the transaction");
    if (v->end != IMDB_LIVE || (v->flags & (IMDB_V_STUB | IMDB_V_PURGED)))
        return imdb_fail(e, IMDB_ERR_STATE, "row version is not live");
    return IMDB_OK;
}

int imdb_salt_next(imdb_salts *s, uint8_t out[16], imdb_err *e)
{
    static const uint8_t nonce[12] = {'I', 'M', 'D', 'B', 'S', 'A', 'L', 'T', 0, 0, 0, 0};
    if (!s->seeded) {
        if (imdb_random(s->seed, sizeof s->seed, e)) return e->code;
        s->seeded = true;
        s->ctr = 0;
        s->taken = 4;
    }
    if (s->taken == 4) {
        if (s->ctr == UINT32_MAX) return imdb_fail(e, IMDB_ERR_LIMIT, "too many rows in one statement for its salts");
        crypto_chacha20_ietf(s->block, NULL, sizeof s->block, s->seed, nonce, s->ctr++);
        s->taken = 0;
    }
    memcpy(out, s->block + 16 * s->taken++, 16);
    return IMDB_OK;
}

void imdb_salts_wipe(imdb_salts *s) { imdb_wipe(s, sizeof *s); }

int imdb_insert(imdb_db *db, imdb_table *t, const imdb_value *vals, imdb_err *e)
{
    return imdb_insert_salt(db, t, vals, NULL, e);
}

int imdb_insert_salt(imdb_db *db, imdb_table *t, const imdb_value *vals, const uint8_t salt[16], imdb_err *e)
{
    if (!db->in_txn) return imdb_fail(e, IMDB_ERR_STATE, "no transaction");
    imdb_buf row;
    imdb_buf_init(&row);
    int rc = imdb_row_encode(&t->s, vals, &row, e);
    if (!rc) rc = imdb_insert_row(db, t, row.p, row.len, salt, e);
    imdb_buf_wipe_free(&row);
    return rc;
}

/* Inserts canonical row bytes (salt: as add_version's). */
int imdb_insert_row(imdb_db *db, imdb_table *t, const uint8_t *row, size_t len, const uint8_t *salt, imdb_err *e)
{
    if (!db->in_txn) return imdb_fail(e, IMDB_ERR_STATE, "no transaction");
    int rc = IMDB_OK;
    imdb_value key;
    imdb_row_get(&t->s, row, len, t->s.pk, &key);
    /* duplicate in the writer's own view (its snapshot and pending rows); held only by a
     * row committed after that snapshot: the concurrent insert won */
    uint64_t snap, pend;
    imdb_txn_write_view(db, &snap, &pend);
    uint64_t *head = imdb_hmap_get(&t->pk, &key);
    if (imdb_lookup_pk_at(db, t, &key, snap, pend) != IMDB_NONE) {
        rc = imdb_fail(e, IMDB_ERR_CONSTRAINT, "duplicate primary key in table %s (column %s)", t->s.name,
                       t->s.cols[t->s.pk].name);
        goto out;
    }
    if (head && imdb_vh(t, *head)->end == IMDB_LIVE) {
        rc = imdb_fail(e, IMDB_ERR_CONFLICT,
                       "could not serialize access: a concurrent commit inserted the same primary key in table %s; "
                       "retry the transaction",
                       t->s.name);
        goto out;
    }
    if ((rc = unique_check(db, t, row, len, e))) goto out;
    if ((rc = tx_bytes_check(db, len, e))) goto out;
    imdb_op *op = tx_push(db, e);
    if (!op) {
        rc = e->code;
        goto out;
    }
    uint64_t vid;
    if ((rc = add_version(db, t, row, len, salt, &vid, e))) {
        db->ntx--;
        goto out;
    }
    imdb_version *v = imdb_vh(t, vid);
    op->code = IMDB_OP_INSERT;
    op->table = t->s.id;
    op->vid = vid;
    memcpy(op->commit, imdb_vc(t, vid)->commit, 32);
    op->pkind = IMDB_PAYLOAD_ROW;
    memcpy(op->salt, imdb_vc(t, vid)->salt, 16);
    op->row_len = v->row_len;
    db->tx_row_off[db->ntx - 1] = v->row_off;
    db->tx_bytes += v->row_len;
out:
    return rc;
}

int imdb_delete(imdb_db *db, imdb_table *t, uint64_t vid, imdb_err *e)
{
    if (!db->in_txn) return imdb_fail(e, IMDB_ERR_STATE, "no transaction");
    if (check_live_for_write(db, t, vid, e)) return e->code;
    imdb_op *op = tx_push(db, e);
    if (!op) return e->code;
    imdb_undo u = {.kind = UNDO_END, .table = t->s.id, .vid = vid};
    if (undo_push(db, &u, e)) {
        db->ntx--;
        return e->code;
    }
    imdb_version *v = imdb_vh(t, vid);
    v->end = db->seq + 1;
    imdb_seg_set_end(t, v, v->end);
    t->live--;
    t->ended++;
    op->code = IMDB_OP_DELETE;
    op->table = t->s.id;
    op->vid = vid;
    memcpy(op->commit, imdb_vc(t, vid)->commit, 32);
    return IMDB_OK;
}

int imdb_update(imdb_db *db, imdb_table *t, uint64_t vid, const imdb_value *vals, imdb_err *e)
{
    return imdb_update_salt(db, t, vid, vals, NULL, e);
}

int imdb_update_salt(imdb_db *db, imdb_table *t, uint64_t vid, const imdb_value *vals, const uint8_t salt[16], imdb_err *e)
{
    if (!db->in_txn) return imdb_fail(e, IMDB_ERR_STATE, "no transaction");
    imdb_buf row;
    imdb_buf_init(&row);
    int rc = imdb_row_encode(&t->s, vals, &row, e);
    if (!rc) rc = imdb_update_row(db, t, vid, row.p, row.len, salt, e);
    imdb_buf_wipe_free(&row);
    return rc;
}

/* Replaces live version vid by canonical row bytes with the same primary key. */
int imdb_update_row(imdb_db *db, imdb_table *t, uint64_t vid, const uint8_t *row, size_t len, const uint8_t *salt,
                    imdb_err *e)
{
    if (!db->in_txn) return imdb_fail(e, IMDB_ERR_STATE, "no transaction");
    if (check_live_for_write(db, t, vid, e)) return e->code;
    imdb_value oldkey, newkey;
    imdb_version_key(t, vid, t->s.pk, &oldkey);
    imdb_row_get(&t->s, row, len, t->s.pk, &newkey);
    if (imdb_value_cmp(&oldkey, &newkey) != 0)
        return imdb_fail(e, IMDB_ERR_CONSTRAINT, "UPDATE cannot change the primary key (use DELETE + INSERT)");
    int rc = IMDB_OK;
    if ((rc = tx_bytes_check(db, len, e))) return rc;
    imdb_savepoint sp = imdb_savepoint_take(db);
    imdb_op *op = tx_push(db, e);
    if (!op) {
        rc = e->code;
        goto out;
    }
    imdb_undo u = {.kind = UNDO_END, .table = t->s.id, .vid = vid};
    if ((rc = undo_push(db, &u, e))) {
        db->ntx--;
        goto out;
    }
    imdb_version *old = imdb_vh(t, vid);
    old->end = db->seq + 1;
    imdb_seg_set_end(t, old, old->end);
    t->live--;
    t->ended++;
    uint64_t nvid;
    /* after the old version ended: a row that keeps its key does not collide with itself */
    if ((rc = unique_check(db, t, row, len, e)) || (rc = add_version(db, t, row, len, salt, &nvid, e))) {
        imdb_savepoint_restore(db, sp);
        goto out;
    }
    old = imdb_vh(t, vid); /* array may have moved */
    imdb_version *nv = imdb_vh(t, nvid);
    op = &db->tx[sp.ntx];
    op->code = IMDB_OP_UPDATE;
    op->table = t->s.id;
    op->vid = vid;
    memcpy(op->commit, imdb_vc(t, vid)->commit, 32);
    op->new_vid = nvid;
    memcpy(op->new_commit, imdb_vc(t, nvid)->commit, 32);
    op->pkind = IMDB_PAYLOAD_ROW;
    memcpy(op->salt, imdb_vc(t, nvid)->salt, 16);
    op->row_len = nv->row_len;
    db->tx_row_off[sp.ntx] = nv->row_off;
    db->tx_bytes += nv->row_len;
out:
    return rc;
}

/* Adds an ERASE op (entries sorted) to the open transaction; ownership of
 * ents passes to the transaction. */
int imdb_tx_add_erase(imdb_db *db, imdb_erase_ent *ents, uint32_t n, imdb_rewrite *rw, uint32_t nrw,
                      const uint8_t manifest[32], imdb_err *e)
{
    imdb_op *op = tx_push(db, e);
    if (!op) return e->code;
    op->code = IMDB_OP_ERASE;
    memcpy(op->manifest, manifest, 32);
    op->erase = ents;
    op->n_erase = n;
    op->rewrites = rw;
    op->n_rewrites = nrw;
    return IMDB_OK;
}

int imdb_tx_add_physical(imdb_db *db, uint8_t code, uint32_t table, uint64_t purge_before,
                         const uint8_t manifest[32], imdb_err *e)
{
    imdb_op *op = tx_push(db, e);
    if (!op) return e->code;
    op->code = code;
    op->table = table;
    op->purge_before = purge_before;
    memcpy(op->manifest, manifest, 32);
    return IMDB_OK;
}

int imdb_tx_add_writer(imdb_db *db, uint32_t epoch, const uint8_t new_pk[IMDB_PUBKEY_LEN], uint8_t how, imdb_err *e)
{
    if (db->ntx) return imdb_fail(e, IMDB_ERR_STATE, "WRITER_KEY is the only op of its commit");
    imdb_op *op = tx_push(db, e);
    if (!op) return e->code;
    op->code = IMDB_OP_WRITER_KEY;
    op->epoch = epoch;
    memcpy(op->new_pk, new_pk, IMDB_PUBKEY_LEN);
    op->how = how;
    return IMDB_OK;
}

int imdb_meta_write(imdb_db *db, bool replica, imdb_err *e) { return write_meta(db->dirfd, &db->meta, replica, e); }

static uint64_t now_us(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (uint64_t)ts.tv_sec * 1000000u + (uint64_t)ts.tv_nsec / 1000u;
}

uint64_t imdb_now_us(void) { return now_us(); }

static bool g_log_tagged = true; /* imdb_log_set_tagged: tests of the untagged format only */

void imdb_log_set_tagged(bool on) { g_log_tagged = on; }

/* n zero bytes at off: a tagged segment's fill. */
static int log_write_zeros(int fd, uint64_t off, uint64_t n, imdb_err *e)
{
    static uint8_t zeros[IMDB_LOG_FILL_CHUNK]; /* one write a chunk; not const: in .bss, not 1 MiB of the binary; only read */
    while (n) {
        size_t k = n < sizeof zeros ? (size_t)n : sizeof zeros;
        if (imdb_pwrite_all(fd, zeros, k, (int64_t)off, e)) return e->code;
        off += k;
        n -= k;
    }
    return IMDB_OK;
}

/* Every fdatasync of the last segment ends its open write group: the next append begins another at
 * the sector after it (design.md §3), so no flushed sector is ever rewritten. */
static void log_group_end(imdb_db *db)
{
    if (db->log_tagged && db->log_group) db->log_phys = imdb_tgroup_end(&db->log_tg);
    db->log_group = false;
}

/* Starts the segment named by the frame's seq (see logdir.h for the rule). */
static int log_new_segment(imdb_db *db, uint64_t seq, imdb_err *e)
{
    char name[IMDB_LOGSEG_NAME + 1];
    imdb_logseg_name(seq, name);
    if (db->nsegs == db->capsegs) {
        size_t nc = db->capsegs ? db->capsegs * 2 : 16;
        uint64_t *ns = imdb_realloc_array(db->segs, db->capsegs, nc, sizeof *ns, e);
        if (!ns) return e->code;
        db->segs = ns;
        db->capsegs = nc;
    }
    /* Only the last segment may end torn (log.h), so the one it follows must be whole on disk
     * first, also under --nosync: else an OS crash could keep a later segment while an earlier
     * one lost its tail, and no open could continue the chain. */
    if (db->logfd >= 0 && imdb_io_fdatasync(db->logfd) != 0) {
        db->failed = true; /* an uncertain sync: fail-stop */
        return imdb_fail(e, IMDB_ERR_IO, "fdatasync(log) before a new segment failed: %s", strerror(errno));
    }
    if (db->logfd >= 0 && db->log_tagged) {
        /* it ends: its fill goes (a truncate changes the size, so fsync); were this lost, zero sectors
         * to its end are allowed anywhere */
        log_group_end(db);
        if (imdb_io_ftruncate(db->logfd, (off_t)(db->log_phys * IMDB_TSEG_SECTOR)) != 0 || imdb_io_fsync(db->logfd) != 0) {
            db->failed = true;
            return imdb_fail(e, IMDB_ERR_IO, "cannot end log segment: %s", strerror(errno));
        }
    } else if (db->logfd < 0 && db->log_tagged && db->nsegs) {
        /* an open found it ended and left it closed (its replay synced it, durable_after_recovery): its
         * fill goes all the same, else every segment a later process ends keeps a chunk of zeros */
        char prev[IMDB_LOGSEG_NAME + 1];
        imdb_logseg_name(db->segs[db->nsegs - 1], prev);
        int pfd = imdb_io_openat(db->logdirfd, prev, O_RDWR | O_CLOEXEC | O_NOFOLLOW);
        bool ended = pfd >= 0 && imdb_io_ftruncate(pfd, (off_t)(db->log_phys * IMDB_TSEG_SECTOR)) == 0 &&
                     imdb_io_fsync(pfd) == 0;
        int err = errno;
        if (pfd >= 0) close(pfd);
        if (!ended) {
            db->failed = true;
            return imdb_fail(e, IMDB_ERR_IO, "cannot end log segment: %s", strerror(err));
        }
    }
    int fd = imdb_io_openat(db->logdirfd, name,
                            (g_log_tagged ? O_RDWR : O_WRONLY | O_APPEND) | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (fd < 0) return imdb_fail(e, IMDB_ERR_IO, "create log segment: %s", strerror(errno));
    int rc = IMDB_OK;
    if (g_log_tagged) { /* design.md §3: its header and the first fill, durable before any frame lands there */
        uint8_t h[IMDB_TSEG_SECTOR];
        imdb_tseg_header(seq, h);
        rc = imdb_pwrite_all(fd, h, sizeof h, 0, e);
        if (!rc) rc = log_write_zeros(fd, IMDB_TSEG_SECTOR, IMDB_LOG_FILL_CHUNK, e);
        if (!rc && imdb_io_fdatasync(fd) != 0) {
            db->failed = true;
            rc = imdb_fail(e, IMDB_ERR_IO, "fdatasync of a new log segment failed: %s", strerror(errno));
        }
    }
    /* the segment's name must be durable before any commit relies on it */
    if (!rc) rc = imdb_sync_dir(db->logdirfd, e);
    if (rc) {
        close(fd);
        imdb_io_unlinkat(db->logdirfd, name, 0);
        return rc;
    }
    if (db->logfd >= 0) close(db->logfd);
    db->logfd = fd;
    db->log_size = 0;
    db->log_rotate = false;
    db->log_tagged = g_log_tagged;
    db->log_group = false;
    db->log_phys = 1;
    db->log_fill = IMDB_TSEG_SECTOR + IMDB_LOG_FILL_CHUNK;
    db->segs[db->nsegs++] = seq;
    return IMDB_OK;
}

/* Rewrites DURABLE (log.h) in place. Only ever after the frames it names are
 * persisted, so it can lag the log after an OS crash (it is not fsynced per
 * append) but never lead it. */
static int durable_publish(imdb_db *db, uint64_t seq, const uint8_t head[32], bool synced, bool sync_file,
                           imdb_err *e)
{
    /* a strict handle fsyncs every record before the commits it names are acknowledged, and says so */
    imdb_durable w = {.seq = seq, .synced = synced, .strict = synced && db->strict};
    if (db->strict) sync_file = true;
    memcpy(w.head, head, 32);
    uint8_t b[IMDB_DURABLE_LEN];
    imdb_durable_encode(&w, b);
    imdb_err ew = {0};
    if (imdb_pwrite_all(db->durfd, b, sizeof b, 0, &ew)) return imdb_fail(e, IMDB_ERR_IO, "DURABLE: %s", ew.msg);
    if (sync_file && imdb_io_fsync(db->durfd) != 0) return imdb_fail(e, IMDB_ERR_IO, "DURABLE: fsync failed: %s", strerror(errno));
    db->dur = w;
    db->have_dur = true;
    return IMDB_OK;
}

/* Writable open, after replay: whatever the log holds now is accepted as
 * committed, so make it durable first (a frame a crashed writer left behind may
 * never have been synced, and --nosync segments never were), then publish. */
static int sync_log_segments(int logdirfd, const uint64_t *segs, size_t nsegs, uint64_t from, imdb_err *e)
{
    size_t start = imdb_logseg_find(segs, nsegs, from);
    for (size_t si = start < nsegs ? start : 0; si < nsegs; si++) {
        char name[IMDB_LOGSEG_NAME + 1];
        imdb_logseg_name(segs[si], name);
        int fd = imdb_io_openat(logdirfd, name, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
        int err = fd < 0 || imdb_io_fdatasync(fd) != 0 ? errno : 0;
        if (fd >= 0) close(fd);
        if (err) return imdb_fail(e, IMDB_ERR_IO, "fdatasync(log) failed: %s", strerror(err));
    }
    return IMDB_OK;
}

static int sync_segments_from(imdb_db *db, uint64_t from, imdb_err *e)
{
    return sync_log_segments(db->logdirfd, db->segs, db->nsegs, from, e);
}

static void anchor_record(const imdb_db *db, uint64_t seq, uint32_t hlen, const uint8_t hash[32], const uint8_t *sig,
                          uint8_t out[IMDB_ANCHOR_LEN])
{
    imdb_anchor a = {.seq = seq, .hlen = hlen, .epoch = imdb_writer_epoch_at(db, seq)};
    memcpy(a.db_id, db->db_id, 16);
    memcpy(a.hash, hash, 32);
    memcpy(a.sig, sig, IMDB_SIG_LEN);
    imdb_anchor_encode(&a, out);
}

/* Rewrites one record of the external anchor in place, the one the last rewrite did not touch, to
 * name commit seq (its descriptor), without an fsync of its own (sync: with one). Called only for
 * commits that are durable, so the anchor never names a commit the log could still lose: after each
 * fdatasync'd append, under --nosync at the sync points. */
static int anchor_write(imdb_db *db, uint64_t seq, uint32_t hlen, const uint8_t hash[32], const uint8_t *sig, bool sync,
                        imdb_err *e)
{
    if (db->anchorfd < 0) return IMDB_OK;
    uint8_t b[IMDB_ANCHOR_LEN];
    anchor_record(db, seq, hlen, hash, sig, b);
    imdb_err ew = {0};
    if (imdb_pwrite_all(db->anchorfd, b, sizeof b, (int64_t)db->anchor_slot * IMDB_ANCHOR_SLOT, &ew))
        return imdb_fail(e, IMDB_ERR_IO, "anchor: %s", ew.msg);
    db->anchor_slot ^= 1;
    if (sync && imdb_io_fsync(db->anchorfd) != 0) return imdb_fail(e, IMDB_ERR_IO, "anchor: fsync failed: %s", strerror(errno));
    return IMDB_OK;
}

static int anchor_publish(imdb_db *db, bool sync, imdb_err *e)
{
    return anchor_write(db, db->seq, db->last_hlen, db->head, db->last_sig, sync, e);
}

/* A new anchor, or one rewritten after an accepted rollback: both records name the current commit,
 * replaced atomically (temp, fsync, rename, fsync of the directory). */
static int anchor_create(imdb_db *db, const char *path, imdb_err *e)
{
    const char *base;
    int dfd = imdb_open_parent(path, &base, e);
    if (dfd < 0) return dfd;
    uint8_t b[IMDB_ANCHOR_FILE] = {0};
    anchor_record(db, db->seq, db->last_hlen, db->head, db->last_sig, b);
    memcpy(b + IMDB_ANCHOR_SLOT, b, IMDB_ANCHOR_LEN);
    int rc = imdb_write_file_atomic(dfd, base, b, sizeof b, 0600, e);
    close(dfd);
    return rc;
}

/* the key of an epoch this history has reached, for the anchor's records */
static const uint8_t *anchor_key(void *ctx, uint32_t epoch)
{
    const imdb_db *db = ctx;
    return epoch < db->nwep ? db->wep[epoch].k.pk : NULL;
}

/* An anchor file's n bytes: the length it must have (created whole, rewritten in place), the
 * database it must name, and its newest authentic record (log.h: epoch first), which *ahead marks
 * when its epoch is past this history. */
static int anchor_parse(imdb_db *db, const char *path, const uint8_t *b, ssize_t n, imdb_anchor *a, int *slot,
                        bool *ahead, imdb_err *e)
{
    if (n != IMDB_ANCHOR_FILE) return imdb_fail(e, IMDB_ERR_CORRUPT, "anchor %s has the wrong length (%zd bytes)", path, n);
    for (size_t off = 0; off < IMDB_ANCHOR_FILE; off += IMDB_ANCHOR_SLOT) {
        imdb_anchor r; /* first which database it names: the most useful refusal */
        imdb_err ed = {0};
        if (imdb_anchor_decode(b + off, IMDB_ANCHOR_LEN, &r, &ed) == IMDB_OK && memcmp(r.db_id, db->db_id, 16) != 0)
            return imdb_fail(e, IMDB_ERR_CORRUPT, "anchor %s belongs to another database", path);
    }
    bool bad = false;
    if (!imdb_anchor_pick(b, (size_t)n, anchor_key, db, a, slot, &bad, ahead))
        return imdb_fail(e, IMDB_ERR_CORRUPT, "anchor %s is damaged or not signed by this database's writer", path);
    return IMDB_OK;
}

/* The commit an anchor record names (seq <= db->seq) must be this history's: the same hash, signed
 * in the same epoch. A commit this directory cannot show fails closed. */
int imdb_anchor_in_history(imdb_db *db, const char *path, const imdb_anchor *a, imdb_err *e)
{
    uint8_t h[32];
    const imdb_commit_info *ci = a->seq ? imdb_ci_at(db, a->seq, e) : NULL;
    if (a->seq == 0) imdb_genesis_hash(db->db_id, h);
    else if (ci) memcpy(h, ci->hash, 32);
    if (a->seq && !ci)
        return e->code ? e->code
                       : imdb_fail(e, IMDB_ERR_CORRUPT, "the anchor %s names commit %llu, which cannot be checked", path,
                                   (unsigned long long)a->seq);
    if (a->epoch != imdb_writer_epoch_at(db, a->seq) || memcmp(h, a->hash, 32) != 0)
        return imdb_fail(e, IMDB_ERR_CORRUPT, "the anchor %s names commit %llu with another hash: a different history", path,
                         (unsigned long long)a->seq);
    return IMDB_OK;
}

/* A record naming a commit of an older epoch, past the cut the promotion to the next epoch made:
 * abandoned by that promotion, by design. */
bool imdb_anchor_abandoned(const imdb_db *db, const imdb_anchor *a)
{
    return a->epoch + 1 < db->nwep && db->wep[a->epoch + 1].promote && a->seq >= db->wep[a->epoch + 1].k.first;
}

/* Open, before recovery changes anything in the directory: the anchor, when one is given, must not
 * be ahead of the log (a directory restored from an older copy, or one that lost commits) nor name
 * another history; a record that decodes but is not the writer's is refused. *rewrite: the anchor
 * is new, or the operator accepted a rollback (anchor_start writes it whole). */
static int anchor_check(imdb_db *db, const imdb_open_opts *o, bool *rewrite, imdb_err *e)
{
    *rewrite = false;
    if (!o || !o->anchor) return IMDB_OK;
    int fd = imdb_io_open(o->anchor, (db->read_only ? O_RDONLY : O_RDWR) | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0 && errno != ENOENT) return imdb_fail(e, IMDB_ERR_IO, "anchor %s: %s", o->anchor, strerror(errno));
    uint8_t b[IMDB_ANCHOR_FILE + 1];
    ssize_t n = fd < 0 ? 0 : imdb_io_pread(fd, b, sizeof b, 0);
    int rc = n < 0 ? imdb_fail(e, IMDB_ERR_IO, "anchor %s: %s", o->anchor, strerror(errno)) : IMDB_OK;
    bool fresh = n == 0, ahead = false;
    imdb_anchor a;
    int slot = 0;
    if (!rc && !fresh) rc = anchor_parse(db, o->anchor, b, n, &a, &slot, &ahead, e);
    if (!rc && !fresh) {
        uint32_t cur = imdb_current_epoch(db);
        if (ahead && !o->accept_rollback) { /* fenced: another writer is past this copy */
            rc = imdb_fail(e, IMDB_ERR_CORRUPT,
                           "the anchor %s names commit %llu of writer epoch %u, but this directory is at epoch %u: a newer "
                           "writer (a promotion, or a rotation this copy lacks) holds it; restore the newer copy, or "
                           "continue from here with --accept-rollback", o->anchor, (unsigned long long)a.seq, a.epoch, cur);
        } else if (!ahead && imdb_anchor_abandoned(db, &a)) {
            /* the root-certified cut abandons old-epoch commits past this replica's tip; it need not catch up */
            imdb_warn(db, "the anchor named commit %llu of writer epoch %u, which the promotion at commit %llu abandoned: "
                      "the anchor follows this writer", (unsigned long long)a.seq, a.epoch,
                      (unsigned long long)db->wep[a.epoch + 1].seq);
            *rewrite = true;
        } else if ((ahead || a.seq > db->seq) && !o->accept_rollback) {
            rc = imdb_fail(e, IMDB_ERR_CORRUPT,
                           "the log ends at commit %llu, but the anchor %s names commit %llu: this directory is an older "
                           "copy or lost commits; restore the newer copy, or continue from here with --accept-rollback",
                           (unsigned long long)db->seq, o->anchor, (unsigned long long)a.seq);
        } else if (ahead || a.seq > db->seq) {
            imdb_warn(db, "rolled back from commit %llu (epoch %u) to %llu (epoch %u) (--accept-rollback): the anchor follows",
                      (unsigned long long)a.seq, a.epoch, (unsigned long long)db->seq, cur);
            *rewrite = true;
        } else {
            rc = imdb_anchor_in_history(db, o->anchor, &a, e);
        }
    }
    if (rc || db->read_only) {
        if (!rc && fresh) imdb_warn(db, "anchor %s holds nothing yet: nothing to check", o->anchor);
        if (fd >= 0) close(fd);
        return rc;
    }
    if (fresh) *rewrite = true;
    if (*rewrite) {
        if (fd >= 0) close(fd);
        return IMDB_OK;
    }
    db->anchorfd = fd;
    db->anchor_slot = slot ^ 1; /* the newest record stays intact until the next rewrite completes */
    return IMDB_OK;
}

int imdb_anchor_lock(const char *anchor, int *fd, imdb_err *e)
{
    char p[4200];
    *fd = -1;
    if (strlen(anchor) >= sizeof p - 6) return imdb_fail(e, IMDB_ERR_INVALID, "anchor path too long");
    snprintf(p, sizeof p, "%s.lock", anchor);
    int f = imdb_io_open(p, O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (f < 0) return imdb_fail(e, IMDB_ERR_IO, "anchor lock %s: %s", p, strerror(errno));
    if (imdb_io_flock(f, LOCK_EX | LOCK_NB) != 0) {
        int err = errno;
        close(f);
        if (err == EWOULDBLOCK)
            return imdb_fail(e, IMDB_ERR_STATE, "%s is held: another writer of this database is running (stop it first)", p);
        return imdb_fail(e, IMDB_ERR_IO, "anchor lock %s: %s", p, strerror(err));
    }
    *fd = f;
    return IMDB_OK;
}

int imdb_anchor_load(imdb_db *db, const char *path, imdb_anchor *a, bool *present, bool *ahead, imdb_err *e)
{
    *present = *ahead = false;
    int fd = imdb_io_open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return errno == ENOENT ? IMDB_OK : imdb_fail(e, IMDB_ERR_IO, "anchor %s: %s", path, strerror(errno));
    uint8_t b[IMDB_ANCHOR_FILE + 1];
    ssize_t n = imdb_io_pread(fd, b, sizeof b, 0);
    int err = n < 0 ? errno : 0;
    close(fd);
    if (n < 0) return imdb_fail(e, IMDB_ERR_IO, "anchor %s: %s", path, strerror(err));
    if (n == 0) return IMDB_OK; /* created, nothing written yet */
    int slot;
    if (anchor_parse(db, path, b, n, a, &slot, ahead, e)) return e->code;
    *present = true;
    return IMDB_OK;
}

/* Both records name the current commit: in place, one after the other, so a torn write costs one
 * and the file stays the one every writer sharing it reads (fencing); created whole, atomically,
 * when there is none. Leaves db->anchorfd open on it. */
static int anchor_rewrite(imdb_db *db, const char *path, imdb_err *e)
{
    db->anchorfd = imdb_io_open(path, O_RDWR | O_CLOEXEC | O_NOFOLLOW);
    if (db->anchorfd < 0 && errno != ENOENT) return imdb_fail(e, IMDB_ERR_IO, "anchor %s: %s", path, strerror(errno));
    if (db->anchorfd < 0) {
        int rc = anchor_create(db, path, e);
        if (rc) return rc;
        db->anchorfd = imdb_io_open(path, O_RDWR | O_CLOEXEC | O_NOFOLLOW);
        if (db->anchorfd < 0) return imdb_fail(e, IMDB_ERR_IO, "anchor %s: %s", path, strerror(errno));
    } else {
        db->anchor_slot = 0;
        int rc = anchor_publish(db, true, e);
        if (!rc) rc = anchor_publish(db, true, e);
        if (rc) return rc;
    }
    db->anchor_slot = 1;
    return IMDB_OK;
}

static int anchor_path_set(imdb_db *db, const char *path, imdb_err *e)
{
    size_t pl = strlen(path) + 1;
    imdb_free(db->anchor_path);
    if (!(db->anchor_path = imdb_alloc(pl, e))) return e->code;
    memcpy(db->anchor_path, path, pl);
    return IMDB_OK;
}

int imdb_anchor_adopt(imdb_db *db, const char *path, imdb_err *e)
{
    if (db->anchorfd >= 0) close(db->anchorfd);
    db->anchorfd = -1;
    if (anchor_path_set(db, path, e)) return e->code;
    return anchor_rewrite(db, path, e);
}

/* A writable open, once recovery has made every commit on disk durable (never before: the anchor
 * must not name a commit a power cut could still take): the anchor names the current commit. */
static int anchor_start(imdb_db *db, const imdb_open_opts *o, bool rewrite, imdb_err *e)
{
    if (!o || !o->anchor) return IMDB_OK;
    if (anchor_path_set(db, o->anchor, e)) return e->code;
    if (rewrite) { /* new, the operator's accepted rollback, or a commit a promotion abandoned */
        int rc = anchor_rewrite(db, o->anchor, e);
        if (!rc && !db->warning[0])
            imdb_warn(db, "anchor %s now names commit %llu", o->anchor, (unsigned long long)db->seq);
        return rc;
    }
    return anchor_publish(db, true, e);
}

int imdb_log_sync(imdb_db *db, imdb_err *e)
{
    if (!db->unsynced_from) return IMDB_OK;
    if (db->failed) return imdb_fail(e, IMDB_ERR_STATE, "database handle failed earlier; reopen to recover");
    if (sync_segments_from(db, db->unsynced_from, e)) {
        db->failed = true; /* an uncertain sync: fail-stop */
        return e->code;
    }
    log_group_end(db);
    db->unsynced_from = 0;
    imdb_err e2 = {0}; /* the commits are durable even if the watermark or the anchor cannot say so */
    if (db->have_dur) (void)durable_publish(db, db->dur.seq, db->dur.head, true, false, &e2);
    (void)anchor_publish(db, false, &e2);
    return IMDB_OK;
}

static int durable_after_recovery(imdb_db *db, imdb_err *e)
{
    int rc = sync_segments_from(db, db->have_dur && db->dur.synced ? db->dur.seq + 1 : 1, e);
    if (!rc) log_group_end(db);
    if (!rc) rc = durable_publish(db, db->seq, db->head, true, true, e);
    if (!rc) db->unsynced_from = 0;
    return rc;
}

/* An old database's untagged last segment, continued until a manifest ends it: appended. */
static int log_put_untagged(imdb_db *db, const uint8_t *frame, size_t len, imdb_err *e)
{
    off_t before = (off_t)db->log_size;
    int rc = imdb_write_all(db->logfd, frame, len, e);
    bool sync_failed = false;
    if (!rc && db->sync && imdb_io_fdatasync(db->logfd) != 0) {
        rc = imdb_fail(e, IMDB_ERR_IO, "fdatasync(log) failed: %s; reopen (the commit may or may not be there)",
                       strerror(errno));
        sync_failed = true;
    }
    if (rc) {
        /* never leave a partial frame behind; if that fails, refuse further writes. A failed
         * fdatasync stops the handle either way: the kernel may have dropped the dirty pages and
         * reported the error once, so no later sync proves this or any earlier write landed
         * (fail-stop; the next open decides from the disk, by the watermark rules). */
        if (imdb_io_ftruncate(db->logfd, before) != 0 || (db->sync && imdb_io_fdatasync(db->logfd) != 0) ||
            sync_failed)
            db->failed = true;
    }
    return rc;
}

/* A tagged segment (design.md §3): the frame's sectors overwrite the fill, the first rewritten with
 * the bytes the open group already had in it. A synchronous commit whose frame leaves less than the
 * low-water mark extends the fill before its own fdatasync (one flush for both). Nothing else does:
 * under --nosync a flush of its own would cost what the untagged log never paid (frames go past the
 * fill, as appends), and a frame larger than the low-water mark is not what the fill is for (its own
 * write dwarfs an append's metadata, and the next such frame would outgrow the fill again). A failed
 * write puts back what the sectors held. */
static int log_put_tagged(imdb_db *db, const uint8_t *frame, size_t len, imdb_err *e)
{
    uint64_t seq = imdb_frame_seq(frame);
    if (seq >= IMDB_TSEG_TOP) return imdb_fail(e, IMDB_ERR_LIMIT, "commit numbers end at 2^63");
    bool was_open = db->log_group;
    imdb_tgroup g = db->log_tg; /* as before this frame: what a failure puts back */
    if (!was_open) imdb_tgroup_begin(&g, seq, db->log_phys);
    uint64_t at = imdb_tgroup_at(&g);
    size_t ns = imdb_tgroup_sectors(&g, len), piece = ns < 2048 ? ns : 2048; /* a large frame: 1 MiB a write */
    uint64_t end = (at + ns) * IMDB_TSEG_SECTOR;
    uint8_t small[8 * IMDB_TSEG_SECTOR];
    uint8_t *buf = piece <= 8 ? small : imdb_alloc(piece * IMDB_TSEG_SECTOR, e);
    if (!buf) return e->code;
    int rc = IMDB_OK;
    for (size_t i = 0; i < ns && !rc; i += piece) {
        size_t k = ns - i < piece ? ns - i : piece;
        imdb_tgroup_fill(&g, frame, len, i, k, buf);
        rc = imdb_pwrite_all(db->logfd, buf, k * IMDB_TSEG_SECTOR, (int64_t)((at + i) * IMDB_TSEG_SECTOR), e);
    }
    uint64_t fill = end > db->log_fill ? end : db->log_fill; /* a frame past the fill grew the file */
    bool big = (uint64_t)ns * IMDB_TSEG_SECTOR > IMDB_LOG_FILL_LOW;
    bool extend = !rc && db->sync && !big && fill - end < IMDB_LOG_FILL_LOW, synced = false, sync_failed = false;
    if (extend) rc = log_write_zeros(db->logfd, fill, IMDB_LOG_FILL_CHUNK, e);
    if (!rc && db->sync) {
        if (imdb_io_fdatasync(db->logfd) != 0) {
            rc = imdb_fail(e, IMDB_ERR_IO, "fdatasync(log) failed: %s; reopen (the commit may or may not be there)",
                           strerror(errno));
            sync_failed = true;
        } else {
            synced = true;
        }
    }
    if (rc) {
        /* as in the untagged case, never a partial frame left behind, else fail-stop */
        bool back = true;
        for (size_t i = 0; i < ns && back; i += piece) {
            size_t k = ns - i < piece ? ns - i : piece;
            memset(buf, 0, k * IMDB_TSEG_SECTOR);
            if (i == 0 && was_open && g.len % IMDB_TSEG_PAYLOAD) memcpy(buf, g.last, IMDB_TSEG_SECTOR);
            imdb_err eb = {0};
            back = imdb_pwrite_all(db->logfd, buf, k * IMDB_TSEG_SECTOR, (int64_t)((at + i) * IMDB_TSEG_SECTOR), &eb) == 0;
        }
        if (!back || (db->sync && imdb_io_fdatasync(db->logfd) != 0) || sync_failed) db->failed = true;
        if (buf != small) imdb_free(buf);
        return rc;
    }
    if (buf != small) imdb_free(buf);
    db->log_fill = extend ? fill + IMDB_LOG_FILL_CHUNK : fill;
    imdb_tgroup_advance(&g, frame, len);
    db->log_tg = g;
    db->log_group = true;
    if (synced) log_group_end(db);
    return IMDB_OK;
}

int imdb_log_append(imdb_db *db, const uint8_t *frame, size_t len, imdb_err *e)
{
    if ((db->logfd < 0 || db->log_rotate) && log_new_segment(db, imdb_frame_seq(frame), e)) return e->code;
    int rc = db->log_tagged ? log_put_tagged(db, frame, len, e) : log_put_untagged(db, frame, len, e);
    if (rc) return rc;
    db->log_size += len;
    if (!db->sync && !db->unsynced_from) db->unsynced_from = imdb_frame_seq(frame);
    /* the watermark moves only now: a shipper never sees a frame that could still be truncated */
    imdb_err e2 = {0};
    if (durable_publish(db, imdb_frame_seq(frame), imdb_frame_hash(frame), db->sync != 0, false, &e2)) {
        /* the commit stands (it is in the log, synced); shipping would stall behind a stale watermark */
        db->failed = true;
        /* Under --durable-ack the acknowledgement is the synced watermark: without it there is no OK.
         * The frame stays (cutting it would need the syncs that just failed); after a crash, damage
         * to it is dropped as an append never acknowledged, which this error makes true. */
        if (db->strict)
            return imdb_fail(e, IMDB_ERR_IO, "commit %llu reached the log but is not acknowledged: %s (--durable-ack); the "
                             "handle is stopped: reopen, and the commit is there unless its frame is damaged first",
                             (unsigned long long)imdb_frame_seq(frame), e2.msg);
        snprintf(db->warning, sizeof db->warning, "commit %llu is durable, but %s; reopen to recover",
                 (unsigned long long)imdb_frame_seq(frame), e2.msg);
    }
    /* the anchor names only commits on disk: here when this one was synced, else at the next sync point */
    const uint8_t *d = frame + IMDB_FRAME_HDR;
    if (db->sync && anchor_write(db, imdb_frame_seq(frame), imdb_get_le32(d + 1), d + 13, d + 45, false, &e2)) {
        db->failed = true;
        snprintf(db->warning, sizeof db->warning, "commit %llu is durable, but %s; reopen to recover",
                 (unsigned long long)imdb_frame_seq(frame), e2.msg);
    }
    return IMDB_OK;
}

/* Automatic retention (--retain-history N; primary only, between transactions): a table that
 * has ended at least retain_min (IMDB_RETAIN_MIN_ENDED) versions since its last purge, and at
 * least as many as it holds live, gets a logged COMPACT ... PURGE of the history before the
 * last N commits, never of history an open transaction's snapshot can still read (parked ones
 * included: every open transaction is on db->txns). A purge rewrites the whole table,
 * tombstones included, so the threshold keeps it to a constant share of the updates that made
 * it due; the tombstones stay until log retirement (deferred.md R4). Replicas replay the same
 * logged purges. */
static void retain(imdb_db *db)
{
    if (!db->retain_commits || db->seq <= db->retain_commits) return;
    uint64_t floor = db->seq - db->retain_commits;
    for (const imdb_txn *x = db->txns; x; x = x->next)
        if (x->open && x->started && x->snap < floor) floor = x->snap;
    for (uint32_t i = 0; i < db->nt && !db->failed; i++) {
        imdb_table *t = db->t[i];
        if (t->ended < db->retain_min || t->ended < t->live || floor <= t->horizon) continue;
        imdb_err e2 = {0};
        if (imdb_compact(db, t, floor, &e2))
            snprintf(db->warning, sizeof db->warning, "automatic COMPACT %s PURGE failed (%s)", t->s.name, e2.msg);
    }
}

/* After an open the purges' own count is gone: every ended version a purge kept counts again,
 * so the first automatic purge may come a cycle early, never late. */
static void retain_count(imdb_db *db)
{
    for (uint32_t i = 0; i < db->nt; i++) {
        imdb_table *t = db->t[i];
        t->ended = 0;
        for (uint64_t vid = 0; vid < t->nver; vid++)
            if (imdb_vh(t, vid)->end != IMDB_LIVE && !(imdb_vh(t, vid)->flags & (IMDB_V_PURGED | IMDB_V_STUB))) t->ended++;
    }
}

/* Primary-only policy, but a logged op: once the segment passes the threshold a
 * CHECKPOINT ends it, so open replays at most about that much and replicas
 * rotate at the same commit. It runs between transactions, never inside a
 * commit, so a COMMIT reports its own commit number. */
int imdb_maintain(imdb_db *db, imdb_err *e)
{
    (void)e;
    if (db->in_txn || db->active || db->replica || db->read_only || db->failed) return IMDB_OK;
    retain(db); /* first: a purge publishes the lake and ends the segment, so no CHECKPOINT is then due */
    if (db->failed) return IMDB_OK;
    /* synchronous publication: the lake files then answer at the latest commit too (one more commit and a
     * lake publication per change: the price is measured in docs/plan-round3.md) */
    bool due = db->checkpoint_bytes && db->log_size >= db->checkpoint_bytes && !db->log_rotate && db->nt;
    if (due || (db->lake_sync && db->lake_dirty && db->nt)) {
        imdb_err e2 = {0};
        if (imdb_checkpoint(db, &e2))
            snprintf(db->warning, sizeof db->warning, "automatic CHECKPOINT failed (%s)", e2.msg);
    }
    return IMDB_OK;
}

/* Builds, appends and installs the open transaction as one commit. */
/* Before each commit, check that the anchor is readable and authentic for known epochs;
 * a newer epoch's unknown key makes us stop too. This detects an already published promotion,
 * but the read and commit are not atomic: exclusive fencing needs coordination outside this check. */
static int anchor_fenced(imdb_db *db, imdb_err *e)
{
    if (db->anchorfd < 0 || !db->anchor_path) return IMDB_OK;
    uint8_t b[IMDB_ANCHOR_FILE + 1];
    int fd = imdb_io_open(db->anchor_path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW); /* whatever file is there now */
    ssize_t n = fd < 0 ? -1 : imdb_io_pread(fd, b, sizeof b, 0);
    if (fd >= 0) close(fd);
    if (n != IMDB_ANCHOR_FILE) {
        db->failed = true;
        return imdb_fail(e, IMDB_ERR_IO, "fenced: cannot read the complete anchor; reopen to recover");
    }
    uint32_t cur = imdb_current_epoch(db);
    bool valid = false;
    for (size_t off = 0; off < IMDB_ANCHOR_FILE; off += IMDB_ANCHOR_SLOT) {
        imdb_anchor a;
        imdb_err ed = {0};
        if (imdb_anchor_decode(b + off, IMDB_ANCHOR_LEN, &a, &ed)) continue; /* the other slot may be intact */
        if (memcmp(a.db_id, db->db_id, 16) != 0) {
            db->failed = true;
            return imdb_fail(e, IMDB_ERR_AUTH, "fenced: anchor belongs to another database");
        }
        if (a.epoch > cur) {
            db->failed = true;
            return imdb_fail(e, IMDB_ERR_STATE, "fenced: the anchor names writer epoch %u, newer than this writer's %u "
                             "(another writer was promoted); this handle stops", a.epoch, cur);
        }
        if (!imdb_anchor_authentic(&a, db->wep[a.epoch].k.pk)) {
            db->failed = true;
            return imdb_fail(e, IMDB_ERR_AUTH, "fenced: anchor signature is invalid");
        }
        valid = true;
    }
    if (!valid) {
        db->failed = true;
        return imdb_fail(e, IMDB_ERR_CORRUPT, "fenced: anchor has no intact record");
    }
    return IMDB_OK;
}

int imdb_commit(imdb_db *db, imdb_err *e)
{
    if (!db->in_txn) return imdb_fail(e, IMDB_ERR_STATE, "no transaction");
    if (db->ntx == 0) {
        db->in_txn = false;
        db->nundo = 0;
        return IMDB_OK;
    }
    int frc = anchor_fenced(db, e);
    /* the commit index doubles now and then: a commit that writes rows is refused here, before
     * anything is logged; deletions and the physical ops (the ways down) never are */
    bool grows = false;
    for (uint32_t i = 0; i < db->ntx; i++) grows |= db->tx[i].code == IMDB_OP_INSERT || db->tx[i].code == IMDB_OP_UPDATE;
    if (!frc && grows && db->nci == db->capci)
        frc = imdb_mem_admit(db, (db->capci ? db->capci : 256) * sizeof(imdb_commit_info), e);
    /* the ordered indexes take the new versions once the commit is durable: what that allocates,
     * every carry counted whole, is admitted here instead, before anything is logged */
    for (uint32_t i = 0; !frc && grows && db->mem_limit && i < db->nt; i++) {
        const imdb_table *t = db->t[i];
        uint64_t k = t->nver > t->idx_upto ? t->nver - t->idx_upto : 0, g = 0;
        for (uint32_t j = 0; k && j < t->nidx; j++)
            if (t->idx[j].ox) g += imdb_oidx_growth(t->idx[j].ox, k);
        if (g) frc = imdb_mem_admit(db, g, e);
    }
    if (frc) {
        imdb_rollback(db);
        return frc;
    }
    int rc = IMDB_OK;
    imdb_buf hdr, pay, frame;
    imdb_buf_init(&hdr);
    imdb_buf_init(&pay);
    imdb_buf_init(&frame);
    imdb_lthash *delta = imdb_alloc_aligned(db->nt ? db->nt : 1, sizeof *delta, e);
    bool *touched = imdb_alloc_array(db->nt ? db->nt : 1, sizeof *touched, e);
    if (!delta || !touched) {
        rc = e->code;
        goto fail;
    }
    for (uint32_t i = 0; i < db->ntx; i++) {
        imdb_op *o = &db->tx[i];
        if (o->code == IMDB_OP_INSERT || o->code == IMDB_OP_UPDATE) o->row = db->t[o->table]->arena.p + db->tx_row_off[i];
    }
    if ((rc = imdb_digest_delta(db->meta.digest_alg, db->tx, db->ntx, db->nt, delta, touched, e))) goto fail;
    imdb_lthash global = db->global;
    for (uint32_t t = 0; t < db->nt; t++)
        if (touched[t]) imdb_lthash_add(&global, &delta[t]);

    imdb_commit_rec c;
    memset(&c, 0, sizeof c);
    c.seq = db->seq + 1;
    c.alg = db->meta.digest_alg;
    c.time_us = now_us();
    if (c.time_us <= db->last_time) c.time_us = db->last_time + 1;
    memcpy(c.prev, db->head, 32);
    c.ops = db->tx;
    c.nops = db->ntx;
    imdb_lthash_digest(db->meta.digest_alg, &global, c.digest);
    imdb_commit_encode_header(&c, &hdr);
    imdb_commit_encode_payload(&c, &pay);
    if ((rc = imdb_buf_check(&hdr, e)) || (rc = imdb_buf_check(&pay, e))) goto fail;
    imdb_commit_hash(hdr.p, hdr.len, c.hash);
    if (hdr.len > IMDB_MAX_HEADER) {
        rc = imdb_fail(e, IMDB_ERR_LIMIT, "commit header exceeds %u bytes", IMDB_MAX_HEADER);
        goto fail;
    }
    c.hlen = (uint32_t)hdr.len;
    uint8_t msg[IMDB_SIGMSG_LEN];
    imdb_commit_sigmsg(c.seq, c.hlen, c.hash, msg);
    imdb_sign(&db->signer, msg, sizeof msg, c.sig);
    imdb_frame_build(hdr.p, hdr.len, c.seq, c.hash, c.sig, pay.p, pay.len, &frame);
    if ((rc = imdb_buf_check(&frame, e))) goto fail;
    if ((rc = imdb_log_append(db, frame.p, frame.len, e))) goto fail;
    for (uint32_t i = 0; i < db->ntx; i++)
        if (imdb_op_publishes_manifest(db->tx[i].code)) db->log_rotate = true; /* the commit ends its segment */

    /* durable: install */
    for (uint32_t i = 0; i < db->ntx; i++) {
        uint8_t code = db->tx[i].code;
        if (code == IMDB_OP_INSERT || code == IMDB_OP_DELETE || code == IMDB_OP_UPDATE || code == IMDB_OP_CREATE_TABLE ||
            code == IMDB_OP_CREATE_INDEX || code == IMDB_OP_DROP_INDEX) /* the manifest records the definitions */
            db->lake_dirty = true;
    }
    db->seq = c.seq;
    memcpy(db->head, c.hash, 32);
    db->last_hlen = c.hlen;
    memcpy(db->last_sig, c.sig, IMDB_SIG_LEN);
    db->last_time = c.time_us;
    if (db->ntx == 1 && db->tx[0].code == IMDB_OP_WRITER_KEY) { /* a rotation: the next commit is signed by the new key */
        imdb_err ew = {0};
        if (imdb_writer_apply(db, &c, &ew)) {
            db->failed = true;
            snprintf(db->warning, sizeof db->warning, "commit %llu rotated the writer key, but %s; reopen",
                     (unsigned long long)c.seq, ew.msg);
        }
    }
    for (uint32_t t = 0; t < db->nt; t++)
        if (touched[t]) imdb_lthash_add(&db->t[t]->digest, &delta[t]);
    db->global = global;
    if (imdb_ci_push(db, c.time_us, c.hash, c.digest, e)) db->failed = true;
    bool erased = false;
    for (uint32_t i = 0; i < db->ntx; i++) {
        imdb_op *o = &db->tx[i];
        if (o->code != IMDB_OP_ERASE) continue;
        for (uint32_t k = 0; k < o->n_erase; k++) {
            imdb_table *et = db->t[o->erase[k].table];
            const imdb_version *v = imdb_vh(et, o->erase[k].vid);
            imdb_err e3 = {0};
            if (!(v->flags & IMDB_V_STUB) && imdb_redact_note(db, v->begin, &e3)) db->failed = true;
            imdb_stub_version(et, o->erase[k].vid);
        }
        imdb_txn_doom_erased(db, o->erase, o->n_erase); /* suspended writes built on erased rows */
        erased = true;
        db->last_erase = c.seq;
    }
    for (uint32_t i = 0; i < db->ntx; i++) tx_op_free(&db->tx[i]);
    db->ntx = 0;
    db->tx_bytes = 0;
    db->nundo = 0;
    db->in_txn = false;
    rc = IMDB_OK;
    imdb_index_catch_up(db); /* the committed versions join the structures */
    for (uint32_t i = 0; erased && i < db->nt; i++) imdb_index_rebuild_table(db, db->t[i]); /* stubs out, keys wiped */
    if (erased) {
        /* The ERASE is durable at this point, so the caller gets success even if
         * the physical rewrite fails; the rewrite is retried at the next open and
         * VERIFY reports "erasure incomplete" until it has happened. The lake
         * is installed in memory first; its objects and LAKE_HEAD are written
         * only after the log is redacted (lake_persist refuses before), so a
         * LAKE_HEAD at seq S always means every ERASE up to S is in the log. */
        db->needs_redaction = true;
        imdb_err e2 = {0};
        if (imdb_lake_after_erase(db, &e2) || imdb_redact_log(db, &e2))
            snprintf(db->warning, sizeof db->warning,
                     "erasure committed at %llu but physical redaction is pending (%s); it is retried at next open",
                     (unsigned long long)db->seq, e2.msg);
    }
    goto out; /* due maintenance (the size-triggered CHECKPOINT) runs in imdb_maintain */
fail:
    imdb_rollback(db);
out:
    imdb_free(delta);
    imdb_free(touched);
    imdb_buf_free(&hdr);
    imdb_buf_wipe_free(&pay);
    imdb_buf_wipe_free(&frame);
    return rc;
}

/* ---- open / close ---------------------------------------------------------------- */

/* Drops everything a (failed) snapshot load built, back to the empty database
 * a full replay starts from; files and descriptors are untouched. */
void imdb_reset_state(imdb_db *db)
{
    imdb_lake_db_free(db);
    for (uint32_t i = 0; i < db->nt; i++) imdb_table_free(db->t[i]);
    db->nt = 0;
    db->nci = 0;
    db->ci_first = 1;
    db->seq = 0;
    db->last_erase = 0;
    db->last_time = 0;
    imdb_genesis_hash(db->db_id, db->head);
    imdb_lthash_zero(&db->global);
    db->lake_seq = 0;
    memset(db->lake_manifest, 0, sizeof db->lake_manifest);
    db->lake_dirty = db->lake_unverified = db->lake_pending = db->gc_pending = false;
    db->pending_auth = 0;
    db->needs_redaction = false;
    db->nredact = 0;
    imdb_writers_reset(db); /* a full replay re-derives every epoch from commit 1 */
}

int imdb_close(imdb_db *db)
{
    if (!db) return IMDB_OK;
    int rc = IMDB_OK;
    while (db->txns) imdb_txn_rollback(db, db->txns); /* sessions should be closed first; their writes are discarded */
    if (db->in_txn) imdb_rollback(db);
    imdb_lake_db_free(db);
    for (uint32_t i = 0; i < db->nt; i++) imdb_table_free(db->t[i]);
    imdb_free(db->t);
    for (uint32_t i = 0; i < db->ntx; i++) tx_op_free(&db->tx[i]);
    imdb_free(db->tx);
    imdb_free(db->tx_row_off);
    imdb_free(db->undo);
    imdb_free(db->ci);
    imdb_signer_wipe(&db->signer);
    if (db->durfd >= 0) {
        /* a clean close makes --nosync commits durable, and then the watermark says so */
        imdb_err e2 = {0};
        if (imdb_log_sync(db, &e2)) rc = IMDB_ERR_IO;
        if (imdb_io_fsync(db->durfd) != 0) rc = IMDB_ERR_IO;
        close(db->durfd);
    }
    if (db->anchorfd >= 0) {
        /* Every rewrite named a commit already durable (the closing imdb_log_sync published the last
         * one); only make it stay. Never publish here: a handle whose open or sync failed holds commits
         * the disk may not. */
        if (imdb_io_fsync(db->anchorfd) != 0) rc = IMDB_ERR_IO;
        close(db->anchorfd);
    }
    imdb_free(db->anchor_path);
    if (db->logfd >= 0) close(db->logfd);
    if (db->logdirfd >= 0) close(db->logdirfd);
    imdb_free(db->segs);
    imdb_free(db->redact_seqs);
    imdb_writers_free(db); /* after the closing sync: the anchor still names its commit's epoch */
    if (db->lockfd >= 0) close(db->lockfd);
    if (db->anchor_lockfd >= 0) close(db->anchor_lockfd); /* the lease goes last */
    if (db->dirfd >= 0) close(db->dirfd);
    imdb_free(db->path);
    imdb_free(db);
    return rc;
}

int imdb_open(const char *path, const imdb_open_opts *o, imdb_db **out, imdb_err *e)
{
    *out = NULL;
    if (o && (o->txn_bytes > IMDB_MAX_TXN_BYTES || o->txn_ops > IMDB_MAX_OPS_PER_COMMIT ||
              o->txn_locks > IMDB_MAX_TXN_LOCKS))
        return imdb_fail(e, IMDB_ERR_INVALID, "transaction limits above the maxima in limits.h");
    if (o && o->durable_ack && (!o->sync || o->read_only))
        return imdb_fail(e, IMDB_ERR_INVALID, "--durable-ack needs a writable open with synchronous commits: it syncs the "
                                             "watermark as each durable commit returns");
    if (o && o->retain_commits && o->read_only)
        return imdb_fail(e, IMDB_ERR_INVALID, "--retain-history needs a writable primary: it purges with logged "
                                             "COMPACT ... PURGE commits");
    imdb_db *db = imdb_alloc(sizeof *db, e);
    if (!db) return e->code;
    db->dirfd = db->logfd = db->lockfd = db->logdirfd = db->durfd = db->anchorfd = db->anchor_lockfd = -1;
    db->ci_first = 1;
    db->pin_max_lag = IMDB_PIN_MAX_LAG;
    db->retain_min = IMDB_RETAIN_MIN_ENDED;
    db->sync = o ? o->sync : 1;
    db->strict = o && o->durable_ack;
    db->mem_limit = o ? o->mem_limit : 0;
    db->full_replay = o && o->full_replay;
    db->lake_sync = o && o->lake_sync;
    db->checkpoint_bytes = !o || !o->checkpoint_bytes ? IMDB_CHECKPOINT_BYTES
                           : o->checkpoint_bytes == UINT64_MAX ? 0 : o->checkpoint_bytes;
    db->retain_commits = o ? o->retain_commits : 0;
    db->lim_txn_bytes = o && o->txn_bytes ? o->txn_bytes : IMDB_MAX_TXN_BYTES;
    db->lim_txn_ops = o && o->txn_ops ? o->txn_ops : IMDB_MAX_OPS_PER_COMMIT;
    db->lim_txn_locks = o && o->txn_locks ? o->txn_locks : IMDB_MAX_TXN_LOCKS;
    bool ro = o && o->read_only;
    imdb_lthash_zero(&db->global);
    int rc = IMDB_OK;
    db->path = imdb_strndup(path, strlen(path), e);
    if (!db->path) {
        rc = e->code;
        goto fail;
    }
    db->dirfd = imdb_io_open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (db->dirfd < 0) {
        rc = imdb_fail(e, IMDB_ERR_IO, "open %s: %s", path, strerror(errno));
        goto fail;
    }
    if (!ro) {
        db->lockfd = imdb_io_openat(db->dirfd, "LOCK", O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0600);
        if (db->lockfd < 0 || imdb_io_flock(db->lockfd, LOCK_EX | LOCK_NB) != 0) {
            rc = imdb_fail(e, IMDB_ERR_STATE, "%s is in use by another process", path);
            goto fail;
        }
        /* one writer per anchor: the lease covers the check below and every commit after it */
        if (o && o->anchor && (rc = imdb_anchor_lock(o->anchor, &db->anchor_lockfd, e))) goto fail;
        db->durfd = imdb_io_openat(db->dirfd, IMDB_DURABLE_NAME, O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0600);
        struct stat st;
        if (db->durfd < 0 || imdb_io_fstat(db->durfd, &st) != 0 || !S_ISREG(st.st_mode)) {
            rc = imdb_fail(e, IMDB_ERR_IO, "DURABLE: cannot open it as a regular file");
            goto fail;
        }
    }
    imdb_err ed = {0};
    if (imdb_durable_read(db->dirfd, &db->dur, &db->have_dur, &ed)) {
        db->have_dur = false; /* a damaged final frame then counts as damage, not as a torn append */
        snprintf(db->warning, sizeof db->warning, "%s: ignored", ed.msg);
    }
    if ((rc = read_meta(db->dirfd, &db->meta, &db->replica, e))) goto fail;
    memcpy(db->db_id, db->meta.db_id, 16);
    if ((rc = imdb_writers_init(db, e))) goto fail; /* epoch 0 from META, the rest from WRITERS or the replay */
    /* checked against the log's current key once the replay has found it (imdb_writer_settle) */
    if (!db->replica && !ro && (rc = imdb_seed_read(db->dirfd, SIGNING_KEY_NAME, &db->signer, &db->can_sign, e))) goto fail;
    imdb_genesis_hash(db->db_id, db->head);
    db->read_only = ro;
    db->logdirfd = imdb_open_dir_at(db->dirfd, IMDB_LOG_DIR, e);
    if (db->logdirfd < 0) {
        rc = e->code;
        goto fail;
    }
    if (!ro && (rc = imdb_logdir_cleanup_temps(db->logdirfd, e))) goto fail;
    if ((rc = imdb_lake_open(db, e))) goto fail;
    db->replaying = true;
    rc = imdb_replay(db, ro, e);
    db->replaying = false;
    if (rc) goto fail;
    if (db->retain_commits && db->replica) {
        rc = imdb_fail(e, IMDB_ERR_INVALID, "--retain-history is set on the primary: a replica applies the purges it logs");
        goto fail;
    }
    if (db->retain_commits) retain_count(db);
    if ((rc = imdb_index_build_all(db, e))) goto fail; /* once, after the replay: one sort each */
    bool anchor_new;
    if ((rc = anchor_check(db, o, &anchor_new, e))) goto fail; /* before recovery changes anything in the directory */
    if (!ro && db->nsegs && !db->log_rotate) {
        /* appends continue the last segment (replay left it valid to its end): a tagged one in place,
         * an untagged one appended; an untagged one with no frame (a crash before its header landed)
         * is made tagged, as every new segment is */
        char name[IMDB_LOGSEG_NAME + 1];
        imdb_logseg_name(db->segs[db->nsegs - 1], name);
        bool retag = g_log_tagged && !db->log_tagged && db->log_size == 0;
        db->logfd = imdb_io_openat(db->logdirfd, name, db->log_tagged || retag ? O_RDWR | O_CLOEXEC | O_NOFOLLOW
                                                                              : O_WRONLY | O_APPEND | O_CLOEXEC | O_NOFOLLOW);
        if (db->logfd < 0) {
            rc = imdb_fail(e, IMDB_ERR_IO, "open log segment: %s", strerror(errno));
            goto fail;
        }
        if (retag) {
            uint8_t h[IMDB_TSEG_SECTOR];
            imdb_tseg_header(db->segs[db->nsegs - 1], h);
            if (imdb_io_ftruncate(db->logfd, 0) != 0) rc = imdb_fail(e, IMDB_ERR_IO, "log segment: %s", strerror(errno));
            if (!rc) rc = imdb_pwrite_all(db->logfd, h, sizeof h, 0, e);
            if (!rc) rc = log_write_zeros(db->logfd, IMDB_TSEG_SECTOR, IMDB_LOG_FILL_CHUNK, e);
            if (!rc && imdb_io_fdatasync(db->logfd) != 0)
                rc = imdb_fail(e, IMDB_ERR_IO, "fdatasync(log) failed: %s", strerror(errno));
            if (!rc) rc = imdb_sync_dir(db->logdirfd, e);
            if (rc) goto fail;
            db->log_tagged = true;
            db->log_phys = 1;
            db->log_fill = IMDB_TSEG_SECTOR + IMDB_LOG_FILL_CHUNK;
        }
    }
    if (!ro) {
        if ((rc = durable_after_recovery(db, e))) goto fail;
        if ((rc = imdb_writer_settle(db, e))) goto fail; /* after the sync: an epoch change in the log is durable */
        imdb_err ew = {0};
        if (imdb_writers_publish(db, &ew)) imdb_warn(db, "WRITERS could not be written (%s)", ew.msg);
        if ((rc = anchor_start(db, o, anchor_new, e))) goto fail;
        if (db->needs_redaction && (rc = imdb_redact_log(db, e))) goto fail;
        /* lake readers' leases (lake.h): a database made before them gets the directory here;
         * without it readers read unpinned, so a failure only warns */
        if (imdb_io_mkdirat(db->dirfd, IMDB_PINS_DIR, 0700) == 0) {
            imdb_err ep = {0};
            if (imdb_sync_dir(db->dirfd, &ep)) imdb_warn(db, "pins/ made but not synced (%s)", ep.msg);
        } else if (errno != EEXIST) {
            imdb_warn(db, "pins/ could not be made (%s): lake readers read unpinned", strerror(errno));
        }
        if ((rc = imdb_lake_finish_open(db, e))) goto fail;
    }
    *out = db;
    return IMDB_OK;
fail:
    imdb_close(db);
    return rc;
}

/* ---- recovery ----------------------------------------------------------------------- */

/* recover --save from a tagged segment: n raw bytes of it from offset from, to fd. */
static int save_sectors(int logfd, uint64_t first, uint64_t from, uint64_t n, int fd, imdb_err *e)
{
    char name[IMDB_LOGSEG_NAME + 1];
    imdb_logseg_name(first, name);
    int sfd = imdb_io_openat(logfd, name, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (sfd < 0) return imdb_fail(e, IMDB_ERR_IO, "cannot read the damaged tail: %s", strerror(errno));
    enum { PIECE = 65536 };
    uint8_t *b = imdb_alloc(PIECE, e);
    int rc = b ? IMDB_OK : e->code;
    while (!rc && n) {
        size_t k = n < PIECE ? (size_t)n : PIECE;
        if (imdb_io_pread(sfd, b, k, (off_t)from) != (ssize_t)k) rc = imdb_fail(e, IMDB_ERR_IO, "cannot read the damaged tail");
        else rc = imdb_write_all(fd, b, k, e);
        from += k;
        n -= k;
    }
    imdb_free(b);
    close(sfd);
    return rc;
}

/* Walks the frames of one segment: seq/hash enter as the commit before it and
 * leave as its last intact commit; *off is where the valid frames stop. */
static imdb_scan_status scan_tail(const imdb_logseg *s, uint64_t *seq, uint8_t hash[32], size_t *off, imdb_err *e2)
{
    *off = 0;
    for (;;) {
        size_t flen = 0;
        imdb_scan_status st = imdb_logseg_scan(s, *off, &flen, e2);
        if (st != IMDB_SCAN_FRAME) return st;
        if (flen < IMDB_FRAME_HDR + IMDB_BODY_DESC || imdb_frame_seq(s->buf + *off) != *seq + 1) {
            imdb_fail(e2, IMDB_ERR_CORRUPT, "frame at offset %zu is not commit %llu", *off, (unsigned long long)(*seq + 1));
            return IMDB_SCAN_CORRUPT;
        }
        *seq += 1;
        memcpy(hash, imdb_frame_hash(s->buf + *off), 32);
        *off += flen;
    }
}

int imdb_recover_tail(const char *path, bool apply, const char *save_path, imdb_recover_report *r, imdb_err *e)
{
    memset(r, 0, sizeof *r);
    int dirfd = imdb_io_open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW), lockfd = -1, logfd = -1, segfd = -1;
    uint64_t *segs = NULL;
    size_t nsegs = 0;
    imdb_logseg seg; /* the segment being read: in the end, the last */
    memset(&seg, 0, sizeof seg);
    bool tagged_before = false;
    int rc = IMDB_OK;
    if (dirfd < 0) return imdb_fail(e, IMDB_ERR_IO, "open %s: %s", path, strerror(errno));
    lockfd = imdb_io_openat(dirfd, "LOCK", O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (lockfd < 0 || imdb_io_flock(lockfd, LOCK_EX | LOCK_NB) != 0) {
        rc = imdb_fail(e, IMDB_ERR_STATE, "%s is in use by another process", path);
        goto out;
    }
    imdb_identity id;
    bool replica;
    if ((rc = read_meta(dirfd, &id, &replica, e))) goto out;
    imdb_durable w;
    imdb_err ed = {0};
    if ((rc = imdb_durable_read(dirfd, &w, &r->have_durable, &ed))) {
        if (rc != IMDB_ERR_CORRUPT) { /* unreadable: no decision can be made */
            imdb_fail(e, rc, "%s", ed.msg);
            goto out;
        }
        rc = IMDB_OK; /* a torn or damaged record: decide as without one (the operator's call) */
        r->have_durable = false;
        r->durable_ignored = true;
    }
    r->durable = r->have_durable ? w.seq : 0;
    if ((logfd = imdb_open_dir_at(dirfd, IMDB_LOG_DIR, e)) < 0) {
        rc = e->code;
        goto out;
    }
    if ((rc = imdb_logdir_list(logfd, &segs, &nsegs, e))) goto out;
    uint64_t seq = 0;
    uint8_t hash[32];
    imdb_genesis_hash(id.db_id, hash);
    size_t off = 0;
    imdb_scan_status st = IMDB_SCAN_END;
    for (size_t si = 0; si < nsegs; si++) { /* earlier segments: only their last commit is needed */
        imdb_logseg_free(&seg);
        if ((rc = imdb_logseg_load(logfd, segs[si], &seg, e))) goto out;
        if (!seg.tagged && tagged_before && !(si + 1 == nsegs && imdb_logseg_blank(&seg))) {
            rc = imdb_fail(e, IMDB_ERR_CORRUPT, "log segment %llu is untagged, after a tagged one: restore it from a "
                           "replica", (unsigned long long)segs[si]);
            goto out;
        }
        tagged_before = seg.tagged;
        imdb_err e2 = {0};
        if (segs[si] != seq + 1) {
            rc = imdb_fail(e, IMDB_ERR_CORRUPT, "log segment %llu does not follow commit %llu: restore it from a replica",
                           (unsigned long long)segs[si], (unsigned long long)seq);
            goto out;
        }
        st = scan_tail(&seg, &seq, hash, &off, &e2);
        if (st == IMDB_SCAN_CORRUPT || (st != IMDB_SCAN_END && si + 1 < nsegs)) {
            rc = imdb_fail(e, IMDB_ERR_CORRUPT, "segment %llu: %s; this is not a damaged end of the log: restore the "
                           "segment from a replica", (unsigned long long)segs[si], e2.msg);
            goto out;
        }
        if (st != IMDB_SCAN_END) snprintf(r->what, sizeof r->what, "%s", e2.msg);
    }
    r->last = seq;
    r->damaged = st == IMDB_SCAN_TORN || st == IMDB_SCAN_DAMAGED;
    r->acked_lost = r->have_durable && w.synced && w.seq > seq; /* a --nosync watermark acknowledged nothing */
    r->durable_synced = r->have_durable && w.synced;
    r->durable_strict = r->have_durable && w.strict;
    r->maybe_acked = st == IMDB_SCAN_DAMAGED && !r->acked_lost && !r->durable_strict;
    bool lake_present = false;
    uint8_t lm[32];
    imdb_err el = {0};
    if (imdb_lake_head(dirfd, &lake_present, &r->lake_seq, lm, &el) == IMDB_OK && lake_present && r->lake_seq > seq)
        r->lake_ahead = true;
    if (r->damaged) {
        r->segment = segs[nsegs - 1];
        /* tagged: from where the last kept frame ends (E) to the last non-zero sector */
        r->offset = seg.tagged ? seg.end.keep_sector * IMDB_TSEG_SECTOR + (seg.end.keep_bytes ? 8 + seg.end.keep_bytes : 0) : off;
        r->bytes = seg.tagged ? seg.end.dirty * IMDB_TSEG_SECTOR - r->offset : seg.len - off;
    }
    if (!apply || (!r->damaged && !r->acked_lost && !r->lake_ahead)) goto out;
    /* the lake is derived from the log: one past the kept commits goes first (the next writable
     * open rebuilds it from the log), so LAKE_HEAD never names a commit the log has dropped */
    if (r->lake_ahead && (imdb_io_unlinkat(dirfd, "LAKE_HEAD", 0) != 0 || imdb_sync_dir(dirfd, e))) {
        rc = imdb_fail(e, IMDB_ERR_IO, "cannot remove LAKE_HEAD: %s", strerror(errno));
        goto out;
    }
    if (r->damaged) {
        if (!save_path) {
            rc = imdb_fail(e, IMDB_ERR_INVALID, "discarding the damaged tail needs --save FILE for its bytes");
            goto out;
        }
        const char *sbase;
        int sdir = imdb_open_parent(save_path, &sbase, e);
        if (sdir < 0) {
            rc = sdir;
            goto out;
        }
        int sfd = imdb_io_openat(sdir, sbase, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
        if (sfd < 0) {
            rc = imdb_fail(e, IMDB_ERR_IO, "create %s: %s", save_path, strerror(errno));
            close(sdir);
            goto out;
        }
        if (seg.tagged) { /* the raw sectors from the one E falls in: the scan compacted its copy */
            uint64_t from = seg.end.keep_sector * IMDB_TSEG_SECTOR, n = seg.end.dirty * IMDB_TSEG_SECTOR - from;
            rc = save_sectors(logfd, segs[nsegs - 1], from, n, sfd, e);
        } else {
            rc = imdb_write_all(sfd, seg.buf + off, seg.len - off, e);
        }
        if (!rc && imdb_io_fsync(sfd) != 0) rc = imdb_fail(e, IMDB_ERR_IO, "fsync %s: %s", save_path, strerror(errno));
        close(sfd);
        /* its name too, before the cut: else a power cut could keep the cut and lose the saved bytes */
        if (!rc) rc = imdb_sync_dir(sdir, e);
        if (rc) imdb_io_unlinkat(sdir, sbase, 0); /* the log still holds them: a retry may use the same name */
        close(sdir);
        if (rc) goto out;
        char name[IMDB_LOGSEG_NAME + 1];
        imdb_logseg_name(segs[nsegs - 1], name);
        if (seg.tagged) {
            if ((rc = imdb_logseg_drop_tail(logfd, &seg, e))) goto out;
        } else {
            segfd = imdb_io_openat(logfd, name, O_WRONLY | O_CLOEXEC | O_NOFOLLOW);
            if (segfd < 0 || imdb_io_ftruncate(segfd, (off_t)off) != 0 || imdb_io_fsync(segfd) != 0) {
                rc = imdb_fail(e, IMDB_ERR_IO, "cannot cut log segment %s: %s", name, strerror(errno));
                goto out;
            }
        }
    }
    /* "synced" must be true of every kept commit: a --nosync writer or a crash may have left frames
     * past the old watermark that never reached the disk */
    if ((rc = sync_log_segments(logfd, segs, nsegs, r->have_durable && w.synced ? w.seq + 1 : 1, e))) goto out;
    if (imdb_io_fsync(logfd) != 0) {
        rc = imdb_fail(e, IMDB_ERR_IO, "fsync(log/) failed: %s", strerror(errno));
        goto out;
    }
    imdb_durable nw = {.seq = seq, .synced = true};
    memcpy(nw.head, hash, 32);
    uint8_t wb[IMDB_DURABLE_LEN];
    imdb_durable_encode(&nw, wb);
    if ((rc = imdb_write_file_atomic(dirfd, IMDB_DURABLE_NAME, wb, sizeof wb, 0600, e))) goto out;
    r->applied = true;
out:
    imdb_logseg_free(&seg);
    imdb_free(segs);
    if (segfd >= 0) close(segfd);
    if (logfd >= 0) close(logfd);
    if (lockfd >= 0) close(lockfd);
    close(dirfd);
    return rc;
}

void imdb_warn(imdb_db *db, const char *fmt, ...)
{
    char m[sizeof db->warning];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(m, sizeof m, fmt, ap);
    va_end(ap);
    if (strstr(db->warning, m)) return;
    size_t used = strlen(db->warning);
    snprintf(db->warning + used, sizeof db->warning - used, "%s%s", used ? "; " : "", m);
}

uint64_t imdb_cleanup_seq(imdb_db *db)
{
    /* every flag covers all outstanding work, whichever ERASE caused it: when none is set, nothing up
     * to db->seq is left; while one is, the claim stays at the last commit where none was */
    if (!db->failed && !db->in_txn && !db->needs_redaction && !db->nredact && !db->pending_auth &&
        !db->lake_unverified && !db->lake_pending && !db->gc_pending)
        db->clean_seq = db->seq;
    return db->clean_seq;
}

/* ---- the memory budget (db.h) ------------------------------------------------------- */

void imdb_mem(const imdb_db *db, imdb_mem_report *r)
{
    memset(r, 0, sizeof *r);
    for (uint32_t ti = 0; ti < db->nt; ti++) {
        const imdb_table *t = db->t[ti];
        r->versions += imdb_ver_bytes(t);
        r->rows += t->arena.cap;
        r->indexes += (t->pk.cap + t->subj.cap) * sizeof(imdb_hslot) + t->pk.key_bytes + t->subj.key_bytes +
                      (uint64_t)t->capsubj * sizeof(imdb_vlist);
        for (uint32_t k = 0; k < t->nsubj; k++) r->indexes += (uint64_t)t->subj_lists[k].cap * sizeof(uint64_t);
        for (uint32_t k = 0; k < t->nidx; k++) {
            if (t->idx[k].ox) r->indexes += imdb_oidx_bytes(t->idx[k].ox);
            r->indexes += imdb_index_unique_bytes(&t->idx[k]);
        }
        r->segments += (uint64_t)t->capseg * sizeof(imdb_segment *);
        for (uint32_t k = 0; k < t->nseg; k++) {
            const imdb_segment *g = t->seg[k];
            r->segments += sizeof *g + g->len + (uint64_t)g->nrows * sizeof(uint64_t) + (g->nrows / 64 + 1) * sizeof(uint64_t);
        }
    }
    r->commits = db->capci * sizeof(imdb_commit_info);
    r->txns = db->capundo * sizeof(imdb_undo) + (uint64_t)db->captx * sizeof(imdb_op);
    for (const imdb_txn *x = db->txns; x; x = x->next) {
        r->txns += (uint64_t)x->capops * sizeof(imdb_saved_op) + (uint64_t)x->caplocks * sizeof(imdb_txn_lock) +
                   (uint64_t)x->capsps * sizeof(imdb_txn_sp);
        for (uint32_t i = 0; i < x->nops; i++) r->txns += x->ops[i].row_len;
    }
    r->total = r->versions + r->rows + r->indexes + r->segments + r->commits + r->txns;
    r->limit = db->mem_limit;
}

int imdb_mem_admit(imdb_db *db, uint64_t growth, imdb_err *e)
{
    if (!db->mem_limit || !growth) return IMDB_OK;
    imdb_mem_report r;
    imdb_mem(db, &r);
    if (r.total + growth <= db->mem_limit) return IMDB_OK;
    return imdb_fail(e, IMDB_ERR_LIMIT,
                     "memory budget: this write needs %llu more bytes at a growth step (%llu held, budget %llu): "
                     "nothing was written; reopen with a larger budget, or hold less (SHOW MEMORY)",
                     (unsigned long long)growth, (unsigned long long)r.total, (unsigned long long)r.limit);
}
