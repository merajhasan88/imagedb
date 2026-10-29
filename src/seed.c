/* Seeding a replica past a cut: seed.h. */
#include "seed.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "cpu.h"
#include "db_internal.h"
#include "fsio.h"
#include "lake.h"
#include "limits.h"
#include "log.h"
#include "logdir.h"
#include "sha256.h"
#include "writer.h"

enum { OBJ_SEG = 1, OBJ_DV = 2, OBJ_MAN = 3 };
static const char *const kExt[] = {"", ".seg", ".dv", ".man"};
#define CHUNK (64u << 10)

typedef struct sobj {
    uint8_t kind;
    uint8_t h[32];
} sobj;

static int cmp_sobj(const void *a, const void *b)
{
    const sobj *x = a, *y = b;
    int c = memcmp(x->h, y->h, 32);
    return c ? c : (int)x->kind - (int)y->kind;
}

static void obj_file(uint8_t kind, const uint8_t h[32], char name[80])
{
    imdb_hex(h, 32, name);
    snprintf(name + 64, 16, "%s", kExt[kind]);
}

/* the objects a manifest names but itself, by hash, each once (a zero hash: no deletion vector); its retained
 * generation's manifest among them (the snapshot load reads it, and the objects check requires it), not that
 * generation's segments */
static int manifest_objects(const imdb_manifest *m, sobj **out, size_t *n, imdb_err *e)
{
    static const uint8_t zero[32];
    size_t cap = 1;
    for (uint32_t t = 0; t < m->nt; t++) cap += 2 * (size_t)m->t[t].nseg;
    sobj *v = imdb_alloc_array(cap, sizeof *v, e);
    if (!v) return e->code;
    size_t k = 0;
    if (memcmp(m->prev_manifest, zero, 32) != 0) {
        v[k].kind = OBJ_MAN;
        memcpy(v[k++].h, m->prev_manifest, 32);
    }
    for (uint32_t t = 0; t < m->nt; t++)
        for (uint32_t i = 0; i < m->t[t].nseg; i++) {
            v[k].kind = OBJ_SEG;
            memcpy(v[k++].h, m->t[t].seg[i].seg, 32);
            if (memcmp(m->t[t].seg[i].dv, zero, 32) != 0) {
                v[k].kind = OBJ_DV;
                memcpy(v[k++].h, m->t[t].seg[i].dv, 32);
            }
        }
    qsort(v, k, sizeof *v, cmp_sobj);
    size_t w = 0;
    for (size_t i = 0; i < k; i++)
        if (!w || cmp_sobj(&v[w - 1], &v[i]) != 0) v[w++] = v[i];
    *out = v;
    *n = w;
    return IMDB_OK;
}

/* ---- the primary's side ------------------------------------------------------------------------------- */

/* commit S's header and signature, from the frame that ends its segment */
static int floor_frame(int logfd, const uint64_t *segs, size_t nsegs, uint64_t S, imdb_buf *hd, imdb_err *e)
{
    size_t si = imdb_logseg_find(segs, nsegs, S);
    if (si == nsegs || (si + 1 < nsegs && segs[si + 1] != S + 1))
        return imdb_fail(e, IMDB_ERR_STATE, "seed: commit %llu does not end a log segment here", (unsigned long long)S);
    imdb_logseg seg;
    if (imdb_logseg_load(logfd, segs[si], &seg, e)) return e->code;
    size_t off = 0, last = SIZE_MAX, lastlen = 0;
    for (;;) {
        size_t flen = 0;
        imdb_err e2 = {0};
        if (imdb_logseg_scan(&seg, off, &flen, &e2) != IMDB_SCAN_FRAME) break;
        last = off;
        lastlen = flen;
        off += flen;
    }
    int rc = IMDB_OK;
    if (last == SIZE_MAX || imdb_frame_seq(seg.buf + last) != S) {
        rc = imdb_fail(e, IMDB_ERR_STATE, "seed: commit %llu is not the last frame of its segment", (unsigned long long)S);
    } else {
        const uint8_t *body = seg.buf + last + IMDB_FRAME_HDR;
        size_t blen = lastlen - IMDB_FRAME_HDR, dl = imdb_body_desc_len(body);
        uint32_t hlen = blen >= dl ? imdb_get_le32(body + 1) : 0;
        if (blen < dl || !hlen || hlen > blen - dl) {
            rc = imdb_fail(e, IMDB_ERR_CORRUPT, "seed: commit %llu: a malformed frame", (unsigned long long)S);
        } else {
            imdb_buf_put_u32(hd, hlen);
            imdb_buf_put(hd, body + dl, hlen);
            imdb_buf_put(hd, body + 1 + 4 + 8 + 32, IMDB_SIG_LEN); /* kind | hlen | seq | hash | signature */
        }
    }
    imdb_logseg_free(&seg);
    return rc;
}

/* the entries of WRITERS (or FLOOR) as written: from off, cnt of them; those at or below S copied */
static int copy_entries(const uint8_t *p, size_t n, size_t off, uint32_t cnt, uint64_t S, imdb_buf *out, uint32_t *took,
                        imdb_err *e)
{
    imdb_rd r;
    imdb_rd_init(&r, p, n);
    (void)imdb_rd_bytes(&r, off);
    for (uint32_t i = 0; i < cnt && !r.err; i++) {
        size_t at = n - imdb_rd_left(&r);
        uint64_t seq = imdb_rd_u64(&r);
        uint8_t promote = imdb_rd_u8(&r);
        uint32_t hlen = imdb_rd_u32(&r);
        (void)imdb_rd_bytes(&r, hlen);
        (void)imdb_rd_bytes(&r, IMDB_SIG_LEN * (promote ? 2u : 1u));
        if (r.err || seq > S) continue;
        imdb_buf_put(out, p + at, n - imdb_rd_left(&r) - at);
        (*took)++;
    }
    return r.err ? imdb_fail(e, IMDB_ERR_CORRUPT, "seed: a malformed list of key changes") : IMDB_OK;
}

/* The primary's FLOOR, when it has one: its floor, where its entries begin and how many, its starts. */
typedef struct pfloor {
    uint8_t *p;
    size_t n;
    uint64_t floor;
    size_t entries;
    uint32_t nentries, nstarts;
    const uint8_t *starts;
} pfloor;

static int read_pfloor(int dirfd, pfloor *f, imdb_err *e)
{
    memset(f, 0, sizeof *f);
    int rc = imdb_read_file_at(dirfd, IMDB_FLOOR_NAME, &f->p, &f->n, IMDB_MAX_OBJECT, e);
    if (rc == IMDB_ERR_NOTFOUND) {
        imdb_err_clear(e);
        return IMDB_OK;
    }
    if (rc) return rc;
    imdb_rd r;
    imdb_rd_init(&r, f->p, f->n > 4 ? f->n - 4 : 0);
    (void)imdb_rd_bytes(&r, 24);
    f->floor = imdb_rd_u64(&r);
    uint32_t hlen = imdb_rd_u32(&r);
    (void)imdb_rd_bytes(&r, hlen);
    (void)imdb_rd_bytes(&r, IMDB_SIG_LEN);
    f->nentries = imdb_rd_u32(&r);
    f->entries = f->n - 4 - imdb_rd_left(&r);
    for (uint32_t i = 0; i < f->nentries && !r.err; i++) {
        (void)imdb_rd_u64(&r);
        uint8_t promote = imdb_rd_u8(&r);
        (void)imdb_rd_bytes(&r, imdb_rd_u32(&r));
        (void)imdb_rd_bytes(&r, IMDB_SIG_LEN * (promote ? 2u : 1u));
    }
    f->nstarts = imdb_rd_u32(&r);
    f->starts = imdb_rd_bytes(&r, (size_t)f->nstarts * 16);
    if (r.err || f->n < 64) return imdb_fail(e, IMDB_ERR_CORRUPT, "seed: this database's FLOOR is malformed");
    return IMDB_OK;
}

/* The head: FLOOR's format up to its manifest, for the floor S (writer.h). */
static int build_head(const char *path, int dirfd, int logfd, const uint64_t *segs, size_t nsegs, uint64_t S,
                      const imdb_manifest *m, imdb_buf *hd, imdb_err *e)
{
    uint8_t id[16], wpk[IMDB_PUBKEY_LEN];
    int rc = imdb_read_identity(path, id, wpk, e);
    pfloor pf;
    memset(&pf, 0, sizeof pf);
    if (!rc) rc = read_pfloor(dirfd, &pf, e);
    imdb_buf_put(hd, "IMDBFLR1", 8);
    imdb_buf_put(hd, id, 16);
    imdb_buf_put_u64(hd, S);
    if (!rc) rc = floor_frame(logfd, segs, nsegs, S, hd, e);
    /* the key changes up to S: WRITERS has them all; without it, the primary's FLOOR those up to its floor */
    imdb_buf en;
    imdb_buf_init(&en);
    uint32_t took = 0;
    uint8_t *w = NULL;
    size_t wn = 0;
    int wr = rc ? rc : imdb_read_file_at(dirfd, "WRITERS", &w, &wn, (size_t)IMDB_MAX_EPOCHS * 4096u, e);
    if (!rc && wr == IMDB_ERR_NOTFOUND) {
        imdb_err_clear(e);
        if (pf.p) rc = copy_entries(pf.p, pf.n - 4, pf.entries, pf.nentries, S, &en, &took, e);
    } else if (!rc && !(rc = wr)) {
        rc = wn < 32 ? imdb_fail(e, IMDB_ERR_CORRUPT, "seed: WRITERS is malformed")
                     : copy_entries(w, wn - 4, 28, imdb_get_le32(w + 24), S, &en, &took, e);
    }
    imdb_free(w);
    imdb_buf_put_u32(hd, took);
    imdb_buf_put(hd, en.p, en.len);
    imdb_buf_free(&en);
    /* the segment starts in (the lowest horizon at S, S]: those at or below the primary's floor from its FLOOR,
     * the cut having taken their segments, the rest from its log */
    uint64_t hmin = S;
    for (uint32_t t = 0; t < m->nt; t++)
        if (m->t[t].horizon < hmin) hmin = m->t[t].horizon;
    imdb_buf st;
    imdb_buf_init(&st);
    uint32_t ns = 0;
    for (uint32_t i = 0; !rc && pf.p && i < pf.nstarts; i++) {
        uint64_t s = imdb_get_le64(pf.starts + 16 * i);
        if (s <= hmin || s > S) continue;
        imdb_buf_put(&st, pf.starts + 16 * i, 16);
        ns++;
    }
    for (size_t i = 0; !rc && i < nsegs; i++) {
        uint64_t s = segs[i], t = 0;
        if (s <= hmin || s > S || s <= pf.floor) continue;
        if ((rc = imdb_logseg_first_time(logfd, s, &t, e))) break;
        imdb_buf_put_u64(&st, s);
        imdb_buf_put_u64(&st, t);
        ns++;
    }
    imdb_buf_put_u32(hd, ns);
    imdb_buf_put(hd, st.p, st.len);
    imdb_buf_free(&st);
    imdb_free(pf.p);
    if (!rc) rc = imdb_buf_check(hd, e);
    return rc;
}

static int send_object(int ofd, int outfd, uint8_t kind, const uint8_t h[32], uint8_t *buf, imdb_err *e)
{
    char name[80];
    obj_file(kind, h, name);
    int fd = imdb_io_openat(ofd, name, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    struct stat st;
    if (fd < 0 || imdb_io_fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) {
        if (fd >= 0) close(fd);
        return imdb_fail(e, IMDB_ERR_NOTFOUND, "seed: lake object %s is gone (a newer generation replaced it): ship again",
                         name);
    }
    uint8_t rec[1 + 32 + 8];
    rec[0] = kind;
    memcpy(rec + 1, h, 32);
    imdb_le64(rec + 33, (uint64_t)st.st_size);
    int rc = imdb_write_all(outfd, rec, sizeof rec, e);
    for (uint64_t at = 0; !rc && at < (uint64_t)st.st_size;) {
        ssize_t r = imdb_io_pread(fd, buf, CHUNK, (off_t)at);
        if (r < 0 && errno == EINTR) continue;
        if (r <= 0) {
            rc = imdb_fail(e, IMDB_ERR_IO, "seed: lake object %s: short read", name);
            break;
        }
        rc = imdb_write_all(outfd, buf, (size_t)r, e);
        at += (uint64_t)r;
    }
    close(fd);
    return rc;
}

int imdb_seed_send(const char *path, int dirfd, int logfd, int outfd, uint64_t *seq, imdb_err *e)
{
    *seq = 0;
    bool present = false;
    uint64_t S = 0;
    uint8_t mh[32];
    int rc = imdb_lake_head(dirfd, &present, &S, mh, e);
    if (!rc && !present)
        return imdb_fail(e, IMDB_ERR_STATE, "seed: no lake snapshot is published here (its log is cut, so there must be)");
    if (rc) return rc;
    int pin;
    (void)imdb_lake_pin(dirfd, mh, &pin, e); /* best effort (lake.h): a generation gone meanwhile fails the seed */
    int ofd = imdb_open_dir_at(dirfd, "objects", e);
    uint8_t *mb = NULL, *buf = NULL;
    size_t ml = 0;
    uint64_t *segs = NULL;
    size_t nsegs = 0;
    imdb_manifest m;
    memset(&m, 0, sizeof m);
    sobj *objs = NULL;
    size_t nobj = 0;
    imdb_buf hd;
    imdb_buf_init(&hd);
    char mname[80];
    obj_file(OBJ_MAN, mh, mname);
    rc = ofd < 0 ? e->code : imdb_read_file_at(ofd, mname, &mb, &ml, IMDB_MAX_OBJECT, e);
    if (!rc) rc = imdb_manifest_parse(mb, ml, &m, e);
    if (!rc && m.seq != S) rc = imdb_fail(e, IMDB_ERR_STATE, "seed: the manifest LAKE_HEAD names is another commit's");
    if (!rc) rc = imdb_logdir_list(logfd, &segs, &nsegs, e);
    if (!rc) rc = build_head(path, dirfd, logfd, segs, nsegs, S, &m, &hd, e);
    if (!rc) rc = manifest_objects(&m, &objs, &nobj, e);
    if (!rc && (hd.len > IMDB_SEED_HEAD_MAX || nobj + 1 > IMDB_SEED_OBJECTS_MAX))
        rc = imdb_fail(e, IMDB_ERR_LIMIT, "seed: the snapshot at commit %llu is past a seed's limits", (unsigned long long)S);
    if (!rc && !(buf = imdb_alloc(CHUNK, e))) rc = e->code;
    if (!rc) {
        uint8_t p[IMDB_SEED_PREFIX], c[4];
        memcpy(p, "IMDBSED1", 8);
        imdb_le64(p + 8, S);
        imdb_le32(p + 16, (uint32_t)hd.len);
        imdb_le32(p + 20, (uint32_t)(nobj + 1));
        imdb_le32(p + 24, imdb_kern()->crc32c(0, p, 24));
        imdb_le32(c, imdb_kern()->crc32c(0, hd.p, hd.len));
        rc = imdb_write_all(outfd, p, sizeof p, e);
        if (!rc) rc = imdb_write_all(outfd, hd.p, hd.len, e);
        if (!rc) rc = imdb_write_all(outfd, c, sizeof c, e);
    }
    if (!rc) rc = send_object(ofd, outfd, OBJ_MAN, mh, buf, e);
    for (size_t i = 0; !rc && i < nobj; i++) rc = send_object(ofd, outfd, objs[i].kind, objs[i].h, buf, e);
    if (!rc) *seq = S;
    imdb_free(buf);
    imdb_free(objs);
    imdb_buf_free(&hd);
    imdb_manifest_free(&m);
    imdb_free(mb);
    imdb_free(segs);
    if (ofd >= 0) close(ofd);
    imdb_lake_unpin(pin);
    return rc;
}

/* ---- the replica's side ------------------------------------------------------------------------------- */

/* one object of n bytes into objects/, kept only if they hash to h: streamed to a temporary file in chunks */
static int take_object(int ofd, imdb_stream *s, uint8_t kind, const uint8_t h[32], uint64_t n, uint8_t *buf, imdb_err *e)
{
    char name[80], tmp[90];
    obj_file(kind, h, name);
    snprintf(tmp, sizeof tmp, "%s.tmp", name);
    (void)imdb_io_unlinkat(ofd, tmp, 0);
    int fd = imdb_io_openat(ofd, tmp, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (fd < 0) return imdb_fail(e, IMDB_ERR_IO, "seed: objects/%s: %s", tmp, strerror(errno));
    imdb_sha256_ctx c;
    imdb_sha256_init(&c);
    int rc = IMDB_OK;
    for (uint64_t left = n; !rc && left;) {
        size_t k = left < CHUNK ? (size_t)left : CHUNK;
        if (!(rc = imdb_stream_need(s, buf, k, e))) {
            imdb_sha256_update(&c, buf, k);
            rc = imdb_write_all(fd, buf, k, e);
        }
        left -= k;
    }
    uint8_t got[32];
    imdb_sha256_final(&c, got);
    if (!rc && memcmp(got, h, 32) != 0)
        rc = imdb_fail(e, IMDB_ERR_AUTH, "seed: object %s is not the bytes its name says", name);
    if (!rc && imdb_io_fsync(fd) != 0) rc = imdb_fail(e, IMDB_ERR_IO, "seed: objects/%s: fsync: %s", tmp, strerror(errno));
    close(fd);
    if (!rc && imdb_io_renameat(ofd, tmp, ofd, name) != 0)
        rc = imdb_fail(e, IMDB_ERR_IO, "seed: objects/%s: rename: %s", name, strerror(errno));
    if (rc) (void)imdb_io_unlinkat(ofd, tmp, 0);
    return rc;
}

static int object_rec(imdb_stream *s, uint8_t *kind, uint8_t h[32], uint64_t *n, imdb_err *e)
{
    uint8_t rec[1 + 32 + 8];
    if (imdb_stream_need(s, rec, sizeof rec, e)) return e->code;
    *kind = rec[0];
    memcpy(h, rec + 1, 32);
    *n = imdb_get_le64(rec + 33);
    if (*kind < OBJ_SEG || *kind > OBJ_MAN || *n > IMDB_MAX_OBJECT)
        return imdb_fail(e, IMDB_ERR_CORRUPT, "seed: a malformed object record");
    return IMDB_OK;
}

int imdb_seed_take(imdb_db *db, imdb_stream *s, const uint8_t p[IMDB_SEED_PREFIX], imdb_err *e)
{
    if (!db->replica || db->read_only) return imdb_fail(e, IMDB_ERR_STATE, "a seed is taken only by a writable replica");
    if (db->seq || db->nt || db->lake_seq || db->nsegs || db->log_floor)
        return imdb_fail(e, IMDB_ERR_STATE, "a seed is taken only by an empty replica (imagedb init-replica): this one "
                         "holds commit %llu", (unsigned long long)db->seq);
    uint64_t S = imdb_get_le64(p + 8);
    uint32_t hl = imdb_get_le32(p + 16), nobj = imdb_get_le32(p + 20);
    if (memcmp(p, "IMDBSED1", 8) != 0 || imdb_kern()->crc32c(0, p, 24) != imdb_get_le32(p + 24) || !S || hl < 64 ||
        hl > IMDB_SEED_HEAD_MAX || !nobj || nobj > IMDB_SEED_OBJECTS_MAX)
        return imdb_fail(e, IMDB_ERR_CORRUPT, "seed: a malformed prefix");
    db->failed = true; /* from here on the directory moves away from this handle: reopen it */
    uint8_t *head = imdb_alloc((size_t)hl + 4, e), *buf = head ? imdb_alloc(CHUNK, e) : NULL, *mb = NULL;
    size_t ml = 0, nwant = 0;
    sobj *want = NULL;
    bool *got = NULL;
    imdb_manifest m;
    memset(&m, 0, sizeof m);
    int ofd = -1, rc = buf ? IMDB_OK : e->code;
    if (!rc) rc = imdb_stream_need(s, head, (size_t)hl + 4, e);
    if (!rc && imdb_kern()->crc32c(0, head, hl) != imdb_get_le32(head + hl))
        rc = imdb_fail(e, IMDB_ERR_CORRUPT, "seed: its FLOOR is damaged");
    imdb_floor_hd fh;
    imdb_rd r;
    imdb_rd_init(&r, head, hl);
    /* the head as an open checks FLOOR: nothing it names is trusted before */
    if (!rc) rc = imdb_floor_head(db, &r, &fh, e);
    if (!rc && (imdb_rd_left(&r) || fh.floor != S))
        rc = imdb_fail(e, IMDB_ERR_CORRUPT, "seed: its FLOOR is not commit %llu's", (unsigned long long)S);
    if (!rc && (ofd = imdb_open_dir_at(db->dirfd, "objects", e)) < 0) rc = e->code;
    uint8_t kind, h[32];
    uint64_t n;
    if (!rc) rc = object_rec(s, &kind, h, &n, e);
    if (!rc && (kind != OBJ_MAN || memcmp(h, fh.manifest, 32) != 0))
        rc = imdb_fail(e, IMDB_ERR_AUTH, "seed: its first object is not the manifest commit %llu published", (unsigned long long)S);
    if (!rc) rc = take_object(ofd, s, OBJ_MAN, h, n, buf, e);
    char mname[80];
    obj_file(OBJ_MAN, fh.manifest, mname);
    if (!rc) rc = imdb_read_file_at(ofd, mname, &mb, &ml, IMDB_MAX_OBJECT, e);
    if (!rc) rc = imdb_manifest_parse(mb, ml, &m, e);
    if (!rc && (m.seq != S || memcmp(m.db_id, db->db_id, 16) != 0))
        rc = imdb_fail(e, IMDB_ERR_STATE, "seed: the manifest names another commit or database");
    if (!rc) rc = manifest_objects(&m, &want, &nwant, e);
    if (!rc && nobj - 1 != nwant)
        rc = imdb_fail(e, IMDB_ERR_CORRUPT, "seed: %u objects, where the manifest names %llu", nobj - 1,
                       (unsigned long long)nwant);
    if (!rc && !(got = imdb_alloc_array(nwant ? nwant : 1, sizeof *got, e))) rc = e->code;
    for (uint32_t i = 1; !rc && i < nobj; i++) {
        if ((rc = object_rec(s, &kind, h, &n, e))) break;
        sobj key;
        key.kind = kind;
        memcpy(key.h, h, 32);
        const sobj *w = bsearch(&key, want, nwant, sizeof *want, cmp_sobj);
        if (!w || got[w - want]) {
            rc = imdb_fail(e, IMDB_ERR_AUTH, "seed: an object the manifest does not name, or names once");
            break;
        }
        got[w - want] = true;
        rc = take_object(ofd, s, kind, h, n, buf, e);
    }
    if (!rc) rc = imdb_sync_dir(ofd, e);
    /* FLOOR, then LAKE_HEAD: the order a cut keeps (seed.h); the open checks both again */
    imdb_buf f;
    imdb_buf_init(&f);
    if (!rc) {
        imdb_buf_put(&f, head, hl);
        imdb_buf_put_u64(&f, ml);
        imdb_buf_put(&f, mb, ml);
        if (!f.err) imdb_buf_put_u32(&f, imdb_kern()->crc32c(0, f.p, f.len));
        rc = imdb_buf_check(&f, e);
    }
    if (!rc) rc = imdb_write_file_atomic(db->dirfd, IMDB_FLOOR_NAME, f.p, f.len, 0600, e);
    imdb_buf_free(&f);
    if (!rc) {
        char hex[65], lh[200];
        imdb_hex(fh.manifest, 32, hex);
        int k = snprintf(lh, sizeof lh, "imagedb-lake 1\nseq %llu\nmanifest %s\n", (unsigned long long)S, hex);
        rc = imdb_write_file_atomic(db->dirfd, "LAKE_HEAD", lh, (size_t)k, 0600, e);
    }
    if (!rc) db->seeded = S;
    imdb_free(got);
    imdb_free(want);
    imdb_manifest_free(&m);
    imdb_free(mb);
    imdb_free(buf);
    imdb_free(head);
    if (ofd >= 0) close(ofd);
    return rc;
}

int imdb_seed_leftovers(imdb_db *db, imdb_err *e)
{
    if (faccessat(db->dirfd, "LAKE_HEAD", F_OK, AT_SYMLINK_NOFOLLOW) == 0) return IMDB_OK;
    int lfd = imdb_open_dir_at(db->dirfd, IMDB_LOG_DIR, e);
    if (lfd < 0) return e->code;
    uint64_t *segs = NULL;
    size_t n = 0;
    int rc = imdb_logdir_list(lfd, &segs, &n, e);
    imdb_free(segs);
    close(lfd);
    if (rc || n) return rc; /* a replica that applied a commit: nothing of a seed's */
    bool any = false;
    if (imdb_io_unlinkat(db->dirfd, IMDB_FLOOR_NAME, 0) == 0) any = true;
    else if (errno != ENOENT) return imdb_fail(e, IMDB_ERR_IO, "FLOOR: %s", strerror(errno));
    int ofd = imdb_open_dir_at(db->dirfd, "objects", e);
    if (ofd < 0) return e->code;
    int dfd = dup(ofd);
    DIR *d = dfd >= 0 ? imdb_io_fdopendir(dfd) : NULL;
    if (!d) {
        if (dfd >= 0) close(dfd);
        close(ofd);
        return imdb_fail(e, IMDB_ERR_IO, "objects: cannot list directory");
    }
    for (struct dirent *de; !rc && (errno = 0, de = imdb_io_readdir(d));) {
        if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0) continue;
        if (imdb_io_unlinkat(ofd, de->d_name, 0) != 0 && errno != ENOENT)
            rc = imdb_fail(e, IMDB_ERR_IO, "objects: a seed's leftover: %s", strerror(errno));
        any = true;
    }
    closedir(d);
    if (!rc && any) rc = imdb_sync_dir(ofd, e);
    close(ofd);
    if (!rc && any) rc = imdb_sync_dir(db->dirfd, e);
    return rc;
}
