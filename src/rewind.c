/* P2 R1.3: rewind (rewind.h; design.md §8, "Rewind"). */
#include "rewind.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <unistd.h>

#include "cpu.h"
#include "db_internal.h"
#include "fsio.h"
#include "lake.h"
#include "log.h"
#include "logdir.h"
#include "repl.h"
#include "writer.h"

/* ---- a log's frames in order ---------------------------------------------------------------------------------------- */

typedef struct fwalk {
    int logfd;
    const uint64_t *segs;
    size_t nsegs, si; /* the segment read next, or loaded: segs[si] */
    imdb_logseg seg;
    bool loaded;
    size_t off;  /* the next frame's offset in seg.buf (untagged form) */
    uint64_t at; /* the seq the next frame must have */
} fwalk;

/* the walk from commit from (a commit in the log) */
static void fwalk_init(fwalk *w, int logfd, const uint64_t *segs, size_t nsegs, uint64_t from)
{
    memset(w, 0, sizeof *w);
    w->logfd = logfd;
    w->segs = segs;
    w->nsegs = nsegs;
    size_t si = imdb_logseg_find(segs, nsegs, from);
    w->si = si == nsegs ? 0 : si;
    w->at = w->si < nsegs ? segs[w->si] : from;
}

static void fwalk_free(fwalk *w)
{
    if (w->loaded) imdb_logseg_free(&w->seg);
    w->loaded = false;
}

/* The next frame (*f, *n: in the walk's segment, good until the next call), which must be commit w->at; *end past the
 * last. A torn or damaged end is an error: the copy's is refused before anything, the primary's is past its watermark
 * (the caller stops there). */
static int fwalk_next(fwalk *w, const uint8_t **f, size_t *n, bool *end, imdb_err *e)
{
    *end = false;
    for (;;) {
        if (!w->loaded) {
            if (w->si >= w->nsegs) {
                *end = true;
                return IMDB_OK;
            }
            if (w->segs[w->si] != w->at)
                return imdb_fail(e, IMDB_ERR_CORRUPT, "log segment %llu does not follow commit %llu",
                                 (unsigned long long)w->segs[w->si], (unsigned long long)(w->at - 1));
            if (imdb_logseg_load(w->logfd, w->segs[w->si], &w->seg, e)) return e->code;
            w->loaded = true;
            w->off = 0;
        }
        size_t fl = 0;
        imdb_err e2 = {0};
        imdb_scan_status st = imdb_logseg_scan(&w->seg, w->off, &fl, &e2);
        if (st == IMDB_SCAN_FRAME) {
            const uint8_t *p = w->seg.buf + w->off;
            if (imdb_frame_seq(p) != w->at)
                return imdb_fail(e, IMDB_ERR_CORRUPT, "log: commit %llu where %llu was expected",
                                 (unsigned long long)imdb_frame_seq(p), (unsigned long long)w->at);
            *f = p;
            *n = fl;
            w->off += fl;
            w->at++;
            return IMDB_OK;
        }
        if (st != IMDB_SCAN_END)
            return imdb_fail(e, IMDB_ERR_CORRUPT, "log segment %llu: %s", (unsigned long long)w->segs[w->si], e2.msg);
        imdb_logseg_free(&w->seg);
        w->loaded = false;
        w->si++;
    }
}

/* Moves the walk to commit q (at or past w->at): the frames before it read and passed. */
static int fwalk_skip_to(fwalk *w, uint64_t q, imdb_err *e)
{
    while (w->at < q) {
        const uint8_t *f;
        size_t n;
        bool end;
        if (fwalk_next(w, &f, &n, &end, e)) return e->code;
        if (end) return imdb_fail(e, IMDB_ERR_CORRUPT, "log: it ends before commit %llu", (unsigned long long)q);
    }
    return IMDB_OK;
}

/* The prev hash of commit first's frame: the floor's hash, for a log that begins past a cut. */
static int frame_prev(const uint8_t *f, size_t n, uint8_t out[32], imdb_err *e)
{
    imdb_commit_rec c;
    if (imdb_frame_decode_body(f + IMDB_FRAME_HDR, n - IMDB_FRAME_HDR, &c, e)) return e->code;
    memcpy(out, c.prev, 32);
    imdb_commit_free(&c);
    return IMDB_OK;
}

/* The hash of commit q of a log beginning at first (q at or past first - 1; 0: the genesis hash), the walk then past
 * it: at q + 1. */
static int hash_at(fwalk *w, const uint8_t db_id[16], uint64_t first, uint64_t q, uint8_t out[32], imdb_err *e)
{
    if (q == 0 && first == 1) {
        imdb_genesis_hash(db_id, out);
        return IMDB_OK;
    }
    const uint8_t *f;
    size_t n;
    bool end;
    if (q + 1 == first) { /* the floor: the first frame's prev; the walk stays at it */
        fwalk tmp;
        fwalk_init(&tmp, w->logfd, w->segs, w->nsegs, first);
        int rc = fwalk_next(&tmp, &f, &n, &end, e);
        if (!rc && end) rc = imdb_fail(e, IMDB_ERR_CORRUPT, "log: no commit past its floor %llu", (unsigned long long)q);
        if (!rc) rc = frame_prev(f, n, out, e);
        fwalk_free(&tmp);
        return rc;
    }
    if (fwalk_skip_to(w, q, e) || fwalk_next(w, &f, &n, &end, e)) return e->code;
    if (end) return imdb_fail(e, IMDB_ERR_CORRUPT, "log: it ends before commit %llu", (unsigned long long)q);
    memcpy(out, imdb_frame_hash(f), 32);
    return IMDB_OK;
}

/* ---- the primary's side: ship --hashes ------------------------------------------------------------------------------ */

typedef struct hout {
    const imdb_sink *out;
    uint8_t buf[IMDB_HASHES_ENTRY * 1600];
    size_t len;
    uint32_t crc;
} hout;

static int hout_flush(hout *h, imdb_err *e)
{
    if (!h->len) return IMDB_OK;
    int rc = h->out->write(h->out->ctx, h->buf, h->len, e);
    h->len = 0;
    return rc;
}

static int hout_entry(hout *h, uint64_t seq, const uint8_t hash[32], imdb_err *e)
{
    if (h->len + IMDB_HASHES_ENTRY > sizeof h->buf && hout_flush(h, e)) return e->code;
    uint8_t *p = h->buf + h->len;
    imdb_le64(p, seq);
    memcpy(p + 8, hash, 32);
    h->crc = imdb_kern()->crc32c(h->crc, p, IMDB_HASHES_ENTRY);
    h->len += IMDB_HASHES_ENTRY;
    return IMDB_OK;
}

static void hashes_header(const uint8_t db_id[16], uint64_t n, const uint8_t base[32], uint64_t l, const uint8_t head[32],
                          uint8_t out[IMDB_HASHES_HDR])
{
    memcpy(out, "IMDBHSH1", 8);
    memcpy(out + 8, db_id, 16);
    imdb_le64(out + 24, n);
    memcpy(out + 32, base, 32);
    imdb_le64(out + 64, l);
    memcpy(out + 72, head, 32);
    imdb_le32(out + 104, imdb_kern()->crc32c(0, out, 104));
}

int imdb_ship_hashes(const char *path, uint64_t after, const imdb_sink *out, imdb_err *e)
{
    int dirfd = imdb_io_open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (dirfd < 0) return imdb_fail(e, IMDB_ERR_IO, "open %s: %s", path, strerror(errno));
    imdb_identity id;
    bool replica = false, have = false;
    imdb_durable w;
    memset(&w, 0, sizeof w);
    uint64_t *segs = NULL;
    size_t nsegs = 0;
    int logfd = -1;
    fwalk fw;
    memset(&fw, 0, sizeof fw);
    hout *h = imdb_alloc(sizeof *h, e);
    int rc = h ? imdb_meta_read_at(dirfd, &id, &replica, e) : e->code;
    if (!rc) rc = imdb_durable_read(dirfd, &w, &have, e);
    if (!rc && !have)
        rc = imdb_fail(e, IMDB_ERR_STATE, "ship: %s has no DURABLE watermark yet; open it for writing once", path);
    if (!rc && (logfd = imdb_open_dir_at(dirfd, IMDB_LOG_DIR, e)) < 0) rc = e->code;
    if (!rc) rc = imdb_logdir_list(logfd, &segs, &nsegs, e);
    uint64_t l = w.seq, first = nsegs ? segs[0] : l + 1;
    if (!rc && after < l && after + 1 < first)
        rc = imdb_fail(e, IMDB_ERR_STATE, "ship --hashes: the log before commit %llu is retired here: start at %llu or "
                       "later", (unsigned long long)first, (unsigned long long)(first - 1));
    uint8_t base[32] = {0}, hdr[IMDB_HASHES_HDR];
    if (!rc) {
        h->out = out;
        fwalk_init(&fw, logfd, segs, nsegs, after >= first ? after : first);
        if (after == l) memcpy(base, w.head, 32); /* nothing past it: the watermark names it */
        else if (after < l) rc = hash_at(&fw, id.db_id, first, after, base, e);
    }
    if (!rc) {
        hashes_header(id.db_id, after, base, l, w.head, hdr);
        rc = out->write(out->ctx, hdr, sizeof hdr, e);
    }
    if (!rc && after < l && fw.at < after + 1) rc = fwalk_skip_to(&fw, after + 1, e); /* the floor's case: at first */
    for (uint64_t q = after + 1; !rc && q <= l; q++) { /* the durable commits: whole frames, whatever is past them */
        const uint8_t *f;
        size_t n;
        bool end;
        if ((rc = fwalk_next(&fw, &f, &n, &end, e))) break;
        if (end) {
            rc = imdb_fail(e, IMDB_ERR_CORRUPT, "ship --hashes: the log ends at commit %llu, before its watermark's %llu",
                           (unsigned long long)(q - 1), (unsigned long long)l);
            break;
        }
        rc = hout_entry(h, q, imdb_frame_hash(f), e);
    }
    if (!rc) rc = hout_flush(h, e);
    if (!rc) {
        uint8_t t[4];
        imdb_le32(t, h->crc);
        rc = out->write(out->ctx, t, sizeof t, e);
    }
    fwalk_free(&fw);
    imdb_free(h);
    imdb_free(segs);
    if (logfd >= 0) close(logfd);
    close(dirfd);
    return rc;
}

/* ---- the copy's side -------------------------------------------------------------------------------------------------- */

struct imdb_rewind {
    char *path;
    int dirfd, lockfd, logfd;
    imdb_identity id;
    bool replica;
    uint64_t *segs;
    size_t nsegs;
    uint64_t first; /* the log's first commit: 1, or past a cut its floor + 1 */
    uint64_t last;
    bool lake;
    uint64_t lake_seq;
    imdb_durable w;
    bool have_w;
};

void imdb_rewind_end(imdb_rewind *rw)
{
    if (!rw) return;
    imdb_free(rw->segs);
    if (rw->logfd >= 0) close(rw->logfd);
    if (rw->lockfd >= 0) close(rw->lockfd);
    if (rw->dirfd >= 0) close(rw->dirfd);
    imdb_free(rw->path);
    imdb_free(rw);
}

/* a reader holding a pin (lake.h) reads a generation the rewind may take from it */
static int pins_free(int dirfd, imdb_err *e)
{
    int pfd = imdb_io_openat(dirfd, IMDB_PINS_DIR, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (pfd < 0) return IMDB_OK;
    int dfd = imdb_io_openat(pfd, ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    DIR *d = dfd >= 0 ? imdb_io_fdopendir(dfd) : NULL;
    if (!d && dfd >= 0) close(dfd);
    int rc = IMDB_OK;
    for (struct dirent *de; !rc && d && (de = imdb_io_readdir(d));) {
        if (!imdb_pin_name_valid(de->d_name)) continue;
        int f = imdb_io_openat(pfd, de->d_name, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
        if (f < 0) continue; /* gone meanwhile */
        if (imdb_io_flock(f, LOCK_EX | LOCK_NB) != 0)
            rc = imdb_fail(e, IMDB_ERR_STATE, "a reader holds pins/%s: stop the copy's readers first", de->d_name);
        close(f);
    }
    if (d) closedir(d);
    close(pfd);
    return rc;
}

static bool exists_at(int dirfd, const char *name)
{
    return faccessat(dirfd, name, F_OK, AT_SYMLINK_NOFOLLOW) == 0;
}

int imdb_rewind_begin(const char *path, imdb_rewind **out, imdb_rewind_report *r, imdb_err *e)
{
    memset(r, 0, sizeof *r);
    *out = NULL;
    imdb_rewind *rw = imdb_alloc(sizeof *rw, e);
    if (!rw) return e->code;
    rw->dirfd = rw->lockfd = rw->logfd = -1;
    size_t pl = strlen(path);
    int rc = (rw->path = imdb_alloc(pl + 1, e)) ? IMDB_OK : e->code;
    if (!rc) memcpy(rw->path, path, pl + 1);
    if (!rc && (rw->dirfd = imdb_io_open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)) < 0)
        rc = imdb_fail(e, IMDB_ERR_IO, "open %s: %s", path, strerror(errno));
    if (!rc) {
        rw->lockfd = imdb_io_openat(rw->dirfd, "LOCK", O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0600);
        if (rw->lockfd < 0 || imdb_io_flock(rw->lockfd, LOCK_EX | LOCK_NB) != 0)
            rc = imdb_fail(e, IMDB_ERR_STATE, "%s is in use by another process (a writer or a follower): stop it first",
                           path);
    }
    if (!rc) rc = imdb_meta_read_at(rw->dirfd, &rw->id, &rw->replica, e);
    if (!rc && exists_at(rw->dirfd, IMDB_SIGNING_NEXT_NAME))
        rc = imdb_fail(e, IMDB_ERR_STATE, "a key change is pending (signing.key.next): open the copy once to settle it");
    if (!rc) rc = pins_free(rw->dirfd, e);
    if (!rc) {
        imdb_err ed = {0};
        if (imdb_durable_read(rw->dirfd, &rw->w, &rw->have_w, &ed)) rw->have_w = false; /* a torn one: synced from 1 */
    }
    if (!rc && (rw->logfd = imdb_open_dir_at(rw->dirfd, IMDB_LOG_DIR, e)) < 0) rc = e->code;
    if (!rc) rc = imdb_logdir_list(rw->logfd, &rw->segs, &rw->nsegs, e);
    if (!rc) {
        rw->first = rw->nsegs ? rw->segs[0] : 1;
        uint8_t mh[32];
        rc = imdb_lake_head(rw->dirfd, &rw->lake, &rw->lake_seq, mh, e);
    }
    if (!rc && rw->nsegs) { /* the last commit, by the last segment's frames; its end must be clean */
        size_t si = rw->nsegs - 1;
        imdb_logseg s;
        if (!(rc = imdb_logseg_load(rw->logfd, rw->segs[si], &s, e))) {
            uint64_t q = rw->segs[si] - 1;
            size_t off = 0;
            for (;;) {
                size_t fl = 0;
                imdb_err e2 = {0};
                imdb_scan_status st = imdb_logseg_scan(&s, off, &fl, &e2);
                if (st == IMDB_SCAN_FRAME) {
                    if (imdb_frame_seq(s.buf + off) != q + 1) {
                        rc = imdb_fail(e, IMDB_ERR_CORRUPT, "log segment %llu: commit %llu out of order",
                                       (unsigned long long)rw->segs[si], (unsigned long long)imdb_frame_seq(s.buf + off));
                        break;
                    }
                    q++;
                    off += fl;
                    continue;
                }
                if (st != IMDB_SCAN_END)
                    rc = imdb_fail(e, IMDB_ERR_STATE, "the end of the copy's log is torn or damaged (%s): open it once (a "
                                   "torn end is dropped), or run imagedb recover", e2.msg);
                break;
            }
            rw->last = q;
            imdb_logseg_free(&s);
        }
    }
    if (!rc) {
        r->last = rw->last;
        r->replica = rw->replica;
        r->lowest = rw->first > 1 ? (rw->lake && rw->lake_seq > rw->first - 1 ? rw->lake_seq : rw->first - 1) : 0;
        *out = rw;
        return IMDB_OK;
    }
    imdb_rewind_end(rw);
    return rc;
}

/* exactly n bytes of the primary's hashes */
static int hread(imdb_read_fn rfn, void *ctx, void *p, size_t n, imdb_err *e)
{
    size_t got = 0;
    if (rfn(ctx, p, n, &got, e)) return e->code;
    if (got != n)
        return imdb_fail(e, IMDB_ERR_CORRUPT, "the primary's hashes ended early (is CMD `imagedb ship PRIMARY --hashes "
                         "--after {after}`, and did it fail?)");
    return IMDB_OK;
}

/* the frames past f to FILE (an operator's path: made exclusively, synced with its directory) */
static int save_frames(imdb_rewind *rw, uint64_t f, const char *save, uint64_t *saved, imdb_err *e)
{
    const char *sbase;
    int sdir = imdb_open_parent(save, &sbase, e);
    if (sdir < 0) return sdir;
    int sfd = imdb_io_openat(sdir, sbase, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (sfd < 0) {
        int err = errno;
        close(sdir);
        return imdb_fail(e, IMDB_ERR_IO, "create %s: %s (FILE is never written over: give another)", save,
                         strerror(err));
    }
    fwalk fw;
    fwalk_init(&fw, rw->logfd, rw->segs, rw->nsegs, f + 1);
    int rc = fwalk_skip_to(&fw, f + 1, e);
    *saved = 0;
    while (!rc && fw.at <= rw->last) {
        const uint8_t *fr;
        size_t n;
        bool end;
        if ((rc = fwalk_next(&fw, &fr, &n, &end, e))) break;
        if (end) {
            rc = imdb_fail(e, IMDB_ERR_CORRUPT, "log: it ends before commit %llu", (unsigned long long)fw.at);
            break;
        }
        if (!(rc = imdb_write_all(sfd, fr, n, e))) (*saved)++;
    }
    fwalk_free(&fw);
    if (!rc && imdb_io_fsync(sfd) != 0) rc = imdb_fail(e, IMDB_ERR_IO, "fsync %s: %s", save, strerror(errno));
    close(sfd);
    if (!rc) rc = imdb_sync_dir(sdir, e); /* its name too, before anything is cut */
    if (rc) imdb_io_unlinkat(sdir, sbase, 0); /* nothing is cut yet: the log still holds them */
    close(sdir);
    return rc;
}

/* The copy's commits past f: none an ERASE or a RETIRE (each changed the log, or what the lake can be rebuilt from,
 * below f). */
static int check_past(imdb_rewind *rw, uint64_t f, imdb_err *e)
{
    fwalk fw;
    fwalk_init(&fw, rw->logfd, rw->segs, rw->nsegs, f + 1);
    int rc = fwalk_skip_to(&fw, f + 1, e);
    while (!rc && fw.at <= rw->last) {
        const uint8_t *fr;
        size_t n;
        bool end;
        if ((rc = fwalk_next(&fw, &fr, &n, &end, e))) break;
        if (end) {
            rc = imdb_fail(e, IMDB_ERR_CORRUPT, "log: it ends before commit %llu", (unsigned long long)fw.at);
            break;
        }
        imdb_commit_rec c;
        if ((rc = imdb_frame_decode_body(fr + IMDB_FRAME_HDR, n - IMDB_FRAME_HDR, &c, e))) break;
        for (uint32_t i = 0; !rc && i < c.nops; i++) {
            if (c.ops[i].code == IMDB_OP_ERASE)
                rc = imdb_fail(e, IMDB_ERR_STATE, "commit %llu, past the fork point %llu, is an ERASE: what it removed "
                               "below the fork cannot be put back; seed this copy again", (unsigned long long)c.seq,
                               (unsigned long long)f);
            else if (c.ops[i].code == IMDB_OP_RETIRE)
                rc = imdb_fail(e, IMDB_ERR_STATE, "commit %llu, past the fork point %llu, is a RETIRE: it cut the log "
                               "below the fork; seed this copy again", (unsigned long long)c.seq, (unsigned long long)f);
        }
        imdb_commit_free(&c);
    }
    fwalk_free(&fw);
    return rc;
}

/* --demote: a replica of the history it is rewound onto, its old key kept aside. The key goes first and META last, each
 * step skipped when done: a crash between them leaves a primary that cannot sign (fenced), and rewind --demote run
 * again finishes it */
static int set_aside(int dirfd, const char *name, const char *aside, imdb_err *e)
{
    if (!exists_at(dirfd, name)) return IMDB_OK;
    if (imdb_io_renameat(dirfd, name, dirfd, aside) != 0) return imdb_fail(e, IMDB_ERR_IO, "%s: %s", name, strerror(errno));
    return imdb_sync_dir(dirfd, e);
}

static int demote(imdb_rewind *rw, imdb_err *e)
{
    int rc = set_aside(rw->dirfd, "signing.key", "signing.key.demoted", e);
    if (!rc) rc = set_aside(rw->dirfd, IMDB_REPLICAS_DIR, IMDB_REPLICAS_DIR ".demoted", e);
    if (!rc) rc = imdb_meta_write_at(rw->dirfd, &rw->id, true, e);
    if (!rc) rc = imdb_sync_dir(rw->dirfd, e);
    return rc;
}

/* the log cut after f: the segments wholly past it removed newest first, the one holding f + 1 cut */
static int cut_log(imdb_rewind *rw, uint64_t f, imdb_err *e)
{
    int rc = IMDB_OK;
    size_t keep = rw->nsegs; /* the segments with first <= f */
    while (keep && rw->segs[keep - 1] > f) keep--;
    for (size_t si = rw->nsegs; !rc && si > keep; si--) {
        char name[IMDB_LOGSEG_NAME + 1];
        imdb_logseg_name(rw->segs[si - 1], name);
        if (imdb_io_unlinkat(rw->logfd, name, 0) != 0)
            rc = imdb_fail(e, IMDB_ERR_IO, "cannot remove log segment %s: %s", name, strerror(errno));
        else if (imdb_io_fsync(rw->logfd) != 0)
            rc = imdb_fail(e, IMDB_ERR_IO, "fsync(log/) failed: %s", strerror(errno));
    }
    if (rc || !keep) return rc;
    uint64_t sf = rw->segs[keep - 1];
    imdb_logseg s;
    if (imdb_logseg_load(rw->logfd, sf, &s, e)) return e->code;
    size_t off = 0; /* the end of frame f in s.buf */
    for (uint64_t q = sf; !rc && q <= f; q++) {
        size_t fl = 0;
        imdb_err e2 = {0};
        if (imdb_logseg_scan(&s, off, &fl, &e2) != IMDB_SCAN_FRAME || imdb_frame_seq(s.buf + off) != q)
            rc = imdb_fail(e, IMDB_ERR_CORRUPT, "log segment %llu: commit %llu not found", (unsigned long long)sf,
                           (unsigned long long)q);
        else
            off += fl;
    }
    char name[IMDB_LOGSEG_NAME + 1];
    imdb_logseg_name(sf, name);
    if (!rc && off < s.len) { /* frames past f in it */
        if (s.tagged) { /* written whole again: its frames to f as one group (as a redaction writes one) */
            imdb_buf whole;
            imdb_buf_init(&whole);
            imdb_tseg_build(sf, s.buf, off, &whole);
            if (!(rc = imdb_buf_check(&whole, e))) rc = imdb_write_file_atomic(rw->logfd, name, whole.p, whole.len, 0600, e);
            imdb_buf_wipe_free(&whole);
        } else {
            int fd = imdb_io_openat(rw->logfd, name, O_WRONLY | O_CLOEXEC | O_NOFOLLOW);
            if (fd < 0 || imdb_io_ftruncate(fd, (off_t)off) != 0 || imdb_io_fsync(fd) != 0)
                rc = imdb_fail(e, IMDB_ERR_IO, "cannot cut log segment %s: %s", name, strerror(errno));
            if (fd >= 0) close(fd);
        }
        if (!rc && imdb_io_fsync(rw->logfd) != 0) rc = imdb_fail(e, IMDB_ERR_IO, "fsync(log/) failed: %s", strerror(errno));
    }
    imdb_logseg_free(&s);
    return rc;
}

int imdb_rewind_run(imdb_rewind *rw, uint64_t after, imdb_read_fn rfn, void *ctx, const char *save, bool demote_it,
                    imdb_rewind_report *r, imdb_err *e)
{
    if (after < r->lowest || after > rw->last)
        return imdb_fail(e, IMDB_ERR_INVALID, "the start %llu is not between this copy's lowest rewind point "
                         "%llu and its last commit %llu", (unsigned long long)after, (unsigned long long)r->lowest,
                         (unsigned long long)rw->last);
    if (!save) return imdb_fail(e, IMDB_ERR_INVALID, "rewind needs --save FILE for the commits it takes off");
    uint8_t hdr[IMDB_HASHES_HDR];
    if (hread(rfn, ctx, hdr, sizeof hdr, e)) return e->code;
    imdb_rd hr; /* untrusted: the transport's bytes (rewind.h's header) */
    imdb_rd_init(&hr, hdr, sizeof hdr);
    const uint8_t *magic = imdb_rd_bytes(&hr, 8), *hdb = imdb_rd_bytes(&hr, 16);
    uint64_t hn = imdb_rd_u64(&hr);
    const uint8_t *base = imdb_rd_bytes(&hr, 32);
    uint64_t l = imdb_rd_u64(&hr);
    const uint8_t *head = imdb_rd_bytes(&hr, 32);
    uint32_t hcrc = imdb_rd_u32(&hr);
    if (hr.err || imdb_rd_left(&hr) || memcmp(magic, "IMDBHSH1", 8) != 0 || imdb_kern()->crc32c(0, hdr, 104) != hcrc)
        return imdb_fail(e, IMDB_ERR_CORRUPT, "CMD's output is not a primary's hashes (ship --hashes), or it is "
                         "damaged");
    if (memcmp(hdb, rw->id.db_id, 16) != 0)
        return imdb_fail(e, IMDB_ERR_VERIFY, "the hashes are another database's");
    if (hn != after)
        return imdb_fail(e, IMDB_ERR_INVALID, "the hashes start after commit %llu, not %llu: give CMD --after "
                         "{after}", (unsigned long long)hn, (unsigned long long)after);
    r->primary = l;
    uint64_t lo = l < after ? l : after;
    if (lo < r->lowest)
        return imdb_fail(e, IMDB_ERR_STATE, "the primary's last commit %llu is below this copy's lowest rewind "
                         "point %llu: seed it again", (unsigned long long)l, (unsigned long long)r->lowest);
    fwalk fw;
    fwalk_init(&fw, rw->logfd, rw->segs, rw->nsegs, lo >= rw->first ? lo : rw->first);
    uint8_t own[32];
    int rc = hash_at(&fw, rw->id.db_id, rw->first, lo, own, e);
    uint64_t f = lo;
    if (!rc && l <= after) { /* nothing past the start on the primary: its last commit is the comparison */
        if (memcmp(own, head, 32) != 0)
            rc = imdb_fail(e, IMDB_ERR_STATE, "the histories differ at or below commit %llu: start lower "
                           "(--from; this copy's lowest rewind point is %llu)", (unsigned long long)l,
                           (unsigned long long)r->lowest);
    } else if (!rc && memcmp(own, base, 32) != 0) {
        rc = imdb_fail(e, IMDB_ERR_STATE, "the histories differ at or below commit %llu: start lower (--from; "
                       "this copy's lowest rewind point is %llu)", (unsigned long long)after, (unsigned long long)r->lowest);
    }
    bool same = !rc;
    uint32_t crc = 0;
    for (uint64_t q = after + 1; !rc && q <= l; q++) { /* every entry, read to the trailer */
        uint8_t ent[IMDB_HASHES_ENTRY];
        if ((rc = hread(rfn, ctx, ent, sizeof ent, e))) break;
        crc = imdb_kern()->crc32c(crc, ent, sizeof ent);
        imdb_rd er;
        imdb_rd_init(&er, ent, sizeof ent);
        uint64_t eq = imdb_rd_u64(&er);
        const uint8_t *eh = imdb_rd_bytes(&er, 32);
        if (er.err || eq != q) {
            rc = imdb_fail(e, IMDB_ERR_CORRUPT, "the primary's hashes are out of order at commit %llu",
                           (unsigned long long)q);
            break;
        }
        if (!same || q > rw->last) continue;
        const uint8_t *fr;
        size_t n;
        bool end;
        if ((rc = fwalk_next(&fw, &fr, &n, &end, e))) break;
        if (end) {
            rc = imdb_fail(e, IMDB_ERR_CORRUPT, "log: it ends before commit %llu", (unsigned long long)q);
            break;
        }
        if (memcmp(imdb_frame_hash(fr), eh, 32) == 0) f = q;
        else same = false;
    }
    fwalk_free(&fw);
    if (!rc) {
        uint8_t t[4];
        if (!(rc = hread(rfn, ctx, t, sizeof t, e)) && imdb_get_le32(t) != crc)
            rc = imdb_fail(e, IMDB_ERR_CORRUPT, "the primary's hashes are damaged (their checksum)");
    }
    if (rc) return rc;
    r->fork = f;
    if (f == rw->last) {
        r->nothing = true;
        return imdb_fail(e, IMDB_ERR_STATE, "nothing to rewind: this copy holds the primary's history through "
                         "its last commit %llu (the primary is at %llu)", (unsigned long long)rw->last,
                         (unsigned long long)l);
    }
    if (!rw->replica && !demote_it)
        return imdb_fail(e, IMDB_ERR_STATE, "%s is a primary: --demote makes it a replica of the history it is "
                         "rewound onto (its signing key kept aside)", rw->path);
    if (rw->replica && demote_it) return imdb_fail(e, IMDB_ERR_INVALID, "--demote: %s is a replica already", rw->path);
    if (demote_it && ((exists_at(rw->dirfd, "signing.key") && exists_at(rw->dirfd, "signing.key.demoted")) ||
                      (exists_at(rw->dirfd, IMDB_REPLICAS_DIR) && exists_at(rw->dirfd, IMDB_REPLICAS_DIR ".demoted"))))
        return imdb_fail(e, IMDB_ERR_STATE, "signing.key and signing.key.demoted (or replicas/ and replicas.demoted) are both "
                         "there: move the .demoted one aside first");
    bool drop_lake = rw->lake && rw->lake_seq > f;
    if (drop_lake && rw->first > 1) /* below the lowest point: refused above; kept for a caller that skipped it */
        return imdb_fail(e, IMDB_ERR_STATE, "the lake was published past the fork point and the log below "
                         "commit %llu is retired here: seed this copy again", (unsigned long long)rw->first);
    if ((rc = check_past(rw, f, e))) return rc;
    /* from here on, in order: each step durable before the next (rewind.h) */
    if ((rc = save_frames(rw, f, save, &r->saved, e))) return rc;
    if (demote_it) {
        if ((rc = demote(rw, e))) return rc;
        r->demoted = true;
    }
    uint8_t seed[IMDB_SEED_LEN]; /* a new incarnation, under the lock this rewind holds (imdb_replica_key_new takes it) */
    imdb_signer ks;
    rc = imdb_random(seed, sizeof seed, e);
    if (!rc) rc = imdb_write_file_atomic(rw->dirfd, IMDB_REPLICA_KEY_NAME, seed, sizeof seed, 0600, e);
    if (!rc) {
        imdb_signer_init(&ks, seed);
        memcpy(r->replica_pk, ks.pk, IMDB_PUBKEY_LEN);
        imdb_signer_wipe(&ks);
    }
    imdb_wipe(seed, sizeof seed);
    if (rc) return rc;
    if (drop_lake) {
        if (imdb_io_unlinkat(rw->dirfd, "LAKE_HEAD", 0) != 0 && errno != ENOENT)
            return imdb_fail(e, IMDB_ERR_IO, "cannot remove LAKE_HEAD: %s", strerror(errno));
        if ((rc = imdb_sync_dir(rw->dirfd, e))) return rc;
        r->lake_dropped = true;
    }
    /* "synced" must be true of every kept commit: a --nosync copy may have frames past its watermark not yet on disk */
    if ((rc = imdb_log_sync_segments(rw->logfd, rw->segs, rw->nsegs, rw->have_w && rw->w.synced ? rw->w.seq + 1 : 1, e)))
        return rc;
    imdb_durable nw = {.seq = f, .synced = true};
    fwalk_init(&fw, rw->logfd, rw->segs, rw->nsegs, f >= rw->first ? f : rw->first);
    rc = hash_at(&fw, rw->id.db_id, rw->first, f, nw.head, e);
    fwalk_free(&fw);
    uint8_t wb[IMDB_DURABLE_LEN];
    if (!rc) {
        imdb_durable_encode(&nw, wb);
        rc = imdb_write_file_atomic(rw->dirfd, IMDB_DURABLE_NAME, wb, sizeof wb, 0600, e);
    }
    if (!rc) rc = cut_log(rw, f, e);
    if (!rc) r->applied = true;
    return rc;
}
