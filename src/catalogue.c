/* P2 D1.1: the backup catalogue (catalogue.h). */
#include "catalogue.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

#include "cpu.h"
#include "db_internal.h"
#include "fsio.h"
#include "limits.h"
#include "log.h"
#include "logdir.h"

#define CAT_MAGIC "imagedb-catalogue"
#define CAT_FIELDS 10

void imdb_catalogue_free(imdb_catalogue *c)
{
    for (size_t i = 0; i < c->nb; i++) imdb_free(c->b[i].name);
    imdb_free(c->b);
    imdb_free(c->er);
    memset(c, 0, sizeof *c);
}

static bool lower_hex(const char *p, size_t n)
{
    for (size_t i = 0; i < n; i++)
        if (!((p[i] >= '0' && p[i] <= '9') || (p[i] >= 'a' && p[i] <= 'f'))) return false;
    return true;
}

/* a canonical decimal: digits, no sign, no leading zero */
static bool cat_num(const char *p, size_t n, uint64_t *out)
{
    if (n == 0 || n > 20 || (n > 1 && p[0] == '0')) return false;
    uint64_t v = 0;
    for (size_t i = 0; i < n; i++)
        if (p[i] < '0' || p[i] > '9' || imdb_mul_ovf(v, (uint64_t)10, &v) || imdb_add_ovf(v, (uint64_t)(p[i] - '0'), &v))
            return false;
    *out = v;
    return true;
}

static bool cat_hex32(const char *p, size_t n, uint8_t *out, size_t bytes)
{
    return n == 2 * bytes && lower_hex(p, n) && imdb_unhex(p, n, out, bytes);
}

/* a line (no newline): its fields, single spaces apart, the last its record's CRC; the field count, or -1 */
static int cat_fields(const char *l, size_t len, const char *f[CAT_FIELDS], size_t fl[CAT_FIELDS])
{
    int k = 0;
    size_t at = 0;
    while (at <= len) {
        const char *sp = memchr(l + at, ' ', len - at);
        size_t end = sp ? (size_t)(sp - l) : len;
        if (end == at || k == CAT_FIELDS) return -1; /* an empty field: two spaces, or one at an end */
        f[k] = l + at;
        fl[k++] = end - at;
        if (!sp) break;
        at = end + 1;
    }
    if (k < 2 || fl[k - 1] != 8 || !lower_hex(f[k - 1], 8)) return -1;
    uint8_t c[4];
    if (!imdb_unhex(f[k - 1], 8, c, 4)) return -1;
    uint32_t want = (uint32_t)c[0] << 24 | (uint32_t)c[1] << 16 | (uint32_t)c[2] << 8 | c[3];
    if (imdb_kern()->crc32c(0, l, (size_t)(f[k - 1] - l) - 1) != want) return -1;
    return k - 1; /* the record's fields, the CRC not counted */
}

static int cat_bad(imdb_err *e, const char *path, size_t line)
{
    return imdb_fail(e, IMDB_ERR_CORRUPT, "catalogue %s: line %zu is not a catalogue record (a bad field, order or CRC)",
                     path, line);
}

static int cat_push_backup(imdb_catalogue *c, size_t *cap, imdb_err *e)
{
    if (c->nb == *cap) {
        size_t n = *cap ? *cap * 2 : 16;
        imdb_cat_backup *b = imdb_realloc_array(c->b, *cap, n, sizeof *b, e);
        if (!b) return e->code;
        c->b = b;
        *cap = n;
    }
    memset(&c->b[c->nb], 0, sizeof c->b[c->nb]);
    return IMDB_OK;
}

static int cat_push_erase(imdb_catalogue *c, size_t *cap, uint64_t seq, uint64_t t, imdb_err *e)
{
    if (c->ne == *cap) {
        size_t n = *cap ? *cap * 2 : 16;
        imdb_cat_erase *x = imdb_realloc_array(c->er, *cap, n, sizeof *x, e);
        if (!x) return e->code;
        c->er = x;
        *cap = n;
    }
    c->er[c->ne].seq = seq;
    c->er[c->ne++].time_us = t;
    return IMDB_OK;
}

static ssize_t cat_find(const imdb_catalogue *c, const char *name)
{
    for (size_t i = 0; i < c->nb; i++)
        if (strcmp(c->b[i].name, name) == 0) return (ssize_t)i;
    return -1;
}

/* a name's bytes from its hex (never a NUL), its own allocation */
static char *cat_name(const char *p, size_t n, imdb_err *e)
{
    if (n == 0 || n % 2 || n > 2 * (size_t)IMDB_MAX_PATH || !lower_hex(p, n)) return NULL;
    char *s = imdb_alloc(n / 2 + 1, e);
    if (!s) return NULL;
    if (!imdb_unhex(p, n, (uint8_t *)s, n / 2) || memchr(s, 0, n / 2)) {
        imdb_free(s);
        return NULL;
    }
    s[n / 2] = 0;
    return s;
}

static int cat_parse(const char *path, const uint8_t *b, size_t n, imdb_catalogue *c, imdb_err *e)
{
    memset(c, 0, sizeof *c);
    size_t bcap = 0, ecap = 0, line = 0;
    int rc = IMDB_OK;
    for (size_t at = 0; !rc && at < n; line++) {
        const char *l = (const char *)b + at;
        const char *nl = memchr(l, '\n', n - at);
        if (!nl) { /* a torn append: never acknowledged */
            c->torn = true;
            break;
        }
        size_t len = (size_t)(nl - l);
        const char *f[CAT_FIELDS];
        size_t fl[CAT_FIELDS];
        int k = cat_fields(l, len, f, fl);
        uint64_t v[6] = {0};
#define IS(i, s) (fl[i] == sizeof(s) - 1 && memcmp(f[i], s, sizeof(s) - 1) == 0)
        if (k < 0) {
            rc = cat_bad(e, path, line + 1);
        } else if (line == 0) {
            if (!(k == 3 && IS(0, CAT_MAGIC) && IS(1, "1") && cat_hex32(f[2], fl[2], c->db_id, 16))) rc = cat_bad(e, path, 1);
            c->has_head = true;
        } else if (k == 8 && IS(0, "backup")) {
            char *name = cat_name(f[1], fl[1], e);
            bool inc = IS(2, "incremental");
            if (!name || (!inc && !IS(2, "full")) || !cat_num(f[3], fl[3], &v[0]) || !cat_num(f[4], fl[4], &v[1]) ||
                v[0] > v[1] || !cat_num(f[6], fl[6], &v[2]) || !v[2] || !cat_num(f[7], fl[7], &v[3]) ||
                (v[3] && v[3] <= v[2]) || cat_find(c, name) >= 0 || (rc = cat_push_backup(c, &bcap, e))) {
                imdb_free(name);
                if (!rc) rc = cat_bad(e, path, line + 1);
            } else {
                imdb_cat_backup *x = &c->b[c->nb++];
                x->name = name;
                x->incremental = inc;
                x->first = v[0];
                x->last = v[1];
                x->made_us = v[2];
                x->expires_us = v[3];
                if (!cat_hex32(f[5], fl[5], x->last_hash, 32)) rc = cat_bad(e, path, line + 1);
            }
        } else if (k == 3 && IS(0, "erase")) {
            if (!cat_num(f[1], fl[1], &v[0]) || !v[0] || !cat_num(f[2], fl[2], &v[1]) ||
                (c->ne && v[0] <= c->er[c->ne - 1].seq) || v[0] <= c->scanned)
                rc = cat_bad(e, path, line + 1);
            else
                rc = cat_push_erase(c, &ecap, v[0], v[1], e);
        } else if (k == 2 && IS(0, "scan")) {
            if (!cat_num(f[1], fl[1], &v[0]) || v[0] < c->scanned || (c->ne && v[0] < c->er[c->ne - 1].seq))
                rc = cat_bad(e, path, line + 1);
            else
                c->scanned = v[0];
        } else if (k == 2 && IS(0, "gap")) {
            if (!cat_num(f[1], fl[1], &v[0]) || v[0] <= c->scanned) rc = cat_bad(e, path, line + 1);
            else c->gap_to = v[0], c->scanned = v[0]; /* the scan resumes past the floor: what lay below is unknown */
        } else if (k == 3 && IS(0, "forget")) {
            char *name = cat_name(f[1], fl[1], e);
            ssize_t i = name ? cat_find(c, name) : -1;
            imdb_free(name);
            if (i < 0 || c->b[i].forgotten || !cat_num(f[2], fl[2], &v[0])) {
                rc = cat_bad(e, path, line + 1);
            } else {
                c->b[i].forgotten = true;
                c->b[i].forgotten_us = v[0];
            }
        } else {
            rc = cat_bad(e, path, line + 1);
        }
#undef IS
        if (!rc && line == 0 && !c->has_head) rc = cat_bad(e, path, 1);
        at = (size_t)(nl - (const char *)b) + 1;
        if (!rc) c->whole = at;
    }
    if (rc) imdb_catalogue_free(c);
    return rc;
}

static int cat_read_fd(int fd, const char *path, imdb_catalogue *c, imdb_err *e)
{
    uint8_t *b = imdb_alloc(IMDB_CATALOGUE_MAX + 1, e);
    if (!b) return e->code;
    size_t n = 0;
    int rc = IMDB_OK;
    for (;;) { /* from the start, whatever the file offset (O_APPEND writes ignore it) */
        ssize_t k = imdb_io_pread(fd, b + n, IMDB_CATALOGUE_MAX + 1 - n, (off_t)n);
        if (k < 0 && errno == EINTR) continue;
        if (k < 0) {
            rc = imdb_fail(e, IMDB_ERR_IO, "catalogue %s: read: %s", path, strerror(errno));
            break;
        }
        if (k == 0) break;
        n += (size_t)k;
        if (n > IMDB_CATALOGUE_MAX) {
            rc = imdb_fail(e, IMDB_ERR_LIMIT, "catalogue %s is past %u bytes: start another", path, IMDB_CATALOGUE_MAX);
            break;
        }
    }
    if (!rc) rc = cat_parse(path, b, n, c, e);
    imdb_free(b);
    return rc;
}

int imdb_catalogue_read(const char *path, imdb_catalogue *c, imdb_err *e)
{
    memset(c, 0, sizeof *c);
    const char *base;
    int dfd = imdb_open_parent(path, &base, e);
    if (dfd < 0) return e->code;
    int fd = imdb_io_openat(dfd, base, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    int rc = fd < 0 ? imdb_fail(e, errno == ENOENT ? IMDB_ERR_NOTFOUND : IMDB_ERR_IO, "catalogue %s: %s", path, strerror(errno))
                    : IMDB_OK;
    struct stat st;
    if (!rc && (imdb_io_fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)))
        rc = imdb_fail(e, IMDB_ERR_INVALID, "catalogue %s is not a regular file", path);
    if (!rc) rc = cat_read_fd(fd, path, c, e);
    if (fd >= 0) close(fd);
    close(dfd);
    return rc;
}

/* ---- appending, under the lock ----------------------------------------------------------------------------------- */

typedef struct cat_handle {
    const char *path;
    int dfd, fd;
    imdb_catalogue c;
    imdb_buf out; /* one operation's records, written at once */
} cat_handle;

static void cat_unlock(cat_handle *h)
{
    if (h->fd >= 0) close(h->fd);
    if (h->dfd >= 0) close(h->dfd);
    imdb_catalogue_free(&h->c);
    imdb_buf_free(&h->out);
}

static int cat_lock(const char *path, cat_handle *h, imdb_err *e)
{
    memset(h, 0, sizeof *h);
    h->path = path;
    h->fd = -1;
    imdb_buf_init(&h->out);
    const char *base;
    if ((h->dfd = imdb_open_parent(path, &base, e)) < 0) return e->code;
    h->fd = imdb_io_openat(h->dfd, base, O_RDWR | O_APPEND | O_CREAT | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK, 0600);
    if (h->fd < 0) return imdb_fail(e, IMDB_ERR_IO, "catalogue %s: %s", path, strerror(errno));
    struct stat st;
    if (imdb_io_fstat(h->fd, &st) != 0 || !S_ISREG(st.st_mode))
        return imdb_fail(e, IMDB_ERR_INVALID, "catalogue %s is not a regular file", path);
    if (imdb_io_flock(h->fd, LOCK_EX | LOCK_NB) != 0)
        return errno == EWOULDBLOCK ? imdb_fail(e, IMDB_ERR_STATE, "catalogue %s is held: another backup is using it", path)
                                    : imdb_fail(e, IMDB_ERR_IO, "catalogue %s: lock: %s", path, strerror(errno));
    if (cat_read_fd(h->fd, path, &h->c, e)) return e->code;
    if (h->c.torn && (imdb_io_ftruncate(h->fd, (off_t)h->c.whole) != 0 || imdb_io_fsync(h->fd) != 0))
        return imdb_fail(e, IMDB_ERR_IO, "catalogue %s: cutting off a torn append: %s", path, strerror(errno));
    return IMDB_OK;
}

/* one record: its text, a space, its CRC, a newline */
static void cat_rec(cat_handle *h, const char *rec)
{
    size_t n = strlen(rec);
    char crc[16];
    snprintf(crc, sizeof crc, " %08x\n", imdb_kern()->crc32c(0, rec, n));
    imdb_buf_put(&h->out, rec, n);
    imdb_buf_put(&h->out, crc, strlen(crc));
}

static void cat_head(cat_handle *h, const uint8_t db_id[16])
{
    if (h->c.has_head) return;
    char rec[80], hex[33];
    imdb_hex(db_id, 16, hex);
    snprintf(rec, sizeof rec, CAT_MAGIC " 1 %s", hex);
    cat_rec(h, rec);
}

/* the records written at once (a crash leaves at most this append torn), synced with the directory */
static int cat_commit(cat_handle *h, imdb_err *e)
{
    if (imdb_buf_check(&h->out, e)) return e->code;
    int rc = h->out.len ? imdb_write_all(h->fd, h->out.p, h->out.len, e) : IMDB_OK;
    if (!rc && imdb_io_fsync(h->fd) != 0) rc = imdb_fail(e, IMDB_ERR_IO, "catalogue %s: fsync: %s", h->path, strerror(errno));
    if (!rc) rc = imdb_sync_dir(h->dfd, e); /* a new file's name too */
    return rc;
}

/* the erasures in src's log past the catalogue's scan, and the scan's new end */
static int cat_scan(cat_handle *h, const char *src, uint64_t *added, imdb_err *e)
{
    imdb_cat_erase *er = NULL;
    size_t n = 0;
    uint64_t through = 0, floor = 0;
    if (imdb_erasures_in(src, h->c.scanned, &er, &n, &through, &floor, e)) return e->code;
    char rec[96];
    if (floor > h->c.scanned) { /* a RETIRE cut the log below what the catalogue has seen */
        snprintf(rec, sizeof rec, "gap %llu", (unsigned long long)floor);
        cat_rec(h, rec);
    }
    for (size_t i = 0; i < n; i++) {
        snprintf(rec, sizeof rec, "erase %llu %llu", (unsigned long long)er[i].seq, (unsigned long long)er[i].time_us);
        cat_rec(h, rec);
    }
    if (through > (floor > h->c.scanned ? floor : h->c.scanned)) {
        snprintf(rec, sizeof rec, "scan %llu", (unsigned long long)through);
        cat_rec(h, rec);
    }
    if (added) *added = n;
    imdb_free(er);
    return IMDB_OK;
}

static int cat_db_check(cat_handle *h, const uint8_t db_id[16], imdb_err *e)
{
    if (h->c.has_head && memcmp(h->c.db_id, db_id, 16) != 0)
        return imdb_fail(e, IMDB_ERR_INVALID, "catalogue %s lists another database's backups", h->path);
    return IMDB_OK;
}

int imdb_catalogue_add_backup(const char *path, const char *name, const imdb_backup_info *bi, const char *src, imdb_err *e)
{
    cat_handle h;
    int rc = cat_lock(path, &h, e);
    if (!rc) rc = cat_db_check(&h, bi->id.db_id, e);
    if (!rc && cat_find(&h.c, name) >= 0) rc = imdb_fail(e, IMDB_ERR_STATE, "catalogue %s lists %s already", path, name);
    if (!rc && strlen(name) > IMDB_MAX_PATH) rc = imdb_fail(e, IMDB_ERR_LIMIT, "catalogue: the backup's name is too long");
    if (!rc) {
        cat_head(&h, bi->id.db_id);
        rc = cat_scan(&h, src, NULL, e);
    }
    if (!rc) {
        size_t nl = strlen(name);
        char hash[65];
        imdb_hex(bi->last_hash, 32, hash);
        imdb_buf r;
        imdb_buf_init(&r);
        imdb_buf_printf(&r, "backup ");
        for (size_t i = 0; i < nl; i++) imdb_buf_printf(&r, "%02x", (unsigned)(uint8_t)name[i]);
        imdb_buf_printf(&r, " %s %llu %llu %s %llu %llu", bi->incremental ? "incremental" : "full",
                        (unsigned long long)bi->first_seq, (unsigned long long)bi->last_seq, hash,
                        (unsigned long long)bi->made_us, (unsigned long long)bi->expires_us);
        imdb_buf_put_zeros(&r, 1);
        if (!(rc = imdb_buf_check(&r, e))) cat_rec(&h, (const char *)r.p);
        imdb_buf_free(&r);
    }
    if (!rc) rc = cat_commit(&h, e);
    cat_unlock(&h);
    return rc;
}

int imdb_catalogue_note(const char *path, const char *src, uint64_t *added, imdb_err *e)
{
    *added = 0;
    imdb_identity id;
    bool replica = false;
    if (imdb_identity_read(src, &id, &replica, e)) return e->code;
    cat_handle h;
    int rc = cat_lock(path, &h, e);
    if (!rc) rc = cat_db_check(&h, id.db_id, e);
    if (!rc) {
        cat_head(&h, id.db_id);
        rc = cat_scan(&h, src, added, e);
    }
    if (!rc) rc = cat_commit(&h, e);
    cat_unlock(&h);
    return rc;
}

int imdb_catalogue_forget(const char *path, const char *name, imdb_err *e)
{
    cat_handle h;
    int rc = cat_lock(path, &h, e);
    ssize_t i = rc ? -1 : cat_find(&h.c, name);
    if (!rc && (i < 0 || h.c.b[i].forgotten))
        rc = imdb_fail(e, IMDB_ERR_NOTFOUND, "catalogue %s does not list %s%s", path, name, i >= 0 ? " any more" : "");
    if (!rc) {
        imdb_buf r;
        imdb_buf_init(&r);
        imdb_buf_printf(&r, "forget ");
        for (size_t k = 0; name[k]; k++) imdb_buf_printf(&r, "%02x", (unsigned)(uint8_t)name[k]);
        imdb_buf_printf(&r, " %llu", (unsigned long long)imdb_now_us());
        imdb_buf_put_zeros(&r, 1);
        if (!(rc = imdb_buf_check(&r, e))) cat_rec(&h, (const char *)r.p);
        imdb_buf_free(&r);
    }
    if (!rc) rc = cat_commit(&h, e);
    cat_unlock(&h);
    return rc;
}

/* ---- a database's erasures, from its log ------------------------------------------------------------------------- */

int imdb_erasures_in(const char *dir, uint64_t after, imdb_cat_erase **out, size_t *n, uint64_t *through, uint64_t *floor,
                     imdb_err *e)
{
    *out = NULL;
    *n = 0;
    *through = *floor = 0;
    int dirfd = imdb_io_open(dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (dirfd < 0) return imdb_fail(e, IMDB_ERR_IO, "open %s: %s", dir, strerror(errno));
    imdb_durable w;
    bool have = false;
    uint64_t *segs = NULL;
    size_t nsegs = 0, cap = 0;
    int logfd = -1;
    imdb_cat_erase *er = NULL;
    int rc = imdb_durable_read(dirfd, &w, &have, e);
    if (!rc && !have) rc = imdb_fail(e, IMDB_ERR_STATE, "%s has no DURABLE watermark yet: open it for writing once", dir);
    if (!rc && (logfd = imdb_open_dir_at(dirfd, IMDB_LOG_DIR, e)) < 0) rc = e->code;
    if (!rc) rc = imdb_logdir_list(logfd, &segs, &nsegs, e);
    uint64_t first = !rc && nsegs ? segs[0] : w.seq + 1, from = after + 1 > first ? after + 1 : first, at = first;
    size_t si = 0;
    if (!rc) {
        *floor = first - 1;
        si = imdb_logseg_find(segs, nsegs, from);
        if (si == nsegs) si = 0;
        if (from > w.seq) si = nsegs; /* nothing past the start: no segment read */
        if (nsegs) at = segs[si];
    }
    for (; !rc && si < nsegs && at <= w.seq; si++) {
        if (segs[si] != at) {
            rc = imdb_fail(e, IMDB_ERR_CORRUPT, "%s: log segment %llu does not follow commit %llu", dir,
                           (unsigned long long)segs[si], (unsigned long long)(at - 1));
            break;
        }
        imdb_logseg s;
        if ((rc = imdb_logseg_load(logfd, segs[si], &s, e))) break;
        for (size_t off = 0; !rc && at <= w.seq;) {
            size_t fl = 0;
            imdb_err e2 = {0};
            imdb_scan_status st = imdb_logseg_scan(&s, off, &fl, &e2);
            if (st == IMDB_SCAN_END) break;
            if (st != IMDB_SCAN_FRAME || imdb_frame_seq(s.buf + off) != at) {
                rc = imdb_fail(e, IMDB_ERR_CORRUPT, "%s: log segment %llu: commit %llu unreadable", dir,
                               (unsigned long long)segs[si], (unsigned long long)at);
                break;
            }
            if (at >= from) {
                imdb_commit_rec c;
                if ((rc = imdb_frame_decode_body(s.buf + off + IMDB_FRAME_HDR, fl - IMDB_FRAME_HDR, &c, e))) break;
                bool erase = false;
                for (uint32_t i = 0; i < c.nops; i++) erase |= c.ops[i].code == IMDB_OP_ERASE;
                uint64_t t = c.time_us;
                imdb_commit_free(&c);
                if (erase && *n == cap) {
                    size_t nc = cap ? cap * 2 : 16;
                    imdb_cat_erase *x = imdb_realloc_array(er, cap, nc, sizeof *x, e);
                    if (!x) rc = e->code;
                    else er = x, cap = nc;
                }
                if (!rc && erase) {
                    er[*n].seq = at;
                    er[(*n)++].time_us = t;
                }
            }
            off += fl;
            at++;
        }
        imdb_logseg_free(&s);
    }
    if (!rc && at <= w.seq && from <= w.seq)
        rc = imdb_fail(e, IMDB_ERR_CORRUPT, "%s: its log ends before commit %llu, its watermark's", dir,
                       (unsigned long long)w.seq);
    if (!rc) {
        *through = w.seq;
        *out = er;
    } else {
        imdb_free(er);
        *n = 0;
    }
    imdb_free(segs);
    if (logfd >= 0) close(logfd);
    close(dirfd);
    return rc;
}
