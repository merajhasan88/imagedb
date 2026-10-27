/*
 * Fault injection and crash tests (deferred.md R7).
 *
 * Every file system call and allocation of the engine goes through fsio.c's
 * hooks. A scenario runs in a forked child, where the worker pool runs inline,
 * so its calls come in the same order every run. A first run counts the calls;
 * then each run faults one of them: it fails (EIO, ENOSPC, or a short write),
 * or the process crashes there. The child reports every commit whose call
 * returned success through a pipe: the external acknowledgement record. The
 * parent then checks what must hold after any fault: the writable open
 * succeeds (a crash only loses what was never synced, so refusing would be a
 * bug); every acknowledged commit is there with its hash; VERIFY passes; erased
 * bytes are in no file once the ERASE is in the log; a failed fdatasync stopped
 * the handle (fail-stop).
 *
 * Crashes are checked against a MODEL of a power cut, not a real one. The
 * tracker keeps the durable state of the directory tree as POSIX promises it (a
 * file's bytes after its fsync or fdatasync; a directory's entries after the
 * directory's fsync) and, at the crash, rebuilds the tree as one state a file
 * system may show afterwards: everything written (a process crash), only what
 * was synced (a power cut), what was synced plus a torn or zero-filled part of
 * later appends, or a mix per directory and file. Real power-cut states come
 * from dm-log-writes (tests/crash/, R7d).
 *
 * By default every sync, write, truncate, rename, unlink and mkdir is faulted,
 * and every 7th other call and allocation; IMDB_FAULT_FULL=1 faults every one.
 */
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <ftw.h>
#include <limits.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include "../../src/lake.h"
#include "../../src/logdir.h"
#include "../../src/repl.h"
#include "../../src/sql.h"
#include "../../src/writer.h"
#include "thelp.h"

#if defined(__has_feature)
#if __has_feature(address_sanitizer)
#define IMDB_TEST_ASAN 1
#endif
#endif
#if defined(__SANITIZE_ADDRESS__) || defined(IMDB_TEST_ASAN) /* gcc's spelling, then clang's */
#include <sanitizer/lsan_interface.h>
/* A child ends in _exit or a modelled power cut, which skip LeakSanitizer's check at exit: a run
 * that returned is checked here (one that crashed at its fault point keeps its memory, by design).
 * The registry fork copied names the parent's pool workers, which do not exist here and were
 * parked at the fork; LeakSanitizer warns about each ("not suspended"), so its report goes to a
 * file in the run and only the other lines are shown. */
static bool leaks_found(const char *run)
{
    char path[700];
    snprintf(path, sizeof path, "%s/lsan.txt", run);
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600), saved = dup(2);
    if (fd >= 0 && saved >= 0) dup2(fd, 2);
    bool leaked = __lsan_do_recoverable_leak_check() != 0;
    if (saved >= 0) {
        dup2(saved, 2);
        close(saved);
    }
    if (fd >= 0) close(fd);
    FILE *f = leaked ? fopen(path, "r") : NULL;
    char line[512];
    while (f && fgets(line, sizeof line, f))
        if (!strstr(line, "was not suspended")) fputs(line, stderr);
    if (f) fclose(f);
    return leaked;
}
#else
static bool leaks_found(const char *run)
{
    (void)run;
    return false;
}
#endif

/* A writer that dies on purpose keeps its handle open: what the handle owns is no leak.
 * LeakSanitizer takes an ignored object's referents as reachable too (an ignored object holding
 * the only pointer to another leaves both unreported), so the rest of the run stays checked. */
static void abandon_handle(imdb_db *db)
{
#if defined(__SANITIZE_ADDRESS__) || defined(IMDB_TEST_ASAN)
    __lsan_ignore_object(db);
#else
    (void)db;
#endif
}

/* ---- the durable-state tracker (child only) ------------------------------------ */

#define TF_NODES 4096
#define TF_DIRS 64

typedef struct tver {
    uint64_t sector;
    uint8_t b[IMDB_TSEG_SECTOR];
} tver;

typedef struct tnode {
    dev_t dev;
    ino_t ino;
    int fd; /* held open, so the inode number cannot be reused during the run */
    bool dir;
    uint8_t *dur; /* durable bytes of a file (NULL with ndur 0: none synced) */
    size_t ndur;
    /* a tagged log segment (design.md §3): every sector written since its last sync, in order, each a
     * version a power cut may show instead of the durable one (sector by sector, independently) */
    struct tver *ver;
    size_t nver, capver;
} tnode;

typedef struct tent {
    char name[96];
    int node;
} tent;

typedef struct tdir {
    int node;
    tent *ent; /* the durable entries */
    size_t nent;
} tdir;

static char g_root[PATH_MAX];
static tnode g_nodes[TF_NODES];
static int g_nnodes;
static tdir g_dirs[TF_DIRS];
static int g_ndirs;

static void die(const char *what)
{
    fprintf(stderr, "    fault tracker: %s (%s)\n", what, strerror(errno));
    _exit(90);
}

static int node_find(dev_t dev, ino_t ino)
{
    for (int i = 0; i < g_nnodes; i++)
        if (g_nodes[i].dev == dev && g_nodes[i].ino == ino) return i;
    return -1;
}

/* A node for an inode we have an fd or a name for (fd >= 0: reopened through /proc). */
static int node_add(const struct stat *st, int dirfd, const char *name, int fd)
{
    int k = node_find(st->st_dev, st->st_ino);
    if (k >= 0) return k;
    if (g_nnodes == TF_NODES) die("too many inodes");
    int own;
    if (fd >= 0) {
        char p[64];
        snprintf(p, sizeof p, "/proc/self/fd/%d", fd);
        own = open(p, O_RDONLY | O_CLOEXEC);
    } else {
        own = openat(dirfd, name, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    }
    if (own < 0) die("cannot hold an inode");
    tnode *n = &g_nodes[g_nnodes];
    memset(n, 0, sizeof *n);
    n->dev = st->st_dev;
    n->ino = st->st_ino;
    n->fd = own;
    n->dir = S_ISDIR(st->st_mode);
    return g_nnodes++;
}

static uint8_t *read_node(int k, size_t *len)
{
    struct stat st;
    if (fstat(g_nodes[k].fd, &st) != 0) die("fstat");
    size_t n = (size_t)st.st_size;
    uint8_t *b = malloc(n ? n : 1);
    if (!b) die("malloc");
    size_t got = 0;
    while (got < n) {
        ssize_t r = pread(g_nodes[k].fd, b + got, n - got, (off_t)got);
        if (r <= 0) break;
        got += (size_t)r;
    }
    *len = got;
    return b;
}

static void snap_file(int k)
{
    free(g_nodes[k].dur);
    g_nodes[k].dur = read_node(k, &g_nodes[k].ndur);
    g_nodes[k].nver = 0; /* synced: no other version of any sector is possible */
}

static tdir *dir_of(int k)
{
    for (int i = 0; i < g_ndirs; i++)
        if (g_dirs[i].node == k) return &g_dirs[i];
    return NULL;
}

/* The directory's current entries (names to nodes). */
static tent *list_now(int k, size_t *n)
{
    int fd = openat(g_nodes[k].fd, ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    DIR *d = fd >= 0 ? fdopendir(fd) : NULL;
    if (!d) die("opendir");
    tent *ent = NULL;
    size_t cnt = 0, cap = 0;
    struct dirent *de;
    while ((de = readdir(d))) {
        if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0) continue;
        struct stat st;
        if (fstatat(dirfd(d), de->d_name, &st, AT_SYMLINK_NOFOLLOW) != 0) continue;
        if (!S_ISREG(st.st_mode) && !S_ISDIR(st.st_mode)) continue;
        if (strlen(de->d_name) >= sizeof ent->name) die("name too long");
        if (cnt == cap) {
            cap = cap ? 2 * cap : 16;
            tent *ne = malloc(cap * sizeof *ne);
            if (!ne) die("malloc");
            if (cnt) memcpy(ne, ent, cnt * sizeof *ne);
            free(ent);
            ent = ne;
        }
        snprintf(ent[cnt].name, sizeof ent[cnt].name, "%s", de->d_name);
        ent[cnt].node = node_add(&st, dirfd(d), de->d_name, -1);
        cnt++;
    }
    closedir(d);
    *n = cnt;
    return ent;
}

static void snap_dir(int k)
{
    tdir *t = dir_of(k);
    if (!t) {
        if (g_ndirs == TF_DIRS) die("too many directories");
        t = &g_dirs[g_ndirs++];
        memset(t, 0, sizeof *t);
        t->node = k;
    }
    free(t->ent);
    t->ent = list_now(k, &t->nent);
}

/* At the start of a run everything on disk counts as durable. */
static void snap_tree(int k)
{
    snap_dir(k);
    tdir *t = dir_of(k);
    for (size_t i = 0; i < t->nent; i++) {
        int c = t->ent[i].node;
        if (g_nodes[c].dir) snap_tree(c);
        else snap_file(c);
        t = dir_of(k); /* g_dirs does not move, but keep the lookup honest */
    }
}

static void tracker_init(const char *root)
{
    if (!realpath(root, g_root)) die("realpath"); /* /proc/self/fd links are absolute */
    struct stat st;
    if (stat(root, &st) != 0) die("stat root");
    int k = node_add(&st, AT_FDCWD, root, -1);
    snap_tree(k);
}

static bool fd_under_root(int fd)
{
    char p[64], target[600];
    snprintf(p, sizeof p, "/proc/self/fd/%d", fd);
    ssize_t n = readlink(p, target, sizeof target - 1);
    if (n <= 0) return false;
    target[n] = 0;
    size_t rl = strlen(g_root);
    return strncmp(target, g_root, rl) == 0 && (target[rl] == 0 || target[rl] == '/');
}

static void on_sync(int fd)
{
    if (!fd_under_root(fd)) return;
    struct stat st;
    if (fstat(fd, &st) != 0) return;
    int k = node_add(&st, -1, NULL, fd);
    if (g_nodes[k].dir) snap_dir(k);
    else snap_file(k);
}

/* ---- crash views ------------------------------------------------------------------ */

enum { V_KILL, V_POWER, V_TORN, V_ZERO, V_MIXED, V_SECTORS, V_COUNT };
static const char *const kViewName[V_COUNT] = {"process kill", "power cut", "power cut, torn appends",
                                               "power cut, zero-filled appends", "power cut, mixed",
                                               "power cut, tagged sectors each any version"};

typedef struct vfile {
    char rel[400];
    bool dir;
    uint8_t *b;
    size_t n;
} vfile;

static vfile *g_view;
static size_t g_nview, g_capview;
static uint64_t g_vrng;

static uint64_t vrand(void)
{
    g_vrng ^= g_vrng << 13;
    g_vrng ^= g_vrng >> 7;
    g_vrng ^= g_vrng << 17;
    return g_vrng;
}

static void view_push(const char *rel, bool dir, uint8_t *b, size_t n)
{
    if (g_nview == g_capview) {
        g_capview = g_capview ? 2 * g_capview : 64;
        vfile *nv = malloc(g_capview * sizeof *nv);
        if (!nv) die("malloc");
        if (g_nview) memcpy(nv, g_view, g_nview * sizeof *nv);
        free(g_view);
        g_view = nv;
    }
    vfile *f = &g_view[g_nview++];
    snprintf(f->rel, sizeof f->rel, "%s", rel);
    f->dir = dir;
    f->b = b;
    f->n = n;
}

/* The bytes a file shows after the crash. */
/* A tagged segment's sectors written since its last sync (design.md §3: the fault model): each is
   kept as a version a power cut may show. The torn write of a crash is noted too. */
static void note_write(int fd, const uint8_t *buf, size_t len, int64_t off)
{
    if (off < 0 || off % IMDB_TSEG_SECTOR || len < IMDB_TSEG_SECTOR || !fd_under_root(fd)) return;
    struct stat st;
    uint8_t magic[4];
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) return;
    bool tagged = (off == 0 && memcmp(buf, "ILT1", 4) == 0) || (pread(fd, magic, 4, 0) == 4 && memcmp(magic, "ILT1", 4) == 0);
    if (!tagged) return;
    tnode *f = &g_nodes[node_add(&st, -1, NULL, fd)];
    for (size_t i = 0; i + IMDB_TSEG_SECTOR <= len; i += IMDB_TSEG_SECTOR) {
        if (f->nver == f->capver) {
            f->capver = f->capver ? 2 * f->capver : 64;
            tver *nv = malloc(f->capver * sizeof *nv);
            if (!nv) die("malloc");
            if (f->nver) memcpy(nv, f->ver, f->nver * sizeof *nv);
            free(f->ver);
            f->ver = nv;
        }
        f->ver[f->nver].sector = (uint64_t)off / IMDB_TSEG_SECTOR + i / IMDB_TSEG_SECTOR;
        memcpy(f->ver[f->nver].b, buf + i, IMDB_TSEG_SECTOR);
        f->nver++;
    }
}

static const tnode *g_sort;
static int cmp_ver(const void *a, const void *b)
{
    size_t x = *(const size_t *)a, y = *(const size_t *)b;
    uint64_t sx = g_sort->ver[x].sector, sy = g_sort->ver[y].sector;
    return sx != sy ? (sx < sy ? -1 : 1) : (x < y ? -1 : x > y);
}

/* A power cut, sector by sector: each sector written since the sync shows its durable state (none,
 * past the durable size) or any one of the versions written since, chosen independently. */
static uint8_t *sector_view(const tnode *f, size_t *n)
{
    size_t *idx = malloc(f->nver * sizeof *idx);
    if (!idx) die("malloc");
    uint64_t top = 0;
    for (size_t i = 0; i < f->nver; i++) {
        idx[i] = i;
        if (f->ver[i].sector + 1 > top) top = f->ver[i].sector + 1;
    }
    g_sort = f;
    qsort(idx, f->nver, sizeof *idx, cmp_ver);
    size_t cap = f->ndur > top * IMDB_TSEG_SECTOR ? f->ndur : (size_t)top * IMDB_TSEG_SECTOR, size = f->ndur;
    uint8_t *b = calloc(1, cap ? cap : 1);
    if (!b) die("malloc");
    if (f->ndur) memcpy(b, f->dur, f->ndur);
    for (size_t i = 0; i < f->nver;) {
        size_t j = i;
        uint64_t s = f->ver[idx[i]].sector;
        while (j < f->nver && f->ver[idx[j]].sector == s) j++;
        size_t pick = (size_t)(vrand() % (j - i + 1)); /* 0: as it was durably */
        if (pick) {
            memcpy(b + s * IMDB_TSEG_SECTOR, f->ver[idx[i + pick - 1]].b, IMDB_TSEG_SECTOR);
            if ((s + 1) * IMDB_TSEG_SECTOR > size) size = (size_t)(s + 1) * IMDB_TSEG_SECTOR;
        }
        i = j;
    }
    free(idx);
    *n = size;
    return b;
}

static uint8_t *file_view(int k, int v, size_t *n)
{
    tnode *f = &g_nodes[k];
    size_t cur_n;
    uint8_t *cur = read_node(k, &cur_n);
    int pick = v;
    if (v == V_MIXED) pick = (int)(vrand() % 4); /* KILL, POWER, TORN or ZERO for this file */
    if (v == V_MIXED && f->nver && vrand() % 5 == 0) pick = V_SECTORS; /* a tagged segment: by sectors too */
    if (pick == V_SECTORS && f->nver) {
        free(cur);
        return sector_view(f, n);
    }
    if (pick == V_SECTORS) pick = V_POWER; /* any other file: what was synced */
    if (pick == V_KILL) {
        *n = cur_n;
        return cur;
    }
    bool append = cur_n > f->ndur && (f->ndur == 0 || memcmp(cur, f->dur, f->ndur) == 0);
    size_t keep = f->ndur;
    if (append && pick == V_TORN) keep = f->ndur + (cur_n - f->ndur) / 2;
    if (append && pick == V_TORN && cur_n >= 4 && memcmp(cur, "ILT1", 4) == 0) keep -= keep % IMDB_TSEG_SECTOR; /* sectors */
    if (append && pick == V_ZERO) {
        memset(cur + f->ndur, 0, cur_n - f->ndur);
        keep = cur_n;
    }
    if (pick == V_POWER || !append) { /* what was synced, and nothing else */
        free(cur);
        uint8_t *b = malloc(f->ndur ? f->ndur : 1);
        if (!b) die("malloc");
        if (f->ndur) memcpy(b, f->dur, f->ndur);
        *n = f->ndur;
        return b;
    }
    *n = keep;
    return cur;
}

static void view_dir(int k, const char *rel, int v)
{
    tdir *t = dir_of(k);
    bool now = v == V_KILL || (v == V_MIXED && (vrand() & 1));
    size_t n = 0;
    tent *ent;
    if (now) {
        ent = list_now(k, &n);
    } else { /* the durable entries (none for a directory never synced) */
        n = t ? t->nent : 0;
        ent = malloc((n ? n : 1) * sizeof *ent);
        if (!ent) die("malloc");
        if (n) memcpy(ent, t->ent, n * sizeof *ent);
    }
    for (size_t i = 0; i < n; i++) {
        char p[400];
        snprintf(p, sizeof p, "%s%s%s", rel, *rel ? "/" : "", ent[i].name);
        if (g_nodes[ent[i].node].dir) {
            view_push(p, true, NULL, 0);
            view_dir(ent[i].node, p, v);
        } else {
            size_t bn;
            uint8_t *b = file_view(ent[i].node, v, &bn);
            view_push(p, false, b, bn);
        }
    }
    free(ent);
}

static int rm_one(const char *path, const struct stat *sb, int flag, struct FTW *ftw)
{
    (void)sb;
    (void)flag;
    return ftw->level ? remove(path) : 0;
}

/* Rebuilds the tree under the root as view v shows it, then the process ends. */
static void crash_now(int v, uint64_t seed)
{
    if (v != V_KILL) {
        g_vrng = seed | 1;
        g_nview = 0;
        view_dir(0, "", v);
        if (nftw(g_root, rm_one, 16, FTW_DEPTH | FTW_PHYS) != 0) die("clear");
        for (size_t i = 0; i < g_nview; i++) {
            char p[1000];
            snprintf(p, sizeof p, "%s/%s", g_root, g_view[i].rel);
            if (g_view[i].dir) {
                if (mkdir(p, 0700) != 0) die("mkdir");
                continue;
            }
            int fd = open(p, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
            if (fd < 0) die("create");
            size_t off = 0;
            while (off < g_view[i].n) {
                ssize_t w = write(fd, g_view[i].b + off, g_view[i].n - off);
                if (w <= 0) die("write");
                off += (size_t)w;
            }
            close(fd);
        }
    }
    _exit(77);
}

/* ---- the fault plan (child only) ---------------------------------------------------- */

enum { A_COUNT, A_ERRNO, A_SHORT, A_CRASH };

typedef struct fplan {
    unsigned mask; /* the classes counted: 1u << IMDB_IO_* */
    uint64_t at;   /* the at-th counted call faults */
    int action;
    int err;
    int view; /* the crash view, also used at the end of a faulted run */
    uint64_t seed;
} fplan;

static fplan g_plan;
static uint64_t g_count, g_counts[IMDB_IO_ALLOC + 1];
static int g_hit_op; /* the faulted call's operation, 0 if none yet */
static void note_hit(int op);

static long hook_before(imdb_io_call *c, void *ctx)
{
    (void)ctx;
    if (c->op <= 0 || c->op > IMDB_IO_ALLOC) return 0;
    g_counts[c->op]++;
    if (!(g_plan.mask & (1u << c->op))) return 0;
    if (++g_count != g_plan.at || g_plan.action == A_COUNT) return 0;
    g_hit_op = c->op;
    note_hit(c->op);
    switch (g_plan.action) {
    case A_CRASH:
        if (c->op == IMDB_IO_WRITE && c->len > 1 && g_plan.view != V_KILL) { /* this write itself torn */
            size_t half = c->len / 2;
            uint8_t magic[4];
            /* a tagged segment tears in whole sectors, the device's unit (design.md §3: a sector
             * written halfway is refused, by design, and is outside this model) */
            if (c->off >= 0 && ((c->off == 0 && c->len >= 4 && memcmp(c->buf, "ILT1", 4) == 0) ||
                                (pread(c->fd, magic, 4, 0) == 4 && memcmp(magic, "ILT1", 4) == 0)))
                half -= half % IMDB_TSEG_SECTOR; /* its header too, the file still empty */
            if (c->off >= 0 && pwrite(c->fd, c->buf, half, (off_t)c->off) == (ssize_t)half) note_write(c->fd, c->buf, half, c->off);
            else (void)!write(c->fd, c->buf, half);
        }
        crash_now(g_plan.view, g_plan.seed);
        return 0;
    case A_SHORT:
        if (c->op == IMDB_IO_WRITE && c->len > 1) return (long)(c->len / 2);
        errno = ENOSPC; /* not a write: another errno than A_ERRNO uses */
        return -1;
    default:
        errno = c->op == IMDB_IO_WRITE && (g_plan.at & 1) ? ENOSPC : g_plan.err;
        return -1;
    }
}

static void hook_after(const imdb_io_call *c, long result, void *ctx)
{
    (void)ctx;
    if ((c->op == IMDB_IO_FSYNC || c->op == IMDB_IO_FDATASYNC) && result == 0) on_sync(c->fd);
    if (c->op == IMDB_IO_WRITE && result > 0) note_write(c->fd, c->buf, (size_t)result, c->off);
}

static const imdb_io_hooks g_hooks = {hook_before, hook_after, NULL};

/* ---- the acknowledgement record ------------------------------------------------------ */

enum { R_ACK = 1, R_CLOSED, R_COUNTS, R_NOTE };

typedef struct frec {
    uint8_t kind;
    uint64_t seq;
    uint8_t head[32];
    uint64_t counts[IMDB_IO_ALLOC + 1];
} frec;

static int g_ackfd = -1;

static void rec_send(const frec *r)
{
    const uint8_t *p = (const uint8_t *)r;
    size_t off = 0;
    while (off < sizeof *r) {
        ssize_t w = write(g_ackfd, p + off, sizeof *r - off);
        if (w <= 0) _exit(91);
        off += (size_t)w;
    }
}

static void ack(imdb_db *db)
{
    frec r;
    memset(&r, 0, sizeof r);
    r.kind = R_ACK;
    r.seq = db->seq;
    memcpy(r.head, db->head, 32);
    rec_send(&r);
}

static void note_hit(int op)
{
    frec r;
    memset(&r, 0, sizeof r);
    r.kind = R_NOTE;
    r.seq = (uint64_t)op;
    rec_send(&r);
}

static void ack_closed(void)
{
    frec r;
    memset(&r, 0, sizeof r);
    r.kind = R_CLOSED;
    rec_send(&r);
}

/* ---- scenarios ------------------------------------------------------------------------ */

enum {
    VIOL_FAILSTOP = 3, VIOL_OPEN = 4, VIOL_PINNED = 5, VIOL_RETAIN = 6, VIOL_INDEX = 7, VIOL_ORDERED = 8, VIOL_JOIN = 9,
    VIOL_LEAK = 10, VIOL_FILL = 11, VIOL_PUTBACK = 12
};

typedef struct fscen {
    const char *name;
    void (*setup)(const char *base); /* parent: the starting state */
    int (*run)(const char *run);     /* child: the workload; 0 or a VIOL_* code */
    bool nosync;                     /* acknowledgements count only once the close completed */
    const char *erased;              /* bytes of subject 42's rows that an ERASE must remove */
    const char *(*base_ok)(const char *base); /* parent: NULL if setup built what the scenario needs */
    bool anchored;                   /* the checks open with the run's external anchor (run/anchor) */
    bool signs;                      /* a recovered primary must sign with the log's current writer key */
    bool strict;                     /* --durable-ack: DURABLE names every acknowledgement (strict_check) */
} fscen;

/* After a failed operation: a failed fdatasync must have stopped the handle. */
static int after_error(imdb_db *db)
{
    if (g_hit_op == IMDB_IO_FDATASYNC && !db->failed) return VIOL_FAILSTOP;
    return 0;
}

static char g_anchor[700]; /* the run's anchor, for the anchored scenarios */

static imdb_db *child_open(const char *dir, int sync)
{
    imdb_open_opts o = {.sync = sync};
    o.anchor = g_anchor[0] ? g_anchor : NULL;
    imdb_db *db = NULL;
    imdb_err e = {0};
    if (imdb_open(dir, &o, &db, &e)) return NULL;
    return db;
}

/* one insert as its own commit; acknowledged when it returns success */
static int put(imdb_db *db, int64_t id, int64_t user, const char *memo)
{
    if (ins1(db, id, user, 100 * id, memo)) return after_error(db) ? VIOL_FAILSTOP : -1;
    ack(db);
    return 0;
}

static char *dir_in(const char *run, const char *sub)
{
    static char p[2][600];
    static int k;
    char *s = p[k++ & 1];
    snprintf(s, 600, "%s/%s", run, sub);
    return s;
}

static void setup_txns(const char *base)
{
    char *p = dir_in(base, "p");
    imdb_err e = {0};
    if (imdb_init(p, false, NULL, &e)) return;
    imdb_db *db = child_open(p, 1);
    if (!db) return;
    if (!make_table(db, &e)) {
        ins1(db, 1, 42, 100, "secret-42-first");
        ins1(db, 2, 7, 200, "plain-7");
        ins1(db, 3, 42, 300, "secret-42-second");
    }
    imdb_close(db);
}

static int run_commits(const char *run)
{
    imdb_db *db = child_open(dir_in(run, "p"), 1);
    if (!db) return 0; /* the open itself was faulted: nothing to acknowledge */
    int v = 0;
    for (int64_t id = 10; id < 14 && !v; id++) {
        int r = put(db, id, id % 2 ? 42 : 7, "row");
        if (r > 0) v = r;
        if (r < 0) break;
    }
    imdb_close(db);
    return v;
}

static int run_nosync(const char *run)
{
    imdb_db *db = child_open(dir_in(run, "p"), 0);
    if (!db) return 0;
    for (int64_t id = 10; id < 14; id++)
        if (put(db, id, 7, "row") < 0) break;
    if (imdb_close(db) == IMDB_OK) ack_closed(); /* only now are the acknowledged commits durable */
    return 0;
}

static int run_checkpoint(const char *run)
{
    imdb_db *db = child_open(dir_in(run, "p"), 1);
    if (!db) return 0;
    imdb_err e = {0};
    int v = 0;
    if (put(db, 10, 7, "row") == 0 && !imdb_checkpoint(db, &e)) {
        ack(db);
        if (put(db, 11, 42, "row") == 0 && !imdb_checkpoint(db, &e)) ack(db);
    } else {
        v = after_error(db);
    }
    imdb_close(db);
    return v;
}

static int run_compact(const char *run)
{
    imdb_db *db = child_open(dir_in(run, "p"), 1);
    if (!db) return 0;
    imdb_err e = {0};
    imdb_table *t = imdb_table_by_name(db, "txns");
    uint64_t vid = pk_lookup(db, 2, db->seq);
    if (t && vid != IMDB_NONE && !imdb_begin(db, &e) && !imdb_delete(db, t, vid, &e) && !imdb_commit(db, &e)) {
        ack(db);
        if (!imdb_checkpoint(db, &e)) {
            ack(db);
            if (!imdb_compact(db, t, db->seq, &e)) ack(db);
        }
    } else if (db->in_txn) {
        imdb_rollback(db);
    }
    imdb_close(db);
    return 0;
}

/* --retain-history: the policy's logged COMPACT ... PURGE runs from the executor after the
 * statements that make it due, here after every third ended version (retain_min lowered from
 * IMDB_RETAIN_MIN_ENDED): a statement acknowledged includes the purge it triggered, if that
 * commit became durable */
static int run_retain(const char *run)
{
    imdb_open_opts o = {.sync = 1, .retain_commits = 1};
    imdb_db *db = NULL;
    imdb_err e = {0};
    if (imdb_open(dir_in(run, "p"), &o, &db, &e)) return 0;
    db->retain_min = 2;
    db->warning[0] = 0; /* only a purge's warning may excuse the check below (an open's may not) */
    imdb_session s;
    imdb_session_init(&s, db);
    static const char *const q[] = {
        "INSERT INTO txns VALUES (10, 7, 1.00, 'x')", "DELETE FROM txns WHERE id = 10",
        "INSERT INTO txns VALUES (11, 7, 1.00, 'x')", "DELETE FROM txns WHERE id = 11",
        "INSERT INTO txns VALUES (12, 7, 1.00, 'x')", "DELETE FROM txns WHERE id = 12", /* due: a purge */
        "UPDATE txns SET memo = 'y' WHERE id = 2",    "DELETE FROM txns WHERE id = 1",
        "INSERT INTO txns VALUES (13, 7, 1.00, 'x')", "DELETE FROM txns WHERE id = 13", /* due again */
    };
    int v = 0, purges = 0;
    size_t done = 0;
    for (size_t i = 0; i < sizeof q / sizeof *q; i++) {
        imdb_result r;
        imdb_err_clear(&e);
        uint64_t h = db->t[0]->horizon;
        if (imdb_exec_one(&s, q[i], strlen(q[i]), NULL, 0, &r, &e)) {
            v = after_error(db);
            break;
        }
        imdb_result_free(&r);
        ack(db);
        purges += db->t[0]->horizon > h;
        done++;
    }
    /* not vacuous: a run nothing faulted (every statement through, no purge warning) purged twice */
    if (!v && done == sizeof q / sizeof *q && !db->warning[0] && !db->failed && purges != 2) v = VIOL_RETAIN;
    imdb_session_close(&s);
    imdb_close(db);
    return v;
}

/* After a failed commit on a handle it left usable: log_put_tagged put back what the sectors held, so
 * no byte past the open group's is non-zero (the scan would mostly drop a frame left behind as torn,
 * so only this sees one). */
static bool put_back_clean(imdb_db *db)
{
    if (db->failed || !db->log_tagged || db->logfd < 0) return true;
    uint64_t s = db->log_group ? imdb_tgroup_at(&db->log_tg) : db->log_phys;
    size_t keep = db->log_group && db->log_tg.len % IMDB_TSEG_PAYLOAD ? 8 + db->log_tg.len % IMDB_TSEG_PAYLOAD : 0;
    uint8_t b[IMDB_TSEG_SECTOR];
    for (uint64_t k = s;; k++) {
        ssize_t n = pread(db->logfd, b, sizeof b, (off_t)(k * IMDB_TSEG_SECTOR));
        if (n <= 0) return true;
        for (size_t i = k == s ? keep : 0; i < (size_t)n; i++)
            if (b[i]) return false;
    }
}

/* A tagged segment's fill (design.md §3, "The fill"): one-row commits of about 60 KB until one extends
 * the fill, then a frame larger than the fill left (written past it in two pieces, extending nothing),
 * then a small commit past it, which extends again; so every call of an extension, and of the put-back
 * after a failed one, is faulted, and a failed commit must leave nothing it wrote behind. */
static int run_fill(const char *run)
{
    imdb_db *db = child_open(dir_in(run, "p"), 1);
    if (!db) return 0;
    db->warning[0] = 0;
    static char memo[60001];
    memset(memo, 'f', sizeof memo - 1);
    int64_t id = 100;
    uint64_t fill = db->log_fill;
    int r = 0;
    bool ext = false, past = false, ext2 = false;
    while (!r && !ext && id < 140) {
        r = put(db, id++, 7, memo);
        ext = !r && db->log_fill != fill; /* these frames fit: only an extension moves the fill */
    }
    imdb_err e = {0};
    imdb_table *t = imdb_table_by_name(db, "txns");
    if (!r && ext && t) {
        int n = (int)((db->log_fill - db->log_phys * IMDB_TSEG_SECTOR) / 60000) + 2, k = 0;
        if (!imdb_begin(db, &e)) {
            for (; k < n; k++) {
                imdb_value v[4];
                row_vals(v, id + k, 42, 100, memo);
                if (imdb_insert(db, t, v, &e)) break;
            }
            if (k < n) imdb_rollback(db);
        }
        if (k == n && !imdb_commit(db, &e) && !imdb_maintain(db, &e)) {
            ack(db);
            past = db->log_fill == db->log_phys * IMDB_TSEG_SECTOR; /* the file ends where the frame does */
            r = put(db, id + n, 7, "row");
            ext2 = !r && db->log_fill - db->log_phys * IMDB_TSEG_SECTOR >= IMDB_LOG_FILL_CHUNK;
        } else {
            r = after_error(db) ? VIOL_FAILSTOP : -1;
        }
    }
    int v = r > 0 ? r : 0;
    if (r < 0 && !put_back_clean(db)) v = VIOL_PUTBACK;
    /* not vacuous: a run nothing faulted (every commit through, r 0) extended at both places, and not
     * after the large frame; one that never extended skipped the rest and fails here too */
    if (!r && !db->warning[0] && !db->failed && !(ext && past && ext2)) v = VIOL_FILL;
    imdb_close(db);
    return v;
}

/* setup_txns, then a CHECKPOINT: the last segment ends (its last commit published a manifest), so the
 * run's first commit, in another process, ends it and makes the next (log_new_segment) */
static void setup_ended(const char *base)
{
    setup_txns(base);
    imdb_db *db = child_open(dir_in(base, "p"), 1);
    if (!db) return;
    imdb_err e = {0};
    imdb_checkpoint(db, &e);
    imdb_close(db);
}

/* A commit after a failed one goes on in the same handle (unless the failure stopped it): on a tagged
 * segment the failed frame's sectors were put back, so the next commit lands where it would have.
 * The failed frames are the larger (30 KB), so one left behind would outlast the frame written over
 * it. */
static int run_retry(const char *run)
{
    imdb_db *db = child_open(dir_in(run, "p"), 1);
    if (!db) return 0;
    static char memo[30001];
    memset(memo, 'r', sizeof memo - 1);
    int v = 0;
    for (int64_t id = 10; id < 14 && !v && !db->failed; id++) {
        int r = put(db, id, 7, id % 2 ? "row" : memo);
        if (r > 0) v = r;
        if (r < 0 && !put_back_clean(db)) v = VIOL_PUTBACK;
    }
    imdb_close(db);
    return v;
}

/* CREATE INDEX: the DDL commits (each alone in its commit) and the structures they build, with a
 * CHECKPOINT between (a version-3 manifest), under every fault point; VERIFY and the auditor then
 * re-derive the definitions. Cross-check stays on: an ordered path that disagrees with the scan
 * is a violation, not an I/O error. The COUNT on the DECIMAL column is index-only, the one on the
 * TEXT column reads its rows, so both kinds run under the faults; a unique two-column index takes
 * an insert and an update (its chains built at creation, in every replay and every open) */
static int run_index(const char *run)
{
    imdb_open_opts o = {.sync = 1};
    imdb_db *db = NULL;
    imdb_err e = {0};
    if (imdb_open(dir_in(run, "p"), &o, &db, &e)) return 0;
    db->warning[0] = 0; /* only a fault's warning may excuse the check below */
    imdb_session s;
    imdb_session_init(&s, db);
    s.cross_check = true;
    static const char *const q[] = {
        "CREATE INDEX t_amount ON txns (amount)",    "INSERT INTO txns VALUES (10, 7, 1.00, 'x')",
        "SELECT COUNT(*) FROM txns WHERE amount BETWEEN 0.50 AND 2.00", "CHECKPOINT",
        "CREATE INDEX t_memo ON txns (memo)",        "CREATE UNIQUE INDEX t_im ON txns (id, memo)",
        "INSERT INTO txns VALUES (11, 7, 3.00, 'z')", "UPDATE txns SET memo = 'y' WHERE id = 2",
        "DROP INDEX t_amount",                       "SELECT COUNT(*) FROM txns WHERE memo >= 'x'",
    };
    int v = 0, ordered = 0;
    size_t done = 0;
    for (size_t i = 0; i < sizeof q / sizeof *q; i++) {
        imdb_result r;
        imdb_err_clear(&e);
        int rc = imdb_exec_one(&s, q[i], strlen(q[i]), NULL, 0, &r, &e);
        if (rc) {
            v = rc == IMDB_ERR_VERIFY && strstr(e.msg, "cross-check") ? VIOL_INDEX : after_error(db);
            break;
        }
        ordered += strstr(r.path, "index(ordered") != NULL; /* either kind */
        imdb_result_free(&r);
        ack(db);
        done++;
    }
    /* not vacuous: a run nothing faulted took the ordered path for both SELECTs */
    if (!v && done == sizeof q / sizeof *q && !db->warning[0] && !db->failed && ordered != 2) v = VIOL_ORDERED;
    imdb_session_close(&s);
    imdb_close(db);
    return v;
}

static bool cell_text(const imdb_cell *c, const char *want)
{
    if (!want) return c->null;
    size_t n = strlen(want);
    return !c->null && c->v.len == n && memcmp(c->v.s, want, n) == 0;
}

/* the answers to run_join's SELECTs (i: the statement), checked whole */
static bool join_answer(size_t i, const imdb_result *r)
{
    const imdb_cell *c = r->cells;
    switch (i) {
    case 2: /* txns 1 and 3 belong to user 42 */
    case 7:
        return r->nrows == 2 && c[0].v.i == 1 && cell_text(&c[1], "ann") && c[2].v.i == 3 && cell_text(&c[3], "ann");
    case 4: /* user 7 is not in users: its row is NULL-extended, which MAX skips */
    case 8:
        return r->nrows == 1 && cell_text(&c[0], "ann") && c[1].v.i == 3;
    case 5: /* cid has no txns: one NULL-extended row, whose MAX is NULL */
    case 9: {
        bool ann = false, cid = false;
        for (uint64_t g = 0; g < r->nrows; g++) {
            const imdb_cell *x = &c[g * 3];
            ann |= cell_text(&x[0], "ann") && x[1].v.i == 2 && cell_text(&x[2], "secret-42-second");
            cid |= cell_text(&x[0], "cid") && x[1].v.i == 1 && cell_text(&x[2], NULL);
        }
        return r->nrows == 2 && ann && cid;
    }
    default:
        return true;
    }
}

/* Joins under every fault point: the build side's hash, lists, kept columns and TEXT chunks, the
 * pairs and their sort, and the result, each allocation failing in turn, with the second table's
 * DDL, rows and a CHECKPOINT committed between (the joins read rows in memory, then segments).
 * The same three again under plan C (join_plan = index: users probed by primary key, txns by
 * subject). Cross-check stays on: a join that answers differently under its second plan is a
 * violation, not an I/O error, and so is a join that succeeds with another answer than the known
 * one, or with another plan than plan C where it is forced */
static int run_join(const char *run)
{
    imdb_open_opts o = {.sync = 1};
    imdb_db *db = NULL;
    imdb_err e = {0};
    if (imdb_open(dir_in(run, "p"), &o, &db, &e)) return 0;
    db->warning[0] = 0;
    imdb_session s;
    imdb_session_init(&s, db);
    s.cross_check = true;
    static const char *const q[] = {
        "CREATE TABLE users (id INT64 PRIMARY KEY, name TEXT)",
        "INSERT INTO users VALUES (42, 'ann'), (9, 'cid')",
        "SELECT t.id, u.name FROM txns AS t JOIN users AS u ON t.user_id = u.id",
        "CHECKPOINT",
        "SELECT MAX(u.name), COUNT(*) FROM txns AS t LEFT JOIN users AS u ON t.user_id = u.id",
        "SELECT u.name, COUNT(*), MAX(t.memo) FROM users AS u LEFT JOIN txns AS t ON u.id = t.user_id GROUP BY u.name",
        "SET join_plan = index",
        "SELECT t.id, u.name FROM txns AS t JOIN users AS u ON t.user_id = u.id",
        "SELECT MAX(u.name), COUNT(*) FROM txns AS t LEFT JOIN users AS u ON t.user_id = u.id",
        "SELECT u.name, COUNT(*), MAX(t.memo) FROM users AS u LEFT JOIN txns AS t ON u.id = t.user_id GROUP BY u.name",
    };
    int v = 0;
    size_t done = 0, joins = 0;
    for (size_t i = 0; i < sizeof q / sizeof *q; i++) {
        imdb_result r;
        imdb_err_clear(&e);
        int rc = imdb_exec_one(&s, q[i], strlen(q[i]), NULL, 0, &r, &e);
        if (rc) {
            v = rc == IMDB_ERR_VERIFY && strstr(e.msg, "cross-check") ? VIOL_JOIN : after_error(db);
            break;
        }
        bool join = strstr(r.path, "join(") != NULL;
        joins += join;
        if (join && !join_answer(i, &r)) v = VIOL_JOIN; /* fault or not: a join that succeeds is right */
        if (join && i >= 7 && strncmp(r.path, "join(index", 10) != 0) v = VIOL_JOIN;
        imdb_result_free(&r);
        if (v) break;
        ack(db);
        done++;
    }
    /* not vacuous: a run nothing faulted ran all six joins */
    if (!v && done == sizeof q / sizeof *q && !db->warning[0] && !db->failed && joins != 6) v = VIOL_JOIN;
    imdb_session_close(&s);
    imdb_close(db);
    return v;
}

static int run_erase(const char *run)
{
    imdb_db *db = child_open(dir_in(run, "p"), 1);
    if (!db) return 0;
    imdb_err e = {0};
    imdb_value k = {.type = IMDB_T_INT64, .i = 42};
    imdb_erase_report rep;
    if (!imdb_erase_subject(db, &k, &rep, &e)) ack(db);
    imdb_close(db);
    return 0;
}

static void setup_erased(const char *base)
{
    setup_txns(base);
    imdb_db *db = child_open(dir_in(base, "p"), 1);
    if (!db) return;
    imdb_err e = {0};
    imdb_checkpoint(db, &e);
    ins1(db, 4, 42, 400, "secret-42-third");
    imdb_close(db);
}

/* A reader pins a generation from before an ERASE (lake.h): the ERASE revokes it, so after a
 * fault anywhere, once the ERASE is in the log no file still holds the erased bytes (the scenario's
 * erased check); a stale pin left by a dead reader goes with the next GC. */
static void setup_erase_pinned(const char *base)
{
    setup_erased(base);
    char p[700];
    snprintf(p, sizeof p, "%s/pins/%064d.pin", dir_in(base, "p"), 0); /* a dead reader's, of no generation */
    spit(p, (const uint8_t *)"", 0);
}

static int run_erase_pinned(const char *run)
{
    imdb_db *db = child_open(dir_in(run, "p"), 1);
    if (!db) return 0;
    imdb_err e = {0};
    int pin = -1;
    if (imdb_lake_pin(db->dirfd, db->lake_manifest, &pin, &e)) {
        imdb_close(db);
        return 0;
    }
    int v = 0;
    for (int k = 0; k < 2 && !v; k++) { /* two publications: only the pin keeps the generation now */
        int r = put(db, 20 + k, 7, "row");
        if (r > 0) v = r;
        if (r < 0 || imdb_checkpoint(db, &e)) break;
    }
    imdb_value s = {.type = IMDB_T_INT64, .i = 42};
    imdb_erase_report rep;
    if (!v && !imdb_erase_subject(db, &s, &rep, &e)) {
        ack(db);
        /* its cleanup complete while the pin is still held: the pin kept nothing the ERASE removed */
        if (imdb_cleanup_seq(db) >= db->seq && tree_contains(run, "secret-42")) v = VIOL_PINNED;
    }
    imdb_lake_unpin(pin);
    imdb_close(db);
    return v;
}

/* a writable open completing what an ERASE left (redaction, lake, GC) after a crash */
static void setup_erase_crashed(const char *base);

static int run_reopen(const char *run)
{
    imdb_db *db = child_open(dir_in(run, "p"), 1);
    if (db) imdb_close(db);
    return 0;
}

static void setup_replica(const char *base)
{
    setup_erased(base);
    imdb_err e = {0};
    if (imdb_init(dir_in(base, "r"), true, dir_in(base, "p"), &e)) return;
    if (ship_to_file(dir_in(base, "p"), 0, dir_in(base, "stream"), &e)) return;
    /* as ship --acks sends it: its session record first (repl.h) */
    size_t n;
    uint8_t *b = slurp(dir_in(base, "stream"), &n), *w = b ? malloc(IMDB_SESSION_LEN + n) : NULL;
    uint8_t id[16], pk[IMDB_PUBKEY_LEN], nonce[IMDB_NONCE_LEN];
    memset(nonce, 0x33, sizeof nonce);
    if (w && !imdb_read_identity(dir_in(base, "p"), id, pk, &e)) {
        imdb_session_encode(id, nonce, w);
        memcpy(w + IMDB_SESSION_LEN, b, n);
        spit(dir_in(base, "stream"), w, IMDB_SESSION_LEN + n);
    }
    free(w);
    free(b);
}

static int run_replica(const char *run)
{
    imdb_db *db = child_open(dir_in(run, "r"), 1);
    if (!db) return 0;
    uint64_t applied = 0;
    imdb_err e = {0};
    int fd = open(dir_in(run, "stream"), O_RDONLY | O_CLOEXEC);
    int rc = imdb_apply_stream(db, fd, &applied, &e);
    close(fd);
    if (!rc) ack(db);
    imdb_close(db);
    return 0;
}

/* follow's loop: a --nosync replica acknowledging at every point. Each acknowledgement must name a
 * commit that survives any crash (the point syncs first), and a failed sync must stop the handle. */
static int ack_point(void *ctx, imdb_db *db)
{
    (void)ctx;
    ack(db);
    return 0;
}

static int run_replica_acks(const char *run)
{
    imdb_db *db = child_open(dir_in(run, "r"), 0);
    if (!db) return 0;
    uint64_t applied = 0;
    imdb_err e = {0};
    imdb_apply_opts ao = {.applied = ack_point, .every = 1};
    int fd = open(dir_in(run, "stream"), O_RDONLY | O_CLOEXEC);
    int rc = imdb_apply_stream_ex(db, fd, &applied, &ao, &e);
    close(fd);
    int v = rc ? after_error(db) : 0;
    imdb_close(db);
    return v;
}

/* Key rotation (writer.h): after a crash anywhere in it, the directory opens and signs with the
 * log's current key (signing.key.next completed or dropped) and keeps every acknowledged commit. */
static int run_rotate(const char *run)
{
    imdb_db *db = child_open(dir_in(run, "p"), 1);
    if (!db) return 0;
    imdb_err e = {0};
    int v = put(db, 10, 7, "before");
    if (v == 0) {
        if (imdb_rotate_key(db, &e) == IMDB_OK) {
            ack(db);
            v = put(db, 11, 7, "after");
        } else {
            v = after_error(db);
        }
    }
    imdb_close(db);
    return v > 0 ? v : 0;
}

/* Promotion: a replica of a primary with a root key becomes the writer of the next epoch; after a
 * crash anywhere in it, it is still a replica (nothing reached its log) or a primary that signs. */
static void root_seed(uint8_t s[IMDB_SEED_LEN]) { memset(s, 0x61, IMDB_SEED_LEN); }

static void setup_promote(const char *base)
{
    uint8_t seed[IMDB_SEED_LEN];
    root_seed(seed);
    imdb_signer root;
    imdb_signer_init(&root, seed);
    imdb_err e = {0};
    char p[600], r[600], st[600];
    snprintf(p, sizeof p, "%s/p", base);
    snprintf(r, sizeof r, "%s/r", base);
    snprintf(st, sizeof st, "%s/stream", base);
    if (imdb_init_primary(p, root.pk, &e)) return;
    imdb_db *db = child_open(p, 1);
    if (!db) return;
    if (!make_table(db, &e)) {
        ins1(db, 1, 42, 100, "x");
        ins1(db, 2, 7, 200, "y");
    }
    imdb_close(db);
    if (imdb_init(r, true, p, &e) || ship_to_file(p, 0, st, &e)) return;
    imdb_db *rd = child_open(r, 1);
    uint64_t applied;
    if (rd) {
        apply_file(rd, st, &applied, &e);
        imdb_close(rd);
    }
}

static int run_replica_promote(const char *run)
{
    uint8_t seed[IMDB_SEED_LEN];
    root_seed(seed);
    imdb_err e = {0};
    imdb_promote_opts po = {.old_writer_stopped = true};
    imdb_promote_result pr;
    if (imdb_promote(dir_in(run, "r"), seed, &po, &pr, &e)) return 0;
    imdb_db *db = child_open(dir_in(run, "r"), 1);
    if (!db) return 0;
    ack(db); /* the promotion is durable once imdb_promote returned */
    int v = put(db, 10, 7, "after");
    imdb_close(db);
    return v > 0 ? v : 0;
}

/* Promotion through the anchor: its writer lock taken, the new epoch published to it last. After a
 * crash anywhere in it, the replica opens with that anchor: still a replica (nothing reached its
 * log, the anchor unchanged), or the promoted writer, signing. */
static int run_replica_promote_anchored(const char *run)
{
    uint8_t seed[IMDB_SEED_LEN];
    root_seed(seed);
    snprintf(g_anchor, sizeof g_anchor, "%s/anchor", run);
    imdb_err e = {0};
    imdb_promote_opts po = {.anchor = g_anchor};
    imdb_promote_result pr;
    if (imdb_promote(dir_in(run, "r"), seed, &po, &pr, &e)) return 0;
    imdb_db *db = child_open(dir_in(run, "r"), 1);
    if (!db) return 0;
    ack(db);
    int v = put(db, 10, 7, "after");
    imdb_close(db);
    return v > 0 ? v : 0;
}

/* Promotion with the root key's ledger (run/root.ledger) and the operator's word, no anchor. The
 * setup also keeps c, a copy of the replica from before the promotion: a restored backup has the
 * replica's identity and its cut. check_promote_ledger then holds the ledger to its promise. */
static void setup_promote_ledger(const char *base)
{
    setup_promote(base);
    char r[600], c[600];
    snprintf(r, sizeof r, "%s/r", base);
    snprintf(c, sizeof c, "%s/c", base);
    copy_tree(r, c);
}

static int run_replica_promote_ledger(const char *run)
{
    uint8_t seed[IMDB_SEED_LEN];
    root_seed(seed);
    char led[700];
    snprintf(led, sizeof led, "%s/root.ledger", run);
    imdb_err e = {0};
    imdb_promote_opts po = {.old_writer_stopped = true, .ledger = led};
    imdb_promote_result pr;
    if (imdb_promote(dir_in(run, "r"), seed, &po, &pr, &e)) return 0;
    imdb_db *db = child_open(dir_in(run, "r"), 1);
    if (!db) return 0;
    ack(db);
    int v = put(db, 10, 7, "after");
    imdb_close(db);
    return v > 0 ? v : 0;
}

/* --durable-ack: a commit returns only once the watermark naming it is synced, marked strict */
static int run_strict(const char *run)
{
    imdb_open_opts o = {.sync = 1, .durable_ack = true};
    imdb_db *db = NULL;
    imdb_err e = {0};
    if (imdb_open(dir_in(run, "p"), &o, &db, &e)) return 0;
    int v = 0;
    for (int64_t id = 10; id < 14 && !v; id++) {
        int r = put(db, id, id % 2 ? 42 : 7, "row");
        if (r > 0) v = r;
        if (r < 0) break;
    }
    imdb_close(db);
    return v;
}

/* An operator's `imagedb recover --discard-tail` after a --nosync writer died with commits in
 * two segments and garbage at the end: recover keeps those commits and writes DURABLE as
 * synced, so it must have synced both segments first (an OS crash afterwards must not lose
 * them). The commits count as acknowledged once recover returned. */
static int run_recover(const char *run)
{
    imdb_db *db = child_open(dir_in(run, "p"), 0);
    if (!db) return 0;
    imdb_err e = {0};
    if (put(db, 10, 7, "row") || imdb_checkpoint(db, &e)) {
        imdb_close(db);
        return 0;
    }
    ack(db);
    if (put(db, 11, 7, "row")) {
        imdb_close(db);
        return 0;
    }
    /* the writer dies: no close (that would sync), its lock released by the kernel */
    abandon_handle(db);
    close(db->lockfd);
    db->lockfd = -1;
    char seg[700];
    snprintf(seg, sizeof seg, "%s/log/%020llu.ilg", dir_in(run, "p"), (unsigned long long)db->segs[db->nsegs - 1]);
    uint8_t f[IMDB_FRAME_HDR + 64];
    memset(f, 0x55, sizeof f);
    imdb_le32(f, IMDB_FRAME_MAGIC);
    imdb_le32(f + 4, 64);
    imdb_le32(f + 8, 0xdeadbeefu); /* a complete frame whose body fails its checksum */
    imdb_le32(f + 12, imdb_kern()->crc32c(0, f, 12));
    seg_append(seg, f, sizeof f); /* where an unfinished append leaves it, either format */
    imdb_recover_report r;
    if (!imdb_recover_tail(dir_in(run, "p"), true, dir_in(run, "saved-tail"), &r, &e) && r.applied) ack_closed();
    return 0;
}

/* LAKE_HEAD is fsynced while a --nosync log may still hold its commit only in the page cache. */
static int run_nosync_checkpoint(const char *run)
{
    imdb_db *db = child_open(dir_in(run, "p"), 0);
    if (!db) return 0;
    imdb_err e = {0};
    if (put(db, 10, 7, "row") == 0 && !imdb_checkpoint(db, &e)) {
        ack(db);
        if (put(db, 11, 42, "row") == 0 && !imdb_checkpoint(db, &e)) ack(db);
    }
    if (imdb_close(db) == IMDB_OK) ack_closed();
    return 0;
}

/* With an external anchor: after any crash the anchor must not be ahead of the log (it names only
 * commits on disk), so the anchored open must still succeed. */
static int run_anchored(const char *run)
{
    snprintf(g_anchor, sizeof g_anchor, "%s/anchor", run);
    return run_commits(run);
}

static int run_anchored_nosync(const char *run)
{
    snprintf(g_anchor, sizeof g_anchor, "%s/anchor", run);
    return run_nosync_checkpoint(run);
}

/* A --nosync writer dies with commits only in the page cache, and the next writer opens with the
 * anchor: that open may name those commits in the anchor only once it has synced them (a power cut
 * in between would leave the anchor naming lost commits, and every anchored open would refuse the
 * directory from then on). */
static int run_anchored_reopen(const char *run)
{
    snprintf(g_anchor, sizeof g_anchor, "%s/anchor", run);
    imdb_db *db = child_open(dir_in(run, "p"), 0);
    if (!db) return 0;
    for (int64_t id = 10; id < 12; id++) {
        int r = put(db, id, 7, "row");
        if (r) {
            imdb_close(db);
            return r > 0 ? r : 0;
        }
    }
    abandon_handle(db);
    close(db->lockfd); /* the writer dies: no close (that would sync), its locks released by the kernel */
    db->lockfd = -1;
    close(db->anchor_lockfd);
    db->anchor_lockfd = -1;
    db = child_open(dir_in(run, "p"), 1);
    if (!db) return 0;
    ack_closed(); /* this open synced what the first writer left */
    int v = put(db, 12, 7, "row");
    if (imdb_close(db) == IMDB_OK && !v) ack_closed();
    return v > 0 ? v : 0;
}

static const char *erase_crashed_ok(const char *base)
{
    if (!tree_contains(base, "secret-42")) return "no unredacted payload of subject 42 is left to recover";
    imdb_open_opts o = {.sync = 0, .read_only = true};
    imdb_db *db = NULL;
    imdb_err e = {0};
    if (imdb_open(dir_in(base, "p"), &o, &db, &e)) return "it does not open read-only";
    bool erased = count_subject(db, 42, db->seq) == 0;
    imdb_close(db);
    return erased ? NULL : "its log holds no ERASE of subject 42";
}

/* ---- the parent: one run, and the checks after it -------------------------------------- */

typedef struct frun {
    frec *recs;
    size_t nrecs;
    int status;
} frun;

static bool run_child(const fscen *s, const char *run, const fplan *p, frun *out)
{
    memset(out, 0, sizeof *out);
    int pfd[2];
    if (pipe(pfd) != 0) return false;
    fflush(NULL);
    pid_t pid = fork();
    if (pid < 0) return false;
    if (pid == 0) {
        close(pfd[0]);
        g_ackfd = pfd[1];
        alarm(60);
        g_plan = *p;
        g_count = 0;
        g_hit_op = 0;
        memset(g_counts, 0, sizeof g_counts);
        tracker_init(run);
        imdb_io_set_hooks(&g_hooks);
        int v = s->run(run);
        imdb_io_set_hooks(NULL);
        if (!v && leaks_found(run)) v = VIOL_LEAK;
        if (p->action == A_COUNT) {
            frec r;
            memset(&r, 0, sizeof r);
            r.kind = R_COUNTS;
            memcpy(r.counts, g_counts, sizeof r.counts);
            rec_send(&r);
            _exit(v);
        }
        if (v) _exit(v);
        crash_now(p->view, p->seed ^ 0x5bd1e995); /* and a power cut after the faulted run */
    }
    close(pfd[1]);
    size_t cap = 0;
    for (;;) {
        frec r;
        size_t got = 0;
        while (got < sizeof r) {
            ssize_t n = read(pfd[0], (uint8_t *)&r + got, sizeof r - got);
            if (n <= 0) break;
            got += (size_t)n;
        }
        if (got < sizeof r) break;
        if (out->nrecs == cap) {
            cap = cap ? 2 * cap : 16;
            frec *nr = realloc(out->recs, cap * sizeof *nr);
            if (!nr) break;
            out->recs = nr;
        }
        out->recs[out->nrecs++] = r;
    }
    close(pfd[0]);
    return waitpid(pid, &out->status, 0) == pid;
}

static char g_why[900];

/* The independent auditor (IMDB_AUDIT_BIN, set by the Makefile) must accept every state a
 * crash left, once the engine's writable open has recovered it. */
static const char *audit_run(const char *dir)
{
    const char *bin = getenv("IMDB_AUDIT_BIN");
    if (!bin || !*bin) return NULL;
    int pfd[2];
    if (pipe(pfd) != 0) return "pipe for the auditor failed";
    fflush(NULL);
    pid_t pid = fork();
    if (pid < 0) return "fork for the auditor failed";
    if (pid == 0) {
        dup2(pfd[1], 1);
        dup2(pfd[1], 2);
        close(pfd[0]);
        close(pfd[1]);
        execl(bin, bin, "verify", dir, (char *)NULL);
        _exit(127);
    }
    close(pfd[1]);
    char out[4096];
    size_t n = 0;
    for (;;) {
        ssize_t r = read(pfd[0], out + n, sizeof out - 1 - n);
        if (r <= 0) break;
        n += (size_t)r;
        if (n == sizeof out - 1) n = 0; /* keep reading; only a FAILED line matters */
    }
    out[n] = 0;
    close(pfd[0]);
    int st = 0;
    if (waitpid(pid, &st, 0) == pid && WIFEXITED(st) && WEXITSTATUS(st) == 0) return NULL;
    const char *f = strstr(out, "FAILED");
    char line[300];
    snprintf(line, sizeof line, "%s", f ? f : "no output");
    char *nl = strchr(line, '\n');
    if (nl) *nl = 0;
    snprintf(g_why, sizeof g_why, "the independent auditor rejects the recovered state (exit %d): %s",
             WIFEXITED(st) ? WEXITSTATUS(st) : -1, line);
    return g_why;
}

/* NULL if everything holds after the run, else why not. */
static int g_strict_damaged; /* strict runs whose frame past the watermark the check damaged */

/* The strict scenario's claim, before any recovery: DURABLE is strict and names every acknowledged
 * commit, so a complete frame past it was never acknowledged. Make it so that frame is damaged (it
 * fails its checksum, zeros after it): the writable open must still succeed, dropping it, and the
 * checks after this one find every acknowledged commit. */
static const char *strict_check(const char *dir, const frun *r)
{
    uint64_t maxack = 0;
    for (size_t i = 0; i < r->nrecs; i++)
        if (r->recs[i].kind == R_ACK && r->recs[i].seq > maxack) maxack = r->recs[i].seq;
    char wm[700];
    snprintf(wm, sizeof wm, "%s/DURABLE", dir);
    size_t wn = 0;
    uint8_t *w = slurp(wm, &wn);
    imdb_durable d;
    imdb_err e = {0};
    bool ok = w && imdb_durable_decode(w, wn, &d, &e) == IMDB_OK;
    free(w);
    if (maxack && (!ok || !d.synced || !d.strict || d.seq < maxack)) {
        snprintf(g_why, sizeof g_why, "commit %llu was acknowledged, but DURABLE %s", (unsigned long long)maxack,
                 !ok ? "does not decode" : !d.strict ? "is not strict" : "does not name it");
        return g_why;
    }
    if (!ok || !d.strict) return NULL; /* the strict open never got that far: nothing claimed */
    char *seg = seg_path(dir, -1);
    size_t n = 0;
    uint8_t *b = seg ? slurp(seg, &n) : NULL;
    if (b && imdb_tseg_is_tagged(b, n)) {
        /* tagged: its frames end cleanly (only the fill after) and the last is past the strict
         * watermark: damage that frame's last byte where it lies, sectors and fill as they are */
        uint8_t *c = malloc(n);
        memcpy(c, b, n);
        const char *base = strrchr(seg, '/');
        uint64_t first = 0;
        size_t len = 0;
        imdb_tseg_end end;
        bool named = imdb_logseg_parse(base ? base + 1 : seg, &first);
        if (named && imdb_tseg_scan(c, n, first, &len, &end, &e) == IMDB_SCAN_END && end.frames && end.last > d.seq) {
            uint64_t s = end.keep_bytes ? end.keep_sector : end.keep_sector - 1;
            size_t at = (size_t)s * IMDB_TSEG_SECTOR + 8 + (end.keep_bytes ? end.keep_bytes - 1 : IMDB_TSEG_PAYLOAD - 1);
            b[at] ^= 1;
            spit(seg, b, n);
            g_strict_damaged++;
        }
        free(c);
        free(b);
        return NULL;
    }
    size_t off = 0, last = 0, len = 0, fl = 0;
    while (b && imdb_frame_scan(b, n, off, &fl, &e) == IMDB_SCAN_FRAME) {
        last = off;
        len = fl;
        off += fl;
    }
    bool zeros_after = true;
    for (size_t i = off; b && i < n; i++) zeros_after &= b[i] == 0;
    if (b && len && zeros_after && imdb_frame_seq(b + last) > d.seq) {
        b[last + len - 1] ^= 1;
        spit(seg, b, n);
        g_strict_damaged++;
    }
    free(b);
    return NULL;
}

/* Whatever a fault or a crash left: once the replica holds epoch 1, the ledger refuses the copy that
 * epoch (a second epoch-1 writer key would fork the history: the review of 2026-10-26, F2 and F3).
 * Before that, the copy may take it or be refused (a reservation that outlived a failed promotion). */
static const char *check_promote_ledger(const char *run)
{
    imdb_open_opts o = {.sync = 1};
    imdb_db *db = NULL;
    imdb_err e = {0};
    if (imdb_open(dir_in(run, "r"), &o, &db, &e)) {
        snprintf(g_why, sizeof g_why, "the replica does not reopen: %s", e.msg);
        return g_why;
    }
    bool promoted = imdb_current_epoch(db) > 0;
    imdb_close(db);
    uint8_t seed[IMDB_SEED_LEN];
    root_seed(seed);
    char led[700];
    snprintf(led, sizeof led, "%s/root.ledger", run);
    imdb_promote_opts po = {.old_writer_stopped = true, .ledger = led};
    imdb_promote_result pr;
    int rc = imdb_promote(dir_in(run, "c"), seed, &po, &pr, &e);
    if (promoted && (rc != IMDB_ERR_STATE || pr.committed)) {
        snprintf(g_why, sizeof g_why, "the ledger let a copy of the promoted replica take epoch 1 too (rc %d%s%s)", rc,
                 rc ? ": " : "", rc ? e.msg : "");
        return g_why;
    }
    return NULL;
}

static const char *check_run(const fscen *s, const char *run, const frun *r)
{
    if (!WIFEXITED(r->status)) {
        snprintf(g_why, sizeof g_why, "the child died (signal %d)", WIFSIGNALED(r->status) ? WTERMSIG(r->status) : 0);
        return g_why;
    }
    int code = WEXITSTATUS(r->status);
    if (code != 0 && code != 77) {
        snprintf(g_why, sizeof g_why, "the child reports %s (exit %d)",
                 code == VIOL_FAILSTOP  ? "a failed fdatasync that left the handle usable"
                 : code == VIOL_PINNED ? "erased bytes kept for a reader's pin"
                 : code == VIOL_RETAIN ? "a clean run without its two automatic purges"
                 : code == VIOL_INDEX  ? "an ordered path that disagrees with the scan"
                 : code == VIOL_ORDERED ? "a clean run whose SELECTs did not take the ordered path"
                 : code == VIOL_JOIN   ? "a join that disagrees with its mirror plan, or a clean run's wrong answer"
                 : code == VIOL_LEAK   ? "memory the run leaked (LeakSanitizer's report is above)"
                 : code == VIOL_FILL   ? "a clean run whose tagged segment's fill did not move as design.md §3 says"
                 : code == VIOL_PUTBACK ? "a failed commit that left bytes in its tagged segment (no put-back)"
                                       : "a violation",
                 code);
        return g_why;
    }
    bool closed = false;
    for (size_t i = 0; i < r->nrecs; i++) closed |= r->recs[i].kind == R_CLOSED;
    const char *dir = dir_in(run, strncmp(s->name, "replica", 7) == 0 ? "r" : "p");
    if (s->strict) {
        const char *sw = strict_check(dir, r);
        if (sw) return sw;
    }
    char anc[700];
    snprintf(anc, sizeof anc, "%s/anchor", run);
    imdb_open_opts o = {.sync = 1, .anchor = s->anchored ? anc : NULL};
    imdb_db *db = NULL;
    imdb_err e = {0};
    int orc = imdb_open(dir, &o, &db, &e);
    if (orc && strcmp(s->name, "recover") == 0 && !closed && strstr(e.msg, "cannot show that commit")) {
        /* the fault came before recover cut the damaged frame it was run for: only the operator
         * drops a complete damaged frame past a watermark that may lag, so it runs recover again */
        char sv[700];
        snprintf(sv, sizeof sv, "%s/saved-tail-again", run);
        imdb_recover_report rr;
        imdb_err e2 = {0};
        if (imdb_recover_tail(dir, true, sv, &rr, &e2) == IMDB_OK && rr.applied) {
            memset(&e, 0, sizeof e);
            orc = imdb_open(dir, &o, &db, &e);
        }
    }
    if (orc) {
        snprintf(g_why, sizeof g_why, "the writable open fails: %s", e.msg);
        return g_why;
    }
    const char *why = NULL;
    for (size_t i = 0; i < r->nrecs && !why; i++) {
        if (r->recs[i].kind != R_ACK || (s->nosync && !closed)) continue;
        if (r->recs[i].seq > db->seq) {
            snprintf(g_why, sizeof g_why, "acknowledged commit %llu is lost (the log ends at %llu)",
                     (unsigned long long)r->recs[i].seq, (unsigned long long)db->seq);
            why = g_why;
            break;
        }
        uint8_t gen[32]; /* commit 0: the genesis (a replica's first acknowledgement, before anything arrived) */
        imdb_genesis_hash(db->db_id, gen);
        const imdb_commit_info *ci = r->recs[i].seq ? imdb_ci_at(db, r->recs[i].seq, &e) : NULL;
        if (r->recs[i].seq ? !ci || memcmp(ci->hash, r->recs[i].head, 32) != 0 : memcmp(gen, r->recs[i].head, 32) != 0) {
            snprintf(g_why, sizeof g_why, "acknowledged commit %llu has another hash", (unsigned long long)r->recs[i].seq);
            why = g_why;
        }
    }
    /* in these scenarios an epoch past 0 is the directory's own: it must then be a primary that signs */
    bool must_sign = s->signs && (!db->replica || imdb_current_epoch(db) > 0);
    if (!why && must_sign && (db->replica || !db->can_sign || !imdb_ct_eq(db->signer.pk, db->writer_pk, IMDB_PUBKEY_LEN))) {
        snprintf(g_why, sizeof g_why, "the recovered primary cannot sign with the writer key of epoch %u", imdb_current_epoch(db));
        why = g_why;
    }
    imdb_verify_report vr;
    if (!why && imdb_verify(db, &vr, &e)) {
        snprintf(g_why, sizeof g_why, "VERIFY fails: %s", e.msg);
        why = g_why;
    }
    if (!why && s->erased && count_subject(db, 42, db->seq) == 0 && tree_contains(run, s->erased)) {
        snprintf(g_why, sizeof g_why, "subject 42 is erased but a file still holds \"%s\"", s->erased);
        why = g_why;
    }
    imdb_close(db);
    if (!why) why = audit_run(dir);
    if (!why && strcmp(s->name, "replica_promote_ledger") == 0) why = check_promote_ledger(run);
    return why;
}

static const char *op_name(int op)
{
    static const char *const n[] = {"?",      "open",  "read", "write",  "fsync",   "fdatasync", "ftruncate", "rename",
                                    "unlink", "mkdir", "stat", "flock",  "opendir", "readdir",   "alloc"};
    return op >= 0 && op <= IMDB_IO_ALLOC ? n[op] : "?";
}

static unsigned kBoundary = 1u << IMDB_IO_WRITE | 1u << IMDB_IO_FSYNC | 1u << IMDB_IO_FDATASYNC |
                            1u << IMDB_IO_TRUNCATE | 1u << IMDB_IO_RENAME | 1u << IMDB_IO_UNLINK | 1u << IMDB_IO_MKDIR;
static unsigned kOther = 1u << IMDB_IO_OPEN | 1u << IMDB_IO_READ | 1u << IMDB_IO_STAT | 1u << IMDB_IO_LOCK |
                         1u << IMDB_IO_OPENDIR | 1u << IMDB_IO_READDIR;
static unsigned kAlloc = 1u << IMDB_IO_ALLOC;

static uint64_t masked(const uint64_t counts[], unsigned mask)
{
    uint64_t n = 0;
    for (int op = 1; op <= IMDB_IO_ALLOC; op++)
        if (mask & (1u << op)) n += counts[op];
    return n;
}

static int g_runs, g_fail_runs;

/* IMDB_FAULT_ONLY=<class>:<at>:<fails|short|crashes> runs one fault point (to debug it); a failing
 * run is then kept in $IMDB_TEST_TMP/fault-kept. */
static bool only_point(const char *klass, uint64_t at, int action, bool *only)
{
    const char *o = getenv("IMDB_FAULT_ONLY");
    *only = o && *o;
    if (!*only) return true;
    char k[32], act[16];
    unsigned long long a;
    if (sscanf(o, "%31[^:]:%llu:%15s", k, &a, act) != 3) return true;
    int ac = strcmp(act, "crashes") == 0 ? A_CRASH : strcmp(act, "short") == 0 ? A_SHORT : A_ERRNO;
    return strcmp(k, klass) == 0 && a == at && ac == action;
}

/* Every fault point of one class mask; stops at the first violation (reported with its run). */
static bool fault_points(const fscen *s, const char *base, const char *run, unsigned mask, uint64_t total, int step,
                         const char *klass)
{
    for (uint64_t at = 1; at <= total; at += (uint64_t)step) {
        for (int action = A_ERRNO; action <= A_CRASH; action++) {
            fplan p = {.mask = mask, .at = at, .action = action, .err = EIO,
                       .view = (int)((at + (uint64_t)action) % V_COUNT), .seed = at * 0x9E3779B97F4A7C15ull + (uint64_t)action};
            if (action == A_SHORT && mask != kBoundary) continue;
            bool only;
            if (!only_point(klass, at, action, &only)) continue;
            nftw(run, rm_one, 16, FTW_DEPTH | FTW_PHYS);
            rmdir(run);
            if (copy_tree(base, run) != 0) {
                test_fail(__FILE__, __LINE__, "copy_tree");
                return false;
            }
            frun r;
            if (!run_child(s, run, &p, &r)) {
                test_fail(__FILE__, __LINE__, "fork");
                return false;
            }
            g_runs++;
            if (only) { /* keep the state the fault left, before the checks open it */
                char kept[600];
                snprintf(kept, sizeof kept, "%s/fault-kept", getenv("IMDB_TEST_TMP") ? getenv("IMDB_TEST_TMP") : "/tmp");
                nftw(kept, rm_one, 16, FTW_DEPTH | FTW_PHYS);
                rmdir(kept);
                copy_tree(run, kept);
            }
            int hit = 0;
            for (size_t i = 0; i < r.nrecs; i++)
                if (r.recs[i].kind == R_NOTE) hit = (int)r.recs[i].seq;
            const char *why = check_run(s, run, &r);
            free(r.recs);
            if (why) {
                char m[1400];
                snprintf(m, sizeof m, "%s: %s call %llu %s (%s), then %s: %s", s->name, klass, (unsigned long long)at,
                         action == A_CRASH ? "crashes" : action == A_SHORT ? "is short" : "fails",
                         hit ? op_name(hit) : "no call reached", kViewName[p.view], why);
                test_fail(__FILE__, __LINE__, m);
                g_fail_runs++;
                if (only) {
                    char kept[600];
                    snprintf(kept, sizeof kept, "%s/fault-kept", getenv("IMDB_TEST_TMP") ? getenv("IMDB_TEST_TMP") : "/tmp");
                    printf("    the state the fault left is in %s\n", kept);
                }
                return false;
            }
        }
    }
    return true;
}

/* The runs need no real durability (the model decides what survives), so they use tmpfs unless
 * IMDB_FAULT_TMP names another place (`make faults` runs them on the build disk). */
static const char *fault_tmpdir(char *buf, size_t cap)
{
    static int n;
    const char *root = getenv("IMDB_FAULT_TMP");
    struct stat st;
    if (!root && stat("/dev/shm", &st) == 0 && S_ISDIR(st.st_mode) && access("/dev/shm", W_OK) == 0) root = "/dev/shm";
    if (!root) return test_tmpdir();
    snprintf(buf, cap, "%s/imdb-fault-%d-%d", root, (int)getpid(), n++);
    nftw(buf, rm_one, 16, FTW_DEPTH | FTW_PHYS);
    rmdir(buf);
    return mkdir(buf, 0700) == 0 ? buf : test_tmpdir();
}

static void fault_scenario(const fscen *s)
{
    if (getenv("IMDB_FAULT_SKIP") && strcmp(getenv("IMDB_FAULT_SKIP"), "1") == 0) {
        printf("    skipped (IMDB_FAULT_SKIP=1)\n");
        return;
    }
    char tbuf[600];
    const char *tmp = fault_tmpdir(tbuf, sizeof tbuf);
    char base[600], run[600];
    snprintf(base, sizeof base, "%s/base", tmp);
    snprintf(run, sizeof run, "%s/run", tmp);
    CHECK(mkdir(base, 0700) == 0);
    s->setup(base);
    const char *bad = s->base_ok ? s->base_ok(base) : NULL;
    if (bad) {
        char m[700];
        snprintf(m, sizeof m, "%s: the starting state is wrong: %s", s->name, bad);
        test_fail(__FILE__, __LINE__, m);
        return;
    }
    /* the unfaulted run: it must pass, and it counts the calls */
    CHECK(copy_tree(base, run) == 0);
    fplan count = {.mask = ~0u, .action = A_COUNT};
    frun r;
    CHECK(run_child(s, run, &count, &r));
    uint64_t counts[IMDB_IO_ALLOC + 1] = {0};
    for (size_t i = 0; i < r.nrecs; i++)
        if (r.recs[i].kind == R_COUNTS) memcpy(counts, r.recs[i].counts, sizeof counts);
    const char *why = check_run(s, run, &r);
    free(r.recs);
    if (why) {
        char m[1000];
        snprintf(m, sizeof m, "%s without faults: %s", s->name, why);
        test_fail(__FILE__, __LINE__, m);
        return;
    }
    bool full = getenv("IMDB_FAULT_FULL") && strcmp(getenv("IMDB_FAULT_FULL"), "1") == 0;
    g_runs = g_fail_runs = g_strict_damaged = 0;
    bool ok = fault_points(s, base, run, kBoundary, masked(counts, kBoundary), 1, "boundary") &&
              fault_points(s, base, run, kOther, masked(counts, kOther), full ? 1 : 7, "other") &&
              fault_points(s, base, run, kAlloc, masked(counts, kAlloc), full ? 1 : 7, "allocation");
    printf("    %s: %llu boundary, %llu other, %llu allocation calls; %d faulted runs%s\n", s->name,
           (unsigned long long)masked(counts, kBoundary), (unsigned long long)masked(counts, kOther),
           (unsigned long long)masked(counts, kAlloc), g_runs, ok ? "" : " (stopped at a failure)");
    if (s->strict) printf("    %s: %d runs left a complete frame past the strict watermark; damaged, it was dropped\n", s->name,
                          g_strict_damaged);
    if (tmp == tbuf) {
        nftw(tbuf, rm_one, 16, FTW_DEPTH | FTW_PHYS);
        rmdir(tbuf);
    }
}

static void setup_erase_crashed(const char *base)
{
    setup_erased(base);
    /* stop right after the ERASE commit is durable: no redaction, lake or GC yet */
    char run[600];
    snprintf(run, sizeof run, "%s.tmp", base);
    fscen e = {"erase", NULL, run_erase, false, NULL, NULL, false, false, false};
    fplan count = {.mask = 1u << IMDB_IO_FDATASYNC, .action = A_COUNT};
    frun r;
    nftw(run, rm_one, 16, FTW_DEPTH | FTW_PHYS);
    rmdir(run);
    if (copy_tree(base, run) != 0 || !run_child(&e, run, &count, &r)) return;
    free(r.recs);
    nftw(run, rm_one, 16, FTW_DEPTH | FTW_PHYS);
    rmdir(run);
    if (copy_tree(base, run) != 0) return;
    /* crash (a process kill) just before the fdatasync of the ERASE frame: the frame is written, nothing
     * after it ran; the open that follows accepts the frame and must finish the erasure */
    fplan cut = {.mask = 1u << IMDB_IO_FDATASYNC, .at = 2, .action = A_CRASH, .view = V_KILL};
    if (!run_child(&e, run, &cut, &r)) return;
    free(r.recs);
    char p[600];
    snprintf(p, sizeof p, "%s/p", base);
    nftw(p, rm_one, 16, FTW_DEPTH | FTW_PHYS);
    rmdir(p);
    snprintf(p, sizeof p, "%s/p", run);
    char q[600];
    snprintf(q, sizeof q, "%s/p", base);
    copy_tree(p, q);
}

static const fscen kScen[] = {
    {"commits", setup_txns, run_commits, false, NULL, NULL, false, false, false},
    {"nosync", setup_txns, run_nosync, true, NULL, NULL, false, false, false},
    {"checkpoint", setup_txns, run_checkpoint, false, NULL, NULL, false, false, false},
    {"compact", setup_txns, run_compact, false, NULL, NULL, false, false, false},
    {"erase", setup_erased, run_erase, false, "secret-42", NULL, false, false, false},
    {"reopen", setup_erase_crashed, run_reopen, false, "secret-42", erase_crashed_ok, false, false, false},
    {"replica", setup_replica, run_replica, false, NULL, NULL, false, false, false},
    {"recover", setup_txns, run_recover, true, NULL, NULL, false, false, false},
    {"nosync_checkpoint", setup_txns, run_nosync_checkpoint, true, NULL, NULL, false, false, false},
    {"anchored", setup_txns, run_anchored, false, NULL, NULL, true, false, false},
    {"anchored_nosync", setup_txns, run_anchored_nosync, true, NULL, NULL, true, false, false},
    {"anchored_reopen", setup_txns, run_anchored_reopen, true, NULL, NULL, true, false, false},
    {"replica_acks", setup_replica, run_replica_acks, false, NULL, NULL, false, false, false},
    {"rotate", setup_txns, run_rotate, false, NULL, NULL, false, true, false},
    {"replica_promote", setup_promote, run_replica_promote, false, NULL, NULL, false, true, false},
    {"replica_promote_anchored", setup_promote, run_replica_promote_anchored, false, NULL, NULL, true, true, false},
    {"strict", setup_txns, run_strict, false, NULL, NULL, false, false, true},
    {"erase_pinned", setup_erase_pinned, run_erase_pinned, false, "secret-42", NULL, false, false, false},
    {"retain", setup_txns, run_retain, false, NULL, NULL, false, false, false},
    {"index", setup_txns, run_index, false, NULL, NULL, false, false, false},
    {"join", setup_txns, run_join, false, NULL, NULL, false, false, false},
    {"replica_promote_ledger", setup_promote_ledger, run_replica_promote_ledger, false, NULL, NULL, false, true, false},
    {"fill", setup_txns, run_fill, false, NULL, NULL, false, false, false},
    {"rotate_reopen", setup_ended, run_commits, false, NULL, NULL, false, false, false},
    {"retry", setup_txns, run_retry, false, NULL, NULL, false, false, false},
};

static void t_fault_commits(void) { fault_scenario(&kScen[0]); }
static void t_fault_nosync(void) { fault_scenario(&kScen[1]); }
static void t_fault_checkpoint(void) { fault_scenario(&kScen[2]); }
static void t_fault_compact(void) { fault_scenario(&kScen[3]); }
static void t_fault_erase(void) { fault_scenario(&kScen[4]); }
static void t_fault_reopen(void) { fault_scenario(&kScen[5]); }
static void t_fault_replica(void) { fault_scenario(&kScen[6]); }
static void t_fault_recover(void) { fault_scenario(&kScen[7]); }
static void t_fault_nosync_checkpoint(void) { fault_scenario(&kScen[8]); }
static void t_fault_anchored(void) { fault_scenario(&kScen[9]); }
static void t_fault_anchored_nosync(void) { fault_scenario(&kScen[10]); }
static void t_fault_anchored_reopen(void) { fault_scenario(&kScen[11]); }
static void t_fault_replica_acks(void) { fault_scenario(&kScen[12]); }
static void t_fault_rotate(void) { fault_scenario(&kScen[13]); }
static void t_fault_replica_promote(void) { fault_scenario(&kScen[14]); }
static void t_fault_replica_promote_anchored(void) { fault_scenario(&kScen[15]); }
static void t_fault_strict(void) { fault_scenario(&kScen[16]); }
static void t_fault_erase_pinned(void) { fault_scenario(&kScen[17]); }
static void t_fault_retain(void) { fault_scenario(&kScen[18]); }
static void t_fault_index(void) { fault_scenario(&kScen[19]); }
static void t_fault_join(void) { fault_scenario(&kScen[20]); }
static void t_fault_replica_promote_ledger(void) { fault_scenario(&kScen[21]); }
static void t_fault_fill(void) { fault_scenario(&kScen[22]); }
static void t_fault_rotate_reopen(void) { fault_scenario(&kScen[23]); }
static void t_fault_retry(void) { fault_scenario(&kScen[24]); }

const test_case fault_tests[] = {
    {"fault_commits", t_fault_commits},     {"fault_nosync", t_fault_nosync}, {"fault_checkpoint", t_fault_checkpoint},
    {"fault_compact", t_fault_compact},     {"fault_erase", t_fault_erase},   {"fault_reopen", t_fault_reopen},
    {"fault_replica", t_fault_replica},     {"fault_recover", t_fault_recover},
    {"fault_nosync_checkpoint", t_fault_nosync_checkpoint},
    {"fault_anchored", t_fault_anchored},
    {"fault_anchored_nosync", t_fault_anchored_nosync},
    {"fault_anchored_reopen", t_fault_anchored_reopen},
    {"fault_replica_acks", t_fault_replica_acks},
    {"fault_rotate", t_fault_rotate},
    {"fault_replica_promote", t_fault_replica_promote},
    {"fault_replica_promote_anchored", t_fault_replica_promote_anchored},
    {"fault_strict", t_fault_strict},
    {"fault_erase_pinned", t_fault_erase_pinned},
    {"fault_retain", t_fault_retain},
    {"fault_index", t_fault_index},
    {"fault_join", t_fault_join},
    {"fault_replica_promote_ledger", t_fault_replica_promote_ledger},
    {"fault_fill", t_fault_fill},
    {"fault_rotate_reopen", t_fault_rotate_reopen},
    {"fault_retry", t_fault_retry},
};
const size_t fault_ntests = sizeof fault_tests / sizeof *fault_tests;
