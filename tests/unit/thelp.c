/* Shared helpers for engine and lake tests. */
#include "thelp.h"

#include "../../src/logdir.h"

#include <dirent.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>


imdb_err g_e;

imdb_db *open_db(const char *dir)
{
    imdb_open_opts o = {.sync = 0};
    imdb_db *db = NULL;
    imdb_err_clear(&g_e);
    if (imdb_open(dir, &o, &db, &g_e)) {
        fprintf(stderr, "    open %s: %s\n", dir, g_e.msg);
        return NULL;
    }
    return db;
}

void txn_schema(imdb_schema *s)
{
    memset(s, 0, sizeof *s);
    strcpy(s->name, "txns");
    s->ncols = 4;
    strcpy(s->cols[0].name, "id");
    s->cols[0].type = IMDB_T_INT64;
    s->cols[0].flags = IMDB_COL_PK;
    strcpy(s->cols[1].name, "user_id");
    s->cols[1].type = IMDB_T_INT64;
    s->cols[1].flags = IMDB_COL_SUBJECT;
    strcpy(s->cols[2].name, "amount");
    s->cols[2].type = IMDB_T_DECIMAL;
    s->cols[2].precision = 12;
    s->cols[2].scale = 2;
    strcpy(s->cols[3].name, "memo");
    s->cols[3].type = IMDB_T_TEXT;
    s->pk = 0;
    s->subject = 1;
}

void row_vals(imdb_value v[4], int64_t id, int64_t user, int64_t cents, const char *memo)
{
    memset(v, 0, 4 * sizeof *v);
    v[0].type = IMDB_T_INT64;
    v[0].i = id;
    v[1].type = IMDB_T_INT64;
    v[1].i = user;
    v[2].type = IMDB_T_DECIMAL;
    v[2].scale = 2;
    v[2].i = cents;
    v[3].type = IMDB_T_TEXT;
    v[3].s = (const uint8_t *)memo;
    v[3].len = (uint32_t)strlen(memo);
}

int make_table(imdb_db *db, imdb_err *e)
{
    imdb_schema s;
    txn_schema(&s);
    if (imdb_begin(db, e) || imdb_create_table(db, &s, e)) return e->code;
    return imdb_commit(db, e);
}

int ins1(imdb_db *db, int64_t id, int64_t user, int64_t cents, const char *memo)
{
    imdb_err *e = &g_e;
    imdb_value v[4];
    row_vals(v, id, user, cents, memo);
    imdb_table *t = imdb_table_by_name(db, "txns");
    if (imdb_begin(db, e)) return e->code;
    if (imdb_insert(db, t, v, e)) {
        imdb_rollback(db);
        return e->code;
    }
    if (imdb_commit(db, e)) return e->code;
    return imdb_maintain(db, e);
}

uint64_t pk_lookup(imdb_db *db, int64_t id, uint64_t snap)
{
    imdb_table *t = imdb_table_by_name(db, "txns");
    imdb_value k = {.type = IMDB_T_INT64, .i = id};
    return imdb_lookup_pk(db, t, &k, snap);
}

uint64_t count_subject(imdb_db *db, int64_t user, uint64_t snap)
{
    imdb_table *t = imdb_table_by_name(db, "txns");
    imdb_value k = {.type = IMDB_T_INT64, .i = user};
    const imdb_vlist *l = imdb_subject_versions(t, &k);
    uint64_t n = 0;
    for (uint32_t i = 0; l && i < l->n; i++) n += imdb_visible(&t->ver[l->v[i]], snap);
    return n;
}

char *path_join(const char *a, const char *b)
{
    static char buf[4][600];
    static int k;
    char *p = buf[k++ & 3];
    snprintf(p, 600, "%s/%s", a, b);
    return p;
}

long file_size(const char *p)
{
    struct stat st;
    return stat(p, &st) == 0 ? (long)st.st_size : -1;
}

uint8_t *slurp(const char *p, size_t *n)
{
    FILE *f = fopen(p, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    uint8_t *b = malloc(sz > 0 ? (size_t)sz : 1);
    *n = fread(b, 1, (size_t)(sz > 0 ? sz : 0), f);
    fclose(f);
    return b;
}

void spit(const char *p, const uint8_t *b, size_t n)
{
    FILE *f = fopen(p, "wb");
    fwrite(b, 1, n, f);
    fclose(f);
}

bool mem_contains(const uint8_t *h, size_t hn, const char *needle)
{
    size_t nn = strlen(needle);
    for (size_t i = 0; i + nn <= hn; i++)
        if (memcmp(h + i, needle, nn) == 0) return true;
    return false;
}

/* true if any regular file under dir contains needle */
bool tree_contains(const char *dir, const char *needle)
{
    DIR *d = opendir(dir);
    if (!d) return false;
    struct dirent *de;
    bool found = false;
    while (!found && (de = readdir(d))) {
        if (de->d_name[0] == '.') continue;
        char p[1024];
        snprintf(p, sizeof p, "%s/%s", dir, de->d_name);
        struct stat st;
        if (lstat(p, &st) != 0) continue;
        if (S_ISDIR(st.st_mode)) {
            found = tree_contains(p, needle);
        } else if (S_ISREG(st.st_mode)) {
            size_t n;
            uint8_t *b = slurp(p, &n);
            if (b) found = mem_contains(b, n, needle);
            free(b);
        }
    }
    closedir(d);
    return found;
}

int ship_to_file(const char *primary, uint64_t after, const char *file, imdb_err *e)
{
    int fd = open(file, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    int rc = imdb_ship(primary, after, fd, false, e);
    close(fd);
    return rc;
}

int apply_file(imdb_db *rep, const char *file, uint64_t *applied, imdb_err *e)
{
    int fd = open(file, O_RDONLY);
    int rc = imdb_apply_stream(rep, fd, applied, e);
    close(fd);
    return rc;
}


bool mem_contains_n(const uint8_t *h, size_t hn, const uint8_t *needle, size_t nn)
{
    for (size_t i = 0; i + nn <= hn; i++)
        if (memcmp(h + i, needle, nn) == 0) return true;
    return false;
}

bool tree_contains_n(const char *dir, const uint8_t *needle, size_t nn)
{
    DIR *d = opendir(dir);
    if (!d) return false;
    struct dirent *de;
    bool found = false;
    while (!found && (de = readdir(d))) {
        if (de->d_name[0] == '.') continue;
        char p[1024];
        snprintf(p, sizeof p, "%s/%s", dir, de->d_name);
        struct stat st;
        if (lstat(p, &st) != 0) continue;
        if (S_ISDIR(st.st_mode)) {
            found = tree_contains_n(p, needle, nn);
        } else if (S_ISREG(st.st_mode)) {
            size_t n;
            uint8_t *b = slurp(p, &n);
            if (b) found = mem_contains_n(b, n, needle, nn);
            free(b);
        }
    }
    closedir(d);
    return found;
}

static int cmpstr(const void *a, const void *b) { return strcmp(*(char *const *)a, *(char *const *)b); }

static int list_dir(const char *dir, char ***out)
{
    DIR *d = opendir(dir);
    if (!d) return -1;
    int n = 0, cap = 16;
    char **v = malloc(sizeof *v * (size_t)cap);
    struct dirent *de;
    while ((de = readdir(d))) {
        if (de->d_name[0] == '.') continue;
        if (n == cap) v = realloc(v, sizeof *v * (size_t)(cap *= 2));
        v[n++] = strdup(de->d_name);
    }
    closedir(d);
    qsort(v, (size_t)n, sizeof *v, cmpstr);
    *out = v;
    return n;
}

bool dirs_identical(const char *a, const char *b, char *why, size_t whylen)
{
    char **la, **lb;
    int na = list_dir(a, &la), nb = list_dir(b, &lb);
    bool same = na == nb && na >= 0;
    if (!same) snprintf(why, whylen, "%s has %d entries, %s has %d", a, na, b, nb);
    for (int i = 0; same && i < na; i++) {
        if (strcmp(la[i], lb[i]) != 0) {
            snprintf(why, whylen, "entry %s vs %s", la[i], lb[i]);
            same = false;
            break;
        }
        char pa[1024], pb[1024];
        snprintf(pa, sizeof pa, "%s/%s", a, la[i]);
        snprintf(pb, sizeof pb, "%s/%s", b, lb[i]);
        struct stat sa, sb;
        lstat(pa, &sa);
        lstat(pb, &sb);
        if (S_ISDIR(sa.st_mode) && S_ISDIR(sb.st_mode)) {
            same = dirs_identical(pa, pb, why, whylen);
        } else {
            size_t x, y;
            uint8_t *ba = slurp(pa, &x), *bb = slurp(pb, &y);
            same = ba && bb && x == y && memcmp(ba, bb, x) == 0;
            if (!same) snprintf(why, whylen, "file %s differs", la[i]);
            free(ba);
            free(bb);
        }
    }
    for (int i = 0; i < na; i++) free(la[i]);
    for (int i = 0; i < nb; i++) free(lb[i]);
    if (na >= 0) free(la);
    if (nb >= 0) free(lb);
    return same;
}

int count_files(const char *dir, const char *suffix)
{
    char **l;
    int n = list_dir(dir, &l), c = 0;
    for (int i = 0; i < n; i++) {
        size_t a = strlen(l[i]), b = strlen(suffix);
        if (a >= b && strcmp(l[i] + a - b, suffix) == 0) c++;
        free(l[i]);
    }
    if (n >= 0) free(l);
    return c;
}

/* Path of segment k of dir's log (0-based; k < 0 counts from the end), or
 * NULL. The returned buffer is one of four rotating static buffers. */
char *seg_path(const char *dir, int k)
{
    static char buf[4][700];
    static int r;
    char ld[650];
    snprintf(ld, sizeof ld, "%s/log", dir);
    char **names;
    int n = list_dir(ld, &names);
    char *out = NULL;
    if (n > 0) {
        int idx = k < 0 ? n + k : k;
        if (idx >= 0 && idx < n) {
            out = buf[r++ & 3];
            snprintf(out, 700, "%s/%s", ld, names[idx]);
        }
    }
    for (int i = 0; i < n; i++) free(names[i]);
    if (n >= 0) free(names);
    return out;
}

int log_segments(const char *dir)
{
    char ld[650];
    snprintf(ld, sizeof ld, "%s/log", dir);
    char **names;
    int n = list_dir(ld, &names);
    for (int i = 0; i < n; i++) free(names[i]);
    if (n >= 0) free(names);
    return n;
}

/* Removes the published lake (LAKE_HEAD and every object): the state of a
 * directory before its first manifest. */
void rm_lake(const char *dir)
{
    char p[700];
    snprintf(p, sizeof p, "%s/LAKE_HEAD", dir);
    unlink(p);
    char od[650];
    snprintf(od, sizeof od, "%s/objects", dir);
    char **names;
    int n = list_dir(od, &names);
    for (int i = 0; i < n; i++) {
        snprintf(p, sizeof p, "%s/%s", od, names[i]);
        unlink(p);
        free(names[i]);
    }
    if (n >= 0) free(names);
}

/* Recursive copy of directories and regular files (a crash-state snapshot). */
int copy_tree(const char *src, const char *dst)
{
    if (mkdir(dst, 0700) != 0) return -1;
    DIR *d = opendir(src);
    if (!d) return -1;
    struct dirent *de;
    int rc = 0;
    while (!rc && (de = readdir(d))) {
        if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0) continue;
        char a[1024], b[1024];
        snprintf(a, sizeof a, "%s/%s", src, de->d_name);
        snprintf(b, sizeof b, "%s/%s", dst, de->d_name);
        struct stat st;
        if (lstat(a, &st) != 0) rc = -1;
        else if (S_ISDIR(st.st_mode)) rc = copy_tree(a, b);
        else if (S_ISREG(st.st_mode)) {
            size_t n;
            uint8_t *p = slurp(a, &n);
            if (!p) rc = -1;
            else spit(b, p, n);
            free(p);
            chmod(b, st.st_mode & 07777);
        }
    }
    closedir(d);
    return rc;
}

void durable_set(const char *dir, uint64_t seq, const uint8_t head[32], bool synced)
{
    imdb_durable w = {.seq = seq, .synced = synced};
    memcpy(w.head, head, 32);
    uint8_t b[IMDB_DURABLE_LEN];
    imdb_durable_encode(&w, b);
    char p[700];
    snprintf(p, sizeof p, "%s/%s", dir, IMDB_DURABLE_NAME);
    spit(p, b, sizeof b);
}

/* A segment file's frames (its untagged form), whichever format it is in; *first from its name. */
uint8_t *seg_frames(const char *path, size_t *n, uint64_t *first, bool *tagged)
{
    const char *base = strrchr(path, '/');
    uint64_t f = 0;
    if (!imdb_logseg_parse(base ? base + 1 : path, &f)) return NULL;
    size_t raw = 0;
    uint8_t *b = slurp(path, &raw);
    if (!b) return NULL;
    *first = f;
    *tagged = imdb_tseg_is_tagged(b, raw);
    *n = raw;
    if (*tagged) {
        imdb_tseg_end end;
        imdb_err e = {0};
        imdb_tseg_scan(b, raw, f, n, &end, &e);
    }
    return b;
}

/* Writes frames back as segment path: untagged as they are, tagged as one group with no fill (how
 * redaction rewrites one), so a test that edits frames keeps the file's format. */
void seg_put_frames(const char *path, uint64_t first, bool tagged, const uint8_t *b, size_t n)
{
    if (!tagged) {
        spit(path, b, n);
        return;
    }
    imdb_buf o;
    imdb_buf_init(&o);
    imdb_tseg_build(first, b, n, &o);
    if (!o.err) spit(path, o.p, o.len);
    imdb_buf_free(&o);
}

/* Two logs alike as design.md §1 has them since tagged segments: the same segment names, and in
 * each the same frames (the files' sectors may differ: each copy's groups follow its own syncs). */
bool logs_identical(const char *a, const char *b, char *why, size_t whylen)
{
    char **la, **lb;
    int na = list_dir(a, &la), nb = list_dir(b, &lb);
    bool same = na == nb && na >= 0;
    if (!same) snprintf(why, whylen, "%s has %d segments, %s has %d", a, na, b, nb);
    for (int i = 0; same && i < na; i++) {
        if (strcmp(la[i], lb[i]) != 0) {
            snprintf(why, whylen, "segment %s vs %s", la[i], lb[i]);
            same = false;
            break;
        }
        char pa[1024], pb[1024];
        snprintf(pa, sizeof pa, "%s/%s", a, la[i]);
        snprintf(pb, sizeof pb, "%s/%s", b, lb[i]);
        size_t x = 0, y = 0;
        uint64_t fa, fb;
        bool ta, tb;
        uint8_t *ba = seg_frames(pa, &x, &fa, &ta), *bb = seg_frames(pb, &y, &fb, &tb);
        same = ba && bb && x == y && memcmp(ba, bb, x) == 0;
        if (!same) snprintf(why, whylen, "segment %s: other frames", la[i]);
        free(ba);
        free(bb);
    }
    for (int i = 0; i < na; i++) free(la[i]);
    for (int i = 0; i < nb; i++) free(lb[i]);
    if (na >= 0) free(la);
    if (nb >= 0) free(lb);
    return same;
}

/* Appends frame bytes to segment path where the writer would put them: an untagged segment at its
 * end; a tagged one as a new group at its first fresh sector, tagged with the seq its scan expects
 * next (so a damaged frame lands where a torn append would have left it). */
void seg_append(const char *path, const uint8_t *b, size_t n)
{
    size_t raw = 0;
    uint8_t *f = slurp(path, &raw);
    const char *base = strrchr(path, '/');
    uint64_t first = 0;
    if (!f || !imdb_logseg_parse(base ? base + 1 : path, &first)) {
        free(f);
        return;
    }
    if (!imdb_tseg_is_tagged(f, raw)) {
        int fd = open(path, O_WRONLY | O_APPEND | O_CLOEXEC);
        if (fd >= 0 && write(fd, b, n) != (ssize_t)n) fprintf(stderr, "seg_append: short write\n");
        if (fd >= 0) close(fd);
        free(f);
        return;
    }
    imdb_tseg_end end;
    size_t len = 0;
    imdb_err e = {0};
    imdb_tseg_scan(f, raw, first, &len, &end, &e);
    imdb_tgroup g;
    imdb_tgroup_begin(&g, end.last + 1, end.next);
    imdb_buf o;
    imdb_buf_init(&o);
    imdb_tgroup_put(&g, b, n, &o);
    int fd = open(path, O_WRONLY | O_CLOEXEC);
    if (fd >= 0 && !o.err && pwrite(fd, o.p, o.len, (off_t)(end.next * IMDB_TSEG_SECTOR)) != (ssize_t)o.len)
        fprintf(stderr, "seg_append: short write\n");
    if (fd >= 0) close(fd);
    imdb_buf_free(&o);
    free(f);
}

long seg_frames_len(const char *path)
{
    size_t n = 0;
    uint64_t first;
    bool tagged;
    uint8_t *b = seg_frames(path, &n, &first, &tagged);
    free(b);
    return b ? (long)n : -1;
}
