/*
 * imagedb-audit: independent verifier and reader for imagedb data directories.
 *
 * Written from the format descriptions (design.md, src/log.h, src/lake.h) and
 * sharing no code with the engine: it has its own decoders, its own SHA-256,
 * SHA-512, CRC32C and Ed25519 verification (acrypto.c), and it trusts only the
 * writer public key pinned in META.
 *
 *   imagedb-audit verify <dir>
 *       hash chain, every Ed25519 signature, row commitments, the state digest
 *       of every commit, erasure authorisation and completeness, unique indexes
 *       (every commit whose log still holds the rows, and every manifest's live
 *       rows), then the published lake (manifest, segments, deletion vectors)
 *       against the log. Memory: the payload of every live row, kept for the
 *       unique indexes (a CREATE UNIQUE INDEX may come at any commit), so about
 *       the live data's size; history costs a small record per version. On
 *       bench/mem_split's database (700,500 versions, 150,500 live) the peak RSS
 *       is 162.6 MB, against 136.6 MB before the payloads were kept: about 170
 *       bytes per live row.
 *   imagedb-audit count <dir> <table> [col=value]... [--as-of N | --lake]
 *       COUNT(*) and SUM of the INT64/DECIMAL/FLOAT64 value columns at the latest durable commit (or N),
 *       from files only: the lake snapshot plus the authenticated log tail after it (--lake: the
 *       snapshot alone)
 *   imagedb-audit digest <dir> <table> [col=value]... [--as-of N | --lake]
 *       LtHash digest of the matching rows, at the same read point
 *   imagedb-audit identity <dir> [--as-of N | --lake]
 *       db id, commit, head, state digest and view token (the engine's SHOW IDENTITY)
 *
 * Exit status: 0 verified, 1 verification failure, 2 usage.
 */
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "acrypto.h"
#include "afsum.h"

#define LIVE ((uint64_t)INT64_MAX)
#define MAX_COLS 64
#define MAX_TEXT 65535u
#define MAX_ROW (1u << 20)
#define MAX_FRAME (1u << 30)
#define MAX_OBJECT (1ull << 34)
#define LANES 1024

enum { T_INT64 = 1, T_DECIMAL = 2, T_TEXT = 3, T_BOOL = 4, T_TIMESTAMP = 5, T_FLOAT64 = 6 };
enum { F_PK = 1, F_SUBJECT = 2, F_NULLABLE = 4 };
#define TS_MIN (-62135596800000000LL)
#define TS_MAX (253402300799999999LL)

/* ---- failure ---------------------------------------------------------------- */

static char g_err[600];
static char g_note[200]; /* printed with an answer: how it was reached, when that needs saying */
static bool g_vanished;  /* a lake object went while it was read: a newer publication's GC */

__attribute__((format(printf, 1, 2))) static int fail(const char *fmt, ...)
{
    if (g_err[0]) return -1; /* keep the first reason */
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(g_err, sizeof g_err, fmt, ap);
    va_end(ap);
    return -1;
}

static void *xcalloc(size_t n, size_t sz)
{
    if (sz && n > SIZE_MAX / sz) {
        fputs("imagedb-audit: allocation too large\n", stderr);
        exit(1);
    }
    void *p = calloc(n ? n : 1, sz ? sz : 1);
    if (!p) {
        fputs("imagedb-audit: out of memory\n", stderr);
        exit(1);
    }
    return p;
}

static void *xrealloc(void *p, size_t n, size_t sz)
{
    if (sz && n > SIZE_MAX / sz) {
        fputs("imagedb-audit: allocation too large\n", stderr);
        exit(1);
    }
    size_t bytes = n * sz;
    void *q = realloc(p, bytes ? bytes : 1);
    if (!q) {
        fputs("imagedb-audit: out of memory\n", stderr);
        exit(1);
    }
    return q;
}

static void hex(const uint8_t *p, size_t n, char *out)
{
    static const char d[] = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) {
        out[2 * i] = d[p[i] >> 4];
        out[2 * i + 1] = d[p[i] & 15];
    }
    out[2 * n] = 0;
}

static bool unhex(const char *s, size_t len, uint8_t *out, size_t n)
{
    if (len != 2 * n) return false;
    for (size_t i = 0; i < 2 * n; i++) {
        char c = s[i];
        int v = c >= '0' && c <= '9' ? c - '0' : c >= 'a' && c <= 'f' ? c - 'a' + 10 : -1;
        if (v < 0) return false;
        if (i & 1) out[i / 2] |= (uint8_t)v;
        else out[i / 2] = (uint8_t)(v << 4);
    }
    return true;
}

static bool all_zero(const uint8_t *p, size_t n)
{
    for (size_t i = 0; i < n; i++)
        if (p[i]) return false;
    return true;
}

static uint32_t le32(const uint8_t *p) { return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24; }
static uint64_t le64(const uint8_t *p)
{
    uint64_t v = 0;
    for (int i = 7; i >= 0; i--) v = v << 8 | p[i];
    return v;
}
static void put32(uint8_t *p, uint32_t v)
{
    for (int i = 0; i < 4; i++) p[i] = (uint8_t)(v >> (8 * i));
}
static void put64(uint8_t *p, uint64_t v)
{
    for (int i = 0; i < 8; i++) p[i] = (uint8_t)(v >> (8 * i));
}

/* ---- files: regular files only, never through a symlink (CVE-2026-6475) ---- */

static int read_file(int dirfd, const char *name, uint8_t **out, size_t *len, uint64_t max)
{
    *out = NULL;
    *len = 0;
    int fd = openat(dirfd, name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) {
        if (errno == ELOOP) return fail("refusing to follow a symbolic link: %s", name);
        return fail("cannot open %s: %s", name, strerror(errno));
    }
    struct stat st;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) {
        close(fd);
        return fail("%s is not a regular file", name);
    }
    if ((uint64_t)st.st_size > max) {
        close(fd);
        return fail("%s is too large", name);
    }
    size_t n = (size_t)st.st_size, got = 0;
    uint8_t *b = xcalloc(n + 1, 1);
    while (got < n) {
        ssize_t r = read(fd, b + got, n - got);
        if (r < 0 && errno == EINTR) continue;
        if (r <= 0) break;
        got += (size_t)r;
    }
    close(fd);
    if (got != n) {
        free(b);
        return fail("%s: short read", name);
    }
    *out = b;
    *len = n;
    return 0;
}

/* ---- bounded reader --------------------------------------------------------------- */

typedef struct rd {
    const uint8_t *p;
    size_t n, o;
    bool bad;
} rd;

static const uint8_t *rd_bytes(rd *r, size_t k)
{
    if (r->bad || k > r->n - r->o) {
        r->bad = true;
        return NULL;
    }
    const uint8_t *q = r->p + r->o;
    r->o += k;
    return q;
}
static uint8_t rd_u8(rd *r)
{
    const uint8_t *q = rd_bytes(r, 1);
    return q ? q[0] : 0;
}
static uint16_t rd_u16(rd *r)
{
    const uint8_t *q = rd_bytes(r, 2);
    return q ? (uint16_t)(q[0] | q[1] << 8) : 0;
}
static uint32_t rd_u32(rd *r)
{
    const uint8_t *q = rd_bytes(r, 4);
    return q ? le32(q) : 0;
}
static uint64_t rd_u64(rd *r)
{
    const uint8_t *q = rd_bytes(r, 8);
    return q ? le64(q) : 0;
}
static size_t rd_left(const rd *r) { return r->n - r->o; }

/* ---- text ---------------------------------------------------------------------------- */

/* Strict UTF-8 (Unicode Table 3-7), NUL rejected. */
static bool utf8_ok(const uint8_t *s, size_t n)
{
    size_t i = 0;
    while (i < n) {
        uint8_t c = s[i];
        if (c == 0) return false;
        if (c < 0x80) {
            i++;
            continue;
        }
        size_t need;
        uint8_t lo = 0x80, hi = 0xBF;
        if (c >= 0xC2 && c <= 0xDF) need = 1;
        else if (c == 0xE0) need = 2, lo = 0xA0;
        else if ((c >= 0xE1 && c <= 0xEC) || c == 0xEE || c == 0xEF) need = 2;
        else if (c == 0xED) need = 2, hi = 0x9F;
        else if (c == 0xF0) need = 3, lo = 0x90;
        else if (c >= 0xF1 && c <= 0xF3) need = 3;
        else if (c == 0xF4) need = 3, hi = 0x8F;
        else return false;
        if (n - i - 1 < need) return false;
        if (s[i + 1] < lo || s[i + 1] > hi) return false;
        for (size_t k = 2; k <= need; k++)
            if ((s[i + k] & 0xC0) != 0x80) return false;
        i += need + 1;
    }
    return true;
}

static bool ident_ok(const uint8_t *s, size_t n)
{
    if (n < 1 || n > 63) return false;
    for (size_t i = 0; i < n; i++) {
        uint8_t c = s[i];
        bool alpha = (c >= 'a' && c <= 'z') || c == '_';
        if (!(alpha || (i && c >= '0' && c <= '9'))) return false; /* folded: no uppercase */
    }
    return true;
}

/* ---- schemas and rows ------------------------------------------------------------- */

typedef struct col {
    char name[64];
    uint8_t type, prec, scale, flags;
} col;

typedef struct schema {
    uint32_t id;
    char name[64];
    int ncols, pk, subject;
    col c[MAX_COLS];
    uint8_t *raw; /* canonical encoding as it appeared in the log */
    size_t rawlen;
} schema;

static int64_t pow10i(int n)
{
    int64_t v = 1;
    for (int i = 0; i < n; i++) v *= 10;
    return v;
}

static int decode_schema(rd *r, schema *s)
{
    size_t start = r->o;
    memset(s, 0, sizeof *s);
    s->id = rd_u32(r);
    uint8_t nl = rd_u8(r);
    const uint8_t *nm = rd_bytes(r, nl);
    if (!nm || !ident_ok(nm, nl)) return fail("schema: bad table name");
    memcpy(s->name, nm, nl);
    s->ncols = rd_u16(r);
    if (s->ncols < 1 || s->ncols > MAX_COLS) return fail("schema: bad column count");
    s->pk = s->subject = -1;
    for (int i = 0; i < s->ncols; i++) {
        col *c = &s->c[i];
        uint8_t cl = rd_u8(r);
        const uint8_t *cn = rd_bytes(r, cl);
        if (!cn || !ident_ok(cn, cl) || cn[0] == '_') return fail("schema: bad column name");
        memcpy(c->name, cn, cl);
        for (int j = 0; j < i; j++)
            if (strcmp(s->c[j].name, c->name) == 0) return fail("schema: duplicate column");
        c->type = rd_u8(r);
        c->prec = rd_u8(r);
        c->scale = rd_u8(r);
        c->flags = rd_u8(r);
        if (r->bad) return fail("schema: truncated");
        if (c->type < T_INT64 || c->type > T_FLOAT64 || (c->flags & ~(F_PK | F_SUBJECT | F_NULLABLE)) ||
            ((c->flags & F_NULLABLE) && (c->flags & (F_PK | F_SUBJECT))))
            return fail("schema: bad column type or flags");
        if (c->type == T_DECIMAL ? (c->prec < 1 || c->prec > 18 || c->scale > c->prec) : (c->prec || c->scale))
            return fail("schema: bad precision/scale");
        if (c->flags & F_PK) {
            if (s->pk >= 0 || (c->type != T_INT64 && c->type != T_TEXT)) return fail("schema: bad PRIMARY KEY");
            s->pk = i;
        }
        if (c->flags & F_SUBJECT) {
            if (s->subject >= 0 || (c->type != T_INT64 && c->type != T_TEXT)) return fail("schema: bad SUBJECT");
            s->subject = i;
        }
    }
    if (s->pk < 0) return fail("schema: no PRIMARY KEY");
    s->rawlen = r->o - start;
    s->raw = xcalloc(s->rawlen, 1);
    memcpy(s->raw, r->p + start, s->rawlen);
    return 0;
}

typedef struct val {
    int64_t i;
    const uint8_t *s;
    uint32_t len;
    bool null;
} val;

/* A FLOAT64 is stored as an int64 key: a non-negative double's bits as they are, a
 * negative one's with its 63 low bits flipped. Only finite doubles, and +0.0 alone for zero. */
static bool float_key_ok(int64_t key)
{
    uint64_t bits = key < 0 ? (uint64_t)key ^ 0x7fffffffffffffffull : (uint64_t)key;
    if (bits == 0x8000000000000000ull) return false;
    return (bits & 0x7ff0000000000000ull) != 0x7ff0000000000000ull;
}

static double float_value(int64_t key)
{
    uint64_t bits = key < 0 ? (uint64_t)key ^ 0x7fffffffffffffffull : (uint64_t)key;
    double d;
    memcpy(&d, &bits, 8);
    return d;
}

static int count_nullable(const schema *s)
{
    int k = 0;
    for (int i = 0; i < s->ncols; i++) k += (s->c[i].flags & F_NULLABLE) != 0;
    return k;
}

static int check_value(const col *c, const val *v)
{
    if (c->type == T_DECIMAL && (v->i > pow10i(c->prec) - 1 || v->i < -(pow10i(c->prec) - 1)))
        return fail("value out of DECIMAL range in column %s", c->name);
    if (c->type == T_TIMESTAMP && (v->i < TS_MIN || v->i > TS_MAX)) return fail("TIMESTAMP out of range in column %s", c->name);
    if (c->type == T_BOOL && v->i != 0 && v->i != 1) return fail("bad BOOL in column %s", c->name);
    if (c->type == T_FLOAT64 && !float_key_ok(v->i)) return fail("not a finite FLOAT64 in column %s", c->name);
    if (c->type == T_TEXT && (v->len > MAX_TEXT || (v->len && !utf8_ok(v->s, v->len))))
        return fail("invalid TEXT in column %s", c->name);
    return 0;
}

static int decode_row(const schema *s, const uint8_t *row, size_t n, val *out)
{
    rd r = {row, n, 0, false};
    int nn = count_nullable(s);
    const uint8_t *bm = rd_bytes(&r, (size_t)(nn + 7) / 8);
    if (r.bad) return fail("row: truncated null bitmap");
    if (nn % 8 && bm[nn / 8] >> (nn % 8)) return fail("row: null bitmap padding is not zero");
    for (int i = 0, k = 0; i < s->ncols; i++) {
        val *v = &out[i];
        memset(v, 0, sizeof *v);
        if (s->c[i].flags & F_NULLABLE) {
            v->null = bm[k / 8] >> (k % 8) & 1;
            k++;
            if (v->null) continue;
        }
        uint8_t t = s->c[i].type;
        if (t == T_TEXT) {
            v->len = rd_u32(&r);
            if (v->len > MAX_TEXT) return fail("row: TEXT too long");
            v->s = rd_bytes(&r, v->len);
        } else if (t == T_BOOL) {
            v->i = rd_u8(&r);
        } else {
            v->i = (int64_t)rd_u64(&r);
        }
        if (r.bad) return fail("row: truncated");
        if (check_value(&s->c[i], v)) return -1;
    }
    if (rd_left(&r)) return fail("row: trailing bytes");
    return 0;
}

/* Canonical row bytes from column values (inverse of decode_row). */
static size_t encode_row(const schema *s, const val *v, uint8_t **buf, size_t *cap)
{
    int nn = count_nullable(s);
    size_t need = (size_t)(nn + 7) / 8;
    for (int i = 0; i < s->ncols; i++)
        if (!v[i].null) need += s->c[i].type == T_TEXT ? 4 + v[i].len : s->c[i].type == T_BOOL ? 1 : 8;
    if (need > *cap) {
        *buf = xrealloc(*buf, need, 1);
        *cap = need;
    }
    uint8_t *p = *buf;
    memset(p, 0, (size_t)(nn + 7) / 8);
    for (int i = 0, k = 0; i < s->ncols; i++) {
        if (!(s->c[i].flags & F_NULLABLE)) continue;
        if (v[i].null) p[k / 8] |= (uint8_t)(1u << (k % 8));
        k++;
    }
    p += (nn + 7) / 8;
    for (int i = 0; i < s->ncols; i++) {
        if (v[i].null) continue;
        if (s->c[i].type == T_TEXT) {
            put32(p, v[i].len);
            if (v[i].len) memcpy(p + 4, v[i].s, v[i].len);
            p += 4 + v[i].len;
        } else if (s->c[i].type == T_BOOL) {
            *p++ = (uint8_t)v[i].i;
        } else {
            put64(p, (uint64_t)v[i].i);
            p += 8;
        }
    }
    return need;
}

static void row_commit(uint32_t table, const uint8_t salt[16], const uint8_t *row, size_t n, uint8_t out[32])
{
    uint8_t h[32];
    memcpy(h, "IMDBROW1", 8);
    put32(h + 8, table);
    a_sha256_ctx c;
    a_sha256_init(&c);
    a_sha256_update(&c, h, 12);
    a_sha256_update(&c, salt, 16);
    put32(h, (uint32_t)n);
    a_sha256_update(&c, h, 4);
    a_sha256_update(&c, row, n);
    a_sha256_final(&c, out);
}

/* ---- LtHash ---------------------------------------------------------------------- */

typedef struct lt {
    uint16_t v[LANES];
} lt;

static void lt_add(uint8_t alg, lt *a, const uint8_t commit[32])
{
    uint16_t e[LANES];
    a_lthash_element(alg, commit, e);
    for (int i = 0; i < LANES; i++) a->v[i] = (uint16_t)(a->v[i] + e[i]);
}
static void lt_sub(uint8_t alg, lt *a, const uint8_t commit[32])
{
    uint16_t e[LANES];
    a_lthash_element(alg, commit, e);
    for (int i = 0; i < LANES; i++) a->v[i] = (uint16_t)(a->v[i] - e[i]);
}
static void lt_sum(lt *a, const lt *b)
{
    for (int i = 0; i < LANES; i++) a->v[i] = (uint16_t)(a->v[i] + b->v[i]);
}
static void lt_bytes(const lt *a, uint8_t out[2 * LANES])
{
    for (int i = 0; i < LANES; i++) {
        out[2 * i] = (uint8_t)a->v[i];
        out[2 * i + 1] = (uint8_t)(a->v[i] >> 8);
    }
}
/* the state's digest by the database's algorithm: 1, SHA256("IMDBLTD1" || lanes); 2, the root
 * SHA256("IMDBLTR2" || leaf_0 .. leaf_7) of leaf_i = SHA256("IMDBLTL2" || u32 i LE || lane bytes
 * 256 i .. 256 i + 255), each through a_sha256, which pads */
static void lt_digest(uint8_t alg, const lt *a, uint8_t out[32])
{
    uint8_t b[8 + 2 * LANES];
    if (alg == 2) {
        uint8_t lanes[2 * LANES], leaf[8 + 4 + 256], root[8 + 8 * 32];
        lt_bytes(a, lanes);
        memcpy(root, "IMDBLTR2", 8);
        for (uint32_t i = 0; i < 8; i++) {
            memcpy(leaf, "IMDBLTL2", 8);
            put32(leaf + 8, i);
            memcpy(leaf + 12, lanes + 256 * i, 256);
            a_sha256(leaf, sizeof leaf, root + 8 + 32 * i);
        }
        a_sha256(root, sizeof root, out);
        return;
    }
    memcpy(b, "IMDBLTD1", 8);
    lt_bytes(a, b + 8);
    a_sha256(b, sizeof b, out);
}

/* ---- META ----------------------------------------------------------------------------- */

/* META v2: db id, role, the writer key of epoch 0; v3 adds the root key that may certify a
 * promotion; v4 (digest_alg 2's) always names the digest algorithm, after the root key's line,
 * which it has only when the database has a root key. v2 and v3 are digest_alg 1. */
typedef struct meta {
    uint8_t db_id[16], writer[32], root[32];
    bool replica, has_root;
    uint8_t alg; /* every commit's header names it */
} meta;

static int read_meta(int dirfd, meta *m)
{
    uint8_t *b;
    size_t n;
    if (read_file(dirfd, "META", &b, &n, 4096)) return -1;
    static const char a2[] = "imagedb-meta 2\ndb_id ", a3[] = "imagedb-meta 3\ndb_id ", a4[] = "imagedb-meta 4\ndb_id ";
    const char *s = (const char *)b;
    size_t off = sizeof a2 - 1;
    int rc = 0;
    bool v3 = n >= off && memcmp(s, a3, off) == 0, v4 = n >= off && memcmp(s, a4, off) == 0;
    memset(m, 0, sizeof *m);
    m->alg = 1;
    if (n < off + 33 || (!v3 && !v4 && memcmp(s, a2, off) != 0) || !unhex(s + off, 32, m->db_id, 16) || s[off + 32] != '\n') {
        rc = fail("META malformed (expected imagedb-meta 2, 3 or 4)");
    } else {
        off += 33;
        if (n - off >= 13 && memcmp(s + off, "role primary\n", 13) == 0) m->replica = false;
        else if (n - off >= 13 && memcmp(s + off, "role replica\n", 13) == 0) m->replica = true;
        else rc = fail("META: malformed role");
        off += 13;
        if (!rc && (n - off < 7 + 64 + 1 || memcmp(s + off, "writer ", 7) != 0 || !unhex(s + off + 7, 64, m->writer, 32) ||
                    s[off + 71] != '\n'))
            rc = fail("META: malformed writer key");
        off += 72;
        bool root = v3 || (v4 && !rc && n - off >= 5 && memcmp(s + off, "root ", 5) == 0);
        if (!rc && root && (n - off < 5 + 64 + 1 || memcmp(s + off, "root ", 5) != 0 || !unhex(s + off + 5, 64, m->root, 32) ||
                            s[off + 69] != '\n'))
            rc = fail("META: malformed root key");
        if (!rc && root) off += 70;
        m->has_root = root;
        if (!rc && v4) {
            if (n - off != 9 || memcmp(s + off, "digest ", 7) != 0 || s[off + 8] != '\n' || (s[off + 7] != '1' && s[off + 7] != '2'))
                rc = fail("META: malformed digest algorithm (1 or 2)");
            else m->alg = (uint8_t)(s[off + 7] - '0'), off += 9;
        }
        if (!rc && off != n) rc = fail("META: trailing bytes");
    }
    free(b);
    return rc;
}

/* The writer keys: epoch 0 from META, each WRITER_KEY commit adds the next (decode_body moves it
 * once the commit passed every check). ek[i], efirst[i], eprom[i]: epoch i's key, the first commit
 * it signs, whether a promotion made it. */
typedef struct keys {
    uint32_t epoch;
    uint8_t cur[32];
    uint8_t (*ek)[32];
    uint64_t *efirst;
    bool *eprom;
    uint32_t nek;
} keys;

static void keys_init(keys *k, const meta *m)
{
    memset(k, 0, sizeof *k);
    memcpy(k->cur, m->writer, 32);
    k->ek = xcalloc(1, sizeof *k->ek);
    k->efirst = xcalloc(1, sizeof *k->efirst);
    k->eprom = xcalloc(1, sizeof *k->eprom);
    memcpy(k->ek[0], m->writer, 32);
    k->efirst[0] = 1;
    k->nek = 1;
}

static void keys_free(keys *k)
{
    free(k->ek);
    free(k->efirst);
    free(k->eprom);
    memset(k, 0, sizeof *k);
}

static void keys_push(keys *k, const uint8_t pk[32], uint64_t first, bool promote)
{
    k->ek = xrealloc(k->ek, k->nek + 1, sizeof *k->ek);
    k->efirst = xrealloc(k->efirst, k->nek + 1, sizeof *k->efirst);
    k->eprom = xrealloc(k->eprom, k->nek + 1, sizeof *k->eprom);
    memcpy(k->ek[k->nek], pk, 32);
    k->efirst[k->nek] = first;
    k->eprom[k->nek] = promote;
    k->nek++;
    k->epoch++;
    memcpy(k->cur, pk, 32);
}

/* the epoch whose key signed commit seq */
static uint32_t keys_epoch_at(const keys *k, uint64_t seq)
{
    uint32_t i = k->nek;
    while (i > 1 && k->efirst[i - 1] > seq) i--;
    return i - 1;
}

/* ---- commit log ---------------------------------------------------------------------- */

typedef struct erase_ent {
    uint32_t table;
    uint64_t vid;
    uint8_t commit[32];
} erase_ent;

/* an index definition (CREATE INDEX): its name, flags (1: unique) and columns in key order */
#define MAX_INDEXES 16
#define MAX_INDEX_COLS 4
struct ukmap;
typedef struct aidx {
    char name[64];
    uint8_t flags, ncols;
    uint16_t cols[MAX_INDEX_COLS];
    struct ukmap *uk; /* unique, in the log's model: the live rows' keys (else NULL) */
} aidx;

/* an index definition by its own rules: known flags, 1..MAX_INDEX_COLS distinct columns, each
 * below ncols (ncols 0: the table is not known yet) */
static bool aidx_ok(const aidx *x, int ncols)
{
    if ((x->flags & ~1u) || !x->ncols || x->ncols > MAX_INDEX_COLS) return false;
    for (int i = 0; i < x->ncols; i++) {
        if (ncols && x->cols[i] >= ncols) return false;
        for (int j = 0; j < i; j++)
            if (x->cols[i] == x->cols[j]) return false;
    }
    return true;
}

static bool aidx_same(const aidx *a, const aidx *b)
{
    return strcmp(a->name, b->name) == 0 && a->flags == b->flags && a->ncols == b->ncols &&
           memcmp(a->cols, b->cols, a->ncols * sizeof *a->cols) == 0;
}

typedef struct op {
    uint8_t code;
    uint32_t table;
    uint64_t vid, new_vid, purge_before;
    const uint8_t *commit, *new_commit, *manifest;
    schema *sch;
    erase_ent *erase;
    uint32_t n_erase;
    uint32_t epoch; /* WRITER_KEY: the next epoch, its key, 1 rotation or 2 promotion */
    const uint8_t *new_pk;
    uint8_t how;
    aidx ix; /* CREATE_INDEX (14): the definition; DROP_INDEX (15): its name only */
    char iname[64];
    /* payload */
    bool redacted;
    const uint8_t *salt, *row;
    uint32_t row_len;
} op;

typedef struct commit {
    uint64_t seq, time;
    const uint8_t *prev, *digest;
    uint8_t hash[32];
    op *ops;
    uint32_t nops;
    uint32_t epoch; /* whose key signed it */
} commit;

static void commit_free(commit *c)
{
    for (uint32_t i = 0; i < c->nops; i++) {
        if (c->ops[i].sch) free(c->ops[i].sch->raw);
        free(c->ops[i].sch);
        free(c->ops[i].erase);
    }
    free(c->ops);
    memset(c, 0, sizeof *c);
}

/* A body: kind 2, or kind 3 (a promotion: after the descriptor, u32 epoch | new key | the root's
 * signature over "IMDBPRO1" || db id || epoch || seq || prev || new key). The signature is checked
 * under k's current key, a promotion's under the key its root certificate names; a WRITER_KEY
 * commit moves k once everything else passed. */
static int decode_body(const uint8_t *b, size_t n, const meta *m, keys *ks, commit *c)
{
    memset(c, 0, sizeof *c);
    rd r = {b, n, 0, false};
    uint8_t bkind = rd_u8(&r);
    if (bkind != 2 && bkind != 3) return fail("frame: unknown body kind");
    uint32_t hlen = rd_u32(&r);
    uint64_t dseq = rd_u64(&r);
    const uint8_t *dhash = rd_bytes(&r, 32), *sig = rd_bytes(&r, 64), *ext = bkind == 3 ? rd_bytes(&r, 100) : NULL;
    const uint8_t *h = rd_bytes(&r, hlen);
    uint32_t plen = rd_u32(&r);
    const uint8_t *p = rd_bytes(&r, plen);
    if (r.bad || rd_left(&r)) return fail("frame: malformed body");
    uint8_t tagged[8];
    memcpy(tagged, "IMDBCHN2", 8);
    a_sha256_ctx hc;
    a_sha256_init(&hc);
    a_sha256_update(&hc, tagged, 8);
    a_sha256_update(&hc, h, hlen);
    a_sha256_final(&hc, c->hash);
    if (memcmp(c->hash, dhash, 32) != 0) return fail("frame: header does not match its descriptor hash");
    const uint8_t *signer = ks->cur;
    c->epoch = ks->epoch;
    if (ext) { /* the root certifies the next epoch's key on top of exactly this history */
        if (hlen < 86) return fail("frame: short header"); /* prev is at 18..49 */
        uint8_t pm[100];
        memcpy(pm, "IMDBPRO1", 8);
        memcpy(pm + 8, m->db_id, 16);
        memcpy(pm + 24, ext, 4);
        put64(pm + 28, dseq);
        memcpy(pm + 36, h + 18, 32); /* the header's prev (version, alg, seq, time before it) */
        memcpy(pm + 68, ext + 4, 32);
        if (!m->has_root || !a_ed25519_verify(m->root, pm, sizeof pm, ext + 36))
            return fail("commit %llu: a promotion without this database's root certificate", (unsigned long long)dseq);
        signer = ext + 4;
        c->epoch = ks->epoch + 1;
    }
    uint8_t msg[52];
    memcpy(msg, "IMDBSIG2", 8);
    put64(msg + 8, dseq);
    put32(msg + 16, hlen);
    memcpy(msg + 20, c->hash, 32);
    if (!a_ed25519_verify(signer, msg, sizeof msg, sig))
        return fail("commit %llu: signature invalid (not signed by the writer key of epoch %u)", (unsigned long long)dseq,
                    c->epoch);

    rd hr = {h, hlen, 0, false};
    uint8_t hver = rd_u8(&hr), halg = rd_u8(&hr);
    if (hver != 2) return fail("header: unsupported version");
    if (halg != m->alg) /* never mixed in one log: every digest is computed by META's algorithm */
        return fail("commit %llu: digest algorithm %u, but this database's is %u", (unsigned long long)dseq, halg, m->alg);
    c->seq = rd_u64(&hr);
    c->time = rd_u64(&hr);
    c->prev = rd_bytes(&hr, 32);
    uint32_t nops = rd_u32(&hr);
    if (hr.bad || c->seq != dseq) return fail("header: truncated or descriptor seq mismatch");
    if (nops > (1u << 20) || nops > rd_left(&hr) / 33) return fail("header: op count out of range");
    c->ops = xcalloc(nops, sizeof *c->ops);
    c->nops = nops;
    for (uint32_t i = 0; i < nops; i++) {
        op *o = &c->ops[i];
        o->code = rd_u8(&hr);
        switch (o->code) {
        case 1:
            o->table = rd_u32(&hr);
            o->sch = xcalloc(1, sizeof *o->sch);
            if (decode_schema(&hr, o->sch)) return -1;
            if (o->sch->id != o->table) return fail("header: schema id mismatch");
            break;
        case 2:
        case 3:
            o->table = rd_u32(&hr);
            o->vid = rd_u64(&hr);
            o->commit = rd_bytes(&hr, 32);
            break;
        case 4:
            o->table = rd_u32(&hr);
            o->vid = rd_u64(&hr);
            o->commit = rd_bytes(&hr, 32);
            o->new_vid = rd_u64(&hr);
            o->new_commit = rd_bytes(&hr, 32);
            break;
        case 10:
            o->manifest = rd_bytes(&hr, 32);
            break;
        case 11:
            o->table = rd_u32(&hr);
            o->purge_before = rd_u64(&hr);
            o->manifest = rd_bytes(&hr, 32);
            break;
        case 12: {
            uint32_t k = rd_u32(&hr);
            if (hr.bad || k == 0 || k > (1u << 24) || k > rd_left(&hr) / 44) return fail("ERASE: bad count");
            o->erase = xcalloc(k, sizeof *o->erase);
            o->n_erase = k;
            for (uint32_t j = 0; j < k; j++) {
                o->erase[j].table = rd_u32(&hr);
                o->erase[j].vid = rd_u64(&hr);
                const uint8_t *cm = rd_bytes(&hr, 32);
                if (cm) memcpy(o->erase[j].commit, cm, 32);
                if (j && (o->erase[j - 1].table > o->erase[j].table ||
                          (o->erase[j - 1].table == o->erase[j].table && o->erase[j - 1].vid >= o->erase[j].vid)))
                    return fail("ERASE: entries not strictly sorted");
            }
            uint32_t m2 = rd_u32(&hr);
            if (hr.bad || m2 > 65536u * 4u || m2 > rd_left(&hr) / 68) return fail("ERASE: bad rewrite count");
            const uint8_t *prevrw = NULL;
            for (uint32_t j = 0; j < m2; j++) {
                const uint8_t *rw = rd_bytes(&hr, 68);
                if (rw && prevrw && (le32(prevrw) > le32(rw) || (le32(prevrw) == le32(rw) && memcmp(prevrw + 4, rw + 4, 32) >= 0)))
                    return fail("ERASE: rewrites not strictly sorted");
                prevrw = rw;
            }
            o->manifest = rd_bytes(&hr, 32);
            break;
        }
        case 14:
        case 15: {
            o->table = rd_u32(&hr);
            if (o->code == 14) {
                o->ix.flags = rd_u8(&hr);
                o->ix.ncols = rd_u8(&hr);
                for (int k = 0; k < o->ix.ncols && k < MAX_INDEX_COLS; k++) o->ix.cols[k] = rd_u16(&hr);
                if (!hr.bad && !aidx_ok(&o->ix, 0)) return fail("header: bad index definition");
            }
            uint8_t nl = rd_u8(&hr);
            const uint8_t *nm = rd_bytes(&hr, nl);
            if (!hr.bad && !ident_ok(nm, nl)) return fail("header: bad index name");
            if (nm) memcpy(o->iname, nm, nl);
            if (!hr.bad && nops != 1) return fail("header: an index op must be the only op");
            break;
        }
        case 13:
            o->epoch = rd_u32(&hr);
            o->new_pk = rd_bytes(&hr, 32);
            o->how = rd_u8(&hr);
            if (!hr.bad && (nops != 1 || o->epoch == 0 || (o->how != 1 && o->how != 2)))
                return fail("header: WRITER_KEY must be the only op, with epoch >= 1 and how 1 or 2");
            break;
        default:
            return fail("header: unknown op %u", o->code);
        }
        if (hr.bad) return fail("header: truncated op");
    }
    c->digest = rd_bytes(&hr, 32);
    if (hr.bad || rd_left(&hr)) return fail("header: truncated or trailing bytes");
    const op *w = nops == 1 && c->ops[0].code == 13 ? &c->ops[0] : NULL;
    if ((w && w->how == 2) != (ext != NULL))
        return fail("commit %llu: a promotion must come in a body of kind 3, and only a promotion", (unsigned long long)dseq);
    if (ext && (le32(ext) != w->epoch || memcmp(ext + 4, w->new_pk, 32) != 0))
        return fail("commit %llu: the promotion's certificate names another key", (unsigned long long)dseq);
    if (w && w->epoch != ks->epoch + 1)
        return fail("commit %llu: WRITER_KEY names epoch %u after epoch %u", (unsigned long long)dseq, w->epoch, ks->epoch);

    rd pr = {p, plen, 0, false};
    for (uint32_t i = 0; i < nops; i++) {
        op *o = &c->ops[i];
        if (o->code != 2 && o->code != 4) continue;
        uint8_t kind = rd_u8(&pr);
        if (pr.bad || kind > 1) return fail("payload: bad entry");
        o->redacted = kind == 1;
        if (o->redacted) continue;
        o->salt = rd_bytes(&pr, 16);
        o->row_len = rd_u32(&pr);
        if (o->row_len > MAX_ROW) return fail("payload: row too long");
        o->row = rd_bytes(&pr, o->row_len);
        if (pr.bad) return fail("payload: truncated");
    }
    if (rd_left(&pr)) return fail("payload: trailing bytes");
    if (w) keys_push(ks, w->new_pk, w->how == 1 ? c->seq + 1 : c->seq, w->how == 2); /* the next commits verify under it */
    return 0;
}

/* ---- commitment-level state rebuilt from the log alone ------------------------------- */

typedef struct ver {
    uint8_t commit[32];
    uint64_t begin, end;
    bool payload;   /* the log still holds this version's row */
    bool redacted;  /* the log holds a redaction marker instead */
    bool stub;      /* named by an ERASE */
    bool has_subj;  /* the SUBJECT value from the payload (to check tombstones) */
    int64_t subj_i;
    uint8_t *subj_s;
    uint32_t subj_len;
    uint8_t *row; /* a live version's payload, kept for the unique indexes (freed when it ends) */
    uint32_t row_len;
} ver;

typedef struct table {
    schema s;
    ver *v;
    uint64_t n, cap, live;
    lt d, d_at_lake;     /* digest now, and at the lake snapshot commit */
    uint64_t horizon_at_lake;
    aidx idx[MAX_INDEXES], idx_at_lake[MAX_INDEXES]; /* sorted by name, now and at the lake snapshot */
    uint32_t nidx, nidx_at_lake;
} table;

typedef struct state {
    meta m;
    table *t;
    uint32_t nt;
    lt glob;
    uint64_t seq, payload_rows, sigs, last_erase;
    uint8_t head[32];
    uint64_t lake_seq;       /* from LAKE_HEAD, 0 if none */
    uint8_t lake_manifest[32];
    bool lake_recorded;      /* the commit at lake_seq records lake_manifest */
    uint8_t lake_digest[32]; /* recorded state digest at lake_seq */
    uint8_t lake_prev[32];
    uint8_t last_manifest[32];     /* the manifest recorded by the latest publishing commit so far */
    uint8_t lake_prev_manifest[32]; /* what the snapshot's prev_manifest must be */
    bool dur_present, dur_synced, dur_strict; /* DURABLE: the writer's durable watermark */
    keys K;                  /* the writer keys so far */
    int anc_n;               /* --anchor: its intact records (checked once the log's keys are known) */
    uint8_t anc_rec[2][144];
    bool anc_seen[2];        /* replay met the commit a record names: its hash and the epoch that signed it */
    uint8_t anc_hash_at[2][32];
    uint32_t anc_epoch_at[2];
    uint64_t dur_seq;
    uint8_t dur_head[32];
    uint8_t (*pin)[32];      /* the generations pins/ names (a reader holds or held each), sorted */
    uint64_t *pin_at;        /* the commit that published each, 0 if none */
    size_t npin, cappin;
    char note[200];
} state;

static int cmp32(const void *a, const void *b) { return memcmp(a, b, 32); }

/* pins/ (the engine's lake.h): the generations readers pin, each a 64-hex-digit name + .pin; their
 * files count as kept if the log published them at or after its last ERASE (check_objects). */
static int load_pins(int dirfd, state *S)
{
    int pfd = openat(dirfd, "pins", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (pfd < 0) return errno == ENOENT ? 0 : fail("pins/: %s", errno == ELOOP ? "refusing to follow a symbolic link" : strerror(errno));
    DIR *d = fdopendir(pfd);
    if (!d) {
        close(pfd);
        return fail("pins/: cannot list the directory");
    }
    int rc = 0;
    struct dirent *de;
    while (!rc && (de = readdir(d))) {
        if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0) continue;
        uint8_t h[32];
        if (strlen(de->d_name) != 68 || strcmp(de->d_name + 64, ".pin") != 0 || !unhex(de->d_name, 64, h, 32)) {
            rc = fail("unexpected file in pins/: %s", de->d_name);
            break;
        }
        if (S->npin == 4096) {
            rc = fail("pins/: more than 4096 pins");
            break;
        }
        if (S->npin == S->cappin) { /* grown as pins/ is read: proportional to it */
            S->cappin = S->cappin ? 2 * S->cappin : 8;
            S->pin = xrealloc(S->pin, S->cappin, sizeof *S->pin);
            S->pin_at = xrealloc(S->pin_at, S->cappin, sizeof *S->pin_at);
        }
        S->pin_at[S->npin] = 0;
        memcpy(S->pin[S->npin++], h, 32);
    }
    closedir(d);
    if (!rc && S->npin) qsort(S->pin, S->npin, sizeof *S->pin, cmp32);
    return rc;
}

/* ---- unique indexes: the live rows' keys, per index (the auditor's own map) --------------------
 * Keys hash by SHA-256 (a hostile log cannot flood the probes), open addressing, deletion by
 * backward shift. A key is each column in 8 bytes, a TEXT as a u32 length and its bytes; a NULL
 * in any column exempts the row. */
typedef struct ukslot {
    uint8_t *k;
    size_t n;
    uint64_t h; /* 0: empty */
    uint64_t vid;
} ukslot;

typedef struct ukmap {
    ukslot *s;
    size_t cap, count;
} ukmap;

static uint64_t uk_hash(const uint8_t *k, size_t n)
{
    uint8_t d[32];
    a_sha256(k, n, d);
    return le64(d) | 1;
}

static ukslot *uk_find(const ukmap *m, const uint8_t *k, size_t n, uint64_t h)
{
    if (!m->cap) return NULL;
    for (size_t i = h & (m->cap - 1); m->s[i].h; i = (i + 1) & (m->cap - 1))
        if (m->s[i].h == h && m->s[i].n == n && (!n || memcmp(m->s[i].k, k, n) == 0)) return &m->s[i];
    return NULL;
}

/* takes k over */
static void uk_put(ukmap *m, uint8_t *k, size_t n, uint64_t h, uint64_t vid)
{
    if ((m->count + 1) * 4 > m->cap * 3) {
        size_t nc = m->cap ? 2 * m->cap : 64;
        ukslot *ns = xcalloc(nc, sizeof *ns);
        for (size_t i = 0; i < m->cap; i++)
            if (m->s[i].h) {
                size_t j = m->s[i].h & (nc - 1);
                while (ns[j].h) j = (j + 1) & (nc - 1);
                ns[j] = m->s[i];
            }
        free(m->s);
        m->s = ns;
        m->cap = nc;
    }
    size_t j = h & (m->cap - 1);
    while (m->s[j].h) j = (j + 1) & (m->cap - 1);
    m->s[j] = (ukslot){k, n, h, vid};
    m->count++;
}

static void uk_del(ukmap *m, ukslot *s)
{
    size_t mask = m->cap - 1, i = (size_t)(s - m->s);
    free(s->k);
    memset(s, 0, sizeof *s);
    m->count--;
    for (size_t j = (i + 1) & mask; m->s[j].h; j = (j + 1) & mask) {
        size_t home = m->s[j].h & mask;
        bool between = i <= j ? (i < home && home <= j) : (i < home || home <= j);
        if (between) continue;
        m->s[i] = m->s[j];
        memset(&m->s[j], 0, sizeof m->s[j]);
        i = j;
    }
}

static void uk_free(ukmap *m)
{
    for (size_t i = 0; m && i < m->cap; i++) free(m->s[i].k);
    if (m) free(m->s);
    free(m);
}

/* a decoded row's key in index x, false when a column is NULL */
static bool uk_key(const schema *s, const val *vals, const aidx *x, uint8_t **out, size_t *len)
{
    uint8_t *b = NULL;
    size_t n = 0;
    for (int c = 0; c < x->ncols; c++) {
        const val *v = &vals[x->cols[c]];
        if (v->null) {
            free(b);
            return false;
        }
        bool text = s->c[x->cols[c]].type == T_TEXT;
        size_t add = text ? 4 + (size_t)v->len : 8;
        b = xrealloc(b, n + add, 1);
        uint64_t w = text ? v->len : (uint64_t)v->i;
        for (int k = 0; k < (text ? 4 : 8); k++) b[n + k] = (uint8_t)(w >> (8 * k));
        if (text && v->len) memcpy(b + n + 4, v->s, v->len);
        n += add;
    }
    *out = b;
    *len = n;
    return true;
}

/* version vid's row into unique index x: a live row holding its key already is a violation */
static int uk_add(const table *t, aidx *x, const val *vals, uint64_t vid, uint64_t seq)
{
    uint8_t *k;
    size_t n;
    if (!uk_key(&t->s, vals, x, &k, &n)) return 0;
    uint64_t h = uk_hash(k, n);
    if (uk_find(x->uk, k, n, h)) {
        free(k);
        return fail("commit %llu: two live rows of table %s share a key of unique index %s", (unsigned long long)seq,
                    t->s.name, x->name);
    }
    uk_put(x->uk, k, n, h, vid);
    return 0;
}

/* version vid ends: its key leaves the unique indexes */
static void uk_end(table *t, uint64_t vid)
{
    ver *v = &t->v[vid];
    if (!v->row) return;
    val vals[MAX_COLS];
    if (!decode_row(&t->s, v->row, v->row_len, vals))
        for (uint32_t x = 0; x < t->nidx; x++) {
            uint8_t *k;
            size_t n;
            if (!t->idx[x].uk || !uk_key(&t->s, vals, &t->idx[x], &k, &n)) continue;
            ukslot *sl = uk_find(t->idx[x].uk, k, n, uk_hash(k, n));
            if (sl && sl->vid == vid) uk_del(t->idx[x].uk, sl);
            free(k);
        }
    free(v->row);
    v->row = NULL;
}

static int apply_op(state *S, const op *o, uint64_t seq)
{
    if (o->code == 13) return 0; /* WRITER_KEY: keys, not data (decode_body follows it) */
    if (o->code == 1) {
        if (o->table != S->nt) return fail("commit %llu: table id out of sequence", (unsigned long long)seq);
        S->t = xrealloc(S->t, S->nt + 1, sizeof *S->t);
        memset(&S->t[S->nt], 0, sizeof S->t[S->nt]);
        S->t[S->nt].s = *o->sch;
        S->t[S->nt].s.raw = xcalloc(o->sch->rawlen, 1);
        memcpy(S->t[S->nt].s.raw, o->sch->raw, o->sch->rawlen);
        for (uint32_t i = 0; i < S->nt; i++)
            if (strcmp(S->t[i].s.name, o->sch->name) == 0) return fail("commit %llu: duplicate table", (unsigned long long)seq);
        S->nt++;
        return 0;
    }
    if (o->code == 14 || o->code == 15) {
        if (o->table >= S->nt) return fail("commit %llu: an index op on an unknown table", (unsigned long long)seq);
        table *t = &S->t[o->table];
        uint32_t p = 0;
        if (o->code == 15) {
            while (p < t->nidx && strcmp(t->idx[p].name, o->iname) != 0) p++;
            if (p == t->nidx) return fail("commit %llu: DROP INDEX of an index the table lacks", (unsigned long long)seq);
            uk_free(t->idx[p].uk);
            memmove(&t->idx[p], &t->idx[p + 1], (t->nidx - p - 1) * sizeof *t->idx);
            memset(&t->idx[--t->nidx], 0, sizeof *t->idx);
            return 0;
        }
        for (uint32_t i = 0; i < S->nt; i++)
            for (uint32_t j = 0; j < S->t[i].nidx; j++)
                if (strcmp(S->t[i].idx[j].name, o->iname) == 0)
                    return fail("commit %llu: CREATE INDEX with a name in use", (unsigned long long)seq);
        if (!aidx_ok(&o->ix, t->s.ncols) || t->nidx >= MAX_INDEXES)
            return fail("commit %llu: CREATE INDEX on a column the table lacks, or past the limit", (unsigned long long)seq);
        while (p < t->nidx && strcmp(t->idx[p].name, o->iname) < 0) p++;
        memmove(&t->idx[p + 1], &t->idx[p], (t->nidx - p) * sizeof *t->idx);
        t->idx[p] = o->ix;
        memcpy(t->idx[p].name, o->iname, sizeof t->idx[p].name);
        t->idx[p].uk = NULL;
        t->nidx++;
        if (!(o->ix.flags & 1)) return 0;
        t->idx[p].uk = xcalloc(1, sizeof *t->idx[p].uk); /* from the rows live now */
        for (uint64_t vid = 0; vid < t->n; vid++) {
            const ver *v = &t->v[vid];
            val vals[MAX_COLS];
            if (v->end != LIVE || !v->row) continue;
            if (decode_row(&t->s, v->row, v->row_len, vals)) return -1;
            if (uk_add(t, &t->idx[p], vals, vid, seq)) return -1;
        }
        return 0;
    }
    if (o->code == 10) return 0;
    if (o->code == 11) {
        if (o->table >= S->nt) return fail("commit %llu: COMPACT of unknown table", (unsigned long long)seq);
        return 0;
    }
    if (o->code == 12) {
        for (uint32_t k = 0; k < o->n_erase; k++) {
            const erase_ent *en = &o->erase[k];
            if (en->table >= S->nt || en->vid >= S->t[en->table].n)
                return fail("commit %llu: ERASE names an unknown version", (unsigned long long)seq);
            ver *v = &S->t[en->table].v[en->vid];
            if (memcmp(v->commit, en->commit, 32) != 0 || v->end == LIVE)
                return fail("commit %llu: invalid ERASE entry", (unsigned long long)seq);
            if (v->payload)
                return fail("erasure incomplete: the payload of erased version %llu of table %s is still in the log",
                            (unsigned long long)en->vid, S->t[en->table].s.name);
            v->stub = true;
        }
        S->last_erase = seq;
        return 0;
    }
    if (o->table >= S->nt) return fail("commit %llu: unknown table %u", (unsigned long long)seq, o->table);
    table *t = &S->t[o->table];
    if (o->code == 3 || o->code == 4) {
        if (o->vid >= t->n || t->v[o->vid].end != LIVE || memcmp(t->v[o->vid].commit, o->commit, 32) != 0)
            return fail("commit %llu: delete precondition fails", (unsigned long long)seq);
        t->v[o->vid].end = seq;
        uk_end(t, o->vid);
        t->live--;
        lt_sub(S->m.alg, &t->d, o->commit);
        lt_sub(S->m.alg, &S->glob, o->commit);
    }
    if (o->code == 2 || o->code == 4) {
        uint64_t vid = o->code == 2 ? o->vid : o->new_vid;
        const uint8_t *cm = o->code == 2 ? o->commit : o->new_commit;
        if (vid != t->n) return fail("commit %llu: version id out of sequence", (unsigned long long)seq);
        val vals[MAX_COLS];
        if (!o->redacted) {
            uint8_t chk[32];
            row_commit(o->table, o->salt, o->row, o->row_len, chk);
            if (memcmp(chk, cm, 32) != 0) return fail("commit %llu: payload does not match its commitment", (unsigned long long)seq);
            if (decode_row(&t->s, o->row, o->row_len, vals)) return -1;
            S->payload_rows++;
        }
        if (t->n == t->cap) {
            t->cap = t->cap ? t->cap * 2 : 64;
            t->v = xrealloc(t->v, t->cap, sizeof *t->v);
        }
        ver *v = &t->v[t->n++];
        memset(v, 0, sizeof *v);
        memcpy(v->commit, cm, 32);
        v->begin = seq;
        v->end = LIVE;
        v->payload = !o->redacted;
        v->redacted = o->redacted;
        if (!o->redacted) { /* the unique indexes, then the row kept while it is live */
            for (uint32_t x = 0; x < t->nidx; x++)
                if (t->idx[x].uk && uk_add(t, &t->idx[x], vals, vid, seq)) return -1;
            v->row = xcalloc(o->row_len, 1);
            memcpy(v->row, o->row, o->row_len);
            v->row_len = o->row_len;
        }
        if (!o->redacted && t->s.subject >= 0) {
            const val *sv = &vals[t->s.subject];
            v->has_subj = true;
            v->subj_i = sv->i;
            v->subj_len = sv->len;
            if (sv->len) {
                v->subj_s = xcalloc(sv->len, 1);
                memcpy(v->subj_s, sv->s, sv->len);
            }
        }
        t->live++;
        lt_add(S->m.alg, &t->d, cm);
        lt_add(S->m.alg, &S->glob, cm);
    }
    return 0;
}

/* ---- tagged log segments, read by design.md §3 ("Tagged, preallocated segments") -------- */

enum { TS_SEC = 512, TS_PAY = 504 };
#define TS_TOP (1ull << 63)
enum { TAIL_END = 0, TAIL_TORN = 1, TAIL_DAMAGED = 2 };

static bool tagged_seg(const uint8_t *b, size_t n) { return n >= 4 && memcmp(b, "ILT1", 4) == 0; }

typedef struct tsread {
    const uint8_t *b;
    uint64_t nsec;
    uint64_t sec; /* the sector being read */
    size_t at;    /* payload bytes of it used up (TS_PAY: all) */
    uint64_t g;   /* its group's tag */
} tsread;

static bool ts_zero(const tsread *r, uint64_t s) { return s < r->nsec && all_zero(r->b + s * TS_SEC, TS_SEC); }
static uint64_t ts_tag(const tsread *r, uint64_t s) { return le64(r->b + s * TS_SEC); }

/* n payload bytes of group r->g to dst: 0, or TAIL_TORN (a zero sector or the end of the file on
 * the way), or -1 (a sector there carries another tag). */
static int ts_take(tsread *r, uint8_t *dst, size_t n)
{
    for (; n;) {
        if (r->at == TS_PAY) {
            if (r->sec + 1 >= r->nsec || ts_zero(r, r->sec + 1)) return TAIL_TORN;
            if (ts_tag(r, r->sec + 1) != r->g) return -1;
            r->sec++;
            r->at = 0;
        }
        size_t k = TS_PAY - r->at < n ? TS_PAY - r->at : n;
        memcpy(dst, r->b + r->sec * TS_SEC + 8 + r->at, k);
        r->at += k;
        dst += k;
        n -= k;
    }
    return 0;
}

/* After a torn group t: every later sector zero, or t's own (tag t, landed out of order). A later
 * group would mean t had been flushed, so t is damage, not a tear. */
static int ts_rest(const tsread *r, uint64_t from, uint64_t t, const char *name)
{
    for (uint64_t s = from; s < r->nsec; s++)
        if (!ts_zero(r, s) && ts_tag(r, s) != t)
            return fail("log corrupt: in segment %s a write follows a torn one, which was therefore flushed", name);
    return TAIL_TORN;
}

/* A tagged segment's frames, back to back, into *out (*len bytes): the form the frame rules then
 * read. The verdict for what follows them: TAIL_END, TAIL_TORN, TAIL_DAMAGED, or -1 (fail called). */
static int untag(const uint8_t *b, size_t n, uint64_t first, const char *name, uint8_t **out, size_t *len)
{
    *out = NULL;
    *len = 0;
    if (n < TS_SEC || n % TS_SEC) return fail("log corrupt: segment %s: a tagged segment's size is not a multiple of 512", name);
    if (le32(b + 4) != 1 || le64(b + 8) != first || a_crc32c(b, 16) != le32(b + 16) || !all_zero(b + 20, TS_SEC - 20))
        return fail("log corrupt: segment %s: a malformed tagged header", name);
    uint8_t *o = xcalloc(n, 1);
    size_t w = 0;
    tsread r = {.b = b, .nsec = n / TS_SEC};
    uint64_t want = first, ended = 0; /* ended: the tag of the group that ended last */
    int v = TAIL_END;
    bool done = false;
    for (uint64_t s = 1; !done;) {
        /* between groups, at sector s: the first non-zero sector from here decides */
        uint64_t nz = s;
        while (nz < r.nsec && ts_zero(&r, nz)) nz++;
        if (nz == r.nsec) break; /* only the fill: the end */
        uint64_t t = ts_tag(&r, nz);
        if (nz == s && want < TS_TOP && t == (want | TS_TOP)) {
            r.sec = s;
            r.at = 0;
            r.g = want;
        } else {
            done = true;
            if (ended && t == ended) v = ts_rest(&r, nz + 1, ended, name); /* a later part of it landed, an earlier not */
            else if (nz > s && t == want) v = ts_rest(&r, nz + 1, want, name); /* its first sector never landed */
            else
                v = fail("log corrupt: segment %s: sector %llu carries a tag no write there could have", name,
                         (unsigned long long)nz);
            break;
        }
        while (!done) { /* group r.g, frame by frame */
            uint8_t h[16];
            int k = ts_take(&r, h, 16);
            uint32_t blen = k ? 0 : le32(h + 4);
            if (!k && (le32(h) != 0x32474C49u || a_crc32c(h, 12) != le32(h + 12) || blen > MAX_FRAME)) k = -1;
            if (!k && blen > n) k = TAIL_TORN; /* longer than the file: it cannot be all there */
            if (!k) {
                memcpy(o + w, h, 16);
                k = ts_take(&r, o + w + 16, blen);
            }
            if (k) {
                done = true;
                v = k == TAIL_TORN ? ts_rest(&r, r.sec + 1, r.g, name)
                                   : fail("log corrupt: segment %s: a malformed frame or a foreign sector after commit %llu",
                                          name, (unsigned long long)(want - 1));
                break;
            }
            if (a_crc32c(o + w + 16, blen) != le32(h + 8)) { /* every sector of it there */
                bool zeros = r.at == TS_PAY || all_zero(b + r.sec * TS_SEC + 8 + r.at, TS_PAY - r.at);
                for (uint64_t z = r.sec + 1; zeros && z < r.nsec; z++) zeros = ts_zero(&r, z);
                done = true;
                v = zeros ? TAIL_DAMAGED : fail("log corrupt: checksum mismatch in segment %s, data after it", name);
                break;
            }
            if (blen < 109 || le64(o + w + 16 + 5) != want) {
                done = true;
                v = fail("log corrupt: segment %s: the frame after commit %llu is not the next commit", name,
                         (unsigned long long)(want - 1));
                break;
            }
            w += 16 + blen;
            want++;
            /* the group goes on after it, or ended: only zeros to the end of its sector, or, at a sector's
             * end, no sector of the group next */
            if (r.at < TS_PAY && !all_zero(b + r.sec * TS_SEC + 8 + r.at, TS_PAY - r.at)) continue;
            if (r.at == TS_PAY && r.sec + 1 < r.nsec && !ts_zero(&r, r.sec + 1) && ts_tag(&r, r.sec + 1) == r.g) continue;
            ended = r.g;
            s = r.sec + 1;
            break;
        }
    }
    if (v < 0) {
        free(o);
        return -1;
    }
    *out = o;
    *len = w;
    return v;
}

static int cmp_seg(const void *a, const void *b)
{
    uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;
    return x < y ? -1 : x > y;
}

/* log/: every entry must be "<20 digits>.ilg", a regular file (no symlinks). */
static int list_segments(int dirfd, int *logfd, uint64_t **out, size_t *n)
{
    *out = NULL;
    *n = 0;
    *logfd = openat(dirfd, "log", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (*logfd < 0) return fail("log/: %s", errno == ELOOP ? "refusing to follow a symbolic link" : strerror(errno));
    int dfd = dup(*logfd);
    DIR *d = dfd >= 0 ? fdopendir(dfd) : NULL;
    if (!d) {
        if (dfd >= 0) close(dfd);
        return fail("log/: cannot list the directory");
    }
    size_t cap = 0;
    uint64_t *v = NULL;
    struct dirent *de;
    int rc = 0;
    for (;;) {
        errno = 0;
        if (!(de = readdir(d))) {
            if (errno) rc = fail("log/: cannot list the directory: %s", strerror(errno));
            break;
        }
        if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0) continue;
        const char *nm = de->d_name;
        uint64_t first = 0;
        /* a redaction rewrite's temporary <segment>.ilg.tmp: the segment stays authoritative until
         * the rename, and a writable engine open removes a leftover one */
        bool tmp = strlen(nm) == 28 && strcmp(nm + 24, ".tmp") == 0;
        bool ok = (strlen(nm) == 24 || tmp) && strncmp(nm + 20, ".ilg", 4) == 0;
        for (int i = 0; ok && i < 20; i++) {
            ok = nm[i] >= '0' && nm[i] <= '9' && first <= (UINT64_MAX - 9) / 10;
            first = first * 10 + (uint64_t)(nm[i] - '0');
        }
        struct stat st;
        if (tmp && ok && first != 0) {
            struct stat bs;
            char base[25];
            memcpy(base, nm, 24);
            base[24] = '\0';
            if (fstatat(*logfd, nm, &st, AT_SYMLINK_NOFOLLOW) != 0 || !S_ISREG(st.st_mode) ||
                fstatat(*logfd, base, &bs, AT_SYMLINK_NOFOLLOW) != 0 || !S_ISREG(bs.st_mode))
                rc = fail("log/: redaction temporary %s has no regular segment or is not regular", nm);
            if (rc) break;
            continue;
        }
        if (!ok || first == 0) rc = fail("unexpected file in log/: %s", nm);
        else if (fstatat(*logfd, nm, &st, AT_SYMLINK_NOFOLLOW) != 0 || !S_ISREG(st.st_mode))
            rc = fail("refusing to follow a symbolic link or special file in log/: %s", nm);
        if (rc) break;
        if (*n == cap) {
            cap = cap ? cap * 2 : 16;
            v = xrealloc(v, cap, sizeof *v);
        }
        v[(*n)++] = first;
    }
    closedir(d);
    if (rc) {
        free(v);
        return rc;
    }
    if (*n) qsort(v, *n, sizeof *v, cmp_seg);
    *out = v;
    return 0;
}

static bool publishes(const commit *c)
{
    for (uint32_t i = 0; i < c->nops; i++)
        if (c->ops[i].code == 10 || c->ops[i].code == 11 || c->ops[i].code == 12) return true;
    return false;
}

/* The log is the concatenation of its segments. Layout rules: a segment
 * starts with the commit its name gives; a commit that publishes a manifest
 * is the last of its segment and every segment but the last ends with one;
 * only the last segment may be empty or end in a torn frame. */
/* DURABLE: "IMDBDUR1", u64 seq, the hash of commit seq, u32 flags (1: synced; 3: synced and strict,
 * fsynced before the commits it names were acknowledged), u32 0,
 * CRC32C of the first 56 bytes. The writer rewrites it in place, so a read that
 * fails the check is tried again before it counts as damage. */
static int load_durable(int dirfd, state *S)
{
    if (faccessat(dirfd, "DURABLE", F_OK, AT_SYMLINK_NOFOLLOW) != 0) return 0;
    for (int attempt = 0;; attempt++) {
        uint8_t *b;
        size_t n;
        if (read_file(dirfd, "DURABLE", &b, &n, 64)) return -1;
        uint32_t fl = n == 60 ? le32(b + 48) : 0;
        bool ok = n == 60 && memcmp(b, "IMDBDUR1", 8) == 0 && a_crc32c(b, 56) == le32(b + 56) &&
                  (fl == 0 || fl == 1 || fl == 3) && le32(b + 52) == 0;
        if (ok) {
            S->dur_present = true;
            S->dur_seq = le64(b + 8);
            memcpy(S->dur_head, b + 16, 32);
            S->dur_synced = (fl & 1u) != 0;
            S->dur_strict = fl == 3;
        }
        free(b);
        if (ok || n == 0) return 0; /* empty: created by a writer that crashed before writing it */
        if (attempt == 4) return fail("DURABLE: malformed");
        struct timespec ts = {0, 1000 * 1000};
        nanosleep(&ts, NULL);
    }
}

static int replay(state *S, int dirfd, uint64_t *commits)
{
    {
        uint8_t g[24];
        memcpy(g, "IMDBGEN1", 8);
        memcpy(g + 8, S->m.db_id, 16);
        a_sha256(g, sizeof g, S->head);
    }
    if (load_durable(dirfd, S)) return -1;
    if (S->dur_present && S->dur_seq == 0 && memcmp(S->dur_head, S->head, 32) != 0)
        return fail("DURABLE names commit 0 with another hash: it belongs to another database");
    int logfd;
    uint64_t *segs;
    size_t nsegs;
    if (list_segments(dirfd, &logfd, &segs, &nsegs)) {
        if (logfd >= 0) close(logfd);
        return -1;
    }
    uint64_t last_time = 0;
    int rc = 0;
    bool seen_tagged = false; /* the format only moves forward (design.md §3) */
    for (size_t si = 0; !rc && si < nsegs; si++) {
        bool lastseg = si + 1 == nsegs, ended = false;
        char name[32];
        snprintf(name, sizeof name, "%020llu.ilg", (unsigned long long)segs[si]);
        uint8_t *log;
        size_t n, off = 0, frames = 0;
        if ((rc = read_file(logfd, name, &log, &n, MAX_OBJECT))) break;
        int tail = TAIL_END; /* a tagged segment: its frames, and the verdict for what follows them */
        if (tagged_seg(log, n)) {
            uint8_t *fr;
            size_t fl;
            tail = untag(log, n, segs[si], name, &fr, &fl);
            free(log);
            if (tail < 0) {
                rc = -1;
                break;
            }
            log = fr;
            n = fl;
            seen_tagged = true;
        } else if (seen_tagged && !(lastseg && all_zero(log, n))) { /* a new segment whose header never landed */
            free(log);
            rc = fail("log corrupt: segment %s is untagged, after a tagged one", name);
            break;
        }
        bool tail_left = tail != TAIL_END;
        while (!rc && (off < n || tail_left)) {
            size_t left = n - off;
            const uint8_t *f = log + off;
            bool torn = false, damaged = false;
            if (off >= n) { /* past a tagged segment's frames */
                torn = tail == TAIL_TORN;
                damaged = tail == TAIL_DAMAGED;
                tail_left = false;
            } else if (left < 16 || le32(f) != 0x32474C49u || a_crc32c(f, 12) != le32(f + 12)) {
                if (left >= 16 && !all_zero(f, left)) rc = fail("log corrupt: bad frame header in segment %s", name);
                else torn = true;
            } else if (le32(f + 4) > MAX_FRAME) {
                rc = fail("log corrupt: frame too large in segment %s", name);
            } else if (le32(f + 4) > left - 16) {
                torn = true;
            } else if (a_crc32c(f + 16, le32(f + 4)) != le32(f + 8)) {
                /* a complete frame at the very end: an append that never finished, or damage */
                if (all_zero(f + 16 + le32(f + 4), left - 16 - le32(f + 4))) damaged = true;
                else rc = fail("log corrupt: checksum mismatch in segment %s", name);
            }
            if (torn || damaged) {
                if (!lastseg) rc = fail("log corrupt: torn frame inside segment %s, which is not the last", name);
                else if (S->dur_present && S->dur_synced && S->dur_seq > S->seq)
                    rc = fail("log damaged: commit %llu was acknowledged as durable, but segment %s ends with a damaged or "
                              "incomplete frame after commit %llu", (unsigned long long)S->dur_seq, name, (unsigned long long)S->seq);
                else if (damaged && !(S->dur_present && S->dur_strict))
                    /* only a watermark fsynced before each acknowledgement (--durable-ack) shows that a
                     * complete frame past it never was one; any other may lag the log after a crash */
                    rc = fail("log damaged: the final frame of segment %s fails its checksum, and %s cannot show it was "
                              "never acknowledged (imagedb recover inspects it)", name,
                              S->dur_present ? "the DURABLE watermark (not strict)" : "no DURABLE watermark");
                else
                    snprintf(S->note, sizeof S->note, "torn tail in %s after commit %llu (the engine truncates it at the next "
                             "open)", name, (unsigned long long)S->seq);
                break;
            }
            if (rc) break;
            uint32_t blen = le32(f + 4);
            if (ended) {
                rc = fail("segment %s continues past a commit that publishes a manifest", name);
                break;
            }
            commit c;
            if ((rc = decode_body(f + 16, blen, &S->m, &S->K, &c))) {
                commit_free(&c);
                break;
            }
            S->sigs++;
            if (frames == 0 && c.seq != segs[si]) rc = fail("segment %s begins with commit %llu", name, (unsigned long long)c.seq);
            else if (c.seq != S->seq + 1) rc = fail("commit %llu out of sequence", (unsigned long long)c.seq);
            else if (memcmp(c.prev, S->head, 32) != 0) rc = fail("hash chain broken at commit %llu", (unsigned long long)c.seq);
            else if (c.time <= last_time) rc = fail("commit %llu: time not increasing", (unsigned long long)c.seq);
            for (uint32_t i = 0; !rc && i < c.nops; i++) rc = apply_op(S, &c.ops[i], c.seq);
            uint8_t d[32];
            lt_digest(S->m.alg, &S->glob, d);
            if (!rc && memcmp(d, c.digest, 32) != 0)
                rc = fail("commit %llu: recorded state digest does not match the log", (unsigned long long)c.seq);
            if (!rc && c.seq == S->lake_seq) {
                /* GC keeps the generation this manifest replaced, none after an ERASE */
                bool erase = false;
                for (uint32_t i = 0; i < c.nops; i++) erase |= c.ops[i].code == 12;
                if (erase) memset(S->lake_prev_manifest, 0, 32);
                else memcpy(S->lake_prev_manifest, S->last_manifest, 32);
                for (uint32_t ti = 0; ti < S->nt; ti++) {
                    S->t[ti].d_at_lake = S->t[ti].d;
                    memcpy(S->t[ti].idx_at_lake, S->t[ti].idx, sizeof S->t[ti].idx);
                    S->t[ti].nidx_at_lake = S->t[ti].nidx;
                }
                memcpy(S->lake_digest, c.digest, 32);
                memcpy(S->lake_prev, c.prev, 32);
                for (uint32_t i = 0; i < c.nops; i++)
                    if (c.ops[i].manifest && memcmp(c.ops[i].manifest, S->lake_manifest, 32) == 0) S->lake_recorded = true;
            }
            for (uint32_t i = 0; !rc && i < c.nops; i++) /* history horizon as of the lake snapshot */
                if (c.ops[i].code == 11 && c.seq <= S->lake_seq && c.ops[i].purge_before > S->t[c.ops[i].table].horizon_at_lake)
                    S->t[c.ops[i].table].horizon_at_lake = c.ops[i].purge_before;
            if (!rc) {
                if (S->dur_present && c.seq == S->dur_seq && memcmp(c.hash, S->dur_head, 32) != 0)
                    rc = fail("DURABLE names commit %llu with another hash: it belongs to a different history",
                              (unsigned long long)c.seq);
                for (int a = 0; a < S->anc_n; a++) /* what the anchor's records are checked against, after replay */
                    if (c.seq == le64(S->anc_rec[a] + 24)) {
                        S->anc_seen[a] = true;
                        memcpy(S->anc_hash_at[a], c.hash, 32);
                        S->anc_epoch_at[a] = c.epoch;
                    }
                memcpy(S->head, c.hash, 32);
                last_time = c.time;
                S->seq = c.seq;
                ended = publishes(&c);
                for (uint32_t i = 0; i < c.nops; i++)
                    if (c.ops[i].manifest) {
                        memcpy(S->last_manifest, c.ops[i].manifest, 32);
                        uint8_t (*p)[32] = S->npin ? bsearch(c.ops[i].manifest, S->pin, S->npin, 32, cmp32) : NULL;
                        if (p) S->pin_at[p - S->pin] = c.seq;
                    }
            }
            commit_free(&c);
            off += 16 + (size_t)blen;
            frames++;
        }
        free(log);
        if (!rc && !lastseg && (frames == 0 || !ended))
            rc = fail("segment %s %s", name, frames ? "ends without a commit that publishes a manifest" : "is empty but not the last");
        if (!rc && lastseg && frames == 0 && segs[si] != S->seq + 1)
            rc = fail("empty last segment %s does not follow commit %llu", name, (unsigned long long)S->seq);
    }
    free(segs);
    close(logfd);
    if (rc) return rc;
    if (S->dur_present && S->dur_synced && S->dur_seq > S->seq)
        return fail("log damaged: commit %llu was acknowledged as durable, but the log ends at commit %llu",
                    (unsigned long long)S->dur_seq, (unsigned long long)S->seq);
    if (S->dur_present && !S->dur_synced && S->dur_seq > S->seq) {
        size_t used = strlen(S->note);
        snprintf(S->note + used, sizeof S->note - used, "%scommits %llu..%llu were written under --nosync and are not in "
                 "the log", used ? "; " : "", (unsigned long long)(S->seq + 1), (unsigned long long)S->dur_seq);
    }
    for (uint32_t ti = 0; ti < S->nt; ti++)
        for (uint64_t vid = 0; vid < S->t[ti].n; vid++)
            if (S->t[ti].v[vid].redacted && !S->t[ti].v[vid].stub)
                return fail("version %llu of table %s: redacted payload not authorised by any ERASE",
                            (unsigned long long)vid, S->t[ti].s.name);
    *commits = S->seq;
    return 0;
}

/* ---- lake objects ---------------------------------------------------------------------- */

enum { S_VID = 1, S_BEGIN = 2, S_FLAGS = 3, S_SALT = 4, S_COMMIT = 5, S_I64 = 16, S_U8 = 17, S_TOFF = 18, S_TDATA = 19,
       S_VALID = 20, S_ZONE = 32 };
#define MAX_SECTIONS (5 + 3 * MAX_COLS + 1)

typedef struct segrow {
    uint64_t vid, begin, end;
    bool stub, purged; /* flags 1 and 2: erased; purged to a tombstone */
    uint8_t flags;
    const uint8_t *salt, *commit;
} segrow;

typedef struct seg {
    uint8_t *bytes;
    size_t len;
    uint32_t n;
    segrow *row;
    const uint8_t *colp[MAX_COLS];   /* I64 / U8 / TEXT_OFF section */
    const uint8_t *tdata[MAX_COLS];  /* TEXT_DATA section */
    const uint8_t *valid[MAX_COLS];  /* VALID section of a NULLABLE column, else NULL */
} seg;

static void seg_free(seg *g)
{
    free(g->bytes);
    free(g->row);
    memset(g, 0, sizeof *g);
}

static bool is_int(uint8_t t) { return t == T_INT64 || t == T_DECIMAL || t == T_TIMESTAMP || t == T_FLOAT64; }

static bool has_value(const seg *g, int c, uint32_t i) { return !g->valid[c] || (g->valid[c][i / 8] >> (i % 8) & 1); }

/* Whatever is stored for row i of column c, read without its VALID bit. */
static void seg_raw(const schema *s, const seg *g, uint32_t i, int c, val *v)
{
    memset(v, 0, sizeof *v);
    uint8_t t = s->c[c].type;
    if (is_int(t)) v->i = (int64_t)le64(g->colp[c] + 8u * i);
    else if (t == T_BOOL) v->i = g->colp[c][i];
    else {
        uint32_t a = le32(g->colp[c] + 4u * i), z = le32(g->colp[c] + 4u * (i + 1));
        v->s = g->tdata[c] + a;
        v->len = z - a;
    }
}

static void seg_value(const schema *s, const seg *g, uint32_t i, int c, val *v)
{
    seg_raw(s, g, i, c, v);
    if (!has_value(g, c, i)) { /* parse_segment has checked that nothing is stored under it */
        memset(v, 0, sizeof *v);
        v->null = true;
    }
}

/* A live row's key in a unique index: each column in 8 bytes, a TEXT as a u32 length and its bytes;
 * false when a column is NULL (the row is exempt, as in SQL). */
typedef struct ukey {
    uint8_t *b;
    size_t n;
} ukey;

static bool ukey_of(const schema *s, const seg *g, uint32_t i, const aidx *x, ukey *out)
{
    uint8_t *b = NULL;
    size_t n = 0;
    for (int c = 0; c < x->ncols; c++) {
        int cn = x->cols[c];
        if (!has_value(g, cn, i)) {
            free(b);
            return false;
        }
        val v;
        seg_value(s, g, i, cn, &v);
        bool text = s->c[cn].type == T_TEXT;
        size_t add = text ? 4 + (size_t)v.len : 8;
        b = xrealloc(b, n + add, 1);
        uint64_t w = text ? v.len : (uint64_t)v.i;
        for (int k = 0; k < (text ? 4 : 8); k++) b[n + k] = (uint8_t)(w >> (8 * k));
        if (text && v.len) memcpy(b + n + 4, v.s, v.len);
        n += add;
    }
    out->b = b;
    out->n = n;
    return true;
}

static int cmp_ukey(const void *a, const void *b)
{
    const ukey *x = a, *y = b;
    if (x->n != y->n) return x->n < y->n ? -1 : 1;
    return x->n ? memcmp(x->b, y->b, x->n) : 0;
}

/* Strict, canonical parse; every non-stub row's commitment is recomputed. */
static int parse_segment(const schema *s, uint8_t *b, size_t len, seg *g)
{
    memset(g, 0, sizeof *g);
    if (len < 64 || memcmp(b, "IMDBSEG1", 8) != 0) return fail("segment: bad magic");
    uint32_t n = le32(b + 48), ncols = le32(b + 52), nsec = le32(b + 56);
    if (le32(b + 8) != 2 || le32(b + 12) != s->id || le32(b + 60) != 0 || ncols != (uint32_t)s->ncols)
        return fail("segment: bad header");
    uint8_t sh[32];
    a_sha256(s->raw, s->rawlen, sh);
    if (memcmp(sh, b + 16, 32) != 0) return fail("segment: schema hash mismatch");
    if (n > (1u << 22)) return fail("segment: too many rows");
    uint32_t want_kind[MAX_SECTIONS], want_col[MAX_SECTIONS];
    uint64_t want_len[MAX_SECTIONS];
    uint32_t k = 0;
    uint32_t sys[5] = {S_VID, S_BEGIN, S_FLAGS, S_SALT, S_COMMIT};
    uint64_t syslen[5] = {8ull * n, 8ull * n, n, 16ull * n, 32ull * n};
    for (int i = 0; i < 5; i++) want_kind[k] = sys[i], want_col[k] = 0, want_len[k++] = syslen[i];
    for (int c = 0; c < s->ncols; c++) {
        uint8_t t = s->c[c].type;
        if (is_int(t)) want_kind[k] = S_I64, want_col[k] = (uint32_t)c, want_len[k++] = 8ull * n;
        else if (t == T_BOOL) want_kind[k] = S_U8, want_col[k] = (uint32_t)c, want_len[k++] = n;
        else {
            want_kind[k] = S_TOFF, want_col[k] = (uint32_t)c, want_len[k++] = 4ull * (n + 1);
            want_kind[k] = S_TDATA, want_col[k] = (uint32_t)c, want_len[k++] = UINT64_MAX;
        }
        if (s->c[c].flags & F_NULLABLE) want_kind[k] = S_VALID, want_col[k] = (uint32_t)c, want_len[k++] = (n + 7ull) / 8;
    }
    want_kind[k] = S_ZONE, want_col[k] = 0, want_len[k++] = 24ull * ncols;
    if (nsec != k) return fail("segment: wrong section count");
    size_t pos = 64 + 24u * (size_t)nsec;
    if (pos > len) return fail("segment: truncated directory");
    const uint8_t *sec[MAX_SECTIONS];
    uint64_t slen[MAX_SECTIONS];
    for (uint32_t i = 0; i < nsec; i++) {
        const uint8_t *d = b + 64 + 24u * i;
        uint64_t off = le64(d + 8), l = le64(d + 16);
        size_t expect = (pos + 7) & ~(size_t)7;
        if (le32(d) != want_kind[i] || le32(d + 4) != want_col[i] || (want_len[i] != UINT64_MAX && l != want_len[i]) ||
            off != expect || expect > len || l > len - off)
            return fail("segment: section %u not canonical", i);
        if (!all_zero(b + pos, expect - pos)) return fail("segment: non-zero padding");
        sec[i] = b + off;
        slen[i] = l;
        pos = (size_t)(off + l);
    }
    if (pos != len) return fail("segment: trailing bytes");
    g->bytes = b;
    g->len = len;
    g->n = n;
    g->row = xcalloc(n, sizeof *g->row);
    int rc = 0;
    for (uint32_t i = 0; i < n && !rc; i++) {
        segrow *r = &g->row[i];
        r->vid = le64(sec[0] + 8u * i);
        r->begin = le64(sec[1] + 8u * i);
        uint8_t fl = sec[2][i];
        r->salt = sec[3] + 16u * i;
        r->commit = sec[4] + 32u * i;
        r->end = LIVE;
        if (fl > 3 || (i && r->vid <= g->row[i - 1].vid) || r->begin == 0 || r->begin >= LIVE)
            rc = fail("segment: bad system columns");
        r->flags = fl;
        r->stub = (fl & 1) != 0;
        r->purged = (fl & 2) != 0;
        if (!rc && fl && !all_zero(r->salt, 16)) rc = fail("segment: erased or purged row keeps a salt");
    }
    k = 5;
    for (int c = 0; c < s->ncols && !rc; c++) {
        g->colp[c] = sec[k++];
        if (s->c[c].type == T_TEXT) {
            g->tdata[c] = sec[k];
            uint64_t dl = slen[k++];
            if (le32(g->colp[c]) != 0 || le32(g->colp[c] + 4u * n) != dl) rc = fail("segment: bad TEXT offsets");
            for (uint32_t i = 0; i < n && !rc; i++) {
                uint32_t a = le32(g->colp[c] + 4u * i), z = le32(g->colp[c] + 4u * (i + 1));
                if (z < a || z > dl || z - a > MAX_TEXT) rc = fail("segment: bad TEXT offsets");
            }
        }
        if (s->c[c].flags & F_NULLABLE) {
            g->valid[c] = sec[k++];
            if (n % 8 && g->valid[c][n / 8] >> (n % 8)) rc = fail("segment: VALID padding is not zero");
        }
    }
    const uint8_t *zone = sec[k];
    uint8_t *rowbuf = NULL;
    size_t rowcap = 0;
    for (uint32_t i = 0; i < n && !rc; i++) {
        val v[MAX_COLS];
        for (int c = 0; c < s->ncols; c++) seg_value(s, g, i, c, &v[c]);
        uint8_t fl = g->row[i].flags;
        for (int c = 0; c < s->ncols && !rc; c++) { /* a NULL is zero data under a clear VALID bit */
            val raw;
            seg_raw(s, g, i, c, &raw);
            if (!has_value(g, c, i) && (raw.i || raw.len)) rc = fail("segment: data under a clear VALID bit");
            if (fl && g->valid[c] && has_value(g, c, i)) rc = fail("segment: erased or purged row has a VALID bit");
        }
        if (fl) {
            /* a tombstone (2) keeps the SUBJECT value; anything else stays zero */
            for (int c = 0; c < s->ncols && !rc; c++) {
                if (fl == 2 && c == s->subject) rc = check_value(&s->c[c], &v[c]);
                else if (v[c].i || v[c].len) rc = fail("segment: erased or purged row keeps data");
            }
            continue;
        }
        for (int c = 0; c < s->ncols && !rc; c++)
            if (!v[c].null) rc = check_value(&s->c[c], &v[c]);
        if (rc) break;
        size_t rl = encode_row(s, v, &rowbuf, &rowcap);
        uint8_t cm[32];
        row_commit(s->id, g->row[i].salt, rowbuf, rl, cm);
        if (memcmp(cm, g->row[i].commit, 32) != 0) rc = fail("segment: row %u does not match its commitment", i);
    }
    free(rowbuf);
    for (int c = 0; c < s->ncols && !rc; c++) {
        bool has = false, has_null = false;
        int64_t mn = 0, mx = 0;
        for (uint32_t i = 0; i < n; i++) has_null |= !g->row[i].flags && !has_value(g, c, i);
        if (s->c[c].type != T_TEXT)
            for (uint32_t i = 0; i < n; i++) {
                if (g->row[i].flags || !has_value(g, c, i)) continue;
                val v;
                seg_value(s, g, i, c, &v);
                if (!has || v.i < mn) mn = v.i;
                if (!has || v.i > mx) mx = v.i;
                has = true;
            }
        const uint8_t *z = zone + 24u * (size_t)c;
        if (z[0] != has || z[1] != has_null || !all_zero(z + 2, 6) || (int64_t)le64(z + 8) != mn ||
            (int64_t)le64(z + 16) != mx)
            rc = fail("segment: zone map does not match the data (column %s)", s->c[c].name);
    }
    if (rc) {
        free(g->row);
        g->row = NULL;
        g->bytes = NULL;
    }
    return rc;
}

static int parse_dv(const uint8_t *b, size_t len, const uint8_t seg_hash[32], seg *g, uint64_t snap)
{
    rd r = {b, len, 0, false};
    const uint8_t *mg = rd_bytes(&r, 8), *sh = rd_bytes(&r, 32);
    uint32_t cnt = rd_u32(&r), pad = rd_u32(&r);
    if (!mg || memcmp(mg, "IMDBDV01", 8) != 0 || !sh || memcmp(sh, seg_hash, 32) != 0)
        return fail("dv: bad header or names another segment");
    if (r.bad || pad || cnt == 0 || cnt > g->n || cnt > rd_left(&r) / 16) return fail("dv: bad count");
    int64_t last = -1;
    for (uint32_t i = 0; i < cnt; i++) {
        uint32_t row = rd_u32(&r), p2 = rd_u32(&r);
        uint64_t end = rd_u64(&r);
        if (r.bad || p2 || row >= g->n || (int64_t)row <= last || end == 0 || end >= LIVE) return fail("dv: bad entry");
        if (end > snap) return fail("dv: records a delete after the snapshot");
        g->row[row].end = end;
        last = row;
    }
    if (rd_left(&r)) return fail("dv: trailing bytes");
    return 0;
}

typedef struct mtable {
    schema s;
    uint64_t horizon, live, versions;
    uint8_t lthash[2048];
    uint8_t (*seg)[32], (*dv)[32];
    uint32_t *nrows, nseg;
    aidx idx[MAX_INDEXES]; /* version 3 */
    uint32_t nidx;
} mtable;

typedef struct manifest {
    uint8_t db_id[16], prev[32], state[32], hash[32], prev_manifest[32];
    uint64_t seq;
    mtable *t;
    uint32_t nt;
} manifest;

static void manifest_free(manifest *m)
{
    for (uint32_t i = 0; i < m->nt; i++) {
        free(m->t[i].s.raw);
        free(m->t[i].seg);
        free(m->t[i].dv);
        free(m->t[i].nrows);
    }
    free(m->t);
    memset(m, 0, sizeof *m);
}

static int obj_read(int ofd, const uint8_t h[32], const char *ext, uint8_t **out, size_t *len)
{
    char name[80];
    hex(h, 32, name);
    strcat(name, ext);
    if (faccessat(ofd, name, F_OK, AT_SYMLINK_NOFOLLOW) != 0 && errno == ENOENT) {
        g_vanished = true;
        return fail("lake object %s is gone (removed by a newer publication's GC?)", name);
    }
    if (read_file(ofd, name, out, len, MAX_OBJECT)) return -1;
    uint8_t got[32];
    a_sha256(*out, *len, got);
    if (memcmp(got, h, 32) != 0) {
        free(*out);
        *out = NULL;
        return fail("object %s does not hash to its name", name);
    }
    return 0;
}

static bool obj_name_ok(const char *n)
{
    size_t l = strlen(n);
    if (l < 67 || l > 68) return false;
    for (int i = 0; i < 64; i++)
        if (!((n[i] >= '0' && n[i] <= '9') || (n[i] >= 'a' && n[i] <= 'f'))) return false;
    return strcmp(n + 64, ".seg") == 0 || strcmp(n + 64, ".dv") == 0 || strcmp(n + 64, ".man") == 0;
}

/* LAKE_HEAD, then the manifest it names. */
static int load_head(int dirfd, uint64_t *seq, uint8_t mh[32], bool *present)
{
    *present = false;
    if (faccessat(dirfd, "LAKE_HEAD", F_OK, AT_SYMLINK_NOFOLLOW) != 0) return 0;
    uint8_t *b;
    size_t n;
    if (read_file(dirfd, "LAKE_HEAD", &b, &n, 256)) return -1;
    static const char a[] = "imagedb-lake 1\nseq ";
    const char *s = (const char *)b;
    size_t i = sizeof a - 1;
    uint64_t v = 0;
    int rc = 0;
    if (n < i || memcmp(s, a, i) != 0) rc = fail("LAKE_HEAD malformed");
    size_t d0 = i;
    while (!rc && i < n && s[i] >= '0' && s[i] <= '9' && i - d0 < 19) v = v * 10 + (uint64_t)(s[i++] - '0');
    if (!rc && (i == d0 || (s[d0] == '0' && i - d0 > 1) || n - i != 1 + 9 + 64 + 1 || memcmp(s + i, "\nmanifest ", 10) != 0 ||
                !unhex(s + i + 10, 64, mh, 32) || s[n - 1] != '\n'))
        rc = fail("LAKE_HEAD malformed");
    free(b);
    if (!rc) {
        *seq = v;
        *present = true;
    }
    return rc;
}

static int cmp_str(const void *a, const void *b) { return strcmp(*(const char *const *)a, *(const char *const *)b); }

static int parse_manifest(const uint8_t *b, size_t len, manifest *m)
{
    memset(m, 0, sizeof *m);
    rd r = {b, len, 0, false};
    const uint8_t *mg = rd_bytes(&r, 8);
    uint32_t mver = mg && memcmp(mg, "IMDBMAN1", 8) == 0 ? rd_u32(&r) : 0;
    if (mver != 2 && mver != 3) return fail("manifest: bad header");
    uint32_t nt = rd_u32(&r);
    const uint8_t *id = rd_bytes(&r, 16);
    m->seq = rd_u64(&r);
    const uint8_t *prev = rd_bytes(&r, 32), *st = rd_bytes(&r, 32), *pm = rd_bytes(&r, 32);
    if (r.bad || nt > 1024 || nt > rd_left(&r) / 64) return fail("manifest: bad table count");
    memcpy(m->db_id, id, 16);
    memcpy(m->prev, prev, 32);
    memcpy(m->state, st, 32);
    memcpy(m->prev_manifest, pm, 32);
    m->t = xcalloc(nt, sizeof *m->t);
    m->nt = nt;
    for (uint32_t i = 0; i < nt; i++) {
        mtable *t = &m->t[i];
        uint32_t sl = rd_u32(&r);
        const uint8_t *sb = rd_bytes(&r, sl);
        if (!sb) return fail("manifest: truncated");
        rd sr = {sb, sl, 0, false};
        if (decode_schema(&sr, &t->s) || rd_left(&sr) || t->s.id != i) return fail("manifest: bad schema");
        t->horizon = rd_u64(&r);
        t->live = rd_u64(&r);
        t->versions = rd_u64(&r);
        const uint8_t *lh = rd_bytes(&r, 2048);
        t->nseg = rd_u32(&r);
        if (r.bad || t->nseg > 65536 || t->nseg > rd_left(&r) / 68 || t->live > t->versions) return fail("manifest: malformed");
        memcpy(t->lthash, lh, 2048);
        t->seg = xcalloc(t->nseg, 32);
        t->dv = xcalloc(t->nseg, 32);
        t->nrows = xcalloc(t->nseg, sizeof *t->nrows);
        for (uint32_t k = 0; k < t->nseg; k++) {
            const uint8_t *sg = rd_bytes(&r, 32), *dv = rd_bytes(&r, 32);
            t->nrows[k] = rd_u32(&r);
            if (r.bad) return fail("manifest: truncated");
            memcpy(t->seg[k], sg, 32);
            memcpy(t->dv[k], dv, 32);
        }
        if (mver == 3) { /* indexes, sorted by name; their names unique across tables (checked below) */
            t->nidx = rd_u32(&r);
            if (r.bad || t->nidx > MAX_INDEXES) return fail("manifest: bad index count");
            for (uint32_t k = 0; k < t->nidx; k++) {
                uint8_t nl = rd_u8(&r);
                const uint8_t *nm = rd_bytes(&r, nl);
                t->idx[k].flags = rd_u8(&r);
                t->idx[k].ncols = rd_u8(&r);
                for (int c = 0; c < t->idx[k].ncols && c < MAX_INDEX_COLS; c++) t->idx[k].cols[c] = rd_u16(&r);
                if (r.bad || !ident_ok(nm, nl) || !aidx_ok(&t->idx[k], t->s.ncols)) return fail("manifest: bad index");
                memcpy(t->idx[k].name, nm, nl);
                if (k && strcmp(t->idx[k - 1].name, t->idx[k].name) >= 0) return fail("manifest: indexes not sorted");
            }
        }
    }
    if (rd_left(&r)) return fail("manifest: trailing bytes");
    if (mver == 3) { /* version 3 only with an index (else version 2 is its encoding), names unique */
        size_t total = 0;
        for (uint32_t i = 0; i < nt; i++) total += m->t[i].nidx;
        if (!total) return fail("manifest: version 3 without an index");
        const char **nm = xcalloc(total, sizeof *nm);
        size_t k = 0;
        for (uint32_t i = 0; i < nt; i++)
            for (uint32_t j = 0; j < m->t[i].nidx; j++) nm[k++] = m->t[i].idx[j].name;
        qsort(nm, total, sizeof *nm, cmp_str);
        bool dup = false;
        for (size_t i = 1; i < total && !dup; i++) dup = strcmp(nm[i - 1], nm[i]) == 0;
        free(nm);
        if (dup) return fail("manifest: an index name used twice");
    }
    return 0;
}

static bool manifest_refs(const manifest *m, const uint8_t h[32])
{
    if (memcmp(h, m->hash, 32) == 0) return true;
    for (uint32_t ti = 0; ti < m->nt; ti++)
        for (uint32_t k = 0; k < m->t[ti].nseg; k++)
            if (memcmp(h, m->t[ti].seg[k], 32) == 0 || (!all_zero(m->t[ti].dv[k], 32) && memcmp(h, m->t[ti].dv[k], 32) == 0))
                return true;
    return false;
}

/* objects/ holds exactly the published generation and the one it retains
 * (prev_manifest). Anything else is an interrupted publish or, after an
 * ERASE, older segments that still hold the erased rows. */
static int check_objects(int dirfd, const manifest *m, const state *S)
{
    int ofd = openat(dirfd, "objects", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (ofd < 0) return fail("objects/: cannot open");
    manifest pm;
    memset(&pm, 0, sizeof pm);
    bool retained = !all_zero(m->prev_manifest, 32);
    int rc = 0;
    if (retained) {
        char name[80];
        hex(m->prev_manifest, 32, name);
        strcat(name, ".man");
        uint8_t *pb = NULL;
        size_t pl;
        if (faccessat(ofd, name, F_OK, AT_SYMLINK_NOFOLLOW) != 0)
            rc = fail("the retained generation %s named by the manifest is missing from objects/", name);
        else if (obj_read(ofd, m->prev_manifest, ".man", &pb, &pl) || parse_manifest(pb, pl, &pm))
            rc = -1;
        else
            memcpy(pm.hash, m->prev_manifest, 32);
        free(pb);
    }
    /* a generation a reader pins (a pin file in pins/, held or stale): its files are kept, if this
     * log published it at or after its last ERASE; never one from before, nor one it never published */
    manifest *pg = rc || !S->npin ? NULL : xcalloc(S->npin, sizeof *pg);
    bool *pk = pg ? xcalloc(S->npin, sizeof *pk) : NULL;
    for (size_t i = 0; pg && !rc && i < S->npin; i++) {
        if (!S->pin_at[i] || S->pin_at[i] < S->last_erase) continue;
        char name[80];
        hex(S->pin[i], 32, name);
        strcat(name, ".man");
        if (faccessat(ofd, name, F_OK, AT_SYMLINK_NOFOLLOW) != 0) continue; /* gone: nothing kept */
        uint8_t *qb = NULL;
        size_t ql;
        if (obj_read(ofd, S->pin[i], ".man", &qb, &ql) || parse_manifest(qb, ql, &pg[i])) rc = -1;
        else {
            memcpy(pg[i].hash, S->pin[i], 32);
            pk[i] = true;
        }
        free(qb);
    }
    int dfd = rc ? -1 : dup(ofd);
    DIR *d = dfd >= 0 ? fdopendir(dfd) : NULL;
    if (!rc && !d) {
        if (dfd >= 0) close(dfd);
        rc = fail("objects/: cannot list the directory");
    }
    struct dirent *de;
    while (d && !rc && (de = readdir(d))) {
        if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0) continue;
        uint8_t h[32];
        bool pinned = false;
        if (!unhex(de->d_name, 64, h, 32)) {
            rc = fail("unexpected file in objects/: %s", de->d_name);
            break;
        }
        for (size_t i = 0; pk && !pinned && i < S->npin; i++) pinned = pk[i] && manifest_refs(&pg[i], h);
        if (!manifest_refs(m, h) && !(retained && manifest_refs(&pm, h)) && !pinned)
            rc = fail("objects/ holds %s, which neither the manifest nor its retained generation references (nor a "
                      "pinned one)", de->d_name);
    }
    if (d) closedir(d);
    for (size_t i = 0; pk && i < S->npin; i++)
        if (pk[i]) manifest_free(&pg[i]);
    free(pg);
    free(pk);
    manifest_free(&pm);
    close(ofd);
    return rc;
}

/* Per-row callback while walking the lake; returns nonzero to fail. */
/* No LAKE_HEAD: no lake is published, so objects/ must be empty (anything there is from a
 * publication that never completed, or from commits a crash took from the log). */
static int check_no_objects(int dirfd)
{
    int ofd = openat(dirfd, "objects", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (ofd < 0) return errno == ENOENT ? 0 : fail("objects/: cannot open");
    DIR *d = fdopendir(ofd);
    if (!d) {
        close(ofd);
        return fail("objects/: cannot list the directory");
    }
    int rc = 0;
    struct dirent *de;
    while (!rc && (de = readdir(d)))
        if (strcmp(de->d_name, ".") != 0 && strcmp(de->d_name, "..") != 0)
            rc = fail("objects/ holds %s, but no LAKE_HEAD publishes a lake", de->d_name);
    closedir(d);
    return rc;
}

typedef int (*row_fn)(void *ctx, uint32_t table, const schema *s, const seg *g, uint32_t i);

/* Walks every segment of the published snapshot with full structural and
 * commitment checks and re-derives each table digest from the rows. */
/* A reader's pin on a lake generation (the engine's lake.h): flock(LOCK_SH) on pins/<hash>.pin while
 * its files are read, so the writer's GC keeps them. -1: none (no pins/, not ours to write); the read
 * is then unpinned, and a file that goes sends the command back to LAKE_HEAD. */
static int pin_take(int dirfd, const uint8_t h[32])
{
    int pfd = openat(dirfd, "pins", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (pfd < 0) return -1;
    char name[80];
    hex(h, 32, name);
    strcat(name, ".pin");
    int f = -1;
    for (int attempt = 0; attempt < 3 && f < 0; attempt++) {
        int g = openat(pfd, name, O_RDWR | O_CREAT | O_NOFOLLOW | O_CLOEXEC, 0600);
        if (g < 0) break;
        /* GC unlinks a stale pin while it holds it exclusively: a lock on that file pins nothing */
        struct stat a, b;
        if (flock(g, LOCK_SH) == 0 && fstat(g, &a) == 0 && fstatat(pfd, name, &b, AT_SYMLINK_NOFOLLOW) == 0 &&
            a.st_ino == b.st_ino && a.st_dev == b.st_dev)
            f = g;
        else
            close(g);
    }
    close(pfd);
    return f;
}

static int walk_lake_pinned(int dirfd, uint8_t alg, const uint8_t mh[32], uint64_t seq, manifest *m, row_fn fn, void *ctx,
                            uint64_t *rows_checked);

static int walk_lake(int dirfd, uint8_t alg, manifest *m, row_fn fn, void *ctx, uint64_t *rows_checked)
{
    uint64_t seq;
    uint8_t mh[32];
    bool present;
    if (load_head(dirfd, &seq, mh, &present)) return -1;
    if (!present) return fail("no LAKE_HEAD: nothing has been checkpointed");
    int pin = pin_take(dirfd, mh);
    int rc = walk_lake_pinned(dirfd, alg, mh, seq, m, fn, ctx, rows_checked);
    if (pin >= 0) close(pin);
    return rc;
}

static int walk_lake_pinned(int dirfd, uint8_t alg, const uint8_t mh[32], uint64_t seq, manifest *m, row_fn fn, void *ctx,
                            uint64_t *rows_checked)
{
    int ofd = openat(dirfd, "objects", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (ofd < 0) return fail("objects/: %s", errno == ELOOP ? "refusing to follow a symbolic link" : strerror(errno));
    int rc = 0;
    int dfd = dup(ofd);
    DIR *d = dfd >= 0 ? fdopendir(dfd) : NULL;
    if (!d) {
        if (dfd >= 0) close(dfd);
        rc = fail("objects/: cannot list the directory");
    }
    struct dirent *de;
    while (d && !rc && (de = readdir(d))) {
        if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0) continue;
        struct stat st;
        if (!obj_name_ok(de->d_name)) rc = fail("unexpected file in objects/: %s", de->d_name);
        else if (fstatat(ofd, de->d_name, &st, AT_SYMLINK_NOFOLLOW) != 0 || !S_ISREG(st.st_mode))
            rc = fail("refusing to follow a symbolic link or special file in objects/: %s", de->d_name);
    }
    if (d) closedir(d);
    uint8_t *mb = NULL;
    size_t ml = 0;
    if (!rc) rc = obj_read(ofd, mh, ".man", &mb, &ml);
    if (!rc) rc = parse_manifest(mb, ml, m);
    if (!rc) memcpy(m->hash, mh, 32);
    if (!rc && m->seq != seq) rc = fail("manifest seq differs from LAKE_HEAD");
    lt total;
    memset(&total, 0, sizeof total);
    for (uint32_t ti = 0; !rc && ti < m->nt; ti++) {
        mtable *t = &m->t[ti];
        lt dg;
        memset(&dg, 0, sizeof dg);
        uint64_t live = 0;
        ukey *uk[MAX_INDEXES] = {0}; /* the live rows' keys of each unique index */
        size_t nuk[MAX_INDEXES] = {0}, capuk[MAX_INDEXES] = {0};
        for (uint32_t k = 0; !rc && k < t->nseg; k++) {
            uint8_t *sb;
            size_t sl;
            if ((rc = obj_read(ofd, t->seg[k], ".seg", &sb, &sl))) break;
            seg g;
            if ((rc = parse_segment(&t->s, sb, sl, &g))) {
                free(sb);
                break;
            }
            if (g.n != t->nrows[k]) rc = fail("segment row count differs from the manifest");
            if (!rc && !all_zero(t->dv[k], 32)) {
                uint8_t *dvb;
                size_t dl;
                if (!(rc = obj_read(ofd, t->dv[k], ".dv", &dvb, &dl))) {
                    rc = parse_dv(dvb, dl, t->seg[k], &g, m->seq);
                    free(dvb);
                }
            }
            for (uint32_t i = 0; !rc && i < g.n; i++) {
                const segrow *r = &g.row[i];
                if (r->begin <= m->seq && m->seq < r->end) {
                    lt_add(alg, &dg, r->commit);
                    live++;
                    for (uint32_t x = 0; x < t->nidx; x++) {
                        ukey key;
                        if (!(t->idx[x].flags & 1) || !ukey_of(&t->s, &g, i, &t->idx[x], &key)) continue;
                        if (nuk[x] == capuk[x]) {
                            capuk[x] = capuk[x] ? 2 * capuk[x] : 64;
                            uk[x] = xrealloc(uk[x], capuk[x], sizeof *uk[x]);
                        }
                        uk[x][nuk[x]++] = key;
                    }
                }
                if (fn) rc = fn(ctx, ti, &t->s, &g, i);
            }
            if (rows_checked) *rows_checked += g.n;
            seg_free(&g);
        }
        for (uint32_t x = 0; x < t->nidx; x++) { /* each unique key held by one live row at most */
            if (nuk[x]) qsort(uk[x], nuk[x], sizeof *uk[x], cmp_ukey);
            for (size_t j = 1; !rc && j < nuk[x]; j++)
                if (cmp_ukey(&uk[x][j - 1], &uk[x][j]) == 0)
                    rc = fail("lake: two live rows of table %s share a key of unique index %s", t->s.name, t->idx[x].name);
            for (size_t j = 0; j < nuk[x]; j++) free(uk[x][j].b);
            free(uk[x]);
        }
        uint8_t mine[2048];
        lt_bytes(&dg, mine);
        if (!rc && (memcmp(mine, t->lthash, 2048) != 0 || live != t->live))
            rc = fail("table %s: digest recomputed from lake files differs from the manifest", t->s.name);
        lt_sum(&total, &dg);
    }
    uint8_t sd[32];
    lt_digest(alg, &total, sd);
    if (!rc && memcmp(sd, m->state, 32) != 0) rc = fail("lake: tables do not sum to the manifest digest");
    free(mb);
    close(ofd);
    return rc;
}

/* ---- verify ------------------------------------------------------------------------------- */

typedef struct vctx {
    state *S;
    manifest *m;
    uint8_t **seen; /* per table: bitmap of vids found in segments */
} vctx;

static int verify_row(void *ctx, uint32_t ti, const schema *s, const seg *g, uint32_t i)
{
    vctx *x = ctx;
    const segrow *r = &g->row[i];
    table *t = &x->S->t[ti];
    if (r->vid >= t->n) return fail("lake: segment holds an unknown version of table %s", t->s.name);
    const ver *v = &t->v[r->vid];
    uint64_t end = v->end <= x->m->seq ? v->end : LIVE;
    bool purged = t->horizon_at_lake && v->end <= t->horizon_at_lake;
    if (memcmp(v->commit, r->commit, 32) != 0 || v->begin != r->begin || end != r->end || v->stub != r->stub ||
        purged != r->purged)
        return fail("lake: a segment row of table %s disagrees with the log", t->s.name);
    if (r->flags == 2 && s->subject >= 0 && v->has_subj) { /* the tombstone names the payload's subject */
        val tv;
        seg_value(s, g, i, s->subject, &tv);
        bool same = s->c[s->subject].type == T_TEXT
                        ? tv.len == v->subj_len && (!tv.len || memcmp(tv.s, v->subj_s, tv.len) == 0)
                        : tv.i == v->subj_i;
        if (!same) return fail("lake: a tombstone of table %s names another subject than its row in the log", t->s.name);
    }
    if (x->seen[ti][r->vid >> 3] & (1u << (r->vid & 7))) return fail("lake: version in two segments");
    x->seen[ti][r->vid >> 3] |= (uint8_t)(1u << (r->vid & 7));
    return 0;
}

/* --anchor FILE: the writer's external anchor. Two records, at offsets 0 and 512, each "IMDBANC1" |
 * db id | the descriptor of the commit it names (u64 seq, u32 header length, hash, signature) | u32
 * epoch | u32 0 | CRC32C of the 140 bytes (a torn rewrite damages only one). Read here; each is
 * authenticated after replay, by the signature it carries under the key of the epoch it names
 * (commit 0: the genesis hash), and the newest counts. */
static int load_anchor(const char *path, state *S)
{
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return fail("anchor %s: %s", path, strerror(errno));
    uint8_t b[512 + 144 + 1];
    ssize_t n = pread(fd, b, sizeof b, 0);
    close(fd);
    if (n != 512 + 144) return fail("anchor %s: wrong length (%zd bytes)", path, n); /* created whole, rewritten in place */
    for (size_t off = 0; off < 512 + 144; off += 512) {
        const uint8_t *r = b + off;
        if (memcmp(r, "IMDBANC1", 8) != 0 || a_crc32c(r, 140) != le32(r + 140) || le32(r + 136) != 0) continue; /* torn */
        if (memcmp(r + 8, S->m.db_id, 16) != 0) return fail("anchor %s belongs to another database", path);
        memcpy(S->anc_rec[S->anc_n++], r, 144);
    }
    if (!S->anc_n) return fail("anchor %s: damaged (no intact record)", path);
    return 0;
}

/* After replay, with every writer key the log holds: the anchor's newest authentic record must be
 * a commit of this history (or one a promotion abandoned); one this directory is behind is refused. */
static int anchor_final(state *S, const char *path)
{
    int best = -1;
    bool ahead = false;
    for (int a = 0; a < S->anc_n; a++) {
        const uint8_t *r = S->anc_rec[a];
        uint64_t seq = le64(r + 24);
        uint32_t ep = le32(r + 132);
        bool known = ep < S->K.nek;
        if (known && seq == 0) {
            uint8_t g[24], h[32];
            memcpy(g, "IMDBGEN1", 8);
            memcpy(g + 8, S->m.db_id, 16);
            a_sha256(g, sizeof g, h);
            if (memcmp(h, r + 36, 32) != 0) return fail("anchor %s: commit 0 with another hash", path);
        } else if (known) {
            uint8_t msg[52];
            memcpy(msg, "IMDBSIG2", 8);
            put64(msg + 8, seq);
            put32(msg + 16, le32(r + 32));
            memcpy(msg + 20, r + 36, 32);
            if (!a_ed25519_verify(S->K.ek[ep], msg, sizeof msg, r + 68))
                return fail("anchor %s is not signed by this database's writer (epoch %u)", path, ep);
        }
        const uint8_t *bb = best >= 0 ? S->anc_rec[best] : NULL;
        if (!bb || ep > le32(bb + 132) || (ep == le32(bb + 132) && seq > le64(bb + 24))) {
            best = a;
            ahead = !known;
        }
    }
    const uint8_t *r = S->anc_rec[best];
    uint64_t seq = le64(r + 24);
    uint32_t ep = le32(r + 132);
    if (ahead)
        return fail("the anchor names commit %llu of writer epoch %u, but this directory is at epoch %u: a newer writer "
                    "holds it", (unsigned long long)seq, ep, S->K.epoch);
    uint32_t at = keys_epoch_at(&S->K, seq);
    if (ep < at && S->K.eprom[ep + 1] && seq >= S->K.efirst[ep + 1]) {
        snprintf(S->note, sizeof S->note, "the anchor names commit %llu of writer epoch %u, which the promotion to epoch %u "
                 "abandoned", (unsigned long long)seq, ep, ep + 1);
        return 0;
    }
    if (seq > S->seq)
        return fail("the log ends at commit %llu, but the anchor names commit %llu: an older copy, or lost commits",
                    (unsigned long long)S->seq, (unsigned long long)seq);
    if (seq && (!S->anc_seen[best] || S->anc_epoch_at[best] != ep || memcmp(S->anc_hash_at[best], r + 36, 32) != 0))
        return fail("the anchor names commit %llu with another hash: a different history", (unsigned long long)seq);
    return 0;
}

static int cmd_verify(const char *dir, const char *anchor)
{
    int dirfd = open(dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (dirfd < 0) return fail("cannot open %s: %s", dir, strerror(errno));
    state S;
    memset(&S, 0, sizeof S);
    int rc = read_meta(dirfd, &S.m);
    if (!rc) keys_init(&S.K, &S.m);
    if (!rc && anchor) rc = load_anchor(anchor, &S);
    bool lake = false;
    if (!rc) rc = load_head(dirfd, &S.lake_seq, S.lake_manifest, &lake);
    uint64_t commits = 0;
    if (!rc) rc = load_pins(dirfd, &S);
    if (!rc) rc = replay(&S, dirfd, &commits);
    if (!rc && S.anc_n) rc = anchor_final(&S, anchor);
    if (!rc) {
        char dh[65];
        uint8_t d[32];
        lt_digest(S.m.alg, &S.glob, d);
        hex(d, 32, dh);
        printf("log ok: %llu commits, chain + %llu Ed25519 signatures, %llu payloads re-hashed, digest %s\n",
               (unsigned long long)commits, (unsigned long long)S.sigs, (unsigned long long)S.payload_rows, dh);
        for (uint32_t i = 0; i < S.nt; i++) {
            uint64_t stubs = 0;
            for (uint64_t k = 0; k < S.t[i].n; k++) stubs += S.t[i].v[k].stub;
            printf("  table %-12s %llu versions, %llu live, %llu erased\n", S.t[i].s.name, (unsigned long long)S.t[i].n,
                   (unsigned long long)S.t[i].live, (unsigned long long)stubs);
        }
    }
    if (!rc && lake && (S.lake_seq < 1 || S.lake_seq > S.seq)) /* before its files: they may hold rows the log lost */
        rc = fail("lake snapshot (commit %llu) is not in the log, which ends at commit %llu", (unsigned long long)S.lake_seq,
                  (unsigned long long)S.seq);
    if (!rc && !lake) rc = check_no_objects(dirfd);
    if (!rc && lake) {
        manifest m;
        memset(&m, 0, sizeof m);
        vctx x = {&S, &m, NULL};
        x.seen = xcalloc(S.nt ? S.nt : 1, sizeof *x.seen);
        for (uint32_t i = 0; i < S.nt; i++) x.seen[i] = xcalloc(S.t[i].n / 8 + 1, 1);
        uint64_t rows = 0;
        /* the files first (structure, names, hashes), then their binding to the log */
        rc = walk_lake(dirfd, S.m.alg, &m, verify_row, &x, &rows);
        if (rc) {
        } else if (S.lake_seq < 1 || S.lake_seq > S.seq) {
            rc = fail("lake snapshot (commit %llu) is not in the log", (unsigned long long)S.lake_seq);
        } else if (!S.lake_recorded) {
            rc = fail("no commit records the manifest named by LAKE_HEAD");
        } else if (S.last_erase > S.lake_seq) {
            rc = fail("lake snapshot predates the ERASE at commit %llu (erasure not yet applied to the lake)",
                      (unsigned long long)S.last_erase);
        }
        if (!rc && (memcmp(m.db_id, S.m.db_id, 16) != 0)) rc = fail("lake belongs to another database");
        if (!rc && (memcmp(m.state, S.lake_digest, 32) != 0 || memcmp(m.prev, S.lake_prev, 32) != 0))
            rc = fail("lake digest differs from the log digest at commit %llu", (unsigned long long)m.seq);
        if (!rc && memcmp(m.prev_manifest, S.lake_prev_manifest, 32) != 0)
            rc = fail("manifest names the wrong retained generation (prev_manifest)");
        if (!rc) rc = check_objects(dirfd, &m, &S);
        if (!rc && m.nt > S.nt) rc = fail("manifest names tables the log does not have");
        for (uint32_t ti = 0; !rc && ti < m.nt; ti++) {
            table *t = &S.t[ti];
            mtable *mt = &m.t[ti];
            uint8_t at[2048];
            lt_bytes(&t->d_at_lake, at);
            uint64_t versions = 0;
            while (versions < t->n && t->v[versions].begin <= m.seq) versions++;
            if (mt->s.rawlen != t->s.rawlen || memcmp(mt->s.raw, t->s.raw, t->s.rawlen) != 0)
                rc = fail("manifest schema of %s differs from the log", t->s.name);
            else if (memcmp(at, mt->lthash, 2048) != 0)
                rc = fail("table %s: manifest digest differs from the log at commit %llu", t->s.name, (unsigned long long)m.seq);
            else if (mt->versions != versions || mt->horizon != t->horizon_at_lake)
                rc = fail("table %s: manifest version count or history horizon differs from the log", t->s.name);
            else if (mt->nidx != t->nidx_at_lake)
                rc = fail("table %s: the manifest's indexes differ from the log's", t->s.name);
            for (uint32_t k = 0; !rc && k < mt->nidx; k++)
                if (!aidx_same(&mt->idx[k], &t->idx_at_lake[k]))
                    rc = fail("table %s: the manifest's indexes differ from the log's", t->s.name);
            for (uint64_t vid = 0; !rc && vid < versions; vid++) {
                if (!(x.seen[ti][vid >> 3] & (1u << (vid & 7))))
                    rc = fail("table %s: version %llu is missing from the lake (purged versions keep a tombstone)", t->s.name,
                              (unsigned long long)vid);
            }
        }
        for (uint32_t i = 0; i < S.nt; i++) free(x.seen[i]);
        free(x.seen);
        if (!rc)
            printf("lake ok: snapshot at commit %llu, %u tables, %llu rows re-derived from segment files\n",
                   (unsigned long long)m.seq, m.nt, (unsigned long long)rows);
        manifest_free(&m);
    }
    if (!rc && S.note[0]) printf("note: %s\n", S.note);
    for (uint32_t i = 0; i < S.nt; i++) {
        for (uint64_t k = 0; k < S.t[i].n; k++) free(S.t[i].v[k].subj_s), free(S.t[i].v[k].row);
        for (uint32_t k = 0; k < S.t[i].nidx; k++) uk_free(S.t[i].idx[k].uk);
        free(S.t[i].v);
        free(S.t[i].s.raw);
    }
    keys_free(&S.K);
    free(S.t);
    free(S.pin);
    free(S.pin_at);
    close(dirfd);
    return rc;
}

/* ---- count / digest from lake files only ------------------------------------------------- */

/* ---- answering past the lake snapshot: the log tail --------------------------------------
 *
 * The lake snapshot at commit S plus the log's tail S+1..N, from files only and
 * authenticated: commit S is signed and records the manifest LAKE_HEAD names, whose
 * table digests sum to S's recorded digest (walk_lake checks them against the rows);
 * every tail commit is signed, links to the one before, has every payload match its
 * commitment, and has its recorded state digest equal to the snapshot's digests plus
 * the tail's changes. Commits after N are read too, for their ERASEs: erased rows
 * disappear from every snapshot, as in the engine. */

typedef struct tver {
    uint64_t begin, end;
    uint8_t commit[32];
    bool stub, redacted;
    val v[MAX_COLS];
} tver;

typedef struct lend { /* a snapshot version the tail ended or erased */
    uint64_t vid, end;
    uint8_t commit[32]; /* the commitment the ending op names (checked against the lake row) */
    bool ended, stub;
} lend;

typedef struct ttab {
    const schema *s;
    schema own; /* a table the tail created */
    uint64_t lake_n, horizon, live;
    lend *le;
    size_t nle, cle;
    tver *v;
    uint64_t n, cap;
    lt d;
} ttab;

typedef struct ttail {
    uint64_t S, N, end; /* end: the last commit in the log */
    ttab *t;
    uint32_t nt;
    lt glob;
    uint8_t head[32]; /* the hash of commit N */
    uint8_t **bufs;   /* the segments read: tail values point into them */
    uint8_t alg;      /* META's digest algorithm */
    size_t nbufs;
} ttail;

static void lt_from(lt *a, const uint8_t b[2 * LANES])
{
    for (int i = 0; i < LANES; i++) a->v[i] = (uint16_t)(b[2 * i] | b[2 * i + 1] << 8);
}

static lend *lend_get(ttab *t, uint64_t vid)
{
    for (size_t i = 0; i < t->nle; i++)
        if (t->le[i].vid == vid) return &t->le[i];
    if (t->nle == t->cle) {
        t->cle = t->cle ? 2 * t->cle : 16;
        t->le = xrealloc(t->le, t->cle, sizeof *t->le);
    }
    lend *e = &t->le[t->nle++];
    memset(e, 0, sizeof *e);
    e->vid = vid;
    e->end = LIVE;
    return e;
}

static const lend *lend_find(const ttab *t, uint64_t vid)
{
    for (size_t i = 0; i < t->nle; i++)
        if (t->le[i].vid == vid) return &t->le[i];
    return NULL;
}

static void tail_free(ttail *T)
{
    for (uint32_t i = 0; i < T->nt; i++) {
        free(T->t[i].le);
        free(T->t[i].v);
        free(T->t[i].own.raw);
    }
    free(T->t);
    for (size_t i = 0; i < T->nbufs; i++) free(T->bufs[i]);
    free(T->bufs);
    memset(T, 0, sizeof *T);
}

/* one op of a tail commit; apply = false past N: only ERASE entries count */
static int tail_op(ttail *T, const op *o, uint64_t seq, bool apply)
{
    if (o->code == 12) {
        for (uint32_t k = 0; k < o->n_erase; k++) {
            const erase_ent *en = &o->erase[k];
            if (en->table >= T->nt) return fail("commit %llu: ERASE names an unknown table", (unsigned long long)seq);
            ttab *t = &T->t[en->table];
            if (en->vid < t->lake_n) {
                lend *e = lend_get(t, en->vid);
                if (e->ended && memcmp(e->commit, en->commit, 32) != 0)
                    return fail("commit %llu: ERASE names another commitment", (unsigned long long)seq);
                memcpy(e->commit, en->commit, 32);
                e->stub = true;
            } else if (en->vid - t->lake_n < t->n && memcmp(t->v[en->vid - t->lake_n].commit, en->commit, 32) == 0) {
                t->v[en->vid - t->lake_n].stub = true;
            } else if (apply || en->vid - t->lake_n < t->n) {
                return fail("commit %llu: invalid ERASE entry", (unsigned long long)seq);
            } /* past N: a version created after N, never visible at N */
        }
        return 0;
    }
    if (!apply) return 0;
    if (o->code == 1) {
        if (o->table != T->nt) return fail("commit %llu: table id out of sequence", (unsigned long long)seq);
        T->t = xrealloc(T->t, T->nt + 1, sizeof *T->t);
        ttab *t = &T->t[T->nt++];
        memset(t, 0, sizeof *t);
        t->own = *o->sch;
        t->own.raw = xcalloc(o->sch->rawlen, 1);
        memcpy(t->own.raw, o->sch->raw, o->sch->rawlen);
        t->s = &t->own;
        for (uint32_t i = 0; i + 1 < T->nt; i++) T->t[i].s = T->t[i].own.raw ? &T->t[i].own : T->t[i].s;
        return 0;
    }
    if (o->code == 10) return 0;
    if (o->table >= T->nt) return fail("commit %llu: unknown table %u", (unsigned long long)seq, o->table);
    ttab *t = &T->t[o->table];
    if (o->code == 11) {
        if (o->purge_before > t->horizon) t->horizon = o->purge_before;
        return 0;
    }
    if (o->code == 3 || o->code == 4) {
        if (o->vid < t->lake_n) {
            lend *e = lend_get(t, o->vid);
            if (e->ended) return fail("commit %llu: delete precondition fails", (unsigned long long)seq);
            e->ended = true;
            e->end = seq;
            memcpy(e->commit, o->commit, 32);
        } else {
            uint64_t k = o->vid - t->lake_n;
            if (k >= t->n || t->v[k].end != LIVE || memcmp(t->v[k].commit, o->commit, 32) != 0)
                return fail("commit %llu: delete precondition fails", (unsigned long long)seq);
            t->v[k].end = seq;
        }
        t->live--;
        lt_sub(T->alg, &t->d, o->commit);
        lt_sub(T->alg, &T->glob, o->commit);
    }
    if (o->code == 2 || o->code == 4) {
        uint64_t vid = o->code == 2 ? o->vid : o->new_vid;
        const uint8_t *cm = o->code == 2 ? o->commit : o->new_commit;
        if (vid != t->lake_n + t->n) return fail("commit %llu: version id out of sequence", (unsigned long long)seq);
        if (t->n == t->cap) {
            t->cap = t->cap ? 2 * t->cap : 64;
            t->v = xrealloc(t->v, t->cap, sizeof *t->v);
        }
        tver *v = &t->v[t->n++];
        memset(v, 0, sizeof *v);
        memcpy(v->commit, cm, 32);
        v->begin = seq;
        v->end = LIVE;
        v->redacted = o->redacted;
        if (!o->redacted) {
            uint8_t chk[32];
            row_commit(o->table, o->salt, o->row, o->row_len, chk);
            if (memcmp(chk, cm, 32) != 0) return fail("commit %llu: payload does not match its commitment", (unsigned long long)seq);
            if (decode_row(t->s, o->row, o->row_len, v->v)) return -1;
        }
        t->live++;
        lt_add(T->alg, &t->d, cm);
        lt_add(T->alg, &T->glob, cm);
    }
    return 0;
}

/* the frames of a segment, in order: offsets and lengths; *torn when it ends in an
 * unfinished or damaged frame (the engine truncates that at its next writable open) */
static int seg_frames(const uint8_t *log, size_t n, const char *name, size_t **off, size_t *nf, bool *torn)
{
    size_t o = 0, cap = 0;
    *off = NULL;
    *nf = 0;
    *torn = false;
    while (o < n) {
        size_t left = n - o;
        const uint8_t *f = log + o;
        if (left < 16 || le32(f) != 0x32474C49u || a_crc32c(f, 12) != le32(f + 12)) {
            if (left >= 16 && !all_zero(f, left)) return fail("log corrupt: bad frame header in segment %s", name);
            *torn = true; /* a short or zero-filled end */
            return 0;
        }
        uint32_t blen = le32(f + 4);
        if (blen > MAX_FRAME) return fail("log corrupt: frame too large in segment %s", name);
        if (blen > left - 16) {
            *torn = true;
            return 0;
        }
        if (a_crc32c(f + 16, blen) != le32(f + 8)) {
            if (!all_zero(f + 16 + blen, left - 16 - blen)) return fail("log corrupt: checksum mismatch in segment %s", name);
            *torn = true; /* a complete final frame that fails its checksum: the end of what can be read */
            return 0;
        }
        if (*nf == cap) {
            cap = cap ? 2 * cap : 64;
            *off = xrealloc(*off, cap, sizeof **off);
        }
        (*off)[(*nf)++] = o;
        o += 16 + blen;
    }
    return 0;
}

/* WRITERS (the engine's writer.h): every WRITER_KEY commit's header, signature and root signature,
 * so the keys up to a lake snapshot are known without the log before it. Each entry is proven
 * here from META's keys alone: the header hashes to what its signature covers, holds only
 * WRITER_KEY of the next epoch, and verifies under the key before it (a rotation) or under the
 * root key and its own (a promotion). Absent: the keys stay at epoch 0 (and a snapshot under a
 * later epoch then fails its signature check). Entries past the snapshot are left to the tail. */
static int load_writers(int dirfd, const meta *m, uint64_t S, keys *k)
{
    uint8_t *b;
    size_t n;
    int fd = openat(dirfd, "WRITERS", O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0 && errno == ENOENT) return 0;
    if (fd >= 0) close(fd);
    if (read_file(dirfd, "WRITERS", &b, &n, 4096u * 4096u)) return -1;
    int rc = 0;
    if (n < 32 || a_crc32c(b, n - 4) != le32(b + n - 4) || memcmp(b, "IMDBWRS1", 8) != 0 || memcmp(b + 8, m->db_id, 16) != 0)
        rc = fail("WRITERS: damaged or another database's");
    rd r = {b, n - 4, 28, false};
    uint32_t cnt = rc ? 0 : le32(b + 24);
    uint64_t last = 0;
    for (uint32_t i = 0; !rc && i < cnt; i++) {
        uint64_t seq = rd_u64(&r);
        uint8_t promote = rd_u8(&r);
        uint32_t hlen = rd_u32(&r);
        const uint8_t *h = rd_bytes(&r, hlen), *sig = rd_bytes(&r, 64), *rs = promote ? rd_bytes(&r, 64) : NULL;
        /* header: version 2 | alg (META's) | seq | time | prev | n_ops 1 | 13 | epoch | key | how | digest */
        if (r.bad || promote > 1 || seq <= last || hlen != 86 + 38 || h[0] != 2 || h[1] != m->alg || le64(h + 2) != seq ||
            le32(h + 50) != 1 || h[54] != 13 || (h[91] != 1 && h[91] != 2) || (h[91] == 2) != (promote == 1)) {
            rc = fail("WRITERS: entry %u is not a WRITER_KEY commit", i + 1);
            break;
        }
        if (seq >= S) break; /* the tail holds this one and those after it */
        uint32_t ep = le32(h + 55);
        const uint8_t *pk = h + 59;
        if (ep != k->epoch + 1) {
            rc = fail("WRITERS: entry %u names epoch %u after %u", i + 1, ep, k->epoch);
            break;
        }
        uint8_t hash[32], msg[52], tagged[8];
        memcpy(tagged, "IMDBCHN2", 8);
        a_sha256_ctx hc;
        a_sha256_init(&hc);
        a_sha256_update(&hc, tagged, 8);
        a_sha256_update(&hc, h, hlen);
        a_sha256_final(&hc, hash);
        memcpy(msg, "IMDBSIG2", 8);
        put64(msg + 8, seq);
        put32(msg + 16, hlen);
        memcpy(msg + 20, hash, 32);
        const uint8_t *signer = k->cur;
        if (promote) {
            uint8_t pm[100];
            memcpy(pm, "IMDBPRO1", 8);
            memcpy(pm + 8, m->db_id, 16);
            put32(pm + 24, ep);
            put64(pm + 28, seq);
            memcpy(pm + 36, h + 18, 32);
            memcpy(pm + 68, pk, 32);
            if (!m->has_root || !a_ed25519_verify(m->root, pm, sizeof pm, rs)) {
                rc = fail("WRITERS: entry %u: a promotion without this database's root certificate", i + 1);
                break;
            }
            signer = pk;
        }
        if (!a_ed25519_verify(signer, msg, sizeof msg, sig)) {
            rc = fail("WRITERS: entry %u (commit %llu) is not signed by the keys before it", i + 1, (unsigned long long)seq);
            break;
        }
        keys_push(k, pk, promote ? seq : seq + 1, promote);
        last = seq;
    }
    free(b);
    return rc;
}

/* Loads the tail of the log after the snapshot m (at m->seq, LAKE_HEAD's manifest mh) up to
  * commit N (N >= m->seq), or fails naming why commit N cannot be answered from these files. */
static int tail_load(int dirfd, const meta *mt, const manifest *m, const uint8_t mh[32], uint64_t N, ttail *T)
{
    memset(T, 0, sizeof *T);
    T->alg = mt->alg;
    T->S = m->seq;
    T->N = N;
    T->nt = m->nt;
    T->t = xcalloc(m->nt ? m->nt : 1, sizeof *T->t);
    for (uint32_t i = 0; i < m->nt; i++) {
        ttab *t = &T->t[i];
        t->s = &m->t[i].s;
        t->lake_n = m->t[i].versions;
        t->horizon = m->t[i].horizon;
        t->live = m->t[i].live;
        lt_from(&t->d, m->t[i].lthash);
        lt_sum(&T->glob, &t->d);
    }
    int logfd;
    uint64_t *segs;
    size_t nsegs;
    if (list_segments(dirfd, &logfd, &segs, &nsegs)) {
        if (logfd >= 0) close(logfd);
        return -1;
    }
    keys K; /* up to the snapshot from WRITERS, then from the tail */
    keys_init(&K, mt);
    int rc = load_writers(dirfd, mt, T->S, &K);
    size_t si = 0;
    while (si + 1 < nsegs && segs[si + 1] <= T->S) si++;
    uint64_t seq = T->S;
    uint8_t run[32]; /* the chain: the hash of the last commit read */
    bool have_s = T->S == 0; /* no snapshot: the log from its first commit */
    if (have_s) {
        uint8_t g[24];
        memcpy(g, "IMDBGEN1", 8);
        memcpy(g + 8, mt->db_id, 16);
        a_sha256(g, sizeof g, run);
        memcpy(T->head, run, 32); /* commit 0 */
    } else if (nsegs == 0 || segs[si] > T->S) {
        rc = fail("no log segment holds the snapshot commit %llu", (unsigned long long)T->S);
    }
    bool seen_tagged = false;
    for (; !rc && si < nsegs; si++) {
        char name[32];
        snprintf(name, sizeof name, "%020llu.ilg", (unsigned long long)segs[si]);
        uint8_t *log;
        size_t n;
        if ((rc = read_file(logfd, name, &log, &n, MAX_OBJECT))) break;
        int tail = TAIL_END;
        if (tagged_seg(log, n)) { /* its frames, and the verdict for what follows them */
            uint8_t *fr;
            size_t fl;
            tail = untag(log, n, segs[si], name, &fr, &fl);
            free(log);
            if (tail < 0) {
                rc = -1;
                break;
            }
            log = fr;
            n = fl;
            seen_tagged = true;
        } else if (seen_tagged && !(si + 1 == nsegs && all_zero(log, n))) { /* as in the replay */
            free(log);
            rc = fail("log corrupt: segment %s is untagged, after a tagged one", name);
            break;
        }
        T->bufs = xrealloc(T->bufs, T->nbufs + 1, sizeof *T->bufs);
        T->bufs[T->nbufs++] = log;
        size_t *off, nf;
        bool torn;
        if ((rc = seg_frames(log, n, name, &off, &nf, &torn))) break;
        torn = torn || tail != TAIL_END;
        if (torn && si + 1 < nsegs) rc = fail("log corrupt: torn frame inside segment %s, which is not the last", name);
        /* the snapshot commit is the last frame of its segment: only that one is decoded there */
        size_t first = have_s ? 0 : (nf ? nf - 1 : 0);
        for (size_t k = first; !rc && k < nf; k++) {
            const uint8_t *f = log + off[k];
            commit c;
            if ((rc = decode_body(f + 16, le32(f + 4), mt, &K, &c))) {
                commit_free(&c);
                break;
            }
            if (!have_s) {
                bool recorded = false;
                for (uint32_t i = 0; i < c.nops; i++) recorded |= c.ops[i].manifest && memcmp(c.ops[i].manifest, mh, 32) == 0;
                uint8_t d[32];
                lt_digest(T->alg, &T->glob, d);
                if (c.seq != T->S) rc = fail("the snapshot commit %llu does not end its log segment", (unsigned long long)T->S);
                else if (!recorded) rc = fail("commit %llu does not record the manifest LAKE_HEAD names", (unsigned long long)T->S);
                else if (memcmp(d, c.digest, 32) != 0 || memcmp(d, m->state, 32) != 0)
                    rc = fail("the snapshot's digest differs from commit %llu's", (unsigned long long)T->S);
                memcpy(run, c.hash, 32);
                if (N == T->S) memcpy(T->head, c.hash, 32);
                have_s = true;
            } else {
                if (c.seq != seq + 1) rc = fail("commit %llu out of sequence", (unsigned long long)c.seq);
                else if (memcmp(c.prev, run, 32) != 0) rc = fail("hash chain broken at commit %llu", (unsigned long long)c.seq);
                bool apply = c.seq <= N; /* past N only the ERASEs count */
                for (uint32_t i = 0; !rc && i < c.nops; i++) rc = tail_op(T, &c.ops[i], c.seq, apply);
                uint8_t d[32];
                lt_digest(T->alg, &T->glob, d);
                if (!rc && apply && memcmp(d, c.digest, 32) != 0)
                    rc = fail("commit %llu: recorded state digest does not match the snapshot plus the tail",
                              (unsigned long long)c.seq);
                seq = c.seq;
                memcpy(run, c.hash, 32);
                if (seq == N) memcpy(T->head, c.hash, 32);
            }
            commit_free(&c);
        }
        free(off);
    }
    if (!rc && seq < N)
        rc = fail("commit %llu is not in the log, which ends at commit %llu", (unsigned long long)N, (unsigned long long)seq);
    for (uint32_t i = 0; !rc && i < T->nt; i++)
        for (uint64_t k = 0; k < T->t[i].n; k++)
            if (T->t[i].v[k].redacted && !T->t[i].v[k].stub && T->t[i].v[k].begin <= N)
                rc = fail("table %s: a redacted payload that no ERASE in the log authorises", T->t[i].s->name);
    keys_free(&K);
    T->end = seq;
    free(segs);
    close(logfd);
    return rc;
}

typedef struct filt {
    int col;
    val v;
    uint8_t *own;
} filt;

typedef struct qctx {
    const char *table;
    int ti;
    filt f[MAX_COLS];
    int nf;
    char **fargs;
    int nfargs;
    uint64_t snap, count;
    __int128 sum[MAX_COLS];
    uint64_t nsum[MAX_COLS]; /* non-null values summed: none means the SUM is NULL */
    afsum fs[MAX_COLS];      /* FLOAT64 columns: exact, by afsum.c */
    uint8_t alg;             /* META's digest algorithm */
    lt dg;
    bool parsed;
    ttail *tail; /* the log tail past the snapshot, when the read point is past it */
} qctx;

static int parse_filter(const schema *s, const char *arg, filt *f)
{
    const char *eq = strchr(arg, '=');
    if (!eq) return fail("filter must be col=value: %s", arg);
    size_t cl = (size_t)(eq - arg);
    f->col = -1;
    for (int c = 0; c < s->ncols; c++)
        if (strlen(s->c[c].name) == cl && memcmp(s->c[c].name, arg, cl) == 0) f->col = c;
    if (f->col < 0) return fail("no column %.*s", (int)cl, arg);
    const char *v = eq + 1;
    const col *c = &s->c[f->col];
    memset(&f->v, 0, sizeof f->v);
    if (c->type == T_TEXT) {
        f->v.len = (uint32_t)strlen(v);
        f->v.s = (const uint8_t *)v;
        return 0;
    }
    if (c->type == T_BOOL) {
        bool t = strcmp(v, "true") == 0 || strcmp(v, "1") == 0;
        if (!t && strcmp(v, "false") != 0 && strcmp(v, "0") != 0) return fail("filter %s: true or false", arg);
        f->v.i = t;
        return 0;
    }
    /* stored as an order-preserving key, not as the digits: an integer here would match the wrong rows */
    if (c->type == T_FLOAT64) return fail("filters on FLOAT64 column %s are not supported", c->name);
    bool neg = *v == '-';
    if (*v == '-' || *v == '+') v++;
    __int128 acc = 0;
    int frac = -1;
    for (; *v; v++) {
        if (*v == '.' && frac < 0 && c->type == T_DECIMAL) {
            frac = 0;
            continue;
        }
        if (*v < '0' || *v > '9') return fail("bad number in filter %s", arg);
        if (frac >= 0 && ++frac > c->scale) return fail("too many fractional digits in filter %s", arg);
        acc = acc * 10 + (*v - '0');
        if (acc > ((__int128)1 << 64)) return fail("number out of range in filter %s", arg);
    }
    int scale = c->type == T_DECIMAL ? c->scale : 0;
    for (int k = frac < 0 ? 0 : frac; k < scale; k++) acc *= 10;
    f->v.i = (int64_t)(neg ? -acc : acc);
    return 0;
}


/* the engine's rule (imdb_format_float64): the fewest of 15, 16 or 17 significant digits that read
 * back as the same double; past the finite range, the engine refuses the SUM and this says so */
static void print_sum_f64(const afsum *s)
{
    double d;
    int rc = afsum_result(s, &d);
    if (rc) {
        fputs(rc == 1 ? "out-of-range" : "error", stdout);
        return;
    }
    char b[40];
    for (int prec = 15; prec <= 17; prec++) {
        snprintf(b, sizeof b, "%.*g", prec, d);
        if (prec == 17 || strtod(b, NULL) == d) break;
    }
    fputs(b, stdout);
}

static void print_i128(__int128 v, int scale)
{
    char tmp[64];
    int n = 0;
    bool neg = v < 0;
    unsigned __int128 a = neg ? (unsigned __int128)0 - (unsigned __int128)v : (unsigned __int128)v;
    do {
        tmp[n++] = (char)('0' + (int)(a % 10));
        a /= 10;
    } while (a || n <= scale);
    if (neg) putchar('-');
    for (int i = n - 1; i >= 0; i--) {
        putchar(tmp[i]);
        if (i == scale && scale > 0) putchar('.');
    }
}

/* A commit number: decimal digits only, no sign, no overflow ("abc" is not 0). */
static bool parse_seq(const char *s, uint64_t *out)
{
    uint64_t v = 0;
    if (!*s) return false;
    for (; *s; s++) {
        if (*s < '0' || *s > '9' || v > (UINT64_MAX - (uint64_t)(*s - '0')) / 10) return false;
        v = v * 10 + (uint64_t)(*s - '0');
    }
    *out = v;
    return true;
}

/* one row that is visible at the read point: filters, then the count, sums and digest */
static void q_take(qctx *q, const schema *s, const val *vals, const uint8_t cm[32])
{
    for (int k = 0; k < q->nf; k++) {
        const val *v = &vals[q->f[k].col], *w = &q->f[k].v;
        if (v->null) return;
        if (s->c[q->f[k].col].type == T_TEXT ? (v->len != w->len || (v->len && memcmp(v->s, w->s, v->len) != 0)) : v->i != w->i)
            return;
    }
    q->count++;
    for (int c = 0; c < s->ncols; c++)
        if ((s->c[c].type == T_INT64 || s->c[c].type == T_DECIMAL) && !(s->c[c].flags & (F_PK | F_SUBJECT)) && !vals[c].null) {
            q->sum[c] += vals[c].i;
            q->nsum[c]++;
        }
        else if (s->c[c].type == T_FLOAT64 && !(s->c[c].flags & (F_PK | F_SUBJECT)) && !vals[c].null) {
            afsum_add(&q->fs[c], float_value(vals[c].i));
            q->nsum[c]++;
        }
    lt_add(q->alg, &q->dg, cm);
}

static int query_row(void *ctx, uint32_t ti, const schema *s, const seg *g, uint32_t i)
{
    qctx *q = ctx;
    if ((int)ti != q->ti) return 0;
    const segrow *r = &g->row[i];
    uint64_t end = r->end;
    bool stub = r->stub;
    if (q->tail) { /* what the log tail did to this snapshot version */
        const lend *e = lend_find(&q->tail->t[ti], r->vid);
        if (e) {
            if (memcmp(e->commit, r->commit, 32) != 0 || (e->ended && r->end != LIVE))
                return fail("table %s: the log tail ends or erases version %llu, which the lake holds otherwise", s->name,
                            (unsigned long long)r->vid);
            if (e->ended) end = e->end;
            stub = stub || e->stub;
        }
    }
    if (stub || r->purged || !(r->begin <= q->snap && q->snap < end)) return 0;
    val vals[MAX_COLS];
    for (int c = 0; c < s->ncols; c++) seg_value(s, g, i, c, &vals[c]);
    q_take(q, s, vals, r->commit);
    return 0;
}

/* the manifest LAKE_HEAD names (walk_lake reads and checks it again with the segments) */
static int head_manifest(int dirfd, const uint8_t mh[32], manifest *m)
{
    int ofd = openat(dirfd, "objects", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (ofd < 0) return fail("objects/: %s", strerror(errno));
    uint8_t *mb = NULL;
    size_t ml = 0;
    int rc = obj_read(ofd, mh, ".man", &mb, &ml);
    if (!rc) rc = parse_manifest(mb, ml, m);
    free(mb);
    close(ofd);
    return rc;
}

static int cmd_query(bool digest, const char *dir, int argc, char **argv)
{
    qctx q;
    memset(&q, 0, sizeof q);
    q.ti = -1;
    q.fargs = xcalloc((size_t)argc, sizeof *q.fargs);
    bool has_asof = false, lake_only = false;
    uint64_t asof = 0;
    int rc = 0;
    for (int i = 0; i < argc && !rc; i++) {
        if (strcmp(argv[i], "--as-of") == 0 && i + 1 < argc) {
            has_asof = true;
            if (!parse_seq(argv[++i], &asof)) rc = fail("--as-of takes a commit number");
        } else if (strcmp(argv[i], "--lake") == 0) {
            lake_only = true;
        } else if (!q.table) {
            q.table = argv[i];
        } else {
            q.fargs[q.nfargs++] = argv[i];
        }
    }
    if (!rc && !q.table) rc = fail("need a table name");
    if (!rc && has_asof && lake_only) rc = fail("--as-of and --lake exclude each other");
    int dirfd = rc ? -1 : open(dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (!rc && dirfd < 0) rc = fail("cannot open %s: %s", dir, strerror(errno));
    meta mt;
    state ds; /* for DURABLE only */
    memset(&ds, 0, sizeof ds);
    uint64_t S = 0;
    uint8_t mh[32] = {0};
    bool present = false;
    if (!rc) rc = read_meta(dirfd, &mt);
    q.alg = mt.alg;
    if (!rc) rc = load_head(dirfd, &S, mh, &present);
    if (!rc) rc = load_durable(dirfd, &ds);
    if (!rc && lake_only && !present) rc = fail("no LAKE_HEAD: nothing has been checkpointed");
    /* the read point: as asked, the lake snapshot, or the latest commit DURABLE names */
    uint64_t N = has_asof ? asof : lake_only ? S : ds.dur_present && ds.dur_seq > S ? ds.dur_seq : S;
    if (!rc && !has_asof && !lake_only && !ds.dur_present && present)
        snprintf(g_note, sizeof g_note, "no DURABLE watermark: answered at the lake snapshot");
    if (!rc && ds.dur_present && N > ds.dur_seq && N > S)
        rc = fail("commit %llu is past the durable watermark (commit %llu)", (unsigned long long)N, (unsigned long long)ds.dur_seq);
    q.snap = N;
    manifest m;
    memset(&m, 0, sizeof m);
    ttail T;
    memset(&T, 0, sizeof T);
    if (!rc && present) rc = head_manifest(dirfd, mh, &m);
    if (!rc && N > S) {
        rc = tail_load(dirfd, &mt, &m, mh, N, &T);
        q.tail = &T;
    }
    uint32_t nt = q.tail ? T.nt : m.nt;
    const schema *qs = NULL;
    uint64_t horizon = 0;
    for (uint32_t i = 0; !rc && i < nt; i++) {
        const schema *s = q.tail ? T.t[i].s : &m.t[i].s;
        if (strcmp(s->name, q.table) == 0) {
            q.ti = (int)i;
            qs = s;
            horizon = q.tail ? T.t[i].horizon : m.t[i].horizon;
        }
    }
    if (!rc && !qs) rc = fail("no table %s at commit %llu", q.table, (unsigned long long)N);
    if (!rc && N < horizon) rc = fail("history before commit %llu was purged", (unsigned long long)horizon);
    for (int k = 0; k < q.nfargs && !rc; k++) rc = parse_filter(qs, q.fargs[k], &q.f[q.nf++]);
    manifest m2;
    memset(&m2, 0, sizeof m2);
    if (!rc && present && q.ti < (int)m.nt) rc = walk_lake(dirfd, mt.alg, &m2, query_row, &q, NULL);
    if (!rc && q.tail)
        for (uint64_t k = 0; k < T.t[q.ti].n; k++) {
            const tver *v = &T.t[q.ti].v[k];
            if (!v->stub && !v->redacted && v->begin <= N && N < v->end) q_take(&q, qs, v->v, v->commit);
        }
    char how[120];
    if (q.tail && present)
        snprintf(how, sizeof how, "lake snapshot at commit %llu + log tail %llu..%llu", (unsigned long long)S,
                 (unsigned long long)S + 1, (unsigned long long)N);
    else if (q.tail)
        snprintf(how, sizeof how, "the log, no lake snapshot yet");
    else
        snprintf(how, sizeof how, "lake snapshot");
    if (!rc && !digest) {
        printf("count=%llu", (unsigned long long)q.count);
        for (int c = 0; c < qs->ncols; c++)
            if ((qs->c[c].type == T_INT64 || qs->c[c].type == T_DECIMAL) && !(qs->c[c].flags & (F_PK | F_SUBJECT))) {
                printf(" sum(%s)=", qs->c[c].name);
                if (q.nsum[c]) print_i128(q.sum[c], qs->c[c].type == T_DECIMAL ? qs->c[c].scale : 0);
                else fputs("null", stdout);
            }
            else if (qs->c[c].type == T_FLOAT64 && !(qs->c[c].flags & (F_PK | F_SUBJECT))) {
                printf(" sum(%s)=", qs->c[c].name);
                if (q.nsum[c]) print_sum_f64(&q.fs[c]);
                else fputs("null", stdout);
            }
        printf(" (commit %llu: %s, from files only)\n", (unsigned long long)N, how);
    } else if (!rc) {
        uint8_t d[32];
        char dh[65];
        lt_digest(mt.alg, &q.dg, d);
        hex(d, 32, dh);
        printf("rows=%llu digest=%s (commit %llu: %s)\n", (unsigned long long)q.count, dh, (unsigned long long)N, how);
    }
    if (!rc && g_note[0]) printf("note: %s\n", g_note);
    manifest_free(&m);
    manifest_free(&m2);
    tail_free(&T);
    free(q.fargs);
    if (dirfd >= 0) close(dirfd);
    return rc;
}

/* imagedb-audit identity: the database, commit, head, state digest and view token at a read
 * point, from files only; the engine's SHOW IDENTITY must print the same token. */
static int cmd_identity(const char *dir, int argc, char **argv)
{
    bool has_at = false, lake_only = false;
    uint64_t at = 0;
    int rc = 0;
    for (int i = 0; i < argc && !rc; i++) {
        if (strcmp(argv[i], "--as-of") == 0 && i + 1 < argc) {
            has_at = true;
            if (!parse_seq(argv[++i], &at)) rc = fail("--as-of takes a commit number");
        } else if (strcmp(argv[i], "--lake") == 0) {
            lake_only = true;
        } else {
            rc = fail("unknown argument %s", argv[i]);
        }
    }
    int dirfd = rc ? -1 : open(dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (!rc && dirfd < 0) rc = fail("cannot open %s: %s", dir, strerror(errno));
    meta mt;
    state ds;
    memset(&ds, 0, sizeof ds);
    uint64_t S = 0;
    uint8_t mh[32] = {0};
    bool present = false;
    if (!rc) rc = read_meta(dirfd, &mt);
    if (!rc) rc = load_head(dirfd, &S, mh, &present);
    if (!rc) rc = load_durable(dirfd, &ds);
    if (!rc && lake_only && !present) rc = fail("no LAKE_HEAD: nothing has been checkpointed");
    uint64_t N = has_at ? at : lake_only ? S : ds.dur_present && ds.dur_seq > S ? ds.dur_seq : S;
    if (!rc && N < S) rc = fail("the identity is computed at or after the lake snapshot (commit %llu)", (unsigned long long)S);
    if (!rc && ds.dur_present && N > ds.dur_seq && N > S)
        rc = fail("commit %llu is past the durable watermark (commit %llu)", (unsigned long long)N, (unsigned long long)ds.dur_seq);
    manifest m, m2;
    memset(&m, 0, sizeof m);
    memset(&m2, 0, sizeof m2);
    ttail T;
    memset(&T, 0, sizeof T);
    if (!rc && present) rc = head_manifest(dirfd, mh, &m);
    if (!rc && present) rc = walk_lake(dirfd, mt.alg, &m2, NULL, NULL, NULL); /* the lanes against the rows */
    if (!rc) rc = tail_load(dirfd, &mt, &m, mh, N, &T);
    if (!rc) {
        a_sha256_ctx c;
        uint8_t b[16], tok[32], d[32];
        a_sha256_init(&c);
        a_sha256_update(&c, (const uint8_t *)"IMDBVIEW1", 9);
        a_sha256_update(&c, mt.db_id, 16);
        put64(b, N);
        a_sha256_update(&c, b, 8);
        a_sha256_update(&c, T.head, 32);
        put32(b, T.nt);
        a_sha256_update(&c, b, 4);
        for (uint32_t i = 0; i < T.nt; i++) {
            const ttab *t = &T.t[i];
            uint8_t lanes[2 * LANES];
            put32(b, i);
            put32(b + 4, (uint32_t)t->s->rawlen);
            a_sha256_update(&c, b, 8);
            a_sha256_update(&c, t->s->raw, t->s->rawlen);
            put64(b, t->horizon);
            put64(b + 8, t->live);
            a_sha256_update(&c, b, 16);
            lt_bytes(&t->d, lanes);
            a_sha256_update(&c, lanes, sizeof lanes);
        }
        a_sha256_final(&c, tok);
        lt_digest(mt.alg, &T.glob, d);
        char hid[33], hh[65], hd[65], ht[65];
        hex(mt.db_id, 16, hid);
        hex(T.head, 32, hh);
        hex(d, 32, hd);
        hex(tok, 32, ht);
        printf("db %s commit %llu head %s digest %s view_token %s (from files only)\n", hid, (unsigned long long)N, hh, hd,
               ht);
    }
    manifest_free(&m);
    manifest_free(&m2);
    tail_free(&T);
    if (dirfd >= 0) close(dirfd);
    return rc;
}

/* frames DIR: per log segment, its name, its frames' bytes and their SHA-256, in either format. Two
 * copies of a log agree here when they hold the same frames, whatever sectors each wrote them to
 * (design.md §1: a replica's log files follow its own syncs). */
static int cmd_frames(const char *dir)
{
    int dirfd = open(dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (dirfd < 0) return fail("cannot open %s", dir);
    int logfd;
    uint64_t *segs;
    size_t nsegs;
    int rc = list_segments(dirfd, &logfd, &segs, &nsegs);
    for (size_t si = 0; !rc && si < nsegs; si++) {
        char name[32];
        snprintf(name, sizeof name, "%020llu.ilg", (unsigned long long)segs[si]);
        uint8_t *log;
        size_t n;
        if ((rc = read_file(logfd, name, &log, &n, MAX_OBJECT))) break;
        if (tagged_seg(log, n)) {
            uint8_t *fr;
            size_t fl;
            int tail = untag(log, n, segs[si], name, &fr, &fl);
            free(log);
            if (tail < 0) {
                rc = -1;
                break;
            }
            log = fr;
            n = fl;
        }
        uint8_t h[32];
        a_sha256(log, n, h);
        printf("%s %zu ", name, n);
        for (int i = 0; i < 32; i++) printf("%02x", h[i]);
        printf("\n");
        free(log);
    }
    free(segs);
    if (logfd >= 0) close(logfd);
    close(dirfd);
    return rc;
}

int main(int argc, char **argv)
{
    if (argc < 3 || (strcmp(argv[1], "verify") != 0 && strcmp(argv[1], "count") != 0 && strcmp(argv[1], "digest") != 0 &&
                      strcmp(argv[1], "identity") != 0 && strcmp(argv[1], "frames") != 0)) {
        fputs("usage: imagedb-audit verify   <dir> [--anchor FILE]\n"
              "       imagedb-audit count    <dir> <table> [col=value]... [--as-of N | --lake]\n"
              "       imagedb-audit digest   <dir> <table> [col=value]... [--as-of N | --lake]\n"
              "       imagedb-audit identity <dir> [--as-of N | --lake]\n"
              "       imagedb-audit frames   <dir>   (each log segment's frames: their bytes and SHA-256)\n"
              "  (count, digest and identity answer at the latest durable commit unless told otherwise)\n",
              stderr);
        return 2;
    }
    int rc;
    if (strcmp(argv[1], "frames") == 0)
        rc = argc == 3 ? cmd_frames(argv[2]) : fail("frames takes a directory");
    else if (strcmp(argv[1], "verify") == 0)
        rc = argc == 3                                                ? cmd_verify(argv[2], NULL)
             : argc == 5 && strcmp(argv[3], "--anchor") == 0 ? cmd_verify(argv[2], argv[4])
                                                              : fail("verify takes a directory and an optional --anchor FILE");
    else
        for (int attempt = 1;; attempt++) {
            g_vanished = false;
            rc = strcmp(argv[1], "identity") == 0 ? cmd_identity(argv[2], argc - 3, argv + 3)
                                                    : cmd_query(strcmp(argv[1], "digest") == 0, argv[2], argc - 3, argv + 3);
            /* the generation it read went (GC, after newer publications): the current one, from the start */
            if (!rc || !g_vanished || attempt == 3) break;
            g_err[0] = g_note[0] = 0;
        }
    if (rc) {
        fprintf(stderr, "imagedb-audit: FAILED: %s\n", g_err[0] ? g_err : "verification failed");
        return 1;
    }
    return 0;
}
