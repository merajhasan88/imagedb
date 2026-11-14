/*
 * imdb-forge: builds hostile but checksum-consistent inputs for the rejection
 * tests, and seed corpora for the fuzzers. Test-only: unlike imagedb-audit it
 * may use the engine's code, because its job is to produce bytes, not to judge
 * them.
 *
 *   imdb-forge lie-payload <segment>       flip a row byte in the last frame with a payload, checksums
 *                                          recomputed (the payload is outside the signature)
 *   imdb-forge redact-all <segment>        replace every row payload by the redaction
 *                                          marker, keeping descriptors and headers
 *   imdb-forge lie-zonemap <dir>           F5: a segment's statistics lie (its first column's max), then re-hash
 *                                          the segment,
 *                                          the manifest and LAKE_HEAD so all names match
 *   imdb-forge lie-chunks <dir>            F5: a segment's imagedb.chunks names a chunk by another SHA-256, re-hash
 *                                          the lake and re-sign the log from the snapshot's commit
 *   imdb-forge lie-name <dir>              F5b: a segment, its content honest, named by its whole file's SHA-256
 *                                          (F5a's rule) instead of its tail's; the lake re-hashed and the log re-signed
 *   imdb-forge lie-format1 <dir>           F5b: a segment's imagedb.format "1" (F5a's), named by its tail; the
 *                                          lake re-hashed and the log re-signed
 *   imdb-forge lie-tombstone <dir>         move a purged tombstone to another subject, re-hash the
 *                                          lake and re-sign the log from the snapshot's commit
 *                                          (a malicious or buggy writer: everything consistent)
 *   imdb-forge lie-missing <dir>           F1: a row older than its segment's version reads another value than its
 *                                          missing one at a column added since (its statistics and chunk list
 *                                          made again: pq_patch),
 *                                          the lake re-hashed and the log re-signed from the snapshot's commit
 *   imdb-forge lie-stub <dir>              F5: an erased row (a stub) holds 1000 where a NOT NULL INT64 column's
 *                                          placeholder, zero, must stand (its page, statistics and chunk list
 *                                          made again: pq_patch), the lake re-hashed and the log re-signed
 *   imdb-forge lie-stub-null <dir>         F5: the same, a nullable INT64 column marked VALID at the stub, its value
 *                                          zero, so that only the VALID rule refuses it (the file
 *                                          decoded and written again: pq_mark)
 *   imdb-forge lie-stub-text|-bool|-cell <dir> F5: the same, a NOT NULL TEXT, BOOL or UUID holding a value at the stub
 *   imdb-forge durable-rewind <dir>        DURABLE as a writer that crashed during its last append
 *                                          left it (naming the commit before the last frame)
 *   imdb-forge rotate-foreign <dir>         append a key rotation signed by a key that is not the writer's
 *   imdb-forge promote-elsewhere <dir> <root-key>  append a promotion the root key certified for
 *                                          another history (another prev)
 *   imdb-forge writers-resign <dir>        alter WRITERS' first signature, CRC recomputed
 *   imdb-forge corpus <dir> <outdir>       fuzz seeds from a real database
 */
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "../../src/cpu.h"
#include "../../src/lake.h"
#include "../../src/parquet.h" /* F5: segments are Parquet files */
#include "../../src/log.h"
#include "../../src/db.h"
#include "../../src/db_internal.h" /* imdb_version_key: the forged row repeats a live one */
#include "../../src/logdir.h"
#include "../../src/repl.h"
#include "../../src/writer.h"

static uint8_t *slurp(const char *p, size_t *n)
{
    FILE *f = fopen(p, "rb");
    if (!f) {
        fprintf(stderr, "imdb-forge: %s: %s\n", p, strerror(errno));
        exit(1);
    }
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    uint8_t *b = malloc(sz > 0 ? (size_t)sz : 1);
    *n = fread(b, 1, sz > 0 ? (size_t)sz : 0, f);
    fclose(f);
    return b;
}

static void spit(const char *p, const uint8_t *b, size_t n)
{
    FILE *f = fopen(p, "wb");
    if (!f || fwrite(b, 1, n, f) != n || fclose(f) != 0) {
        fprintf(stderr, "imdb-forge: cannot write %s\n", p);
        exit(1);
    }
}

static void die(const char *what, const imdb_err *e)
{
    fprintf(stderr, "imdb-forge: %s: %s\n", what, e->msg);
    exit(1);
}

/* A log segment's frames, whichever format it is in (design.md §3): a tagged one compacted by the
 * engine's own scan (forge reads what it built; the verdict is the readers' to judge). */
static uint8_t *seg_read(const char *p, size_t *n)
{
    uint8_t *b = slurp(p, n);
    if (!imdb_tseg_is_tagged(b, *n)) return b;
    const char *base = strrchr(p, '/');
    uint64_t first = 0;
    if (!imdb_logseg_parse(base ? base + 1 : p, &first)) {
        fprintf(stderr, "imdb-forge: %s is not a log segment\n", p);
        exit(1);
    }
    imdb_tseg_end end;
    imdb_err e = {0};
    size_t len = 0;
    imdb_tseg_scan(b, *n, first, &len, &end, &e);
    *n = len;
    return b;
}

/* Frames written back as segment p in its format: tagged (one group, no fill, as redaction writes
 * one) when p is tagged or new, else as they are. */
static void seg_write(const char *p, const uint8_t *b, size_t n)
{
    uint8_t h[4] = {0};
    FILE *f = fopen(p, "rb");
    bool tagged = !f || (fread(h, 1, 4, f) == 4 && memcmp(h, "ILT1", 4) == 0);
    if (f) fclose(f);
    if (!tagged) {
        spit(p, b, n);
        return;
    }
    const char *base = strrchr(p, '/');
    uint64_t first = 0;
    if (!imdb_logseg_parse(base ? base + 1 : p, &first)) {
        fprintf(stderr, "imdb-forge: %s is not a log segment\n", p);
        exit(1);
    }
    imdb_buf o;
    imdb_buf_init(&o);
    imdb_tseg_build(first, b, n, &o);
    if (o.err) exit(1);
    spit(p, o.p, o.len);
    imdb_buf_free(&o);
}

/* A frame added to segment p where the writer would put it: a new segment is made tagged, an
 * untagged one appended to, a tagged one given it as a new group at its first fresh sector. */
static void seg_add(const char *p, const uint8_t *frame, size_t n)
{
    struct stat st;
    if (stat(p, &st) != 0) {
        seg_write(p, frame, n);
        return;
    }
    size_t raw = 0;
    uint8_t *b = slurp(p, &raw);
    int fd = open(p, O_WRONLY | O_CLOEXEC | (imdb_tseg_is_tagged(b, raw) ? 0 : O_APPEND));
    bool ok = fd >= 0;
    if (ok && !imdb_tseg_is_tagged(b, raw)) {
        ok = write(fd, frame, n) == (ssize_t)n;
    } else if (ok) {
        const char *base = strrchr(p, '/');
        uint64_t first = 0;
        imdb_tseg_end end;
        imdb_err e = {0};
        size_t len = 0;
        ok = imdb_logseg_parse(base ? base + 1 : p, &first);
        if (ok) imdb_tseg_scan(b, raw, first, &len, &end, &e);
        imdb_tgroup g;
        imdb_tgroup_begin(&g, end.last + 1, end.next);
        imdb_buf o;
        imdb_buf_init(&o);
        imdb_tgroup_put(&g, frame, n, &o);
        ok = ok && !o.err && pwrite(fd, o.p, o.len, (off_t)(end.next * IMDB_TSEG_SECTOR)) == (ssize_t)o.len;
        imdb_buf_free(&o);
    }
    if (fd >= 0) close(fd);
    free(b);
    if (!ok) {
        fprintf(stderr, "imdb-forge: append to %s failed\n", p);
        exit(1);
    }
}

/* Calls fn(frame, len) for every complete frame. */
static void each_frame(const uint8_t *log, size_t n, void (*fn)(void *, const uint8_t *, size_t), void *ctx)
{
    size_t off = 0;
    for (;;) {
        size_t fl;
        imdb_err e = {0};
        if (imdb_frame_scan(log, n, off, &fl, &e) != IMDB_SCAN_FRAME) break;
        fn(ctx, log + off, fl);
        off += fl;
    }
}

static void redact_one(void *ctx, const uint8_t *f, size_t fl)
{
    imdb_buf *out = ctx;
    imdb_commit_rec c;
    imdb_err e = {0};
    if (imdb_frame_decode_body(f + IMDB_FRAME_HDR, fl - IMDB_FRAME_HDR, &c, &e)) die("decode", &e);
    bool any = false;
    for (uint32_t i = 0; i < c.nops; i++)
        if (imdb_op_is_row(c.ops[i].code)) {
            c.ops[i].pkind = IMDB_PAYLOAD_REDACTED;
            any = true;
        }
    if (any) {
        imdb_buf pay;
        imdb_buf_init(&pay);
        imdb_commit_encode_payload(&c, &pay);
        imdb_frame_build(f + IMDB_FRAME_HDR + IMDB_BODY_DESC, c.hlen, c.seq, c.hash, c.sig, pay.p, pay.len, out);
        imdb_buf_free(&pay);
    } else {
        imdb_buf_put(out, f, fl);
    }
    imdb_commit_free(&c);
}

/* F2b-2's fk-erase lies: the payload of one version (an INSERT's vid, an UPDATE's new_vid) redacted, the rest as it was,
 * as the writer's redaction leaves a segment after an ERASE */
struct redact_ver {
    imdb_buf *out;
    uint32_t table;
    uint64_t vid;
    int hits;
};

static void redact_ver_one(void *ctx, const uint8_t *f, size_t fl)
{
    struct redact_ver *x = ctx;
    imdb_commit_rec c;
    imdb_err e = {0};
    if (imdb_frame_decode_body(f + IMDB_FRAME_HDR, fl - IMDB_FRAME_HDR, &c, &e)) die("decode", &e);
    bool any = false;
    for (uint32_t i = 0; i < c.nops; i++) {
        imdb_op *o = &c.ops[i];
        if (!imdb_op_is_row(o->code) || o->pkind != IMDB_PAYLOAD_ROW || o->table != x->table) continue;
        if ((o->code == IMDB_OP_INSERT ? o->vid : o->new_vid) != x->vid) continue;
        o->pkind = IMDB_PAYLOAD_REDACTED;
        any = true;
        x->hits++;
    }
    if (any) {
        imdb_buf pay;
        imdb_buf_init(&pay);
        imdb_commit_encode_payload(&c, &pay);
        imdb_frame_build(f + IMDB_FRAME_HDR + IMDB_BODY_DESC, c.hlen, c.seq, c.hash, c.sig, pay.p, pay.len, x->out);
        imdb_buf_free(&pay);
    } else {
        imdb_buf_put(x->out, f, fl);
    }
    imdb_commit_free(&c);
}

static bool g_whole_name; /* F5b: lie-name: a segment named by its whole file, F5a's rule */

static int obj_rename(int ofd, const char *old, const uint8_t *b, size_t n, const char *ext, char *newname)
{
    uint8_t h[32];
    imdb_err ne = {0};
    if (!strcmp(ext, ".seg") && !g_whole_name) { /* F5b: a segment is named by its tail */
        if (imdb_pq_name(b, n, h, &ne)) die("segment", &ne);
    } else {
        imdb_sha256(b, n, h);
    }
    imdb_hex(h, 32, newname);
    strcat(newname, ext);
    if (unlinkat(ofd, old, 0) != 0) return -1;
    int fd = openat(ofd, newname, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0 || write(fd, b, n) != (ssize_t)n) return -1;
    close(fd);
    return 0;
}

/* F5: segment file f (len bytes, of version v) with user column c's row `row` set to val (w bytes): in its page, and in
 * its footer's statistics and chunk list made again (stats_only: in the statistics alone, the page as it was), so
 * that only the rule the value breaks refuses it. The new file (malloc'd), its length at *outlen */
static uint8_t *pq_patch(const imdb_sver *v, const uint8_t *f, size_t len, uint32_t c, uint32_t row, const uint8_t *val,
                         unsigned w, bool stats_only, size_t *outlen)
{
    imdb_err e = {0};
    uint8_t *b = malloc(len);
    memcpy(b, f, len);
    pq_footer ft;
    pq_col sh[PQ_MAX_COLUMNS];
    pq_rcol r[PQ_MAX_COLUMNS];
    imdb_seg_shapes(v, sh);
    uint32_t nc = IMDB_SEG_NSYS + v->s.ncols, ci = IMDB_SEG_NSYS + c;
    if (imdb_pq_footer(b, len, &ft, &e) || imdb_pq_read(b, len, &ft, sh, nc, r, &e)) die("segment", &e);
    pq_col cols[PQ_MAX_COLUMNS];
    for (uint32_t k = 0; k < nc; k++) cols[k] = r[k].c;
    uint8_t *copy = malloc((size_t)ft.nrows * w);
    memcpy(copy, r[ci].c.fixed, (size_t)ft.nrows * w); /* before the page changes: a REQUIRED column's view is b's */
    memcpy(copy + (size_t)row * w, val, w);
    cols[ci].fixed = copy; /* what the statistics are made from */
    if (!stats_only) {
        size_t at;
        if (imdb_pq_value_at(b, len, &ft, ci, &sh[ci], r[ci].c.present, row, &at, &e)) die("segment", &e);
        memcpy(b + at, val, w);
    }
    char list[PQ_MAX_COLUMNS * 112];
    size_t ll = 0;
    for (uint32_t k = 0; k < nc; k++) { /* imagedb.chunks again: each chunk's SHA-256 as it now is */
        uint8_t h[32];
        char hx[65];
        imdb_sha256(b + ft.off[k], ft.size[k], h);
        imdb_hex(h, 32, hx);
        ll += (size_t)snprintf(list + ll, sizeof list - ll, "%llu,%llu,%s;", (unsigned long long)ft.off[k],
                               (unsigned long long)ft.size[k], hx);
    }
    const uint8_t *vals[PQ_MAX_KV + 1];
    uint32_t vlen[PQ_MAX_KV + 1];
    memcpy(vals, ft.val, sizeof vals);
    memcpy(vlen, ft.vlen, sizeof vlen);
    vals[0] = (const uint8_t *)list;
    vlen[0] = (uint32_t)ll;
    imdb_buf out;
    imdb_buf_init(&out);
    imdb_buf_put(&out, b, ft.meta_at);
    size_t meta = out.len;
    imdb_pq_footer_encode(&out, cols, nc, ft.nrows, ft.off, ft.size, ft.key, ft.klen, vals, vlen, ft.nkv);
    imdb_buf_put_u32(&out, (uint32_t)(out.len - meta));
    imdb_buf_put(&out, "PAR1", 4);
    if (imdb_buf_check(&out, &e)) die("segment", &e);
    uint8_t *res = malloc(out.len);
    memcpy(res, out.p, out.len);
    *outlen = out.len;
    imdb_buf_free(&out);
    imdb_pq_free_read(r, nc);
    free(copy);
    free(b);
    return res;
}

/* F5: segment file f (len bytes, of version v) with user column c's row `row` given a value by kind: 0 an OPTIONAL INT64
 * marked present and holding val; 1 a REQUIRED BYTE_ARRAY holding a byte ("q"); 2 a REQUIRED BOOLEAN true; 3 a REQUIRED
 * FIXED_LEN_BYTE_ARRAY's first byte 1. The file decoded, that column changed, and written again by imdb_pq_write (its
 * levels, statistics and chunk list made for it, so that only the rule the value breaks refuses it). The new file
 * (malloc'd), its length at *outlen */
static uint8_t *pq_mark(const imdb_sver *v, const uint8_t *f, size_t len, uint32_t c, uint32_t row, int kind, int64_t val,
                        size_t *outlen)
{
    imdb_err e = {0};
    pq_footer ft;
    pq_col sh[PQ_MAX_COLUMNS];
    pq_rcol r[PQ_MAX_COLUMNS];
    imdb_seg_shapes(v, sh);
    uint32_t nc = IMDB_SEG_NSYS + v->s.ncols, ci = IMDB_SEG_NSYS + c;
    if (imdb_pq_footer(f, len, &ft, &e) || imdb_pq_read(f, len, &ft, sh, nc, r, &e)) die("segment", &e);
    static const int want[4] = {PQ_INT64, PQ_BYTE_ARRAY, PQ_BOOLEAN, PQ_FLBA};
    if (kind < 0 || kind > 3 || (int)sh[ci].phys != want[kind] || (kind == 0) != (r[ci].c.present != NULL)) {
        fputs("imdb-forge: pq_mark: the column is not of its kind\n", stderr);
        exit(1);
    }
    pq_col cols[PQ_MAX_COLUMNS];
    for (uint32_t k = 0; k < nc; k++) cols[k] = r[k].c;
    uint64_t n = ft.nrows;
    uint8_t *pr = NULL, *fx = NULL, *dt = NULL;
    uint64_t *of = NULL;
    if (kind == 0) {
        pr = calloc((n + 63) / 64 * 8, 1);
        fx = malloc(n * 8);
        memcpy(pr, cols[ci].present, (n + 7) / 8);
        pr[row >> 3] |= (uint8_t)(1u << (row & 7));
        memcpy(fx, cols[ci].fixed, n * 8);
        imdb_le64(fx + 8 * (size_t)row, (uint64_t)val);
        cols[ci].present = pr;
        cols[ci].fixed = fx;
    } else if (kind == 1) {
        of = malloc((n + 1) * sizeof *of);
        dt = malloc(cols[ci].off[n] + 1);
        uint64_t at = 0;
        for (uint64_t i = 0; i < n; i++) {
            of[i] = at;
            memcpy(dt + at, cols[ci].data + cols[ci].off[i], cols[ci].off[i + 1] - cols[ci].off[i]);
            at += cols[ci].off[i + 1] - cols[ci].off[i];
            if (i == row) dt[at++] = 'q';
        }
        of[n] = at;
        cols[ci].off = of;
        cols[ci].data = dt;
    } else {
        size_t w = kind == 2 ? 1 : (size_t)sh[ci].type_length;
        fx = malloc(n * w);
        memcpy(fx, cols[ci].fixed, n * w);
        fx[(size_t)row * w] = 1;
        cols[ci].fixed = fx;
    }
    static char kb[PQ_MAX_KV][64], vb[PQ_MAX_KV][256]; /* the pairs after imagedb.chunks (the writer makes that one) */
    pq_kv kv[PQ_MAX_KV];
    for (uint32_t k = 1; k < ft.nkv; k++) {
        snprintf(kb[k - 1], sizeof kb[k - 1], "%.*s", (int)ft.klen[k], (const char *)ft.key[k]);
        snprintf(vb[k - 1], sizeof vb[k - 1], "%.*s", (int)ft.vlen[k], (const char *)ft.val[k]);
        kv[k - 1].key = kb[k - 1];
        kv[k - 1].value = vb[k - 1];
    }
    imdb_buf out;
    imdb_buf_init(&out);
    if (imdb_pq_write(cols, nc, ft.nrows, kv, ft.nkv - 1, &out, &e) || imdb_buf_check(&out, &e)) die("segment", &e);
    uint8_t *res = malloc(out.len);
    memcpy(res, out.p, out.len);
    *outlen = out.len;
    imdb_buf_free(&out);
    free(pr);
    free(fx);
    free(dt);
    free(of);
    imdb_pq_free_read(r, nc);
    return res;
}

/* lie_row's stub modes: the column a mode wants at a stub (1 a NOT NULL INT64, 2 a nullable INT64, 3 a NOT NULL TEXT,
 * 4 a NOT NULL BOOL, 5 a NOT NULL UUID: a 16-byte cell) */
static bool stub_col(const imdb_sver *gv, const imdb_segimg *gi, uint16_t c, int mode)
{
    int t = gv->s.cols[c].type;
    bool req = !gi->ocol[c].valid;
    switch (mode) {
    case 1: return t == IMDB_T_INT64 && gi->ocol[c].i64 && req;
    case 2: return t == IMDB_T_INT64 && gi->ocol[c].i64 && !req;
    case 3: return t == IMDB_T_TEXT && req;
    case 4: return t == IMDB_T_BOOL && req;
    case 5: return t == IMDB_T_UUID && req;
    default: return false;
    }
}

/* F5: the statistics of a segment's first column lie (its max 999999 where its page holds less), the file otherwise the
 * writer's (its chunk list made again); segment, manifest and LAKE_HEAD re-hashed, the log not re-signed: the reader's
 * footer rule refuses it (before F5, the zone map's lie: zone maps live in memory now, made at the load) */
static void lie_zonemap(const char *dir)
{
    char p[1200];
    snprintf(p, sizeof p, "%s/LAKE_HEAD", dir);
    size_t hn;
    uint8_t *head = slurp(p, &hn);
    char *mpos = strstr((char *)head, "manifest ");
    if (!mpos) exit(1);
    char mname[80];
    memcpy(mname, mpos + 9, 64);
    strcpy(mname + 64, ".man");
    snprintf(p, sizeof p, "%s/objects", dir);
    int ofd = open(p, O_RDONLY | O_DIRECTORY);
    snprintf(p, sizeof p, "%s/objects/%s", dir, mname);
    size_t mn;
    uint8_t *man = slurp(p, &mn);
    imdb_manifest m;
    imdb_err e = {0};
    if (imdb_manifest_parse(man, mn, &m, &e)) die("manifest", &e);
    const imdb_manifest_tab *mt = NULL;
    for (uint32_t ti = 0; ti < m.nt && !mt; ti++)
        if (m.t[ti].nseg) mt = &m.t[ti];
    if (!mt) exit(1);
    char sname[80];
    imdb_hex(mt->seg[0].seg, 32, sname);
    strcat(sname, ".seg");
    snprintf(p, sizeof p, "%s/objects/%s", dir, sname);
    size_t sn;
    uint8_t *raw = slurp(p, &sn);
    uint8_t *al = aligned_alloc(32, (sn + 31) & ~(size_t)31);
    memcpy(al, raw, sn);
    imdb_segment *g;
    if (imdb_segment_parse_h(&mt->hist, al, sn, NULL, &g, &e)) die("segment", &e);
    const imdb_sver *gv = &mt->hist.vers[g->gver];
    imdb_segment_free(g);
    uint8_t lie[8];
    imdb_le64(lie, 999999);
    size_t nl;
    uint8_t *ns = pq_patch(gv, raw, sn, 0, 0, lie, 8, true, &nl);
    char newseg[300], newman[300];
    if (obj_rename(ofd, sname, ns, nl, ".seg", newseg)) exit(1);
    uint8_t oldh[32], newh[32];
    imdb_unhex(sname, 64, oldh, 32);
    imdb_unhex(newseg, 64, newh, 32);
    for (size_t i = 0; i + 32 <= mn; i++)
        if (memcmp(man + i, oldh, 32) == 0) memcpy(man + i, newh, 32);
    if (obj_rename(ofd, mname, man, mn, ".man", newman)) exit(1);
    memcpy(mpos + 9, newman, 64);
    snprintf(p, sizeof p, "%s/LAKE_HEAD", dir);
    spit(p, head, hn);
    imdb_manifest_free(&m);
    close(ofd);
    free(ns);
    free(raw);
    free(head);
    free(man);
}

/* Re-chains and re-signs the log from commit `from` on with signing.key: every
 * later commit gets its predecessor's new hash. `patch` edits commit `from`
 * (it is called once, before that commit is re-encoded). A writer that holds
 * the key can always do this; the tests use it to model a malicious or buggy
 * writer whose log is internally consistent. */
static void resign_from(const char *dir, uint64_t from, void (*patch)(imdb_commit_rec *, void *), void *ctx)
{
    char p[1200];
    snprintf(p, sizeof p, "%s/signing.key", dir);
    size_t kn;
    uint8_t *seed = slurp(p, &kn);
    if (kn != IMDB_SEED_LEN) exit(1);
    imdb_signer sg;
    imdb_signer_init(&sg, seed);
    free(seed);
    /* the writer's watermark names a commit hash too; a writer re-signing its log rewrites it */
    int dfd = open(dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    imdb_durable w;
    bool have_w = false;
    imdb_err we = {0};
    if (dfd < 0 || imdb_durable_read(dfd, &w, &have_w, &we)) die("DURABLE", &we);
    close(dfd);
    snprintf(p, sizeof p, "%s/log", dir);
    struct dirent **ents;
    int ne = scandir(p, &ents, NULL, alphasort);
    uint8_t prev[32];
    bool chained = false;
    for (int i = 0; i < ne; i++) {
        if (ents[i]->d_name[0] == '.') {
            free(ents[i]);
            continue;
        }
        char q[1600];
        snprintf(q, sizeof q, "%s/%s", p, ents[i]->d_name);
        free(ents[i]);
        size_t n;
        uint8_t *log = seg_read(q, &n);
        imdb_buf out;
        imdb_buf_init(&out);
        bool changed = false;
        for (size_t off = 0;;) {
            size_t fl;
            imdb_err e = {0};
            if (imdb_frame_scan(log, n, off, &fl, &e) != IMDB_SCAN_FRAME) break;
            const uint8_t *f = log + off;
            off += fl;
            imdb_commit_rec c;
            if (imdb_frame_decode_body(f + IMDB_FRAME_HDR, fl - IMDB_FRAME_HDR, &c, &e)) die("decode", &e);
            if (c.seq < from) {
                imdb_buf_put(&out, f, fl);
                imdb_commit_free(&c);
                continue;
            }
            imdb_buf h;
            imdb_buf_init(&h);
            imdb_commit_encode_header(&c, &h);
            if (h.len != c.hlen || memcmp(h.p, f + IMDB_FRAME_HDR + IMDB_BODY_DESC, h.len) != 0) {
                fputs("imdb-forge: header does not re-encode to itself\n", stderr);
                exit(1);
            }
            if (c.seq == from) patch(&c, ctx);
            if (chained) memcpy(c.prev, prev, 32);
            imdb_buf_free(&h);
            imdb_buf_init(&h);
            imdb_commit_encode_header(&c, &h);
            uint8_t hash[32], msg[IMDB_SIGMSG_LEN], sig[IMDB_SIG_LEN];
            imdb_commit_hash(h.p, h.len, hash);
            imdb_commit_sigmsg(c.seq, (uint32_t)h.len, hash, msg);
            imdb_sign(&sg, msg, sizeof msg, sig);
            imdb_buf pay;
            imdb_buf_init(&pay);
            imdb_commit_encode_payload(&c, &pay);
            imdb_frame_build(h.p, h.len, c.seq, hash, sig, pay.p, pay.len, &out);
            imdb_buf_free(&pay);
            imdb_buf_free(&h);
            memcpy(prev, hash, 32);
            if (have_w && c.seq == w.seq) memcpy(w.head, hash, 32);
            chained = changed = true;
            imdb_commit_free(&c);
        }
        if (changed) seg_write(q, out.p, out.len);
        imdb_buf_free(&out);
        free(log);
    }
    if (ne >= 0) free(ents);
    if (have_w && w.seq >= from) {
        uint8_t wb[IMDB_DURABLE_LEN];
        imdb_durable_encode(&w, wb);
        snprintf(p, sizeof p, "%s/%s", dir, IMDB_DURABLE_NAME);
        spit(p, wb, sizeof wb);
    }
    imdb_signer_wipe(&sg);
}

typedef struct man_swap {
    uint8_t old[32], new_[32];
} man_swap;

/* alg-flip: the commit names the other digest algorithm, everything else as it was (its state digest
 * is still its database's algorithm's), re-signed by the writer: only the algorithm rule refuses it */
static void flip_alg(imdb_commit_rec *c, void *ctx)
{
    (void)ctx;
    c->alg = c->alg == IMDB_DIGEST_ALG_LTHASH16 ? IMDB_DIGEST_ALG_LTHASH16_TREE : IMDB_DIGEST_ALG_LTHASH16;
}

static void swap_manifest(imdb_commit_rec *c, void *ctx)
{
    man_swap *s = ctx;
    for (uint32_t i = 0; i < c->nops; i++)
        if (imdb_op_publishes_manifest(c->ops[i].code) && memcmp(c->ops[i].manifest, s->old, 32) == 0)
            memcpy(c->ops[i].manifest, s->new_, 32);
}

static void replace_hash(uint8_t *b, size_t n, const uint8_t old[32], const uint8_t new_[32])
{
    for (size_t i = 0; i + 32 <= n; i++)
        if (memcmp(b + i, old, 32) == 0) memcpy(b + i, new_, 32);
}

/* A purged tombstone moved to another subject: segment, its DV, the manifest
 * and LAKE_HEAD re-hashed, and the log re-signed from the snapshot's commit so
 * that it records the new manifest. */
static void lie_tombstone(const char *dir)
{
    char p[1200];
    snprintf(p, sizeof p, "%s/LAKE_HEAD", dir);
    size_t hn;
    uint8_t *head = slurp(p, &hn);
    char *mpos = strstr((char *)head, "manifest ");
    unsigned long long S = 0;
    if (!mpos || sscanf((char *)head, "imagedb-lake 1\nseq %llu", &S) != 1) exit(1);
    char mname[80];
    memcpy(mname, mpos + 9, 64);
    strcpy(mname + 64, ".man");
    snprintf(p, sizeof p, "%s/objects", dir);
    int ofd = open(p, O_RDONLY | O_DIRECTORY);
    snprintf(p, sizeof p, "%s/objects/%s", dir, mname);
    size_t mn;
    uint8_t *man = slurp(p, &mn);
    imdb_manifest m;
    imdb_err e = {0};
    if (imdb_manifest_parse(man, mn, &m, &e)) die("manifest", &e);
    bool done = false;
    for (uint32_t ti = 0; ti < m.nt && !done; ti++) {
        const imdb_manifest_tab *mt = &m.t[ti];
        if (mt->s.subject < 0 || mt->s.cols[mt->s.subject].type != IMDB_T_INT64) continue;
        for (uint32_t k = 0; k < mt->nseg && !done; k++) {
            char sname[80];
            imdb_hex(mt->seg[k].seg, 32, sname);
            strcat(sname, ".seg");
            snprintf(p, sizeof p, "%s/objects/%s", dir, sname);
            size_t sn;
            uint8_t *raw = slurp(p, &sn);
            uint8_t *al = aligned_alloc(32, (sn + 31) & ~(size_t)31);
            memcpy(al, raw, sn);
            imdb_segment *g;
            if (imdb_segment_parse_h(&mt->hist, al, sn, NULL, &g, &e)) die("segment", &e); /* F1: by its version */
            const imdb_segimg *gi = imdb_seg_pin(NULL, g, &e); /* a parse of its own: apart, resident */
            uint32_t row = UINT32_MAX;
            const imdb_sver *gv = &mt->hist.vers[gi->gver];
            int sc = gv->s.subject; /* the SUBJECT in the segment's own version */
            int64_t old = 0;
            for (uint32_t r = 0; r < g->nrows && row == UINT32_MAX; r++)
                if (gi->flags[r] == IMDB_SEG_PURGED)
                    row = r, old = gi->ocol[sc].i64[r];
            imdb_segment_free(g);
            if (row == UINT32_MAX) {
                free(raw);
                continue;
            }
            uint8_t sv[8]; /* another subject: its page, statistics and chunk list (pq_patch) */
            imdb_le64(sv, (uint64_t)(old + 1000));
            size_t nl;
            uint8_t *ns = pq_patch(gv, raw, sn, (uint32_t)sc, row, sv, 8, false, &nl);
            char nseg[80], nman[80];
            if (obj_rename(ofd, sname, ns, nl, ".seg", nseg)) exit(1);
            free(ns);
            uint8_t nsh[32];
            imdb_unhex(nseg, 64, nsh, 32);
            if (memcmp(mt->seg[k].dv, (uint8_t[32]){0}, 32) != 0) { /* the DV names its segment */
                char dname[80], ndv[80];
                imdb_hex(mt->seg[k].dv, 32, dname);
                strcat(dname, ".dv");
                snprintf(p, sizeof p, "%s/objects/%s", dir, dname);
                size_t dn;
                uint8_t *dv = slurp(p, &dn);
                replace_hash(dv, dn, mt->seg[k].seg, nsh);
                if (obj_rename(ofd, dname, dv, dn, ".dv", ndv)) exit(1);
                uint8_t ndh[32];
                imdb_unhex(ndv, 64, ndh, 32);
                replace_hash(man, mn, mt->seg[k].dv, ndh);
                free(dv);
            }
            replace_hash(man, mn, mt->seg[k].seg, nsh);
            if (obj_rename(ofd, mname, man, mn, ".man", nman)) exit(1);
            man_swap sw;
            imdb_unhex(mname, 64, sw.old, 32);
            imdb_unhex(nman, 64, sw.new_, 32);
            memcpy(mpos + 9, nman, 64);
            snprintf(p, sizeof p, "%s/LAKE_HEAD", dir);
            spit(p, head, hn);
            resign_from(dir, S, swap_manifest, &sw);
            free(raw);
            done = true;
        }
    }
    if (!done) {
        fputs("imdb-forge: no purged tombstone with an INT64 subject\n", stderr);
        exit(1);
    }
    imdb_manifest_free(&m);
    close(ofd);
    free(man);
    free(head);
}

/* A row's value where no commitment covers it, the segment's page, statistics and chunk list made again for it so that
 * only the rule refuses it; segment, its DV, the manifest and LAKE_HEAD re-hashed, the log re-signed from the snapshot's
 * commit. F1 (stub false): a row of an older version than its segment holds, at a column added after it, another value
 * than its missing one (the readers would read it): wants an INT64 column added by an ALTER and a segment built after it
 * holding a row from before it. F5 (stub true): an erased row (a stub keeps vid, begin and commitment alone) holding a
 * value where a NOT NULL INT64 column's placeholder, zero, must stand: wants an ERASE's segment. */
static void lie_row(const char *dir, int mode) /* 0 F1 missing; F5 stubs: 1 NOT NULL INT64, 2 nullable INT64, 3 TEXT, 4 BOOL, 5 UUID */
{
    char p[1200];
    snprintf(p, sizeof p, "%s/LAKE_HEAD", dir);
    size_t hn;
    uint8_t *head = slurp(p, &hn);
    char *mpos = strstr((char *)head, "manifest ");
    unsigned long long S = 0;
    if (!mpos || sscanf((char *)head, "imagedb-lake 1\nseq %llu", &S) != 1) exit(1);
    char mname[80];
    memcpy(mname, mpos + 9, 64);
    strcpy(mname + 64, ".man");
    snprintf(p, sizeof p, "%s/objects", dir);
    int ofd = open(p, O_RDONLY | O_DIRECTORY);
    snprintf(p, sizeof p, "%s/objects/%s", dir, mname);
    size_t mn;
    uint8_t *man = slurp(p, &mn);
    imdb_manifest m;
    imdb_err e = {0};
    if (imdb_manifest_parse(man, mn, &m, &e)) die("manifest", &e);
    bool done = false;
    for (uint32_t ti = 0; ti < m.nt && !done; ti++) {
        const imdb_manifest_tab *mt = &m.t[ti];
        if (!mode && mt->hist.nvers < 2) continue;
        for (uint32_t k = 0; k < mt->nseg && !done; k++) {
            char sname[80];
            imdb_hex(mt->seg[k].seg, 32, sname);
            strcat(sname, ".seg");
            snprintf(p, sizeof p, "%s/objects/%s", dir, sname);
            size_t sn;
            uint8_t *raw = slurp(p, &sn);
            uint8_t *al = aligned_alloc(32, (sn + 31) & ~(size_t)31);
            memcpy(al, raw, sn);
            imdb_segment *g;
            if (imdb_segment_parse_h(&mt->hist, al, sn, NULL, &g, &e)) die("segment", &e);
            const imdb_segimg *gi = imdb_seg_pin(NULL, g, &e); /* a parse of its own: apart, resident */
            const imdb_sver *gv = &mt->hist.vers[gi->gver];
            uint32_t row = UINT32_MAX;
            int64_t old = 0;
            uint32_t col = 0;
            for (uint32_t r = 0; mode && r < g->nrows && row == UINT32_MAX; r++)
                for (uint16_t c = 0; (gi->flags[r] & IMDB_SEG_STUB) && c < gv->s.ncols && row == UINT32_MAX; c++)
                    if (stub_col(gv, gi, c, mode)) {
                        row = r, old = gi->ocol[c].i64 ? gi->ocol[c].i64[r] : 0; /* the placeholder, 0: it becomes 1000 */
                        col = c;
                    }
            for (uint32_t r = 0; !mode && r < g->nrows && row == UINT32_MAX; r++) {
                const imdb_sver *rv = imdb_hist_at(&mt->hist, gi->begin[r]);
                for (uint16_t c = 0; !gi->flags[r] && c < gv->s.ncols && row == UINT32_MAX; c++)
                    if (rv->at[gv->pos[c]] < 0 && gv->s.cols[c].type == IMDB_T_INT64 && gi->ocol[c].i64 &&
                        (!gi->ocol[c].valid || (gi->ocol[c].valid[r >> 3] >> (r & 7) & 1))) {
                        row = r, old = gi->ocol[c].i64[r];
                        col = c;
                    }
            }
            if (row == UINT32_MAX) {
                imdb_segment_free(g);
                free(raw);
                continue;
            }
            uint8_t mv[8]; /* another value than its missing one: its page, statistics and chunk list (pq_patch) */
            imdb_le64(mv, (uint64_t)(old + 1000));
            size_t nl;
            uint8_t *ns = mode >= 2 ? pq_mark(gv, raw, sn, col, row, mode - 2, mode == 2 ? 0 : old + 1000, &nl) : pq_patch(gv, raw, sn, col, row, mv, 8, false, &nl);
            imdb_segment_free(g);
            char nseg[80], nman[80];
            if (obj_rename(ofd, sname, ns, nl, ".seg", nseg)) exit(1);
            free(ns);
            uint8_t nsh[32];
            imdb_unhex(nseg, 64, nsh, 32);
            if (memcmp(mt->seg[k].dv, (uint8_t[32]){0}, 32) != 0) { /* the DV names its segment */
                char dname[80], ndv[80];
                imdb_hex(mt->seg[k].dv, 32, dname);
                strcat(dname, ".dv");
                snprintf(p, sizeof p, "%s/objects/%s", dir, dname);
                size_t dn;
                uint8_t *dv = slurp(p, &dn);
                replace_hash(dv, dn, mt->seg[k].seg, nsh);
                if (obj_rename(ofd, dname, dv, dn, ".dv", ndv)) exit(1);
                uint8_t ndh[32];
                imdb_unhex(ndv, 64, ndh, 32);
                replace_hash(man, mn, mt->seg[k].dv, ndh);
                free(dv);
            }
            replace_hash(man, mn, mt->seg[k].seg, nsh);
            if (obj_rename(ofd, mname, man, mn, ".man", nman)) exit(1);
            man_swap sw;
            imdb_unhex(mname, 64, sw.old, 32);
            imdb_unhex(nman, 64, sw.new_, 32);
            memcpy(mpos + 9, nman, 64);
            snprintf(p, sizeof p, "%s/LAKE_HEAD", dir);
            spit(p, head, hn);
            resign_from(dir, S, swap_manifest, &sw);
            free(raw);
            done = true;
        }
    }
    if (!done) {
        static const char *const none[] = {"no segment row of an older version under an added INT64 column",
                                           "no erased row in a segment with a NOT NULL INT64 column",
                                           "no erased row in a segment with a nullable INT64 column",
                                           "no erased row in a segment with a NOT NULL TEXT column",
                                           "no erased row in a segment with a NOT NULL BOOL column",
                                           "no erased row in a segment with a NOT NULL UUID column"};
        fprintf(stderr, "imdb-forge: %s\n", none[mode]);
        exit(1);
    }
    imdb_manifest_free(&m);
    close(ofd);
    free(man);
    free(head);
}

/* F5: a segment whose imagedb.chunks names one chunk by another SHA-256 (a hex digit changed: the file's own hash, its
 * name, right again), its DV, the manifest and LAKE_HEAD re-hashed and the log re-signed from the snapshot's commit:
 * a load reads the file whole by its name and hashes no chunk, so VERIFY and the auditor alone refuse it */
/* mode 0 (lie-chunks): the last chunk's hash in imagedb.chunks changed; 1 (lie-name, F5b): the content kept, the
 * segment named by its whole file's hash; 2 (lie-format1, F5b): its imagedb.format "1", named by its tail */
static void lie_chunks(const char *dir, int mode)
{
    char p[1200];
    snprintf(p, sizeof p, "%s/LAKE_HEAD", dir);
    size_t hn;
    uint8_t *head = slurp(p, &hn);
    char *mpos = strstr((char *)head, "manifest ");
    unsigned long long S = 0;
    if (!mpos || sscanf((char *)head, "imagedb-lake 1\nseq %llu", &S) != 1) exit(1);
    char mname[80];
    memcpy(mname, mpos + 9, 64);
    strcpy(mname + 64, ".man");
    snprintf(p, sizeof p, "%s/objects", dir);
    int ofd = open(p, O_RDONLY | O_DIRECTORY);
    snprintf(p, sizeof p, "%s/objects/%s", dir, mname);
    size_t mn;
    uint8_t *man = slurp(p, &mn);
    imdb_manifest m;
    imdb_err e = {0};
    if (imdb_manifest_parse(man, mn, &m, &e)) die("manifest", &e);
    const imdb_manifest_tab *mt = NULL;
    for (uint32_t ti = 0; ti < m.nt && !mt; ti++)
        if (m.t[ti].nseg) mt = &m.t[ti];
    if (!mt) exit(1);
    char sname[80];
    imdb_hex(mt->seg[0].seg, 32, sname);
    strcat(sname, ".seg");
    snprintf(p, sizeof p, "%s/objects/%s", dir, sname);
    size_t sn;
    uint8_t *raw = slurp(p, &sn);
    pq_footer ft;
    if (imdb_pq_footer(raw, sn, &ft, &e)) die("segment", &e);
    uint8_t *d = raw + (ft.chunk_hex[ft.ncols - 1] - raw); /* the last chunk's hash, its first digit */
    if (mode == 0) *d = *d == '0' ? '1' : '0';
    if (mode == 2) {
        uint32_t fl;
        const uint8_t *fv = imdb_pq_kv(&ft, "imagedb.format", &fl);
        if (!fv || fl != 1) exit(1);
        raw[fv - raw] = '1';
    }
    char nseg[80], nman[80];
    g_whole_name = mode == 1;
    if (obj_rename(ofd, sname, raw, sn, ".seg", nseg)) exit(1);
    g_whole_name = false;
    uint8_t nsh[32];
    imdb_unhex(nseg, 64, nsh, 32);
    if (memcmp(mt->seg[0].dv, (uint8_t[32]){0}, 32) != 0) { /* the DV names its segment */
        char dname[80], ndv[80];
        imdb_hex(mt->seg[0].dv, 32, dname);
        strcat(dname, ".dv");
        snprintf(p, sizeof p, "%s/objects/%s", dir, dname);
        size_t dn;
        uint8_t *dv = slurp(p, &dn);
        replace_hash(dv, dn, mt->seg[0].seg, nsh);
        if (obj_rename(ofd, dname, dv, dn, ".dv", ndv)) exit(1);
        uint8_t ndh[32];
        imdb_unhex(ndv, 64, ndh, 32);
        replace_hash(man, mn, mt->seg[0].dv, ndh);
        free(dv);
    }
    replace_hash(man, mn, mt->seg[0].seg, nsh);
    if (obj_rename(ofd, mname, man, mn, ".man", nman)) exit(1);
    man_swap sw;
    imdb_unhex(mname, 64, sw.old, 32);
    imdb_unhex(nman, 64, sw.new_, 32);
    memcpy(mpos + 9, nman, 64);
    snprintf(p, sizeof p, "%s/LAKE_HEAD", dir);
    spit(p, head, hn);
    resign_from(dir, S, swap_manifest, &sw);
    imdb_manifest_free(&m);
    close(ofd);
    free(raw);
    free(man);
    free(head);
}

static int g_seed;
static const char *g_out;
static uint8_t g_writer[32]; /* the key that signs the next frame: META's, then each WRITER_KEY's */
static imdb_identity g_id;

/* a stream seed's prefix: writer key | root key (zeros: none) | db id | the commit it must be | prev */
#define SEED_PREFIX 120u
static void seed_prefix(uint8_t *s, const uint8_t key[32], uint64_t seq, const uint8_t prev[32])
{
    memcpy(s, key, 32);
    memset(s + 32, 0, 32);
    if (g_id.has_root) memcpy(s + 32, g_id.root, 32);
    memcpy(s + 64, g_id.db_id, 16);
    imdb_le64(s + 80, seq);
    memcpy(s + 88, prev, 32);
}

static void corpus_frame(void *ctx, const uint8_t *f, size_t fl)
{
    (void)ctx;
    char p[1200];
    snprintf(p, sizeof p, "%s/frame/f%03d", g_out, g_seed);
    spit(p, f, fl);
    snprintf(p, sizeof p, "%s/frame/b%03d", g_out, g_seed);
    spit(p, f + IMDB_FRAME_HDR, fl - IMDB_FRAME_HDR);
    imdb_commit_rec c;
    imdb_err e = {0};
    if (!imdb_frame_decode_body(f + IMDB_FRAME_HDR, fl - IMDB_FRAME_HDR, &c, &e)) {
        /* stream seed: the keys, the commit it must be, its prev, the frame */
        const imdb_op *w = imdb_commit_writer_op(&c);
        uint8_t *s = malloc(SEED_PREFIX + fl);
        seed_prefix(s, c.promote ? w->new_pk : g_writer, c.seq, c.prev);
        memcpy(s + SEED_PREFIX, f, fl);
        snprintf(p, sizeof p, "%s/stream/s%03d", g_out, g_seed);
        spit(p, s, SEED_PREFIX + fl);
        free(s);
        if (w) memcpy(g_writer, w->new_pk, 32); /* the frames after it are signed by the new key */
        for (uint32_t i = 0; i < c.nops; i++)
            if (c.ops[i].row && c.ops[i].pkind == IMDB_PAYLOAD_ROW) {
                snprintf(p, sizeof p, "%s/codec/r%02d_%02u", g_out, g_seed, i);
                spit(p, c.ops[i].row, c.ops[i].row_len);
            }
        imdb_commit_free(&c);
    }
    g_seed++;
}

static void corpus(const char *dir, const char *out)
{
    g_out = out;
    char p[1200];
    const char *subs[] = {"frame", "stream", "segment", "manifest", "codec"};
    for (size_t i = 0; i < 5; i++) {
        snprintf(p, sizeof p, "%s/%s", out, subs[i]);
        mkdir(p, 0700);
    }
    imdb_err e = {0};
    if (imdb_identity_read(dir, &g_id, NULL, &e)) die("identity", &e);
    memcpy(g_writer, g_id.writer, 32);
    /* the log: every segment, in order (names are zero-padded first seqs) */
    snprintf(p, sizeof p, "%s/log", dir);
    struct dirent **ents;
    int ne = scandir(p, &ents, NULL, alphasort);
    imdb_buf all;
    imdb_buf_init(&all);
    for (int i = 0; i < ne; i++) {
        if (ents[i]->d_name[0] != '.') {
            char q[1600];
            snprintf(q, sizeof q, "%s/%s", p, ents[i]->d_name);
            size_t sn;
            uint8_t *sb = seg_read(q, &sn);
            imdb_buf_put(&all, sb, sn);
            free(sb);
        }
        free(ents[i]);
    }
    if (ne >= 0) free(ents);
    size_t n = all.len;
    uint8_t *log = all.p;
    each_frame(log, n, corpus_frame, NULL);
    uint8_t *w = malloc(SEED_PREFIX + n), gen[32]; /* the whole log as one stream from genesis */
    imdb_genesis_hash(g_id.db_id, gen);
    seed_prefix(w, g_id.writer, 1, gen);
    memcpy(w + SEED_PREFIX, log, n);
    snprintf(p, sizeof p, "%s/stream/whole", out);
    spit(p, w, SEED_PREFIX + n);
    free(w);
    /* the same as ship --acks sends it: its session record first (repl.h) */
    uint8_t *ws = malloc(SEED_PREFIX + IMDB_SESSION_LEN + n), nonce[IMDB_NONCE_LEN];
    memset(nonce, 0x42, sizeof nonce);
    seed_prefix(ws, g_id.writer, 1, gen);
    imdb_session_encode(g_id.db_id, nonce, ws + SEED_PREFIX);
    memcpy(ws + SEED_PREFIX + IMDB_SESSION_LEN, log, n);
    snprintf(p, sizeof p, "%s/stream/whole-session", out);
    spit(p, ws, SEED_PREFIX + IMDB_SESSION_LEN + n);
    free(ws);
    { /* P2 R1.2: the same with a keep-alive before each frame and after the last (repl.h), counted from 1 */
        size_t nf = 0, off = 0, fl = 0;
        imdb_err fe = {0};
        while (off < n && imdb_frame_scan(log, n, off, &fl, &fe) == IMDB_SCAN_FRAME) {
            nf++;
            off += fl;
        }
        uint8_t *wa = malloc(SEED_PREFIX + IMDB_SESSION_LEN + n + (nf + 1) * IMDB_ALIVE_LEN);
        size_t at = SEED_PREFIX + IMDB_SESSION_LEN;
        seed_prefix(wa, g_id.writer, 1, gen);
        imdb_session_encode(g_id.db_id, nonce, wa + SEED_PREFIX);
        off = 0;
        for (uint64_t k = 0;; k++) {
            imdb_alive_encode(g_id.db_id, nonce, k, gen, k + 1, wa + at);
            at += IMDB_ALIVE_LEN;
            if (k == nf || imdb_frame_scan(log, n, off, &fl, &fe) != IMDB_SCAN_FRAME) break;
            memcpy(wa + at, log + off, fl);
            at += fl;
            off += fl;
        }
        snprintf(p, sizeof p, "%s/stream/whole-alive", out);
        spit(p, wa, at);
        free(wa);
    }
    free(log);
    snprintf(p, sizeof p, "%s/objects", dir);
    DIR *d = opendir(p);
    struct dirent *de;
    while (d && (de = readdir(d))) {
        if (de->d_name[0] == '.') continue;
        char q[1200], dst[1200];
        snprintf(q, sizeof q, "%s/objects/%s", dir, de->d_name);
        size_t on;
        uint8_t *b = slurp(q, &on);
        if (strstr(de->d_name, ".seg") && on > 16) {
            /* seed = table id byte + segment (the harness parses against that schema): F5, the id its footer's
             * imagedb.table names (before, the old header's bytes 12-15: in a Parquet file, a chunk's data) */
            pq_footer ft;
            imdb_err fe = {0};
            unsigned long tid = 256;
            if (imdb_pq_footer(b, on, &ft, &fe)) die("segment", &fe);
            for (uint32_t k = 0; k < ft.nkv; k++)
                if (ft.klen[k] == 13 && !memcmp(ft.key[k], "imagedb.table", 13) && ft.vlen[k] < 12) {
                    char v[16];
                    snprintf(v, sizeof v, "%.*s", (int)ft.vlen[k], (const char *)ft.val[k]);
                    tid = strtoul(v, NULL, 10);
                }
            if (tid > 255) {
                fputs("imdb-forge: corpus: a segment without a table id of a byte\n", stderr);
                exit(1);
            }
            uint8_t *s = malloc(on + 1);
            s[0] = (uint8_t)tid;
            memcpy(s + 1, b, on);
            snprintf(dst, sizeof dst, "%s/segment/%.16s", out, de->d_name);
            spit(dst, s, on + 1);
            free(s);
        } else {
            snprintf(dst, sizeof dst, "%s/manifest/%.16s", out, de->d_name);
            spit(dst, b, on);
        }
        free(b);
    }
    if (d) closedir(d);
}

/* DURABLE as a writer that crashed during its last append leaves it: naming the
 * commit before the last frame in the log (the genesis hash before commit 1). */
typedef struct last2 {
    uint64_t seq[2];
    uint8_t hash[2][32];
} last2;

static void keep_last2(void *ctx, const uint8_t *f, size_t fl)
{
    (void)fl;
    last2 *l = ctx;
    l->seq[0] = l->seq[1];
    memcpy(l->hash[0], l->hash[1], 32);
    l->seq[1] = imdb_frame_seq(f);
    memcpy(l->hash[1], imdb_frame_hash(f), 32);
}

static void durable_rewind(const char *dir)
{
    uint8_t id[16], writer[32];
    imdb_err e = {0};
    if (imdb_read_identity(dir, id, writer, &e)) die("identity", &e);
    last2 l = {{0, 0}, {{0}}};
    imdb_genesis_hash(id, l.hash[1]);
    char p[1200];
    snprintf(p, sizeof p, "%s/log", dir);
    struct dirent **ents;
    int ne = scandir(p, &ents, NULL, alphasort);
    for (int i = 0; i < ne; i++) {
        if (ents[i]->d_name[0] != '.') {
            char q[1600];
            snprintf(q, sizeof q, "%s/%s", p, ents[i]->d_name);
            size_t sn;
            uint8_t *sb = seg_read(q, &sn);
            each_frame(sb, sn, keep_last2, &l);
            free(sb);
        }
        free(ents[i]);
    }
    if (ne >= 0) free(ents);
    /* the record the last commit before it left: strict if that writer was (--durable-ack) */
    snprintf(p, sizeof p, "%s/%s", dir, IMDB_DURABLE_NAME);
    imdb_durable old;
    size_t on;
    uint8_t *ob = slurp(p, &on);
    bool strict = imdb_durable_decode(ob, on, &old, &e) == IMDB_OK && old.strict;
    free(ob);
    imdb_durable w = {.seq = l.seq[0], .synced = true, .strict = strict};
    memcpy(w.head, l.hash[0], 32);
    uint8_t wb[IMDB_DURABLE_LEN];
    imdb_durable_encode(&w, wb);
    spit(p, wb, sizeof wb);
}

/* lie-payload: the last frame with a row payload gets one row byte flipped and its
 * checksums recomputed. The payload is outside the signature (only its commitment is
 * in the signed header), so only the commitment check can catch it. */
typedef struct lpctx {
    imdb_buf *out;
    size_t idx, target, found;
} lpctx;

static bool has_row_payload(const uint8_t *f, size_t fl)
{
    imdb_commit_rec c;
    imdb_err e = {0};
    if (imdb_frame_decode_body(f + IMDB_FRAME_HDR, fl - IMDB_FRAME_HDR, &c, &e)) die("decode", &e);
    bool any = false;
    for (uint32_t i = 0; i < c.nops; i++) any |= imdb_op_is_row(c.ops[i].code) && c.ops[i].pkind == IMDB_PAYLOAD_ROW;
    imdb_commit_free(&c);
    return any;
}

static void lie_payload_find(void *ctx, const uint8_t *f, size_t fl)
{
    lpctx *x = ctx;
    if (has_row_payload(f, fl)) x->target = x->idx, x->found = 1;
    x->idx++;
}

static void lie_payload_one(void *ctx, const uint8_t *f, size_t fl)
{
    lpctx *x = ctx;
    if (x->idx++ != x->target) {
        imdb_buf_put(x->out, f, fl);
        return;
    }
    imdb_commit_rec c;
    imdb_err e = {0};
    if (imdb_frame_decode_body(f + IMDB_FRAME_HDR, fl - IMDB_FRAME_HDR, &c, &e)) die("decode", &e);
    uint8_t *row = NULL;
    for (uint32_t i = 0; i < c.nops && !row; i++)
        if (imdb_op_is_row(c.ops[i].code) && c.ops[i].pkind == IMDB_PAYLOAD_ROW && c.ops[i].row_len) {
            row = malloc(c.ops[i].row_len);
            memcpy(row, c.ops[i].row, c.ops[i].row_len);
            row[c.ops[i].row_len - 1] ^= 0x01;
            c.ops[i].row = row;
        }
    imdb_buf pay;
    imdb_buf_init(&pay);
    imdb_commit_encode_payload(&c, &pay);
    imdb_frame_build(f + IMDB_FRAME_HDR + IMDB_BODY_DESC, c.hlen, c.seq, c.hash, c.sig, pay.p, pay.len, x->out);
    imdb_buf_free(&pay);
    free(row);
    imdb_commit_free(&c);
}

/* ---- writer epochs (deferred.md R2b) ---------------------------------------------------- */

static imdb_db *open_ro(const char *dir)
{
    imdb_open_opts o = {.read_only = true};
    imdb_db *db;
    imdb_err e = {0};
    if (imdb_open(dir, &o, &db, &e)) {
        fprintf(stderr, "imdb-forge: open %s: %s\n", dir, e.msg);
        exit(1);
    }
    return db;
}

/* a commit on top of dir's last one, appended to its last log segment, signed by key (ext: a
 * promotion's descriptor extension); the database is only read through the engine */
/* digest: the state digest the commit records, or NULL for the current one (ops that change no
 * row); the ops' payloads go into the frame */
/* F3c: bytes of the encoded commit header changed before it is hashed and signed (one lie the encoder would refuse to
 * write: an ADD's VARCHAR length shorter than its DEFAULT): the first match of g_find, its byte g_at made g_to */
static const uint8_t *g_find;
static size_t g_find_len, g_at;
static uint8_t g_to;

static void append_commit_digest(const char *dir, imdb_db *db, imdb_op *ops, uint32_t nops, const imdb_signer *key,
                                 const uint8_t *ext, const uint8_t *digest)
{
    imdb_commit_rec c;
    memset(&c, 0, sizeof c);
    c.seq = db->seq + 1;
    c.alg = db->meta.digest_alg;
    c.time_us = db->last_time + 1000;
    memcpy(c.prev, db->head, 32);
    c.ops = ops;
    c.nops = nops;
    if (digest) memcpy(c.digest, digest, 32);
    else imdb_state_digest(db, NULL, c.digest);
    imdb_buf h, f, pl;
    imdb_buf_init(&h);
    imdb_buf_init(&f);
    imdb_buf_init(&pl);
    imdb_commit_encode_header(&c, &h);
    imdb_commit_encode_payload(&c, &pl);
    for (size_t i = 0; g_find && h.len >= g_find_len && i <= h.len - g_find_len; i++)
        if (!memcmp(h.p + i, g_find, g_find_len)) {
            h.p[i + g_at] = g_to;
            g_find = NULL;
        }
    if (g_find) exit(1); /* the lie's bytes were not found: nothing written */
    if (h.err || pl.err) exit(1);
    imdb_commit_hash(h.p, h.len, c.hash);
    uint8_t m[IMDB_SIGMSG_LEN];
    imdb_commit_sigmsg(c.seq, (uint32_t)h.len, c.hash, m);
    imdb_sign(key, m, sizeof m, c.sig);
    imdb_frame_build_ext(h.p, h.len, c.seq, c.hash, c.sig, ext, pl.len ? pl.p : NULL, pl.len, &f);
    char seg[700]; /* the writer's rule: after a commit that publishes a manifest, a new segment */
    uint64_t first = db->log_rotate || !db->nsegs ? c.seq : db->segs[db->nsegs - 1];
    snprintf(seg, sizeof seg, "%s/log/%020llu.ilg", dir, (unsigned long long)first);
    seg_add(seg, f.p, f.len);
    imdb_buf_free(&h);
    imdb_buf_free(&f);
    imdb_buf_free(&pl);
}

static void append_commit(const char *dir, imdb_db *db, imdb_op *ops, uint32_t nops, const imdb_signer *key,
                          const uint8_t *ext)
{
    append_commit_digest(dir, db, ops, nops, key, ext, NULL);
}

/* a lake manifest (version 6) that breaks one of its rules, re-pointed and re-signed so only that rule can
 * refuse it: boundary (the header names a retirement boundary, commit 1, that no op of the log made)
 * or column (the last index names a column its table lacks; needs an index in the last table, whose
 * entry is then followed only by that table's retention, creation and drop commits) */
static void manifest_lie(const char *dir, const char *kind)
{
    char p[1200];
    snprintf(p, sizeof p, "%s/LAKE_HEAD", dir);
    size_t hn;
    uint8_t *head = slurp(p, &hn);
    char *mpos = strstr((char *)head, "manifest ");
    unsigned long long S = 0;
    if (!mpos || sscanf((char *)head, "imagedb-lake 1\nseq %llu", &S) != 1) exit(1);
    char mname[80];
    memcpy(mname, mpos + 9, 64);
    strcpy(mname + 64, ".man");
    snprintf(p, sizeof p, "%s/objects", dir);
    int ofd = open(p, O_RDONLY | O_DIRECTORY);
    snprintf(p, sizeof p, "%s/objects/%s", dir, mname);
    size_t mn;
    uint8_t *man = slurp(p, &mn);
    imdb_manifest m;
    imdb_err e = {0};
    if (imdb_manifest_parse(man, mn, &m, &e)) die("manifest", &e);
    imdb_buf nb;
    imdb_buf_init(&nb);
    if (strcmp(kind, "boundary") == 0 && imdb_get_le32(man + 8) == IMDB_MANIFEST_VERSION && S > 1 && m.boundary == 0) {
        imdb_buf_put(&nb, man, mn);
        /* after magic, version, nsections, db id, seq, prev, state digest, prev manifest: the u64 boundary */
        nb.p[136] = 1;
    } else if (strcmp(kind, "column") == 0 && m.nt && m.t[m.nt - 1].nidx && !m.nv) {
        imdb_buf_put(&nb, man, mn);
        uint16_t c = m.t[m.nt - 1].s.ncols; /* the last index's column, little endian, before the three u64, F1's u32 and
                                             * F2a's u16 (manifest 9: version 1's DEFAULTs, none) */
        nb.p[nb.len - 232] = (uint8_t)c; /* then F2b-1's u16 (manifest 11: version 1's CHECKs, none), F2b-2's u16
                                          * (manifest 13: its FOREIGN KEYs, none), the views section (12 + a count of 0), the
                                          * sequences and the types (16 each), the roles (52, L: its object's hash, last id and
                                          * count), the grants and the five reserved ones (16 each) */
        nb.p[nb.len - 231] = (uint8_t)(c >> 8);
    } else if (strcmp(kind, "section") == 0 && imdb_get_le32(man + 8) == IMDB_MANIFEST_VERSION && mn > 144 + 144) {
        imdb_buf_put(&nb, man, mn); /* the format design's slice 1: the seven reserved sections end it, 16 bytes each */
        nb.p[nb.len - 68] = 1;      /* the replica set's section (7): its u32 count a later format's (sections 3 to 6 are read now: F2a-2,
                                     * F3g, L; with no role, section 5 is 52 bytes and section 6 16) */
    } else if (strcmp(kind, "nsections") == 0 && imdb_get_le32(man + 8) == IMDB_MANIFEST_VERSION && mn > 144 + 144) {
        imdb_buf_put(&nb, man, mn);
        nb.p[12] = 10; /* the header's section count: ten, with eleven there */
    } else if (strcmp(kind, "order") == 0 && imdb_get_le32(man + 8) == IMDB_MANIFEST_VERSION && mn > 144 + 144) {
        imdb_buf_put(&nb, man, mn);
        nb.p[nb.len - 180] = 4; /* the sequences section given the enums' kind: out of order (L: no role, 52 + 16 bytes of 5 and 6) */
    } else if (strcmp(kind, "later") == 0 && imdb_get_le32(man + 8) == IMDB_MANIFEST_VERSION && mn > 144 + 144) {
        imdb_buf_put(&nb, man, mn - 16); /* the triggers section, last, as a later format would write it: a count and */
        imdb_buf_put_u32(&nb, 11);        /* its entry (4 bytes here), so its length is not 4 */
        imdb_buf_put_u64(&nb, 8);
        imdb_buf_put_u32(&nb, 1);
        imdb_buf_put_u32(&nb, 0);
    } else if (strcmp(kind, "keylist") == 0 && imdb_get_le32(man + 8) == IMDB_MANIFEST_VERSION && m.nt && m.t[0].s.npk == 1 && m.t[0].s.ncols > 1) {
        imdb_buf_put(&nb, man, mn);
        /* table 0's schema after the header (144), the tables section's frame (12), its count and the schema's length
         * (4 each); its key list (u8 1, u16 column) is the schema's last 3 bytes: another column named there */
        uint32_t sl = imdb_get_le32(man + 160);
        uint16_t k = (uint16_t)((m.t[0].s.key[0] + 1) % m.t[0].s.ncols); /* a one-column key's list */
        if (sl < 3 || 164 + (size_t)sl > mn) exit(1);
        nb.p[164 + sl - 2] = (uint8_t)k;
        nb.p[164 + sl - 1] = (uint8_t)(k >> 8);
    } else if (strcmp(kind, "default") == 0 && imdb_get_le32(man + 8) == IMDB_MANIFEST_VERSION) {
        /* F1: the history's ADD of an INT64 NOT NULL column n (u8 kind 1, u8 1, "n", type, precision, scale, flags,
         * u8 has 1, then its u64 DEFAULT) given another DEFAULT: the history still ends at the schema */
        imdb_buf_put(&nb, man, mn);
        static const uint8_t pat[8] = {1, 1, 'n', IMDB_T_INT64, 0, 0, 0, 1};
        size_t at = 0;
        for (size_t i = mn - 16; i > 0 && !at; i--)
            if (memcmp(nb.p + i, pat, sizeof pat) == 0) at = i + sizeof pat;
        if (!at) exit(1);
        imdb_le64(nb.p + at, imdb_get_le64(nb.p + at) + 1);
    } else if (strcmp(kind, "seq-state") == 0 && imdb_get_le32(man + 8) == IMDB_MANIFEST_VERSION) {
        /* F2a-2: the sequence fu_seq's last value in the manifest one increment on (its definition: u32 id, u8 6,
         * "fu_seq", u8 width, then increment, min, max and start, then last): aligned, in bounds, another state */
        imdb_buf_put(&nb, man, mn);
        static const uint8_t pat[7] = {6, 'f', 'u', '_', 's', 'e', 'q'};
        size_t at = 0;
        for (size_t i = 0; i + sizeof pat + 41 <= mn && !at; i++)
            if (memcmp(nb.p + i, pat, sizeof pat) == 0) at = i + sizeof pat;
        if (!at) exit(1);
        int64_t inc = (int64_t)imdb_get_le64(nb.p + at + 1);
        imdb_le64(nb.p + at + 33, imdb_get_le64(nb.p + at + 33) + (uint64_t)inc);
    } else if (strcmp(kind, "fk-def") == 0 && imdb_get_le32(man + 8) == IMDB_MANIFEST_VERSION) {
        /* F2b-2: version 1's FOREIGN KEY c_pid_fkey (manifest 13: u8 10, the name, u8 1, u16 1, u32 0, u16 0, then ON
         * DELETE 2 CASCADE) made 0 NO ACTION: a valid definition, another than the log's */
        imdb_buf_put(&nb, man, mn);
        static const uint8_t pat[] = {10, 'c', '_', 'p', 'i', 'd', '_', 'f', 'k', 'e', 'y', 1, 1, 0, 0, 0, 0, 0, 0, 0, IMDB_FK_CASCADE};
        size_t at = 0;
        for (size_t i = 0; i + sizeof pat <= mn && !at; i++)
            if (memcmp(nb.p + i, pat, sizeof pat) == 0) at = i + sizeof pat - 1;
        if (!at) exit(1);
        nb.p[at] = IMDB_FK_NO_ACTION;
    } else if (strcmp(kind, "gen-text") == 0 && imdb_get_le32(man + 8) == IMDB_MANIFEST_VERSION) {
        /* F2c: version 1's generated column w (manifest 12, op 23's kind 9 among the DEFAULTs: u16 column 2, u8 9, u32 5,
         * "a * 2") made "a * 3": a text that binds, another than the log's */
        imdb_buf_put(&nb, man, mn);
        static const uint8_t pat[] = {2, 0, IMDB_DEFK_GENERATED, 5, 0, 0, 0, 'a', ' ', '*', ' ', '2'};
        size_t at = 0;
        for (size_t i = 0; i + sizeof pat <= mn && !at; i++)
            if (memcmp(nb.p + i, pat, sizeof pat) == 0) at = i + sizeof pat - 1;
        if (!at) exit(1);
        nb.p[at] = '3';
    } else if (strcmp(kind, "check-text") == 0 && imdb_get_le32(man + 8) == IMDB_MANIFEST_VERSION) {
        /* F2b-1: version 1's CHECK z_a_check (manifest 11: u8 9, the name, u32 5, "a > 0") made "a > 1": a CHECK the rows still
         * pass, another than the log's */
        imdb_buf_put(&nb, man, mn);
        static const uint8_t pat[] = {9, 'z', '_', 'a', '_', 'c', 'h', 'e', 'c', 'k', 5, 0, 0, 0, 'a', ' ', '>', ' ', '0'};
        size_t at = 0;
        for (size_t i = 0; i + sizeof pat <= mn && !at; i++)
            if (memcmp(nb.p + i, pat, sizeof pat) == 0) at = i + sizeof pat - 1;
        if (!at) exit(1);
        nb.p[at] = '1';
    } else if (strcmp(kind, "grant-bits") == 0 && imdb_get_le32(man + 8) == IMDB_MANIFEST_VERSION) {
        /* L (LJ): staff's SELECT on t in section 6 (u8 1, u32 2, u8 1, u32 0, u32 1) made SELECT and INSERT: its one
         * encoding, another than the log's */
        imdb_buf_put(&nb, man, mn);
        static const uint8_t pat[] = {1, 2, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0};
        size_t at = 0;
        for (size_t i = mn - sizeof pat; i > 0 && !at; i--)
            if (memcmp(nb.p + i, pat, sizeof pat) == 0) at = i + 10;
        if (!at) exit(1);
        nb.p[at] = 3;
    } else if (strcmp(kind, "enum-label") == 0 && imdb_get_le32(man + 8) == IMDB_MANIFEST_VERSION) {
        /* F3g (KF): a label of the enums section (u8 2, "kc") made "kd": a label the log never made */
        imdb_buf_put(&nb, man, mn);
        static const uint8_t pat[] = {2, 'k', 'c'};
        size_t at = 0;
        for (size_t i = mn - sizeof pat; i > 0 && !at; i--)
            if (memcmp(nb.p + i, pat, sizeof pat) == 0) at = i + 2;
        if (!at) exit(1);
        nb.p[at] = 'd';
    } else if (strcmp(kind, "dec-precision") == 0 && imdb_get_le32(man + 8) == IMDB_MANIFEST_VERSION) {
        /* F3e: a schema's DECIMAL(30,2) column w (u8 1, "w", type, precision, scale) made DECIMAL(39,2): past 38 digits */
        imdb_buf_put(&nb, man, mn);
        static const uint8_t pat[] = {1, 'w', IMDB_T_DECIMAL, 30, 2};
        size_t at = 0;
        for (size_t i = 0; i + sizeof pat <= mn && !at; i++)
            if (memcmp(nb.p + i, pat, sizeof pat) == 0) at = i + 3;
        if (!at) exit(1);
        nb.p[at] = 39;
    } else if (strcmp(kind, "create-default") == 0 && imdb_get_le32(man + 8) == IMDB_MANIFEST_VERSION) {
        /* F2a: version 1's DEFAULTs (manifest 9) of a table with no ALTER whose column 2 is an INT64 DEFAULT 77: u32 0
         * (no ALTER), u16 1, u16 column 2, u8 kind 1, then the u64 value, made 78: the history still ends at the schema */
        imdb_buf_put(&nb, man, mn);
        static const uint8_t pat[13] = {0, 0, 0, 0, 1, 0, 2, 0, IMDB_DEFK_VALUE, 77, 0, 0, 0};
        size_t at = 0;
        for (size_t i = mn - 16; i > 0 && !at; i--)
            if (memcmp(nb.p + i, pat, sizeof pat) == 0) at = i + 9;
        if (!at) exit(1);
        nb.p[at] = 78;
    } else {
        fputs("imdb-forge: manifest-lie DIR boundary (none yet) | column (an index in the last table) | section (a reserved"
              " one not empty) | nsections (ten) | order (a reserved one out of order) | later (the last one a later"
              " format's, longer) | keylist (table 0's key list another column) | default (an added column n's DEFAULT"
              " another in the history) | create-default (a CREATE's DEFAULT 77 of column 2 another) | seq-state (fu_seq's last on)"
              " | check-text (z_a_check's 'a > 0' another) | gen-text (w's 'a * 2' another) | fk-def (c_pid_fkey's CASCADE another)"
              " | dec-precision (a DECIMAL(30,2) w made DECIMAL(39,2))"
              " | enum-label (an ENUM label kc made kd) | grant-bits (staff's SELECT on t made SELECT and INSERT)\n", stderr);
        exit(1);
    }
    if (nb.err) exit(1);
    char nman[80];
    if (obj_rename(ofd, mname, nb.p, nb.len, ".man", nman)) exit(1);
    man_swap sw;
    imdb_unhex(mname, 64, sw.old, 32);
    imdb_unhex(nman, 64, sw.new_, 32);
    memcpy(mpos + 9, nman, 64);
    snprintf(p, sizeof p, "%s/LAKE_HEAD", dir);
    spit(p, head, hn);
    resign_from(dir, S, swap_manifest, &sw);
    imdb_buf_free(&nb);
    imdb_manifest_free(&m);
    close(ofd);
    free(man);
    free(head);
}

/* a commit with an index op the log's rules forbid, signed by the writer (signing.key): an index
 * on a column the table lacks, a name already in use, or a DROP of an index that is not there */
static void index_lie(const char *dir, const char *kind)
{
    char p[1200];
    snprintf(p, sizeof p, "%s/signing.key", dir);
    size_t kn;
    uint8_t *seed = slurp(p, &kn);
    if (kn != IMDB_SEED_LEN) exit(1);
    imdb_signer sg;
    imdb_signer_init(&sg, seed);
    free(seed);
    imdb_db *db = open_ro(dir);
    if (!db->nt) {
        fputs("imdb-forge: index-lie needs a table\n", stderr);
        exit(1);
    }
    char nm[IMDB_MAX_IDENT + 1];
    imdb_op op;
    memset(&op, 0, sizeof op);
    op.iname = nm;
    op.incols = 1;
    if (strcmp(kind, "column") == 0) {
        op.code = IMDB_OP_CREATE_INDEX;
        op.icols[0] = db->t[0]->s.ncols;
        snprintf(nm, sizeof nm, "lie_column");
    } else if (strcmp(kind, "duplicate") == 0 && db->t[0]->nidx) {
        op.code = IMDB_OP_CREATE_INDEX;
        snprintf(nm, sizeof nm, "%s", db->t[0]->idx[0].d.name);
    } else if (strcmp(kind, "alter-varchar-default") == 0) { /* F3c: ADD COLUMN k VARCHAR(2) DEFAULT 'abc' to table 0: a default
                                                               * past its length, every old row's missing value if taken */
        op.code = IMDB_OP_ALTER_TABLE;
        op.akind = IMDB_ALTER_ADD_COLUMN;
        snprintf(op.acol.name, sizeof op.acol.name, "k");
        op.acol.type = IMDB_T_TEXT;
        op.acol.vlen = 3; /* encoded as VARCHAR(3), which the DEFAULT fits; the header's length byte then made 2 */
        static const uint8_t pat[] = {1, 'k', IMDB_T_TEXT, 3, 0};
        g_find = pat;
        g_find_len = sizeof pat;
        g_at = 3;
        g_to = 2;
        op.acol.flags = IMDB_COL_NULLABLE;
        op.adef = (imdb_value){.type = IMDB_T_TEXT, .s = (const uint8_t *)"abc", .len = 3};
    } else if (strcmp(kind, "alter-view") == 0) { /* F1: ADD COLUMN k (INT64, NULL) to table 0, a name a view reading it holds */
        op.code = IMDB_OP_ALTER_TABLE;
        op.akind = IMDB_ALTER_ADD_COLUMN;
        snprintf(op.acol.name, sizeof op.acol.name, "k");
        op.acol.type = IMDB_T_INT64;
        op.acol.flags = IMDB_COL_NULLABLE;
        op.adef = (imdb_value){.type = IMDB_T_INT64, .null = true};
    } else if (strcmp(kind, "alter-not-null") == 0 || strcmp(kind, "alter-drop-indexed") == 0) {
        /* F1 stage 4: SET NOT NULL of table 0's first nullable column, which a live row holds NULL (the test made it
         * so), or DROP COLUMN of the first column table 0's first index names */
        imdb_table *t = db->t[0];
        bool nn = strcmp(kind, "alter-not-null") == 0;
        int c = -1;
        for (uint16_t k = 0; nn && k < t->s.ncols && c < 0; k++)
            if (t->s.cols[k].flags & IMDB_COL_NULLABLE) c = k;
        if (!nn && t->nidx) c = t->idx[0].d.cols[0];
        if (c < 0) {
            fputs("imdb-forge: index-lie alter-not-null needs a nullable column, alter-drop-indexed an index\n", stderr);
            exit(1);
        }
        op.code = IMDB_OP_ALTER_TABLE;
        op.table = t->s.id;
        op.akind = nn ? IMDB_ALTER_SET_NOT_NULL : IMDB_ALTER_DROP_COLUMN;
        op.apos = t->hist.vers[t->hist.nvers - 1].pos[c];
        op.iname = NULL;
    } else if (strcmp(kind, "drop-absent") == 0) {
        op.code = IMDB_OP_DROP_INDEX;
        snprintf(nm, sizeof nm, "no_such_index");
    } else if (strcmp(kind, "unique-dup") == 0) {
        /* an INSERT repeating the first live row's values under a new primary key, so it repeats
         * that row's key of every unique index; the state digest it records is right, so only
         * the unique rule can refuse it */
        imdb_table *t = db->t[0];
        uint64_t src = IMDB_NONE;
        int64_t maxpk = 0;
        for (uint64_t vid = imdb_v_next(t, 0); vid < t->nver; vid = imdb_v_next(t, vid + 1)) {
            imdb_value k;
            if (imdb_vh(t, vid)->end != IMDB_LIVE || imdb_version_key(t, vid, t->s.key[0], &k) != IMDB_OK) continue;
            if (src == IMDB_NONE) src = vid;
            if (k.i > maxpk) maxpk = k.i;
        }
        imdb_value vals[IMDB_MAX_COLS];
        imdb_err e = {0};
        if (src == IMDB_NONE || t->s.npk != 1 || t->s.cols[t->s.key[0]].type != IMDB_T_INT64 || imdb_version_values(db, t, src, vals, &e)) {
            fputs("imdb-forge: index-lie unique-dup needs a live row with an INT64 primary key\n", stderr);
            exit(1);
        }
        vals[t->s.key[0]].i = maxpk + 1;
        static imdb_buf row;
        imdb_buf_init(&row);
        if (imdb_row_encode(&t->s, vals, &row, &e) || imdb_buf_check(&row, &e)) die("row", &e);
        memset(op.salt, 0x5a, sizeof op.salt);
        op.code = IMDB_OP_INSERT;
        op.table = t->s.id;
        op.vid = t->nver;
        op.pkind = IMDB_PAYLOAD_ROW;
        op.row = row.p;
        op.row_len = (uint32_t)row.len;
        op.iname = NULL;
        imdb_row_commit(t->s.id, op.salt, row.p, row.len, op.commit);
        imdb_lthash g = db->global;
        imdb_lthash_add_commit(db->meta.digest_alg, &g, op.commit);
        uint8_t dg[32];
        imdb_lthash_digest(db->meta.digest_alg, &g, dg);
        append_commit_digest(dir, db, &op, 1, &sg, NULL, dg);
        imdb_close(db);
        return;
    } else if (strcmp(kind, "varchar-long") == 0) { /* F3c: an INSERT into the last table whose first VARCHAR(n) holds
                                                       * n + 1 characters (encoded as a TEXT's: the bytes are the
                                                       * same), the key a new INT64, its commitment and digest right */
        imdb_table *t = db->t[db->nt - 1];
        int vc = -1;
        for (int c = 0; c < t->s.ncols && vc < 0; c++) if (t->s.cols[c].type == IMDB_T_TEXT && t->s.cols[c].vlen) vc = c;
        if (vc < 0 || t->s.cols[vc].vlen > 200 || t->s.npk != 1 || t->s.cols[t->s.key[0]].type != IMDB_T_INT64) {
            fputs("imdb-forge: index-lie varchar-long needs a VARCHAR(n <= 200) and an INT64 key in the last table\n", stderr);
            exit(1);
        }
        imdb_value vals[IMDB_MAX_COLS];
        memset(vals, 0, sizeof vals);
        for (int c = 0; c < t->s.ncols; c++) {
            vals[c].type = t->s.cols[c].type;
            vals[c].scale = t->s.cols[c].scale;
            vals[c].null = c != vc && c != t->s.key[0];
        }
        static uint8_t lng[256];
        memset(lng, 'x', sizeof lng);
        vals[vc].s = lng;
        vals[vc].len = (uint32_t)t->s.cols[vc].vlen + 1;
        vals[t->s.key[0]].i = 987654322;
        imdb_schema loose = t->s;
        loose.cols[vc].vlen = 0; /* the encoder's check passed: a TEXT's bytes */
        imdb_err e = {0};
        static imdb_buf row;
        imdb_buf_init(&row);
        if (imdb_row_encode(&loose, vals, &row, &e) || imdb_buf_check(&row, &e)) die("row", &e);
        memset(op.salt, 0x5d, sizeof op.salt);
        op.code = IMDB_OP_INSERT;
        op.table = t->s.id;
        op.vid = t->nver;
        op.pkind = IMDB_PAYLOAD_ROW;
        op.row = row.p;
        op.row_len = (uint32_t)row.len;
        op.iname = NULL;
        imdb_row_commit(t->s.id, op.salt, row.p, row.len, op.commit);
        imdb_lthash g = db->global;
        imdb_lthash_add_commit(db->meta.digest_alg, &g, op.commit);
        uint8_t dg[32];
        imdb_lthash_digest(db->meta.digest_alg, &g, dg);
        append_commit_digest(dir, db, &op, 1, &sg, NULL, dg);
        imdb_close(db);
        return;
    } else if (strcmp(kind, "date-range") == 0) { /* F3b: an INSERT into the last table whose first DATE column holds
                                                     * 9999-12-31 + 1 (its bytes written past the encoder's check), the
                                                     * key a new INT64, its commitment and digest right */
        imdb_table *t = db->t[db->nt - 1];
        int dc = -1;
        for (int c = 0; c < t->s.ncols && dc < 0; c++) if (t->s.cols[c].type == IMDB_T_DATE) dc = c;
        if (dc < 0 || t->s.npk != 1 || t->s.cols[t->s.key[0]].type != IMDB_T_INT64) {
            fputs("imdb-forge: index-lie date-range needs a DATE column and an INT64 key in the last table\n", stderr);
            exit(1);
        }
        imdb_value vals[IMDB_MAX_COLS];
        memset(vals, 0, sizeof vals);
        for (int c = 0; c < t->s.ncols; c++) {
            vals[c].type = t->s.cols[c].type;
            vals[c].scale = t->s.cols[c].scale;
            vals[c].null = c != dc && c != t->s.key[0];
        }
        vals[t->s.key[0]].i = 987654321; /* a key no honest row of the test holds */
        imdb_err e = {0};
        static imdb_buf row;
        imdb_buf_init(&row);
        if (imdb_row_encode(&t->s, vals, &row, &e) || imdb_buf_check(&row, &e)) die("row", &e);
        size_t off = 0, nn = 0;
        for (int c = 0; c < t->s.ncols; c++) nn += (t->s.cols[c].flags & IMDB_COL_NULLABLE) != 0;
        off = (nn + 7) / 8;
        for (int c = 0; c < dc; c++) if (!vals[c].null) off += t->s.cols[c].type == IMDB_T_BOOL ? 1 : 8; /* no TEXT before */
        imdb_le64(row.p + off, (uint64_t)(IMDB_DATE_MAX + 1));
        memset(op.salt, 0x5c, sizeof op.salt);
        op.code = IMDB_OP_INSERT;
        op.table = t->s.id;
        op.vid = t->nver;
        op.pkind = IMDB_PAYLOAD_ROW;
        op.row = row.p;
        op.row_len = (uint32_t)row.len;
        op.iname = NULL;
        imdb_row_commit(t->s.id, op.salt, row.p, row.len, op.commit);
        imdb_lthash g = db->global;
        imdb_lthash_add_commit(db->meta.digest_alg, &g, op.commit);
        uint8_t dg[32];
        imdb_lthash_digest(db->meta.digest_alg, &g, dg);
        append_commit_digest(dir, db, &op, 1, &sg, NULL, dg);
        imdb_close(db);
        return;
    } else if (strcmp(kind, "seq-back") == 0 || strcmp(kind, "seq-drop-owned") == 0) {
        /* F2a-2: a SEQ_ADVANCE of the first sequence to a mark one increment below its last (replay's monotone rule), or
         * a DROP SEQUENCE of the first sequence an IDENTITY owns: each signed, the encoder's places kept */
        bool back = strcmp(kind, "seq-back") == 0;
        const imdb_sequence *s = NULL;
        for (uint32_t i = 0; i < db->nseqs && !s; i++)
            if (!db->seqs[i].dropped_at && (back ? db->seqs[i].called : db->seqs[i].owner != UINT32_MAX)) s = &db->seqs[i];
        if (!s) {
            fputs("imdb-forge: index-lie seq-back needs a used sequence, seq-drop-owned an IDENTITY's\n", stderr);
            exit(1);
        }
        op.code = back ? IMDB_OP_SEQ_ADVANCE : IMDB_OP_DROP_SEQUENCE;
        op.seq = s->d.id;
        op.sval = s->last - s->d.inc;
        op.iname = NULL;
        append_commit(dir, db, &op, 1, &sg, NULL);
        imdb_close(db);
        return;
    } else if (strcmp(kind, "uuid-short") == 0) {
        /* F3d: an INSERT into the last table, (id INT64 PRIMARY KEY, u UUID NOT NULL), of a row whose UUID is 15 bytes:
         * no NULL bitmap, the id's 8 bytes, then 15 (the row codec wants 16); its commitment and digest right */
        imdb_table *t = db->t[db->nt - 1];
        if (t->s.ncols != 2 || t->s.cols[1].type != IMDB_T_UUID || (t->s.cols[1].flags & IMDB_COL_NULLABLE)) {
            fputs("imdb-forge: index-lie uuid-short needs a last table (id INT64 PRIMARY KEY, u UUID NOT NULL)\n", stderr);
            exit(1);
        }
        static uint8_t row[8 + 15];
        imdb_le64(row, 999);
        memset(row + 8, 0xab, 15);
        memset(op.salt, 0x5f, sizeof op.salt);
        op.code = IMDB_OP_INSERT;
        op.table = t->s.id;
        op.vid = t->nver;
        op.pkind = IMDB_PAYLOAD_ROW;
        op.row = row;
        op.row_len = sizeof row;
        op.iname = NULL;
        imdb_row_commit(t->s.id, op.salt, row, sizeof row, op.commit);
        imdb_lthash g = db->global;
        imdb_lthash_add_commit(db->meta.digest_alg, &g, op.commit);
        uint8_t dg[32];
        imdb_lthash_digest(db->meta.digest_alg, &g, dg);
        append_commit_digest(dir, db, &op, 1, &sg, NULL, dg);
        imdb_close(db);
        return;
    } else if (strcmp(kind, "iv-short") == 0) {
        /* F3f: an INSERT into the last table, (id INT64 PRIMARY KEY, iv INTERVAL NOT NULL), of a row whose INTERVAL is 15
         * bytes: no NULL bitmap, the id's 8 bytes, then 15 (the row codec wants 16); its commitment and digest right */
        imdb_table *t = db->t[db->nt - 1];
        if (t->s.ncols != 2 || t->s.cols[1].type != IMDB_T_INTERVAL || (t->s.cols[1].flags & IMDB_COL_NULLABLE)) {
            fputs("imdb-forge: index-lie iv-short needs a last table (id INT64 PRIMARY KEY, iv INTERVAL NOT NULL)\n", stderr);
            exit(1);
        }
        static uint8_t row[8 + 15];
        imdb_le64(row, 999);
        memset(row + 8, 0x01, 15);
        memset(op.salt, 0x61, sizeof op.salt);
        op.code = IMDB_OP_INSERT;
        op.table = t->s.id;
        op.vid = t->nver;
        op.pkind = IMDB_PAYLOAD_ROW;
        op.row = row;
        op.row_len = sizeof row;
        op.iname = NULL;
        imdb_row_commit(t->s.id, op.salt, row, sizeof row, op.commit);
        imdb_lthash g = db->global;
        imdb_lthash_add_commit(db->meta.digest_alg, &g, op.commit);
        uint8_t dg[32];
        imdb_lthash_digest(db->meta.digest_alg, &g, dg);
        append_commit_digest(dir, db, &op, 1, &sg, NULL, dg);
        imdb_close(db);
        return;
    } else if (strcmp(kind, "enum-ord") == 0) {
        /* F3g (KA): an INSERT into the last table, (id INT64 PRIMARY KEY, m an ENUM NOT NULL), of a row whose ordinal is its
         * type's label count: no label; its commitment and digest right */
        imdb_table *t = db->t[db->nt - 1];
        const imdb_enumdef *d = t->s.ncols == 2 && t->s.cols[1].type == IMDB_T_ENUM ? imdb_enum_def(db, t->s.cols[1].eid) : NULL;
        if (!d || (t->s.cols[1].flags & IMDB_COL_NULLABLE)) {
            fputs("imdb-forge: index-lie enum-ord needs a last table (id INT64 PRIMARY KEY, m an ENUM NOT NULL)\n", stderr);
            exit(1);
        }
        static uint8_t row[8 + 4];
        imdb_le64(row, 999);
        row[8] = (uint8_t)d->n, row[9] = (uint8_t)(d->n >> 8), row[10] = row[11] = 0;
        memset(op.salt, 0x61, sizeof op.salt);
        op.code = IMDB_OP_INSERT;
        op.table = t->s.id;
        op.vid = t->nver;
        op.pkind = IMDB_PAYLOAD_ROW;
        op.row = row;
        op.row_len = sizeof row;
        op.iname = NULL;
        imdb_row_commit(t->s.id, op.salt, row, sizeof row, op.commit);
        imdb_lthash g = db->global;
        imdb_lthash_add_commit(db->meta.digest_alg, &g, op.commit);
        uint8_t dg[32];
        imdb_lthash_digest(db->meta.digest_alg, &g, dg);
        append_commit_digest(dir, db, &op, 1, &sg, NULL, dg);
        imdb_close(db);
        return;
    } else if (strcmp(kind, "create-enum-unknown") == 0 || strcmp(kind, "create-enum-dropped") == 0) {
        /* F3g (KB, KC): CREATE TABLE kb (id INT64 PRIMARY KEY, m ...) with its retention, m an ENUM of a type id no type has,
         * or of the last dropped type's */
        uint32_t eid = db->nenums + 7;
        if (kind[12] == 'd') {
            eid = 0;
            for (uint32_t i = 0; i < db->nenums; i++)
                if (db->enums[i].dropped_at) eid = i + 1;
            if (!eid) {
                fputs("imdb-forge: index-lie create-enum-dropped needs a dropped type\n", stderr);
                exit(1);
            }
        }
        static imdb_schema s;
        memset(&s, 0, sizeof s);
        snprintf(s.name, sizeof s.name, "kb");
        s.id = db->nt;
        s.ncols = 2;
        s.subject = -1;
        snprintf(s.cols[0].name, sizeof s.cols[0].name, "id");
        s.cols[0].type = IMDB_T_INT64;
        s.cols[0].flags = IMDB_COL_PK;
        snprintf(s.cols[1].name, sizeof s.cols[1].name, "m");
        s.cols[1].type = IMDB_T_ENUM;
        s.cols[1].eid = (uint16_t)eid;
        s.cols[1].flags = IMDB_COL_NULLABLE;
        s.npk = 1;
        s.key[0] = 0;
        imdb_op ops[2];
        memset(ops, 0, sizeof ops);
        ops[0] = (imdb_op){.code = IMDB_OP_CREATE_TABLE, .table = s.id, .schema = &s};
        ops[1] = (imdb_op){.code = IMDB_OP_SET_RETENTION, .table = s.id, .retention_us = IMDB_RETAIN_DEFAULT_US};
        append_commit(dir, db, ops, 2, &sg, NULL);
        imdb_close(db);
        return;
    } else if (strcmp(kind, "erase-role-live") == 0 || strcmp(kind, "erase-role-commit") == 0 || strcmp(kind, "erase-role-part") == 0) {
        /* L stage 2 (LM, LN): a signed ERASE of role entries alone, on a directory of l_db's, its manifest planned as the
         * writer plans one (the entry doomed): -live names alice's current name (a live role's: never erased), -commit
         * names the dropped gone's current name under another commitment, -part the dropped gone2's name alone (it holds a
         * verifier too: a part of its entries) */
        bool live = kind[11] == 'l';
        bool part = kind[11] == 'p';
        imdb_role *r = imdb_rcat_by_id(&db->rc, live ? 1 : part ? 4 : 3);
        if (!r) {
            fputs("imdb-forge: index-lie erase-role-*: a directory of l_db's (alice 1, gone 3, gone2 4)\n", stderr);
            exit(1);
        }
        imdb_rerase x = {.role = r->id, .seq = r->nent.at, .what = IMDB_RPAY_NAME};
        memcpy(x.commit, r->nent.commit, 32);
        imdb_role_doom(&db->rc, &x, 1);
        imdb_rewrite *rw = NULL;
        uint32_t nrw = 0;
        uint8_t man[32];
        imdb_err e = {0};
        if (imdb_lake_plan_erase(db, NULL, 0, &rw, &nrw, man, &e)) die("plan", &e);
        imdb_role_undoom(&db->rc);
        if (!live && !part) x.commit[0] ^= 1;
        op.code = IMDB_OP_ERASE;
        op.iname = NULL;
        memcpy(op.manifest, man, 32);
        op.rerase = &x;
        op.n_rerase = 1;
        append_commit(dir, db, &op, 1, &sg, NULL);
        op.rerase = NULL;
        imdb_free(rw);
        imdb_close(db);
        return;
    } else if (strncmp(kind, "role-", 5) == 0 || strncmp(kind, "grant-", 6) == 0 || strcmp(kind, "drop-role-granted") == 0 ||
               strcmp(kind, "member-cycle") == 0) {
        /* L (LA-LL): a signed role op past one of its rules, on a directory of l_db's (audit_reject.sh): roles alice (1, LOGIN,
         * a password, a member of staff), staff (2, SELECT on t), gone (3, dropped); tables t (0) and old (1, dropped) */
        static imdb_roleop ro;
        static imdb_grant_rec g;
        memset(&ro, 0, sizeof ro);
        memset(&g, 0, sizeof g);
        uint32_t next = db->rc.last + 1;
        const char *name = NULL, *as = NULL;
        op.iname = NULL;
        op.ro = &ro;
        if (strcmp(kind, "role-reserved") == 0) name = "public";                      /* LA */
        else if (strcmp(kind, "role-taken") == 0) name = "alice";                     /* LB */
        else if (strcmp(kind, "role-commitment") == 0) name = "zed", as = "zee";      /* LI: the payload not its commitment's */
        else if (strcmp(kind, "role-redacted") == 0) name = "zed";                    /* LK */
        if (name) {
            op.code = IMDB_OP_CREATE_ROLE;
            ro.rid = next;
            ro.rfields = IMDB_RF_ATTRS | IMDB_RF_NAME;
            ro.rname.pkind = strcmp(kind, "role-redacted") ? IMDB_PAYLOAD_ROW : IMDB_PAYLOAD_REDACTED;
            memset(ro.rname.salt, 7, 16);
            ro.rname.bytes = (const uint8_t *)name;
            ro.rname.len = (uint32_t)strlen(name);
            imdb_role_commit(next, IMDB_RPAY_NAME, ro.rname.salt, (const uint8_t *)(as ? as : name), (uint32_t)strlen(as ? as : name),
                             ro.rname.commit);
        } else if (strcmp(kind, "role-rename-taken") == 0) { /* LC: staff renamed alice */
            op.code = IMDB_OP_ALTER_ROLE;
            ro.rid = 2;
            ro.rfields = IMDB_RF_NAME;
            ro.rname.pkind = IMDB_PAYLOAD_ROW;
            memset(ro.rname.salt, 7, 16);
            ro.rname.bytes = (const uint8_t *)"alice";
            ro.rname.len = 5;
            imdb_role_commit(2, IMDB_RPAY_NAME, ro.rname.salt, ro.rname.bytes, 5, ro.rname.commit);
        } else if (strcmp(kind, "role-noop") == 0) { /* LL: alice's attributes set to what they are */
            op.code = IMDB_OP_ALTER_ROLE;
            ro.rid = 1;
            ro.rfields = IMDB_RF_ATTRS;
            ro.rattrs = IMDB_RA_LOGIN;
        } else if (strcmp(kind, "drop-role-granted") == 0) { /* LF: staff holds SELECT on t */
            op.code = IMDB_OP_DROP_ROLE;
            ro.rid = 2;
        } else {
            op.code = IMDB_OP_GRANT;
            ro.grants = &g;
            ro.ngrants = 1;
            g = (imdb_grant_rec){.kind = IMDB_GRANT_PRIV, .okind = IMDB_OBJ_TABLE, .a = 2, .b = 0, .privs = IMDB_PRIV_SELECT}; /* LH */
            if (strcmp(kind, "grant-dropped-role") == 0) g.a = 3;                                   /* LD */
            else if (strcmp(kind, "grant-dropped-table") == 0) g.a = 1, g.b = 1;                    /* LE */
            else if (strcmp(kind, "member-cycle") == 0)                                              /* LG */
                g = (imdb_grant_rec){.kind = IMDB_GRANT_MEMBER, .a = 2, .b = 1}; /* staff into alice, who is in staff */
            else if (strcmp(kind, "grant-held") != 0) {
                fputs("imdb-forge: index-lie role-reserved | role-taken | role-rename-taken | role-commitment | role-redacted |"
                      " role-noop | drop-role-granted | grant-dropped-role | grant-dropped-table | grant-held | member-cycle\n", stderr);
                exit(1);
            }
        }
        append_commit(dir, db, &op, 1, &sg, NULL);
        op.ro = NULL;
        imdb_close(db);
        return;
    } else if (strcmp(kind, "enum-drop-used") == 0 || strcmp(kind, "enum-add-dup") == 0) {
        /* F3g (KD, KE): DROP TYPE of the type the last table's column 1 has; ADD VALUE of that type's first label */
        imdb_table *t = db->t[db->nt - 1];
        const imdb_enumdef *d = t->s.ncols >= 2 && t->s.cols[1].type == IMDB_T_ENUM ? imdb_enum_def(db, t->s.cols[1].eid) : NULL;
        if (!d || !d->n) {
            fputs("imdb-forge: index-lie enum-drop-used and enum-add-dup need a last table whose column 1 is an ENUM of labels\n", stderr);
            exit(1);
        }
        static char lab[IMDB_MAX_ENUM_LABEL + 1];
        memcpy(lab, d->text + d->off[0], d->off[1] - d->off[0]);
        lab[d->off[1] - d->off[0]] = 0;
        op.code = kind[5] == 'd' ? IMDB_OP_DROP_ENUM : IMDB_OP_ENUM_ADD;
        op.eid = d->id;
        op.aname = op.code == IMDB_OP_ENUM_ADD ? lab : NULL;
        op.iname = NULL;
        append_commit(dir, db, &op, 1, &sg, NULL);
        op.aname = NULL;
        imdb_close(db);
        return;
    } else if (strcmp(kind, "enum-default-ord") == 0) {
        /* F3g (KG): ADD COLUMN kg (the type of the last table's column 1, NULL) with a DEFAULT whose ordinal is the type's
         * label count: every older row's missing value, no label */
        imdb_table *t = db->t[db->nt - 1];
        const imdb_enumdef *d = t->s.ncols >= 2 && t->s.cols[1].type == IMDB_T_ENUM ? imdb_enum_def(db, t->s.cols[1].eid) : NULL;
        if (!d) {
            fputs("imdb-forge: index-lie enum-default-ord needs a last table whose column 1 is an ENUM\n", stderr);
            exit(1);
        }
        op.code = IMDB_OP_ALTER_TABLE;
        op.table = t->s.id;
        op.akind = IMDB_ALTER_ADD_COLUMN;
        snprintf(op.acol.name, sizeof op.acol.name, "kg");
        op.acol.type = IMDB_T_ENUM;
        op.acol.eid = (uint16_t)d->id;
        op.acol.flags = IMDB_COL_NULLABLE;
        op.adef = (imdb_value){.type = IMDB_T_ENUM, .i = d->n};
        op.adef.eid = d->id;
        op.iname = NULL;
    } else if (strcmp(kind, "create-interval-key") == 0) {
        /* F3f: CREATE TABLE jb (jbkey TIMESTAMP PRIMARY KEY, n INT64) with its retention, the key's type byte then made
         * INTERVAL (12): a key the schema check refuses (deferred.md D26) */
        static imdb_schema s;
        memset(&s, 0, sizeof s);
        snprintf(s.name, sizeof s.name, "jb");
        s.id = db->nt;
        s.ncols = 2;
        s.subject = -1;
        snprintf(s.cols[0].name, sizeof s.cols[0].name, "jbkey");
        s.cols[0].type = IMDB_T_TIMESTAMP;
        s.cols[0].flags = IMDB_COL_PK;
        snprintf(s.cols[1].name, sizeof s.cols[1].name, "n");
        s.cols[1].type = IMDB_T_INT64;
        s.cols[1].flags = IMDB_COL_NULLABLE;
        s.npk = 1;
        s.key[0] = 0;
        imdb_op ops[2];
        memset(ops, 0, sizeof ops);
        ops[0] = (imdb_op){.code = IMDB_OP_CREATE_TABLE, .table = s.id, .schema = &s};
        ops[1] = (imdb_op){.code = IMDB_OP_SET_RETENTION, .table = s.id, .retention_us = IMDB_RETAIN_DEFAULT_US};
        static const uint8_t pat[] = {5, 'j', 'b', 'k', 'e', 'y', IMDB_T_TIMESTAMP, 0, 0, IMDB_COL_PK};
        g_find = pat;
        g_find_len = sizeof pat;
        g_at = 6;
        g_to = IMDB_T_INTERVAL;
        append_commit(dir, db, ops, 2, &sg, NULL);
        imdb_close(db);
        return;
    } else if (strcmp(kind, "dec-range") == 0) {
        /* F3e: an INSERT into the last table, (id INT64 PRIMARY KEY, w DECIMAL(30,2) NOT NULL), of a row whose w is 10^28:
         * past its precision by one (the row codec's 16 bytes, i then hi, of its scaled 10^30); commitment and digest
         * right */
        imdb_table *t = db->t[db->nt - 1];
        if (t->s.ncols != 2 || t->s.cols[1].type != IMDB_T_DECIMAL || t->s.cols[1].precision != 30 ||
            t->s.cols[1].scale != 2 || (t->s.cols[1].flags & IMDB_COL_NULLABLE)) {
            fputs("imdb-forge: index-lie dec-range needs a last table (id INT64 PRIMARY KEY, w DECIMAL(30,2) NOT NULL)\n", stderr);
            exit(1);
        }
        static uint8_t row[8 + 16];
        imdb_le64(row, 999);
        unsigned __int128 x = (unsigned __int128)imdb_pow10_128(30); /* scaled 10^30: 10^28.00, one past 9999999999999999999999999999.99 */
        imdb_le64(row + 8, (uint64_t)x);
        imdb_le64(row + 16, (uint64_t)(x >> 64));
        memset(op.salt, 0x60, sizeof op.salt);
        op.code = IMDB_OP_INSERT;
        op.table = t->s.id;
        op.vid = t->nver;
        op.pkind = IMDB_PAYLOAD_ROW;
        op.row = row;
        op.row_len = sizeof row;
        op.iname = NULL;
        imdb_row_commit(t->s.id, op.salt, row, sizeof row, op.commit);
        imdb_lthash g = db->global;
        imdb_lthash_add_commit(db->meta.digest_alg, &g, op.commit);
        uint8_t dg[32];
        imdb_lthash_digest(db->meta.digest_alg, &g, dg);
        append_commit_digest(dir, db, &op, 1, &sg, NULL, dg);
        imdb_close(db);
        return;
    } else if (strcmp(kind, "create-default-clock") == 0 || strcmp(kind, "create-default-uuid") == 0) {
        /* F2a: CREATE TABLE dz (id INT64 PRIMARY KEY, at TIMESTAMPTZ) with its retention and op 23 giving at
         * CURRENT_TIMESTAMP, which the encoder takes; the kind byte then made LOCALTIME (5), a TIME's clock; F3d
         * (create-default-uuid): made 10, gen_random_uuid, a UUID column's alone */
        static imdb_schema s;
        memset(&s, 0, sizeof s);
        snprintf(s.name, sizeof s.name, "dz");
        s.id = db->nt;
        s.ncols = 2;
        s.subject = -1;
        snprintf(s.cols[0].name, sizeof s.cols[0].name, "id");
        s.cols[0].type = IMDB_T_INT64;
        s.cols[0].flags = IMDB_COL_PK;
        snprintf(s.cols[1].name, sizeof s.cols[1].name, "at");
        s.cols[1].type = IMDB_T_TIMESTAMPTZ;
        s.cols[1].flags = IMDB_COL_NULLABLE;
        s.npk = 1;
        s.key[0] = 0;
        static imdb_coldef cd = {.col = 1, .kind = IMDB_DEFK_CURRENT_TIMESTAMP};
        imdb_op ops[3];
        memset(ops, 0, sizeof ops);
        ops[0] = (imdb_op){.code = IMDB_OP_CREATE_TABLE, .table = s.id, .schema = &s};
        ops[1] = (imdb_op){.code = IMDB_OP_SET_RETENTION, .table = s.id, .retention_us = IMDB_RETAIN_DEFAULT_US};
        ops[2] = (imdb_op){.code = IMDB_OP_COLUMN_DEFAULTS, .table = s.id, .defs = &cd, .ndefs = 1};
        static uint8_t pat[10];
        pat[0] = IMDB_OP_COLUMN_DEFAULTS;
        imdb_le32(pat + 1, s.id);
        pat[5] = 1; /* u16 n, u16 column 1, the kind */
        pat[7] = 1;
        pat[9] = IMDB_DEFK_CURRENT_TIMESTAMP;
        g_find = pat;
        g_find_len = sizeof pat;
        g_at = 9;
        g_to = strcmp(kind, "create-default-uuid") == 0 ? IMDB_DEFK_RANDOM_UUID : IMDB_DEFK_LOCALTIME;
        append_commit(dir, db, ops, 3, &sg, NULL);
        imdb_close(db);
        return;
    } else if (strcmp(kind, "alter-clock-type") == 0) { /* F2a: SET DEFAULT CURRENT_DATE (kind 10) on table 0's first TEXT
                                                         * column: a clock its type does not take (the history's rule) */
        imdb_table *t = db->t[0];
        int c = -1;
        for (uint16_t k = 0; k < t->s.ncols && c < 0; k++)
            if (t->s.cols[k].type == IMDB_T_TEXT) c = k;
        if (c < 0) {
            fputs("imdb-forge: index-lie alter-clock-type needs a TEXT column in table 0\n", stderr);
            exit(1);
        }
        op.code = IMDB_OP_ALTER_TABLE;
        op.table = t->s.id;
        op.akind = IMDB_ALTER_SET_DEFAULT_CLOCK;
        op.apos = t->hist.vers[t->hist.nvers - 1].pos[c];
        op.aclock = IMDB_DEFK_CURRENT_DATE;
        op.iname = NULL;
    } else if (strcmp(kind, "check-add") == 0) { /* F2b-1: ADD CHECK forged (a > 100) to table 0, which a live row fails */
        static imdb_check fc = {.name = "forged", .len = 7, .text = "a > 100"};
        op.code = IMDB_OP_ALTER_TABLE;
        op.table = db->t[0]->s.id;
        op.akind = IMDB_ALTER_ADD_CHECK;
        op.chk = &fc;
        op.nchk = 1;
        op.iname = NULL;
    } else if (strcmp(kind, "check-row") == 0) { /* F2b-1: an INSERT into the last table of a live row's values under a new INT64
                                                * key, its column a -1 (the test's CHECK (a > 0) refuses it), its digest right */
        imdb_table *t = db->t[db->nt - 1];
        uint64_t src = IMDB_NONE;
        int64_t maxpk = 0;
        for (uint64_t vid = imdb_v_next(t, 0); vid < t->nver; vid = imdb_v_next(t, vid + 1)) {
            imdb_value k;
            if (imdb_vh(t, vid)->end != IMDB_LIVE || imdb_version_key(t, vid, t->s.key[0], &k) != IMDB_OK) continue;
            if (src == IMDB_NONE) src = vid;
            if (k.i > maxpk) maxpk = k.i;
        }
        imdb_value vals[IMDB_MAX_COLS];
        imdb_err e = {0};
        int ac = imdb_schema_col(&t->s, "a");
        if (src == IMDB_NONE || ac < 0 || t->s.npk != 1 || imdb_version_values(db, t, src, vals, &e)) {
            fputs("imdb-forge: index-lie check-row needs a live row and an INT64 column a in the last table\n", stderr);
            exit(1);
        }
        vals[t->s.key[0]].i = maxpk + 1;
        vals[ac].null = false;
        vals[ac].i = -1;
        static imdb_buf row;
        imdb_buf_init(&row);
        if (imdb_row_encode(&t->s, vals, &row, &e) || imdb_buf_check(&row, &e)) die("row", &e);
        memset(op.salt, 0x5c, sizeof op.salt);
        op.code = IMDB_OP_INSERT;
        op.table = t->s.id;
        op.vid = t->nver;
        op.pkind = IMDB_PAYLOAD_ROW;
        op.row = row.p;
        op.row_len = (uint32_t)row.len;
        op.iname = NULL;
        imdb_row_commit(t->s.id, op.salt, row.p, row.len, op.commit);
        imdb_lthash g = db->global;
        imdb_lthash_add_commit(db->meta.digest_alg, &g, op.commit);
        uint8_t dg[32];
        imdb_lthash_digest(db->meta.digest_alg, &g, dg);
        append_commit_digest(dir, db, &op, 1, &sg, NULL, dg);
        imdb_close(db);
        return;
    } else if (strcmp(kind, "fk-orphan") == 0) {
        /* F2b-2: an INSERT into the last table of a live row's values under a new INT64 key, its INT64 column pid 999
         * (no parent holds it), its digest right */
        imdb_table *t = db->t[db->nt - 1];
        uint64_t src = IMDB_NONE;
        int64_t maxpk = 0;
        for (uint64_t vid = imdb_v_next(t, 0); vid < t->nver; vid = imdb_v_next(t, vid + 1)) {
            imdb_value k;
            if (imdb_vh(t, vid)->end != IMDB_LIVE || imdb_version_key(t, vid, t->s.key[0], &k) != IMDB_OK) continue;
            if (src == IMDB_NONE) src = vid;
            if (k.i > maxpk) maxpk = k.i;
        }
        imdb_value vals[IMDB_MAX_COLS];
        imdb_err e = {0};
        int pc = imdb_schema_col(&t->s, "pid");
        if (src == IMDB_NONE || pc < 0 || t->s.npk != 1 || imdb_version_values(db, t, src, vals, &e)) {
            fputs("imdb-forge: index-lie fk-orphan needs a live row and an INT64 column pid in the last table\n", stderr);
            exit(1);
        }
        vals[t->s.key[0]].i = maxpk + 1;
        vals[pc].null = false;
        vals[pc].i = 999;
        static imdb_buf row;
        imdb_buf_init(&row);
        if (imdb_row_encode(&t->s, vals, &row, &e) || imdb_buf_check(&row, &e)) die("row", &e);
        memset(op.salt, 0x5e, sizeof op.salt);
        op.code = IMDB_OP_INSERT;
        op.table = t->s.id;
        op.vid = t->nver;
        op.pkind = IMDB_PAYLOAD_ROW;
        op.row = row.p;
        op.row_len = (uint32_t)row.len;
        op.iname = NULL;
        imdb_row_commit(t->s.id, op.salt, row.p, row.len, op.commit);
        imdb_lthash g = db->global;
        imdb_lthash_add_commit(db->meta.digest_alg, &g, op.commit);
        uint8_t dg[32];
        imdb_lthash_digest(db->meta.digest_alg, &g, dg);
        append_commit_digest(dir, db, &op, 1, &sg, NULL, dg);
        imdb_close(db);
        return;
    } else if (strcmp(kind, "fk-delete") == 0) {
        /* F2b-2: a DELETE of table 0's first live row (a parent a live child references), its digest right */
        imdb_table *t = db->t[0];
        uint64_t src = IMDB_NONE;
        for (uint64_t vid = imdb_v_next(t, 0); vid < t->nver && src == IMDB_NONE; vid = imdb_v_next(t, vid + 1))
            if (imdb_vh(t, vid)->end == IMDB_LIVE) src = vid;
        const uint8_t *oc = NULL;
        imdb_err e = {0};
        if (src == IMDB_NONE || imdb_v_commit(t, src, &oc, &e)) {
            fputs("imdb-forge: index-lie fk-delete needs a live row in table 0\n", stderr);
            exit(1);
        }
        op.code = IMDB_OP_DELETE;
        op.table = t->s.id;
        op.vid = src;
        memcpy(op.commit, oc, 32);
        op.iname = NULL;
        imdb_lthash g = db->global;
        imdb_lthash_sub_commit(db->meta.digest_alg, &g, op.commit);
        uint8_t dg[32];
        imdb_lthash_digest(db->meta.digest_alg, &g, dg);
        append_commit_digest(dir, db, &op, 1, &sg, NULL, dg);
        imdb_close(db);
        return;
    } else if (strcmp(kind, "fk-erase-other") == 0 || strcmp(kind, "fk-erase-named") == 0) {
        /* F2b-2: one commit of a DELETE of table 0's first live row (a parent a live child references) and an ERASE
         * that names that row (-named: the ERASE's own delete, which no parent check refuses) or the last table's first
         * ended version (-other: the delete is not the ERASE's, so the parent check stands). Made as the writer makes
         * one: the ERASE's manifest planned over the commit's DELETE (imdb_lake_plan_erase reads the pending ops; every
         * publish flushes the memtable, so the deleted row's end is the commit's while it plans), the digest right, and
         * the erased version's payload redacted in the log afterwards (each verifier wants an erasure complete) */
        bool named = kind[9] == 'n';
        imdb_table *t = db->t[0], *xt = named ? t : db->t[db->nt - 1];
        uint64_t live = IMDB_NONE, ended = IMDB_NONE;
        for (uint64_t vid = imdb_v_next(t, 0); vid < t->nver && live == IMDB_NONE; vid = imdb_v_next(t, vid + 1))
            if (imdb_vh(t, vid)->end == IMDB_LIVE) live = vid;
        for (uint64_t vid = imdb_v_next(xt, 0); !named && vid < xt->nver && ended == IMDB_NONE; vid = imdb_v_next(xt, vid + 1))
            if (imdb_vh(xt, vid)->end != IMDB_LIVE && !(imdb_vh(xt, vid)->flags & IMDB_V_STUB)) ended = vid;
        const uint8_t *cm = NULL;
        uint8_t lc[32], ec[32];
        imdb_err e = {0};
        if (live == IMDB_NONE || (!named && ended == IMDB_NONE) || imdb_v_commit(t, live, &cm, &e)) {
            fputs("imdb-forge: index-lie fk-erase-* needs a live row in table 0 (and, for -other, an ended version in the "
                  "last table)\n", stderr);
            exit(1);
        }
        memcpy(lc, cm, 32);
        if (!named) {
            if (imdb_v_commit(xt, ended, &cm, &e)) die("commitment", &e);
            memcpy(ec, cm, 32);
        }
        imdb_op ops[2];
        memset(ops, 0, sizeof ops);
        ops[0].code = IMDB_OP_DELETE;
        ops[0].table = t->s.id;
        ops[0].vid = live;
        memcpy(ops[0].commit, lc, 32);
        imdb_erase_ent ent;
        memset(&ent, 0, sizeof ent);
        ent.table = xt->s.id;
        ent.vid = named ? live : ended;
        memcpy(ent.commit, named ? lc : ec, 32);
        uint64_t ebegin = imdb_vh(xt, ent.vid)->begin;
        imdb_op *stx = db->tx;
        uint32_t sntx = db->ntx;
        db->tx = ops; /* the plan's digests are the commit's, its DELETE pending, as in the writer's ERASE */
        db->ntx = 1;
        imdb_vh(t, live)->end = db->seq + 1; /* and the live count the manifest records, as imdb_delete leaves them */
        t->live--;
        imdb_rewrite *rw = NULL;
        uint32_t nrw = 0;
        uint8_t man[32];
        int prc = imdb_lake_plan_erase(db, &ent, 1, &rw, &nrw, man, &e);
        imdb_vh(t, live)->end = IMDB_LIVE;
        t->live++;
        db->tx = stx;
        db->ntx = sntx;
        if (prc) die("plan", &e);
        ops[1].code = IMDB_OP_ERASE;
        memcpy(ops[1].manifest, man, 32);
        ops[1].erase = &ent;
        ops[1].n_erase = 1;
        ops[1].rewrites = rw;
        ops[1].n_rewrites = nrw;
        imdb_lthash g = db->global;
        imdb_lthash_sub_commit(db->meta.digest_alg, &g, lc);
        uint8_t dg[32];
        imdb_lthash_digest(db->meta.digest_alg, &g, dg);
        append_commit_digest(dir, db, ops, 2, &sg, NULL, dg);
        imdb_free(rw);
        uint64_t first = db->segs[0]; /* the segment of the erased version's commit: the last to begin at or before it */
        for (size_t k = 0; k < db->nsegs; k++)
            if (db->segs[k] <= ebegin) first = db->segs[k];
        char seg[700];
        snprintf(seg, sizeof seg, "%s/log/%020llu.ilg", dir, (unsigned long long)first);
        size_t sn;
        uint8_t *sb = seg_read(seg, &sn);
        imdb_buf out;
        imdb_buf_init(&out);
        struct redact_ver x = {&out, ent.table, ent.vid, 0};
        each_frame(sb, sn, redact_ver_one, &x);
        if (x.hits != 1 || out.err) {
            fputs("imdb-forge: index-lie fk-erase-*: the erased version's payload is not in one frame\n", stderr);
            exit(1);
        }
        seg_write(seg, out.p, out.len);
        free(sb);
        imdb_buf_free(&out);
        imdb_close(db);
        return;
    } else if (strcmp(kind, "gen-row") == 0 || strcmp(kind, "gen-update") == 0) {
        /* F2c: a row of the last table whose generated column w holds one more than its expression gives (the test's
         * w GENERATED ALWAYS AS (a * 2)), its digest right: gen-row an INSERT of a live row's values under a new INT64
         * key, gen-update an UPDATE of that row (op 4: the old commitment out of the digest, the new one in) */
        bool upd = kind[4] == 'u';
        imdb_table *t = db->t[db->nt - 1];
        uint64_t src = IMDB_NONE;
        int64_t maxpk = 0;
        for (uint64_t vid = imdb_v_next(t, 0); vid < t->nver; vid = imdb_v_next(t, vid + 1)) {
            imdb_value k;
            if (imdb_vh(t, vid)->end != IMDB_LIVE || imdb_version_key(t, vid, t->s.key[0], &k) != IMDB_OK) continue;
            if (src == IMDB_NONE) src = vid;
            if (k.i > maxpk) maxpk = k.i;
        }
        imdb_value vals[IMDB_MAX_COLS];
        imdb_err e = {0};
        int wc = imdb_schema_col(&t->s, "w");
        const uint8_t *oc = NULL;
        if (src == IMDB_NONE || wc < 0 || t->s.npk != 1 || imdb_version_values(db, t, src, vals, &e) || vals[wc].null ||
            (upd && imdb_v_commit(t, src, &oc, &e))) {
            fputs("imdb-forge: index-lie gen-row and gen-update need a live row with a non-NULL INT64 column w in the last "
                  "table\n", stderr);
            exit(1);
        }
        if (!upd) vals[t->s.key[0]].i = maxpk + 1;
        vals[wc].i += 1;
        static imdb_buf row;
        imdb_buf_init(&row);
        if (imdb_row_encode(&t->s, vals, &row, &e) || imdb_buf_check(&row, &e)) die("row", &e);
        memset(op.salt, 0x5d, sizeof op.salt);
        op.code = upd ? IMDB_OP_UPDATE : IMDB_OP_INSERT;
        op.table = t->s.id;
        op.pkind = IMDB_PAYLOAD_ROW;
        op.row = row.p;
        op.row_len = (uint32_t)row.len;
        op.iname = NULL;
        imdb_lthash g = db->global;
        if (upd) {
            op.vid = src;
            memcpy(op.commit, oc, 32);
            op.new_vid = t->nver;
            imdb_row_commit(t->s.id, op.salt, row.p, row.len, op.new_commit);
            imdb_lthash_sub_commit(db->meta.digest_alg, &g, op.commit);
            imdb_lthash_add_commit(db->meta.digest_alg, &g, op.new_commit);
        } else {
            op.vid = t->nver;
            imdb_row_commit(t->s.id, op.salt, row.p, row.len, op.commit);
            imdb_lthash_add_commit(db->meta.digest_alg, &g, op.commit);
        }
        uint8_t dg[32];
        imdb_lthash_digest(db->meta.digest_alg, &g, dg);
        append_commit_digest(dir, db, &op, 1, &sg, NULL, dg);
        imdb_close(db);
        return;
    } else if (strcmp(kind, "pk-dup") == 0) { /* F4: an INSERT repeating a live row's whole key (the last table), its digest right */
        imdb_table *t = db->t[db->nt - 1];
        uint64_t src = IMDB_NONE;
        for (uint64_t vid = imdb_v_next(t, 0); vid < t->nver && src == IMDB_NONE; vid = imdb_v_next(t, vid + 1))
            if (imdb_vh(t, vid)->end == IMDB_LIVE) src = vid;
        imdb_value vals[IMDB_MAX_COLS];
        imdb_err e = {0};
        if (src == IMDB_NONE || imdb_version_values(db, t, src, vals, &e)) {
            fputs("imdb-forge: index-lie pk-dup needs a live row in the last table\n", stderr);
            exit(1);
        }
        static imdb_buf row;
        imdb_buf_init(&row);
        if (imdb_row_encode(&t->s, vals, &row, &e) || imdb_buf_check(&row, &e)) die("row", &e);
        memset(op.salt, 0x5b, sizeof op.salt); /* another salt: another commitment, the same key */
        op.code = IMDB_OP_INSERT;
        op.table = t->s.id;
        op.vid = t->nver;
        op.pkind = IMDB_PAYLOAD_ROW;
        op.row = row.p;
        op.row_len = (uint32_t)row.len;
        op.iname = NULL;
        imdb_row_commit(t->s.id, op.salt, row.p, row.len, op.commit);
        imdb_lthash g = db->global;
        imdb_lthash_add_commit(db->meta.digest_alg, &g, op.commit);
        uint8_t dg[32];
        imdb_lthash_digest(db->meta.digest_alg, &g, dg);
        append_commit_digest(dir, db, &op, 1, &sg, NULL, dg);
        imdb_close(db);
        return;
    } else {
        fputs("imdb-forge: index-lie DIR column | duplicate (needs an index) | drop-absent | unique-dup (needs a unique index) | "
              "pk-dup (a live row in the last table) | alter-view (ADD COLUMN k to table 0) | alter-not-null | "
              "alter-drop-indexed | date-range (a DATE column and an INT64 key in the last table) | varchar-long (a VARCHAR(n <= 200)) | alter-varchar-default | create-default-clock | alter-clock-type (a TEXT column in table 0) | seq-back | seq-drop-owned | "
              "check-add (ADD CHECK forged: a > 100, to table 0) | check-row (a -1 in the last table's column a) | "
              "gen-row | gen-update (column w one past its expression in the last table) | "
              "fk-orphan (a child of no parent in the last table) | fk-delete (table 0's first live row) | "
              "fk-erase-other | fk-erase-named (that DELETE beside an ERASE of an ended version, or of the row itself) | erase-role-live |\n"
              "erase-role-commit | erase-role-part (L stage 2: an ERASE of alice's current name, of gone's under another\n"
              "commitment, of gone2's name alone) | dec-range (a\n"
              "DECIMAL(30,2) of 10^28 in the last table) | uuid-short (a\n"
              "UUID of 15 bytes in the last table) | create-default-uuid (gen_random_uuid on a TIMESTAMPTZ) | iv-short (an\n"
              "INTERVAL of 15 bytes in the last table) | create-interval-key (a CREATE whose key is an INTERVAL) |\n"
              "enum-ord | enum-drop-used | enum-add-dup | enum-default-ord (the last table (id, m an ENUM)) | create-enum-unknown |\n"
              "create-enum-dropped\n", stderr);
        exit(1);
    }
    append_commit(dir, db, &op, 1, &sg, NULL);
    imdb_close(db);
}

/* P2 S7: a commit with a view op the log's rules forbid, signed by the writer, its state digest right: drop-table (the
 * DROP_TABLE of table 0, which a live view names), name (a CREATE_VIEW named as table 0), deps (a CREATE_VIEW of SELECT
 * id FROM table 0 that logs no dependency), type (the same view, its dependency logged, its column logged as TEXT;
 * P2 S7b: the engine's re-bind and the auditor's binder refuse both), drop-named (the DROP_VIEW of view 0, which a live
 * view names) */
static void view_lie(const char *dir, const char *kind)
{
    char p[1200];
    snprintf(p, sizeof p, "%s/signing.key", dir);
    size_t kn;
    uint8_t *seed = slurp(p, &kn);
    if (kn != IMDB_SEED_LEN) exit(1);
    imdb_signer sg;
    imdb_signer_init(&sg, seed);
    free(seed);
    imdb_db *db = open_ro(dir);
    if (!db->nt || !db->nviews) {
        fputs("imdb-forge: view-lie needs a table and a view\n", stderr);
        exit(1);
    }
    imdb_op op;
    memset(&op, 0, sizeof op);
    imdb_viewdef d;
    memset(&d, 0, sizeof d);
    imdb_viewcol col = {.type = IMDB_T_INT64};
    imdb_viewdep dep = {IMDB_VIEWDEP_TABLE, 0};
    char text[2 * IMDB_MAX_IDENT + 32];
    const imdb_table *t = db->t[0];
    if (strcmp(kind, "drop-table") == 0) {
        op.code = IMDB_OP_DROP_TABLE;
        op.table = 0;
        imdb_lthash g = db->global; /* all it held leaves the state: the digest the drop's commit records */
        imdb_lthash_sub(&g, &t->digest);
        uint8_t dg[32];
        imdb_lthash_digest(db->meta.digest_alg, &g, dg);
        append_commit_digest(dir, db, &op, 1, &sg, NULL, dg);
        imdb_close(db);
        return;
    } else if ((strcmp(kind, "name") == 0 || strcmp(kind, "deps") == 0 || strcmp(kind, "type") == 0) &&
               t->s.cols[0].type == IMDB_T_INT64) {
        op.code = IMDB_OP_CREATE_VIEW;
        d.id = db->nviews;
        snprintf(d.name, sizeof d.name, "%s", strcmp(kind, "name") == 0 ? t->s.name : strcmp(kind, "deps") == 0 ? "lie_deps" : "lie_type");
        snprintf(col.name, sizeof col.name, "%s", t->s.cols[0].name);
        d.ncols = 1;
        d.cols = &col;
        d.ndeps = strcmp(kind, "deps") != 0; /* deps: none logged, though the text reads the table */
        if (strcmp(kind, "type") == 0) col.type = IMDB_T_TEXT; /* the text yields INT64 */
        d.deps = &dep;
        snprintf(text, sizeof text, "SELECT %s FROM %s", t->s.cols[0].name, t->s.name);
        d.text = text;
        d.text_len = (uint32_t)strlen(text);
        op.vdef = &d;
    } else if (strcmp(kind, "drop-named") == 0 && db->nviews >= 2) {
        op.code = IMDB_OP_DROP_VIEW;
        op.view = 0;
    } else {
        fputs("imdb-forge: view-lie DIR drop-table | name | deps | type (table 0's first column INT64) | drop-named (two views)\n", stderr);
        exit(1);
    }
    append_commit(dir, db, &op, 1, &sg, NULL);
    imdb_close(db);
}

/* a key rotation signed by a key that is not the writer's */
static void rotate_foreign(const char *dir)
{
    imdb_db *db = open_ro(dir);
    uint8_t s[32];
    memset(s, 0x66, sizeof s);
    imdb_signer k;
    imdb_signer_init(&k, s);
    imdb_op op;
    memset(&op, 0, sizeof op);
    op.code = IMDB_OP_WRITER_KEY;
    op.epoch = imdb_current_epoch(db) + 1;
    memcpy(op.new_pk, k.pk, 32);
    op.how = IMDB_WRITER_ROTATE;
    append_commit(dir, db, &op, 1, &k, NULL);
    imdb_close(db);
}

/* a promotion the real root key certified, but for another history (another prev) */
static void promote_elsewhere(const char *dir, const char *rootfile)
{
    imdb_db *db = open_ro(dir);
    size_t n;
    uint8_t *seed = slurp(rootfile, &n);
    if (n != 32) {
        fputs("imdb-forge: the root key file must hold 32 bytes\n", stderr);
        exit(1);
    }
    imdb_signer root, nk;
    imdb_signer_init(&root, seed);
    free(seed);
    uint8_t s[32], other[32], ext[IMDB_BODY_EXT], pm[IMDB_PROMOTE_MSG_LEN];
    memset(s, 0x67, sizeof s);
    memset(other, 0x5c, sizeof other);
    imdb_signer_init(&nk, s);
    imdb_op op;
    memset(&op, 0, sizeof op);
    op.code = IMDB_OP_WRITER_KEY;
    op.epoch = imdb_current_epoch(db) + 1;
    memcpy(op.new_pk, nk.pk, 32);
    op.how = IMDB_WRITER_PROMOTE;
    imdb_le32(ext, op.epoch);
    memcpy(ext + 4, nk.pk, 32);
    imdb_promote_msg(db->db_id, op.epoch, db->seq + 1, other, nk.pk, pm);
    imdb_sign(&root, pm, sizeof pm, ext + 36);
    append_commit(dir, db, &op, 1, &nk, ext);
    imdb_close(db);
}

/* WRITERS with its first entry's signature altered and its CRC recomputed: only the proof of the
 * entry can catch it */
static void writers_resign(const char *dir)
{
    char p[700];
    snprintf(p, sizeof p, "%s/WRITERS", dir);
    size_t n;
    uint8_t *b = slurp(p, &n);
    if (n < 32 + 13) {
        fputs("imdb-forge: WRITERS has no entry\n", stderr);
        exit(1);
    }
    uint32_t hlen = imdb_get_le32(b + 28 + 9);
    size_t sig = 28 + 13 + (size_t)hlen;
    if (sig + 64 > n - 4) {
        fputs("imdb-forge: WRITERS entry out of range\n", stderr);
        exit(1);
    }
    b[sig + 7] ^= 0x10;
    imdb_le32(b + n - 4, imdb_kern()->crc32c(0, b, n - 4));
    spit(p, b, n);
    free(b);
}

int main(int argc, char **argv)
{
    if (argc == 3 && strcmp(argv[1], "damage-last") == 0) { /* the final frame's body checksum fails, where it lies */
        size_t n;
        uint8_t *b = slurp(argv[2], &n);
        if (!n) return 1;
        if (imdb_tseg_is_tagged(b, n)) {
            uint8_t *c = malloc(n);
            memcpy(c, b, n);
            const char *base = strrchr(argv[2], '/');
            uint64_t first = 0;
            size_t len = 0;
            imdb_tseg_end end;
            imdb_err e = {0};
            if (!imdb_logseg_parse(base ? base + 1 : argv[2], &first) ||
                imdb_tseg_scan(c, n, first, &len, &end, &e) != IMDB_SCAN_END || !end.frames) {
                fputs("imdb-forge: damage-last needs a tagged segment that ends cleanly\n", stderr);
                return 1;
            }
            uint64_t s = end.keep_bytes ? end.keep_sector : end.keep_sector - 1;
            b[s * IMDB_TSEG_SECTOR + 8 + (end.keep_bytes ? end.keep_bytes - 1 : IMDB_TSEG_PAYLOAD - 1)] ^= 1;
            free(c);
        } else {
            b[n - 1] ^= 1;
        }
        spit(argv[2], b, n);
        free(b);
        return 0;
    }
    if (argc == 4 && strcmp(argv[1], "merge-segments") == 0) { /* SEG2's frames after SEG1's, in SEG1; SEG2 gone */
        size_t a, c;
        uint8_t *x = seg_read(argv[2], &a), *y = seg_read(argv[3], &c);
        uint8_t *m = malloc(a + c);
        memcpy(m, x, a);
        memcpy(m + a, y, c);
        seg_write(argv[2], m, a + c);
        if (unlink(argv[3]) != 0) return 1;
        free(x);
        free(y);
        free(m);
        return 0;
    }
    if (argc == 3 && strcmp(argv[1], "redact-all") == 0) {
        size_t n;
        uint8_t *log = seg_read(argv[2], &n);
        imdb_buf out;
        imdb_buf_init(&out);
        each_frame(log, n, redact_one, &out);
        seg_write(argv[2], out.p, out.len);
        imdb_buf_free(&out);
        free(log);
        return 0;
    }
    if (argc == 3 && strcmp(argv[1], "lie-payload") == 0) {
        size_t n;
        uint8_t *log = seg_read(argv[2], &n);
        imdb_buf out;
        imdb_buf_init(&out);
        lpctx x = {&out, 0, 0, 0};
        each_frame(log, n, lie_payload_find, &x);
        if (!x.found) {
            fputs("imdb-forge: no frame with a row payload\n", stderr);
            return 1;
        }
        x.idx = 0;
        each_frame(log, n, lie_payload_one, &x);
        seg_write(argv[2], out.p, out.len);
        imdb_buf_free(&out);
        free(log);
        return 0;
    }
    if (argc == 3 && strcmp(argv[1], "lie-zonemap") == 0) {
        lie_zonemap(argv[2]);
        return 0;
    }
    if (argc == 3 && strcmp(argv[1], "durable-rewind") == 0) {
        durable_rewind(argv[2]);
        return 0;
    }
    if (argc == 3 && strcmp(argv[1], "lie-chunks") == 0) { /* F5: a chunk's SHA-256 lies, its file's name right */
        lie_chunks(argv[2], 0);
        return 0;
    }
    if (argc == 3 && strcmp(argv[1], "lie-name") == 0) { /* F5b: an honest segment under its whole file's hash */
        lie_chunks(argv[2], 1);
        return 0;
    }
    if (argc == 3 && strcmp(argv[1], "lie-format1") == 0) { /* F5b: a segment of F5a's format marker */
        lie_chunks(argv[2], 2);
        return 0;
    }
    if (argc == 3 && (!strcmp(argv[1], "lie-stub-text") || !strcmp(argv[1], "lie-stub-bool") || !strcmp(argv[1], "lie-stub-cell"))) {
        lie_row(argv[2], argv[1][9] == 't' ? 3 : argv[1][9] == 'b' ? 4 : 5); /* F5 */
        return 0;
    }
    if (argc == 3 && strcmp(argv[1], "lie-stub-null") == 0) { /* F5 */
        lie_row(argv[2], 2);
        return 0;
    }
    if (argc == 3 && strcmp(argv[1], "lie-stub") == 0) { /* F5 */
        lie_row(argv[2], 1);
        return 0;
    }
    if (argc == 3 && strcmp(argv[1], "lie-missing") == 0) { /* F1 */
        lie_row(argv[2], 0);
        return 0;
    }
    if (argc == 3 && strcmp(argv[1], "lie-tombstone") == 0) {
        lie_tombstone(argv[2]);
        return 0;
    }
    if (argc == 3 && strcmp(argv[1], "rotate-foreign") == 0) {
        rotate_foreign(argv[2]);
        return 0;
    }
    if (argc == 4 && strcmp(argv[1], "promote-elsewhere") == 0) {
        promote_elsewhere(argv[2], argv[3]);
        return 0;
    }
    if (argc == 3 && strcmp(argv[1], "writers-resign") == 0) {
        writers_resign(argv[2]);
        return 0;
    }
    if (argc == 4 && strcmp(argv[1], "manifest-lie") == 0) {
        manifest_lie(argv[2], argv[3]);
        return 0;
    }
    if (argc == 4 && strcmp(argv[1], "view-lie") == 0) { /* P2 S7 */
        view_lie(argv[2], argv[3]);
        return 0;
    }
    if (argc == 4 && strcmp(argv[1], "index-lie") == 0) {
        index_lie(argv[2], argv[3]);
        return 0;
    }
    if (argc == 4 && strcmp(argv[1], "alg-flip") == 0) { /* commit SEQ (the log's last, as used) under the other algorithm */
        resign_from(argv[2], strtoull(argv[3], NULL, 10), flip_alg, NULL);
        return 0;
    }
    if (argc == 4 && strcmp(argv[1], "corpus") == 0) {
        corpus(argv[2], argv[3]);
        return 0;
    }
    fputs("usage: imdb-forge lie-payload SEGMENT | redact-all SEGMENT | index-lie DIR KIND | view-lie DIR KIND | manifest-lie DIR KIND | lie-zonemap DIR | lie-chunks DIR | lie-tombstone DIR | lie-missing DIR | lie-stub DIR | lie-stub-null DIR | lie-stub-text DIR | lie-stub-bool DIR | lie-stub-cell DIR | durable-rewind DIR | "
          "rotate-foreign DIR | promote-elsewhere DIR ROOTKEY | writers-resign DIR | alg-flip DIR SEQ | corpus DIR OUT\n", stderr);
    return 2;
}
