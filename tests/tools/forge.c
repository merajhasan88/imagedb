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
 *   imdb-forge lie-zonemap <dir>           corrupt a zone map, then re-hash the segment,
 *                                          the manifest and LAKE_HEAD so all names match
 *   imdb-forge lie-tombstone <dir>         move a purged tombstone to another subject, re-hash the
 *                                          lake and re-sign the log from the snapshot's commit
 *                                          (a malicious or buggy writer: everything consistent)
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
        if (imdb_op_has_payload(c.ops[i].code)) {
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

static int obj_rename(int ofd, const char *old, const uint8_t *b, size_t n, const char *ext, char *newname)
{
    uint8_t h[32];
    imdb_sha256(b, n, h);
    imdb_hex(h, 32, newname);
    strcat(newname, ext);
    if (unlinkat(ofd, old, 0) != 0) return -1;
    int fd = openat(ofd, newname, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0 || write(fd, b, n) != (ssize_t)n) return -1;
    close(fd);
    return 0;
}

static void lie_zonemap(const char *dir)
{
    char p[1200];
    snprintf(p, sizeof p, "%s/LAKE_HEAD", dir);
    size_t hn;
    uint8_t *head = slurp(p, &hn);
    char *mpos = strstr((char *)head, "manifest ");
    if (!mpos) exit(1);
    char mhex[65];
    memcpy(mhex, mpos + 9, 64);
    mhex[64] = 0;
    snprintf(p, sizeof p, "%s/objects", dir);
    int ofd = open(p, O_RDONLY | O_DIRECTORY);
    DIR *d = fdopendir(dup(ofd));
    struct dirent *de;
    char segname[300] = {0};
    while ((de = readdir(d)))
        if (strstr(de->d_name, ".seg")) {
            snprintf(segname, sizeof segname, "%s", de->d_name);
            break;
        }
    closedir(d);
    snprintf(p, sizeof p, "%s/objects/%s", dir, segname);
    size_t sn;
    uint8_t *seg = slurp(p, &sn);
    uint32_t nsec = imdb_get_le32(seg + 56);
    const uint8_t *zd = seg + IMDB_SEG_HEADER + 24u * (nsec - 1);
    if (imdb_get_le32(zd) != SEG_ZONEMAP) exit(1);
    imdb_le64(seg + imdb_get_le64(zd + 8) + 16, 999999); /* max of column 0 is now a lie */
    char newseg[300], mfile[300], newman[300];
    if (obj_rename(ofd, segname, seg, sn, ".seg", newseg)) exit(1);
    snprintf(mfile, sizeof mfile, "%s.man", mhex);
    snprintf(p, sizeof p, "%s/objects/%s", dir, mfile);
    size_t mn;
    uint8_t *man = slurp(p, &mn);
    uint8_t oldh[32], newh[32];
    imdb_unhex(segname, 64, oldh, 32);
    imdb_unhex(newseg, 64, newh, 32);
    for (size_t i = 0; i + 32 <= mn; i++)
        if (memcmp(man + i, oldh, 32) == 0) memcpy(man + i, newh, 32);
    if (obj_rename(ofd, mfile, man, mn, ".man", newman)) exit(1);
    memcpy(mpos + 9, newman, 64);
    snprintf(p, sizeof p, "%s/LAKE_HEAD", dir);
    spit(p, head, hn);
    close(ofd);
    free(head);
    free(seg);
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
            if (imdb_segment_parse(&mt->s, al, sn, &g, &e)) die("segment", &e);
            size_t at = SIZE_MAX;
            for (uint32_t r = 0; r < g->nrows && at == SIZE_MAX; r++)
                if (g->flags[r] == IMDB_SEG_PURGED)
                    at = (size_t)((const uint8_t *)&g->col[mt->s.subject].i64[r] - g->bytes);
            imdb_segment_free(g);
            if (at == SIZE_MAX) {
                free(raw);
                continue;
            }
            imdb_le64(raw + at, imdb_get_le64(raw + at) + 1000); /* another subject */
            char nseg[80], nman[80];
            if (obj_rename(ofd, sname, raw, sn, ".seg", nseg)) exit(1);
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
            /* seed = table id byte + segment (the harness parses against that schema) */
            uint8_t *s = malloc(on + 1);
            s[0] = (uint8_t)imdb_get_le32(b + 12);
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
    for (uint32_t i = 0; i < c.nops; i++) any |= imdb_op_has_payload(c.ops[i].code) && c.ops[i].pkind == IMDB_PAYLOAD_ROW;
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
        if (imdb_op_has_payload(c.ops[i].code) && c.ops[i].pkind == IMDB_PAYLOAD_ROW && c.ops[i].row_len) {
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

/* a lake manifest that breaks one version-3 rule, re-pointed and re-signed so only that rule can
 * refuse it: v3-empty (version 3 with no index anywhere, where version 2 is the encoding; from a
 * database without indexes) or column (the last index names a column its table lacks; needs an
 * index in the last table, whose entry then ends the manifest) */
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
    if (strcmp(kind, "v3-empty") == 0 && imdb_get_le32(man + 8) == 2) {
        size_t at = 136; /* magic, version, ntables, db id, seq, prev, state digest, prev manifest */
        imdb_buf_put(&nb, man, 8);
        imdb_buf_put_u32(&nb, 3);
        imdb_buf_put(&nb, man + 12, at - 12);
        for (uint32_t ti = 0; ti < m.nt; ti++) {
            size_t len = 4 + imdb_get_le32(man + at) + 24 + IMDB_LTHASH_BYTES + 4 + (size_t)m.t[ti].nseg * 68;
            imdb_buf_put(&nb, man + at, len);
            imdb_buf_put_u32(&nb, 0);
            at += len;
        }
    } else if (strcmp(kind, "column") == 0 && m.nt && m.t[m.nt - 1].nidx) {
        imdb_buf_put(&nb, man, mn);
        uint16_t c = m.t[m.nt - 1].s.ncols; /* the last index's column, little endian */
        nb.p[nb.len - 2] = (uint8_t)c;
        nb.p[nb.len - 1] = (uint8_t)(c >> 8);
    } else {
        fputs("imdb-forge: manifest-lie DIR v3-empty (no indexes) | column (an index in the last table)\n", stderr);
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
        for (uint64_t vid = 0; vid < t->nver; vid++) {
            imdb_value k;
            if (imdb_vh(t, vid)->end != IMDB_LIVE || imdb_version_key(t, vid, t->s.pk, &k) != IMDB_OK) continue;
            if (src == IMDB_NONE) src = vid;
            if (k.i > maxpk) maxpk = k.i;
        }
        imdb_value vals[IMDB_MAX_COLS];
        imdb_err e = {0};
        if (src == IMDB_NONE || t->s.cols[t->s.pk].type != IMDB_T_INT64 || imdb_version_values(db, t, src, vals, &e)) {
            fputs("imdb-forge: index-lie unique-dup needs a live row with an INT64 primary key\n", stderr);
            exit(1);
        }
        vals[t->s.pk].i = maxpk + 1;
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
    } else {
        fputs("imdb-forge: index-lie DIR column | duplicate (needs an index) | drop-absent | unique-dup (needs a unique index)\n", stderr);
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
    fputs("usage: imdb-forge lie-payload SEGMENT | redact-all SEGMENT | index-lie DIR KIND | manifest-lie DIR KIND | lie-zonemap DIR | lie-tombstone DIR | durable-rewind DIR | "
          "rotate-foreign DIR | promote-elsewhere DIR ROOTKEY | writers-resign DIR | alg-flip DIR SEQ | corpus DIR OUT\n", stderr);
    return 2;
}
