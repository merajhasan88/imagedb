/* Format 1's rule for a later version (docs/format-1.md; the freeze's slice 3): a structure stamped with a version past
 * format 1's is refused by name by every entry that reads it (a writable, a read-only and a full-replay open, recover,
 * ship, a replica's apply, the auditor), and nothing in the directory changes: no repair (recover's cut, a torn tail's
 * drop, DURABLE or LAKE_HEAD rewritten, a lake or WRITERS made again by a full replay) runs over a later imagedb's files.
 * A frame so stamped whose signature fails is refused for its signature, not as a later imagedb's. */
#include <dirent.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "../../src/backup.h"
#include "../../src/catalogue.h"
#include "../../src/cpu.h"
#include "../../src/db.h"
#include "../../src/lake.h"
#include "../../src/log.h"
#include "../../src/logdir.h"
#include "../../src/repl.h"
#include "../../src/rewind.h"
#include "../../src/sha256.h"
#include "../../src/sql.h"
#include "../../src/sign.h"
#include "../../src/util.h"
#include "../../src/writer.h"
#include "test.h"
#include "thelp.h"

/* the auditor's verify on dir: 1 refused in words holding needle, 0 refused otherwise (said), 2 taken, -1 no auditor */
static int audit_refuses(const char *dir, const char *needle)
{
    const char *bin = getenv("IMDB_AUDIT_BIN");
    if (!bin || !*bin) return -1;
    char out[900], cmd[2000];
    snprintf(out, sizeof out, "%s.audit.txt", dir);
    snprintf(cmd, sizeof cmd, "'%s' verify '%s' > '%s' 2>&1", bin, dir, out);
    int st = system(cmd);
    size_t n = 0;
    uint8_t *b = slurp(out, &n);
    bool has = b && mem_contains(b, n, needle);
    if (st != 0 && !has) fprintf(stderr, "    auditor: %.*s\n", b ? (int)(n < 300 ? n : 300) : 0, b ? (const char *)b : "");
    free(b);
    unlink(out);
    return st == 0 ? 2 : has;
}

/* a primary: a table, rows, a CHECKPOINT (LAKE_HEAD, a manifest, segments), then a commit past the snapshot, the log's
 * last frame */
static void base_db_ex(const char *name, char *dir, size_t cap, bool tail)
{
    snprintf(dir, cap, "%s/%s", test_tmpdir(), name);
    OK(imdb_init(dir, false, NULL, E));
    imdb_db *db = open_db(dir);
    CHECK(db);
    if (!db) return;
    OK(make_table(db, E));
    for (int i = 1; i <= 4; i++) OK(ins1(db, i, 7, 100 * i, "row"));
    OK(imdb_checkpoint(db, E));
    if (tail) OK(ins1(db, 5, 7, 500, "row"));
    imdb_close(db);
}

static void base_db(const char *name, char *dir, size_t cap) { base_db_ex(name, dir, cap, true); }

/* byte at of file (under dir) set to v; crc_to: the CRC32C of [0, crc_to) put after it again (0: none) */
static void set_byte(const char *dir, const char *file, size_t at, uint8_t v, size_t crc_to)
{
    char p[900];
    snprintf(p, sizeof p, "%s/%s", dir, file);
    size_t n = 0;
    uint8_t *b = slurp(p, &n);
    CHECK(b && at < n && crc_to + 4 <= n);
    if (!b || at >= n || crc_to + 4 > n) {
        free(b);
        return;
    }
    b[at] = v;
    if (crc_to) imdb_le32(b + crc_to, imdb_kern()->crc32c(0, b, crc_to));
    spit(p, b, n);
    free(b);
}

static void plant(const char *dir, const char *file, const char *magic, size_t n)
{
    char p[900];
    snprintf(p, sizeof p, "%s/%s", dir, file);
    uint8_t *b = calloc(n, 1);
    CHECK(b != NULL);
    if (!b) return;
    memcpy(b, magic, strlen(magic));
    spit(p, b, n);
    free(b);
}

/* the head manifest made again at a later version (magic: its magic's digit instead), put under its own name, LAKE_HEAD
 * naming it */
static void later_manifest(const char *dir, bool magic)
{
    char p[900];
    snprintf(p, sizeof p, "%s/LAKE_HEAD", dir);
    size_t hn = 0;
    uint8_t *head = slurp(p, &hn);
    CHECK(head && hn > 65 && head[hn - 1] == '\n');
    if (!head || hn <= 65) {
        free(head);
        return;
    }
    char q[900];
    snprintf(q, sizeof q, "%s/objects/%.64s.man", dir, (const char *)head + hn - 65);
    size_t mn = 0;
    uint8_t *man = slurp(q, &mn);
    CHECK(man && mn > 12 && memcmp(man, "IMDBMAN1", 8) == 0);
    if (man && mn > 12) {
        if (magic) man[7] = '2';
        else imdb_le32(man + 8, IMDB_MANIFEST_VERSION + 1);
        uint8_t h[32];
        char hex[65];
        imdb_sha256(man, mn, h);
        imdb_hex(h, 32, hex);
        snprintf(q, sizeof q, "%s/objects/%s.man", dir, hex);
        spit(q, man, mn);
        memcpy(head + hn - 65, hex, 64);
        spit(p, head, hn);
    }
    free(man);
    free(head);
}

/* The log's last frame with byte at of its header set to v, signed again by the writer (sign false: a signature no key
 * made), DURABLE's head moved with it: so that only the rule for a later version refuses it. */
static void restamp_last(const char *dir, size_t at, uint8_t v, bool sign)
{
    char p[900];
    snprintf(p, sizeof p, "%s/signing.key", dir);
    size_t kn = 0;
    uint8_t *seed = slurp(p, &kn);
    CHECK(seed && kn == IMDB_SEED_LEN);
    if (!seed || kn != IMDB_SEED_LEN) {
        free(seed);
        return;
    }
    imdb_signer sg;
    imdb_signer_init(&sg, seed);
    imdb_wipe(seed, kn);
    free(seed);
    char *sp = seg_path(dir, -1);
    size_t n = 0, off = 0, last = 0, flen = 0;
    uint64_t first = 0;
    bool tg = false;
    uint8_t *fr = seg_frames(sp, &n, &first, &tg);
    if (fr && !n) { /* a new segment's zeros last: the log's last frame ends the one before */
        free(fr);
        sp = seg_path(dir, -2);
        fr = seg_frames(sp, &n, &first, &tg);
    }
    CHECK(fr && tg && n);
    while (fr && off < n) {
        size_t fl = 0;
        imdb_err e2 = {0};
        if (imdb_frame_scan(fr, n, off, &fl, &e2) != IMDB_SCAN_FRAME) break;
        last = off;
        flen = fl;
        off += fl;
    }
    CHECK(fr && off == n && flen > IMDB_FRAME_HDR + IMDB_BODY_DESC);
    if (!fr || off != n || flen <= IMDB_FRAME_HDR + IMDB_BODY_DESC) {
        free(fr);
        imdb_signer_wipe(&sg);
        return;
    }
    const uint8_t *d = fr + last + IMDB_FRAME_HDR;
    uint32_t hlen = imdb_get_le32(d + 1);
    uint64_t seq = imdb_get_le64(d + 5);
    CHECK(d[0] == IMDB_BODY_KIND && at < hlen);
    uint8_t *h = malloc(hlen);
    CHECK(h != NULL);
    if (h && at < hlen) {
        memcpy(h, d + IMDB_BODY_DESC, hlen);
        h[at] = v;
        const uint8_t *pay = d + IMDB_BODY_DESC + hlen;
        uint32_t plen = imdb_get_le32(pay);
        uint8_t hash[32], msg[IMDB_SIGMSG_LEN], sig[IMDB_SIG_LEN];
        imdb_commit_hash(h, hlen, hash);
        imdb_commit_sigmsg(seq, hlen, hash, msg);
        if (sign) imdb_sign(&sg, msg, sizeof msg, sig);
        else memset(sig, 0x5a, sizeof sig);
        imdb_buf out;
        imdb_buf_init(&out);
        imdb_buf_put(&out, fr, last);
        imdb_frame_build(h, hlen, seq, hash, sig, pay + 4, plen, &out);
        CHECK(imdb_buf_check(&out, E) == IMDB_OK);
        seg_put_frames(sp, first, true, out.p, out.len);
        imdb_buf_free(&out);
        int dfd = open(dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC); /* DURABLE names the last commit's hash */
        imdb_durable w;
        bool hw = false;
        if (dfd >= 0 && imdb_durable_read(dfd, &w, &hw, E) == IMDB_OK && hw && w.seq == seq) {
            uint8_t wb[IMDB_DURABLE_LEN];
            memcpy(w.head, hash, 32);
            imdb_durable_encode(&w, wb);
            snprintf(p, sizeof p, "%s/%s", dir, IMDB_DURABLE_NAME);
            spit(p, wb, sizeof wb);
        }
        if (dfd >= 0) close(dfd);
    }
    free(h);
    free(fr);
    imdb_signer_wipe(&sg);
}

enum {
    L_META, L_META_BARE, L_LAKE_HEAD, L_DURABLE, L_ILT2, L_TSEG_V2, L_WRITERS, L_FLOOR, L_MANIFEST, L_MANIFEST_MAGIC,
    L_LOGVER, L_OP, L_LOGVER_UNSIGNED, L_SNAP_LOGVER, L_SNAP_UNSIGNED, L_FRAME_MAGIC, L_FRAME_MAGIC_STRICT, L_BODY_KIND, L_N
};

typedef struct later_case {
    const char *what;
    const char *needle;  /* the engine's words: the structure by name */
    const char *aneedle; /* the auditor's (NULL: the auditor's verify does not read it, and takes the copy) */
    int code;            /* the opens' verdict */
    int rcode;           /* recover's: IMDB_OK, it finds nothing to cut */
    const char *rneedle; /* in recover's words (NULL: needle) */
    bool ship;           /* ship reads it: refused, in needle's words */
    bool snap;           /* the copy's last commit its CHECKPOINT: the stamp is on the snapshot's own commit */
} later_case;

/* A frame's magic and its body's kind lie below the signature: format 1 cannot tell a later layout of them from
 * damage, so they are refused as damage (CORRUPT), resting on META's version for their name (docs/format-1.md §3);
 * what is held to here is that the verdict is never one a repair acts on: recover finds no damaged end to cut, the
 * open drops nothing (a strict watermark below the frame too), and the directory is as it was. */
#define LC(w, n, a, c, rc, rn, s, sn) {.what = w, .needle = n, .aneedle = a, .code = c, .rcode = rc, .rneedle = rn, .ship = s, .snap = sn}
#define UNS IMDB_ERR_UNSUPPORTED
static const later_case kLater[L_N] = {
    [L_META] = LC("META", "META: imagedb-meta 6", "META: imagedb-meta 6", UNS, UNS, NULL, false, false),
    [L_META_BARE] = LC("META, no LOCK or DURABLE", "META: imagedb-meta 6", "META: imagedb-meta 6", UNS, UNS, NULL, false,
                       false),
    [L_LAKE_HEAD] = LC("LAKE_HEAD", "LAKE_HEAD: imagedb-lake 2", "LAKE_HEAD: imagedb-lake 2", UNS, UNS, NULL, false, false),
    [L_DURABLE] = LC("DURABLE", "DURABLE: IMDBDUR2", "DURABLE: IMDBDUR2", UNS, UNS, NULL, true, false),
    [L_ILT2] = LC("a tagged segment's magic", "a tagged segment of a later format (ILT2)",
                  "a tagged segment of a later format (ILT2)", UNS, UNS, NULL, true, false),
    [L_TSEG_V2] = LC("a tagged segment's version", "tagged segment version 2", "tagged segment version 2", UNS, UNS, NULL,
                     true, false),
    [L_WRITERS] = LC("WRITERS", "WRITERS: IMDBWRS2", NULL, UNS, IMDB_OK, NULL, false, false),
    [L_FLOOR] = LC("FLOOR", "FLOOR: IMDBFLR2", "FLOOR: IMDBFLR2", UNS, IMDB_OK, NULL, false, false),
    [L_MANIFEST] = LC("the manifest's version", "manifest version 22", "manifest version 22", UNS, IMDB_OK, NULL, false,
                      false),
    [L_MANIFEST_MAGIC] = LC("the manifest's magic", "manifest: IMDBMAN2", "manifest: IMDBMAN2", UNS, IMDB_OK, NULL, false,
                            false),
    [L_LOGVER] = LC("a commit's log version", "log version 4, written by a later imagedb",
                    "log version 4, written by a later imagedb", UNS, IMDB_OK, NULL, false, false),
    [L_OP] = LC("a commit's op", "op 38, written by a later imagedb", "op 38, written by a later imagedb", UNS, IMDB_OK,
                NULL, false, false),
    [L_LOGVER_UNSIGNED] = LC("a log version under no signature", "signature invalid", "signature invalid", IMDB_ERR_AUTH,
                             IMDB_OK, NULL, false, false),
    [L_SNAP_LOGVER] = LC("the snapshot's commit's log version", "log version 4, written by a later imagedb",
                         "log version 4, written by a later imagedb", UNS, IMDB_OK, NULL, false, true),
    [L_SNAP_UNSIGNED] = LC("the snapshot's commit's log version under no signature", "signature invalid",
                           "signature invalid", IMDB_ERR_AUTH, IMDB_OK, NULL, false, true),
    [L_FRAME_MAGIC] = LC("a frame's magic", "a malformed frame", "a malformed frame", IMDB_ERR_CORRUPT, IMDB_ERR_CORRUPT,
                         "this is not a damaged end of the log", false, false),
    [L_FRAME_MAGIC_STRICT] = LC("a frame's magic past a strict watermark", "a malformed frame", "a malformed frame",
                                IMDB_ERR_CORRUPT, IMDB_ERR_CORRUPT, "this is not a damaged end of the log", false, false),
    [L_BODY_KIND] = LC("a frame's body kind", "unknown body kind", "unknown body kind", IMDB_ERR_CORRUPT, IMDB_OK, NULL,
                       false, false),
};
#undef UNS
#undef LC

/* DURABLE strict and one commit back (its head that commit's hash): a writer under --durable-ack that wrote its last
 * frame and stopped before the watermark's sync, so that the last frame is one recovery may drop if it is damaged */
static void durable_strict_back(const char *dir)
{
    int dfd = open(dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    imdb_durable w;
    bool hw = false;
    CHECK(dfd >= 0 && imdb_durable_read(dfd, &w, &hw, E) == IMDB_OK && hw && w.seq > 1);
    if (dfd >= 0) close(dfd);
    char *sp = seg_path(dir, -2); /* the last segment holds the last commit alone: the one before ends this one */
    size_t n = 0, off = 0, last = 0;
    uint64_t first = 0;
    bool tg = false;
    uint8_t *fr = seg_frames(sp, &n, &first, &tg);
    while (fr && off < n) {
        size_t fl = 0;
        imdb_err e2 = {0};
        if (imdb_frame_scan(fr, n, off, &fl, &e2) != IMDB_SCAN_FRAME) break;
        last = off;
        off += fl;
    }
    CHECK(fr && off == n && n && imdb_frame_seq(fr + last) == w.seq - 1);
    if (fr && off == n && n && hw) {
        uint8_t wb[IMDB_DURABLE_LEN];
        char p[900];
        w.seq -= 1;
        memcpy(w.head, imdb_frame_hash(fr + last), 32);
        w.synced = w.strict = true;
        imdb_durable_encode(&w, wb);
        snprintf(p, sizeof p, "%s/%s", dir, IMDB_DURABLE_NAME);
        spit(p, wb, sizeof wb);
    }
    free(fr);
}

/* the log's last frame with its magic's digit (kind false) or its body's kind set to v, its CRCs made again: a later
 * frame layout, below the signature */
static void restamp_frame(const char *dir, bool kind, uint8_t v)
{
    char *sp = seg_path(dir, -1);
    size_t n = 0, off = 0, last = 0, flen = 0;
    uint64_t first = 0;
    bool tg = false;
    uint8_t *fr = seg_frames(sp, &n, &first, &tg);
    CHECK(fr && tg && n);
    while (fr && off < n) {
        size_t fl = 0;
        imdb_err e2 = {0};
        if (imdb_frame_scan(fr, n, off, &fl, &e2) != IMDB_SCAN_FRAME) break;
        last = off;
        flen = fl;
        off += fl;
    }
    CHECK(fr && off == n && flen > IMDB_FRAME_HDR);
    if (fr && off == n && flen > IMDB_FRAME_HDR) {
        uint8_t *f = fr + last;
        if (kind) f[IMDB_FRAME_HDR] = v;
        else f[3] = v;
        uint32_t blen = imdb_get_le32(f + 4);
        imdb_le32(f + 8, imdb_kern()->crc32c(0, f + IMDB_FRAME_HDR, blen));
        imdb_le32(f + 12, imdb_kern()->crc32c(0, f, 12));
        seg_put_frames(sp, first, true, fr, n);
    }
    free(fr);
}

static void stamp(const char *dir, int k)
{
    char lp[900];
    switch (k) {
    case L_META_BARE: /* nothing a later imagedb's directory need hold: the open must make nothing */
        snprintf(lp, sizeof lp, "%s/LOCK", dir);
        unlink(lp);
        snprintf(lp, sizeof lp, "%s/%s", dir, IMDB_DURABLE_NAME);
        unlink(lp);
        /* fall through */
    case L_META: set_byte(dir, "META", 13, '6', 0); break;
    case L_LAKE_HEAD: set_byte(dir, "LAKE_HEAD", 13, '2', 0); break;
    case L_DURABLE: set_byte(dir, IMDB_DURABLE_NAME, 7, '2', 0); break;
    case L_ILT2:
    case L_TSEG_V2: {
        char *sp = seg_path(dir, -1);
        const char *base = strrchr(sp, '/');
        snprintf(lp, sizeof lp, "log/%s", base ? base + 1 : sp);
        if (k == L_ILT2) set_byte(dir, lp, 3, '2', 0);
        else set_byte(dir, lp, 4, 2, 16); /* its header whole: version 2, the CRC made again */
        break;
    }
    case L_WRITERS: plant(dir, "WRITERS", "IMDBWRS2", 64); break;
    case L_FLOOR: plant(dir, "FLOOR", "IMDBFLR2", 128); break;
    case L_MANIFEST: later_manifest(dir, false); break;
    case L_MANIFEST_MAGIC: later_manifest(dir, true); break;
    case L_LOGVER: restamp_last(dir, 0, IMDB_LOG_VERSION + 1, true); break;
    case L_OP: restamp_last(dir, 54, IMDB_OP_FORMAT1_LAST + 1, true); break; /* the first op's code */
    case L_LOGVER_UNSIGNED: restamp_last(dir, 0, IMDB_LOG_VERSION + 1, false); break;
    case L_SNAP_LOGVER: restamp_last(dir, 0, IMDB_LOG_VERSION + 1, true); break;
    case L_SNAP_UNSIGNED: restamp_last(dir, 0, IMDB_LOG_VERSION + 1, false); break;
    case L_FRAME_MAGIC_STRICT: durable_strict_back(dir); /* fall through */
    case L_FRAME_MAGIC: restamp_frame(dir, false, '3'); break;
    case L_BODY_KIND: restamp_frame(dir, true, 4); break;
    }
}

/* A reader's lease is all an entry may leave: a pin file (pins/<64 hex>.pin, empty: lake.h) that the engine's and the
 * auditor's readers take on the generation they read, which GC removes once no reader holds it. Those new since copy are
 * taken away (said by *n), so that every other byte is compared. */
static void drop_new_leases(const char *dir, const char *copy, int *n)
{
    char pd[1000], pc[1000];
    snprintf(pd, sizeof pd, "%s/pins", dir);
    snprintf(pc, sizeof pc, "%s/pins", copy);
    DIR *d = opendir(pd);
    if (!d) return;
    struct dirent *de;
    while ((de = readdir(d))) {
        char a[1300], b[1300];
        struct stat st;
        snprintf(a, sizeof a, "%s/%s", pd, de->d_name);
        snprintf(b, sizeof b, "%s/%s", pc, de->d_name);
        if (!imdb_pin_name_valid(de->d_name) || access(b, F_OK) == 0 || lstat(a, &st) != 0 || !S_ISREG(st.st_mode) ||
            st.st_size != 0)
            continue;
        if (unlink(a) == 0) (*n)++;
    }
    closedir(d);
    if (access(pc, F_OK) != 0) rmdir(pd); /* pins/ made for it: gone if empty */
}

/* after an entry: the tree as stamped, or the failure said (and the tree put back for the next entry) */
static void tree_kept(const char *dir, const char *copy, const char *what, const char *entry, int *fails)
{
    char why[400] = "";
    int leases = 0;
    drop_new_leases(dir, copy, &leases);
    if (dirs_identical(dir, copy, why, sizeof why)) return;
    fprintf(stderr, "    %s, %s: the directory changed: %s\n", what, entry, why);
    (*fails)++;
    char cmd[2000];
    snprintf(cmd, sizeof cmd, "rm -rf '%s'", dir);
    if (system(cmd) != 0 || copy_tree(copy, dir) != 0) (*fails)++;
}

static void t_format1_later_refused(void)
{
    const char *tmp = test_tmpdir();
    char base[900], snapbase[900];
    base_db("base", base, sizeof base);
    base_db_ex("snapbase", snapbase, sizeof snapbase, false); /* its last commit its CHECKPOINT */
    int fails = 0;
    static const char *const kOpen[3] = {"writable open", "read-only open", "full-replay open"};
    for (int k = 0; k < L_N; k++) {
        const later_case *c = &kLater[k];
        char dir[900], copy[900], save[900], stream[900];
        snprintf(dir, sizeof dir, "%s/c%d", tmp, k);
        snprintf(copy, sizeof copy, "%s/c%d.copy", tmp, k);
        snprintf(save, sizeof save, "%s/c%d.save", tmp, k);
        snprintf(stream, sizeof stream, "%s/c%d.stream", tmp, k);
        if (copy_tree(c->snap ? snapbase : base, dir) != 0) {
            fails++;
            continue;
        }
        stamp(dir, k);
        if (copy_tree(dir, copy) != 0) {
            fails++;
            continue;
        }
        for (int how = 0; how < 3; how++) {
            imdb_open_opts o = {.sync = 0, .read_only = how == 1, .full_replay = how == 2};
            imdb_db *x = NULL;
            imdb_err_clear(E);
            int rc = imdb_open(dir, &o, &x, E);
            if (!(rc == c->code && !x && strstr(g_e.msg, c->needle))) {
                fprintf(stderr, "    %s, %s: %d %s\n", c->what, kOpen[how], rc, g_e.msg);
                fails++;
            }
            if (x) imdb_close(x);
            tree_kept(dir, copy, c->what, kOpen[how], &fails);
        }
        imdb_recover_report r;
        imdb_err_clear(E);
        int rc = imdb_recover_tail(dir, true, save, &r, E);
        bool ok = c->rcode ? rc == c->rcode && strstr(g_e.msg, c->rneedle ? c->rneedle : c->needle)
                           : rc == IMDB_OK && !r.damaged && !r.applied;
        if (!ok || access(save, F_OK) == 0) { /* nothing saved: nothing cut */
            fprintf(stderr, "    %s, recover: %d %s\n", c->what, rc, g_e.msg);
            fails++;
        }
        tree_kept(dir, copy, c->what, "recover", &fails);
        imdb_err_clear(E);
        rc = ship_to_file(dir, 0, stream, E);
        if (c->ship && !(rc == IMDB_ERR_UNSUPPORTED && strstr(g_e.msg, c->needle))) {
            fprintf(stderr, "    %s, ship: %d %s\n", c->what, rc, g_e.msg);
            fails++;
        }
        unlink(stream);
        tree_kept(dir, copy, c->what, "ship", &fails);
        int ar = audit_refuses(dir, c->aneedle ? c->aneedle : "");
        if (ar >= 0 && ar != (c->aneedle ? 1 : 2)) {
            fprintf(stderr, "    %s, the auditor: %s\n", c->what, c->aneedle ? "not refused in its words" : "refused");
            fails++;
        }
        tree_kept(dir, copy, c->what, "the auditor", &fails);
    }
    CHECK(fails == 0);
}

/* A replica fed a later imagedb's commit refuses it by name, its log ending at the commit before; and a stream whose
 * seed is a later imagedb's leaves an empty replica empty. */
static void t_format1_later_stream(void)
{
    char p[900];
    base_db("primary", p, sizeof p);
    uint64_t last = 0; /* the primary's last commit, the one a later imagedb's stamp then marks */
    {
        imdb_open_opts ro = {.read_only = true};
        imdb_db *x = NULL;
        OK(imdb_open(p, &ro, &x, E));
        if (x) {
            last = x->seq;
            imdb_close(x);
        }
    }
    CHECK(last > 1);
    restamp_last(p, 0, IMDB_LOG_VERSION + 1, true);
    char rep[900], stream[900];
    snprintf(rep, sizeof rep, "%s/replica", test_tmpdir());
    snprintf(stream, sizeof stream, "%s/stream", test_tmpdir());
    OK(imdb_init(rep, true, p, E));
    imdb_err_clear(E);
    int rc = ship_to_file(p, 0, stream, E);
    if (rc == IMDB_OK) {
        imdb_open_opts o = {.sync = 0};
        imdb_db *r = NULL;
        OK(imdb_open(rep, &o, &r, E));
        if (r) {
            uint64_t applied = 0;
            imdb_err_clear(E);
            rc = apply_file(r, stream, &applied, E);
            CHECK(rc == IMDB_ERR_UNSUPPORTED && strstr(g_e.msg, "log version 4, written by a later imagedb"));
            if (rc != IMDB_ERR_UNSUPPORTED) fprintf(stderr, "    apply: %d %s\n", rc, g_e.msg);
            CHECK(r->seq == last - 1); /* the commit before the later one */
            imdb_close(r);
        }
        r = NULL;
        OK(imdb_open(rep, &o, &r, E)); /* its log the format 1 commits alone */
        CHECK(r && r->seq == last - 1);
        if (r) imdb_close(r);
    } else { /* ship read the commit itself: refused by name there */
        CHECK(rc == IMDB_ERR_UNSUPPORTED && strstr(g_e.msg, "log version 4, written by a later imagedb"));
    }
    /* the seed: a stream from a fresh primary, its first frame's prefix a later imagedb's seed's */
    char q[900];
    base_db("primary2", q, sizeof q);
    char rep2[900], copy[900], why[300] = "";
    snprintf(rep2, sizeof rep2, "%s/replica2", test_tmpdir());
    snprintf(copy, sizeof copy, "%s/replica2.copy", test_tmpdir());
    OK(imdb_init(rep2, true, q, E));
    OK(ship_to_file(q, 0, stream, E));
    size_t n = 0;
    uint8_t *b = slurp(stream, &n);
    size_t at = 0;
    while (b && at + 4 <= n && imdb_get_le32(b + at) != IMDB_FRAME_MAGIC) at++;
    CHECK(b && at + IMDB_FRAME_HDR <= n);
    if (b && at + IMDB_FRAME_HDR <= n) {
        memcpy(b + at, "IMDBSED2", 8);
        spit(stream, b, n);
        imdb_db *r = NULL;
        imdb_open_opts o = {.sync = 0};
        OK(imdb_open(rep2, &o, &r, E));
        if (r) {
            uint64_t applied = 0;
            imdb_err_clear(E);
            rc = apply_file(r, stream, &applied, E);
            CHECK(rc == IMDB_ERR_UNSUPPORTED && strstr(g_e.msg, "seed: IMDBSED2, written by a later imagedb"));
            if (rc != IMDB_ERR_UNSUPPORTED) fprintf(stderr, "    seed: %d %s\n", rc, g_e.msg);
            CHECK(r->seq == 0 && applied == 0);
            imdb_close(r);
        }
    }
    free(b);
    (void)copy;
    (void)why;
}

/* The operator's files and the texts: an anchor, an identity, a catalogue, each a later imagedb's, refused by name */
static void t_format1_later_files(void)
{
    char dir[900];
    base_db("db", dir, sizeof dir);
    char anchor[900], copy[900], why[300] = "";
    snprintf(anchor, sizeof anchor, "%s/anchor", test_tmpdir());
    snprintf(copy, sizeof copy, "%s/db.copy", test_tmpdir());
    imdb_open_opts o = {.sync = 1, .anchor = anchor};
    imdb_db *db = NULL;
    OK(imdb_open(dir, &o, &db, E)); /* the anchor made, then a commit it names */
    if (db) {
        OK(ins1(db, 6, 7, 600, "row"));
        imdb_close(db);
    }
    size_t an = 0;
    uint8_t *ab = slurp(anchor, &an);
    CHECK(ab && an == IMDB_ANCHOR_FILE);
    if (ab && an == IMDB_ANCHOR_FILE) {
        ab[7] = '2';
        ab[IMDB_ANCHOR_SLOT + 7] = '2';
        spit(anchor, ab, an);
        CHECK(copy_tree(dir, copy) == 0);
        db = NULL;
        imdb_err_clear(E);
        int rc = imdb_open(dir, &o, &db, E);
        CHECK(rc == IMDB_ERR_UNSUPPORTED && !db && strstr(g_e.msg, "anchor: IMDBANC2, written by a later imagedb"));
        if (rc != IMDB_ERR_UNSUPPORTED) fprintf(stderr, "    anchor: %d %s\n", rc, g_e.msg);
        if (db) imdb_close(db);
        size_t an2 = 0;
        uint8_t *ab2 = slurp(anchor, &an2);
        CHECK(ab2 && an2 == an && memcmp(ab, ab2, an) == 0); /* the anchor never written over */
        free(ab2);
        int leases = 0;
        drop_new_leases(dir, copy, &leases);
        bool same = dirs_identical(dir, copy, why, sizeof why);
        if (!same) fprintf(stderr, "    anchor: the directory changed: %s\n", why);
        CHECK(same);
        if (why[0]) fprintf(stderr, "    %s\n", why);
    }
    free(ab);
    /* an identity text (imagedb identity, init-replica's input) */
    imdb_identity id;
    bool replica = false;
    OK(imdb_identity_read(dir, &id, &replica, E));
    char txt[2048];
    int tl = imdb_identity_format(&id, txt, sizeof txt);
    CHECK(tl > 20 && memcmp(txt, "imagedb-identity 3\n", 19) == 0);
    if (tl > 20) {
        txt[17] = '4';
        imdb_identity id2;
        imdb_err_clear(E);
        CHECK(imdb_identity_parse(txt, (size_t)tl, &id2, E) == IMDB_ERR_UNSUPPORTED && strstr(g_e.msg, "identity version 4"));
    }
    /* a catalogue whose first record names version 2, its CRC its own */
    char cat[900], rec[200], hex[33], line[260];
    snprintf(cat, sizeof cat, "%s/catalogue", test_tmpdir());
    imdb_hex(id.db_id, 16, hex);
    snprintf(rec, sizeof rec, "imagedb-catalogue 2 %s", hex);
    snprintf(line, sizeof line, "%s %08x\n", rec, imdb_kern()->crc32c(0, rec, strlen(rec)));
    spit(cat, (const uint8_t *)line, strlen(line));
    imdb_catalogue cg;
    memset(&cg, 0, sizeof cg);
    imdb_err_clear(E);
    int rc = imdb_catalogue_read(cat, &cg, E);
    CHECK(rc == IMDB_ERR_UNSUPPORTED && strstr(g_e.msg, "version 2, written by a later imagedb"));
    if (rc != IMDB_ERR_UNSUPPORTED) fprintf(stderr, "    catalogue: %d %s\n", rc, g_e.msg);
    if (rc == IMDB_OK) imdb_catalogue_free(&cg);
    /* replica-add (an allowlist entry under replicas/): refused before replicas/ is made in a later imagedb's directory */
    char radd[900], raddc[900];
    snprintf(radd, sizeof radd, "%s/radd", test_tmpdir());
    snprintf(raddc, sizeof raddc, "%s/radd.copy", test_tmpdir());
    CHECK(copy_tree(dir, radd) == 0);
    set_byte(radd, "META", 13, '6', 0);
    CHECK(copy_tree(radd, raddc) == 0);
    uint8_t pub[IMDB_PUBKEY_LEN];
    memset(pub, 7, sizeof pub);
    imdb_err_clear(E);
    rc = imdb_replica_add(radd, "r1", pub, false, E);
    CHECK(rc == IMDB_ERR_UNSUPPORTED && strstr(g_e.msg, "META: imagedb-meta 6"));
    if (rc != IMDB_ERR_UNSUPPORTED) fprintf(stderr, "    replica-add: %d %s\n", rc, g_e.msg);
    char why2[400] = "";
    bool same2 = dirs_identical(radd, raddc, why2, sizeof why2);
    if (!same2) fprintf(stderr, "    replica-add: the directory changed: %s\n", why2);
    CHECK(same2);
}

/* Rewind and promotion, the most destructive writers: a later imagedb's META refused by each before anything is written
 * (the copy as it was, with LOCK and without; no save file; no root ledger made) */
static void t_format1_later_rewind_promote(void)
{
    const char *tmp = test_tmpdir();
    char p[900], r[900], stream[900], save[900], ledger[900];
    snprintf(p, sizeof p, "%s/primary", tmp);
    snprintf(r, sizeof r, "%s/replica", tmp);
    snprintf(stream, sizeof stream, "%s/stream", tmp);
    snprintf(save, sizeof save, "%s/rewind.save", tmp);
    snprintf(ledger, sizeof ledger, "%s/root.ledger", tmp);
    uint8_t seed[IMDB_SEED_LEN];
    for (size_t i = 0; i < sizeof seed; i++) seed[i] = (uint8_t)(i * 7 + 3); /* a root key of this test's alone */
    imdb_signer root;
    imdb_signer_init(&root, seed);
    OK(imdb_init_primary(p, root.pk, E));
    imdb_db *db = open_db(p);
    CHECK(db);
    if (!db) return;
    OK(make_table(db, E));
    OK(ins1(db, 1, 7, 100, "row"));
    imdb_close(db);
    OK(imdb_init(r, true, p, E));
    OK(ship_to_file(p, 0, stream, E));
    db = open_db(r);
    CHECK(db);
    if (!db) return;
    uint64_t applied = 0;
    OK(apply_file(db, stream, &applied, E));
    imdb_close(db);
    int fails = 0;
    for (int bare = 0; bare < 2; bare++) {
        for (int who = 0; who < 2; who++) { /* the primary rewound, the replica promoted */
            const char *dir = who ? r : p;
            char d[900], copy[900], lp[1000];
            snprintf(d, sizeof d, "%s/c%d%d", tmp, bare, who);
            snprintf(copy, sizeof copy, "%s.copy", d);
            if (copy_tree(dir, d) != 0) {
                fails++;
                continue;
            }
            set_byte(d, "META", 13, '6', 0);
            if (bare) {
                snprintf(lp, sizeof lp, "%s/LOCK", d);
                unlink(lp);
            }
            if (copy_tree(d, copy) != 0) {
                fails++;
                continue;
            }
            imdb_err_clear(E);
            int rc;
            if (!who) {
                imdb_rewind *rw = NULL;
                imdb_rewind_report rr;
                rc = imdb_rewind_begin(d, &rw, &rr, E);
                if (rw) imdb_rewind_end(rw);
            } else {
                imdb_promote_opts po = {.old_writer_stopped = true, .ledger = ledger};
                imdb_promote_result pr;
                memset(&pr, 0, sizeof pr);
                rc = imdb_promote(d, seed, &po, &pr, E);
                if (pr.committed) fails++;
            }
            if (rc != IMDB_ERR_UNSUPPORTED || !strstr(g_e.msg, "META: imagedb-meta 6")) {
                fprintf(stderr, "    %s%s: %d %s\n", who ? "promote" : "rewind", bare ? ", no LOCK" : "", rc, g_e.msg);
                fails++;
            }
            tree_kept(d, copy, who ? "promote" : "rewind", bare ? "no LOCK" : "LOCK", &fails);
            if (access(save, F_OK) == 0 || access(ledger, F_OK) == 0) {
                fprintf(stderr, "    %s: a save file or a ledger was made\n", who ? "promote" : "rewind");
                fails++;
            }
        }
    }
    imdb_signer_wipe(&root);
    imdb_wipe(seed, sizeof seed);
    CHECK(fails == 0);
}

/* The census of format 1's fixtures: what their logs hold, every op code, op 22's kinds, op 23's kinds, op 12's three
 * lists, both WRITER_KEY forms, both body kinds and every type tag a schema names, counted over every copy in every
 * tarball listed; *missing says how many of them none holds (each named on stderr) */
typedef struct census {
    uint32_t op[64], akind[32], defk[32], body[8], how[4], type[32];
    uint32_t erase_rows, erase_vers, erase_roles, frames;
} census;

static void census_log(const char *dir, census *cs)
{
    char ld[1000];
    snprintf(ld, sizeof ld, "%s/log", dir);
    int lfd = open(ld, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (lfd < 0) return;
    uint64_t *segs = NULL;
    size_t nsegs = 0;
    imdb_err e2 = {0};
    if (imdb_logdir_list(lfd, &segs, &nsegs, &e2) == IMDB_OK) {
        for (size_t si = 0; si < nsegs; si++) {
            imdb_logseg seg;
            imdb_err e3 = {0};
            if (imdb_logseg_load(lfd, segs[si], &seg, &e3)) continue;
            for (size_t off = 0;;) {
                size_t flen = 0;
                imdb_err e4 = {0};
                if (imdb_logseg_scan(&seg, off, &flen, &e4) != IMDB_SCAN_FRAME) break;
                const uint8_t *body = seg.buf + off + IMDB_FRAME_HDR;
                cs->body[body[0] & 7]++;
                cs->frames++;
                imdb_commit_rec c;
                imdb_err e5 = {0};
                if (imdb_frame_decode_body(body, flen - IMDB_FRAME_HDR, &c, &e5) == IMDB_OK) {
                    for (uint32_t k = 0; k < c.nops; k++) {
                        const imdb_op *o = &c.ops[k];
                        cs->op[o->code & 63]++;
                        if (o->code == IMDB_OP_ALTER_TABLE) cs->akind[o->akind & 31]++;
                        if (o->code == IMDB_OP_COLUMN_DEFAULTS)
                            for (uint16_t d = 0; d < o->ndefs; d++) cs->defk[o->defs[d].kind & 31]++;
                        if (o->code == IMDB_OP_WRITER_KEY) cs->how[o->how & 3]++;
                        if (o->code == IMDB_OP_ERASE) {
                            cs->erase_rows += o->n_erase;
                            cs->erase_vers += o->n_rewrites;
                            cs->erase_roles += o->n_rerase;
                        }
                        if (o->code == IMDB_OP_CREATE_TABLE && o->schema)
                            for (uint16_t i = 0; i < o->schema->ncols; i++) cs->type[o->schema->cols[i].type & 31]++;
                        if (o->code == IMDB_OP_ALTER_TABLE && o->akind == IMDB_ALTER_ADD_COLUMN) cs->type[o->acol.type & 31]++;
                    }
                    imdb_commit_free(&c);
                }
                off += flen;
            }
            imdb_logseg_free(&seg);
        }
    }
    imdb_free(segs);
    close(lfd);
}

static void census_say(const census *cs, int *missing)
{
    static const uint8_t ops[] = {1, 2, 3, 4, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
                                  26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37};
    *missing = 0;
    for (size_t i = 0; i < sizeof ops; i++)
        if (!cs->op[ops[i]]) fprintf(stderr, "    census: no op %u\n", ops[i]), (*missing)++;
    for (unsigned k = 1; k <= IMDB_ALTER_LAST; k++)
        if (!cs->akind[k]) fprintf(stderr, "    census: no ALTER kind %u\n", k), (*missing)++;
    for (unsigned k = 1; k <= IMDB_DEFK_LAST; k++)
        if (!cs->defk[k]) fprintf(stderr, "    census: no DEFAULT kind %u\n", k), (*missing)++;
    for (unsigned k = IMDB_WRITER_ROTATE; k <= IMDB_WRITER_PROMOTE; k++)
        if (!cs->how[k]) fprintf(stderr, "    census: no WRITER_KEY form %u\n", k), (*missing)++;
    for (unsigned k = IMDB_BODY_KIND; k <= IMDB_BODY_KIND_PROMOTE; k++)
        if (!cs->body[k]) fprintf(stderr, "    census: no body kind %u\n", k), (*missing)++;
    for (unsigned k = IMDB_T_INT64; k <= IMDB_T_ENUM; k++)
        if (!cs->type[k]) fprintf(stderr, "    census: no type tag %u\n", k), (*missing)++;
    if (!cs->erase_rows) fprintf(stderr, "    census: no ERASE of rows\n"), (*missing)++;
    if (!cs->erase_vers) fprintf(stderr, "    census: no ERASE's rewritten versions\n"), (*missing)++;
    if (!cs->erase_roles) fprintf(stderr, "    census: no ERASE of role entries\n"), (*missing)++;
}

/* the census over each copy in dir: a directory holding a log/, or one a level down (a fixture set's copies) */
static void census_walk(const char *dir, census *cs, int depth)
{
    char lg[1300];
    snprintf(lg, sizeof lg, "%s/log", dir);
    if (access(lg, F_OK) == 0) {
        census_log(dir, cs);
        return;
    }
    DIR *d = depth ? opendir(dir) : NULL;
    if (!d) return;
    struct dirent *de;
    while ((de = readdir(d))) {
        if (de->d_name[0] == '.') continue;
        char sub[1300];
        struct stat st;
        snprintf(sub, sizeof sub, "%s/%s", dir, de->d_name);
        if (lstat(sub, &st) == 0 && S_ISDIR(st.st_mode)) census_walk(sub, cs, depth - 1);
    }
    closedir(d);
}

/* the census over each copy of a tarball */
static void census_tarball(const char *tgz, census *cs)
{
    const char *dir = test_tmpdir();
    char cmd[1600];
    snprintf(cmd, sizeof cmd, "tar -xzf '%s' -C '%s'", tgz, dir);
    CHECK(system(cmd) == 0);
    census_walk(dir, cs, 2);
}

static void t_format1_census(void)
{
    census cs;
    memset(&cs, 0, sizeof cs);
    census_tarball("tests/fixtures/format1-20261115.tar.gz", &cs);
    int missing = 0;
    census_say(&cs, &missing);
    if (missing) fprintf(stderr, "    census: %u frames, %d missing\n", cs.frames, missing);
    CHECK(cs.frames > 0 && missing == 0);
}

/* ---- format 1's fixtures (make_format1.sh; docs/format-1.md §5) ---- */

static int fx_fails;
#define FX(cond, ...)                                                                                                  \
    do {                                                                                                               \
        if (!(cond)) {                                                                                                 \
            fprintf(stderr, "    fixture: " __VA_ARGS__);                                                              \
            fprintf(stderr, "\n");                                                                                     \
            fx_fails++;                                                                                                \
        }                                                                                                              \
    } while (0)

static int fx_sql(imdb_db *db, const char *sql)
{
    imdb_session s;
    imdb_session_init(&s, db);
    imdb_result r;
    imdb_err_clear(E);
    int rc = imdb_exec_one(&s, sql, strlen(sql), NULL, 0, &r, E);
    if (!rc) imdb_result_free(&r);
    imdb_session_close(&s);
    return rc;
}

/* a copy's last commit, its time and digest (a read-only open; *seq 0: it did not open) */
static void fx_state(const char *dir, uint64_t *seq, uint64_t *time_us, uint8_t digest[32])
{
    imdb_open_opts o = {.read_only = true};
    imdb_db *db = NULL;
    *seq = *time_us = 0;
    imdb_err_clear(E);
    if (imdb_open(dir, &o, &db, E)) {
        fprintf(stderr, "    fixture: %s does not open: %s\n", dir, g_e.msg);
        fx_fails++;
        return;
    }
    *seq = db->seq;
    *time_us = db->last_time;
    imdb_state_digest(db, NULL, digest);
    imdb_close(db);
}

static bool fx_same_file(const char *a, const char *b, const char *name)
{
    char pa[1000], pb[1000];
    snprintf(pa, sizeof pa, "%s/%s", a, name);
    snprintf(pb, sizeof pb, "%s/%s", b, name);
    size_t na = 0, nb = 0;
    uint8_t *x = slurp(pa, &na), *y = slurp(pb, &nb);
    bool same = (!x && !y && access(pa, F_OK) != 0 && access(pb, F_OK) != 0) || (x && y && na == nb && memcmp(x, y, na) == 0);
    free(x);
    free(y);
    return same;
}

/* the writer opened with the clock at its last commit plus ahead, verified, given one commit and no other (nothing due)
 * and closed; each follower given it too (a ship from its own last commit): their digests the writer's */
static void fx_write(const char *w, const char *const *followers, size_t nf, const char *sql, uint64_t ahead_us)
{
    uint64_t seq, t;
    uint8_t d[32];
    fx_state(w, &seq, &t, d);
    if (!seq) return;
    imdb_clock_freeze(t + ahead_us);
    imdb_open_opts o = {.sync = 0};
    imdb_db *db = NULL;
    imdb_err_clear(E);
    int rc = imdb_open(w, &o, &db, E);
    FX(rc == IMDB_OK, "%s: the writable open: %s", w, g_e.msg);
    if (!db) return;
    FX(db->seq == seq, "%s: the open committed (%llu to %llu)", w, (unsigned long long)seq, (unsigned long long)db->seq);
    imdb_verify_report vr;
    memset(&vr, 0, sizeof vr);
    imdb_err_clear(E);
    FX(imdb_verify(db, &vr, E) == IMDB_OK, "%s: VERIFY: %s", w, g_e.msg);
    FX(fx_sql(db, sql) == IMDB_OK, "%s: %s: %s", w, sql, g_e.msg);
    FX(db->seq == seq + 1, "%s: the commit and nothing else (%llu after %llu)", w, (unsigned long long)db->seq,
       (unsigned long long)seq);
    uint8_t dw[32];
    imdb_state_digest(db, NULL, dw);
    imdb_close(db);
    char stream[1100];
    for (size_t i = 0; i < nf; i++) {
        uint64_t fs, ft;
        uint8_t fd[32];
        fx_state(followers[i], &fs, &ft, fd);
        snprintf(stream, sizeof stream, "%s.stream", followers[i]);
        imdb_err_clear(E);
        FX(ship_to_file(w, fs, stream, E) == IMDB_OK, "ship %s: %s", w, g_e.msg);
        imdb_db *r = NULL;
        imdb_open_opts ro = {.sync = 0};
        imdb_err_clear(E);
        if (imdb_open(followers[i], &ro, &r, E) == IMDB_OK) {
            uint64_t applied = 0;
            imdb_err_clear(E);
            FX(apply_file(r, stream, &applied, E) == IMDB_OK && r->seq == seq + 1, "%s: the apply: %s", followers[i],
               g_e.msg);
            uint8_t dr[32];
            imdb_state_digest(r, NULL, dr);
            FX(memcmp(dr, dw, 32) == 0, "%s: a digest other than its writer's", followers[i]);
            imdb_close(r);
        } else {
            FX(false, "%s does not open writable: %s", followers[i], g_e.msg);
        }
        unlink(stream);
    }
}

/* the witness: a fresh replica of w fed w's whole log from commit 1 (or, from_seed, the fixture's own seed stream and
 * then the commits past it), byte for byte like: its log's frames like's, its LAKE_HEAD like's, its digest w's */
static void fx_witness(const char *w, const char *like, const char *witness, const char *from_seed, bool frames)
{
    char stream[1100];
    snprintf(stream, sizeof stream, "%s.stream", witness);
    imdb_err_clear(E);
    FX(imdb_init(witness, true, w, E) == IMDB_OK, "%s: init-replica: %s", witness, g_e.msg);
    imdb_db *r = NULL;
    imdb_open_opts ro = {.sync = 0};
    imdb_err_clear(E);
    if (imdb_open(witness, &ro, &r, E)) {
        FX(false, "%s does not open: %s", witness, g_e.msg);
        return;
    }
    uint64_t applied = 0;
    if (from_seed) {
        imdb_err_clear(E);
        FX(apply_file(r, from_seed, &applied, E) == IMDB_OK, "%s: the seed: %s", witness, g_e.msg);
        imdb_close(r); /* a seeded replica's next open: it goes on from the seed's commit */
        r = NULL;
        imdb_err_clear(E);
        if (imdb_open(witness, &ro, &r, E)) {
            FX(false, "%s does not open after its seed: %s", witness, g_e.msg);
            return;
        }
    }
    imdb_err_clear(E);
    FX(ship_to_file(w, r->seq, stream, E) == IMDB_OK, "ship %s for the witness: %s", w, g_e.msg);
    imdb_err_clear(E);
    FX(apply_file(r, stream, &applied, E) == IMDB_OK, "%s: the apply: %s", witness, g_e.msg);
    imdb_close(r);
    unlink(stream);
    uint64_t sw, sl, sq, t;
    uint8_t dw[32], dl[32], dq[32];
    fx_state(witness, &sw, &t, dw);
    fx_state(like, &sl, &t, dl);
    fx_state(w, &sq, &t, dq);
    FX(sw == sl && sw == sq && memcmp(dw, dl, 32) == 0 && memcmp(dw, dq, 32) == 0, "%s: not %s's state", witness, like);
    FX(fx_same_file(witness, like, "LAKE_HEAD"), "%s: a LAKE_HEAD other than %s's", witness, like);
    if (frames) {
        char la[1100], lb[1100], why[400] = "";
        snprintf(la, sizeof la, "%s/log", witness);
        snprintf(lb, sizeof lb, "%s/log", like);
        FX(logs_identical(la, lb, why, sizeof why), "%s: its log not %s's: %s", witness, like, why);
    }
}

static void fx_audit(const char *dir)
{
    int ar = audit_refuses(dir, "");
    FX(ar == 2 || ar < 0, "the auditor refused %s", dir);
}

static void fx_pass(uint64_t ahead_us)
{
    const char *root = test_tmpdir();
    char cmd[1600];
    snprintf(cmd, sizeof cmd, "tar -xzf tests/fixtures/format1-20261115.tar.gz -C '%s'", root);
    FX(system(cmd) == 0, "the tarball (tests/fixtures/format1-20261115.tar.gz) does not unpack: run from the tree root");
    char p[900], r[900], rest[900], restored[900], wit[900], cat[900], key[900], full[900], incr[900];
    snprintf(p, sizeof p, "%s/main/primary", root);
    snprintf(r, sizeof r, "%s/main/replica", root);
    snprintf(rest, sizeof rest, "%s/main/rest", root);
    snprintf(restored, sizeof restored, "%s/main/restored", root);
    snprintf(wit, sizeof wit, "%s/main/witness", root);
    snprintf(cat, sizeof cat, "%s/main/catalogue", root);
    snprintf(key, sizeof key, "%s/main/backup.key", root);
    snprintf(full, sizeof full, "%s/main/full.bak", root);
    snprintf(incr, sizeof incr, "%s/main/incr.bak", root);
    /* the backups first, while the primary is as they hold it: restored, the state the replica holds */
    uint64_t rs, rt, bs, bt;
    uint8_t rd[32], bd[32], bk[IMDB_BACKUP_KEY_LEN];
    fx_state(r, &rs, &rt, rd);
    imdb_err_clear(E);
    FX(imdb_backup_key_load(key, bk, E) == IMDB_OK, "the backup key: %s", g_e.msg);
    const char *files[2] = {full, incr};
    imdb_backup_info bi;
    imdb_err_clear(E);
    FX(imdb_restore(rest, bk, files, 2, &bi, E) == IMDB_OK, "the restore of both backups: %s", g_e.msg);
    imdb_wipe(bk, sizeof bk);
    fx_state(rest, &bs, &bt, bd);
    FX(bs == rs && memcmp(bd, rd, 32) == 0, "the restored copy is not the primary's state at its last backup");
    fx_audit(rest);
    imdb_catalogue cg;
    memset(&cg, 0, sizeof cg);
    imdb_err_clear(E);
    int rc = imdb_catalogue_read(cat, &cg, E);
    FX(rc == IMDB_OK && cg.nb == 2 && cg.ne >= 1, "the catalogue: %d %s", rc, g_e.msg);
    if (rc == IMDB_OK) imdb_catalogue_free(&cg);
    snprintf(cmd, sizeof cmd, "%s/ERASE_DEBT", restored);
    FX(access(cmd, F_OK) == 0, "the restore accepting an erasure keeps no ERASE_DEBT");
    fx_state(restored, &bs, &bt, bd);
    fx_audit(restored);
    /* main: written to with the anchor it was written under, then replicated; the witness from commit 1 */
    const char *mf[1] = {r};
    fx_write(p, mf, 1, "INSERT INTO bools (id, b, f) VALUES (100, TRUE, 9.5)", ahead_us);
    fx_witness(p, r, wit, NULL, true);
    fx_audit(p);
    fx_audit(r);
    /* cut: VERIFY from FLOOR, the replica and the seeded one given the commit; the witness from the seed stream */
    char cp[900], cr[900], sd[900], ss[900], cw[900];
    snprintf(cp, sizeof cp, "%s/cut/primary", root);
    snprintf(cr, sizeof cr, "%s/cut/replica", root);
    snprintf(sd, sizeof sd, "%s/cut/seeded", root);
    snprintf(ss, sizeof ss, "%s/cut/seed.stream", root);
    snprintf(cw, sizeof cw, "%s/cut/witness", root);
    const char *cf[2] = {cr, sd};
    fx_write(cp, cf, 2, "INSERT INTO k VALUES (100, 100, 'k100')", ahead_us);
    fx_witness(cp, sd, cw, ss, false);
    FX(fx_same_file(cw, sd, "FLOOR"), "the cut set's witness: a FLOOR other than the seeded replica's");
    FX(fx_same_file(cp, cr, "FLOOR"), "the cut set's replica: a FLOOR other than its primary's");
    fx_audit(cp);
    fx_audit(cr);
    fx_audit(sd);
    fx_audit(cw);
    /* promote: the promoted writer, the old one its replica; the witness from commit 1, through the promotion */
    char qw[900], qo[900], qx[900];
    snprintf(qw, sizeof qw, "%s/promote/writer", root);
    snprintf(qo, sizeof qo, "%s/promote/old", root);
    snprintf(qx, sizeof qx, "%s/promote/witness", root);
    const char *qf[1] = {qo};
    fx_write(qw, qf, 1, "INSERT INTO p VALUES (100, 'hundred')", ahead_us);
    fx_witness(qw, qw, qx, NULL, true);
    fx_audit(qw);
    fx_audit(qo);
    imdb_clock_freeze(0);
}

/* The fixtures' instances no other case reads: each anchor taken by a writable open under it (a commit, the anchor then
 * naming it), the root ledger by a second promotion through it (epoch 2, its line appended), ERASE_DEBT's record */
static void t_format1_fixture_instances(void)
{
    const char *root = test_tmpdir();
    char cmd[1600];
    snprintf(cmd, sizeof cmd, "tar -xzf tests/fixtures/format1-20261115.tar.gz -C '%s'", root);
    CHECK(system(cmd) == 0);
    char p[900], qa[900], ma[900], qw[900], qo[900], rk[900], led[900], debt[900];
    snprintf(p, sizeof p, "%s/main/primary", root);
    snprintf(ma, sizeof ma, "%s/main/anchor", root);
    snprintf(qw, sizeof qw, "%s/promote/writer", root);
    snprintf(qo, sizeof qo, "%s/promote/old", root);
    snprintf(qa, sizeof qa, "%s/promote/anchor", root);
    snprintf(rk, sizeof rk, "%s/promote/root.key", root);
    snprintf(led, sizeof led, "%s/promote/root.key.ledger", root);
    snprintf(debt, sizeof debt, "%s/main/restored/ERASE_DEBT", root);
    const char *dirs[2] = {p, qw}, *anchors[2] = {ma, qa}, *sqls[2] = {"INSERT INTO bools (id, b, f) VALUES (300, TRUE, 1.0)",
                                                                      "INSERT INTO p VALUES (300, 'anchored')"};
    for (int i = 0; i < 2; i++) {
        uint64_t s, t;
        uint8_t d[32];
        fx_state(dirs[i], &s, &t, d);
        imdb_clock_freeze(t);
        size_t n0 = 0, n1 = 0;
        uint8_t *a0 = slurp(anchors[i], &n0);
        imdb_open_opts o = {.sync = 1, .anchor = anchors[i]};
        imdb_db *db = NULL;
        OK(imdb_open(dirs[i], &o, &db, E));
        if (db) {
            CHECK(fx_sql(db, sqls[i]) == IMDB_OK && db->seq == s + 1);
            imdb_close(db);
        }
        uint8_t *a1 = slurp(anchors[i], &n1);
        CHECK(a0 && a1 && n0 == n1 && n0 == IMDB_ANCHOR_FILE && memcmp(a0, a1, n0) != 0); /* it names the new commit */
        free(a0);
        free(a1);
    }
    /* the old writer, the promoted one's replica, given its commit and promoted through the ledger to epoch 2 */
    const char *qf[1] = {qo};
    fx_write(qw, qf, 1, "INSERT INTO p VALUES (301, 'before the second promotion')", 0);
    size_t kn = 0, ln0 = 0, ln1 = 0;
    uint8_t *seed = slurp(rk, &kn), *l0 = slurp(led, &ln0);
    CHECK(seed && kn == IMDB_SEED_LEN && l0);
    if (seed && kn == IMDB_SEED_LEN) {
        imdb_promote_opts po = {.anchor = qa, .ledger = led};
        imdb_promote_result pr;
        memset(&pr, 0, sizeof pr);
        imdb_err_clear(E);
        int rc = imdb_promote(qo, seed, &po, &pr, E);
        CHECK(rc == IMDB_OK && pr.committed && pr.epoch == 2);
        if (rc) fprintf(stderr, "    the second promotion: %s\n", g_e.msg);
        uint8_t *l1 = slurp(led, &ln1);
        CHECK(l1 && ln1 > ln0 && memcmp(l0, l1, ln0) == 0); /* appended, the first promotion's line kept */
        free(l1);
        fx_audit(qo);
    }
    if (seed) imdb_wipe(seed, kn);
    free(seed);
    free(l0);
    size_t dn = 0;
    uint8_t *db = slurp(debt, &dn);
    CHECK(db && dn > 21 && memcmp(db, "imagedb-erase-debt 1\n", 21) == 0 && mem_contains(db, dn, "erase "));
    free(db);
    imdb_clock_freeze(0);
}

/* Format 1's fixtures with the engine's clock frozen at each copy's last commit, then a decade past it: the same verdicts
 * (every table kept FOREVER, no backup with an expiry: nothing is ever due); the census holds every structure */
static void t_format1_fixtures(void)
{
    fx_fails = 0;
    fx_pass(0);
    fx_pass(10ull * 366 * 86400 * 1000000);
    CHECK(fx_fails == 0);
}

/* The two helpers' edges: a stem and as many digits, a greater number; a text's number ended by a newline */
static void t_format1_later_helpers(void)
{
    CHECK(imdb_later_magic((const uint8_t *)"IMDBDUR2", 8, "IMDBDUR1"));
    CHECK(imdb_later_magic((const uint8_t *)"IMDBDV02", 8, "IMDBDV01"));
    CHECK(imdb_later_magic((const uint8_t *)"IMDBDV10", 8, "IMDBDV01"));
    CHECK(!imdb_later_magic((const uint8_t *)"IMDBDUR1", 8, "IMDBDUR1"));
    CHECK(!imdb_later_magic((const uint8_t *)"IMDBDUR0", 8, "IMDBDUR1"));
    CHECK(!imdb_later_magic((const uint8_t *)"IMDBDURX", 8, "IMDBDUR1"));
    CHECK(!imdb_later_magic((const uint8_t *)"IMDBDXR2", 8, "IMDBDUR1"));
    CHECK(!imdb_later_magic((const uint8_t *)"IMDBDUR", 7, "IMDBDUR1"));
    CHECK(!imdb_later_magic((const uint8_t *)"IMDBDV0A", 8, "IMDBDV01"));
    unsigned long v = 0;
    CHECK(imdb_later_text((const uint8_t *)"imagedb-meta 6\n", 15, "imagedb-meta ", 5, &v) && v == 6);
    CHECK(imdb_later_text((const uint8_t *)"imagedb-meta 10\nx", 17, "imagedb-meta ", 5, &v) && v == 10);
    CHECK(!imdb_later_text((const uint8_t *)"imagedb-meta 5\n", 15, "imagedb-meta ", 5, &v));
    CHECK(!imdb_later_text((const uint8_t *)"imagedb-meta 4\n", 15, "imagedb-meta ", 5, &v));
    CHECK(!imdb_later_text((const uint8_t *)"imagedb-meta 6", 14, "imagedb-meta ", 5, &v));     /* no newline */
    CHECK(!imdb_later_text((const uint8_t *)"imagedb-meta 06\n", 16, "imagedb-meta ", 5, &v));  /* a leading zero */
    CHECK(!imdb_later_text((const uint8_t *)"imagedb-meta 6x\n", 16, "imagedb-meta ", 5, &v));  /* not a number */
    CHECK(!imdb_later_text((const uint8_t *)"imagedb-meta \n", 14, "imagedb-meta ", 5, &v));    /* none */
    CHECK(!imdb_later_text((const uint8_t *)"imagedb-lake 6\n", 15, "imagedb-meta ", 5, &v));   /* another's */
    CHECK(!imdb_later_text((const uint8_t *)"imagedb-meta 1234567890\n", 24, "imagedb-meta ", 5, &v)); /* past 9 digits */
}

const test_case format1_tests[] = {
    {"format1_later_helpers", t_format1_later_helpers},
    {"format1_later_refused", t_format1_later_refused},
    {"format1_later_stream", t_format1_later_stream},
    {"format1_later_files", t_format1_later_files},
    {"format1_later_rewind_promote", t_format1_later_rewind_promote},
    {"format1_census", t_format1_census},
    {"format1_fixtures", t_format1_fixtures},
    {"format1_fixture_instances", t_format1_fixture_instances},
};
const size_t format1_ntests = sizeof format1_tests / sizeof *format1_tests;
