/* Tagged log segments (design.md §3, "Tagged, preallocated segments"): the scan's rules one by
 * one on segments laid out as the writer lays them, every crash state of a group written by
 * several appends, and the writer's fill through the engine. */
#include <stdlib.h>

#include "../../src/cpu.h"
#include "../../src/log.h"
#include "../../src/logdir.h"
#include "test.h"
#include "thelp.h"

#define SEC IMDB_TSEG_SECTOR
#define PAY IMDB_TSEG_PAYLOAD

/* A frame the scan accepts: its prefix and CRCs right, seq where log.h reads it, blen body bytes
 * (at least the descriptor) of a pattern that is never all zero. */
static size_t mkframe(uint64_t seq, uint32_t blen, uint8_t *out)
{
    uint8_t *body = out + IMDB_FRAME_HDR;
    for (uint32_t i = 0; i < blen; i++) body[i] = (uint8_t)(0x41 + (seq * 7 + i) % 23);
    body[0] = 1;
    imdb_le64(body + 5, seq);
    imdb_le32(out, IMDB_FRAME_MAGIC);
    imdb_le32(out + 4, blen);
    imdb_le32(out + 8, imdb_kern()->crc32c(0, body, blen));
    imdb_le32(out + 12, imdb_kern()->crc32c(0, out, 12));
    return IMDB_FRAME_HDR + blen;
}

/* A segment image: the header, then groups laid out by imdb_tgroup, then a fill. */
typedef struct seg {
    uint8_t *b;
    size_t cap;          /* bytes (sectors * 512) */
    uint8_t *frames;     /* every frame written, back to back */
    size_t nframes_bytes;
    uint64_t first, next; /* the next frame's seq */
    imdb_tgroup g;
    bool open;
    uint64_t at;         /* the next fresh sector when no group is open */
} seg;

static void seg_init(seg *s, uint64_t first, size_t sectors)
{
    memset(s, 0, sizeof *s);
    s->cap = sectors * SEC;
    s->b = calloc(1, s->cap);
    s->frames = calloc(1, 1u << 20);
    s->first = s->next = first;
    s->at = 1;
    imdb_tseg_header(first, s->b);
}

static void seg_free(seg *s)
{
    free(s->b);
    free(s->frames);
}

/* One append of a frame of blen body bytes: its sectors written whole at their place. */
static void seg_put(seg *s, uint32_t blen)
{
    if (!s->open) {
        imdb_tgroup_begin(&s->g, s->next, s->at);
        s->open = true;
    }
    uint8_t *f = s->frames + s->nframes_bytes;
    size_t n = mkframe(s->next++, blen, f);
    s->nframes_bytes += n;
    imdb_buf out;
    imdb_buf_init(&out);
    uint64_t at = imdb_tgroup_at(&s->g);
    imdb_tgroup_put(&s->g, f, n, &out);
    if (!out.err && at * SEC + out.len <= s->cap) memcpy(s->b + at * SEC, out.p, out.len);
    imdb_buf_free(&out);
}

/* The fdatasync: the group ends; the next begins at the sector after its last. */
static void seg_sync(seg *s)
{
    if (s->open) s->at = imdb_tgroup_end(&s->g);
    s->open = false;
}

/* Scans a copy of n bytes of the image (the scan works in place). */
static imdb_scan_status scan(const uint8_t *b, size_t n, uint64_t first, uint8_t **out, size_t *len, imdb_tseg_end *end)
{
    uint8_t *c = malloc(n ? n : 1);
    memcpy(c, b, n);
    imdb_err e = {0};
    imdb_scan_status st = imdb_tseg_scan(c, n, first, len, end, &e);
    snprintf(g_errmsg, sizeof g_errmsg, "%s", e.msg);
    *out = c;
    return st;
}

static uint64_t tag_of(const uint8_t *b, uint64_t sector) { return imdb_get_le64(b + sector * SEC); }

/* Whole groups, of every shape: frames that end mid-sector, at a sector's end, cross several. */
static void t_tseg_groups(void)
{
    static const uint32_t sizes[] = {109, 200, 334, 488, 489, 504 - 16, 1000, 1007, 1008 - 16, 3000, 109, 20000};
    for (int shape = 0; shape < 3; shape++) {
        seg s;
        seg_init(&s, 7, 400);
        for (size_t i = 0; i < sizeof sizes / sizeof *sizes; i++) {
            seg_put(&s, sizes[i]);
            if (shape == 0 || (shape == 1 && i % 3 == 2)) seg_sync(&s); /* 0: a group a frame; 1: of three; 2: one */
        }
        seg_sync(&s);
        uint8_t *out;
        size_t len;
        imdb_tseg_end end;
        imdb_scan_status st = scan(s.b, s.cap, 7, &out, &len, &end);
        CHECK(st == IMDB_SCAN_END);
        CHECK(len == s.nframes_bytes && memcmp(out, s.frames, len) == 0);
        CHECK(end.frames == sizeof sizes / sizeof *sizes && end.last == 7 + end.frames - 1);
        CHECK(end.next == s.at && end.dirty == s.at);
        free(out);
        /* without a fill (a closed segment): the same */
        st = scan(s.b, s.at * SEC, 7, &out, &len, &end);
        CHECK(st == IMDB_SCAN_END && len == s.nframes_bytes && end.next == s.at);
        free(out);
        seg_free(&s);
    }
}

/* The group's first sector carries the top bit; a frame ending at a sector's end lets the group
 * go on into the next sector (tagged g) or end there (the next group, or the fill). */
static void t_tseg_layout(void)
{
    seg s;
    seg_init(&s, 1, 64);
    seg_put(&s, 504 - 16); /* fills sector 1 exactly */
    seg_put(&s, 200);      /* the same group, from sector 2 */
    seg_sync(&s);
    seg_put(&s, 504 - 16); /* a group of one sector */
    seg_sync(&s);
    CHECK(tag_of(s.b, 1) == (1 | IMDB_TSEG_TOP) && tag_of(s.b, 2) == 1);
    CHECK(tag_of(s.b, 3) == (3 | IMDB_TSEG_TOP) && tag_of(s.b, 4) == 0);
    uint8_t *out;
    size_t len;
    imdb_tseg_end end;
    CHECK(scan(s.b, s.cap, 1, &out, &len, &end) == IMDB_SCAN_END && end.frames == 3 && end.next == 4);
    free(out);
    /* imdb_tseg_build: one group, no fill */
    imdb_buf b;
    imdb_buf_init(&b);
    imdb_tseg_build(1, s.frames, s.nframes_bytes, &b);
    CHECK(!b.err && b.len % SEC == 0);
    CHECK(scan(b.p, b.len, 1, &out, &len, &end) == IMDB_SCAN_END && end.frames == 3 && len == s.nframes_bytes &&
          memcmp(out, s.frames, len) == 0 && end.next * SEC == b.len);
    free(out);
    /* a frame built in pieces equals the whole */
    imdb_tgroup g;
    imdb_tgroup_begin(&g, 9, 5);
    uint8_t f[4000], whole[10 * SEC], piece[SEC];
    size_t n = mkframe(9, 3000, f);
    imdb_tgroup_advance(&g, f, 100); /* as if 100 bytes of the group were already there */
    size_t ns = imdb_tgroup_sectors(&g, n);
    imdb_tgroup_fill(&g, f, n, 0, ns, whole);
    for (size_t i = 0; i < ns; i++) {
        imdb_tgroup_fill(&g, f, n, i, 1, piece);
        CHECK(memcmp(piece, whole + i * SEC, SEC) == 0);
    }
    imdb_buf_free(&b);
    seg_free(&s);
}

static void t_tseg_header(void)
{
    seg s;
    seg_init(&s, 5, 8);
    seg_put(&s, 300);
    seg_sync(&s);
    uint8_t *out;
    size_t len;
    imdb_tseg_end end;
    CHECK(imdb_tseg_is_tagged(s.b, s.cap));
    CHECK(scan(s.b, s.cap, 5, &out, &len, &end) == IMDB_SCAN_END);
    free(out);
    CHECK(scan(s.b, s.cap, 6, &out, &len, &end) == IMDB_SCAN_CORRUPT); /* another name */
    free(out);
    CHECK(scan(s.b, s.cap - 1, 5, &out, &len, &end) == IMDB_SCAN_CORRUPT); /* not a multiple of 512 */
    free(out);
    static const size_t at[] = {4, 8, 16, 20, 511}; /* the version, first seq, CRC, padding */
    for (size_t i = 0; i < sizeof at / sizeof *at; i++) {
        s.b[at[i]] ^= 1;
        CHECK(scan(s.b, s.cap, 5, &out, &len, &end) == IMDB_SCAN_CORRUPT);
        free(out);
        s.b[at[i]] ^= 1;
    }
    s.b[0] = 'X';
    CHECK(!imdb_tseg_is_tagged(s.b, s.cap));
    seg_free(&s);
}

/* A zero sector inside a group: TORN from the frame that runs into it; later sectors of the group
 * may have landed. E is where the last kept frame ends. */
static void t_tseg_torn_inside(void)
{
    seg s;
    seg_init(&s, 1, 64);
    seg_put(&s, 300);
    seg_sync(&s); /* group 1: sector 1 */
    seg_put(&s, 400); /* group 2 from sector 2: frame 2 in sector 2, frame 3 crosses 2..4 */
    seg_put(&s, 1000);
    seg_put(&s, 100);
    seg_sync(&s);
    CHECK(tag_of(s.b, 2) == (2 | IMDB_TSEG_TOP) && tag_of(s.b, 3) == 2 && tag_of(s.b, 4) == 2);
    memset(s.b + 3 * SEC, 0, SEC); /* frame 3's middle sector never landed */
    uint8_t *out;
    size_t len;
    imdb_tseg_end end;
    CHECK(scan(s.b, s.cap, 1, &out, &len, &end) == IMDB_SCAN_TORN);
    CHECK(end.frames == 2 && end.last == 2);
    CHECK(len == 2 * IMDB_FRAME_HDR + 300 + 400 && memcmp(out, s.frames, len) == 0);
    CHECK(end.keep_sector == 2 && end.keep_bytes == IMDB_FRAME_HDR + 400 && end.next == 3);
    CHECK(end.dirty == 6); /* sectors 4 and 5 (frames 3 and 4) landed: a repair zeroes them */
    free(out);
    seg_free(&s);
}

/* The advisor's state: frame k fills sector s1 exactly, frame k+1 takes s2 and s3; s2 lost, s3
 * landed. The group seemed to end at k (s2 zero), and a later part of it follows: TORN, not CORRUPT. */
static void t_tseg_lost_middle(void)
{
    seg s;
    seg_init(&s, 1, 64);
    seg_put(&s, 504 - 16); /* frame 1 fills sector 1 */
    seg_put(&s, 700);      /* frame 2: sectors 2 and 3 */
    seg_sync(&s);
    memset(s.b + 2 * SEC, 0, SEC);
    uint8_t *out;
    size_t len;
    imdb_tseg_end end;
    CHECK(scan(s.b, s.cap, 1, &out, &len, &end) == IMDB_SCAN_TORN);
    CHECK(end.frames == 1 && end.keep_sector == 2 && end.keep_bytes == 0 && end.next == 2 && end.dirty == 4);
    free(out);
    seg_free(&s);
}

/* The rewrite of a shared sector lost: frame k ends mid-sector (its old version: k, then zeros),
 * frame k+1's later sector landed. TORN. */
static void t_tseg_lost_rewrite(void)
{
    seg s;
    seg_init(&s, 1, 64);
    seg_put(&s, 200); /* frame 1: sector 1, 216 bytes of it */
    uint8_t v1[SEC];
    memcpy(v1, s.b + SEC, SEC); /* sector 1 as the first append wrote it */
    seg_put(&s, 900); /* frame 2: the rest of sector 1 (rewritten), sector 2, part of 3 */
    seg_sync(&s);
    memcpy(s.b + SEC, v1, SEC); /* the rewrite lost */
    uint8_t *out;
    size_t len;
    imdb_tseg_end end;
    CHECK(scan(s.b, s.cap, 1, &out, &len, &end) == IMDB_SCAN_TORN);
    CHECK(end.frames == 1 && end.keep_sector == 1 && end.keep_bytes == IMDB_FRAME_HDR + 200 && end.next == 2 &&
          end.dirty == 4);
    free(out);
    seg_free(&s);
}

/* The next group's first sector never landed, a later one did: TORN. */
static void t_tseg_first_lost(void)
{
    seg s;
    seg_init(&s, 1, 64);
    seg_put(&s, 300);
    seg_sync(&s);
    seg_put(&s, 1200); /* group 2: sectors 2..4 */
    seg_sync(&s);
    memset(s.b + 2 * SEC, 0, SEC);
    uint8_t *out;
    size_t len;
    imdb_tseg_end end;
    CHECK(scan(s.b, s.cap, 1, &out, &len, &end) == IMDB_SCAN_TORN && end.frames == 1 && end.next == 2 && end.dirty == 5);
    free(out);
    seg_free(&s);
}

/* A later group after a torn one: the torn one had been flushed, so it is damage: CORRUPT. Also a
 * gap of zero sectors before a group, and foreign tags. */
static void t_tseg_corrupt(void)
{
    seg s;
    seg_init(&s, 1, 64);
    seg_put(&s, 300);
    seg_sync(&s); /* group 1: sector 1 */
    seg_put(&s, 900);
    seg_sync(&s); /* group 2: sectors 2, 3 */
    seg_put(&s, 300);
    seg_sync(&s); /* group 3: sector 4 */
    uint8_t *out, keep[SEC];
    size_t len;
    imdb_tseg_end end;
    CHECK(scan(s.b, s.cap, 1, &out, &len, &end) == IMDB_SCAN_END && end.frames == 3);
    free(out);
    memcpy(keep, s.b + 3 * SEC, SEC);
    memset(s.b + 3 * SEC, 0, SEC); /* group 2 torn, group 3 after it */
    CHECK(scan(s.b, s.cap, 1, &out, &len, &end) == IMDB_SCAN_CORRUPT);
    free(out);
    memcpy(s.b + 3 * SEC, keep, SEC);
    memcpy(keep, s.b + 2 * SEC, SEC);
    memset(s.b + 2 * SEC, 0, SEC); /* group 2's first sector gone, group 3 there: CORRUPT */
    CHECK(scan(s.b, s.cap, 1, &out, &len, &end) == IMDB_SCAN_CORRUPT);
    free(out);
    memcpy(s.b + 2 * SEC, keep, SEC);
    imdb_le64(s.b + 3 * SEC, 99); /* inside group 2, another tag */
    CHECK(scan(s.b, s.cap, 1, &out, &len, &end) == IMDB_SCAN_CORRUPT);
    free(out);
    imdb_le64(s.b + 3 * SEC, 2);
    imdb_le64(s.b + 4 * SEC, 5 | IMDB_TSEG_TOP); /* a group naming the wrong seq */
    CHECK(scan(s.b, s.cap, 1, &out, &len, &end) == IMDB_SCAN_CORRUPT);
    free(out);
    imdb_le64(s.b + 4 * SEC, 3 | IMDB_TSEG_TOP);
    s.b[40 * SEC + 100] = 1; /* a byte in the fill */
    CHECK(scan(s.b, s.cap, 1, &out, &len, &end) == IMDB_SCAN_CORRUPT);
    free(out);
    s.b[40 * SEC + 100] = 0;
    s.b[SEC + 8 + IMDB_FRAME_HDR + 300 + 5] = 7; /* a byte in group 1's pad */
    CHECK(scan(s.b, s.cap, 1, &out, &len, &end) == IMDB_SCAN_CORRUPT);
    free(out);
    seg_free(&s);
}

/* A complete frame failing its CRC: DAMAGED with only zeros after it, CORRUPT with anything after. */
static void t_tseg_damaged(void)
{
    seg s;
    seg_init(&s, 1, 64);
    seg_put(&s, 300);
    seg_sync(&s);
    seg_put(&s, 700); /* group 2: sectors 2, 3 */
    seg_sync(&s);
    s.b[2 * SEC + 8 + IMDB_FRAME_HDR + 200] ^= 0x10;
    uint8_t *out;
    size_t len;
    imdb_tseg_end end;
    CHECK(scan(s.b, s.cap, 1, &out, &len, &end) == IMDB_SCAN_DAMAGED && end.frames == 1 && end.next == 2 &&
          end.dirty == 4);
    free(out);
    seg_put(&s, 100); /* a group after it */
    seg_sync(&s);
    CHECK(scan(s.b, s.cap, 1, &out, &len, &end) == IMDB_SCAN_CORRUPT);
    free(out);
    seg_free(&s);
    /* A large frame, early in the segment, damaged in its last sector. The scan copies its body
     * forward before it knows: the copy must stay behind what is still to be read, so the zeros
     * after it are still zeros (DAMAGED), and a group after it is still seen (CORRUPT). */
    for (int after = 0; after < 2; after++) {
        seg t;
        seg_init(&t, 1, 128);
        seg_put(&t, 30000); /* group 1: sectors 1..60 */
        seg_sync(&t);
        if (after) {
            seg_put(&t, 100);
            seg_sync(&t);
        }
        uint64_t lastsec = 1 + (IMDB_FRAME_HDR + 30000 - 1) / PAY;
        t.b[lastsec * SEC + 8 + 10] ^= 0x20;
        CHECK(scan(t.b, t.cap, 1, &out, &len, &end) == (after ? IMDB_SCAN_CORRUPT : IMDB_SCAN_DAMAGED) && end.frames == 0);
        if (!after) CHECK(end.dirty == lastsec + 1 && end.next == 1);
        free(out);
        seg_free(&t);
    }
}

/* Seqs: the group's tag must be its first frame's, and frames follow one another. */
static void t_tseg_seq(void)
{
    seg s;
    seg_init(&s, 1, 64);
    seg_put(&s, 300);
    seg_sync(&s);
    uint8_t *out;
    size_t len;
    imdb_tseg_end end;
    CHECK(scan(s.b, s.cap, 2, &out, &len, &end) == IMDB_SCAN_CORRUPT); /* its header names 1 */
    free(out);
    seg t;
    seg_init(&t, 1, 64);
    t.next = 2; /* the first frame is commit 2, in a segment named 1 */
    seg_put(&t, 300);
    seg_sync(&t);
    CHECK(scan(t.b, t.cap, 1, &out, &len, &end) == IMDB_SCAN_CORRUPT);
    free(out);
    /* the tags right, a frame's own seq wrong: the group's first, then one inside a group */
    for (int which = 0; which < 2; which++) {
        uint8_t img[16 * SEC] = {0}, f[2000];
        imdb_tseg_header(1, img);
        imdb_tgroup g;
        imdb_tgroup_begin(&g, 1, 1);
        imdb_buf o;
        imdb_buf_init(&o);
        for (uint64_t i = 0; i < 3; i++) {
            uint64_t seq = which == 0 ? (i == 0 ? 5 : i + 1) : (i == 2 ? 4 : i + 1);
            size_t n = mkframe(seq, 300, f);
            uint64_t at = imdb_tgroup_at(&g);
            imdb_tgroup_put(&g, f, n, &o);
            memcpy(img + at * SEC, o.p, o.len);
        }
        imdb_buf_free(&o);
        CHECK(scan(img, sizeof img, 1, &out, &len, &end) == IMDB_SCAN_CORRUPT && end.frames == (which == 0 ? 0u : 2u));
        free(out);
    }
    seg_free(&s);
    seg_free(&t);
}

/* A group must begin at the sector after the last one's end: zero sectors between them would be
 * lost sectors of a flushed group (or a write no layout makes). */
static void t_tseg_gap(void)
{
    seg s;
    seg_init(&s, 1, 64);
    seg_put(&s, 300);
    seg_sync(&s);
    s.at += 2; /* two sectors skipped */
    seg_put(&s, 300);
    seg_sync(&s);
    uint8_t *out;
    size_t len;
    imdb_tseg_end end;
    CHECK(scan(s.b, s.cap, 1, &out, &len, &end) == IMDB_SCAN_CORRUPT && end.frames == 1);
    free(out);
    seg_free(&s);
}

/* Every crash state of a group written by several appends (any version of each of its sectors: as
 * durable, zero, or as any append left it), after a durable group: END or TORN, never anything
 * else, and the kept frames are a prefix of what was written, never less than the durable group. */
static void t_tseg_crash_states(void)
{
    static const uint32_t plans[][4] = {{200, 300, 109, 900}, {504 - 16, 700, 109, 200}, {150, 150, 150, 150}};
    for (size_t p = 0; p < sizeof plans / sizeof *plans; p++) {
        seg s;
        seg_init(&s, 1, 32);
        seg_put(&s, 250);
        seg_sync(&s); /* group 1, durable */
        uint64_t g2 = s.at;
        /* versions[sector][v]: v 0 is zero (the fill), then each append's whole write */
        enum { NS = 6, NV = 5 };
        uint8_t ver[NS][NV][SEC];
        int nver[NS];
        memset(ver, 0, sizeof ver);
        for (int i = 0; i < NS; i++) nver[i] = 1;
        for (int a = 0; a < 4; a++) {
            seg_put(&s, plans[p][a]);
            for (int i = 0; i < NS; i++) {
                const uint8_t *now = s.b + (g2 + (uint64_t)i) * SEC;
                if (memcmp(now, ver[i][nver[i] - 1], SEC) != 0) memcpy(ver[i][nver[i]++], now, SEC);
            }
        }
        CHECK(s.g.sector + (s.g.len + PAY - 1) / PAY <= g2 + NS); /* the group fits the model */
        uint64_t states = 1;
        for (int i = 0; i < NS; i++) states *= (uint64_t)nver[i];
        uint64_t bad = 0, seen_torn = 0, seen_end = 0;
        for (uint64_t k = 0; k < states; k++) {
            uint64_t x = k;
            for (int i = 0; i < NS; i++) {
                memcpy(s.b + (g2 + (uint64_t)i) * SEC, ver[i][x % (uint64_t)nver[i]], SEC);
                x /= (uint64_t)nver[i];
            }
            uint8_t *out;
            size_t len;
            imdb_tseg_end end;
            imdb_scan_status st = scan(s.b, s.cap, 1, &out, &len, &end);
            bool prefix = len <= s.nframes_bytes && memcmp(out, s.frames, len) == 0;
            if ((st != IMDB_SCAN_END && st != IMDB_SCAN_TORN) || !prefix || end.frames < 1) bad++;
            seen_torn += st == IMDB_SCAN_TORN;
            seen_end += st == IMDB_SCAN_END;
            free(out);
        }
        printf("    plan %zu: %llu states, %llu END, %llu TORN, %llu wrong\n", p, (unsigned long long)states,
               (unsigned long long)seen_end, (unsigned long long)seen_torn, (unsigned long long)bad);
        CHECK(bad == 0 && seen_torn > 0 && seen_end > 0);
        seg_free(&s);
    }
}

/* A repair as a writable open makes it: keep E's sector up to E, zero every later non-zero sector.
 * The scan then ends cleanly with the same frames, and the next group begins at end.next. */
static void t_tseg_repair(void)
{
    seg s;
    seg_init(&s, 1, 64);
    seg_put(&s, 300);
    seg_sync(&s);
    seg_put(&s, 400);
    seg_put(&s, 1000);
    seg_put(&s, 100);
    seg_sync(&s);
    memset(s.b + 3 * SEC, 0, SEC);
    uint8_t *out;
    size_t len;
    imdb_tseg_end end;
    CHECK(scan(s.b, s.cap, 1, &out, &len, &end) == IMDB_SCAN_TORN);
    free(out);
    if (end.keep_bytes) memset(s.b + end.keep_sector * SEC + 8 + end.keep_bytes, 0, PAY - end.keep_bytes);
    for (uint64_t z = end.keep_bytes ? end.keep_sector + 1 : end.keep_sector; z < end.dirty; z++) memset(s.b + z * SEC, 0, SEC);
    imdb_tseg_end e2;
    CHECK(scan(s.b, s.cap, 1, &out, &len, &e2) == IMDB_SCAN_END && e2.frames == end.frames && e2.next == end.next);
    free(out);
    seg_free(&s);
}

/* The zero bytes after a segment's last written sector: the fill the writer has ahead (frames are
 * never all zero, a tag in every sector). */
static uint64_t fill_left(const char *path)
{
    size_t n = 0;
    uint8_t *b = path ? slurp(path, &n) : NULL;
    if (!b || n % SEC) {
        free(b);
        return UINT64_MAX;
    }
    size_t last = 0;
    for (size_t s = 1; s < n / SEC; s++)
        for (size_t i = 0; i < SEC; i++)
            if (b[s * SEC + i]) {
                last = s;
                break;
            }
    free(b);
    return n - (last + 1) * SEC;
}

/* The fill through the engine (design.md §3, "The fill"): under --nosync it is never extended (the
 * frames go past it, as appends did); under synchronous commits a frame of up to the low-water mark
 * that leaves less extends it by a chunk, so a commit always finds that much ahead; a larger frame
 * never extends it (written past it, the file ends where the frame does), and the next small one
 * extends again. A reopen reads every row back and VERIFY passes. */
static void t_tseg_fill(void)
{
    char *dir = path_join(test_tmpdir(), "p");
    OK(imdb_init(dir, false, NULL, E));
    static char memo[60001];
    memset(memo, 'f', sizeof memo - 1);
    imdb_db *db = open_db(dir); /* --nosync */
    CHECK(db);
    if (!db) return;
    OK(make_table(db, E)); /* the first commit makes the first segment */
    CHECK(db->log_tagged);
    uint64_t left = fill_left(seg_path(dir, -1)), was;
    int64_t id = 1, small = 0;
    for (; id <= 20; id++) { /* 1.2 MB: more than the first fill */
        OK(ins1(db, id, 7, 100, memo));
        was = left;
        left = fill_left(seg_path(dir, -1));
        CHECK(left <= was);
    }
    CHECK(left == 0);
    imdb_close(db);
    imdb_open_opts o = {.sync = 1};
    OK(imdb_open(dir, &o, &db, E));
    CHECK(fill_left(seg_path(dir, -1)) == 0);
    int extended = 0;
    for (; id <= 45; id++) {
        OK(ins1(db, id, 7, 100, memo));
        was = left;
        left = fill_left(seg_path(dir, -1));
        CHECK(left >= IMDB_LOG_FILL_LOW && left != UINT64_MAX);
        extended += left > was;
    }
    CHECK(extended >= 2);
    int64_t n = (int64_t)(left / 60000) + 2, k = 0; /* a frame larger than the fill left */
    imdb_table *t = imdb_table_by_name(db, "txns");
    OK(imdb_begin(db, E));
    for (; k < n; k++) {
        imdb_value v[4];
        row_vals(v, id + k, 7, 100, memo);
        OK(imdb_insert(db, t, v, E));
    }
    OK(imdb_commit(db, E));
    id += n;
    CHECK(fill_left(seg_path(dir, -1)) == 0);
    OK(ins1(db, id, 7, 100, "row"));
    small = id;
    CHECK(fill_left(seg_path(dir, -1)) == IMDB_LOG_FILL_CHUNK);
    imdb_close(db);
    db = open_db(dir);
    CHECK(db);
    if (!db) return;
    CHECK(count_subject(db, 7, db->seq) == (uint64_t)small && pk_lookup(db, small, db->seq) != IMDB_NONE);
    imdb_verify_report vr;
    memset(&vr, 0, sizeof vr);
    OK(imdb_verify(db, &vr, E));
    imdb_close(db);
}

/* A segment ends (its last commit published a manifest) and the next commit makes the next one: its
 * fill goes, whether that commit runs in the process that ended it or in a later one (the open left
 * the ended segment closed); the last segment keeps its fill. */
static void t_tseg_end_after_reopen(void)
{
    for (int later = 0; later < 2; later++) {
        char *dir = path_join(test_tmpdir(), later ? "later" : "same");
        OK(imdb_init(dir, false, NULL, E));
        imdb_db *db = open_db(dir);
        CHECK(db);
        if (!db) return;
        OK(make_table(db, E));
        OK(ins1(db, 1, 7, 100, "row"));
        OK(imdb_checkpoint(db, E));
        CHECK(log_segments(dir) == 1 && fill_left(seg_path(dir, -1)) > IMDB_LOG_FILL_LOW);
        if (later) {
            imdb_close(db);
            db = open_db(dir);
            CHECK(db && db->log_rotate && db->logfd < 0);
            if (!db) return;
        }
        OK(ins1(db, 2, 7, 100, "row"));
        CHECK(log_segments(dir) == 2 && fill_left(seg_path(dir, 0)) == 0 && fill_left(seg_path(dir, -1)) > IMDB_LOG_FILL_LOW);
        imdb_close(db);
        db = open_db(dir);
        CHECK(db && db->seq == 4 && pk_lookup(db, 2, db->seq) != IMDB_NONE);
        imdb_verify_report vr;
        memset(&vr, 0, sizeof vr);
        if (db) OK(imdb_verify(db, &vr, E));
        imdb_close(db);
    }
}

/* the auditor's verdict on dir: 0 accepts, 1 rejects, -1 when it is not available (IMDB_AUDIT_BIN) */
static int audit_verdict(const char *dir)
{
    const char *bin = getenv("IMDB_AUDIT_BIN");
    if (!bin || !*bin) return -1;
    char cmd[1600];
    snprintf(cmd, sizeof cmd, "'%s' verify '%s' >/dev/null 2>&1", bin, dir);
    return system(cmd) == 0 ? 0 : 1;
}

/* A new segment whose header never landed (a crash in log_new_segment: the file made and nothing in it,
 * or zeros only) after a tagged, ended one: no reader takes it for an untagged segment after a tagged
 * one; a read-only open, VERIFY and the auditor accept it, and a writable open makes it tagged and goes
 * on in it. The lake snapshot is at the ended segment's last commit, so the open replays only it. */
static void t_tseg_blank_last(void)
{
    static uint8_t z[IMDB_TSEG_SECTOR + 4096];
    for (int zeros = 0; zeros < 2; zeros++) {
        char *dir = path_join(test_tmpdir(), zeros ? "zeros" : "empty");
        OK(imdb_init(dir, false, NULL, E));
        imdb_db *db = open_db(dir);
        CHECK(db);
        if (!db) return;
        OK(make_table(db, E));
        OK(ins1(db, 1, 7, 100, "row"));
        OK(imdb_checkpoint(db, E));
        uint64_t next = db->seq + 1;
        imdb_close(db);
        char name[IMDB_LOGSEG_NAME + 1], p[800];
        imdb_logseg_name(next, name);
        snprintf(p, sizeof p, "%s/log/%s", dir, name);
        spit(p, z, zeros ? sizeof z : 0);
        imdb_open_opts ro = {.sync = 0, .read_only = true};
        OK(imdb_open(dir, &ro, &db, E));
        imdb_verify_report vr;
        memset(&vr, 0, sizeof vr);
        OK(imdb_verify(db, &vr, E));
        CHECK(db->seq == next - 1);
        imdb_close(db);
        CHECK(audit_verdict(dir) != 1);
        db = open_db(dir);
        CHECK(db);
        if (!db) return;
        OK(ins1(db, 2, 7, 100, "row"));
        CHECK(db->seq == next && log_segments(dir) == 2);
        imdb_close(db);
        size_t n = 0;
        uint8_t *b = slurp(p, &n);
        CHECK(b && imdb_tseg_is_tagged(b, n));
        free(b);
        db = open_db(dir);
        CHECK(db && db->seq == next && pk_lookup(db, 2, db->seq) != IMDB_NONE);
        memset(&vr, 0, sizeof vr);
        if (db) OK(imdb_verify(db, &vr, E));
        imdb_close(db);
        CHECK(audit_verdict(dir) != 1);
    }
}

const test_case tseg_tests[] = {
    {"tseg_groups", t_tseg_groups},
    {"tseg_layout", t_tseg_layout},
    {"tseg_header", t_tseg_header},
    {"tseg_torn_inside", t_tseg_torn_inside},
    {"tseg_lost_middle", t_tseg_lost_middle},
    {"tseg_lost_rewrite", t_tseg_lost_rewrite},
    {"tseg_first_lost", t_tseg_first_lost},
    {"tseg_corrupt", t_tseg_corrupt},
    {"tseg_damaged", t_tseg_damaged},
    {"tseg_seq", t_tseg_seq},
    {"tseg_gap", t_tseg_gap},
    {"tseg_crash_states", t_tseg_crash_states},
    {"tseg_repair", t_tseg_repair},
    {"tseg_fill", t_tseg_fill},
    {"tseg_end_after_reopen", t_tseg_end_after_reopen},
    {"tseg_blank_last", t_tseg_blank_last},
};
const size_t tseg_ntests = sizeof tseg_tests / sizeof *tseg_tests;
