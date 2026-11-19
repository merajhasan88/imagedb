/* N1a: IMDBWIR1's decoders (server/wire.c) on any bytes. The first byte picks what the rest is: 0 a hello, 1 a challenge,
 * 2 a verdict (each exactly its fixed size), 3 one frame a client sends, 4 one a server sends (a ROWS frame against a
 * fixed COLUMNS: an INTEGER, a DECIMAL(38,6), a VARCHAR(12) and an ENUM), 5 a run of values, 6 a hello, a challenge,
 * then a proof, a StoredKey and a ServerKey (the server's check run twice: one verdict), 7 a COLUMNS frame and then a
 * ROWS frame against it. Whatever a decoder takes encodes back to its bytes exactly (one encoding each), and no block of
 * the wire's is left (imdbw_live_blocks). A disagreement aborts. IMDB_FUZZ_WIRE_SEEDS=DIR writes seeds there and exits
 * (fuzz/make_corpus.sh). */
#include <stdio.h>

#include "../server/wire.h"
#include "fuzz_common.h"

/* the fixed columns: "id" INTEGER, "amount" DECIMAL(38,6), "name" VARCHAR(12), "mood" ENUM ('', 'x', 'é') */
static const uint8_t kCols[] = {0x04, 0x00,                                                  /* four columns */
                                0x02, 'i',  'd',  0x01, 0x20, 0x00, 0x00, 0x00,              /* INT64, 32 bits */
                                0x06, 'a',  'm',  'o',  'u',  'n',  't',  0x05, 0x26, 0x00, 0x06, 0x00,
                                0x04, 'n',  'a',  'm',  'e',  0x04, 0x0c, 0x00, 0x00, 0x00,
                                0x04, 'm',  'o',  'o',  'd',  0x0d, 0x00, 0x00, 0x00, 0x00,
                                0x03, 0x00, 0x00, 0x01, 'x',  0x02, 0xc3, 0xa9};

static imdbw_msg g_cols;
static bool g_have;

static const imdbw_msg *fixed_cols(void)
{
    if (!g_have) {
        imdb_err e = {0};
        if (imdbw_msg_get(IMDBW_COLUMNS, kCols, sizeof kCols, NULL, &g_cols, &e)) abort(); /* the harness's own bug */
        g_have = true;
    }
    return &g_cols;
}

/* one frame of p's first n bytes: its length (0 when it does not parse as one of the side's) */
static size_t frame_len(const uint8_t *p, size_t n, bool server)
{
    uint32_t len;
    uint8_t type;
    imdb_err e = {0};
    if (n < IMDBW_HEAD || imdbw_head_get(p, server, &len, &type, &e) || (size_t)len + 4 > n) return 0;
    return (size_t)len + 4;
}

/* the frame decoded against cols and encoded again: abort unless the same bytes; m kept when keep (the caller frees) */
static bool frame(const uint8_t *p, size_t n, bool server, const imdbw_msg *cols, imdbw_msg *keep)
{
    if (frame_len(p, n, server) != n) return false;
    imdbw_msg m;
    imdb_err e = {0};
    if (imdbw_msg_get(p[4], p + IMDBW_HEAD, n - IMDBW_HEAD, cols, &m, &e)) return false;
    imdbw_buf b;
    imdbw_buf_init(&b);
    imdbw_msg_put(&b, &m, cols);
    if (b.err || b.len != n || memcmp(b.p, p, n)) abort(); /* taken, but not its one encoding */
    imdbw_buf_free(&b);
    if (keep) *keep = m;
    else imdbw_msg_free(&m);
    return true;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < 2) return 0;
    const imdbw_msg *cols = fixed_cols();
    int64_t live = imdbw_live_blocks();
    const uint8_t *p = data + 1;
    size_t n = size - 1;
    imdb_err e = {0};
    switch (data[0] % 8) {
    case 0: {
        imdbw_hello h;
        uint8_t again[IMDBW_HELLO_LEN];
        if (n == IMDBW_HELLO_LEN && imdbw_hello_get(p, &h, &e) == 0 && (imdbw_hello_put(&h, again) || memcmp(again, p, n)))
            abort();
        break;
    }
    case 1: {
        imdbw_challenge c;
        uint8_t again[IMDBW_CHALLENGE_LEN];
        if (n == IMDBW_CHALLENGE_LEN && imdbw_challenge_get(p, &c, &e) == 0 &&
            (imdbw_challenge_put(&c, again) || memcmp(again, p, n)))
            abort();
        break;
    }
    case 2: {
        imdbw_verdict v;
        uint8_t again[IMDBW_VERDICT_LEN];
        if (n == IMDBW_VERDICT_LEN && imdbw_verdict_get(p, &v, &e) == 0 && (imdbw_verdict_put(&v, again) || memcmp(again, p, n)))
            abort();
        break;
    }
    case 3: frame(p, n, false, NULL, NULL); break;
    case 4: frame(p, n, true, cols, NULL); break;
    case 5: {
        imdb_rd r;
        imdb_rd_init(&r, p, n);
        while (imdb_rd_left(&r)) {
            size_t at = r.off;
            imdbw_value v;
            imdb_err_clear(&e);
            if (imdbw_value_get(&r, &v, &e)) break;
            imdbw_buf b;
            imdbw_buf_init(&b);
            imdbw_value_put(&b, &v);
            if (b.err || b.len != r.off - at || memcmp(b.p, p + at, b.len)) abort();
            imdbw_buf_free(&b);
        }
        break;
    }
    case 6: {
        if (n != IMDBW_HELLO_LEN + IMDBW_CHALLENGE_LEN + 3 * IMDBW_KEY) break;
        imdbw_hello h;
        imdbw_challenge c;
        if (imdbw_hello_get(p, &h, &e) || imdbw_challenge_get(p + IMDBW_HELLO_LEN, &c, &e)) break;
        const uint8_t *k = p + IMDBW_HELLO_LEN + IMDBW_CHALLENGE_LEN;
        uint8_t am[IMDBW_AUTHMSG_LEN], s1[IMDBW_KEY], s2[IMDBW_KEY];
        imdbw_auth_message(IMDBW_EP_TCP, p, p + IMDBW_HELLO_LEN, k, am);
        bool a = imdbw_scram_server(k + IMDBW_KEY, k + 2 * IMDBW_KEY, am, k, s1);
        bool b = imdbw_scram_server(k + IMDBW_KEY, k + 2 * IMDBW_KEY, am, k, s2);
        if (a != b || memcmp(s1, s2, IMDBW_KEY)) abort();
        break;
    }
    case 7: {
        size_t cl = frame_len(p, n, true);
        imdbw_msg c;
        if (!cl || p[4] != IMDBW_COLUMNS || !frame(p, cl, true, NULL, &c)) break;
        if (n - cl >= IMDBW_HEAD && p[cl + 4] == IMDBW_ROWS) frame(p + cl, n - cl, true, &c, NULL);
        imdbw_msg_free(&c);
        break;
    }
    }
    if (imdbw_live_blocks() != live) abort(); /* a block of the wire's left */
    return 0;
}

/* ---- seeds ---- */

static void put_seed(const char *dir, const char *name, uint8_t sel, const uint8_t *p, size_t n)
{
    char path[512];
    snprintf(path, sizeof path, "%s/%s", dir, name);
    FILE *f = fopen(path, "wb");
    if (!f) return;
    fputc(sel, f);
    fwrite(p, 1, n, f);
    fclose(f);
}

static void seed_frames(const char *dir, const char *name, uint8_t sel, const imdbw_msg *m, size_t nm)
{
    imdbw_buf b;
    imdbw_buf_init(&b);
    for (size_t i = 0; i < nm; i++) imdbw_msg_put(&b, &m[i], fixed_cols());
    if (!b.err) put_seed(dir, name, sel, b.p, b.len);
    imdbw_buf_free(&b);
}

static imdbw_span span_of(imdbw_buf *b, const imdbw_value *v, uint32_t n)
{
    imdbw_buf_init(b);
    for (uint32_t i = 0; i < n; i++) imdbw_value_put(b, &v[i]);
    return (imdbw_span){b->p, b->len, n};
}

int LLVMFuzzerInitialize(int *argc, char ***argv);
int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    const char *dir = getenv("IMDB_FUZZ_WIRE_SEEDS");
    if (!dir) return 0;
    imdbw_hello h = {.version = 1};
    memcpy(h.user, "alice", 5);
    memset(h.nonce, 1, sizeof h.nonce);
    uint8_t hb[IMDBW_HELLO_LEN], cb[IMDBW_CHALLENGE_LEN], vb[IMDBW_VERDICT_LEN];
    imdbw_challenge c = {.version = 1, .salt_len = 16, .iter = 4096};
    memset(c.salt, 3, 16);
    memset(c.nonce, 2, sizeof c.nonce);
    imdbw_verdict v = {.code = 0};
    memset(v.sig, 9, sizeof v.sig);
    if (imdbw_hello_put(&h, hb) || imdbw_challenge_put(&c, cb) || imdbw_verdict_put(&v, vb)) abort();
    put_seed(dir, "hello", 0, hb, sizeof hb);
    put_seed(dir, "challenge", 1, cb, sizeof cb);
    put_seed(dir, "verdict", 2, vb, sizeof vb);
    uint8_t ex[IMDBW_HELLO_LEN + IMDBW_CHALLENGE_LEN + 3 * IMDBW_KEY] = {0};
    memcpy(ex, hb, sizeof hb);
    memcpy(ex + sizeof hb, cb, sizeof cb);
    put_seed(dir, "exchange", 6, ex, sizeof ex);

    static const uint8_t uuid[16] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
    imdbw_value vals[] = {
        {.null = true},
        {.type = IMDBW_T_INT64, .i = -5},
        {.type = IMDBW_T_FLOAT64, .f = 0x3ff8000000000000ull},
        {.type = IMDBW_T_BOOL, .i = 1},
        {.type = IMDBW_T_TEXT, .s = (const uint8_t *)"h\xc3\xa9", .len = 3},
        {.type = IMDBW_T_DECIMAL, .scale = 2, .d = -12345},
        {.type = IMDBW_T_TIMESTAMP, .i = 1},
        {.type = IMDBW_T_TIMESTAMPTZ, .i = -1},
        {.type = IMDBW_T_DATE, .day = 20000},
        {.type = IMDBW_T_TIME, .i = 3600000000},
        {.type = IMDBW_T_UUID, .s = uuid, .len = 16},
        {.type = IMDBW_T_BYTEA, .s = (const uint8_t *)"\x00\xff", .len = 2},
        {.type = IMDBW_T_INTERVAL, .mon = 1, .day = -2, .i = 3},
        {.type = IMDBW_T_ENUM, .s = (const uint8_t *)"a", .len = 1},
    };
    enum { NV = sizeof vals / sizeof *vals };
    imdbw_buf vbuf, pbuf, ebuf, rbuf;
    imdbw_span all = span_of(&vbuf, vals, NV);
    put_seed(dir, "values", 5, all.p, all.len);

    imdbw_text texts[] = {{(const uint8_t *)"SELECT $1", 9}, {(const uint8_t *)"BEGIN", 5}};
    imdbw_span params[2] = {span_of(&pbuf, vals + 1, 1), {0}};
    imdbw_msg m[4] = {{.type = IMDBW_QUERY, .texts = texts, .params = params, .ntexts = 2}};
    seed_frames(dir, "query", 3, m, 1);
    m[0] = (imdbw_msg){.type = IMDBW_PREPARE, .texts = texts, .ntexts = 1};
    strcpy(m[0].name, "p1");
    seed_frames(dir, "prepare", 3, m, 1);
    vals[NV - 1] = (imdbw_value){.null = true, .type = IMDBW_T_ENUM}; /* a parameter: an ENUM only as a NULL */
    m[0] = (imdbw_msg){.type = IMDBW_EXECUTE, .vals = span_of(&ebuf, vals, NV), .nsets = 2, .nvals = NV / 2};
    strcpy(m[0].name, "p1");
    seed_frames(dir, "execute", 3, m, 1);
    m[0] = (imdbw_msg){.type = IMDBW_COPY_DATA, .data = (const uint8_t *)"1,a\n", .dlen = 4};
    seed_frames(dir, "copy_data", 3, m, 1);
    m[0] = (imdbw_msg){.type = IMDBW_COPY_FAIL, .texts = texts, .ntexts = 1};
    seed_frames(dir, "copy_fail", 3, m, 1);

    const imdbw_msg *cols = fixed_cols();
    __int128 big = 1;
    for (int i = 0; i < 37; i++) big *= 10;
    imdbw_value rv[] = {{.type = IMDBW_T_INT64, .i = 7}, {.type = IMDBW_T_DECIMAL, .scale = 6, .d = big},
                        {.type = IMDBW_T_TEXT, .s = (const uint8_t *)"abc", .len = 3},
                        {.type = IMDBW_T_ENUM, .s = (const uint8_t *)"x", .len = 1},
                        {.null = true, .type = IMDBW_T_INT64}, {.null = true, .type = IMDBW_T_DECIMAL},
                        {.null = true, .type = IMDBW_T_TEXT},
                        {.type = IMDBW_T_ENUM, .s = (const uint8_t *)"\xc3\xa9", .len = 2}};
    m[0] = *cols;
    m[1] = (imdbw_msg){.type = IMDBW_ROWS, .vals = span_of(&rbuf, rv, 8), .nsets = 2, .nvals = 4};
    seed_frames(dir, "columns", 4, m, 1);
    seed_frames(dir, "rows", 4, m + 1, 1);
    seed_frames(dir, "columns_rows", 7, m, 2);
    m[0] = (imdbw_msg){.type = IMDBW_DONE, .status = {(const uint8_t *)"SELECT 2", 8}, .has_read = true, .has_write = true,
                       .count = 2, .read_commit = 9, .lake_commit = 8, .write_commit = 10};
    memset(m[0].read_hash, 1, 32);
    memset(m[0].db_id, 4, 16);
    seed_frames(dir, "done", 4, m, 1);
    m[0] = (imdbw_msg){.type = IMDBW_ERROR, .code = 3, .index = 1, .texts = texts + 1, .ntexts = 1};
    seed_frames(dir, "error", 4, m, 1);
    m[0] = (imdbw_msg){.type = IMDBW_READY, .state = IMDBW_IN_TXN};
    seed_frames(dir, "ready", 4, m, 1);
    /* N1e stage two: KILL, and SESSIONS_LIST and KILL_DONE */
    m[0] = (imdbw_msg){.type = IMDBW_KILL, .kill = IMDBW_KILL_TERMINATE, .sid = 12};
    seed_frames(dir, "kill", 3, m, 1);
    imdbw_sess ss[2] = {{.id = 1, .role = 2, .endpoint = 1, .state = IMDBW_SS_RUNNING, .age_ms = 1500,
                         .name = {(const uint8_t *)"alice", 5}},
                        {.id = 7, .role = 3, .endpoint = 2, .state = IMDBW_SS_IN_TXN, .name = {(const uint8_t *)"", 0}}};
    m[0] = (imdbw_msg){.type = IMDBW_SESSIONS_LIST, .sess = ss, .nsess = 2};
    seed_frames(dir, "sessions_list", 4, m, 1);
    m[0] = (imdbw_msg){.type = IMDBW_KILL_DONE, .code = IMDBW_KILL_NONE, .sid = 7};
    seed_frames(dir, "kill_done", 4, m, 1);
    exit(0);
}
