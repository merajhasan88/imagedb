/* CREATE INDEX / DROP INDEX, stage (a): the definitions, logged (each op alone in its commit)
 * and in the manifest (version 3 only when some table has an index), replayed by replicas and
 * re-derived by VERIFY; the ordered structure comes in stage (b). */
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "../../src/db_internal.h"
#include "../../src/lake.h"
#include "../../src/log.h"
#include "../../src/oidx.h"
#include "../../src/sql.h"
#include "thelp.h"

static imdb_db *iopen(const char *dir, bool full_replay)
{
    imdb_open_opts o = {.sync = 0, .full_replay = full_replay};
    imdb_db *db = NULL;
    imdb_err_clear(E);
    return imdb_open(dir, &o, &db, E) ? NULL : db;
}

static int ex(imdb_session *s, const char *sql)
{
    imdb_result r;
    imdb_err_clear(E);
    int rc = imdb_exec_one(s, sql, strlen(sql), NULL, 0, &r, E);
    if (!rc) imdb_result_free(&r);
    return rc;
}

static int verify_db(imdb_db *db)
{
    imdb_verify_report vr;
    imdb_err_clear(E);
    return imdb_verify(db, &vr, E);
}

/* a table's index names in order, joined by spaces */
static const char *names(imdb_db *db, const char *table)
{
    static char b[1200];
    b[0] = 0;
    imdb_table *t = imdb_table_by_name(db, table);
    for (uint32_t k = 0; t && k < t->nidx; k++)
        snprintf(b + strlen(b), sizeof b - strlen(b), "%s%s", k ? " " : "", t->idx[k].d.name);
    return b;
}

/* a one-column, non-unique definition */
static imdb_index_def def1(const char *name, uint16_t col)
{
    imdb_index_def d;
    memset(&d, 0, sizeof d);
    snprintf(d.name, sizeof d.name, "%s", name);
    d.ncols = 1;
    d.cols[0] = col;
    return d;
}

/* the current manifest's version field */
static uint32_t manifest_version(const imdb_db *db)
{
    if (!db->lake_mbytes || db->lake_mlen < 12) return 0;
    const uint8_t *p = db->lake_mbytes + 8;
    return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}

static void t_index_ddl(void)
{
    const char *dir = test_tmpdir();
    OK(imdb_init(dir, false, NULL, E));
    imdb_db *db = iopen(dir, false);
    CHECK(db);
    if (!db) return;
    imdb_session s;
    imdb_session_init(&s, db);
    OK(ex(&s, "CREATE TABLE t (id INT64 PRIMARY KEY, v INT64, s TEXT)"));
    OK(ex(&s, "CREATE TABLE u (id INT64 PRIMARY KEY, w INT64)"));
    OK(ex(&s, "CREATE INDEX t_v ON t (v)"));
    OK(ex(&s, "CREATE INDEX a_s ON t (s)"));
    CHECK(strcmp(names(db, "t"), "a_s t_v") == 0); /* sorted by name */
    CHECK(ex(&s, "CREATE INDEX t_v ON u (w)") == IMDB_ERR_INVALID && strstr(g_e.msg, "exists already")); /* per database */
    CHECK(ex(&s, "CREATE INDEX x ON t (nope)") == IMDB_ERR_INVALID);
    CHECK(ex(&s, "CREATE INDEX x ON nope (v)") == IMDB_ERR_INVALID);
    CHECK(ex(&s, "DROP INDEX nope") == IMDB_ERR_INVALID);
    OK(ex(&s, "BEGIN"));
    CHECK(ex(&s, "CREATE INDEX x ON t (v)") == IMDB_ERR_STATE && strstr(g_e.msg, "commits on its own"));
    CHECK(ex(&s, "DROP INDEX t_v") == IMDB_ERR_STATE);
    OK(ex(&s, "ROLLBACK"));
    OK(ex(&s, "DROP INDEX t_v"));
    CHECK(strcmp(names(db, "t"), "a_s") == 0);
    for (unsigned k = 1; k < IMDB_MAX_INDEXES; k++) { /* a_s and 15 more: the limit */
        char q[96];
        snprintf(q, sizeof q, "CREATE INDEX i%02u ON t (v)", k);
        OK(ex(&s, q));
    }
    CHECK(ex(&s, "CREATE INDEX one_too_many ON t (v)") == IMDB_ERR_LIMIT);
    imdb_session_close(&s);
    OK(verify_db(db));
    imdb_close(db);
}

/* undone with its transaction (through the C API: SQL commits them at once), and alone in it */
static void t_index_rollback(void)
{
    const char *dir = test_tmpdir();
    OK(imdb_init(dir, false, NULL, E));
    imdb_db *db = iopen(dir, false);
    CHECK(db);
    if (!db) return;
    imdb_session s;
    imdb_session_init(&s, db);
    OK(ex(&s, "CREATE TABLE t (id INT64 PRIMARY KEY, v INT64, s TEXT)"));
    OK(ex(&s, "CREATE INDEX t_v ON t (v)"));
    imdb_session_close(&s);
    imdb_table *t = imdb_table_by_name(db, "t");
    CHECK(t);
    if (!t) return;
    OK(imdb_begin(db, E));
    imdb_index_def ds = def1("t_s", 2), did = def1("t_id", 0);
    OK(imdb_create_index(db, t, &ds, E));
    CHECK(strcmp(names(db, "t"), "t_s t_v") == 0);
    imdb_err_clear(E);
    CHECK(imdb_create_index(db, t, &did, E) == IMDB_ERR_STATE); /* a second op in its commit */
    imdb_rollback(db);
    CHECK(strcmp(names(db, "t"), "t_v") == 0);
    OK(imdb_begin(db, E));
    OK(imdb_drop_index(db, "t_v", E));
    CHECK(t->nidx == 0);
    imdb_rollback(db);
    CHECK(strcmp(names(db, "t"), "t_v") == 0 && t->idx[0].d.ncols == 1 && t->idx[0].d.cols[0] == 1);
    OK(verify_db(db));
    imdb_close(db);
}

/* a full replay and a snapshot open both rebuild the definitions, VERIFY checking them; a
 * database without an index writes version 2 manifests, and goes back to them after its last DROP */
static void t_index_persist(void)
{
    const char *dir = test_tmpdir();
    OK(imdb_init(dir, false, NULL, E));
    imdb_db *db = iopen(dir, false);
    CHECK(db);
    if (!db) return;
    imdb_session s;
    imdb_session_init(&s, db);
    OK(ex(&s, "CREATE TABLE t (id INT64 PRIMARY KEY, v INT64, s TEXT)"));
    OK(ex(&s, "INSERT INTO t VALUES (1, 10, 'a'), (2, 20, 'b')"));
    OK(ex(&s, "CHECKPOINT"));
    CHECK(manifest_version(db) == 2);
    OK(ex(&s, "CREATE INDEX t_v ON t (v)"));
    OK(ex(&s, "CHECKPOINT"));
    CHECK(manifest_version(db) == 3);
    OK(ex(&s, "CREATE INDEX t_s ON t (s)")); /* in the log tail only */
    imdb_session_close(&s);
    imdb_close(db);
    for (int full = 0; full < 2; full++) {
        db = iopen(dir, full);
        CHECK(db);
        if (!db) return;
        CHECK(strcmp(names(db, "t"), "t_s t_v") == 0);
        CHECK(full || db->snapshot_seq > 0); /* the second open is a full replay */
        OK(verify_db(db));
        imdb_close(db);
    }
    db = iopen(dir, false);
    CHECK(db);
    if (!db) return;
    imdb_session_init(&s, db);
    OK(ex(&s, "DROP INDEX t_v"));
    OK(ex(&s, "DROP INDEX t_s"));
    OK(ex(&s, "CHECKPOINT"));
    CHECK(manifest_version(db) == 2);
    imdb_session_close(&s);
    OK(verify_db(db));
    imdb_close(db);
}

/* a replica applies the same definitions */
static void t_index_replica(void)
{
    const char *tmp = test_tmpdir();
    char p[600], rr[600], st[700];
    snprintf(p, sizeof p, "%s/p", tmp);
    snprintf(rr, sizeof rr, "%s/r", tmp);
    snprintf(st, sizeof st, "%s/stream", tmp);
    OK(imdb_init(p, false, NULL, E));
    OK(imdb_init(rr, true, p, E));
    imdb_db *db = iopen(p, false);
    CHECK(db);
    if (!db) return;
    imdb_session s;
    imdb_session_init(&s, db);
    OK(ex(&s, "CREATE TABLE t (id INT64 PRIMARY KEY, v INT64, s TEXT)"));
    OK(ex(&s, "CREATE INDEX t_v ON t (v)"));
    OK(ex(&s, "CHECKPOINT"));
    OK(ex(&s, "CREATE INDEX t_s ON t (s)"));
    OK(ex(&s, "DROP INDEX t_v"));
    /* a unique index the replica applies: its chains built on the replayed op, then the rows */
    OK(ex(&s, "CREATE UNIQUE INDEX t_u ON t (v, s)"));
    OK(ex(&s, "INSERT INTO t VALUES (1, 5, 'a'), (2, 5, 'b')"));
    OK(ex(&s, "UPDATE t SET s = 'c' WHERE id = 1"));
    imdb_result r;
    imdb_err_clear(E);
    CHECK(imdb_exec_one(&s, "INSERT INTO t VALUES (3, 5, 'b')", 32, NULL, 0, &r, E) == IMDB_ERR_CONSTRAINT);
    imdb_session_close(&s);
    imdb_close(db);
    OK(ship_to_file(p, 0, st, E));
    imdb_db *rep = iopen(rr, false);
    CHECK(rep);
    if (!rep) return;
    uint64_t applied = 0;
    int fd = open(st, O_RDONLY | O_CLOEXEC);
    OK(imdb_apply_stream(rep, fd, &applied, E));
    close(fd);
    CHECK(strcmp(names(rep, "t"), "t_s t_u") == 0);
    imdb_table *rt = imdb_table_by_name(rep, "t");
    /* t_u's chains, built when the replica applied its op; the rows and the UPDATE then passed the
     * replay's duplicate check (imdb_index_unique_replay), or the apply above would have failed */
    CHECK(rt && rt->nidx == 2 && rt->idx[1].ux);
    imdb_session rs;
    imdb_session_init(&rs, rep);
    imdb_err_clear(E);
    OK(imdb_exec_one(&rs, "SELECT COUNT(*) FROM t WHERE v = 5", 34, NULL, 0, &r, E));
    CHECK(r.nrows == 1 && r.cells[0].v.i == 2);
    imdb_result_free(&r);
    imdb_session_close(&rs);
    OK(verify_db(rep));
    imdb_close(rep);
}

/* the ops' codec: a round trip; alone in their commit; names valid and folded */
static void t_index_codec(void)
{
    char nm[IMDB_MAX_IDENT + 1] = "t_v";
    imdb_op op = {.code = IMDB_OP_CREATE_INDEX, .table = 3, .iflags = IMDB_INDEX_UNIQUE, .incols = 2, .icols = {2, 0}, .iname = nm};
    imdb_commit_rec c = {.seq = 7, .alg = IMDB_DIGEST_ALG_LTHASH16, .ops = &op, .nops = 1};
    imdb_buf b;
    imdb_buf_init(&b);
    imdb_commit_encode_header(&c, &b);
    OK(imdb_buf_check(&b, E));
    imdb_commit_rec d;
    memset(&d, 0, sizeof d);
    OK(imdb_commit_decode_header(b.p, b.len, &d, E));
    CHECK(d.nops == 1 && d.ops[0].code == IMDB_OP_CREATE_INDEX && d.ops[0].table == 3 && d.ops[0].iflags == IMDB_INDEX_UNIQUE &&
          d.ops[0].incols == 2 && d.ops[0].icols[0] == 2 && d.ops[0].icols[1] == 0 && strcmp(d.ops[0].iname, "t_v") == 0);
    imdb_commit_free(&d);
    /* the definition's own rules, one broken at a time in the encoded bytes (the encoder refuses
     * them): the op at 54, u32 table, then flags at 59, ncols at 60, the columns from 61 */
    {
        static const struct { size_t at; uint8_t v; } bad[] = {{59, 2}, {59, 0x81}, {60, 0}, {60, 5}, {61, 0}};
        for (size_t i = 0; i < sizeof bad / sizeof *bad; i++) {
            imdb_buf h2;
            imdb_buf_init(&h2);
            imdb_buf_put(&h2, b.p, b.len);
            OK(imdb_buf_check(&h2, E));
            CHECK(h2.p[54] == IMDB_OP_CREATE_INDEX && h2.p[61] == 2 && h2.p[63] == 0);
            h2.p[bad[i].at] = bad[i].v; /* 61 = 0: the columns 0 and 0, not distinct */
            memset(&d, 0, sizeof d);
            imdb_err_clear(E);
            CHECK(imdb_commit_decode_header(h2.p, h2.len, &d, E) == IMDB_ERR_CORRUPT && strstr(g_e.msg, "index definition"));
            imdb_commit_free(&d);
            imdb_buf_free(&h2);
        }
        /* and the encoder: unknown flags, no column, too many, the same column twice */
        imdb_op bo = op;
        uint8_t ef[] = {2, 0, 0, 0}, en[] = {2, 0, 5, 2};
        for (int i = 0; i < 4; i++) {
            bo.iflags = ef[i];
            bo.incols = en[i];
            bo.icols[0] = 2;
            bo.icols[1] = i == 3 ? 2 : 0;
            imdb_commit_rec cb = {.seq = 7, .alg = IMDB_DIGEST_ALG_LTHASH16, .ops = &bo, .nops = 1};
            imdb_buf eb;
            imdb_buf_init(&eb);
            imdb_commit_encode_header(&cb, &eb);
            CHECK(eb.err != 0);
            imdb_buf_free(&eb);
        }
    }
    /* a second op after it, built by hand (the encoder refuses to): the decoder refuses it too.
     * The header: u8 version, u8 digest alg, u64 seq, u64 time, prev[32], u32 nops at 50 */
    {
        imdb_buf h2;
        imdb_buf_init(&h2);
        imdb_buf_put(&h2, b.p, 50);
        imdb_buf_put_u32(&h2, 2);
        imdb_buf_put(&h2, b.p + 54, b.len - 54 - 32);
        imdb_buf_put_u8(&h2, IMDB_OP_CHECKPOINT);
        uint8_t zero[32] = {0};
        imdb_buf_put(&h2, zero, 32);
        imdb_buf_put(&h2, b.p + b.len - 32, 32);
        memset(&d, 0, sizeof d);
        imdb_err_clear(E);
        CHECK(imdb_commit_decode_header(h2.p, h2.len, &d, E) == IMDB_ERR_CORRUPT && strstr(g_e.msg, "only op"));
        imdb_commit_free(&d);
        imdb_buf_free(&h2);
    }
    /* the same bytes with the name in capitals: the decoder refuses it (folded names only) */
    for (size_t i = 0; i + 3 <= b.len; i++)
        if (memcmp(b.p + i, "t_v", 3) == 0) memcpy(b.p + i, "T_V", 3);
    memset(&d, 0, sizeof d);
    imdb_err_clear(E);
    CHECK(imdb_commit_decode_header(b.p, b.len, &d, E) == IMDB_ERR_CORRUPT && strstr(g_e.msg, "index name"));
    imdb_commit_free(&d);
    imdb_buf_free(&b);
    /* with a second op the encoder refuses it */
    imdb_op two[2] = {{.code = IMDB_OP_CHECKPOINT}, op};
    imdb_commit_rec c2 = {.seq = 7, .alg = IMDB_DIGEST_ALG_LTHASH16, .ops = two, .nops = 2};
    imdb_buf_init(&b);
    imdb_commit_encode_header(&c2, &b);
    CHECK(b.err != 0);
    imdb_buf_free(&b);
}

/* the current manifest's bytes, copied */
static uint8_t *manifest_copy(const imdb_db *db, size_t *n)
{
    *n = db->lake_mlen;
    uint8_t *b = malloc(*n ? *n : 1);
    if (b && *n) memcpy(b, db->lake_mbytes, *n);
    return b;
}

static int parse_bytes(const uint8_t *b, size_t n)
{
    imdb_manifest m;
    imdb_err_clear(E);
    int rc = imdb_manifest_parse(b, n, &m, E);
    if (!rc) imdb_manifest_free(&m);
    return rc;
}

/* where the 3-byte name s starts in an index entry (u8 length 3, then the name) */
static size_t name_at(const uint8_t *b, size_t n, const char *s)
{
    for (size_t i = 1; i + 3 <= n; i++)
        if (b[i - 1] == 3 && memcmp(b + i, s, 3) == 0) return i;
    return 0;
}

/* the engine's version-3 rules on real manifest bytes, one rule broken at a time */
static void t_index_manifest_strict(void)
{
    const char *dir = test_tmpdir();
    OK(imdb_init(dir, false, NULL, E));
    imdb_db *db = iopen(dir, false);
    CHECK(db);
    if (!db) return;
    imdb_session s;
    imdb_session_init(&s, db);
    OK(ex(&s, "CREATE TABLE t (id INT64 PRIMARY KEY, v INT64)"));
    OK(ex(&s, "CREATE TABLE u (id INT64 PRIMARY KEY, w INT64)"));
    OK(ex(&s, "CREATE INDEX t_v ON t (v)"));
    OK(ex(&s, "CREATE INDEX t_x ON t (id)"));
    OK(ex(&s, "CREATE INDEX u_w ON u (w)"));
    OK(ex(&s, "INSERT INTO t VALUES (1, 10)"));
    OK(ex(&s, "CHECKPOINT"));
    CHECK(manifest_version(db) == 3);
    size_t n;
    uint8_t *b = manifest_copy(db, &n);
    CHECK(b && parse_bytes(b, n) == IMDB_OK);
    if (!b) return;
    uint8_t *w = malloc(n);
    CHECK(w);
    if (!w) return;
    /* an entry: u8 length, the name, u8 flags, u8 ncols, u16 per column; u_w is the last */
    memcpy(w, b, n); /* the last index (u_w) on a column u lacks */
    w[n - 2] = 2;
    w[n - 1] = 0;
    CHECK(parse_bytes(w, n) == IMDB_ERR_CORRUPT);
    memcpy(w, b, n); /* an unknown flag */
    CHECK(w[n - 4] == 0 && w[n - 3] == 1);
    w[n - 4] = 2;
    CHECK(parse_bytes(w, n) == IMDB_ERR_CORRUPT);
    memcpy(w, b, n); /* no column */
    w[n - 3] = 0;
    CHECK(parse_bytes(w, n) == IMDB_ERR_CORRUPT);
    memcpy(w, b, n); /* u_w renamed t_v: one name in two tables */
    size_t at = name_at(w, n, "u_w");
    CHECK(at);
    memcpy(w + at, "t_v", 3);
    CHECK(parse_bytes(w, n) == IMDB_ERR_CORRUPT);
    memcpy(w, b, n); /* t's two names swapped: not sorted */
    size_t a1 = name_at(w, n, "t_v"), a2 = name_at(w, n, "t_x");
    CHECK(a1 && a2 && a1 < a2);
    memcpy(w + a1, "t_x", 3);
    memcpy(w + a2, "t_v", 3);
    CHECK(parse_bytes(w, n) == IMDB_ERR_CORRUPT);
    free(w);
    free(b);
    /* version 3 with no index anywhere: only version 2 may encode that */
    OK(ex(&s, "DROP INDEX t_v"));
    OK(ex(&s, "DROP INDEX t_x"));
    OK(ex(&s, "CHECKPOINT"));
    CHECK(manifest_version(db) == 3); /* u_w remains, last: u32 1, u8 3, "u_w", u8 0, u8 1, u16 */
    b = manifest_copy(db, &n);
    CHECK(b && n > 12 && parse_bytes(b, n) == IMDB_OK);
    if (!b) return;
    uint8_t *p = b + n - 12;
    CHECK(p[0] == 1 && p[1] == 0 && p[2] == 0 && p[3] == 0 && p[4] == 3);
    memset(p, 0, 4); /* nidx = 0, and the entry gone */
    CHECK(parse_bytes(b, n - 8) == IMDB_ERR_CORRUPT);
    free(b);
    imdb_session_close(&s);
    imdb_close(db);
}

/* ---- stage (b): the ordered structure and the ordered path ------------------------------------- */

static uint64_t g_seen[4096];
static size_t g_nseen;

static size_t g_keybad;

typedef struct mctx {
    const uint64_t (*model)[IMDB_MAX_INDEX_COLS]; /* entry vid's key words, or NULL */
    uint8_t nk;
} mctx;

/* ctx: an mctx, or NULL */
static int collect(void *ctx, const uint64_t *key, uint64_t vid)
{
    const mctx *m = ctx;
    if (m && m->model && memcmp(m->model[vid], key, m->nk * sizeof *key) != 0) g_keybad++;
    if (g_nseen < sizeof g_seen / sizeof *g_seen) g_seen[g_nseen++] = vid;
    return IMDB_OK;
}

static int cmp_u64(const void *a, const void *b)
{
    uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;
    return x < y ? -1 : x > y;
}

static int kcmp_model(const uint64_t *a, const uint64_t *b, uint8_t nk)
{
    for (uint8_t c = 0; c < nk; c++)
        if (a[c] != b[c]) return a[c] < b[c] ? -1 : 1;
    return 0;
}

/* The Bentley-Saxe runs against a plain list, keys of nk words: inserts, a rebuild in the middle,
 * random ranges of the planner's shape (equality on a prefix, a range on the next word, any value
 * after), each also counted by that shape's own definition */
static void oidx_model(uint8_t nk)
{
    enum { N = 3000 };
    static uint64_t model[N][IMDB_MAX_INDEX_COLS];
    const uint64_t span = nk == 1 ? 500 : 12; /* duplicates on purpose */
    size_t w = (size_t)nk + 1;
    imdb_oidx x;
    imdb_oidx_init(&x, nk);
    mctx m = {(const uint64_t(*)[IMDB_MAX_INDEX_COLS])model, nk};
    for (uint64_t i = 0; i < N && !g_test_failed; i++) {
        for (uint8_t c = 0; c < nk; c++) model[i][c] = test_rand() % span;
        OK(imdb_oidx_insert(&x, model[i], i, E));
        if (i == N / 2) { /* the open's path: one build from everything so far */
            uint64_t *all = malloc((i + 1) * w * sizeof *all);
            CHECK(all);
            if (!all) return;
            for (uint64_t j = 0; j <= i; j++) {
                memcpy(all + j * w, model[j], nk * sizeof *all);
                all[j * w + nk] = j;
            }
            OK(imdb_oidx_build(&x, all, i + 1, E));
        }
        if (i % 97 == 0 || i == N - 1)
            for (int q = 0; q < 20; q++) {
                uint64_t lo[IMDB_MAX_INDEX_COLS], hi[IMDB_MAX_INDEX_COLS];
                uint8_t neq = (uint8_t)(test_rand() % nk);
                for (uint8_t c = 0; c < neq; c++) lo[c] = hi[c] = test_rand() % (span + 1);
                lo[neq] = test_rand() % (span + 20);
                hi[neq] = lo[neq] + test_rand() % (nk == 1 ? 60 : 5);
                for (uint8_t c = neq + 1; c < nk; c++) lo[c] = 0, hi[c] = UINT64_MAX;
                g_nseen = g_keybad = 0;
                OK(imdb_oidx_range(&x, lo, hi, collect, &m));
                size_t want = 0, shape = 0;
                for (uint64_t j = 0; j <= i; j++) {
                    want += kcmp_model(model[j], lo, nk) >= 0 && kcmp_model(model[j], hi, nk) <= 0;
                    bool in = model[j][neq] >= lo[neq] && model[j][neq] <= hi[neq];
                    for (uint8_t c = 0; c < neq; c++) in = in && model[j][c] == lo[c];
                    shape += in;
                }
                CHECK(want == shape); /* the planner's bounds select exactly the prefix and the range */
                CHECK(g_nseen == want && g_keybad == 0); /* each entry with its own key */
                CHECK(imdb_oidx_count(&x, lo, hi) == want); /* the planner's estimate is the exact count */
                qsort(g_seen, g_nseen, sizeof *g_seen, cmp_u64);
                for (size_t j = 0; j < g_nseen; j++)
                    CHECK(g_seen[j] <= i && kcmp_model(model[g_seen[j]], lo, nk) >= 0 &&
                          kcmp_model(model[g_seen[j]], hi, nk) <= 0 && (!j || g_seen[j] > g_seen[j - 1]));
            }
    }
    CHECK(imdb_oidx_bytes(&x) >= N * imdb_oidx_entry_bytes(nk));
    if (nk == 1) {
        /* the ends of the key space: INT64_MAX maps to UINT64_MAX; a full buffer of them, so some
         * are carried into a sorted run */
        uint64_t mx = UINT64_MAX, zero = 0, k250 = 250, mx1 = UINT64_MAX - 1, k10 = 10, k5 = 5;
        for (uint64_t j = 0; j < IMDB_OIDX_BASE; j++) OK(imdb_oidx_insert(&x, &mx, N + j, E));
        size_t ge250 = 0;
        for (uint64_t j = 0; j < N; j++) ge250 += model[j][0] >= 250;
        CHECK(imdb_oidx_count(&x, &zero, &mx) == N + IMDB_OIDX_BASE);
        CHECK(imdb_oidx_count(&x, &k250, &mx) == ge250 + IMDB_OIDX_BASE);
        CHECK(imdb_oidx_count(&x, &mx, &mx) == IMDB_OIDX_BASE);
        CHECK(imdb_oidx_count(&x, &zero, &mx1) == N);
        CHECK(imdb_oidx_count(&x, &k10, &k5) == 0);
    }
    imdb_oidx_free(&x);
}

static void t_index_oidx(void)
{
    for (uint8_t nk = 1; nk <= 3 && !g_test_failed; nk++) oidx_model(nk);
}

/* random data and predicates on every indexed type, with cross_check on: every SELECT runs the
 * ordered path and the scan and must get identical results, through updates, deletes, an open
 * transaction's own rows, AS OF, a purge, an ERASE, a replica and a reopen */
static void t_index_ordered_crosscheck(void)
{
    const char *tmp = test_tmpdir();
    char p[600], rr[600], st[700];
    snprintf(p, sizeof p, "%s/p", tmp);
    snprintf(rr, sizeof rr, "%s/r", tmp);
    snprintf(st, sizeof st, "%s/stream", tmp);
    OK(imdb_init(p, false, NULL, E));
    OK(imdb_init(rr, true, p, E));
    imdb_db *db = iopen(p, false);
    CHECK(db);
    if (!db) return;
    imdb_session s;
    imdb_session_init(&s, db);
    s.cross_check = true;
    OK(ex(&s, "CREATE TABLE t (id INT64 PRIMARY KEY, u INT64 SUBJECT, v INT64, d DECIMAL(10,2), f FLOAT64, "
              "ts TIMESTAMP, s TEXT, n INT64 NULL)"));
    OK(ex(&s, "CREATE INDEX t_v ON t (v)"));
    OK(ex(&s, "CREATE INDEX t_d ON t (d)"));
    OK(ex(&s, "CREATE INDEX t_f ON t (f)"));
    OK(ex(&s, "CREATE INDEX t_ts ON t (ts)"));
    OK(ex(&s, "CREATE INDEX t_s ON t (s)"));
    OK(ex(&s, "CREATE INDEX t_n ON t (n)"));
    static const char *const words[] = {"apple", "apple pie", "apricot", "banana", "band", "b", "", "cherry", "z"};
    char q[512];
    for (int id = 1; id <= 300; id++) {
        int v = (int)(test_rand() % 40) - 20;
        snprintf(q, sizeof q, "INSERT INTO t VALUES (%d, %d, %d, %d.%02d, %d.5e%d, '2026-10-%02d 10:00:00', '%s', %s)", id, id % 7, v,
                 v, (int)(test_rand() % 100), v, (int)(test_rand() % 5) - 2, 1 + (int)(test_rand() % 28),
                 words[test_rand() % 9], test_rand() % 4 ? "5" : "NULL");
        OK(ex(&s, q));
    }
    static const char *const preds[] = {
        "v = 3", "v BETWEEN -5 AND 5", "v < -10", "v >= 15", "d > 3.50", "d BETWEEN -2.25 AND 2.25", "f < 0",
        "f BETWEEN -1e2 AND 1e2", "ts >= '2026-10-15'", "ts BETWEEN '2026-10-03' AND '2026-10-09 23:59:59'",
        "s = 'apple'", "s >= 'apple' AND s < 'apricot'", "s BETWEEN 'b' AND 'band'", "s < 'b'", "s > 'cherry'",
        "n = 5", "v BETWEEN -5 AND 5 AND s = 'banana'", "v > 0 AND u = 3", "v != 3", "n IS NULL"};
    const size_t np = sizeof preds / sizeof *preds;
    int ordered = 0, asked = 0, only = 0;
    for (int round = 0; round < 6 && !g_test_failed; round++) {
        for (size_t i = 0; i < np; i++) {
            snprintf(q, sizeof q, "SELECT COUNT(*), SUM(v) FROM t WHERE %s", preds[i]);
            imdb_result r;
            imdb_err_clear(E);
            OK(imdb_exec_one(&s, q, strlen(q), NULL, 0, &r, E));
            ordered += strstr(r.path, "index(ordered") != NULL; /* not vacuous: the path ran (either kind) */
            asked++;
            imdb_result_free(&r);
            snprintf(q, sizeof q, "SELECT id, s FROM t WHERE %s", preds[i]);
            OK(ex(&s, q));
            /* aggregates of the predicate's own column: index-only where it is not TEXT, and
             * grouped by it; SUM where the type has one */
            char col[8] = "";
            for (size_t j = 0; j < sizeof col - 1 && preds[i][j] != ' '; j++) col[j] = preds[i][j];
            bool sums = strcmp(col, "v") == 0 || strcmp(col, "d") == 0 || strcmp(col, "f") == 0 || strcmp(col, "n") == 0;
            snprintf(q, sizeof q, "SELECT COUNT(*), COUNT(%s), MIN(%s), MAX(%s)%s%s%s FROM t WHERE %s", col, col, col,
                     sums ? ", SUM(" : "", sums ? col : "", sums ? ")" : "", preds[i]);
            imdb_err_clear(E);
            OK(imdb_exec_one(&s, q, strlen(q), NULL, 0, &r, E));
            only += strstr(r.path, "index(ordered, only)") != NULL;
            imdb_result_free(&r);
            snprintf(q, sizeof q, "SELECT %s, COUNT(*) FROM t WHERE %s GROUP BY %s", col, preds[i], col);
            imdb_err_clear(E);
            OK(imdb_exec_one(&s, q, strlen(q), NULL, 0, &r, E));
            only += strstr(r.path, "index(ordered, only)") != NULL;
            imdb_result_free(&r);
        }
        uint64_t before = db->seq;
        snprintf(q, sizeof q, "UPDATE t SET v = %d, s = 'band' WHERE id BETWEEN %d AND %d", round, round * 30 + 1, round * 30 + 20);
        OK(ex(&s, q));
        snprintf(q, sizeof q, "DELETE FROM t WHERE id BETWEEN %d AND %d", round * 30 + 21, round * 30 + 25);
        OK(ex(&s, q));
        OK(ex(&s, "BEGIN")); /* the transaction's own rows: above idx_upto, scanned */
        snprintf(q, sizeof q, "INSERT INTO t VALUES (%d, 1, 3, 3.00, 3.0, '2026-10-05', 'apple', 5)", 1000 + round);
        OK(ex(&s, q));
        {
            imdb_result r;
            imdb_err_clear(E);
            OK(imdb_exec_one(&s, "SELECT COUNT(*) FROM t WHERE v = 3", 34, NULL, 0, &r, E));
            CHECK(strstr(r.path, "index(ordered, only)") && r.snap_own); /* index-only, its own rows fetched */
            imdb_result_free(&r);
        }
        OK(ex(&s, "SELECT id FROM t WHERE s = 'apple'"));
        OK(ex(&s, round % 2 ? "COMMIT" : "ROLLBACK"));
        snprintf(q, sizeof q, "SELECT COUNT(*), SUM(v) FROM t AS OF %llu WHERE v BETWEEN -5 AND 5", (unsigned long long)before);
        OK(ex(&s, q));
        if (round == 2) {
            OK(ex(&s, "CHECKPOINT")); /* the rows move to segments: the index reads them from there */
            snprintf(q, sizeof q, "COMPACT t PURGE BEFORE %llu", (unsigned long long)before);
            OK(ex(&s, q));
        }
        if (round == 4) OK(ex(&s, "ERASE SUBJECT 3"));
    }
    CHECK(s.cross_checks_run > 0 && ordered * 10 >= asked * 6); /* 16 of the 20 predicates can use one */
    CHECK(only >= 6 * 2 * 11); /* the 11 single-column predicates on v, d, f, ts and n, twice a round */
    imdb_table *tt = imdb_table_by_name(db, "t");
    CHECK(tt && tt->idx_upto == tt->nver); /* outside a transaction every committed version is indexed */
    imdb_session_close(&s);
    OK(verify_db(db));
    imdb_close(db);
    /* the replica and a reopen build the same structures from the same log */
    OK(ship_to_file(p, 0, st, E));
    imdb_db *rep = iopen(rr, false);
    CHECK(rep);
    if (!rep) return;
    uint64_t applied = 0;
    int fd = open(st, O_RDONLY | O_CLOEXEC);
    OK(imdb_apply_stream(rep, fd, &applied, E));
    close(fd);
    db = iopen(p, false);
    CHECK(db);
    if (!db) return;
    imdb_session a, b;
    imdb_session_init(&a, db);
    imdb_session_init(&b, rep);
    a.cross_check = b.cross_check = true;
    for (size_t i = 0; i < np; i++) {
        snprintf(q, sizeof q, "SELECT COUNT(*), SUM(v) FROM t WHERE %s", preds[i]);
        imdb_result r1, r2;
        imdb_err_clear(E);
        OK(imdb_exec_one(&a, q, strlen(q), NULL, 0, &r1, E));
        OK(imdb_exec_one(&b, q, strlen(q), NULL, 0, &r2, E));
        CHECK(r1.nrows == 1 && r2.nrows == 1 && memcmp(r1.cells, r2.cells, 2 * sizeof *r1.cells) == 0);
        imdb_result_free(&r1);
        imdb_result_free(&r2);
    }
    imdb_session_close(&a);
    imdb_session_close(&b);
    imdb_close(rep);
    imdb_close(db);
}

/* an ERASE takes the erased versions out of every index, whatever the key type (an erased
 * version's key is the erased value), and the path still agrees with the scan */
static void t_index_erase(void)
{
    const char *dir = test_tmpdir();
    OK(imdb_init(dir, false, NULL, E));
    imdb_db *db = iopen(dir, false);
    CHECK(db);
    if (!db) return;
    imdb_session s;
    imdb_session_init(&s, db);
    s.cross_check = true;
    OK(ex(&s, "CREATE TABLE t (id INT64 PRIMARY KEY, u INT64 SUBJECT, v INT64, s TEXT)"));
    OK(ex(&s, "CREATE INDEX t_v ON t (v)"));
    OK(ex(&s, "CREATE INDEX t_s ON t (s)"));
    OK(ex(&s, "CREATE UNIQUE INDEX t_us ON t (s, v)"));
    OK(ex(&s, "INSERT INTO t VALUES (1, 42, 777, 'secret-42'), (2, 7, 5, 'plain'), (3, 42, 778, 'secret-42b')"));
    OK(ex(&s, "UPDATE t SET v = 779 WHERE id = 1"));
    OK(ex(&s, "ERASE SUBJECT 42"));
    imdb_table *t = imdb_table_by_name(db, "t");
    CHECK(t && t->nidx == 3);
    if (!t) return;
    for (uint32_t k = 0; k < t->nidx; k++) {
        g_nseen = 0;
        uint64_t lo[IMDB_MAX_INDEX_COLS] = {0}, hi[IMDB_MAX_INDEX_COLS] = {UINT64_MAX, UINT64_MAX, UINT64_MAX, UINT64_MAX};
        OK(imdb_oidx_range(t->idx[k].ox, lo, hi, collect, NULL));
        for (size_t j = 0; j < g_nseen; j++) CHECK(!(imdb_vh(t, g_seen[j])->flags & IMDB_V_STUB));
        CHECK(g_nseen == 1); /* only row 2's version is left */
    }
    OK(ex(&s, "SELECT COUNT(*) FROM t WHERE v BETWEEN 700 AND 800"));
    OK(ex(&s, "SELECT COUNT(*) FROM t WHERE s >= 'secret'"));
    /* the unique chains were rebuilt from the live rows: an erased row's key is free again, a
     * live row's is not */
    OK(ex(&s, "INSERT INTO t VALUES (4, 9, 778, 'secret-42b')"));
    CHECK(ex(&s, "INSERT INTO t VALUES (5, 9, 5, 'plain')") == IMDB_ERR_CONSTRAINT);
    imdb_session_close(&s);
    OK(verify_db(db));
    imdb_close(db);
}

/* an index's growth counts against the memory budget: a commit whose new entries would take the
 * database past it is refused before anything is logged (eight indexes, so they dominate), the
 * accounting never above the budget after a commit, the database consistent */
/* an index's growth counts against the memory budget, apart from the store's: the budget is set
 * right after the version store doubled (it has room for thousands of rows, so its own admission
 * cannot fire), and eight indexes take the inserts; a commit whose new entries would pass the
 * budget is refused before anything is logged, and the accounting is never above it after one */
static void t_index_budget(void)
{
    const char *dir = test_tmpdir();
    OK(imdb_init(dir, false, NULL, E));
    imdb_db *db = iopen(dir, false);
    CHECK(db);
    if (!db) return;
    imdb_session s;
    imdb_session_init(&s, db);
    s.cross_check = true;
    OK(ex(&s, "CREATE TABLE t (id INT64 PRIMARY KEY, a INT64, b INT64, c INT64, d INT64, f INT64, g INT64, h INT64, i INT64)"));
    static const char *const cols[] = {"a", "b", "c", "d", "f", "g", "h", "i"};
    for (int k = 0; k < 8; k++) {
        char q[96];
        snprintf(q, sizeof q, "CREATE INDEX t_%s ON t (%s)", cols[k], cols[k]);
        OK(ex(&s, q));
    }
    imdb_table *t = imdb_table_by_name(db, "t");
    CHECK(t);
    if (!t) return;
    int64_t id = 0;
    bool armed = false;
    int refused = 0;
    imdb_mem_report m;
    for (int batch = 0; batch < 400 && !refused && !g_test_failed; batch++) {
        imdb_buf ins;
        imdb_buf_init(&ins);
        imdb_buf_put_str(&ins, "INSERT INTO t VALUES ");
        for (int r = 0; r < 50; r++) {
            id++;
            char v[200];
            snprintf(v, sizeof v, "%s(%lld, %lld, %lld, %lld, %lld, %lld, %lld, %lld, %lld)", r ? ", " : "", (long long)id,
                     (long long)(id % 97), (long long)(id % 89), (long long)(id % 83), (long long)(id % 79),
                     (long long)(id % 73), (long long)(id % 71), (long long)(id % 67), (long long)(id % 61));
            imdb_buf_put_str(&ins, v);
        }
        OK(imdb_buf_check(&ins, E));
        uint64_t seq = db->seq;
        imdb_result r;
        imdb_err_clear(E);
        int rc = imdb_exec_one(&s, (const char *)ins.p, ins.len, NULL, 0, &r, E);
        imdb_buf_free(&ins);
        if (rc) {
            CHECK(armed && rc == IMDB_ERR_LIMIT && db->seq == seq); /* the index's admission, nothing logged */
            refused = 1;
            break;
        }
        imdb_result_free(&r);
        imdb_mem(db, &m);
        CHECK(!armed || m.total <= db->mem_limit);
        /* arm once the store has just doubled and its arena has room: only the indexes grow now */
        if (!armed && t->nver >= 2048 && t->capver >= 2 * t->nver - 64 && t->arena.cap - t->arena.len > 200000) {
            db->mem_limit = m.total + (24u << 10);
            armed = true;
        }
    }
    CHECK(armed && refused);
    CHECK(t->idx_upto == t->nver); /* outside a transaction every committed version is indexed */
    db->mem_limit = 0;
    OK(ex(&s, "SELECT COUNT(*) FROM t WHERE a BETWEEN 10 AND 20")); /* cross-checked */
    imdb_session_close(&s);
    OK(verify_db(db));
    imdb_close(db);
}

/* runs q; want >= 0 is the answer of its one cell; path gets the path the result reports */
static void path_of(imdb_session *s, const char *q, int64_t want, char *path, size_t n)
{
    imdb_result r;
    imdb_err_clear(E);
    path[0] = 0;
    int rc = imdb_exec_one(s, q, strlen(q), NULL, 0, &r, E);
    OK_RC(rc);
    if (rc) return;
    if (want >= 0) CHECK(r.nrows == 1 && (r.cells[0].wide ? (int64_t)r.cells[0].i128 : r.cells[0].v.i) == want);
    snprintf(path, n, "%s", r.path);
    imdb_result_free(&r);
}

/* the planner's cost rule (sql_exec.c scan_cheaper): a plain SUM or COUNT over a range covering
 * most of a checkpointed table takes the vectorised scan; a selective one, any range before the
 * checkpoint, other kinds of query, and SET access_path keep the index. Cross-check on: a scan
 * the rule chose is compared against the index, and each answer against its closed form */
static void t_index_planner(void)
{
    const char *dir = test_tmpdir();
    OK(imdb_init(dir, false, NULL, E));
    imdb_db *db = iopen(dir, false);
    CHECK(db);
    if (!db) return;
    imdb_session s;
    imdb_session_init(&s, db);
    s.cross_check = true;
    OK(ex(&s, "CREATE TABLE t (id INT64 PRIMARY KEY, a INT64, memo TEXT)"));
    OK(ex(&s, "CREATE INDEX t_a ON t (a)"));
    enum { N = 20000, B = 500 };
    for (int64_t id = 1; id <= N && !g_test_failed; id += B) {
        imdb_buf ins;
        imdb_buf_init(&ins);
        imdb_buf_put_str(&ins, "INSERT INTO t VALUES ");
        for (int64_t r = 0; r < B; r++) {
            char v[64];
            snprintf(v, sizeof v, "%s(%lld, %lld, 'a memo')", r ? ", " : "", (long long)(id + r), (long long)(id + r));
            imdb_buf_put_str(&ins, v);
        }
        OK(imdb_buf_check(&ins, E));
        imdb_result r;
        imdb_err_clear(E);
        int rc = imdb_exec_one(&s, (const char *)ins.p, ins.len, NULL, 0, &r, E);
        imdb_buf_free(&ins);
        OK_RC(rc);
        if (!rc) imdb_result_free(&r);
    }
    char p[64];
    const int64_t narrow = (1001 + 1500) * 500 / 2, medium = (1001 + 2500) * 1500 / 2, all = (int64_t)N * (N + 1) / 2;
    /* SUM(id) reads each row (id is not the index's column; here id = a), SUM(a) and COUNT(*) are
     * index-only. Before the checkpoint the scan decodes every row one by one: the index never
     * loses */
    path_of(&s, "SELECT SUM(id) FROM t WHERE a BETWEEN 1001 AND 1500", narrow, p, sizeof p);
    CHECK(strncmp(p, "index(ordered) = ", 17) == 0);
    path_of(&s, "SELECT SUM(id) FROM t WHERE a BETWEEN 1 AND 20000", all, p, sizeof p);
    CHECK(strncmp(p, "index(ordered) = ", 17) == 0);
    path_of(&s, "SELECT SUM(a) FROM t WHERE a BETWEEN 1 AND 20000", all, p, sizeof p);
    CHECK(strncmp(p, "index(ordered, only) = ", 23) == 0);
    OK(ex(&s, "CHECKPOINT"));
    /* one segment of 20,000 rows: the scan costs 20,000 units. These cases encode today's measured
     * ratios, not an invariant: 500 candidates read from the segment cost 8,000 units and keep the
     * index, 1,500 cost 24,000 and take the scan, unless index-only (15,000); the whole range takes
     * the scan either way (320,000 and 200,000) */
    path_of(&s, "SELECT SUM(id) FROM t WHERE a BETWEEN 1001 AND 1500", narrow, p, sizeof p);
    CHECK(strncmp(p, "index(ordered) = ", 17) == 0);
    path_of(&s, "SELECT SUM(id) FROM t WHERE a BETWEEN 1001 AND 2500", medium, p, sizeof p);
    CHECK(strcmp(p, "scan = index(ordered) (cross-checked)") == 0);
    path_of(&s, "SELECT SUM(a) FROM t WHERE a BETWEEN 1001 AND 2500", medium, p, sizeof p);
    CHECK(strncmp(p, "index(ordered, only) = ", 23) == 0);
    path_of(&s, "SELECT SUM(id) FROM t WHERE a BETWEEN 1 AND 20000", all, p, sizeof p);
    CHECK(strcmp(p, "scan = index(ordered) (cross-checked)") == 0);
    path_of(&s, "SELECT SUM(a) FROM t WHERE a BETWEEN 1 AND 20000", all, p, sizeof p);
    CHECK(strcmp(p, "scan = index(ordered, only) (cross-checked)") == 0);
    path_of(&s, "SELECT COUNT(*) FROM t WHERE a >= 1", N, p, sizeof p);
    CHECK(strcmp(p, "scan = index(ordered, only) (cross-checked)") == 0);
    /* MAX is no plain sum: the scan reads every match too, so the index is kept */
    path_of(&s, "SELECT MAX(a) FROM t WHERE a BETWEEN 1 AND 20000", N, p, sizeof p);
    CHECK(strncmp(p, "index(ordered, only) = ", 23) == 0);
    /* a predicate on another column: each row is read */
    path_of(&s, "SELECT SUM(a) FROM t WHERE a BETWEEN 1001 AND 1500 AND id >= 1", narrow, p, sizeof p);
    CHECK(strncmp(p, "index(ordered) = ", 17) == 0);
    /* two columns: the equality on memo and the range on a are one range of 500 keys, so the
     * index keeps it (its bounds must hold the equality: all 20,000 entries would go to the scan) */
    OK(ex(&s, "CREATE INDEX t_ma ON t (memo, a)"));
    path_of(&s, "SELECT COUNT(*) FROM t WHERE memo = 'a memo' AND a BETWEEN 1001 AND 1500", 500, p, sizeof p);
    CHECK(strncmp(p, "index(ordered) = ", 17) == 0);
    path_of(&s, "SELECT COUNT(*) FROM t WHERE memo = 'a memo' AND a >= 1", N, p, sizeof p);
    CHECK(strcmp(p, "scan = index(ordered) (cross-checked)") == 0);
    OK(ex(&s, "DROP INDEX t_ma"));
    /* rows to return are read on the scan path too: the index is kept; grouped by its column, the
     * index alone answers */
    imdb_result r;
    imdb_err_clear(E);
    int rc = imdb_exec_one(&s, "SELECT id FROM t WHERE a BETWEEN 1 AND 20000", 44, NULL, 0, &r, E);
    OK_RC(rc);
    if (!rc) {
        CHECK(r.nrows == N && strncmp(r.path, "index(ordered) = ", 17) == 0);
        imdb_result_free(&r);
    }
    imdb_err_clear(E);
    rc = imdb_exec_one(&s, "SELECT a, COUNT(*) FROM t WHERE a BETWEEN 1 AND 100 GROUP BY a", 62, NULL, 0, &r, E);
    OK_RC(rc);
    if (!rc) {
        CHECK(r.nrows == 100 && strncmp(r.path, "index(ordered, only) = ", 23) == 0);
        imdb_result_free(&r);
    }
    path_of(&s, "SELECT SUM(a) FROM t WHERE a BETWEEN 30000 AND 40000", -1, p, sizeof p); /* no candidates */
    CHECK(strncmp(p, "index(ordered, only) = ", 23) == 0);
    OK(ex(&s, "SET access_path = ordered")); /* the session's choice stands */
    path_of(&s, "SELECT SUM(a) FROM t WHERE a BETWEEN 1 AND 20000", all, p, sizeof p);
    CHECK(strncmp(p, "index(ordered, only) = ", 23) == 0);
    OK(ex(&s, "SET access_path = auto"));
    /* a small table keeps the index whatever the range (below the cost floor plans do not flip) */
    OK(ex(&s, "CREATE TABLE u (id INT64 PRIMARY KEY, a INT64)"));
    OK(ex(&s, "CREATE INDEX u_a ON u (a)"));
    OK(ex(&s, "INSERT INTO u VALUES (1, 1), (2, 2), (3, 3), (4, 4), (5, 5), (6, 6), (7, 7), (8, 8), (9, 9), (10, 10)"));
    OK(ex(&s, "CHECKPOINT"));
    path_of(&s, "SELECT SUM(id) FROM u WHERE a >= 1", 55, p, sizeof p);
    CHECK(strncmp(p, "index(ordered) = ", 17) == 0);
    path_of(&s, "SELECT SUM(a) FROM u WHERE a >= 1", 55, p, sizeof p);
    CHECK(strncmp(p, "index(ordered, only) = ", 23) == 0);
    imdb_session_close(&s);
    OK(verify_db(db));
    imdb_close(db);
}

/* CREATE UNIQUE INDEX: a duplicate among live rows is refused at the statement (a NULL in any
 * column exempts the row); a row that keeps its key may be updated; a deleted key is free again,
 * also within one transaction; a rollback and a savepoint free their keys; a statement that fails
 * leaves nothing; refused over live duplicates; another session's commit of the same key wins
 * (CONFLICT at this one's replay); enforced again after a full replay and a snapshot open */
static void t_index_unique(void)
{
    const char *dir = test_tmpdir();
    OK(imdb_init(dir, false, NULL, E));
    imdb_db *db = iopen(dir, false);
    CHECK(db);
    if (!db) return;
    imdb_session s;
    imdb_session_init(&s, db);
    s.cross_check = true;
    OK(ex(&s, "CREATE TABLE t (id INT64 PRIMARY KEY, email TEXT NULL, a INT64, b INT64 NULL)"));
    OK(ex(&s, "INSERT INTO t VALUES (1, 'x@a', 1, 1), (2, 'y@a', 1, 2), (3, NULL, 2, NULL), (4, NULL, 2, NULL)"));
    OK(ex(&s, "CREATE UNIQUE INDEX t_email ON t (email)")); /* two NULL emails, two (2, NULL): exempt */
    OK(ex(&s, "CREATE UNIQUE INDEX t_ab ON t (a, b)"));
    CHECK(ex(&s, "INSERT INTO t VALUES (5, 'x@a', 9, 9)") == IMDB_ERR_CONSTRAINT && strstr(g_e.msg, "t_email"));
    CHECK(ex(&s, "INSERT INTO t VALUES (5, 'z@a', 1, 2)") == IMDB_ERR_CONSTRAINT && strstr(g_e.msg, "t_ab"));
    OK(ex(&s, "INSERT INTO t VALUES (5, NULL, 2, NULL)"));
    CHECK(ex(&s, "UPDATE t SET email = 'y@a' WHERE id = 1") == IMDB_ERR_CONSTRAINT);
    OK(ex(&s, "UPDATE t SET b = 1 WHERE id = 1")); /* it keeps (1, 1) and its email */
    OK(ex(&s, "UPDATE t SET email = 'w@a' WHERE id = 1"));
    OK(ex(&s, "INSERT INTO t VALUES (6, 'x@a', 7, 7)")); /* x@a is free again */
    imdb_table *t = imdb_table_by_name(db, "t");
    CHECK(t);
    if (!t) return;
    uint64_t live = t->live;
    CHECK(ex(&s, "INSERT INTO t VALUES (7, 'q@a', 8, 8), (8, 'q@a', 8, 9)") == IMDB_ERR_CONSTRAINT);
    CHECK(t->live == live); /* the statement left nothing */
    OK(ex(&s, "BEGIN"));
    OK(ex(&s, "DELETE FROM t WHERE id = 6"));
    OK(ex(&s, "INSERT INTO t VALUES (9, 'x@a', 7, 7)"));
    CHECK(ex(&s, "INSERT INTO t VALUES (10, 'x@a', 0, 0)") == IMDB_ERR_CONSTRAINT); /* its own row holds it */
    OK(ex(&s, "COMMIT"));
    OK(ex(&s, "BEGIN"));
    OK(ex(&s, "INSERT INTO t VALUES (10, 'r@a', 3, 3)"));
    OK(ex(&s, "ROLLBACK"));
    OK(ex(&s, "INSERT INTO t VALUES (10, 'r@a', 3, 3)"));
    OK(ex(&s, "BEGIN"));
    OK(ex(&s, "SAVEPOINT p"));
    OK(ex(&s, "INSERT INTO t VALUES (11, 's@a', 4, 4)"));
    OK(ex(&s, "ROLLBACK TO p"));
    OK(ex(&s, "INSERT INTO t VALUES (12, 's@a', 4, 4)"));
    OK(ex(&s, "COMMIT"));
    /* two TEXT columns: ('ab', 'c') and ('a', 'bc') are two keys (each TEXT carries its length) */
    OK(ex(&s, "CREATE TABLE w (id INT64 PRIMARY KEY, x TEXT, y TEXT)"));
    OK(ex(&s, "CREATE UNIQUE INDEX w_xy ON w (x, y)"));
    OK(ex(&s, "INSERT INTO w VALUES (1, 'ab', 'c'), (2, 'a', 'bc'), (3, '', 'abc'), (4, 'abc', '')"));
    CHECK(ex(&s, "INSERT INTO w VALUES (5, 'ab', 'c')") == IMDB_ERR_CONSTRAINT && strstr(g_e.msg, "w_xy"));
    uint64_t seq = db->seq;
    CHECK(ex(&s, "CREATE UNIQUE INDEX t_a ON t (a)") == IMDB_ERR_CONSTRAINT && db->seq == seq);
    CHECK(strcmp(names(db, "t"), "t_ab t_email") == 0);
    /* s's transaction is parked while s2 commits the same key; s's replay then meets it */
    imdb_session s2;
    imdb_session_init(&s2, db);
    OK(ex(&s, "BEGIN"));
    OK(ex(&s, "INSERT INTO t VALUES (13, 'c@a', 5, 5)"));
    OK(ex(&s2, "INSERT INTO t VALUES (14, 'c@a', 6, 6)"));
    int rc = ex(&s, "COMMIT");
    CHECK(rc == IMDB_ERR_CONFLICT);
    if (rc != IMDB_ERR_CONFLICT) ex(&s, "ROLLBACK");
    imdb_session_close(&s2);
    OK(ex(&s, "SELECT COUNT(*) FROM t WHERE email = 'c@a'"));
    imdb_session_close(&s);
    OK(verify_db(db));
    imdb_close(db);
    for (int full = 1; full >= 0 && !g_test_failed; full--) { /* a full replay, then a snapshot open */
        db = iopen(dir, full);
        CHECK(db);
        if (!db) return;
        /* the snapshot was used, not set aside for the log (an open recovers from a snapshot it cannot
         * load by replaying everything, which would hide a wrong build of the unique chains) */
        if (!full) CHECK(db->snapshot_seq && !db->warning[0]);
        imdb_session_init(&s, db);
        char q[128];
        int id = full ? 20 : 21; /* an id of its own each time: the refusals are the unique index's */
        snprintf(q, sizeof q, "INSERT INTO t VALUES (%d, 'x@a', 70, 70)", id);
        CHECK(ex(&s, q) == IMDB_ERR_CONSTRAINT && strstr(g_e.msg, "t_email"));
        snprintf(q, sizeof q, "INSERT INTO t VALUES (%d, 'n@a', 1, 1)", id);
        CHECK(ex(&s, q) == IMDB_ERR_CONSTRAINT && strstr(g_e.msg, "t_ab"));
        snprintf(q, sizeof q, "INSERT INTO t VALUES (%d, NULL, 2, NULL)", id);
        OK(ex(&s, q));
        if (full) OK(ex(&s, "CHECKPOINT")); /* the next open loads this snapshot */
        imdb_session_close(&s);
        OK(verify_db(db));
        imdb_close(db);
    }
}

/* runs q, counting what its path was: index-only, the ordered index reading rows, or another */
static void comp_q(imdb_session *s, const char *q, int *only, int *ordered)
{
    imdb_result r;
    imdb_err_clear(E);
    int rc = imdb_exec_one(s, q, strlen(q), NULL, 0, &r, E);
    OK_RC(rc);
    if (rc) return;
    if (strncmp(r.path, "index(ordered, only)", 20) == 0) (*only)++;
    else if (strncmp(r.path, "index(ordered)", 14) == 0) (*ordered)++;
    imdb_result_free(&r);
}

/* comp_q's, returning the first cell of a one-row result (-1: none) */
static int64_t comp_n(imdb_session *s, const char *q, int *only, int *ordered)
{
    imdb_result r;
    imdb_err_clear(E);
    if (imdb_exec_one(s, q, strlen(q), NULL, 0, &r, E)) {
        test_fail(__FILE__, __LINE__, E->msg);
        return -1;
    }
    int64_t n = r.nrows == 1 ? r.cells[0].v.i : -1;
    if (strncmp(r.path, "index(ordered, only)", 20) == 0) (*only)++;
    else if (strncmp(r.path, "index(ordered)", 14) == 0) (*ordered)++;
    imdb_result_free(&r);
    return n;
}

/* a multi-column index: equality on a prefix of its columns and a range on the next, a TEXT column
 * among them (an 8-byte prefix: 'apple pie' and 'apple pit' share their word), index-only where
 * every column read is in the key; cross-checked against the scan through updates, deletes, a
 * checkpoint and both kinds of reopen. A quarter of s, a and b are NULL: a row whose later column
 * is NULL is in the index (its word 0, shared with INT64's lowest value), one whose first is not,
 * and index-only never reads a nullable later column (c, NOT NULL, is the one it may) */
static void t_index_composite(void)
{
    const char *dir = test_tmpdir();
    OK(imdb_init(dir, false, NULL, E));
    imdb_db *db = iopen(dir, false);
    CHECK(db);
    if (!db) return;
    imdb_session s;
    imdb_session_init(&s, db);
    s.cross_check = true;
    OK(ex(&s, "CREATE TABLE t (id INT64 PRIMARY KEY, s TEXT, a INT64, b INT64, f FLOAT64, c INT64 NOT NULL)"));
    OK(ex(&s, "CREATE INDEX t_ab ON t (a, b)"));
    OK(ex(&s, "CREATE INDEX t_ac ON t (a, c)"));
    OK(ex(&s, "CREATE INDEX t_sa ON t (s, a)"));
    static const char *const words[] = {"apple pie", "apple pit", "apple pi", "apple", "banana", "b", ""};
    char q[512];
    for (int id = 1; id <= 400; id++) {
        char sv[16] = "NULL", av[8] = "NULL", bv[8] = "NULL";
        if (test_rand() % 4) snprintf(sv, sizeof sv, "'%s'", words[test_rand() % 7]);
        if (test_rand() % 4) snprintf(av, sizeof av, "%d", (int)(test_rand() % 10));
        if (test_rand() % 4) snprintf(bv, sizeof bv, "%d", (int)(test_rand() % 41) - 20);
        snprintf(q, sizeof q, "INSERT INTO t VALUES (%d, %s, %s, %s, %d.25, %d)", id, sv, av, bv, (int)(test_rand() % 100) - 50,
                 (int)(test_rand() % 41) - 20);
        OK(ex(&s, q));
    }
    int only = 0, ordered = 0;
    int64_t null_b = 0;
    for (int round = 0; round < 6 && !g_test_failed; round++) {
        for (int k = 0; k < 10; k++) {
            int x = (int)(test_rand() % 11), lo = (int)(test_rand() % 41) - 20, hi = lo + (int)(test_rand() % 15);
            snprintf(q, sizeof q, "SELECT COUNT(*), SUM(c), MIN(c), MAX(c) FROM t WHERE a = %d AND c BETWEEN %d AND %d", x, lo, hi);
            comp_q(&s, q, &only, &ordered);
            snprintf(q, sizeof q, "SELECT COUNT(*), SUM(b), MIN(b), MAX(b) FROM t WHERE a = %d AND b BETWEEN %d AND %d", x, lo, hi);
            comp_q(&s, q, &only, &ordered);
            snprintf(q, sizeof q, "SELECT id, f FROM t WHERE a = %d AND b >= %d", x, lo);
            comp_q(&s, q, &only, &ordered);
            snprintf(q, sizeof q, "SELECT a, COUNT(*) FROM t WHERE a BETWEEN %d AND %d GROUP BY a", x, x + 3);
            comp_q(&s, q, &only, &ordered);
            snprintf(q, sizeof q, "SELECT COUNT(*) FROM t WHERE b = %d", lo); /* b alone: no index serves it */
            comp_q(&s, q, &only, &ordered);
            snprintf(q, sizeof q, "SELECT SUM(a) FROM t WHERE s = '%s' AND a BETWEEN %d AND %d", words[k % 7], x % 5, x % 5 + 4);
            comp_q(&s, q, &only, &ordered);
            snprintf(q, sizeof q, "SELECT COUNT(*) FROM t WHERE s = '%s'", words[(k + round) % 7]); /* rows whose a is NULL */
            comp_q(&s, q, &only, &ordered);
            /* the first column alone finds the rows whose later column is NULL */
            snprintf(q, sizeof q, "SELECT COUNT(*) FROM t WHERE a = %d", x);
            comp_q(&s, q, &only, &ordered);
            snprintf(q, sizeof q, "SELECT COUNT(*) FROM t WHERE a = %d AND b IS NULL", x);
            int64_t n = comp_n(&s, q, &only, &ordered);
            if (n > 0) null_b += n;
            snprintf(q, sizeof q, "SELECT id FROM t WHERE a = %d AND b IS NULL", x);
            comp_q(&s, q, &only, &ordered);
            /* b is nullable after the first column: read from rows, never from its word, where a
             * NULL and INT64's lowest value are both 0 */
            snprintf(q, sizeof q, "SELECT COUNT(b), MIN(b), MAX(b), SUM(b) FROM t WHERE a = %d", x);
            comp_q(&s, q, &only, &ordered);
            snprintf(q, sizeof q, "SELECT b, COUNT(*) FROM t WHERE a = %d GROUP BY b", x);
            comp_q(&s, q, &only, &ordered);
            snprintf(q, sizeof q, "SELECT COUNT(*) FROM t WHERE a = %d AND b < -9223372036854775807", x);
            CHECK(comp_n(&s, q, &only, &ordered) == 0); /* the range is the word 0 alone: only NULLs are there */
        }
        snprintf(q, sizeof q, "UPDATE t SET b = %d WHERE a = %d AND b < 0", round, round % 10);
        OK(ex(&s, q));
        snprintf(q, sizeof q, "UPDATE t SET b = NULL WHERE a = %d AND b = %d", (round + 3) % 10, round);
        OK(ex(&s, q));
        snprintf(q, sizeof q, "DELETE FROM t WHERE s = 'apple pit' AND a = %d", round % 10);
        OK(ex(&s, q));
        if (round == 2) OK(ex(&s, "CHECKPOINT"));
    }
    /* index-only: the first shape (a and c in t_ac's key), the GROUP BY a and the COUNT(*) on a;
     * the shapes reading b, the TEXT ones and the IS NULL ones read rows: not vacuous, and NULLs
     * in b were found through the index */
    CHECK(only >= 6 * 10 * 3 && ordered >= 6 * 10 * 6);
    CHECK(null_b > 0);
    imdb_session_close(&s);
    OK(verify_db(db));
    imdb_close(db);
    for (int full = 1; full >= 0 && !g_test_failed; full--) {
        db = iopen(dir, full);
        CHECK(db);
        if (!db) return;
        if (!full) CHECK(db->snapshot_seq && !db->warning[0]); /* the snapshot was used */
        imdb_session_init(&s, db);
        s.cross_check = true;
        comp_q(&s, "SELECT COUNT(*), SUM(b) FROM t WHERE a = 3 AND b BETWEEN -5 AND 5", &only, &ordered);
        comp_q(&s, "SELECT COUNT(*) FROM t WHERE s = 'apple pie' AND a > 2", &only, &ordered);
        comp_q(&s, "SELECT COUNT(*) FROM t WHERE a = 3", &only, &ordered); /* the structure built at open */
        comp_q(&s, "SELECT id FROM t WHERE a = 3 AND b IS NULL", &only, &ordered);
        comp_q(&s, "SELECT COUNT(b), MIN(b) FROM t WHERE a = 3", &only, &ordered);
        if (full) OK(ex(&s, "CHECKPOINT"));
        imdb_session_close(&s);
        imdb_close(db);
    }
}

const test_case index_tests[] = {
    {"index_ddl", t_index_ddl},         {"index_rollback", t_index_rollback}, {"index_persist", t_index_persist},
    {"index_replica", t_index_replica}, {"index_codec", t_index_codec},   {"index_manifest_strict", t_index_manifest_strict},
    {"index_oidx", t_index_oidx},       {"index_ordered_crosscheck", t_index_ordered_crosscheck}, {"index_erase", t_index_erase},
    {"index_budget", t_index_budget},   {"index_planner", t_index_planner}, {"index_unique", t_index_unique},
    {"index_composite", t_index_composite},
};
const size_t index_ntests = sizeof index_tests / sizeof *index_tests;
