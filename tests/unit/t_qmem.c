/* A read statement's memory has a hard ceiling (P0 resource limits, R2; docs/plan-p0.md): every engine allocation while
 * a SELECT or SHOW runs is charged against the statement's workspace (SET statement_memory; a quarter of the memory
 * budget, or IMDB_MAX_RESULT_BYTES) before its block exists, growth's overlap included, and one past it fails the
 * statement with IMDB_ERR_LIMIT and leaves the session as it was. A segment image's load is the segment cache's, not
 * the workspace's. These tests hold each memory-hungry shape to a refusal at a small workspace and to the right answer
 * at a large one (cross-checked), the lake's images to their exemption, the ceiling to its statement, and, where RSS
 * means something (no sanitizer), the process's peak to the workspace. */
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>

#include "../../src/sql.h"
#include "thelp.h"

#if defined(__SANITIZE_ADDRESS__) || defined(__SANITIZE_THREAD__)
#define QMEM_RSS 0
#elif defined(__has_feature)
#if __has_feature(address_sanitizer) || __has_feature(thread_sanitizer) || __has_feature(memory_sanitizer)
#define QMEM_RSS 0
#endif
#endif
#ifndef QMEM_RSS
#define QMEM_RSS 1
#endif

enum { NROWS = 60000, NSKEW = 1000, NWIDE = 100, WIDE = 60000 };

static int ex(imdb_session *s, const char *sql)
{
    imdb_result r;
    imdb_err_clear(E);
    int rc = imdb_exec_one(s, sql, strlen(sql), NULL, 0, &r, E);
    if (!rc) imdb_result_free(&r);
    return rc;
}

/* the first cell of a one-row answer as an integer; INT64_MIN for an error or anything else */
static int64_t one(imdb_session *s, const char *sql)
{
    imdb_result r;
    imdb_err_clear(E);
    if (imdb_exec_one(s, sql, strlen(sql), NULL, 0, &r, E)) return INT64_MIN;
    const imdb_cell *c = r.nrows >= 1 ? &r.cells[0] : NULL;
    int64_t v = !c || c->null ? INT64_MIN : c->wide ? (int64_t)c->i128 : c->v.i;
    imdb_result_free(&r);
    return v;
}

static int set_mem(imdb_session *s, uint64_t bytes)
{
    char q[80];
    snprintf(q, sizeof q, "SET statement_memory = %llu", (unsigned long long)bytes);
    return ex(s, q);
}

static int run_buf(imdb_session *s, const imdb_buf *b)
{
    imdb_result r;
    imdb_err_clear(E);
    int rc = imdb_exec_one(s, (const char *)b->p, b->len, NULL, 0, &r, E);
    if (!rc) imdb_result_free(&r);
    return rc;
}

/* t: NROWS rows (id, g = id % (NROWS / 2): two rows a group, k: 0 for the first NSKEW rows, else id, s: 40 bytes);
 * w: NWIDE rows of WIDE bytes of TEXT; u: a row for every tenth id of t, an index on its tid */
static int load(imdb_session *s)
{
    if (ex(s, "CREATE TABLE t (id INT64 PRIMARY KEY, g INT64, k INT64, s TEXT)") ||
        ex(s, "CREATE TABLE w (id INT64 PRIMARY KEY, s TEXT)") || ex(s, "CREATE TABLE u (id INT64 PRIMARY KEY, tid INT64)"))
        return -1;
    imdb_buf b;
    imdb_buf_init(&b);
    int rc = 0;
    for (int base = 0; !rc && base < NROWS; base += 5000) {
        b.len = 0;
        imdb_buf_put_str(&b, "INSERT INTO t VALUES ");
        for (int i = base + 1; i <= base + 5000; i++)
            imdb_buf_printf(&b, "%s(%d, %d, %d, 'row-%08d-padding-padding-padding-pad')", i > base + 1 ? ", " : "", i,
                            i % (NROWS / 2), i <= NSKEW ? 0 : i, i);
        rc = imdb_buf_check(&b, E) || run_buf(s, &b);
    }
    for (int base = 0; !rc && base < NWIDE; base += 10) {
        b.len = 0;
        imdb_buf_put_str(&b, "INSERT INTO w VALUES ");
        for (int i = base + 1; i <= base + 10; i++) {
            imdb_buf_printf(&b, "%s(%d, '", i > base + 1 ? ", " : "", i);
            for (int j = 0; j < WIDE; j++) imdb_buf_put_u8(&b, (uint8_t)('a' + (i + j) % 26));
            imdb_buf_put_str(&b, "')");
        }
        rc = imdb_buf_check(&b, E) || run_buf(s, &b);
    }
    for (int base = 0; !rc && base < NROWS / 10; base += 3000) {
        b.len = 0;
        imdb_buf_put_str(&b, "INSERT INTO u VALUES ");
        for (int i = base + 1; i <= base + 3000; i++) imdb_buf_printf(&b, "%s(%d, %d)", i > base + 1 ? ", " : "", i, i * 10);
        rc = imdb_buf_check(&b, E) || run_buf(s, &b);
    }
    imdb_buf_free(&b);
    return rc || ex(s, "CREATE INDEX u_tid ON u (tid)");
}

static imdb_db *dopen(const char *dir, uint64_t seg_cache)
{
    imdb_open_opts o = {.sync = 0, .seg_cache_bytes = seg_cache};
    imdb_db *db = NULL;
    imdb_err_clear(E);
    return imdb_open(dir, &o, &db, E) ? NULL : db;
}

/* The memory-hungry shapes: each refused at IMDB_MIN_STATEMENT_MEMORY with IMDB_ERR_LIMIT, the session then as it was
 * (no ceiling left, the view token unchanged, the heap back to what it held, the next statement answering), and each
 * answering at 256 MB, cross-checked */
static const struct {
    const char *sql;
    int64_t answer; /* the first cell of the answer at 256 MB */
} kShapes[] = {
    {"SELECT id FROM t ORDER BY s DESC, id", NROWS},
    {"SELECT DISTINCT g FROM t ORDER BY g DESC", NROWS / 2 - 1},
    {"SELECT g, COUNT(*) FROM t GROUP BY g ORDER BY g DESC", NROWS / 2 - 1},
    {"SELECT t.id, b.id FROM t JOIN t AS b ON t.k = b.k ORDER BY t.id DESC, b.id LIMIT 1", NROWS}, /* NSKEW^2 pairs */
    {"SELECT s FROM w ORDER BY id DESC", INT64_MIN},                                             /* 6 MB of TEXT */
    {"SELECT t.id FROM t JOIN u ON t.id = u.tid ORDER BY t.id DESC", NROWS},
};

static void shapes(imdb_session *s, imdb_db *db)
{
    uint8_t tok0[32], tok1[32];
    OK(imdb_view_token(db, tok0, E));
    for (size_t i = 0; i < sizeof kShapes / sizeof *kShapes; i++) {
        OK(set_mem(s, IMDB_MIN_STATEMENT_MEMORY));
        uint64_t h0 = imdb_heap_bytes();
        int rc = ex(s, kShapes[i].sql);
        if (rc != IMDB_ERR_LIMIT) {
            char m[400];
            snprintf(m, sizeof m, "%s at 1 MB: %d (%s)", kShapes[i].sql, rc, g_e.msg);
            test_fail(__FILE__, __LINE__, m);
        }
        CHECK(imdb_heap_ceiling() == 0);
        CHECK(imdb_heap_bytes() <= h0 + 4096); /* what the statement held went with it */
        CHECK(one(s, "SELECT COUNT(*) FROM u") == NROWS / 10);
        OK(imdb_view_token(db, tok1, E));
        CHECK(!memcmp(tok0, tok1, 32));
        OK(set_mem(s, 256ull << 20));
        OK(ex(s, "SET cross_check = on"));
        if (kShapes[i].answer != INT64_MIN) {
            int64_t v = one(s, kShapes[i].sql);
            if (v != kShapes[i].answer) {
                char m[400];
                snprintf(m, sizeof m, "%s at 256 MB: %lld (%s)", kShapes[i].sql, (long long)v, g_e.msg);
                test_fail(__FILE__, __LINE__, m);
            }
        } else {
            OK(ex(s, kShapes[i].sql));
        }
        OK(ex(s, "SET cross_check = off"));
        CHECK(imdb_heap_ceiling() == 0);
    }
    OK(set_mem(s, 0));
}

static void t_qmem_shapes(void)
{
    const char *dir = test_tmpdir();
    OK(imdb_init(dir, false, NULL, E));
    imdb_db *db = dopen(dir, 0);
    CHECK(db);
    if (!db) return;
    imdb_session s;
    imdb_session_init(&s, db);
    OK(load(&s));
    shapes(&s, db); /* in memory */
    OK(ex(&s, "SET join_plan = index"));
    OK(set_mem(&s, IMDB_MIN_STATEMENT_MEMORY));
    CHECK(ex(&s, "SELECT t.id FROM t JOIN u ON t.id = u.tid ORDER BY t.id DESC") == IMDB_ERR_LIMIT);
    OK(set_mem(&s, 256ull << 20));
    CHECK(one(&s, "SELECT t.id FROM t JOIN u ON t.id = u.tid ORDER BY t.id DESC") == NROWS);
    OK(ex(&s, "SET join_plan = auto"));
    imdb_session_close(&s);
    imdb_close(db);
}

/* In the lake: every image read again at each statement (a cache of one byte), so every load runs under a workspace
 * far smaller than the images; the loads are exempt and a scan answers, while the same shapes are refused as in
 * memory */
static void t_qmem_lake(void)
{
    const char *dir = test_tmpdir();
    OK(imdb_init(dir, false, NULL, E));
    imdb_db *db = dopen(dir, 0);
    CHECK(db);
    if (!db) return;
    imdb_session s;
    imdb_session_init(&s, db);
    OK(load(&s));
    OK(ex(&s, "CHECKPOINT"));
    imdb_session_close(&s);
    imdb_close(db);
    db = dopen(dir, 1);
    CHECK(db);
    if (!db) return;
    imdb_session_init(&s, db);
    OK(set_mem(&s, IMDB_MIN_STATEMENT_MEMORY));
    uint64_t loads = db->segcache.loads;
    CHECK(one(&s, "SELECT COUNT(*) FROM w WHERE s >= 'a'") == NWIDE); /* 6 MB of images under a 1 MB workspace */
    CHECK(one(&s, "SELECT COUNT(*) FROM t WHERE s >= 'row'") == NROWS);
    CHECK(db->segcache.loads > loads);
    shapes(&s, db);
    imdb_session_close(&s);
    imdb_close(db);
}

/* The ceiling belongs to its statement: never left after one that answers, fails, is cancelled or is refused; inside a
 * transaction; never on what a write writes (an INSERT and an UPDATE far larger than the workspace succeed: they read
 * little; their reading is under it, P2 S8, t_dml_write_ceiling), on DDL or on
 * maintenance; and SET statement_memory's range */
static void t_qmem_scope(void)
{
    const char *dir = test_tmpdir();
    OK(imdb_init(dir, false, NULL, E));
    imdb_db *db = dopen(dir, 0);
    CHECK(db);
    if (!db) return;
    imdb_session s;
    imdb_session_init(&s, db);
    OK(load(&s));
    OK(set_mem(&s, IMDB_MIN_STATEMENT_MEMORY));
    CHECK(imdb_heap_ceiling() == 0);
    CHECK(one(&s, "SELECT COUNT(*) FROM t") == NROWS && imdb_heap_ceiling() == 0);
    CHECK(ex(&s, "SELECT id FROM t ORDER BY s") == IMDB_ERR_LIMIT && imdb_heap_ceiling() == 0);
    CHECK(ex(&s, "SELECT nosuch FROM t") != IMDB_OK && imdb_heap_ceiling() == 0);
    CHECK(ex(&s, "SELEC 1") != IMDB_OK && imdb_heap_ceiling() == 0);
    OK(ex(&s, "SET statement_timeout = 1"));
    int rc = ex(&s, "SELECT COUNT(*) FROM t JOIN t AS b ON t.k = b.k");
    CHECK((rc == IMDB_ERR_CANCELLED || rc == IMDB_ERR_LIMIT || rc == IMDB_OK) && imdb_heap_ceiling() == 0);
    OK(ex(&s, "SET statement_timeout = 0"));
    OK(ex(&s, "SHOW TABLES"));
    OK(ex(&s, "SHOW MEMORY"));
    CHECK(imdb_heap_ceiling() == 0);
    /* writes: an UPDATE of every row and an INSERT of ~2 MB, each past the 1 MB workspace */
    OK(ex(&s, "UPDATE t SET g = g + 1"));
    imdb_buf b;
    imdb_buf_init(&b);
    imdb_buf_put_str(&b, "INSERT INTO w VALUES ");
    for (int i = 0; i < 35; i++) {
        imdb_buf_printf(&b, "%s(%d, '", i ? ", " : "", 1000 + i);
        for (int j = 0; j < WIDE; j++) imdb_buf_put_u8(&b, 'z');
        imdb_buf_put_str(&b, "')");
    }
    OK(imdb_buf_check(&b, E));
    OK(run_buf(&s, &b));
    imdb_buf_free(&b);
    CHECK(imdb_heap_ceiling() == 0);
    /* in a transaction: its reads are bounded, its writes and its COMMIT are not */
    OK(ex(&s, "BEGIN"));
    OK(ex(&s, "UPDATE t SET g = g - 1"));
    CHECK(ex(&s, "SELECT id FROM t ORDER BY s") == IMDB_ERR_LIMIT && imdb_heap_ceiling() == 0);
    CHECK(one(&s, "SELECT COUNT(*) FROM t WHERE g = 0") == 2);
    OK(ex(&s, "COMMIT"));
    CHECK(imdb_heap_ceiling() == 0);
    OK(ex(&s, "CREATE INDEX t_g ON t (g)"));
    OK(ex(&s, "CHECKPOINT"));
    CHECK(imdb_heap_ceiling() == 0);
    /* the setting's range; 0 is the default again */
    CHECK(ex(&s, "SET statement_memory = 1048575") == IMDB_ERR_INVALID);
    CHECK(ex(&s, "SET statement_memory = 17179869185") == IMDB_ERR_INVALID);
    CHECK(ex(&s, "SET statement_memory = big") == IMDB_ERR_INVALID);
    OK(ex(&s, "SET statement_memory = 0"));
    OK(ex(&s, "SELECT id FROM t ORDER BY s"));
    imdb_session_close(&s);
    imdb_close(db);
}

/* The default follows the memory budget: a quarter of it */
static void t_qmem_budget(void)
{
    const char *dir = test_tmpdir();
    OK(imdb_init(dir, false, NULL, E));
    imdb_db *db = dopen(dir, 0);
    CHECK(db);
    if (!db) return;
    imdb_session s;
    imdb_session_init(&s, db);
    OK(load(&s));
    imdb_session_close(&s);
    imdb_close(db);
    imdb_open_opts o = {.sync = 0, .mem_limit = 4ull << 30};
    db = NULL;
    OK(imdb_open(dir, &o, &db, E));
    imdb_session_init(&s, db);
    OK(ex(&s, "SELECT id FROM t ORDER BY s")); /* a GiB of workspace */
    imdb_session_close(&s);
    imdb_close(db);
    o.mem_limit = 4ull << 20; /* 1 MB of workspace: the open itself is never refused */
    db = NULL;
    OK(imdb_open(dir, &o, &db, E));
    imdb_session_init(&s, db);
    CHECK(ex(&s, "SELECT id FROM t ORDER BY s") == IMDB_ERR_LIMIT);
    CHECK(one(&s, "SELECT COUNT(*) FROM u") == NROWS / 10);
    imdb_session_close(&s);
    imdb_close(db);
}

/* The process's peak holds to the workspace: in a forked child (the pool's workers do not cross a fork, so its
 * loops run inline: one arena), a join needing ~64 MB at a 2 MB workspace is refused and the peak RSS (VmHWM) grows
 * by less than the workspace plus 8 MB (malloc's arenas and the kernel's rounding); the same query at 256 MB answers
 * and grows it past that (the measure is not blind). No sanitizer: their shadow memory is RSS too. */
static uint64_t hwm_kb(void)
{
    FILE *f = fopen("/proc/self/status", "r");
    if (!f) return 0;
    char line[256];
    uint64_t v = 0;
    while (fgets(line, sizeof line, f))
        if (strncmp(line, "VmHWM:", 6) == 0) v = strtoull(line + 6, NULL, 10);
    fclose(f);
    return v;
}

static int rss_child(const char *dir, uint64_t workspace, bool want_refused)
{
    imdb_db *db = dopen(dir, 0);
    if (!db) return 2;
    imdb_session s;
    imdb_session_init(&s, db);
    if (one(&s, "SELECT COUNT(*) FROM t WHERE s >= 'row'") != NROWS) return 3; /* the warm-up: the store is touched */
    if (set_mem(&s, workspace)) return 4;
    uint64_t before = hwm_kb();
    int rc = ex(&s, "SELECT t.id, b.id FROM t JOIN t AS b ON t.k = b.k ORDER BY t.id DESC, b.id LIMIT 1000");
    uint64_t grew = (hwm_kb() - before) * 1024;
    imdb_session_close(&s);
    imdb_close(db);
    if (want_refused) return rc == IMDB_ERR_LIMIT && grew < workspace + (8ull << 20) ? 0 : 5;
    return rc == IMDB_OK && grew > (2ull << 20) + (8ull << 20) ? 0 : 6;
}

static void t_qmem_rss(void)
{
    if (!QMEM_RSS) return;
    const char *dir = test_tmpdir();
    OK(imdb_init(dir, false, NULL, E));
    imdb_db *db = dopen(dir, 0);
    CHECK(db);
    if (!db) return;
    imdb_session s;
    imdb_session_init(&s, db);
    OK(load(&s));
    imdb_session_close(&s);
    imdb_close(db);
    for (int k = 0; k < 2; k++) {
        fflush(NULL);
        pid_t pid = fork();
        if (pid == 0) _exit(rss_child(dir, k ? 256ull << 20 : 2ull << 20, k == 0));
        int st = 0;
        CHECK(pid > 0 && waitpid(pid, &st, 0) == pid);
        if (!WIFEXITED(st) || WEXITSTATUS(st) != 0) {
            char m[160];
            snprintf(m, sizeof m, "rss child %d: status %d", k, WIFEXITED(st) ? WEXITSTATUS(st) : -1);
            test_fail(__FILE__, __LINE__, m);
        }
    }
}


/* ---- a script streamed (the CLI's -f and piped input) ---------------------------------------------------------- */

typedef struct stmts {
    char text[16][160];
    int n;
} stmts;

static int collect_stmt(void *arg, const char *sql, size_t len)
{
    stmts *c = arg;
    if (c->n >= 16 || len >= sizeof c->text[0]) return IMDB_ERR_LIMIT;
    memcpy(c->text[c->n], sql, len);
    c->text[c->n][len] = 0;
    c->n++;
    return IMDB_OK;
}

/* the stream's way: each chunk appended, the complete statements at the front run, the rest kept; at the end the rest
 * as a whole text (main.c's run_stream) */
static int stream_split(const char *s, size_t n, size_t chunk, stmts *out, imdb_err *e)
{
    char buf[1024];
    size_t have = 0, at = 0;
    memset(out, 0, sizeof *out);
    for (;;) {
        size_t take = n - at < chunk ? n - at : chunk;
        if (!take) return have ? imdb_split_statements(buf, have, collect_stmt, out, e) : IMDB_OK;
        memcpy(buf + have, s + at, take);
        have += take;
        at += take;
        size_t used = 0;
        int rc = imdb_split_complete(buf, have, collect_stmt, out, &used, e);
        if (rc) return rc;
        memmove(buf, buf + used, have - used);
        have -= used;
    }
}

/* Every chunk size from one byte to the whole script gives the statements the whole text gives, with literals that
 * hold ';', '--' and doubled quotes, comments that hold ';', and quotes and dashes at every chunk's edge; an
 * unterminated literal is the same error either way */
static void t_qmem_stream(void)
{
    static const char script[] = "INSERT INTO x VALUES (1, 'a;b'); -- c;d\n"
                                 "INSERT INTO x VALUES (2, 'it''s;'); INSERT INTO x VALUES (3, '--not a comment');\n"
                                 "-- a whole line; a comment\n"
                                 "INSERT INTO x VALUES (4, '''');SELECT COUNT(*) FROM x WHERE v - 1 > 0;\n"
                                 "SELECT COUNT(*) FROM x -- the last one has no ';'";
    size_t n = sizeof script - 1;
    stmts whole, part;
    memset(&whole, 0, sizeof whole);
    OK(imdb_split_statements(script, n, collect_stmt, &whole, E));
    CHECK(whole.n == 6);
    for (size_t chunk = 1; chunk <= n; chunk++) {
        imdb_err_clear(E);
        int rc = stream_split(script, n, chunk, &part, E);
        if (rc || part.n != whole.n) {
            char m[160];
            snprintf(m, sizeof m, "chunk %zu: rc %d, %d statements of %d", chunk, rc, part.n, whole.n);
            test_fail(__FILE__, __LINE__, m);
            return;
        }
        for (int i = 0; i < whole.n; i++)
            if (strcmp(whole.text[i], part.text[i]) != 0) {
                char m[400];
                snprintf(m, sizeof m, "chunk %zu, statement %d: [%s] for [%s]", chunk, i, part.text[i], whole.text[i]);
                test_fail(__FILE__, __LINE__, m);
                return;
            }
    }
    static const char bad[] = "INSERT INTO x VALUES (1, 'a'); INSERT INTO x VALUES (2, 'no end);";
    size_t bn = sizeof bad - 1;
    imdb_err_clear(E);
    CHECK(imdb_split_statements(bad, bn, collect_stmt, &whole, E) == IMDB_ERR_SYNTAX);
    for (size_t chunk = 1; chunk <= bn; chunk++) {
        imdb_err_clear(E);
        CHECK(stream_split(bad, bn, chunk, &part, E) == IMDB_ERR_SYNTAX && part.n == 1 && strstr(g_e.msg, "unterminated"));
    }
}

const test_case qmem_tests[] = {
    {"qmem_shapes", t_qmem_shapes}, {"qmem_lake", t_qmem_lake}, {"qmem_scope", t_qmem_scope},
    {"qmem_budget", t_qmem_budget}, {"qmem_rss", t_qmem_rss}, {"qmem_stream", t_qmem_stream},
};
const size_t qmem_ntests = sizeof qmem_tests / sizeof *qmem_tests;
