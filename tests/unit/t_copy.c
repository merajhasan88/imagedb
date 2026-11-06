/* P2 S10 (docs/plan-p2.md): COPY ... FROM STDIN and COPY ... TO STDOUT through the session's stream
 * (imdb_session_copy_io), served here from memory in pieces of every size, so a record is cut at every byte. A round
 * trip of every type with NULLs, empty strings, quotes, delimiters, CR LF and LF streams, newlines inside quotes and
 * UTF-8 at its limits gives back the same bytes; each refusal names its line and field and no value, and leaves the
 * table as it was; BATCH commits as it goes and SKIP resumes after it; inside a transaction the rows are its own; a
 * replica applying a COPY's commits ends at the primary's digest, VERIFY passing on both; a query's rows; a cancel;
 * every refused form. */
#include <stdlib.h>

#include "../../src/db.h"
#include "../../src/sql.h"
#include "thelp.h"

static imdb_session g_s;
static char g_out[1 << 18];

/* the stream: COPY FROM reads in (at most piece bytes a read: 0 any), COPY TO writes into out */
typedef struct mem_io {
    const char *in;
    size_t inlen, inpos, piece;
    char *out;
    size_t outlen, outcap;
    bool fail_read, fail_write;
    size_t cancel_at; /* a byte count: the session is cancelled once the reads pass it (0: never) */
} mem_io;
static mem_io g_io;

static long mem_read(void *arg, char *buf, size_t cap)
{
    mem_io *m = arg;
    if (m->fail_read && m->inpos) return -1;
    size_t k = m->inlen - m->inpos;
    if (k > cap) k = cap;
    if (m->piece && k > m->piece) k = m->piece;
    if (k) memcpy(buf, m->in + m->inpos, k); /* in is NULL for a stream given no data: memcpy wants a pointer even for 0 */
    m->inpos += k;
    if (m->cancel_at && m->inpos >= m->cancel_at) imdb_session_cancel(&g_s);
    return (long)k;
}

static int mem_write(void *arg, const char *b, size_t n)
{
    mem_io *m = arg;
    if (m->fail_write || m->outlen + n > m->outcap) return -1;
    if (n) memcpy(m->out + m->outlen, b, n);
    m->outlen += n;
    return 0;
}

static const char *res_text(int rc, imdb_result *r, char *out, size_t cap)
{
    if (rc) {
        snprintf(out, cap, "ERR %s", g_e.msg);
        return out;
    }
    imdb_buf b;
    imdb_buf_init(&b);
    if (r->has_rows) imdb_result_render(r, true, &b);
    else imdb_buf_put_str(&b, r->status);
    if (imdb_buf_check(&b, &g_e)) snprintf(out, cap, "ERR render");
    else snprintf(out, cap, "%.*s", (int)b.len, (const char *)b.p);
    imdb_buf_free(&b);
    imdb_result_free(r);
    return out;
}

static const char *csv(const char *sql)
{
    imdb_result r;
    imdb_err_clear(&g_e);
    int rc = imdb_exec_one(&g_s, sql, strlen(sql), NULL, 0, &r, &g_e);
    return res_text(rc, &r, g_out, sizeof g_out);
}

static int run(const char *sql)
{
    imdb_result r;
    imdb_err_clear(&g_e);
    int rc = imdb_exec_one(&g_s, sql, strlen(sql), NULL, 0, &r, &g_e);
    if (!rc) imdb_result_free(&r);
    return rc;
}

/* COPY ... FROM STDIN with data, read in pieces of piece bytes: its status ("COPY n") or "ERR ..." */
static const char *copy_in(const char *stmt, const char *data, size_t len, size_t piece)
{
    g_io.in = data;
    g_io.inlen = len;
    g_io.inpos = 0;
    g_io.piece = piece;
    return csv(stmt);
}

/* COPY ... TO STDOUT: the bytes it wrote, NUL-ended in g_io.out, or "ERR ..." */
static const char *copy_out(const char *stmt)
{
    g_io.outlen = 0;
    const char *st = csv(stmt);
    if (!strncmp(st, "ERR ", 4)) return st;
    if (g_io.outlen == g_io.outcap) return "ERR full";
    g_io.out[g_io.outlen] = 0;
    return g_io.out;
}

static imdb_db *open_at(const char *dir)
{
    imdb_err e = {0};
    imdb_open_opts o = {.sync = 0};
    imdb_db *db = NULL;
    if (imdb_open(dir, &o, &db, &e)) return NULL;
    imdb_session_init(&g_s, db);
    imdb_session_copy_io(&g_s, mem_read, mem_write, &g_io);
    return db;
}

static imdb_db *open_fresh(void)
{
    const char *dir = test_tmpdir();
    imdb_err e = {0};
    if (imdb_init(dir, false, NULL, &e)) return NULL;
    memset(&g_io, 0, sizeof g_io);
    g_io.outcap = 8u << 20;
    if (!(g_io.out = malloc(g_io.outcap + 1))) return NULL;
    return open_at(dir);
}

static void done(imdb_db *db)
{
    imdb_session_close(&g_s);
    imdb_close(db);
    free(g_io.out);
    g_io.out = NULL;
}

#define EXPECT(got, want)                                                                                          \
    do {                                                                                                           \
        const char *g_ = (got), *w_ = (want);                                                                      \
        bool ok_ = !strncmp(w_, "ERR ", 4) ? !strncmp(g_, "ERR ", 4) && strstr(g_ + 4, w_ + 4) != NULL : !strcmp(g_, w_); \
        if (!ok_) {                                                                                                \
            char m_[1600];                                                                                         \
            snprintf(m_, sizeof m_, "\n      want: %.700s\n      got:  %.700s", w_, g_);                            \
            test_fail(__FILE__, __LINE__, m_);                                                                     \
        }                                                                                                          \
    } while (0)

#define SCHEMA "(id INT64 PRIMARY KEY, s TEXT NULL, d DECIMAL(18,3) NULL, f FLOAT64 NULL, b BOOL NULL, ts TIMESTAMP NULL)"

/* every type at its edges, NULLs and the empty string, quotes, delimiters, a newline and a CR inside quotes, UTF-8 of
 * every length; LF ends (eol 1) or CR LF (eol 2) */
static size_t edge_data(char *out, size_t cap, int eol, bool header)
{
    const char *nl = eol == 2 ? "\r\n" : "\n";
    size_t n = 0;
#define PUT(...) (n += (size_t)snprintf(out + n, cap - n, __VA_ARGS__))
    if (header) PUT("id,s,d,f,b,ts%s", nl);
    PUT("-9223372036854775808,plain,-999999999999999.999,-1.7976931348623157e+308,true,0001-01-01 00:00:00%s", nl);
    PUT("9223372036854775807,\"\",999999999999999.999,1.7976931348623157e+308,false,9999-12-31 23:59:59.999999%s", nl);
    PUT("0,,,,,%s", nl);
    PUT("1,\"a, comma; and \"\"quotes\"\"\",0.001,0.1,true,2026-11-05 13:45:00.500000%s", nl);
    PUT("2,\"line one\nline two\r\nline three\",-0.001,1e-300,false,1970-01-01 00:00:00%s", nl);
    PUT("3,\xc3\xa9\xe6\x97\xa5\xf0\x9f\x98\x80 \x7f end,12.345,-2.5,,%s", nl);
    PUT("4,\"\\.\",1.000,1,true,2000-02-29 12:00:00%s", nl);
    PUT("5, spaces kept ,0.000,0,false,2026-01-01 00:00:00.000001%s", nl);
#undef PUT
    return n;
}

static char g_d1[1 << 16], g_d2[1 << 16], g_t1[1 << 16];

static void t_copy_round_trip(void)
{
    imdb_db *db = open_fresh();
    CHECK(db);
    CHECK(run("CREATE TABLE t " SCHEMA) == 0 && run("CREATE TABLE t2 " SCHEMA) == 0);
    size_t n = edge_data(g_d1, sizeof g_d1, 1, true);
    EXPECT(copy_in("COPY t FROM STDIN (HEADER)", g_d1, n, 0), "COPY 8");
    /* the same bytes back: every value written as the input wrote it (each already in its canonical form) */
    const char *o = copy_out("COPY t TO STDOUT (HEADER)");
    snprintf(g_t1, sizeof g_t1, "%s", o);
    char sorted[1 << 16];
    snprintf(sorted, sizeof sorted, "%s", g_d1);
    CHECK(strlen(g_t1) == n);
    /* the export is in key order: the input's rows sorted by id; compare by loading it again */
    EXPECT(copy_in("COPY t2 FROM STDIN (HEADER)", g_t1, strlen(g_t1), 0), "COPY 8");
    EXPECT(copy_out("COPY t2 TO STDOUT (HEADER)"), g_t1);
    char a[1 << 16];
    snprintf(a, sizeof a, "%s", csv("SELECT * FROM t ORDER BY id"));
    EXPECT(csv("SELECT * FROM t2 ORDER BY id"), a);
    EXPECT(csv("SELECT COUNT(*) FROM t WHERE s IS NULL"), "count\n1\n");
    EXPECT(csv("SELECT COUNT(*) FROM t WHERE s = ''"), "count\n1\n");
    EXPECT(csv("SELECT s FROM t WHERE id = 4"), "s\n\"\\.\"\n");
    EXPECT(csv("SELECT LENGTH(s) AS n FROM t WHERE id = 5"), "n\n13\n");
    /* every piece size: a record cut at every byte, the same table */
    static const size_t pieces[] = {1, 2, 3, 5, 7, 64, 4096};
    for (size_t k = 0; k < sizeof pieces / sizeof pieces[0]; k++) {
        CHECK(run("DELETE FROM t2") == 0);
        EXPECT(copy_in("COPY t2 FROM STDIN (HEADER)", g_d1, n, pieces[k]), "COPY 8");
        EXPECT(copy_out("COPY t2 TO STDOUT (HEADER)"), g_t1);
    }
    /* a CR LF stream: the same rows (a CR LF inside quotes is data either way) */
    CHECK(run("DELETE FROM t2") == 0);
    size_t n2 = edge_data(g_d2, sizeof g_d2, 2, true);
    EXPECT(copy_in("COPY t2 FROM STDIN (HEADER)", g_d2, n2, 3), "COPY 8");
    EXPECT(copy_out("COPY t2 TO STDOUT (HEADER)"), g_t1);
    /* another delimiter, both ways; no header */
    const char *semi = copy_out("COPY t TO STDOUT (DELIMITER ';')");
    snprintf(g_d2, sizeof g_d2, "%s", semi);
    CHECK(strstr(g_d2, "id;s") == NULL && strstr(g_d2, "\"a, comma; and \"\"quotes\"\"\"") != NULL);
    CHECK(run("DELETE FROM t2") == 0);
    EXPECT(copy_in("COPY t2 FROM STDIN (DELIMITER ';')", g_d2, strlen(g_d2), 0), "COPY 8");
    EXPECT(copy_out("COPY t2 TO STDOUT (HEADER)"), g_t1);
    const char *tab = copy_out("COPY t TO STDOUT (DELIMITER '\t', HEADER FALSE)");
    snprintf(g_d2, sizeof g_d2, "%s", tab);
    CHECK(run("DELETE FROM t2") == 0);
    EXPECT(copy_in("COPY t2 FROM STDIN (DELIMITER '\t')", g_d2, strlen(g_d2), 0), "COPY 8");
    EXPECT(copy_out("COPY t2 TO STDOUT (HEADER)"), g_t1);
    /* a column list: the rest NULL; the last record without its line end */
    CHECK(run("DELETE FROM t2") == 0);
    EXPECT(copy_in("COPY t2 (b, id) FROM STDIN", "true,7\nfalse,8", 14, 1), "COPY 2");
    EXPECT(copy_out("COPY t2 (id, b, s) TO STDOUT (HEADER)"), "id,b,s\n7,true,\n8,false,\n");
    CHECK(run("DELETE FROM t2") == 0); /* a CR LF stream whose last record has no line end */
    EXPECT(copy_in("COPY t2 (b, id) FROM STDIN", "true,7\r\nfalse,8", 15, 2), "COPY 2");
    EXPECT(copy_out("COPY t2 (id, b, s) TO STDOUT (HEADER)"), "id,b,s\n7,true,\n8,false,\n");
    /* a TEXT of the longest: 65,535 bytes, read whole in pieces */
    char *big = malloc(70000);
    CHECK(big);
    size_t m = (size_t)snprintf(big, 70000, "9,");
    memset(big + m, 'x', IMDB_MAX_TEXT);
    m += IMDB_MAX_TEXT;
    big[m++] = '\n';
    EXPECT(copy_in("COPY t2 (id, s) FROM STDIN", big, m, 4093), "COPY 1");
    EXPECT(csv("SELECT LENGTH(s) AS n FROM t2 WHERE id = 9"), "n\n65535\n");
    free(big);
    CHECK(run("VERIFY") == 0);
    done(db);
}

/* a refused load: its message names the line and field and no value, and the table is as it was */
typedef struct refusal {
    const char *data;
    const char *msg;
} refusal;

static const refusal g_refusals[] = {
    {"1,SECRET\n2\n", "COPY line 2: 1 fields, the columns are 2"},
    {"1,SECRET\n2,a,b\n", "COPY line 2: 3 fields, the columns are 2"},
    {"x1,SECRET\n", "COPY line 1, column id: invalid integer literal"},
    {"1,SECRET\n99999999999999999999,a\n", "COPY line 2, column id: integer literal out of INT64 range"},
    {"1,\"SECRET\n", "COPY line 1, field 2: a quoted field the data ends inside"},
    {"1,SE\"CRET\n", "COPY line 1, field 2: a quote inside an unquoted field"},
    {"1,\"SECRET\"x\n", "COPY line 1, field 2: a byte after a closing quote"},
    {"1,SECRET\r2,a\n", "COPY line 1, field 2: a CR outside quotes not followed by LF"},
    {"1,SECRET\n2,a\r\n", "COPY line 2, field 2: line ends mixed"},
    {"\xEF\xBB\xBF" "1,SECRET\n", "COPY line 1, field 1: the data begins with a byte-order mark"},
    {"\xEF\xBB\xBF\"1\",SECRET\n", "COPY line 1, field 1: the data begins with a byte-order mark"},
    {"1,SECRET\n2,\xC3\x28\n", "COPY line 2, column s: TEXT that is not UTF-8, or holds a NUL, at byte 1"},
    {"1,SECRET\n1,again\n", "COPY line 2:"}, /* the key: INSERT's own refusal */
    {",SECRET\n", "COPY line 1, column id: NULL (an empty field) in a NOT NULL column"},
    {"1,SECRET\r\n2,a\r", "COPY line 2, field 2: a CR outside quotes not followed by LF"}, /* a bare CR at the end */
};

static void t_copy_refusals(void)
{
    imdb_db *db = open_fresh();
    CHECK(db);
    CHECK(run("CREATE TABLE r (id INT64 PRIMARY KEY, s TEXT NULL)") == 0 && run("INSERT INTO r VALUES (100, 'kept')") == 0);
    char before[4096];
    snprintf(before, sizeof before, "%s", csv("SELECT * FROM r ORDER BY id"));
    for (size_t i = 0; i < sizeof g_refusals / sizeof g_refusals[0]; i++) {
        for (size_t piece = 0; piece <= 3; piece += 3) {
            const char *got = copy_in("COPY r FROM STDIN", g_refusals[i].data, strlen(g_refusals[i].data), piece);
            char want[300];
            snprintf(want, sizeof want, "ERR %s", g_refusals[i].msg);
            EXPECT(got, want);
            CHECK(strstr(got, "SECRET") == NULL && strstr(got, "again") == NULL);
            EXPECT(csv("SELECT * FROM r ORDER BY id"), before);
        }
    }
    /* a NUL inside TEXT, and a TEXT one byte past the longest */
    static const char nul[] = "1,a\0b\n";
    EXPECT(copy_in("COPY r FROM STDIN", nul, sizeof nul - 1, 0), "ERR COPY line 1, column s: TEXT that is not UTF-8, or holds a NUL, at byte 2");
    char *big = malloc(70000);
    CHECK(big);
    size_t m = (size_t)snprintf(big, 70000, "1,");
    memset(big + m, 'y', IMDB_MAX_TEXT + 1);
    m += IMDB_MAX_TEXT + 1;
    EXPECT(copy_in("COPY r FROM STDIN", big, m, 0), "ERR COPY line 1, field 2: a field longer than 65535 bytes");
    free(big);
    /* more fields than a table may have columns */
    char wide[400];
    size_t w = 0;
    for (int k = 0; k <= (int)IMDB_MAX_COLS; k++) w += (size_t)snprintf(wide + w, sizeof wide - w, "%s1", k ? "," : "");
    EXPECT(copy_in("COPY r FROM STDIN", wide, w, 0), "ERR COPY line 1, field 64: more than 64 fields");
    /* HEADER: the names, in order, every one; an empty stream has none */
    EXPECT(copy_in("COPY r FROM STDIN (HEADER)", "s,id\n1,a\n", 9, 0), "ERR COPY line 1: the header's field 1 is not column id");
    EXPECT(copy_in("COPY r FROM STDIN (HEADER)", "id\n1\n", 5, 0), "ERR COPY line 1: the header has 1 fields, the columns are 2");
    EXPECT(copy_in("COPY r FROM STDIN (HEADER)", "", 0, 0), "ERR COPY ... HEADER: the data is empty, with no header line");
    EXPECT(copy_in("COPY r FROM STDIN (HEADER)", "ID,S\n7,x\n", 9, 0), "COPY 1"); /* names as identifiers: any case */
    EXPECT(copy_in("COPY r FROM STDIN", "", 0, 0), "COPY 0");
    /* the stream's own failure, mid-way */
    g_io.fail_read = true;
    EXPECT(copy_in("COPY r FROM STDIN", "8,a\n9,b\n", 8, 4), "ERR COPY line 2: reading the data failed");
    g_io.fail_read = false;
    g_io.fail_write = true;
    EXPECT(copy_out("COPY r TO STDOUT"), "ERR COPY ... TO STDOUT: writing the data failed");
    g_io.fail_write = false;
    EXPECT(csv("SELECT COUNT(*) FROM r"), "count\n2\n");
    CHECK(run("VERIFY") == 0);
    done(db);
}

static char g_batch[1 << 16];

static void t_copy_batch(void)
{
    imdb_db *db = open_fresh();
    CHECK(db);
    CHECK(run("CREATE TABLE b (id INT64 PRIMARY KEY, v INT64)") == 0);
    /* ten rows, then a bad eleventh: BATCH 4 commits two batches, rolls back the third */
    size_t n = 0;
    for (int i = 1; i <= 10; i++) n += (size_t)snprintf(g_batch + n, sizeof g_batch - n, "%d,%d\n", i, i * 10);
    n += (size_t)snprintf(g_batch + n, sizeof g_batch - n, "11,bad\n12,120\n");
    uint64_t seq0 = db->seq;
    EXPECT(copy_in("COPY b FROM STDIN (BATCH 4)", g_batch, n, 0),
           "ERR COPY line 11, column v: invalid integer literal; earlier batches committed 8 rows: SKIP 8 resumes after them");
    EXPECT(csv("SELECT COUNT(*), MAX(id) FROM b"), "count,max_id\n8,8\n");
    CHECK(db->seq == seq0 + 2);
    /* the resume: the same data, the bad value put right, SKIP 8 */
    char *bad = strstr(g_batch, "11,bad");
    CHECK(bad);
    memcpy(bad, "11,110", 6);
    EXPECT(copy_in("COPY b FROM STDIN (BATCH 4, SKIP 8)", g_batch, n, 5), "COPY 4");
    EXPECT(csv("SELECT COUNT(*), SUM(v) FROM b"), "count,sum_v\n12,780\n");
    /* SKIP past the end: nothing; BATCH larger than the data: one commit */
    EXPECT(copy_in("COPY b FROM STDIN (SKIP 100)", g_batch, n, 0), "COPY 0");
    CHECK(run("DELETE FROM b") == 0);
    uint64_t seq1 = db->seq;
    EXPECT(copy_in("COPY b FROM STDIN (BATCH 1000)", g_batch, n, 0), "COPY 12");
    CHECK(db->seq == seq1 + 1);
    /* BATCH commits as it goes: refused inside a transaction, and a COPY TO has none */
    CHECK(run("BEGIN") == 0);
    EXPECT(copy_in("COPY b FROM STDIN (BATCH 2)", "100,1\n", 6, 0), "ERR COPY ... BATCH commits as it goes: run it outside an explicit transaction");
    CHECK(run("ROLLBACK") == 0);
    EXPECT(csv("COPY b TO STDOUT (BATCH 2)"), "ERR BATCH is COPY ... FROM's");
    EXPECT(csv("COPY b FROM STDIN (BATCH 0)"), "ERR BATCH is 1 to 1048576 rows a commit");
    CHECK(run("VERIFY") == 0);
    done(db);
}

static void t_copy_txn(void)
{
    imdb_db *db = open_fresh();
    CHECK(db);
    CHECK(run("CREATE TABLE x (id INT64 PRIMARY KEY, v INT64 NULL)") == 0);
    CHECK(run("BEGIN") == 0);
    EXPECT(copy_in("COPY x FROM STDIN", "1,1\n2,2\n3,3\n", 12, 2), "COPY 3");
    EXPECT(csv("SELECT COUNT(*) FROM x"), "count\n3\n"); /* its own rows */
    CHECK(run("ROLLBACK") == 0);
    EXPECT(csv("SELECT COUNT(*) FROM x"), "count\n0\n");
    /* a refused COPY inside a transaction: its own rows undone, the transaction's earlier ones kept */
    CHECK(run("BEGIN") == 0);
    CHECK(run("INSERT INTO x VALUES (10, 10)") == 0);
    EXPECT(copy_in("COPY x FROM STDIN", "4,4\n5,oops\n", 11, 0), "ERR COPY line 2, column v: invalid integer literal");
    EXPECT(copy_in("COPY x FROM STDIN", "6,6\n", 4, 0), "COPY 1");
    CHECK(run("COMMIT") == 0);
    EXPECT(csv("SELECT id FROM x ORDER BY id"), "id\n6\n10\n");
    /* an autocommit COPY refused part way leaves nothing */
    EXPECT(copy_in("COPY x FROM STDIN", "20,1\n21,1\n6,dup\n", 17, 1), "ERR COPY line 3");
    EXPECT(csv("SELECT COUNT(*) FROM x"), "count\n2\n");
    CHECK(run("VERIFY") == 0);
    done(db);
}

/* the rows a COPY wrote are commits like any: a replica applying them ends at the primary's digest and head */
static void t_copy_replica(void)
{
    const char *base = test_tmpdir();
    char p[600], r[600], s[600];
    snprintf(p, sizeof p, "%s/primary", base);
    snprintf(r, sizeof r, "%s/replica", base);
    snprintf(s, sizeof s, "%s/stream", base);
    OK(imdb_init(p, false, NULL, E));
    OK(imdb_init(r, true, p, E));
    memset(&g_io, 0, sizeof g_io);
    g_io.outcap = 8u << 20;
    g_io.out = malloc(g_io.outcap + 1);
    CHECK(g_io.out);
    imdb_db *db = open_at(p);
    CHECK(db);
    CHECK(run("CREATE TABLE c (id INT64 PRIMARY KEY, s TEXT NULL, d DECIMAL(9,2) NULL)") == 0);
    size_t n = 0;
    for (int i = 1; i <= 500; i++)
        n += (size_t)snprintf(g_batch + n, sizeof g_batch - n, "%d,\"r%d, \"\"q\"\"\",%d.%02d\n", i, i, i, i % 100);
    EXPECT(copy_in("COPY c FROM STDIN (BATCH 100)", g_batch, n, 997), "COPY 500");
    CHECK(run("VERIFY") == 0);
    char want[1 << 16];
    snprintf(want, sizeof want, "%s", copy_out("COPY c TO STDOUT"));
    imdb_session_close(&g_s);
    OK(ship_to_file(p, 0, s, E));
    imdb_db *rep = NULL;
    imdb_open_opts o = {.sync = 0};
    OK(imdb_open(r, &o, &rep, E));
    uint64_t applied = 0;
    OK(apply_file(rep, s, &applied, E));
    CHECK(rep->seq == db->seq && memcmp(rep->head, db->head, 32) == 0 && memcmp(&rep->global, &db->global, sizeof db->global) == 0);
    imdb_close(db);
    imdb_session_init(&g_s, rep);
    imdb_session_copy_io(&g_s, mem_read, mem_write, &g_io);
    EXPECT(copy_out("COPY c TO STDOUT"), want);
    CHECK(run("VERIFY") == 0);
    imdb_session_close(&g_s);
    imdb_close(rep);
    free(g_io.out);
    g_io.out = NULL;
}

static void t_copy_query(void)
{
    imdb_db *db = open_fresh();
    CHECK(db);
    CHECK(run("CREATE TABLE q (id INT64 PRIMARY KEY, g INT64, s TEXT NULL)") == 0 &&
          run("INSERT INTO q VALUES (1, 1, 'a'), (2, 1, NULL), (3, 2, 'c,d'), (4, 2, '')") == 0);
    EXPECT(copy_out("COPY (SELECT id, s FROM q WHERE id > 1 ORDER BY id DESC) TO STDOUT (HEADER)"),
           "id,s\n4,\"\"\n3,\"c,d\"\n2,\n");
    EXPECT(copy_out("COPY (SELECT g, COUNT(*) AS n, MIN(s) AS lo FROM q GROUP BY g ORDER BY g) TO STDOUT (HEADER)"),
           "g,n,lo\n1,2,a\n2,2,\"\"\n");
    EXPECT(copy_out("COPY (WITH w AS (SELECT id FROM q WHERE g = 2) SELECT id * 10 AS t FROM w ORDER BY t) TO STDOUT"), "30\n40\n");
    EXPECT(copy_out("COPY q (s, id) TO STDOUT"), "a,1\n,2\n\"c,d\",3\n\"\",4\n"); /* key order */
    EXPECT(csv("COPY (SELECT nosuch FROM q) TO STDOUT"), "ERR nosuch");
    /* a read: no commit, and SET min_commit holds it as it holds a SELECT */
    uint64_t seq = db->seq;
    CHECK(strncmp(copy_out("COPY q TO STDOUT"), "ERR", 3) != 0 && db->seq == seq);
    CHECK(run("SET min_commit = 1000") == 0);
    EXPECT(csv("COPY q TO STDOUT"), "ERR the session requires commit 1000");
    CHECK(run("SET min_commit = 0") == 0);
    done(db);
}

static void t_copy_cancel(void)
{
    imdb_db *db = open_fresh();
    CHECK(db);
    CHECK(run("CREATE TABLE k (id INT64 PRIMARY KEY, v INT64)") == 0);
    size_t n = 0;
    for (int i = 1; i <= 5000; i++) n += (size_t)snprintf(g_batch + n, sizeof g_batch - n, "%d,%d\n", i, i);
    g_io.cancel_at = n / 2;
    const char *got = copy_in("COPY k FROM STDIN", g_batch, n, 512);
    g_io.cancel_at = 0;
    CHECK(!strncmp(got, "ERR ", 4) && strstr(got, "cancel") != NULL);
    EXPECT(csv("SELECT COUNT(*) FROM k"), "count\n0\n");
    EXPECT(copy_in("COPY k FROM STDIN", g_batch, n, 0), "COPY 5000");
    CHECK(run("VERIFY") == 0);
    done(db);
}

static void t_copy_forms(void)
{
    imdb_db *db = open_fresh();
    CHECK(db);
    CHECK(run("CREATE TABLE f (id INT64 PRIMARY KEY, s TEXT NOT NULL)") == 0);
    EXPECT(csv("COPY f FROM 'data.csv'"), "ERR expected STDIN (COPY reads the client's stream; no file names)");
    EXPECT(csv("COPY f TO '/tmp/out.csv'"), "ERR expected STDOUT (COPY writes to the client's stream; no file names)");
    EXPECT(csv("COPY (SELECT 1) FROM STDIN"), "ERR expected TO STDOUT after COPY's query");
    EXPECT(csv("COPY f FROM STDIN (FORMAT text)"), "ERR expected CSV after FORMAT (the one format)");
    EXPECT(csv("COPY f FROM STDIN (HEADER, HEADER)"), "ERR a COPY option given twice");
    EXPECT(csv("COPY f FROM STDIN (QUOTE '\"')"), "ERR expected a COPY option");
    EXPECT(csv("COPY f FROM STDIN (DELIMITER '\"')"), "ERR COPY's DELIMITER is one ASCII byte, not a quote, CR or LF");
    EXPECT(csv("COPY f FROM STDIN (DELIMITER 'ab')"), "ERR COPY's DELIMITER is one ASCII byte");
    EXPECT(csv("COPY f FROM STDIN WITH"), "ERR expected ( after WITH");
    EXPECT(csv("COPY f FROM STDIN (SKIP 1, FORMAT CSV, HEADER FALSE, DELIMITER '|')"), "COPY 0");
    EXPECT(csv("COPY nosuch FROM STDIN"), "ERR no table nosuch");
    EXPECT(csv("COPY f (id, nope) FROM STDIN"), "ERR no column nope in table f");
    EXPECT(csv("COPY f (id) FROM STDIN"), "ERR column s needs a value: it is NOT NULL");
    EXPECT(csv("COPY f (id, id) FROM STDIN"), "ERR column id listed twice");
    EXPECT(csv("PREPARE p AS COPY f TO STDOUT"), "ERR ");
    EXPECT(csv("EXPLAIN COPY f TO STDOUT"), "ERR ");
    CHECK(imdb_copy_in_stmt("COPY f FROM STDIN;", 18) && imdb_copy_in_stmt("copy f (id, s) from stdin with (header)", 39));
    CHECK(!imdb_copy_in_stmt("COPY f TO STDOUT", 16) && !imdb_copy_in_stmt("SELECT 1", 8) && !imdb_copy_in_stmt("COPY f FROM", 11));
    /* a session with no stream */
    imdb_session_copy_io(&g_s, NULL, NULL, NULL);
    EXPECT(csv("COPY f FROM STDIN"), "ERR COPY ... FROM STDIN reads the client's stream, and this session has none");
    EXPECT(csv("COPY f TO STDOUT"), "ERR COPY ... TO STDOUT writes the client's stream, and this session has none");
    done(db);
}

const test_case copy_tests[] = {
    {"copy_round_trip", t_copy_round_trip},
    {"copy_refusals", t_copy_refusals},
    {"copy_batch", t_copy_batch},
    {"copy_txn", t_copy_txn},
    {"copy_replica", t_copy_replica},
    {"copy_query", t_copy_query},
    {"copy_cancel", t_copy_cancel},
    {"copy_forms", t_copy_forms},
};
const size_t copy_ntests = sizeof copy_tests / sizeof copy_tests[0];
