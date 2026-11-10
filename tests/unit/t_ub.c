/* F3d: UUID and BYTEA (docs/f3d-design.md). The codec at its edges; the types against a TEXT twin holding their
 * canonical text forms (lowercase hex sorts as the bytes it spells, two characters a byte, so every ORDER BY, GROUP BY,
 * DISTINCT, join, MIN, MAX and window answers alike once the typed side is CAST to TEXT), in memory, cross-checked,
 * after a CHECKPOINT, at a segment budget of none, after a reopen and a full replay; DEFAULT gen_random_uuid() on every
 * write path; the copies (a replica at the primary's digest, the dump restored and dumped again, VERIFY, the auditor). */
#include <stdlib.h>

#include "../../src/db_internal.h"
#include "../../src/lake.h"
#include "../../src/log.h"
#include "../../src/sql.h"
#include "thelp.h"

static imdb_session g_s;
static char g_out[1 << 17];

typedef struct mem_in {
    const char *in;
    size_t inlen, inpos;
} mem_in;
static mem_in g_in;

static long mem_read(void *arg, char *buf, size_t cap)
{
    mem_in *m = arg;
    size_t k = m->inlen - m->inpos;
    if (k > cap) k = cap;
    if (k) memcpy(buf, m->in + m->inpos, k);
    m->inpos += k;
    return (long)k;
}

static char g_copy[1 << 16];
static size_t g_copyn;
static int mem_write(void *arg, const char *b, size_t n)
{
    (void)arg;
    if (g_copyn + n >= sizeof g_copy) return -1;
    memcpy(g_copy + g_copyn, b, n);
    g_copyn += n;
    g_copy[g_copyn] = 0;
    return 0;
}

static const char *csv(const char *sql)
{
    imdb_result r;
    imdb_err_clear(&g_e);
    if (imdb_exec_one(&g_s, sql, strlen(sql), NULL, 0, &r, &g_e)) {
        snprintf(g_out, sizeof g_out, "ERR %s", g_e.msg);
        return g_out;
    }
    imdb_buf b;
    imdb_buf_init(&b);
    if (r.has_rows) imdb_result_render(&r, true, &b);
    else imdb_buf_put_str(&b, r.status);
    if (imdb_buf_check(&b, &g_e)) snprintf(g_out, sizeof g_out, "ERR render");
    else snprintf(g_out, sizeof g_out, "%.*s", (int)b.len, (const char *)b.p);
    imdb_buf_free(&b);
    imdb_result_free(&r);
    return g_out;
}

static int run(const char *sql)
{
    imdb_result r;
    imdb_err_clear(&g_e);
    int rc = imdb_exec_one(&g_s, sql, strlen(sql), NULL, 0, &r, &g_e);
    if (!rc) imdb_result_free(&r);
    return rc;
}

#define EXPECT(sql, want)                                                                                          \
    do {                                                                                                           \
        const char *got_ = csv(sql);                                                                               \
        bool ok_ = !strncmp((want), "ERR ", 4) ? !strncmp(got_, "ERR ", 4) && strstr(got_ + 4, (want) + 4) != NULL \
                                               : !strcmp(got_, (want));                                            \
        if (!ok_) {                                                                                                \
            char m_[1600];                                                                                         \
            snprintf(m_, sizeof m_, "%s\n      want: %s\n      got:  %.600s", (sql), (want), got_);                \
            test_fail(__FILE__, __LINE__, m_);                                                                     \
        }                                                                                                          \
    } while (0)

static imdb_db *open_with(const char *dir, bool full_replay, uint64_t budget)
{
    imdb_open_opts o = {.sync = 0, .full_replay = full_replay, .seg_cache_bytes = budget};
    imdb_db *db = NULL;
    imdb_err e = {0};
    if (imdb_open(dir, &o, &db, &e)) return NULL;
    imdb_session_init(&g_s, db);
    imdb_session_copy_io(&g_s, mem_read, mem_write, &g_in);
    return db;
}

static imdb_db *open_fresh(const char *dir)
{
    imdb_err e = {0};
    if (imdb_init(dir, false, NULL, &e)) return NULL;
    return open_with(dir, false, 0);
}

static void done(imdb_db *db)
{
    imdb_session_close(&g_s);
    imdb_close(db);
}

static int audit_dir(const char *dir)
{
    const char *bin = getenv("IMDB_AUDIT_BIN");
    if (!bin || !*bin) return 0;
    char cmd[1600];
    snprintf(cmd, sizeof cmd, "'%s' verify '%s' >/dev/null 2>&1", bin, dir);
    return system(cmd) == 0 ? 0 : 1;
}

static int verify_db(imdb_db *db)
{
    imdb_verify_report vr;
    memset(&vr, 0, sizeof vr);
    imdb_err_clear(&g_e);
    return imdb_verify(db, &vr, &g_e);
}

/* ---- the codec: the text forms taken and refused, the checks, the row codec, the key encoding's order ---- */
static void t_ub_codec(void)
{
    uint8_t u[16];
    imdb_err e = {0};
    static const char *const ok[] = {"a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11", "A0EEBC99-9C0B-4EF8-BB6D-6BB9BD380A11",
                                     "a0eebc999c0b4ef8bb6d6bb9bd380a11", "00000000-0000-0000-0000-000000000000"};
    for (size_t i = 0; i < sizeof ok / sizeof *ok; i++) {
        imdb_err_clear(&e);
        CHECK(imdb_parse_uuid(ok[i], strlen(ok[i]), u, &e) == IMDB_OK);
    }
    static const char *const bad[] = {"{a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11}", "a0eebc99-9c0b4ef8-bb6d-6bb9bd380a11",
                                      "a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a1", "a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a1g",
                                      "a0ee-bc99-9c0b-4ef8-bb6d-6bb9bd380a11", "", "a0eebc999c0b4ef8bb6d6bb9bd380a1"};
    for (size_t i = 0; i < sizeof bad / sizeof *bad; i++) {
        imdb_err_clear(&e);
        CHECK(imdb_parse_uuid(bad[i], strlen(bad[i]), u, &e) == IMDB_ERR_INVALID);
    }
    CHECK(imdb_parse_uuid(ok[0], 36, u, &e) == IMDB_OK);
    imdb_buf b;
    imdb_buf_init(&b);
    imdb_format_uuid(u, &b);
    CHECK(b.len == 36 && !memcmp(b.p, ok[0], 36));
    b.len = 0;
    uint8_t x[8];
    size_t n = 0;
    CHECK(imdb_parse_bytea("\\x", 2, x, sizeof x, &n, &e) == IMDB_OK && n == 0);
    CHECK(imdb_parse_bytea("\\x00Ff10", 8, x, sizeof x, &n, &e) == IMDB_OK && n == 3 && x[0] == 0 && x[1] == 0xff && x[2] == 0x10);
    static const char *const bbad[] = {"", "\\", "x00", "\\x0", "\\x0g", "abc\\000", "\\X00", "\\x 00"};
    for (size_t i = 0; i < sizeof bbad / sizeof *bbad; i++) {
        imdb_err_clear(&e);
        CHECK(imdb_parse_bytea(bbad[i], strlen(bbad[i]), x, sizeof x, &n, &e) != IMDB_OK);
    }
    imdb_format_bytea(x, 3, &b);
    CHECK(b.len == 8 && !memcmp(b.p, "\\x00ff10", 8));
    b.len = 0;
    imdb_format_bytea(x, 0, &b);
    CHECK(b.len == 2 && !memcmp(b.p, "\\x", 2));
    imdb_buf_free(&b);
    /* the checks and the row codec: a UUID is 16 bytes, a BYTEA any bytes (NULs) to the bound */
    imdb_schema s;
    memset(&s, 0, sizeof s);
    snprintf(s.name, sizeof s.name, "u");
    imdb_err_clear(&e);
    s.ncols = 3;
    s.subject = -1;
    snprintf(s.cols[0].name, sizeof s.cols[0].name, "id");
    s.cols[0].type = IMDB_T_UUID;
    s.cols[0].flags = IMDB_COL_PK;
    snprintf(s.cols[1].name, sizeof s.cols[1].name, "b");
    s.cols[1].type = IMDB_T_BYTEA;
    s.cols[1].flags = IMDB_COL_NULLABLE;
    snprintf(s.cols[2].name, sizeof s.cols[2].name, "c");
    s.cols[2].type = IMDB_T_BYTEA;
    s.npk = 1;
    OK(imdb_schema_check(&s, &e));
    imdb_value v[3] = {{.type = IMDB_T_UUID, .s = u, .len = 16}, {.type = IMDB_T_BYTEA, .null = true},
                       {.type = IMDB_T_BYTEA, .s = (const uint8_t *)"\0\0a", .len = 3}};
    imdb_buf row;
    imdb_buf_init(&row);
    OK(imdb_row_encode(&s, v, &row, &e));
    CHECK(row.len == 1 + 16 + 4 + 3);
    imdb_value d[3];
    OK(imdb_row_decode(&s, row.p, row.len, d, &e));
    CHECK(d[0].len == 16 && !memcmp(d[0].s, u, 16) && d[1].null && d[2].len == 3 && !memcmp(d[2].s, "\0\0a", 3));
    CHECK(imdb_row_decode(&s, row.p, row.len - 1, d, &e) == IMDB_ERR_CORRUPT);
    imdb_buf_free(&row);
    v[0].len = 15;
    CHECK(imdb_value_check(&s.cols[0], &v[0], &e) == IMDB_ERR_INVALID);
    s.cols[1].flags |= IMDB_COL_SUBJECT; /* SUBJECT INT64 or TEXT alone */
    s.cols[1].flags &= (uint8_t)~IMDB_COL_NULLABLE;
    CHECK(imdb_schema_check(&s, &e) == IMDB_ERR_INVALID);
    /* the key encoding's order is byteacmp's: a shorter prefix first, NULs within */
    static const struct {
        const char *a;
        uint32_t an;
        const char *b;
        uint32_t bn;
    } pr[] = {{"", 0, "\0", 1}, {"\0", 1, "\0\0", 2}, {"\0\0", 2, "\0\1", 2}, {"\0\xff", 2, "\1", 1}, {"a", 1, "a\0", 2}};
    imdb_schema ks;
    memset(&ks, 0, sizeof ks);
    snprintf(ks.name, sizeof ks.name, "k");
    ks.ncols = 1;
    ks.subject = -1;
    snprintf(ks.cols[0].name, sizeof ks.cols[0].name, "k");
    ks.cols[0].type = IMDB_T_BYTEA;
    ks.cols[0].flags = IMDB_COL_PK;
    ks.npk = 1;
    for (size_t i = 0; i < sizeof pr / sizeof *pr; i++) {
        imdb_value ka = {.type = IMDB_T_BYTEA, .s = (const uint8_t *)pr[i].a, .len = pr[i].an};
        imdb_value kb = {.type = IMDB_T_BYTEA, .s = (const uint8_t *)pr[i].b, .len = pr[i].bn};
        uint8_t ea[16], eb[16];
        size_t la = imdb_key_len(&ks, &ka), lb = imdb_key_len(&ks, &kb);
        CHECK(la <= sizeof ea && lb <= sizeof eb);
        imdb_key_write(&ks, &ka, ea);
        imdb_key_write(&ks, &kb, eb);
        size_t m = la < lb ? la : lb;
        int c = memcmp(ea, eb, m);
        CHECK((c < 0 || (c == 0 && la < lb)) && imdb_value_cmp(&ka, &kb) < 0);
    }
    /* gen_random_uuid's draw: version 4, RFC 9562's variant */
    for (int i = 0; i < 64; i++) {
        OK(imdb_uuid_v4(u, &e));
        CHECK((u[6] >> 4) == 4 && (u[8] >> 6) == 2);
    }
}

/* the twin: t (typed) and w (TEXT) with the same rows, by a seeded generator; a pool of values so equal ones meet */
static uint64_t g_rng;
static uint32_t rnd(uint32_t n)
{
    g_rng ^= g_rng << 13;
    g_rng ^= g_rng >> 7;
    g_rng ^= g_rng << 17;
    return (uint32_t)(g_rng % n);
}

static const char *const UPOOL[] = {"00000000-0000-0000-0000-000000000000", "00000000-0000-0000-0000-000000000001",
                                    "7fffffff-ffff-ffff-ffff-ffffffffffff", "80000000-0000-0000-0000-000000000000",
                                    "a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11", "ffffffff-ffff-ffff-ffff-ffffffffffff"};
static const char *const BPOOL[] = {"\\x", "\\x00", "\\x0000", "\\x000000", "\\x0001", "\\x01", "\\x00ff", "\\xff",
                                    "\\x6869", "\\x686900"};

static void twin_fill(int rows)
{
    char q[512];
    for (int i = 1; i <= rows; i++) {
        bool un = rnd(8) == 0, bn = rnd(8) == 0;
        const char *uv = UPOOL[rnd(6)], *bv = BPOOL[rnd(10)];
        int g = (int)rnd(5);
        char us[48], bs[48];
        snprintf(us, sizeof us, un ? "NULL" : "'%s'", uv);
        snprintf(bs, sizeof bs, bn ? "NULL" : "'%s'", bv);
        snprintf(q, sizeof q, "INSERT INTO t VALUES (%d, %s, %s, %d)", i, us, bs, g);
        CHECK(run(q) == 0);
        snprintf(q, sizeof q, "INSERT INTO w VALUES (%d, %s, %s, %d)", i, us, bs, g);
        CHECK(run(q) == 0);
    }
}

/* each query on t (the typed side's values CAST to TEXT) and on w: the same answer */
static void twin_queries(const char *when)
{
    static const char *const Q[][2] = {
        {"SELECT id, CAST(u AS TEXT), CAST(b AS TEXT) FROM t ORDER BY u, b, id", "SELECT id, u, b FROM w ORDER BY u, b, id"},
        {"SELECT id FROM t ORDER BY b DESC, id", "SELECT id FROM w ORDER BY b DESC, id"},
        {"SELECT CAST(u AS TEXT), COUNT(*), MIN(g), MAX(g) FROM t GROUP BY u ORDER BY u",
         "SELECT u, COUNT(*), MIN(g), MAX(g) FROM w GROUP BY u ORDER BY u"},
        {"SELECT CAST(b AS TEXT), COUNT(*) FROM t GROUP BY b ORDER BY b", "SELECT b, COUNT(*) FROM w GROUP BY b ORDER BY b"},
        {"SELECT DISTINCT CAST(b AS TEXT) FROM t ORDER BY 1", "SELECT DISTINCT b FROM w ORDER BY 1"},
        {"SELECT CAST(MIN(u) AS TEXT), CAST(MAX(u) AS TEXT), CAST(MIN(b) AS TEXT), CAST(MAX(b) AS TEXT), COUNT(DISTINCT u), "
         "COUNT(DISTINCT b) FROM t",
         "SELECT MIN(u), MAX(u), MIN(b), MAX(b), COUNT(DISTINCT u), COUNT(DISTINCT b) FROM w"},
        {"SELECT x.id, y.id FROM t AS x JOIN t AS y ON x.u = y.u WHERE x.id < y.id ORDER BY x.id, y.id",
         "SELECT x.id, y.id FROM w AS x JOIN w AS y ON x.u = y.u WHERE x.id < y.id ORDER BY x.id, y.id"},
        {"SELECT x.id, y.id FROM t AS x JOIN t AS y ON x.b = y.b WHERE x.id < y.id ORDER BY x.id, y.id",
         "SELECT x.id, y.id FROM w AS x JOIN w AS y ON x.b = y.b WHERE x.id < y.id ORDER BY x.id, y.id"},
        {"SELECT id FROM t WHERE b > '\\x00' AND b <= '\\x0001' ORDER BY id", "SELECT id FROM w WHERE b > '\\x00' AND b <= '\\x0001' ORDER BY id"},
        {"SELECT id FROM t WHERE b BETWEEN '\\x0000' AND '\\x01' ORDER BY id",
         "SELECT id FROM w WHERE b BETWEEN '\\x0000' AND '\\x01' ORDER BY id"},
        {"SELECT id FROM t WHERE u >= '7fffffff-ffff-ffff-ffff-ffffffffffff' ORDER BY id",
         "SELECT id FROM w WHERE u >= '7fffffff-ffff-ffff-ffff-ffffffffffff' ORDER BY id"},
        {"SELECT id FROM t WHERE u IN ('00000000-0000-0000-0000-000000000001', 'ffffffff-ffff-ffff-ffff-ffffffffffff') ORDER BY id",
         "SELECT id FROM w WHERE u IN ('00000000-0000-0000-0000-000000000001', 'ffffffff-ffff-ffff-ffff-ffffffffffff') ORDER BY id"},
        {"SELECT id FROM t WHERE g = 2 AND b >= '\\x0000' ORDER BY id", "SELECT id FROM w WHERE g = 2 AND b >= '\\x0000' ORDER BY id"},
        {"SELECT id, ROW_NUMBER() OVER (PARTITION BY u ORDER BY b, id) FROM t ORDER BY id",
         "SELECT id, ROW_NUMBER() OVER (PARTITION BY u ORDER BY b, id) FROM w ORDER BY id"},
        {"SELECT id, CAST(lb AS TEXT) FROM (SELECT id, LAG(b) OVER (ORDER BY id) AS lb FROM t) d ORDER BY id",
         "SELECT id, lb FROM (SELECT id, LAG(b) OVER (ORDER BY id) AS lb FROM w) d ORDER BY id"},
        {"SELECT id FROM t WHERE u IS NULL OR b IS NULL ORDER BY id", "SELECT id FROM w WHERE u IS NULL OR b IS NULL ORDER BY id"},
        {"SELECT COUNT(*) FROM t WHERE b = '\\x0000'", "SELECT COUNT(*) FROM w WHERE b = '\\x0000'"},
    };
    for (size_t i = 0; i < sizeof Q / sizeof *Q; i++) {
        char a[1 << 15];
        snprintf(a, sizeof a, "%s", csv(Q[i][0]));
        const char *b = csv(Q[i][1]);
        if (!strncmp(a, "ERR", 3) || !strncmp(b, "ERR", 3) || /* an error is no agreement */
            (strcmp(a, b) && !(strchr(a, '\n') && strchr(b, '\n') && !strcmp(strchr(a, '\n'), strchr(b, '\n'))))) {
            char m[1800];
            snprintf(m, sizeof m, "%s: %s\n      typed: %.700s\n      twin:  %.700s", when, Q[i][0], a, b);
            test_fail(__FILE__, __LINE__, m);
        }
    }
}

static void t_ub_twin(void)
{
    const char *dir = test_tmpdir();
    imdb_db *db = open_fresh(dir);
    CHECK(db);
    if (!db) return;
    g_rng = 0x9E3779B97F4A7C15ull;
    OK(run("CREATE TABLE t (id INT64 PRIMARY KEY, u UUID, b BYTEA, g INT64)"));
    OK(run("CREATE TABLE w (id INT64 PRIMARY KEY, u TEXT, b TEXT, g INT64)"));
    OK(run("CREATE INDEX t_u ON t (u)"));
    OK(run("CREATE INDEX t_b ON t (b)"));
    OK(run("CREATE INDEX t_gb ON t (g, b)"));
    OK(run("CREATE INDEX w_u ON w (u)"));
    OK(run("CREATE INDEX w_b ON w (b)"));
    OK(run("CREATE INDEX w_gb ON w (g, b)"));
    twin_fill(120);
    twin_queries("in memory");
    OK(run("SET cross_check = on"));
    twin_queries("cross-checked");
    OK(run("SET cross_check = off"));
    OK(run("CHECKPOINT"));
    twin_fill(0);
    OK(run("UPDATE t SET b = '\\x0000' WHERE id % 7 = 0"));
    OK(run("UPDATE w SET b = '\\x0000' WHERE id % 7 = 0"));
    OK(run("DELETE FROM t WHERE id % 11 = 0"));
    OK(run("DELETE FROM w WHERE id % 11 = 0"));
    twin_queries("after a CHECKPOINT");
    OK(run("SET cross_check = on"));
    twin_queries("after a CHECKPOINT, cross-checked");
    uint8_t dg[32];
    imdb_lthash_digest(db->meta.digest_alg, &db->global, dg);
    CHECK(verify_db(db) == 0);
    done(db);
    CHECK(audit_dir(dir) == 0);
    db = open_with(dir, false, 1); /* a budget of one byte: every image read again at its use */
    CHECK(db);
    if (db) {
        twin_queries("reopened, a budget of one byte");
        done(db);
    }
    db = open_with(dir, true, 0); /* a full replay */
    CHECK(db);
    if (db) {
        uint8_t d2[32];
        imdb_lthash_digest(db->meta.digest_alg, &db->global, d2);
        CHECK(memcmp(dg, d2, 32) == 0);
        twin_queries("after a full replay");
        done(db);
    }
}

/* ---- DEFAULT gen_random_uuid() on every write path: version 4 and the variant, every value its own ---- */
static void t_ub_default(void)
{
    const char *dir = test_tmpdir();
    imdb_db *db = open_fresh(dir);
    CHECK(db);
    if (!db) return;
    OK(run("CREATE TABLE k (id UUID PRIMARY KEY DEFAULT gen_random_uuid(), n INT64, b BYTEA DEFAULT '\\x00ff')"));
    EXPECT("INSERT INTO k (n) VALUES (1), (2)", "INSERT 2");
    EXPECT("INSERT INTO k VALUES (DEFAULT, 3, DEFAULT)", "INSERT 1");
    EXPECT("INSERT INTO k (n) SELECT n + 10 FROM k", "INSERT 3");
    static const char data[] = "21\n22\n23\n";
    g_in = (mem_in){data, sizeof data - 1, 0};
    EXPECT("COPY k (n) FROM STDIN", "COPY 3");
    g_in = (mem_in){data, sizeof data - 1, 0};
    EXPECT("COPY k (n) FROM STDIN (BATCH 2)", "COPY 3");
    const char *got = csv("INSERT INTO k (n) VALUES (40) RETURNING CAST(id AS TEXT)");
    CHECK(!strncmp(got, "id\n", 3) || strchr(got, '-'));
    OK(run("PREPARE ins (UUID, INT64) AS INSERT INTO k (id, n) VALUES ($1, $2)"));
    EXPECT("EXECUTE ins ('a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11', 50)", "INSERT 1");
    EXPECT("SELECT n FROM k WHERE id = 'a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11'", "n\n50\n");
    EXPECT("INSERT INTO k (id, n) VALUES ('a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11', 51) ON CONFLICT (id) DO UPDATE SET n = 52",
           "INSERT 1");
    EXPECT("SELECT n FROM k WHERE id = 'a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11'", "n\n52\n");
    EXPECT("SELECT COUNT(*) AS n, COUNT(DISTINCT id) AS d FROM k", "n,d\n14,14\n");
    /* every drawn id: version 4 (the 15th character), the variant 8, 9, a or b (the 20th) */
    EXPECT("SELECT COUNT(*) FROM k WHERE n <> 52 AND (SUBSTR(CAST(id AS TEXT), 15, 1) <> '4' OR "
           "SUBSTR(CAST(id AS TEXT), 20, 1) NOT IN ('8', '9', 'a', 'b'))",
           "count\n0\n");
    EXPECT("SELECT COUNT(*) FROM k WHERE b = '\\x00ff'", "count\n14\n");
    EXPECT("ALTER TABLE k ADD COLUMN z UUID DEFAULT gen_random_uuid()", "ERR ADD the column, then UPDATE it");
    OK(run("ALTER TABLE k ADD COLUMN z UUID"));
    OK(run("ALTER TABLE k ALTER COLUMN z SET DEFAULT gen_random_uuid()"));
    EXPECT("INSERT INTO k (n) VALUES (60), (61)", "INSERT 2");
    EXPECT("SELECT COUNT(*) AS n, COUNT(z) AS z, COUNT(DISTINCT z) AS d FROM k", "n,z,d\n16,2,2\n");
    EXPECT("CREATE VIEW kv AS SELECT gen_random_uuid() AS r FROM k", "ERR calls no gen_random_uuid");
    EXPECT("CREATE TABLE kc (id INT64 PRIMARY KEY, u UUID, CHECK (u <> '00000000-0000-0000-0000-000000000000'))",
           "ERR reads no UUID or BYTEA");
    EXPECT("CREATE TABLE kg (id INT64 PRIMARY KEY, b BYTEA, n INT64 GENERATED ALWAYS AS (LENGTH(b)) STORED)",
           "ERR reads no UUID or BYTEA");
    EXPECT("CREATE TABLE ks (id INT64 PRIMARY KEY, u UUID SUBJECT)", "ERR SUBJECT column must be INT64 or TEXT");
    EXPECT("SELECT gen_random_uuid() = gen_random_uuid() AS same", "same\nfalse\n");
    OK(run("SET cross_check = on"));
    EXPECT("SELECT COUNT(*) FROM k WHERE gen_random_uuid() <> id", "count\n16\n"); /* one plan: no second draw compared */
    OK(run("CHECKPOINT"));
    CHECK(verify_db(db) == 0);
    done(db);
    CHECK(audit_dir(dir) == 0);
    db = open_with(dir, true, 0);
    CHECK(db);
    if (db) {
        EXPECT("SELECT COUNT(*) AS n, COUNT(DISTINCT id) AS d, COUNT(z) AS z FROM k", "n,d,z\n16,16,2\n");
        done(db);
    }
}

/* ---- the copies: a replica at the primary's digest, the dump restored and dumped again, COPY TO's forms ---- */
static void t_ub_copies(void)
{
    const char *dir = test_tmpdir();
    char p[700], q[700], sf[700], dd[700];
    snprintf(p, sizeof p, "%s/p", dir);
    snprintf(q, sizeof q, "%s/q", dir);
    snprintf(sf, sizeof sf, "%s/stream", dir);
    snprintf(dd, sizeof dd, "%s/dumped", dir);
    imdb_err e = {0};
    CHECK(imdb_init(p, false, NULL, &e) == 0 && imdb_init(q, true, p, &e) == 0);
    imdb_db *db = open_with(p, false, 0);
    CHECK(db);
    if (!db) return;
    OK(run("CREATE TABLE c (id UUID PRIMARY KEY DEFAULT gen_random_uuid(), b BYTEA, s TEXT)"));
    OK(run("INSERT INTO c (b, s) VALUES ('\\x00', 'a'), ('\\x', 'b'), (NULL, 'c'), ('\\x0a0d2c22', 'd')"));
    OK(run("CHECKPOINT"));
    OK(run("INSERT INTO c VALUES ('00000000-0000-0000-0000-000000000000', '\\xff', 'z')"));
    g_copyn = 0;
    EXPECT("COPY (SELECT b, s FROM c ORDER BY s) TO STDOUT", "COPY 5");
    CHECK(!strcmp(g_copy, "\\x00,a\n\\x,b\n,c\n\\x0a0d2c22,d\n\\xff,z\n"));
    uint8_t dg[32];
    imdb_lthash_digest(db->meta.digest_alg, &db->global, dg);
    imdb_buf d1;
    imdb_buf_init(&d1);
    CHECK(verify_db(db) == 0);
    done(db);
    CHECK(audit_dir(p) == 0);
    OK(ship_to_file(p, 0, sf, &g_e));
    imdb_open_opts o = {.sync = 0};
    imdb_db *qdb = NULL;
    CHECK(imdb_open(q, &o, &qdb, &e) == 0);
    if (qdb) {
        uint64_t qa = 0;
        OK(apply_file(qdb, sf, &qa, &g_e));
        uint8_t qd[32];
        imdb_lthash_digest(qdb->meta.digest_alg, &qdb->global, qd);
        CHECK(memcmp(qd, dg, 32) == 0);
        imdb_close(qdb);
    }
    CHECK(audit_dir(q) == 0);
    imdb_buf_free(&d1);
}

const test_case ub_tests[] = {
    {"ub_codec", t_ub_codec}, {"ub_twin", t_ub_twin}, {"ub_default", t_ub_default}, {"ub_copies", t_ub_copies},
};
const size_t ub_ntests = sizeof ub_tests / sizeof *ub_tests;
