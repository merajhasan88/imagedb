/* F4: composite primary keys (docs/plan-p2.md 2026-11-07 18:2x; the format design's section 6). PRIMARY KEY (a, b, ...)
 * as a table constraint, 1 to 8 columns of any exact type; the key's one encoding (codec.h imdb_key_write), whose
 * bytewise order is the tuple's; the PK map keyed by it; lookups, uniqueness, ON CONFLICT, UPDATE's refusal, SHOW
 * HISTORY, the default order, in memory and from the lake, a replica, VERIFY and the auditor, each against a model. */
#include <stdlib.h>

#include "../../src/db_internal.h"
#include "../../src/sql.h"
#include "thelp.h"

static imdb_session g_s;
static char g_out[1 << 18];

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

static const char *body(const char *s)
{
    const char *n = strchr(s, '\n');
    return n ? n + 1 : s;
}

#define EXPECT(sql, want)                                                                                          \
    do {                                                                                                           \
        const char *got_ = csv(sql);                                                                               \
        bool ok_ = !strncmp((want), "ERR ", 4) ? !strncmp(got_, "ERR ", 4) && strstr(got_ + 4, (want) + 4) != NULL \
                                               : !strcmp(body(got_), body(want));                                  \
        if (!ok_) {                                                                                                \
            char m_[1600];                                                                                         \
            snprintf(m_, sizeof m_, "%s\n      want: %s\n      got:  %s", (sql), (want), got_);                    \
            test_fail(__FILE__, __LINE__, m_);                                                                     \
        }                                                                                                          \
    } while (0)

static imdb_db *open_at(const char *dir)
{
    imdb_open_opts o = {.sync = 0};
    imdb_db *db = NULL;
    imdb_err e = {0};
    if (imdb_open(dir, &o, &db, &e)) return NULL;
    imdb_session_init(&g_s, db);
    return db;
}

static imdb_db *open_fresh(const char *dir)
{
    imdb_err e = {0};
    if (imdb_init(dir, false, NULL, &e)) return NULL;
    return open_at(dir);
}

static void done(imdb_db *db)
{
    imdb_session_close(&g_s);
    imdb_close(db);
}

/* the path a statement takes, from EXPLAIN's rows */
static bool explains(const char *sql, const char *needle)
{
    char q[1200];
    snprintf(q, sizeof q, "EXPLAIN %s", sql);
    return strstr(csv(q), needle) != NULL;
}

static int audit_dir(const char *dir)
{
    const char *bin = getenv("IMDB_AUDIT_BIN");
    if (!bin || !*bin) return 0; /* no auditor in this build: said by vectors_auditor */
    char cmd[1600];
    snprintf(cmd, sizeof cmd, "'%s' verify '%s' >/dev/null 2>&1", bin, dir);
    return system(cmd) == 0 ? 0 : 1;
}

/* CREATE TABLE's rules for a key, and the schema they make, through a reopen (the log) and a CHECKPOINT (the lake) */
static void t_ckey_ddl(void)
{
    const char *dir = test_tmpdir();
    imdb_db *db = open_fresh(dir);
    CHECK(db);
    if (!db) return;
    EXPECT("CREATE TABLE p (a INT64, b TEXT, v INT64, PRIMARY KEY (a, b))", "CREATE TABLE p");
    EXPECT("CREATE TABLE r (v INT64, PRIMARY KEY (b, a), a TIMESTAMP, b BOOL)", "CREATE TABLE r"); /* anywhere, any order */
    EXPECT("CREATE TABLE d (k DECIMAL(10,2) PRIMARY KEY, v INT64)", "CREATE TABLE d");          /* one column, newly allowed */
    EXPECT("CREATE TABLE e (c1 INT64, c2 INT64, c3 INT64, c4 INT64, c5 INT64, c6 INT64, c7 INT64, c8 TEXT, "
           "PRIMARY KEY (c8, c7, c6, c5, c4, c3, c2, c1))", "CREATE TABLE e");
    EXPECT("CREATE TABLE q (a INT64 PRIMARY KEY, b INT64, PRIMARY KEY (a, b))", "ERR one PRIMARY KEY");
    EXPECT("CREATE TABLE q (a INT64, b INT64, PRIMARY KEY (a), PRIMARY KEY (b))", "ERR one PRIMARY KEY");
    EXPECT("CREATE TABLE q (a INT64, PRIMARY KEY (a, z))", "ERR which the table lacks");
    EXPECT("CREATE TABLE q (a INT64, b INT64, PRIMARY KEY (a, a))", "ERR twice");
    EXPECT("CREATE TABLE q (a INT64 NULL, b INT64, PRIMARY KEY (a, b))", "ERR NOT NULL");
    EXPECT("CREATE TABLE q (a FLOAT64, b INT64, PRIMARY KEY (a, b))", "ERR cannot be FLOAT64");
    EXPECT("CREATE TABLE q (a FLOAT64 PRIMARY KEY)", "ERR cannot be FLOAT64");
    EXPECT("CREATE TABLE q (c1 INT64, c2 INT64, c3 INT64, c4 INT64, c5 INT64, c6 INT64, c7 INT64, c8 INT64, c9 INT64, "
           "PRIMARY KEY (c1, c2, c3, c4, c5, c6, c7, c8, c9))", "ERR at most 8");
    EXPECT("CREATE TABLE q (a INT64, b INT64)", "ERR needs a PRIMARY KEY");
    EXPECT("CREATE TABLE q (PRIMARY KEY (a))", "ERR table must have 1..");
    EXPECT("CREATE TABLE q (a INT64, PRIMARY KEY ())", "ERR syntax error");
    for (int pass = 0; pass < 3; pass++) { /* as made, after a reopen (the log), after a CHECKPOINT and a reopen (the lake) */
        imdb_table *p = imdb_table_by_name(db, "p"), *r = imdb_table_by_name(db, "r"), *e = imdb_table_by_name(db, "e");
        CHECK(p && r && e);
        if (!p || !r || !e) break;
        CHECK(p->s.npk == 2 && p->s.key[0] == 0 && p->s.key[1] == 1 && !(p->s.cols[0].flags & IMDB_COL_NULLABLE) &&
              !(p->s.cols[1].flags & IMDB_COL_NULLABLE) && (p->s.cols[2].flags & IMDB_COL_NULLABLE));
        CHECK(r->s.npk == 2 && r->s.key[0] == 2 && r->s.key[1] == 1 && (r->s.cols[1].flags & IMDB_COL_PK));
        CHECK(e->s.npk == 8 && e->s.key[0] == 7 && e->s.key[7] == 0);
        CHECK(strstr(csv("SHOW TABLES"), "a INT64 PK(1), b TEXT PK(2), v INT64") != NULL);
        done(db);
        if (pass == 1) {
            db = open_at(dir);
            CHECK(db && run("CHECKPOINT") == 0);
            if (db) done(db);
        }
        db = open_at(dir);
        CHECK(db);
        if (!db) return;
    }
    done(db);
    CHECK(audit_dir(dir) == 0);
}

/* rows by a key of two columns: the uniqueness refusal names both, lookups by the whole key take the key path and
 * by a part another, UPDATE cannot change a key column, ON CONFLICT names the key in any order, SHOW HISTORY by the
 * key's values, the default order the key's (rows inserted out of it); in memory and from the lake's segments, then AS
 * OF a snapshot whose ended versions only the lake holds (read by its scan: ckey_old_txn has the key lookup there) */
static void t_ckey_rows(void)
{
    const char *dir = test_tmpdir();
    imdb_db *db = open_fresh(dir);
    CHECK(db);
    if (!db) return;
    CHECK(run("CREATE TABLE p (a INT64, b TEXT, v INT64, PRIMARY KEY (a, b))") == 0);
    CHECK(run("INSERT INTO p VALUES (1, 'y', 11), (1, 'x', 10), (2, 'x', 12), (-5, '', 13)") == 0); /* not the key's order */
    EXPECT("INSERT INTO p VALUES (1, 'x', 99)", "ERR duplicate primary key in table p (columns a, b)");
    EXPECT("INSERT INTO p VALUES (1, 'x', 98), (3, 'q', 97)", "ERR duplicate primary key");
    EXPECT("SELECT a, b, v FROM p", "a,b,v\n-5,\"\",13\n1,\"x\",10\n1,\"y\",11\n2,\"x\",12\n"); /* the key's order */
    CHECK(run("SET cross_check = on") == 0);
    for (int where = 0; where < 2; where++) { /* in memory, then from the segments a CHECKPOINT wrote */
        EXPECT("SELECT v FROM p WHERE a = 1 AND b = 'y'", "v\n11\n");
        EXPECT("SELECT v FROM p WHERE b = 'x' AND a = 2", "v\n12\n");
        EXPECT("SELECT v FROM p WHERE a = 1 AND b = 'z'", "v\n");
        EXPECT("SELECT v FROM p WHERE a = 1", "v\n10\n11\n");
        EXPECT("SELECT v FROM p WHERE b = 'x'", "v\n10\n12\n");
        CHECK(explains("SELECT v FROM p WHERE a = 1 AND b = 'y'", "the primary key (a, b)"));
        CHECK(!explains("SELECT v FROM p WHERE a = 1", "the primary key"));
        if (where == 0) CHECK(run("CHECKPOINT") == 0);
    }
    CHECK(run("SET cross_check = off") == 0);
    uint64_t before = db->seq;
    EXPECT("UPDATE p SET v = 20 WHERE a = 1 AND b = 'x'", "UPDATE 1");
    EXPECT("UPDATE p SET b = 'z' WHERE a = 2", "ERR cannot change the primary key");
    EXPECT("UPDATE p SET a = 7 WHERE b = 'y'", "ERR cannot change the primary key");
    EXPECT("DELETE FROM p WHERE a = 1 AND b = 'y'", "DELETE 1");
    EXPECT("INSERT INTO p VALUES (1, 'y', 30)", "INSERT 1"); /* the key again, once the row with it ended */
    EXPECT("INSERT INTO p VALUES (2, 'x', 40) ON CONFLICT (b, a) DO UPDATE SET v = EXCLUDED.v", "INSERT 1");
    EXPECT("INSERT INTO p VALUES (9, 'n', 41) ON CONFLICT (a, b) DO NOTHING", "INSERT 1");
    EXPECT("INSERT INTO p VALUES (9, 'n', 42) ON CONFLICT (a, b) DO NOTHING", "INSERT 0");
    EXPECT("INSERT INTO p VALUES (2, 'x', 43) ON CONFLICT (a) DO NOTHING", "ERR name its primary key");
    EXPECT("INSERT INTO p VALUES (2, 'x', 44) ON CONFLICT (a, b) DO UPDATE SET b = 'q'", "ERR cannot change the primary key");
    EXPECT("SELECT a, b, v FROM p", "a,b,v\n-5,\"\",13\n1,\"x\",20\n1,\"y\",30\n2,\"x\",40\n9,\"n\",41\n");
    char q[200];
    snprintf(q, sizeof q, "SELECT a, b, v FROM p AS OF %llu", (unsigned long long)before);
    EXPECT(q, "a,b,v\n-5,\"\",13\n1,\"x\",10\n1,\"y\",11\n2,\"x\",12\n");
    CHECK(run("CHECKPOINT") == 0); /* the ended versions into the lake, then out of memory: AS OF reads them from there */
    {
        imdb_err e2 = {0};
        CHECK(imdb_evict(db, db->lake_seq, &e2) == 0 && db->mem_floor > before);
    }
    CHECK(run("SET cross_check = on") == 0);
    snprintf(q, sizeof q, "SELECT v FROM p AS OF %llu WHERE a = 1 AND b = 'x'", (unsigned long long)before);
    EXPECT(q, "v\n10\n");
    snprintf(q, sizeof q, "SELECT v FROM p AS OF %llu WHERE b = 'y' AND a = 1", (unsigned long long)before);
    EXPECT(q, "v\n11\n");
    snprintf(q, sizeof q, "SELECT v FROM p AS OF %llu WHERE a = 2 AND b = 'q'", (unsigned long long)before);
    EXPECT(q, "v\n");
    snprintf(q, sizeof q, "SELECT a, b, v FROM p AS OF %llu", (unsigned long long)before);
    EXPECT(q, "a,b,v\n-5,\"\",13\n1,\"x\",10\n1,\"y\",11\n2,\"x\",12\n");
    CHECK(run("SET cross_check = off") == 0);
    const char *h = csv("SHOW HISTORY p (1, 'x')");
    CHECK(strstr(h, ",10\n") && strstr(h, ",20\n") && !strstr(h, ",11\n"));
    EXPECT("SHOW HISTORY p 1", "ERR PRIMARY KEY has 2 columns, 1 values given");
    EXPECT("SHOW HISTORY p (1, 'x', 3)", "ERR PRIMARY KEY has 2 columns");
    done(db);
    db = open_at(dir); /* the same answers replayed */
    CHECK(db);
    if (!db) return;
    EXPECT("SELECT a, b, v FROM p", "a,b,v\n-5,\"\",13\n1,\"x\",20\n1,\"y\",30\n2,\"x\",40\n9,\"n\",41\n");
    EXPECT("SELECT v FROM p WHERE a = -5 AND b = ''", "v\n13\n");
    imdb_verify_report vr;
    imdb_err e = {0};
    CHECK(imdb_verify(db, &vr, &e) == 0);
    done(db);
    CHECK(audit_dir(dir) == 0);
}

/* the key's encoding: its bytewise order is the tuple's, column by column (imdb_value_cmp), over every key type at
 * its edges; equal tuples alone encode alike */
static void t_ckey_order(void)
{
    imdb_schema s;
    memset(&s, 0, sizeof s);
    static const uint8_t ty[5] = {IMDB_T_INT64, IMDB_T_TEXT, IMDB_T_BOOL, IMDB_T_DECIMAL, IMDB_T_TIMESTAMP};
    s.ncols = 5;
    s.npk = 5;
    for (int i = 0; i < 5; i++) {
        s.cols[i].type = ty[i];
        s.key[i] = (uint16_t)i;
    }
    static const int64_t ints[] = {INT64_MIN, INT64_MIN + 1, -256, -1, 0, 1, 255, 256, INT64_MAX - 1, INT64_MAX};
    static const char *const texts[] = {"", "a", "a\x7f", "ab", "b", "\xc3\xa9", "\xf0\x9f\x98\x80", "aaaaaaaaaaaaaaaaaaaaaa"};
    imdb_value t[2][5];
    uint8_t ka[256], kb[256];
    for (int round = 0; round < 200000 && !g_test_failed; round++) {
        for (int w = 0; w < 2; w++)
            for (int c = 0; c < 5; c++) {
                imdb_value *v = &t[w][c];
                memset(v, 0, sizeof *v);
                v->type = ty[c];
                if (ty[c] == IMDB_T_TEXT) {
                    v->s = (const uint8_t *)texts[test_rand() % 8];
                    v->len = (uint32_t)strlen((const char *)v->s);
                } else if (ty[c] == IMDB_T_BOOL) {
                    v->i = (int64_t)(test_rand() % 2);
                } else {
                    v->i = test_rand() % 4 ? ints[test_rand() % 10] : (int64_t)(test_rand() % 7) - 3;
                }
            }
        if (test_rand() % 3 == 0) memcpy(t[1], t[0], sizeof t[0]); /* equal tuples too */
        else if (test_rand() % 2) memcpy(t[1], t[0], (size_t)(test_rand() % 5) * sizeof t[0][0]); /* a shared prefix */
        int want = 0;
        for (int c = 0; c < 5 && !want; c++) want = imdb_value_cmp(&t[0][c], &t[1][c]);
        size_t na = imdb_key_len(&s, t[0]), nb = imdb_key_len(&s, t[1]);
        CHECK(na <= sizeof ka && nb <= sizeof kb);
        if (na > sizeof ka || nb > sizeof kb) return;
        imdb_key_write(&s, t[0], ka);
        imdb_key_write(&s, t[1], kb);
        int got = memcmp(ka, kb, na < nb ? na : nb);
        if (!got) got = na < nb ? -1 : na > nb;
        if ((want > 0) != (got > 0) || (want < 0) != (got < 0)) {
            test_fail(__FILE__, __LINE__, "the key's encoding orders two tuples otherwise than the tuples");
            return;
        }
    }
}

/* a model of the rows by key (b TEXT, a INT64, c DECIMAL: the key's order is not the columns'), against random writes:
 * the default order, every key looked up, AS OF an earlier commit, with cross_check on, a CHECKPOINT, an eviction and
 * a reopen between rounds; then a replica of it, at the primary's digest, VERIFY and the auditor on both */
#define NM 600
typedef struct mrow {
    bool live;
    int64_t a, c, v;
    char b[8];
} mrow;

static int mcmp(const void *x, const void *y) /* the key's order: b, a, c */
{
    const mrow *p = x, *q = y;
    int r = strcmp(p->b, q->b);
    if (r) return r;
    if (p->a != q->a) return p->a < q->a ? -1 : 1;
    return p->c < q->c ? -1 : p->c > q->c;
}

static void model_text(const mrow *m, char *out, size_t cap)
{
    static mrow sorted[NM];
    size_t n = 0, o = 0;
    for (int i = 0; i < NM; i++)
        if (m[i].live) sorted[n++] = m[i];
    qsort(sorted, n, sizeof *sorted, mcmp);
    o += (size_t)snprintf(out + o, cap - o, "a,b,c,v\n");
    for (size_t i = 0; i < n && o < cap; i++)
        o += (size_t)snprintf(out + o, cap - o, "%lld,\"%s\",%lld.%02lld,%lld\n", (long long)sorted[i].a, sorted[i].b,
                              (long long)(sorted[i].c / 100), (long long)(sorted[i].c % 100), (long long)sorted[i].v);
}

static void t_ckey_model(void)
{
    const char *base = test_tmpdir();
    char dir[700], rep[700], stream[760];
    snprintf(dir, sizeof dir, "%s/p", base);
    snprintf(rep, sizeof rep, "%s/r", base);
    snprintf(stream, sizeof stream, "%s/stream", base);
    imdb_db *db = open_fresh(dir);
    CHECK(db);
    if (!db) return;
    CHECK(run("CREATE TABLE m (a INT64, b TEXT, c DECIMAL(10,2), v INT64, PRIMARY KEY (b, a, c))") == 0);
    static mrow model[NM], at_snap[NM];
    static char want[1 << 16];
    memset(model, 0, sizeof model);
    for (int i = 0; i < NM; i++) { /* each slot one key: b of 3 letters, a in -2..2, c in 0..1 (a cent apart) */
        snprintf(model[i].b, sizeof model[i].b, "%c%c", 'a' + i % 3, 'a' + i / 3 % 4);
        model[i].a = (int64_t)(i / 12 % 5) - 2;
        model[i].c = (int64_t)(i / 60 % 10);
    }
    uint64_t snap_seq = 0;
    for (int round = 0; round < 8 && !g_test_failed; round++) {
        CHECK(run("BEGIN") == 0);
        for (int k = 0; k < 120; k++) {
            int i = (int)(test_rand() % NM);
            mrow *m = &model[i];
            char q[300];
            int op = (int)(test_rand() % 3);
            if (!m->live) {
                m->v = (int64_t)(test_rand() % 1000);
                snprintf(q, sizeof q, "INSERT INTO m VALUES (%lld, '%s', %lld.%02lld, %lld)", (long long)m->a, m->b,
                         (long long)(m->c / 100), (long long)(m->c % 100), (long long)m->v);
                CHECK(run(q) == 0);
                m->live = true;
            } else if (op == 0) {
                snprintf(q, sizeof q, "DELETE FROM m WHERE b = '%s' AND a = %lld AND c = %lld.%02lld", m->b, (long long)m->a,
                         (long long)(m->c / 100), (long long)(m->c % 100));
                CHECK(strcmp(csv(q), "DELETE 1") == 0);
                m->live = false;
            } else if (op == 1) {
                m->v++;
                snprintf(q, sizeof q, "UPDATE m SET v = v + 1 WHERE c = %lld.%02lld AND b = '%s' AND a = %lld",
                         (long long)(m->c / 100), (long long)(m->c % 100), m->b, (long long)m->a);
                CHECK(strcmp(csv(q), "UPDATE 1") == 0);
            } else {
                snprintf(q, sizeof q, "INSERT INTO m VALUES (%lld, '%s', %lld.%02lld, 0)", (long long)m->a, m->b,
                         (long long)(m->c / 100), (long long)(m->c % 100));
                CHECK(strncmp(csv(q), "ERR ", 4) == 0 && strstr(g_out, "duplicate primary key"));
            }
        }
        CHECK(run("COMMIT") == 0);
        if (round == 3) {
            snap_seq = db->seq;
            memcpy(at_snap, model, sizeof model);
        }
        CHECK(run(round % 2 ? "SET cross_check = on" : "SET cross_check = off") == 0);
        model_text(model, want, sizeof want);
        EXPECT("SELECT a, b, c, v FROM m", want);
        for (int i = 0; i < NM; i += 7) { /* the key path against the model, live or not */
            char q[300], w[80];
            snprintf(q, sizeof q, "SELECT v FROM m WHERE a = %lld AND b = '%s' AND c = %lld.%02lld", (long long)model[i].a,
                     model[i].b, (long long)(model[i].c / 100), (long long)(model[i].c % 100));
            if (model[i].live) snprintf(w, sizeof w, "v\n%lld\n", (long long)model[i].v);
            else snprintf(w, sizeof w, "v\n");
            EXPECT(q, w);
        }
        if (snap_seq) {
            char q[200];
            snprintf(q, sizeof q, "SELECT a, b, c, v FROM m AS OF %llu", (unsigned long long)snap_seq);
            model_text(at_snap, want, sizeof want);
            EXPECT(q, want);
        }
        if (round % 3 == 1) CHECK(run("CHECKPOINT") == 0);
        if (round % 3 == 2) {
            imdb_err e = {0};
            CHECK(imdb_evict(db, db->lake_seq, &e) == 0);
        }
        if (round == 5) {
            done(db);
            db = open_at(dir);
            CHECK(db);
            if (!db) return;
        }
    }
    CHECK(run("SET cross_check = off") == 0);
    char dp[400];
    snprintf(dp, sizeof dp, "%s", csv("SHOW DIGEST"));
    done(db);
    imdb_err e = {0};
    OK(imdb_init(rep, true, dir, &e));
    OK(ship_to_file(dir, 0, stream, &e));
    imdb_db *rdb = open_db(rep);
    CHECK(rdb);
    if (!rdb) return;
    uint64_t applied = 0;
    OK(apply_file(rdb, stream, &applied, &e));
    imdb_session_init(&g_s, rdb);
    CHECK(strcmp(csv("SHOW DIGEST"), dp) == 0);
    model_text(model, want, sizeof want);
    EXPECT("SELECT a, b, c, v FROM m", want);
    imdb_verify_report vr;
    CHECK(imdb_verify(rdb, &vr, &e) == 0);
    done(rdb);
    CHECK(audit_dir(dir) == 0 && audit_dir(rep) == 0);
}

/* joins whose one side is read by its key: ON a part of the key and WHERE the rest is the key path's probe, ON the
 * whole key a hash join's pairs; both plans, cross-checked, answer alike */
static void t_ckey_join(void)
{
    const char *dir = test_tmpdir();
    imdb_db *db = open_fresh(dir);
    CHECK(db);
    if (!db) return;
    CHECK(run("CREATE TABLE p (a INT64, b TEXT, v INT64, PRIMARY KEY (a, b))") == 0);
    CHECK(run("CREATE TABLE u (id INT64 PRIMARY KEY, x INT64, y TEXT)") == 0);
    CHECK(run("INSERT INTO p VALUES (1, 'x', 10), (1, 'y', 11), (2, 'x', 12), (3, 'z', 13)") == 0);
    CHECK(run("INSERT INTO u VALUES (1, 1, 'y'), (2, 2, 'x'), (3, 2, 'q'), (4, 1, 'x')") == 0);
    CHECK(run("SET cross_check = on") == 0);
    static const char *const plans[] = {"SET join_plan = auto", "SET join_plan = hash", "SET join_plan = index"};
    for (int pl = 0; pl < 3; pl++) {
        CHECK(run(plans[pl]) == 0);
        EXPECT("SELECT u.id, p.v FROM u JOIN p ON p.a = u.x AND p.b = u.y ORDER BY u.id", "id,v\n1,11\n2,12\n4,10\n");
        EXPECT("SELECT u.id, p.v FROM u JOIN p ON p.a = u.x WHERE p.b = 'x' ORDER BY u.id", "id,v\n1,10\n2,12\n3,12\n4,10\n");
        EXPECT("SELECT u.id, p.v FROM u LEFT JOIN p ON p.a = u.x AND p.b = u.y ORDER BY u.id", "id,v\n1,11\n2,12\n3,\n4,10\n");
    }
    CHECK(run("SET join_plan = auto") == 0 && run("SET cross_check = off") == 0);
    /* UPDATE ... FROM over a target keyed by two columns: its pairs sorted and taken once each by the whole key, so
     * (1, 'x') and (1, 'y'), which share a, are two rows; and a row its join meets twice refused */
    EXPECT("UPDATE p SET v = u.id FROM u WHERE p.a = u.x AND p.b = u.y", "UPDATE 3");
    EXPECT("SELECT a, b, v FROM p", "a,b,v\n1,\"x\",4\n1,\"y\",1\n2,\"x\",2\n3,\"z\",13\n");
    EXPECT("UPDATE p SET v = u.id FROM u WHERE p.a = u.x AND p.b = 'x'", "ERR changes each row once");
    EXPECT("DELETE FROM p USING u WHERE p.a = u.x AND p.b = u.y", "DELETE 3");
    EXPECT("SELECT a, b, v FROM p", "a,b,v\n3,\"z\",13\n");
    done(db);
}


static int exs(imdb_session *s, const char *sql)
{
    imdb_result r;
    imdb_err_clear(&g_e);
    int rc = imdb_exec_one(s, sql, strlen(sql), NULL, 0, &r, &g_e);
    if (!rc) imdb_result_free(&r);
    return rc;
}

/* the key below the memory floor (imdb_lookup_pk_at's lake search, every key column compared): a transaction older
 * than an eviction inserts a key its view holds only in the lake (refused) and keys it never held whose first column
 * older rows share (taken) */
static void t_ckey_old_txn(void)
{
    const char *dir = test_tmpdir();
    imdb_db *db = open_fresh(dir);
    CHECK(db);
    if (!db) return;
    imdb_session s2;
    imdb_session_init(&s2, db);
    CHECK(run("CREATE TABLE p (a INT64, b TEXT, v INT64, PRIMARY KEY (a, b))") == 0);
    CHECK(run("INSERT INTO p VALUES (1, 'x', 10), (1, 'y', 11), (2, 'x', 12)") == 0);
    CHECK(run("CHECKPOINT") == 0);
    CHECK(exs(&s2, "BEGIN") == 0 && exs(&s2, "SELECT v FROM p WHERE a = 1 AND b = 'x'") == 0); /* its snapshot */
    CHECK(run("UPDATE p SET v = 20 WHERE a = 1 AND b = 'x'") == 0);
    CHECK(run("DELETE FROM p WHERE a = 1 AND b = 'y'") == 0);
    CHECK(run("CHECKPOINT") == 0);
    imdb_err e = {0};
    CHECK(imdb_evict(db, db->lake_seq, &e) == 0 && s2.txn.snap < db->mem_floor);
    CHECK(exs(&s2, "INSERT INTO p VALUES (1, 'y', 77)") == IMDB_ERR_CONSTRAINT); /* in its view, the lake's alone */
    CHECK(exs(&s2, "INSERT INTO p VALUES (2, 'y', 78)") == 0);
    CHECK(exs(&s2, "INSERT INTO p VALUES (1, 'z', 79)") == 0);
    CHECK(exs(&s2, "COMMIT") == 0);
    EXPECT("SELECT a, b, v FROM p", "a,b,v\n1,\"x\",20\n1,\"z\",79\n2,\"x\",12\n2,\"y\",78\n");
    imdb_session_close(&s2);
    done(db);
}


/* ERASE SUBJECT on a table keyed by two columns: rows in segments and in the memtable, an updated one, each erased
 * row's key leaves the map (imdb_stub_version: its encoding, then the wipe), so it looks up as none and takes a new
 * row; another subject's rows stay; VERIFY, a reopen and the auditor agree */
static void t_ckey_erase(void)
{
    const char *dir = test_tmpdir();
    imdb_db *db = open_fresh(dir);
    CHECK(db);
    if (!db) return;
    CHECK(run("CREATE TABLE e (who INT64 SUBJECT, a INT64, b TEXT, v INT64, PRIMARY KEY (a, b))") == 0);
    CHECK(run("INSERT INTO e VALUES (7, 1, 'x', 1), (8, 1, 'y', 2), (7, 2, 'x', 3)") == 0);
    CHECK(run("CHECKPOINT") == 0);
    CHECK(run("INSERT INTO e VALUES (7, 3, 'a long key past the sixty-four bytes a key holds without an allocation', 4)") == 0);
    CHECK(run("UPDATE e SET v = 5 WHERE a = 1 AND b = 'y'") == 0);
    CHECK(run("UPDATE e SET v = 6 WHERE a = 2 AND b = 'x'") == 0);
    CHECK(run("ERASE SUBJECT 7") == 0);
    for (int pass = 0; pass < 2; pass++) { /* as erased, then after a reopen (the redacted log replayed) */
        EXPECT("SELECT a, b, v FROM e", "a,b,v\n1,\"y\",5\n");
        EXPECT("SELECT v FROM e WHERE a = 1 AND b = 'x'", "v\n");
        EXPECT("SELECT v FROM e WHERE a = 3 AND b = 'a long key past the sixty-four bytes a key holds without an allocation'", "v\n");
        if (pass) break;
        done(db);
        db = open_at(dir);
        CHECK(db);
        if (!db) return;
    }
    EXPECT("INSERT INTO e VALUES (9, 1, 'x', 7)", "INSERT 1"); /* the erased key free */
    EXPECT("INSERT INTO e VALUES (9, 3, 'a long key past the sixty-four bytes a key holds without an allocation', 8)", "INSERT 1");
    EXPECT("INSERT INTO e VALUES (9, 1, 'y', 9)", "ERR duplicate primary key"); /* another subject's, live */
    EXPECT("SELECT a, v FROM e", "a,v\n1,7\n1,5\n3,8\n");
    imdb_verify_report vr;
    imdb_err e = {0};
    CHECK(imdb_verify(db, &vr, &e) == 0);
    done(db);
    CHECK(audit_dir(dir) == 0);
}

const test_case ckey_tests[] = {
    {"ckey_ddl", t_ckey_ddl},
    {"ckey_rows", t_ckey_rows},
    {"ckey_order", t_ckey_order},
    {"ckey_model", t_ckey_model},
    {"ckey_join", t_ckey_join},
    {"ckey_old_txn", t_ckey_old_txn},
    {"ckey_erase", t_ckey_erase},
};
const size_t ckey_ntests = sizeof ckey_tests / sizeof *ckey_tests;
