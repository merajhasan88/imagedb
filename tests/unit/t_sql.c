/* SQL tests: parser strictness and limits, exact binding, injection
 * resistance, and a randomized differential test of the three read paths
 * against an independent model (including AS OF, ERASE and PURGE). */
#include <math.h>
#include <stdlib.h>

#include "../../src/sql.h"
#include "../../src/sql_internal.h"
#include "thelp.h"

static imdb_session g_ss;

static int q(const char *sql, imdb_result *r)
{
    imdb_err_clear(&g_e);
    return imdb_exec_one(&g_ss, sql, strlen(sql), NULL, 0, r, &g_e);
}

/* runs and discards the result; returns rc */
static int run(const char *sql)
{
    imdb_result r;
    int rc = q(sql, &r);
    if (!rc) imdb_result_free(&r);
    return rc;
}

#define RUN(sql)                                                                \
    do {                                                                        \
        if (run(sql)) {                                                         \
            char m_[900];                                                       \
            snprintf(m_, sizeof m_, "%s -> %s", sql, g_e.msg);                  \
            test_fail(__FILE__, __LINE__, m_);                                  \
            return;                                                             \
        }                                                                       \
    } while (0)

static imdb_db *fresh(void)
{
    const char *dir = test_tmpdir();
    imdb_err e = {0};
    if (imdb_init(dir, false, NULL, &e)) return NULL;
    imdb_db *db = open_db(dir);
    if (db) imdb_session_init(&g_ss, db);
    return db;
}

static int64_t cell_i(const imdb_result *r, uint64_t row, uint16_t col)
{
    const imdb_cell *c = &r->cells[row * r->ncols + col];
    if (c->null) return INT64_MIN;
    if (c->wide) return (int64_t)c->i128;
    return c->v.i;
}

static void t_parser_accepts(void)
{
    const char *ok[] = {
        "CREATE TABLE t (id INT64 PRIMARY KEY, u BIGINT SUBJECT, a DECIMAL(10,2), s TEXT, b BOOL, ts TIMESTAMP)",
        "insert into t values (1, 2, -3.50, 'it''s', true, '2026-01-01')",
        "INSERT INTO t (id, u, a, s, b, ts) VALUES (2, 2, 0, '', FALSE, TIMESTAMP '2026-01-01 10:00:00');",
        "SELECT * FROM t",
        "select count(*), sum(a), min(s), max(ts) from t where u = 2 and a between -1 and 5.5",
        "SELECT u, COUNT(*) FROM t AS OF 3 GROUP BY u LIMIT 10",
        "SELECT * FROM t AS OF TIMESTAMP '2026-10-20 00:00:00' WHERE s >= 'a' AND s < 'z'",
        "UPDATE t SET a = 1.00, s = 'x' WHERE id = 1",
        "DELETE FROM t WHERE id != 1",
        "-- comment\n  SELECT * FROM t -- trailing\n",
        "BEGIN", "COMMIT", "ROLLBACK", "CHECKPOINT", "COMPACT t PURGE BEFORE 5", "ERASE SUBJECT 42",
        "ERASE SUBJECT 'alice'", "ERASE FROM t WHERE s = 'pii'", "VERIFY", "SHOW TABLES", "SHOW DIGEST",
        "SHOW DIGEST t SUBJECT 2", "SHOW HISTORY t 1", "SHOW LOG 3", "SHOW LAKE", "SET cross_check = on",
        "SELECT * FROM t WHERE id = $1", ";", "",
    };
    for (size_t i = 0; i < sizeof ok / sizeof *ok; i++) {
        sql_stmt st;
        imdb_err e = {0};
        int rc = imdb_sql_parse(ok[i], strlen(ok[i]), &st, &e);
        if (rc) fprintf(stderr, "    rejected: %s (%s)\n", ok[i], e.msg);
        CHECK(rc == 0);
        imdb_sql_stmt_free(&st);
    }
}

static void t_parser_rejects(void)
{
    const char *bad[] = {
        "SELECT * FROM t WHERE a = 1 OR b = 2",         /* no OR */
        "SELECT * FROM t; DROP TABLE t",                  /* one statement per call */
        "SELECT * FROM \"t\"",                            /* no quoted identifiers */
        "SELECT * FROM t WHERE s = 'unterminated",
        "SELECT * FROM t WHERE id = 1.2.3",
        "SELECT * FROM t ORDER BY id",
        "CREATE TABLE t (x REAL PRIMARY KEY)",
        "CREATE TABLE t (x INT64)",                       /* no primary key */
        "CREATE TABLE t (x INT64 PRIMARY KEY, y INT64 PRIMARY KEY)",
        "CREATE TABLE select (x INT64 PRIMARY KEY)",       /* reserved word */
        "INSERT INTO t VALUES (1, -NULL)",                /* a sign needs a number */
        "INSERT INTO t VALUES (1, 2), (3)",               /* ragged rows */
        "SELECT * FROM t WHERE id = $0",
        "SELECT * FROM t WHERE id = $999",
        "SELECT * FROM t WHERE NOT id = 1",
        "SELEC * FROM t",
        "SELECT * FROM t WHERE id = 1 extra",
        "SELECT * FROM t \x01",
        "SELECT * FROM t WHERE s = 'a\xff'",              /* invalid UTF-8 */
    };
    for (size_t i = 0; i < sizeof bad / sizeof *bad; i++) {
        sql_stmt st;
        imdb_err e = {0};
        int rc = imdb_sql_parse(bad[i], strlen(bad[i]), &st, &e);
        if (!rc) {
            fprintf(stderr, "    accepted: %s\n", bad[i]);
            imdb_sql_stmt_free(&st);
        }
        CHECK(rc != 0);
    }
    {
        /* an embedded NUL anywhere in the statement is rejected */
        static const char withnul[] = {'S', 'E', 'L', 'E', 'C', 'T', ' ', '\'', 'a', '\0', 'b', '\''};
        sql_stmt st;
        imdb_err e = {0};
        CHECK(imdb_sql_parse(withnul, sizeof withnul, &st, &e) == IMDB_ERR_INVALID);
    }
    /* limits: huge identifier, too many predicates, deep token streams */
    char big[200];
    memset(big, 'a', sizeof big);
    big[sizeof big - 1] = 0;
    char sql[400];
    snprintf(sql, sizeof sql, "SELECT * FROM %s", big);
    sql_stmt st;
    imdb_err e = {0};
    CHECK(imdb_sql_parse(sql, strlen(sql), &st, &e) == IMDB_ERR_LIMIT);
    imdb_buf b;
    imdb_buf_init(&b);
    imdb_buf_put_str(&b, "SELECT * FROM t WHERE x = 1");
    for (int i = 0; i < 40; i++) imdb_buf_put_str(&b, " AND x = 1");
    imdb_err_clear(&e);
    CHECK(imdb_sql_parse((const char *)b.p, b.len, &st, &e) == IMDB_ERR_LIMIT);
    imdb_buf_free(&b);
    /* a very long flat statement stays linear and bounded (no recursion) */
    imdb_buf_init(&b);
    imdb_buf_put_str(&b, "INSERT INTO t VALUES ");
    for (int i = 0; i < 20000; i++) imdb_buf_printf(&b, "%s(%d, 1)", i ? "," : "", i);
    imdb_err_clear(&e);
    CHECK(imdb_sql_parse((const char *)b.p, b.len, &st, &e) == 0 && st.nrows == 20000 && st.rowlen == 2);
    imdb_sql_stmt_free(&st);
    imdb_buf_free(&b);
    imdb_buf_init(&b);
    for (int i = 0; i < 300000; i++) imdb_buf_put_str(&b, "( ");
    imdb_err_clear(&e);
    CHECK(imdb_sql_parse((const char *)b.p, b.len, &st, &e) == IMDB_ERR_LIMIT); /* token limit */
    imdb_buf_free(&b);
}

static void t_binding_exact(void)
{
    imdb_db *db = fresh();
    CHECK(db);
    RUN("CREATE TABLE t (id INT64 PRIMARY KEY, u INT64 SUBJECT, a DECIMAL(6,2), s TEXT, ts TIMESTAMP, b BOOL)");
    RUN("INSERT INTO t VALUES (1, 1, 1234.56, 'x', '2026-01-01 00:00:00', true)");
    CHECK(run("INSERT INTO t VALUES (2, 1, 1.005, 'x', '2026-01-01', true)") == IMDB_ERR_INVALID); /* would round */
    CHECK(run("INSERT INTO t VALUES (2, 1, 10000.00, 'x', '2026-01-01', true)") == IMDB_ERR_LIMIT); /* precision */
    CHECK(run("INSERT INTO t VALUES (2.5, 1, 1, 'x', '2026-01-01', true)") == IMDB_ERR_INVALID);   /* INT64 */
    CHECK(run("INSERT INTO t VALUES (2, 1, 1, 7, '2026-01-01', true)") == IMDB_ERR_INVALID);       /* TEXT */
    CHECK(run("INSERT INTO t VALUES (2, 1, 1, 'x', '2026-02-30', true)") == IMDB_ERR_INVALID);     /* date */
    CHECK(run("INSERT INTO t VALUES (2, 1, 1, 'x', '2026-01-01', 1)") == IMDB_ERR_INVALID);        /* BOOL */
    CHECK(run("INSERT INTO t VALUES (1, 9, 1, 'x', '2026-01-01', true)") == IMDB_ERR_CONSTRAINT);  /* dup key */
    CHECK(run("UPDATE t SET id = 5 WHERE id = 1") == IMDB_ERR_INVALID);
    /* statement atomicity: a failing row aborts the whole INSERT */
    CHECK(run("INSERT INTO t VALUES (3, 1, 1, 'x', '2026-01-01', true), (1, 1, 1, 'x', '2026-01-01', true)") ==
          IMDB_ERR_CONSTRAINT);
    imdb_result r;
    CHECK(q("SELECT COUNT(*) FROM t", &r) == 0 && cell_i(&r, 0, 0) == 1);
    imdb_result_free(&r);
    /* comparisons are exact; literals beyond the column precision still compare */
    CHECK(q("SELECT COUNT(*) FROM t WHERE a > 1234.559 AND a < 99999999.00", &r) == IMDB_ERR_INVALID); /* 3 decimals */
    CHECK(q("SELECT COUNT(*) FROM t WHERE a > 1234.55 AND a < 99999999.00", &r) == 0 && cell_i(&r, 0, 0) == 1);
    imdb_result_free(&r);
    /* parameters bind with exact types; there is no escaping API to misuse */
    imdb_value pv[1] = {{.type = IMDB_T_TEXT, .s = (const uint8_t *)"x' OR '1'='1", .len = 12}};
    const char *sql = "SELECT COUNT(*) FROM t WHERE s = $1";
    imdb_err_clear(&g_e);
    CHECK(imdb_exec_one(&g_ss, sql, strlen(sql), pv, 1, &r, &g_e) == 0 && cell_i(&r, 0, 0) == 0);
    imdb_result_free(&r);
    imdb_value pi[1] = {{.type = IMDB_T_INT64, .i = 1}};
    const char *sq2 = "SELECT COUNT(*) FROM t WHERE s = $1";
    imdb_err_clear(&g_e);
    CHECK(imdb_exec_one(&g_ss, sq2, strlen(sq2), pi, 1, &r, &g_e) == IMDB_ERR_INVALID); /* wrong type */
    /* error messages never contain stored values */
    RUN("INSERT INTO t VALUES (77777, 1, 1, 'SECRETVALUE', '2026-01-01', true)");
    imdb_err_clear(&g_e);
    CHECK(run("INSERT INTO t VALUES (77777, 1, 1, 'SECRETVALUE', '2026-01-01', true)") == IMDB_ERR_CONSTRAINT);
    CHECK(!strstr(g_e.msg, "77777") && !strstr(g_e.msg, "SECRETVALUE"));
    /* NUL inside a parameter is rejected like any other TEXT ingress */
    imdb_value pn[1] = {{.type = IMDB_T_TEXT, .s = (const uint8_t *)"a\0b", .len = 3}};
    const char *ins = "INSERT INTO t VALUES (9, 1, 1, $1, '2026-01-01', true)";
    imdb_err_clear(&g_e);
    CHECK(imdb_exec_one(&g_ss, ins, strlen(ins), pn, 1, &r, &g_e) == IMDB_ERR_INVALID);
    imdb_close(db);
}

static void t_transactions_sql(void)
{
    imdb_db *db = fresh();
    CHECK(db);
    RUN("CREATE TABLE t (id INT64 PRIMARY KEY, v INT64)");
    RUN("BEGIN");
    RUN("INSERT INTO t VALUES (1, 10), (2, 20)");
    imdb_result r;
    CHECK(q("SELECT SUM(v) FROM t", &r) == 0 && cell_i(&r, 0, 0) == 30); /* read your writes */
    imdb_result_free(&r);
    CHECK(run("INSERT INTO t VALUES (1, 99)") == IMDB_ERR_CONSTRAINT); /* statement fails ... */
    CHECK(q("SELECT COUNT(*) FROM t", &r) == 0 && cell_i(&r, 0, 0) == 2); /* ... transaction survives */
    imdb_result_free(&r);
    RUN("UPDATE t SET v = 11 WHERE id = 1");
    RUN("ROLLBACK");
    CHECK(q("SELECT COUNT(*) FROM t", &r) == 0 && cell_i(&r, 0, 0) == 0);
    imdb_result_free(&r);
    RUN("BEGIN");
    RUN("INSERT INTO t VALUES (1, 10), (2, 20)");
    RUN("DELETE FROM t WHERE id = 2");
    RUN("COMMIT");
    uint64_t seq = db->seq;
    CHECK(q("SELECT COUNT(*), SUM(v) FROM t", &r) == 0 && cell_i(&r, 0, 0) == 1 && cell_i(&r, 0, 1) == 10);
    imdb_result_free(&r);
    CHECK(run("CHECKPOINT") == 0 && db->seq == seq + 1);
    RUN("BEGIN");
    CHECK(run("CHECKPOINT") == IMDB_ERR_STATE);
    CHECK(run("ERASE SUBJECT 1") == IMDB_ERR_STATE);
    RUN("ROLLBACK");
    imdb_close(db);
}

/* ---- randomized differential test ------------------------------------------------ */

enum { MK = 48, MU = 5, MSNAP = 24 };

typedef struct mrow {
    bool live;
    int64_t user, cents;
    char memo[16];
} mrow;

typedef struct msnap {
    uint64_t seq;
    mrow rows[MK];
} msnap;

static int64_t sum_user(const mrow *rows, int64_t u, int64_t *cnt)
{
    int64_t s = 0;
    *cnt = 0;
    for (int k = 0; k < MK; k++)
        if (rows[k].live && rows[k].user == u) {
            s += rows[k].cents;
            (*cnt)++;
        }
    return s;
}

static void t_random_differential(void)
{
    imdb_db *db = fresh();
    CHECK(db);
    g_ss.cross_check = true;
    RUN("CREATE TABLE txns (id INT64 PRIMARY KEY, user_id INT64 SUBJECT, amount DECIMAL(12,2), memo TEXT)");
    mrow m[MK];
    memset(m, 0, sizeof m);
    msnap *snaps = calloc(MSNAP, sizeof *snaps);
    int nsnap = 0;
    uint64_t horizon = 0;
    char sql[512];
    for (int step = 0; step < 700; step++) {
        int op = (int)(test_rand() % 100);
        int k = (int)(test_rand() % MK);
        int64_t u = (int64_t)(test_rand() % MU), cents = (int64_t)(test_rand() % 200000) - 100000;
        const char *memos[] = {"coffee", "rent", "caf\xc3\xa9", "", "it''s"};
        const char *memo_m[] = {"coffee", "rent", "caf\xc3\xa9", "", "it's"};
        int mi = (int)(test_rand() % 5);
        if (op < 40) {
            snprintf(sql, sizeof sql, "INSERT INTO txns VALUES (%d, %lld, %s%lld.%02lld, '%s')", k, (long long)u,
                     cents < 0 ? "-" : "", (long long)(llabs(cents) / 100), (long long)(llabs(cents) % 100), memos[mi]);
            int rc = run(sql);
            CHECK(m[k].live ? rc == IMDB_ERR_CONSTRAINT : rc == 0);
            if (!m[k].live) {
                m[k].live = true;
                m[k].user = u;
                m[k].cents = cents;
                strcpy(m[k].memo, memo_m[mi]);
            }
        } else if (op < 55) {
            snprintf(sql, sizeof sql, "UPDATE txns SET amount = %lld.%02lld, user_id = %lld WHERE id = %d",
                     (long long)llabs(cents) / 100, (long long)llabs(cents) % 100, (long long)u, k);
            RUN(sql);
            if (m[k].live) {
                m[k].cents = llabs(cents);
                m[k].user = u;
            }
        } else if (op < 65) {
            snprintf(sql, sizeof sql, "DELETE FROM txns WHERE user_id = %lld AND amount < 0", (long long)u);
            RUN(sql);
            for (int j = 0; j < MK; j++)
                if (m[j].live && m[j].user == u && m[j].cents < 0) m[j].live = false;
        } else if (op < 72) {
            RUN("CHECKPOINT");
        } else if (op < 75 && nsnap > 2) {
            uint64_t pb = snaps[nsnap / 2].seq;
            snprintf(sql, sizeof sql, "COMPACT txns PURGE BEFORE %llu", (unsigned long long)pb);
            RUN(sql);
            if (pb > horizon) horizon = pb;
        } else if (op < 78) {
            snprintf(sql, sizeof sql, "ERASE SUBJECT %lld", (long long)u);
            RUN(sql);
            for (int j = 0; j < MK; j++)
                if (m[j].user == u) m[j].live = false;
            /* erasure is retroactive: history forgets the subject too */
            for (int s = 0; s < nsnap; s++)
                for (int j = 0; j < MK; j++)
                    if (snaps[s].rows[j].user == u) snaps[s].rows[j].live = false;
        } else if (op < 80) {
            snprintf(sql, sizeof sql, "BEGIN");
            RUN(sql);
            snprintf(sql, sizeof sql, "DELETE FROM txns WHERE id = %d", k);
            RUN(sql);
            RUN("ROLLBACK");
        }
        if (step % 7 == 0 && nsnap < MSNAP) {
            snaps[nsnap].seq = db->seq;
            memcpy(snaps[nsnap].rows, m, sizeof m);
            nsnap++;
        }
        /* every query runs cross-checked (scan vs index/store) and is compared with the model */
        int64_t qu = (int64_t)(test_rand() % MU);
        imdb_result r;
        snprintf(sql, sizeof sql, "SELECT COUNT(*), SUM(amount) FROM txns WHERE user_id = %lld", (long long)qu);
        int rc = q(sql, &r);
        if (rc) fprintf(stderr, "    %s -> %s\n", sql, g_e.msg);
        CHECK(rc == 0);
        int64_t cnt, s = sum_user(m, qu, &cnt);
        CHECK(cell_i(&r, 0, 0) == cnt && (cnt ? cell_i(&r, 0, 1) == s : r.cells[1].null));
        imdb_result_free(&r);
        if (step % 5 == 0) {
            int64_t lo = (int64_t)(test_rand() % 1000) - 500, hi = lo + (int64_t)(test_rand() % 1000);
            snprintf(sql, sizeof sql, "SELECT COUNT(*) FROM txns WHERE amount BETWEEN %lld AND %lld AND memo != 'rent'",
                     (long long)lo, (long long)hi);
            CHECK(q(sql, &r) == 0);
            int64_t c2 = 0;
            for (int j = 0; j < MK; j++)
                if (m[j].live && m[j].cents >= lo * 100 && m[j].cents <= hi * 100 && strcmp(m[j].memo, "rent")) c2++;
            CHECK(cell_i(&r, 0, 0) == c2);
            imdb_result_free(&r);
        }
        if (step % 9 == 0 && nsnap) {
            int si = (int)(test_rand() % (uint64_t)nsnap);
            snprintf(sql, sizeof sql, "SELECT COUNT(*), SUM(amount) FROM txns AS OF %llu WHERE user_id = %lld",
                     (unsigned long long)snaps[si].seq, (long long)qu);
            rc = q(sql, &r);
            if (snaps[si].seq < horizon) {
                CHECK(rc == IMDB_ERR_HISTORY); /* purged history is never answered partially */
            } else {
                CHECK(rc == 0);
                int64_t c3, s3 = sum_user(snaps[si].rows, qu, &c3);
                CHECK(cell_i(&r, 0, 0) == c3 && (c3 ? cell_i(&r, 0, 1) == s3 : r.cells[1].null));
                imdb_result_free(&r);
            }
        }
        if (step % 25 == 0) {
            /* full row listing along all three paths must be identical */
            imdb_result ra[3];
            int paths[3] = {IMDB_PATH_INDEX, IMDB_PATH_SCAN, IMDB_PATH_STORE};
            g_ss.cross_check = false;
            for (int p = 0; p < 3; p++) {
                g_ss.access_path = paths[p];
                snprintf(sql, sizeof sql, "SELECT * FROM txns WHERE user_id = %lld", (long long)qu);
                CHECK(q(sql, &ra[p]) == 0);
            }
            g_ss.access_path = IMDB_PATH_AUTO;
            g_ss.cross_check = true;
            for (int p = 1; p < 3; p++) {
                CHECK(ra[p].nrows == ra[0].nrows);
                for (uint64_t i = 0; i < ra[0].nrows * ra[0].ncols; i++)
                    CHECK(imdb_value_cmp(&ra[0].cells[i].v, &ra[p].cells[i].v) == 0);
            }
            for (int p = 0; p < 3; p++) imdb_result_free(&ra[p]);
            /* and the per-subject digest agrees between index and lake scan */
            snprintf(sql, sizeof sql, "SHOW DIGEST txns SUBJECT %lld", (long long)qu);
            CHECK(q(sql, &r) == 0);
            imdb_result_free(&r);
        }
    }
    CHECK(g_ss.cross_checks_run > 700);
    RUN("VERIFY");
    imdb_close(db);
    free(snaps);
}

/* ERASE FROM ... WHERE: by a non-subject predicate, across memtable and
 * segments, including historical versions whose current version no longer
 * matches; zone-map extremes must vanish too. */
static void t_erase_where(void)
{
    const char *base = test_tmpdir();
    char p[600], r[600], s[600];
    snprintf(p, sizeof p, "%s/primary", base);
    snprintf(r, sizeof r, "%s/replica", base);
    snprintf(s, sizeof s, "%s/stream", base);
    imdb_err e = {0};
    CHECK(imdb_init(p, false, NULL, &e) == 0 && imdb_init(r, true, p, &e) == 0);
    imdb_db *db = open_db(p);
    CHECK(db);
    imdb_session_init(&g_ss, db);
    g_ss.cross_check = true;
    RUN("CREATE TABLE t (id INT64 PRIMARY KEY, u INT64 SUBJECT, big INT64, memo TEXT)");
    char sql[256];
    for (int i = 1; i <= 20; i++) {
        snprintf(sql, sizeof sql, "INSERT INTO t VALUES (%d, %d, %d, '%s')", i, i % 3,
                 i == 5 ? 0 : i, (i == 5 || i == 6) ? "pii-XYZ" : "ok");
        RUN(sql);
    }
    RUN("UPDATE t SET big = 8877665544332211 WHERE id = 5"); /* the column maximum, in a zone map */
    RUN("CHECKPOINT");
    uint64_t old = db->seq;
    RUN("UPDATE t SET memo = 'clean' WHERE id = 6"); /* current version no longer matches */
    RUN("INSERT INTO t VALUES (30, 1, 30, 'pii-XYZ')"); /* memtable only */
    imdb_result res;
    CHECK(q("SELECT COUNT(*) FROM t WHERE memo = 'pii-XYZ'", &res) == 0 && cell_i(&res, 0, 0) == 2);
    imdb_result_free(&res);
    uint8_t pat[8];
    imdb_le64(pat, 8877665544332211ull);
    CHECK(tree_contains(p, "pii-XYZ") && tree_contains_n(p, pat, 8));
    RUN("ERASE FROM t WHERE memo = 'pii-XYZ'");
    CHECK(q("SELECT COUNT(*) FROM t", &res) == 0 && cell_i(&res, 0, 0) == 19);
    imdb_result_free(&res);
    CHECK(q("SELECT memo FROM t WHERE id = 6", &res) == 0 && res.nrows == 1 &&
          res.cells[0].v.len == 5 && memcmp(res.cells[0].v.s, "clean", 5) == 0);
    imdb_result_free(&res);
    snprintf(sql, sizeof sql, "SELECT COUNT(*) FROM t AS OF %llu WHERE id BETWEEN 5 AND 6", (unsigned long long)old);
    CHECK(q(sql, &res) == 0 && cell_i(&res, 0, 0) == 0); /* erased from history too */
    imdb_result_free(&res);
    CHECK(!tree_contains(p, "pii-XYZ") && !tree_contains_n(p, pat, 8));
    RUN("VERIFY");
    imdb_close(db);
    CHECK(ship_to_file(p, 0, s, &e) == 0);
    imdb_db *rep = open_db(r);
    CHECK(rep);
    uint64_t applied;
    CHECK(apply_file(rep, s, &applied, &e) == 0);
    imdb_verify_report vr;
    CHECK(imdb_verify(rep, &vr, &e) == 0);
    imdb_close(rep);
    char why[300] = "";
    CHECK(dirs_identical(path_join(p, "objects"), path_join(r, "objects"), why, sizeof why));
    CHECK(!tree_contains(r, "pii-XYZ"));
}

/* ERASE SUBJECT spans every table whose SUBJECT column has the value's type. */
static void t_erase_multi_table(void)
{
    imdb_db *db = fresh();
    CHECK(db);
    const char *dir = db->path;
    RUN("CREATE TABLE users (user_id INT64 PRIMARY KEY SUBJECT, name TEXT)");
    RUN("CREATE TABLE txns (id INT64 PRIMARY KEY, user_id INT64 SUBJECT, memo TEXT)");
    RUN("CREATE TABLE tags (tag TEXT PRIMARY KEY, owner TEXT SUBJECT)");
    RUN("INSERT INTO users VALUES (42, 'NAME-OF-42'), (7, 'seven')");
    RUN("INSERT INTO txns VALUES (1, 42, 'TXN-OF-42'), (2, 7, 'txn7'), (3, 42, 'TXN-OF-42b')");
    RUN("INSERT INTO tags VALUES ('TAG-42', '42')"); /* TEXT subject '42' is a different subject */
    RUN("CHECKPOINT");
    RUN("INSERT INTO txns VALUES (4, 42, 'TXN-OF-42c')");
    imdb_result res;
    CHECK(q("ERASE SUBJECT 42", &res) == 0 && strstr(res.status, "ERASE 4 versions") && strstr(res.status, "in 2 tables"));
    imdb_result_free(&res);
    CHECK(!tree_contains(dir, "NAME-OF-42") && !tree_contains(dir, "TXN-OF-42"));
    CHECK(tree_contains(dir, "TAG-42") && tree_contains(dir, "seven") && tree_contains(dir, "txn7"));
    CHECK(q("SELECT COUNT(*) FROM users", &res) == 0 && cell_i(&res, 0, 0) == 1);
    imdb_result_free(&res);
    CHECK(q("SELECT COUNT(*) FROM tags WHERE owner = '42'", &res) == 0 && cell_i(&res, 0, 0) == 1);
    imdb_result_free(&res);
    RUN("ERASE SUBJECT '42'"); /* now the TEXT subject */
    CHECK(!tree_contains(dir, "TAG-42"));
    RUN("VERIFY");
    imdb_close(db);
}

/* Random workload over BOOL/TIMESTAMP/TEXT/DECIMAL columns: edge ranges,
 * GROUP BY on INT and TEXT keys, MIN/MAX, LIMIT, AS OF TIMESTAMP -- all
 * compared with a model, all cross-checked between paths. */
enum { TK = 40, TU = 4, TSNAP = 16 };
typedef struct trow {
    bool live, flag;
    int64_t u, at, amt;
    int kind;
} trow;
static const char *kKinds[] = {"buy", "refund", "fee", "caf\xc3\xa9"};

static void t_random_types(void)
{
    imdb_db *db = fresh();
    CHECK(db);
    g_ss.cross_check = true;
    RUN("CREATE TABLE ev (id INT64 PRIMARY KEY, u INT64 SUBJECT, flag BOOL, at TIMESTAMP, kind TEXT, amt DECIMAL(10,2))");
    trow m[TK];
    memset(m, 0, sizeof m);
    struct {
        uint64_t seq;
        trow rows[TK];
    } *snaps = calloc(TSNAP, sizeof *snaps);
    int nsnap = 0;
    const int64_t T0 = 1767225600000000LL; /* 2026-01-01 */
    char sql[600];
    for (int step = 0; step < 500; step++) {
        int op = (int)(test_rand() % 100), k = (int)(test_rand() % TK);
        if (op < 45) {
            trow n = {true, test_rand() & 1, (int64_t)(test_rand() % TU), T0 + (int64_t)(test_rand() % 31536000000000ULL),
                      (int64_t)(test_rand() % 100000) - 50000, (int)(test_rand() % 4)};
            imdb_buf tb;
            imdb_buf_init(&tb);
            imdb_format_timestamp(n.at, &tb);
            imdb_buf_put_u8(&tb, 0);
            snprintf(sql, sizeof sql, "INSERT INTO ev VALUES (%d, %lld, %s, '%s', '%s', %s%lld.%02lld)", k, (long long)n.u,
                     n.flag ? "TRUE" : "FALSE", (const char *)tb.p, kKinds[n.kind], n.amt < 0 ? "-" : "",
                     (long long)(llabs(n.amt) / 100), (long long)(llabs(n.amt) % 100));
            imdb_buf_free(&tb);
            int rc = run(sql);
            CHECK(m[k].live ? rc == IMDB_ERR_CONSTRAINT : rc == 0);
            if (!m[k].live) m[k] = n;
        } else if (op < 60) {
            bool f = test_rand() & 1;
            snprintf(sql, sizeof sql, "UPDATE ev SET flag = %s, kind = '%s' WHERE id >= %d AND id <= %d", f ? "TRUE" : "FALSE",
                     kKinds[k % 4], k, k + 3);
            RUN(sql);
            for (int j = k; j <= k + 3 && j < TK; j++)
                if (m[j].live) {
                    m[j].flag = f;
                    m[j].kind = k % 4;
                }
        } else if (op < 70) {
            snprintf(sql, sizeof sql, "DELETE FROM ev WHERE flag = %s AND at < TIMESTAMP '2026-04-01'",
                     (test_rand() & 1) ? "TRUE" : "FALSE");
            bool fv = strstr(sql, "TRUE") != NULL;
            RUN(sql);
            for (int j = 0; j < TK; j++)
                if (m[j].live && m[j].flag == fv && m[j].at < 1775001600000000LL) m[j].live = false;
        } else if (op < 78) {
            RUN("CHECKPOINT");
        } else if (op < 80) {
            RUN("COMPACT ev");
        } else if (op < 82) {
            int64_t u = (int64_t)(test_rand() % TU);
            snprintf(sql, sizeof sql, "ERASE SUBJECT %lld", (long long)u);
            RUN(sql);
            for (int j = 0; j < TK; j++)
                if (m[j].u == u) m[j].live = false;
            for (int si = 0; si < nsnap; si++)
                for (int j = 0; j < TK; j++)
                    if (snaps[si].rows[j].u == u) snaps[si].rows[j].live = false;
        }
        if (step % 11 == 0 && nsnap < TSNAP) {
            snaps[nsnap].seq = db->seq;
            memcpy(snaps[nsnap].rows, m, sizeof m);
            nsnap++;
        }
        imdb_result r;
        /* (a) BOOL on the scan path and on the index path */
        bool fq = test_rand() & 1;
        int64_t uq = (int64_t)(test_rand() % TU);
        snprintf(sql, sizeof sql, "SELECT COUNT(*) FROM ev WHERE flag = %s", fq ? "TRUE" : "FALSE");
        CHECK(q(sql, &r) == 0);
        int64_t c = 0;
        for (int j = 0; j < TK; j++) c += m[j].live && m[j].flag == fq;
        CHECK(cell_i(&r, 0, 0) == c);
        imdb_result_free(&r);
        snprintf(sql, sizeof sql, "SELECT COUNT(*) FROM ev WHERE u = %lld AND flag != %s", (long long)uq, fq ? "TRUE" : "FALSE");
        CHECK(q(sql, &r) == 0);
        c = 0;
        for (int j = 0; j < TK; j++) c += m[j].live && m[j].u == uq && m[j].flag != fq;
        CHECK(cell_i(&r, 0, 0) == c);
        imdb_result_free(&r);
        /* (b) TIMESTAMP range with MIN/MAX */
        CHECK(q("SELECT COUNT(*), MIN(at), MAX(at) FROM ev WHERE at >= TIMESTAMP '2026-03-01' AND at < TIMESTAMP '2026-09-01'", &r) == 0);
        int64_t cnt = 0, mn = INT64_MAX, mx = INT64_MIN;
        for (int j = 0; j < TK; j++)
            if (m[j].live && m[j].at >= 1772323200000000LL && m[j].at < 1788220800000000LL) {
                cnt++;
                if (m[j].at < mn) mn = m[j].at;
                if (m[j].at > mx) mx = m[j].at;
            }
        CHECK(cell_i(&r, 0, 0) == cnt);
        if (cnt) CHECK(cell_i(&r, 0, 1) == mn && cell_i(&r, 0, 2) == mx);
        else CHECK(r.cells[1].null && r.cells[2].null);
        imdb_result_free(&r);
        /* (c) edge literals on an INT64 column */
        static const char *ops[] = {"<", "<=", ">", ">="};
        static const int64_t edges[] = {INT64_MIN, INT64_MIN + 1, -1, 0, 1, 20, INT64_MAX - 1, INT64_MAX};
        int oi = (int)(test_rand() % 4);
        int64_t ev = edges[test_rand() % 8];
        snprintf(sql, sizeof sql, "SELECT COUNT(*) FROM ev WHERE id %s %lld", ops[oi], (long long)ev);
        CHECK(q(sql, &r) == 0);
        c = 0;
        for (int j = 0; j < TK; j++) {
            if (!m[j].live) continue;
            bool ok = oi == 0 ? j < ev : oi == 1 ? j <= ev : oi == 2 ? j > ev : j >= ev;
            c += ok;
        }
        CHECK(cell_i(&r, 0, 0) == c);
        imdb_result_free(&r);
        /* (d) GROUP BY an INT key with SUM and TEXT MIN/MAX */
        CHECK(q("SELECT u, COUNT(*), SUM(amt), MIN(kind), MAX(kind) FROM ev GROUP BY u", &r) == 0);
        uint64_t gi = 0;
        for (int64_t u = 0; u < TU; u++) {
            int64_t gc = 0, gs = 0;
            int kmin = -1, kmax = -1;
            for (int j = 0; j < TK; j++) {
                if (!m[j].live || m[j].u != u) continue;
                gc++;
                gs += m[j].amt;
                if (kmin < 0 || strcmp(kKinds[m[j].kind], kKinds[kmin]) < 0) kmin = m[j].kind;
                if (kmax < 0 || strcmp(kKinds[m[j].kind], kKinds[kmax]) > 0) kmax = m[j].kind;
            }
            if (!gc) continue;
            CHECK(gi < r.nrows && cell_i(&r, gi, 0) == u && cell_i(&r, gi, 1) == gc && cell_i(&r, gi, 2) == gs);
            const imdb_value *vmin = &r.cells[gi * r.ncols + 3].v, *vmax = &r.cells[gi * r.ncols + 4].v;
            CHECK(vmin->len == strlen(kKinds[kmin]) && memcmp(vmin->s, kKinds[kmin], vmin->len) == 0);
            CHECK(vmax->len == strlen(kKinds[kmax]) && memcmp(vmax->s, kKinds[kmax], vmax->len) == 0);
            gi++;
        }
        CHECK(gi == r.nrows);
        imdb_result_free(&r);
        /* (e) GROUP BY a TEXT key (bytewise order) */
        CHECK(q("SELECT kind, COUNT(*) FROM ev GROUP BY kind", &r) == 0);
        static const int order[] = {0, 2, 1, 3}; /* buy < fee < refund < caf\xc3\xa9? bytewise: 'b'<'c'<'f'<'r' */
        (void)order;
        uint64_t rows_seen = 0;
        for (uint64_t i = 0; i < r.nrows; i++) {
            const imdb_value *kv = &r.cells[i * 2].v;
            int kk = -1;
            for (int z = 0; z < 4; z++)
                if (kv->len == strlen(kKinds[z]) && memcmp(kv->s, kKinds[z], kv->len) == 0) kk = z;
            CHECK(kk >= 0);
            int64_t gc = 0;
            for (int j = 0; j < TK; j++) gc += m[j].live && m[j].kind == kk;
            CHECK(cell_i(&r, i, 1) == gc);
            if (i) CHECK(imdb_value_cmp(&r.cells[(i - 1) * 2].v, kv) < 0);
            rows_seen += (uint64_t)gc;
        }
        int64_t live = 0;
        for (int j = 0; j < TK; j++) live += m[j].live;
        CHECK((int64_t)rows_seen == live);
        imdb_result_free(&r);
        /* (f) LIMIT returns the first rows in key order */
        snprintf(sql, sizeof sql, "SELECT id FROM ev WHERE u = %lld LIMIT 3", (long long)uq);
        CHECK(q(sql, &r) == 0);
        uint64_t want = 0;
        for (int j = 0; j < TK && want < 3; j++)
            if (m[j].live && m[j].u == uq) {
                CHECK(want < r.nrows && cell_i(&r, want, 0) == j);
                want++;
            }
        CHECK(r.nrows == want);
        imdb_result_free(&r);
        /* (g) AS OF TIMESTAMP resolves to the commit in effect at that instant */
        if (nsnap && step % 13 == 0) {
            int si = (int)(test_rand() % (uint64_t)nsnap);
            uint64_t sq = snaps[si].seq;
            if (sq >= 1) {
                imdb_buf tb;
                imdb_buf_init(&tb);
                imdb_format_timestamp((int64_t)imdb_ci_at(db, sq, E)->time_us, &tb);
                imdb_buf_put_u8(&tb, 0);
                snprintf(sql, sizeof sql, "SELECT COUNT(*) FROM ev AS OF TIMESTAMP '%s'", (const char *)tb.p);
                imdb_buf_free(&tb);
                CHECK(q(sql, &r) == 0);
                int64_t sc = 0;
                for (int j = 0; j < TK; j++) sc += snaps[si].rows[j].live;
                CHECK(cell_i(&r, 0, 0) == sc);
                imdb_result_free(&r);
            }
        }
    }
    RUN("VERIFY");
    free(snaps);
    imdb_close(db);
}

/* ---- NULL and FLOAT64 (E1) ---------------------------------------------------- */

static double cell_f(const imdb_result *r, uint64_t row, uint16_t col)
{
    const imdb_cell *c = &r->cells[row * r->ncols + col];
    return c->null ? NAN : imdb_f64_value(c->v.i);
}

static const char *const kPaths[] = {"auto", "store", "scan"};

/* One query on every path (each also cross-checked against a second): the first
 * cell of row 0, as an int (INT64_MIN for NULL), or as a double in *f. */
static int64_t q1_all(const char *sql, double *f)
{
    int64_t first = 0;
    double ff = 0;
    for (int p = 0; p < 3; p++) {
        char set[64];
        snprintf(set, sizeof set, "SET access_path = %s", kPaths[p]);
        if (run(set)) return INT64_MIN + 1;
        imdb_result r;
        if (q(sql, &r) || r.nrows < 1) {
            fprintf(stderr, "    %s [%s]: %s\n", sql, kPaths[p], g_e.msg);
            return INT64_MIN + 1;
        }
        int64_t v = cell_i(&r, 0, 0);
        double d = r.cells[0].v.type == IMDB_T_FLOAT64 ? cell_f(&r, 0, 0) : 0;
        imdb_result_free(&r);
        if (p == 0) {
            first = v;
            ff = d;
        } else if (v != first || memcmp(&d, &ff, sizeof d) != 0) {
            fprintf(stderr, "    %s: paths disagree\n", sql);
            return INT64_MIN + 1;
        }
    }
    run("SET access_path = auto");
    if (f) *f = ff;
    return first;
}

static void t_null_float_sql(void)
{
    imdb_db *db = fresh();
    CHECK(db);
    g_ss.cross_check = true;
    /* declarations */
    CHECK(run("CREATE TABLE x1 (id FLOAT64 PRIMARY KEY)") == IMDB_ERR_INVALID);
    CHECK(run("CREATE TABLE x2 (id INT64 PRIMARY KEY NULL)") == IMDB_ERR_INVALID);
    CHECK(run("CREATE TABLE x3 (id INT64 PRIMARY KEY, u TEXT SUBJECT NULL)") == IMDB_ERR_INVALID);
    CHECK(run("CREATE TABLE x4 (id INT64 PRIMARY KEY, v INT64 NULL NOT NULL)") == IMDB_ERR_INVALID);
    CHECK(run("CREATE TABLE x5 (id INT64 PRIMARY KEY, v REAL)") == IMDB_ERR_UNSUPPORTED);
    RUN("CREATE TABLE m (id INT64 PRIMARY KEY, u INT64 SUBJECT, a INT64, f DOUBLE PRECISION, s TEXT NULL, b BOOL, "
        "n INT64 NOT NULL)");
    imdb_table *t = imdb_table_by_name(db, "m");
    CHECK(t && t->s.cols[5].type == IMDB_T_BOOL && t->s.cols[3].type == IMDB_T_FLOAT64);
    for (int c = 0; c < 7; c++) CHECK(!(t->s.cols[c].flags & IMDB_COL_NULLABLE) == (c < 2 || c == 6));
    /* values, NULL, and what is refused */
    RUN("INSERT INTO m VALUES (1, 1, NULL, 0.1, NULL, NULL, 7)");
    RUN("INSERT INTO m (id, u, n) VALUES (2, 1, 8)"); /* a, f, s, b left out: NULL */
    CHECK(run("INSERT INTO m (id, u) VALUES (3, 1)") == IMDB_ERR_CONSTRAINT && strstr(g_e.msg, "column n"));
    CHECK(run("INSERT INTO m VALUES (3, NULL, 1, 1, 'x', TRUE, 1)") == IMDB_ERR_CONSTRAINT);
    CHECK(run("INSERT INTO m VALUES (3, 1, 1, 1e400, 'x', TRUE, 1)") == IMDB_ERR_LIMIT);
    CHECK(run("INSERT INTO m VALUES (3, 1, 1.5, 1, 'x', TRUE, 1)") == IMDB_ERR_INVALID); /* INT64: exact only */
    CHECK(run("SELECT COUNT(*) FROM m WHERE a = NULL") == IMDB_ERR_INVALID && strstr(g_e.msg, "IS NULL"));
    CHECK(run("SELECT COUNT(*) FROM m WHERE a BETWEEN 1 AND NULL") == IMDB_ERR_INVALID);
    RUN("INSERT INTO m VALUES (3, 1, 5, 0.2, 'x', TRUE, 9), (4, 2, 6, -0.3, '', FALSE, 10)");
    RUN("CHECKPOINT"); /* rows 1-4 in a segment, the next ones in the memtable */
    RUN("INSERT INTO m VALUES (5, 2, NULL, -0, NULL, TRUE, 11), (6, 2, 9, 2.5E-3, 'y', NULL, 12)");
    RUN("INSERT INTO m VALUES (7, 3, NULL, NULL, NULL, NULL, 13)");
    /* IS [NOT] NULL and comparisons skipping NULLs, on every path */
    CHECK(q1_all("SELECT COUNT(*) FROM m", NULL) == 7);
    CHECK(q1_all("SELECT COUNT(a) FROM m", NULL) == 3);
    CHECK(q1_all("SELECT COUNT(*) FROM m WHERE a IS NULL", NULL) == 4);
    CHECK(q1_all("SELECT COUNT(*) FROM m WHERE a IS NOT NULL", NULL) == 3);
    CHECK(q1_all("SELECT COUNT(*) FROM m WHERE a != 5", NULL) == 2);  /* NULLs are not "not 5" */
    CHECK(q1_all("SELECT COUNT(*) FROM m WHERE a < 100", NULL) == 3);
    CHECK(q1_all("SELECT COUNT(*) FROM m WHERE n IS NULL", NULL) == 0); /* NOT NULL column */
    CHECK(q1_all("SELECT COUNT(*) FROM m WHERE n IS NOT NULL", NULL) == 7);
    CHECK(q1_all("SELECT COUNT(*) FROM m WHERE s IS NULL", NULL) == 4);
    CHECK(q1_all("SELECT COUNT(*) FROM m WHERE s = ''", NULL) == 1);   /* the empty string is a value */
    CHECK(q1_all("SELECT COUNT(*) FROM m WHERE b IS NULL", NULL) == 4); /* ids 1, 2, 6, 7 */
    CHECK(q1_all("SELECT COUNT(*) FROM m WHERE b = TRUE", NULL) == 2);
    CHECK(q1_all("SELECT COUNT(*) FROM m WHERE b != TRUE", NULL) == 1);
    CHECK(q1_all("SELECT COUNT(*) FROM m WHERE u = 2 AND a IS NULL", NULL) == 1); /* subject index */
    CHECK(q1_all("SELECT COUNT(*) FROM m WHERE id = 7 AND f IS NULL", NULL) == 1); /* primary key */
    /* aggregates ignore NULLs; over none at all they are NULL */
    CHECK(q1_all("SELECT SUM(a) FROM m", NULL) == 20);
    CHECK(q1_all("SELECT MIN(a) FROM m", NULL) == 5 && q1_all("SELECT MAX(a) FROM m", NULL) == 9);
    CHECK(q1_all("SELECT SUM(a) FROM m WHERE a IS NULL", NULL) == INT64_MIN);
    CHECK(q1_all("SELECT MIN(f) FROM m WHERE id = 7", NULL) == INT64_MIN);
    CHECK(q1_all("SELECT COUNT(a) FROM m WHERE a IS NULL", NULL) == 0);
    /* FLOAT64: -0 is +0, ranges and the exact sum 0.1 + 0.2 - 0.3 + 0 + 0.0025 */
    double f;
    CHECK(q1_all("SELECT COUNT(*) FROM m WHERE f = 0", NULL) == 1);
    CHECK(q1_all("SELECT COUNT(*) FROM m WHERE f >= 0", NULL) == q1_all("SELECT COUNT(*) FROM m WHERE f > -1e-300", NULL));
    CHECK(q1_all("SELECT COUNT(*) FROM m WHERE f < 0.15 AND f > -1", NULL) == 4);
    CHECK(q1_all("SELECT COUNT(*) FROM m WHERE f BETWEEN 0.1 AND 0.2", NULL) == 2);
    CHECK(q1_all("SELECT MIN(f) FROM m", &f) != INT64_MIN + 1 && f == -0.3);
    CHECK(q1_all("SELECT MAX(f) FROM m", &f) != INT64_MIN + 1 && f == 0.2);
    CHECK(q1_all("SELECT SUM(f) FROM m WHERE id <= 4", &f) != INT64_MIN + 1 && f == 0x1p-55); /* naive: 5.55e-17 */
    double naive = 0.1 + 0.2 - 0.3;
    CHECK(naive != 0x1p-55);
    CHECK(q1_all("SELECT SUM(f) FROM m", &f) != INT64_MIN + 1 && f == 0x1p-55 + 2.5e-3);
    /* GROUP BY a nullable column: one NULL group, last */
    imdb_result r;
    CHECK(q("SELECT a, COUNT(*) FROM m GROUP BY a", &r) == 0 && r.nrows == 4);
    CHECK(cell_i(&r, 0, 0) == 5 && cell_i(&r, 1, 0) == 6 && cell_i(&r, 2, 0) == 9);
    CHECK(r.cells[6].null && cell_i(&r, 3, 1) == 4);
    imdb_result_free(&r);
    /* output: "null" in tables, an empty field in CSV, floats that read back */
    CHECK(q("SELECT id, a, f, s FROM m WHERE id <= 2", &r) == 0);
    imdb_buf out;
    imdb_buf_init(&out);
    imdb_result_render(&r, true, &out);
    imdb_buf_put_u8(&out, 0);
    CHECK(strcmp((const char *)out.p, "id,a,f,s\n1,,0.1,\n2,,,\n") == 0);
    out.len = 0;
    imdb_result_render(&r, false, &out);
    imdb_buf_put_u8(&out, 0);
    CHECK(strstr((const char *)out.p, "null") != NULL);
    imdb_buf_free(&out);
    imdb_result_free(&r);
    /* UPDATE to and from NULL */
    RUN("UPDATE m SET a = NULL, f = 1e10 WHERE id = 3");
    CHECK(run("UPDATE m SET n = NULL WHERE id = 3") == IMDB_ERR_CONSTRAINT);
    RUN("UPDATE m SET s = 'z', b = FALSE WHERE s IS NULL");
    CHECK(q1_all("SELECT COUNT(*) FROM m WHERE s = 'z' AND b = FALSE", NULL) == 4);
    CHECK(q1_all("SELECT COUNT(a) FROM m", NULL) == 2);
    /* the exact sum leaves the finite range: an error, never Inf */
    RUN("INSERT INTO m VALUES (8, 4, 1, 1.7e308, 'w', TRUE, 14), (9, 4, 1, 1.7e308, 'w', TRUE, 15)");
    CHECK(run("SELECT SUM(f) FROM m WHERE u = 4") == IMDB_ERR_LIMIT);
    RUN("INSERT INTO m VALUES (10, 4, 1, -1.7e308, 'w', TRUE, 16)");
    CHECK(q1_all("SELECT SUM(f) FROM m WHERE u = 4", &f) != INT64_MIN + 1 && f == 1.7e308); /* exact again */
    RUN("VERIFY");
    double before = 0;
    CHECK(q1_all("SELECT SUM(f) FROM m WHERE id <= 7", &before) != INT64_MIN + 1 && before > 1e10 - 1);
    /* the same answers, to the bit, after a full replay and from the lake snapshot */
    char dir[600];
    snprintf(dir, sizeof dir, "%s", db->path);
    imdb_close(db);
    for (int full = 0; full < 2 && !g_test_failed; full++) {
        imdb_open_opts o = {.sync = 0, .full_replay = full};
        CHECK(imdb_open(dir, &o, &db, E) == 0);
        imdb_session_init(&g_ss, db);
        g_ss.cross_check = true;
        CHECK(q1_all("SELECT COUNT(a) FROM m", NULL) == 5 && q1_all("SELECT COUNT(*) FROM m WHERE s = 'z'", NULL) == 4); /* ids 4, 6, 8-10 */
        CHECK(q1_all("SELECT SUM(f) FROM m WHERE id <= 7", &f) != INT64_MIN + 1 && memcmp(&f, &before, sizeof f) == 0);
        RUN("VERIFY");
        imdb_close(db);
    }
}

#define NK 40
#define NU 5

typedef struct nrow {
    bool live;
    int64_t u;
    bool an, fn, sn; /* NULL flags */
    int64_t a;
    int64_t fq;      /* f = fq / 8: every sum of these is exact in a double */
    int s;
} nrow;

static const char *const kWords[] = {"", "a", "b", "ab"};

typedef struct npred {
    int kind;
    int64_t v1, v2;
} npred;

static bool np_eval(const nrow *r, const npred *p)
{
    switch (p->kind) {
    case 0: return r->an;
    case 1: return !r->an;
    case 2: return !r->an && r->a < p->v1;
    case 3: return !r->an && r->a != p->v1;
    case 4: return !r->an && r->a >= p->v1 && r->a <= p->v2;
    case 5: return r->fn;
    case 6: return !r->fn && r->fq >= p->v1;
    case 7: return !r->fn && r->fq < p->v1;
    case 8: return r->sn;
    case 9: return !r->sn && r->s == (int)p->v1;
    case 10: return r->u == p->v1;
    default: return !r->fn && r->fq != p->v1;
    }
}

/* a multiple of 1/8 written exactly, sometimes with an exponent */
static void f_lit(int64_t fq, char *out, size_t cap)
{
    if (test_rand() % 3 == 0) snprintf(out, cap, "%lldE-3", (long long)(fq * 125));
    else snprintf(out, cap, "%s%lld.%03lld", fq < 0 ? "-" : "", (long long)(llabs(fq) / 8), (long long)(llabs(fq) % 8 * 125));
}

static void np_sql(const npred *p, char *out, size_t cap)
{
    char a[40], b[40];
    f_lit(p->v1, a, sizeof a);
    switch (p->kind) {
    case 0: snprintf(out, cap, "a IS NULL"); break;
    case 1: snprintf(out, cap, "a IS NOT NULL"); break;
    case 2: snprintf(out, cap, "a < %lld", (long long)p->v1); break;
    case 3: snprintf(out, cap, "a != %lld", (long long)p->v1); break;
    case 4: snprintf(out, cap, "a BETWEEN %lld AND %lld", (long long)p->v1, (long long)p->v2); break;
    case 5: snprintf(out, cap, "f IS NULL"); break;
    case 6: snprintf(out, cap, "f >= %s", a); break;
    case 7: snprintf(out, cap, "f < %s", a); break;
    case 8: snprintf(out, cap, "s IS NULL"); break;
    case 9: snprintf(out, cap, "s = '%s'", kWords[p->v1]); break;
    case 10: snprintf(out, cap, "u = %lld", (long long)p->v1); break;
    default: f_lit(p->v1, b, sizeof b); snprintf(out, cap, "f != %s", b); break;
    }
}

static npred np_rand(void)
{
    npred p = {(int)(test_rand() % 12), (int64_t)(test_rand() % 21) - 10, 0};
    if (p.kind == 4) p.v2 = p.v1 + (int64_t)(test_rand() % 8);
    if (p.kind == 6 || p.kind == 7 || p.kind == 11) p.v1 = (int64_t)(test_rand() % 81) - 40;
    if (p.kind == 9) p.v1 = (int64_t)(test_rand() % 4);
    if (p.kind == 10) p.v1 = (int64_t)(test_rand() % NU);
    return p;
}

static nrow nrow_rand(int64_t u)
{
    nrow n = {true, u, test_rand() % 3 == 0, test_rand() % 3 == 0, test_rand() % 3 == 0,
              (int64_t)(test_rand() % 21) - 10, (int64_t)(test_rand() % 81) - 40, (int)(test_rand() % 4)};
    return n;
}

static void nrow_sql(int k, const nrow *n, char *out, size_t cap)
{
    char a[32], f[40], s[16];
    if (n->an) snprintf(a, sizeof a, "NULL");
    else snprintf(a, sizeof a, "%lld", (long long)n->a);
    if (n->fn) snprintf(f, sizeof f, "NULL");
    else f_lit(n->fq, f, sizeof f);
    if (n->sn) snprintf(s, sizeof s, "NULL");
    else snprintf(s, sizeof s, "'%s'", kWords[n->s]);
    snprintf(out, cap, "(%d, %lld, %s, %s, %s)", k, (long long)n->u, a, f, s);
}

static void t_random_nulls(void)
{
    imdb_db *db = fresh();
    CHECK(db);
    g_ss.cross_check = true;
    RUN("CREATE TABLE nx (id INT64 PRIMARY KEY, u INT64 SUBJECT, a INT64, f FLOAT64, s TEXT)");
    nrow m[NK];
    memset(m, 0, sizeof m);
    char sql[800], p1[96], p2[96];
    int checked = 0;
    for (int step = 0; step < 700 && !g_test_failed; step++) {
        int op = (int)(test_rand() % 100), k = (int)(test_rand() % NK);
        if (op < 40) {
            nrow n = nrow_rand((int64_t)(test_rand() % NU));
            char vals[160];
            nrow_sql(k, &n, vals, sizeof vals);
            snprintf(sql, sizeof sql, "INSERT INTO nx VALUES %s", vals);
            int rc = run(sql);
            CHECK(m[k].live ? rc == IMDB_ERR_CONSTRAINT : rc == 0);
            if (!m[k].live) m[k] = n;
        } else if (op < 60) {
            nrow n = nrow_rand(0);
            int col = (int)(test_rand() % 3);
            char v[48];
            if (col == 0) n.an ? snprintf(v, sizeof v, "NULL") : snprintf(v, sizeof v, "%lld", (long long)n.a);
            else if (col == 1) n.fn ? snprintf(v, sizeof v, "NULL") : (f_lit(n.fq, v, sizeof v), 0);
            else n.sn ? snprintf(v, sizeof v, "NULL") : snprintf(v, sizeof v, "'%s'", kWords[n.s]);
            snprintf(sql, sizeof sql, "UPDATE nx SET %s = %s WHERE id >= %d AND id <= %d", col == 0 ? "a" : col == 1 ? "f" : "s", v, k,
                     k + 3);
            RUN(sql);
            for (int j = k; j <= k + 3 && j < NK; j++) {
                if (!m[j].live) continue;
                if (col == 0) m[j].an = n.an, m[j].a = n.a;
                else if (col == 1) m[j].fn = n.fn, m[j].fq = n.fq;
                else m[j].sn = n.sn, m[j].s = n.s;
            }
        } else if (op < 68) {
            npred p = np_rand();
            np_sql(&p, p1, sizeof p1);
            snprintf(sql, sizeof sql, "DELETE FROM nx WHERE %s AND id < %d", p1, k);
            RUN(sql);
            for (int j = 0; j < k; j++)
                if (m[j].live && np_eval(&m[j], &p)) m[j].live = false;
        } else if (op < 76) {
            RUN("CHECKPOINT");
        } else if (op < 78) {
            RUN("COMPACT nx");
        } else if (op < 80) {
            int64_t u = (int64_t)(test_rand() % NU);
            snprintf(sql, sizeof sql, "ERASE SUBJECT %lld", (long long)u);
            RUN(sql);
            for (int j = 0; j < NK; j++)
                if (m[j].u == u) m[j].live = false;
        }
        /* aggregates under one or two predicates, on a random path */
        npred pa = np_rand(), pb = np_rand();
        bool two = test_rand() & 1;
        np_sql(&pa, p1, sizeof p1);
        np_sql(&pb, p2, sizeof p2);
        snprintf(sql, sizeof sql, "SET access_path = %s", kPaths[test_rand() % 3]);
        RUN(sql);
        snprintf(sql, sizeof sql,
                 "SELECT COUNT(*), COUNT(a), SUM(a), MIN(a), MAX(a), COUNT(f), SUM(f), MIN(f), MAX(f), COUNT(s) FROM nx "
                 "WHERE %s%s%s",
                 p1, two ? " AND " : "", two ? p2 : "");
        imdb_result r;
        if (q(sql, &r)) {
            fprintf(stderr, "    %s: %s\n", sql, g_e.msg);
            CHECK(false);
            break;
        }
        int64_t cnt = 0, ca = 0, sa = 0, mna = INT64_MAX, mxa = INT64_MIN, cf = 0, sf = 0, mnf = INT64_MAX, mxf = INT64_MIN,
                cs = 0;
        for (int j = 0; j < NK; j++) {
            const nrow *n = &m[j];
            if (!n->live || !np_eval(n, &pa) || (two && !np_eval(n, &pb))) continue;
            cnt++;
            if (!n->an) ca++, sa += n->a, mna = n->a < mna ? n->a : mna, mxa = n->a > mxa ? n->a : mxa;
            if (!n->fn) cf++, sf += n->fq, mnf = n->fq < mnf ? n->fq : mnf, mxf = n->fq > mxf ? n->fq : mxf;
            if (!n->sn) cs++;
        }
        bool ok = r.nrows == 1 && cell_i(&r, 0, 0) == cnt && cell_i(&r, 0, 1) == ca && cell_i(&r, 0, 5) == cf &&
                  cell_i(&r, 0, 9) == cs;
        ok = ok && (ca ? cell_i(&r, 0, 2) == sa && cell_i(&r, 0, 3) == mna && cell_i(&r, 0, 4) == mxa
                       : r.cells[2].null && r.cells[3].null && r.cells[4].null);
        ok = ok && (cf ? cell_f(&r, 0, 6) == (double)sf / 8 && cell_f(&r, 0, 7) == (double)mnf / 8 && cell_f(&r, 0, 8) == (double)mxf / 8
                       : r.cells[6].null && r.cells[7].null && r.cells[8].null);
        if (!ok) fprintf(stderr, "    step %d: %s [%s]\n", step, sql, r.path);
        CHECK(ok);
        imdb_result_free(&r);
        checked++;
        /* GROUP BY a nullable column: groups in key order, the NULL group last */
        CHECK(q("SELECT a, COUNT(*), SUM(f) FROM nx GROUP BY a", &r) == 0);
        uint64_t gi = 0;
        for (int64_t a = -10; a <= 11; a++) { /* 11 stands for NULL */
            int64_t gc = 0, gf = 0, gfn = 0;
            for (int j = 0; j < NK; j++) {
                const nrow *n = &m[j];
                if (!n->live || (a == 11 ? !n->an : n->an || n->a != a)) continue;
                gc++;
                if (!n->fn) gf += n->fq, gfn++;
            }
            if (!gc) continue;
            bool g_ok = gi < r.nrows && (a == 11 ? r.cells[gi * 3].null : cell_i(&r, gi, 0) == a) && cell_i(&r, gi, 1) == gc &&
                        (gfn ? cell_f(&r, gi, 2) == (double)gf / 8 : r.cells[gi * 3 + 2].null);
            CHECK(g_ok);
            gi++;
        }
        CHECK(gi == r.nrows);
        imdb_result_free(&r);
    }
    RUN("SET access_path = auto");
    RUN("VERIFY");
    CHECK(checked > 600);
    imdb_close(db);
}

const test_case sql_tests[] = {
    {"null_float_sql", t_null_float_sql},
    {"random_nulls", t_random_nulls},
    {"parser_accepts", t_parser_accepts},
    {"parser_rejects", t_parser_rejects},
    {"binding_exact", t_binding_exact},
    {"transactions_sql", t_transactions_sql},
    {"random_differential", t_random_differential},
    {"erase_where", t_erase_where},
    {"erase_multi_table", t_erase_multi_table},
    {"random_types", t_random_types},
};
const size_t sql_ntests = sizeof sql_tests / sizeof *sql_tests;
