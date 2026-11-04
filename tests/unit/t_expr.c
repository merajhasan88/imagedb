/* Arithmetic expressions (docs/plan-p0.md 1b): each rule of sql_expr.c at its edges, then through SQL: UPDATE's SET
 * over the old values, VALUES, SELECT items and their names, WHERE's trees on every read path and in joins (each
 * answer against a model kept here), and the parser's limits. */
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

static void done(imdb_db *db)
{
    imdb_session_close(&g_ss);
    imdb_close(db);
}

/* a cell as the CLI prints it (rotating buffers: two in one CHECK) */
static const char *cell(const imdb_result *r, uint64_t row, uint16_t col)
{
    static char out[8][128];
    static int n;
    char *o = out[n++ & 7];
    const imdb_cell *c = &r->cells[row * r->ncols + col];
    imdb_buf b;
    imdb_buf_init(&b);
    if (c->null) imdb_buf_put_str(&b, "null");
    else if (c->wide) imdb_format_i128(c->i128, c->v.type == IMDB_T_DECIMAL ? c->v.scale : 0, &b);
    else imdb_format_value(&c->v, &b);
    snprintf(o, 128, "%.*s", (int)b.len, b.p ? (const char *)b.p : "");
    imdb_buf_free(&b);
    return o;
}

/* SELECT expr FROM one (a table of one row): its first cell, or the error's code */
static int one(const char *expr, char *out, size_t n)
{
    char sql[600];
    snprintf(sql, sizeof sql, "SELECT %s FROM one", expr);
    imdb_result r;
    int rc = q(sql, &r);
    if (rc) return rc;
    snprintf(out, n, "%s", r.nrows == 1 ? cell(&r, 0, 0) : "(not one row)");
    imdb_result_free(&r);
    return 0;
}

#define VAL(expr, want)                                                                                    \
    do {                                                                                                   \
        char o_[128];                                                                                      \
        int rc_ = one(expr, o_, sizeof o_);                                                                \
        if (rc_ || strcmp(o_, want) != 0) {                                                                \
            char m_[700];                                                                                  \
            snprintf(m_, sizeof m_, "%s -> %s (rc %d %s), want %s", expr, rc_ ? "-" : o_, rc_, rc_ ? g_e.msg : "", \
                     want);                                                                                \
            test_fail(__FILE__, __LINE__, m_);                                                             \
            return;                                                                                        \
        }                                                                                                  \
    } while (0)

#define ERR(expr, code)                                                                                    \
    do {                                                                                                   \
        char o_[128];                                                                                      \
        int rc_ = one(expr, o_, sizeof o_);                                                                \
        if (rc_ != (code)) {                                                                               \
            char m_[700];                                                                                  \
            snprintf(m_, sizeof m_, "%s -> rc %d (%s), want rc %d", expr, rc_, rc_ ? g_e.msg : o_, code);  \
            test_fail(__FILE__, __LINE__, m_);                                                             \
            return;                                                                                        \
        }                                                                                                  \
    } while (0)

/* a statement's single cell */
#define CELL(sql, want)                                                                                    \
    do {                                                                                                   \
        imdb_result r_;                                                                                    \
        int rc_ = q(sql, &r_);                                                                             \
        if (rc_ || r_.nrows != 1 || strcmp(cell(&r_, 0, 0), want) != 0) {                                  \
            char m_[700];                                                                                  \
            snprintf(m_, sizeof m_, "%s -> %s (rc %d %s), want %s", sql, rc_ ? "-" : r_.nrows == 1 ? cell(&r_, 0, 0) \
                     : "(rows)", rc_, rc_ ? g_e.msg : "", want);                                           \
            if (!rc_) imdb_result_free(&r_);                                                               \
            test_fail(__FILE__, __LINE__, m_);                                                             \
            return;                                                                                        \
        }                                                                                                  \
        imdb_result_free(&r_);                                                                             \
    } while (0)

static imdb_db *with_one(void)
{
    imdb_db *db = fresh();
    if (!db) return NULL;
    if (run("CREATE TABLE one (id INT64 PRIMARY KEY, n INT64, d DECIMAL(12,2), f FLOAT64, s TEXT, m INT64, "
            "p DECIMAL(5,2), s2 TEXT)") ||
        run("INSERT INTO one VALUES (1, NULL, 2.50, 0.25, 'x', 4611686018427387904, 0, 'y')")) {
        done(db);
        return NULL;
    }
    return db;
}

static void t_int64(void)
{
    imdb_db *db = with_one();
    CHECK(db);
    VAL("7 / 2", "3");
    VAL("-7 / 2", "-3"); /* toward zero */
    VAL("7 / -2", "-3");
    VAL("-7 % 3", "-1"); /* the dividend's sign */
    VAL("7 % -3", "1");
    VAL("2 + 3 * 4", "14");
    VAL("(2 + 3) * 4", "20");
    VAL("2 - 3 - 4", "-5"); /* left to right */
    VAL("100 / 10 / 5", "2");
    VAL("- 2 * 3", "-6");
    VAL("-(2 - 5)", "3");
    VAL("+5", "5");
    VAL("- -5", "5");
    VAL("9223372036854775807 - 1 + 1", "9223372036854775807");
    VAL("-9223372036854775808", "-9223372036854775808"); /* the sign is the literal's */
    VAL("-9223372036854775808 % -1", "0");               /* no idiv: it would trap */
    VAL("3037000499 * 3037000499", "9223372030926249001");
    ERR("9223372036854775807 + 1", IMDB_ERR_LIMIT);
    ERR("-9223372036854775808 - 1", IMDB_ERR_LIMIT);
    ERR("-9223372036854775808 / -1", IMDB_ERR_LIMIT);
    ERR("-(-9223372036854775808)", IMDB_ERR_LIMIT);
    ERR("3037000500 * 3037000500", IMDB_ERR_LIMIT);
    ERR("1 / 0", IMDB_ERR_INVALID);
    ERR("1 % 0", IMDB_ERR_INVALID);
    ERR("m * 2 - m - m", IMDB_ERR_LIMIT); /* an intermediate past int64 fails though the end would fit */
    VAL("n + 1", "null");                 /* a NULL operand */
    VAL("n / 0", "null");                 /* NULL before the divisor is looked at, as in PostgreSQL */
    done(db);
}

static void t_decimal(void)
{
    imdb_db *db = with_one();
    CHECK(db);
    VAL("1.5 + 0.25", "1.75");
    VAL("1.5 - 0.25", "1.25");
    VAL("1.5 * 0.25", "0.375"); /* scales add */
    VAL("0.1 + 0.2", "0.3");    /* exact */
    VAL("3 + 0.5", "3.5");
    VAL("d * 2", "5.00");
    VAL("10.00 / 3", "3.33333333"); /* the larger scale + 6 */
    VAL("2 / 3.0", "0.6666667");
    VAL("-2 / 3.0", "-0.6666667");
    VAL("1.0 / 128", "0.0078125");
    VAL("1.0 / 256", "0.0039063"); /* ...625: half, away from zero */
    VAL("-1.0 / 256", "-0.0039063");
    VAL("1000000.0 / 7.0000000000", "142857.1428571428571429");                  /* scaled in one step */
    VAL("1000000000000000000000.0 / 7.0000000000", "142857142857142857142.8571428571428571"); /* digit by digit */
    VAL("1 / 0.50000000000000000000", "2.00000000000000000000000000"); /* k = 46: past 10^38 in one step */
    VAL("7.5 % 2", "1.5");
    VAL("-7.5 % 2", "-1.5");
    VAL("9999999999999999999999999999999999999.9 - 0.1", "9999999999999999999999999999999999999.8");
    ERR("9999999999999999999999999999999999999.9 + 0.1", IMDB_ERR_LIMIT); /* 38 digits */
    ERR("1.00000000000000000000000000000000000000", IMDB_ERR_LIMIT);      /* a 39-digit literal */
    ERR("0.0000000000000000001 * 0.00000000000000000001", IMDB_ERR_LIMIT); /* scale 39 */
    ERR("1.5 / 0", IMDB_ERR_INVALID);
    ERR("1.5 % 0.0", IMDB_ERR_INVALID);
    RUN("CREATE TABLE r18 (id INT64 PRIMARY KEY, r DECIMAL(18,18))");
    RUN("INSERT INTO r18 VALUES (1, 0.250000000000000000)");
    CELL("SELECT 1 / r FROM r18", "4.000000000000000000000000"); /* scale 24, k = 42 */
    CELL("SELECT r / 3 FROM r18", "0.083333333333333333333333");
    done(db);
}

static void t_float64(void)
{
    imdb_db *db = with_one();
    CHECK(db);
    VAL("0.1e0 + 0.2e0", "0.30000000000000004");
    VAL("f * 2", "0.5");
    VAL("1.0e0 / 4", "0.25");
    VAL("4 * 0.5e0", "2");
    VAL("0.1 + 0.0e0", "0.1"); /* a DECIMAL correctly rounded */
    VAL("0.0e0 * -1", "0");    /* -0.0 is 0.0 */
    VAL("9007199254740992 * 1.0e0 - 9007199254740992 * 1.0e0", "0");
    ERR("9007199254740993 * 1.0e0", IMDB_ERR_LIMIT); /* not exact */
    ERR("m * 1.0e0", IMDB_ERR_LIMIT);
    ERR("1.0e0 / 0", IMDB_ERR_INVALID);
    ERR("1e308 * 10", IMDB_ERR_LIMIT);
    ERR("5.5e0 % 2", IMDB_ERR_INVALID);
    ERR("s + 1", IMDB_ERR_INVALID); /* TEXT */
    ERR("1 + NULL", IMDB_ERR_INVALID);
    done(db);
}

/* comparisons: exact, never an error, whatever the magnitudes */
static void t_compare(void)
{
    imdb_xval a = {.type = IMDB_T_INT64}, b = {.type = IMDB_T_FLOAT64};
    a.i = 9007199254740993;
    b.f = 9007199254740992.0;
    CHECK(imdb_x_cmp(&a, &b) == 1 && imdb_x_cmp(&b, &a) == -1);
    a.i = INT64_MAX;
    b.f = 0x1p63;
    CHECK(imdb_x_cmp(&a, &b) == -1);
    a.i = 0;
    b.f = -0.5;
    CHECK(imdb_x_cmp(&a, &b) == 1);
    a.i = -1;
    CHECK(imdb_x_cmp(&a, &b) == -1);
    a.i = 1;
    b.f = 1.0;
    CHECK(imdb_x_cmp(&a, &b) == 0);
    a.i = (__int128)1 << 100; /* a SUM's width */
    b.f = 0x1p127;
    CHECK(imdb_x_cmp(&a, &b) == -1);
    b.f = -0x1p128;
    CHECK(imdb_x_cmp(&a, &b) == 1);
    imdb_xval d = {.type = IMDB_T_DECIMAL, .scale = 2, .i = 100}, i = {.type = IMDB_T_INT64, .i = 1};
    CHECK(imdb_x_cmp(&d, &i) == 0);
    imdb_err e = {0};
    CHECK(imdb_x_parse_decimal("0.99999999999999999999999999999999999999", 40, &d, &e) == 0 && d.scale == 38);
    CHECK(imdb_x_cmp(&d, &i) == -1 && imdb_x_cmp(&i, &d) == 1);
    i.i = 2; /* 2 * 10^38 is past __int128: the magnitude decides */
    CHECK(imdb_x_cmp(&i, &d) == 1 && imdb_x_cmp(&d, &i) == -1);
    i.i = -2;
    CHECK(imdb_x_cmp(&i, &d) == -1);
    imdb_xval p1 = {.type = IMDB_T_DECIMAL, .scale = 1, .i = 1}, f1 = {.type = IMDB_T_FLOAT64, .f = 0.1};
    CHECK(imdb_x_cmp(&p1, &f1) == 0); /* as PostgreSQL: the DECIMAL as the nearest double */
    imdb_xval s1 = {.type = IMDB_T_TEXT, .s = (const uint8_t *)"ab", .len = 2};
    imdb_xval s2 = {.type = IMDB_T_TEXT, .s = (const uint8_t *)"abc", .len = 3};
    imdb_xval s3 = {.type = IMDB_T_TEXT, .s = (const uint8_t *)"b", .len = 1};
    CHECK(imdb_x_cmp(&s1, &s2) == -1 && imdb_x_cmp(&s3, &s2) == 1 && imdb_x_cmp(&s2, &s2) == 0);
    CHECK(imdb_x_comparable(IMDB_T_INT64, IMDB_T_FLOAT64) && !imdb_x_comparable(IMDB_T_TEXT, IMDB_T_INT64));
    /* through SQL: a filter never fails on a row's magnitude (m is 2^62) */
    imdb_db *db = with_one();
    CHECK(db);
    CELL("SELECT COUNT(*) FROM one WHERE m > 1.5e0 + 0", "1");
    CELL("SELECT COUNT(*) FROM one WHERE m + 0 < 1.5e0", "0");
    CELL("SELECT COUNT(*) FROM one WHERE d = 2.5 + 0", "1");
    CELL("SELECT COUNT(*) FROM one WHERE d * 2 = 5", "1");
    CELL("SELECT COUNT(*) FROM one WHERE s = s2", "0");
    CELL("SELECT COUNT(*) FROM one WHERE s < s2", "1");
    CELL("SELECT COUNT(*) FROM one WHERE n + 1 IS NULL", "1");
    CELL("SELECT COUNT(*) FROM one WHERE n + 1 IS NOT NULL", "0");
    CELL("SELECT COUNT(*) FROM one WHERE n + 1 = n + 1", "0"); /* unknown is not true */
    CELL("SELECT COUNT(*) FROM one WHERE d + 0 BETWEEN 2 AND 3", "1");
    CHECK(run("SELECT COUNT(*) FROM one WHERE s + 0 = 1") == IMDB_ERR_INVALID);
    CHECK(run("SELECT COUNT(*) FROM one WHERE s = d + 0") == IMDB_ERR_INVALID);
    CHECK(run("SELECT COUNT(*) FROM one WHERE COUNT(*) > 0") == IMDB_ERR_INVALID);
    done(db);
}

static void t_assign(void)
{
    imdb_db *db = with_one();
    CHECK(db);
    RUN("UPDATE one SET p = 1.005 + 0");
    CELL("SELECT p FROM one", "1.01"); /* half away from zero */
    RUN("UPDATE one SET p = -1.005 + 0");
    CELL("SELECT p FROM one", "-1.01");
    RUN("UPDATE one SET p = 1.0049999 + 0");
    CELL("SELECT p FROM one", "1.00");
    RUN("UPDATE one SET p = 7");
    CELL("SELECT p FROM one", "7.00");
    RUN("UPDATE one SET p = p / 3");
    CELL("SELECT p FROM one", "2.33");
    CHECK(run("UPDATE one SET p = 1.005") == IMDB_ERR_INVALID);          /* a literal that would round: refused */
    CHECK(run("UPDATE one SET p = 999.995 + 0") == IMDB_ERR_LIMIT);      /* 1000.00: past DECIMAL(5,2) */
    CHECK(run("UPDATE one SET n = 1.5 + 0") == IMDB_ERR_INVALID);        /* DECIMAL into INT64 */
    CHECK(run("UPDATE one SET d = f + 0") == IMDB_ERR_INVALID);          /* FLOAT64 into DECIMAL */
    CHECK(run("UPDATE one SET f = 9007199254740993 + 0") == IMDB_ERR_LIMIT);
    RUN("UPDATE one SET f = 9007199254740992 + 0");
    RUN("UPDATE one SET f = d + 0");
    CELL("SELECT f FROM one", "2.5");
    RUN("UPDATE one SET f = 0.0e0 * -1");
    CELL("SELECT f FROM one", "0");
    RUN("UPDATE one SET s = s2");
    CELL("SELECT s FROM one", "y");
    CHECK(run("UPDATE one SET s = d + 0") == IMDB_ERR_INVALID);
    CHECK(run("UPDATE one SET p = 1, p = 2") == IMDB_ERR_INVALID); /* a column set twice */
    done(db);
}

/* the user's example; SET reads the old row; a failure anywhere leaves every row as it was */
static void t_update(void)
{
    imdb_db *db = fresh();
    CHECK(db);
    RUN("SET cross_check = on");
    RUN("CREATE TABLE acct (id INT64 PRIMARY KEY, balance DECIMAL(12,2), a INT64, b INT64)");
    RUN("INSERT INTO acct VALUES (1, 250.00, 1, 10), (2, 80.50, 2, 0), (3, 0.00, 3, 30)");
    RUN("UPDATE acct SET balance = balance - 100 WHERE id = 1");
    CELL("SELECT balance FROM acct WHERE id = 1", "150.00");
    RUN("UPDATE acct SET a = b, b = a WHERE id = 1"); /* old values: swapped */
    CELL("SELECT a FROM acct WHERE id = 1", "10");
    CELL("SELECT b FROM acct WHERE id = 1", "1");
    CHECK(run("UPDATE acct SET a = 100 / b") == IMDB_ERR_INVALID); /* row 2's b is 0 */
    CELL("SELECT SUM(a) FROM acct", "15");                         /* 10 + 2 + 3: nothing changed */
    RUN("UPDATE acct SET a = 100 / b WHERE b != 0");
    CELL("SELECT SUM(a) FROM acct", "105"); /* 100 + 2 + 3 */
    RUN("BEGIN");
    RUN("UPDATE acct SET balance = balance * 2 WHERE id = 2");
    CHECK(run("UPDATE acct SET a = a / (b - b)") == IMDB_ERR_INVALID); /* the statement undone, the transaction kept */
    RUN("COMMIT");
    CELL("SELECT balance FROM acct WHERE id = 2", "161.00");
    CELL("SELECT SUM(a) FROM acct", "105");
    RUN("UPDATE acct SET balance = balance + 0.005 WHERE id = 3"); /* rounded on the way in */
    CELL("SELECT balance FROM acct WHERE id = 3", "0.01");
    done(db);
}

static void t_values(void)
{
    imdb_db *db = fresh();
    CHECK(db);
    RUN("CREATE TABLE t (id INT64 PRIMARY KEY, a INT64, d DECIMAL(10,2), f FLOAT64)");
    RUN("INSERT INTO t VALUES (1 + 2, 2 * -3, 10.00 / 4, 1.0e0 / 8), (4, -(1), 7 % 4, 2)");
    CELL("SELECT a FROM t WHERE id = 3", "-6");
    CELL("SELECT d FROM t WHERE id = 3", "2.50");
    CELL("SELECT f FROM t WHERE id = 3", "0.125");
    CELL("SELECT d FROM t WHERE id = 4", "3.00");
    CHECK(run("INSERT INTO t VALUES (5, a + 1, 0, 0)") == IMDB_ERR_INVALID); /* VALUES takes constants */
    CHECK(run("INSERT INTO t VALUES (5, -NULL, 0, 0)") == IMDB_ERR_INVALID);
    CHECK(run("INSERT INTO t VALUES (5, 1 / 0, 0, 0)") == IMDB_ERR_INVALID);
    CHECK(run("INSERT INTO t VALUES (5, 1, 0, 0), (6, 9223372036854775807 + 1, 0, 0)") == IMDB_ERR_LIMIT);
    CELL("SELECT COUNT(*) FROM t", "2"); /* the whole INSERT refused */
    imdb_value pv[2] = {{.type = IMDB_T_INT64, .i = 40}, {.type = IMDB_T_DECIMAL, .scale = 2, .i = 125}};
    const char *ins = "INSERT INTO t VALUES ($1 + 1, $1 * 2, $2 * 2, $2 + 0.0e0)";
    imdb_result r;
    imdb_err_clear(&g_e);
    OK(imdb_exec_one(&g_ss, ins, strlen(ins), pv, 2, &r, &g_e));
    imdb_result_free(&r);
    CELL("SELECT d FROM t WHERE id = 41", "2.50");
    CELL("SELECT f FROM t WHERE id = 41", "1.25");
    done(db);
}

static void t_items(void)
{
    imdb_db *db = fresh();
    CHECK(db);
    RUN("CREATE TABLE t (id INT64 PRIMARY KEY, a INT64, b INT64, s TEXT)");
    RUN("INSERT INTO t VALUES (1, 5, 1, 'p'), (2, 6, 2, 'q'), (3, 3, 3, 'r'), (4, 8, 4, 's')");
    imdb_result r;
    OK(q("SELECT id, a * b, -a, (a + b) / 2, s, 'k', 1.50 FROM t WHERE id <= 2", &r));
    CHECK(r.nrows == 2 && r.ncols == 7);
    CHECK(!strcmp(r.names[1], "a * b") && !strcmp(r.names[3], "(a + b) / 2") && !strcmp(r.names[5], "'k'"));
    CHECK(!strcmp(cell(&r, 0, 1), "5") && !strcmp(cell(&r, 1, 1), "12") && !strcmp(cell(&r, 1, 2), "-6"));
    CHECK(!strcmp(cell(&r, 0, 3), "3") && !strcmp(cell(&r, 1, 4), "q") && !strcmp(cell(&r, 1, 5), "k"));
    CHECK(!strcmp(cell(&r, 0, 6), "1.50"));
    imdb_result_free(&r);
    /* only the rows the result keeps are computed: row 3's a - b is 0 */
    OK(q("SELECT id, 10 / (a - b) FROM t LIMIT 2", &r));
    CHECK(r.nrows == 2);
    imdb_result_free(&r);
    CHECK(run("SELECT id, 10 / (a - b) FROM t") == IMDB_ERR_INVALID);
    /* a long item's name is cut at a character's end */
    OK(q("SELECT a + 1 + 2 + 3 + 4 + 5 + 6 + 7 + 8 + 9 + 10 + 11 + 12 + 13 + 14 + 15 + 16 + 17 + 18 + 19 + 20 FROM t "
         "WHERE id = 1",
         &r));
    size_t bad;
    CHECK(strlen(r.names[0]) <= IMDB_MAX_IDENT + 7 && imdb_utf8_valid((const uint8_t *)r.names[0], strlen(r.names[0]), &bad));
    CHECK(!strcmp(cell(&r, 0, 0), "215"));
    imdb_result_free(&r);
    CHECK(run("SELECT a + 1, COUNT(*) FROM t") == IMDB_ERR_INVALID); /* a column outside an aggregate, no GROUP BY */
    done(db);
}

/* a model row */
typedef struct mrow {
    int64_t id, g, a, b;
    bool bnull;
} mrow;

/* WHERE's trees on every read path, against the model: in memory and in the lake, cross-checked */
static void t_where_paths(void)
{
    imdb_db *db = fresh();
    CHECK(db);
    RUN("CREATE TABLE t (id INT64 PRIMARY KEY, g INT64, a INT64, b INT64)");
    RUN("CREATE INDEX t_g ON t (g)");
    RUN("SET cross_check = on");
    enum { N = 300 };
    mrow m[N];
    test_seed(1102);
    char sql[256];
    for (int i = 0; i < N; i++) {
        m[i].id = i + 1;
        m[i].g = (int64_t)(test_rand() % 7);
        m[i].a = (int64_t)(test_rand() % 2001) - 1000;
        m[i].bnull = test_rand() % 10 == 0;
        m[i].b = (int64_t)(test_rand() % 201) - 100;
        if (m[i].bnull) snprintf(sql, sizeof sql, "INSERT INTO t VALUES (%lld, %lld, %lld, NULL)", (long long)m[i].id,
                                 (long long)m[i].g, (long long)m[i].a);
        else snprintf(sql, sizeof sql, "INSERT INTO t VALUES (%lld, %lld, %lld, %lld)", (long long)m[i].id,
                      (long long)m[i].g, (long long)m[i].a, (long long)m[i].b);
        RUN(sql);
        if (i == N / 2) RUN("CHECKPOINT"); /* half the rows in the lake */
    }
    static const char *const paths[] = {"auto", "scan", "store", "index", "ordered"};
    for (int round = 0; round < 2; round++) {
        if (round) RUN("CHECKPOINT");
        for (size_t p = 0; p < sizeof paths / sizeof *paths; p++) {
            snprintf(sql, sizeof sql, "SET access_path = %s", paths[p]);
            RUN(sql);
            for (int64_t k = -40; k <= 40; k += 20) {
                /* a + b > k; g = 3 AND a * 2 < k + b; id = 7 AND a - b >= k; b IS NULL AND a + 0 > k */
                int64_t want[4] = {0, 0, 0, 0};
                for (int i = 0; i < N; i++) {
                    if (!m[i].bnull && m[i].a + m[i].b > k) want[0]++;
                    if (m[i].g == 3 && !m[i].bnull && m[i].a * 2 < k + m[i].b) want[1]++;
                    if (m[i].id == 7 && !m[i].bnull && m[i].a - m[i].b >= k) want[2]++;
                    if (m[i].bnull && m[i].a > k) want[3]++;
                }
                for (int f = 0; f < 4; f++) {
                    long long kk = (long long)k;
                    switch (f) { /* format strings stay literals */
                    case 0: snprintf(sql, sizeof sql, "SELECT COUNT(*) FROM t WHERE a + b > %lld", kk); break;
                    case 1: snprintf(sql, sizeof sql, "SELECT COUNT(*) FROM t WHERE g = 3 AND a * 2 < %lld + b", kk); break;
                    case 2: snprintf(sql, sizeof sql, "SELECT COUNT(*) FROM t WHERE id = 7 AND a - b >= %lld", kk); break;
                    default: snprintf(sql, sizeof sql, "SELECT COUNT(*) FROM t WHERE b IS NULL AND a + 0 > %lld", kk); break;
                    }
                    char w[24];
                    snprintf(w, sizeof w, "%lld", (long long)want[f]);
                    CELL(sql, w);
                }
                /* rows, not a count: the same set, by key */
                snprintf(sql, sizeof sql, "SELECT id, a + b FROM t WHERE g = 2 AND a + b > %lld", (long long)k);
                imdb_result r;
                OK(q(sql, &r));
                uint64_t row = 0;
                for (int i = 0; i < N; i++) {
                    if (m[i].g != 2 || m[i].bnull || m[i].a + m[i].b <= k) continue;
                    char a[24], s[24];
                    snprintf(a, sizeof a, "%lld", (long long)m[i].id);
                    snprintf(s, sizeof s, "%lld", (long long)(m[i].a + m[i].b));
                    CHECK(row < r.nrows && !strcmp(cell(&r, row, 0), a) && !strcmp(cell(&r, row, 1), s));
                    row++;
                }
                CHECK(row == r.nrows);
                imdb_result_free(&r);
            }
            /* a tree that fails on a row any path reaches fails on every path; none fails where no row reaches it */
            CHECK(run("SELECT COUNT(*) FROM t WHERE 10 / (a - a) > 0") == IMDB_ERR_INVALID);
            CELL("SELECT COUNT(*) FROM t WHERE id = -1 AND 10 / (a - a) > 0", "0");
            CELL("SELECT COUNT(*) FROM t WHERE g = 99 AND 10 / (a - a) > 0", "0");
            /* a constant against a column: flipped into an index's predicate */
            CELL("SELECT COUNT(*) FROM t WHERE 7 = id", "1");
            int64_t g4 = 0;
            for (int i = 0; i < N; i++) g4 += m[i].g == 4;
            char w4[24];
            snprintf(w4, sizeof w4, "%lld", (long long)g4);
            CELL("SELECT COUNT(*) FROM t WHERE 3 < g AND g < 5", w4);
        }
    }
    done(db);
}

/* WHERE's trees on the joined row: kept pairs and aggregates, INNER and LEFT, every plan, against the model */
static void t_join(void)
{
    imdb_db *db = fresh();
    CHECK(db);
    RUN("CREATE TABLE t (id INT64 PRIMARY KEY, a INT64)");
    RUN("CREATE TABLE u (id INT64 PRIMARY KEY, tid INT64, v INT64)");
    RUN("CREATE INDEX u_tid ON u (tid)");
    RUN("SET cross_check = on");
    enum { NT = 60, NU = 150 };
    int64_t ta[NT + 1], utid[NU], uv[NU];
    bool unull[NU];
    char sql[256];
    test_seed(1104);
    for (int i = 1; i <= NT; i++) {
        ta[i] = (int64_t)(test_rand() % 41) - 20;
        snprintf(sql, sizeof sql, "INSERT INTO t VALUES (%d, %lld)", i, (long long)ta[i]);
        RUN(sql);
    }
    for (int i = 0; i < NU; i++) {
        utid[i] = (int64_t)(test_rand() % (NT + 10)) + 1; /* some match no t */
        uv[i] = (int64_t)(test_rand() % 41) - 20;
        unull[i] = test_rand() % 8 == 0;
        if (unull[i]) snprintf(sql, sizeof sql, "INSERT INTO u VALUES (%d, %lld, NULL)", i + 1, (long long)utid[i]);
        else snprintf(sql, sizeof sql, "INSERT INTO u VALUES (%d, %lld, %lld)", i + 1, (long long)utid[i], (long long)uv[i]);
        RUN(sql);
    }
    static const char *const plans[] = {"auto", "hash", "index"};
    for (int round = 0; round < 2; round++) {
        if (round) RUN("CHECKPOINT");
        for (size_t p = 0; p < sizeof plans / sizeof *plans; p++) {
            snprintf(sql, sizeof sql, "SET join_plan = %s", plans[p]);
            RUN(sql);
            for (int64_t k = -10; k <= 10; k += 10) {
                int64_t inner = 0, left = 0, unmatched = 0;
                for (int i = 1; i <= NT; i++) {
                    bool any = false;
                    for (int j = 0; j < NU; j++) {
                        if (utid[j] != i) continue;
                        any = true;
                        if (!unull[j] && ta[i] + uv[j] > k) inner++;
                    }
                    if (!any) unmatched++; /* LEFT's NULL-extended row: t.a + NULL is unknown, filtered */
                }
                left = inner;
                (void)unmatched;
                char w[24];
                snprintf(w, sizeof w, "%lld", (long long)inner);
                snprintf(sql, sizeof sql, "SELECT COUNT(*) FROM t JOIN u ON t.id = u.tid WHERE t.a + u.v > %lld", (long long)k);
                CELL(sql, w);
                snprintf(sql, sizeof sql, "SELECT COUNT(*) FROM t LEFT JOIN u ON t.id = u.tid WHERE t.a + u.v > %lld",
                         (long long)k);
                snprintf(w, sizeof w, "%lld", (long long)left);
                CELL(sql, w);
                /* kept pairs: the rows themselves, and a tree item over both sides */
                snprintf(sql, sizeof sql,
                         "SELECT t.id, u.id, t.a * u.v FROM t JOIN u ON t.id = u.tid WHERE t.a + u.v > %lld AND t.id < 30",
                         (long long)k);
                imdb_result r;
                OK(q(sql, &r));
                uint64_t row = 0;
                for (int i = 1; i < 30; i++)
                    for (int j = 0; j < NU; j++) {
                        if (utid[j] != i || unull[j] || ta[i] + uv[j] <= k) continue;
                        char a[24], b[24], c[24];
                        snprintf(a, sizeof a, "%d", i);
                        snprintf(b, sizeof b, "%d", j + 1);
                        snprintf(c, sizeof c, "%lld", (long long)(ta[i] * uv[j]));
                        CHECK(row < r.nrows && !strcmp(cell(&r, row, 0), a) && !strcmp(cell(&r, row, 1), b) &&
                              !strcmp(cell(&r, row, 2), c));
                        row++;
                    }
                CHECK(row == r.nrows);
                imdb_result_free(&r);
            }
            /* a tree on one side alone, and one that fails on a joined row: every plan fails it */
            CELL("SELECT COUNT(*) FROM t JOIN u ON t.id = u.tid WHERE t.a * 0 = 0 AND u.id = 1", "1");
            CHECK(run("SELECT COUNT(*) FROM t JOIN u ON t.id = u.tid WHERE 1 / (t.a - t.a) = 0") == IMDB_ERR_INVALID);
        }
    }
    done(db);
}

/* the parser's bounds: a tree's height and terms, nesting, without recursion past them */
static void t_limits(void)
{
    sql_stmt st;
    imdb_err e = {0};
    imdb_buf b;
    imdb_buf_init(&b);
    imdb_buf_put_str(&b, "SELECT 1");
    for (int i = 1; i < (int)IMDB_MAX_EXPR_DEPTH; i++) imdb_buf_put_str(&b, " + 1"); /* height 64: taken */
    imdb_buf_put_str(&b, " FROM t");
    CHECK(imdb_sql_parse((const char *)b.p, b.len, &st, &e) == 0);
    imdb_sql_stmt_free(&st);
    imdb_buf_free(&b);
    imdb_buf_init(&b);
    imdb_buf_put_str(&b, "SELECT 1");
    for (int i = 0; i < (int)IMDB_MAX_EXPR_DEPTH; i++) imdb_buf_put_str(&b, " + 1"); /* 65 */
    imdb_buf_put_str(&b, " FROM t");
    imdb_err_clear(&e);
    CHECK(imdb_sql_parse((const char *)b.p, b.len, &st, &e) == IMDB_ERR_LIMIT);
    imdb_buf_free(&b);
    imdb_buf_init(&b); /* deep parentheses and signs: refused before the stack is */
    imdb_buf_put_str(&b, "SELECT ");
    for (int i = 0; i < 100000; i++) imdb_buf_put_str(&b, "(");
    imdb_err_clear(&e);
    CHECK(imdb_sql_parse((const char *)b.p, b.len, &st, &e) == IMDB_ERR_LIMIT);
    imdb_buf_free(&b);
    imdb_buf_init(&b);
    imdb_buf_put_str(&b, "SELECT ");
    for (int i = 0; i < 100000; i++) imdb_buf_put_str(&b, "- ");
    imdb_buf_put_str(&b, "a FROM t");
    imdb_err_clear(&e);
    CHECK(imdb_sql_parse((const char *)b.p, b.len, &st, &e) == IMDB_ERR_LIMIT);
    imdb_buf_free(&b);
    /* terms: VALUES of trees past IMDB_MAX_EXPR_NODES; literals take none */
    imdb_buf_init(&b);
    imdb_buf_put_str(&b, "INSERT INTO t VALUES ");
    for (int i = 0; i < 6000; i++) imdb_buf_printf(&b, "%s(%d, 1 + 1)", i ? "," : "", i);
    imdb_err_clear(&e);
    CHECK(imdb_sql_parse((const char *)b.p, b.len, &st, &e) == IMDB_ERR_LIMIT);
    imdb_buf_free(&b);
    imdb_buf_init(&b);
    imdb_buf_put_str(&b, "INSERT INTO t VALUES ");
    for (int i = 0; i < 20000; i++) imdb_buf_printf(&b, "%s(%d, -1)", i ? "," : "", i);
    imdb_err_clear(&e);
    CHECK(imdb_sql_parse((const char *)b.p, b.len, &st, &e) == 0 && st.nrows == 20000 && st.nex == 0);
    imdb_sql_stmt_free(&st);
    imdb_buf_free(&b);
    /* shapes today's statements had keep today's structures */
    const char *same[] = {"SELECT a, t.b, COUNT(*), SUM(c) FROM t WHERE a = 1 AND b BETWEEN -2 AND 3 AND c IS NULL",
                          "UPDATE t SET a = 1, b = 'x' WHERE id = 5", "INSERT INTO t VALUES (1, -2.5, 'x', TRUE, NULL)"};
    for (size_t i = 0; i < sizeof same / sizeof *same; i++) {
        imdb_err_clear(&e);
        CHECK(imdb_sql_parse(same[i], strlen(same[i]), &st, &e) == 0);
        for (uint16_t k = 0; k < st.nitems; k++) CHECK(!st.items[k].expr);
        for (uint16_t k = 0; k < st.nwhere; k++) CHECK(!st.where[k].lx && st.where[k].a.kind != LIT_EXPR);
        for (uint16_t k = 0; k < st.nset; k++) CHECK(st.set_vals[k].kind != LIT_EXPR);
        for (uint32_t k = 0; k < st.nrows * st.rowlen; k++) CHECK(st.vals[k].kind != LIT_EXPR);
        imdb_sql_stmt_free(&st);
    }
    const char *flip = "SELECT * FROM t WHERE 5 < a";
    imdb_err_clear(&e);
    CHECK(imdb_sql_parse(flip, strlen(flip), &st, &e) == 0 && !st.where[0].lx && st.where[0].op == CMP_GT &&
          !strcmp(st.where[0].col, "a"));
    imdb_sql_stmt_free(&st);
}

/* aggregates of trees and trees of aggregates: plain, grouped, in joins, on every path, against the model */
static void t_aggregates(void)
{
    imdb_db *db = fresh();
    CHECK(db);
    RUN("SET cross_check = on");
    RUN("CREATE TABLE s (id INT64 PRIMARY KEY, g INT64, qty INT64, price DECIMAL(10,2), f FLOAT64)");
    RUN("INSERT INTO s VALUES (1, 1, 3, 2.50, 0.5), (2, 1, 4, 1.25, 0.25), (3, 2, 10, 0.10, 1.5), (4, 2, NULL, 9.99, 2),"
        " (5, 3, 1, NULL, NULL)");
    CELL("SELECT SUM(qty * price) FROM s", "13.50");
    CELL("SELECT SUM(qty) / COUNT(*) FROM s", "3"); /* INT64: truncated, as SQL Server and SQLite do */
    CELL("SELECT SUM(qty) * 1.0 / COUNT(*) FROM s", "3.6000000");
    CELL("SELECT MAX(qty * 2) - MIN(qty) FROM s", "19");
    CELL("SELECT COUNT(qty * price) FROM s", "3");
    CELL("SELECT SUM(f * 2) FROM s", "8.5");
    CELL("SELECT MIN(-price) FROM s", "-9.99");
    CELL("SELECT SUM(qty * price) FROM s WHERE qty * price > 2", "12.50");
    CELL("SELECT SUM(qty * price) FROM s WHERE id > 100", "null");
    CELL("SELECT COUNT(*) + 1 FROM s WHERE id > 100", "1");
    imdb_result r;
    OK(q("SELECT g, SUM(qty * price), g * 10, SUM(f) / 2, COUNT(*), 7 FROM s GROUP BY g", &r));
    CHECK(r.nrows == 3 && !strcmp(r.names[1], "SUM(qty * price)") && !strcmp(r.names[2], "g * 10"));
    CHECK(!strcmp(cell(&r, 0, 1), "12.50") && !strcmp(cell(&r, 1, 1), "1.00") && !strcmp(cell(&r, 2, 1), "null"));
    CHECK(!strcmp(cell(&r, 0, 2), "10") && !strcmp(cell(&r, 2, 2), "30") && !strcmp(cell(&r, 0, 3), "0.375"));
    CHECK(!strcmp(cell(&r, 1, 3), "1.75") && !strcmp(cell(&r, 2, 3), "null") && !strcmp(cell(&r, 2, 4), "1"));
    CHECK(!strcmp(cell(&r, 0, 5), "7"));
    imdb_result_free(&r);
    CHECK(run("SELECT qty + 1, COUNT(*) FROM s") == IMDB_ERR_INVALID);            /* a column outside, no GROUP BY */
    CHECK(run("SELECT g, qty + SUM(qty) FROM s GROUP BY g") == IMDB_ERR_INVALID); /* not the GROUP BY column */
    CHECK(run("SELECT SUM(SUM(qty)) FROM s") == IMDB_ERR_INVALID);                 /* nested */
    CHECK(run("SELECT SUM(price) FROM s WHERE SUM(qty) > 1") == IMDB_ERR_INVALID); /* WHERE */
    CHECK(run("UPDATE s SET qty = COUNT(*)") == IMDB_ERR_INVALID);
    CHECK(run("SELECT SUM(qty / 0) FROM s") == IMDB_ERR_INVALID);
    CHECK(run("SELECT SUM(qty / 0) FROM s WHERE id > 100") == 0); /* no row reached it */
    /* a SUM of 38-digit values: checked, not wrapped */
    CHECK(run("SELECT SUM(price * 99999999999999999999999999999) FROM s") == IMDB_ERR_LIMIT);
    RUN("CREATE TABLE wide (id INT64 PRIMARY KEY, m INT64)");
    RUN("INSERT INTO wide VALUES (1, 4611686018427387904), (2, 4611686018427387904), (3, 4611686018427387904)");
    CELL("SELECT SUM(m) FROM wide", "13835058055282163712"); /* past int64: a wide cell */
    CHECK(run("SELECT -SUM(m) FROM wide") == IMDB_ERR_LIMIT);  /* an INT64 result: past int64 either way */
    CHECK(run("SELECT SUM(m) + 0 FROM wide") == IMDB_ERR_LIMIT);
    CELL("SELECT SUM(m) - SUM(m) FROM wide", "0");
    /* more aggregates than a SELECT list's slots */
    imdb_buf b;
    imdb_buf_init(&b);
    imdb_buf_put_str(&b, "SELECT 0");
    for (int i = 0; i < 70; i++) imdb_buf_put_str(&b, " + COUNT(*)");
    imdb_buf_put_str(&b, " FROM s");
    CHECK(imdb_buf_check(&b, &g_e) == 0);
    char *sq = malloc(b.len + 1);
    CHECK(sq);
    memcpy(sq, b.p, b.len);
    sq[b.len] = 0;
    imdb_buf_free(&b);
    int lrc = run(sq);
    free(sq);
    CHECK(lrc == IMDB_ERR_LIMIT);
    /* every path, in memory and in the lake, against the model */
    enum { N = 200 };
    int64_t mg[N], mq[N], mp[N];
    char sql[256];
    test_seed(1106);
    RUN("CREATE TABLE m (id INT64 PRIMARY KEY, g INT64, q INT64, p DECIMAL(8,2))");
    RUN("CREATE INDEX m_g ON m (g)");
    for (int i = 0; i < N; i++) {
        mg[i] = (int64_t)(test_rand() % 5);
        mq[i] = (int64_t)(test_rand() % 100);
        mp[i] = (int64_t)(test_rand() % 100000); /* cents */
        snprintf(sql, sizeof sql, "INSERT INTO m VALUES (%d, %lld, %lld, %lld.%02lld)", i + 1, (long long)mg[i],
                 (long long)mq[i], (long long)(mp[i] / 100), (long long)(mp[i] % 100));
        RUN(sql);
    }
    static const char *const paths[] = {"auto", "scan", "store", "ordered"};
    for (int round = 0; round < 2; round++) {
        if (round) RUN("CHECKPOINT");
        for (size_t p = 0; p < sizeof paths / sizeof *paths; p++) {
            snprintf(sql, sizeof sql, "SET access_path = %s", paths[p]);
            RUN(sql);
            OK(q("SELECT g, SUM(q * p), MAX(q - g), SUM(q) * 100 / COUNT(*) FROM m WHERE g >= 1 GROUP BY g", &r));
            CHECK(r.nrows == 4);
            for (int64_t g = 1; g <= 4; g++) {
                __int128 sum = 0;
                int64_t mx = INT64_MIN, qs = 0, cnt = 0;
                for (int i = 0; i < N; i++) {
                    if (mg[i] != g) continue;
                    sum += (__int128)mq[i] * mp[i];
                    if (mq[i] - g > mx) mx = mq[i] - g;
                    qs += mq[i];
                    cnt++;
                }
                char a[48], c[24], d[24];
                snprintf(a, sizeof a, "%lld.%02lld", (long long)(sum / 100), (long long)(sum % 100));
                snprintf(c, sizeof c, "%lld", (long long)mx);
                snprintf(d, sizeof d, "%lld", (long long)(cnt ? qs * 100 / cnt : 0));
                CHECK(!strcmp(cell(&r, (uint64_t)(g - 1), 1), a) && !strcmp(cell(&r, (uint64_t)(g - 1), 2), c));
                CHECK(!strcmp(cell(&r, (uint64_t)(g - 1), 3), d));
            }
            imdb_result_free(&r);
        }
    }
    /* in a join: grouped by the joined side, aggregates over both sides */
    RUN("SET access_path = auto");
    RUN("CREATE TABLE gn (id INT64 PRIMARY KEY, w INT64)");
    RUN("INSERT INTO gn VALUES (0, 7), (1, 11), (2, 13), (3, 17), (4, 19)");
    static const char *const plans[] = {"hash", "index", "auto"};
    for (size_t p = 0; p < sizeof plans / sizeof *plans; p++) {
        snprintf(sql, sizeof sql, "SET join_plan = %s", plans[p]);
        RUN(sql);
        OK(q("SELECT gn.id, SUM(m.q * gn.w) + gn.id, COUNT(*) FROM m JOIN gn ON m.g = gn.id GROUP BY gn.id", &r));
        CHECK(r.nrows == 5);
        for (int64_t g = 0; g <= 4; g++) {
            int64_t w = g == 0 ? 7 : g == 1 ? 11 : g == 2 ? 13 : g == 3 ? 17 : 19, s = 0;
            for (int i = 0; i < N; i++)
                if (mg[i] == g) s += mq[i] * w;
            char a[24];
            snprintf(a, sizeof a, "%lld", (long long)(s + g));
            CHECK(!strcmp(cell(&r, (uint64_t)g, 1), a));
        }
        imdb_result_free(&r);
        OK(q("SELECT SUM(m.q * gn.w) - SUM(m.q) * 0 FROM m JOIN gn ON m.g = gn.id WHERE m.q * 2 > gn.w", &r));
        int64_t s = 0;
        for (int i = 0; i < N; i++) {
            int64_t w = mg[i] == 0 ? 7 : mg[i] == 1 ? 11 : mg[i] == 2 ? 13 : mg[i] == 3 ? 17 : 19;
            if (mq[i] * 2 > w) s += mq[i] * w;
        }
        char a[24];
        snprintf(a, sizeof a, "%lld", (long long)s);
        CHECK(r.nrows == 1 && !strcmp(cell(&r, 0, 0), a));
        imdb_result_free(&r);
    }
    done(db);
}

/* two statements' rows, cell by cell */
static int same_rows(const char *s1, const char *s2, uint64_t *nrows)
{
    imdb_result a, b;
    if (q(s1, &a)) return -1;
    if (q(s2, &b)) {
        imdb_result_free(&a);
        return -2;
    }
    int rc = a.nrows == b.nrows && a.ncols == b.ncols ? 0 : 1;
    for (uint64_t i = 0; !rc && i < a.nrows; i++)
        for (uint16_t c = 0; !rc && c < a.ncols; c++)
            if (strcmp(cell(&a, i, c), cell(&b, i, c))) rc = 1;
    *nrows = a.nrows;
    imdb_result_free(&a);
    imdb_result_free(&b);
    return rc;
}

/* col op literal with a literal of another numeric kind than the column's (1.25 for an INT64): no longer refused, it
 * answers exactly as the tree col + 0 op literal does, on every path, in memory and in the lake, and in joins */
static void t_mixed_literals(void)
{
    imdb_db *db = fresh();
    CHECK(db);
    RUN("CREATE TABLE t (id INT64 PRIMARY KEY, g INT64, d DECIMAL(10,2), f FLOAT64)");
    RUN("CREATE INDEX t_g ON t (g)");
    RUN("CREATE TABLE u (id INT64 PRIMARY KEY, tid INT64, v INT64)");
    RUN("SET cross_check = on");
    char sql[256];
    test_seed(1108);
    for (int i = 1; i <= 120; i++) {
        snprintf(sql, sizeof sql, "INSERT INTO t VALUES (%d, %d, %d.%02d, %d.25)", i, (int)(test_rand() % 9) - 4,
                 (int)(test_rand() % 7) - 3, (int)(test_rand() % 100), (int)(test_rand() % 9) - 4);
        RUN(sql);
        snprintf(sql, sizeof sql, "INSERT INTO u VALUES (%d, %d, %d)", i, (int)(test_rand() % 130) + 1,
                 (int)(test_rand() % 9) - 4);
        RUN(sql);
        if (i == 60) RUN("CHECKPOINT");
    }
    static const char *const pairs[][2] = {
        {"SELECT id FROM t WHERE g <= -1.25", "SELECT id FROM t WHERE g + 0 <= -1.25"},
        {"SELECT id FROM t WHERE -1.25 >= g", "SELECT id FROM t WHERE g + 0 <= -1.25"},
        {"SELECT id FROM t WHERE g = 2.0", "SELECT id FROM t WHERE g + 0 = 2.0"},
        {"SELECT id FROM t WHERE g = 2.5", "SELECT id FROM t WHERE g + 0 = 2.5"},
        {"SELECT id FROM t WHERE g != 2.0", "SELECT id FROM t WHERE g + 0 != 2.0"},
        {"SELECT id FROM t WHERE g BETWEEN -1.5 AND 0.5", "SELECT id FROM t WHERE g + 0 BETWEEN -1.5 AND 0.5"},
        {"SELECT id FROM t WHERE g < 2.5e0 AND g > -2.5e0", "SELECT id FROM t WHERE g + 0 < 2.5e0 AND g + 0 > -2.5e0"},
        {"SELECT id FROM t WHERE d > 1.005", "SELECT id FROM t WHERE d + 0 > 1.005"},
        {"SELECT id FROM t WHERE d <= -0.5e0", "SELECT id FROM t WHERE d + 0 <= -0.5e0"},
        {"SELECT id FROM t WHERE g = 1 AND d < 0.001", "SELECT id FROM t WHERE g = 1 AND d + 0 < 0.001"},
        {"SELECT t.id, u.id FROM t JOIN u ON t.id = u.tid WHERE t.g >= 0.5 AND u.v < 1.5",
         "SELECT t.id, u.id FROM t JOIN u ON t.id = u.tid WHERE t.g + 0 >= 0.5 AND u.v + 0 < 1.5"},
        {"SELECT t.id, u.v FROM t LEFT JOIN u ON t.id = u.tid WHERE u.v > 1.5",
         "SELECT t.id, u.v FROM t LEFT JOIN u ON t.id = u.tid WHERE u.v + 0 > 1.5"},
        {"SELECT COUNT(*) FROM t WHERE g > -0.5", "SELECT COUNT(*) FROM t WHERE g >= 0"},
    };
    static const char *const paths[] = {"auto", "scan", "store", "index", "ordered"};
    for (int round = 0; round < 2; round++) {
        if (round) RUN("CHECKPOINT");
        for (size_t p = 0; p < sizeof paths / sizeof *paths; p++) {
            snprintf(sql, sizeof sql, "SET access_path = %s", paths[p]);
            RUN(sql);
            for (size_t i = 0; i < sizeof pairs / sizeof *pairs; i++) {
                uint64_t n = 0;
                int rc = same_rows(pairs[i][0], pairs[i][1], &n);
                if (rc) {
                    char m_[600];
                    snprintf(m_, sizeof m_, "%s (%s): rc %d (%s)", pairs[i][0], paths[p], rc, g_e.msg);
                    test_fail(__FILE__, __LINE__, m_);
                    return;
                }
                CHECK(n > 0 || i == 3); /* each matches rows, but g = 2.5, which none can */
            }
        }
    }
    /* still refused: not numbers, or not comparable */
    CHECK(run("SELECT id FROM t WHERE g = 'x'") == IMDB_ERR_INVALID);
    CHECK(run("SELECT id FROM t WHERE g = TRUE") == IMDB_ERR_INVALID);
    CHECK(run("SELECT id FROM t WHERE g = NULL") == IMDB_ERR_INVALID);
    done(db);
}

/* ---- 1c: OR, NOT, three-valued logic ------------------------------------------------------------------------- */

/* the truth tables: AND, OR, NOT over TRUE, FALSE and UNKNOWN (NULL) */
static void t_truth(void)
{
    imdb_db *db = fresh();
    CHECK(db);
    RUN("CREATE TABLE b (id INT64 PRIMARY KEY, p BOOL, q BOOL)");
    RUN("INSERT INTO b VALUES (1, true, true), (2, true, false), (3, true, NULL), (4, false, true), (5, false, false),"
        " (6, false, NULL), (7, NULL, true), (8, NULL, false), (9, NULL, NULL)");
    RUN("SET cross_check = on");
    static const char *const want[9][4] = { /* p AND q, p OR q, NOT p, NOT (p AND q) */
        {"true", "true", "false", "false"},  {"false", "true", "false", "true"}, {"null", "true", "false", "null"},
        {"false", "true", "true", "true"},   {"false", "false", "true", "true"}, {"false", "null", "true", "true"},
        {"null", "true", "null", "null"},   {"false", "null", "null", "true"},  {"null", "null", "null", "null"}};
    imdb_result r;
    OK(q("SELECT p AND q, p OR q, NOT p, NOT (p AND q) FROM b", &r));
    CHECK(r.nrows == 9);
    for (uint64_t i = 0; i < 9; i++)
        for (uint16_t c = 0; c < 4; c++)
            if (strcmp(cell(&r, i, c), want[i][c])) {
                char m_[200];
                snprintf(m_, sizeof m_, "row %llu column %u: %s, want %s", (unsigned long long)i + 1, c, cell(&r, i, c),
                         want[i][c]);
                imdb_result_free(&r);
                test_fail(__FILE__, __LINE__, m_);
                return;
            }
    imdb_result_free(&r);
    CELL("SELECT COUNT(*) FROM b WHERE p OR q", "5");            /* TRUE only: 1-4, 7 */
    CELL("SELECT COUNT(*) FROM b WHERE NOT (p OR q)", "1");      /* 5 */
    CELL("SELECT COUNT(*) FROM b WHERE p AND NOT q", "1");       /* 2 */
    CELL("SELECT COUNT(*) FROM b WHERE NOT p IS NULL", "6");     /* NOT (p IS NULL): never unknown */
    CELL("SELECT COUNT(*) FROM b WHERE p = q", "2");             /* 1, 5 */
    CELL("SELECT COUNT(*) FROM b WHERE p != q OR p IS NULL", "5"); /* 2, 4, 7-9 */
    done(db);
}

/* left to right, stopping once decided: what PostgreSQL, MySQL and SQLite do inside an expression */
static void t_short_circuit(void)
{
    imdb_db *db = fresh();
    CHECK(db);
    RUN("CREATE TABLE t (id INT64 PRIMARY KEY, a INT64, b INT64)");
    RUN("INSERT INTO t VALUES (1, 0, NULL), (2, 2, 7), (3, NULL, 10), (4, 5, 1)");
    RUN("SET cross_check = on");
    CELL("SELECT COUNT(*) FROM t WHERE a = 0 OR 10 / a > 1", "3");   /* 1 (stops), 2, 4; 3 unknown */
    CELL("SELECT COUNT(*) FROM t WHERE a != 0 AND 10 / a > 1", "2"); /* 2, 4 */
    CHECK(run("SELECT COUNT(*) FROM t WHERE 10 / a > 1 OR a = 0") == IMDB_ERR_INVALID);   /* row 1 divides first */
    /* a plain col op literal is a bound predicate, applied by the read path before any residual: a != 0 comes first
     * though written second (SQL fixes no order; PostgreSQL may raise here; imagedb's never depends on the plan) */
    CELL("SELECT COUNT(*) FROM t WHERE 10 / a > 1 AND a != 0", "2");
    CHECK(run("SELECT COUNT(*) FROM t WHERE 10 / a > 1 AND a + 0 != 0") == IMDB_ERR_INVALID); /* both residuals */
    CELL("SELECT COUNT(*) FROM t WHERE id = 1 AND (a = 0 OR 10 / a > 1)", "1");
    CHECK(run("SELECT COUNT(*) FROM t WHERE id = 1 AND (a = 1 OR 10 / a > 1)") == IMDB_ERR_INVALID); /* goes on */
    /* UNKNOWN does not stop either: row 3's a is NULL, so a = 0 is unknown and 10 / a is computed (NULL, no error) */
    CELL("SELECT COUNT(*) FROM t WHERE id = 3 AND (a = 0 OR 10 / a > 1)", "0");
    /* BETWEEN's operands all computed; under NOT, three-valued: 5 BETWEEN 10 AND NULL is FALSE, so NOT is TRUE */
    CELL("SELECT COUNT(*) FROM t WHERE id = 1 AND NOT (5 BETWEEN 10 AND b)", "1");
    CELL("SELECT COUNT(*) FROM t WHERE id = 1 AND NOT (5 BETWEEN 1 AND b)", "0"); /* TRUE AND unknown: unknown */
    CELL("SELECT COUNT(*) FROM t WHERE id = 1 AND (5 BETWEEN 1 AND b) IS NULL", "1");
    done(db);
}

/* a 3VL model's value: 1, 0, -1 (unknown) */
static int m_and(int x, int y) { return x == 0 || y == 0 ? 0 : x < 0 || y < 0 ? -1 : 1; }
static int m_or(int x, int y) { return x == 1 || y == 1 ? 1 : x < 0 || y < 0 ? -1 : 0; }
static int m_not(int x) { return x < 0 ? -1 : !x; }
static int m_cmp(bool xn, int64_t x, bool yn, int64_t y, int op) /* 0 =, 1 <, 2 > */
{
    if (xn || yn) return -1;
    return op == 0 ? x == y : op == 1 ? x < y : x > y;
}

typedef struct brow {
    int64_t id, g, a, b;
    bool an, bn;
} brow;

/* OR and NOT on every path, in memory and in the lake, cross-checked, against the model; in UPDATE, DELETE, ERASE */
static void t_or_not_paths(void)
{
    imdb_db *db = fresh();
    CHECK(db);
    RUN("CREATE TABLE t (id INT64 PRIMARY KEY, g INT64, a INT64, b INT64)");
    RUN("CREATE INDEX t_g ON t (g)");
    RUN("SET cross_check = on");
    enum { N = 240 };
    brow m[N];
    char sql[320];
    test_seed(1110);
    for (int i = 0; i < N; i++) {
        m[i].id = i + 1;
        m[i].g = (int64_t)(test_rand() % 5);
        m[i].an = test_rand() % 6 == 0;
        m[i].bn = test_rand() % 6 == 0;
        m[i].a = (int64_t)(test_rand() % 9);
        m[i].b = (int64_t)(test_rand() % 9);
        char av[24], bv[24];
        snprintf(av, sizeof av, "%lld", (long long)m[i].a);
        snprintf(bv, sizeof bv, "%lld", (long long)m[i].b);
        snprintf(sql, sizeof sql, "INSERT INTO t VALUES (%lld, %lld, %s, %s)", (long long)m[i].id, (long long)m[i].g,
                 m[i].an ? "NULL" : av, m[i].bn ? "NULL" : bv);
        RUN(sql);
        if (i == N / 2) RUN("CHECKPOINT");
    }
    static const char *const conds[] = {
        "a = 1 OR b = 2",
        "NOT (a = 1 OR b IS NULL)",
        "(a > 2 AND b < 5) OR NOT g = 3",
        "NOT (a BETWEEN 2 AND 6) OR b = a",
        "g = 2 AND (a = 1 OR a = 3)",
        "NOT NOT a = 1",
        "g = 1 AND NOT (b > 4 AND a < 3)",
    };
    static const char *const paths[] = {"auto", "scan", "store", "index", "ordered"};
    for (int round = 0; round < 2; round++) {
        if (round) RUN("CHECKPOINT");
        for (size_t p = 0; p < sizeof paths / sizeof *paths; p++) {
            snprintf(sql, sizeof sql, "SET access_path = %s", paths[p]);
            RUN(sql);
            for (size_t c = 0; c < sizeof conds / sizeof *conds; c++) {
                snprintf(sql, sizeof sql, "SELECT id FROM t WHERE %s", conds[c]);
                imdb_result r;
                OK(q(sql, &r));
                uint64_t row = 0;
                for (int i = 0; i < N; i++) {
                    const brow *w = &m[i];
                    int a1 = m_cmp(w->an, w->a, false, 1, 0), b2 = m_cmp(w->bn, w->b, false, 2, 0), v;
                    switch (c) {
                    case 0: v = m_or(a1, b2); break;
                    case 1: v = m_not(m_or(a1, w->bn)); break;
                    case 2: v = m_or(m_and(m_cmp(w->an, w->a, false, 2, 2), m_cmp(w->bn, w->b, false, 5, 1)), m_not(w->g == 3)); break;
                    case 3: {
                        int btw = m_and(m_not(m_cmp(w->an, w->a, false, 2, 1)), m_not(m_cmp(w->an, w->a, false, 6, 2)));
                        v = m_or(m_not(btw), m_cmp(w->bn, w->b, w->an, w->a, 0));
                        break;
                    }
                    case 4: v = m_and(w->g == 2, m_or(a1, m_cmp(w->an, w->a, false, 3, 0))); break;
                    case 5: v = m_not(m_not(a1)); break;
                    default: v = m_and(w->g == 1, m_not(m_and(m_cmp(w->bn, w->b, false, 4, 2), m_cmp(w->an, w->a, false, 3, 1)))); break;
                    }
                    if (v != 1) continue;
                    char id[24];
                    snprintf(id, sizeof id, "%lld", (long long)w->id);
                    if (row >= r.nrows || strcmp(cell(&r, row, 0), id)) {
                        char m_[600];
                        snprintf(m_, sizeof m_, "%s (%s): row %llu is not id %s", conds[c], paths[p], (unsigned long long)row, id);
                        imdb_result_free(&r);
                        test_fail(__FILE__, __LINE__, m_);
                        return;
                    }
                    row++;
                }
                if (row != r.nrows) {
                    char m_[600];
                    snprintf(m_, sizeof m_, "%s (%s): %llu rows, the model %llu", conds[c], paths[p],
                             (unsigned long long)r.nrows, (unsigned long long)row);
                    imdb_result_free(&r);
                    test_fail(__FILE__, __LINE__, m_);
                    return;
                }
                imdb_result_free(&r);
            }
        }
    }
    RUN("SET access_path = auto");
    /* DML: the rows an OR picks, changed, counted; the model follows */
    int64_t up = 0, del = 0;
    for (int i = 0; i < N; i++) up += m_or(m_cmp(m[i].an, m[i].a, false, 0, 0), m[i].g == 4) == 1;
    snprintf(sql, sizeof sql, "%lld", (long long)up);
    imdb_result r;
    OK(q("UPDATE t SET b = 100 WHERE a = 0 OR g = 4", &r));
    char st[48];
    snprintf(st, sizeof st, "UPDATE %lld", (long long)up);
    CHECK(!strcmp(r.status, st));
    imdb_result_free(&r);
    for (int i = 0; i < N; i++)
        if (m_or(m_cmp(m[i].an, m[i].a, false, 0, 0), m[i].g == 4) == 1) m[i].b = 100, m[i].bn = false;
    for (int i = 0; i < N; i++) del += m_not(m_or(m_cmp(m[i].bn, m[i].b, false, 100, 0), m[i].an)) == 1;
    OK(q("DELETE FROM t WHERE NOT (b = 100 OR a IS NULL)", &r));
    snprintf(st, sizeof st, "DELETE %lld", (long long)del);
    CHECK(!strcmp(r.status, st));
    imdb_result_free(&r);
    snprintf(sql, sizeof sql, "%lld", (long long)(N - del));
    CELL("SELECT COUNT(*) FROM t", sql);
    OK(q("ERASE FROM t WHERE g = 0 OR NOT b = 100", &r));
    imdb_result_free(&r);
    CELL("SELECT COUNT(*) FROM t WHERE g = 0 OR NOT b = 100", "0");
    done(db);
}

/* OR and NOT on joined rows: across both sides, LEFT's NULL-extended side unknown; every plan */
static void t_or_not_join(void)
{
    imdb_db *db = fresh();
    CHECK(db);
    RUN("CREATE TABLE t (id INT64 PRIMARY KEY, a INT64)");
    RUN("CREATE TABLE u (id INT64 PRIMARY KEY, tid INT64, v INT64)");
    RUN("CREATE INDEX u_tid ON u (tid)");
    RUN("SET cross_check = on");
    RUN("INSERT INTO t VALUES (1, 1), (2, 2), (3, 3), (4, NULL)");
    RUN("INSERT INTO u VALUES (10, 1, 5), (11, 1, 6), (12, 2, 5), (13, 9, 5), (14, 4, NULL)");
    static const char *const plans[] = {"auto", "hash", "index"};
    char sql[200];
    for (size_t p = 0; p < sizeof plans / sizeof *plans; p++) {
        snprintf(sql, sizeof sql, "SET join_plan = %s", plans[p]);
        RUN(sql);
        CELL("SELECT COUNT(*) FROM t JOIN u ON t.id = u.tid WHERE t.a = 2 OR u.v = 6", "2");       /* (2,12), (1,11) */
        CELL("SELECT COUNT(*) FROM t JOIN u ON t.id = u.tid WHERE NOT (t.a = 1 AND u.v = 5)", "2"); /* 11, 12; 14 unknown */
        CELL("SELECT COUNT(*) FROM t LEFT JOIN u ON t.id = u.tid WHERE NOT u.v = 5", "1");          /* 11; 3 unknown */
        CELL("SELECT COUNT(*) FROM t LEFT JOIN u ON t.id = u.tid WHERE u.v IS NULL OR u.v = 6", "3"); /* 3, 14, 11 */
        CELL("SELECT COUNT(*) FROM t LEFT JOIN u ON t.id = u.tid WHERE t.a = 3 OR u.id = 10", "2");
    }
    done(db);
}

/* booleans as values: items, SET, comparisons of them; and the parser's bounds over NOT and OR */
static void t_bool_values(void)
{
    imdb_db *db = fresh();
    CHECK(db);
    RUN("CREATE TABLE t (id INT64 PRIMARY KEY, a INT64, k BOOL)");
    RUN("INSERT INTO t VALUES (1, 1, NULL), (2, 5, NULL)");
    RUN("UPDATE t SET k = a > 2");
    CELL("SELECT COUNT(*) FROM t WHERE k", "1");
    CELL("SELECT COUNT(*) FROM t WHERE NOT k", "1");
    RUN("UPDATE t SET k = NOT k OR a = 1");
    CELL("SELECT k FROM t WHERE id = 1", "true");
    CELL("SELECT k FROM t WHERE id = 2", "false");
    CELL("SELECT COUNT(*) FROM t WHERE (a > 2) = k", "0");
    CELL("SELECT COUNT(*) FROM t WHERE TRUE", "2");
    CELL("SELECT COUNT(*) FROM t WHERE FALSE OR a = 5", "1");
    CHECK(run("SELECT COUNT(*) FROM t WHERE a") == IMDB_ERR_INVALID);        /* not a condition */
    CHECK(run("SELECT COUNT(*) FROM t WHERE a = 1 OR a") == IMDB_ERR_INVALID);
    CHECK(run("SELECT COUNT(*) FROM t WHERE k < (a > 1)") == IMDB_ERR_INVALID); /* BOOL: = and != only */
    CHECK(run("SELECT a + (a > 1) FROM t") == IMDB_ERR_INVALID);
    CHECK(run("UPDATE t SET a = a > 1") == IMDB_ERR_INVALID);
    sql_stmt st;
    imdb_err e = {0};
    imdb_buf b;
    imdb_buf_init(&b);
    imdb_buf_put_str(&b, "SELECT * FROM t WHERE ");
    for (int i = 0; i < 100000; i++) imdb_buf_put_str(&b, "NOT ");
    imdb_buf_put_str(&b, "a = 1");
    CHECK(imdb_sql_parse((const char *)b.p, b.len, &st, &e) == IMDB_ERR_LIMIT); /* no recursion past the bound */
    imdb_buf_free(&b);
    imdb_buf_init(&b);
    imdb_buf_put_str(&b, "SELECT * FROM t WHERE a = 1");
    for (int i = 0; i < 70; i++) imdb_buf_put_str(&b, " OR a = 1");
    imdb_err_clear(&e);
    CHECK(imdb_sql_parse((const char *)b.p, b.len, &st, &e) == IMDB_ERR_LIMIT); /* a tree's height */
    imdb_buf_free(&b);
    imdb_buf_init(&b); /* 40 ANDs are 40 conjuncts: past IMDB_MAX_PREDICATES as before */
    imdb_buf_put_str(&b, "SELECT * FROM t WHERE a = 1");
    for (int i = 0; i < 40; i++) imdb_buf_put_str(&b, " AND a = 1");
    imdb_err_clear(&e);
    CHECK(imdb_sql_parse((const char *)b.p, b.len, &st, &e) == IMDB_ERR_LIMIT);
    imdb_buf_free(&b);
    const char *mixed = "SELECT * FROM t WHERE a = 1 AND (a = 2 OR a = 3) AND 4 < a AND NOT a = 5";
    imdb_err_clear(&e);
    CHECK(imdb_sql_parse(mixed, strlen(mixed), &st, &e) == 0 && st.nwhere == 4);
    CHECK(!st.where[0].lx && st.where[1].lx && !st.where[2].lx && st.where[2].op == CMP_GT && st.where[3].lx);
    imdb_sql_stmt_free(&st);
    done(db);
}

/* a string literal against a TIMESTAMP inside a condition is a timestamp (as in today's form); comparisons over
 * aggregates as items */
static void t_cond_timestamps(void)
{
    imdb_db *db = fresh();
    CHECK(db);
    RUN("CREATE TABLE t (id INT64 PRIMARY KEY, g INT64, a INT64, ts TIMESTAMP)");
    RUN("CREATE INDEX t_ts ON t (ts)");
    RUN("SET cross_check = on");
    RUN("INSERT INTO t VALUES (1, 1, 1, '2025-12-31 23:59:59'), (2, 1, 2, '2026-01-01'), (3, 2, 3, '2026-06-30 12:00:00'),"
        " (4, 2, 1, NULL), (5, 3, 9, '2027-01-01')");
    RUN("CHECKPOINT");
    RUN("INSERT INTO t VALUES (6, 3, 5, '2026-01-01 00:00:00.000001')");
    static const char *const pairs[][2] = {
        {"SELECT id FROM t WHERE ts >= '2026-01-01' OR a = 1", "SELECT id FROM t WHERE ts >= TIMESTAMP '2026-01-01' OR a = 1"},
        {"SELECT id FROM t WHERE '2026-01-01' <= ts OR a = 9", "SELECT id FROM t WHERE ts >= TIMESTAMP '2026-01-01' OR a = 9"},
        {"SELECT id FROM t WHERE NOT (ts BETWEEN '2026-01-01' AND '2026-12-31')",
         "SELECT id FROM t WHERE NOT (ts BETWEEN TIMESTAMP '2026-01-01' AND TIMESTAMP '2026-12-31')"},
        {"SELECT id FROM t WHERE ts > '2026-01-01' AND (g = 2 OR g = 3)", "SELECT id FROM t WHERE ts > TIMESTAMP '2026-01-01' AND (g = 2 OR g = 3)"},
        {"SELECT id, ts < '2026-01-01' FROM t", "SELECT id, ts < TIMESTAMP '2026-01-01' FROM t"},
    };
    static const char *const paths[] = {"auto", "scan", "store", "ordered"};
    char sql[64];
    for (size_t p = 0; p < sizeof paths / sizeof *paths; p++) {
        snprintf(sql, sizeof sql, "SET access_path = %s", paths[p]);
        RUN(sql);
        for (size_t i = 0; i < sizeof pairs / sizeof *pairs; i++) {
            uint64_t nr = 0;
            int rc = same_rows(pairs[i][0], pairs[i][1], &nr);
            if (rc || !nr) {
                char m_[400];
                snprintf(m_, sizeof m_, "%s (%s): rc %d, %llu rows (%s)", pairs[i][0], paths[p], rc, (unsigned long long)nr,
                         g_e.msg);
                test_fail(__FILE__, __LINE__, m_);
                return;
            }
        }
    }
    RUN("SET access_path = auto");
    CELL("SELECT COUNT(*) FROM t WHERE ts >= '2026-01-01' OR a = 1", "6"); /* 2, 3, 5, 6 by ts; 1, 4 by a (4's ts unknown) */
    CHECK(run("SELECT id FROM t WHERE ts > '2026-02-30' OR a = 1") == IMDB_ERR_INVALID); /* not a date */
    CHECK(run("SELECT id FROM t WHERE ts > 'soon' OR a = 1") == IMDB_ERR_INVALID);
    CHECK(run("SELECT id FROM t WHERE ts > 5 OR a = 1") == IMDB_ERR_INVALID); /* a number: not converted */
    /* comparisons over aggregates as items: the slots under an EX_CMP */
    imdb_result r;
    OK(q("SELECT COUNT(*) > 5, MAX(a) > MIN(g), NOT (SUM(a) = 21), COUNT(ts) = COUNT(*) FROM t", &r));
    CHECK(r.nrows == 1 && !strcmp(cell(&r, 0, 0), "true") && !strcmp(cell(&r, 0, 1), "true"));
    CHECK(!strcmp(cell(&r, 0, 2), "false") && !strcmp(cell(&r, 0, 3), "false")); /* SUM 21; one ts NULL */
    imdb_result_free(&r);
    OK(q("SELECT g, COUNT(*) >= 2, MAX(ts) > '2026-03-01', g = 2 OR SUM(a) > 10 FROM t GROUP BY g", &r));
    CHECK(r.nrows == 3);
    CHECK(!strcmp(cell(&r, 0, 1), "true") && !strcmp(cell(&r, 0, 2), "false") && !strcmp(cell(&r, 0, 3), "false"));
    CHECK(!strcmp(cell(&r, 1, 2), "true") && !strcmp(cell(&r, 1, 3), "true"));  /* g 2: MAX 2026-06-30 */
    CHECK(!strcmp(cell(&r, 2, 2), "true") && !strcmp(cell(&r, 2, 3), "true"));  /* g 3: SUM 14 */
    imdb_result_free(&r);
    CHECK(run("SELECT g, a > 1 FROM t GROUP BY g") == IMDB_ERR_INVALID); /* a outside an aggregate */
    done(db);
}

/* ---- 1d: ORDER BY, OFFSET, DISTINCT ------------------------------------------------------------------------------ */

typedef struct orow {
    int64_t id, g, a, b;
    bool an, bn;
    char s[8];
    bool sn;
} orow;

static const orow *g_om;
static int g_okind; /* which order the model sorts by */

/* a key's comparison: NULLs placed by nf whatever the direction, else desc reverses */
static int ocmp(bool xn, int64_t x, bool yn, int64_t y, bool desc, bool nf)
{
    if (xn || yn) return xn == yn ? 0 : (xn ? 1 : -1) * (nf ? -1 : 1);
    int r = x < y ? -1 : x > y;
    return desc ? -r : r;
}

static int ostr(const orow *p, const orow *q, bool desc, bool nf)
{
    if (p->sn || q->sn) return p->sn == q->sn ? 0 : (p->sn ? 1 : -1) * (nf ? -1 : 1);
    int r = strcmp(p->s, q->s);
    r = r < 0 ? -1 : r > 0;
    return desc ? -r : r;
}

static int cmp_model(const void *pa, const void *pb)
{
    const orow *p = &g_om[*(const int *)pa], *q = &g_om[*(const int *)pb];
    int r = 0;
    switch (g_okind) {
    case 0: r = ocmp(p->an, p->a, q->an, q->a, false, false); break;                      /* a */
    case 1: r = ocmp(p->an, p->a, q->an, q->a, true, true); break;                        /* a DESC */
    case 2: r = ocmp(p->an, p->a, q->an, q->a, false, true); break;                       /* a NULLS FIRST */
    case 3:                                                                               /* a DESC NULLS LAST, id DESC */
        r = ocmp(p->an, p->a, q->an, q->a, true, false);
        if (!r) r = ocmp(false, p->id, false, q->id, true, false);
        break;
    case 4:                                                                               /* s, a DESC */
        r = ostr(p, q, false, false);
        if (!r) r = ocmp(p->an, p->a, q->an, q->a, true, true);
        break;
    case 5: r = ocmp(p->an || p->bn, p->a + p->b, q->an || q->bn, q->a + q->b, false, false); break; /* a + b */
    case 6:                                                                               /* g DESC, b */
        r = ocmp(false, p->g, false, q->g, true, true);
        if (!r) r = ocmp(p->bn, p->b, q->bn, q->b, false, false);
        break;
    default: break;
    }
    if (r) return r;
    return p->id < q->id ? -1 : p->id > q->id; /* the primary key breaks ties */
}

/* ORDER BY on every path, in memory and in the lake, cross-checked, against the model's sort; with LIMIT and OFFSET */
static void t_order_paths(void)
{
    imdb_db *db = fresh();
    CHECK(db);
    RUN("CREATE TABLE t (id INT64 PRIMARY KEY, g INT64, a INT64, b INT64, s TEXT)");
    RUN("CREATE INDEX t_g ON t (g)");
    RUN("SET cross_check = on");
    enum { N = 150 };
    orow m[N];
    char sql[256];
    test_seed(1112);
    for (int i = 0; i < N; i++) {
        orow *w = &m[i];
        w->id = 1000 - i * 3; /* key order is not insertion order */
        w->g = (int64_t)(test_rand() % 4);
        w->an = test_rand() % 7 == 0;
        w->bn = test_rand() % 7 == 0;
        w->sn = test_rand() % 9 == 0;
        w->a = (int64_t)(test_rand() % 12) - 3;
        w->b = (int64_t)(test_rand() % 12) - 3;
        snprintf(w->s, sizeof w->s, "%c%c", 'a' + (int)(test_rand() % 3), 'a' + (int)(test_rand() % 3));
        char av[24], bv[24], sv[16];
        snprintf(av, sizeof av, "%lld", (long long)w->a);
        snprintf(bv, sizeof bv, "%lld", (long long)w->b);
        snprintf(sv, sizeof sv, "'%s'", w->s);
        snprintf(sql, sizeof sql, "INSERT INTO t VALUES (%lld, %lld, %s, %s, %s)", (long long)w->id, (long long)w->g,
                 w->an ? "NULL" : av, w->bn ? "NULL" : bv, w->sn ? "NULL" : sv);
        RUN(sql);
        if (i == N / 2) RUN("CHECKPOINT");
    }
    static const char *const orders[] = {"a", "a DESC", "a NULLS FIRST", "a DESC NULLS LAST, id DESC", "s, a DESC",
                                         "a + b", "g DESC, b"};
    static const char *const windows[] = {"", " LIMIT 7", " LIMIT 5 OFFSET 11", " OFFSET 140", " OFFSET 200"};
    static const char *const paths[] = {"auto", "scan", "store", "ordered"};
    int idx[N];
    g_om = m;
    for (int round = 0; round < 2; round++) {
        if (round) RUN("CHECKPOINT");
        for (size_t p = 0; p < sizeof paths / sizeof *paths; p++) {
            snprintf(sql, sizeof sql, "SET access_path = %s", paths[p]);
            RUN(sql);
            for (int o = 0; o < 7; o++) {
                g_okind = o;
                for (int i = 0; i < N; i++) idx[i] = i;
                qsort(idx, N, sizeof *idx, cmp_model);
                for (size_t wi = 0; wi < sizeof windows / sizeof *windows; wi++) {
                    int lo = 0, hi = N; /* the window the model keeps */
                    if (wi == 1) hi = 7;
                    if (wi == 2) lo = 11, hi = 16;
                    if (wi == 3) lo = 140;
                    if (wi == 4) lo = N;
                    /* g >= 0 keeps every row (g is 0..3) and is a bound predicate, so the ordered path reads the index */
                    snprintf(sql, sizeof sql, "SELECT id FROM t WHERE g >= 0 ORDER BY %s%s", orders[o], windows[wi]);
                    imdb_result r;
                    OK(q(sql, &r));
                    bool ok = r.nrows == (uint64_t)(hi - lo);
                    for (int i = lo; ok && i < hi; i++) {
                        char id[24];
                        snprintf(id, sizeof id, "%lld", (long long)m[idx[i]].id);
                        ok = !strcmp(cell(&r, (uint64_t)(i - lo), 0), id);
                    }
                    if (!ok) {
                        char m_[400];
                        snprintf(m_, sizeof m_, "%s (%s): %llu rows, not the model's %d in its order", sql, paths[p],
                                 (unsigned long long)r.nrows, hi - lo);
                        imdb_result_free(&r);
                        test_fail(__FILE__, __LINE__, m_);
                        return;
                    }
                    imdb_result_free(&r);
                }
            }
        }
    }
    RUN("SET access_path = auto");
    /* a position names an item (or a column under *); an item's tree sorts as its value */
    uint64_t nr;
    CHECK(same_rows("SELECT id, a + b FROM t ORDER BY 2, 1 DESC", "SELECT id, a + b FROM t ORDER BY a + b, id DESC", &nr) == 0 && nr == N);
    CHECK(same_rows("SELECT * FROM t ORDER BY 4 DESC LIMIT 9", "SELECT * FROM t ORDER BY b DESC LIMIT 9", &nr) == 0 && nr == 9);
    /* every matching row's keys are computed: one that fails fails the statement, even past LIMIT */
    CHECK(run("SELECT id FROM t ORDER BY 10 / (a - a) LIMIT 1") == IMDB_ERR_INVALID);
    CHECK(run("SELECT id FROM t ORDER BY 0") == IMDB_ERR_INVALID);
    CHECK(run("SELECT id FROM t ORDER BY 2") == IMDB_ERR_INVALID); /* one item */
    CHECK(run("SELECT id FROM t ORDER BY SUM(a)") == IMDB_ERR_INVALID); /* an aggregate makes it one; id is not */
    done(db);
}

/* DISTINCT: rows equal in every item kept once (NULL equal to NULL), the first in the order; grouped and joined
 * ordering; LIMIT and OFFSET on an aggregate's one row */
static void t_distinct_groups(void)
{
    imdb_db *db = fresh();
    CHECK(db);
    RUN("CREATE TABLE t (id INT64 PRIMARY KEY, g INT64, a INT64, s TEXT)");
    RUN("CREATE TABLE u (id INT64 PRIMARY KEY, tid INT64, v INT64)");
    RUN("SET cross_check = on");
    RUN("INSERT INTO t VALUES (1, 1, 5, 'x'), (2, 1, 5, 'x'), (3, 2, NULL, 'y'), (4, 2, NULL, 'y'), (5, 3, 7, NULL),"
        " (6, 3, 7, NULL), (7, 1, 6, 'x'), (8, 4, 5, 'z')");
    RUN("INSERT INTO u VALUES (1, 1, 10), (2, 1, 20), (3, 2, 10), (4, 9, 30), (5, 8, 20)");
    CELL("SELECT COUNT(*) FROM t", "8");
    imdb_result r;
    OK(q("SELECT DISTINCT g, a, s FROM t", &r));
    CHECK(r.nrows == 5); /* (1,5,x) (2,null,y) (3,7,null) (1,6,x) (4,5,z), first-seen order */
    CHECK(!strcmp(cell(&r, 0, 0), "1") && !strcmp(cell(&r, 1, 1), "null") && !strcmp(cell(&r, 2, 2), "null"));
    CHECK(!strcmp(cell(&r, 3, 1), "6") && !strcmp(cell(&r, 4, 2), "z"));
    imdb_result_free(&r);
    OK(q("SELECT DISTINCT a FROM t ORDER BY a DESC", &r));
    CHECK(r.nrows == 4 && !strcmp(cell(&r, 0, 0), "null") && !strcmp(cell(&r, 1, 0), "7") && !strcmp(cell(&r, 3, 0), "5"));
    imdb_result_free(&r);
    OK(q("SELECT DISTINCT s FROM t ORDER BY 1 LIMIT 2 OFFSET 1", &r));
    CHECK(r.nrows == 2 && !strcmp(cell(&r, 0, 0), "y") && !strcmp(cell(&r, 1, 0), "z"));
    imdb_result_free(&r);
    CELL("SELECT COUNT(*) FROM t WHERE a IS NULL", "2");
    CHECK(run("SELECT DISTINCT g FROM t ORDER BY a") == IMDB_ERR_INVALID); /* not a select item */
    CHECK(run("SELECT DISTINCT g, a FROM t ORDER BY a + 1") == IMDB_ERR_INVALID);
    /* grouped: by an aggregate, by a position, by an aggregate not in the list; DISTINCT over groups */
    OK(q("SELECT g, COUNT(*) FROM t GROUP BY g ORDER BY 2 DESC, g DESC", &r));
    CHECK(r.nrows == 4 && !strcmp(cell(&r, 0, 0), "1") && !strcmp(cell(&r, 1, 0), "3") && !strcmp(cell(&r, 3, 0), "4"));
    imdb_result_free(&r);
    OK(q("SELECT g FROM t GROUP BY g ORDER BY SUM(a) NULLS FIRST, g LIMIT 3", &r));
    CHECK(r.nrows == 3 && !strcmp(cell(&r, 0, 0), "2") && !strcmp(cell(&r, 1, 0), "4") && !strcmp(cell(&r, 2, 0), "3"));
    imdb_result_free(&r);
    OK(q("SELECT DISTINCT COUNT(*) FROM t GROUP BY g ORDER BY 1", &r));
    CHECK(r.nrows == 3 && !strcmp(cell(&r, 0, 0), "1") && !strcmp(cell(&r, 1, 0), "2") && !strcmp(cell(&r, 2, 0), "3"));
    /* the counts: g 1 three rows (1, 2, 7), g 2 and 3 two, g 4 one */
    imdb_result_free(&r);
    CHECK(run("SELECT g FROM t GROUP BY g ORDER BY a") == IMDB_ERR_INVALID); /* not the GROUP BY column */
    /* an aggregate's one row: LIMIT 0 and OFFSET 1 leave none */
    OK(q("SELECT COUNT(*) FROM t LIMIT 0", &r));
    CHECK(r.nrows == 0);
    imdb_result_free(&r);
    OK(q("SELECT COUNT(*) FROM t OFFSET 1", &r));
    CHECK(r.nrows == 0);
    imdb_result_free(&r);
    CELL("SELECT COUNT(*) FROM t LIMIT 1 OFFSET 0", "8");
    /* joins: ordered by either side, LEFT's NULL-extended rows placed by NULLS; DISTINCT over joined rows */
    static const char *const plans[] = {"hash", "index"};
    char sql[64];
    for (size_t p = 0; p < sizeof plans / sizeof *plans; p++) {
        snprintf(sql, sizeof sql, "SET join_plan = %s", plans[p]);
        RUN(sql);
        OK(q("SELECT t.id, u.v FROM t LEFT JOIN u ON t.id = u.tid ORDER BY u.v DESC NULLS LAST, t.id LIMIT 4", &r));
        /* (1, 20), (8, 20): v DESC, then t.id; (1, 10), (2, 10); the NULL-extended 3 to 7 last */
        CHECK(r.nrows == 4 && !strcmp(cell(&r, 0, 0), "1") && !strcmp(cell(&r, 0, 1), "20") && !strcmp(cell(&r, 1, 0), "8"));
        CHECK(!strcmp(cell(&r, 2, 0), "1") && !strcmp(cell(&r, 2, 1), "10"));
        CHECK(!strcmp(cell(&r, 3, 0), "2") && !strcmp(cell(&r, 3, 1), "10"));
        imdb_result_free(&r);
        OK(q("SELECT DISTINCT u.v FROM t JOIN u ON t.id = u.tid ORDER BY 1", &r));
        CHECK(r.nrows == 2 && !strcmp(cell(&r, 0, 0), "10") && !strcmp(cell(&r, 1, 0), "20"));
        imdb_result_free(&r);
    }
    done(db);
}

/* AVG(x) at six places past x's scale, rounded half away from zero, as an integer: sum * 10^6 / cnt */
static __int128 avg_scaled(__int128 sum, int64_t cnt)
{
    __int128 num = sum * 1000000, quo = num / cnt, rem = num % cnt;
    if (rem < 0) rem = -rem;
    if (2 * rem >= cnt) quo += num < 0 ? -1 : 1;
    return quo;
}

/* its text, as a cell prints it */
static void avg_text(__int128 sum, int64_t cnt, int scale, char *out, size_t n)
{
    __int128 quo = avg_scaled(sum, cnt);
    __int128 p = 1;
    for (int i = 0; i < scale + 6; i++) p *= 10;
    __int128 a = quo < 0 ? -quo : quo;
    snprintf(out, n, "%s%lld.%0*lld", quo < 0 ? "-" : "", (long long)(a / p), scale + 6, (long long)(a % p));
}

/* AVG (1e): SUM / COUNT once, by the division rule: an INT64's or a DECIMAL's a DECIMAL six places past its scale,
 * rounded half away from zero, a FLOAT64's a FLOAT64; NULLs skipped, none: NULL. HAVING: the groups (or the one
 * aggregate row) its condition keeps, TRUE only, decided before the items (an item's error on a dropped group is never
 * raised), DISTINCT, ORDER BY and the window; on every path, in memory and in the lake, and in joins, against a model */
static void t_avg_having(void)
{
    imdb_db *db = fresh();
    CHECK(db);
    RUN("SET cross_check = on");
    RUN("CREATE TABLE s (id INT64 PRIMARY KEY, g INT64, qty INT64, price DECIMAL(10,2), f FLOAT64)");
    RUN("INSERT INTO s VALUES (1, 1, 3, 2.50, 0.5), (2, 1, 4, 1.25, 0.25), (3, 2, 10, 0.10, 1.5), (4, 2, NULL, 9.99, 2),"
        " (5, 3, 1, NULL, NULL)");
    CELL("SELECT AVG(qty) FROM s", "4.500000");
    CELL("SELECT AVG(price) FROM s", "3.46000000");
    CELL("SELECT AVG(f) FROM s", "1.0625");
    CELL("SELECT AVG(qty * price) FROM s", "4.50000000"); /* 13.50 / 3: two rows' products are NULL */
    CELL("SELECT AVG(qty) FROM s WHERE id > 100", "null");
    CELL("SELECT SUM(qty) / COUNT(qty) FROM s", "4"); /* INT64 division truncates; AVG does not */
    CELL("SELECT AVG(qty) * 2 FROM s", "9.000000");
    /* an INT64 AVG whose sum passes int64 (an INT64-typed dividend of more than 64 bits, divided exactly) */
    RUN("CREATE TABLE wide (id INT64 PRIMARY KEY, m INT64)");
    RUN("INSERT INTO wide VALUES (1, 4611686018427387904), (2, 4611686018427387904), (3, 4611686018427387904)");
    CELL("SELECT AVG(m) FROM wide", "4611686018427387904.000000");
    CELL("SELECT AVG(-m) FROM wide", "-4611686018427387904.000000");
    RUN("INSERT INTO wide VALUES (4, 9223372036854775807), (5, 9223372036854775807), (6, 1)");
    CELL("SELECT AVG(m) FROM wide WHERE id > 3", "6148914691236517205.000000"); /* (2^64 - 1) / 3 */
    RUN("CREATE TABLE r (id INT64 PRIMARY KEY, a INT64, d DECIMAL(6,2))");
    RUN("INSERT INTO r VALUES (1, 1, 0.01), (2, 1, 0.02), (3, 2, NULL)");
    CELL("SELECT AVG(a) FROM r", "1.333333");
    CELL("SELECT AVG(a * 2 - 1) FROM r", "1.666667"); /* 5 / 3, half away from zero */
    CELL("SELECT AVG(1 - a * 2) FROM r", "-1.666667");
    CELL("SELECT AVG(d) FROM r", "0.01500000");
    CELL("SELECT AVG(d) FROM r WHERE d IS NULL", "null");
    CHECK(run("SELECT AVG(qty > 1) FROM s") == IMDB_ERR_INVALID);
    CHECK(run("SELECT AVG(price * 0.0000000000000000000000000000001) FROM s") == IMDB_ERR_LIMIT); /* 33 + 6 places */
    CHECK(strstr(g_e.msg, "AVG of a DECIMAL past 32 decimal places") != NULL);
    /* the 38-digit edges, each refusal by its own message (an INT64 literal past range is IMDB_ERR_LIMIT too) */
    CHECK(run("SELECT AVG(price * 999999999999999999999999999999.0) FROM s") == IMDB_ERR_LIMIT);
    CHECK(strstr(g_e.msg, "DECIMAL result of more than 38 digits") != NULL); /* the quotient: 40 digits at scale 9 */
    CHECK(run("SELECT AVG(price * 9999999999999999999999999999999999.0) FROM s") == IMDB_ERR_LIMIT);
    CHECK(strstr(g_e.msg, "an AVG's sum of more than 38 digits") != NULL);
    CELL("SELECT AVG(price * 99999999999999999999999999.0) FROM s", "345999999999999999999999996.540000000");
    CHECK(run("SELECT AVG(AVG(qty)) FROM s") == IMDB_ERR_INVALID);
    CHECK(run("SELECT id FROM s WHERE AVG(qty) > 1") == IMDB_ERR_INVALID);
    imdb_result r;
    OK(q("SELECT g, COUNT(*), AVG(qty) FROM s GROUP BY g HAVING COUNT(*) > 1", &r));
    CHECK(r.nrows == 2 && !strcmp(cell(&r, 0, 0), "1") && !strcmp(cell(&r, 1, 0), "2") && !strcmp(r.names[2], "avg_qty"));
    CHECK(!strcmp(cell(&r, 0, 2), "3.500000") && !strcmp(cell(&r, 1, 2), "10.000000"));
    imdb_result_free(&r);
    OK(q("SELECT g FROM s GROUP BY g HAVING SUM(price) > 1", &r)); /* g 3's SUM is NULL: UNKNOWN, dropped */
    CHECK(r.nrows == 2 && !strcmp(cell(&r, 0, 0), "1") && !strcmp(cell(&r, 1, 0), "2"));
    imdb_result_free(&r);
    OK(q("SELECT g FROM s GROUP BY g HAVING NOT SUM(price) > 4", &r)); /* NOT UNKNOWN is UNKNOWN */
    CHECK(r.nrows == 1 && !strcmp(cell(&r, 0, 0), "1"));
    imdb_result_free(&r);
    OK(q("SELECT g, AVG(price) FROM s GROUP BY g HAVING AVG(price) IS NULL OR g = 1", &r));
    CHECK(r.nrows == 2 && !strcmp(cell(&r, 0, 0), "1") && !strcmp(cell(&r, 0, 1), "1.87500000"));
    CHECK(!strcmp(cell(&r, 1, 0), "3") && !strcmp(cell(&r, 1, 1), "null"));
    imdb_result_free(&r);
    OK(q("SELECT g FROM s GROUP BY g HAVING MAX(f) > 1", &r)); /* an aggregate the list does not hold */
    CHECK(r.nrows == 1 && !strcmp(cell(&r, 0, 0), "2"));
    imdb_result_free(&r);
    OK(q("SELECT g, 10 / (COUNT(*) - 1) FROM s GROUP BY g HAVING COUNT(*) > 1", &r)); /* g 3's item would divide by 0 */
    CHECK(r.nrows == 2 && !strcmp(cell(&r, 0, 1), "10") && !strcmp(cell(&r, 1, 1), "10"));
    imdb_result_free(&r);
    CHECK(run("SELECT g FROM s GROUP BY g HAVING 10 / (COUNT(*) - 1) > 0") == IMDB_ERR_INVALID); /* HAVING's own */
    OK(q("SELECT g, SUM(qty) FROM s GROUP BY g HAVING COUNT(*) >= 1 ORDER BY 2 DESC LIMIT 2", &r));
    CHECK(r.nrows == 2 && !strcmp(cell(&r, 0, 0), "2") && !strcmp(cell(&r, 1, 0), "1"));
    imdb_result_free(&r);
    OK(q("SELECT g FROM s GROUP BY g HAVING COUNT(*) < 2 ORDER BY AVG(qty) LIMIT 5", &r));
    CHECK(r.nrows == 1 && !strcmp(cell(&r, 0, 0), "3"));
    imdb_result_free(&r);
    OK(q("SELECT DISTINCT COUNT(*) FROM s GROUP BY g HAVING COUNT(*) > 0", &r)); /* 2, 2, 1 */
    CHECK(r.nrows == 2 && !strcmp(cell(&r, 0, 0), "2") && !strcmp(cell(&r, 1, 0), "1"));
    imdb_result_free(&r);
    OK(q("SELECT g FROM s GROUP BY g HAVING g >= 2 OFFSET 1", &r));
    CHECK(r.nrows == 1 && !strcmp(cell(&r, 0, 0), "3"));
    imdb_result_free(&r);
    /* without GROUP BY: the one row, or none */
    CELL("SELECT COUNT(*) FROM s HAVING COUNT(*) > 1", "5");
    OK(q("SELECT COUNT(*), AVG(qty) FROM s HAVING COUNT(*) > 10", &r));
    CHECK(r.nrows == 0 && r.ncols == 2);
    imdb_result_free(&r);
    OK(q("SELECT SUM(qty) FROM s WHERE id > 100 HAVING SUM(qty) IS NULL", &r));
    CHECK(r.nrows == 1 && !strcmp(cell(&r, 0, 0), "null"));
    imdb_result_free(&r);
    CHECK(run("SELECT g FROM s GROUP BY g HAVING qty > 1") == IMDB_ERR_INVALID); /* not the GROUP BY column */
    CHECK(strstr(g_e.msg, "must be the GROUP BY column or inside an aggregate") != NULL);
    CHECK(run("SELECT id FROM s HAVING id > 1") == IMDB_ERR_INVALID);            /* no group, no aggregate */
    CHECK(strstr(g_e.msg, "HAVING needs GROUP BY or an aggregate") != NULL);
    CHECK(run("SELECT COUNT(*) FROM s HAVING qty > 1") == IMDB_ERR_INVALID);     /* a column outside, no GROUP BY */
    CHECK(strstr(g_e.msg, "mixing aggregates and columns needs GROUP BY") != NULL);
    CHECK(run("SELECT g FROM s GROUP BY g HAVING SUM(qty)") == IMDB_ERR_INVALID); /* not a condition */
    CHECK(strstr(g_e.msg, "HAVING takes a condition") != NULL);
    CHECK(run("SELECT g FROM s GROUP BY g HAVING COUNT(*) > 1 FOR UPDATE") == IMDB_ERR_INVALID);
    CHECK(strstr(g_e.msg, "FOR UPDATE locks rows") != NULL);
    /* every column of * is a plain one: an aggregate in HAVING or ORDER BY is mixing (until this, one row of no column;
     * ORDER BY COUNT(*) since 1d) */
    CHECK(run("SELECT * FROM s HAVING COUNT(*) > 1") == IMDB_ERR_INVALID);
    CHECK(strstr(g_e.msg, "mixing aggregates and columns needs GROUP BY") != NULL);
    CHECK(run("SELECT * FROM s ORDER BY COUNT(*)") == IMDB_ERR_INVALID);
    CHECK(strstr(g_e.msg, "mixing aggregates and columns needs GROUP BY") != NULL);
    CHECK(run("SELECT * FROM s JOIN r ON s.id = r.id HAVING COUNT(*) > 1") == IMDB_ERR_INVALID);
    CHECK(strstr(g_e.msg, "mixing aggregates and columns needs GROUP BY") != NULL);
    CHECK(run("SELECT * FROM s JOIN r ON s.id = r.id ORDER BY SUM(r.a)") == IMDB_ERR_INVALID);
    CELL("SELECT 1 FROM s HAVING COUNT(*) > 1", "1"); /* no column: the one row, as PostgreSQL gives it */
    /* every path, in memory and in the lake, against the model; a threshold at group 2's average */
    enum { N = 200 };
    int64_t mg[N], mq[N], mp[N];
    bool qn[N];
    char sql[320], w[48];
    test_seed(1107);
    RUN("CREATE TABLE m (id INT64 PRIMARY KEY, g INT64, q INT64, p DECIMAL(8,2))");
    RUN("CREATE INDEX m_g ON m (g)");
    for (int i = 0; i < N; i++) {
        mg[i] = (int64_t)(test_rand() % 5);
        mq[i] = (int64_t)(test_rand() % 100) - 20;
        mp[i] = (int64_t)(test_rand() % 100000) - 30000; /* cents */
        qn[i] = test_rand() % 9 == 0;
        int64_t ap = mp[i] < 0 ? -mp[i] : mp[i];
        if (qn[i])
            snprintf(sql, sizeof sql, "INSERT INTO m VALUES (%d, %lld, NULL, %s%lld.%02lld)", i + 1, (long long)mg[i],
                     mp[i] < 0 ? "-" : "", (long long)(ap / 100), (long long)(ap % 100));
        else
            snprintf(sql, sizeof sql, "INSERT INTO m VALUES (%d, %lld, %lld, %s%lld.%02lld)", i + 1, (long long)mg[i],
                     (long long)mq[i], mp[i] < 0 ? "-" : "", (long long)(ap / 100), (long long)(ap % 100));
        RUN(sql);
    }
    __int128 qs[5] = {0}, ps[5] = {0};
    int64_t qc[5] = {0}, pc[5] = {0};
    for (int i = 0; i < N; i++) {
        if (!qn[i]) qs[mg[i]] += mq[i], qc[mg[i]]++;
        ps[mg[i]] += mp[i], pc[mg[i]]++;
    }
    __int128 rq[5]; /* each group's AVG(q) at scale 6; the threshold the median group's: exact at that scale */
    int byq[5];
    for (int g = 0; g < 5; g++) rq[g] = avg_scaled(qs[g], qc[g]), byq[g] = g;
    for (int i = 1; i < 5; i++)
        for (int j = i; j > 0 && rq[byq[j]] < rq[byq[j - 1]]; j--) {
            int t = byq[j];
            byq[j] = byq[j - 1];
            byq[j - 1] = t;
        }
    char thr[48];
    avg_text(qs[byq[2]], qc[byq[2]], 0, thr, sizeof thr);
    int kept = 0;
    for (int g = 0; g < 5; g++) kept += rq[g] > rq[byq[2]];
    CHECK(kept >= 1 && kept <= 4); /* the threshold splits the groups */
    static const char *const paths[] = {"auto", "scan", "store", "ordered"};
    for (int round = 0; round < 2; round++) {
        if (round) RUN("CHECKPOINT");
        for (size_t p = 0; p < sizeof paths / sizeof *paths; p++) {
            snprintf(sql, sizeof sql, "SET access_path = %s", paths[p]);
            RUN(sql);
            snprintf(sql, sizeof sql, "SELECT g, AVG(q), AVG(p), COUNT(*) FROM m WHERE g >= 0 GROUP BY g HAVING AVG(q) > %s",
                     thr);
            OK(q(sql, &r));
            CHECK(r.nrows == (uint64_t)kept);
            uint64_t row = 0;
            for (int g = 0; g < 5 && row < r.nrows; g++) {
                if (!(rq[g] > rq[byq[2]])) continue;
                char a[48], b[48];
                avg_text(qs[g], qc[g], 0, a, sizeof a);
                avg_text(ps[g], pc[g], 2, b, sizeof b);
                snprintf(w, sizeof w, "%d", g);
                CHECK(!strcmp(cell(&r, row, 0), w) && !strcmp(cell(&r, row, 1), a) && !strcmp(cell(&r, row, 2), b));
                row++;
            }
            imdb_result_free(&r);
            OK(q("SELECT AVG(q), AVG(p) FROM m WHERE g >= 0", &r));
            __int128 tq = 0, tp = 0;
            int64_t cq = 0;
            for (int g = 0; g < 5; g++) tq += qs[g], tp += ps[g], cq += qc[g];
            char a[48], b[48];
            avg_text(tq, cq, 0, a, sizeof a);
            avg_text(tp, N, 2, b, sizeof b);
            CHECK(r.nrows == 1 && !strcmp(cell(&r, 0, 0), a) && !strcmp(cell(&r, 0, 1), b));
            imdb_result_free(&r);
        }
    }
    /* in a join: grouped by the joined side */
    RUN("SET access_path = auto");
    RUN("CREATE TABLE gn (id INT64 PRIMARY KEY, w INT64)");
    RUN("INSERT INTO gn VALUES (0, 7), (1, 11), (2, 13), (3, 17), (4, 19)");
    static const char *const plans[] = {"hash", "index", "auto"};
    for (size_t p = 0; p < sizeof plans / sizeof *plans; p++) {
        snprintf(sql, sizeof sql, "SET join_plan = %s", plans[p]);
        RUN(sql);
        snprintf(sql, sizeof sql, "SELECT gn.id, AVG(m.q) FROM m JOIN gn ON m.g = gn.id GROUP BY gn.id HAVING AVG(m.q) > %s"
                 " ORDER BY 2 DESC", thr);
        OK(q(sql, &r));
        CHECK(r.nrows == (uint64_t)kept);
        for (uint64_t i = 0; i + 1 < r.nrows; i++) { /* descending by the average at scale 6 */
            int g0 = atoi(cell(&r, i, 0)), g1 = atoi(cell(&r, i + 1, 0));
            CHECK(g0 >= 0 && g0 < 5 && g1 >= 0 && g1 < 5);
            CHECK(rq[g0] > rq[g1] || (rq[g0] == rq[g1] && g0 < g1));
            char a[48];
            avg_text(qs[g0], qc[g0], 0, a, sizeof a);
            CHECK(!strcmp(cell(&r, i, 1), a));
        }
        imdb_result_free(&r);
        /* a column that only HAVING reads, or only an ORDER BY key: a hash join keeps its build side's columns that the
         * statement reads (join_need), these included (the oracle's seed 51 found HAVING's left out, 1d's keys too) */
        OK(q("SELECT gn.id FROM m JOIN gn ON m.g = gn.id GROUP BY gn.id HAVING MIN(gn.w) > 12 AND MAX(m.p) > -1000", &r));
        CHECK(r.nrows == 3 && !strcmp(cell(&r, 0, 0), "2") && !strcmp(cell(&r, 2, 0), "4"));
        imdb_result_free(&r);
        OK(q("SELECT COUNT(*) FROM m JOIN gn ON m.g = gn.id GROUP BY gn.id ORDER BY MAX(gn.w) DESC, SUM(m.q)", &r));
        CHECK(r.nrows == 5);
        for (int g = 4; g >= 0 && r.nrows == 5; g--) {
            int64_t cnt = 0;
            for (int i = 0; i < N; i++) cnt += mg[i] == g;
            snprintf(w, sizeof w, "%lld", (long long)cnt);
            CHECK(!strcmp(cell(&r, (uint64_t)(4 - g), 0), w));
        }
        imdb_result_free(&r);
    }
    done(db);
}

const test_case expr_tests[] = {
    {"expr_int64", t_int64},
    {"expr_decimal", t_decimal},
    {"expr_float64", t_float64},
    {"expr_compare", t_compare},
    {"expr_assign", t_assign},
    {"expr_update", t_update},
    {"expr_values", t_values},
    {"expr_items", t_items},
    {"expr_where_paths", t_where_paths},
    {"expr_join", t_join},
    {"expr_aggregates", t_aggregates},
    {"expr_mixed_literals", t_mixed_literals},
    {"expr_truth", t_truth},
    {"expr_short_circuit", t_short_circuit},
    {"expr_or_not_paths", t_or_not_paths},
    {"expr_or_not_join", t_or_not_join},
    {"expr_bool_values", t_bool_values},
    {"expr_cond_timestamps", t_cond_timestamps},
    {"expr_order_paths", t_order_paths},
    {"expr_distinct_groups", t_distinct_groups},
    {"expr_avg_having", t_avg_having},
    {"expr_limits", t_limits},
};
const size_t expr_ntests = sizeof expr_tests / sizeof *expr_tests;
