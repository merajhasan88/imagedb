/* F3b: DATE and TIME (docs/format-design-v7.md section 5; design.md section 5, DATE and TIME). A DATE is its days since
 * 1970-01-01, a TIME its microseconds since midnight, each in eight bytes like every fixed-width type; each rule checked
 * at its edges (literals, ranges, arithmetic, CASTs in every direction, the refusals), then a table keyed by a DATE
 * against a model on every access path, cross-checked, in memory, from the lake, after a reopen and a full replay, its
 * writes by every path, a view, a replica, VERIFY and the auditor. */
#include <stdlib.h>

#include "../../src/codec.h"
#include "../../src/db_internal.h"
#include "../../src/sql.h"
#include "thelp.h"

static imdb_session g_s;
static char g_out[1 << 16];

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

static imdb_db *open_at(const char *dir, bool full_replay)
{
    imdb_open_opts o = {.sync = 0, .full_replay = full_replay};
    imdb_db *db = NULL;
    imdb_err e = {0};
    if (imdb_open(dir, &o, &db, &e)) return NULL;
    imdb_session_init(&g_s, db);
    return db;
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

static imdb_db *fresh(void)
{
    const char *dir = test_tmpdir();
    imdb_err e = {0};
    if (imdb_init(dir, false, NULL, &e)) return NULL;
    return open_at(dir, false);
}

/* the codec's literals and texts at their edges: every refusal a shape or a field, never a guess */
static void t_dt_codec(void)
{
    imdb_err e = {0};
    int64_t v = 0;
    CHECK(imdb_parse_date("1970-01-01", 10, &v, &e) == 0 && v == 0);
    CHECK(imdb_parse_date("0001-01-01", 10, &v, &e) == 0 && v == IMDB_DATE_MIN);
    CHECK(imdb_parse_date("9999-12-31", 10, &v, &e) == 0 && v == IMDB_DATE_MAX);
    CHECK(imdb_parse_date("2024-02-29", 10, &v, &e) == 0 && v == 19782);
    static const char *const bad_d[] = {"0000-12-31", "2023-02-29", "2026-13-01", "2026-00-10", "2026-04-31", "2026-1-01",
                                        "2026-01-1",  "26-01-01",   "2026/01/01", "2026-01-01 ", " 2026-01-01", "",
                                        "2026-01-01 00:00:00", "+2026-01-01"};
    for (size_t i = 0; i < sizeof bad_d / sizeof *bad_d; i++) CHECK(imdb_parse_date(bad_d[i], strlen(bad_d[i]), &v, &e) != 0);
    CHECK(imdb_parse_time("00:00:00", 8, &v, &e) == 0 && v == 0);
    CHECK(imdb_parse_time("23:59:59.999999", 15, &v, &e) == 0 && v == IMDB_TIME_MAX);
    CHECK(imdb_parse_time("12:34:56.5", 10, &v, &e) == 0 && v == 45296500000LL);
    CHECK(imdb_parse_time("01:02:03.000004", 15, &v, &e) == 0 && v == 3723000004LL);
    static const char *const bad_t[] = {"24:00:00", "23:60:00", "23:59:60", "12:00", "12:00:00.", "12:00:00.1234567",
                                        "1:00:00",  "12:0:00",  "12-00-00", "12:00:00 ", "T12:00:00", "", "12:00:00Z"};
    for (size_t i = 0; i < sizeof bad_t / sizeof *bad_t; i++) CHECK(imdb_parse_time(bad_t[i], strlen(bad_t[i]), &v, &e) != 0);
    imdb_buf b;
    imdb_buf_init(&b);
    imdb_format_date(IMDB_DATE_MIN, &b);
    imdb_buf_put_str(&b, "|");
    imdb_format_date(-1, &b);
    imdb_buf_put_str(&b, "|");
    imdb_format_date(IMDB_DATE_MAX, &b);
    imdb_buf_put_str(&b, "|");
    imdb_format_time(0, &b);
    imdb_buf_put_str(&b, "|");
    imdb_format_time(45296500000LL, &b);
    imdb_buf_put_str(&b, "|");
    imdb_format_time(IMDB_TIME_MAX, &b);
    CHECK(imdb_buf_check(&b, &e) == 0);
    const char *want = "0001-01-01|1969-12-31|9999-12-31|00:00:00|12:34:56.500000|23:59:59.999999";
    CHECK(b.len == strlen(want) && memcmp(b.p, want, b.len) == 0);
    imdb_buf_free(&b);
    /* every day's text reads back as the day, around both ends and the epoch */
    static const int64_t from[] = {IMDB_DATE_MIN, -800, 18000, IMDB_DATE_MAX - 800};
    for (size_t k = 0; k < sizeof from / sizeof *from; k++)
        for (int64_t d = from[k]; d <= from[k] + 800 && d <= IMDB_DATE_MAX; d++) {
            imdb_buf t;
            imdb_buf_init(&t);
            imdb_format_date(d, &t);
            int64_t back = 0;
            CHECK(imdb_buf_check(&t, &e) == 0 && imdb_parse_date((const char *)t.p, t.len, &back, &e) == 0 && back == d);
            imdb_buf_free(&t);
        }
    imdb_column c;
    memset(&c, 0, sizeof c);
    strcpy(c.name, "c");
    c.type = IMDB_T_DATE;
    imdb_value x = {.type = IMDB_T_DATE, .i = IMDB_DATE_MAX + 1};
    CHECK(imdb_value_check(&c, &x, &e) != 0);
    x.i = IMDB_DATE_MIN - 1;
    CHECK(imdb_value_check(&c, &x, &e) != 0);
    x.i = IMDB_DATE_MIN;
    CHECK(imdb_value_check(&c, &x, &e) == 0);
    c.type = IMDB_T_TIME;
    x.type = IMDB_T_TIME;
    x.i = -1;
    CHECK(imdb_value_check(&c, &x, &e) != 0);
    x.i = IMDB_TIME_MAX + 1;
    CHECK(imdb_value_check(&c, &x, &e) != 0);
    x.i = IMDB_TIME_MAX;
    CHECK(imdb_value_check(&c, &x, &e) == 0);
}

/* SQL's literals, the types by context, arithmetic and its refusals */
static void t_dt_sql(void)
{
    imdb_db *db = fresh();
    CHECK(db);
    if (!db) return;
    EXPECT("SELECT DATE '2026-11-09' AS d, TIME '07:08:09.01' AS t", "d,t\n2026-11-09,07:08:09.010000\n");
    EXPECT("SELECT DATE '2026-11-09' + 30 AS a, 30 + DATE '2026-11-09' AS b, DATE '2026-03-01' - 1 AS c",
           "a,b,c\n2026-12-09,2026-12-09,2026-02-28\n");
    EXPECT("SELECT DATE '2024-03-01' - DATE '2024-02-01' AS leap, DATE '1970-01-01' - DATE '0001-01-01' AS span",
           "leap,span\n29,719162\n");
    EXPECT("SELECT DATE '2026-11-09' + TIME '23:59:59.999999' AS a, TIME '00:00:01' + DATE '1969-12-31' AS b",
           "a,b\n2026-11-09 23:59:59.999999,1969-12-31 00:00:01\n");
    EXPECT("SELECT DATE '9999-12-31' + 1", "ERR a DATE result out of range");
    EXPECT("SELECT DATE '0001-01-01' - 1", "ERR a DATE result out of range");
    EXPECT("SELECT DATE '0001-01-01' + 3652058 AS d", "d\n9999-12-31\n");
    EXPECT("SELECT TIME '12:00:00' - TIME '11:00:00'", "ERR date arithmetic");
    EXPECT("SELECT DATE '2026-01-01' + DATE '2026-01-01'", "ERR date arithmetic");
    EXPECT("SELECT DATE '2026-01-01' * 2", "ERR date arithmetic");
    EXPECT("SELECT DATE '2026-01-01' + 1.5", "ERR date arithmetic");
    EXPECT("SELECT -DATE '2026-01-01'", "ERR arithmetic takes");
    EXPECT("SELECT DATE '2026-02-30'", "ERR date field out of range");
    EXPECT("SELECT TIME '24:00:00'", "ERR time field out of range");
    EXPECT("SELECT DATE '2026-1-1'", "ERR a DATE must look like");
    EXPECT("SELECT TIME '12:00'", "ERR a TIME must look like");
    OK(run("CREATE TABLE t (id INT64 PRIMARY KEY, d DATE, tm TIME, ts TIMESTAMP, tz TIMESTAMPTZ)"));
    EXPECT("CREATE TABLE z (id INT64 PRIMARY KEY, t TIME WITH TIME ZONE)", "ERR TIME WITH TIME ZONE is not supported");
    OK(run("CREATE TABLE z (id INT64 PRIMARY KEY, t TIME WITHOUT TIME ZONE, date INT64, time INT64)"));
    EXPECT("INSERT INTO z VALUES (1, '01:00:00', 5, 6)", "INSERT 1");
    EXPECT("SELECT date + time AS s, t FROM z", "s,t\n11,01:00:00\n"); /* columns named date and time stay columns */
    EXPECT("INSERT INTO t VALUES (1, '2026-11-09', '12:00:00', '2026-11-09 12:30:00', '2026-11-09 23:30:00+00'), "
           "(2, DATE '1969-12-31', TIME '23:59:59.5', '1969-12-31 23:59:59.5', NULL), (3, NULL, NULL, NULL, NULL)",
           "INSERT 3");
    EXPECT("INSERT INTO t (id, d) VALUES (4, 20261109)", "ERR column d expects DATE");
    EXPECT("INSERT INTO t (id, tm) VALUES (4, TIMESTAMP '2026-01-01 00:00:00')", "ERR column tm expects TIME");
    EXPECT("INSERT INTO t (id, d) VALUES (4, '10000-01-01')", "ERR a DATE must look like");
    EXPECT("SELECT id FROM t WHERE d = '2026-11-09'", "id\n1\n");
    EXPECT("SELECT id FROM t WHERE d BETWEEN '1969-01-01' AND '2026-11-08' ORDER BY id", "id\n2\n");
    EXPECT("SELECT id FROM t WHERE d IN ('1969-12-31', '2026-11-09') ORDER BY d DESC", "id\n1\n2\n");
    EXPECT("SELECT id FROM t WHERE tm > '12:00:00' ORDER BY id", "id\n2\n");
    EXPECT("SELECT COALESCE(d, '2000-01-01') AS c FROM t ORDER BY id", "c\n2026-11-09\n1969-12-31\n2000-01-01\n");
    EXPECT("SELECT CASE WHEN id = 1 THEN d ELSE '1999-09-09' END AS c FROM t ORDER BY id",
           "c\n2026-11-09\n1999-09-09\n1999-09-09\n");
    EXPECT("SELECT id FROM t WHERE d = ts", "ERR a comparison of DATE with TIMESTAMP");
    EXPECT("SELECT id FROM t WHERE d = TIMESTAMP '2026-11-09 00:00:00'", "ERR ");
    EXPECT("SELECT id FROM t WHERE tm = d", "ERR ");
    EXPECT("SELECT d + 1 AS n, d - DATE '1970-01-01' AS days, d + tm AS ts2 FROM t ORDER BY id",
           "n,days,ts2\n2026-11-10,20766,2026-11-09 12:00:00\n1970-01-01,-1,1969-12-31 23:59:59.500000\n,,\n");
    EXPECT("SELECT MIN(d) AS a, MAX(d) AS b, MIN(tm) AS c, MAX(tm) AS e, COUNT(d) AS n FROM t",
           "a,b,c,e,n\n1969-12-31,2026-11-09,12:00:00,23:59:59.500000,2\n");
    EXPECT("SELECT SUM(d) FROM t", "ERR SUM needs");
    EXPECT("SELECT AVG(tm) FROM t", "ERR ");
    EXPECT("SELECT date_trunc('month', d) FROM t", "ERR date_trunc of a DATE: CAST it to TIMESTAMP first");
    EXPECT("SELECT date_trunc('month', CAST(d AS TIMESTAMP)) AS m FROM t WHERE id = 1", "m\n2026-11-01 00:00:00\n");
    EXPECT("SELECT d, COUNT(*) AS n FROM t GROUP BY d ORDER BY d", "d,n\n1969-12-31,1\n2026-11-09,1\n,1\n");
    EXPECT("SELECT DISTINCT tm FROM t ORDER BY tm DESC", "tm\n\n23:59:59.500000\n12:00:00\n"); /* NULLS FIRST descending */
    done(db);
}

/* CAST in every direction a DATE or a TIME has, the zone's when a TIMESTAMPTZ is on one side, and the refused ones */
static void t_dt_cast(void)
{
    imdb_db *db = fresh();
    CHECK(db);
    if (!db) return;
    EXPECT("SELECT CAST('2026-11-09' AS DATE) AS a, CAST('01:02:03.5' AS TIME) AS b, CAST(DATE '2026-11-09' AS TEXT) AS c, "
           "CAST(TIME '01:02:03' AS TEXT) AS e",
           "a,b,c,e\n2026-11-09,01:02:03.500000,\"2026-11-09\",\"01:02:03\"\n");
    EXPECT("SELECT CAST('2026-11-31' AS DATE)", "ERR ");
    EXPECT("SELECT CAST(TIMESTAMP '1969-12-31 23:59:59.5' AS DATE) AS a, CAST(TIMESTAMP '1969-12-31 23:59:59.5' AS TIME) AS b, "
           "CAST(TIMESTAMP '0001-01-01 00:00:00' AS DATE) AS c, CAST(TIMESTAMP '9999-12-31 23:59:59.999999' AS TIME) AS e",
           "a,b,c,e\n1969-12-31,23:59:59.500000,0001-01-01,23:59:59.999999\n");
    EXPECT("SELECT CAST(DATE '2026-11-09' AS TIMESTAMP) AS a, CAST(DATE '0001-01-01' AS TIMESTAMP) AS b",
           "a,b\n2026-11-09 00:00:00,0001-01-01 00:00:00\n");
    OK(run("SET TIME ZONE 'Asia/Kathmandu'")); /* +05:45 */
    EXPECT("SELECT CAST(TIMESTAMPTZ '2026-11-09 20:00:00+00' AS DATE) AS a, CAST(TIMESTAMPTZ '2026-11-09 20:00:00+00' AS TIME) AS b",
           "a,b\n2026-11-10,01:45:00\n");
    EXPECT("SELECT CAST(DATE '2026-11-10' AS TIMESTAMPTZ) AS a", "a\n2026-11-10 00:00:00+05:45\n");
    OK(run("SET TIME ZONE 'UTC'"));
    EXPECT("SELECT CAST(DATE '2026-11-10' AS TIMESTAMPTZ) AS a", "a\n2026-11-10 00:00:00+00\n");
    EXPECT("SELECT CAST(TIME '01:00:00' AS DATE)", "ERR CAST of TIME to DATE is not defined");
    EXPECT("SELECT CAST(DATE '2026-01-01' AS TIME)", "ERR CAST of DATE to TIME is not defined");
    EXPECT("SELECT CAST(TIME '01:00:00' AS TIMESTAMP)", "ERR CAST of TIME to TIMESTAMP is not defined");
    EXPECT("SELECT CAST(DATE '2026-01-01' AS INT64)", "ERR CAST of DATE to INT64 is not defined");
    EXPECT("SELECT CAST(20260101 AS DATE)", "ERR CAST of INT64 to DATE is not defined");
    EXPECT("SELECT CAST(TRUE AS TIME)", "ERR CAST of BOOL to TIME is not defined");
    done(db);
}

/* a table keyed by a DATE, with a TIME and a nullable DATE, against a model: every access path (the key, an ordered
 * index on the TIME, a scan), cross-checked, in memory, from the lake (every image reloaded), after a reopen and a full
 * replay; joins on a DATE; the writes by INSERT, UPDATE, COPY, INSERT ... SELECT and ON CONFLICT; VERIFY, a replica at
 * the primary's digest, the auditor on both */
#define DT_N 400
static void t_dt_paths(void)
{
    const char *dir = test_tmpdir();
    imdb_err e = {0};
    CHECK(imdb_init(dir, false, NULL, &e) == 0);
    imdb_db *db = open_at(dir, false);
    CHECK(db);
    if (!db) return;
    OK(run("CREATE TABLE t (d DATE PRIMARY KEY, tm TIME NOT NULL, e DATE, n INT64)"));
    OK(run("CREATE INDEX t_tm ON t (tm)"));
    OK(run("CREATE TABLE u (id INT64 PRIMARY KEY, d DATE)"));
    static int64_t md[DT_N], mt[DT_N], me[DT_N];
    static bool mnull[DT_N];
    uint64_t seed = 0x9e3779b97f4a7c15ull;
    char sql[256];
    for (int i = 0; i < DT_N; i++) { /* days strictly increasing from 1900, so the key is unique; times any in a day */
        seed = seed * 6364136223846793005ull + 1442695040888963407ull;
        md[i] = -25567 + (int64_t)i * 211 + (int64_t)(seed >> 60);
        mt[i] = (int64_t)((seed >> 20) % (uint64_t)(IMDB_TIME_MAX + 1));
        mnull[i] = (seed >> 8) % 5 == 0;
        me[i] = md[i] + (int64_t)((seed >> 30) % 3000) - 1500;
        imdb_buf b;
        imdb_buf_init(&b);
        imdb_buf_put_str(&b, "INSERT INTO t VALUES ('");
        imdb_format_date(md[i], &b);
        imdb_buf_put_str(&b, "', '");
        imdb_format_time(mt[i], &b);
        imdb_buf_put_str(&b, "', ");
        if (mnull[i]) imdb_buf_put_str(&b, "NULL");
        else {
            imdb_buf_put_str(&b, "DATE '");
            imdb_format_date(me[i], &b);
            imdb_buf_put_str(&b, "'");
        }
        imdb_buf_printf(&b, ", %d)", i);
        CHECK(imdb_buf_check(&b, &e) == 0);
        snprintf(sql, sizeof sql, "%.*s", (int)b.len, (const char *)b.p);
        imdb_buf_free(&b);
        OK(run(sql));
        if (i % 7 == 0) {
            imdb_buf_init(&b);
            imdb_buf_printf(&b, "INSERT INTO u VALUES (%d, '", i);
            imdb_format_date(md[i], &b);
            imdb_buf_put_str(&b, "')");
            CHECK(imdb_buf_check(&b, &e) == 0);
            snprintf(sql, sizeof sql, "%.*s", (int)b.len, (const char *)b.p);
            imdb_buf_free(&b);
            OK(run(sql));
        }
    }
    /* the model's answers: rows with tm in the middle third, their n's sum; rows whose e is past their d; the days
     * summed over a key range; the join's count */
    int64_t lo_t = IMDB_TIME_MAX / 3, hi_t = 2 * (IMDB_TIME_MAX / 3), want_n = 0, want_sum = 0;
    int want_c = 0, want_after = 0, want_range = 0;
    int64_t k_lo = md[50], k_hi = md[250];
    int64_t range_days = 0;
    for (int i = 0; i < DT_N; i++) {
        if (mt[i] >= lo_t && mt[i] <= hi_t) want_c++, want_n += i;
        if (!mnull[i] && me[i] > md[i]) want_after++;
        if (md[i] >= k_lo && md[i] <= k_hi) want_range++, range_days += md[i] - md[0];
        want_sum += i;
    }
    char q1[256], q2[256], q3[256], q4[160], w1[96], w2[64], w3[96], w4[64];
    imdb_buf tb;
    imdb_buf_init(&tb);
    imdb_format_time(lo_t, &tb);
    imdb_buf_put_str(&tb, "|");
    imdb_format_time(hi_t, &tb);
    imdb_buf_put_str(&tb, "|");
    imdb_format_date(k_lo, &tb);
    imdb_buf_put_str(&tb, "|");
    imdb_format_date(k_hi, &tb);
    imdb_buf_put_str(&tb, "|");
    imdb_format_date(md[0], &tb);
    CHECK(imdb_buf_check(&tb, &e) == 0);
    char lits[160];
    snprintf(lits, sizeof lits, "%.*s", (int)tb.len, (const char *)tb.p);
    imdb_buf_free(&tb);
    char *a1 = strtok(lits, "|"), *a2 = strtok(NULL, "|"), *a3 = strtok(NULL, "|"), *a4 = strtok(NULL, "|"),
         *a5 = strtok(NULL, "|");
    CHECK(a1 && a2 && a3 && a4 && a5);
    if (!a5) return;
    snprintf(q1, sizeof q1, "SELECT COUNT(*) AS c, SUM(n) AS s FROM t WHERE tm BETWEEN '%s' AND '%s'", a1, a2);
    snprintf(w1, sizeof w1, "c,s\n%d,%lld\n", want_c, (long long)want_n);
    snprintf(q2, sizeof q2, "SELECT COUNT(*) AS c FROM t WHERE e > d");
    snprintf(w2, sizeof w2, "c\n%d\n", want_after);
    snprintf(q3, sizeof q3, "SELECT COUNT(*) AS c, SUM(d - DATE '%s') AS s FROM t WHERE d >= '%s' AND d <= '%s'", a5, a3, a4);
    snprintf(w3, sizeof w3, "c,s\n%d,%lld\n", want_range, (long long)range_days);
    snprintf(q4, sizeof q4, "SELECT COUNT(*) AS c FROM u JOIN t ON t.d = u.d");
    snprintf(w4, sizeof w4, "c\n%d\n", (DT_N + 6) / 7);
    /* GROUP BY a DATE (the grouped fast path's key from a segment once checkpointed), its MAX of a TIME */
    char qg[160], wg[512];
    snprintf(qg, sizeof qg, "SELECT d, COUNT(*) AS c, MAX(tm) AS m FROM t WHERE n < 5 GROUP BY d ORDER BY d");
    {
        imdb_buf gb;
        imdb_buf_init(&gb);
        imdb_buf_put_str(&gb, "d,c,m\n");
        for (int i = 0; i < 5; i++) {
            imdb_format_date(md[i], &gb);
            imdb_buf_put_str(&gb, ",1,");
            imdb_format_time(mt[i], &gb);
            imdb_buf_put_str(&gb, "\n");
        }
        CHECK(imdb_buf_check(&gb, &e) == 0 && gb.len < sizeof wg);
        snprintf(wg, sizeof wg, "%.*s", (int)gb.len, (const char *)gb.p);
        imdb_buf_free(&gb);
    }
    (void)want_sum;
    OK(run("SET cross_check = on"));
    for (int pass = 0; pass < 5; pass++) {
        if (pass == 1) OK(run("CHECKPOINT")); /* from the lake */
        if (pass == 2) {
            db->segcache.budget = 0; /* every image reloaded */
        }
        if (pass == 3 || pass == 4) {
            done(db);
            db = open_at(dir, pass == 4);
            CHECK(db);
            if (!db) return;
            OK(run("SET cross_check = on"));
        }
        EXPECT(q1, w1);
        EXPECT(q2, w2);
        EXPECT(q3, w3);
        EXPECT(q4, w4);
        EXPECT(qg, wg);
        EXPECT("SELECT COUNT(*) AS c, SUM(n) AS s FROM t", "c,s\n400,79800\n");
        imdb_buf kb;
        imdb_buf_init(&kb);
        imdb_buf_put_str(&kb, "SELECT n FROM t WHERE d = '");
        imdb_format_date(md[123], &kb);
        imdb_buf_put_str(&kb, "'");
        CHECK(imdb_buf_check(&kb, &e) == 0);
        snprintf(sql, sizeof sql, "%.*s", (int)kb.len, (const char *)kb.p);
        imdb_buf_free(&kb);
        EXPECT(sql, "n\n123\n");
    }
    /* writes: UPDATE by the key and by arithmetic, INSERT ... SELECT, ON CONFLICT, a write out of range refused whole */
    imdb_buf ub;
    imdb_buf_init(&ub);
    imdb_buf_put_str(&ub, "UPDATE t SET e = d + 1, tm = '00:00:00' WHERE d = '");
    imdb_format_date(md[10], &ub);
    imdb_buf_put_str(&ub, "'");
    CHECK(imdb_buf_check(&ub, &e) == 0);
    snprintf(sql, sizeof sql, "%.*s", (int)ub.len, (const char *)ub.p);
    imdb_buf_free(&ub);
    EXPECT(sql, "UPDATE 1");
    EXPECT("UPDATE t SET e = DATE '9999-12-31' + n", "ERR a DATE result out of range");
    EXPECT("SELECT COUNT(*) AS c FROM t WHERE e = DATE '9999-12-31'", "c\n0\n");
    OK(run("CREATE TABLE w (d DATE PRIMARY KEY, n INT64)"));
    EXPECT("INSERT INTO w (d, n) SELECT d + 1, n FROM t WHERE n < 10", "INSERT 10");
    EXPECT("INSERT INTO w VALUES ('9999-12-31', 1) ON CONFLICT (d) DO UPDATE SET n = EXCLUDED.n", "INSERT 1");
    EXPECT("INSERT INTO w VALUES ('9999-12-31', 2) ON CONFLICT (d) DO UPDATE SET n = EXCLUDED.n + w.n", "INSERT 1");
    EXPECT("SELECT n FROM w WHERE d = '9999-12-31'", "n\n3\n");
    EXPECT("CREATE VIEW v AS SELECT d, CAST(d AS TIMESTAMP) + tm AS at FROM t", "ERR date arithmetic"); /* TIMESTAMP + TIME: none */
    OK(run("CREATE VIEW v AS SELECT d, d + 7 AS wk, d + tm AS at FROM t WHERE n < 3"));
    EXPECT("SELECT * FROM v WHERE n < 1", "ERR "); /* n is not one of v's columns */
    EXPECT("SELECT COUNT(*) AS c FROM v WHERE wk > d", "c\n3\n");
    CHECK(imdb_verify(db, &(imdb_verify_report){0}, &g_e) == 0);
    char dig[2048];
    snprintf(dig, sizeof dig, "%s", csv("SHOW DIGEST"));
    done(db);
    CHECK(audit_dir(dir) == 0);
    char rp[700], sf[760];
    snprintf(rp, sizeof rp, "%s-replica", dir);
    snprintf(sf, sizeof sf, "%s-stream", dir);
    imdb_identity id;
    OK(imdb_identity_read(dir, &id, NULL, &g_e));
    OK(imdb_init_replica(rp, &id, &g_e));
    OK(ship_to_file(dir, 0, sf, &g_e));
    imdb_db *rep = NULL;
    imdb_open_opts ro = {.sync = 0};
    CHECK(imdb_open(rp, &ro, &rep, &e) == 0);
    if (!rep) return;
    uint64_t applied = 0;
    OK(apply_file(rep, sf, &applied, &g_e));
    imdb_session_init(&g_s, rep);
    EXPECT("SELECT COUNT(*) AS c FROM w", "c\n11\n");
    EXPECT("SELECT COUNT(*) AS c FROM v WHERE wk > d", "c\n3\n");
    const char *rdig = csv("SHOW DIGEST");
    if (strcmp(rdig, dig)) fprintf(stderr, "      primary: %s\n      replica: %s\n", dig, rdig);
    CHECK(!strcmp(rdig, dig));
    done(rep);
    CHECK(audit_dir(rp) == 0);
}

const test_case dt_tests[] = {
    {"dt_codec", t_dt_codec},
    {"dt_sql", t_dt_sql},
    {"dt_cast", t_dt_cast},
    {"dt_paths", t_dt_paths},
};
const size_t dt_ntests = sizeof dt_tests / sizeof *dt_tests;
