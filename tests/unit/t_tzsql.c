/* P2's zone slice through the engine: TIMESTAMPTZ on every path (in memory, from the lake, after a reopen; each query
 * cross-checked against a second plan), the session's zone in output and literals, AT TIME ZONE and date_trunc in
 * WHERE, GROUP BY, ORDER BY and DISTINCT, a zone per row, prepared values, views, a replica, VERIFY and the auditor.
 * The expected answers come from glibc (localtime_r and mktime on the same zone files), never from src/tz.c. */
#include <stdlib.h>
#include <time.h>

#include "../../src/db_internal.h"
#include "../../src/sql.h"
#include "thelp.h"

static imdb_session g_s;
static char g_out[1 << 21];

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

/* the first line where two texts part, for a failure's message */
static void first_diff(const char *a, const char *b, char *out, size_t n)
{
    int line = 1;
    const char *la = a, *lb = b;
    while (*a && *a == *b) {
        if (*a == '\n') line++, la = a + 1, lb = b + 1;
        a++, b++;
    }
    const char *ea = strchr(la, '\n'), *eb = strchr(lb, '\n');
    snprintf(out, n, "line %d: want \"%.*s\", got \"%.*s\"", line, (int)(ea ? ea - la : (long)strlen(la)), la,
             (int)(eb ? eb - lb : (long)strlen(lb)), lb);
}

#define EXPECT(sql, want)                                                                                          \
    do {                                                                                                           \
        const char *got_ = csv(sql);                                                                               \
        bool ok_ = !strncmp((want), "ERR ", 4) ? !strncmp(got_, "ERR ", 4) && strstr(got_ + 4, (want) + 4) != NULL \
                                               : !strcmp(got_, (want));                                            \
        if (!ok_) {                                                                                                \
            char m_[2400], d_[600];                                                                                \
            first_diff((want), got_, d_, sizeof d_);                                                               \
            snprintf(m_, sizeof m_, "%s\n      %s", (sql), d_);                                                    \
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

/* ---- glibc's view of a zone (the model) ------------------------------------------------------------------------- */

static char g_oldtz[512];
static bool g_hadtz;

static void zone_on(const char *name)
{
    const char *o = getenv("TZ");
    g_hadtz = o != NULL;
    snprintf(g_oldtz, sizeof g_oldtz, "%s", o ? o : "");
    char spec[300];
    snprintf(spec, sizeof spec, ":/usr/share/zoneinfo/%s", name);
    setenv("TZ", spec, 1);
    tzset();
}

static void zone_off(void)
{
    if (g_hadtz) setenv("TZ", g_oldtz, 1);
    else unsetenv("TZ");
    tzset();
}

/* t (UTC microseconds) as imagedb writes a TIMESTAMPTZ in the zone glibc has on: its wall clock, then +HH[:MM[:SS]] */
static void model_text(int64_t t_us, bool utc, char *out, size_t n)
{
    time_t s = (time_t)(t_us >= 0 ? t_us / 1000000 : -((-t_us + 999999) / 1000000));
    int64_t us = t_us - (int64_t)s * 1000000;
    struct tm tm;
    long off = 0;
    if (utc) gmtime_r(&s, &tm);
    else {
        localtime_r(&s, &tm);
        off = tm.tm_gmtoff;
    }
    long a = off < 0 ? -off : off;
    char frac[16] = "", tail[16];
    if (us) snprintf(frac, sizeof frac, ".%06lld", (long long)us);
    if (a % 60) snprintf(tail, sizeof tail, "%c%02ld:%02ld:%02ld", off < 0 ? '-' : '+', a / 3600, a / 60 % 60, a % 60);
    else if (a % 3600) snprintf(tail, sizeof tail, "%c%02ld:%02ld", off < 0 ? '-' : '+', a / 3600, a / 60 % 60);
    else snprintf(tail, sizeof tail, "%c%02ld", off < 0 ? '-' : '+', a / 3600);
    snprintf(out, n, "%04d-%02d-%02d %02d:%02d:%02d%s%s", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min,
             tm.tm_sec, frac, tail);
}

/* the instant of the local midnight that begins t's local day, in the zone glibc has on (its midnights are never in a
 * gap or an overlap for the zones used here) */
static int64_t model_day(int64_t t_us)
{
    time_t s = (time_t)(t_us >= 0 ? t_us / 1000000 : -((-t_us + 999999) / 1000000));
    struct tm tm;
    localtime_r(&s, &tm);
    tm.tm_hour = tm.tm_min = tm.tm_sec = 0;
    tm.tm_isdst = -1;
    return (int64_t)mktime(&tm) * 1000000;
}

/* ---- the table ---------------------------------------------------------------------------------------------------- */

#define NROWS 4000
static int64_t g_ts[NROWS];
static bool g_null[NROWS];
static const char *const g_zones[] = {"Europe/London", "America/New_York", "Asia/Kolkata", "Australia/Lord_Howe",
                                      "Asia/Kathmandu", "America/St_Johns", "UTC", "Pacific/Chatham"};

/* the instants: London's and New York's transitions 2025-2027 and a second either side, then random ones (some with
 * microseconds), every 41st NULL */
static void make_instants(void)
{
    test_seed(20261108);
    static const int64_t trans[] = {1743296400, 1761440400, 1774746000, 1792890000, 1806195600, 1824944400,
                                    1741503600, 1762063200, 1772953200, 1793512800, 1805007600, 1825567200};
    int k = 0;
    for (size_t i = 0; i < sizeof trans / sizeof *trans && k + 3 <= NROWS; i++)
        for (int d = -1; d <= 1; d++) g_ts[k++] = (trans[i] + d) * 1000000;
    for (; k < NROWS; k++) {
        int64_t s = 1735689600LL + (int64_t)(test_rand() % 94694400ULL); /* 2025-01-01 .. 2028-01-01 */
        g_ts[k] = s * 1000000 + (k % 7 == 0 ? (int64_t)(test_rand() % 1000000) : 0);
    }
    for (int i = 0; i < NROWS; i++) g_null[i] = i % 41 == 40;
}

/* k: 2023-11-14 22:13:20 UTC on, a second and 3 microseconds a row apart: increasing and distinct */
static int64_t k_of(int i) { return 1700000000LL * 1000000 + (int64_t)i * 1000003; }

static int load_table(void)
{
    if (run("CREATE TABLE t (id INT64 PRIMARY KEY, ts TIMESTAMPTZ, k TIMESTAMPTZ NOT NULL, z TEXT NOT NULL)")) return -1;
    static char q[1 << 16];
    for (int i = 0; i < NROWS;) {
        size_t o = (size_t)snprintf(q, sizeof q, "INSERT INTO t VALUES ");
        for (int j = 0; j < 200 && i < NROWS; j++, i++) {
            char a[64], b[64];
            model_text(g_ts[i], true, a, sizeof a);
            model_text(k_of(i), true, b, sizeof b); /* k: distinct, in the order of i */
            if (g_null[i])
                o += (size_t)snprintf(q + o, sizeof q - o, "%s(%d, NULL, '%s', '%s')", j ? ", " : "", i, b,
                                      g_zones[i % 8]);
            else
                o += (size_t)snprintf(q + o, sizeof q - o, "%s(%d, '%s', '%s', '%s')", j ? ", " : "", i, a, b,
                                      g_zones[i % 8]);
        }
        if (run(q)) return -1;
    }
    return 0;
}

/* each query under each forced path, cross-checked against a second plan: the same text from all */
static const char *const g_paths[] = {"auto", "scan", "store", "ordered"};

static void expect_paths(const char *sql, const char *want)
{
    for (size_t p = 0; p < sizeof g_paths / sizeof *g_paths; p++) {
        char set[64];
        snprintf(set, sizeof set, "SET access_path = %s", g_paths[p]);
        CHECK(run(set) == 0);
        EXPECT(sql, want);
    }
    CHECK(run("SET access_path = auto") == 0);
}

/* the expected answers, from glibc */
static char *model_group_day(const char *zone)
{
    static int64_t key[NROWS];
    static int64_t cnt[NROWS];
    int nk = 0;
    zone_on(zone);
    for (int i = 0; i < NROWS; i++) {
        if (g_null[i]) continue;
        int64_t d = model_day(g_ts[i]);
        int j = 0;
        while (j < nk && key[j] != d) j++;
        if (j == nk) key[nk] = d, cnt[nk++] = 0;
        cnt[j]++;
    }
    zone_off();
    for (int a = 1; a < nk; a++) /* by key */
        for (int b = a; b > 0 && key[b - 1] > key[b]; b--) {
            int64_t tk = key[b], tc = cnt[b];
            key[b] = key[b - 1], cnt[b] = cnt[b - 1];
            key[b - 1] = tk, cnt[b - 1] = tc;
        }
    char *out = malloc((size_t)nk * 48 + 16);
    size_t o = (size_t)sprintf(out, "d,n\n");
    for (int j = 0; j < nk; j++) {
        char t[64];
        model_text(key[j], true, t, sizeof t);
        o += (size_t)sprintf(out + o, "%s,%lld\n", t, (long long)cnt[j]);
    }
    return out;
}

static void check_queries(bool lake)
{
    /* the session's zone in output: the first rows in four zones */
    static const char *const show[] = {"Europe/London", "Asia/Kathmandu", "America/St_Johns", "Pacific/Chatham"};
    for (size_t z = 0; z < sizeof show / sizeof *show; z++) {
        char set[96], *want = malloc(1 << 16);
        snprintf(set, sizeof set, "SET TIME ZONE '%s'", show[z]);
        CHECK(run(set) == 0);
        zone_on(show[z]);
        size_t o = (size_t)sprintf(want, "id,ts\n");
        for (int i = 0; i < 60; i++) {
            char t[64] = "";
            if (!g_null[i]) model_text(g_ts[i], false, t, sizeof t);
            o += (size_t)sprintf(want + o, "%d,%s\n", i, g_null[i] ? "" : t); /* CSV: a NULL the empty field */
        }
        zone_off();
        expect_paths("SELECT id, ts FROM t WHERE id < 60 ORDER BY id", want);
        free(want);
    }
    CHECK(run("SET TIME ZONE DEFAULT") == 0);
    EXPECT("SHOW TIME ZONE", "TimeZone\n\"UTC\"\n");
    /* GROUP BY a day in a zone (glibc's local midnights) */
    uint64_t fg0 = imdb_sql_fast_group_segments(); /* from the lake, the fast path's FG_TRUNC takes these */
    char *want = model_group_day("Europe/London");
    expect_paths("SELECT date_trunc('day', ts, 'Europe/London') AS d, count(*) AS n FROM t WHERE ts IS NOT NULL "
                 "GROUP BY date_trunc('day', ts, 'Europe/London') ORDER BY 1", want);
    free(want);
    if (lake) CHECK(imdb_sql_fast_group_segments() > fg0);
    want = model_group_day("America/New_York");
    CHECK(run("SET TIME ZONE 'America/New_York'") == 0);
    /* the same groups by the session's zone, shown in it: each midnight its own offset */
    zone_on("America/New_York");
    char *w2 = malloc(strlen("d,n\n") + 64 * NROWS);
    {
        const char *p = strchr(want, '\n') + 1;
        size_t o = (size_t)sprintf(w2, "d,n\n");
        while (*p) {
            const char *nl = strchr(p, '\n');
            const char *comma = strchr(p, ',');
            struct tm tm;
            memset(&tm, 0, sizeof tm);
            sscanf(p, "%d-%d-%d %d:%d:%d", &tm.tm_year, &tm.tm_mon, &tm.tm_mday, &tm.tm_hour, &tm.tm_min, &tm.tm_sec);
            tm.tm_year -= 1900, tm.tm_mon -= 1;
            int64_t us = (int64_t)timegm(&tm) * 1000000;
            char t[64];
            model_text(us, false, t, sizeof t);
            o += (size_t)sprintf(w2 + o, "%s%.*s\n", t, (int)(nl - comma), comma);
            p = nl + 1;
        }
    }
    zone_off();
    expect_paths("SELECT date_trunc('day', ts) AS d, count(*) AS n FROM t WHERE ts IS NOT NULL GROUP BY date_trunc('day', ts) "
                 "ORDER BY 1", w2);
    free(w2);
    free(want);
    CHECK(run("SET TIME ZONE 'UTC'") == 0);
    /* ranges, counts, extremes: the model's */
    int64_t lo = 1774746000LL * 1000000, hi = 1792890000LL * 1000000; /* London's 2026 summer */
    long long in = 0, nn = 0, onhour = 0, ny = 0, mn = INT64_MAX, mx = INT64_MIN, perrow = 0;
    zone_on("America/New_York");
    for (int i = 0; i < NROWS; i++) {
        if (g_null[i]) continue;
        nn++;
        in += g_ts[i] >= lo && g_ts[i] < hi;
        onhour += g_ts[i] % 3600000000LL == 0;
        mn = g_ts[i] < mn ? g_ts[i] : mn;
        mx = g_ts[i] > mx ? g_ts[i] : mx;
        time_t s = (time_t)(g_ts[i] / 1000000);
        struct tm tm;
        localtime_r(&s, &tm);
        ny += tm.tm_year + 1900 > 2026 || (tm.tm_year + 1900 == 2026 && tm.tm_mon >= 6); /* local >= 2026-07-01 */
    }
    zone_off();
    for (int i = 0; i < NROWS; i++) { /* AT TIME ZONE z, z the row's own zone: local time at or past 12:00 */
        if (g_null[i]) continue;
        zone_on(g_zones[i % 8]);
        time_t s = (time_t)(g_ts[i] / 1000000);
        struct tm tm;
        localtime_r(&s, &tm);
        perrow += tm.tm_hour >= 10; /* the LIKEs: hours 10-19 and 20-23 */
        zone_off();
    }
    char w[256], a[64], b[64];
    snprintf(w, sizeof w, "n\n%lld\n", in);
    expect_paths("SELECT count(*) AS n FROM t WHERE ts >= TIMESTAMPTZ '2026-03-29 01:00:00+00' AND ts < '2026-10-25 02:00:00+01'", w);
    model_text(mn, true, a, sizeof a);
    model_text(mx, true, b, sizeof b);
    snprintf(w, sizeof w, "lo,hi,n\n%s,%s,%lld\n", a, b, nn);
    expect_paths("SELECT min(ts) AS lo, max(ts) AS hi, count(ts) AS n FROM t", w);
    snprintf(w, sizeof w, "n\n%lld\n", onhour);
    expect_paths("SELECT count(*) AS n FROM t WHERE date_trunc('hour', ts) = ts", w);
    snprintf(w, sizeof w, "n\n%lld\n", ny);
    expect_paths("SELECT count(*) AS n FROM t WHERE ts AT TIME ZONE 'America/New_York' >= TIMESTAMP '2026-07-01 00:00:00'", w);
    snprintf(w, sizeof w, "n\n%lld\n", perrow);
    /* a zone per row: the local wall clock of ts in its row's own zone z, at 10:00 or later */
    expect_paths("SELECT count(*) AS n FROM t WHERE CAST(ts AT TIME ZONE z AS TEXT) LIKE '% 1_:%' OR "
                 "CAST(ts AT TIME ZONE z AS TEXT) LIKE '% 2_:%'", w);
    /* the key column: an ordered index on a TIMESTAMPTZ, its order, a key lookup by an offset literal */
    CHECK(run("CREATE INDEX tk ON t (k)") == 0);
    {
        char *wk = malloc(1 << 14);
        size_t o = (size_t)sprintf(wk, "id\n");
        for (int i = 0; i < 25; i++) o += (size_t)sprintf(wk + o, "%d\n", i);
        expect_paths("SELECT id FROM t ORDER BY k LIMIT 25", wk);
        free(wk);
        char kt[64], q[256];
        model_text(k_of(777), true, kt, sizeof kt);
        snprintf(q, sizeof q, "SELECT id FROM t WHERE k = '%s'", kt);
        expect_paths(q, "id\n777\n");
        /* the same instant written in Kathmandu's offset */
        CHECK(run("SET TIME ZONE 'Asia/Kathmandu'") == 0);
        char kl[64];
        zone_on("Asia/Kathmandu");
        model_text(k_of(777), false, kl, sizeof kl);
        zone_off();
        snprintf(q, sizeof q, "SELECT id FROM t WHERE k = '%s'", kl);
        expect_paths(q, "id\n777\n");
        CHECK(run("SET TIME ZONE 'UTC'") == 0);
    }
    /* DISTINCT months, in UTC */
    {
        int64_t months[64];
        int nm = 0;
        for (int i = 0; i < NROWS; i++) {
            if (g_null[i]) continue;
            time_t s = (time_t)(g_ts[i] / 1000000);
            struct tm tm;
            gmtime_r(&s, &tm);
            tm.tm_mday = 1, tm.tm_hour = tm.tm_min = tm.tm_sec = 0;
            int64_t m = (int64_t)timegm(&tm);
            int j = 0;
            while (j < nm && months[j] != m) j++;
            if (j == nm && nm < 64) months[nm++] = m;
        }
        char *wm = malloc(4096);
        snprintf(wm, 4096, "n\n%d\n", nm);
        expect_paths("SELECT count(*) AS n FROM (SELECT DISTINCT date_trunc('month', ts) AS m FROM t WHERE ts IS NOT NULL) AS d", wm);
        free(wm);
    }
}

static void t_tzsql_paths(void)
{
    char dir[600];
    snprintf(dir, sizeof dir, "%s/db", test_tmpdir());
    imdb_err e = {0};
    CHECK_OK(imdb_init(dir, false, NULL, &e));
    imdb_db *db = open_at(dir);
    CHECK(db);
    keep_in_memory(db);
    make_instants();
    CHECK(load_table() == 0);
    CHECK(run("SET cross_check = on") == 0);
    check_queries(false); /* in memory */
    CHECK(run("DROP INDEX tk") == 0);
    CHECK(run("CHECKPOINT") == 0);
    check_queries(true); /* from the lake */
    CHECK(run("VERIFY") == 0);
    done(db);
    db = open_at(dir);
    CHECK(db);
    CHECK(run("SET cross_check = on") == 0);
    CHECK(run("DROP INDEX tk") == 0);
    check_queries(true); /* after a reopen */
    done(db);
    CHECK(audit_dir(dir) == 0);
}


static imdb_db *fresh(const char *name)
{
    char dir[600];
    snprintf(dir, sizeof dir, "%s/%s", test_tmpdir(), name);
    imdb_err e = {0};
    if (imdb_init(dir, false, NULL, &e)) return NULL;
    return open_at(dir);
}

/* each literal form to its instant (hand-checked against PostgreSQL 14: .work/tz-probe), shown in UTC; the session's
 * zone for a literal without an offset; odd offsets shown as PostgreSQL writes them (glibc's for the local mean times);
 * the range's ends */
static void t_tzsql_literals(void)
{
    imdb_db *db = fresh("db");
    CHECK(db);
    static const char *const in[][2] = {
        {"2026-01-01 10:00:00+05:30", "2026-01-01 04:30:00+00"}, {"2026-01-01 10:00:00-0430", "2026-01-01 14:30:00+00"},
        {"2026-01-01 10:00:00 -04:30", "2026-01-01 14:30:00+00"}, {"2026-01-01 10:00:00Z", "2026-01-01 10:00:00+00"},
        {"2026-01-01T10:00:00.25+01", "2026-01-01 09:00:00.250000+00"}, {"2026-01-01", "2026-01-01 00:00:00+00"},
        {"2026-01-01 Europe/Paris", "2025-12-31 23:00:00+00"}, {"2026-06-01 12:00:00 America/New_York", "2026-06-01 16:00:00+00"},
        {"2026-03-29 01:30:00 Europe/London", "2026-03-29 01:30:00+00"}, /* in the gap: the offset before */
        {"2026-10-25 01:30:00 Europe/London", "2026-10-25 01:30:00+00"}, /* in the overlap: the later instant */
        {"2026-01-01 10:00:00+00:01:15", "2026-01-01 09:58:45+00"},      {"2026-01-01 10:00:00 UTC", "2026-01-01 10:00:00+00"},
        {"2026-01-01 10:00:00 etc/gmt", "2026-01-01 10:00:00+00"},       {"0001-01-01 00:00:00+00", "0001-01-01 00:00:00+00"},
        {"9999-12-31 23:59:59.999999+00", "9999-12-31 23:59:59.999999+00"},
    };
    for (size_t i = 0; i < sizeof in / sizeof *in; i++) {
        char q[200], w[200];
        snprintf(q, sizeof q, "SELECT TIMESTAMPTZ '%s' AS v", in[i][0]);
        snprintf(w, sizeof w, "v\n%s\n", in[i][1]);
        EXPECT(q, w);
        snprintf(q, sizeof q, "SELECT CAST('%s' AS TIMESTAMPTZ) AS v", in[i][0]);
        EXPECT(q, w);
    }
    static const char *const bad[][2] = {
        {"2026-01-01 10:00:00+16:00", "ERR at most 15:59:59"}, {"2026-13-01 00:00:00+00", "ERR field out of range"},
        {"2026-01-01 25:00:00+00", "ERR field out of range"},  {"2026-01-01 10:00:00 Nowhere/Zone", "ERR unknown time zone"},
        {"2026-01-01 10:00:00 ../etc", "ERR zone is named by"}, {"2026-01-01 10:00:00+5", "ERR must look like"},
        {"0001-01-01 00:00:00+01", "ERR before 0001-01-01"},  {"9999-12-31 23:59:59-01", "ERR past 9999-12-31"},
        {"2026-01-01 localtime", "ERR unknown time zone"},     {"2026-01-01 10:00:00 Europe/London/x", "ERR unknown time zone"},
    };
    for (size_t i = 0; i < sizeof bad / sizeof *bad; i++) {
        char q[200];
        snprintf(q, sizeof q, "SELECT TIMESTAMPTZ '%s'", bad[i][0]);
        EXPECT(q, bad[i][1]);
    }
    EXPECT("SELECT TIMESTAMP '2026-01-01 10:00:00+05'", "ERR only UTC is supported");
    /* the session's zone reads a literal without an offset, and shows every value */
    CHECK(run("SET TIME ZONE 'Asia/Kolkata'") == 0);
    EXPECT("SELECT TIMESTAMPTZ '2026-01-01 10:00:00' AS v, CAST(TIMESTAMPTZ '2026-01-01 10:00:00' AS TIMESTAMP) AS w",
           "v,w\n2026-01-01 10:00:00+05:30,2026-01-01 10:00:00\n");
    static const char *const odd[] = {"Pacific/Chatham", "America/St_Johns", "Asia/Kathmandu", "Europe/Amsterdam",
                                      "Africa/Monrovia", "Pacific/Kiritimati", "Pacific/Pago_Pago"};
    static const int64_t at[] = {1767225600LL, 1782864000LL, -2208988800LL, -1500000000LL, -1000000000LL};
    for (size_t z = 0; z < sizeof odd / sizeof *odd; z++) {
        char set[100];
        snprintf(set, sizeof set, "SET TIME ZONE '%s'", odd[z]);
        CHECK(run(set) == 0);
        for (size_t k = 0; k < sizeof at / sizeof *at; k++) {
            char q[200], w[200], t[64], u[64];
            model_text(at[k] * 1000000, true, u, sizeof u);
            zone_on(odd[z]);
            model_text(at[k] * 1000000, false, t, sizeof t);
            zone_off();
            snprintf(q, sizeof q, "SELECT TIMESTAMPTZ '%s' AS v", u);
            snprintf(w, sizeof w, "v\n%s\n", t);
            EXPECT(q, w);
        }
    }
    done(db);
}

/* every refusal: the two types never compared, assigned or computed across without AT TIME ZONE or CAST; date_trunc's
 * and AT TIME ZONE's arguments; zones unknown, malformed or NULL */
static void t_tzsql_refusals(void)
{
    imdb_db *db = fresh("db");
    CHECK(db);
    CHECK(run("CREATE TABLE t (id INT64 PRIMARY KEY, tz TIMESTAMPTZ, w TIMESTAMP, z TEXT, u TEXT)") == 0);
    CHECK(run("INSERT INTO t VALUES (1, '2026-01-01 00:00:00+00', '2026-01-01 00:00:00', 'Asia/Tokyo', 'day'), "
              "(2, NULL, NULL, NULL, 'hour')") == 0);
    EXPECT("SELECT tz = w FROM t", "ERR TIMESTAMPTZ with TIMESTAMP");
    EXPECT("SELECT count(*) FROM t WHERE tz > w", "ERR values are not converted");
    EXPECT("SELECT COALESCE(tz, w) FROM t", "ERR values are not converted");
    EXPECT("INSERT INTO t (id, tz) VALUES (3, TIMESTAMP '2026-01-01 00:00:00')", "ERR expects TIMESTAMPTZ");
    EXPECT("INSERT INTO t (id, w) VALUES (3, TIMESTAMPTZ '2026-01-01 00:00:00+00')", "ERR expects TIMESTAMP");
    EXPECT("UPDATE t SET tz = w WHERE id = 1", "ERR expects a TIMESTAMPTZ");
    EXPECT("SELECT tz + 1 FROM t", "ERR arithmetic takes");
    EXPECT("SELECT sum(tz) FROM t", "ERR SUM needs");
    EXPECT("SELECT avg(tz) FROM t", "ERR AVG needs");
    EXPECT("SELECT date_trunc('fortnight', tz) FROM t", "ERR date_trunc's unit");
    EXPECT("SELECT date_trunc(u, tz) FROM t", "ERR string constant");
    EXPECT("SELECT date_trunc('day', w, 'UTC') FROM t", "ERR TIMESTAMPTZ's zone");
    EXPECT("SELECT date_trunc('day', z) FROM t", "ERR takes a TIMESTAMP or a TIMESTAMPTZ");
    EXPECT("SELECT date_trunc('day') FROM t", "ERR DATE_TRUNC takes 2 to 3 arguments");
    EXPECT("SELECT '2026-01-01 00:00:00' AT TIME ZONE 'UTC'", "ERR write TIMESTAMP");
    EXPECT("SELECT tz AT TIME ZONE 5 FROM t", "ERR zone's name (TEXT)");
    EXPECT("SELECT tz AT TIME ZONE 'Mars/Base' FROM t", "ERR unknown time zone");
    EXPECT("SELECT tz AT TIME ZONE '../../etc/passwd' FROM t", "ERR a time zone is named by");
    EXPECT("SELECT CAST(tz AS INT64) FROM t", "ERR CAST of TIMESTAMPTZ to INT64 is not defined");
    EXPECT("SELECT CAST(5 AS TIMESTAMPTZ)", "ERR CAST of INT64 to TIMESTAMPTZ is not defined");
    EXPECT("CREATE TABLE b (id INT64 PRIMARY KEY, x TIMESTAMP WITH TIMEZONE)", "ERR syntax error");
    /* a zone named by a row: NULL gives NULL, an unknown one fails the statement when a row needs it */
    EXPECT("SELECT id, tz AT TIME ZONE z AS l FROM t ORDER BY id", "id,l\n1,2026-01-01 09:00:00\n2,\n");
    CHECK(run("INSERT INTO t VALUES (3, '2026-01-01 00:00:00+00', NULL, 'Mars/Base', 'day')") == 0);
    EXPECT("SELECT id, tz AT TIME ZONE z FROM t ORDER BY id", "ERR unknown time zone");
    /* SET TIME ZONE: refused names leave the zone as it was */
    CHECK(run("SET TIME ZONE 'Asia/Tokyo'") == 0);
    EXPECT("SET TIME ZONE 'Nowhere/Zone'", "ERR unknown time zone");
    EXPECT("SET timezone = utc", "ERR a time zone's name as a string");
    EXPECT("SET TIME ZONE '/etc/localtime'", "ERR a time zone is named by");
    EXPECT("SHOW TIME ZONE", "TimeZone\n\"Asia/Tokyo\"\n");
    done(db);
}

/* two sessions, each its own zone; DEFAULT and LOCAL; the built-in names in any case; a SET inside a transaction kept
 * after its ROLLBACK (imagedb's SETs are a session's, not a transaction's: design.md) */
static void t_tzsql_sessions(void)
{
    imdb_db *db = fresh("db");
    CHECK(db);
    CHECK(run("CREATE TABLE t (id INT64 PRIMARY KEY, tz TIMESTAMPTZ)") == 0);
    CHECK(run("INSERT INTO t VALUES (1, '2026-07-01 12:00:00+00')") == 0);
    imdb_session s2;
    imdb_session_init(&s2, db);
    CHECK(run("SET TIME ZONE 'America/New_York'") == 0);
    imdb_result r;
    imdb_err e = {0};
    CHECK(imdb_exec_one(&s2, "SET TIME ZONE 'Asia/Tokyo'", 26, NULL, 0, &r, &e) == 0);
    imdb_result_free(&r);
    EXPECT("SELECT tz FROM t", "tz\n2026-07-01 08:00:00-04\n");
    CHECK(imdb_exec_one(&s2, "SELECT tz FROM t", 16, NULL, 0, &r, &e) == 0);
    imdb_buf b;
    imdb_buf_init(&b);
    imdb_result_render(&r, true, &b);
    CHECK(b.len == 26 && !memcmp(b.p, "tz\n2026-07-01 21:00:00+09\n", 26));
    imdb_buf_free(&b);
    imdb_result_free(&r);
    imdb_session_close(&s2);
    CHECK(run("SET TIME ZONE LOCAL") == 0);
    EXPECT("SHOW TIME ZONE", "TimeZone\n\"UTC\"\n");
    CHECK(run("SET TIME ZONE 'gmt'") == 0);
    EXPECT("SHOW TIME ZONE", "TimeZone\n\"gmt\"\n");
    EXPECT("SELECT tz FROM t", "tz\n2026-07-01 12:00:00+00\n");
    CHECK(run("SET timezone TO 'Europe/Berlin'") == 0);
    EXPECT("SELECT tz FROM t", "tz\n2026-07-01 14:00:00+02\n");
    CHECK(run("BEGIN") == 0 && run("SET TIME ZONE 'Asia/Kolkata'") == 0 && run("ROLLBACK") == 0);
    EXPECT("SHOW TIME ZONE", "TimeZone\n\"Asia/Kolkata\"\n");
    CHECK(run("SET TIME ZONE DEFAULT") == 0);
    EXPECT("SELECT tz FROM t", "tz\n2026-07-01 12:00:00+00\n");
    done(db);
}

/* a TIMESTAMPTZ through PREPARE's declared type (a literal's rules at EXECUTE, in that EXECUTE's session zone) and the
 * API's values (an instant: no zone) */
static void t_tzsql_prepared(void)
{
    imdb_db *db = fresh("db");
    CHECK(db);
    CHECK(run("CREATE TABLE t (id INT64 PRIMARY KEY, tz TIMESTAMPTZ)") == 0);
    CHECK(run("INSERT INTO t VALUES (1, '2026-01-01 00:00:00+00'), (2, '2026-01-01 05:00:00+00'), (3, '2026-01-02 00:00:00+00')") == 0);
    CHECK(run("PREPARE p (TIMESTAMPTZ) AS SELECT count(*) AS n FROM t WHERE tz >= $1") == 0);
    EXPECT("EXECUTE p ('2026-01-01 10:00:00+05:30')", "n\n2\n"); /* 04:30 UTC */
    CHECK(run("SET TIME ZONE 'America/New_York'") == 0);
    EXPECT("EXECUTE p ('2026-01-01 00:00:00')", "n\n2\n"); /* 05:00 UTC, read in the session's zone at EXECUTE (UTC: 3) */
    CHECK(run("SET TIME ZONE 'UTC'") == 0);
    imdb_value pv = {.type = IMDB_T_TIMESTAMPTZ, .i = 1767243600000000LL}; /* 2026-01-01 05:00:00 UTC */
    imdb_result r;
    imdb_err e = {0};
    const char *q = "SELECT id FROM t WHERE tz = $1";
    CHECK(imdb_exec_one(&g_s, q, strlen(q), &pv, 1, &r, &e) == 0);
    CHECK(r.nrows == 1 && r.cells[0].v.i == 2);
    imdb_result_free(&r);
    const char *ins = "INSERT INTO t VALUES (4, $1)";
    CHECK(imdb_exec_one(&g_s, ins, strlen(ins), &pv, 1, &r, &e) == 0);
    imdb_result_free(&r);
    EXPECT("SELECT id, tz FROM t WHERE id = 4", "id,tz\n4,2026-01-01 05:00:00+00\n");
    imdb_value tv = {.type = IMDB_T_TIMESTAMP, .i = 1767243600000000LL}; /* a TIMESTAMP for a TIMESTAMPTZ: refused */
    CHECK(imdb_exec_one(&g_s, q, strlen(q), &tv, 1, &r, &e) != 0);
    done(db);
}

/* a view of the zone functions read alike in memory, from the lake, after a reopen from the snapshot and a full replay,
 * on a replica at the primary's digest; VERIFY and the auditor on both */
static void t_tzsql_views(void)
{
    char p[600], rp[600], sf[600];
    snprintf(p, sizeof p, "%s/primary", test_tmpdir());
    snprintf(rp, sizeof rp, "%s/replica", test_tmpdir());
    snprintf(sf, sizeof sf, "%s/stream", test_tmpdir());
    imdb_err e = {0};
    CHECK(imdb_init(p, false, NULL, &e) == 0 && imdb_init(rp, true, p, &e) == 0);
    imdb_db *db = open_at(p);
    CHECK(db);
    CHECK(run("CREATE TABLE t (id INT64 PRIMARY KEY, tz TIMESTAMPTZ, w TIMESTAMP)") == 0);
    CHECK(run("INSERT INTO t VALUES (1, '2026-03-29 00:30:00+00', '2026-03-29 01:30:00'), (2, '2026-10-25 00:30:00+00', "
              "'2026-10-25 01:30:00'), (3, NULL, NULL)") == 0);
    CHECK(run("CREATE VIEW v (id, lon, inst, d, h) AS SELECT id, tz AT TIME ZONE 'Europe/London', w AT TIME ZONE "
              "'Europe/London', date_trunc('day', tz, 'Asia/Tokyo'), date_trunc('hour', CAST(w AS TIMESTAMPTZ)) FROM t") == 0);
    const char *want = "id,lon,inst,d,h\n1,2026-03-29 00:30:00,2026-03-29 01:30:00+00,2026-03-28 15:00:00+00,"
                       "2026-03-29 01:00:00+00\n2,2026-10-25 01:30:00,2026-10-25 01:30:00+00,2026-10-24 15:00:00+00,"
                       "2026-10-25 01:00:00+00\n3,,,,\n";
    EXPECT("SELECT * FROM v ORDER BY id", want);
    CHECK(run("CHECKPOINT") == 0);
    EXPECT("SELECT * FROM v ORDER BY id", want);
    char dig[512];
    snprintf(dig, sizeof dig, "%s", csv("SHOW DIGEST"));
    done(db);
    imdb_open_opts o = {.sync = 0, .full_replay = true};
    imdb_db *fr = NULL;
    CHECK(imdb_open(p, &o, &fr, &e) == 0);
    imdb_session_init(&g_s, fr);
    EXPECT("SELECT * FROM v ORDER BY id", want);
    CHECK(run("VERIFY") == 0);
    done(fr);
    db = open_at(p);
    CHECK(db);
    EXPECT("SELECT * FROM v ORDER BY id", want);
    done(db);
    CHECK(ship_to_file(p, 0, sf, &e) == 0);
    imdb_db *rep = NULL;
    imdb_open_opts ro = {.sync = 0};
    CHECK(imdb_open(rp, &ro, &rep, &e) == 0);
    uint64_t applied = 0;
    CHECK(apply_file(rep, sf, &applied, &e) == 0);
    imdb_session_init(&g_s, rep);
    EXPECT("SELECT * FROM v ORDER BY id", want);
    CHECK(!strcmp(csv("SHOW DIGEST"), dig));
    done(rep);
    CHECK(audit_dir(p) == 0 && audit_dir(rp) == 0);
}

const test_case tzsql_tests[] = {
    {"tzsql_paths", t_tzsql_paths},
    {"tzsql_literals", t_tzsql_literals},
    {"tzsql_refusals", t_tzsql_refusals},
    {"tzsql_sessions", t_tzsql_sessions},
    {"tzsql_prepared", t_tzsql_prepared},
    {"tzsql_views", t_tzsql_views},
};
const size_t tzsql_ntests = sizeof tzsql_tests / sizeof *tzsql_tests;
