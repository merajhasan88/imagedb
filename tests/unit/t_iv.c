/* F3f: INTERVAL (docs/f3f-design.md). Its text forms both ways against PostgreSQL 14's own answers (each recorded from a
 * postgres:14 container as a literal here: 157 inputs, the refusals among them) and every triple's text read back as
 * that triple; the codec (the row's 16 bytes, the check, the hash of the triple, the order of the span); the arithmetic
 * against PostgreSQL 14's answers (71 expressions: month ends, leap years, the range's ends, overflow); the rules
 * (MIN and MAX of equal spans the least triple, SUM's total held to the fields, every refusal); then a table of
 * INTERVALs, months and days with no microseconds among them and the equal-span trio '1 mon', '30 days', '720:00:00',
 * against a model of its own (its own calendar, not the engine's) on every path: in memory, cross-checked, after a
 * CHECKPOINT, at a segment budget of none, after a reopen and a full replay at the same digest; joins by the span, a
 * correlated subquery whose memo must key the triple, windows, a view; writes, an ADD with a DEFAULT read by older
 * segments and a flush writing it as a cell, SET DEFAULT; VERIFY, the auditor, a replica at the primary's digest, COPY
 * both ways and the dump restored. */
#include <stdlib.h>

#include "../../src/codec.h"
#include "../../src/db_internal.h"
#include "../../src/lthash.h"
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

static char g_copy[1 << 17];
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
            char m_[3000];                                                                                         \
            snprintf(m_, sizeof m_, "%.900s\n      want: %.900s\n      got:  %.900s", (sql), (want), got_);        \
            test_fail(__FILE__, __LINE__, m_);                                                                     \
        }                                                                                                          \
    } while (0)

static imdb_db *open_with(const char *dir, bool full_replay, uint64_t budget)
{
    imdb_open_opts o = {.sync = 0, .full_replay = full_replay, .seg_cache_bytes = budget};
    imdb_db *db = NULL;
    imdb_err e = {0};
    if (imdb_open(dir, &o, &db, &e)) {
        fprintf(stderr, "    open%s: %s\n", full_replay ? " (a full replay)" : "", e.msg); /* the CHECK after says where */
        return NULL;
    }
    imdb_session_init(&g_s, db);
    imdb_session_copy_io(&g_s, mem_read, mem_write, &g_in);
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

static int verify_db(imdb_db *db)
{
    imdb_verify_report vr;
    memset(&vr, 0, sizeof vr);
    imdb_err_clear(&g_e);
    return imdb_verify(db, &vr, &g_e);
}

/* an INTERVAL's text into one of a few rotating buffers (several in one expression) */
static const char *ivt(int32_t mon, int32_t day, int64_t us)
{
    static char b[8][160];
    static int k;
    char *o = b[k++ & 7];
    imdb_buf t;
    imdb_buf_init(&t);
    imdb_format_interval(mon, day, us, &t);
    snprintf(o, 160, "%.*s", (int)t.len, (const char *)t.p);
    imdb_buf_free(&t);
    return o;
}

/* ---- the text forms: PostgreSQL 14's answers, recorded from its container (SELECT 'text'::interval) ---- */
static const struct {
    const char *in, *out; /* out "ERROR": PostgreSQL refused it */
} kPg14[] = {
    {"1 year 2 months 3 days 4 hours 5 minutes 6.789 seconds", "1 year 2 mons 3 days 04:05:06.789"},
    {"-1 day 2 hours", "-1 days +02:00:00"},
    {"1 day -2 hours", "1 day -02:00:00"},
    {"-1 year -2 mons +3 days", "-1 years -2 mons +3 days"},
    {"@ 1 day ago", "-1 days"},
    {"1.5 days", "1 day 12:00:00"},
    {"1.5 months", "1 mon 15 days"},
    {"1.5 years", "1 year 6 mons"},
    {"0.5 weeks", "3 days 12:00:00"},
    {"1 decade", "10 years"},
    {"100 microseconds", "00:00:00.0001"},
    {"-0.000001 sec", "-00:00:00.000001"},
    {"720:00:00", "720:00:00"},
    {"0 seconds", "00:00:00"},
    {"1 mon", "1 mon"},
    {"30 days", "30 days"},
    {"-1 days -02:00:00", "-1 days -02:00:00"},
    {"1 day 01:02", "1 day 01:02:00"},
    {"1 day 01:02:03.5", "1 day 01:02:03.5"},
    {"-1:00", "-01:00:00"},
    {"1 hour 30", "01:00:30"},
    {"2 weeks 3 days", "17 days"},
    {"1 century", "100 years"},
    {"1 millennium", "1000 years"},
    {"13 months", "1 year 1 mon"},
    {"-13 months", "-1 years -1 mons"},
    {"1.5 hours", "01:30:00"},
    {"0.1 seconds", "00:00:00.1"},
    {"1 y 2 mon 3 d 4 h 5 m 6 s", "1 year 2 mons 3 days 04:05:06"},
    {"1 yr", "1 year"},
    {"2 hrs", "02:00:00"},
    {"3 mins", "00:03:00"},
    {"4 secs", "00:00:04"},
    {"5 msec", "00:00:00.005"},
    {"6 usec", "00:00:00.000006"},
    {"7 ms", "00:00:00.007"},
    {"8 us", "00:00:00.000008"},
    {"1 day ago", "-1 days"},
    {"-1 day ago", "1 day"},
    {"1:30:45.123456789", "01:30:45.123457"},
    {"178000000 years", "178000000 years"},
    {"2147483647 days", "2147483647 days"},
    {"2147483648 days", "ERROR"},
    {"-2147483648 days", "-2147483648 days"},
    {"2147483647 months", "178956970 years 7 mons"},
    {"1e3 seconds", "ERROR"},
    {".5 days", "12:00:00"},
    {"1. days", "ERROR"},
    {"+1 day", "1 day"},
    {"1 DAY", "1 day"},
    {"2147483647 hours", "2147483647:00:00"},
    {"2147483648 hours", "ERROR"},
    {"1 hour -1 second", "00:59:59"},
    {"-1 hour 1 second", "-00:59:59"},
    {"1 mon -1 day", "1 mon -1 days"},
    {"-1 mon 1 day -1 hour", "-1 mons +1 day -01:00:00"},
    {"1 mons", "1 mon"},
    {"1 days", "1 day"},
    {"-1 day -1 hour", "-1 days -01:00:00"},
    {"1 year -1 mon", "11 mons"},
    {"12 mons", "1 year"},
    {"0 years", "00:00:00"},
    {"00:00:00.000000", "00:00:00"},
    {"1 sec 500 ms", "00:00:01.5"},
    {"1.123456789 seconds", "00:00:01.123457"},
    {"0.0000005 seconds", "00:00:00"},
    {"0.0000015 seconds", "00:00:00.000002"},
    {"-0.0000005 seconds", "00:00:00"},
    {"1 week", "7 days"},
    {"1.5 weeks", "10 days 12:00:00"},
    {"0.3 months", "9 days"},
    {"0.1 years", "1 mon"},
    {"1.01 years", "1 year"},
    {"1000000000 days", "1000000000 days"},
    {"35791394 years 7 mons", "35791394 years 7 mons"},
    {"-178956970 years -8 mons", "-178956970 years -8 mons"},
    {"1day", "1 day"},
    {"1d2h", "1 day 02:00:00"},
    {"1.5days", "1 day 12:00:00"},
    {"00:00:60", "00:01:00"},
    {"00:00:61", "ERROR"},
    {"1:60", "ERROR"},
    {"1:30.5", "00:01:30.5"},
    {"10:00 ago", "-10:00:00"},
    {"+1:00", "01:00:00"},
    {"1 +02:03", "1 day 02:03:00"},
    {"-1 2:03:04", "-1 days +02:03:04"},
    {"1 2", "ERROR"},
    {"1.5", "00:00:01.5"},
    {"5", "00:00:05"},
    {"1:2:3", "01:02:03"},
    {"1 day 2", "1 day 00:00:02"},
    {"-1.5 days", "-1 days -12:00:00"},
    {"- 1 day", "-1 days"},
    {"1 - day", "ERROR"},
    {"day", "ERROR"},
    {"1 fortnight", "ERROR"},
    {"1 hour 1 hour", "ERROR"},
    {"1 days 1 day", "ERROR"},
    {"2 secs 500 msecs", "00:00:02.5"},
    {"1 ms 1 us", "00:00:00.001001"},
    {"3 hours 1:00", "ERROR"},
    {"1 day ago 2 hours", "-1 days -02:00:00"},
    {"ago 1 day", "-1 days"},
    {"@1 day", "1 day"},
    {"1 DAYS", "1 day"},
    {"1 Mon", "1 mon"},
    {"1,5 days", "ERROR"},
    {"1  day", "1 day"},
    {" 1 day ", "1 day"},
    {"1e1 days", "ERROR"},
    {"0x10 days", "ERROR"},
    {"1 sec ago ago", "-00:00:01"},
    {"1 microsecondsxyz", "00:00:00.000001"},
    {"-1.5 weeks", "-10 days -12:00:00"},
    {"0.123456789 days", "02:57:46.66657"},
    {"1.000001 years", "1 year"},
    {"-0.5 mons", "-15 days"},
    {"1 c", "100 years"},
    {"1 dec", "10 years"},
    {"1 mil", "1000 years"},
    {"1 cent", "100 years"},
    {"3 decs", "30 years"},
    {"2 mils", "2000 years"},
    {"1 millennia", "1000 years"},
    {"1 2 hours", "1 day 02:00:00"},
    {"day 1", "00:00:01"},
    {"1 hour 2 day", "2 days 01:00:00"},
    {"1.5 ms", "00:00:00.0015"},
    {"-1.5 us", "-00:00:00.000002"},
    {"1.4999 us", "00:00:00.000001"},
    {"2.5 us", "00:00:00.000002"},
    {"-2.5 ms", "-00:00:00.0025"},
    {"59.9999999 seconds", "00:01:00"},
    {"1 2 days", "ERROR"},
    {"1 2 mins", "ERROR"},
    {"1 2 secs", "ERROR"},
    {"3 1 2 hours", "ERROR"},
    {"1 2 months", "ERROR"},
    {"1 2 years", "ERROR"},
    {"1 2 weeks", "ERROR"},
    {"1 2 ms", "ERROR"},
    {"1:00 2 days", "2 days 01:00:00"},
    {"1 2 hours 3", "1 day 02:00:03"},
    {"0.99 years", "11 mons"},
    {"-0.99 years", "-11 mons"},
    {"0.99 decades", "9 years 10 mons"},
    {"0.999 centuries", "99 years 10 mons"},
    {"0.9999 millennium", "999 years 10 mons"},
    {"-11.22971 century", "-1122 years -11 mons"},
    {"37 usec -11.22971 century 28seconds 94599.333261 hrs", "-1122 years -11 mons +94599:20:27.739637"},
    {"-0.05 years 3 mons", "2 mons"},
    {"3 mons -0.05 years", "3 mons"},
    {"0.05 years -3 mons", "-2 mons"},
    {"1.5 years 3 mons", "1 year 9 mons"},
    {"-1.5 decades 7 mons", "-14 years -5 mons"},
    {"2.71828 millennia -1 mon", "2718 years 2 mons"},
};

/* ---- the arithmetic: PostgreSQL 14's answers (SELECT expr), its timestamps' fractions written to six places as
 * imagedb writes them, t and f as true and false ---- */
static const struct {
    const char *expr, *out;
} kArith[] = {
    {"TIMESTAMP '2024-01-31' + INTERVAL '1 mon'", "2024-02-29 00:00:00"},
    {"TIMESTAMP '2023-01-31' + INTERVAL '1 mon'", "2023-02-28 00:00:00"},
    {"TIMESTAMP '2024-02-29' + INTERVAL '1 year'", "2025-02-28 00:00:00"},
    {"TIMESTAMP '2024-03-31' - INTERVAL '1 mon'", "2024-02-29 00:00:00"},
    {"TIMESTAMP '2024-01-31 10:00:00' + INTERVAL '1 mon 1 day 2 hours'", "2024-03-01 12:00:00"},
    {"TIMESTAMP '2024-01-30' + INTERVAL '1 mon 1 day'", "2024-03-01 00:00:00"},
    {"TIMESTAMP '2000-03-31' + INTERVAL '-1 mon 1 day'", "2000-03-01 00:00:00"},
    {"TIMESTAMP '2024-12-31' + INTERVAL '2 mons'", "2025-02-28 00:00:00"},
    {"TIMESTAMP '2024-10-31' + INTERVAL '-8 mons'", "2024-02-29 00:00:00"},
    {"TIMESTAMP '2024-05-31' + INTERVAL '1 mon -1 day'", "2024-06-29 00:00:00"},
    {"TIMESTAMP '2023-12-31 23:59:59' + INTERVAL '1 sec'", "2024-01-01 00:00:00"},
    {"TIMESTAMP '2024-02-28' + INTERVAL '1 day'", "2024-02-29 00:00:00"},
    {"TIMESTAMP '2000-02-29' + INTERVAL '100 years'", "2100-02-28 00:00:00"},
    {"TIMESTAMP '2000-02-29' + INTERVAL '400 years'", "2400-02-29 00:00:00"},
    {"TIMESTAMP '1900-02-28' + INTERVAL '1 day'", "1900-03-01 00:00:00"},
    {"TIMESTAMP '0001-01-01' + INTERVAL '1 day'", "0001-01-02 00:00:00"},
    {"TIMESTAMP '9999-12-30' + INTERVAL '1 day'", "9999-12-31 00:00:00"},
    {"TIMESTAMP '2024-06-15 12:00:00' + INTERVAL '-1 mon -30 days'", "2024-04-15 12:00:00"},
    {"TIMESTAMP '2024-06-15 12:00:00' - INTERVAL '1 year 2 mons 3 days 04:05:06'", "2023-04-12 07:54:54"},
    {"TIMESTAMP '2024-01-15' + INTERVAL '1.5 mons'", "2024-03-01 00:00:00"},
    {"TIMESTAMP '2024-03-10 01:30:00' + INTERVAL '720:00:00'", "2024-04-09 01:30:00"},
    {"TIMESTAMP '2024-01-31' + INTERVAL '1 mon' + INTERVAL '1 mon'", "2024-03-29 00:00:00"},
    {"TIMESTAMP '2024-01-31' + (INTERVAL '1 mon' + INTERVAL '1 mon')", "2024-03-31 00:00:00"},
    {"TIMESTAMP '9999-12-15' + INTERVAL '1 mon -30 days'", "9999-12-16 00:00:00"},
    {"TIMESTAMP '2024-01-01' + INTERVAL '-1 us'", "2023-12-31 23:59:59.999999"},
    {"TIMESTAMP '2024-08-31' - INTERVAL '6 mons'", "2024-02-29 00:00:00"},
    {"TIMESTAMP '2023-03-29' - INTERVAL '1 mon'", "2023-02-28 00:00:00"},
    {"TIMESTAMP '2024-02-29 23:00:00' + INTERVAL '1 hour'", "2024-03-01 00:00:00"},
    {"DATE '2024-01-31' + INTERVAL '1 mon'", "2024-02-29 00:00:00"},
    {"DATE '2024-01-31' - INTERVAL '1 mon 1 us'", "2023-12-30 23:59:59.999999"},
    {"INTERVAL '1 day' + DATE '2024-02-28'", "2024-02-29 00:00:00"},
    {"INTERVAL '1 day' + TIMESTAMP '2024-02-28 12:00:00'", "2024-02-29 12:00:00"},
    {"DATE '2024-03-01' - INTERVAL '1 day'", "2024-02-29 00:00:00"},
    {"TIMESTAMP '2024-01-01' - TIMESTAMP '2023-11-01 03:00:00'", "60 days 21:00:00"},
    {"TIMESTAMP '2023-11-01 03:00:00' - TIMESTAMP '2024-01-01'", "-60 days -21:00:00"},
    {"TIMESTAMP '2024-03-01' - TIMESTAMP '2024-02-28'", "2 days"},
    {"TIMESTAMP '2024-01-01 00:00:00.5' - TIMESTAMP '2024-01-01'", "00:00:00.5"},
    {"TIMESTAMP '9999-12-31 23:59:59.999999' - TIMESTAMP '0001-01-01'", "3652058 days 23:59:59.999999"},
    {"TIMESTAMP '0001-01-01' - TIMESTAMP '9999-12-31 23:59:59.999999'", "-3652058 days -23:59:59.999999"},
    {"TIMESTAMP '2024-01-02 01:00:00' - TIMESTAMP '2024-01-01 02:00:00'", "23:00:00"},
    {"TIMESTAMP '2024-01-01 02:00:00' - TIMESTAMP '2024-01-02 01:00:00'", "-23:00:00"},
    {"TIMESTAMP '2024-01-01' - TIMESTAMP '2024-01-01'", "00:00:00"},
    {"INTERVAL '1 mon' - INTERVAL '1 day'", "1 mon -1 days"},
    {"INTERVAL '1 mon 2 days 03:00' + INTERVAL '-1 mon -2 days -03:00'", "00:00:00"},
    {"INTERVAL '1 year' + INTERVAL '-13 mons'", "-1 mons"},
    {"INTERVAL '23:59:59' + INTERVAL '00:00:01'", "24:00:00"},
    {"INTERVAL '1 day -1 sec' + INTERVAL '1 sec'", "1 day"},
    {"INTERVAL '2147483647 days' + INTERVAL '1 day'", "ERROR"},
    {"INTERVAL '-2147483648 mons' - INTERVAL '1 mon'", "ERROR"},
    {"INTERVAL '2147483646 days' + INTERVAL '1 day'", "2147483647 days"},
    {"-INTERVAL '1 mon 2 days 03:00'", "-1 mons -2 days -03:00:00"},
    {"-INTERVAL '-2147483648 days'", "ERROR"},
    {"-INTERVAL '-2147483647 days'", "2147483647 days"},
    {"-(INTERVAL '-1 mon' - INTERVAL '1 mon')", "2 mons"},
    {"INTERVAL '1 mon' = INTERVAL '30 days'", "true"},
    {"INTERVAL '1 mon' = INTERVAL '720:00:00'", "true"},
    {"INTERVAL '1 year' = INTERVAL '360 days'", "true"},
    {"INTERVAL '1 year' > INTERVAL '365 days'", "false"},
    {"INTERVAL '1 day' = INTERVAL '24:00:00'", "true"},
    {"INTERVAL '1 mon -1 day' < INTERVAL '29 days 1 sec'", "true"},
    {"INTERVAL '-1 mon' < INTERVAL '-29 days'", "true"},
    {"INTERVAL '1 mon' <> INTERVAL '30 days 1 us'", "true"},
    {"INTERVAL '1 mon' >= INTERVAL '30 days'", "true"},
    {"INTERVAL '1 mon' BETWEEN INTERVAL '30 days' AND INTERVAL '720:00:00'", "true"},
    {"INTERVAL '30 days' IN (INTERVAL '1 mon', INTERVAL '1 day')", "true"},
    {"INTERVAL '1 day' IN (INTERVAL '1 mon', INTERVAL '23:59:59')", "false"},
    {"CAST('1 year 2 mons' AS INTERVAL)", "1 year 2 mons"},
    {"CAST(INTERVAL '-1 mon 1 day -1 hour' AS TEXT)", "\"-1 mons +1 day -01:00:00\""}, /* CSV quotes a TEXT */
    {"CAST(CAST(INTERVAL '1 mon' AS TEXT) AS INTERVAL) = INTERVAL '1 mon'", "true"},
    {"COALESCE(NULL, INTERVAL '3 days')", "3 days"},
    {"CASE WHEN INTERVAL '1 mon' = INTERVAL '30 days' THEN INTERVAL '1 year' ELSE INTERVAL '2 years' END", "1 year"},
};

static uint64_t g_rs;
static uint64_t rnd(void)
{
    g_rs ^= g_rs << 13;
    g_rs ^= g_rs >> 7;
    g_rs ^= g_rs << 17;
    return g_rs;
}

/* the codec: PostgreSQL's texts both ways, every triple's text read back, the check, the row's 16 bytes, the hash of
 * the triple and the order of the span */
static void t_iv_codec(void)
{
    imdb_err e = {0};
    for (size_t i = 0; i < sizeof kPg14 / sizeof *kPg14; i++) {
        int32_t mon = 7, day = 7;
        int64_t us = 7;
        int rc = imdb_parse_interval(kPg14[i].in, strlen(kPg14[i].in), &mon, &day, &us, &e);
        char got[200];
        if (rc) snprintf(got, sizeof got, "ERROR");
        else snprintf(got, sizeof got, "%s", ivt(mon, day, us));
        if (strcmp(got, kPg14[i].out)) {
            char m[600];
            snprintf(m, sizeof m, "'%s': PostgreSQL 14 '%s', imagedb '%s'", kPg14[i].in, kPg14[i].out, got);
            test_fail(__FILE__, __LINE__, m);
        }
    }
    /* every triple's text reads back as that triple: the ends of each field and drawn ones (the dump's and COPY's
     * round trip; the hours of the time past int32, which PostgreSQL 14 itself cannot read back) */
    static const int32_t f32[] = {0, 1, -1, 11, 12, 13, -11, -12, -13, INT32_MAX, INT32_MIN, 2147483646, -2147483647};
    static const int64_t f64[] = {0, 1, -1, 999999, 1000000, -1000000, 86399999999LL, 86400000000LL, INT64_MAX, INT64_MIN,
                                  INT64_MIN + 1, 3600000000LL, -3600000001LL};
    g_rs = 0x2545f4914f6cdd1dull;
    int bad = 0;
    for (int it = 0; it < 300000 && bad < 5; it++) {
        int32_t mon, day;
        int64_t us;
        if (it % 3 == 0) mon = f32[rnd() % 13], day = f32[rnd() % 13], us = f64[rnd() % 13];
        else if (it % 3 == 1) mon = (int32_t)rnd(), day = (int32_t)rnd(), us = (int64_t)rnd();
        else mon = (int32_t)(rnd() % 400) - 200, day = (int32_t)(rnd() % 400) - 200, us = (int64_t)(rnd() % 200000000000ull) - 100000000000LL;
        const char *t = ivt(mon, day, us);
        int32_t m2 = 0, d2 = 0;
        int64_t u2 = 0;
        if (imdb_parse_interval(t, strlen(t), &m2, &d2, &u2, &e) || m2 != mon || d2 != day || u2 != us) {
            bad++;
            char m[300];
            snprintf(m, sizeof m, "(%d, %d, %lld) as '%s' reads back otherwise", mon, day, (long long)us, t);
            test_fail(__FILE__, __LINE__, m);
        }
    }
    /* the check: every triple a value, nothing else in an INTERVAL column */
    imdb_column c;
    memset(&c, 0, sizeof c);
    strcpy(c.name, "c");
    c.type = IMDB_T_INTERVAL;
    imdb_value v;
    memset(&v, 0, sizeof v);
    v.type = IMDB_T_INTERVAL;
    imdb_iv_set(&v, INT32_MIN, INT32_MAX, INT64_MIN);
    CHECK(imdb_value_check(&c, &v, &e) == IMDB_OK);
    v.wide = true;
    CHECK(imdb_value_check(&c, &v, &e) != IMDB_OK);
    CHECK(sizeof(imdb_value) == 24);
    /* the row codec: 16 bytes (months, days, microseconds); a cut one refused */
    imdb_schema s;
    memset(&s, 0, sizeof s);
    snprintf(s.name, sizeof s.name, "r");
    s.ncols = 2;
    s.subject = -1;
    snprintf(s.cols[0].name, sizeof s.cols[0].name, "id");
    s.cols[0].type = IMDB_T_INT64;
    s.cols[0].flags = IMDB_COL_PK;
    snprintf(s.cols[1].name, sizeof s.cols[1].name, "iv");
    s.cols[1].type = IMDB_T_INTERVAL;
    s.cols[1].flags = IMDB_COL_NULLABLE;
    s.npk = 1;
    s.key[0] = 0;
    OK(imdb_schema_check(&s, &e));
    imdb_value r[2], d[2];
    memset(r, 0, sizeof r);
    r[0].type = IMDB_T_INT64;
    r[0].i = 5;
    r[1].type = IMDB_T_INTERVAL;
    imdb_iv_set(&r[1], -14, 3, -1);
    imdb_buf row;
    imdb_buf_init(&row);
    OK(imdb_row_encode(&s, r, &row, &e));
    CHECK(row.len == 1 + 8 + 16);
    OK(imdb_row_decode(&s, row.p, row.len, d, &e));
    CHECK(d[1].type == IMDB_T_INTERVAL && d[1].iv.mon == -14 && d[1].iv.day == 3 && d[1].i == -1);
    CHECK(imdb_row_decode(&s, row.p, row.len - 1, d, &e) == IMDB_ERR_CORRUPT);
    imdb_buf_free(&row);
    /* a PRIMARY KEY of an INTERVAL is refused by the schema check (deferred.md D26) */
    s.cols[1].flags = IMDB_COL_PK;
    s.npk = 2;
    s.key[1] = 1;
    CHECK(imdb_schema_check(&s, &e) == IMDB_ERR_UNSUPPORTED);
    /* SQL's order is the span: '1 mon' = '30 days' = '720:00:00'; the hash is the triple's (the maps' identity) */
    imdb_value a = {.type = IMDB_T_INTERVAL}, b2 = {.type = IMDB_T_INTERVAL}, h = {.type = IMDB_T_INTERVAL};
    imdb_iv_set(&a, 1, 0, 0);
    imdb_iv_set(&b2, 0, 30, 0);
    imdb_iv_set(&h, 0, 0, 720LL * 3600000000LL);
    CHECK(imdb_value_cmp(&a, &b2) == 0 && imdb_value_cmp(&b2, &h) == 0);
    CHECK(imdb_value_hash(&a, 1) != imdb_value_hash(&b2, 1) && imdb_value_hash(&b2, 1) != imdb_value_hash(&h, 1));
    imdb_value a2 = a;
    CHECK(imdb_value_hash(&a, 1) == imdb_value_hash(&a2, 1));
    imdb_iv_set(&b2, 0, 30, 1);
    CHECK(imdb_value_cmp(&a, &b2) < 0 && imdb_value_cmp(&b2, &a) > 0);
}

/* the arithmetic against PostgreSQL 14's answers; the rules; every refusal */
static void t_iv_sql(void)
{
    const char *dir = test_tmpdir();
    imdb_err e = {0};
    CHECK(imdb_init(dir, false, NULL, &e) == 0);
    imdb_db *db = open_with(dir, false, 0);
    CHECK(db);
    if (!db) return;
    char sql[512], want[512];
    for (size_t i = 0; i < sizeof kArith / sizeof *kArith; i++) {
        snprintf(sql, sizeof sql, "SELECT %s AS r", kArith[i].expr);
        if (!strcmp(kArith[i].out, "ERROR")) snprintf(want, sizeof want, "ERR ");
        else snprintf(want, sizeof want, "r\n%s\n", kArith[i].out);
        if (!strcmp(kArith[i].out, "ERROR")) {
            const char *got = csv(sql);
            if (strncmp(got, "ERR ", 4)) {
                char m[900];
                snprintf(m, sizeof m, "%s: PostgreSQL 14 refuses it, imagedb gave %.300s", sql, got);
                test_fail(__FILE__, __LINE__, m);
            }
        } else {
            EXPECT(sql, want);
        }
    }
    EXPECT("SELECT NULLIF(INTERVAL '1 mon', INTERVAL '30 days') AS r", "r\n\n");
    /* where imagedb's TIMESTAMP ends (years 1 to 9999) and PostgreSQL's does not: an error, never a wrapped date */
    EXPECT("SELECT TIMESTAMP '9999-12-31' + INTERVAL '1 day'", "ERR a timestamp before 0001-01-01 or past 9999-12-31");
    EXPECT("SELECT TIMESTAMP '0001-01-01' - INTERVAL '1 us'", "ERR a timestamp before 0001-01-01 or past 9999-12-31");
    EXPECT("SELECT TIMESTAMP '2000-01-01' + INTERVAL '2147483647 days'", "ERR a timestamp before 0001-01-01");
    EXPECT("SELECT TIMESTAMP '2000-01-01' - INTERVAL '-2147483648 mons'", "ERR a timestamp before 0001-01-01");
    EXPECT("SELECT TIMESTAMP '2000-01-01' + INTERVAL '9223372036854775807 us'", "ERR interval: a field out of range");
    /* a step past PostgreSQL's own bounds (its months, then its days) is its error, even where the end comes back */
    EXPECT("SELECT TIMESTAMP '2000-01-01' + INTERVAL '300000 years -109500000 days'", "ERR a timestamp before 0001-01-01");
    EXPECT("SELECT TIMESTAMP '9999-12-15' + INTERVAL '1 mon -30 days' AS r", "r\n9999-12-16 00:00:00\n");
    /* the stored value and the comparison: two relations (design 8.1) */
    OK(run("CREATE TABLE q (id INT64 PRIMARY KEY, iv INTERVAL, ts TIMESTAMP)"));
    OK(run("INSERT INTO q VALUES (1, INTERVAL '1 mon', TIMESTAMP '2024-01-31'), (2, '30 days', TIMESTAMP '2024-01-31'), "
           "(3, '720:00:00', TIMESTAMP '2024-01-31'), (4, NULL, TIMESTAMP '2024-01-31'), (5, '-1 day 2 hours', NULL)"));
    EXPECT("SELECT id, ts + iv AS e FROM q ORDER BY id",
           "id,e\n1,2024-02-29 00:00:00\n2,2024-03-01 00:00:00\n3,2024-03-01 00:00:00\n4,\n5,\n");
    EXPECT("SELECT COUNT(*) AS c FROM q WHERE iv = INTERVAL '1 mon'", "c\n3\n");
    EXPECT("SELECT COUNT(*) AS c FROM q WHERE iv = '30 days' AND iv >= '720:00:00' AND iv <= '1 mon'", "c\n3\n");
    EXPECT("SELECT COUNT(*) AS c FROM q WHERE iv IN ('720:00:00', '1 day')", "c\n3\n");
    /* ORDER BY: the span, ties by the next key (PostgreSQL 14's interval_cmp), then the default order */
    EXPECT("SELECT id FROM q ORDER BY iv, id DESC", "id\n5\n3\n2\n1\n4\n");
    EXPECT("SELECT id FROM q ORDER BY iv DESC, id", "id\n4\n1\n2\n3\n5\n");
    /* MIN and MAX of equal spans: the least triple (720:00:00), whatever the rows' order; SUM field by field */
    EXPECT("SELECT MIN(iv) AS lo, MAX(iv) AS hi FROM q WHERE id <= 3", "lo,hi\n720:00:00,720:00:00\n");
    EXPECT("SELECT MIN(iv) AS lo, MAX(iv) AS hi, SUM(iv) AS s, COUNT(iv) AS k FROM q",
           "lo,hi,s,k\n-1 days +02:00:00,720:00:00,1 mon 29 days 722:00:00,4\n");
    EXPECT("SELECT SUM(iv + INTERVAL '1 day') AS s, MIN(-iv) AS lo, MAX(-iv) AS hi FROM q",
           "s,lo,hi\n1 mon 33 days 722:00:00,-1 mons,1 day -02:00:00\n"); /* the least triple: (-1, 0, 0) */
    EXPECT("SELECT id, MIN(iv) OVER (ORDER BY id ROWS BETWEEN 1 PRECEDING AND 1 FOLLOWING) AS m, "
           "SUM(iv) OVER (ORDER BY id ROWS BETWEEN 1 PRECEDING AND CURRENT ROW) AS s FROM q ORDER BY id",
           "id,m,s\n1,30 days,1 mon\n2,720:00:00,1 mon 30 days\n3,720:00:00,30 days 720:00:00\n4,-1 days +02:00:00,"
           "720:00:00\n5,-1 days +02:00:00,-1 days +02:00:00\n");
    /* SUM's total alone is held to each field: a partial sum past a field and back is no error (no order decides) */
    OK(run("CREATE TABLE big (id INT64 PRIMARY KEY, iv INTERVAL)"));
    OK(run("INSERT INTO big VALUES (1, '2147483647 days'), (2, '1 day'), (3, '-2 days')"));
    EXPECT("SELECT SUM(iv) AS s FROM big", "s\n2147483646 days\n");
    OK(run("INSERT INTO big VALUES (4, '2 days')"));
    EXPECT("SELECT SUM(iv) AS s FROM big", "ERR an INTERVAL SUM out of range");
    /* a join by the span: a condition on each pair (never a key: the key maps compare the triple) */
    OK(run("CREATE TABLE r (id INT64 PRIMARY KEY, iv INTERVAL)"));
    OK(run("INSERT INTO r VALUES (1, '30 days'), (2, '1 day'), (3, NULL)"));
    EXPECT("SELECT q.id AS a, r.id AS b FROM q JOIN r ON q.iv = r.iv ORDER BY a, b", "a,b\n1,1\n2,1\n3,1\n");
    EXPECT("SELECT q.id AS a, r.id AS b FROM q, r WHERE q.iv = r.iv AND r.id < 3 ORDER BY a, b", "a,b\n1,1\n2,1\n3,1\n");
    EXPECT("SELECT q.id AS a, r.id AS b FROM q LEFT JOIN r ON q.iv = r.iv ORDER BY a, b",
           "a,b\n1,1\n2,1\n3,1\n4,\n5,\n");
    EXPECT("SELECT COUNT(*) AS c FROM q WHERE iv IN (SELECT iv FROM r)", "c\n3\n");
    EXPECT("SELECT COUNT(*) AS c FROM q WHERE EXISTS (SELECT 1 FROM r WHERE r.iv = q.iv)", "c\n3\n");
    /* a correlated subquery's memo keys the triple: '1 mon' and '30 days' take two runs, two answers */
    EXPECT("SELECT id, (SELECT COUNT(*) FROM r WHERE r.id = 1 AND TIMESTAMP '2024-02-29 12:00:00' < TIMESTAMP '2024-01-31' + "
           "q.iv) AS n FROM q WHERE id <= 3 ORDER BY id",
           "id,n\n1,0\n2,1\n3,1\n");
    /* UNION ALL keeps every row; a view and a derived table carry the type */
    EXPECT("SELECT COUNT(*) AS c, MIN(iv) AS m FROM (SELECT iv FROM q UNION ALL SELECT iv FROM r) d", "c,m\n8,-1 days +02:00:00\n");
    OK(run("CREATE VIEW qv AS SELECT id, iv + INTERVAL '1 mon' AS x, ts - TIMESTAMP '2024-01-01' AS y FROM q"));
    EXPECT("SELECT x, y FROM qv WHERE id = 2", "x,y\n1 mon 30 days,30 days\n");
    /* ORDER BY over built cells (the advisor, 14:3x): a grouped statement by its INTERVAL aggregate, by position and by the
     * tree (reorder_rows' cell_x), UNION ALL's tail, a window statement's tail; per-group SUM, MIN and MAX, alone and over a
     * join. gq's microseconds are 0 in three of its rows whose months and days differ: a key cut to the microseconds sorts
     * them as one */
    OK(run("CREATE TABLE gq (id INT64 PRIMARY KEY, iv INTERVAL, n INT64)"));
    OK(run("INSERT INTO gq VALUES (1, '1 mon', 1), (2, '30 days', 2), (3, '720:00:00', 3), (4, NULL, 4), "
           "(5, '2 mons -30 days', 5), (6, '1 day', 6)"));
    EXPECT("SELECT n % 3 AS g, SUM(iv) AS s FROM gq GROUP BY n % 3 ORDER BY 2", "g,s\n1,1 mon\n0,1 day 720:00:00\n2,2 mons\n");
    EXPECT("SELECT n % 3 AS g, SUM(iv) AS s FROM gq GROUP BY n % 3 ORDER BY SUM(iv) DESC",
           "g,s\n2,2 mons\n0,1 day 720:00:00\n1,1 mon\n");
    EXPECT("SELECT n % 3 AS g, MIN(iv) AS lo, MAX(iv) AS hi, COUNT(iv) AS k FROM gq GROUP BY n % 3 ORDER BY g",
           "g,lo,hi,k\n0,1 day,720:00:00,2\n1,1 mon,1 mon,1\n2,30 days,30 days,2\n"); /* g 2: two triples of one span */
    EXPECT("SELECT gq.n % 2 AS g, SUM(gq.iv) AS s, MIN(r.iv) AS m FROM gq JOIN r ON gq.id = r.id GROUP BY gq.n % 2 ORDER BY g",
           "g,s,m\n0,30 days,1 day\n1,1 mon 720:00:00,30 days\n");
    EXPECT("SELECT iv FROM gq WHERE id IN (3, 6) UNION ALL SELECT iv FROM r WHERE id = 2 ORDER BY 1",
           "iv\n1 day\n1 day\n720:00:00\n");
    EXPECT("SELECT id, iv, ROW_NUMBER() OVER (ORDER BY id) AS k FROM gq WHERE id IN (1, 3, 6) ORDER BY iv, id",
           "id,iv,k\n6,1 day,3\n1,1 mon,1\n3,720:00:00,2\n");
    EXPECT("SELECT n % 3 AS g, SUM(iv) AS s FROM gq GROUP BY n % 3 HAVING SUM(iv) > INTERVAL '30 days' ORDER BY g",
           "g,s\n0,1 day 720:00:00\n2,2 mons\n");
    /* PREPARE and EXECUTE: a declared INTERVAL (a bare string read as one, a typed literal), an undeclared one (the
     * literal's own type; a bare string a TEXT, refused in arithmetic as written out), a write's; the API's values */
    OK(run("PREPARE pi (INTERVAL) AS SELECT ts + $1 AS e FROM q WHERE id = 1"));
    EXPECT("EXECUTE pi ('1 mon')", "e\n2024-02-29 00:00:00\n");
    EXPECT("EXECUTE pi (INTERVAL '30 days')", "e\n2024-03-01 00:00:00\n");
    OK(run("PREPARE pu AS SELECT ts + $1 AS e FROM q WHERE id = 1"));
    EXPECT("EXECUTE pu (INTERVAL '1 mon')", "e\n2024-02-29 00:00:00\n");
    EXPECT("EXECUTE pu ('1 mon')", "ERR arithmetic");
    OK(run("PREPARE pw (INTERVAL, INT64) AS UPDATE q SET iv = $1 WHERE id = $2"));
    EXPECT("EXECUTE pw ('1 day', 5)", "UPDATE 1");
    EXPECT("SELECT iv FROM q WHERE id = 5", "iv\n1 day\n");
    EXPECT("EXECUTE pw ('-1 day 2 hours', 5)", "UPDATE 1");
    {
        imdb_value pv[1];
        memset(pv, 0, sizeof pv);
        pv[0].type = IMDB_T_INTERVAL;
        imdb_iv_set(&pv[0], 1, 0, 0);
        static const char ps[] = "SELECT ts + $1 AS e FROM q WHERE id = 2";
        imdb_result pr;
        imdb_err_clear(&g_e);
        CHECK(imdb_exec_one(&g_s, ps, sizeof ps - 1, pv, 1, &pr, &g_e) == IMDB_OK);
        if (!g_e.code) {
            imdb_buf b;
            imdb_buf_init(&b);
            imdb_result_render(&pr, true, &b);
            CHECK(b.len == strlen("e\n2024-02-29 00:00:00\n") && !memcmp(b.p, "e\n2024-02-29 00:00:00\n", b.len));
            imdb_buf_free(&b);
            imdb_result_free(&pr);
        }
    }
    /* the refusals: each by name */
    static const struct {
        const char *sql, *err;
    } kRefused[] = {
        {"SELECT iv, COUNT(*) FROM q GROUP BY iv", "GROUP BY over an INTERVAL"},
        {"SELECT iv + INTERVAL '1 day', COUNT(*) FROM q GROUP BY iv + INTERVAL '1 day'", "GROUP BY over an INTERVAL"},
        {"SELECT q.iv, COUNT(*) FROM q JOIN r ON q.id = r.id GROUP BY q.iv", "GROUP BY over an INTERVAL"},
        {"SELECT DISTINCT iv FROM q", "SELECT DISTINCT over an INTERVAL"},
        {"SELECT DISTINCT id, iv FROM q ORDER BY id", "SELECT DISTINCT over an INTERVAL"},
        {"SELECT COUNT(DISTINCT iv) FROM q", "an aggregate's DISTINCT over an INTERVAL"},
        {"SELECT iv FROM q UNION SELECT iv FROM r", "a set operation other than UNION ALL"},
        {"SELECT iv FROM q INTERSECT SELECT iv FROM r", "a set operation other than UNION ALL"},
        {"SELECT iv FROM q EXCEPT ALL SELECT iv FROM r", "a set operation other than UNION ALL"},
        {"WITH RECURSIVE w (n, iv) AS (SELECT 1, INTERVAL '1 day' UNION SELECT n + 1, iv FROM w WHERE n < 3) SELECT n FROM w",
         "WITH RECURSIVE's UNION over an INTERVAL"},
        {"SELECT q.id FROM q JOIN r USING (iv)", "USING over an INTERVAL"},
        {"SELECT id, ROW_NUMBER() OVER (PARTITION BY iv ORDER BY id) FROM q", "a window's PARTITION BY or ORDER BY"},
        {"SELECT id, RANK() OVER (ORDER BY iv) FROM q", "a window's PARTITION BY or ORDER BY"},
        {"SELECT DISTINCT id, SUM(iv) OVER (ORDER BY id) FROM q", "SELECT DISTINCT over an INTERVAL"},
        {"CREATE TABLE x1 (iv INTERVAL PRIMARY KEY)", "a PRIMARY KEY column cannot be an INTERVAL"},
        {"CREATE TABLE x2 (id INT64 PRIMARY KEY, iv INTERVAL SUBJECT)", "SUBJECT"},
        {"CREATE INDEX qi ON q (iv)", "an index on iv, an INTERVAL: not yet"},
        {"CREATE TABLE x3 (id INT64 PRIMARY KEY, iv INTERVAL CHECK (iv IS NOT NULL))", "a CHECK reads no INTERVAL value"},
        {"CREATE TABLE x4 (id INT64 PRIMARY KEY, a TIMESTAMP, b TIMESTAMP, CHECK (b - a > '0 days'))", "a CHECK reads no INTERVAL"},
        {"CREATE TABLE x5 (id INT64 PRIMARY KEY, ts TIMESTAMP, e TIMESTAMP GENERATED ALWAYS AS (ts + INTERVAL '1 day') STORED)",
         "a generation expression"},
        {"CREATE TABLE x6 (id INT64 PRIMARY KEY, iv INTERVAL YEAR TO MONTH)", "INTERVAL's fields and precision"},
        {"CREATE TABLE x7 (id INT64 PRIMARY KEY, iv INTERVAL(3))", "INTERVAL's fields and precision"},
        {"SELECT CAST('1 day' AS INTERVAL(2))", "INTERVAL's fields and precision"},
        {"SELECT INTERVAL '1' DAY", "with a field after it"},
        {"SELECT ts + '1 day' FROM q", "arithmetic"},
        {"SELECT iv * 2 FROM q", "interval arithmetic"},
        {"SELECT iv / 2 FROM q", "interval arithmetic"},
        {"SELECT 2 * iv FROM q", "interval arithmetic"},
        {"SELECT AVG(iv) FROM q", "AVG needs"},
        {"SELECT TIMESTAMPTZ '2024-01-01 00:00:00+00' + INTERVAL '1 day'", "interval arithmetic"},
        {"SELECT TIME '10:00:00' + INTERVAL '1 hour'", "interval arithmetic"},
        {"SELECT DATE '2024-01-01' - DATE '2023-01-01' + INTERVAL '1 day'", "interval arithmetic"},
        {"SELECT INTERVAL '1 day' - TIMESTAMP '2024-01-01'", "interval arithmetic"},
        {"SELECT CAST(TIME '10:00:00' AS INTERVAL)", "CAST of TIME to INTERVAL is not defined"},
        {"SELECT CAST(INTERVAL '1 day' AS INT64)", "CAST of INTERVAL to INT64 is not defined"},
        {"SELECT INTERVAL 'infinity'", "invalid input syntax"},
        {"SELECT INTERVAL '1-2'", "invalid input syntax"},
        {"SELECT INTERVAL 'P1D'", "invalid input syntax"},
        {"SELECT iv = 1 FROM q", "a comparison of INTERVAL with INT64"},
        {"INSERT INTO q VALUES (9, 5, NULL)", "expects INTERVAL"},
        {"INSERT INTO q VALUES (9, '1 fortnight', NULL)", "invalid input syntax"},
        /* the bind-only pass (a view's probe, the replay's re-bind) and EXPLAIN refuse each as the run does */
        {"CREATE VIEW x8 AS SELECT DISTINCT iv FROM q", "SELECT DISTINCT over an INTERVAL"},
        {"CREATE VIEW x9 AS SELECT DISTINCT id, iv + INTERVAL '1 day' AS e FROM q", "SELECT DISTINCT over an INTERVAL"},
        {"CREATE VIEW x10 AS SELECT id, ROW_NUMBER() OVER (PARTITION BY iv ORDER BY id) AS k FROM q", "a window's PARTITION BY"},
        {"CREATE VIEW x11 AS SELECT id, RANK() OVER (ORDER BY iv) AS k FROM q", "a window's PARTITION BY"},
        {"CREATE VIEW x12 AS SELECT DISTINCT iv, ROW_NUMBER() OVER (ORDER BY id) AS k FROM q", "SELECT DISTINCT over an INTERVAL"},
        {"CREATE VIEW x13 AS SELECT iv FROM q UNION SELECT iv FROM r", "a set operation other than UNION ALL"},
        {"CREATE VIEW x14 AS SELECT iv, COUNT(*) AS c FROM q GROUP BY iv", "GROUP BY over an INTERVAL"},
        {"EXPLAIN SELECT DISTINCT iv FROM q", "SELECT DISTINCT over an INTERVAL"},
        {"EXPLAIN SELECT id, RANK() OVER (ORDER BY iv) FROM q", "a window's PARTITION BY"},
        {"EXPLAIN SELECT DISTINCT iv, ROW_NUMBER() OVER (ORDER BY id) FROM q", "SELECT DISTINCT over an INTERVAL"},
        {"EXPLAIN SELECT iv FROM q INTERSECT SELECT iv FROM r", "a set operation other than UNION ALL"},
        {"EXPLAIN WITH RECURSIVE w (n, iv) AS (SELECT 1, INTERVAL '1 day' UNION SELECT n + 1, iv FROM w WHERE n < 3) SELECT n FROM w",
         "WITH RECURSIVE's UNION over an INTERVAL"},
        {"EXPLAIN SELECT COUNT(DISTINCT iv) FROM q", "an aggregate's DISTINCT over an INTERVAL"},
        {"EXPLAIN SELECT iv, COUNT(*) FROM q GROUP BY iv", "GROUP BY over an INTERVAL"},
        /* a window statement over one: the outer copy's marks kept across the inner one's (exec_window restores them) */
        {"CREATE VIEW x15 AS SELECT id, ROW_NUMBER() OVER (PARTITION BY iv ORDER BY id) AS k FROM (SELECT id, iv, "
         "RANK() OVER (ORDER BY id) AS r FROM q) d", "a window's PARTITION BY"},
        {"EXPLAIN SELECT id, ROW_NUMBER() OVER (PARTITION BY iv ORDER BY id) FROM (SELECT id, iv, RANK() OVER (ORDER BY id) "
         "AS r FROM q) d", "a window's PARTITION BY"},
    };
    for (size_t i = 0; i < sizeof kRefused / sizeof *kRefused; i++) {
        char w[300];
        snprintf(w, sizeof w, "ERR %s", kRefused[i].err);
        EXPECT(kRefused[i].sql, w);
    }
    EXPECT("SELECT DISTINCT INTERVAL '1 day' AS x", "x\n1 day\n"); /* one row: nothing for DISTINCT to merge */
    EXPECT("SELECT COUNT(*) AS c FROM q", "c\n5\n"); /* nothing above wrote */
    CHECK(verify_db(db) == 0);
    done(db);
    CHECK(audit_dir(dir) == 0);
}

/* ---- a table of INTERVALs against a model of its own ---- */

/* the model's calendar, by counting (not the engine's arithmetic): days since 1970-01-01 */
static bool m_leap(int64_t y) { return (y % 4 == 0 && y % 100 != 0) || y % 400 == 0; }
static int m_dim(int64_t y, int m)
{
    static const int d[12] = {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
    return m == 2 && m_leap(y) ? 29 : d[m - 1];
}
static int64_t m_days(int64_t y, int m, int d)
{
    int64_t n = 0;
    for (int64_t k = 1970; k < y; k++) n += m_leap(k) ? 366 : 365;
    for (int64_t k = y; k < 1970; k++) n -= m_leap(k) ? 366 : 365;
    for (int k = 1; k < m; k++) n += m_dim(y, k);
    return n + d - 1;
}
static void m_ymd(int64_t n, int64_t *y, int *m, int *d)
{
    int64_t yy = 1970;
    while (n < 0) n += m_leap(--yy) ? 366 : 365;
    while (n >= (m_leap(yy) ? 366 : 365)) n -= m_leap(yy++) ? 366 : 365;
    int mm = 1;
    while (n >= m_dim(yy, mm)) n -= m_dim(yy, mm++);
    *y = yy;
    *m = mm;
    *d = (int)n + 1;
}
#define DAYUS 86400000000LL
/* PostgreSQL's order: the months to the year and month, the day clamped; then the days; then the time */
static int64_t m_plus(int64_t ts, int32_t mon, int32_t day, int64_t us)
{
    int64_t days = ts / DAYUS - (ts % DAYUS < 0), tod = ts - days * DAYUS;
    if (mon) {
        int64_t y;
        int m, d;
        m_ymd(days, &y, &m, &d);
        int64_t t = y * 12 + (m - 1) + mon, y2 = t / 12 - (t % 12 < 0);
        int m2 = (int)(t - y2 * 12) + 1;
        days = m_days(y2, m2, d > m_dim(y2, m2) ? m_dim(y2, m2) : d);
    }
    return (days + day) * DAYUS + tod + us;
}

typedef struct miv {
    bool null;
    int32_t mon, day;
    int64_t us;
} miv;
static __int128 m_span(const miv *v) { return ((__int128)v->mon * 30 + v->day) * DAYUS + v->us; }
/* MIN's and MAX's order: the span, then (both) the least triple */
static int m_tri(const miv *a, const miv *b)
{
    if (a->mon != b->mon) return a->mon < b->mon ? -1 : 1;
    if (a->day != b->day) return a->day < b->day ? -1 : 1;
    return a->us < b->us ? -1 : a->us > b->us;
}
static bool m_better(const miv *v, const miv *cur, bool max)
{
    __int128 a = m_span(v), b = m_span(cur);
    if (a != b) return max ? a > b : a < b;
    return m_tri(v, cur) < 0;
}

#define IVN 240
#define IVU 24
typedef struct mrow {
    int64_t id, ts, n;
    miv iv;
} mrow;
static mrow g_t[IVN + 64];
static int g_nt;
static mrow g_u[IVU];

static miv m_draw(void)
{
    miv v = {0};
    switch (rnd() % 10) {
    case 0: v.mon = 1; break;
    case 1: v.day = 30; break;
    case 2: v.us = 720LL * 3600000000LL; break;
    case 3: v.null = true; break;
    case 4:
    case 5: /* months and days, no microseconds: a cut to the microseconds alone merges these */
        v.mon = (int32_t)(rnd() % 29) - 14;
        v.day = (int32_t)(rnd() % 81) - 40;
        break;
    default:
        v.mon = (int32_t)(rnd() % 7) - 3;
        v.day = (int32_t)(rnd() % 21) - 10;
        v.us = (int64_t)(rnd() % (6 * (uint64_t)DAYUS)) - 3 * DAYUS;
        break;
    }
    return v;
}

static void iv_lit(imdb_buf *b, const miv *v)
{
    if (v->null) {
        imdb_buf_put_str(b, "NULL");
        return;
    }
    imdb_buf_put_str(b, "INTERVAL '");
    imdb_format_interval(v->mon, v->day, v->us, b);
    imdb_buf_put_str(b, "'");
}

static void ts_text(imdb_buf *b, int64_t ts)
{
    imdb_value v = {.type = IMDB_T_TIMESTAMP, .i = ts};
    imdb_format_value(&v, b);
}

/* the model's answers to the queries, as their CSV */
typedef struct mans {
    char q1[64], q2[64], q3[400], q4[300], q5[64], q6[64], q7[64], q8[3000], q9[200], q10[200], q11[64];
} mans;

static void m_answers(mans *a)
{
    miv mon1 = {.mon = 1}, d30 = {.day = 30};
    int c1 = 0, c2 = 0, k = 0, c6 = 0, n5 = 0, n7 = 0;
    __int128 smon = 0, sday = 0, sus = 0, s5 = 0, s7 = 0;
    miv lo = {.null = true}, hi = {.null = true}, m10 = {.null = true};
    int64_t cut = m_days(2015, 6, 1) * DAYUS, base = m_days(2020, 1, 31) * DAYUS;
    for (int i = 0; i < g_nt; i++) {
        const mrow *r = &g_t[i];
        if (r->iv.null) continue;
        c1 += m_span(&r->iv) > m_span(&mon1);
        c2 += m_span(&r->iv) == m_span(&d30);
        k++;
        smon += r->iv.mon, sday += r->iv.day, sus += r->iv.us;
        if (lo.null || m_better(&r->iv, &lo, false)) lo = r->iv;
        if (hi.null || m_better(&r->iv, &hi, true)) hi = r->iv;
        if (m_plus(r->ts, r->iv.mon, r->iv.day, r->iv.us) > cut) s5 += r->n, n5++;
        for (int j = 0; j < IVU; j++) c6 += !g_u[j].iv.null && m_span(&g_u[j].iv) == m_span(&r->iv);
        int64_t x = m_plus(base, r->iv.mon, r->iv.day, r->iv.us);
        int below = 0;
        for (int j = 0; j < IVU; j++) below += g_u[j].ts < x;
        if (below > 3) s7 += r->n, n7++;
        if (r->id % 3 == 0) {
            miv w = r->iv;
            w.mon -= 1;
            if (m10.null || m_better(&w, &m10, true)) m10 = w;
        }
    }
    snprintf(a->q1, sizeof a->q1, "c\n%d\n", c1);
    snprintf(a->q2, sizeof a->q2, "c\n%d\n", c2);
    if (!k) snprintf(a->q3, sizeof a->q3, "s,lo,hi,k\n,,,0\n");
    else
        snprintf(a->q3, sizeof a->q3, "s,lo,hi,k\n%s,%s,%s,%d\n", ivt((int32_t)smon, (int32_t)sday, (int64_t)sus),
                 ivt(lo.mon, lo.day, lo.us), ivt(hi.mon, hi.day, hi.us), k);
    /* Q4: the first 12 by the span, ties by id */
    int ord[IVN + 64], no = 0;
    for (int i = 0; i < g_nt; i++)
        if (!g_t[i].iv.null) ord[no++] = i;
    for (int x = 1; x < no; x++) /* insertion sort: stable by id within a span (rows are in id order) */
        for (int y = x; y > 0; y--) {
            const mrow *p = &g_t[ord[y - 1]], *q = &g_t[ord[y]];
            __int128 sp = m_span(&p->iv), sq = m_span(&q->iv);
            if (sp < sq || (sp == sq && p->id < q->id)) break;
            int t = ord[y - 1];
            ord[y - 1] = ord[y];
            ord[y] = t;
        }
    int at = snprintf(a->q4, sizeof a->q4, "id\n");
    for (int x = 0; x < 12 && x < no; x++) at += snprintf(a->q4 + at, sizeof a->q4 - (size_t)at, "%lld\n", (long long)g_t[ord[x]].id);
    snprintf(a->q5, sizeof a->q5, n5 ? "s\n%lld\n" : "s\n\n", (long long)s5);
    snprintf(a->q6, sizeof a->q6, "c\n%d\n", c6);
    snprintf(a->q7, sizeof a->q7, n7 ? "s\n%lld\n" : "s\n\n", (long long)s7);
    /* Q8: a sliding SUM over ids below 30 (every id there, in order), NULL when its frame holds none */
    at = snprintf(a->q8, sizeof a->q8, "id,w\n");
    for (int i = 0; i < 30; i++) {
        __int128 fm = 0, fd = 0, fu = 0;
        bool any = false;
        for (int j = i - 2 < 0 ? 0 : i - 2; j <= i; j++)
            if (!g_t[j].iv.null) any = true, fm += g_t[j].iv.mon, fd += g_t[j].iv.day, fu += g_t[j].iv.us;
        at += snprintf(a->q8 + at, sizeof a->q8 - (size_t)at, "%d,%s\n", i, any ? ivt((int32_t)fm, (int32_t)fd, (int64_t)fu) : "");
    }
    snprintf(a->q9, sizeof a->q9, "s\n%s\n", k ? ivt((int32_t)smon, (int32_t)(sday + k), (int64_t)sus) : "");
    snprintf(a->q10, sizeof a->q10, "m\n%s\n", m10.null ? "" : ivt(m10.mon, m10.day, m10.us));
    snprintf(a->q11, sizeof a->q11, "k\n%d\n", k);
}

static const char *const kQ[11] = {
    "SELECT COUNT(*) AS c FROM t WHERE iv > INTERVAL '1 mon'",
    "SELECT COUNT(*) AS c FROM t WHERE iv = '30 days'",
    "SELECT SUM(iv) AS s, MIN(iv) AS lo, MAX(iv) AS hi, COUNT(iv) AS k FROM t",
    "SELECT id FROM t WHERE iv IS NOT NULL ORDER BY iv, id LIMIT 12",
    "SELECT SUM(n) AS s FROM t WHERE ts + iv > TIMESTAMP '2015-06-01 00:00:00'",
    "SELECT COUNT(*) AS c FROM t JOIN u ON t.iv = u.iv",
    "SELECT SUM(n) AS s FROM t WHERE (SELECT COUNT(*) FROM u WHERE u.ts2 < TIMESTAMP '2020-01-31' + t.iv) > 3",
    "SELECT id, SUM(iv) OVER (ORDER BY id ROWS BETWEEN 2 PRECEDING AND CURRENT ROW) AS w FROM t WHERE id < 30 ORDER BY id",
    "SELECT SUM(x) AS s FROM v",
    "SELECT MAX(iv - INTERVAL '1 mon') AS m FROM t WHERE id % 3 = 0",
    "SELECT COUNT(iv) AS k FROM t", /* the fast aggregate path over a 16-byte column (the advisor, 15:0x) */
};

static void check_all(const char *what)
{
    mans a;
    m_answers(&a);
    const char *w[11] = {a.q1, a.q2, a.q3, a.q4, a.q5, a.q6, a.q7, a.q8, a.q9, a.q10, a.q11};
    for (int q = 0; q < 11; q++) {
        const char *got = csv(kQ[q]);
        if (strcmp(got, w[q])) {
            char m[3600];
            snprintf(m, sizeof m, "%s, %.300s\n      want: %.1200s\n      got:  %.1200s", what, kQ[q], w[q], got);
            test_fail(__FILE__, __LINE__, m);
        }
    }
}

static void insert_row(const mrow *r)
{
    imdb_buf b;
    imdb_buf_init(&b);
    imdb_buf_printf(&b, "INSERT INTO t VALUES (%lld, ", (long long)r->id);
    iv_lit(&b, &r->iv);
    imdb_buf_put_str(&b, ", TIMESTAMP '");
    ts_text(&b, r->ts);
    imdb_buf_printf(&b, "', %lld)", (long long)r->n);
    char sql[400];
    CHECK(imdb_buf_check(&b, &g_e) == 0 && b.len < sizeof sql);
    snprintf(sql, sizeof sql, "%.*s", (int)b.len, (const char *)b.p);
    imdb_buf_free(&b);
    OK(run(sql));
}

/* a dump's bytes */
typedef struct outb {
    char *p;
    size_t n, cap;
} outb;

static int outb_write(void *arg, const char *b, size_t n)
{
    outb *o = arg;
    if (o->n + n + 1 > o->cap) {
        size_t c = (o->n + n + 1) * 2;
        char *q = realloc(o->p, c);
        if (!q) return -1;
        o->p = q;
        o->cap = c;
    }
    memcpy(o->p + o->n, b, n);
    o->n += n;
    o->p[o->n] = 0;
    return 0;
}

/* a dump restored as imagedb sql -f restores it: each line a statement, a COPY's data the lines up to a \. line */
static int restore_text(const char *s, size_t n)
{
    static char line[1 << 14];
    size_t at = 0;
    while (at < n) {
        size_t eol = at;
        while (eol < n && s[eol] != '\n') eol++;
        size_t ll = eol - at;
        if (ll >= sizeof line) return -1;
        memcpy(line, s + at, ll);
        line[ll] = 0;
        at = eol < n ? eol + 1 : n;
        if (!ll || !strncmp(line, "--", 2)) continue;
        if (strncmp(line, "COPY ", 5)) {
            if (run(line)) return -1;
            continue;
        }
        size_t k = at;
        bool bol = true, inq = false;
        for (; k < n; k++) {
            if (bol && !inq && s[k] == '\\' && k + 1 < n && s[k + 1] == '.' && (k + 2 == n || s[k + 2] == '\n')) break;
            if (s[k] == '"') inq = !inq;
            bol = s[k] == '\n';
        }
        if (k >= n) return -1;
        g_in = (mem_in){s + at, k - at, 0};
        if (strncmp(csv(line), "COPY ", 5)) return -1;
        at = k + 2 < n ? k + 3 : n;
    }
    return 0;
}

static void digest_of(imdb_db *db, uint8_t out[32]) { imdb_lthash_digest(db->meta.digest_alg, &db->global, out); }

static void t_iv_paths(void)
{
    const char *dir = test_tmpdir();
    char p[700], q[700], r[700], sf[760];
    snprintf(p, sizeof p, "%s/p", dir);
    snprintf(q, sizeof q, "%s/q", dir);
    snprintf(r, sizeof r, "%s/r", dir);
    snprintf(sf, sizeof sf, "%s/stream", dir);
    imdb_err e = {0};
    CHECK(imdb_init(p, false, NULL, &e) == 0);
    imdb_db *db = open_with(p, false, 0);
    CHECK(db);
    if (!db) return;
    OK(run("CREATE TABLE t (id INT64 PRIMARY KEY, iv INTERVAL, ts TIMESTAMP NOT NULL, n INT64 NOT NULL)"));
    OK(run("CREATE TABLE u (id INT64 PRIMARY KEY, iv INTERVAL, ts2 TIMESTAMP NOT NULL)"));
    OK(run("CREATE VIEW v AS SELECT id, iv + INTERVAL '1 day' AS x FROM t"));
    g_rs = 0x9e3779b97f4a7c15ull;
    g_nt = 0;
    for (int i = 0; i < IVN; i++) {
        mrow *m = &g_t[g_nt++];
        m->id = i;
        m->n = i;
        m->ts = (m_days(2000, 1, 1) + (int64_t)i * 41) * DAYUS + (int64_t)(i % 24) * 3600000000LL;
        m->iv = m_draw();
        insert_row(m);
    }
    for (int j = 0; j < IVU; j++) {
        g_u[j].id = j;
        g_u[j].iv = m_draw();
        g_u[j].ts = (m_days(2020, 1, 31) + (int64_t)j * 3 - 30) * DAYUS + (int64_t)(j % 5) * 3600000000LL;
        imdb_buf b;
        imdb_buf_init(&b);
        imdb_buf_printf(&b, "INSERT INTO u VALUES (%d, ", j);
        iv_lit(&b, &g_u[j].iv);
        imdb_buf_put_str(&b, ", TIMESTAMP '");
        ts_text(&b, g_u[j].ts);
        imdb_buf_put_str(&b, "')");
        char sql[400];
        CHECK(imdb_buf_check(&b, &g_e) == 0 && b.len < sizeof sql);
        snprintf(sql, sizeof sql, "%.*s", (int)b.len, (const char *)b.p);
        imdb_buf_free(&b);
        OK(run(sql));
    }
    OK(run("SET cross_check = on"));
    uint8_t d0[32], d1[32];
    digest_of(db, d0);
    for (int pass = 0; pass < 5; pass++) {
        static const char *const what[5] = {"in memory", "after a CHECKPOINT", "at a budget of none", "after a reopen",
                                            "after a full replay"};
        if (pass == 1) OK(run("CHECKPOINT"));
        if (pass == 2) db->segcache.budget = 0; /* every image read again at its next use */
        if (pass >= 3) {
            done(db);
            db = open_with(p, pass == 4, 0);
            CHECK(db);
            if (!db) return;
            OK(run("SET cross_check = on"));
            digest_of(db, d1);
            CHECK(memcmp(d0, d1, 32) == 0);
        }
        check_all(what[pass]);
    }
    /* writes: an UPDATE by arithmetic, an INSERT ... SELECT negating, then the queries again, in memory and from the lake */
    OK(run("UPDATE t SET iv = iv + INTERVAL '1 mon -2 days' WHERE n % 4 = 0"));
    for (int i = 0; i < g_nt; i++)
        if (g_t[i].n % 4 == 0 && !g_t[i].iv.null) g_t[i].iv.mon += 1, g_t[i].iv.day -= 2;
    OK(run("INSERT INTO t SELECT id + 1000, -iv, ts, n FROM t WHERE id < 50"));
    for (int i = 0; i < 50; i++) {
        mrow *m = &g_t[g_nt++];
        *m = g_t[i];
        m->id += 1000;
        m->iv.mon = -m->iv.mon, m->iv.day = -m->iv.day, m->iv.us = -m->iv.us;
    }
    /* an equal span written as another triple: the row changes (its text, ts + iv), through the passes after and the
     * replica's digest (the advisor, 15:0x) */
    OK(run("UPDATE t SET iv = INTERVAL '30 days' WHERE iv = INTERVAL '1 mon' AND n % 2 = 0"));
    for (int i = 0; i < g_nt; i++)
        if (!g_t[i].iv.null && g_t[i].n % 2 == 0 && m_span(&g_t[i].iv) == (__int128)30 * DAYUS) g_t[i].iv = (miv){.day = 30};
    check_all("after the writes");
    OK(run("CHECKPOINT"));
    check_all("after the writes and a CHECKPOINT");
    /* an ADD with a DEFAULT: the older segments' rows read it as their missing value; a SET DEFAULT; a flush writes an
     * older row's value as a 16-byte cell */
    OK(run("ALTER TABLE t ADD COLUMN j INTERVAL DEFAULT INTERVAL '1 mon 2 days 00:00:03'"));
    char w[256];
    snprintf(w, sizeof w, "c,s\n%d,%s\n", g_nt, ivt(g_nt, 2 * g_nt, 3000000LL * g_nt));
    EXPECT("SELECT COUNT(*) AS c, SUM(j) AS s FROM t WHERE j = INTERVAL '1 mon 2 days 00:00:03'", w);
    OK(run("INSERT INTO t (id, iv, ts, n) VALUES (5000, NULL, TIMESTAMP '2001-01-01 00:00:00', 0)"));
    OK(run("ALTER TABLE t ALTER COLUMN j SET DEFAULT INTERVAL '-3 days'"));
    OK(run("INSERT INTO t (id, iv, ts, n) VALUES (5001, '1 day', TIMESTAMP '2001-01-01 00:00:00', 0)"));
    OK(run("CHECKPOINT"));
    OK(run("UPDATE t SET n = n + 1 WHERE id = 5")); /* an older segment's row, its j its missing value: written whole */
    OK(run("CHECKPOINT"));
    snprintf(w, sizeof w, "c,s,lo\n%d,%s,-3 days\n", g_nt + 2, ivt(g_nt + 1, 2 * (g_nt + 1) - 3, 3000000LL * (g_nt + 1)));
    EXPECT("SELECT COUNT(j) AS c, SUM(j) AS s, MIN(j) AS lo FROM t", w);
    EXPECT("SELECT j FROM t WHERE id = 5", "j\n1 mon 2 days 00:00:03\n");
    EXPECT("SELECT COUNT(*) AS c FROM t WHERE j = INTERVAL '-3 days'", "c\n1\n");
    for (int pass = 0; pass < 2; pass++) {
        done(db);
        db = open_with(p, pass == 1, pass == 1 ? 1 : 0);
        CHECK(db);
        if (!db) return;
        OK(run("SET cross_check = on"));
        EXPECT("SELECT COUNT(j) AS c, SUM(j) AS s, MIN(j) AS lo FROM t", w);
        EXPECT("SELECT j FROM t WHERE id = 5", "j\n1 mon 2 days 00:00:03\n");
    }
    CHECK(verify_db(db) == 0);
    /* COPY both ways: t's text into a twin, every row alike */
    OK(run("CREATE TABLE t2 (id INT64 PRIMARY KEY, iv INTERVAL, ts TIMESTAMP NOT NULL, n INT64 NOT NULL, j INTERVAL)"));
    g_copyn = 0;
    g_copy[0] = 0;
    EXPECT("COPY t TO STDOUT", "COPY 292");
    static char data[1 << 17];
    snprintf(data, sizeof data, "%s", g_copy);
    g_in = (mem_in){data, strlen(data), 0};
    EXPECT("COPY t2 FROM STDIN", "COPY 292");
    static char a1[1 << 17];
    snprintf(a1, sizeof a1, "%s", csv("SELECT * FROM t ORDER BY id"));
    EXPECT("SELECT * FROM t2 ORDER BY id", a1);
    CHECK(strstr(a1, "1 mon 2 days 00:00:03") && strstr(a1, "720:00:00") && strstr(a1, "30 days"));
    /* the dump, restored into a fresh database and dumped again alike */
    outb o1 = {0};
    OK(imdb_dump(db, 0, outb_write, &o1, &e));
    CHECK(o1.p && strstr(o1.p, "j INTERVAL DEFAULT '-3 days'"));
    digest_of(db, d0); /* the primary's last state, t2 and its rows too */
    done(db);
    CHECK(audit_dir(p) == 0);
    /* a replica at the primary's digest */
    imdb_identity id;
    OK(imdb_identity_read(p, &id, NULL, &g_e));
    OK(imdb_init_replica(q, &id, &g_e));
    OK(ship_to_file(p, 0, sf, &g_e));
    imdb_open_opts ro = {.sync = 0};
    imdb_db *rep = NULL;
    CHECK(imdb_open(q, &ro, &rep, &e) == 0);
    if (rep) {
        uint64_t applied = 0;
        OK(apply_file(rep, sf, &applied, &g_e));
        digest_of(rep, d1);
        CHECK(memcmp(d0, d1, 32) == 0);
        imdb_close(rep);
    }
    CHECK(audit_dir(q) == 0);
    CHECK(imdb_init(r, false, NULL, &e) == 0);
    imdb_db *rdb = open_with(r, false, 0);
    CHECK(rdb);
    if (rdb && o1.p) {
        CHECK(restore_text(o1.p, o1.n) == 0);
        outb o2 = {0};
        OK(imdb_dump(rdb, 0, outb_write, &o2, &e));
        CHECK(o2.p && strchr(o1.p, '\n') && strchr(o2.p, '\n') && !strcmp(strchr(o1.p, '\n'), strchr(o2.p, '\n')));
        EXPECT("SELECT * FROM t ORDER BY id", a1);
        CHECK(verify_db(rdb) == 0);
        free(o2.p);
    }
    if (rdb) done(rdb);
    CHECK(audit_dir(r) == 0);
    free(o1.p);
}


/* ERASE SUBJECT over INTERVAL cells (the advisor, 14:3x): rows in a segment, whose 16-byte cells the ERASE rewrites as
 * stubs, and rows in memory, an ADD's DEFAULT read by the older segment's rows; then a COMPACT, a reopen and a full replay
 * at the same digest, a replica of the redacted log at the primary's, VERIFY and the auditor on both */
static void t_iv_erase(void)
{
    const char *dir = test_tmpdir();
    char p[700], q[700], sf[760];
    snprintf(p, sizeof p, "%s/p", dir);
    snprintf(q, sizeof q, "%s/q", dir);
    snprintf(sf, sizeof sf, "%s/stream", dir);
    imdb_err e = {0};
    CHECK(imdb_init(p, false, NULL, &e) == 0);
    imdb_db *db = open_with(p, false, 0);
    CHECK(db);
    if (!db) return;
    OK(run("CREATE TABLE s (id INT64 PRIMARY KEY, u INT64 SUBJECT, iv INTERVAL, n INT64)"));
    OK(run("INSERT INTO s VALUES (1, 7, '1 mon', 1), (2, 7, '30 days', 2), (3, 8, '720:00:00', 3), (4, 9, NULL, 4), "
           "(5, 9, '-178956970 years -8 mons -2147483648 days -2562047788:00:54.775808', 5)"));
    OK(run("CHECKPOINT"));
    OK(run("ALTER TABLE s ADD COLUMN j INTERVAL DEFAULT INTERVAL '1 day 02:00:00'"));
    OK(run("INSERT INTO s VALUES (6, 7, '2 mons', 6, '3 days'), (7, 8, '1 day', 7, NULL)"));
    OK(run("ERASE SUBJECT 7")); /* rows 1 and 2 in the segment, 6 in memory */
    OK(run("CHECKPOINT"));
    OK(run("ERASE SUBJECT 8")); /* row 3 in the older segment, 7 in the newer */
    OK(run("SET cross_check = on"));
    static const char *const want = "c,s,j\n2,-178956970 years -8 mons -2147483648 days -2562047788:00:54.775808,2 days 04:00:00\n";
    EXPECT("SELECT COUNT(*) AS c, SUM(iv) AS s, SUM(j) AS j FROM s", want);
    OK(run("COMPACT s")); /* both versions' segments merged, stubs and 16-byte cells among them */
    EXPECT("SELECT COUNT(*) AS c, SUM(iv) AS s, SUM(j) AS j FROM s", want);
    uint8_t d0[32], d1[32];
    digest_of(db, d0);
    CHECK(verify_db(db) == 0);
    for (int pass = 0; pass < 2; pass++) {
        done(db);
        db = open_with(p, pass == 1, pass == 1 ? 1 : 0);
        CHECK(db);
        if (!db) return;
        OK(run("SET cross_check = on"));
        EXPECT("SELECT COUNT(*) AS c, SUM(iv) AS s, SUM(j) AS j FROM s", want);
        digest_of(db, d1);
        CHECK(memcmp(d0, d1, 32) == 0);
    }
    done(db);
    CHECK(audit_dir(p) == 0);
    imdb_identity id;
    OK(imdb_identity_read(p, &id, NULL, &g_e));
    OK(imdb_init_replica(q, &id, &g_e));
    OK(ship_to_file(p, 0, sf, &g_e)); /* the redacted log: the erased rows stubs from their INSERTs */
    imdb_open_opts ro = {.sync = 0};
    imdb_db *rep = NULL;
    CHECK(imdb_open(q, &ro, &rep, &e) == 0);
    if (rep) {
        uint64_t applied = 0;
        OK(apply_file(rep, sf, &applied, &g_e));
        digest_of(rep, d1);
        CHECK(memcmp(d0, d1, 32) == 0);
        imdb_close(rep);
    }
    CHECK(audit_dir(q) == 0);
}

const test_case iv_tests[] = {
    {"iv_codec", t_iv_codec},
    {"iv_sql", t_iv_sql},
    {"iv_paths", t_iv_paths},
    {"iv_erase", t_iv_erase},
};
const size_t iv_ntests = sizeof iv_tests / sizeof *iv_tests;
