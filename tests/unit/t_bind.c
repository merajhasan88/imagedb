/* N1b: a parameter binds as the literal of its value (docs/n1-design.md §4, N1b's rule): numbers and NULLs, in VALUES,
 * SET, a plain predicate, the key, UPDATE's and DELETE's WHERE, BETWEEN, IN and a join's ON. Each value runs twice, once
 * written as its literal into one table and once as an API parameter into its twin: the same verdict (taken or refused,
 * and its error's class), the same rows counted, the same path (the key's or not), and after every write the twins'
 * rows the same values. The table this replaces in prose: .work/scratch/n1/bind_probe2.c's. */
#include <math.h>
#include <string.h>

#include "../../server/conv.h"
#include "../../src/codec.h"
#include "../../src/db.h"
#include "../../src/sql.h"
#include "test.h"

static imdb_session g_s;
static imdb_err be;

typedef struct outcome {
    int rc;
    uint64_t n;
    bool key;
} outcome;

static outcome run(const char *sql, const imdb_value *p, uint32_t np)
{
    imdb_result r;
    imdb_err_clear(&be);
    outcome o = {0};
    o.rc = imdb_exec_one(&g_s, sql, strlen(sql), p, np, &r, &be);
    if (!o.rc) {
        o.n = r.has_count ? r.count : r.nrows;
        o.key = strstr(r.path, "primary key") != NULL;
    }
    imdb_result_free(&r);
    return o;
}

typedef struct val {
    char lit[64];
    imdb_value v;
} val;

/* a DECIMAL of scale s as its literal's text, and as a parameter */
static val dec(__int128 x, uint8_t s)
{
    val k;
    memset(&k, 0, sizeof k);
    k.v.type = IMDB_T_DECIMAL;
    k.v.scale = s;
    imdb_dec_set(&k.v, x, x < INT64_MIN || x > INT64_MAX);
    char dig[48];
    unsigned __int128 m = x < 0 ? (unsigned __int128)(-x) : (unsigned __int128)x;
    int n = 0;
    do dig[n++] = (char)('0' + (int)(m % 10)), m /= 10;
    while (m || n <= s);
    size_t o = 0;
    if (x < 0) k.lit[o++] = '-';
    for (int i = n - 1; i >= 0; i--) {
        k.lit[o++] = dig[i];
        if (i == s && s) k.lit[o++] = '.';
    }
    k.lit[o] = 0;
    return k;
}

static val i64(int64_t x)
{
    val k;
    memset(&k, 0, sizeof k);
    k.v.type = IMDB_T_INT64;
    k.v.i = x;
    snprintf(k.lit, sizeof k.lit, "%lld", (long long)x);
    return k;
}

static val f64(double d)
{
    val k;
    memset(&k, 0, sizeof k);
    k.v.type = IMDB_T_FLOAT64;
    k.v.i = imdb_f64_key(d);
    snprintf(k.lit, sizeof k.lit, "%.17e", d); /* an exponent: the literal is a FLOAT64's */
    return k;
}

static val null_of(uint8_t t)
{
    val k;
    memset(&k, 0, sizeof k);
    k.v.type = t;
    k.v.null = true;
    snprintf(k.lit, sizeof k.lit, "NULL");
    return k;
}

static val text(const char *s)
{
    val k;
    memset(&k, 0, sizeof k);
    k.v.type = IMDB_T_TEXT;
    k.v.s = (const uint8_t *)s;
    k.v.len = (uint32_t)strlen(s);
    snprintf(k.lit, sizeof k.lit, "'%s'", s);
    return k;
}

/* the twins' rows the same, column by column, by their text through the engine's own rendering (SELECT ... ORDER BY) */
static bool twins_equal(int c)
{
    char a[128], b[128];
    snprintf(a, sizeof a, "SELECT id, c FROM l%d ORDER BY id", c);
    snprintf(b, sizeof b, "SELECT id, c FROM p%d ORDER BY id", c);
    imdb_result ra, rb;
    imdb_err_clear(&be);
    bool ok = imdb_exec_one(&g_s, a, strlen(a), NULL, 0, &ra, &be) == 0;
    ok = ok && imdb_exec_one(&g_s, b, strlen(b), NULL, 0, &rb, &be) == 0;
    if (ok) {
        ok = ra.nrows == rb.nrows;
        for (uint64_t i = 0; ok && i < ra.nrows * 2; i++) {
            const imdb_cell *x = &ra.cells[i], *y = &rb.cells[i];
            bool xn = x->null || x->v.null, yn = y->null || y->v.null;
            ok = xn == yn && (xn || (x->v.type == y->v.type && imdb_value_cmp(&x->v, &y->v) == 0 &&
                                     (x->v.type != IMDB_T_DECIMAL || x->v.scale == y->v.scale)));
        }
        imdb_result_free(&rb);
    }
    imdb_result_free(&ra);
    return ok;
}

/* two statements' answers the same: their rows, or their statuses, through the engine's own rendering */
static bool render_of(const char *sql, const imdb_value *p, imdb_buf *out)
{
    imdb_result r;
    imdb_err_clear(&be);
    if (imdb_exec_one(&g_s, sql, strlen(sql), p, p ? 1 : 0, &r, &be)) return false;
    if (r.has_rows) imdb_result_render(&r, true, out);
    else imdb_buf_put_str(out, r.status);
    imdb_result_free(&r);
    return imdb_buf_check(out, &be) == 0;
}

static bool same_answer_p(const char *a, const char *b, const imdb_value *pb)
{
    imdb_buf x, y;
    imdb_buf_init(&x);
    imdb_buf_init(&y);
    bool ok = render_of(a, NULL, &x) && render_of(b, pb, &y) && x.len == y.len && !memcmp(x.p, y.p, x.len);
    imdb_buf_free(&x);
    imdb_buf_free(&y);
    return ok;
}

static bool same_answer(const char *a, const char *b) { return same_answer_p(a, b, NULL); }

static void t_bind_as_literal(void)
{
    const char *dir = test_tmpdir();
    imdb_err e = {0};
    CHECK_OK(imdb_init(dir, false, NULL, &e));
    imdb_open_opts o = {.sync = 0};
    imdb_db *db = NULL;
    CHECK_OK(imdb_open(dir, &o, &db, &e));
    imdb_session_init(&g_s, db);
    static const char *const cols[] = {"INT64", "SMALLINT", "DECIMAL(10,2)", "DECIMAL(38,6)", "FLOAT64", "TEXT", "DECIMAL(38,37)"};
    static const char *const seed[] = {"7", "7", "1.50", "1.5", "1.5e0", "'7'", "0.5"};
    static const bool keyable[] = {true, true, true, true, false, true, true};
    enum { NC = sizeof cols / sizeof *cols };
    __int128 big = imdb_pow10_128(30);
    val base[] = {
        i64(7), i64(0), i64(-7), i64(99999999), i64(100000000), i64(INT64_MAX), i64(INT64_MIN),
        dec(150, 2), dec(15, 1), dec(1505, 3), dec(700, 2), dec(-1, 1), dec(9999999999, 2), dec(10000000000, 2),
        dec(big + 1, 6), dec(big * 10, 0), dec(1, 7), dec(7, 0), dec(-5, 0), dec((__int128)INT64_MAX + 1, 0),
        f64(1.5), f64(-0.1), f64(7.0),
        null_of(IMDB_T_INT64), null_of(IMDB_T_TEXT), null_of(IMDB_T_DECIMAL), null_of(IMDB_T_FLOAT64),
        text("7"), dec(-1500, 3), dec(1500, 3), i64(1000000000000000000LL),
    };
    enum { NB = sizeof base / sizeof *base, NV = NB + 30 };
    val vals[NV];
    memcpy(vals, base, sizeof base);
    for (int k = NB; k < NV; k++) { /* wide DECIMALs past 2^53: into a FLOAT64 by one rounding, the literal's, never two */
        __int128 x = (__int128)(test_rand() % 9000000000000000000ull + 1000000000000000000ull) * 1000 + (__int128)(test_rand() % 1000);
        if (k % 3 == 0) x = x * 1000000000 + (__int128)(test_rand() % 1000000000);
        vals[k] = dec(k % 2 ? -x : x, (uint8_t)(1 + test_rand() % 12));
    }
    bool fine = true;
    char sql[512];
    for (int c = 0; c < NC && fine; c++)
        for (int t = 0; t < 2; t++) { /* l: the literal's table, p: the parameter's; kl and kp keyed by the column */
            snprintf(sql, sizeof sql, "CREATE TABLE %c%d (id INT64 PRIMARY KEY, c %s)", t ? 'p' : 'l', c, cols[c]);
            fine = fine && run(sql, NULL, 0).rc == 0;
            snprintf(sql, sizeof sql, "INSERT INTO %c%d VALUES (1, %s), (2, NULL)", t ? 'p' : 'l', c, seed[c]);
            fine = fine && run(sql, NULL, 0).rc == 0;
            if (keyable[c]) {
                snprintf(sql, sizeof sql, "CREATE TABLE k%c%d (c %s PRIMARY KEY, x INT64)", t ? 'p' : 'l', c, cols[c]);
                fine = fine && run(sql, NULL, 0).rc == 0;
                snprintf(sql, sizeof sql, "INSERT INTO k%c%d VALUES (%s, 1)", t ? 'p' : 'l', c, seed[c]);
                fine = fine && run(sql, NULL, 0).rc == 0;
            }
        }
    CHECK(fine);
    static const char *const pos[] = {"VALUES", "SET", "pred", "key", "UPDATE WHERE", "DELETE WHERE", "BETWEEN", "IN", "ON"};
    enum { NP = sizeof pos / sizeof *pos };
    int id = 100, checked = 0, taken = 0;
    for (int k = 0; k < NV; k++)
        for (int c = 0; c < NC; c++)
            for (int p = 0; p < NP; p++) {
                if (p == 3 && !keyable[c]) continue;
                outcome r[2];
                for (int t = 0; t < 2; t++) {
                    char tb = t ? 'p' : 'l';
                    const char *v = t ? "$1" : vals[k].lit;
                    switch (p) {
                    case 0: snprintf(sql, sizeof sql, "INSERT INTO %c%d VALUES (%d, %s)", tb, c, id, v); break;
                    case 1: snprintf(sql, sizeof sql, "UPDATE %c%d SET c = %s WHERE id = 1", tb, c, v); break;
                    case 2: snprintf(sql, sizeof sql, "SELECT id FROM %c%d WHERE c = %s", tb, c, v); break;
                    case 3: snprintf(sql, sizeof sql, "SELECT x FROM k%c%d WHERE c = %s", tb, c, v); break;
                    case 4: snprintf(sql, sizeof sql, "UPDATE %c%d SET c = c WHERE c = %s", tb, c, v); break;
                    case 5: snprintf(sql, sizeof sql, "DELETE FROM %c%d WHERE c = %s AND id < 0", tb, c, v); break;
                    case 6: snprintf(sql, sizeof sql, "SELECT id FROM %c%d WHERE c BETWEEN %s AND %s", tb, c, v, v); break;
                    case 7: snprintf(sql, sizeof sql, "SELECT id FROM %c%d WHERE c IN (%s)", tb, c, v); break;
                    default: snprintf(sql, sizeof sql, "SELECT a.id FROM %c%d AS a JOIN %c%d AS b ON a.id = b.id AND a.c = %s", tb,
                                      c, tb, c, v); break;
                    }
                    imdb_value pv = vals[k].v;
                    r[t] = run(sql, t ? &pv : NULL, t ? 1 : 0);
                }
                if (p == 0) id++;
                /* the divergence outside the rule, the trees' (IN and a join's ON): a NULL parameter keeps its type there
                 * (NULL + 1 is NULL), so it finds no row where its type compares with the column's and is refused where it
                 * does not, while the untyped literal NULL is taken in IN and refused in ON */
                bool tree_null = (p == 7 || p == 8) && vals[k].v.null;
                bool same = tree_null ? (r[1].rc == 0 && r[1].n == 0) || r[1].rc == IMDB_ERR_INVALID
                                      : (r[0].rc == 0) == (r[1].rc == 0) && r[0].rc == r[1].rc && r[0].n == r[1].n &&
                                            r[0].key == r[1].key;
                if (same && (p == 0 || p == 1) && r[0].rc == 0) same = twins_equal(c);
                if (!same) {
                    fprintf(stderr, "    %s into %s, %s: literal rc %d n %llu key %d, parameter rc %d n %llu key %d\n", vals[k].lit,
                            cols[c], pos[p], r[0].rc, (unsigned long long)r[0].n, r[0].key, r[1].rc,
                            (unsigned long long)r[1].n, r[1].key);
                    fine = false;
                }
                checked++;
                taken += r[1].rc == 0;
            }
    fprintf(stderr, "    %d cells, the parameter taken in %d\n", checked, taken);
    SOFT(fine && checked > 1000);
    imdb_session_close(&g_s);
    imdb_close(db);
}

static imdb_db *open_bind(void)
{
    const char *dir = test_tmpdir();
    imdb_err e = {0};
    if (imdb_init(dir, false, NULL, &e)) return NULL;
    imdb_open_opts o = {.sync = 0};
    imdb_db *db = NULL;
    if (imdb_open(dir, &o, &db, &e)) return NULL;
    imdb_session_init(&g_s, db);
    return db;
}

static void close_bind(imdb_db *db)
{
    imdb_session_close(&g_s);
    imdb_close(db);
}

/* a parameter outside its own type's rules is refused wherever it is bound, as before N1b (a caller's bytes: a DECIMAL's
 * scale past 38 indexes nothing, a FLOAT64 that is not finite never reaches a tree); SAN reads the memory */
static void t_bind_malformed(void)
{
    imdb_db *db = open_bind();
    CHECK(db);
    static const char *const cols[] = {"INT64", "DECIMAL(10,2)", "FLOAT64", "TEXT", "DECIMAL(38,37)"};
    enum { NC = sizeof cols / sizeof *cols };
    char sql[256];
    bool fine = true;
    for (int c = 0; c < NC; c++) {
        snprintf(sql, sizeof sql, "CREATE TABLE m%d (id INT64 PRIMARY KEY, c %s, x INT64)", c, cols[c]);
        fine = fine && run(sql, NULL, 0).rc == 0;
    }
    SOFT(fine);
    imdb_value bad[8];
    memset(bad, 0, sizeof bad);
    bad[0].type = IMDB_T_DECIMAL, bad[0].scale = 39, bad[0].i = 1;
    bad[1].type = IMDB_T_DECIMAL, bad[1].scale = 255, bad[1].i = 7;
    bad[2].type = IMDB_T_DECIMAL, imdb_dec_set(&bad[2], imdb_pow10_128(38), true);
    bad[3].type = IMDB_T_DECIMAL, imdb_dec_set(&bad[3], -imdb_pow10_128(38), true);
    bad[4].type = IMDB_T_FLOAT64, bad[4].i = imdb_f64_key(__builtin_nan(""));
    bad[5].type = IMDB_T_FLOAT64, bad[5].i = imdb_f64_key(__builtin_inf());
    bad[6].type = IMDB_T_FLOAT64, bad[6].i = -1; /* the key -0 would have: the engine's one zero is 0 */
    bad[7].type = 14;                            /* no such type */
    static const char *const pre[] = {"INSERT INTO m", "UPDATE m", "SELECT x FROM m", "SELECT x FROM m", "SELECT x FROM m",
                                      "SELECT x FROM m", "DELETE FROM m", "SELECT $1 FROM m"};
    static const char *const suf[] = {" VALUES (1, $1, 1)", " SET x = 1 WHERE c = $1", " WHERE c = $1",
                                      " WHERE c BETWEEN $1 AND $1", " WHERE c IN ($1)", " WHERE (c = $1) = TRUE",
                                      " WHERE c = $1", ""};
    int n = 0;
    for (int k = 0; k < 8; k++)
        for (int c = 0; c < NC; c++)
            for (size_t p = 0; p < sizeof pre / sizeof *pre; p++) {
                snprintf(sql, sizeof sql, "%s%d%s", pre[p], c, suf[p]);
                outcome o = run(sql, &bad[k], 1);
                if (o.rc == 0) {
                    fprintf(stderr, "    malformed parameter %d taken: %s (column %s)\n", k, sql, cols[c]);
                    fine = false;
                }
                n++;
            }
    SOFT(fine && n == 8 * NC * 8);
    close_bind(db);
}

/* the other places a parameter binds through bind_lit: SHOW HISTORY's key, EXECUTE's declared types, the API's prepared
 * statements, ON CONFLICT's SET, UPDATE ... FROM's SET, a DEFAULT; and ERASE SUBJECT, an integer or a string as its
 * literal (a number of another kind, a NULL: refused before anything binds) */
static void t_bind_callers(void)
{
    imdb_db *db = open_bind();
    CHECK(db);
    static const char *const setup[] = {
        "CREATE TABLE h (k DECIMAL(10,2) PRIMARY KEY, x INT64)",       "INSERT INTO h VALUES (7, 1)",
        "CREATE TABLE ul (id INT64 PRIMARY KEY, c DECIMAL(10,2))",     "CREATE TABLE up (id INT64 PRIMARY KEY, c DECIMAL(10,2))",
        "INSERT INTO ul VALUES (1, 0), (2, 0)",                        "INSERT INTO up VALUES (1, 0), (2, 0)",
        "CREATE TABLE src (id INT64 PRIMARY KEY, w INT64)",            "INSERT INTO src VALUES (1, 5), (2, 6)",
        "CREATE TABLE sl (id INT64 PRIMARY KEY, who INT64 SUBJECT)",   "INSERT INTO sl VALUES (1, 7), (2, 8), (3, 9)",
    };
    bool fine = true;
    for (size_t i = 0; i < sizeof setup / sizeof *setup; i++) {
        outcome o = run(setup[i], NULL, 0);
        if (o.rc) fprintf(stderr, "    setup: %s: %s\n", setup[i], be.msg), fine = false;
    }
    CHECK(fine);
    val seven = i64(7), inexact = dec(1505, 3), whole = dec(700, 2);
    /* SHOW HISTORY's key: as its literal */
    const val *hv[] = {&seven, &inexact, &whole};
    for (int k = 0; k < 3; k++) {
        char a[128];
        snprintf(a, sizeof a, "SHOW HISTORY h (%s)", hv[k]->lit);
        outcome l = run(a, NULL, 0), p = run("SHOW HISTORY h ($1)", &hv[k]->v, 1);
        if (l.rc != p.rc || l.n != p.n) fprintf(stderr, "    SHOW HISTORY %s: %d/%llu, %d/%llu\n", hv[k]->lit, l.rc,
                                                (unsigned long long)l.n, p.rc, (unsigned long long)p.n), fine = false;
    }
    /* EXECUTE with a declared type: an API $1 bound to it as its literal would be */
    fine = fine && run("PREPARE q (DECIMAL(10,2)) AS SELECT x FROM h WHERE k = $1", NULL, 0).rc == 0;
    for (int k = 0; k < 3; k++) {
        char a[128];
        snprintf(a, sizeof a, "EXECUTE q (%s)", hv[k]->lit);
        outcome l = run(a, NULL, 0), p = run("EXECUTE q ($1)", &hv[k]->v, 1);
        if (l.rc != p.rc || l.n != p.n) fprintf(stderr, "    EXECUTE q (%s): %d/%llu, %d/%llu\n", hv[k]->lit, l.rc,
                                                (unsigned long long)l.n, p.rc, (unsigned long long)p.n), fine = false;
    }
    /* the API's prepared statement */
    imdb_err_clear(&be);
    static const char ps[] = "SELECT x FROM h WHERE k = $1";
    fine = fine && imdb_prepare(&g_s, "ap", ps, sizeof ps - 1, &be) == 0;
    for (int k = 0; k < 3; k++) {
        char a[128];
        snprintf(a, sizeof a, "SELECT x FROM h WHERE k = %s", hv[k]->lit);
        outcome l = run(a, NULL, 0);
        imdb_result r;
        imdb_err_clear(&be);
        int rc = imdb_execute(&g_s, "ap", &hv[k]->v, 1, &r, &be);
        uint64_t n = rc ? 0 : r.nrows;
        imdb_result_free(&r);
        if (l.rc != rc || l.n != n) fprintf(stderr, "    imdb_execute %s: %d/%llu, %d/%llu\n", hv[k]->lit, l.rc,
                                            (unsigned long long)l.n, rc, (unsigned long long)n), fine = false;
    }
    /* ON CONFLICT's SET and UPDATE ... FROM's SET, into twins */
    for (int k = 0; k < 3; k++) {
        char a[160];
        snprintf(a, sizeof a, "INSERT INTO ul VALUES (1, 0) ON CONFLICT (id) DO UPDATE SET c = %s", hv[k]->lit);
        outcome l = run(a, NULL, 0), p = run("INSERT INTO up VALUES (1, 0) ON CONFLICT (id) DO UPDATE SET c = $1", &hv[k]->v, 1);
        snprintf(a, sizeof a, "UPDATE ul SET c = %s FROM src WHERE src.id = ul.id", hv[k]->lit);
        outcome l2 = run(a, NULL, 0), p2 = run("UPDATE up SET c = $1 FROM src WHERE src.id = up.id", &hv[k]->v, 1);
        if (l.rc != p.rc || l.n != p.n || l2.rc != p2.rc || l2.n != p2.n)
            fprintf(stderr, "    SET of %s: upsert %d/%d, from %d/%d\n", hv[k]->lit, l.rc, p.rc, l2.rc, p2.rc), fine = false;
    }
    imdb_result ra, rb;
    imdb_err_clear(&be);
    if (imdb_exec_one(&g_s, "SELECT id, c FROM ul ORDER BY id", 32, NULL, 0, &ra, &be) == 0 &&
        imdb_exec_one(&g_s, "SELECT id, c FROM up ORDER BY id", 32, NULL, 0, &rb, &be) == 0) {
        for (uint64_t i = 0; i < ra.nrows * 2 && i < rb.nrows * 2; i++)
            if (imdb_value_cmp(&ra.cells[i].v, &rb.cells[i].v)) fine = false, fprintf(stderr, "    the SETs' twins differ\n");
        imdb_result_free(&ra);
        imdb_result_free(&rb);
    } else
        fine = false;
    /* a DEFAULT takes a parameter as its literal: CREATE's, an ADD's and a SET DEFAULT's each taken, the defaults the
     * literal twin's (rows inserted leaving the columns out); one that would lose a digit refused by both */
    val sevenhalf = dec(75, 1);
    static const char *const dl[] = {"CREATE TABLE dl (id INT64 PRIMARY KEY, x DECIMAL(10,2) DEFAULT 7)",
                                     "ALTER TABLE dl ADD COLUMN y DECIMAL(10,2) DEFAULT 7",
                                     "ALTER TABLE dl ALTER COLUMN x SET DEFAULT 7.5"};
    static const char *const dp[] = {"CREATE TABLE dp (id INT64 PRIMARY KEY, x DECIMAL(10,2) DEFAULT $1)",
                                     "ALTER TABLE dp ADD COLUMN y DECIMAL(10,2) DEFAULT $1",
                                     "ALTER TABLE dp ALTER COLUMN x SET DEFAULT $1"};
    const val *dv[] = {&seven, &seven, &sevenhalf};
    for (int k = 0; k < 3; k++) {
        outcome l = run(dl[k], NULL, 0), p = run(dp[k], &dv[k]->v, 1);
        if (l.rc || p.rc) fine = false, fprintf(stderr, "    %s: %d, the parameter %s: %d\n", dl[k], l.rc, dv[k]->lit, p.rc);
        char a[96];
        snprintf(a, sizeof a, "INSERT INTO dl (id) VALUES (%d)", k + 1);
        fine = fine && run(a, NULL, 0).rc == 0;
        snprintf(a, sizeof a, "INSERT INTO dp (id) VALUES (%d)", k + 1);
        fine = fine && run(a, NULL, 0).rc == 0;
    }
    if (!same_answer("SELECT * FROM dl ORDER BY id", "SELECT * FROM dp ORDER BY id"))
        fine = false, fprintf(stderr, "    the DEFAULTs' twins differ\n");
    outcome dli = run("ALTER TABLE dl ALTER COLUMN x SET DEFAULT 1.505", NULL, 0);
    outcome dpi = run("ALTER TABLE dp ALTER COLUMN x SET DEFAULT $1", &inexact.v, 1);
    if (!dli.rc || !dpi.rc) fine = false, fprintf(stderr, "    SET DEFAULT of 1.505: %d, the parameter %d\n", dli.rc, dpi.rc);
    /* SHOW DIGEST's SUBJECT: the subject column's predicate, as its literal */
    val d70 = dec(7, 0);
    if (!same_answer("SHOW DIGEST sl SUBJECT 7", "SHOW DIGEST sl SUBJECT 7") || /* the control: a digest is stable */
        !same_answer_p("SHOW DIGEST sl SUBJECT 7", "SHOW DIGEST sl SUBJECT $1", &seven.v) ||
        !same_answer_p("SHOW DIGEST sl SUBJECT 7", "SHOW DIGEST sl SUBJECT $1", &d70.v))
        fine = false, fprintf(stderr, "    SHOW DIGEST sl SUBJECT $1: not its literal's\n");
    outcome sdl = run("SHOW DIGEST sl SUBJECT 7.00", NULL, 0), sdp = run("SHOW DIGEST sl SUBJECT $1", &whole.v, 1);
    if (sdl.rc != IMDB_ERR_INVALID || sdp.rc != IMDB_ERR_INVALID)
        fine = false, fprintf(stderr, "    SHOW DIGEST SUBJECT 7.00: %d, the parameter %d\n", sdl.rc, sdp.rc);
    /* a malformed value through every one of these callers: refused, nothing committed */
    imdb_value mal[2];
    memset(mal, 0, sizeof mal);
    mal[0].type = IMDB_T_DECIMAL, mal[0].scale = 255, mal[0].i = 7;
    mal[1].type = IMDB_T_FLOAT64, mal[1].i = imdb_f64_key(__builtin_nan(""));
    static const char *const via[] = {"SHOW HISTORY h ($1)", "EXECUTE q ($1)",
                                      "INSERT INTO up VALUES (1, 0) ON CONFLICT (id) DO UPDATE SET c = $1",
                                      "UPDATE up SET c = $1 FROM src WHERE src.id = up.id",
                                      "CREATE TABLE dz (id INT64 PRIMARY KEY, x DECIMAL(10,2) DEFAULT $1)",
                                      "ALTER TABLE dp ADD COLUMN z DECIMAL(10,2) DEFAULT $1",
                                      "ALTER TABLE dp ALTER COLUMN x SET DEFAULT $1", "ERASE SUBJECT $1",
                                      "SHOW DIGEST sl SUBJECT $1"};
    uint64_t seq = db->seq;
    for (int k = 0; k < 2; k++) {
        for (size_t v = 0; v < sizeof via / sizeof *via; v++)
            if (!run(via[v], &mal[k], 1).rc) fine = false, fprintf(stderr, "    a malformed value %d taken: %s\n", k, via[v]);
        imdb_result r;
        imdb_err_clear(&be);
        if (!imdb_execute(&g_s, "ap", &mal[k], 1, &r, &be)) fine = false, fprintf(stderr, "    imdb_execute took malformed %d\n", k);
        imdb_result_free(&r);
    }
    if (db->seq != seq) fine = false, fprintf(stderr, "    a refused malformed value committed\n");
    /* ERASE SUBJECT: an integer or a string, a parameter as the literal */
    val nul = null_of(IMDB_T_INT64), dnul = null_of(IMDB_T_DECIMAL), seven0 = dec(7, 0);
    const val *refused[] = {&whole, &seven0, &nul, &dnul, &inexact};
    for (int k = 0; k < 5; k++) {
        outcome p = run("ERASE SUBJECT $1", &refused[k]->v, 1);
        if (p.rc != IMDB_ERR_INVALID) fprintf(stderr, "    ERASE SUBJECT $1 (%s): %d\n", refused[k]->lit, p.rc), fine = false;
    }
    outcome lit = run("ERASE SUBJECT 7.00", NULL, 0);
    if (lit.rc != IMDB_ERR_INVALID) fine = false, fprintf(stderr, "    ERASE SUBJECT 7.00: %d\n", lit.rc);
    outcome rows = run("SELECT id FROM sl", NULL, 0);
    if (rows.n != 3) fine = false, fprintf(stderr, "    a refused ERASE erased: %llu rows left\n", (unsigned long long)rows.n);
    val eight = i64(8);
    outcome ok = run("ERASE SUBJECT $1", &eight.v, 1);
    rows = run("SELECT id FROM sl", NULL, 0);
    if (ok.rc || rows.n != 2) fine = false, fprintf(stderr, "    ERASE SUBJECT $1 (8): %d, %llu rows\n", ok.rc, (unsigned long long)rows.n);
    SOFT(fine);
    close_bind(db);
}

/* a NULL parameter of any type, or of none, into a column of any type: as a literal NULL (taken where the column takes
 * NULL, refused by NOT NULL); a number into a column of another kind than a number's: refused, as its literal */
static void t_bind_nulls(void)
{
    imdb_db *db = open_bind();
    CHECK(db);
    CHECK(run("CREATE TYPE mood AS ENUM ('sad', 'ok')", NULL, 0).rc == 0);
    static const char *const cols[] = {"INT64",   "DECIMAL(10,2)", "FLOAT64",   "BOOL", "TEXT",     "TIMESTAMP", "TIMESTAMPTZ",
                                       "DATE",    "TIME",          "UUID",      "BYTEA", "INTERVAL", "mood",      "INT64 NOT NULL",
                                       "mood NOT NULL"};
    enum { NC = sizeof cols / sizeof *cols };
    static const uint8_t types[] = {0, IMDB_T_INT64, IMDB_T_DECIMAL, IMDB_T_TEXT, IMDB_T_BOOL, IMDB_T_TIMESTAMP, IMDB_T_FLOAT64,
                                    IMDB_T_TIMESTAMPTZ, IMDB_T_DATE, IMDB_T_TIME, IMDB_T_UUID, IMDB_T_BYTEA, IMDB_T_INTERVAL,
                                    IMDB_T_ENUM};
    bool fine = true;
    char sql[256];
    for (int c = 0; c < NC; c++) {
        snprintf(sql, sizeof sql, "CREATE TABLE n%d (id INT64 PRIMARY KEY, c %s)", c, cols[c]);
        if (run(sql, NULL, 0).rc) fine = false, fprintf(stderr, "    %s: %s\n", sql, be.msg);
    }
    CHECK(fine);
    int id = 1;
    for (int c = 0; c < NC; c++) {
        snprintf(sql, sizeof sql, "INSERT INTO n%d VALUES (%d, NULL)", c, id++);
        outcome lit = run(sql, NULL, 0);
        for (size_t t = 0; t < sizeof types; t++) {
            imdb_value pv = {.type = types[t], .null = true};
            snprintf(sql, sizeof sql, "INSERT INTO n%d VALUES (%d, $1)", c, id++);
            outcome p = run(sql, &pv, 1);
            if (p.rc != lit.rc) fine = false, fprintf(stderr, "    a NULL of type %u into %s: literal %d, parameter %d\n", types[t],
                                                      cols[c], lit.rc, p.rc);
        }
        /* a number into a column that is not a number's: refused as its literal */
        if (c >= 3 && c != 13) {
            val nums[] = {i64(7), dec(150, 2)};
            for (int k = 0; k < 2; k++) {
                snprintf(sql, sizeof sql, "INSERT INTO n%d VALUES (%d, %s)", c, id++, nums[k].lit);
                outcome l = run(sql, NULL, 0);
                snprintf(sql, sizeof sql, "INSERT INTO n%d VALUES (%d, $1)", c, id++);
                outcome p = run(sql, &nums[k].v, 1);
                if (!l.rc || !p.rc) fine = false, fprintf(stderr, "    %s into %s taken: literal %d, parameter %d\n", nums[k].lit,
                                                          cols[c], l.rc, p.rc);
            }
        }
    }
    SOFT(fine);
    close_bind(db);
}

/* an ENUM column takes a label as a TEXT parameter, as its string literal (the wire's one non-NULL ENUM parameter, §4):
 * in VALUES, SET, a predicate and the key, its literal twin's verdict, count and path, the twins' rows the same; an
 * unknown label refused by both; a label holding a quote by its bytes; AS OF below a label refused by both; in a tree a
 * parameter keeps its type (TEXT against an ENUM refused; CAST($1 AS mood) the way); and a wire TEXT through conv into
 * the column, the column's label back as an ENUM */
static void t_bind_enum(void)
{
    imdb_db *db = open_bind();
    CHECK(db);
    static const char *const setup[] = {"CREATE TYPE mood AS ENUM ('sad', 'ok', 'it''s')",
                                        "CREATE TABLE le (id INT64 PRIMARY KEY, c mood)",
                                        "CREATE TABLE pe (id INT64 PRIMARY KEY, c mood)",
                                        "CREATE TABLE kle (c mood PRIMARY KEY, x INT64)",
                                        "CREATE TABLE kpe (c mood PRIMARY KEY, x INT64)"};
    bool fine = true;
    for (size_t i = 0; i < sizeof setup / sizeof *setup; i++)
        if (run(setup[i], NULL, 0).rc) fine = false, fprintf(stderr, "    %s: %s\n", setup[i], be.msg);
    CHECK(fine);
    val ok = text("ok"), sad = text("sad"), quote = text("it's"), meh = text("meh");
    struct {
        const char *l, *p;
        const val *v;
    } twins[] = {
        {"INSERT INTO le VALUES (1, 'ok')", "INSERT INTO pe VALUES (1, $1)", &ok},
        {"INSERT INTO le VALUES (2, 'it''s')", "INSERT INTO pe VALUES (2, $1)", &quote},
        {"INSERT INTO le VALUES (3, 'meh')", "INSERT INTO pe VALUES (3, $1)", &meh},
        {"UPDATE le SET c = 'sad' WHERE id = 1", "UPDATE pe SET c = $1 WHERE id = 1", &sad},
        {"UPDATE le SET c = 'meh' WHERE id = 1", "UPDATE pe SET c = $1 WHERE id = 1", &meh},
        {"SELECT id FROM le WHERE c = 'sad'", "SELECT id FROM pe WHERE c = $1", &sad},
        {"SELECT id FROM le WHERE c = 'it''s'", "SELECT id FROM pe WHERE c = $1", &quote},
        {"SELECT id FROM le WHERE c = 'meh'", "SELECT id FROM pe WHERE c = $1", &meh},
        {"SELECT id FROM le WHERE c <> 'ok'", "SELECT id FROM pe WHERE c <> $1", &ok},
        {"INSERT INTO kle VALUES ('ok', 1)", "INSERT INTO kpe VALUES ($1, 1)", &ok},
        {"SELECT x FROM kle WHERE c = 'ok'", "SELECT x FROM kpe WHERE c = $1", &ok},
        {"DELETE FROM le WHERE c = 'it''s'", "DELETE FROM pe WHERE c = $1", &quote},
    };
    for (size_t i = 0; i < sizeof twins / sizeof *twins; i++) {
        outcome l = run(twins[i].l, NULL, 0), p = run(twins[i].p, &twins[i].v->v, 1);
        if (l.rc != p.rc || l.n != p.n || l.key != p.key)
            fine = false, fprintf(stderr, "    %s: %d/%llu/%d, the parameter %d/%llu/%d\n", twins[i].l, l.rc, (unsigned long long)l.n,
                                  l.key, p.rc, (unsigned long long)p.n, p.key);
    }
    if (!same_answer("SELECT id, c FROM le ORDER BY id", "SELECT id, c FROM pe ORDER BY id"))
        fine = false, fprintf(stderr, "    the ENUM twins differ\n");
    /* a label added later: AS OF the commit before it refuses it, literal and parameter alike */
    uint64_t before = db->seq;
    if (run("ALTER TYPE mood ADD VALUE 'new'", NULL, 0).rc) fine = false, fprintf(stderr, "    ADD VALUE: %s\n", be.msg);
    fine = fine && run("INSERT INTO le VALUES (5, 'new')", NULL, 0).rc == 0 && run("INSERT INTO pe VALUES (5, 'new')", NULL, 0).rc == 0;
    val nw = text("new");
    char a[128], b[128];
    snprintf(a, sizeof a, "SELECT id FROM le AS OF %llu WHERE c = 'new'", (unsigned long long)before);
    snprintf(b, sizeof b, "SELECT id FROM pe AS OF %llu WHERE c = $1", (unsigned long long)before);
    outcome al = run(a, NULL, 0), ap = run(b, &nw.v, 1);
    if (!al.rc || al.rc != ap.rc) fine = false, fprintf(stderr, "    AS OF below the label: %d, the parameter %d\n", al.rc, ap.rc);
    outcome cl = run("SELECT id FROM le WHERE c = 'new'", NULL, 0), cp = run("SELECT id FROM pe WHERE c = $1", &nw.v, 1);
    if (cl.rc || cp.rc || cl.n != 1 || cp.n != 1) fine = false, fprintf(stderr, "    the label now: %d, the parameter %d: %s\n", cl.rc, cp.rc, be.msg);
    /* in a tree a parameter keeps its type: TEXT against an ENUM refused, CAST its way */
    outcome tl = run("SELECT id FROM le WHERE (c = 'ok') = FALSE", NULL, 0);
    outcome tp = run("SELECT id FROM pe WHERE (c = $1) = FALSE", &ok.v, 1);
    outcome tc = run("SELECT id FROM pe WHERE (c = CAST($1 AS mood)) = FALSE", &ok.v, 1);
    if (tl.rc || !tp.rc || tc.rc || tl.n != tc.n)
        fine = false, fprintf(stderr, "    a tree: the literal %d, the parameter %d, CAST %d\n", tl.rc, tp.rc, tc.rc);
    /* a wire TEXT through conv: into the column and back as the column's ENUM label */
    imdbw_value w;
    memset(&w, 0, sizeof w);
    w.type = IMDBW_T_TEXT;
    w.s = (const uint8_t *)"sad", w.len = 3;
    imdb_value pv;
    imdb_err ce = {0};
    CHECK(imdbw_param_of(&w, &pv, &ce) == 0);
    outcome wi = run("INSERT INTO pe VALUES (7, $1)", &pv, 1);
    imdb_result r;
    imdb_err_clear(&be);
    if (wi.rc || imdb_exec_one(&g_s, "SELECT c FROM pe WHERE id = 7", 29, NULL, 0, &r, &be)) {
        fine = false, fprintf(stderr, "    a wire TEXT into the ENUM column: %d %s\n", wi.rc, be.msg);
    } else {
        imdbw_msg cols;
        imdbw_value back;
        memset(&cols, 0, sizeof cols);
        if (imdbw_columns_of(&r, &cols, &ce) || cols.cols[0].type != IMDBW_T_ENUM ||
            imdbw_value_of(&r, 0, 0, &cols.cols[0], &back, &ce) || back.type != IMDBW_T_ENUM || back.null || back.len != 3 ||
            memcmp(back.s, "sad", 3))
            fine = false, fprintf(stderr, "    the ENUM back through conv: %s\n", ce.msg);
        imdbw_msg_free(&cols);
        imdb_result_free(&r);
    }
    SOFT(fine);
    close_bind(db);
}

const test_case pbind_tests[] = {
    {"pbind_enum", t_bind_enum},
    {"pbind_malformed", t_bind_malformed},
    {"pbind_callers", t_bind_callers},
    {"pbind_nulls", t_bind_nulls},
    {"pbind_as_literal", t_bind_as_literal},
};
const size_t pbind_ntests = sizeof pbind_tests / sizeof *pbind_tests;
