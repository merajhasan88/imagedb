/* N1b: the engine's results into IMDBWIR1 frames and the wire's parameters into the engine's (server/conv.c). Every
 * statement of a corpus (every type at its edges and NULL, aggregates, a SUM past INT64 as an aggregate, a window and an
 * arm of a set operation, ENUM labels and an AS OF below a label, SHOW, EXPLAIN, writes' counts) runs through the engine;
 * its result goes into COLUMNS, ROWS frames cut small and DONE, which the codec's decoders take back, and every value
 * decoded is the engine's cell, compared here field by field (not through conv.c). */
#include <string.h>

#include "../../server/conv.h"
#include "../../src/codec.h"
#include "../../src/db.h"
#include "../../src/log.h"
#include "test.h"

static imdb_session g_s;
static imdb_err ce;

static imdb_db *open_fresh(void)
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

static void close_fresh(imdb_db *db)
{
    imdb_session_close(&g_s);
    imdb_close(db);
}

static int exec(const char *sql, const imdb_value *p, uint32_t np, imdb_result *r)
{
    imdb_err_clear(&ce);
    return imdb_exec_one(&g_s, sql, strlen(sql), p, np, r, &ce);
}

/* the wire value v is the engine's cell (row, col) of r under the decoded column c: compared field by field */
static bool cell_is(const imdb_result *r, uint64_t row, uint16_t col, const imdbw_col *c, const imdbw_value *v)
{
    const imdb_cell *cl = &r->cells[row * r->ncols + col];
    if (cl->null || cl->v.null) return v->null && v->type == (c->type ? c->type : imdbw_type_of_engine(cl->v.type));
    if (v->null) return false;
    switch (cl->v.type) {
    case IMDB_T_INT64:
        if (c->type == IMDBW_T_DECIMAL || (c->type == IMDBW_T_NONE && cl->wide)) /* a SUM's column, or a wide one of none */
            return v->type == IMDBW_T_DECIMAL && !v->scale && v->d == (cl->wide ? cl->i128 : cl->v.i);
        return v->type == IMDBW_T_INT64 && !cl->wide && v->i == cl->v.i;
    case IMDB_T_DECIMAL:
        return v->type == IMDBW_T_DECIMAL && v->scale == cl->v.scale && v->d == (cl->wide ? cl->i128 : imdb_dec_value(&cl->v));
    case IMDB_T_FLOAT64: {
        double d = imdb_f64_value(cl->v.i);
        uint64_t bits;
        memcpy(&bits, &d, 8);
        return v->type == IMDBW_T_FLOAT64 && v->f == bits;
    }
    case IMDB_T_BOOL: return v->type == IMDBW_T_BOOL && v->i == cl->v.i;
    case IMDB_T_TIMESTAMP: return v->type == IMDBW_T_TIMESTAMP && v->i == cl->v.i;
    case IMDB_T_TIMESTAMPTZ: return v->type == IMDBW_T_TIMESTAMPTZ && v->i == cl->v.i;
    case IMDB_T_TIME: return v->type == IMDBW_T_TIME && v->i == cl->v.i;
    case IMDB_T_DATE: return v->type == IMDBW_T_DATE && v->day == cl->v.i;
    case IMDB_T_TEXT:
    case IMDB_T_BYTEA:
    case IMDB_T_UUID:
        return v->type == imdbw_type_of_engine(cl->v.type) && v->len == cl->v.len && (!v->len || !memcmp(v->s, cl->v.s, v->len));
    case IMDB_T_INTERVAL:
        return v->type == IMDBW_T_INTERVAL && v->mon == cl->v.iv.mon && v->day == cl->v.iv.day && v->i == cl->v.i;
    case IMDB_T_ENUM: {
        const imdb_enumdef *d = r->clab[col];
        if (!d || cl->v.i < 0 || cl->v.i >= d->n) return false;
        uint32_t n = d->off[cl->v.i + 1] - d->off[cl->v.i];
        return v->type == IMDBW_T_ENUM && v->len == n && !memcmp(v->s, d->text + d->off[cl->v.i], n);
    }
    default: return false;
    }
}

/* r's frames: COLUMNS, ROWS cut at target bytes, DONE, each decoded by the codec and checked against r */
static bool frames_of(const imdb_result *r, size_t target, const char *sql)
{
    bool ok = true;
    imdbw_msg cols, dcols, d, dd;
    imdbw_buf b, cb; /* cb: the COLUMNS frame's bytes, kept while ROWS are decoded (a decoded message points into them) */
    imdbw_buf_init(&cb);
    imdbw_buf_init(&b);
    memset(&dcols, 0, sizeof dcols);
    if (r->ncols) {
        if (imdbw_columns_of(r, &cols, &ce)) {
            fprintf(stderr, "    %s: COLUMNS: %s\n", sql, ce.msg);
            imdbw_msg_free(&cols);
            imdbw_buf_free(&b);
            return false;
        }
        imdbw_msg_put(&cb, &cols, NULL);
        ok = !cb.err && imdbw_msg_get(IMDBW_COLUMNS, cb.p + IMDBW_HEAD, cb.len - IMDBW_HEAD, NULL, &dcols, &ce) == 0;
        if (!ok) fprintf(stderr, "    %s: COLUMNS not decoded: %s\n", sql, ce.msg);
        for (uint16_t i = 0; ok && i < r->ncols; i++) ok = dcols.cols[i].type == cols.cols[i].type;
        uint64_t next = 0, seen = 0;
        while (ok && next < r->nrows) {
            imdbw_buf_reset(&b);
            uint64_t from = next;
            if (imdbw_rows_of(r, &cols, &next, target, &b, &ce)) {
                fprintf(stderr, "    %s: ROWS: %s\n", sql, ce.msg);
                ok = false;
                break;
            }
            ok = next > from;
            for (size_t at = 0; ok && at < b.len;) { /* each frame in b: decoded against the decoded COLUMNS */
                uint32_t len;
                uint8_t type;
                imdbw_msg m;
                ok = at + IMDBW_HEAD <= b.len && imdbw_head_get(b.p + at, true, &len, &type, &ce) == 0 && type == IMDBW_ROWS &&
                     at + 4 + len <= b.len && imdbw_msg_get(type, b.p + at + IMDBW_HEAD, len - 1, &dcols, &m, &ce) == 0;
                if (!ok) {
                    fprintf(stderr, "    %s: a ROWS frame not decoded: %s\n", sql, ce.msg);
                    imdb_rd rd; /* which value: walked here, each against its column, the encoder's and the decoded */
                    imdb_rd_init(&rd, b.p + at + IMDBW_HEAD + 4, len - 5);
                    for (uint32_t k = 0; imdb_rd_left(&rd); k++) {
                        imdbw_value v;
                        if (imdbw_value_get(&rd, &v, &ce)) break;
                        uint16_t c = (uint16_t)(k % r->ncols);
                        if (!imdbw_value_fits(&dcols.cols[c], &v) || !imdbw_value_fits(&cols.cols[c], &v))
                            fprintf(stderr, "      value %u, column %u: wire type %u null %d len %u; column type %u precision %u "
                                    "scale %u (encoder's: type %u precision %u scale %u fits %d)\n", k, c + 1u, v.type, v.null,
                                    v.len, dcols.cols[c].type, dcols.cols[c].precision, dcols.cols[c].scale, cols.cols[c].type,
                                    cols.cols[c].precision, cols.cols[c].scale, imdbw_value_fits(&cols.cols[c], &v));
                    }
                    break;
                }
                imdb_rd rd;
                imdbw_value v;
                imdbw_span_begin(&m.vals, &rd);
                for (uint32_t k = 0; ok && k < m.nsets * (uint32_t)r->ncols; k++) {
                    ok = imdbw_span_next(&rd, &v) && cell_is(r, seen + k / r->ncols, (uint16_t)(k % r->ncols),
                                                             &dcols.cols[k % r->ncols], &v);
                    if (!ok) fprintf(stderr, "    %s: row %llu column %u differs\n", sql,
                                     (unsigned long long)(seen + k / r->ncols + 1), k % r->ncols + 1);
                }
                if (target == 1 && m.nsets != 1) { /* a frame cut at its first row past the target: one row each */
                    fprintf(stderr, "    %s: a frame of %u rows at a target of 1 byte\n", sql, m.nsets);
                    ok = false;
                }
                seen += m.nsets;
                imdbw_msg_free(&m);
                at += 4 + (size_t)len;
            }
        }
        ok = ok && seen == r->nrows;
        imdbw_msg_free(&cols);
    }
    imdbw_done_of(r, &d);
    imdbw_buf_reset(&b);
    imdbw_msg_put(&b, &d, NULL);
    bool dok = !b.err && imdbw_msg_get(IMDBW_DONE, b.p + IMDBW_HEAD, b.len - IMDBW_HEAD, NULL, &dd, &ce) == 0;
    if (dok) {
        dok = dd.count == (r->has_count ? r->count : r->nrows) && dd.has_read == r->has_snap &&
              (!dd.has_read || (dd.read_commit == r->snap && dd.lake_commit == r->lake_seq && dd.own == r->snap_own &&
                                !memcmp(dd.db_id, r->db_id, 16) && !memcmp(dd.read_hash, r->head, 32)));
        imdbw_msg_free(&dd);
    }
    if (!dok) fprintf(stderr, "    %s: DONE\n", sql);
    imdbw_msg_free(&dcols);
    imdbw_buf_free(&b);
    imdbw_buf_free(&cb);
    return ok && dok;
}

static void t_conv_types(void)
{
    for (uint8_t t = 1; t <= IMDB_T_LAST; t++) {
        uint8_t w = imdbw_type_of_engine(t);
        CHECK(w >= 1 && w <= IMDBW_T_LAST && imdbw_engine_type_of(w) == t);
    }
    CHECK(imdbw_type_of_engine(0) == IMDBW_T_NONE && imdbw_engine_type_of(IMDBW_T_NONE) == 0 && imdbw_type_of_engine(14) == 0);
}

static const char *const kSetup[] = {
    "CREATE TYPE mood AS ENUM ('sad', 'ok', 'happy')",
    "CREATE TABLE a (id INT64 PRIMARY KEY, s SMALLINT, n INTEGER, d DECIMAL(10,2), w DECIMAL(38,6), f FLOAT64, b BOOL, "
    "t TEXT, v VARCHAR(5), ts TIMESTAMP, tz TIMESTAMPTZ, dt DATE, tm TIME, u UUID, bb BYTEA, iv INTERVAL, m mood)",
    "INSERT INTO a VALUES (1, 32767, 2147483647, 99999999.99, 99999999999999999999999999999999.999999, 1.5e0, TRUE, "
    "'h\xc3\xa9', 'abcde', TIMESTAMP '0001-01-01 00:00:00', TIMESTAMPTZ '9999-12-31 23:59:59.999999+00', DATE '0001-01-01', "
    "TIME '23:59:59.999999', UUID 'ffffffff-ffff-ffff-ffff-ffffffffffff', '\\x00ff', INTERVAL '1 day', 'happy')",
    "INSERT INTO a VALUES (2, -32768, -2147483648, -99999999.99, -99999999999999999999999999999999.999999, -2.5e300, FALSE, "
    "'', '', TIMESTAMP '9999-12-31 23:59:59.999999', TIMESTAMPTZ '0001-01-01 00:00:00+00', DATE '9999-12-31', "
    "TIME '00:00:00', UUID '00000000-0000-0000-0000-000000000000', '\\x', INTERVAL '-3 months', 'sad')",
    "INSERT INTO a (id) VALUES (3)",
    "CREATE TABLE big (id INT64 PRIMARY KEY, x INT64)",
    "INSERT INTO big VALUES (1, 9223372036854775807), (2, 9223372036854775807), (3, 5)",
};

static const char *const kCorpus[] = {
    "SELECT * FROM a",
    "SELECT * FROM a ORDER BY id DESC",
    "SELECT id, s + 1, n - 1, d * 2, w + 0, f * 2.0e0, NOT b, t || 'x', v, ts, tz, dt, tm, u, bb, iv, m FROM a",
    "SELECT COUNT(*), SUM(s), SUM(n), SUM(d), SUM(w), AVG(d), MIN(t), MAX(t), MIN(ts), MAX(tz), MIN(dt), MAX(tm) FROM a",
    "SELECT MIN(m), MAX(m), MIN(u), MAX(bb), MIN(iv), MAX(iv), MIN(f), MAX(f) FROM a",
    "SELECT SUM(x) FROM big",
    "SELECT SUM(x) FROM big WHERE id = 3",
    "SELECT SUM(x) FROM big WHERE id > 100",
    "SELECT id, SUM(x) FROM big GROUP BY id",
    "SELECT SUM(x) OVER () FROM big",
    "SELECT id, SUM(x) OVER (ORDER BY id) FROM big",
    "SELECT SUM(x) FROM big UNION ALL SELECT 1",
    "SELECT 1 UNION ALL SELECT SUM(x) FROM big",
    "SELECT SUM(x) / 2 FROM big WHERE id <= 2",
    "SELECT SUM(p.x) FROM big AS p JOIN big AS q ON p.id = q.id",
    "SELECT SUM(p.x) FROM big AS p JOIN big AS q ON p.id = q.id WHERE p.id = 3",
    "SELECT p.id, SUM(q.x) FROM big AS p JOIN big AS q ON p.id = q.id GROUP BY p.id",
    "SELECT SUM(DISTINCT x) FROM big",
    "SELECT SUM(DISTINCT x) FROM big WHERE id = 3",
    "SELECT SUM(x) FILTER (WHERE id < 3) FROM big",
    "SELECT SUM(x) FILTER (WHERE id = 3) FROM big",
    "SELECT id, x, SUM(x) FROM big GROUP BY id, x",
    "SELECT id + 1, SUM(x) FROM big GROUP BY id + 1",
    "SELECT SUM(x) FROM big WHERE id < 3 HAVING SUM(x) > 0",
    "SELECT SUM(l.d), SUM(r2.w) FROM a AS l JOIN a AS r2 ON l.id = r2.id",
    "SELECT 1",
    "SELECT NULL",
    "SELECT 1.5",
    "SELECT 'x', TRUE, 2.5e0",
    "SELECT CAST(1 AS DECIMAL(5,2)), CAST('2026-11-16' AS DATE)",
    "SELECT m, COUNT(*) FROM a GROUP BY m",
    "SELECT id FROM a WHERE m = 'ok'",
    "SELECT id, m FROM a WHERE m >= 'ok'",
    "SELECT id FROM a WHERE iv > INTERVAL '0 days'",
    "SELECT DISTINCT b FROM a",
    "SELECT id, ROW_NUMBER() OVER (ORDER BY id) FROM a",
    "WITH c AS (SELECT id, t FROM a) SELECT * FROM c",
    "SELECT * FROM (SELECT id, d FROM a) q WHERE d > 0",
    "SELECT x.id, y.id FROM a AS x JOIN a AS y ON x.id = y.id",
    "SELECT id, CASE WHEN b THEN 'y' ELSE 'n' END FROM a",
    "SELECT d FROM a UNION SELECT 1",
    "SELECT d FROM a UNION ALL SELECT 2.5",
    "SHOW TABLES",
    "SHOW STATS",
    "SHOW IDENTITY",
    "SHOW HISTORY a (1)",
    "SHOW HISTORY a (2)",
    "SHOW HISTORY a (3)",
    "SHOW HISTORY big (1)",
    "SHOW DIGEST",
    "SHOW LAKE",
    "SHOW INDEXES",
    "SHOW VIEWS",
    "SHOW ROLES",
    "SHOW GRANTS",
    "SHOW PREPARED",
    "SHOW TRANSACTIONS",
    "SHOW MEMORY",
    "SHOW REPLICAS",
    "SHOW ERASURE",
    "SHOW TIME ZONE",
    "EXPLAIN SELECT * FROM a WHERE id = 1",
    "INSERT INTO a (id, t) VALUES (10, 'r'), (11, 's') RETURNING id, t",
    "UPDATE a SET t = 'y' WHERE id >= 10",
    "DELETE FROM a WHERE id = 11",
    "SELECT * FROM a WHERE id = 10",
    "BEGIN",
    "INSERT INTO a (id) VALUES (12)",
    "SELECT id FROM a WHERE id >= 10",
    "ROLLBACK",
    "CREATE TABLE z (k INT64 PRIMARY KEY)",
};

static void t_conv_results(void)
{
    int64_t live = imdbw_live_blocks();
    imdb_db *db = open_fresh();
    CHECK(db);
    imdb_result r;
    bool fine = true;
    for (size_t i = 0; i < sizeof kSetup / sizeof *kSetup; i++) {
        if (exec(kSetup[i], NULL, 0, &r)) fprintf(stderr, "    setup %zu: %s\n", i, ce.msg), fine = false;
        imdb_result_free(&r);
    }
    SOFT(fine);
    int ran = 0;
    for (size_t i = 0; fine && i < sizeof kCorpus / sizeof *kCorpus; i++) {
        if (exec(kCorpus[i], NULL, 0, &r)) {
            fprintf(stderr, "    %s: %s\n", kCorpus[i], ce.msg);
            fine = false;
        } else {
            for (size_t target = 1; target <= 1u << 20 && fine; target <<= 10)
                if (!(fine = frames_of(&r, target, kCorpus[i]))) fprintf(stderr, "    %s: frames at a target of %zu\n", kCorpus[i], target);
            ran++;
        }
        imdb_result_free(&r);
    }
    SOFT(fine && ran == (int)(sizeof kCorpus / sizeof *kCorpus));
    /* a SUM past INT64's range is a DECIMAL column; a narrow one too (the statement's type, not its cells') */
    for (int k = 0; fine && k < 3; k++) {
        static const char *const q[] = {"SELECT SUM(x) FROM big", "SELECT SUM(x) FROM big WHERE id = 3",
                                        "SELECT SUM(x) FROM big WHERE id > 100"};
        imdbw_msg cols;
        SOFT(exec(q[k], NULL, 0, &r) == 0 && r.cwide[0] && imdbw_columns_of(&r, &cols, &ce) == 0 &&
             cols.cols[0].type == IMDBW_T_DECIMAL && cols.cols[0].scale == 0);
        imdbw_msg_free(&cols);
        imdb_result_free(&r);
    }
    /* an AS OF below a label's ADD VALUE: the labels the read point sees */
    uint64_t before = db->seq;
    if (exec("ALTER TYPE mood ADD VALUE 'new'", NULL, 0, &r)) fine = false;
    imdb_result_free(&r);
    char asof[128];
    snprintf(asof, sizeof asof, "SELECT id, m FROM a AS OF %llu", (unsigned long long)before);
    if (fine && !exec(asof, NULL, 0, &r)) {
        imdbw_msg cols;
        int crc = imdbw_columns_of(&r, &cols, &ce);
        SOFT(crc == 0 && cols.cols[1].nlabels == 3 && frames_of(&r, 64, asof));
        imdbw_msg_free(&cols);
    } else
        fine = false;
    imdb_result_free(&r);
    if (fine && !exec("SELECT id, m FROM a", NULL, 0, &r)) {
        imdbw_msg cols;
        SOFT(imdbw_columns_of(&r, &cols, &ce) == 0 && cols.cols[1].nlabels == 4);
        imdbw_msg_free(&cols);
    } else
        fine = false;
    imdb_result_free(&r);
    SOFT(fine);
    close_fresh(db);
    CHECK(imdbw_live_blocks() == live);
}

/* every wire value as a parameter: SELECT $1 gives it back, through the engine and the conversion, the same bytes */
static void t_conv_params(void)
{
    int64_t live = imdbw_live_blocks();
    imdb_db *db = open_fresh();
    CHECK(db);
    static const uint8_t uu[16] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
    const imdbw_value ps[] = {
        {.type = IMDBW_T_INT64, .i = INT64_MIN},
        {.type = IMDBW_T_INT64, .i = INT64_MAX},
        {.type = IMDBW_T_FLOAT64, .f = 0x3ff8000000000000ull},
        {.type = IMDBW_T_FLOAT64, .f = 0xbff8000000000000ull}, /* -1.5: a negative double's key is not its bits */
        {.type = IMDBW_T_BOOL, .i = 1},
        {.type = IMDBW_T_TEXT, .s = (const uint8_t *)"h\xc3\xa9", .len = 3},
        {.type = IMDBW_T_TEXT, .s = (const uint8_t *)"", .len = 0},
        {.type = IMDBW_T_DECIMAL, .scale = 2, .d = -12345},
        {.type = IMDBW_T_DECIMAL, .scale = 6, .d = (__int128)INT64_MAX * 1000},
        {.type = IMDBW_T_TIMESTAMP, .i = -62135596800000000LL},
        {.type = IMDBW_T_TIMESTAMPTZ, .i = 253402300799999999LL},
        {.type = IMDBW_T_DATE, .day = 2932896},
        {.type = IMDBW_T_TIME, .i = 86399999999},
        {.type = IMDBW_T_UUID, .s = uu, .len = 16},
        {.type = IMDBW_T_BYTEA, .s = (const uint8_t *)"\x00\xff", .len = 2},
        {.type = IMDBW_T_INTERVAL, .mon = -3, .day = 7, .i = 11},
        {.null = true, .type = IMDBW_T_INT64},
        {.null = true, .type = IMDBW_T_TEXT},
    };
    for (size_t k = 0; k < sizeof ps / sizeof *ps; k++) {
        imdb_value pv;
        CHECK_OK(imdbw_param_of(&ps[k], &pv, &ce));
        imdb_result r;
        int rc = exec("SELECT $1", &pv, 1, &r);
        imdbw_msg cols;
        imdbw_value v;
        bool ok = rc == 0 && r.nrows == 1 && imdbw_columns_of(&r, &cols, &ce) == 0 &&
                  imdbw_value_of(&r, 0, 0, &cols.cols[0], &v, &ce) == 0 && imdbw_value_eq(&v, &ps[k]);
        if (!ok) fprintf(stderr, "    parameter %zu (wire type %u): %d %s\n", k, ps[k].type, rc, ce.msg);
        if (rc == 0) imdbw_msg_free(&cols);
        imdb_result_free(&r);
        SOFT(ok);
    }
    /* an ENUM's label, a NULL of no type: not yet bound by the engine (N1b's rule), refused */
    imdb_value pv;
    imdbw_value lab = {.type = IMDBW_T_ENUM, .s = (const uint8_t *)"ok", .len = 2};
    CHECK(imdbw_param_of(&lab, &pv, &ce) == IMDB_ERR_UNSUPPORTED);
    imdbw_value none = {.null = true};
    CHECK_OK(imdbw_param_of(&none, &pv, &ce));
    imdb_result r;
    CHECK(exec("SELECT $1", &pv, 1, &r) != 0);
    imdb_result_free(&r);
    close_fresh(db);
    CHECK(imdbw_live_blocks() == live);
}

/* COPY's stream, from memory: FROM STDIN reads src, TO STDOUT writes nowhere */
typedef struct copy_src {
    const char *p;
    size_t n, at;
} copy_src;

static long copy_rd(void *arg, char *buf, size_t cap)
{
    copy_src *s = arg;
    size_t k = s->n - s->at < cap ? s->n - s->at : cap;
    memcpy(buf, s->p + s->at, k);
    s->at += k;
    return (long)k;
}

static int copy_wr(void *arg, const char *buf, size_t len)
{
    (void)arg, (void)buf, (void)len;
    return 0;
}

/* DONE's count is the engine's: each write's rows (its status's number), a SELECT's rows held, a statement without rows
 * none; asked of the engine itself here, not of the conversion (which reads the field) */
static void t_conv_counts(void)
{
    imdb_db *db = open_fresh();
    CHECK(db);
    static const struct {
        const char *sql;
        bool has;
        uint64_t count, nrows;
    } q[] = {
        {"CREATE TABLE c (id INT64 PRIMARY KEY, v INT64)", false, 0, 0},
        {"INSERT INTO c VALUES (1, 1), (2, 2), (3, 3)", true, 3, 0},
        {"INSERT INTO c SELECT id + 10, v FROM c", true, 3, 0},
        {"INSERT INTO c VALUES (20, 0) RETURNING id", true, 1, 1},
        {"UPDATE c SET v = v + 1 WHERE id < 10", true, 3, 0},
        {"UPDATE c SET v = 0 WHERE id > 100", true, 0, 0},
        {"DELETE FROM c WHERE id >= 10", true, 4, 0},
        {"INSERT INTO c VALUES (1, 9) ON CONFLICT (id) DO NOTHING", true, 0, 0},
        {"SELECT * FROM c", false, 0, 3},
        {"SELECT * FROM c WHERE id > 100", false, 0, 0},
        {"CREATE TABLE u (tid INT64 PRIMARY KEY, w INT64)", false, 0, 0},
        {"INSERT INTO u VALUES (1, 10), (2, 20), (9, 90)", true, 3, 0},
        {"UPDATE c SET v = u.w FROM u WHERE u.tid = c.id", true, 2, 0},
        {"DELETE FROM c USING u WHERE u.tid = c.id AND u.w > 15", true, 1, 0},
        {"COPY c FROM STDIN", true, 2, 0},
        {"COPY c TO STDOUT", true, 4, 0},
        {"COPY (SELECT id FROM c WHERE id > 40) TO STDOUT", true, 2, 0},
    };
    static const char in[] = "41,1\n42,2\n";
    copy_src src = {in, sizeof in - 1, 0};
    imdb_session_copy_io(&g_s, copy_rd, copy_wr, &src);
    for (size_t k = 0; k < sizeof q / sizeof *q; k++) {
        imdb_result r;
        int rc = exec(q[k].sql, NULL, 0, &r);
        imdbw_msg d;
        imdbw_done_of(&r, &d);
        bool ok = rc == 0 && r.has_count == q[k].has && (!q[k].has || r.count == q[k].count) && r.nrows == q[k].nrows &&
                  d.count == (q[k].has ? q[k].count : q[k].nrows);
        if (!ok) fprintf(stderr, "    %s: rc %d, has_count %d count %llu nrows %llu (%s)\n", q[k].sql, rc, r.has_count,
                         (unsigned long long)r.count, (unsigned long long)r.nrows, ce.msg);
        imdb_result_free(&r);
        SOFT(ok);
    }
    close_fresh(db);
}

/* every allocation of a result's conversion failed in turn (COLUMNS with an ENUM's labels and index, ROWS into a buffer
 * that grows, DONE): out of memory each time, never another error, nothing of the wire's left */
static void t_conv_alloc(void)
{
    int64_t live = imdbw_live_blocks();
    imdb_db *db = open_fresh();
    CHECK(db);
    imdb_result r;
    static char ins[300 * 48 + 64];
    size_t o = (size_t)snprintf(ins, sizeof ins, "INSERT INTO f VALUES ");
    for (int g = 1; g <= 300; g++)
        o += (size_t)snprintf(ins + o, sizeof ins - o, "%s(%d, 'bb', 'text of a row', %d.25)", g > 1 ? ", " : "", g, g);
    const char *setup[] = {"CREATE TYPE e AS ENUM ('a', 'bb', 'ccc')",
                           "CREATE TABLE f (id INT64 PRIMARY KEY, m e, t TEXT, d DECIMAL(38,2))", ins};
    bool set = true;
    for (size_t i = 0; i < 3; i++) {
        int rc = exec(setup[i], NULL, 0, &r);
        if (rc) fprintf(stderr, "    setup %zu: %s\n", i, ce.msg), set = false;
        imdb_result_free(&r);
    }
    int rc0 = set ? exec("SELECT * FROM f", NULL, 0, &r) : -1;
    if (!set || rc0 || r.nrows != 300) {
        if (!rc0) imdb_result_free(&r);
        close_fresh(db);
        CHECK(false);
    }
    int failures = 0;
    for (int64_t at = 1;; at++) {
        imdbw_msg cols;
        imdbw_buf b;
        imdbw_buf_init(&b);
        imdbw_alloc_fail_at(at);
        int rc = imdbw_columns_of(&r, &cols, &ce);
        if (!rc) {
            imdbw_msg_put(&b, &cols, NULL);
            uint64_t next = 0;
            while (!rc && !b.err && next < r.nrows) {
                imdbw_buf_reset(&b);
                rc = imdbw_rows_of(&r, &cols, &next, 512, &b, &ce);
            }
            if (!rc && b.err) rc = b.nomem ? IMDB_ERR_NOMEM : IMDB_ERR_STATE;
        }
        imdbw_alloc_fail_at(0);
        imdbw_msg_free(&cols);
        imdbw_buf_free(&b);
        bool ok = imdbw_live_blocks() == live && (rc == 0 || rc == IMDB_ERR_NOMEM);
        if (!ok) fprintf(stderr, "    allocation %lld: rc %d (%s), live %lld\n", (long long)at, rc, ce.msg,
                         (long long)(imdbw_live_blocks() - live));
        CHECK(ok);
        if (rc == 0) break;
        failures++;
    }
    CHECK(failures >= 3);
    imdb_result_free(&r);
    close_fresh(db);
    CHECK(imdbw_live_blocks() == live);
}

const test_case conv_tests[] = {
    {"conv_counts", t_conv_counts},
    {"conv_alloc", t_conv_alloc},
    {"conv_types", t_conv_types},
    {"conv_results", t_conv_results},
    {"conv_params", t_conv_params},
};
const size_t conv_ntests = sizeof conv_tests / sizeof *conv_tests;
