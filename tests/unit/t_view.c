/* P2 S7 (docs/plan-p2.md; design.md §5, Views): CREATE VIEW, DROP VIEW, SHOW VIEWS. A view is its query's text, logged
 * (op 20, its columns and the tables and views it names beside it), parsed again and run as a derived table in each
 * statement that names it. A differential (each view answers as `(its query) AS name` does, live, cross-checked, from the
 * lake, after a replaying open and a snapshot open); every refusal; RESTRICT both ways, names freed by a drop; a
 * transaction older than a CREATE or a DROP; a replica; prepared statements across DDL; EXPLAIN; the dump's round trip;
 * the definition's codec, strict; the limits; the writer's re-bind of what an API caller hands it. */
#include <stdlib.h>

#include "../../src/backup.h"
#include "../../src/db.h"
#include "../../src/log.h"
#include "../../src/sql.h"
#include "thelp.h"

static imdb_session g_s;
static char g_out[1 << 16], g_out2[1 << 16];

static const char *csv_to(imdb_session *s, const char *sql, char *out, size_t cap)
{
    imdb_result r;
    imdb_err_clear(&g_e);
    if (imdb_exec_one(s, sql, strlen(sql), NULL, 0, &r, &g_e)) {
        snprintf(out, cap, "ERR %s", g_e.msg);
        return out;
    }
    imdb_buf b;
    imdb_buf_init(&b);
    if (r.has_rows) imdb_result_render(&r, true, &b);
    else imdb_buf_put_str(&b, r.status);
    if (imdb_buf_check(&b, &g_e)) snprintf(out, cap, "ERR render");
    else snprintf(out, cap, "%.*s", (int)b.len, (const char *)b.p);
    imdb_buf_free(&b);
    imdb_result_free(&r);
    return out;
}

static int run_s(imdb_session *s, const char *sql)
{
    imdb_result r;
    imdb_err_clear(&g_e);
    int rc = imdb_exec_one(s, sql, strlen(sql), NULL, 0, &r, &g_e);
    if (!rc) imdb_result_free(&r);
    return rc;
}
static int run(const char *sql) { return run_s(&g_s, sql); }

typedef struct vsrc { /* a COPY's data, read from memory */
    const char *p;
    size_t n, at;
} vsrc;
static vsrc g_src;

static long src_read(void *arg, char *buf, size_t cap)
{
    vsrc *s = arg;
    size_t k = s->n - s->at;
    if (k > cap) k = cap;
    if (k) memcpy(buf, s->p + s->at, k);
    s->at += k;
    return (long)k;
}

static int discard(void *arg, const char *b, size_t n)
{
    (void)arg;
    (void)b;
    (void)n;
    return 0;
}

/* a statement refused, its message holding want */
static void refused(const char *sql, const char *want, int line)
{
    int rc = run(sql);
    if (rc == IMDB_OK || !strstr(g_e.msg, want)) {
        char m[900];
        snprintf(m, sizeof m, "%s\n      want a refusal holding: %s\n      got: %s", sql, want, rc ? g_e.msg : "(accepted)");
        test_fail(__FILE__, line, m);
    }
}
#define REFUSED(sql, want) refused((sql), (want), __LINE__)

static imdb_db *dopen(const char *dir, bool full)
{
    imdb_open_opts o = {.sync = 0, .full_replay = full};
    imdb_db *db = NULL;
    imdb_err_clear(&g_e);
    return imdb_open(dir, &o, &db, &g_e) ? NULL : db;
}

static imdb_db *open_fresh(const char **dirp)
{
    const char *dir = test_tmpdir();
    imdb_err e = {0};
    if (imdb_init(dir, false, NULL, &e)) return NULL;
    imdb_db *db = dopen(dir, false);
    if (db) imdb_session_init(&g_s, db);
    if (dirp) *dirp = dir;
    return db;
}

static void done(imdb_db *db)
{
    imdb_session_close(&g_s);
    imdb_close(db);
}

static int audit_ok(const char *dir) /* 1: no auditor in this build (IMDB_AUDIT_BIN) */
{
    const char *bin = getenv("IMDB_AUDIT_BIN");
    if (!bin || !*bin) return 1;
    char cmd[1600];
    snprintf(cmd, sizeof cmd, "'%s' verify '%s' >/dev/null 2>&1", bin, dir);
    return system(cmd) == 0;
}

static int verify_db(imdb_db *db)
{
    imdb_verify_report vr;
    memset(&vr, 0, sizeof vr);
    imdb_err_clear(&g_e);
    return imdb_verify(db, &vr, &g_e);
}

static void fill(void)
{
    CHECK(run("CREATE TABLE t (id INT64 PRIMARY KEY, g INT64, d DECIMAL(9,2), s TEXT, k BOOL)") == 0);
    CHECK(run("CREATE TABLE u (id INT64 PRIMARY KEY, tid INT64, w TEXT)") == 0);
    imdb_buf b;
    imdb_buf_init(&b);
    imdb_buf_put_str(&b, "INSERT INTO t VALUES ");
    for (int i = 1; i <= 300; i++)
        imdb_buf_printf(&b, "%s(%d, %s, %d.%02d, %s, %s)", i > 1 ? ", " : "", i, i % 9 ? (i % 7 == 0 ? "NULL" : "1") : "2",
                        i % 50, i % 100, i % 11 ? (i % 2 ? "'ab'" : "'Cd'") : "NULL", i % 3 ? "TRUE" : "FALSE");
    imdb_buf_put_u8(&b, 0);
    CHECK(!imdb_buf_check(&b, &g_e) && !run((const char *)b.p));
    b.len = 0;
    imdb_buf_put_str(&b, "INSERT INTO u VALUES ");
    for (int i = 1; i <= 80; i++)
        imdb_buf_printf(&b, "%s(%d, %d, %s)", i > 1 ? ", " : "", i, (i * 7) % 320, i % 5 ? "'w'" : "NULL");
    imdb_buf_put_u8(&b, 0);
    CHECK(!imdb_buf_check(&b, &g_e) && !run((const char *)b.p));
    imdb_buf_free(&b);
}

/* each view's body; the view vN is created with list[N] as its column list where one is given */
static const char *const g_body[] = {
    "SELECT id, g, d FROM t WHERE d > 20 AND s = 'ab'",
    "SELECT g, COUNT(*) AS n, SUM(d) AS sd, MIN(s) AS ms FROM t GROUP BY g",
    "SELECT DISTINCT g, k FROM t",
    "SELECT id, ROW_NUMBER() OVER (ORDER BY d DESC, id) AS rn FROM t",
    "SELECT t.id, u.w FROM t JOIN u ON t.id = u.tid",
    "SELECT t.id, u.w FROM t LEFT JOIN u ON t.id = u.tid WHERE t.id < 50",
    "WITH c AS (SELECT id, g FROM t WHERE g IS NOT NULL) SELECT id, g FROM c WHERE id > 10",
    "SELECT id FROM t WHERE g = 2 UNION SELECT tid FROM u",
    "SELECT id FROM t WHERE id IN (SELECT tid FROM u)",
    "SELECT id FROM t WHERE EXISTS (SELECT 1 FROM u WHERE u.tid = t.id)",
    "SELECT q.id, q.d FROM (SELECT id, d FROM t WHERE k) AS q",
    "SELECT id, d * 2 FROM t WHERE id BETWEEN 50 AND 90",
    "SELECT id, g FROM v0 WHERE g IS NOT NULL", /* a view on a view */
};
static const char *const g_list[] = {NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, "(x)", NULL, NULL, "(id, dd)", NULL};
#define NBODY (sizeof g_body / sizeof *g_body)

/* every view answers as its body as a derived table does, row for row (one execution: the order too) */
static void compare_all(imdb_session *s, const char *when)
{
    for (size_t i = 0; i < NBODY; i++) {
        char a[700], b[900];
        for (int ord = 0; ord < 2; ord++) {
            snprintf(a, sizeof a, "SELECT * FROM v%zu%s", i, ord ? " ORDER BY 1" : "");
            if (i == 12) /* v0's body inlined in its own place */
                snprintf(b, sizeof b, "SELECT * FROM (SELECT id, g FROM (%s) AS v0 WHERE g IS NOT NULL) AS v%zu%s", g_body[0], i,
                         ord ? " ORDER BY 1" : "");
            else if (!strncmp(g_body[i], "WITH", 4)) /* a derived table holds no WITH: the body itself, its rows in order */
                snprintf(b, sizeof b, "%s%s", g_body[i], ord ? " ORDER BY 1" : "");
            else if (g_list[i]) /* a column list: the body's columns renamed as a WITH's list renames them */
                snprintf(b, sizeof b, "WITH v%zu %s AS (%s) SELECT * FROM v%zu%s", i, g_list[i], g_body[i], i,
                         ord ? " ORDER BY 1" : "");
            else snprintf(b, sizeof b, "SELECT * FROM (%s) AS v%zu%s", g_body[i], i, ord ? " ORDER BY 1" : "");
            csv_to(s, a, g_out, sizeof g_out);
            csv_to(s, b, g_out2, sizeof g_out2);
            if (!strncmp(g_out, "ERR", 3) || strcmp(strchr(g_out, '\n') ? strchr(g_out, '\n') : g_out,
                                                    strchr(g_out2, '\n') ? strchr(g_out2, '\n') : g_out2)) {
                char m[900];
                snprintf(m, sizeof m, "%s (%s)\n      view:    %.250s\n      inlined: %.250s", a, when, g_out, g_out2);
                test_fail(__FILE__, __LINE__, m);
            }
        }
    }
}

static void t_view_differential(void)
{
    const char *dir;
    imdb_db *db = open_fresh(&dir);
    CHECK(db);
    if (!db) return;
    fill();
    for (size_t i = 0; i < NBODY; i++) {
        char q[800];
        snprintf(q, sizeof q, "CREATE VIEW v%zu %s AS %s", i, g_list[i] ? g_list[i] : "", g_body[i]);
        if (run(q)) {
            char m[900];
            snprintf(m, sizeof m, "%s: %s", q, g_e.msg);
            test_fail(__FILE__, __LINE__, m);
        }
    }
    CHECK(db->nviews == NBODY);
    char views[1 << 13];
    snprintf(views, sizeof views, "%s", csv_to(&g_s, "SHOW VIEWS", g_out, sizeof g_out));
    compare_all(&g_s, "live");
    CHECK(run("SET cross_check = on") == 0);
    compare_all(&g_s, "cross-checked");
    CHECK(run("SET cross_check = off") == 0);
    CHECK(run("CHECKPOINT") == 0); /* the manifest carries every view; the rows in the lake */
    CHECK(run("UPDATE t SET g = 2 WHERE id < 20") == 0 && run("DELETE FROM u WHERE id > 70") == 0);
    compare_all(&g_s, "after a checkpoint");
    uint8_t tok[32], tok2[32];
    OK(imdb_view_token(db, tok, &g_e));
    OK(verify_db(db));
    done(db);
    CHECK(audit_ok(dir));
    for (int full = 0; full < 2; full++) { /* the views from the log alone, and from the manifest and the tail */
        db = dopen(dir, full);
        CHECK(db);
        if (!db) return;
        imdb_session_init(&g_s, db);
        CHECK(!strcmp(csv_to(&g_s, "SHOW VIEWS", g_out, sizeof g_out), views));
        OK(imdb_view_token(db, tok2, &g_e));
        CHECK(!memcmp(tok, tok2, 32));
        compare_all(&g_s, full ? "after a full replay" : "after a snapshot open");
        OK(verify_db(db));
        done(db);
    }
}

static void t_view_refusals(void)
{
    imdb_db *db = open_fresh(NULL);
    CHECK(db);
    if (!db) return;
    fill();
    CHECK(run("CREATE VIEW v AS SELECT id, g FROM t") == 0);
    REFUSED("CREATE VIEW w AS SELECT * FROM t", "write them instead of *");
    REFUSED("CREATE VIEW w AS SELECT id FROM (SELECT * FROM t) AS q", "write them instead of *");
    CHECK(run("CREATE VIEW w0 AS SELECT id FROM t WHERE EXISTS (SELECT * FROM u WHERE u.tid = t.id)") == 0); /* EXISTS' own */
    REFUSED("CREATE VIEW w AS SELECT g + 1 FROM t", "is an expression: name it");
    REFUSED("CREATE VIEW w AS SELECT COUNT(*) FROM t", "is an expression: name it");
    CHECK(run("CREATE VIEW w1 (n) AS SELECT COUNT(*) FROM t") == 0); /* a column list names it */
    REFUSED("CREATE VIEW w (a, b) AS SELECT id FROM t", "names 2 columns, its query yields 1");
    REFUSED("CREATE VIEW w (a, a) AS SELECT id, g FROM t", "names two columns a");
    REFUSED("CREATE VIEW w AS SELECT id, id FROM t", "names two columns id");
    REFUSED("CREATE VIEW w AS SELECT id FROM t FOR UPDATE", "FOR UPDATE");
    REFUSED("CREATE VIEW w AS SELECT id FROM t AS OF 3", "AS OF in a view's query");
    REFUSED("CREATE VIEW w AS SELECT id FROM t WHERE id = $1", "takes no parameter");
    REFUSED("CREATE OR REPLACE VIEW v AS SELECT id FROM t", "CREATE OR REPLACE");
    REFUSED("CREATE VIEW t AS SELECT id FROM u", "table t exists already");
    REFUSED("CREATE VIEW v AS SELECT id FROM u", "view v exists already");
    REFUSED("CREATE TABLE v (id INT64 PRIMARY KEY)", "view v exists already");
    REFUSED("CREATE VIEW w AS SELECT id FROM nosuch", "no table nosuch");
    CHECK(run("CREATE VIEW w2 AS SELECT NULL AS x FROM t") == 0); /* typed as a derived table types it */
    imdb_session_copy_io(&g_s, src_read, discard, &g_src); /* COPY's refusals past the stream's own */
    REFUSED("INSERT INTO v VALUES (1, 2)", "v is a view");
    REFUSED("UPDATE v SET g = 1", "v is a view");
    REFUSED("DELETE FROM v WHERE id = 1", "v is a view");
    REFUSED("COPY v FROM STDIN", "v is a view");
    REFUSED("COPY v TO STDOUT", "COPY of view v");
    REFUSED("UPDATE t SET g = 1 FROM v WHERE t.id = v.id", "a view: a later step");
    REFUSED("SELECT id FROM v AS OF 3", "AS OF with a view");
    REFUSED("DROP VIEW nosuch", "no view nosuch");
    REFUSED("DROP VIEW t", "no view t");
    REFUSED("DROP TABLE v", "no table v");
    CHECK(run("BEGIN") == 0);
    REFUSED("CREATE VIEW w AS SELECT id FROM t", "CREATE VIEW commits on its own");
    REFUSED("DROP VIEW v", "DROP VIEW commits on its own");
    CHECK(run("ROLLBACK") == 0);
    CHECK(db->nviews == 4); /* v, w0, w1, w2: no refusal left a view behind */
    done(db);
}

/* RESTRICT both ways (PostgreSQL's), each name free once its holder is dropped, a name reused never capturing an old view */
static void t_view_deps(void)
{
    imdb_db *db = open_fresh(NULL);
    CHECK(db);
    if (!db) return;
    fill();
    CHECK(run("CREATE VIEW a AS SELECT id, g FROM t WHERE id IN (SELECT tid FROM u)") == 0);
    CHECK(run("CREATE VIEW b AS SELECT id FROM a WHERE g = 1") == 0);
    const imdb_view *va = imdb_view_by_name(db, "a"), *vb = imdb_view_by_name(db, "b");
    CHECK(va && vb && va->def->ndeps == 2 && va->def->deps[0].kind == IMDB_VIEWDEP_TABLE &&
          va->def->deps[1].kind == IMDB_VIEWDEP_TABLE && vb->def->ndeps == 1 && vb->def->deps[0].kind == IMDB_VIEWDEP_VIEW);
    REFUSED("DROP TABLE u", "view a names table u: drop it first");
    REFUSED("DROP TABLE t", "view a names table t: drop it first");
    REFUSED("DROP VIEW a", "view b names view a: drop it first");
    CHECK(run("DROP VIEW b") == 0 && run("DROP VIEW a") == 0);
    CHECK(run("DROP TABLE u") == 0);
    CHECK(run("CREATE TABLE a (id INT64 PRIMARY KEY)") == 0); /* the view's name, free again, now a table's */
    CHECK(run("CREATE VIEW u AS SELECT id FROM t WHERE id < 3") == 0); /* the dropped table's name, now a view's */
    CHECK(!strcmp(csv_to(&g_s, "SELECT * FROM u", g_out, sizeof g_out), "id\n1\n2\n"));
    REFUSED("SELECT * FROM b", "no table b");
    CHECK(db->nviews == 3); /* a, b (tombstones) and u: ids are never reused */
    OK(verify_db(db));
    done(db);
}

/* a transaction older than a CREATE VIEW reads it as the live table answers (at the transaction's snapshot); one older
 * than a DROP VIEW still reads the view, though a new table now holds the name */
static void t_view_txn(void)
{
    imdb_db *db = open_fresh(NULL);
    CHECK(db);
    if (!db) return;
    fill();
    imdb_session s2;
    imdb_session_init(&s2, db);
    CHECK(run_s(&s2, "BEGIN ISOLATION LEVEL SNAPSHOT") == 0 && run_s(&s2, "SELECT COUNT(*) FROM t") == 0);
    CHECK(run("INSERT INTO t VALUES (1001, 1, 1.00, 'zz', TRUE)") == 0);
    CHECK(run("CREATE VIEW v (n) AS SELECT COUNT(*) FROM t") == 0);
    CHECK(!strcmp(csv_to(&s2, "SELECT n FROM v", g_out, sizeof g_out), "n\n300\n")); /* its snapshot's rows */
    CHECK(!strcmp(csv_to(&g_s, "SELECT n FROM v", g_out, sizeof g_out), "n\n301\n"));
    CHECK(run_s(&s2, "COMMIT") == 0);
    CHECK(run_s(&s2, "BEGIN ISOLATION LEVEL SNAPSHOT") == 0 && run_s(&s2, "SELECT n FROM v") == 0);
    CHECK(run("DROP VIEW v") == 0);
    CHECK(run("CREATE TABLE v (id INT64 PRIMARY KEY)") == 0);
    CHECK(!strcmp(csv_to(&s2, "SELECT n FROM v", g_out, sizeof g_out), "n\n301\n")); /* the view it saw */
    CHECK(!strcmp(csv_to(&g_s, "SELECT COUNT(*) AS c FROM v", g_out, sizeof g_out), "c\n0\n")); /* the table now */
    CHECK(run_s(&s2, "COMMIT") == 0);
    REFUSED("SELECT n FROM v", "no column n");
    imdb_session_close(&s2);
    OK(verify_db(db));
    done(db);
}

static void t_view_replica(void)
{
    const char *dir;
    imdb_db *db = open_fresh(&dir);
    CHECK(db);
    if (!db) return;
    fill();
    CHECK(run("CREATE VIEW v AS SELECT id, g FROM t WHERE g = 2") == 0);
    CHECK(run("CREATE VIEW w AS SELECT id FROM v WHERE id > 100") == 0);
    CHECK(run("CREATE VIEW gone AS SELECT id FROM u") == 0 && run("DROP VIEW gone") == 0);
    char rdir[700], f[760];
    snprintf(rdir, sizeof rdir, "%s-replica", dir);
    snprintf(f, sizeof f, "%s-stream", dir);
    imdb_identity id;
    OK(imdb_identity_read(dir, &id, NULL, &g_e));
    OK(imdb_init_replica(rdir, &id, &g_e));
    OK(ship_to_file(dir, 0, f, &g_e));
    imdb_db *rdb = dopen(rdir, false);
    CHECK(rdb);
    if (!rdb) {
        done(db);
        return;
    }
    uint64_t applied = 0;
    OK(apply_file(rdb, f, &applied, &g_e));
    uint8_t a[32], b[32];
    OK(imdb_view_token(db, a, &g_e));
    OK(imdb_view_token(rdb, b, &g_e));
    CHECK(rdb->seq == db->seq && !memcmp(a, b, 32) && rdb->nviews == 3);
    imdb_session rs;
    imdb_session_init(&rs, rdb);
    CHECK(!strcmp(csv_to(&rs, "SELECT * FROM w ORDER BY id", g_out, sizeof g_out),
                  csv_to(&g_s, "SELECT * FROM w ORDER BY id", g_out2, sizeof g_out2)));
    imdb_session_close(&rs);
    OK(verify_db(rdb));
    imdb_close(rdb);
    CHECK(audit_ok(rdir));
    done(db);
}

/* a prepared statement re-resolves its views at each run: DDL between two runs is what the second one sees */
static void t_view_prepared(void)
{
    imdb_db *db = open_fresh(NULL);
    CHECK(db);
    if (!db) return;
    fill();
    CHECK(run("CREATE VIEW v (n) AS SELECT COUNT(*) FROM t WHERE g = 2") == 0);
    CHECK(run("PREPARE p AS SELECT n FROM v") == 0);
    CHECK(!strcmp(csv_to(&g_s, "EXECUTE p", g_out, sizeof g_out), "n\n33\n"));
    CHECK(run("DROP VIEW v") == 0);
    REFUSED("EXECUTE p", "no table v");
    CHECK(run("CREATE VIEW v (n) AS SELECT COUNT(*) FROM u") == 0);
    CHECK(!strcmp(csv_to(&g_s, "EXECUTE p", g_out, sizeof g_out), "n\n80\n"));
    CHECK(strstr(csv_to(&g_s, "EXPLAIN SELECT n FROM v", g_out, sizeof g_out), "nested") != NULL);
    done(db);
}

/* a dump writes each live view after the tables, by id, its columns named; restored elsewhere, dumped again the same */
static int outb_write(void *arg, const char *b, size_t n)
{
    imdb_buf *o = arg;
    imdb_buf_put(o, b, n);
    return o->err ? -1 : 0;
}


/* a dump restored as imagedb sql -f restores it (in small: t_copy's): each line a statement, a comment line skipped,
 * a COPY's data the lines after it up to a \. line outside quotes */
static int restore(const char *s, size_t n)
{
    static char line[1 << 14];
    imdb_session_copy_io(&g_s, src_read, NULL, &g_src);
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
        g_src.p = s + at;
        g_src.n = k - at;
        g_src.at = 0;
        if (run(line)) return -1;
        at = k + 2 < n ? k + 3 : n;
    }
    return 0;
}

static void t_view_dump(void)
{
    imdb_db *db = open_fresh(NULL);
    CHECK(db);
    if (!db) return;
    fill();
    CHECK(run("CREATE VIEW v (x, y) AS SELECT id, g FROM t WHERE g = 2") == 0);
    CHECK(run("CREATE VIEW gone AS SELECT id FROM u") == 0 && run("DROP VIEW gone") == 0);
    CHECK(run("CREATE VIEW w AS SELECT x FROM v WHERE x > 100") == 0);
    imdb_buf d1, d2;
    imdb_buf_init(&d1);
    imdb_buf_init(&d2);
    OK(imdb_dump(db, 0, outb_write, &d1, &g_e));
    imdb_buf_put_u8(&d1, 0);
    const char *txt = (const char *)d1.p;
    const char *cv = strstr(txt, "\nCREATE VIEW v (x, y) AS SELECT id, g FROM t WHERE g = 2;\n");
    const char *cw = strstr(txt, "\nCREATE VIEW w (x) AS SELECT x FROM v WHERE x > 100;\n");
    CHECK(cv && cw && cv < cw && !strstr(txt, "gone") && strstr(txt, "-- the end of the dump: 2 tables, 2 views, 380 rows\n"));
    char want[1 << 12];
    snprintf(want, sizeof want, "%s", csv_to(&g_s, "SELECT * FROM w ORDER BY x", g_out, sizeof g_out));
    done(db);
    db = open_fresh(NULL);
    CHECK(db);
    if (!db) return;
    CHECK(restore(txt, d1.len - 1) == 0);
    CHECK(!strcmp(csv_to(&g_s, "SELECT * FROM w ORDER BY x", g_out, sizeof g_out), want));
    OK(imdb_dump(db, 0, outb_write, &d2, &g_e));
    imdb_buf_put_u8(&d2, 0);
    CHECK(!strcmp(strchr(txt, '\n'), strchr((const char *)d2.p, '\n')));
    imdb_buf_free(&d1);
    imdb_buf_free(&d2);
    done(db);
}

/* the definition's codec: a round trip, and each field broken refused */
static void t_view_codec(void)
{
    imdb_viewcol cols[2] = {{"a", IMDB_T_INT64, 0}, {"b", IMDB_T_DECIMAL, 2}};
    imdb_viewdep deps[2] = {{IMDB_VIEWDEP_TABLE, 3}, {IMDB_VIEWDEP_VIEW, 1}};
    char text[] = "SELECT a, b FROM t";
    imdb_viewdef d = {.id = 4, .name = "v", .ncols = 2, .ndeps = 2, .text_len = sizeof text - 1, .cols = cols, .deps = deps,
                      .text = text};
    OK(imdb_viewdef_check(&d, &g_e));
    imdb_buf b;
    imdb_buf_init(&b);
    imdb_viewdef_encode(&d, &b);
    OK(imdb_buf_check(&b, &g_e));
    imdb_rd r;
    imdb_rd_init(&r, b.p, b.len);
    imdb_viewdef *back = NULL;
    OK(imdb_viewdef_decode(&r, &back, &g_e));
    CHECK(back && !imdb_rd_left(&r) && back->id == 4 && !strcmp(back->name, "v") && back->ncols == 2 && back->ndeps == 2 &&
          back->cols[1].type == IMDB_T_DECIMAL && back->cols[1].scale == 2 && back->deps[1].id == 1 &&
          back->text_len == d.text_len && !memcmp(back->text, text, d.text_len));
    imdb_viewdef_free(back);
    struct {
        size_t at; /* the byte changed */
        uint8_t to;
    } bad[] = {
        /* the layout: u32 id (0-3), u8 1 and "v" (4, 5), u16 2 (6, 7), a: u8 1 "a" type scale (8-11), b: u8 1 "b"
         * type scale (12-15), u16 2 (16, 17), u8 kind u32 id (18-22, 23-27), u32 text length (28-31), the text */
        {4, 0},   /* a name of length 0 */
        {5, 'V'}, /* the name not folded */
        {6, 0},   /* no column (u16 2 -> 0) */
        {10, 9},  /* a column of an unknown type */
        {11, 1},  /* an INT64 with a scale */
        {15, 19}, /* a DECIMAL past 18 places */
        {13, 'a'}, /* two columns named a */
        {18, 3},  /* a dependency of an unknown kind */
        {24, 4},  /* a view's dependency on itself, not an earlier one */
        {18, 2},  /* the dependencies out of order: view 3, then view 1 */
        {16, 3},  /* three dependencies claimed: the text length read from the third's bytes */
    };
    for (size_t k = 0; k < sizeof bad / sizeof *bad; k++) {
        uint8_t w[256];
        CHECK(b.len <= sizeof w);
        memcpy(w, b.p, b.len);
        w[bad[k].at] = bad[k].to;
        imdb_rd_init(&r, w, b.len);
        imdb_viewdef *x = NULL;
        imdb_err_clear(&g_e);
        int rc = imdb_viewdef_decode(&r, &x, &g_e);
        if (rc != IMDB_ERR_CORRUPT || x) {
            char m[120];
            snprintf(m, sizeof m, "a definition with byte %zu changed to %u decoded", bad[k].at, bad[k].to);
            test_fail(__FILE__, __LINE__, m);
        }
        imdb_viewdef_free(x);
    }
    /* the text: empty, bad UTF-8, a NUL; and nothing may follow (a commit's decoder wants the op's end) */
    for (int k = 0; k < 3; k++) {
        imdb_viewdef dd = d;
        char t2[] = "SELECT \xff";
        char t3[] = "SELECT a\0b";
        dd.text = k == 0 ? text : k == 1 ? t2 : t3;
        dd.text_len = k == 0 ? 0 : k == 1 ? (uint32_t)(sizeof t2 - 1) : (uint32_t)(sizeof t3 - 1);
        CHECK(imdb_viewdef_check(&dd, &g_e) == IMDB_ERR_CORRUPT);
    }
    imdb_buf_free(&b);
}

static void t_view_limits(void)
{
    imdb_db *db = open_fresh(NULL);
    CHECK(db);
    if (!db) return;
    fill();
    CHECK(run("CREATE VIEW c0 AS SELECT id FROM t") == 0);
    for (unsigned i = 1; i <= IMDB_MAX_VIEW_DEPTH; i++) { /* a statement reading c3 expands c3, c2, c1, c0: four; c4 one more */
        char q[200];
        snprintf(q, sizeof q, "CREATE VIEW c%u AS SELECT id FROM c%u", i, i - 1);
        if (i < IMDB_MAX_VIEW_DEPTH) CHECK(run(q) == 0);
        else REFUSED(q, "views inside views deeper than");
    }
    CHECK(run("SELECT COUNT(*) FROM c3") == 0);
    CHECK(run("SELECT COUNT(*) FROM (SELECT id FROM c3) AS q") == 0); /* a derived table is no view's level */
    imdb_buf b; /* a query's text past the limit */
    imdb_buf_init(&b);
    imdb_buf_put_str(&b, "CREATE VIEW big AS SELECT id -- ");
    while (b.len < IMDB_MAX_VIEW_TEXT + 16) imdb_buf_put_str(&b, "a comment that grows the text ");
    imdb_buf_put_str(&b, "\nFROM t");
    imdb_buf_put_u8(&b, 0);
    OK(imdb_buf_check(&b, &g_e));
    REFUSED((const char *)b.p, "a view's query of more than");
    imdb_buf_free(&b);
    done(db);
}

/* what an API caller hands imdb_create_view is re-bound as replay will: columns or dependencies its text does not yield
 * never reach the log */
static void t_view_api_rebind(void)
{
    imdb_db *db = open_fresh(NULL);
    CHECK(db);
    if (!db) return;
    fill();
    for (int k = 0; k < 3; k++) {
        imdb_viewdef *d = imdb_alloc(sizeof *d, &g_e);
        CHECK(d);
        if (!d) break;
        snprintf(d->name, sizeof d->name, "lie%d", k);
        const char *txt = "SELECT id, g FROM t";
        d->text_len = (uint32_t)strlen(txt);
        d->text = imdb_alloc(d->text_len + 1, &g_e);
        d->ncols = k == 1 ? 1 : 2; /* 1: a column short */
        d->cols = imdb_alloc_array(2, sizeof *d->cols, &g_e);
        d->ndeps = k == 0 ? 0 : 1; /* 0: no dependency, though it reads t */
        d->deps = imdb_alloc_array(1, sizeof *d->deps, &g_e);
        memcpy(d->text, txt, d->text_len);
        snprintf(d->cols[0].name, sizeof d->cols[0].name, "id");
        snprintf(d->cols[1].name, sizeof d->cols[1].name, "g");
        d->cols[0].type = IMDB_T_INT64;
        d->cols[1].type = k == 2 ? IMDB_T_TEXT : IMDB_T_INT64; /* 2: a column of another type */
        d->deps[0].kind = IMDB_VIEWDEP_TABLE;
        d->deps[0].id = 0;
        OK(imdb_begin(db, &g_e));
        imdb_err_clear(&g_e);
        CHECK(imdb_create_view(db, d, &g_e) == IMDB_ERR_INVALID && strstr(g_e.msg, "not what its text yields"));
        imdb_rollback(db);
    }
    CHECK(db->nviews == 0);
    done(db);
}


/* the dependencies CREATE VIEW notes reach every table a lazy subquery names (P2 S11: run only when a row needs it,
 * typed by the probe all the same): a scalar item, a CASE branch, COALESCE, HAVING, a recursive step, ORDER BY */
static void t_view_lazy_deps(void)
{
    imdb_db *db = open_fresh(NULL);
    CHECK(db);
    if (!db) return;
    CHECK(run("CREATE TABLE t (id INT64 PRIMARY KEY, g INT64)") == 0 && run("CREATE TABLE u (id INT64 PRIMARY KEY, x INT64)") == 0);
    CHECK(run("INSERT INTO t VALUES (1, 1), (2, 2)") == 0 && run("INSERT INTO u VALUES (1, 10)") == 0);
    static const char *const v[] = {
        "CREATE VIEW s0 AS SELECT id, (SELECT MAX(x) FROM u) AS m FROM t",
        "CREATE VIEW s0 AS SELECT id, CASE WHEN g > 1 THEN (SELECT MIN(x) FROM u) ELSE 0 END AS c FROM t",
        "CREATE VIEW s0 AS SELECT id, COALESCE(g, (SELECT COUNT(*) FROM u)) AS c FROM t",
        "CREATE VIEW s0 AS SELECT g, COUNT(*) AS n FROM t GROUP BY g HAVING COUNT(*) > (SELECT COUNT(*) FROM u)",
        "CREATE VIEW s0 AS WITH RECURSIVE r (n) AS (SELECT 1 UNION ALL SELECT n + 1 FROM r WHERE n < (SELECT COUNT(*) FROM u) + 2) "
        "SELECT n FROM r",
        "CREATE VIEW s0 AS SELECT id FROM t ORDER BY (SELECT MAX(x) FROM u) LIMIT 1",
    };
    for (size_t i = 0; i < sizeof v / sizeof *v; i++) {
        CHECK(run(v[i]) == 0);
        REFUSED("DROP TABLE u RETENTION 1 DAY", "view s0 names table u");
        CHECK(run("DROP VIEW s0") == 0);
    }
    CHECK(run("DROP TABLE u RETENTION 1 DAY") == 0);
    done(db);
}

/* past a RETIRE's cut: VERIFY and the auditor seed their views from FLOOR's manifest (a live view, one on it, a
 * tombstone), a replica seeded from it has them, and a view made after the cut keeps its table from a drop */
static void t_view_retire(void)
{
    const char *dir;
    imdb_db *db = open_fresh(&dir);
    CHECK(db);
    if (!db) return;
    db->no_auto_retire = true;
    CHECK(run("CREATE TABLE a (id INT64 PRIMARY KEY, v INT64) RETENTION 10 SECONDS") == 0);
    CHECK(run("INSERT INTO a VALUES (1, 1), (2, 2), (3, 3)") == 0);
    CHECK(run("CREATE VIEW va AS SELECT id, v FROM a WHERE v > 1") == 0);
    CHECK(run("CREATE VIEW vb AS SELECT id FROM va") == 0);
    CHECK(run("CREATE VIEW gone AS SELECT id FROM a") == 0 && run("DROP VIEW gone") == 0);
    CHECK(run("UPDATE a SET v = 5 WHERE id = 1") == 0);
    CHECK(run("CHECKPOINT") == 0); /* the first segment ends */
    uint64_t first = db->seq + 1;
    CHECK(run("UPDATE a SET v = 6 WHERE id = 1") == 0);
    CHECK(run("CHECKPOINT") == 0);

    imdb_clock_offset(15 * 1000000ll);
    CHECK(run("SELECT COUNT(*) FROM a") == 0); /* the expiry policy: the horizon to the second segment's start */
    OK(imdb_retire(db, first - 1, &g_e));
    CHECK(db->nsegs && db->segs[0] >= first); /* the cut: the log begins past FLOOR's commit */
    OK(verify_db(db));
    CHECK(run("CREATE VIEW vc AS SELECT id FROM vb WHERE id > 1") == 0);
    REFUSED("DROP TABLE a RETENTION 1 DAY", "view va names table a");
    char want[256];
    snprintf(want, sizeof want, "%s", csv_to(&g_s, "SELECT * FROM vc ORDER BY id", g_out, sizeof g_out));
    CHECK(!strcmp(want, "id\n2\n3\n"));
    uint8_t t1[32], t2[32];
    OK(imdb_view_token(db, t1, &g_e));
    done(db);
    CHECK(audit_ok(dir)); /* the auditor's floor_seed: F's views */
    db = dopen(dir, false);
    CHECK(db);
    if (!db) return;
    OK(imdb_view_token(db, t2, &g_e));
    CHECK(!memcmp(t1, t2, 32));
    OK(verify_db(db)); /* verify_seed: F's views, then the log's from F + 1 */
    imdb_close(db);
    char rdir[700], f[760]; /* a replica seeded from FLOOR: the version-6 manifest's views */
    snprintf(rdir, sizeof rdir, "%s-replica", dir);
    snprintf(f, sizeof f, "%s-stream", dir);
    imdb_identity id;
    OK(imdb_identity_read(dir, &id, NULL, &g_e));
    OK(imdb_init_replica(rdir, &id, &g_e));
    OK(ship_to_file(dir, 0, f, &g_e));
    imdb_db *rdb = dopen(rdir, false);
    CHECK(rdb);
    if (!rdb) return;
    uint64_t applied = 0;
    OK(apply_file(rdb, f, &applied, &g_e));
    CHECK(rdb->seeded && rdb->failed); /* the seed taken into the directory: the handle stale (t_retain's retain_seed) */
    imdb_close(rdb);
    rdb = dopen(rdir, false); /* the snapshot at the floor: its views from the seed's manifest */
    CHECK(rdb && rdb->nviews == 3);
    if (!rdb) return;
    OK(ship_to_file(dir, rdb->seq, f, &g_e)); /* then the commits past it: vc */
    OK(apply_file(rdb, f, &applied, &g_e));
    OK(imdb_view_token(rdb, t2, &g_e));
    CHECK(!memcmp(t1, t2, 32) && rdb->nviews == 4);
    imdb_session rs;
    imdb_session_init(&rs, rdb);
    CHECK(!strcmp(csv_to(&rs, "SELECT * FROM vc ORDER BY id", g_out, sizeof g_out), want));
    imdb_session_close(&rs);
    OK(verify_db(rdb));
    imdb_close(rdb);
    CHECK(audit_ok(rdir));
}

/* a backup holds the views (its seed's manifest, the commits after it); its restore answers through them */
static void t_view_backup(void)
{
    const char *tmp = test_tmpdir();
    char p[600], kf[600], out[600], r[600];
    snprintf(p, sizeof p, "%s/p", tmp);
    snprintf(kf, sizeof kf, "%s/backup.key", tmp);
    snprintf(out, sizeof out, "%s/b.bak", tmp);
    snprintf(r, sizeof r, "%s/r", tmp);
    uint8_t kid[32], key[IMDB_BACKUP_KEY_LEN];
    OK(imdb_backup_key_create(kf, kid, &g_e));
    OK(imdb_backup_key_load(kf, key, &g_e));
    OK(imdb_init(p, false, NULL, &g_e));
    imdb_db *db = dopen(p, false);
    CHECK(db);
    if (!db) return;
    imdb_session_init(&g_s, db);
    fill();
    CHECK(run("CREATE VIEW v (x, y) AS SELECT id, g FROM t WHERE g = 2") == 0);
    CHECK(run("CHECKPOINT") == 0); /* v in the seed's manifest */
    CHECK(run("CREATE VIEW w AS SELECT x FROM v WHERE x > 100") == 0); /* w in the commits after it */
    CHECK(run("CREATE VIEW gone AS SELECT id FROM u") == 0 && run("DROP VIEW gone") == 0);
    char want[1 << 12];
    snprintf(want, sizeof want, "%s", csv_to(&g_s, "SELECT * FROM w ORDER BY x", g_out, sizeof g_out));
    uint8_t vt[32], vr[32];
    OK(imdb_view_token(db, vt, &g_e));
    done(db);
    imdb_backup_info bi, ri;
    OK(imdb_backup_full(p, out, key, &bi, &g_e));
    const char *files[1] = {out};
    OK(imdb_restore(r, key, files, 1, &ri, &g_e));
    CHECK(ri.last_seq == bi.last_seq);
    db = dopen(r, false);
    CHECK(db);
    if (!db) return;
    OK(imdb_view_token(db, vr, &g_e));
    CHECK(!memcmp(vt, vr, 32) && db->nviews == 3);
    imdb_session_init(&g_s, db);
    CHECK(!strcmp(csv_to(&g_s, "SELECT * FROM w ORDER BY x", g_out, sizeof g_out), want));
    OK(verify_db(db));
    done(db);
    CHECK(audit_ok(r));
}


/* a replica applying from commit 0 a log an ERASE redacted re-binds each view while it waits for the ERASE record
 * (pending_auth: no read until then; a bind-only pass reads none) */
static void t_view_replica_erase(void)
{
    const char *dir;
    imdb_db *db = open_fresh(&dir);
    CHECK(db);
    if (!db) return;
    CHECK(run("CREATE TABLE p (id INT64 PRIMARY KEY, who INT64 SUBJECT, note TEXT)") == 0);
    CHECK(run("INSERT INTO p VALUES (1, 7, 'seven'), (2, 8, 'eight')") == 0);
    CHECK(run("CREATE VIEW pv AS SELECT id, note FROM p WHERE who > 0") == 0);
    CHECK(run("ERASE SUBJECT 7") == 0);
    CHECK(run("CREATE VIEW pw AS SELECT id FROM pv") == 0);
    uint8_t a[32], b[32];
    OK(imdb_view_token(db, a, &g_e));
    done(db);
    char rdir[700], f[760];
    snprintf(rdir, sizeof rdir, "%s-replica", dir);
    snprintf(f, sizeof f, "%s-stream", dir);
    imdb_identity id;
    OK(imdb_identity_read(dir, &id, NULL, &g_e));
    OK(imdb_init_replica(rdir, &id, &g_e));
    OK(ship_to_file(dir, 0, f, &g_e));
    imdb_db *rdb = dopen(rdir, false);
    CHECK(rdb);
    if (!rdb) return;
    uint64_t applied = 0;
    OK(apply_file(rdb, f, &applied, &g_e));
    OK(imdb_view_token(rdb, b, &g_e));
    CHECK(!memcmp(a, b, 32) && rdb->nviews == 2);
    imdb_session rs;
    imdb_session_init(&rs, rdb);
    CHECK(!strcmp(csv_to(&rs, "SELECT * FROM pw", g_out, sizeof g_out), "id\n2\n"));
    imdb_session_close(&rs);
    imdb_close(rdb);
}

const test_case view_tests[] = {
    {"view_differential", t_view_differential},
    {"view_refusals", t_view_refusals},
    {"view_deps", t_view_deps},
    {"view_txn", t_view_txn},
    {"view_replica", t_view_replica},
    {"view_prepared", t_view_prepared},
    {"view_dump", t_view_dump},
    {"view_codec", t_view_codec},
    {"view_limits", t_view_limits},
    {"view_api_rebind", t_view_api_rebind},
    {"view_lazy_deps", t_view_lazy_deps},
    {"view_retire", t_view_retire},
    {"view_backup", t_view_backup},
    {"view_replica_erase", t_view_replica_erase},
};
const size_t view_ntests = sizeof view_tests / sizeof *view_tests;
