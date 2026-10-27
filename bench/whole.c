/* Whole-engine benchmarks under equal contracts (deferred.md R8): imagedb, SQLite and PostgreSQL,
 * one engine per process, the same schema and workload, every transaction's commit durable when
 * it returns (imagedb: fdatasync per commit, --durable-ack: the watermark too; SQLite: WAL with
 * synchronous=FULL; PostgreSQL: fsync and synchronous_commit on, its defaults). Statements are SQL
 * text with parameters; SQLite and PostgreSQL prepare theirs, imagedb has no prepared statements
 * and parses each one. Single client, single node, no replicas. Since 2026-10-24 (the head-to-head
 * after CREATE INDEX): imagedb has an ordered index on id, as the others' B-tree primary keys are
 * ordered (--no-index runs R8's imagedb), W4c sums the whole id range, W6 adds a secondary index,
 * and every range answer is checked. Since 2026-10-26: W7 (two-table joins) and W8 (a multi-column
 * index, a unique one) on two more tables. Built with -DWITH_EXT (build/whole-ext, the user's
 * request of 2026-10-26), it also drives MySQL and MariaDB (libmysqlclient, the MySQL C API, for
 * both), SQL Server (unixODBC and Microsoft's ODBC Driver 18) and DuckDB (its C API, in process),
 * with the durability their defaults give (bench/whole.sh prints and checks it).
 *   whole imagedb DIR [--durable-ack | --no-index]
 *   whole sqlite FILE
 *   whole postgres CONNINFO PIDFILE [NAME]   (a private instance the driver script started)
 *   whole mysql|mariadb SOCKET USER PASSWORD PIDFILE      (WITH_EXT; a private container)
 *   whole sqlserver PIDFILE    (WITH_EXT; ODBC connection string in $WHOLE_ODBC, kept out of ps)
 *   whole duckdb FILE          (WITH_EXT)
 *   whole ping ENGINE ARGS...  (WITH_EXT: connect, read row 1, exit: the restart's first query)
 * One line per measure: "engine workload metric value unit". bench/whole.sh runs them all. */
#include <errno.h>
#include <libpq-fe.h>
#include <sqlite3.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#ifdef WITH_EXT
#include <duckdb.h>
#include <mysql.h>
#include <sql.h> /* unixODBC's (an angle include: the engine's src/sql.h is included by path below) */
#include <sqlext.h>
#endif

#include "../src/db.h"
#include "../src/db_internal.h" /* commit counters: automatic CHECKPOINTs are commits too */
#include "../src/sql.h"

/* W6: a second table with a scattered key and a secondary index on it, in all three engines */
enum { Q2_INS, Q2_SUM, Q2_UPD, NQ2 };
static const char *const kQ2[NQ2] = {"INSERT INTO t2 VALUES ($1, $2, $3)", "SELECT SUM(v) FROM t2 WHERE k BETWEEN $1 AND $2",
                                     "UPDATE t2 SET v = $1 WHERE k BETWEEN $2 AND $3"};
static const char *const kQ2lite[NQ2] = {"INSERT INTO t2 VALUES (?1, ?2, ?3)", "SELECT SUM(v) FROM t2 WHERE k BETWEEN ?1 AND ?2",
                                         "UPDATE t2 SET v = ?1 WHERE k BETWEEN ?2 AND ?3"};

/* W7 and W8: customers c and orders o, in all three engines; a TEXT parameter, where a statement has
 * one, comes after its INT64 ones */
enum { Q3_INSC, Q3_INSO, Q3_POINT, Q3_CUST, Q3_ANTI, Q3_ALL, Q3_CA, Q3_NAME, Q3_COUNTC, NQ3 };
static const char *const kQ3[NQ3] = {
    "INSERT INTO c VALUES ($1, $2, $3)",
    "INSERT INTO o VALUES ($1, $2, $3)",
    "SELECT c.region, o.amount FROM o JOIN c ON o.cust = c.id WHERE o.id = $1",
    "SELECT COUNT(*), SUM(o.amount) FROM c JOIN o ON c.id = o.cust WHERE c.id = $1",
    "SELECT COUNT(*) FROM c LEFT JOIN o ON c.id = o.cust WHERE c.region = $1 AND o.id IS NULL",
    "SELECT c.region, SUM(o.amount) FROM o JOIN c ON o.cust = c.id GROUP BY c.region",
    "SELECT COUNT(*) FROM o WHERE cust = $1 AND amount BETWEEN $2 AND $3",
    "SELECT region FROM c WHERE name = $1",
    "SELECT COUNT(*) FROM c"};
static const char *const kQ3lite[NQ3] = {
    "INSERT INTO c VALUES (?1, ?2, ?3)",
    "INSERT INTO o VALUES (?1, ?2, ?3)",
    "SELECT c.region, o.amount FROM o JOIN c ON o.cust = c.id WHERE o.id = ?1",
    "SELECT COUNT(*), SUM(o.amount) FROM c JOIN o ON c.id = o.cust WHERE c.id = ?1",
    "SELECT COUNT(*) FROM c LEFT JOIN o ON c.id = o.cust WHERE c.region = ?1 AND o.id IS NULL",
    "SELECT c.region, SUM(o.amount) FROM o JOIN c ON o.cust = c.id GROUP BY c.region",
    "SELECT COUNT(*) FROM o WHERE cust = ?1 AND amount BETWEEN ?2 AND ?3",
    "SELECT region FROM c WHERE name = ?1",
    "SELECT COUNT(*) FROM c"};

/* which SQL each engine speaks, where the statements differ (DDL types, ANALYZE, CHECKPOINT, EXPLAIN) */
enum { D_IMAGEDB, D_SQLITE, D_PG, D_MYSQL, D_MARIADB, D_MSSQL, D_DUCKDB };
#ifdef WITH_EXT
/* R8's statements on t, as the WITH_EXT engines prepare them ($n become ? where an engine wants it) */
enum { ST_INS, ST_GET, ST_SUM, ST_UPD, ST_SUB, ST_DEL, NST };
static const char *const kT[NST] = {"INSERT INTO t VALUES ($1, $2, $3, $4)", "SELECT amount FROM t WHERE id = $1",
                                    "SELECT SUM(amount) FROM t WHERE id BETWEEN $1 AND $2",
                                    "UPDATE t SET amount = $1 WHERE id BETWEEN $2 AND $3",
                                    "SELECT COUNT(*) FROM t WHERE user_id = $1", "DELETE FROM t WHERE id BETWEEN $1 AND $2"};
#endif

typedef struct eng eng;
struct eng {
    const char *name;
    int dialect;
    int (*exec)(eng *g, const char *sql);
    int (*insert)(eng *g, int64_t id, int64_t user, int64_t amount, const char *memo);
    int (*lookup)(eng *g, int64_t id, int64_t *amount);
    int (*range_sum)(eng *g, int64_t lo, int64_t hi, int64_t *sum);
    int (*update_range)(eng *g, int64_t lo, int64_t hi, int64_t amount);
    int (*subject_count)(eng *g, int64_t user, int64_t *n);
    int (*delete_range)(eng *g, int64_t lo, int64_t hi);
    int (*reopen)(eng *g);
    int (*q2)(eng *g, int which, const int64_t *p, int n, int64_t *out); /* W6's statements (Q2_*) */
    /* W7's and W8's (Q3_*): up to cap rows' first ncol columns into out (row by row), *nrows the
     * rows returned (out may be NULL) */
    int (*q3)(eng *g, int which, const int64_t *p, int n, const char *text, int64_t *out, int ncol, int cap, int *nrows);
    /* imagedb */
    imdb_db *db;
    imdb_session ss;
    const char *dir;
    bool strict, noindex;
    char plan3[NQ3][96]; /* the path each Q3 statement last ran */
    /* sqlite */
    sqlite3 *lite;
    sqlite3_stmt *s_ins, *s_get, *s_sum, *s_upd, *s_sub, *s_del, *s2[3], *s3[NQ3];
    const char *file;
    /* postgres */
    PGconn *pg;
    const char *pidfile;
#ifdef WITH_EXT
    /* the WITH_EXT engines share one shape: statement set 0 (t: ST_*), 1 (t2: Q2_*), 2 (c, o: Q3_*),
     * prepared after their tables exist, run by run() into up to cap rows of ncol columns */
    int (*run)(eng *g, int set, int which, const int64_t *p, int n, const char *text, int64_t *out, int ncol, int cap,
               int *nrows);
    void (*prep)(eng *g, int set);
    void (*plan)(eng *g, const char *sql, char *line, size_t cap, size_t *len);
    MYSQL *my;
    MYSQL_STMT *mst[3][NQ3];
    SQLHENV oenv;
    SQLHDBC odbc;
    SQLHSTMT ost[3][NQ3];
    duckdb_database ddb;
    duckdb_connection dcon;
    duckdb_prepared_statement dst[3][NQ3];
#endif
};

static void die(const char *what, const char *msg)
{
    fprintf(stderr, "whole: %s: %s\n", what, msg);
    exit(1);
}

static double now(void)
{
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (double)t.tv_sec + (double)t.tv_nsec * 1e-9;
}

/* A sample far past its workload's median, kept with its wall-clock start so it can be matched
 * against the system journal (2026-10-26: four single samples of 2-3 s, cause unknown). Called
 * after the clock stops, with the sample's start and seconds, which it returns; report_lat prints
 * the ones over 10 times the median. Under 0.2 s nothing is kept. */
typedef struct stall_rec {
    double at, took; /* CLOCK_REALTIME at the sample's start; its seconds */
} stall_rec;
static stall_rec g_stall[64];
static int g_nstall;
static double stall(double a, double took)
{
    if (took >= 0.2 && g_nstall < (int)(sizeof g_stall / sizeof *g_stall)) {
        struct timespec t;
        clock_gettime(CLOCK_REALTIME, &t);
        g_stall[g_nstall++] = (stall_rec){(double)t.tv_sec + (double)t.tv_nsec * 1e-9 - (now() - a), took};
    }
    return took;
}

/* ---- imagedb -------------------------------------------------------------------------------- */

static int i_run(eng *g, const char *sql, const imdb_value *p, uint32_t np, imdb_result *r)
{
    imdb_err e = {0};
    int rc = imdb_exec_one(&g->ss, sql, strlen(sql), p, np, r, &e);
    if (rc) fprintf(stderr, "whole: imagedb: %s: %s\n", sql, e.msg);
    return rc;
}

static int i_exec(eng *g, const char *sql)
{
    imdb_result r;
    int rc = i_run(g, sql, NULL, 0, &r);
    imdb_result_free(&r);
    return rc;
}

static int i_insert(eng *g, int64_t id, int64_t user, int64_t amount, const char *memo)
{
    imdb_value p[4] = {{.type = IMDB_T_INT64, .i = id},
                       {.type = IMDB_T_INT64, .i = user},
                       {.type = IMDB_T_INT64, .i = amount},
                       {.type = IMDB_T_TEXT, .s = (const uint8_t *)memo, .len = (uint32_t)strlen(memo)}};
    imdb_result r;
    int rc = i_run(g, "INSERT INTO t VALUES ($1, $2, $3, $4)", p, 4, &r);
    imdb_result_free(&r);
    return rc;
}

static int i_one(eng *g, const char *sql, const imdb_value *p, uint32_t np, int64_t *out)
{
    imdb_result r;
    int rc = i_run(g, sql, p, np, &r);
    if (!rc && out) /* an INT64 SUM is held whole (i128); COUNT and plain values are in v */
        *out = r.nrows && !r.cells[0].null ? (r.cells[0].wide ? (int64_t)r.cells[0].i128 : r.cells[0].v.i) : 0;
    imdb_result_free(&r);
    return rc;
}

static int i_lookup(eng *g, int64_t id, int64_t *amount)
{
    imdb_value p = {.type = IMDB_T_INT64, .i = id};
    return i_one(g, "SELECT amount FROM t WHERE id = $1", &p, 1, amount);
}

static int i_sum(eng *g, int64_t lo, int64_t hi, int64_t *sum)
{
    imdb_value p[2] = {{.type = IMDB_T_INT64, .i = lo}, {.type = IMDB_T_INT64, .i = hi}};
    return i_one(g, "SELECT SUM(amount) FROM t WHERE id BETWEEN $1 AND $2", p, 2, sum);
}

static int i_update(eng *g, int64_t lo, int64_t hi, int64_t amount)
{
    imdb_value p[3] = {{.type = IMDB_T_INT64, .i = amount}, {.type = IMDB_T_INT64, .i = lo}, {.type = IMDB_T_INT64, .i = hi}};
    return i_one(g, "UPDATE t SET amount = $1 WHERE id BETWEEN $2 AND $3", p, 3, NULL);
}

static int i_subject(eng *g, int64_t user, int64_t *n)
{
    imdb_value p = {.type = IMDB_T_INT64, .i = user};
    return i_one(g, "SELECT COUNT(*) FROM t WHERE user_id = $1", &p, 1, n);
}

static int i_delete(eng *g, int64_t lo, int64_t hi)
{
    imdb_value p[2] = {{.type = IMDB_T_INT64, .i = lo}, {.type = IMDB_T_INT64, .i = hi}};
    return i_one(g, "DELETE FROM t WHERE id BETWEEN $1 AND $2", p, 2, NULL);
}

static int i_q2(eng *g, int which, const int64_t *p, int n, int64_t *out)
{
    imdb_value v[3];
    for (int i = 0; i < n; i++) v[i] = (imdb_value){.type = IMDB_T_INT64, .i = p[i]};
    return i_one(g, kQ2[which], v, (uint32_t)n, out);
}

static int i_q3(eng *g, int which, const int64_t *p, int n, const char *text, int64_t *out, int ncol, int cap, int *nrows)
{
    imdb_value v[4];
    for (int i = 0; i < n; i++) v[i] = (imdb_value){.type = IMDB_T_INT64, .i = p[i]};
    if (text) v[n++] = (imdb_value){.type = IMDB_T_TEXT, .s = (const uint8_t *)text, .len = (uint32_t)strlen(text)};
    imdb_result r;
    int rc = i_run(g, kQ3[which], v, (uint32_t)n, &r);
    if (!rc && out && r.ncols < (uint32_t)ncol) rc = -1;
    for (uint64_t i = 0; !rc && out && i < r.nrows && i < (uint64_t)cap; i++)
        for (int c = 0; c < ncol; c++) { /* an INT64 SUM is held whole (i128); a NULL one reads as 0, as the others' do */
            const imdb_cell *x = &r.cells[i * r.ncols + (uint32_t)c];
            out[i * (uint64_t)ncol + (uint64_t)c] = x->null ? 0 : x->wide ? (int64_t)x->i128 : x->v.i;
        }
    if (!rc && nrows) *nrows = (int)r.nrows;
    if (!rc) snprintf(g->plan3[which], sizeof g->plan3[which], "%s", r.path);
    imdb_result_free(&r);
    return rc;
}

static int i_open(eng *g)
{
    imdb_open_opts o = {.sync = 1, .durable_ack = g->strict};
    imdb_err e = {0};
    if (imdb_open(g->dir, &o, &g->db, &e)) die("imagedb open", e.msg);
    imdb_session_init(&g->ss, g->db);
    return 0;
}

static int i_reopen(eng *g)
{
    imdb_session_close(&g->ss);
    if (imdb_close(g->db)) die("imagedb", "close");
    return i_open(g);
}

/* ---- sqlite --------------------------------------------------------------------------------- */

static int l_exec(eng *g, const char *sql)
{
    char *err = NULL;
    if (sqlite3_exec(g->lite, sql, NULL, NULL, &err) != SQLITE_OK) {
        fprintf(stderr, "whole: sqlite: %s: %s\n", sql, err ? err : "?");
        sqlite3_free(err);
        return -1;
    }
    return 0;
}

static int l_step(sqlite3_stmt *s, int64_t *out)
{
    int rc = sqlite3_step(s);
    if (rc == SQLITE_ROW && out) *out = sqlite3_column_int64(s, 0);
    if (rc == SQLITE_ROW) rc = sqlite3_step(s);
    sqlite3_reset(s);
    return rc == SQLITE_DONE ? 0 : -1;
}

static int l_insert(eng *g, int64_t id, int64_t user, int64_t amount, const char *memo)
{
    sqlite3_bind_int64(g->s_ins, 1, id);
    sqlite3_bind_int64(g->s_ins, 2, user);
    sqlite3_bind_int64(g->s_ins, 3, amount);
    sqlite3_bind_text(g->s_ins, 4, memo, -1, SQLITE_STATIC);
    return l_step(g->s_ins, NULL);
}

static int l_lookup(eng *g, int64_t id, int64_t *amount)
{
    sqlite3_bind_int64(g->s_get, 1, id);
    return l_step(g->s_get, amount);
}

static int l_sum(eng *g, int64_t lo, int64_t hi, int64_t *sum)
{
    sqlite3_bind_int64(g->s_sum, 1, lo);
    sqlite3_bind_int64(g->s_sum, 2, hi);
    return l_step(g->s_sum, sum);
}

static int l_update(eng *g, int64_t lo, int64_t hi, int64_t amount)
{
    sqlite3_bind_int64(g->s_upd, 1, amount);
    sqlite3_bind_int64(g->s_upd, 2, lo);
    sqlite3_bind_int64(g->s_upd, 3, hi);
    return l_step(g->s_upd, NULL);
}

static int l_subject(eng *g, int64_t user, int64_t *n)
{
    sqlite3_bind_int64(g->s_sub, 1, user);
    return l_step(g->s_sub, n);
}

static int l_delete(eng *g, int64_t lo, int64_t hi)
{
    sqlite3_bind_int64(g->s_del, 1, lo);
    sqlite3_bind_int64(g->s_del, 2, hi);
    return l_step(g->s_del, NULL);
}

static void l_prepare(eng *g)
{
    if (sqlite3_prepare_v2(g->lite, "INSERT INTO t VALUES (?1, ?2, ?3, ?4)", -1, &g->s_ins, NULL) ||
        sqlite3_prepare_v2(g->lite, "SELECT amount FROM t WHERE id = ?1", -1, &g->s_get, NULL) ||
        sqlite3_prepare_v2(g->lite, "SELECT SUM(amount) FROM t WHERE id BETWEEN ?1 AND ?2", -1, &g->s_sum, NULL) ||
        sqlite3_prepare_v2(g->lite, "UPDATE t SET amount = ?1 WHERE id BETWEEN ?2 AND ?3", -1, &g->s_upd, NULL) ||
        sqlite3_prepare_v2(g->lite, "SELECT COUNT(*) FROM t WHERE user_id = ?1", -1, &g->s_sub, NULL) ||
        sqlite3_prepare_v2(g->lite, "DELETE FROM t WHERE id BETWEEN ?1 AND ?2", -1, &g->s_del, NULL))
        die("sqlite prepare", sqlite3_errmsg(g->lite));
}

static int l_q2(eng *g, int which, const int64_t *p, int n, int64_t *out)
{
    for (int i = 0; i < n; i++) sqlite3_bind_int64(g->s2[which], i + 1, p[i]);
    return l_step(g->s2[which], out);
}

static void l_prepare2(eng *g)
{
    for (int i = 0; i < NQ2; i++)
        if (sqlite3_prepare_v2(g->lite, kQ2lite[i], -1, &g->s2[i], NULL)) die("sqlite prepare", sqlite3_errmsg(g->lite));
}

static int l_q3(eng *g, int which, const int64_t *p, int n, const char *text, int64_t *out, int ncol, int cap, int *nrows)
{
    sqlite3_stmt *s = g->s3[which];
    for (int i = 0; i < n; i++) sqlite3_bind_int64(s, i + 1, p[i]);
    if (text) sqlite3_bind_text(s, n + 1, text, -1, SQLITE_STATIC);
    int rc, k = 0;
    if (out && sqlite3_column_count(s) < ncol) return -1;
    while ((rc = sqlite3_step(s)) == SQLITE_ROW) { /* a NULL SUM reads as 0 */
        for (int c = 0; out && k < cap && c < ncol; c++) out[k * ncol + c] = sqlite3_column_int64(s, c);
        k++;
    }
    if (rc != SQLITE_DONE) fprintf(stderr, "whole: sqlite: %s: %s\n", kQ3lite[which], sqlite3_errmsg(g->lite));
    sqlite3_reset(s);
    if (nrows) *nrows = k;
    return rc == SQLITE_DONE ? 0 : -1;
}

static void l_prepare3(eng *g)
{
    for (int i = 0; i < NQ3; i++)
        if (sqlite3_prepare_v2(g->lite, kQ3lite[i], -1, &g->s3[i], NULL)) die("sqlite prepare", sqlite3_errmsg(g->lite));
}

static int l_open(eng *g)
{
    if (sqlite3_open(g->file, &g->lite) != SQLITE_OK) die("sqlite open", sqlite3_errmsg(g->lite));
    if (l_exec(g, "PRAGMA journal_mode = WAL") || l_exec(g, "PRAGMA synchronous = FULL")) die("sqlite", "pragmas");
    return 0;
}

static int l_reopen(eng *g)
{
    sqlite3_finalize(g->s_ins);
    sqlite3_finalize(g->s_get);
    sqlite3_finalize(g->s_sum);
    sqlite3_finalize(g->s_upd);
    sqlite3_finalize(g->s_sub);
    sqlite3_finalize(g->s_del);
    sqlite3_close(g->lite);
    l_open(g);
    l_prepare(g);
    return 0;
}

/* ---- postgres ------------------------------------------------------------------------------- */

static int p_check(eng *g, PGresult *r, const char *what)
{
    ExecStatusType st = PQresultStatus(r);
    if (st != PGRES_COMMAND_OK && st != PGRES_TUPLES_OK) {
        fprintf(stderr, "whole: postgres: %s: %s\n", what, PQerrorMessage(g->pg));
        PQclear(r);
        return -1;
    }
    return 0;
}

static int p_exec(eng *g, const char *sql)
{
    PGresult *r = PQexec(g->pg, sql);
    int rc = p_check(g, r, sql);
    if (!rc) PQclear(r);
    return rc;
}

static int p_run(eng *g, const char *name, int n, const char *const *vals, int64_t *out)
{
    PGresult *r = PQexecPrepared(g->pg, name, n, vals, NULL, NULL, 0);
    if (p_check(g, r, name)) return -1;
    if (out) *out = PQntuples(r) && !PQgetisnull(r, 0, 0) ? strtoll(PQgetvalue(r, 0, 0), NULL, 10) : 0;
    PQclear(r);
    return 0;
}

static int p_insert(eng *g, int64_t id, int64_t user, int64_t amount, const char *memo)
{
    char a[24], b[24], c[24];
    snprintf(a, sizeof a, "%lld", (long long)id);
    snprintf(b, sizeof b, "%lld", (long long)user);
    snprintf(c, sizeof c, "%lld", (long long)amount);
    const char *v[4] = {a, b, c, memo};
    return p_run(g, "ins", 4, v, NULL);
}

static int p_lookup(eng *g, int64_t id, int64_t *amount)
{
    char a[24];
    snprintf(a, sizeof a, "%lld", (long long)id);
    const char *v[1] = {a};
    return p_run(g, "get", 1, v, amount);
}

static int p_sum(eng *g, int64_t lo, int64_t hi, int64_t *sum)
{
    char a[24], b[24];
    snprintf(a, sizeof a, "%lld", (long long)lo);
    snprintf(b, sizeof b, "%lld", (long long)hi);
    const char *v[2] = {a, b};
    return p_run(g, "sum", 2, v, sum);
}

static int p_update(eng *g, int64_t lo, int64_t hi, int64_t amount)
{
    char a[24], b[24], c[24];
    snprintf(a, sizeof a, "%lld", (long long)amount);
    snprintf(b, sizeof b, "%lld", (long long)lo);
    snprintf(c, sizeof c, "%lld", (long long)hi);
    const char *v[3] = {a, b, c};
    return p_run(g, "upd", 3, v, NULL);
}

static int p_subject(eng *g, int64_t user, int64_t *n)
{
    char a[24];
    snprintf(a, sizeof a, "%lld", (long long)user);
    const char *v[1] = {a};
    return p_run(g, "sub", 1, v, n);
}

static int p_delete(eng *g, int64_t lo, int64_t hi)
{
    char a[24], b[24];
    snprintf(a, sizeof a, "%lld", (long long)lo);
    snprintf(b, sizeof b, "%lld", (long long)hi);
    const char *v[2] = {a, b};
    return p_run(g, "del", 2, v, NULL);
}

static void p_prepare(eng *g)
{
    const char *const q[6][2] = {{"ins", "INSERT INTO t VALUES ($1, $2, $3, $4)"},
                                 {"get", "SELECT amount FROM t WHERE id = $1"},
                                 {"sum", "SELECT SUM(amount) FROM t WHERE id BETWEEN $1 AND $2"},
                                 {"upd", "UPDATE t SET amount = $1 WHERE id BETWEEN $2 AND $3"},
                                 {"sub", "SELECT COUNT(*) FROM t WHERE user_id = $1"},
                                 {"del", "DELETE FROM t WHERE id BETWEEN $1 AND $2"}};
    for (int i = 0; i < 6; i++) {
        PGresult *r = PQprepare(g->pg, q[i][0], q[i][1], 0, NULL);
        if (p_check(g, r, q[i][1])) exit(1);
        PQclear(r);
    }
}

static const char *const kQ2pg[NQ2] = {"ins2", "sum2", "upd2"};

static int p_q2(eng *g, int which, const int64_t *p, int n, int64_t *out)
{
    char a[3][24];
    const char *v[3];
    for (int i = 0; i < n; i++) {
        snprintf(a[i], sizeof a[i], "%lld", (long long)p[i]);
        v[i] = a[i];
    }
    return p_run(g, kQ2pg[which], n, v, out);
}

static void p_prepare2(eng *g)
{
    for (int i = 0; i < NQ2; i++) {
        PGresult *r = PQprepare(g->pg, kQ2pg[i], kQ2[i], 0, NULL);
        if (p_check(g, r, kQ2[i])) exit(1);
        PQclear(r);
    }
}

static int p_q3(eng *g, int which, const int64_t *p, int n, const char *text, int64_t *out, int ncol, int cap, int *nrows)
{
    char a[4][24], name[16];
    const char *v[4];
    for (int i = 0; i < n; i++) {
        snprintf(a[i], sizeof a[i], "%lld", (long long)p[i]);
        v[i] = a[i];
    }
    if (text) v[n++] = text;
    snprintf(name, sizeof name, "q3_%d", which);
    PGresult *r = PQexecPrepared(g->pg, name, n, v, NULL, NULL, 0);
    if (p_check(g, r, kQ3[which])) return -1;
    int k = PQntuples(r);
    if (out && PQnfields(r) < ncol) {
        PQclear(r);
        return -1;
    }
    for (int i = 0; out && i < k && i < cap; i++) /* a NULL SUM reads as 0 */
        for (int c = 0; c < ncol; c++) out[i * ncol + c] = PQgetisnull(r, i, c) ? 0 : strtoll(PQgetvalue(r, i, c), NULL, 10);
    if (nrows) *nrows = k;
    PQclear(r);
    return 0;
}

/* the settings that decide durability and memory, as the server reports them (the native instance
 * and the container must match, and the version is recorded, not typed in) */
static void p_settings(eng *g)
{
    static const char *const k[] = {"server_version", "fsync", "synchronous_commit", "wal_sync_method", "full_page_writes",
                                    "shared_buffers", "max_parallel_workers_per_gather"};
    for (size_t i = 0; i < sizeof k / sizeof *k; i++) {
        char q[96];
        snprintf(q, sizeof q, "SHOW %s", k[i]);
        PGresult *r = PQexec(g->pg, q);
        printf("%s setting %s %s\n", g->name, k[i],
               PQresultStatus(r) == PGRES_TUPLES_OK && PQntuples(r) ? PQgetvalue(r, 0, 0) : "(unknown)");
        PQclear(r);
    }
}

static void p_prepare3(eng *g)
{
    for (int i = 0; i < NQ3; i++) {
        char name[16];
        snprintf(name, sizeof name, "q3_%d", i);
        PGresult *r = PQprepare(g->pg, name, kQ3[i], 0, NULL);
        if (p_check(g, r, kQ3[i])) exit(1);
        PQclear(r);
    }
}

#ifdef WITH_EXT
/* ---- the WITH_EXT engines: what they share -------------------------------------------------- */

static void append(char *line, size_t cap, size_t *len, const char *s);
static const char *const *x_texts(int set) { return set == 0 ? kT : set == 1 ? kQ2 : kQ3; }
static int x_count(int set) { return set == 0 ? NST : set == 1 ? NQ2 : NQ3; }

/* $n -> ?, for the engines that number parameters by position (each statement here names each
 * parameter once, in ascending order) */
static void qmarks(const char *src, char *dst, size_t cap)
{
    size_t o = 0;
    for (const char *s = src; *s && o + 2 < cap; s++) {
        if (s[0] == '$' && s[1] >= '1' && s[1] <= '9') {
            dst[o++] = '?';
            while (s[1] >= '0' && s[1] <= '9') s++;
        } else {
            dst[o++] = *s;
        }
    }
    dst[o] = 0;
}

/* a statement with the driver's own values written in, for EXPLAIN (digits; the text 'c' and digits) */
static void inline_values(const char *src, const int64_t *p, int n, const char *text, char *dst, size_t cap)
{
    size_t o = 0;
    for (const char *s = src; *s && o + 32 < cap; s++) {
        if (s[0] == '$' && s[1] >= '1' && s[1] <= '9') {
            int k = 0;
            while (s[1] >= '0' && s[1] <= '9') k = k * 10 + (*++s - '0');
            o += (size_t)(k <= n ? snprintf(dst + o, cap - o, "%lld", (long long)p[k - 1])
                                 : snprintf(dst + o, cap - o, "'%s'", text ? text : ""));
        } else {
            dst[o++] = *s;
        }
    }
    dst[o] = 0;
}

static int x_insert(eng *g, int64_t id, int64_t user, int64_t amount, const char *memo)
{
    int64_t p[3] = {id, user, amount};
    return g->run(g, 0, ST_INS, p, 3, memo, NULL, 0, 0, NULL);
}

static int x_lookup(eng *g, int64_t id, int64_t *amount)
{
    *amount = 0;
    return g->run(g, 0, ST_GET, &id, 1, NULL, amount, 1, 1, NULL);
}

static int x_sum(eng *g, int64_t lo, int64_t hi, int64_t *sum)
{
    int64_t p[2] = {lo, hi};
    *sum = 0; /* a NULL SUM reads as 0, as in the others */
    return g->run(g, 0, ST_SUM, p, 2, NULL, sum, 1, 1, NULL);
}

static int x_update(eng *g, int64_t lo, int64_t hi, int64_t amount)
{
    int64_t p[3] = {amount, lo, hi};
    return g->run(g, 0, ST_UPD, p, 3, NULL, NULL, 0, 0, NULL);
}

static int x_subject(eng *g, int64_t user, int64_t *n)
{
    *n = 0;
    return g->run(g, 0, ST_SUB, &user, 1, NULL, n, 1, 1, NULL);
}

static int x_delete(eng *g, int64_t lo, int64_t hi)
{
    int64_t p[2] = {lo, hi};
    return g->run(g, 0, ST_DEL, p, 2, NULL, NULL, 0, 0, NULL);
}

static int x_q2(eng *g, int which, const int64_t *p, int n, int64_t *out)
{
    if (out) *out = 0;
    return g->run(g, 1, which, p, n, NULL, out, out ? 1 : 0, out ? 1 : 0, NULL);
}

static int x_q3(eng *g, int which, const int64_t *p, int n, const char *text, int64_t *out, int ncol, int cap, int *nrows)
{
    return g->run(g, 2, which, p, n, text, out, ncol, cap, nrows);
}

static void x_engine(eng *g)
{
    g->insert = x_insert, g->lookup = x_lookup, g->range_sum = x_sum, g->update_range = x_update;
    g->subject_count = x_subject, g->delete_range = x_delete, g->q2 = x_q2, g->q3 = x_q3;
}

/* ---- MySQL and MariaDB (the MySQL C API: libmysqlclient serves both servers) ---------------- */

static int m_fail(eng *g, const char *what, const char *msg)
{
    fprintf(stderr, "whole: %s: %s: %s\n", g->name, what, msg);
    return -1;
}

static int m_exec(eng *g, const char *sql)
{
    if (mysql_query(g->my, sql)) return m_fail(g, sql, mysql_error(g->my));
    MYSQL_RES *r = mysql_store_result(g->my); /* ANALYZE TABLE returns rows */
    if (r) mysql_free_result(r);
    else if (mysql_field_count(g->my)) return m_fail(g, sql, mysql_error(g->my));
    return 0;
}

static void m_prepare(eng *g, int set)
{
    for (int i = 0; i < x_count(set); i++) {
        char sql[512];
        qmarks(x_texts(set)[i], sql, sizeof sql);
        if (g->mst[set][i]) mysql_stmt_close(g->mst[set][i]);
        MYSQL_STMT *s = mysql_stmt_init(g->my);
        if (!s || mysql_stmt_prepare(s, sql, strlen(sql))) die(g->name, s ? mysql_stmt_error(s) : mysql_error(g->my));
        g->mst[set][i] = s;
    }
}

static int m_run(eng *g, int set, int which, const int64_t *p, int n, const char *text, int64_t *out, int ncol, int cap,
                 int *nrows)
{
    MYSQL_STMT *s = g->mst[set][which];
    MYSQL_BIND b[5];
    long long v[4];
    unsigned long tl = text ? (unsigned long)strlen(text) : 0;
    memset(b, 0, sizeof b);
    for (int i = 0; i < n; i++) {
        v[i] = p[i];
        b[i].buffer_type = MYSQL_TYPE_LONGLONG;
        b[i].buffer = &v[i];
    }
    if (text) {
        b[n].buffer_type = MYSQL_TYPE_STRING;
        b[n].buffer = (void *)(uintptr_t)text; /* read only: the library takes a void * */
        b[n].buffer_length = tl;
        b[n].length = &tl;
    }
    if (mysql_stmt_bind_param(s, b) || mysql_stmt_execute(s)) return m_fail(g, x_texts(set)[which], mysql_stmt_error(s));
    int k = 0, nc = (int)mysql_stmt_field_count(s);
    if (nc > 0) {
        MYSQL_BIND rb[4];
        long long rv[4] = {0};
        bool rnull[4] = {0};
        memset(rb, 0, sizeof rb);
        if (nc > 4) nc = 4;
        for (int c = 0; c < nc; c++) {
            rb[c].buffer_type = MYSQL_TYPE_LONGLONG; /* SUM's DECIMAL converted by the library, exactly */
            rb[c].buffer = &rv[c];
            rb[c].is_null = &rnull[c];
        }
        if (mysql_stmt_bind_result(s, rb)) return m_fail(g, "bind result", mysql_stmt_error(s));
        int rc;
        while ((rc = mysql_stmt_fetch(s)) == 0) {
            for (int c = 0; out && k < cap && c < ncol && c < nc; c++) out[k * ncol + c] = rnull[c] ? 0 : rv[c];
            k++;
        }
        mysql_stmt_free_result(s);
        if (rc != MYSQL_NO_DATA) return m_fail(g, "fetch (a truncated value is an error)", mysql_stmt_error(s));
    }
    if (nrows) *nrows = k;
    return 0;
}

/* MySQL: EXPLAIN FORMAT=TREE, a node per line ("-> " first, the estimates after); MariaDB: its
 * tabular EXPLAIN, a row per table (table, access type, key) */
static void m_plan(eng *g, const char *sql, char *line, size_t cap, size_t *len)
{
    if (mysql_query(g->my, sql)) {
        append(line, cap, len, mysql_error(g->my));
        return;
    }
    MYSQL_RES *r = mysql_store_result(g->my);
    unsigned nf = r ? mysql_num_fields(r) : 0;
    MYSQL_ROW row;
    while (r && (row = mysql_fetch_row(r))) {
        if (g->dialect == D_MYSQL && row[0]) {
            for (char *s = row[0], *e; *s; s = e) {
                e = strchr(s, '\n');
                if (e) *e++ = 0;
                else e = s + strlen(s);
                while (*s == ' ') s++;
                if (strncmp(s, "-> ", 3) == 0) s += 3;
                char *c = strstr(s, "  (cost=");
                if (c) *c = 0;
                if (*s) append(line, cap, len, s);
            }
        } else if (nf >= 6) {
            char item[192];
            snprintf(item, sizeof item, "%s %s%s%s", row[2] ? row[2] : "?", row[3] ? row[3] : "?", row[5] ? " " : "",
                     row[5] ? row[5] : "");
            append(line, cap, len, item);
        }
    }
    if (r) mysql_free_result(r);
}

static void m_connect(eng *g, const char *sock, const char *user, const char *pass)
{
    unsigned int proto = MYSQL_PROTOCOL_SOCKET;
    g->my = mysql_init(NULL);
    if (!g->my) die(g->name, "mysql_init");
    mysql_options(g->my, MYSQL_OPT_PROTOCOL, &proto);
    if (!mysql_real_connect(g->my, NULL, user, pass, "bench", 0, sock, 0)) die(g->name, mysql_error(g->my));
}

/* the settings that decide durability and memory, as the server reports them */
static void m_settings(eng *g)
{
    static const char *const k[] = {"version", "innodb_flush_log_at_trx_commit", "sync_binlog", "log_bin",
                                    "innodb_doublewrite", "innodb_flush_method", "innodb_buffer_pool_size",
                                    "transaction_isolation"};
    for (size_t i = 0; i < sizeof k / sizeof *k; i++) {
        char q[96];
        snprintf(q, sizeof q, "SELECT @@%s", k[i]);
        MYSQL_RES *r = mysql_query(g->my, q) ? NULL : mysql_store_result(g->my);
        MYSQL_ROW row = r ? mysql_fetch_row(r) : NULL;
        printf("%s setting %s %s\n", g->name, k[i], row && row[0] ? row[0] : "(unknown)");
        if (r) mysql_free_result(r);
    }
}

/* ---- SQL Server (unixODBC, Microsoft's ODBC Driver 18) -------------------------------------- */

/* a function, not a macro: its argument is often the call itself, which a macro would make twice
 * (SQLDriverConnect returns SQL_SUCCESS_WITH_INFO at every login, and the second call is refused
 * "connection in use"; a second SQLFetch would skip a row) */
static bool ODBC_OK(SQLRETURN r) { return r == SQL_SUCCESS || r == SQL_SUCCESS_WITH_INFO; }

static int o_fail(eng *g, SQLSMALLINT type, SQLHANDLE h, const char *what)
{
    SQLCHAR state[8] = "", msg[1024] = "";
    SQLINTEGER native = 0;
    SQLSMALLINT len = 0;
    SQLGetDiagRec(type, h, 1, state, &native, msg, (SQLSMALLINT)sizeof msg, &len);
    fprintf(stderr, "whole: %s: %s: [%s] %s\n", g->name, what, (const char *)state, (const char *)msg);
    return -1;
}

/* T-SQL opens a transaction with BEGIN TRANSACTION (a bare BEGIN starts a block) */
static int o_exec(eng *g, const char *sql)
{
    const char *q = strcmp(sql, "BEGIN") == 0 ? "BEGIN TRANSACTION" : sql;
    SQLHSTMT h = SQL_NULL_HSTMT;
    if (!ODBC_OK(SQLAllocHandle(SQL_HANDLE_STMT, g->odbc, &h))) return o_fail(g, SQL_HANDLE_DBC, g->odbc, "alloc");
    SQLRETURN r = SQLExecDirect(h, (SQLCHAR *)(uintptr_t)q, SQL_NTS);
    int rc = ODBC_OK(r) || r == SQL_NO_DATA ? 0 : o_fail(g, SQL_HANDLE_STMT, h, q);
    while (!rc && ODBC_OK(SQLMoreResults(h))) {
    }
    SQLFreeHandle(SQL_HANDLE_STMT, h);
    return rc;
}

static void o_prepare(eng *g, int set)
{
    for (int i = 0; i < x_count(set); i++) {
        char sql[512];
        qmarks(x_texts(set)[i], sql, sizeof sql);
        if (g->ost[set][i]) SQLFreeHandle(SQL_HANDLE_STMT, g->ost[set][i]);
        SQLHSTMT h = SQL_NULL_HSTMT;
        if (!ODBC_OK(SQLAllocHandle(SQL_HANDLE_STMT, g->odbc, &h)) || !ODBC_OK(SQLPrepare(h, (SQLCHAR *)sql, SQL_NTS))) {
            o_fail(g, SQL_HANDLE_STMT, h, sql);
            exit(1);
        }
        g->ost[set][i] = h;
    }
}

static int o_run(eng *g, int set, int which, const int64_t *p, int n, const char *text, int64_t *out, int ncol, int cap,
                 int *nrows)
{
    SQLHSTMT h = g->ost[set][which];
    SQLBIGINT v[4];
    SQLLEN ind[4], tl = text ? (SQLLEN)strlen(text) : 0;
    for (int i = 0; i < n; i++) {
        v[i] = p[i], ind[i] = 0;
        SQLBindParameter(h, (SQLUSMALLINT)(i + 1), SQL_PARAM_INPUT, SQL_C_SBIGINT, SQL_BIGINT, 0, 0, &v[i], 0, &ind[i]);
    }
    if (text)
        SQLBindParameter(h, (SQLUSMALLINT)(n + 1), SQL_PARAM_INPUT, SQL_C_CHAR, SQL_VARCHAR, 255, 0,
                         (SQLPOINTER)(uintptr_t)text, tl, &tl);
    SQLRETURN r = SQLExecute(h);
    if (!ODBC_OK(r) && r != SQL_NO_DATA) {
        int rc = o_fail(g, SQL_HANDLE_STMT, h, x_texts(set)[which]);
        SQLFreeStmt(h, SQL_CLOSE);
        return rc;
    }
    int k = 0;
    SQLSMALLINT nc = 0;
    SQLNumResultCols(h, &nc);
    while (nc > 0 && ODBC_OK(SQLFetch(h))) {
        for (int c = 0; out && k < cap && c < ncol && c < nc; c++) {
            SQLBIGINT x = 0;
            SQLLEN xi = 0;
            SQLGetData(h, (SQLUSMALLINT)(c + 1), SQL_C_SBIGINT, &x, 0, &xi);
            out[k * ncol + c] = xi == SQL_NULL_DATA ? 0 : x;
        }
        k++;
    }
    SQLFreeStmt(h, SQL_CLOSE);
    if (nrows) *nrows = k;
    return 0;
}

/* SET SHOWPLAN_TEXT: the statement's text comes first, then a row per operator ("  |--Nested
 * Loops(...)"); each kept as its operator and, for an index, the table and the index */
static void o_plan(eng *g, const char *sql, char *line, size_t cap, size_t *len)
{
    if (o_exec(g, "SET SHOWPLAN_TEXT ON")) return;
    SQLHSTMT h = SQL_NULL_HSTMT;
    SQLAllocHandle(SQL_HANDLE_STMT, g->odbc, &h);
    if (ODBC_OK(SQLExecDirect(h, (SQLCHAR *)(uintptr_t)sql, SQL_NTS))) {
        int set = 0;
        do {
            SQLCHAR buf[2048];
            SQLLEN ind = 0;
            while (ODBC_OK(SQLFetch(h))) {
                if (!set || !ODBC_OK(SQLGetData(h, 1, SQL_C_CHAR, buf, sizeof buf, &ind)) || ind == SQL_NULL_DATA) continue;
                char *s = (char *)buf, item[192], *obj = strstr(s, "OBJECT:(");
                while (*s == ' ' || *s == '|' || *s == '-') s++;
                size_t op = strcspn(s, "(");
                char tab[64] = "", idx[96] = "";
                if (obj) { /* [db].[schema].[table].[index] */
                    const char *q = obj + 8;
                    for (int part = 0; part < 4 && (q = strchr(q, '[')) != NULL; part++) {
                        const char *e = strchr(q, ']');
                        if (!e) break;
                        if (part == 2) snprintf(tab, sizeof tab, "%.*s", (int)(e - q - 1), q + 1);
                        if (part == 3) snprintf(idx, sizeof idx, "%.*s", (int)(e - q - 1), q + 1);
                        q = e + 1;
                    }
                }
                while (op && s[op - 1] == ' ') op--;
                snprintf(item, sizeof item, "%.*s%s%s%s%s", (int)op, s, tab[0] ? " " : "", tab, idx[0] ? "." : "", idx);
                append(line, cap, len, item);
            }
            set++;
        } while (ODBC_OK(SQLMoreResults(h)));
    }
    SQLFreeHandle(SQL_HANDLE_STMT, h);
    o_exec(g, "SET SHOWPLAN_TEXT OFF");
}

/* the connection string from the environment (it carries the password: out of ps), then (use) the
 * benchmark's database, made first when create: simple recovery, the closest to the others' logs
 * (PostgreSQL's WAL and InnoDB's redo are recycled after checkpoints; FULL keeps every log record
 * until a log backup that never comes) */
static void o_connect(eng *g, bool use, bool create)
{
    const char *conn = getenv("WHOLE_ODBC");
    if (!conn) die(g->name, "WHOLE_ODBC names no connection string");
    SQLAllocHandle(SQL_HANDLE_ENV, SQL_NULL_HANDLE, &g->oenv);
    SQLSetEnvAttr(g->oenv, SQL_ATTR_ODBC_VERSION, (SQLPOINTER)SQL_OV_ODBC3, 0);
    SQLAllocHandle(SQL_HANDLE_DBC, g->oenv, &g->odbc);
    if (!ODBC_OK(SQLDriverConnect(g->odbc, NULL, (SQLCHAR *)(uintptr_t)conn, SQL_NTS, NULL, 0, NULL, SQL_DRIVER_NOPROMPT))) {
        o_fail(g, SQL_HANDLE_DBC, g->odbc, "connect");
        exit(1);
    }
    if (create && (o_exec(g, "IF DB_ID('bench') IS NULL CREATE DATABASE bench") ||
                   o_exec(g, "ALTER DATABASE bench SET RECOVERY SIMPLE")))
        exit(1);
    if (use && o_exec(g, "USE bench")) exit(1);
}

static void o_settings(eng *g)
{
    static const char *const q[][2] = {
        {"version", "SELECT CAST(SERVERPROPERTY('ProductVersion') AS varchar(32)) + ' ' + "
                    "CAST(SERVERPROPERTY('Edition') AS varchar(64))"},
        {"recovery_model", "SELECT recovery_model_desc FROM sys.databases WHERE name = 'bench'"},
        {"delayed_durability", "SELECT delayed_durability_desc FROM sys.databases WHERE name = 'bench'"},
        {"read_committed_snapshot", "SELECT CAST(is_read_committed_snapshot_on AS varchar(4)) FROM sys.databases WHERE "
                                    "name = 'bench'"},
        {"max_degree_of_parallelism", "SELECT CAST(value_in_use AS varchar(16)) FROM sys.configurations WHERE name = "
                                      "'max degree of parallelism'"},
        {"max_server_memory_mb", "SELECT CAST(value_in_use AS varchar(16)) FROM sys.configurations WHERE name = "
                                 "'max server memory (MB)'"}};
    for (size_t i = 0; i < sizeof q / sizeof *q; i++) {
        SQLHSTMT h = SQL_NULL_HSTMT;
        SQLCHAR buf[256] = "(unknown)";
        SQLLEN ind = 0;
        SQLAllocHandle(SQL_HANDLE_STMT, g->odbc, &h);
        if (!ODBC_OK(SQLExecDirect(h, (SQLCHAR *)(uintptr_t)q[i][1], SQL_NTS)) || !ODBC_OK(SQLFetch(h)) ||
            !ODBC_OK(SQLGetData(h, 1, SQL_C_CHAR, buf, sizeof buf, &ind)) || ind == SQL_NULL_DATA)
            snprintf((char *)buf, sizeof buf, "(unknown)");
        printf("%s setting %s %s\n", g->name, q[i][0], (const char *)buf);
        SQLFreeHandle(SQL_HANDLE_STMT, h);
    }
}

/* ---- DuckDB (in process, like SQLite) ------------------------------------------------------- */

static int d_fail(eng *g, const char *what, const char *msg)
{
    fprintf(stderr, "whole: %s: %s: %s\n", g->name, what, msg ? msg : "failed");
    return -1;
}

static int d_exec(eng *g, const char *sql)
{
    duckdb_result r;
    int rc = duckdb_query(g->dcon, sql, &r) == DuckDBError ? d_fail(g, sql, duckdb_result_error(&r)) : 0;
    duckdb_destroy_result(&r);
    return rc;
}

static void d_prepare(eng *g, int set)
{
    for (int i = 0; i < x_count(set); i++) {
        if (g->dst[set][i]) duckdb_destroy_prepare(&g->dst[set][i]);
        if (duckdb_prepare(g->dcon, x_texts(set)[i], &g->dst[set][i]) == DuckDBError) {
            d_fail(g, x_texts(set)[i], duckdb_prepare_error(g->dst[set][i]));
            exit(1);
        }
    }
}

static int d_run(eng *g, int set, int which, const int64_t *p, int n, const char *text, int64_t *out, int ncol, int cap,
                 int *nrows)
{
    duckdb_prepared_statement s = g->dst[set][which];
    for (int i = 0; i < n; i++)
        if (duckdb_bind_int64(s, (idx_t)i + 1, p[i]) == DuckDBError) return d_fail(g, x_texts(set)[which], "bind");
    if (text && duckdb_bind_varchar(s, (idx_t)n + 1, text) == DuckDBError) return d_fail(g, x_texts(set)[which], "bind");
    duckdb_result r;
    if (duckdb_execute_prepared(s, &r) == DuckDBError) {
        int rc = d_fail(g, x_texts(set)[which], duckdb_result_error(&r));
        duckdb_destroy_result(&r);
        return rc;
    }
    idx_t rows = out || nrows ? duckdb_row_count(&r) : 0, nc = duckdb_column_count(&r);
    for (idx_t i = 0; out && i < rows && i < (idx_t)cap; i++)
        for (idx_t c = 0; c < (idx_t)ncol && c < nc; c++)
            out[(size_t)i * (size_t)ncol + (size_t)c] = duckdb_value_is_null(&r, c, i) ? 0 : duckdb_value_int64(&r, c, i);
    duckdb_destroy_result(&r);
    if (nrows) *nrows = (int)rows;
    return 0;
}

/* EXPLAIN (FORMAT JSON): the operators depth first, each object's "name" before its children and its
 * "extra_info" ("Table", "Type", "Join Type") after them; kept as the operator, its table, and the
 * join type or a scan type other than sequential. The box drawing of the default format puts
 * sibling operators side by side on one line, which a line scan cannot pull apart. */
static void d_plan(eng *g, const char *sql, char *line, size_t cap, size_t *len)
{
    duckdb_result r;
    if (duckdb_query(g->dcon, sql, &r) == DuckDBError) {
        append(line, cap, len, duckdb_result_error(&r));
        duckdb_destroy_result(&r);
        return;
    }
    char *v = duckdb_row_count(&r) ? duckdb_value_varchar(&r, 1, 0) : NULL;
    char item[24][96], key[96] = "", str[96];
    int nitem = 0, depth = 0, at[64]; /* at[d]: the operator whose object opened at depth d */
    for (const char *s = v; s && *s; s++) {
        if (*s == '{' && depth < 63) {
            at[++depth] = -1;
        } else if (*s == '}' && depth > 0) {
            depth--;
        } else if (*s == '"') { /* a string: a key when a ':' follows it, else a value */
            size_t n = 0;
            for (s++; *s && *s != '"'; s++) {
                if (*s == '\\' && s[1]) s++;
                if (n + 1 < sizeof str) str[n++] = *s;
            }
            str[n] = 0;
            if (!*s) break;
            const char *c = s + 1;
            while (*c == ' ' || *c == '\n') c++;
            if (*c == ':') {
                snprintf(key, sizeof key, "%s", str);
                continue;
            }
            int op = depth >= 2 ? at[depth - 1] : -1; /* extra_info is an object inside its operator's */
            if (strcmp(key, "name") == 0 && nitem < 24) {
                at[depth] = nitem;
                snprintf(item[nitem++], sizeof item[0], "%s", str);
            } else if (op >= 0 && strcmp(key, "Table") == 0) {
                const char *t = strrchr(str, '.');
                size_t il = strlen(item[op]);
                snprintf(item[op] + il, sizeof item[0] - il, " %s", t ? t + 1 : str);
            } else if (op >= 0 && (strcmp(key, "Join Type") == 0 ||
                                   (strcmp(key, "Type") == 0 && strcmp(str, "Sequential Scan") != 0))) {
                size_t il = strlen(item[op]);
                snprintf(item[op] + il, sizeof item[0] - il, " (%s)", str);
            }
        }
    }
    for (int i = 0; i < nitem; i++) append(line, cap, len, item[i]);
    if (v) duckdb_free(v);
    duckdb_destroy_result(&r);
}

static void d_open(eng *g)
{
    if (duckdb_open(g->file, &g->ddb) == DuckDBError) die(g->name, "duckdb_open");
    if (duckdb_connect(g->ddb, &g->dcon) == DuckDBError) die(g->name, "duckdb_connect");
}

static void d_close(eng *g)
{
    for (int set = 0; set < 3; set++)
        for (int i = 0; i < NQ3; i++)
            if (g->dst[set][i]) duckdb_destroy_prepare(&g->dst[set][i]);
    duckdb_disconnect(&g->dcon);
    duckdb_close(&g->ddb);
}

/* the reopen comes after W5b, so only t's statements exist to prepare again */
static int d_reopen(eng *g)
{
    d_close(g);
    d_open(g);
    d_prepare(g, 0);
    return 0;
}

static void d_settings(eng *g)
{
    static const char *const q[][2] = {{"version", "SELECT version()"},
                                       {"threads", "SELECT current_setting('threads')"},
                                       {"memory_limit", "SELECT current_setting('memory_limit')"},
                                       {"checkpoint_threshold", "SELECT current_setting('checkpoint_threshold')"}};
    for (size_t i = 0; i < sizeof q / sizeof *q; i++) {
        duckdb_result r;
        char *v = duckdb_query(g->dcon, q[i][1], &r) == DuckDBError ? NULL : duckdb_value_varchar(&r, 0, 0);
        printf("%s setting %s %s\n", g->name, q[i][0], v ? v : "(unknown)");
        if (v) duckdb_free(v);
        duckdb_destroy_result(&r);
    }
}
#endif

/* ---- measures ------------------------------------------------------------------------------- */

static int cmp_d(const void *a, const void *b)
{
    double x = *(const double *)a, y = *(const double *)b;
    return x < y ? -1 : x > y;
}

static void report_lat(const char *eng_name, const char *w, double *lat, size_t n)
{
    qsort(lat, n, sizeof *lat, cmp_d);
    printf("%s %s p50 %.1f us\n", eng_name, w, lat[n / 2] * 1e6);
    printf("%s %s p95 %.1f us\n", eng_name, w, lat[(n * 95) / 100] * 1e6);
    printf("%s %s p99 %.1f us\n", eng_name, w, lat[(n * 99) / 100] * 1e6);
    for (int i = 0; i < g_nstall; i++) /* this workload's samples kept by stall() */
        if (g_stall[i].took > 10 * lat[n / 2]) {
            time_t s = (time_t)g_stall[i].at;
            struct tm tm;
            localtime_r(&s, &tm);
            printf("%s %s stall %.3f s at %02d:%02d:%02d.%03d\n", eng_name, w, g_stall[i].took, tm.tm_hour, tm.tm_min,
                   tm.tm_sec, (int)((g_stall[i].at - (double)s) * 1000));
        }
    g_nstall = 0;
}

/* resident and written bytes and CPU seconds of this process, or (postgres) of every process of
 * the instance */
static double g_cpu;
static void proc_mem_io(eng *g, uint64_t *pss, uint64_t *wbytes)
{
    *pss = *wbytes = 0;
    g_cpu = 0;
    long pids[512];
    int np = 0;
    if (g->pidfile) { /* the postmaster and its children (smaps_rollup Pss: shared memory counted once) */
        FILE *f = fopen(g->pidfile, "r");
        long pm = 0;
        if (f && fscanf(f, "%ld", &pm) == 1) pids[np++] = pm;
        if (f) fclose(f);
        /* every descendant, not only the children: a container's pid 1 can be a launcher whose child's
         * child is the server (SQL Server: launch_sqlservr.sh, a watchdog sqlservr, the engine) */
        static long pid[8192], ppid[8192];
        int nall = 0;
        FILE *p = pm ? popen("ps -e -o pid=,ppid=", "r") : NULL;
        while (p && nall < 8192 && fscanf(p, "%ld %ld", &pid[nall], &ppid[nall]) == 2) nall++;
        if (p) pclose(p);
        for (int k = 0; k < np && np < 512; k++) /* breadth first: pids[] grows as it is walked */
            for (int a = 0; a < nall && np < 512; a++)
                if (ppid[a] == pids[k]) pids[np++] = pid[a];
    } else {
        pids[np++] = (long)getpid();
    }
    for (int i = 0; i < np; i++) {
        char path[64], line[256];
        snprintf(path, sizeof path, "/proc/%ld/smaps_rollup", pids[i]);
        FILE *f = fopen(path, "r");
        while (f && fgets(line, sizeof line, f)) {
            unsigned long long kb;
            if (sscanf(line, "Pss: %llu kB", &kb) == 1) *pss += kb * 1024;
        }
        if (f) fclose(f);
        snprintf(path, sizeof path, "/proc/%ld/stat", pids[i]);
        f = fopen(path, "r");
        if (f && fgets(line, sizeof line, f)) { /* utime, stime, cutime, cstime: fields 14-17, after the (comm) */
            const char *q = strrchr(line, ')');
            unsigned long ut = 0, st = 0;
            long cut = 0, cst = 0;
            if (q && sscanf(q + 2, "%*c %*d %*d %*d %*d %*d %*u %*u %*u %*u %*u %lu %lu %ld %ld", &ut, &st, &cut, &cst) == 4) {
                g_cpu += (double)(ut + st) / (double)sysconf(_SC_CLK_TCK);
                /* the postmaster's exited children (autovacuum and other workers) */
                if (g->pidfile && i == 0) g_cpu += (double)(cut + cst) / (double)sysconf(_SC_CLK_TCK);
            }
        }
        if (f) fclose(f);
        snprintf(path, sizeof path, "/proc/%ld/io", pids[i]);
        f = fopen(path, "r");
        while (f && fgets(line, sizeof line, f)) {
            unsigned long long b;
            if (sscanf(line, "write_bytes: %llu", &b) == 1) *wbytes += b;
        }
        if (f) fclose(f);
    }
}

#define CHECKRC(x)                                                                                 \
    do {                                                                                           \
        if ((x) != 0) die(g->name, #x);                                                            \
    } while (0)

/* The CPU seconds of each phase (all threads of this process; for PostgreSQL every process of the
 * instance, not the driver's libpq side), so a phase's cost is not charged to the next one. */
static double g_cpu_mark;
static void phase_cpu(eng *g, const char *phase)
{
    uint64_t pss, w;
    proc_mem_io(g, &pss, &w);
    printf("%s %s cpu %.2f s\n", g->name, phase, g_cpu - g_cpu_mark);
    g_cpu_mark = g_cpu;
}

/* peak resident memory of this process (in-process engines only: summing VmHWM over the
 * PostgreSQL processes would count its shared buffers once per process) */
static void peak_rss(eng *g, const char *label)
{
    FILE *f = fopen("/proc/self/status", "r");
    char line[256];
    unsigned long long kb;
    while (f && fgets(line, sizeof line, f))
        if (sscanf(line, "VmHWM: %llu kB", &kb) == 1) printf("%s %s memory %.1f MB\n", g->name, label, (double)kb * 1024 / 1e6);
    if (f) fclose(f);
}

#ifdef SMOKE /* a 1/20 run: the driver works on this box, nothing measured */
enum { W1 = 25, W2_TX = 50, W2_ROWS = 100, W2B_TX = 1, LOOKUPS = 1000, SUMS = 50, SUBJ = 50, ROUNDS = 2, UPD_TX = 10,
       DEL_TX = 2, WIDE = 4, N2_TX = 5, SUMS2 = 10, UPD2_TX = 5 };
#else
enum { W1 = 500, W2_TX = 1000, W2_ROWS = 100, W2B_TX = 5, LOOKUPS = 20000, SUMS = 1000, SUBJ = 1000, ROUNDS = 5,
       UPD_TX = 100, DEL_TX = 50, WIDE = 20, N2_TX = 100, SUMS2 = 100, UPD2_TX = 100 };
#endif
/* W7 and W8: customers, orders, the customers with orders (each 12 or 13; CUST3 is prime to 7919),
 * the statements of each kind, the whole join's runs, W8b's transactions of 100 inserts */
#ifdef SMOKE
enum { NC3 = 1000, NO3 = 10000, CUST3 = 800, Q3N = 500, ALL3 = 2, INS3_TX = 2 };
#else
enum { NC3 = 20000, NO3 = 200000, CUST3 = 16000, Q3N = 10000, ALL3 = 10, INS3_TX = 10 };
#endif

/* W3, W4, W4b, after the load and again after the checkpoint (TAG says which) */
static void reads(eng *g, const char *tag, double *lat)
{
    int64_t total = (int64_t)W2_TX * W2_ROWS, v;
    char w[64];
    /* W3: point lookups by primary key */
    unsigned seed = 12345;
    for (int i = 0; i < LOOKUPS; i++) {
        seed = seed * 1103515245u + 12345u;
        int64_t id = (int64_t)(seed % (unsigned)total) + 1;
        double a = now();
        CHECKRC(g->lookup(g, id, &v));
        lat[i] = stall(a, now() - a);
        if (v != id) die(g->name, "lookup returned another value");
    }
    snprintf(w, sizeof w, "pk_lookup%s", tag);
    report_lat(g->name, w, lat, LOOKUPS);
    phase_cpu(g, w);

    /* W4: aggregates over a range of 1,000 keys */
    for (int i = 0; i < SUMS; i++) {
        int64_t lo = (int64_t)(i * 487) % (total - 1000) + 1;
        double a = now();
        CHECKRC(g->range_sum(g, lo, lo + 999, &v));
        lat[i] = stall(a, now() - a);
        if (v != 1000 * lo + 499500) die(g->name, "range sum returned another value"); /* amount = id */
    }
    snprintf(w, sizeof w, "range_sum_1000%s", tag);
    report_lat(g->name, w, lat, SUMS);
    phase_cpu(g, w);

    /* W4b: all the rows of one data subject (imagedb: its SUBJECT index; the others: an index) */
    for (int i = 0; i < SUBJ; i++) {
        double a = now();
        CHECKRC(g->subject_count(g, i % 97, &v));
        lat[i] = stall(a, now() - a);
    }
    snprintf(w, sizeof w, "subject_count%s", tag);
    report_lat(g->name, w, lat, SUBJ);
    phase_cpu(g, w);

    /* W4c: the same over all of W2's ids (2026-10-24: where imagedb's planner takes its scan) */
    for (int i = 0; i < WIDE; i++) {
        double a = now();
        CHECKRC(g->range_sum(g, 1, total, &v));
        lat[i] = stall(a, now() - a);
        if (v != total * (total + 1) / 2) die(g->name, "range sum returned another value");
    }
    snprintf(w, sizeof w, "range_sum_all%s", tag);
    report_lat(g->name, w, lat, WIDE);
    phase_cpu(g, w);
}

/* Each engine's checkpoint, timed. Different work, one purpose (bounding what a restart redoes):
 * imagedb writes the table to lake segments and publishes a manifest, so an open replays only the
 * log after it; SQLite copies its WAL into the database file; PostgreSQL flushes dirty pages. */
static void checkpoint(eng *g, const char *w)
{
    if (g->dialect == D_MYSQL || g->dialect == D_MARIADB) { /* nothing to time: InnoDB checkpoints on its own */
        printf("%s %s seconds n/a (InnoDB has no CHECKPOINT statement)\n", g->name, w);
        phase_cpu(g, w);
        return;
    }
    double t0 = now();
    CHECKRC(g->exec(g, g->lite ? "PRAGMA wal_checkpoint(TRUNCATE)" : "CHECKPOINT"));
    printf("%s %s seconds %.3f s\n", g->name, w, now() - t0);
    phase_cpu(g, w);
}

/* starts a phase's CPU count here, so work the driver does between phases (W6's model) is not
 * charged to the engine */
static void cpu_mark(eng *g)
{
    uint64_t pss, w;
    proc_mem_io(g, &pss, &w);
    g_cpu_mark = g_cpu;
}

/* W6: a secondary index on a scattered key, in a second table loaded after everything above (so
 * no R8 measure changes): the index built over loaded rows, ranges of 1,000 keys and the whole
 * key space through it, and updates that find their rows through it. k = id * 7919 mod 100,003
 * (a prime): distinct keys spread over 1..100,002, so a key range picks rows from all over the
 * table, unlike W4's ranges of id. Every answer is checked against a model of the table. */
enum { N2 = N2_TX * 1000, KMOD = 100003 };
static int64_t g_k[N2 + 1], g_v[N2 + 1], g_want[SUMS2 + 1];

static int64_t model_sum(int64_t lo, int64_t hi)
{
    int64_t s = 0;
    for (int64_t id = 1; id <= N2; id++)
        if (g_k[id] >= lo && g_k[id] <= hi) s += g_v[id];
    return s;
}

static int64_t w6_lo(int i, int step) { return (int64_t)i * step % (KMOD - 1000) + 1; }

static void w6_reads(eng *g, const char *tag, double *lat)
{
    char w[64];
    int64_t v;
    for (int i = 0; i < SUMS2; i++) g_want[i] = model_sum(w6_lo(i, 997), w6_lo(i, 997) + 999);
    g_want[SUMS2] = model_sum(1, KMOD - 1);
    cpu_mark(g);
    for (int i = 0; i < SUMS2; i++) {
        int64_t p[2] = {w6_lo(i, 997), w6_lo(i, 997) + 999};
        double a = now();
        CHECKRC(g->q2(g, Q2_SUM, p, 2, &v));
        lat[i] = stall(a, now() - a);
        if (v != g_want[i]) die(g->name, "W6 range sum returned another value");
    }
    snprintf(w, sizeof w, "w6_range_sum_1000%s", tag);
    report_lat(g->name, w, lat, SUMS2);
    phase_cpu(g, w);
    for (int i = 0; i < WIDE; i++) {
        int64_t p[2] = {1, KMOD - 1};
        double a = now();
        CHECKRC(g->q2(g, Q2_SUM, p, 2, &v));
        lat[i] = stall(a, now() - a);
        if (v != g_want[SUMS2]) die(g->name, "W6 range sum returned another value");
    }
    snprintf(w, sizeof w, "w6_range_sum_all%s", tag);
    report_lat(g->name, w, lat, WIDE);
    phase_cpu(g, w);
}

static void w6(eng *g, double *lat)
{
    CHECKRC(g->exec(g, g->db     ? "CREATE TABLE t2 (id INT64 PRIMARY KEY, k INT64 NOT NULL, v INT64 NOT NULL)"
                       : g->lite ? "CREATE TABLE t2 (id INTEGER PRIMARY KEY, k INTEGER NOT NULL, v INTEGER NOT NULL)"
                                 : "CREATE TABLE t2 (id BIGINT PRIMARY KEY, k BIGINT NOT NULL, v BIGINT NOT NULL)"));
    if (g->lite) l_prepare2(g);
    if (g->pg) p_prepare2(g);
#ifdef WITH_EXT
    if (g->prep) g->prep(g, 1);
#endif
    for (int64_t id = 1; id <= N2; id++) g_k[id] = id * 7919 % KMOD, g_v[id] = id;
    uint64_t pss0, w0, pss, w;
    proc_mem_io(g, &pss0, &w0);
    cpu_mark(g);
    /* W6a: the load, 1,000 rows per transaction, no index on k yet */
    double t0 = now();
    for (int k = 0; k < N2_TX; k++) {
        double a = now();
        CHECKRC(g->exec(g, "BEGIN"));
        for (int i = 0; i < 1000; i++) {
            int64_t id = (int64_t)k * 1000 + i + 1, p[3] = {id, g_k[id], g_v[id]};
            CHECKRC(g->q2(g, Q2_INS, p, 3, NULL));
        }
        CHECKRC(g->exec(g, "COMMIT"));
        lat[k] = stall(a, now() - a);
    }
    double dt = now() - t0;
    printf("%s w6_load_1000 rows_per_s %.0f /s\n", g->name, (double)N2 / dt);
    report_lat(g->name, "w6_load_1000", lat, N2_TX);
    phase_cpu(g, "w6_load_1000");
    /* W6b: the index, built over the loaded rows (durable when it returns, in all three) */
    t0 = now();
    CHECKRC(g->exec(g, "CREATE INDEX t2_k ON t2 (k)"));
    printf("%s w6_create_index seconds %.3f s\n", g->name, now() - t0);
    phase_cpu(g, "w6_create_index");
    w6_reads(g, "", lat);
    /* W6c: updates that find their rows through the index, 1,000 keys per transaction */
    t0 = now();
    for (int i = 0; i < UPD2_TX; i++) {
        int64_t lo = w6_lo(i, 1009), p[3] = {1000000 + i, lo, lo + 999};
        double a = now();
        CHECKRC(g->exec(g, "BEGIN"));
        CHECKRC(g->q2(g, Q2_UPD, p, 3, NULL));
        CHECKRC(g->exec(g, "COMMIT"));
        lat[i] = stall(a, now() - a);
    }
    dt = now() - t0;
    report_lat(g->name, "w6_update_1000", lat, UPD2_TX);
    phase_cpu(g, "w6_update_1000");
    uint64_t rows = 0; /* the model follows, after the clock */
    for (int i = 0; i < UPD2_TX; i++)
        for (int64_t id = 1, lo = w6_lo(i, 1009); id <= N2; id++)
            if (g_k[id] >= lo && g_k[id] <= lo + 999) g_v[id] = 1000000 + i, rows++;
    printf("%s w6_update_1000 rows_per_s %.0f /s (%llu rows)\n", g->name, (double)rows / dt, (unsigned long long)rows);
    cpu_mark(g);
    checkpoint(g, "w6_checkpoint");
    w6_reads(g, "_after_checkpoint", lat);
    proc_mem_io(g, &pss, &w);
    printf("%s after_w6 memory %.1f MB (W6 added %.1f MB)\n", g->name, (double)pss / 1e6,
           ((double)pss - (double)pss0) / 1e6);
    printf("%s w6 written %.1f MB\n", g->name, (double)(w - w0) / 1e6);
}

/* W7 and W8 (2026-10-26): two more tables, loaded after W6 (so no earlier measure changes):
 * customers c (region = id % 100, name 'c<id>') and orders o (cust = id * 7919 mod CUST3 + 1, so
 * an order's customer is scattered, the customers up to CUST3 have 12 or 13 orders and the rest
 * none; amount = id % 1,000), indexed alike in all three, o (cust) and c (region), and imagedb's id
 * columns ordered, as t's is. W7: joins: a point join, one customer's orders, a region's customers
 * without one (an anti-join), the whole join by region. W8: a two-column index and a unique one,
 * each built over the loaded rows. Every answer is checked against a model of the tables. */
static int32_t g_ocust[NO3 + 1], g_cfirst[NC3 + 2], g_cord[NO3];
static int64_t g_ccount[NC3 + 1], g_csum[NC3 + 1], g_rsum[100], g_rnone[100], g_want8[Q3N];

static void w7_model(void)
{
    for (int64_t id = 1; id <= NO3; id++) {
        int32_t c = (int32_t)(id * 7919 % CUST3) + 1;
        g_ocust[id] = c;
        g_ccount[c]++;
        g_csum[c] += id % 1000;
        g_rsum[c % 100] += id % 1000;
    }
    for (int c = 1; c <= NC3; c++) {
        if (!g_ccount[c]) g_rnone[c % 100]++;
        g_cfirst[c + 1] = g_cfirst[c] + (int32_t)g_ccount[c];
    }
    static int32_t at[NC3 + 2]; /* each customer's orders, in id order */
    memcpy(at, g_cfirst, sizeof at);
    for (int64_t id = 1; id <= NO3; id++) g_cord[at[g_ocust[id]]++] = (int32_t)id;
}

static void append(char *line, size_t cap, size_t *len, const char *s)
{
    if (*len + 1 >= cap) return;
    int k = snprintf(line + *len, cap - *len, "%s%s", *len ? "; " : "", s);
    if (k > 0) *len = *len + (size_t)k < cap ? *len + (size_t)k : cap - 1;
}

/* The plan each engine ran for a Q3 statement, on one line: imagedb's path (its last run's), SQLite's
 * EXPLAIN QUERY PLAN, PostgreSQL's EXPLAIN (COSTS OFF) of the prepared statement with the last
 * parameters. After the phase's clock and CPU count, and charged to no phase. */
static void plan_line(eng *g, const char *w, int which, const int64_t *p, int n, const char *text)
{
    char line[512] = "";
    size_t len = 0;
    if (g->db) snprintf(line, sizeof line, "%s", g->plan3[which]);
    if (g->lite) {
        char sql[512];
        sqlite3_stmt *s;
        snprintf(sql, sizeof sql, "EXPLAIN QUERY PLAN %s", kQ3lite[which]);
        if (sqlite3_prepare_v2(g->lite, sql, -1, &s, NULL)) die("sqlite prepare", sqlite3_errmsg(g->lite));
        for (int i = 0; i < n; i++) sqlite3_bind_int64(s, i + 1, p[i]);
        if (text) sqlite3_bind_text(s, n + 1, text, -1, SQLITE_STATIC);
        while (sqlite3_step(s) == SQLITE_ROW) {
            const char *d = (const char *)sqlite3_column_text(s, 3);
            append(line, sizeof line, &len, d ? d : "?");
        }
        sqlite3_finalize(s);
    }
    if (g->pg) { /* the values are the driver's own (digits, 'c' and digits), so they are written inline */
        char args[128] = "", sql[256];
        size_t al = 0;
        for (int i = 0; i < n && al < sizeof args; i++)
            al += (size_t)snprintf(args + al, sizeof args - al, "%s%lld", i ? ", " : "", (long long)p[i]);
        if (text && al < sizeof args) snprintf(args + al, sizeof args - al, "%s'%s'", n ? ", " : "", text);
        snprintf(sql, sizeof sql, "EXPLAIN (COSTS OFF) EXECUTE q3_%d%s%s%s", which, args[0] ? "(" : "", args, args[0] ? ")" : "");
        PGresult *r = PQexec(g->pg, sql);
        if (!p_check(g, r, sql)) {
            for (int i = 0; i < PQntuples(r); i++) {
                const char *s = PQgetvalue(r, i, 0);
                while (*s == ' ') s++;
                if (strncmp(s, "->  ", 4) == 0) s += 4;
                append(line, sizeof line, &len, s);
            }
            PQclear(r);
        }
    }
#ifdef WITH_EXT
    if (g->plan) { /* the statement with the values written in, through each one's own EXPLAIN */
        char lit[512], sql[600];
        inline_values(kQ3[which], p, n, text, lit, sizeof lit);
        snprintf(sql, sizeof sql, "%s%s",
                 g->dialect == D_MYSQL    ? "EXPLAIN FORMAT=TREE "
                 : g->dialect == D_MSSQL  ? ""
                 : g->dialect == D_DUCKDB ? "EXPLAIN (FORMAT JSON) "
                                          : "EXPLAIN ",
                 lit);
        g->plan(g, sql, line, sizeof line, &len);
    }
#endif
    printf("%s %s plan %s\n", g->name, w, line);
    cpu_mark(g);
}

/* W7d's runs, each answer checked: 100 rows, one per region, in any order */
static void w7_all(eng *g, double *lat)
{
    int64_t out[200];
    int n;
    for (int i = 0; i < ALL3; i++) {
        double a = now();
        CHECKRC(g->q3(g, Q3_ALL, NULL, 0, NULL, out, 2, 100, &n));
        lat[i] = stall(a, now() - a);
        bool seen[100] = {false}, bad = n != 100;
        for (int k = 0; !bad && k < n; k++) {
            int64_t r = out[2 * k];
            bad = r < 0 || r >= 100 || seen[r] || out[2 * k + 1] != g_rsum[r];
            if (!bad) seen[r] = true;
        }
        if (bad) die(g->name, "W7d returned other rows");
    }
}

static void w7_reads(eng *g, const char *tag, double *lat)
{
    char w[64];
    int64_t out[200], id = 0;
    int n;
    cpu_mark(g);
    /* W7a: a point join: an order by its primary key, its customer by theirs */
    unsigned seed = 4242;
    for (int i = 0; i < Q3N; i++) {
        seed = seed * 1103515245u + 12345u;
        id = (int64_t)(seed % (unsigned)NO3) + 1;
        double a = now();
        CHECKRC(g->q3(g, Q3_POINT, &id, 1, NULL, out, 2, 1, &n));
        lat[i] = stall(a, now() - a);
        if (n != 1 || out[0] != g_ocust[id] % 100 || out[1] != id % 1000) die(g->name, "W7a returned another row");
    }
    snprintf(w, sizeof w, "w7_point_join%s", tag);
    report_lat(g->name, w, lat, Q3N);
    phase_cpu(g, w);
    plan_line(g, w, Q3_POINT, &id, 1, NULL);
    /* W7b: one customer's orders, counted and summed (a fifth of the customers have none) */
    for (int i = 0; i < Q3N; i++) {
        id = (int64_t)i * 7 % NC3 + 1;
        double a = now();
        CHECKRC(g->q3(g, Q3_CUST, &id, 1, NULL, out, 2, 1, &n));
        lat[i] = stall(a, now() - a);
        if (n != 1 || out[0] != g_ccount[id] || out[1] != g_csum[id]) die(g->name, "W7b returned another count or sum");
    }
    snprintf(w, sizeof w, "w7_customer_orders%s", tag);
    report_lat(g->name, w, lat, Q3N);
    phase_cpu(g, w);
    plan_line(g, w, Q3_CUST, &id, 1, NULL);
    /* W7c: the anti-join: a region's customers without an order */
    for (int i = 0; i < 100; i++) {
        id = i;
        double a = now();
        CHECKRC(g->q3(g, Q3_ANTI, &id, 1, NULL, out, 1, 1, &n));
        lat[i] = stall(a, now() - a);
        if (n != 1 || out[0] != g_rnone[i]) die(g->name, "W7c returned another count");
    }
    snprintf(w, sizeof w, "w7_anti_join%s", tag);
    report_lat(g->name, w, lat, 100);
    phase_cpu(g, w);
    plan_line(g, w, Q3_ANTI, &id, 1, NULL);
    /* W7d: the whole join, summed by region */
    w7_all(g, lat);
    snprintf(w, sizeof w, "w7_join_by_region%s", tag);
    report_lat(g->name, w, lat, ALL3);
    phase_cpu(g, w);
    plan_line(g, w, Q3_ALL, NULL, 0, NULL);
    if (g->db) { /* imagedb only: the same join with the hash join forced (SET join_plan = hash), beside its planner's choice */
        g->ss.join_plan = IMDB_JOIN_HASH;
        w7_all(g, lat);
        g->ss.join_plan = IMDB_JOIN_AUTO;
        snprintf(w, sizeof w, "w7_join_by_region_forced_hash%s", tag);
        report_lat(g->name, w, lat, ALL3);
        phase_cpu(g, w);
        plan_line(g, w, Q3_ALL, NULL, 0, NULL);
    }
}

static void w7(eng *g, double *lat)
{
    if (g->db) {
        CHECKRC(g->exec(g, "CREATE TABLE c (id INT64 PRIMARY KEY, region INT64 NOT NULL, name TEXT NOT NULL)"));
        CHECKRC(g->exec(g, "CREATE TABLE o (id INT64 PRIMARY KEY, cust INT64 NOT NULL, amount INT64 NOT NULL)"));
        if (!g->noindex) CHECKRC(g->exec(g, "CREATE INDEX c_id ON c (id)"));
        if (!g->noindex) CHECKRC(g->exec(g, "CREATE INDEX o_id ON o (id)"));
    } else if (g->lite) {
        CHECKRC(g->exec(g, "CREATE TABLE c (id INTEGER PRIMARY KEY, region INTEGER NOT NULL, name TEXT NOT NULL)"));
        CHECKRC(g->exec(g, "CREATE TABLE o (id INTEGER PRIMARY KEY, cust INTEGER NOT NULL, amount INTEGER NOT NULL)"));
    } else if (g->dialect == D_MYSQL || g->dialect == D_MARIADB || g->dialect == D_MSSQL) {
        /* a unique index on a TEXT column is refused by both: a bounded VARCHAR, compared byte by byte as
         * in the others (PostgreSQL's C locale) */
        CHECKRC(g->exec(g, g->dialect == D_MSSQL ? "CREATE TABLE c (id BIGINT PRIMARY KEY, region BIGINT NOT NULL, name "
                                                   "VARCHAR(64) COLLATE Latin1_General_BIN2 NOT NULL)"
                                                 : "CREATE TABLE c (id BIGINT PRIMARY KEY, region BIGINT NOT NULL, name "
                                                   "VARCHAR(64) NOT NULL) DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin"));
        CHECKRC(g->exec(g, "CREATE TABLE o (id BIGINT PRIMARY KEY, cust BIGINT NOT NULL, amount BIGINT NOT NULL)"));
    } else {
        CHECKRC(g->exec(g, "CREATE TABLE c (id BIGINT PRIMARY KEY, region BIGINT NOT NULL, name TEXT NOT NULL)"));
        CHECKRC(g->exec(g, "CREATE TABLE o (id BIGINT PRIMARY KEY, cust BIGINT NOT NULL, amount BIGINT NOT NULL)"));
    }
    CHECKRC(g->exec(g, "CREATE INDEX c_region ON c (region)"));
    CHECKRC(g->exec(g, "CREATE INDEX o_cust ON o (cust)"));
    if (g->lite) l_prepare3(g);
    if (g->pg) p_prepare3(g);
#ifdef WITH_EXT
    if (g->prep) g->prep(g, 2);
#endif
    w7_model();
    uint64_t pss0, w0, pss, w;
    proc_mem_io(g, &pss0, &w0);
    cpu_mark(g);
    /* the load: the customers, then the orders, 1,000 rows per transaction, the indexes kept as it goes */
    double t0 = now();
    int k = 0;
    for (int b = 0; b < NC3 / 1000; b++) {
        double a = now();
        CHECKRC(g->exec(g, "BEGIN"));
        for (int i = 0; i < 1000; i++) {
            int64_t p[2] = {(int64_t)b * 1000 + i + 1, ((int64_t)b * 1000 + i + 1) % 100};
            char name[24];
            snprintf(name, sizeof name, "c%lld", (long long)p[0]);
            CHECKRC(g->q3(g, Q3_INSC, p, 2, name, NULL, 0, 0, NULL));
        }
        CHECKRC(g->exec(g, "COMMIT"));
        lat[k++] = stall(a, now() - a);
    }
    for (int b = 0; b < NO3 / 1000; b++) {
        double a = now();
        CHECKRC(g->exec(g, "BEGIN"));
        for (int i = 0; i < 1000; i++) {
            int64_t id = (int64_t)b * 1000 + i + 1, p[3] = {id, g_ocust[id], id % 1000};
            CHECKRC(g->q3(g, Q3_INSO, p, 3, NULL, NULL, 0, 0, NULL));
        }
        CHECKRC(g->exec(g, "COMMIT"));
        lat[k++] = stall(a, now() - a);
    }
    double dt = now() - t0;
    printf("%s w7_load_1000 rows_per_s %.0f /s\n", g->name, (double)(NC3 + NO3) / dt);
    report_lat(g->name, "w7_load_1000", lat, (size_t)k);
    phase_cpu(g, "w7_load_1000");
    if (!g->db) { /* their planners read statistics; imagedb keeps none (its plans come from its structures) */
        t0 = now();
        if (g->dialect == D_MYSQL || g->dialect == D_MARIADB) {
            CHECKRC(g->exec(g, "ANALYZE TABLE c, o"));
        } else if (g->dialect == D_MSSQL) {
            CHECKRC(g->exec(g, "UPDATE STATISTICS c"));
            CHECKRC(g->exec(g, "UPDATE STATISTICS o"));
        } else {
            CHECKRC(g->exec(g, "ANALYZE"));
        }
        printf("%s w7_analyze seconds %.3f s\n", g->name, now() - t0);
        phase_cpu(g, "w7_analyze");
    }
    if (g->lite) { /* prepared again, so the timed statements are planned with the statistics, as EXPLAIN's are */
        for (int i = 0; i < NQ3; i++) sqlite3_finalize(g->s3[i]);
        l_prepare3(g);
        cpu_mark(g);
    }
#ifdef WITH_EXT
    if (g->prep) { /* the same */
        g->prep(g, 2);
        cpu_mark(g);
    }
#endif
    w7_reads(g, "", lat);
    checkpoint(g, "w7_checkpoint");
    w7_reads(g, "_after_checkpoint", lat);
    proc_mem_io(g, &pss, &w);
    printf("%s after_w7 memory %.1f MB (W7 added %.1f MB)\n", g->name, (double)pss / 1e6, ((double)pss - (double)pss0) / 1e6);
    printf("%s w7 written %.1f MB\n", g->name, (double)(w - w0) / 1e6);
}

static void w8(eng *g, double *lat)
{
    char name[24];
    int64_t out[2], p[3] = {0, 0, 0};
    int n;
    for (int i = 0; i < Q3N; i++) { /* W8a's answers, before the clock */
        int64_t c = (int64_t)i * 13 % CUST3 + 1, lo = (int64_t)i * 37 % 900;
        g_want8[i] = 0;
        for (int32_t x = g_cfirst[c]; x < g_cfirst[c + 1]; x++) g_want8[i] += g_cord[x] % 1000 >= lo && g_cord[x] % 1000 <= lo + 99;
    }
    cpu_mark(g);
    /* W8a: a two-column index, built over the loaded orders, then counts through it (an equality and a range) */
    double t0 = now();
    CHECKRC(g->exec(g, "CREATE INDEX o_ca ON o (cust, amount)"));
    printf("%s w8_create_index_2col seconds %.3f s\n", g->name, now() - t0);
    phase_cpu(g, "w8_create_index_2col");
    for (int i = 0; i < Q3N; i++) {
        p[0] = (int64_t)i * 13 % CUST3 + 1, p[1] = (int64_t)i * 37 % 900, p[2] = p[1] + 99;
        double a = now();
        CHECKRC(g->q3(g, Q3_CA, p, 3, NULL, out, 1, 1, &n));
        lat[i] = stall(a, now() - a);
        if (n != 1 || out[0] != g_want8[i]) die(g->name, "W8a returned another count");
    }
    report_lat(g->name, "w8_two_column_count", lat, Q3N);
    phase_cpu(g, "w8_two_column_count");
    plan_line(g, "w8_two_column_count", Q3_CA, p, 3, NULL);
    /* W8b: a unique index on the names, lookups through it, inserts it checks, and a duplicate it refuses */
    t0 = now();
    CHECKRC(g->exec(g, "CREATE UNIQUE INDEX c_name ON c (name)"));
    printf("%s w8_create_unique_index seconds %.3f s\n", g->name, now() - t0);
    phase_cpu(g, "w8_create_unique_index");
    for (int i = 0; i < Q3N; i++) {
        int64_t id = (int64_t)i * 7919 % NC3 + 1;
        snprintf(name, sizeof name, "c%lld", (long long)id);
        double a = now();
        CHECKRC(g->q3(g, Q3_NAME, NULL, 0, name, out, 1, 1, &n));
        lat[i] = stall(a, now() - a);
        if (n != 1 || out[0] != id % 100) die(g->name, "W8b returned another row");
    }
    report_lat(g->name, "w8_unique_lookup", lat, Q3N);
    phase_cpu(g, "w8_unique_lookup");
    plan_line(g, "w8_unique_lookup", Q3_NAME, NULL, 0, name);
    t0 = now();
    for (int b = 0; b < INS3_TX; b++) {
        double a = now();
        CHECKRC(g->exec(g, "BEGIN"));
        for (int i = 0; i < 100; i++) {
            p[0] = NC3 + (int64_t)b * 100 + i + 1, p[1] = p[0] % 100;
            snprintf(name, sizeof name, "c%lld", (long long)p[0]);
            CHECKRC(g->q3(g, Q3_INSC, p, 2, name, NULL, 0, 0, NULL));
        }
        CHECKRC(g->exec(g, "COMMIT"));
        lat[b] = stall(a, now() - a);
    }
    double dt = now() - t0;
    printf("%s w8_unique_insert_100 rows_per_s %.0f /s\n", g->name, (double)INS3_TX * 100 / dt);
    report_lat(g->name, "w8_unique_insert_100", lat, INS3_TX);
    phase_cpu(g, "w8_unique_insert_100");
    /* a new customer under a taken name, in a statement of its own: every engine must refuse it */
    fprintf(stderr, "whole: %s: W8b inserts a duplicate name, which must be refused:\n", g->name);
    p[0] = NC3 + 100000, p[1] = 0;
    if (g->q3(g, Q3_INSC, p, 2, "c1", NULL, 0, 0, NULL) == 0) die(g->name, "W8b: a duplicate name was accepted");
    CHECKRC(g->q3(g, Q3_COUNTC, NULL, 0, NULL, out, 1, 1, &n));
    if (n != 1 || out[0] != NC3 + INS3_TX * 100) die(g->name, "W8b: another number of customers");
    printf("%s w8_duplicate_name refused\n", g->name);
}

#ifdef WITH_EXT
/* whole ping mysql|mariadb SOCKET USER PASSWORD | ping sqlserver: connect, read row 1 of t, exit 0;
 * bench/whole.sh times a server's restart up to this answer, through the run's own client library.
 * ping sqlserver-up: a login and SELECT 1, before the benchmark's database exists. ping
 * sqlserver-shutdown: T-SQL SHUTDOWN, the clean stop (the server ends the connection: no answer). */
static int ping(int argc, char **argv)
{
    eng G;
    memset(&G, 0, sizeof G);
    eng *g = &G;
    g->name = argv[1];
    int rc = 2;
    bool up = strcmp(argv[1], "sqlserver-up") == 0, down = strcmp(argv[1], "sqlserver-shutdown") == 0;
    if ((strcmp(argv[1], "mysql") == 0 || strcmp(argv[1], "mariadb") == 0) && argc == 5) {
        m_connect(g, argv[2], argv[3], argv[4]);
        rc = m_exec(g, "SELECT amount FROM t WHERE id = 1") ? 1 : 0;
        mysql_close(g->my);
    } else if (down && argc == 2) {
        o_connect(g, false, false);
        (void)o_exec(g, "SHUTDOWN");
        return 0;
    } else if ((up || strcmp(argv[1], "sqlserver") == 0) && argc == 2) {
        o_connect(g, !up, false);
        rc = o_exec(g, up ? "SELECT 1" : "SELECT amount FROM t WHERE id = 1") ? 1 : 0;
        SQLDisconnect(g->odbc);
        SQLFreeHandle(SQL_HANDLE_DBC, g->odbc);
        SQLFreeHandle(SQL_HANDLE_ENV, g->oenv);
    } else {
        fputs("usage: whole ping mysql|mariadb SOCKET USER PASSWORD | ping sqlserver[-up|-shutdown]\n", stderr);
    }
    return rc;
}
#endif

int main(int argc, char **argv)
{
    setvbuf(stdout, NULL, _IOLBF, 0); /* a line at a time, so a message on stderr never splits one (W8b's refusal did) */
    if (argc < 3) {
        fputs("usage: whole imagedb DIR [--durable-ack | --no-index] | sqlite FILE | postgres CONNINFO PIDFILE [NAME]"
#ifdef WITH_EXT
              " | mysql|mariadb SOCKET USER PASSWORD PIDFILE | sqlserver PIDFILE | duckdb FILE | ping ENGINE ARGS"
#endif
              "\n",
              stderr);
        return 2;
    }
#ifdef WITH_EXT
    if (strcmp(argv[1], "ping") == 0) return ping(argc - 1, argv + 1);
#endif
    eng G;
    memset(&G, 0, sizeof G);
    eng *g = &G;
    if (strcmp(argv[1], "imagedb") == 0) {
        g->dialect = D_IMAGEDB;
        g->dir = argv[2];
        g->strict = argc > 3 && strcmp(argv[3], "--durable-ack") == 0;
        g->noindex = argc > 3 && strcmp(argv[3], "--no-index") == 0; /* R8's imagedb: no ordered index on id */
        g->name = g->strict ? "imagedb-durable-ack" : g->noindex ? "imagedb-noindex" : "imagedb";
        imdb_err e = {0};
        if (imdb_init(g->dir, false, NULL, &e)) die("imagedb init", e.msg);
        i_open(g);
        g->exec = i_exec, g->insert = i_insert, g->lookup = i_lookup, g->range_sum = i_sum, g->update_range = i_update,
        g->reopen = i_reopen, g->subject_count = i_subject, g->delete_range = i_delete, g->q2 = i_q2, g->q3 = i_q3;
        CHECKRC(g->exec(g, "CREATE TABLE t (id INT64 PRIMARY KEY, user_id INT64 SUBJECT, amount INT64 NOT NULL, "
                           "memo TEXT NOT NULL)"));
        /* the others' primary keys are B-trees, ordered: imagedb's is a hash, so it gets an ordered
         * index too, before the load, and pays its upkeep through every phase as they do theirs */
        if (!g->noindex) CHECKRC(g->exec(g, "CREATE INDEX t_id ON t (id)"));
    } else if (strcmp(argv[1], "sqlite") == 0) {
        g->dialect = D_SQLITE;
        g->name = "sqlite";
        g->file = argv[2];
        l_open(g);
        printf("sqlite setting version %s\n", sqlite3_libversion());
        g->exec = l_exec, g->insert = l_insert, g->lookup = l_lookup, g->range_sum = l_sum, g->update_range = l_update,
        g->reopen = l_reopen, g->subject_count = l_subject, g->delete_range = l_delete, g->q2 = l_q2, g->q3 = l_q3;
        CHECKRC(g->exec(g, "CREATE TABLE t (id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL, amount INTEGER NOT NULL, "
                           "memo TEXT NOT NULL)"));
        CHECKRC(g->exec(g, "CREATE INDEX t_user ON t (user_id)")); /* imagedb's SUBJECT column is indexed */
        l_prepare(g);
    } else if (strcmp(argv[1], "postgres") == 0 && (argc == 4 || argc == 5)) {
        g->dialect = D_PG;
        g->name = argc == 5 ? argv[4] : "postgres"; /* postgres-docker: the container-overhead control */
        g->pidfile = argv[3];
        g->pg = PQconnectdb(argv[2]);
        if (PQstatus(g->pg) != CONNECTION_OK) die("postgres connect", PQerrorMessage(g->pg));
        p_settings(g);
        g->exec = p_exec, g->insert = p_insert, g->lookup = p_lookup, g->range_sum = p_sum, g->update_range = p_update;
        g->subject_count = p_subject, g->delete_range = p_delete, g->q2 = p_q2, g->q3 = p_q3;
        CHECKRC(g->exec(g, "CREATE TABLE t (id BIGINT PRIMARY KEY, user_id BIGINT NOT NULL, amount BIGINT NOT NULL, "
                           "memo TEXT NOT NULL)"));
        CHECKRC(g->exec(g, "CREATE INDEX t_user ON t (user_id)"));
        p_prepare(g);
#ifdef WITH_EXT
    } else if ((strcmp(argv[1], "mysql") == 0 || strcmp(argv[1], "mariadb") == 0) && argc == 6) {
        g->dialect = argv[1][1] == 'y' ? D_MYSQL : D_MARIADB;
        g->name = argv[1];
        g->pidfile = argv[5];
        m_connect(g, argv[2], argv[3], argv[4]);
        g->exec = m_exec, g->run = m_run, g->prep = m_prepare, g->plan = m_plan;
        x_engine(g);
        m_settings(g);
        CHECKRC(g->exec(g, "CREATE TABLE t (id BIGINT PRIMARY KEY, user_id BIGINT NOT NULL, amount BIGINT NOT NULL, "
                           "memo VARCHAR(255) NOT NULL) DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin"));
        CHECKRC(g->exec(g, "CREATE INDEX t_user ON t (user_id)"));
        g->prep(g, 0);
    } else if (strcmp(argv[1], "sqlserver") == 0 && argc == 3) {
        g->dialect = D_MSSQL;
        g->name = "sqlserver";
        g->pidfile = argv[2];
        o_connect(g, true, true);
        g->exec = o_exec, g->run = o_run, g->prep = o_prepare, g->plan = o_plan;
        x_engine(g);
        o_settings(g);
        CHECKRC(g->exec(g, "CREATE TABLE t (id BIGINT PRIMARY KEY, user_id BIGINT NOT NULL, amount BIGINT NOT NULL, "
                           "memo VARCHAR(255) COLLATE Latin1_General_BIN2 NOT NULL)"));
        CHECKRC(g->exec(g, "CREATE INDEX t_user ON t (user_id)"));
        g->prep(g, 0);
    } else if (strcmp(argv[1], "duckdb") == 0 && argc == 3) {
        g->dialect = D_DUCKDB;
        g->name = "duckdb";
        g->file = argv[2];
        d_open(g);
        g->exec = d_exec, g->run = d_run, g->prep = d_prepare, g->plan = d_plan, g->reopen = d_reopen;
        x_engine(g);
        d_settings(g);
        CHECKRC(g->exec(g, "CREATE TABLE t (id BIGINT PRIMARY KEY, user_id BIGINT NOT NULL, amount BIGINT NOT NULL, "
                           "memo VARCHAR NOT NULL)"));
        CHECKRC(g->exec(g, "CREATE INDEX t_user ON t (user_id)"));
        g->prep(g, 0);
#endif
    } else {
        die("usage", "unknown engine, or its arguments");
    }
    /* bench/whole.sh's durability check (WHOLE_SYNCS): after the setup above, N single-row commits,
     * each its own transaction, and nothing else. It waits for a line on stdin first, so that strace
     * attaches after the setup, and counts only what the commits do. */
    const char *nchk = getenv("WHOLE_COMMITS");
    if (nchk) {
        int n = atoi(nchk);
        printf("%s ready for %d commits\n", g->name, n);
        if (getchar() == EOF) die(g->name, "no go on stdin");
        for (int i = 0; i < n; i++) CHECKRC(g->insert(g, 9000000 + i, i % 97, i, "durability check"));
        printf("%s commits %d done\n", g->name, n);
        goto done;
    }
    const char *memo = "a memo of a typical length for a row in this table";
    double *lat = calloc(LOOKUPS, sizeof *lat);
    if (!lat) die("alloc", "latencies");
    uint64_t pss0, w0, pss, w;
    proc_mem_io(g, &pss0, &w0);
    g_cpu_mark = g_cpu;

    /* W1: single-row transactions, each durable when it returns */
    double t0 = now();
    for (int i = 0; i < W1; i++) {
        double a = now();
        CHECKRC(g->insert(g, 1000000 + i, i % 97, i, memo));
        lat[i] = stall(a, now() - a);
    }
    double dt = now() - t0;
    printf("%s single_row_commit commits_per_s %.0f /s\n", g->name, W1 / dt);
    report_lat(g->name, "single_row_commit", lat, W1);
    phase_cpu(g, "single_row_commit");

    /* W2: 100 rows per transaction */
    t0 = now();
    for (int k = 0; k < W2_TX; k++) {
        double a = now();
        CHECKRC(g->exec(g, "BEGIN"));
        for (int i = 0; i < W2_ROWS; i++) {
            int64_t id = (int64_t)k * W2_ROWS + i + 1;
            CHECKRC(g->insert(g, id, id % 97, id, memo));
        }
        CHECKRC(g->exec(g, "COMMIT"));
        lat[k] = stall(a, now() - a);
    }
    dt = now() - t0;
    printf("%s batch_insert_100 rows_per_s %.0f /s\n", g->name, (double)W2_TX * W2_ROWS / dt);
    report_lat(g->name, "batch_insert_100", lat, W2_TX);
    phase_cpu(g, "batch_insert_100");
    proc_mem_io(g, &pss, &w);
    printf("%s after_load memory %.1f MB\n", g->name, (double)pss / 1e6);
    printf("%s after_load written %.1f MB\n", g->name, (double)(w - w0) / 1e6);
    printf("%s after_load cumulative_cpu %.2f s\n", g->name, g_cpu);

    /* W2b: 10,000 rows per transaction */
    t0 = now();
    for (int k = 0; k < W2B_TX; k++) {
        double a = now();
        CHECKRC(g->exec(g, "BEGIN"));
        for (int i = 0; i < 10000; i++) {
            int64_t id = 5000000 + (int64_t)k * 10000 + i;
            CHECKRC(g->insert(g, id, id % 97, id, memo));
        }
        CHECKRC(g->exec(g, "COMMIT"));
        lat[k] = stall(a, now() - a);
    }
    dt = now() - t0;
    printf("%s batch_insert_10000 rows_per_s %.0f /s\n", g->name, (double)W2B_TX * 10000 / dt);
    report_lat(g->name, "batch_insert_10000", lat, W2B_TX);
    phase_cpu(g, "batch_insert_10000");

    reads(g, "", lat);
    checkpoint(g, "checkpoint_after_load");
    proc_mem_io(g, &pss, &w);
    printf("%s after_checkpoint memory %.1f MB\n", g->name, (double)pss / 1e6);
    reads(g, "_after_checkpoint", lat);
    int64_t total = (int64_t)W2_TX * W2_ROWS;

    /* W5: churn: every live row updated once per round, 1,000 rows per transaction */
    uint64_t seq_w5 = g->db ? g->db->seq : 0;
    uint64_t wc0 = 0, pc0 = 0;
    proc_mem_io(g, &pc0, &wc0);
    t0 = now();
    int nlat = 0;
    for (int r = 0; r < ROUNDS; r++)
        for (int k = 0; k < UPD_TX; k++) {
            int64_t lo = (int64_t)k * (total / UPD_TX) + 1;
            double a = now();
            CHECKRC(g->exec(g, "BEGIN"));
            CHECKRC(g->update_range(g, lo, lo + total / UPD_TX - 1, r));
            CHECKRC(g->exec(g, "COMMIT"));
            lat[nlat++] = stall(a, now() - a);
        }
    dt = now() - t0;
    printf("%s churn_update_1000 rows_per_s %.0f /s\n", g->name, (double)ROUNDS * total / dt);
    report_lat(g->name, "churn_update_1000", lat, (size_t)nlat);
    phase_cpu(g, "churn_update_1000");
    if (g->db)
        printf("%s churn_update_1000 commits %llu (%d transactions; the rest are automatic CHECKPOINTs)\n", g->name,
               (unsigned long long)(g->db->seq - seq_w5), ROUNDS * UPD_TX);
    uint64_t seq_w5b = g->db ? g->db->seq : 0;
    proc_mem_io(g, &pss, &w);
    printf("%s after_churn memory %.1f MB\n", g->name, (double)pss / 1e6);
    printf("%s churn written %.1f MB\n", g->name, (double)(w - wc0) / 1e6);

    /* W5b: delete churn: 1,000-key ranges deleted and inserted again, a transaction each */
    t0 = now();
    nlat = 0;
    for (int k = 0; k < DEL_TX; k++) {
        int64_t lo = (int64_t)k * 1000 + 1;
        double a = now();
        CHECKRC(g->exec(g, "BEGIN"));
        CHECKRC(g->delete_range(g, lo, lo + 999));
        CHECKRC(g->exec(g, "COMMIT"));
        CHECKRC(g->exec(g, "BEGIN"));
        for (int64_t id = lo; id <= lo + 999; id++) CHECKRC(g->insert(g, id, id % 97, id, memo));
        CHECKRC(g->exec(g, "COMMIT"));
        lat[nlat++] = stall(a, now() - a);
    }
    dt = now() - t0;
    printf("%s delete_reinsert_1000 rows_per_s %.0f /s\n", g->name, (double)DEL_TX * 2000 / dt);
    report_lat(g->name, "delete_reinsert_1000", lat, (size_t)nlat);
    phase_cpu(g, "delete_reinsert_1000");
    if (g->db)
        printf("%s delete_reinsert_1000 commits %llu (%d transactions; the rest are automatic CHECKPOINTs)\n", g->name,
               (unsigned long long)(g->db->seq - seq_w5b), 2 * DEL_TX);
    proc_mem_io(g, &pss, &w);
    printf("%s after_deletes memory %.1f MB\n", g->name, (double)pss / 1e6);
    printf("%s cumulative cpu %.2f s (every phase so far; the phases print their own)\n", g->name, g_cpu);

    /* reopen, then the first lookup: three different things, named apart. imagedb loads its state
     * (the lake snapshot, then the log after it: first with all the churn still in the log, then
     * after a checkpoint); SQLite reopens a connection (nothing is loaded); PostgreSQL's server
     * restart is timed by the script, after this checkpoint. */
    int64_t v;
    if (g->db) {
        unsigned long long tail = (unsigned long long)(g->db->seq - g->db->lake_seq);
        t0 = now();
        CHECKRC(g->reopen(g));
        CHECKRC(g->lookup(g, 1, &v));
        printf("%s reopen_load_state seconds %.3f s (the log after the last checkpoint: %llu commits)\n", g->name,
               now() - t0, tail);
        phase_cpu(g, "reopen_load_state");
    }
    checkpoint(g, "checkpoint_after_churn");
    if (g->reopen) {
        t0 = now();
        CHECKRC(g->reopen(g));
        CHECKRC(g->lookup(g, 1, &v));
        printf("%s %s seconds %.3f s\n", g->name, g->db ? "reopen_after_checkpoint" : "reopen_connection", now() - t0);
        phase_cpu(g, g->db ? "reopen_after_checkpoint" : "reopen_connection");
    }
    if (!g->pidfile) peak_rss(g, "peak_rss");
    w6(g, lat); /* after R8's last measure */
    w7(g, lat); /* after W6, so no earlier measure moves */
    w8(g, lat);
    if (!g->pidfile) peak_rss(g, "peak_rss_after_w8");
    free(lat);
done:
    if (g->db) {
        imdb_session_close(&g->ss);
        imdb_close(g->db);
    }
    if (g->lite) {
        for (int i = 0; i < NQ2; i++) sqlite3_finalize(g->s2[i]);
        for (int i = 0; i < NQ3; i++) sqlite3_finalize(g->s3[i]);
        sqlite3_close(g->lite);
    }
    if (g->pg) PQfinish(g->pg);
#ifdef WITH_EXT
    for (int s = 0; s < 3; s++)
        for (int i = 0; i < NQ3; i++) {
            if (g->mst[s][i]) mysql_stmt_close(g->mst[s][i]);
            if (g->ost[s][i]) SQLFreeHandle(SQL_HANDLE_STMT, g->ost[s][i]);
        }
    if (g->my) mysql_close(g->my);
    if (g->odbc) {
        SQLDisconnect(g->odbc);
        SQLFreeHandle(SQL_HANDLE_DBC, g->odbc);
        SQLFreeHandle(SQL_HANDLE_ENV, g->oenv);
    }
    if (g->dialect == D_DUCKDB) d_close(g);
#endif
    return 0;
}
