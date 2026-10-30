/*
 * SQL front-end: a deliberately small, strict dialect.
 *
 * Safety properties (from the PostgreSQL CVE study):
 *   - the grammar is flat: no recursion, so no stack exhaustion (CVE-2026-6479 class);
 *   - every count and length is bounded by limits.h before it is used;
 *   - the whole statement must be strict UTF-8 without NUL before lexing;
 *   - identifiers are [A-Za-z_][A-Za-z0-9_]{0,62}; no quoted identifiers, no
 *     escaping API: applications pass values as $n parameters;
 *   - nothing in imagedb generates SQL text, so there is no deparse/dump
 *     injection surface (CVE-2025-8714/8715, CVE-2026-15741 classes);
 *   - error messages carry positions and column names, never stored values.
 *
 * Four read paths over the same data:
 *   index  primary-key chain or data-subject list (scalar)
 *   ordered  CREATE INDEX's sorted runs (candidates, each checked like any row)
 *   scan   vectorised over segments (SIMD filters, exact masked sums) + memtable
 *   store  every version in the version store (scalar reference)
 * SET cross_check = on runs scan and (index or store) for every SELECT and
 * fails if their results differ in any cell; a join's second plan is the hash
 * join with each side read by scan (by store where the first read it by scan).
 * SET join_plan = auto | hash | index chooses between the hash join and the
 * index nested-loop join (design.md §5, Joins).
 */
#ifndef IMDB_SQL_H
#define IMDB_SQL_H

#include "db.h"

/* IMDB_PATH_ROWS, the lake read row by row, is no SET access_path's: below the memory floor it cross-checks the scan */
enum { IMDB_PATH_AUTO = 0, IMDB_PATH_INDEX = 1, IMDB_PATH_SCAN = 2, IMDB_PATH_STORE = 3, IMDB_PATH_ORDERED = 4, IMDB_PATH_ROWS = 5 };
enum { IMDB_JOIN_AUTO = 0, IMDB_JOIN_HASH = 1, IMDB_JOIN_INDEX = 2 };

/* What the session's last commit is known to hold beyond this database (SHOW REPLICATION, and the
 * statement's status). Never an error: the commit is durable here in every case. */
typedef enum {
    IMDB_REPL_LOCAL = 0,     /* sync_replicas = 0: no replica waited for */
    IMDB_REPL_CONFIRMED = 1, /* k replicas acknowledged holding it (durably, on their disks) */
    IMDB_REPL_UNKNOWN = 2,   /* fewer within the timeout: the others may hold it or not */
    IMDB_REPL_UNCHECKED = 3  /* the acknowledgements could not be read (see the warning) */
} imdb_repl_kind;

typedef struct imdb_repl_outcome {
    uint64_t seq; /* the commit; 0: none in this session yet */
    uint32_t wanted, confirmed, waited_ms;
    imdb_repl_kind kind;
} imdb_repl_outcome;

typedef struct imdb_session {
    imdb_db *db;
    bool cross_check;
    bool show_identity;      /* SET identity = on: results print their read point in full */
    uint64_t min_commit;     /* SET min_commit = N: reads refuse a database that has not reached N */
    uint32_t sync_replicas;  /* SET sync_replicas = k: a commit waits for k replicas to acknowledge it (repl.h) */
    uint32_t sync_wait_ms;   /* SET sync_timeout_ms = t: how long it waits (0: 10000), then reports */
    imdb_repl_outcome last_repl;
    int access_path;
    int join_plan;           /* SET join_plan: IMDB_JOIN_AUTO, IMDB_JOIN_HASH or IMDB_JOIN_INDEX */
    imdb_txn txn;            /* BEGIN ... COMMIT (db.h: session transactions) */
    uint64_t cross_checks_run;
} imdb_session;

typedef struct imdb_cell {
    imdb_value v;
    bool null;               /* only for aggregates over no rows */
    bool wide;               /* SUM result held in i128 */
    __int128 i128;
} imdb_cell;

typedef struct imdb_result {
    uint16_t ncols;
    char names[IMDB_MAX_COLS + 4][IMDB_MAX_IDENT + 8];
    imdb_cell *cells;        /* nrows * ncols */
    uint64_t nrows, caprows;
    imdb_buf text;           /* backing store for TEXT cells */
    char status[512];        /* e.g. "INSERT 3", "VERIFY ok: ..." */
    char path[80];           /* access path(s) used */
    uint64_t snap;           /* SELECT: the commit it was answered at (compare views at the same one) */
    bool has_snap, snap_own; /* snap is set; it also saw this transaction's own pending writes */
    uint64_t byte_cap;       /* cells and text this result may hold (IMDB_MAX_RESULT_BYTES, less under a budget) */
    /* the rest of the read point (has_snap): the database, commit snap's hash and the state digest it
     * records, and the lake snapshot published then (lake_seq 0: none) */
    uint8_t db_id[16], head[32], digest[32];
    uint64_t lake_seq;
    uint8_t lake_manifest[32];
    bool show_identity;      /* the session asked to print it */
    bool has_rows;
} imdb_result;

void imdb_session_init(imdb_session *s, imdb_db *db);
/* Rolls back an open transaction. Close every session before imdb_close. */
void imdb_session_close(imdb_session *s);
void imdb_result_init(imdb_result *r);
void imdb_result_free(imdb_result *r);

/* Executes one statement (text may contain one trailing ';'). params are
 * bound to $1..$n with exact type matching. */
int imdb_exec_one(imdb_session *s, const char *sql, size_t len, const imdb_value *params, uint32_t nparams,
                  imdb_result *res, imdb_err *e);

/* Splits a script into statements (respecting string literals and -- comments).
 * Calls cb for each; stops at the first error. */
typedef int (*imdb_stmt_cb)(void *arg, const char *sql, size_t len);
int imdb_split_statements(const char *sql, size_t len, imdb_stmt_cb cb, void *arg, imdb_err *e);

/* Renders a result as an aligned, terminal-safe table (or CSV). */
void imdb_result_render(const imdb_result *r, bool csv, imdb_buf *out);

#endif
