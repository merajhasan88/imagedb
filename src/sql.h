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

#include <stdatomic.h>

#include "db.h"

/* IMDB_PATH_ROWS, the lake read row by row, is no SET access_path's: below the memory floor it cross-checks the scan */
/* IMDB_PATH_NESTED (P2 S4), a nested SELECT's rows read as a table, is no SET access_path's either */
enum { IMDB_PATH_AUTO = 0, IMDB_PATH_INDEX = 1, IMDB_PATH_SCAN = 2, IMDB_PATH_STORE = 3, IMDB_PATH_ORDERED = 4, IMDB_PATH_ROWS = 5,
       IMDB_PATH_NESTED = 6 };
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

/* P2 S10: a session's COPY stream (imdb_session_copy_io): the bytes COPY ... FROM STDIN reads (> 0 put in buf, at most
 * cap; 0 the data's end; < 0 a failure) and COPY ... TO STDOUT writes (0, or < 0 a failure) */
typedef long (*imdb_copy_read_fn)(void *arg, char *buf, size_t cap);
typedef int (*imdb_copy_write_fn)(void *arg, const char *buf, size_t len);

typedef struct imdb_session {
    imdb_db *db;
    uint32_t role;           /* N1e: the role it acts as (0: none); its privileges checked only when enforce is set */
    bool enforce;            /* N1e: set by the server alone (an embedded caller, the CLI, a re-bind and the dump keep a
                              * superuser's rights); an enforced session of role 0 is refused every statement */
    imdb_caps caps;          /* N1e stage two: its role's caps (the server's options), while enforce is set and the role is not
                              * a superuser (db.h imdb_cap_eff); zero: none */
    bool disk_low;           /* 2b-3: set by the server before each statement: its data directory's free space is below
                              * --disk-headroom, so an enforced role's row writes are refused at their start (gate_write; a
                              * superuser's run: the operator acting on a full disk) */
    bool disk_refused;       /* 2b-3: set by gate_write when it refused for disk_low (the server counts it, then clears it) */
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
    uint64_t row_limit;       /* SET statement_row_limit = n: a statement testing more rows fails (D8 #4; 0: none) */
    uint64_t rows_tested;     /* the last statement's rows tested (its first plan's; the work limit's count) */
    uint64_t corr_runs;       /* P2 S4b: the last statement's runs of correlated subqueries (one per distinct tuple of the
                               * outer values each reads) and the rows that found their answer kept (corr_hits) */
    uint64_t corr_hits;
    uint32_t slow_ms;         /* SET slow_statement_ms = ms: a statement past it is an event in the log (P1 M2; 0: none) */
    uint32_t stmt_timeout_ms; /* SET statement_timeout = ms: a statement running longer is cancelled (0: none) */
    uint32_t txn_timeout_ms;  /* SET transaction_timeout = ms: a transaction older can only roll back (R4; 0: none) */
    uint32_t idle_timeout_ms; /* SET idle_in_transaction_timeout = ms: one idle longer, the same (R4; 0: none) */
    uint8_t default_iso;      /* E3: SET default_transaction_isolation: a BEGIN's level when it names none (IMDB_ISO_*) */
    uint8_t su_set;           /* N1e stage two: the superuser-only settings this enforced session SET itself (SU_*):
                               * demoted_reset takes back these alone (a harness's field, set directly, stays) */
    uint8_t priv_gate;        /* N1e stage two: the gate that refused this statement (0 A: its kind, a SET; 1 B: a read; 2 C: a
                               * write's target) and the relation (0: none), for the count and the event (priv_note) */
    uint32_t priv_rel;
    uint64_t stmt_memory;     /* SET statement_memory = bytes: a read statement's workspace ceiling (P0 R2; 0: the default,
                               * a quarter of the memory budget or IMDB_MAX_RESULT_BYTES) */
    struct imdb_prep_set *prep; /* P2 S9: its prepared statements (PREPARE, imdb_prepare), NULL until the first */
    imdb_copy_read_fn copy_rd;  /* P2 S10: the COPY stream (imdb_session_copy_io); NULL: COPY is refused */
    imdb_copy_write_fn copy_wr;
    void *copy_arg;
    const struct imdb_tz *zone; /* P2: SET TIME ZONE: the session's zone (a TIMESTAMPTZ shown in it, a literal without an
                                 * offset read in it; never the process's TZ); NULL: UTC */
    char zone_name[IMDB_MAX_TZ_NAME + 1]; /* P2: its name as SET (SHOW TIME ZONE); "": UTC */
    struct imdb_seqcur *seqcur; /* F2a-2: currval: each sequence's last value in this session (allocated; by id) */
    uint32_t nseqcur, capseqcur;
    bool has_lastval;           /* F2a-2: lastval: the last nextval in this session, of any sequence */
    int64_t lastval;
    atomic_bool cancel;       /* imdb_session_cancel: the running statement stops at its next check (cleared at
                               * each statement's start, so a request between statements is dropped) */
    atomic_bool cancel_hold;  /* N1e stage two: imdb_session_cancel_held: every statement starting while it is set starts
                               * cancelled (the server's KILL: a request's statements, until the server clears it) */
} imdb_session;

typedef struct imdb_cell {
    imdb_value v;
    bool null;               /* only for aggregates over no rows */
    bool wide;               /* SUM result held in i128 */
    int32_t tz_off;          /* P2: a TIMESTAMPTZ's offset in the session's zone, seconds east (the renderer writes its wall clock) */
    __int128 i128;
} imdb_cell;

typedef struct imdb_result {
    uint16_t ncols;
    char names[IMDB_MAX_COLS + 4][IMDB_MAX_IDENT + 8];
    uint8_t ctype[IMDB_MAX_COLS + 4], cscale[IMDB_MAX_COLS + 4]; /* P2 S4: a SELECT's column types as its statement bound
                                                                * them (0: not known), a nested SELECT's schema */
    uint16_t ceid[IMDB_MAX_COLS + 4];      /* F3g: an ENUM column's type id beside its ctype (0: another type) */
    bool cwide[IMDB_MAX_COLS + 4];         /* N1b: the column a statement's top-level SUM (an aggregate's or a window's,
                                            * through set operations): its cells hold 38 digits in an i128 whatever ctype
                                            * says (ctype stays its column's: a nested SELECT's schema and a view's logged
                                            * types read it), so the server sends an INT64 one as a DECIMAL */
    imdb_enumdef *clab[IMDB_MAX_COLS + 4]; /* F3g: the result a statement hands out: each ENUM column's labels, copied once
                                            * at its finish (res_labels), so the renderer reads no catalog and a result
                                            * outlives DDL; NULL elsewhere (imdb_result_free frees them) */
    imdb_cell *cells;        /* nrows * ncols */
    uint64_t nrows, caprows;
    imdb_buf text;           /* backing store for TEXT cells */
    char status[512];        /* e.g. "INSERT 3", "VERIFY ok: ..." */
    char path[128];          /* access path(s) used (two join plans' names and " = ... (cross-checked)": P2 S4) */
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
    bool copy_out;           /* P2 S10: COPY ... TO STDOUT wrote its rows to the session's stream: status is its count alone */
    bool has_count;          /* N1b: count is the rows a write wrote (INSERT, UPDATE, DELETE, COPY), its status's number;
                              * otherwise the rows a result holds are nrows */
    uint64_t count;
    bool has_commit;         /* N1b: the statement made a commit (an autocommit write, COMMIT, DDL; COPY's BATCH: its last):
                              * commit and its hash, never a CHECKPOINT or an expiry imdb_maintain made after it */
    uint64_t commit;
    uint8_t commit_hash[32];
} imdb_result;

void imdb_session_init(imdb_session *s, imdb_db *db);
/* Rolls back an open transaction. Close every session before imdb_close. */
void imdb_session_close(imdb_session *s);
/* Cancels the statement running in s (R1): any thread, and a signal handler (one lock-free atomic store). It fails
 * with IMDB_ERR_CANCELLED at its next check, every few thousand rows its read paths, joins and row loops pass, and its
 * statement savepoint undoes what it wrote. COMMIT, CREATE TABLE, CREATE INDEX, DROP INDEX, ALTER, CHECKPOINT, COMPACT,
 * ERASE and VERIFY run to their end. */
void imdb_session_cancel(imdb_session *s);
/* N1e stage two: a cancel that holds (on) until released (off): any thread; sequentially consistent with the clear at a
 * statement's start, so a cancel landing between that start and its first check is never lost */
void imdb_session_cancel_held(imdb_session *s, bool on);
/* P2 S12, tests: a window function's moving frames each summed afresh (the reference the sliding window is checked
 * against), process-wide; off by default */
void imdb_sql_set_window_reference(bool on);
/* 2b-2b, tests (the sort's deadline): every executor sort by the C library's qsort (the old sort: the order's reference),
 * process-wide, off by default; a hook called at each of a sort's checks (every 4,096 element moves), before it; the
 * sorts a check stopped */
void imdb_sql_set_sort_reference(bool on);
void imdb_sql_set_sort_hook(void (*fn)(void *arg, int phase, int site), void *arg); /* (phase: 0 a run, 1 a merge, 2 the
                                                                                    * permutation; site: the call site, 1-15) */
uint64_t imdb_sql_sorts_stopped(void);
/* tests: the length of the runs a sort sorts in place before its merges (0: 16,384), so a few thousand rows reach them */
void imdb_sql_set_sort_run(size_t n);
/* sortpg (a prototype): ORDER BY's order arrays through abbreviated keys (0 off; 1 merged; 2 introsort); the insertion
 * sort's cutoff; comparisons counted */
void imdb_sql_set_sort_noab(bool on);
/* topk (ORDER BY ... LIMIT): 0 the top-k where taken (OFFSET + LIMIT at most a quarter of the rows); 1 never (the full
 * sort); 2 whenever OFFSET + LIMIT is under the rows; 3 as 2, the selections by heaps alone. The top-k's runs */
void imdb_sql_set_sort_topk(int mode);
uint64_t imdb_sql_sorts_topk(void);
void imdb_sql_sort_time(bool on);
uint64_t imdb_sql_sort_ns(void);
uint64_t imdb_sql_sort_ns_site(int site);
void imdb_sql_sort_inorder(int site, uint64_t *inorder, uint64_t *n);
void imdb_sql_set_sort_nopre(bool on);
/* tests: the segments the scan's grouped fast path (fast_group_seg) has taken in this process, so a test can show it ran */
uint64_t imdb_sql_fast_group_segments(void);
void imdb_result_init(imdb_result *r);
void imdb_result_free(imdb_result *r);

/* Executes one statement (text may contain one trailing ';'). params are bound to $1..$n: one of its use's type as
 * that type's value, one of another as the literal of its value would be (N1b: a NULL as NULL, a number exactly or not at
 * all; design.md §5, An API parameter as the literal of its value), each checked against its own type's rules first. */
int imdb_exec_one(imdb_session *s, const char *sql, size_t len, const imdb_value *params, uint32_t nparams,
                  imdb_result *res, imdb_err *e);
/* P2 S9: a session's prepared statement by name, as PREPARE, EXECUTE and DEALLOCATE make, run and drop one: sql parsed
 * once (SELECT, INSERT, UPDATE or DELETE), each run with params as its $1..$n (as imdb_exec_one's: each of the type its
 * use wants), names and types bound at each run */
int imdb_prepare(imdb_session *s, const char *name, const char *sql, size_t len, imdb_err *e);
int imdb_execute(imdb_session *s, const char *name, const imdb_value *params, uint32_t nparams, imdb_result *res,
                 imdb_err *e);
int imdb_deallocate(imdb_session *s, const char *name, imdb_err *e);
/* P2 S10: the stream COPY ... FROM STDIN reads and COPY ... TO STDOUT writes (rd or wr NULL: that one refused), arg
 * passed to each; until set, COPY is refused. No COPY names a file: the client opens the operator's and serves it here */
void imdb_session_copy_io(imdb_session *s, imdb_copy_read_fn rd, imdb_copy_write_fn wr, void *arg);
/* P2 S10: sql is one COPY ... FROM STDIN statement, whose data a client sends after it (main.c: a script's inline data) */
bool imdb_copy_in_stmt(const char *sql, size_t len);
/* N1e: a COPY ... FROM STDIN this session may run (an enforced one's gates asked before its data is: the server's COPY_IN) */
bool imdb_copy_in_open(imdb_session *ss, const char *sql, size_t len);
/* P2 S17 (deferred.md D10; src/dump.c): a logical dump of db at one commit through wr: every live table by name, its
 * CREATE TABLE, its rows as COPY ... FROM STDIN (BATCH batch; 0: IMDB_DUMP_BATCH) data ended by \., its indexes; the
 * commit named first, the totals last. imagedb sql -f restores it into an empty database. A failure part way leaves
 * what was written, without the totals */
int imdb_dump(imdb_db *db, uint32_t batch, imdb_copy_write_fn wr, void *arg, imdb_err *e);
/* L: IMDB_DUMP_ROLE_PASSWORDS writes each role's SCRAM-SHA-256 verifier (an offline-guessing target: off by default) */
#define IMDB_DUMP_ROLE_PASSWORDS 1u
int imdb_dump_ex(imdb_db *db, uint32_t batch, uint32_t flags, imdb_copy_write_fn wr, void *arg, imdb_err *e);

/* Splits a script into statements (respecting string literals and -- comments).
 * Calls cb for each; stops at the first error. */
typedef int (*imdb_stmt_cb)(void *arg, const char *sql, size_t len);
int imdb_split_statements(const char *sql, size_t len, imdb_stmt_cb cb, void *arg, imdb_err *e);
/* A stream's chunk: only the complete statements at its front run; *used is what they took (sql_exec.c) */
int imdb_split_complete(const char *sql, size_t len, imdb_stmt_cb cb, void *arg, size_t *used, imdb_err *e);

/* Renders a result as an aligned, terminal-safe table (or CSV). */
void imdb_result_render(const imdb_result *r, bool csv, imdb_buf *out);

#endif
