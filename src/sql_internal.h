/* SQL internals shared by the parser and the executor. */
#ifndef IMDB_SQL_INTERNAL_H
#define IMDB_SQL_INTERNAL_H

#include "sql.h"

enum {
    TK_EOF = 0, TK_IDENT, TK_INT, TK_DEC, TK_STR, TK_PARAM, TK_FLOAT,
    TK_LP, TK_RP, TK_COMMA, TK_SEMI, TK_STAR, TK_EQ, TK_NE, TK_LT, TK_LE, TK_GT, TK_GE, TK_MINUS, TK_PLUS, TK_DOT,
    TK_SLASH, TK_PERCENT, TK_CONCAT, /* || (P2 S1) */
};

typedef struct sql_tok {
    uint8_t kind;
    uint32_t off, len;       /* span in the statement text */
} sql_tok;

/* LIT_EXPR: not a literal but an expression's tree (ex), where a value may be one: an UPDATE's SET, an INSERT's
 * VALUES (a WHERE condition that is not today's col op literal is a tree too: sql_cmp lx) */
enum { LIT_INT = 1, LIT_DEC, LIT_STR, LIT_BOOL, LIT_TS, LIT_PARAM, LIT_FLOAT, LIT_NULL, LIT_EXPR };

typedef struct sql_lit {
    uint8_t kind;
    bool neg;                /* leading '-' on a number */
    bool bval;
    uint32_t off, len;       /* digits, or string contents (quotes excluded, '' not yet unescaped) */
    uint16_t param;          /* 1-based */
    uint16_t ex;             /* LIT_EXPR: the tree's root */
} sql_lit;

/* Arithmetic expressions (docs/plan-p0.md 1b): trees in a statement's node pool, st->ex[1..nex] (0: none). A shape
 * today's statements had (a column, an aggregate of a column, col op literal, a literal value) keeps today's
 * structures, so the planner and the read paths see what they saw; only the rest carries a tree. */
/* EX_CMP: l cmp r (BETWEEN: l BETWEEN r AND x3; IS [NOT] NULL: l alone), a BOOL, NULL when unknown; EX_AND, EX_OR,
 * EX_NOT: three-valued, left to right, AND stopping at FALSE and OR at TRUE (1c) */
/* P2 S1: EX_FN a function of its arguments (l: a list, nargs of them); EX_CASE (l: the operand of a simple CASE, else
 * 0; r: a list of EX_WHEN, each l WHEN and r THEN; x3: ELSE, else 0); EX_CAST (l to ctype, cscale). A list is a
 * balanced tree of EX_LIST nodes (l, r) over its elements, in order, so its depth grows as log2 of its length and every
 * walker that follows l, r and x3 reaches each element within the height bound; a list of one is its element alone. */
enum { EX_LIT = 1, EX_COL, EX_NEG, EX_ADD, EX_SUB, EX_MUL, EX_DIV, EX_MOD, EX_AGG, EX_CMP, EX_AND, EX_OR, EX_NOT,
       EX_FN, EX_LIST, EX_CASE, EX_WHEN, EX_CAST, EX_SUBQ, EX_WIN };

typedef struct sql_expr {
    uint8_t op;
    uint8_t agg;             /* EX_AGG: AGG_COUNT_STAR (no operand), AGG_COUNT, AGG_SUM, AGG_MIN, AGG_MAX, AGG_AVG */
    uint8_t h;               /* height: at most IMDB_MAX_EXPR_DEPTH */
    uint16_t l, r;           /* operands (EX_NEG, EX_NOT, EX_AGG: l only) */
    uint8_t cmp;             /* EX_CMP: CMP_EQ .. CMP_NOTLIKE */
    uint16_t x3;             /* EX_CMP BETWEEN: its upper bound; LIKE: its ESCAPE, else 0; EX_CASE: its ELSE */
    uint8_t fn, nargs;       /* EX_FN (P2 S1): FN_*, and its arguments' count */
    uint8_t ctype, cscale, cprec; /* EX_CAST (P2 S1): the target type, scale and precision (a DECIMAL's) */
    bool dist;               /* EX_AGG (P2 S2): agg(DISTINCT x); its FILTER (WHERE c) is x3 */
    uint8_t sub, subk;       /* EX_SUBQ (P2 S4): the statement's sub[sub]; subk 0 a value, 1 EXISTS, 2 IN's values */
                             /* EX_WIN (P2 S6): fn a WF_*, agg its aggregate (WF_AGG), l r x3 its arguments, sub its
                              * window (the statement's win[sub]) */
    sql_lit lit;             /* EX_LIT */
    char qual[IMDB_MAX_IDENT + 1]; /* EX_COL: a.col's a, or "" */
    char col[IMDB_MAX_IDENT + 1];
} sql_expr;

/* CMP_IN, CMP_NOTIN: l [NOT] IN (r: a list), three-valued; CMP_LIKE, CMP_NOTLIKE (P2 S1) */
enum { CMP_EQ = 1, CMP_NE, CMP_LT, CMP_LE, CMP_GT, CMP_GE, CMP_BETWEEN, CMP_ISNULL, CMP_NOTNULL, CMP_IN, CMP_NOTIN,
       CMP_LIKE, CMP_NOTLIKE };

/* P2 S1: the functions, each with one definition (design.md §5, Functions) */
enum { FN_ABS = 1, FN_SIGN, FN_ROUND, FN_CEIL, FN_FLOOR, FN_MOD, FN_LENGTH, FN_SUBSTR, FN_TRIM, FN_LTRIM, FN_RTRIM,
       FN_POSITION, FN_COALESCE, FN_NULLIF, FN_LOWER, FN_UPPER, FN_REPLACE, FN_CONCAT };

/* col op a (BETWEEN: a AND b), today's form, whose literals bind to the column (an index may serve it); or with lx a
 * residual: a boolean tree (1c), tested on every row that passed the bound conjuncts, kept when TRUE */
typedef struct sql_cmp {
    char qual[IMDB_MAX_IDENT + 1]; /* a.col: the table name or alias, or "" */
    char col[IMDB_MAX_IDENT + 1];
    uint8_t op;
    sql_lit a, b;
    uint16_t lx;             /* a residual's boolean tree, else 0 */
    uint16_t nl;             /* today's form's own comparison node: a literal of another numeric kind than the
                              * column's (1.25 for an INT64) makes it a residual through it (sql_exec.c falls_back) */
} sql_cmp;

enum { AGG_NONE = 0, AGG_COUNT_STAR, AGG_COUNT, AGG_SUM, AGG_MIN, AGG_MAX, AGG_AVG }; /* AVG (1e): always a tree's slot */

typedef struct sql_item {
    uint8_t agg;
    char qual[IMDB_MAX_IDENT + 1];
    char col[IMDB_MAX_IDENT + 1];
    uint16_t expr;           /* a tree (agg, qual and col unused), else 0 */
    char alias[IMDB_MAX_IDENT + 1]; /* P2 S1: expr AS name, the result column's name; "" for none */
    uint32_t off, len;       /* the item's text: a tree's result column is named by it */
} sql_item;

enum {
    ST_CREATE = 1, ST_INSERT, ST_UPDATE, ST_DELETE, ST_SELECT, ST_BEGIN, ST_COMMIT, ST_ROLLBACK,
    ST_CHECKPOINT, ST_COMPACT, ST_ERASE_SUBJECT, ST_ERASE_WHERE, ST_VERIFY,
    ST_SHOW_TABLES, ST_SHOW_DIGEST, ST_SHOW_HISTORY, ST_SHOW_LOG, ST_SHOW_LAKE, ST_SHOW_IDENTITY, ST_SHOW_REPLICAS, ST_SHOW_REPLICATION, ST_SHOW_ERASURE, ST_SHOW_MEMORY, ST_SET, ST_EMPTY,
    ST_SAVEPOINT, ST_ROLLBACK_TO, ST_RELEASE, ST_SET_TXN,
    ST_CREATE_INDEX, ST_DROP_INDEX, ST_SHOW_INDEXES, ST_DROP_TABLE,
    ST_ALTER_RETENTION, ST_SHOW_RETENTION,
    ST_SHOW_STATS, ST_SHOW_TRANSACTIONS, /* P1 M1 */
    ST_EXPLAIN, /* P1 Q1: the plan of the statement in explained (SELECT, UPDATE or DELETE), which is not run */
    ST_PREPARE, ST_EXECUTE, ST_DEALLOCATE, ST_SHOW_PREPARED, /* P2 S9 */
    ST_COPY_FROM, ST_COPY_TO, /* P2 S10 */
};

/* P2 S3: a join's kind as written (RIGHT keeps side 1's rows, FULL both sides'; CROSS and FROM a, b have no ON) */
enum { SQL_JOIN_INNER = 1, SQL_JOIN_LEFT, SQL_JOIN_RIGHT, SQL_JOIN_FULL, SQL_JOIN_CROSS };
enum { SQL_SET_UNION = 1, SQL_SET_INTERSECT, SQL_SET_EXCEPT, SQL_SET_ALL = 0x80 }; /* P2 S5: an arm's operator, | ALL */
/* P2 S6: window functions (EX_WIN.fn), a frame's kind and its bounds */
enum { WF_ROW_NUMBER = 1, WF_RANK, WF_DENSE_RANK, WF_NTILE, WF_LAG, WF_LEAD, WF_FIRST, WF_LAST, WF_AGG };
enum { WFR_DEFAULT = 0, WFR_ROWS, WFR_RANGE };
enum { WB_UNB_PREC = 1, WB_PREC, WB_CURRENT, WB_FOLL, WB_UNB_FOLL };
typedef struct sql_win { /* OVER ( [PARTITION BY part ...] [ORDER BY ord ...] [ROWS | RANGE lo .. hi] ) */
    uint8_t npart, nord;
    uint16_t part[IMDB_MAX_WIN_KEYS], ord[IMDB_MAX_WIN_KEYS]; /* expression roots */
    bool desc[IMDB_MAX_WIN_KEYS], nfirst[IMDB_MAX_WIN_KEYS];
    uint8_t frame, lo, hi;   /* WFR_*, WB_* (WFR_DEFAULT: the whole partition, or to the current row's last peer under
                              * ORDER BY) */
    int64_t lo_n, hi_n;      /* n PRECEDING / n FOLLOWING */
} sql_win;

/* isolation levels as written (the executor maps them; SERIALIZABLE is refused for now) */
enum { SQL_ISO_SNAPSHOT = 1, SQL_ISO_READ_COMMITTED, SQL_ISO_SERIALIZABLE };
enum { SQL_UPSERT_NOTHING = 1, SQL_UPSERT_UPDATE }; /* P2 S8: ON CONFLICT DO NOTHING | DO UPDATE */
typedef struct sql_ptype { /* P2 S9: a parameter PREPARE declares: a column's type */
    uint8_t type, scale, precision;
} sql_ptype;

typedef struct sql_stmt {
    uint8_t kind;
    char table[IMDB_MAX_IDENT + 1];
    char alias[IMDB_MAX_IDENT + 1];             /* FROM table AS alias, or "" */
    /* SELECT ... FROM table [AS alias] [INNER | LEFT [OUTER]] JOIN table2 [AS alias2] ON x = y */
    bool has_join, join_left;                   /* join_left: join_kind is SQL_JOIN_LEFT */
    uint8_t join_kind;                          /* P2 S3: SQL_JOIN_INNER .. SQL_JOIN_CROSS */
    uint16_t on_ex;                             /* P2 S3: ON's condition, a tree; on_qual and on_col name its two
                                                 * columns when it is one equality of columns (that path unchanged) */
    uint8_t nusing;                             /* P2 S3: USING (columns): each a key pair by its name */
    char using_col[IMDB_MAX_JOIN_KEYS][IMDB_MAX_IDENT + 1];
    /* P2 S4: nested SELECTs, each run first into a row set the statement reads as a table by its name: FROM (SELECT ...)
     * AS name, a join's (SELECT ...) AS name, WITH name AS (SELECT ...) */
    struct sql_stmt *sub[IMDB_MAX_SUBQUERIES];
    char sub_name[IMDB_MAX_SUBQUERIES][IMDB_MAX_IDENT + 1];
    uint8_t nsub;
    /* P2 S5: a set operation: arm[0] armop[1] arm[1] ..., folded left (an INTERSECT chain inside a UNION or EXCEPT
     * one is an arm of its own, as a parenthesized query is). The arms are this statement's alone, not sub[]'s: no
     * nesting level, never a row set. Its tail applies to the combined rows: ORDER BY an output column, LIMIT, OFFSET */
    struct sql_stmt *arm[IMDB_MAX_SETOP_ARMS];
    uint8_t armop[IMDB_MAX_SETOP_ARMS];
    uint8_t narm;
    /* P2 S5: a WITH's nested SELECT: its column list, WITH name (c1, ...) AS (...) (NULL: its own names), and
     * RECURSIVE: base UNION [ALL] step, the step reading the name (rset_recursive) */
    char (*cte_col)[IMDB_MAX_IDENT + 1];
    uint8_t cte_ncols;
    bool recursive;
    bool with_cte; /* P2 S11: a WITH's: the one kind of row set a nested SELECT reads by its name (a derived table's name is
                    * a range variable of its own statement alone, as SQL has it) */
    sql_win win[IMDB_MAX_WINDOWS]; /* P2 S6: its window functions' windows, EX_WIN.sub */
    uint8_t nwin;
    char table2[IMDB_MAX_IDENT + 1], alias2[IMDB_MAX_IDENT + 1];
    char on_qual[2][IMDB_MAX_IDENT + 1], on_col[2][IMDB_MAX_IDENT + 1];
    imdb_schema schema;                         /* CREATE */
    bool has_retention;                         /* CREATE TABLE ... RETENTION, ALTER TABLE ... SET RETENTION */
    uint64_t retention_us;
    char index_name[IMDB_MAX_IDENT + 1];        /* CREATE INDEX, DROP INDEX */
    char index_cols[IMDB_MAX_INDEX_COLS][IMDB_MAX_IDENT + 1]; /* CREATE [UNIQUE] INDEX: the key's columns */
    uint8_t index_ncols;
    bool index_unique;
    char cols[IMDB_MAX_COLS][IMDB_MAX_IDENT + 1]; /* INSERT column list */
    uint16_t ncols;
    sql_lit *vals;                              /* INSERT: nrows x rowlen */
    uint32_t nrows;
    uint16_t rowlen;
    struct sql_stmt *src;                       /* P2 S8: INSERT ... query: the query whose rows it inserts (its own
                                                 * statement, not a row set of this one: nothing reads it by name) */
    uint8_t upsert;                             /* P2 S8: INSERT ... ON CONFLICT: SQL_UPSERT_NOTHING or SQL_UPSERT_UPDATE
                                                 * (0: none); DO UPDATE's SET in set_cols / set_vals, EXCLUDED as
                                                 * table2 (join_col's side 1) */
    uint8_t nconf;                              /* its target's columns (0: the primary key) */
    char conf_cols[IMDB_MAX_INDEX_COLS][IMDB_MAX_IDENT + 1];
    uint16_t upsert_where;                      /* DO UPDATE ... WHERE: a condition's tree, else 0 */
    /* P2 S9: PREPARE name [(type, ...)] AS body: the body's text in the statement's (body_off, body_len), the declared
     * types; EXECUTE name [(value, ...)]: the values in vals, rowlen of them; DEALLOCATE name | ALL (prep_all) */
    char prep_name[IMDB_MAX_IDENT + 1];
    uint32_t body_off, body_len;
    sql_ptype *ptypes;
    uint16_t nptype;
    bool prep_all;
    /* P2 S10: COPY t [(cols)] FROM STDIN, COPY t [(cols)] | (query) TO STDOUT: the table and columns as INSERT's (a
     * query's statement in src), and the options: HEADER, DELIMITER (one byte), BATCH n rows a commit (FROM, outside a
     * transaction), SKIP n records (FROM: a BATCH's resume) */
    bool copy_header;
    char copy_delim;
    uint32_t copy_batch;
    uint64_t copy_skip;
    char set_cols[IMDB_MAX_COLS][IMDB_MAX_IDENT + 1]; /* UPDATE */
    sql_lit set_vals[IMDB_MAX_COLS];
    uint16_t nset;
    sql_cmp where[IMDB_MAX_PREDICATES];
    uint16_t nwhere;
    bool star;                                  /* SELECT; P2 S8: RETURNING * */
    bool returning;                             /* P2 S8: INSERT, UPDATE, DELETE ... RETURNING: items[] over the row */
    bool no_from;                               /* P2 S1: SELECT of expressions alone: one row, no table */
    sql_item items[IMDB_MAX_COLS];
    uint16_t nitems;
    bool has_group;
    uint16_t having;                            /* HAVING: a condition over the groups (1e), else 0 */
    uint8_t ngroup;                             /* P2 S2: GROUP BY's keys, each a tree (group_ex); group_qual and
                                                 * group_col name the one key that is a bare column (the path of one
                                                 * column, unchanged), else group_col is "" */
    uint16_t group_ex[IMDB_MAX_GROUP_KEYS];
    uint32_t group_off[IMDB_MAX_GROUP_KEYS], group_len[IMDB_MAX_GROUP_KEYS]; /* each key's text (EXPLAIN) */
    char group_qual[IMDB_MAX_IDENT + 1], group_col[IMDB_MAX_IDENT + 1];
    bool has_asof;
    sql_lit asof;                               /* INT = commit seq, TS/STR = time */
    bool has_limit;
    uint64_t limit;
    bool has_purge;                             /* COMPACT */
    uint64_t purge_before;
    sql_lit subject;                            /* ERASE SUBJECT, SHOW DIGEST ... SUBJECT */
    bool has_subject;
    sql_lit key;                                /* SHOW HISTORY */
    char set_name[IMDB_MAX_IDENT + 1];          /* SET */
    char set_value[IMDB_MAX_IDENT + 1];
    uint64_t n;                                 /* SHOW LOG n */
    uint8_t iso;                                /* BEGIN / SET TRANSACTION ... ISOLATION LEVEL */
    char savepoint[IMDB_MAX_IDENT + 1];         /* SAVEPOINT, ROLLBACK TO, RELEASE */
    bool for_update;                            /* SELECT ... FOR UPDATE */
    uint8_t explained;                          /* ST_EXPLAIN (P1 Q1): the explained statement's kind */
    bool nolock;                                /* SELECT ... FROM t WITH (NOLOCK): accepted, changes nothing */
    bool distinct;                              /* SELECT DISTINCT (1d) */
    uint8_t norder;                             /* ORDER BY: keys, each a tree (ord_ex) or an item's position (ord_pos) */
    uint16_t ord_ex[IMDB_MAX_ORDER], ord_pos[IMDB_MAX_ORDER];
    bool ord_desc[IMDB_MAX_ORDER], ord_nulls_first[IMDB_MAX_ORDER]; /* NULLS: LAST for ASC, FIRST for DESC by default */
    bool has_offset;                            /* OFFSET n: skipped after the order, before LIMIT */
    uint64_t offset;
    sql_expr *ex;                               /* expression nodes, 1-based (ex[0] unused) */
    uint16_t nex, capex;
} sql_stmt;

int imdb_sql_lex(const char *s, size_t n, sql_tok **toks, uint32_t *ntok, imdb_err *e);
/* P1 M2: the shape of statement s for the event log (literals as ?, comments dropped, cut to cap on a token) */
size_t imdb_sql_shape(const char *s, size_t n, char *out, size_t cap);
int imdb_sql_parse(const char *s, size_t n, sql_stmt *st, imdb_err *e);
void imdb_sql_stmt_free(sql_stmt *st);
bool imdb_sql_has_agg(const sql_stmt *st, uint16_t k); /* the tree at k holds an aggregate */

/* ---- evaluation (sql_expr.c) ---------------------------------------------------------------------------------
 * A value a tree computes: INT64 and DECIMAL (scaled; at most 38 digits) in i, an INT64 past int64 only as a SUM's
 * result; FLOAT64 as a double in f (a column holds its key: converted at the leaf); BOOL and TIMESTAMP in i; TEXT in
 * s/len. Types are the columns' (IMDB_T_*); each node's is fixed when the statement is bound, so a row's value never
 * decides a type, only whether an operation fails (an overflow, a zero divisor). */
typedef struct imdb_xval {
    uint8_t type;
    uint8_t scale;           /* DECIMAL */
    bool null;
    __int128 i;
    double f;
    const uint8_t *s;
    uint32_t len;
} imdb_xval;

/* st->ex[k] bound: its result's type, its column or constant (an array parallel to st->ex) */
/* P2 S4: IN (SELECT ...)'s values: the non-NULL ones sorted by imdb_x_cmp (exact across numeric kinds), a NULL seen */
typedef struct imdb_xset {
    imdb_xval *v;
    uint64_t n;
    bool has_null;
} imdb_xset;

typedef struct imdb_xnode {
    uint8_t type, scale;
    uint8_t outer;           /* P2 S4b: an EX_COL naming a column of a statement around this one: k, a constant for
                              * the run (col -1) */
    uint8_t corr;            /* P2 S4b: an EX_SUBQ that is correlated: computed on each row by env->subq */
    int16_t col;             /* EX_COL: the column in the row the evaluator is given */
    uint16_t slot;           /* EX_AGG: the aggregate's accumulator */
    uint16_t gslot;          /* P2 S2: a GROUP BY key's subtree read over a group: slots[gslot - 1], else 0 */
    const imdb_xset *set;    /* P2 S4: an EX_SUBQ of IN's values: the set */
    imdb_xval k;             /* EX_LIT: the constant */
} imdb_xnode;

#define IMDB_X_MAX_SCALE 38
#define IMDB_X_GSLOT0 IMDB_MAX_COLS /* P2 S2: GROUP BY key j's slot is IMDB_X_GSLOT0 + j, past every aggregate's */
/* the result type of a op b (EX_ADD .. EX_MOD), or an error: the bind-time half of every rule */
int imdb_x_type(uint8_t op, uint8_t ta, uint8_t sa, uint8_t tb, uint8_t sb, uint8_t *rt, uint8_t *rs, imdb_err *e);
/* a column's value as an expression value (a FLOAT64 key becomes its double) */
void imdb_x_from_value(const imdb_value *v, imdb_xval *out);
/* a op b at the bound result type: checked; a NULL operand gives NULL */
int imdb_x_arith(uint8_t op, const imdb_xval *a, const imdb_xval *b, uint8_t rt, uint8_t rs, imdb_xval *out,
                 imdb_err *e);
int imdb_x_neg(const imdb_xval *a, imdb_xval *out, imdb_err *e);
/* two non-NULL values of comparable types (both numbers, or one type): -1, 0, 1, exactly; never an error */
bool imdb_x_comparable(uint8_t ta, uint8_t tb);
int imdb_x_cmp(const imdb_xval *a, const imdb_xval *b);
/* a value stored into a column: the assignment's conversions, then imdb_value_check (TEXT points into v) */
int imdb_x_assign(const imdb_column *c, const imdb_xval *v, imdb_value *out, imdb_err *e);
/* a DECIMAL literal's digits ([-]d+.d*) as an exact value at its written scale */
int imdb_x_parse_decimal(const char *s, size_t n, imdb_xval *out, imdb_err *e);
/* a value that is a BOOL and TRUE: what WHERE keeps (FALSE and UNKNOWN, a NULL, are not) */
bool imdb_x_true(const imdb_xval *v);
/* P2 S1: the statement's memory for computed TEXT (LOWER, ||, CAST to TEXT ...): chunks charged to the heap's counter (a
 * read statement's ceiling sees them), freed when the statement ends, so a computed value lives as long as a row's TEXT
 * does; the executor resets it to a mark where no value outlives its row (a WHERE residual, an output row copied,
 * an UPDATE's row encoded) */
typedef struct imdb_xchunk {
    struct imdb_xchunk *next;
    size_t used, cap;
    uint8_t data[];
} imdb_xchunk;
typedef struct imdb_xarena {
    imdb_xchunk *head;
} imdb_xarena;
typedef struct imdb_xmark {
    imdb_xchunk *head;
    size_t used;
} imdb_xmark;
uint8_t *imdb_xarena_alloc(imdb_xarena *a, size_t n, imdb_err *e);
imdb_xmark imdb_xarena_mark(const imdb_xarena *a);
void imdb_xarena_reset(imdb_xarena *a, imdb_xmark m);
void imdb_xarena_free(imdb_xarena *a);

/* P2 S1: what an evaluation may need of its statement: the statement's cancel and deadline (xcheck), asked every
 * 2^16 steps of a function whose work grows with its operands (LIKE), so no single value outlasts a timeout */
typedef struct imdb_xenv {
    int (*check)(void *ctx, imdb_err *e);
    void *ctx;
    uint32_t steps;
    imdb_xarena *arena;      /* computed TEXT (NULL: none can be computed: an internal error if needed) */
    /* P2 S4b: a correlated subquery's value (out), or IN's set (set), on this row: the statement's executor runs it
     * with the row's values (memoized); NULL where none can be (an internal error if needed) */
    int (*subq)(void *ctx, uint16_t k, const imdb_value *row, imdb_xval *out, const imdb_xset **set, imdb_err *e);
} imdb_xenv;
/* the tree at k on a row (columns by the bound col) and the aggregates' final values (slots); env may be NULL (no
 * cancellation: constants) */
int imdb_x_eval(const sql_stmt *st, const imdb_xnode *xn, uint16_t k, const imdb_value *row, const imdb_xval *slots,
                imdb_xenv *env, imdb_xval *out, imdb_err *e);
/* P2 S1: a function's result type from its arguments' (fn: FN_*), or the error a wrong call is */
int imdb_x_fn_type(uint8_t fn, uint8_t nargs, const uint8_t *ta, const uint8_t *sa, const imdb_xval *const *kv,
                   uint8_t *rt, uint8_t *rs, imdb_err *e); /* kv[i]: argument i's constant, or NULL */
/* P2 S1: the type CASE's results and COALESCE's arguments share (t, s), widened by one more (t2, s2): one type, or
 * INT64 and DECIMAL as a DECIMAL at the larger scale (exact); 0, an untyped NULL, takes the others'; what names the form */
int imdb_x_unify(uint8_t *t, uint8_t *s, uint8_t t2, uint8_t s2, const char *what, imdb_err *e);
/* P2 S1: v (of a type CASE or COALESCE unified) as their type rt at scale rs: exact */
int imdb_x_widen(imdb_xval *v, uint8_t rt, uint8_t rs, imdb_err *e);

/* P2 S1: an in-order walk of a list (the parser's balanced EX_LIST tree): its next element, 0 at its end; the stack
 * holds a list's depth (log2 of IMDB_MAX_EXPR_NODES at most, 14) */
typedef struct imdb_xlist {
    const sql_stmt *st;
    uint16_t stack[32];
    int n;
} imdb_xlist;
static inline void imdb_xlist_start(imdb_xlist *it, const sql_stmt *st, uint16_t k)
{
    it->st = st;
    it->n = 0;
    if (k) it->stack[it->n++] = k;
}
static inline uint16_t imdb_xlist_next(imdb_xlist *it)
{
    while (it->n > 0) {
        uint16_t k = it->stack[--it->n];
        const sql_expr *x = &it->st->ex[k];
        if (x->op != EX_LIST) return k;
        if (it->n > 29) return 0; /* deeper than a balanced list of IMDB_MAX_EXPR_NODES: never built */
        it->stack[it->n++] = x->r;
        it->stack[it->n++] = x->l;
    }
    return 0;
}
/* P2 S1: the function on its arguments' values (COALESCE and NULLIF are the evaluator's: they evaluate lazily) */
int imdb_x_fn(uint8_t fn, const imdb_xval *a, uint8_t nargs, uint8_t rt, uint8_t rs, imdb_xenv *env, imdb_xval *out,
              imdb_err *e);
/* P2 S1: v converted to column c's type by CAST's rule (design.md §5, CAST): exact or refused, never rounded */
int imdb_x_cast(const imdb_xval *v, const imdb_column *c, imdb_xenv *env, imdb_xval *out, imdb_err *e);
/* P2 S1: s LIKE p with the escape character esc (0: none): -1 when p ends in an unfinished escape */
int imdb_x_like(const uint8_t *s, uint32_t n, const uint8_t *p, uint32_t m, uint32_t esc, imdb_xenv *env, bool *match,
                imdb_err *e);

#endif
