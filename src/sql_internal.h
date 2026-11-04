/* SQL internals shared by the parser and the executor. */
#ifndef IMDB_SQL_INTERNAL_H
#define IMDB_SQL_INTERNAL_H

#include "sql.h"

enum {
    TK_EOF = 0, TK_IDENT, TK_INT, TK_DEC, TK_STR, TK_PARAM, TK_FLOAT,
    TK_LP, TK_RP, TK_COMMA, TK_SEMI, TK_STAR, TK_EQ, TK_NE, TK_LT, TK_LE, TK_GT, TK_GE, TK_MINUS, TK_PLUS, TK_DOT,
    TK_SLASH, TK_PERCENT,
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
enum { EX_LIT = 1, EX_COL, EX_NEG, EX_ADD, EX_SUB, EX_MUL, EX_DIV, EX_MOD, EX_AGG, EX_CMP, EX_AND, EX_OR, EX_NOT };

typedef struct sql_expr {
    uint8_t op;
    uint8_t agg;             /* EX_AGG: AGG_COUNT_STAR (no operand), AGG_COUNT, AGG_SUM, AGG_MIN, AGG_MAX, AGG_AVG */
    uint8_t h;               /* height: at most IMDB_MAX_EXPR_DEPTH */
    uint16_t l, r;           /* operands (EX_NEG, EX_NOT, EX_AGG: l only) */
    uint8_t cmp;             /* EX_CMP: CMP_EQ .. CMP_NOTNULL */
    uint16_t x3;             /* EX_CMP BETWEEN: its upper bound */
    sql_lit lit;             /* EX_LIT */
    char qual[IMDB_MAX_IDENT + 1]; /* EX_COL: a.col's a, or "" */
    char col[IMDB_MAX_IDENT + 1];
} sql_expr;

enum { CMP_EQ = 1, CMP_NE, CMP_LT, CMP_LE, CMP_GT, CMP_GE, CMP_BETWEEN, CMP_ISNULL, CMP_NOTNULL };

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
    uint32_t off, len;       /* the item's text: a tree's result column is named by it */
} sql_item;

enum {
    ST_CREATE = 1, ST_INSERT, ST_UPDATE, ST_DELETE, ST_SELECT, ST_BEGIN, ST_COMMIT, ST_ROLLBACK,
    ST_CHECKPOINT, ST_COMPACT, ST_ERASE_SUBJECT, ST_ERASE_WHERE, ST_VERIFY,
    ST_SHOW_TABLES, ST_SHOW_DIGEST, ST_SHOW_HISTORY, ST_SHOW_LOG, ST_SHOW_LAKE, ST_SHOW_IDENTITY, ST_SHOW_REPLICAS, ST_SHOW_REPLICATION, ST_SHOW_ERASURE, ST_SHOW_MEMORY, ST_SET, ST_EMPTY,
    ST_SAVEPOINT, ST_ROLLBACK_TO, ST_RELEASE, ST_SET_TXN,
    ST_CREATE_INDEX, ST_DROP_INDEX, ST_SHOW_INDEXES,
    ST_ALTER_RETENTION, ST_SHOW_RETENTION,
};

/* isolation levels as written (the executor maps them; SERIALIZABLE is refused for now) */
enum { SQL_ISO_SNAPSHOT = 1, SQL_ISO_READ_COMMITTED, SQL_ISO_SERIALIZABLE };

typedef struct sql_stmt {
    uint8_t kind;
    char table[IMDB_MAX_IDENT + 1];
    char alias[IMDB_MAX_IDENT + 1];             /* FROM table AS alias, or "" */
    /* SELECT ... FROM table [AS alias] [INNER | LEFT [OUTER]] JOIN table2 [AS alias2] ON x = y */
    bool has_join, join_left;
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
    char set_cols[IMDB_MAX_COLS][IMDB_MAX_IDENT + 1]; /* UPDATE */
    sql_lit set_vals[IMDB_MAX_COLS];
    uint16_t nset;
    sql_cmp where[IMDB_MAX_PREDICATES];
    uint16_t nwhere;
    bool star;                                  /* SELECT */
    sql_item items[IMDB_MAX_COLS];
    uint16_t nitems;
    bool has_group;
    uint16_t having;                            /* HAVING: a condition over the groups (1e), else 0 */
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
typedef struct imdb_xnode {
    uint8_t type, scale;
    int16_t col;             /* EX_COL: the column in the row the evaluator is given */
    uint16_t slot;           /* EX_AGG: the aggregate's accumulator */
    imdb_xval k;             /* EX_LIT: the constant */
} imdb_xnode;

#define IMDB_X_MAX_SCALE 38
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
/* the tree at k on a row (columns by the bound col) and the aggregates' final values (slots) */
int imdb_x_eval(const sql_stmt *st, const imdb_xnode *xn, uint16_t k, const imdb_value *row, const imdb_xval *slots,
                imdb_xval *out, imdb_err *e);

#endif
