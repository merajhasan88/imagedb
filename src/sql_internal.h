/* SQL internals shared by the parser and the executor. */
#ifndef IMDB_SQL_INTERNAL_H
#define IMDB_SQL_INTERNAL_H

#include "sql.h"

enum {
    TK_EOF = 0, TK_IDENT, TK_INT, TK_DEC, TK_STR, TK_PARAM, TK_FLOAT,
    TK_LP, TK_RP, TK_COMMA, TK_SEMI, TK_STAR, TK_EQ, TK_NE, TK_LT, TK_LE, TK_GT, TK_GE, TK_MINUS, TK_PLUS, TK_DOT,
};

typedef struct sql_tok {
    uint8_t kind;
    uint32_t off, len;       /* span in the statement text */
} sql_tok;

enum { LIT_INT = 1, LIT_DEC, LIT_STR, LIT_BOOL, LIT_TS, LIT_PARAM, LIT_FLOAT, LIT_NULL };

typedef struct sql_lit {
    uint8_t kind;
    bool neg;                /* leading '-' on a number */
    bool bval;
    uint32_t off, len;       /* digits, or string contents (quotes excluded, '' not yet unescaped) */
    uint32_t param;          /* 1-based */
} sql_lit;

enum { CMP_EQ = 1, CMP_NE, CMP_LT, CMP_LE, CMP_GT, CMP_GE, CMP_BETWEEN, CMP_ISNULL, CMP_NOTNULL };

typedef struct sql_cmp {
    char qual[IMDB_MAX_IDENT + 1]; /* a.col: the table name or alias, or "" */
    char col[IMDB_MAX_IDENT + 1];
    uint8_t op;
    sql_lit a, b;
} sql_cmp;

enum { AGG_NONE = 0, AGG_COUNT_STAR, AGG_COUNT, AGG_SUM, AGG_MIN, AGG_MAX };

typedef struct sql_item {
    uint8_t agg;
    char qual[IMDB_MAX_IDENT + 1];
    char col[IMDB_MAX_IDENT + 1];
} sql_item;

enum {
    ST_CREATE = 1, ST_INSERT, ST_UPDATE, ST_DELETE, ST_SELECT, ST_BEGIN, ST_COMMIT, ST_ROLLBACK,
    ST_CHECKPOINT, ST_COMPACT, ST_ERASE_SUBJECT, ST_ERASE_WHERE, ST_VERIFY,
    ST_SHOW_TABLES, ST_SHOW_DIGEST, ST_SHOW_HISTORY, ST_SHOW_LOG, ST_SHOW_LAKE, ST_SHOW_IDENTITY, ST_SHOW_REPLICAS, ST_SHOW_REPLICATION, ST_SHOW_ERASURE, ST_SHOW_MEMORY, ST_SET, ST_EMPTY,
    ST_SAVEPOINT, ST_ROLLBACK_TO, ST_RELEASE, ST_SET_TXN,
    ST_CREATE_INDEX, ST_DROP_INDEX, ST_SHOW_INDEXES,
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
} sql_stmt;

int imdb_sql_lex(const char *s, size_t n, sql_tok **toks, uint32_t *ntok, imdb_err *e);
int imdb_sql_parse(const char *s, size_t n, sql_stmt *st, imdb_err *e);
void imdb_sql_stmt_free(sql_stmt *st);

#endif
