/* SQL lexer and parser: flat grammar, bounded everywhere, no recursion. */
#include <stdio.h>
#include <stdlib.h>

#include "sql_internal.h"

/* ---- lexer ------------------------------------------------------------------- */

static bool is_alpha(char c) { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_'; }
static bool is_digit(char c) { return c >= '0' && c <= '9'; }

int imdb_sql_lex(const char *s, size_t n, sql_tok **out, uint32_t *ntok, imdb_err *e)
{
    *out = NULL;
    *ntok = 0;
    if (n > IMDB_MAX_SQL) return imdb_fail(e, IMDB_ERR_LIMIT, "statement longer than %u bytes", IMDB_MAX_SQL);
    size_t bad;
    if (!imdb_utf8_valid((const uint8_t *)s, n, &bad))
        return imdb_fail(e, IMDB_ERR_INVALID, "statement is not valid UTF-8 (byte %zu)", bad);
    uint32_t cap = 64, k = 0;
    sql_tok *t = imdb_alloc_array(cap, sizeof *t, e);
    if (!t) return e->code;
    size_t i = 0;
    while (i < n) {
        char c = s[i];
        if (c == ' ' || c == '\t' || c == '\r' || c == '\n') {
            i++;
            continue;
        }
        if (c == '-' && i + 1 < n && s[i + 1] == '-') {
            while (i < n && s[i] != '\n') i++;
            continue;
        }
        if (k + 1 >= cap) {
            if (cap >= IMDB_MAX_TOKENS) {
                imdb_free(t);
                return imdb_fail(e, IMDB_ERR_LIMIT, "statement has more than %u tokens", IMDB_MAX_TOKENS);
            }
            sql_tok *nt = imdb_realloc_array(t, cap, cap * 2, sizeof *t, e);
            if (!nt) {
                imdb_free(t);
                return e->code;
            }
            t = nt;
            cap *= 2;
        }
        sql_tok *tk = &t[k];
        tk->off = (uint32_t)i;
        if (is_alpha(c)) {
            size_t j = i;
            while (j < n && (is_alpha(s[j]) || is_digit(s[j]))) j++;
            if (j - i > IMDB_MAX_IDENT) {
                imdb_free(t);
                return imdb_fail(e, IMDB_ERR_LIMIT, "identifier at offset %zu longer than %u bytes", i, IMDB_MAX_IDENT);
            }
            tk->kind = TK_IDENT;
            tk->len = (uint32_t)(j - i);
            i = j;
        } else if (is_digit(c)) {
            size_t j = i;
            while (j < n && is_digit(s[j])) j++;
            tk->kind = TK_INT;
            if (j < n && s[j] == '.') {
                j++;
                size_t f = j;
                while (j < n && is_digit(s[j])) j++;
                if (j == f) {
                    imdb_free(t);
                    return imdb_fail(e, IMDB_ERR_SYNTAX, "malformed number at offset %zu", i);
                }
                tk->kind = TK_DEC;
            }
            if (j < n && (s[j] == 'e' || s[j] == 'E')) {
                size_t x = j + 1;
                if (x < n && (s[x] == '+' || s[x] == '-')) x++;
                size_t x0 = x;
                while (x < n && is_digit(s[x])) x++;
                if (x == x0) {
                    imdb_free(t);
                    return imdb_fail(e, IMDB_ERR_SYNTAX, "malformed number at offset %zu", i);
                }
                j = x;
                tk->kind = TK_FLOAT;
            }
            if (j < n && (is_alpha(s[j]) || s[j] == '.')) {
                imdb_free(t);
                return imdb_fail(e, IMDB_ERR_SYNTAX, "malformed number at offset %zu", i);
            }
            if (j - i > IMDB_MAX_NUMERIC) {
                imdb_free(t);
                return imdb_fail(e, IMDB_ERR_LIMIT, "numeric literal at offset %zu too long", i);
            }
            tk->len = (uint32_t)(j - i);
            i = j;
        } else if (c == '\'') {
            size_t j = i + 1, content = 0;
            for (;;) {
                if (j >= n) {
                    imdb_free(t);
                    return imdb_fail(e, IMDB_ERR_SYNTAX, "unterminated string starting at offset %zu", i);
                }
                if (s[j] == '\'') {
                    if (j + 1 < n && s[j + 1] == '\'') {
                        j += 2;
                        content++;
                        continue;
                    }
                    break;
                }
                j++;
                content++;
            }
            if (content > IMDB_MAX_TEXT) {
                imdb_free(t);
                return imdb_fail(e, IMDB_ERR_LIMIT, "string literal at offset %zu longer than %u bytes", i, IMDB_MAX_TEXT);
            }
            tk->kind = TK_STR;
            tk->off = (uint32_t)(i + 1);
            tk->len = (uint32_t)(j - i - 1);
            i = j + 1;
        } else if (c == '$') {
            size_t j = i + 1;
            while (j < n && is_digit(s[j])) j++;
            if (j == i + 1 || j - i > 4) {
                imdb_free(t);
                return imdb_fail(e, IMDB_ERR_SYNTAX, "malformed parameter at offset %zu", i);
            }
            tk->kind = TK_PARAM;
            tk->len = (uint32_t)(j - i);
            i = j;
        } else {
            tk->len = 1;
            switch (c) {
            case '(': tk->kind = TK_LP; break;
            case ')': tk->kind = TK_RP; break;
            case ',': tk->kind = TK_COMMA; break;
            case ';': tk->kind = TK_SEMI; break;
            case '*': tk->kind = TK_STAR; break;
            case '=': tk->kind = TK_EQ; break;
            case '-': tk->kind = TK_MINUS; break;
            case '+': tk->kind = TK_PLUS; break;
            case '.': tk->kind = TK_DOT; break; /* a.col (a number's point is lexed with the number) */
            case '<':
                if (i + 1 < n && s[i + 1] == '=') tk->kind = TK_LE, tk->len = 2;
                else if (i + 1 < n && s[i + 1] == '>') tk->kind = TK_NE, tk->len = 2;
                else tk->kind = TK_LT;
                break;
            case '>':
                if (i + 1 < n && s[i + 1] == '=') tk->kind = TK_GE, tk->len = 2;
                else tk->kind = TK_GT;
                break;
            case '!':
                if (i + 1 < n && s[i + 1] == '=') {
                    tk->kind = TK_NE;
                    tk->len = 2;
                    break;
                }
                /* fallthrough */
            default:
                imdb_free(t);
                return imdb_fail(e, IMDB_ERR_SYNTAX, "unexpected character at offset %zu", i);
            }
            i += tk->len;
        }
        k++;
    }
    t[k].kind = TK_EOF;
    t[k].off = (uint32_t)n;
    t[k].len = 0;
    *out = t;
    *ntok = k;
    return IMDB_OK;
}

/* ---- parser -------------------------------------------------------------------- */

typedef struct parser {
    const char *s;
    const sql_tok *t;
    uint32_t n, i;
    imdb_err *e;
} parser;

static const char *const kReserved[] = {
    "select", "from", "where", "insert", "into", "values", "update", "set", "delete", "create", "table",
    "and", "or", "not", "between", "as", "of", "group", "by", "order", "limit", "true", "false", "null",
    "primary", "key", "subject", "erase", "count", "sum", "min", "max", "begin", "commit", "rollback", "is",
};

static bool tok_is_kw(const parser *p, uint32_t at, const char *kw)
{
    const sql_tok *t = &p->t[at];
    if (t->kind != TK_IDENT) return false;
    size_t kl = strlen(kw);
    if (t->len != kl) return false;
    for (size_t k = 0; k < kl; k++) {
        char c = p->s[t->off + k];
        if (c >= 'A' && c <= 'Z') c = (char)(c + 32);
        if (c != kw[k]) return false;
    }
    return true;
}

static bool kw(parser *p, const char *k)
{
    if (!tok_is_kw(p, p->i, k)) return false;
    p->i++;
    return true;
}

static int fail_at(parser *p, const char *what)
{
    return imdb_fail(p->e, IMDB_ERR_SYNTAX, "syntax error at offset %u: expected %s", p->t[p->i].off, what);
}

static int expect_kw(parser *p, const char *k)
{
    if (kw(p, k)) return IMDB_OK;
    char what[48];
    snprintf(what, sizeof what, "%s", k);
    for (char *c = what; *c; c++)
        if (*c >= 'a' && *c <= 'z') *c = (char)(*c - 32);
    return fail_at(p, what);
}

static bool tok(parser *p, uint8_t kind)
{
    if (p->t[p->i].kind != kind) return false;
    p->i++;
    return true;
}

static int expect(parser *p, uint8_t kind, const char *what)
{
    return tok(p, kind) ? IMDB_OK : fail_at(p, what);
}

static bool is_reserved(const parser *p, uint32_t at)
{
    for (size_t k = 0; k < sizeof kReserved / sizeof *kReserved; k++)
        if (tok_is_kw(p, at, kReserved[k])) return true;
    return false;
}

static int ident(parser *p, char out[IMDB_MAX_IDENT + 1])
{
    const sql_tok *t = &p->t[p->i];
    if (t->kind != TK_IDENT || is_reserved(p, p->i)) return fail_at(p, "an identifier");
    if (!imdb_ident_fold(p->s + t->off, t->len, out)) return fail_at(p, "a valid identifier");
    p->i++;
    return IMDB_OK;
}

/* a column, perhaps qualified: col, or table.col / alias.col (qual "" when not) */
static int qident(parser *p, char qual[IMDB_MAX_IDENT + 1], char col[IMDB_MAX_IDENT + 1])
{
    qual[0] = 0;
    if (ident(p, col)) return p->e->code;
    if (!tok(p, TK_DOT)) return IMDB_OK;
    memcpy(qual, col, IMDB_MAX_IDENT + 1);
    return ident(p, col);
}

/* AS alias after a table; not AS OF, the time travel that may follow */
static int alias(parser *p, char out[IMDB_MAX_IDENT + 1])
{
    out[0] = 0;
    if (!tok_is_kw(p, p->i, "as") || tok_is_kw(p, p->i + 1, "of")) return IMDB_OK;
    p->i++;
    return ident(p, out);
}

static int literal(parser *p, sql_lit *l)
{
    memset(l, 0, sizeof *l);
    bool neg = false, sign = false;
    if (p->t[p->i].kind == TK_MINUS || p->t[p->i].kind == TK_PLUS) {
        neg = p->t[p->i].kind == TK_MINUS;
        sign = true;
        p->i++;
    }
    const sql_tok *t = &p->t[p->i];
    if (t->kind == TK_INT || t->kind == TK_DEC || t->kind == TK_FLOAT) {
        l->kind = t->kind == TK_INT ? LIT_INT : t->kind == TK_DEC ? LIT_DEC : LIT_FLOAT;
        l->neg = neg;
        l->off = t->off;
        l->len = t->len;
        p->i++;
        return IMDB_OK;
    }
    if (sign) return fail_at(p, "a number after the sign");
    if (t->kind == TK_STR) {
        l->kind = LIT_STR;
        l->off = t->off;
        l->len = t->len;
        p->i++;
        return IMDB_OK;
    }
    if (t->kind == TK_PARAM) {
        unsigned v = 0;
        for (uint32_t k = 1; k < t->len; k++) v = v * 10 + (unsigned)(p->s[t->off + k] - '0');
        if (v < 1 || v > IMDB_MAX_PARAMS) return fail_at(p, "a parameter $1..$256");
        l->kind = LIT_PARAM;
        l->param = v;
        p->i++;
        return IMDB_OK;
    }
    if (kw(p, "true") || kw(p, "false")) {
        l->kind = LIT_BOOL;
        l->bval = tok_is_kw(p, p->i - 1, "true");
        return IMDB_OK;
    }
    if (kw(p, "timestamp")) {
        const sql_tok *s = &p->t[p->i];
        if (s->kind != TK_STR) return fail_at(p, "a string after TIMESTAMP");
        l->kind = LIT_TS;
        l->off = s->off;
        l->len = s->len;
        p->i++;
        return IMDB_OK;
    }
    if (kw(p, "null")) {
        l->kind = LIT_NULL;
        return IMDB_OK;
    }
    return fail_at(p, "a literal");
}

static int uint_lit(parser *p, uint64_t *out)
{
    const sql_tok *t = &p->t[p->i];
    if (t->kind != TK_INT) return fail_at(p, "an unsigned integer");
    int64_t v;
    imdb_err e2 = {0};
    if (imdb_parse_int64(p->s + t->off, t->len, &v, &e2) || v < 0)
        return imdb_fail(p->e, IMDB_ERR_LIMIT, "integer at offset %u out of range", t->off);
    *out = (uint64_t)v;
    p->i++;
    return IMDB_OK;
}

static int preds(parser *p, sql_stmt *st)
{
    do {
        if (st->nwhere >= IMDB_MAX_PREDICATES)
            return imdb_fail(p->e, IMDB_ERR_LIMIT, "WHERE has more than %u conditions", IMDB_MAX_PREDICATES);
        sql_cmp *c = &st->where[st->nwhere];
        if (kw(p, "not")) return imdb_fail(p->e, IMDB_ERR_UNSUPPORTED, "NOT is not supported; use != or a range");
        if (qident(p, c->qual, c->col)) return p->e->code;
        uint8_t k = p->t[p->i].kind;
        if (kw(p, "is")) {
            c->op = kw(p, "not") ? CMP_NOTNULL : CMP_ISNULL;
            if (expect_kw(p, "null")) return p->e->code;
        } else if (kw(p, "between")) {
            c->op = CMP_BETWEEN;
            if (literal(p, &c->a) || expect_kw(p, "and") || literal(p, &c->b)) return p->e->code;
        } else {
            switch (k) {
            case TK_EQ: c->op = CMP_EQ; break;
            case TK_NE: c->op = CMP_NE; break;
            case TK_LT: c->op = CMP_LT; break;
            case TK_LE: c->op = CMP_LE; break;
            case TK_GT: c->op = CMP_GT; break;
            case TK_GE: c->op = CMP_GE; break;
            default: return fail_at(p, "a comparison (= != < <= > >= BETWEEN IS)");
            }
            p->i++;
            if (literal(p, &c->a)) return p->e->code;
        }
        st->nwhere++;
        if (tok_is_kw(p, p->i, "or"))
            return imdb_fail(p->e, IMDB_ERR_UNSUPPORTED, "OR is not supported; conditions are joined with AND");
    } while (kw(p, "and"));
    return IMDB_OK;
}

static int col_type(parser *p, imdb_column *c)
{
    if (kw(p, "int64") || kw(p, "bigint") || kw(p, "int") || kw(p, "integer")) c->type = IMDB_T_INT64;
    else if (kw(p, "text")) c->type = IMDB_T_TEXT;
    else if (kw(p, "bool") || kw(p, "boolean")) c->type = IMDB_T_BOOL;
    else if (kw(p, "timestamp")) c->type = IMDB_T_TIMESTAMP;
    else if (kw(p, "decimal") || kw(p, "numeric")) {
        c->type = IMDB_T_DECIMAL;
        uint64_t prec, scale = 0;
        if (expect(p, TK_LP, "(") || uint_lit(p, &prec)) return p->e->code;
        if (tok(p, TK_COMMA) && uint_lit(p, &scale)) return p->e->code;
        if (expect(p, TK_RP, ")")) return p->e->code;
        if (prec < 1 || prec > 18 || scale > prec)
            return imdb_fail(p->e, IMDB_ERR_INVALID, "DECIMAL(p,s) needs 1 <= p <= 18 and 0 <= s <= p");
        c->precision = (uint8_t)prec;
        c->scale = (uint8_t)scale;
    } else if (kw(p, "float64") || kw(p, "float8") || kw(p, "float")) {
        c->type = IMDB_T_FLOAT64;
    } else if (kw(p, "double")) {
        kw(p, "precision");
        c->type = IMDB_T_FLOAT64;
    } else if (kw(p, "real") || kw(p, "float4")) {
        return imdb_fail(p->e, IMDB_ERR_UNSUPPORTED, "REAL is single precision; imagedb has FLOAT64 (DOUBLE PRECISION)");
    } else {
        return fail_at(p, "a type (INT64, DECIMAL(p,s), FLOAT64, TEXT, BOOL, TIMESTAMP)");
    }
    return IMDB_OK;
}

/* CREATE INDEX name ON table (column) */
static int parse_create_index(parser *p, sql_stmt *st, bool unique)
{
    st->kind = ST_CREATE_INDEX;
    st->index_unique = unique;
    if (ident(p, st->index_name) || expect_kw(p, "on") || ident(p, st->table) || expect(p, TK_LP, "(")) return p->e->code;
    do {
        if (st->index_ncols >= IMDB_MAX_INDEX_COLS)
            return imdb_fail(p->e, IMDB_ERR_LIMIT, "an index takes at most %u columns", IMDB_MAX_INDEX_COLS);
        if (ident(p, st->index_cols[st->index_ncols++])) return p->e->code;
    } while (tok(p, TK_COMMA));
    return expect(p, TK_RP, ")");
}

/* after RETENTION: n SECONDS | MINUTES | HOURS | DAYS (or the singular), or FOREVER */
static int parse_retention(parser *p, uint64_t *us)
{
    if (kw(p, "forever")) {
        *us = IMDB_RETAIN_FOREVER;
        return IMDB_OK;
    }
    uint64_t n, unit;
    if (uint_lit(p, &n)) return p->e->code;
    if (kw(p, "seconds") || kw(p, "second")) unit = 1000000ull;
    else if (kw(p, "minutes") || kw(p, "minute")) unit = 60ull * 1000000;
    else if (kw(p, "hours") || kw(p, "hour")) unit = 3600ull * 1000000;
    else if (kw(p, "days") || kw(p, "day")) unit = 86400ull * 1000000;
    else return fail_at(p, "SECONDS, MINUTES, HOURS or DAYS");
    if (imdb_mul_ovf(n, unit, us) || !imdb_retention_ok(*us))
        return imdb_fail(p->e, IMDB_ERR_INVALID, "RETENTION is a second to a century, or FOREVER");
    return IMDB_OK;
}

static int parse_create(parser *p, sql_stmt *st)
{
    st->kind = ST_CREATE;
    imdb_schema *s = &st->schema;
    memset(s, 0, sizeof *s);
    s->subject = -1;
    if (expect_kw(p, "table") || ident(p, st->table) || expect(p, TK_LP, "(")) return p->e->code;
    strcpy(s->name, st->table);
    int pk = -1;
    do {
        if (s->ncols >= IMDB_MAX_COLS) return imdb_fail(p->e, IMDB_ERR_LIMIT, "more than %u columns", IMDB_MAX_COLS);
        imdb_column *c = &s->cols[s->ncols];
        if (ident(p, c->name) || col_type(p, c)) return p->e->code;
        int null_spec = 0; /* 1 NULL, 2 NOT NULL */
        for (;;) {
            if (kw(p, "primary")) {
                if (expect_kw(p, "key")) return p->e->code;
                if (c->flags & IMDB_COL_PK) return fail_at(p, "one PRIMARY KEY per column");
                c->flags |= IMDB_COL_PK;
                if (pk >= 0) return imdb_fail(p->e, IMDB_ERR_INVALID, "only one PRIMARY KEY column is supported");
                pk = s->ncols;
            } else if (kw(p, "subject")) {
                if (s->subject >= 0) return imdb_fail(p->e, IMDB_ERR_INVALID, "only one SUBJECT column is supported");
                c->flags |= IMDB_COL_SUBJECT;
                s->subject = (int16_t)s->ncols;
            } else if (kw(p, "not")) {
                if (expect_kw(p, "null")) return p->e->code;
                if (null_spec == 1) return imdb_fail(p->e, IMDB_ERR_INVALID, "column %s: NULL and NOT NULL", c->name);
                null_spec = 2;
            } else if (kw(p, "null")) {
                if (null_spec == 2) return imdb_fail(p->e, IMDB_ERR_INVALID, "column %s: NULL and NOT NULL", c->name);
                null_spec = 1;
            } else {
                break;
            }
        }
        if (c->flags & (IMDB_COL_PK | IMDB_COL_SUBJECT)) {
            if (null_spec == 1)
                return imdb_fail(p->e, IMDB_ERR_INVALID, "column %s: PRIMARY KEY and SUBJECT columns are NOT NULL", c->name);
        } else if (null_spec != 2) {
            c->flags |= IMDB_COL_NULLABLE; /* the SQL default */
        }
        s->ncols++;
    } while (tok(p, TK_COMMA));
    if (expect(p, TK_RP, ")")) return p->e->code;
    if (pk < 0) return imdb_fail(p->e, IMDB_ERR_INVALID, "table needs a PRIMARY KEY column");
    s->pk = (uint16_t)pk;
    if (kw(p, "retention")) {
        st->has_retention = true;
        return parse_retention(p, &st->retention_us);
    }
    return IMDB_OK;
}

static int parse_insert(parser *p, sql_stmt *st)
{
    st->kind = ST_INSERT;
    if (expect_kw(p, "into") || ident(p, st->table)) return p->e->code;
    if (tok(p, TK_LP)) {
        do {
            if (st->ncols >= IMDB_MAX_COLS) return imdb_fail(p->e, IMDB_ERR_LIMIT, "too many columns");
            if (ident(p, st->cols[st->ncols++])) return p->e->code;
        } while (tok(p, TK_COMMA));
        if (expect(p, TK_RP, ")")) return p->e->code;
    }
    if (expect_kw(p, "values")) return p->e->code;
    uint32_t cap = 0;
    do {
        if (st->nrows >= IMDB_MAX_INSERT_ROWS)
            return imdb_fail(p->e, IMDB_ERR_LIMIT, "INSERT has more than %u rows", IMDB_MAX_INSERT_ROWS);
        if (expect(p, TK_LP, "(")) return p->e->code;
        uint16_t w = 0;
        do {
            if (w >= IMDB_MAX_COLS) return imdb_fail(p->e, IMDB_ERR_LIMIT, "too many values in a row");
            size_t at = (size_t)st->nrows * (st->rowlen ? st->rowlen : IMDB_MAX_COLS) + w;
            if (at >= cap) {
                uint32_t ncap = cap ? cap * 2 : 256;
                sql_lit *nv = imdb_realloc_array(st->vals, cap, ncap, sizeof *nv, p->e);
                if (!nv) return p->e->code;
                st->vals = nv;
                cap = ncap;
            }
            if (literal(p, &st->vals[at])) return p->e->code;
            w++;
        } while (tok(p, TK_COMMA));
        if (expect(p, TK_RP, ")")) return p->e->code;
        if (st->nrows == 0) {
            /* first row fixes the width; re-pack it at stride w */
            st->rowlen = w;
        } else if (w != st->rowlen) {
            return imdb_fail(p->e, IMDB_ERR_INVALID, "row %u has %u values, expected %u", st->nrows + 1, w, st->rowlen);
        }
        st->nrows++;
    } while (tok(p, TK_COMMA));
    return IMDB_OK;
}

/* ISOLATION LEVEL SNAPSHOT | REPEATABLE READ | READ COMMITTED | READ UNCOMMITTED | SERIALIZABLE */
static int isolation(parser *p, sql_stmt *st)
{
    if (expect_kw(p, "isolation") || expect_kw(p, "level")) return p->e->code;
    if (kw(p, "snapshot")) st->iso = SQL_ISO_SNAPSHOT;
    else if (kw(p, "serializable")) st->iso = SQL_ISO_SERIALIZABLE;
    else if (kw(p, "repeatable")) {
        if (expect_kw(p, "read")) return p->e->code;
        st->iso = SQL_ISO_SNAPSHOT; /* as in PostgreSQL: snapshot isolation */
    } else if (kw(p, "read")) {
        if (!kw(p, "committed") && !kw(p, "uncommitted")) return fail_at(p, "COMMITTED or UNCOMMITTED");
        st->iso = SQL_ISO_READ_COMMITTED; /* uncommitted data is never visible */
    } else {
        return fail_at(p, "SNAPSHOT, REPEATABLE READ, READ COMMITTED, READ UNCOMMITTED or SERIALIZABLE");
    }
    return IMDB_OK;
}

static int parse_select(parser *p, sql_stmt *st)
{
    st->kind = ST_SELECT;
    if (tok(p, TK_STAR)) {
        st->star = true;
    } else {
        do {
            if (st->nitems >= IMDB_MAX_COLS) return imdb_fail(p->e, IMDB_ERR_LIMIT, "too many select items");
            sql_item *it = &st->items[st->nitems];
            uint8_t agg = 0;
            if (tok_is_kw(p, p->i, "count")) agg = AGG_COUNT;
            else if (tok_is_kw(p, p->i, "sum")) agg = AGG_SUM;
            else if (tok_is_kw(p, p->i, "min")) agg = AGG_MIN;
            else if (tok_is_kw(p, p->i, "max")) agg = AGG_MAX;
            if (agg) {
                p->i++;
                if (expect(p, TK_LP, "(")) return p->e->code;
                if (agg == AGG_COUNT && tok(p, TK_STAR)) agg = AGG_COUNT_STAR;
                else if (qident(p, it->qual, it->col)) return p->e->code;
                if (expect(p, TK_RP, ")")) return p->e->code;
                it->agg = agg;
            } else if (qident(p, it->qual, it->col)) {
                return p->e->code;
            }
            st->nitems++;
        } while (tok(p, TK_COMMA));
    }
    if (expect_kw(p, "from") || ident(p, st->table) || alias(p, st->alias)) return p->e->code;
    if (kw(p, "with")) {
        if (expect(p, TK_LP, "(") || expect_kw(p, "nolock") || expect(p, TK_RP, ")")) return p->e->code;
        st->nolock = true;
    }
    if (tok_is_kw(p, p->i, "right") || tok_is_kw(p, p->i, "full") || tok_is_kw(p, p->i, "cross"))
        return imdb_fail(p->e, IMDB_ERR_UNSUPPORTED, "only INNER and LEFT joins are supported");
    if (tok_is_kw(p, p->i, "join") || tok_is_kw(p, p->i, "inner") || tok_is_kw(p, p->i, "left")) {
        st->has_join = true;
        if (kw(p, "left")) {
            st->join_left = true;
            kw(p, "outer");
        } else {
            kw(p, "inner");
        }
        if (expect_kw(p, "join") || ident(p, st->table2) || alias(p, st->alias2) || expect_kw(p, "on") ||
            qident(p, st->on_qual[0], st->on_col[0]) || expect(p, TK_EQ, "=") || qident(p, st->on_qual[1], st->on_col[1]))
            return p->e->code;
        if (tok_is_kw(p, p->i, "and") || tok_is_kw(p, p->i, "or"))
            return imdb_fail(p->e, IMDB_ERR_UNSUPPORTED, "a join's ON takes one equality; filter in WHERE");
        if (tok_is_kw(p, p->i, "join") || tok_is_kw(p, p->i, "inner") || tok_is_kw(p, p->i, "left") ||
            tok_is_kw(p, p->i, "right") || tok_is_kw(p, p->i, "full") || tok_is_kw(p, p->i, "cross"))
            return imdb_fail(p->e, IMDB_ERR_UNSUPPORTED, "a join takes two tables");
    }
    if (kw(p, "as")) {
        if (expect_kw(p, "of")) return p->e->code;
        st->has_asof = true;
        if (literal(p, &st->asof)) return p->e->code;
        if (st->asof.kind != LIT_INT && st->asof.kind != LIT_TS && st->asof.kind != LIT_STR)
            return imdb_fail(p->e, IMDB_ERR_SYNTAX, "AS OF takes a commit number or TIMESTAMP '...'");
        if (st->asof.neg) return imdb_fail(p->e, IMDB_ERR_SYNTAX, "AS OF commit number must not be negative");
    }
    if (kw(p, "where") && preds(p, st)) return p->e->code;
    if (kw(p, "group")) {
        if (expect_kw(p, "by") || qident(p, st->group_qual, st->group_col)) return p->e->code;
        st->has_group = true;
    }
    if (tok_is_kw(p, p->i, "order"))
        return imdb_fail(p->e, IMDB_ERR_UNSUPPORTED,
                         "ORDER BY is not supported: rows are always returned in primary-key order, groups in key order");
    if (kw(p, "limit")) {
        st->has_limit = true;
        if (uint_lit(p, &st->limit)) return p->e->code;
    }
    if (kw(p, "for")) {
        if (expect_kw(p, "update")) return p->e->code;
        st->for_update = true;
        bool agg = st->has_group;
        for (uint16_t i = 0; i < st->nitems; i++) agg = agg || st->items[i].agg != AGG_NONE;
        if (agg || st->has_asof || st->has_join)
            return imdb_fail(p->e, IMDB_ERR_INVALID, "FOR UPDATE locks rows: not with aggregates, GROUP BY, AS OF or a join");
    }
    return IMDB_OK;
}

void imdb_sql_stmt_free(sql_stmt *st)
{
    imdb_free(st->vals);
    st->vals = NULL;
}

int imdb_sql_parse(const char *s, size_t n, sql_stmt *st, imdb_err *e)
{
    memset(st, 0, sizeof *st);
    sql_tok *t;
    uint32_t nt;
    if (imdb_sql_lex(s, n, &t, &nt, e)) return e->code;
    parser p = {s, t, nt, 0, e};
    int rc = IMDB_OK;
    if (nt == 0 || (nt == 1 && t[0].kind == TK_SEMI)) {
        st->kind = ST_EMPTY;
        imdb_free(t);
        return IMDB_OK;
    }
    if (kw(&p, "create")) {
        bool unique = kw(&p, "unique");
        if (unique) rc = expect_kw(&p, "index");
        if (!rc) rc = unique || kw(&p, "index") ? parse_create_index(&p, st, unique) : parse_create(&p, st);
    }
    else if (kw(&p, "drop")) {
        st->kind = ST_DROP_INDEX;
        if (!(rc = expect_kw(&p, "index"))) rc = ident(&p, st->index_name);
    }
    else if (kw(&p, "alter")) { /* ALTER TABLE t SET RETENTION ... */
        st->kind = ST_ALTER_RETENTION;
        st->has_retention = true;
        if (!(rc = expect_kw(&p, "table")) && !(rc = ident(&p, st->table)) && !(rc = expect_kw(&p, "set")) &&
            !(rc = expect_kw(&p, "retention")))
            rc = parse_retention(&p, &st->retention_us);
    }
    else if (kw(&p, "insert")) rc = parse_insert(&p, st);
    else if (kw(&p, "update")) {
        st->kind = ST_UPDATE;
        if (!(rc = ident(&p, st->table)) && !(rc = expect_kw(&p, "set"))) {
            do {
                if (st->nset >= IMDB_MAX_COLS) {
                    rc = imdb_fail(e, IMDB_ERR_LIMIT, "too many assignments");
                    break;
                }
                if ((rc = ident(&p, st->set_cols[st->nset])) || (rc = expect(&p, TK_EQ, "=")) ||
                    (rc = literal(&p, &st->set_vals[st->nset])))
                    break;
                st->nset++;
            } while (tok(&p, TK_COMMA));
            if (!rc && kw(&p, "where")) rc = preds(&p, st);
        }
    } else if (kw(&p, "delete")) {
        st->kind = ST_DELETE;
        if (!(rc = expect_kw(&p, "from")) && !(rc = ident(&p, st->table)) && kw(&p, "where")) rc = preds(&p, st);
    } else if (kw(&p, "select")) rc = parse_select(&p, st);
    else if (kw(&p, "begin")) {
        st->kind = ST_BEGIN;
        if (!kw(&p, "transaction")) kw(&p, "work");
        if (tok_is_kw(&p, p.i, "isolation")) rc = isolation(&p, st);
    } else if (kw(&p, "commit")) {
        st->kind = ST_COMMIT;
        if (!kw(&p, "transaction")) kw(&p, "work");
    } else if (kw(&p, "rollback")) {
        st->kind = ST_ROLLBACK;
        if (!kw(&p, "transaction")) kw(&p, "work");
        if (kw(&p, "to")) {
            st->kind = ST_ROLLBACK_TO;
            kw(&p, "savepoint");
            rc = ident(&p, st->savepoint);
        }
    } else if (kw(&p, "savepoint")) {
        st->kind = ST_SAVEPOINT;
        rc = ident(&p, st->savepoint);
    } else if (kw(&p, "release")) {
        st->kind = ST_RELEASE;
        kw(&p, "savepoint");
        rc = ident(&p, st->savepoint);
    }
    else if (kw(&p, "checkpoint")) st->kind = ST_CHECKPOINT;
    else if (kw(&p, "compact")) {
        st->kind = ST_COMPACT;
        if (!(rc = ident(&p, st->table)) && kw(&p, "purge")) {
            st->has_purge = true;
            if (!(rc = expect_kw(&p, "before"))) rc = uint_lit(&p, &st->purge_before);
        }
    } else if (kw(&p, "erase")) {
        if (kw(&p, "subject")) {
            st->kind = ST_ERASE_SUBJECT;
            rc = literal(&p, &st->subject);
        } else if (kw(&p, "from")) {
            st->kind = ST_ERASE_WHERE;
            if (!(rc = ident(&p, st->table)) && !(rc = expect_kw(&p, "where"))) rc = preds(&p, st);
        } else {
            rc = fail_at(&p, "SUBJECT or FROM after ERASE");
        }
    } else if (kw(&p, "verify")) st->kind = ST_VERIFY;
    else if (kw(&p, "show")) {
        if (kw(&p, "tables")) st->kind = ST_SHOW_TABLES;
        else if (kw(&p, "indexes")) st->kind = ST_SHOW_INDEXES;
        else if (kw(&p, "retention")) st->kind = ST_SHOW_RETENTION;
        else if (kw(&p, "lake")) st->kind = ST_SHOW_LAKE;
        else if (kw(&p, "identity")) st->kind = ST_SHOW_IDENTITY;
        else if (kw(&p, "replicas")) st->kind = ST_SHOW_REPLICAS;
        else if (kw(&p, "replication")) st->kind = ST_SHOW_REPLICATION;
        else if (kw(&p, "memory")) st->kind = ST_SHOW_MEMORY;
        else if (kw(&p, "erasure")) { /* AT n: through commit n (the default: the current commit) */
            st->kind = ST_SHOW_ERASURE;
            if (kw(&p, "at") && !(rc = uint_lit(&p, &st->n)) && st->n == 0) rc = fail_at(&p, "a commit number from 1");
        }
        else if (kw(&p, "log")) {
            st->kind = ST_SHOW_LOG;
            st->n = 10;
            if (p.t[p.i].kind == TK_INT) rc = uint_lit(&p, &st->n);
        } else if (kw(&p, "history")) {
            st->kind = ST_SHOW_HISTORY;
            if (!(rc = ident(&p, st->table))) rc = literal(&p, &st->key);
        } else if (kw(&p, "digest")) {
            st->kind = ST_SHOW_DIGEST;
            if (p.t[p.i].kind == TK_IDENT && !is_reserved(&p, p.i)) {
                rc = ident(&p, st->table);
                if (!rc && kw(&p, "subject")) {
                    st->has_subject = true;
                    rc = literal(&p, &st->subject);
                }
                if (!rc && kw(&p, "as")) {
                    if (!(rc = expect_kw(&p, "of"))) {
                        st->has_asof = true;
                        rc = literal(&p, &st->asof);
                    }
                }
            }
        } else {
            rc = fail_at(&p, "TABLES, DIGEST, HISTORY, LOG, LAKE, IDENTITY or REPLICAS after SHOW");
        }
    } else if (kw(&p, "set")) {
        st->kind = ST_SET;
        if (kw(&p, "transaction")) {
            st->kind = ST_SET_TXN;
            rc = isolation(&p, st);
        } else if (!(rc = ident(&p, st->set_name))) {
            if (!tok(&p, TK_EQ) && !kw(&p, "to")) rc = fail_at(&p, "= or TO");
            else {
                const sql_tok *v = &p.t[p.i];
                if ((v->kind == TK_IDENT || v->kind == TK_INT) && v->len <= IMDB_MAX_IDENT) {
                    for (uint32_t k = 0; k < v->len; k++) {
                        char c = s[v->off + k];
                        st->set_value[k] = (c >= 'A' && c <= 'Z') ? (char)(c + 32) : c;
                    }
                    st->set_value[v->len] = 0;
                    p.i++;
                } else {
                    rc = fail_at(&p, "a setting value");
                }
            }
        }
    } else {
        rc = fail_at(&p, "a statement");
    }
    if (!rc) {
        tok(&p, TK_SEMI);
        if (p.t[p.i].kind != TK_EOF) rc = fail_at(&p, "end of statement");
    }
    imdb_free(t);
    if (rc) imdb_sql_stmt_free(st);
    return rc;
}
