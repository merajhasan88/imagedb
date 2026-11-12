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
            case '/': tk->kind = TK_SLASH; break;
            case '%': tk->kind = TK_PERCENT; break;
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
            case '|': /* P2 S1: || alone */
                if (i + 1 < n && s[i + 1] == '|') {
                    tk->kind = TK_CONCAT;
                    tk->len = 2;
                    break;
                }
                imdb_free(t);
                return imdb_fail(e, IMDB_ERR_SYNTAX, "unexpected character at offset %zu", i);
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
    sql_stmt *st;            /* its expression nodes */
    uint8_t depth;           /* P2 S4: nested SELECTs around this point */
    uint16_t narms;          /* P2 S5: the statement's set operations' arms so far (arm_new) */
    uint8_t parens;          /* P2 S5: parenthesized queries around this point (parse_operand: bounded) */
    bool win_ok;             /* P2 S6: parsing a SELECT item's expression, where a window function may stand */
    bool seqcall;            /* F2a-2: nextval or setval called anywhere in the statement: it writes */
    bool randcall;           /* F3d: gen_random_uuid called anywhere in it */
} parser;

static int parse_nested(parser *p, sql_stmt *outer, const char *name); /* P2 S4 */

static const char *const kReserved[] = {
    "select", "from", "where", "insert", "into", "values", "update", "set", "delete", "create", "table",
    "and", "or", "not", "between", "as", "of", "group", "by", "order", "limit", "true", "false", "null",
    "primary", "key", "subject", "erase", "count", "sum", "min", "max", "begin", "commit", "rollback", "is",
    "case", "when", "then", "else", "end", "cast", "in", "like", "escape", /* P2 S1 */
    "union", "intersect", "except", /* P2 S5: never a FROM item's alias */
    "over",                          /* P2 S6 */
    "returning", "with", "on",       /* P2 S8: never an alias in INSERT's query (ON CONFLICT); WITH, as PostgreSQL */
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

/* a typed timestamp literal begins at token i: TIMESTAMP or TIMESTAMPTZ then a string; P2: TIMESTAMP WITH or WITHOUT TIME
 * ZONE then a string (each token checked before the next is read: the end token stops the chain) */
static bool ts_literal_at(const parser *p, uint32_t i)
{
    if (tok_is_kw(p, i, "date") || tok_is_kw(p, i, "time")) return p->t[i + 1].kind == TK_STR; /* F3b: DATE '...', TIME '...' */
    if (tok_is_kw(p, i, "uuid") || tok_is_kw(p, i, "bytea")) return p->t[i + 1].kind == TK_STR; /* F3d */
    if (tok_is_kw(p, i, "interval")) return p->t[i + 1].kind == TK_STR; /* F3f */
    if (tok_is_kw(p, i, "timestamptz")) return p->t[i + 1].kind == TK_STR;
    if (!tok_is_kw(p, i, "timestamp")) return false;
    if (p->t[i + 1].kind == TK_STR) return true;
    return (tok_is_kw(p, i + 1, "with") || tok_is_kw(p, i + 1, "without")) && tok_is_kw(p, i + 2, "time") &&
           tok_is_kw(p, i + 3, "zone") && p->t[i + 4].kind == TK_STR;
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

/* F3f: a word naming an INTERVAL field (the SQL standard's qualifiers, refused this slice) */
static bool iv_field_word(const parser *p, uint32_t i)
{
    static const char *const w[] = {"year", "month", "day", "hour", "minute", "second"};
    for (size_t k = 0; k < sizeof w / sizeof *w; k++)
        if (tok_is_kw(p, i, w[k])) return true;
    return false;
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
    /* F3d: UUID '...' and BYTEA '...', as DATE's */
    if ((tok_is_kw(p, p->i, "uuid") || tok_is_kw(p, p->i, "bytea")) && p->t[p->i + 1].kind == TK_STR) {
        l->kind = tok_is_kw(p, p->i, "uuid") ? LIT_UUID : LIT_BYTEA;
        l->off = p->t[p->i + 1].off;
        l->len = p->t[p->i + 1].len;
        p->i += 2;
        return IMDB_OK;
    }
    /* F3f: INTERVAL '...', PostgreSQL's verbose form; a field after it (INTERVAL '1' DAY, the SQL standard's) is refused
     * by name: read as an alias it would change the value */
    if (tok_is_kw(p, p->i, "interval") && p->t[p->i + 1].kind == TK_STR) {
        l->kind = LIT_INTERVAL;
        l->off = p->t[p->i + 1].off;
        l->len = p->t[p->i + 1].len;
        p->i += 2;
        if (iv_field_word(p, p->i))
            return imdb_fail(p->e, IMDB_ERR_UNSUPPORTED, "INTERVAL '...' with a field after it (the SQL standard's form) is "
                                                         "not in imagedb yet: write the unit in the string, INTERVAL '1 day'");
        return IMDB_OK;
    }
    /* F3b: DATE '...' and TIME '...' (a column named date or time is an identifier: no string follows it) */
    if ((tok_is_kw(p, p->i, "date") || tok_is_kw(p, p->i, "time")) && p->t[p->i + 1].kind == TK_STR) {
        l->kind = tok_is_kw(p, p->i, "date") ? LIT_DATE : LIT_TIME;
        l->off = p->t[p->i + 1].off;
        l->len = p->t[p->i + 1].len;
        p->i += 2;
        return IMDB_OK;
    }
    /* TIMESTAMP '...', TIMESTAMP WITHOUT TIME ZONE '...'; P2: TIMESTAMPTZ '...', TIMESTAMP WITH TIME ZONE '...' */
    if (tok_is_kw(p, p->i, "timestamp") || tok_is_kw(p, p->i, "timestamptz")) {
        bool tz = tok_is_kw(p, p->i, "timestamptz");
        p->i++;
        if (!tz && (tok_is_kw(p, p->i, "with") || tok_is_kw(p, p->i, "without")) && tok_is_kw(p, p->i + 1, "time") &&
            tok_is_kw(p, p->i + 2, "zone")) {
            tz = tok_is_kw(p, p->i, "with");
            p->i += 3;
        }
        const sql_tok *s = &p->t[p->i];
        if (s->kind != TK_STR) return fail_at(p, tz ? "a string after TIMESTAMPTZ" : "a string after TIMESTAMP");
        l->kind = tz ? LIT_TSTZ : LIT_TS;
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

/* F2a-2: [-]n as an int64, INT64_MIN too */
static int int64_lit(parser *p, int64_t *out)
{
    bool neg = tok(p, TK_MINUS);
    if (!neg) tok(p, TK_PLUS);
    const sql_tok *t = &p->t[p->i];
    if (t->kind != TK_INT) return fail_at(p, "an integer");
    char buf[32];
    if (t->len + 1 >= sizeof buf) return imdb_fail(p->e, IMDB_ERR_LIMIT, "integer at offset %u out of range", t->off);
    buf[0] = '-';
    memcpy(buf + 1, p->s + t->off, t->len);
    imdb_err e2 = {0};
    if (imdb_parse_int64(neg ? buf : buf + 1, t->len + neg, out, &e2))
        return imdb_fail(p->e, IMDB_ERR_LIMIT, "integer at offset %u out of range", t->off);
    p->i++;
    return IMDB_OK;
}

/* F2a-2: a sequence's options, PostgreSQL's spelling (create: AS type too); CYCLE, a CACHE past 1 and OWNED BY refused */
static int seq_options(parser *p, sql_seqopt *o, bool create)
{
    for (;;) {
        if (create && kw(p, "as")) {
            if (kw(p, "bigint") || kw(p, "int8") || kw(p, "int64")) o->width = 0;
            else if (kw(p, "integer") || kw(p, "int") || kw(p, "int4")) o->width = 32;
            else if (kw(p, "smallint") || kw(p, "int2")) o->width = 16;
            else return fail_at(p, "SMALLINT, INTEGER or BIGINT");
        } else if (kw(p, "increment")) {
            kw(p, "by");
            if (int64_lit(p, &o->inc)) return p->e->code;
            o->has_inc = true;
        } else if (kw(p, "minvalue")) {
            if (int64_lit(p, &o->min)) return p->e->code;
            o->has_min = true;
        } else if (kw(p, "maxvalue")) {
            if (int64_lit(p, &o->max)) return p->e->code;
            o->has_max = true;
        } else if (kw(p, "start")) {
            kw(p, "with");
            if (int64_lit(p, &o->start)) return p->e->code;
            o->has_start = true;
        } else if (kw(p, "cache")) {
            int64_t c;
            if (int64_lit(p, &c)) return p->e->code;
            if (c != 1) return imdb_fail(p->e, IMDB_ERR_UNSUPPORTED, "CACHE %lld: a sequence's values are handed out "
                                         "one at a time (each commit logs its mark)", (long long)c);
        } else if (kw(p, "cycle")) {
            return imdb_fail(p->e, IMDB_ERR_UNSUPPORTED, "CYCLE: a sequence's marks only advance (deferred.md D18)");
        } else if (tok_is_kw(p, p->i, "no")) {
            p->i++;
            if (kw(p, "minvalue")) o->has_min = false;
            else if (kw(p, "maxvalue")) o->has_max = false;
            else if (!kw(p, "cycle")) return fail_at(p, "MINVALUE, MAXVALUE or CYCLE");
        } else if (tok_is_kw(p, p->i, "owned")) {
            return imdb_fail(p->e, IMDB_ERR_UNSUPPORTED, "OWNED BY: an IDENTITY column owns its sequence (deferred.md D18)");
        } else {
            return IMDB_OK;
        }
    }
}

/* ---- expressions (docs/plan-p0.md 1b) ----------------------------------------------------------------------------
 *   bexpr   := b_and (OR b_and)*                     one ladder, PostgreSQL's (1c): (a + 1) > 2 and (a > 1 OR b < 2)
 *   b_and   := b_not (AND b_not)*                   both parse through '(' bexpr ')'
 *   b_not   := NOT b_not | b_cmp
 *   b_cmp   := aexpr [(= | != | < | <= | > | >=) aexpr | BETWEEN aexpr AND aexpr | IS [NOT] NULL]   (not chained)
 *   aexpr   := term (('+' | '-') term)*
 *   term    := unary (('*' | '/' | '%') unary)*
 *   unary   := ('-' | '+') unary | primary          a sign right before a number is the literal's (INT64_MIN parses)
 *   primary := literal | $n | [qual.]col | '(' bexpr ')' | COUNT '(' '*' ')' | (COUNT | SUM | MIN | MAX) '(' bexpr ')'
 * Nodes go into the statement's pool; both the recursion and a tree's height stop at IMDB_MAX_EXPR_DEPTH, so neither
 * the parser nor the evaluator can be driven deep. Which trees may hold columns or aggregates is the binder's rule. */

static int bexpr(parser *p, uint16_t *out, unsigned depth);
static int aexpr(parser *p, uint16_t *out, unsigned depth);
static int col_type(parser *p, imdb_column *c, char *tname);
static int col_tname(parser *p, uint16_t at, const char *tname);

static int ex_new(parser *p, uint8_t op, uint16_t l, uint16_t r, uint16_t *out)
{
    sql_stmt *st = p->st;
    if (st->nex + 1u >= IMDB_MAX_EXPR_NODES)
        return imdb_fail(p->e, IMDB_ERR_LIMIT, "expressions of more than %u terms in one statement", IMDB_MAX_EXPR_NODES - 1);
    if (st->nex + 2u > st->capex) {
        uint16_t nc = st->capex ? (uint16_t)(st->capex * 2) : 16;
        sql_expr *ne = imdb_realloc_array(st->ex, st->capex, nc, sizeof *ne, p->e);
        if (!ne) return p->e->code;
        st->ex = ne;
        st->capex = nc;
    }
    uint16_t k = ++st->nex;
    sql_expr *x = &st->ex[k];
    memset(x, 0, sizeof *x);
    x->op = op;
    x->l = l;
    x->r = r;
    unsigned hl = l ? st->ex[l].h : 0u, hr = r ? st->ex[r].h : 0u, h = hl > hr ? hl : hr;
    if (h + 1 > IMDB_MAX_EXPR_DEPTH)
        return imdb_fail(p->e, IMDB_ERR_LIMIT, "an expression nested deeper than %u", IMDB_MAX_EXPR_DEPTH);
    x->h = (uint8_t)(h + 1);
    *out = k;
    return IMDB_OK;
}

static int too_deep(parser *p)
{
    return imdb_fail(p->e, IMDB_ERR_LIMIT, "an expression nested deeper than %u", IMDB_MAX_EXPR_DEPTH);
}

/* ---- P2 S1: lists, functions, CASE, CAST ------------------------------------------------------------------------- */

/* the n elements of el as a balanced EX_LIST tree, in order (one element is itself): its depth is log2(n), so the
 * walkers that follow l, r and x3 stay within the height bound whatever a list's length */
static int list_build_n(parser *p, const uint16_t *el, uint32_t n, uint16_t *out);
static int list_build(parser *p, const uint16_t *el, uint32_t n, uint16_t *out)
{
    if (!n) return fail_at(p, "a value"); /* never from the parser's callers: they hold one at least */
    return list_build_n(p, el, n, out);
}

static int list_build_n(parser *p, const uint16_t *el, uint32_t n, uint16_t *out)
{
    if (n == 1) {
        *out = el[0];
        return IMDB_OK;
    }
    uint16_t a, b;
    if (list_build_n(p, el, n / 2, &a) || list_build_n(p, el + n / 2, n - n / 2, &b)) return p->e->code;
    return ex_new(p, EX_LIST, a, b, out);
}

static int list_push(parser *p, uint16_t **el, uint32_t *n, uint32_t *cap, uint16_t k)
{
    if (*n == *cap) {
        uint32_t nc = *cap ? *cap * 2 : 8;
        uint16_t *ne = imdb_realloc_array(*el, *cap, nc, sizeof *ne, p->e);
        if (!ne) return p->e->code;
        *el = ne;
        *cap = nc;
    }
    (*el)[(*n)++] = k;
    return IMDB_OK;
}

/* expressions separated by commas up to ")" (eaten), one at least, as a balanced list; their count in *n */
static int expr_list(parser *p, unsigned depth, uint16_t *out, uint32_t *n)
{
    uint16_t *el = NULL, k;
    uint32_t cnt = 0, cap = 0;
    int rc = IMDB_OK;
    do {
        if ((rc = bexpr(p, &k, depth + 1)) || (rc = list_push(p, &el, &cnt, &cap, k))) break;
    } while (tok(p, TK_COMMA));
    if (!rc) rc = expect(p, TK_RP, ")");
    if (!rc) rc = list_build(p, el, cnt, out);
    imdb_free(el);
    *n = cnt;
    return rc;
}

/* the function a name calls (an identifier followed by "("), 0 for none: its column keeps the name otherwise */
static uint8_t fn_named(const parser *p, uint32_t at)
{
    static const struct {
        const char *name;
        uint8_t fn;
    } k[] = {{"abs", FN_ABS},           {"sign", FN_SIGN},         {"round", FN_ROUND},
             {"ceil", FN_CEIL},         {"ceiling", FN_CEIL},      {"floor", FN_FLOOR},
             {"mod", FN_MOD},           {"length", FN_LENGTH},     {"char_length", FN_LENGTH},
             {"character_length", FN_LENGTH}, {"substr", FN_SUBSTR}, {"substring", FN_SUBSTR},
             {"trim", FN_TRIM},         {"ltrim", FN_LTRIM},       {"rtrim", FN_RTRIM},
             {"position", FN_POSITION}, {"coalesce", FN_COALESCE}, {"nullif", FN_NULLIF},
             {"lower", FN_LOWER},       {"upper", FN_UPPER},       {"replace", FN_REPLACE},
             {"date_trunc", FN_DATE_TRUNC}, {"timezone", FN_TIMEZONE}, /* P2 */
             {"now", FN_NOW},                                    /* F2a */
             {"nextval", FN_NEXTVAL}, {"currval", FN_CURRVAL}, {"setval", FN_SETVAL}, {"lastval", FN_LASTVAL}, /* F2a-2 */
             {"gen_random_uuid", FN_GEN_RANDOM_UUID}, {"octet_length", FN_OCTET_LENGTH}}; /* F3d */
    for (size_t i = 0; i < sizeof k / sizeof *k; i++)
        if (tok_is_kw(p, at, k[i].name)) return k[i].fn;
    return 0;
}

/* name(args): POSITION(a IN b) in the standard's form, the others with commas; the binder checks the arguments */
static int fn_call(parser *p, uint8_t fn, uint16_t *out, unsigned depth)
{
    p->i += 2; /* the name and its ( */
    if (fn == FN_NEXTVAL || fn == FN_SETVAL) p->seqcall = true; /* F2a-2: the statement writes */
    if (fn == FN_GEN_RANDOM_UUID) p->randcall = true; /* F3d */
    uint16_t args;
    uint32_t n;
    if (fn == FN_POSITION) {
        uint16_t el[2];
        if (aexpr(p, &el[0], depth + 1) || expect_kw(p, "in") || aexpr(p, &el[1], depth + 1) || expect(p, TK_RP, ")") ||
            list_build(p, el, 2, &args))
            return p->e->code;
        n = 2;
    } else if (p->t[p->i].kind == TK_RP) { /* F2a: now(), no arguments */
        p->i++;
        args = 0;
        n = 0;
    } else if (expr_list(p, depth, &args, &n)) {
        return p->e->code;
    }
    if (n > 255) return imdb_fail(p->e, IMDB_ERR_LIMIT, "a function call of more than 255 arguments");
    if (ex_new(p, EX_FN, args, 0, out)) return p->e->code;
    p->st->ex[*out].fn = fn;
    p->st->ex[*out].nargs = (uint8_t)n;
    return IMDB_OK;
}

/* CASE [operand] WHEN a THEN b ... [ELSE c] END (CASE eaten) */
static int case_expr(parser *p, uint16_t *out, unsigned depth)
{
    uint16_t operand = 0, els = 0, whens = 0, *w = NULL;
    uint32_t n = 0, cap = 0;
    int rc = IMDB_OK;
    if (!tok_is_kw(p, p->i, "when")) rc = bexpr(p, &operand, depth + 1);
    while (!rc && kw(p, "when")) {
        uint16_t c, v, k;
        if ((rc = bexpr(p, &c, depth + 1)) || (rc = expect_kw(p, "then")) || (rc = bexpr(p, &v, depth + 1)) ||
            (rc = ex_new(p, EX_WHEN, c, v, &k)))
            break;
        rc = list_push(p, &w, &n, &cap, k);
    }
    if (!rc && !n) rc = fail_at(p, "WHEN");
    if (!rc && kw(p, "else")) rc = bexpr(p, &els, depth + 1);
    if (!rc) rc = expect_kw(p, "end");
    if (!rc) rc = list_build(p, w, n, &whens);
    imdb_free(w);
    if (rc || ex_new(p, EX_CASE, operand, whens, out)) return p->e->code;
    sql_expr *x = &p->st->ex[*out];
    x->x3 = els;
    if (els && p->st->ex[els].h + 1u > x->h) x->h = (uint8_t)(p->st->ex[els].h + 1u);
    return x->h > IMDB_MAX_EXPR_DEPTH ? too_deep(p) : IMDB_OK;
}

/* CAST(x AS type) (CAST eaten): the type as a column's */
static int cast_expr(parser *p, uint16_t *out, unsigned depth)
{
    uint16_t a;
    imdb_column c;
    memset(&c, 0, sizeof c);
    char tn[IMDB_MAX_IDENT + 1] = "";
    if (expect(p, TK_LP, "(") || bexpr(p, &a, depth + 1) || expect_kw(p, "as") || col_type(p, &c, tn) ||
        expect(p, TK_RP, ")") || ex_new(p, EX_CAST, a, 0, out))
        return p->e->code;
    sql_expr *x = &p->st->ex[*out];
    x->ctype = c.type;
    x->cscale = c.scale;
    x->cprec = c.precision;
    x->cvlen = c.vlen; /* F3c */
    if (c.type == IMDB_T_ENUM) memcpy(x->col, tn, sizeof tn); /* F3g: its type's name, resolved at binding */
    return IMDB_OK;
}

/* P2 S4: (SELECT ...) after its '(', as an expression's operand: a value (subk 0), EXISTS's (1), IN's values (2) */
static int subq(parser *p, uint8_t kind, uint16_t *out)
{
    if (parse_nested(p, p->st, "") || expect(p, TK_RP, ")") || ex_new(p, EX_SUBQ, 0, 0, out)) return p->e->code;
    p->st->ex[*out].sub = (uint8_t)(p->st->nsub - 1);
    p->st->ex[*out].subk = kind;
    return IMDB_OK;
}

/* ---- P2 S6: window functions -------------------------------------------------------------------------------------- */

static uint8_t wf_named(const parser *p, uint32_t at)
{
    static const struct {
        const char *n;
        uint8_t f;
    } W[] = {{"row_number", WF_ROW_NUMBER}, {"rank", WF_RANK},   {"dense_rank", WF_DENSE_RANK}, {"ntile", WF_NTILE},
             {"lag", WF_LAG},               {"lead", WF_LEAD},   {"first_value", WF_FIRST},     {"last_value", WF_LAST}};
    for (size_t i = 0; i < sizeof W / sizeof *W; i++)
        if (tok_is_kw(p, at, W[i].n)) return W[i].f;
    return 0;
}

/* a frame's bound: UNBOUNDED PRECEDING, n PRECEDING, CURRENT ROW, n FOLLOWING, UNBOUNDED FOLLOWING */
static int frame_bound(parser *p, uint8_t *kind, int64_t *n)
{
    if (kw(p, "unbounded")) {
        if (kw(p, "preceding")) *kind = WB_UNB_PREC;
        else if (kw(p, "following")) *kind = WB_UNB_FOLL;
        else return fail_at(p, "PRECEDING or FOLLOWING");
        return IMDB_OK;
    }
    if (kw(p, "current")) {
        *kind = WB_CURRENT;
        return expect_kw(p, "row");
    }
    uint64_t v;
    if (uint_lit(p, &v)) return p->e->code;
    if (v > IMDB_MAX_VERSIONS) return imdb_fail(p->e, IMDB_ERR_LIMIT, "a frame of more than %llu rows", (unsigned long long)IMDB_MAX_VERSIONS);
    *n = (int64_t)v;
    if (kw(p, "preceding")) *kind = WB_PREC;
    else if (kw(p, "following")) *kind = WB_FOLL;
    else return fail_at(p, "PRECEDING or FOLLOWING");
    return IMDB_OK;
}

/* OVER ( [PARTITION BY e, ...] [ORDER BY k [ASC | DESC] [NULLS FIRST | LAST], ...] [ROWS | RANGE frame] ) into the
 * statement's next window: no window function inside one (win_ok off); RANGE with UNBOUNDED and CURRENT ROW bounds only
 * (an offset needs a numeric distance between order keys: a later step); PostgreSQL's order of bounds */
static int window_spec(parser *p, uint8_t *out, unsigned depth)
{
    sql_stmt *st = p->st;
    if (st->nwin >= IMDB_MAX_WINDOWS)
        return imdb_fail(p->e, IMDB_ERR_LIMIT, "more than %u window functions in one SELECT", IMDB_MAX_WINDOWS);
    if (expect(p, TK_LP, "(")) return p->e->code;
    if (p->t[p->i].kind == TK_IDENT && !is_reserved(p, p->i) && !tok_is_kw(p, p->i, "partition") &&
        !tok_is_kw(p, p->i, "rows") && !tok_is_kw(p, p->i, "range"))
        return imdb_fail(p->e, IMDB_ERR_UNSUPPORTED, "a named window (WINDOW w AS ...): a later step");
    sql_win *w = &st->win[st->nwin];
    memset(w, 0, sizeof *w);
    bool ok = p->win_ok;
    p->win_ok = false;
    int rc = IMDB_OK;
    if (kw(p, "partition") && !(rc = expect_kw(p, "by"))) {
        do {
            if (w->npart >= IMDB_MAX_WIN_KEYS) rc = imdb_fail(p->e, IMDB_ERR_LIMIT, "PARTITION BY of more than %u keys", IMDB_MAX_WIN_KEYS);
            else rc = bexpr(p, &w->part[w->npart++], depth + 1);
        } while (!rc && tok(p, TK_COMMA));
    }
    if (!rc && kw(p, "order") && !(rc = expect_kw(p, "by"))) {
        do {
            if (w->nord >= IMDB_MAX_WIN_KEYS) {
                rc = imdb_fail(p->e, IMDB_ERR_LIMIT, "a window's ORDER BY of more than %u keys", IMDB_MAX_WIN_KEYS);
                break;
            }
            uint8_t o = w->nord;
            if ((rc = bexpr(p, &w->ord[o], depth + 1))) break;
            w->desc[o] = kw(p, "desc");
            if (!w->desc[o]) kw(p, "asc");
            w->nfirst[o] = w->desc[o]; /* PostgreSQL's default: NULLs as the largest */
            if (kw(p, "nulls")) {
                if (kw(p, "first")) w->nfirst[o] = true;
                else if (kw(p, "last")) w->nfirst[o] = false;
                else rc = fail_at(p, "FIRST or LAST after NULLS");
            }
            w->nord++;
        } while (!rc && tok(p, TK_COMMA));
    }
    if (!rc && (tok_is_kw(p, p->i, "rows") || tok_is_kw(p, p->i, "range"))) {
        w->frame = kw(p, "rows") ? WFR_ROWS : (kw(p, "range"), WFR_RANGE);
        if (kw(p, "between")) {
            if (!(rc = frame_bound(p, &w->lo, &w->lo_n)) && !(rc = expect_kw(p, "and"))) rc = frame_bound(p, &w->hi, &w->hi_n);
        } else {
            rc = frame_bound(p, &w->lo, &w->lo_n);
            w->hi = WB_CURRENT;
        }
        if (!rc && w->lo == WB_UNB_FOLL) rc = imdb_fail(p->e, IMDB_ERR_INVALID, "a frame cannot start UNBOUNDED FOLLOWING");
        if (!rc && w->hi == WB_UNB_PREC) rc = imdb_fail(p->e, IMDB_ERR_INVALID, "a frame cannot end UNBOUNDED PRECEDING");
        if (!rc && ((w->lo == WB_CURRENT && w->hi == WB_PREC) || (w->lo == WB_FOLL && (w->hi == WB_PREC || w->hi == WB_CURRENT))))
            rc = imdb_fail(p->e, IMDB_ERR_INVALID, "a frame cannot end before the row it starts at");
        if (!rc && w->frame == WFR_RANGE && (w->lo == WB_PREC || w->lo == WB_FOLL || w->hi == WB_PREC || w->hi == WB_FOLL))
            rc = imdb_fail(p->e, IMDB_ERR_UNSUPPORTED, "RANGE with an offset: a later step (ROWS takes one)");
    }
    if (!rc) rc = expect(p, TK_RP, ")");
    p->win_ok = ok;
    if (!rc) *out = st->nwin++;
    return rc;
}

/* a window function's call: f(args) OVER (...), a SELECT item's whole expression only (win_ok) */
static int window_call(parser *p, uint8_t wf, uint16_t *out, unsigned depth)
{
    if (!p->win_ok)
        return imdb_fail(p->e, IMDB_ERR_INVALID, "a window function stands only as a SELECT item, alone (compute on it from a "
                                                 "derived table)");
    p->i += 2; /* the name, then ( */
    uint16_t a[3] = {0, 0, 0};
    uint8_t n = 0;
    bool none = wf == WF_ROW_NUMBER || wf == WF_RANK || wf == WF_DENSE_RANK;
    if (!none) {
        bool ok = p->win_ok;
        p->win_ok = false;
        int rc = IMDB_OK;
        do {
            if (n >= 3) rc = imdb_fail(p->e, IMDB_ERR_INVALID, "a window function of more than 3 arguments");
            else rc = bexpr(p, &a[n++], depth + 1);
        } while (!rc && tok(p, TK_COMMA));
        p->win_ok = ok;
        if (rc) return rc;
    }
    if (expect(p, TK_RP, ")")) return p->e->code;
    uint8_t lo = none ? 0 : 1, hi = none ? 0 : wf == WF_LAG || wf == WF_LEAD ? 3 : 1;
    if (n < lo || n > hi) return imdb_fail(p->e, IMDB_ERR_INVALID, "that window function takes %u to %u arguments", lo, hi);
    if (!kw(p, "over")) return fail_at(p, "OVER (...) after a window function");
    uint8_t w;
    if (window_spec(p, &w, depth) || ex_new(p, EX_WIN, a[0], a[1], out)) return p->e->code;
    sql_expr *x = &p->st->ex[*out];
    x->fn = wf;
    x->sub = w;
    x->x3 = a[2];
    if (a[2] && p->st->ex[a[2]].h + 1u > x->h) x->h = (uint8_t)(p->st->ex[a[2]].h + 1u);
    return x->h > IMDB_MAX_EXPR_DEPTH ? too_deep(p) : IMDB_OK;
}

/* a tree holds a window function below its root */
static bool win_below(const sql_stmt *st, uint16_t k, bool root)
{
    if (!k) return false;
    const sql_expr *x = &st->ex[k];
    if (x->op == EX_WIN && !root) return true;
    return win_below(st, x->l, false) || win_below(st, x->r, false) || win_below(st, x->x3, false); /* height-bounded */
}

static int primary(parser *p, uint16_t *out, unsigned depth)
{
    if (depth > IMDB_MAX_EXPR_DEPTH) return too_deep(p);
    if (tok(p, TK_LP)) {
        if (tok_is_kw(p, p->i, "select")) return subq(p, 0, out); /* P2 S4: a scalar subquery */
        if (bexpr(p, out, depth + 1)) return p->e->code; /* (a + 1) and (a > 1 OR b < 2) alike */
        return expect(p, TK_RP, ")");
    }
    if (tok_is_kw(p, p->i, "exists") && p->t[p->i + 1].kind == TK_LP) { /* P2 S4 */
        p->i += 2;
        return subq(p, 1, out);
    }
    uint8_t agg = tok_is_kw(p, p->i, "count") ? AGG_COUNT : tok_is_kw(p, p->i, "sum") ? AGG_SUM
                : tok_is_kw(p, p->i, "min")   ? AGG_MIN   : tok_is_kw(p, p->i, "max") ? AGG_MAX
                : tok_is_kw(p, p->i, "avg")   ? AGG_AVG   : AGG_NONE;
    if (agg && p->t[p->i + 1].kind == TK_LP) { /* p->i is an identifier, not the end: p->i + 1 is a token */
        p->i += 2;
        uint16_t a = 0;
        bool dist = kw(p, "distinct"); /* P2 S2: agg(DISTINCT x), agg(ALL x) */
        if (!dist) kw(p, "all");
        if (agg == AGG_COUNT && tok(p, TK_STAR)) {
            if (dist) return imdb_fail(p->e, IMDB_ERR_SYNTAX, "COUNT(DISTINCT *) is not SQL: COUNT(DISTINCT x) counts x's values");
            agg = AGG_COUNT_STAR;
        } else if (bexpr(p, &a, depth + 1)) {
            return p->e->code;
        }
        uint16_t f = 0;
        if (expect(p, TK_RP, ")")) return p->e->code;
        if (tok_is_kw(p, p->i, "filter") && p->t[p->i + 1].kind == TK_LP) { /* FILTER (WHERE c): rows where c is TRUE */
            p->i += 2;
            if (expect_kw(p, "where") || bexpr(p, &f, depth + 1) || expect(p, TK_RP, ")")) return p->e->code;
        }
        if (tok_is_kw(p, p->i, "over")) { /* P2 S6: an aggregate over a window */
            if (dist || f) return imdb_fail(p->e, IMDB_ERR_UNSUPPORTED, "DISTINCT or FILTER with OVER: a later step");
            if (!p->win_ok)
                return imdb_fail(p->e, IMDB_ERR_INVALID, "a window function stands only as a SELECT item, alone (compute on "
                                                         "it from a derived table)");
            p->i++;
            uint8_t w;
            if (window_spec(p, &w, depth) || ex_new(p, EX_WIN, a, 0, out)) return p->e->code;
            p->st->ex[*out].fn = WF_AGG;
            p->st->ex[*out].agg = agg;
            p->st->ex[*out].sub = w;
            return IMDB_OK;
        }
        if (ex_new(p, EX_AGG, a, 0, out)) return p->e->code;
        p->st->ex[*out].agg = agg;
        p->st->ex[*out].dist = dist;
        p->st->ex[*out].x3 = f;
        sql_expr *x = &p->st->ex[*out];
        if (f && p->st->ex[f].h + 1u > x->h) x->h = (uint8_t)(p->st->ex[f].h + 1u); /* walkers follow x3 too */
        if (x->h > IMDB_MAX_EXPR_DEPTH) return too_deep(p);
        return IMDB_OK;
    }
    if (kw(p, "case")) return case_expr(p, out, depth); /* P2 S1 */
    if (kw(p, "cast")) return cast_expr(p, out, depth);
    /* F2a: the SQL standard's clock values, written without parentheses (a column of one of these names cannot be read) */
    static const struct {
        const char *name;
        uint8_t fn;
    } ck[] = {{"current_timestamp", FN_NOW}, {"localtimestamp", FN_LOCALTIMESTAMP}, {"current_date", FN_CURRENT_DATE},
              {"localtime", FN_LOCALTIME}};
    for (size_t i = 0; i < sizeof ck / sizeof *ck; i++)
        if (kw(p, ck[i].name)) {
            if (ex_new(p, EX_FN, 0, 0, out)) return p->e->code;
            p->st->ex[*out].fn = ck[i].fn;
            return IMDB_OK;
        }
    if (tok_is_kw(p, p->i, "current_time"))
        return imdb_fail(p->e, IMDB_ERR_INVALID, "CURRENT_TIME is a time with a zone, which imagedb has not: write LOCALTIME");
    if (p->t[p->i].kind == TK_IDENT && p->t[p->i + 1].kind == TK_LP) { /* an identifier is not the end: i + 1 exists */
        uint8_t wf = wf_named(p, p->i); /* P2 S6 */
        if (wf) return window_call(p, wf, out, depth);
        uint8_t fn = fn_named(p, p->i);
        if (fn) return fn_call(p, fn, out, depth);
    }
    const sql_tok *t = &p->t[p->i];
    if (t->kind == TK_IDENT && !tok_is_kw(p, p->i, "true") && !tok_is_kw(p, p->i, "false") && !tok_is_kw(p, p->i, "null") &&
        !ts_literal_at(p, p->i)) {
        char qual[IMDB_MAX_IDENT + 1], col[IMDB_MAX_IDENT + 1];
        if (qident(p, qual, col) || ex_new(p, EX_COL, 0, 0, out)) return p->e->code;
        memcpy(p->st->ex[*out].qual, qual, sizeof qual);
        memcpy(p->st->ex[*out].col, col, sizeof col);
        return IMDB_OK;
    }
    sql_lit l;
    if (literal(p, &l) || ex_new(p, EX_LIT, 0, 0, out)) return p->e->code;
    p->st->ex[*out].lit = l;
    return IMDB_OK;
}

static int unary(parser *p, uint16_t *out, unsigned depth)
{
    if (depth > IMDB_MAX_EXPR_DEPTH) return too_deep(p);
    uint8_t k = p->t[p->i].kind;
    if (k == TK_MINUS || k == TK_PLUS) {
        uint8_t nk = p->t[p->i + 1].kind; /* the sign is not the end: p->i + 1 is a token */
        if (nk == TK_INT || nk == TK_DEC || nk == TK_FLOAT) return primary(p, out, depth); /* the literal's sign */
        p->i++;
        uint16_t a;
        if (unary(p, &a, depth + 1)) return p->e->code;
        if (k == TK_PLUS) {
            *out = a;
            return IMDB_OK;
        }
        return ex_new(p, EX_NEG, a, 0, out);
    }
    return primary(p, out, depth);
}

/* P2: x AT TIME ZONE z where PostgreSQL ranks it: below a sign, above * and /, left to right (x AT TIME ZONE a AT TIME
 * ZONE b converts twice); the zone an operand of the level above; the node is timezone(z, x), its function form */
static int at_expr(parser *p, uint16_t *out, unsigned depth)
{
    if (unary(p, out, depth)) return p->e->code;
    while (tok_is_kw(p, p->i, "at") && tok_is_kw(p, p->i + 1, "time") && tok_is_kw(p, p->i + 2, "zone")) {
        p->i += 3;
        uint16_t el[2] = {0, *out}, args;
        if (unary(p, &el[0], depth + 1) || list_build(p, el, 2, &args) || ex_new(p, EX_FN, args, 0, out)) return p->e->code;
        p->st->ex[*out].fn = FN_TIMEZONE;
        p->st->ex[*out].nargs = 2;
    }
    return IMDB_OK;
}

static int term(parser *p, uint16_t *out, unsigned depth)
{
    if (at_expr(p, out, depth)) return p->e->code;
    for (;;) {
        uint8_t k = p->t[p->i].kind;
        uint8_t op = k == TK_STAR ? EX_MUL : k == TK_SLASH ? EX_DIV : k == TK_PERCENT ? EX_MOD : 0;
        if (!op) return IMDB_OK;
        p->i++;
        uint16_t r;
        if (at_expr(p, &r, depth) || ex_new(p, op, *out, r, out)) return p->e->code;
    }
}

static int aexpr(parser *p, uint16_t *out, unsigned depth)
{
    if (depth > IMDB_MAX_EXPR_DEPTH) return too_deep(p);
    if (term(p, out, depth)) return p->e->code;
    for (;;) {
        uint8_t k = p->t[p->i].kind;
        uint8_t op = k == TK_PLUS ? EX_ADD : k == TK_MINUS ? EX_SUB : 0;
        if (!op) return IMDB_OK;
        p->i++;
        uint16_t r;
        if (term(p, &r, depth) || ex_new(p, op, *out, r, out)) return p->e->code;
    }
}

/* P2 S1: a || b || ...: below + and -, above the comparisons (as PostgreSQL ranks it), each a two-argument CONCAT */
static int cexpr(parser *p, uint16_t *out, unsigned depth)
{
    if (aexpr(p, out, depth)) return p->e->code;
    while (tok(p, TK_CONCAT)) {
        uint16_t el[2] = {*out, 0}, args;
        if (aexpr(p, &el[1], depth) || list_build(p, el, 2, &args) || ex_new(p, EX_FN, args, 0, out)) return p->e->code;
        p->st->ex[*out].fn = FN_CONCAT;
        p->st->ex[*out].nargs = 2;
    }
    return IMDB_OK;
}

/* bcmp: one comparison, or the operand alone (a BOOL, or no condition: the binder's to say) */
static int b_cmp(parser *p, uint16_t *out, unsigned depth)
{
    if (cexpr(p, out, depth)) return p->e->code;
    uint8_t op = 0;
    uint16_t r = 0, x3 = 0;
    /* P2 S1: a NOT before IN, LIKE or BETWEEN is theirs (x NOT IN (...)); one before anything else is b_not's */
    bool neg = tok_is_kw(p, p->i, "not") && (tok_is_kw(p, p->i + 1, "in") || tok_is_kw(p, p->i + 1, "like") ||
                                             tok_is_kw(p, p->i + 1, "between"));
    if (neg) p->i++;
    if (kw(p, "in")) { /* P2 S1: a list of values; a subquery is S4's */
        uint32_t n;
        if (expect(p, TK_LP, "(")) return p->e->code;
        if (tok_is_kw(p, p->i, "select")) { /* P2 S4: IN (SELECT ...) */
            if (subq(p, 2, &r)) return p->e->code;
        } else if (expr_list(p, depth, &r, &n)) {
            return p->e->code;
        }
        op = neg ? CMP_NOTIN : CMP_IN;
    } else if (kw(p, "like")) { /* P2 S1 */
        op = neg ? CMP_NOTLIKE : CMP_LIKE;
        if (cexpr(p, &r, depth) || (kw(p, "escape") && cexpr(p, &x3, depth))) return p->e->code;
    } else if (kw(p, "is")) {
        op = kw(p, "not") ? CMP_NOTNULL : CMP_ISNULL;
        if (expect_kw(p, "null")) return p->e->code;
    } else if (kw(p, "between")) { /* its AND is its own, not a conjunction's */
        op = CMP_BETWEEN;
        if (cexpr(p, &r, depth) || expect_kw(p, "and") || cexpr(p, &x3, depth)) return p->e->code;
    } else {
        switch (p->t[p->i].kind) {
        case TK_EQ: op = CMP_EQ; break;
        case TK_NE: op = CMP_NE; break;
        case TK_LT: op = CMP_LT; break;
        case TK_LE: op = CMP_LE; break;
        case TK_GT: op = CMP_GT; break;
        case TK_GE: op = CMP_GE; break;
        default: return IMDB_OK;
        }
        p->i++;
        if (cexpr(p, &r, depth)) return p->e->code;
    }
    uint16_t k;
    if (ex_new(p, EX_CMP, *out, r, &k)) return p->e->code;
    sql_expr *x = &p->st->ex[k];
    x->cmp = op;
    if (x3) {
        x->x3 = x3;
        if (p->st->ex[x3].h + 1u > x->h) x->h = (uint8_t)(p->st->ex[x3].h + 1u);
        if (x->h > IMDB_MAX_EXPR_DEPTH) return too_deep(p);
    }
    if (neg && op == CMP_BETWEEN) return ex_new(p, EX_NOT, k, 0, out); /* P2 S1: NOT BETWEEN, as NOT (BETWEEN) */
    *out = k;
    return IMDB_OK;
}

static int b_not(parser *p, uint16_t *out, unsigned depth)
{
    if (depth > IMDB_MAX_EXPR_DEPTH) return too_deep(p);
    if (kw(p, "not")) {
        uint16_t a;
        if (b_not(p, &a, depth + 1)) return p->e->code;
        return ex_new(p, EX_NOT, a, 0, out);
    }
    return b_cmp(p, out, depth);
}

static int b_and(parser *p, uint16_t *out, unsigned depth)
{
    if (b_not(p, out, depth)) return p->e->code;
    while (kw(p, "and")) {
        uint16_t r;
        if (b_not(p, &r, depth) || ex_new(p, EX_AND, *out, r, out)) return p->e->code;
    }
    return IMDB_OK;
}

static int bexpr(parser *p, uint16_t *out, unsigned depth)
{
    if (depth > IMDB_MAX_EXPR_DEPTH) return too_deep(p);
    if (b_and(p, out, depth)) return p->e->code;
    while (kw(p, "or")) {
        uint16_t r;
        if (b_and(p, &r, depth) || ex_new(p, EX_OR, *out, r, out)) return p->e->code;
    }
    return IMDB_OK;
}

/* a value where a literal stood (SET, VALUES): a literal alone takes no node (a 100,000-row VALUES of literals takes
 * none), anything else is the tree */
static int value(parser *p, sql_lit *l)
{
    const sql_tok *t = &p->t[p->i];
    uint8_t k0 = t->kind, k1 = k0 == TK_EOF ? TK_EOF : p->t[p->i + 1].kind;
    bool lit = k0 == TK_INT || k0 == TK_DEC || k0 == TK_FLOAT || k0 == TK_STR || k0 == TK_PARAM ||
               ((k0 == TK_MINUS || k0 == TK_PLUS) && (k1 == TK_INT || k1 == TK_DEC || k1 == TK_FLOAT)) ||
               tok_is_kw(p, p->i, "true") || tok_is_kw(p, p->i, "false") || tok_is_kw(p, p->i, "null") ||
               ts_literal_at(p, p->i);
    uint32_t at = p->i;
    if (lit) {
        if (literal(p, l)) return p->e->code;
        uint8_t nk = p->t[p->i].kind; /* the value ends here: a comma, a parenthesis, the end, or SET's WHERE */
        if (nk == TK_COMMA || nk == TK_RP || nk == TK_SEMI || nk == TK_EOF || tok_is_kw(p, p->i, "where")) return IMDB_OK;
        p->i = at; /* the literal begins an expression */
    }
    uint16_t k;
    if (bexpr(p, &k, 0)) return p->e->code;
    if (p->st->ex[k].op == EX_LIT) {
        *l = p->st->ex[k].lit;
        return IMDB_OK;
    }
    memset(l, 0, sizeof *l);
    l->kind = LIT_EXPR;
    l->ex = k;
    return IMDB_OK;
}

bool imdb_sql_has_agg(const sql_stmt *st, uint16_t k)
{
    if (!k) return false;
    const sql_expr *x = &st->ex[k];
    return x->op == EX_AGG || imdb_sql_has_agg(st, x->l) || imdb_sql_has_agg(st, x->r) ||
           imdb_sql_has_agg(st, x->x3); /* height-bounded */
}

static uint8_t mirror(uint8_t op)
{
    return op == CMP_LT ? CMP_GT : op == CMP_LE ? CMP_GE : op == CMP_GT ? CMP_LT : op == CMP_GE ? CMP_LE : op;
}

/* one conjunct of WHERE's tree, its top-level ANDs split left to right: today's col op literal where it is one (a
 * constant op a column flipped into it: an index serves it), keeping its comparison node (nl) for falls_back; any
 * other (an OR, a NOT, a comparison of trees, a BOOL) a residual tree (lx) */
static int conjunct(parser *p, sql_stmt *st, uint16_t k)
{
    const sql_expr *x = &st->ex[k];
    if (x->op == EX_AND) /* the height bounds the recursion */
        return conjunct(p, st, x->l) ? p->e->code : conjunct(p, st, x->r);
    if (st->nwhere >= IMDB_MAX_PREDICATES)
        return imdb_fail(p->e, IMDB_ERR_LIMIT, "WHERE has more than %u conditions", IMDB_MAX_PREDICATES);
    sql_cmp *c = &st->where[st->nwhere++];
    memset(c, 0, sizeof *c);
    if (x->op == EX_CMP && x->cmp <= CMP_NOTNULL) { /* P2 S1: IN and LIKE are residuals: no index serves them yet */
        const sql_expr *L = &st->ex[x->l], *R = x->r ? &st->ex[x->r] : NULL, *X3 = x->x3 ? &st->ex[x->x3] : NULL;
        if (L->op == EX_COL && (!R || R->op == EX_LIT) && (!X3 || X3->op == EX_LIT)) { /* today's form */
            c->nl = k;
            c->op = x->cmp;
            memcpy(c->qual, L->qual, sizeof c->qual);
            memcpy(c->col, L->col, sizeof c->col);
            if (R) c->a = R->lit;
            if (X3) c->b = X3->lit;
            return IMDB_OK;
        }
        if (L->op == EX_LIT && R && R->op == EX_COL && x->cmp != CMP_BETWEEN) { /* 5 < a: a > 5 */
            c->nl = k;
            c->op = mirror(x->cmp);
            memcpy(c->qual, R->qual, sizeof c->qual);
            memcpy(c->col, R->col, sizeof c->col);
            c->a = L->lit;
            return IMDB_OK;
        }
    }
    c->lx = k;
    return IMDB_OK;
}

static int preds(parser *p, sql_stmt *st)
{
    uint16_t k;
    if (bexpr(p, &k, 0)) return p->e->code;
    return conjunct(p, st, k);
}

static int col_type(parser *p, imdb_column *c, char *tname)
{
    if (kw(p, "int64") || kw(p, "bigint") || kw(p, "int8")) c->type = IMDB_T_INT64;
    else if (kw(p, "integer") || kw(p, "int") || kw(p, "int4")) c->type = IMDB_T_INT64, c->precision = 32; /* F3a */
    else if (kw(p, "smallint") || kw(p, "int2")) c->type = IMDB_T_INT64, c->precision = 16;
    else if (kw(p, "text")) c->type = IMDB_T_TEXT;
    else if (tok_is_kw(p, p->i, "varchar") || (tok_is_kw(p, p->i, "character") && tok_is_kw(p, p->i + 1, "varying"))) {
        p->i += tok_is_kw(p, p->i, "varchar") ? 1 : 2; /* F3c: VARCHAR(n), CHARACTER VARYING(n); without (n) a TEXT */
        c->type = IMDB_T_TEXT;
        if (tok(p, TK_LP)) {
            uint64_t n;
            if (uint_lit(p, &n) || expect(p, TK_RP, ")")) return p->e->code;
            if (n < 1 || n > IMDB_MAX_TEXT) return imdb_fail(p->e, IMDB_ERR_INVALID, "VARCHAR(n) needs 1 <= n <= %u", IMDB_MAX_TEXT);
            imdb_text_set_max(c, (uint32_t)n);
        }
    }
    else if (kw(p, "bool") || kw(p, "boolean")) c->type = IMDB_T_BOOL;
    else if (kw(p, "timestamptz")) c->type = IMDB_T_TIMESTAMPTZ; /* P2 */
    else if (kw(p, "date")) c->type = IMDB_T_DATE; /* F3b */
    else if (kw(p, "uuid")) c->type = IMDB_T_UUID; /* F3d */
    else if (kw(p, "bytea")) c->type = IMDB_T_BYTEA;
    else if (kw(p, "interval")) { /* F3f: its fields and precision (INTERVAL YEAR TO MONTH, INTERVAL(p)): not yet */
        c->type = IMDB_T_INTERVAL;
        if (iv_field_word(p, p->i) || p->t[p->i].kind == TK_LP)
            return imdb_fail(p->e, IMDB_ERR_UNSUPPORTED, "INTERVAL's fields and precision (INTERVAL YEAR TO MONTH, "
                                                         "INTERVAL(p)) are not in imagedb yet");
    }
    else if (tok_is_kw(p, p->i, "time")) { /* F3b: TIME [WITHOUT TIME ZONE]; WITH TIME ZONE is refused (no zone in a time of day) */
        p->i++;
        c->type = IMDB_T_TIME;
        if ((tok_is_kw(p, p->i, "with") || tok_is_kw(p, p->i, "without")) && tok_is_kw(p, p->i + 1, "time") &&
            tok_is_kw(p, p->i + 2, "zone")) {
            if (tok_is_kw(p, p->i, "with"))
                return imdb_fail(p->e, IMDB_ERR_INVALID, "TIME WITH TIME ZONE is not supported (a time of day has no zone: TIMESTAMPTZ)");
            p->i += 3;
        }
    }
    else if (kw(p, "timestamp")) {
        c->type = IMDB_T_TIMESTAMP;
        if ((tok_is_kw(p, p->i, "with") || tok_is_kw(p, p->i, "without")) && tok_is_kw(p, p->i + 1, "time") &&
            tok_is_kw(p, p->i + 2, "zone")) {
            if (tok_is_kw(p, p->i, "with")) c->type = IMDB_T_TIMESTAMPTZ;
            p->i += 3;
        }
    }
    else if (kw(p, "decimal") || kw(p, "numeric")) {
        c->type = IMDB_T_DECIMAL;
        uint64_t prec, scale = 0;
        if (expect(p, TK_LP, "(") || uint_lit(p, &prec)) return p->e->code;
        if (tok(p, TK_COMMA) && uint_lit(p, &scale)) return p->e->code;
        if (expect(p, TK_RP, ")")) return p->e->code;
        if (prec < 1 || prec > IMDB_DEC_MAX_DIGITS || scale > prec) /* F3e: to 38 digits */
            return imdb_fail(p->e, IMDB_ERR_INVALID, "DECIMAL(p,s) needs 1 <= p <= 38 and 0 <= s <= p");
        c->precision = (uint8_t)prec;
        c->scale = (uint8_t)scale;
    } else if (kw(p, "float64") || kw(p, "float8") || kw(p, "float")) {
        c->type = IMDB_T_FLOAT64;
    } else if (kw(p, "double")) {
        kw(p, "precision");
        c->type = IMDB_T_FLOAT64;
    } else if (kw(p, "real") || kw(p, "float4")) {
        return imdb_fail(p->e, IMDB_ERR_UNSUPPORTED, "REAL is single precision; imagedb has FLOAT64 (DOUBLE PRECISION)");
    } else if (tname && p->t[p->i].kind == TK_IDENT && !is_reserved(p, p->i)) { /* F3g: an ENUM type by its name */
        if (ident(p, tname)) return p->e->code;
        c->type = IMDB_T_ENUM; /* its id the statement's at its read point (the executor's) */
    } else {
        return fail_at(p, "a type (INT64, DECIMAL(p,s), FLOAT64, TEXT, BOOL, TIMESTAMP, TIMESTAMPTZ)");
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

/* F2a: a DEFAULT's value: a literal, or a clock read at each write (now() or CURRENT_TIMESTAMP, LOCALTIMESTAMP,
 * CURRENT_DATE, LOCALTIME: *clock its kind); CURRENT_TIME refused as in an expression */
static int default_value(parser *p, sql_lit *l, uint8_t *clock)
{
    *clock = 0;
    memset(l, 0, sizeof *l);
    if (tok_is_kw(p, p->i, "now") && p->t[p->i + 1].kind == TK_LP) {
        p->i++;
        if (expect(p, TK_LP, "(") || expect(p, TK_RP, ")")) return p->e->code;
        *clock = IMDB_DEFK_CURRENT_TIMESTAMP;
        return IMDB_OK;
    }
    if (tok_is_kw(p, p->i, "gen_random_uuid") && p->t[p->i + 1].kind == TK_LP) { /* F3d: drawn at each write */
        p->i++;
        if (expect(p, TK_LP, "(") || expect(p, TK_RP, ")")) return p->e->code;
        *clock = IMDB_DEFK_RANDOM_UUID;
        return IMDB_OK;
    }
    if (tok_is_kw(p, p->i, "nextval") && p->t[p->i + 1].kind == TK_LP) { /* F2a-2: DEFAULT nextval('s'), the name a string */
        p->i += 2;
        if (literal(p, l) || expect(p, TK_RP, ")")) return p->e->code;
        if (l->kind != LIT_STR) return imdb_fail(p->e, IMDB_ERR_INVALID, "nextval takes a sequence's name as a string");
        *clock = IMDB_DEFK_NEXTVAL;
        return IMDB_OK;
    }
    if (tok_is_kw(p, p->i, "current_time"))
        return imdb_fail(p->e, IMDB_ERR_UNSUPPORTED, "CURRENT_TIME is a time with a zone, which imagedb has not: write LOCALTIME");
    if (kw(p, "current_timestamp")) *clock = IMDB_DEFK_CURRENT_TIMESTAMP;
    else if (kw(p, "localtimestamp")) *clock = IMDB_DEFK_LOCALTIMESTAMP;
    else if (kw(p, "current_date")) *clock = IMDB_DEFK_CURRENT_DATE;
    else if (kw(p, "localtime")) *clock = IMDB_DEFK_LOCALTIME;
    if (*clock) {
        if (p->t[p->i].kind == TK_LP) /* PostgreSQL's precision: imagedb keeps microseconds */
            return imdb_fail(p->e, IMDB_ERR_UNSUPPORTED, "a clock value's precision: imagedb keeps microseconds");
        return IMDB_OK;
    }
    return literal(p, l);
}

/* ALTER TABLE t, read: SET RETENTION ...; F1: ADD [COLUMN] c type [NULL | NOT NULL] [DEFAULT literal] (either order),
 * RENAME [COLUMN] a TO b, RENAME TO n */
/* F2c: (text) at p's token: the text's span as written, from its first token to the end of its last (balanced
 * parentheses, no ';' or parameter), at most IMDB_MAX_CHECK_TEXT bytes; the parentheses read */
static int paren_span(parser *p, uint32_t *off, uint32_t *len, const char *what)
{
    if (expect(p, TK_LP, "(")) return p->e->code;
    uint32_t t0 = p->i;
    int depth = 0;
    for (;; p->i++) {
        uint8_t k = p->t[p->i].kind;
        if (k == TK_EOF || k == TK_SEMI) return fail_at(p, "the closing )");
        if (k == TK_PARAM) return imdb_fail(p->e, IMDB_ERR_INVALID, "%s takes no parameter ($n)", what);
        if (k == TK_LP) depth++;
        if (k == TK_RP && !depth--) break;
    }
    if (p->i == t0) return imdb_fail(p->e, IMDB_ERR_SYNTAX, "%s is empty", what);
    const sql_tok *a = &p->t[t0], *z = &p->t[p->i - 1];
    *off = a->off - (a->kind == TK_STR);
    *len = z->off + z->len + (z->kind == TK_STR) - *off;
    if (*len > IMDB_MAX_CHECK_TEXT) return imdb_fail(p->e, IMDB_ERR_LIMIT, "%s of more than %u bytes", what, IMDB_MAX_CHECK_TEXT);
    p->i++; /* its ) */
    return IMDB_OK;
}

/* F2b-1: CHECK (condition), CHECK already read: the condition's text kept as written, from its first token to the end
 * of its last (balanced parentheses; the engine binds it on its own, as replay and the auditor do: design.md §5, CHECK
 * constraints); name: CONSTRAINT's, or "" for the engine to choose */
static int parse_check(parser *p, sql_stmt *st, const char *name)
{
    if (st->nchecks >= IMDB_MAX_CHECKS)
        return imdb_fail(p->e, IMDB_ERR_LIMIT, "a table has at most %u CHECK constraints", IMDB_MAX_CHECKS);
    if (expect(p, TK_LP, "(")) return p->e->code;
    uint32_t t0 = p->i;
    int depth = 0;
    for (;; p->i++) {
        uint8_t k = p->t[p->i].kind;
        if (k == TK_EOF || k == TK_SEMI) return fail_at(p, "the CHECK's closing )");
        if (k == TK_PARAM) return imdb_fail(p->e, IMDB_ERR_INVALID, "a CHECK takes no parameter ($n)");
        if (k == TK_LP) depth++;
        if (k == TK_RP && !depth--) break;
    }
    if (p->i == t0) return imdb_fail(p->e, IMDB_ERR_SYNTAX, "CHECK () holds no condition");
    const sql_tok *a = &p->t[t0], *z = &p->t[p->i - 1];
    uint32_t off = a->off - (a->kind == TK_STR), len = z->off + z->len + (z->kind == TK_STR) - off;
    if (len > IMDB_MAX_CHECK_TEXT) return imdb_fail(p->e, IMDB_ERR_LIMIT, "a CHECK's text of more than %u bytes", IMDB_MAX_CHECK_TEXT);
    p->i++; /* its ) */
    if (tok_is_kw(p, p->i, "no") || (tok_is_kw(p, p->i, "not") && tok_is_kw(p, p->i + 1, "valid")))
        return imdb_fail(p->e, IMDB_ERR_UNSUPPORTED, "a CHECK holds for every row: NOT VALID and NO INHERIT are not in imagedb");
    snprintf(st->checks[st->nchecks].name, sizeof st->checks[st->nchecks].name, "%s", name);
    st->checks[st->nchecks].off = off;
    st->checks[st->nchecks].len = len;
    st->nchecks++;
    return IMDB_OK;
}

/* F2b-2: ON DELETE / ON UPDATE's action at p's token (ON and the event read): IMDB_FK_* */
static int fk_action(parser *p, uint8_t *out)
{
    if (kw(p, "cascade")) *out = IMDB_FK_CASCADE;
    else if (kw(p, "restrict")) *out = IMDB_FK_RESTRICT;
    else if (kw(p, "no")) {
        if (expect_kw(p, "action")) return p->e->code;
        *out = IMDB_FK_NO_ACTION;
    } else if (kw(p, "set")) {
        if (kw(p, "null")) *out = IMDB_FK_SET_NULL;
        else if (kw(p, "default")) *out = IMDB_FK_SET_DEFAULT;
        else return fail_at(p, "NULL or DEFAULT");
    } else {
        return fail_at(p, "CASCADE, RESTRICT, NO ACTION, SET NULL or SET DEFAULT");
    }
    return IMDB_OK;
}

/* F2b-2: REFERENCES parent [(cols)] [ON DELETE action] [ON UPDATE action] [MATCH SIMPLE] [NOT DEFERRABLE], REFERENCES
 * already read, for the FK st->fks[st->nfks] whose name and columns the caller set; then it counts */
static int parse_references(parser *p, sql_stmt *st)
{
    sql_fkdef *f = &st->fks[st->nfks];
    if (ident(p, f->parent)) return p->e->code;
    if (tok(p, TK_LP)) {
        do {
            if (f->npcols >= IMDB_MAX_KEY_COLS)
                return imdb_fail(p->e, IMDB_ERR_LIMIT, "a FOREIGN KEY of more than %u columns", IMDB_MAX_KEY_COLS);
            if (ident(p, f->pcols[f->npcols++])) return p->e->code;
        } while (tok(p, TK_COMMA));
        if (expect(p, TK_RP, ")")) return p->e->code;
    }
    bool del = false, upd = false;
    for (;;) {
        if (tok_is_kw(p, p->i, "on") && (tok_is_kw(p, p->i + 1, "delete") || tok_is_kw(p, p->i + 1, "update"))) {
            p->i++;
            bool d = kw(p, "delete");
            if (!d) p->i++; /* UPDATE */
            if (d ? del : upd) return imdb_fail(p->e, IMDB_ERR_SYNTAX, "ON %s given twice", d ? "DELETE" : "UPDATE");
            if (fk_action(p, d ? &f->on_delete : &f->on_update)) return p->e->code;
            if (d) del = true;
            else upd = true;
        } else if (kw(p, "match")) {
            if (!kw(p, "simple"))
                return imdb_fail(p->e, IMDB_ERR_UNSUPPORTED, "MATCH FULL and MATCH PARTIAL are a later step: MATCH SIMPLE (the "
                                                            "default) checks a key with no NULL in it");
        } else if (tok_is_kw(p, p->i, "not") && tok_is_kw(p, p->i + 1, "deferrable")) {
            p->i += 2;
        } else if (tok_is_kw(p, p->i, "deferrable") || tok_is_kw(p, p->i, "initially")) {
            return imdb_fail(p->e, IMDB_ERR_UNSUPPORTED, "a deferrable FOREIGN KEY is a later step: it is checked at each "
                                                        "statement's end");
        } else {
            break;
        }
    }
    if (f->on_update != IMDB_FK_NO_ACTION && f->on_update != IMDB_FK_RESTRICT)
        return imdb_fail(p->e, IMDB_ERR_UNSUPPORTED, "ON UPDATE takes NO ACTION or RESTRICT: a key is never updated in imagedb, "
                                                    "so no other action could fire");
    st->nfks++;
    return IMDB_OK;
}

/* F2b-2: a table's FOREIGN KEY (cols) REFERENCES ..., FOREIGN read, named name ("" for one to choose) */
static int parse_fk_table(parser *p, sql_stmt *st, const char *name)
{
    if (st->nfks >= IMDB_MAX_FKS) return imdb_fail(p->e, IMDB_ERR_LIMIT, "a table has at most %u FOREIGN KEY constraints", IMDB_MAX_FKS);
    if (!st->fks && !(st->fks = imdb_alloc_array(IMDB_MAX_FKS, sizeof *st->fks, p->e))) return p->e->code;
    if (expect_kw(p, "key") || expect(p, TK_LP, "(")) return p->e->code;
    sql_fkdef *f = &st->fks[st->nfks];
    memset(f, 0, sizeof *f);
    snprintf(f->name, sizeof f->name, "%s", name);
    do {
        if (f->ncols >= IMDB_MAX_KEY_COLS)
            return imdb_fail(p->e, IMDB_ERR_LIMIT, "a FOREIGN KEY of more than %u columns", IMDB_MAX_KEY_COLS);
        if (ident(p, f->cols[f->ncols++])) return p->e->code;
    } while (tok(p, TK_COMMA));
    if (expect(p, TK_RP, ")") || expect_kw(p, "references")) return p->e->code;
    return parse_references(p, st);
}

/* F2b-2: a column's [CONSTRAINT name] REFERENCES ..., at p's token: 1 (one added), 0 (not one: nothing read), or the
 * error; col the column's name */
static int maybe_column_fk(parser *p, sql_stmt *st, const char *col)
{
    char name[IMDB_MAX_IDENT + 1] = "";
    uint32_t at = p->i;
    if (tok_is_kw(p, p->i, "constraint") && tok_is_kw(p, p->i + 2, "references")) {
        p->i++;
        if (ident(p, name)) return p->e->code;
    }
    if (!kw(p, "references")) {
        p->i = at;
        return 0;
    }
    if (st->nfks >= IMDB_MAX_FKS) return imdb_fail(p->e, IMDB_ERR_LIMIT, "a table has at most %u FOREIGN KEY constraints", IMDB_MAX_FKS);
    if (!st->fks && !(st->fks = imdb_alloc_array(IMDB_MAX_FKS, sizeof *st->fks, p->e))) return p->e->code;
    sql_fkdef *f = &st->fks[st->nfks];
    memset(f, 0, sizeof *f);
    snprintf(f->name, sizeof f->name, "%s", name);
    snprintf(f->cols[0], sizeof f->cols[0], "%s", col);
    f->ncols = 1;
    return parse_references(p, st) ? p->e->code : 1;
}

/* F2b-1: [CONSTRAINT name] CHECK at p's token, read: 1 (a CHECK added), 0 (neither word: nothing read), or the error */
static int maybe_check(parser *p, sql_stmt *st)
{
    char name[IMDB_MAX_IDENT + 1] = "";
    if (tok_is_kw(p, p->i, "constraint")) {
        p->i++;
        if (ident(p, name)) return p->e->code;
        if (kw(p, "foreign")) return parse_fk_table(p, st, name) ? p->e->code : 1; /* F2b-2 */
        if (!tok_is_kw(p, p->i, "check")) return fail_at(p, "CHECK or FOREIGN KEY (a CONSTRAINT names one: PRIMARY KEY takes no name)");
    } else if (tok_is_kw(p, p->i, "foreign") && tok_is_kw(p, p->i + 1, "key")) { /* F2b-2: a table's FOREIGN KEY */
        p->i++;
        return parse_fk_table(p, st, name) ? p->e->code : 1;
    } else if (!tok_is_kw(p, p->i, "check") || p->t[p->i + 1].kind != TK_LP) {
        return 0;
    }
    p->i++;
    return parse_check(p, st, name) ? p->e->code : 1;
}

static int parse_alter(parser *p, sql_stmt *st)
{
    if (kw(p, "set")) {
        st->kind = ST_ALTER_RETENTION;
        st->has_retention = true;
        if (expect_kw(p, "retention")) return p->e->code;
        return parse_retention(p, &st->retention_us);
    }
    st->kind = ST_ALTER_TABLE;
    if (kw(p, "add")) {
        int ck = maybe_check(p, st); /* F2b-1: ADD [CONSTRAINT name] CHECK (condition); F2b-2: or FOREIGN KEY */
        if (ck < 0) return ck;
        if (ck) {
            st->alter_kind = st->nfks ? IMDB_ALTER_ADD_FK : IMDB_ALTER_ADD_CHECK;
            return IMDB_OK;
        }
        kw(p, "column");
        st->alter_kind = IMDB_ALTER_ADD_COLUMN;
        imdb_column *c = &st->schema.cols[0];
        memset(c, 0, sizeof *c);
        char tn[IMDB_MAX_IDENT + 1] = "";
        if (ident(p, c->name) || col_type(p, c, tn) || (c->type == IMDB_T_ENUM && col_tname(p, 0, tn))) return p->e->code;
        int null_spec = 0; /* 1 NULL, 2 NOT NULL */
        for (;;) {
            if (kw(p, "not")) {
                if (expect_kw(p, "null")) return p->e->code;
                if (null_spec) return imdb_fail(p->e, IMDB_ERR_INVALID, "column %s: NULL or NOT NULL, once", c->name);
                null_spec = 2;
            } else if (kw(p, "null")) {
                if (null_spec) return imdb_fail(p->e, IMDB_ERR_INVALID, "column %s: NULL or NOT NULL, once", c->name);
                null_spec = 1;
            } else if (kw(p, "default")) {
                if (st->has_alter_def) return imdb_fail(p->e, IMDB_ERR_INVALID, "column %s: one DEFAULT", c->name);
                if (default_value(p, &st->alter_def, &st->alter_clock)) return p->e->code;
                st->has_alter_def = true;
            } else if (kw(p, "primary") || kw(p, "subject")) {
                return imdb_fail(p->e, IMDB_ERR_INVALID, "an added column is neither a key nor a SUBJECT");
            } else if (kw(p, "generated")) { /* F2c */
                return imdb_fail(p->e, IMDB_ERR_UNSUPPORTED, "ADD COLUMN ... GENERATED would compute a value for every row "
                                                            "there: a later step (CREATE the table with it)");
            } else {
                break;
            }
        }
        if (null_spec != 2) c->flags |= IMDB_COL_NULLABLE;
        return IMDB_OK;
    }
    if (kw(p, "drop")) { /* F1 stage 4: DROP [COLUMN] c (RESTRICT, the default and only one) */
        if (tok_is_kw(p, p->i, "constraint") && p->t[p->i + 1].kind == TK_IDENT) { /* F2b-1: DROP CONSTRAINT name */
            p->i++;
            st->alter_kind = IMDB_ALTER_DROP_CHECK;
            if (ident(p, st->alter_old)) return p->e->code;
            if (kw(p, "cascade")) return imdb_fail(p->e, IMDB_ERR_UNSUPPORTED, "DROP CONSTRAINT ... CASCADE: nothing depends on a CHECK");
            kw(p, "restrict");
            return IMDB_OK;
        }
        kw(p, "column");
        st->alter_kind = IMDB_ALTER_DROP_COLUMN;
        if (ident(p, st->alter_old)) return p->e->code;
        if (kw(p, "cascade")) return imdb_fail(p->e, IMDB_ERR_UNSUPPORTED, "DROP COLUMN ... CASCADE: drop the index or view first");
        kw(p, "restrict");
        return IMDB_OK;
    }
    if (kw(p, "alter")) { /* F1 stage 4: ALTER [COLUMN] c SET NOT NULL | DROP NOT NULL | SET DEFAULT v | DROP DEFAULT |
                             [SET DATA] TYPE t */
        kw(p, "column");
        if (ident(p, st->alter_old)) return p->e->code;
        bool set = kw(p, "set");
        if (!set && kw(p, "drop")) {
            if (kw(p, "default")) {
                st->alter_kind = IMDB_ALTER_DROP_DEFAULT;
                return IMDB_OK;
            }
            if (expect_kw(p, "not") || expect_kw(p, "null")) return p->e->code;
            st->alter_kind = IMDB_ALTER_DROP_NOT_NULL;
            return IMDB_OK;
        }
        if (set && kw(p, "not")) {
            if (expect_kw(p, "null")) return p->e->code;
            st->alter_kind = IMDB_ALTER_SET_NOT_NULL;
            return IMDB_OK;
        }
        if (set && kw(p, "default")) {
            st->alter_kind = IMDB_ALTER_SET_DEFAULT;
            if (default_value(p, &st->alter_def, &st->alter_clock)) return p->e->code;
            if (!st->alter_clock && st->alter_def.kind == LIT_NULL) /* one state, one spelling: no DEFAULT is DROP DEFAULT */
                return imdb_fail(p->e, IMDB_ERR_INVALID, "SET DEFAULT NULL: write DROP DEFAULT");
            st->has_alter_def = true;
            return IMDB_OK;
        }
        if (set) kw(p, "data");
        if (!kw(p, "type")) return fail_at(p, "SET NOT NULL, DROP NOT NULL, SET DEFAULT, DROP DEFAULT or TYPE");
        st->alter_kind = IMDB_ALTER_SET_TYPE;
        imdb_column *c = &st->schema.cols[0];
        memset(c, 0, sizeof *c);
        char tn[IMDB_MAX_IDENT + 1] = "";
        if (col_type(p, c, tn)) return p->e->code;
        if (c->type == IMDB_T_ENUM) /* F3g: deferred.md D27 */
            return imdb_fail(p->e, IMDB_ERR_UNSUPPORTED, "SET TYPE to an ENUM type is not in imagedb yet");
        return IMDB_OK;
    }
    if (!kw(p, "rename")) return fail_at(p, "SET RETENTION, ADD, DROP, ALTER or RENAME");
    if (kw(p, "to")) {
        st->alter_kind = IMDB_ALTER_RENAME_TABLE;
        return ident(p, st->alter_new);
    }
    kw(p, "column");
    st->alter_kind = IMDB_ALTER_RENAME_COLUMN;
    if (ident(p, st->alter_old) || expect_kw(p, "to")) return p->e->code;
    return ident(p, st->alter_new);
}

static int parse_create(parser *p, sql_stmt *st)
{
    st->kind = ST_CREATE;
    imdb_schema *s = &st->schema;
    memset(s, 0, sizeof *s);
    s->subject = -1;
    if (expect_kw(p, "table") || ident(p, st->table) || expect(p, TK_LP, "(")) return p->e->code;
    strcpy(s->name, st->table);
    int pk = -1;                                       /* a column's own PRIMARY KEY */
    char kname[IMDB_MAX_KEY_COLS][IMDB_MAX_IDENT + 1]; /* F4: PRIMARY KEY (a, b, ...), resolved once every column is read */
    int nkname = -1;
    bool said_null[IMDB_MAX_COLS] = {false};
    do {
        int cki = maybe_check(p, st); /* F2b-1: a table's [CONSTRAINT name] CHECK (condition), anywhere among the columns */
        if (cki < 0) return cki;
        if (cki) continue;
        if (kw(p, "primary")) { /* the table's constraint, anywhere among the columns (PRIMARY is reserved) */
            if (expect_kw(p, "key") || expect(p, TK_LP, "(")) return p->e->code;
            if (pk >= 0 || nkname >= 0) return imdb_fail(p->e, IMDB_ERR_INVALID, "a table has one PRIMARY KEY");
            nkname = 0;
            do {
                if (nkname >= (int)IMDB_MAX_KEY_COLS)
                    return imdb_fail(p->e, IMDB_ERR_LIMIT, "a PRIMARY KEY takes at most %u columns", IMDB_MAX_KEY_COLS);
                if (ident(p, kname[nkname++])) return p->e->code;
            } while (tok(p, TK_COMMA));
            if (expect(p, TK_RP, ")")) return p->e->code;
            continue; /* to the list's comma */
        }
        if (s->ncols >= IMDB_MAX_COLS) return imdb_fail(p->e, IMDB_ERR_LIMIT, "more than %u columns", IMDB_MAX_COLS);
        imdb_column *c = &s->cols[s->ncols];
        if (ident(p, c->name)) return p->e->code;
        int serial = kw(p, "serial") ? 32 : kw(p, "bigserial") ? 64 : kw(p, "smallserial") ? 16 : 0; /* F2a-2 */
        if (serial) {
            c->type = IMDB_T_INT64;
            c->precision = (uint8_t)(serial == 64 ? 0 : serial);
            st->cdef_kind[s->ncols] = IMDB_DEFK_IDENTITY; /* PostgreSQL's SERIAL: a sequence of its own, a value given taken */
            memset(&st->idopt[s->ncols], 0, sizeof st->idopt[s->ncols]);
        } else {
            char tn[IMDB_MAX_IDENT + 1] = "";
            if (col_type(p, c, tn) || (c->type == IMDB_T_ENUM && col_tname(p, s->ncols, tn))) return p->e->code;
        }
        int null_spec = 0; /* 1 NULL, 2 NOT NULL */
        for (;;) {
            if (kw(p, "primary")) {
                if (expect_kw(p, "key")) return p->e->code;
                if (c->flags & IMDB_COL_PK) return fail_at(p, "one PRIMARY KEY per column");
                if (pk >= 0 || nkname >= 0)
                    return imdb_fail(p->e, IMDB_ERR_INVALID, "a table has one PRIMARY KEY (PRIMARY KEY (a, b) names several columns)");
                c->flags |= IMDB_COL_PK;
                pk = s->ncols;
            } else if (kw(p, "generated")) { /* F2a-2: GENERATED {ALWAYS | BY DEFAULT} AS IDENTITY [(options)] */
                bool always = kw(p, "always");
                if (!always && (expect_kw(p, "by") || expect_kw(p, "default"))) return p->e->code;
                if (expect_kw(p, "as")) return p->e->code;
                if (always && p->t[p->i].kind == TK_LP) { /* F2c: GENERATED ALWAYS AS (expr) STORED, its text as written */
                    if (st->cdef_kind[s->ncols])
                        return imdb_fail(p->e, IMDB_ERR_INVALID, "column %s: a generated column takes no DEFAULT or IDENTITY", c->name);
                    if (paren_span(p, &st->cdef[s->ncols].off, &st->cdef[s->ncols].len, "a generated column's expression"))
                        return p->e->code;
                    if (kw(p, "virtual"))
                        return imdb_fail(p->e, IMDB_ERR_UNSUPPORTED, "column %s: a VIRTUAL generated column is a later step: write STORED", c->name);
                    if (expect_kw(p, "stored")) return p->e->code;
                    st->cdef_kind[s->ncols] = IMDB_DEFK_GENERATED;
                    continue;
                }
                if (expect_kw(p, "identity")) return p->e->code;
                if (st->cdef_kind[s->ncols])
                    return imdb_fail(p->e, IMDB_ERR_INVALID, "column %s: an IDENTITY takes no DEFAULT, once", c->name);
                st->cdef_kind[s->ncols] = always ? IMDB_DEFK_IDENTITY_ALWAYS : IMDB_DEFK_IDENTITY;
                memset(&st->idopt[s->ncols], 0, sizeof st->idopt[s->ncols]);
                if (tok(p, TK_LP) && (seq_options(p, &st->idopt[s->ncols], false) || expect(p, TK_RP, ")")))
                    return p->e->code;
            } else if (kw(p, "default")) { /* F2a: a literal (DEFAULT NULL: none) or a clock */
                if (st->cdef_kind[s->ncols]) return imdb_fail(p->e, IMDB_ERR_INVALID, "column %s: one DEFAULT", c->name);
                uint8_t ck = 0;
                if (default_value(p, &st->cdef[s->ncols], &ck)) return p->e->code;
                st->cdef_kind[s->ncols] = ck ? ck : IMDB_DEFK_VALUE;
            } else if ((cki = maybe_column_fk(p, st, c->name)) != 0) { /* F2b-2: a column's [CONSTRAINT name] REFERENCES */
                if (cki < 0) return cki;
            } else if ((cki = maybe_check(p, st)) != 0) { /* F2b-1: a column's [CONSTRAINT name] CHECK (condition) */
                if (cki < 0) return cki;
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
        if (st->cdef_kind[s->ncols] == IMDB_DEFK_IDENTITY_ALWAYS || st->cdef_kind[s->ncols] == IMDB_DEFK_IDENTITY) {
            if (null_spec == 1) return imdb_fail(p->e, IMDB_ERR_INVALID, "column %s: an IDENTITY is NOT NULL", c->name);
            if (c->type != IMDB_T_INT64)
                return imdb_fail(p->e, IMDB_ERR_INVALID, "column %s: an IDENTITY is SMALLINT, INTEGER or BIGINT", c->name);
            null_spec = 2; /* PostgreSQL's: an IDENTITY is NOT NULL */
        }
        if (c->flags & (IMDB_COL_PK | IMDB_COL_SUBJECT)) {
            if (null_spec == 1)
                return imdb_fail(p->e, IMDB_ERR_INVALID, "column %s: PRIMARY KEY and SUBJECT columns are NOT NULL", c->name);
        } else if (null_spec != 2) {
            c->flags |= IMDB_COL_NULLABLE; /* the SQL default */
        }
        said_null[s->ncols] = null_spec == 1;
        s->ncols++;
    } while (tok(p, TK_COMMA));
    if (expect(p, TK_RP, ")")) return p->e->code;
    if (!s->ncols) return imdb_fail(p->e, IMDB_ERR_INVALID, "table must have 1..%u columns", IMDB_MAX_COLS);
    if (pk >= 0) {
        s->npk = 1;
        s->key[0] = (uint16_t)pk;
    } else if (nkname > 0) { /* each named column the table's, once; NOT NULL by being a key column */
        for (int k = 0; k < nkname; k++) {
            int ci = imdb_schema_col(s, kname[k]);
            if (ci < 0) return imdb_fail(p->e, IMDB_ERR_INVALID, "PRIMARY KEY names column %s, which the table lacks", kname[k]);
            if (s->cols[ci].flags & IMDB_COL_PK)
                return imdb_fail(p->e, IMDB_ERR_INVALID, "PRIMARY KEY names column %s twice", kname[k]);
            if (said_null[ci])
                return imdb_fail(p->e, IMDB_ERR_INVALID, "column %s: PRIMARY KEY and SUBJECT columns are NOT NULL", kname[k]);
            s->cols[ci].flags = (uint8_t)((s->cols[ci].flags | IMDB_COL_PK) & ~IMDB_COL_NULLABLE);
            s->key[k] = (uint16_t)ci;
        }
        s->npk = (uint8_t)nkname;
    } else {
        return imdb_fail(p->e, IMDB_ERR_INVALID, "table needs a PRIMARY KEY column (or PRIMARY KEY (a, b, ...))");
    }
    if (kw(p, "retention")) {
        st->has_retention = true;
        return parse_retention(p, &st->retention_us);
    }
    return IMDB_OK;
}

static int parse_query(parser *p, sql_stmt *st); /* P2 S5 */

/* WITH [RECURSIVE] name [(c1, ...)] AS (query) [, ...], WITH already read: each a nested SELECT of st by its name (P2
 * S4, S5); P2 S8: before a SELECT or an INSERT, and inside INSERT's query */
static int parse_with_list(parser *p, sql_stmt *st)
{
    bool rec = kw(p, "recursive");
    do {
        char name[IMDB_MAX_IDENT + 1], cols[IMDB_MAX_COLS][IMDB_MAX_IDENT + 1];
        uint8_t nc = 0;
        if (ident(p, name)) return p->e->code;
        if (tok(p, TK_LP)) {
            int rc = IMDB_OK;
            do {
                if (nc >= IMDB_MAX_COLS) rc = imdb_fail(p->e, IMDB_ERR_LIMIT, "a WITH names more than %u columns", IMDB_MAX_COLS);
                else rc = ident(p, cols[nc++]);
                for (uint8_t i = 0; !rc && i + 1 < nc; i++)
                    if (!strcmp(cols[i], cols[nc - 1])) rc = imdb_fail(p->e, IMDB_ERR_INVALID, "a WITH names its column %s twice", cols[i]);
            } while (!rc && tok(p, TK_COMMA));
            if (rc || expect(p, TK_RP, ")")) return p->e->code;
        }
        if (expect_kw(p, "as") || expect(p, TK_LP, "(") || parse_nested(p, st, name) || expect(p, TK_RP, ")"))
            return p->e->code;
        sql_stmt *in = st->sub[st->nsub - 1];
        in->recursive = rec;
        in->with_cte = true; /* P2 S11 */
        if (nc) {
            if (!(in->cte_col = imdb_alloc((size_t)nc * sizeof *in->cte_col, p->e))) return p->e->code;
            memcpy(in->cte_col, cols, (size_t)nc * sizeof *in->cte_col);
            in->cte_ncols = nc;
        }
    } while (tok(p, TK_COMMA));
    return IMDB_OK;
}

/* P2 S9: PREPARE name [(type, ...)] AS statement: the statement's text kept (every token to the end, a final ; the
 * statement's own end) for the executor, which parses it into the session's registry and checks its kind */
static int parse_prepare(parser *p, sql_stmt *st)
{
    st->kind = ST_PREPARE;
    if (ident(p, st->prep_name)) return p->e->code;
    if (tok(p, TK_LP)) {
        do {
            if (st->nptype >= IMDB_MAX_PARAMS)
                return imdb_fail(p->e, IMDB_ERR_LIMIT, "PREPARE declares more than %u parameters", IMDB_MAX_PARAMS);
            if (!st->ptypes && !(st->ptypes = imdb_alloc_array(IMDB_MAX_PARAMS, sizeof *st->ptypes, p->e))) return p->e->code;
            imdb_column c;
            memset(&c, 0, sizeof c);
            char tn[IMDB_MAX_IDENT + 1] = "";
            if (col_type(p, &c, tn)) return p->e->code;
            st->ptypes[st->nptype] = (sql_ptype){c.type, c.scale, c.precision, ""};
            memcpy(st->ptypes[st->nptype++].tname, tn, sizeof tn); /* F3g: an ENUM's name, resolved at each EXECUTE */
        } while (tok(p, TK_COMMA));
        if (expect(p, TK_RP, ")")) return p->e->code;
    }
    if (expect_kw(p, "as")) return p->e->code;
    uint32_t end = p->n;
    if (end > p->i && p->t[end - 1].kind == TK_SEMI) end--;
    if (end <= p->i) return fail_at(p, "a statement to prepare");
    const sql_tok *a = &p->t[p->i], *z = &p->t[end - 1];
    st->body_off = a->off - (a->kind == TK_STR); /* a string token's span: inside its quotes */
    st->body_len = z->off + z->len + (z->kind == TK_STR) - st->body_off;
    p->i = end;
    return IMDB_OK;
}

/* P2 S9: EXECUTE name [(value, ...)]: the values, literals or constant expressions, kept as an INSERT keeps a row */
static int parse_execute(parser *p, sql_stmt *st)
{
    st->kind = ST_EXECUTE;
    if (ident(p, st->prep_name)) return p->e->code;
    if (!tok(p, TK_LP)) return IMDB_OK;
    if (!(st->vals = imdb_alloc_array(IMDB_MAX_PARAMS, sizeof *st->vals, p->e))) return p->e->code;
    uint16_t w = 0;
    do {
        if (w >= IMDB_MAX_PARAMS) return imdb_fail(p->e, IMDB_ERR_LIMIT, "EXECUTE passes more than %u values", IMDB_MAX_PARAMS);
        if (value(p, &st->vals[w++])) return p->e->code;
    } while (tok(p, TK_COMMA));
    st->rowlen = w;
    st->nrows = 1;
    return expect(p, TK_RP, ")") ? p->e->code : IMDB_OK;
}

/* P2 S8: a query starts at token at (SELECT, WITH, or a parenthesized one) */
static bool query_at(const parser *p, uint32_t at)
{
    return tok_is_kw(p, at, "select") || tok_is_kw(p, at, "with") || p->t[at].kind == TK_LP;
}

/* P2 S8: INSERT's query: its own statement, st->src, one level down (FOR UPDATE refused there, as in any nested
 * SELECT); a WITH before it is its own */
static int insert_query(parser *p, sql_stmt *st)
{
    if (!query_at(p, p->i)) return imdb_fail(p->e, IMDB_ERR_SYNTAX, "expected VALUES or a query (SELECT, WITH or one in parentheses)");
    sql_stmt *in = imdb_alloc(sizeof *in, p->e);
    if (!in) return p->e->code;
    memset(in, 0, sizeof *in);
    st->src = in;
    sql_stmt *saved = p->st;
    p->st = in;
    p->depth++;
    int rc = kw(p, "with") ? parse_with_list(p, in) : IMDB_OK;
    if (!rc) rc = parse_query(p, in);
    p->depth--;
    p->st = saved;
    return rc;
}

/* P2 S10: COPY t [(cols)] FROM STDIN | TO STDOUT [[WITH] (option, ...)] and COPY (query) TO STDOUT [...]. No file name,
 * ever: a statement's text may come from anyone who can send SQL, and the operator's files are the client's to open
 * (the CLI's -c with a redirection, a script's inline data, imdb_session_copy_io). Options: HEADER [TRUE | FALSE],
 * DELIMITER 'c' (one byte: not a quote, CR, LF or past ASCII), BATCH n and SKIP n (FROM), FORMAT CSV (the one) */
static int parse_copy(parser *p, sql_stmt *st)
{
    st->copy_delim = ',';
    if (p->t[p->i].kind == TK_LP) { /* a query's rows */
        if (!query_at(p, p->i + 1)) return fail_at(p, "a table or a query in parentheses");
        tok(p, TK_LP);
        if (insert_query(p, st) || expect(p, TK_RP, ")")) return p->e->code;
        st->kind = ST_COPY_TO;
        if (!kw(p, "to")) return fail_at(p, "TO STDOUT after COPY's query");
        if (!kw(p, "stdout")) return fail_at(p, "STDOUT (COPY writes to the client's stream; no file names)");
    } else {
        if (ident(p, st->table)) return p->e->code;
        if (tok(p, TK_LP)) {
            do {
                if (st->ncols >= IMDB_MAX_COLS) return imdb_fail(p->e, IMDB_ERR_LIMIT, "too many columns");
                if (ident(p, st->cols[st->ncols++])) return p->e->code;
            } while (tok(p, TK_COMMA));
            if (expect(p, TK_RP, ")")) return p->e->code;
        }
        if (kw(p, "from")) {
            st->kind = ST_COPY_FROM;
            if (!kw(p, "stdin")) return fail_at(p, "STDIN (COPY reads the client's stream; no file names)");
        } else if (kw(p, "to")) {
            st->kind = ST_COPY_TO;
            if (!kw(p, "stdout")) return fail_at(p, "STDOUT (COPY writes to the client's stream; no file names)");
        } else {
            return fail_at(p, "FROM STDIN or TO STDOUT");
        }
    }
    bool with = kw(p, "with");
    if (!tok(p, TK_LP)) return with ? fail_at(p, "( after WITH") : IMDB_OK;
    bool seen[5] = {false};
    do {
        int o = tok_is_kw(p, p->i, "header") ? 0 : tok_is_kw(p, p->i, "delimiter") ? 1 : tok_is_kw(p, p->i, "batch") ? 2
              : tok_is_kw(p, p->i, "skip") ? 3 : tok_is_kw(p, p->i, "format") ? 4 : -1;
        if (o < 0) return fail_at(p, "a COPY option: HEADER, DELIMITER, BATCH, SKIP or FORMAT");
        if (seen[o]) return imdb_fail(p->e, IMDB_ERR_SYNTAX, "a COPY option given twice at offset %u", p->t[p->i].off);
        seen[o] = true;
        p->i++;
        if (o == 0) {
            st->copy_header = !kw(p, "false");
            if (st->copy_header) kw(p, "true");
        } else if (o == 1) {
            const sql_tok *t = &p->t[p->i];
            if (t->kind != TK_STR) return fail_at(p, "a one-byte string after DELIMITER");
            unsigned char ch = t->len == 1 ? (unsigned char)p->s[t->off] : 0;
            if (t->len != 1 || ch == '"' || ch == '\r' || ch == '\n' || ch >= 0x80)
                return imdb_fail(p->e, IMDB_ERR_INVALID, "COPY's DELIMITER is one ASCII byte, not a quote, CR or LF");
            st->copy_delim = (char)ch;
            p->i++;
        } else if (o == 2 || o == 3) {
            if (st->kind != ST_COPY_FROM) return imdb_fail(p->e, IMDB_ERR_INVALID, "%s is COPY ... FROM's", o == 2 ? "BATCH" : "SKIP");
            uint64_t v;
            if (uint_lit(p, &v)) return p->e->code;
            if (o == 2) {
                if (v < 1 || v > IMDB_MAX_OPS_PER_COMMIT)
                    return imdb_fail(p->e, IMDB_ERR_LIMIT, "BATCH is 1 to %u rows a commit", IMDB_MAX_OPS_PER_COMMIT);
                st->copy_batch = (uint32_t)v;
            } else {
                st->copy_skip = v;
            }
        } else if (!kw(p, "csv")) {
            return fail_at(p, "CSV after FORMAT (the one format)");
        }
    } while (tok(p, TK_COMMA));
    return expect(p, TK_RP, ")") ? p->e->code : IMDB_OK;
}
/* P2 S8: UPDATE t SET ... FROM u [AS a] [WHERE condition], DELETE FROM t USING u [AS a] [WHERE condition], FROM or
 * USING at p->i: st->src is SELECT * FROM t JOIN u ON condition (CROSS without one), which the executor runs whole at
 * the statement's snapshot; st's SET trees read t and u as a join's two sides (st->table2, alias2) */
static int join_source(parser *p, sql_stmt *st, const char *what)
{
    p->i++;
    if (p->t[p->i].kind == TK_LP) return imdb_fail(p->e, IMDB_ERR_UNSUPPORTED, "%s a nested SELECT: a later step (name a table)", what);
    sql_stmt *in = imdb_alloc(sizeof *in, p->e);
    if (!in) return p->e->code;
    memset(in, 0, sizeof *in);
    st->src = in;
    in->kind = ST_SELECT;
    in->star = true;
    in->has_join = true;
    in->join_kind = SQL_JOIN_INNER;
    memcpy(in->table, st->table, sizeof in->table);
    if (ident(p, in->table2) || alias(p, in->alias2)) return p->e->code;
    if (p->t[p->i].kind == TK_COMMA) return imdb_fail(p->e, IMDB_ERR_UNSUPPORTED, "%s one table (more: a later step)", what);
    if (!strcmp(in->table2, st->table) && !in->alias2[0])
        return imdb_fail(p->e, IMDB_ERR_INVALID, "%s %s again: name it with AS", what, st->table);
    memcpy(st->table2, in->table2, sizeof st->table2);
    memcpy(st->alias2, in->alias2, sizeof st->alias2);
    if (!kw(p, "where")) {
        in->join_kind = SQL_JOIN_CROSS;
        return IMDB_OK;
    }
    sql_stmt *saved = p->st;
    p->st = in;
    p->depth++;
    int rc = bexpr(p, &in->on_ex, 0);
    p->depth--;
    p->st = saved;
    if (rc) return rc;
    const sql_expr *o = &in->ex[in->on_ex]; /* one equality of two columns: the path a join's ON has */
    if (o->op == EX_CMP && o->cmp == CMP_EQ && in->ex[o->l].op == EX_COL && in->ex[o->r].op == EX_COL) {
        memcpy(in->on_qual[0], in->ex[o->l].qual, sizeof in->on_qual[0]);
        memcpy(in->on_col[0], in->ex[o->l].col, sizeof in->on_col[0]);
        memcpy(in->on_qual[1], in->ex[o->r].qual, sizeof in->on_qual[1]);
        memcpy(in->on_col[1], in->ex[o->r].col, sizeof in->on_col[1]);
    }
    return IMDB_OK;
}

/* P2 S8: ON CONFLICT [(c, ...)] DO NOTHING | DO UPDATE SET c = v, ... [WHERE condition]: the SET's values and the
 * condition read the existing row by the table's name and the proposed one as EXCLUDED (table2: join_col's side 1) */
static int on_conflict(parser *p, sql_stmt *st)
{
    if (!tok_is_kw(p, p->i, "on")) return IMDB_OK;
    p->i++;
    if (expect_kw(p, "conflict")) return p->e->code;
    if (tok(p, TK_LP)) {
        do {
            if (st->nconf >= IMDB_MAX_KEY_COLS)
                return imdb_fail(p->e, IMDB_ERR_LIMIT, "ON CONFLICT names more than %u columns", IMDB_MAX_KEY_COLS);
            if (ident(p, st->conf_cols[st->nconf++])) return p->e->code;
        } while (tok(p, TK_COMMA));
        if (expect(p, TK_RP, ")")) return p->e->code;
    }
    if (expect_kw(p, "do")) return p->e->code;
    if (kw(p, "nothing")) {
        st->upsert = SQL_UPSERT_NOTHING;
        return IMDB_OK;
    }
    if (expect_kw(p, "update") || expect_kw(p, "set")) return p->e->code;
    if (!st->nconf) /* PostgreSQL's rule: which conflict it resolves is named */
        return imdb_fail(p->e, IMDB_ERR_INVALID, "ON CONFLICT DO UPDATE names its key: ON CONFLICT (column, ...) DO UPDATE");
    st->upsert = SQL_UPSERT_UPDATE;
    snprintf(st->table2, sizeof st->table2, "excluded");
    do {
        if (st->nset >= IMDB_MAX_COLS) return imdb_fail(p->e, IMDB_ERR_LIMIT, "too many assignments");
        if (ident(p, st->set_cols[st->nset]) || expect(p, TK_EQ, "=") || value(p, &st->set_vals[st->nset])) return p->e->code;
        st->nset++;
    } while (tok(p, TK_COMMA));
    return kw(p, "where") && bexpr(p, &st->upsert_where, 0) ? p->e->code : IMDB_OK;
}

/* P2 S8: RETURNING * | item [[AS] alias], ...: each item a tree over the row written (INSERT's and UPDATE's new
 * values, DELETE's old ones), its own columns alone: no aggregate, window function or nested SELECT */
static int returning(parser *p, sql_stmt *st)
{
    if (!kw(p, "returning")) return IMDB_OK;
    st->returning = true;
    if (tok(p, TK_STAR)) {
        st->star = true;
        return IMDB_OK;
    }
    do {
        if (st->nitems >= IMDB_MAX_COLS) return imdb_fail(p->e, IMDB_ERR_LIMIT, "too many RETURNING items");
        sql_item *it = &st->items[st->nitems];
        uint32_t from = p->t[p->i].off - (p->t[p->i].kind == TK_STR); /* a string token's span: inside its quotes */
        uint8_t nsub = st->nsub;
        uint16_t k;
        if (bexpr(p, &k, 0)) return p->e->code;
        if (st->nsub != nsub) return imdb_fail(p->e, IMDB_ERR_UNSUPPORTED, "a nested SELECT in RETURNING: a later step");
        if (imdb_sql_has_agg(st, k))
            return imdb_fail(p->e, IMDB_ERR_INVALID, "RETURNING computes on each row written: no aggregate");
        it->off = from;
        it->len = p->t[p->i - 1].off + p->t[p->i - 1].len + (p->t[p->i - 1].kind == TK_STR) - from;
        if (kw(p, "as") ? ident(p, it->alias)
                        : p->t[p->i].kind == TK_IDENT && !is_reserved(p, p->i) && ident(p, it->alias))
            return p->e->code;
        it->expr = k; /* a bare column too: evaluated on the row */
        st->nitems++;
    } while (tok(p, TK_COMMA));
    return IMDB_OK;
}


static int parse_insert(parser *p, sql_stmt *st)
{
    st->kind = ST_INSERT;
    if (expect_kw(p, "into") || ident(p, st->table)) return p->e->code;
    if (p->t[p->i].kind == TK_LP && !query_at(p, p->i + 1)) { /* a column list: (SELECT ...) is a query (P2 S8) */
        tok(p, TK_LP);
        do {
            if (st->ncols >= IMDB_MAX_COLS) return imdb_fail(p->e, IMDB_ERR_LIMIT, "too many columns");
            if (ident(p, st->cols[st->ncols++])) return p->e->code;
        } while (tok(p, TK_COMMA));
        if (expect(p, TK_RP, ")")) return p->e->code;
    }
    if (kw(p, "overriding")) { /* F2a-2: OVERRIDING SYSTEM VALUE (an ALWAYS IDENTITY takes the value given) or USER VALUE */
        if (kw(p, "system")) st->overriding = 1;
        else if (kw(p, "user")) st->overriding = 2;
        else return fail_at(p, "SYSTEM or USER");
        if (expect_kw(p, "value")) return p->e->code;
    }
    if (!st->ncols && tok_is_kw(p, p->i, "default") && tok_is_kw(p, p->i + 1, "values")) { /* F2a-2: one row of DEFAULTs */
        p->i += 2;
        st->default_values = true;
        st->nrows = 1;
        return on_conflict(p, st) ? p->e->code : returning(p, st);
    }
    if (!kw(p, "values")) return insert_query(p, st) || on_conflict(p, st) ? p->e->code : returning(p, st); /* P2 S8 */
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
            if (kw(p, "default")) { /* F2a-2: the column's DEFAULT */
                memset(&st->vals[at], 0, sizeof st->vals[at]);
                st->vals[at].kind = LIT_DEFAULT;
            } else if (value(p, &st->vals[at])) {
                return p->e->code;
            }
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
    return on_conflict(p, st) ? p->e->code : returning(p, st); /* P2 S8 */
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

/* P2 S4: a nested SELECT, parsed from the same tokens into its own statement (its own expression nodes), named: the
 * row set its outer statement reads as a table of that name; nesting bounded */
static int parse_core(parser *p, sql_stmt *st);
static int parse_tail(parser *p, sql_stmt *st);
static int parse_query(parser *p, sql_stmt *st); /* P2 S5 */
static int parse_nested(parser *p, sql_stmt *outer, const char *name)
{
    if (outer->nsub >= IMDB_MAX_SUBQUERIES)
        return imdb_fail(p->e, IMDB_ERR_LIMIT, "more than %u nested SELECTs in one statement", IMDB_MAX_SUBQUERIES);
    if (p->depth >= IMDB_MAX_SUBQUERY_DEPTH)
        return imdb_fail(p->e, IMDB_ERR_LIMIT, "SELECTs nested deeper than %u", IMDB_MAX_SUBQUERY_DEPTH);
    for (uint8_t i = 0; name[0] && i < outer->nsub; i++) /* an expression's (unnamed) never collides */
        if (!strcmp(outer->sub_name[i], name))
            return imdb_fail(p->e, IMDB_ERR_INVALID, "two nested SELECTs named %s", name);
    sql_stmt *in = imdb_alloc(sizeof *in, p->e);
    if (!in) return p->e->code;
    memset(in, 0, sizeof *in);
    uint8_t i = outer->nsub++;
    outer->sub[i] = in;
    snprintf(outer->sub_name[i], sizeof outer->sub_name[i], "%s", name);
    sql_stmt *saved = p->st;
    p->st = in;
    p->depth++;
    bool wok = p->win_ok; /* P2 S6: a nested SELECT's items set it for their own */
    p->win_ok = false;
    int rc = parse_query(p, in); /* P2 S5: a set operation too */
    p->win_ok = wok;
    p->depth--;
    p->st = saved;
    return rc;
}

/* P2 S4: a table where FROM or a join names one: a name, or (SELECT ...) AS name, the name required */
static int from_item(parser *p, sql_stmt *st, char *table, char *al)
{
    if (!tok(p, TK_LP)) return ident(p, table) || alias(p, al) ? p->e->code : IMDB_OK;
    char name[IMDB_MAX_IDENT + 1];
    uint16_t at = (uint16_t)st->nsub;
    if (parse_nested(p, st, "") || expect(p, TK_RP, ")")) return p->e->code;
    kw(p, "as");
    if (p->t[p->i].kind != TK_IDENT || is_reserved(p, p->i))
        return imdb_fail(p->e, IMDB_ERR_SYNTAX, "a nested SELECT in FROM needs a name: (SELECT ...) AS name");
    if (ident(p, name)) return p->e->code;
    for (uint8_t i = 0; i < st->nsub; i++)
        if (i != at && !strcmp(st->sub_name[i], name)) return imdb_fail(p->e, IMDB_ERR_INVALID, "two nested SELECTs named %s", name);
    snprintf(st->sub_name[at], sizeof st->sub_name[at], "%s", name);
    snprintf(table, IMDB_MAX_IDENT + 1, "%s", name);
    al[0] = 0;
    return IMDB_OK;
}

static int parse_core(parser *p, sql_stmt *st)
{
    st->kind = ST_SELECT;
    st->distinct = kw(p, "distinct");
    if (tok(p, TK_STAR)) {
        st->star = true;
    } else {
        do {
            if (st->nitems >= IMDB_MAX_COLS) return imdb_fail(p->e, IMDB_ERR_LIMIT, "too many select items");
            sql_item *it = &st->items[st->nitems];
            uint32_t from = p->t[p->i].off - (p->t[p->i].kind == TK_STR); /* a string token's span: inside its quotes */
            uint16_t k;
            bool wok = p->win_ok;
            p->win_ok = true; /* P2 S6: a window function may stand here, as the item's whole expression */
            int brc = bexpr(p, &k, 0);
            p->win_ok = wok;
            if (brc) return p->e->code;
            if (win_below(st, k, true))
                return imdb_fail(p->e, IMDB_ERR_INVALID, "a window function stands only as a SELECT item, alone (compute on it "
                                                         "from a derived table)");
            it->off = from;
            it->len = p->t[p->i - 1].off + p->t[p->i - 1].len + (p->t[p->i - 1].kind == TK_STR) - from;
            if (kw(p, "as") ? ident(p, it->alias) /* P2 S1: an alias, with AS or without it */
                              : p->t[p->i].kind == TK_IDENT && !is_reserved(p, p->i) && ident(p, it->alias))
                return p->e->code;
            const sql_expr *x = &st->ex[k], *a = x->op == EX_AGG && x->l ? &st->ex[x->l] : NULL;
            if (x->op == EX_COL) { /* today's shapes: a column, an aggregate of a column, COUNT(*) */
                memcpy(it->qual, x->qual, sizeof it->qual);
                memcpy(it->col, x->col, sizeof it->col);
            } else if (x->op == EX_AGG && x->agg != AGG_AVG && !x->dist && !x->x3 && (!a || a->op == EX_COL)) { /* AVG,
                                                     * DISTINCT and FILTER (P2 S2): a tree's slot */
                it->agg = x->agg;
                if (a) {
                    memcpy(it->qual, a->qual, sizeof it->qual);
                    memcpy(it->col, a->col, sizeof it->col);
                }
            } else {
                it->expr = k;
            }
            st->nitems++;
        } while (tok(p, TK_COMMA));
    }
    if (!st->star && !tok_is_kw(p, p->i, "from")) { /* P2 S1: SELECT of expressions alone: one row, no table */
        st->no_from = true;
        static const char *const cl[] = {"where", "group", "having"}; /* its tail: parse_query's (P2 S5: a set
                                                                          * operation's, after its last SELECT) */
        for (size_t c = 0; c < sizeof cl / sizeof *cl; c++)
            if (tok_is_kw(p, p->i, cl[c]))
                return imdb_fail(p->e, IMDB_ERR_INVALID, "a SELECT without FROM computes one row: no WHERE, GROUP BY, HAVING, ORDER "
                                                       "BY, LIMIT, OFFSET or FOR UPDATE");
        return IMDB_OK;
    }
    if (expect_kw(p, "from") || from_item(p, st, st->table, st->alias)) return p->e->code; /* P2 S4: or (SELECT ...) AS x */
    if (kw(p, "with")) {
        if (expect(p, TK_LP, "(") || expect_kw(p, "nolock") || expect(p, TK_RP, ")")) return p->e->code;
        st->nolock = true;
    }
    /* P2 S3: [INNER] JOIN, LEFT | RIGHT | FULL [OUTER] JOIN ... ON cond | USING (cols), CROSS JOIN, FROM a, b; two
     * tables (three or more: a later step) */
    bool comma = p->t[p->i].kind == TK_COMMA;
    if (comma || tok_is_kw(p, p->i, "join") || tok_is_kw(p, p->i, "inner") || tok_is_kw(p, p->i, "left") ||
        tok_is_kw(p, p->i, "right") || tok_is_kw(p, p->i, "full") || tok_is_kw(p, p->i, "cross")) {
        st->has_join = true;
        st->join_kind = SQL_JOIN_INNER;
        if (comma) {
            p->i++;
            st->join_kind = SQL_JOIN_CROSS;
        } else {
            if (kw(p, "cross")) st->join_kind = SQL_JOIN_CROSS;
            else if (kw(p, "left")) st->join_kind = SQL_JOIN_LEFT;
            else if (kw(p, "right")) st->join_kind = SQL_JOIN_RIGHT;
            else if (kw(p, "full")) st->join_kind = SQL_JOIN_FULL;
            else kw(p, "inner");
            if (st->join_kind != SQL_JOIN_INNER && st->join_kind != SQL_JOIN_CROSS) kw(p, "outer");
            if (expect_kw(p, "join")) return p->e->code;
        }
        st->join_left = st->join_kind == SQL_JOIN_LEFT;
        if (from_item(p, st, st->table2, st->alias2)) return p->e->code;
        if (st->join_kind != SQL_JOIN_CROSS && kw(p, "using")) {
            if (expect(p, TK_LP, "(")) return p->e->code;
            do {
                if (st->nusing >= IMDB_MAX_JOIN_KEYS)
                    return imdb_fail(p->e, IMDB_ERR_LIMIT, "USING names more than %u columns", IMDB_MAX_JOIN_KEYS);
                if (ident(p, st->using_col[st->nusing++])) return p->e->code;
            } while (tok(p, TK_COMMA));
            if (expect(p, TK_RP, ")")) return p->e->code;
        } else if (st->join_kind != SQL_JOIN_CROSS) {
            if (expect_kw(p, "on") || bexpr(p, &st->on_ex, 0)) return p->e->code;
            const sql_expr *o = &st->ex[st->on_ex]; /* one equality of two columns: the path it always had */
            if (o->op == EX_CMP && o->cmp == CMP_EQ && st->ex[o->l].op == EX_COL && st->ex[o->r].op == EX_COL) {
                memcpy(st->on_qual[0], st->ex[o->l].qual, sizeof st->on_qual[0]);
                memcpy(st->on_col[0], st->ex[o->l].col, sizeof st->on_col[0]);
                memcpy(st->on_qual[1], st->ex[o->r].qual, sizeof st->on_qual[1]);
                memcpy(st->on_col[1], st->ex[o->r].col, sizeof st->on_col[1]);
            }
        }
        if (p->t[p->i].kind == TK_COMMA || tok_is_kw(p, p->i, "join") || tok_is_kw(p, p->i, "inner") ||
            tok_is_kw(p, p->i, "left") || tok_is_kw(p, p->i, "right") || tok_is_kw(p, p->i, "full") ||
            tok_is_kw(p, p->i, "cross"))
            return imdb_fail(p->e, IMDB_ERR_UNSUPPORTED, "a join takes two tables (three or more: a later step)");
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
        if (expect_kw(p, "by")) return p->e->code;
        do { /* P2 S2: keys are trees; the one bare column keeps group_qual and group_col (the path of one column) */
            if (st->ngroup >= IMDB_MAX_GROUP_KEYS)
                return imdb_fail(p->e, IMDB_ERR_LIMIT, "GROUP BY has more than %u keys", IMDB_MAX_GROUP_KEYS);
            uint8_t g = st->ngroup;
            uint32_t from = p->t[p->i].off - (p->t[p->i].kind == TK_STR);
            if (bexpr(p, &st->group_ex[g], 0)) return p->e->code;
            st->group_off[g] = from;
            st->group_len[g] = p->t[p->i - 1].off + p->t[p->i - 1].len + (p->t[p->i - 1].kind == TK_STR) - from;
            st->ngroup++;
        } while (tok(p, TK_COMMA));
        const sql_expr *g0 = &st->ex[st->group_ex[0]];
        if (st->ngroup == 1 && g0->op == EX_COL) {
            memcpy(st->group_qual, g0->qual, sizeof st->group_qual);
            memcpy(st->group_col, g0->col, sizeof st->group_col);
        }
        st->has_group = true;
    }
    if (kw(p, "having")) { /* 1e: a condition over the groups (or the one aggregate row) */
        if (bexpr(p, &st->having, 0)) return p->e->code;
    }
    return IMDB_OK;
}

/* a query's tail: ORDER BY, LIMIT and OFFSET (P2 S5: a set operation's too), FOR UPDATE */
static int parse_tail(parser *p, sql_stmt *st)
{
    if (kw(p, "order")) { /* 1d: key [ASC | DESC] [NULLS FIRST | LAST], ...; a bare integer is an item's position */
        if (expect_kw(p, "by")) return p->e->code;
        do {
            if (st->norder >= IMDB_MAX_ORDER)
                return imdb_fail(p->e, IMDB_ERR_LIMIT, "ORDER BY has more than %u keys", IMDB_MAX_ORDER);
            uint8_t o = st->norder;
            const sql_tok *t = &p->t[p->i];
            uint8_t nk = t->kind == TK_EOF ? TK_EOF : p->t[p->i + 1].kind;
            if (t->kind == TK_INT && (nk == TK_COMMA || nk == TK_EOF || nk == TK_SEMI || nk == TK_IDENT || nk == TK_RP)) { /* P2 S5: ) too */
                uint64_t pos;
                if (uint_lit(p, &pos)) return p->e->code;
                if (pos < 1 || pos > IMDB_MAX_COLS) return imdb_fail(p->e, IMDB_ERR_INVALID, "ORDER BY %llu: no such item",
                                                                       (unsigned long long)pos);
                st->ord_pos[o] = (uint16_t)pos;
            } else if (bexpr(p, &st->ord_ex[o], 0)) {
                return p->e->code;
            }
            if (st->ord_ex[o] && st->ex[st->ord_ex[o]].op == EX_COL && !st->ex[st->ord_ex[o]].qual[0]) /* P2 S1: an alias
                * names its item (PostgreSQL: an output column before an input one) */
                for (uint16_t i = 0; i < st->nitems; i++)
                    if (st->items[i].alias[0] && !strcmp(st->items[i].alias, st->ex[st->ord_ex[o]].col)) {
                        st->ord_pos[o] = (uint16_t)(i + 1);
                        st->ord_ex[o] = 0;
                        break;
                    }
            st->ord_desc[o] = kw(p, "desc");
            if (!st->ord_desc[o]) kw(p, "asc");
            st->ord_nulls_first[o] = st->ord_desc[o]; /* PostgreSQL's default: NULLs as the largest */
            if (kw(p, "nulls")) {
                if (kw(p, "first")) st->ord_nulls_first[o] = true;
                else if (kw(p, "last")) st->ord_nulls_first[o] = false;
                else return fail_at(p, "FIRST or LAST after NULLS");
            }
            st->norder++;
        } while (tok(p, TK_COMMA));
    }
    for (int k = 0; k < 2; k++) { /* LIMIT n and OFFSET n, in either order, each once */
        if (!st->has_limit && kw(p, "limit")) {
            st->has_limit = true;
            if (uint_lit(p, &st->limit)) return p->e->code;
        } else if (!st->has_offset && kw(p, "offset")) {
            st->has_offset = true;
            if (uint_lit(p, &st->offset)) return p->e->code;
        }
    }
    if (kw(p, "for")) {
        if (expect_kw(p, "update")) return p->e->code;
        if (p->depth || p->parens) /* P2 S5: a nested SELECT's or an arm's would lock under EXPLAIN, which locks nothing */
            return imdb_fail(p->e, IMDB_ERR_INVALID, "FOR UPDATE locks a statement's own rows: at its top level only");
        st->for_update = true;
        bool agg = st->has_group || st->having;
        for (uint16_t i = 0; i < st->nitems; i++) agg = agg || st->items[i].agg != AGG_NONE || imdb_sql_has_agg(st, st->items[i].expr);
        if (agg || st->has_asof || st->has_join)
            return imdb_fail(p->e, IMDB_ERR_INVALID, "FOR UPDATE locks rows: not with aggregates, GROUP BY, AS OF or a join");
    }
    return IMDB_OK;
}


/* ---- P2 S5: set operations ---------------------------------------------------------------------------------------- */

/* the operator at the current token, consumed with its ALL (DISTINCT, the default) when it is one of level's
 * (1: INTERSECT; 0: UNION and EXCEPT); else 0 */
static uint8_t setop_take(parser *p, int level)
{
    uint8_t op = tok_is_kw(p, p->i, "union")       ? SQL_SET_UNION
                 : tok_is_kw(p, p->i, "intersect") ? SQL_SET_INTERSECT
                 : tok_is_kw(p, p->i, "except")    ? SQL_SET_EXCEPT
                                                   : 0;
    if (!op || (level == 1) != (op == SQL_SET_INTERSECT)) return 0;
    p->i++;
    if (kw(p, "all")) op |= SQL_SET_ALL;
    else kw(p, "distinct");
    return op;
}

/* a fresh statement for an arm, the statement's arms (every chain's) counted against IMDB_MAX_SETOP_ARMS */
static int arm_new(parser *p, sql_stmt **out)
{
    if (p->narms >= IMDB_MAX_SETOP_ARMS)
        return imdb_fail(p->e, IMDB_ERR_LIMIT, "set operations of more than %u SELECTs in one statement", IMDB_MAX_SETOP_ARMS);
    sql_stmt *a = imdb_alloc(sizeof *a, p->e);
    if (!a) return p->e->code;
    memset(a, 0, sizeof *a);
    p->narms++;
    *out = a;
    return IMDB_OK;
}

/* st, which holds one operand, becomes a set operation whose first arm is that operand, moved whole but for its first
 * keep nested SELECTs (a WITH's, parsed before the query: every arm reads them), which stay st's; the operand's own,
 * renumbered from 0, go with it (its EX_SUBQ nodes follow) */
static int setop_open(parser *p, sql_stmt *st, uint8_t keep)
{
    sql_stmt *a;
    if (arm_new(p, &a)) return p->e->code;
    memcpy(a, st, sizeof *st);
    memset(st, 0, sizeof *st);
    st->kind = ST_SELECT;
    for (uint8_t i = 0; i < keep; i++) {
        st->sub[i] = a->sub[i];
        memcpy(st->sub_name[i], a->sub_name[i], sizeof st->sub_name[i]);
    }
    st->nsub = keep;
    uint8_t n = (uint8_t)(a->nsub - keep);
    for (uint8_t i = 0; i < n; i++) {
        a->sub[i] = a->sub[i + keep];
        memcpy(a->sub_name[i], a->sub_name[i + keep], sizeof a->sub_name[i]);
    }
    for (uint8_t i = n; i < a->nsub; i++) {
        a->sub[i] = NULL;
        a->sub_name[i][0] = 0;
    }
    a->nsub = n;
    for (uint16_t k = 1; keep && k <= a->nex; k++)
        if (a->ex[k].op == EX_SUBQ) a->ex[k].sub = (uint8_t)(a->ex[k].sub - keep);
    st->arm[0] = a;
    st->narm = 1;
    return IMDB_OK;
}

static int parse_query(parser *p, sql_stmt *st);

/* one operand: SELECT's core (the query's tail follows its last operand), or a parenthesized query with its own tail */
static int parse_operand(parser *p, sql_stmt *st)
{
    if (tok(p, TK_LP)) { /* bounded: the recursion is the parser's, the text a client's */
        if (p->parens >= IMDB_MAX_QUERY_PARENS)
            return imdb_fail(p->e, IMDB_ERR_LIMIT, "queries parenthesized deeper than %u", IMDB_MAX_QUERY_PARENS);
        p->parens++;
        int rc = parse_query(p, st) || expect(p, TK_RP, ")") ? p->e->code : IMDB_OK;
        p->parens--;
        return rc;
    }
    return expect_kw(p, "select") || parse_core(p, st) ? p->e->code : IMDB_OK;
}

/* operands joined by the operators of one precedence (level 0: UNION and EXCEPT, whose operands are level 1's chains;
 * 1: INTERSECT, whose operands are parse_operand's) into st: one operand is st itself; more make st their set operation
 * (setop_open). keep: st's nested SELECTs from before the query (a WITH's) */
static int parse_chain(parser *p, sql_stmt *st, int level, uint8_t keep)
{
    if (level ? parse_operand(p, st) : parse_chain(p, st, 1, keep)) return p->e->code;
    bool open = false;
    for (uint8_t op; (op = setop_take(p, level)) != 0;) {
        if (!open && setop_open(p, st, keep)) return p->e->code;
        open = true;
        sql_stmt *b;
        if (arm_new(p, &b)) return p->e->code;
        st->armop[st->narm] = op;
        st->arm[st->narm++] = b;
        sql_stmt *saved = p->st;
        p->st = b;
        int rc = level ? parse_operand(p, b) : parse_chain(p, b, 1, 0);
        p->st = saved;
        if (rc) return rc;
    }
    return IMDB_OK;
}

/* a query, its first SELECT keyword not yet read: one SELECT (as before), or a set operation; then the tail. A query
 * whose last operand was parenthesized with its own tail, followed by another, becomes a set operation of one arm, so
 * each tail applies in its order. A set operation's ORDER BY names an output column or its position (PostgreSQL's
 * rule), and it takes no FOR UPDATE */
static int parse_query(parser *p, sql_stmt *st)
{
    sql_stmt *saved = p->st;
    p->st = st;
    uint8_t keep = st->nsub;
    int rc = parse_chain(p, st, 0, keep);
    bool tail = st->norder || st->has_limit || st->has_offset;
    if (!rc && tail &&
        (tok_is_kw(p, p->i, "order") || tok_is_kw(p, p->i, "limit") || tok_is_kw(p, p->i, "offset") || tok_is_kw(p, p->i, "for")))
        rc = setop_open(p, st, keep);
    if (!rc) rc = parse_tail(p, st);
    for (uint8_t o = 0; !rc && st->narm && o < st->norder; o++) {
        const sql_expr *k = st->ord_ex[o] ? &st->ex[st->ord_ex[o]] : NULL;
        if (k && (k->op != EX_COL || k->qual[0]))
            rc = imdb_fail(p->e, IMDB_ERR_INVALID, "a set operation's ORDER BY names an output column or its position");
    }
    if (!rc && st->narm && st->for_update) rc = imdb_fail(p->e, IMDB_ERR_INVALID, "FOR UPDATE locks a table's rows: not a set operation's");
    if (!rc && !st->narm && st->no_from && (st->norder || st->has_limit || st->has_offset || st->for_update))
        rc = imdb_fail(p->e, IMDB_ERR_INVALID, "a SELECT without FROM computes one row: no WHERE, GROUP BY, HAVING, ORDER BY, "
                                               "LIMIT, OFFSET or FOR UPDATE");
    p->st = saved;
    return rc;
}

void imdb_sql_stmt_free(sql_stmt *st)
{
    for (uint8_t i = 0; i < st->nsub; i++) { /* P2 S4 */
        if (!st->sub[i]) continue;
        imdb_sql_stmt_free(st->sub[i]);
        imdb_free(st->sub[i]);
        st->sub[i] = NULL;
    }
    st->nsub = 0;
    for (uint8_t i = 0; i < st->narm; i++) { /* P2 S5 */
        if (!st->arm[i]) continue;
        imdb_sql_stmt_free(st->arm[i]);
        imdb_free(st->arm[i]);
        st->arm[i] = NULL;
    }
    st->narm = 0;
    imdb_free(st->ptypes); /* P2 S9 */
    st->ptypes = NULL;
    imdb_free(st->ctname); /* F3g */
    st->ctname = NULL;
    imdb_free(st->fks); /* F2b-2 */
    st->fks = NULL;
    st->nfks = 0;
    imdb_free(st->cte_col); /* P2 S5 */
    st->cte_col = NULL;
    st->cte_ncols = 0;
    if (st->src) { /* P2 S8 */
        imdb_sql_stmt_free(st->src);
        imdb_free(st->src);
        st->src = NULL;
    }
    imdb_free(st->vals);
    st->vals = NULL;
    imdb_free(st->ex);
    st->ex = NULL;
    st->nex = st->capex = 0;
}

/* P2 S7: CREATE VIEW name [(c1, ...)] AS query: the query its own statement (src) at the top of its own parse, as the
 * text parses when the view is used; the text kept as written, from the token after AS to the end of the last token
 * (body_off, body_len: no trailing comment, so a dump's ';' after it stays a statement's end); the column list in
 * set_cols (nset). A parameter is refused: a view's query is complete */
static int parse_create_view(parser *p, sql_stmt *st)
{
    st->kind = ST_CREATE_VIEW;
    if (ident(p, st->table)) return p->e->code;
    if (tok(p, TK_LP)) {
        do {
            if (st->nset >= IMDB_MAX_COLS)
                return imdb_fail(p->e, IMDB_ERR_LIMIT, "a view of more than %u columns", IMDB_MAX_COLS);
            if (ident(p, st->set_cols[st->nset])) return p->e->code;
            st->nset++;
        } while (tok(p, TK_COMMA));
        if (expect(p, TK_RP, ")")) return p->e->code;
    }
    if (expect_kw(p, "as")) return p->e->code;
    if (!query_at(p, p->i)) return imdb_fail(p->e, IMDB_ERR_SYNTAX, "expected a query after AS (SELECT, WITH or one in parentheses)");
    uint32_t t0 = p->i;
    sql_stmt *in = imdb_alloc(sizeof *in, p->e);
    if (!in) return p->e->code;
    st->src = in;
    sql_stmt *saved = p->st;
    p->st = in;
    int rc = kw(p, "with") ? parse_with_list(p, in) : IMDB_OK;
    if (!rc) rc = parse_query(p, in);
    p->st = saved;
    if (rc) return rc;
    for (uint32_t k = t0; k < p->i; k++)
        if (p->t[k].kind == TK_PARAM) return imdb_fail(p->e, IMDB_ERR_INVALID, "a view's query takes no parameter ($n)");
    const sql_tok *a = &p->t[t0], *z = &p->t[p->i - 1];
    st->body_off = a->off - (a->kind == TK_STR);
    st->body_len = z->off + z->len + (z->kind == TK_STR) - st->body_off;
    return IMDB_OK;
}

/* P2: SET TIME ZONE's value (and SET timezone's): a string, the zone's name as written (its case kept: a zone file's
 * name), or DEFAULT or LOCAL, UTC */
static int set_zone_value(parser *p, sql_stmt *st)
{
    st->set_zone = true;
    st->set_value[0] = 0;
    if (kw(p, "default") || kw(p, "local")) return IMDB_OK;
    const sql_tok *v = &p->t[p->i];
    if (v->kind != TK_STR) return fail_at(p, "a time zone's name as a string, DEFAULT or LOCAL");
    if (!v->len || v->len > IMDB_MAX_IDENT) return imdb_fail(p->e, IMDB_ERR_INVALID, "a time zone's name of 1 to %u bytes", IMDB_MAX_IDENT);
    memcpy(st->set_value, p->s + v->off, v->len);
    st->set_value[v->len] = 0;
    p->i++;
    return IMDB_OK;
}

/* F3g: an ENUM column's type name at position at (CREATE TABLE's, ADD COLUMN's at 0), into the statement's list */
static int col_tname(parser *p, uint16_t at, const char *tname)
{
    sql_stmt *st = p->st;
    if (!st->ctname && !(st->ctname = imdb_alloc_array(IMDB_MAX_COLS, sizeof *st->ctname, p->e))) return p->e->code;
    memcpy(st->ctname[at], tname, IMDB_MAX_IDENT + 1);
    return IMDB_OK;
}

/* F3g: CREATE TYPE name AS ENUM ('label', ...) (TYPE eaten): the labels as string literals in vals (rowlen of them; the
 * executor reads each, its bytes, its UTF-8 and its uniqueness); another kind of type refused by name */
static int parse_create_type(parser *p, sql_stmt *st)
{
    st->kind = ST_CREATE_TYPE;
    if (ident(p, st->table) || expect_kw(p, "as")) return p->e->code;
    if (!kw(p, "enum"))
        return imdb_fail(p->e, IMDB_ERR_UNSUPPORTED, "CREATE TYPE ... AS ENUM alone (composite, range and base types are not in imagedb)");
    if (expect(p, TK_LP, "(")) return p->e->code;
    if (!(st->vals = imdb_alloc_array(IMDB_MAX_ENUM_LABELS, sizeof *st->vals, p->e))) return p->e->code;
    st->nrows = 1;
    if (tok(p, TK_RP)) return IMDB_OK; /* no label, as PostgreSQL takes */
    do {
        if (st->rowlen >= IMDB_MAX_ENUM_LABELS)
            return imdb_fail(p->e, IMDB_ERR_LIMIT, "an ENUM type holds at most %u labels", IMDB_MAX_ENUM_LABELS);
        const sql_tok *t = &p->t[p->i];
        if (t->kind != TK_STR) return fail_at(p, "a label (a string)");
        st->vals[st->rowlen++] = (sql_lit){.kind = LIT_STR, .off = t->off, .len = t->len};
        p->i++;
    } while (tok(p, TK_COMMA));
    return expect(p, TK_RP, ")");
}

/* F3g: ALTER TYPE name ADD VALUE [IF NOT EXISTS] 'label' (TYPE eaten): appended; BEFORE and AFTER refused by name (an
 * ordinal is a value's identity and order: deferred.md D27), as RENAME and the rest are */
static int parse_alter_type(parser *p, sql_stmt *st)
{
    st->kind = ST_ALTER_TYPE;
    if (ident(p, st->table)) return p->e->code;
    if (tok_is_kw(p, p->i, "rename") || tok_is_kw(p, p->i, "owner") || tok_is_kw(p, p->i, "set"))
        return imdb_fail(p->e, IMDB_ERR_UNSUPPORTED, "ALTER TYPE ... ADD VALUE alone (RENAME VALUE and RENAME TO are not in imagedb yet)");
    if (!kw(p, "add") || !kw(p, "value")) return fail_at(p, "ADD VALUE");
    if (tok_is_kw(p, p->i, "if") && tok_is_kw(p, p->i + 1, "not") && tok_is_kw(p, p->i + 2, "exists")) {
        p->i += 3;
        st->if_not_exists = true;
    }
    const sql_tok *t = &p->t[p->i];
    if (t->kind != TK_STR) return fail_at(p, "a label (a string)");
    st->alter_def = (sql_lit){.kind = LIT_STR, .off = t->off, .len = t->len};
    p->i++;
    if (tok_is_kw(p, p->i, "before") || tok_is_kw(p, p->i, "after"))
        return imdb_fail(p->e, IMDB_ERR_UNSUPPORTED, "ADD VALUE ... BEFORE or AFTER: a label is appended (an ordinal is a value's "
                                                    "identity and its order: placing one would rewrite every row of the type)");
    return IMDB_OK;
}

int imdb_sql_parse(const char *s, size_t n, sql_stmt *st, imdb_err *e)
{
    memset(st, 0, sizeof *st);
    sql_tok *t;
    uint32_t nt;
    if (imdb_sql_lex(s, n, &t, &nt, e)) return e->code;
    parser p = {s, t, nt, 0, e, st, 0, 0, 0, false, false, false};
    int rc = IMDB_OK;
    if (nt == 0 || (nt == 1 && t[0].kind == TK_SEMI)) {
        st->kind = ST_EMPTY;
        imdb_free(t);
        return IMDB_OK;
    }
    bool explain = kw(&p, "explain"); /* P1 Q1: the plan of what follows, which is not run */
    if (kw(&p, "create")) {
        if (tok_is_kw(&p, p.i, "or") && tok_is_kw(&p, p.i + 1, "replace")) /* P2 S7 */
            rc = imdb_fail(e, IMDB_ERR_UNSUPPORTED, "CREATE OR REPLACE: drop the view and create it again");
        else if (kw(&p, "view")) rc = parse_create_view(&p, st);
        else if (kw(&p, "type")) rc = parse_create_type(&p, st); /* F3g */
        else if (kw(&p, "sequence")) { /* F2a-2 */
            st->kind = ST_CREATE_SEQUENCE;
            memset(&st->seqopt, 0, sizeof st->seqopt);
            if (!(rc = ident(&p, st->table))) rc = seq_options(&p, &st->seqopt, true);
        }
        else {
            bool unique = kw(&p, "unique");
            if (unique) rc = expect_kw(&p, "index");
            if (!rc) rc = unique || kw(&p, "index") ? parse_create_index(&p, st, unique) : parse_create(&p, st);
        }
    }
    else if (kw(&p, "drop")) {
        if (kw(&p, "type")) { /* F3g: RESTRICT, the default and only one */
            st->kind = ST_DROP_TYPE;
            if (tok_is_kw(&p, p.i, "if") && tok_is_kw(&p, p.i + 1, "exists")) {
                p.i += 2;
                st->if_exists = true;
            }
            if (!(rc = ident(&p, st->table))) {
                if (kw(&p, "cascade")) rc = imdb_fail(e, IMDB_ERR_UNSUPPORTED, "DROP TYPE ... CASCADE: drop the columns and views that use it first");
                else kw(&p, "restrict");
            }
        } else
        if (kw(&p, "sequence")) { /* F2a-2: RESTRICT, the default and only one */
            st->kind = ST_DROP_SEQUENCE;
            if (!(rc = ident(&p, st->table))) {
                if (kw(&p, "cascade")) rc = imdb_fail(e, IMDB_ERR_UNSUPPORTED, "DROP SEQUENCE ... CASCADE: drop the DEFAULT first");
                else kw(&p, "restrict");
            }
        } else
        if (kw(&p, "view")) { /* P2 S7 */
            st->kind = ST_DROP_VIEW;
            rc = ident(&p, st->table);
        } else if (kw(&p, "table")) { /* DROP TABLE t [RETENTION n UNIT] (1f): its history kept, for that long */
            st->kind = ST_DROP_TABLE;
            if (!(rc = ident(&p, st->table)) && kw(&p, "retention")) {
                st->has_retention = true;
                rc = parse_retention(&p, &st->retention_us);
            }
        } else {
            st->kind = ST_DROP_INDEX;
            if (!(rc = expect_kw(&p, "index"))) rc = ident(&p, st->index_name);
        }
    }
    else if (kw(&p, "alter")) { /* ALTER TABLE t SET RETENTION ... | ADD ... | RENAME ... (F1) */
        if (kw(&p, "type")) rc = parse_alter_type(&p, st); /* F3g */
        else if (!(rc = expect_kw(&p, "table")) && !(rc = ident(&p, st->table))) rc = parse_alter(&p, st);
    }
    else if (kw(&p, "insert")) rc = parse_insert(&p, st);
    else if (kw(&p, "prepare")) rc = parse_prepare(&p, st); /* P2 S9 */
    else if (kw(&p, "copy")) rc = parse_copy(&p, st); /* P2 S10 */
    else if (kw(&p, "execute")) rc = parse_execute(&p, st);
    else if (kw(&p, "deallocate")) {
        st->kind = ST_DEALLOCATE;
        kw(&p, "prepare");
        if (kw(&p, "all")) st->prep_all = true;
        else rc = ident(&p, st->prep_name);
    }
    else if (kw(&p, "update")) {
        st->kind = ST_UPDATE;
        if (!(rc = ident(&p, st->table)) && !(rc = expect_kw(&p, "set"))) {
            do {
                if (st->nset >= IMDB_MAX_COLS) {
                    rc = imdb_fail(e, IMDB_ERR_LIMIT, "too many assignments");
                    break;
                }
                if ((rc = ident(&p, st->set_cols[st->nset])) || (rc = expect(&p, TK_EQ, "=")) ||
                    (rc = value(&p, &st->set_vals[st->nset])))
                    break;
                st->nset++;
            } while (tok(&p, TK_COMMA));
            if (!rc && tok_is_kw(&p, p.i, "from")) rc = join_source(&p, st, "UPDATE ... FROM"); /* P2 S8 */
            else if (!rc && kw(&p, "where")) rc = preds(&p, st);
            if (!rc) rc = returning(&p, st); /* P2 S8 */
        }
    } else if (kw(&p, "delete")) {
        st->kind = ST_DELETE;
        if (!(rc = expect_kw(&p, "from")) && !(rc = ident(&p, st->table))) {
            if (tok_is_kw(&p, p.i, "using")) rc = join_source(&p, st, "DELETE ... USING"); /* P2 S8 */
            else if (kw(&p, "where")) rc = preds(&p, st);
        }
        if (!rc) rc = returning(&p, st); /* P2 S8 */
    } else if (kw(&p, "with")) { /* P2 S4: WITH name AS (SELECT ...) [, ...] SELECT ...; P2 S5: RECURSIVE, (c1, ...) */
        if (!(rc = parse_with_list(&p, st))) /* P2 S5: a set operation too; P2 S8: WITH ... INSERT, its query reading them */
            rc = kw(&p, "insert") ? parse_insert(&p, st) : parse_query(&p, st);
    } else if (tok_is_kw(&p, p.i, "select") || p.t[p.i].kind == TK_LP) {
        rc = parse_query(&p, st); /* P2 S5: a set operation too, or a parenthesized query */
    }
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
        else if (kw(&p, "timezone")) st->kind = ST_SHOW_TIMEZONE; /* P2 */
        else if (tok_is_kw(&p, p.i, "time") && tok_is_kw(&p, p.i + 1, "zone")) {
            p.i += 2;
            st->kind = ST_SHOW_TIMEZONE;
        }
        else if (kw(&p, "prepared")) st->kind = ST_SHOW_PREPARED; /* P2 S9 */
        else if (kw(&p, "views")) st->kind = ST_SHOW_VIEWS; /* P2 S7 */
        else if (kw(&p, "indexes")) st->kind = ST_SHOW_INDEXES;
        else if (kw(&p, "retention")) st->kind = ST_SHOW_RETENTION;
        else if (kw(&p, "lake")) st->kind = ST_SHOW_LAKE;
        else if (kw(&p, "identity")) st->kind = ST_SHOW_IDENTITY;
        else if (kw(&p, "replicas")) st->kind = ST_SHOW_REPLICAS;
        else if (kw(&p, "replication")) st->kind = ST_SHOW_REPLICATION;
        else if (kw(&p, "memory")) st->kind = ST_SHOW_MEMORY;
        else if (kw(&p, "stats")) st->kind = ST_SHOW_STATS;
        else if (kw(&p, "transactions")) st->kind = ST_SHOW_TRANSACTIONS;
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
            if (!(rc = ident(&p, st->table)) && tok(&p, TK_LP)) { /* F4: a key of several columns, (v1, v2, ...) */
                do {
                    if (st->nkeys >= IMDB_MAX_KEY_COLS) {
                        rc = imdb_fail(p.e, IMDB_ERR_LIMIT, "a key of more than %u values", IMDB_MAX_KEY_COLS);
                        break;
                    }
                    rc = literal(&p, &st->keys[st->nkeys++]);
                } while (!rc && tok(&p, TK_COMMA));
                if (!rc) rc = expect(&p, TK_RP, ")");
            } else if (!rc && !(rc = literal(&p, &st->keys[0]))) {
                st->nkeys = 1;
            }
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
            rc = fail_at(&p, "TABLES, VIEWS, DIGEST, HISTORY, LOG, LAKE, IDENTITY or REPLICAS after SHOW");
        }
    } else if (kw(&p, "set")) {
        st->kind = ST_SET;
        if (kw(&p, "transaction")) {
            st->kind = ST_SET_TXN;
            rc = isolation(&p, st);
        } else if (tok_is_kw(&p, p.i, "time") && tok_is_kw(&p, p.i + 1, "zone")) { /* P2: SET TIME ZONE x */
            p.i += 2;
            memcpy(st->set_name, "timezone", 9);
            rc = set_zone_value(&p, st);
        } else if (!(rc = ident(&p, st->set_name))) {
            if (!tok(&p, TK_EQ) && !kw(&p, "to")) rc = fail_at(&p, "= or TO");
            else if (!strcmp(st->set_name, "timezone")) rc = set_zone_value(&p, st); /* P2: SET timezone = x */
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
    if (!rc) st->seq_write = p.seqcall; /* F2a-2: nextval or setval anywhere in it, a nested SELECT's too */
    if (!rc) st->rand_call = p.randcall; /* F3d */
    if (!rc && explain && p.seqcall) /* F2a-2: EXPLAIN runs nothing, and would hand out no value */
        rc = imdb_fail(e, IMDB_ERR_UNSUPPORTED, "EXPLAIN of a statement calling nextval or setval");
    if (!rc && explain) { /* P1 Q1: its own kind, so no test of the inner kind (a write's autocommit, FOR UPDATE's locks) */
        if (st->kind != ST_SELECT && st->kind != ST_UPDATE && st->kind != ST_DELETE)
            rc = imdb_fail(e, IMDB_ERR_INVALID, "EXPLAIN explains SELECT, UPDATE and DELETE");
        st->explained = st->kind;
        st->kind = ST_EXPLAIN;
    }
    imdb_free(t);
    if (rc) imdb_sql_stmt_free(st);
    return rc;
}

/* P1 M2: a statement's shape for the event log: its tokens joined by one space, every number, string and boolean literal a ?,
 * comments never copied (the lexer skips them: they may hold anything), cut on a token boundary with " ..." to fit cap
 * (NUL included). No row value is ever in it. A text the lexer refuses is "(not lexed)". */
size_t imdb_sql_shape(const char *s, size_t n, char *out, size_t cap)
{
    if (cap < 5) { /* not even " ..." fits */
        if (cap) out[0] = 0;
        return 0;
    }
    out[0] = 0;
    sql_tok *t = NULL;
    uint32_t nt = 0;
    imdb_err e = {0};
    if (imdb_sql_lex(s, n, &t, &nt, &e)) {
        snprintf(out, cap, "(not lexed)");
        return strlen(out);
    }
    size_t len = 0;
    for (uint32_t i = 0; i < nt && t[i].kind != TK_EOF; i++) {
        bool lit = t[i].kind == TK_INT || t[i].kind == TK_DEC || t[i].kind == TK_STR || t[i].kind == TK_FLOAT;
        if (t[i].kind == TK_IDENT && ((t[i].len == 4 && !strncasecmp(s + t[i].off, "true", 4)) ||
                                      (t[i].len == 5 && !strncasecmp(s + t[i].off, "false", 5))))
            lit = true; /* a boolean is a value too (an INSERT's); NULL names none */
        const char *p = lit ? "?" : s + t[i].off;
        size_t k = lit ? 1 : t[i].len;
        if (len + (len ? 1 : 0) + k + 5 > cap) { /* room for " ..." and the NUL */
            memcpy(out + len, " ...", 4);
            len += 4;
            break;
        }
        if (len) out[len++] = ' ';
        memcpy(out + len, p, k);
        len += k;
    }
    out[len] = 0;
    imdb_free(t);
    return len;
}
