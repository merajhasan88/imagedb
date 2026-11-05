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
} parser;

static int parse_nested(parser *p, sql_stmt *outer, const char *name); /* P2 S4 */

static const char *const kReserved[] = {
    "select", "from", "where", "insert", "into", "values", "update", "set", "delete", "create", "table",
    "and", "or", "not", "between", "as", "of", "group", "by", "order", "limit", "true", "false", "null",
    "primary", "key", "subject", "erase", "count", "sum", "min", "max", "begin", "commit", "rollback", "is",
    "case", "when", "then", "else", "end", "cast", "in", "like", "escape", /* P2 S1 */
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
static int col_type(parser *p, imdb_column *c);

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
             {"lower", FN_LOWER},       {"upper", FN_UPPER},       {"replace", FN_REPLACE}};
    for (size_t i = 0; i < sizeof k / sizeof *k; i++)
        if (tok_is_kw(p, at, k[i].name)) return k[i].fn;
    return 0;
}

/* name(args): POSITION(a IN b) in the standard's form, the others with commas; the binder checks the arguments */
static int fn_call(parser *p, uint8_t fn, uint16_t *out, unsigned depth)
{
    p->i += 2; /* the name and its ( */
    uint16_t args;
    uint32_t n;
    if (fn == FN_POSITION) {
        uint16_t el[2];
        if (aexpr(p, &el[0], depth + 1) || expect_kw(p, "in") || aexpr(p, &el[1], depth + 1) || expect(p, TK_RP, ")") ||
            list_build(p, el, 2, &args))
            return p->e->code;
        n = 2;
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
    if (expect(p, TK_LP, "(") || bexpr(p, &a, depth + 1) || expect_kw(p, "as") || col_type(p, &c) ||
        expect(p, TK_RP, ")") || ex_new(p, EX_CAST, a, 0, out))
        return p->e->code;
    sql_expr *x = &p->st->ex[*out];
    x->ctype = c.type;
    x->cscale = c.scale;
    x->cprec = c.precision;
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
    if (p->t[p->i].kind == TK_IDENT && p->t[p->i + 1].kind == TK_LP) { /* an identifier is not the end: i + 1 exists */
        uint8_t fn = fn_named(p, p->i);
        if (fn) return fn_call(p, fn, out, depth);
    }
    const sql_tok *t = &p->t[p->i];
    if (t->kind == TK_IDENT && !tok_is_kw(p, p->i, "true") && !tok_is_kw(p, p->i, "false") && !tok_is_kw(p, p->i, "null") &&
        !(tok_is_kw(p, p->i, "timestamp") && p->t[p->i + 1].kind == TK_STR)) {
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

static int term(parser *p, uint16_t *out, unsigned depth)
{
    if (unary(p, out, depth)) return p->e->code;
    for (;;) {
        uint8_t k = p->t[p->i].kind;
        uint8_t op = k == TK_STAR ? EX_MUL : k == TK_SLASH ? EX_DIV : k == TK_PERCENT ? EX_MOD : 0;
        if (!op) return IMDB_OK;
        p->i++;
        uint16_t r;
        if (unary(p, &r, depth) || ex_new(p, op, *out, r, out)) return p->e->code;
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
               (tok_is_kw(p, p->i, "timestamp") && k1 == TK_STR);
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
            if (value(p, &st->vals[at])) return p->e->code;
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

/* P2 S4: a nested SELECT, parsed from the same tokens into its own statement (its own expression nodes), named: the
 * row set its outer statement reads as a table of that name; nesting bounded */
static int parse_select(parser *p, sql_stmt *st);
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
    int rc = expect_kw(p, "select") ? p->e->code : parse_select(p, in);
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

static int parse_select(parser *p, sql_stmt *st)
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
            if (bexpr(p, &k, 0)) return p->e->code;
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
        static const char *const cl[] = {"where", "group", "having", "order", "limit", "offset", "for"};
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
    if (kw(p, "order")) { /* 1d: key [ASC | DESC] [NULLS FIRST | LAST], ...; a bare integer is an item's position */
        if (expect_kw(p, "by")) return p->e->code;
        do {
            if (st->norder >= IMDB_MAX_ORDER)
                return imdb_fail(p->e, IMDB_ERR_LIMIT, "ORDER BY has more than %u keys", IMDB_MAX_ORDER);
            uint8_t o = st->norder;
            const sql_tok *t = &p->t[p->i];
            uint8_t nk = t->kind == TK_EOF ? TK_EOF : p->t[p->i + 1].kind;
            if (t->kind == TK_INT && (nk == TK_COMMA || nk == TK_EOF || nk == TK_SEMI || nk == TK_IDENT)) {
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
        st->for_update = true;
        bool agg = st->has_group || st->having;
        for (uint16_t i = 0; i < st->nitems; i++) agg = agg || st->items[i].agg != AGG_NONE || imdb_sql_has_agg(st, st->items[i].expr);
        if (agg || st->has_asof || st->has_join)
            return imdb_fail(p->e, IMDB_ERR_INVALID, "FOR UPDATE locks rows: not with aggregates, GROUP BY, AS OF or a join");
    }
    return IMDB_OK;
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
    imdb_free(st->vals);
    st->vals = NULL;
    imdb_free(st->ex);
    st->ex = NULL;
    st->nex = st->capex = 0;
}

int imdb_sql_parse(const char *s, size_t n, sql_stmt *st, imdb_err *e)
{
    memset(st, 0, sizeof *st);
    sql_tok *t;
    uint32_t nt;
    if (imdb_sql_lex(s, n, &t, &nt, e)) return e->code;
    parser p = {s, t, nt, 0, e, st, 0};
    int rc = IMDB_OK;
    if (nt == 0 || (nt == 1 && t[0].kind == TK_SEMI)) {
        st->kind = ST_EMPTY;
        imdb_free(t);
        return IMDB_OK;
    }
    bool explain = kw(&p, "explain"); /* P1 Q1: the plan of what follows, which is not run */
    if (kw(&p, "create")) {
        bool unique = kw(&p, "unique");
        if (unique) rc = expect_kw(&p, "index");
        if (!rc) rc = unique || kw(&p, "index") ? parse_create_index(&p, st, unique) : parse_create(&p, st);
    }
    else if (kw(&p, "drop")) {
        if (kw(&p, "table")) { /* DROP TABLE t [RETENTION n UNIT] (1f): its history kept, for that long */
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
                    (rc = value(&p, &st->set_vals[st->nset])))
                    break;
                st->nset++;
            } while (tok(&p, TK_COMMA));
            if (!rc && kw(&p, "where")) rc = preds(&p, st);
        }
    } else if (kw(&p, "delete")) {
        st->kind = ST_DELETE;
        if (!(rc = expect_kw(&p, "from")) && !(rc = ident(&p, st->table)) && kw(&p, "where")) rc = preds(&p, st);
    } else if (kw(&p, "with")) { /* P2 S4: WITH name AS (SELECT ...) [, ...] SELECT ... */
        do {
            char name[IMDB_MAX_IDENT + 1];
            if ((rc = ident(&p, name)) || (rc = expect_kw(&p, "as")) || (rc = expect(&p, TK_LP, "(")) ||
                (rc = parse_nested(&p, st, name)) || (rc = expect(&p, TK_RP, ")")))
                break;
        } while (tok(&p, TK_COMMA));
        if (!rc && !(rc = expect_kw(&p, "select"))) rc = parse_select(&p, st);
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
