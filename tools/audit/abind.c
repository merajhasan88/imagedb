/* abind.c - the auditor's view binder (P2 S7b, 2026-11-07).
 *
 * op 20 logs a view's query text with the columns (types, scales) and the dependencies (the tables and views the text
 * names, by kind and id) the engine derived from it; the engine's replay and VERIFY re-bind the text with the engine's
 * parser. This file does it with the auditor's own, so a log whose view text yields other columns or dependencies than
 * it says (audit_reject's VD) is refused here too. It parses the text in the engine's grammar (SELECT, set operations,
 * WITH [RECURSIVE], derived tables, a join of two, expression subqueries, functions, CASE, CAST, aggregates, window
 * functions), resolves its names against the catalog at the view's commit, types each result column and collects the
 * dependencies. Nothing is evaluated.
 *
 * STRICT ONLY WHERE A RULE DECIDES A COLUMN'S TYPE OR SCALE, OR THE DEPENDENCY LIST; PERMISSIVE EVERYWHERE ELSE: a
 * condition's types (WHERE, ON, HAVING, CASE's WHEN, FILTER, a comparison's operands), GROUP BY's and DISTINCT's rules,
 * ORDER BY, LIMIT and OFFSET, a window's frame and keys, WHERE's count of conditions. A false rejection fails every check
 * that audits a database the engine wrote; a false acceptance of a text the engine refuses for a reason that changes
 * none of those is a smaller gap (the engine's own replay still refuses it). Every rule added here keeps to that. Two
 * modes follow from it: TYPED (the view's query, its arms, its derived tables and WITH row sets, a value subquery in a
 * typed item) computes columns; DEPS (everything else) only resolves the names a FROM gives, for the dependencies.
 *
 * Independent: written from design.md §5 (Expressions, Functions, Grouping, Joins, Row sets and subqueries, Correlated
 * subqueries, Set operations, Window functions, Views), the engine's grammar its reference; it shares no code with src/,
 * and its constants are the log's bytes. Bounded as the engine's parser is, so a hostile text costs what its length
 * allows: a view's text at most 64 KiB, 2^18 tokens, an expression 64 high (the recursion with it), 16,384 nodes a
 * statement, 8 nested SELECTs a statement, 4 deep, 64 arms, queries parenthesized 32 deep.
 */
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "abind.h"

enum { T_INT64 = 1, T_DECIMAL = 2, T_TEXT = 3, T_BOOL = 4, T_TIMESTAMP = 5, T_FLOAT64 = 6, T_TIMESTAMPTZ = 7 };
enum { DEP_TABLE = 1, DEP_VIEW = 2 };

#define MAX_IDENT 63
#define MAX_COLS 64
#define MAX_TOKENS (1u << 18)
#define MAX_NUMERIC 128
#define MAX_TEXT 65535
#define MAX_VIEW_TEXT 65536
#define MAX_NODES 16384
#define MAX_DEPTH 64
#define MAX_SUBS 8
#define MAX_SUB_DEPTH 4
#define MAX_ARMS 64
#define MAX_PARENS 32
#define MAX_WINDOWS 8
#define MAX_WIN_KEYS 8
#define MAX_GROUP 8
#define MAX_USING 8
#define MAX_ORDER 16
#define MAX_SCALE 38
#define MAX_PARAMS 256
#define MAX_ARGS 255
#define MAX_CTES 512 /* visible WITH row sets: a statement's 8 at each of its levels */

/* ---- tokens ----------------------------------------------------------------------------------------------------- */

enum { K_EOF, K_ID, K_INT, K_DEC, K_FLT, K_STR, K_PARAM, K_LP, K_RP, K_COMMA, K_SEMI, K_STAR, K_EQ, K_NE, K_LT, K_LE,
       K_GT, K_GE, K_PLUS, K_MINUS, K_SLASH, K_PCT, K_DOT, K_CONCAT };

typedef struct tk {
    uint8_t k;
    uint32_t off, len; /* a string's: its content, inside the quotes */
} tk;

/* ---- the tree ---------------------------------------------------------------------------------------------------- */

enum { L_INT = 1, L_DEC, L_FLT, L_STR, L_PARAM, L_BOOL, L_TS, L_NULL, L_TSTZ }; /* L_TSTZ: P2 */
enum { X_LIT = 1, X_COL, X_NEG, X_ADD, X_SUB, X_MUL, X_DIV, X_MOD, X_CMP, X_AND, X_OR, X_NOT, X_FN, X_CASE, X_WHEN, X_CAST,
       X_AGG, X_WIN, X_SUBQ, X_LIST };
enum { C_EQ = 1, C_NE, C_LT, C_LE, C_GT, C_GE, C_BETWEEN, C_ISNULL, C_NOTNULL, C_IN, C_NOTIN, C_LIKE, C_NOTLIKE };
enum { F_ABS = 1, F_SIGN, F_ROUND, F_CEIL, F_FLOOR, F_MOD, F_LENGTH, F_SUBSTR, F_TRIM, F_LTRIM, F_RTRIM, F_POSITION,
       F_COALESCE, F_NULLIF, F_LOWER, F_UPPER, F_REPLACE, F_CONCAT, F_DATE_TRUNC, F_TIMEZONE }; /* the last two: P2 */
enum { A_COUNT = 1, A_COUNT_STAR, A_SUM, A_MIN, A_MAX, A_AVG }; /* the engine's names: count, count, sum, min, max, avg */
enum { W_ROW_NUMBER = 1, W_RANK, W_DENSE_RANK, W_NTILE, W_LAG, W_LEAD, W_FIRST, W_LAST, W_AGG };
enum { S_VALUE = 0, S_EXISTS = 1, S_IN = 2 };
enum { SUB_EXPR = 0, SUB_DERIVED = 1, SUB_CTE = 2 };
enum { J_NONE = 0, J_INNER, J_LEFT, J_RIGHT, J_FULL, J_CROSS };

typedef struct xn {
    uint8_t op, h, lit, cmp, fn, agg, wf, subk, ctype, cscale, nargs, sub, win;
    bool neg, dist;
    uint16_t l, r, x3;
    uint32_t off, len;   /* a literal's token; a column's name token */
    uint32_t qoff, qlen; /* a column's qualifier token (qlen 0: none) */
} xn;

typedef struct aitem {
    uint16_t ex;
    uint8_t shape;     /* 0 a tree, 1 a bare column, 2 an aggregate of a bare column (or COUNT(*)), as the engine names
                        * its result's columns */
    uint32_t off, len; /* the item's text (a string's quotes in it) */
    char alias[64];
} aitem;

typedef struct aq aq;
struct aq {
    aq **arm; /* a set operation's arms (narm > 0), every chain folded left; else a SELECT's core */
    uint8_t narm, caparm;
    bool star, distinct, no_from, for_update, has_asof, has_limit, has_offset;
    aitem *items;
    uint16_t nitems, capitems;
    uint8_t nfrom, join, nusing;
    char fname[2][64], falias[2][64]; /* a FROM item's name (a derived table's own) and its alias */
    int8_t fsub[2];                   /* a derived table's sub, else -1 */
    char using_col[MAX_USING][64];
    uint16_t on, where, having;
    uint8_t ngroup, norder, nwin;
    uint16_t group[MAX_GROUP], order[MAX_ORDER];
    struct {
        uint8_t npart, nord;
        uint16_t part[MAX_WIN_KEYS], ord[MAX_WIN_KEYS];
    } win[MAX_WINDOWS];
    aq *sub[MAX_SUBS]; /* nested SELECTs: WITH's (first), derived tables, expressions' */
    uint8_t nsub;
    char sub_name[MAX_SUBS][64];
    uint8_t sub_kind[MAX_SUBS], sub_subk[MAX_SUBS], cte_ncols[MAX_SUBS];
    bool sub_rec[MAX_SUBS];
    char (*cte_cols[MAX_SUBS])[64];
    xn *ex; /* node 0 is no node */
    uint16_t nex, capex;
};

typedef struct ty {
    uint8_t t, s; /* t 0: an untyped NULL */
} ty;

typedef struct rel {
    char name[64]; /* what a qualifier names: the alias, else the FROM name */
    uint16_t ncols;
    ab_col *cols; /* owned */
} rel;

typedef struct scope {
    const aq *q;
    rel r[2];
    uint8_t nr;
    const struct scope *up; /* the statement around (a correlated reference) */
} scope;

typedef struct cte {
    char name[64];
    uint16_t ncols;
    ab_col *cols; /* owned */
} cte;

typedef struct ab {
    const char *s;
    size_t n;
    tk *t;
    uint32_t nt, i;
    char *err;
    size_t errn;
    bool failed;
    aq *q; /* the statement whose nodes are being made */
    uint8_t depth, parens;
    uint16_t narms;
    ab_lookup_fn lookup;
    void *arg;
    uint16_t ndeps;
    uint8_t dkind[AB_MAX_DEPS];
    uint32_t did[AB_MAX_DEPS];
    cte *ctes; /* visible WITH row sets, the latest last */
    uint32_t nctes;
} ab;

enum { M_DEPS = 0, M_TYPED = 1 };

static int fail(ab *b, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
static int fail(ab *b, const char *fmt, ...)
{
    if (!b->failed && b->errn) {
        va_list ap;
        va_start(ap, fmt);
        vsnprintf(b->err, b->errn, fmt, ap);
        va_end(ap);
    }
    b->failed = true;
    return -1;
}

static int oom(ab *b) { return fail(b, "out of memory"); }

/* ---- the lexer: the engine's tokens (design.md §5 and its grammar: -- comments, '' in a string, a number's point and
 * exponent; nothing else) ----------------------------------------------------------------------------------------- */

static bool alpha(char c) { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_'; }
static bool digit(char c) { return c >= '0' && c <= '9'; }

static int lex(ab *b)
{
    const char *s = b->s;
    size_t n = b->n, i = 0;
    uint32_t cap = 64, k = 0;
    tk *t = malloc(cap * sizeof *t);
    if (!t) return oom(b);
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
            if (cap >= MAX_TOKENS) {
                free(t);
                return fail(b, "more than %u tokens", MAX_TOKENS);
            }
            tk *nt = realloc(t, (size_t)cap * 2 * sizeof *t);
            if (!nt) {
                free(t);
                return oom(b);
            }
            t = nt;
            cap *= 2;
        }
        tk *x = &t[k];
        x->off = (uint32_t)i;
        if (alpha(c)) {
            size_t j = i;
            while (j < n && (alpha(s[j]) || digit(s[j]))) j++;
            if (j - i > MAX_IDENT) {
                free(t);
                return fail(b, "an identifier at offset %zu longer than %u bytes", i, MAX_IDENT);
            }
            x->k = K_ID;
            x->len = (uint32_t)(j - i);
            i = j;
        } else if (digit(c)) {
            size_t j = i;
            while (j < n && digit(s[j])) j++;
            x->k = K_INT;
            if (j < n && s[j] == '.') {
                size_t f = ++j;
                while (j < n && digit(s[j])) j++;
                if (j == f) {
                    free(t);
                    return fail(b, "a malformed number at offset %zu", i);
                }
                x->k = K_DEC;
            }
            if (j < n && (s[j] == 'e' || s[j] == 'E')) {
                size_t e = j + 1;
                if (e < n && (s[e] == '+' || s[e] == '-')) e++;
                size_t e0 = e;
                while (e < n && digit(s[e])) e++;
                if (e == e0) {
                    free(t);
                    return fail(b, "a malformed number at offset %zu", i);
                }
                j = e;
                x->k = K_FLT;
            }
            if ((j < n && (alpha(s[j]) || s[j] == '.')) || j - i > MAX_NUMERIC) {
                free(t);
                return fail(b, "a malformed or long number at offset %zu", i);
            }
            x->len = (uint32_t)(j - i);
            i = j;
        } else if (c == '\'') {
            size_t j = i + 1, content = 0;
            for (;;) {
                if (j >= n) {
                    free(t);
                    return fail(b, "an unterminated string at offset %zu", i);
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
            if (content > MAX_TEXT) {
                free(t);
                return fail(b, "a string at offset %zu longer than %u bytes", i, MAX_TEXT);
            }
            x->k = K_STR;
            x->off = (uint32_t)(i + 1);
            x->len = (uint32_t)(j - i - 1);
            i = j + 1;
        } else if (c == '$') {
            size_t j = i + 1;
            while (j < n && digit(s[j])) j++;
            if (j == i + 1 || j - i > 4) {
                free(t);
                return fail(b, "a malformed parameter at offset %zu", i);
            }
            x->k = K_PARAM;
            x->len = (uint32_t)(j - i);
            i = j;
        } else {
            x->len = 1;
            switch (c) {
            case '(': x->k = K_LP; break;
            case ')': x->k = K_RP; break;
            case ',': x->k = K_COMMA; break;
            case ';': x->k = K_SEMI; break;
            case '*': x->k = K_STAR; break;
            case '=': x->k = K_EQ; break;
            case '-': x->k = K_MINUS; break;
            case '+': x->k = K_PLUS; break;
            case '/': x->k = K_SLASH; break;
            case '%': x->k = K_PCT; break;
            case '.': x->k = K_DOT; break;
            case '<':
                if (i + 1 < n && s[i + 1] == '=') x->k = K_LE, x->len = 2;
                else if (i + 1 < n && s[i + 1] == '>') x->k = K_NE, x->len = 2;
                else x->k = K_LT;
                break;
            case '>':
                if (i + 1 < n && s[i + 1] == '=') x->k = K_GE, x->len = 2;
                else x->k = K_GT;
                break;
            case '|':
                if (i + 1 < n && s[i + 1] == '|') {
                    x->k = K_CONCAT;
                    x->len = 2;
                    break;
                }
                free(t);
                return fail(b, "an unexpected character at offset %zu", i);
            case '!':
                if (i + 1 < n && s[i + 1] == '=') {
                    x->k = K_NE;
                    x->len = 2;
                    break;
                }
                free(t);
                return fail(b, "an unexpected character at offset %zu", i);
            default:
                free(t);
                return fail(b, "an unexpected character at offset %zu", i);
            }
            i += x->len;
        }
        k++;
    }
    t[k].k = K_EOF;
    t[k].off = (uint32_t)n;
    t[k].len = 0;
    b->t = t;
    b->nt = k;
    return 0;
}

/* ---- the parser ------------------------------------------------------------------------------------------------- */

static const char *const RESERVED[] = {
    "select", "from", "where", "insert", "into", "values", "update", "set", "delete", "create", "table", "and", "or",
    "not", "between", "as", "of", "group", "by", "order", "limit", "true", "false", "null", "primary", "key", "subject",
    "erase", "count", "sum", "min", "max", "begin", "commit", "rollback", "is", "case", "when", "then", "else", "end",
    "cast", "in", "like", "escape", "union", "intersect", "except", "over", "returning", "with", "on"};

static uint8_t kind_at(const ab *b, uint32_t at) { return at <= b->nt ? b->t[at].k : K_EOF; }

static bool kwat(const ab *b, uint32_t at, const char *k)
{
    if (at > b->nt || b->t[at].k != K_ID) return false;
    const tk *t = &b->t[at];
    size_t kl = strlen(k);
    if (t->len != kl) return false;
    for (size_t j = 0; j < kl; j++) {
        char c = b->s[t->off + j];
        if (c >= 'A' && c <= 'Z') c = (char)(c + 32);
        if (c != k[j]) return false;
    }
    return true;
}

static bool kw(ab *b, const char *k)
{
    if (!kwat(b, b->i, k)) return false;
    b->i++;
    return true;
}

static bool tok(ab *b, uint8_t k)
{
    if (b->t[b->i].k != k) return false;
    b->i++;
    return true;
}

static int expect(ab *b, uint8_t k, const char *what)
{
    return tok(b, k) ? 0 : fail(b, "expected %s at offset %u", what, b->t[b->i].off);
}

static int expect_kw(ab *b, const char *k) { return kw(b, k) ? 0 : fail(b, "expected %s at offset %u", k, b->t[b->i].off); }

static bool reserved(const ab *b, uint32_t at)
{
    for (size_t k = 0; k < sizeof RESERVED / sizeof *RESERVED; k++)
        if (kwat(b, at, RESERVED[k])) return true;
    return false;
}

static void fold(const char *s, uint32_t len, char out[64])
{
    for (uint32_t j = 0; j < len && j < MAX_IDENT; j++) out[j] = s[j] >= 'A' && s[j] <= 'Z' ? (char)(s[j] + 32) : s[j];
    out[len < MAX_IDENT ? len : MAX_IDENT] = 0;
}

static int ident(ab *b, char out[64])
{
    const tk *t = &b->t[b->i];
    if (t->k != K_ID || reserved(b, b->i)) return fail(b, "expected an identifier at offset %u", t->off);
    fold(b->s + t->off, t->len, out);
    b->i++;
    return 0;
}

#define X(k) (&b->q->ex[(k)])

static int deep(ab *b) { return fail(b, "an expression nested deeper than %u", MAX_DEPTH); }

static int nnew(ab *b, uint8_t op, uint16_t l, uint16_t r, uint16_t *out)
{
    aq *q = b->q;
    if (q->nex + 1u >= MAX_NODES) return fail(b, "expressions of more than %u terms in one statement", MAX_NODES - 1);
    if (q->nex + 2u > q->capex) {
        unsigned nc = q->capex ? q->capex * 2u : 16u;
        if (nc > MAX_NODES + 1u) nc = MAX_NODES + 1u;
        xn *ne = realloc(q->ex, nc * sizeof *ne);
        if (!ne) return oom(b);
        q->ex = ne;
        q->capex = (uint16_t)nc;
    }
    uint16_t k = ++q->nex;
    xn *x = &q->ex[k];
    memset(x, 0, sizeof *x);
    x->op = op;
    x->l = l;
    x->r = r;
    unsigned hl = l ? q->ex[l].h : 0u, hr = r ? q->ex[r].h : 0u, h = (hl > hr ? hl : hr) + 1u;
    if (h > MAX_DEPTH) return deep(b);
    x->h = (uint8_t)h;
    *out = k;
    return 0;
}

static int third(ab *b, uint16_t k, uint16_t x3) /* node k's third child, its height counted */
{
    X(k)->x3 = x3;
    if (x3 && X(x3)->h + 1u > X(k)->h) X(k)->h = (uint8_t)(X(x3)->h + 1u);
    return X(k)->h > MAX_DEPTH ? deep(b) : 0;
}

static int bexpr(ab *b, uint16_t *out, unsigned d);
static int aexpr(ab *b, uint16_t *out, unsigned d);
static int parse_query(ab *b, aq *q);

/* elements as a balanced list (one element is itself), as the engine builds them: the height log2 of the count */
static int list_n(ab *b, const uint16_t *el, uint32_t n, uint16_t *out)
{
    if (n == 1) {
        *out = el[0];
        return 0;
    }
    uint16_t a, c;
    if (list_n(b, el, n / 2, &a) || list_n(b, el + n / 2, n - n / 2, &c)) return -1;
    return nnew(b, X_LIST, a, c, out);
}

static int push(ab *b, uint16_t **el, uint32_t *n, uint32_t *cap, uint16_t k)
{
    if (*n == *cap) {
        uint32_t nc = *cap ? *cap * 2 : 8;
        uint16_t *ne = realloc(*el, nc * sizeof *ne);
        if (!ne) return oom(b);
        *el = ne;
        *cap = nc;
    }
    (*el)[(*n)++] = k;
    return 0;
}

/* expressions separated by commas up to ")" (eaten), one at least */
static int expr_list(ab *b, unsigned d, uint16_t *out, uint32_t *n)
{
    uint16_t *el = NULL, k;
    uint32_t cnt = 0, cap = 0;
    int rc = 0;
    do {
        if ((rc = bexpr(b, &k, d + 1)) || (rc = push(b, &el, &cnt, &cap, k))) break;
    } while (tok(b, K_COMMA));
    if (!rc) rc = expect(b, K_RP, ")");
    if (!rc) rc = list_n(b, el, cnt, out);
    free(el);
    *n = cnt;
    return rc;
}

static uint8_t fn_named(const ab *b, uint32_t at)
{
    static const struct {
        const char *name;
        uint8_t fn;
    } F[] = {{"abs", F_ABS},          {"sign", F_SIGN},         {"round", F_ROUND},     {"ceil", F_CEIL},
             {"ceiling", F_CEIL},     {"floor", F_FLOOR},       {"mod", F_MOD},         {"length", F_LENGTH},
             {"char_length", F_LENGTH}, {"character_length", F_LENGTH}, {"substr", F_SUBSTR}, {"substring", F_SUBSTR},
             {"trim", F_TRIM},        {"ltrim", F_LTRIM},       {"rtrim", F_RTRIM},     {"position", F_POSITION},
             {"coalesce", F_COALESCE}, {"nullif", F_NULLIF},    {"lower", F_LOWER},     {"upper", F_UPPER},
             {"replace", F_REPLACE},  {"date_trunc", F_DATE_TRUNC}, {"timezone", F_TIMEZONE}}; /* P2 */
    for (size_t i = 0; i < sizeof F / sizeof *F; i++)
        if (kwat(b, at, F[i].name)) return F[i].fn;
    return 0;
}

static uint8_t wf_named(const ab *b, uint32_t at)
{
    static const struct {
        const char *name;
        uint8_t wf;
    } W[] = {{"row_number", W_ROW_NUMBER}, {"rank", W_RANK}, {"dense_rank", W_DENSE_RANK}, {"ntile", W_NTILE},
             {"lag", W_LAG},               {"lead", W_LEAD}, {"first_value", W_FIRST},     {"last_value", W_LAST}};
    for (size_t i = 0; i < sizeof W / sizeof *W; i++)
        if (kwat(b, at, W[i].name)) return W[i].wf;
    return 0;
}

static int fn_call(ab *b, uint8_t fn, uint16_t *out, unsigned d)
{
    b->i += 2; /* the name and its ( */
    uint16_t args;
    uint32_t n;
    if (fn == F_POSITION) { /* POSITION(a IN b) */
        uint16_t el[2];
        if (aexpr(b, &el[0], d + 1) || expect_kw(b, "in") || aexpr(b, &el[1], d + 1) || expect(b, K_RP, ")") ||
            list_n(b, el, 2, &args))
            return -1;
        n = 2;
    } else if (expr_list(b, d, &args, &n)) {
        return -1;
    }
    if (n > MAX_ARGS) return fail(b, "a function call of more than %u arguments", MAX_ARGS);
    if (nnew(b, X_FN, args, 0, out)) return -1;
    X(*out)->fn = fn;
    X(*out)->nargs = (uint8_t)n;
    return 0;
}

static int case_expr(ab *b, uint16_t *out, unsigned d) /* CASE eaten */
{
    uint16_t operand = 0, els = 0, whens = 0, *w = NULL;
    uint32_t n = 0, cap = 0;
    int rc = 0;
    if (!kwat(b, b->i, "when")) rc = bexpr(b, &operand, d + 1);
    while (!rc && kw(b, "when")) {
        uint16_t c, v, k;
        if ((rc = bexpr(b, &c, d + 1)) || (rc = expect_kw(b, "then")) || (rc = bexpr(b, &v, d + 1)) ||
            (rc = nnew(b, X_WHEN, c, v, &k)))
            break;
        rc = push(b, &w, &n, &cap, k);
    }
    if (!rc && !n) rc = fail(b, "expected WHEN at offset %u", b->t[b->i].off);
    if (!rc && kw(b, "else")) rc = bexpr(b, &els, d + 1);
    if (!rc) rc = expect_kw(b, "end");
    if (!rc) rc = list_n(b, w, n, &whens);
    free(w);
    if (rc || nnew(b, X_CASE, operand, whens, out)) return -1;
    return third(b, *out, els);
}

static int col_type(ab *b, uint8_t *type, uint8_t *scale) /* a CAST's type, as a column's */
{
    *scale = 0;
    if (kw(b, "int64") || kw(b, "bigint") || kw(b, "int") || kw(b, "integer")) *type = T_INT64;
    else if (kw(b, "text")) *type = T_TEXT;
    else if (kw(b, "bool") || kw(b, "boolean")) *type = T_BOOL;
    else if (kw(b, "timestamptz")) *type = T_TIMESTAMPTZ; /* P2 */
    else if (kw(b, "timestamp")) {
        *type = T_TIMESTAMP;
        if ((kwat(b, b->i, "with") || kwat(b, b->i, "without")) && kwat(b, b->i + 1, "time") && kwat(b, b->i + 2, "zone")) {
            if (kwat(b, b->i, "with")) *type = T_TIMESTAMPTZ;
            b->i += 3;
        }
    }
    else if (kw(b, "decimal") || kw(b, "numeric")) {
        *type = T_DECIMAL;
        uint32_t p, s = 0;
        const tk *t = &b->t[b->i];
        if (expect(b, K_LP, "(")) return -1;
        t = &b->t[b->i];
        if (t->k != K_INT || t->len > 2) return fail(b, "DECIMAL(p,s) needs 1 <= p <= 18 and 0 <= s <= p");
        p = (uint32_t)atoi(b->s + t->off) % 1000u;
        b->i++;
        if (tok(b, K_COMMA)) {
            t = &b->t[b->i];
            if (t->k != K_INT || t->len > 2) return fail(b, "DECIMAL(p,s) needs 1 <= p <= 18 and 0 <= s <= p");
            s = (uint32_t)atoi(b->s + t->off) % 1000u;
            b->i++;
        }
        if (expect(b, K_RP, ")")) return -1;
        if (p < 1 || p > 18 || s > p) return fail(b, "DECIMAL(p,s) needs 1 <= p <= 18 and 0 <= s <= p");
        *scale = (uint8_t)s;
    } else if (kw(b, "float64") || kw(b, "float8") || kw(b, "float")) {
        *type = T_FLOAT64;
    } else if (kw(b, "double")) {
        kw(b, "precision");
        *type = T_FLOAT64;
    } else {
        return fail(b, "expected a type at offset %u", b->t[b->i].off);
    }
    return 0;
}

static int cast_expr(ab *b, uint16_t *out, unsigned d) /* CAST eaten */
{
    uint16_t a;
    uint8_t t, s;
    if (expect(b, K_LP, "(") || bexpr(b, &a, d + 1) || expect_kw(b, "as") || col_type(b, &t, &s) ||
        expect(b, K_RP, ")") || nnew(b, X_CAST, a, 0, out))
        return -1;
    X(*out)->ctype = t;
    X(*out)->cscale = s;
    return 0;
}

static int parse_nested(ab *b, aq *outer, const char *name, uint8_t kind);

static int subq(ab *b, uint8_t subk, uint16_t *out) /* (SELECT ...) after its '(': a value, EXISTS's or IN's */
{
    if (parse_nested(b, b->q, "", SUB_EXPR) || expect(b, K_RP, ")") || nnew(b, X_SUBQ, 0, 0, out)) return -1;
    X(*out)->sub = (uint8_t)(b->q->nsub - 1);
    X(*out)->subk = subk;
    b->q->sub_subk[b->q->nsub - 1] = subk;
    return 0;
}

static int frame_bound(ab *b)
{
    if (kw(b, "unbounded")) return kw(b, "preceding") || kw(b, "following") ? 0 : fail(b, "expected PRECEDING or FOLLOWING");
    if (kw(b, "current")) return expect_kw(b, "row");
    if (!tok(b, K_INT)) return fail(b, "expected a frame's bound at offset %u", b->t[b->i].off);
    return kw(b, "preceding") || kw(b, "following") ? 0 : fail(b, "expected PRECEDING or FOLLOWING");
}

/* OVER (...): its keys kept (walked for their subqueries), its frame parsed and nothing more (no type depends on it) */
static int window_spec(ab *b, uint8_t *out, unsigned d)
{
    aq *q = b->q;
    if (q->nwin >= MAX_WINDOWS) return fail(b, "more than %u window functions in one SELECT", MAX_WINDOWS);
    if (expect(b, K_LP, "(")) return -1;
    uint8_t w = q->nwin;
    memset(&q->win[w], 0, sizeof q->win[w]);
    if (kw(b, "partition")) {
        if (expect_kw(b, "by")) return -1;
        do {
            if (b->q->win[w].npart >= MAX_WIN_KEYS) return fail(b, "PARTITION BY of more than %u keys", MAX_WIN_KEYS);
            uint16_t k;
            if (bexpr(b, &k, d + 1)) return -1;
            b->q->win[w].part[b->q->win[w].npart++] = k;
        } while (tok(b, K_COMMA));
    }
    if (kw(b, "order")) {
        if (expect_kw(b, "by")) return -1;
        do {
            if (b->q->win[w].nord >= MAX_WIN_KEYS) return fail(b, "a window's ORDER BY of more than %u keys", MAX_WIN_KEYS);
            uint16_t k;
            if (bexpr(b, &k, d + 1)) return -1;
            b->q->win[w].ord[b->q->win[w].nord++] = k;
            if (!kw(b, "desc")) kw(b, "asc");
            if (kw(b, "nulls") && !kw(b, "first") && !kw(b, "last")) return fail(b, "expected FIRST or LAST after NULLS");
        } while (tok(b, K_COMMA));
    }
    if (kw(b, "rows") || kw(b, "range")) {
        if (kw(b, "between")) {
            if (frame_bound(b) || expect_kw(b, "and") || frame_bound(b)) return -1;
        } else if (frame_bound(b)) {
            return -1;
        }
    }
    if (expect(b, K_RP, ")")) return -1;
    *out = b->q->nwin++;
    return 0;
}

static int window_call(ab *b, uint8_t wf, uint16_t *out, unsigned d)
{
    b->i += 2; /* the name, then ( */
    uint16_t a[3] = {0, 0, 0};
    uint8_t n = 0;
    bool none = wf == W_ROW_NUMBER || wf == W_RANK || wf == W_DENSE_RANK;
    if (!none) {
        do {
            if (n >= 3) return fail(b, "a window function of more than 3 arguments");
            if (bexpr(b, &a[n++], d + 1)) return -1;
        } while (tok(b, K_COMMA));
    }
    if (expect(b, K_RP, ")")) return -1;
    uint8_t lo = none ? 0 : 1, hi = none ? 0 : wf == W_LAG || wf == W_LEAD ? 3 : 1;
    if (n < lo || n > hi) return fail(b, "that window function takes %u to %u arguments", lo, hi);
    if (!kw(b, "over")) return fail(b, "expected OVER after a window function at offset %u", b->t[b->i].off);
    uint8_t w;
    if (window_spec(b, &w, d) || nnew(b, X_WIN, a[0], a[1], out)) return -1;
    X(*out)->wf = wf;
    X(*out)->win = w;
    return third(b, *out, a[2]);
}

/* a typed timestamp literal begins at token i: TIMESTAMP or TIMESTAMPTZ then a string; P2: TIMESTAMP WITH or WITHOUT TIME
 * ZONE then a string (the engine's rule) */
static bool ts_literal_at(const ab *b, uint32_t i)
{
    if (kwat(b, i, "timestamptz")) return kind_at(b, i + 1) == K_STR;
    if (!kwat(b, i, "timestamp")) return false;
    if (kind_at(b, i + 1) == K_STR) return true;
    return (kwat(b, i + 1, "with") || kwat(b, i + 1, "without")) && kwat(b, i + 2, "time") && kwat(b, i + 3, "zone") &&
           kind_at(b, i + 4) == K_STR;
}

static int literal(ab *b, uint16_t *out)
{
    bool neg = false, sign = false;
    if (b->t[b->i].k == K_MINUS || b->t[b->i].k == K_PLUS) {
        neg = b->t[b->i].k == K_MINUS;
        sign = true;
        b->i++;
    }
    const tk *t = &b->t[b->i];
    uint8_t lit = 0;
    if (t->k == K_INT || t->k == K_DEC || t->k == K_FLT) lit = t->k == K_INT ? L_INT : t->k == K_DEC ? L_DEC : L_FLT;
    else if (sign) return fail(b, "expected a number after the sign at offset %u", t->off);
    else if (t->k == K_STR) lit = L_STR;
    else if (t->k == K_PARAM) lit = L_PARAM;
    else if (kwat(b, b->i, "true") || kwat(b, b->i, "false")) lit = L_BOOL;
    else if (ts_literal_at(b, b->i)) { /* P2: TIMESTAMPTZ and TIMESTAMP WITH TIME ZONE its TIMESTAMPTZ */
        bool tz = kwat(b, b->i, "timestamptz") || kwat(b, b->i + 1, "with");
        b->i += kwat(b, b->i, "timestamptz") || kind_at(b, b->i + 1) == K_STR ? 1 : 4;
        lit = tz ? L_TSTZ : L_TS;
        t = &b->t[b->i];
    } else if (kwat(b, b->i, "null")) lit = L_NULL;
    else return fail(b, "expected a literal at offset %u", t->off);
    uint32_t off = t->off, len = t->len;
    b->i++;
    if (nnew(b, X_LIT, 0, 0, out)) return -1;
    X(*out)->lit = lit;
    X(*out)->neg = neg;
    X(*out)->off = off;
    X(*out)->len = len;
    return 0;
}

static int primary(ab *b, uint16_t *out, unsigned d)
{
    if (d > MAX_DEPTH) return deep(b);
    if (tok(b, K_LP)) {
        if (kwat(b, b->i, "select")) return subq(b, S_VALUE, out);
        if (bexpr(b, out, d + 1)) return -1;
        return expect(b, K_RP, ")");
    }
    if (kwat(b, b->i, "exists") && kind_at(b, b->i + 1) == K_LP) {
        b->i += 2;
        return subq(b, S_EXISTS, out);
    }
    uint8_t agg = kwat(b, b->i, "count") ? A_COUNT : kwat(b, b->i, "sum") ? A_SUM : kwat(b, b->i, "min") ? A_MIN
                : kwat(b, b->i, "max")   ? A_MAX   : kwat(b, b->i, "avg") ? A_AVG : 0;
    if (agg && kind_at(b, b->i + 1) == K_LP) {
        b->i += 2;
        uint16_t a = 0, f = 0;
        bool dist = kw(b, "distinct");
        if (!dist) kw(b, "all");
        if (agg == A_COUNT && tok(b, K_STAR)) {
            if (dist) return fail(b, "COUNT(DISTINCT *)");
            agg = A_COUNT_STAR;
        } else if (bexpr(b, &a, d + 1)) {
            return -1;
        }
        if (expect(b, K_RP, ")")) return -1;
        if (kwat(b, b->i, "filter") && kind_at(b, b->i + 1) == K_LP) {
            b->i += 2;
            if (expect_kw(b, "where") || bexpr(b, &f, d + 1) || expect(b, K_RP, ")")) return -1;
        }
        if (kwat(b, b->i, "over")) {
            if (dist || f) return fail(b, "DISTINCT or FILTER with OVER");
            b->i++;
            uint8_t w;
            if (window_spec(b, &w, d) || nnew(b, X_WIN, a, 0, out)) return -1;
            X(*out)->wf = W_AGG;
            X(*out)->agg = agg;
            X(*out)->win = w;
            return 0;
        }
        if (nnew(b, X_AGG, a, 0, out)) return -1;
        X(*out)->agg = agg;
        X(*out)->dist = dist;
        return third(b, *out, f);
    }
    if (kw(b, "case")) return case_expr(b, out, d);
    if (kw(b, "cast")) return cast_expr(b, out, d);
    if (b->t[b->i].k == K_ID && kind_at(b, b->i + 1) == K_LP) {
        uint8_t wf = wf_named(b, b->i);
        if (wf) return window_call(b, wf, out, d);
        uint8_t fn = fn_named(b, b->i);
        if (fn) return fn_call(b, fn, out, d);
    }
    const tk *t = &b->t[b->i];
    if (t->k == K_ID && !kwat(b, b->i, "true") && !kwat(b, b->i, "false") && !kwat(b, b->i, "null") &&
        !ts_literal_at(b, b->i)) {
        if (reserved(b, b->i)) return fail(b, "expected an identifier at offset %u", t->off);
        uint32_t qo = 0, ql = 0, co = t->off, cl = t->len;
        b->i++;
        if (tok(b, K_DOT)) {
            const tk *c = &b->t[b->i];
            if (c->k != K_ID || reserved(b, b->i)) return fail(b, "expected an identifier at offset %u", c->off);
            qo = co, ql = cl, co = c->off, cl = c->len;
            b->i++;
        }
        if (nnew(b, X_COL, 0, 0, out)) return -1;
        X(*out)->off = co;
        X(*out)->len = cl;
        X(*out)->qoff = qo;
        X(*out)->qlen = ql;
        return 0;
    }
    return literal(b, out);
}

static int unary(ab *b, uint16_t *out, unsigned d)
{
    if (d > MAX_DEPTH) return deep(b);
    uint8_t k = b->t[b->i].k;
    if (k == K_MINUS || k == K_PLUS) {
        uint8_t nk = kind_at(b, b->i + 1);
        if (nk == K_INT || nk == K_DEC || nk == K_FLT) return primary(b, out, d); /* the literal's own sign */
        b->i++;
        uint16_t a;
        if (unary(b, &a, d + 1)) return -1;
        if (k == K_PLUS) {
            *out = a;
            return 0;
        }
        return nnew(b, X_NEG, a, 0, out);
    }
    return primary(b, out, d);
}

/* P2: x AT TIME ZONE z, the engine's level: below a sign, above * and /, left to right; the node timezone(z, x) */
static int at_expr(ab *b, uint16_t *out, unsigned d)
{
    if (unary(b, out, d)) return -1;
    while (kwat(b, b->i, "at") && kwat(b, b->i + 1, "time") && kwat(b, b->i + 2, "zone")) {
        b->i += 3;
        uint16_t el[2] = {0, *out}, args;
        if (unary(b, &el[0], d + 1) || list_n(b, el, 2, &args) || nnew(b, X_FN, args, 0, out)) return -1;
        X(*out)->fn = F_TIMEZONE;
        X(*out)->nargs = 2;
    }
    return 0;
}

static int term(ab *b, uint16_t *out, unsigned d)
{
    if (at_expr(b, out, d)) return -1;
    for (;;) {
        uint8_t k = b->t[b->i].k, op = k == K_STAR ? X_MUL : k == K_SLASH ? X_DIV : k == K_PCT ? X_MOD : 0;
        if (!op) return 0;
        b->i++;
        uint16_t r;
        if (at_expr(b, &r, d) || nnew(b, op, *out, r, out)) return -1;
    }
}

static int aexpr(ab *b, uint16_t *out, unsigned d)
{
    if (d > MAX_DEPTH) return deep(b);
    if (term(b, out, d)) return -1;
    for (;;) {
        uint8_t k = b->t[b->i].k, op = k == K_PLUS ? X_ADD : k == K_MINUS ? X_SUB : 0;
        if (!op) return 0;
        b->i++;
        uint16_t r;
        if (term(b, &r, d) || nnew(b, op, *out, r, out)) return -1;
    }
}

static int cexpr(ab *b, uint16_t *out, unsigned d) /* a || b: below + and -, above the comparisons */
{
    if (aexpr(b, out, d)) return -1;
    while (tok(b, K_CONCAT)) {
        uint16_t el[2] = {*out, 0}, args;
        if (aexpr(b, &el[1], d) || list_n(b, el, 2, &args) || nnew(b, X_FN, args, 0, out)) return -1;
        X(*out)->fn = F_CONCAT;
        X(*out)->nargs = 2;
    }
    return 0;
}

static int b_cmp(ab *b, uint16_t *out, unsigned d)
{
    if (cexpr(b, out, d)) return -1;
    uint8_t op = 0;
    uint16_t r = 0, x3 = 0;
    bool neg = kwat(b, b->i, "not") && (kwat(b, b->i + 1, "in") || kwat(b, b->i + 1, "like") || kwat(b, b->i + 1, "between"));
    if (neg) b->i++;
    if (kw(b, "in")) {
        uint32_t n;
        if (expect(b, K_LP, "(")) return -1;
        if (kwat(b, b->i, "select")) {
            if (subq(b, S_IN, &r)) return -1;
        } else if (expr_list(b, d, &r, &n)) {
            return -1;
        }
        op = neg ? C_NOTIN : C_IN;
    } else if (kw(b, "like")) {
        op = neg ? C_NOTLIKE : C_LIKE;
        if (cexpr(b, &r, d) || (kw(b, "escape") && cexpr(b, &x3, d))) return -1;
    } else if (kw(b, "is")) {
        op = kw(b, "not") ? C_NOTNULL : C_ISNULL;
        if (expect_kw(b, "null")) return -1;
    } else if (kw(b, "between")) {
        op = C_BETWEEN;
        if (cexpr(b, &r, d) || expect_kw(b, "and") || cexpr(b, &x3, d)) return -1;
    } else {
        switch (b->t[b->i].k) {
        case K_EQ: op = C_EQ; break;
        case K_NE: op = C_NE; break;
        case K_LT: op = C_LT; break;
        case K_LE: op = C_LE; break;
        case K_GT: op = C_GT; break;
        case K_GE: op = C_GE; break;
        default: return 0;
        }
        b->i++;
        if (cexpr(b, &r, d)) return -1;
    }
    uint16_t k;
    if (nnew(b, X_CMP, *out, r, &k)) return -1;
    X(k)->cmp = op;
    if (x3 && third(b, k, x3)) return -1;
    if (neg && op == C_BETWEEN) return nnew(b, X_NOT, k, 0, out);
    *out = k;
    return 0;
}

static int b_not(ab *b, uint16_t *out, unsigned d)
{
    if (d > MAX_DEPTH) return deep(b);
    if (kw(b, "not")) {
        uint16_t a;
        if (b_not(b, &a, d + 1)) return -1;
        return nnew(b, X_NOT, a, 0, out);
    }
    return b_cmp(b, out, d);
}

static int b_and(ab *b, uint16_t *out, unsigned d)
{
    if (b_not(b, out, d)) return -1;
    while (kw(b, "and")) {
        uint16_t r;
        if (b_not(b, &r, d) || nnew(b, X_AND, *out, r, out)) return -1;
    }
    return 0;
}

static int bexpr(ab *b, uint16_t *out, unsigned d)
{
    if (d > MAX_DEPTH) return deep(b);
    if (b_and(b, out, d)) return -1;
    while (kw(b, "or")) {
        uint16_t r;
        if (b_and(b, &r, d) || nnew(b, X_OR, *out, r, out)) return -1;
    }
    return 0;
}

static aq *aq_new(ab *b)
{
    aq *q = calloc(1, sizeof *q);
    if (!q) {
        oom(b);
        return NULL;
    }
    q->fsub[0] = q->fsub[1] = -1;
    return q;
}

static void aq_free(aq *q)
{
    if (!q) return;
    for (uint8_t i = 0; i < q->nsub; i++) {
        aq_free(q->sub[i]);
        free(q->cte_cols[i]);
    }
    for (uint8_t i = 0; i < q->narm; i++) aq_free(q->arm[i]);
    free(q->arm);
    free(q->items);
    free(q->ex);
    free(q);
}

static int parse_nested(ab *b, aq *outer, const char *name, uint8_t kind)
{
    if (outer->nsub >= MAX_SUBS) return fail(b, "more than %u nested SELECTs in one statement", MAX_SUBS);
    if (b->depth >= MAX_SUB_DEPTH) return fail(b, "SELECTs nested deeper than %u", MAX_SUB_DEPTH);
    for (uint8_t i = 0; name[0] && i < outer->nsub; i++)
        if (!strcmp(outer->sub_name[i], name)) return fail(b, "two nested SELECTs named %s", name);
    aq *in = aq_new(b);
    if (!in) return -1;
    uint8_t i = outer->nsub++;
    outer->sub[i] = in;
    snprintf(outer->sub_name[i], sizeof outer->sub_name[i], "%s", name);
    outer->sub_kind[i] = kind;
    aq *saved = b->q;
    b->q = in;
    b->depth++;
    int rc = parse_query(b, in);
    b->depth--;
    b->q = saved;
    return rc;
}

static int from_item(ab *b, aq *q, int slot)
{
    q->falias[slot][0] = 0;
    if (!tok(b, K_LP)) {
        if (ident(b, q->fname[slot])) return -1;
        if (kwat(b, b->i, "as") && !kwat(b, b->i + 1, "of")) { /* AS alias (not AS OF) */
            b->i++;
            return ident(b, q->falias[slot]);
        }
        return 0;
    }
    uint8_t at = q->nsub;
    if (parse_nested(b, q, "", SUB_DERIVED) || expect(b, K_RP, ")")) return -1;
    kw(b, "as");
    if (b->t[b->i].k != K_ID || reserved(b, b->i)) return fail(b, "a nested SELECT in FROM needs a name");
    char name[64];
    if (ident(b, name)) return -1;
    for (uint8_t i = 0; i < q->nsub; i++)
        if (i != at && !strcmp(q->sub_name[i], name)) return fail(b, "two nested SELECTs named %s", name);
    snprintf(q->sub_name[at], sizeof q->sub_name[at], "%s", name);
    snprintf(q->fname[slot], sizeof q->fname[slot], "%s", name);
    q->fsub[slot] = (int8_t)at;
    return 0;
}

static bool join_word(const ab *b)
{
    return b->t[b->i].k == K_COMMA || kwat(b, b->i, "join") || kwat(b, b->i, "inner") || kwat(b, b->i, "left") ||
           kwat(b, b->i, "right") || kwat(b, b->i, "full") || kwat(b, b->i, "cross");
}

static int parse_core(ab *b, aq *q)
{
    q->distinct = kw(b, "distinct");
    if (tok(b, K_STAR)) {
        q->star = true;
    } else {
        do {
            if (q->nitems >= MAX_COLS) return fail(b, "too many select items");
            if (q->nitems == q->capitems) {
                uint16_t nc = q->capitems ? (uint16_t)(q->capitems * 2) : 8;
                aitem *ni = realloc(q->items, nc * sizeof *ni);
                if (!ni) return oom(b);
                q->items = ni;
                q->capitems = nc;
            }
            aitem *it = &q->items[q->nitems];
            memset(it, 0, sizeof *it);
            const tk *t0 = &b->t[b->i];
            uint32_t from = t0->off - (t0->k == K_STR);
            uint16_t k;
            if (bexpr(b, &k, 0)) return -1;
            it = &q->items[q->nitems];
            it->ex = k;
            const tk *tl = &b->t[b->i - 1];
            it->off = from;
            it->len = tl->off + tl->len + (tl->k == K_STR) - from;
            if (kw(b, "as") ? ident(b, it->alias) : b->t[b->i].k == K_ID && !reserved(b, b->i) && ident(b, it->alias))
                return -1;
            const xn *x = X(k);
            if (x->op == X_COL) it->shape = 1;
            else if (x->op == X_AGG && x->agg != A_AVG && !x->dist && !x->x3 && (!x->l || X(x->l)->op == X_COL)) it->shape = 2;
            q->nitems++;
        } while (tok(b, K_COMMA));
    }
    if (!q->star && !kwat(b, b->i, "from")) { /* constants alone: one row */
        q->no_from = true;
        if (kwat(b, b->i, "where") || kwat(b, b->i, "group") || kwat(b, b->i, "having"))
            return fail(b, "a SELECT without FROM computes one row");
        return 0;
    }
    if (expect_kw(b, "from") || from_item(b, q, 0)) return -1;
    q->nfrom = 1;
    if (kw(b, "with") && (expect(b, K_LP, "(") || expect_kw(b, "nolock") || expect(b, K_RP, ")"))) return -1;
    if (join_word(b)) {
        if (tok(b, K_COMMA)) {
            q->join = J_CROSS;
        } else {
            q->join = kw(b, "cross") ? J_CROSS : kw(b, "left") ? J_LEFT : kw(b, "right") ? J_RIGHT : kw(b, "full") ? J_FULL
                                                                                                                 : J_INNER;
            if (q->join == J_INNER) kw(b, "inner");
            if (q->join != J_INNER && q->join != J_CROSS) kw(b, "outer");
            if (expect_kw(b, "join")) return -1;
        }
        if (from_item(b, q, 1)) return -1;
        q->nfrom = 2;
        if (q->join != J_CROSS && kw(b, "using")) {
            if (expect(b, K_LP, "(")) return -1;
            do {
                if (q->nusing >= MAX_USING) return fail(b, "USING names more than %u columns", MAX_USING);
                if (ident(b, q->using_col[q->nusing++])) return -1;
            } while (tok(b, K_COMMA));
            if (expect(b, K_RP, ")")) return -1;
        } else if (q->join != J_CROSS) {
            if (expect_kw(b, "on") || bexpr(b, &q->on, 0)) return -1;
        }
        if (join_word(b)) return fail(b, "a join takes two tables");
    }
    if (kw(b, "as")) {
        uint16_t l;
        if (expect_kw(b, "of") || literal(b, &l)) return -1;
        q->has_asof = true;
    }
    if (kw(b, "where") && bexpr(b, &q->where, 0)) return -1;
    if (kw(b, "group")) {
        if (expect_kw(b, "by")) return -1;
        do {
            if (q->ngroup >= MAX_GROUP) return fail(b, "GROUP BY has more than %u keys", MAX_GROUP);
            uint16_t k;
            if (bexpr(b, &k, 0)) return -1;
            q->group[q->ngroup++] = k;
        } while (tok(b, K_COMMA));
    }
    if (kw(b, "having") && bexpr(b, &q->having, 0)) return -1;
    return 0;
}

static int parse_tail(ab *b, aq *q)
{
    if (kw(b, "order")) {
        if (expect_kw(b, "by")) return -1;
        do {
            if (q->norder >= MAX_ORDER) return fail(b, "ORDER BY has more than %u keys", MAX_ORDER);
            const tk *t = &b->t[b->i];
            uint8_t nk = t->k == K_EOF ? K_EOF : kind_at(b, b->i + 1);
            uint16_t k = 0;
            if (t->k == K_INT && (nk == K_COMMA || nk == K_EOF || nk == K_SEMI || nk == K_ID || nk == K_RP)) b->i++;
            else if (bexpr(b, &k, 0)) return -1;
            q->order[q->norder++] = k;
            if (!kw(b, "desc")) kw(b, "asc");
            if (kw(b, "nulls") && !kw(b, "first") && !kw(b, "last")) return fail(b, "expected FIRST or LAST after NULLS");
        } while (tok(b, K_COMMA));
    }
    for (int k = 0; k < 2; k++) {
        if (!q->has_limit && kw(b, "limit")) {
            q->has_limit = true;
            if (!tok(b, K_INT)) return fail(b, "expected an unsigned integer at offset %u", b->t[b->i].off);
        } else if (!q->has_offset && kw(b, "offset")) {
            q->has_offset = true;
            if (!tok(b, K_INT)) return fail(b, "expected an unsigned integer at offset %u", b->t[b->i].off);
        }
    }
    if (kw(b, "for")) {
        if (expect_kw(b, "update")) return -1;
        q->for_update = true;
    }
    return 0;
}

static uint8_t setop_take(ab *b, int level) /* 1: INTERSECT's; 0: UNION's and EXCEPT's */
{
    bool i = kwat(b, b->i, "intersect"), o = kwat(b, b->i, "union") || kwat(b, b->i, "except");
    if (level ? !i : !o) return 0;
    b->i++;
    if (!kw(b, "all")) kw(b, "distinct");
    return 1;
}

static int arm_add(ab *b, aq *q, aq *a)
{
    if (q->narm == q->caparm) {
        uint8_t nc = q->caparm ? (uint8_t)(q->caparm * 2 > MAX_ARMS ? MAX_ARMS : q->caparm * 2) : 4;
        if (nc <= q->narm) return fail(b, "set operations of more than %u SELECTs", MAX_ARMS);
        aq **na = realloc(q->arm, nc * sizeof *na);
        if (!na) return oom(b);
        q->arm = na;
        q->caparm = nc;
    }
    q->arm[q->narm++] = a;
    return 0;
}

static int arm_new(ab *b, aq **out)
{
    if (b->narms >= MAX_ARMS) return fail(b, "set operations of more than %u SELECTs in one statement", MAX_ARMS);
    if (!(*out = aq_new(b))) return -1;
    b->narms++;
    return 0;
}

/* q, holding one operand, becomes a set operation whose first arm is that operand, moved whole but for its first keep
 * nested SELECTs (a WITH's, which every arm reads), which stay q's; the operand's own follow it, renumbered */
static int setop_open(ab *b, aq *q, uint8_t keep)
{
    aq *a;
    if (arm_new(b, &a)) return -1;
    *a = *q;
    memset(q, 0, sizeof *q);
    q->fsub[0] = q->fsub[1] = -1;
    for (uint8_t i = 0; i < keep; i++) {
        q->sub[i] = a->sub[i];
        memcpy(q->sub_name[i], a->sub_name[i], sizeof q->sub_name[i]);
        q->sub_kind[i] = a->sub_kind[i];
        q->sub_subk[i] = a->sub_subk[i];
        q->sub_rec[i] = a->sub_rec[i];
        q->cte_ncols[i] = a->cte_ncols[i];
        q->cte_cols[i] = a->cte_cols[i];
    }
    q->nsub = keep;
    uint8_t n = (uint8_t)(a->nsub - keep);
    for (uint8_t i = 0; i < n; i++) {
        a->sub[i] = a->sub[i + keep];
        memcpy(a->sub_name[i], a->sub_name[i + keep], sizeof a->sub_name[i]);
        a->sub_kind[i] = a->sub_kind[i + keep];
        a->sub_subk[i] = a->sub_subk[i + keep];
        a->sub_rec[i] = a->sub_rec[i + keep];
        a->cte_ncols[i] = a->cte_ncols[i + keep];
        a->cte_cols[i] = a->cte_cols[i + keep];
    }
    for (uint8_t i = n; i < a->nsub; i++) {
        a->sub[i] = NULL;
        a->sub_name[i][0] = 0;
        a->cte_cols[i] = NULL;
        a->cte_ncols[i] = 0;
    }
    a->nsub = n;
    for (uint16_t k = 1; keep && k <= a->nex; k++)
        if (a->ex[k].op == X_SUBQ) a->ex[k].sub = (uint8_t)(a->ex[k].sub - keep);
    for (int s = 0; keep && s < 2; s++)
        if (a->fsub[s] >= 0) a->fsub[s] = (int8_t)(a->fsub[s] - keep);
    return arm_add(b, q, a);
}

static int parse_operand(ab *b, aq *q)
{
    if (tok(b, K_LP)) {
        if (b->parens >= MAX_PARENS) return fail(b, "queries parenthesized deeper than %u", MAX_PARENS);
        b->parens++;
        int rc = parse_query(b, q) || expect(b, K_RP, ")") ? -1 : 0;
        b->parens--;
        return rc;
    }
    return expect_kw(b, "select") || parse_core(b, q) ? -1 : 0;
}

static int parse_chain(ab *b, aq *q, int level, uint8_t keep)
{
    if (level ? parse_operand(b, q) : parse_chain(b, q, 1, keep)) return -1;
    bool open = false;
    while (setop_take(b, level)) {
        if (!open && setop_open(b, q, keep)) return -1;
        open = true;
        aq *a;
        if (arm_new(b, &a)) return -1;
        if (arm_add(b, q, a)) {
            aq_free(a);
            return -1;
        }
        aq *saved = b->q;
        b->q = a;
        int rc = level ? parse_operand(b, a) : parse_chain(b, a, 1, 0);
        b->q = saved;
        if (rc) return -1;
    }
    return 0;
}

static int parse_query(ab *b, aq *q)
{
    aq *saved = b->q;
    b->q = q;
    uint8_t keep = q->nsub;
    int rc = parse_chain(b, q, 0, keep);
    bool tail = q->norder || q->has_limit || q->has_offset;
    if (!rc && tail && (kwat(b, b->i, "order") || kwat(b, b->i, "limit") || kwat(b, b->i, "offset") || kwat(b, b->i, "for")))
        rc = setop_open(b, q, keep);
    if (!rc) rc = parse_tail(b, q);
    b->q = saved;
    return rc;
}

static int parse_with_list(ab *b, aq *q) /* WITH eaten */
{
    bool rec = kw(b, "recursive");
    do {
        char name[64], cols[MAX_COLS][64];
        uint8_t nc = 0;
        if (ident(b, name)) return -1;
        if (tok(b, K_LP)) {
            do {
                if (nc >= MAX_COLS) return fail(b, "a WITH names more than %u columns", MAX_COLS);
                if (ident(b, cols[nc++])) return -1;
                for (uint8_t i = 0; i + 1 < nc; i++)
                    if (!strcmp(cols[i], cols[nc - 1])) return fail(b, "a WITH names its column %s twice", cols[i]);
            } while (tok(b, K_COMMA));
            if (expect(b, K_RP, ")")) return -1;
        }
        if (expect_kw(b, "as") || expect(b, K_LP, "(") || parse_nested(b, q, name, SUB_CTE) || expect(b, K_RP, ")"))
            return -1;
        uint8_t s = (uint8_t)(q->nsub - 1);
        q->sub_rec[s] = rec;
        if (nc) {
            if (!(q->cte_cols[s] = malloc((size_t)nc * sizeof *q->cte_cols[s]))) return oom(b);
            memcpy(q->cte_cols[s], cols, (size_t)nc * sizeof *q->cte_cols[s]);
            q->cte_ncols[s] = nc;
        }
    } while (tok(b, K_COMMA));
    return 0;
}

/* the text: [WITH ...] query [;], nothing after; no parameter anywhere */
static int parse_text(ab *b, aq *q)
{
    if (lex(b)) return -1;
    if (b->nt == 0 || (b->nt == 1 && b->t[0].k == K_SEMI)) return fail(b, "an empty text");
    for (uint32_t i = 0; i < b->nt; i++)
        if (b->t[i].k == K_PARAM) return fail(b, "a view's query takes no parameter ($n)");
    b->q = q;
    if (kw(b, "with")) {
        if (parse_with_list(b, q)) return -1;
        if (kwat(b, b->i, "insert")) return fail(b, "a view's text is a query");
        if (parse_query(b, q)) return -1;
    } else if (kwat(b, b->i, "select") || b->t[b->i].k == K_LP) {
        if (parse_query(b, q)) return -1;
    } else {
        return fail(b, "a view's text is a query");
    }
    tok(b, K_SEMI);
    return b->t[b->i].k == K_EOF ? 0 : fail(b, "expected the end of the query at offset %u", b->t[b->i].off);
}

/* the engine's rules for a view's query: * nowhere but in an EXISTS's own list, no FOR UPDATE, no AS OF */
static int shape(ab *b, const aq *q, bool exists)
{
    if (q->star && !exists) return fail(b, "a view's query names its columns: * (but in an EXISTS)");
    if (q->for_update) return fail(b, "FOR UPDATE in a view's query");
    if (q->has_asof) return fail(b, "AS OF in a view's query");
    for (uint8_t i = 0; i < q->nsub; i++)
        if (shape(b, q->sub[i], q->sub_kind[i] == SUB_EXPR && q->sub_subk[i] == S_EXISTS)) return -1;
    for (uint8_t i = 0; i < q->narm; i++)
        if (shape(b, q->arm[i], false)) return -1;
    return 0;
}

/* ---- the binder ------------------------------------------------------------------------------------------------- */

#undef X
#define QX(q, k) (&(q)->ex[(k)])

static bool num(uint8_t t) { return t == T_INT64 || t == T_DECIMAL || t == T_FLOAT64; }

static const char *tname(uint8_t t)
{
    static const char *const N[] = {"NULL", "INT64", "DECIMAL", "TEXT", "BOOL", "TIMESTAMP", "FLOAT64", "TIMESTAMPTZ"};
    return t <= T_TIMESTAMPTZ ? N[t] : "?";
}

static int dep_note(ab *b, uint8_t kind, uint32_t id)
{
    for (uint16_t i = 0; i < b->ndeps; i++)
        if (b->dkind[i] == kind && b->did[i] == id) return 0;
    if (b->ndeps >= AB_MAX_DEPS) return fail(b, "a view's query names more than %u tables and views", AB_MAX_DEPS);
    b->dkind[b->ndeps] = kind;
    b->did[b->ndeps++] = id;
    return 0;
}

static int bind_query(ab *b, const aq *q, const scope *up, int mode, ab_col *out, uint16_t *nout);
static int walk(ab *b, const scope *sc, uint16_t k);

static void rel_free(rel *r)
{
    free(r->cols);
    r->cols = NULL;
    r->ncols = 0;
}

static int rel_set(ab *b, rel *r, const char *name, const ab_col *cols, uint16_t n)
{
    snprintf(r->name, sizeof r->name, "%s", name);
    r->ncols = n;
    r->cols = malloc((n ? n : 1u) * sizeof *r->cols);
    if (!r->cols) return oom(b);
    if (n) memcpy(r->cols, cols, n * sizeof *r->cols);
    return 0;
}

/* a row set's columns (a derived table, a WITH): each named within 63 bytes, once, typed, a DECIMAL within 18 places */
static int rowset_rules(ab *b, const ab_col *c, uint16_t n)
{
    for (uint16_t i = 0; i < n; i++) {
        if (strlen(c[i].name) > MAX_IDENT) return fail(b, "a nested SELECT's column name of more than %u bytes", MAX_IDENT);
        for (uint16_t j = 0; j < i; j++)
            if (!strcmp(c[i].name, c[j].name)) return fail(b, "a nested SELECT names two columns %s", c[i].name);
        if (!c[i].type) return fail(b, "a nested SELECT's column %s has no type", c[i].name);
        if (c[i].type == T_DECIMAL && c[i].scale > 18)
            return fail(b, "a nested SELECT's DECIMAL %s has more than 18 places", c[i].name);
    }
    return 0;
}

static int cte_push(ab *b, const char *name, const ab_col *cols, uint16_t n)
{
    if (b->nctes >= MAX_CTES) return fail(b, "more than %u WITH row sets in view", MAX_CTES);
    if (!b->ctes && !(b->ctes = calloc(MAX_CTES, sizeof *b->ctes))) return oom(b);
    cte *c = &b->ctes[b->nctes];
    snprintf(c->name, sizeof c->name, "%s", name);
    c->ncols = n;
    if (!(c->cols = malloc((n ? n : 1u) * sizeof *c->cols))) return oom(b);
    if (n) memcpy(c->cols, cols, n * sizeof *c->cols);
    b->nctes++;
    return 0;
}

static void cte_pop(ab *b, uint32_t mark)
{
    while (b->nctes > mark) {
        b->nctes--;
        free(b->ctes[b->nctes].cols);
        b->ctes[b->nctes].cols = NULL;
    }
}

/* a strict UTF-8 prefix (Unicode's Table 3-7): where a name's cut split a character */
static bool utf8_ok(const char *s, size_t n)
{
    const unsigned char *p = (const unsigned char *)s;
    size_t i = 0;
    while (i < n) {
        unsigned c = p[i];
        size_t k;
        unsigned lo = 0x80, hi = 0xBF;
        if (c < 0x80) {
            i++;
            continue;
        } else if (c >= 0xC2 && c <= 0xDF) k = 1;
        else if (c >= 0xE0 && c <= 0xEF) {
            k = 2;
            if (c == 0xE0) lo = 0xA0;
            if (c == 0xED) hi = 0x9F;
        } else if (c >= 0xF0 && c <= 0xF4) {
            k = 3;
            if (c == 0xF0) lo = 0x90;
            if (c == 0xF4) hi = 0x8F;
        } else {
            return false;
        }
        if (k > n - i - 1) return false; /* the cut split it */
        if (p[i + 1] < lo || p[i + 1] > hi) return false;
        for (size_t j = 2; j <= k; j++)
            if (p[i + j] < 0x80 || p[i + j] > 0xBF) return false;
        i += k + 1;
    }
    return true;
}

/* a result column's name, as the engine names it: the alias; AVG of a bare column avg_c; a bare column its own; a tree
 * its text (control characters as spaces, runs of spaces one, none at either end, cut at 70 bytes on a character); an
 * aggregate of a bare column count, count_c, sum_c, min_c, max_c */
static void item_name(const ab *b, const aq *q, const aitem *it, char out[72])
{
    static const char *const AN[] = {"", "count", "count", "sum", "min", "max", "avg"};
    const xn *x = QX(q, it->ex);
    char col[64];
    if (it->alias[0]) {
        snprintf(out, 72, "%s", it->alias);
        return;
    }
    if (it->shape == 0 && x->op == X_AGG && x->agg == A_AVG && !x->dist && !x->x3 && x->l && QX(q, x->l)->op == X_COL) {
        fold(b->s + QX(q, x->l)->off, QX(q, x->l)->len, col);
        snprintf(out, 72, "avg_%s", col);
        return;
    }
    if (it->shape == 1) {
        fold(b->s + x->off, x->len, col);
        snprintf(out, 72, "%s", col);
        return;
    }
    if (it->shape == 2) {
        if (x->agg == A_COUNT_STAR) {
            snprintf(out, 72, "count");
            return;
        }
        fold(b->s + QX(q, x->l)->off, QX(q, x->l)->len, col);
        snprintf(out, 72, "%s_%s", AN[x->agg], col);
        return;
    }
    size_t k = 0;
    for (uint32_t i = 0; i < it->len && k + 1 < 71; i++) {
        char c = b->s[it->off + i];
        if ((unsigned char)c < 0x20) c = ' ';
        if (c != ' ' || (k && out[k - 1] != ' ')) out[k++] = c;
    }
    while (k && out[k - 1] == ' ') k--;
    while (k && !utf8_ok(out, k)) k--;
    out[k] = 0;
}

/* a name in a FROM: this statement's own derived table by its name, a visible WITH row set (the latest), the catalog
 * (a dependency) */
static int from_name(ab *b, const aq *q, const char *name, int mode, rel *r, const char *as)
{
    for (uint8_t i = 0; i < q->nsub; i++)
        if (q->sub_kind[i] == SUB_DERIVED && !strcmp(q->sub_name[i], name)) {
            ab_col cols[MAX_COLS];
            uint16_t n = 0;
            if (bind_query(b, q->sub[i], NULL, mode, cols, &n) || (mode == M_TYPED && rowset_rules(b, cols, n))) return -1;
            return rel_set(b, r, as, cols, n);
        }
    for (uint32_t k = b->nctes; k-- > 0;)
        if (!strcmp(b->ctes[k].name, name)) return rel_set(b, r, as, b->ctes[k].cols, b->ctes[k].ncols);
    ab_rel cr;
    memset(&cr, 0, sizeof cr);
    if (!b->lookup || !b->lookup(b->arg, name, &cr)) return fail(b, "no table %s", name);
    if (cr.kind != DEP_TABLE && cr.kind != DEP_VIEW) return fail(b, "the catalog's %s is neither a table nor a view", name);
    if (cr.ncols > MAX_COLS) return fail(b, "the catalog's %s has more than %u columns", name, MAX_COLS);
    if (dep_note(b, cr.kind, cr.id)) return -1;
    return rel_set(b, r, as, cr.cols, cr.ncols);
}

static int find_col(const rel *r, const char *name)
{
    for (uint16_t c = 0; c < r->ncols; c++)
        if (!strcmp(r->cols[c].name, name)) return c;
    return -1;
}

/* a column in one scope: 1 found, 0 not here (an unqualified one, or a qualifier naming no relation here: the scope
 * around), -1 refused (a qualifier naming a relation here that lacks it, the nearest scope's: C2; or ambiguous) */
static int scope_col(ab *b, const scope *s, const char *qual, const char *name, ty *out)
{
    if (!s->nr) return 0;
    if (qual[0] && strcmp(qual, s->r[0].name) && (s->nr < 2 || strcmp(qual, s->r[1].name))) return 0;
    int found = 0, side = 0, col = -1;
    for (int k = 0; k < s->nr; k++) {
        if (qual[0] && strcmp(qual, s->r[k].name)) continue;
        int c = find_col(&s->r[k], name);
        if (c < 0) continue;
        if (found++) {
            bool used = false;
            for (uint8_t u = 0; u < s->q->nusing; u++) used |= !strcmp(s->q->using_col[u], name);
            if (!used || s->q->join == J_FULL) return fail(b, "column %s is in both tables: qualify it", name);
            if (s->q->join != J_RIGHT) break; /* the kept side's: side 1's (RIGHT: side 2's) */
        }
        side = k;
        col = c;
    }
    if (!found) return qual[0] ? fail(b, "no column %s in %s", name, qual) : 0;
    out->t = s->r[side].cols[col].type;
    out->s = s->r[side].cols[col].scale;
    return 1;
}

static int col_of(ab *b, const scope *sc, const xn *x, ty *out)
{
    char qual[64] = "", name[64];
    if (x->qlen) fold(b->s + x->qoff, x->qlen, qual);
    fold(b->s + x->off, x->len, name);
    for (const scope *s = sc; s; s = s->up) {
        int r = scope_col(b, s, qual, name, out);
        if (r) return r < 0 ? -1 : 0;
    }
    return fail(b, "no column %s", name);
}

/* a list's elements in order (a balanced tree of X_LIST) */
static int list_items(ab *b, const aq *q, uint16_t k, uint16_t *el, unsigned *n, unsigned cap)
{
    if (!k) return 0;
    if (QX(q, k)->op == X_LIST) return list_items(b, q, QX(q, k)->l, el, n, cap) || list_items(b, q, QX(q, k)->r, el, n, cap);
    if (*n >= cap) return fail(b, "a list of more than %u values", cap);
    el[(*n)++] = k;
    return 0;
}

static int type_of(ab *b, const scope *sc, uint16_t k, bool null_ok, ty *out);

/* the arithmetic rule: INT64 with INT64 INT64; with a DECIMAL a DECIMAL (+ - % the larger scale, * their sum, / the
 * larger plus six, within 38); anything with FLOAT64 FLOAT64 (% refused) */
static int arith(ab *b, uint8_t op, ty l, ty r, ty *out)
{
    if (!num(l.t) || !num(r.t)) return fail(b, "arithmetic takes INT64, DECIMAL and FLOAT64 values");
    if (l.t == T_FLOAT64 || r.t == T_FLOAT64) {
        if (op == X_MOD) return fail(b, "%% is not defined on FLOAT64");
        *out = (ty){T_FLOAT64, 0};
        return 0;
    }
    if (l.t == T_INT64 && r.t == T_INT64) {
        *out = (ty){T_INT64, 0};
        return 0;
    }
    int s1 = l.t == T_DECIMAL ? l.s : 0, s2 = r.t == T_DECIMAL ? r.s : 0, big = s1 > s2 ? s1 : s2;
    int s = op == X_MUL ? s1 + s2 : op == X_DIV ? big + 6 : big;
    if (s > MAX_SCALE) return fail(b, "a DECIMAL result of more than %u decimal places", MAX_SCALE);
    *out = (ty){T_DECIMAL, (uint8_t)s};
    return 0;
}

/* one type for values (CASE's results, COALESCE's, LAG's value and default): equal, or INT64 with DECIMAL as a DECIMAL at
 * the larger scale; an untyped NULL takes the others'. ts: a string literal beside a TIMESTAMP is one */
static int unify(ab *b, ty *acc, ty v, const char *what)
{
    if (!v.t) return 0;
    if (!acc->t) {
        *acc = v;
        return 0;
    }
    if (acc->t == v.t) {
        if (v.t == T_DECIMAL && v.s > acc->s) acc->s = v.s;
        return 0;
    }
    if ((acc->t == T_INT64 && v.t == T_DECIMAL) || (acc->t == T_DECIMAL && v.t == T_INT64)) {
        uint8_t a = acc->t == T_DECIMAL ? acc->s : 0, c = v.t == T_DECIMAL ? v.s : 0;
        *acc = (ty){T_DECIMAL, a > c ? a : c};
        return 0;
    }
    return fail(b, "%s %s and %s: values are not converted", what, tname(acc->t), tname(v.t));
}

static bool str_lit(const aq *q, uint16_t k) { return QX(q, k)->op == X_LIT && QX(q, k)->lit == L_STR; }

static int unify_all(ab *b, const scope *sc, const uint16_t *v, unsigned n, const char *what, ty *out)
{
    ty t[MAX_ARGS + 1];
    uint8_t ts = 0; /* a TIMESTAMP or (P2) a TIMESTAMPTZ among them: a string literal is of its type */
    for (unsigned i = 0; i < n; i++) {
        if (type_of(b, sc, v[i], true, &t[i])) return -1;
        if (t[i].t == T_TIMESTAMP || t[i].t == T_TIMESTAMPTZ) ts = t[i].t;
    }
    *out = (ty){0, 0};
    for (unsigned i = 0; i < n; i++) {
        ty x = ts && str_lit(sc->q, v[i]) ? (ty){ts, 0} : t[i];
        if (unify(b, out, x, what)) return -1;
    }
    return out->t ? 0 : fail(b, "%s NULL alone has no type", what);
}

static int fn_args(ab *b, unsigned n, unsigned lo, unsigned hi)
{
    return n >= lo && n <= hi ? 0 : fail(b, "a function of %u to %u arguments given %u", lo, hi, n);
}

static int fn_type(ab *b, const scope *sc, const xn *x, ty *out)
{
    const aq *q = sc->q;
    uint16_t v[MAX_ARGS + 1];
    unsigned n = 0;
    if (list_items(b, q, x->l, v, &n, MAX_ARGS)) return -1;
    if (x->fn == F_COALESCE) return fn_args(b, n, 1, MAX_ARGS) || unify_all(b, sc, v, n, "COALESCE of", out);
    ty a[MAX_ARGS + 1];
    for (unsigned i = 0; i < n; i++)
        if (type_of(b, sc, v[i], x->fn == F_NULLIF && i == 1, &a[i])) return -1;
    *out = (ty){0, 0};
    switch (x->fn) {
    case F_ABS:
    case F_SIGN:
    case F_CEIL:
    case F_FLOOR:
        if (fn_args(b, n, 1, 1)) return -1;
        if (!num(a[0].t)) return fail(b, "that function takes a number");
        *out = (ty){x->fn == F_SIGN ? T_INT64 : a[0].t, x->fn == F_ABS && a[0].t == T_DECIMAL ? a[0].s : 0};
        return 0;
    case F_ROUND: {
        if (fn_args(b, n, 1, 2)) return -1;
        if (!num(a[0].t)) return fail(b, "ROUND takes a number");
        long d = 0;
        if (n == 2) { /* the places: an integer constant */
            const xn *p = QX(q, v[1]);
            if (p->op != X_LIT || p->lit != L_INT || p->len > 3) return fail(b, "ROUND's places are an integer constant");
            d = strtol(b->s + p->off, NULL, 10);
            if (p->neg) d = -d;
            if (d < 0 || d > MAX_SCALE) return fail(b, "ROUND's places are 0 to %u", MAX_SCALE);
        }
        if (a[0].t == T_FLOAT64 && d) return fail(b, "ROUND of a FLOAT64 rounds to an integer");
        *out = (ty){a[0].t, a[0].t == T_DECIMAL ? (uint8_t)(a[0].s < d ? a[0].s : d) : 0};
        return 0;
    }
    case F_MOD: return fn_args(b, n, 2, 2) || arith(b, X_MOD, a[0], a[1], out);
    case F_LOWER:
    case F_UPPER:
    case F_LENGTH:
    case F_TRIM:
    case F_LTRIM:
    case F_RTRIM:
        if (fn_args(b, n, 1, 1)) return -1;
        if (a[0].t != T_TEXT) return fail(b, "that function takes a TEXT value");
        *out = (ty){x->fn == F_LENGTH ? T_INT64 : T_TEXT, 0};
        return 0;
    case F_REPLACE:
    case F_CONCAT:
        if (fn_args(b, n, x->fn == F_REPLACE ? 3 : 2, x->fn == F_REPLACE ? 3 : 2)) return -1;
        for (unsigned i = 0; i < n; i++)
            if (a[i].t != T_TEXT) return fail(b, "that function takes TEXT values");
        *out = (ty){T_TEXT, 0};
        return 0;
    case F_SUBSTR:
        if (fn_args(b, n, 2, 3)) return -1;
        if (a[0].t != T_TEXT || a[1].t != T_INT64 || (n == 3 && a[2].t != T_INT64))
            return fail(b, "SUBSTR takes a TEXT value, a start and a length");
        *out = (ty){T_TEXT, 0};
        return 0;
    case F_POSITION:
        if (fn_args(b, n, 2, 2)) return -1;
        if (a[0].t != T_TEXT || a[1].t != T_TEXT) return fail(b, "POSITION takes TEXT values");
        *out = (ty){T_INT64, 0};
        return 0;
    case F_DATE_TRUNC: { /* P2: date_trunc(unit, x [, zone]): x's type; the unit a string constant of PostgreSQL's names */
        static const char *const U[] = {"microseconds", "microsecond", "milliseconds", "millisecond", "second", "seconds",
                                        "minute", "minutes", "hour", "hours", "day", "days", "week", "weeks", "month",
                                        "months", "quarter", "quarters", "year", "years", "decade", "decades", "century",
                                        "centuries", "millennium", "millennia"};
        if (fn_args(b, n, 2, 3)) return -1;
        const xn *p = QX(q, v[0]);
        bool found = false;
        for (size_t i = 0; p->op == X_LIT && p->lit == L_STR && !found && i < sizeof U / sizeof *U; i++)
            found = strlen(U[i]) == p->len && !strncasecmp(U[i], b->s + p->off, p->len);
        if (!found) return fail(b, "date_trunc's unit is a string constant of a unit's name");
        if (a[1].t != T_TIMESTAMP && a[1].t != T_TIMESTAMPTZ) return fail(b, "date_trunc takes a TIMESTAMP or a TIMESTAMPTZ");
        if (n == 3 && (a[1].t != T_TIMESTAMPTZ || a[2].t != T_TEXT)) return fail(b, "date_trunc's zone is a TIMESTAMPTZ's");
        *out = (ty){a[1].t, 0};
        return 0;
    }
    case F_TIMEZONE: /* P2: x AT TIME ZONE z: a TIMESTAMPTZ's wall clock (TIMESTAMP), a TIMESTAMP's instant (TIMESTAMPTZ) */
        if (fn_args(b, n, 2, 2)) return -1;
        if (a[0].t != T_TEXT) return fail(b, "AT TIME ZONE takes a zone's name (TEXT)");
        if (a[1].t != T_TIMESTAMP && a[1].t != T_TIMESTAMPTZ) return fail(b, "AT TIME ZONE converts a TIMESTAMP or a TIMESTAMPTZ");
        *out = (ty){a[1].t == T_TIMESTAMP ? T_TIMESTAMPTZ : T_TIMESTAMP, 0};
        return 0;
    case F_NULLIF:
        if (fn_args(b, n, 2, 2)) return -1;
        if (!a[0].t) return fail(b, "NULLIF of NULL has no type");
        *out = a[0];
        return 0;
    default: return fail(b, "an unknown function");
    }
}

static int case_type(ab *b, const scope *sc, const xn *x, ty *out)
{
    const aq *q = sc->q;
    uint16_t w[MAX_ARGS + 1], v[MAX_ARGS + 1];
    unsigned nw = 0, nv = 0;
    if (walk(b, sc, x->l) || list_items(b, q, x->r, w, &nw, MAX_ARGS)) return -1;
    for (unsigned i = 0; i < nw; i++) {
        if (walk(b, sc, QX(q, w[i])->l)) return -1; /* the condition, or the value compared: no type it decides */
        v[nv++] = QX(q, w[i])->r;
    }
    if (x->x3) v[nv++] = x->x3;
    return unify_all(b, sc, v, nv, "a CASE of", out);
}

static int cast_type(ab *b, const scope *sc, const xn *x, ty *out)
{
    ty a;
    if (type_of(b, sc, x->l, true, &a)) return -1;
    bool to_num = num(x->ctype);
    bool ts2 = (a.t == T_TIMESTAMP || a.t == T_TIMESTAMPTZ) && (x->ctype == T_TIMESTAMP || x->ctype == T_TIMESTAMPTZ); /* P2 */
    if (a.t && a.t != T_TEXT && x->ctype != T_TEXT && a.t != x->ctype && !(num(a.t) && to_num) && !ts2)
        return fail(b, "CAST of %s to %s is not defined", tname(a.t), tname(x->ctype));
    *out = (ty){x->ctype, x->ctype == T_DECIMAL ? x->cscale : 0};
    return 0;
}

/* an aggregate's type (plain or over a window): COUNT INT64; SUM, MIN, MAX their argument's (SUM and AVG of numbers
 * alone); AVG of a FLOAT64 FLOAT64, of an INT64 or a DECIMAL(s) a DECIMAL at s + 6 (within 38) */
static int agg_type(ab *b, const scope *sc, uint8_t agg, uint16_t arg, ty *out)
{
    if (agg == A_COUNT_STAR || agg == A_COUNT) {
        *out = (ty){T_INT64, 0};
        return walk(b, sc, arg);
    }
    ty a;
    if (type_of(b, sc, arg, false, &a)) return -1;
    if ((agg == A_SUM || agg == A_AVG) && !num(a.t)) return fail(b, "SUM and AVG need an INT64, DECIMAL or FLOAT64 value");
    *out = a;
    if (agg == A_AVG && a.t != T_FLOAT64) {
        unsigned s = (a.t == T_DECIMAL ? a.s : 0u) + 6u;
        if (s > MAX_SCALE) return fail(b, "AVG of a DECIMAL past %u decimal places", MAX_SCALE - 6);
        *out = (ty){T_DECIMAL, (uint8_t)s};
    }
    return 0;
}

static int win_type(ab *b, const scope *sc, const xn *x, ty *out)
{
    const aq *q = sc->q;
    for (uint8_t i = 0; i < q->win[x->win].npart; i++)
        if (walk(b, sc, q->win[x->win].part[i])) return -1;
    for (uint8_t i = 0; i < q->win[x->win].nord; i++)
        if (walk(b, sc, q->win[x->win].ord[i])) return -1;
    switch (x->wf) {
    case W_ROW_NUMBER:
    case W_RANK:
    case W_DENSE_RANK:
    case W_NTILE:
        *out = (ty){T_INT64, 0};
        return walk(b, sc, x->l);
    case W_LAG:
    case W_LEAD:
    case W_FIRST:
    case W_LAST: {
        if (walk(b, sc, x->r)) return -1; /* LAG's and LEAD's offset */
        ty v, d = {0, 0};
        if (type_of(b, sc, x->l, true, &v)) return -1;
        if (x->x3 && (type_of(b, sc, x->x3, true, &d) || unify(b, &v, d, "LAG's and LEAD's value and default are")))
            return -1;
        *out = v.t ? v : (ty){T_TEXT, 0};
        return 0;
    }
    case W_AGG: return agg_type(b, sc, x->agg, x->l, out);
    default: return fail(b, "an unknown window function");
    }
}

/* the columns, none typed, a tree reads: its subqueries bound for their dependencies (DEPS), nothing else decided */
static int walk(ab *b, const scope *sc, uint16_t k)
{
    if (!k) return 0;
    const aq *q = sc->q;
    const xn *x = QX(q, k);
    if (x->op == X_SUBQ) {
        if (x->sub >= q->nsub) return fail(b, "a subquery this statement lacks");
        return bind_query(b, q->sub[x->sub], sc, M_DEPS, NULL, NULL);
    }
    if (x->op == X_WIN) {
        for (uint8_t i = 0; i < q->win[x->win].npart; i++)
            if (walk(b, sc, q->win[x->win].part[i])) return -1;
        for (uint8_t i = 0; i < q->win[x->win].nord; i++)
            if (walk(b, sc, q->win[x->win].ord[i])) return -1;
    }
    return walk(b, sc, x->l) || walk(b, sc, x->r) || walk(b, sc, x->x3) ? -1 : 0; /* height-bounded */
}

static int type_of(ab *b, const scope *sc, uint16_t k, bool null_ok, ty *out)
{
    const aq *q = sc->q;
    const xn *x = QX(q, k);
    ty l, r;
    switch (x->op) {
    case X_LIT:
        switch (x->lit) {
        case L_INT: *out = (ty){T_INT64, 0}; return 0;
        case L_DEC: { /* at its written scale; significant digits (not leading zeros) and the scale within 38 */
            uint32_t s = 0, digits = 0;
            bool point = false, sig = false;
            for (uint32_t i = 0; i < x->len; i++) {
                char c = b->s[x->off + i];
                if (c == '.') {
                    point = true;
                    continue;
                }
                s += point;
                if (sig || c != '0') sig = true, digits++;
            }
            if (digits > MAX_SCALE || s > MAX_SCALE) return fail(b, "a DECIMAL literal of more than %u digits", MAX_SCALE);
            *out = (ty){T_DECIMAL, (uint8_t)s};
            return 0;
        }
        case L_FLT: *out = (ty){T_FLOAT64, 0}; return 0;
        case L_STR: *out = (ty){T_TEXT, 0}; return 0;
        case L_BOOL: *out = (ty){T_BOOL, 0}; return 0;
        case L_TS: *out = (ty){T_TIMESTAMP, 0}; return 0;
        case L_TSTZ: *out = (ty){T_TIMESTAMPTZ, 0}; return 0; /* P2 */
        case L_NULL:
            if (!null_ok) return fail(b, "NULL cannot be an operand");
            *out = (ty){0, 0};
            return 0;
        default: return fail(b, "a parameter in a view's query");
        }
    case X_COL: return col_of(b, sc, x, out);
    case X_NEG:
        if (type_of(b, sc, x->l, false, &l)) return -1;
        if (!num(l.t)) return fail(b, "arithmetic takes INT64, DECIMAL and FLOAT64 values");
        *out = l;
        return 0;
    case X_ADD:
    case X_SUB:
    case X_MUL:
    case X_DIV:
    case X_MOD:
        if (type_of(b, sc, x->l, false, &l) || type_of(b, sc, x->r, false, &r)) return -1;
        return arith(b, x->op, l, r, out);
    case X_CMP:
    case X_AND:
    case X_OR:
    case X_NOT:
        *out = (ty){T_BOOL, 0};
        return walk(b, sc, k);
    case X_FN: return fn_type(b, sc, x, out);
    case X_CASE: return case_type(b, sc, x, out);
    case X_CAST: return cast_type(b, sc, x, out);
    case X_AGG:
        if (walk(b, sc, x->x3)) return -1; /* FILTER's condition */
        return agg_type(b, sc, x->agg, x->l, out);
    case X_WIN: return win_type(b, sc, x, out);
    case X_SUBQ: {
        if (x->sub >= q->nsub) return fail(b, "a subquery this statement lacks");
        if (x->subk != S_VALUE) {
            *out = (ty){T_BOOL, 0};
            return bind_query(b, q->sub[x->sub], sc, M_DEPS, NULL, NULL);
        }
        ab_col c[MAX_COLS];
        uint16_t n = 0;
        if (bind_query(b, q->sub[x->sub], sc, M_TYPED, c, &n)) return -1;
        if (n != 1) return fail(b, "a subquery as a value returns one column");
        *out = (ty){c[0].type, c[0].scale};
        return 0;
    }
    default: return fail(b, "an expression the binder does not know");
    }
}

/* a WITH row set: an ordinary one bound as any query; a RECURSIVE one that reads its own name in its second arm's FROM
 * is its base's columns (the step must fit them: the engine's rule, not a type this needs), the step bound for its
 * dependencies with the name visible; a column list renames either */
static int bind_cte(ab *b, const aq *q, uint8_t i, int mode, ab_col *cols, uint16_t *nc)
{
    const aq *c = q->sub[i];
    const char *name = q->sub_name[i];
    bool rec = q->sub_rec[i] && c->narm == 2 && c->arm[1]->narm == 0 && c->arm[1]->nfrom &&
               ((c->arm[1]->fsub[0] < 0 && !strcmp(c->arm[1]->fname[0], name)) ||
                (c->arm[1]->nfrom == 2 && c->arm[1]->fsub[1] < 0 && !strcmp(c->arm[1]->fname[1], name)));
    if (!rec) {
        if (bind_query(b, c, NULL, mode, cols, nc)) return -1;
    } else {
        if (bind_query(b, c->arm[0], NULL, mode, cols, nc)) return -1;
    }
    if (q->cte_ncols[i]) {
        if (mode == M_TYPED && q->cte_ncols[i] != *nc)
            return fail(b, "WITH %s names %u columns, its query yields %u", name, q->cte_ncols[i], *nc);
        for (uint8_t k = 0; k < q->cte_ncols[i] && k < *nc; k++) snprintf(cols[k].name, sizeof cols[k].name, "%s", q->cte_cols[i][k]);
    }
    if (mode == M_TYPED && rowset_rules(b, cols, *nc)) return -1;
    if (rec) {
        uint32_t mark = b->nctes;
        int rc = cte_push(b, name, cols, *nc) || bind_query(b, c->arm[1], NULL, M_DEPS, NULL, NULL) ? -1 : 0;
        cte_pop(b, mark);
        if (rc) return -1;
    }
    return 0;
}

static int bind_core(ab *b, const aq *q, const scope *up, int mode, ab_col *out, uint16_t *nout)
{
    scope sc;
    memset(&sc, 0, sizeof sc);
    sc.q = q;
    sc.up = up;
    int rc = 0;
    for (int s = 0; !rc && s < q->nfrom; s++) {
        const char *as = q->falias[s][0] ? q->falias[s] : q->fname[s];
        if (q->fsub[s] >= 0) {
            ab_col cols[MAX_COLS];
            uint16_t n = 0;
            rc = bind_query(b, q->sub[q->fsub[s]], NULL, mode, cols, &n) || (mode == M_TYPED && rowset_rules(b, cols, n)) ||
                 rel_set(b, &sc.r[s], as, cols, n);
        } else {
            rc = from_name(b, q, q->fname[s], mode, &sc.r[s], as);
        }
        if (!rc) sc.nr = (uint8_t)(s + 1);
    }
    if (!rc && mode == M_TYPED) {
        if (q->star) rc = fail(b, "* in a typed query");
        for (uint16_t i = 0; !rc && i < q->nitems; i++) {
            const aitem *it = &q->items[i];
            const xn *x = QX(q, it->ex);
            ty t = {0, 0};
            if (it->shape == 2) {
                if (x->agg == A_COUNT || x->agg == A_COUNT_STAR) t = (ty){T_INT64, 0};
                else if (!(rc = col_of(b, &sc, QX(q, x->l), &t)) && x->agg == A_SUM && !num(t.t))
                    rc = fail(b, "SUM needs an INT64, DECIMAL or FLOAT64 value");
            } else {
                rc = type_of(b, &sc, it->ex, true, &t);
            }
            if (rc) break;
            if (!t.t) t = (ty){T_TEXT, 0}; /* SELECT NULL: a TEXT NULL */
            item_name(b, q, it, out[i].name);
            out[i].type = t.t;
            out[i].scale = t.t == T_DECIMAL ? t.s : 0;
        }
        if (!rc) *nout = q->nitems;
    } else if (!rc) {
        for (uint16_t i = 0; !rc && i < q->nitems; i++) rc = walk(b, &sc, q->items[i].ex);
        if (nout) *nout = 0; /* DEPS: no column is typed, so none is handed on (nothing reads a DEPS relation's columns) */
    }
    if (!rc) rc = walk(b, &sc, q->on) || walk(b, &sc, q->where) || walk(b, &sc, q->having);
    for (uint8_t g = 0; !rc && g < q->ngroup; g++) rc = walk(b, &sc, q->group[g]);
    for (uint8_t o = 0; !rc && o < q->norder; o++) rc = walk(b, &sc, q->order[o]);
    rel_free(&sc.r[0]);
    rel_free(&sc.r[1]);
    return rc ? -1 : 0;
}

static int bind_query(ab *b, const aq *q, const scope *up, int mode, ab_col *out, uint16_t *nout)
{
    uint32_t mark = b->nctes;
    int rc = 0;
    for (uint8_t i = 0; !rc && i < q->nsub; i++) /* WITH's row sets, in order: each sees the ones before */
        if (q->sub_kind[i] == SUB_CTE) {
            ab_col cols[MAX_COLS];
            uint16_t n = 0;
            rc = bind_cte(b, q, i, mode, cols, &n) || cte_push(b, q->sub_name[i], cols, n);
        }
    if (!rc && q->narm) {
        ab_col acc[MAX_COLS], c[MAX_COLS];
        uint16_t na = 0, n = 0;
        for (uint8_t a = 0; !rc && a < q->narm; a++) {
            if ((rc = bind_query(b, q->arm[a], up, mode, a ? c : acc, a ? &n : &na))) break;
            if (!a || mode != M_TYPED) continue;
            if (n != na) {
                rc = fail(b, "a set operation's SELECTs return %u and %u columns", na, n);
                break;
            }
            for (uint16_t k = 0; !rc && k < na; k++) {
                ty t = {acc[k].type, acc[k].scale};
                if (!(rc = unify(b, &t, (ty){c[k].type, c[k].scale}, "a set operation's column is"))) {
                    acc[k].type = t.t;
                    acc[k].scale = t.t == T_DECIMAL ? t.s : 0;
                }
            }
        }
        if (!rc && out && mode == M_TYPED) {
            memcpy(out, acc, na * sizeof *out);
            *nout = na;
        } else if (!rc && nout) {
            *nout = 0; /* DEPS: as bind_core's */
        }
    } else if (!rc) {
        rc = bind_core(b, q, up, mode, out, nout);
    }
    cte_pop(b, mark);
    return rc ? -1 : 0;
}

static int cmp_dep(const void *x, const void *y)
{
    const uint32_t *a = x, *c = y;
    return a[0] != c[0] ? (a[0] < c[0] ? -1 : 1) : a[1] != c[1] ? (a[1] < c[1] ? -1 : 1) : 0;
}

int ab_bind(const char *text, size_t len, ab_lookup_fn lookup, void *arg, ab_result *r, char *err, size_t errn)
{
    ab b;
    memset(&b, 0, sizeof b);
    b.s = text;
    b.n = len;
    b.err = err;
    b.errn = errn;
    b.lookup = lookup;
    b.arg = arg;
    if (errn) err[0] = 0;
    memset(r, 0, sizeof *r);
    if (!len || len > MAX_VIEW_TEXT) return fail(&b, "a view's text of %zu bytes", len);
    aq *q = aq_new(&b);
    int rc = q ? 0 : -1;
    ab_col cols[MAX_COLS];
    uint16_t n = 0;
    if (!rc) rc = parse_text(&b, q) || shape(&b, q, false) || bind_query(&b, q, NULL, M_TYPED, cols, &n) ? -1 : 0;
    for (uint16_t c = 0; !rc && c < n; c++) {
        if (!cols[c].type) rc = fail(&b, "its column %u has no type", c + 1u);
        else if (cols[c].type == T_DECIMAL && cols[c].scale > 18) rc = fail(&b, "its DECIMAL column %u has more than 18 places", c + 1u);
    }
    if (!rc && (n < 1 || n > AB_MAX_COLS)) rc = fail(&b, "a view of %u columns", n);
    if (!rc) {
        uint32_t d[AB_MAX_DEPS][2];
        for (uint16_t i = 0; i < b.ndeps; i++) d[i][0] = b.dkind[i], d[i][1] = b.did[i];
        qsort(d, b.ndeps, sizeof d[0], cmp_dep);
        r->ncols = n;
        memcpy(r->cols, cols, n * sizeof *cols);
        r->ndeps = b.ndeps;
        for (uint16_t i = 0; i < b.ndeps; i++) r->dep_kind[i] = (uint8_t)d[i][0], r->dep_id[i] = d[i][1];
    }
    cte_pop(&b, 0);
    free(b.ctes);
    free(b.t);
    aq_free(q);
    return rc;
}

int ab_names(const char *text, size_t len, const char *ident, char *err, size_t errn)
{
    ab b;
    memset(&b, 0, sizeof b);
    b.s = text;
    b.n = len;
    b.err = err;
    b.errn = errn;
    if (errn) err[0] = 0;
    if (lex(&b)) {
        free(b.t);
        return -1;
    }
    size_t il = strlen(ident);
    int has = 0;
    for (uint32_t k = 0; k < b.nt && !has; k++)
        has = b.t[k].k == K_ID && b.t[k].len == il && strncasecmp(text + b.t[k].off, ident, il) == 0;
    free(b.t);
    return has;
}
