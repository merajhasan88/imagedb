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

enum { T_INT64 = 1, T_DECIMAL = 2, T_TEXT = 3, T_BOOL = 4, T_TIMESTAMP = 5, T_FLOAT64 = 6, T_TIMESTAMPTZ = 7, T_DATE = 8, T_TIME = 9,
       T_UUID = 10, T_BYTEA = 11, T_INTERVAL = 12, T_ENUM = 13 }; /* F3d; F3f; F3g: a label's ordinal, its type's id beside */
enum { DEP_TABLE = 1, DEP_VIEW = 2, DEP_TYPE = 3 }; /* F3g: a CAST's ENUM type */

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

enum { L_INT = 1, L_DEC, L_FLT, L_STR, L_PARAM, L_BOOL, L_TS, L_NULL, L_TSTZ, L_DATE, L_TIME, L_UUID, L_BYTEA, L_INTERVAL }; /* L_TSTZ: P2; L_DATE,
                                                                                                   * L_TIME: F3b; L_UUID,
                                                                                                   * L_BYTEA: F3d; L_INTERVAL: F3f */
enum { X_LIT = 1, X_COL, X_NEG, X_ADD, X_SUB, X_MUL, X_DIV, X_MOD, X_CMP, X_AND, X_OR, X_NOT, X_FN, X_CASE, X_WHEN, X_CAST,
       X_AGG, X_WIN, X_SUBQ, X_LIST };
enum { C_EQ = 1, C_NE, C_LT, C_LE, C_GT, C_GE, C_BETWEEN, C_ISNULL, C_NOTNULL, C_IN, C_NOTIN, C_LIKE, C_NOTLIKE };
enum { F_ABS = 1, F_SIGN, F_ROUND, F_CEIL, F_FLOOR, F_MOD, F_LENGTH, F_SUBSTR, F_TRIM, F_LTRIM, F_RTRIM, F_POSITION,
       F_COALESCE, F_NULLIF, F_LOWER, F_UPPER, F_REPLACE, F_CONCAT, F_DATE_TRUNC, F_TIMEZONE, /* the last two: P2 */
       F_NOW, F_LOCALTIMESTAMP, F_CURRENT_DATE, F_LOCALTIME, /* F2a: the clock */
       F_OCTET_LENGTH }; /* F3d: a TEXT's or a BYTEA's bytes (a view calls no gen_random_uuid: the engine refuses it) */
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
    uint16_t e;   /* F3g: an ENUM's type id (0 for every other type): two ENUMs meet within one type alone */
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
    bool in_win; /* inside a window's definition: no window function there (the engine's win_ok; fuzz_abind found an
                  * overflow of a window's keys by one nested in them, 2026-11-09) */
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
             {"replace", F_REPLACE},  {"date_trunc", F_DATE_TRUNC}, {"timezone", F_TIMEZONE}, /* P2 */
             {"now", F_NOW},                                                                 /* F2a */
             {"octet_length", F_OCTET_LENGTH}};                                              /* F3d */
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
    } else if (kind_at(b, b->i) == K_RP) { /* F2a: now() */
        b->i++;
        args = 0;
        n = 0;
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
    if (kw(b, "int64") || kw(b, "bigint") || kw(b, "int8") || kw(b, "int") || kw(b, "integer") || kw(b, "int4") ||
        kw(b, "smallint") || kw(b, "int2"))
        *type = T_INT64; /* F3a: every width an INT64 value (a CAST's range is the run's, not the type's) */
    else if (kw(b, "text")) *type = T_TEXT;
    else if (kw(b, "varchar") || (kwat(b, b->i, "character") && kwat(b, b->i + 1, "varying") && (b->i += 2))) {
        *type = T_TEXT; /* F3c: VARCHAR(n), a TEXT to a view's types (its length the run's rule, as a width is) */
        if (tok(b, K_LP)) {
            const tk *t = &b->t[b->i];
            if (t->k != K_INT || t->len > 5 || atoi(b->s + t->off) < 1 || atoi(b->s + t->off) > 65535)
                return fail(b, "VARCHAR(n) needs 1 <= n <= 65535");
            b->i++;
            if (expect(b, K_RP, ")")) return -1;
        }
    }
    else if (kw(b, "bool") || kw(b, "boolean")) *type = T_BOOL;
    else if (kw(b, "timestamptz")) *type = T_TIMESTAMPTZ; /* P2 */
    else if (kw(b, "date")) *type = T_DATE; /* F3b */
    else if (kw(b, "uuid")) *type = T_UUID; /* F3d */
    else if (kw(b, "bytea")) *type = T_BYTEA;
    else if (kw(b, "interval")) { /* F3f: its fields and precision, as the engine refuses them */
        *type = T_INTERVAL;
        if (kind_at(b, b->i) == K_LP) return fail(b, "INTERVAL(p) is not supported");
    }
    else if (kw(b, "time")) {
        *type = T_TIME;
        if ((kwat(b, b->i, "with") || kwat(b, b->i, "without")) && kwat(b, b->i + 1, "time") && kwat(b, b->i + 2, "zone")) {
            if (kwat(b, b->i, "with")) return fail(b, "TIME WITH TIME ZONE is not supported");
            b->i += 3;
        }
    }
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
        if (t->k != K_INT || t->len > 2) return fail(b, "DECIMAL(p,s) needs 1 <= p <= 38 and 0 <= s <= p");
        p = (uint32_t)atoi(b->s + t->off) % 1000u;
        b->i++;
        if (tok(b, K_COMMA)) {
            t = &b->t[b->i];
            if (t->k != K_INT || t->len > 2) return fail(b, "DECIMAL(p,s) needs 1 <= p <= 38 and 0 <= s <= p");
            s = (uint32_t)atoi(b->s + t->off) % 1000u;
            b->i++;
        }
        if (expect(b, K_RP, ")")) return -1;
        if (p < 1 || p > 38 || s > p) return fail(b, "DECIMAL(p,s) needs 1 <= p <= 38 and 0 <= s <= p"); /* F3e */
        *scale = (uint8_t)s;
    } else if (kw(b, "float64") || kw(b, "float8") || kw(b, "float")) {
        *type = T_FLOAT64;
    } else if (kw(b, "double")) {
        kw(b, "precision");
        *type = T_FLOAT64;
    } else if (b->t[b->i].k == K_ID && !reserved(b, b->i)) { /* F3g: an ENUM type by its name (the caller keeps the token) */
        *type = T_ENUM;
        b->i++;
    } else {
        return fail(b, "expected a type at offset %u", b->t[b->i].off);
    }
    return 0;
}

static int cast_expr(ab *b, uint16_t *out, unsigned d) /* CAST eaten */
{
    uint16_t a;
    uint8_t t = 0, s = 0; /* set by col_type on its every success */
    uint32_t tat = 0; /* F3g: the type's name token, an ENUM's */
    if (expect(b, K_LP, "(") || bexpr(b, &a, d + 1) || expect_kw(b, "as") || ((tat = b->i), col_type(b, &t, &s)) ||
        expect(b, K_RP, ")") || nnew(b, X_CAST, a, 0, out))
        return -1;
    X(*out)->ctype = t;
    X(*out)->cscale = s;
    if (t == T_ENUM) X(*out)->off = b->t[tat].off, X(*out)->len = b->t[tat].len; /* F3g: resolved at binding (cast_type) */
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
    if (b->in_win) return fail(b, "a window function inside a window's definition");
    if (q->nwin >= MAX_WINDOWS) return fail(b, "more than %u window functions in one SELECT", MAX_WINDOWS);
    if (expect(b, K_LP, "(")) return -1;
    uint8_t w = q->nwin;
    memset(&q->win[w], 0, sizeof q->win[w]);
    b->in_win = true;
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
    b->in_win = false;
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
    if (kwat(b, i, "date") || kwat(b, i, "time")) return kind_at(b, i + 1) == K_STR; /* F3b */
    if (kwat(b, i, "interval")) return kind_at(b, i + 1) == K_STR; /* F3f */
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
    else if ((kwat(b, b->i, "date") || kwat(b, b->i, "time")) && kind_at(b, b->i + 1) == K_STR) { /* F3b */
        lit = kwat(b, b->i, "date") ? L_DATE : L_TIME;
        b->i++;
        t = &b->t[b->i];
    } else if (kwat(b, b->i, "interval") && kind_at(b, b->i + 1) == K_STR) { /* F3f: its text the engine's to check */
        lit = L_INTERVAL;
        b->i++;
        t = &b->t[b->i];
    } else if ((kwat(b, b->i, "uuid") || kwat(b, b->i, "bytea")) && kind_at(b, b->i + 1) == K_STR) { /* F3d */
        lit = kwat(b, b->i, "uuid") ? L_UUID : L_BYTEA;
        b->i++;
        t = &b->t[b->i];
    } else if (ts_literal_at(b, b->i)) { /* P2: TIMESTAMPTZ and TIMESTAMP WITH TIME ZONE its TIMESTAMPTZ */
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
    static const struct { /* F2a: the standard's clock values without parentheses (the engine's rule) */
        const char *name;
        uint8_t fn;
    } ck[] = {{"current_timestamp", F_NOW}, {"localtimestamp", F_LOCALTIMESTAMP}, {"current_date", F_CURRENT_DATE},
              {"localtime", F_LOCALTIME}};
    for (size_t i = 0; i < sizeof ck / sizeof *ck; i++)
        if (kw(b, ck[i].name)) {
            if (nnew(b, X_FN, 0, 0, out)) return -1;
            X(*out)->fn = ck[i].fn;
            return 0;
        }
    if (kwat(b, b->i, "current_time")) return fail(b, "CURRENT_TIME is a time with a zone");
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
    static const char *const N[] = {"NULL", "INT64", "DECIMAL", "TEXT", "BOOL", "TIMESTAMP", "FLOAT64", "TIMESTAMPTZ", "DATE", "TIME",
                                    "UUID", "BYTEA", "INTERVAL"};
    return t <= T_INTERVAL ? N[t] : t == T_ENUM ? "ENUM" : "?";
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

/* a row set's columns (a derived table, a WITH): each named within 63 bytes, once, typed, a DECIMAL within 38 places (F3e) */
static int rowset_rules(ab *b, const ab_col *c, uint16_t n)
{
    for (uint16_t i = 0; i < n; i++) {
        if (strlen(c[i].name) > MAX_IDENT) return fail(b, "a nested SELECT's column name of more than %u bytes", MAX_IDENT);
        for (uint16_t j = 0; j < i; j++)
            if (!strcmp(c[i].name, c[j].name)) return fail(b, "a nested SELECT names two columns %s", c[i].name);
        if (!c[i].type) return fail(b, "a nested SELECT's column %s has no type", c[i].name);
        if (c[i].type == T_DECIMAL && c[i].scale > 38)
            return fail(b, "a nested SELECT's DECIMAL %s has more than 38 places", c[i].name);
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
    out->e = s->r[side].cols[col].eid; /* F3g */
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
    /* F3f: INTERVAL + or - INTERVAL, a TIMESTAMP or a DATE + or - an INTERVAL (a TIMESTAMP), TIMESTAMP - TIMESTAMP and
     * TIMESTAMPTZ - TIMESTAMPTZ (an INTERVAL), as the engine's imdb_x_type */
    if (l.t == T_INTERVAL || r.t == T_INTERVAL || (op == X_SUB && l.t == r.t && (l.t == T_TIMESTAMP || l.t == T_TIMESTAMPTZ))) {
        bool dl = l.t == T_TIMESTAMP || l.t == T_DATE, dr = r.t == T_TIMESTAMP || r.t == T_DATE;
        if (l.t == T_INTERVAL && r.t == T_INTERVAL && (op == X_ADD || op == X_SUB)) *out = (ty){T_INTERVAL, 0, 0};
        else if ((op == X_ADD || op == X_SUB) && dl && r.t == T_INTERVAL) *out = (ty){T_TIMESTAMP, 0, 0};
        else if (op == X_ADD && l.t == T_INTERVAL && dr) *out = (ty){T_TIMESTAMP, 0, 0};
        else if (op == X_SUB && l.t == r.t && l.t != T_INTERVAL) *out = (ty){T_INTERVAL, 0, 0};
        else return fail(b, "interval arithmetic: INTERVAL + or - INTERVAL, a TIMESTAMP or DATE + or - an INTERVAL, "
                            "TIMESTAMP - TIMESTAMP");
        return 0;
    }
    /* F3b: a DATE plus or minus days, DATE minus DATE (days), DATE plus TIME (a TIMESTAMP); the rest refused */
    if (l.t == T_DATE || r.t == T_DATE || l.t == T_TIME || r.t == T_TIME) {
        if (op == X_ADD && ((l.t == T_DATE && r.t == T_INT64) || (l.t == T_INT64 && r.t == T_DATE))) *out = (ty){T_DATE, 0, 0};
        else if (op == X_SUB && l.t == T_DATE && r.t == T_INT64) *out = (ty){T_DATE, 0, 0};
        else if (op == X_SUB && l.t == T_DATE && r.t == T_DATE) *out = (ty){T_INT64, 0, 0};
        else if (op == X_ADD && ((l.t == T_DATE && r.t == T_TIME) || (l.t == T_TIME && r.t == T_DATE))) *out = (ty){T_TIMESTAMP, 0, 0};
        else return fail(b, "date arithmetic: DATE + or - INT64, DATE - DATE, DATE + TIME");
        return 0;
    }
    if (!num(l.t) || !num(r.t)) return fail(b, "arithmetic takes INT64, DECIMAL and FLOAT64 values");
    if (l.t == T_FLOAT64 || r.t == T_FLOAT64) {
        if (op == X_MOD) return fail(b, "%% is not defined on FLOAT64");
        *out = (ty){T_FLOAT64, 0, 0};
        return 0;
    }
    if (l.t == T_INT64 && r.t == T_INT64) {
        *out = (ty){T_INT64, 0, 0};
        return 0;
    }
    int s1 = l.t == T_DECIMAL ? l.s : 0, s2 = r.t == T_DECIMAL ? r.s : 0, big = s1 > s2 ? s1 : s2;
    int s = op == X_MUL ? s1 + s2 : op == X_DIV ? big + 6 : big;
    if (s > MAX_SCALE) return fail(b, "a DECIMAL result of more than %u decimal places", MAX_SCALE);
    *out = (ty){T_DECIMAL, (uint8_t)s, 0};
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
    if (acc->t == v.t && v.t == T_ENUM && acc->e != v.e) return fail(b, "%s two ENUM types: values are not converted", what); /* F3g */
    if (acc->t == v.t) {
        if (v.t == T_DECIMAL && v.s > acc->s) acc->s = v.s;
        return 0;
    }
    if ((acc->t == T_INT64 && v.t == T_DECIMAL) || (acc->t == T_DECIMAL && v.t == T_INT64)) {
        uint8_t a = acc->t == T_DECIMAL ? acc->s : 0, c = v.t == T_DECIMAL ? v.s : 0;
        *acc = (ty){T_DECIMAL, a > c ? a : c, 0};
        return 0;
    }
    return fail(b, "%s %s and %s: values are not converted", what, tname(acc->t), tname(v.t));
}

static bool str_lit(const aq *q, uint16_t k) { return QX(q, k)->op == X_LIT && QX(q, k)->lit == L_STR; }

static int unify_all(ab *b, const scope *sc, const uint16_t *v, unsigned n, const char *what, ty *out)
{
    ty t[MAX_ARGS + 1];
    uint8_t ts = 0; /* a TIMESTAMP or (P2) a TIMESTAMPTZ among them: a string literal is of its type */
    uint16_t tse = 0; /* F3g: an ENUM's type id */
    for (unsigned i = 0; i < n; i++) {
        if (type_of(b, sc, v[i], true, &t[i])) return -1;
        if (t[i].t == T_TIMESTAMP || t[i].t == T_TIMESTAMPTZ || t[i].t == T_DATE || t[i].t == T_TIME || t[i].t == T_UUID ||
            t[i].t == T_BYTEA || t[i].t == T_INTERVAL || t[i].t == T_ENUM) /* F3f: a string literal beside an INTERVAL is one; F3g: an ENUM's label */
            ts = t[i].t, tse = t[i].e; /* F3b; F3d: a string literal beside a UUID or a BYTEA is one, as the engine's is_ts */
    }
    *out = (ty){0, 0, 0};
    for (unsigned i = 0; i < n; i++) {
        ty x = ts && str_lit(sc->q, v[i]) ? (ty){ts, 0, tse} : t[i];
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
    if (x->fn == F_CONCAT && n == 2) /* F3d: a string literal beside a BYTEA is one, as the engine binds it */
        for (unsigned i = 0; i < 2; i++)
            if (a[1 - i].t == T_BYTEA && str_lit(q, v[i])) a[i] = (ty){T_BYTEA, 0, 0};
    *out = (ty){0, 0, 0};
    switch (x->fn) {
    case F_NOW: /* F2a: the clock's types; their values are a run's, never a bind's */
    case F_LOCALTIMESTAMP:
    case F_CURRENT_DATE:
    case F_LOCALTIME:
        if (fn_args(b, n, 0, 0)) return -1;
        *out = (ty){x->fn == F_NOW ? T_TIMESTAMPTZ : x->fn == F_LOCALTIMESTAMP ? T_TIMESTAMP : x->fn == F_CURRENT_DATE ? T_DATE : T_TIME, 0, 0};
        return 0;
    case F_ABS:
    case F_SIGN:
    case F_CEIL:
    case F_FLOOR:
        if (fn_args(b, n, 1, 1)) return -1;
        if (!num(a[0].t)) return fail(b, "that function takes a number");
        *out = (ty){x->fn == F_SIGN ? T_INT64 : a[0].t, x->fn == F_ABS && a[0].t == T_DECIMAL ? a[0].s : 0, 0};
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
        *out = (ty){a[0].t, a[0].t == T_DECIMAL ? (uint8_t)(a[0].s < d ? a[0].s : d) : 0, 0};
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
        if (x->fn == F_LENGTH && a[0].t == T_BYTEA) { /* F3d: its bytes */
            *out = (ty){T_INT64, 0, 0};
            return 0;
        }
        if (a[0].t != T_TEXT) return fail(b, "that function takes a TEXT value");
        *out = (ty){x->fn == F_LENGTH ? T_INT64 : T_TEXT, 0, 0};
        return 0;
    case F_OCTET_LENGTH: /* F3d */
        if (fn_args(b, n, 1, 1)) return -1;
        if (a[0].t != T_TEXT && a[0].t != T_BYTEA) return fail(b, "OCTET_LENGTH takes a TEXT or a BYTEA");
        *out = (ty){T_INT64, 0, 0};
        return 0;
    case F_REPLACE:
    case F_CONCAT:
        if (fn_args(b, n, x->fn == F_REPLACE ? 3 : 2, x->fn == F_REPLACE ? 3 : 2)) return -1;
        if (x->fn == F_CONCAT && a[0].t == T_BYTEA && a[1].t == T_BYTEA) { /* F3d */
            *out = (ty){T_BYTEA, 0, 0};
            return 0;
        }
        for (unsigned i = 0; i < n; i++)
            if (a[i].t != T_TEXT) return fail(b, "that function takes TEXT values");
        *out = (ty){T_TEXT, 0, 0};
        return 0;
    case F_SUBSTR:
        if (fn_args(b, n, 2, 3)) return -1;
        if (a[0].t != T_TEXT || a[1].t != T_INT64 || (n == 3 && a[2].t != T_INT64))
            return fail(b, "SUBSTR takes a TEXT value, a start and a length");
        *out = (ty){T_TEXT, 0, 0};
        return 0;
    case F_POSITION:
        if (fn_args(b, n, 2, 2)) return -1;
        if (a[0].t != T_TEXT || a[1].t != T_TEXT) return fail(b, "POSITION takes TEXT values");
        *out = (ty){T_INT64, 0, 0};
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
        *out = (ty){a[1].t, 0, 0};
        return 0;
    }
    case F_TIMEZONE: /* P2: x AT TIME ZONE z: a TIMESTAMPTZ's wall clock (TIMESTAMP), a TIMESTAMP's instant (TIMESTAMPTZ) */
        if (fn_args(b, n, 2, 2)) return -1;
        if (a[0].t != T_TEXT) return fail(b, "AT TIME ZONE takes a zone's name (TEXT)");
        if (a[1].t != T_TIMESTAMP && a[1].t != T_TIMESTAMPTZ) return fail(b, "AT TIME ZONE converts a TIMESTAMP or a TIMESTAMPTZ");
        *out = (ty){a[1].t == T_TIMESTAMP ? T_TIMESTAMPTZ : T_TIMESTAMP, 0, 0};
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

/* F3g: a CAST's ENUM type by its name: live in the catalog, its dependency noted wherever the CAST stands (a WHERE
 * too, which the binder walks untyped, as the engine binds every tree) */
static int cast_enum(ab *b, const xn *x, uint32_t *id)
{
    char nm[64];
    fold(b->s + x->off, x->len, nm);
    ab_rel cr;
    memset(&cr, 0, sizeof cr);
    if (!b->lookup || !b->lookup(b->arg, nm, &cr) || cr.kind != DEP_TYPE) return fail(b, "no type %s", nm);
    *id = cr.id;
    return dep_note(b, DEP_TYPE, cr.id);
}

static int cast_type(ab *b, const scope *sc, const xn *x, ty *out)
{
    ty a;
    if (type_of(b, sc, x->l, true, &a)) return -1;
    if (x->ctype == T_ENUM) { /* F3g: the type a name says now (live: the catalog's), its dependency; from a TEXT, itself, NULL */
        uint32_t id;
        if (cast_enum(b, x, &id)) return -1;
        if (a.t && a.t != T_TEXT && (a.t != T_ENUM || a.e != id)) return fail(b, "CAST to an ENUM type takes a TEXT or that type");
        *out = (ty){T_ENUM, 0, (uint16_t)id};
        return 0;
    }
    if (a.t == T_ENUM && x->ctype != T_TEXT) return fail(b, "CAST of an ENUM to %s is not defined", tname(x->ctype)); /* F3g */
    bool to_num = num(x->ctype);
    bool fts = a.t == T_TIMESTAMP || a.t == T_TIMESTAMPTZ, tts = x->ctype == T_TIMESTAMP || x->ctype == T_TIMESTAMPTZ;
    bool ts2 = (fts && (tts || x->ctype == T_DATE || x->ctype == T_TIME)) || (a.t == T_DATE && tts); /* P2; F3b: the engine's dt_cast_ok */
    if (a.t && a.t != T_TEXT && x->ctype != T_TEXT && a.t != x->ctype && !(num(a.t) && to_num) && !ts2)
        return fail(b, "CAST of %s to %s is not defined", tname(a.t), tname(x->ctype));
    *out = (ty){x->ctype, x->ctype == T_DECIMAL ? x->cscale : 0, 0};
    return 0;
}

/* an aggregate's type (plain or over a window): COUNT INT64; SUM, MIN, MAX their argument's (SUM and AVG of numbers
 * alone); AVG of a FLOAT64 FLOAT64, of an INT64 or a DECIMAL(s) a DECIMAL at s + 6 (within 38) */
static int agg_type(ab *b, const scope *sc, uint8_t agg, uint16_t arg, ty *out)
{
    if (agg == A_COUNT_STAR || agg == A_COUNT) {
        *out = (ty){T_INT64, 0, 0};
        return walk(b, sc, arg);
    }
    ty a;
    if (type_of(b, sc, arg, false, &a)) return -1;
    if ((agg == A_SUM || agg == A_AVG) && !num(a.t) && !(agg == A_SUM && a.t == T_INTERVAL)) /* F3f: SUM of an INTERVAL */
        return fail(b, "SUM and AVG need an INT64, DECIMAL or FLOAT64 value");
    *out = a;
    if (agg == A_AVG && a.t != T_FLOAT64) {
        unsigned s = (a.t == T_DECIMAL ? a.s : 0u) + 6u;
        if (s > MAX_SCALE) return fail(b, "AVG of a DECIMAL past %u decimal places", MAX_SCALE - 6);
        *out = (ty){T_DECIMAL, (uint8_t)s, 0};
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
        *out = (ty){T_INT64, 0, 0};
        return walk(b, sc, x->l);
    case W_LAG:
    case W_LEAD:
    case W_FIRST:
    case W_LAST: {
        if (walk(b, sc, x->r)) return -1; /* LAG's and LEAD's offset */
        ty v, d = {0, 0, 0};
        if (type_of(b, sc, x->l, true, &v)) return -1;
        if (x->x3 && (type_of(b, sc, x->x3, true, &d) || unify(b, &v, d, "LAG's and LEAD's value and default are")))
            return -1;
        *out = v.t ? v : (ty){T_TEXT, 0, 0};
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
    uint32_t eid;
    if (x->op == X_CAST && x->ctype == T_ENUM && cast_enum(b, x, &eid)) return -1;
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

/* F3e: an integer literal's type, as the engine's (bind_xlit): INT64 within its range (the sign the literal's), else a
 * DECIMAL of scale 0 to 38 significant digits (PostgreSQL's numeric); past that its INT64 refusal */
static int int_lit_type(ab *b, const xn *x, ty *out)
{
    unsigned __int128 m = 0;
    unsigned digits = 0;
    for (uint32_t i = 0; i < x->len; i++) {
        char c = b->s[x->off + i];
        if (m || c != '0') digits++;
        if (digits > MAX_SCALE) return fail(b, "integer literal out of INT64 range");
        m = m * 10 + (unsigned)(c - '0');
    }
    *out = m <= (unsigned __int128)INT64_MAX + (x->neg ? 1u : 0u) ? (ty){T_INT64, 0, 0} : (ty){T_DECIMAL, 0, 0};
    return 0;
}

static int type_of(ab *b, const scope *sc, uint16_t k, bool null_ok, ty *out)
{
    const aq *q = sc->q;
    const xn *x = QX(q, k);
    ty l, r;
    switch (x->op) {
    case X_LIT:
        switch (x->lit) {
        case L_INT: return int_lit_type(b, x, out); /* F3e: past INT64 a DECIMAL of scale 0 */
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
            *out = (ty){T_DECIMAL, (uint8_t)s, 0};
            return 0;
        }
        case L_FLT: *out = (ty){T_FLOAT64, 0, 0}; return 0;
        case L_STR: *out = (ty){T_TEXT, 0, 0}; return 0;
        case L_BOOL: *out = (ty){T_BOOL, 0, 0}; return 0;
        case L_TS: *out = (ty){T_TIMESTAMP, 0, 0}; return 0;
        case L_TSTZ: *out = (ty){T_TIMESTAMPTZ, 0, 0}; return 0; /* P2 */
        case L_DATE: *out = (ty){T_DATE, 0, 0}; return 0; /* F3b */
        case L_TIME: *out = (ty){T_TIME, 0, 0}; return 0;
        case L_UUID: *out = (ty){T_UUID, 0, 0}; return 0; /* F3d */
        case L_BYTEA: *out = (ty){T_BYTEA, 0, 0}; return 0;
        case L_INTERVAL: *out = (ty){T_INTERVAL, 0, 0}; return 0; /* F3f */
        case L_NULL:
            if (!null_ok) return fail(b, "NULL cannot be an operand");
            *out = (ty){0, 0, 0};
            return 0;
        default: return fail(b, "a parameter in a view's query");
        }
    case X_COL: return col_of(b, sc, x, out);
    case X_NEG:
        if (type_of(b, sc, x->l, false, &l)) return -1;
        if (!num(l.t) && l.t != T_INTERVAL) return fail(b, "arithmetic takes INT64, DECIMAL and FLOAT64 values"); /* F3f */
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
        *out = (ty){T_BOOL, 0, 0};
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
            *out = (ty){T_BOOL, 0, 0};
            return bind_query(b, q->sub[x->sub], sc, M_DEPS, NULL, NULL);
        }
        ab_col c[MAX_COLS];
        uint16_t n = 0;
        if (bind_query(b, q->sub[x->sub], sc, M_TYPED, c, &n)) return -1;
        if (n != 1) return fail(b, "a subquery as a value returns one column");
        *out = (ty){c[0].type, c[0].scale, c[0].eid}; /* F3g */
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
            ty t = {0, 0, 0};
            if (it->shape == 2) {
                if (x->agg == A_COUNT || x->agg == A_COUNT_STAR) t = (ty){T_INT64, 0, 0};
                else if (!(rc = col_of(b, &sc, QX(q, x->l), &t)) && x->agg == A_SUM && !num(t.t) && t.t != T_INTERVAL) /* F3f */
                    rc = fail(b, "SUM needs an INT64, DECIMAL or FLOAT64 value");
            } else {
                rc = type_of(b, &sc, it->ex, true, &t);
            }
            if (rc) break;
            if (!t.t) t = (ty){T_TEXT, 0, 0}; /* SELECT NULL: a TEXT NULL */
            item_name(b, q, it, out[i].name);
            out[i].type = t.t;
            out[i].scale = t.t == T_DECIMAL ? t.s : 0;
            out[i].eid = t.t == T_ENUM ? t.e : 0; /* F3g */
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
                ty t = {acc[k].type, acc[k].scale, acc[k].eid};
                if (!(rc = unify(b, &t, (ty){c[k].type, c[k].scale, c[k].eid}, "a set operation's column is"))) {
                    acc[k].type = t.t;
                    acc[k].scale = t.t == T_DECIMAL ? t.s : 0;
                    acc[k].eid = t.t == T_ENUM ? t.e : 0; /* F3g */
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
        else if (cols[c].type == T_DECIMAL && cols[c].scale > 38) rc = fail(&b, "its DECIMAL column %u has more than 38 places", c + 1u);
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

/* ---- F2b-1: CHECK constraints (design.md §5, CHECK constraints) --------------------------------------------------
 * A CHECK's text, as op 28 or op 22's kind 11 logs it, bound against its table's columns and evaluated on a row, by
 * this file's own parser, a strict typer of the engine's subset and an evaluator of it: the row's columns, literals,
 * + - * / % and unary minus, the comparisons, BETWEEN, IN (a list), IS [NOT] NULL, [NOT] LIKE, AND, OR, NOT, CASE,
 * COALESCE, NULLIF, LENGTH, ABS, LOWER, UPPER and ||; no FLOAT64 value, no TIMESTAMPTZ literal. STRICT HERE, unlike the
 * views' binder: a CHECK's verdict decides whether a row may exist, so every rule the engine's binder applies to the
 * subset is applied (a text it refuses is refused), and every value is computed by design.md §5's rules exactly
 * (INT64 checked, DECIMAL to 38 digits, division by its rule, three-valued logic, left to right as the engine's
 * evaluator stops). */

typedef struct cv { /* a value a CHECK computes: INT64, DECIMAL (scaled), BOOL and the temporal types in i; TEXT p, n */
    uint8_t t, s;
    bool null;
    __int128 i;
    const uint8_t *p;
    uint32_t n;
} cv;

typedef struct cnode { /* a node bound: its type and scale, a column's index, a literal's value */
    uint8_t t, s;
    int16_t col;
    cv k;
} cnode;

struct ab_check {
    char *text; /* its own copy: the tokens point into it */
    aq *q;
    uint16_t root;
    cnode *nd;
    uint64_t cols; /* F2c: the columns it names (the first 64) */
    uint8_t *sbuf; /* its string literals' bytes */
    size_t sused;
};

typedef struct ck {
    ab *b;
    ab_check *c;
    const ab_col *cols;
    uint16_t ncols;
} ck;

enum { CK_DATE_MIN = -719162, CK_DATE_MAX = 2932896 }; /* 0001-01-01 and 9999-12-31, days from 1970-01-01 */
#define CK_DAY_US 86400000000LL

#define CN(x, k) (&(x)->c->q->ex[(k)])
#define CK_MAX_TEXT 8192 /* a CHECK's text (the engine's IMDB_MAX_CHECK_TEXT) */

/* a list's elements in order (the parser's balanced EX_LIST tree: its height log2 of its length) */
typedef struct cli {
    const aq *q;
    uint16_t st[40];
    int n;
} cli;
static void cli_start(cli *it, const aq *q, uint16_t k)
{
    it->q = q;
    it->n = 0;
    if (k) it->st[it->n++] = k;
}
static uint16_t cli_next(cli *it)
{
    while (it->n > 0) {
        uint16_t k = it->st[--it->n];
        const xn *x = QX(it->q, k);
        if (x->op != X_LIST) return k;
        if (x->r && it->n < 40) it->st[it->n++] = x->r;
        if (x->l && it->n < 40) it->st[it->n++] = x->l;
    }
    return 0;
}

static bool cnum(uint8_t t) { return t == T_INT64 || t == T_DECIMAL || t == T_FLOAT64; }
static bool ctemporal(uint8_t t) { return t == T_TIMESTAMP || t == T_TIMESTAMPTZ || t == T_DATE || t == T_TIME; }
static bool ccomparable(uint8_t a, uint8_t b) { return a == b || (cnum(a) && cnum(b)); }

static unsigned __int128 cp10(int n)
{
    unsigned __int128 r = 1;
    while (n-- > 0) r *= 10;
    return r;
}
static unsigned __int128 cmag(__int128 v) { return v < 0 ? (unsigned __int128)0 - (unsigned __int128)v : (unsigned __int128)v; }

/* ---- the engine's literal grammars (design.md §5): DATE 'YYYY-MM-DD', TIME 'HH:MM:SS[.f]', TIMESTAMP 'YYYY-MM-DD[
 * HH:MM:SS[.f][Z]]' (a T for the space), at most 32 bytes */
static bool cdig(const char *s, size_t n, size_t off, size_t cnt, int64_t *v)
{
    if (off > n || cnt > n - off) return false;
    int64_t x = 0;
    for (size_t i = 0; i < cnt; i++) {
        if (s[off + i] < '0' || s[off + i] > '9') return false;
        x = x * 10 + (s[off + i] - '0');
    }
    *v = x;
    return true;
}
static bool cleap(int64_t y) { return (y % 4 == 0 && y % 100 != 0) || y % 400 == 0; }
static int cdim(int64_t y, int m)
{
    static const int d[12] = {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
    return m == 2 && cleap(y) ? 29 : d[m - 1];
}
static int64_t cdays(int64_t y, int m, int d) /* days from 1970-01-01, the proleptic Gregorian calendar */
{
    y -= m <= 2;
    int64_t era = (y >= 0 ? y : y - 399) / 400, yoe = y - era * 400;
    int64_t doy = (153 * (m + (m > 2 ? -3 : 9)) + 2) / 5 + d - 1, doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    return era * 146097 + doe - 719468;
}
static int pdate(const char *s, size_t n, int64_t *out)
{
    int64_t Y, M, D;
    if (n != 10 || !cdig(s, n, 0, 4, &Y) || s[4] != '-' || !cdig(s, n, 5, 2, &M) || s[7] != '-' || !cdig(s, n, 8, 2, &D))
        return -1;
    if (Y < 1 || M < 1 || M > 12 || D < 1 || D > cdim(Y, (int)M)) return -1;
    *out = cdays(Y, (int)M, (int)D);
    return 0;
}
static int ptime(const char *s, size_t n, int64_t *out)
{
    int64_t h, mi, se, fr = 0;
    if (n < 8 || n > 15 || !cdig(s, n, 0, 2, &h) || s[2] != ':' || !cdig(s, n, 3, 2, &mi) || s[5] != ':' || !cdig(s, n, 6, 2, &se))
        return -1;
    if (n > 8) {
        size_t fd = n - 9;
        if (s[8] != '.' || fd < 1 || !cdig(s, n, 9, fd, &fr)) return -1;
        for (size_t k = fd; k < 6; k++) fr *= 10;
    }
    if (h > 23 || mi > 59 || se > 59) return -1;
    *out = (h * 3600 + mi * 60 + se) * 1000000 + fr;
    return 0;
}
static int pts(const char *s, size_t n, int64_t *out)
{
    int64_t Y, M, D, h = 0, mi = 0, se = 0, us = 0;
    if (n > 32 || !cdig(s, n, 0, 4, &Y) || n < 10 || s[4] != '-' || !cdig(s, n, 5, 2, &M) || s[7] != '-' || !cdig(s, n, 8, 2, &D))
        return -1;
    size_t i = 10;
    if (i < n && (s[i] == ' ' || s[i] == 'T') && i + 1 < n && s[i + 1] >= '0' && s[i + 1] <= '9') {
        if (!cdig(s, n, i + 1, 2, &h) || i + 3 >= n || s[i + 3] != ':' || !cdig(s, n, i + 4, 2, &mi) || i + 6 >= n ||
            s[i + 6] != ':' || !cdig(s, n, i + 7, 2, &se))
            return -1;
        i += 9;
        if (i < n && s[i] == '.') {
            size_t f0 = ++i;
            while (i < n && s[i] >= '0' && s[i] <= '9') i++;
            size_t fd = i - f0;
            if (fd < 1 || fd > 6) return -1;
            cdig(s, n, f0, fd, &us);
            for (size_t k = fd; k < 6; k++) us *= 10;
        }
    } else if (i < n && s[i] == 'T') {
        return -1;
    }
    if (i < n && i > 10 && s[i] == 'Z') i++;
    if (i != n) return -1;
    if (Y < 1 || M < 1 || M > 12 || D < 1 || D > cdim(Y, (int)M) || h > 23 || mi > 59 || se > 59) return -1;
    *out = ((cdays(Y, (int)M, (int)D) * 86400 + h * 3600 + mi * 60 + se) * 1000000) + us;
    return 0;
}

/* a string literal at k read as temporal type t (a comparison's, IN's, CASE's or COALESCE's: the engine reads it as
 * the other side's type, never compares it as text) */
static int ck_tslit(ck *x, uint16_t k, uint8_t t)
{
    const xn *n = CN(x, k);
    if (n->op != X_LIT || n->lit != L_STR) return 0;
    if (t == T_TIMESTAMPTZ) return fail(x->b, "a CHECK reads no TIMESTAMPTZ literal: it would be read in a session's zone");
    int64_t v = 0;
    const char *s = x->c->text + n->off;
    if (t == T_DATE ? pdate(s, n->len, &v) : t == T_TIME ? ptime(s, n->len, &v) : pts(s, n->len, &v))
        return fail(x->b, "a %s literal that does not parse", tname(t));
    cnode *d = &x->c->nd[k];
    d->t = t;
    d->s = 0;
    memset(&d->k, 0, sizeof d->k);
    d->k.t = t;
    d->k.i = v;
    return 0;
}

static int ck_lit(ck *x, uint16_t k, bool null_ok)
{
    const xn *n = CN(x, k);
    cnode *d = &x->c->nd[k];
    const char *s = x->c->text + n->off;
    memset(&d->k, 0, sizeof d->k);
    switch (n->lit) {
    case L_INT: {
        unsigned __int128 m = 0;
        for (uint32_t i = 0; i < n->len; i++) {
            if (m > ((unsigned __int128)1 << 124)) return fail(x->b, "integer literal out of INT64 range"); /* F3e: past 38 digits; no wrap */
            m = m * 10 + (unsigned)(s[i] - '0');
        }
        if (m > (unsigned __int128)INT64_MAX + (n->neg ? 1u : 0u)) { /* F3e: a DECIMAL of scale 0 to 38 digits, the engine's */
            unsigned digits = 0;
            for (uint32_t i = 0; i < n->len; i++) digits += digits || s[i] != '0';
            if (digits > MAX_SCALE) return fail(x->b, "integer literal out of INT64 range");
            d->k.i = n->neg ? -(__int128)m : (__int128)m;
            d->t = d->k.t = T_DECIMAL;
            d->s = d->k.s = 0;
            return 0;
        }
        d->k.i = n->neg ? -(__int128)m : (__int128)m;
        d->t = d->k.t = T_INT64;
        return 0;
    }
    case L_DEC: {
        unsigned __int128 m = 0;
        unsigned scale = 0, digits = 0;
        bool point = false, any = false;
        for (uint32_t i = 0; i < n->len; i++) {
            if (s[i] == '.' && !point) {
                point = true;
                continue;
            }
            if (s[i] < '0' || s[i] > '9') return fail(x->b, "invalid DECIMAL literal");
            any = true;
            if (point) scale++;
            if (m || s[i] != '0') digits++;
            if (digits > MAX_SCALE || scale > MAX_SCALE) return fail(x->b, "a DECIMAL literal of more than %u digits", MAX_SCALE);
            m = m * 10 + (unsigned)(s[i] - '0');
        }
        if (!any) return fail(x->b, "invalid DECIMAL literal");
        d->k.i = n->neg ? -(__int128)m : (__int128)m;
        d->t = d->k.t = T_DECIMAL;
        d->s = d->k.s = (uint8_t)scale;
        return 0;
    }
    case L_STR: { /* '' is one quote */
        uint8_t *p = x->c->sbuf + x->c->sused;
        uint32_t j = 0;
        for (uint32_t i = 0; i < n->len; i++) {
            p[j++] = (uint8_t)s[i];
            if (s[i] == '\'') i++;
        }
        x->c->sused += j;
        d->k.p = p;
        d->k.n = j;
        d->t = d->k.t = T_TEXT;
        return 0;
    }
    case L_BOOL:
        d->k.i = n->len == 4 && !strncasecmp(s, "true", 4);
        d->t = d->k.t = T_BOOL;
        return 0;
    case L_TS:
    case L_DATE:
    case L_TIME: {
        int64_t v = 0;
        uint8_t t = n->lit == L_TS ? T_TIMESTAMP : n->lit == L_DATE ? T_DATE : T_TIME;
        if (t == T_DATE ? pdate(s, n->len, &v) : t == T_TIME ? ptime(s, n->len, &v) : pts(s, n->len, &v))
            return fail(x->b, "a %s literal that does not parse", tname(t));
        d->k.i = v;
        d->t = d->k.t = t;
        return 0;
    }
    case L_NULL:
        if (!null_ok) return fail(x->b, "NULL cannot be an operand: the result would always be unknown (use IS NULL)");
        d->t = 0;
        d->k.null = true;
        return 0;
    default:
        return fail(x->b, "a CHECK's literal is an integer, a DECIMAL, a string, TRUE, FALSE, NULL, a DATE, a TIME or a "
                          "TIMESTAMP");
    }
}

/* arithmetic's result type (design.md §5): DATE +- INT64 days, DATE - DATE, DATE + TIME; INT64 with INT64; with a
 * DECIMAL a DECIMAL (+ - % the larger scale, * their sum, / the larger plus six), within 38 */
static int ck_arith(ck *x, uint8_t op, const cnode *l, const cnode *r, cnode *d)
{
    d->s = 0;
    if (l->t == T_DATE || r->t == T_DATE || l->t == T_TIME || r->t == T_TIME) {
        if (op == X_ADD && ((l->t == T_DATE && r->t == T_INT64) || (l->t == T_INT64 && r->t == T_DATE))) d->t = T_DATE;
        else if (op == X_SUB && l->t == T_DATE && r->t == T_INT64) d->t = T_DATE;
        else if (op == X_SUB && l->t == T_DATE && r->t == T_DATE) d->t = T_INT64;
        else if (op == X_ADD && ((l->t == T_DATE && r->t == T_TIME) || (l->t == T_TIME && r->t == T_DATE))) d->t = T_TIMESTAMP;
        else return fail(x->b, "date arithmetic: a DATE + or - an INT64 of days, DATE - DATE, DATE + TIME");
        return 0;
    }
    if (!cnum(l->t) || !cnum(r->t) || l->t == T_FLOAT64 || r->t == T_FLOAT64)
        return fail(x->b, "arithmetic takes INT64 and DECIMAL values in a CHECK");
    if (l->t == T_INT64 && r->t == T_INT64) {
        d->t = T_INT64;
        return 0;
    }
    int s1 = l->t == T_DECIMAL ? l->s : 0, s2 = r->t == T_DECIMAL ? r->s : 0, big = s1 > s2 ? s1 : s2;
    int s = op == X_MUL ? s1 + s2 : op == X_DIV ? big + 6 : big;
    if (s > MAX_SCALE) return fail(x->b, "a DECIMAL result of more than %u decimal places", MAX_SCALE);
    d->t = T_DECIMAL;
    d->s = (uint8_t)s;
    return 0;
}

static int ck_unify(ck *x, uint8_t *t, uint8_t *s, uint8_t t2, uint8_t s2)
{
    if (!t2) return 0;
    if (!*t) {
        *t = t2;
        *s = s2;
        return 0;
    }
    if (*t == t2) {
        if (t2 == T_DECIMAL && s2 > *s) *s = s2;
        return 0;
    }
    if ((*t == T_INT64 && t2 == T_DECIMAL) || (*t == T_DECIMAL && t2 == T_INT64)) {
        uint8_t a = *t == T_DECIMAL ? *s : 0, b2 = t2 == T_DECIMAL ? s2 : 0;
        *t = T_DECIMAL;
        *s = a > b2 ? a : b2;
        return 0;
    }
    return fail(x->b, "%s and %s: values are not converted", tname(*t), tname(t2));
}

/* CASE's results and COALESCE's arguments: a string literal beside a temporal value is of the last one's type, then
 * one type (INT64 and DECIMAL a DECIMAL at the larger scale); an untyped NULL takes it */
static int ck_unify_all(ck *x, const uint16_t *v, unsigned n, cnode *d)
{
    uint8_t ts = 0;
    for (unsigned i = 0; i < n; i++)
        if (ctemporal(x->c->nd[v[i]].t)) ts = x->c->nd[v[i]].t;
    for (unsigned i = 0; ts && i < n; i++)
        if (ck_tslit(x, v[i], ts)) return -1;
    d->t = d->s = 0;
    for (unsigned i = 0; i < n; i++)
        if (ck_unify(x, &d->t, &d->s, x->c->nd[v[i]].t, x->c->nd[v[i]].s)) return -1;
    if (!d->t) return fail(x->b, "NULL alone has no type");
    for (unsigned i = 0; i < n; i++)
        if (!x->c->nd[v[i]].t) {
            x->c->nd[v[i]].t = d->t;
            x->c->nd[v[i]].s = d->s;
        }
    return 0;
}

static int ck_bind(ck *x, uint16_t k, bool null_ok);

static int ck_items(ck *x, uint16_t k, uint16_t *el, unsigned *n, unsigned cap)
{
    return list_items(x->b, x->c->q, k, el, n, cap);
}

static int ck_fn(ck *x, uint16_t k)
{
    const xn *n = CN(x, k);
    cnode *d = &x->c->nd[k];
    uint16_t el[MAX_ARGS];
    unsigned na = 0;
    if (ck_items(x, n->l, el, &na, MAX_ARGS)) return -1;
    switch (n->fn) {
    case F_COALESCE:
        if (na < 1) return fail(x->b, "COALESCE takes 1 to 255 arguments");
        for (unsigned i = 0; i < na; i++)
            if (ck_bind(x, el[i], true)) return -1;
        return ck_unify_all(x, el, na, d);
    case F_NULLIF: {
        if (na != 2) return fail(x->b, "NULLIF takes 2 arguments");
        if (ck_bind(x, el[0], false) || ck_bind(x, el[1], true)) return -1;
        cnode *a = &x->c->nd[el[0]], *b2 = &x->c->nd[el[1]];
        if (ctemporal(a->t) && ck_tslit(x, el[1], a->t)) return -1;
        if (b2->t && !ccomparable(a->t, b2->t)) return fail(x->b, "NULLIF of %s and %s", tname(a->t), tname(b2->t));
        d->t = a->t;
        d->s = a->s;
        if (!b2->t) {
            b2->t = d->t;
            b2->s = d->s;
        }
        return 0;
    }
    case F_ABS:
    case F_LENGTH:
    case F_LOWER:
    case F_UPPER:
        if (na != 1) return fail(x->b, "a function of one argument called with %u", na);
        if (ck_bind(x, el[0], false)) return -1;
        if (n->fn == F_ABS) {
            if (x->c->nd[el[0]].t != T_INT64 && x->c->nd[el[0]].t != T_DECIMAL) return fail(x->b, "ABS takes a number");
            d->t = x->c->nd[el[0]].t;
            d->s = x->c->nd[el[0]].t == T_DECIMAL ? x->c->nd[el[0]].s : 0;
            return 0;
        }
        if (x->c->nd[el[0]].t != T_TEXT) return fail(x->b, "LENGTH, LOWER and UPPER take a TEXT value");
        d->t = n->fn == F_LENGTH ? T_INT64 : T_TEXT;
        d->s = 0;
        return 0;
    case F_CONCAT:
        if (na != 2) return fail(x->b, "|| takes two values");
        if (ck_bind(x, el[0], false) || ck_bind(x, el[1], false)) return -1;
        if (x->c->nd[el[0]].t != T_TEXT || x->c->nd[el[1]].t != T_TEXT) return fail(x->b, "|| takes TEXT values");
        d->t = T_TEXT;
        d->s = 0;
        return 0;
    default:
        return fail(x->b, "a CHECK calls ABS, LENGTH, LOWER, UPPER, COALESCE, NULLIF and || alone");
    }
}

static int ck_case(ck *x, uint16_t k)
{
    const xn *n = CN(x, k);
    cnode *d = &x->c->nd[k];
    uint16_t w[MAX_ARGS + 1], v[MAX_ARGS + 1];
    unsigned nw = 0, nv = 0;
    if (n->l && ck_bind(x, n->l, false)) return -1;
    if (ck_items(x, n->r, w, &nw, MAX_ARGS)) return -1;
    for (unsigned i = 0; i < nw; i++) {
        const xn *wx = CN(x, w[i]);
        if (ck_bind(x, wx->l, false)) return -1;
        if (!n->l && x->c->nd[wx->l].t != T_BOOL) return fail(x->b, "CASE WHEN takes a condition");
        if (n->l) {
            if (ctemporal(x->c->nd[n->l].t) && ck_tslit(x, wx->l, x->c->nd[n->l].t)) return -1;
            if (!ccomparable(x->c->nd[n->l].t, x->c->nd[wx->l].t))
                return fail(x->b, "a CASE of %s compared with %s", tname(x->c->nd[n->l].t), tname(x->c->nd[wx->l].t));
        }
        if (ck_bind(x, wx->r, true)) return -1;
        v[nv++] = wx->r;
    }
    if (n->x3) {
        if (ck_bind(x, n->x3, true)) return -1;
        v[nv++] = n->x3;
    }
    return ck_unify_all(x, v, nv, d);
}

static int ck_cmp(ck *x, uint16_t k)
{
    const xn *n = CN(x, k);
    cnode *d = &x->c->nd[k];
    d->t = T_BOOL;
    d->s = 0;
    if (ck_bind(x, n->l, false)) return -1;
    if (n->cmp == C_ISNULL || n->cmp == C_NOTNULL) return 0;
    if (n->cmp == C_IN || n->cmp == C_NOTIN) {
        if (CN(x, n->r)->op == X_SUBQ) return fail(x->b, "a CHECK is a condition on its row: no subquery");
        cli it;
        cli_start(&it, x->c->q, n->r);
        for (uint16_t el = cli_next(&it); el; el = cli_next(&it)) {
            if (ck_bind(x, el, true)) return -1;
            cnode *a = &x->c->nd[n->l], *e2 = &x->c->nd[el];
            if (ctemporal(a->t) && ck_tslit(x, el, a->t)) return -1;
            if (e2->t && !ccomparable(a->t, e2->t)) return fail(x->b, "IN compares %s with %s", tname(a->t), tname(e2->t));
            if (!e2->t) {
                e2->t = a->t;
                e2->s = a->s;
            }
        }
        return 0;
    }
    if (n->cmp == C_LIKE || n->cmp == C_NOTLIKE) {
        if (ck_bind(x, n->r, false) || (n->x3 && ck_bind(x, n->x3, false))) return -1;
        if (x->c->nd[n->l].t != T_TEXT || x->c->nd[n->r].t != T_TEXT || (n->x3 && x->c->nd[n->x3].t != T_TEXT))
            return fail(x->b, "LIKE takes TEXT values");
        return 0;
    }
    uint16_t ops[2] = {n->r, n->x3};
    for (int i = 0; i < (n->cmp == C_BETWEEN ? 2 : 1); i++) {
        if (ck_bind(x, ops[i], false)) return -1;
        if (ctemporal(x->c->nd[n->l].t) && ck_tslit(x, ops[i], x->c->nd[n->l].t)) return -1;
        if (ctemporal(x->c->nd[ops[i]].t) && ck_tslit(x, n->l, x->c->nd[ops[i]].t)) return -1;
        uint8_t ta = x->c->nd[n->l].t, tb = x->c->nd[ops[i]].t;
        if (!ccomparable(ta, tb)) return fail(x->b, "a comparison of %s with %s", tname(ta), tname(tb));
        if (ta == T_BOOL && n->cmp != C_EQ && n->cmp != C_NE) return fail(x->b, "BOOL values support only = and !=");
    }
    return 0;
}

static int ck_bind(ck *x, uint16_t k, bool null_ok)
{
    const xn *n = CN(x, k);
    cnode *d = &x->c->nd[k];
    d->col = -1;
    switch (n->op) {
    case X_LIT: return ck_lit(x, k, null_ok);
    case X_COL: {
        if (n->qlen) return fail(x->b, "a CHECK names its table's columns bare");
        char nm[64];
        fold(x->c->text + n->off, n->len, nm);
        for (uint16_t c = 0; c < x->ncols; c++)
            if (!strcmp(x->cols[c].name, nm)) {
                d->col = (int16_t)c;
                if (c < 64) x->c->cols |= 1ull << c;
                d->t = x->cols[c].type;
                d->s = x->cols[c].type == T_DECIMAL ? x->cols[c].scale : 0;
                if (d->t == T_FLOAT64) return fail(x->b, "a CHECK computes no FLOAT64 value");
                if (d->t == T_UUID || d->t == T_BYTEA) return fail(x->b, "a CHECK reads no UUID or BYTEA value yet"); /* F3d */
                if (d->t == T_INTERVAL) return fail(x->b, "a CHECK reads no INTERVAL value yet"); /* F3f */
                if (d->t == T_ENUM) return fail(x->b, "a CHECK reads no ENUM value yet"); /* F3g: deferred.md D27 */
                return 0;
            }
        return fail(x->b, "no column %s in its table", nm);
    }
    case X_NEG:
        if (ck_bind(x, n->l, false)) return -1;
        if (x->c->nd[n->l].t != T_INT64 && x->c->nd[n->l].t != T_DECIMAL) return fail(x->b, "arithmetic takes numbers");
        d->t = x->c->nd[n->l].t;
        d->s = x->c->nd[n->l].s;
        return 0;
    case X_ADD:
    case X_SUB:
    case X_MUL:
    case X_DIV:
    case X_MOD:
        if (ck_bind(x, n->l, false) || ck_bind(x, n->r, false)) return -1;
        return ck_arith(x, n->op, &x->c->nd[n->l], &x->c->nd[n->r], d);
    case X_AND:
    case X_OR:
    case X_NOT:
        d->t = T_BOOL;
        d->s = 0;
        for (int i = 0; i < (n->op == X_NOT ? 1 : 2); i++) {
            uint16_t o = i ? n->r : n->l;
            if (ck_bind(x, o, false)) return -1;
            if (x->c->nd[o].t != T_BOOL) return fail(x->b, "AND, OR and NOT take conditions");
        }
        return 0;
    case X_CMP: return ck_cmp(x, k);
    case X_FN: return ck_fn(x, k);
    case X_CASE: return ck_case(x, k);
    default: return fail(x->b, "a CHECK is a condition on its row: no subquery, aggregate, window function or CAST");
    }
}

void ab_check_free(ab_check *c)
{
    if (!c) return;
    aq_free(c->q);
    free(c->nd);
    free(c->sbuf);
    free(c->text);
    free(c);
}

/* the subset bound alone against cols: cond, a CHECK (its value a BOOL); else F2c's generation expression (any type: its
 * caller decides) */
static int cbind(const char *text, size_t len, const ab_col *cols, uint16_t ncols, bool cond, ab_check **out, char *err,
                 size_t errn)
{
    *out = NULL;
    ab b;
    memset(&b, 0, sizeof b);
    b.err = err;
    b.errn = errn;
    if (errn) err[0] = 0;
    if (!len || len > CK_MAX_TEXT || !utf8_ok(text, len) || memchr(text, 0, len)) return fail(&b, "a CHECK's text of %zu bytes", len);
    ab_check *c = calloc(1, sizeof *c);
    if (!c) return oom(&b);
    int rc = 0;
    if (!(c->text = malloc(len + 1)) || !(c->sbuf = malloc(len + 1))) rc = oom(&b);
    if (!rc) {
        memcpy(c->text, text, len);
        c->text[len] = 0;
        b.s = c->text;
        b.n = len;
        rc = lex(&b);
    }
    if (!rc && !(c->q = aq_new(&b))) rc = -1;
    if (!rc) {
        b.q = c->q;
        rc = bexpr(&b, &c->root, 0);
    }
    if (!rc && b.t[b.i].k != K_EOF) rc = fail(&b, "a CHECK is one condition (offset %u)", b.t[b.i].off);
    if (!rc && c->q->nsub) rc = fail(&b, "a CHECK is a condition on its row: no subquery");
    if (!rc && !(c->nd = calloc((size_t)c->q->nex + 1, sizeof *c->nd))) rc = oom(&b);
    if (!rc) {
        ck x = {&b, c, cols, ncols};
        rc = ck_bind(&x, c->root, false);
        if (!rc && cond && c->nd[c->root].t != T_BOOL) rc = fail(&b, "a CHECK is a condition: its value a BOOL");
    }
    free(b.t);
    if (rc) {
        ab_check_free(c);
        return -1;
    }
    *out = c;
    return 0;
}

/* ---- evaluation: the engine's evaluator's rules (sql_expr.c's, from design.md §5) ---- */

typedef struct cx {
    const ab_check *c;
    const ab_val *row;
    char *err;
    size_t errn;
    uint8_t *tbuf[64]; /* computed TEXT, freed with the evaluation */
    unsigned ntbuf;
} cx;

static int cfail(cx *e, const char *m)
{
    if (e->errn) snprintf(e->err, e->errn, "%s", m);
    return -1;
}

static int ctext(cx *e, size_t n, cv *out)
{
    if (n > MAX_TEXT) return cfail(e, "a computed TEXT of more than 65535 bytes");
    if (e->ntbuf >= sizeof e->tbuf / sizeof *e->tbuf) return cfail(e, "too many computed TEXT values");
    uint8_t *p = malloc(n ? n : 1);
    if (!p) return cfail(e, "out of memory");
    e->tbuf[e->ntbuf++] = p;
    out->p = p;
    out->n = (uint32_t)n;
    return 0;
}

static int ccmp(const cv *a, const cv *b) /* two comparable non-NULL values: -1, 0, 1, exactly */
{
    if (a->t == T_TEXT) {
        uint32_t n = a->n < b->n ? a->n : b->n;
        int c = n ? memcmp(a->p, b->p, n) : 0;
        if (c) return c < 0 ? -1 : 1;
        return a->n < b->n ? -1 : a->n > b->n;
    }
    if (a->t == T_DECIMAL || b->t == T_DECIMAL) {
        __int128 x = a->i, y = b->i, r;
        int sx = a->t == T_DECIMAL ? a->s : 0, sy = b->t == T_DECIMAL ? b->s : 0;
        if (sx < sy) {
            if (__builtin_mul_overflow(x, (__int128)cp10(sy - sx), &r)) return x < 0 ? -1 : 1;
            x = r;
        } else if (sy < sx) {
            if (__builtin_mul_overflow(y, (__int128)cp10(sx - sy), &r)) return y < 0 ? 1 : -1;
            y = r;
        }
        return x < y ? -1 : x > y;
    }
    return a->i < b->i ? -1 : a->i > b->i;
}

static void ctruth(cv *out, int t) /* 1, 0, -1 unknown */
{
    memset(out, 0, sizeof *out);
    out->t = T_BOOL;
    out->null = t < 0;
    out->i = t > 0;
}
static int ctv(const cv *v) { return v->null ? -1 : v->i != 0; }

static int ccmp3(uint8_t op, const cv *a, const cv *b)
{
    if (a->null || b->null) return -1;
    int c = ccmp(a, b);
    switch (op) {
    case C_EQ: return c == 0;
    case C_NE: return c != 0;
    case C_LT: return c < 0;
    case C_LE: return c <= 0;
    case C_GT: return c > 0;
    default: return c >= 0;
    }
}

static bool crescale(__int128 v, int s, int t, __int128 *out)
{
    __int128 r;
    if (__builtin_mul_overflow(v, (__int128)cp10(t - s), &r) || cmag(r) >= cp10(MAX_SCALE)) return false;
    *out = r;
    return true;
}

static int cwiden(cx *e, cv *v, uint8_t rt, uint8_t rs)
{
    if (v->null || (v->t == rt && (rt != T_DECIMAL || v->s == rs))) {
        v->t = rt;
        v->s = rs;
        return 0;
    }
    if (rt == T_DECIMAL && (v->t == T_INT64 || v->t == T_DECIMAL)) {
        int s = v->t == T_DECIMAL ? v->s : 0;
        if (s > rs || !crescale(v->i, s, rs, &v->i)) return cfail(e, "a DECIMAL result of more than 38 digits");
        v->t = T_DECIMAL;
        v->s = rs;
        return 0;
    }
    return cfail(e, "a value of another type than its CASE's or COALESCE's");
}

static int cdiv(cx *e, __int128 a, __int128 b, int k, __int128 *out) /* |a| * 10^k / |b| half away from zero, signed */
{
    if (!b) return cfail(e, "division by zero");
    unsigned __int128 ua = cmag(a), ub = cmag(b), q, r, lim = cp10(MAX_SCALE), u128max = ~(unsigned __int128)0;
    if (k <= MAX_SCALE && ua <= u128max / cp10(k)) {
        unsigned __int128 n = ua * cp10(k);
        q = n / ub;
        r = n % ub;
    } else {
        if (ub > u128max / 10) return cfail(e, "a DECIMAL division by a value of more than 37 digits");
        q = ua / ub;
        r = ua % ub;
        for (int i = 0; i < k; i++) {
            if (q > (lim - 1) / 10) return cfail(e, "a DECIMAL result of more than 38 digits");
            r *= 10;
            q = q * 10 + r / ub;
            r %= ub;
        }
    }
    if (r >= ub - r) q++;
    if (q >= lim) return cfail(e, "a DECIMAL result of more than 38 digits");
    *out = (a < 0) != (b < 0) ? -(__int128)q : (__int128)q;
    return 0;
}

static int carith(cx *e, uint8_t op, const cv *a, const cv *b, uint8_t rt, uint8_t rs, cv *out)
{
    memset(out, 0, sizeof *out);
    out->t = rt;
    out->s = rs;
    if (a->null || b->null) {
        out->null = true;
        return 0;
    }
    __int128 x = a->i, y = b->i, r = 0;
    if (rt == T_DATE) {
        r = op == X_ADD ? x + y : x - y;
        if (r < CK_DATE_MIN || r > CK_DATE_MAX) return cfail(e, "a DATE result out of range");
        out->i = r;
        return 0;
    }
    if (rt == T_TIMESTAMP) { /* a DATE + a TIME */
        out->i = a->t == T_DATE ? x * CK_DAY_US + y : y * CK_DAY_US + x;
        return 0;
    }
    if (rt == T_INT64) { /* a DATE - a DATE too: both within their range */
        switch (op) {
        case X_ADD: r = x + y; break;
        case X_SUB: r = x - y; break;
        case X_MUL:
            if (__builtin_mul_overflow(x, y, &r)) return cfail(e, "INT64 overflow");
            break;
        case X_DIV:
            if (!y) return cfail(e, "division by zero");
            r = x / y;
            break;
        default:
            if (!y) return cfail(e, "division by zero");
            r = x % y;
            break;
        }
        if (r < INT64_MIN || r > INT64_MAX) return cfail(e, "INT64 overflow");
        out->i = r;
        return 0;
    }
    int sa = a->t == T_DECIMAL ? a->s : 0, sb = b->t == T_DECIMAL ? b->s : 0;
    switch (op) {
    case X_MUL:
        if (__builtin_mul_overflow(x, y, &r) || cmag(r) >= cp10(MAX_SCALE)) return cfail(e, "a DECIMAL result of more than 38 digits");
        break;
    case X_DIV:
        if (cdiv(e, x, y, rs - sa + sb, &r)) return -1;
        break;
    default:
        if (!crescale(x, sa, rs, &x) || !crescale(y, sb, rs, &y)) return cfail(e, "a DECIMAL result of more than 38 digits");
        if (op == X_MOD) {
            if (!y) return cfail(e, "division by zero");
            r = x % y;
        } else {
            if (op == X_ADD ? __builtin_add_overflow(x, y, &r) : __builtin_sub_overflow(x, y, &r))
                return cfail(e, "a DECIMAL result of more than 38 digits");
            if (cmag(r) >= cp10(MAX_SCALE)) return cfail(e, "a DECIMAL result of more than 38 digits");
        }
        break;
    }
    out->i = r;
    return 0;
}

static uint32_t cu8(const uint8_t *s, uint32_t n, uint32_t i, uint32_t *cpt) /* the next character after i */
{
    uint8_t c = s[i];
    uint32_t k = c < 0x80 ? 1 : c < 0xE0 ? 2 : c < 0xF0 ? 3 : 4, v = k == 1 ? c : k == 2 ? c & 0x1Fu : k == 3 ? c & 0x0Fu : c & 0x07u;
    if (k > n - i) k = n - i;
    for (uint32_t j = 1; j < k; j++) v = v << 6 | (s[i + j] & 0x3Fu);
    *cpt = v;
    return i + k;
}

static int cpat(const uint8_t *p, uint32_t m, uint32_t j, uint32_t esc, uint32_t *cpt, int *wild, uint32_t *next)
{
    uint32_t c, k = cu8(p, m, j, &c);
    *wild = 0;
    if (esc && c == esc) {
        if (k >= m) return -1;
        *next = cu8(p, m, k, cpt);
        return 0;
    }
    if (c == '%' || c == '_') *wild = (int)c;
    *cpt = c;
    *next = k;
    return 0;
}

static int clike(cx *e, const uint8_t *s, uint32_t n, const uint8_t *p, uint32_t m, uint32_t esc, bool *match)
{
    uint32_t i = 0, j = 0, star_j = UINT32_MAX, star_i = 0, cpt, tc, next;
    int wild;
    for (uint32_t k = 0; k < m;) {
        if (cpat(p, m, k, esc, &cpt, &wild, &next)) return cfail(e, "a LIKE pattern ends in its escape character");
        k = next;
    }
    while (i < n) {
        if (j < m) {
            cpat(p, m, j, esc, &cpt, &wild, &next);
            if (wild == '%') {
                star_j = next;
                star_i = i;
                j = next;
                continue;
            }
            uint32_t ni = cu8(s, n, i, &tc);
            if (wild == '_' || cpt == tc) {
                i = ni;
                j = next;
                continue;
            }
        }
        if (star_j == UINT32_MAX) {
            *match = false;
            return 0;
        }
        star_i = cu8(s, n, star_i, &tc);
        i = star_i;
        j = star_j;
    }
    while (j < m) {
        cpat(p, m, j, esc, &cpt, &wild, &next);
        if (wild != '%') break;
        j = next;
    }
    *match = j >= m;
    return 0;
}

static int ceval(cx *e, uint16_t k, cv *out)
{
    const aq *q = e->c->q;
    const xn *x = QX(q, k);
    const cnode *d = &e->c->nd[k];
    cv l, r, h;
    switch (x->op) {
    case X_LIT:
        *out = d->k;
        out->t = d->t;
        if (out->null) out->s = d->s;
        return 0;
    case X_COL: {
        const ab_val *v = &e->row[d->col];
        memset(out, 0, sizeof *out);
        out->t = d->t;
        out->s = d->s;
        out->null = v->null;
        if (!v->null) {
            if (d->t == T_TEXT) out->p = v->s, out->n = v->len;
            else if (v->wide) out->i = (__int128)(((unsigned __int128)(uint64_t)v->hi << 64) | (uint64_t)v->i); /* F3e */
            else out->i = v->i;
        }
        return 0;
    }
    case X_NEG:
        if (ceval(e, x->l, &l)) return -1;
        *out = l;
        if (l.null) return 0;
        out->i = -l.i;
        if (l.t == T_INT64 && (out->i > INT64_MAX || out->i < INT64_MIN)) return cfail(e, "INT64 overflow");
        return 0;
    case X_NOT:
        if (ceval(e, x->l, &l)) return -1;
        ctruth(out, ctv(&l) < 0 ? -1 : !ctv(&l));
        return 0;
    case X_AND:
    case X_OR: {
        if (ceval(e, x->l, &l)) return -1;
        int a = ctv(&l), stop = x->op == X_AND ? 0 : 1;
        if (a == stop) {
            ctruth(out, stop);
            return 0;
        }
        if (ceval(e, x->r, &r)) return -1;
        int c = ctv(&r);
        ctruth(out, c == stop ? stop : a < 0 || c < 0 ? -1 : !stop);
        return 0;
    }
    case X_CMP: {
        if (ceval(e, x->l, &l)) return -1;
        if (x->cmp == C_ISNULL || x->cmp == C_NOTNULL) {
            ctruth(out, l.null == (x->cmp == C_ISNULL));
            return 0;
        }
        if (x->cmp == C_IN || x->cmp == C_NOTIN) {
            int t = l.null ? -1 : 0;
            cli it;
            cli_start(&it, q, l.null ? 0 : x->r);
            for (uint16_t el = cli_next(&it); el; el = cli_next(&it)) {
                if (ceval(e, el, &r)) return -1;
                if (r.null) t = -1;
                else if (ccmp(&l, &r) == 0) {
                    t = 1;
                    break;
                }
            }
            ctruth(out, x->cmp == C_IN ? t : t < 0 ? -1 : !t);
            return 0;
        }
        if (ceval(e, x->r, &r)) return -1;
        if (x->cmp == C_LIKE || x->cmp == C_NOTLIKE) {
            uint32_t esc = 0;
            if (x->x3) {
                if (ceval(e, x->x3, &h)) return -1;
                if (h.null) l.null = true;
                else if (h.n && cu8(h.p, h.n, 0, &esc) != h.n) return cfail(e, "a LIKE's ESCAPE is one character");
            }
            if (l.null || r.null) {
                ctruth(out, -1);
                return 0;
            }
            bool m;
            if (clike(e, l.p, l.n, r.p, r.n, esc, &m)) return -1;
            ctruth(out, (x->cmp == C_LIKE) == m);
            return 0;
        }
        if (x->cmp != C_BETWEEN) {
            ctruth(out, ccmp3(x->cmp, &l, &r));
            return 0;
        }
        if (ceval(e, x->x3, &h)) return -1;
        int lo = ccmp3(C_GE, &l, &r), hi = ccmp3(C_LE, &l, &h);
        ctruth(out, lo == 0 || hi == 0 ? 0 : lo < 0 || hi < 0 ? -1 : 1);
        return 0;
    }
    case X_FN: {
        uint16_t el[MAX_ARGS];
        unsigned na = 0;
        cli it;
        cli_start(&it, q, x->l);
        for (uint16_t a1 = cli_next(&it); a1 && na < MAX_ARGS; a1 = cli_next(&it)) el[na++] = a1;
        if (x->fn == F_COALESCE) {
            for (unsigned i = 0; i < na; i++) {
                if (ceval(e, el[i], out)) return -1;
                if (!out->null) return cwiden(e, out, d->t, d->s);
            }
            memset(out, 0, sizeof *out);
            out->null = true;
            out->t = d->t;
            out->s = d->s;
            return 0;
        }
        cv a[2];
        for (unsigned i = 0; i < na && i < 2; i++)
            if (ceval(e, el[i], &a[i])) return -1;
        if (x->fn == F_NULLIF) {
            *out = a[0];
            if (!a[0].null && !a[1].null && ccmp(&a[0], &a[1]) == 0) out->null = true;
            out->t = d->t;
            out->s = d->s;
            return 0;
        }
        memset(out, 0, sizeof *out);
        out->t = d->t;
        out->s = d->s;
        for (unsigned i = 0; i < na; i++)
            if (a[i].null) {
                out->null = true;
                return 0;
            }
        switch (x->fn) {
        case F_ABS:
            out->i = a[0].i < 0 ? -a[0].i : a[0].i;
            if (a[0].t == T_INT64 && out->i > INT64_MAX) return cfail(e, "INT64 overflow");
            return 0;
        case F_LENGTH: {
            uint32_t c = 0;
            for (uint32_t i = 0; i < a[0].n; i++) c += (a[0].p[i] & 0xC0) != 0x80;
            out->i = c;
            return 0;
        }
        case F_LOWER:
        case F_UPPER: {
            if (ctext(e, a[0].n, out)) return -1;
            uint8_t *p = (uint8_t *)(uintptr_t)out->p;
            for (uint32_t i = 0; i < a[0].n; i++) {
                uint8_t c = a[0].p[i];
                p[i] = x->fn == F_LOWER && c >= 'A' && c <= 'Z' ? (uint8_t)(c + 32)
                     : x->fn == F_UPPER && c >= 'a' && c <= 'z' ? (uint8_t)(c - 32) : c;
            }
            return 0;
        }
        default: { /* || */
            if (ctext(e, (size_t)a[0].n + a[1].n, out)) return -1;
            uint8_t *p = (uint8_t *)(uintptr_t)out->p;
            if (a[0].n) memcpy(p, a[0].p, a[0].n);
            if (a[1].n) memcpy(p + a[0].n, a[1].p, a[1].n);
            return 0;
        }
        }
    }
    case X_CASE: {
        cli it;
        if (x->l && ceval(e, x->l, &l)) return -1;
        cli_start(&it, q, x->r);
        for (uint16_t w = cli_next(&it); w; w = cli_next(&it)) {
            const xn *wx = QX(q, w);
            if (ceval(e, wx->l, &r)) return -1;
            bool hit = x->l ? !l.null && !r.null && ccmp(&l, &r) == 0 : !r.null && r.i != 0;
            if (hit) {
                if (ceval(e, wx->r, out)) return -1;
                return cwiden(e, out, d->t, d->s);
            }
        }
        if (x->x3) {
            if (ceval(e, x->x3, out)) return -1;
            return cwiden(e, out, d->t, d->s);
        }
        memset(out, 0, sizeof *out);
        out->null = true;
        out->t = d->t;
        out->s = d->s;
        return 0;
    }
    default:
        if (ceval(e, x->l, &l) || ceval(e, x->r, &r)) return -1;
        return carith(e, x->op, &l, &r, d->t, d->s, out);
    }
}

int ab_check_eval(const ab_check *c, const ab_val *row, char *err, size_t errn)
{
    cx e = {c, row, err, errn, {0}, 0};
    if (errn) err[0] = 0;
    cv v;
    int rc = ceval(&e, c->root, &v);
    for (unsigned i = 0; i < e.ntbuf; i++) free(e.tbuf[i]);
    if (rc) return -1;
    return v.null || v.i != 0;
}

int ab_check_bind(const char *text, size_t len, const ab_col *cols, uint16_t ncols, ab_check **out, char *err, size_t errn)
{
    return cbind(text, len, cols, ncols, true, out, err, errn);
}

/* ---- F2c: a generated column's expression (design.md §5, Generated columns): CHECK's subset bound alone, its value of a
 * type its column takes, naming no generated column; computed by the evaluator above and assigned by INSERT's rules ---- */

int ab_gen_bind(const char *text, size_t len, const ab_col *cols, uint16_t ncols, uint16_t target, uint64_t genmask,
                ab_check **out, char *err, size_t errn)
{
    *out = NULL;
    if (target >= ncols) {
        if (errn) snprintf(err, errn, "no column at %u", target);
        return -1;
    }
    ab_check *c = NULL;
    if (cbind(text, len, cols, ncols, false, &c, err, errn)) return -1;
    uint8_t t = c->nd[c->root].t, ct = cols[target].type;
    bool ok = ct == T_INT64 ? t == T_INT64 : ct == T_DECIMAL ? t == T_INT64 || t == T_DECIMAL : ct != T_FLOAT64 && t == ct;
    const char *why = !ok ? "its value of a type its column does not take" : (c->cols & genmask) ? "it names a generated column" : NULL;
    if (why) {
        if (errn) snprintf(err, errn, "%s", why);
        ab_check_free(c);
        return -1;
    }
    *out = c;
    return 0;
}

/* the column's assignment of a computed value (sql_expr.c's imdb_x_assign and codec.c's value check, from design.md
 * §5): 0 and *out, or -2 */
static int gassign(cx *e, const cv *v, const ab_gcol *col, ab_val *out)
{
    memset(out, 0, sizeof *out);
    if (v->null) {
        out->null = true;
        return col->nullable ? 0 : (cfail(e, "NULL in a NOT NULL column"), -2);
    }
    switch (col->type) {
    case T_INT64: {
        __int128 lo = col->prec == 16 ? INT16_MIN : col->prec == 32 ? INT32_MIN : INT64_MIN;
        __int128 hi = col->prec == 16 ? INT16_MAX : col->prec == 32 ? INT32_MAX : INT64_MAX;
        if (v->t != T_INT64) return cfail(e, "not an integer"), -2;
        if (v->i < lo || v->i > hi) return cfail(e, "a value out of its integer's range"), -2;
        out->i = (int64_t)v->i;
        return 0;
    }
    case T_DECIMAL: {
        if (v->t != T_INT64 && v->t != T_DECIMAL) return cfail(e, "not a number"), -2;
        int s = v->t == T_DECIMAL ? v->s : 0;
        __int128 r = v->i;
        if (s < col->scale) {
            if (__builtin_mul_overflow(r, (__int128)cp10(col->scale - s), &r)) return cfail(e, "past its DECIMAL"), -2;
        } else if (s > col->scale) { /* PostgreSQL's assignment: half away from zero */
            unsigned __int128 d = cp10(s - col->scale), m = cmag(r), q = m / d, rem = m % d;
            if (rem >= d - rem) q++;
            r = r < 0 ? -(__int128)q : (__int128)q;
        }
        if (cmag(r) > cp10(col->prec) - 1) return cfail(e, "past its DECIMAL"), -2; /* F3e: to 38 digits */
        out->wide = col->prec > 18; /* the column's form: past 18 digits the 128 bits in i and hi */
        out->i = (int64_t)(uint64_t)(unsigned __int128)r;
        out->hi = out->wide ? (int64_t)(uint64_t)((unsigned __int128)r >> 64) : 0;
        return 0;
    }
    case T_TEXT: {
        if (v->t != T_TEXT) return cfail(e, "not a TEXT"), -2;
        if (v->n > 65535u || (v->n && !utf8_ok((const char *)v->p, v->n))) return cfail(e, "not a TEXT value"), -2;
        uint32_t chars = 0;
        for (uint32_t i = 0; i < v->n; i++) chars += (v->p[i] & 0xC0) != 0x80;
        if (col->vlen && chars > col->vlen) return cfail(e, "longer than its VARCHAR"), -2;
        out->s = v->p;
        out->len = v->n;
        return 0;
    }
    default:
        if (v->t != col->type || col->type == T_FLOAT64) return cfail(e, "another type"), -2;
        if ((col->type == T_BOOL && v->i != 0 && v->i != 1) ||
            ((col->type == T_TIMESTAMP || col->type == T_TIMESTAMPTZ) &&
             (v->i < -62135596800000000LL || v->i > 253402300799999999LL)) ||
            (col->type == T_DATE && (v->i < CK_DATE_MIN || v->i > CK_DATE_MAX)) ||
            (col->type == T_TIME && (v->i < 0 || v->i >= CK_DAY_US)))
            return cfail(e, "out of its type's range"), -2;
        out->i = (int64_t)v->i;
        return 0;
    }
}

int ab_gen_eval(const ab_check *c, const ab_val *row, const ab_gcol *col, ab_val *out, uint8_t **tbuf, char *err, size_t errn)
{
    cx e = {c, row, err, errn, {0}, 0};
    if (errn) err[0] = 0;
    *tbuf = NULL;
    memset(out, 0, sizeof *out);
    cv v;
    int rc = ceval(&e, c->root, &v);
    if (!rc && !v.null && v.t == T_TEXT) { /* its bytes outlive the evaluation's buffers */
        if (!(*tbuf = malloc(v.n ? v.n : 1))) {
            rc = cfail(&e, "out of memory");
        } else {
            if (v.n) memcpy(*tbuf, v.p, v.n);
            v.p = *tbuf;
        }
    }
    if (!rc) rc = gassign(&e, &v, col, out);
    for (unsigned i = 0; i < e.ntbuf; i++) free(e.tbuf[i]);
    if (rc && *tbuf) {
        free(*tbuf);
        *tbuf = NULL;
    }
    return rc;
}
