/* The SQL oracle (P0, docs/plan-p0.md 1a): the same statements on imagedb and on reference engines (SQLite in this
 * process; PostgreSQL, MySQL, MariaDB and SQL Server in private docker containers started by tests/oracle/run.sh),
 * every answer compared after normalisation. A seeded generator draws schemas' rows and statements from the SQL imagedb
 * supports, each printed in every engine's dialect; results compare as multisets unless an order is promised
 * (imagedb's key order under LIMIT, which the others are given as ORDER BY), and after every change the tables'
 * whole states are compared. Test-only: it links SQLite, libpq, libmysqlclient and unixODBC (the user's yes,
 * 2026-11-01); the engine links none of them. Nothing any engine answers is kept beyond this run's own output (SQL
 * Server's licence).
 *   oracle [--engines imagedb,sqlite,pg,mysql,mariadb,mssql] [--seeds A-B] [--steps N] [--dir DIR] [--keep-going]
 *          [--no-expr] [--no-fns] [--ping] [-v]   (--no-expr: 1a's generator, without arithmetic expressions, draw for draw;
 *          --no-fns: the generator before P2 S1's functions, CASE, CAST, IN, LIKE and ||, draw for draw)
 * The servers, from the environment: ORACLE_PG (a libpq conninfo), ORACLE_MYSQL and ORACLE_MARIADB ("socket user
 * password database"), ORACLE_ODBC (an ODBC connection string, out of ps). */
#include <errno.h>
#include <ftw.h>
#include <inttypes.h>
#include <libpq-fe.h>
#include <locale.h>
#include <mysql.h>
#include <sql.h> /* unixODBC's (an angle include: the engine's own sql.h is reached by its path) */
#include <sqlext.h>
#include <sqlite3.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "../../src/codec.h"
#include "../../src/db.h"
#include "../../src/sql.h"

/* ---- a growable string ------------------------------------------------------------------------------------- */

typedef struct sb {
    char *p;
    size_t n, cap;
} sb;

static void sb_put(sb *b, const char *s, size_t n)
{
    if (b->n + n + 1 > b->cap) {
        size_t c = b->cap ? b->cap * 2 : 256;
        while (c < b->n + n + 1) c *= 2;
        char *q = realloc(b->p, c);
        if (!q) {
            perror("oracle: realloc");
            exit(3);
        }
        b->p = q;
        b->cap = c;
    }
    memcpy(b->p + b->n, s, n);
    b->n += n;
    b->p[b->n] = 0;
}

static void sb_str(sb *b, const char *s) { sb_put(b, s, strlen(s)); }

__attribute__((format(printf, 2, 3))) static void sb_printf(sb *b, const char *fmt, ...)
{
    char tmp[512];
    va_list ap;
    va_start(ap, fmt);
    int k = vsnprintf(tmp, sizeof tmp, fmt, ap);
    va_end(ap);
    if (k < 0 || k >= (int)sizeof tmp) {
        fprintf(stderr, "oracle: a printed piece too long\n");
        exit(3);
    }
    sb_put(b, tmp, (size_t)k);
}

static void sb_reset(sb *b)
{
    b->n = 0;
    if (b->p) b->p[0] = 0;
}

/* ---- the schema, values, the generator ---------------------------------------------------------------------- */

enum { CT_INT, CT_DEC, CT_FLT, CT_TXT, CT_BOOL, CT_TS };
enum { D_IMDB, D_SQLITE, D_PG, D_MY, D_MA, D_MS, ND };
static const char *const DNAME[ND] = {"imagedb", "sqlite", "pg", "mysql", "mariadb", "mssql"};

typedef struct colspec {
    const char *name;
    int t;
} colspec;

/* t: id, a group key, an integer, one of the INT64 extremes, DECIMAL(12,2), FLOAT64, TEXT, BOOL, TIMESTAMP; u: a
 * child of t by tid. Every column but id is nullable. */
static const colspec TC[] = {{"id", CT_INT}, {"g", CT_INT}, {"a", CT_INT}, {"x", CT_INT}, {"d", CT_DEC},
                             {"f", CT_FLT},  {"s", CT_TXT}, {"k", CT_BOOL}, {"ts", CT_TS}};
static const colspec UC[] = {{"id", CT_INT}, {"tid", CT_INT}, {"v", CT_INT}, {"s", CT_TXT}};
#define NT 9
#define NU 4
#define MAXC 9
static const colspec *cols(int tab) { return tab ? UC : TC; }
static int ncols(int tab) { return tab ? NU : NT; }
static const char *tname(int tab) { return tab ? "u" : "t"; }

typedef struct val {
    bool null;
    int64_t i; /* INT, DEC (scaled by 100), BOOL, TS (microseconds since 1970) */
    double f;
    char s[64];
} val;

static uint64_t g_rng;
static uint64_t rnd(void)
{
    g_rng ^= g_rng >> 12;
    g_rng ^= g_rng << 25;
    g_rng ^= g_rng >> 27;
    return g_rng * 0x2545F4914F6CDD1Dull;
}
static int64_t rr(int64_t lo, int64_t hi) { return lo + (int64_t)(rnd() % (uint64_t)(hi - lo + 1)); }
static bool chance(int pct) { return (int)(rnd() % 100) < pct; }

/* text: ASCII, Latin-1 letters, CJK, a 4-byte emoji, '-', '_' and an inner space; never a trailing space (SQL
 * Server's comparison pads one away), never a control byte */
static const char *const PIECES[] = {"a",  "b",  "z",          "A",          "Z",            "0",
                                     "9",  "\xc3\xa9", "\xc3\xbc", "\xc3\x9f", "\xe6\x97\xa5", "\xe2\x82\xac",
                                     "\xf0\x9f\x98\x80", "-", "_", "a b"};
#define NPIECES (sizeof PIECES / sizeof PIECES[0])

static void gen_text(char *out, size_t cap)
{
    size_t n = 0;
    int k = (int)rr(0, 5);
    out[0] = 0;
    for (int i = 0; i < k; i++) {
        const char *p = PIECES[rnd() % NPIECES];
        size_t l = strlen(p);
        if (n + l + 1 > cap) break;
        memcpy(out + n, p, l);
        n += l;
        out[n] = 0;
    }
}

static const int64_t EXTREMES[] = {INT64_MIN, INT64_MIN + 1, -1, 0, 1, INT64_MAX - 1, INT64_MAX};

/* a value for column c of table tab (not the key); null_pct of them NULL */
static void gen_val(int tab, int c, val *v, int null_pct)
{
    memset(v, 0, sizeof *v);
    if (c > 0 && chance(null_pct)) {
        v->null = true;
        return;
    }
    int t = cols(tab)[c].t;
    const char *n = cols(tab)[c].name;
    switch (t) {
    case CT_INT:
        if (!strcmp(n, "g")) v->i = rr(0, 4);
        else if (!strcmp(n, "x")) v->i = chance(60) ? EXTREMES[rnd() % 7] : rr(-1000, 1000);
        else if (!strcmp(n, "v")) v->i = rr(-1000, 1000);
        else v->i = rr(-1000000, 1000000);
        break;
    case CT_DEC: v->i = rr(-1000000000, 1000000000); break; /* |d| < 10^7: DECIMAL(12,2), sums stay exact */
    case CT_FLT: v->f = (double)rr(-40000, 40000) / 4.0; break; /* dyadic: every summation order exact */
    case CT_TXT: gen_text(v->s, sizeof v->s); break;
    case CT_BOOL: v->i = rr(0, 1); break;
    case CT_TS: v->i = rr(0, 4102444799999999ll); break; /* 1970 to 2099, in microseconds */
    }
}

/* ---- statements ------------------------------------------------------------------------------------------------ */

enum { Q_SELECT, Q_INSERT, Q_UPDATE, Q_DELETE, Q_BEGIN, Q_COMMIT, Q_ROLLBACK };
enum { F_COL, F_COUNT_STAR, F_COUNT, F_SUM, F_MIN, F_MAX, F_AVG }; /* F_AVG: a tree's node only (1e) */
enum { OP_EQ, OP_NE, OP_LT, OP_LE, OP_GT, OP_GE, OP_BETWEEN, OP_ISNULL, OP_NOTNULL };
static const char *const OPS[] = {"=", "!=", "<", "<=", ">", ">="};

typedef struct item {
    int fn, tab, col;
    int ex; /* a tree (index + 1 into the statement's xe): fn, tab and col unused */
} item;

typedef struct pred {
    int tab, col, op;
    val a, b;
    int lx, ax, bx; /* a tree comparison: lx op ax (BETWEEN ax AND bx; IS NULL lx alone), else 0 */
    int bt;         /* a condition tree (1c: AND, OR, NOT over comparisons), else 0 */
} pred;

/* an expression's node (1b): imagedb's result type and scale kept with it, which every engine's answer is read as */
/* 1c: X_CMP, X_AND, X_OR, X_NOT conditions; X_PRED a plain predicate under one (the statement's xp[col]) */
/* P2 S1: X_FN a function (fn: XF_*, its arguments l, r, x3; a1, a2 its constants), X_CASE (WHEN l THEN r ELSE x3),
 * X_IN (l IN the X_LIST chain r: each its element l, the next r; fn 1: NOT IN), X_LIKE (l LIKE s ESCAPE '!'; fn 1:
 * NOT LIKE), X_CAST (l as ty, sc), X_TXT (the text s), X_NULL, X_VAL (a column's value: i, f, s by ty) */
enum { X_COL, X_INT, X_DEC, X_NEG, X_ADD, X_SUB, X_MUL, X_DIV, X_MOD, X_AGG, X_CMP, X_AND, X_OR, X_NOT, X_PRED,
       X_FN, X_CASE, X_IN, X_LIST, X_LIKE, X_CAST, X_TXT, X_NULL, X_VAL, X_SUBQ }; /* X_SUBQ (P2 S4): fn 0 IN's, 1 EXISTS, 2 a
                                                                          * value (agg i); tab, col; WHERE x3 */
typedef struct xnode {
    int op;
    int tab, col; /* X_COL */
    int64_t i;    /* X_INT; X_DEC scaled by 10^lscale */
    int lscale;
    int fn;       /* X_AGG: F_COUNT_STAR .. F_AVG, its operand l */
    int ty, sc;   /* the result's type and DECIMAL scale, by imagedb's rules (design.md, Expressions) */
    bool scaled;  /* X_DEC in a SET of d: SQLite's scaled integer (elsewhere a REAL: every literal there is dyadic) */
    int l, r;
    int x3;       /* X_CMP BETWEEN: the upper bound (fn: the comparison, OP_EQ .. OP_NOTNULL) */
    int64_t a1, a2; /* P2 S1: ROUND's places (-1: none), SUBSTR's start and length (-1: none) */
    int qual;     /* P2 S4b: an X_COL of a correlated subquery's table, by its alias ci (1), or of the statement
                   * around it, by its name (2); an X_SUBQ that is correlated (1: FROM its table AS ci) */
    double f;     /* X_VAL of a FLOAT64 */
    char s[136];  /* X_TXT, X_VAL of a TEXT, X_LIKE's pattern */
    bool dist;    /* P2 S2: X_AGG over its DISTINCT values (a FILTER (WHERE c): x3) */
} xnode;

typedef struct stmt {
    int kind, tab, join; /* join: 0 none, 1 INNER, 2 LEFT (t then u, on t.id = u.tid) */
    bool star;
    item it[8];
    int nit;
    pred pr[4];
    int npr;
    int gcol;  /* GROUP BY this column of t; -1: none */
    int limit; /* 0: none */
    val row[8][MAXC];
    int nrow;
    int scol[3];
    val sval[3];
    int nset;
    int sx[3];         /* a SET's tree (index + 1), else its value sval */
    xnode xe[512];     /* P2 S1: 512 (FNROOM keeps 120 free beyond every function form) */
    pred xp[8];        /* plain predicates under conditions (X_PRED): TEXT, TIMESTAMP, BOOL, DECIMAL against literals */
    int nxp;
    int nxe;
    unsigned skip;     /* engines this statement is not put to: a dialect computes it otherwise (a SELECT only) */
    int nord;          /* ORDER BY (1d): a key a column (col >= 0, of tab), a tree (ex) or an item's position (pos) */
    struct okey {
        int tab, col, ex, pos;
        bool desc, nf;
    } ord[3];
    bool distinct;
    int offset;        /* OFFSET n; 0: none (OFFSET 0 is never drawn) */
    int hv;            /* HAVING (1e): a condition's tree (index + 1), else 0 */
    bool fns;          /* P2 S1: it holds a function, CASE, CAST, IN, LIKE or || (counted when compared) */
    int gk[3], ngk;    /* P2 S2: GROUP BY these trees (gcol -1) */
    bool grp;          /* P2 S2's form (counted when compared) */
    int jx;            /* P2 S3: the join's other ON condition (a tree), else 0; join 3 RIGHT, 4 FULL, 5 CROSS */
    bool jkey2, jusing, jn3; /* ON's second key pair, t.s = u.s; USING (s) for ON; P2 S3's (counted when compared) */
    bool subq;         /* P2 S4: a subquery, a derived table or a CTE (counted when compared) */
    bool corr;         /* P2 S4b: a correlated subquery (counted when compared) */
    int narm, ncol;    /* P2 S5: a set operation's SELECTs (arm, armop[a] before arm a: 0 UNION, 1 UNION ALL, 2 INTERSECT,
                        * 3 EXCEPT) of ncol columns; its tail (stail: ORDER BY 1 [DESC] [LIMIT slim] [OFFSET soff]) */
    struct sarm {
        int tab, col[2];
        pred pr;
        bool has_pr;
    } arm[3];
    int armop[3];
    bool stail, sdesc;
    int slim, soff;
    int rec, rk;       /* P2 S5: WITH RECURSIVE: 1 a count to rk, 2 a walk from rstart along u; rall: UNION ALL */
    int64_t rstart;
    bool rall;
    bool win, wpart, wdesc, wdef, wtotal; /* P2 S6: a window statement (gen_wselect): its function wfn of column wcol,
                                        * NTILE's buckets or LAG's offset wk, its ROWS frame (wframe: wlo
                                        * PRECEDING, whi FOLLOWING) */
    int wfn, wcol, wk, wframe, wlo, whi;
    int dsel;          /* P2 S4: 1 FROM (SELECT dc FROM t [WHERE dpred]) AS x, 2 WITH x AS (...) SELECT ... FROM x */
    int dc[4], ndc;
    pred dpred;
    bool has_dpred;
} stmt;

static int64_t g_next_id;          /* the next new key of t, of u */
static int64_t g_tids[4096];       /* keys of t inserted (some may be gone) */
static int g_ntids;

/* values the tables hold (inserted or set, some since gone): a predicate drawn from them matches rows, where a random
 * one mostly matches none or all */
#define NSAMP 64
static val g_samp[2][MAXC][NSAMP];
static int g_nsamp[2][MAXC];

static void sample(int tab, int c, const val *v)
{
    if (v->null) return;
    int *n = &g_nsamp[tab][c];
    if (*n < NSAMP) g_samp[tab][c][(*n)++] = *v;
    else g_samp[tab][c][rnd() % NSAMP] = *v;
}

static void pred_val(int tab, int col, val *v)
{
    gen_val(tab, col, v, 0); /* a comparison with NULL is refused by imagedb: never generated */
    if (col == 0 && tab == 0 && g_ntids && chance(70)) v->i = g_tids[rnd() % (uint64_t)g_ntids];
    else if (g_nsamp[tab][col] && chance(50)) *v = g_samp[tab][col][rnd() % (uint64_t)g_nsamp[tab][col]];
}

/* a predicate on this column: IS [NOT] NULL, BETWEEN, or a comparison (BOOL: = and != only) */
static void gen_pred_on(int tab, int col, pred *p)
{
    memset(p, 0, sizeof *p);
    p->tab = tab;
    p->col = col;
    int t = cols(tab)[col].t;
    int r = (int)(rnd() % 100);
    if (r < 12) p->op = chance(50) ? OP_ISNULL : OP_NOTNULL;
    else if (r < 24 && t != CT_BOOL) p->op = OP_BETWEEN;
    else p->op = t == CT_BOOL ? (int)rr(OP_EQ, OP_NE) : (int)rr(OP_EQ, OP_GE);
    if (p->op == OP_ISNULL || p->op == OP_NOTNULL) return;
    pred_val(tab, col, &p->a);
    if (p->op == OP_BETWEEN) {
        pred_val(tab, col, &p->b);
        if (t == CT_FLT ? p->b.f < p->a.f : t == CT_TXT ? strcmp(p->b.s, p->a.s) < 0 : p->b.i < p->a.i) {
            val tmp = p->a;
            p->a = p->b;
            p->b = tmp;
        }
    }
}

/* half the time on a key or an indexed column (t: id, g, a, s, ts; u: id, tid), where imagedb's paths differ */
static void gen_pred(int tab, pred *p)
{
    static const int TIDX[] = {0, 1, 2, 6, 8};
    int col = chance(50) ? (tab ? (int)rr(0, 1) : TIDX[rnd() % 5]) : (int)(rnd() % (uint64_t)ncols(tab));
    gen_pred_on(tab, col, p);
}

static bool g_expr = true; /* --no-expr: 1a's generator, draw for draw */
static bool g_fns = true;  /* --no-fns: the generator before P2 S1, draw for draw */
/* A seed names the same statements only within one stage: each P2 stage (S1 to S4) adds forms to the default
 * generator's draws, so seed N's statements differ from the stage before's (a mismatch is reproduced on its own
 * build); --no-fns and --no-expr reproduce the generators before P2 S1 and before 1a. */
static bool g_in_txn;      /* generating a transaction's statements: no tree that may fail (PostgreSQL aborts the
                            * whole transaction at an error) */
static bool g_corr_ok;     /* P2 S4b: generating a SELECT's WHERE, where a subquery may be correlated */
#define TY(t, s) ((t) | ((s) << 8)) /* a column's type, a DECIMAL's scale with it */
#define TYT(ty) ((ty) & 0xff)
#define TYS(ty) ((ty) >> 8)
#define XN(q, k) (&(q)->xe[(k) - 1])
/* the reserves of the forms before P2 S1 are against 192 nodes, the array's size then, so --no-fns draws as before */
#define XROOM(q) ((q)->nxe + 24 <= 192) /* a tree comparison: at most ~18 */
#define XCOND_ROOM(q) ((q)->nxe + 60 <= 192)
#define FNROOM(q) ((q)->nxe + 120 <= (int)(sizeof (q)->xe / sizeof (q)->xe[0])) /* P2 S1: a form at most ~25 */
enum { XF_ABS = 1, XF_SIGN, XF_ROUND, XF_CEIL, XF_FLOOR, XF_MOD, XF_LENGTH, XF_SUBSTR, XF_TRIM, XF_LTRIM, XF_RTRIM,
       XF_POSITION, XF_COALESCE, XF_NULLIF, XF_LOWER, XF_UPPER, XF_REPLACE, XF_CONCAT };
static int gen_fint(stmt *q, int depth, bool fail);
static int gen_fdec(stmt *q, int depth, bool fail);
static int gen_fflt(stmt *q, int depth);
static int gen_fcmp(stmt *q);
static int gen_xtxt(stmt *q, int depth);
static int gen_ftagg(stmt *q);
static int gen_jcond(stmt *q);
static void fn_mark(stmt *q, int k);
static bool txt_computed(const stmt *q, int k);
static int gen_xcond(stmt *q, int depth, bool dml);
static void gen_xpred(stmt *q, pred *p, bool dml);
static void gen_order(stmt *q, bool window, bool distinct_ok);
static bool x_const(const stmt *q, int k);
static void xmark_pred(stmt *q, const pred *p);

static int gen_subq_cond(stmt *q); /* P2 S4 */
static void xmark(stmt *q, int k);

static void gen_preds(stmt *q, int max, bool two_tables)
{
    q->npr = (int)rr(0, max);
    for (int i = 0; i < q->npr; i++) {
        if (g_fns && q->kind == Q_SELECT && FNROOM(q) && chance(10)) { /* P2 S4, S4b: a subquery condition, maybe correlated */
            memset(&q->pr[i], 0, sizeof q->pr[i]);
            g_corr_ok = true;
            q->pr[i].bt = gen_subq_cond(q);
            g_corr_ok = false;
            xmark(q, q->pr[i].bt);
            continue;
        }
        if (g_expr && XROOM(q) && chance(15)) { /* a comparison of trees (DML: what SQLite computes alike) */
            gen_xpred(q, &q->pr[i], q->kind != Q_SELECT);
            if (q->kind == Q_SELECT) xmark_pred(q, &q->pr[i]);
        } else if (g_expr && XCOND_ROOM(q) && chance(14)) { /* 1c: AND, OR, NOT (DML: what SQLite computes alike) */
            memset(&q->pr[i], 0, sizeof q->pr[i]);
            g_corr_ok = q->kind == Q_SELECT; /* P2 S4b: WHERE */
            q->pr[i].bt = gen_xcond(q, 2, q->kind != Q_SELECT);
            g_corr_ok = false;
            if (q->kind == Q_SELECT) xmark(q, q->pr[i].bt);
        } else {
            gen_pred(two_tables && chance(40) ? 1 : q->tab, &q->pr[i]);
        }
    }
}

/* ---- expressions (1b): typed trees, imagedb's result type at every node ----------------------------------------- *
 * Where a row's value may make an operation fail (a zero divisor, an overflow), engines differ in when they evaluate:
 * PostgreSQL computes a SELECT list before it sorts for LIMIT, and any engine may test WHERE's conditions in another
 * order. So a tree that may fail stands only in a SELECT list without LIMIT and in an aggregate's argument (every
 * engine computes it on every row); WHERE's trees and SET's never fail (no INT64 extremes, divisors nonzero
 * literals, multipliers small). FLOAT64 trees stay dyadic (no division but by 2 or 4) so every engine prints them
 * exactly; SQLite computes DECIMAL as the scaled integer this oracle stores, so a SELECT with DECIMAL arithmetic is
 * not put to it, and a DECIMAL quotient is not put to SQL Server (its scale shrinks past 38 digits of precision). */



static int xnew(stmt *q, int op, int l, int r)
{
    if (q->nxe >= (int)(sizeof q->xe / sizeof q->xe[0])) { /* the callers' reserves keep it unreached: never silently */
        fprintf(stderr, "oracle: a statement's expression nodes ran out (a reserve too small)\n");
        exit(3);
    }
    xnode *n = &q->xe[q->nxe++];
    memset(n, 0, sizeof *n);
    n->op = op;
    n->l = l;
    n->r = r;
    if (op == X_NEG) {
        n->ty = XN(q, l)->ty;
        n->sc = XN(q, l)->sc;
    } else if (op >= X_ADD && op <= X_MOD) {
        const xnode *a = XN(q, l), *b = XN(q, r);
        int s1 = a->ty == CT_DEC ? a->sc : 0, s2 = b->ty == CT_DEC ? b->sc : 0, big = s1 > s2 ? s1 : s2;
        if (a->ty == CT_FLT || b->ty == CT_FLT) n->ty = CT_FLT;
        else if (a->ty == CT_INT && b->ty == CT_INT) n->ty = CT_INT;
        else {
            n->ty = CT_DEC;
            n->sc = op == X_MUL ? s1 + s2 : op == X_DIV ? big + 6 : big;
        }
    }
    return q->nxe;
}

static int xlit_int(stmt *q, int64_t v)
{
    int k = xnew(q, X_INT, 0, 0);
    XN(q, k)->i = v;
    XN(q, k)->ty = CT_INT;
    return k;
}

static int xlit_dec(stmt *q, int64_t v, int lscale)
{
    int k = xnew(q, X_DEC, 0, 0);
    XN(q, k)->i = v;
    XN(q, k)->lscale = lscale;
    XN(q, k)->ty = CT_DEC;
    XN(q, k)->sc = lscale;
    return k;
}

static int xcol(stmt *q, int tab, int col)
{
    int k = xnew(q, X_COL, 0, 0);
    xnode *n = XN(q, k);
    n->tab = tab;
    n->col = col;
    n->ty = cols(tab)[col].t;
    n->sc = n->ty == CT_DEC ? 2 : 0;
    return k;
}

/* the tree reads a column (else it is a constant, which an engine may compute before any row) */
static bool has_col(const stmt *q, int k)
{
    if (!k) return false;
    const xnode *n = XN(q, k);
    return n->op == X_COL || has_col(q, n->l) || has_col(q, n->r) || has_col(q, n->x3);
}

static int64_t nonzero(int64_t lo, int64_t hi)
{
    int64_t v = rr(lo, hi);
    return v ? v : 1;
}

/* an INT64 tree over the statement's tables (join: t's and u's): fail lets x (the INT64 extremes) in, any divisor */
static int gen_xint(stmt *q, int depth, bool fail)
{
    if (depth <= 0 || chance(35)) {
        if (chance(55)) {
            int tab = q->join ? (chance(40) ? 1 : 0) : q->tab;
            int col = tab ? (int)rr(0, 2) : fail && chance(30) ? 3 : (int)rr(0, 2); /* u: id, tid, v; t: id, g, a, x */
            return xcol(q, tab, col);
        }
        return xlit_int(q, chance(80) ? rr(-20, 20) : rr(-1000000, 1000000));
    }
    if (g_fns && q->kind == Q_SELECT && FNROOM(q) && chance(14)) return gen_fint(q, depth, fail); /* P2 S1 */
    int r = (int)rr(0, 99);
    if (r < 10) return xnew(q, X_NEG, gen_xint(q, depth - 1, fail), 0);
    int op = r < 40 ? X_ADD : r < 60 ? X_SUB : r < 80 ? X_MUL : r < 90 ? X_DIV : X_MOD;
    int l = gen_xint(q, depth - 1, fail), rt;
    if (op == X_MUL && !fail) rt = xlit_int(q, rr(-10, 10)); /* growth bounded */
    else if ((op == X_DIV || op == X_MOD) && !fail) rt = xlit_int(q, nonzero(-9, 9));
    else rt = gen_xint(q, depth - 1, fail);
    if ((op == X_DIV || op == X_MOD) && !has_col(q, rt)) /* a constant divisor: PostgreSQL folds it when planning, so a
                                                         * zero one fails there without a row; never zero then */
        rt = xlit_int(q, nonzero(-9, 9));
    return xnew(q, op, l, rt);
}

/* a DECIMAL tree: d, literals at scale 1 or 2, INT64 operands promoted; products' scales at most 6 */
static int gen_xdec(stmt *q, int depth, bool fail)
{
    if (depth <= 0 || chance(35)) {
        if ((q->tab == 0 || q->join) && chance(55)) return xcol(q, 0, 4);
        if (chance(20)) return gen_xint(q, 0, false);
        int s = (int)rr(1, 2);
        return xlit_dec(q, rr(-999, 999), s);
    }
    if (g_fns && q->kind == Q_SELECT && FNROOM(q) && chance(14)) return gen_fdec(q, depth, fail); /* P2 S1 */
    int r = (int)rr(0, 99);
    if (r < 8) return xnew(q, X_NEG, gen_xdec(q, depth - 1, fail), 0);
    int op = r < 38 ? X_ADD : r < 58 ? X_SUB : r < 80 ? X_MUL : r < 92 ? X_DIV : X_MOD;
    int l = gen_xdec(q, depth - 1, fail), rt;
    if ((op == X_DIV || op == X_MOD) && !fail) rt = chance(50) ? xlit_dec(q, nonzero(-999, 999), 2) : xlit_int(q, nonzero(-9, 9));
    else rt = gen_xdec(q, depth - 1, fail);
    if ((op == X_DIV || op == X_MOD) && !has_col(q, rt)) rt = xlit_dec(q, nonzero(-999, 999), 2);
    const xnode *a = XN(q, l), *b = XN(q, rt);
    if (op == X_MUL && (a->ty == CT_DEC ? a->sc : 0) + (b->ty == CT_DEC ? b->sc : 0) > 6) op = X_ADD;
    return xnew(q, op, l, rt);
}

/* a FLOAT64 tree that stays dyadic: f, a (exact in a double), small integers and quarters; / only by 2 or 4 */
static int gen_xflt(stmt *q, int depth)
{
    if (depth <= 0 || chance(30)) {
        int r = (int)rr(0, 99);
        if ((q->tab == 0 || q->join) && r < 55) return xcol(q, 0, 5);
        if ((q->tab == 0 || q->join) && r < 65) return xcol(q, 0, 2);
        if (r < 82) return xlit_int(q, rr(-8, 8));
        static const int64_t Q[] = {25, 50, 75, 125, 250, -25, -50, -75, -125, -250};
        return xlit_dec(q, Q[rnd() % 10], 2);
    }
    if (g_fns && q->kind == Q_SELECT && FNROOM(q) && chance(14)) return gen_fflt(q, depth); /* P2 S1 */
    int r = (int)rr(0, 99);
    if (r < 10) return xnew(q, X_NEG, gen_xflt(q, depth - 1), 0);
    if (r < 25) return xnew(q, X_DIV, gen_xflt(q, depth - 1), xlit_int(q, chance(50) ? 2 : 4));
    int op = r < 55 ? X_ADD : r < 80 ? X_SUB : X_MUL;
    return xnew(q, op, gen_xflt(q, depth - 1), gen_xflt(q, depth - 1));
}

/* a tree of one of the three types */
static int gen_xany(stmt *q, int depth, bool fail)
{
    int r = (int)rr(0, 99);
    return r < 45 ? gen_xint(q, depth, fail) : r < 75 ? gen_xdec(q, depth, fail) : gen_xflt(q, depth);
}

/* SQLite computes DECIMAL as its scaled integer, and DECIMAL in a FLOAT64 expression as REAL: a tree it computes as
 * imagedb does has no DECIMAL-typed node but a literal under a FLOAT64 one */
static bool lite_ok(const stmt *q, int k, bool under_flt)
{
    if (!k) return true;
    const xnode *n = XN(q, k);
    if (n->op == X_IN && XN(q, n->l)->op == X_COL && XN(q, n->l)->ty == CT_DEC) return true; /* P2 S1: d IN (values):
                                                                                           * its scaled integers */
    if (n->op == X_AGG && n->fn != F_AVG && n->l && XN(q, n->l)->op == X_COL) /* P2 S2: COUNT, SUM, MIN, MAX of a bare
                                                                              * column: d's its scaled integers */
        return lite_ok(q, n->x3, false);
    if (n->ty == CT_DEC && !(n->op == X_DEC && under_flt)) return false;
    return lite_ok(q, n->l, n->ty == CT_FLT) && lite_ok(q, n->r, n->ty == CT_FLT) && lite_ok(q, n->x3, n->ty == CT_FLT);
}

/* the tree holds a SUM of a DECIMAL */
static bool dec_sum(const stmt *q, int k)
{
    if (!k) return false;
    const xnode *n = XN(q, k);
    if (n->op == X_AGG && n->fn == F_SUM && n->ty == CT_DEC) return true;
    return dec_sum(q, n->l) || dec_sum(q, n->r) || dec_sum(q, n->x3);
}

/* SQL Server keeps a DECIMAL within 38 digits by shrinking its scale (rounding): no DECIMAL quotient or remainder (its
 * division's scale is max(6, s1 + p2 + 1), past 38 shrunk), and no DECIMAL arithmetic over a SUM (decimal(38, s)) */
static bool ms_ok(const stmt *q, int k)
{
    if (!k) return true;
    const xnode *n = XN(q, k);
    if (n->ty == CT_DEC && (n->op == X_DIV || n->op == X_MOD || (n->op == X_FN && n->fn == XF_MOD))) return false;
    if (n->op == X_AGG && n->fn == F_AVG && n->ty == CT_DEC) return false; /* its AVG: an INT64's an INT64, a
                                                                          * DECIMAL's at max(s, 6) places */
    if (n->ty == CT_DEC && n->op >= X_ADD && n->op <= X_MOD && (dec_sum(q, n->l) || dec_sum(q, n->r))) return false;
    return ms_ok(q, n->l) && ms_ok(q, n->r) && ms_ok(q, n->x3);
}

/* MariaDB 12.3.3: a DECIMAL remainder of a negative value is -0.00, which compares below 0 and unequal to it
 * (-5.37 % 0.01 < 0 is true; reproduced alone, 2026-11-04; its * 0 and negation give 0.00): no DECIMAL % for it */
static bool ma_ok(const stmt *q, int k)
{
    if (!k) return true;
    const xnode *n = XN(q, k);
    if (n->ty == CT_DEC && (n->op == X_MOD || (n->op == X_FN && n->fn == XF_MOD))) return false;
    return ma_ok(q, n->l) && ma_ok(q, n->r) && ma_ok(q, n->x3);
}

/* MySQL 8.4.13: a BIGINT column compared with a constant DECIMAL expression through its index matches the expression
 * rounded to an integer (tid = ((8.14) + (-6.45)) finds tid 2; with the index ignored, or the literal 1.69, nothing;
 * reproduced alone, 2026-11-04): no comparison of a bare INT64 column with a constant
 * tree that is not an INT64 or a plain literal for it, either way round */
static bool my_pair_ok(const stmt *q, int c, int o)
{
    if (!c || !o) return true;
    const xnode *x = XN(q, c), *y = XN(q, o);
    return !(x->op == X_COL && x->ty == CT_INT && x_const(q, o) && y->ty != CT_INT && y->op != X_DEC);
}

static bool my_ok(const stmt *q, int k)
{
    if (!k) return true;
    const xnode *n = XN(q, k);
    if (n->op == X_CMP && (!my_pair_ok(q, n->l, n->r) || !my_pair_ok(q, n->r, n->l) || !my_pair_ok(q, n->l, n->x3) ||
                           !my_pair_ok(q, n->x3, n->l)))
        return false;
    return my_ok(q, n->l) && my_ok(q, n->r) && my_ok(q, n->x3);
}

/* a tree put to engines: the SELECT's skip mask follows it */
static void xmark(stmt *q, int k)
{
    if (!lite_ok(q, k, false)) q->skip |= 1u << D_SQLITE;
    if (!ms_ok(q, k)) q->skip |= 1u << D_MS;
    if (!ma_ok(q, k)) q->skip |= 1u << D_MA;
    if (!my_ok(q, k)) q->skip |= 1u << D_MY;
    fn_mark(q, k); /* P2 S1 */
}

/* a tree predicate put to engines: its trees, and its own comparison (MySQL's index defect, my_pair_ok) */
static void xmark_pred(stmt *q, const pred *p)
{
    xmark(q, p->lx);
    xmark(q, p->ax);
    xmark(q, p->bx);
    if (!my_pair_ok(q, p->lx, p->ax) || !my_pair_ok(q, p->ax, p->lx) || !my_pair_ok(q, p->lx, p->bx) ||
        !my_pair_ok(q, p->bx, p->lx))
        q->skip |= 1u << D_MY;
}

/* an aggregate of a tree: SUM's and AVG's of INT64, DECIMAL or FLOAT64; MIN, MAX, COUNT of any. AVG (1e) is SUM /
 * COUNT at six places past an INT64's or a DECIMAL's scale, a FLOAT64's a FLOAT64 */
static int gen_xagg(stmt *q, bool fail)
{
    int fn = (int)rr(F_COUNT_STAR, F_AVG);
    if (fn == F_COUNT_STAR) {
        int k = xnew(q, X_AGG, 0, 0);
        XN(q, k)->fn = fn;
        XN(q, k)->ty = CT_INT;
        return k;
    }
    int a = gen_xany(q, 1, fail && fn != F_SUM); /* a SUM of x would leave INT64 in SQL Server (bigint) */
    if (fn == F_SUM && XN(q, a)->ty == CT_INT && XN(q, a)->op == X_COL && XN(q, a)->col == 3 && XN(q, a)->tab == 0)
        a = xcol(q, 0, 2);
    int k = xnew(q, X_AGG, a, 0);
    xnode *n = XN(q, k);
    n->fn = fn;
    n->ty = fn == F_COUNT ? CT_INT : XN(q, a)->ty;
    n->sc = fn == F_COUNT ? 0 : XN(q, a)->sc;
    if (fn == F_AVG && n->ty != CT_FLT) {
        n->sc = (n->ty == CT_DEC ? n->sc : 0) + 6;
        n->ty = CT_DEC;
    }
    return k;
}

/* a tree of aggregates: one or two, combined with small literals (SUM(a) / COUNT(*), MAX(e) - MIN(e), SUM(d) * 2) */
static int gen_xaggtree(stmt *q, bool fail)
{
    int l = gen_xagg(q, fail);
    int r = (int)rr(0, 99);
    if (r < 30) return l;
    if (r < 55) {
        int b = gen_xagg(q, fail);
        const xnode *x = XN(q, l), *y = XN(q, b);
        bool num = (x->ty == CT_INT || x->ty == CT_DEC) && (y->ty == CT_INT || y->ty == CT_DEC);
        bool flt = x->ty == CT_FLT && (y->ty == CT_FLT || y->ty == CT_INT);
        if (!num && !flt) return l;
        /* a FLOAT64's / stays out (not dyadic); one by an aggregate only where a failure is welcome (COUNT(*) is 0
         * over no row) */
        int op = flt ? (chance(50) ? X_ADD : X_SUB) : (int)rr(X_ADD, fail ? X_DIV : X_MUL);
        return xnew(q, op, l, b);
    }
    const xnode *x = XN(q, l);
    if (x->ty != CT_INT && x->ty != CT_DEC && x->ty != CT_FLT) return l;
    int op = x->ty == CT_FLT ? (chance(50) ? X_ADD : X_MUL) : (int)rr(X_ADD, X_MOD);
    int lit = op == X_DIV || op == X_MOD ? xlit_int(q, nonzero(1, 9)) : xlit_int(q, rr(-5, 5));
    return xnew(q, op, l, lit);
}

/* a WHERE condition between trees that never fail: comparable types (two numbers) */
static void gen_xpred(stmt *q, pred *p, bool dml)
{
    memset(p, 0, sizeof *p);
    int t1 = dml ? (chance(60) ? CT_INT : CT_FLT) : (int)rr(0, 2); /* DML: what SQLite computes as the others do */
    p->lx = t1 == CT_INT ? gen_xint(q, 2, false) : t1 == CT_DEC ? gen_xdec(q, 2, false) : gen_xflt(q, 2);
    int r = (int)rr(0, 99);
    if (r < 10) {
        p->op = chance(50) ? OP_ISNULL : OP_NOTNULL;
        return;
    }
    int t2 = dml ? t1 : (int)rr(0, 2);
    p->op = r < 22 ? OP_BETWEEN : (int)rr(OP_EQ, OP_GE);
    p->ax = t2 == CT_INT ? gen_xint(q, 1, false) : t2 == CT_DEC ? gen_xdec(q, 1, false) : gen_xflt(q, 1);
    if (p->op == OP_BETWEEN) p->bx = t2 == CT_INT ? gen_xint(q, 1, false) : t2 == CT_DEC ? gen_xdec(q, 1, false) : gen_xflt(q, 1);
}

/* ---- conditions (1c): AND, OR, NOT over comparisons that never fail ----------------------------------------------- */

static int xbool(stmt *q, int op, int l, int r)
{
    int k = xnew(q, op, l, r);
    XN(q, k)->ty = CT_BOOL;
    return k;
}

/* ---- P2 S1: functions, CASE, CAST, IN, LIKE and || ----------------------------------------------------------------- *
 * Drawn in SELECTs only (a dialect that computes one otherwise is skipped there, where a DML statement is put to every
 * engine), never under --no-fns (the generator before them, draw for draw), each form only within FNROOM: its children
 * one level shallower, a CASE's condition a column's (gen_fcond), so a form holds at most ~25 nodes. Definitions pinned
 * to what the engines agree on (docs/plan-p2.md, S1): SUBSTR from 1; a needle and REPLACE's pattern never empty; LIKE
 * always with ESCAPE '!' and never '['; ROUND of a FLOAT64, LOWER and UPPER compared with SQLite alone (fn_mark: the
 * servers round a double's half to even, and map case past ASCII); a CAST to INT64 only of an integral value; no
 * FLOAT64 cast to TEXT (SQLite writes 3.0); a CASE's or COALESCE's FLOAT64 branches each a FLOAT64 (imagedb converts
 * no value). A computed TEXT is printed under the column's binary collation (put_x: a constant one would be ordered by
 * the server's default), and compared nowhere in SQL Server (its = pads a trailing space away). */

static int xfn(stmt *q, int fn, int l, int r, int ty, int sc)
{
    int k = xnew(q, X_FN, l, r);
    xnode *n = XN(q, k);
    n->fn = fn;
    n->ty = ty;
    n->sc = sc;
    n->a1 = n->a2 = -1;
    q->fns = true;
    return k;
}

static int xtxt(stmt *q, const char *s)
{
    int k = xnew(q, X_TXT, 0, 0);
    snprintf(XN(q, k)->s, sizeof XN(q, k)->s, "%s", s);
    XN(q, k)->ty = CT_TXT;
    return k;
}

static int xcast(stmt *q, int l, int ty, int sc)
{
    int k = xnew(q, X_CAST, l, 0);
    XN(q, k)->ty = ty;
    XN(q, k)->sc = sc;
    q->fns = true;
    return k;
}

/* a CASE's or COALESCE's branches unified as imagedb does (INT64 and DECIMAL: a DECIMAL at the larger scale) */
static void unify2(const xnode *a, const xnode *b, int *ty, int *sc)
{
    *ty = a->ty == b->ty ? a->ty : CT_DEC;
    *sc = (a->ty == CT_DEC ? a->sc : 0) > (b->ty == CT_DEC ? b->sc : 0) ? (a->ty == CT_DEC ? a->sc : 0)
                                                                         : (b->ty == CT_DEC ? b->sc : 0);
    if (*ty != CT_DEC) *sc = 0;
}

static int as_flt(stmt *q, int k) { return XN(q, k)->ty == CT_FLT ? k : xcast(q, k, CT_FLT, 0); }

/* a CASE's condition: a column's plain predicate, or an INT64 column or literal against a literal (no tree: FNROOM) */
static int gen_fcond(stmt *q)
{
    if (q->nxp < (int)(sizeof q->xp / sizeof q->xp[0]) && chance(50)) {
        gen_pred(q->join && chance(40) ? 1 : q->tab, &q->xp[q->nxp]);
        int k = xbool(q, X_PRED, 0, 0);
        XN(q, k)->col = q->nxp++;
        return k;
    }
    int c = gen_xint(q, 0, false);
    int k = xbool(q, X_CMP, c, xlit_int(q, rr(-20, 20)));
    XN(q, k)->fn = (int)rr(OP_EQ, OP_GE);
    return k;
}

static int xcase(stmt *q, int then, int els)
{
    int k = xnew(q, X_CASE, gen_fcond(q), then);
    xnode *n = XN(q, k);
    n->x3 = els;
    if (els) unify2(XN(q, then), XN(q, els), &n->ty, &n->sc);
    else n->ty = XN(q, then)->ty, n->sc = XN(q, then)->sc;
    q->fns = true;
    return k;
}

/* a TEXT tree: s (t's or u's), a literal or an INT64 cast; SUBSTR, TRIM, LTRIM, RTRIM, LOWER, UPPER, REPLACE, ||,
 * COALESCE, NULLIF and CASE over them */
static int gen_xtxt(stmt *q, int depth)
{
    if (depth <= 0 || chance(30)) {
        int r = (int)rr(0, 99);
        if (r < 60) {
            int tab = q->join ? (chance(40) ? 1 : 0) : q->tab;
            return xcol(q, tab, tab ? 3 : 6);
        }
        if (r < 85) {
            char s[64];
            gen_text(s, sizeof s);
            return xtxt(q, s);
        }
        return xcast(q, gen_xint(q, 0, false), CT_TXT, 0);
    }
    int r = (int)rr(0, 99), x = gen_xtxt(q, depth - 1), k;
    if (r < 18) {
        k = xfn(q, XF_SUBSTR, x, 0, CT_TXT, 0);
        XN(q, k)->a1 = rr(1, 4);
        XN(q, k)->a2 = chance(70) ? rr(0, 4) : -1;
        return k;
    }
    if (r < 30) return xfn(q, (int)rr(XF_TRIM, XF_RTRIM), x, 0, CT_TXT, 0);
    if (r < 40) return xfn(q, chance(50) ? XF_LOWER : XF_UPPER, x, 0, CT_TXT, 0);
    if (r < 52) {
        char to[64];
        gen_text(to, 16);
        k = xfn(q, XF_REPLACE, x, xtxt(q, PIECES[rnd() % NPIECES]), CT_TXT, 0);
        XN(q, k)->x3 = xtxt(q, to);
        return k;
    }
    if (r < 72) return xfn(q, XF_CONCAT, x, gen_xtxt(q, depth - 1), CT_TXT, 0);
    if (r < 80) {
        char s[64];
        gen_text(s, sizeof s);
        return xfn(q, XF_COALESCE, x, xtxt(q, s), CT_TXT, 0);
    }
    if (r < 86) return xfn(q, XF_NULLIF, x, xtxt(q, PIECES[rnd() % NPIECES]), CT_TXT, 0);
    return xcase(q, x, chance(70) ? gen_xtxt(q, depth - 1) : 0);
}

/* a needle: one or two pieces, never empty */
static int gen_needle(stmt *q)
{
    char s[32];
    snprintf(s, sizeof s, "%s%s", PIECES[rnd() % NPIECES], chance(30) ? PIECES[rnd() % NPIECES] : "");
    return xtxt(q, s);
}

/* an INT64 function form: ABS, SIGN, CEIL, FLOOR, ROUND, MOD, LENGTH, POSITION, CASE, COALESCE, NULLIF, CASTs */
static int gen_fint(stmt *q, int depth, bool fail)
{
    int r = (int)rr(0, 99), k;
    if (r < 10) return xfn(q, XF_ABS, gen_xint(q, depth - 1, fail), 0, CT_INT, 0);
    if (r < 18) return xfn(q, XF_SIGN, gen_xany(q, depth - 1, fail), 0, CT_INT, 0);
    if (r < 26) {
        int fn = chance(50) ? XF_CEIL : XF_FLOOR;
        return xfn(q, fn, gen_xint(q, depth - 1, fail), 0, CT_INT, 0);
    }
    if (r < 31) return xfn(q, XF_ROUND, gen_xint(q, depth - 1, fail), 0, CT_INT, 0);
    if (r < 38) { /* MOD: the remainder's rules (xnew's X_MOD), named as a function */
        int a = gen_xint(q, depth - 1, fail);
        k = xnew(q, X_MOD, a, xlit_int(q, nonzero(-9, 9)));
        XN(q, k)->op = X_FN;
        XN(q, k)->fn = XF_MOD;
        q->fns = true;
        return k;
    }
    if (r < 52) return xfn(q, XF_LENGTH, gen_xtxt(q, depth - 1), 0, CT_INT, 0);
    if (r < 60) {
        int nd = gen_needle(q);
        return xfn(q, XF_POSITION, nd, gen_xtxt(q, depth - 1), CT_INT, 0);
    }
    if (r < 74) {
        int t = gen_xint(q, depth - 1, fail);
        return xcase(q, t, chance(75) ? gen_xint(q, depth - 1, fail) : 0);
    }
    if (r < 82) {
        int a = gen_xint(q, depth - 1, fail);
        return xfn(q, XF_COALESCE, a, gen_xint(q, depth - 1, fail), CT_INT, 0);
    }
    if (r < 88) {
        int a = gen_xint(q, depth - 1, fail);
        return xfn(q, XF_NULLIF, a, gen_xint(q, 0, false), CT_INT, 0);
    }
    if (r < 94) return xcast(q, xcast(q, gen_xint(q, depth - 1, fail), CT_TXT, 0), CT_INT, 0); /* both ways, exact */
    /* an integral value of another kind: FLOOR or CEIL of a FLOAT64, ROUND or FLOOR of a DECIMAL */
    if (chance(50)) {
        int fn = chance(50) ? XF_FLOOR : XF_CEIL;
        return xcast(q, xfn(q, fn, as_flt(q, gen_xflt(q, depth - 1)), 0, CT_FLT, 0), CT_INT, 0);
    }
    int d = gen_xdec(q, depth - 1, false);
    k = xfn(q, chance(50) ? XF_ROUND : XF_FLOOR, d, 0, XN(q, d)->ty, 0);
    return xcast(q, k, CT_INT, 0);
}

/* a DECIMAL function form: ABS, ROUND (places), CEIL, FLOOR, MOD, CASE, COALESCE, NULLIF, CASTs to DECIMAL(18, s) */
static int gen_fdec(stmt *q, int depth, bool fail)
{
    int r = (int)rr(0, 99), x, k;
    if (r < 12) {
        x = gen_xdec(q, depth - 1, fail);
        return xfn(q, XF_ABS, x, 0, XN(q, x)->ty, XN(q, x)->sc);
    }
    if (r < 30) {
        x = gen_xdec(q, depth - 1, fail);
        const xnode *a = XN(q, x);
        if (a->ty != CT_DEC) return xfn(q, XF_ROUND, x, 0, a->ty, 0); /* an INT64's places would print .00 in PostgreSQL */
        int64_t pl = rr(0, 3);
        k = xfn(q, XF_ROUND, x, 0, CT_DEC, a->sc < pl ? a->sc : (int)pl);
        XN(q, k)->a1 = pl;
        return k;
    }
    if (r < 42) {
        x = gen_xdec(q, depth - 1, fail);
        return xfn(q, chance(50) ? XF_CEIL : XF_FLOOR, x, 0, XN(q, x)->ty, 0);
    }
    if (r < 50) {
        int a = gen_xdec(q, depth - 1, fail);
        k = xnew(q, X_MOD, a, xlit_dec(q, nonzero(-999, 999), 2));
        XN(q, k)->op = X_FN;
        XN(q, k)->fn = XF_MOD;
        q->fns = true;
        return k;
    }
    if (r < 64) {
        int t = gen_xdec(q, depth - 1, fail);
        return xcase(q, t, chance(75) ? gen_xdec(q, depth - 1, fail) : 0);
    }
    if (r < 74) {
        int a = gen_xdec(q, depth - 1, fail), b = gen_xdec(q, depth - 1, fail), ty, sc;
        unify2(XN(q, a), XN(q, b), &ty, &sc);
        return xfn(q, XF_COALESCE, a, b, ty, sc);
    }
    if (r < 80) {
        x = gen_xdec(q, depth - 1, fail);
        return xfn(q, XF_NULLIF, x, gen_xdec(q, 0, false), XN(q, x)->ty, XN(q, x)->sc);
    }
    if (r < 87) return xcast(q, gen_xint(q, depth - 1, false), CT_DEC, 2);  /* |x| < 10^9: DECIMAL(18,2) holds it */
    if (r < 94) return xcast(q, gen_xdec(q, depth - 1, false), CT_DEC, 1); /* fewer places: half away from zero */
    return xcast(q, as_flt(q, gen_xflt(q, depth > 1 ? 1 : 0)), CT_DEC, 4);   /* a dyadic value, exact at 4 places */
}

/* a FLOAT64 function form: ABS, CEIL, FLOOR, ROUND, a CAST of an INT64, CASE and COALESCE (FLOAT64 branches) */
static int gen_fflt(stmt *q, int depth)
{
    int r = (int)rr(0, 99);
    if (r < 15) return xfn(q, XF_ABS, as_flt(q, gen_xflt(q, depth - 1)), 0, CT_FLT, 0);
    if (r < 40) {
        int fn = chance(50) ? XF_CEIL : XF_FLOOR;
        return xfn(q, fn, as_flt(q, gen_xflt(q, depth - 1)), 0, CT_FLT, 0);
    }
    if (r < 55) return xfn(q, XF_ROUND, as_flt(q, gen_xflt(q, depth - 1)), 0, CT_FLT, 0);
    if (r < 70) return xcast(q, gen_xint(q, depth - 1, false), CT_FLT, 0);
    if (r < 88) {
        int t = as_flt(q, gen_xflt(q, depth - 1));
        return xcase(q, t, chance(75) ? as_flt(q, gen_xflt(q, depth - 1)) : 0);
    }
    int a = as_flt(q, gen_xflt(q, depth - 1));
    return xfn(q, XF_COALESCE, a, as_flt(q, gen_xflt(q, depth - 1)), CT_FLT, 0);
}

static int xval(stmt *q, int ty, const val *v)
{
    int k = xnew(q, X_VAL, 0, 0);
    xnode *n = XN(q, k);
    n->ty = ty;
    n->sc = ty == CT_DEC ? 2 : 0;
    n->i = v->i;
    n->f = v->f;
    snprintf(n->s, sizeof n->s, "%s", v->s);
    return k;
}

/* x IN (...) and NOT IN: a column of any type against its own values (a NULL among them sometimes), or an INT64 tree
 * against integers */
static int gen_in(stmt *q)
{
    int tab = q->join ? (chance(40) ? 1 : 0) : q->tab, col = -1, l;
    if (chance(70)) {
        col = (int)(rnd() % (uint64_t)ncols(tab));
        l = xcol(q, tab, col);
    } else {
        l = gen_xint(q, 1, false);
    }
    int k = xbool(q, X_IN, l, 0), prev = 0, n = (int)rr(1, 5);
    XN(q, k)->fn = chance(30);
    for (int i = 0; i < n; i++) {
        int e;
        if (chance(10)) {
            e = xnew(q, X_NULL, 0, 0);
            XN(q, e)->ty = XN(q, l)->ty;
        } else if (col >= 0) {
            val v;
            pred_val(tab, col, &v);
            e = xval(q, XN(q, l)->ty, &v);
        } else {
            e = xlit_int(q, rr(-20, 20));
        }
        int li = xnew(q, X_LIST, e, 0);
        if (prev) XN(q, prev)->r = li;
        else XN(q, k)->r = li;
        prev = li;
    }
    q->fns = true;
    return k;
}

/* s LIKE / NOT LIKE a pattern made from one of its values: characters kept, replaced by _, a run by %; its own %, _
 * and ! escaped by ! (always ESCAPE '!': PostgreSQL's default escape is a backslash, imagedb has none) */
static int gen_like(stmt *q)
{
    int tab = q->join ? (chance(40) ? 1 : 0) : q->tab, c = tab ? 3 : 6;
    int l = chance(80) ? xcol(q, tab, c) : gen_xtxt(q, 1);
    val v;
    pred_val(tab, c, &v);
    char pat[136];
    size_t n = 0;
    if (chance(30)) pat[n++] = '%';
    for (const unsigned char *p = (const unsigned char *)v.s; *p && n + 8 < sizeof pat;) {
        size_t cl = *p < 0x80 ? 1 : *p < 0xE0 ? 2 : *p < 0xF0 ? 3 : 4;
        int r = (int)rr(0, 99);
        if (r < 15) {
            pat[n++] = '_';
        } else if (r < 25) {
            if (!n || pat[n - 1] != '%') pat[n++] = '%';
        } else {
            if (*p == '%' || *p == '_' || *p == '!') pat[n++] = '!';
            memcpy(pat + n, p, cl);
            n += cl;
        }
        p += cl;
    }
    if (chance(30) && (!n || pat[n - 1] != '%')) pat[n++] = '%';
    pat[n] = 0;
    int k = xbool(q, X_LIKE, l, 0);
    snprintf(XN(q, k)->s, sizeof XN(q, k)->s, "%s", pat);
    XN(q, k)->fn = chance(25);
    q->fns = true;
    return k;
}

/* P2 S4: a condition on one INT64 column of the subquery's table (t: g, a; u: tid, v), never column `avoid`, against a
 * small literal */
static int gen_subq_where(stmt *q, int tab, int avoid)
{
    int c = (int)rr(1, 2);
    if (c == avoid) c = 3 - c;
    int lit = xlit_int(q, rr(-3, 6));
    int k = xbool(q, X_CMP, xcol(q, tab, c), lit);
    XN(q, k)->fn = (int)rr(OP_EQ, OP_GE);
    return k;
}

/* P2 S4: an uncorrelated subquery in a condition: x [NOT] IN (SELECT y FROM w [WHERE c]), EXISTS (SELECT 1 FROM w
 * WHERE c), or x op (SELECT MAX(y) | MIN(y) | COUNT(*) FROM w [WHERE c]); x a column of the outer table, y one of w of
 * x's type (INT64: t's id, g, a, u's id, tid, v; TEXT: their s). The values are random over wide ranges, so a set of
 * another column rarely holds x: half the INs read x's own column (every x found, a NULL in the set when the filter is
 * on another column), and half the EXISTS look for c = (SELECT MAX(c) ...), one row or a few (the mutants' finding:
 * EXISTS of exactly one row, NOT IN over a NULL and the set's search were each caught in 0 to 2 seeds of 30) */
/* P2 S4b: the columns of a correlated subquery's own table, by its alias ci (a nested subquery's are its own) */
static void corr_mark(stmt *q, int k)
{
    if (!k) return;
    xnode *n = XN(q, k);
    if (n->op == X_SUBQ) return;
    if (n->op == X_COL) n->qual = 1;
    corr_mark(q, n->l); /* height-bounded */
    corr_mark(q, n->r);
    corr_mark(q, n->x3);
}

/* P2 S4b: subquery sq made correlated with the statement around it (WHERE only: g_corr_ok): its table aliased ci, a
 * comparison of one of its columns with one of the outer table's, by name (mostly ci.tid = t.id, which matches: u's tid
 * is often a t id), either side first, sometimes the outer one in a tree (the mutants: a comparison only ever written
 * inner first, and bare, left imagedb's flip and its constant outer values untested), ANDed to its WHERE */
static void corr_add(stmt *q, int sq, int otab)
{
    int itab = XN(q, sq)->tab, ic, oc;
    if (itab == 1 && otab == 0 && chance(60)) ic = 1, oc = 0;
    else ic = (int)rr(0, 2), oc = (int)rr(0, 2);
    corr_mark(q, XN(q, sq)->x3);
    int a = xcol(q, itab, ic), o = xcol(q, otab, oc);
    XN(q, a)->qual = 1;
    XN(q, o)->qual = 2;
    if (chance(50)) o = xnew(q, X_ADD, o, xlit_int(q, rr(-2, 2))); /* in a tree: a residual on each run (imagedb takes a
                                                                    * bare outer column as a plain predicate) */
    int k = chance(50) ? xbool(q, X_CMP, a, o) : xbool(q, X_CMP, o, a); /* either side first */
    XN(q, k)->fn = chance(50) ? OP_EQ : (int)rr(OP_EQ, OP_GE);
    XN(q, sq)->x3 = XN(q, sq)->x3 ? xbool(q, X_AND, XN(q, sq)->x3, k) : k;
    XN(q, sq)->qual = 1;
    q->corr = true;
}

static int gen_subq_cond(stmt *q)
{
    int otab = q->join ? (chance(40) ? 1 : 0) : q->tab, itab = chance(70) ? 1 : 0, r = (int)rr(0, 99);
    bool text = r < 50 && chance(25);
    int oc = text ? (otab ? 3 : 6) : (int)rr(0, 2), ic = text ? (itab ? 3 : 6) : (int)rr(0, 2);
    q->fns = q->subq = true;
    if (r < 50) { /* IN */
        if (chance(50)) itab = otab, ic = oc; /* its own column */
        int sq = xnew(q, X_SUBQ, 0, 0);
        XN(q, sq)->tab = itab;
        XN(q, sq)->col = ic;
        XN(q, sq)->fn = 0;
        XN(q, sq)->ty = text ? CT_TXT : CT_INT;
        if (chance(60)) XN(q, sq)->x3 = gen_subq_where(q, itab, ic);
        if (g_corr_ok && chance(70)) corr_add(q, sq, otab); /* P2 S4b */
        int k = xbool(q, X_IN, xcol(q, otab, oc), sq);
        XN(q, k)->fn = chance(45); /* NOT IN */
        return k;
    }
    int sq = xnew(q, X_SUBQ, 0, 0);
    XN(q, sq)->tab = itab;
    XN(q, sq)->col = ic;
    if (r < 70) { /* EXISTS, under NOT sometimes */
        XN(q, sq)->fn = 1;
        XN(q, sq)->ty = CT_BOOL;
        if (chance(50)) { /* c = | >= (SELECT MAX(c) ...), c = | <= (SELECT MIN(c) ...): a subquery in a subquery */
            int c = itab ? (int)rr(0, 2) : (chance(50) ? 0 : 2), in = xnew(q, X_SUBQ, 0, 0);
            XN(q, in)->tab = itab;
            XN(q, in)->col = c;
            XN(q, in)->fn = 2;
            XN(q, in)->i = chance(50) ? F_MAX : F_MIN;
            XN(q, in)->ty = CT_INT;
            int k = xbool(q, X_CMP, xcol(q, itab, c), in);
            XN(q, k)->fn = chance(50) ? OP_EQ : XN(q, in)->i == F_MAX ? OP_GE : OP_LE;
            XN(q, sq)->x3 = k;
        } else {
            XN(q, sq)->x3 = gen_subq_where(q, itab, -1);
        }
        if (g_corr_ok && chance(70)) corr_add(q, sq, otab); /* P2 S4b */
        return chance(30) ? xbool(q, X_NOT, sq, 0) : sq;
    }
    XN(q, sq)->fn = 2; /* a value: MAX, MIN, COUNT(*) */
    XN(q, sq)->i = (int[]){F_MAX, F_MIN, F_COUNT_STAR}[rnd() % 3];
    XN(q, sq)->ty = CT_INT;
    if (chance(60)) XN(q, sq)->x3 = gen_subq_where(q, itab, -1);
    if (g_corr_ok && chance(70)) corr_add(q, sq, otab); /* P2 S4b */
    int k = xbool(q, X_CMP, xcol(q, otab, oc), sq);
    XN(q, k)->fn = (int)rr(OP_EQ, OP_GE);
    return k;
}

/* P2 S4: aggregates over a derived table or a CTE of t (its columns g, a, d, s; a plain predicate inside), with a
 * plain predicate outside on one of them sometimes: one row, every engine */
static void gen_dselect(stmt *q)
{
    q->tab = 0;
    q->dsel = chance(50) ? 1 : 2;
    q->fns = q->subq = true;
    static const int DC[] = {1, 2, 4, 6};
    for (int i = 0; i < 4; i++)
        if (chance(60) || (i == 3 && !q->ndc)) q->dc[q->ndc++] = DC[i];
    if (chance(70)) { /* inside: any column of t */
        gen_pred(0, &q->dpred);
        q->has_dpred = true;
    }
    q->it[q->nit++] = (item){F_COUNT_STAR, 0, 0, 0};
    for (int i = 0; i < q->ndc && q->nit < 4; i++) {
        int c = q->dc[i], fn = cols(0)[c].t == CT_TXT ? (int)rr(F_MIN, F_MAX) : (int)rr(F_COUNT, F_MAX);
        q->it[q->nit++] = (item){fn, 0, c, 0};
    }
    if (chance(40)) gen_pred_on(0, q->dc[rnd() % (uint64_t)q->ndc], &q->pr[q->npr++]);
}

/* a condition of S1's: IN, LIKE, or a TEXT tree (never a bare literal) against a literal, or IS [NOT] NULL */
static int gen_fcmp(stmt *q)
{
    if (chance(g_corr_ok ? 40 : 25)) return gen_subq_cond(q); /* P2 S4; in a WHERE, P2 S4b's correlated forms too */
    int r = (int)rr(0, 99);
    if (r < 40) return gen_in(q);
    if (r < 75) return gen_like(q);
    int l = gen_xtxt(q, 1);
    if (XN(q, l)->op == X_TXT) l = xcol(q, q->join ? 0 : q->tab, q->join || !q->tab ? 6 : 3);
    int k = xbool(q, X_CMP, l, 0);
    if (chance(15)) {
        XN(q, k)->fn = chance(50) ? OP_ISNULL : OP_NOTNULL;
        return k;
    }
    val v;
    int tab = q->join ? 0 : q->tab;
    pred_val(tab, tab ? 3 : 6, &v);
    XN(q, k)->r = xtxt(q, v.s);
    XN(q, k)->fn = (int)rr(OP_EQ, OP_GE);
    q->fns = true;
    return k;
}

/* MIN, MAX or COUNT of a TEXT tree (an item of its own: never in HAVING's arithmetic) */
static int gen_ftagg(stmt *q)
{
    int x = gen_xtxt(q, 1);
    int k = xnew(q, X_AGG, x, 0);
    xnode *n = XN(q, k);
    n->fn = (int[]){F_COUNT, F_MIN, F_MAX}[rnd() % 3];
    n->ty = n->fn == F_COUNT ? CT_INT : CT_TXT;
    q->fns = true;
    return k;
}

/* a comparison of two numbers (DML: INT64 or FLOAT64, what SQLite computes alike), IS [NOT] NULL, or t's BOOL k */
static int gen_xcmp(stmt *q, bool dml)
{
    int r = (int)rr(0, 99);
    if (g_fns && !dml && q->kind == Q_SELECT && FNROOM(q) && chance(20)) return gen_fcmp(q); /* P2 S1 */
    if ((q->tab == 0 || q->join) && r < 10) return xcol(q, 0, 7); /* k as a condition (SQL Server: k = 1) */
    if (r >= 70 && q->nxp < (int)(sizeof q->xp / sizeof q->xp[0])) { /* a plain predicate: TEXT, TIMESTAMP, BOOL, DECIMAL
                                                                        * against literals of the column's type */
        gen_pred(q->join && chance(40) ? 1 : q->tab, &q->xp[q->nxp]);
        int k = xbool(q, X_PRED, 0, 0);
        XN(q, k)->col = q->nxp++;
        return k;
    }
    int t1 = dml ? (chance(60) ? CT_INT : CT_FLT) : (int)rr(0, 2);
    int l = t1 == CT_INT ? gen_xint(q, 1, false) : t1 == CT_DEC ? gen_xdec(q, 1, false) : gen_xflt(q, 1);
    int k = xbool(q, X_CMP, l, 0);
    if (r < 22) {
        XN(q, k)->fn = chance(50) ? OP_ISNULL : OP_NOTNULL;
        return k;
    }
    int t2 = dml ? t1 : (int)rr(0, 2);
    int rt = t2 == CT_INT ? gen_xint(q, 1, false) : t2 == CT_DEC ? gen_xdec(q, 1, false) : gen_xflt(q, 1);
    XN(q, k)->r = rt;
    XN(q, k)->fn = r < 34 ? OP_BETWEEN : (int)rr(OP_EQ, OP_GE);
    if (XN(q, k)->fn == OP_BETWEEN)
        XN(q, k)->x3 = t2 == CT_INT ? gen_xint(q, 1, false) : t2 == CT_DEC ? gen_xdec(q, 1, false) : gen_xflt(q, 1);
    return k;
}

/* a condition: comparisons under AND, OR and NOT, depth at most 2: at most four comparisons of 13 nodes each (three
 * operand trees of up to 4, a constant divisor replaced) and three joins, 55 nodes (its caller checks XCOND_ROOM) */
static int gen_xcond(stmt *q, int depth, bool dml)
{
    int r = (int)rr(0, 99);
    if (depth <= 0 || r < 35) return gen_xcmp(q, dml);
    if (r < 50) return xbool(q, X_NOT, gen_xcond(q, depth - 1, dml), 0);
    int l = gen_xcond(q, depth - 1, dml);
    return xbool(q, r < 75 ? X_AND : X_OR, l, gen_xcond(q, depth - 1, dml));
}

/* HAVING's comparison (1e): a tree of aggregates that never fails against literals, IS [NOT] NULL of one, or the group
 * column's own. A FLOAT64's average is no dyadic number: it meets INT64 literals and quarters only, which every engine
 * compares as imagedb does (a decimal like 0.1 would be rounded to a double first in PostgreSQL and MySQL) */
static int gen_hcmp(stmt *q)
{
    int r = (int)rr(0, 99);
    if (q->gcol >= 0 && r < 15) {
        int k = xbool(q, X_CMP, xcol(q, 0, q->gcol), xlit_int(q, rr(-2, 6)));
        XN(q, k)->fn = (int)rr(OP_EQ, OP_GE);
        return k;
    }
    int l = gen_xaggtree(q, false);
    int k = xbool(q, X_CMP, l, 0);
    if (r < 27) {
        XN(q, k)->fn = chance(50) ? OP_ISNULL : OP_NOTNULL;
        return k;
    }
    static const int64_t Q[] = {25, 50, 75, 125, 250, -25, -50, -75, -125, -250};
    bool flt = XN(q, l)->ty == CT_FLT;
    int n = r < 37 ? 2 : 1, lit[2];
    for (int i = 0; i < n; i++) {
        int64_t v = chance(70) ? rr(-30, 60) : rr(-3000, 3000);
        lit[i] = flt ? (chance(50) ? xlit_int(q, v) : xlit_dec(q, Q[rnd() % 10] + v * 100, 2))
                     : (chance(50) ? xlit_int(q, v) : xlit_dec(q, v * 10 + rr(-9, 9), 1));
    }
    XN(q, k)->r = lit[0];
    if (n == 2) {
        XN(q, k)->fn = OP_BETWEEN;
        XN(q, k)->x3 = lit[1];
    } else {
        XN(q, k)->fn = (int)rr(OP_EQ, OP_GE);
    }
    return k;
}

/* HAVING (1e): comparisons under AND, OR and NOT, depth at most 2 (four comparisons of at most 12 nodes, three joins:
 * its caller checks XCOND_ROOM) */
static int gen_hcond(stmt *q, int depth)
{
    int r = (int)rr(0, 99);
    if (depth <= 0 || r < 40) return gen_hcmp(q);
    if (r < 52) return xbool(q, X_NOT, gen_hcond(q, depth - 1), 0);
    int l = gen_hcond(q, depth - 1);
    return xbool(q, r < 76 ? X_AND : X_OR, l, gen_hcond(q, depth - 1));
}

/* a SELECT with expressions: rows (trees that may fail, no LIMIT), aggregates of trees, trees of aggregates, grouped by
 * g sometimes; with trees in WHERE too */
static void gen_xselect(stmt *q)
{
    q->tab = chance(85) ? 0 : 1;
    q->join = q->tab == 0 && chance(25) ? (int)rr(1, 2) : 0;
    int form = (int)rr(0, 99);
    if (form < 45) { /* rows */
        q->it[q->nit++] = (item){F_COL, q->tab, 0, 0};
        int n = (int)rr(1, 3);
        for (int i = 0; i < n; i++) {
            int k;
            if (g_fns && FNROOM(q) && chance(20)) { /* P2 S1: a TEXT tree */
                k = gen_xtxt(q, 2);
            } else if (XCOND_ROOM(q) && chance(20)) { /* a condition as an item: a BOOL (SQL Server has none: its BIT is no value of
                                                * a comparison) */
                k = gen_xcond(q, 1, false);
                q->skip |= 1u << D_MS;
            } else {
                k = gen_xany(q, 2, !g_in_txn);
            }
            q->it[q->nit++] = (item){F_COL, 0, 0, k};
        }
    } else {
        if (q->tab == 0 && chance(50)) {
            q->gcol = 1;
            q->it[q->nit++] = (item){F_COL, 0, 1, 0};
            if (chance(30)) q->it[q->nit++] = (item){F_COL, 0, 0, xnew(q, X_MUL, xcol(q, 0, 1), xlit_int(q, rr(2, 9)))};
        }
        int n = (int)rr(1, 3);
        for (int i = 0; i < n; i++) /* P2 S1: an aggregate of a TEXT tree sometimes (an item alone: never in arithmetic) */
            q->it[q->nit++] = (item){F_COL, 0, 0, g_fns && FNROOM(q) && chance(12) ? gen_ftagg(q) : gen_xaggtree(q, !g_in_txn)};
        if (XCOND_ROOM(q) && chance(q->gcol >= 0 ? 40 : 15)) q->hv = gen_hcond(q, chance(30) ? 2 : 1); /* 1e */
    }
    if (q->gcol >= 0) { /* grouped: every group's row is built before any cut (1d), so a window is safe here */
        gen_order(q, true, false);
        if (q->nord && chance(30)) q->limit = (int)rr(1, 4);
    } else if (form < 45) {
        gen_order(q, false, false); /* rows whose items may fail: ordered, never cut */
    }
    int np = (int)rr(0, 2);
    for (int i = 0; i < np && XROOM(q); i++) gen_xpred(q, &q->pr[q->npr++], false);
    for (int i = 0; i < q->nit; i++) xmark(q, q->it[i].ex);
    xmark(q, q->hv);
    if (q->hv && q->gcol < 0) q->skip |= 1u << D_SQLITE; /* SQLite before 3.39 (3.37.2 here) refuses HAVING without GROUP BY */
    for (int i = 0; i < q->nord; i++) /* P2 S1: SQL Server orders a computed TEXT with a trailing space padded away */
        if (q->ord[i].pos && q->it[q->ord[i].pos - 1].ex && txt_computed(q, q->it[q->ord[i].pos - 1].ex)) q->skip |= 1u << D_MS;
    for (int i = 0; i < q->npr; i++) xmark_pred(q, &q->pr[i]);
}

/* an UPDATE's SET by a tree of its own column alone (MySQL and MariaDB compute SET left to right, reading what an
 * earlier SET wrote): every engine, SQLite included, computes it alike, and it never fails */
static void gen_xset(stmt *q, int i)
{
    int r = (int)rr(0, 99);
    if (r < 45) { /* a: + - small, negation, / and % by a nonzero literal, * by -1 */
        q->scol[i] = 2;
        int c = xcol(q, 0, 2), k;
        int o = (int)rr(0, 5);
        if (o == 0) k = xnew(q, X_ADD, c, xlit_int(q, rr(-1000, 1000)));
        else if (o == 1) k = xnew(q, X_SUB, c, xlit_int(q, rr(-1000, 1000)));
        else if (o == 2) k = xnew(q, X_NEG, c, 0);
        else if (o == 3) k = xnew(q, X_DIV, c, xlit_int(q, nonzero(-9, 9)));
        else if (o == 4) k = xnew(q, X_MOD, c, xlit_int(q, nonzero(-9, 9)));
        else k = xnew(q, X_MUL, c, xlit_int(q, -1));
        q->sx[i] = k;
    } else if (r < 75) { /* d: + - a literal at its scale, or negated (SQLite: the scaled integer) */
        q->scol[i] = 4;
        int c = xcol(q, 0, 4);
        int o = (int)rr(0, 2);
        int lit = xlit_dec(q, rr(-99999, 99999), 2);
        XN(q, lit)->scaled = true;
        q->sx[i] = o == 2 ? xnew(q, X_NEG, c, 0) : xnew(q, o ? X_SUB : X_ADD, c, lit);
    } else { /* f: + - a quarter, negated, halved */
        q->scol[i] = 5;
        int c = xcol(q, 0, 5);
        int o = (int)rr(0, 3);
        static const int64_t QQ[] = {25, 50, 75, 125};
        q->sx[i] = o == 0   ? xnew(q, X_ADD, c, xlit_dec(q, QQ[rnd() % 4], 2))
                   : o == 1 ? xnew(q, X_SUB, c, xlit_dec(q, QQ[rnd() % 4], 2))
                   : o == 2 ? xnew(q, X_NEG, c, 0)
                            : xnew(q, X_DIV, c, xlit_int(q, 2));
    }
}

static void gen_row(int tab, val *row)
{
    for (int c = 0; c < ncols(tab); c++) gen_val(tab, c, &row[c], 15);
    row[0].null = false;
    row[0].i = g_next_id++;
    if (tab == 1 && !row[1].null && g_ntids && chance(70)) row[1].i = g_tids[rnd() % (uint64_t)g_ntids];
    if (tab == 0 && g_ntids < (int)(sizeof g_tids / sizeof g_tids[0])) g_tids[g_ntids++] = row[0].i;
    for (int c = tab ? 0 : 1; c < ncols(tab); c++) sample(tab, c, &row[c]); /* t.id: g_tids */
}

/* a SELECT: whole rows, some columns, aggregates, grouped aggregates, or a two-table join */
/* ORDER BY (1d) and sometimes OFFSET (window: a LIMIT or OFFSET may cut it; a statement whose items may fail gets
 * none, PostgreSQL computing them before it sorts). Keys: a position, a column of the statement's tables, a tree
 * that never fails; grouped: a position, g, or an aggregate tree. Under DISTINCT with a window the keys are every
 * item by position, a total order over distinct rows, put only to PostgreSQL and SQLite (MySQL, MariaDB and SQL
 * Server have no NULLS FIRST/LAST, and under DISTINCT no key outside the select list) */
static void gen_order(stmt *q, bool window, bool distinct_ok)
{
    if (distinct_ok && q->nit && q->nit <= 3 && chance(15)) q->distinct = true;
    if (q->distinct) {
        if (!q->limit && !(window && chance(30))) return; /* DISTINCT alone: compared as a multiset, every engine */
        q->nord = q->nit;
        for (int i = 0; i < q->nord; i++) q->ord[i] = (struct okey){0, 0, 0, i + 1, chance(50), chance(50)};
        if (window && chance(40)) q->offset = (int)rr(1, 6);
        q->skip |= 1u << D_MY | 1u << D_MA | 1u << D_MS;
        return;
    }
    if (!chance(35)) return;
    q->nord = (int)rr(1, 2);
    for (int i = 0; i < q->nord; i++) {
        struct okey *k = &q->ord[i];
        memset(k, 0, sizeof *k);
        k->desc = chance(50);
        k->nf = chance(50);
        int r = (int)rr(0, 99), nout = q->star ? ncols(q->tab) : q->nit;
        if (q->gcol >= 0) {
            if (r < 45 && nout) k->pos = (int)rr(1, nout);
            else if (r < 75 || !XROOM(q)) k->col = q->gcol;
            else xmark(q, k->ex = gen_xaggtree(q, false));
            continue;
        }
        if (r < 30 && nout) k->pos = (int)rr(1, nout);
        else if (r < 70 || !XROOM(q)) {
            k->tab = q->join ? (int)rr(0, 1) : q->tab;
            k->col = (int)(rnd() % (uint64_t)ncols(k->tab));
        } else {
            k->ex = gen_xany(q, 1, false);
            if (!has_col(q, k->ex)) { /* a constant key orders nothing, and SQLite reads an integer one, (-6) too, as a
                                       * position: a column instead */
                k->ex = 0;
                k->tab = q->join ? (int)rr(0, 1) : q->tab;
                k->col = (int)(rnd() % (uint64_t)ncols(k->tab));
            } else {
                xmark(q, k->ex);
            }
        }
    }
    if (window && chance(30)) q->offset = (int)rr(1, 12);
}

/* P2 S1: a SELECT of its forms: rows of t, u or their join (TEXT trees, INT64, FLOAT64 and DECIMAL function forms) or
 * aggregates of them (grouped by g sometimes), under its conditions (IN, LIKE, TEXT comparisons), ordered sometimes;
 * rows whose items may fail are never cut (gen_xselect's rule) */
static void gen_fselect(stmt *q)
{
    q->tab = chance(75) ? 0 : 1;
    q->join = q->tab == 0 && chance(25) ? (int)rr(1, 2) : 0;
    bool agg = chance(35);
    if (agg && q->tab == 0 && chance(40)) {
        q->gcol = 1;
        q->it[q->nit++] = (item){F_COL, 0, 1, 0};
    } else if (!agg) {
        q->it[q->nit++] = (item){F_COL, q->tab, 0, 0};
    }
    int n = (int)rr(1, 3);
    for (int i = 0; i < n && FNROOM(q); i++) {
        int r = (int)rr(0, 99), k;
        if (agg && r < 40) {
            k = gen_ftagg(q);
        } else {
            bool fl = !agg && !g_in_txn; /* an aggregate's operand never fails: a SUM of x would pass INT64 (gen_xagg's rule) */
            k = r < 45 ? gen_xtxt(q, 2) : r < 75 ? gen_fint(q, 2, fl) : r < 88 ? gen_fflt(q, 2) : gen_fdec(q, 2, fl);
            if (agg) { /* COUNT, MIN, MAX of any; SUM of a number */
                const xnode *a = XN(q, k);
                int fn = a->ty == CT_TXT ? (int[]){F_COUNT, F_MIN, F_MAX}[rnd() % 3] : (int)rr(F_COUNT, F_MAX);
                int g = xnew(q, X_AGG, k, 0);
                XN(q, g)->fn = fn;
                XN(q, g)->ty = fn == F_COUNT ? CT_INT : XN(q, k)->ty;
                XN(q, g)->sc = fn == F_COUNT ? 0 : XN(q, k)->sc;
                k = g;
            }
        }
        q->it[q->nit++] = (item){F_COL, 0, 0, k};
    }
    int np = (int)rr(0, 2);
    for (int i = 0; i < np && FNROOM(q); i++) {
        memset(&q->pr[q->npr], 0, sizeof q->pr[0]);
        g_corr_ok = true; /* P2 S4b: WHERE */
        q->pr[q->npr++].bt = gen_fcmp(q);
        g_corr_ok = false;
    }
    if (agg && q->gcol < 0) {
        /* one row: no order */
    } else if (agg) {
        gen_order(q, true, false);
    } else {
        gen_order(q, false, false);
    }
    for (int i = 0; i < q->nit; i++) xmark(q, q->it[i].ex);
    for (int i = 0; i < q->npr; i++) xmark(q, q->pr[i].bt);
    for (int i = 0; i < q->nord; i++) /* SQL Server orders a computed TEXT with a trailing space padded away */
        if (q->ord[i].pos && q->it[q->ord[i].pos - 1].ex && txt_computed(q, q->it[q->ord[i].pos - 1].ex)) q->skip |= 1u << D_MS;
}

/* P2 S2: GROUP BY one to three keys (columns, LOWER(s), a % 3, CAST(g AS TEXT), a CASE), each repeated as an item, and
 * aggregates with DISTINCT and FILTER (WHERE c) over bare columns (a bare DECIMAL's SUM is SQLite's scaled integer:
 * lite_ok takes it); no order: compared as a multiset */
static void gen_gselect(stmt *q)
{
    q->tab = 0;
    q->join = chance(20) ? (int)rr(1, 2) : 0;
    q->grp = true;
    q->fns = true;
    int nk = (int)rr(1, 3);
    for (int i = 0; i < nk; i++) {
        int r = (int)rr(0, 99), k;
        if (r < 50) {
            int tab = q->join && chance(30) ? 1 : 0;
            int col = tab ? (int)rr(1, 3) : (int[]){1, 2, 4, 5, 6, 7, 8}[rnd() % 7];
            k = xcol(q, tab, col);
            q->it[q->nit++] = (item){F_COL, tab, col, 0};
        } else {
            if (r < 65) {
                k = xfn(q, XF_LOWER, xcol(q, 0, 6), 0, CT_TXT, 0);
            } else if (r < 80) {
                k = xnew(q, X_MOD, xcol(q, 0, 2), xlit_int(q, 3));
            } else if (r < 90) {
                k = xcast(q, xcol(q, 0, 1), CT_TXT, 0);
            } else {
                int col = (int[]){1, 2}[rnd() % 2]; /* g or a: a key reads a column (a constant one is refused) */
                int lit = xlit_int(q, rr(-3, 6));
                int c = xbool(q, X_CMP, xcol(q, 0, col), lit);
                XN(q, c)->fn = (int)rr(OP_EQ, OP_GE);
                k = xnew(q, X_CASE, c, xtxt(q, "hi"));
                XN(q, k)->x3 = xtxt(q, "lo");
                XN(q, k)->ty = CT_TXT;
            }
            q->it[q->nit++] = (item){F_COL, 0, 0, k};
        }
        q->gk[q->ngk++] = k;
    }
    int na = (int)rr(1, 3);
    for (int i = 0; i < na; i++) {
        int fn = (int)rr(F_COUNT_STAR, F_MAX), a = 0;
        if (fn != F_COUNT_STAR) {
            int tab = q->join && chance(30) ? 1 : 0, col;
            if (fn == F_SUM) col = tab ? 2 : (int[]){0, 1, 2, 4, 5}[rnd() % 5]; /* id, g, a, d, f; u's v */
            else col = tab ? (int)rr(1, 3) : (int[]){0, 1, 2, 4, 5, 6, 8}[rnd() % 7]; /* not BOOL (SQL Server's BIT) */
            a = xcol(q, tab, col);
        }
        int k = xnew(q, X_AGG, a, 0);
        xnode *n = XN(q, k);
        n->fn = fn;
        n->ty = fn == F_COUNT_STAR || fn == F_COUNT ? CT_INT : XN(q, a)->ty;
        n->sc = n->ty == CT_DEC ? XN(q, a)->sc : 0;
        n->dist = fn != F_COUNT_STAR && chance(40);
        if (chance(40)) XN(q, k)->x3 = gen_fcond(q); /* FILTER (WHERE c) */
        q->it[q->nit++] = (item){F_COL, 0, 0, k};
    }
    for (int i = 0; i < q->nit; i++) xmark(q, q->it[i].ex);
}

/* P2 S5: a set operation of two or three SELECTs of matching columns (one INT64, or INT64 and TEXT; under a tail one
 * id, never NULL, so ORDER BY its position is total everywhere), each over t or u with a predicate sometimes; INTERSECT
 * chains alone (SQLite gives every operator one precedence, left to right, and takes no parentheses: a chain mixing
 * INTERSECT with the others means another thing there), UNION, UNION ALL and EXCEPT mixed */
static void gen_sselect(stmt *q)
{
    q->narm = chance(70) ? 2 : 3;
    q->stail = chance(35);
    q->ncol = q->stail ? 1 : (int)rr(1, 2);
    int ty[2] = {q->stail || chance(80) ? CT_INT : CT_TXT, chance(50) ? CT_TXT : CT_INT};
    bool inter = chance(25);
    for (int a = 0; a < q->narm; a++) {
        struct sarm *m = &q->arm[a];
        m->tab = (int)rr(0, 1);
        for (int c = 0; c < q->ncol; c++)
            m->col[c] = q->stail ? 0 : ty[c] == CT_TXT ? (m->tab ? 3 : 6) : m->tab ? (int)rr(0, 2) : (int)rr(0, 3);
        if (chance(60)) {
            gen_pred(m->tab, &m->pr);
            m->has_pr = true;
        }
        if (a) q->armop[a] = inter ? 2 : (int[]){0, 1, 3}[rnd() % 3];
    }
    if (q->stail) {
        q->sdesc = chance(50);
        if (chance(60)) q->slim = (int)rr(1, 8);
        if (chance(40)) q->soff = (int)rr(1, 4);
    }
}

/* P2 S5: WITH RECURSIVE: a count to rk, or a walk from rstart along u (tid -> id) at most six steps deep; under UNION
 * or UNION ALL (T-SQL takes UNION ALL alone in a recursive WITH); or t's g values (alike rows), each counted up to 6:
 * UNION drops the base's repeats and the rounds' meetings, UNION ALL keeps them */
static void gen_rselect(stmt *q)
{
    q->rec = (int)rr(1, 3); /* 3: a base of many alike rows whose rounds meet (the mutant: UNION's drop untested) */
    q->rall = chance(50);
    if (q->rec == 1) q->rk = (int)rr(1, 60);
    else q->rstart = g_ntids ? g_tids[rnd() % (uint64_t)g_ntids] : rr(-5, 5);
    if (!q->rall) q->skip |= 1u << D_MS;
}

/* P2 S6: a window function over t: SELECT id, f(...) OVER ([PARTITION BY g] ORDER BY k [, id]) FROM t [WHERE p]. The
 * order keys are never NULL (no dialect's NULL placement matters): id % 3 (ties: RANK, DENSE_RANK and the default
 * frame's aggregates, which read every peer alike), then id where a function reads the order among peers (ROW_NUMBER,
 * NTILE, LAG, LEAD, FIRST_VALUE, LAST_VALUE, a ROWS frame: PostgreSQL and SQLite promise no order among ties, imagedb
 * breaks them by its own); the values g and a (INT64, sums far from overflow) or s */
enum { WO_ROW_NUMBER, WO_RANK, WO_DENSE_RANK, WO_NTILE, WO_LAG, WO_LEAD, WO_FIRST, WO_LAST, WO_SUM, WO_COUNT, WO_MIN, WO_MAX };
static void gen_wselect(stmt *q)
{
    q->win = true;
    q->wfn = (int)rr(WO_ROW_NUMBER, WO_MAX);
    q->wpart = chance(60);
    q->wdesc = chance(40);
    q->wcol = chance(70) ? (chance(50) ? 1 : 2) : 6; /* g, a, or s */
    if (q->wfn == WO_SUM) q->wcol = chance(50) ? 1 : 2;
    q->wk = q->wfn == WO_NTILE ? (int)rr(1, 5) : (int)rr(1, 3);
    q->wdef = (q->wfn == WO_LAG || q->wfn == WO_LEAD) && chance(70); /* a default: read at a partition's edges */
    if (q->wdef) q->skip |= 1u << D_MA; /* MariaDB's LAG and LEAD take no default */
    bool agg = q->wfn >= WO_SUM;
    q->wframe = agg && chance(40) ? 1 : 0;
    q->wlo = (int)rr(0, 3);
    q->whi = (int)rr(0, 2);
    q->wtotal = !(q->wfn == WO_RANK || q->wfn == WO_DENSE_RANK || (agg && !q->wframe)) || chance(30);
    if (chance(50)) {
        gen_pred(0, &q->pr[0]);
        q->npr = 1;
    }
    q->tab = 0;
}

static void gen_select(stmt *q)
{
    memset(q, 0, sizeof *q);
    q->kind = Q_SELECT;
    q->gcol = -1;
    if (g_fns && chance(5)) { /* P2 S6: a window function */
        gen_wselect(q);
        return;
    }
    if (g_fns && chance(6)) { /* P2 S5: a set operation */
        gen_sselect(q);
        return;
    }
    if (g_fns && chance(3)) { /* P2 S5: WITH RECURSIVE */
        gen_rselect(q);
        return;
    }
    if (g_fns && chance(8)) { /* P2 S4: a derived table or a CTE */
        gen_dselect(q);
        return;
    }
    if (g_fns && chance(10)) { /* P2 S2 */
        gen_gselect(q);
        return;
    }
    if (g_fns && chance(12)) { /* P2 S1 */
        gen_fselect(q);
        return;
    }
    if (g_expr && chance(30)) {
        gen_xselect(q);
        return;
    }
    q->tab = chance(80) ? 0 : 1;
    int form = (int)(rnd() % 100);
    if (form < 25) { /* whole rows */
        q->star = true;
        gen_preds(q, 3, false);
        if (chance(25)) q->limit = (int)rr(1, 8);
        if (g_expr) gen_order(q, true, false); /* 1d */
    } else if (form < 40) { /* some columns */
        q->nit = (int)rr(1, 4);
        for (int i = 0; i < q->nit; i++) q->it[i] = (item){F_COL, q->tab, (int)(rnd() % (uint64_t)ncols(q->tab)), 0};
        gen_preds(q, 3, false);
        if (chance(25)) q->limit = (int)rr(1, 8);
        if (g_expr) gen_order(q, true, true);
    } else if (form < 50) { /* the (g, a) index's own shape: aggregates of g under a predicate on g, which imagedb
                             * answers from the index alone (index(ordered, only)); or of a, nullable after the first
                             * column, which the ordered path reads row by row */
        q->tab = 0;
        if (chance(50)) {
            q->gcol = 1;
            q->it[q->nit++] = (item){F_COL, 0, 1, 0};
        }
        q->it[q->nit++] = (item){F_COUNT_STAR, 0, 0, 0};
        int on = chance(60) ? 1 : 2;
        q->it[q->nit++] = (item){(int)rr(F_COUNT, F_MAX), 0, on, 0};
        gen_pred_on(0, 1, &q->pr[q->npr++]);
        if (on == 2 && chance(70)) gen_pred_on(0, 2, &q->pr[q->npr++]);
    } else if (form < 75) { /* aggregates, grouped by g sometimes (t only) */
        q->tab = 0;
        if (chance(50)) {
            q->gcol = 1;
            q->it[q->nit++] = (item){F_COL, 0, 1, 0};
        }
        int k = (int)rr(1, 4);
        for (int i = 0; i < k; i++) {
            int fn = (int)rr(F_COUNT_STAR, F_MAX), c;
            if (fn == F_SUM) c = (int[]){2, 4, 5}[rnd() % 3]; /* a, d, f: sums that every engine keeps exact */
            else if (fn == F_MIN || fn == F_MAX) c = (int[]){0, 1, 2, 3, 4, 5, 6, 8}[rnd() % 8]; /* not BOOL */
            else c = (int)(rnd() % NT);
            q->it[q->nit++] = (item){fn, 0, c, 0};
        }
        gen_preds(q, 3, false);
        if (g_expr && XCOND_ROOM(q) && chance(q->gcol >= 0 ? 35 : 10)) { /* 1e */
            q->hv = gen_hcond(q, 1);
            xmark(q, q->hv);
            if (q->gcol < 0) q->skip |= 1u << D_SQLITE; /* before 3.39 it refuses HAVING without GROUP BY */
        }
    } else { /* a join, rows or aggregates */
        q->tab = 0;
        q->join = chance(50) ? 1 : 2;
        if (g_fns && chance(45)) { /* P2 S3: RIGHT, FULL, CROSS; ON's other condition, a second key pair, USING */
            q->join = (int)rr(3, 5);
            q->jn3 = true;
        }
        if (g_fns && q->join != 5 && chance(30)) q->jx = gen_jcond(q), q->jn3 = true;
        if (g_fns && q->join != 5 && chance(20)) q->jkey2 = q->jn3 = true;
        if (g_fns && q->join != 5 && !q->jx && !q->jkey2 && chance(15)) q->jusing = q->jn3 = true;
        if (chance(70)) {
            q->nit = (int)rr(1, 4);
            q->it[0] = (item){F_COL, 0, 0, 0};
            for (int i = 1; i < q->nit; i++) {
                int tab = (int)rr(0, 1);
                q->it[i] = (item){F_COL, tab, (int)(rnd() % (uint64_t)ncols(tab)), 0};
            }
        } else {
            q->it[q->nit++] = (item){F_COUNT_STAR, 0, 0, 0};
            q->it[q->nit++] = (item){F_COUNT, 1, (int)rr(0, NU - 1), 0};
            q->it[q->nit++] = (item){F_SUM, 1, 2, 0};
        }
        gen_preds(q, 3, true);
        if (q->join == 4) /* P2 S3: FULL: no FULL JOIN in MySQL and MariaDB; SQLite's UNION ALL only for rows */
            q->skip |= 1u << D_MY | 1u << D_MA | (q->it[0].fn == F_COL ? 0u : 1u << D_SQLITE);
        if (q->jx) xmark(q, q->jx);
        if (g_expr && q->it[0].fn == F_COL && q->join <= 2) { /* a join's rows ordered, cut sometimes (1d); RIGHT, FULL and
                                                          * CROSS rows compared as a multiset (P2 S3) */
            gen_order(q, true, false);
            if (q->nord && chance(30)) q->limit = (int)rr(1, 8);
        }
    }
}

static void gen_dml(stmt *q, bool may_fail)
{
    memset(q, 0, sizeof *q);
    q->gcol = -1;
    q->tab = chance(75) ? 0 : 1;
    int r = (int)(rnd() % 100);
    if (r < 40) {
        q->kind = Q_INSERT;
        q->nrow = (int)rr(1, 4);
        for (int i = 0; i < q->nrow; i++) gen_row(q->tab, q->row[i]);
        if (may_fail && q->tab == 0 && g_ntids > 1 && chance(15)) /* a key that may exist: refused everywhere */
            q->row[q->nrow - 1][0].i = g_tids[rnd() % (uint64_t)(g_ntids - 1)];
    } else if (r < 75) {
        q->kind = Q_UPDATE;
        q->nset = (int)rr(1, 2);
        for (int i = 0; i < q->nset; i++) {
            q->scol[i] = (int)rr(1, ncols(q->tab) - 1);
            for (int j = 0; j < i; j++)
                if (q->scol[j] == q->scol[i]) q->scol[i] = 0;
            if (!q->scol[i]) {
                q->nset = i;
                break;
            }
            gen_val(q->tab, q->scol[i], &q->sval[i], 15);
            sample(q->tab, q->scol[i], &q->sval[i]);
        }
        if (!q->nset) {
            q->scol[0] = 1;
            q->nset = 1;
            gen_val(q->tab, 1, &q->sval[0], 15);
        }
        if (g_expr && q->tab == 0 && chance(40)) { /* SETs by trees of their own columns: a, d, f */
            q->nset = (int)rr(1, 2);
            for (int i = 0; i < q->nset; i++) {
                gen_xset(q, i);
                if (i && q->scol[i] == q->scol[0]) q->nset = 1;
            }
        }
        gen_preds(q, 2, false);
    } else {
        q->kind = Q_DELETE;
        gen_preds(q, 2, false);
        if (!q->npr) q->npr = 1, gen_pred(q->tab, &q->pr[0]);
    }
}

/* ---- printing, per dialect ------------------------------------------------------------------------------------ */

/* days since 1970-01-01 to a civil date (Howard Hinnant's) */
static void civil(int64_t z, int64_t *y, unsigned *m, unsigned *d)
{
    z += 719468;
    int64_t era = (z >= 0 ? z : z - 146096) / 146097;
    unsigned doe = (unsigned)(z - era * 146097);
    unsigned yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    int64_t yy = (int64_t)yoe + era * 400;
    unsigned doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    unsigned mp = (5 * doy + 2) / 153;
    *d = doy - (153 * mp + 2) / 5 + 1;
    *m = mp < 10 ? mp + 3 : mp - 9;
    *y = yy + (*m <= 2);
}

static int64_t days_from_civil(int64_t y, unsigned m, unsigned d)
{
    y -= m <= 2;
    int64_t era = (y >= 0 ? y : y - 399) / 400;
    unsigned yoe = (unsigned)(y - era * 400);
    unsigned doy = (153 * (m > 2 ? m - 3 : m + 9) + 2) / 5 + d - 1;
    unsigned doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    return era * 146097 + (int64_t)doe - 719468;
}

static void put_ts(sb *b, int64_t us)
{
    int64_t days = us / 86400000000ll, rem = us % 86400000000ll, y;
    unsigned mo, d;
    civil(days, &y, &mo, &d);
    int64_t s = rem / 1000000, f = rem % 1000000;
    sb_printf(b, "%04" PRId64 "-%02u-%02u %02" PRId64 ":%02" PRId64 ":%02" PRId64 ".%06" PRId64, y, mo, d, s / 3600,
              s / 60 % 60, s % 60, f);
}

static void put_dec(sb *b, __int128 x)
{
    bool neg = x < 0;
    unsigned __int128 a = neg ? -(unsigned __int128)x : (unsigned __int128)x;
    char dig[64];
    int n = 0;
    unsigned __int128 ip = a / 100;
    do {
        dig[n++] = (char)('0' + (int)(ip % 10));
        ip /= 10;
    } while (ip);
    if (neg) sb_str(b, "-");
    for (int i = n - 1; i >= 0; i--) sb_put(b, &dig[i], 1);
    sb_printf(b, ".%02u", (unsigned)(a % 100));
}

static void put_lit(sb *b, int d, int t, const val *v)
{
    if (v->null) {
        sb_str(b, "NULL");
        return;
    }
    switch (t) {
    case CT_INT: sb_printf(b, "%" PRId64, v->i); break;
    case CT_DEC:
        if (d == D_SQLITE) sb_printf(b, "%" PRId64, v->i); /* SQLite keeps DECIMAL as its scaled integer here */
        else put_dec(b, v->i);
        break;
    case CT_FLT: sb_printf(b, "%.2f", v->f); break; /* a multiple of 1/4: exact in two decimals */
    case CT_TXT:
        sb_str(b, "'");
        for (const char *p = v->s; *p; p++) sb_put(b, *p == '\'' ? "''" : p, *p == '\'' ? 2 : 1);
        sb_str(b, "'");
        break;
    case CT_BOOL:
        if (d == D_IMDB || d == D_PG) sb_str(b, v->i ? "true" : "false");
        else if (d == D_MY || d == D_MA) sb_str(b, v->i ? "TRUE" : "FALSE");
        else sb_str(b, v->i ? "1" : "0");
        break;
    case CT_TS:
        if (d == D_SQLITE) sb_printf(b, "%" PRId64, v->i);
        else {
            sb_str(b, "'");
            put_ts(b, v->i);
            sb_str(b, "'");
        }
        break;
    }
}

static bool g_qual; /* SQL Server's ORDER BY: every column qualified (a bare name is the select list's first, and
                     * ambiguous when the list names it twice: SELECT d, d ... ORDER BY d) */
static void put_col(sb *b, const stmt *q, int tab, int col)
{
    if (q->join || g_qual) sb_printf(b, "%s.%s", tname(tab), cols(tab)[col].name);
    else sb_str(b, cols(tab)[col].name);
}

/* a scaled value's text at scale s */
static void put_scaled(sb *b, __int128 x, int s)
{
    bool neg = x < 0;
    unsigned __int128 a = neg ? -(unsigned __int128)x : (unsigned __int128)x;
    char dig[80];
    int n = 0;
    do {
        dig[n++] = (char)('0' + (int)(a % 10));
        a /= 10;
    } while (a || n <= s);
    if (neg) sb_str(b, "-");
    for (int i = n - 1; i >= 0; i--) {
        sb_put(b, &dig[i], 1);
        if (i == s && s > 0) sb_str(b, ".");
    }
}

/* ---- P2 S1's forms in each dialect ----------------------------------------------------------------------------------- */

static void put_x(sb *b, int d, const stmt *q, int k, int pty);

static void put_txt(sb *b, const char *s)
{
    sb_str(b, "'");
    for (const char *p = s; *p; p++) sb_put(b, *p == '\'' ? "''" : p, *p == '\'' ? 2 : 1);
    sb_str(b, "'");
}

/* name(x[, y[, z]]) */
static void put_call(sb *b, int d, const stmt *q, const char *name, int x, int y, int z)
{
    sb_printf(b, "%s(", name);
    put_x(b, d, q, x, -1);
    if (y) sb_str(b, ", "), put_x(b, d, q, y, -1);
    if (z) sb_str(b, ", "), put_x(b, d, q, z, -1);
    sb_str(b, ")");
}

/* x, cast to NUMERIC in PostgreSQL where it is an INT64 (its CEIL, FLOOR, ROUND and SIGN of a bigint are a double's) */
static void put_num_arg(sb *b, int d, const stmt *q, int x)
{
    if (d == D_PG && XN(q, x)->ty == CT_INT) {
        sb_str(b, "CAST(");
        put_x(b, d, q, x, -1);
        sb_str(b, " AS NUMERIC)");
        return;
    }
    put_x(b, d, q, x, -1);
}

static void put_fn(sb *b, int d, const stmt *q, const xnode *n)
{
    const xnode *a = n->l ? XN(q, n->l) : NULL;
    switch (n->fn) {
    case XF_ABS: put_call(b, d, q, "ABS", n->l, 0, 0); return;
    /* SIGN, CEIL, FLOOR and ROUND where imagedb's is an INT64: PostgreSQL's of the NUMERIC put_num_arg makes (or of a
     * double) is a NUMERIC (a double), cast back, so arithmetic over it is an INT64's (FLOOR(19) / 372 truncates to 0:
     * seed 69 of the 2026-11-05 five-engine run). SQL Server's SIGN of a DECIMAL is a DECIMAL (1.00): cast too */
    case XF_SIGN:
        sb_str(b, d == D_MS || d == D_PG ? "CAST(SIGN(" : "SIGN(");
        put_num_arg(b, d, q, n->l);
        sb_str(b, d == D_MS || d == D_PG ? ") AS BIGINT)" : ")");
        return;
    case XF_CEIL:
    case XF_FLOOR:
        if (d == D_PG && n->ty == CT_INT) sb_str(b, "CAST(");
        sb_str(b, n->fn == XF_FLOOR ? "FLOOR(" : d == D_MS ? "CEILING(" : "CEIL(");
        put_num_arg(b, d, q, n->l);
        sb_str(b, d == D_PG && n->ty == CT_INT ? ") AS BIGINT)" : ")");
        return;
    case XF_ROUND: /* SQL Server's needs its places */
        if (d == D_SQLITE && a->ty == CT_INT) { /* SQLite's round is a REAL, inexact past 2^53: an INT64's is itself */
            sb_str(b, "(");
            put_x(b, d, q, n->l, -1);
            sb_str(b, ")");
            return;
        }
        if (d == D_PG && n->ty == CT_INT) sb_str(b, "CAST(");
        sb_str(b, "ROUND(");
        if (d == D_MS && a->ty == CT_DEC) { /* its ROUND keeps the argument's precision, so ROUND(-99.7, 0), -100.0, is
                                             * past numeric(3,1): an overflow (seed 25 of the 2026-11-05 five-engine run).
                                             * A DECIMAL(1,0) zero added gives it one more integer digit, the most a
                                             * rounding adds */
            sb_str(b, "(");
            put_num_arg(b, d, q, n->l);
            sb_str(b, " + CAST(0 AS DECIMAL(1,0)))");
        } else {
            put_num_arg(b, d, q, n->l);
        }
        if (n->a1 >= 0 && d != D_SQLITE) sb_printf(b, ", %" PRId64, n->a1);
        else if (d == D_MS || (d == D_PG && a->ty == CT_DEC) || ((d == D_MY || d == D_MA) && a->ty == CT_DEC)) sb_str(b, ", 0");
        sb_str(b, d == D_PG && n->ty == CT_INT ? ") AS BIGINT)" : ")");
        return;
    case XF_MOD:
        if (d == D_SQLITE || d == D_MS) {
            sb_str(b, "(");
            put_x(b, d, q, n->l, n->ty);
            sb_str(b, " % ");
            put_x(b, d, q, n->r, n->ty);
            sb_str(b, ")");
            return;
        }
        put_call(b, d, q, "MOD", n->l, n->r, 0);
        return;
    case XF_LENGTH:
        if (d == D_MS) { /* LEN drops trailing spaces */
            sb_str(b, "(LEN(");
            put_x(b, d, q, n->l, -1);
            sb_str(b, " + 'x') - 1)");
            return;
        }
        put_call(b, d, q, d == D_IMDB || d == D_SQLITE ? "LENGTH" : "CHAR_LENGTH", n->l, 0, 0);
        return;
    case XF_SUBSTR:
        sb_str(b, d == D_MY || d == D_MA || d == D_MS ? "SUBSTRING(" : "SUBSTR(");
        put_x(b, d, q, n->l, -1);
        sb_printf(b, ", %" PRId64, n->a1);
        if (n->a2 >= 0) sb_printf(b, ", %" PRId64, n->a2);
        else if (d == D_MS) sb_str(b, ", 100000"); /* its SUBSTRING has no two-argument form */
        sb_str(b, ")");
        return;
    case XF_TRIM: put_call(b, d, q, "TRIM", n->l, 0, 0); return;
    case XF_LTRIM: put_call(b, d, q, "LTRIM", n->l, 0, 0); return;
    case XF_RTRIM: put_call(b, d, q, "RTRIM", n->l, 0, 0); return;
    case XF_POSITION: /* POSITION(needle IN text) */
        if (d == D_SQLITE) put_call(b, d, q, "instr", n->r, n->l, 0);
        else if (d == D_MY || d == D_MA) put_call(b, d, q, "LOCATE", n->l, n->r, 0);
        else if (d == D_MS) put_call(b, d, q, "CHARINDEX", n->l, n->r, 0);
        else {
            sb_str(b, "POSITION(");
            put_x(b, d, q, n->l, -1);
            sb_str(b, " IN ");
            put_x(b, d, q, n->r, -1);
            sb_str(b, ")");
        }
        return;
    case XF_COALESCE: put_call(b, d, q, "COALESCE", n->l, n->r, 0); return;
    case XF_NULLIF: put_call(b, d, q, "NULLIF", n->l, n->r, 0); return;
    case XF_LOWER: put_call(b, d, q, "LOWER", n->l, 0, 0); return;
    case XF_UPPER: put_call(b, d, q, "UPPER", n->l, 0, 0); return;
    case XF_REPLACE: put_call(b, d, q, "REPLACE", n->l, n->r, n->x3); return;
    case XF_CONCAT:
        if (d == D_MY || d == D_MA) { /* their || is OR */
            put_call(b, d, q, "CONCAT", n->l, n->r, 0);
            return;
        }
        sb_str(b, "(");
        put_x(b, d, q, n->l, -1);
        sb_str(b, d == D_MS ? " + " : " || ");
        put_x(b, d, q, n->r, -1);
        sb_str(b, ")");
        return;
    }
}

static void put_cast(sb *b, int d, const stmt *q, const xnode *n)
{
    sb_str(b, "CAST(");
    put_x(b, d, q, n->l, -1);
    switch (n->ty) {
    case CT_INT:
        sb_str(b, d == D_IMDB ? " AS INT64)" : d == D_SQLITE ? " AS INTEGER)" : d == D_MY || d == D_MA ? " AS SIGNED)" : " AS BIGINT)");
        return;
    case CT_FLT:
        sb_str(b, d == D_IMDB     ? " AS FLOAT64)"
                  : d == D_SQLITE ? " AS REAL)"
                  : d == D_PG     ? " AS DOUBLE PRECISION)"
                  : d == D_MS     ? " AS FLOAT(53))"
                                  : " AS DOUBLE)");
        return;
    case CT_DEC: sb_printf(b, " AS %s(18,%d))", d == D_PG ? "NUMERIC" : "DECIMAL", n->sc); return;
    default:
        sb_str(b, d == D_MY || d == D_MA ? " AS CHAR CHARACTER SET utf8mb4)" : d == D_MS ? " AS VARCHAR(40))" : " AS TEXT)");
        return;
    }
}

/* a computed TEXT under the columns' binary collation (a constant one would take the server's default) */
static const char *bin_coll(int d)
{
    return d == D_PG   ? " COLLATE \"C\""
           : d == D_MY ? " COLLATE utf8mb4_0900_bin"
           : d == D_MA ? " COLLATE utf8mb4_nopad_bin"
           : d == D_MS ? " COLLATE Latin1_General_100_BIN2_UTF8"
                       : NULL;
}

/* P2 S1: the engines a statement's forms are not put to: ROUND of a FLOAT64, LOWER and UPPER past SQLite (the
 * servers round half to even, map case past ASCII); a computed TEXT compared, NULLIF'd or ordered by MIN or MAX in SQL
 * Server (its comparison pads a trailing space away) */
static bool txt_computed(const stmt *q, int k)
{
    const xnode *n = XN(q, k);
    return n->ty == CT_TXT && n->op != X_COL && n->op != X_TXT && n->op != X_VAL;
}

static void fn_mark(stmt *q, int k)
{
    if (!k) return;
    const xnode *n = XN(q, k);
    const unsigned servers = 1u << D_PG | 1u << D_MY | 1u << D_MA | 1u << D_MS;
    if (n->op == X_FN && n->fn == XF_ROUND && XN(q, n->l)->ty == CT_FLT) q->skip |= servers;
    if (n->op == X_FN && (n->fn == XF_LOWER || n->fn == XF_UPPER)) q->skip |= servers;
    if ((n->op == X_CMP || n->op == X_LIKE || n->op == X_IN || (n->op == X_FN && n->fn == XF_NULLIF) ||
         (n->op == X_AGG && (n->fn == F_MIN || n->fn == F_MAX))) &&
        n->l && txt_computed(q, n->l))
        q->skip |= 1u << D_MS;
    fn_mark(q, n->l);
    fn_mark(q, n->r);
    fn_mark(q, n->x3);
}

/* a tree in dialect d, fully parenthesised (so "a - -5" never prints "--", a comment). Integer literals are BIGINT
 * in PostgreSQL and SQL Server (their bare literals are 32-bit); an INT64 / is DIV in MySQL and MariaDB, div() in
 * PostgreSQL where an operand is its numeric SUM; a DECIMAL quotient is rounded at imagedb's scale from one computed
 * far past it (PostgreSQL at 30 places, MySQL and MariaDB with div_precision_increment 30). SQLite (scaled) takes a
 * DECIMAL literal as its scaled integer in a DECIMAL tree, as a REAL in a FLOAT64 one. */
static void put_pred(sb *b, int d, const stmt *q, const pred *p);

static void put_x(sb *b, int d, const stmt *q, int k, int pty)
{
    const xnode *n = XN(q, k);
    if ((n->op == X_FN || n->op == X_CASE || n->op == X_CAST) && n->ty == CT_TXT && bin_coll(d)) { /* P2 S1 */
        sb_str(b, "(");
        if (n->op == X_FN) put_fn(b, d, q, n);
        else if (n->op == X_CAST) put_cast(b, d, q, n);
        else {
            sb_str(b, "CASE WHEN ");
            put_x(b, d, q, n->l, -1);
            sb_str(b, " THEN ");
            put_x(b, d, q, n->r, -1);
            if (n->x3) sb_str(b, " ELSE "), put_x(b, d, q, n->x3, -1);
            sb_str(b, " END");
        }
        sb_str(b, bin_coll(d));
        sb_str(b, ")");
        return;
    }
    switch (n->op) {
    case X_FN: put_fn(b, d, q, n); return;
    case X_CAST: put_cast(b, d, q, n); return;
    case X_CASE:
        sb_str(b, "(CASE WHEN ");
        put_x(b, d, q, n->l, -1);
        sb_str(b, " THEN ");
        put_x(b, d, q, n->r, n->ty);
        if (n->x3) sb_str(b, " ELSE "), put_x(b, d, q, n->x3, n->ty);
        sb_str(b, " END)");
        return;
    case X_TXT: put_txt(b, n->s); return;
    case X_NULL: sb_str(b, "NULL"); return;
    case X_VAL: {
        val v;
        memset(&v, 0, sizeof v);
        v.i = n->i;
        v.f = n->f;
        snprintf(v.s, sizeof v.s, "%s", n->s);
        put_lit(b, d, n->ty, &v);
        return;
    }
    case X_LIST: return; /* its elements: printed by their X_IN */
    case X_SUBQ: { /* P2 S4: (SELECT y FROM w [WHERE c]), EXISTS (SELECT 1 ...), (SELECT MAX(y) ...) */
        static const char *const AG[] = {"", "COUNT", "COUNT", "SUM", "MIN", "MAX", "AVG"};
        sb_str(b, n->fn == 1 ? "(EXISTS (SELECT 1" : "(SELECT ");
        if (n->fn == 0 && n->qual) sb_printf(b, "ci.%s", cols(n->tab)[n->col].name); /* P2 S4b */
        else if (n->fn == 0) put_col(b, q, n->tab, n->col);
        else if (n->fn == 2 && n->i == F_COUNT_STAR) sb_str(b, "COUNT(*)");
        else if (n->fn == 2 && n->qual) sb_printf(b, "%s(ci.%s)", AG[n->i], cols(n->tab)[n->col].name);
        else if (n->fn == 2) sb_printf(b, "%s(", AG[n->i]), put_col(b, q, n->tab, n->col), sb_str(b, ")");
        sb_printf(b, n->qual ? " FROM %s AS ci" : " FROM %s", tname(n->tab));
        if (n->x3) sb_str(b, " WHERE "), put_x(b, d, q, n->x3, -1);
        sb_str(b, n->fn == 1 ? "))" : ")");
        return;
    }
    case X_IN: {
        const xnode *o = XN(q, n->l);
        if (XN(q, n->r)->op == X_SUBQ) { /* P2 S4 */
            sb_str(b, "(");
            if (o->op == X_COL) put_col(b, q, o->tab, o->col);
            else put_x(b, d, q, n->l, -1);
            sb_str(b, n->fn ? " NOT IN " : " IN ");
            put_x(b, d, q, n->r, -1);
            sb_str(b, ")");
            return;
        }
        sb_str(b, "(");
        if (o->op == X_COL) put_col(b, q, o->tab, o->col); /* SQL Server's BIT bare: k IN (1, 0) */
        else put_x(b, d, q, n->l, -1);
        sb_str(b, n->fn ? " NOT IN (" : " IN (");
        for (int li = n->r, first = 1; li; li = XN(q, li)->r, first = 0) {
            if (!first) sb_str(b, ", ");
            put_x(b, d, q, XN(q, li)->l, -1);
        }
        sb_str(b, "))");
        return;
    }
    case X_LIKE:
        sb_str(b, "(");
        put_x(b, d, q, n->l, -1);
        sb_str(b, n->fn ? " NOT LIKE " : " LIKE ");
        put_txt(b, n->s);
        sb_str(b, " ESCAPE '!')");
        return;
    case X_COL:
        if (n->qual) { /* P2 S4b: a correlated subquery's own column by its alias, or the outer table's by name */
            sb_printf(b, "%s.%s", n->qual == 1 ? "ci" : tname(n->tab), cols(n->tab)[n->col].name);
            return;
        }
        if (d == D_MS && cols(n->tab)[n->col].t == CT_BOOL) { /* T-SQL has no bare boolean: its BIT, as a condition */
            sb_str(b, "(");
            put_col(b, q, n->tab, n->col);
            sb_str(b, " = 1)");
            return;
        }
        put_col(b, q, n->tab, n->col);
        return;
    case X_PRED: /* a plain predicate, printed as the top level prints one */
        sb_str(b, "(");
        put_pred(b, d, q, &q->xp[n->col]);
        sb_str(b, ")");
        return;
    case X_NOT:
        sb_str(b, "(NOT ");
        put_x(b, d, q, n->l, n->ty);
        sb_str(b, ")");
        return;
    case X_AND:
    case X_OR:
        sb_str(b, "(");
        put_x(b, d, q, n->l, n->ty);
        sb_str(b, n->op == X_AND ? " AND " : " OR ");
        put_x(b, d, q, n->r, n->ty);
        sb_str(b, ")");
        return;
    case X_CMP:
        sb_str(b, "(");
        put_x(b, d, q, n->l, -1);
        if (n->fn == OP_ISNULL || n->fn == OP_NOTNULL) {
            sb_str(b, n->fn == OP_ISNULL ? " IS NULL)" : " IS NOT NULL)");
            return;
        }
        if (n->fn == OP_BETWEEN) {
            sb_str(b, " BETWEEN ");
            put_x(b, d, q, n->r, -1);
            sb_str(b, " AND ");
            put_x(b, d, q, n->x3, -1);
        } else {
            sb_printf(b, " %s ", OPS[n->fn]);
            put_x(b, d, q, n->r, -1);
        }
        sb_str(b, ")");
        return;
    case X_INT:
        if (d == D_PG || d == D_MS) sb_printf(b, "CAST(%" PRId64 " AS BIGINT)", n->i);
        else if (n->i < 0) sb_printf(b, "(%" PRId64 ")", n->i);
        else sb_printf(b, "%" PRId64, n->i);
        return;
    case X_DEC:
        if (d == D_SQLITE && n->scaled) { /* a SET's d +- literal: the scaled integer */
            sb_printf(b, "(%" PRId64 ")", n->i);
            return;
        }
        sb_str(b, "(");
        put_scaled(b, n->i, n->lscale);
        sb_str(b, ")");
        return;
    case X_NEG:
        sb_str(b, "(-");
        put_x(b, d, q, n->l, n->ty);
        sb_str(b, ")");
        return;
    case X_AGG: {
        static const char *const FN[] = {"", "COUNT", "COUNT", "SUM", "MIN", "MAX", "AVG"};
        /* P2 S2: FILTER (WHERE c) native in imagedb, SQLite and PostgreSQL; the others' agg(CASE WHEN c THEN x END),
         * COUNT(*)'s COUNT(CASE WHEN c THEN 1 END) */
        bool native = d == D_IMDB || d == D_SQLITE || d == D_PG, rewrite = n->x3 && !native;
        if (n->fn == F_COUNT_STAR) {
            if (rewrite) {
                sb_str(b, "COUNT(CASE WHEN ");
                put_x(b, d, q, n->x3, -1);
                sb_str(b, " THEN 1 END)");
                return;
            }
            sb_str(b, "COUNT(*)");
            if (n->x3) sb_str(b, " FILTER (WHERE "), put_x(b, d, q, n->x3, -1), sb_str(b, ")");
            return;
        }
        if (n->dist || n->x3) {
            bool cast = n->fn == F_SUM && n->ty == CT_INT && (d == D_PG || d == D_MY || d == D_MA);
            if (cast) sb_str(b, "CAST(");
            sb_printf(b, "%s(%s", FN[n->fn], n->dist ? "DISTINCT " : "");
            if (rewrite) sb_str(b, "CASE WHEN "), put_x(b, d, q, n->x3, -1), sb_str(b, " THEN ");
            put_x(b, d, q, n->l, n->ty);
            sb_str(b, rewrite ? " END)" : ")");
            if (n->x3 && native) sb_str(b, " FILTER (WHERE "), put_x(b, d, q, n->x3, -1), sb_str(b, ")");
            if (cast) sb_str(b, d == D_PG ? " AS BIGINT)" : " AS SIGNED)");
            return;
        }
        /* an integer SUM is NUMERIC in PostgreSQL and DECIMAL in MySQL and MariaDB, which never overflow: cast to
         * imagedb's INT64, so arithmetic over it overflows where imagedb's does (its values stay far inside) */
        if (n->fn == F_AVG && n->ty == CT_DEC && (d == D_PG || d == D_MY || d == D_MA)) {
            /* imagedb's AVG of an INT64 or a DECIMAL: SUM / COUNT at its scale, rounded half away from zero; theirs
             * SUM / COUNT computed far past it, as a DECIMAL quotient is (PostgreSQL at 30 places, MySQL and MariaDB by
             * div_precision_increment 30), then rounded there. SQLite (a REAL) and SQL Server (an INT64's AVG an
             * INT64) are not asked (lite_ok, ms_ok) */
            sb_str(b, d == D_PG ? "ROUND(CAST(SUM(" : "ROUND(SUM(");
            put_x(b, d, q, n->l, -1);
            sb_str(b, d == D_PG ? ") AS NUMERIC(70,30)) / COUNT(" : ") / COUNT(");
            put_x(b, d, q, n->l, -1);
            sb_printf(b, "), %d)", n->sc);
            return;
        }
        bool cast = n->fn == F_SUM && n->ty == CT_INT && (d == D_PG || d == D_MY || d == D_MA);
        if (cast) sb_str(b, "CAST(");
        sb_printf(b, "%s(", FN[n->fn]);
        put_x(b, d, q, n->l, n->ty);
        sb_str(b, !cast ? ")" : d == D_PG ? ") AS BIGINT)" : ") AS SIGNED)");
        return;
    }
    default:
        break;
    }
    if (n->op == X_DIV && n->ty == CT_INT && (d == D_MY || d == D_MA)) { /* their / of integers is a DECIMAL */
        sb_str(b, "(");
        put_x(b, d, q, n->l, n->ty);
        sb_str(b, " DIV ");
        put_x(b, d, q, n->r, n->ty);
        sb_str(b, ")");
        return;
    }
    if (n->op == X_DIV && n->ty == CT_DEC && (d == D_PG || d == D_MY || d == D_MA)) {
        sb_str(b, d == D_PG ? "ROUND(CAST(" : "ROUND((");
        put_x(b, d, q, n->l, n->ty);
        sb_str(b, d == D_PG ? " AS NUMERIC(70,30)) / " : ") / ");
        put_x(b, d, q, n->r, n->ty);
        sb_printf(b, ", %d)", n->sc);
        return;
    }
    static const char *const OP[] = {"", "", "", "", " + ", " - ", " * ", " / ", " % "};
    sb_str(b, "(");
    put_x(b, d, q, n->l, n->ty);
    sb_str(b, OP[n->op]);
    put_x(b, d, q, n->r, n->ty);
    sb_str(b, ")");
}

static void put_pred(sb *b, int d, const stmt *q, const pred *p)
{
    if (p->bt) { /* a condition (1c) */
        put_x(b, d, q, p->bt, -1);
        return;
    }
    if (p->lx) { /* trees */
        put_x(b, d, q, p->lx, -1);
        if (p->op == OP_ISNULL || p->op == OP_NOTNULL) {
            sb_str(b, p->op == OP_ISNULL ? " IS NULL" : " IS NOT NULL");
            return;
        }
        if (p->op == OP_BETWEEN) {
            sb_str(b, " BETWEEN ");
            put_x(b, d, q, p->ax, -1);
            sb_str(b, " AND ");
            put_x(b, d, q, p->bx, -1);
            return;
        }
        sb_printf(b, " %s ", OPS[p->op]);
        put_x(b, d, q, p->ax, -1);
        return;
    }
    put_col(b, q, p->tab, p->col);
    int t = cols(p->tab)[p->col].t;
    switch (p->op) {
    case OP_ISNULL: sb_str(b, " IS NULL"); break;
    case OP_NOTNULL: sb_str(b, " IS NOT NULL"); break;
    case OP_BETWEEN:
        sb_str(b, " BETWEEN ");
        put_lit(b, d, t, &p->a);
        sb_str(b, " AND ");
        put_lit(b, d, t, &p->b);
        break;
    default:
#ifdef ORACLE_MUTATE /* the oracle's own check: imagedb is sent <= where the others get <, which it must catch */
        if (d == D_IMDB && p->op == OP_LT) {
            sb_str(b, " <= ");
            put_lit(b, d, t, &p->a);
            break;
        }
#endif
        sb_printf(b, " %s ", OPS[p->op]);
        put_lit(b, d, t, &p->a);
    }
}

static void put_where(sb *b, int d, const stmt *q)
{
    for (int i = 0; i < q->npr; i++) {
        sb_str(b, i ? " AND " : " WHERE ");
        put_pred(b, d, q, &q->pr[i]);
    }
}

/* SELECT item i */
static void put_item(sb *b, int d, const stmt *q, int i)
{
    static const char *const FN[] = {"", "COUNT", "COUNT", "SUM", "MIN", "MAX", "AVG"};
    const item *it = &q->it[i];
    if (it->ex) put_x(b, d, q, it->ex, -1);
    else if (it->fn == F_COL) put_col(b, q, it->tab, it->col);
    else if (it->fn == F_COUNT_STAR) sb_str(b, "COUNT(*)");
    else {
        sb_printf(b, "%s(", FN[it->fn]);
        put_col(b, q, it->tab, it->col);
        sb_str(b, ")");
    }
}

/* an ORDER BY key's expression; a position as written, but where it must be repeated (an IS NULL key) the item */
static void put_okey_expr(sb *b, int d, const stmt *q, const struct okey *k, bool spelled)
{
    if (k->pos && !spelled) sb_printf(b, "%d", k->pos);
    else if (k->pos && q->star) put_col(b, q, q->tab, k->pos - 1);
    else if (k->pos) put_item(b, d, q, k->pos - 1);
    else if (k->ex) put_x(b, d, q, k->ex, -1);
    else put_col(b, q, k->tab, k->col);
}

/* an ORDER BY key with its NULLs placed: PostgreSQL, SQLite and imagedb say NULLS FIRST/LAST; MySQL and MariaDB have
 * none (NULL is their least), so a key (k IS NULL) goes first; SQL Server, the same as CASE */
/* for SQL Server, which refuses a column named twice in ORDER BY (a position counts as its item's column): has the
 * column key k names (a position of a plain item, a bare column tree, a column key) been a key already? Marks it if
 * not. A repeated column orders nothing more, so dropping it keeps the order; a position of an item that is no column
 * repeats as that position; a tree key that is no column is taken as new */
static bool key_seen(const stmt *q, const struct okey *k, int seen[][2], int *nseen)
{
    int tab = -1, col = -1;
    const xnode *n = NULL;
    if (k->pos && q->star) {
        tab = q->tab;
        col = k->pos - 1;
    } else if (k->pos) {
        const item *it = &q->it[k->pos - 1];
        if (it->ex && XN(q, it->ex)->op == X_COL) n = XN(q, it->ex);
        else if (it->ex || it->fn != F_COL) tab = -2, col = k->pos; /* an item that is no column: its position */
        else tab = it->tab, col = it->col;
    } else if (k->ex) {
        n = XN(q, k->ex);
    } else {
        tab = k->tab;
        col = k->col;
    }
    if (n) {
        if (n->op != X_COL) return false;
        tab = n->tab;
        col = n->col;
    }
    for (int i = 0; i < *nseen; i++)
        if (seen[i][0] == tab && seen[i][1] == col) return true;
    if (*nseen < 8) {
        seen[*nseen][0] = tab;
        seen[*nseen][1] = col;
        (*nseen)++;
    }
    return false;
}

/* a constant: no column, aggregate or plain predicate in it (never NULL: no NULL literal is drawn) */
static bool x_const(const stmt *q, int k)
{
    if (!k) return true;
    const xnode *n = XN(q, k);
    if (n->op == X_COL || n->op == X_AGG || n->op == X_PRED) return false;
    return x_const(q, n->l) && x_const(q, n->r) && x_const(q, n->x3);
}

/* the key orders by a constant (a position of a constant item: SQL Server takes it, but refuses a CASE over it) */
static bool okey_const(const stmt *q, const struct okey *k)
{
    if (k->pos) return !q->star && q->it[k->pos - 1].ex && x_const(q, q->it[k->pos - 1].ex);
    return k->ex && x_const(q, k->ex);
}

static void put_okey(sb *b, int d, const stmt *q, const struct okey *k)
{
    if (d == D_MY || d == D_MA) {
        sb_str(b, "(");
        put_okey_expr(b, d, q, k, true);
        sb_str(b, ") IS NULL");
        sb_str(b, k->nf ? " DESC, " : ", ");
        put_okey_expr(b, d, q, k, false);
        if (k->desc) sb_str(b, " DESC");
        return;
    }
    put_okey_expr(b, d, q, k, false);
    sb_str(b, k->desc ? " DESC" : "");
    sb_str(b, k->nf ? " NULLS FIRST" : " NULLS LAST");
}

/* SQL Server refuses an ORDER BY item that its folding makes a constant: COALESCE(2.32, t.d), CASE WHEN 11 = -6 THEN
 * t.d END, the CASE WHEN k IS NULL over either, or that CASE over a position whose item folds (seeds 14, 25, 43, 49, 93
 * of the 2026-11-05 five-engine run). A constant orders nothing, so each item it names is left out and the statement
 * run again (ms_drop_constants): g_ms_drop holds them, numbered over the list as printed with none left out, and
 * g_ms_at maps a printed position back to that numbering. Only the statement's own ORDER BY comes here: a set
 * operation's and a window's are printed apart */
static unsigned long long g_ms_drop;
static int g_ms_item, g_ms_at[64], g_ms_nat;
static long g_ms_dropped;

/* the next ORDER BY item (SQL Server): false when it is one left out, else its comma */
static bool ms_item(sb *b, bool *first)
{
    int i = g_ms_item++;
    if (i < 64 && (g_ms_drop >> i & 1)) return false;
    if (!*first) sb_str(b, ", ");
    *first = false;
    if (g_ms_nat < 64) g_ms_at[g_ms_nat++] = i;
    return true;
}

/* a key in SQL Server's words: NULLs placed by a CASE before it (none over a constant: never NULL, and refused) */
static void put_okey_ms(sb *b, const stmt *q, const struct okey *k, bool *first)
{
    if (!okey_const(q, k) && ms_item(b, first)) {
        sb_str(b, "CASE WHEN ");
        put_okey_expr(b, D_MS, q, k, true);
        sb_str(b, " IS NULL THEN 1 ELSE 0 END");
        if (k->nf) sb_str(b, " DESC");
    }
    if (ms_item(b, first)) {
        put_okey_expr(b, D_MS, q, k, false);
        if (k->desc) sb_str(b, " DESC");
    }
}

/* the join's FROM: t JOIN | LEFT | RIGHT | FULL | CROSS JOIN u, ON t.id = u.tid [AND t.s = u.s] [AND cond] or USING (s)
 * (P2 S3; SQL Server has no USING: its ON). swap: u first (SQLite 3.37's RIGHT JOIN, written as the LEFT JOIN it is,
 * and the second half of its FULL JOIN) */
static void put_join(sb *b, int d, const stmt *q, int kind, bool swap)
{
    static const char *const KW[] = {"", " JOIN ", " LEFT JOIN ", " RIGHT JOIN ", " FULL JOIN ", " CROSS JOIN "};
    sb_printf(b, " FROM %s%s%s", swap ? "u" : "t", KW[kind], swap ? "t" : "u");
    if (kind == 5) return;
    if (q->jusing && d != D_MS) {
        sb_str(b, " USING (s)");
        return;
    }
    sb_str(b, q->jusing ? " ON t.s = u.s" : " ON t.id = u.tid");
    if (q->jkey2) sb_str(b, " AND t.s = u.s");
    if (q->jx) sb_str(b, " AND "), put_x(b, d, q, q->jx, -1);
}

/* P2 S3: ON's other condition: a column of u against a literal, or a column of each side compared */
static int gen_jcond(stmt *q)
{
    int k;
    if (chance(50)) {
        int lit = xlit_int(q, rr(-400, 400));
        k = xbool(q, X_CMP, xcol(q, 1, 2), lit);
    } else {
        int c0 = xcol(q, 0, (int[]){1, 2}[rnd() % 2]);
        k = xbool(q, X_CMP, c0, xcol(q, 1, 2));
    }
    XN(q, k)->fn = (int)rr(OP_EQ, OP_GE);
    return k;
}

/* P2 S5: a set operation: its SELECTs, their operators, its tail (ORDER BY the one column's position) */
static void print_setop(sb *b, int d, const stmt *q)
{
    static const char *const OP[] = {"UNION", "UNION ALL", "INTERSECT", "EXCEPT"};
    for (int a = 0; a < q->narm; a++) {
        const struct sarm *m = &q->arm[a];
        if (a) sb_printf(b, " %s ", OP[q->armop[a]]);
        sb_str(b, "SELECT ");
        for (int c = 0; c < q->ncol; c++) sb_printf(b, "%s%s", c ? ", " : "", cols(m->tab)[m->col[c]].name);
        sb_printf(b, " FROM %s", tname(m->tab));
        if (m->has_pr) {
            sb_str(b, " WHERE ");
            put_pred(b, d, q, &m->pr);
        }
    }
    if (!q->stail) return;
    sb_printf(b, " ORDER BY 1%s", q->sdesc ? " DESC" : "");
    if (d == D_MS) {
        sb_printf(b, " OFFSET %d ROWS", q->soff);
        if (q->slim) sb_printf(b, " FETCH NEXT %d ROWS ONLY", q->slim);
        return;
    }
    if (q->slim) sb_printf(b, " LIMIT %d", q->slim);
    else if (q->soff && d == D_SQLITE) sb_str(b, " LIMIT -1");
    else if (q->soff && (d == D_MY || d == D_MA)) sb_str(b, " LIMIT 18446744073709551615");
    if (q->soff) sb_printf(b, " OFFSET %d", q->soff);
}

/* P2 S5: WITH RECURSIVE, printed as each dialect writes it (T-SQL: no RECURSIVE) */
static void print_rec(sb *b, int d, const stmt *q)
{
    const char *rk = d == D_MS ? "WITH" : "WITH RECURSIVE", *op = q->rall ? "UNION ALL" : "UNION";
    if (q->rec == 3)
        sb_printf(b, "%s r(x) AS (SELECT g FROM t WHERE g IS NOT NULL %s SELECT x + 1 FROM r WHERE x < 6) SELECT COUNT(*), "
                     "SUM(x) FROM r", rk, op);
    else if (q->rec == 1)
        sb_printf(b, "%s n(i) AS (SELECT 1 %s SELECT i + 1 FROM n WHERE i < %d) SELECT COUNT(*), SUM(i) FROM n", rk, op, q->rk);
    else
        sb_printf(b, "%s r(x, depth) AS (SELECT %s%" PRId64 "%s, 0 %s SELECT u.id, r.depth + 1 FROM r JOIN u ON u.tid = r.x WHERE "
                     "r.depth < 6) SELECT COUNT(*), SUM(x) FROM r",
                  rk, d == D_PG || d == D_MS ? "CAST(" : "", q->rstart, d == D_PG || d == D_MS ? " AS BIGINT)" : "", op); /* the start
                  * a BIGINT, as u.id is: PostgreSQL and SQL Server want the two parts' types alike (MySQL's CAST has no
                  * BIGINT) */
}

/* P2 S6: the window statement, each dialect alike (T-SQL writes the frame the same; its default is the same) */
static void print_win(sb *b, int d, const stmt *q)
{
    static const char *const F[] = {"ROW_NUMBER", "RANK", "DENSE_RANK", "NTILE", "LAG", "LEAD", "FIRST_VALUE", "LAST_VALUE",
                                    "SUM", "COUNT", "MIN", "MAX"};
    const char *col = cols(0)[q->wcol].name;
    sb_printf(b, "SELECT id, %s(", F[q->wfn]);
    if (q->wfn == WO_NTILE) sb_printf(b, "%d", q->wk);
    else if (q->wfn == WO_LAG || q->wfn == WO_LEAD) {
        sb_printf(b, "%s, %d", col, q->wk);
        if (q->wdef) sb_str(b, cols(0)[q->wcol].t == CT_TXT ? ", 'none'" : ", -1");
    } else if (q->wfn >= WO_FIRST) sb_str(b, col);
    sb_str(b, ") OVER (");
    if (q->wpart) sb_str(b, "PARTITION BY g ");
    sb_printf(b, "ORDER BY id %% 3%s", q->wdesc ? " DESC" : "");
    if (q->wtotal) sb_printf(b, ", id%s", q->wdesc ? " DESC" : "");
    if (q->wframe) sb_printf(b, " ROWS BETWEEN %d PRECEDING AND %d FOLLOWING", q->wlo, q->whi);
    sb_str(b, ") AS w FROM t");
    if (q->npr) {
        sb_str(b, " WHERE ");
        put_pred(b, d, q, &q->pr[0]);
    }
}

static void print_stmt(sb *b, int d, const stmt *q)
{
    sb_reset(b);
    switch (q->kind) {
    case Q_BEGIN: sb_str(b, d == D_MY || d == D_MA ? "START TRANSACTION" : d == D_MS ? "BEGIN TRANSACTION" : "BEGIN"); return;
    case Q_COMMIT: sb_str(b, "COMMIT"); return;
    case Q_ROLLBACK: sb_str(b, "ROLLBACK"); return;
    case Q_INSERT:
        sb_printf(b, "INSERT INTO %s VALUES ", tname(q->tab));
        for (int r = 0; r < q->nrow; r++) {
            sb_str(b, r ? ", (" : "(");
            for (int c = 0; c < ncols(q->tab); c++) {
                if (c) sb_str(b, ", ");
                put_lit(b, d, cols(q->tab)[c].t, &q->row[r][c]);
            }
            sb_str(b, ")");
        }
        return;
    case Q_UPDATE:
        sb_printf(b, "UPDATE %s SET ", tname(q->tab));
        for (int i = 0; i < q->nset; i++) {
            if (i) sb_str(b, ", ");
            sb_printf(b, "%s = ", cols(q->tab)[q->scol[i]].name);
            if (q->sx[i]) put_x(b, d, q, q->sx[i], -1);
            else put_lit(b, d, cols(q->tab)[q->scol[i]].t, &q->sval[i]);
        }
        put_where(b, d, q);
        return;
    case Q_DELETE:
        sb_printf(b, "DELETE FROM %s", tname(q->tab));
        put_where(b, d, q);
        return;
    }
    if (q->win) { /* P2 S6 */
        print_win(b, d, q);
        return;
    }
    if (q->narm) { /* P2 S5 */
        print_setop(b, d, q);
        return;
    }
    if (q->rec) {
        print_rec(b, d, q);
        return;
    }
    if (q->dsel == 2) { /* P2 S4: the CTE first */
        sb_str(b, "WITH x AS (SELECT ");
        for (int i = 0; i < q->ndc; i++) sb_printf(b, "%s%s", i ? ", " : "", cols(0)[q->dc[i]].name);
        sb_str(b, " FROM t");
        if (q->has_dpred) sb_str(b, " WHERE "), put_pred(b, d, q, &q->dpred);
        sb_str(b, ") ");
    }
    sb_str(b, "SELECT ");
    if (q->distinct) sb_str(b, "DISTINCT ");
    if (q->star) sb_str(b, "*");
    for (int i = 0; i < q->nit; i++) {
        const item *it = &q->it[i];
        if (i) sb_str(b, ", ");
        static const char *const FN[] = {"", "COUNT", "COUNT", "SUM", "MIN", "MAX", "AVG"};
        if (it->ex) put_x(b, d, q, it->ex, -1);
        else if (it->fn == F_COL) put_col(b, q, it->tab, it->col);
        else if (it->fn == F_COUNT_STAR) sb_str(b, "COUNT(*)");
        else {
            sb_printf(b, "%s(", FN[it->fn]);
            put_col(b, q, it->tab, it->col);
            sb_str(b, ")");
        }
    }
    if (q->dsel == 1) { /* P2 S4: a derived table */
        sb_str(b, " FROM (SELECT ");
        for (int i = 0; i < q->ndc; i++) sb_printf(b, "%s%s", i ? ", " : "", cols(0)[q->dc[i]].name);
        sb_str(b, " FROM t");
        if (q->has_dpred) sb_str(b, " WHERE "), put_pred(b, d, q, &q->dpred);
        sb_str(b, ") AS x");
    } else if (q->dsel == 2) {
        sb_str(b, " FROM x");
    } else if (!q->join) {
        sb_printf(b, " FROM %s", tname(q->tab)); /* a join's FROM: put_join (P2 S3) */
    }
    if (q->join == 4 && d == D_SQLITE) { /* P2 S3: FULL as LEFT JOIN UNION ALL the other side's rows nothing matched */
        size_t sel = b->n;
        char *head = malloc(sel + 1);
        if (!head) exit(3);
        memcpy(head, b->p, sel + 1);
        put_join(b, d, q, 2, false);
        put_where(b, d, q);
        sb_str(b, " UNION ALL ");
        sb_put(b, head, sel);
        free(head);
        put_join(b, d, q, 2, true);
        put_where(b, d, q);
        sb_str(b, q->npr ? " AND t.id IS NULL" : " WHERE t.id IS NULL");
    } else {
        if (q->join) put_join(b, d, q, q->join == 3 && d == D_SQLITE ? 2 : q->join, q->join == 3 && d == D_SQLITE);
            put_where(b, d, q);
    }
    if (q->gcol >= 0) {
        sb_str(b, " GROUP BY ");
        put_col(b, q, 0, q->gcol);
    }
    if (q->ngk) { /* P2 S2: each key as its item prints it (a bare column unqualified alike) */
        sb_str(b, " GROUP BY ");
        for (int g = 0; g < q->ngk; g++) {
            const xnode *n = XN(q, q->gk[g]);
            if (g) sb_str(b, ", ");
            if (d == D_MA) sb_printf(b, "%d", g + 1); /* MariaDB matches no item to a key with COLLATE: its position
                                                       * (gen_group: key g is item g) */
            else if (n->op == X_COL) put_col(b, q, n->tab, n->col);
            else put_x(b, d, q, q->gk[g], -1);
        }
    }
    if (q->hv) { /* 1e */
        sb_str(b, " HAVING ");
        put_x(b, d, q, q->hv, -1);
    }
    /* ORDER BY (1d), LIMIT, OFFSET. imagedb's order is total (its keys, then its default order: the primary key's, a
     * group's key, a join's keys with the NULL-extended row last); each reference is given that tie-break written out
     * (qualified: T-SQL reads a bare id as the select list's, ambiguous when it is named twice) and its own way with
     * NULLs. Under DISTINCT the keys are every item already (gen_order). */
    bool ordered = q->nord || q->limit || q->offset;
    if (ordered && (d != D_IMDB || q->nord)) {
        g_qual = d == D_MS || d == D_PG; /* PostgreSQL: a bare name is an output column's first, and it names
                                          * CAST(id AS TEXT) id too (seed 31 of the 2026-11-05 five-engine run) */
        sb_str(b, " ORDER BY ");
        int seen[8][2], nseen = 0; /* SQL Server refuses a column named twice: a repeated key orders nothing more */
        bool first = true;
        g_ms_item = g_ms_nat = 0;
        for (int i = 0; i < q->nord; i++) {
            if (d == D_MS) {
                if (!key_seen(q, &q->ord[i], seen, &nseen)) put_okey_ms(b, q, &q->ord[i], &first);
                continue;
            }
            if (!first) sb_str(b, ", ");
            first = false;
            put_okey(b, d, q, &q->ord[i]);
        }
        if (d != D_IMDB && !q->distinct) {
            struct okey tb[2] = {{q->gcol >= 0 ? 0 : q->join ? 0 : q->tab, q->gcol >= 0 ? q->gcol : 0, 0, 0, false, false},
                                 {1, 0, 0, 0, false, false}};
            for (int i = 0; i < (q->gcol < 0 && q->join ? 2 : 1); i++) {
                if (d == D_MS && key_seen(q, &tb[i], seen, &nseen)) continue;
                if (q->gcol < 0 && i == 0) { /* a key: never NULL */
                    if (d == D_MS && !ms_item(b, &first)) continue;
                    if (d != D_MS && !first) sb_str(b, ", ");
                    first = false;
                    sb_printf(b, "%s.id", tname(tb[0].tab));
                    continue;
                }
                if (d == D_MS) {
                    put_okey_ms(b, q, &tb[i], &first);
                    continue;
                }
                if (!first) sb_str(b, ", ");
                first = false;
                put_okey(b, d, q, &tb[i]);
            }
        }
        if (d == D_MS && first) sb_str(b, "(SELECT NULL)"); /* every item a constant SQL Server left out */
    }
    g_qual = false;
    if (d == D_MS) { /* its window needs ORDER BY, which every ordered statement has */
        if (ordered) sb_printf(b, " OFFSET %d ROWS", q->offset);
        if (q->limit) sb_printf(b, " FETCH NEXT %d ROWS ONLY", q->limit);
    } else {
        if (q->limit) sb_printf(b, " LIMIT %d", q->limit);
        else if (q->offset && d == D_SQLITE) sb_str(b, " LIMIT -1"); /* their OFFSET needs a LIMIT */
        else if (q->offset && (d == D_MY || d == D_MA)) sb_str(b, " LIMIT 18446744073709551615");
        if (q->offset) sb_printf(b, " OFFSET %d", q->offset);
    }
}

/* the result's column types, as the statement promises them */
static int out_types(const stmt *q, int *ty)
{
    if (q->narm) { /* P2 S5 */
        for (int c = 0; c < q->ncol; c++) ty[c] = TY(cols(q->arm[0].tab)[q->arm[0].col[c]].t, 0);
        return q->ncol;
    }
    if (q->win) { /* P2 S6: id, then the function's value (a count or a rank INT64, else its column's type) */
        ty[0] = TY(CT_INT, 0);
        bool isval = q->wfn == WO_LAG || q->wfn == WO_LEAD || q->wfn == WO_FIRST || q->wfn == WO_LAST || q->wfn == WO_MIN ||
                   q->wfn == WO_MAX || q->wfn == WO_SUM;
        ty[1] = TY(isval ? cols(0)[q->wcol].t : CT_INT, 0);
        return 2;
    }
    if (q->rec) { /* P2 S5: COUNT(*), SUM */
        ty[0] = ty[1] = TY(CT_INT, 0);
        return 2;
    }
    if (q->star) {
        for (int c = 0; c < ncols(q->tab); c++) ty[c] = TY(cols(q->tab)[c].t, cols(q->tab)[c].t == CT_DEC ? 2 : 0);
        return ncols(q->tab);
    }
    for (int i = 0; i < q->nit; i++) {
        const item *it = &q->it[i];
        if (it->ex) { /* imagedb's type for it, which every engine's answer is read as */
            const xnode *n = XN(q, it->ex);
            ty[i] = TY(n->ty, n->ty == CT_DEC ? n->sc : 0);
            continue;
        }
        int t = it->fn == F_COUNT_STAR || it->fn == F_COUNT ? CT_INT : cols(it->tab)[it->col].t;
        ty[i] = TY(t, t == CT_DEC ? 2 : 0);
    }
    return q->nit;
}

static const char *ddl(int d, int tab)
{
    static const char *const T[ND] = {
        "CREATE TABLE t (id INT64 PRIMARY KEY, g INT64, a INT64, x INT64, d DECIMAL(12,2), f FLOAT64, s TEXT, k BOOL, "
        "ts TIMESTAMP)",
        "CREATE TABLE t (id INTEGER PRIMARY KEY, g INTEGER, a INTEGER, x INTEGER, d INTEGER, f REAL, s TEXT, "
        "k INTEGER, ts INTEGER)",
        "CREATE TABLE t (id BIGINT PRIMARY KEY, g BIGINT, a BIGINT, x BIGINT, d NUMERIC(12,2), f DOUBLE PRECISION, "
        "s TEXT COLLATE \"C\", k BOOLEAN, ts TIMESTAMP(6))",
        "CREATE TABLE t (id BIGINT PRIMARY KEY, g BIGINT, a BIGINT, x BIGINT, d DECIMAL(12,2), f DOUBLE, "
        "s VARCHAR(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_bin, k BOOLEAN, ts DATETIME(6))",
        "CREATE TABLE t (id BIGINT PRIMARY KEY, g BIGINT, a BIGINT, x BIGINT, d DECIMAL(12,2), f DOUBLE, "
        "s VARCHAR(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_nopad_bin, k BOOLEAN, ts DATETIME(6))",
        "CREATE TABLE t (id BIGINT NOT NULL PRIMARY KEY, g BIGINT, a BIGINT, x BIGINT, d DECIMAL(12,2), f FLOAT(53), "
        "s VARCHAR(255) COLLATE Latin1_General_100_BIN2_UTF8, k BIT, ts DATETIME2(6))"};
    static const char *const U[ND] = {
        "CREATE TABLE u (id INT64 PRIMARY KEY, tid INT64, v INT64, s TEXT)",
        "CREATE TABLE u (id INTEGER PRIMARY KEY, tid INTEGER, v INTEGER, s TEXT)",
        "CREATE TABLE u (id BIGINT PRIMARY KEY, tid BIGINT, v BIGINT, s TEXT COLLATE \"C\")",
        "CREATE TABLE u (id BIGINT PRIMARY KEY, tid BIGINT, v BIGINT, s VARCHAR(255) CHARACTER SET utf8mb4 COLLATE "
        "utf8mb4_0900_bin)",
        "CREATE TABLE u (id BIGINT PRIMARY KEY, tid BIGINT, v BIGINT, s VARCHAR(255) CHARACTER SET utf8mb4 COLLATE "
        "utf8mb4_nopad_bin)",
        "CREATE TABLE u (id BIGINT NOT NULL PRIMARY KEY, tid BIGINT, v BIGINT, s VARCHAR(255) COLLATE "
        "Latin1_General_100_BIN2_UTF8)"};
    return tab ? U[d] : T[d];
}

/* ---- canonical cells: every engine's answer to one text per value ------------------------------------------------ */

#define NULLMARK "\\N"

static void canon_flt(sb *b, double f) { sb_printf(b, "%a", f == 0 ? 0.0 : f); }

/* an integer's text: optional sign, digits; leading zeros dropped, "-0" is "0" */
static int canon_int_text(sb *b, const char *s)
{
    bool neg = *s == '-';
    if (*s == '-' || *s == '+') s++;
    if (!*s) return -1;
    for (const char *p = s; *p; p++)
        if (*p < '0' || *p > '9') return -1;
    while (*s == '0' && s[1]) s++;
    if (neg && strcmp(s, "0")) sb_str(b, "-");
    sb_str(b, s);
    return 0;
}

/* a decimal's text ("-12.30", ".50", "-.5", "7", "1.5000") at scale sc: a digit past it that is not zero is refused */
static int canon_dec_text(sb *b, const char *s, int sc)
{
    bool neg = *s == '-';
    if (*s == '-' || *s == '+') s++;
    __int128 x = 0;
    int nd = 0, nf = 0;
    for (; *s >= '0' && *s <= '9'; s++, nd++) {
        if (x > ((__int128)1 << 120)) return -1;
        x = x * 10 + (*s - '0');
    }
    if (*s == '.') {
        for (s++; *s >= '0' && *s <= '9'; s++, nf++) {
            if (nf < sc) x = x * 10 + (*s - '0');
            else if (*s != '0') return -1;
        }
    }
    if (*s || (!nd && !nf)) return -1;
    for (int k = nf; k < sc; k++) x *= 10;
    put_scaled(b, neg ? -x : x, sc);
    return 0;
}

static int canon_bool_text(sb *b, const char *s)
{
    if (!strcmp(s, "t") || !strcmp(s, "true") || !strcmp(s, "1")) sb_str(b, "1");
    else if (!strcmp(s, "f") || !strcmp(s, "false") || !strcmp(s, "0")) sb_str(b, "0");
    else return -1;
    return 0;
}

/* "YYYY-MM-DD[ HH:MM:SS[.f...]]" to microseconds */
static int canon_ts_text(sb *b, const char *s)
{
    int64_t y = 0, mo = 0, d = 0, h = 0, mi = 0, se = 0, us = 0;
    int n = 0;
    if (sscanf(s, "%4" SCNd64 "-%2" SCNd64 "-%2" SCNd64 "%n", &y, &mo, &d, &n) != 3) return -1;
    s += n;
    if (*s == ' ' || *s == 'T') {
        if (sscanf(s + 1, "%2" SCNd64 ":%2" SCNd64 ":%2" SCNd64 "%n", &h, &mi, &se, &n) != 3) return -1;
        s += 1 + n;
        if (*s == '.') {
            int k = 0;
            for (s++; *s >= '0' && *s <= '9'; s++, k++)
                if (k < 6) us = us * 10 + (*s - '0');
            for (; k < 6; k++) us *= 10;
        }
    }
    if (*s) return -1;
    sb_printf(b, "%" PRId64, (days_from_civil(y, (unsigned)mo, (unsigned)d) * 86400 + h * 3600 + mi * 60 + se) * 1000000 + us);
    return 0;
}

/* a cell from an engine's text (NULL: the null marker) */
static int canon_text(sb *b, int ty, const char *s, size_t len)
{
    if (!s) {
        sb_str(b, NULLMARK);
        return 0;
    }
    switch (TYT(ty)) {
    case CT_INT: return canon_int_text(b, s);
    case CT_DEC: return canon_dec_text(b, s, TYS(ty));
    case CT_FLT: {
        char *end;
        double f = strtod(s, &end);
        if (*end) return -1;
        canon_flt(b, f);
        return 0;
    }
    case CT_TXT: sb_put(b, s, len); return 0;
    case CT_BOOL: return canon_bool_text(b, s);
    case CT_TS: return canon_ts_text(b, s);
    }
    return -1;
}

/* ---- a result -------------------------------------------------------------------------------------------------------- */

typedef struct res {
    bool err;
    char msg[256];
    long long affected; /* -1: not reported */
    char **rows;
    size_t n, cap;
} res;

static void res_clear(res *r)
{
    for (size_t i = 0; i < r->n; i++) free(r->rows[i]);
    free(r->rows);
    memset(r, 0, sizeof *r);
    r->affected = -1;
}

static void res_row(res *r, const sb *row)
{
    if (r->n == r->cap) {
        r->cap = r->cap ? r->cap * 2 : 16;
        r->rows = realloc(r->rows, r->cap * sizeof *r->rows);
        if (!r->rows) exit(3);
    }
    r->rows[r->n++] = strdup(row->p ? row->p : "");
}

__attribute__((format(printf, 2, 3))) static void res_fail(res *r, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(r->msg, sizeof r->msg, fmt, ap);
    va_end(ap);
    r->err = true;
}

/* ---- the engines -------------------------------------------------------------------------------------------------------- */

typedef struct eng {
    int d;
    bool on;
    sqlite3 *lite;
    PGconn *pg;
    MYSQL *my;
    SQLHENV env;
    SQLHDBC dbc;
    imdb_db *idb;
    imdb_session ses;
    bool ses_open;
    char dir[600];
    long long statements;
} eng;

static eng g_eng[ND];
static char g_root[512] = "build/tmp/oracle";
static bool g_verbose;

/* the access paths imagedb answered by (its result names them): what the agreement covers */
typedef struct ptally {
    char path[96];
    long n;
} ptally;
static ptally g_paths[64];
static int g_npaths;

static void tally_path(const char *p)
{
    for (int i = 0; i < g_npaths; i++)
        if (!strcmp(g_paths[i].path, p)) {
            g_paths[i].n++;
            return;
        }
    if (g_npaths < (int)(sizeof g_paths / sizeof g_paths[0])) {
        snprintf(g_paths[g_npaths].path, sizeof g_paths[0].path, "%s", p);
        g_paths[g_npaths++].n = 1;
    }
}

/* P1 Q1: EXPLAIN's path (a join's plan) for a SELECT about to run, into out; false when EXPLAIN refused it */
static long g_explained, g_explain_bad;
static bool explain_path(eng *e, const char *sql, char *out, size_t cap)
{
    size_t n = strlen(sql);
    char *q = malloc(n + 9);
    out[0] = 0;
    if (!q) return false;
    memcpy(q, "EXPLAIN ", 8);
    memcpy(q + 8, sql, n + 1);
    imdb_result xr;
    imdb_result_init(&xr);
    imdb_err xe = {0};
    int rc = imdb_exec_one(&e->ses, q, n + 8, NULL, 0, &xr, &xe);
    free(q);
    if (rc) {
        imdb_result_free(&xr);
        return false;
    }
    for (uint64_t i = 0; xr.ncols == 2 && i < xr.nrows; i++) {
        const imdb_value *it = &xr.cells[2 * i].v, *d = &xr.cells[2 * i + 1].v;
        if (it->len == 4 && (!memcmp(it->s, "path", 4) || !memcmp(it->s, "plan", 4))) {
            size_t k = d->len < cap - 1 ? d->len : cap - 1;
            memcpy(out, d->s, k);
            out[k] = 0;
        }
    }
    imdb_result_free(&xr);
    return true;
}

static void exec_imdb(eng *e, const char *sql, bool rows, const int *ty, int nty, res *r)
{
    char xp[128];
    bool sel = rows && !strncasecmp(sql, "SELECT", 6), xok = sel && explain_path(e, sql, xp, sizeof xp);
    imdb_result ir;
    imdb_result_init(&ir);
    imdb_err er = {0};
    if (imdb_exec_one(&e->ses, sql, strlen(sql), NULL, 0, &ir, &er)) {
        res_fail(r, "%s", er.msg);
        imdb_result_free(&ir);
        return;
    }
    if (!rows) {
        unsigned long long n = 0;
        if (sscanf(ir.status, "%*s %llu", &n) == 1) r->affected = (long long)n;
        imdb_result_free(&ir);
        return;
    }
    if (sel) { /* P1 Q1: what EXPLAIN said is what ran (the text before " = ": cross_check is on) */
        g_explained++;
        const char *eq = strstr(ir.path, " = ");
        size_t pn = eq ? (size_t)(eq - ir.path) : strlen(ir.path);
        if (!xok || strlen(xp) != pn || memcmp(xp, ir.path, pn) != 0) {
            g_explain_bad++;
            printf("EXPLAIN MISMATCH: %s\n  EXPLAIN %s '%s', the run '%s'\n", sql, xok ? "said" : "refused it:", xp, ir.path);
        }
    }
    tally_path(ir.path);
    if (ir.ncols != nty) res_fail(r, "imagedb answered %u columns, %d expected", ir.ncols, nty);
    sb row = {0};
    for (uint64_t i = 0; !r->err && i < ir.nrows; i++) {
        sb_reset(&row);
        for (int c = 0; c < nty; c++) {
            const imdb_cell *cl = &ir.cells[i * ir.ncols + (uint64_t)c];
            if (cl->null || cl->v.null) sb_str(&row, NULLMARK);
            else switch (TYT(ty[c])) {
                case CT_INT:
                    if (cl->wide) {
                        char dig[48];
                        int n = 0;
                        __int128 x = cl->i128;
                        bool neg = x < 0;
                        unsigned __int128 a = neg ? -(unsigned __int128)x : (unsigned __int128)x;
                        do {
                            dig[n++] = (char)('0' + (int)(a % 10));
                            a /= 10;
                        } while (a);
                        if (neg) sb_str(&row, "-");
                        while (n) sb_put(&row, &dig[--n], 1);
                    } else sb_printf(&row, "%" PRId64, cl->v.i);
                    break;
                case CT_DEC:
                    /* at the cell's own scale: another than the expected shows as another row */
                    put_scaled(&row, cl->wide ? cl->i128 : (__int128)cl->v.i, cl->v.scale);
                    break;
                case CT_FLT: canon_flt(&row, imdb_f64_value(cl->v.i)); break;
                case CT_TXT: sb_put(&row, (const char *)cl->v.s, cl->v.len); break;
                case CT_BOOL:
                case CT_TS: sb_printf(&row, "%" PRId64, cl->v.i); break;
                }
            sb_str(&row, "\x1f");
        }
        res_row(r, &row);
    }
    free(row.p);
    imdb_result_free(&ir);
}

static void exec_lite(eng *e, const char *sql, bool rows, const int *ty, int nty, res *r)
{
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(e->lite, sql, -1, &st, NULL) != SQLITE_OK) {
        res_fail(r, "%s", sqlite3_errmsg(e->lite));
        return;
    }
    if (rows && sqlite3_column_count(st) != nty) res_fail(r, "sqlite answered %d columns", sqlite3_column_count(st));
    sb row = {0};
    int rc;
    while (!r->err && (rc = sqlite3_step(st)) == SQLITE_ROW) {
        sb_reset(&row);
        for (int c = 0; c < nty; c++) {
            if (sqlite3_column_type(st, c) == SQLITE_NULL) sb_str(&row, NULLMARK);
            else switch (TYT(ty[c])) {
                case CT_DEC: put_scaled(&row, sqlite3_column_int64(st, c), 2); break; /* d itself: DECIMAL trees skip SQLite */
                case CT_FLT: canon_flt(&row, sqlite3_column_double(st, c)); break;
                case CT_TXT: sb_put(&row, (const char *)sqlite3_column_text(st, c), (size_t)sqlite3_column_bytes(st, c)); break;
                default: sb_printf(&row, "%" PRId64, (int64_t)sqlite3_column_int64(st, c)); break;
                }
            sb_str(&row, "\x1f");
        }
        res_row(r, &row);
    }
    if (!r->err && rc != SQLITE_DONE) res_fail(r, "%s", sqlite3_errmsg(e->lite));
    if (!r->err && !rows) r->affected = sqlite3_changes(e->lite);
    free(row.p);
    sqlite3_finalize(st);
}

static void row_from_texts(res *r, sb *row, const int *ty, int nty, const char *const *v, const unsigned long *len)
{
    sb_reset(row);
    for (int c = 0; c < nty; c++) {
        if (canon_text(row, ty[c], v[c], v[c] ? len[c] : 0)) {
            res_fail(r, "an answer this oracle cannot read in column %d: \"%.40s\"", c + 1, v[c]);
            return;
        }
        sb_str(row, "\x1f");
    }
    res_row(r, row);
}

static void exec_pg(eng *e, const char *sql, bool rows, const int *ty, int nty, res *r)
{
    PGresult *pr = PQexec(e->pg, sql);
    ExecStatusType st = PQresultStatus(pr);
    if (st == PGRES_TUPLES_OK) {
        if (PQnfields(pr) != nty) res_fail(r, "pg answered %d columns", PQnfields(pr));
        sb row = {0};
        for (int i = 0; !r->err && i < PQntuples(pr); i++) {
            const char *v[MAXC + 8];
            unsigned long len[MAXC + 8];
            for (int c = 0; c < nty; c++) {
                v[c] = PQgetisnull(pr, i, c) ? NULL : PQgetvalue(pr, i, c);
                len[c] = (unsigned long)PQgetlength(pr, i, c);
            }
            row_from_texts(r, &row, ty, nty, v, len);
        }
        free(row.p);
    } else if (st == PGRES_COMMAND_OK) {
        const char *n = PQcmdTuples(pr);
        if (*n) r->affected = atoll(n);
    } else res_fail(r, "%s", PQresultErrorMessage(pr));
    PQclear(pr);
}

static void exec_my(eng *e, const char *sql, bool rows, const int *ty, int nty, res *r)
{
    if (mysql_real_query(e->my, sql, strlen(sql))) {
        res_fail(r, "%s", mysql_error(e->my));
        return;
    }
    MYSQL_RES *mr = mysql_store_result(e->my);
    if (!mr) {
        if (mysql_field_count(e->my)) res_fail(r, "%s", mysql_error(e->my));
        else if (!rows) r->affected = (long long)mysql_affected_rows(e->my);
        return;
    }
    if ((int)mysql_num_fields(mr) != nty) res_fail(r, "mysql answered %u columns", mysql_num_fields(mr));
    sb row = {0};
    MYSQL_ROW mrow;
    while (!r->err && (mrow = mysql_fetch_row(mr))) {
        unsigned long *len = mysql_fetch_lengths(mr);
        char *v[MAXC + 8];
        sb cells[MAXC + 8];
        memset(cells, 0, sizeof cells);
        for (int c = 0; c < nty; c++) { /* the text protocol's values are not terminated: copied, terminated */
            if (!mrow[c]) {
                v[c] = NULL;
                continue;
            }
            sb_put(&cells[c], mrow[c], len[c]);
            v[c] = cells[c].p;
        }
        row_from_texts(r, &row, ty, nty, (const char *const *)v, len);
        for (int c = 0; c < nty; c++) free(cells[c].p);
    }
    free(row.p);
    mysql_free_result(mr);
}

static void odbc_err(SQLSMALLINT kind, SQLHANDLE h, char *out, size_t cap)
{
    SQLCHAR state[8], msg[512];
    SQLINTEGER native;
    SQLSMALLINT len;
    out[0] = 0;
    if (SQL_SUCCEEDED(SQLGetDiagRec(kind, h, 1, state, &native, msg, sizeof msg, &len)))
        snprintf(out, cap, "%.5s %.200s", (char *)state, (char *)msg);
}

/* The statement as UTF-16 for SQLExecDirectW: unixODBC's narrow call converts its text as Latin-1, which stored each
 * byte of a multibyte character as a character of its own (found on its first run). The input is valid UTF-8. */
static SQLWCHAR *utf16(const char *s)
{
    size_t n = strlen(s), k = 0;
    SQLWCHAR *w = malloc((n + 1) * sizeof *w);
    if (!w) exit(3);
    for (const unsigned char *p = (const unsigned char *)s; *p;) {
        uint32_t c;
        int len = *p < 0x80 ? 1 : (*p & 0xE0) == 0xC0 ? 2 : (*p & 0xF0) == 0xE0 ? 3 : 4;
        c = len == 1 ? *p : len == 2 ? *p & 0x1Fu : len == 3 ? *p & 0x0Fu : *p & 0x07u;
        for (int i = 1; i < len; i++) c = c << 6 | (p[i] & 0x3Fu);
        p += len;
        if (c >= 0x10000) {
            c -= 0x10000;
            w[k++] = (SQLWCHAR)(0xD800 + (c >> 10));
            w[k++] = (SQLWCHAR)(0xDC00 + (c & 0x3FF));
        } else w[k++] = (SQLWCHAR)c;
    }
    w[k] = 0;
    return w;
}

static void exec_ms(eng *e, const char *sql, bool rows, const int *ty, int nty, res *r)
{
    SQLHSTMT h;
    if (!SQL_SUCCEEDED(SQLAllocHandle(SQL_HANDLE_STMT, e->dbc, &h))) {
        res_fail(r, "mssql: no statement handle");
        return;
    }
    SQLWCHAR *w = utf16(sql);
    SQLRETURN rc = SQLExecDirectW(h, w, SQL_NTS);
    free(w);
    if (!SQL_SUCCEEDED(rc) && rc != SQL_NO_DATA) {
        odbc_err(SQL_HANDLE_STMT, h, r->msg, sizeof r->msg);
        r->err = true;
        SQLFreeHandle(SQL_HANDLE_STMT, h);
        return;
    }
    SQLSMALLINT nc = 0;
    SQLNumResultCols(h, &nc);
    if (nc > 0) {
        if (nc != nty) res_fail(r, "mssql answered %d columns", nc);
        sb row = {0};
        while (!r->err && SQL_SUCCEEDED(rc = SQLFetch(h))) {
            sb_reset(&row);
            for (int c = 0; c < nty && !r->err; c++) {
                SQLLEN ind = 0;
                if (TYT(ty[c]) == CT_FLT) {
                    double dv = 0;
                    SQLGetData(h, (SQLUSMALLINT)(c + 1), SQL_C_DOUBLE, &dv, sizeof dv, &ind);
                    if (ind == SQL_NULL_DATA) sb_str(&row, NULLMARK);
                    else canon_flt(&row, dv);
                } else {
                    char buf[1024];
                    SQLGetData(h, (SQLUSMALLINT)(c + 1), SQL_C_CHAR, buf, sizeof buf, &ind);
                    if (ind != SQL_NULL_DATA && canon_text(&row, ty[c], buf, (size_t)ind))
                        res_fail(r, "an answer this oracle cannot read in column %d: \"%.40s\"", c + 1, buf);
                    if (ind == SQL_NULL_DATA) sb_str(&row, NULLMARK);
                }
                sb_str(&row, "\x1f");
            }
            if (!r->err) res_row(r, &row);
        }
        if (!r->err && rc != SQL_NO_DATA) { /* an error that came with a row (an overflow): the rows before it are not
                                                * the answer */
            odbc_err(SQL_HANDLE_STMT, h, r->msg, sizeof r->msg);
            r->err = true;
        }
        free(row.p);
    } else if (!rows) {
        SQLLEN n = -1;
        if (SQL_SUCCEEDED(SQLRowCount(h, &n)) && n >= 0) r->affected = n;
    }
    SQLFreeHandle(SQL_HANDLE_STMT, h);
}

static void exec_eng(eng *e, const char *sql, bool rows, const int *ty, int nty, res *r)
{
    res_clear(r);
    e->statements++;
    switch (e->d) {
    case D_IMDB: exec_imdb(e, sql, rows, ty, nty, r); break;
    case D_SQLITE: exec_lite(e, sql, rows, ty, nty, r); break;
    case D_PG: exec_pg(e, sql, rows, ty, nty, r); break;
    case D_MY:
    case D_MA: exec_my(e, sql, rows, ty, nty, r); break;
    case D_MS: exec_ms(e, sql, rows, ty, nty, r); break;
    }
}

/* setup statements whose failure stops the run */
static void must(eng *e, const char *sql)
{
    res r = {0};
    r.affected = -1;
    exec_eng(e, sql, false, NULL, 0, &r);
    if (r.err) {
        fprintf(stderr, "oracle: %s: %s: %s\n", DNAME[e->d], sql, r.msg);
        exit(2);
    }
    res_clear(&r);
}

static int rm_entry(const char *path, const struct stat *st, int flag, struct FTW *ftw)
{
    (void)st;
    (void)flag;
    (void)ftw;
    return remove(path);
}

static void quiet(void *arg, const char *msg)
{
    (void)arg;
    (void)msg;
}

static void connect_all(void)
{
    for (int d = 0; d < ND; d++) {
        eng *e = &g_eng[d];
        if (!e->on) continue;
        e->d = d;
        if (d == D_PG) {
            const char *ci = getenv("ORACLE_PG");
            if (!ci || !(e->pg = PQconnectdb(ci)) || PQstatus(e->pg) != CONNECTION_OK) {
                fprintf(stderr, "oracle: pg: %s\n", ci ? PQerrorMessage(e->pg) : "ORACLE_PG is not set");
                exit(2);
            }
            PQsetNoticeProcessor(e->pg, quiet, NULL); /* "does not exist, skipping" and the like */
            must(e, "SET extra_float_digits = 3"); /* doubles in text, exact */
        } else if (d == D_MY || d == D_MA) {
            const char *ci = getenv(d == D_MY ? "ORACLE_MYSQL" : "ORACLE_MARIADB");
            char sock[400] = "", user[64] = "", pass[64] = "", db[64] = "";
            if (!ci || sscanf(ci, "%399s %63s %63s %63s", sock, user, pass, db) < 4) {
                fprintf(stderr, "oracle: %s: \"socket user password database\" not set\n", DNAME[d]);
                exit(2);
            }
            e->my = mysql_init(NULL);
            mysql_options(e->my, MYSQL_SET_CHARSET_NAME, "utf8mb4");
            if (!mysql_real_connect(e->my, NULL, user, strcmp(pass, "-") ? pass : "", db, 0, sock, CLIENT_FOUND_ROWS)) {
                fprintf(stderr, "oracle: %s: %s\n", DNAME[d], mysql_error(e->my));
                exit(2);
            }
            /* literals in the columns' binary collation: MariaDB 12.3.3 judges a BETWEEN's ends under the connection's
             * collation (uca1400_ai_ci by default), and over an index on s took BETWEEN 'Z' AND 'z' for = 'Z' (one row
             * of eight; found by this oracle, 2026-11-04, reproduced alone: wrong only through the index, 8 rows with
             * IGNORE INDEX or as >= AND <=) */
            must(e, d == D_MY ? "SET NAMES utf8mb4 COLLATE utf8mb4_0900_bin" : "SET NAMES utf8mb4 COLLATE utf8mb4_nopad_bin");
            must(e, "SET SESSION sql_mode = 'STRICT_ALL_TABLES,NO_ZERO_DATE,NO_ZERO_IN_DATE,ERROR_FOR_DIVISION_BY_ZERO,"
                    "ONLY_FULL_GROUP_BY,NO_ENGINE_SUBSTITUTION'");
            must(e, "SET SESSION div_precision_increment = 30"); /* a DECIMAL quotient far past imagedb's scale */
        } else if (d == D_MS) {
            const char *ci = getenv("ORACLE_ODBC");
            SQLCHAR out[1024];
            SQLSMALLINT ol;
            if (!ci || !SQL_SUCCEEDED(SQLAllocHandle(SQL_HANDLE_ENV, SQL_NULL_HANDLE, &e->env)) ||
                !SQL_SUCCEEDED(SQLSetEnvAttr(e->env, SQL_ATTR_ODBC_VERSION, (void *)SQL_OV_ODBC3, 0)) ||
                !SQL_SUCCEEDED(SQLAllocHandle(SQL_HANDLE_DBC, e->env, &e->dbc)) ||
                !SQL_SUCCEEDED(SQLDriverConnect(e->dbc, NULL, (SQLCHAR *)(uintptr_t)ci, SQL_NTS, out, sizeof out, &ol,
                                                SQL_DRIVER_NOPROMPT))) {
                char m[256] = "ORACLE_ODBC is not set";
                if (ci && e->dbc) odbc_err(SQL_HANDLE_DBC, e->dbc, m, sizeof m);
                fprintf(stderr, "oracle: mssql: %s\n", m);
                exit(2);
            }
            must(e, "IF DB_ID('oracle') IS NULL CREATE DATABASE oracle COLLATE Latin1_General_100_BIN2_UTF8");
            must(e, "USE oracle");
            must(e, "SET ANSI_NULLS ON; SET ANSI_WARNINGS ON; SET ARITHABORT ON; SET XACT_ABORT OFF");
        }
    }
}

/* fresh tables in every engine for a seed: imagedb a new directory, SQLite a new in-memory database, the servers
 * their tables dropped and made again */
static void imdb_down(eng *e)
{
    if (e->ses_open) imdb_session_close(&e->ses), e->ses_open = false;
    if (e->idb && imdb_close(e->idb)) {
        fprintf(stderr, "oracle: imagedb: %s: the close failed\n", e->dir);
        exit(2);
    }
    e->idb = NULL;
}

/* imagedb's directory opened (made first when fresh), its session up with cross_check on: every query answered by a
 * second plan too, a disagreement failing it */
static void imdb_up(eng *e, bool fresh)
{
    imdb_err er = {0};
    imdb_open_opts o;
    memset(&o, 0, sizeof o);
    o.sync = 0;
    if ((fresh && imdb_init(e->dir, false, NULL, &er)) || imdb_open(e->dir, &o, &e->idb, &er)) {
        fprintf(stderr, "oracle: imagedb: %s: %s\n", e->dir, er.msg);
        exit(2);
    }
    imdb_session_init(&e->ses, e->idb);
    e->ses_open = true;
    must(e, "SET cross_check = on");
}

static void reset_all(unsigned seed)
{
    for (int d = 0; d < ND; d++) {
        eng *e = &g_eng[d];
        if (!e->on) continue;
        if (d == D_IMDB) {
            imdb_down(e);
            if (e->dir[0]) nftw(e->dir, rm_entry, 16, FTW_DEPTH | FTW_PHYS);
            snprintf(e->dir, sizeof e->dir, "%s/imagedb-%u", g_root, seed);
            nftw(e->dir, rm_entry, 16, FTW_DEPTH | FTW_PHYS);
            imdb_up(e, true);
        } else if (d == D_SQLITE) {
            if (e->lite) sqlite3_close(e->lite);
            if (sqlite3_open(":memory:", &e->lite) != SQLITE_OK) exit(2);
            must(e, "PRAGMA case_sensitive_like = ON"); /* P2 S1: LIKE as the others compare it (binary collations) */
        } else {
            /* a seed stopped by a mismatch (--keep-going) may have left a transaction open, or aborted (PostgreSQL) */
            res rb;
            memset(&rb, 0, sizeof rb);
            exec_eng(e, d == D_MS ? "IF @@TRANCOUNT > 0 ROLLBACK TRANSACTION" : "ROLLBACK", false, NULL, 0, &rb);
            res_clear(&rb);
            if (d == D_MS) {
                must(e, "DROP TABLE IF EXISTS u; DROP TABLE IF EXISTS t");
            } else {
                must(e, "DROP TABLE IF EXISTS u");
                must(e, "DROP TABLE IF EXISTS t");
            }
        }
        must(e, ddl(d, 0));
        must(e, ddl(d, 1));
        /* indexes: on imagedb the ordered paths and the index-only aggregates answer through them */
        static const char *const IDX[] = {"CREATE INDEX t_ga ON t (g, a)", "CREATE INDEX t_s ON t (s)",
                                          "CREATE INDEX t_ts ON t (ts)", "CREATE INDEX u_tid ON u (tid)"};
        for (size_t i = 0; i < sizeof IDX / sizeof IDX[0]; i++) must(e, IDX[i]);
    }
}

/* ---- comparing --------------------------------------------------------------------------------------------------------- */

static int cmp_rows(const void *a, const void *b) { return strcmp(*(char *const *)a, *(char *const *)b); }

static long g_mismatches, g_compared, g_checkpoints, g_reopens, g_drops;
static long g_fn_compared; /* P2 S1: comparisons of statements holding its forms */
static long g_grp_compared; /* P2 S2: comparisons of its grouped form */
static long g_jn_compared; /* P2 S3: comparisons of its join forms */
static long g_subq_compared; /* P2 S4: comparisons of statements with a subquery, a derived table or a CTE */
static long g_corr_compared; /* P2 S4b: comparisons of statements with a correlated subquery */
static long g_set_compared, g_rec_compared; /* P2 S5: comparisons of set operations, of WITH RECURSIVE */
static long g_win_compared; /* P2 S6: comparisons of window functions */

static void show_rows(const res *r, size_t from)
{
    for (size_t i = from; i < r->n && i < from + 5; i++) {
        fprintf(stderr, "      ");
        for (const char *p = r->rows[i]; *p; p++) fputc(*p == '\x1f' ? '|' : *p, stderr);
        fputc('\n', stderr);
    }
    if (r->n > from + 5) fprintf(stderr, "      ... (%zu rows)\n", r->n);
}

/* one statement on every engine; 0 when every answer is imagedb's */
/* After a mismatch on a filtered SELECT: COUNT(*) under each predicate alone, then under all of them, on imagedb and
 * on the engine that disagreed: which condition the two read differently. */
static void diagnose(const stmt *q, int d)
{
    if (q->kind != Q_SELECT || !q->npr || (q->join == 4 && d == D_SQLITE) || q->dsel || q->win) return; /* FULL: two counts; a
                                                                                             * derived table: its own FROM */
    stmt c;
    sb text = {0};
    res a = {0}, b = {0};
    int ty[1] = {CT_INT};
    for (int i = 0; i <= q->npr; i++) {
        memset(&c, 0, sizeof c);
        c.kind = Q_SELECT;
        c.tab = q->tab;
        c.join = q->join;
        c.jx = q->jx;
        c.jkey2 = q->jkey2;
        c.jusing = q->jusing;
        memcpy(c.xe, q->xe, sizeof q->xe); /* the conditions' trees */
        c.nxe = q->nxe;
        memcpy(c.xp, q->xp, sizeof q->xp);
        c.nxp = q->nxp;
        c.skip = q->skip;
        c.gcol = -1;
        c.it[c.nit++] = (item){F_COUNT_STAR, 0, 0, 0};
        if (i < q->npr) c.pr[c.npr++] = q->pr[i];
        else {
            memcpy(c.pr, q->pr, sizeof q->pr);
            c.npr = q->npr;
        }
        print_stmt(&text, D_IMDB, &c);
        exec_eng(&g_eng[D_IMDB], text.p, true, ty, 1, &a);
        print_stmt(&text, d, &c);
        exec_eng(&g_eng[d], text.p, true, ty, 1, &b);
        fprintf(stderr, "  diagnosis: %s -> imagedb %s, %s %s\n", text.p, a.err ? a.msg : a.n ? a.rows[0] : "?",
                DNAME[d], b.err ? b.msg : b.n ? b.rows[0] : "?");
    }
    res_clear(&a);
    res_clear(&b);
    free(text.p);
}

/* imagedb refused what engine d answered, as d's dialect does (counted, not a mismatch): a zero divisor is NULL in
 * MySQL and MariaDB (a SELECT's; strict mode errs only in a write) and SQLite; SQLite turns an INT64 overflow
 * into a REAL */
static long g_excused;
static long g_class_diff; /* both refused, one for a zero divisor and one for an overflow */

/* an error's class: 1 a zero divisor, 2 an overflow, 0 another (each engine's words) */
static int err_class(const char *msg)
{
    if (strstr(msg, "division by zero") || strstr(msg, "Divide by zero")) return 1;
    if (strstr(msg, "overflow") || strstr(msg, "out of range") || strstr(msg, "38 digits")) return 2;
    return 0;
}
static bool excused(int d, const char *msg, const char *text)
{
    if (strstr(msg, "division by zero")) return d == D_SQLITE || d == D_MY || d == D_MA;
    /* MariaDB 12.3.3 wraps 0 - x for x = INT64_MIN to INT64_MIN, silently (-x, 1 - x, x - 1, -1 * x and x DIV -1 it
     * refuses as overflows; reproduced alone, 2026-11-05, seed 6 of that day's five-engine run: AVG((0 - x))). An
     * INT64 overflow imagedb wrongly raised would still be caught: PostgreSQL is compared first */
    if (strstr(msg, "INT64 overflow") && d == D_MA && strstr(text, "(0 - ")) return true;
    if (strstr(msg, "INT64 overflow")) return d == D_SQLITE;
    /* imagedb never turns an INT64 past 2^53 into a FLOAT64 (design.md, Expressions); the others round it silently */
    if (strstr(msg, "beyond 2^53")) return true;
    return false;
}

/* SQL Server named an ORDER BY item a constant (its folding: g_ms_drop): left out, the statement printed and run again,
 * once for each it names. Its compile error leaves a transaction as it was (XACT_ABORT OFF) */
static void ms_drop_constants(const stmt *q, sb *t, bool rows, const int *ty, int nty, res *r)
{
    static const char K[] = "A constant expression was encountered in the ORDER BY list, position ";
    for (int tries = 0; tries < 16 && r->err; tries++) {
        const char *p = strstr(r->msg, K);
        int pos = p ? atoi(p + sizeof K - 1) : 0;
        if (pos < 1 || pos > g_ms_nat || g_ms_at[pos - 1] >= 64) break;
        g_ms_drop |= 1ull << g_ms_at[pos - 1];
        g_ms_dropped++;
        print_stmt(t, D_MS, q);
        exec_eng(&g_eng[D_MS], t->p, rows, ty, nty, r);
    }
    g_ms_drop = 0;
}

/* imagedb refused, under HAVING, LIMIT or OFFSET, what engine d answered: imagedb computes every group's aggregates
 * before HAVING and every group's and row's items before the window (design.md, Expressions: whether an operation fails
 * never depends on the plan), while a reference streaming sorted groups may stop at its LIMIT before the failing one
 * (PostgreSQL, seed 5 of the 2026-11-05 run: SUM(-d) / AVG(g * -11) over GROUP BY g with g = 0 past the window), and
 * PostgreSQL moves a HAVING condition on the keys alone into WHERE, so it never aggregates a group the condition drops
 * (seed 23 of S6's five-engine run, 2026-11-05: MAX(514005 / x) ... HAVING g > 6). Excused only when d, asked the same
 * statement without HAVING, LIMIT and OFFSET, refuses it for the same class of reason, so the claim is checked every
 * time; never inside a transaction, where a failed statement would abort PostgreSQL's */
static long g_excused_window;
static bool excused_window(int d, const stmt *q, const char *base_msg)
{
    if (!(q->limit || q->offset || q->hv) || g_in_txn || !err_class(base_msg)) return false;
    stmt q2 = *q;
    q2.limit = 0;
    q2.offset = 0;
    q2.hv = 0;
    static sb t2;
    static res o2;
    int ty[MAXC + 8];
    int nty = out_types(&q2, ty);
    print_stmt(&t2, d, &q2);
    exec_eng(&g_eng[d], t2.p, true, ty, nty, &o2);
    if (d == D_MS) ms_drop_constants(&q2, &t2, true, ty, nty, &o2);
    bool same = o2.err && err_class(o2.msg) == err_class(base_msg);
    res_clear(&o2);
    if (same) g_excused_window++;
    return same;
}

/* the reverse: engine d refused what imagedb answered, as d does wrongly. MySQL 8.4.13 refuses INT64_MIN DIV n though the
 * quotient is an INT64 ("BIGINT value is out of range"; MariaDB 12.3.3 answers it; reproduced alone, 2026-11-04);
 * an INT64_MIN DIV -1 that imagedb wrongly answered would still be caught: PostgreSQL is compared first */
static bool excused_other(int d, const char *msg, const char *text)
{
    if (d == D_MY) return strstr(msg, "BIGINT value is out of range") && strstr(msg, " DIV ");
    /* SQL Server refuses INT64_MIN % -1 ("Arithmetic overflow"), which is 0 (PostgreSQL, MySQL, imagedb) */
    return d == D_MS && strstr(msg, "Arithmetic overflow error converting expression to data type bigint") &&
           strstr(text, "% CAST(-1 AS BIGINT)");
}

static int run_stmt(unsigned seed, int step, const stmt *q, bool state)
{
    static sb text[ND];
    static res out[ND];
    int ty[MAXC + 8], nty = 0;
    bool rows = q->kind == Q_SELECT;
    if (rows) nty = out_types(q, ty);
    bool ordered = rows && (q->limit || q->nord || q->offset); /* a total order (1d): compared row by row */
    for (int d = 0; d < ND; d++) {
        if (!g_eng[d].on || (q->skip & (1u << d))) continue; /* not put to it: its dialect computes it otherwise */
        print_stmt(&text[d], d, q);
        exec_eng(&g_eng[d], text[d].p, rows, ty, nty, &out[d]);
        if (d == D_MS) ms_drop_constants(q, &text[d], rows, ty, nty, &out[d]);
        if (rows && !ordered && !out[d].err) qsort(out[d].rows, out[d].n, sizeof *out[d].rows, cmp_rows);
    }
    if (g_verbose) fprintf(stderr, "  [%u.%d] %s\n", seed, step, text[D_IMDB].p);
    const res *base = &out[D_IMDB];
    for (int d = 1; d < ND; d++) {
        if (!g_eng[d].on || (q->skip & (1u << d))) continue;
        g_compared++;
        if (q->fns) g_fn_compared++;
        if (q->grp) g_grp_compared++;
        if (q->jn3) g_jn_compared++;
        if (q->subq) g_subq_compared++;
        if (q->corr) g_corr_compared++;
        if (q->narm) g_set_compared++;
        if (q->rec) g_rec_compared++;
        if (q->win) g_win_compared++;
        const res *o = &out[d];
        const char *why = NULL;
        size_t at = 0;
        if ((base->err && !o->err && (excused(d, base->msg, text[d].p) || excused_window(d, q, base->msg))) ||
            (!base->err && o->err && excused_other(d, o->msg, text[d].p))) {
            g_excused++;
            if (g_verbose) fprintf(stderr, "  excused (%s): %s\n    imagedb: %s\n    %s: %s\n", DNAME[d], text[d].p,
                                   base->err ? base->msg : "answered", DNAME[d], o->err ? o->msg : "answered");
            continue;
        }
        if (base->err && strstr(base->msg, "syntax error")) /* P2 S3: the generator's fault, never an agreement (two
                                                          * refusals of a broken statement hid every join once) */
            why = "imagedb refused it as a syntax error: the oracle wrote it wrong";
        if (base->err && o->err) { /* both refused: for one reason? Rows are computed in other orders, so a
                                  * statement with two ways to fail may meet another first: counted, not failed */
            int cb = err_class(base->msg), co = err_class(o->msg);
            if (cb && co && cb != co) {
                g_class_diff++;
                if (g_verbose) fprintf(stderr, "  both refused, for other reasons (%s): %s | %s\n", DNAME[d], base->msg, o->msg);
            }
        }
        if (why) { /* the syntax error above: reported as it is */
        } else if (base->err != o->err) {
            why = base->err ? "imagedb refused it, the other answered" : "imagedb answered, the other refused it";
        }
        else if (!base->err && !rows && base->affected >= 0 && o->affected >= 0 && base->affected != o->affected)
            why = "another count of rows changed";
        else if (!base->err && rows) {
            if (base->n != o->n) why = "another number of rows";
            for (at = 0; !why && at < base->n; at++)
                if (strcmp(base->rows[at], o->rows[at])) why = "another row";
            if (why && at) at--;
        }
        if (!why) continue;
        g_mismatches++;
        fprintf(stderr, "MISMATCH seed %u step %d%s, imagedb against %s: %s\n", seed, step, state ? " (a table's state)" : "",
                DNAME[d], why);
        fprintf(stderr, "  imagedb: %s\n", text[D_IMDB].p);
        fprintf(stderr, "  %s: %s\n", DNAME[d], text[d].p);
        fprintf(stderr, "  imagedb: %s (%zu rows, %lld changed)\n", base->err ? base->msg : "ok", base->n, base->affected);
        if (!base->err) show_rows(base, at);
        fprintf(stderr, "  %s: %s (%zu rows, %lld changed)\n", DNAME[d], o->err ? o->msg : "ok", o->n, o->affected);
        if (!o->err) show_rows(o, at);
        if (!state) diagnose(q, d);
        return -1;
    }
    return 0;
}

static int check_state(unsigned seed, int step)
{
    for (int tab = 0; tab < 2; tab++) {
        stmt q;
        memset(&q, 0, sizeof q);
        q.kind = Q_SELECT;
        q.tab = tab;
        q.star = true;
        q.gcol = -1;
        if (run_stmt(seed, step, &q, true)) return -1;
    }
    return 0;
}

/* ---- the driver ---------------------------------------------------------------------------------------------------- */

/* DROP TABLE (P0 1f) against the references: between statements (no transaction open), u dropped on every engine,
 * made again by its dialect's DDL with its index, and refilled; what follows reads the new u (on imagedb the name
 * resolves to the table live at the read's snapshot, the dropped one kept as history), compared like any table */
static int drop_u_again(unsigned seed, int *step)
{
    for (int d = 0; d < ND; d++) {
        eng *e = &g_eng[d];
        if (!e->on) continue;
        must(e, "DROP TABLE u");
        must(e, ddl(d, 1));
        must(e, "CREATE INDEX u_tid ON u (tid)");
    }
    g_drops++;
    if (g_verbose) fprintf(stderr, "  [%u.%d] (DROP TABLE u on every engine, made again)\n", seed, *step);
    if (check_state(seed, *step)) return -1;
    stmt q;
    int n = (int)rr(5, 30);
    for (int i = 0; i < n; i += 8) {
        memset(&q, 0, sizeof q);
        q.kind = Q_INSERT;
        q.tab = 1;
        q.gcol = -1;
        q.nrow = n - i < 8 ? n - i : 8;
        for (int r = 0; r < q.nrow; r++) gen_row(1, q.row[r]);
        if (run_stmt(seed, (*step)++, &q, false)) return -1;
    }
    return check_state(seed, *step);
}

static int run_seed(unsigned seed, int steps)
{
    g_rng = 0x9E3779B97F4A7C15ull ^ ((uint64_t)seed * 0xBF58476D1CE4E5B9ull);
    if (!g_rng) g_rng = 1;
    g_next_id = 1;
    g_ntids = 0;
    memset(g_nsamp, 0, sizeof g_nsamp);
    reset_all(seed);
    stmt q;
    int step = 0;
    for (int tab = 0; tab < 2; tab++) { /* the first rows: t's, then u's children */
        int n = (int)rr(tab ? 10 : 20, tab ? 60 : 100);
        for (int i = 0; i < n; i += 8) {
            memset(&q, 0, sizeof q);
            q.kind = Q_INSERT;
            q.tab = tab;
            q.gcol = -1;
            q.nrow = n - i < 8 ? n - i : 8;
            for (int r = 0; r < q.nrow; r++) gen_row(tab, q.row[r]);
            if (run_stmt(seed, step++, &q, false)) return -1;
        }
    }
    if (check_state(seed, step)) return -1;
    for (int s = 0; s < steps; s++, step++) {
        if (chance(5)) { /* imagedb alone, between statements: its rows to the lake, or its directory reopened; the
                          * answers after it come from segments and a replayed log, and must not change */
            eng *e = &g_eng[D_IMDB];
            bool cp = chance(50);
            if (cp) must(e, "CHECKPOINT"), g_checkpoints++;
            else imdb_down(e), imdb_up(e, false), g_reopens++;
            if (g_verbose) fprintf(stderr, "  [%u.%d] (imagedb alone: %s)\n", seed, step, cp ? "CHECKPOINT" : "a reopen");
            if (check_state(seed, step)) return -1;
        }
        if (chance(2) && drop_u_again(seed, &step)) return -1; /* about one step in fifty */
        int r = (int)(rnd() % 100);
        if (r < 70) {
            gen_select(&q);
            if (run_stmt(seed, step, &q, false)) return -1;
        } else if (r < 90) { /* a statement on its own: it may fail (an existing key), alike everywhere */
            gen_dml(&q, true);
            if (run_stmt(seed, step, &q, false) || check_state(seed, step)) return -1;
        } else { /* a transaction: changes read back inside it, then committed or rolled back */
            memset(&q, 0, sizeof q);
            q.kind = Q_BEGIN;
            q.gcol = -1;
            if (run_stmt(seed, step, &q, false)) return -1;
            int k = (int)rr(1, 3);
            for (int i = 0; i < k; i++) {
                gen_dml(&q, false); /* none that fails: PostgreSQL aborts a transaction at its first error */
                if (run_stmt(seed, step, &q, false)) return -1;
                g_in_txn = true; /* a SELECT here must not fail either */
                gen_select(&q);
                g_in_txn = false;
                if (run_stmt(seed, step, &q, false)) return -1;
            }
            memset(&q, 0, sizeof q);
            q.kind = chance(50) ? Q_COMMIT : Q_ROLLBACK;
            q.gcol = -1;
            if (run_stmt(seed, step, &q, false) || check_state(seed, step)) return -1;
        }
    }
    return 0;
}

int main(int argc, char **argv)
{
    setlocale(LC_ALL, "C.UTF-8"); /* the ODBC driver's client code page: UTF-8 */
    unsigned lo = 1, hi = 20;
    int steps = 80;
    bool keep_going = false, ping = false;
    const char *engines = "imagedb,sqlite";
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--engines") && i + 1 < argc) engines = argv[++i];
        else if (!strcmp(argv[i], "--seeds") && i + 1 < argc) {
            if (sscanf(argv[++i], "%u-%u", &lo, &hi) != 2) hi = lo = (unsigned)atoi(argv[i]);
        } else if (!strcmp(argv[i], "--steps") && i + 1 < argc) steps = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--dir") && i + 1 < argc) snprintf(g_root, sizeof g_root, "%s", argv[++i]);
        else if (!strcmp(argv[i], "--keep-going")) keep_going = true;
        else if (!strcmp(argv[i], "--no-expr")) g_expr = false;
        else if (!strcmp(argv[i], "--no-fns")) g_fns = false;
        else if (!strcmp(argv[i], "--ping")) ping = true; /* connect to every engine named, then stop (run.sh waits on it) */
        else if (!strcmp(argv[i], "-v")) g_verbose = true;
        else {
            fprintf(stderr, "usage: oracle [--engines LIST] [--seeds A-B] [--steps N] [--dir DIR] [--keep-going] [--no-expr] [--no-fns] [--ping] [-v]\n");
            return 2;
        }
    }
    char list[256];
    snprintf(list, sizeof list, "%s", engines);
    for (char *tok = strtok(list, ","); tok; tok = strtok(NULL, ",")) {
        int d = 0;
        while (d < ND && strcmp(DNAME[d], tok)) d++;
        if (d == ND) {
            fprintf(stderr, "oracle: no engine named %s\n", tok);
            return 2;
        }
        g_eng[d].on = true;
    }
    g_eng[D_IMDB].on = true; /* the engine under test */
    mkdir(g_root, 0755);
    connect_all();
    if (ping) return 0;
    unsigned failed = 0;
    for (unsigned s = lo; s <= hi; s++) {
        if (run_seed(s, steps)) {
            failed++;
            if (!keep_going) break;
        } else if (g_verbose) fprintf(stderr, "seed %u: agreed\n", s);
    }
    for (int d = 0; d < ND; d++) { /* imagedb's directory of the last seed is kept when it failed */
        eng *e = &g_eng[d];
        if (!e->on) continue;
        if (e->ses_open) imdb_session_close(&e->ses);
        if (e->idb) imdb_close(e->idb);
        if (d == D_IMDB && !failed && e->dir[0]) nftw(e->dir, rm_entry, 16, FTW_DEPTH | FTW_PHYS);
        if (e->lite) sqlite3_close(e->lite);
        if (e->pg) PQfinish(e->pg);
        if (e->my) mysql_close(e->my);
        if (e->dbc) SQLDisconnect(e->dbc), SQLFreeHandle(SQL_HANDLE_DBC, e->dbc);
        if (e->env) SQLFreeHandle(SQL_HANDLE_ENV, e->env);
    }
    g_mismatches += g_explain_bad; /* P1 Q1: an EXPLAIN that disagrees with its run is a mismatch */
    printf("oracle: seeds %u-%u, %ld comparisons, %ld mismatches (", lo, hi, g_compared, g_mismatches);
    for (int d = 1, first = 1; d < ND; d++)
        if (g_eng[d].on) printf("%s%s", first ? "" : ", ", DNAME[d]), first = 0;
    printf(")\n");
    printf("oracle: %ld refusals excused%s as the dialects compute them (a zero divisor: NULL in MySQL, MariaDB and "
           "SQLite; an INT64 overflow: REAL in SQLite; INT64 past 2^53 in FLOAT64: rounded by all; MySQL's INT64_MIN DIV n; SQL Server's INT64_MIN %% -1); %ld both refused "
           "for another reason\n", g_excused, g_eng[D_PG].on ? "" : " (UNGUARDED: PostgreSQL was not run)", g_class_diff);
    printf("oracle: DROP TABLE u made again %ld times on every engine\n", g_drops);
    printf("oracle: %ld refusals under HAVING, LIMIT or OFFSET excused: the reference refused the same statement without them\n",
           g_excused_window);
    printf("oracle: %ld ORDER BY items SQL Server called constants, left out (a constant orders nothing)\n", g_ms_dropped);
    printf("oracle: imagedb alone: %ld CHECKPOINTs, %ld reopens; the paths it answered by:\n", g_checkpoints, g_reopens);
    for (int i = 0; i < g_npaths; i++) printf("  %7ld  %s\n", g_paths[i].n, g_paths[i].path);
    printf("oracle: EXPLAIN checked against the run on %ld SELECTs, %ld disagreements\n", g_explained, g_explain_bad);
    bool servers = g_eng[D_PG].on || g_eng[D_MY].on || g_eng[D_MA].on || g_eng[D_MS].on;
    printf("oracle: %ld comparisons of P2 S2's grouped form (several keys and trees, DISTINCT, FILTER)\n", g_grp_compared);
    printf("oracle: %ld comparisons of P2 S6's window functions\n", g_win_compared);
    printf("oracle: %ld comparisons of P2 S5's set operations, %ld of its WITH RECURSIVE\n", g_set_compared, g_rec_compared);
    printf("oracle: %ld comparisons of P2 S4b's correlated subqueries\n", g_corr_compared);
    printf("oracle: %ld comparisons of P2 S4's subqueries (IN, NOT IN, EXISTS, a value), derived tables and CTEs\n",
           g_subq_compared);
    printf("oracle: %ld comparisons of P2 S3's joins (RIGHT, FULL, CROSS, ON's conditions and key pairs, USING); SQLite's "
           "RIGHT JOIN is its LEFT JOIN, its FULL JOIN a LEFT JOIN UNION ALL the anti-join (rows only)%s\n", g_jn_compared,
           g_eng[D_PG].on || g_eng[D_MS].on ? "" : " (UNGUARDED: FULL JOIN's aggregates, no FULL-capable server run)");
    printf("oracle: %ld comparisons of statements with P2 S1's forms (functions, CASE, CAST, IN, LIKE, ||); ROUND of a "
           "FLOAT64, LOWER and UPPER compared with SQLite alone%s\n", g_fn_compared,
           servers ? "" : " (UNGUARDED: no server engine was run, so a CAST to DECIMAL, the DECIMAL functions and SQL "
                     "Server's, MySQL's and PostgreSQL's spellings were compared with nothing)");
    return g_mismatches ? 1 : 0;
}
