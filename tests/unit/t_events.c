/* P1 M2, observability (docs/plan-p1.md): the event log (imdb_open_opts.events_path: JSON lines, one an event,
 * appended whole, never synced, advisory, FILE.1 past its cap); slow statements by their shape (no literal, no comment,
 * cut on a token); a failed handle said once; an open's progress (the opener's callback and the log's lines). */
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

#include "../../src/db.h"
#include "../../src/fsio.h"
#include "../../src/sql.h"
#include "../../src/sql_internal.h"
#include "thelp.h"

static int run(imdb_session *s, const char *sql)
{
    imdb_result r;
    imdb_err_clear(&g_e);
    int rc = imdb_exec_one(s, sql, strlen(sql), NULL, 0, &r, &g_e);
    if (!rc) imdb_result_free(&r);
    return rc;
}

/* a SHOW STATS row's value (-1: no such row) */
static int64_t stat_of(imdb_session *s, const char *name)
{
    imdb_result r;
    imdb_err e = {0};
    if (imdb_exec_one(s, "SHOW STATS", 10, NULL, 0, &r, &e)) return -1;
    int64_t v = -1;
    size_t n = strlen(name);
    for (uint64_t i = 0; i < r.nrows; i++)
        if (r.cells[2 * i].v.len == n && memcmp(r.cells[2 * i].v.s, name, n) == 0) v = r.cells[2 * i + 1].v.i;
    imdb_result_free(&r);
    return v;
}

#define FILE_MAX (1u << 20)
static char g_file[FILE_MAX + 1];

static size_t ev_slurp(const char *path, char *buf, size_t cap)
{
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return 0;
    size_t got = 0;
    for (;;) {
        ssize_t n = read(fd, buf + got, cap - 1 - got);
        if (n <= 0) break;
        got += (size_t)n;
    }
    close(fd);
    buf[got] = 0;
    return got;
}

static bool put_file(const char *path, const char *s)
{
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
    if (fd < 0) return false;
    bool ok = write(fd, s, strlen(s)) == (ssize_t)strlen(s);
    close(fd);
    return ok;
}

/* ---- one event line, read strictly: a flat object of strings and integers, time_us first and ev second; strings
 * escaped only as the engine writes them (\" \\, \u00XX below 0x20, �), no raw control byte, the line UTF-8 */
#define EV_FIELDS 16
typedef struct evline {
    int nf;
    char key[EV_FIELDS][32];
    char val[EV_FIELDS][2048];
    size_t vlen[EV_FIELDS];
    bool str[EV_FIELDS];
} evline;
static evline g_l;

static int hexval(char c)
{
    return c >= '0' && c <= '9' ? c - '0' : c >= 'a' && c <= 'f' ? c - 'a' + 10 : -1;
}

static bool ev_parse(const char *p, size_t n, evline *o) /* n: the line without its \n */
{
    memset(o, 0, sizeof *o);
    size_t bad;
    if (!imdb_utf8_valid((const uint8_t *)p, n, &bad)) return false;
    size_t i = 0;
    if (n < 2 || p[i++] != '{') return false;
    for (;;) {
        if (o->nf == EV_FIELDS || i >= n || p[i++] != '"') return false;
        size_t k = 0;
        while (i < n && p[i] != '"') {
            char c = p[i++];
            if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_') || k + 1 >= sizeof o->key[0]) return false;
            o->key[o->nf][k++] = c;
        }
        if (!k || i + 2 > n || p[i] != '"' || p[i + 1] != ':') return false;
        i += 2;
        for (int j = 0; j < o->nf; j++)
            if (!strcmp(o->key[j], o->key[o->nf])) return false; /* a key once */
        char *v = o->val[o->nf];
        size_t vl = 0, cap = sizeof o->val[0];
        if (i < n && p[i] == '"') {
            i++;
            o->str[o->nf] = true;
            for (;;) {
                if (i >= n || vl + 4 >= cap) return false;
                unsigned char c = (unsigned char)p[i++];
                if (c == '"') break;
                if (c < 0x20) return false;
                if (c != '\\') {
                    v[vl++] = (char)c;
                    continue;
                }
                if (i >= n) return false;
                char x = p[i++];
                if (x == '"' || x == '\\') {
                    v[vl++] = x;
                } else if (x == 'u' && n - i >= 4 && !memcmp(p + i, "fffd", 4)) {
                    memcpy(v + vl, "\xef\xbf\xbd", 3);
                    vl += 3;
                    i += 4;
                } else if (x == 'u' && n - i >= 4 && p[i] == '0' && p[i + 1] == '0' && (p[i + 2] == '0' || p[i + 2] == '1') &&
                           hexval(p[i + 3]) >= 0) {
                    v[vl++] = (char)((p[i + 2] - '0') * 16 + hexval(p[i + 3]));
                    i += 4;
                } else {
                    return false;
                }
            }
        } else {
            if (i < n && p[i] == '-') v[vl++] = p[i++];
            size_t d0 = vl;
            while (i < n && p[i] >= '0' && p[i] <= '9' && vl + 1 < cap) v[vl++] = p[i++];
            if (vl == d0 || (vl - d0 > 1 && v[d0] == '0')) return false; /* digits, none leading */
        }
        v[vl] = 0;
        o->vlen[o->nf++] = vl;
        if (i >= n) return false;
        if (p[i] == '}') {
            i++;
            break;
        }
        if (p[i++] != ',') return false;
    }
    return i == n && !strcmp(o->key[0], "time_us") && !o->str[0] && !strcmp(o->key[1], "ev") && o->str[1];
}

/* every line of buf parses and ends with \n: their count (or -1) */
static long ev_lines(const char *buf, size_t n)
{
    long lines = 0;
    for (size_t i = 0; i < n;) {
        const char *nl = memchr(buf + i, '\n', n - i);
        if (!nl || !ev_parse(buf + i, (size_t)(nl - buf - (long)i), &g_l)) return -1;
        lines++;
        i = (size_t)(nl - buf) + 1;
    }
    return lines;
}

/* the line at index at (0-based), or the nth line of event ev (ev non-NULL), into *o */
static bool ev_at(const char *buf, size_t n, const char *ev, long at, evline *o)
{
    long seen = 0;
    for (size_t i = 0; i < n;) {
        const char *nl = memchr(buf + i, '\n', n - i);
        if (!nl || !ev_parse(buf + i, (size_t)(nl - buf - (long)i), o)) return false;
        if (!ev || !strcmp(o->val[1], ev)) {
            if (seen == at) return true;
            seen++;
        }
        i = (size_t)(nl - buf) + 1;
    }
    return false;
}

static long ev_count(const char *buf, size_t n, const char *ev)
{
    long c = 0;
    while (ev_at(buf, n, ev, c, &g_l)) c++;
    return c;
}

static const char *ev_str(const evline *l, const char *key)
{
    for (int i = 0; i < l->nf; i++)
        if (l->str[i] && !strcmp(l->key[i], key)) return l->val[i];
    return NULL;
}

static int64_t ev_int(const evline *l, const char *key)
{
    for (int i = 0; i < l->nf; i++)
        if (!l->str[i] && !strcmp(l->key[i], key)) return strtoll(l->val[i], NULL, 10);
    return INT64_MIN;
}

static bool ev_str_is(const evline *l, const char *key, const char *want)
{
    const char *v = ev_str(l, key);
    return v && !strcmp(v, want);
}

/* ---- the tests ------------------------------------------------------------------------------------------------------ */

/* the log's lines through an open, a checkpoint, a warning and the close, in order, each with its fields; a warning's
 * text escaped (quotes, backslashes, control bytes) and its invalid UTF-8 made U+FFFD, valid sequences kept; the same
 * warning again is no line; SHOW STATS counts the lines; a second open appends after the first's lines */
static void t_events_lines(void)
{
    const char *dir = test_tmpdir();
    char p[700], f[720];
    snprintf(p, sizeof p, "%s/db", dir);
    snprintf(f, sizeof f, "%s/events.jsonl", dir);
    OK(imdb_init(p, false, NULL, E));
    imdb_open_opts o = {.sync = 0, .events_path = f, .mem_window_us = UINT64_MAX}; /* no eviction's lines */
    imdb_db *db = NULL;
    OK(imdb_open(p, &o, &db, E));
    if (!db) return;
    imdb_session s;
    imdb_session_init(&s, db);
    CHECK(run(&s, "CREATE TABLE t (id INT64 PRIMARY KEY, v TEXT)") == 0);
    CHECK(run(&s, "INSERT INTO t VALUES (1, 'a'), (2, 'b')") == 0);
    CHECK(run(&s, "CHECKPOINT") == 0);
    uint64_t at_cp = db->seq;
    CHECK(run(&s, "INSERT INTO t VALUES (3, 'c')") == 0);
    static const char msg[] = "q\"b\\c\td\ne \xff f \xe2\x82 g \xc3\xa9 \xe2\x82\xac \xf0\x9f\x98\x80 h \x01";
    static const char want[] =
        "q\"b\\c\td\ne \xef\xbf\xbd f \xef\xbf\xbd\xef\xbf\xbd g \xc3\xa9 \xe2\x82\xac \xf0\x9f\x98\x80 h \x01";
    imdb_warn(db, "%s", msg);
    imdb_warn(db, "%s", msg); /* the same warning: no second line */
    size_t n = ev_slurp(f, g_file, sizeof g_file);
    long lines = ev_lines(g_file, n);
    CHECK(lines == 4);
    CHECK(stat_of(&s, "events.lines") == lines && stat_of(&s, "events.errors") == 0);
    uint64_t last = db->seq;
    imdb_session_close(&s);
    imdb_close(db);
    n = ev_slurp(f, g_file, sizeof g_file);
    CHECK(ev_lines(g_file, n) == 5);
    static const char *const order[] = {"open", "opened", "checkpoint", "warning", "close"};
    for (long i = 0; i < 5; i++) CHECK(ev_at(g_file, n, NULL, i, &g_l) && !strcmp(g_l.val[1], order[i]));
    CHECK(ev_at(g_file, n, "open", 0, &g_l) && ev_str_is(&g_l, "path", p) && ev_int(&g_l, "read_only") == 0 &&
          ev_int(&g_l, "pid") == (int64_t)getpid());
    CHECK(ev_at(g_file, n, "opened", 0, &g_l) && ev_int(&g_l, "ms") >= 0 && ev_int(&g_l, "commit") == 0 &&
          ev_int(&g_l, "snapshot") == 0 && ev_int(&g_l, "replayed") == 0);
    CHECK(ev_at(g_file, n, "checkpoint", 0, &g_l) && ev_int(&g_l, "commit") == (int64_t)at_cp && ev_int(&g_l, "ms") >= 0);
    CHECK(ev_at(g_file, n, "warning", 0, &g_l) && g_l.vlen[2] == sizeof want - 1 && !strcmp(g_l.key[2], "message") &&
          !memcmp(g_l.val[2], want, sizeof want - 1));
    CHECK(ev_at(g_file, n, "close", 0, &g_l) && ev_int(&g_l, "commit") == (int64_t)last);
    CHECK(ev_at(g_file, n, NULL, 0, &g_l) && ev_int(&g_l, "time_us") > 0);
    /* a read-only open from the snapshot: its lines after the first open's */
    imdb_open_opts ro = {.read_only = true, .events_path = f};
    OK(imdb_open(p, &ro, &db, E));
    if (!db) return;
    imdb_close(db);
    n = ev_slurp(f, g_file, sizeof g_file);
    CHECK(ev_lines(g_file, n) == 8);
    CHECK(ev_at(g_file, n, NULL, 5, &g_l) && !strcmp(g_l.val[1], "open") && ev_int(&g_l, "read_only") == 1);
    CHECK(ev_at(g_file, n, "opened", 1, &g_l) && ev_int(&g_l, "commit") == (int64_t)last &&
          ev_int(&g_l, "snapshot") == (int64_t)at_cp && ev_int(&g_l, "replayed") == (int64_t)(last - at_cp));
}

/* a statement's shape: tokens joined by one space, every number, string and boolean literal a ?, a parameter kept,
 * comments gone; cut on a token boundary with " ..." to fit; a text the lexer refuses is "(not lexed)" */
static void t_events_shape(void)
{
    static const struct {
        const char *sql, *shape;
    } c[] = {
        {"SELECT a FROM t WHERE s = 'it''s' AND b = 1.5e3 AND c = -7 AND d = TRUE AND e IS NULL AND f = 2.50 -- x 'y'",
         "SELECT a FROM t WHERE s = ? AND b = ? AND c = - ? AND d = ? AND e IS NULL AND f = ?"},
        {"insert into t values (1, 'x', true, FALSE, null)", "insert into t values ( ? , ? , ? , ? , null )"},
        {"SELECT COUNT(*)\n\tFROM t -- the end", "SELECT COUNT ( * ) FROM t"},
        {"SELECT a FROM t WHERE id = $1 AND trueish = 0", "SELECT a FROM t WHERE id = $1 AND trueish = ?"},
        {"SELECT 'abc", "(not lexed)"},
        {"", ""},
    };
    char out[1024];
    for (size_t i = 0; i < sizeof c / sizeof *c; i++) {
        size_t k = imdb_sql_shape(c[i].sql, strlen(c[i].sql), out, sizeof out);
        CHECK(k == strlen(out) && !strcmp(out, c[i].shape));
    }
    /* a long IN list: cut, on a token, within the buffer, a prefix of the whole shape; no digit anywhere */
    imdb_buf b;
    imdb_buf_init(&b);
    imdb_buf_put_str(&b, "SELECT a FROM t WHERE id IN (");
    for (int i = 1; i <= 1500; i++) imdb_buf_printf(&b, "%s%d", i > 1 ? ", " : "", i);
    imdb_buf_put_str(&b, ")");
    OK(imdb_buf_check(&b, E));
    static char full[1 << 16];
    size_t fl = imdb_sql_shape((const char *)b.p, b.len, full, sizeof full);
    size_t cl = imdb_sql_shape((const char *)b.p, b.len, out, sizeof out);
    CHECK(fl == strlen(full) && fl > sizeof out && !strpbrk(full, "0123456789"));
    CHECK(cl == strlen(out) && cl < sizeof out && cl >= 4 && !memcmp(out + cl - 4, " ...", 4));
    CHECK(!memcmp(out, full, cl - 4) && full[cl - 4] == ' ');
    imdb_buf_free(&b);
    /* tiny buffers: nothing past them */
    char tiny[6];
    memset(tiny, 'z', sizeof tiny);
    CHECK(imdb_sql_shape("SELECT 1", 8, tiny, 0) == 0 && tiny[0] == 'z');
    CHECK(imdb_sql_shape("SELECT 1", 8, tiny, 4) == 0 && tiny[0] == 0 && tiny[4] == 'z');
    CHECK(imdb_sql_shape("SELECT 1", 8, tiny, 5) == 4 && !strcmp(tiny, " ...") && tiny[5] == 'z');
}

enum { N = 200000 };

/* SET slow_statement_ms: a statement at or past it is a line with its class, time, path, rows tested, outcome and
 * shape (a timed-out one too, its time at least its timeout); never its literals or comments; 60 s and 0 (none) log
 * nothing; values out of range refused */
static void t_events_slow(void)
{
    const char *dir = test_tmpdir();
    char p[700], f[720];
    snprintf(p, sizeof p, "%s/db", dir);
    snprintf(f, sizeof f, "%s/events.jsonl", dir);
    OK(imdb_init(p, false, NULL, E));
    imdb_open_opts o = {.sync = 0, .events_path = f};
    imdb_db *db = NULL;
    OK(imdb_open(p, &o, &db, E));
    if (!db) return;
    imdb_session s;
    imdb_session_init(&s, db);
    CHECK(run(&s, "CREATE TABLE t (id INT64 PRIMARY KEY, a INT64, s TEXT)") == 0);
    imdb_buf b;
    imdb_buf_init(&b);
    for (int base = 0; base < N && !g_e.code; base += 10000) {
        b.len = 0;
        imdb_buf_put_str(&b, "INSERT INTO t VALUES ");
        for (int i = base + 1; i <= base + 10000; i++) imdb_buf_printf(&b, "%s(%d, %d, 'r')", i > base + 1 ? ", " : "", i, i % 1000);
        if (imdb_buf_check(&b, &g_e)) break;
        imdb_result r;
        if (!imdb_exec_one(&s, (const char *)b.p, b.len, NULL, 0, &r, &g_e)) imdb_result_free(&r);
    }
    imdb_buf_free(&b);
    CHECK(!g_e.code);
    CHECK(run(&s, "SET slow_statement_ms = -1") != 0 && run(&s, "SET slow_statement_ms = 99999999999") != 0);
    static const char q[] = "SELECT a, COUNT(*) FROM t WHERE a >= 0 AND a + 1 > -1 AND s <> 'xyzzy' GROUP BY a "
                            "ORDER BY a DESC LIMIT 3 -- plugh";
    static const char shape[] = "SELECT a , COUNT ( * ) FROM t WHERE a >= ? AND a + ? > - ? AND s <> ? GROUP BY a "
                                "ORDER BY a DESC LIMIT ?";
    CHECK(run(&s, "SET slow_statement_ms = 1") == 0);
    CHECK(run(&s, "SET statement_timeout = 1") == 0);
    CHECK(run(&s, q) == IMDB_ERR_CANCELLED); /* it ran its timeout: a millisecond at least */
    CHECK(run(&s, "SET statement_timeout = 0") == 0);
    CHECK(run(&s, q) == 0); /* the same, to its end: longer */
    CHECK(run(&s, "SET slow_statement_ms = 60000") == 0);
    CHECK(run(&s, q) == 0);
    CHECK(run(&s, "SET slow_statement_ms = 0") == 0);
    CHECK(run(&s, q) == 0);
    imdb_session_close(&s);
    imdb_close(db);
    size_t n = ev_slurp(f, g_file, sizeof g_file);
    CHECK(ev_lines(g_file, n) > 0);
    long reads = 0;
    for (long i = 0; ev_at(g_file, n, "slow", i, &g_l); i++) {
        if (!ev_str_is(&g_l, "class", "read")) continue; /* a SET past a millisecond on a busy machine is a line too */
        CHECK(ev_str_is(&g_l, "shape", shape) && ev_int(&g_l, "ms") >= 1 && ev_int(&g_l, "rows_tested") > 0 &&
              ev_int(&g_l, "cross_check") == 0 && ev_str(&g_l, "path"));
        CHECK(reads == 0 || ev_str(&g_l, "path")[0]); /* a cancelled statement has no path to report */
        CHECK(ev_int(&g_l, "rc") == (reads == 0 ? IMDB_ERR_CANCELLED : 0));
        reads++;
    }
    CHECK(reads == 2);
    CHECK(!memmem(g_file, n, "xyzzy", 5) && !memmem(g_file, n, "plugh", 5));
}

/* past its cap the log becomes FILE.1 (the older one replaced) and a new FILE begins: each file whole lines, within the
 * cap, FILE.1's last line the one before FILE's first; a FILE.1 that is not an event log is never replaced (counted:
 * FILE goes on past its cap) */
static void t_events_rotate(void)
{
    const char *dir = test_tmpdir();
    char p[700], f[720], f1[730];
    snprintf(p, sizeof p, "%s/db", dir);
    snprintf(f, sizeof f, "%s/events.jsonl", dir);
    snprintf(f1, sizeof f1, "%s.1", f);
    OK(imdb_init(p, false, NULL, E));
    imdb_open_opts o = {.sync = 0, .events_path = f};
    imdb_db *db = NULL;
    OK(imdb_open(p, &o, &db, E));
    if (!db) return;
    imdb_session s;
    imdb_session_init(&s, db);
    db->events_cap = 1000;
    for (int i = 0; i < 60; i++) imdb_warn(db, "rotation %03d", i);
    static char one[FILE_MAX + 1];
    size_t n = ev_slurp(f, g_file, sizeof g_file), n1 = ev_slurp(f1, one, sizeof one);
    long l0 = ev_lines(g_file, n), l1 = ev_lines(one, n1);
    CHECK(l0 > 0 && l1 > 0 && n <= 1000 && n1 <= 1000);
    CHECK(stat_of(&s, "events.lines") == 62 && stat_of(&s, "events.errors") == 0); /* open, opened, 60 warnings */
    CHECK(ev_at(g_file, n, NULL, l0 - 1, &g_l) && ev_str_is(&g_l, "message", "rotation 059"));
    int first = -1, before = -1;
    if (ev_at(g_file, n, NULL, 0, &g_l) && ev_str(&g_l, "message")) first = atoi(ev_str(&g_l, "message") + 9);
    if (ev_at(one, n1, NULL, l1 - 1, &g_l) && ev_str(&g_l, "message")) before = atoi(ev_str(&g_l, "message") + 9);
    CHECK(first > 0 && before == first - 1);
    /* someone else's FILE.1 */
    CHECK(put_file(f1, "precious\n"));
    for (int i = 60; i < 100; i++) imdb_warn(db, "rotation %03d", i);
    n = ev_slurp(f, g_file, sizeof g_file);
    n1 = ev_slurp(f1, one, sizeof one);
    CHECK(n > 1000 && ev_lines(g_file, n) > 0 && n1 == 9 && !memcmp(one, "precious\n", 9));
    CHECK(stat_of(&s, "events.errors") > 0 && stat_of(&s, "events.lines") == 102);
    imdb_session_close(&s);
    imdb_close(db);
}

/* a FILE that is not an event log (its first bytes), a symlink, or a path that cannot be opened: the open goes on, warned,
 * counted, the file untouched, no line anywhere; an empty FILE is taken; an open that fails ends its lines with open_failed */
static void t_events_foreign(void)
{
    const char *dir = test_tmpdir();
    char p[700], f[720], tgt[730], bad[760];
    snprintf(p, sizeof p, "%s/db", dir);
    snprintf(f, sizeof f, "%s/events.jsonl", dir);
    snprintf(tgt, sizeof tgt, "%s/target.txt", dir);
    snprintf(bad, sizeof bad, "%s/no/such/dir/events.jsonl", dir);
    OK(imdb_init(p, false, NULL, E));
    const char *paths[] = {f, f, bad};
    for (int k = 0; k < 3; k++) {
        if (k == 0) CHECK(put_file(f, "operator notes\n"));
        if (k == 1) {
            CHECK(unlink(f) == 0 && put_file(tgt, "target\n") && symlink(tgt, f) == 0);
        }
        imdb_open_opts o = {.sync = 0, .events_path = paths[k]};
        imdb_db *db = NULL;
        OK(imdb_open(p, &o, &db, E));
        if (!db) return;
        CHECK(strstr(db->warning, k == 0 ? "holds something else" : "cannot be written") != NULL);
        imdb_session s;
        imdb_session_init(&s, db);
        CHECK(run(&s, k == 0 ? "CREATE TABLE t (id INT64 PRIMARY KEY)" : "SELECT COUNT(*) FROM t") == 0);
        CHECK(stat_of(&s, "events.errors") == 1 && stat_of(&s, "events.lines") == 0);
        imdb_session_close(&s);
        imdb_close(db);
        size_t n = ev_slurp(k == 1 ? tgt : f, g_file, sizeof g_file);
        if (k == 0) CHECK(n == 15 && !memcmp(g_file, "operator notes\n", 15));
        if (k == 1) CHECK(n == 7 && !memcmp(g_file, "target\n", 7));
    }
    struct stat st;
    CHECK(lstat(f, &st) == 0 && S_ISLNK(st.st_mode));
    CHECK(unlink(f) == 0 && put_file(f, ""));
    imdb_open_opts o = {.sync = 0, .events_path = f};
    imdb_db *db = NULL;
    OK(imdb_open(p, &o, &db, E));
    if (!db) return;
    imdb_close(db);
    size_t n = ev_slurp(f, g_file, sizeof g_file);
    CHECK(ev_lines(g_file, n) == 3 && ev_count(g_file, n, "open") == 1 && ev_count(g_file, n, "close") == 1);
    /* an open that fails: its open line, then open_failed with the error, and nothing after */
    char gone[740];
    snprintf(gone, sizeof gone, "%s/no-such-db", dir);
    CHECK(unlink(f) == 0);
    imdb_open_opts og = {.sync = 0, .events_path = f};
    imdb_err ge = {0};
    db = NULL;
    CHECK(imdb_open(gone, &og, &db, &ge) != 0 && !db && ge.msg[0]);
    n = ev_slurp(f, g_file, sizeof g_file);
    CHECK(ev_lines(g_file, n) == 2 && ev_at(g_file, n, NULL, 0, &g_l) && !strcmp(g_l.val[1], "open") &&
          ev_str_is(&g_l, "path", gone));
    CHECK(ev_at(g_file, n, NULL, 1, &g_l) && !strcmp(g_l.val[1], "open_failed") && ev_str_is(&g_l, "error", ge.msg));
}

static int g_fail_fd = -1, g_fail_sync;
static long fail_ev_write(imdb_io_call *c, void *ctx)
{
    (void)ctx;
    if (c->op == IMDB_IO_WRITE && c->fd >= 0 && c->fd == __atomic_load_n(&g_fail_fd, __ATOMIC_RELAXED)) {
        errno = ENOSPC;
        return -1;
    }
    if ((c->op == IMDB_IO_FDATASYNC || c->op == IMDB_IO_FSYNC) && __atomic_exchange_n(&g_fail_sync, 0, __ATOMIC_RELAXED)) {
        errno = EIO;
        return -1;
    }
    return 0;
}
static const imdb_io_hooks g_ev_hooks = {.before = fail_ev_write};

/* an append that fails is counted, never an error (the statement goes on); a handle that fails says so once, with the
 * failing statement's message, however many statements it then refuses, before its close */
static void t_events_failures(void)
{
    const char *dir = test_tmpdir();
    char p[700], f[720];
    snprintf(p, sizeof p, "%s/db", dir);
    snprintf(f, sizeof f, "%s/events.jsonl", dir);
    OK(imdb_init(p, false, NULL, E));
    imdb_open_opts o = {.sync = 1, .events_path = f};
    imdb_db *db = NULL;
    OK(imdb_open(p, &o, &db, E));
    if (!db) return;
    imdb_session s;
    imdb_session_init(&s, db);
    CHECK(run(&s, "CREATE TABLE t (id INT64 PRIMARY KEY)") == 0);
    g_fail_fd = db->events_fd;
    imdb_io_set_hooks(&g_ev_hooks);
    imdb_warn(db, "%s", "a lost line");
    int rc = run(&s, "INSERT INTO t VALUES (1)");
    imdb_io_set_hooks(NULL);
    g_fail_fd = -1;
    CHECK(rc == 0 && stat_of(&s, "events.errors") == 1);
    size_t n = ev_slurp(f, g_file, sizeof g_file);
    CHECK(ev_lines(g_file, n) == 2 && !memmem(g_file, n, "a lost line", 11));
    /* the next sync fails: the handle stops */
    g_fail_sync = 1;
    imdb_io_set_hooks(&g_ev_hooks);
    rc = run(&s, "INSERT INTO t VALUES (2)");
    imdb_io_set_hooks(NULL);
    g_fail_sync = 0;
    char why[sizeof g_e.msg];
    snprintf(why, sizeof why, "%s", rc ? g_e.msg : db->warning);
    CHECK(db->failed && why[0]);
    CHECK(run(&s, "SELECT COUNT(*) FROM t") == IMDB_ERR_STATE && run(&s, "INSERT INTO t VALUES (3)") == IMDB_ERR_STATE);
    imdb_session_close(&s);
    imdb_close(db);
    n = ev_slurp(f, g_file, sizeof g_file);
    long lines = ev_lines(g_file, n);
    CHECK(lines > 0 && ev_count(g_file, n, "failed") == 1);
    CHECK(ev_at(g_file, n, "failed", 0, &g_l) && ev_str_is(&g_l, "reason", why));
    CHECK(ev_at(g_file, n, NULL, lines - 1, &g_l) && !strcmp(g_l.val[1], "close"));
}

static int g_np;
static struct {
    char phase[8];
    uint64_t done, total;
} g_prog[256];
static void prog_cb(void *ctx, const char *phase, uint64_t done, uint64_t total)
{
    (void)ctx;
    if (g_np < 256) {
        snprintf(g_prog[g_np].phase, sizeof g_prog[g_np].phase, "%s", phase);
        g_prog[g_np].done = done;
        g_prog[g_np].total = total;
    }
    g_np++;
}

/* an open's progress: none for a short open at the default rate; at every step with the rate lowered, a replay's
 * commits 1..n of n, the lake's segments then the commits past the snapshot, each also a line in the log */
static void t_events_progress(void)
{
    const char *dir = test_tmpdir();
    char p[700], f[720];
    snprintf(p, sizeof p, "%s/db", dir);
    snprintf(f, sizeof f, "%s/events.jsonl", dir);
    OK(imdb_init(p, false, NULL, E));
    imdb_open_opts o = {.sync = 0};
    imdb_db *db = NULL;
    OK(imdb_open(p, &o, &db, E));
    if (!db) return;
    imdb_session s;
    imdb_session_init(&s, db);
    CHECK(run(&s, "CREATE TABLE t (id INT64 PRIMARY KEY)") == 0);
    for (int i = 1; i <= 30; i++) {
        char q[64];
        snprintf(q, sizeof q, "INSERT INTO t VALUES (%d)", i);
        CHECK(run(&s, q) == 0);
    }
    uint64_t seq = db->seq;
    imdb_session_close(&s);
    imdb_close(db);
    g_np = 0;
    o.progress = prog_cb;
    OK(imdb_open(p, &o, &db, E));
    if (!db) return;
    imdb_close(db);
    CHECK(g_np == 0);
    imdb_progress_every_ns = 0;
    g_np = 0;
    o.events_path = f;
    OK(imdb_open(p, &o, &db, E));
    if (!db) {
        imdb_progress_every_ns = 1000000000u;
        return;
    }
    CHECK(g_np == (int)seq);
    for (int i = 0; i < g_np && i < 256; i++)
        CHECK(!strcmp(g_prog[i].phase, "replay") && g_prog[i].done == (uint64_t)i + 1 && g_prog[i].total == seq);
    imdb_close(db);
    size_t n = ev_slurp(f, g_file, sizeof g_file);
    CHECK(ev_lines(g_file, n) > 0 && ev_count(g_file, n, "progress") == g_np);
    for (int i = 0; i < g_np && i < 256; i++)
        CHECK(ev_at(g_file, n, "progress", i, &g_l) && ev_str_is(&g_l, "phase", g_prog[i].phase) &&
              ev_int(&g_l, "done") == (int64_t)g_prog[i].done && ev_int(&g_l, "total") == (int64_t)g_prog[i].total);
    /* from a snapshot: the lake, then the commits past it */
    o.progress = NULL;
    o.events_path = NULL;
    OK(imdb_open(p, &o, &db, E));
    if (db) {
        imdb_session_init(&s, db);
        CHECK(run(&s, "CHECKPOINT") == 0);
        for (int i = 31; i <= 35; i++) {
            char q[64];
            snprintf(q, sizeof q, "INSERT INTO t VALUES (%d)", i);
            CHECK(run(&s, q) == 0);
        }
        imdb_session_close(&s);
        imdb_close(db);
    }
    g_np = 0;
    o.progress = prog_cb;
    OK(imdb_open(p, &o, &db, E));
    if (db) imdb_close(db);
    imdb_progress_every_ns = 1000000000u;
    int lake = 0;
    while (lake < g_np && lake < 256 && !strcmp(g_prog[lake].phase, "lake")) lake++;
    CHECK(lake >= 1 && g_prog[lake - 1].done == g_prog[lake - 1].total && g_np == lake + 5);
    for (int i = lake; i < g_np && i < 256; i++)
        CHECK(!strcmp(g_prog[i].phase, "replay") && g_prog[i].done == (uint64_t)(i - lake + 1) && g_prog[i].total == 5);
}

const test_case events_tests[] = {
    {"events_lines", t_events_lines},
    {"events_shape", t_events_shape},
    {"events_slow", t_events_slow},
    {"events_rotate", t_events_rotate},
    {"events_foreign", t_events_foreign},
    {"events_failures", t_events_failures},
    {"events_progress", t_events_progress},
};
const size_t events_ntests = sizeof events_tests / sizeof *events_tests;
