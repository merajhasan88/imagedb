/* N1b: the server on its Unix-domain socket (server/srv.c) through the C client (client/client.c): authentication's
 * one path for every refusal and an unknown name's stable salt; a later version answered with the server's head;
 * statements, batches, parameters, PREPARE and EXECUTE, pipelined requests and their replies in order; a write's
 * commit in DONE, never a maintenance commit; transactions across sessions and READY's states; CANCEL; a client that
 * leaves mid-statement; roles changed through the server and seen at the next connection; protocol errors; the stop;
 * and many clients at once against a model. Every reply is read as a driver reads it: by the codec, strictly. */
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

#include "../../client/imagedb_client.h"
#include "../../server/conv.h"
#include "../../server/srv.h"
#include "../../server/tls.h"
#include "../../src/db.h"
#include "../../src/fsio.h"
#include "../../src/sql.h"
#include "test.h"

static char g_sock[200];
static uint64_t g_ckpt; /* the next serve's size-triggered CHECKPOINT (0: the default) */
static int g_sync;      /* the next serve's sync (0: none) */
static int64_t g_blocks; /* the wire's live blocks before the server: the same after it and every client are gone */
static bool g_tcp;       /* N1c: the tests run again over TCP with TLS 1.3 (login by the pin) */
static uint16_t g_port;
static uint8_t g_pin[32];

static int sql_run(imdb_db *db, const char *sql)
{
    imdb_session s;
    imdb_session_init(&s, db);
    imdb_result r;
    imdb_err e = {0};
    int rc = imdb_exec_one(&s, sql, strlen(sql), NULL, 0, &r, &e);
    imdb_result_free(&r);
    imdb_session_close(&s);
    if (rc) fprintf(stderr, "    %s: %s\n", sql, e.msg);
    return rc;
}

/* a database with the roles the tests log in as, served on a socket in the test's directory */
static imdb_db *serve(imdbs **s, const imdbs_opts *extra)
{
    const char *dir = test_tmpdir();
    char dbdir[256];
    snprintf(dbdir, sizeof dbdir, "%s/db", dir);
    snprintf(g_sock, sizeof g_sock, "%s/s", dir);
    if (strlen(g_sock) >= sizeof(((struct sockaddr_un *)0)->sun_path)) return NULL; /* 107 bytes at most */
    imdb_err e = {0};
    if (imdb_init(dbdir, false, NULL, &e)) return NULL;
    imdb_open_opts o = {.sync = g_sync, .checkpoint_bytes = g_ckpt};
    g_sync = 0;
    g_ckpt = 0;
    imdb_db *db = NULL;
    if (imdb_open(dbdir, &o, &db, &e)) return NULL;
    static const char *const roles[] = {"CREATE ROLE admin LOGIN SUPERUSER PASSWORD 'pw-admin'",
                                        "CREATE ROLE nologin SUPERUSER PASSWORD 'pw'",
                                        "CREATE ROLE plain LOGIN PASSWORD 'pw'",
                                        "CREATE ROLE nopass LOGIN SUPERUSER"};
    for (size_t i = 0; i < sizeof roles / sizeof *roles; i++)
        if (sql_run(db, roles[i])) return NULL;
    imdbs_opts so;
    memset(&so, 0, sizeof so);
    if (extra) so = *extra;
    g_blocks = imdbw_live_blocks();
    so.socket_path = g_sock;
    char sdir[300];
    if (g_tcp) { /* N1c: a certificate in the test's directory, TCP on an ephemeral port beside the socket */
        snprintf(sdir, sizeof sdir, "%s/sd", dir);
        if (mkdir(sdir, 0700) || imdbt_cert_make(sdir, NULL, 0, g_pin, &e)) return NULL;
        so.tcp = "127.0.0.1:0";
        so.server_dir = sdir;
    }
    memset(so.secret, 0x42, sizeof so.secret);
    if (imdbs_start(db, &so, s, &e)) {
        fprintf(stderr, "    imdbs_start: %s\n", e.msg);
        imdb_close(db);
        return NULL;
    }
    g_port = imdbs_tcp_port(*s);
    return db;
}

static void unserve(imdb_db *db, imdbs *s)
{
    imdb_err e = {0};
    SOFT(imdbs_stop(s, &e) == 0);
    imdb_close(db);
    SOFT(imdbw_live_blocks() == g_blocks); /* every block the server and its clients took, freed */
}

static imdbc *login(const char *user, const char *pw)
{
    imdbc *c = NULL;
    imdb_err e = {0};
    if (g_tcp) { /* N1c: TLS 1.3 on TCP, the server's key pinned */
        char port[8];
        snprintf(port, sizeof port, "%u", (unsigned)g_port);
        imdbc_tls t = {NULL, g_pin};
        if (imdbc_connect_tcp("127.0.0.1", port, &t, user, pw, strlen(pw), &c, &e)) return NULL;
    } else if (imdbc_connect(g_sock, user, pw, strlen(pw), &c, &e)) {
        return NULL;
    }
    imdbc_set_timeout(c, 20000); /* a server that stops answering fails the test, never hangs it */
    return c;
}

/* a reply read whole, to its READY: each statement's rows rendered as text, its DONE's fields, an ERROR's */
typedef struct reply {
    int rc;              /* the client's: IMDB_OK, or the connection's failure */
    uint32_t ndone, nerr, nrows, ncols_msgs;
    uint32_t err_code, err_index;
    char err[512];
    uint8_t state;
    uint64_t count;      /* the last DONE's */
    bool has_write, has_read;
    uint64_t write_commit, read_commit;
    uint8_t write_hash[32];
    char status[256];
    char text[8192];     /* rows as "v|v|v\n" */
    size_t tlen;
    bool pong;
    uint32_t nwarn;
    bool warn_before_done; /* a WARNING came before its statement's DONE */
    char warn[512];
} reply;

static void render(const imdbw_value *v, char *o, size_t cap)
{
    if (v->null) {
        snprintf(o, cap, "NULL");
        return;
    }
    switch (v->type) {
    case IMDBW_T_INT64: snprintf(o, cap, "%lld", (long long)v->i); break;
    case IMDBW_T_BOOL: snprintf(o, cap, "%s", v->i ? "t" : "f"); break;
    case IMDBW_T_TEXT:
    case IMDBW_T_ENUM: snprintf(o, cap, "%.*s", (int)v->len, (const char *)v->s); break;
    case IMDBW_T_DECIMAL: {
        __int128 d = v->d;
        bool neg = d < 0;
        unsigned __int128 u = neg ? (unsigned __int128)-d : (unsigned __int128)d;
        char dig[48];
        int n = 0;
        do dig[n++] = (char)('0' + (int)(u % 10)), u /= 10;
        while (u || n <= v->scale);
        size_t k = 0;
        if (neg && k < cap) o[k++] = '-';
        for (int i = n - 1; i >= 0 && k + 2 < cap; i--) {
            o[k++] = dig[i];
            if (i == v->scale && v->scale) o[k++] = '.';
        }
        o[k] = 0;
        break;
    }
    default: snprintf(o, cap, "<%u>", v->type);
    }
}

static int read_reply(imdbc *c, reply *r)
{
    memset(r, 0, sizeof *r);
    imdb_err e = {0};
    for (;;) {
        imdbw_msg m;
        if ((r->rc = imdbc_next(c, &m, &e))) {
            snprintf(r->err, sizeof r->err, "%s", e.msg);
            return r->rc;
        }
        switch (m.type) {
        case IMDBW_COLUMNS: r->ncols_msgs++; break;
        case IMDBW_ROWS: {
            const imdbw_msg *cols = imdbc_columns(c);
            imdb_rd rd;
            imdbw_span_begin(&m.vals, &rd);
            imdbw_value v;
            uint32_t k = 0;
            while (imdbw_span_next(&rd, &v)) {
                char one[96];
                render(&v, one, sizeof one);
                r->tlen += (size_t)snprintf(r->text + r->tlen, sizeof r->text - r->tlen, "%s%s", one,
                                            ++k % cols->ncols ? "|" : "\n");
                if (r->tlen >= sizeof r->text) r->tlen = sizeof r->text - 1;
            }
            r->nrows += m.nsets;
            break;
        }
        case IMDBW_DONE:
            r->ndone++;
            r->count = m.count;
            r->has_write = m.has_write, r->write_commit = m.write_commit;
            memcpy(r->write_hash, m.write_hash, 32);
            r->has_read = m.has_read, r->read_commit = m.read_commit;
            snprintf(r->status, sizeof r->status, "%.*s", (int)m.status.len, (const char *)m.status.p);
            break;
        case IMDBW_ERROR:
            r->nerr++;
            r->err_code = m.code, r->err_index = m.index;
            snprintf(r->err, sizeof r->err, "%.*s", (int)m.texts[0].len, (const char *)m.texts[0].p);
            break;
        case IMDBW_WARNING:
            r->nwarn++;
            r->warn_before_done = r->ndone == 0;
            snprintf(r->warn, sizeof r->warn, "%.*s", (int)m.texts[0].len, (const char *)m.texts[0].p);
            break;
        case IMDBW_PONG: r->pong = true; return IMDB_OK;
        case IMDBW_READY: r->state = m.state; return IMDB_OK;
        default: break;
        }
    }
}

static int q1(imdbc *c, const char *sql, reply *r)
{
    imdbc_stmt st = {sql, strlen(sql), NULL, 0};
    imdb_err e = {0};
    if (imdbc_query(c, &st, 1, &e)) return e.code;
    return read_reply(c, r);
}

/* the challenge a hello for user draws (the raw exchange: a test reads what a stranger would see) */
static bool raw_challenge(const char *user, imdbw_challenge *ch)
{
    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    struct sockaddr_un sa;
    memset(&sa, 0, sizeof sa);
    sa.sun_family = AF_UNIX;
    memcpy(sa.sun_path, g_sock, strlen(g_sock) + 1);
    if (fd < 0 || connect(fd, (struct sockaddr *)&sa, sizeof sa)) {
        if (fd >= 0) close(fd);
        return false;
    }
    imdbw_hello h;
    memset(&h, 0, sizeof h);
    h.version = 1;
    memcpy(h.user, user, strlen(user));
    uint8_t hb[IMDBW_HELLO_LEN], cb[IMDBW_CHALLENGE_LEN];
    imdb_err e = {0};
    bool ok = !imdbw_hello_put(&h, hb) && write(fd, hb, sizeof hb) == (ssize_t)sizeof hb &&
              recv(fd, cb, sizeof cb, MSG_WAITALL) == (ssize_t)sizeof cb && !imdbw_challenge_get(cb, ch, &e);
    close(fd);
    return ok;
}

static void t_server_auth(void)
{
    imdbs *s;
    imdb_db *db = serve(&s, NULL);
    CHECK(db);
    imdbc *c = login("admin", "pw-admin");
    SOFT(c);
    imdbc_close(c);
    /* every refusal one path: a wrong password, an unknown name, a role without LOGIN, without SUPERUSER (until N1e),
     * without a verifier */
    static const char *const bad[][2] = {{"admin", "wrong"}, {"ghost", "pw"}, {"nologin", "pw"}, {"plain", "pw"}, {"nopass", "x"}};
    for (size_t i = 0; i < sizeof bad / sizeof *bad; i++) {
        imdbc *x = NULL;
        imdb_err e = {0};
        int rc = imdbc_connect(g_sock, bad[i][0], bad[i][1], strlen(bad[i][1]), &x, &e);
        if (rc != IMDB_ERR_AUTH) fprintf(stderr, "    %s/%s: %d %s\n", bad[i][0], bad[i][1], rc, e.msg);
        SOFT(rc == IMDB_ERR_AUTH && !x);
        imdbc_close(x);
    }
    /* an unknown name's salt: the same at every attempt, another name's another, the default count; a known role's its
     * verifier's */
    imdbw_challenge a, b, g, k;
    SOFT(raw_challenge("ghost", &a) && raw_challenge("ghost", &b) && raw_challenge("ghost2", &g) && raw_challenge("admin", &k));
    SOFT(a.salt_len == 16 && !memcmp(a.salt, b.salt, 16) && memcmp(a.salt, g.salt, 16) && a.iter == 4096);
    SOFT(memcmp(a.nonce, b.nonce, sizeof a.nonce)); /* the server's nonce fresh each time */
    SOFT(k.salt_len == 16 && k.iter == 4096 && memcmp(k.salt, a.salt, 16));
    /* a later version: the server's own head, then the close */
    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    struct sockaddr_un sa;
    memset(&sa, 0, sizeof sa);
    sa.sun_family = AF_UNIX;
    memcpy(sa.sun_path, g_sock, strlen(g_sock) + 1);
    SOFT(fd >= 0 && !connect(fd, (struct sockaddr *)&sa, sizeof sa));
    uint8_t later[IMDBW_HELLO_LEN];
    memset(later, 0, sizeof later);
    memcpy(later, "IMDBWIR1", 8);
    later[8] = 2;
    uint8_t got[IMDBW_PREAUTH_HEAD + 1];
    SOFT(write(fd, later, sizeof later) == (ssize_t)sizeof later);
    ssize_t n = recv(fd, got, sizeof got, MSG_WAITALL);
    uint32_t v = 0;
    imdb_err e = {0};
    SOFT(n == IMDBW_PREAUTH_HEAD && !imdbw_preauth_head(got, &v, &e) && v == 1);
    close(fd);
    imdbs_counts cn;
    imdbs_counts_get(s, &cn);
    SOFT(cn.logins == 1 && cn.refusals == 5 + 4);
    unserve(db, s);
}

static void t_server_statements(void)
{
    imdbs *s;
    imdb_db *db = serve(&s, NULL);
    CHECK(db);
    imdbc *c = login("admin", "pw-admin");
    CHECK(c);
    reply r;
    SOFT(q1(c, "CREATE TABLE t (id INT64 PRIMARY KEY, s TEXT, d DECIMAL(10,2))", &r) == 0 && r.ndone == 1 && !r.nerr &&
         r.has_write && r.state == IMDBW_IDLE);
    uint64_t created = r.write_commit;
    /* parameters: an INT64, a TEXT, a DECIMAL of another scale (N1b: as its literal) */
    imdbw_value p[3];
    memset(p, 0, sizeof p);
    p[0].type = IMDBW_T_INT64, p[0].i = 1;
    p[1].type = IMDBW_T_TEXT, p[1].s = (const uint8_t *)"héllo", p[1].len = 6;
    p[2].type = IMDBW_T_DECIMAL, p[2].scale = 1, p[2].d = 15;
    imdbc_stmt ins = {"INSERT INTO t VALUES ($1, $2, $3)", 33, p, 3};
    imdb_err e = {0};
    SOFT(imdbc_query(c, &ins, 1, &e) == 0 && read_reply(c, &r) == 0 && r.ndone == 1 && r.count == 1 && r.has_write &&
         r.write_commit == created + 1 && !r.nerr);
    SOFT(q1(c, "SELECT id, s, d FROM t", &r) == 0 && r.ncols_msgs == 1 && r.nrows == 1 && !strcmp(r.text, "1|héllo|1.50\n") &&
         r.has_read && r.read_commit == created + 1 && !r.has_write && r.count == 1);
    /* a batch stops at its first error: its index, the statement after it never run, READY idle (each committed alone) */
    imdbc_stmt b[3] = {{"INSERT INTO t VALUES (2, 'b', 2)", 32, NULL, 0},
                       {"INSERT INTO t VALUES (1, 'dup', 1)", 34, NULL, 0},
                       {"INSERT INTO t VALUES (3, 'c', 3)", 32, NULL, 0}};
    SOFT(imdbc_query(c, b, 3, &e) == 0 && read_reply(c, &r) == 0 && r.ndone == 1 && r.nerr == 1 && r.err_index == 1 &&
         r.err_code == (uint32_t)-IMDB_ERR_CONSTRAINT && r.state == IMDBW_IDLE);
    SOFT(q1(c, "SELECT id FROM t ORDER BY id", &r) == 0 && !strcmp(r.text, "1\n2\n"));
    /* a SUM past INT64 is a DECIMAL (§4) */
    SOFT(q1(c, "SELECT SUM(id) FROM t", &r) == 0 && !strcmp(r.text, "3\n"));
    /* an empty result still has its COLUMNS */
    SOFT(q1(c, "SELECT id FROM t WHERE id > 100", &r) == 0 && r.ncols_msgs == 1 && r.nrows == 0 && r.ndone == 1);
    /* a syntax error: its code, the session idle */
    SOFT(q1(c, "SELEC 1", &r) == 0 && r.nerr == 1 && r.err_code == (uint32_t)-IMDB_ERR_SYNTAX && r.state == IMDBW_IDLE);
    /* a statement's text ends at its length: an unterminated string followed in the frame by its 39 parameters' count,
     * whose first byte is a quote (39 = '\''), stays unterminated */
    imdbw_value p39[39];
    memset(p39, 0, sizeof p39);
    for (int k = 0; k < 39; k++) p39[k].type = IMDBW_T_INT64, p39[k].i = k;
    imdbc_stmt un = {"SELECT 'abc", 11, p39, 39};
    SOFT(imdbc_query(c, &un, 1, &e) == 0 && read_reply(c, &r) == 0 && r.nerr == 1 && !r.ndone);
    /* COPY through the server: refused (N1d), the connection usable after */
    SOFT(q1(c, "COPY t FROM STDIN", &r) == 0 && r.nerr == 1 && r.err_code == (uint32_t)-IMDB_ERR_UNSUPPORTED);
    SOFT(q1(c, "COPY t TO STDOUT", &r) == 0 && r.nerr == 1);
    SOFT(q1(c, "SELECT 3", &r) == 0 && !r.nerr && !strcmp(r.text, "3\n"));
    /* PREPARE, EXECUTE of three sets, DEALLOCATE, an EXECUTE of none */
    SOFT(imdbc_prepare(c, "ins", "INSERT INTO t VALUES ($1, $2, $3)", 33, &e) == 0 && read_reply(c, &r) == 0 &&
         r.ndone == 1 && !strcmp(r.status, "PREPARE"));
    imdbw_value sets[9];
    memset(sets, 0, sizeof sets);
    for (int k = 0; k < 3; k++) {
        sets[3 * k].type = IMDBW_T_INT64, sets[3 * k].i = 10 + k;
        sets[3 * k + 1].type = IMDBW_T_TEXT, sets[3 * k + 1].s = (const uint8_t *)"x", sets[3 * k + 1].len = 1;
        sets[3 * k + 2].type = IMDBW_T_INT64, sets[3 * k + 2].i = k; /* an INT64 into a DECIMAL(10,2): as its literal */
    }
    SOFT(imdbc_execute(c, "ins", sets, 3, 3, &e) == 0 && read_reply(c, &r) == 0 && r.ndone == 3 && !r.nerr);
    SOFT(imdbc_deallocate(c, "ins", &e) == 0 && read_reply(c, &r) == 0 && r.ndone == 1);
    SOFT(imdbc_execute(c, "ins", sets, 1, 3, &e) == 0 && read_reply(c, &r) == 0 && r.nerr == 1 &&
         r.err_code == (uint32_t)-IMDB_ERR_NOTFOUND);
    SOFT(q1(c, "SELECT COUNT(*), SUM(d) FROM t", &r) == 0 && !strcmp(r.text, "5|6.50\n"));
    /* pipelined: three requests sent before any reply, answered in order; a PING among them */
    imdbc_stmt p1 = {"SELECT 1", 8, NULL, 0}, p2 = {"SELECT 2", 8, NULL, 0};
    SOFT(imdbc_query(c, &p1, 1, &e) == 0 && imdbc_ping(c, &e) == 0 && imdbc_query(c, &p2, 1, &e) == 0);
    /* the connection answers PING at once, so PONG may come before an earlier request's replies (§4: "between requests
     * or during one"); the two statements' replies come in their order */
    reply three[3];
    int pongs = 0, seen = 0;
    for (int k = 0; k < 3; k++) {
        SOFT(read_reply(c, &three[k]) == 0);
        if (three[k].pong) {
            pongs++;
            continue;
        }
        SOFT(!strcmp(three[k].text, seen ? "2\n" : "1\n"));
        seen++;
    }
    SOFT(pongs == 1 && seen == 2);
    imdbc_close(c);
    unserve(db, s);
}

/* transactions across two sessions: READY's states, the first committer winning, a doomed one taking only ROLLBACK */
static void t_server_txn(void)
{
    imdbs *s;
    imdb_db *db = serve(&s, NULL);
    CHECK(db);
    imdbc *a = login("admin", "pw-admin"), *b = login("admin", "pw-admin");
    CHECK(a && b);
    reply r;
    SOFT(q1(a, "CREATE TABLE t (id INT64 PRIMARY KEY, v INT64)", &r) == 0);
    SOFT(q1(a, "INSERT INTO t VALUES (1, 0)", &r) == 0 && !r.nerr);
    SOFT(q1(a, "BEGIN", &r) == 0 && r.state == IMDBW_IN_TXN);
    SOFT(q1(b, "BEGIN", &r) == 0 && r.state == IMDBW_IN_TXN);
    SOFT(q1(a, "UPDATE t SET v = 1 WHERE id = 1", &r) == 0 && !r.nerr && r.state == IMDBW_IN_TXN && !r.has_write);
    reply rb;
    SOFT(q1(b, "UPDATE t SET v = 2 WHERE id = 1", &rb) == 0);
    SOFT(q1(a, "COMMIT", &r) == 0 && !r.nerr && r.state == IMDBW_IDLE && r.has_write);
    reply rc2;
    SOFT(q1(b, "COMMIT", &rc2) == 0);
    /* b lost: refused at its UPDATE or at its COMMIT, by a conflict (14), its transaction ended or doomed */
    bool lost = (rb.nerr && rb.err_code == (uint32_t)-IMDB_ERR_CONFLICT) || (rc2.nerr && rc2.err_code == (uint32_t)-IMDB_ERR_CONFLICT);
    SOFT(lost);
    if (rc2.state != IMDBW_IDLE) SOFT(q1(b, "ROLLBACK", &r) == 0 && r.state == IMDBW_IDLE);
    SOFT(q1(b, "SELECT v FROM t", &r) == 0 && !strcmp(r.text, "1\n"));
    /* a statement's error inside a transaction undoes it alone: the transaction goes on (READY 1) */
    SOFT(q1(a, "BEGIN", &r) == 0 && q1(a, "INSERT INTO t VALUES (2, 2)", &r) == 0 && !r.nerr);
    SOFT(q1(a, "INSERT INTO t VALUES (2, 3)", &r) == 0 && r.nerr && r.state == IMDBW_IN_TXN);
    SOFT(q1(a, "COMMIT", &r) == 0 && !r.nerr && r.has_write);
    SOFT(q1(b, "SELECT id, v FROM t ORDER BY id", &r) == 0 && !strcmp(r.text, "1|1\n2|2\n"));
    /* a client that leaves inside a transaction: rolled back, its row's lock gone (another session's write to the row
     * then commits; with the session left open it would conflict) */
    SOFT(q1(b, "BEGIN", &r) == 0 && q1(b, "UPDATE t SET v = 9 WHERE id = 1", &r) == 0 && !r.nerr && r.state == IMDBW_IN_TXN);
    SOFT(q1(a, "SHOW TRANSACTIONS", &r) == 0 && r.nrows == 1); /* b's, open */
    imdbc_close(b);
    bool ended = false;
    for (int k = 0; k < 2000 && !ended; k++) { /* its session's end is a request the engine runs next */
        usleep(10000);
        SOFT(q1(a, "SHOW TRANSACTIONS", &r) == 0);
        ended = r.nrows == 0;
    }
    SOFT(ended);
    SOFT(q1(a, "UPDATE t SET v = 5 WHERE id = 1", &r) == 0 && !r.nerr && r.count == 1);
    SOFT(q1(a, "SELECT id, v FROM t ORDER BY id", &r) == 0 && !strcmp(r.text, "1|5\n2|2\n"));
    imdbc_close(a);
    unserve(db, s);
}

/* a write's commit in DONE is its own, never the CHECKPOINT the size triggered after it (imdb_maintain's) */
static void t_server_commit_stamp(void)
{
    imdbs *s;
    g_ckpt = 4096; /* a CHECKPOINT the size triggers every few INSERTs, imdb_maintain's, after the INSERT's commit */
    imdb_db *db = serve(&s, NULL);
    CHECK(db);
    imdbc *c = login("admin", "pw-admin");
    CHECK(c);
    reply r, h, l;
    SOFT(q1(c, "CREATE TABLE t (id INT64 PRIMARY KEY, v TEXT)", &r) == 0);
    int after = 0;
    for (int k = 0; k < 60; k++) {
        char sql[160];
        snprintf(sql, sizeof sql, "INSERT INTO t VALUES (%d, 'a value long enough that the log grows past its trigger soon')", k);
        SOFT(q1(c, sql, &r) == 0 && r.has_write && !r.nerr);
        /* the row's version began at DONE's commit; SHOW LOG's last commit past it when a CHECKPOINT followed */
        snprintf(sql, sizeof sql, "SHOW HISTORY t (%d)", k);
        char want[64];
        snprintf(want, sizeof want, "|%llu|", (unsigned long long)r.write_commit);
        SOFT(q1(c, sql, &h) == 0 && h.nrows == 1 && strstr(h.text, want) == strchr(h.text, '|'));
        /* SHOW LOG's last two commits: the INSERT's own (its hash DONE's) and, when a CHECKPOINT followed, that one */
        SOFT(q1(c, "SHOW LOG 2", &l) == 0 && l.nrows == 2);
        char hex[65];
        const char *line = l.text;
        for (int b = 0; b < 32; b++) snprintf(hex + 2 * b, 3, "%02x", r.write_hash[b]);
        bool found = false;
        unsigned long long last = 0;
        for (int row = 0; row < 2 && line && *line; row++) {
            unsigned long long n = strtoull(line, NULL, 10);
            const char *nl = strchr(line, '\n'), *bar = NULL;
            for (const char *p = line; nl && p < nl; p++) bar = *p == '|' ? p : bar; /* this line's last field: the hash */
            if (n == r.write_commit) found = bar && nl - bar - 1 == 64 && !memcmp(bar + 1, hex, 64);
            last = n;
            line = nl ? nl + 1 : NULL;
        }
        SOFT(found && last >= r.write_commit);
        after += last > r.write_commit;
    }
    SOFT(after > 0); /* the case the stamp exists for happened */
    SOFT(q1(c, "CHECKPOINT", &r) == 0 && r.has_write); /* a CHECKPOINT statement's commit is the statement's */
    SOFT(q1(c, "SELECT COUNT(*) FROM t", &r) == 0 && !r.has_write && !strcmp(r.text, "60\n"));
    imdbc_close(c);
    unserve(db, s);
}

/* the statements begun so far: read before a request is sent, then waited past (never a clock) */
static uint64_t started_now(imdbs *s)
{
    imdbs_counts cn;
    imdbs_counts_get(s, &cn);
    return cn.started;
}

/* until a statement past before has begun, 20 s at most */
static void wait_started(imdbs *s, uint64_t before)
{
    for (int k = 0; k < 2000 && started_now(s) <= before; k++) usleep(10000);
}

/* CANCEL again every 20 ms until told to stop: one that lands between statements, or just before the statement's start
 * clears it, is dropped (§4), so a client that wants a cancel repeats it until the reply comes */
typedef struct canceller {
    imdbc *c;
    atomic_bool stop;
} canceller;

static void *cancel_later(void *arg)
{
    canceller *k = arg;
    while (!atomic_load(&k->stop)) {
        imdbc_cancel(k->c);
        usleep(20000);
    }
    return NULL;
}

/* the deepest statements the engine takes (views four deep, SELECTs nested, an expression 61 high, 64 set-operation
 * arms, a recursion of 2,000 rounds): through the engine thread's own stack */
static bool deep_ok(imdbc *c)
{
    static const char *const setup[] = {"CREATE TABLE d (id INT64 PRIMARY KEY, v INT64)", "INSERT INTO d VALUES (1, 1), (2, 2)",
                                        "CREATE VIEW v1 AS SELECT id, v FROM d", "CREATE VIEW v2 AS SELECT id, v FROM v1",
                                        "CREATE VIEW v3 AS SELECT id, v FROM v2", "CREATE VIEW v4 AS SELECT id, v FROM v3"};
    reply r;
    bool ok = true;
    for (size_t i = 0; i < sizeof setup / sizeof *setup; i++) ok = ok && q1(c, setup[i], &r) == 0 && !r.nerr;
    char par[256], uni[2048];
    size_t n = (size_t)snprintf(par, sizeof par, "SELECT ");
    for (int k = 0; k < 60; k++) par[n++] = '(';
    par[n++] = '1';
    for (int k = 0; k < 60; k++) par[n++] = ')';
    snprintf(par + n, sizeof par - n, " AS x");
    n = (size_t)snprintf(uni, sizeof uni, "SELECT COUNT(*) FROM (");
    for (int k = 1; k < 64; k++) n += (size_t)snprintf(uni + n, sizeof uni - n, "SELECT %d UNION ALL ", k);
    snprintf(uni + n, sizeof uni - n, "SELECT 64) AS u");
    const char *q[][2] = {{"SELECT COUNT(*) FROM v4", "2\n"},
                          {"SELECT (SELECT (SELECT (SELECT 1)))", "1\n"},
                          {par, "1\n"},
                          {uni, "64\n"},
                          {"WITH RECURSIVE r (n) AS (SELECT 1 UNION ALL SELECT n + 1 FROM r WHERE n < 2000) SELECT COUNT(*) FROM r",
                           "2000\n"}};
    for (size_t i = 0; i < sizeof q / sizeof *q; i++) {
        bool one = q1(c, q[i][0], &r) == 0 && !r.nerr && !strcmp(r.text, q[i][1]);
        if (!one) fprintf(stderr, "    deep %zu: %u %s\n", i, r.err_code, r.err);
        ok = ok && one;
    }
    return ok;
}

static void t_server_deep(void)
{
    imdbs *s;
    imdb_db *db = serve(&s, NULL);
    CHECK(db);
    imdbc *c = login("admin", "pw-admin");
    SOFT(c && deep_ok(c));
    imdbc_close(c);
    unserve(db, s);
}


static void load_rows(imdbc *c, int n)
{
    reply r;
    imdb_err e = {0};
    SOFT(q1(c, "CREATE TABLE big (id INT64 PRIMARY KEY, v INT64)", &r) == 0);
    SOFT(imdbc_prepare(c, "ins", "INSERT INTO big VALUES ($1, $2)", 31, &e) == 0 && read_reply(c, &r) == 0);
    imdbw_value v[2 * 400];
    memset(v, 0, sizeof v);
    for (int k = 0; k < n && k < 400; k++) {
        v[2 * k].type = v[2 * k + 1].type = IMDBW_T_INT64;
        v[2 * k].i = k, v[2 * k + 1].i = k % 7;
    }
    SOFT(imdbc_execute(c, "ins", v, (uint32_t)n, 2, &e) == 0 && read_reply(c, &r) == 0 && r.ndone == (uint32_t)n);
    SOFT(q1(c, "CREATE TABLE big2 (id INT64 PRIMARY KEY, v INT64)", &r) == 0 && !r.nerr);
    SOFT(q1(c, "INSERT INTO big2 SELECT a.id * 1000 + b.id, a.v FROM big AS a, big AS b", &r) == 0 && !r.nerr);
    if (r.nerr || r.rc) fprintf(stderr, "    big2: rc %d, code %u: %s\n", r.rc, r.err_code, r.err);
}

/* CANCEL from another thread: the running statement ends in ERROR 15, the session goes on; a client that leaves
 * mid-statement cancels it, so another client's request runs at once */
static void t_server_cancel(void)
{
    imdbs *s;
    imdb_db *db = serve(&s, NULL);
    CHECK(db);
    imdbc *c = login("admin", "pw-admin");
    CHECK(c);
    load_rows(c, 400);
    static const char slow[] = "SELECT COUNT(*) FROM big2 AS a, big2 AS b WHERE a.v + b.v = 99"; /* 2.56e10 pairs: minutes */
    reply r;
    SOFT(q1(c, "SET statement_timeout = 30000", &r) == 0 && !r.nerr); /* a cancel that failed ends anyway, late */
    imdbc_stmt st = {slow, sizeof slow - 1, NULL, 0};
    imdb_err e = {0};
    /* a batch: SELECT 41's reply comes while the slow statement after it runs (its client had nothing to read: the
     * engine hands it over at once, not at 64 KiB or the batch's end), then CANCEL ends the slow one */
    imdbc_stmt two[2] = {{"SELECT 41", 9, NULL, 0}, {slow, sizeof slow - 1, NULL, 0}};
    uint64_t t0 = imdb_mono_ns();
    SOFT(imdbc_query(c, two, 2, &e) == 0);
    imdbw_msg m;
    bool first = false;
    while (!first && imdbc_next(c, &m, &e) == 0) first = m.type == IMDBW_DONE; /* 20 s at most: the read timeout */
    SOFT(first);
    canceller k = {.c = c};
    atomic_store(&k.stop, false);
    pthread_t th;
    SOFT(pthread_create(&th, NULL, cancel_later, &k) == 0);
    SOFT(read_reply(c, &r) == 0 && r.nerr == 1 && r.err_index == 1 && r.err_code == (uint32_t)-IMDB_ERR_CANCELLED &&
         r.state == IMDBW_IDLE);
    if (r.err_code != (uint32_t)-IMDB_ERR_CANCELLED) fprintf(stderr, "    the slow statement: %u %s, %u rows %s\n", r.err_code, r.err, r.nrows, r.text);
    atomic_store(&k.stop, true);
    pthread_join(th, NULL);
    SOFT(imdbc_ping(c, &e) == 0 && read_reply(c, &r) == 0 && r.pong); /* a cancel the canceller left pending, sent with nothing running: dropped */
    SOFT((imdb_mono_ns() - t0) / 1000000u < 20000); /* well under the 30 s timeout: the cancel ended it (the counter below) */
    SOFT(q1(c, "SELECT COUNT(*) FROM big", &r) == 0 && !strcmp(r.text, "400\n"));
    imdbs_counts cn;
    imdbs_counts_get(s, &cn);
    SOFT(cn.cancels >= 1);
    /* a client that leaves mid-statement: another's request answered in well under the statement's time */
    imdbc *d = login("admin", "pw-admin");
    SOFT(d && q1(d, "SET statement_timeout = 30000", &r) == 0);
    uint64_t before = started_now(s);
    SOFT(d && imdbc_query(d, &st, 1, &e) == 0);
    wait_started(s, before); /* its statement begun: the leave cancels it (again until it ends) */
    imdbc_close(d); /* gone: its statement cancelled */
    t0 = imdb_mono_ns();
    SOFT(q1(c, "SELECT 7", &r) == 0 && !strcmp(r.text, "7\n"));
    SOFT((imdb_mono_ns() - t0) / 1000000u < 20000); /* the gone client's statement cancelled (the counter below) */
    imdbs_counts_get(s, &cn);
    SOFT(cn.leave_cancels >= 1);
    imdbc_close(c);
    unserve(db, s);
}

/* roles changed through the server are seen at the very next connection: a password, NOLOGIN, a rename, DROP and
 * ERASE ROLE */
static void t_server_roles(void)
{
    imdbs *s;
    imdb_db *db = serve(&s, NULL);
    CHECK(db);
    imdbc *c = login("admin", "pw-admin");
    CHECK(c);
    reply r;
    SOFT(q1(c, "CREATE ROLE bob LOGIN SUPERUSER PASSWORD 'b1'", &r) == 0 && !r.nerr);
    imdbc *x = login("bob", "b1");
    SOFT(x);
    imdbc_close(x);
    SOFT(q1(c, "ALTER ROLE bob PASSWORD 'b2'", &r) == 0 && !r.nerr);
    SOFT(!login("bob", "b1"));
    SOFT((x = login("bob", "b2")) != NULL);
    imdbc_close(x);
    SOFT(q1(c, "ALTER ROLE bob NOLOGIN", &r) == 0 && !r.nerr);
    SOFT(!login("bob", "b2"));
    SOFT(q1(c, "ALTER ROLE bob LOGIN", &r) == 0 && !r.nerr);
    SOFT((x = login("bob", "b2")) != NULL);
    imdbc_close(x);
    SOFT(q1(c, "ALTER ROLE bob RENAME TO rob", &r) == 0 && !r.nerr);
    SOFT(!login("bob", "b2"));
    SOFT((x = login("rob", "b2")) != NULL);
    imdbc_close(x);
    SOFT(q1(c, "DROP ROLE rob", &r) == 0 && !r.nerr);
    SOFT(!login("rob", "b2"));
    SOFT(q1(c, "ERASE ROLE rob", &r) == 0 && !r.nerr);
    SOFT(!login("rob", "b2"));
    imdbs_counts cn;
    imdbs_counts_get(s, &cn);
    SOFT(cn.logins_made >= 7);
    imdbc_close(c);
    unserve(db, s);
}

/* frames the protocol refuses: an ERROR, then the close; COPY data with no COPY running the same */
static void t_server_protocol(void)
{
    imdbs *s;
    imdb_db *db = serve(&s, NULL);
    CHECK(db);
    static const uint8_t frames[][6] = {
        {6, 0, 0, 0, 64, 0},   /* a server's type from the client */
        {1, 0, 0, 0, 5, 0},    /* COPY_DATA of no byte */
        {1, 0, 0, 0, 6, 0},    /* COPY_DONE with no COPY */
        {0, 0, 0, 0, 1, 0},    /* a length of 0 */
        {2, 0, 0, 0, 9, 7},    /* PING with a body */
    };
    static const size_t lens[] = {6, 5, 5, 5, 6};
    for (size_t i = 0; i < sizeof frames / sizeof *frames; i++) {
        imdbc *c = login("admin", "pw-admin");
        SOFT(c);
        if (!c) continue;
        SOFT(write(imdbc_fd(c), frames[i], lens[i]) == (ssize_t)lens[i]);
        imdbw_msg m;
        imdb_err e = {0};
        int rc = imdbc_next(c, &m, &e);
        SOFT(rc == 0 && m.type == IMDBW_ERROR);
        rc = imdbc_next(c, &m, &e); /* then the close */
        SOFT(rc == IMDB_ERR_IO);
        imdbc_close(c);
    }
    /* the server goes on */
    imdbc *c = login("admin", "pw-admin");
    reply r;
    SOFT(c && q1(c, "SELECT 1", &r) == 0 && !strcmp(r.text, "1\n"));
    imdbc_close(c);
    unserve(db, s);
}

/* the stop: an open transaction rolled back, the database the caller's again */
static void t_server_stop(void)
{
    imdbs *s;
    imdb_db *db = serve(&s, NULL);
    CHECK(db);
    imdbc *c = login("admin", "pw-admin");
    CHECK(c);
    reply r;
    SOFT(q1(c, "CREATE TABLE t (id INT64 PRIMARY KEY)", &r) == 0);
    SOFT(q1(c, "BEGIN", &r) == 0 && q1(c, "INSERT INTO t VALUES (1)", &r) == 0 && r.state == IMDBW_IN_TXN);
    imdb_err e = {0};
    SOFT(imdbs_stop(s, &e) == 0);
    imdbw_msg m;
    SOFT(imdbc_next(c, &m, &e) == IMDB_ERR_IO); /* closed */
    imdbc_close(c);
    imdb_session ss;
    imdb_session_init(&ss, db);
    imdb_result res;
    SOFT(imdb_exec_one(&ss, "SELECT COUNT(*) FROM t", 22, NULL, 0, &res, &e) == 0 && res.nrows == 1 && res.cells[0].v.i == 0);
    imdb_result_free(&res);
    /* no transaction left behind: the client's was rolled back with its session at the stop */
    SOFT(imdb_exec_one(&ss, "SHOW TRANSACTIONS", 17, NULL, 0, &res, &e) == 0 && res.nrows == 0);
    imdb_result_free(&res);
    imdb_session_close(&ss);
    SOFT(access(g_sock, F_OK) != 0); /* the socket removed */
    imdb_close(db);
}

/* many clients at once: each its own key range, inserting, updating and reading in transactions and alone; the table
 * the model's at the end, every reply as expected */
typedef struct worker {
    int id, ok;
} worker;

static void *work(void *arg)
{
    worker *w = arg;
    imdbc *c = login("admin", "pw-admin");
    if (!c) return NULL;
    reply r;
    int ok = 0;
    for (int k = 0; k < 40; k++) {
        char sql[128];
        int key = w->id * 1000 + k;
        snprintf(sql, sizeof sql, "INSERT INTO t VALUES (%d, %d)", key, k);
        if (k % 4 == 0) {
            imdbc_stmt b[3] = {{"BEGIN", 5, NULL, 0}, {sql, strlen(sql), NULL, 0}, {"COMMIT", 6, NULL, 0}};
            imdb_err e = {0};
            if (imdbc_query(c, b, 3, &e) || read_reply(c, &r) || r.nerr || r.ndone != 3 || r.state != IMDBW_IDLE) continue;
        } else if (q1(c, sql, &r) || r.nerr || r.count != 1) {
            continue;
        }
        snprintf(sql, sizeof sql, "SELECT v FROM t WHERE id = %d", key);
        char want[32];
        snprintf(want, sizeof want, "%d\n", k);
        if (q1(c, sql, &r) || strcmp(r.text, want)) continue;
        ok++;
    }
    w->ok = ok;
    imdbc_close(c);
    return NULL;
}

static void t_server_clients(void)
{
    imdbs *s;
    imdbs_opts o;
    memset(&o, 0, sizeof o);
    o.slice_ms = 1;
    imdb_db *db = serve(&s, &o);
    CHECK(db);
    imdbc *c = login("admin", "pw-admin");
    reply r;
    SOFT(c && q1(c, "CREATE TABLE t (id INT64 PRIMARY KEY, v INT64)", &r) == 0 && !r.nerr);
    enum { NW = 40 }; /* past twice the per-address cap (16): over TCP a pool from one address waits, never refused */
    worker w[NW];
    pthread_t th[NW];
    for (int i = 0; i < NW; i++) {
        w[i] = (worker){i, 0};
        SOFT(pthread_create(&th[i], NULL, work, &w[i]) == 0);
    }
    int total = 0;
    for (int i = 0; i < NW; i++) {
        pthread_join(th[i], NULL);
        total += w[i].ok;
    }
    SOFT(total == NW * 40);
    char want[64];
    snprintf(want, sizeof want, "%d|%d\n", NW * 40, NW * (39 * 40 / 2)); /* each worker's v: 0 to 39 */
    SOFT(c && q1(c, "SELECT COUNT(*), SUM(v) FROM t", &r) == 0 && !strcmp(r.text, want));
    imdbc_close(c);
    imdbs_counts cn;
    imdbs_counts_get(s, &cn);
    SOFT(cn.logins == NW + 1);
    unserve(db, s);
}


/* a request pauses at a statement's boundary and resumes where it stopped: a slice of 1 ms, two connections, a large
 * EXECUTE (its values cursor) and a transaction of many statements (its batch) pipelined at once; every row as sent,
 * the transaction whole */
static void t_server_pause(void)
{
    imdbs *s;
    imdbs_opts o;
    memset(&o, 0, sizeof o);
    o.slice_ms = 1;
    imdb_db *db = serve(&s, &o);
    CHECK(db);
    imdbc *a = login("admin", "pw-admin"), *b = login("admin", "pw-admin");
    CHECK(a && b);
    reply r;
    imdb_err e = {0};
    SOFT(q1(a, "CREATE TABLE t (id INT64 PRIMARY KEY, v INT64)", &r) == 0 && !r.nerr);
    SOFT(imdbc_prepare(a, "ins", "INSERT INTO t VALUES ($1, $2)", 29, &e) == 0 && read_reply(a, &r) == 0 && !r.nerr);
    enum { NA = 2000, NB = 300 };
    static imdbw_value v[2 * NA];
    memset(v, 0, sizeof v);
    for (int k = 0; k < NA; k++) {
        v[2 * k].type = v[2 * k + 1].type = IMDBW_T_INT64;
        v[2 * k].i = k, v[2 * k + 1].i = 3 * k;
    }
    static imdbc_stmt bs[NB + 2];
    static char sql[NB][64];
    bs[0] = (imdbc_stmt){"BEGIN", 5, NULL, 0};
    for (int k = 0; k < NB; k++) {
        snprintf(sql[k], sizeof sql[k], "INSERT INTO t VALUES (%d, %d)", 100000 + k, k);
        bs[k + 1] = (imdbc_stmt){sql[k], strlen(sql[k]), NULL, 0};
    }
    bs[NB + 1] = (imdbc_stmt){"COMMIT", 6, NULL, 0};
    imdbs_counts before, after;
    imdbs_counts_get(s, &before);
    SOFT(imdbc_execute(a, "ins", v, NA, 2, &e) == 0 && imdbc_query(b, bs, NB + 2, &e) == 0);
    reply ra, rb;
    SOFT(read_reply(a, &ra) == 0 && ra.ndone == NA && !ra.nerr && ra.state == IMDBW_IDLE);
    SOFT(read_reply(b, &rb) == 0 && rb.ndone == NB + 2 && !rb.nerr && rb.state == IMDBW_IDLE);
    imdbs_counts_get(s, &after);
    SOFT(after.pauses > before.pauses); /* the case resuming exists for happened */
    SOFT(q1(a, "SELECT COUNT(*), SUM(v) FROM t WHERE id < 100000", &r) == 0 && !strcmp(r.text, "2000|5997000\n"));
    SOFT(q1(a, "SELECT COUNT(*), SUM(v) FROM t WHERE id >= 100000", &r) == 0 && !strcmp(r.text, "300|44850\n"));
    imdbc_close(a);
    imdbc_close(b);
    unserve(db, s);
}

/* a client that sends a statement with a large result and never reads: dropped once it takes no byte for the send
 * timeout, its replies freed; another client meanwhile answered */
static void t_server_slow_reader(void)
{
    imdbs *s;
    imdbs_opts o;
    memset(&o, 0, sizeof o);
    o.conn_cap = 64u << 10;
    o.send_timeout_ms = 300;
    imdb_db *db = serve(&s, &o);
    CHECK(db);
    imdbc *c = login("admin", "pw-admin");
    CHECK(c);
    load_rows(c, 400);
    imdbc *slow = login("admin", "pw-admin");
    CHECK(slow);
    static const char all[] = "SELECT * FROM big2"; /* 160,000 rows: megabytes, never read */
    imdbc_stmt st = {all, sizeof all - 1, NULL, 0};
    imdb_err e = {0};
    SOFT(imdbc_query(slow, &st, 1, &e) == 0);
    reply r;
    bool dropped = false;
    for (int k = 0; k < 2000 && !dropped; k++) {
        usleep(10000);
        imdbs_counts cn;
        imdbs_counts_get(s, &cn);
        dropped = cn.dropped >= 1;
    }
    SOFT(dropped);
    SOFT(q1(c, "SELECT COUNT(*) FROM big2", &r) == 0 && !strcmp(r.text, "160000\n"));
    imdbc_close(slow);
    imdbc_close(c);
    unserve(db, s);
}

/* a peer gone while the engine thread is busy with another's statement: its connection thread waits quietly (no spin
 * on the socket's hang-up) until its session's end runs */
static void t_server_quiet(void)
{
    imdbs *s;
    imdb_db *db = serve(&s, NULL);
    CHECK(db);
    imdbc *c = login("admin", "pw-admin");
    CHECK(c);
    load_rows(c, 400);
    reply r;
    SOFT(q1(c, "SET statement_timeout = 30000", &r) == 0 && !r.nerr);
    static const char slow[] = "SELECT COUNT(*) FROM big2 AS a, big2 AS b WHERE a.v + b.v = 99";
    imdbc_stmt st = {slow, sizeof slow - 1, NULL, 0};
    imdb_err e = {0};
    uint64_t before = started_now(s);
    SOFT(imdbc_query(c, &st, 1, &e) == 0);
    wait_started(s, before); /* the slow statement holds the engine thread */
    imdbc *g = login("admin", "pw-admin");
    SOFT(g);
    imdbc_stmt one = {"SELECT 1", 8, NULL, 0};
    SOFT(g && imdbc_query(g, &one, 1, &e) == 0); /* queued behind the slow statement */
    usleep(50000);
    imdbc_close(g); /* gone, its request queued: its thread waits for its session's end */
    usleep(50000);
    imdbs_counts c0, c1;
    imdbs_counts_get(s, &c0);
    usleep(500000);
    imdbs_counts_get(s, &c1);
    SOFT(c1.wakeups - c0.wakeups < 100); /* a spin is millions in half a second */
    imdbc_cancel(c);
    SOFT(read_reply(c, &r) == 0 && r.nerr == 1 && r.err_code == (uint32_t)-IMDB_ERR_CANCELLED);
    imdbc_close(c);
    unserve(db, s);
}

/* a failed sync stops the handle (db->failed): the statement's ERROR, every later request's, imdbs_failed, and the
 * stop's error; the hooks installed before the server's threads start, a flag arming them */
static atomic_bool g_fail_sync;
static long fail_sync(imdb_io_call *c, void *ctx)
{
    (void)ctx;
    if ((c->op == IMDB_IO_FDATASYNC || c->op == IMDB_IO_FSYNC) && atomic_load(&g_fail_sync)) {
        errno = EIO;
        return -1;
    }
    return 0;
}

static void t_server_failed(void)
{
    static const imdb_io_hooks h = {fail_sync, NULL, NULL};
    atomic_store(&g_fail_sync, false);
    g_sync = 1;
    imdb_io_set_hooks(&h);
    imdbs *s;
    imdb_db *db = serve(&s, NULL);
    if (!db) imdb_io_set_hooks(NULL);
    CHECK(db);
    imdbc *c = login("admin", "pw-admin");
    reply r;
    SOFT(c && q1(c, "CREATE TABLE t (id INT64 PRIMARY KEY)", &r) == 0 && !r.nerr);
    atomic_store(&g_fail_sync, true);
    SOFT(c && q1(c, "INSERT INTO t VALUES (1)", &r) == 0 && r.nerr == 1);
    SOFT(imdbs_wait_failed(s, 5000));
    SOFT(c && q1(c, "SELECT 1", &r) == 0 && r.nerr == 1 && r.err_code == (uint32_t)-IMDB_ERR_IO);
    imdbc_close(c);
    imdb_err e = {0};
    SOFT(imdbs_stop(s, &e) == IMDB_ERR_IO);
    imdb_io_set_hooks(NULL);
    atomic_store(&g_fail_sync, false);
    imdb_close(db); /* failed: the reopen decides */
}

/* an idle transaction past its limit expires without a statement of its session (the engine thread's tick, or another
 * session's statement): its lock gone, its session's next statement refused, READY doomed until its ROLLBACK */
static void t_server_idle_timeout(void)
{
    imdbs *s;
    imdbs_opts o;
    memset(&o, 0, sizeof o);
    o.tick_ms = 20;
    imdb_db *db = serve(&s, &o);
    CHECK(db);
    imdbc *a = login("admin", "pw-admin"), *b = login("admin", "pw-admin");
    CHECK(a && b);
    reply r;
    SOFT(q1(a, "CREATE TABLE t (id INT64 PRIMARY KEY, v INT64)", &r) == 0 && q1(a, "INSERT INTO t VALUES (1, 0)", &r) == 0);
    SOFT(q1(b, "SET idle_in_transaction_timeout = 100", &r) == 0 && !r.nerr);
    SOFT(q1(b, "BEGIN", &r) == 0 && q1(b, "UPDATE t SET v = 9 WHERE id = 1", &r) == 0 && !r.nerr);
    usleep(400000);
    SOFT(q1(b, "SELECT v FROM t", &r) == 0 && r.nerr == 1 && r.state == IMDBW_DOOMED);
    SOFT(q1(b, "ROLLBACK", &r) == 0 && !r.nerr && r.state == IMDBW_IDLE);
    SOFT(q1(a, "UPDATE t SET v = 5 WHERE id = 1", &r) == 0 && !r.nerr && r.count == 1);
    imdbc_close(a);
    imdbc_close(b);
    unserve(db, s);
}

/* the binary: imagedb-server beside the suite's own binary (its build's); its secret made once (32 bytes, 0600) and
 * kept across a restart (an unknown name's salt the same), SIGTERM's stop (exit 0), a kill in the middle of commits
 * (every acknowledged commit there at the reopen, VERIFY clean), a replica's directory refused (exit 1) */
static pid_t spawn(const char *bin, const char *dbdir, const char *sdir)
{
    pid_t pid = fork();
    if (pid == 0) {
        int nul = open("/dev/null", O_WRONLY | O_CLOEXEC);
        if (nul >= 0) dup2(nul, 1);
        prctl(PR_SET_PDEATHSIG, SIGKILL); /* a test that stops early leaves no server behind */
        struct rlimit rl = {RLIM_INFINITY, RLIM_INFINITY}; /* a supervisor's: the engine thread's stack its own */
        setrlimit(RLIMIT_STACK, &rl);
        execl(bin, bin, dbdir, "--socket", g_sock, "--server-dir", sdir, "--nosync", (char *)NULL);
        _exit(127);
    }
    return pid;
}

static bool wait_ready(pid_t pid)
{
    for (int k = 0; k < 1000; k++) {
        imdbc *c = login("admin", "pw-admin");
        if (c) {
            imdbc_close(c);
            return true;
        }
        int st;
        if (waitpid(pid, &st, WNOHANG) == pid) return false;
        usleep(10000);
    }
    return false;
}

/* the child's exit within 20 s (a server that never ends killed then, and -1: a failure, never a hang) */
static int wait_exit(pid_t pid)
{
    int st = 0;
    for (int k = 0; k < 2000; k++) {
        pid_t w = waitpid(pid, &st, WNOHANG);
        if (w == pid) return WIFEXITED(st) ? WEXITSTATUS(st) : 128 + WTERMSIG(st);
        if (w < 0) return -1;
        usleep(10000);
    }
    kill(pid, SIGKILL);
    waitpid(pid, &st, 0);
    return -1;
}

static int stop_with(pid_t pid, int sig)
{
    kill(pid, sig);
    return wait_exit(pid);
}

typedef struct inserter {
    _Atomic int64_t acked; /* the last id whose INSERT's DONE came back */
    _Atomic bool stop;
} inserter;

static void *insert_on(void *arg)
{
    inserter *in = arg;
    imdbc *c = login("admin", "pw-admin");
    if (!c) return NULL;
    for (int64_t id = 1; !atomic_load(&in->stop); id++) {
        char sql[96];
        reply r;
        snprintf(sql, sizeof sql, "INSERT INTO k VALUES (%lld)", (long long)id);
        if (q1(c, sql, &r) || r.nerr || !r.has_write) break;
        atomic_store(&in->acked, id);
    }
    imdbc_close(c);
    return NULL;
}

static void t_server_binary(void)
{
    char exe[4096], bin[4200];
    ssize_t n = readlink("/proc/self/exe", exe, sizeof exe - 1);
    CHECK(n > 0);
    exe[n] = 0;
    char *slash = strrchr(exe, '/');
    CHECK(slash);
    *slash = 0;
    snprintf(bin, sizeof bin, "%s/imagedb-server", exe);
    CHECK(access(bin, X_OK) == 0); /* built with the suite ($(TBIN)'s order-only prerequisite) */
    const char *dir = test_tmpdir();
    char dbdir[300], sdir[300], rep[300], secret[320];
    snprintf(dbdir, sizeof dbdir, "%s/db", dir);
    snprintf(sdir, sizeof sdir, "%s/sd", dir);
    snprintf(rep, sizeof rep, "%s/rep", dir);
    snprintf(secret, sizeof secret, "%s/secret", sdir);
    snprintf(g_sock, sizeof g_sock, "%s/s", dir);
    CHECK(strlen(g_sock) < sizeof(((struct sockaddr_un *)0)->sun_path)); /* a socket's path: 107 bytes at most */
    CHECK(mkdir(sdir, 0700) == 0);
    imdb_err e = {0};
    CHECK_OK(imdb_init(dbdir, false, NULL, &e));
    imdb_open_opts o = {.sync = 0};
    imdb_db *db = NULL;
    CHECK_OK(imdb_open(dbdir, &o, &db, &e));
    CHECK(sql_run(db, "CREATE ROLE admin LOGIN SUPERUSER PASSWORD 'pw-admin'") == 0);
    CHECK(sql_run(db, "CREATE TABLE k (id INT64 PRIMARY KEY)") == 0);
    CHECK_OK(imdb_close(db));
    pid_t pid = spawn(bin, dbdir, sdir);
    CHECK(pid > 0 && wait_ready(pid));
    imdbw_challenge c1, c2;
    SOFT(raw_challenge("ghost", &c1));
    SOFT(stop_with(pid, SIGTERM) == 0);
    struct stat st;
    SOFT(stat(secret, &st) == 0 && st.st_size == 32 && (st.st_mode & 0777) == 0600);
    SOFT(access(g_sock, F_OK) != 0);
    pid = spawn(bin, dbdir, sdir);
    CHECK(pid > 0 && wait_ready(pid));
    SOFT(raw_challenge("ghost", &c2) && !memcmp(c1.salt, c2.salt, 16)); /* the secret kept: the same salt */
    imdbc *dc = login("admin", "pw-admin"); /* the deepest statements, the binary run with RLIMIT_STACK unlimited */
    SOFT(dc && deep_ok(dc));
    imdbc_close(dc);
    /* killed in the middle of commits: every acknowledged one there */
    inserter in = {0};
    pthread_t th;
    SOFT(pthread_create(&th, NULL, insert_on, &in) == 0);
    for (int k = 0; k < 2000 && atomic_load(&in.acked) < 20; k++) usleep(10000); /* commits acknowledged, then the kill */
    int code = stop_with(pid, SIGKILL);
    atomic_store(&in.stop, true);
    pthread_join(th, NULL);
    SOFT(code == 128 + SIGKILL);
    int64_t acked = atomic_load(&in.acked);
    SOFT(acked > 0);
    unlink(g_sock); /* the killed server's socket: the next would take it, as no server answers on it */
    CHECK_OK(imdb_open(dbdir, &o, &db, &e));
    imdb_session ss;
    imdb_session_init(&ss, db);
    imdb_result r;
    char q[128];
    snprintf(q, sizeof q, "SELECT COUNT(*) FROM k WHERE id <= %lld", (long long)acked);
    SOFT(imdb_exec_one(&ss, q, strlen(q), NULL, 0, &r, &e) == 0 && r.nrows == 1 && r.cells[0].v.i == acked);
    imdb_result_free(&r);
    SOFT(imdb_exec_one(&ss, "VERIFY", 6, NULL, 0, &r, &e) == 0);
    imdb_result_free(&r);
    imdb_session_close(&ss);
    CHECK_OK(imdb_close(db));
    /* the stop's two signals: the first lets the running statement end at its own end (the server lives on), the second
     * cancels it (the server exits at once, 0) */
    pid = spawn(bin, dbdir, sdir);
    CHECK(pid > 0 && wait_ready(pid));
    imdbc *sl = login("admin", "pw-admin");
    SOFT(sl);
    if (sl) {
        reply rr;
        load_rows(sl, 400);
        SOFT(q1(sl, "SET statement_timeout = 120000", &rr) == 0 && !rr.nerr);
        static const char slow[] = "SELECT COUNT(*) FROM big2 AS a, big2 AS b WHERE a.v + b.v = 99";
        imdbc_stmt sst = {slow, sizeof slow - 1, NULL, 0};
        SOFT(imdbc_query(sl, &sst, 1, &e) == 0);
        usleep(1000000); /* the engine is idle: its statement started (another process: no gauge to wait on) */
        kill(pid, SIGTERM);
        usleep(500000);
        int st0 = 0;
        SOFT(waitpid(pid, &st0, WNOHANG) == 0); /* alive: the statement runs on */
        uint64_t t0 = imdb_mono_ns();
        SOFT(stop_with(pid, SIGTERM) == 0);
        SOFT((imdb_mono_ns() - t0) / 1000000u < 20000); /* cancelled, not its 120 s */
        imdbc_close(sl);
    } else {
        stop_with(pid, SIGKILL);
    }
    /* a replica's directory: refused, exit 1 */
    CHECK_OK(imdb_init(rep, true, dbdir, &e));
    pid = fork();
    if (pid == 0) {
        int nul = open("/dev/null", O_WRONLY | O_CLOEXEC);
        if (nul >= 0) dup2(nul, 1), dup2(nul, 2);
        prctl(PR_SET_PDEATHSIG, SIGKILL);
        execl(bin, bin, rep, "--socket", g_sock, "--server-dir", sdir, "--nosync", (char *)NULL);
        _exit(127);
    }
    SOFT(pid > 0 && wait_exit(pid) == 1);
}

/* a warning the engine raises during a statement reaches its client before the statement's DONE, as the CLI shows it:
 * the CHECKPOINT the size triggers after an INSERT fails (a segment's creation refused by the hooks, installed before
 * the server's threads start and armed by a flag), the INSERT itself committed */
static atomic_bool g_fail_seg;
static long fail_seg(imdb_io_call *c, void *ctx)
{
    (void)ctx;
    if (c->op == IMDB_IO_OPEN && (c->flags & O_CREAT) && c->name && strstr(c->name, ".seg") && atomic_load(&g_fail_seg)) {
        errno = EIO;
        return -1;
    }
    return 0;
}

static void t_server_warning(void)
{
    static const imdb_io_hooks h = {fail_seg, NULL, NULL};
    atomic_store(&g_fail_seg, false);
    imdb_io_set_hooks(&h);
    imdbs *s;
    g_ckpt = 4096;
    imdb_db *db = serve(&s, NULL);
    if (!db) imdb_io_set_hooks(NULL);
    CHECK(db);
    imdbc *c = login("admin", "pw-admin");
    reply r;
    SOFT(c && q1(c, "CREATE TABLE t (id INT64 PRIMARY KEY, v TEXT)", &r) == 0 && !r.nerr);
    atomic_store(&g_fail_seg, true);
    int warned = 0;
    for (int k = 0; c && k < 60 && !warned; k++) {
        char sql[160];
        snprintf(sql, sizeof sql, "INSERT INTO t VALUES (%d, 'a value long enough that the log grows past its trigger soon')", k);
        SOFT(q1(c, sql, &r) == 0 && !r.nerr && r.ndone == 1);
        warned += r.nwarn > 0 && r.warn_before_done && strstr(r.warn, "CHECKPOINT") != NULL;
    }
    SOFT(warned == 1);
    atomic_store(&g_fail_seg, false);
    imdbc_close(c);
    unserve(db, s);
    imdb_io_set_hooks(NULL);
}

/* the stop in two steps (a signal's): begun, it waits for the running statement (not ready while it runs); a cancel of
 * every running statement (a second signal's, repeated: one landing before a statement's start is cleared by it) ends
 * it, its client given its ERROR and READY, then the stop is ready and returns at once */
static void t_server_stop_two(void)
{
    imdbs *s;
    imdb_db *db = serve(&s, NULL);
    CHECK(db);
    imdbc *c = login("admin", "pw-admin");
    CHECK(c);
    load_rows(c, 400);
    reply r;
    SOFT(q1(c, "SET statement_timeout = 60000", &r) == 0 && !r.nerr);
    static const char slow[] = "SELECT COUNT(*) FROM big2 AS a, big2 AS b WHERE a.v + b.v = 99";
    imdbc_stmt st = {slow, sizeof slow - 1, NULL, 0};
    imdb_err e = {0};
    uint64_t before = started_now(s);
    SOFT(imdbc_query(c, &st, 1, &e) == 0);
    wait_started(s, before);
    imdbs_stop_begin(s);
    usleep(200000);
    SOFT(!imdbs_stop_ready(s)); /* the statement runs on: a stop never cuts one short by itself */
    for (int k = 0; k < 2000 && !imdbs_stop_ready(s); k++) {
        imdbs_cancel_all(s);
        usleep(10000);
    }
    SOFT(imdbs_stop_ready(s));
    SOFT(read_reply(c, &r) == 0 && r.nerr == 1 && r.err_code == (uint32_t)-IMDB_ERR_CANCELLED);
    SOFT(imdbs_stop(s, &e) == 0);
    imdbc_close(c);
    imdb_close(db);
    SOFT(imdbw_live_blocks() == g_blocks);
}

/* N1c: the same tests over TCP with TLS 1.3 (the pin's login), the answers the socket's; those that write raw frames or
 * read the socket's raw challenge (auth, protocol) stay on the socket, and t_tls holds TLS's own */
#define OVER_TCP(name)                                                                                                 \
    static void name##_tcp(void)                                                                                       \
    {                                                                                                                  \
        g_tcp = true;                                                                                                  \
        name();                                                                                                        \
        g_tcp = false;                                                                                                 \
    }
OVER_TCP(t_server_statements)
OVER_TCP(t_server_txn)
OVER_TCP(t_server_commit_stamp)
OVER_TCP(t_server_cancel)
OVER_TCP(t_server_roles)
OVER_TCP(t_server_stop)
OVER_TCP(t_server_clients)
OVER_TCP(t_server_pause)
OVER_TCP(t_server_slow_reader)
OVER_TCP(t_server_quiet)
OVER_TCP(t_server_idle_timeout)
OVER_TCP(t_server_deep)
OVER_TCP(t_server_stop_two)
OVER_TCP(t_server_warning)
const test_case server_tests[] = {
    {"server_auth", t_server_auth},
    {"server_statements", t_server_statements},
    {"server_txn", t_server_txn},
    {"server_commit_stamp", t_server_commit_stamp},
    {"server_cancel", t_server_cancel},
    {"server_roles", t_server_roles},
    {"server_protocol", t_server_protocol},
    {"server_stop", t_server_stop},
    {"server_clients", t_server_clients},
    {"server_pause", t_server_pause},
    {"server_slow_reader", t_server_slow_reader},
    {"server_quiet", t_server_quiet},
    {"server_failed", t_server_failed},
    {"server_idle_timeout", t_server_idle_timeout},
    {"server_binary", t_server_binary},
    {"server_warning", t_server_warning},
    {"server_deep", t_server_deep},
    {"server_stop_two", t_server_stop_two},
    {"server_tcp_statements", t_server_statements_tcp},
    {"server_tcp_txn", t_server_txn_tcp},
    {"server_tcp_commit_stamp", t_server_commit_stamp_tcp},
    {"server_tcp_cancel", t_server_cancel_tcp},
    {"server_tcp_roles", t_server_roles_tcp},
    {"server_tcp_stop", t_server_stop_tcp},
    {"server_tcp_clients", t_server_clients_tcp},
    {"server_tcp_pause", t_server_pause_tcp},
    {"server_tcp_slow_reader", t_server_slow_reader_tcp},
    {"server_tcp_quiet", t_server_quiet_tcp},
    {"server_tcp_idle_timeout", t_server_idle_timeout_tcp},
    {"server_tcp_deep", t_server_deep_tcp},
    {"server_tcp_stop_two", t_server_stop_two_tcp},
    {"server_tcp_warning", t_server_warning_tcp},
};
const size_t server_ntests = sizeof server_tests / sizeof *server_tests;
