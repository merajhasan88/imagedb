/* N1b: the server on its Unix-domain socket (server/srv.c) through the C client (client/client.c): authentication's
 * one path for every refusal and an unknown name's stable salt; a later version answered with the server's head;
 * statements, batches, parameters, PREPARE and EXECUTE, pipelined requests and their replies in order; a write's
 * commit in DONE, never a maintenance commit; transactions across sessions and READY's states; CANCEL; a client that
 * leaves mid-statement; roles changed through the server and seen at the next connection; protocol errors; the stop;
 * and many clients at once against a model. Every reply is read as a driver reads it: by the codec, strictly. */
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
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
#include "../../server/spool.h"
#include "../../server/srv.h"
#include "../../server/tls.h"
#include "../../src/db.h"
#include "../../src/fsio.h"
#include "../../src/sql.h"
#include "test.h"

static char g_sock[200];
static uint64_t g_ckpt; /* the next serve's size-triggered CHECKPOINT (0: the default) */
static int g_sync;      /* the next serve's sync (0: none) */
static bool g_nomem;    /* 2c: the next serve's database without a memory budget (superusers alone log in); else 2 GiB */
static const char *g_events; /* 2b-2b: the next serve's event log (NULL: none) */
static int64_t g_blocks; /* the wire's live blocks before the server: the same after it and every client are gone */
static bool g_tcp;       /* N1c: the tests run again over TCP with TLS 1.3 (login by the pin) */
static uint16_t g_port;
static uint8_t g_pin[32];
static bool g_nospool;    /* N1d: the next serve has no spool directory (COPY refused by name) */
static char g_spool[300]; /* N1d: the spool directory serve gives the server */
static char g_dbdir[256]; /* N1d: the database serve made (test_tmpdir names a new directory at each call) */
static uint8_t *g_out;    /* N1d: COPY_OUT's bytes gathered by read_reply when set (the test's own buffer) */
static size_t g_outlen, g_outcap;

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
    snprintf(g_dbdir, sizeof g_dbdir, "%s", dbdir);
    snprintf(g_sock, sizeof g_sock, "%s/s", dir);
    if (strlen(g_sock) >= sizeof(((struct sockaddr_un *)0)->sun_path)) return NULL; /* 107 bytes at most */
    imdb_err e = {0};
    if (imdb_init(dbdir, false, NULL, &e)) return NULL;
    imdb_open_opts o = {.sync = g_sync, .checkpoint_bytes = g_ckpt, .events_path = g_events,
                        .mem_limit = g_nomem ? 0 : (2ull << 30)}; /* 2c: a budget opens a role's logins */
    g_events = NULL;
    g_sync = 0;
    g_ckpt = 0;
    g_nomem = false;
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
    if (!so.spool_dir && !g_nospool) { /* N1d: COPY's spool beside the database */
        snprintf(g_spool, sizeof g_spool, "%s/spool", dir);
        so.spool_dir = g_spool;
    }
    g_nospool = false;
    memset(so.secret, 0x42, sizeof so.secret);
    if (imdbs_start(db, &so, s, &e)) {
        fprintf(stderr, "    imdbs_start: %s\n", e.msg);
        imdb_close(db);
        return NULL;
    }
    g_port = imdbs_tcp_port(*s);
    if (getenv("IMDB_SRV_HOLD_US")) imdbs_test_reply_hold((uint32_t)atoi(getenv("IMDB_SRV_HOLD_US"))); /* (a group run under the hold) */
    if (getenv("IMDB_SRV_COUNT_HOLD_US")) imdbs_test_count_hold((uint32_t)atoi(getenv("IMDB_SRV_COUNT_HOLD_US")));
    return db;
}

static void unserve(imdb_db *db, imdbs *s)
{
    imdb_err e = {0};
    SOFT(imdbs_stop(s, &e) == 0);
    imdb_close(db);
    SOFT(imdbw_live_blocks() == g_blocks); /* every block the server and its clients took, freed */
}

static _Thread_local imdb_err g_login_err; /* the calling thread's last login's failure (server_clients logs in from 40) */

static imdbc *login(const char *user, const char *pw)
{
    imdbc *c = NULL;
    imdb_err e = {0};
    imdb_err_clear(&g_login_err);
    int rc;
    if (g_tcp) { /* N1c: TLS 1.3 on TCP, the server's key pinned */
        char port[8];
        snprintf(port, sizeof port, "%u", (unsigned)g_port);
        imdbc_tls t = {NULL, g_pin};
        rc = imdbc_connect_tcp("127.0.0.1", port, &t, user, pw, strlen(pw), &c, &e);
    } else {
        rc = imdbc_connect(g_sock, user, pw, strlen(pw), &c, &e);
    }
    if (rc) {
        g_login_err = e;
        return NULL;
    }
    imdbc_set_timeout(c, 20000); /* a server that stops answering fails the test, never hangs it */
    return c;
}

/* a reply read whole, to its READY: each statement's rows rendered as text, its DONE's fields, an ERROR's. Every one is
 * declared = {0}: a send that failed leaves it unread, and a reply as the stack held it once passed for an admission (D34) */
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
    bool copy_in;          /* N1d: COPY_IN came (read_reply returns at it: the caller sends the data) */
    uint64_t nout;         /* COPY_OUT's bytes */
    char seq[256];         /* the replies' kinds in order: C COLUMNS, R ROWS, O COPY_OUT, D DONE, E ERROR, W WARNING */
    size_t nseq;
    char warn[512];
    bool kill_done;        /* N1e stage two: a KILL_DONE came (read_reply returns at it), its code and session */
    uint32_t kill_code;
    uint64_t kill_sid;
    bool sessions;         /* a SESSIONS_LIST came (read_reply returns at it): its first 16 entries, names copied */
    uint32_t nsess;
    imdbw_sess sess[16];
    char sname[16][64];
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
            if (!r->nerr) snprintf(r->err, sizeof r->err, "%s", e.msg); /* (an ERROR before the close keeps its text) */
            return r->rc;
        }
        if (r->nseq + 1 < sizeof r->seq) { /* N1d: the kinds in order (consecutive COPY_OUTs as one O) */
            char k = m.type == IMDBW_COLUMNS ? 'C' : m.type == IMDBW_ROWS ? 'R' : m.type == IMDBW_COPY_OUT ? 'O'
                   : m.type == IMDBW_DONE ? 'D' : m.type == IMDBW_ERROR ? 'E' : m.type == IMDBW_WARNING ? 'W' : 0;
            if (k && !(k == 'O' && r->nseq && r->seq[r->nseq - 1] == 'O')) r->seq[r->nseq++] = k;
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
        case IMDBW_COPY_IN: r->copy_in = true; return IMDB_OK; /* N1d: the caller sends the data */
        case IMDBW_COPY_OUT:
            r->nout += m.dlen;
            if (g_out && g_outlen + m.dlen <= g_outcap) memcpy(g_out + g_outlen, m.data, m.dlen);
            g_outlen += m.dlen; /* (past the buffer: counted, the comparison then fails) */
            break;
        case IMDBW_PONG: r->pong = true; return IMDB_OK;
        case IMDBW_KILL_DONE: /* N1e stage two */
            r->kill_done = true, r->kill_code = m.code, r->kill_sid = m.sid;
            return IMDB_OK;
        case IMDBW_SESSIONS_LIST:
            r->sessions = true, r->nsess = m.nsess;
            for (uint32_t i = 0; i < m.nsess && i < 16; i++) {
                r->sess[i] = m.sess[i];
                snprintf(r->sname[i], sizeof r->sname[i], "%.*s", (int)m.sess[i].name.len, (const char *)m.sess[i].name.p);
                r->sess[i].name = (imdbw_text){(const uint8_t *)r->sname[i], m.sess[i].name.len};
            }
            return IMDB_OK;
        case IMDBW_READY: r->state = m.state; return IMDB_OK;
        default: break;
        }
    }
}

static int q1(imdbc *c, const char *sql, reply *r)
{
    imdbc_stmt st = {sql, strlen(sql), NULL, 0};
    imdb_err e = {0};
    if (imdbc_query(c, &st, 1, &e)) { /* (D34: never a reply left as the stack held it) */
        memset(r, 0, sizeof *r);
        r->rc = e.code;
        snprintf(r->err, sizeof r->err, "%s", e.msg);
        return e.code;
    }
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
    /* every refusal one path: a wrong password, an unknown name, a role without LOGIN, without a verifier (2c: a role
     * that is not a superuser logs in where the database has a memory budget: server_logins_budget) */
    static const char *const bad[][2] = {{"admin", "wrong"}, {"ghost", "pw"}, {"nologin", "pw"}, {"nopass", "x"}};
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
    /* the counts as the connections' threads keep them: the last refusals are counted by threads that may still be
     * finishing when the client has moved on (a heavy load showed it), so waited for, never read at once */
    for (int w = 0; w < 1000; w++) {
        imdbs_counts_get(s, &cn);
        if (cn.logins == 1 && cn.refusals == 4 + 4) break;
        usleep(10000);
    }
    SOFT(cn.logins == 1 && cn.refusals == 4 + 4);
    unserve(db, s);
}

static void t_server_statements(void)
{
    imdbs *s;
    imdb_db *db = serve(&s, NULL);
    CHECK(db);
    imdbc *c = login("admin", "pw-admin");
    CHECK(c);
    reply r = {0};
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
    /* N1d: COPY through the server, both ways (its own tests: server_copy_*) */
    SOFT(q1(c, "COPY t FROM STDIN", &r) == 0 && r.copy_in && !r.nerr);
    SOFT(imdbc_copy_data(c, "7,\"seven\",7.5\n", 14, &e) == 0 && imdbc_copy_done(c, &e) == 0 && read_reply(c, &r) == 0 &&
         r.ndone == 1 && r.count == 1 && !r.nerr);
    SOFT(q1(c, "COPY (SELECT id, s FROM t WHERE id = 7) TO STDOUT", &r) == 0 && !r.nerr && r.nout == 8 && r.count == 1);
    SOFT(q1(c, "DELETE FROM t WHERE id = 7", &r) == 0 && r.count == 1);
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
    reply three[3] = {{0}};
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
    reply r = {0};
    SOFT(q1(a, "CREATE TABLE t (id INT64 PRIMARY KEY, v INT64)", &r) == 0);
    SOFT(q1(a, "INSERT INTO t VALUES (1, 0)", &r) == 0 && !r.nerr);
    SOFT(q1(a, "BEGIN", &r) == 0 && r.state == IMDBW_IN_TXN);
    SOFT(q1(b, "BEGIN", &r) == 0 && r.state == IMDBW_IN_TXN);
    SOFT(q1(a, "UPDATE t SET v = 1 WHERE id = 1", &r) == 0 && !r.nerr && r.state == IMDBW_IN_TXN && !r.has_write);
    reply rb = {0};
    SOFT(q1(b, "UPDATE t SET v = 2 WHERE id = 1", &rb) == 0);
    SOFT(q1(a, "COMMIT", &r) == 0 && !r.nerr && r.state == IMDBW_IDLE && r.has_write);
    reply rc2 = {0};
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
    reply r = {0};
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
    reply r = {0};
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
    reply r = {0};
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
    reply r = {0};
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
    reply r = {0};
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
    reply r = {0};
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
    reply r = {0};
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
    reply r = {0};
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
    reply r = {0};
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
    reply r = {0};
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
    reply r = {0};
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
    reply r = {0};
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
    reply r = {0};
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
        execl(bin, bin, dbdir, "--socket", g_sock, "--server-dir", sdir, "--nosync", "--mem-limit", "768M", "--seg-cache", "96M",
              "--disk-headroom", "0", (char *)NULL); /* N1e stage two: the budget and the images reach the handle (SHOW MEMORY
                                                       * below); 2b-3: no headroom (the tests' file system may be near full) */
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
        reply r = {0};
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
    snprintf(g_dbdir, sizeof g_dbdir, "%s", dbdir);
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
    reply mr = {0};
    SOFT(dc && q1(dc, "SHOW MEMORY", &mr) == 0 && strstr(mr.status, "budget 805306368") && strstr(mr.status, "budget 100663296"));
    if (!strstr(mr.status, "budget 805306368")) fprintf(stderr, "    SHOW MEMORY: %d %s %s\n", mr.rc, mr.err, mr.status);
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
        reply rr = {0};
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
    reply r = {0};
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
    reply r = {0};
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
/* ---- N1d: COPY through the server (docs/n1-design.md §8d) ---- */

/* sql (a COPY ... FROM STDIN) sent and its COPY_IN read; then data sent in pieces of piece bytes (0: as one), its end,
 * and the statement's replies read to READY into r. Without a COPY_IN (an ERROR came instead), r holds that reply */
static int copy_in(imdbc *c, const char *sql, const void *data, size_t n, size_t piece, reply *r)
{
    imdb_err e = {0};
    imdbc_stmt st = {sql, strlen(sql), NULL, 0};
    if (imdbc_query(c, &st, 1, &e)) return e.code;
    if (read_reply(c, r)) return r->rc;
    if (!r->copy_in) return IMDB_OK;
    const uint8_t *p = data;
    if (!piece) piece = n ? n : 1;
    while (n) {
        size_t k = n < piece ? n : piece;
        if (imdbc_copy_data(c, p, k, &e)) return e.code;
        p += k, n -= k;
    }
    if (imdbc_copy_done(c, &e)) return e.code;
    return read_reply(c, r);
}

/* rows id, name, v for ids [from, to): CSV as COPY TO writes it (a field quoted only when it must be), so COPY TO's output
 * of them is these bytes */
static size_t make_rows(char *d, size_t cap, int from, int to)
{
    size_t n = 0;
    for (int i = from; i < to && n + 64 < cap; i++) n += (size_t)snprintf(d + n, cap - n, "%d,name %d,%d\n", i, i * 7, i % 97);
    return n;
}

/* the same with names ~200 bytes long: megabytes from few rows (a load under the sanitizers stays quick) */
static size_t make_wide_rows(char *d, size_t cap, int from, int to)
{
    static const char pad[] = "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrst"
                              "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrst";
    size_t n = 0;
    for (int i = from; i < to && n + 300 < cap; i++)
        n += (size_t)snprintf(d + n, cap - n, "%d,name %d %s,%d\n", i, i * 7, pad, i % 97);
    return n;
}

static uint64_t spool_held(imdbs *s)
{
    imdbs_counts cn;
    imdbs_counts_get(s, &cn);
    return cn.spool_held;
}

/* until the server's spools hold want bytes (10 s at most) */
static bool wait_held(imdbs *s, uint64_t want)
{
    for (int k = 0; k < 1000; k++) {
        if (spool_held(s) == want) return true;
        usleep(10000);
    }
    return false;
}

typedef struct capbuf {
    uint8_t *p;
    size_t n, cap;
} capbuf;

static int cap_wr(void *arg, const char *b, size_t n)
{
    capbuf *k = arg;
    if (k->n + n > k->cap) return -1;
    memcpy(k->p + k->n, b, n);
    k->n += n;
    return 0;
}

/* the embedded engine's COPY TO of sql on the database at dbdir (the server stopped): its bytes into k */
static bool embedded_copy_to(const char *sql, capbuf *k)
{
    const char *dbdir = g_dbdir;
    imdb_err e = {0};
    imdb_open_opts o = {.sync = 0};
    imdb_db *db = NULL;
    if (imdb_open(dbdir, &o, &db, &e)) {
        fprintf(stderr, "    reopen %s: %s\n", dbdir, e.msg);
        return false;
    }
    imdb_session ss;
    imdb_session_init(&ss, db);
    imdb_session_copy_io(&ss, NULL, cap_wr, k);
    imdb_result r;
    int rc = imdb_exec_one(&ss, sql, strlen(sql), NULL, 0, &r, &e);
    imdb_result_free(&r);
    imdb_session_close(&ss);
    imdb_close(db);
    if (rc) fprintf(stderr, "    %s: %s\n", sql, e.msg);
    return rc == 0;
}

/* COPY ... FROM STDIN through the server: no data, one byte a frame, pieces cutting rows, megabytes in 1 MiB frames;
 * COPY TO of the table and of a query, byte for byte the embedded engine's on the same database once the server stops */
static void t_server_copy_in(void)
{
    imdbs *s;
    imdb_db *db = serve(&s, NULL);
    CHECK(db);
    imdbc *c = login("admin", "pw-admin");
    CHECK(c);
    reply r = {0};
    SOFT(q1(c, "CREATE TABLE t (id INT64 PRIMARY KEY, name TEXT, v INT64)", &r) == 0 && !r.nerr);
    size_t cap = 8u << 20;
    char *d = malloc(cap);
    CHECK(d);
    SOFT(copy_in(c, "COPY t FROM STDIN", "", 0, 0, &r) == 0 && r.ndone == 1 && !r.nerr && r.count == 0);
    size_t n = make_rows(d, cap, 0, 100);
    SOFT(copy_in(c, "COPY t FROM STDIN", d, n, 1, &r) == 0 && r.ndone == 1 && !r.nerr && r.count == 100); /* a byte a frame */
    n = make_rows(d, cap, 100, 50100);
    SOFT(copy_in(c, "COPY t FROM STDIN", d, n, 4093, &r) == 0 && r.ndone == 1 && !r.nerr && r.count == 50000);
    n = make_rows(d, cap, 50100, 250100); /* ~5 MB: 1 MiB frames */
    SOFT(n > (4u << 20));
    SOFT(copy_in(c, "COPY t FROM STDIN", d, n, 0, &r) == 0 && r.ndone == 1 && !r.nerr && r.count == 200000);
    long long sum = 0;
    for (int i = 0; i < 250100; i++) sum += i % 97;
    char want[64];
    snprintf(want, sizeof want, "250100|%lld\n", sum);
    SOFT(q1(c, "SELECT COUNT(*), SUM(v) FROM t", &r) == 0 && !strcmp(r.text, want));
    SOFT(q1(c, "SELECT name FROM t WHERE id = 123456", &r) == 0 && !strcmp(r.text, "name 864192\n"));
    /* COPY TO through the server, then the same through the embedded engine */
    g_out = malloc(cap), g_outcap = cap, g_outlen = 0;
    CHECK(g_out);
    SOFT(q1(c, "COPY t TO STDOUT", &r) == 0 && r.ndone == 1 && !r.nerr && r.count == 250100 && r.nout == g_outlen);
    SOFT(!strcmp(r.seq, "OD"));
    size_t whole = g_outlen;
    uint8_t *got = g_out;
    g_out = malloc(1u << 20), g_outcap = 1u << 20, g_outlen = 0;
    CHECK(g_out);
    SOFT(q1(c, "COPY (SELECT id, v FROM t WHERE id < 1000 ORDER BY id DESC) TO STDOUT", &r) == 0 && r.count == 1000);
    size_t qlen = g_outlen;
    uint8_t *qgot = g_out;
    g_out = NULL;
    imdbs_counts cn;
    imdbs_counts_get(s, &cn);
    SOFT(cn.copy_in == 4 && cn.copy_out == 2 && cn.spool_held == 0);
    imdbc_close(c);
    unserve(db, s);
    SOFT(imdbsp_live() == 0);
    capbuf k = {malloc(cap), 0, cap};
    CHECK(k.p);
    SOFT(embedded_copy_to("COPY t TO STDOUT", &k) && k.n == whole && !memcmp(k.p, got, whole));
    k.n = 0;
    SOFT(embedded_copy_to("COPY (SELECT id, v FROM t WHERE id < 1000 ORDER BY id DESC) TO STDOUT", &k) && k.n == qlen &&
         !memcmp(k.p, qgot, qlen));
    free(k.p);
    free(got);
    free(qgot);
    free(d);
}

/* COPY TO past its ring (64 KiB): read at once, whole and in order within a batch; not read, its wait bound passed:
 * LIMIT after a prefix, the connection usable */
static void t_server_copy_out(void)
{
    imdbs_opts so;
    memset(&so, 0, sizeof so);
    so.copy_ring = 64u << 10, so.copy_wait_ms = 300;
    imdbs *s;
    imdb_db *db = serve(&s, &so);
    CHECK(db);
    imdbc *c = login("admin", "pw-admin");
    CHECK(c);
    reply r = {0};
    SOFT(q1(c, "CREATE TABLE t (id INT64 PRIMARY KEY, name TEXT, v INT64)", &r) == 0 && !r.nerr);
    size_t cap = 32u << 20; /* (TCP's loopback buffers hold megabytes: the output must pass them and the ring) */
    char *d = malloc(cap);
    CHECK(d);
    size_t n = make_wide_rows(d, cap, 0, 100000); /* ~23 MB */
    SOFT(copy_in(c, "COPY t FROM STDIN", d, n, 0, &r) == 0 && r.count == 100000);
    g_out = (uint8_t *)malloc(cap), g_outcap = cap, g_outlen = 0;
    CHECK(g_out);
    imdbc_stmt st[3] = {{"SELECT 1", 8, NULL, 0}, {"COPY t TO STDOUT", 16, NULL, 0}, {"SELECT 2", 8, NULL, 0}};
    imdb_err e = {0};
    SOFT(imdbc_query(c, st, 3, &e) == 0 && read_reply(c, &r) == 0);
    SOFT(!strcmp(r.seq, "CRDODCRD") && r.ndone == 3 && !r.nerr && g_outlen == n && !memcmp(g_out, d, n)); /* the order */
    /* not read: the engine fills the ring, waits 300 ms in all, then fails the statement */
    SOFT(imdbc_query(c, &st[1], 1, &e) == 0);
    usleep(1500000);
    g_outlen = 0;
    SOFT(read_reply(c, &r) == 0 && r.nerr == 1 && r.err_code == (uint32_t)-IMDB_ERR_LIMIT && strstr(r.err, "--copy-ring") &&
         g_outlen < n && !memcmp(g_out, d, g_outlen)); /* a prefix, then the ERROR */
    SOFT(q1(c, "SELECT COUNT(*) FROM t", &r) == 0 && !strcmp(r.text, "100000\n"));
    /* read slowly but always taking some, each gap (50 ms) under the bound and their sum past it: the bound is the
     * statement's, so LIMIT all the same (one per write would let it run on at the reader's pace) */
    SOFT(imdbc_query(c, &st[1], 1, &e) == 0);
    bool limit = false, done = false;
    for (int k = 0; k < 4000 && !limit && !done; k++) {
        imdbw_msg m;
        if (imdbc_next(c, &m, &e)) break;
        limit = m.type == IMDBW_ERROR && m.code == (uint32_t)-IMDB_ERR_LIMIT;
        done = m.type == IMDBW_DONE;
        usleep(50000);
    }
    SOFT(limit && !done && read_reply(c, &r) == 0 && !r.nerr); /* (its READY) */
    SOFT(q1(c, "SELECT COUNT(*) FROM t", &r) == 0 && !strcmp(r.text, "100000\n"));
    imdbs_counts cn;
    imdbs_counts_get(s, &cn);
    SOFT(cn.copy_limits == 2 && cn.copy_waits > 0 && cn.spool_held == 0);
    free(g_out);
    g_out = NULL;
    free(d);
    imdbc_close(c);
    unserve(db, s);
    SOFT(imdbsp_live() == 0);
}

/* the refusals: COPY_FAIL; bad data (after COPY_DONE); the spool's bound (at once); a failed spool write; CANCEL while
 * the data arrives; no spool directory; the O_TMPFILE path refused (the named file, unlinked at once): each answered,
 * the table unchanged, the connection usable, nothing held */
static void t_server_copy_refusals(void)
{
    imdbs_opts so;
    memset(&so, 0, sizeof so);
    so.copy_spool = 1u << 20;
    imdbs *s;
    imdb_db *db = serve(&s, &so);
    CHECK(db);
    imdbc *c = login("admin", "pw-admin");
    CHECK(c);
    reply r = {0};
    imdb_err e = {0};
    SOFT(q1(c, "CREATE TABLE t (id INT64 PRIMARY KEY, name TEXT, v INT64)", &r) == 0 && !r.nerr);
    size_t cap = 4u << 20;
    char *d = malloc(cap);
    CHECK(d);
    size_t n = make_rows(d, cap, 0, 1000);
    imdbc_stmt cp = {"COPY t FROM STDIN", 17, NULL, 0};
    /* COPY_FAIL */
    SOFT(imdbc_query(c, &cp, 1, &e) == 0 && read_reply(c, &r) == 0 && r.copy_in);
    SOFT(imdbc_copy_data(c, d, n, &e) == 0 && imdbc_copy_fail(c, "the operator stopped it", &e) == 0);
    SOFT(read_reply(c, &r) == 0 && r.nerr == 1 && r.err_code == (uint32_t)-IMDB_ERR_CANCELLED &&
         strstr(r.err, "failed by its client: the operator stopped it"));
    SOFT(q1(c, "SELECT COUNT(*) FROM t", &r) == 0 && !strcmp(r.text, "0\n"));
    /* bad data: the error after COPY_DONE, nothing written */
    const char *bad = "1,\"a\",1\n2,\"b\",x\n";
    SOFT(copy_in(c, "COPY t FROM STDIN", bad, strlen(bad), 0, &r) == 0 && r.nerr == 1 && strstr(r.err, "line 2"));
    SOFT(q1(c, "SELECT COUNT(*) FROM t", &r) == 0 && !strcmp(r.text, "0\n"));
    /* the bound (1 MiB): 3 MiB sent, refused at once (the ERROR may come while the client still sends) */
    n = make_rows(d, cap, 0, 150000);
    SOFT(n > (3u << 20) - 400000);
    SOFT(copy_in(c, "COPY t FROM STDIN", d, n, 65536, &r) == 0 && r.nerr == 1 && r.err_code == (uint32_t)-IMDB_ERR_LIMIT &&
         strstr(r.err, "--copy-spool"));
    SOFT(q1(c, "SELECT COUNT(*) FROM t", &r) == 0 && !strcmp(r.text, "0\n") && spool_held(s) == 0);
    /* a failed spool write (the hook: the open, then the first write) */
    n = make_rows(d, cap, 0, 100);
    imdbsp_fail_at(2);
    SOFT(copy_in(c, "COPY t FROM STDIN", d, n, 0, &r) == 0 && r.nerr == 1 && r.err_code == (uint32_t)-IMDB_ERR_IO);
    imdbsp_fail_at(0);
    SOFT(q1(c, "SELECT COUNT(*) FROM t", &r) == 0 && !strcmp(r.text, "0\n") && spool_held(s) == 0);
    /* CANCEL while the data arrives: answered at once; the client ends its COPY; the next request answered */
    SOFT(imdbc_query(c, &cp, 1, &e) == 0 && read_reply(c, &r) == 0 && r.copy_in);
    SOFT(imdbc_copy_data(c, d, n, &e) == 0);
    imdbc_cancel(c);
    SOFT(read_reply(c, &r) == 0 && r.nerr == 1 && r.err_code == (uint32_t)-IMDB_ERR_CANCELLED && strstr(r.err, "never ran"));
    SOFT(imdbc_copy_data(c, d, n, &e) == 0 && imdbc_copy_done(c, &e) == 0); /* the rest dropped, to its end */
    SOFT(q1(c, "SELECT COUNT(*) FROM t", &r) == 0 && !strcmp(r.text, "0\n") && spool_held(s) == 0);
    /* a spool read failed: COPY FROM's (the engine's read: the statement fails, nothing written) */
    imdbsp_fail_at(3); /* its open, its one write, then the read */
    SOFT(copy_in(c, "COPY t FROM STDIN", d, n, 0, &r) == 0 && r.nerr == 1 && r.err_code == (uint32_t)-IMDB_ERR_IO);
    imdbsp_fail_at(0);
    SOFT(q1(c, "SELECT COUNT(*) FROM t", &r) == 0 && !strcmp(r.text, "0\n") && spool_held(s) == 0);
    /* and COPY TO's (its connection's read of the ring: the connection ends, never a stream cut short and a DONE) */
    SOFT(q1(c, "CREATE TABLE t2 (id INT64 PRIMARY KEY)", &r) == 0 && q1(c, "INSERT INTO t2 VALUES (1), (2), (3)", &r) == 0);
    {
        imdbc *x = login("admin", "pw-admin");
        CHECK(x);
        imdbsp_fail_at(3); /* the engine's open and its one write, then the connection's read */
        uint64_t t0 = imdb_mono_ns();
        SOFT(q1(x, "COPY t2 TO STDOUT", &r) != 0 && r.ndone == 0);
        SOFT((imdb_mono_ns() - t0) / 1000000u < 5000); /* closed at once, never a hang to the client's timeout */
        imdbsp_fail_at(0);
        imdbc_close(x);
        SOFT(wait_held(s, 0));
    }
    /* a request, or TERMINATE, while the data is expected: a protocol error (§4), the connection closed, nothing held */
    for (int k = 0; k < 2; k++) {
        imdbc *x = login("admin", "pw-admin");
        CHECK(x);
        SOFT(imdbc_query(x, &cp, 1, &e) == 0 && read_reply(x, &r) == 0 && r.copy_in);
        SOFT(imdbc_copy_data(x, d, n, &e) == 0);
        imdbc_stmt one = {"SELECT 1", 8, NULL, 0};
        SOFT((k ? imdbc_terminate(x, &e) : imdbc_query(x, &one, 1, &e)) == 0);
        SOFT(read_reply(x, &r) != 0 && r.nerr == 1 && strstr(r.err, "COPY's data was expected"));
        imdbc_close(x);
        SOFT(wait_held(s, 0));
    }
    /* the named fallback: the file unlinked at once, the directory empty while it is held */
    imdbsp_no_tmpfile(true);
    SOFT(imdbc_query(c, &cp, 1, &e) == 0 && read_reply(c, &r) == 0 && r.copy_in);
    SOFT(imdbc_copy_data(c, d, n, &e) == 0 && wait_held(s, n));
    DIR *dp = opendir(g_spool);
    int names = 0;
    for (struct dirent *de; dp && (de = readdir(dp));) names += de->d_name[0] != '.';
    if (dp) closedir(dp);
    SOFT(dp && names == 0 && imdbsp_live() == 1);
    SOFT(imdbc_copy_done(c, &e) == 0 && read_reply(c, &r) == 0 && r.count == 100 && !r.nerr);
    imdbsp_no_tmpfile(false);
    imdbc_close(c);
    unserve(db, s);
    /* no spool directory: COPY refused by name both ways, before any COPY_IN (on the socket alone: over TCP the
     * certificate's server directory always gives one) */
    if (g_tcp) {
        free(d);
        return;
    }
    g_nospool = true;
    db = serve(&s, NULL);
    CHECK(db);
    c = login("admin", "pw-admin");
    CHECK(c);
    SOFT(q1(c, "CREATE TABLE t (id INT64 PRIMARY KEY)", &r) == 0 && !r.nerr);
    SOFT(copy_in(c, "COPY t FROM STDIN", "1\n", 2, 0, &r) == 0 && !r.copy_in && r.nerr == 1 && strstr(r.err, "spool directory"));
    SOFT(q1(c, "INSERT INTO t VALUES (1)", &r) == 0 && !r.nerr); /* (COPY TO refuses at its first bytes) */
    SOFT(q1(c, "COPY t TO STDOUT", &r) == 0 && r.nerr == 1 && strstr(r.err, "spool directory"));
    SOFT(q1(c, "SELECT COUNT(*) FROM t", &r) == 0 && !strcmp(r.text, "1\n"));
    imdbc_close(c);
    unserve(db, s);
    SOFT(imdbsp_live() == 0);
    free(d);
}

/* COPY in a transaction (rolled back, committed), BATCH; an upload longer than idle_in_transaction_timeout (the
 * transaction never idle) and than transaction_timeout (doomed: the COPY refused, only ROLLBACK ends it) */
static void t_server_copy_txn(void)
{
    imdbs *s;
    imdb_db *db = serve(&s, NULL);
    CHECK(db);
    imdbc *c = login("admin", "pw-admin");
    CHECK(c);
    reply r = {0};
    imdb_err e = {0};
    SOFT(q1(c, "CREATE TABLE t (id INT64 PRIMARY KEY, name TEXT, v INT64)", &r) == 0 && !r.nerr);
    char d[16384];
    size_t n = make_rows(d, sizeof d, 0, 200);
    SOFT(q1(c, "BEGIN", &r) == 0 && copy_in(c, "COPY t FROM STDIN", d, n, 0, &r) == 0 && r.count == 200);
    SOFT(q1(c, "ROLLBACK", &r) == 0 && q1(c, "SELECT COUNT(*) FROM t", &r) == 0 && !strcmp(r.text, "0\n"));
    SOFT(q1(c, "BEGIN", &r) == 0 && copy_in(c, "COPY t FROM STDIN", d, n, 0, &r) == 0 && r.count == 200);
    SOFT(q1(c, "COMMIT", &r) == 0 && q1(c, "SELECT COUNT(*) FROM t", &r) == 0 && !strcmp(r.text, "200\n"));
    n = make_rows(d, sizeof d, 200, 400);
    SOFT(copy_in(c, "COPY t FROM STDIN (BATCH 30)", d, n, 0, &r) == 0 && r.count == 200 && !r.nerr);
    SOFT(q1(c, "SELECT COUNT(*) FROM t", &r) == 0 && !strcmp(r.text, "400\n"));
    /* idle_in_transaction_timeout 300 ms, an upload of 1.2 s in pieces 100 ms apart: the transaction never idle */
    n = make_rows(d, sizeof d, 400, 412);
    imdbc_stmt cp = {"COPY t FROM STDIN", 17, NULL, 0};
    SOFT(q1(c, "SET idle_in_transaction_timeout = 300", &r) == 0 && !r.nerr && q1(c, "BEGIN", &r) == 0);
    SOFT(imdbc_query(c, &cp, 1, &e) == 0 && read_reply(c, &r) == 0 && r.copy_in);
    for (size_t k = 0; k < 12; k++) {
        SOFT(imdbc_copy_data(c, d + k * (n / 12), k == 11 ? n - 11 * (n / 12) : n / 12, &e) == 0);
        usleep(100000);
    }
    SOFT(imdbc_copy_done(c, &e) == 0 && read_reply(c, &r) == 0 && !r.nerr && r.count == 12);
    SOFT(q1(c, "COMMIT", &r) == 0 && !r.nerr && q1(c, "SELECT COUNT(*) FROM t", &r) == 0 && !strcmp(r.text, "412\n"));
    /* transaction_timeout 300 ms: its age still counts; doomed during the upload, the COPY refused, ROLLBACK ends it */
    n = make_rows(d, sizeof d, 412, 424);
    SOFT(q1(c, "SET idle_in_transaction_timeout = 0", &r) == 0 && q1(c, "SET transaction_timeout = 300", &r) == 0);
    SOFT(q1(c, "BEGIN", &r) == 0 && imdbc_query(c, &cp, 1, &e) == 0 && read_reply(c, &r) == 0 && r.copy_in);
    SOFT(imdbc_copy_data(c, d, n, &e) == 0);
    usleep(800000);
    SOFT(imdbc_copy_done(c, &e) == 0 && read_reply(c, &r) == 0 && r.nerr == 1 && strstr(r.err, "transaction timeout"));
    SOFT(q1(c, "ROLLBACK", &r) == 0 && !r.nerr && q1(c, "SELECT COUNT(*) FROM t", &r) == 0 && !strcmp(r.text, "412\n"));
    imdbc_close(c);
    unserve(db, s);
}

/* a client that leaves mid-upload (its spool freed at once), one that leaves its COPY TO unread, and the stop with a
 * COPY spooling: nothing held, nothing left open, the stop prompt */
static void t_server_copy_gone(void)
{
    imdbs_opts so;
    memset(&so, 0, sizeof so);
    so.copy_ring = 64u << 10;
    imdbs *s;
    imdb_db *db = serve(&s, &so);
    CHECK(db);
    imdbc *c = login("admin", "pw-admin");
    CHECK(c);
    reply r = {0};
    imdb_err e = {0};
    SOFT(q1(c, "CREATE TABLE t (id INT64 PRIMARY KEY, name TEXT, v INT64)", &r) == 0 && !r.nerr);
    size_t cap = 4u << 20;
    char *d = malloc(cap);
    CHECK(d);
    size_t n = make_rows(d, cap, 0, 100000);
    SOFT(copy_in(c, "COPY t FROM STDIN", d, n, 0, &r) == 0 && r.count == 100000);
    imdbc_stmt cp = {"COPY t FROM STDIN", 17, NULL, 0};
    imdbc *a = login("admin", "pw-admin");
    CHECK(a);
    SOFT(imdbc_query(a, &cp, 1, &e) == 0 && read_reply(a, &r) == 0 && r.copy_in);
    SOFT(imdbc_copy_data(a, d, n, &e) == 0 && wait_held(s, n));
    imdbc_close(a); /* gone mid-upload */
    SOFT(wait_held(s, 0) && imdbsp_live() == 0);
    imdbc *b = login("admin", "pw-admin");
    CHECK(b);
    imdbc_stmt to = {"COPY t TO STDOUT", 16, NULL, 0};
    SOFT(imdbc_query(b, &to, 1, &e) == 0);
    usleep(200000); /* its ring full, the engine waiting */
    imdbc_close(b);
    SOFT(wait_held(s, 0));
    SOFT(q1(c, "SELECT COUNT(*) FROM t", &r) == 0 && !strcmp(r.text, "100000\n")); /* the engine answers again */
    imdbc *k = login("admin", "pw-admin");
    CHECK(k);
    SOFT(imdbc_query(k, &cp, 1, &e) == 0 && read_reply(k, &r) == 0 && r.copy_in);
    SOFT(imdbc_copy_data(k, d, 1000, &e) == 0 && wait_held(s, 1000));
    uint64_t t0 = imdb_mono_ns();
    imdbc_close(c);
    SOFT(imdbs_stop(s, &e) == 0); /* a COPY spooling (k's, open past the stop): the stop never waits for it */
    SOFT((imdb_mono_ns() - t0) / 1000000u < 5000);
    SOFT(imdbsp_live() == 0);
    imdbc_close(k);
    imdb_close(db);
    SOFT(imdbw_live_blocks() == g_blocks);
    free(d);
}

/* a COPY whose data stops for copy_idle_ms (300) ends its connection, its ERROR first; nothing held */
static void t_server_copy_idle(void)
{
    imdbs_opts so;
    memset(&so, 0, sizeof so);
    so.copy_idle_ms = 300;
    imdbs *s;
    imdb_db *db = serve(&s, &so);
    CHECK(db);
    imdbc *c = login("admin", "pw-admin");
    CHECK(c);
    reply r = {0};
    imdb_err e = {0};
    SOFT(q1(c, "CREATE TABLE t (id INT64 PRIMARY KEY, name TEXT, v INT64)", &r) == 0 && !r.nerr);
    char d[4096];
    size_t n = make_rows(d, sizeof d, 0, 50);
    imdbc_stmt cp = {"COPY t FROM STDIN", 17, NULL, 0};
    SOFT(imdbc_query(c, &cp, 1, &e) == 0 && read_reply(c, &r) == 0 && r.copy_in);
    SOFT(imdbc_copy_data(c, d, n, &e) == 0);
    usleep(1200000);
    SOFT(read_reply(c, &r) != 0 && r.nerr == 1 && strstr(r.err, "stopped arriving")); /* its ERROR, then the close */
    imdbs_counts cn;
    imdbs_counts_get(s, &cn);
    SOFT(cn.copy_idle == 1 && wait_held(s, 0));
    imdbc_close(c);
    unserve(db, s);
    SOFT(imdbsp_live() == 0);
}

typedef struct trickler {
    imdbc *c;
    const char *d;
    size_t n;
    atomic_bool done;    /* its COPY_DONE sent */
    atomic_bool release; /* its last piece held until the test lets it go (never a clock) */
    int rc;
} trickler;

static void *trickle(void *arg)
{
    trickler *t = arg;
    imdb_err e = {0};
    for (size_t k = 0; k < 10 && !t->rc; k++) {
        size_t part = k == 9 ? t->n - 9 * (t->n / 10) : t->n / 10;
        while (k == 9 && !atomic_load(&t->release)) usleep(1000);
        t->rc = imdbc_copy_data(t->c, t->d + k * (t->n / 10), part, &e);
        usleep(100000);
    }
    atomic_store(&t->done, true);
    if (!t->rc) t->rc = imdbc_copy_done(t->c, &e);
    return NULL;
}

/* the engine never waits on a client's network: another client's statements answered while one trickles its COPY's
 * data, and while another leaves its COPY TO (held whole in its ring) unread */
static void t_server_copy_fair(void)
{
    imdbs_opts so;
    memset(&so, 0, sizeof so);
    so.copy_ring = 8u << 20;
    imdbs *s;
    imdb_db *db = serve(&s, &so);
    CHECK(db);
    imdbc *a = login("admin", "pw-admin"), *b = login("admin", "pw-admin");
    CHECK(a && b);
    reply r = {0};
    imdb_err e = {0};
    SOFT(q1(b, "CREATE TABLE t (id INT64 PRIMARY KEY, name TEXT, v INT64)", &r) == 0 && !r.nerr);
    size_t cap = 4u << 20;
    char *d = malloc(cap);
    CHECK(d);
    size_t n = make_rows(d, cap, 0, 50000);
    imdbc_stmt cp = {"COPY t FROM STDIN", 17, NULL, 0};
    SOFT(imdbc_query(a, &cp, 1, &e) == 0 && read_reply(a, &r) == 0 && r.copy_in);
    trickler t = {.c = a, .d = d, .n = n};
    pthread_t th;
    CHECK(pthread_create(&th, NULL, trickle, &t) == 0);
    int answered = 0;
    for (int i = 0; i < 20; i++) answered += q1(b, "SELECT COUNT(*) FROM t", &r) == 0 && !strcmp(r.text, "0\n");
    SOFT(answered == 20 && !atomic_load(&t.done)); /* all twenty while the upload went on (its last piece held) */
    atomic_store(&t.release, true);
    pthread_join(th, NULL);
    SOFT(t.rc == 0 && read_reply(a, &r) == 0 && r.count == 50000 && !r.nerr);
    /* a COPY TO left unread: its output (~1.2 MB) whole in its ring, the engine free for b */
    g_out = malloc(cap), g_outcap = cap, g_outlen = 0;
    CHECK(g_out);
    imdbc_stmt to = {"COPY t TO STDOUT", 16, NULL, 0};
    SOFT(imdbc_query(a, &to, 1, &e) == 0);
    usleep(300000);
    answered = 0;
    for (int i = 0; i < 20; i++) answered += q1(b, "SELECT COUNT(*) FROM t", &r) == 0 && !strcmp(r.text, "50000\n");
    imdbs_counts cn;
    imdbs_counts_get(s, &cn);
    SOFT(answered == 20 && cn.copy_waits == 0);
    SOFT(read_reply(a, &r) == 0 && !r.nerr && r.count == 50000 && g_outlen == n && !memcmp(g_out, d, n));
    free(g_out);
    g_out = NULL;
    free(d);
    imdbc_close(a);
    imdbc_close(b);
    unserve(db, s);
}

/* a COPY TO whose output comes slowly (the test's hold: 700 ms between its writes): its ring empty between writes is no
 * reply waiting, so a send_timeout of 300 ms never drops its client, which reads all of it */
static void t_server_copy_slow_output(void)
{
    imdbs_opts so;
    memset(&so, 0, sizeof so);
    so.send_timeout_ms = 300;
    imdbs *s;
    imdb_db *db = serve(&s, &so);
    CHECK(db);
    imdbc *c = login("admin", "pw-admin");
    CHECK(c);
    reply r = {0};
    SOFT(q1(c, "CREATE TABLE t (id INT64 PRIMARY KEY, name TEXT, v INT64)", &r) == 0 && !r.nerr);
    size_t cap = 1u << 20;
    char *d = malloc(cap);
    CHECK(d);
    size_t n = make_rows(d, cap, 0, 12000); /* ~240 KB: four writes of COPY's 64 KiB buffer */
    SOFT(n > 3 * 65536 && copy_in(c, "COPY t FROM STDIN", d, n, 0, &r) == 0 && r.count == 12000);
    g_out = malloc(cap), g_outcap = cap, g_outlen = 0;
    CHECK(g_out);
    imdbs_test_copy_hold(700);
    SOFT(q1(c, "COPY t TO STDOUT", &r) == 0 && !r.nerr && r.count == 12000 && g_outlen == n && !memcmp(g_out, d, n));
    imdbs_test_copy_hold(0);
    imdbs_counts cn;
    imdbs_counts_get(s, &cn);
    SOFT(cn.dropped == 0);
    free(g_out);
    g_out = NULL;
    free(d);
    imdbc_close(c);
    unserve(db, s);
}

/* the generated rows of the measurement: ids from next, in pieces of up to cap bytes */
typedef struct rowgen {
    int next, end;
    char *buf;
    size_t len, off;
} rowgen;

static long gen_read(void *arg, char *out, size_t cap)
{
    rowgen *g = arg;
    if (g->off == g->len) {
        if (g->next >= g->end) return 0;
        int to = g->next + 100000 < g->end ? g->next + 100000 : g->end;
        g->len = make_rows(g->buf, 4u << 20, g->next, to), g->off = 0;
        g->next = to;
    }
    size_t k = g->len - g->off < cap ? g->len - g->off : cap;
    memcpy(out, g->buf + g->off, k);
    g->off += k;
    return (long)k;
}

/* the cost of the spool (§8d, recorded): IMDB_SRV_COPY_MB megabytes of rows loaded by COPY through the socket (upload,
 * spool and load, serial) and by the embedded engine into a database of its own beside it; times printed, nothing
 * asserted but that both load every row. Skipped unless IMDB_SRV_COPY_MB is set */
static void t_server_copy_measure(void)
{
    const char *mb = getenv("IMDB_SRV_COPY_MB");
    if (!mb) return;
    int rows = (int)(atol(mb) * 1000000 / 21); /* ~21 bytes a row */
    imdbs *s;
    g_sync = 1;
    imdb_db *db = serve(&s, NULL);
    CHECK(db);
    imdbc *c = login("admin", "pw-admin");
    CHECK(c);
    imdbc_set_timeout(c, 0);
    reply r = {0};
    imdb_err e = {0};
    SOFT(q1(c, "CREATE TABLE t (id INT64 PRIMARY KEY, name TEXT, v INT64)", &r) == 0 && !r.nerr);
    rowgen g = {0, rows, malloc(4u << 20), 0, 0};
    char *piece = malloc(8u << 20);
    CHECK(g.buf && piece);
    imdbc_stmt cp = {"COPY t FROM STDIN (BATCH 100000)", 32, NULL, 0}; /* (a transaction holds 768 MiB at most) */
    uint64_t t0 = imdb_mono_ns();
    SOFT(imdbc_query(c, &cp, 1, &e) == 0 && read_reply(c, &r) == 0 && r.copy_in);
    uint64_t bytes = 0;
    for (long k; (k = gen_read(&g, piece, 8u << 20)) > 0; bytes += (uint64_t)k) SOFT(imdbc_copy_data(c, piece, (size_t)k, &e) == 0);
    uint64_t t1 = imdb_mono_ns();
    SOFT(imdbc_copy_done(c, &e) == 0 && read_reply(c, &r) == 0 && !r.nerr && r.count == (uint64_t)rows);
    uint64_t t2 = imdb_mono_ns();
    imdbc_close(c);
    unserve(db, s);
    char dir[300];
    snprintf(dir, sizeof dir, "%s/embedded", test_tmpdir());
    imdb_open_opts o = {.sync = 1};
    imdb_db *db2 = NULL;
    CHECK(imdb_init(dir, false, NULL, &e) == 0 && imdb_open(dir, &o, &db2, &e) == 0);
    SOFT(sql_run(db2, "CREATE TABLE t (id INT64 PRIMARY KEY, name TEXT, v INT64)") == 0);
    g.next = 0, g.len = g.off = 0;
    imdb_session ss;
    imdb_session_init(&ss, db2);
    imdb_session_copy_io(&ss, gen_read, NULL, &g);
    imdb_result res;
    uint64_t t3 = imdb_mono_ns();
    SOFT(imdb_exec_one(&ss, "COPY t FROM STDIN (BATCH 100000)", 32, NULL, 0, &res, &e) == 0 && res.count == (uint64_t)rows);
    uint64_t t4 = imdb_mono_ns();
    imdb_result_free(&res);
    imdb_session_close(&ss);
    imdb_close(db2);
    fprintf(stderr, "    COPY of %llu bytes (%d rows): through the socket %.2f s (the upload into the spool %.2f s, then the "
                    "load %.2f s); embedded %.2f s\n",
            (unsigned long long)bytes, rows, (double)(t2 - t0) / 1e9, (double)(t1 - t0) / 1e9, (double)(t2 - t1) / 1e9,
            (double)(t4 - t3) / 1e9);
    free(piece);
    free(g.buf);
}

/* the server's spools full (copy_spool exactly one held upload): a COPY TO refused at once, never waiting on another
 * client's upload; queue_max 1, so a COPY's frames are read past a full queue; a CANCEL ends a COPY TO's wait for room
 * at once (copy_wait the default 60 s) */
static void t_server_copy_full(void)
{
    size_t cap = 8u << 20;
    char *d = malloc(cap);
    CHECK(d);
    size_t n = make_wide_rows(d, cap, 0, 20000); /* ~4.6 MB: past the ring and the socket's buffers */
    imdbs_opts so;
    memset(&so, 0, sizeof so);
    so.copy_spool = n, so.queue_max = 1, so.copy_ring = 64u << 10;
    imdbs *s;
    imdb_db *db = serve(&s, &so);
    CHECK(db);
    imdbc *a = login("admin", "pw-admin"), *b = login("admin", "pw-admin");
    CHECK(a && b);
    reply r = {0};
    imdb_err e = {0};
    SOFT(q1(a, "CREATE TABLE t (id INT64 PRIMARY KEY, name TEXT, v INT64)", &r) == 0 && !r.nerr);
    SOFT(copy_in(a, "COPY t FROM STDIN", d, n, 65536, &r) == 0 && r.count == 20000 && !r.nerr); /* past a queue of one */
    imdbc_stmt cp = {"COPY t2 FROM STDIN", 18, NULL, 0};
    SOFT(q1(a, "CREATE TABLE t2 (id INT64 PRIMARY KEY, name TEXT, v INT64)", &r) == 0 && !r.nerr);
    SOFT(imdbc_query(a, &cp, 1, &e) == 0 && read_reply(a, &r) == 0 && r.copy_in);
    SOFT(imdbc_copy_data(a, d, n, &e) == 0 && wait_held(s, n)); /* every byte of the bound held by a's upload */
    uint64_t t0 = imdb_mono_ns();
    SOFT(q1(b, "COPY t TO STDOUT", &r) == 0 && r.nerr == 1 && r.err_code == (uint32_t)-IMDB_ERR_LIMIT &&
         strstr(r.err, "spools are full"));
    SOFT((imdb_mono_ns() - t0) / 1000000u < 5000); /* at once: no wait on a's upload */
    SOFT(imdbc_copy_done(a, &e) == 0 && read_reply(a, &r) == 0 && r.count == 20000 && !r.nerr);
    SOFT(q1(b, "SELECT COUNT(*) FROM t2", &r) == 0 && !strcmp(r.text, "20000\n") && wait_held(s, 0));
    imdbc_close(a);
    imdbc_close(b);
    unserve(db, s);
    /* b's COPY TO, unread past its ring: the engine waits; a CANCEL ends the wait at once. On a server of the default
     * queue: CANCEL is read in band, so a queue of one, full with the COPY TO itself, reads it only once that ends (D32) */
    memset(&so, 0, sizeof so);
    so.copy_ring = 64u << 10;
    db = serve(&s, &so);
    CHECK(db);
    a = login("admin", "pw-admin"), b = login("admin", "pw-admin");
    CHECK(a && b);
    SOFT(q1(a, "CREATE TABLE t (id INT64 PRIMARY KEY, name TEXT, v INT64)", &r) == 0 && !r.nerr);
    SOFT(q1(a, "CREATE TABLE t2 (id INT64 PRIMARY KEY)", &r) == 0 && !r.nerr);
    SOFT(copy_in(a, "COPY t FROM STDIN", d, n, 0, &r) == 0 && r.count == 20000 && !r.nerr);
    SOFT(q1(a, "INSERT INTO t2 SELECT id FROM t", &r) == 0 && r.count == 20000);
    imdbc_stmt to = {"COPY t TO STDOUT", 16, NULL, 0};
    SOFT(imdbc_query(b, &to, 1, &e) == 0);
    usleep(300000);
    /* CANCEL sent as raw bytes, b reading nothing (its ring stays full: no row the engine's own check would reach): the
     * wait itself ends, so a's statement is answered at once */
    imdbw_buf cb;
    imdbw_buf_init(&cb);
    imdbw_msg cm = {.type = IMDBW_CANCEL};
    imdbw_msg_put(&cb, &cm, NULL);
    SOFT(!cb.err && imdbc_send_raw(b, cb.p, cb.len, &e) == 0);
    imdbw_buf_free(&cb);
    t0 = imdb_mono_ns();
    SOFT(q1(a, "SELECT COUNT(*) FROM t2", &r) == 0 && !strcmp(r.text, "20000\n"));
    SOFT((imdb_mono_ns() - t0) / 1000000u < 5000);
    SOFT(read_reply(b, &r) == 0 && r.nerr == 1 && r.err_code == (uint32_t)-IMDB_ERR_CANCELLED); /* a prefix, then it */
    SOFT(q1(b, "SELECT COUNT(*) FROM t2", &r) == 0 && !strcmp(r.text, "20000\n") && wait_held(s, 0));
    imdbc_close(a);
    imdbc_close(b);
    unserve(db, s);
    free(d);
}

/* the server-wide bound (3.5 MiB): three uploads of 1 MiB held at once, a fourth refused at once; the three then run */
static void t_server_copy_bound(void)
{
    imdbs_opts so;
    memset(&so, 0, sizeof so);
    so.copy_spool = (7u << 20) / 2;
    imdbs *s;
    imdb_db *db = serve(&s, &so);
    CHECK(db);
    imdbc *c[4];
    for (int i = 0; i < 4; i++) {
        c[i] = login("admin", "pw-admin");
        CHECK(c[i]);
    }
    reply r = {0};
    imdb_err e = {0};
    SOFT(q1(c[0], "CREATE TABLE t (id INT64 PRIMARY KEY, name TEXT, v INT64)", &r) == 0 && !r.nerr);
    size_t cap = 4u << 20;
    char *d = malloc(cap);
    CHECK(d);
    imdbc_stmt cp = {"COPY t FROM STDIN", 17, NULL, 0};
    size_t len[4];
    uint64_t held = 0;
    for (int i = 0; i < 4; i++) { /* each just under 1 MiB of whole rows: one frame */
        len[i] = make_rows(d + i * (1u << 20), 1u << 20, i * 100000, i * 100000 + 60000);
        SOFT(len[i] > (1u << 20) - 100);
        SOFT(imdbc_query(c[i], &cp, 1, &e) == 0 && read_reply(c[i], &r) == 0 && r.copy_in);
        SOFT(imdbc_copy_data(c[i], d + i * (1u << 20), len[i], &e) == 0);
        if (i < 3) SOFT(wait_held(s, held += len[i]));
    }
    SOFT(read_reply(c[3], &r) == 0 && r.nerr == 1 && r.err_code == (uint32_t)-IMDB_ERR_LIMIT); /* before its end */
    SOFT(imdbc_copy_done(c[3], &e) == 0 && spool_held(s) == held);
    for (int i = 0; i < 3; i++) SOFT(imdbc_copy_done(c[i], &e) == 0 && read_reply(c[i], &r) == 0 && !r.nerr);
    SOFT(q1(c[3], "SELECT COUNT(*) FROM t", &r) == 0 && !r.nerr && spool_held(s) == 0);
    for (int i = 0; i < 4; i++) imdbc_close(c[i]);
    free(d);
    unserve(db, s);
}


static imdbc *login_runs(const char *user, const char *pw); /* (below) */

/* until the server's connection is wholly closed (after its lingering close): on the socket, the client's POLLHUP; over
 * TCP, which gives a client no POLLHUP for its peer's close, the server's own count of that connection's end. 10 s at
 * most (a client's frames are readable at once, so the wait sleeps between its polls) */
static bool server_closed(imdbs *s, imdbc *c, uint64_t ends_before, int cause)
{
    for (int w = 0; c && w < 1000; w++) {
        if (g_tcp) {
            imdbs_counts n;
            imdbs_counts_get(s, &n);
            if (n.ends[cause] > ends_before) return true;
        } else {
            struct pollfd pf = {imdbc_fd(c), POLLIN, 0};
            if (poll(&pf, 1, 10) == 1 && (pf.revents & POLLHUP)) return true;
        }
        usleep(10000);
    }
    return false;
}

static uint64_t ends_of(imdbs *s, int cause)
{
    imdbs_counts n;
    imdbs_counts_get(s, &n);
    return n.ends[cause];
}

/* N1e stage two (the advisor's 02:21 and 14:01 reviews): what a client reports when the server closed the connection. A
 * login refused after its verdict: a statement sent at once reads the refusal as its reply; one sent after the server's
 * whole close (its lingering close ended) fails to send and reports the refusal as the reason (closed_reason: the
 * server's last frame an ERROR). A failing statement and a TERMINATE pipelined unread: the last frame before the close is
 * READY, so a later send's error is the plain one, never that statement's ERROR taken for the reason. On the socket the
 * failed send is asserted itself; over TCP a first write after the peer's close is taken by the kernel, so the client
 * meets the same words, or the plain error, on the read instead (the path is not forced there) */
static void t_server_closed_reason(void)
{
    imdbs_opts o;
    memset(&o, 0, sizeof o);
    o.role_conns = 1;
    imdbs *s = NULL;
    imdb_db *db = serve(&s, &o);
    CHECK(db);
    imdbc *p1 = login_runs("plain", "pw");
    CHECK(p1);
    imdb_err e = {0};
    imdbc_stmt one = {"SELECT 1", 8, NULL, 0};
    for (int order = 0; order < 2; order++) { /* 0: sent before the close is seen; 1: after it */
        uint64_t before = ends_of(s, IMDBS_END_REFUSED);
        imdbc *c = login("plain", "pw");
        SOFT(c != NULL);
        if (!c) continue;
        if (order) {
            SOFT(server_closed(s, c, before, IMDBS_END_REFUSED));
            if (!g_tcp) { /* the send itself fails, and its error is the refusal (closed_reason) */
                imdb_err_clear(&e);
                int rq = imdbc_query(c, &one, 1, &e);
                SOFT(rq == IMDB_ERR_LIMIT && strstr(e.msg, "the server closed the connection: too many connections for this role"));
                if (rq != IMDB_ERR_LIMIT) fprintf(stderr, "    a send after the close: %d %s\n", rq, e.msg);
                imdbc_close(c);
                continue;
            }
        }
        reply r = {0};
        int rc = q1(c, "SELECT 1", &r);
        bool words = strstr(r.err, "too many connections for this role") != NULL;
        SOFT(r.ndone == 0 && words && ((r.nerr == 1 && r.err_code == (uint32_t)-IMDB_ERR_LIMIT) || rc == IMDB_ERR_LIMIT));
        if (!words) fprintf(stderr, "    order %d: rc %d, %u errors, code %u: %s\n", order, rc, r.nerr, r.err_code, r.err);
        imdbc_close(c);
    }
    /* a failing statement and TERMINATE, unread: the server's last frame is READY */
    imdbc *a = login("admin", "pw-admin");
    SOFT(a != NULL);
    if (a) {
        imdbc_stmt bad = {"SELECT 1 / 0", 12, NULL, 0};
        uint64_t before = ends_of(s, IMDBS_END_TERMINATE);
        SOFT(imdbc_query(a, &bad, 1, &e) == 0 && imdbc_terminate(a, &e) == 0);
        SOFT(server_closed(s, a, before, IMDBS_END_TERMINATE));
        imdb_err_clear(&e);
        int rc = imdbc_query(a, &one, 1, &e);
        SOFT(g_tcp || rc != 0); /* the socket: the send itself fails, so closed_reason runs and finds READY last */
        if (rc == 0) { /* (TCP: a send into a closed peer may still be taken by the kernel: the read then fails) */
            imdbw_msg m;
            while ((rc = imdbc_next(a, &m, &e)) == 0) {
            }
        }
        SOFT(rc == IMDB_ERR_IO && !strstr(e.msg, "the server closed the connection"));
        if (rc != IMDB_ERR_IO || strstr(e.msg, "the server closed")) fprintf(stderr, "    after TERMINATE: %d %s\n", rc, e.msg);
        imdbc_close(a);
    }
    imdbc_close(p1);
    unserve(db, s);
}
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
OVER_TCP(t_server_copy_in)
OVER_TCP(t_server_copy_out)
OVER_TCP(t_server_copy_refusals)
OVER_TCP(t_server_copy_fair)
OVER_TCP(t_server_closed_reason)
/* N1d's review: the engine thread's tick on its own clock. While a client drains a large COPY TO slowly, its every send
 * wakes the engine thread: the ticks (timeouts, maintenance) still run (once a wait that never timed out starved them),
 * and another session idle in its transaction past idle_in_transaction_timeout is doomed meanwhile */
static void t_server_tick_load(void)
{
    imdbs *s;
    imdb_db *db = serve(&s, NULL);
    CHECK(db);
    imdbc *a = login("admin", "pw-admin"), *b = login("admin", "pw-admin");
    CHECK(a && b);
    reply r = {0};
    imdb_err e = {0};
    SOFT(q1(a, "CREATE TABLE t (id INT64 PRIMARY KEY, name TEXT, v INT64)", &r) == 0 && !r.nerr);
    size_t cap = 24u << 20;
    char *d = malloc(cap);
    CHECK(d);
    size_t n = make_wide_rows(d, cap, 0, 60000); /* ~14 MB: fourteen COPY_OUT frames */
    SOFT(copy_in(a, "COPY t FROM STDIN", d, n, 0, &r) == 0 && r.count == 60000);
    SOFT(q1(b, "SET idle_in_transaction_timeout = 300", &r) == 0 && q1(b, "BEGIN", &r) == 0 && q1(b, "SELECT 1", &r) == 0);
    imdbs_counts c0, c1;
    imdbs_counts_get(s, &c0);
    uint64_t t0 = imdb_mono_ns();
    imdbc_stmt to = {"COPY t TO STDOUT", 16, NULL, 0};
    SOFT(imdbc_query(a, &to, 1, &e) == 0);
    for (int k = 0; k < 2000; k++) { /* a message, then 80 ms: the server's sends wake its engine thread all along */
        imdbw_msg m;
        if (imdbc_next(a, &m, &e) || m.type == IMDBW_READY) break;
        usleep(80000);
    }
    imdbs_counts_get(s, &c1);
    uint64_t ms = (imdb_mono_ns() - t0) / 1000000u;
    SOFT(ms >= 1000 && c1.ticks >= c0.ticks + ms / 400); /* one each 100 ms: a quarter of them at least, under any load */
    if (c1.ticks < c0.ticks + ms / 400)
        fprintf(stderr, "    %llu ticks in %llu ms\n", (unsigned long long)(c1.ticks - c0.ticks), (unsigned long long)ms);
    SOFT(q1(b, "SELECT 2", &r) == 0 && r.nerr == 1 && r.state == IMDBW_DOOMED);
    SOFT(q1(b, "ROLLBACK", &r) == 0 && !r.nerr && r.state == IMDBW_IDLE);
    free(d);
    imdbc_close(a);
    imdbc_close(b);
    unserve(db, s);
}

/* N1d's review: a cancel asked while no request runs is for none: the next statement runs whole (the client drops it;
 * once, the flag waited and cancelled whatever came next) */
static void t_server_cancel_idle(void)
{
    imdbs *s;
    imdb_db *db = serve(&s, NULL);
    CHECK(db);
    imdbc *c = login("admin", "pw-admin");
    CHECK(c);
    reply r = {0};
    imdb_err e = {0};
    SOFT(q1(c, "CREATE TABLE t (id INT64 PRIMARY KEY)", &r) == 0 && !r.nerr);
    SOFT(q1(c, "CREATE TABLE u (id INT64 PRIMARY KEY)", &r) == 0 && !r.nerr);
    size_t cap = 1u << 20;
    char *d = malloc(cap);
    CHECK(d);
    size_t n = 0;
    for (int i = 0; i < 20000; i++) n += (size_t)snprintf(d + n, cap - n, "%d\n", i);
    SOFT(copy_in(c, "COPY u FROM STDIN", d, n, 0, &r) == 0 && r.count == 20000);
    n = 0;
    for (int i = 0; i < 2000; i++) n += (size_t)snprintf(d + n, cap - n, "%d\n", i);
    SOFT(copy_in(c, "COPY t FROM STDIN", d, n, 0, &r) == 0 && r.count == 2000);
    /* a cancel with nothing outstanding, then a statement read only once it runs (the old flag went out at the first
     * read: into the running statement) */
    static const char mid[] = "SELECT COUNT(*) FROM t AS x, t AS y WHERE x.id + y.id >= 0";
    imdbc_stmt ms = {mid, sizeof mid - 1, NULL, 0};
    imdbc_cancel(c);
    uint64_t b0 = started_now(s);
    SOFT(imdbc_query(c, &ms, 1, &e) == 0);
    wait_started(s, b0);
    SOFT(read_reply(c, &r) == 0 && !r.nerr && !strcmp(r.text, "4000000\n"));
    /* and one asked while a statement runs still cancels it (400 million pairs) */
    static const char slow[] = "SELECT COUNT(*) FROM u AS x, u AS y WHERE x.id + y.id = -1";
    imdbc_stmt st = {slow, sizeof slow - 1, NULL, 0};
    uint64_t before = started_now(s);
    SOFT(imdbc_query(c, &st, 1, &e) == 0);
    wait_started(s, before);
    imdbc_cancel(c);
    SOFT(read_reply(c, &r) == 0 && r.nerr == 1 && r.err_code == (uint32_t)-IMDB_ERR_CANCELLED);
    SOFT(q1(c, "SELECT COUNT(*) FROM t", &r) == 0 && !r.nerr && !strcmp(r.text, "2000\n"));
    free(d);
    imdbc_close(c);
    unserve(db, s);
}

/* N1d's review: a cancel asked while a COPY's data is sent goes out before the next frame: the COPY refused unrun (once
 * it waited for the whole upload, when the COPY might not have begun and the CANCEL reached nothing) */
static void t_server_copy_cancel_upload(void)
{
    imdbs *s;
    imdb_db *db = serve(&s, NULL);
    CHECK(db);
    imdbc *c = login("admin", "pw-admin");
    CHECK(c);
    reply r = {0};
    imdb_err e = {0};
    SOFT(q1(c, "CREATE TABLE t (id INT64 PRIMARY KEY, name TEXT, v INT64)", &r) == 0 && !r.nerr);
    size_t cap = 4u << 20;
    char *d = malloc(cap);
    CHECK(d);
    size_t n = make_rows(d, cap, 0, 20000), h = n / 2;
    while (h < n && d[h - 1] != '\n') h++;
    imdbc_stmt cp = {"COPY t FROM STDIN", 17, NULL, 0};
    SOFT(imdbc_query(c, &cp, 1, &e) == 0 && read_reply(c, &r) == 0 && r.copy_in);
    SOFT(imdbc_copy_data(c, d, h, &e) == 0);
    imdbc_cancel(c);
    SOFT(imdbc_copy_data(c, d + h, n - h, &e) == 0 && imdbc_copy_done(c, &e) == 0);
    SOFT(read_reply(c, &r) == 0 && r.nerr == 1 && r.err_code == (uint32_t)-IMDB_ERR_CANCELLED && strstr(r.err, "never ran"));
    SOFT(q1(c, "SELECT COUNT(*) FROM t", &r) == 0 && !r.nerr && !strcmp(r.text, "0\n") && spool_held(s) == 0);
    free(d);
    imdbc_close(c);
    unserve(db, s);
}

/* N1d's review: --copy-idle counts from COPY_IN's delivery: a batch's COPY TO read slowly (its frames ahead of COPY_IN
 * for longer than --copy-idle, 1.5 s), then its COPY FROM's data, taken (once the connection was closed for idleness
 * while its client read at full speed) */
static void t_server_copy_idle_late(void)
{
    imdbs_opts so;
    memset(&so, 0, sizeof so);
    so.copy_idle_ms = 1500;
    imdbs *s;
    imdb_db *db = serve(&s, &so);
    CHECK(db);
    imdbc *c = login("admin", "pw-admin");
    CHECK(c);
    reply r = {0};
    imdb_err e = {0};
    SOFT(q1(c, "CREATE TABLE t (id INT64 PRIMARY KEY, name TEXT, v INT64)", &r) == 0 && !r.nerr);
    SOFT(q1(c, "CREATE TABLE t2 (id INT64 PRIMARY KEY, name TEXT, v INT64)", &r) == 0 && !r.nerr);
    size_t cap = 16u << 20;
    char *d = malloc(cap);
    CHECK(d);
    size_t n = make_wide_rows(d, cap, 0, 40000); /* ~9 MB: nine frames */
    SOFT(copy_in(c, "COPY t FROM STDIN", d, n, 0, &r) == 0 && r.count == 40000);
    imdbs_counts c0, c1;
    imdbs_counts_get(s, &c0);
    imdbc_stmt two[2] = {{"COPY t TO STDOUT", 16, NULL, 0}, {"COPY t2 FROM STDIN", 18, NULL, 0}};
    SOFT(imdbc_query(c, two, 2, &e) == 0);
    bool in = false;
    uint64_t t0 = imdb_mono_ns();
    for (int k = 0; k < 2000 && !in; k++) {
        imdbw_msg m;
        if (imdbc_next(c, &m, &e)) break;
        in = m.type == IMDBW_COPY_IN;
        if (m.type == IMDBW_COPY_OUT) usleep(250000); /* (its last bytes in the socket's buffer read at once) */
    }
    SOFT(in && (imdb_mono_ns() - t0) / 1000000u > 1500); /* COPY_IN came past --copy-idle */
    SOFT(imdbc_copy_data(c, d, n, &e) == 0 && imdbc_copy_done(c, &e) == 0);
    SOFT(read_reply(c, &r) == 0 && !r.nerr && r.count == 40000);
    imdbs_counts_get(s, &c1);
    SOFT(c1.copy_idle == c0.copy_idle);
    SOFT(q1(c, "SELECT COUNT(*) FROM t2", &r) == 0 && !r.nerr && !strcmp(r.text, "40000\n"));
    free(d);
    imdbc_close(c);
    unserve(db, s);
}

/* N1e: the server's sessions act as their login's role, enforced. Logins are still SUPERUSER ones (N1e's second stage
 * opens the rest), so two log in as superusers and lose it from a third connection: each one's next statement then
 * meets the gates over the wire (code 16): DDL, a table not granted, a table granted to the other alone (a wrong role
 * id would read it), COPY FROM without INSERT answered with its ERROR and no COPY_IN, a prepared statement's EXECUTE,
 * and a role dropped under its live session */
static void t_server_priv(void)
{
    imdbs *s;
    imdb_db *db = serve(&s, NULL);
    CHECK(db);
    imdbc *c = login("admin", "pw-admin");
    CHECK(c);
    reply r = {0};
    imdb_err e = {0};
    SOFT(q1(c, "CREATE TABLE t (id INT64 PRIMARY KEY, v INT64)", &r) == 0 && !r.nerr);
    SOFT(q1(c, "CREATE TABLE u (id INT64 PRIMARY KEY, v INT64)", &r) == 0 && !r.nerr);
    SOFT(q1(c, "INSERT INTO t VALUES (1, 1), (2, 2)", &r) == 0 && !r.nerr);
    SOFT(q1(c, "INSERT INTO u VALUES (1, 1)", &r) == 0 && !r.nerr);
    SOFT(q1(c, "CREATE ROLE a1 LOGIN SUPERUSER PASSWORD 'pw-a1'", &r) == 0 && !r.nerr);
    SOFT(q1(c, "CREATE ROLE a2 LOGIN SUPERUSER PASSWORD 'pw-a2'", &r) == 0 && !r.nerr);
    SOFT(q1(c, "GRANT SELECT ON t TO a1", &r) == 0 && !r.nerr);
    imdbc *a1 = login("a1", "pw-a1"), *a2 = login("a2", "pw-a2");
    CHECK(a1 && a2);
    SOFT(q1(a1, "CREATE TABLE z1 (id INT64 PRIMARY KEY)", &r) == 0 && !r.nerr); /* a superuser still */
    SOFT(q1(c, "ALTER ROLE a1 NOSUPERUSER", &r) == 0 && !r.nerr);
    SOFT(q1(c, "ALTER ROLE a2 NOSUPERUSER", &r) == 0 && !r.nerr);
    uint32_t priv = (uint32_t)-IMDB_ERR_PRIVILEGE;
    SOFT(q1(a1, "SELECT COUNT(*) FROM t", &r) == 0 && !r.nerr && !strcmp(r.text, "2\n"));
    SOFT(q1(a1, "SELECT COUNT(*) FROM u", &r) == 0 && r.nerr == 1 && r.err_code == priv && strstr(r.err, "table u"));
    SOFT(q1(a1, "CREATE TABLE z2 (id INT64 PRIMARY KEY)", &r) == 0 && r.nerr == 1 && r.err_code == priv);
    SOFT(q1(a2, "SELECT COUNT(*) FROM t", &r) == 0 && r.nerr == 1 && r.err_code == priv && strstr(r.err, "table t"));
    /* COPY FROM without INSERT: its ERROR at once, never a COPY_IN (nothing spooled) */
    SOFT(q1(a1, "COPY u FROM STDIN", &r) == 0 && !r.copy_in && r.nerr == 1 && r.err_code == priv);
    SOFT(spool_held(s) == 0);
    /* the protocol's EXECUTE (imdb_execute) checked at its run */
    SOFT(imdbc_prepare(a1, "p", "SELECT COUNT(*) FROM u", 22, &e) == 0 && read_reply(a1, &r) == 0 && !r.nerr);
    SOFT(imdbc_execute(a1, "p", NULL, 1, 0, &e) == 0 && read_reply(a1, &r) == 0 && r.nerr == 1 && r.err_code == priv);
    SOFT(q1(c, "GRANT SELECT ON u TO a1", &r) == 0 && !r.nerr);
    SOFT(imdbc_execute(a1, "p", NULL, 1, 0, &e) == 0 && read_reply(a1, &r) == 0 && !r.nerr && !strcmp(r.text, "1\n"));
    /* a role dropped under its live session: refused by name at its next statement */
    SOFT(q1(c, "DROP ROLE a2", &r) == 0 && !r.nerr);
    SOFT(q1(a2, "SELECT 1", &r) == 0 && r.nerr == 1 && r.err_code == priv && strstr(r.err, "dropped"));
    /* COPY into a name no table holds, or into a view: its ERROR and no COPY_IN, a superuser's session too (nothing
     * spooled for a statement that cannot run) */
    SOFT(q1(c, "CREATE VIEW vt (id) AS SELECT id FROM t", &r) == 0 && !r.nerr);
    SOFT(q1(c, "COPY nosuch FROM STDIN", &r) == 0 && !r.copy_in && r.nerr == 1 &&
         r.err_code == (uint32_t)-IMDB_ERR_NOTFOUND);
    SOFT(q1(c, "COPY vt FROM STDIN", &r) == 0 && !r.copy_in && r.nerr == 1 && r.err_code == (uint32_t)-IMDB_ERR_INVALID);
    SOFT(spool_held(s) == 0 && q1(c, "SELECT 1", &r) == 0 && !r.nerr);
    imdbc_close(a1);
    imdbc_close(a2);
    imdbc_close(c);
    unserve(db, s);
}


/* N1e stage two: turns go by role, then by connection. A third role's statement holds the engine thread (a cross join of
 * minutes, cut at 1.5 s by its statement_timeout) while role ra's six connections and rb's one each queue three requests,
 * a nextval each: the values are the order they ran in. By role, ra and rb alternate, so rb's third runs by the sixth or
 * seventh turn; by connection, rb would have one turn in seven, its third at the fifteenth at the soonest, whatever the
 * connections' order. No clock is asserted: the order alone */
static void t_server_turns(void)
{
    imdbs *s = NULL;
    imdb_db *db = serve(&s, NULL);
    CHECK(db);
    imdbc *adm = login("admin", "pw-admin");
    CHECK(adm);
    reply r = {0};
    load_rows(adm, 400);
    static const char *const setup[] = {"CREATE ROLE ra LOGIN SUPERUSER PASSWORD 'pw-a'",
                                        "CREATE ROLE rb LOGIN SUPERUSER PASSWORD 'pw-b'",
                                        "CREATE ROLE rc LOGIN SUPERUSER PASSWORD 'pw-c'", "CREATE SEQUENCE q"};
    for (size_t i = 0; i < sizeof setup / sizeof *setup; i++) SOFT(q1(adm, setup[i], &r) == 0 && !r.nerr);
    imdbc *a[6], *b = NULL, *hold = login("rc", "pw-c");
    for (int i = 0; i < 6; i++) a[i] = login("ra", "pw-a");
    b = login("rb", "pw-b");
    CHECK(hold && b);
    for (int i = 0; i < 6; i++) CHECK(a[i]);
    SOFT(q1(hold, "SET statement_timeout = 1500", &r) == 0 && !r.nerr);
    imdb_err e = {0};
    static const char slow[] = "SELECT COUNT(*) FROM big2 AS x, big2 AS y WHERE x.v + y.v = 99";
    imdbc_stmt hs = {slow, sizeof slow - 1, NULL, 0}, nv = {"SELECT nextval('q')", 19, NULL, 0};
    uint64_t before = started_now(s);
    SOFT(imdbc_query(hold, &hs, 1, &e) == 0);
    wait_started(s, before);
    for (int k = 0; k < 3; k++) {
        for (int i = 0; i < 6; i++) SOFT(imdbc_query(a[i], &nv, 1, &e) == 0);
        SOFT(imdbc_query(b, &nv, 1, &e) == 0);
    }
    SOFT(read_reply(hold, &r) == 0 && r.err_code == (uint32_t)-IMDB_ERR_CANCELLED);
    long vb[3] = {0, 0, 0};
    for (int k = 0; k < 3; k++) {
        SOFT(read_reply(b, &r) == 0 && !r.nerr);
        vb[k] = strtol(r.text, NULL, 10);
    }
    SOFT(vb[0] < vb[1] && vb[1] < vb[2] && vb[2] <= 7);
    if (vb[2] > 7) fprintf(stderr, "    rb's nextvals: %ld %ld %ld (by role: the third by 7)\n", vb[0], vb[1], vb[2]);
    for (int i = 0; i < 6; i++) {
        for (int k = 0; k < 3; k++) SOFT(read_reply(a[i], &r) == 0 && !r.nerr);
        imdbc_close(a[i]);
    }
    imdbc_close(b);
    imdbc_close(hold);
    imdbc_close(adm);
    unserve(db, s);
}

/* N1e stage two: the server sets a session's caps from its options (their defaults here: 60 s for a statement, 10 min for
 * a transaction, 60 s idle in one, 2 MiB of prepared statements). Logins are a superuser's until stage two's last slice,
 * so the role logs in a superuser and is demoted: its session is held from its next statement, and promoted again, freed */
static void t_server_role_caps(void)
{
    imdbs *s = NULL;
    imdb_db *db = serve(&s, NULL);
    CHECK(db);
    imdbc *adm = login("admin", "pw-admin");
    CHECK(adm);
    reply r = {0};
    SOFT(q1(adm, "CREATE ROLE dem LOGIN SUPERUSER PASSWORD 'pw-d'", &r) == 0 && !r.nerr);
    imdbc *d = login("dem", "pw-d");
    CHECK(d);
    SOFT(q1(d, "SET statement_timeout = 0", &r) == 0 && !r.nerr); /* a superuser's: none */
    SOFT(q1(adm, "ALTER ROLE dem NOSUPERUSER", &r) == 0 && !r.nerr);
    static const char *const held[][2] = {{"SET statement_timeout = 0", "(60000)"},
                                          {"SET statement_timeout = 60001", "(60000)"},
                                          {"SET transaction_timeout = 600001", "(600000)"},
                                          {"SET idle_in_transaction_timeout = 0", "(60000)"}};
    for (size_t i = 0; i < sizeof held / sizeof *held; i++) {
        SOFT(q1(d, held[i][0], &r) == 0 && r.err_code == (uint32_t)-IMDB_ERR_PRIVILEGE && strstr(r.err, held[i][1]));
        if (r.err_code != (uint32_t)-IMDB_ERR_PRIVILEGE) fprintf(stderr, "    %s: %u %s\n", held[i][0], r.err_code, r.err);
    }
    SOFT(q1(d, "SET statement_timeout = 59000", &r) == 0 && !r.nerr);
    SOFT(q1(adm, "ALTER ROLE dem SUPERUSER", &r) == 0 && !r.nerr);
    SOFT(q1(d, "SET statement_timeout = 0", &r) == 0 && !r.nerr);
    imdbc_close(d);
    imdbc_close(adm);
    unserve(db, s);
}

/* a login answered and then refused (a role's cap, the superusers' reserve): the server's ERROR, unasked, then the close.
 * A statement sent meets either: sent before the close, its reply is that ERROR; sent after it, the send fails and the
 * client reports the ERROR it then reads (closed_reason). D34 was this race read wrong: a failed send left q1's reply as
 * the stack held it (an earlier reply's "1 done"), taken for an admission */
static bool refused_after_login(const char *user, const char *pw, const char *want)
{
    imdbc *c = login(user, pw);
    if (!c) {
        fprintf(stderr, "    %s's login failed: %d %s\n", user, g_login_err.code, g_login_err.msg);
        return false;
    }
    reply r = {0};
    q1(c, "SELECT 1", &r);
    bool ok = ((r.nerr && r.err_code == (uint32_t)-IMDB_ERR_LIMIT) || r.rc == IMDB_ERR_LIMIT) && strstr(r.err, want) && r.ndone == 0;
    if (!ok) fprintf(stderr, "    %s's login: code %u, %u done: %s\n", user, r.err_code, r.ndone, r.err);
    imdbc_close(c);
    return ok;
}

/* a login of user that runs a statement, within 10 s (a closed connection's place is freed when its session ends) */
static imdbc *login_runs(const char *user, const char *pw)
{
    for (int k = 0; k < 200; k++) {
        imdbc *c = login(user, pw);
        reply r = {0};
        if (c && q1(c, "SELECT 1", &r) == 0 && !r.nerr) return c;
        imdbc_close(c);
        usleep(50000);
    }
    return NULL;
}

/* N1e stage two: one role's connections at most --role-conns; a superuser past it; a place freed by a close; the last
 * --superuser-reserve slots a superuser's alone (2c: a role logs in where the database has a memory budget, serve's 2 GiB) */
static void t_server_role_conns(void)
{
    imdbs_opts o;
    memset(&o, 0, sizeof o);
    o.role_conns = 2;
    o.max_conns = 6;
    o.su_reserve = 2;
    imdbs *s = NULL;
    imdb_db *db = serve(&s, &o);
    CHECK(db);
    imdbc *p1 = login_runs("plain", "pw"), *p2 = login_runs("plain", "pw");
    CHECK(p1 && p2);
    imdbs_counts c0, c1;
    imdbs_counts_get(s, &c0);
    SOFT(refused_after_login("plain", "pw", "--role-conns"));
    imdbc *a[3];
    for (int i = 0; i < 3; i++) SOFT((a[i] = login_runs("admin", "pw-admin")) != NULL); /* a superuser: no role cap */
    imdbc_close(a[2]);
    imdbc_close(p2);
    imdbc *p3 = login_runs("plain", "pw"); /* p2's place freed */
    SOFT(p3 != NULL);
    imdbc_close(a[1]);
    /* now 3 connections (p1, a[0], p3): the reserve is the last 2 of 6, so a fourth role connection would leave 2 */
    SOFT(q1(p1, "SELECT 1", &(reply){0}) == 0);
    imdbc_close(p3);
    SOFT(q1(a[0], "CREATE ROLE other LOGIN PASSWORD 'pw-o'", &(reply){0}) == 0);
    imdbc *o1 = login_runs("other", "pw-o"), *o2 = login_runs("other", "pw-o"); /* p1, a[0], o1, o2: 4 of 6 */
    SOFT(o1 && o2);
    /* the closed connections reaped first (10 s at most): the reserve counts what is in the server's list, and exactly
     * the four above must be, or the check below means nothing (once, under the gate's load, the fifth login was taken:
     * not reproduced since; this says which way the count was off if it comes back) */
    imdbs_counts lv;
    for (int w = 0; w < 1000; w++) {
        imdbs_counts_get(s, &lv);
        if (lv.live == 4) break;
        usleep(10000);
    }
    SOFT(lv.live == 4);
    if (lv.live != 4) fprintf(stderr, "    connections live before the reserve's check: %llu, not 4\n", (unsigned long long)lv.live);
    SOFT(refused_after_login("plain", "pw", "reserved for superusers"));
    /* the send after the server's close fails, and the error is the server's own refusal (closed_reason): the server
     * shut the connection (the client's socket hung up: after the lingering close's second, the client sending nothing),
     * then a statement is sent */
    imdbs_counts ce;
    for (int w = 0; w < 1000; w++) { /* the refusal before it ended first (its thread's end counted), so this one counts alone */
        imdbs_counts_get(s, &ce);
        if (ce.live == 4) break;
        usleep(10000);
    }
    imdbc *c6 = login("plain", "pw");
    SOFT(c6 != NULL);
    bool hup = false;
    for (int w = 0; c6 && w < 1000 && !hup; w++) { /* (the refusal is readable at once: poll returns, so the wait sleeps) */
        struct pollfd pf = {imdbc_fd(c6), POLLIN, 0};
        hup = poll(&pf, 1, 10) == 1 && (pf.revents & POLLHUP);
        if (!hup) usleep(10000);
    }
    SOFT(hup);
    imdbc_stmt st6 = {"SELECT 1", 8, NULL, 0};
    imdb_err e6 = {0};
    int rc6 = c6 ? imdbc_query(c6, &st6, 1, &e6) : 0;
    SOFT(rc6 == IMDB_ERR_LIMIT && strstr(e6.msg, "the server closed the connection: ") && strstr(e6.msg, "reserved for superusers"));
    if (rc6 != IMDB_ERR_LIMIT) fprintf(stderr, "    a send after the refusal's close: %d %s\n", rc6, e6.msg);
    imdbc_close(c6);
    imdbs_counts cf;
    imdbs_counts_get(s, &cf);
    SOFT(cf.ends[IMDBS_END_REFUSED] == ce.ends[IMDBS_END_REFUSED] + 1); /* the server's own count of how it ended */
    /* D34: each held connection still answers (one that had left the server's list early would explain a fifth login
     * taken: the test held them unused until now) */
    imdbc *held[4] = {p1, a[0], o1, o2};
    for (int i = 0; i < 4; i++) {
        reply hr = {0};
        SOFT(held[i] && q1(held[i], "SELECT 3", &hr) == 0 && !hr.nerr);
        if (!held[i] || hr.rc || hr.nerr) fprintf(stderr, "    held connection %d: rc %d code %u %s\n", i, hr.rc, hr.err_code, hr.err);
    }
    imdbc *a5 = login_runs("admin", "pw-admin"); /* the reserve: a superuser takes it */
    SOFT(a5 != NULL);
    imdbs_counts_get(s, &c1);
    SOFT(c1.role_refused >= c0.role_refused + 2);
    imdbc_close(a5);
    imdbc_close(o1);
    imdbc_close(o2);
    imdbc_close(a[0]);
    imdbc_close(p1);
    unserve(db, s);
}

/* N1e stage two: a role's shares, one server per case (budget: every connection's unsent replies; share: one role's).
 * Role plain's first connection leaves 3 MB of replies unread: its second connection's statement waits (past the
 * server's budget with replies of its own, or past its role's share), while role other's runs (it has none unsent: a
 * role holding the server stops itself, never another) and a superuser's runs; read, plain's runs. A superuser past the
 * share runs until demoted, then waits (the refresh of the roles). Its queued requests past --role-queue-bytes: its
 * sockets are not read (role_queue_waits) */
static void shares_case(uint64_t budget, uint64_t share, bool queue, bool demote)
{
    imdbs_opts o;
    memset(&o, 0, sizeof o);
    o.reply_budget = budget; /* (2c: test_no_spill gone: a budget below one chunk, 64 KiB, which a connection holding none
                              * always takes into memory, so p1's first chunk passes it however the rest spools) */
    o.role_reply_bytes = share;
    o.role_queue_bytes = 1u << 20;
    imdbs *s = NULL;
    imdb_db *db = serve(&s, &o);
    CHECK(db);
    imdbc *adm = login("admin", "pw-admin");
    CHECK(adm);
    reply r = {0};
    load_rows(adm, 400);
    static const char *const setup[] = {"GRANT SELECT ON big2 TO plain", "CREATE ROLE other LOGIN PASSWORD 'pw-o'",
                                        "CREATE ROLE boss LOGIN SUPERUSER PASSWORD 'pw-b'"};
    for (size_t i = 0; i < sizeof setup / sizeof *setup; i++) SOFT(q1(adm, setup[i], &r) == 0 && !r.nerr);
    const char *who = demote ? "boss" : "plain", *pw = demote ? "pw-b" : "pw";
    imdbc *p1 = login(who, pw), *p2 = login(who, pw), *ot = login("other", "pw-o");
    CHECK(p1 && p2 && ot);
    imdb_err e = {0};
    imdbc_stmt all = {"SELECT * FROM big2", 18, NULL, 0}; /* 160,000 rows: about 3 MB of frames, past the socket's buffers */
    uint64_t before = started_now(s);
    SOFT(imdbc_query(p1, &all, 1, &e) == 0);
    wait_started(s, before);
    SOFT(q1(adm, "SELECT 1", &r) == 0 && !r.nerr); /* runs after p1's statement (one engine thread) */
    if (demote) { /* a superuser past the share: its statement runs; demoted, the next waits */
        SOFT(q1(p2, "SELECT 2", &r) == 0 && !r.nerr);
        SOFT(q1(adm, "ALTER ROLE boss NOSUPERUSER", &r) == 0 && !r.nerr);
    }
    before = started_now(s);
    imdbc_stmt two = {"SELECT 2", 8, NULL, 0};
    SOFT(imdbc_query(p2, &two, 1, &e) == 0);
    usleep(300000);
    SOFT(started_now(s) == before); /* p2's statement waits */
    if (started_now(s) != before) fprintf(stderr, "    budget %llu, share %llu: the held role's statement ran\n",
                                          (unsigned long long)budget, (unsigned long long)share);
    SOFT(q1(ot, "SELECT 3", &r) == 0 && !r.nerr); /* another role's runs */
    SOFT(q1(adm, "SELECT 4", &r) == 0 && !r.nerr); /* a superuser's runs */
    imdbs_counts c0, c1;
    imdbs_counts_get(s, &c0);
    if (queue) { /* three requests of 400 KB, each read while the role's queue was under its 1 MiB, the last past it */
        static char pad[400000];
        size_t n = (size_t)snprintf(pad, sizeof pad, "SELECT 5 -- ");
        memset(pad + n, 'x', sizeof pad - n - 1);
        pad[sizeof pad - 1] = 0;
        imdbc_stmt big = {pad, strlen(pad), NULL, 0};
        for (int k = 0; k < 3; k++) SOFT(imdbc_query(p2, &big, 1, &e) == 0);
        for (int w = 0; w < 500; w++) {
            imdbs_counts_get(s, &c1);
            if (c1.role_queue_waits > c0.role_queue_waits) break;
            usleep(10000);
        }
        SOFT(c1.role_queue_waits > c0.role_queue_waits);
    }
    /* p1's replies read: the role's statements run, its queue drains */
    SOFT(read_reply(p1, &r) == 0 && !r.nerr && r.nrows == 160000);
    SOFT(read_reply(p2, &r) == 0 && !r.nerr);
    for (int k = 0; queue && k < 3; k++) {
        SOFT(read_reply(p2, &r) == 0 && !r.nerr && strstr(r.text, "5"));
        if (r.nerr || r.rc) fprintf(stderr, "    the padded request: rc %d code %u %s\n", r.rc, r.err_code, r.err);
    }
    imdbc_close(p1);
    imdbc_close(p2);
    imdbc_close(ot);
    imdbc_close(adm);
    unserve(db, s);
}

static void t_server_role_shares(void)
{
    shares_case(32u << 10, IMDBS_NONE, false, false); /* the server's budget alone (below one chunk: see shares_case) */
    shares_case(0, 1u << 20, true, false);           /* the role's share alone, and its queue */
    shares_case(0, 1u << 20, false, true);           /* a superuser exempt, then demoted */
}

/* N1e stage two: a role's statement cut at the server's cap, through the server, and another session's statement queued
 * behind it runs once it ends: --role-statement-timeout 400 ms, a role demoted after its login (logins are a superuser's
 * until 2c) running a cross join of minutes; the superuser's SELECT waits for the one engine thread, then answers (a
 * cap that never cut would hold it for minutes, past the client's 20 s) */
static void t_server_role_cap_cancel(void)
{
    imdbs_opts o;
    memset(&o, 0, sizeof o);
    o.role_stmt_ms = 400;
    imdbs *s = NULL;
    imdb_db *db = serve(&s, &o);
    CHECK(db);
    imdbc *adm = login("admin", "pw-admin");
    CHECK(adm);
    reply r = {0};
    load_rows(adm, 400);
    SOFT(q1(adm, "CREATE ROLE dem LOGIN SUPERUSER PASSWORD 'pw-d'", &r) == 0 && !r.nerr);
    SOFT(q1(adm, "GRANT SELECT ON big2 TO dem", &r) == 0 && !r.nerr);
    imdbc *d = login("dem", "pw-d");
    CHECK(d);
    SOFT(q1(adm, "ALTER ROLE dem NOSUPERUSER", &r) == 0 && !r.nerr);
    imdb_err e = {0};
    static const char slow[] = "SELECT COUNT(*) FROM big2 AS x, big2 AS y WHERE x.v + y.v = 99";
    imdbc_stmt st = {slow, sizeof slow - 1, NULL, 0};
    uint64_t before = started_now(s);
    SOFT(imdbc_query(d, &st, 1, &e) == 0);
    wait_started(s, before);
    SOFT(q1(adm, "SELECT 7", &r) == 0 && !r.nerr && strstr(r.text, "7")); /* after the capped statement ends */
    SOFT(read_reply(d, &r) == 0 && r.err_code == (uint32_t)-IMDB_ERR_CANCELLED && strstr(r.err, "400 ms") &&
         strstr(r.err, "--role-statement-timeout"));
    if (r.err_code != (uint32_t)-IMDB_ERR_CANCELLED) fprintf(stderr, "    the capped statement: %u %s\n", r.err_code, r.err);
    imdbc_close(d);
    imdbc_close(adm);
    unserve(db, s);
}

/* D34 (2026-11-19): what server_role_conns met once under load, forced: four connections held (a role's, two of another
 * role's, a superuser's) while logins are refused for the role's cap and for the superusers' reserve and others open
 * and close around them, many times; then every held handle still answers and the server counts exactly them (a
 * descriptor closed twice, or a connection's end that took a neighbour with it, would show here) */
static void t_server_conns_churn(void)
{
    imdbs_opts o;
    memset(&o, 0, sizeof o);
    o.role_conns = 2;
    o.max_conns = 8;
    o.su_reserve = 2;
    imdbs *s = NULL;
    imdb_db *db = serve(&s, &o);
    CHECK(db);
    imdbc *a0 = login_runs("admin", "pw-admin");
    CHECK(a0);
    reply r = {0};
    SOFT(q1(a0, "CREATE ROLE other LOGIN PASSWORD 'pw-o'", &r) == 0 && !r.nerr);
    imdbc *p1 = login_runs("plain", "pw"), *p2 = login_runs("plain", "pw"), *o1 = login_runs("other", "pw-o");
    CHECK(p1 && p2 && o1);
    int churned = 0;
    for (int k = 0; k < 60; k++) {
        refused_after_login("plain", "pw", "--role-conns"); /* plain at its cap: answered, refused */
        imdbc *x = login("admin", "pw-admin");              /* a superuser's, opened and closed at once */
        imdbc_close(x);
        imdbc *y = login("other", "pw-o"); /* other's second: taken or refused for the reserve, by the count at that moment */
        if (y) {
            reply ry = {0};
            q1(y, "SELECT 1", &ry);
            imdbc_close(y);
        }
        churned++;
    }
    imdbc *held[4] = {a0, p1, p2, o1};
    for (int i = 0; i < 4; i++) {
        SOFT(q1(held[i], "SELECT 2", &r) == 0 && !r.nerr && strstr(r.text, "2"));
        if (r.rc || r.nerr) fprintf(stderr, "    held connection %d after %d rounds: rc %d code %u %s\n", i, churned, r.rc, r.err_code, r.err);
    }
    imdbs_counts lv;
    for (int w = 0; w < 1000; w++) {
        imdbs_counts_get(s, &lv);
        if (lv.live == 4) break;
        usleep(10000);
    }
    SOFT(lv.live == 4);
    if (lv.live != 4) fprintf(stderr, "    connections live after the churn: %llu, not 4\n", (unsigned long long)lv.live);
    for (int i = 0; i < 4; i++) imdbc_close(held[i]);
    unserve(db, s);
}

/* N1e stage two: a session in a SESSIONS_LIST by id (-1: absent) */
static int sess_at(const reply *r, uint64_t id)
{
    for (uint32_t i = 0; i < r->nsess && i < 16; i++)
        if (r->sess[i].id == id) return (int)i;
    return -1;
}

static bool list_of(imdbc *c, reply *r)
{
    imdb_err e = {0};
    return imdbc_sessions(c, &e) == 0 && read_reply(c, r) == 0 && r->sessions;
}

static bool kill_of(imdbc *c, uint8_t kind, uint64_t id, uint32_t want)
{
    imdb_err e = {0};
    reply r = {0};
    bool ok = imdbc_kill(c, kind, id, &e) == 0 && read_reply(c, &r) == 0 && r.kill_done && r.kill_code == want &&
              r.kill_sid == id;
    if (!ok) fprintf(stderr, "    KILL %u of %llu: done %d, code %u (wanted %u): %s\n", kind, (unsigned long long)id,
                     r.kill_done, r.kill_code, want, r.err);
    return ok;
}

/* N1e stage two: SESSIONS and KILL (docs/n1-design.md §8e): a superuser lists every session, a role its own role's;
 * a superuser who logs in while the engine runs a long statement cancels it (the login and the KILL need no engine turn),
 * a role cancels its own role's session and is refused another's; terminate ends an idle session and one in a transaction
 * (rolled back), each told why */
static void t_server_kill(void)
{
    imdbs *s;
    imdbs_opts so;
    memset(&so, 0, sizeof so);
    imdb_db *db = serve(&s, &so);
    CHECK(db);
    imdbc *a = login("admin", "pw-admin");
    CHECK(a);
    load_rows(a, 400);
    reply r = {0};
    static const char *const setup[] = {"GRANT SELECT ON big2 TO plain", "GRANT SELECT, INSERT ON big TO plain",
                                        "CREATE ROLE other LOGIN PASSWORD 'pw-o'"};
    for (size_t i = 0; i < sizeof setup / sizeof *setup; i++) SOFT(q1(a, setup[i], &r) == 0 && !r.nerr);
    imdbc *w = login("plain", "pw"), *w2 = login("plain", "pw"), *o = login("other", "pw-o");
    CHECK(w && w2 && o);
    /* the superuser's list: every session, ids increasing, each its role's name, the socket's, idle */
    SOFT(list_of(a, &r) && r.nsess == 4);
    uint64_t idw = 0, idw2 = 0, ido = 0, ida = 0;
    for (uint32_t i = 0; i < r.nsess && i < 16; i++) {
        SOFT(!i || r.sess[i].id > r.sess[i - 1].id);
        SOFT(r.sess[i].endpoint == 2 && r.sess[i].state == IMDBW_SS_IDLE);
        if (!strcmp(r.sname[i], "plain")) *(idw ? &idw2 : &idw) = r.sess[i].id; /* w logged in first: the smaller id */
        else if (!strcmp(r.sname[i], "other")) ido = r.sess[i].id;
        else if (!strcmp(r.sname[i], "admin")) ida = r.sess[i].id;
    }
    SOFT(idw && idw2 && ido && ida && idw < idw2);
    /* a role's: its own role's sessions alone */
    SOFT(list_of(w, &r) && r.nsess == 2 && sess_at(&r, idw) >= 0 && sess_at(&r, idw2) >= 0);
    SOFT(list_of(o, &r) && r.nsess == 1 && r.sess[0].id == ido);
    /* refused: another role's session (2, both kinds), no such session (1); the target untouched */
    SOFT(kill_of(o, IMDBW_KILL_CANCEL, idw, IMDBW_KILL_NONE)); /* (to a role: none, as its list shows none) */
    SOFT(kill_of(o, IMDBW_KILL_TERMINATE, idw, IMDBW_KILL_NONE)); /* (to a role: none, as its list shows none) */
    SOFT(kill_of(o, IMDBW_KILL_TERMINATE, ida, IMDBW_KILL_NONE)); /* (to a role: none, as its list shows none) */
    SOFT(kill_of(a, IMDBW_KILL_TERMINATE, 999999, IMDBW_KILL_NONE));
    SOFT(q1(w, "SELECT COUNT(*) FROM big", &r) == 0 && !strcmp(r.text, "400\n"));
    /* a superuser who logs in after the statement began cancels it, answered before the statement's own end */
    static const char slow[] = "SELECT COUNT(*) FROM big2 AS a, big2 AS b WHERE a.v + b.v = 99"; /* minutes */
    SOFT(q1(w, "SET statement_timeout = 30000", &r) == 0 && !r.nerr);
    imdbc_stmt st = {slow, sizeof slow - 1, NULL, 0};
    imdb_err e = {0};
    uint64_t before = started_now(s);
    SOFT(imdbc_query(w, &st, 1, &e) == 0);
    wait_started(s, before);
    uint64_t t0 = imdb_mono_ns();
    imdbc *k = login("admin", "pw-admin");
    SOFT(k != NULL);
    int at = -1;
    SOFT(k && list_of(k, &r) && r.nsess == 5 && (at = sess_at(&r, idw)) >= 0 && r.sess[at].state == IMDBW_SS_RUNNING);
    SOFT(k && kill_of(k, IMDBW_KILL_CANCEL, idw, IMDBW_KILLED));
    uint64_t kill_ms = (imdb_mono_ns() - t0) / 1000000u;
    SOFT(read_reply(w, &r) == 0 && r.nerr == 1 && r.err_code == (uint32_t)-IMDB_ERR_CANCELLED && r.state == IMDBW_IDLE);
    uint64_t end_ms = (imdb_mono_ns() - t0) / 1000000u;
    SOFT(kill_ms < 10000 && end_ms < 20000); /* well under the 30 s timeout: the KILL ended it */
    if (kill_ms >= 10000 || end_ms >= 20000) fprintf(stderr, "    KILL answered in %llu ms, the statement ended in %llu ms\n",
                                                     (unsigned long long)kill_ms, (unsigned long long)end_ms);
    /* its role's other session cancels it too */
    before = started_now(s);
    SOFT(imdbc_query(w, &st, 1, &e) == 0);
    wait_started(s, before);
    t0 = imdb_mono_ns();
    SOFT(kill_of(w2, IMDBW_KILL_CANCEL, idw, IMDBW_KILLED));
    SOFT(read_reply(w, &r) == 0 && r.nerr == 1 && r.err_code == (uint32_t)-IMDB_ERR_CANCELLED);
    SOFT((imdb_mono_ns() - t0) / 1000000u < 20000);
    /* a request queued behind another connection's statement, cancelled before it begins: it starts cancelled */
    SOFT(q1(a, "SET statement_timeout = 30000", &r) == 0 && !r.nerr);
    before = started_now(s);
    SOFT(imdbc_query(a, &st, 1, &e) == 0);
    wait_started(s, before);
    static const char scan[] = "SELECT COUNT(*) FROM big2 WHERE v + 1 > 0"; /* each row tested: checked every 4,096 */
    imdbc_stmt sc = {scan, sizeof scan - 1, NULL, 0};
    SOFT(imdbc_query(w, &sc, 1, &e) == 0);
    bool queued = false;
    for (int t = 0; t < 500 && !queued; t++) { /* its request at the server, behind a's statement */
        queued = list_of(k, &r) && (at = sess_at(&r, idw)) >= 0 && r.sess[at].state == IMDBW_SS_RUNNING;
        if (!queued) usleep(10000);
    }
    SOFT(queued);
    SOFT(kill_of(k, IMDBW_KILL_CANCEL, idw, IMDBW_KILLED));
    SOFT(kill_of(k, IMDBW_KILL_CANCEL, ida, IMDBW_KILLED)); /* then a's, so w's runs */
    SOFT(read_reply(a, &r) == 0 && r.nerr == 1 && r.err_code == (uint32_t)-IMDB_ERR_CANCELLED);
    SOFT(read_reply(w, &r) == 0 && r.nerr == 1 && r.err_code == (uint32_t)-IMDB_ERR_CANCELLED);
    if (r.nerr != 1) fprintf(stderr, "    the queued request: %u errors, %s\n", r.nerr, r.text);
    /* nothing running: a cancel taken (KILL_DONE 0), dropped, the session goes on */
    SOFT(kill_of(a, IMDBW_KILL_CANCEL, idw, IMDBW_KILLED));
    SOFT(q1(w, "SELECT 5", &r) == 0 && !strcmp(r.text, "5\n"));
    /* the hold ended with its request: a statement that reads rows runs (a hold left on would cancel it) */
    SOFT(q1(w, "SELECT COUNT(*) FROM big2 WHERE v + 1 > 0", &r) == 0 && !r.nerr && !strcmp(r.text, "160000\n"));
    if (r.nerr) fprintf(stderr, "    after the KILLs: %u %s\n", r.err_code, r.err);
    /* a role's name as the logins give it now: renamed, then NOLOGIN ("": no longer among them) */
    SOFT(q1(a, "CREATE ROLE ren LOGIN PASSWORD 'pw-r'", &r) == 0 && !r.nerr);
    imdbc *rl = login("ren", "pw-r");
    SOFT(rl != NULL);
    uint64_t idr = 0;
    SOFT(list_of(a, &r));
    for (uint32_t i = 0; i < r.nsess && i < 16; i++)
        if (!strcmp(r.sname[i], "ren")) idr = r.sess[i].id;
    SOFT(idr != 0);
    SOFT(q1(a, "ALTER ROLE ren RENAME TO ren2", &r) == 0 && !r.nerr);
    SOFT(list_of(a, &r) && (at = sess_at(&r, idr)) >= 0 && !strcmp(r.sname[at], "ren2"));
    SOFT(q1(a, "ALTER ROLE ren2 NOLOGIN", &r) == 0 && !r.nerr);
    SOFT(list_of(a, &r) && (at = sess_at(&r, idr)) >= 0 && r.sname[at][0] == 0 && r.sess[at].name.len == 0);
    imdbc_close(rl);
    /* a KILL while a COPY's data arrives: the COPY refused unrun by its own connection's thread, its data dropped */
    imdbc_stmt cp = {"COPY big FROM STDIN", 19, NULL, 0};
    SOFT(imdbc_query(w, &cp, 1, &e) == 0 && read_reply(w, &r) == 0 && r.copy_in);
    SOFT(imdbc_copy_data(w, "2000001,1\n", 10, &e) == 0);
    imdbs_counts c0, c1;
    imdbs_counts_get(s, &c0);
    SOFT(kill_of(k, IMDBW_KILL_CANCEL, idw, IMDBW_KILLED));
    for (int t = 0; t < 500; t++) {
        imdbs_counts_get(s, &c1);
        if (c1.cancels > c0.cancels) break; /* its thread refused it */
        usleep(10000);
    }
    SOFT(c1.cancels > c0.cancels);
    SOFT(imdbc_copy_data(w, "2000002,1\n", 10, &e) == 0); /* (read and dropped) */
    SOFT(imdbc_copy_done(w, &e) == 0 && read_reply(w, &r) == 0 && r.nerr == 1 && strstr(r.err, "by a KILL") &&
         strstr(r.err, "never ran"));
    if (!strstr(r.err, "by a KILL")) fprintf(stderr, "    the COPY: %u %s\n", r.err_code, r.err);
    SOFT(q1(a, "SELECT COUNT(*) FROM big WHERE id >= 2000001", &r) == 0 && !strcmp(r.text, "0\n"));
    /* terminate of a session in a transaction: listed as one, then ended, told why, its insert rolled back */
    SOFT(q1(w, "BEGIN", &r) == 0 && !r.nerr && q1(w, "INSERT INTO big VALUES (1000000, 1)", &r) == 0 && !r.nerr);
    SOFT(list_of(a, &r) && (at = sess_at(&r, idw)) >= 0 && r.sess[at].state == IMDBW_SS_IN_TXN);
    SOFT(kill_of(a, IMDBW_KILL_TERMINATE, idw, IMDBW_KILLED));
    SOFT(read_reply(w, &r) != 0 && r.nerr == 1 && r.err_code == (uint32_t)-IMDB_ERR_CANCELLED && strstr(r.err, "a KILL"));
    /* an idle session, by its own role's other session */
    SOFT(kill_of(w2, IMDBW_KILL_TERMINATE, idw2, IMDBW_KILLED)); /* (itself: as TERMINATE) */
    SOFT(read_reply(w2, &r) != 0 && r.nerr == 1 && strstr(r.err, "a KILL"));
    bool gone = false;
    for (int t = 0; t < 500 && !gone; t++) { /* their sessions' ends run on the engine thread */
        gone = list_of(a, &r) && sess_at(&r, idw) < 0 && sess_at(&r, idw2) < 0 && r.nsess == 3;
        if (!gone) usleep(10000);
    }
    SOFT(gone);
    SOFT(q1(a, "SELECT COUNT(*) FROM big", &r) == 0 && !strcmp(r.text, "400\n")); /* the insert rolled back */
    SOFT(kill_of(a, IMDBW_KILL_CANCEL, idw, IMDBW_KILL_NONE)); /* ended: no such session */
    imdbs_counts cn;
    imdbs_counts_get(s, &cn);
    SOFT(cn.kills == 8 && cn.kills_refused == 5); /* taken: two cancels running, one queued (and the one ahead of it),
                                                  * one idle, one of a COPY's upload, two terminates */
    if (cn.kills != 8 || cn.kills_refused != 5)
        fprintf(stderr, "    kills %llu, refused %llu\n", (unsigned long long)cn.kills, (unsigned long long)cn.kills_refused);
    imdbc_close(w);
    imdbc_close(w2);
    imdbc_close(o);
    imdbc_close(k);
    imdbc_close(a);
    unserve(db, s);
}

/* N1e stage two: out-of-turn answers bounded: a client that sends 20,000 SESSIONS frames at once and reads nothing holds
 * at most OOT_MAX of their answers unsent past the socket's buffer (its socket is not read past it: oot_waits), then gets
 * every one once it reads; 10,000 PINGs every PONG */
static void t_server_oot(void)
{
    imdbs *s;
    imdb_db *db = serve(&s, NULL);
    CHECK(db);
    imdbc *c = login("admin", "pw-admin");
    CHECK(c);
    for (int round = 0; round < 2; round++) {
        uint8_t type = round ? IMDBW_PING : IMDBW_SESSIONS;
        imdbw_buf b;
        imdbw_buf_init(&b);
        imdbw_msg m = {.type = type};
        int nf = round ? 10000 : 20000; /* SESSIONS: 100 KB sent (the socket holds them), about 750 KB of answers */
        for (int k = 0; k < nf; k++) imdbw_msg_put(&b, &m, NULL);
        imdb_err e = {0};
        imdbs_counts c0, c1;
        imdbs_counts_get(s, &c0);
        SOFT(!b.err && imdbc_send_raw(c, b.p, b.len, &e) == 0);
        imdbw_buf_free(&b);
        for (int t = 0; t < 1000; t++) {
            imdbs_counts_get(s, &c1);
            if (c1.oot_waits > c0.oot_waits) break;
            usleep(10000);
        }
        /* SESSIONS: its answers (about 370 KB) pass the socket's buffer and the bound: its reads paused. PINGs: their answers
         * (about 50 KB) fit the socket's buffer, no pause needed; every one answered all the same */
        SOFT(round || c1.oot_waits > c0.oot_waits);
        SOFT(c1.oot_peak <= (64u << 10) + 1024); /* the bound and one answer: never the 750 KB */
        if (c1.oot_peak > (64u << 10) + 1024) fprintf(stderr, "    out-of-turn bytes held: %llu\n", (unsigned long long)c1.oot_peak);
        if (!round && c1.oot_waits == c0.oot_waits) fprintf(stderr, "    SESSIONS: no pause\n");
        int got = 0;
        bool other = false;
        imdbw_msg a;
        while (got < nf && imdbc_next(c, &a, &e) == 0) {
            if (a.type == (round ? IMDBW_PONG : IMDBW_SESSIONS_LIST) && (round || (a.nsess == 1 && !a.sess[0].state)))
                got++;
            else
                other = true;
        }
        SOFT(got == nf && !other);
        if (got != nf || other) fprintf(stderr, "    round %d: %d answers, other %d: %s\n", round, got, other, e.msg);
    }
    reply r = {0};
    SOFT(q1(c, "SELECT 1", &r) == 0 && !strcmp(r.text, "1\n")); /* the session goes on */
    imdbc_close(c);
    unserve(db, s);
}

/* N1e stage two (the advisor's 14:01 review): a refused login holds its slot only through its own lingering close,
 * whatever the engine thread does. With a long statement running and refused logins filling every other slot, held open
 * by their clients, a superuser still logs in within seconds and KILLs the statement (before, each refused login waited
 * for the engine thread's turn to close, so the slots stayed full for the statement's whole run) */
static void t_server_refused_slots(void)
{
    imdbs_opts o;
    memset(&o, 0, sizeof o);
    o.role_conns = 1;
    o.max_conns = 6;
    o.su_reserve = 1;
    imdbs *s = NULL;
    imdb_db *db = serve(&s, &o);
    CHECK(db);
    imdbc *a = login_runs("admin", "pw-admin"), *p1 = login_runs("plain", "pw");
    CHECK(a && p1);
    load_rows(a, 400);
    reply r = {0};
    SOFT(q1(a, "SET statement_timeout = 30000", &r) == 0 && !r.nerr);
    static const char slow[] = "SELECT COUNT(*) FROM big2 AS a, big2 AS b WHERE a.v + b.v = 99"; /* minutes */
    imdbc_stmt st = {slow, sizeof slow - 1, NULL, 0};
    imdb_err e = {0};
    uint64_t before = started_now(s);
    SOFT(imdbc_query(a, &st, 1, &e) == 0);
    wait_started(s, before); /* the engine thread busy */
    imdbc *rf[4] = {0};
    for (int i = 0; i < 4; i++) SOFT((rf[i] = login("plain", "pw")) != NULL); /* answered, then refused: held open */
    uint64_t t0 = imdb_mono_ns();
    imdbc *k = NULL;
    for (int w = 0; w < 200 && !k; w++) /* every slot taken until a refused one's linger ends (no statement: the engine is busy) */
        if (!(k = login("admin", "pw-admin"))) usleep(50000);
    uint64_t in_ms = (imdb_mono_ns() - t0) / 1000000u;
    SOFT(k != NULL && in_ms < 10000);
    reply l = {0};
    int at = -1;
    uint64_t ida = 0;
    if (k && list_of(k, &l))
        for (uint32_t i = 0; i < l.nsess && i < 16; i++)
            if (!strcmp(l.sname[i], "admin") && l.sess[i].state == IMDBW_SS_RUNNING) at = (int)i, ida = l.sess[i].id;
    SOFT(at >= 0);
    SOFT(k && ida && kill_of(k, IMDBW_KILL_CANCEL, ida, IMDBW_KILLED));
    SOFT(read_reply(a, &r) == 0 && r.nerr == 1 && r.err_code == (uint32_t)-IMDB_ERR_CANCELLED);
    if (!k || in_ms >= 10000) fprintf(stderr, "    the superuser's login: %s after %llu ms\n", k ? "in" : "refused", (unsigned long long)in_ms);
    for (int i = 0; i < 4; i++) imdbc_close(rf[i]);
    imdbc_close(k);
    imdbc_close(p1);
    imdbc_close(a);
    unserve(db, s);
}

/* ---- 2b-2a: results past their connection's room spooled (docs/n1-design.md §4, §8e) ---- */

static imdbs_counts counts_of(imdbs *s)
{
    imdbs_counts n;
    imdbs_counts_get(s, &n);
    return n;
}

/* until the server ran one more request to its end than before (its replies all handed over: memory or spool), 20 s */
static bool requests_past(imdbs *s, uint64_t before)
{
    /* 60 s at most: a spilled result under TSan and a loaded machine took past 20, 11-21 (the cause not established). A
     * wait past 5 s is printed, with the server's counts at its start and end: counts that moved are a slow machine,
     * counts frozen for seconds a stall (2b-3: the matrix's runs give the data at no extra load) */
    imdbs_counts c0 = counts_of(s);
    uint64_t t0 = imdb_mono_ns();
    bool ok = false;
    for (int w = 0; w < 6000 && !ok; w++) {
        if (counts_of(s).requests > before) ok = true;
        else usleep(10000);
    }
    uint64_t ms = (imdb_mono_ns() - t0) / 1000000u;
    if (ms > 5000) {
        imdbs_counts c1 = counts_of(s);
        fprintf(stderr, "    requests_past in %s: %llu ms (%s); requests %llu -> %llu, wakeups %llu -> %llu, ticks %llu -> %llu, "
                        "res_spool_bytes %llu -> %llu\n", g_test_current, (unsigned long long)ms, ok ? "done" : "TIMED OUT",
                (unsigned long long)c0.requests, (unsigned long long)c1.requests, (unsigned long long)c0.wakeups,
                (unsigned long long)c1.wakeups, (unsigned long long)c0.ticks, (unsigned long long)c1.ticks,
                (unsigned long long)c0.res_spool_bytes, (unsigned long long)c1.res_spool_bytes);
    }
    return ok;
}

/* until the server's spools hold nothing and no spool file is open (every credit back), 10 s */
static bool spools_empty(imdbs *s)
{
    for (int w = 0; w < 1000; w++) {
        if (!counts_of(s).spool_held && !imdbsp_live()) return true;
        usleep(10000);
    }
    fprintf(stderr, "    spools: %llu bytes held, %d files\n", (unsigned long long)counts_of(s).spool_held, (int)imdbsp_live());
    return false;
}

static const imdbc_stmt k_all = {"SELECT * FROM big2", 18, NULL, 0}; /* 160,000 rows: about 3 MB of frames */

/* a result past its connection's room, its client reading only after the statement ended: the frames past the room
 * spooled, the replies in memory never past that room and a chunk, every row then delivered in order, and
 * every credit back once read */
static void t_server_res_spill(void)
{
    imdbs_opts o;
    memset(&o, 0, sizeof o);
    o.conn_cap = 1u << 20;
    o.reply_budget = 64u << 20; /* the connection's room alone binds (the server's budget counts spooled replies too) */
    imdbs *s = NULL;
    imdb_db *db = serve(&s, &o);
    CHECK(db);
    imdbc *a = login("admin", "pw-admin");
    CHECK(a);
    load_rows(a, 400);
    reply r = {0};
    /* over TCP the kernel's buffers hold a few megabytes: a result of 1,280,000 rows (about 25 MB) to spill there */
    const char *q = "SELECT * FROM big2";
    uint32_t want = 160000;
    if (g_tcp) {
        SOFT(q1(a, "CREATE TABLE m (id INT64 PRIMARY KEY, v INT64)", &r) == 0 && !r.nerr);
        for (int k = 0; k < 8; k++) {
            char ins[100];
            snprintf(ins, sizeof ins, "INSERT INTO m SELECT id + %d, v FROM big2", k * 1000000);
            SOFT(q1(a, ins, &r) == 0 && !r.nerr);
        }
        q = "SELECT * FROM m", want = 1280000;
    }
    imdbc_stmt big = {q, strlen(q), NULL, 0};
    imdbs_counts c0 = counts_of(s);
    imdb_err e = {0};
    SOFT(imdbc_query(a, &big, 1, &e) == 0);
    SOFT(requests_past(s, c0.requests));
    imdbs_counts c1 = counts_of(s);
    SOFT(c1.res_spilled == c0.res_spilled + 1 && c1.res_spool_bytes > (1u << 20));
    SOFT(c1.pend_peak <= (1u << 20) + (128u << 10)); /* its room and a chunk: never the 3 MB */
    if (c1.pend_peak > (1u << 20) + (128u << 10) || c1.res_spilled != c0.res_spilled + 1)
        fprintf(stderr, "    spilled %llu, %llu bytes, peak in memory %llu\n", (unsigned long long)(c1.res_spilled - c0.res_spilled),
                (unsigned long long)c1.res_spool_bytes, (unsigned long long)c1.pend_peak);
    /* its spooled replies count against its connection's room: a statement pipelined behind them waits for the drain */
    uint64_t st0 = started_now(s);
    imdbc_stmt two = {"SELECT 2", 8, NULL, 0};
    SOFT(imdbc_query(a, &two, 1, &e) == 0);
    usleep(300000);
    SOFT(started_now(s) == st0);
    SOFT(read_reply(a, &r) == 0 && r.nrows == want && r.ndone == 1 && !r.nerr && r.state == IMDBW_IDLE);
    SOFT(!strncmp(r.text, "0|0\n", 4)); /* the first rows first (big2 in key order: 0, 1, ...) */
    SOFT(read_reply(a, &r) == 0 && !strcmp(r.text, "2\n")); /* then it ran */
    SOFT(q1(a, "SELECT COUNT(*), SUM(v) FROM big2", &r) == 0 && !strcmp(r.text, "160000|478800\n")); /* the session goes on */
    SOFT(spools_empty(s));
    imdbc_close(a);
    unserve(db, s);
}

/* every credit of a spooled result back on every path: its client gone part way through it, its session ended by a
 * KILL with it unread, and the server's stop with one unread */
static void t_server_res_spill_paths(void)
{
    imdbs_opts o;
    memset(&o, 0, sizeof o);
    o.conn_cap = 512u << 10;
    imdbs *s = NULL;
    imdb_db *db = serve(&s, &o);
    CHECK(db);
    imdbc *a = login("admin", "pw-admin");
    CHECK(a);
    load_rows(a, 400);
    imdb_err e = {0};
    /* gone part way */
    imdbc *g = login("admin", "pw-admin");
    imdbs_counts c0 = counts_of(s);
    SOFT(g && imdbc_query(g, &k_all, 1, &e) == 0);
    SOFT(requests_past(s, c0.requests) && counts_of(s).spool_held > 0);
    imdbw_msg m;
    for (int k = 0; g && k < 3; k++) SOFT(imdbc_next(g, &m, &e) == 0); /* COLUMNS and two ROWS, then gone */
    imdbc_close(g);
    SOFT(spools_empty(s));
    /* a KILL's terminate with it unread */
    imdbc *t = login("admin", "pw-admin");
    c0 = counts_of(s);
    SOFT(t && imdbc_query(t, &k_all, 1, &e) == 0);
    SOFT(requests_past(s, c0.requests) && counts_of(s).spool_held > 0);
    reply l = {0};
    uint64_t victim = 0;
    if (list_of(a, &l))
        for (uint32_t i = 0; i < l.nsess && i < 16; i++) victim = l.sess[i].id; /* the newest: t */
    SOFT(victim && kill_of(a, IMDBW_KILL_TERMINATE, victim, IMDBW_KILLED));
    SOFT(spools_empty(s));
    imdbc_close(t);
    /* the stop with one unread */
    imdbc *u = login("admin", "pw-admin");
    c0 = counts_of(s);
    SOFT(u && imdbc_query(u, &k_all, 1, &e) == 0);
    SOFT(requests_past(s, c0.requests) && counts_of(s).spool_held > 0);
    imdbc_close(a);
    imdb_err se = {0};
    SOFT(imdbs_stop(s, &se) == 0);
    SOFT(imdbsp_live() == 0); /* the stop freed the unread spool */
    imdbc_close(u);
    imdb_close(db);
    SOFT(imdbw_live_blocks() == g_blocks);
}

/* a role's share of the spools (--role-copy-spool, 4 MiB): role plain's two connections each leave a 3 MB result unread:
 * the first spills within the share, the second crosses it and is refused by name; role other's 3 MB result spills
 * within its own share and is read whole while plain's are held; a superuser exempt */
static void t_server_res_role_share(void)
{
    imdbs_opts o;
    memset(&o, 0, sizeof o);
    o.conn_cap = 256u << 10;
    o.role_copy_spool = 4u << 20;
    imdbs *s = NULL;
    imdb_db *db = serve(&s, &o);
    CHECK(db);
    imdbc *a = login("admin", "pw-admin");
    CHECK(a);
    load_rows(a, 400);
    reply r = {0};
    static const char *const setup[] = {"GRANT SELECT ON big2 TO plain", "CREATE ROLE other LOGIN PASSWORD 'pw-o'",
                                        "GRANT SELECT ON big2 TO other"};
    for (size_t i = 0; i < sizeof setup / sizeof *setup; i++) SOFT(q1(a, setup[i], &r) == 0 && !r.nerr);
    imdbc *p0 = login("plain", "pw"), *p = login("plain", "pw"), *ot = login("other", "pw-o");
    CHECK(p0 && p && ot);
    imdb_err e = {0};
    imdbs_counts c0 = counts_of(s);
    SOFT(imdbc_query(p0, &k_all, 1, &e) == 0); /* spilled within the share, unread */
    SOFT(requests_past(s, c0.requests));
    SOFT(counts_of(s).res_refused == c0.res_refused);
    c0 = counts_of(s);
    SOFT(imdbc_query(p, &k_all, 1, &e) == 0); /* crosses the share */
    SOFT(requests_past(s, c0.requests));
    imdbs_counts c1 = counts_of(s);
    SOFT(c1.res_refused == c0.res_refused + 1 && c1.role_spool_limits == c0.role_spool_limits + 1);
    SOFT(q1(ot, "SELECT * FROM big2", &r) == 0 && r.nrows == 160000 && !r.nerr); /* another role's: its own share */
    if (r.nerr || r.nrows != 160000) fprintf(stderr, "    other's read: %u rows, rc %d, code %u: %s\n", r.nrows, r.rc, r.err_code, r.err);
    SOFT(q1(a, "SELECT * FROM big2", &r) == 0 && r.nrows == 160000 && !r.nerr);  /* a superuser's: exempt */
    SOFT(read_reply(p, &r) == 0 && r.nerr == 1 && r.err_code == (uint32_t)-IMDB_ERR_LIMIT && strstr(r.err, "--role-copy-spool") &&
         r.nrows < 160000 && r.state == IMDBW_IDLE);
    if (!strstr(r.err, "--role-copy-spool")) fprintf(stderr, "    plain's read: %u rows, %u errors: %s\n", r.nrows, r.nerr, r.err);
    SOFT(q1(p, "SELECT COUNT(*) FROM big2", &r) == 0 && !strcmp(r.text, "160000\n")); /* the session goes on */
    SOFT(read_reply(p0, &r) == 0 && !r.nerr && r.nrows == 160000); /* the first, within the share: whole */
    SOFT(spools_empty(s));
    imdbc_close(p);
    imdbc_close(ot);
    imdbc_close(p0);
    imdbc_close(a);
    unserve(db, s);
}

/* the server's spools full: a read past its room refused by name (ERROR 3, what was handed over before it kept), and a
 * write's RETURNING past every bound delivered whole with its commit (its rows are in the log: never refused) */
static void t_server_res_bounds(void)
{
    imdbs_opts o;
    memset(&o, 0, sizeof o);
    o.conn_cap = 256u << 10;
    o.copy_spool = 512u << 10;
    imdbs *s = NULL;
    imdb_db *db = serve(&s, &o);
    CHECK(db);
    imdbc *a = login("admin", "pw-admin"), *b = login("admin", "pw-admin");
    CHECK(a && b);
    load_rows(a, 400);
    reply r = {0};
    SOFT(q1(a, "CREATE TABLE w (id INT64 PRIMARY KEY, v INT64)", &r) == 0 && !r.nerr);
    imdb_err e = {0};
    imdbs_counts c0 = counts_of(s);
    SOFT(imdbc_query(b, &k_all, 1, &e) == 0);
    SOFT(requests_past(s, c0.requests));
    SOFT(read_reply(b, &r) == 0 && r.nerr == 1 && r.err_code == (uint32_t)-IMDB_ERR_LIMIT && strstr(r.err, "--copy-spool") &&
         r.nrows < 160000);
    imdbc_stmt ins = {"INSERT INTO w SELECT id, v FROM big2 RETURNING id, v", 52, NULL, 0};
    c0 = counts_of(s);
    SOFT(imdbc_query(a, &ins, 1, &e) == 0);
    SOFT(requests_past(s, c0.requests));
    imdbs_counts c1 = counts_of(s);
    SOFT(c1.res_spool_bytes - c0.res_spool_bytes > (512u << 10)); /* spooled past the server's bound */
    SOFT(read_reply(a, &r) == 0 && !r.nerr && r.nrows == 160000 && r.ndone == 1 && r.has_write && r.write_commit > 0);
    SOFT(q1(b, "SELECT COUNT(*) FROM w", &r) == 0 && !strcmp(r.text, "160000\n"));
    SOFT(spools_empty(s));
    imdbc_close(a);
    imdbc_close(b);
    unserve(db, s);
}

/* no spool directory: a read past its room refused by name; a write's RETURNING held in memory and delivered whole */
static void t_server_res_nospool(void)
{
    imdbs_opts o;
    memset(&o, 0, sizeof o);
    o.conn_cap = 256u << 10;
    g_nospool = true;
    imdbs *s = NULL;
    imdb_db *db = serve(&s, &o);
    g_nospool = false;
    CHECK(db);
    imdbc *a = login("admin", "pw-admin"), *b = login("admin", "pw-admin");
    CHECK(a && b);
    load_rows(a, 400);
    reply r = {0};
    SOFT(q1(a, "CREATE TABLE w (id INT64 PRIMARY KEY, v INT64)", &r) == 0 && !r.nerr);
    imdb_err e = {0};
    imdbs_counts c0 = counts_of(s);
    SOFT(imdbc_query(b, &k_all, 1, &e) == 0);
    SOFT(requests_past(s, c0.requests));
    SOFT(read_reply(b, &r) == 0 && r.nerr == 1 && r.err_code == (uint32_t)-IMDB_ERR_STATE && strstr(r.err, "spool directory"));
    imdbc_stmt ins = {"INSERT INTO w SELECT id, v FROM big2 RETURNING id, v", 52, NULL, 0};
    c0 = counts_of(s);
    SOFT(imdbc_query(a, &ins, 1, &e) == 0);
    SOFT(requests_past(s, c0.requests));
    SOFT(read_reply(a, &r) == 0 && !r.nerr && r.nrows == 160000 && r.has_write);
    imdbc_close(a);
    imdbc_close(b);
    unserve(db, s);
}

/* 2b-2a's measure (recorded, never asserted): IMDB_SRV_RES_ROWS rows (a multiple of 160,000) read by SELECT * through
 * the socket by a client that reads at once, three runs each: as before the spool (every frame in memory: the test
 * option), at the default room (32 MiB a connection) and at a room of 1 MiB; the time and what spilled. Skipped unless
 * IMDB_SRV_RES_ROWS is set */
static void t_server_res_measure(void)
{
    const char *env = getenv("IMDB_SRV_RES_ROWS");
    if (!env) return;
    long want = atol(env), mult = want / 160000 < 1 ? 1 : want / 160000;
    for (int mode = 1; mode < 3; mode++) { /* (2c: mode 0, every result in memory as before the spool, gone with its knob) */
        imdbs_opts o;
        memset(&o, 0, sizeof o);
        o.conn_cap = mode == 2 ? 1u << 20 : 0;
        imdbs *s = NULL;
        imdb_db *db = serve(&s, &o);
        CHECK(db);
        imdbc *c = login("admin", "pw-admin");
        CHECK(c);
        imdbc_set_timeout(c, 0);
        load_rows(c, 400);
        reply r = {0};
        char q[200];
        snprintf(q, sizeof q, "CREATE TABLE m (id INT64 PRIMARY KEY, v INT64)");
        SOFT(q1(c, q, &r) == 0 && !r.nerr);
        for (long k = 0; k < mult; k++) {
            snprintf(q, sizeof q, "INSERT INTO m SELECT id + %ld, v FROM big2", k * 1000000L);
            SOFT(q1(c, q, &r) == 0 && !r.nerr);
        }
        for (int run = 0; run < 3; run++) {
            imdbs_counts c0 = counts_of(s);
            uint64_t t0 = imdb_mono_ns();
            SOFT(q1(c, "SELECT * FROM m", &r) == 0 && !r.nerr && r.nrows == (uint32_t)(mult * 160000));
            uint64_t ms = (imdb_mono_ns() - t0) / 1000000u;
            imdbs_counts c1 = counts_of(s);
            fprintf(stderr, "    %s, run %d: %ld rows in %llu ms; spilled %.1f MB; memory peak %.1f MB\n",
                    mode == 0 ? "before (all in memory)" : mode == 1 ? "room 32 MiB" : "room 1 MiB", run, mult * 160000,
                    (unsigned long long)ms, (double)(c1.res_spool_bytes - c0.res_spool_bytes) / 1048576.0,
                    (double)c1.pend_peak / 1048576.0);
        }
        imdbc_close(c);
        unserve(db, s);
    }
}

/* 2b-2a's rule, 2b-2b's release: a spool is charged by the bytes of its file not given back. A client that has read all
 * but the tail of a spooled result: its sent bytes given back in 1 MiB steps (holes), so the charge is its unsent part
 * and a step at most; with releases refused (a file system without holes: imdbsp_no_release) the whole file stays charged
 * until it is freed, as before. The rest read, the file freed and every credit back, both ways */
static void t_server_res_tail(void)
{
    imdbs_opts o;
    memset(&o, 0, sizeof o);
    o.conn_cap = 256u << 10;
    o.test_sndbuf = 4096; /* (the kernel holds none of the unread tail: it stays the spool's) */
    imdbs *s = NULL;
    imdb_db *db = serve(&s, &o);
    CHECK(db);
    imdbc *a = login("admin", "pw-admin");
    CHECK(a);
    load_rows(a, 400);
    imdb_err e = {0};
    for (int keep = 0; keep < 2; keep++) {
        imdbsp_no_release(keep);
        imdbs_counts c0 = counts_of(s);
        SOFT(imdbc_query(a, &k_all, 1, &e) == 0);
        SOFT(requests_past(s, c0.requests));
        imdbs_counts c1 = counts_of(s);
        uint64_t file = c1.res_spool_bytes - c0.res_spool_bytes;
        SOFT(file > (2u << 20) && c1.spool_held == file);
        imdbw_msg m;
        uint64_t rows = 0;
        while (rows < 150000 && imdbc_next(a, &m, &e) == 0) /* all but the tail */
            if (m.type == IMDBW_ROWS) rows += m.nsets;
        /* the server's thread sends and gives back as the client reads: waited on by its counts (a fixed 200 ms was not
         * enough under load: sortpg's suite, 11-21), a fixed pause where nothing should move */
        imdbs_counts c2 = counts_of(s);
        if (keep) usleep(200000), c2 = counts_of(s);
        else
            for (int w = 0; w < 1000 && !(c2.spool_held < file / 2 && c2.spool_held <= (3u << 19)); w++)
                usleep(10000), c2 = counts_of(s);
        uint64_t unsent = c2.spool_held - (c2.spool_held > (1u << 20) ? (1u << 20) : 0); /* (a step at most not given back) */
        SOFT(rows >= 150000 && rows < 160000);
        if (keep) SOFT(c2.spool_held == file && c2.res_released == c1.res_released); /* the whole file still charged */
        else SOFT(c2.spool_held < file / 2 && unsent <= (512u << 10) && c2.res_released >= (1u << 20) &&
                  c2.res_released - c1.res_released + c2.spool_held >= file - (512u << 10));
        if (keep ? c2.spool_held != file : c2.spool_held >= file / 2)
            fprintf(stderr, "    release %s: after %llu rows read, %llu of %llu charged, %llu given back\n", keep ? "refused" : "on",
                    (unsigned long long)rows, (unsigned long long)c2.spool_held, (unsigned long long)file,
                    (unsigned long long)(c2.res_released - c1.res_released));
        reply r = {0};
        SOFT(read_reply(a, &r) == 0 && rows + r.nrows == 160000 && r.ndone == 1);
        SOFT(spools_empty(s));
    }
    imdbsp_no_release(false);
    imdbc_close(a);
    unserve(db, s);
}

/* a KILL's terminate of a session whose client still reads (a spooled result's backlog taking it over a second): the
 * whole result, then the ERROR (its deadline runs from the last byte its client took, never from the KILL) */
static void t_server_res_kill_reading(void)
{
    imdbs_opts o;
    memset(&o, 0, sizeof o);
    o.conn_cap = 256u << 10;
    imdbs *s = NULL;
    imdb_db *db = serve(&s, &o);
    CHECK(db);
    imdbc *a = login("admin", "pw-admin"), *t = login("admin", "pw-admin");
    CHECK(a && t);
    load_rows(a, 400);
    imdb_err e = {0};
    imdbs_counts c0 = counts_of(s);
    SOFT(imdbc_query(t, &k_all, 1, &e) == 0);
    SOFT(requests_past(s, c0.requests) && counts_of(s).spool_held > 0);
    reply l = {0};
    uint64_t victim = 0;
    if (list_of(a, &l))
        for (uint32_t i = 0; i < l.nsess && i < 16; i++) victim = l.sess[i].id; /* the newest: t */
    SOFT(victim && kill_of(a, IMDBW_KILL_TERMINATE, victim, IMDBW_KILLED));
    imdbw_msg m;
    uint64_t rows = 0, t0 = imdb_mono_ns();
    bool killed = false;
    while (imdbc_next(t, &m, &e) == 0) { /* a frame every 40 ms: the backlog takes it well over a second */
        if (m.type == IMDBW_ROWS) rows += m.nsets;
        if (m.type == IMDBW_ERROR && m.ntexts && memmem(m.texts[0].p, m.texts[0].len, "a KILL", 6)) killed = true;
        usleep(40000);
    }
    uint64_t ms = (imdb_mono_ns() - t0) / 1000000u;
    SOFT(rows == 160000 && killed && ms > 1000);
    if (rows != 160000 || !killed) fprintf(stderr, "    the killed reader: %llu rows, ERROR %d, %llu ms\n", (unsigned long long)rows, killed,
                                           (unsigned long long)ms);
    SOFT(spools_empty(s));
    imdbc_close(t);
    imdbc_close(a);
    unserve(db, s);
}

/* COPY's role share (--role-copy-spool, 1 MiB): a role's COPY FROM past it refused at once (the table unchanged); its
 * COPY TO (2b-2b) a result's, never a ring: past its room and the share refused at once by name, in parts whole (the
 * server's send buffer 4 KiB, test_sndbuf: the kernel holds no export) */
static void t_server_copy_role_share(void)
{
    imdbs_opts o;
    memset(&o, 0, sizeof o);
    o.role_copy_spool = 1u << 20;
    o.conn_cap = 128u << 10;
    o.test_sndbuf = 4096;
    imdbs *s = NULL;
    imdb_db *db = serve(&s, &o);
    CHECK(db);
    imdbc *a = login("admin", "pw-admin");
    CHECK(a);
    load_rows(a, 400);
    reply r = {0};
    static const char *const setup[] = {"CREATE TABLE cf (id INT64 PRIMARY KEY, v INT64)", "GRANT SELECT, INSERT ON cf TO plain",
                                        "GRANT SELECT ON big2 TO plain"};
    for (size_t i = 0; i < sizeof setup / sizeof *setup; i++) SOFT(q1(a, setup[i], &r) == 0 && !r.nerr);
    imdbc *p = login("plain", "pw"), *p2 = login("plain", "pw");
    CHECK(p && p2);
    imdb_err e = {0};
    /* COPY FROM: 2 MB of rows past the 1 MiB share */
    imdbc_stmt cf = {"COPY cf FROM STDIN", 18, NULL, 0};
    SOFT(imdbc_query(p, &cf, 1, &e) == 0 && read_reply(p, &r) == 0 && r.copy_in);
    char line[64];
    static char chunk[64u << 10];
    size_t n = 0;
    for (int i = 0; i < 100000; i++) {
        int k = snprintf(line, sizeof line, "%d,%d\n", i, i);
        if (n + (size_t)k > sizeof chunk) {
            SOFT(imdbc_copy_data(p, chunk, n, &e) == 0);
            n = 0;
        }
        memcpy(chunk + n, line, (size_t)k), n += (size_t)k;
    }
    SOFT(imdbc_copy_data(p, chunk, n, &e) == 0 && imdbc_copy_done(p, &e) == 0);
    SOFT(read_reply(p, &r) == 0 && r.nerr == 1 && r.err_code == (uint32_t)-IMDB_ERR_LIMIT && strstr(r.err, "--role-copy-spool"));
    SOFT(q1(a, "SELECT COUNT(*) FROM cf", &r) == 0 && !strcmp(r.text, "0\n"));
    SOFT(spools_empty(s));
    /* 2b-2b: a role's COPY TO is a result's, never a ring (no engine wait). Its client reading only after the engine
     * finished: the export (about 1.4 MB) past the room (128 KiB) and the share (1 MiB) fails at once by name, a prefix
     * then the ERROR, every credit back; the export in parts (the advised COPY (SELECT ... WHERE a key range) TO STDOUT,
     * as the role, under its statement_memory and caps), each within them, read after the engine finished: whole, the
     * parts' bytes the superuser's whole export's in key order; a superuser's COPY TO its ring still */
    size_t cap = 4u << 20;
    uint8_t *whole = malloc(cap), *pre = malloc(cap);
    CHECK(whole && pre);
    imdbs_counts c1 = counts_of(s);
    g_out = whole, g_outcap = cap, g_outlen = 0;
    SOFT(q1(a, "COPY (SELECT id, v FROM big2 ORDER BY id) TO STDOUT", &r) == 0 && !r.nerr && r.count == 160000 &&
         g_outlen == r.nout);
    size_t wlen = g_outlen;
    SOFT(wlen > (1u << 20) + (128u << 10)); /* past the room and the share together */
    SOFT(counts_of(s).copy_out == c1.copy_out + 1 && counts_of(s).copy_out_res == c1.copy_out_res); /* a superuser's ring */
    static const char cts[] = "COPY (SELECT id, v FROM big2 ORDER BY id) TO STDOUT";
    imdbc_stmt ct = {cts, sizeof cts - 1, NULL, 0};
    uint64_t req0 = counts_of(s).requests, t0 = imdb_mono_ns();
    SOFT(imdbc_query(p, &ct, 1, &e) == 0);
    SOFT(requests_past(s, req0)); /* the engine finished without its reader: never a wait */
    SOFT((imdb_mono_ns() - t0) / 1000000u < 5000);
    SOFT(counts_of(s).spool_held <= (1u << 20));
    g_out = pre, g_outcap = cap, g_outlen = 0;
    SOFT(read_reply(p, &r) == 0 && r.nerr == 1 && r.err_code == (uint32_t)-IMDB_ERR_LIMIT && !r.ndone &&
         strstr(r.err, "--role-copy-spool") && strstr(r.err, "export in parts"));
    if (!strstr(r.err, "export in parts")) fprintf(stderr, "    a role's export past its share: %s\n", r.err);
    SOFT(g_outlen > 0 && g_outlen < wlen && !memcmp(pre, whole, g_outlen)); /* a prefix, then the ERROR */
    SOFT(counts_of(s).copy_out_res == c1.copy_out_res + 1 && counts_of(s).copy_out == c1.copy_out + 1 &&
         counts_of(s).role_spool_limits == c1.role_spool_limits + 1);
    SOFT(spools_empty(s));
    static const char *const parts[] = {"COPY (SELECT id, v FROM big2 WHERE id < 200000 ORDER BY id) TO STDOUT",
                                        "COPY (SELECT id, v FROM big2 WHERE id >= 200000 ORDER BY id) TO STDOUT"};
    size_t got = 0;
    for (int k = 0; k < 2; k++) {
        imdbc_stmt pt = {parts[k], (uint32_t)strlen(parts[k]), NULL, 0};
        req0 = counts_of(s).requests;
        SOFT(imdbc_query(p, &pt, 1, &e) == 0 && requests_past(s, req0)); /* each part spooled whole, unread */
        g_out = pre + got, g_outcap = cap - got, g_outlen = 0;
        SOFT(read_reply(p, &r) == 0 && !r.nerr && r.ndone == 1 && r.count == 80000);
        if (r.nerr) fprintf(stderr, "    part %d: %s\n", k, r.err);
        got += g_outlen;
    }
    SOFT(got == wlen && !memcmp(pre, whole, wlen));
    g_out = NULL, g_outlen = 0, g_outcap = 0;
    free(whole);
    free(pre);
    SOFT(spools_empty(s));
    /* the share all but 100 bytes held by an upload kept open: another of the role's connections' COPY TO, unread, goes
     * to memory within its room and fails at once by name past it (no spool takes it), never waiting */
    SOFT(imdbc_query(p, &cf, 1, &e) == 0 && read_reply(p, &r) == 0 && r.copy_in);
    static char upl[(1u << 20) - 100];
    memset(upl, 'x', sizeof upl);
    SOFT(imdbc_copy_data(p, upl, sizeof upl, &e) == 0);
    for (int w = 0; w < 500 && counts_of(s).spool_held < sizeof upl; w++) usleep(10000);
    SOFT(counts_of(s).spool_held == sizeof upl);
    imdbs_counts c0 = counts_of(s);
    req0 = counts_of(s).requests, t0 = imdb_mono_ns();
    SOFT(imdbc_query(p2, &ct, 1, &e) == 0 && requests_past(s, req0));
    SOFT((imdb_mono_ns() - t0) / 1000000u < 5000); /* at once */
    SOFT(read_reply(p2, &r) == 0 && r.nerr == 1 && strstr(r.err, "--role-copy-spool") && !r.ndone);
    if (!strstr(r.err, "--role-copy-spool")) fprintf(stderr, "    COPY TO past its room, the share full: %u errors, %llu bytes: %s\n", r.nerr, (unsigned long long)r.nout, r.err);
    SOFT(r.nout > 0 && r.nout <= (128u << 10) + (128u << 10)); /* its room's frames (a chunk past it at most) */
    SOFT(counts_of(s).role_spool_limits == c0.role_spool_limits + 1 && counts_of(s).spool_held == sizeof upl);
    SOFT(imdbc_copy_fail(p, "done", &e) == 0 && read_reply(p, &r) == 0 && r.nerr == 1);
    SOFT(spools_empty(s));
    imdbc_close(p);
    imdbc_close(p2);
    imdbc_close(a);
    unserve(db, s);
}

/* 2b-2b: a role's export several times its spool share (about 5.8 MB against 3 MiB), its reader late by 150 ms and then
 * keeping up (the output slowed, 10 ms a write): spilled, its sent bytes given back as it goes, so it streams whole and
 * the share never refuses it (charged by extent, it would fail past the share) */
static void t_server_copy_role_stream(void)
{
    imdbs_opts o;
    memset(&o, 0, sizeof o);
    o.role_copy_spool = 3u << 20;
    o.conn_cap = 128u << 10;
    o.test_sndbuf = 4096;
    imdbs *s = NULL;
    imdb_db *db = serve(&s, &o);
    CHECK(db);
    imdbc *a = login("admin", "pw-admin");
    CHECK(a);
    load_rows(a, 400);
    reply r = {0};
    static const char *const setup[] = {"CREATE TABLE big3 (id INT64 PRIMARY KEY, v INT64)",
                                        "INSERT INTO big3 SELECT id * 4, v FROM big2", "INSERT INTO big3 SELECT id * 4 + 1, v FROM big2",
                                        "INSERT INTO big3 SELECT id * 4 + 2, v FROM big2", "INSERT INTO big3 SELECT id * 4 + 3, v FROM big2",
                                        "GRANT SELECT ON big3 TO plain"};
    for (size_t i = 0; i < sizeof setup / sizeof *setup; i++) SOFT(q1(a, setup[i], &r) == 0 && !r.nerr);
    imdbc *p = login("plain", "pw");
    CHECK(p);
    imdb_err e = {0};
    /* the spool's file system gives blocks back (tmpfs, ext4, xfs do): else the share bounds the export, 2b-2a's rule, and
     * this case is not tested here */
    int dfd = -1;
    imdbsp *sp = NULL;
    bool holes = !imdbsp_dir(g_spool, &dfd, &e) && !imdbsp_open(dfd, &sp, &e);
    static char blk[1u << 20];
    holes = holes && !imdbsp_write(sp, 0, blk, sizeof blk, &e) && imdbsp_release(sp, 0, sizeof blk);
    imdbsp_close(sp);
    if (dfd >= 0) close(dfd);
    if (!holes) {
        fprintf(stderr, "    the spool's file system punches no holes: a role's export past its share not tested here\n");
        imdbc_close(p);
        imdbc_close(a);
        unserve(db, s);
        return;
    }
    static const char cts[] = "COPY big3 TO STDOUT";
    imdbc_stmt ct = {cts, sizeof cts - 1, NULL, 0};
    imdbs_test_copy_hold(10);
    imdbs_counts c0 = counts_of(s);
    uint64_t before = started_now(s);
    SOFT(imdbc_query(p, &ct, 1, &e) == 0);
    wait_started(s, before);
    usleep(150000); /* its reader late: the room fills, the rest spills */
    SOFT(read_reply(p, &r) == 0 && !r.nerr && r.ndone == 1 && r.count == 640000 && r.nout > (5u << 20));
    if (r.nerr || r.count != 640000) fprintf(stderr, "    a role's export past its share: %u errors, count %llu: %s\n", r.nerr, (unsigned long long)r.count, r.err);
    imdbs_counts c1 = counts_of(s);
    SOFT(c1.res_spilled == c0.res_spilled + 1 && c1.role_spool_limits == c0.role_spool_limits &&
         c1.res_spool_bytes - c0.res_spool_bytes > (3u << 20) + (128u << 10) && c1.res_released - c0.res_released >= (2u << 20));
    if (c1.res_spool_bytes - c0.res_spool_bytes <= (3u << 20) + (128u << 10))
        fprintf(stderr, "    spooled %llu, given back %llu\n", (unsigned long long)(c1.res_spool_bytes - c0.res_spool_bytes),
                (unsigned long long)(c1.res_released - c0.res_released));
    imdbs_test_copy_hold(0);
    SOFT(spools_empty(s));
    imdbc_close(p);
    imdbc_close(a);
    unserve(db, s);
}

/* 2b-2b: the trickle floor: a client must take 1 KiB of its waiting replies within --send-timeout (3 s here), never just
 * a byte. Each plain write at most 64 bytes (test_write_max) and the server's send buffer 4 KiB, so the bytes the server
 * sees taken are its reader's own pace. One reading 64 bytes a second (kept by the old rule: a buffer freed every second)
 * is dropped within the timeout and a little; one reading 512 a second is kept for 8 s */
static void t_server_trickle(void)
{
    imdbs_opts o;
    memset(&o, 0, sizeof o);
    o.send_timeout_ms = 3000;
    o.test_write_max = 64;
    o.test_sndbuf = 4096;
    imdbs *s = NULL;
    imdb_db *db = serve(&s, &o);
    CHECK(db);
    imdbc *a = login("admin", "pw-admin");
    CHECK(a);
    load_rows(a, 400);
    imdb_err e = {0};
    for (int fast = 0; fast < 2; fast++) {
        imdbc *c = login("admin", "pw-admin");
        CHECK(c);
        imdbs_counts c0 = counts_of(s);
        SOFT(imdbc_query(c, &k_all, 1, &e) == 0);
        int fd = imdbc_fd(c);
        size_t want = fast ? 512 : 64, total = 0;
        /* the window from its first bytes: a statement slow to begin its rows (160,000 under TSan on a loaded machine took
         * seconds, 11-22) holds no reply waiting, so no clock of the server's runs before them either */
        struct pollfd pf0 = {fd, POLLIN, 0};
        (void)poll(&pf0, 1, 30000);
        uint64_t t0 = imdb_mono_ns(), dropped_ms = 0;
        while (imdb_mono_ns() - t0 < 8000000000u) {
            if (counts_of(s).dropped != c0.dropped) {
                dropped_ms = (imdb_mono_ns() - t0) / 1000000u;
                break;
            }
            char buf[512];
            size_t got = 0;
            while (got < want) { /* its second's bytes, then a second's pause */
                struct pollfd pf = {fd, POLLIN, 0};
                if (poll(&pf, 1, 200) <= 0) break;
                ssize_t k = recv(fd, buf, want - got, MSG_DONTWAIT);
                if (k <= 0) break;
                got += (size_t)k;
            }
            total += got;
            usleep(1000000);
        }
        if (fast) SOFT(counts_of(s).dropped == c0.dropped && total >= 3000);
        else SOFT(dropped_ms > 0 && dropped_ms < 6000 && total < 1024);
        if (fast ? counts_of(s).dropped != c0.dropped : !dropped_ms || dropped_ms >= 6000)
            fprintf(stderr, "    a reader of %zu bytes a second: %zu read, dropped after %llu ms (0: kept)\n", want, total,
                    (unsigned long long)dropped_ms);
        imdbc_close(c);
    }
    reply r = {0};
    SOFT(q1(a, "SELECT COUNT(*) FROM big", &r) == 0 && !strcmp(r.text, "400\n"));
    imdbc_close(a);
    unserve(db, s);
}

/* lines of the event log at path holding needle */
static int ev_count(const char *path, const char *needle)
{
    FILE *f = fopen(path, "r");
    if (!f) return 0;
    char line[4096];
    int n = 0;
    while (fgets(line, sizeof line, f)) n += strstr(line, needle) != NULL;
    fclose(f);
    return n;
}

/* 2b-2b: a role's defaults. --role-slow-statement-ms (1 ms here): a role's slow statement an event in the log, a
 * superuser's not; a superuser that SET slow_statement_ms and was then demoted returns to the role's default (not to
 * none). --role-idle-session (1 s): a role's session with nothing to do ended with an ERROR naming the option (a PING
 * every 300 ms keeps nothing; its open transaction rolled back), a role's running statement past it and a superuser's idle
 * session untouched */
static void t_server_role_defaults(void)
{
    char ev[300];
    snprintf(ev, sizeof ev, "%s/events", test_tmpdir());
    g_events = ev;
    imdbs_opts o;
    memset(&o, 0, sizeof o);
    o.role_slow_ms = 1;
    o.role_sess_idle_ms = 1000;
    imdbs *s = NULL;
    imdb_db *db = serve(&s, &o);
    CHECK(db);
    imdbc *a = login("admin", "pw-admin");
    CHECK(a);
    load_rows(a, 400);
    reply r = {0};
    imdb_err e = {0};
    static const char *const setup[] = {"GRANT SELECT, INSERT ON big TO plain", "GRANT SELECT ON big2 TO plain",
                                        "CREATE ROLE su2 LOGIN SUPERUSER PASSWORD 'pw'", "GRANT SELECT ON big2 TO su2"};
    for (size_t i = 0; i < sizeof setup / sizeof *setup; i++) SOFT(q1(a, setup[i], &r) == 0 && !r.nerr);
    static const char slow[] = "COPY big2 TO STDOUT"; /* slowed by imdbs_test_copy_hold: past the idle bound in every build */
    /* the slow-statement default: a role's an event, a superuser's none */
    int ev0 = ev_count(ev, "\"slow\"");
    imdbc *p = login("plain", "pw");
    CHECK(p);
    SOFT(q1(p, "SELECT COUNT(*) FROM big2", &r) == 0 && !r.nerr);
    SOFT(ev_count(ev, "\"slow\"") == ev0 + 1);
    SOFT(q1(a, "SELECT COUNT(*) FROM big2", &r) == 0 && !r.nerr);
    SOFT(ev_count(ev, "\"slow\"") == ev0 + 1);
    /* a demoted superuser: its SET taken back to the role's default */
    imdbc *u = login("su2", "pw");
    CHECK(u);
    SOFT(q1(u, "SET slow_statement_ms = 100000", &r) == 0 && !r.nerr);
    SOFT(q1(u, "SELECT COUNT(*) FROM big2", &r) == 0 && !r.nerr && ev_count(ev, "\"slow\"") == ev0 + 1);
    SOFT(q1(a, "ALTER ROLE su2 NOSUPERUSER", &r) == 0 && !r.nerr);
    SOFT(q1(u, "SELECT COUNT(*) FROM big2", &r) == 0 && !r.nerr);
    SOFT(ev_count(ev, "\"slow\"") == ev0 + 2);
    if (ev_count(ev, "\"slow\"") != ev0 + 2) fprintf(stderr, "    slow events: %d after the demotion, %d before\n", ev_count(ev, "\"slow\""), ev0);
    imdbc_close(u); /* (a role's session now: left idle, the idle bound would end it) */
    /* a running statement past the idle bound is not idle (a COPY TO slowed to about two seconds in every build: 100 ms a
     * write); then its session idles and is ended. Its session logged in just before (one left waiting in a slow build
     * would be ended idle first) */
    imdbc_close(p);
    p = login("plain", "pw");
    CHECK(p);
    imdbs_counts c0 = counts_of(s);
    imdbs_test_copy_hold(100);
    uint64_t t0 = imdb_mono_ns();
    SOFT(q1(p, slow, &r) == 0 && !r.nerr && r.count == 160000);
    imdbs_test_copy_hold(0);
    uint64_t ran = (imdb_mono_ns() - t0) / 1000000u;
    if (ran < 1200) fprintf(stderr, "    the slow statement ran %llu ms: not past the idle bound\n", (unsigned long long)ran);
    SOFT(counts_of(s).idle_closed == c0.idle_closed);
    t0 = imdb_mono_ns();
    SOFT(read_reply(p, &r) != 0 && r.nerr == 1 && strstr(r.err, "--role-idle-session"));
    uint64_t idle_ms = (imdb_mono_ns() - t0) / 1000000u;
    SOFT(idle_ms >= 800 && idle_ms < 4000 && counts_of(s).idle_closed == c0.idle_closed + 1);
    if (!strstr(r.err, "--role-idle-session")) fprintf(stderr, "    idle: after %llu ms: %s\n", (unsigned long long)idle_ms, r.err);
    imdbc_close(p);
    /* pings keep nothing; an open transaction rolled back */
    p = login("plain", "pw");
    CHECK(p);
    SOFT(q1(p, "BEGIN", &r) == 0 && !r.nerr && q1(p, "INSERT INTO big VALUES (100000, 1)", &r) == 0 && !r.nerr);
    t0 = imdb_mono_ns();
    bool ended = false;
    while (!ended && imdb_mono_ns() - t0 < 4000000000u) {
        usleep(300000);
        if (imdbc_ping(p, &e) || read_reply(p, &r) || !r.pong) ended = true;
    }
    SOFT(ended && strstr(r.err, "--role-idle-session"));
    if (!strstr(r.err, "--role-idle-session")) fprintf(stderr, "    pinged: %s\n", r.err);
    SOFT(q1(a, "SELECT COUNT(*) FROM big WHERE id = 100000", &r) == 0 && !strcmp(r.text, "0\n"));
    imdbc_close(p);
    /* a superuser's idle session untouched */
    usleep(1500000);
    SOFT(q1(a, "SELECT 1", &r) == 0 && !strcmp(r.text, "1\n"));
    SOFT(counts_of(s).idle_closed == c0.idle_closed + 2 && counts_of(s).ends[IMDBS_END_IDLE] >= 2);
    imdbc_close(a);
    unserve(db, s);
}


/* 2b-3: --role-idle-session's busy by progress (D35: a frame only partly received; reads the server holds). A QUERY half
 * sent and then silent is idle: closed past the bound. The same frame arriving a KiB every 400 ms, past the bound three
 * times over, is not: answered once whole. A role's second connection whose request its role's queue share holds unread
 * (the first's result unread past its reply share, its three padded requests past the 1 MiB queue share) is not idle
 * either: answered once the first reads */
static void t_server_idle_busy(void)
{
    imdbs_opts o;
    memset(&o, 0, sizeof o);
    o.role_sess_idle_ms = 1000;
    o.role_reply_bytes = 1u << 20;
    o.role_queue_bytes = 1u << 20;
    imdbs *s = NULL;
    imdb_db *db = serve(&s, &o);
    CHECK(db);
    imdbc *a = login("admin", "pw-admin");
    CHECK(a);
    reply r = {0};
    imdb_err e = {0};
    static char text[16000]; /* (16 KiB: 16 pieces 200 ms apart, past the bound three times; five pieces a bound) */
    size_t n = (size_t)snprintf(text, sizeof text, "SELECT 7 -- ");
    memset(text + n, 'x', sizeof text - n - 1);
    text[sizeof text - 1] = 0;
    imdbw_text txt = {(const uint8_t *)text, (uint32_t)strlen(text)};
    imdbw_span none = {(const uint8_t *)"", 0, 0};
    imdbw_msg q;
    memset(&q, 0, sizeof q);
    q.type = IMDBW_QUERY, q.texts = &txt, q.ntexts = 1, q.params = &none;
    imdbw_buf b;
    imdbw_buf_init(&b);
    imdbw_msg_put(&b, &q, NULL);
    CHECK(!b.err);
    /* half, then silence: idle */
    imdbc *p = login("plain", "pw");
    CHECK(p);
    imdbs_counts c0 = counts_of(s);
    SOFT(imdbc_send_raw(p, b.p, b.len / 2, &e) == 0);
    uint64_t t0 = imdb_mono_ns();
    SOFT(read_reply(p, &r) != 0 && r.nerr == 1 && strstr(r.err, "--role-idle-session"));
    uint64_t ms = (imdb_mono_ns() - t0) / 1000000u;
    SOFT(ms >= 800 && ms < 4000 && counts_of(s).idle_closed == c0.idle_closed + 1);
    if (!strstr(r.err, "--role-idle-session")) fprintf(stderr, "    half a frame: after %llu ms: %s\n", (unsigned long long)ms, r.err);
    imdbc_close(p);
    /* a KiB every 200 ms: busy while it arrives */
    p = login("plain", "pw");
    CHECK(p);
    c0 = counts_of(s);
    for (size_t off = 0; off < b.len; off += 1024) {
        size_t k = b.len - off < 1024 ? b.len - off : 1024;
        SOFT(imdbc_send_raw(p, b.p + off, k, &e) == 0);
        if (off + k < b.len) usleep(200000);
    }
    SOFT(read_reply(p, &r) == 0 && !r.nerr && strstr(r.text, "7"));
    SOFT(counts_of(s).idle_closed == c0.idle_closed);
    if (r.nerr) fprintf(stderr, "    a frame arriving: %s\n", r.err);
    imdbc_close(p);
    imdbw_buf_free(&b);
    /* reads held by the role's queue share */
    load_rows(a, 400);
    SOFT(q1(a, "GRANT SELECT ON big2 TO plain", &r) == 0 && !r.nerr);
    imdbc *p1 = login("plain", "pw"), *p2 = NULL;
    CHECK(p1);
    imdbc_stmt all = {"SELECT * FROM big2", 18, NULL, 0}; /* about 3 MB unread: past the role's reply share */
    uint64_t before = started_now(s);
    SOFT(imdbc_query(p1, &all, 1, &e) == 0);
    wait_started(s, before);
    static char pad[400000];
    n = (size_t)snprintf(pad, sizeof pad, "SELECT 5 -- ");
    memset(pad + n, 'x', sizeof pad - n - 1);
    pad[sizeof pad - 1] = 0;
    imdbc_stmt big = {pad, strlen(pad), NULL, 0};
    for (int k = 0; k < 3; k++) SOFT(imdbc_query(p1, &big, 1, &e) == 0);
    imdbs_counts c1;
    for (int w = 0; w < 500; w++) {
        c1 = counts_of(s);
        if (c1.role_queue_waits > c0.role_queue_waits) break;
        usleep(10000);
    }
    SOFT(c1.role_queue_waits > c0.role_queue_waits);
    p2 = login("plain", "pw"); /* (logged in once the queue is held: its idle clock from here) */
    CHECK(p2);
    c0 = counts_of(s);
    imdbc_stmt eight = {"SELECT 8", 8, NULL, 0};
    SOFT(imdbc_query(p2, &eight, 1, &e) == 0); /* held unread: the role's queue is past its share */
    usleep(2500000); /* past the idle bound twice */
    SOFT(counts_of(s).idle_closed == c0.idle_closed);
    SOFT(read_reply(p1, &r) == 0 && !r.nerr && r.nrows == 160000);
    for (int k = 0; k < 3; k++) SOFT(read_reply(p1, &r) == 0 && !r.nerr);
    SOFT(read_reply(p2, &r) == 0 && !r.nerr && strstr(r.text, "8"));
    if (r.nerr) fprintf(stderr, "    held reads: %s\n", r.err);
    imdbc_close(p1);
    imdbc_close(p2);
    imdbc_close(a);
    unserve(db, s);
}

/* 2b-3: --disk-headroom, each cell of its table (the free bytes by the tests' hook alone: no file system filled). The
 * data disk below it: a role's INSERT, INSERT ... SELECT, UPDATE, DELETE and COPY FROM refused at their start by name
 * (COPY's data never asked), its SELECT and EXPLAIN run, a COMMIT of writes made above it commits, a superuser's writes
 * run, a superuser's statements that give space back run (the README's runbook), a superuser demoted refused at once (the
 * catalog decides, not the server's copy). The spool disk below it, everyone's (a superuser's too): a COPY FROM upload
 * refused and never run, a read past its connection's room refused by name, a write's RETURNING past its room kept in
 * memory with its commit, a superuser's COPY TO streaming through a ring held at its floor. Each crossing an event, either
 * way; the counts and the gauges */
static void t_server_disk_headroom(void)
{
    char ev[300];
    snprintf(ev, sizeof ev, "%s/events", test_tmpdir());
    g_events = ev;
    imdbs_opts o;
    memset(&o, 0, sizeof o);
    o.conn_cap = 256u << 10;
    o.disk_headroom = 1ull << 30;
    imdbsp_test_free(IMDBSP_FREE_DATA, 2ll << 30);
    imdbsp_test_free(IMDBSP_FREE_SPOOL, 2ll << 30);
    imdbs *s = NULL;
    imdb_db *db = serve(&s, &o);
    CHECK(db);
    imdbc *a = login("admin", "pw-admin");
    CHECK(a);
    reply r = {0};
    imdb_err e = {0};
    load_rows(a, 400);
    static const char *const setup[] = {"CREATE TABLE w (id INT64 PRIMARY KEY, v INT64)", "INSERT INTO w VALUES (1, 1), (2, 2)",
                                        "GRANT SELECT, INSERT, UPDATE, DELETE ON w TO plain", "GRANT SELECT ON big2 TO plain",
                                        "CREATE ROLE boss LOGIN SUPERUSER PASSWORD 'pw-b'",
                                        "CREATE TABLE zz (id INT64 PRIMARY KEY)", "INSERT INTO zz VALUES (1)"};
    for (size_t i = 0; i < sizeof setup / sizeof *setup; i++) SOFT(q1(a, setup[i], &r) == 0 && !r.nerr);
    imdbc *p = login("plain", "pw"), *u = login("boss", "pw-b");
    CHECK(p && u);
    SOFT(q1(p, "INSERT INTO w VALUES (3, 3)", &r) == 0 && !r.nerr); /* above it: runs */
    SOFT(q1(p, "BEGIN", &r) == 0 && !r.nerr && q1(p, "INSERT INTO w VALUES (4, 4)", &r) == 0 && !r.nerr);
    int ev0 = ev_count(ev, "\"disk_headroom\"");
    /* the data disk below it */
    imdbsp_test_free(IMDBSP_FREE_DATA, 100ll << 20);
    SOFT(q1(p, "COMMIT", &r) == 0 && !r.nerr); /* admitted above it: a margin, not a quota */
    imdbs_counts c0 = counts_of(s);
    static const char *const refused[] = {"INSERT INTO w VALUES (5, 5)", "INSERT INTO w SELECT id + 10, v FROM w",
                                          "UPDATE w SET v = 9 WHERE id = 1", "DELETE FROM w WHERE id = 2"};
    for (size_t i = 0; i < sizeof refused / sizeof *refused; i++) {
        SOFT(q1(p, refused[i], &r) == 0 && r.nerr == 1 && r.err_code == (uint32_t)-IMDB_ERR_LIMIT &&
             strstr(r.err, "--disk-headroom"));
        if (!strstr(r.err, "--disk-headroom")) fprintf(stderr, "    %s: %s\n", refused[i], r.err);
    }
    static const char d[] = "6,6\n7,7\n";
    SOFT(copy_in(p, "COPY w FROM STDIN", d, sizeof d - 1, 0, &r) == 0 && r.nerr == 1 && strstr(r.err, "--disk-headroom") &&
         !r.copy_in); /* refused before its data is asked for */
    imdbs_counts c1 = counts_of(s);
    SOFT(c1.disk_refused == c0.disk_refused + 5 && c1.disk_low_data == 1 && c1.disk_free_data == (100ull << 20));
    SOFT(c1.copy_in == c0.copy_in);
    SOFT(q1(p, "SELECT id, v FROM w ORDER BY id", &r) == 0 && !r.nerr && !strcmp(r.text, "1|1\n2|2\n3|3\n4|4\n"));
    if (strcmp(r.text, "1|1\n2|2\n3|3\n4|4\n")) fprintf(stderr, "    w: %s\n", r.text);
    SOFT(q1(p, "EXPLAIN UPDATE w SET v = 9 WHERE id = 1", &r) == 0 && !r.nerr); /* (it writes nothing) */
    if (r.nerr) fprintf(stderr, "    EXPLAIN: %s\n", r.err);
    SOFT(q1(u, "INSERT INTO w VALUES (5, 5)", &r) == 0 && !r.nerr); /* a superuser's runs */
    /* and the statements that give space back, a superuser's (the runbook: README) */
    static const char *const freeing[] = {"ALTER TABLE zz SET RETENTION 1 HOURS", "CHECKPOINT", "COMPACT zz",
                                          "DROP TABLE zz RETENTION 1 HOURS"};
    for (size_t i = 0; i < sizeof freeing / sizeof *freeing; i++) {
        SOFT(q1(u, freeing[i], &r) == 0 && !r.nerr);
        if (r.nerr) fprintf(stderr, "    below the line, %s: %s\n", freeing[i], r.err);
    }
    SOFT(copy_in(u, "COPY w FROM STDIN", d, sizeof d - 1, 0, &r) == 0 && !r.nerr && r.count == 2);
    SOFT(q1(a, "ALTER ROLE boss NOSUPERUSER", &r) == 0 && !r.nerr);
    SOFT(q1(u, "INSERT INTO w VALUES (8, 8)", &r) == 0 && r.nerr == 1 && strstr(r.err, "--disk-headroom")); /* at once */
    SOFT(q1(a, "ALTER ROLE boss SUPERUSER", &r) == 0 && !r.nerr);
    /* the crossing, said once, then the way back */
    for (int w = 0; w < 500 && ev_count(ev, "\"disk_headroom\"") == ev0; w++) usleep(10000);
    SOFT(ev_count(ev, "\"disk_headroom\"") == ev0 + 1 && ev_count(ev, "\"below\":1") >= 1);
    imdbsp_test_free(IMDBSP_FREE_DATA, 2ll << 30);
    for (int w = 0; w < 1000 && ev_count(ev, "\"disk_headroom\"") == ev0 + 1; w++) usleep(10000); /* (5 s after the first) */
    SOFT(ev_count(ev, "\"disk_headroom\"") == ev0 + 2);
    SOFT(q1(p, "INSERT INTO w VALUES (9, 9)", &r) == 0 && !r.nerr && counts_of(s).disk_low_data == 0);
    /* a COPY whose gates change while its data arrives (the disk below the headroom, then a REVOKE): refused by its run,
     * its spool freed, and the next COPY on the connection its own (its data asked for, its rows alone) */
    for (int round = 0; round < 2; round++) {
        imdbc_stmt cp = {"COPY w FROM STDIN", 17, NULL, 0};
        char row[16];
        int rl = snprintf(row, sizeof row, "%d,1\n", 20 + round);
        SOFT(imdbc_query(p, &cp, 1, &e) == 0 && read_reply(p, &r) == 0 && r.copy_in);
        SOFT(imdbc_copy_data(p, row, (size_t)rl, &e) == 0);
        for (int w = 0; w < 1000 && spool_held(s) == 0; w++) usleep(10000);
        SOFT(spool_held(s) > 0);
        if (round == 0) imdbsp_test_free(IMDBSP_FREE_DATA, 100ll << 20);
        else SOFT(q1(a, "REVOKE INSERT ON w FROM plain", &r) == 0 && !r.nerr);
        SOFT(imdbc_copy_done(p, &e) == 0 && read_reply(p, &r) == 0 && r.nerr == 1 &&
             strstr(r.err, round ? "permission denied" : "--disk-headroom"));
        if (r.nerr != 1) fprintf(stderr, "    a COPY's gates changed, round %d: nerr %d %s\n", round, r.nerr, r.err);
        SOFT(spools_empty(s));
        if (round == 0) imdbsp_test_free(IMDBSP_FREE_DATA, 2ll << 30);
        else SOFT(q1(a, "GRANT INSERT ON w TO plain", &r) == 0 && !r.nerr);
        rl = snprintf(row, sizeof row, "%d,1\n", 30 + round);
        SOFT(copy_in(p, "COPY w FROM STDIN", row, (size_t)rl, 0, &r) == 0 && !r.nerr && r.count == 1);
    }
    SOFT(q1(p, "SELECT id FROM w WHERE id IN (20, 21, 30, 31) ORDER BY id", &r) == 0 && !strcmp(r.text, "30\n31\n"));
    if (strcmp(r.text, "30\n31\n")) fprintf(stderr, "    the COPYs' rows: %s\n", r.text);
    /* the spool disk below it */
    imdbsp_test_free(IMDBSP_FREE_SPOOL, 100ll << 20);
    c0 = counts_of(s);
    SOFT(copy_in(p, "COPY w FROM STDIN", d, sizeof d - 1, 0, &r) == 0 && r.nerr == 1 && strstr(r.err, "--disk-headroom"));
    if (!strstr(r.err, "--disk-headroom")) fprintf(stderr, "    a role's upload: %s\n", r.err);
    SOFT(q1(p, "SELECT COUNT(*) FROM w WHERE id IN (6, 7)", &r) == 0 && !strcmp(r.text, "2\n")); /* (the superuser's rows) */
    SOFT(copy_in(u, "COPY w FROM STDIN", "10,10\n", 6, 0, &r) == 0 && r.nerr == 1 && strstr(r.err, "--disk-headroom"));
    if (!strstr(r.err, "--disk-headroom")) fprintf(stderr, "    a superuser's upload: %s\n", r.err); /* (its spool's too) */
    c1 = counts_of(s);
    SOFT(imdbc_query(p, &k_all, 1, &e) == 0); /* a role's read past its room: refused by name */
    SOFT(requests_past(s, c1.requests));
    SOFT(read_reply(p, &r) == 0 && r.nerr == 1 && r.err_code == (uint32_t)-IMDB_ERR_LIMIT && strstr(r.err, "--disk-headroom") &&
         r.nrows < 160000);
    if (!strstr(r.err, "--disk-headroom")) fprintf(stderr, "    a role's read: %s\n", r.err);
    imdbs_counts c2 = counts_of(s);
    SOFT(c2.res_spool_bytes == c1.res_spool_bytes && c2.res_refused == c1.res_refused + 1);
    SOFT(q1(a, "CREATE TABLE w2 (id INT64 PRIMARY KEY, v INT64)", &r) == 0 && !r.nerr);
    SOFT(q1(a, "GRANT SELECT, INSERT ON w2 TO plain", &r) == 0 && !r.nerr);
    imdbc_stmt ins = {"INSERT INTO w2 SELECT id, v FROM big2 RETURNING id, v", 53, NULL, 0};
    c1 = counts_of(s);
    SOFT(imdbc_query(p, &ins, 1, &e) == 0); /* a role's write past its room: its reply in memory, its commit stands */
    SOFT(requests_past(s, c1.requests));
    c2 = counts_of(s);
    SOFT(read_reply(p, &r) == 0 && !r.nerr && r.nrows == 160000 && r.has_write && r.write_commit > 0);
    SOFT(c2.disk_kept == c1.disk_kept + 1 && c2.res_spool_bytes == c1.res_spool_bytes);
    if (c2.disk_kept != c1.disk_kept + 1 || c2.res_spool_bytes != c1.res_spool_bytes)
        fprintf(stderr, "    a write's reply: kept %llu -> %llu, spooled %llu -> %llu\n", (unsigned long long)c1.disk_kept,
                (unsigned long long)c2.disk_kept, (unsigned long long)c1.res_spool_bytes, (unsigned long long)c2.res_spool_bytes);
    c1 = counts_of(s);
    SOFT(imdbc_query(u, &k_all, 1, &e) == 0); /* a superuser's read past its room: refused too */
    SOFT(requests_past(s, c1.requests));
    c2 = counts_of(s);
    SOFT(read_reply(u, &r) == 0 && r.nerr == 1 && strstr(r.err, "--disk-headroom") && c2.res_spilled == c1.res_spilled);
    SOFT(c2.disk_refused == c0.disk_refused + 4 && c2.disk_low_spool == 1);
    /* a superuser's COPY TO streams through a ring held at its floor (a dump leaves a filling disk): unread for a while,
     * its spool no larger than the floor; read, whole */
    imdbs_test_copy_hold(20);
    imdbc_stmt dump = {"COPY big2 TO STDOUT", 19, NULL, 0};
    SOFT(imdbc_query(u, &dump, 1, &e) == 0);
    usleep(1500000);
    uint64_t held = spool_held(s);
    SOFT(held > 0 && held <= (64u << 10));
    if (held > (64u << 10)) fprintf(stderr, "    a superuser's ring below the line: %llu bytes\n", (unsigned long long)held);
    imdbs_test_copy_hold(0);
    SOFT(read_reply(u, &r) == 0 && !r.nerr && r.count == 160000);
    if (r.nerr) fprintf(stderr, "    a superuser's export below the line: %s\n", r.err);
    /* the bytes about to be written count: 32 KiB past the headroom takes a role's upload of 6 bytes, not a read's chunk
     * of 64 KiB */
    imdbsp_test_free(IMDBSP_FREE_SPOOL, (1ll << 30) + (32 << 10));
    SOFT(copy_in(p, "COPY w FROM STDIN", "11,11\n", 6, 0, &r) == 0 && !r.nerr && r.count == 1);
    c1 = counts_of(s);
    SOFT(imdbc_query(p, &k_all, 1, &e) == 0);
    SOFT(requests_past(s, c1.requests));
    SOFT(read_reply(p, &r) == 0 && r.nerr == 1 && strstr(r.err, "--disk-headroom"));
    SOFT(spools_empty(s));
    /* checked at every chunk: a role's COPY TO (a result's) already spilling when the spool disk falls below it stops at
     * the next chunk, by name, after the frames handed over, every credit back */
    imdbsp_test_free(IMDBSP_FREE_SPOOL, 2ll << 30);
    imdbs_test_copy_hold(50);
    c1 = counts_of(s);
    imdbc_stmt cto = {"COPY big2 TO STDOUT", 19, NULL, 0};
    SOFT(imdbc_query(p, &cto, 1, &e) == 0);
    for (int w = 0; w < 2000 && counts_of(s).res_spool_bytes == c1.res_spool_bytes; w++) usleep(10000);
    SOFT(counts_of(s).res_spool_bytes > c1.res_spool_bytes);
    imdbsp_test_free(IMDBSP_FREE_SPOOL, 100ll << 20);
    imdbs_test_copy_hold(0);
    SOFT(requests_past(s, c1.requests));
    SOFT(read_reply(p, &r) == 0 && r.nerr == 1 && strstr(r.err, "COPY TO") && strstr(r.err, "--disk-headroom"));
    if (!strstr(r.err, "--disk-headroom")) fprintf(stderr, "    a role's COPY TO: %s\n", r.err);
    SOFT(spools_empty(s));
    imdbc_close(p);
    imdbc_close(u);
    imdbc_close(a);
    unserve(db, s);
}

/* 2b-3's measure (recorded, never asserted; IMDB_SRV_DISK_MEASURE set, else skipped): the free-space read the headroom
 * adds before each statement (fstatvfs of the test directory and the server's lock, alone, 200,000 times), and pipelined
 * SELECT 1 through the socket in windows of 50 with the headroom off and at imagedb-server's 1 GiB, three interleaved
 * runs each of 20,000 statements */
static void t_server_disk_measure(void)
{
    if (!getenv("IMDB_SRV_DISK_MEASURE")) return;
    int dfd = open(test_tmpdir(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    CHECK(dfd >= 0);
    pthread_mutex_t mu = PTHREAD_MUTEX_INITIALIZER;
    uint64_t sink = 0, t0 = imdb_mono_ns();
    for (int k = 0; k < 200000; k++) {
        uint64_t fr = 0;
        (void)imdbsp_free(dfd, IMDBSP_FREE_DATA, &fr);
        pthread_mutex_lock(&mu);
        sink += fr & 1;
        pthread_mutex_unlock(&mu);
    }
    fprintf(stderr, "    the read alone: %.0f ns a call (%llu)\n", (double)(imdb_mono_ns() - t0) / 200000.0,
            (unsigned long long)(sink & 1));
    close(dfd);
    double us[2][3];
    for (int run = 0; run < 3; run++) {
        for (int mode = 0; mode < 2; mode++) {
            imdbs_opts o;
            memset(&o, 0, sizeof o);
            o.disk_headroom = mode ? 1ull << 30 : 0;
            imdbs *s = NULL;
            imdb_db *db = serve(&s, &o);
            CHECK(db);
            imdbc *a = login("admin", "pw-admin");
            CHECK(a);
            imdbc_stmt one = {"SELECT 1", 8, NULL, 0};
            imdb_err e = {0};
            reply r = {0};
            uint64_t t1 = imdb_mono_ns();
            bool good = true;
            for (int w = 0; w < 400 && good; w++) {
                for (int k = 0; k < 50; k++) good = good && imdbc_query(a, &one, 1, &e) == 0;
                for (int k = 0; k < 50 && good; k++) good = read_reply(a, &r) == 0 && !r.nerr;
            }
            us[mode][run] = (double)(imdb_mono_ns() - t1) / 20000.0 / 1000.0;
            SOFT(good);
            imdbc_close(a);
            unserve(db, s);
        }
    }
    for (int mode = 0; mode < 2; mode++)
        fprintf(stderr, "    headroom %s: %.2f %.2f %.2f us a statement\n", mode ? "1 GiB" : "off", us[mode][0], us[mode][1],
                us[mode][2]);
}

/* 2b-3, the COMMIT margin's premise (a commit admitted above the headroom may still meet a full disk): such a commit
 * fails alone through the server and the handle goes on (log_put_tagged: its sectors put back and synced; only a failed
 * put-back or its sync stops the handle). The log's next write refused once with ENOSPC by the fault hook (no file system
 * filled; installed before the server's threads, as fsio.h asks), synced as a production server: a role's autocommit
 * INSERT and then its COMMIT answer an error, and its next statements, a superuser's and the reads run, the failed
 * commits' rows nowhere */
static _Atomic int g_enospc_fd = -1;
static long enospc_write(imdb_io_call *c, void *ctx)
{
    (void)ctx;
    int fd = atomic_load(&g_enospc_fd);
    if (c->op == IMDB_IO_WRITE && fd >= 0 && c->fd == fd && atomic_compare_exchange_strong(&g_enospc_fd, &fd, -1)) {
        errno = ENOSPC;
        return -1;
    }
    return 0;
}
static const imdb_io_hooks g_enospc_hooks = {.before = enospc_write};

static void t_server_disk_enospc(void)
{
    imdb_io_set_hooks(&g_enospc_hooks);
    imdbs_opts o;
    memset(&o, 0, sizeof o);
    g_sync = 1;
    imdbs *s = NULL;
    imdb_db *db = serve(&s, &o);
    imdbc *a = db ? login("admin", "pw-admin") : NULL;
    SOFT(db && a);
    reply r = {0};
    imdbc *p = NULL;
    if (a) {
        SOFT(q1(a, "CREATE TABLE w (id INT64 PRIMARY KEY, v INT64)", &r) == 0 && !r.nerr);
        SOFT(q1(a, "GRANT SELECT, INSERT ON w TO plain", &r) == 0 && !r.nerr);
        p = login("plain", "pw");
        SOFT(p);
    }
    if (p) {
        (void)counts_of(s); /* (the engine thread's last write of logfd seen through the server's lock) */
        int lfd = db->logfd;
        SOFT(lfd >= 0);
        atomic_store(&g_enospc_fd, lfd);
        SOFT(q1(p, "INSERT INTO w VALUES (1, 1)", &r) == 0 && r.nerr == 1);
        if (r.nerr != 1) fprintf(stderr, "    the commit meeting ENOSPC: nerr %d\n", r.nerr);
        SOFT(atomic_load(&g_enospc_fd) == -1); /* (the hook was reached) */
        SOFT(q1(p, "INSERT INTO w VALUES (2, 2)", &r) == 0 && !r.nerr);
        SOFT(q1(a, "INSERT INTO w VALUES (3, 3)", &r) == 0 && !r.nerr);
        SOFT(q1(p, "BEGIN", &r) == 0 && !r.nerr && q1(p, "INSERT INTO w VALUES (4, 4)", &r) == 0 && !r.nerr);
        atomic_store(&g_enospc_fd, lfd);
        SOFT(q1(p, "COMMIT", &r) == 0 && r.nerr == 1);
        SOFT(atomic_load(&g_enospc_fd) == -1);
        SOFT(q1(p, "INSERT INTO w VALUES (5, 5)", &r) == 0 && !r.nerr);
        SOFT(q1(p, "SELECT id FROM w ORDER BY id", &r) == 0 && !strcmp(r.text, "2\n3\n5\n"));
        if (strcmp(r.text, "2\n3\n5\n")) fprintf(stderr, "    after ENOSPC: %s\n", r.text);
        SOFT(!db->failed);
        imdbc_close(p);
    }
    atomic_store(&g_enospc_fd, -1);
    if (a) imdbc_close(a);
    if (db) unserve(db, s);
    imdb_io_set_hooks(NULL);
}

/* the KILL race (found 11-22 by the Java driver's rerun against 2b-3's binaries): a victim's next frame sent after its
 * KILL_DONE and in its socket before its thread reads (imdbs_test_wake_hold: 300 ms between the wake and the read) is
 * never answered: the victim is told why (by a KILL). A PING and a QUERY, held and not (before the fix, the held PING
 * was answered PONG: a session reported ended still answering) */
static void t_server_kill_wake(void)
{
    imdbs_opts o;
    memset(&o, 0, sizeof o);
    imdbs *s = NULL;
    imdb_db *db = serve(&s, &o);
    CHECK(db);
    imdbc *a = login("admin", "pw-admin");
    CHECK(a);
    reply r = {0};
    imdb_err e = {0};
    for (int k = 0; k < 4; k++) { /* 0 a PING held, 1 a QUERY held, 2 a PING, 3 a QUERY */
        imdbc *v = login("admin", "pw-admin");
        CHECK(v);
        uint64_t vid = 0;
        SOFT(list_of(a, &r));
        for (uint32_t i = 0; i < r.nsess && i < 16; i++)
            if (r.sess[i].id > vid) vid = r.sess[i].id; /* (the newest: the victim logged in last) */
        imdbs_test_wake_hold(k < 2 ? 300 : 0);
        SOFT(kill_of(a, IMDBW_KILL_TERMINATE, vid, IMDBW_KILLED));
        r.err[0] = 0;
        bool answered;
        if (k % 2 == 0) answered = imdbc_ping(v, &e) == 0 && read_reply(v, &r) == 0 && r.pong;
        else answered = q1(v, "SELECT 1", &r) == 0 && !r.nerr;
        imdbs_test_wake_hold(0);
        SOFT(!answered && strstr(r.err, "by a KILL"));
        if (answered || !strstr(r.err, "by a KILL"))
            fprintf(stderr, "    case %d: %s, %s\n", k, answered ? "answered" : "not answered", r.err[0] ? r.err : e.msg);
        imdbc_close(v);
    }
    imdbc_close(a);
    unserve(db, s);
}

/* 2c, logins open: a role that is not a superuser logs in where the database has a memory budget (its bounds are charged
 * against it), and is refused without one on the one path a wrong password takes (an unknown name's, the same verdict),
 * a superuser logging in either way; with a budget, a role's privileges and caps hold it (a write it holds no privilege
 * for refused, its read of what it may read answered) */
static void t_server_logins_budget(void)
{
    for (int budget = 0; budget < 2; budget++) {
        g_nomem = !budget;
        imdbs *s = NULL;
        imdb_db *db = serve(&s, NULL);
        CHECK(db);
        imdbc *a = login("admin", "pw-admin");
        SOFT(a);
        imdbc *p = NULL;
        imdb_err e = {0};
        int rc = imdbc_connect(g_sock, "plain", "pw", 2, &p, &e);
        if (!budget) {
            SOFT(rc == IMDB_ERR_AUTH && !p);
            if (rc != IMDB_ERR_AUTH) fprintf(stderr, "    no budget: plain's login: %d %s\n", rc, e.msg);
        } else {
            SOFT(rc == 0 && p);
            if (rc) fprintf(stderr, "    a budget: plain's login: %d %s\n", rc, e.msg);
            reply r = {0};
            if (a && p) {
                SOFT(q1(a, "CREATE TABLE lb (id INT64 PRIMARY KEY)", &r) == 0 && !r.nerr);
                SOFT(q1(a, "INSERT INTO lb VALUES (1)", &r) == 0 && !r.nerr);
                SOFT(q1(p, "SELECT id FROM lb", &r) == 0 && r.nerr == 1 && strstr(r.err, "permission denied"));
                SOFT(q1(a, "GRANT SELECT ON lb TO plain", &r) == 0 && !r.nerr);
                SOFT(q1(p, "SELECT id FROM lb", &r) == 0 && !r.nerr && !strcmp(r.text, "1\n"));
                SOFT(q1(p, "INSERT INTO lb VALUES (2)", &r) == 0 && r.nerr == 1 && strstr(r.err, "permission denied"));
            }
        }
        imdbc_close(p);
        imdbc_close(a);
        unserve(db, s);
    }
}
/* 2b-2b: state recorded before the reply that announces it, held to it by a pause at every point where a client may
 * already know (imdbs_test_reply_hold, 20 ms: after a verdict's write, around a READY's flush, after a push): a login
 * listed as soon as its verdict is read, a BEGIN's session IN_TXN and a query's request counted as soon as its READY is.
 * (Found by matrix mainm39's slowest modes: a listing missed a login, showed a finished request running, and a wait on
 * the count ended on the request before) */
static void t_server_state_order(void)
{
    imdbs_opts o;
    memset(&o, 0, sizeof o);
    imdbs *s = NULL;
    imdb_db *db = serve(&s, &o);
    CHECK(db);
    imdbc *a = login("admin", "pw-admin");
    CHECK(a);
    imdbs_test_reply_hold(20000);
    for (int k = 0; k < 3; k++) {
        imdbc *w = login("plain", "pw");
        CHECK(w);
        SOFT(counts_of(s).logins == (uint64_t)(k + 2)); /* counted as soon as its verdict is read (the admin's, then these) */
        reply r = {0};
        uint64_t id = 0;
        SOFT(list_of(a, &r));
        for (uint32_t i = 0; i < r.nsess && i < 16; i++)
            if (!strcmp(r.sname[i], "plain")) id = r.sess[i].id;
        SOFT(id != 0); /* listed as soon as its verdict is read */
        SOFT(q1(w, "BEGIN", &r) == 0 && !r.nerr);
        SOFT(counts_of(s).requests == (uint64_t)(3 * k + 1)); /* (absolute: the admin's SESSIONS are no requests) */
        int at = -1;
        SOFT(list_of(a, &r) && (at = sess_at(&r, id)) >= 0 && r.sess[at].state == IMDBW_SS_IN_TXN);
        if (at < 0 || r.sess[at].state != IMDBW_SS_IN_TXN) fprintf(stderr, "    round %d: after BEGIN, state %d\n", k, at >= 0 ? (int)r.sess[at].state : -1);
        SOFT(q1(w, "SELECT 1", &r) == 0 && !strcmp(r.text, "1\n"));
        SOFT(counts_of(s).requests == (uint64_t)(3 * k + 2)); /* counted as soon as its READY is read */
        SOFT(q1(w, "ROLLBACK", &r) == 0 && !r.nerr);
        SOFT(counts_of(s).requests == (uint64_t)(3 * k + 3));
        imdbc_close(w);
    }
    imdbs_test_reply_hold(0);
    imdbc_close(a);
    unserve(db, s);
}

/* 2b-2b: a connection's reply spools at most SPOOL_FILES (4) at once, each a descriptor: six COPY TOs pipelined unread
 * (each about 1.4 MB in its ring; the server's send buffer 4 KiB, so the kernel holds none of them) leave four rings
 * and the fifth waiting, never a fifth file; read, every export whole and in order, every credit back */
static void t_server_spool_files(void)
{
    imdbs_opts o;
    memset(&o, 0, sizeof o);
    o.test_sndbuf = 4096;
    imdbs *s = NULL;
    imdb_db *db = serve(&s, &o);
    CHECK(db);
    imdbc *a = login("admin", "pw-admin");
    CHECK(a);
    load_rows(a, 400);
    imdbc *c = login("admin", "pw-admin");
    CHECK(c);
    reply r = {0};
    imdb_err e = {0};
    static const char cts[] = "COPY big2 TO STDOUT";
    imdbc_stmt ct = {cts, sizeof cts - 1, NULL, 0};
    imdbs_counts c0 = counts_of(s);
    for (int k = 0; k < 6; k++) SOFT(imdbc_query(c, &ct, 1, &e) == 0);
    for (int w = 0; w < 2000 && counts_of(s).requests < c0.requests + 4; w++) usleep(10000);
    usleep(300000); /* the fifth would have run by now */
    imdbs_counts c1 = counts_of(s);
    SOFT(c1.requests == c0.requests + 4 && c1.copy_out == c0.copy_out + 4 && c1.files_peak == 4);
    if (c1.requests != c0.requests + 4 || c1.files_peak != 4)
        fprintf(stderr, "    six COPY TOs unread: %llu ran, %llu spools at most\n", (unsigned long long)(c1.requests - c0.requests),
                (unsigned long long)c1.files_peak);
    SOFT(q1(a, "SELECT COUNT(*) FROM big", &r) == 0 && !strcmp(r.text, "400\n")); /* another connection runs meanwhile */
    for (int k = 0; k < 6; k++) {
        SOFT(read_reply(c, &r) == 0 && !r.nerr && r.ndone == 1 && r.count == 160000 && r.nout > (1u << 20));
        if (r.nerr || r.count != 160000) fprintf(stderr, "    export %d: %u errors, count %llu: %s\n", k, r.nerr, (unsigned long long)r.count, r.err);
    }
    SOFT(counts_of(s).files_peak == 4);
    SOFT(spools_empty(s));
    imdbc_close(c);
    imdbc_close(a);
    unserve(db, s);
}

typedef struct churner {
    atomic_bool stop;
    atomic_uint opened;
} churner;

/* refused logins opened as fast as the slots allow, each held open 1.5 s (past its server's 1 s linger) */
static void *churn_main(void *arg)
{
    churner *ch = arg;
    imdbc *held[8] = {0};
    uint64_t at[8] = {0};
    while (!atomic_load(&ch->stop)) {
        uint64_t now = imdb_mono_ns();
        int slot = -1;
        for (int i = 0; i < 8; i++) {
            if (held[i] && now - at[i] > 1500000000u) imdbc_close(held[i]), held[i] = NULL;
            if (!held[i] && slot < 0) slot = i;
        }
        if (slot < 0) {
            usleep(1000);
            continue;
        }
        imdbc *c = login("plain", "pw");
        if (c) held[slot] = c, at[slot] = now, atomic_fetch_add(&ch->opened, 1);
        else usleep(1000);
    }
    for (int i = 0; i < 8; i++) imdbc_close(held[i]);
    return NULL;
}

/* 2b-2b: a refused login lingers out of the slots: three threads opening a capped role's logins without pause (each
 * answered, refused, then held open past its linger) never keep a superuser out: logins every 50 ms for 3 s each get in
 * at once. (Before, each lingering refusal held its slot, and the churn kept every slot full.) At most 64 linger */
static void t_server_refused_churn(void)
{
    imdbs_opts o;
    memset(&o, 0, sizeof o);
    o.role_conns = 1;
    o.max_conns = 8;
    o.su_reserve = 1;
    imdbs *s = NULL;
    imdb_db *db = serve(&s, &o);
    CHECK(db);
    imdbc *a = login("admin", "pw-admin"), *p1 = login("plain", "pw");
    CHECK(a && p1);
    churner ch;
    atomic_init(&ch.stop, false);
    atomic_init(&ch.opened, 0);
    pthread_t th[3];
    for (int i = 0; i < 3; i++) CHECK(pthread_create(&th[i], NULL, churn_main, &ch) == 0);
    usleep(500000);
    int in = 0, tries = 0;
    uint64_t worst = 0;
    for (uint64_t t0 = imdb_mono_ns(); imdb_mono_ns() - t0 < 3000000000u; tries++) {
        uint64_t t1 = imdb_mono_ns();
        imdbc *k = login("admin", "pw-admin");
        uint64_t ms = (imdb_mono_ns() - t1) / 1000000u;
        if (ms > worst) worst = ms;
        if (k) in++, imdbc_close(k);
        usleep(50000);
    }
    atomic_store(&ch.stop, true);
    for (int i = 0; i < 3; i++) pthread_join(th[i], NULL);
    imdbs_counts n = counts_of(s);
    SOFT(in == tries && atomic_load(&ch.opened) > 20 && n.linger_refused > 20 && n.lingering <= 64);
    if (in != tries || n.linger_refused <= 20)
        fprintf(stderr, "    superuser logins %d of %d (slowest %llu ms); refused logins opened %u, lingered %llu, skipped %llu\n", in,
                tries, (unsigned long long)worst, atomic_load(&ch.opened), (unsigned long long)n.linger_refused,
                (unsigned long long)n.linger_skipped);
    reply r = {0};
    SOFT(q1(p1, "SELECT 1", &r) == 0 && !strcmp(r.text, "1\n")); /* the role's own connection unharmed */
    imdbc_close(p1);
    imdbc_close(a);
    unserve(db, s);
}

/* 2b-2b: a role's COPY TO through a result's path, its output slowed (imdbs_test_copy_hold: 20 ms a write, the export
 * about half a second), ended part way: its client gone (the engine answers another at once, nothing held); its CANCEL
 * and a superuser's KILL (cancel) (ERROR 15 after a prefix, no DONE, the session going on); the stop (within 5 s, every
 * spool freed). Every credit back after each */
static void t_server_copy_role_paths(void)
{
    imdbs_opts o;
    memset(&o, 0, sizeof o);
    o.conn_cap = 128u << 10;
    o.test_sndbuf = 4096;
    imdbs *s = NULL;
    imdb_db *db = serve(&s, &o);
    CHECK(db);
    imdbc *a = login("admin", "pw-admin");
    CHECK(a);
    load_rows(a, 400);
    reply r = {0};
    imdb_err e = {0};
    SOFT(q1(a, "GRANT SELECT ON big2 TO plain", &r) == 0 && !r.nerr);
    static const char cts[] = "COPY big2 TO STDOUT";
    imdbc_stmt ct = {cts, sizeof cts - 1, NULL, 0};
    imdbs_test_copy_hold(50); /* (the export about a second) */
    /* its client gone: its statement ends at its next write (one hold), never running the export out */
    imdbc *p = login("plain", "pw");
    CHECK(p);
    imdbs_counts c0 = counts_of(s);
    uint64_t before = started_now(s);
    SOFT(imdbc_query(p, &ct, 1, &e) == 0);
    wait_started(s, before);
    usleep(150000);
    imdbc_close(p);
    uint64_t t0 = imdb_mono_ns();
    SOFT(requests_past(s, c0.requests));
    uint64_t end_ms = (imdb_mono_ns() - t0) / 1000000u;
    SOFT(end_ms < 500);
    if (end_ms >= 500) fprintf(stderr, "    a gone reader's export ended %llu ms after its close\n", (unsigned long long)end_ms);
    SOFT(q1(a, "SELECT COUNT(*) FROM big", &r) == 0 && !strcmp(r.text, "400\n"));
    imdbs_test_copy_hold(20);
    SOFT(counts_of(s).copy_out_res == c0.copy_out_res + 1 && counts_of(s).copy_out == c0.copy_out);
    SOFT(spools_empty(s));
    /* its CANCEL, then a superuser's KILL */
    p = login("plain", "pw");
    CHECK(p);
    uint64_t sid = 0;
    SOFT(list_of(a, &r));
    for (uint32_t i = 0; i < r.nsess && i < 16; i++)
        if (!strcmp(r.sname[i], "plain")) sid = r.sess[i].id;
    SOFT(sid != 0);
    for (int k = 0; k < 2; k++) {
        uint64_t sp0 = counts_of(s).res_spilled;
        before = started_now(s);
        SOFT(imdbc_query(p, &ct, 1, &e) == 0);
        wait_started(s, before);
        usleep(k ? 300000 : 150000); /* the KILL's: its reader not reading, so its frames spill first */
        if (k) {
            SOFT(counts_of(s).res_spilled == sp0 + 1); /* spilled, then cancelled: its ERROR after the spool, which ends */
            SOFT(kill_of(a, 1, sid, 0));
        } else {
            imdbc_cancel(p);
        }
        SOFT(read_reply(p, &r) == 0 && r.nerr == 1 && r.err_code == (uint32_t)-IMDB_ERR_CANCELLED && !r.ndone && r.nout > 0);
        if (r.err_code != (uint32_t)-IMDB_ERR_CANCELLED) fprintf(stderr, "    %s part way: %u errors, code %u: %s\n", k ? "KILL" : "CANCEL", r.nerr, r.err_code, r.err);
        SOFT(spools_empty(s)); /* before the next statement: the spool ended with its ERROR (never left to the next result's end) */
        SOFT(q1(p, "SELECT COUNT(*) FROM big2", &r) == 0 && !strcmp(r.text, "160000\n")); /* the session goes on */
    }
    /* the stop */
    before = started_now(s);
    SOFT(imdbc_query(p, &ct, 1, &e) == 0);
    wait_started(s, before);
    usleep(100000);
    imdbc_close(a);
    t0 = imdb_mono_ns();
    SOFT(imdbs_stop(s, &e) == 0);
    SOFT((imdb_mono_ns() - t0) / 1000000u < 5000);
    SOFT(imdbsp_live() == 0);
    imdbs_test_copy_hold(0);
    imdbc_close(p);
    imdb_close(db);
    SOFT(imdbw_live_blocks() == g_blocks);
}

/* 2b-2a (the advisor's 16:19 review): every spool call failed in turn (imdbsp_fail_at: an open, a write, a read). A read
 * ends whole, or in one ERROR with no DONE (the frames before it whole), or with its connection closed and no DONE (its
 * spool unreadable: never a stream cut short and then a DONE); a write's RETURNING arrives whole with its commit, or (a
 * read of its spool failing) its connection closes, never an ERROR for what committed; the open and the first write
 * failing, a write's reply falls back to memory, whole. Every credit back after each */
static void t_server_res_spool_faults(void)
{
    imdbs_opts o;
    memset(&o, 0, sizeof o);
    o.conn_cap = 256u << 10;
    imdbs *s = NULL;
    imdb_db *db = serve(&s, &o);
    CHECK(db);
    imdbc *a = login("admin", "pw-admin");
    CHECK(a);
    load_rows(a, 400);
    reply r = {0};
    imdb_err e = {0};
    for (int k = 1; k <= 8; k++) {
        for (int wr = 0; wr < 2; wr++) {
            char q[160];
            if (wr) {
                snprintf(q, sizeof q, "CREATE TABLE w%d_%d (id INT64 PRIMARY KEY, v INT64)", k, wr);
                SOFT(q1(a, q, &r) == 0 && !r.nerr);
                snprintf(q, sizeof q, "INSERT INTO w%d_%d SELECT id, v FROM big2 RETURNING id, v", k, wr);
            } else {
                snprintf(q, sizeof q, "SELECT * FROM big2");
            }
            imdbc *c = login("admin", "pw-admin");
            SOFT(c != NULL);
            if (!c) continue;
            imdbc_stmt st = {q, strlen(q), NULL, 0};
            imdbs_counts c0 = counts_of(s);
            imdbsp_fail_at(k);
            SOFT(imdbc_query(c, &st, 1, &e) == 0);
            SOFT(requests_past(s, c0.requests));
            reply x = {0};
            int rc = read_reply(c, &x);
            imdbsp_fail_at(0);
            bool whole = !rc && x.ndone == 1 && x.nrows == 160000 && !x.nerr;
            bool one_error = !rc && x.nerr == 1 && x.ndone == 0;
            bool closed = rc && x.ndone == 0 && !x.nerr;
            bool ok = wr ? (whole || (k > 2 && closed)) : (whole || one_error || closed);
            SOFT(ok);
            if (!ok) fprintf(stderr, "    fail at %d, %s: rc %d, %u rows, %u done, %u errors: %s\n", k, wr ? "write" : "read", rc,
                             x.nrows, x.ndone, x.nerr, x.err);
            if (wr) {
                snprintf(q, sizeof q, "SELECT COUNT(*) FROM w%d_%d", k, wr);
                SOFT(q1(a, q, &r) == 0 && !strcmp(r.text, "160000\n")); /* the write committed whatever its reply met */
            }
            imdbc_close(c);
            SOFT(spools_empty(s));
        }
    }
    imdbc_close(a);
    unserve(db, s);
}

/* a batch's earlier statements kept when a later one is refused mid-result: one request of SELECT 1 then a result past
 * the room and the spools, sent while an earlier reply is unread in the server (a small socket buffer: the first
 * statement's frames are then still the engine's when the second is refused): the reply is statement 0's DONE, then
 * the ERROR at index 1 */
static void t_server_res_batch_refused(void)
{
    imdbs_opts o;
    memset(&o, 0, sizeof o);
    o.test_sndbuf = 4096; /* the kernel holds a few KiB of a reply: the rest of the first stays the server's, unsent */
    o.conn_cap = 64u << 10;
    o.copy_spool = 64u << 10;
    imdbs *s = NULL;
    imdb_db *db = serve(&s, &o);
    CHECK(db);
    imdbc *a = login("admin", "pw-admin");
    CHECK(a);
    load_rows(a, 400);
    reply r = {0};
    imdb_err e = {0};
    /* about 40 KB: past the few KiB the kernel holds, under the connection's 64 KiB (the next request starts), and the next
     * statement's first chunk beside it past the room: it spills, finds the spools full and is refused at that chunk */
    imdbc_stmt first = {"SELECT * FROM big2 LIMIT 2000", 29, NULL, 0};
    imdbc_stmt two[2] = {{"SELECT 1", 8, NULL, 0}, {"SELECT * FROM big2", 18, NULL, 0}};
    imdbs_counts c0 = counts_of(s);
    SOFT(imdbc_query(a, &first, 1, &e) == 0 && imdbc_query(a, two, 2, &e) == 0);
    for (int w = 0; w < 2000 && counts_of(s).requests < c0.requests + 2; w++) usleep(10000);
    SOFT(read_reply(a, &r) == 0 && r.nrows == 2000 && r.ndone == 1);
    SOFT(read_reply(a, &r) == 0 && r.ndone == 1 && !strncmp(r.text, "1\n", 2) && r.nerr == 1 && r.err_index == 1 &&
         r.err_code == (uint32_t)-IMDB_ERR_LIMIT);
    if (r.ndone != 1 || r.err_index != 1) fprintf(stderr, "    the batch: %u done, %u errors at %u: %s\n", r.ndone, r.nerr, r.err_index, r.err);
    SOFT(spools_empty(s));
    imdbc_close(a);
    unserve(db, s);
}

/* 2b-2a (the advisor's 17:19 review): the two other bounds of mem_room, each alone binding. The server's budget (1 MiB)
 * with a connection's room of 64 MiB: a 3 MB result spills and the replies in memory stay within the budget and a chunk
 * before its client reads. A role's reply share (1 MiB) with the room and the budget large: a role's result spills */
static void t_server_res_mem_bounds(void)
{
    for (int k = 0; k < 2; k++) {
        imdbs_opts o;
        memset(&o, 0, sizeof o);
        o.conn_cap = 64u << 20;
        o.reply_budget = k ? (512u << 20) : (1u << 20);
        o.role_reply_bytes = k ? (1u << 20) : 0;
        imdbs *s = NULL;
        imdb_db *db = serve(&s, &o);
        CHECK(db);
        imdbc *a = login("admin", "pw-admin");
        CHECK(a);
        load_rows(a, 400);
        reply r = {0};
        SOFT(q1(a, "GRANT SELECT ON big2 TO plain", &r) == 0 && !r.nerr);
        imdbc *c = k ? login("plain", "pw") : login("admin", "pw-admin");
        CHECK(c);
        imdb_err e = {0};
        imdbs_counts c0 = counts_of(s);
        SOFT(imdbc_query(c, &k_all, 1, &e) == 0);
        SOFT(requests_past(s, c0.requests));
        imdbs_counts c1 = counts_of(s);
        SOFT(c1.res_spilled == c0.res_spilled + 1);
        SOFT(c1.pend_peak <= (1u << 20) + (192u << 10)); /* the bound and a chunk or two (the floor's): never the 3 MB */
        if (c1.res_spilled != c0.res_spilled + 1 || c1.pend_peak > (1u << 20) + (192u << 10))
            fprintf(stderr, "    %s: spilled %llu, peak %llu\n", k ? "the role's share" : "the budget",
                    (unsigned long long)(c1.res_spilled - c0.res_spilled), (unsigned long long)c1.pend_peak);
        SOFT(read_reply(c, &r) == 0 && r.nrows == 160000 && !r.nerr);
        SOFT(spools_empty(s));
        imdbc_close(c);
        imdbc_close(a);
        unserve(db, s);
    }
}
OVER_TCP(t_server_res_spill)

const test_case server_tests[] = {
    {"server_auth", t_server_auth},
    {"server_statements", t_server_statements},
    {"server_txn", t_server_txn},
    {"server_commit_stamp", t_server_commit_stamp},
    {"server_cancel", t_server_cancel},
    {"server_turns", t_server_turns},
    {"server_role_caps", t_server_role_caps},
    {"server_role_conns", t_server_role_conns},
    {"server_role_shares", t_server_role_shares},
    {"server_role_cap_cancel", t_server_role_cap_cancel},
    {"server_conns_churn", t_server_conns_churn},
    {"server_kill", t_server_kill},
    {"server_oot", t_server_oot},
    {"server_closed_reason", t_server_closed_reason},
    {"server_tcp_closed_reason", t_server_closed_reason_tcp},
    {"server_refused_slots", t_server_refused_slots},
    {"server_res_spill", t_server_res_spill},
    {"server_res_spill_paths", t_server_res_spill_paths},
    {"server_res_role_share", t_server_res_role_share},
    {"server_res_bounds", t_server_res_bounds},
    {"server_res_nospool", t_server_res_nospool},
    {"server_res_measure", t_server_res_measure},
    {"server_res_tail", t_server_res_tail},
    {"server_res_kill_reading", t_server_res_kill_reading},
    {"server_copy_role_share", t_server_copy_role_share},
    {"server_copy_role_paths", t_server_copy_role_paths},
    {"server_copy_role_stream", t_server_copy_role_stream},
    {"server_spool_files", t_server_spool_files},
    {"server_trickle", t_server_trickle},
    {"server_state_order", t_server_state_order},
    {"server_role_defaults", t_server_role_defaults},
    {"server_idle_busy", t_server_idle_busy},
    {"server_disk_headroom", t_server_disk_headroom},
    {"server_disk_measure", t_server_disk_measure},
    {"server_disk_enospc", t_server_disk_enospc},
    {"server_kill_wake", t_server_kill_wake},
    {"server_logins_budget", t_server_logins_budget},
    {"server_refused_churn", t_server_refused_churn},
    {"server_res_spool_faults", t_server_res_spool_faults},
    {"server_res_batch_refused", t_server_res_batch_refused},
    {"server_res_mem_bounds", t_server_res_mem_bounds},
    {"server_tcp_res_spill", t_server_res_spill_tcp},
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
    {"server_copy_in", t_server_copy_in},
    {"server_copy_out", t_server_copy_out},
    {"server_copy_refusals", t_server_copy_refusals},
    {"server_copy_txn", t_server_copy_txn},
    {"server_copy_gone", t_server_copy_gone},
    {"server_copy_idle", t_server_copy_idle},
    {"server_copy_fair", t_server_copy_fair},
    {"server_copy_bound", t_server_copy_bound},
    {"server_copy_slow_output", t_server_copy_slow_output},
    {"server_copy_full", t_server_copy_full},
    {"server_copy_measure", t_server_copy_measure},
    {"server_tick_load", t_server_tick_load},
    {"server_cancel_idle", t_server_cancel_idle},
    {"server_copy_cancel_upload", t_server_copy_cancel_upload},
    {"server_copy_idle_late", t_server_copy_idle_late},
    {"server_priv", t_server_priv},
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
    {"server_tcp_copy_in", t_server_copy_in_tcp},
    {"server_tcp_copy_out", t_server_copy_out_tcp},
    {"server_tcp_copy_refusals", t_server_copy_refusals_tcp},
    {"server_tcp_copy_fair", t_server_copy_fair_tcp},
};
const size_t server_ntests = sizeof server_tests / sizeof *server_tests;
