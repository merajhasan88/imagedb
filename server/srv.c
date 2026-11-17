/* N1b: imagedb's server on a Unix-domain socket (srv.h; docs/n1-design.md §3-§5). Three kinds of thread:
 * - the engine thread owns the imdb_db and every imdb_session: it runs a connection's requests in order, a request's
 *   statements (or an EXECUTE's sets) in order, encodes each result into frames (conv.c) and frees it, and hands the
 *   frames to the connection; at a statement's boundary it may pause a request (its slice, its connection's unsent
 *   replies past their cap) and run another connection's, a session in a transaction running on within its slice;
 * - the acceptor takes connections (at most max_conns, at most preauth_max authenticating) and reaps ended ones;
 * - a thread per connection authenticates it against the logins the engine thread publishes (never engine state),
 *   then reads its frames, queues each request, answers PING itself, passes CANCEL to imdb_session_cancel at once, and
 *   sends the replies. A client that leaves cancels its running statement and its session ends as a queued request.
 * Every block the server allocates is the wire's (imdbw_alloc); the engine's blocks stay on the engine thread. */
#include "srv.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <time.h>
#include <unistd.h>

#include "../src/role.h"
#include "../src/scram.h"
#include "../src/sql.h"
#include "conv.h"
#include "tls.h"

#define RQ_CLOSE 0u               /* a request that is no frame: the connection's end, its session closed */
#define FLUSH_AT (64u << 10)      /* the engine hands a connection its frames once this many are encoded */
#define ROWS_TARGET (64u << 10)   /* a ROWS frame cut at a row's end once past this */
#define QBYTES_MAX (64ull << 20)  /* a connection's queued request bytes before its socket is read again */
#define BUDGET (256ull << 20)     /* every connection's unsent replies: past it, only a connection with none runs */
#define STOP_FLUSH_MS 1000        /* at a stop, a connection's last replies get this long */

/* ---- the logins: an immutable snapshot the engine thread makes, a connection thread reads ---- */
typedef struct login {
    char name[IMDBW_USER];
    imdb_scram v;
} login;
typedef struct logins {
    uint32_t refs, n; /* refs under imdbs.lmu */
    login e[];
} logins;

typedef struct outbuf { /* whole frames, sent in order */
    struct outbuf *next;
    uint8_t *p;
    size_t len, off;
} outbuf;

typedef struct conn conn;
typedef struct rq {
    struct rq *next; /* its connection's, in arrival order */
    conn *c;
    uint8_t type;    /* IMDBW_QUERY, _PREPARE, _EXECUTE, _DEALLOCATE, or RQ_CLOSE */
    uint8_t *body;   /* the frame's body, the request's own: m points into it */
    uint32_t len;
    imdbw_msg m;
    uint32_t at;     /* the next statement or parameter set: a request pauses and resumes at a boundary */
    imdb_rd vals;    /* EXECUTE: its values from set at */
    bool begun;
} rq;

struct conn {
    conn *next; /* imdbs.conns */
    imdbs *s;
    int fd, wake[2];
    pthread_t th;
    bool started;
    /* under imdbs.mu */
    rq *rh, *rt;         /* its requests: the head runs next (or now) */
    uint32_t nq;
    uint64_t qbytes;
    outbuf *oh, *ot;     /* replies not yet sent */
    uint64_t pending;
    bool running;        /* the engine thread runs its head request now (CANCEL reaches imdb_session_cancel) */
    _Atomic bool gone;   /* its client left, broke the protocol or the server stops: no further reply, no request */
    bool close_queued;
    bool closed;         /* its session ended (RQ_CLOSE ran, or the stop): its thread may end */
    bool authing;
    bool preauth;        /* N1c: not yet through authentication (waiting for a slot or authenticating) */
    bool tcp;            /* N1c: came by TCP (its TLS session freed at its end, this stays for the counts) */
    bool done;           /* its thread ended: the acceptor joins and frees it */
    _Atomic bool ses_open; /* ses initialised (the engine thread sets it; a connection asks before a cancel) */
    imdbt *tls;          /* N1c: a TCP connection's TLS session (its thread's alone); NULL on the Unix socket */
    bool rd_wants_write, wr_wants_read; /* TLS: a read that needs the socket writable, a write that needs it readable */
    char addr[48];       /* N1c: a TCP peer's address, for the per-address cap on authenticating connections */
    imdb_session ses;    /* the engine thread's alone (imdb_session_cancel: any thread) */
};

struct imdbs {
    imdb_db *db;
    imdbs_opts o;
    int lfd, stop[2];
    int tfd;             /* N1c: the TCP listener (-1: none) */
    imdbt_ctx *tls;      /* its TLS context */
    uint16_t tcp_port;
    int cert_days;
    char path[sizeof(((struct sockaddr_un *)0)->sun_path)];
    pthread_t engine, acceptor;
    bool engine_started, acceptor_started;
    bool engine_done; /* under mu: the engine thread closed every session and left its loop */
    pthread_mutex_t mu;
    pthread_cond_t cv;   /* the engine waits for work; connections wait for their close; imdbs_wait_failed */
    pthread_cond_t pacv; /* the acceptor waits for a pre-auth slot */
    conn *conns;
    uint32_t nconns, npreauth; /* npreauth: the socket's pre-auth pool */
    uint32_t ntcp, npre_tcp;   /* N1c: TCP's connections and its own pre-auth pool */
    uint64_t pending;    /* every connection's unsent replies */
    conn *rr, *last;     /* round robin's last served; the session run last and since when */
    uint64_t last_since;
    _Atomic bool stopping;
    bool failed;
    imdbs_counts n;
    pthread_mutex_t lmu;
    logins *lg;          /* NULL: no one may log in (the logins could not be made: fail closed) */
    uint64_t role_gen;   /* db->role_gen the logins were made at (the engine thread's) */
};

static uint64_t ms_since(uint64_t t0) { return (imdb_mono_ns() - t0) / 1000000u; }

static void wake(int fd)
{
    char x = 1;
    ssize_t n = write(fd, &x, 1); /* a full pipe already wakes its reader */
    (void)n;
}

static void drain(int fd)
{
    char b[64];
    while (read(fd, b, sizeof b) > 0) {
    }
}

/* ---- logins ---- */
static bool login_ok(const imdb_role *r)
{
    return r && !r->dropped_at && (r->attrs & IMDB_RA_LOGIN) && (r->attrs & IMDB_RA_SUPERUSER) && r->has_ver &&
           r->vent.bytes && !r->vent.erased && !r->vent.doomed && !r->vent.pending && r->name[0];
}

static size_t logins_size(uint32_t n) { return offsetof(logins, e) + (size_t)n * sizeof(login); }

static logins *logins_make(const imdb_db *db)
{
    const imdb_rcat *c = &db->rc;
    uint32_t n = 0;
    for (uint32_t i = 0; i < c->n; i++) n += login_ok(c->roles[i]);
    logins *l = imdbw_alloc(1, logins_size(n));
    if (!l) return NULL;
    l->refs = 1;
    for (uint32_t i = 0; i < c->n; i++) {
        const imdb_role *r = c->roles[i];
        imdb_err e = {0};
        if (!login_ok(r) || strlen(r->name) >= IMDBW_USER) continue;
        login *lo = &l->e[l->n];
        if (imdb_scram_decode(r->vent.bytes, r->vent.len, &lo->v, &e)) continue; /* the catalog's own bytes: never */
        memcpy(lo->name, r->name, strlen(r->name) + 1);
        l->n++;
    }
    return l;
}

static void logins_put(imdbs *s, logins *l)
{
    if (!l) return;
    pthread_mutex_lock(&s->lmu);
    bool last = --l->refs == 0;
    pthread_mutex_unlock(&s->lmu);
    if (!last) return;
    size_t sz = logins_size(l->n);
    imdb_wipe(l, sz); /* the verifiers leave memory with their last reader (an ERASE ROLE's among them) */
    imdbw_free(l);
}

static logins *logins_take(imdbs *s)
{
    pthread_mutex_lock(&s->lmu);
    logins *l = s->lg;
    if (l) l->refs++;
    pthread_mutex_unlock(&s->lmu);
    return l;
}

/* the engine thread: the logins made again when a role changed, before any reply naming the change is sent, so the
 * next connection already sees it (a password, NOLOGIN, a rename, DROP, ERASE ROLE) */
static void logins_publish(imdbs *s, bool force)
{
    if (!force && s->db->role_gen == s->role_gen) return;
    logins *l = logins_make(s->db); /* NULL: none may log in until the next change (fail closed) */
    pthread_mutex_lock(&s->lmu);
    logins *old = s->lg;
    s->lg = l;
    s->role_gen = s->db->role_gen;
    pthread_mutex_unlock(&s->lmu);
    logins_put(s, old);
    pthread_mutex_lock(&s->mu);
    s->n.logins_made++;
    pthread_mutex_unlock(&s->mu);
}

/* ---- the engine thread ---- */
static bool runnable(const imdbs *s, const rq *r)
{
    if (r->type == RQ_CLOSE || r->c->gone) return true;
    uint64_t cap = s->o.conn_cap ? s->o.conn_cap : (32ull << 20);
    return r->c->pending < cap && (s->pending < BUDGET || !r->c->pending);
}

/* the session run last runs on while it is in a transaction and within its slice (no swap of its transaction); else
 * the connections in turn from the one after the last served */
static rq *pick(imdbs *s)
{
    uint64_t slice = (uint64_t)(s->o.slice_ms ? s->o.slice_ms : 10) * 1000000u;
    conn *l = s->last;
    if (l && l->rh && l->ses_open && l->ses.txn.open && imdb_mono_ns() - s->last_since < slice && runnable(s, l->rh))
        return l->rh;
    conn *c = s->rr && s->rr->next ? s->rr->next : s->conns;
    for (uint32_t k = 0; c && k <= s->nconns; k++) {
        if (c->rh && runnable(s, c->rh)) {
            s->rr = c;
            return c->rh;
        }
        c = c->next ? c->next : s->conns;
    }
    return NULL;
}

static void rq_free(rq *r)
{
    if (!r) return;
    imdbw_msg_free(&r->m);
    imdbw_free(r->body);
    imdbw_free(r);
}

/* the engine thread: b's frames handed to c (dropped when its client is gone), b empty again */
static void flush(imdbs *s, conn *c, imdbw_buf *b)
{
    if (!b->len) return;
    outbuf *o = imdbw_alloc(1, sizeof *o);
    pthread_mutex_lock(&s->mu);
    if (c->gone || !o) { /* no memory to queue a reply: the client could wait for it for ever, so the connection ends */
        bool lost = !o && !c->gone;
        c->gone = true;
        pthread_mutex_unlock(&s->mu);
        imdbw_free(o);
        imdbw_buf_reset(b);
        if (lost) wake(c->wake[1]); /* its thread sees gone and ends it */
        return;
    }
    o->p = b->p, o->len = b->len;
    if (c->ot) c->ot->next = o;
    else c->oh = o;
    c->ot = o;
    c->pending += o->len;
    s->pending += o->len;
    pthread_mutex_unlock(&s->mu);
    imdbw_buf_init(b); /* its bytes are the queue's now */
    wake(c->wake[1]);
}

static void put_error(imdbw_buf *b, uint32_t code, uint32_t index, const char *msg)
{
    imdbw_text t = {(const uint8_t *)msg, (uint32_t)imdbw_utf8_fit((const uint8_t *)msg, strlen(msg), IMDBW_MESSAGE_MAX)};
    imdbw_msg m;
    memset(&m, 0, sizeof m);
    m.type = IMDBW_ERROR;
    m.code = code ? code : (uint32_t)-IMDB_ERR_STATE;
    m.index = index < IMDBW_BATCH_MAX ? index : 0;
    m.texts = &t;
    m.ntexts = 1;
    imdbw_msg_put(b, &m, NULL);
}

/* a message onto b, or b back to where it was and an ERROR in its place (an encoder's refusal: the server's own fault,
 * or memory); false then */
static bool put_msg(imdbw_buf *b, const imdbw_msg *m, const imdbw_msg *cols, uint32_t index)
{
    size_t at = b->len;
    imdbw_msg_put(b, m, cols);
    if (!b->err) return true;
    bool nomem = b->nomem;
    b->len = at, b->err = b->nomem = false;
    put_error(b, (uint32_t)-(nomem ? IMDB_ERR_NOMEM : IMDB_ERR_STATE), index,
              nomem ? "out of memory encoding a reply" : "a reply the server could not encode");
    return false;
}

/* a WARNING: the handle's warning a statement raised (a publication left pending, a replica's lag), as the CLI shows it */
static void put_warning(imdbw_buf *b, const char *msg, uint32_t index)
{
    imdbw_text t = {(const uint8_t *)msg, (uint32_t)imdbw_utf8_fit((const uint8_t *)msg, strlen(msg), IMDBW_MESSAGE_MAX)};
    imdbw_msg m;
    memset(&m, 0, sizeof m);
    m.type = IMDBW_WARNING;
    m.texts = &t;
    m.ntexts = 1;
    put_msg(b, &m, NULL, index);
}

static uint8_t ready_state(const conn *c)
{
    if (!c->ses_open || !c->ses.txn.open) return IMDBW_IDLE;
    return c->ses.txn.doomed ? IMDBW_DOOMED : IMDBW_IN_TXN;
}

/* a statement's result: COLUMNS and its ROWS when it returns rows, then DONE; or an ERROR where a frame could not be
 * made (the rows before it are not the statement's answer, §4). false when it ended in an ERROR */
static bool put_result(imdbs *s, conn *c, imdbw_buf *b, const imdb_result *r, uint32_t index, const char *warn)
{
    imdb_err e = {0};
    if (r->has_rows && r->ncols) {
        imdbw_msg cols;
        memset(&cols, 0, sizeof cols);
        if (imdbw_columns_of(r, &cols, &e)) {
            put_error(b, (uint32_t)-e.code, index, e.msg);
            return false;
        }
        bool ok = put_msg(b, &cols, NULL, index);
        for (uint64_t next = 0; ok && next < r->nrows;) {
            if (imdbw_rows_of(r, &cols, &next, ROWS_TARGET, b, &e)) {
                put_error(b, (uint32_t)-e.code, index, e.msg);
                ok = false;
            } else if (b->len >= FLUSH_AT) {
                flush(s, c, b);
                if (c->gone) ok = false; /* its client gone: no further row is encoded, no one would read it */
            }
        }
        imdbw_msg_free(&cols);
        if (!ok) return false;
    }
    imdbw_msg d;
    if (warn) put_warning(b, warn, index);
    imdbw_done_of(r, &d);
    return put_msg(b, &d, NULL, index);
}

static bool put_status(imdbw_buf *b, const char *status, uint32_t index)
{
    imdbw_msg d;
    memset(&d, 0, sizeof d);
    d.type = IMDBW_DONE;
    d.status = (imdbw_text){(const uint8_t *)status, (uint32_t)strlen(status)};
    return put_msg(b, &d, NULL, index);
}

/* after each statement: a changed role's logins published before its reply leaves; a failed handle noted */
static void after_statement(imdbs *s)
{
    logins_publish(s, false);
    if (s->db->failed && !s->failed) {
        pthread_mutex_lock(&s->mu);
        s->failed = true;
        pthread_cond_broadcast(&s->cv);
        pthread_mutex_unlock(&s->mu);
    }
}

static const char k_failed[] = "the database handle failed (a failed sync): the server stops; reopen to recover";

/* a request's next set of values (EXECUTE) or a statement's (QUERY) as the engine's parameters */
static int params_of(imdb_rd *rd, uint32_t n, imdb_value *pv, imdb_err *e)
{
    for (uint32_t k = 0; k < n; k++) {
        imdbw_value w;
        if (!imdbw_span_next(rd, &w)) return imdb_fail(e, IMDB_ERR_STATE, "a request's values ended early");
        if (imdbw_param_of(&w, &pv[k], e)) return e->code;
    }
    return IMDB_OK;
}

/* the engine thread: r's statements from r->at on; true when the request ended (its READY sent), false when it pauses
 * at a statement's boundary and runs on later */
static bool run(imdbs *s, rq *r)
{
    conn *c = r->c;
    if (r->type == RQ_CLOSE) {
        if (c->ses_open) imdb_session_close(&c->ses); /* an open transaction rolled back */
        c->ses_open = false;
        return true;
    }
    if (!c->ses_open) {
        imdb_session_init(&c->ses, s->db);
        c->ses_open = true;
    }
    imdbw_buf b;
    imdbw_buf_init(&b);
    uint64_t t0 = imdb_mono_ns(), slice = (uint64_t)(s->o.slice_ms ? s->o.slice_ms : 10) * 1000000u;
    imdb_value pv[IMDBW_VALUES_MAX];
    imdb_err e = {0};
    const imdbw_msg *m = &r->m;
    uint32_t n = r->type == IMDBW_QUERY ? m->ntexts : r->type == IMDBW_EXECUTE ? m->nsets : 1;
    if (r->type == IMDBW_EXECUTE && !r->begun) imdbw_span_begin(&m->vals, &r->vals);
    r->begun = true;
    while (r->at < n) {
        uint32_t i = r->at;
        imdb_err_clear(&e);
        if (c->gone || s->stopping) break;
        if (s->failed) {
            put_error(&b, (uint32_t)-IMDB_ERR_IO, i, k_failed);
            break;
        }
        pthread_mutex_lock(&s->mu);
        s->n.started++; /* before it runs: a test waiting for it to move knows this statement has begun */
        pthread_mutex_unlock(&s->mu);
        char wb[sizeof s->db->warning]; /* the handle's warning before: one this statement raised goes to its client */
        memcpy(wb, s->db->warning, sizeof wb);
        imdb_result res;
        imdb_result_init(&res);
        int rc = IMDB_OK;
        bool rows = false;
        switch (r->type) {
        case IMDBW_QUERY: {
            const imdbw_text *t = &m->texts[i];
            imdb_rd rd;
            imdbw_span_begin(&m->params[i], &rd);
            rc = params_of(&rd, m->params[i].n, pv, &e);
            if (!rc && imdb_copy_in_stmt((const char *)t->p, t->len))
                rc = imdb_fail(&e, IMDB_ERR_UNSUPPORTED, "COPY ... FROM STDIN through the server: a later step (N1d)");
            if (!rc) rc = imdb_exec_one(&c->ses, (const char *)t->p, t->len, m->params[i].n ? pv : NULL, m->params[i].n, &res, &e);
            rows = true;
            break;
        }
        case IMDBW_EXECUTE:
            rc = params_of(&r->vals, m->nvals, pv, &e);
            if (!rc) rc = imdb_execute(&c->ses, m->name, m->nvals ? pv : NULL, m->nvals, &res, &e);
            rows = true;
            break;
        case IMDBW_PREPARE:
            rc = imdb_prepare(&c->ses, m->name, (const char *)m->texts[0].p, m->texts[0].len, &e);
            if (!rc) put_status(&b, "PREPARE", i);
            break;
        case IMDBW_DEALLOCATE:
            rc = imdb_deallocate(&c->ses, m->name, &e);
            if (!rc) put_status(&b, "DEALLOCATE", i);
            break;
        default:
            rc = imdb_fail(&e, IMDB_ERR_STATE, "a request of no kind");
        }
        pthread_mutex_lock(&s->mu);
        s->n.statements++;
        pthread_mutex_unlock(&s->mu);
        bool ok = !rc;
        const char *warn = s->db->warning[0] && strcmp(wb, s->db->warning) ? s->db->warning : NULL; /* as the CLI shows one */
        if (rc) {
            if (warn) put_warning(&b, warn, i);
            put_error(&b, (uint32_t)-rc, i, e.msg);
        } else if (rows) {
            ok = put_result(s, c, &b, &res, i, warn);
        }
        imdb_result_free(&res);
        after_statement(s);
        r->at = ok ? i + 1 : n; /* an ERROR ends its batch: the statements after it never run (§4) */
        if (r->at >= n) break;
        if (b.len >= FLUSH_AT) flush(s, c, &b); /* (and below, at once when its client has nothing to read) */
        pthread_mutex_lock(&s->mu);
        bool others = false;
        for (conn *o = s->conns; o && !others; o = o->next) others = o != c && o->rh && runnable(s, o->rh);
        bool pause = !runnable(s, r) || (others && imdb_mono_ns() - t0 >= slice);
        bool waiting = !c->pending; /* its client has nothing to read: this statement's replies go now, not at 64 KiB */
        pthread_mutex_unlock(&s->mu);
        if (waiting && !pause) flush(s, c, &b);
        if (pause) {
            flush(s, c, &b);
            imdbw_buf_free(&b);
            pthread_mutex_lock(&s->mu);
            s->n.pauses++;
            pthread_mutex_unlock(&s->mu);
            return false;
        }
    }
    imdbw_msg rd;
    memset(&rd, 0, sizeof rd);
    rd.type = IMDBW_READY;
    rd.state = ready_state(c);
    put_msg(&b, &rd, NULL, 0);
    flush(s, c, &b);
    imdbw_buf_free(&b);
    return true;
}

/* the idle tick: transaction timeouts (an abandoned session's writes freed), due maintenance between transactions, a
 * role change another path made, a failed handle */
static void tick(imdbs *s)
{
    imdb_txn_timeouts(s->db, imdb_mono_ns(), NULL);
    if (!s->db->in_txn && !s->db->active) {
        imdb_err e = {0};
        imdb_maintain(s->db, &e); /* a failure is the handle's (db->failed) or a warning: the next statement says */
    }
    after_statement(s);
}

static void *engine_main(void *arg)
{
    imdbs *s = arg;
    uint32_t tick_ms = s->o.tick_ms ? s->o.tick_ms : 100;
    pthread_mutex_lock(&s->mu);
    uint64_t last_tick = imdb_mono_ns();
    while (!s->stopping) {
        rq *r = pick(s);
        if (!r || ms_since(last_tick) >= tick_ms) {
            if (!r) {
                struct timespec ts;
                clock_gettime(CLOCK_REALTIME, &ts);
                ts.tv_nsec += (long)tick_ms * 1000000L;
                ts.tv_sec += ts.tv_nsec / 1000000000L;
                ts.tv_nsec %= 1000000000L;
                if (pthread_cond_timedwait(&s->cv, &s->mu, &ts) != ETIMEDOUT) continue;
            }
            pthread_mutex_unlock(&s->mu);
            tick(s);
            pthread_mutex_lock(&s->mu);
            last_tick = imdb_mono_ns();
            continue;
        }
        conn *c = r->c;
        c->running = true;
        if (s->last != c) s->last = c, s->last_since = imdb_mono_ns();
        pthread_mutex_unlock(&s->mu);
        bool ended = run(s, r);
        pthread_mutex_lock(&s->mu);
        c->running = false;
        if (ended) {
            c->rh = r->next;
            if (!c->rh) c->rt = NULL;
            c->nq--;
            c->qbytes -= r->len;
            if (r->type == RQ_CLOSE) c->closed = true;
            else s->n.requests++;
            rq_free(r);
            pthread_cond_broadcast(&s->cv); /* a connection waits for its close, or for room in its queue */
            wake(c->wake[1]);
        }
    }
    /* the stop: queued requests dropped, every session closed (an open transaction rolled back) */
    for (conn *c = s->conns; c; c = c->next) {
        for (rq *r = c->rh, *nx; r; r = nx) nx = r->next, rq_free(r);
        c->rh = c->rt = NULL, c->nq = 0, c->qbytes = 0;
        if (c->ses_open) imdb_session_close(&c->ses);
        c->ses_open = false;
        c->closed = true;
        wake(c->wake[1]);
    }
    s->engine_done = true;
    pthread_cond_broadcast(&s->cv);
    pthread_mutex_unlock(&s->mu);
    return NULL;
}

/* ---- a connection's thread ---- */
/* N1c: a connection's bytes over its socket or its TLS session alike: >0 bytes, 0 the peer closed, -1 a failure,
 * IMDBT_WANT_READ or IMDBT_WANT_WRITE for the poll (TLS may want either for either) */
static ssize_t c_read(conn *c, void *p, size_t n)
{
    if (c->tls) return imdbt_read(c->tls, p, n);
    ssize_t k = recv(c->fd, p, n, 0);
    if (k < 0) return errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR ? IMDBT_WANT_READ : -1;
    return k;
}

static ssize_t c_write(conn *c, const void *p, size_t n)
{
    if (c->tls) return imdbt_write(c->tls, p, n);
    ssize_t k = send(c->fd, p, n, MSG_NOSIGNAL);
    if (k < 0) return errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR ? IMDBT_WANT_WRITE : -1;
    return k;
}

/* until the socket can do what a want asks, the deadline, the stop or a wake-up; -1 past the deadline or at the stop */
static int c_wait(conn *c, ssize_t want, uint64_t deadline)
{
    uint64_t now = imdb_mono_ns();
    if (now >= deadline || c->s->stopping) return -1;
    struct pollfd pf[2] = {{c->fd, (short)(want == IMDBT_WANT_WRITE ? POLLOUT : POLLIN), 0}, {c->wake[0], POLLIN, 0}};
    if (poll(pf, 2, (int)((deadline - now) / 1000000u) + 1) < 0 && errno != EINTR) return -1;
    if (pf[1].revents) drain(c->wake[0]);
    return 0;
}

/* reads exactly n bytes before the deadline */
static int read_full(conn *c, uint8_t *p, size_t n, uint64_t deadline)
{
    size_t got = 0;
    while (got < n) {
        ssize_t k = c_read(c, p + got, n - got);
        if (k > 0) got += (size_t)k;
        else if (k == 0 || k == -1 || c_wait(c, k, deadline)) return -1;
    }
    return 0;
}

static int write_full(conn *c, const uint8_t *p, size_t n, uint64_t deadline)
{
    size_t put = 0;
    while (put < n) {
        ssize_t k = c_write(c, p + put, n - put);
        if (k > 0) put += (size_t)k;
        else if (k == 0 || k == -1 || c_wait(c, k, deadline)) return -1;
    }
    return 0;
}

/* N1c: a TCP connection's TLS handshake inside pre-auth's budget (ALPN, TLS 1.3 alone: tls.c) */
static bool handshake(conn *c, uint64_t deadline)
{
    for (;;) {
        imdb_err e = {0};
        int r = imdbt_handshake(c->tls, &e);
        if (r == IMDB_OK) return true;
        if (r != IMDBT_WANT_READ && r != IMDBT_WANT_WRITE) return false;
        if (c_wait(c, r, deadline)) return false;
    }
}

/* §3, §4: the hello's head (a later version answered with ours, then closed), the hello, the challenge (a known role's
 * salt and count, or an unknown name's from the secret: one path, the same work), the proof, the verdict */
static bool authenticate(conn *c)
{
    imdbs *s = c->s;
    uint64_t deadline = imdb_mono_ns() + (uint64_t)(s->o.preauth_ms ? s->o.preauth_ms : 10000) * 1000000u;
    uint8_t hello[IMDBW_HELLO_LEN], chb[IMDBW_CHALLENGE_LEN], proof[IMDBW_PROOF_LEN], am[IMDBW_AUTHMSG_LEN];
    uint8_t sig[IMDBW_KEY], vb[IMDBW_VERDICT_LEN];
    uint32_t version;
    imdb_err e = {0};
    /* N1c: on TCP, TLS first (nothing in the clear), its exporter the AuthMessage's binding (RFC 9266): a proof made
     * over another TLS session, a relay's, fails */
    uint8_t binding[IMDBW_KEY] = {0};
    if (c->tls && (!handshake(c, deadline) || imdbt_binding(c->tls, binding))) return false;
    if (read_full(c, hello, IMDBW_PREAUTH_HEAD, deadline) || imdbw_preauth_head(hello, &version, &e)) return false;
    if (version != 1) { /* a version this server does not speak: its own head, then the close */
        uint8_t mine[IMDBW_PREAUTH_HEAD];
        imdbw_version_put(mine);
        write_full(c, mine, sizeof mine, deadline);
        return false;
    }
    imdbw_hello h;
    if (read_full(c, hello + IMDBW_PREAUTH_HEAD, IMDBW_HELLO_LEN - IMDBW_PREAUTH_HEAD, deadline) ||
        imdbw_hello_get(hello, &h, &e))
        return false;
    logins *l = logins_take(s);
    const login *lo = NULL;
    for (uint32_t i = 0; l && i < l->n && !lo; i++)
        if (!strcmp(l->e[i].name, h.user)) lo = &l->e[i];
    imdbw_challenge ch;
    memset(&ch, 0, sizeof ch);
    ch.version = 1;
    uint8_t stored[IMDBW_KEY], server_key[IMDBW_KEY];
    uint8_t fake[16]; /* made on both paths: an unknown name costs what a known one does (the HMAC included) */
    imdbw_fake_salt(s->o.secret, h.user, fake);
    if (lo) {
        ch.salt_len = lo->v.salt_len;
        memcpy(ch.salt, lo->v.salt, lo->v.salt_len);
        ch.iter = lo->v.iter;
        memcpy(stored, lo->v.stored, IMDBW_KEY);
        memcpy(server_key, lo->v.server, IMDBW_KEY);
    } else { /* no such login (no role, no LOGIN, no verifier, no SUPERUSER until N1e): the same messages, the same work */
        ch.salt_len = 16;
        memcpy(ch.salt, fake, sizeof fake);
        ch.iter = IMDB_SCRAM_ITER_NEW;
        memset(stored, 0x5a, sizeof stored);
        memset(server_key, 0xa5, sizeof server_key);
    }
    logins_put(s, l); /* the keys are copied: the snapshot may go */
    bool ok = !imdb_random(ch.nonce, sizeof ch.nonce, &e) && !imdbw_challenge_put(&ch, chb) &&
              !write_full(c, chb, sizeof chb, deadline) && !read_full(c, proof, sizeof proof, deadline);
    if (ok) {
        imdbw_auth_message(c->tls ? IMDBW_EP_TCP : IMDBW_EP_UNIX, hello, chb, binding, am);
        bool proven = imdbw_scram_server(stored, server_key, am, proof, sig);
        ok = proven && lo;
        imdbw_verdict v;
        memset(&v, 0, sizeof v);
        v.code = ok ? 0 : 1;
        if (ok) memcpy(v.sig, sig, IMDBW_KEY);
        if (imdbw_verdict_put(&v, vb) || write_full(c, vb, sizeof vb, deadline)) ok = false;
    }
    imdb_wipe(stored, sizeof stored);
    imdb_wipe(server_key, sizeof server_key);
    imdb_wipe(sig, sizeof sig);
    pthread_mutex_lock(&s->mu);
    if (ok) s->n.logins++;
    else s->n.refusals++;
    pthread_mutex_unlock(&s->mu);
    return ok;
}

/* under mu: the connection's end queued behind what runs (its queued requests dropped when its client is gone) */
static void queue_close(conn *c, bool drop)
{
    imdbs *s = c->s;
    if (drop) {
        rq *keep = c->running ? c->rh : NULL; /* the running one ends at its next boundary (gone) */
        for (rq *r = keep ? keep->next : c->rh, *nx; r; r = nx) {
            nx = r->next;
            c->nq--;
            c->qbytes -= r->len;
            rq_free(r);
        }
        if (keep) keep->next = NULL;
        c->rh = c->rt = keep;
    }
    if (c->close_queued) return;
    rq *r = imdbw_alloc(1, sizeof *r);
    if (!r) { /* no memory for the close: the session ends at the stop */
        c->gone = true;
        return;
    }
    r->c = c;
    r->type = RQ_CLOSE;
    if (c->rt) c->rt->next = r;
    else c->rh = r;
    c->rt = r;
    c->nq++;
    c->close_queued = true;
    pthread_cond_broadcast(&s->cv);
}

/* the client left or broke the protocol: its running statement cancelled, its queued requests dropped, its session's end
 * queued; no further reply is queued for it */
static void leave(conn *c)
{
    imdbs *s = c->s;
    pthread_mutex_lock(&s->mu);
    c->gone = true;
    if (c->running && c->ses_open) {
        imdb_session_cancel(&c->ses);
        s->n.leave_cancels++;
    }
    queue_close(c, true);
    pthread_mutex_unlock(&s->mu);
}

/* a frame the connection itself answers or refuses, appended behind the replies queued */
static void conn_put(conn *c, const imdbw_msg *m)
{
    imdbs *s = c->s;
    imdbw_buf b;
    imdbw_buf_init(&b);
    imdbw_msg_put(&b, m, NULL);
    outbuf *o = b.err ? NULL : imdbw_alloc(1, sizeof *o);
    if (!o) {
        imdbw_buf_free(&b);
        return;
    }
    o->p = b.p, o->len = b.len;
    pthread_mutex_lock(&s->mu);
    if (c->ot) c->ot->next = o;
    else c->oh = o;
    c->ot = o;
    c->pending += o->len;
    s->pending += o->len;
    pthread_mutex_unlock(&s->mu);
}

/* a frame from the client: a request queued, CANCEL and PING answered here; false when the connection is to end (a
 * protocol error, after its ERROR) */
static bool take_frame(conn *c, uint8_t type, uint8_t *body, uint32_t len, bool *terminate)
{
    imdbs *s = c->s;
    imdb_err e = {0};
    imdbw_msg m;
    memset(&m, 0, sizeof m);
    if (imdbw_msg_get(type, body, len, NULL, &m, &e)) {
        imdbw_free(body);
        char msg[300];
        snprintf(msg, sizeof msg, "a frame refused, the connection closed: %s", e.msg);
        imdbw_text t = {(const uint8_t *)msg, (uint32_t)imdbw_utf8_fit((const uint8_t *)msg, strlen(msg), IMDBW_MESSAGE_MAX)};
        imdbw_msg er = {.type = IMDBW_ERROR, .code = (uint32_t)-e.code, .texts = &t, .ntexts = 1};
        conn_put(c, &er);
        return false;
    }
    switch (type) {
    case IMDBW_QUERY:
    case IMDBW_PREPARE:
    case IMDBW_EXECUTE:
    case IMDBW_DEALLOCATE: {
        rq *r = imdbw_alloc(1, sizeof *r);
        if (!r) {
            imdbw_msg_free(&m);
            imdbw_free(body);
            imdbw_text t = {(const uint8_t *)"out of memory queueing a request", 32};
            imdbw_msg er = {.type = IMDBW_ERROR, .code = (uint32_t)-IMDB_ERR_NOMEM, .texts = &t, .ntexts = 1};
            conn_put(c, &er);
            return false;
        }
        r->c = c, r->type = type, r->body = body, r->len = len, r->m = m;
        pthread_mutex_lock(&s->mu);
        if (c->rt) c->rt->next = r;
        else c->rh = r;
        c->rt = r;
        c->nq++;
        c->qbytes += len;
        pthread_cond_broadcast(&s->cv);
        pthread_mutex_unlock(&s->mu);
        return true;
    }
    case IMDBW_CANCEL: /* the statement running now, never one queued behind it (§4); no reply of its own */
        pthread_mutex_lock(&s->mu);
        if (c->running && c->ses_open) {
            imdb_session_cancel(&c->ses);
            s->n.cancels++;
        }
        pthread_mutex_unlock(&s->mu);
        break;
    case IMDBW_PING: {
        imdbw_msg pong = {.type = IMDBW_PONG};
        conn_put(c, &pong);
        break;
    }
    case IMDBW_TERMINATE:
        *terminate = true;
        break;
    default: { /* COPY_DATA, COPY_DONE, COPY_FAIL with no COPY running: the stream no longer says whose bytes they are */
        imdbw_msg_free(&m);
        imdbw_free(body);
        imdbw_text t = {(const uint8_t *)"COPY data with no COPY running: the connection closed", 53};
        imdbw_msg er = {.type = IMDBW_ERROR, .code = (uint32_t)-IMDB_ERR_STATE, .texts = &t, .ntexts = 1};
        conn_put(c, &er);
        return false;
    }
    }
    imdbw_msg_free(&m);
    imdbw_free(body);
    return true;
}

typedef struct inframe {
    uint8_t head[IMDBW_HEAD];
    uint32_t hgot, blen, bgot;
    uint8_t type;
    uint8_t *body;
} inframe;

/* whatever the socket holds now, as frames; -1 when the client left, 1 when the connection is to end (a protocol error
 * or TERMINATE), 0 to go on */
static int pull(conn *c, inframe *in)
{
    imdbs *s = c->s;
    uint32_t qmax = s->o.queue_max ? s->o.queue_max : 64;
    for (;;) {
        pthread_mutex_lock(&s->mu);
        bool room = c->nq < qmax && c->qbytes < QBYTES_MAX;
        pthread_mutex_unlock(&s->mu);
        if (!room && in->hgot == 0) return 0; /* its queue full: read again once the engine takes one */
        ssize_t k;
        if (in->hgot < IMDBW_HEAD) {
            k = c_read(c, in->head + in->hgot, IMDBW_HEAD - in->hgot);
        } else {
            k = c_read(c, in->body + in->bgot, in->blen - in->bgot);
        }
        if (k == 0) return -1;
        if (k == IMDBT_WANT_READ || k == IMDBT_WANT_WRITE) { /* nothing more now (TLS may want the socket writable) */
            c->rd_wants_write = k == IMDBT_WANT_WRITE;
            return 0;
        }
        if (k < 0) return -1;
        if (in->hgot < IMDBW_HEAD) {
            in->hgot += (uint32_t)k;
            if (in->hgot < IMDBW_HEAD) continue;
            uint32_t len;
            imdb_err e = {0};
            if (imdbw_head_get(in->head, false, &len, &in->type, &e)) {
                char msg[300];
                snprintf(msg, sizeof msg, "a frame refused, the connection closed: %s", e.msg);
                imdbw_text t = {(const uint8_t *)msg, (uint32_t)imdbw_utf8_fit((const uint8_t *)msg, strlen(msg), IMDBW_MESSAGE_MAX)};
                imdbw_msg er = {.type = IMDBW_ERROR, .code = (uint32_t)-e.code, .texts = &t, .ntexts = 1};
                conn_put(c, &er);
                return 1;
            }
            in->blen = len - 1, in->bgot = 0;
            in->body = imdbw_alloc(in->blen ? in->blen : 1, 1);
            if (!in->body) return -1;
        } else {
            in->bgot += (uint32_t)k;
        }
        if (in->bgot < in->blen) continue;
        uint8_t *body = in->body;
        uint32_t blen = in->blen;
        in->body = NULL, in->hgot = in->bgot = in->blen = 0;
        bool terminate = false;
        if (!take_frame(c, in->type, body, blen, &terminate)) return 1;
        if (terminate) return 2;
    }
}

/* sends what is queued: 1 when bytes left, 0 when none could, -1 when the client is gone */
static int push(conn *c)
{
    imdbs *s = c->s;
    int sent = 0;
    for (;;) {
        pthread_mutex_lock(&s->mu);
        outbuf *o = c->oh; /* this thread alone takes from the head; the engine appends at the tail */
        pthread_mutex_unlock(&s->mu);
        if (!o) return sent;
        ssize_t k = c_write(c, o->p + o->off, o->len - o->off); /* TLS: retried with these arguments (partial writes on) */
        if (k == IMDBT_WANT_READ || k == IMDBT_WANT_WRITE) {
            c->wr_wants_read = k == IMDBT_WANT_READ;
            return sent;
        }
        if (k <= 0) return -1;
        sent = 1;
        o->off += (size_t)k;
        pthread_mutex_lock(&s->mu);
        c->pending -= (uint64_t)k;
        s->pending -= (uint64_t)k;
        bool whole = o->off == o->len;
        if (whole) {
            c->oh = o->next;
            if (!c->oh) c->ot = NULL;
        }
        pthread_cond_broadcast(&s->cv); /* the engine may wait for this connection's room */
        pthread_mutex_unlock(&s->mu);
        if (!whole) return sent;
        imdbw_free(o->p);
        imdbw_free(o);
    }
}

/* the replies no one can receive now (the client left, or was dropped), freed */
static void drop_out(conn *c)
{
    imdbs *s = c->s;
    pthread_mutex_lock(&s->mu);
    for (outbuf *o = c->oh, *nx; o; o = nx) {
        nx = o->next;
        s->pending -= o->len - o->off;
        imdbw_free(o->p);
        imdbw_free(o);
    }
    c->oh = c->ot = NULL, c->pending = 0;
    pthread_mutex_unlock(&s->mu);
}

/* N1c: a TCP connection authenticates once its address has room (preauth_per_addr authenticating at once from one
 * address, so one address cannot hold every slot), waiting for it within pre-auth's budget; true when it has a slot */
static bool addr_slot(conn *c)
{
    imdbs *s = c->s;
    uint32_t cap = s->o.preauth_per_addr ? s->o.preauth_per_addr : 8;
    uint64_t until = imdb_mono_ns() + (uint64_t)(s->o.preauth_ms ? s->o.preauth_ms : 10000) * 1000000u;
    pthread_mutex_lock(&s->mu);
    for (;;) {
        uint32_t same = 0;
        for (conn *o = s->conns; o; o = o->next) same += o != c && o->authing && o->tcp && !strcmp(o->addr, c->addr);
        uint32_t maxp = s->o.preauth_max ? s->o.preauth_max : 32;
        bool room = same < cap && s->npre_tcp < maxp; /* its address's share and TCP's pool */
        if (room || s->stopping || imdb_mono_ns() >= until) {
            bool ok = room && !s->stopping;
            if (ok) c->authing = true, s->npre_tcp++;
            pthread_mutex_unlock(&s->mu);
            return ok;
        }
        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        ts.tv_nsec += 50 * 1000000L;
        ts.tv_sec += ts.tv_nsec / 1000000000L;
        ts.tv_nsec %= 1000000000L;
        pthread_cond_timedwait(&s->pacv, &s->mu, &ts);
    }
}

static void *conn_main(void *arg)
{
    conn *c = arg;
    imdbs *s = c->s;
    bool slot = !c->tcp || addr_slot(c); /* the socket's took its slot at the accept */
    if (slot && c->tcp) { /* its TLS session made here, by this thread, once it has a slot: a refused connection costs none */
        imdb_err e = {0};
        if (imdbt_new(s->tls, c->fd, NULL, &c->tls, &e)) c->tls = NULL;
    }
    bool authed = slot && (!c->tcp || c->tls) && authenticate(c);
    pthread_mutex_lock(&s->mu);
    c->preauth = false;
    if (slot) { /* a connection that never took a slot gives none back */
        c->authing = false;
        if (c->tcp) s->npre_tcp--;
        else s->npreauth--;
    }
    pthread_cond_broadcast(&s->pacv);
    pthread_mutex_unlock(&s->mu);
    inframe in;
    memset(&in, 0, sizeof in);
    bool reading = authed, peer = authed; /* peer: the socket can still be read or written (after it, poll it no more) */
    uint64_t stop_at = 0, progress = imdb_mono_ns();
    bool waiting = false; /* replies waited at the last turn too */
    uint64_t send_ns = (uint64_t)(s->o.send_timeout_ms ? s->o.send_timeout_ms : 30000) * 1000000u;
    if (!authed) {
        pthread_mutex_lock(&s->mu);
        c->gone = c->closed = true; /* no session was made */
        pthread_mutex_unlock(&s->mu);
    }
    for (;;) {
        pthread_mutex_lock(&s->mu);
        s->n.wakeups++;
        bool closed = c->closed, out = c->oh != NULL, stopping = s->stopping;
        /* its client gone and its statement still running: the cancel again (one that landed just before the statement
         * began was cleared by its start), every turn until the session's end runs */
        bool recancel = c->gone && c->running && c->ses_open && !closed;
        if (recancel) imdb_session_cancel(&c->ses);
        uint32_t qmax = s->o.queue_max ? s->o.queue_max : 64;
        bool room = c->nq < qmax && c->qbytes < QBYTES_MAX;
        pthread_mutex_unlock(&s->mu);
        uint64_t now = imdb_mono_ns();
        if (stopping && reading) reading = false;
        if (c->gone && reading) { /* the engine could not queue a reply, or the server stops: no further request */
            reading = false;
            leave(c);
        }
        if (!out || !waiting) progress = now; /* the clock starts when replies begin to wait, never in an idle sleep */
        waiting = out;
        if (out && peer && now - progress > send_ns) { /* it takes no byte: dropped, its statement cancelled */
            pthread_mutex_lock(&s->mu);
            s->n.dropped++;
            pthread_mutex_unlock(&s->mu);
            reading = peer = false;
            leave(c);
            drop_out(c);
            out = false;
        }
        if (stopping && !stop_at) stop_at = now + (uint64_t)STOP_FLUSH_MS * 1000000u;
        if (closed && (!out || !peer || (stop_at && now >= stop_at))) break;
        /* each side's events by its want (TLS may want the other); bytes OpenSSL already holds read without a poll, but
         * only while there is room for a request: a reader paused for a full queue never spins on them */
        bool want_in = peer && reading && room, want_out = peer && out;
        short in_ev = c->rd_wants_write ? POLLOUT : POLLIN, out_ev = c->wr_wants_read ? POLLIN : POLLOUT;
        bool pend = want_in && c->tls && imdbt_pending(c->tls) > 0;
        struct pollfd pf[2] = {{peer ? c->fd : -1, (short)((want_in ? in_ev : 0) | (want_out ? out_ev : 0)), 0},
                               {c->wake[0], POLLIN, 0}};
        int wait_ms = stop_at ? 50 : (out && peer) || recancel ? 100 : 1000;
        if (poll(pf, 2, pend ? 0 : wait_ms) < 0 && errno != EINTR) break;
        if (pf[1].revents) drain(c->wake[0]);
        bool can_in = pend || (want_in && (pf[0].revents & in_ev)), can_out = want_out && (pf[0].revents & out_ev);
        if (can_in) {
            c->rd_wants_write = false;
            int r = pull(c, &in);
            if (r < 0) { /* the client left: nothing more can reach it */
                reading = peer = false;
                leave(c);
                drop_out(c);
            } else if (r == 1) { /* a protocol error: its ERROR goes out, then the close */
                reading = false;
                leave(c);
            } else if (r == 2) { /* TERMINATE: the requests before it run, then the session's end */
                reading = false;
                pthread_mutex_lock(&s->mu);
                queue_close(c, false);
                pthread_mutex_unlock(&s->mu);
            }
        } else if (!can_out && (pf[0].revents & (POLLHUP | POLLERR | POLLNVAL))) { /* hung up: neither read nor written again */
            if (reading) leave(c);
            reading = peer = false;
            drop_out(c);
        }
        if (peer && can_out) {
            c->wr_wants_read = false;
            int k = push(c);
            if (k < 0) {
                if (reading) leave(c);
                reading = peer = false;
                drop_out(c);
            } else if (k > 0) {
                progress = imdb_mono_ns();
            }
        }
        if (!reading) { /* a session's end must be queued once nothing more is read (an unauthenticated one has none) */
            pthread_mutex_lock(&s->mu);
            if (!c->closed && !c->close_queued) queue_close(c, false);
            pthread_mutex_unlock(&s->mu);
        }
    }
    imdbw_free(in.body);
    drop_out(c);
    pthread_mutex_lock(&s->mu);
    c->done = true;
    s->n.live--;
    pthread_cond_broadcast(&s->pacv);
    pthread_mutex_unlock(&s->mu);
    imdbt_free(c->tls); /* a best-effort close_notify, then the session; its thread's alone until now */
    c->tls = NULL;
    shutdown(c->fd, SHUT_RDWR);
    return NULL;
}

/* ---- the acceptor ---- */
static void conn_free(conn *c)
{
    for (rq *r = c->rh, *nx; r; r = nx) nx = r->next, rq_free(r); /* a close queued after the engine's stop: every thread joined */
    imdbt_free(c->tls); /* one its thread never took (a limit refused it) */
    if (c->fd >= 0) close(c->fd);
    if (c->wake[0] >= 0) close(c->wake[0]);
    if (c->wake[1] >= 0) close(c->wake[1]);
    imdbw_free(c);
}

/* under mu: ended connections joined and freed (the engine thread never holds one: its requests and session are gone) */
static void reap(imdbs *s)
{
    for (conn **pp = &s->conns; *pp;) {
        conn *c = *pp;
        if (!c->done || c->rh || c->running) {
            pp = &c->next;
            continue;
        }
        *pp = c->next;
        if (s->rr == c) s->rr = NULL;
        if (s->last == c) s->last = NULL;
        s->nconns--;
        s->ntcp -= c->tcp;
        pthread_mutex_unlock(&s->mu);
        pthread_join(c->th, NULL);
        conn_free(c);
        pthread_mutex_lock(&s->mu);
    }
}

/* N1c: a TCP connection's options: no Nagle delay (small pipelined frames), keepalive (a peer gone without a FIN found
 * in about two minutes: its session then ends as any leave's) */
static void tcp_opts(int fd)
{
    int one = 1, idle = 60, intvl = 10, cnt = 6;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
    setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &one, sizeof one);
    setsockopt(fd, IPPROTO_TCP, TCP_KEEPIDLE, &idle, sizeof idle);
    setsockopt(fd, IPPROTO_TCP, TCP_KEEPINTVL, &intvl, sizeof intvl);
    setsockopt(fd, IPPROTO_TCP, TCP_KEEPCNT, &cnt, sizeof cnt);
}

/* one connection from a ready listener: the socket's in its own pre-auth pool; TCP's below max_conns less the socket's
 * reserve, and from one address at most a quarter of max_conns (never under twice preauth_per_addr) before
 * authentication (waiting or authenticating); its TLS session made by its own thread once it has a slot (addr_slot) */
static void take(imdbs *s, bool tcp, pthread_attr_t *at)
{
    uint32_t maxc = s->o.max_conns ? s->o.max_conns : 256;
    uint32_t reserve = s->o.socket_reserve ? s->o.socket_reserve : 16, per_addr = s->o.preauth_per_addr ? s->o.preauth_per_addr : 8;
    if (reserve > maxc / 2) reserve = maxc / 2;
    struct sockaddr_storage sa;
    socklen_t salen = sizeof sa;
    int fd = accept4(tcp ? s->tfd : s->lfd, tcp ? (struct sockaddr *)&sa : NULL, tcp ? &salen : NULL, SOCK_CLOEXEC | SOCK_NONBLOCK);
    if (fd < 0) return;
    conn *c = imdbw_alloc(1, sizeof *c);
    if (!c) {
        close(fd);
        return;
    }
    c->fd = fd, c->s = s, c->wake[0] = c->wake[1] = -1;
    if (tcp) {
        tcp_opts(fd);
        const void *a = sa.ss_family == AF_INET6 ? (const void *)&((struct sockaddr_in6 *)&sa)->sin6_addr
                                                 : (const void *)&((struct sockaddr_in *)&sa)->sin_addr;
        if (!inet_ntop(sa.ss_family, a, c->addr, sizeof c->addr)) snprintf(c->addr, sizeof c->addr, "?");
    }
    pthread_mutex_lock(&s->mu);
    uint32_t same = 0;
    for (conn *o = s->conns; tcp && o; o = o->next) same += o->tcp && o->preauth && !strcmp(o->addr, c->addr);
    /* one address's connections before authentication (waiting for its slot or authenticating): a quarter of max_conns at
     * most (never under twice its cap), so a client's own pool waits and one address cannot hold every TCP connection */
    uint32_t wait_bound = maxc / 4 > 2 * per_addr ? maxc / 4 : 2 * per_addr;
    bool room = tcp ? s->ntcp < maxc - reserve && same < wait_bound : s->nconns < maxc;
    if (!room || s->stopping || pipe2(c->wake, O_CLOEXEC | O_NONBLOCK)) {
        pthread_mutex_unlock(&s->mu);
        conn_free(c); /* one past a limit is closed unread */
        return;
    }
    c->preauth = true, c->tcp = tcp;
    c->authing = !tcp; /* a TCP connection authenticates once its address and its pool have room (addr_slot) */
    c->next = s->conns;
    s->conns = c;
    s->nconns++;
    s->ntcp += tcp;
    s->npreauth += !tcp;
    s->n.accepted++;
    s->n.live++;
    if (pthread_create(&c->th, at, conn_main, c)) {
        s->conns = c->next;
        s->nconns--, s->ntcp -= tcp, s->npreauth -= !tcp, s->n.live--;
        pthread_mutex_unlock(&s->mu);
        conn_free(c);
        return;
    }
    c->started = true;
    pthread_mutex_unlock(&s->mu);
}

static void *accept_main(void *arg)
{
    imdbs *s = arg;
    uint32_t maxp = s->o.preauth_max ? s->o.preauth_max : 32;
    pthread_attr_t at;
    pthread_attr_init(&at);
    pthread_attr_setstacksize(&at, 256u << 10);
    for (;;) {
        /* each listener polled while its own pre-auth pool has room: TCP's full never stops the socket's logins */
        pthread_mutex_lock(&s->mu);
        reap(s);
        bool unix_room = s->npreauth < maxp, tcp_room = s->tfd >= 0 && s->npre_tcp < maxp;
        while (!unix_room && !tcp_room && !s->stopping) {
            pthread_cond_wait(&s->pacv, &s->mu);
            unix_room = s->npreauth < maxp, tcp_room = s->tfd >= 0 && s->npre_tcp < maxp;
        }
        bool stopping = s->stopping;
        pthread_mutex_unlock(&s->mu);
        if (stopping) break;
        struct pollfd pf[3] = {{unix_room ? s->lfd : -1, POLLIN, 0}, {s->stop[0], POLLIN, 0}, {tcp_room ? s->tfd : -1, POLLIN, 0}};
        if (poll(pf, 3, 200) < 0 && errno != EINTR) break;
        if (pf[1].revents) break;
        if (pf[0].revents & POLLIN) take(s, false, &at); /* each ready listener served in a turn */
        if (pf[2].revents & POLLIN) take(s, true, &at);
    }
    pthread_attr_destroy(&at);
    return NULL;
}

/* ---- start and stop ---- */
static int listen_unix(imdbs *s, const char *path, imdb_err *e)
{
    struct sockaddr_un sa;
    memset(&sa, 0, sizeof sa);
    sa.sun_family = AF_UNIX;
    if (!path || !*path || strlen(path) >= sizeof sa.sun_path)
        return imdb_fail(e, IMDB_ERR_INVALID, "the socket's path is empty or longer than %zu bytes", sizeof sa.sun_path - 1);
    memcpy(sa.sun_path, path, strlen(path) + 1);
    struct stat st;
    if (!lstat(path, &st)) { /* a socket left by a server that ended: taken only when no server answers on it */
        if (!S_ISSOCK(st.st_mode)) return imdb_fail(e, IMDB_ERR_STATE, "the socket's path names something else");
        int probe = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
        bool live = probe >= 0 && !connect(probe, (struct sockaddr *)&sa, sizeof sa);
        if (probe >= 0) close(probe);
        if (live) return imdb_fail(e, IMDB_ERR_STATE, "a server already listens on the socket");
        if (unlink(path)) return imdb_fail(e, IMDB_ERR_IO, "the old socket could not be removed");
    }
    s->lfd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
    if (s->lfd < 0) return imdb_fail(e, IMDB_ERR_IO, "socket: %s", strerror(errno));
    if (bind(s->lfd, (struct sockaddr *)&sa, sizeof sa) || chmod(path, 0600) || listen(s->lfd, 128)) {
        int en = errno;
        close(s->lfd);
        s->lfd = -1;
        unlink(path);
        return imdb_fail(e, IMDB_ERR_IO, "the socket: %s", strerror(en));
    }
    memcpy(s->path, path, strlen(path) + 1);
    return IMDB_OK;
}

/* N1c: "ADDR:PORT" ("[ADDR]:PORT" for IPv6) as a TCP listener; the port bound (an ephemeral one's number) */
static int listen_tcp(imdbs *s, const char *spec, imdb_err *e)
{
    char host[128], port[16];
    const char *colon = strrchr(spec, ':');
    if (!colon || colon == spec || strlen(colon + 1) >= sizeof port || !colon[1])
        return imdb_fail(e, IMDB_ERR_INVALID, "--tcp ADDR:PORT ([ADDR]:PORT for IPv6)");
    size_t hl = (size_t)(colon - spec);
    const char *h = spec;
    if (spec[0] == '[' && hl >= 2 && spec[hl - 1] == ']') h = spec + 1, hl -= 2;
    if (hl >= sizeof host) return imdb_fail(e, IMDB_ERR_INVALID, "--tcp: an address too long");
    memcpy(host, h, hl);
    host[hl] = 0;
    memcpy(port, colon + 1, strlen(colon + 1) + 1);
    struct addrinfo hints, *ai = NULL;
    memset(&hints, 0, sizeof hints);
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_NUMERICHOST | AI_NUMERICSERV | AI_PASSIVE; /* an address, never a name to resolve */
    if (getaddrinfo(host, port, &hints, &ai) || !ai) return imdb_fail(e, IMDB_ERR_INVALID, "--tcp: not an address and port");
    int fd = socket(ai->ai_family, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0), one = 1;
    int rc = IMDB_OK;
    if (fd < 0 || setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one) || bind(fd, ai->ai_addr, ai->ai_addrlen) ||
        listen(fd, 128))
        rc = imdb_fail(e, IMDB_ERR_IO, "--tcp %s: %s", spec, strerror(errno));
    freeaddrinfo(ai);
    struct sockaddr_storage sa;
    socklen_t sl = sizeof sa;
    if (!rc && getsockname(fd, (struct sockaddr *)&sa, &sl)) rc = imdb_fail(e, IMDB_ERR_IO, "getsockname: %s", strerror(errno));
    if (rc) {
        if (fd >= 0) close(fd);
        return rc;
    }
    s->tfd = fd;
    s->tcp_port = ntohs(sa.ss_family == AF_INET6 ? ((struct sockaddr_in6 *)&sa)->sin6_port : ((struct sockaddr_in *)&sa)->sin_port);
    return IMDB_OK;
}

int imdbs_start(imdb_db *db, const imdbs_opts *o, imdbs **out, imdb_err *e)
{
    *out = NULL;
    if (db->failed) return imdb_fail(e, IMDB_ERR_STATE, "the database handle has failed: reopen it");
    imdbs *s = imdbw_alloc(1, sizeof *s);
    if (!s) return imdb_fail(e, IMDB_ERR_NOMEM, "out of memory");
    s->db = db, s->o = *o, s->lfd = -1, s->tfd = -1, s->stop[0] = s->stop[1] = -1;
    s->o.socket_path = s->o.tcp = s->o.server_dir = NULL; /* the caller's strings: used here alone */
    pthread_mutex_init(&s->mu, NULL);
    pthread_mutex_init(&s->lmu, NULL);
    pthread_cond_init(&s->cv, NULL);
    pthread_cond_init(&s->pacv, NULL);
    int rc = listen_unix(s, o->socket_path, e);
    if (!rc && o->tcp) { /* N1c: TLS 1.3 on TCP, its key and certificate from the server directory */
        if (!o->server_dir) rc = imdb_fail(e, IMDB_ERR_INVALID, "--tcp needs the server directory's certificate");
        if (!rc) rc = imdbt_server_ctx(o->server_dir, &s->tls, &s->cert_days, e);
        if (!rc) rc = listen_tcp(s, o->tcp, e);
    }
    if (!rc && pipe2(s->stop, O_CLOEXEC | O_NONBLOCK)) rc = imdb_fail(e, IMDB_ERR_IO, "pipe: %s", strerror(errno));
    if (!rc) {
        logins_publish(s, true);
        /* its own stack, never the default: RLIMIT_STACK unlimited (a supervisor's) gives glibc's threads a small one, and
         * the engine's statements (parser, expressions, views, set operations) have only run on the CLI's main thread */
        pthread_attr_t at;
        pthread_attr_init(&at);
        pthread_attr_setstacksize(&at, 64u << 20);
        if (pthread_create(&s->engine, &at, engine_main, s)) rc = imdb_fail(e, IMDB_ERR_IO, "the engine thread did not start");
        else s->engine_started = true;
        pthread_attr_destroy(&at);
    }
    if (!rc) {
        if (pthread_create(&s->acceptor, NULL, accept_main, s)) rc = imdb_fail(e, IMDB_ERR_IO, "the acceptor did not start");
        else s->acceptor_started = true;
    }
    if (rc) {
        imdb_err ignored = {0};
        imdbs_stop(s, &ignored);
        return rc;
    }
    *out = s;
    return IMDB_OK;
}

void imdbs_stop_begin(imdbs *s)
{
    pthread_mutex_lock(&s->mu);
    s->stopping = true;
    pthread_cond_broadcast(&s->cv);
    pthread_cond_broadcast(&s->pacv);
    for (conn *c = s->conns; c; c = c->next) {
        c->gone = c->gone || !c->rh; /* a connection with nothing running gets no further reply */
        if (c->wake[1] >= 0) wake(c->wake[1]);
    }
    pthread_mutex_unlock(&s->mu);
    if (s->stop[1] >= 0) wake(s->stop[1]);
}

bool imdbs_stop_ready(imdbs *s)
{
    pthread_mutex_lock(&s->mu);
    bool r = s->engine_done || !s->engine_started;
    pthread_mutex_unlock(&s->mu);
    return r;
}

void imdbs_cancel_all(imdbs *s)
{
    pthread_mutex_lock(&s->mu);
    for (conn *c = s->conns; c; c = c->next)
        if (c->running && c->ses_open) imdb_session_cancel(&c->ses);
    pthread_mutex_unlock(&s->mu);
}

int imdbs_stop(imdbs *s, imdb_err *e)
{
    if (!s) return IMDB_OK;
    imdbs_stop_begin(s);
    if (s->engine_started) pthread_join(s->engine, NULL);
    if (s->acceptor_started) pthread_join(s->acceptor, NULL);
    pthread_mutex_lock(&s->mu);
    while (s->conns) {
        conn *c = s->conns;
        s->conns = c->next;
        pthread_mutex_unlock(&s->mu);
        if (c->started) pthread_join(c->th, NULL);
        conn_free(c);
        pthread_mutex_lock(&s->mu);
    }
    bool failed = s->failed || s->db->failed;
    pthread_mutex_unlock(&s->mu);
    if (s->lfd >= 0) close(s->lfd);
    if (s->tfd >= 0) close(s->tfd);
    imdbt_ctx_free(s->tls);
    if (s->path[0]) unlink(s->path);
    if (s->stop[0] >= 0) close(s->stop[0]);
    if (s->stop[1] >= 0) close(s->stop[1]);
    logins_put(s, s->lg);
    pthread_mutex_destroy(&s->mu);
    pthread_mutex_destroy(&s->lmu);
    pthread_cond_destroy(&s->cv);
    pthread_cond_destroy(&s->pacv);
    imdbw_free(s);
    return failed ? imdb_fail(e, IMDB_ERR_IO, "%s", k_failed) : IMDB_OK;
}

bool imdbs_failed(imdbs *s)
{
    pthread_mutex_lock(&s->mu);
    bool f = s->failed;
    pthread_mutex_unlock(&s->mu);
    return f;
}

bool imdbs_wait_failed(imdbs *s, uint32_t ms)
{
    pthread_mutex_lock(&s->mu);
    uint64_t until = imdb_mono_ns() + (uint64_t)ms * 1000000u;
    while (!s->failed && !s->stopping && (!ms || imdb_mono_ns() < until)) {
        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        ts.tv_nsec += 100 * 1000000L;
        ts.tv_sec += ts.tv_nsec / 1000000000L;
        ts.tv_nsec %= 1000000000L;
        pthread_cond_timedwait(&s->cv, &s->mu, &ts);
    }
    bool f = s->failed;
    pthread_mutex_unlock(&s->mu);
    return f;
}

void imdbs_counts_get(imdbs *s, imdbs_counts *c)
{
    pthread_mutex_lock(&s->mu);
    *c = s->n;
    c->tcp_authing = c->tcp_waiting = 0;
    for (conn *o = s->conns; o; o = o->next) {
        c->tcp_authing += o->tcp && o->preauth && o->authing;
        c->tcp_waiting += o->tcp && o->preauth && !o->authing;
    }
    pthread_mutex_unlock(&s->mu);
}

uint16_t imdbs_tcp_port(const imdbs *s) { return s->tcp_port; }

int imdbs_cert_days(const imdbs *s) { return s->cert_days; }
