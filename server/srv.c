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
#include <stdlib.h> /* qsort */
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
#include "spool.h"
#include "tls.h"

#define RQ_CLOSE 0u               /* a request that is no frame: the connection's end, its session closed */
#define COPY_FRAME (1u << 20)     /* N1d: a COPY_OUT frame's bytes at most */
#define RING_FLOOR (64u << 10)    /* 2b-2a: a COPY TO ring the spools' bounds keep smaller fails at once (its own size if less) */
#define SPOOL_FILES 4              /* 2b-2b: a connection's reply spools at once (COPY TO rings, results'): its next statement waits */
#define LINGER_REFUSED 64          /* 2b-2b: refused logins lingering at once, out of the slots (their descriptors bounded) */
#define RELEASE_STEP (1u << 20)    /* 2b-2b: a result spool's sent bytes given back once this many have gone */
/* N1d: a COPY ... FROM STDIN's data, as its connection's thread takes it (docs/n1-design.md §8d) */
#define CIN_NONE 0u               /* no COPY's data expected */
#define CIN_OPEN 1u               /* its request paused at the COPY, COPY_IN sent: the data arrives into the spool */
#define CIN_DISCARD 2u            /* the COPY answered (refused part way): its frames dropped to the client's end */
#define FLUSH_AT (64u << 10)      /* the engine hands a connection its frames once this many are encoded */
#define ROWS_TARGET (64u << 10)   /* a ROWS frame cut at a row's end once past this */
#define QBYTES_MAX (64ull << 20)  /* a connection's queued request bytes before its socket is read again */
#define OOT_MAX (64u << 10)        /* N1e stage two: its out-of-turn answers unsent before its socket is read again */
#define BUDGET (256ull << 20)     /* every connection's unsent replies: past it, only a connection with none runs */
#define STOP_FLUSH_MS 1000        /* at a stop, a connection's last replies get this long */
#define TRICKLE_FLOOR 1024        /* 2b-2b: waiting replies a client must take within --send-timeout (or all of them) */

/* ---- the logins: an immutable snapshot the engine thread makes, a connection thread reads ---- */
typedef struct login {
    char name[IMDBW_USER];
    uint32_t id; /* N1e: its role, the session's (imdb_session.role) */
    bool super;  /* N1e stage two: a superuser when the snapshot was made (the role caps and the reserve exempt it) */
    imdb_scram v;
} login;
typedef struct logins {
    uint32_t refs, n; /* refs under imdbs.lmu */
    login e[];
} logins;

/* N1d: a COPY TO's ring (a spool file of at most copy_ring bytes, wrapping): the engine thread writes at w, the
 * connection's thread takes from r (both counted from the statement's start, the file at their remainder by size), done
 * once the statement ended; w - r its bytes held, counted in imdbs.spool_held */
typedef struct cring {
    struct cring *next;
    imdbsp *sp;
    uint64_t size, w, r;
    bool done;
    bool raw;            /* 2b-2a: a result's frames past its connection's room, sent as they are (append-only: no wrap) */
    uint64_t freed;      /* 2b-2b: a raw spool's [0, freed) given back (sent: imdbsp_release), no longer charged */
    bool keep;           /* 2b-2b: its file system gives no blocks back: charged by its extent until freed (2b-2a's rule) */
} cring;

typedef struct outbuf { /* whole frames, sent in order */
    struct outbuf *next;
    uint8_t *p;
    size_t len, off;
    cring *ring;         /* N1d: no frame but a COPY TO's place: its ring's bytes go out here as COPY_OUT frames */
    bool oot;            /* N1e stage two: a frame its connection's thread put (conn_put): counted in conn.oot */
} outbuf;

typedef struct conn conn;
/* N1e stage two: a role's connections' queued request bytes and unsent reply bytes together (under mu), so one role's
 * shares (--role-queue-bytes, --role-reply-bytes) bound what all its connections hold; an entry a role with an
 * authenticated connection (imdbs.tal, max_conns of them), freed with its last */
typedef struct rtally {
    uint32_t role, conns;
    uint64_t qbytes, pending;
    uint64_t spool, spout; /* 2b-2a: its spooled bytes (every spool of its connections) and of them its unsent replies */
} rtally;
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
    _Atomic bool killed; /* N1e stage two: a KILL's cancel holds for this request (its statements start cancelled) */
    bool readied;        /* 2b-2b (under mu): its READY is queued: SESSIONS lists it done (its client may already know) */
} rq;

struct conn {
    conn *next; /* imdbs.conns */
    imdbs *s;
    int fd, wake[2];
    uint32_t role; /* N1e: its login's role, set (under mu) when it authenticates; its session acts as it */
    const char *refuse;  /* N1e stage two: its login was answered but refused (a role's cap, the reserve): an ERROR, then the close */
    rtally *tal;         /* N1e stage two (under mu): its role's tally, from its login to its end (NULL: none yet) */
    bool q_held;         /* N1e stage two (under mu): its reads held by its role's queue share (counted once a hold) */
    bool super;          /* N1e stage two (under mu): its role a superuser (at its login, then at each change of the roles)
                          * exempt from the role's shares */
    uint64_t served;     /* under mu: the engine thread's turn it was last served at (pick: a role's least recent first) */
    uint64_t id;         /* N1e stage two: its session's id, a counter at accept never reused (SESSIONS, KILL) */
    uint64_t login_ns;   /* N1e stage two (under mu): when it authenticated (SESSIONS' age) */
    uint8_t txstate;     /* N1e stage two (under mu): its READY's state at its last request's end (SESSIONS) */
    bool kill_term;      /* N1e stage two (under mu): a KILL ended it: its thread stops reading, says so, then closes */
    bool cin_kill;       /* N1e stage two (under mu): a KILL's cancel of the COPY whose data arrives (its thread refuses it) */
    uint64_t spool, spout; /* 2b-2a (under mu): its bytes in spools (COPY FROM's, its rings, its result spools) and of them
                            * its unsent replies (rings and result spools): runnable() counts spout with pending */
    uint64_t oot;        /* N1e stage two (under mu): its out-of-turn frames' bytes unsent (PONG, SESSIONS_LIST, KILL_DONE,
                          * its ERRORs): past OOT_MAX its socket is not read, so a client that asks and never reads holds
                          * at most that much (a frame each answer: one SESSIONS_LIST may pass it alone) */
    bool oot_held;       /* N1e stage two (under mu): reading paused for them (counted once a pause) */
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
    bool linger_out;     /* 2b-2b: a refused login lingering out of the counts accept reads (nconns, ntcp): reap leaves them */
    bool authing;
    bool preauth;        /* N1c: not yet through authentication (waiting for a slot or authenticating) */
    bool tcp;            /* N1c: came by TCP (its TLS session freed at its end, this stays for the counts) */
    bool done;           /* its thread ended: the acceptor joins and frees it */
    _Atomic bool ses_open; /* ses initialised (the engine thread sets it; a connection asks before a cancel) */
    imdbt *tls;          /* N1c: a TCP connection's TLS session (its thread's alone); NULL on the Unix socket */
    bool rd_wants_write, wr_wants_read; /* TLS: a read that needs the socket writable, a write that needs it readable */
    uint64_t sent_total; /* 2b-2b: bytes its thread handed the socket (its own: the trickle floor's count) */
    char addr[48];       /* N1c: a TCP peer's address, for the per-address cap on authenticating connections */
    imdb_session ses;    /* the engine thread's alone (imdb_session_cancel: any thread) */
    /* N1d: COPY FROM's spool (under imdbs.mu but the file's bytes): its connection's thread owns it while the data
     * arrives (cin OPEN, no end), writing at in_len; at the client's COPY_DONE it is the engine thread's, read from in_rd
     * by the statement; one the engine never took is freed by the connection's thread at its end */
    uint8_t cin;
    bool cin_end;        /* the client's COPY_DONE or COPY_FAIL arrived */
    int32_t cin_err;     /* the COPY refused before it runs (an IMDB_ERR_*: the bound, the spool, a CANCEL, COPY_FAIL) */
    char cin_msg[IMDBW_MESSAGE_MAX + 1];
    imdbsp *sp_in;
    uint64_t in_len, in_rd;
    uint64_t cin_last;   /* the last of its frames (copy_idle_ms) */
    struct cring *rings; /* N1d: its COPY TO rings (under mu): each freed once drained, or by its thread at its end */
    /* the engine thread's alone: */
    bool cin_run;        /* the running statement is a COPY FROM reading its spool */
    /* 2b-3, under mu: the request and statement whose COPY_IN opened the COPY (its resume is that COPY's, whatever a second
     * look at its gates would say: a disk below the headroom, a REVOKE or a DROP TABLE while its data arrived refused by
     * its run, its spool freed) */
    const void *cin_rq;
    uint32_t cin_i;
    bool dkept;          /* 2b-3, the engine thread's: the running statement's write reply kept in memory for the spool disk's
                          * headroom (disk_kept counted at its first chunk so kept: once a statement) */
    struct cring *ring;  /* the running statement's COPY TO ring (made at its first write) */
    struct cring *rsp;   /* 2b-2a: the running statement's result spool (its frames past the room: made at its first spill) */
    int32_t out_err;     /* a COPY TO's write refused (the wait's bound: LIMIT; the spool: IO; a spool directory: STATE) */
    uint64_t out_waited; /* the running statement's waits for room so far (ns): copy_wait_ms bounds their sum */
    uint8_t out_mode;    /* 2b-2b: the running statement's COPY TO: 0 none yet, 1 its ring (a superuser's), 2 a result's path (a role's) */
    size_t out_at;       /* 2b-2b: where its frames not yet handed over begin in run_b (a result's path) */
    char out_msg[sizeof(((imdb_err *)0)->msg)];
    imdbw_buf *run_b;    /* the running request's frames not yet handed over (a COPY TO's ring is queued after them) */
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
    uint32_t nlinger;          /* 2b-2b: refused logins lingering out of the counts, until reaped (LINGER_REFUSED) */
    uint64_t pending;    /* every connection's unsent replies */
    conn *last;          /* the session run last and since when */
    uint32_t rr_role;    /* N1e stage two: the role served last (turns go by role, then by connection) */
    uint64_t serve_clock; /* each turn's number: a connection's served is its last turn's */
    uint64_t next_id;    /* N1e stage two: the last session id given (under mu) */
    uint64_t last_since;
    _Atomic bool stopping;
    bool failed;
    imdbs_counts n;
    pthread_mutex_t lmu;
    logins *lg;          /* NULL: no one may log in (the logins could not be made: fail closed) */
    uint64_t role_gen;   /* db->role_gen the logins were made at (the engine thread's) */
    int spool_dfd;       /* N1d: the spool directory (-1: none, COPY refused by name) */
    int obj_dfd;         /* 2b-3: the database's objects/ (the lake), its free space read with the data directory's and log/'s */
    rtally *tal;         /* N1e stage two: the roles' tallies (max_conns entries; role 0: free) */
    uint32_t ntal;
    uint64_t spool_held; /* under mu: every spool's bytes held now (copy_spool bounds it) */
    bool ev_disk[2];                /* 2b-3: the engine thread's: below the headroom at its last "disk_headroom" event, */
    uint64_t ev_disk_ns[2];         /* and that event's time (at most one in 5 s a directory: a disk at the line flaps) */
    uint64_t disk_ns[2];            /* 2b-3, under mu: when each directory's free bytes were last read (disk_low) */
    uint64_t ev_endpoint, ev_cbref; /* §8f: the engine thread's: the counts its last "channel_binding" event gave, and
                                     * when (an unauthenticated peer moves cb_refused: at most one event in 5 s) */
    uint64_t ev_cb_ns;
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

/* N1e stage two: the caps a session of a role (not a superuser) is held to, from the options and their defaults */
static uint32_t cap_ms(uint32_t v, uint32_t dflt) { return v == IMDBS_NONE ? 0 : v ? v : dflt; }

static void role_caps(const imdbs_opts *o, imdb_caps *c)
{
    memset(c, 0, sizeof *c);
    c->stmt_ms = cap_ms(o->role_stmt_ms, 60000);
    c->txn_ms = cap_ms(o->role_txn_ms, 600000);
    c->idle_ms = cap_ms(o->role_idle_ms, 60000);
    c->row_limit = o->role_row_limit;
    /* a role's sessions together at most 64 MiB of prepared statements (one session's own bound): its share over its
     * connection cap, 2 MiB at the defaults, never under 64 KiB */
    uint32_t conns = o->role_conns == IMDBS_NONE ? (o->max_conns ? o->max_conns : 256) : o->role_conns ? o->role_conns : 32;
    uint64_t each = (64ull << 20) / conns;
    c->prep_bytes = o->role_prep_bytes ? o->role_prep_bytes : each < (64u << 10) ? (64u << 10) : each;
    c->slow_ms = o->role_slow_ms; /* 2b-2b */
}

/* open (2c, logins open): the database has a memory budget (--mem-limit): a role that is not a superuser logs in only
 * where the server's bounds hold it, and they are charged against the budget (a query's share, the replies' room, the
 * statement memory capped at the default); without one, superusers alone (the start says so) */
static bool login_ok(const imdb_role *r, bool open)
{
    return r && !r->dropped_at && (r->attrs & IMDB_RA_LOGIN) && (open || (r->attrs & IMDB_RA_SUPERUSER)) && r->has_ver &&
           r->vent.bytes && !r->vent.erased && !r->vent.doomed && !r->vent.pending && r->name[0];
}

static size_t logins_size(uint32_t n) { return offsetof(logins, e) + (size_t)n * sizeof(login); }

static logins *logins_make(const imdb_db *db, bool open)
{
    const imdb_rcat *c = &db->rc;
    uint32_t n = 0;
    for (uint32_t i = 0; i < c->n; i++) n += login_ok(c->roles[i], open);
    logins *l = imdbw_alloc(1, logins_size(n));
    if (!l) return NULL;
    l->refs = 1;
    for (uint32_t i = 0; i < c->n; i++) {
        const imdb_role *r = c->roles[i];
        imdb_err e = {0};
        if (!login_ok(r, open) || strlen(r->name) >= IMDBW_USER) continue;
        login *lo = &l->e[l->n];
        if (imdb_scram_decode(r->vent.bytes, r->vent.len, &lo->v, &e)) continue; /* the catalog's own bytes: never */
        memcpy(lo->name, r->name, strlen(r->name) + 1);
        lo->id = r->id;
        lo->super = (r->attrs & IMDB_RA_SUPERUSER) != 0;
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
    logins *l = logins_make(s->db, s->db->mem_limit != 0); /* NULL: none may log in until the next change (fail closed) */
    pthread_mutex_lock(&s->lmu);
    logins *old = s->lg;
    s->lg = l;
    s->role_gen = s->db->role_gen;
    pthread_mutex_unlock(&s->lmu);
    logins_put(s, old);
    pthread_mutex_lock(&s->mu);
    s->n.logins_made++;
    for (conn *c = s->conns; c; c = c->next) /* N1e stage two: the shares follow a role's attributes now (this thread
                                               * owns the catalog) */
        if (c->role) c->super = imdb_role_superuser(&s->db->rc, c->role);
    pthread_mutex_unlock(&s->mu);
}

/* ---- a role's tally (N1e stage two; under mu) ---- */
/* c's bytes moved by d (queued requests, or unsent replies with the server's total), its role's tally with them */
static void qb_move(conn *c, int64_t d)
{
    c->qbytes += (uint64_t)d;
    if (!c->tal) return;
    c->tal->qbytes += (uint64_t)d;
    if (d < 0) /* its role's share freed: a connection of it held by the share reads again now, not at its next poll */
        for (conn *o = c->s->conns; o; o = o->next)
            if (o != c && o->tal == c->tal && o->q_held) wake(o->wake[1]);
}

static void pend_move(imdbs *s, conn *c, int64_t d)
{
    c->pending += (uint64_t)d;
    s->pending += (uint64_t)d;
    if (s->pending > s->n.pend_peak) s->n.pend_peak = s->pending; /* 2b-2a */
    if (c->tal) c->tal->pending += (uint64_t)d;
}

/* c joins its role's tally at its login (an entry made for the role's first connection; there are max_conns entries, so
 * one is free for every authenticated connection) */
static void tal_join(imdbs *s, conn *c, uint32_t role)
{
    rtally *free_e = NULL;
    for (uint32_t i = 0; i < s->ntal; i++) {
        if (s->tal[i].conns && s->tal[i].role == role) {
            c->tal = &s->tal[i];
            break;
        }
        if (!s->tal[i].conns && !free_e) free_e = &s->tal[i];
    }
    if (!c->tal && free_e) {
        memset(free_e, 0, sizeof *free_e);
        free_e->role = role;
        c->tal = free_e;
    }
    if (c->tal) c->tal->conns++;
}

/* c leaves its tally at its end, what it still holds taken off */
static void tal_leave(conn *c)
{
    if (!c->tal) return;
    c->tal->qbytes -= c->qbytes;
    c->tal->pending -= c->pending;
    c->tal->spool -= c->spool; /* 2b-2a */
    c->tal->spout -= c->spout;
    if (!--c->tal->conns) c->tal->role = 0;
    c->tal = NULL;
}

static uint64_t share(uint64_t v, uint64_t dflt) { return v == IMDBS_NONE ? UINT64_MAX : v ? v : dflt; }

/* 2b-2a, under mu: dspool bytes of c's spool files charged (or credited): the server's, c's and its role's, each file by
 * its extent until it is freed (a byte sent stays on disk: an append-only result spool keeps its size, a COPY TO ring its
 * extent); dspout of a result spool's bytes not yet sent, which runnable() counts with pending (a COPY TO ring's backlog
 * is bounded by its own ring and wait, and its disk by the spools' bounds) */
static void spool_move(imdbs *s, conn *c, int64_t dspool, int64_t dspout)
{
    s->spool_held += (uint64_t)dspool;
    c->spool += (uint64_t)dspool;
    if (c->tal) c->tal->spool += (uint64_t)dspool;
    c->spout += (uint64_t)dspout;
    if (c->tal) c->tal->spout += (uint64_t)dspout;
}

/* a ring's file extent (what its spool charges): a result spool's every byte written but those given back (2b-2b: sent,
 * released in RELEASE_STEP pieces, so it charges its backlog and a step at most), a COPY TO ring's up to its size */
static uint64_t ring_extent(const struct cring *g) { return g->raw ? g->w - g->freed : g->w < g->size ? g->w : g->size; }

/* 2b-2a, under mu: n more spooled bytes within c's role's share (a superuser's exempt) */
static bool role_spool_room(const imdbs *s, const conn *c, uint64_t n)
{
    if (c->super || !c->tal) return true;
    uint64_t cs = s->o.copy_spool ? s->o.copy_spool : (4ull << 30);
    return c->tal->spool + n <= share(s->o.role_copy_spool, cs / 4);
}

/* 2b-3: kind's directory below --disk-headroom with n more bytes written there (none set: never): its free bytes read now
 * (fstatvfs, a failure 0: fail closed), the gauges set; outside mu (it takes mu). Either thread: the engine's per
 * statement and result chunk, a connection's per COPY frame */
#define DISK_EVERY_NS 2000000u /* 2b-3: a directory's free bytes read at most every 2 ms (about a microsecond each, on the one
                                * engine thread: a statement's check takes the last reading; the headroom is a margin) */
static bool disk_low(imdbs *s, int kind, uint64_t n)
{
    uint64_t h = s->o.disk_headroom, fr = 0;
    if (!h) return false;
    uint64_t now = imdb_mono_ns();
    pthread_mutex_lock(&s->mu);
    bool fresh = s->disk_ns[kind] && now - s->disk_ns[kind] < DISK_EVERY_NS && !imdbsp_free_hooked(kind);
    fr = kind == IMDBSP_FREE_DATA ? s->n.disk_free_data : s->n.disk_free_spool;
    pthread_mutex_unlock(&s->mu);
    if (!fresh) {
        if (kind == IMDBSP_FREE_DATA) { /* every file system the engine writes (log/ or objects/ may be a mount of its own):
                                         * the least */
            const int fds[3] = {s->db->dirfd, s->db->logdirfd, s->obj_dfd};
            fr = UINT64_MAX;
            for (int k = 0; k < 3; k++) {
                uint64_t f = 0;
                if (fds[k] < 0) continue;
                (void)imdbsp_free(fds[k], kind, &f);
                if (f < fr) fr = f;
            }
            if (fr == UINT64_MAX) fr = 0;
        } else {
            (void)imdbsp_free(s->spool_dfd, kind, &fr);
        }
        pthread_mutex_lock(&s->mu);
        if (kind == IMDBSP_FREE_DATA) s->n.disk_low_data = fr < h, s->n.disk_free_data = fr; /* (the gauges: below it now) */
        else s->n.disk_low_spool = fr < h, s->n.disk_free_spool = fr;
        s->disk_ns[kind] = now;
        pthread_mutex_unlock(&s->mu);
    }
    return fr < h || fr - h < n;
}

/* c's socket may be read for another request: its role's queued requests under --role-queue-bytes (a superuser's exempt);
 * a connection held by it counted once a hold (role_queue_waits) */
static bool q_room(imdbs *s, conn *c)
{
    bool ok = c->super || !c->tal || c->tal->qbytes < share(s->o.role_queue_bytes, 64ull << 20);
    if (!ok && !c->q_held) s->n.role_queue_waits++;
    c->q_held = !ok;
    return ok;
}

/* ---- the engine thread ---- */
/* N1e stage two: a role's statement starts only while its role's unsent replies are under --role-reply-bytes, and the
 * server's under its budget unless the role has none unsent (the escape a connection with none had before, now the
 * role's: a role that holds the server past its budget stops itself, never another role); so one statement adds at most
 * one result's encoding past them. A superuser's: the rule before, by its connection */
static uint64_t reply_budget(const imdbs *s) { return s->o.reply_budget ? s->o.reply_budget : BUDGET; }

/* 2b-2b, under mu: the reply spools c holds (COPY TO rings and results', each a file until sent and freed) */
static uint32_t out_files(const conn *c)
{
    uint32_t n = 0;
    for (const cring *g = c->rings; g; g = g->next) n++;
    return n;
}

/* 2b-2b, under mu: a reply spool just added to c: the most one connection held, noted */
static void files_note(imdbs *s, const conn *c)
{
    uint32_t n = out_files(c);
    if (n > s->n.files_peak) s->n.files_peak = n;
}

static bool runnable(const imdbs *s, const rq *r)
{
    if (r->type == RQ_CLOSE || r->c->gone) return true;
    if (r->c->cin == CIN_OPEN && !r->c->cin_end && !r->c->cin_err) return false; /* N1d: its COPY's data still arriving */
    if (out_files(r->c) >= SPOOL_FILES) return false; /* 2b-2b: its spools (a descriptor each) until its client reads one */
    uint64_t cap = s->o.conn_cap ? s->o.conn_cap : (32ull << 20);
    if (r->c->pending + r->c->spout >= cap) return false; /* 2b-2a: its spooled replies too */
    /* the server's unsent replies in memory past its budget (its resource is memory: the disk has its own two bounds,
     * and one result may spool to its role's share): only a connection (a role) with none in memory starts */
    bool under = s->pending < reply_budget(s);
    if (r->c->super || !r->c->tal) return under || !r->c->pending;
    const rtally *t = r->c->tal;
    return t->pending + t->spout < share(s->o.role_reply_bytes, 64ull << 20) && (under || !t->pending);
}

/* the session run last runs on while it is in a transaction and within its slice (no swap of its transaction); else
 * N1e stage two: turns go by role, then by connection: the next role after the last served (by id, cyclically) with a
 * runnable request, then that role's least recently served runnable connection. A role's many connections share one
 * turn among the roles, so a session waits one statement of each other active role, whatever their connection counts
 * (by connection, a role's 32 connections took 32 turns to another's one). Superusers' roles take turns like any other */
static rq *pick(imdbs *s)
{
    uint64_t slice = (uint64_t)(s->o.slice_ms ? s->o.slice_ms : 10) * 1000000u;
    conn *l = s->last;
    if (l && l->rh && l->ses_open && l->ses.txn.open && imdb_mono_ns() - s->last_since < slice && runnable(s, l->rh))
        return l->rh;
    bool any = false;
    uint32_t next = 0, key = 0; /* key: the role's distance after rr_role, cyclically (rr_role itself last) */
    for (conn *c = s->conns; c; c = c->next) {
        if (!c->rh || !runnable(s, c->rh)) continue;
        uint32_t k = c->role - s->rr_role - 1u;
        if (!any || k < key) any = true, key = k, next = c->role;
    }
    if (!any) return NULL;
    conn *best = NULL;
    for (conn *c = s->conns; c; c = c->next)
        if (c->role == next && c->rh && runnable(s, c->rh) && (!best || c->served < best->served)) best = c;
    s->rr_role = next;
    best->served = ++s->serve_clock;
    return best->rh;
}

static void rq_free(rq *r)
{
    if (!r) return;
    imdbw_msg_free(&r->m);
    imdbw_free(r->body);
    imdbw_free(r);
}

/* 2b-2a, the engine thread: c's result spool marked ended (its frames all written): its connection's thread sends what is
 * left of it, then the replies after it */
static void rsp_end(imdbs *s, conn *c)
{
    if (!c->rsp) return;
    pthread_mutex_lock(&s->mu);
    c->rsp->done = true;
    pthread_mutex_unlock(&s->mu);
    c->rsp = NULL;
    wake(c->wake[1]);
}

static int rsp_append(imdbs *s, conn *c, const imdbw_buf *b, imdb_err *e, bool reserved);

/* the engine thread: b's frames handed to c (dropped when its client is gone), b empty again */
static void flush(imdbs *s, conn *c, imdbw_buf *b)
{
    if (!b->len) return;
    if (c->rsp && !rsp_append(s, c, b, NULL, false)) { /* 2b-2a: a statement whose frames spill: every later one of it after them */
        imdbw_buf_reset(b);
        return;
    }
    if (c->rsp) rsp_end(s, c); /* (its spool unwritable: the rest in memory, after it) */
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
    pend_move(s, c, (int64_t)o->len);
    pthread_mutex_unlock(&s->mu);
    imdbw_buf_init(b); /* its bytes are the queue's now */
    wake(c->wake[1]);
}

/* 2b-2a, the engine thread: b's frames appended to c's result spool (made at its first spill, its place in the replies
 * after those handed over before it); 0, or the write's error (a spool that cannot be made or written: the caller
 * decides). The bounds are the caller's (rows_flush); a client gone: the bytes dropped, 0. Its bytes charged before the
 * write (reserved: by rows_flush, under the lock it decided in), credited back when the write fails */
static int rsp_append(imdbs *s, conn *c, const imdbw_buf *b, imdb_err *e, bool reserved)
{
    imdb_err e2 = {0};
    if (!e) e = &e2;
    if (!b->len) return 0;
    if (!reserved) {
        pthread_mutex_lock(&s->mu);
        spool_move(s, c, (int64_t)b->len, (int64_t)b->len);
        pthread_mutex_unlock(&s->mu);
    }
    int rc = 0;
    if (c->gone) goto undo; /* (dropped: nothing written) */
    if (!c->rsp) {
        if (s->spool_dfd < 0) {
            rc = imdb_fail(e, IMDB_ERR_STATE, "no spool directory (--spool-dir, or --server-dir's spool/)");
            goto undo;
        }
        cring *g = imdbw_alloc(1, sizeof *g);
        outbuf *mk = g ? imdbw_alloc(1, sizeof *mk) : NULL;
        if (!mk || imdbsp_open(s->spool_dfd, &g->sp, e)) {
            rc = mk ? e->code : imdb_fail(e, IMDB_ERR_NOMEM, "out of memory for a result's spool");
            imdbw_free(mk);
            imdbw_free(g);
            goto undo;
        }
        g->size = UINT64_MAX, g->raw = true;
        mk->ring = g;
        pthread_mutex_lock(&s->mu);
        g->next = c->rings;
        c->rings = g;
        files_note(s, c);
        if (c->gone) {
            imdbw_free(mk); /* no reply reaches it: the spool is freed with the connection */
        } else {
            if (c->ot) c->ot->next = mk;
            else c->oh = mk;
            c->ot = mk;
        }
        s->n.res_spilled++;
        pthread_mutex_unlock(&s->mu);
        c->rsp = g;
    }
    {
        cring *g = c->rsp;
        if (imdbsp_write(g->sp, g->w, b->p, b->len, e)) { /* [w, ...) the engine's alone */
            rc = e->code;
            goto undo;
        }
        pthread_mutex_lock(&s->mu);
        g->w += b->len;
        s->n.res_spool_bytes += b->len;
        pthread_mutex_unlock(&s->mu);
        wake(c->wake[1]);
        return 0;
    }
undo:
    pthread_mutex_lock(&s->mu);
    spool_move(s, c, -(int64_t)b->len, -(int64_t)b->len);
    pthread_mutex_unlock(&s->mu);
    return rc;
}

/* 2b-2a, under mu: a chunk of n more bytes of c's replies in memory: within its connection's room (conn_cap), its role's
 * (role_reply_bytes, a superuser's exempt) and the server's (reply_budget), with no start escape; or the floor, a chunk
 * while its connection holds none, so a small reply never goes to disk when the server's budget is full */
static bool mem_room(const imdbs *s, const conn *c, uint64_t n)
{
    if (!c->pending) return true;
    if (c->pending + n > (s->o.conn_cap ? s->o.conn_cap : (32ull << 20))) return false;
    if (s->pending + n > reply_budget(s)) return false;
    return c->super || !c->tal || c->tal->pending + n <= share(s->o.role_reply_bytes, 64ull << 20);
}

/* 2b-2a, the engine thread: a result's chunk of frames (b, at FLUSH_AT) to memory while there is room, else to its
 * spool, decided under mu before the next chunk is encoded, so its connection's, its role's and the server's unsent
 * replies in memory stay within their bounds and a slow reader never makes the engine wait. A read finds the spools full
 * (the server's, its role's share) or none at all: false, the chunk dropped from at on (the frames of earlier statements
 * kept), e set. A write's chunk (wrote: its rows already in the log or its transaction) is never refused: spooled past
 * the bounds, or held in memory when no spool takes it */
static bool rows_flush(imdbs *s, conn *c, imdbw_buf *b, size_t at, bool wrote, bool copy, imdb_err *e)
{
    uint64_t n = b->len;
    /* 2b-3: the spool disk below --disk-headroom: a read refused (as a full spool), a write's reply kept in memory (its
     * commit stands; bounded by the result the engine already holds); read at every chunk, so a result spilling as the
     * disk fills stops at the chunk that finds it. Everyone's, a superuser's too: a spool never takes the disk's last
     * space (PostgreSQL's temp_file_limit binds a superuser too; --copy-spool's 4 GiB is past the default reserve) */
    bool dlow = s->o.disk_headroom && s->spool_dfd >= 0 && disk_low(s, IMDBSP_FREE_SPOOL, n);
    if (wrote && c->dkept) dlow = true; /* a write's reply once kept in memory stays there to its end: free space hovering at
                                         * the line never alternates it between memory and new spool files (a descriptor each) */
    pthread_mutex_lock(&s->mu);
    bool gone = c->gone, mem = !c->rsp && mem_room(s, c, n);
    uint64_t bound = s->o.copy_spool ? s->o.copy_spool : (4ull << 30);
    bool sfull = s->spool_held + n > bound, rfull = !role_spool_room(s, c, n);
    bool spill = !gone && !mem && s->spool_dfd >= 0 && !dlow && (wrote || (!sfull && !rfull));
    if (spill) spool_move(s, c, (int64_t)n, (int64_t)n); /* reserved under the lock it was decided in */
    pthread_mutex_unlock(&s->mu);
    if (gone || mem) {
        flush(s, c, b);
        return true;
    }
    if (!wrote && (dlow || sfull || rfull || s->spool_dfd < 0)) {
        pthread_mutex_lock(&s->mu);
        s->n.res_refused++;
        s->n.disk_refused += dlow;
        s->n.role_spool_limits += !dlow && !sfull && rfull;
        pthread_mutex_unlock(&s->mu);
        rsp_end(s, c);
        b->len = at; /* this statement's unsent frames dropped: its ERROR follows what was handed over */
        imdb_fail(e, s->spool_dfd < 0 ? IMDB_ERR_STATE : IMDB_ERR_LIMIT, "%s",
                  s->spool_dfd < 0 ? "a result past its connection's room needs a spool directory (--spool-dir, or "
                                     "--server-dir's spool/)"
                  : dlow && copy ? "COPY TO: a role's export unread past its connection's room, the server's spool disk "
                                   "below its headroom (--disk-headroom), fails; read as it comes, or export in parts"
                  : dlow ? "a result unread past its connection's room, the server's spool disk below its headroom "
                           "(--disk-headroom), fails; read as it comes, or read it in parts (LIMIT, OFFSET or key ranges)"
                  : copy && sfull ? "COPY TO: a role's export unread past its connection's room and the server's spools "
                                    "(--copy-spool) fails (the server never waits for a reader); read as it comes, or export "
                                    "in parts (COPY (SELECT ... WHERE a key range) TO STDOUT)"
                  : copy ? "COPY TO: a role's export unread past its connection's room and its role's spool share "
                           "(--role-copy-spool) fails (the server never waits for a reader); read as it comes, or export in "
                           "parts (COPY (SELECT ... WHERE a key range) TO STDOUT)"
                  : sfull ? "a result unread past its connection's room and the server's spools (--copy-spool) fails (the "
                            "server never waits for a reader); read as it comes, or read it in parts (LIMIT, OFFSET or key "
                            "ranges)"
                          : "a result unread past its connection's room and its role's spool share (--role-copy-spool) fails "
                            "(the server never waits for a reader); read as it comes, or read it in parts (LIMIT, OFFSET or "
                            "key ranges)");
        return false;
    }
    imdb_err we = {0};
    if (spill && !rsp_append(s, c, b, &we, true)) {
        imdbw_buf_reset(b);
        return true;
    }
    if (wrote) { /* no spool takes it: a write's reply in memory (its commit reaches the client) */
        if (dlow && !c->dkept) { /* (once a statement) */
            pthread_mutex_lock(&s->mu);
            s->n.disk_kept++;
            pthread_mutex_unlock(&s->mu);
            c->dkept = true;
        }
        rsp_end(s, c);
        flush(s, c, b);
        return true;
    }
    rsp_end(s, c);
    b->len = at;
    pthread_mutex_lock(&s->mu);
    s->n.res_refused++;
    pthread_mutex_unlock(&s->mu);
    *e = we;
    return false;
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
        size_t at = b->len; /* 2b-2a: where this statement's frames not yet handed over begin in b */
        bool wrote = r->has_count || r->has_commit; /* a write's RETURNING: its rows are in the log or its transaction */
        bool ok = put_msg(b, &cols, NULL, index);
        for (uint64_t next = 0; ok && next < r->nrows;) {
            if (imdbw_rows_of(r, &cols, &next, ROWS_TARGET, b, &e)) {
                put_error(b, (uint32_t)-e.code, index, e.msg);
                ok = false;
            } else if (b->len >= FLUSH_AT) {
                if (!rows_flush(s, c, b, at, wrote, false, &e)) {
                    put_error(b, (uint32_t)-e.code, index, e.msg);
                    ok = false;
                }
                at = 0;
                if (c->gone) ok = false; /* its client gone: no further row is encoded, no one would read it */
            }
        }
        imdbw_msg_free(&cols);
        if (!ok) {
            rsp_end(s, c);
            return false;
        }
    }
    imdbw_msg d;
    if (warn) put_warning(b, warn, index);
    imdbw_done_of(r, &d);
    bool done = put_msg(b, &d, NULL, index);
    if (c->rsp) { /* 2b-2a: its DONE after its spooled frames, then the spool ends with the statement */
        flush(s, c, b);
        rsp_end(s, c);
    }
    return done;
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

/* ---- N1d: COPY's spools (docs/n1-design.md §8d) ---- */
/* under mu: a COPY FROM's spool closed, its bytes no longer held (by its owner: §8d's rule in conn's fields) */
static void cin_drop(imdbs *s, conn *c)
{
    if (!c->sp_in) return;
    imdbsp_close(c->sp_in);
    c->sp_in = NULL;
    spool_move(s, c, -(int64_t)c->in_len, 0);
}

/* under mu: a COPY TO's ring closed and freed, its unsent bytes no longer held */
static void ring_free(imdbs *s, conn *c, cring *g)
{
    for (cring **pp = &c->rings; *pp; pp = &(*pp)->next)
        if (*pp == g) {
            *pp = g->next;
            break;
        }
    spool_move(s, c, -(int64_t)ring_extent(g), g->raw ? -(int64_t)(g->w - g->r) : 0);
    imdbsp_close(g->sp);
    imdbw_free(g);
}

/* the session's COPY reader (the engine thread): the spool its connection's thread filled, whole before the statement
 * ran, so it never waits on the network; -1 for a COPY that is not ours to read (the server sends COPY_IN first) */
static long copy_rd(void *arg, char *buf, size_t cap)
{
    conn *c = arg;
    if (!c->cin_run) return -1;
    if (!c->sp_in || c->in_rd >= c->in_len) return 0; /* (no COPY_DATA at all: no spool was made) */
    size_t n = cap < c->in_len - c->in_rd ? cap : (size_t)(c->in_len - c->in_rd);
    ssize_t k = imdbsp_read(c->sp_in, c->in_rd, buf, n);
    if (k <= 0) return -1;
    c->in_rd += (uint64_t)k;
    return (long)k;
}

static void out_fail(conn *c, int32_t code, const char *msg)
{
    if (c->out_err) return;
    c->out_err = code;
    snprintf(c->out_msg, sizeof c->out_msg, "%s", msg);
}

static _Atomic uint32_t g_copy_hold_ms; /* tests: copy_wr sleeps this long before each write of a statement but its first */
static _Atomic uint32_t g_wake_hold_ms; /* tests: a connection's thread sleeps this long after a wake, then polls again */
void imdbs_test_wake_hold(uint32_t ms) { atomic_store_explicit(&g_wake_hold_ms, ms, memory_order_relaxed); }
/* tests: once, the thread of the connection whose id is g_frame_hold_conn holds as it takes a frame, until released (at
 * most 10 s), its id in g_frame_held meanwhile: the KILL race mid-read made deterministic, by the victim's thread alone */
static _Atomic uint64_t g_frame_hold_conn, g_frame_held;
static _Atomic bool g_frame_release;
void imdbs_test_frame_hold(uint64_t id)
{
    atomic_store(&g_frame_held, 0);
    atomic_store(&g_frame_release, id == 0);
    atomic_store(&g_frame_hold_conn, id);
}
uint64_t imdbs_test_frame_held(void) { return atomic_load(&g_frame_held); }
void imdbs_test_frame_release(void) { atomic_store(&g_frame_release, true); }
void imdbs_test_copy_hold(uint32_t ms) { atomic_store_explicit(&g_copy_hold_ms, ms, memory_order_relaxed); }

/* 2b-2b, tests: a pause at each point where a client may already know what the server is about to record (after a
 * verdict's write, around a READY's flush, after a push), so state recorded after its announcement fails every time,
 * not under load alone (t_server's state_order; IMDB_SRV_HOLD_US runs a group with it) */
static _Atomic uint32_t g_reply_hold_us;
void imdbs_test_reply_hold(uint32_t us) { atomic_store_explicit(&g_reply_hold_us, us, memory_order_relaxed); }
static void test_hold(void)
{
    uint32_t us = atomic_load_explicit(&g_reply_hold_us, memory_order_relaxed);
    if (us) usleep(us);
}
static _Atomic uint32_t g_count_hold_us; /* tests: between a request's count and its READY's flush alone */
void imdbs_test_count_hold(uint32_t us) { atomic_store_explicit(&g_count_hold_us, us, memory_order_relaxed); }

/* 2b-2b, the engine thread: a role's COPY TO through a result's path, never a ring: its bytes made COPY_OUT frames in the
 * request's buffer, each FLUSH_AT chunk to memory while its connection's, its role's and the server's room hold it, else
 * to a result's spool (rows_flush), so a role's slow reader never makes the engine wait (a ring's wait held every session
 * for up to --copy-wait). An export past the room and the spools (--copy-spool, its role's --role-copy-spool) fails by
 * name, read or not (the server encodes faster than a client reads): a role exports in parts */
static int copy_res(imdbs *s, conn *c, const char *p, size_t n, bool first)
{
    imdbw_buf *b = c->run_b;
    if (!b) { /* (never: a statement runs with its request's buffer) */
        out_fail(c, IMDB_ERR_STATE, "a COPY TO outside a request");
        return -1;
    }
    if (s->spool_dfd < 0) { /* as a ring's: a role's export may need a spool, so it has one or none runs */
        out_fail(c, IMDB_ERR_STATE, "COPY through the server needs a spool directory (--spool-dir, or --server-dir's spool/)");
        return -1;
    }
    uint32_t hold = atomic_load_explicit(&g_copy_hold_ms, memory_order_relaxed);
    if (hold && !first) usleep(hold * 1000u); /* (tests: a statement whose output comes slowly) */
    while (n) {
        if (c->gone) { /* its client gone: no further frame is made, no one would read it */
            out_fail(c, IMDB_ERR_CANCELLED, "statement cancelled");
            return -1;
        }
        size_t k = n < COPY_FRAME ? n : COPY_FRAME, at0 = b->len;
        imdbw_msg m;
        memset(&m, 0, sizeof m);
        m.type = IMDBW_COPY_OUT;
        m.data = (const uint8_t *)p, m.dlen = (uint32_t)k;
        imdbw_msg_put(b, &m, NULL);
        if (b->err) {
            bool nomem = b->nomem;
            b->len = at0, b->err = b->nomem = false;
            out_fail(c, nomem ? IMDB_ERR_NOMEM : IMDB_ERR_STATE, nomem ? "out of memory encoding a reply"
                                                                       : "a reply the server could not encode");
            return -1;
        }
        p += k, n -= k;
        if (b->len >= FLUSH_AT) {
            imdb_err e = {0};
            if (!rows_flush(s, c, b, c->out_at, false, true, &e)) { /* its unsent frames dropped: the ERROR follows */
                out_fail(c, e.code, e.msg);
                return -1;
            }
            c->out_at = 0;
        }
    }
    return 0;
}

/* the session's COPY writer (the engine thread): a COPY TO's output into its ring, never waiting while the ring has
 * room; when its client reads slower than it fills, waiting for room (others then wait too), at most copy_wait_ms in all
 * for the statement before it fails with LIMIT; its client gone, the stop or a CANCEL end the wait at once */
static int copy_wr(void *arg, const char *p, size_t n)
{
    conn *c = arg;
    imdbs *s = c->s;
    imdb_err e = {0};
    uint64_t size = s->o.copy_ring ? s->o.copy_ring : (256ull << 20);
    uint64_t bound = s->o.copy_spool ? s->o.copy_spool : (4ull << 30);
    uint64_t wait_ns = (uint64_t)(s->o.copy_wait_ms ? s->o.copy_wait_ms : 60000) * 1000000u;
    bool first = !c->out_mode;
    if (first) { /* decided once a statement (a connection's super moves only between statements): a superuser's ring, a
                  * role's result path (2b-2b) */
        c->out_mode = c->super || !c->tal ? 1 : 2;
        if (c->out_mode == 2) {
            c->out_at = c->run_b ? c->run_b->len : 0; /* this statement's frames begin here: a refusal drops them alone */
            pthread_mutex_lock(&s->mu);
            s->n.copy_out_res++;
            pthread_mutex_unlock(&s->mu);
        }
    }
    if (c->out_mode == 2) return copy_res(s, c, p, n, first);
    if (!c->ring) { /* its first bytes: the request's replies before it are handed over, then the ring's place */
        rsp_end(s, c); /* 2b-2a: (never: a result's spool ends with its statement) */
        if (s->spool_dfd < 0) {
            out_fail(c, IMDB_ERR_STATE, "COPY through the server needs a spool directory (--spool-dir, or --server-dir's spool/)");
            return -1;
        }
        cring *g = imdbw_alloc(1, sizeof *g);
        outbuf *mk = g ? imdbw_alloc(1, sizeof *mk) : NULL;
        if (!mk || imdbsp_open(s->spool_dfd, &g->sp, &e)) {
            out_fail(c, mk ? e.code : IMDB_ERR_NOMEM, mk ? e.msg : "out of memory for a COPY's ring");
            imdbw_free(mk);
            imdbw_free(g);
            return -1;
        }
        g->size = size;
        mk->ring = g;
        flush(s, c, c->run_b);
        pthread_mutex_lock(&s->mu);
        g->next = c->rings;
        c->rings = g;
        files_note(s, c);
        if (c->gone) {
            imdbw_free(mk); /* no reply reaches it: the ring is freed at its thread's end */
        } else {
            if (c->ot) c->ot->next = mk;
            else c->oh = mk;
            c->ot = mk;
        }
        s->n.copy_out++;
        pthread_mutex_unlock(&s->mu);
        c->ring = g;
    }
    uint32_t hold = atomic_load_explicit(&g_copy_hold_ms, memory_order_relaxed);
    if (hold && !first) usleep(hold * 1000u); /* (tests: a statement whose output comes slowly) */
    cring *g = c->ring;
    uint64_t *waited = &c->out_waited; /* the statement's, across its writes: copy_wait_ms bounds the sum */
    /* 2b-3: the spool disk below --disk-headroom: the ring grows to its floor and no further, then streams at its
     * reader's pace (a superuser's export runs on a filling disk: it is how data leaves one) */
    bool dlow = s->o.disk_headroom && disk_low(s, IMDBSP_FREE_SPOOL, n);
    while (n) {
        pthread_mutex_lock(&s->mu);
        uint64_t room = 0;
        for (;;) {
            if (c->gone || s->stopping || atomic_load_explicit(&c->ses.cancel, memory_order_relaxed)) {
                bool stop = s->stopping;
                pthread_mutex_unlock(&s->mu);
                out_fail(c, IMDB_ERR_CANCELLED, stop ? "the server stops: statement cancelled" : "statement cancelled");
                return -1;
            }
            uint64_t mine = g->w - g->r;
            room = g->size - mine;
            if (g->w < g->size) { /* 2b-2a: its file still grows, charged as it grows: the server's spool bound stops the
                                   * growth, and it wraps at the size it has: its reader's pace, never another's spools
                                   * freed (2b-3: a ring is a superuser's or a tally-less connection's alone, out_mode 1,
                                   * so no role's share binds here: a role's COPY TO is a result's, copy_res) */
                uint64_t sroom = bound > s->spool_held ? bound - s->spool_held : 0, grow = sroom;
                uint64_t floor = g->size < RING_FLOOR ? g->size : RING_FLOOR;
                if (dlow && grow > (g->w < floor ? floor - g->w : 0)) grow = g->w < floor ? floor - g->w : 0;
                if (g->w + grow < floor && grow < n) { /* a ring too small to stream through (an export that fits
                                                    * whole passes): a byte at a time, the engine waiting */
                    room = 0, mine = 0;
                } else if (!grow) {
                    g->size = g->w; /* [r, w) never wrapped: each byte stays where it is under the smaller size */
                    room = g->size - mine;
                } else if (room > grow) {
                    room = grow;
                }
            }
            if (room) break;
            if (!mine) { /* its ring empty, or kept under its floor, by the spools' bounds: others' bytes, no pace of its
                          * reader's, so no wait */
                s->n.copy_limits++;
                pthread_mutex_unlock(&s->mu);
                out_fail(c, IMDB_ERR_LIMIT, "COPY TO: the server's spools are full (every spool's bytes held at once: "
                                            "--copy-spool)");
                return -1;
            }
            if (*waited >= wait_ns) {
                s->n.copy_limits++;
                pthread_mutex_unlock(&s->mu);
                char msg[200];
                snprintf(msg, sizeof msg, "COPY TO: its client read the data too slowly (the server waited %u ms in all for "
                                          "room: --copy-ring, --copy-wait)", (unsigned)(wait_ns / 1000000u));
                out_fail(c, IMDB_ERR_LIMIT, msg);
                return -1;
            }
            s->n.copy_waits++;
            uint64_t t0 = imdb_mono_ns(), step = wait_ns - *waited < 100000000u ? wait_ns - *waited : 100000000u;
            struct timespec ts;
            clock_gettime(CLOCK_REALTIME, &ts);
            ts.tv_nsec += (long)step;
            ts.tv_sec += ts.tv_nsec / 1000000000L;
            ts.tv_nsec %= 1000000000L;
            pthread_cond_timedwait(&s->cv, &s->mu, &ts);
            *waited += imdb_mono_ns() - t0;
        }
        uint64_t off = g->w % g->size;
        size_t k = n;
        if (k > room) k = (size_t)room;
        if (k > g->size - off) k = (size_t)(g->size - off);
        pthread_mutex_unlock(&s->mu);
        if (imdbsp_write(g->sp, off, p, k, &e)) { /* [w, w + k) is the engine's alone: the reader takes [r, w) */
            out_fail(c, e.code, e.msg);
            return -1;
        }
        pthread_mutex_lock(&s->mu);
        uint64_t ext = ring_extent(g);
        g->w += k;
        spool_move(s, c, (int64_t)(ring_extent(g) - ext), 0); /* (the growth alone: a byte over an old one charged once) */
        pthread_mutex_unlock(&s->mu);
        wake(c->wake[1]);
        p += k, n -= k;
    }
    return 0;
}

/* the engine thread, at a statement's end: its COPY TO ring has all its bytes (its connection's thread sends the rest,
 * then the replies after it) */
static void ring_end(imdbs *s, conn *c)
{
    if (!c->ring) return;
    pthread_mutex_lock(&s->mu);
    c->ring->done = true;
    pthread_mutex_unlock(&s->mu);
    c->ring = NULL;
    wake(c->wake[1]);
}

/* the engine thread: r's statements from r->at on; true when the request ended (its READY sent), false when it pauses
 * at a statement's boundary and runs on later */
static bool run(imdbs *s, rq *r)
{
    conn *c = r->c;
    if (r->type == RQ_CLOSE) {
        if (c->ses_open) imdb_session_close(&c->ses); /* an open transaction rolled back */
        c->ses_open = false;
        pthread_mutex_lock(&s->mu);
        if (c->cin_end) cin_drop(s, c); /* N1d: a spool the engine took (its data ended) but never ran: its client left */
        pthread_mutex_unlock(&s->mu);
        return true;
    }
    if (!c->ses_open) {
        imdb_session_init(&c->ses, s->db);
        imdb_session_copy_io(&c->ses, copy_rd, copy_wr, c); /* N1d: COPY through its spools */
        c->ses.role = c->role; /* N1e: its privileges checked (docs/n1-design.md §8e) */
        c->ses.enforce = true;
        role_caps(&s->o, &c->ses.caps); /* N1e stage two: held while its role is not a superuser */
        if (!c->super) c->ses.slow_ms = c->ses.caps.slow_ms; /* 2b-2b: its role's default (a superuser's none, as SET leaves it) */
        c->ses_open = true;
    }
    if (atomic_load(&r->killed)) imdb_session_cancel_held(&c->ses, true); /* N1e stage two: a KILL before its session was */
    imdbw_buf b;
    imdbw_buf_init(&b);
    c->run_b = &b;
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
        /* N1d: a COPY ... FROM STDIN: COPY_IN, then the request waits here (not runnable) until its data's end or its
         * refusal; it runs then from its spool, so the engine thread never waits on the network */
        /* 2b-3: the data disk read before each statement (a role's row writes refused below the headroom, by the engine's
         * gate: the catalog says who is a superuser now), so a COPY FROM is refused before its upload */
        c->ses.disk_low = disk_low(s, IMDBSP_FREE_DATA, 0);
        c->dkept = false;
        pthread_mutex_lock(&s->mu);
        bool resumed = c->cin == CIN_OPEN && c->cin_rq == (const void *)r && c->cin_i == i; /* 2b-3: its COPY's data ended */
        pthread_mutex_unlock(&s->mu);
        bool cin = resumed ||
                   (r->type == IMDBW_QUERY && imdb_copy_in_open(&c->ses, (const char *)m->texts[i].p, m->texts[i].len));
        int32_t cerr = 0;
        if (cin && s->spool_dfd >= 0) {
            pthread_mutex_lock(&s->mu);
            bool fresh = c->cin == CIN_NONE;
            if (fresh) {
                c->cin = CIN_OPEN, c->cin_end = false, c->cin_err = 0, c->cin_msg[0] = 0;
                c->in_len = c->in_rd = 0, c->cin_last = imdb_mono_ns();
                c->cin_rq = r, c->cin_i = i;
            } else if (c->cin != CIN_OPEN) {
                c->cin_err = IMDB_ERR_STATE; /* (never: a new COPY reaches the engine only after the last one's end) */
                snprintf(c->cin_msg, sizeof c->cin_msg, "a COPY while another's data is still read");
            }
            cerr = c->cin_err;
            pthread_mutex_unlock(&s->mu);
            if (fresh) {
                /* its data arriving is a statement under way, as PostgreSQL's COPY is: its transaction never idle
                 * (idle_in_transaction_timeout), its age still counted (transaction_timeout) */
                if (c->ses.txn.open) c->ses.txn.busy = true;
                imdbw_msg ci;
                memset(&ci, 0, sizeof ci);
                ci.type = IMDBW_COPY_IN;
                put_msg(&b, &ci, NULL, i);
                flush(s, c, &b);
                imdbw_buf_free(&b);
                c->run_b = NULL;
                return false;
            }
        }
        if (cin && c->ses.txn.busy) { /* its upload over: idle from here unless the statement runs (its end stamps it) */
            c->ses.txn.busy = false;
            c->ses.txn.last_ns = imdb_mono_ns();
        }
        pthread_mutex_lock(&s->mu);
        s->n.started++; /* before it runs: a test waiting for it to move knows this statement has begun */
        pthread_mutex_unlock(&s->mu);
        c->out_err = 0, c->out_waited = 0, c->out_mode = 0, c->out_at = 0;
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
            if (!rc && cin && s->spool_dfd < 0)
                rc = imdb_fail(&e, IMDB_ERR_STATE, "COPY through the server needs a spool directory (--spool-dir, or "
                                                   "--server-dir's spool/)");
            else if (!rc && cerr)
                rc = imdb_fail(&e, cerr, "%s", c->cin_msg); /* refused before it ran: its data never read */
            if (!rc && cin) {
                c->cin_run = true;
                pthread_mutex_lock(&s->mu);
                s->n.copy_in++;
                pthread_mutex_unlock(&s->mu);
            }
            if (!rc) rc = imdb_exec_one(&c->ses, (const char *)t->p, t->len, m->params[i].n ? pv : NULL, m->params[i].n, &res, &e);
            if (cin && s->spool_dfd >= 0) { /* its spool freed; a client still sending: the rest dropped to its end */
                c->cin_run = false;
                pthread_mutex_lock(&s->mu);
                c->cin_rq = NULL;
                if (c->cin_end) {
                    cin_drop(s, c);
                    c->cin = CIN_NONE;
                } else {
                    c->cin = CIN_DISCARD; /* (its spool was its thread's, closed when it set the refusal) */
                }
                pthread_mutex_unlock(&s->mu);
            }
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
        ring_end(s, c); /* N1d: a COPY TO's bytes all in its ring: its DONE (or ERROR) queued after them */
        if (rc && c->out_err) { /* its writer's refusal in its own words (the engine's says only that writing failed) */
            imdb_err_clear(&e);
            rc = imdb_fail(&e, c->out_err, "%s", c->out_msg);
        }
        pthread_mutex_lock(&s->mu);
        s->n.statements++;
        s->n.disk_refused += c->ses.disk_refused;
        pthread_mutex_unlock(&s->mu);
        c->ses.disk_refused = false;
        bool ok = !rc;
        const char *warn = s->db->warning[0] && strcmp(wb, s->db->warning) ? s->db->warning : NULL; /* as the CLI shows one */
        if (rc) {
            if (warn) put_warning(&b, warn, i);
            put_error(&b, (uint32_t)-rc, i, e.msg);
            if (c->rsp) { /* 2b-2b: a role's COPY TO spilled, then failed: its ERROR after its spooled frames, the spool ended */
                flush(s, c, &b);
                rsp_end(s, c);
            }
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
            c->run_b = NULL;
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
    pthread_mutex_lock(&s->mu); /* 2b-2b: SESSIONS' state from the READY on (a client that reads it, then lists, sees it) */
    c->txstate = rd.state;
    r->readied = true;
    s->n.requests++; /* 2b-2b: counted here, before its client can read the READY (a test that waits on it read it too soon) */
    pthread_mutex_unlock(&s->mu);
    test_hold();
    {
        uint32_t us = atomic_load_explicit(&g_count_hold_us, memory_order_relaxed);
        if (us) usleep(us);
    }
    flush(s, c, &b);
    test_hold();
    imdbw_buf_free(&b);
    c->run_b = NULL;
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
    /* §8f: logins by the weaker binding, and hellos naming a type this server refuses, said in the event log (the
     * engine's: --events) when either has moved since the last tick, with both totals: an operator who allowed
     * tls-server-end-point sees it in use, and one who did not sees drivers asking for it; at most one in 5 s (a peer
     * that never authenticates moves cb_refused: no flood) */
    pthread_mutex_lock(&s->mu);
    uint64_t ep = s->n.logins_endpoint, cr = s->n.cb_refused;
    pthread_mutex_unlock(&s->mu);
    uint64_t now = imdb_mono_ns();
    if ((ep != s->ev_endpoint || cr != s->ev_cbref) && (!s->ev_cb_ns || now - s->ev_cb_ns >= 5000000000ull)) {
        imdb_event_begin(s->db, "channel_binding");
        imdb_event_int(s->db, "end_point_logins", (int64_t)ep);
        imdb_event_int(s->db, "refused_types", (int64_t)cr);
        imdb_event_end(s->db);
        s->ev_endpoint = ep, s->ev_cbref = cr, s->ev_cb_ns = now;
    }
    /* 2b-3: each directory's crossing of --disk-headroom, either way, said in the event log (read here too, so a crossing
     * is seen with no statement running): its state when it differs from the last event's, at most one in 5 s a
     * directory (a disk flapping at the line logs no more; the state it settles in is said) */
    for (int k = 0; k < 2 && s->o.disk_headroom; k++) {
        if (k == IMDBSP_FREE_SPOOL && s->spool_dfd < 0) continue;
        uint64_t fr = 0;
        bool low = disk_low(s, k, 0);
        pthread_mutex_lock(&s->mu);
        fr = k == IMDBSP_FREE_DATA ? s->n.disk_free_data : s->n.disk_free_spool;
        pthread_mutex_unlock(&s->mu);
        if (low == s->ev_disk[k] || (s->ev_disk_ns[k] && now - s->ev_disk_ns[k] < 5000000000ull)) continue;
        s->ev_disk_ns[k] = now;
        imdb_event_begin(s->db, "disk_headroom");
        imdb_event_str(s->db, "directory", k == IMDBSP_FREE_DATA ? "data" : "spool", k == IMDBSP_FREE_DATA ? 4 : 5);
        imdb_event_int(s->db, "below", low);
        imdb_event_int(s->db, "free_bytes", (int64_t)(fr > INT64_MAX ? INT64_MAX : fr));
        imdb_event_int(s->db, "headroom", (int64_t)(s->o.disk_headroom > INT64_MAX ? INT64_MAX : s->o.disk_headroom));
        imdb_event_end(s->db);
        if (s->o.say_disk) /* (an operator without --events sees it too) */
            fprintf(stderr, low ? "imagedb-server: warning: the %s directory's file system has %llu bytes free, below "
                                  "--disk-headroom (%llu): %s\n"
                                : "imagedb-server: the %s directory's file system has %llu bytes free, above --disk-headroom "
                                  "(%llu) again%s\n",
                    k == IMDBSP_FREE_DATA ? "data" : "spool", (unsigned long long)fr, (unsigned long long)s->o.disk_headroom,
                    !low ? ""
                    : k == IMDBSP_FREE_DATA ? "roles' row writes are refused (a superuser's statements run)"
                                            : "uploads and results past their connection's room are refused (a write's reply "
                                              "kept in memory), everyone's");
        s->ev_disk[k] = low;
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
        /* the tick on its own clock, whatever wakes this thread: a connection's every send broadcasts the condition
         * (a reader draining a large result or a COPY TO), and a wait that never timed out once starved the tick (the
         * transaction timeouts, maintenance, a role change's logins: N1d's review, 2026-11-17) */
        if (ms_since(last_tick) >= tick_ms) {
            pthread_mutex_unlock(&s->mu);
            tick(s);
            pthread_mutex_lock(&s->mu);
            s->n.ticks++;
            last_tick = imdb_mono_ns();
            continue;
        }
        rq *r = pick(s);
        if (!r) { /* nothing runnable: wait for work, at most until the next tick is due */
            uint64_t due = last_tick + (uint64_t)tick_ms * 1000000u, now = imdb_mono_ns();
            uint64_t left = due > now ? due - now : 0;
            struct timespec ts;
            clock_gettime(CLOCK_REALTIME, &ts);
            ts.tv_sec += (time_t)(left / 1000000000u);
            ts.tv_nsec += (long)(left % 1000000000u);
            ts.tv_sec += ts.tv_nsec / 1000000000L;
            ts.tv_nsec %= 1000000000L;
            pthread_cond_timedwait(&s->cv, &s->mu, &ts);
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
            if (r->type != RQ_CLOSE) c->txstate = ready_state(c); /* N1e stage two: SESSIONS' state */
            if (atomic_load(&r->killed) && c->ses_open) imdb_session_cancel_held(&c->ses, false); /* its hold ends with it */
            c->rh = r->next;
            if (!c->rh) c->rt = NULL;
            c->nq--;
            qb_move(c, -(int64_t)r->len);
            if (r->type == RQ_CLOSE) c->closed = true; /* (a request counted when its READY was queued: run) */
            rq_free(r);
            pthread_cond_broadcast(&s->cv); /* a connection waits for its close, or for room in its queue */
            wake(c->wake[1]);
        }
    }
    /* the stop: queued requests dropped, every session closed (an open transaction rolled back) */
    for (conn *c = s->conns; c; c = c->next) {
        for (rq *r = c->rh, *nx; r; r = nx) nx = r->next, rq_free(r);
        qb_move(c, -(int64_t)c->qbytes);
        c->rh = c->rt = NULL, c->nq = 0;
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
    if (c->s->o.test_write_max && n > c->s->o.test_write_max) n = c->s->o.test_write_max; /* (tests: a reader's pace shown) */
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

/* a login whose proof is good, admitted (under the lock it takes): a role's connections at once and the slots kept for
 * superusers (N1e stage two: past either, refused after its verdict: c->refuse), its role's tally, the role its session
 * acts as. Before its verdict is written (2b-2b), so whatever the client does on reading it finds the session listed */
static void admit(imdbs *s, conn *c, uint32_t rid, bool super)
{
    pthread_mutex_lock(&s->mu);
    if (!super) {
        uint32_t mine = 0, cap = s->o.role_conns == IMDBS_NONE ? UINT32_MAX : s->o.role_conns ? s->o.role_conns : 32;
        uint32_t maxc = s->o.max_conns ? s->o.max_conns : 256;
        uint32_t keep = s->o.su_reserve == IMDBS_NONE ? 0 : s->o.su_reserve ? s->o.su_reserve : 4;
        for (conn *o = s->conns; o; o = o->next) mine += o != c && o->role == rid && !o->closed;
        if (mine >= cap) c->refuse = "too many connections for this role (--role-conns)";
        else if ((uint64_t)s->nconns + keep > maxc)
            c->refuse = "the remaining connection slots are reserved for superusers (--superuser-reserve)";
    }
    if (!c->refuse) {
        tal_join(s, c, rid); /* N1e stage two: its role's shares (an entry a connection: never short; if it were, the login
                              * is refused, never left outside its role's shares) */
        if (!c->tal) c->refuse = "the server could not account for this role's connection";
    }
    if (!c->refuse) { /* N1e: the role its session acts as (a refused login's acts as none) */
        c->role = rid;
        c->super = super;
        c->login_ns = imdb_mono_ns(); /* N1e stage two: SESSIONS' age */
    }
    pthread_mutex_unlock(&s->mu);
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
    /* N1c: on TCP, TLS first (nothing in the clear) */
    if (c->tls && !handshake(c, deadline)) return false;
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
    /* §8f (decided 2026-11-18): the AuthMessage's binding is the one the hello names (its type covered by the proof, the
     * hello's bytes in the AuthMessage): none on the socket; on TCP the TLS exporter (RFC 9266: a proof made over
     * another TLS session, a relay's, fails) or, where this server allows it (--channel-binding any), the hash of its
     * certificate (RFC 5929: a relay holding the server's key passes it). A type refused costs what a wrong password
     * does (the same messages, no login looked up) and is answered by name, the verdict's code 2, its proof unchecked */
    uint8_t cb = (uint8_t)h.flags, binding[IMDBW_KEY] = {0};
    bool cb_refused = c->tls ? cb == IMDBW_CB_NONE || (cb == IMDBW_CB_ENDPOINT && !s->o.cb_any) : cb != IMDBW_CB_NONE;
    if (c->tls && !cb_refused &&
        (cb == IMDBW_CB_EXPORTER ? imdbt_binding(c->tls, binding) : imdbt_endpoint(c->tls, binding)))
        return false;
    logins *l = cb_refused ? NULL : logins_take(s);
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
    uint32_t rid = lo ? lo->id : 0;
    bool super = lo && lo->super;
    logins_put(s, l); /* the keys are copied: the snapshot may go */
    bool ok = !imdb_random(ch.nonce, sizeof ch.nonce, &e) && !imdbw_challenge_put(&ch, chb) &&
              !write_full(c, chb, sizeof chb, deadline) && !read_full(c, proof, sizeof proof, deadline);
    bool decided = false; /* 2b-2b: a verdict decided: counted before it is written, as its admission is */
    if (ok) {
        imdbw_auth_message(c->tls ? IMDBW_EP_TCP : IMDBW_EP_UNIX, hello, chb, binding, am);
        bool proven = imdbw_scram_server(stored, server_key, am, proof, sig);
        ok = proven && lo && !cb_refused;
        if (ok) admit(s, c, rid, super); /* 2b-2b: before its verdict leaves (a client that reads it, then lists, sees itself) */
        pthread_mutex_lock(&s->mu);
        if (ok) {
            s->n.logins++;
            s->n.logins_endpoint += cb == IMDBW_CB_ENDPOINT; /* §8f: the weaker binding's logins, counted */
            s->n.role_refused += c->refuse != NULL;
        } else {
            s->n.refusals++;
            s->n.cb_refused += cb_refused;
        }
        pthread_mutex_unlock(&s->mu);
        decided = true;
        imdbw_verdict v;
        memset(&v, 0, sizeof v);
        v.code = cb_refused ? IMDBW_VERDICT_BINDING : ok ? IMDBW_VERDICT_OK : IMDBW_VERDICT_REFUSED;
        if (ok) memcpy(v.sig, sig, IMDBW_KEY);
        if (imdbw_verdict_put(&v, vb) || write_full(c, vb, sizeof vb, deadline)) ok = false; /* (admitted: its end, as any) */
        test_hold();
    }
    imdb_wipe(stored, sizeof stored);
    imdb_wipe(server_key, sizeof server_key);
    imdb_wipe(sig, sizeof sig);
    if (!decided) { /* a login that ended before its verdict (the network, the nonce): a refusal, as before */
        pthread_mutex_lock(&s->mu);
        s->n.refusals++;
        pthread_mutex_unlock(&s->mu);
    }
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
            qb_move(c, -(int64_t)r->len);
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
    if (c->cin == CIN_OPEN && !c->cin_end) cin_drop(s, c); /* N1d: its COPY's spool, still this thread's: freed at once */
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
    o->p = b.p, o->len = b.len, o->oot = true;
    pthread_mutex_lock(&s->mu);
    c->oot += o->len; /* N1e stage two */
    if (c->oot > s->n.oot_peak) s->n.oot_peak = c->oot;
    if (c->ot) c->ot->next = o;
    else c->oh = o;
    c->ot = o;
    pend_move(s, c, (int64_t)o->len);
    pthread_mutex_unlock(&s->mu);
}

/* N1d: a COPY frame from the client (its connection's thread): its data into the spool while it arrives, dropped while
 * the COPY's refusal reads it to its end; false when no COPY expects it (the stream no longer says whose bytes they are) */
static bool copy_frame(conn *c, const imdbw_msg *m)
{
    imdbs *s = c->s;
    uint64_t bound = s->o.copy_spool ? s->o.copy_spool : (4ull << 30);
    /* 2b-3: the spool disk read at every frame of data (everyone's: a spool never takes the disk's last space) */
    bool dlow = m->type == IMDBW_COPY_DATA && s->o.disk_headroom && s->spool_dfd >= 0 && disk_low(s, IMDBSP_FREE_SPOOL, m->dlen);
    pthread_mutex_lock(&s->mu);
    if (c->cin == CIN_NONE || (c->cin == CIN_OPEN && c->cin_end)) { /* (after its end: data no COPY expects) */
        pthread_mutex_unlock(&s->mu);
        return false;
    }
    c->cin_last = imdb_mono_ns();
    if (c->cin == CIN_DISCARD) { /* refused and answered: dropped to the client's end, then no COPY */
        if (m->type != IMDBW_COPY_DATA) c->cin = CIN_NONE;
        pthread_mutex_unlock(&s->mu);
        return true;
    }
    if (m->type != IMDBW_COPY_DATA) { /* the client's end: the request runnable again */
        if (m->type == IMDBW_COPY_FAIL && !c->cin_err) {
            const imdbw_text *t = m->ntexts ? &m->texts[0] : NULL;
            int keep = t ? (int)imdbw_utf8_fit(t->p, t->len, IMDBW_MESSAGE_MAX - 64) : 0;
            snprintf(c->cin_msg, sizeof c->cin_msg, "COPY ... FROM STDIN failed by its client: %.*s", keep,
                     t ? (const char *)t->p : "");
            c->cin_err = IMDB_ERR_CANCELLED;
            cin_drop(s, c);
        }
        c->cin_end = true;
        pthread_cond_broadcast(&s->cv);
        pthread_mutex_unlock(&s->mu);
        return true;
    }
    if (c->cin_err) { /* refused, its answer not yet sent: dropped */
        pthread_mutex_unlock(&s->mu);
        return true;
    }
    if (dlow) { /* 2b-3: an upload past the spool disk's headroom, a superuser's too (its spool's): refused, never run */
        snprintf(c->cin_msg, sizeof c->cin_msg, "COPY ... FROM STDIN: the server's spool disk is below its headroom "
                 "(--disk-headroom): the upload is refused; the rest is read and dropped");
        c->cin_err = IMDB_ERR_LIMIT;
        s->n.copy_limits++;
        s->n.disk_refused++;
        cin_drop(s, c);
        pthread_cond_broadcast(&s->cv);
        pthread_mutex_unlock(&s->mu);
        return true;
    }
    if (s->spool_held + m->dlen <= bound && !role_spool_room(s, c, m->dlen)) { /* 2b-2a: its role's share */
        snprintf(c->cin_msg, sizeof c->cin_msg, "COPY ... FROM STDIN: its data passed its role's spool share (--role-copy-spool: "
                 "every spool of the role's connections at once); the rest is read and dropped");
        c->cin_err = IMDB_ERR_LIMIT;
        s->n.copy_limits++;
        s->n.role_spool_limits++;
        cin_drop(s, c);
        pthread_cond_broadcast(&s->cv);
        pthread_mutex_unlock(&s->mu);
        return true;
    }
    if (s->spool_held + m->dlen > bound) { /* answered at once, the rest dropped (§8d) */
        snprintf(c->cin_msg, sizeof c->cin_msg, "COPY ... FROM STDIN: its data passed the server's spool bound (%llu bytes "
                 "held at once: --copy-spool); the rest is read and dropped", (unsigned long long)bound);
        c->cin_err = IMDB_ERR_LIMIT;
        s->n.copy_limits++;
        cin_drop(s, c);
        pthread_cond_broadcast(&s->cv);
        pthread_mutex_unlock(&s->mu);
        return true;
    }
    spool_move(s, c, (int64_t)m->dlen, 0); /* reserved before the write: the bounds hold across connections */
    imdbsp *sp = c->sp_in;
    uint64_t off = c->in_len;
    pthread_mutex_unlock(&s->mu);
    imdb_err e = {0};
    int rc = sp ? IMDB_OK : imdbsp_open(s->spool_dfd, &sp, &e); /* this thread's while the data arrives */
    if (!rc) rc = imdbsp_write(sp, off, m->data, m->dlen, &e);
    pthread_mutex_lock(&s->mu);
    if (sp && !c->sp_in) c->sp_in = sp;
    if (rc) {
        spool_move(s, c, -(int64_t)m->dlen, 0);
        snprintf(c->cin_msg, sizeof c->cin_msg, "%s", e.msg);
        c->cin_err = e.code;
        cin_drop(s, c);
        pthread_cond_broadcast(&s->cv);
    } else {
        c->in_len += m->dlen;
    }
    pthread_mutex_unlock(&s->mu);
    return true;
}

/* under mu, by the connection's own thread (its spool is written outside mu): the COPY whose data arrives refused, never
 * run, the rest of its data read and dropped */
static void cin_cancel(imdbs *s, conn *c, const char *by)
{
    snprintf(c->cin_msg, sizeof c->cin_msg, "statement cancelled%s: the COPY never ran (the rest of its data is read and "
                                            "dropped)", by);
    c->cin_err = IMDB_ERR_CANCELLED;
    cin_drop(s, c);
    s->n.cancels++;
    pthread_cond_broadcast(&s->cv);
}

/* N1e stage two: SESSIONS, answered here out of turn as PONG is (§4): a superuser's every session, a role's its own role's;
 * each its id, role, endpoint, state (at its last request's end, or running, or receiving a COPY's data), age since its
 * login, and its role's name as the logins give it now ("" for a role no longer among them: dropped, NOLOGIN, erased; a
 * session keeps no copy of a name, so ERASE ROLE's wipe reaches every one). false when no memory: the ERROR, then the close */
static int sess_by_id(const void *a, const void *b)
{
    uint64_t x = ((const imdbw_sess *)a)->id, y = ((const imdbw_sess *)b)->id;
    return x < y ? -1 : x > y;
}

/* a session SESSIONS lists to a caller: a superuser's every one, a role's its own role's (under mu) */
static bool sess_listed(const conn *o, bool su, uint32_t me) { return o->role && !o->closed && (su || o->role == me); }

static bool sessions_answer(conn *c)
{
    imdbs *s = c->s;
    logins *l = logins_take(s);
    pthread_mutex_lock(&s->mu);
    bool su = c->super;
    uint32_t me = c->role, n = 0, k = 0;
    for (conn *o = s->conns; o; o = o->next) n += sess_listed(o, su, me);
    imdbw_sess *v = n ? imdbw_alloc(n, sizeof *v) : NULL;
    uint64_t now = imdb_mono_ns();
    for (conn *o = s->conns; v && o && k < n; o = o->next) {
        if (!sess_listed(o, su, me)) continue;
        imdbw_sess *x = &v[k++];
        x->id = o->id, x->role = o->role, x->endpoint = o->tcp ? 1 : 2;
        const rq *h = o->rh && o->rh->readied ? o->rh->next : o->rh; /* 2b-2b: a request whose READY is out is done */
        bool busy = (o->running && !(o->rh && o->rh->readied)) || (h && h->type != RQ_CLOSE);
        x->state = o->cin == CIN_OPEN && !o->cin_end ? IMDBW_SS_COPY
                   : busy                            ? IMDBW_SS_RUNNING
                   : o->txstate != IMDBW_IDLE        ? IMDBW_SS_IN_TXN
                                                     : IMDBW_SS_IDLE;
        x->age_ms = now > o->login_ns ? (now - o->login_ns) / 1000000u : 0;
        x->name = (imdbw_text){(const uint8_t *)"", 0}; /* until the logins name it */
    }
    pthread_mutex_unlock(&s->mu);
    bool ok = !n || v;
    if (ok) {
        qsort(v, k, sizeof *v, sess_by_id); /* one order: ids increasing (the codec's rule) */
        for (uint32_t i = 0; i < k; i++)
            for (uint32_t j = 0; l && j < l->n; j++)
                if (l->e[j].id == v[i].role) {
                    v[i].name = (imdbw_text){(const uint8_t *)l->e[j].name, (uint32_t)strlen(l->e[j].name)};
                    break;
                }
        imdbw_msg r = {.type = IMDBW_SESSIONS_LIST, .sess = v, .nsess = k};
        conn_put(c, &r);
    } else {
        imdbw_text t = {(const uint8_t *)"out of memory listing the sessions: the connection closed", 57};
        imdbw_msg er = {.type = IMDBW_ERROR, .code = (uint32_t)-IMDB_ERR_NOMEM, .texts = &t, .ntexts = 1};
        conn_put(c, &er);
    }
    imdbw_free(v);
    logins_put(s, l);
    return ok;
}

/* N1e stage two: KILL, answered here (no engine turn: a superuser who logs in while the engine runs a long statement
 * reaches it): a superuser's, or a role's on its own role's sessions. Cancel holds for the request running now (or begun
 * and paused), so each of its statements starts cancelled, however close to its start the KILL lands; terminate also has
 * the session's thread stop reading, send an ERROR and close, as when its client leaves (its transaction rolled back) */
static void kill_answer(conn *c, const imdbw_msg *m)
{
    imdbs *s = c->s;
    uint32_t code = IMDBW_KILL_NONE;
    pthread_mutex_lock(&s->mu);
    conn *t = NULL;
    for (conn *o = s->conns; o && !t; o = o->next)
        if (o->id == m->sid && o->role && !o->closed) t = o;
    if (t && !c->super && t->role != c->role) t = NULL; /* another role's: none to a role, as SESSIONS shows it none */
    if (t) {
        code = IMDBW_KILLED;
        rq *r = t->rh; /* the request running, begun, or next to run (queued behind another connection's): it starts cancelled */
        if (r && r->type != RQ_CLOSE) {
            atomic_store(&r->killed, true);
            if (t->ses_open) imdb_session_cancel_held(&t->ses, true);
        }
        /* a COPY whose data arrives: refused by its own thread at its next turn (it writes the spool outside mu) */
        if (t->cin == CIN_OPEN && !t->cin_end && !t->cin_err) t->cin_kill = true;
        if (m->kill == IMDBW_KILL_TERMINATE) t->kill_term = true;
        pthread_cond_broadcast(&s->cv); /* a COPY TO waiting for room sees it */
        wake(t->wake[1]);
    }
    s->n.kills += code == IMDBW_KILLED;
    s->n.kills_refused += code != IMDBW_KILLED;
    pthread_mutex_unlock(&s->mu);
    imdbw_msg r = {.type = IMDBW_KILL_DONE, .code = code, .sid = m->sid};
    conn_put(c, &r);
}

/* a frame from the client: a request queued, CANCEL and PING answered here; false when the connection is to end (a
 * protocol error, after its ERROR) */
static bool take_frame(conn *c, uint8_t type, uint8_t *body, uint32_t len, bool *terminate, bool *killed_out)
{
    imdbs *s = c->s;
    imdb_err e = {0};
    imdbw_msg m;
    memset(&m, 0, sizeof m);
    pthread_mutex_lock(&s->mu);
    bool copying = (c->cin == CIN_OPEN && !c->cin_end) || c->cin == CIN_DISCARD;
    bool killed = c->kill_term; /* (under mu, as kill_answer sets it before its KILL_DONE) */
    pthread_mutex_unlock(&s->mu);
    uint64_t hc = atomic_load(&g_frame_hold_conn);
    if (hc && hc == c->id && atomic_compare_exchange_strong(&g_frame_hold_conn, &hc, 0)) {
        atomic_store(&g_frame_held, c->id); /* (tests: this frame taken, the rest of the read after it: the KILL mid-read) */
        for (int i = 0; i < 10000 && !atomic_load(&g_frame_release); i++) usleep(1000);
    }
    if (killed) { /* a KILL's terminate set: no frame is decoded, answered or queued after it, wherever the read stands
                   * (pull reads every frame its socket holds, so a check at the wake alone left a frame read later in the
                   * same pull answered after the KILL_DONE: the advisor's 11-22 review; a malformed one would have been
                   * refused as a protocol error); pull returns to the loop's top, which ends the session, its ERROR the
                   * KILL's */
        *killed_out = true;
        imdbw_free(body);
        return true;
    }
    if (imdbw_msg_get(type, body, len, NULL, &m, &e)) {
        imdbw_free(body);
        char msg[300];
        snprintf(msg, sizeof msg, "a frame refused, the connection closed: %s", e.msg);
        imdbw_text t = {(const uint8_t *)msg, (uint32_t)imdbw_utf8_fit((const uint8_t *)msg, strlen(msg), IMDBW_MESSAGE_MAX)};
        imdbw_msg er = {.type = IMDBW_ERROR, .code = (uint32_t)-e.code, .texts = &t, .ntexts = 1};
        conn_put(c, &er);
        return false;
    }
    if (copying && type != IMDBW_COPY_DATA && type != IMDBW_COPY_DONE && type != IMDBW_COPY_FAIL && type != IMDBW_CANCEL &&
        type != IMDBW_PING) { /* N1d: §4: after COPY_IN, COPY's frames to its end (CANCEL and PING answered here) */
        imdbw_msg_free(&m);
        imdbw_free(body);
        imdbw_text t = {(const uint8_t *)"a request while a COPY's data was expected: the connection closed", 65};
        imdbw_msg er = {.type = IMDBW_ERROR, .code = (uint32_t)-IMDB_ERR_STATE, .texts = &t, .ntexts = 1};
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
        qb_move(c, (int64_t)len);
        pthread_cond_broadcast(&s->cv);
        pthread_mutex_unlock(&s->mu);
        return true;
    }
    case IMDBW_CANCEL: /* the statement running now, never one queued behind it (§4); no reply of its own */
        pthread_mutex_lock(&s->mu);
        if (c->cin == CIN_OPEN && !c->cin_end && !c->cin_err) { /* N1d: a COPY whose data arrives: refused, never run */
            cin_cancel(s, c, "");
        } else if (c->running && c->ses_open) {
            imdb_session_cancel(&c->ses);
            s->n.cancels++;
            pthread_cond_broadcast(&s->cv); /* N1d: a COPY TO waiting for room sees it */
        }
        pthread_mutex_unlock(&s->mu);
        break;
    case IMDBW_PING: {
        imdbw_msg pong = {.type = IMDBW_PONG};
        conn_put(c, &pong);
        break;
    }
    case IMDBW_SESSIONS: /* N1e stage two */
        if (sessions_answer(c)) break;
        imdbw_msg_free(&m);
        imdbw_free(body);
        return false;
    case IMDBW_KILL:
        kill_answer(c, &m);
        break;
    case IMDBW_TERMINATE:
        *terminate = true;
        break;
    case IMDBW_COPY_DATA:
    case IMDBW_COPY_DONE:
    case IMDBW_COPY_FAIL:
        if (copy_frame(c, &m)) break;
        /* fall through */
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
        /* N1d: while a COPY's frames arrive (its data, or its refusal's drop) they are never queued: always read */
        bool room = (c->nq < qmax && c->qbytes < QBYTES_MAX && q_room(s, c) && c->oot < OOT_MAX) || (c->cin == CIN_OPEN && !c->cin_end) ||
                    c->cin == CIN_DISCARD;
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
        bool terminate = false, killed = false;
        if (!take_frame(c, in->type, body, blen, &terminate, &killed)) return 1;
        if (terminate) return 2;
        if (killed) return 0; /* (a KILL's terminate: back to the loop's top, which ends the session, however fast its
                               * client still sends: never a read past it) */
    }
}

/* N1d: a COPY TO's place at the head of the replies (o): up to a frame of its ring's bytes made a COPY_OUT frame put
 * before it (1); its ring ended and sent whole, the place removed and the ring freed (1); no bytes yet (0); the ring
 * unreadable (-1: the connection ends, never a stream cut short and then a DONE) */
static int ring_take(conn *c, outbuf *o)
{
    imdbs *s = c->s;
    cring *g = o->ring;
    pthread_mutex_lock(&s->mu);
    uint64_t w = g->w, r = g->r;
    uint64_t size = g->size; /* (the engine may shrink a growing ring under mu: read with w and r) */
    bool done = g->done;
    if (w == r && done) { /* its bytes all sent: the replies after it go next */
        c->oh = o->next;
        if (!c->oh) c->ot = NULL;
        ring_free(s, c, g);
        pthread_cond_broadcast(&s->cv); /* 2b-2b: one spool fewer: a statement waiting for SPOOL_FILES may run */
        pthread_mutex_unlock(&s->mu);
        imdbw_free(o);
        return 1;
    }
    pthread_mutex_unlock(&s->mu);
    if (w == r) return 0;
    uint64_t off = r % size;
    size_t k = (size_t)(w - r);
    if (k > COPY_FRAME) k = COPY_FRAME;
    if (k > size - off) k = (size_t)(size - off);
    uint8_t *tmp = imdbw_alloc(k, 1);
    outbuf *f = tmp ? imdbw_alloc(1, sizeof *f) : NULL;
    ssize_t got = f ? imdbsp_read(g->sp, off, tmp, k) : -1; /* [r, w) is this thread's: the engine writes past w */
    imdbw_buf b;
    imdbw_buf_init(&b);
    if (g->raw && got == (ssize_t)k) { /* 2b-2a: a result's frames, as they are */
        b.p = tmp, b.len = k, tmp = NULL;
    } else if (got == (ssize_t)k) {
        imdbw_msg m;
        memset(&m, 0, sizeof m);
        m.type = IMDBW_COPY_OUT;
        m.data = tmp, m.dlen = (uint32_t)k;
        imdbw_msg_put(&b, &m, NULL);
    }
    imdbw_free(tmp);
    if (got != (ssize_t)k || b.err) {
        imdbw_buf_free(&b);
        imdbw_free(f);
        return -1;
    }
    f->p = b.p, f->len = b.len;
    pthread_mutex_lock(&s->mu);
    g->r += k;
    if (g->raw) spool_move(s, c, 0, -(int64_t)k); /* (its file keeps its bytes until given back or freed) */
    f->next = o; /* o is the head: this thread alone takes from it */
    c->oh = f;
    pend_move(s, c, (int64_t)f->len);
    pthread_cond_broadcast(&s->cv); /* room for the engine's writer */
    uint64_t from = g->freed, to = g->r & ~(uint64_t)4095; /* (whole 4 KiB blocks: a block given back in part stays allocated) */
    bool give = g->raw && !g->keep && to - from >= RELEASE_STEP;
    pthread_mutex_unlock(&s->mu);
    /* 2b-2b: a result spool's sent bytes given back once a step of them has gone, so its charge is its backlog (and a step):
     * a reader that keeps within its share streams a result of any size. [0, r) is never read again; the engine writes
     * past w; this thread alone moves r and freed, and alone frees the ring */
    if (give) {
        bool ok = imdbsp_release(g->sp, from, to - from);
        pthread_mutex_lock(&s->mu);
        if (ok) {
            g->freed = to;
            spool_move(s, c, -(int64_t)(to - from), 0);
            s->n.res_released += to - from;
            pthread_cond_broadcast(&s->cv); /* room in the spools */
        } else {
            g->keep = true; /* (its whole extent charged until it is freed: 2b-2a's rule) */
        }
        pthread_mutex_unlock(&s->mu);
    }
    return 1;
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
        if (o->ring) { /* N1d: a COPY TO's bytes go out here, as frames */
            int k = ring_take(c, o);
            if (k < 0) return -1;
            if (k == 0) return sent;
            continue;
        }
        ssize_t k = c_write(c, o->p + o->off, o->len - o->off); /* TLS: retried with these arguments (partial writes on) */
        if (k == IMDBT_WANT_READ || k == IMDBT_WANT_WRITE) {
            c->wr_wants_read = k == IMDBT_WANT_READ;
            return sent;
        }
        if (k <= 0) return -1;
        test_hold();
        sent = 1;
        o->off += (size_t)k;
        c->sent_total += (uint64_t)k;
        pthread_mutex_lock(&s->mu);
        pend_move(s, c, -(int64_t)k);
        bool whole = o->off == o->len;
        if (whole) {
            if (o->oot) c->oot -= o->len; /* N1e stage two */
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
    if (c->tal) c->tal->pending -= c->pending; /* N1e stage two: its role's tally too */
    c->oh = c->ot = NULL, c->pending = 0, c->oot = 0;
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

/* N1e stage two: Apache's lingering close. A server that closes a TCP socket while the client's bytes sit unread makes
 * the kernel answer with a reset, which discards what the server sent and the client has not yet received: the ERROR
 * saying why (a refused login's, a protocol error's) would be lost on a network with any delay. So the write side is
 * shut first (the client reads everything, then the end), and whatever the client still sends is read and dropped until
 * its own close, at most 1 s or 256 KiB, before the socket is closed */
static void linger_close(conn *c)
{
    shutdown(c->fd, SHUT_WR);
    uint64_t until = imdb_mono_ns() + 1000000000u;
    size_t got = 0;
    char buf[4096];
    for (;;) {
        uint64_t now = imdb_mono_ns();
        if (now >= until || got >= (256u << 10) || atomic_load(&c->s->stopping)) return; /* (a stop ends it: 100 ms) */
        struct pollfd pf = {c->fd, POLLIN, 0};
        uint64_t left = (until - now) / 1000000u + 1;
        int pr = poll(&pf, 1, left < 100 ? (int)left : 100);
        if (pr < 0 && errno == EINTR) continue;
        if (pr < 0) return;
        if (pr == 0) continue; /* (a slice: the stop and the second asked again) */
        ssize_t k = recv(c->fd, buf, sizeof buf, 0);
        if (k < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)) continue;
        if (k <= 0) return; /* its close (or an error): done */
        got += (size_t)k;
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
    uint8_t why = IMDBS_END_N; /* D34: the first cause this connection ends by */
#define END_BY(w) \
    do { \
        if (why == IMDBS_END_N) why = (w); \
    } while (0)
    if (authed && c->refuse) { /* N1e stage two: answered, then refused: its ERROR goes out, no request is read */
        imdbw_text t = {(const uint8_t *)c->refuse, (uint32_t)strlen(c->refuse)};
        imdbw_msg er = {.type = IMDBW_ERROR, .code = (uint32_t)-IMDB_ERR_LIMIT, .texts = &t, .ntexts = 1};
        conn_put(c, &er);
        reading = false;
        END_BY(IMDBS_END_REFUSED);
        /* no session was made, nor any request read: closed now, never waiting for the engine thread's turn (a role at
         * its cap could otherwise fill --max-conns with refused logins while a long statement runs, and lock out the
         * superuser come to KILL it) */
        pthread_mutex_lock(&s->mu);
        c->closed = true;
        pthread_mutex_unlock(&s->mu);
    }
    uint64_t stop_at = 0, progress = imdb_mono_ns();
    uint64_t mark = 0; /* 2b-2b: sent_total when progress last moved: it moves again once TRICKLE_FLOOR more are taken */
    uint64_t idle_from = imdb_mono_ns(); /* 2b-2b: when its session last had something to do */
    uint32_t pmark = 0; /* 2b-3: the frame arriving's bytes when it last moved the idle clock */
    uint64_t idle_ns = (uint64_t)s->o.role_sess_idle_ms * 1000000u;
    uint64_t kill_at = 0; /* 2b-2a: when a KILL ended it */
    bool waiting = false; /* replies waited at the last turn too */
    uint64_t send_ns = (uint64_t)(s->o.send_timeout_ms ? s->o.send_timeout_ms : 30000) * 1000000u;
    uint64_t copy_idle_ns = (uint64_t)(s->o.copy_idle_ms ? s->o.copy_idle_ms : 30000) * 1000000u;
    if (!authed) {
        pthread_mutex_lock(&s->mu);
        c->gone = c->closed = true; /* no session was made */
        pthread_mutex_unlock(&s->mu);
    }
    for (;;) {
        pthread_mutex_lock(&s->mu);
        s->n.wakeups++;
        /* out: bytes to send (N1d: a COPY TO's place at the head counts once its ring holds bytes or has ended: a slow
         * statement's empty ring is no reply waiting, so send_timeout never drops a client for the engine's pace) */
        const cring *hg = c->oh ? c->oh->ring : NULL;
        bool closed = c->closed, out = c->oh != NULL && (!hg || hg->w > hg->r || hg->done), stopping = s->stopping;
        /* its client gone and its statement still running: the cancel again (one that landed just before the statement
         * began was cleared by its start), every turn until the session's end runs */
        bool recancel = c->gone && c->running && c->ses_open && !closed;
        if (c->cin_kill) { /* N1e stage two: a KILL's cancel of the COPY whose data arrives */
            c->cin_kill = false;
            if (c->cin == CIN_OPEN && !c->cin_end && !c->cin_err) cin_cancel(s, c, " by a KILL");
        }
        bool kterm = c->kill_term;
        if (recancel) imdb_session_cancel(&c->ses);
        uint32_t qmax = s->o.queue_max ? s->o.queue_max : 64;
        bool copying = (c->cin == CIN_OPEN && !c->cin_end) || c->cin == CIN_DISCARD; /* N1d: a COPY's frames arrive */
        if (copying && out) c->cin_last = imdb_mono_ns(); /* its client still has replies to read (COPY_IN among them, or a
                                                       * ring draining): its data cannot be due yet, so the idle clock waits */
        uint64_t cin_last = c->cin_last;
        bool oot_ok = c->oot < OOT_MAX; /* N1e stage two: its out-of-turn answers drained below the bound */
        if (!oot_ok && !c->oot_held) s->n.oot_waits++;
        c->oot_held = !oot_ok;
        bool qok = c->nq < qmax && c->qbytes < QBYTES_MAX && q_room(s, c);
        bool room = (qok && oot_ok) || copying; /* N1d: a COPY's frames never queued */
        /* 2b-2b: its session has something to do: a request queued or running, a reply waiting (a PING's or another
         * out-of-turn answer not counted, so a pool's pings never keep a session), a COPY's data due */
        bool busy = c->rh || c->running || c->cin != CIN_NONE || hg || c->pending + c->spout > c->oot;
        /* 2b-3: or its reads held by its queue's bounds (its own, or its role's share: the client's request waits in the
         * socket, on the server; an unread flood of out-of-turn answers is the send timeout's, so that bound is not here) */
        if (!copying && !qok) busy = true;
        bool role_sess = !c->super && c->role;
        pthread_mutex_unlock(&s->mu);
        uint64_t now = imdb_mono_ns();
        if (copying && reading && peer && now - cin_last > copy_idle_ns) { /* N1d: its data stopped: the connection ends */
            pthread_mutex_lock(&s->mu);
            s->n.copy_idle++;
            pthread_mutex_unlock(&s->mu);
            char msg[160];
            snprintf(msg, sizeof msg, "COPY's data stopped arriving for %u ms: the connection closed (--copy-idle)",
                     (unsigned)(copy_idle_ns / 1000000u));
            imdbw_text t = {(const uint8_t *)msg, (uint32_t)strlen(msg)};
            imdbw_msg er = {.type = IMDBW_ERROR, .code = (uint32_t)-IMDB_ERR_CANCELLED, .texts = &t, .ntexts = 1};
            conn_put(c, &er);
            reading = false;
            END_BY(IMDBS_END_COPY_IDLE);
            leave(c);
        }
        /* 2b-3: a frame still arriving counts while it gains a KiB a window (or comes whole, then it is a request): one
         * header and then silence, or a byte now and then, is idle. (Its body's buffer, allocated at its header, is not
         * charged to the role's queue share: at most a frame a connection, --role-conns the role's) */
        uint32_t pgot = in.hgot + in.bgot;
        if (!in.hgot || pgot < pmark) pmark = 0; /* (a new frame) */
        else if (pgot - pmark >= 1024) idle_from = now, pmark = pgot;
        if (busy || !reading) idle_from = now;
        if (idle_ns && role_sess && reading && peer && now - idle_from > idle_ns) { /* 2b-2b: a role's session idle past
                                                                                      * --role-idle-session: as a KILL's */
            pthread_mutex_lock(&s->mu);
            s->n.idle_closed++;
            pthread_mutex_unlock(&s->mu);
            char msg[160];
            snprintf(msg, sizeof msg, "the session was idle for %u ms: closed (--role-idle-session); its transaction, if any, "
                                      "rolled back", (unsigned)(idle_ns / 1000000u));
            imdbw_text t = {(const uint8_t *)msg, (uint32_t)strlen(msg)};
            imdbw_msg er = {.type = IMDBW_ERROR, .code = (uint32_t)-IMDB_ERR_CANCELLED, .texts = &t, .ntexts = 1};
            conn_put(c, &er);
            reading = false;
            END_BY(IMDBS_END_IDLE);
            leave(c);
        }
        if (stopping && reading) {
            reading = false;
            END_BY(IMDBS_END_STOP);
        }
        if (kterm && reading) { /* N1e stage two: a KILL's terminate: as a client that leaves, then its ERROR and the close */
            reading = false;
            END_BY(IMDBS_END_KILL);
            leave(c);
            kill_at = now; /* 2b-2a: what is queued then its ERROR, while its client takes a byte every second (whole
                            * frames: a spooled result part sent is never cut), then the close (its spools freed at its end) */
            static const char km[] = "the session was ended by a KILL: its transaction, if any, rolled back";
            imdbw_text t = {(const uint8_t *)km, (uint32_t)(sizeof km - 1)};
            imdbw_msg er = {.type = IMDBW_ERROR, .code = (uint32_t)-IMDB_ERR_CANCELLED, .texts = &t, .ntexts = 1};
            conn_put(c, &er);
        }
        if (c->gone && reading) { /* the engine could not queue a reply, or the server stops: no further request */
            reading = false;
            END_BY(IMDBS_END_GONE);
            leave(c);
        }
        if (!out || !waiting) progress = now, mark = c->sent_total; /* the clock starts when replies begin to wait, never in an
                                                                      * idle sleep (a client that took them all: none wait) */
        waiting = out;
        if (kill_at && out && peer && (now - (progress > kill_at ? progress : kill_at) > 1000000000u || now - kill_at > send_ns)) {
            /* 2b-2a: a terminated one's client took nothing for 1 s (one still reading gets the rest, then its ERROR,
             * within send_timeout of the KILL: a byte a second never keeps it) */
            reading = peer = false;
            drop_out(c);
            out = false;
        }
        if (out && peer && now - progress > send_ns) { /* 2b-2b: it took fewer than TRICKLE_FLOOR bytes of its waiting replies
                                                         * in send_timeout (a byte a window kept one before): dropped, its
                                                         * statement cancelled */
            pthread_mutex_lock(&s->mu);
            s->n.dropped++;
            pthread_mutex_unlock(&s->mu);
            reading = peer = false;
            END_BY(IMDBS_END_SEND);
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
        int wait_ms = stop_at ? 50 : (out && peer) || recancel || copying ? 100 : 1000;
        if (poll(pf, 2, pend ? 0 : wait_ms) < 0 && errno != EINTR) {
            END_BY(IMDBS_END_POLL);
            break;
        }
        uint32_t hold = atomic_load_explicit(&g_wake_hold_ms, memory_order_relaxed);
        if (hold && pf[1].revents) { /* tests: this thread scheduled late after a wake, so what its client sent meanwhile is
                                       * read in the same turn (the KILL race's shape, made certain) */
            usleep(hold * 1000u);
            (void)poll(pf, 2, 0);
        }
        if (pf[1].revents) drain(c->wake[0]);
        bool can_in = pend || (want_in && (pf[0].revents & in_ev)), can_out = want_out && (pf[0].revents & out_ev);
        if (pf[1].revents && can_in) { /* a KILL's wake: its terminate goes before any frame that came with it (a PING read
                                         * in this turn was answered after the KILL_DONE: a session reported ended answering;
                                         * found 11-22 by the Java driver's rerun). The read waits for the loop's top */
            pthread_mutex_lock(&s->mu);
            if (c->kill_term) can_in = false;
            pthread_mutex_unlock(&s->mu);
        }
        if (can_in) {
            c->rd_wants_write = false;
            errno = 0;
            int r = pull(c, &in);
            if (r < 0) { /* the client left: nothing more can reach it */
                END_BY(errno == EBADF ? IMDBS_END_EBADF : IMDBS_END_LEFT);
                reading = peer = false;
                leave(c);
                drop_out(c);
            } else if (r == 1) { /* a protocol error: its ERROR goes out, then the close */
                END_BY(IMDBS_END_PROTOCOL);
                reading = false;
                leave(c);
            } else if (r == 2) { /* TERMINATE: the requests before it run, then the session's end */
                END_BY(IMDBS_END_TERMINATE);
                reading = false;
                pthread_mutex_lock(&s->mu);
                queue_close(c, false);
                pthread_mutex_unlock(&s->mu);
            }
        } else if (!can_out && (pf[0].revents & (POLLHUP | POLLERR | POLLNVAL))) { /* hung up: neither read nor written again */
            END_BY(pf[0].revents & POLLNVAL ? IMDBS_END_NVAL : IMDBS_END_HUP);
            if (reading) leave(c);
            reading = peer = false;
            drop_out(c);
        }
        if (peer && can_out) {
            c->wr_wants_read = false;
            errno = 0;
            int k = push(c);
            if (k < 0) {
                END_BY(errno == EBADF ? IMDBS_END_EBADF : IMDBS_END_LEFT);
                if (reading) leave(c);
                reading = peer = false;
                drop_out(c);
            } else if (k > 0 && c->sent_total - mark >= TRICKLE_FLOOR) { /* 2b-2b: a floor, never a byte */
                progress = imdb_mono_ns();
                mark = c->sent_total;
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
    imdbt_free(c->tls); /* a best-effort close_notify, then the session; its thread's alone (conn_free frees one never taken) */
    c->tls = NULL;
    /* N1e stage two: a connection this server ends while its client is still there (a login refused after its verdict,
     * a protocol error, a KILL, the end of COPY's data waited for): its replies all handed to the kernel, then a lingering
     * close, before the thread counts as ended (so the acceptor's reap never waits on it) */
    bool lg = peer && authed && !atomic_load(&s->stopping);
    if (lg && c->refuse) { /* 2b-2b: a refused login lingers out of the counts accept reads (its slot free at once: a role
                            * opening refused logins without pause never fills the slots), LINGER_REFUSED at most (their
                            * descriptors held until reaped); past it, closed at once */
        pthread_mutex_lock(&s->mu);
        if (s->nlinger < LINGER_REFUSED) {
            s->nlinger++, c->linger_out = true;
            s->nconns--, s->ntcp -= c->tcp;
            s->n.linger_refused++;
        } else {
            lg = false;
            s->n.linger_skipped++;
        }
        pthread_mutex_unlock(&s->mu);
    }
    if (lg) linger_close(c);
    pthread_mutex_lock(&s->mu);
    if (c->cin == CIN_OPEN && !c->cin_end) cin_drop(s, c); /* N1d: its spool still this thread's: freed at once */
    if (why == IMDBS_END_N) why = !authed ? IMDBS_END_UNAUTH : stop_at ? IMDBS_END_STOP : IMDBS_END_LEFT;
    s->n.ends[why]++; /* D34 */
#undef END_BY
    c->done = true;
    s->n.live--;
    pthread_cond_broadcast(&s->pacv);
    pthread_mutex_unlock(&s->mu);
    shutdown(c->fd, SHUT_RDWR);
    return NULL;
}

/* ---- the acceptor ---- */
static void conn_free(conn *c)
{
    pthread_mutex_lock(&c->s->mu); /* N1d: its spools (the engine is done with it: no request, none running) */
    cin_drop(c->s, c);
    while (c->rings) ring_free(c->s, c, c->rings);
    pthread_mutex_unlock(&c->s->mu);
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
        if (s->last == c) s->last = NULL;
        if (c->linger_out) s->nlinger--; /* 2b-2b: out of the counts since its linger began */
        else s->nconns--, s->ntcp -= c->tcp;
        tal_leave(c); /* N1e stage two */
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
    if (s->o.test_sndbuf) setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &s->o.test_sndbuf, sizeof s->o.test_sndbuf);
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
    c->id = ++s->next_id; /* N1e stage two */
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

static int srv_stats(void *arg, imdb_stat_fn fn, void *ctx); /* the server's rows (below, beside imdbs_counts_get) */

int imdbs_start(imdb_db *db, const imdbs_opts *o, imdbs **out, imdb_err *e)
{
    *out = NULL;
    if (db->failed) return imdb_fail(e, IMDB_ERR_STATE, "the database handle has failed: reopen it");
    imdbs *s = imdbw_alloc(1, sizeof *s);
    if (!s) return imdb_fail(e, IMDB_ERR_NOMEM, "out of memory");
    s->db = db, s->o = *o, s->lfd = -1, s->tfd = -1, s->stop[0] = s->stop[1] = -1, s->spool_dfd = -1;
    s->obj_dfd = imdbsp_subdir(db->dirfd, "objects"); /* (-1: none yet, or none to read: the others are read) */
    s->o.socket_path = s->o.tcp = s->o.server_dir = s->o.spool_dir = NULL; /* the caller's strings: used here alone */
    pthread_mutexattr_t ma; /* error-checking: a relock by its holder answers EDEADLK (srv_stats leaves its rows out), never
                             * a hang of the one engine thread */
    pthread_mutexattr_init(&ma);
    pthread_mutexattr_settype(&ma, PTHREAD_MUTEX_ERRORCHECK);
    pthread_mutex_init(&s->mu, &ma);
    pthread_mutexattr_destroy(&ma);
    imdb_stats_source(db, srv_stats, s); /* the server's counters in SHOW STATS and the export (removed at the stop) */
    pthread_mutex_init(&s->lmu, NULL);
    pthread_cond_init(&s->cv, NULL);
    pthread_cond_init(&s->pacv, NULL);
    int rc = IMDB_OK;
    if (o->spool_dir || o->server_dir) { /* N1d: COPY's spool directory (neither: COPY refused by name) */
        char path[4096];
        if (o->spool_dir) {
            if ((size_t)snprintf(path, sizeof path, "%s", o->spool_dir) >= sizeof path)
                rc = imdb_fail(e, IMDB_ERR_INVALID, "the spool directory's path is too long");
        } else if ((size_t)snprintf(path, sizeof path, "%s/spool", o->server_dir) >= sizeof path) {
            rc = imdb_fail(e, IMDB_ERR_INVALID, "the server directory's path is too long");
        }
        if (!rc) rc = imdbsp_dir(path, &s->spool_dfd, e);
    }
    s->ntal = o->max_conns ? o->max_conns : 256; /* N1e stage two: an entry for every connection's role at worst */
    if (!rc && !(s->tal = imdbw_alloc(s->ntal, sizeof *s->tal))) rc = imdb_fail(e, IMDB_ERR_NOMEM, "out of memory");
    if (!rc) rc = listen_unix(s, o->socket_path, e);
    if (!rc && o->tcp) { /* N1c: TLS 1.3 on TCP, its key and certificate from the server directory */
        if (!o->server_dir) rc = imdb_fail(e, IMDB_ERR_INVALID, "--tcp needs the server directory's certificate");
        if (!rc) rc = imdbt_server_ctx(o->server_dir, &s->tls, &s->cert_days, e);
        if (!rc && o->cb_any && !imdbt_ctx_endpoint_ok(s->tls)) /* §8f: one hash, SHA-256, for every driver */
            rc = imdb_fail(e, IMDB_ERR_INVALID, "--channel-binding any: the server's certificate is not signed with SHA-256 "
                                                "(tls-server-end-point would need another hash)");
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
    imdb_stats_source(s->db, NULL, NULL); /* (the engine thread gone: no row of a server being freed is read) */
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
    if (s->spool_dfd >= 0) close(s->spool_dfd);
    if (s->obj_dfd >= 0) close(s->obj_dfd);
    imdbt_ctx_free(s->tls);
    if (s->path[0]) unlink(s->path);
    if (s->stop[0] >= 0) close(s->stop[0]);
    if (s->stop[1] >= 0) close(s->stop[1]);
    logins_put(s, s->lg);
    imdbw_free(s->tal);
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

/* under mu: the counts and the gauges read from the server's state */
static void counts_take(const imdbs *s, imdbs_counts *c)
{
    *c = s->n;
    c->tcp_authing = c->tcp_waiting = 0;
    c->conns = s->nconns; /* D34 */
    c->lingering = s->nlinger; /* 2b-2b */
    c->spool_held = s->spool_held;
    for (conn *o = s->conns; o; o = o->next) {
        c->tcp_authing += o->tcp && o->preauth && o->authing;
        c->tcp_waiting += o->tcp && o->preauth && !o->authing;
    }
}

void imdbs_counts_get(imdbs *s, imdbs_counts *c)
{
    pthread_mutex_lock(&s->mu);
    counts_take(s, c);
    pthread_mutex_unlock(&s->mu);
}

/* the server's counters for an operator (counters-export, after 2c): SHOW STATS's rows and the --stats export beside the
 * engine's, as server.* (dotted names, units as suffixes, as the engine's), by imdb_stats_source: called on the engine
 * thread, a statement's check too (imdb_stats_tick), so the counts stay live through a long statement. Every field of
 * imdbs_counts is a row here or named left out (the static assert below: a field added fails the build until it is
 * placed); the free-space rows only with a headroom (with none they would read 0: a full disk) */
static const struct srv_row {
    const char *name;
    size_t off;
    bool headroom; /* shown only with --disk-headroom */
} k_srv_rows[] = {
#define R_(n, f) {n, offsetof(imdbs_counts, f), false}
#define RH(n, f) {n, offsetof(imdbs_counts, f), true}
    R_("server.connections.accepted", accepted), R_("server.connections.live", live),
    R_("server.connections.listed", conns), R_("server.connections.lingering", lingering),
    R_("server.logins.ok", logins), R_("server.logins.refused", refusals), R_("server.logins.role_refused", role_refused),
    R_("server.logins.endpoint_binding", logins_endpoint), R_("server.logins.binding_refused", cb_refused),
    R_("server.logins.rebuilt", logins_made), R_("server.logins.lingered", linger_refused),
    R_("server.logins.closed_unlingered", linger_skipped), R_("server.tcp.authenticating", tcp_authing),
    R_("server.tcp.waiting", tcp_waiting), R_("server.requests", requests), R_("server.requests.paused", pauses),
    R_("server.statements", statements), R_("server.cancels", cancels), R_("server.cancels.client_left", leave_cancels),
    R_("server.kills.done", kills), R_("server.kills.refused", kills_refused),
    R_("server.replies.dropped_slow", dropped), R_("server.replies.pending_peak_bytes", pend_peak),
    R_("server.queue.out_of_turn_waits", oot_waits), R_("server.queue.out_of_turn_peak_bytes", oot_peak),
    R_("server.queue.role_waits", role_queue_waits), R_("server.results.spilled", res_spilled),
    R_("server.results.spill_bytes", res_spool_bytes), R_("server.results.refused", res_refused),
    R_("server.results.released_bytes", res_released), R_("server.results.files_peak", files_peak),
    R_("server.roles.spool_limits", role_spool_limits), R_("server.roles.idle_closed", idle_closed),
    R_("server.copy.in", copy_in), R_("server.copy.out", copy_out), R_("server.copy.out_result", copy_out_res),
    R_("server.copy.limits", copy_limits), R_("server.copy.waits", copy_waits), R_("server.copy.idle_closed", copy_idle),
    R_("server.spool.held_bytes", spool_held), R_("server.disk.refused", disk_refused),
    R_("server.disk.kept_in_memory", disk_kept), RH("server.disk.data_low", disk_low_data),
    RH("server.disk.spool_low", disk_low_spool), RH("server.disk.data_free_bytes", disk_free_data),
    RH("server.disk.spool_free_bytes", disk_free_spool),
#undef R_
#undef RH
};
/* left out: wakeups, started, ticks (the tests' instruments: a loop's turns, a statement's start, the tick's count) */
enum { SRV_ROWS_LEFT_OUT = 3 };
static const char *const k_srv_ends[] = {"unauth", "refused", "left", "hup", "nval", "ebadf", "protocol", "terminate",
                                         "send", "copy_idle", "gone", "kill", "stop", "poll", "idle"};
_Static_assert(sizeof k_srv_ends / sizeof *k_srv_ends == IMDBS_END_N, "a connection's end cause without its row's name");
_Static_assert(sizeof k_srv_rows / sizeof *k_srv_rows + SRV_ROWS_LEFT_OUT + IMDBS_END_N ==
                   sizeof(imdbs_counts) / sizeof(uint64_t),
               "a field of imdbs_counts neither a row of k_srv_rows nor named left out");

static int srv_stats(void *arg, imdb_stat_fn fn, void *ctx)
{
    imdbs *s = arg;
    imdbs_counts c;
    if (pthread_mutex_lock(&s->mu)) return IMDB_OK; /* (EDEADLK: its holder re-entered: these rows left out, never a hang) */
    counts_take(s, &c);
    pthread_mutex_unlock(&s->mu);
    int rc = IMDB_OK;
    for (size_t i = 0; !rc && i < sizeof k_srv_rows / sizeof *k_srv_rows; i++) {
        if (k_srv_rows[i].headroom && !s->o.disk_headroom) continue;
        uint64_t v;
        memcpy(&v, (const char *)&c + k_srv_rows[i].off, sizeof v);
        rc = fn(ctx, k_srv_rows[i].name, v > INT64_MAX ? INT64_MAX : (int64_t)v);
    }
    char nm[64];
    for (int k = 0; !rc && k < IMDBS_END_N; k++) {
        snprintf(nm, sizeof nm, "server.connections.ended.%s", k_srv_ends[k]);
        rc = fn(ctx, nm, c.ends[k] > INT64_MAX ? INT64_MAX : (int64_t)c.ends[k]);
    }
    return rc;
}

uint16_t imdbs_tcp_port(const imdbs *s) { return s->tcp_port; }

int imdbs_cert_days(const imdbs *s) { return s->cert_days; }

uint64_t imdbs_fds_needed(const imdbs_opts *o)
{
    uint64_t maxc = o->max_conns ? o->max_conns : 256;
    return maxc * (3 + SPOOL_FILES + 1) + (uint64_t)LINGER_REFUSED * 3 + 256; /* (256: the engine's, the listeners, the stop) */
}
