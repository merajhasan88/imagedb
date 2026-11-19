/* N1b: imagedb's server on a Unix-domain socket (docs/n1-design.md §5): one engine thread owns the database and every
 * session and runs requests (a QUERY's statements, an EXECUTE's sets) in order, at a statement's boundary able to pause
 * for others; a thread per connection authenticates it (SCRAM-SHA-256 over IMDBWIR1, §4) against the logins the engine
 * thread publishes, decodes its frames into requests and sends the replies the engine thread encoded (conv.c). Results
 * never cross threads: the engine thread encodes and frees each one, so the heap's counter and a statement's ceiling
 * (process-wide) see only the engine's own blocks, and the wire's allocator holds the frames. TCP with TLS is N1c. */
#ifndef IMDB_SRV_H
#define IMDB_SRV_H

#include <stdbool.h>
#include <stdint.h>

#include "../src/db.h"
#include "wire.h"

typedef struct imdbs_opts {
    const char *socket_path;   /* the Unix socket, made 0600 (its directory is the operator's: 0700); one in use refused */
    uint8_t secret[IMDBW_KEY]; /* an unknown name's salt (§3): the server directory's secret, made once and kept, so the
                                * salt never changes between attempts */
    uint32_t max_conns;        /* connections at once (0: 256); one past it is closed unread */
    uint32_t preauth_max;      /* connections authenticating at once (0: 32); the rest wait in the listen queue */
    uint32_t preauth_ms;       /* the whole exchange's budget (0: 10,000) */
    uint32_t slice_ms;         /* a session in a transaction runs on this long while others wait (0: 10) */
    uint64_t conn_cap;         /* a connection's replies waiting to be sent before its next statement waits (0: 32 MiB) */
    uint32_t queue_max;        /* a connection's requests queued before its socket is read again (0: 64) */
    uint32_t tick_ms;          /* the engine thread's idle tick: transaction timeouts, maintenance (0: 100) */
    uint32_t send_timeout_ms;  /* a connection that takes no byte this long while replies wait is dropped (0: 30,000) */
    /* N1c: TCP with TLS 1.3 beside the socket: tcp "ADDR:PORT" (an IPv6 address in brackets; port 0: an ephemeral one,
     * imdbs_tcp_port says which), NULL for none; server_dir holds server.key and server.crt (imagedb-server cert) */
    const char *tcp;
    const char *server_dir;
    uint32_t preauth_per_addr; /* TCP connections authenticating at once from one address (0: 8); twice it may wait */
    uint32_t socket_reserve;   /* connections TCP leaves to the socket (0: 16, at most half max_conns); the socket's
                                * pre-auth pool is its own (preauth_max each), so the network never starves it */
    /* N1d: COPY through the server (docs/n1-design.md §8d): spooled, so the engine thread never waits on a client's
     * network. spool_dir (NULL: server_dir's spool/; neither: COPY refused by name) holds the nameless spool files;
     * copy_spool bounds every spool's bytes held at once (0: 4 GiB): a COPY FROM whose data passes it fails at once
     * (LIMIT), the rest of its data read and dropped; copy_ring bounds one COPY TO's output held before its client takes
     * it (0: 256 MiB): past it the engine thread waits for room, at most copy_wait_ms in all for one COPY TO (0: 60,000)
     * before it fails (LIMIT); copy_idle_ms: a COPY's data arriving at none for this long ends the connection (0: 30,000) */
    const char *spool_dir;
    uint64_t copy_spool;
    uint64_t copy_ring;
    uint32_t copy_wait_ms;
    uint32_t copy_idle_ms;
    bool cb_any;               /* §8f: --channel-binding any: tls-server-end-point taken beside the exporter (the default:
                                * the exporter alone); a certificate not signed with SHA-256 then refused at the start */
    /* N1e stage two: a role's caps (docs/n1-design.md §8e), applied to a session while its role is not a superuser (db.h
     * imdb_caps): its statement and transaction timeouts and its idle-in-transaction bound (0: the default, 60 s, 10 min and
     * 60 s; IMDBS_NONE: none), the rows a statement tests (0: none) and a session's prepared statements' bytes (0: 64 MiB over
     * --role-conns: 2 MiB at its default, at least 64 KiB) */
    uint32_t role_stmt_ms, role_txn_ms, role_idle_ms;
    uint64_t role_row_limit, role_prep_bytes;
    /* N1e stage two: a role's authenticated connections at once (0: 32; IMDBS_NONE: max_conns), and the connection
     * slots no role but a superuser takes (0: 4, PostgreSQL's superuser_reserved_connections; IMDBS_NONE: none): a login
     * past either is answered (its proof was right), then an ERROR and the close */
    uint32_t role_conns, su_reserve;
    /* N1e stage two: one role's queued requests' bytes, past which its connections' sockets are not read (0: 64 MiB), and
     * its unsent replies' bytes, past which none of its statements starts (0: 64 MiB); IMDBS_NONE: none; a superuser's
     * exempt. A role's statement starts only while the server's unsent replies are under its own bound too */
    uint64_t role_queue_bytes, role_reply_bytes;
    /* N1e stage two, 2b-2a: one role's spooled bytes at once (its COPY FROM spools, COPY TO rings and results spooled past
     * their connection's room together; 0: a quarter of copy_spool; IMDBS_NONE: none; a superuser's exempt) */
    uint64_t role_copy_spool;
    uint64_t reply_budget;     /* every connection's unsent replies, past which only a connection (a role) with none runs (0:
                                * 256 MiB) */
    bool test_open_logins;     /* tests alone: any LOGIN role logs in (N1e stage two's last slice opens them) */
    bool test_no_spill;        /* tests alone (2b-2a's measure): every result's frames to memory, as before the spool */
    uint32_t test_sndbuf;      /* tests alone: each accepted socket's SO_SNDBUF (0: the kernel's), so a reply's bytes past a few
                                * KiB stay the server's (a client's lag made exact) */
} imdbs_opts;

#define IMDBS_NONE UINT32_MAX /* an imdbs_opts bound that defaults when 0: none */

typedef struct imdbs imdbs;

/* serves db, opened by the caller and from here until imdbs_stop returns the engine thread's alone: the socket bound,
 * the logins made, the threads started */
int imdbs_start(imdb_db *db, const imdbs_opts *o, imdbs **out, imdb_err *e);
/* no new connection; a running statement ends (a statement's own end: CANCEL is the client's); queued requests
 * dropped; every session closed (an open transaction rolled back); every thread joined; the socket removed; then db is
 * the caller's again. IMDB_ERR_IO when the handle failed while serving (db->failed: the caller's reopen decides) */
int imdbs_stop(imdbs *s, imdb_err *e);
/* the stop in two steps (a signal's): imdbs_stop_begin returns at once (no new connection or request; the running
 * statement ends at its own end), imdbs_stop_ready says the engine thread has closed every session, so imdbs_stop then
 * returns at once; imdbs_cancel_all cancels every running statement (a second signal's) */
void imdbs_stop_begin(imdbs *s);
bool imdbs_stop_ready(imdbs *s);
void imdbs_cancel_all(imdbs *s);
/* the handle failed (a failed sync): every request since answered with an error; the owner stops the server and exits
 * non-zero for its supervisor to restart it */
bool imdbs_failed(imdbs *s);
/* blocks until the handle fails or imdbs_stop is called elsewhere, or ms pass (0: forever); true when it failed */
bool imdbs_wait_failed(imdbs *s, uint32_t ms);

/* D34: why a connection's thread ended (imdbs_counts.ends): never authenticated, its login refused, its client left
 * (EOF or a failed read or write), hung up (POLLHUP, POLLERR), its descriptor not open (POLLNVAL: closed by another),
 * EBADF on a read or write, a protocol error, TERMINATE, send_timeout, copy_idle, the engine gone, a KILL, the stop, a
 * failed poll */
enum { IMDBS_END_UNAUTH, IMDBS_END_REFUSED, IMDBS_END_LEFT, IMDBS_END_HUP, IMDBS_END_NVAL, IMDBS_END_EBADF, IMDBS_END_PROTOCOL,
       IMDBS_END_TERMINATE, IMDBS_END_SEND, IMDBS_END_COPY_IDLE, IMDBS_END_GONE, IMDBS_END_KILL, IMDBS_END_STOP,
       IMDBS_END_POLL, IMDBS_END_N };
typedef struct imdbs_counts {
    uint64_t accepted;     /* connections taken */
    uint64_t logins;       /* authentications accepted */
    uint64_t refusals;     /* authentications refused (an unknown name, a wrong password: one path) */
    uint64_t requests;     /* requests run to their end */
    uint64_t statements;   /* statements and parameter sets run */
    uint64_t cancels;      /* CANCELs that reached a running statement */
    uint64_t live;         /* connections open now */
    uint64_t logins_made;  /* times the logins were made (the start, then each role change) */
    uint64_t pauses;       /* requests paused at a statement's boundary (resumed later where they stopped) */
    uint64_t wakeups;      /* connection threads' turns of their loop (a spin shows here) */
    uint64_t dropped;      /* connections dropped for taking no byte past send_timeout_ms */
    uint64_t leave_cancels; /* statements cancelled because their client left */
    uint64_t started;      /* statements and parameter sets begun, bumped just before each runs: a test reads it before it
                            * sends and waits for it to move (never a clock, never a gauge a late clear makes stale) */
    uint64_t tcp_authing;  /* N1c gauges: TCP connections authenticating now (holding a slot of their address and pool) */
    uint64_t tcp_waiting;  /* and those waiting for one */
    uint64_t copy_in;      /* N1d: COPY ... FROM STDIN statements run from their spool */
    uint64_t copy_out;     /* COPY ... TO STDOUT statements that wrote output to their ring */
    uint64_t copy_limits;  /* COPYs failed by a bound (copy_spool, copy_wait_ms) */
    uint64_t copy_waits;   /* times the engine thread waited for a COPY TO's ring to have room */
    uint64_t copy_idle;    /* connections ended for a COPY's data arriving at none past copy_idle_ms */
    uint64_t spool_held;   /* gauge: every spool's bytes held now */
    uint64_t ticks;        /* the engine thread's ticks run (timeouts, maintenance): on their clock under any load */
    uint64_t logins_endpoint; /* §8f: logins bound by tls-server-end-point (--channel-binding any), in logins too */
    uint64_t role_refused; /* N1e stage two: logins past --role-conns or into the superusers' reserve (in logins too) */
    uint64_t role_queue_waits; /* N1e stage two: a connection's reads held by its role's queue share (once a hold) */
    uint64_t cb_refused;   /* §8f: hellos whose binding type this server refuses (none on TCP, end-point by default, any on
                            * the socket), in refusals too */
    uint64_t kills;        /* N1e stage two: KILLs taken (KILL_DONE code 0) */
    uint64_t kills_refused; /* and refused (code 1: no such session, or to a role another role's) */
    uint64_t oot_waits;    /* N1e stage two: a connection's reads paused for its out-of-turn answers unsent (once a pause) */
    uint64_t oot_peak;     /* and the most of them any connection held unsent (OOT_MAX and one frame at most) */
    uint64_t res_spilled;  /* 2b-2a: results whose frames went to a spool past their connection's room */
    uint64_t res_spool_bytes; /* and those frames' bytes */
    uint64_t res_refused;  /* reads refused for want of room for their reply (the spools full, a role's share, no spool) */
    uint64_t role_spool_limits; /* COPYs and results stopped by a role's spool share (--role-copy-spool) */
    uint64_t pend_peak;    /* the most unsent replies in memory at once, every connection's (the budget and a chunk a connection) */
    uint64_t conns;        /* D34: gauge: connections in the server's list (nconns, the count the reserve reads) */
    uint64_t ends[IMDBS_END_N]; /* D34: connection threads ended, by cause (IMDBS_END_*): which way a connection left */
} imdbs_counts;
void imdbs_counts_get(imdbs *s, imdbs_counts *c);
/* N1c: the TCP port listened on (0: none), an ephemeral one's number; cert_days: server.crt's whole days left */
uint16_t imdbs_tcp_port(const imdbs *s);
int imdbs_cert_days(const imdbs *s);
/* N1d, tests: each COPY TO write of a statement but its first waits ms first (0: none): output that comes slowly */
void imdbs_test_copy_hold(uint32_t ms);

#endif
