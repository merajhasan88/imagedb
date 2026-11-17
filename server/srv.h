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
} imdbs_opts;

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
} imdbs_counts;
void imdbs_counts_get(imdbs *s, imdbs_counts *c);
/* N1c: the TCP port listened on (0: none), an ephemeral one's number; cert_days: server.crt's whole days left */
uint16_t imdbs_tcp_port(const imdbs *s);
int imdbs_cert_days(const imdbs *s);

#endif
