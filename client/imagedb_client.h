/* N1b: the C client of imagedb's protocol, IMDBWIR1 (docs/n1-design.md §4, §7), over the server's Unix-domain socket
 * (TCP with TLS: N1c). A request is sent whole (imdbc_query, _prepare, _execute, _deallocate, _ping); its replies are
 * read one message at a time (imdbc_next): COLUMNS, ROWS, DONE, ERROR, WARNING, READY, PONG, SESSIONS_LIST, KILL_DONE, as
 * strict as the server reads the client. Requests may pipeline: send several, then read each one's replies in order.
 * imdbc_cancel, from any thread, wakes a reader blocked in imdbc_next, which sends CANCEL in band. Its blocks are the
 * wire's (imdbw_alloc). */
#ifndef IMAGEDB_CLIENT_H
#define IMAGEDB_CLIENT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "../server/wire.h"

typedef struct imdbc imdbc;

typedef struct imdbc_stmt {
    const char *sql;
    size_t len;
    const imdbw_value *params; /* its $1 to $n */
    uint16_t nparams;
} imdbc_stmt;

/* the server's socket, a role's name and password (the caller's bytes: never a file this library reads); IMDB_ERR_AUTH
 * for a refusal (an unknown name and a wrong password alike), IMDB_ERR_UNSUPPORTED when the server speaks a later
 * version only */
int imdbc_connect(const char *socket_path, const char *user, const char *password, size_t pwlen, imdbc **out, imdb_err *e);
/* N1c: TCP with TLS 1.3 (ALPN imdbwir1): tls names the CA file (the host checked against the certificate's
 * subjectAltName: a name, or an address literal) or a pin (the server key's SPKI SHA-256, imagedb-server cert prints
 * it), exactly one; no unverified mode, no fallback to the socket or to plaintext. The handshake (the pin checked in it)
 * ends before the hello, which names the role, is sent; the AuthMessage binds the session's exporter (RFC 9266) */
typedef struct imdbc_tls {
    const char *ca_file;
    const uint8_t *pin; /* 32 bytes */
} imdbc_tls;
int imdbc_connect_tcp(const char *host, const char *port, const imdbc_tls *tls, const char *user, const char *password,
                      size_t pwlen, imdbc **out, imdb_err *e);
int imdbc_query(imdbc *c, const imdbc_stmt *stmts, uint32_t n, imdb_err *e);
int imdbc_prepare(imdbc *c, const char *name, const char *sql, size_t len, imdb_err *e);
/* nsets sets of nvals values, vals in set order */
int imdbc_execute(imdbc *c, const char *name, const imdbw_value *vals, uint32_t nsets, uint16_t nvals, imdb_err *e);
int imdbc_deallocate(imdbc *c, const char *name, imdb_err *e);
int imdbc_ping(imdbc *c, imdb_err *e);
/* N1e stage two: SESSIONS (a SESSIONS_LIST reply: a superuser's every session, a role's its own role's) and KILL of a
 * session by its id (IMDBW_KILL_CANCEL: the request it runs now, each of its statements; IMDBW_KILL_TERMINATE: the session
 * ended, its transaction rolled back): a KILL_DONE reply (code IMDBW_KILLED, 0; or IMDBW_KILL_NONE, 1: no such session,
 * or to a role another role's). Both answered out of turn, as PONG is: behind the replies already sent, before the rest of
 * a request running now */
int imdbc_sessions(imdbc *c, imdb_err *e);
int imdbc_kill(imdbc *c, uint8_t kind, uint64_t session, imdb_err *e);
/* N1d: after a COPY_IN reply, COPY ... FROM STDIN's data (cut into frames of at most 1 MiB), then its end, or its failure
 * (the statement refused unrun, the reason in its ERROR); a COPY TO's bytes arrive as COPY_OUT replies (imdbc_next) */
int imdbc_copy_data(imdbc *c, const void *p, size_t n, imdb_err *e);
int imdbc_copy_done(imdbc *c, imdb_err *e);
int imdbc_copy_fail(imdbc *c, const char *reason, imdb_err *e);
/* TERMINATE: the server ends the session (an open transaction rolled back) once the requests before it ran */
int imdbc_terminate(imdbc *c, imdb_err *e);
/* the statement running for this connection, cancelled: any thread (a flag and a wake-up; the reader sends CANCEL) */
void imdbc_cancel(imdbc *c);
/* the next reply, decoded (a ROWS against the last COLUMNS, which stays readable until the next COLUMNS): valid until
 * the next call; IMDB_ERR_IO when the server closed the connection */
int imdbc_next(imdbc *c, imdbw_msg *m, imdb_err *e);
/* the last COLUMNS (the one a ROWS is read against), or NULL */
const imdbw_msg *imdbc_columns(const imdbc *c);
int imdbc_fd(const imdbc *c);
/* a bound on each wait for a reply's bytes (0: none, the default): past it imdbc_next fails with IMDB_ERR_IO, the
 * connection then unusable (a frame may be part read) */
void imdbc_set_timeout(imdbc *c, uint32_t ms);
/* tests: bytes sent as they are (crafted frames, several in one TLS record), over TLS when the connection has it */
int imdbc_send_raw(imdbc *c, const void *p, size_t n, imdb_err *e);
void imdbc_close(imdbc *c);

#endif
