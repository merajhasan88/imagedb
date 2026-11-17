/* N1c: TLS 1.3 for IMDBWIR1 over TCP (docs/n1-design.md §3, §8c), the server's and the C client's one place for OpenSSL
 * 3 (libssl, libcrypto: the user's yes of 2026-11-06): no other file of theirs includes an OpenSSL header, src/ none.
 * TLS 1.3 alone, ALPN "imdbwir1" required both ways, no session tickets, ECDSA P-256 certificates from a private CA
 * the server directory holds, channel binding by the exporter (RFC 9266), our own BIO over send(MSG_NOSIGNAL) and recv
 * (OpenSSL's socket BIO writes with write(2): a peer's close would raise SIGPIPE in a process that kept it). */
#ifndef IMDB_TLS_H
#define IMDB_TLS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#include "../src/util.h"

#define IMDBT_ALPN "imdbwir1"
#define IMDBT_WANT_READ (-1000)
#define IMDBT_WANT_WRITE (-1001)

/* imagedb-server cert SDIR [--name NAME]...: SDIR/tls/ (made whole as tls.tmp, renamed in: a crash leaves nothing or the
 * four; a crashed run's tls.tmp removed by the next): ca.key, ca.crt (a self-signed CA, 10 years), server.key and server.crt
 * (signed by it, 2 years; subjectAltName localhost, 127.0.0.1, ::1 and each name), every key 0600 (and refused at a load
 * when its group or the world may read it), each file made exclusively and synced. pin: the server key's SPKI's
 * SHA-256, what a client may pin */
int imdbt_cert_make(const char *sdir, const char *const *names, size_t nnames, uint8_t pin[32], imdb_err *e);
/* --renew: tls/server.crt made again from the same key under the same CA (a new serial and validity: the pin and ca.crt
 * still accept), the old one kept as server.crt.<its serial> first, then server.crt replaced atomically (there is always
 * one; a rerun after a crash makes the same) */
int imdbt_cert_renew(const char *sdir, uint8_t pin[32], imdb_err *e);

typedef struct imdbt_ctx imdbt_ctx;
/* the server's: SDIR/tls/server.key and server.crt (a key that is not its certificate's refused); days_left: the
 * certificate's remaining validity in whole days (negative when expired) */
int imdbt_server_ctx(const char *sdir, imdbt_ctx **out, int *days_left, imdb_err *e);
/* the client's: a CA certificate's file (the server's name or address checked against subjectAltName) or a pin (the
 * server key's SPKI SHA-256, checked before a byte of ours is sent); exactly one of the two */
int imdbt_client_ctx(const char *ca_file, const uint8_t *pin, imdbt_ctx **out, imdb_err *e);
void imdbt_ctx_free(imdbt_ctx *c);

typedef struct imdbt imdbt;
/* a session over a connected non-blocking socket; host: the name or address the client asked for (NULL: the server) */
int imdbt_new(imdbt_ctx *ctx, int fd, const char *host, imdbt **out, imdb_err *e);
/* the handshake's next step: IMDB_OK when done (ALPN, the version, the pin or the CA's verdict checked), IMDBT_WANT_READ
 * or IMDBT_WANT_WRITE to poll for, an error else */
int imdbt_handshake(imdbt *t, imdb_err *e);
/* bytes read or written (at least one), 0 when the peer closed, IMDBT_WANT_READ or IMDBT_WANT_WRITE, -1 on a failure;
 * a write that wanted is retried with the same arguments (or, with OpenSSL's partial-write mode, any) */
ssize_t imdbt_read(imdbt *t, void *p, size_t n);
ssize_t imdbt_write(imdbt *t, const void *p, size_t n);
/* bytes OpenSSL has decrypted and holds: asked before a poll, so none waits for the socket */
size_t imdbt_pending(const imdbt *t);
/* RFC 9266's tls-exporter value: 32 bytes, label "EXPORTER-Channel-Binding", no context (AuthMessage's binding) */
int imdbt_binding(imdbt *t, uint8_t out[32]);
/* a best-effort close_notify (never waited on), then the session freed; the socket is the caller's */
void imdbt_free(imdbt *t);

/* tests: a file's certificate's SPKI SHA-256 (the pin a client may use) */
int imdbt_pin_of_file(const char *crt_file, uint8_t pin[32], imdb_err *e);

#endif
