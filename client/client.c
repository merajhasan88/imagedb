/* N1b: the C client (imagedb_client.h; docs/n1-design.md §7). Blocking socket I/O; a reader waits in poll on its socket
 * and a wake-up pipe, so imdbc_cancel from another thread reaches it and it sends CANCEL in band (§4). */
#include "imagedb_client.h"
#include "../server/tls.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdatomic.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <unistd.h>

struct imdbc {
    int fd, wake[2];
    _Atomic bool cancel;
    imdbt_ctx *tctx;     /* N1c: TCP's TLS context and session (NULL on the Unix socket) */
    imdbt *tls;
    uint32_t timeout_ms; /* each wait for bytes (0: none) */
    uint8_t *body;     /* the last frame's body: the last message points into it */
    imdbw_msg last;
    uint8_t *cbody;    /* the last COLUMNS' body, kept while ROWS are read against it */
    imdbw_msg cols;
    bool has_cols;
    uint32_t outstanding; /* requests sent whose READY has not been read: a cancel reaches only one of them (one asked
                           * between requests would otherwise cancel the next statement: N1d's review) */
};

/* N1c: the connection's bytes over its socket or its TLS session alike (the socket non-blocking either way): >0 bytes,
 * 0 closed, -1 a failure, IMDBT_WANT_READ or IMDBT_WANT_WRITE for the poll */
static ssize_t c_read(imdbc *c, void *p, size_t n)
{
    if (c->tls) return imdbt_read(c->tls, p, n);
    ssize_t k = recv(c->fd, p, n, 0);
    if (k < 0) return errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR ? IMDBT_WANT_READ : -1;
    return k;
}

static ssize_t c_write(imdbc *c, const void *p, size_t n)
{
    if (c->tls) return imdbt_write(c->tls, p, n);
    ssize_t k = send(c->fd, p, n, MSG_NOSIGNAL);
    if (k < 0) return errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR ? IMDBT_WANT_WRITE : -1;
    return k;
}

static void drain(imdbc *c)
{
    char x[16];
    while (read(c->wake[0], x, sizeof x) > 0) {
    }
}

/* until the socket can do what a want asks (or a cancel's wake-up comes, when wake): 0, or a timeout's failure */
static int c_wait(imdbc *c, ssize_t want, bool wake, imdb_err *e)
{
    for (;;) {
        struct pollfd pf[2] = {{c->fd, (short)(want == IMDBT_WANT_WRITE ? POLLOUT : POLLIN), 0}, {c->wake[0], POLLIN, 0}};
        int pr = poll(pf, wake ? 2 : 1, c->timeout_ms ? (int)c->timeout_ms : -1);
        if (pr == 0) return imdb_fail(e, IMDB_ERR_IO, "no reply within %u ms", (unsigned)c->timeout_ms);
        if (pr < 0 && errno == EINTR) continue;
        if (pr < 0) return imdb_fail(e, IMDB_ERR_IO, "poll: %s", strerror(errno));
        if (wake && pf[1].revents) drain(c);
        return IMDB_OK;
    }
}

static int send_all(imdbc *c, const uint8_t *p, size_t n, imdb_err *e)
{
    while (n) {
        ssize_t k = c_write(c, p, n);
        if (k > 0) {
            p += k, n -= (size_t)k;
            continue;
        }
        if (k == 0 || k == -1) return imdb_fail(e, IMDB_ERR_IO, "the connection: %s", k ? "a write failed" : "closed");
        if (c_wait(c, k, false, e)) return e->code; /* TLS keeps the same arguments for the retry */
    }
    return IMDB_OK;
}

static int send_cancel(imdbc *c, imdb_err *e)
{
    imdbw_buf b;
    imdbw_buf_init(&b);
    imdbw_msg m = {.type = IMDBW_CANCEL};
    imdbw_msg_put(&b, &m, NULL);
    int rc = b.err ? imdb_fail(e, IMDB_ERR_NOMEM, "out of memory") : send_all(c, b.p, b.len, e);
    imdbw_buf_free(&b);
    return rc;
}

/* exactly n bytes; a cancel asked meanwhile is sent at once (bytes OpenSSL holds are read before any poll) */
static int recv_all(imdbc *c, uint8_t *p, size_t n, imdb_err *e)
{
    while (n) {
        if (atomic_exchange(&c->cancel, false) && c->outstanding && send_cancel(c, e)) return e->code;
        ssize_t k = c_read(c, p, n);
        if (k > 0) {
            p += k, n -= (size_t)k;
            continue;
        }
        if (k == 0 || k == -1) return imdb_fail(e, IMDB_ERR_IO, "the connection: %s", k ? "a read failed" : "closed by the server");
        if (c_wait(c, k, true, e)) return e->code;
    }
    return IMDB_OK;
}

static int put_msg(imdbc *c, const imdbw_msg *m, imdb_err *e)
{
    bool req = m->type == IMDBW_QUERY || m->type == IMDBW_PREPARE || m->type == IMDBW_EXECUTE || m->type == IMDBW_DEALLOCATE;
    if (req && !c->outstanding) atomic_store(&c->cancel, false); /* one asked while nothing ran: for nothing */
    /* one asked while this client sends (a COPY's data) goes out before the next frame: the upload is cancelled where it
     * stands (§4: the COPY refused unrun, the rest of its data dropped), never after the whole upload, when the COPY may
     * not have begun and a CANCEL reaches nothing (N1d's review) */
    else if (c->outstanding && atomic_exchange(&c->cancel, false) && send_cancel(c, e)) return e->code;
    imdbw_buf b;
    imdbw_buf_init(&b);
    imdbw_msg_put(&b, m, NULL);
    int rc = b.err ? imdb_fail(e, b.nomem ? IMDB_ERR_NOMEM : IMDB_ERR_INVALID, "a request its encoder refuses")
                   : send_all(c, b.p, b.len, e);
    imdbw_buf_free(&b);
    if (!rc && req)
        c->outstanding++; /* each answered to its READY */
    return rc;
}

static void drop_last(imdbc *c)
{
    imdbw_msg_free(&c->last);
    memset(&c->last, 0, sizeof c->last);
    imdbw_free(c->body);
    c->body = NULL;
}

void imdbc_close(imdbc *c)
{
    if (!c) return;
    drop_last(c);
    if (c->has_cols) imdbw_msg_free(&c->cols);
    imdbw_free(c->cbody);
    imdbt_free(c->tls); /* a best-effort close_notify */
    imdbt_ctx_free(c->tctx);
    if (c->fd >= 0) close(c->fd);
    if (c->wake[0] >= 0) close(c->wake[0]);
    if (c->wake[1] >= 0) close(c->wake[1]);
    imdbw_free(c);
}

/* the pre-auth exchange (§4) over the connection's endpoint: the hello, the challenge, the proof over the AuthMessage
 * (binding: the TLS exporter's 32 bytes on TCP, zeros on the socket), the verdict and the server's signature */
static int authenticate(imdbc *c, uint8_t endpoint, const uint8_t binding[IMDBW_KEY], const char *user, size_t ulen,
                        const char *pw, size_t pwlen, imdb_err *e)
{
    imdbw_hello h;
    memset(&h, 0, sizeof h);
    h.version = 1;
    memcpy(h.user, user, ulen);
    uint8_t hello[IMDBW_HELLO_LEN], chb[IMDBW_CHALLENGE_LEN], am[IMDBW_AUTHMSG_LEN], proof[IMDBW_KEY], want[IMDBW_KEY];
    uint8_t vb[IMDBW_VERDICT_LEN];
    imdbw_challenge ch;
    imdbw_verdict v;
    int rc = imdb_random(h.nonce, sizeof h.nonce, e);
    if (!rc && imdbw_hello_put(&h, hello)) rc = imdb_fail(e, IMDB_ERR_INVALID, "a hello its encoder refuses");
    if (!rc) rc = send_all(c, hello, sizeof hello, e);
    if (!rc) rc = recv_all(c, chb, IMDBW_PREAUTH_HEAD, e);
    if (!rc) {
        uint32_t version;
        if (imdbw_preauth_head(chb, &version, e)) rc = e->code;
        else if (version != 1)
            rc = imdb_fail(e, IMDB_ERR_UNSUPPORTED, "the server speaks IMDBWIR1 version %u, not 1", (unsigned)version);
    }
    if (!rc) rc = recv_all(c, chb + IMDBW_PREAUTH_HEAD, sizeof chb - IMDBW_PREAUTH_HEAD, e);
    if (!rc) rc = imdbw_challenge_get(chb, &ch, e);
    if (!rc) {
        imdbw_auth_message(endpoint, hello, chb, binding, am);
        if (imdbw_scram_client(pw, pwlen, &ch, am, proof, want))
            rc = imdb_fail(e, IMDB_ERR_INVALID, "a password is 1 to 1,024 printable ASCII bytes");
    }
    if (!rc) rc = send_all(c, proof, sizeof proof, e);
    if (!rc) rc = recv_all(c, vb, sizeof vb, e);
    if (!rc) rc = imdbw_verdict_get(vb, &v, e);
    if (!rc && (v.code || !imdb_ct_eq(v.sig, want, IMDBW_KEY)))
        rc = imdb_fail(e, IMDB_ERR_AUTH, v.code ? "authentication refused" : "the server did not prove it holds the verifier");
    imdb_wipe(proof, sizeof proof);
    imdb_wipe(want, sizeof want);
    return rc;
}

static imdbc *conn_new(int domain, imdb_err *e)
{
    imdbc *c = imdbw_alloc(1, sizeof *c);
    if (!c) {
        imdb_fail(e, IMDB_ERR_NOMEM, "out of memory");
        return NULL;
    }
    c->wake[0] = c->wake[1] = -1;
    c->fd = domain < 0 ? -1 : socket(domain, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if ((domain >= 0 && c->fd < 0) || pipe2(c->wake, O_CLOEXEC | O_NONBLOCK)) {
        imdb_fail(e, IMDB_ERR_IO, "socket: %s", strerror(errno));
        imdbc_close(c);
        return NULL;
    }
    return c;
}

/* connected: non-blocking from here (every wait a poll, a cancel's wake-up among them) */
static int nonblocking(int fd, imdb_err *e)
{
    int fl = fcntl(fd, F_GETFL);
    if (fl < 0 || fcntl(fd, F_SETFL, fl | O_NONBLOCK)) return imdb_fail(e, IMDB_ERR_IO, "fcntl: %s", strerror(errno));
    return IMDB_OK;
}

int imdbc_connect(const char *path, const char *user, const char *pw, size_t pwlen, imdbc **out, imdb_err *e)
{
    *out = NULL;
    struct sockaddr_un sa;
    memset(&sa, 0, sizeof sa);
    sa.sun_family = AF_UNIX;
    if (!path || strlen(path) >= sizeof sa.sun_path) return imdb_fail(e, IMDB_ERR_INVALID, "the socket's path is too long");
    memcpy(sa.sun_path, path, strlen(path) + 1);
    size_t ulen = user ? strlen(user) : 0;
    if (!imdbw_user_ok(user ? user : "", ulen)) return imdb_fail(e, IMDB_ERR_INVALID, "a role's name is 1 to 63 bytes of UTF-8");
    imdbc *c = conn_new(AF_UNIX, e);
    if (!c) return e->code;
    if (connect(c->fd, (struct sockaddr *)&sa, sizeof sa)) {
        int en = errno;
        imdbc_close(c);
        return imdb_fail(e, IMDB_ERR_IO, "connect: %s", strerror(en));
    }
    uint8_t zero[IMDBW_KEY] = {0};
    int rc = nonblocking(c->fd, e);
    if (!rc) rc = authenticate(c, IMDBW_EP_UNIX, zero, user, ulen, pw, pwlen, e);
    if (rc) {
        imdbc_close(c);
        return rc;
    }
    *out = c;
    return IMDB_OK;
}

int imdbc_connect_tcp(const char *host, const char *port, const imdbc_tls *tls, const char *user, const char *pw, size_t pwlen,
                      imdbc **out, imdb_err *e)
{
    *out = NULL;
    size_t ulen = user ? strlen(user) : 0;
    if (!imdbw_user_ok(user ? user : "", ulen)) return imdb_fail(e, IMDB_ERR_INVALID, "a role's name is 1 to 63 bytes of UTF-8");
    if (!host || !port || !tls) return imdb_fail(e, IMDB_ERR_INVALID, "a host, a port and TLS's CA or pin");
    struct addrinfo hints, *ai = NULL;
    memset(&hints, 0, sizeof hints);
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_NUMERICSERV;
    int g = getaddrinfo(host, port, &hints, &ai);
    if (g || !ai) return imdb_fail(e, IMDB_ERR_IO, "%s: %s", host, g ? gai_strerror(g) : "no address");
    imdbc *c = conn_new(-1, e);
    int rc = c ? IMDB_OK : e->code;
    for (struct addrinfo *a = ai; !rc && a && c->fd < 0; a = a->ai_next) { /* the first address that takes the connection */
        int fd = socket(a->ai_family, SOCK_STREAM | SOCK_CLOEXEC, 0);
        if (fd >= 0 && connect(fd, a->ai_addr, a->ai_addrlen)) close(fd), fd = -1;
        c->fd = fd;
    }
    freeaddrinfo(ai);
    if (!rc && c->fd < 0) rc = imdb_fail(e, IMDB_ERR_IO, "connect %s port %s: %s", host, port, strerror(errno));
    if (!rc) {
        int one = 1, idle = 60, intvl = 10, cnt = 6; /* small frames never wait; a server gone without a FIN found */
        setsockopt(c->fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
        setsockopt(c->fd, SOL_SOCKET, SO_KEEPALIVE, &one, sizeof one);
        setsockopt(c->fd, IPPROTO_TCP, TCP_KEEPIDLE, &idle, sizeof idle);
        setsockopt(c->fd, IPPROTO_TCP, TCP_KEEPINTVL, &intvl, sizeof intvl);
        setsockopt(c->fd, IPPROTO_TCP, TCP_KEEPCNT, &cnt, sizeof cnt);
        rc = nonblocking(c->fd, e);
    }
    if (!rc) rc = imdbt_client_ctx(tls->ca_file, tls->pin, &c->tctx, e);
    if (!rc) rc = imdbt_new(c->tctx, c->fd, host, &c->tls, e);
    uint32_t keep = c ? c->timeout_ms : 0;
    if (c && !c->timeout_ms) c->timeout_ms = 30000; /* the handshake's bound when the caller set none */
    while (!rc) { /* the handshake, the pin checked in it: before the hello (it names the role) leaves */
        int r = imdbt_handshake(c->tls, e);
        if (r == IMDB_OK) break;
        if (r != IMDBT_WANT_READ && r != IMDBT_WANT_WRITE) rc = r;
        else rc = c_wait(c, r, false, e);
    }
    if (c) c->timeout_ms = keep;
    uint8_t binding[IMDBW_KEY];
    if (!rc && imdbt_binding(c->tls, binding)) rc = imdb_fail(e, IMDB_ERR_STATE, "TLS: the exporter");
    if (!rc) rc = authenticate(c, IMDBW_EP_TCP, binding, user, ulen, pw, pwlen, e);
    if (rc) {
        imdbc_close(c);
        return rc;
    }
    *out = c;
    return IMDB_OK;
}

int imdbc_query(imdbc *c, const imdbc_stmt *st, uint32_t n, imdb_err *e)
{
    if (!n || n > IMDBW_BATCH_MAX) return imdb_fail(e, IMDB_ERR_LIMIT, "a QUERY holds 1 to %u statements", IMDBW_BATCH_MAX);
    imdbw_text *t = imdbw_alloc(n, sizeof *t);
    imdbw_span *sp = imdbw_alloc(n, sizeof *sp);
    imdbw_buf vals;
    imdbw_buf_init(&vals);
    size_t *off = imdbw_alloc(n, sizeof *off);
    int rc = t && sp && off ? IMDB_OK : imdb_fail(e, IMDB_ERR_NOMEM, "out of memory");
    for (uint32_t i = 0; !rc && i < n; i++) {
        if (st[i].len > IMDBW_SQL_MAX || st[i].nparams > IMDBW_VALUES_MAX) rc = imdb_fail(e, IMDB_ERR_LIMIT, "a statement past its bounds");
        t[i] = (imdbw_text){(const uint8_t *)st[i].sql, (uint32_t)st[i].len};
        off[i] = vals.len;
        for (uint16_t k = 0; !rc && k < st[i].nparams; k++) imdbw_value_put(&vals, &st[i].params[k]);
        sp[i].n = st[i].nparams;
        sp[i].len = vals.len - off[i];
    }
    if (!rc && vals.err) rc = imdb_fail(e, vals.nomem ? IMDB_ERR_NOMEM : IMDB_ERR_INVALID, "a parameter its encoder refuses");
    for (uint32_t i = 0; !rc && i < n; i++) sp[i].p = vals.p ? vals.p + off[i] : (const uint8_t *)"";
    if (!rc) {
        imdbw_msg m;
        memset(&m, 0, sizeof m);
        m.type = IMDBW_QUERY;
        m.texts = t, m.ntexts = n, m.params = sp;
        rc = put_msg(c, &m, e);
    }
    imdbw_buf_free(&vals);
    imdbw_free(t);
    imdbw_free(sp);
    imdbw_free(off);
    return rc;
}

static int name_ok(const char *name, imdb_err *e)
{
    size_t n = name ? strlen(name) : 0;
    if (!n || n > IMDBW_NAME_MAX) return imdb_fail(e, IMDB_ERR_INVALID, "a prepared statement's name is 1 to 63 bytes");
    return IMDB_OK;
}

int imdbc_prepare(imdbc *c, const char *name, const char *sql, size_t len, imdb_err *e)
{
    if (name_ok(name, e)) return e->code;
    imdbw_msg m;
    memset(&m, 0, sizeof m);
    m.type = IMDBW_PREPARE;
    memcpy(m.name, name, strlen(name) + 1);
    imdbw_text t = {(const uint8_t *)sql, (uint32_t)len};
    m.texts = &t, m.ntexts = 1;
    return put_msg(c, &m, e);
}

int imdbc_execute(imdbc *c, const char *name, const imdbw_value *vals, uint32_t nsets, uint16_t nvals, imdb_err *e)
{
    if (name_ok(name, e)) return e->code;
    imdbw_buf b;
    imdbw_buf_init(&b);
    for (uint64_t k = 0; k < (uint64_t)nsets * nvals; k++) imdbw_value_put(&b, &vals[k]);
    int rc = b.err ? imdb_fail(e, b.nomem ? IMDB_ERR_NOMEM : IMDB_ERR_INVALID, "a parameter its encoder refuses") : IMDB_OK;
    if (!rc) {
        imdbw_msg m;
        memset(&m, 0, sizeof m);
        m.type = IMDBW_EXECUTE;
        memcpy(m.name, name, strlen(name) + 1);
        m.nsets = nsets, m.nvals = nvals;
        m.vals = (imdbw_span){b.p ? b.p : (const uint8_t *)"", b.len, (uint32_t)((uint64_t)nsets * nvals)};
        rc = put_msg(c, &m, e);
    }
    imdbw_buf_free(&b);
    return rc;
}

int imdbc_deallocate(imdbc *c, const char *name, imdb_err *e)
{
    if (name_ok(name, e)) return e->code;
    imdbw_msg m;
    memset(&m, 0, sizeof m);
    m.type = IMDBW_DEALLOCATE;
    memcpy(m.name, name, strlen(name) + 1);
    return put_msg(c, &m, e);
}

/* N1d: COPY ... FROM STDIN's data, after its COPY_IN reply: cut into frames of at most 1 MiB */
int imdbc_copy_data(imdbc *c, const void *p, size_t n, imdb_err *e)
{
    const uint8_t *q = p;
    while (n) {
        size_t k = n < (1u << 20) ? n : (1u << 20);
        imdbw_msg m;
        memset(&m, 0, sizeof m);
        m.type = IMDBW_COPY_DATA;
        m.data = q, m.dlen = (uint32_t)k;
        if (put_msg(c, &m, e)) return e->code;
        q += k, n -= k;
    }
    return IMDB_OK;
}

int imdbc_copy_done(imdbc *c, imdb_err *e)
{
    imdbw_msg m = {.type = IMDBW_COPY_DONE};
    return put_msg(c, &m, e);
}

int imdbc_copy_fail(imdbc *c, const char *reason, imdb_err *e)
{
    imdbw_text t = {(const uint8_t *)reason, (uint32_t)strlen(reason)};
    imdbw_msg m = {.type = IMDBW_COPY_FAIL, .texts = &t, .ntexts = 1};
    return put_msg(c, &m, e);
}

int imdbc_ping(imdbc *c, imdb_err *e)
{
    imdbw_msg m = {.type = IMDBW_PING};
    return put_msg(c, &m, e);
}

int imdbc_terminate(imdbc *c, imdb_err *e)
{
    imdbw_msg m = {.type = IMDBW_TERMINATE};
    return put_msg(c, &m, e);
}

void imdbc_cancel(imdbc *c)
{
    atomic_store(&c->cancel, true);
    char x = 1;
    ssize_t k = write(c->wake[1], &x, 1); /* a full pipe already wakes the reader */
    (void)k;
}

int imdbc_next(imdbc *c, imdbw_msg *m, imdb_err *e)
{
    drop_last(c);
    memset(m, 0, sizeof *m);
    uint8_t head[IMDBW_HEAD];
    uint32_t len;
    uint8_t type;
    if (recv_all(c, head, sizeof head, e) || imdbw_head_get(head, true, &len, &type, e)) return e->code;
    uint8_t *body = imdbw_alloc(len > 1 ? len - 1 : 1, 1);
    if (!body) return imdb_fail(e, IMDB_ERR_NOMEM, "out of memory");
    if (recv_all(c, body, len - 1, e)) {
        imdbw_free(body);
        return e->code;
    }
    imdbw_msg got;
    memset(&got, 0, sizeof got);
    if (imdbw_msg_get(type, body, len - 1, c->has_cols ? &c->cols : NULL, &got, e)) {
        imdbw_free(body);
        return e->code;
    }
    if (type == IMDBW_COLUMNS) { /* kept: the ROWS after it are read against it */
        if (c->has_cols) imdbw_msg_free(&c->cols);
        imdbw_free(c->cbody);
        c->cols = got, c->cbody = body, c->has_cols = true;
        *m = got;
        return IMDB_OK;
    }
    if (type == IMDBW_READY && c->outstanding) c->outstanding--;
    c->last = got, c->body = body;
    *m = got;
    return IMDB_OK;
}

const imdbw_msg *imdbc_columns(const imdbc *c) { return c->has_cols ? &c->cols : NULL; }

int imdbc_fd(const imdbc *c) { return c->fd; }

void imdbc_set_timeout(imdbc *c, uint32_t ms) { c->timeout_ms = ms; }

int imdbc_send_raw(imdbc *c, const void *p, size_t n, imdb_err *e) { return send_all(c, p, n, e); }
