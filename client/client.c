/* N1b: the C client (imagedb_client.h; docs/n1-design.md §7). Blocking socket I/O; a reader waits in poll on its socket
 * and a wake-up pipe, so imdbc_cancel from another thread reaches it and it sends CANCEL in band (§4). */
#include "imagedb_client.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdatomic.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

struct imdbc {
    int fd, wake[2];
    _Atomic bool cancel;
    uint32_t timeout_ms; /* each wait for bytes (0: none) */
    uint8_t *body;     /* the last frame's body: the last message points into it */
    imdbw_msg last;
    uint8_t *cbody;    /* the last COLUMNS' body, kept while ROWS are read against it */
    imdbw_msg cols;
    bool has_cols;
};

static int send_all(imdbc *c, const uint8_t *p, size_t n, imdb_err *e)
{
    while (n) {
        ssize_t k = send(c->fd, p, n, MSG_NOSIGNAL);
        if (k < 0 && errno == EINTR) continue;
        if (k <= 0) return imdb_fail(e, IMDB_ERR_IO, "the connection: %s", k < 0 ? strerror(errno) : "closed");
        p += k, n -= (size_t)k;
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

/* exactly n bytes; a cancel asked meanwhile is sent at once */
static int recv_all(imdbc *c, uint8_t *p, size_t n, imdb_err *e)
{
    while (n) {
        if (atomic_exchange(&c->cancel, false) && send_cancel(c, e)) return e->code;
        struct pollfd pf[2] = {{c->fd, POLLIN, 0}, {c->wake[0], POLLIN, 0}};
        int pr = poll(pf, 2, c->timeout_ms ? (int)c->timeout_ms : -1);
        if (pr == 0) return imdb_fail(e, IMDB_ERR_IO, "no reply within %u ms", (unsigned)c->timeout_ms);
        if (pr < 0) {
            if (errno == EINTR) continue;
            return imdb_fail(e, IMDB_ERR_IO, "poll: %s", strerror(errno));
        }
        if (pf[1].revents) {
            char x[16];
            while (read(c->wake[0], x, sizeof x) > 0) {
            }
        }
        if (!(pf[0].revents & (POLLIN | POLLHUP | POLLERR))) continue;
        ssize_t k = recv(c->fd, p, n, 0);
        if (k < 0 && (errno == EINTR || errno == EAGAIN)) continue;
        if (k <= 0) return imdb_fail(e, IMDB_ERR_IO, "the connection: %s", k < 0 ? strerror(errno) : "closed by the server");
        p += k, n -= (size_t)k;
    }
    return IMDB_OK;
}

static int put_msg(imdbc *c, const imdbw_msg *m, imdb_err *e)
{
    imdbw_buf b;
    imdbw_buf_init(&b);
    imdbw_msg_put(&b, m, NULL);
    int rc = b.err ? imdb_fail(e, b.nomem ? IMDB_ERR_NOMEM : IMDB_ERR_INVALID, "a request its encoder refuses")
                   : send_all(c, b.p, b.len, e);
    imdbw_buf_free(&b);
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
    if (c->fd >= 0) close(c->fd);
    if (c->wake[0] >= 0) close(c->wake[0]);
    if (c->wake[1] >= 0) close(c->wake[1]);
    imdbw_free(c);
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
    imdbc *c = imdbw_alloc(1, sizeof *c);
    if (!c) return imdb_fail(e, IMDB_ERR_NOMEM, "out of memory");
    c->wake[0] = c->wake[1] = -1;
    c->fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (c->fd < 0 || pipe2(c->wake, O_CLOEXEC | O_NONBLOCK) || connect(c->fd, (struct sockaddr *)&sa, sizeof sa)) {
        int en = errno;
        imdbc_close(c);
        return imdb_fail(e, IMDB_ERR_IO, "connect: %s", strerror(en));
    }
    imdbw_hello h;
    memset(&h, 0, sizeof h);
    h.version = 1;
    memcpy(h.user, user, ulen);
    uint8_t hello[IMDBW_HELLO_LEN], chb[IMDBW_CHALLENGE_LEN], am[IMDBW_AUTHMSG_LEN], proof[IMDBW_KEY], want[IMDBW_KEY];
    uint8_t vb[IMDBW_VERDICT_LEN], zero[IMDBW_KEY] = {0};
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
        imdbw_auth_message(IMDBW_EP_UNIX, hello, chb, zero, am);
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
    c->last = got, c->body = body;
    *m = got;
    return IMDB_OK;
}

const imdbw_msg *imdbc_columns(const imdbc *c) { return c->has_cols ? &c->cols : NULL; }

int imdbc_fd(const imdbc *c) { return c->fd; }

void imdbc_set_timeout(imdbc *c, uint32_t ms) { c->timeout_ms = ms; }
