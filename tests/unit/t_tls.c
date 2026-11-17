/* N1c: TLS 1.3 on TCP (server/tls.c): a CA by name and by address, a pin; refusals (a wrong pin, another CA, an address
 * outside subjectAltName, an expired certificate); plaintext on the TLS port, no ALPN, another ALPN, TLS 1.2: refused
 * at the handshake, never answered in our framing; a relay that terminates TLS (a CA-signed man in the middle copying
 * plaintext both ways): the login fails, the proof bound to the other session's exporter; a renewal keeping the pin and
 * the CA; the unknown name's time against a wrong password's, reported. The tests' own OpenSSL clients and the
 * expired certificate are made here directly (tests/ may include OpenSSL: the suite links it as an oracle already). */
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <fcntl.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <unistd.h>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include "../../client/imagedb_client.h"
#include "../../server/srv.h"
#include "../../server/tls.h"
#include "../../src/db.h"
#include "../../src/fsio.h"
#include "../../src/sql.h"
#include "test.h"

static imdbs_opts g_extra; /* the next tstart's pre-auth limits (0: the defaults) */

typedef struct tserv {
    imdb_db *db;
    imdbs *s;
    char dir[256], sdir[300], sock[300], port[8];
    uint8_t pin[32];
} tserv;

static int sql1(imdb_db *db, const char *sql)
{
    imdb_session s;
    imdb_session_init(&s, db);
    imdb_result r;
    imdb_err e = {0};
    int rc = imdb_exec_one(&s, sql, strlen(sql), NULL, 0, &r, &e);
    imdb_result_free(&r);
    imdb_session_close(&s);
    return rc;
}

/* a database with admin, its certificate made (unless certs: already there), served on the socket and TCP addr:0 */
static bool tstart(tserv *t, const char *addr, bool certs)
{
    imdb_err e = {0};
    if (!certs) {
        snprintf(t->dir, sizeof t->dir, "%s", test_tmpdir());
        snprintf(t->sdir, sizeof t->sdir, "%s/sd", t->dir);
        if (mkdir(t->sdir, 0700) || imdbt_cert_make(t->sdir, NULL, 0, t->pin, &e)) return false;
        char dbdir[300];
        snprintf(dbdir, sizeof dbdir, "%s/db", t->dir);
        if (imdb_init(dbdir, false, NULL, &e)) return false;
    }
    char dbdir[300];
    snprintf(dbdir, sizeof dbdir, "%s/db", t->dir);
    snprintf(t->sock, sizeof t->sock, "%s/s", t->dir);
    imdb_open_opts o = {.sync = 0};
    if (imdb_open(dbdir, &o, &t->db, &e)) return false;
    if (!certs && sql1(t->db, "CREATE ROLE admin LOGIN SUPERUSER PASSWORD 'pw-admin'")) return false;
    imdbs_opts so;
    memset(&so, 0, sizeof so);
    so.socket_path = t->sock;
    char spec[64];
    snprintf(spec, sizeof spec, "%s:0", addr);
    so.tcp = spec;
    so.server_dir = t->sdir;
    so.preauth_max = g_extra.preauth_max, so.preauth_per_addr = g_extra.preauth_per_addr, so.preauth_ms = g_extra.preauth_ms;
    so.max_conns = g_extra.max_conns;
    memset(so.secret, 0x42, sizeof so.secret);
    if (imdbs_start(t->db, &so, &t->s, &e)) {
        fprintf(stderr, "    imdbs_start: %s\n", e.msg);
        imdb_close(t->db);
        return false;
    }
    snprintf(t->port, sizeof t->port, "%u", (unsigned)imdbs_tcp_port(t->s));
    return true;
}

static void tstop(tserv *t)
{
    imdb_err e = {0};
    SOFT(imdbs_stop(t->s, &e) == 0);
    imdb_close(t->db);
}

static int tlogin(const char *host, const char *port, const char *ca, const uint8_t *pin, const char *user, const char *pw,
                  imdbc **out, imdb_err *e)
{
    imdbc_tls tl = {ca, pin};
    int rc = imdbc_connect_tcp(host, port, &tl, user, pw, strlen(pw), out, e);
    if (!rc) imdbc_set_timeout(*out, 20000);
    return rc;
}

static bool select1(imdbc *c)
{
    imdbc_stmt st = {"SELECT 1", 8, NULL, 0};
    imdb_err e = {0};
    if (imdbc_query(c, &st, 1, &e)) return false;
    bool done = false;
    for (;;) {
        imdbw_msg m;
        if (imdbc_next(c, &m, &e)) return false;
        done |= m.type == IMDBW_DONE;
        if (m.type == IMDBW_READY) return done;
        if (m.type == IMDBW_ERROR) return false;
    }
}

static void t_tls_verify(void)
{
    tserv t;
    CHECK(tstart(&t, "127.0.0.1", false));
    char ca[340];
    snprintf(ca, sizeof ca, "%s/tls/ca.crt", t.sdir);
    imdb_err e = {0};
    imdbc *c = NULL;
    /* a CA by address and by name, a pin */
    SOFT(tlogin("127.0.0.1", t.port, ca, NULL, "admin", "pw-admin", &c, &e) == 0 && select1(c));
    imdbc_close(c), c = NULL;
    SOFT(tlogin("localhost", t.port, ca, NULL, "admin", "pw-admin", &c, &e) == 0 && select1(c));
    imdbc_close(c), c = NULL;
    SOFT(tlogin("127.0.0.1", t.port, NULL, t.pin, "admin", "pw-admin", &c, &e) == 0 && select1(c));
    imdbc_close(c), c = NULL;
    /* a wrong pin, another CA, neither or both: refused before the hello (the server counts no authentication) */
    imdbs_counts c0, c1;
    imdbs_counts_get(t.s, &c0);
    uint8_t bad[32];
    memcpy(bad, t.pin, 32);
    bad[7] ^= 1;
    SOFT(tlogin("127.0.0.1", t.port, NULL, bad, "admin", "pw-admin", &c, &e) == IMDB_ERR_AUTH && !c);
    char other[300], oca[340];
    snprintf(other, sizeof other, "%s/other", t.dir);
    uint8_t opin[32];
    SOFT(mkdir(other, 0700) == 0 && imdbt_cert_make(other, NULL, 0, opin, &e) == 0);
    snprintf(oca, sizeof oca, "%s/tls/ca.crt", other);
    SOFT(tlogin("127.0.0.1", t.port, oca, NULL, "admin", "pw-admin", &c, &e) == IMDB_ERR_AUTH && !c);
    SOFT(tlogin("127.0.0.1", t.port, NULL, NULL, "admin", "pw-admin", &c, &e) == IMDB_ERR_INVALID && !c);
    SOFT(tlogin("127.0.0.1", t.port, ca, t.pin, "admin", "pw-admin", &c, &e) == IMDB_ERR_INVALID && !c);
    imdbs_counts_get(t.s, &c1);
    SOFT(c1.logins == c0.logins && c1.refusals == c0.refusals); /* none reached the hello */
    /* a wrong password over TLS: the server's refusal */
    SOFT(tlogin("127.0.0.1", t.port, ca, NULL, "admin", "nope", &c, &e) == IMDB_ERR_AUTH && !c);
    tstop(&t);
    /* an address outside subjectAltName (127.0.0.2: loopback, not named) with the CA: refused; with the pin: taken */
    tserv u;
    CHECK(tstart(&u, "127.0.0.2", false));
    snprintf(ca, sizeof ca, "%s/tls/ca.crt", u.sdir);
    SOFT(tlogin("127.0.0.2", u.port, ca, NULL, "admin", "pw-admin", &c, &e) == IMDB_ERR_AUTH && !c);
    SOFT(tlogin("127.0.0.2", u.port, NULL, u.pin, "admin", "pw-admin", &c, &e) == 0 && select1(c));
    imdbc_close(c);
    tstop(&u);
}

/* a certificate past its notAfter: the server starts (a warning's days negative), a client with the CA refuses */
static void t_tls_expired(void)
{
    tserv t;
    snprintf(t.dir, sizeof t.dir, "%s", test_tmpdir());
    snprintf(t.sdir, sizeof t.sdir, "%s/sd", t.dir);
    char tdir[340];
    snprintf(tdir, sizeof tdir, "%s/tls", t.sdir);
    CHECK(mkdir(t.sdir, 0700) == 0 && mkdir(tdir, 0700) == 0);
    EVP_PKEY *k = EVP_PKEY_Q_keygen(NULL, NULL, "EC", "P-256");
    X509 *x = X509_new();
    CHECK(k && x);
    ASN1_INTEGER_set(X509_get_serialNumber(x), 7);
    X509_set_version(x, 2);
    X509_gmtime_adj(X509_getm_notBefore(x), -3 * 86400L);
    X509_gmtime_adj(X509_getm_notAfter(x), -86400L);
    X509_set_pubkey(x, k);
    X509_NAME_add_entry_by_txt(X509_get_subject_name(x), "CN", MBSTRING_ASC, (const unsigned char *)"expired", -1, -1, 0);
    X509_set_issuer_name(x, X509_get_subject_name(x));
    X509V3_CTX v;
    X509V3_set_ctx_nodb(&v);
    X509V3_set_ctx(&v, x, x, NULL, NULL, 0);
    X509_EXTENSION *san = X509V3_EXT_conf_nid(NULL, &v, NID_subject_alt_name, "IP:127.0.0.1");
    X509_add_ext(x, san, -1);
    X509_EXTENSION_free(san);
    CHECK(X509_sign(x, k, EVP_sha256()) > 0);
    char path[340];
    snprintf(path, sizeof path, "%s/tls/server.key", t.sdir);
    FILE *f = fopen(path, "w");
    CHECK(f && PEM_write_PrivateKey(f, k, NULL, NULL, 0, NULL, NULL));
    fclose(f);
    CHECK(chmod(path, 0600) == 0); /* a key readable by others is refused at a load */
    snprintf(path, sizeof path, "%s/tls/server.crt", t.sdir);
    f = fopen(path, "w");
    CHECK(f && PEM_write_X509(f, x));
    fclose(f);
    X509_free(x);
    EVP_PKEY_free(k);
    char dbdir[300];
    snprintf(dbdir, sizeof dbdir, "%s/db", t.dir);
    imdb_err e = {0};
    CHECK_OK(imdb_init(dbdir, false, NULL, &e));
    imdb_open_opts o = {.sync = 0};
    CHECK_OK(imdb_open(dbdir, &o, &t.db, &e));
    SOFT(sql1(t.db, "CREATE ROLE admin LOGIN SUPERUSER PASSWORD 'pw-admin'") == 0);
    CHECK_OK(imdb_close(t.db));
    CHECK(tstart(&t, "127.0.0.1", true));
    SOFT(imdbs_cert_days(t.s) < 0);
    imdbc *c = NULL;
    SOFT(tlogin("127.0.0.1", t.port, path, NULL, "admin", "pw-admin", &c, &e) == IMDB_ERR_AUTH && !c && strstr(e.msg, "expired"));
    tstop(&t);
}

/* a TCP connection to 127.0.0.1's port from src (NULL: any): a second address for one process is 127.0.0.2 */
static int tcp_from(const char *src, const char *port)
{
    int fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_INET;
    if (fd >= 0 && src) {
        struct sockaddr_in me;
        memset(&me, 0, sizeof me);
        me.sin_family = AF_INET;
        inet_pton(AF_INET, src, &me.sin_addr);
        if (bind(fd, (struct sockaddr *)&me, sizeof me)) close(fd), fd = -1;
    }
    sa.sin_port = htons((uint16_t)atoi(port));
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (fd >= 0 && connect(fd, (struct sockaddr *)&sa, sizeof sa)) close(fd), fd = -1;
    return fd;
}

static int tcp_to(const char *port) { return tcp_from(NULL, port); }

/* bytes the server sends within 5 s, at most cap (it closes: fewer) */
static ssize_t read_some(int fd, uint8_t *p, size_t cap)
{
    size_t got = 0;
    for (int k = 0; k < 50 && got < cap; k++) {
        struct pollfd pf = {fd, POLLIN, 0};
        if (poll(&pf, 1, 100) <= 0) continue;
        ssize_t n = recv(fd, p + got, cap - got, 0);
        if (n <= 0) break;
        got += (size_t)n;
    }
    return (ssize_t)got;
}

/* the test's own OpenSSL client: TLS max version, ALPN (NULL: none); after the handshake our hello is sent and the
 * answer's first bytes returned (a refusal: none, or the handshake failed: -1) */
static ssize_t raw_client(const char *port, int maxv, const char *alpn, const char *src, int wait_s, uint8_t *out, size_t cap)
{
    int fd = tcp_from(src, port);
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    if (fd < 0 || !ctx) return -2;
    struct timeval tv = {wait_s, 0}; /* the handshake's bound too: a server waiting to authenticate answers nothing */
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    SSL_CTX_set_max_proto_version(ctx, maxv);
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
    if (alpn) {
        unsigned char wire[32];
        wire[0] = (unsigned char)strlen(alpn);
        memcpy(wire + 1, alpn, strlen(alpn));
        SSL_CTX_set_alpn_protos(ctx, wire, 1 + (unsigned)strlen(alpn));
    }
    SSL *s = SSL_new(ctx);
    SSL_set_fd(s, fd);
    ssize_t r = -1;
    if (SSL_connect(s) == 1) {
        imdbw_hello h;
        memset(&h, 0, sizeof h);
        h.version = 1;
        memcpy(h.user, "admin", 5);
        uint8_t hb[IMDBW_HELLO_LEN];
        imdbw_hello_put(&h, hb);
        r = 0;
        if (SSL_write(s, hb, sizeof hb) > 0) {
            int n = SSL_read(s, out, (int)cap);
            r = n > 0 ? n : 0;
        }
    }
    SSL_free(s);
    SSL_CTX_free(ctx);
    close(fd);
    return r;
}

/* refused at the handshake, never answered in our framing: plaintext, no ALPN, another ALPN, TLS 1.2 */
static void t_tls_refusals(void)
{
    tserv t;
    CHECK(tstart(&t, "127.0.0.1", false));
    /* plaintext: our hello in the clear: whatever comes back is no challenge (a TLS alert at most), then the close */
    int fd = tcp_to(t.port);
    CHECK(fd >= 0);
    imdbw_hello h;
    memset(&h, 0, sizeof h);
    h.version = 1;
    memcpy(h.user, "admin", 5);
    uint8_t hb[IMDBW_HELLO_LEN], back[256];
    imdbw_hello_put(&h, hb);
    SOFT(write(fd, hb, sizeof hb) == (ssize_t)sizeof hb);
    ssize_t n = read_some(fd, back, sizeof back);
    SOFT(n < IMDBW_PREAUTH_HEAD || memcmp(back, "IMDBWIR1", 8)); /* never our framing */
    close(fd);
    uint8_t out[256];
    SOFT(raw_client(t.port, TLS1_3_VERSION, NULL, NULL, 3, out, sizeof out) <= 0);        /* no ALPN: no challenge */
    SOFT(raw_client(t.port, TLS1_3_VERSION, "http/1.1", NULL, 3, out, sizeof out) <= 0);  /* another protocol */
    SOFT(raw_client(t.port, TLS1_2_VERSION, IMDBT_ALPN, NULL, 3, out, sizeof out) == -1); /* TLS 1.2: no handshake */
    ssize_t ok = raw_client(t.port, TLS1_3_VERSION, IMDBT_ALPN, NULL, 3, out, sizeof out); /* the control: a challenge */
    SOFT(ok >= IMDBW_PREAUTH_HEAD && !memcmp(out, "IMDBWIR1", 8));
    imdbs_counts cn;
    imdbs_counts_get(t.s, &cn);
    SOFT(cn.logins == 0);
    tstop(&t);
}

/* a relay that terminates the client's TLS (the server's own certificate: a man in the middle the CA accepts) and opens
 * its own to the server, copying the plaintext both ways: the proof is bound to the client's session, the server checks
 * it against its session with the relay, so the login fails (RFC 9266's point) */
typedef struct relay {
    int lfd;
    char port[8];
    const char *sdir, *up_port;
    const uint8_t *pin;
    _Atomic bool stop;
} relay;

static int pump(imdbt *from, imdbt *to)
{
    uint8_t buf[4096];
    ssize_t n = imdbt_read(from, buf, sizeof buf);
    if (n == IMDBT_WANT_READ || n == IMDBT_WANT_WRITE) return 0;
    if (n <= 0) return -1;
    for (ssize_t put = 0; put < n;) {
        ssize_t k = imdbt_write(to, buf + put, (size_t)(n - put));
        if (k == IMDBT_WANT_READ || k == IMDBT_WANT_WRITE) {
            usleep(1000);
            continue;
        }
        if (k <= 0) return -1;
        put += k;
    }
    return 1;
}

static bool hs(imdbt *t)
{
    for (int k = 0; k < 5000; k++) {
        imdb_err e = {0};
        int r = imdbt_handshake(t, &e);
        if (r == IMDB_OK) return true;
        if (r != IMDBT_WANT_READ && r != IMDBT_WANT_WRITE) return false;
        usleep(1000);
    }
    return false;
}

static void *relay_main(void *arg)
{
    relay *r = arg;
    int cfd = accept4(r->lfd, NULL, NULL, SOCK_CLOEXEC | SOCK_NONBLOCK);
    int ufd = tcp_to(r->up_port);
    imdbt_ctx *sctx = NULL, *cctx = NULL;
    imdbt *down = NULL, *up = NULL;
    imdb_err e = {0};
    int dummy;
    if (cfd >= 0 && ufd >= 0 && !fcntl(ufd, F_SETFL, O_NONBLOCK) && !imdbt_server_ctx(r->sdir, &sctx, &dummy, &e) &&
        !imdbt_client_ctx(NULL, r->pin, &cctx, &e) && !imdbt_new(sctx, cfd, NULL, &down, &e) &&
        !imdbt_new(cctx, ufd, "127.0.0.1", &up, &e) && hs(down) && hs(up)) {
        while (!atomic_load(&r->stop)) {
            struct pollfd pf[2] = {{cfd, POLLIN, 0}, {ufd, POLLIN, 0}};
            if (!imdbt_pending(down) && !imdbt_pending(up)) poll(pf, 2, 50);
            if (pump(down, up) < 0 || pump(up, down) < 0) break;
        }
    }
    imdbt_free(down), imdbt_free(up);
    imdbt_ctx_free(sctx), imdbt_ctx_free(cctx);
    if (cfd >= 0) close(cfd);
    if (ufd >= 0) close(ufd);
    return NULL;
}

static void t_tls_relay(void)
{
    tserv t;
    CHECK(tstart(&t, "127.0.0.1", false));
    relay r;
    memset(&r, 0, sizeof r);
    r.sdir = t.sdir, r.up_port = t.port, r.pin = t.pin;
    r.lfd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    socklen_t sl = sizeof sa;
    CHECK(r.lfd >= 0 && !bind(r.lfd, (struct sockaddr *)&sa, sizeof sa) && !listen(r.lfd, 4) &&
          !getsockname(r.lfd, (struct sockaddr *)&sa, &sl));
    snprintf(r.port, sizeof r.port, "%u", (unsigned)ntohs(sa.sin_port));
    pthread_t th;
    CHECK(pthread_create(&th, NULL, relay_main, &r) == 0);
    char ca[340];
    snprintf(ca, sizeof ca, "%s/tls/ca.crt", t.sdir);
    imdb_err e = {0};
    imdbc *c = NULL;
    imdbs_counts c0, c1;
    imdbs_counts_get(t.s, &c0);
    int rc = tlogin("127.0.0.1", r.port, ca, NULL, "admin", "pw-admin", &c, &e); /* the client trusts the relay's TLS */
    SOFT(rc == IMDB_ERR_AUTH && !c);
    if (rc != IMDB_ERR_AUTH) fprintf(stderr, "    through the relay: %d %s\n", rc, e.msg);
    imdbc_close(c);
    for (int w = 0; w < 1000; w++) { /* counted by the connection's thread after its verdict is sent: waited for */
        imdbs_counts_get(t.s, &c1);
        if (c1.refusals == c0.refusals + 1) break;
        usleep(10000);
    }
    SOFT(c1.refusals == c0.refusals + 1 && c1.logins == c0.logins); /* the server refused the relayed proof */
    atomic_store(&r.stop, true);
    pthread_join(th, NULL);
    close(r.lfd);
    tstop(&t);
}

/* a renewal: the same key under the same CA, so the old pin and the old ca.crt both accept after a restart */
static void t_tls_renew(void)
{
    tserv t;
    CHECK(tstart(&t, "127.0.0.1", false));
    char ca[340], crt[340];
    snprintf(ca, sizeof ca, "%s/tls/ca.crt", t.sdir);
    snprintf(crt, sizeof crt, "%s/tls/server.crt", t.sdir);
    uint8_t before[32], after[32], pin2[32];
    imdb_err e = {0};
    SOFT(imdbt_pin_of_file(crt, before, &e) == 0 && !memcmp(before, t.pin, 32));
    tstop(&t);
    SOFT(imdbt_cert_renew(t.sdir, pin2, &e) == 0 && !memcmp(pin2, t.pin, 32));
    SOFT(imdbt_pin_of_file(crt, after, &e) == 0 && !memcmp(after, before, 32));
    CHECK(tstart(&t, "127.0.0.1", true));
    imdbc *c = NULL;
    SOFT(tlogin("127.0.0.1", t.port, ca, NULL, "admin", "pw-admin", &c, &e) == 0 && select1(c));
    imdbc_close(c), c = NULL;
    SOFT(tlogin("127.0.0.1", t.port, NULL, t.pin, "admin", "pw-admin", &c, &e) == 0 && select1(c));
    imdbc_close(c);
    tstop(&t);
}

/* an unknown name's refusal against a wrong password's, timed over the socket: reported, never asserted (the same code
 * on both paths, the HMAC made on both; a machine under load says nothing about either) */
static int cmp_u64(const void *a, const void *b)
{
    uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;
    return x < y ? -1 : x > y;
}

static void t_tls_timing(void)
{
    tserv t;
    CHECK(tstart(&t, "127.0.0.1", false));
    enum { N = 60 };
    uint64_t un[N], wp[N];
    for (int k = 0; k < N; k++) {
        imdbc *c = NULL;
        imdb_err e = {0};
        uint64_t t0 = imdb_mono_ns();
        SOFT(imdbc_connect(t.sock, "nobody", "pw", 2, &c, &e) == IMDB_ERR_AUTH);
        un[k] = imdb_mono_ns() - t0;
        t0 = imdb_mono_ns();
        SOFT(imdbc_connect(t.sock, "admin", "wrong", 5, &c, &e) == IMDB_ERR_AUTH);
        wp[k] = imdb_mono_ns() - t0;
    }
    qsort(un, N, sizeof *un, cmp_u64);
    qsort(wp, N, sizeof *wp, cmp_u64);
    fprintf(stderr, "    refusals over the socket, median of %d: an unknown name %.2f ms, a wrong password %.2f ms\n", N,
            (double)un[N / 2] / 1e6, (double)wp[N / 2] / 1e6);
    tstop(&t);
}


/* a peer gone while the server writes to it: a client asks for megabytes of rows and closes at once; the server's
 * sends then meet a reset, which our BIO takes as an error (send with MSG_NOSIGNAL), never a SIGPIPE that would end
 * this process; the connection ends as any leave's */
static void t_tls_peer_gone(void)
{
    tserv t;
    snprintf(t.dir, sizeof t.dir, "%s", test_tmpdir());
    snprintf(t.sdir, sizeof t.sdir, "%s/sd", t.dir);
    imdb_err e = {0};
    CHECK(mkdir(t.sdir, 0700) == 0 && imdbt_cert_make(t.sdir, NULL, 0, t.pin, &e) == 0);
    char dbdir[300];
    snprintf(dbdir, sizeof dbdir, "%s/db", t.dir);
    CHECK_OK(imdb_init(dbdir, false, NULL, &e));
    imdb_open_opts o = {.sync = 0};
    CHECK_OK(imdb_open(dbdir, &o, &t.db, &e));
    CHECK(sql1(t.db, "CREATE ROLE admin LOGIN SUPERUSER PASSWORD 'pw-admin'") == 0);
    snprintf(t.sock, sizeof t.sock, "%s/s", t.dir);
    imdbs_opts so;
    memset(&so, 0, sizeof so);
    /* queue_max 1: with requests pipelined, reading pauses while the rows go out, so the reset is met by a write */
    so.socket_path = t.sock, so.tcp = "127.0.0.1:0", so.server_dir = t.sdir, so.queue_max = 1;
    CHECK_OK(imdbs_start(t.db, &so, &t.s, &e));
    snprintf(t.port, sizeof t.port, "%u", (unsigned)imdbs_tcp_port(t.s));
    for (int round = 0; round < 3; round++) {
        imdbc *c = NULL;
        SOFT(tlogin("127.0.0.1", t.port, NULL, t.pin, "admin", "pw-admin", &c, &e) == 0);
        if (!c) break;
        static const char many[] = "WITH RECURSIVE r (n) AS (SELECT 1 UNION ALL SELECT n + 1 FROM r WHERE n < 200000) SELECT n FROM r";
        imdbc_stmt st = {many, sizeof many - 1, NULL, 0};
        for (int k = 0; k < 3; k++) SOFT(imdbc_query(c, &st, 1, &e) == 0);
        /* closed at once, cleanly, before a row arrives: a FIN the paused server does not read (CLOSE_WAIT), so its
         * first write draws a reset and its second an EPIPE: a SIGPIPE but for MSG_NOSIGNAL */
        imdbc_close(c);
    }
    imdbs_counts cn;
    for (int k = 0; k < 6000; k++) { /* every connection's end (60 s at most: a sanitizer's pace) */
        imdbs_counts_get(t.s, &cn);
        if (!cn.live) break;
        usleep(10000);
    }
    SOFT(cn.live == 0);
    tstop(&t);
}

/* frames OpenSSL decrypted and holds while reading is paused for a full queue (queue_max 2): read once there is room,
 * without a byte more on the socket (a poll alone would wait for ever) */
static void t_tls_pending(void)
{
    tserv t;
    snprintf(t.dir, sizeof t.dir, "%s", test_tmpdir());
    snprintf(t.sdir, sizeof t.sdir, "%s/sd", t.dir);
    imdb_err e = {0};
    CHECK(mkdir(t.sdir, 0700) == 0 && imdbt_cert_make(t.sdir, NULL, 0, t.pin, &e) == 0);
    char dbdir[300];
    snprintf(dbdir, sizeof dbdir, "%s/db", t.dir);
    CHECK_OK(imdb_init(dbdir, false, NULL, &e));
    imdb_open_opts o = {.sync = 0};
    CHECK_OK(imdb_open(dbdir, &o, &t.db, &e));
    CHECK(sql1(t.db, "CREATE ROLE admin LOGIN SUPERUSER PASSWORD 'pw-admin'") == 0);
    snprintf(t.sock, sizeof t.sock, "%s/s", t.dir);
    imdbs_opts so;
    memset(&so, 0, sizeof so);
    so.socket_path = t.sock, so.tcp = "127.0.0.1:0", so.server_dir = t.sdir, so.queue_max = 2;
    CHECK_OK(imdbs_start(t.db, &so, &t.s, &e));
    snprintf(t.port, sizeof t.port, "%u", (unsigned)imdbs_tcp_port(t.s));
    imdbc *c = NULL;
    CHECK(tlogin("127.0.0.1", t.port, NULL, t.pin, "admin", "pw-admin", &c, &e) == 0);
    enum { N = 20 };
    imdbw_buf b;
    imdbw_buf_init(&b);
    imdbw_text txt = {(const uint8_t *)"SELECT 5", 8};
    imdbw_span none = {(const uint8_t *)"", 0, 0};
    imdbw_msg q;
    memset(&q, 0, sizeof q);
    q.type = IMDBW_QUERY, q.texts = &txt, q.ntexts = 1, q.params = &none;
    for (int k = 0; k < N; k++) imdbw_msg_put(&b, &q, NULL);
    SOFT(!b.err && imdbc_send_raw(c, b.p, b.len, &e) == 0); /* one write: one TLS record holding all twenty */
    imdbw_buf_free(&b);
    int ready = 0;
    for (int k = 0; k < 10 * N && ready < N; k++) {
        imdbw_msg m;
        if (imdbc_next(c, &m, &e)) break; /* 20 s at most: the read timeout */
        ready += m.type == IMDBW_READY;
    }
    SOFT(ready == N);
    imdbc_close(c);
    tstop(&t);
}

/* the certificate tool under a failure at each of its file system calls in turn (the fault hooks: a failed call, whose
 * cleanup runs, not a crash, which would skip it: a crash leaves tls.tmp or a *.tmp, which the next run removes): `cert`
 * leaves no tls/ (a rerun makes the four) or the four whole (a server loads them);
 * `--renew` always leaves a server.crt a server loads, and a rerun renews with the pin unchanged */
static long g_fail_at, g_calls;
static long fail_nth(imdb_io_call *c, void *ctx)
{
    (void)ctx;
    if (c->op == IMDB_IO_ALLOC) return 0;
    if (++g_calls == g_fail_at) {
        errno = EIO;
        return -1;
    }
    return 0;
}

static void t_tls_cert_crash(void)
{
    static const imdb_io_hooks h = {fail_nth, NULL, NULL};
    const char *dir = test_tmpdir();
    imdb_err e = {0};
    uint8_t pin[32], pin2[32];
    char sdir[300];
    /* each tool's calls counted in a run with no failure, then each failed in turn */
    snprintf(sdir, sizeof sdir, "%s/count", dir);
    CHECK(mkdir(sdir, 0700) == 0);
    g_calls = 0, g_fail_at = 0;
    imdb_io_set_hooks(&h);
    int rc = imdbt_cert_make(sdir, NULL, 0, pin, &e);
    long make_calls = g_calls;
    g_calls = 0;
    rc = rc ? rc : imdbt_cert_renew(sdir, pin2, &e);
    long renew_calls = g_calls;
    imdb_io_set_hooks(NULL);
    CHECK(rc == 0 && make_calls >= 10 && renew_calls >= 6);
    for (long k = 1; k <= make_calls; k++) {
        snprintf(sdir, sizeof sdir, "%s/m%ld", dir, k);
        CHECK(mkdir(sdir, 0700) == 0);
        g_calls = 0, g_fail_at = k;
        imdb_io_set_hooks(&h);
        rc = imdbt_cert_make(sdir, NULL, 0, pin, &e);
        imdb_io_set_hooks(NULL);
        imdbt_ctx *ctx = NULL;
        int days;
        char tls[340];
        snprintf(tls, sizeof tls, "%s/tls", sdir);
        struct stat st;
        bool there = stat(tls, &st) == 0, whole = !imdbt_server_ctx(sdir, &ctx, &days, &e);
        imdbt_ctx_free(ctx);
        if (there) SOFT(whole); /* tls/ is the four, whole */
        else SOFT(rc && imdbt_cert_make(sdir, NULL, 0, pin, &e) == 0); /* none: a rerun makes them */
    }
    snprintf(sdir, sizeof sdir, "%s/r", dir);
    CHECK(mkdir(sdir, 0700) == 0 && imdbt_cert_make(sdir, NULL, 0, pin, &e) == 0);
    for (long k = 1; k <= renew_calls; k++) {
        g_calls = 0, g_fail_at = k;
        imdb_io_set_hooks(&h);
        rc = imdbt_cert_renew(sdir, pin2, &e);
        imdb_io_set_hooks(NULL);
        imdbt_ctx *ctx = NULL;
        int days;
        SOFT(!imdbt_server_ctx(sdir, &ctx, &days, &e)); /* always a server.crt a server loads */
        imdbt_ctx_free(ctx);
        SOFT(imdbt_cert_renew(sdir, pin2, &e) == 0 && !memcmp(pin2, pin, 32)); /* a rerun: the same key, the same pin */
    }
    fprintf(stderr, "    cert: %ld calls failed in turn, --renew: %ld\n", make_calls, renew_calls);
}

/* admission from the network never starves the socket, and one address never holds every slot: with preauth_max 2 and
 * preauth_per_addr 1, two stalled TCP connections (one from 127.0.0.1, one from 127.0.0.2) fill TCP's pool, yet a
 * socket login is answered at once (its own pool); with one freed, a TLS client from 127.0.0.1 waits (its address's
 * one slot held) while one from 127.0.0.2 gets its challenge; the stall's end lets the first in */
static bool sock_challenge(const char *sock)
{
    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    struct sockaddr_un sa;
    memset(&sa, 0, sizeof sa);
    sa.sun_family = AF_UNIX;
    memcpy(sa.sun_path, sock, strlen(sock) + 1);
    if (fd < 0 || connect(fd, (struct sockaddr *)&sa, sizeof sa)) {
        if (fd >= 0) close(fd);
        return false;
    }
    imdbw_hello h;
    memset(&h, 0, sizeof h);
    h.version = 1;
    memcpy(h.user, "admin", 5);
    uint8_t hb[IMDBW_HELLO_LEN], cb[IMDBW_CHALLENGE_LEN];
    imdbw_hello_put(&h, hb);
    struct timeval tv = {3, 0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    bool ok = write(fd, hb, sizeof hb) == (ssize_t)sizeof hb && recv(fd, cb, sizeof cb, MSG_WAITALL) == (ssize_t)sizeof cb &&
              !memcmp(cb, "IMDBWIR1", 8);
    close(fd);
    return ok;
}

/* until the server's gauges say so (10 s at most): TCP connections authenticating, and waiting for a slot */
static bool wait_gauges(imdbs *s, uint64_t authing, uint64_t waiting)
{
    for (int k = 0; k < 1000; k++) {
        imdbs_counts cn;
        imdbs_counts_get(s, &cn);
        if (cn.tcp_authing == authing && cn.tcp_waiting == waiting) return true;
        usleep(10000);
    }
    return false;
}

static void t_tls_admission(void)
{
    tserv t;
    memset(&g_extra, 0, sizeof g_extra);
    g_extra.preauth_max = 2, g_extra.preauth_per_addr = 1, g_extra.preauth_ms = 8000;
    bool up = tstart(&t, "127.0.0.1", false);
    memset(&g_extra, 0, sizeof g_extra);
    CHECK(up);
    int a = tcp_from("127.0.0.1", t.port); /* stalled: no handshake */
    SOFT(a >= 0 && wait_gauges(t.s, 1, 0)); /* .1's one slot taken by it, before anything else connects */
    int b = tcp_from("127.0.0.2", t.port);
    SOFT(b >= 0 && wait_gauges(t.s, 2, 0)); /* TCP's pool full */
    uint64_t t0 = imdb_mono_ns();
    SOFT(sock_challenge(t.sock)); /* the socket's own pool: answered at once */
    SOFT((imdb_mono_ns() - t0) / 1000000u < 3000);
    close(b);
    SOFT(wait_gauges(t.s, 1, 0)); /* one slot free in TCP's pool */
    uint8_t out[256];
    SOFT(raw_client(t.port, TLS1_3_VERSION, IMDBT_ALPN, "127.0.0.1", 2, out, sizeof out) == -1); /* waits: .1's slot held */
    ssize_t two = raw_client(t.port, TLS1_3_VERSION, IMDBT_ALPN, "127.0.0.2", 3, out, sizeof out); /* another address */
    SOFT(two >= IMDBW_PREAUTH_HEAD && !memcmp(out, "IMDBWIR1", 8));
    close(a); /* the stall ends: 127.0.0.1 is let in */
    SOFT(wait_gauges(t.s, 0, 0));
    ssize_t one = raw_client(t.port, TLS1_3_VERSION, IMDBT_ALPN, "127.0.0.1", 3, out, sizeof out);
    SOFT(one >= IMDBW_PREAUTH_HEAD && !memcmp(out, "IMDBWIR1", 8));
    tstop(&t);
}

/* the bound on one address's connections before authentication (a quarter of max_conns: 4 at 16): four stalled from
 * 127.0.0.1 (one authenticating, three waiting), a fifth closed unread; one from 127.0.0.2 let in */
static void t_tls_admission_bound(void)
{
    tserv t;
    memset(&g_extra, 0, sizeof g_extra);
    g_extra.preauth_per_addr = 1, g_extra.preauth_ms = 8000, g_extra.max_conns = 16;
    bool up = tstart(&t, "127.0.0.1", false);
    memset(&g_extra, 0, sizeof g_extra);
    CHECK(up);
    int st[4];
    for (int k = 0; k < 4; k++) st[k] = tcp_from("127.0.0.1", t.port);
    SOFT(wait_gauges(t.s, 1, 3));
    int fifth = tcp_from("127.0.0.1", t.port);
    uint8_t b[16];
    SOFT(fifth >= 0 && read_some(fifth, b, sizeof b) == 0); /* closed unread: nothing, then the end */
    imdbs_counts cn;
    imdbs_counts_get(t.s, &cn);
    SOFT(cn.tcp_authing == 1 && cn.tcp_waiting == 3);
    uint8_t out[256];
    ssize_t two = raw_client(t.port, TLS1_3_VERSION, IMDBT_ALPN, "127.0.0.2", 3, out, sizeof out);
    SOFT(two >= IMDBW_PREAUTH_HEAD && !memcmp(out, "IMDBWIR1", 8));
    for (int k = 0; k < 4; k++) close(st[k]);
    if (fifth >= 0) close(fifth);
    tstop(&t);
}
const test_case tls_tests[] = {
    {"tls_verify", t_tls_verify},     {"tls_expired", t_tls_expired}, {"tls_refusals", t_tls_refusals},
    {"tls_relay", t_tls_relay},       {"tls_renew", t_tls_renew},     {"tls_timing", t_tls_timing},
    {"tls_peer_gone", t_tls_peer_gone}, {"tls_pending", t_tls_pending}, {"tls_cert_crash", t_tls_cert_crash},
    {"tls_admission", t_tls_admission},
    {"tls_admission_bound", t_tls_admission_bound},
};
const size_t tls_ntests = sizeof tls_tests / sizeof *tls_tests;
