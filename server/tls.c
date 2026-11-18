/* N1c: TLS 1.3 for IMDBWIR1 (tls.h): the certificate tool, the server's and the client's contexts, a session's steps,
 * the exporter. The only file of the server and the client that includes an OpenSSL header. Files in the server
 * directory go through the engine's fsio helpers (an operator's directory: imdb_open_parent's rules). */
#include "tls.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include "../src/fsio.h"
#include "wire.h"
#include "../src/sha256.h"

struct imdbt_ctx {
    SSL_CTX *ssl;
    bool client, pinned;
    uint8_t pin[32];
};

struct imdbt {
    SSL *ssl;
    imdbt_ctx *ctx;
    int fd;
};

#define CA_DAYS 3650
#define SERVER_DAYS 730
#define PEM_MAX (64u << 10) /* a key's or a certificate's file: far past either */

/* OpenSSL's reason, for a message (never a value of a row: a library's text) */
static int ssl_fail(imdb_err *e, int code, const char *what)
{
    unsigned long err = ERR_get_error();
    char buf[200];
    if (err) ERR_error_string_n(err, buf, sizeof buf);
    else snprintf(buf, sizeof buf, "no reason given");
    ERR_clear_error();
    return imdb_fail(e, code, "%s: %s", what, buf);
}

/* ---- our BIO: send(MSG_NOSIGNAL) and recv over the session's socket ---- */
static int bio_write(BIO *b, const char *p, int n)
{
    int fd = (int)(intptr_t)BIO_get_data(b);
    BIO_clear_retry_flags(b);
    ssize_t k = send(fd, p, (size_t)n, MSG_NOSIGNAL);
    if (k < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)) BIO_set_retry_write(b);
    return (int)k;
}

static int bio_read(BIO *b, char *p, int n)
{
    int fd = (int)(intptr_t)BIO_get_data(b);
    BIO_clear_retry_flags(b);
    ssize_t k = recv(fd, p, (size_t)n, 0);
    if (k < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)) BIO_set_retry_read(b);
    return (int)k;
}

static long bio_ctrl(BIO *b, int cmd, long num, void *ptr)
{
    (void)b, (void)num, (void)ptr;
    return cmd == BIO_CTRL_FLUSH ? 1 : 0;
}

static int bio_create(BIO *b)
{
    BIO_set_init(b, 1);
    return 1;
}

static BIO_METHOD *g_bio;
static pthread_once_t g_bio_once = PTHREAD_ONCE_INIT;
static void bio_method_make(void)
{
    BIO_METHOD *m = BIO_meth_new(BIO_get_new_index() | BIO_TYPE_SOURCE_SINK, "imagedb socket");
    if (m && BIO_meth_set_write(m, bio_write) && BIO_meth_set_read(m, bio_read) && BIO_meth_set_ctrl(m, bio_ctrl) &&
        BIO_meth_set_create(m, bio_create))
        g_bio = m;
    else if (m)
        BIO_meth_free(m);
}

/* ---- files in the server directory: SDIR/tls/ (ca.key, ca.crt, server.key, server.crt), made whole as tls.tmp and
 * renamed in, so a crash leaves either nothing or the four; a renewal replaces server.crt atomically ---- */
/* a file's bytes, the one it opened (fstat on its descriptor, never a second lookup by name): a regular file of at most
 * PEM_MAX bytes, a key's refused when its group or the world may read it (the operator's chmod 600) */
static int read_pem(const char *path, bool secret, uint8_t **buf, size_t *len, imdb_err *e)
{
    *buf = NULL, *len = 0;
    const char *base;
    int dfd = imdb_open_parent(path, &base, e);
    if (dfd < 0) return e->code;
    int fd = imdb_io_openat(dfd, base, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    close(dfd);
    if (fd < 0) return imdb_fail(e, errno == ENOENT ? IMDB_ERR_NOTFOUND : IMDB_ERR_IO, "%s: %s", base, strerror(errno));
    struct stat st;
    int rc = IMDB_OK;
    if (imdb_io_fstat(fd, &st) || !S_ISREG(st.st_mode) || st.st_size <= 0 || (uint64_t)st.st_size > PEM_MAX)
        rc = imdb_fail(e, IMDB_ERR_STATE, "%s: not a certificate's or a key's file", base);
    else if (secret && (st.st_mode & 077))
        rc = imdb_fail(e, IMDB_ERR_STATE, "%s: readable by its group or the world (chmod 600)", base);
    if (!rc && !(*buf = imdb_alloc((size_t)st.st_size, e))) rc = e->code;
    size_t got = 0;
    if (!rc) rc = imdb_read_all(fd, *buf, (size_t)st.st_size, &got, e);
    if (!rc && got != (size_t)st.st_size) rc = imdb_fail(e, IMDB_ERR_IO, "%s: read short", base);
    close(fd);
    if (rc) {
        imdb_free(*buf);
        *buf = NULL;
        return rc;
    }
    *len = got;
    return IMDB_OK;
}

/* a PEM's bytes made exclusively in dfd (mode), the file synced */
static int write_new(int dfd, const char *name, BIO *mem, int mode, imdb_err *e)
{
    char *p = NULL;
    long n = BIO_get_mem_data(mem, &p);
    return n > 0 ? imdb_create_file_excl(dfd, name, p, (size_t)n, mode, e) : imdb_fail(e, IMDB_ERR_STATE, "%s: empty", name);
}

static EVP_PKEY *key_of(const uint8_t *p, size_t n)
{
    BIO *b = BIO_new_mem_buf(p, (int)n);
    EVP_PKEY *k = b ? PEM_read_bio_PrivateKey(b, NULL, NULL, NULL) : NULL;
    BIO_free(b);
    return k;
}

static X509 *crt_of(const uint8_t *p, size_t n)
{
    BIO *b = BIO_new_mem_buf(p, (int)n);
    X509 *x = b ? PEM_read_bio_X509(b, NULL, NULL, NULL) : NULL;
    BIO_free(b);
    return x;
}

static int load_key(const char *sdir, const char *name, EVP_PKEY **k, imdb_err *e)
{
    char path[4096];
    snprintf(path, sizeof path, "%s/tls/%s", sdir, name);
    uint8_t *p;
    size_t n;
    if (read_pem(path, true, &p, &n, e)) return e->code;
    *k = key_of(p, n);
    imdb_wipe(p, n);
    imdb_free(p);
    return *k ? IMDB_OK : ssl_fail(e, IMDB_ERR_CORRUPT, name);
}

static int load_crt(const char *path, X509 **x, imdb_err *e)
{
    uint8_t *p;
    size_t n;
    if (read_pem(path, false, &p, &n, e)) return e->code;
    *x = crt_of(p, n);
    imdb_free(p);
    return *x ? IMDB_OK : ssl_fail(e, IMDB_ERR_CORRUPT, path);
}

/* the SPKI's SHA-256: what a client pins */
static int spki_pin(X509 *x, uint8_t pin[32])
{
    unsigned char *der = NULL;
    int n = i2d_X509_PUBKEY(X509_get_X509_PUBKEY(x), &der);
    if (n <= 0) return -1;
    imdb_sha256(der, (size_t)n, pin);
    OPENSSL_free(der);
    return 0;
}

/* ---- the certificate tool ---- */
static bool add_ext(X509 *x, X509 *issuer, int nid, const char *value)
{
    X509V3_CTX v;
    X509V3_set_ctx_nodb(&v);
    X509V3_set_ctx(&v, issuer, x, NULL, NULL, 0);
    X509_EXTENSION *ex = X509V3_EXT_conf_nid(NULL, &v, nid, value);
    bool ok = ex && X509_add_ext(x, ex, -1);
    X509_EXTENSION_free(ex);
    return ok;
}

/* a certificate for key, signed by signer (itself when issuer is NULL): a random 128-bit serial, from an hour ago */
static X509 *crt_make(EVP_PKEY *key, const char *cn, X509 *issuer, EVP_PKEY *signer, int days, bool ca, const char *san,
                      X509_EXTENSION *san_ext)
{
    X509 *x = X509_new();
    uint8_t ser[16];
    BIGNUM *bn = NULL;
    bool ok = x && RAND_bytes(ser, sizeof ser) == 1;
    if (ok) ser[0] &= 0x7f, ser[0] |= 0x01; /* positive, never short */
    ok = ok && (bn = BN_bin2bn(ser, sizeof ser, NULL)) && BN_to_ASN1_INTEGER(bn, X509_get_serialNumber(x)) &&
         X509_set_version(x, 2) && X509_gmtime_adj(X509_getm_notBefore(x), -3600) &&
         X509_gmtime_adj(X509_getm_notAfter(x), (long)days * 86400L) && X509_set_pubkey(x, key) &&
         X509_NAME_add_entry_by_txt(X509_get_subject_name(x), "CN", MBSTRING_ASC, (const unsigned char *)cn, -1, -1, 0) &&
         X509_set_issuer_name(x, issuer ? X509_get_subject_name(issuer) : X509_get_subject_name(x));
    X509 *is = issuer ? issuer : x;
    if (ok && ca)
        ok = add_ext(x, is, NID_basic_constraints, "critical,CA:TRUE") && add_ext(x, is, NID_key_usage, "critical,keyCertSign,cRLSign") &&
             add_ext(x, is, NID_subject_key_identifier, "hash");
    if (ok && !ca)
        ok = add_ext(x, is, NID_basic_constraints, "critical,CA:FALSE") && add_ext(x, is, NID_key_usage, "critical,digitalSignature") &&
             add_ext(x, is, NID_ext_key_usage, "serverAuth") &&
             (san_ext ? X509_add_ext(x, san_ext, -1) == 1 : add_ext(x, is, NID_subject_alt_name, san)) &&
             add_ext(x, is, NID_authority_key_identifier, "keyid");
    ok = ok && X509_sign(x, signer, EVP_sha256()) > 0;
    BN_free(bn);
    if (!ok) {
        X509_free(x);
        return NULL;
    }
    return x;
}

static bool name_ok(const char *n)
{
    size_t l = strlen(n);
    if (!l || l > 253) return false;
    for (size_t i = 0; i < l; i++) {
        char c = n[i];
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '.' || c == ':'))
            return false;
    }
    return true;
}

static int pem_key(EVP_PKEY *k, BIO **out)
{
    *out = BIO_new(BIO_s_mem());
    return *out && PEM_write_bio_PrivateKey(*out, k, NULL, NULL, 0, NULL, NULL) ? 0 : -1;
}

static int pem_crt(X509 *x, BIO **out)
{
    *out = BIO_new(BIO_s_mem());
    return *out && PEM_write_bio_X509(*out, x) ? 0 : -1;
}

/* SDIR, opened as tls/'s parent */
static int open_sdir(const char *sdir, int *dfd, imdb_err *e)
{
    char path[4096];
    if ((size_t)snprintf(path, sizeof path, "%s/tls", sdir) >= sizeof path) return imdb_fail(e, IMDB_ERR_INVALID, "path too long");
    const char *base;
    *dfd = imdb_open_parent(path, &base, e); /* the operator's directory: reached through a symlink if they chose */
    return *dfd < 0 ? e->code : IMDB_OK;
}

static const char *const k_files[] = {"ca.key", "server.key", "ca.crt", "server.crt"};

int imdbt_cert_make(const char *sdir, const char *const *names, size_t nnames, uint8_t pin[32], imdb_err *e)
{
    char san[4096];
    size_t n = (size_t)snprintf(san, sizeof san, "DNS:localhost,IP:127.0.0.1,IP:::1");
    for (size_t i = 0; i < nnames; i++) {
        if (!name_ok(names[i])) return imdb_fail(e, IMDB_ERR_INVALID, "--name: a host name or an address");
        struct in6_addr a6;
        struct in_addr a4;
        bool ip = inet_pton(AF_INET, names[i], &a4) == 1 || inet_pton(AF_INET6, names[i], &a6) == 1;
        n += (size_t)snprintf(san + n, sizeof san - n, ",%s:%s", ip ? "IP" : "DNS", names[i]);
        if (n >= sizeof san) return imdb_fail(e, IMDB_ERR_LIMIT, "too many names");
    }
    int dfd, tfd = -1;
    if (open_sdir(sdir, &dfd, e)) return e->code;
    struct stat st;
    if (imdb_io_fstatat(dfd, "tls", &st, AT_SYMLINK_NOFOLLOW) && errno != ENOENT) {
        close(dfd);
        return imdb_fail(e, IMDB_ERR_IO, "%s/tls: %s", sdir, strerror(errno));
    }
    if (!imdb_io_fstatat(dfd, "tls", &st, AT_SYMLINK_NOFOLLOW)) {
        close(dfd);
        return imdb_fail(e, IMDB_ERR_STATE, "%s/tls exists: its certificates are made (--renew renews server.crt)", sdir);
    }
    /* a crashed run's tls.tmp: ours alone, removed (its files, then itself) */
    int tmp_st = imdb_io_fstatat(dfd, "tls.tmp", &st, AT_SYMLINK_NOFOLLOW);
    if (tmp_st && errno != ENOENT) {
        close(dfd);
        return imdb_fail(e, IMDB_ERR_IO, "%s/tls.tmp: %s", sdir, strerror(errno));
    }
    if (!tmp_st) {
        int old = imdb_open_dir_at(dfd, "tls.tmp", e);
        if (old < 0) {
            close(dfd);
            return e->code;
        }
        for (size_t i = 0; i < 4; i++) imdb_io_unlinkat(old, k_files[i], 0);
        close(old);
        if (imdb_io_unlinkat(dfd, "tls.tmp", AT_REMOVEDIR)) {
            close(dfd);
            return imdb_fail(e, IMDB_ERR_IO, "%s/tls.tmp: not ours to remove (%s)", sdir, strerror(errno));
        }
    }
    EVP_PKEY *cak = EVP_PKEY_Q_keygen(NULL, NULL, "EC", "P-256"), *sk = EVP_PKEY_Q_keygen(NULL, NULL, "EC", "P-256");
    X509 *ca = cak ? crt_make(cak, "imagedb private CA", NULL, cak, CA_DAYS, true, NULL, NULL) : NULL;
    X509 *sc = ca && sk ? crt_make(sk, "imagedb server", ca, cak, SERVER_DAYS, false, san, NULL) : NULL;
    BIO *b[4] = {NULL, NULL, NULL, NULL};
    int rc = sc ? IMDB_OK : ssl_fail(e, IMDB_ERR_STATE, "making the certificates");
    if (!rc && (pem_key(cak, &b[0]) || pem_key(sk, &b[1]) || pem_crt(ca, &b[2]) || pem_crt(sc, &b[3])))
        rc = ssl_fail(e, IMDB_ERR_NOMEM, "encoding the certificates");
    if (!rc && imdb_io_mkdirat(dfd, "tls.tmp", 0700)) rc = imdb_fail(e, IMDB_ERR_IO, "%s/tls.tmp: %s", sdir, strerror(errno));
    if (!rc && (tfd = imdb_open_dir_at(dfd, "tls.tmp", e)) < 0) rc = e->code;
    for (size_t i = 0; !rc && i < 4; i++) rc = write_new(tfd, k_files[i], b[i], i < 2 ? 0600 : 0644, e);
    if (!rc) rc = imdb_sync_dir(tfd, e);
    /* the four whole, then in place by one rename: a crash leaves tls.tmp (removed by the next run) or tls/ */
    if (!rc && imdb_io_renameat(dfd, "tls.tmp", dfd, "tls")) rc = imdb_fail(e, IMDB_ERR_IO, "%s/tls: %s", sdir, strerror(errno));
    if (!rc) rc = imdb_sync_dir(dfd, e);
    if (!rc && spki_pin(sc, pin)) rc = ssl_fail(e, IMDB_ERR_STATE, "the pin");
    for (size_t i = 0; i < 4; i++) BIO_free(b[i]);
    X509_free(ca), X509_free(sc);
    EVP_PKEY_free(cak), EVP_PKEY_free(sk);
    if (tfd >= 0) close(tfd);
    close(dfd);
    return rc;
}

int imdbt_cert_renew(const char *sdir, uint8_t pin[32], imdb_err *e)
{
    char path[4096];
    EVP_PKEY *cak = NULL, *sk = NULL;
    X509 *ca = NULL, *old = NULL, *sc = NULL;
    BIO *b = NULL, *ob = NULL;
    int dfd = -1, tfd = -1;
    int rc = load_key(sdir, "ca.key", &cak, e);
    if (!rc) rc = load_key(sdir, "server.key", &sk, e);
    if (!rc) snprintf(path, sizeof path, "%s/tls/ca.crt", sdir), rc = load_crt(path, &ca, e);
    if (!rc) snprintf(path, sizeof path, "%s/tls/server.crt", sdir), rc = load_crt(path, &old, e);
    if (!rc && (X509_check_private_key(ca, cak) != 1 || X509_check_private_key(old, sk) != 1))
        rc = imdb_fail(e, IMDB_ERR_CORRUPT, "the server directory's keys are not its certificates'");
    if (!rc) { /* the old certificate's subjectAltName, the extension itself */
        int i = X509_get_ext_by_NID(old, NID_subject_alt_name, -1);
        X509_EXTENSION *ex = i >= 0 ? X509_get_ext(old, i) : NULL;
        sc = ex ? crt_make(sk, "imagedb server", ca, cak, SERVER_DAYS, false, NULL, ex) : NULL;
        if (!sc || pem_crt(sc, &b) || pem_crt(old, &ob)) rc = ssl_fail(e, IMDB_ERR_STATE, "renewing the certificate");
    }
    if (!rc && !open_sdir(sdir, &dfd, e) && (tfd = imdb_open_dir_at(dfd, "tls", e)) < 0) rc = e->code;
    if (!rc && dfd < 0) rc = e->code;
    if (!rc) { /* the old one kept under its serial first (made again the same by a rerun after a crash), then server.crt
                * replaced atomically (written aside, synced, renamed, the directory synced): there is always one */
        BIGNUM *bn = ASN1_INTEGER_to_BN(X509_get_serialNumber(old), NULL);
        char *hex = bn ? BN_bn2hex(bn) : NULL;
        BN_free(bn);
        char kept[200];
        snprintf(kept, sizeof kept, "server.crt.%s", hex ? hex : "old");
        OPENSSL_free(hex);
        char *p = NULL;
        long n = BIO_get_mem_data(ob, &p);
        uint8_t *was = NULL;
        size_t wl = 0;
        imdb_err e2 = {0};
        if (!imdb_read_file_at(tfd, kept, &was, &wl, PEM_MAX, &e2)) { /* a rerun's: the same bytes, or another's file */
            if (wl != (size_t)n || memcmp(was, p, wl)) rc = imdb_fail(e, IMDB_ERR_STATE, "%s: another certificate's file", kept);
            imdb_free(was);
        } else {
            rc = imdb_write_file_renamed(tfd, kept, p, (size_t)n, 0644, e); /* written aside, renamed in: never part made */
        }
        if (!rc) rc = imdb_sync_dir(tfd, e);
        n = BIO_get_mem_data(b, &p);
        if (!rc) rc = imdb_write_file_atomic(tfd, "server.crt", p, (size_t)n, 0644, e);
    }
    if (!rc && spki_pin(sc, pin)) rc = ssl_fail(e, IMDB_ERR_STATE, "the pin");
    BIO_free(b), BIO_free(ob);
    X509_free(ca), X509_free(old), X509_free(sc);
    EVP_PKEY_free(cak), EVP_PKEY_free(sk);
    if (tfd >= 0) close(tfd);
    if (dfd >= 0) close(dfd);
    return rc;
}

int imdbt_pin_of_file(const char *crt_file, uint8_t pin[32], imdb_err *e)
{
    X509 *x = NULL;
    if (load_crt(crt_file, &x, e)) return e->code;
    int rc = spki_pin(x, pin) ? ssl_fail(e, IMDB_ERR_STATE, "the pin") : IMDB_OK;
    X509_free(x);
    return rc;
}

/* ---- contexts ---- */
static int alpn_select(SSL *s, const unsigned char **out, unsigned char *outlen, const unsigned char *in, unsigned int inlen, void *arg)
{
    (void)s, (void)arg;
    static const unsigned char ours[] = "\x08" IMDBT_ALPN;
    unsigned char *sel = NULL;
    if (SSL_select_next_proto(&sel, outlen, ours, sizeof ours - 1, in, inlen) != OPENSSL_NPN_NEGOTIATED)
        return SSL_TLSEXT_ERR_ALERT_FATAL; /* a client of another protocol: refused at the handshake */
    *out = sel;
    return SSL_TLSEXT_ERR_OK;
}

static SSL_CTX *ctx_base(bool server)
{
    SSL_CTX *c = SSL_CTX_new(server ? TLS_server_method() : TLS_client_method());
    if (!c) return NULL;
    if (!SSL_CTX_set_min_proto_version(c, TLS1_3_VERSION) || !SSL_CTX_set_max_proto_version(c, TLS1_3_VERSION)) {
        SSL_CTX_free(c);
        return NULL;
    }
    SSL_CTX_set_options(c, SSL_OP_NO_TICKET);
    SSL_CTX_set_num_tickets(c, 0); /* no resumption: nothing to keep or protect between sessions */
    SSL_CTX_set_mode(c, SSL_MODE_ENABLE_PARTIAL_WRITE | SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);
    return c;
}

int imdbt_server_ctx(const char *sdir, imdbt_ctx **out, int *days_left, imdb_err *e)
{
    *out = NULL;
    pthread_once(&g_bio_once, bio_method_make);
    if (!g_bio) return imdb_fail(e, IMDB_ERR_NOMEM, "the socket BIO");
    char path[4096];
    EVP_PKEY *k = NULL;
    X509 *x = NULL;
    int rc = load_key(sdir, "server.key", &k, e);
    if (!rc) snprintf(path, sizeof path, "%s/tls/server.crt", sdir), rc = load_crt(path, &x, e);
    imdbt_ctx *c = rc ? NULL : imdbw_alloc(1, sizeof *c);
    if (!rc && !c) rc = imdb_fail(e, IMDB_ERR_NOMEM, "out of memory");
    if (!rc && !(c->ssl = ctx_base(true))) rc = ssl_fail(e, IMDB_ERR_STATE, "the TLS context");
    if (!rc && (SSL_CTX_use_certificate(c->ssl, x) != 1 || SSL_CTX_use_PrivateKey(c->ssl, k) != 1 ||
                SSL_CTX_check_private_key(c->ssl) != 1))
        rc = ssl_fail(e, IMDB_ERR_CORRUPT, "server.key is not server.crt's");
    if (!rc) {
        SSL_CTX_set_alpn_select_cb(c->ssl, alpn_select, NULL);
        SSL_CTX_set_verify(c->ssl, SSL_VERIFY_NONE, NULL); /* SCRAM authenticates the client */
        int day = 0, sec = 0;
        ASN1_TIME_diff(&day, &sec, NULL, X509_get0_notAfter(x));
        *days_left = day;
    }
    X509_free(x);
    EVP_PKEY_free(k);
    if (rc) {
        imdbt_ctx_free(c);
        return rc;
    }
    *out = c;
    return IMDB_OK;
}

int imdbt_client_ctx(const char *ca_file, const uint8_t *pin, imdbt_ctx **out, imdb_err *e)
{
    *out = NULL;
    if (!ca_file == !pin) return imdb_fail(e, IMDB_ERR_INVALID, "TLS: a CA file or a pin, exactly one (no unverified mode)");
    pthread_once(&g_bio_once, bio_method_make);
    if (!g_bio) return imdb_fail(e, IMDB_ERR_NOMEM, "the socket BIO");
    imdbt_ctx *c = imdbw_alloc(1, sizeof *c);
    if (!c) return imdb_fail(e, IMDB_ERR_NOMEM, "out of memory");
    c->client = true;
    int rc = (c->ssl = ctx_base(false)) ? IMDB_OK : ssl_fail(e, IMDB_ERR_STATE, "the TLS context");
    static const unsigned char alpn[] = "\x08" IMDBT_ALPN;
    if (!rc && SSL_CTX_set_alpn_protos(c->ssl, alpn, sizeof alpn - 1)) rc = ssl_fail(e, IMDB_ERR_STATE, "ALPN");
    if (!rc && ca_file) {
        X509 *ca = NULL;
        rc = load_crt(ca_file, &ca, e);
        if (!rc && X509_STORE_add_cert(SSL_CTX_get_cert_store(c->ssl), ca) != 1) rc = ssl_fail(e, IMDB_ERR_STATE, "the CA");
        X509_free(ca);
        if (!rc) SSL_CTX_set_verify(c->ssl, SSL_VERIFY_PEER, NULL);
    } else if (!rc) { /* pinned: the chain is not asked for; the key is, before any byte of ours leaves */
        c->pinned = true;
        memcpy(c->pin, pin, 32);
        SSL_CTX_set_verify(c->ssl, SSL_VERIFY_NONE, NULL);
    }
    if (rc) {
        imdbt_ctx_free(c);
        return rc;
    }
    *out = c;
    return IMDB_OK;
}

void imdbt_ctx_free(imdbt_ctx *c)
{
    if (!c) return;
    SSL_CTX_free(c->ssl);
    imdb_wipe(c, sizeof *c);
    imdbw_free(c);
}

/* ---- sessions ---- */
int imdbt_new(imdbt_ctx *ctx, int fd, const char *host, imdbt **out, imdb_err *e)
{
    *out = NULL;
    imdbt *t = imdbw_alloc(1, sizeof *t);
    if (!t) return imdb_fail(e, IMDB_ERR_NOMEM, "out of memory");
    t->ctx = ctx, t->fd = fd;
    BIO *b = NULL;
    int rc = (t->ssl = SSL_new(ctx->ssl)) && (b = BIO_new(g_bio)) ? IMDB_OK : ssl_fail(e, IMDB_ERR_NOMEM, "a TLS session");
    if (!rc) {
        BIO_set_data(b, (void *)(intptr_t)fd);
        SSL_set_bio(t->ssl, b, b); /* one BIO both ways: one reference taken */
        b = NULL;
        if (ctx->client) SSL_set_connect_state(t->ssl);
        else SSL_set_accept_state(t->ssl);
    }
    if (!rc && ctx->client && !ctx->pinned && host) { /* the name or the address the client asked for, in subjectAltName */
        X509_VERIFY_PARAM *p = SSL_get0_param(t->ssl);
        struct in6_addr a6;
        struct in_addr a4;
        bool ip = inet_pton(AF_INET, host, &a4) == 1 || inet_pton(AF_INET6, host, &a6) == 1;
        if (!(ip ? X509_VERIFY_PARAM_set1_ip_asc(p, host) : X509_VERIFY_PARAM_set1_host(p, host, 0)))
            rc = ssl_fail(e, IMDB_ERR_INVALID, "the server's name");
        if (!rc && !ip) SSL_set_tlsext_host_name(t->ssl, host);
    }
    BIO_free(b);
    if (rc) {
        imdbt_free(t);
        return rc;
    }
    *out = t;
    return IMDB_OK;
}

int imdbt_handshake(imdbt *t, imdb_err *e)
{
    ERR_clear_error();
    int r = SSL_do_handshake(t->ssl);
    if (r != 1) {
        int err = SSL_get_error(t->ssl, r);
        if (err == SSL_ERROR_WANT_READ) return IMDBT_WANT_READ;
        if (err == SSL_ERROR_WANT_WRITE) return IMDBT_WANT_WRITE;
        long v = SSL_get_verify_result(t->ssl);
        if (v != X509_V_OK) {
            ERR_clear_error();
            return imdb_fail(e, IMDB_ERR_AUTH, "TLS: the server's certificate: %s", X509_verify_cert_error_string(v));
        }
        return ssl_fail(e, IMDB_ERR_AUTH, "TLS handshake");
    }
    const unsigned char *a = NULL;
    unsigned int al = 0;
    SSL_get0_alpn_selected(t->ssl, &a, &al); /* a client that offered none never reached the callback */
    if (al != sizeof IMDBT_ALPN - 1 || memcmp(a, IMDBT_ALPN, al))
        return imdb_fail(e, IMDB_ERR_AUTH, "TLS: the peer does not speak %s (ALPN)", IMDBT_ALPN);
    if (SSL_version(t->ssl) != TLS1_3_VERSION) return imdb_fail(e, IMDB_ERR_AUTH, "TLS: not 1.3");
    if (t->ctx->client && t->ctx->pinned) {
        X509 *peer = SSL_get1_peer_certificate(t->ssl);
        uint8_t got[32];
        bool ok = peer && !spki_pin(peer, got) && imdb_ct_eq(got, t->ctx->pin, 32);
        X509_free(peer);
        if (!ok) return imdb_fail(e, IMDB_ERR_AUTH, "TLS: the server's key is not the pinned one");
    }
    return IMDB_OK;
}

static ssize_t io_result(imdbt *t, int r)
{
    if (r > 0) return r;
    int err = SSL_get_error(t->ssl, r);
    if (err == SSL_ERROR_WANT_READ) return IMDBT_WANT_READ;
    if (err == SSL_ERROR_WANT_WRITE) return IMDBT_WANT_WRITE;
    ERR_clear_error();
    return err == SSL_ERROR_ZERO_RETURN ? 0 : -1;
}

ssize_t imdbt_read(imdbt *t, void *p, size_t n)
{
    ERR_clear_error();
    return io_result(t, SSL_read(t->ssl, p, n > INT32_MAX ? INT32_MAX : (int)n));
}

ssize_t imdbt_write(imdbt *t, const void *p, size_t n)
{
    ERR_clear_error();
    return io_result(t, SSL_write(t->ssl, p, n > INT32_MAX ? INT32_MAX : (int)n));
}

size_t imdbt_pending(const imdbt *t) { return (size_t)SSL_pending(t->ssl); }

int imdbt_binding(imdbt *t, uint8_t out[32])
{
    static const char label[] = "EXPORTER-Channel-Binding";
    return SSL_export_keying_material(t->ssl, out, 32, label, sizeof label - 1, NULL, 0, 0) == 1 ? 0 : -1;
}

/* §8f: RFC 5929's tls-server-end-point, the hash of the server's certificate by its signature's hash (MD5 and SHA-1 taken
 * to SHA-256). imagedb's `cert` signs ECDSA with SHA-256, and a server allowing this binding refuses another certificate
 * at its start (imdbt_ctx_endpoint_ok), so SHA-256 is the one hash any driver computes */
static int cert_endpoint(X509 *x, uint8_t out[32])
{
    int md = NID_undef, pk = NID_undef;
    if (!x || !OBJ_find_sigid_algs(X509_get_signature_nid(x), &md, &pk)) return -1;
    if (md == NID_md5 || md == NID_sha1) md = NID_sha256;
    unsigned n = 0;
    if (md != NID_sha256 || X509_digest(x, EVP_sha256(), out, &n) != 1 || n != 32) return -1;
    return 0;
}

int imdbt_endpoint(imdbt *t, uint8_t out[32])
{
    return cert_endpoint(SSL_is_server(t->ssl) ? SSL_get_certificate(t->ssl) : SSL_get0_peer_certificate(t->ssl), out);
}

bool imdbt_ctx_endpoint_ok(imdbt_ctx *c)
{
    uint8_t h[32];
    bool ok = !cert_endpoint(SSL_CTX_get0_certificate(c->ssl), h);
    imdb_wipe(h, sizeof h);
    return ok;
}

void imdbt_free(imdbt *t)
{
    if (!t) return;
    if (t->ssl) {
        ERR_clear_error();
        SSL_shutdown(t->ssl); /* best effort: never waited on */
        ERR_clear_error();
        SSL_free(t->ssl);
    }
    imdbw_free(t);
}
