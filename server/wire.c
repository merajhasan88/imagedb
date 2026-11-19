/* IMDBWIR1's bytes (wire.h; docs/n1-design.md §4). Each decoder is strict: exact lengths, no trailing bytes, zero padding,
 * every count bounded by the bytes left before anything is sized by it. Each field has one predicate (value_ok, text_ok,
 * col_shape_ok, ...), applied by its decoder and by its encoder, so an encoder never writes what its decoder refuses and
 * any bytes a decoder takes encode back to themselves (the tests and fuzz_wire hold both to it). */
#include "wire.h"

#include <stdatomic.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "../src/codec.h"
#include "../src/scram.h"
#include "../src/sha256.h"

#define TS_MIN_US (-62135596800000000LL) /* 0001-01-01 00:00:00 (codec.c's TS_MIN: a TIMESTAMP's range) */
#define TS_MAX_US (253402300799999999LL) /* 9999-12-31 23:59:59.999999 */

/* a callee's own code: never e->code, which keeps the first error (imdb_fail) and may be a caller's earlier one */
#define TRY(x)                \
    do {                      \
        int rc_ = (x);        \
        if (rc_) return rc_;  \
    } while (0)

/* ---- the wire's own allocations ---- */

static _Atomic int64_t g_live;
static _Atomic size_t g_peak;     /* the largest request: the tests hold a refused count to the bytes it came in */
static _Atomic int64_t g_fail_at; /* tests: the allocation that fails, counted down (0: none) */

void *imdbw_alloc(size_t n, size_t size)
{
    if (size && n > SIZE_MAX / size) return NULL;
    size_t want = n * size;
    size_t peak = atomic_load_explicit(&g_peak, memory_order_relaxed);
    while (want > peak && !atomic_compare_exchange_weak_explicit(&g_peak, &peak, want, memory_order_relaxed,
                                                                 memory_order_relaxed)) {
    }
    if (atomic_load_explicit(&g_fail_at, memory_order_relaxed) > 0 &&
        atomic_fetch_sub_explicit(&g_fail_at, 1, memory_order_relaxed) == 1)
        return NULL;
    void *p = calloc(n ? n : 1, size ? size : 1);
    if (p) atomic_fetch_add_explicit(&g_live, 1, memory_order_relaxed);
    return p;
}

void imdbw_free(void *p)
{
    if (!p) return;
    atomic_fetch_sub_explicit(&g_live, 1, memory_order_relaxed);
    free(p);
}

int64_t imdbw_live_blocks(void) { return atomic_load_explicit(&g_live, memory_order_relaxed); }

void imdbw_alloc_peak_reset(void) { atomic_store_explicit(&g_peak, 0, memory_order_relaxed); }

size_t imdbw_alloc_peak(void) { return atomic_load_explicit(&g_peak, memory_order_relaxed); }

void imdbw_alloc_fail_at(int64_t n) { atomic_store_explicit(&g_fail_at, n, memory_order_relaxed); }

/* ---- the output buffer ---- */

void imdbw_buf_init(imdbw_buf *b) { memset(b, 0, sizeof *b); }

void imdbw_buf_free(imdbw_buf *b)
{
    imdbw_free(b->p);
    memset(b, 0, sizeof *b);
}

void imdbw_buf_reset(imdbw_buf *b)
{
    b->len = 0;
    b->err = b->nomem = false;
}

static bool reserve(imdbw_buf *b, size_t n)
{
    if (b->err) return false;
    if (n > IMDBW_FRAME_MAX + IMDBW_HEAD || b->len > IMDBW_FRAME_MAX + IMDBW_HEAD - n) { /* past a frame: refused */
        b->err = true;
        return false;
    }
    if (b->len + n <= b->cap) return true;
    size_t cap = b->cap ? b->cap : 256;
    while (cap < b->len + n) cap *= 2;
    uint8_t *p = imdbw_alloc(cap, 1); /* never grown in place (CLAUDE.md): a new block, the bytes copied */
    if (!p) {
        b->err = b->nomem = true;
        return false;
    }
    if (b->len) memcpy(p, b->p, b->len);
    imdbw_free(b->p);
    b->p = p;
    b->cap = cap;
    return true;
}

void imdbw_put(imdbw_buf *b, const void *p, size_t n)
{
    if (!n || !reserve(b, n)) return;
    memcpy(b->p + b->len, p, n);
    b->len += n;
}

void imdbw_put_u8(imdbw_buf *b, uint8_t v) { imdbw_put(b, &v, 1); }

void imdbw_put_u16(imdbw_buf *b, uint16_t v)
{
    uint8_t x[2] = {(uint8_t)v, (uint8_t)(v >> 8)};
    imdbw_put(b, x, 2);
}

void imdbw_put_u32(imdbw_buf *b, uint32_t v)
{
    uint8_t x[4];
    imdb_le32(x, v);
    imdbw_put(b, x, 4);
}

void imdbw_put_u64(imdbw_buf *b, uint64_t v)
{
    uint8_t x[8];
    imdb_le64(x, v);
    imdbw_put(b, x, 8);
}

void imdbw_patch_u32(imdbw_buf *b, size_t at, uint32_t v)
{
    if (b->err || at > b->len || b->len - at < 4) {
        b->err = true;
        return;
    }
    imdb_le32(b->p + at, v);
}

static __int128 get_i128(imdb_rd *r)
{
    uint64_t lo = imdb_rd_u64(r), hi = imdb_rd_u64(r);
    return (__int128)(((unsigned __int128)hi << 64) | lo);
}

static int bad(imdb_err *e, const char *what) { return imdb_fail(e, IMDB_ERR_CORRUPT, "wire: %s", what); }

static bool zeros(const uint8_t *p, size_t n)
{
    for (size_t i = 0; i < n; i++)
        if (p[i]) return false;
    return true;
}

/* UTF-8 by the engine's rule (codec.c's imdb_utf8_valid: no NUL, no overlong form, no surrogate, nothing past U+10FFFF),
 * the codec's own and scalar, so the client library links no kernel dispatch; t_wire holds it to the engine's on drawn
 * bytes. *bad: the first byte of the first character that is not one. */
static bool utf8_valid(const uint8_t *s, size_t n, size_t *bad)
{
    size_t i = 0;
    while (i < n) {
        uint8_t c = s[i];
        if (c >= 0x01 && c < 0x80) {
            i++;
            continue;
        }
        size_t need;
        uint8_t lo = 0x80, hi = 0xBF;
        if (c >= 0xC2 && c <= 0xDF) need = 1;
        else if (c == 0xE0) need = 2, lo = 0xA0;
        else if (c >= 0xE1 && c <= 0xEC) need = 2;
        else if (c == 0xED) need = 2, hi = 0x9F;
        else if (c == 0xEE || c == 0xEF) need = 2;
        else if (c == 0xF0) need = 3, lo = 0x90;
        else if (c >= 0xF1 && c <= 0xF3) need = 3;
        else if (c == 0xF4) need = 3, hi = 0x8F;
        else goto fail; /* NUL, C0, C1, F5..FF, a stray continuation */
        if (need > n - i - 1 || s[i + 1] < lo || s[i + 1] > hi) goto fail;
        for (size_t j = 2; j <= need; j++)
            if ((s[i + j] & 0xC0) != 0x80) goto fail;
        i += need + 1;
    }
    return true;
fail:
    if (bad) *bad = i;
    return false;
}

static uint32_t utf8_chars(const uint8_t *s, uint32_t n) /* of valid UTF-8: the bytes that begin a character */
{
    uint32_t k = 0;
    for (uint32_t i = 0; i < n; i++) k += (s[i] & 0xC0) != 0x80;
    return k;
}

static __int128 pow10i(int k) /* 10^k, k 0 to 38: one multiplication past 10^19 */
{
    static const uint64_t t[20] = {1ull, 10ull, 100ull, 1000ull, 10000ull, 100000ull, 1000000ull, 10000000ull, 100000000ull,
                                   1000000000ull, 10000000000ull, 100000000000ull, 1000000000000ull, 10000000000000ull,
                                   100000000000000ull, 1000000000000000ull, 10000000000000000ull, 100000000000000000ull,
                                   1000000000000000000ull, 10000000000000000000ull};
    return k <= 19 ? (__int128)t[k] : (__int128)t[k - 19] * (__int128)t[19];
}

size_t imdbw_utf8_fit(const uint8_t *s, size_t n, size_t max)
{
    size_t k = n < max ? n : max, at = 0;
    if (!k || utf8_valid(s, k, &at)) return k;
    return at; /* the first character that is not one, or is cut by max: everything before it is */
}

/* ---- before authentication ---- */

bool imdbw_user_ok(const char *user, size_t len)
{
    return len >= 1 && len < IMDBW_USER && utf8_valid((const uint8_t *)user, len, NULL);
}

int imdbw_preauth_head(const uint8_t in[IMDBW_PREAUTH_HEAD], uint32_t *version, imdb_err *e)
{
    *version = imdb_get_le32(in + 8);
    if (memcmp(in, IMDBW_MAGIC, 8) != 0) {
        if (imdb_later_magic(in, 8, IMDBW_MAGIC))
            return imdb_fail(e, IMDB_ERR_UNSUPPORTED, "wire: %.8s, a later protocol, which this imagedb does not speak",
                             (const char *)in);
        return bad(e, "not imagedb's protocol");
    }
    if (*version < 1) return bad(e, "protocol version 0");
    return IMDB_OK;
}

void imdbw_version_put(uint8_t out[IMDBW_PREAUTH_HEAD])
{
    memcpy(out, IMDBW_MAGIC, 8);
    imdb_le32(out + 8, IMDBW_VERSION);
}

/* the magic and the version, first: a later version refused by name before anything else is read */
static int magic_version(imdb_rd *r, uint32_t *version, imdb_err *e)
{
    const uint8_t *m = imdb_rd_bytes(r, 8);
    *version = imdb_rd_u32(r);
    if (!m || memcmp(m, IMDBW_MAGIC, 8) != 0) {
        if (m && imdb_later_magic(m, 8, IMDBW_MAGIC))
            return imdb_fail(e, IMDB_ERR_UNSUPPORTED, "wire: %.8s, a later protocol, which this imagedb does not speak",
                             (const char *)m);
        return bad(e, "not imagedb's protocol");
    }
    if (*version > IMDBW_VERSION)
        return imdb_fail(e, IMDB_ERR_UNSUPPORTED, "wire: protocol version %u, a later one, which this imagedb (version %u) "
                         "does not speak", *version, IMDBW_VERSION);
    if (*version != IMDBW_VERSION) return bad(e, "an unknown protocol version");
    return IMDB_OK;
}

int imdbw_hello_put(const imdbw_hello *h, uint8_t out[IMDBW_HELLO_LEN])
{
    size_t n = strnlen(h->user, IMDBW_USER);
    if (h->version != IMDBW_VERSION || h->flags > IMDBW_CB_ENDPOINT || !imdbw_user_ok(h->user, n)) return -1;
    memset(out, 0, IMDBW_HELLO_LEN);
    memcpy(out, IMDBW_MAGIC, 8);
    imdb_le32(out + 8, h->version);
    imdb_le32(out + 12, h->flags);
    memcpy(out + 16, h->user, n);
    memcpy(out + 16 + IMDBW_USER, h->nonce, IMDBW_NONCE);
    return 0;
}

int imdbw_hello_get(const uint8_t in[IMDBW_HELLO_LEN], imdbw_hello *h, imdb_err *e)
{
    memset(h, 0, sizeof *h);
    imdb_rd r;
    imdb_rd_init(&r, in, IMDBW_HELLO_LEN);
    TRY(magic_version(&r, &h->version, e));
    h->flags = imdb_rd_u32(&r);
    const uint8_t *u = imdb_rd_bytes(&r, IMDBW_USER);
    imdb_rd_copy(&r, h->nonce, IMDBW_NONCE);
    if (r.err || imdb_rd_left(&r)) return bad(e, "a hello of another length");
    if (h->flags > IMDBW_CB_ENDPOINT) return bad(e, "a hello with flags no version defines (a binding type but 0, 1, 2)");
    size_t n = strnlen((const char *)u, IMDBW_USER);
    if (n == IMDBW_USER || !imdbw_user_ok((const char *)u, n) || !zeros(u + n, IMDBW_USER - n))
        return bad(e, "a hello's role name is not 1 to 63 bytes of UTF-8, NUL-padded");
    memcpy(h->user, u, n);
    return IMDB_OK;
}

static bool challenge_ok(const imdbw_challenge *c)
{
    return c->version == IMDBW_VERSION && c->salt_len >= IMDBW_SCRAM_SALT_MIN && c->salt_len <= IMDBW_SALT &&
           c->iter >= IMDBW_SCRAM_ITER_MIN && c->iter <= IMDBW_SCRAM_ITER_MAX;
}

int imdbw_challenge_put(const imdbw_challenge *c, uint8_t out[IMDBW_CHALLENGE_LEN])
{
    if (!challenge_ok(c)) return -1;
    memset(out, 0, IMDBW_CHALLENGE_LEN);
    memcpy(out, IMDBW_MAGIC, 8);
    imdb_le32(out + 8, c->version);
    out[12] = c->salt_len;
    memcpy(out + 13, c->salt, c->salt_len);
    imdb_le32(out + 13 + IMDBW_SALT, c->iter);
    memcpy(out + 17 + IMDBW_SALT, c->nonce, IMDBW_NONCE);
    return 0; /* then 7 zeros */
}

int imdbw_challenge_get(const uint8_t in[IMDBW_CHALLENGE_LEN], imdbw_challenge *c, imdb_err *e)
{
    memset(c, 0, sizeof *c);
    imdb_rd r;
    imdb_rd_init(&r, in, IMDBW_CHALLENGE_LEN);
    TRY(magic_version(&r, &c->version, e));
    c->salt_len = imdb_rd_u8(&r);
    const uint8_t *salt = imdb_rd_bytes(&r, IMDBW_SALT);
    c->iter = imdb_rd_u32(&r);
    imdb_rd_copy(&r, c->nonce, IMDBW_NONCE);
    const uint8_t *pad = imdb_rd_bytes(&r, 7);
    if (r.err || imdb_rd_left(&r)) return bad(e, "a challenge of another length");
    if (!challenge_ok(c) || !zeros(salt + c->salt_len, IMDBW_SALT - c->salt_len))
        return bad(e, "a challenge's salt is not 8 to 64 bytes, zero-padded, or its iterations not 1,000 to 1,000,000");
    if (!zeros(pad, 7)) return bad(e, "a challenge's padding is not zero");
    memcpy(c->salt, salt, c->salt_len);
    return IMDB_OK;
}

static bool verdict_ok(const imdbw_verdict *v)
{
    return v->code == IMDBW_VERDICT_OK ||
           ((v->code == IMDBW_VERDICT_REFUSED || v->code == IMDBW_VERDICT_BINDING) && zeros(v->sig, IMDBW_KEY));
}

int imdbw_verdict_put(const imdbw_verdict *v, uint8_t out[IMDBW_VERDICT_LEN])
{
    if (!verdict_ok(v)) return -1;
    imdb_le32(out, v->code);
    memcpy(out + 4, v->sig, IMDBW_KEY);
    return 0;
}

int imdbw_verdict_get(const uint8_t in[IMDBW_VERDICT_LEN], imdbw_verdict *v, imdb_err *e)
{
    v->code = imdb_get_le32(in);
    memcpy(v->sig, in + 4, IMDBW_KEY);
    if (!verdict_ok(v)) return bad(e, "a verdict neither accepted nor refused, or a refusal carrying a signature");
    return IMDB_OK;
}

/* ---- SCRAM ---- */

static const char kAuthMagic[] = "IMDBWIR1-SCRAM"; /* 14 bytes, no NUL */
_Static_assert(sizeof kAuthMagic - 1 + 1 + IMDBW_HELLO_LEN + IMDBW_CHALLENGE_LEN + IMDBW_KEY == IMDBW_AUTHMSG_LEN,
               "the AuthMessage's layout");
_Static_assert(8 + 4 + 4 + IMDBW_USER + IMDBW_NONCE == IMDBW_HELLO_LEN, "the hello's layout");
_Static_assert(8 + 4 + 1 + IMDBW_SALT + 4 + IMDBW_NONCE + 7 == IMDBW_CHALLENGE_LEN, "the challenge's layout");
_Static_assert(4 + IMDBW_KEY == IMDBW_VERDICT_LEN, "the verdict's layout");

void imdbw_auth_message(uint8_t endpoint, const uint8_t hello[IMDBW_HELLO_LEN], const uint8_t challenge[IMDBW_CHALLENGE_LEN],
                        const uint8_t binding[IMDBW_KEY], uint8_t out[IMDBW_AUTHMSG_LEN])
{
    size_t o = sizeof kAuthMagic - 1;
    memcpy(out, kAuthMagic, o);
    out[o++] = endpoint;
    memcpy(out + o, hello, IMDBW_HELLO_LEN);
    o += IMDBW_HELLO_LEN;
    memcpy(out + o, challenge, IMDBW_CHALLENGE_LEN);
    o += IMDBW_CHALLENGE_LEN;
    memcpy(out + o, binding, IMDBW_KEY);
}

static void hmac32(const uint8_t *key, size_t klen, const void *msg, size_t n, uint8_t out[IMDBW_KEY])
{
    imdb_hmac m;
    imdb_hmac_init(&m, key, klen);
    imdb_hmac_update(&m, msg, n);
    imdb_hmac_final(&m, out);
    imdb_wipe(&m, sizeof m);
}

/* SHA-256 with its context wiped: a ClientKey passes through the hash's buffer (scram.c's rule) */
static void sha256_wiped(const uint8_t *p, size_t n, uint8_t out[32])
{
    imdb_sha256_ctx c;
    imdb_sha256_init(&c);
    imdb_sha256_update(&c, p, n);
    imdb_sha256_final(&c, out);
    imdb_wipe(&c, sizeof c);
}

int imdbw_scram_client(const char *pw, size_t pwlen, const imdbw_challenge *c, const uint8_t am[IMDBW_AUTHMSG_LEN],
                       uint8_t proof[IMDBW_KEY], uint8_t server_sig[IMDBW_KEY])
{
    if (!pwlen || pwlen > IMDBW_PW_MAX || !challenge_ok(c)) return -1;
    for (size_t i = 0; i < pwlen; i++) /* CREATE ROLE's rule: printable ASCII (no SASLprep in imagedb yet) */
        if ((unsigned char)pw[i] < 0x20 || (unsigned char)pw[i] > 0x7e) return -1;
    uint8_t sp[32], ck[32], sk[32], stored[32], cs[32];
    imdb_pbkdf2_sha256((const uint8_t *)pw, pwlen, c->salt, c->salt_len, c->iter, sp);
    hmac32(sp, sizeof sp, "Client Key", 10, ck);
    hmac32(sp, sizeof sp, "Server Key", 10, sk);
    sha256_wiped(ck, sizeof ck, stored);
    hmac32(stored, sizeof stored, am, IMDBW_AUTHMSG_LEN, cs);
    for (int i = 0; i < 32; i++) proof[i] = ck[i] ^ cs[i];
    hmac32(sk, sizeof sk, am, IMDBW_AUTHMSG_LEN, server_sig);
    imdb_wipe(sp, sizeof sp);
    imdb_wipe(ck, sizeof ck);
    imdb_wipe(sk, sizeof sk);
    imdb_wipe(stored, sizeof stored);
    imdb_wipe(cs, sizeof cs);
    return 0;
}

bool imdbw_scram_server(const uint8_t stored[IMDBW_KEY], const uint8_t server_key[IMDBW_KEY],
                        const uint8_t am[IMDBW_AUTHMSG_LEN], const uint8_t proof[IMDBW_KEY], uint8_t sig[IMDBW_KEY])
{
    uint8_t cs[32], ck[32], h[32];
    hmac32(stored, IMDBW_KEY, am, IMDBW_AUTHMSG_LEN, cs);
    for (int i = 0; i < 32; i++) ck[i] = proof[i] ^ cs[i];
    sha256_wiped(ck, sizeof ck, h);
    bool ok = imdb_ct_eq(h, stored, IMDBW_KEY); /* constant time (CVE-2026-6478) */
    hmac32(server_key, IMDBW_KEY, am, IMDBW_AUTHMSG_LEN, sig);
    imdb_wipe(cs, sizeof cs);
    imdb_wipe(ck, sizeof ck);
    imdb_wipe(h, sizeof h);
    return ok;
}

void imdbw_fake_salt(const uint8_t secret[IMDBW_KEY], const char *user, uint8_t salt[16])
{
    uint8_t field[IMDBW_USER] = {0}, h[32];
    memcpy(field, user, strnlen(user, IMDBW_USER - 1));
    hmac32(secret, IMDBW_KEY, field, sizeof field, h);
    memcpy(salt, h, 16);
    imdb_wipe(h, sizeof h);
}

/* ---- frames ---- */

static bool type_known(uint8_t t, bool from_server)
{
    return from_server ? t >= IMDBW_COLUMNS && t <= IMDBW_SERVER_LAST : t >= IMDBW_QUERY && t <= IMDBW_CLIENT_LAST;
}

int imdbw_head_get(const uint8_t in[IMDBW_HEAD], bool from_server, uint32_t *len, uint8_t *type, imdb_err *e)
{
    *len = imdb_get_le32(in);
    *type = in[4];
    if (*len < 1 || *len > IMDBW_FRAME_MAX)
        return imdb_fail(e, IMDB_ERR_LIMIT, "wire: a frame of %u bytes (1 to %u)", *len, IMDBW_FRAME_MAX);
    if (!type_known(*type, from_server)) return bad(e, "a frame of a type this side does not send");
    return IMDB_OK;
}

size_t imdbw_frame_begin(imdbw_buf *b, uint8_t type)
{
    size_t at = b->len;
    uint8_t h[IMDBW_HEAD] = {0, 0, 0, 0, type};
    imdbw_put(b, h, sizeof h);
    return at;
}

void imdbw_frame_end(imdbw_buf *b, size_t at)
{
    if (b->err || at > b->len || b->len - at < IMDBW_HEAD) {
        b->err = true;
        return;
    }
    size_t n = b->len - at - 4; /* the type and the body */
    if (n > IMDBW_FRAME_MAX) {
        b->err = true;
        return;
    }
    imdb_le32(b->p + at, (uint32_t)n);
}

/* ---- values ---- */

static bool dec_in(__int128 d, int digits)
{
    __int128 lim = pow10i(digits);
    return d > -lim && d < lim;
}

static bool utf8_ok(const uint8_t *s, uint32_t n) { return !n || (s && utf8_valid(s, n, NULL)); }

bool imdbw_value_ok(const imdbw_value *v)
{
    if (v->null) return v->type <= IMDBW_T_LAST; /* a NULL of a type, or of none */
    switch (v->type) {
    case IMDBW_T_INT64:
    case IMDBW_T_INTERVAL: return true;
    case IMDBW_T_FLOAT64: return ((v->f >> 52) & 0x7ff) != 0x7ff && v->f != 0x8000000000000000ull; /* finite, not -0 */
    case IMDBW_T_BOOL: return v->i == 0 || v->i == 1;
    case IMDBW_T_TEXT: return v->len <= IMDBW_VALUE_MAX && utf8_ok(v->s, v->len);
    case IMDBW_T_BYTEA: return v->len <= IMDBW_VALUE_MAX && (!v->len || v->s);
    case IMDBW_T_ENUM: return v->len <= IMDBW_LABEL_MAX && utf8_ok(v->s, v->len);
    case IMDBW_T_DECIMAL: return v->scale <= 38 && dec_in(v->d, 38);
    case IMDBW_T_TIMESTAMP:
    case IMDBW_T_TIMESTAMPTZ: return v->i >= TS_MIN_US && v->i <= TS_MAX_US;
    case IMDBW_T_DATE: return v->day >= IMDB_DATE_MIN && v->day <= IMDB_DATE_MAX;
    case IMDBW_T_TIME: return v->i >= 0 && v->i <= IMDB_TIME_MAX;
    case IMDBW_T_UUID: return v->s && v->len == 16;
    default: return false; /* no type: only a NULL has none */
    }
}

/* a value's bytes on the wire */
static size_t value_size(const imdbw_value *v)
{
    if (v->null) return 1;
    switch (v->type) {
    case IMDBW_T_BOOL: return 2;
    case IMDBW_T_DATE: return 5;
    case IMDBW_T_TEXT:
    case IMDBW_T_BYTEA: return 5 + (size_t)v->len;
    case IMDBW_T_ENUM: return 2 + (size_t)v->len;
    case IMDBW_T_DECIMAL: return 18;
    case IMDBW_T_UUID:
    case IMDBW_T_INTERVAL: return 17;
    default: return 9; /* INT64, FLOAT64, TIMESTAMP, TIMESTAMPTZ, TIME */
    }
}

/* a value's bytes, its rules checked by the caller: one reservation, then the bytes stored in place (the profile of
 * 2026-11-16: a put a field had been most of a row's cost) */
static void value_raw(imdbw_buf *b, const imdbw_value *v)
{
    size_t n = value_size(v);
    if (!reserve(b, n)) return;
    uint8_t *p = b->p + b->len;
    b->len += n;
    if (v->null) {
        p[0] = (uint8_t)(IMDBW_NULL_TAG | v->type);
        return;
    }
    p[0] = v->type;
    switch (v->type) {
    case IMDBW_T_FLOAT64: imdb_le64(p + 1, v->f); break;
    case IMDBW_T_BOOL: p[1] = (uint8_t)v->i; break;
    case IMDBW_T_TEXT:
    case IMDBW_T_BYTEA:
        imdb_le32(p + 1, v->len);
        if (v->len) memcpy(p + 5, v->s, v->len);
        break;
    case IMDBW_T_ENUM:
        p[1] = (uint8_t)v->len;
        if (v->len) memcpy(p + 2, v->s, v->len);
        break;
    case IMDBW_T_DECIMAL: {
        unsigned __int128 u = (unsigned __int128)v->d;
        p[1] = v->scale;
        imdb_le64(p + 2, (uint64_t)u);
        imdb_le64(p + 10, (uint64_t)(u >> 64));
        break;
    }
    case IMDBW_T_DATE: imdb_le32(p + 1, (uint32_t)v->day); break;
    case IMDBW_T_UUID: memcpy(p + 1, v->s, 16); break;
    case IMDBW_T_INTERVAL:
        imdb_le32(p + 1, (uint32_t)v->mon);
        imdb_le32(p + 5, (uint32_t)v->day);
        imdb_le64(p + 9, (uint64_t)v->i);
        break;
    default: imdb_le64(p + 1, (uint64_t)v->i); break; /* INT64, TIMESTAMP, TIMESTAMPTZ, TIME */
    }
}

void imdbw_value_put(imdbw_buf *b, const imdbw_value *v)
{
    if (!imdbw_value_ok(v)) {
        b->err = true;
        return;
    }
    value_raw(b, v);
}

int imdbw_value_get(imdb_rd *r, imdbw_value *v, imdb_err *e)
{
    memset(v, 0, sizeof *v);
    uint8_t tag = imdb_rd_u8(r);
    if (r->err) return bad(e, "a value cut short");
    if (tag & IMDBW_NULL_TAG) {
        v->null = true;
        v->type = (uint8_t)(tag & ~IMDBW_NULL_TAG);
        if (v->type > IMDBW_T_LAST) return bad(e, "a NULL of a type the protocol does not define");
        return IMDB_OK;
    }
    v->type = tag;
    switch (v->type) {
    case IMDBW_T_INT64:
    case IMDBW_T_TIMESTAMP:
    case IMDBW_T_TIMESTAMPTZ:
    case IMDBW_T_TIME: v->i = (int64_t)imdb_rd_u64(r); break;
    case IMDBW_T_FLOAT64: v->f = imdb_rd_u64(r); break;
    case IMDBW_T_BOOL: v->i = imdb_rd_u8(r); break;
    case IMDBW_T_TEXT:
    case IMDBW_T_BYTEA:
    case IMDBW_T_ENUM:
        v->len = v->type == IMDBW_T_ENUM ? imdb_rd_u8(r) : imdb_rd_u32(r);
        if (r->err) break;
        if (v->len > (v->type == IMDBW_T_ENUM ? IMDBW_LABEL_MAX : IMDBW_VALUE_MAX)) /* before its bytes are asked for */
            return imdb_fail(e, IMDB_ERR_LIMIT, "wire: a value of %u bytes (at most %u)", v->len,
                             v->type == IMDBW_T_ENUM ? IMDBW_LABEL_MAX : IMDBW_VALUE_MAX);
        v->s = imdb_rd_bytes(r, v->len);
        break;
    case IMDBW_T_DECIMAL:
        v->scale = imdb_rd_u8(r);
        v->d = get_i128(r);
        break;
    case IMDBW_T_DATE: v->day = (int32_t)imdb_rd_u32(r); break;
    case IMDBW_T_UUID:
        v->s = imdb_rd_bytes(r, 16);
        v->len = 16;
        break;
    case IMDBW_T_INTERVAL:
        v->mon = (int32_t)imdb_rd_u32(r);
        v->day = (int32_t)imdb_rd_u32(r);
        v->i = (int64_t)imdb_rd_u64(r);
        break;
    default: return bad(e, "a value of a type the protocol does not define (a NULL's tag is 0x80 and its type)");
    }
    if (r->err) return bad(e, "a value cut short");
    if (!imdbw_value_ok(v)) return bad(e, "a value outside its type's rules");
    return IMDB_OK;
}

bool imdbw_value_eq(const imdbw_value *a, const imdbw_value *b)
{
    imdbw_buf x, y;
    imdbw_buf_init(&x);
    imdbw_buf_init(&y);
    imdbw_value_put(&x, a);
    imdbw_value_put(&y, b);
    bool eq = !x.err && !y.err && x.len == y.len && memcmp(x.p, y.p, x.len) == 0;
    imdbw_buf_free(&x);
    imdbw_buf_free(&y);
    return eq;
}

void imdbw_span_begin(const imdbw_span *s, imdb_rd *r) { imdb_rd_init(r, s->p, s->len); }

bool imdbw_span_next(imdb_rd *r, imdbw_value *v)
{
    if (r->err || !imdb_rd_left(r)) return false;
    imdb_err e; /* its code alone read: never the 260 bytes zeroed a value */
    imdb_err_clear(&e);
    if (imdbw_value_get(r, v, &e)) { /* a span its decoder did not validate: the caller's bug, never silently */
        r->err = true;
        return false;
    }
    return true;
}

/* ---- columns ---- */

static bool int_width_ok(uint16_t p) { return p == 0 || p == 16 || p == 32; }

static bool col_shape_ok(const imdbw_col *c)
{
    size_t n = strnlen(c->name, IMDBW_COLNAME_MAX + 1);
    if (n < 1 || n > IMDBW_COLNAME_MAX || !utf8_ok((const uint8_t *)c->name, (uint32_t)n)) return false;
    if (c->type > IMDBW_T_LAST) return false;
    if (c->type != IMDBW_T_ENUM && c->nlabels) return false;
    if (c->type == IMDBW_T_ENUM && c->nlabels > IMDBW_LABELS_MAX) return false;
    switch (c->type) {
    case IMDBW_T_DECIMAL: /* precision 0: not known (a result's column: the engine reports a scale alone), 38 digits */
        return c->precision <= 38 && c->scale <= (c->precision ? c->precision : 38);
    case IMDBW_T_INT64: return int_width_ok(c->precision) && !c->scale;
    case IMDBW_T_TEXT: return !c->scale; /* precision: a VARCHAR's length (a u16, as the schema's), 0 none */
    default: return !c->precision && !c->scale;
    }
}

static int label_cmp(const imdbw_text *a, const imdbw_text *b)
{
    uint32_t n = a->len < b->len ? a->len : b->len;
    int c = n ? memcmp(a->p, b->p, n) : 0;
    return c ? c : (a->len > b->len) - (a->len < b->len);
}

static int sorted_cmp(const void *x, const void *y, void *arg)
{
    const imdbw_text *l = arg;
    return label_cmp(&l[*(const uint16_t *)x], &l[*(const uint16_t *)y]);
}

void imdbw_cols_unindex(imdbw_msg *m)
{
    for (uint16_t i = 0; m->cols && i < m->ncols; i++) {
        imdbw_free(m->cols[i].sorted);
        m->cols[i].sorted = NULL;
    }
}

int imdbw_cols_index(imdbw_msg *m)
{
    for (uint16_t i = 0; i < m->ncols; i++) {
        imdbw_col *c = &m->cols[i];
        if (c->type != IMDBW_T_ENUM || c->sorted) continue;
        if (c->nlabels > IMDBW_LABELS_MAX) return -1;
        for (uint32_t k = 0; k < c->nlabels; k++)
            if (c->labels[k].len > IMDBW_LABEL_MAX || !utf8_ok(c->labels[k].p, c->labels[k].len)) return -1;
        if (!(c->sorted = imdbw_alloc(c->nlabels, sizeof *c->sorted))) return -2;
        for (uint32_t k = 0; k < c->nlabels; k++) c->sorted[k] = (uint16_t)k;
        qsort_r(c->sorted, c->nlabels, sizeof *c->sorted, sorted_cmp, c->labels);
        for (uint32_t k = 1; k < c->nlabels; k++)
            if (!label_cmp(&c->labels[c->sorted[k - 1]], &c->labels[c->sorted[k]])) return -1; /* a label twice */
    }
    return 0;
}

static bool label_in(const imdbw_col *c, const uint8_t *s, uint32_t len)
{
    imdbw_text t = {s, len};
    if (!c->sorted) { /* a column not indexed: each label in turn */
        for (uint32_t k = 0; k < c->nlabels; k++)
            if (!label_cmp(&c->labels[k], &t)) return true;
        return false;
    }
    uint32_t lo = 0, hi = c->nlabels;
    while (lo < hi) {
        uint32_t mid = lo + (hi - lo) / 2;
        int x = label_cmp(&c->labels[c->sorted[mid]], &t);
        if (!x) return true;
        if (x < 0) lo = mid + 1;
        else hi = mid;
    }
    return false;
}

bool imdbw_value_fits(const imdbw_col *c, const imdbw_value *v)
{
    if (!imdbw_value_ok(v)) return false;
    if (c->type == IMDBW_T_NONE) return true; /* a column not known: each value its own type */
    if (v->type != c->type) return false;     /* a NULL too: one tag a column, its type's */
    if (v->null) return true;
    switch (c->type) {
    case IMDBW_T_DECIMAL: return v->scale == c->scale && dec_in(v->d, c->precision ? c->precision : 38);
    case IMDBW_T_INT64:
        return c->precision == 16 ? v->i >= INT16_MIN && v->i <= INT16_MAX
               : c->precision == 32 ? v->i >= INT32_MIN && v->i <= INT32_MAX
                                    : true;
    case IMDBW_T_TEXT: return !c->precision || utf8_chars(v->s, v->len) <= c->precision;
    case IMDBW_T_ENUM: return label_in(c, v->s, v->len);
    default: return true;
    }
}

/* ---- messages ---- */

static bool text_ok(const imdbw_text *t, uint32_t min, uint32_t max)
{
    return t->len >= min && t->len <= max && utf8_ok(t->p, t->len);
}

static int text_get(imdb_rd *r, uint32_t lenbytes, uint32_t min, uint32_t max, imdbw_text *t, imdb_err *e)
{
    uint32_t n = lenbytes == 1 ? imdb_rd_u8(r) : lenbytes == 2 ? imdb_rd_u16(r) : imdb_rd_u32(r);
    if (r->err) return bad(e, "a text cut short");
    if (n < min || n > max) return imdb_fail(e, IMDB_ERR_LIMIT, "wire: a text of %u bytes (%u to %u)", n, min, max);
    t->p = imdb_rd_bytes(r, n);
    t->len = n;
    if (!t->p) return bad(e, "a text cut short");
    if (!text_ok(t, min, max)) return bad(e, "a text not UTF-8 without NUL");
    return IMDB_OK;
}

static void text_put(imdbw_buf *b, uint32_t lenbytes, uint32_t min, uint32_t max, const imdbw_text *t)
{
    if (!text_ok(t, min, max)) {
        b->err = true;
        return;
    }
    if (lenbytes == 1) imdbw_put_u8(b, (uint8_t)t->len);
    else if (lenbytes == 2) imdbw_put_u16(b, (uint16_t)t->len);
    else imdbw_put_u32(b, t->len);
    imdbw_put(b, t->p, t->len);
}

static int name_get(imdb_rd *r, char out[IMDBW_NAME_MAX + 1], imdb_err *e)
{
    imdbw_text t;
    TRY(text_get(r, 1, 1, IMDBW_NAME_MAX, &t, e));
    memcpy(out, t.p, t.len);
    out[t.len] = 0;
    return IMDB_OK;
}

static void name_put(imdbw_buf *b, const char *name)
{
    imdbw_text t = {(const uint8_t *)name, (uint32_t)strnlen(name, IMDBW_NAME_MAX + 1)};
    text_put(b, 1, 1, IMDBW_NAME_MAX, &t);
}

static int nomem(imdb_err *e) { return imdb_fail(e, IMDB_ERR_NOMEM, "wire: out of memory"); }

/* n values in place, each against its column when cols is given (ROWS: value i's column is i mod the columns' count) */
static int span_get(imdb_rd *r, uint64_t n, const imdbw_msg *cols, imdbw_span *s, imdb_err *e)
{
    if (n > imdb_rd_left(r)) return bad(e, "more values than bytes"); /* each value is at least one byte */
    size_t at = r->off;
    for (uint64_t i = 0; i < n; i++) {
        imdbw_value v;
        TRY(imdbw_value_get(r, &v, e));
        if (cols && !imdbw_value_fits(&cols->cols[i % cols->ncols], &v)) return bad(e, "a value its column does not take");
        if (!cols && v.type == IMDBW_T_ENUM && !v.null) return bad(e, "an ENUM parameter: a label is sent as TEXT");
    }
    s->p = r->p + at;
    s->len = r->off - at;
    s->n = (uint32_t)n;
    return IMDB_OK;
}

/* what span_get takes: n values, each valid (and its column's, i mod the columns' count, when cols is given), filling the
 * span's bytes exactly; an encoder walks a span it is handed rather than trust its count */
static bool span_check(const imdbw_span *s, uint64_t n, const imdbw_msg *cols)
{
    if (s->n != n || (s->len && !s->p)) return false;
    imdb_rd r;
    imdb_err e; /* one for the walk: a failure ends it, so it is never read twice (zeroing 260 bytes a value had been
                 * half the walk's time) */
    imdb_err_clear(&e);
    imdb_rd_init(&r, s->p, s->len);
    for (uint64_t i = 0; i < n; i++) {
        imdbw_value v;
        if (imdbw_value_get(&r, &v, &e)) return false;
        if (cols && !imdbw_value_fits(&cols->cols[i % cols->ncols], &v)) return false;
        if (!cols && v.type == IMDBW_T_ENUM && !v.null) return false; /* a parameter: never an ENUM but a NULL */
    }
    return !imdb_rd_left(&r);
}

static void span_put(imdbw_buf *b, const imdbw_span *s, uint64_t n, const imdbw_msg *cols)
{
    if (!span_check(s, n, cols)) {
        b->err = true;
        return;
    }
    imdbw_put(b, s->p, s->len);
}

static int col_get(imdb_rd *r, imdbw_col *c, imdb_err *e)
{
    imdbw_text t;
    TRY(text_get(r, 1, 1, IMDBW_COLNAME_MAX, &t, e));
    memcpy(c->name, t.p, t.len);
    c->name[t.len] = 0;
    c->type = imdb_rd_u8(r);
    c->precision = imdb_rd_u16(r);
    c->scale = imdb_rd_u16(r);
    if (r->err) return bad(e, "a column cut short");
    if (c->type == IMDBW_T_ENUM) {
        uint16_t n = imdb_rd_u16(r);
        if (r->err || n > IMDBW_LABELS_MAX || n > imdb_rd_left(r)) return bad(e, "an ENUM's labels past their bounds or bytes");
        if (!(c->labels = imdbw_alloc(n, sizeof *c->labels))) return nomem(e);
        c->nlabels = n;
        for (uint32_t i = 0; i < n; i++) TRY(text_get(r, 1, 0, IMDBW_LABEL_MAX, &c->labels[i], e));
    }
    if (!col_shape_ok(c)) return bad(e, "a column's type, precision or scale its type does not take");
    return IMDB_OK;
}

static void col_put(imdbw_buf *b, const imdbw_col *c)
{
    if (!col_shape_ok(c) || (c->type == IMDBW_T_ENUM && !c->sorted)) { /* indexed: its labels checked distinct */
        b->err = true;
        return;
    }
    imdbw_text t = {(const uint8_t *)c->name, (uint32_t)strnlen(c->name, IMDBW_COLNAME_MAX + 1)};
    text_put(b, 1, 1, IMDBW_COLNAME_MAX, &t);
    imdbw_put_u8(b, c->type);
    imdbw_put_u16(b, c->precision);
    imdbw_put_u16(b, c->scale);
    if (c->type == IMDBW_T_ENUM) {
        imdbw_put_u16(b, (uint16_t)c->nlabels);
        for (uint32_t i = 0; i < c->nlabels; i++) text_put(b, 1, 0, IMDBW_LABEL_MAX, &c->labels[i]);
    }
}

void imdbw_msg_free(imdbw_msg *m)
{
    imdbw_free(m->sess);
    imdbw_free(m->texts);
    imdbw_free(m->params);
    imdbw_cols_unindex(m);
    for (uint16_t i = 0; m->cols && i < m->ncols; i++) imdbw_free(m->cols[i].labels);
    imdbw_free(m->cols);
    memset(m, 0, sizeof *m);
}

static int one_text(imdb_rd *r, uint32_t lenbytes, uint32_t min, uint32_t max, imdbw_msg *m, imdb_err *e)
{
    if (!(m->texts = imdbw_alloc(1, sizeof *m->texts))) return nomem(e);
    m->ntexts = 1;
    return text_get(r, lenbytes, min, max, &m->texts[0], e);
}

static bool done_ok(const imdbw_msg *m)
{
    return text_ok(&m->status, 0, IMDBW_STATUS_MAX) && (!m->has_write || m->write_commit >= 1);
}

/* N1e stage two: a SESSIONS_LIST entry's rules, its decoder's and its encoder's: ids strictly increasing (one order, no
 * id twice), a role, an endpoint (1 TCP, 2 the socket), a state, the role's name 0 to 63 bytes ("" once erased) */
#define IMDBW_SESS_MIN 23u /* an entry's bytes at least: u64 id, u32 role, u8 endpoint, u8 state, u64 age, u8 length */
static bool sess_ok(const imdbw_sess *s, uint64_t prev)
{
    return s->id > prev && s->role && (s->endpoint == 1 || s->endpoint == 2) && s->state <= IMDBW_SS_COPY &&
           text_ok(&s->name, 0, IMDBW_USER - 1);
}

static int sess_get(imdb_rd *r, imdbw_sess *s, uint64_t prev, imdb_err *e)
{
    s->id = imdb_rd_u64(r);
    s->role = imdb_rd_u32(r);
    s->endpoint = imdb_rd_u8(r);
    s->state = imdb_rd_u8(r);
    s->age_ms = imdb_rd_u64(r);
    if (r->err) return bad(e, "a session cut short");
    TRY(text_get(r, 1, 0, IMDBW_USER - 1, &s->name, e));
    if (!sess_ok(s, prev)) return bad(e, "a session's id out of order, or its role, endpoint or state");
    return IMDB_OK;
}

static bool kill_ok(uint8_t kind, uint64_t sid)
{
    return (kind == IMDBW_KILL_CANCEL || kind == IMDBW_KILL_TERMINATE) && sid;
}

static int body_get(uint8_t type, imdb_rd *r, const imdbw_msg *cols, imdbw_msg *m, imdb_err *e)
{
    switch (type) {
    case IMDBW_QUERY: {
        uint32_t n = imdb_rd_u32(r);
        if (r->err || n < 1 || n > IMDBW_BATCH_MAX || n > imdb_rd_left(r) / 7) /* a statement: 7 bytes at least */
            return bad(e, "a QUERY of 1 to 4,096 statements it holds the bytes of");
        if (!(m->texts = imdbw_alloc(n, sizeof *m->texts)) || !(m->params = imdbw_alloc(n, sizeof *m->params)))
            return nomem(e);
        m->ntexts = n;
        for (uint32_t i = 0; i < n; i++) {
            TRY(text_get(r, 4, 1, IMDBW_SQL_MAX, &m->texts[i], e));
            uint16_t nv = imdb_rd_u16(r);
            if (r->err || nv > IMDBW_VALUES_MAX) return bad(e, "a statement's values: at most 256");
            TRY(span_get(r, nv, NULL, &m->params[i], e));
        }
        return IMDB_OK;
    }
    case IMDBW_PREPARE:
        TRY(name_get(r, m->name, e));
        return one_text(r, 4, 1, IMDBW_SQL_MAX, m, e);
    case IMDBW_EXECUTE: {
        TRY(name_get(r, m->name, e));
        m->nsets = imdb_rd_u32(r);
        m->nvals = imdb_rd_u16(r);
        if (r->err || m->nsets < 1 || m->nsets > IMDBW_BATCH_MAX || m->nvals > IMDBW_VALUES_MAX)
            return bad(e, "an EXECUTE of 1 to 4,096 sets of at most 256 values");
        return span_get(r, (uint64_t)m->nsets * m->nvals, NULL, &m->vals, e);
    }
    case IMDBW_DEALLOCATE: return name_get(r, m->name, e);
    case IMDBW_KILL:
        m->kill = imdb_rd_u8(r);
        m->sid = imdb_rd_u64(r);
        if (r->err || !kill_ok(m->kill, m->sid)) return bad(e, "a KILL's kind (1 cancel, 2 terminate) or a session id of 0");
        return IMDB_OK;
    case IMDBW_KILL_DONE:
        m->code = imdb_rd_u8(r);
        m->sid = imdb_rd_u64(r);
        if (r->err || m->code > IMDBW_KILL_NONE || !m->sid) return bad(e, "a KILL_DONE's code or a session id of 0");
        return IMDB_OK;
    case IMDBW_SESSIONS_LIST: {
        uint32_t n = imdb_rd_u32(r);
        if (r->err || n > IMDBW_SESSIONS_MAX || n > imdb_rd_left(r) / IMDBW_SESS_MIN)
            return bad(e, "a SESSIONS_LIST of at most 65,536 sessions it holds the bytes of");
        if (n && !(m->sess = imdbw_alloc(n, sizeof *m->sess))) return nomem(e);
        m->nsess = n;
        for (uint32_t i = 0; i < n; i++) TRY(sess_get(r, &m->sess[i], i ? m->sess[i - 1].id : 0, e));
        return IMDB_OK;
    }
    case IMDBW_COPY_DATA:
    case IMDBW_COPY_OUT:
        m->dlen = (uint32_t)imdb_rd_left(r);
        if (!m->dlen) return bad(e, "a COPY piece of no bytes");
        m->data = imdb_rd_bytes(r, m->dlen);
        return IMDB_OK;
    case IMDBW_COPY_FAIL:
    case IMDBW_WARNING: return one_text(r, 2, 0, IMDBW_MESSAGE_MAX, m, e);
    case IMDBW_SESSIONS:
    case IMDBW_COPY_DONE:
    case IMDBW_CANCEL:
    case IMDBW_PING:
    case IMDBW_TERMINATE:
    case IMDBW_COPY_IN:
    case IMDBW_PONG: return IMDB_OK;
    case IMDBW_COLUMNS: {
        uint16_t n = imdb_rd_u16(r);
        if (r->err || n < 1 || n > IMDBW_VALUES_MAX || n > imdb_rd_left(r) / 7) /* a column: 7 bytes at least */
            return bad(e, "a COLUMNS of 1 to 256 columns it holds the bytes of");
        if (!(m->cols = imdbw_alloc(n, sizeof *m->cols))) return nomem(e);
        m->ncols = n;
        for (uint16_t i = 0; i < n; i++) TRY(col_get(r, &m->cols[i], e));
        int ix = imdbw_cols_index(m);
        if (ix) return ix == -2 ? nomem(e) : bad(e, "an ENUM's labels not distinct");
        return IMDB_OK;
    }
    case IMDBW_ROWS:
        if (!cols || cols->type != IMDBW_COLUMNS || cols->ncols < 1) return bad(e, "a ROWS with no COLUMNS before it");
        m->nsets = imdb_rd_u32(r);
        m->nvals = cols->ncols;
        if (r->err || m->nsets < 1) return bad(e, "a ROWS of no row");
        return span_get(r, (uint64_t)m->nsets * m->nvals, cols, &m->vals, e);
    case IMDBW_DONE: {
        TRY(text_get(r, 2, 0, IMDBW_STATUS_MAX, &m->status, e));
        m->count = imdb_rd_u64(r);
        uint8_t hr = imdb_rd_u8(r);
        if (r->err || hr > 1) return bad(e, "a DONE's read point flag");
        if ((m->has_read = hr)) {
            m->read_commit = imdb_rd_u64(r);
            imdb_rd_copy(r, m->read_hash, 32);
            imdb_rd_copy(r, m->digest, 32);
            m->lake_commit = imdb_rd_u64(r);
            imdb_rd_copy(r, m->lake_manifest, 32);
            imdb_rd_copy(r, m->db_id, 16);
            uint8_t own = imdb_rd_u8(r);
            if (!r->err && own > 1) return bad(e, "a DONE's own-writes flag");
            m->own = own;
        }
        uint8_t hw = imdb_rd_u8(r);
        if (r->err || hw > 1) return bad(e, "a DONE's write flag");
        if ((m->has_write = hw)) {
            m->write_commit = imdb_rd_u64(r);
            imdb_rd_copy(r, m->write_hash, 32);
        }
        if (!r->err && !done_ok(m)) return bad(e, "a DONE's write at commit 0");
        return IMDB_OK;
    }
    case IMDBW_ERROR:
        m->code = imdb_rd_u32(r);
        m->index = imdb_rd_u32(r);
        if (r->err || !m->code || m->index >= IMDBW_BATCH_MAX) return bad(e, "an ERROR's code 0 or its statement's index");
        return one_text(r, 2, 0, IMDBW_MESSAGE_MAX, m, e);
    case IMDBW_READY:
        m->state = imdb_rd_u8(r);
        if (!r->err && m->state > IMDBW_DOOMED) return bad(e, "a READY's state");
        return IMDB_OK;
    default: return bad(e, "a frame of a type the protocol does not define");
    }
}

int imdbw_msg_get(uint8_t type, const uint8_t *body, size_t len, const imdbw_msg *cols, imdbw_msg *m, imdb_err *e)
{
    memset(m, 0, sizeof *m);
    m->type = type;
    imdb_rd r;
    imdb_rd_init(&r, body, len);
    int rc = body_get(type, &r, cols, m, e);
    if (!rc && (r.err || imdb_rd_left(&r))) rc = bad(e, r.err ? "a body cut short" : "a body with bytes past its end");
    if (rc) imdbw_msg_free(m);
    return rc;
}

static void one_text_put(imdbw_buf *b, const imdbw_msg *m, uint32_t max)
{
    if (m->ntexts != 1 || !m->texts) {
        b->err = true;
        return;
    }
    text_put(b, 2, 0, max, &m->texts[0]);
}

void imdbw_msg_put(imdbw_buf *b, const imdbw_msg *m, const imdbw_msg *cols)
{
    size_t at = imdbw_frame_begin(b, m->type);
    switch (m->type) {
    case IMDBW_QUERY:
        if (m->ntexts < 1 || m->ntexts > IMDBW_BATCH_MAX || !m->texts || !m->params) {
            b->err = true;
            break;
        }
        imdbw_put_u32(b, m->ntexts);
        for (uint32_t i = 0; i < m->ntexts; i++) {
            text_put(b, 4, 1, IMDBW_SQL_MAX, &m->texts[i]);
            if (m->params[i].n > IMDBW_VALUES_MAX) b->err = true;
            imdbw_put_u16(b, (uint16_t)m->params[i].n);
            span_put(b, &m->params[i], m->params[i].n, NULL);
        }
        break;
    case IMDBW_PREPARE:
        name_put(b, m->name);
        if (m->ntexts != 1 || !m->texts) b->err = true;
        else text_put(b, 4, 1, IMDBW_SQL_MAX, &m->texts[0]);
        break;
    case IMDBW_EXECUTE:
        name_put(b, m->name);
        if (m->nsets < 1 || m->nsets > IMDBW_BATCH_MAX || m->nvals > IMDBW_VALUES_MAX) b->err = true;
        imdbw_put_u32(b, m->nsets);
        imdbw_put_u16(b, m->nvals);
        span_put(b, &m->vals, (uint64_t)m->nsets * m->nvals, NULL);
        break;
    case IMDBW_DEALLOCATE: name_put(b, m->name); break;
    case IMDBW_COPY_DATA:
    case IMDBW_COPY_OUT:
        if (!m->dlen || !m->data) b->err = true;
        imdbw_put(b, m->data, m->dlen);
        break;
    case IMDBW_COPY_FAIL:
    case IMDBW_WARNING: one_text_put(b, m, IMDBW_MESSAGE_MAX); break;
    case IMDBW_COLUMNS:
        if (m->ncols < 1 || m->ncols > IMDBW_VALUES_MAX || !m->cols) {
            b->err = true;
            break;
        }
        imdbw_put_u16(b, m->ncols);
        for (uint16_t i = 0; i < m->ncols; i++) col_put(b, &m->cols[i]);
        break;
    case IMDBW_ROWS:
        if (m->nsets < 1 || !cols || cols->type != IMDBW_COLUMNS || cols->ncols < 1 || m->nvals != cols->ncols) {
            b->err = true; /* a ROWS against no COLUMNS, or another count of them */
            break;
        }
        imdbw_put_u32(b, m->nsets);
        span_put(b, &m->vals, (uint64_t)m->nsets * m->nvals, cols);
        break;
    case IMDBW_DONE:
        if (!done_ok(m)) b->err = true;
        text_put(b, 2, 0, IMDBW_STATUS_MAX, &m->status);
        imdbw_put_u64(b, m->count);
        imdbw_put_u8(b, m->has_read);
        if (m->has_read) {
            imdbw_put_u64(b, m->read_commit);
            imdbw_put(b, m->read_hash, 32);
            imdbw_put(b, m->digest, 32);
            imdbw_put_u64(b, m->lake_commit);
            imdbw_put(b, m->lake_manifest, 32);
            imdbw_put(b, m->db_id, 16);
            imdbw_put_u8(b, m->own);
        }
        imdbw_put_u8(b, m->has_write);
        if (m->has_write) {
            imdbw_put_u64(b, m->write_commit);
            imdbw_put(b, m->write_hash, 32);
        }
        break;
    case IMDBW_ERROR:
        if (!m->code || m->index >= IMDBW_BATCH_MAX) b->err = true;
        imdbw_put_u32(b, m->code);
        imdbw_put_u32(b, m->index);
        one_text_put(b, m, IMDBW_MESSAGE_MAX);
        break;
    case IMDBW_READY:
        if (m->state > IMDBW_DOOMED) b->err = true;
        imdbw_put_u8(b, m->state);
        break;
    case IMDBW_KILL:
        if (!kill_ok(m->kill, m->sid)) b->err = true;
        imdbw_put_u8(b, m->kill);
        imdbw_put_u64(b, m->sid);
        break;
    case IMDBW_KILL_DONE:
        if (m->code > IMDBW_KILL_NONE || !m->sid) b->err = true;
        imdbw_put_u8(b, (uint8_t)m->code);
        imdbw_put_u64(b, m->sid);
        break;
    case IMDBW_SESSIONS_LIST:
        if (m->nsess > IMDBW_SESSIONS_MAX || (m->nsess && !m->sess)) {
            b->err = true;
            break;
        }
        imdbw_put_u32(b, m->nsess);
        for (uint32_t i = 0; i < m->nsess; i++) {
            const imdbw_sess *s = &m->sess[i];
            if (!sess_ok(s, i ? m->sess[i - 1].id : 0)) b->err = true;
            imdbw_put_u64(b, s->id);
            imdbw_put_u32(b, s->role);
            imdbw_put_u8(b, s->endpoint);
            imdbw_put_u8(b, s->state);
            imdbw_put_u64(b, s->age_ms);
            text_put(b, 1, 0, IMDBW_USER - 1, &s->name);
        }
        break;
    case IMDBW_SESSIONS:
    case IMDBW_COPY_DONE:
    case IMDBW_CANCEL:
    case IMDBW_PING:
    case IMDBW_TERMINATE:
    case IMDBW_COPY_IN:
    case IMDBW_PONG: break;
    default: b->err = true; /* no such frame */
    }
    imdbw_frame_end(b, at);
}

/* ---- ROWS a value at a time: each checked once against its column, then written ---- */

void imdbw_rows_begin(imdbw_rows *w, imdbw_buf *b, const imdbw_msg *cols)
{
    memset(w, 0, sizeof *w);
    w->b = b;
    w->cols = cols;
    if (!cols || cols->type != IMDBW_COLUMNS || cols->ncols < 1) b->err = true;
    w->at = imdbw_frame_begin(b, IMDBW_ROWS);
    imdbw_put_u32(b, 0); /* the count, patched at the end */
}

void imdbw_rows_value(imdbw_rows *w, const imdbw_value *v)
{
    if (w->b->err) return;
    if (!imdbw_value_fits(&w->cols->cols[w->col], v)) {
        w->b->err = true;
        return;
    }
    value_raw(w->b, v);
    if (++w->col == w->cols->ncols) {
        w->col = 0;
        w->n++;
    }
}

void imdbw_rows_end(imdbw_rows *w)
{
    if (!w->n || w->col) w->b->err = true; /* no row, or one left part way */
    imdbw_patch_u32(w->b, w->at + IMDBW_HEAD, w->n);
    imdbw_frame_end(w->b, w->at);
}

size_t imdbw_rows_len(const imdbw_rows *w) { return w->b->len - w->at; }

bool imdbw_rows_whole(const imdbw_rows *w) { return w->col == 0; }
