/* The auditor's own readers of the Iceberg v3 layer (aice.h), from the specifications (Iceberg's spec.md and
 * puffin-spec.md, Avro's, the RoaringFormatSpec), sharing no code with src/. */
#include "aice.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum { AJ_MAX_DEPTH = 32, AJ_MAX_LEN = 1 << 24 };

static void *xalloc(size_t n)
{
    void *p = calloc(n ? n : 1, 1);
    if (!p) {
        fprintf(stderr, "imagedb-audit: out of memory\n");
        exit(2);
    }
    return p;
}

/* ---- JSON --------------------------------------------------------------------------------------------------- */

typedef struct jp {
    const char *p;
    size_t n, at;
    const char *why;
} jp;

static void ws(jp *j)
{
    while (j->at < j->n && (j->p[j->at] == ' ' || j->p[j->at] == '\n' || j->p[j->at] == '\r' || j->p[j->at] == '\t')) j->at++;
}

static int hexv(char c)
{
    return c >= '0' && c <= '9' ? c - '0' : c >= 'a' && c <= 'f' ? c - 'a' + 10 : c >= 'A' && c <= 'F' ? c - 'A' + 10 : -1;
}

/* a string at '"': its bytes, \u escapes below 0x80 and the two-character escapes (the layer's writer escapes no more;
 * a surrogate or a code point past ASCII by \u is refused: one form a string) */
static char *jstr(jp *j)
{
    if (j->at >= j->n || j->p[j->at] != '"') return NULL;
    j->at++;
    size_t cap = 16, k = 0;
    char *s = xalloc(cap);
    while (j->at < j->n && j->p[j->at] != '"') {
        unsigned char c = (unsigned char)j->p[j->at++];
        if (c < 0x20) goto bad;
        if (c == '\\') {
            if (j->at >= j->n) goto bad;
            char e = j->p[j->at++];
            if (e == '"' || e == '\\' || e == '/') c = (unsigned char)e;
            else if (e == 'n') c = '\n';
            else if (e == 't') c = '\t';
            else if (e == 'r') c = '\r';
            else if (e == 'b') c = '\b';
            else if (e == 'f') c = '\f';
            else if (e == 'u') {
                if (j->n - j->at < 4) goto bad;
                int v = 0;
                for (int q = 0; q < 4; q++) {
                    int h = hexv(j->p[j->at + (size_t)q]);
                    if (h < 0) goto bad;
                    v = v << 4 | h;
                }
                j->at += 4;
                if (v == 0 || v >= 0x80) goto bad;
                c = (unsigned char)v;
            } else {
                goto bad;
            }
        }
        if (k + 2 > cap) {
            char *t = xalloc(cap * 2);
            memcpy(t, s, k);
            free(s);
            s = t;
            cap *= 2;
        }
        s[k++] = (char)c;
    }
    if (j->at >= j->n) goto bad;
    j->at++;
    s[k] = 0;
    return s;
bad:
    free(s);
    j->why = "a JSON string that does not parse";
    return NULL;
}

static int jval(jp *j, aj *out, int depth);

static int jmembers(jp *j, aj *out, int depth, bool obj)
{
    size_t cap = 4;
    out->v = xalloc(cap * sizeof *out->v);
    if (obj) out->key = xalloc(cap * sizeof *out->key);
    j->at++;
    ws(j);
    if (j->at < j->n && j->p[j->at] == (obj ? '}' : ']')) {
        j->at++;
        return 0;
    }
    for (;;) {
        if (out->n == cap) {
            aj *nv = xalloc(cap * 2 * sizeof *nv);
            memcpy(nv, out->v, cap * sizeof *nv);
            free(out->v);
            out->v = nv;
            if (obj) {
                char **nk = xalloc(cap * 2 * sizeof *nk);
                memcpy(nk, out->key, cap * sizeof *nk);
                free(out->key);
                out->key = nk;
            }
            cap *= 2;
        }
        ws(j);
        if (obj) {
            char *k = jstr(j);
            if (!k) return -1;
            out->key[out->n] = k;
            ws(j);
            if (j->at >= j->n || j->p[j->at] != ':') {
                out->n++; /* freed with the object */
                out->v[out->n - 1].kind = AJ_NULL;
                j->why = "a JSON object member without its value";
                return -1;
            }
            j->at++;
        }
        if (jval(j, &out->v[out->n], depth + 1)) {
            out->n++;
            return -1;
        }
        out->n++;
        ws(j);
        if (j->at < j->n && j->p[j->at] == ',') {
            j->at++;
            continue;
        }
        if (j->at < j->n && j->p[j->at] == (obj ? '}' : ']')) {
            j->at++;
            return 0;
        }
        j->why = "a JSON object or array that does not close";
        return -1;
    }
}

static int jval(jp *j, aj *out, int depth)
{
    memset(out, 0, sizeof *out);
    if (depth > AJ_MAX_DEPTH) {
        j->why = "JSON nested too deep";
        return -1;
    }
    ws(j);
    if (j->at >= j->n) {
        j->why = "a JSON value missing";
        return -1;
    }
    char c = j->p[j->at];
    if (c == '{' || c == '[') {
        out->kind = c == '{' ? AJ_OBJ : AJ_ARR;
        return jmembers(j, out, depth, c == '{');
    }
    if (c == '"') {
        out->kind = AJ_STR;
        out->s = jstr(j);
        return out->s ? 0 : -1;
    }
    static const struct {
        const char *w;
        int kind, v;
    } lit[] = {{"true", AJ_BOOL, 1}, {"false", AJ_BOOL, 0}, {"null", AJ_NULL, 0}};
    for (size_t k = 0; k < 3; k++) {
        size_t l = strlen(lit[k].w);
        if (j->n - j->at >= l && !memcmp(j->p + j->at, lit[k].w, l)) {
            out->kind = lit[k].kind;
            out->i = lit[k].v;
            j->at += l;
            return 0;
        }
    }
    /* a number: an integer without a fraction or exponent is AJ_INT (within int64), any other its text */
    size_t s = j->at;
    if (j->at < j->n && j->p[j->at] == '-') j->at++;
    size_t d0 = j->at;
    while (j->at < j->n && j->p[j->at] >= '0' && j->p[j->at] <= '9') j->at++;
    if (j->at == d0 || (j->p[d0] == '0' && j->at - d0 > 1)) {
        j->why = "a JSON value that does not parse";
        return -1;
    }
    bool integral = true;
    if (j->at < j->n && j->p[j->at] == '.') {
        integral = false;
        j->at++;
        size_t f0 = j->at;
        while (j->at < j->n && j->p[j->at] >= '0' && j->p[j->at] <= '9') j->at++;
        if (j->at == f0) goto badnum;
    }
    if (j->at < j->n && (j->p[j->at] == 'e' || j->p[j->at] == 'E')) {
        integral = false;
        j->at++;
        if (j->at < j->n && (j->p[j->at] == '+' || j->p[j->at] == '-')) j->at++;
        size_t e0 = j->at;
        while (j->at < j->n && j->p[j->at] >= '0' && j->p[j->at] <= '9') j->at++;
        if (j->at == e0) goto badnum;
    }
    out->s = xalloc(j->at - s + 1);
    memcpy(out->s, j->p + s, j->at - s);
    if (integral) {
        /* within int64: at most 19 digits, and a 19-digit one compared as text */
        size_t nd = j->at - d0;
        bool neg = j->p[s] == '-';
        if (nd > 19 || (nd == 19 && strcmp(out->s + neg, neg ? "9223372036854775808" : "9223372036854775807") > 0)) {
            out->kind = AJ_NUM;
            return 0;
        }
        uint64_t u = 0;
        for (size_t q = d0; q < j->at; q++) u = u * 10 + (uint64_t)(j->p[q] - '0');
        out->kind = AJ_INT;
        out->i = neg ? (int64_t)(0 - u) : (int64_t)u;
        return 0;
    }
    out->kind = AJ_NUM;
    return 0;
badnum:
    j->why = "a JSON number that does not parse";
    return -1;
}

int aj_parse(const char *p, size_t len, aj *out, const char **why)
{
    memset(out, 0, sizeof *out);
    if (len > AJ_MAX_LEN) {
        *why = "a JSON text past 16 MiB";
        return -1;
    }
    jp j = {p, len, 0, NULL};
    int rc = jval(&j, out, 0);
    if (!rc) {
        ws(&j);
        if (j.at != j.n) {
            j.why = "bytes after the JSON value";
            rc = -1;
        }
    }
    if (rc) {
        *why = j.why ? j.why : "JSON that does not parse";
        aj_free(out);
    }
    return rc;
}

const aj *aj_get(const aj *o, const char *key)
{
    if (!o || o->kind != AJ_OBJ) return NULL;
    for (size_t k = 0; k < o->n; k++)
        if (o->key[k] && !strcmp(o->key[k], key)) return &o->v[k];
    return NULL;
}

void aj_free(aj *a)
{
    if (!a) return;
    for (size_t k = 0; k < a->n; k++) {
        if (a->key) free(a->key[k]);
        if (a->v) aj_free(&a->v[k]);
    }
    free(a->v);
    free(a->key);
    free(a->s);
    memset(a, 0, sizeof *a);
}

/* ---- Avro --------------------------------------------------------------------------------------------------- */

int64_t ar_long(arr *r)
{
    uint64_t z = 0;
    for (int shift = 0; shift < 70; shift += 7) {
        if (r->at >= r->n) {
            r->bad = true;
            return 0;
        }
        uint8_t b = r->p[r->at++];
        if (shift == 63 && (b & 0x7e)) { /* past 64 bits */
            r->bad = true;
            return 0;
        }
        z |= (uint64_t)(b & 0x7f) << shift;
        if (!(b & 0x80)) {
            if (shift && !b) r->bad = true; /* a varint's one form: no trailing zero group */
            return (int64_t)(z >> 1) ^ -(int64_t)(z & 1);
        }
    }
    r->bad = true;
    return 0;
}

const uint8_t *ar_bytes(arr *r, size_t *len)
{
    int64_t l = ar_long(r);
    if (r->bad || l < 0 || (uint64_t)l > r->n - r->at) {
        r->bad = true;
        *len = 0;
        return NULL;
    }
    const uint8_t *p = r->p + r->at;
    r->at += (size_t)l;
    *len = (size_t)l;
    return p;
}

int aocf_read(const uint8_t *f, size_t len, aocf *out, const char **why)
{
    memset(out, 0, sizeof *out);
    if (len < 4 || memcmp(f, "Obj\x01", 4)) {
        *why = "not an Avro object container file";
        return -1;
    }
    arr r = {f, len, 4, false};
    int64_t nm = ar_long(&r);
    if (r.bad || nm < 1 || nm > 16) { /* one block of pairs, then 0 */
        *why = "an Avro file's metadata map out of bounds";
        return -1;
    }
    for (int64_t k = 0; k < nm; k++) {
        out->mkey[k] = ar_bytes(&r, &out->mklen[k]);
        out->mval[k] = ar_bytes(&r, &out->mvlen[k]);
    }
    out->nmeta = (uint32_t)nm;
    if (ar_long(&r) != 0 || r.bad || r.n - r.at < 16) {
        *why = "an Avro file's metadata map that does not end";
        return -1;
    }
    const uint8_t *sync = r.p + r.at;
    r.at += 16;
    int64_t nrec = ar_long(&r), size = ar_long(&r);
    if (r.bad || nrec < 0 || size < 0 || (uint64_t)size > r.n - r.at || r.n - r.at - (size_t)size != 16 ||
        memcmp(r.p + r.at + (size_t)size, sync, 16)) {
        *why = "an Avro file not of one block ended by its marker";
        return -1;
    }
    const uint8_t *codec;
    size_t cl;
    if (!(codec = aocf_meta(out, "avro.codec", &cl)) || cl != 4 || memcmp(codec, "null", 4)) {
        *why = "an Avro file of another codec than null";
        return -1;
    }
    out->nrec = (uint64_t)nrec;
    out->records = r.p + r.at;
    out->rlen = (size_t)size;
    return 0;
}

const uint8_t *aocf_meta(const aocf *o, const char *key, size_t *len)
{
    size_t kl = strlen(key);
    for (uint32_t k = 0; k < o->nmeta; k++)
        if (o->mklen[k] == kl && !memcmp(o->mkey[k], key, kl)) {
            *len = o->mvlen[k];
            return o->mval[k];
        }
    return NULL;
}

/* ---- Puffin ------------------------------------------------------------------------------------------------- */

static uint32_t le32(const uint8_t *p) { return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24; }
static uint32_t be32(const uint8_t *p) { return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | (uint32_t)p[3]; }
static uint16_t le16(const uint8_t *p) { return (uint16_t)(p[0] | p[1] << 8); }

int apuf_read(const uint8_t *f, size_t len, aj *footer, const char **why)
{
    memset(footer, 0, sizeof *footer);
    if (len < 4 + 4 + 12 || memcmp(f, "PFA1", 4) || memcmp(f + len - 4, "PFA1", 4)) {
        *why = "not a Puffin file";
        return -1;
    }
    uint32_t fl = le32(f + len - 12);
    if (le32(f + len - 8) != 0) {
        *why = "a Puffin footer's flags not zero (a compressed footer is not read)";
        return -1;
    }
    if (fl > len - 4 - 4 - 12 || memcmp(f + len - 12 - fl - 4, "PFA1", 4)) {
        *why = "a Puffin footer out of place";
        return -1;
    }
    return aj_parse((const char *)f + len - 12 - fl, fl, footer, why);
}

/* the CRC-32 the blob carries (ISO-HDLC), the auditor's own */
static uint32_t crc32_iso(const uint8_t *p, size_t n)
{
    uint32_t c = 0xffffffffu;
    for (size_t i = 0; i < n; i++) {
        c ^= p[i];
        for (int k = 0; k < 8; k++) c = (c >> 1) ^ (0xedb88320u & -(c & 1u));
    }
    return ~c;
}

/* one 32-bit roaring bitmap at b (cookie 12346: no run containers; the layer's form), its values high:low appended */
static int rb32(const uint8_t *b, size_t len, uint64_t high, uint64_t **pos, size_t *n, size_t *cap, size_t *used,
                const char **why)
{
    *why = "a 32-bit roaring bitmap that does not read";
    if (len < 8 || le32(b) != 12346) return -1;
    uint32_t nc = le32(b + 4);
    if (nc > 65536 || (size_t)nc * 8 > len - 8) return -1;
    size_t end = 8 + 8 * (size_t)nc;
    int64_t last_key = -1;
    for (uint32_t c = 0; c < nc; c++) {
        uint16_t key = le16(b + 8 + 4 * (size_t)c);
        uint32_t card = (uint32_t)le16(b + 10 + 4 * (size_t)c) + 1;
        uint32_t off = le32(b + 8 + 4 * (size_t)nc + 4 * (size_t)c);
        if ((int64_t)key <= last_key || off != end) return -1; /* keys ascending, containers in place, no gap */
        last_key = key;
        size_t sz = card <= 4096 ? 2 * (size_t)card : 8192;
        if (sz > len - off) return -1;
        if (*n + card > *cap) {
            size_t nc2 = (*n + card) * 2;
            uint64_t *np = xalloc(nc2 * sizeof *np);
            if (*n) memcpy(np, *pos, *n * sizeof *np);
            free(*pos);
            *pos = np;
            *cap = nc2;
        }
        if (card <= 4096) {
            int32_t prev = -1;
            for (uint32_t i = 0; i < card; i++) {
                uint16_t v = le16(b + off + 2 * (size_t)i);
                if ((int32_t)v <= prev) return -1;
                prev = v;
                (*pos)[(*n)++] = high << 32 | (uint64_t)key << 16 | v;
            }
        } else {
            uint32_t cnt = 0;
            for (uint32_t w = 0; w < 1024; w++)
                for (int k = 0; k < 64; k++)
                    if (b[off + 8 * (size_t)w + (size_t)k / 8] >> (k % 8) & 1) {
                        if (cnt++ < card) (*pos)[(*n)++] = high << 32 | (uint64_t)key << 16 | (uint64_t)(w * 64 + (uint32_t)k);
                    }
            if (cnt != card) return -1; /* the descriptive header's cardinality is the bitset's */
        }
        end = off + sz;
    }
    *used = end;
    return 0;
}

int adv_read(const uint8_t *b, size_t len, uint64_t **pos, size_t *n, const char **why)
{
    *pos = NULL;
    *n = 0;
    if (len < 12 || be32(b) != len - 8 || memcmp(b + 4, "\xd1\xd3\x39\x64", 4)) {
        *why = "a deletion-vector-v1 blob's length or magic";
        return -1;
    }
    if (crc32_iso(b + 4, len - 8) != be32(b + len - 4)) {
        *why = "a deletion-vector-v1 blob's CRC-32";
        return -1;
    }
    const uint8_t *v = b + 8;
    size_t vl = len - 12;
    if (vl < 8) {
        *why = "a 64-bit roaring bitmap without its count";
        return -1;
    }
    uint64_t nk = 0;
    for (int k = 7; k >= 0; k--) nk = nk << 8 | v[k];
    size_t at = 8, cap = 0;
    int64_t last = -1;
    for (uint64_t k = 0; k < nk; k++) {
        if (vl - at < 4) {
            *why = "a 64-bit roaring bitmap cut short";
            free(*pos);
            *pos = NULL;
            return -1;
        }
        uint32_t high = le32(v + at);
        if ((int64_t)high <= last || high >> 31) {
            *why = "a 64-bit roaring bitmap's keys not ascending below 2^31";
            free(*pos);
            *pos = NULL;
            return -1;
        }
        last = high;
        size_t used = 0;
        if (rb32(v + at + 4, vl - at - 4, high, pos, n, &cap, &used, why)) {
            free(*pos);
            *pos = NULL;
            return -1;
        }
        at += 4 + used;
    }
    if (at != vl) {
        *why = "bytes after a 64-bit roaring bitmap";
        free(*pos);
        *pos = NULL;
        return -1;
    }
    return 0;
}
