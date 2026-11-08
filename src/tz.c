/* P2's zone slice: the TZif reader (RFC 8536) and a zone's two conversions (tz.h; design.md §5, Time zones). The file
 * is untrusted input: every field is read through imdb_rd, bounded by limits.h before anything is allocated. */
#include "tz.h"

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <unistd.h>

#include "fsio.h"

static uint32_t rd_be32(imdb_rd *r)
{
    const uint8_t *p = imdb_rd_bytes(r, 4);
    return p ? (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | p[3] : 0;
}

static int64_t rd_be64(imdb_rd *r)
{
    const uint8_t *p = imdb_rd_bytes(r, 8);
    uint64_t v = 0;
    for (int i = 0; p && i < 8; i++) v = v << 8 | p[i];
    return (int64_t)v;
}

bool imdb_tz_name_ok(const char *s, size_t n)
{
    if (!n || n > IMDB_MAX_TZ_NAME || s[0] == '/' || s[n - 1] == '/') return false;
    for (size_t i = 0; i < n; i++) {
        char c = s[i];
        if (c == '/') {
            if (s[i + 1] == '/') return false; /* an empty component */
            continue;
        }
        /* no '.': a component can never be . or .., nor a name a dot-file */
        if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_' || c == '-' || c == '+'))
            return false;
    }
    return true;
}

/* ---- the civil calendar (proleptic Gregorian, days since 1970-01-01) -------------------------------------------- */

static int64_t days_from_civil(int64_t y, int m, int d)
{
    y -= m <= 2;
    int64_t era = (y >= 0 ? y : y - 399) / 400;
    int64_t yoe = y - era * 400;
    int64_t doy = (153 * (m + (m > 2 ? -3 : 9)) + 2) / 5 + d - 1;
    int64_t doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    return era * 146097 + doe - 719468;
}

static int64_t year_of_days(int64_t z)
{
    z += 719468;
    int64_t era = (z >= 0 ? z : z - 146096) / 146097;
    int64_t doe = z - era * 146097;
    int64_t yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    int64_t doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    int64_t mp = (5 * doy + 2) / 153;
    int64_t m = mp + (mp < 10 ? 3 : -9);
    return yoe + era * 400 + (m <= 2);
}

static bool leap(int64_t y) { return (y % 4 == 0 && y % 100 != 0) || y % 400 == 0; }

static int month_days(int64_t y, int m)
{
    static const int d[12] = {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
    return m == 2 && leap(y) ? 29 : d[m - 1];
}

static int64_t floor_div(int64_t a, int64_t b) { return a / b - ((a % b != 0) && ((a < 0) != (b < 0))); }

/* ---- the footer's POSIX TZ string -------------------------------------------------------------------------- */

typedef struct tzlex {
    const char *s;
    size_t n, i;
} tzlex;

static bool lx_digits(tzlex *x, int maxd, int *out)
{
    int v = 0, k = 0;
    while (x->i < x->n && x->s[x->i] >= '0' && x->s[x->i] <= '9' && k < maxd) v = v * 10 + (x->s[x->i++] - '0'), k++;
    *out = v;
    return k > 0;
}

/* a name: <...> of letters, digits, + and -, or three or more letters */
static bool lx_name(tzlex *x)
{
    size_t k = 0;
    if (x->i < x->n && x->s[x->i] == '<') {
        x->i++;
        while (x->i < x->n && x->s[x->i] != '>') {
            char c = x->s[x->i++];
            if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '+' || c == '-'))
                return false;
            k++;
        }
        if (x->i >= x->n) return false;
        x->i++;
        return k >= 3;
    }
    while (x->i < x->n && ((x->s[x->i] >= 'A' && x->s[x->i] <= 'Z') || (x->s[x->i] >= 'a' && x->s[x->i] <= 'z'))) x->i++, k++;
    return k >= 3;
}

/* [+-]hh[:mm[:ss]] in seconds, hours at most maxh (an offset 24, a rule's time 167: RFC 8536) */
static bool lx_hms(tzlex *x, int maxh, int32_t *out)
{
    int sign = 1, h, m = 0, s = 0;
    if (x->i < x->n && (x->s[x->i] == '+' || x->s[x->i] == '-')) sign = x->s[x->i++] == '-' ? -1 : 1;
    if (!lx_digits(x, 3, &h) || h > maxh) return false;
    if (x->i < x->n && x->s[x->i] == ':') {
        x->i++;
        if (!lx_digits(x, 2, &m) || m > 59) return false;
        if (x->i < x->n && x->s[x->i] == ':') {
            x->i++;
            if (!lx_digits(x, 2, &s) || s > 59) return false;
        }
    }
    *out = sign * (h * 3600 + m * 60 + s);
    return true;
}

static bool lx_when(tzlex *x, imdb_tzwhen *w)
{
    memset(w, 0, sizeof *w);
    int a, b, c;
    if (x->i < x->n && x->s[x->i] == 'J') {
        x->i++;
        if (!lx_digits(x, 3, &a) || a < 1 || a > 365) return false;
        w->kind = 'J';
        w->a = (int16_t)a;
    } else if (x->i < x->n && x->s[x->i] == 'M') {
        x->i++;
        if (!lx_digits(x, 2, &a) || a < 1 || a > 12 || x->i >= x->n || x->s[x->i++] != '.' || !lx_digits(x, 1, &b) ||
            b < 1 || b > 5 || x->i >= x->n || x->s[x->i++] != '.' || !lx_digits(x, 1, &c) || c > 6)
            return false;
        w->kind = 'M';
        w->a = (int16_t)a, w->b = (int16_t)b, w->c = (int16_t)c;
    } else {
        if (!lx_digits(x, 3, &a) || a > 365) return false;
        w->kind = 'D';
        w->a = (int16_t)a;
    }
    w->time = 7200; /* 02:00:00 when none is written */
    if (x->i < x->n && x->s[x->i] == '/') {
        x->i++;
        if (!lx_hms(x, 167, &w->time)) return false;
    }
    return true;
}

int imdb_tz_rule_parse(const char *s, size_t n, imdb_tzrule *r, imdb_err *e)
{
    memset(r, 0, sizeof *r);
    tzlex x = {s, n, 0};
    int32_t off;
    if (!lx_name(&x) || !lx_hms(&x, 24, &off)) return imdb_fail(e, IMDB_ERR_CORRUPT, "zone file: a bad footer rule");
    r->std_off = -off; /* POSIX counts west */
    if (x.i == x.n) return IMDB_OK;
    if (!lx_name(&x)) return imdb_fail(e, IMDB_ERR_CORRUPT, "zone file: a bad footer rule");
    r->has_dst = true;
    r->dst_off = r->std_off + 3600;
    if (x.i < x.n && x.s[x.i] != ',') {
        if (!lx_hms(&x, 24, &off)) return imdb_fail(e, IMDB_ERR_CORRUPT, "zone file: a bad footer rule");
        r->dst_off = -off;
    }
    /* a daylight time is given with its two rules (RFC 8536 requires them in a footer) */
    if (x.i >= x.n || x.s[x.i++] != ',' || !lx_when(&x, &r->start) || x.i >= x.n || x.s[x.i++] != ',' ||
        !lx_when(&x, &r->end) || x.i != x.n)
        return imdb_fail(e, IMDB_ERR_CORRUPT, "zone file: a bad footer rule");
    return IMDB_OK;
}

/* the day (since 1970-01-01) a rule's date falls on in year y */
static int64_t when_day(const imdb_tzwhen *w, int64_t y)
{
    int64_t jan1 = days_from_civil(y, 1, 1);
    if (w->kind == 'J') return jan1 + (w->a - 1) + (leap(y) && w->a >= 60); /* Feb 29 never counted */
    if (w->kind == 'D') return jan1 + w->a;
    int64_t first = days_from_civil(y, w->a, 1);
    int dow = (int)(((first % 7) + 7 + 4) % 7); /* 1970-01-01 was a Thursday */
    int64_t d = first + (w->c - dow + 7) % 7 + 7 * (w->b - 1);
    while (d >= first + month_days(y, w->a)) d -= 7; /* week 5: the last */
    return d;
}

/* a rule's transitions in years y0..y1 (at most four), in time order: instant (UTC seconds) and the offset from it on.
 * Sorted, stably, because a rule's time may reach into the next year (RFC 8536 3.3.1: up to 167 hours); two at one
 * instant are one, the later in the list (a year's end that is the next year's start: "DST all year", 0/0,J365/25),
 * since the interval between them holds no instant and maps no local time */
static int rule_trans(const imdb_tzrule *r, int64_t y0, int64_t y1, int64_t *at, int32_t *off)
{
    int k = 0;
    for (int64_t y = y0; y <= y1; y++) {
        at[k] = when_day(&r->start, y) * 86400 + r->start.time - r->std_off, off[k++] = r->dst_off; /* standard time */
        at[k] = when_day(&r->end, y) * 86400 + r->end.time - r->dst_off, off[k++] = r->std_off;     /* daylight time */
    }
    for (int i = 1; i < k; i++)
        for (int j = i; j > 0 && at[j - 1] > at[j]; j--) {
            int64_t ta = at[j];
            at[j] = at[j - 1], at[j - 1] = ta;
            int32_t to = off[j];
            off[j] = off[j - 1], off[j - 1] = to;
        }
    int m = 0;
    for (int i = 0; i < k; i++) {
        if (m && at[m - 1] == at[i]) m--;
        at[m] = at[i], off[m++] = off[i];
    }
    return m;
}

/* the rule's offset at instant t (seconds) */
static int32_t rule_offset(const imdb_tzrule *r, int64_t t)
{
    if (!r->has_dst) return r->std_off;
    int64_t y = year_of_days(floor_div(t + r->std_off, 86400)), at[8];
    int32_t off[8];
    int k = rule_trans(r, y - 2, y + 1, at, off);
    int32_t o = r->std_off;
    for (int i = 0; i < k; i++)
        if (at[i] <= t) o = off[i];
    return o;
}

/* ---- the file ------------------------------------------------------------------------------------------------ */

void imdb_tz_free(imdb_tz *z)
{
    imdb_free(z->at);
    imdb_free(z->off);
    imdb_free(z->lat);
    memset(z, 0, sizeof *z);
}

void imdb_tz_utc(imdb_tz *z)
{
    memset(z, 0, sizeof *z);
    memcpy(z->name, "UTC", 4);
    z->lat_sorted = true;
}

int imdb_tz_parse(const uint8_t *b, size_t len, imdb_tz *z, imdb_err *e)
{
    memset(z, 0, sizeof *z);
    if (len > IMDB_MAX_TZ_FILE) return imdb_fail(e, IMDB_ERR_LIMIT, "zone file of more than %u bytes", IMDB_MAX_TZ_FILE);
    imdb_rd r;
    imdb_rd_init(&r, b, len);
    const uint8_t *h = imdb_rd_bytes(&r, 20);
    if (!h || memcmp(h, "TZif", 4) != 0) return imdb_fail(e, IMDB_ERR_CORRUPT, "zone file: not a TZif file");
    uint8_t ver = h[4];
    if (ver == 0) return imdb_fail(e, IMDB_ERR_UNSUPPORTED, "zone file: version 1 (no 64-bit section)");
    if (ver < '2' || ver > '4') return imdb_fail(e, IMDB_ERR_CORRUPT, "zone file: an unknown version");
    for (int i = 5; i < 20; i++)
        if (h[i]) return imdb_fail(e, IMDB_ERR_CORRUPT, "zone file: reserved bytes not zero");
    uint32_t c[6];
    for (int i = 0; i < 6; i++) c[i] = rd_be32(&r); /* isut, isstd, leap, time, type, char */
    if (r.err) return imdb_fail(e, IMDB_ERR_CORRUPT, "zone file: truncated");
    /* the version 1 block, passed over (each count is bounded by the file's length before it is multiplied) */
    uint64_t v1 = 5ull * c[3] + 6ull * c[4] + c[5] + 8ull * c[2] + c[1] + c[0];
    if (c[3] > len || c[4] > len || c[5] > len || c[2] > len || v1 > imdb_rd_left(&r) || !imdb_rd_bytes(&r, (size_t)v1))
        return imdb_fail(e, IMDB_ERR_CORRUPT, "zone file: truncated");
    h = imdb_rd_bytes(&r, 20);
    if (!h || memcmp(h, "TZif", 4) != 0 || h[4] != ver) return imdb_fail(e, IMDB_ERR_CORRUPT, "zone file: no 64-bit section");
    for (int i = 5; i < 20; i++)
        if (h[i]) return imdb_fail(e, IMDB_ERR_CORRUPT, "zone file: reserved bytes not zero");
    for (int i = 0; i < 6; i++) c[i] = rd_be32(&r);
    uint32_t isut = c[0], isstd = c[1], nleap = c[2], nt = c[3], ntype = c[4], nchar = c[5];
    if (r.err) return imdb_fail(e, IMDB_ERR_CORRUPT, "zone file: truncated");
    if (nleap) return imdb_fail(e, IMDB_ERR_UNSUPPORTED, "zone file: leap seconds (a right/ zone): timestamps count none");
    if (nt > IMDB_MAX_TZ_TRANSITIONS || !ntype || ntype > IMDB_MAX_TZ_TYPES || !nchar ||
        (isut && isut != ntype) || (isstd && isstd != ntype))
        return imdb_fail(e, IMDB_ERR_CORRUPT, "zone file: bad counts");
    if (9ull * nt + 6ull * ntype + nchar + isstd + isut > imdb_rd_left(&r))
        return imdb_fail(e, IMDB_ERR_CORRUPT, "zone file: truncated");
    int32_t toff[IMDB_MAX_TZ_TYPES] = {0};
    z->n = nt;
    if (nt && (!(z->at = imdb_alloc_array(nt, sizeof *z->at, e)) || !(z->off = imdb_alloc_array(nt, sizeof *z->off, e)) ||
               !(z->lat = imdb_alloc_array(nt, sizeof *z->lat, e)))) {
        int rc = e->code;
        imdb_tz_free(z);
        return rc;
    }
    int rc = IMDB_OK;
    for (uint32_t i = 0; i < nt; i++) {
        z->at[i] = rd_be64(&r);
        /* increasing, and within 2^60 seconds of 1970 (zic's earliest is -2^59), so at + off never overflows */
        if ((i && z->at[i] <= z->at[i - 1]) || z->at[i] < -(INT64_C(1) << 60) || z->at[i] > (INT64_C(1) << 60))
            rc = IMDB_ERR_CORRUPT;
    }
    const uint8_t *idx = imdb_rd_bytes(&r, nt);
    for (uint32_t t = 0; t < ntype; t++) {
        int32_t u = (int32_t)rd_be32(&r);
        uint8_t dst = imdb_rd_u8(&r), di = imdb_rd_u8(&r);
        /* RFC 8536 3.2: more than -25 hours and less than 26 */
        if (u < -89999 || u > 93599 || dst > 1 || di >= nchar) rc = IMDB_ERR_CORRUPT;
        toff[t] = u;
    }
    const uint8_t *chars = imdb_rd_bytes(&r, nchar);
    if (!chars || chars[nchar - 1] != 0) rc = IMDB_ERR_CORRUPT; /* every designation ends within */
    const uint8_t *st = imdb_rd_bytes(&r, isstd), *ut = imdb_rd_bytes(&r, isut);
    for (uint32_t t = 0; st && ut && t < ntype; t++) {
        uint8_t sv = isstd ? st[t] : 0, uv = isut ? ut[t] : 0;
        if (sv > 1 || uv > 1 || (uv && !sv)) rc = IMDB_ERR_CORRUPT; /* a UT indicator needs its standard one */
    }
    for (uint32_t i = 0; i < nt; i++) {
        if (!idx || idx[i] >= ntype) {
            rc = IMDB_ERR_CORRUPT;
            break;
        }
        z->off[i] = toff[idx[i]];
        z->lat[i] = z->at[i] + z->off[i];
    }
    z->off0 = toff[0]; /* time type 0, before the first transition (RFC 8536 3.2) */
    /* the footer: "\n", a POSIX TZ string of printable ASCII, "\n", and nothing after */
    if (r.err || imdb_rd_u8(&r) != '\n') rc = IMDB_ERR_CORRUPT;
    size_t fl = imdb_rd_left(&r);
    const uint8_t *fs = imdb_rd_bytes(&r, fl);
    if (!fs || !fl || fs[fl - 1] != '\n') rc = IMDB_ERR_CORRUPT;
    for (size_t i = 0; !rc && i + 1 < fl; i++)
        if (fs[i] < 0x20 || fs[i] > 0x7e) rc = IMDB_ERR_CORRUPT;
    if (rc) {
        imdb_tz_free(z);
        return imdb_fail(e, IMDB_ERR_CORRUPT, "zone file: malformed");
    }
    if (fl > 1) {
        if ((rc = imdb_tz_rule_parse((const char *)fs, fl - 1, &z->rule, e))) {
            imdb_tz_free(z);
            return rc;
        }
        z->has_rule = true;
    }
    z->lat_sorted = true;
    for (uint32_t i = 1; i < nt; i++)
        if (z->lat[i] <= z->lat[i - 1]) z->lat_sorted = false;
    return IMDB_OK;
}

/* ---- the conversions -------------------------------------------------------------------------------------------- */

int32_t imdb_tz_offset(const imdb_tz *z, int64_t t_us)
{
    int64_t t = floor_div(t_us, 1000000);
    if (z->n && t < z->at[0]) return z->off0;
    if (!z->n || t >= z->at[z->n - 1]) /* past the last transition: the footer's rule, if any */
        return z->has_rule ? rule_offset(&z->rule, t) : z->n ? z->off[z->n - 1] : z->off0;
    uint32_t lo = 0, hi = z->n; /* the last at[i] <= t */
    while (hi - lo > 1) {
        uint32_t mid = lo + (hi - lo) / 2;
        if (z->at[mid] <= t) lo = mid;
        else hi = mid;
    }
    return z->off[lo];
}

int64_t imdb_tz_utc_of_local(const imdb_tz *z, int64_t l_us)
{
    int64_t l = floor_div(l_us, 1000000);
    int32_t o;
    if (z->n && l < z->lat[z->n - 1]) { /* among the file's transitions: the last whose local start is at or before l */
        o = z->off0;
        if (z->lat_sorted) {
            uint32_t lo = 0, hi = z->n - 1;
            if (z->lat[0] <= l) {
                while (hi - lo > 1) {
                    uint32_t mid = lo + (hi - lo) / 2;
                    if (z->lat[mid] <= l) lo = mid;
                    else hi = mid;
                }
                o = z->off[lo];
            }
        } else {
            for (uint32_t i = 0; i + 1 < z->n; i++)
                if (z->lat[i] <= l) o = z->off[i];
        }
    } else {
        /* at or past the last transition's local start: it holds, then the footer's rule from the instant after it
         * (a zone with no transitions: the rule, or type 0) */
        int64_t base_t = z->n ? z->at[z->n - 1] : INT64_MIN;
        o = z->n ? z->off[z->n - 1] : z->has_rule ? z->rule.std_off : z->off0;
        if (z->has_rule && z->rule.has_dst) {
            int64_t y = year_of_days(floor_div(l, 86400)), at[8];
            int32_t off[8];
            int k = rule_trans(&z->rule, y - 2, y + 1, at, off);
            if (!z->n) o = rule_offset(&z->rule, at[0] - 1); /* the state before the first of them */
            for (int i = 0; i < k; i++)
                if (at[i] > base_t && at[i] + off[i] <= l) o = off[i];
        }
    }
    return l_us - (int64_t)o * 1000000;
}

/* ---- loading: a name under the operator's zoneinfo directory --------------------------------------------------- */

/* the file name names beneath rootfd: openat2 resolves it there and never out (an alias, a symlink inside the tree,
 * followed; an absolute one, as localtime, or one climbing out refused); where the kernel or a sandbox has no openat2,
 * a walk of the components, each opened O_NOFOLLOW, so an alias is then refused (ELOOP) */
static int open_zone(int rootfd, const char *name)
{
    int fd = imdb_io_openat_beneath(rootfd, name, O_RDONLY | O_CLOEXEC);
    if (fd >= 0 || errno != ENOSYS) return fd;
    char comp[IMDB_MAX_TZ_NAME + 1];
    int dfd = rootfd;
    for (const char *p = name;;) {
        const char *sl = strchr(p, '/');
        size_t cl = sl ? (size_t)(sl - p) : strlen(p);
        memcpy(comp, p, cl);
        comp[cl] = 0;
        int nfd = imdb_io_openat(dfd, comp, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | (sl ? O_DIRECTORY : 0));
        int err = errno;
        if (dfd != rootfd) close(dfd);
        if (nfd < 0) {
            errno = err;
            return -1;
        }
        if (!sl) return nfd;
        dfd = nfd;
        p = sl + 1;
    }
}

int imdb_tz_load(const char *root, const char *name, size_t len, imdb_tz **out, imdb_err *e)
{
    *out = NULL;
    if (!imdb_tz_name_ok(name, len))
        return imdb_fail(e, IMDB_ERR_INVALID, "a time zone is named by letters, digits and / _ - + (at most %u bytes, no "
                                              "empty, . or .. part)", IMDB_MAX_TZ_NAME);
    char nm[IMDB_MAX_TZ_NAME + 1];
    memcpy(nm, name, len);
    nm[len] = 0;
    int rfd = imdb_io_open(root, O_RDONLY | O_DIRECTORY | O_CLOEXEC); /* the operator's: it may be a symlink */
    if (rfd < 0) return imdb_fail(e, IMDB_ERR_IO, "the zoneinfo directory (--zoneinfo) cannot be opened: %s", strerror(errno));
    int fd = open_zone(rfd, nm), err = errno;
    close(rfd);
    if (fd < 0) {
        if (err == ENOENT || err == ENOTDIR || err == EXDEV || err == ELOOP)
            return imdb_fail(e, IMDB_ERR_INVALID, "unknown time zone (none of that name in the zoneinfo directory%s)",
                             err == ELOOP ? "; an alias needs openat2: name the zone it links to" : "");
        return imdb_fail(e, IMDB_ERR_IO, "a time zone file cannot be opened: %s", strerror(err));
    }
    struct stat st;
    int rc = IMDB_OK;
    if (imdb_io_fstat(fd, &st) != 0) rc = imdb_fail(e, IMDB_ERR_IO, "a time zone file: fstat failed: %s", strerror(errno));
    else if (!S_ISREG(st.st_mode)) rc = imdb_fail(e, IMDB_ERR_INVALID, "unknown time zone (not a zone file)");
    else if ((uint64_t)st.st_size > IMDB_MAX_TZ_FILE)
        rc = imdb_fail(e, IMDB_ERR_LIMIT, "a time zone file of more than %u bytes", IMDB_MAX_TZ_FILE);
    uint8_t *buf = NULL;
    size_t got = 0;
    if (!rc && !(buf = imdb_alloc(st.st_size ? (size_t)st.st_size : 1, e))) rc = e->code;
    if (!rc) rc = imdb_read_all(fd, buf, (size_t)st.st_size, &got, e);
    close(fd);
    imdb_tz *z = NULL;
    if (!rc && !(z = imdb_alloc(sizeof *z, e))) rc = e->code;
    if (!rc && (rc = imdb_tz_parse(buf, got, z, e)) != 0) {
        imdb_free(z);
        z = NULL;
    }
    imdb_free(buf);
    if (rc) return rc;
    memcpy(z->name, nm, len + 1);
    *out = z;
    return IMDB_OK;
}

const imdb_tz imdb_tz_utc_zone = {.name = "UTC", .lat_sorted = true};

bool imdb_tz_builtin_utc(const char *s, size_t n)
{
    static const char *const names[] = {"UTC", "Etc/UTC", "GMT", "Etc/GMT"};
    for (size_t i = 0; i < sizeof names / sizeof *names; i++)
        if (strlen(names[i]) == n && !strncasecmp(names[i], s, n)) return true;
    return false;
}

/* ---- spans: where an offset holds, for callers that cache it (rows in time order then read the list once a transition)
 * ------------------------------------------------------------------------------------------------------------------- */

static int64_t s_us(int64_t s) /* seconds to microseconds, saturated: zic's earliest transition is -2^59 s */
{
    return s <= INT64_MIN / 1000000 ? INT64_MIN : s >= INT64_MAX / 1000000 ? INT64_MAX : s * 1000000;
}

int32_t imdb_tz_offset_span(const imdb_tz *z, int64_t t_us, int64_t *lo_us, int64_t *hi_us)
{
    int64_t t = floor_div(t_us, 1000000);
    if (z->n && t < z->at[0]) {
        *lo_us = INT64_MIN, *hi_us = s_us(z->at[0]);
        return z->off0;
    }
    if (z->n && t < z->at[z->n - 1]) {
        uint32_t lo = 0, hi = z->n - 1; /* at[lo] <= t < at[hi] */
        while (hi - lo > 1) {
            uint32_t mid = lo + (hi - lo) / 2;
            if (z->at[mid] <= t) lo = mid;
            else hi = mid;
        }
        *lo_us = s_us(z->at[lo]), *hi_us = s_us(z->at[lo + 1]);
        return z->off[lo];
    }
    /* at or past the last transition (or none): the footer's rule */
    int64_t base = z->n ? z->at[z->n - 1] : INT64_MIN;
    *lo_us = z->n ? s_us(base) : INT64_MIN, *hi_us = INT64_MAX;
    if (!z->has_rule) return z->n ? z->off[z->n - 1] : z->off0;
    if (!z->rule.has_dst) return z->rule.std_off;
    int64_t y = year_of_days(floor_div(t + z->rule.std_off, 86400)), at[8];
    int32_t off[8];
    int k = rule_trans(&z->rule, y - 2, y + 1, at, off), i = -1;
    for (int j = 0; j < k; j++)
        if (at[j] <= t) i = j;
    int32_t o = i >= 0 ? off[i] : rule_offset(&z->rule, at[0] - 1);
    if (i < 0) *lo_us = t_us; /* no rule transition at or before t in the window: claim nothing before t */
    else if (at[i] > base) *lo_us = s_us(at[i]);
    if (i + 1 < k) *hi_us = s_us(at[i + 1]);
    else *hi_us = s_us(t + 1); /* never past the transitions computed */
    if (*hi_us <= t_us) *hi_us = t_us + 1;
    return o;
}
