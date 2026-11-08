/* P2's zone slice: the TZif reader and the two conversions (src/tz.c). The references are independent of it: glibc's
 * localtime_r reads the same files (its 64-bit data and footer) for UTC -> offset, and for local -> UTC PostgreSQL's
 * own algorithm (DetermineTimeZoneOffset: one boundary after L - 24 h, then before / after / the later instant), here
 * over the offset function glibc checked. zic, when the host has it, builds slim files whose footers must give what
 * the host's fat files list explicitly (the footer rule's proof, 1996-2037), and glibc decides past 2037. */
#include <dirent.h>
#include <pthread.h>
#include <fcntl.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "test.h"
#include "thelp.h"
#include "../../src/fsio.h"
#include "../../src/tz.h"

#define ZROOT "/usr/share/zoneinfo"

static char *read_whole(const char *path, size_t *len)
{
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    char *b = NULL;
    size_t n = 0, cap = 0;
    for (;;) {
        if (n == cap) {
            char *nb = realloc(b, cap ? cap * 2 : 8192);
            if (!nb) {
                free(b);
                fclose(f);
                return NULL;
            }
            b = nb, cap = cap ? cap * 2 : 8192;
        }
        size_t g = fread(b + n, 1, cap - n, f);
        if (!g) break;
        n += g;
    }
    fclose(f);
    *len = n;
    return b;
}

static int load(const char *path, imdb_tz *z)
{
    size_t n;
    char *b = read_whole(path, &n);
    if (!b) return -1000;
    imdb_err e = {0};
    int rc = imdb_tz_parse((const uint8_t *)b, n, z, &e);
    free(b);
    return rc;
}

/* every zone file under root (relative names), the leap-second (right/) and copied (posix/) trees left out */
typedef struct names {
    char **v;
    size_t n, cap;
} names;

static void names_add(names *s, const char *p)
{
    if (s->n == s->cap) {
        s->cap = s->cap ? s->cap * 2 : 1024;
        s->v = realloc(s->v, s->cap * sizeof *s->v);
    }
    s->v[s->n++] = strdup(p);
}

static void names_free(names *s)
{
    for (size_t i = 0; i < s->n; i++) free(s->v[i]);
    free(s->v);
    memset(s, 0, sizeof *s);
}

static void walk(const char *root, const char *rel, names *out, bool right)
{
    char dir[4096];
    snprintf(dir, sizeof dir, "%s%s%s", root, *rel ? "/" : "", rel);
    DIR *d = opendir(dir);
    if (!d) return;
    struct dirent *de;
    while ((de = readdir(d))) {
        const char *nm = de->d_name;
        if (nm[0] == '.' || strchr(nm, '.') || !strcmp(nm, "localtime") || !strcmp(nm, "leapseconds") ||
            !strcmp(nm, "SECURITY") || !strcmp(nm, "posixrules"))
            continue;
        if (!*rel && !right && (!strcmp(nm, "right") || !strcmp(nm, "posix"))) continue;
        char r2[4096], full[8192];
        snprintf(r2, sizeof r2, "%s%s%s", rel, *rel ? "/" : "", nm);
        snprintf(full, sizeof full, "%s/%s", root, r2);
        struct stat st;
        if (stat(full, &st) != 0) continue;
        if (S_ISDIR(st.st_mode)) walk(root, r2, out, right);
        else if (S_ISREG(st.st_mode)) names_add(out, r2);
    }
    closedir(d);
}

static char g_oldtz[512];
static bool g_hadtz;

static void tz_env_save(void)
{
    const char *o = getenv("TZ");
    g_hadtz = o != NULL;
    snprintf(g_oldtz, sizeof g_oldtz, "%s", o ? o : "");
}

static void tz_env_restore(void)
{
    if (g_hadtz) setenv("TZ", g_oldtz, 1);
    else unsetenv("TZ");
    tzset();
}

static void glibc_zone(const char *spec)
{
    setenv("TZ", spec, 1);
    tzset();
}

static int32_t glibc_off(int64_t t)
{
    time_t tt = (time_t)t;
    struct tm tm;
    if (!localtime_r(&tt, &tm)) return INT32_MIN;
    return (int32_t)tm.tm_gmtoff;
}

static int32_t off_s(const imdb_tz *z, int64_t t) { return imdb_tz_offset(z, t * 1000000); }

/* PostgreSQL's rule, from its algorithm: the first offset change after L - 24 h (found from the offset function), and
 * the later instant where L is in a gap or an overlap. *skip when two changes fall within 72 h, where PostgreSQL's one
 * boundary and the last-transition rule could part (no such pair is in real data since 1970) */
static int64_t pg_local(const imdb_tz *z, int64_t L, bool *skip)
{
    int64_t prev = L - 86400;
    int32_t before = off_s(z, prev);
    int64_t b = 0;
    int found = 0;
    for (int64_t t = prev + 10800; t <= prev + 72 * 3600; t += 10800) {
        if (off_s(z, t) == (found ? off_s(z, b) : before)) continue;
        int32_t from = found ? off_s(z, b) : before;
        int64_t lo = t - 10800, hi = t;
        while (hi - lo > 1) {
            int64_t m = lo + (hi - lo) / 2;
            if (off_s(z, m) == from) lo = m;
            else hi = m;
        }
        if (found) {
            *skip = true;
            break;
        }
        b = hi, found = 1;
    }
    if (!found) return L - before;
    int32_t after = off_s(z, b);
    int64_t bt = L - before, at = L - after;
    if (bt < b && at < b) return bt;
    if (bt >= b && at >= b) return at;
    return bt > at ? bt : at;
}

/* each zone: imdb's offsets are glibc's at every transition and around it, at random instants 1850-2150 and every
 * day at noon 2037-2046 (past the fat files' explicit list: the footer rule) */
static void t_tz_glibc(void)
{
    names zs = {0};
    walk(ZROOT, "", &zs, false);
    if (zs.n < 300) {
        printf("    (skipped: fewer than 300 zones under " ZROOT ")\n");
        names_free(&zs);
        return;
    }
    tz_env_save();
    uint64_t checked = 0, zones = 0, footer_dst = 0;
    int bad = 0;
    for (size_t i = 0; i < zs.n && bad < 5; i++) {
        char path[4096], spec[4200];
        snprintf(path, sizeof path, ZROOT "/%s", zs.v[i]);
        imdb_tz z;
        int rc = load(path, &z);
        if (rc == -1000) continue;
        if (rc != 0) {
            printf("    %s: refused (%d)\n", zs.v[i], rc);
            bad++;
            continue;
        }
        zones++;
        footer_dst += z.has_rule && z.rule.has_dst;
        snprintf(spec, sizeof spec, ":%s", path);
        glibc_zone(spec);
        for (uint32_t k = 0; k < z.n && bad < 5; k++)
            for (int d = -1; d <= 1; d++) {
                int64_t t = z.at[k] + d;
                if (t < -(INT64_C(1) << 40)) continue; /* zic's "big bang": glibc's time_t arithmetic too far */
                checked++;
                if (off_s(&z, t) != glibc_off(t)) {
                    printf("    %s: at %lld: %d, glibc %d\n", zs.v[i], (long long)t, off_s(&z, t), glibc_off(t));
                    bad++;
                    break;
                }
            }
        test_seed(i + 1);
        for (int k = 0; k < 600 && bad < 5; k++) {
            int64_t t = -3786825600LL + (int64_t)(test_rand() % 9467280000ULL); /* 1850 .. 2150 */
            checked++;
            if (off_s(&z, t) != glibc_off(t)) {
                printf("    %s: at %lld: %d, glibc %d\n", zs.v[i], (long long)t, off_s(&z, t), glibc_off(t));
                bad++;
            }
        }
        for (int64_t t = 2114424000LL; t < 2114424000LL + 3650LL * 86400 && bad < 5; t += 86400) { /* 2037 .. 2047 */
            checked++;
            if (off_s(&z, t) != glibc_off(t)) {
                printf("    %s: at %lld: %d, glibc %d\n", zs.v[i], (long long)t, off_s(&z, t), glibc_off(t));
                bad++;
            }
        }
        imdb_tz_free(&z);
    }
    tz_env_restore();
    printf("    %llu zones, %llu with a daylight footer rule, %llu instants\n", (unsigned long long)zones,
           (unsigned long long)footer_dst, (unsigned long long)checked);
    names_free(&zs);
    CHECK(bad == 0);
    CHECK(zones >= 300 && footer_dst >= 50);
}

/* each zone: local -> UTC is PostgreSQL's around every transition since 1900 (each side's local times, in the gaps and
 * overlaps and at their edges) and at random local times */
static void t_tz_local(void)
{
    names zs = {0};
    walk(ZROOT, "", &zs, false);
    if (zs.n < 300) {
        printf("    (skipped: fewer than 300 zones under " ZROOT ")\n");
        names_free(&zs);
        return;
    }
    uint64_t checked = 0, gaps = 0, overlaps = 0, skipped = 0;
    int bad = 0;
    static const int64_t dl[] = {-3601, -1, 0, 1, 1799, 3599, 3600};
    for (size_t i = 0; i < zs.n && bad < 5; i++) {
        char path[4096];
        snprintf(path, sizeof path, ZROOT "/%s", zs.v[i]);
        imdb_tz z;
        if (load(path, &z) != 0) continue;
        for (uint32_t k = 0; k < z.n && bad < 5; k++) {
            if (z.at[k] < -2208988800LL) continue; /* before 1900 */
            int32_t ob = off_s(&z, z.at[k] - 1), oa = z.off[k];
            for (int side = 0; side < 2; side++)
                for (size_t j = 0; j < sizeof dl / sizeof *dl && bad < 5; j++) {
                    int64_t L = z.at[k] + (side ? oa : ob) + dl[j];
                    bool skip = false;
                    int64_t want = pg_local(&z, L, &skip);
                    if (skip) {
                        skipped++;
                        continue;
                    }
                    checked++;
                    gaps += oa > ob && L >= z.at[k] + ob && L < z.at[k] + oa;
                    overlaps += oa < ob && L >= z.at[k] + oa && L < z.at[k] + ob;
                    int64_t got = imdb_tz_utc_of_local(&z, L * 1000000 + 123456);
                    if (got != want * 1000000 + 123456) {
                        printf("    %s: local %lld: %lld, PostgreSQL's rule %lld\n", zs.v[i], (long long)L,
                               (long long)(got / 1000000), (long long)want);
                        bad++;
                    }
                }
        }
        test_seed(i + 77);
        for (int k = 0; k < 300 && bad < 5; k++) {
            int64_t L = -2208988800LL + (int64_t)(test_rand() % 6311433600ULL); /* 1900 .. 2100 */
            bool skip = false;
            int64_t want = pg_local(&z, L, &skip);
            if (skip) {
                skipped++;
                continue;
            }
            checked++;
            int64_t got = imdb_tz_utc_of_local(&z, L * 1000000);
            if (got != want * 1000000) {
                printf("    %s: local %lld: %lld, PostgreSQL's rule %lld\n", zs.v[i], (long long)L, (long long)(got / 1000000),
                       (long long)want);
                bad++;
            }
        }
        imdb_tz_free(&z);
    }
    printf("    %llu local times (%llu in gaps, %llu in overlaps), %llu skipped (two changes within 72 h)\n",
           (unsigned long long)checked, (unsigned long long)gaps, (unsigned long long)overlaps, (unsigned long long)skipped);
    names_free(&zs);
    CHECK(bad == 0);
    CHECK(gaps > 1000 && overlaps > 1000);
}

/* tz_slim's comparison at one instant (see there) */
typedef struct slimcmp {
    const imdb_tz *s, *f;
    const char *sp, *fp, *name;
    int64_t tlast;
    bool irregular, zicdiff, bad;
    uint64_t checked, reproduced;
} slimcmp;

static void slim_at(slimcmp *c, int64_t t)
{
    int64_t L = t + off_s(c->f, t);
    c->checked++;
    if (off_s(c->s, t) == off_s(c->f, t) &&
        imdb_tz_utc_of_local(c->s, L * 1000000) == imdb_tz_utc_of_local(c->f, L * 1000000)) {
        c->reproduced += t > c->tlast + 172800;
        return;
    }
    char spec[8300];
    snprintf(spec, sizeof spec, ":%s", c->sp);
    glibc_zone(spec);
    int32_t gs = glibc_off(t);
    snprintf(spec, sizeof spec, ":%s", c->fp);
    glibc_zone(spec);
    int32_t gf = glibc_off(t);
    bool sk1 = false, sk2 = false;
    int64_t ps = pg_local(c->s, L, &sk1), pf = pg_local(c->f, L, &sk2);
    if (gs != off_s(c->s, t) || gf != off_s(c->f, t) || (!sk1 && imdb_tz_utc_of_local(c->s, L * 1000000) != ps * 1000000) ||
        (!sk2 && imdb_tz_utc_of_local(c->f, L * 1000000) != pf * 1000000)) {
        if (!c->bad)
            printf("    %s: at %lld: slim %d (glibc %d), fat %d (glibc %d)\n", c->name, (long long)t, off_s(c->s, t), gs,
                   off_s(c->f, t), gf);
        c->bad = true;
    } else if (t > c->tlast + 172800) {
        c->irregular = true;
    } else {
        c->zicdiff = true;
    }
}

/* one zic, both encodings: -b slim leaves to the footer every year its rule decides (London's file lists nothing past
 * 1996), -b fat lists them to 2037; each zone's offsets and local conversions from the slim file are the fat file's.
 * (The host's own files may come from another zic, whose output can differ: glibc 2.35's zic and tzdata 2026e's part on
 * America/Ojinaga's 2022, so those are tz_glibc's, against glibc.) */
static int run_zic(const char *zic, const char *mode, const char *out)
{
    pid_t p = fork();
    if (p == 0) {
        int dn = open("/dev/null", O_WRONLY);
        if (dn >= 0) dup2(dn, 2);
        execl(zic, zic, "-b", mode, "-d", out, ZROOT "/tzdata.zi", (char *)NULL);
        _exit(127);
    }
    int stv = 0;
    return p > 0 && waitpid(p, &stv, 0) == p && WIFEXITED(stv) && WEXITSTATUS(stv) == 0 ? 0 : -1;
}

static void t_tz_slim(void)
{
    const char *zic = access("/usr/sbin/zic", X_OK) == 0 ? "/usr/sbin/zic" : access("/usr/bin/zic", X_OK) == 0 ? "/usr/bin/zic" : NULL;
    if (!zic || access(ZROOT "/tzdata.zi", R_OK) != 0) {
        printf("    (skipped: no zic or no tzdata.zi)\n");
        return;
    }
    char out[4096], fout[4096];
    snprintf(out, sizeof out, "%s/slim", test_tmpdir());
    snprintf(fout, sizeof fout, "%s/fat", test_tmpdir());
    CHECK(run_zic(zic, "slim", out) == 0 && run_zic(zic, "fat", fout) == 0);
    names zs = {0};
    walk(out, "", &zs, false);
    CHECK(zs.n >= 300);
    uint64_t zones = 0, checked = 0, shorter = 0, reproduced = 0, nirregular = 0, nzicdiff = 0;
    tz_env_save();
    int bad = 0;
    for (size_t i = 0; i < zs.n && bad < 5; i++) {
        char sp[8192], fp[8192];
        snprintf(sp, sizeof sp, "%s/%s", out, zs.v[i]);
        snprintf(fp, sizeof fp, "%s/%s", fout, zs.v[i]);
        imdb_tz s, f;
        if (load(fp, &f) != 0) {
            printf("    fat %s refused\n", zs.v[i]);
            bad++;
            continue;
        }
        int rc = load(sp, &s);
        if (rc != 0) {
            printf("    slim %s refused (%d)\n", zs.v[i], rc);
            imdb_tz_free(&f);
            bad++;
            continue;
        }
        zones++;
        shorter += s.n < f.n;
        /* where the two files differ, each must be read as it is written: its offset glibc's reading of that file, its
         * local conversion PostgreSQL's rule over that file. Past the slim file's last transition a difference is a zone
         * whose fat file lists what no footer can say (Gaza's and Hebron's Ramadan to 2086): irregular; before it, a
         * difference is this zic's slim output itself (glibc 2.35's zic gives America/Ojinaga a CDT week in 2022 that
         * its fat output and tzdata 2022g do not have) */
        slimcmp c = {.s = &s, .f = &f, .sp = sp, .fp = fp, .name = zs.v[i], .tlast = s.n ? s.at[s.n - 1] : INT64_MIN};
        for (uint32_t k = 0; k < f.n && !c.bad; k++)
            for (int d = -1; d <= 1 && f.at[k] >= -2208988800LL; d++) slim_at(&c, f.at[k] + d);
        test_seed(i + 5);
        for (int k = 0; k < 400 && !c.bad; k++) slim_at(&c, -2208988800LL + (int64_t)(test_rand() % 6311433600ULL));
        bad += c.bad;
        checked += c.checked;
        reproduced += c.reproduced;
        if (c.irregular) {
            nirregular++;
            printf("    irregular past its slim file's last transition: %s\n", zs.v[i]);
        }
        if (c.zicdiff) {
            nzicdiff++;
            printf("    this zic's slim and fat files differ (each read as glibc reads it): %s\n", zs.v[i]);
        }
        imdb_tz_free(&s);
        imdb_tz_free(&f);
    }
    tz_env_restore();
    printf("    %llu zones (%llu with fewer transitions slim), %llu instants, %llu fat transitions after a slim file's last\n"
           "    reproduced by its footer, %llu zones irregular, %llu whose files differ\n",
           (unsigned long long)zones, (unsigned long long)shorter, (unsigned long long)checked,
           (unsigned long long)reproduced, (unsigned long long)nirregular, (unsigned long long)nzicdiff);
    names_free(&zs);
    CHECK(bad == 0);
    /* the bounds are this host's (glibc 2.35's zic on tzdata 2026e: 179,911 reproduced, two irregular, one differing),
     * with room for another tzdata; a new irregular zone past them is printed above, to be judged, not excused */
    CHECK(zones >= 300 && shorter >= 100 && reproduced >= 10000 && nirregular <= 6 && nzicdiff <= 6);
}

/* POSIX strings: each form against glibc's own parser of the same string (TZ=string), every hour of 2024-2027 and
 * each rule's edges; the refused ones refused */
static void t_tz_rules(void)
{
    static const char *const good[] = {
        "EST5EDT,M3.2.0,M11.1.0",
        "GMT0BST,M3.5.0/1,M10.5.0",
        "CET-1CEST,M3.5.0,M10.5.0/3",
        "IST-1GMT0,M10.5.0,M3.5.0/1",              /* Dublin: daylight time behind standard */
        "<+1030>-10:30<+11>-11,M10.1.0,M4.1.0",    /* Lord Howe: 30 minutes, the southern order */
        "AEST-10AEDT,M10.1.0,M4.1.0/3",
        "<-03>3<-02>,M3.5.0/-2,M10.5.0/-1",        /* a negative time (version 3) */
        "NZST-12NZDT,M9.5.0,M4.1.0/3",
        "<+0545>-5:45",
        "<-0930>9:30",
        "PST8PDT,M3.2.0/2:00:00,M11.1.0/2:00:00",
        "XXX3YYY,J60/2,J300/2",                    /* J days: Feb 29 never counted */
        "XXX3YYY,59/2,300/2",                      /* zero-based days: Feb 29 counted */
        "XXX-3YYY-4:30,M2.5.6/23,M11.5.1/26",      /* week 5, late times */
        "<+13>-13",
        "UTC0",
    };
    tz_env_save();
    int bad = 0;
    uint64_t checked = 0;
    for (size_t i = 0; i < sizeof good / sizeof *good && bad < 5; i++) {
        imdb_tz z;
        imdb_tz_utc(&z);
        imdb_err e = {0};
        if (imdb_tz_rule_parse(good[i], strlen(good[i]), &z.rule, &e) != 0) {
            printf("    refused: %s\n", good[i]);
            bad++;
            continue;
        }
        z.has_rule = true;
        glibc_zone(good[i]);
        for (int64_t t = 1704067200LL - 86400; t < 1830297600LL && bad < 5; t += 3600) { /* 2024 .. 2027 */
            checked++;
            for (int d = 0; d < 2; d++) {
                int64_t tt = t + (d ? 1799 : 0);
                if (off_s(&z, tt) != glibc_off(tt)) {
                    printf("    %s: at %lld: %d, glibc %d\n", good[i], (long long)tt, off_s(&z, tt), glibc_off(tt));
                    bad++;
                    break;
                }
            }
        }
        /* the edges: where glibc's offset changes, to the second */
        for (int64_t t = 1704067200LL; t < 1830297600LL && bad < 5; t += 3600) {
            if (glibc_off(t) == glibc_off(t + 3600)) continue;
            for (int64_t s = t; s <= t + 3600; s++) {
                checked++;
                if (off_s(&z, s) != glibc_off(s)) {
                    printf("    %s: at %lld: %d, glibc %d\n", good[i], (long long)s, off_s(&z, s), glibc_off(s));
                    bad++;
                    break;
                }
            }
        }
    }
    tz_env_restore();
    /* all year daylight time (RFC 8536 3.3.1: its example, and a J form): every hour 2023-2028 in daylight time. glibc is
     * no reference here: it takes a rule's transitions in the instant's UTC year, so it misses the year before's daylight
     * period that runs into the first hours of January (2024-01-01 00:00 UTC: standard time by glibc) */
    static const char *const allyear[] = {"EST5EDT,0/0,J365/25", "WART4WARST,J1/0,J365/25"};
    for (size_t i = 0; i < sizeof allyear / sizeof *allyear; i++) {
        imdb_tz z;
        imdb_tz_utc(&z);
        imdb_err e = {0};
        if (imdb_tz_rule_parse(allyear[i], strlen(allyear[i]), &z.rule, &e) != 0) {
            printf("    refused: %s\n", allyear[i]);
            bad++;
            continue;
        }
        z.has_rule = true;
        for (int64_t t = 1672531200LL; t < 1861920000LL && bad < 5; t += 3600) { /* 2023 .. 2029 */
            checked++;
            if (off_s(&z, t) != z.rule.dst_off || imdb_tz_utc_of_local(&z, t * 1000000) != (t - z.rule.dst_off) * 1000000) {
                printf("    %s: at %lld: %d\n", allyear[i], (long long)t, off_s(&z, t));
                bad++;
            }
        }
    }
    static const char *const refused[] = {
        "", "E", "EST", "EST5EDT", "EST5EDT,M3.2.0", "EST5EDT,M3.2.0,", "EST5EDT,M13.2.0,M11.1.0", "EST5EDT,M3.6.0,M11.1.0",
        "EST5EDT,M3.2.7,M11.1.0", "EST5EDT,M0.2.0,M11.1.0", "EST5EDT,J0,J100", "EST5EDT,J366,J100", "EST5EDT,366,100",
        "EST25", "<+0545-5:45", "<+05>", "<a b>5", "EST5EDT,M3.2.0/168,M11.1.0", "EST5:60", "EST5:00:60", "EST5 ",
        "EST5EDT,M3.2.0,M11.1.0x", "ES5", "<+5>-5",
    };
    for (size_t i = 0; i < sizeof refused / sizeof *refused; i++) {
        imdb_tzrule r;
        imdb_err e = {0};
        if (imdb_tz_rule_parse(refused[i], strlen(refused[i]), &r, &e) == 0) {
            printf("    accepted: \"%s\"\n", refused[i]);
            bad++;
        }
    }
    printf("    %zu rules, %llu instants\n", sizeof good / sizeof *good, (unsigned long long)checked);
    CHECK(bad == 0);
}

/* a file's every truncation refused; every byte changed refused or read whole (and freed); version 1, leap seconds,
 * reserved bytes, a trailing byte and counts past limits.h refused by name */
static void t_tz_strict(void)
{
    size_t n, ln;
    char *b = read_whole(ZROOT "/Europe/London", &n);
    ln = n;
    if (!b) {
        printf("    (skipped: no " ZROOT "/Europe/London)\n");
        return;
    }
    uint8_t *c = malloc(n + 2);
    imdb_err e = {0};
    imdb_tz z;
    CHECK(imdb_tz_parse((const uint8_t *)b, n, &z, &e) == 0);
    CHECK(z.n > 200 && z.has_rule && z.rule.has_dst && z.rule.std_off == 0 && z.rule.dst_off == 3600);
    imdb_tz_free(&z);
    uint64_t h0 = imdb_heap_bytes();
    for (size_t k = 0; k < n; k++) {
        if (imdb_tz_parse((const uint8_t *)b, k, &z, &e) == 0) {
            printf("    a truncation to %zu bytes read\n", k);
            imdb_tz_free(&z);
            CHECK(0);
        }
    }
    uint64_t taken = 0;
    for (size_t k = 0; k < n; k++) {
        memcpy(c, b, n);
        c[k] ^= (uint8_t)(1u << (k % 8));
        if (imdb_tz_parse(c, n, &z, &e) == 0) {
            taken++;
            /* whatever reads is a zone the conversions can use */
            for (int64_t t = -2208988800LL; t < 4102444800LL; t += 86400 * 97) {
                int32_t o = off_s(&z, t);
                CHECK(o > -90000 && o < 93600);
                (void)imdb_tz_utc_of_local(&z, t * 1000000);
            }
            imdb_tz_free(&z);
        }
    }
    CHECK(imdb_heap_bytes() == h0);
    memcpy(c, b, n);
    c[n] = '\n';
    CHECK(imdb_tz_parse(c, n + 1, &z, &e) == IMDB_ERR_CORRUPT); /* a byte after the footer */
    memcpy(c, b, n);
    c[4] = 0;
    CHECK(imdb_tz_parse(c, n, &z, &e) == IMDB_ERR_UNSUPPORTED); /* version 1 */
    memcpy(c, b, n);
    c[4] = '5';
    CHECK(imdb_tz_parse(c, n, &z, &e) == IMDB_ERR_CORRUPT);
    memcpy(c, b, n);
    c[10] = 1;
    CHECK(imdb_tz_parse(c, n, &z, &e) == IMDB_ERR_CORRUPT); /* reserved */
    memcpy(c, b, n);
    CHECK(imdb_tz_parse(c, n - 1, &z, &e) == IMDB_ERR_CORRUPT); /* no final newline */
    uint8_t *big = calloc(1, IMDB_MAX_TZ_FILE + 1);
    memcpy(big, b, n);
    CHECK(imdb_tz_parse(big, IMDB_MAX_TZ_FILE + 1, &z, &e) == IMDB_ERR_LIMIT);
    free(big);
    /* an empty version 1 block: a version 2 reader passes over it whatever it holds, so a file without one reads alike */
    {
        uint32_t cnt[6];
        for (int i = 0; i < 6; i++) {
            const uint8_t *q = (const uint8_t *)b + 20 + 4 * i;
            cnt[i] = (uint32_t)q[0] << 24 | (uint32_t)q[1] << 16 | (uint32_t)q[2] << 8 | q[3];
        }
        size_t v1 = 5u * cnt[3] + 6u * cnt[4] + cnt[5] + 8u * cnt[2] + cnt[1] + cnt[0];
        CHECK(44 + v1 < n);
        memcpy(c, b, 20);
        memset(c + 20, 0, 24);
        memcpy(c + 44, b + 44 + v1, n - 44 - v1);
        imdb_tz z1, z2;
        CHECK(imdb_tz_parse(c, n - v1, &z2, &e) == 0);
        CHECK(imdb_tz_parse((const uint8_t *)b, n, &z1, &e) == 0);
        bool same = z1.n == z2.n;
        for (int64_t t = -2208988800LL; same && t < 4102444800LL; t += 86400 * 7) same = off_s(&z1, t) == off_s(&z2, t);
        imdb_tz_free(&z1);
        imdb_tz_free(&z2);
        CHECK(same);
    }
    free(b);
    free(c);
    /* a leap-second file (right/), where the host has one */
    b = read_whole(ZROOT "/right/UTC", &n);
    if (b) {
        CHECK(imdb_tz_parse((const uint8_t *)b, n, &z, &e) == IMDB_ERR_UNSUPPORTED);
        free(b);
    }
    printf("    %zu bytes: every truncation refused, %llu of %zu changed bytes read\n", ln, (unsigned long long)taken, ln);
}

static void t_tz_names(void)
{
    static const char *const ok[] = {"UTC", "Europe/London", "America/Argentina/Buenos_Aires", "Etc/GMT+5", "Etc/GMT-14",
                                     "America/Port-au-Prince", "EST5EDT", "GB", "a", "Asia/Ho_Chi_Minh"};
    static const char *const no[] = {"", "/etc/passwd", "../etc/passwd", "Europe/../../etc", "Europe//London", "Europe/",
                                     "Europe/London/", "Europe/.London", ".", "..", "a b", "Europe\\London", "zone.tab",
                                     "Europe/Lon\x01" "don", "x\xc3\xa9"};
    for (size_t i = 0; i < sizeof ok / sizeof *ok; i++) CHECK(imdb_tz_name_ok(ok[i], strlen(ok[i])));
    for (size_t i = 0; i < sizeof no / sizeof *no; i++) CHECK(!imdb_tz_name_ok(no[i], strlen(no[i])));
    char longn[IMDB_MAX_TZ_NAME + 2];
    memset(longn, 'a', sizeof longn);
    CHECK(imdb_tz_name_ok(longn, IMDB_MAX_TZ_NAME));
    CHECK(!imdb_tz_name_ok(longn, IMDB_MAX_TZ_NAME + 1));
}


/* the fallback's world: the openat2 call (a directory fd, neither O_NOFOLLOW nor O_DIRECTORY) fails as a kernel without
 * it does */
static long no_openat2(imdb_io_call *c, void *ctx)
{
    (void)ctx;
    if (c->op == IMDB_IO_OPEN && c->dirfd >= 0 && !(c->flags & (O_NOFOLLOW | O_DIRECTORY))) {
        errno = ENOSYS;
        return -1;
    }
    return 0;
}
static const imdb_io_hooks g_no_openat2 = {.before = no_openat2};

static int load_name(const char *root, const char *name, imdb_tz **z)
{
    imdb_err e = {0};
    int rc = imdb_tz_load(root, name, strlen(name), z, &e);
    if (rc) *z = NULL;
    return rc;
}

static bool same_zone(const imdb_tz *a, const imdb_tz *b)
{
    for (int64_t t = -2208988800LL; t < 4102444800LL; t += 86400 * 5)
        if (off_s(a, t) != off_s(b, t)) return false;
    return true;
}

typedef struct zthr {
    imdb_db *db;
    const imdb_tz *got[8];
    int rc;
} zthr;

static void *zone_thread(void *p)
{
    zthr *t = p;
    static const char *const nm[8] = {"Europe/London", "Asia/Kolkata", "America/New_York", "Australia/Lord_Howe",
                                      "Asia/Kathmandu", "Pacific/Chatham", "America/St_Johns", "Europe/Moscow"};
    for (int i = 0; i < 8; i++) {
        imdb_err e = {0};
        int rc = imdb_db_zone(t->db, nm[i], strlen(nm[i]), &t->got[i], &e);
        if (rc) t->rc = rc;
    }
    return NULL;
}

/* the loader: names beneath the root (aliases, symlinks inside the tree, followed; localtime's absolute link, a
 * directory, a link out of the root, a leap-second file refused), the fallback without openat2 (aliases then refused,
 * canonical names read), the handle's table (UTC with no zoneinfo, one zone per name, eight threads loading at once) */
static void t_tz_load(void)
{
    if (access(ZROOT "/Europe/London", R_OK) != 0 || access(ZROOT "/GB", R_OK) != 0) {
        printf("    (skipped: no " ZROOT " with its aliases)\n");
        return;
    }
    imdb_tz *lon, *gb, *useast, *ny;
    CHECK(load_name(ZROOT, "Europe/London", &lon) == 0 && load_name(ZROOT, "GB", &gb) == 0);
    CHECK(load_name(ZROOT, "US/Eastern", &useast) == 0 && load_name(ZROOT, "America/New_York", &ny) == 0);
    CHECK(same_zone(lon, gb) && same_zone(useast, ny) && !same_zone(lon, ny));
    CHECK(!strcmp(gb->name, "GB"));
    imdb_tz *z = NULL;
    CHECK(load_name(ZROOT, "localtime", &z) == IMDB_ERR_INVALID); /* absolute: out of the root */
    CHECK(load_name(ZROOT, "America", &z) == IMDB_ERR_INVALID);   /* a directory */
    CHECK(load_name(ZROOT, "Nowhere/Zone", &z) == IMDB_ERR_INVALID);
    CHECK(load_name(ZROOT, "zone.tab", &z) == IMDB_ERR_INVALID);  /* not a name */
    CHECK(load_name(ZROOT, "../zoneinfo/GB", &z) == IMDB_ERR_INVALID);
    if (access(ZROOT "/right/UTC", R_OK) == 0) CHECK(load_name(ZROOT, "right/UTC", &z) == IMDB_ERR_UNSUPPORTED);
    CHECK(load_name("/nonexistent-zoneinfo", "Europe/London", &z) == IMDB_ERR_IO);
    /* a private root: a link inside it followed, one climbing out of it and an absolute one refused */
    char root[4096], p[8192];
    snprintf(root, sizeof root, "%s/zi", test_tmpdir());
    CHECK(mkdir(root, 0755) == 0);
    snprintf(p, sizeof p, "%s/Inner", root);
    CHECK(mkdir(p, 0755) == 0);
    size_t ln;
    char *lb = read_whole(ZROOT "/Europe/London", &ln);
    CHECK(lb != NULL);
    snprintf(p, sizeof p, "%s/Inner/Zone", root);
    FILE *fw = fopen(p, "wb");
    CHECK(fw && fwrite(lb, 1, ln, fw) == ln);
    fclose(fw);
    free(lb);
    snprintf(p, sizeof p, "%s/Alias", root);
    CHECK(symlink("Inner/Zone", p) == 0);
    snprintf(p, sizeof p, "%s/Out", root);
    CHECK(symlink("../../../../../../../../.." ZROOT "/Europe/London", p) == 0);
    snprintf(p, sizeof p, "%s/Abs", root);
    CHECK(symlink(ZROOT "/Europe/London", p) == 0);
    CHECK(load_name(root, "Alias", &z) == 0 && same_zone(z, lon));
    imdb_tz_free(z);
    imdb_free(z);
    CHECK(load_name(root, "Out", &z) == IMDB_ERR_INVALID);
    CHECK(load_name(root, "Abs", &z) == IMDB_ERR_INVALID);
    /* without openat2: canonical names read, aliases refused (ELOOP), the rest as before */
    imdb_io_set_hooks(&g_no_openat2);
    int r1 = load_name(ZROOT, "Europe/London", &z);
    bool same = r1 == 0 && same_zone(z, lon);
    if (!r1) {
        imdb_tz_free(z);
        imdb_free(z);
    }
    int r2 = load_name(ZROOT, "GB", &z), r3 = load_name(root, "Alias", &z), r4 = load_name(root, "Inner/Zone", &z);
    if (!r4) {
        imdb_tz_free(z);
        imdb_free(z);
    }
    int r5 = load_name(ZROOT, "localtime", &z);
    imdb_io_set_hooks(NULL);
    CHECK(same && r2 == IMDB_ERR_INVALID && r3 == IMDB_ERR_INVALID && r4 == 0 && r5 == IMDB_ERR_INVALID);
    imdb_tz *frees[] = {lon, gb, useast, ny};
    for (size_t i = 0; i < 4; i++) {
        imdb_tz_free(frees[i]);
        imdb_free(frees[i]);
    }
    /* the handle's table: UTC and its aliases with no zoneinfo directory at all */
    char dir[4096];
    snprintf(dir, sizeof dir, "%s/db", test_tmpdir());
    imdb_err e = {0};
    CHECK_OK(imdb_init(dir, false, NULL, &e));
    imdb_open_opts o = {.sync = 0, .zoneinfo = "/nonexistent-zoneinfo"};
    imdb_db *db = NULL;
    CHECK_OK(imdb_open(dir, &o, &db, &e));
    const imdb_tz *u1 = NULL, *u2 = NULL, *u3 = NULL;
    int ru = imdb_db_zone(db, "UTC", 3, &u1, &e) | imdb_db_zone(db, "etc/utc", 7, &u2, &e) | imdb_db_zone(db, "Gmt", 3, &u3, &e);
    const imdb_tz *lz = NULL;
    int rl = imdb_db_zone(db, "Europe/London", 13, &lz, &e);
    uint32_t ntz0 = db->ntz;
    imdb_close(db);
    CHECK(ru == 0 && u1 == &imdb_tz_utc_zone && u2 == u1 && u3 == u1 && off_s(u1, 1700000000) == 0);
    CHECK(rl == IMDB_ERR_IO && ntz0 == 0);
    /* eight threads naming the same eight zones at once: each loaded once, every thread given the same zone */
    o.zoneinfo = NULL;
    CHECK_OK(imdb_open(dir, &o, &db, &e));
    pthread_t th[8];
    zthr zt[8];
    memset(zt, 0, sizeof zt);
    for (int i = 0; i < 8; i++) {
        zt[i].db = db;
        CHECK(pthread_create(&th[i], NULL, zone_thread, &zt[i]) == 0);
    }
    for (int i = 0; i < 8; i++) pthread_join(th[i], NULL);
    bool agree = db->ntz == 8;
    for (int i = 0; i < 8; i++) {
        agree = agree && zt[i].rc == 0;
        for (int k = 0; k < 8; k++) agree = agree && zt[i].got[k] == zt[0].got[k] && zt[i].got[k];
    }
    const imdb_tz *again = NULL;
    agree = agree && imdb_db_zone(db, "Europe/London", 13, &again, &e) == 0 && again == zt[0].got[0] && db->ntz == 8;
    imdb_close(db);
    CHECK(agree);
}


/* the spans a caller caches: each holds t and only its offset (its ends and 16 points between read alike), at every
 * transition and random instants 1850-2150, in every zone */
static void t_tz_spans(void)
{
    names zs = {0};
    walk(ZROOT, "", &zs, false);
    if (zs.n < 300) {
        printf("    (skipped: fewer than 300 zones under " ZROOT ")\n");
        names_free(&zs);
        return;
    }
    uint64_t checked = 0;
    int bad = 0;
    for (size_t i = 0; i < zs.n && bad < 5; i++) {
        char path[4096];
        snprintf(path, sizeof path, ZROOT "/%s", zs.v[i]);
        imdb_tz z;
        if (load(path, &z) != 0) continue;
        test_seed(i + 901);
        for (uint32_t k = 0; k < z.n + 400 && bad < 5; k++) {
            int64_t t = k < z.n ? z.at[k] * 1000000 + (int64_t)(test_rand() % 3) * 1000000 - 1000000
                                : (-3786825600LL + (int64_t)(test_rand() % 9467280000ULL)) * 1000000;
            if (k < z.n && z.at[k] < -(INT64_C(1) << 40)) continue;
            int64_t lo, hi;
            int32_t o = imdb_tz_offset_span(&z, t, &lo, &hi);
            checked++;
            bool ok = lo <= t && t < hi && o == imdb_tz_offset(&z, t);
            int64_t a = lo == INT64_MIN ? t - (INT64_C(1) << 50) : lo, b = hi == INT64_MAX ? t + (INT64_C(1) << 50) : hi - 1;
            for (int s = 0; ok && s <= 16; s++) {
                int64_t q = a + (int64_t)((__int128)(b - a) * s / 16);
                ok = imdb_tz_offset(&z, q) == o;
            }
            if (!ok) {
                printf("    %s: at %lld us: span [%lld, %lld) offset %d\n", zs.v[i], (long long)t, (long long)lo, (long long)hi, o);
                bad++;
            }
        }
        imdb_tz_free(&z);
    }
    printf("    %llu spans\n", (unsigned long long)checked);
    names_free(&zs);
    CHECK(bad == 0);
}

const test_case tz_tests[] = {
    {"tz_glibc", t_tz_glibc},
    {"tz_local", t_tz_local},
    {"tz_slim", t_tz_slim},
    {"tz_rules", t_tz_rules},
    {"tz_strict", t_tz_strict},
    {"tz_names", t_tz_names},
    {"tz_load", t_tz_load},
    {"tz_spans", t_tz_spans},
};
const size_t tz_ntests = sizeof tz_tests / sizeof *tz_tests;
