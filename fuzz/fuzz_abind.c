/* P2 S7b: the auditor's view binder (tools/audit/abind.c) on any text, as a forged log hands it one: against a fixed
 * catalog (two tables of every type, a view over them), it binds or refuses, never crashes, reads nothing outside the
 * text and allocates within the bounds its limits set (libFuzzer's -rss_limit_mb catches a runaway). A text it binds
 * yields at least one column, each typed, a DECIMAL within 38 places (F3e), its dependencies sorted and each once. */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../tools/audit/abind.h"

static const ab_col T[] = {{"id", 1, 0}, {"g", 1, 0}, {"d", 2, 2}, {"f", 6, 0}, {"s", 3, 0}, {"k", 4, 0}, {"ts", 5, 0},
                           {"e", 2, 4}, {"iv", 12, 0}}; /* F3f: iv an INTERVAL */
static const ab_col U[] = {{"id", 1, 0}, {"tid", 1, 0}, {"v", 1, 0}, {"s", 3, 0}, {"d", 2, 3}};
static const ab_col V[] = {{"id", 1, 0}, {"m", 2, 8}};

static bool lookup(void *arg, const char *name, ab_rel *out)
{
    (void)arg;
    if (!strcmp(name, "t")) *out = (ab_rel){1, 0, 9, T};
    else if (!strcmp(name, "u")) *out = (ab_rel){1, 1, 5, U};
    else if (!strcmp(name, "w")) *out = (ab_rel){2, 0, 2, V};
    else return false;
    return true;
}

/* F2b-1: the same text as a CHECK of t's columns, evaluated on rows at the types' edges: a verdict or an error, never a
 * crash, an overflow (the UBSan build) or a leak */
static const ab_col C[] = {{"id", 1, 0}, {"g", 1, 0}, {"d", 2, 2}, {"s", 3, 0}, {"k", 4, 0}, {"ts", 5, 0}, {"e", 2, 18},
                           {"dt", 8, 0}, {"tm", 9, 0}, {"tz", 7, 0}, {"x", 2, 6}}; /* F3e: x a DECIMAL(38,6), wide */

/* F3e: a wide value at the pool's edges: 0, 1, -1, 10^38 - 1 and its negative, 2^64 and its negative */
static ab_val wide_at(int k)
{
    const __int128 P38 = (__int128)10000000000000000000ull * 10000000000000000000ull, P64 = (__int128)1 << 64;
    const __int128 pool[] = {0, 1, -1, P38 - 1, -(P38 - 1), P64, -P64};
    __int128 x = pool[k % 7];
    return (ab_val){.wide = true, .i = (int64_t)(uint64_t)(unsigned __int128)x, .hi = (int64_t)(uint64_t)((unsigned __int128)x >> 64)};
}

static void check_text(const uint8_t *data, size_t size)
{
    ab_check *c = NULL;
    char err[256];
    if (ab_check_bind((const char *)data, size, C, 11, &c, err, sizeof err)) return;
    static const char *txt[] = {"", "a", "\xc3\xa9%", "it's_x"};
    for (int r = 0; r < 12; r++) {
        ab_val row[11];
        memset(row, 0, sizeof row);
        int64_t big[] = {0, 1, -1, INT64_MAX, INT64_MIN, 7};
        for (int k = 0; k < 11; k++) row[k].null = (r + k) % 5 == 0;
        row[0].i = r;
        row[1].i = big[r % 6];
        row[2].i = r & 1 ? 999999999999999999LL : -999999999999999999LL;
        row[3].s = (const uint8_t *)txt[r % 4];
        row[3].len = (uint32_t)strlen(txt[r % 4]);
        row[4].i = r & 1;
        row[5].i = r & 2 ? 253402300799999999LL : -62135596800000000LL;
        row[6].i = big[(r + 3) % 6] / 10;
        row[7].i = r & 1 ? 2932896 : -719162;
        row[8].i = r & 1 ? 86399999999LL : 0;
        row[9].i = big[r % 6] / 100;
        if (!row[10].null) row[10] = wide_at(r);
        int v = ab_check_eval(c, row, err, sizeof err);
        if (v < -1 || v > 1) abort();
    }
    ab_check_free(c);
}

/* F2c: the same text as a generated column's expression into each target of a type (the catalog C, its last column
 * generated): bound or refused, then each row's value assigned to the target's type by INSERT's rules: a value, an
 * evaluation's error or an assignment's, never a crash, an overflow or a leak; a value assigned within its column */
static const ab_col G[] = {{"id", 1, 0}, {"g", 1, 0}, {"d", 2, 2}, {"s", 3, 0}, {"k", 4, 0}, {"ts", 5, 0}, {"e", 2, 18},
                           {"dt", 8, 0}, {"tm", 9, 0}, {"tz", 7, 0}, {"x", 2, 6}, {"w", 1, 0}}; /* F3e: x wide */
static const ab_gcol GT[] = {{1, 16, 0, 0, true}, {1, 0, 0, 0, false}, {2, 6, 2, 0, true}, {3, 0, 0, 4, true}, {4, 0, 0, 0, true},
                             {5, 0, 0, 0, true}, {8, 0, 0, 0, true}, {9, 0, 0, 0, true}, {7, 0, 0, 0, true},
                             {2, 38, 6, 0, true}, {2, 20, 2, 0, false}}; /* F3e: wide targets */

static void gen_text(const uint8_t *data, size_t size)
{
    for (size_t t = 0; t < sizeof GT / sizeof *GT; t++) {
        ab_col cols[12];
        memcpy(cols, G, sizeof cols);
        cols[11].type = GT[t].type;
        cols[11].scale = GT[t].type == 2 ? GT[t].scale : 0;
        ab_check *c = NULL;
        char err[256];
        if (ab_gen_bind((const char *)data, size, cols, 12, 11, 1ull << 11, &c, err, sizeof err)) continue;
        static const char *txt[] = {"", "a", "\xc3\xa9%", "it's_x"};
        for (int r = 0; r < 12; r++) {
            ab_val row[12], out;
            memset(row, 0, sizeof row);
            int64_t big[] = {0, 1, -1, INT64_MAX, INT64_MIN, 7};
            for (int k = 0; k < 12; k++) row[k].null = (r + k) % 5 == 0;
            row[0].i = r;
            row[1].i = big[r % 6];
            row[2].i = r & 1 ? 999999999999999999LL : -999999999999999999LL;
            row[3].s = (const uint8_t *)txt[r % 4];
            row[3].len = (uint32_t)strlen(txt[r % 4]);
            row[4].i = r & 1;
            row[5].i = r & 2 ? 253402300799999999LL : -62135596800000000LL;
            row[6].i = big[(r + 3) % 6] / 10;
            row[7].i = r & 1 ? 2932896 : -719162;
            row[8].i = r & 1 ? 86399999999LL : 0;
            row[9].i = big[r % 6] / 100;
            if (!row[10].null) row[10] = wide_at(r);
            uint8_t *tb = NULL;
            int v = ab_gen_eval(c, row, &GT[t], &out, &tb, err, sizeof err);
            if (v < -2 || v > 0) abort();
            if (!v && !out.null && GT[t].type == 1 && GT[t].prec == 16 && (out.i < -32768 || out.i > 32767)) abort();
            if (!v && !out.null && GT[t].type == 2) { /* F3e: within its precision, in its column's form */
                __int128 x = out.wide ? (__int128)(((unsigned __int128)(uint64_t)out.hi << 64) | (uint64_t)out.i) : out.i, lim = 1;
                for (int q = 0; q < GT[t].prec; q++) lim *= 10;
                if (x >= lim || x <= -lim || out.wide != (GT[t].prec > 18) || (!out.wide && out.hi)) abort();
            }
            if (!v && out.null && !GT[t].nullable) abort();
            free(tb);
        }
        ab_check_free(c);
    }
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    static ab_result r;
    char err[256];
    check_text(data, size);
    gen_text(data, size);
    if (ab_bind((const char *)data, size, lookup, NULL, &r, err, sizeof err)) return 0;
    if (r.ncols < 1 || r.ncols > AB_MAX_COLS || r.ndeps > AB_MAX_DEPS) abort();
    for (uint16_t c = 0; c < r.ncols; c++)
        if (r.cols[c].type < 1 || r.cols[c].type > 6 || (r.cols[c].type == 2 ? r.cols[c].scale > 38 : r.cols[c].scale != 0))
            abort();
    for (uint16_t k = 0; k < r.ndeps; k++) {
        if ((r.dep_kind[k] != 1 && r.dep_kind[k] != 2) || r.dep_id[k] > 1) abort();
        if (k && (r.dep_kind[k - 1] > r.dep_kind[k] || (r.dep_kind[k - 1] == r.dep_kind[k] && r.dep_id[k - 1] >= r.dep_id[k])))
            abort();
    }
    return 0;
}
