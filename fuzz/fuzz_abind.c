/* P2 S7b: the auditor's view binder (tools/audit/abind.c) on any text, as a forged log hands it one: against a fixed
 * catalog (two tables of every type, a view over them), it binds or refuses, never crashes, reads nothing outside the
 * text and allocates within the bounds its limits set (libFuzzer's -rss_limit_mb catches a runaway). A text it binds
 * yields at least one column, each typed, a DECIMAL within 18 places, its dependencies sorted and each once. */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../tools/audit/abind.h"

static const ab_col T[] = {{"id", 1, 0}, {"g", 1, 0}, {"d", 2, 2}, {"f", 6, 0}, {"s", 3, 0}, {"k", 4, 0}, {"ts", 5, 0},
                           {"e", 2, 4}};
static const ab_col U[] = {{"id", 1, 0}, {"tid", 1, 0}, {"v", 1, 0}, {"s", 3, 0}, {"d", 2, 3}};
static const ab_col V[] = {{"id", 1, 0}, {"m", 2, 8}};

static bool lookup(void *arg, const char *name, ab_rel *out)
{
    (void)arg;
    if (!strcmp(name, "t")) *out = (ab_rel){1, 0, 8, T};
    else if (!strcmp(name, "u")) *out = (ab_rel){1, 1, 5, U};
    else if (!strcmp(name, "w")) *out = (ab_rel){2, 0, 2, V};
    else return false;
    return true;
}

/* F2b-1: the same text as a CHECK of t's columns, evaluated on rows at the types' edges: a verdict or an error, never a
 * crash, an overflow (the UBSan build) or a leak */
static const ab_col C[] = {{"id", 1, 0}, {"g", 1, 0}, {"d", 2, 2}, {"s", 3, 0}, {"k", 4, 0}, {"ts", 5, 0}, {"e", 2, 18},
                           {"dt", 8, 0}, {"tm", 9, 0}, {"tz", 7, 0}};

static void check_text(const uint8_t *data, size_t size)
{
    ab_check *c = NULL;
    char err[256];
    if (ab_check_bind((const char *)data, size, C, 10, &c, err, sizeof err)) return;
    static const char *txt[] = {"", "a", "\xc3\xa9%", "it's_x"};
    for (int r = 0; r < 12; r++) {
        ab_val row[10];
        memset(row, 0, sizeof row);
        int64_t big[] = {0, 1, -1, INT64_MAX, INT64_MIN, 7};
        for (int k = 0; k < 10; k++) row[k].null = (r + k) % 5 == 0;
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
        int v = ab_check_eval(c, row, err, sizeof err);
        if (v < -1 || v > 1) abort();
    }
    ab_check_free(c);
}

/* F2c: the same text as a generated column's expression into each target of a type (the catalog C, its last column
 * generated): bound or refused, then each row's value assigned to the target's type by INSERT's rules: a value, an
 * evaluation's error or an assignment's, never a crash, an overflow or a leak; a value assigned within its column */
static const ab_col G[] = {{"id", 1, 0}, {"g", 1, 0}, {"d", 2, 2}, {"s", 3, 0}, {"k", 4, 0}, {"ts", 5, 0}, {"e", 2, 18},
                           {"dt", 8, 0}, {"tm", 9, 0}, {"tz", 7, 0}, {"w", 1, 0}};
static const ab_gcol GT[] = {{1, 16, 0, 0, true}, {1, 0, 0, 0, false}, {2, 6, 2, 0, true}, {3, 0, 0, 4, true}, {4, 0, 0, 0, true},
                             {5, 0, 0, 0, true}, {8, 0, 0, 0, true}, {9, 0, 0, 0, true}, {7, 0, 0, 0, true}};

static void gen_text(const uint8_t *data, size_t size)
{
    for (size_t t = 0; t < sizeof GT / sizeof *GT; t++) {
        ab_col cols[11];
        memcpy(cols, G, sizeof cols);
        cols[10].type = GT[t].type;
        cols[10].scale = GT[t].type == 2 ? GT[t].scale : 0;
        ab_check *c = NULL;
        char err[256];
        if (ab_gen_bind((const char *)data, size, cols, 11, 10, 1ull << 10, &c, err, sizeof err)) continue;
        static const char *txt[] = {"", "a", "\xc3\xa9%", "it's_x"};
        for (int r = 0; r < 12; r++) {
            ab_val row[11], out;
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
            uint8_t *tb = NULL;
            int v = ab_gen_eval(c, row, &GT[t], &out, &tb, err, sizeof err);
            if (v < -2 || v > 0) abort();
            if (!v && !out.null && GT[t].type == 1 && GT[t].prec == 16 && (out.i < -32768 || out.i > 32767)) abort();
            if (!v && !out.null && GT[t].type == 2 && (out.i > 999999 || out.i < -999999)) abort();
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
        if (r.cols[c].type < 1 || r.cols[c].type > 6 || (r.cols[c].type == 2 ? r.cols[c].scale > 18 : r.cols[c].scale != 0))
            abort();
    for (uint16_t k = 0; k < r.ndeps; k++) {
        if ((r.dep_kind[k] != 1 && r.dep_kind[k] != 2) || r.dep_id[k] > 1) abort();
        if (k && (r.dep_kind[k - 1] > r.dep_kind[k] || (r.dep_kind[k - 1] == r.dep_kind[k] && r.dep_id[k - 1] >= r.dep_id[k])))
            abort();
    }
    return 0;
}
