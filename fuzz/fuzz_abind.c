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

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    static ab_result r;
    char err[256];
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
