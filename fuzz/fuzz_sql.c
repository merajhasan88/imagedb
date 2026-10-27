/* SQL lexer + parser: any byte string must be rejected or parsed, never crash. */
#include "../src/sql_internal.h"
#include "fuzz_common.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    char *s = malloc(size ? size : 1);
    memcpy(s, data, size);
    sql_stmt st;
    imdb_err e = {0};
    if (imdb_sql_parse(s, size, &st, &e) == 0) imdb_sql_stmt_free(&st);
    free(s);
    return 0;
}
