/* ThreadSanitizer driver for the pool tests (make tsan; not part of the matrix:
 * ASan and TSan cannot share a build, and only src/pool.c shares memory between threads). */
#include <stdio.h>
#include "../unit/test.h"
int g_test_failed;
char g_errmsg[512];
void test_fail(const char *file, int line, const char *what)
{
    fprintf(stderr, "FAIL %s:%d: %s\n", file, line, what);
    g_test_failed = 1;
}
int main(void)
{
    int failed = 0;
    for (size_t i = 0; i < pool_ntests; i++) {
        g_test_failed = 0;
        printf("[pool] %s\n", pool_tests[i].name);
        fflush(stdout);
        pool_tests[i].fn();
        failed += g_test_failed;
    }
    printf("%zu tests, %d failed\n", pool_ntests, failed);
    return failed != 0;
}
