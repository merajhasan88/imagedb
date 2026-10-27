/* throwaway (2026-10-27): the index of a tagged segment's last non-zero sector (for a torn-tail test) */
#include <stdio.h>
#include <stdlib.h>
int main(int argc, char **argv)
{
    FILE *f = argc == 2 ? fopen(argv[1], "rb") : NULL;
    if (!f) return 2;
    unsigned char s[512];
    long i = 0, last = -1;
    while (fread(s, 1, 512, f) == 512) {
        for (int k = 0; k < 512; k++)
            if (s[k]) {
                last = i;
                break;
            }
        i++;
    }
    fclose(f);
    if (last < 1) return 1;
    printf("%ld\n", last);
    return 0;
}
