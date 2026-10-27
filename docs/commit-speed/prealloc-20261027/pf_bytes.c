/* throwaway (2026-10-27): a log's bytes three ways for the same frames: untagged (the frames back to
 * back), P as written (header + every sector up to the end of the last group; the fill not counted),
 * and F as it would have been (header + each frame on fresh sectors of its own: ceil(len/504) each).
 *   pf_bytes DIR   (built against the preallocation tree: -I src, libimagedb.a) */
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "log.h"
#include "logdir.h"

int main(int argc, char **argv)
{
    if (argc != 2) return 2;
    char p[1100];
    snprintf(p, sizeof p, "%s/log", argv[1]);
    DIR *d = opendir(p);
    if (!d) return 1;
    unsigned long long frames = 0, untagged = 0, pbytes = 0, fbytes = 0, fill = 0;
    struct dirent *de;
    while ((de = readdir(d))) {
        uint64_t first;
        if (!imdb_logseg_parse(de->d_name, &first)) continue;
        char f[1400];
        snprintf(f, sizeof f, "%s/%s", p, de->d_name);
        FILE *fp = fopen(f, "rb");
        if (!fp) return 1;
        fseek(fp, 0, SEEK_END);
        long n = ftell(fp);
        fseek(fp, 0, SEEK_SET);
        uint8_t *b = malloc(n ? (size_t)n : 1);
        if (n && fread(b, 1, (size_t)n, fp) != (size_t)n) return 1;
        fclose(fp);
        if (!imdb_tseg_is_tagged(b, (size_t)n)) {
            untagged += (unsigned long long)n;
            free(b);
            continue;
        }
        size_t len;
        imdb_tseg_end e;
        imdb_err er = {0};
        if (imdb_tseg_scan(b, (size_t)n, first, &len, &e, &er) != IMDB_SCAN_END) {
            fprintf(stderr, "%s: %s\n", de->d_name, er.msg);
            return 1;
        }
        pbytes += e.next * IMDB_TSEG_SECTOR;
        fill += (unsigned long long)n - e.next * IMDB_TSEG_SECTOR;
        fbytes += IMDB_TSEG_SECTOR;
        untagged += len;
        for (size_t off = 0; off < len;) {
            size_t fl = IMDB_FRAME_HDR + imdb_get_le32(b + off + 4);
            fbytes += (fl + IMDB_TSEG_PAYLOAD - 1) / IMDB_TSEG_PAYLOAD * IMDB_TSEG_SECTOR;
            frames++;
            off += fl;
        }
        free(b);
    }
    closedir(d);
    printf("pf_bytes frames %llu\n", frames);
    printf("pf_bytes untagged %llu bytes\n", untagged);
    printf("pf_bytes P %llu bytes (+%.1f%%)\n", pbytes, untagged ? 100.0 * ((double)pbytes / (double)untagged - 1) : 0);
    printf("pf_bytes F %llu bytes (+%.1f%%)\n", fbytes, untagged ? 100.0 * ((double)fbytes / (double)untagged - 1) : 0);
    printf("pf_bytes P_fill %llu bytes\n", fill);
    return 0;
}
