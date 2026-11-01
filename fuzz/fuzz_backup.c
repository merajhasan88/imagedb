/* Backup files (src/backup.c) under a fixed test key: the prologue, each chunk's header, its tag, the parts and the
 * summary, all read strictly. A changed byte inside a sealed chunk fails its tag, so this mostly exercises the
 * clear parts' parsers (the prologue, the chunk headers, the order and the lengths). The input goes to a file of its
 * own, as a backup is read from one (TMPDIR, else /dev/shm). The corpus (make_corpus.sh) holds a backup made with
 * this key: 32 bytes of 'B'. */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "../src/backup.h"
#include "fuzz_common.h"

static char g_path[512];

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (!g_path[0]) {
        const char *d = getenv("TMPDIR");
        snprintf(g_path, sizeof g_path, "%s/imagedb-fuzz-backup-%d.bak", d && *d ? d : "/dev/shm", (int)getpid());
    }
    FILE *f = fopen(g_path, "wb");
    if (!f) return 0;
    if (size) fwrite(data, 1, size, f);
    fclose(f);
    uint8_t key[IMDB_BACKUP_KEY_LEN];
    memset(key, 'B', sizeof key);
    imdb_backup_info bi;
    imdb_err e = {0};
    (void)imdb_backup_check(g_path, key, &bi, &e);
    unlink(g_path);
    return 0;
}
