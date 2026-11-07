/*
 * P2 D1.1: the backup catalogue, and the erasure debt (design.md §8, "Backup and restore").
 *
 * An ERASE removes a subject's data from the database, its log, its lake and its replicas; a backup made before it
 * still holds the data (a backup is the past, sealed). The catalogue is what lets an operator see and pay that debt:
 * an operator's file (imdb_open_parent) listing a database's backups and the erasures its log records, so `imagedb
 * backups CATALOGUE` can say which listed backups are expired and which hold what an erasure removed, and a restore
 * can refuse a backup older than an erasure (backup.h, imdb_restore_opts).
 *
 * Text lines, appended (O_APPEND) under an exclusive flock that spans the read and the append, each line
 * "<record> <crc>" with crc the CRC32C of the record as 8 lowercase hex digits, decimals canonical (no sign, no
 * leading zero), hex lowercase, one space between fields:
 *   imagedb-catalogue 1 <db id: 32 hex>                  the first line, once
 *   backup <name: hex of its bytes> <full|incremental> <first> <last> <last hash: 64 hex> <made_us> <expires_us>
 *   erase <commit> <time_us>                             an ERASE the database's log records, in commit order
 *   scan <commit>                                        the erasures through this commit are all listed above
 *   forget <name: hex> <time_us>                         the operator destroyed that backup: no longer listed
 * A last line without its newline is an append a crash cut short (never acknowledged: its fsync never returned): a
 * reader ignores it, the next appender cuts it off first. Any other bad line refuses the file whole.
 *
 * The erasures come from the database's log (the commits with op ERASE), scanned from the catalogue's last scan to
 * the log's durable end: at each catalogued backup, and by `backups --debt DIR`. Below a copy's log floor (a RETIRE
 * cut it) its erasures cannot be read: a scan that would begin there begins at the floor, and gap_to says so.
 */
#ifndef IMDB_CATALOGUE_H
#define IMDB_CATALOGUE_H

#include <stdbool.h>
#include <stdint.h>

#include "backup.h"
#include "util.h"

typedef struct imdb_cat_backup {
    char *name; /* its own allocation */
    bool incremental, forgotten;
    uint64_t first, last, made_us, expires_us, forgotten_us;
    uint8_t last_hash[32];
} imdb_cat_backup;

typedef struct imdb_cat_erase {
    uint64_t seq, time_us;
} imdb_cat_erase;

typedef struct imdb_catalogue {
    uint8_t db_id[16];
    bool has_head;        /* an empty (new) file has none */
    imdb_cat_backup *b;
    size_t nb;
    imdb_cat_erase *er;
    size_t ne;
    uint64_t scanned;     /* its erasures are known through this commit */
    uint64_t gap_to;      /* a scan began past a log floor: the erasures at or below this commit may be missing (0: none) */
    size_t whole;         /* the bytes of its complete lines */
    bool torn;            /* a last line without its newline (a crash's): ignored, cut off at the next append */
} imdb_catalogue;

int imdb_catalogue_read(const char *path, imdb_catalogue *c, imdb_err *e);
void imdb_catalogue_free(imdb_catalogue *c);
/* A durable backup listed, with the erasures in src's log from the last scan through its last commit (created with its
 * header when new; a backup of another database, or a name listed already, refused). */
int imdb_catalogue_add_backup(const char *path, const char *name, const imdb_backup_info *bi, const char *src, imdb_err *e);
/* The erasures in src's log past the last scan, through its durable end, listed (*added: how many). */
int imdb_catalogue_note(const char *path, const char *src, uint64_t *added, imdb_err *e);
/* A destroyed backup: listed no longer. */
int imdb_catalogue_forget(const char *path, const char *name, imdb_err *e);
/* The erasures in the database dir's log in (after, its durable end], in commit order (*out its own allocation):
 * *through the end, *floor the log's first commit less one (a cut copy's floor; 0: the log begins at commit 1). */
int imdb_erasures_in(const char *dir, uint64_t after, imdb_cat_erase **out, size_t *n, uint64_t *through, uint64_t *floor,
                     imdb_err *e);

#endif
