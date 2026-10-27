/*
 * The commit log is a directory of segments: log/<first seq, 20 digits>.ilg.
 *
 * Rotation is a pure function of the log. A commit that publishes a lake
 * manifest (CHECKPOINT, COMPACT, ERASE) is the last frame of its segment, and
 * the next commit starts a new file named by its seq. Consequences:
 *   - a replica's segments begin and end at the primary's commits and hold its frames byte for
 *     byte (tagged segments: their sectors follow each copy's own syncs, design.md §3), whatever its
 *     history (a replica that bootstraps from an already-redacted log too);
 *   - a lake snapshot at commit S always ends a segment, so open can load the
 *     snapshot and replay only the segments after it;
 *   - ERASE rewrites only the segments that hold erased payloads.
 * Only the last segment may end in a torn frame, and only the last may be
 * empty (a crash after creating it); any other irregularity is corruption.
 */
#ifndef IMDB_LOGDIR_H
#define IMDB_LOGDIR_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "log.h"
#include "util.h"

#define IMDB_LOG_DIR "log"
#define IMDB_LOGSEG_NAME 24 /* 20 digits + ".ilg" */

void imdb_logseg_name(uint64_t first, char out[IMDB_LOGSEG_NAME + 1]);
bool imdb_logseg_parse(const char *name, uint64_t *first);
/* Sorted, validated first seqs of every segment; anything else in log/ (a
 * stray file, a symlink, a malformed name) is refused, except the temporary
 * <segment>.tmp of a redaction rewrite (a regular file beside its regular
 * segment): until its rename the segment is authoritative, so readers skip it
 * (ship --follow runs during a live ERASE) and a writable open removes one a
 * crash left (imdb_logdir_cleanup_temps). */
int imdb_logdir_list(int logfd, uint64_t **firsts, size_t *n, imdb_err *e);
/* Writable open, under LOCK: remove regular <segment>.tmp files left by
 * interrupted atomic redaction. All other unexpected entries stay errors. */
int imdb_logdir_cleanup_temps(int logfd, imdb_err *e);
/* DURABLE (log.h) at the data directory root. *present = false when there is
 * none, or it is empty (a crash right after creating it). A malformed record is
 * re-read a few times (a concurrent writer rewrites it in place) and then is an
 * error. */
int imdb_durable_read(int dirfd, imdb_durable *w, bool *present, imdb_err *e);
/* Index of the segment holding seq (greatest first <= seq); n if none. */
size_t imdb_logseg_find(const uint64_t *firsts, size_t n, uint64_t seq);
int imdb_logseg_read(int logfd, uint64_t first, uint8_t **buf, size_t *len, imdb_err *e);

/* A segment read for its frames, in either format (log.h): buf[0..len) holds its frames back to
 * back (an untagged segment's own bytes, a tagged one's compacted by imdb_tseg_scan, which also
 * gave the verdict for what follows them, tail, and where it ended, end). */
typedef struct imdb_logseg {
    uint64_t first;
    uint8_t *buf;
    size_t len, size; /* the frames' bytes; the file's */
    bool tagged;
    imdb_scan_status tail; /* tagged: END, TORN, DAMAGED or CORRUPT after the frames */
    imdb_tseg_end end;
    char tail_msg[256];
} imdb_logseg;
int imdb_logseg_load(int logfd, uint64_t first, imdb_logseg *s, imdb_err *e);
void imdb_logseg_free(imdb_logseg *s); /* wipes: an erased payload may be in it until redaction */
/* imdb_frame_scan over its frames; at their end, a tagged segment's verdict (with its message). */
imdb_scan_status imdb_logseg_scan(const imdb_logseg *s, size_t off, size_t *flen, imdb_err *e);
/* Nothing but zeros, or no byte at all: a new segment whose header never landed (a crash in
 * log_new_segment), which a writable open makes tagged; as the last segment it follows a tagged one
 * too (design.md §3), and holds no frame. */
bool imdb_logseg_blank(const imdb_logseg *s);
/* A writable open dropping a tagged segment's TORN or DAMAGED end (design.md §3, the scan's rule 5):
 * the sector E falls in keeps its tag and the bytes before E, every later non-zero sector is
 * zeroed, then fsync. */
int imdb_logseg_drop_tail(int logfd, const imdb_logseg *s, imdb_err *e);

#endif
