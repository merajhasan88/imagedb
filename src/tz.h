/* P2's zone slice: IANA time zones read from the operator's zoneinfo directory (TZif files, RFC 8536) by our own
 * strict reader (design.md §5, Time zones). A zone belongs to a database handle (db.c imdb_tz_get: loaded once, at
 * bind time, freed at close); a conversion only reads it, so the parallel workers may. Nothing stored depends on a
 * zone: a write converts at the write and the log holds the value it wrote. */
#ifndef IMDB_TZ_H
#define IMDB_TZ_H

#include <stdbool.h>
#include <stdint.h>

#include "limits.h"
#include "util.h"

/* a footer's POSIX TZ string (RFC 8536 3.3): the standard offset, and with daylight time its offset and two yearly
 * rules; offsets in seconds east of UTC (POSIX writes them west: the reader turns them) */
typedef struct imdb_tzwhen {
    uint8_t kind;  /* 'J': Julian day 1-365, Feb 29 never counted; 'D': day 0-365, counted; 'M': month.week.day */
    int16_t a, b, c; /* J/D: a the day; M: a the month 1-12, b the week 1-5 (5: the last), c the weekday 0-6 (Sunday 0) */
    int32_t time;  /* the local time of day it happens, seconds (RFC 8536: -167 to 167 hours) */
} imdb_tzwhen;

typedef struct imdb_tzrule {
    int32_t std_off, dst_off;
    bool has_dst;
    imdb_tzwhen start, end; /* start: in standard time; end: in daylight time (POSIX) */
} imdb_tzrule;

typedef struct imdb_tz {
    char name[IMDB_MAX_TZ_NAME + 1];
    uint32_t n;     /* transitions */
    int64_t *at;    /* their UTC instants, seconds, strictly increasing */
    int32_t *off;   /* the offset in effect from each one */
    int64_t *lat;   /* at[i] + off[i]: the local time from which transition i's offset reads a wall-clock time */
    bool lat_sorted; /* lat increasing (every real zone): binary search, else a scan */
    int32_t off0;   /* before the first transition: time type 0 (RFC 8536) */
    bool has_rule;  /* the footer gives the instants past the last transition */
    imdb_tzrule rule;
} imdb_tz;

/* a zone's name: 1 to IMDB_MAX_TZ_NAME bytes of letters, digits, / _ - +, no leading /, no empty, . or .. component */
bool imdb_tz_name_ok(const char *s, size_t n);
/* a TZif file (version 2 or later: its 64-bit section and footer), strict: counts within limits.h, transitions
 * increasing, every index and offset in range, no leap seconds (a right/ zone: refused), the footer parsed whole.
 * UNSUPPORTED for a version 1 file or one with leap seconds, CORRUPT otherwise. z's arrays its own (imdb_tz_free). */
int imdb_tz_parse(const uint8_t *b, size_t len, imdb_tz *z, imdb_err *e);
/* UTC, with no file */
void imdb_tz_utc(imdb_tz *z);
void imdb_tz_free(imdb_tz *z);
/* the offset in seconds east of UTC at UTC instant t (microseconds) */
int32_t imdb_tz_offset(const imdb_tz *z, int64_t t_us);
/* the UTC instant of wall-clock time l in the zone (microseconds), by PostgreSQL's rule: a time in a spring-forward gap
 * takes the offset from before the transition, one in a fall-back overlap the offset after it; both are the offset of
 * the last transition whose local start (its instant plus its new offset) is at or before l */
int64_t imdb_tz_utc_of_local(const imdb_tz *z, int64_t l_us);
/* P2: the offset at t and the span [*lo_us, *hi_us) around t where it holds (a caller's cache: rows in time order read
 * the transition list once a transition); microseconds saturated at the ends of int64 */
int32_t imdb_tz_offset_span(const imdb_tz *z, int64_t t_us, int64_t *lo_us, int64_t *hi_us);
/* a footer's string alone (tests, the parser's) */
int imdb_tz_rule_parse(const char *s, size_t n, imdb_tzrule *r, imdb_err *e);

/* a zone file under root, by name (imdb_tz_name_ok's): read whole, parsed, its name set; *out the caller's
 * (imdb_tz_free, then imdb_free). An unknown zone is INVALID, its message never naming it: a name can be a row's value */
int imdb_tz_load(const char *root, const char *name, size_t len, imdb_tz **out, imdb_err *e);
/* UTC itself, with no file: what UTC, Etc/UTC, GMT and Etc/GMT name (in any case), on a host with no zoneinfo too */
extern const imdb_tz imdb_tz_utc_zone;
bool imdb_tz_builtin_utc(const char *s, size_t n);

#endif
