#!/bin/bash
# A long-running, failure-prone workload (deferred.md D8, the 10-26 review's milestone: "correctness and
# bounded operation under a long-running, failure-prone workload"). soak_writer.c churns over a fixed
# live set and is killed (SIGKILL) at random moments, then restarted: each restart's reopen must keep
# the last acknowledged commit with its hash (the writer checks, exit 3), and every Nth restart VERIFY
# and the independent auditor must pass on the stopped database. Memory (the engine's report and the
# writer's RSS, every 10 s) and disk (the log and the whole directory, at each restart) go to CSV files,
# so a change can show whether memory and disk level off. Not part of make test: it runs for hours.
#   IMDB_SOAK_TMP=build/tmp bash tests/soak/soak.sh build/imagedb [MINUTES] [LIVE]
# Knobs: IMDB_SOAK_KILL (mean seconds between kills, 60), IMDB_SOAK_VERIFY (VERIFY every Nth restart, 5),
# IMDB_SOAK_AUDIT (the auditor at every Nth VERIFY and at the end, 1; 0: never: 0.24 ms a commit at 3.28 M, so a long
# run keeps its database, IMDB_SOAK_KEEP=1, and audits it afterwards), IMDB_SOAK_TREE (what is under test, for
# MACHINE.txt),
# IMDB_SOAK_SYNC (1; 0: --nosync), IMDB_SOAK_RETAIN (--retain-history commits, 0: all
# history kept), IMDB_SOAK_CHECKPOINT and IMDB_SOAK_ERASE (commits between them, by the log's sequence, so
# across restarts; 50000 and 20000; 0: never), IMDB_SOAK_FLOOR (MB of MemAvailable below which it stops,
# 4608: the user's 4 GB and a margin), IMDB_SOAK_KEEP=1 keeps the database.
# A run in which an asked-for ERASE or CHECKPOINT never completed did not test what it was asked to: it
# ends SOAK INCOMPLETE (exit 5), not PASSED. A final VERIFY that counts no erased version after an ERASE
# completed is a FAIL.
set -euo pipefail

BIN=$(readlink -f "${1:?usage: soak.sh build/imagedb [MINUTES] [LIVE]}")
MIN=${2:-120}
LIVE=${3:-100000}
B=$(dirname "$BIN")
AUDIT=$B/imagedb-audit
HERE=$(cd "$(dirname "$0")" && pwd)
KILL=${IMDB_SOAK_KILL:-60}
VEVERY=${IMDB_SOAK_VERIFY:-5}
AEVERY=${IMDB_SOAK_AUDIT:-1}
FLOOR=${IMDB_SOAK_FLOOR:-4608}
W=$(readlink -f "${IMDB_SOAK_TMP:-build/tmp}")/soak-$$
D=$W/db
mkdir -p "$W"
[ -x "$AUDIT" ] || { echo "soak.sh: $AUDIT not built"; exit 2; }
cc -std=c11 -D_GNU_SOURCE -O2 -Wall -Wextra -Werror -pthread -I "$HERE/../../src" -o "$W/soak_writer" \
    "$HERE/soak_writer.c" "$B/libimagedb.a"
OPTS=()
[ "${IMDB_SOAK_SYNC:-1}" = 1 ] || OPTS+=(--nosync)
[ "${IMDB_SOAK_RETAIN:-0}" = 0 ] || OPTS+=(--retain "$IMDB_SOAK_RETAIN")
OPTS+=(--checkpoint "${IMDB_SOAK_CHECKPOINT:-50000}" --erase "${IMDB_SOAK_ERASE:-20000}")
OUT=$W/out
mkdir -p "$OUT"
echo "soak: $MIN min, $LIVE live rows, a kill every ~${KILL} s, VERIFY every ${VEVERY} restarts, the auditor every ${AEVERY} VERIFY (0: never); writer ${OPTS[*]}; in $W"
{
    echo "started $(date "+%Y-%m-%d %H:%M:%S %z"); tree: ${IMDB_SOAK_TREE:-unknown}; $MIN min, $LIVE live, kill ~$KILL s, VERIFY every $VEVERY, audit every $AEVERY"
    echo "writer: ${OPTS[*]}"
    echo "governor: $(sort /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor 2>/dev/null | uniq -c | tr -s " " | tr "\n" " "); profile: $(powerprofilesctl get 2>/dev/null || echo -)"
    echo "kernel: $(uname -r); cpu: $(awk -F": " '/model name/ {print $2; exit}' /proc/cpuinfo)"
    echo "filesystem: $(findmnt -no SOURCE,FSTYPE,OPTIONS -T "$W"); disk: $(lsblk -no MODEL "/dev/$(lsblk -no PKNAME "$(findmnt -no SOURCE -T "$W")" | head -n 1)" 2>/dev/null | head -n 1)"
} > "$OUT/MACHINE.txt"
cleanup() {
    set +e
    [ -n "${WPID:-}" ] && kill -9 "$WPID" 2>/dev/null && wait "$WPID" 2>/dev/null
    [ "${IMDB_SOAK_KEEP:-}" = 1 ] || rm -rf "$D"
}
trap cleanup EXIT
avail() { awk '/^MemAvailable:/ {printf "%d", $2 / 1024}' /proc/meminfo; }
check() { # NAME AUDIT: VERIFY through the CLI's writable open (recovery first), then the auditor if AUDIT is 1
    local t0 t1 t2
    t0=$(date +%s.%N)
    "$BIN" sql "$D" -c "VERIFY;" > "$OUT/verify-last.txt" 2>&1 || { echo "FAIL: VERIFY after restart $1:" >&2; tail -n 5 "$OUT/verify-last.txt" >&2; exit 1; }
    t1=$(date +%s.%N)
    if [ "$2" = 1 ]; then
        "$AUDIT" verify "$D" > "$OUT/audit-last.txt" 2>&1 || { echo "FAIL: the auditor after restart $1:" >&2; tail -n 5 "$OUT/audit-last.txt" >&2; exit 1; }
        t2=$(date +%s.%N)
        awk -v a="$t0" -v b="$t1" -v c="$t2" 'BEGIN {printf "%.2f %.2f", b - a, c - b}'
    else
        awk -v a="$t0" -v b="$t1" 'BEGIN {printf "%.2f -", b - a}'
    fi
}

"$BIN" init "$D" > /dev/null
"$W/soak_writer" "$D" load "$LIVE" "$OUT/acks" || { echo "FAIL: the load"; exit 1; }
echo "t_s restarts commits log_bytes dir_bytes verify_s audit_s avail_mb alive_s" > "$OUT/disk.csv"
echo "run t_s commits versions rows indexes segments commits_mem txns total rss_kb" > "$OUT/memory.csv"
: > "$OUT/events"
start=$(date +%s)
end=$((start + MIN * 60))
restarts=0 early= checks=0 alive=0 # alive: the writers' seconds, the rate's denominator (not the checks' time)
while :; do
    nowt=$(date +%s)
    left=$((end - nowt))
    [ "$left" -gt 0 ] || break
    if [ "$(avail)" -lt "$FLOOR" ]; then early="MemAvailable $(avail) MB, under the floor ($FLOOR MB)"; echo "stopping: $early"; break; fi
    : > "$OUT/stats-run"
    run_start=$(date +%s)
    "$W/soak_writer" "$D" churn "$LIVE" "$left" "$((restarts + 1))" "$OUT/acks" "$OUT/stats-run" "${OPTS[@]}" \
        --events "$OUT/events" 2> "$OUT/writer-err.txt" &
    WPID=$!
    nap=$((KILL / 2 + RANDOM % (KILL + 1)))
    [ "$nap" -lt "$left" ] || nap=$left
    while [ "$nap" -gt 0 ] && kill -0 "$WPID" 2>/dev/null; do
        sleep 1
        nap=$((nap - 1))
        if [ "$(avail)" -lt "$FLOOR" ]; then break; fi
    done
    rc=0
    if kill -0 "$WPID" 2>/dev/null; then
        kill -9 "$WPID"
        wait "$WPID" 2>/dev/null || true
    else
        wait "$WPID" || rc=$?
    fi
    WPID=
    alive=$((alive + $(date +%s) - run_start))
    awk -v r="$restarts" -v off="$((run_start - start))" '{$1 = sprintf("%.1f", $1 + off); print r, $0}' "$OUT/stats-run" >> "$OUT/memory.csv"
    case $rc in
        0) ;;
        3) echo "FAIL: $(cat "$OUT/writer-err.txt")"; exit 1 ;;
        *) echo "FAIL: the writer stopped with $rc:"; tail -n 3 "$OUT/writer-err.txt"; exit 1 ;;
    esac
    restarts=$((restarts + 1))
    times="- -"
    if [ $((restarts % VEVERY)) -eq 0 ]; then
        checks=$((checks + 1))
        a=0
        [ "$AEVERY" -gt 0 ] && [ $((checks % AEVERY)) -eq 0 ] && a=1
        times=$(check "$restarts" "$a")
    fi
    commits=$(awk 'END {print $1}' "$OUT/acks")
    echo "$(( $(date +%s) - start )) $restarts $commits $(du -sb "$D/log" | cut -f1) $(du -sb "$D" | cut -f1) $times $(avail) $alive" \
        >> "$OUT/disk.csv"
done
a=0
[ "$AEVERY" -gt 0 ] && a=1
times=$(check final "$a")
commits=$(awk 'END {print $1}' "$OUT/acks")
echo "$(( $(date +%s) - start )) $restarts $commits $(du -sb "$D/log" | cut -f1) $(du -sb "$D" | cut -f1) $times $(avail) $alive" \
    >> "$OUT/disk.csv"
echo "restarts: $restarts, commits: $commits, every acknowledged commit kept across every kill; final VERIFY and audit: $times s"
echo "durable commits per second the writers ran: $(awk -v c="$commits" -v s="$alive" 'BEGIN {printf "%.0f", s ? c / s : 0}') ($commits in $alive s)"
[ "$a" = 1 ] || echo "the auditor did not run (IMDB_SOAK_AUDIT=0): run build/imagedb-audit verify $D (IMDB_SOAK_KEEP=1 keeps it)"
echo "disk (bytes), first and last: $(awk 'NR == 2 {print "log " $4 ", dir " $5}' "$OUT/disk.csv") -> $(awk 'END {print "log " $4 ", dir " $5}' "$OUT/disk.csv")"
echo "writer RSS (kB), highest: $(awk 'NR > 1 && $11 > m {m = $11} END {print m}' "$OUT/memory.csv"); engine total (bytes), highest: $(awk 'NR > 1 && $10 > m {m = $10} END {print m}' "$OUT/memory.csv")"
ev() {
    awk -v w="$1" '$1 == w && $2 == "start" {s++} $1 == w && $2 == "done" {d++; if ($4 > m) m = $4}
        END {printf "%d started, %d completed, %d cut short by a kill, the longest %.1f s", s, d, s - d, m}' "$OUT/events"
}
completed() { awk -v w="$1" '$1 == w && $2 == "done" {d++} END {print d + 0}' "$OUT/events"; }
erased=$(sed -n 's/.* live, \([0-9][0-9]*\) erased).*/\1/p' "$OUT/verify-last.txt")
echo "ERASE: $(ev erase); CHECKPOINT: $(ev checkpoint); the final VERIFY counts ${erased:-no} erased versions"
echo "reopen (the engine's open after each kill), seconds: $(awk '$1 == "open" {n++; if (n == 1) f = $4; l = $4; if ($4 > m) m = $4}
    END {printf "%d opens, the first %.2f, the last %.2f, the longest %.2f", n, f, l, m}' "$OUT/events")"
if [ "$(completed erase)" -gt 0 ] && [ "${erased:-0}" = 0 ]; then
    echo "FAIL: $(completed erase) ERASE completed, but the final VERIFY counts no erased version:"; tail -n 2 "$OUT/verify-last.txt"; exit 1
fi
incomplete=
[ "${IMDB_SOAK_ERASE:-20000}" = 0 ] || [ "$(completed erase)" -gt 0 ] ||
    incomplete="no ERASE completed (one every ${IMDB_SOAK_ERASE:-20000} commits asked for)"
[ "${IMDB_SOAK_CHECKPOINT:-50000}" = 0 ] || [ "$(completed checkpoint)" -gt 0 ] ||
    incomplete="${incomplete:+$incomplete; }no CHECKPOINT completed (one every ${IMDB_SOAK_CHECKPOINT:-50000} commits asked for)"

if [ -n "$early" ]; then echo "SOAK STOPPED EARLY ($early); the data: $OUT"; exit 4; fi
if [ -n "$incomplete" ]; then echo "SOAK INCOMPLETE ($incomplete): it did not test what it was asked to; the data: $OUT"; exit 5; fi
echo "SOAK PASSED (data: $OUT)"
