#!/bin/bash
# A database bigger than its memory limit opens (P0 storage integrity, 3c-2, 2026-11-04): a lake of ROWS rows of ~2 KB in
# twenty segments is built, then opened, writable and read-only, inside a cgroup whose memory limit (MemoryMax, no
# swap) is at most half the lake's size; each open must answer point queries (a full scan pins every image it reads
# until it ends: 3c-2's item 10), and the run prints the lake's size, the limit, and the open's peak RSS and time
# without one. Root (systemd-run), opt in with IMDB_CRASH_OK=1; not part of make test:
#   IMDB_CRASH_OK=1 bash tests/crash/big_open.sh build/imagedb [ROWS]
# The limit: what the open holds afterwards (SHOW MEMORY), the segment cache's budget (64 MB), the images one chunk of
# 2^16 versions spans (the store's placement counts a chunk before it places it) and 96 MB for the process and the kernel.

BIN=$(readlink -f "${1:?usage: big_open.sh build/imagedb [ROWS]}")
ROWS=${2:-400000}
[ "${IMDB_CRASH_OK:-}" = 1 ] || { echo "big_open.sh: set IMDB_CRASH_OK=1 (root, a memory cgroup)"; exit 2; }
[ "$(id -u)" = 0 ] || { echo "big_open.sh: needs root"; exit 2; }
command -v systemd-run > /dev/null || { echo "big_open.sh: needs systemd-run"; exit 2; }
WORK=$(readlink -f "${IMDB_CRASH_TMP:-build/tmp}")/big-open-$$
mkdir -p "$WORK"
cleanup() { [ "${IMDB_CRASH_KEEP:-}" = 1 ] || rm -rf "$WORK"; }
trap cleanup EXIT
fail() { echo "BIG OPEN: FAILED: $*" >&2; exit 1; }
CACHE=$((64 << 20))

db="$WORK/db"
"$BIN" init "$db" > /dev/null
"$BIN" sql "$db" --nosync -c "CREATE TABLE t (id INT64 PRIMARY KEY, g INT64, s TEXT)" > /dev/null
# the load in pieces of 6 statements of 1,000 rows (~12 MB: under the 16 MiB a CLI before P0 R2 read of a script), a
# CHECKPOINT every twentieth of the rows
per=1000
batches=$((ROWS / per))
awk -v batches="$batches" -v per="$per" -v dir="$WORK" 'BEGIN {
    pad = sprintf("%2000s", ""); gsub(/ /, "w", pad); id = 0; piece = 0
    for (b = 0; b < batches; b++) {
        if (b % 6 == 0) { if (b) close(f); f = sprintf("%s/load-%05d.sql", dir, piece++) }
        printf "INSERT INTO t VALUES " > f
        for (i = 0; i < per; i++) { id++; printf "%s(%d, %d, '\''%s-%d'\'')", (i ? ", " : ""), id, id % 1000, pad, id > f }
        print ";" > f
        if ((b + 1) % (batches / 20) == 0) print "CHECKPOINT;" > f
    }
    close(f)
}'
for f in "$WORK"/load-*.sql; do
    "$BIN" sql "$db" --nosync -f "$f" > "$WORK/load.out" 2>&1 || fail "the load: $(tail -1 "$WORK/load.out")"
    rm -f "$f"
done
"$BIN" sql "$db" --nosync -c "UPDATE t SET g = g + 1 WHERE id <= 2000" > /dev/null # a tail past the last publish
lake=$(du -sb "$db/objects" | cut -f1)
held=$("$BIN" sql "$db" --seg-cache "$CACHE" -c "SHOW MEMORY" | awk '/bytes held/ { print $1 }')
[ -n "$held" ] || fail "SHOW MEMORY said nothing"
chunk=$((lake / ROWS * 65536)) # the images one chunk of versions spans
limit=$((held + CACHE + chunk + (96 << 20)))
[ $((2 * limit)) -le "$lake" ] || fail "the limit ($limit bytes) is more than half the lake ($lake bytes): more ROWS"
Q="SELECT COUNT(*) FROM t WHERE id = 1; SELECT COUNT(*) FROM t WHERE id = $ROWS; SELECT COUNT(*) FROM t WHERE id = $((ROWS + 1))"
/usr/bin/time -f "%e %M" -o "$WORK/time" "$BIN" sql "$db" --seg-cache "$CACHE" --csv -c "$Q" > "$WORK/q.out"
[ "$(tr -d '"' < "$WORK/q.out" | grep -c '^[01]$')" = 3 ] || fail "the point queries: $(cat "$WORK/q.out")"
read -r secs peak < "$WORK/time"
echo "big open: lake $((lake >> 20)) MB in objects/, held once open $((held >> 20)) MB, limit $((limit >> 20)) MB;" \
    "uncapped open ${secs} s, peak RSS $((peak >> 10)) MB"
for mode in "" "--read-only"; do
    out=$(systemd-run --scope --quiet -p MemoryMax="$limit" -p MemorySwapMax=0 \
        "$BIN" sql "$db" $mode --seg-cache "$CACHE" --csv -c "$Q" 2>&1) || fail "the open ${mode:-writable} under the limit: $out"
    [ "$(printf '%s\n' "$out" | tr -d '"' | grep -c '^[01]$')" = 3 ] && [ "$(printf '%s\n' "$out" | tr -d '"' | grep -c '^1$')" = 2 ] ||
        fail "the open ${mode:-writable} under the limit: $out"
    echo "big open: ${mode:-writable} open under the limit answered (two rows found, one absent)"
done
echo "BIG OPEN: ALL CHECKS PASSED"
