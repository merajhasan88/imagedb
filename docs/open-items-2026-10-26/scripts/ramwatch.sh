#!/bin/sh
# throwaway: memory beside a heavy job (the user, 2026-10-24: "watch the RAM!!!"). Refuses to
# start the job below 4 GB available; samples every 30 s while it runs; prints the lowest
# available and the largest resident process seen.
#   sh .work/ramwatch.sh LOG CMD [ARG...]
set -u
log=$1
shift
avail() { awk '/^MemAvailable:/ {printf "%d", $2 / 1024}' /proc/meminfo; }
a=$(avail)
if [ "$a" -lt 4096 ]; then
    echo "ramwatch: only $a MB available: not starting" | tee -a "$log"
    exit 3
fi
echo "ramwatch: start $(date +%H:%M:%S), $a MB available" > "$log"
(
    while :; do
        top=$(ps -eo rss=,comm= --sort=-rss | head -1 | awk '{printf "%s %d MB", $2, $1 / 1024}')
        echo "$(date +%H:%M:%S) avail $(avail) MB, largest $top" >> "$log"
        sleep 30
    done
) &
w=$!
"$@"
rc=$?
kill "$w" 2>/dev/null
awk '/ avail / {a = $3 + 0; if (min == "" || a < min) {min = a; at = $1}}
     / largest / {split($0, p, "largest "); split(p[2], q, " "); r = q[2] + 0; if (r > max) {max = r; who = q[1]}}
     END {printf "ramwatch: lowest available %d MB (at %s), largest process %s %d MB\n", min, at, who, max}' "$log" | tee -a "$log"
exit "$rc"
