#!/bin/sh
# throwaway (2026-10-27): preallocation (P) measured against the tree before it (main after the review's
# merge), in one performance window (.work/window.sh), alternating ABBA, on this machine's SSD, with
# bench/devstall watching the disk; then P against F as write patterns (group_probe). Raw output to $OUT.
#   sh .work/window.sh sh .work/p-measure.sh OUT
set -u
OUT=$1
mkdir -p "$OUT"
B=/home/developer/imagedb/build/tmp/commit_lat-before   # built from main's tree
A=/home/developer/imagedb/.work/prealloc/build/commit_lat
G=/home/developer/imagedb/.work/prealloc/build/group_probe
DS=/home/developer/imagedb/build/devstall
D=/home/developer/imagedb/build/tmp/pm
mkdir -p "$D"
"$DS" sda > "$OUT/devstall.txt" 2>&1 &
dsp=$!
trap 'kill $dsp 2>/dev/null' EXIT
run() { # label binary args...
    l=$1; shift
    sync; sleep 5
    echo "== $l $(date +%H:%M:%S.%N | cut -c1-12) $*" >> "$OUT/runs.txt"
    "$@" > "$OUT/$l.txt" 2>&1
    echo "rc $?" >> "$OUT/$l.txt"
    echo "   end $(date +%H:%M:%S.%N | cut -c1-12)" >> "$OUT/runs.txt"
}
abba() { # case mode rows k
    c=$1; shift
    run "$c-1-before" "$B" "$1" "$D/$c-b1" "$2" "$3"
    run "$c-1-after" "$A" "$1" "$D/$c-a1" "$2" "$3"
    run "$c-2-after" "$A" "$1" "$D/$c-a2" "$2" "$3"
    run "$c-2-before" "$B" "$1" "$D/$c-b2" "$2" "$3"
}
abba sync sync 8000 1              # one-row durable commits: four 1 MiB fills of P, a rotation at 4,000
abba strict durable-ack 2000 1     # the watermark fsynced per commit too
abba sync1k sync 200000 1000       # 200 durable transactions of 1,000 rows
abba sync10k sync 200000 10000     # 20 of 10,000 rows: frames larger than P's fill
abba nosync nosync 200000 1000     # a --nosync load, then the close's sync
run group-probe "$G" "$D" 200 330  # P against F as write patterns
echo "done $(date +%H:%M:%S)" >> "$OUT/runs.txt"
