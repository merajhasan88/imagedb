#!/bin/sh
# throwaway (2026-10-27): the case where P and F differ in the engine: one-row commits under --nosync
# (a group of many small frames between syncs), ABBA; then a torn tail repaired by the writable open.
set -u
OUT=$1
B=/home/developer/imagedb/build/tmp/commit_lat-before
A=/home/developer/imagedb/.work/prealloc/build/commit_lat
D=/home/developer/imagedb/build/tmp/pm
"/home/developer/imagedb/build/devstall" sda > "$OUT/devstall2.txt" 2>&1 &
dsp=$!
trap 'kill $dsp 2>/dev/null' EXIT
for x in 1-before:$B 1-after:$A 2-after:$A 2-before:$B; do
    l=${x%%:*}; bin=${x#*:}
    sync; sleep 5
    echo "== nosync1-$l $(date +%H:%M:%S)" >> "$OUT/runs.txt"
    "$bin" nosync "$D/nosync1-$l" 20000 1 > "$OUT/nosync1-$l.txt" 2>&1
    echo "rc $?" >> "$OUT/nosync1-$l.txt"
done
