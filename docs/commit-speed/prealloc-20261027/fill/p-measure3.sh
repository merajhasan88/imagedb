#!/bin/sh
# throwaway (2026-10-27): the fill policy changed (no extension under --nosync, none after a frame over
# 256 KiB): the tree before P, P as first measured (p1) and P with the new policy (p2), ABCCBA, in one
# performance window (.work/window.sh), bench/devstall watching the disk. Raw output to $OUT.
#   sh .work/window.sh sh .work/p-measure3.sh OUT
set -u
OUT=$1
mkdir -p "$OUT"
T=/home/developer/imagedb/build/tmp
D=$T/pm3
mkdir -p "$D"
"/home/developer/imagedb/build/devstall" sda > "$OUT/devstall.txt" 2>&1 &
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
abccba() { # case mode rows k
    c=$1; shift
    for x in 1-before 1-p1 1-p2 2-p2 2-p1 2-before; do
        run "$c-$x" "$T/commit_lat-${x#*-}" "$1" "$D/$c-$x" "$2" "$3"
    done
}
abccba nosync nosync 200000 1000   # a --nosync load: P's extensions fdatasynced (p1), none (p2)
abccba nosync1 nosync 20000 1      # one-row commits under --nosync
abccba sync10k sync 200000 10000   # frames of about 1 MB: p1 extended after each, p2 never
abccba sync1k sync 200000 1000     # frames of about 106 KB: both extend (unchanged)
abccba sync sync 8000 1            # one-row durable commits: unchanged
echo "done $(date +%H:%M:%S)" >> "$OUT/runs.txt"
