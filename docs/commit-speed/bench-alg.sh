#!/bin/sh
# throwaway: build/bench four times in one measurement window, IMDB_DIGEST_ALG 1, 2, 1, 2, so drift
# shows; each run keeps its databases just long enough for imagedb info to name their algorithm
#   sh .work/window.sh sh .work/bench-alg.sh OUTDIR
set -eu
cd /home/developer/imagedb
O=${1:?usage: bench-alg.sh OUTDIR}
mkdir -p "$O" build/tmp
i=0
for a in 1 2 1 2; do
    i=$((i + 1))
    f="$O/run$i-alg$a.txt"
    echo "== run $i: IMDB_DIGEST_ALG=$a, $(date +%H:%M:%S), load $(cut -d' ' -f1 /proc/loadavg)," \
         "mean clock $(awk '/^cpu MHz/ {s += $4; n++} END {if (n) printf "%.0f", s / n}' /proc/cpuinfo) MHz" | tee "$f"
    IMDB_TEST_TMP=build/tmp IMDB_BENCH_KEEP=1 IMDB_DIGEST_ALG=$a build/bench >> "$f" 2>&1
    build/imagedb info build/tmp/bench-primary 2>&1 | grep -E '^ *algorithm' >> "$f"
    build/imagedb info build/tmp/bench-replica 2>&1 | grep -E '^ *algorithm' >> "$f"
    cat "$f"
done
rm -rf build/tmp/bench-primary build/tmp/bench-replica build/tmp/bench-stream
echo "== done $(date +%H:%M:%S)"
