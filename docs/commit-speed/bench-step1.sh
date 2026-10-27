#!/bin/sh
# throwaway: step 1 as shipped against the tree before it, in one measurement window: main before
# the digest_alg 2 merge (build/tmp/pre-e3a: per-row getrandom salts, alg 1 only), main after it
# under alg 1 (per-statement salts) and under alg 2; twice, rotated, so drift shows
#   sh .work/window.sh sh .work/bench-salts.sh OUTDIR
set -eu
cd /home/developer/imagedb
O=${1:?usage: bench-salts.sh OUTDIR}
mkdir -p "$O" build/tmp
i=0
for k in old new1 new2 old new1 new2; do
    i=$((i + 1))
    case $k in
    old) b=build/tmp/pre-e3a/build/bench; a=1 ;;
    new1) b=build/bench; a=1 ;;
    new2) b=build/bench; a=2 ;;
    esac
    f="$O/run$i-$k.txt"
    echo "== run $i: $k ($b, IMDB_DIGEST_ALG=$a), $(date +%H:%M:%S), load $(cut -d' ' -f1 /proc/loadavg)," \
         "mean clock $(awk '/^cpu MHz/ {s += $4; n++} END {if (n) printf "%.0f", s / n}' /proc/cpuinfo) MHz" | tee "$f"
    IMDB_TEST_TMP=build/tmp IMDB_BENCH_KEEP=1 IMDB_DIGEST_ALG=$a "$b" >> "$f" 2>&1
    build/imagedb info build/tmp/bench-primary 2>&1 | grep -E '^ *algorithm' >> "$f"
    cat "$f" | grep -E '^== |^engine|^  (bulk insert|single-row txn|VERIFY|replica apply|reopen)|^algorithm'
done
rm -rf build/tmp/bench-primary build/tmp/bench-replica build/tmp/bench-stream
echo "== done $(date +%H:%M:%S)"
