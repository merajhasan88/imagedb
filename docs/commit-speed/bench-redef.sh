#!/bin/sh
# throwaway: the alg 2 key redefinition against the tree before it, in one measurement window: main before the
# merge (build/tmp/pre-e3b: digest_alg 2 as first defined, ChaCha20 keyed by SHA-256("IMDBLT2K" || commitment))
# under alg 2, main after it under alg 1 (unchanged: the control) and under alg 2 (keyed by the commitment);
# twice, rotated, so drift shows. Each database is read back by the binary that made it: the two alg 2
# definitions give different digests by design.
#   sh .work/window.sh sh .work/bench-redef.sh OUTDIR
set -eu
cd /home/developer/imagedb
O=${1:?usage: bench-redef.sh OUTDIR}
mkdir -p "$O" build/tmp
i=0
for k in old2 new1 new2 old2 new1 new2; do
    i=$((i + 1))
    case $k in
    old2) d=build/tmp/pre-e3b/build; a=2 ;;
    new1) d=build; a=1 ;;
    new2) d=build; a=2 ;;
    esac
    f="$O/run$i-$k.txt"
    echo "== run $i: $k ($d/bench, IMDB_DIGEST_ALG=$a), $(date +%H:%M:%S), load $(cut -d' ' -f1 /proc/loadavg)," \
         "mean clock $(awk '/^cpu MHz/ {s += $4; n++} END {if (n) printf "%.0f", s / n}' /proc/cpuinfo) MHz" | tee "$f"
    IMDB_TEST_TMP=build/tmp IMDB_BENCH_KEEP=1 IMDB_DIGEST_ALG=$a "$d/bench" >> "$f" 2>&1
    "$d/imagedb" info build/tmp/bench-primary 2>&1 | grep -E '^ *algorithm' >> "$f"
    grep -E '^== |^engine|^  (bulk insert|single-row txn|VERIFY|replica apply|reopen)|element|^ *algorithm' "$f"
done
rm -rf build/tmp/bench-primary build/tmp/bench-replica build/tmp/bench-stream
echo "== done $(date +%H:%M:%S)"
