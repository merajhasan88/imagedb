#!/bin/sh
# throwaway: the redefinition through SQL, as bench-step1-sql.sh measured step 1: 200,000 rows by 10 INSERT
# statements, then one UPDATE of all of them, --nosync (CPU, not durability); main before the merge
# (build/tmp/pre-e3b) under alg 2, main after it under alg 1 and under alg 2; twice, rotated. Each database is
# read back by the binary that made it.
#   sh .work/window.sh sh .work/bench-redef-sql.sh OUTDIR
set -eu
cd /home/developer/imagedb
O=${1:?usage: bench-redef-sql.sh OUTDIR}
mkdir -p "$O" build/tmp
awk 'BEGIN { for (s = 0; s < 10; s++) { printf "INSERT INTO t VALUES "; for (i = 0; i < 20000; i++) { id = s * 20000 + i
     printf "%s(%d, %d, %d.%02d, %s)", (i ? ", " : ""), id, id % 1000, id % 100000, id % 100, "'"'"'card payment'"'"'" } print ";" } }' \
    > build/tmp/redef-ins.sql
echo "UPDATE t SET memo = 'updated';" > build/tmp/redef-upd.sql
ms() { echo $(( ($(date +%s%N) - $1) / 1000000 )); }
i=0
for k in old2 new1 new2 old2 new1 new2; do
    i=$((i + 1))
    case $k in
    old2) b=build/tmp/pre-e3b/build/imagedb; a=2 ;;
    new1) b=build/imagedb; a=1 ;;
    new2) b=build/imagedb; a=2 ;;
    esac
    d=build/tmp/redef-db
    rm -rf "$d"
    IMDB_DIGEST_ALG=$a "$b" init "$d" > /dev/null
    "$b" sql "$d" --nosync -c "CREATE TABLE t (id INT64 PRIMARY KEY, u INT64 SUBJECT, amount DECIMAL(12,2), memo TEXT);" > /dev/null
    t0=$(date +%s%N)
    "$b" sql "$d" --nosync -f build/tmp/redef-ins.sql > /dev/null
    ins=$(ms "$t0")
    t0=$(date +%s%N)
    "$b" sql "$d" --nosync -f build/tmp/redef-upd.sql > /dev/null
    upd=$(ms "$t0")
    n=$("$b" sql "$d" --read-only --csv -c "SELECT COUNT(*) FROM t WHERE memo = 'updated';" | tail -n 1)
    al=$("$b" info "$d" | awk '/^ *algorithm/ {print $3}')
    echo "run $i $k alg $al: insert 200000 rows ${ins} ms, update 200000 rows ${upd} ms; updated rows $n;" \
         "clock $(awk '/^cpu MHz/ {s += $4; n++} END {if (n) printf "%.0f", s / n}' /proc/cpuinfo) MHz" | tee -a "$O/sql-runs.txt"
done
rm -rf build/tmp/redef-db build/tmp/redef-ins.sql build/tmp/redef-upd.sql
echo "== done $(date +%H:%M:%S)"
