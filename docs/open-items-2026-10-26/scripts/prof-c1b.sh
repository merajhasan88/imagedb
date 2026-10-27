#!/bin/sh
# throwaway (2026-10-26, open item C): the SQL UPDATE's time split into the open (which replays the INSERTs'
# 200,000 rows) and the update itself, three times each; then call-graph profiles (dwarf) of the INSERT and
# the UPDATE, so the scalar SHA-256 and the ChaCha20 time are charged to their callers.
#   sh .work/window.sh sh .work/prof-c1b.sh
set -eu
cd /home/developer/imagedb
O=.work/prof-c1b-$(date +%Y%m%d-%H%M)
mkdir -p "$O" build/tmp
awk 'BEGIN { for (s = 0; s < 10; s++) { printf "INSERT INTO t VALUES "; for (i = 0; i < 20000; i++) { id = s * 20000 + i
     printf "%s(%d, %d, %d.%02d, %s)", (i ? ", " : ""), id, id % 1000, id % 100000, id % 100, "'"'"'card payment'"'"'" } print ";" } }' \
    > build/tmp/prof-ins.sql
echo "UPDATE t SET memo = 'updated';" > build/tmp/prof-upd.sql
ms() { echo $(( ($(date +%s%N) - $1) / 1000000 )); }
d=build/tmp/prof-db
for i in 1 2 3; do
    rm -rf "$d"
    build/imagedb init "$d" > /dev/null
    build/imagedb sql "$d" --nosync -c "CREATE TABLE t (id INT64 PRIMARY KEY, u INT64 SUBJECT, amount DECIMAL(12,2), memo TEXT);" > /dev/null
    t0=$(date +%s%N); build/imagedb sql "$d" --nosync -f build/tmp/prof-ins.sql > /dev/null; ins=$(ms "$t0")
    t0=$(date +%s%N); build/imagedb sql "$d" --nosync -c "SELECT COUNT(*) FROM t WHERE id = -1;" > /dev/null; open1=$(ms "$t0")
    t0=$(date +%s%N); build/imagedb sql "$d" --nosync -f build/tmp/prof-upd.sql > /dev/null; upd=$(ms "$t0")
    t0=$(date +%s%N); build/imagedb sql "$d" --nosync -c "SELECT COUNT(*) FROM t WHERE id = -1;" > /dev/null; open2=$(ms "$t0")
    echo "run $i: insert $ins ms; open + a point lookup after it $open1 ms; update $upd ms; open + a point lookup after the update $open2 ms" | tee -a "$O/split.txt"
done
rm -rf "$d"
build/imagedb init "$d" > /dev/null
build/imagedb sql "$d" --nosync -c "CREATE TABLE t (id INT64 PRIMARY KEY, u INT64 SUBJECT, amount DECIMAL(12,2), memo TEXT);" > /dev/null
for k in ins upd; do
    perf record -q -F 1999 --call-graph dwarf,16384 -o "$O/$k.data" -- build/imagedb sql "$d" --nosync -f build/tmp/prof-$k.sql > /dev/null 2> "$O/$k-record.log"
    for s in imdb_sha256_compress chacha20_x8.constprop.0; do
        perf report -i "$O/$k.data" --no-children --stdio --symbols "$s" -G --percent-limit 2 2> /dev/null | grep -v '^#' | grep -v '^$' | head -n 60 > "$O/$k-$s-callers.txt"
    done
done
rm -rf "$d" build/tmp/prof-ins.sql build/tmp/prof-upd.sql
echo "output: $O"
