#!/bin/sh
# throwaway (2026-10-26, open item C): CPU time (perf stat task-clock, every thread) of the open after the INSERTs
# and of the UPDATE statement's process, three times, so the update's own CPU per row compares with R8's 24 us.
set -eu
cd /home/developer/imagedb
O=.work/prof-c1c-$(date +%Y%m%d-%H%M)
mkdir -p "$O" build/tmp
awk 'BEGIN { for (s = 0; s < 10; s++) { printf "INSERT INTO t VALUES "; for (i = 0; i < 20000; i++) { id = s * 20000 + i
     printf "%s(%d, %d, %d.%02d, %s)", (i ? ", " : ""), id, id % 1000, id % 100000, id % 100, "'"'"'card payment'"'"'" } print ";" } }' \
    > build/tmp/prof-ins.sql
echo "UPDATE t SET memo = 'updated';" > build/tmp/prof-upd.sql
cpu() { perf stat -x, -e task-clock -o "$O/stat.txt" -- "$@" > /dev/null 2>&1; awk -F, '/task-clock/ {printf "%.0f", $1}' "$O/stat.txt"; }
d=build/tmp/prof-db
for i in 1 2 3; do
    rm -rf "$d"
    build/imagedb init "$d" > /dev/null
    build/imagedb sql "$d" --nosync -c "CREATE TABLE t (id INT64 PRIMARY KEY, u INT64 SUBJECT, amount DECIMAL(12,2), memo TEXT);" > /dev/null
    ins=$(cpu build/imagedb sql "$d" --nosync -f build/tmp/prof-ins.sql)
    open=$(cpu build/imagedb sql "$d" --nosync -c "SELECT COUNT(*) FROM t WHERE id = -1;")
    upd=$(cpu build/imagedb sql "$d" --nosync -f build/tmp/prof-upd.sql)
    echo "run $i CPU ms: insert $ins; open after it $open; update statement process $upd; so the update itself $((upd - open)) ms, $(( (upd - open) * 1000 / 200 )) ns per row" | tee -a "$O/cpu.txt"
done
rm -rf "$d" build/tmp/prof-ins.sql build/tmp/prof-upd.sql
echo "output: $O"
