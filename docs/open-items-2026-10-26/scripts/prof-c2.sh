#!/bin/sh
# throwaway (2026-10-26, open item C): W7c (the anti-join, docs/bench-2026-10-26.md finding 3) rebuilt through
# the CLI with W7's data (bench/whole.c w7_model: 20,000 customers, region id % 100; 200,000 orders, cust
# id * 7919 % 16000 + 1, amount id % 1000; indexes c_id, o_id, c_region, o_cust), then 1,000 W7c queries
# (regions 0-99, ten times), timed net of the open and profiled with perf from after the open (-D), before
# and after a CHECKPOINT. Every region has 40 customers without an order (ids 16,001-20,000).
#   sh .work/window.sh sh .work/prof-c2.sh
set -eu
cd /home/developer/imagedb
O=.work/prof-c2-$(date +%Y%m%d-%H%M)
mkdir -p "$O" build/tmp
L=build/tmp/w7-load.sql Q=build/tmp/w7-q.sql
awk 'BEGIN { for (b = 0; b < 20; b++) { printf "INSERT INTO c VALUES "; for (i = 1; i <= 1000; i++) { id = b * 1000 + i; printf "%s(%d, %d, %s)", (i > 1 ? ", " : ""), id, id % 100, "'"'"'c" id "'"'"'" } print ";" }
             for (b = 0; b < 200; b++) { printf "INSERT INTO o VALUES "; for (i = 1; i <= 1000; i++) { id = b * 1000 + i; printf "%s(%d, %d, %d)", (i > 1 ? ", " : ""), id, (id * 7919) % 16000 + 1, id % 1000 } print ";" } }' > "$L"
awk 'BEGIN { for (k = 0; k < 10; k++) for (r = 0; r < 100; r++) printf "SELECT COUNT(*) FROM c LEFT JOIN o ON c.id = o.cust WHERE c.region = %d AND o.id IS NULL;\n", r }' > "$Q"
d=build/tmp/w7-db
rm -rf "$d"
build/imagedb init "$d" > /dev/null
build/imagedb sql "$d" --nosync -c "CREATE TABLE c (id INT64 PRIMARY KEY, region INT64 NOT NULL, name TEXT NOT NULL);" \
    -c "CREATE TABLE o (id INT64 PRIMARY KEY, cust INT64 NOT NULL, amount INT64 NOT NULL);" -c "CREATE INDEX c_id ON c (id);" \
    -c "CREATE INDEX o_id ON o (id);" -c "CREATE INDEX c_region ON c (region);" -c "CREATE INDEX o_cust ON o (cust);" > /dev/null
build/imagedb sql "$d" --nosync -f "$L" > /dev/null
ms() { echo $(( ($(date +%s%N) - $1) / 1000000 )); }
for state in before after; do
    [ "$state" = after ] && build/imagedb sql "$d" -c "CHECKPOINT;" > /dev/null
    build/imagedb sql "$d" --nosync -c "SELECT COUNT(*) FROM c LEFT JOIN o ON c.id = o.cust WHERE c.region = 7 AND o.id IS NULL;" > "$O/$state-check.txt"
    for i in 1 2 3; do
        t0=$(date +%s%N); build/imagedb sql "$d" --nosync -c "SELECT COUNT(*) FROM c WHERE id = -1;" > /dev/null; open=$(ms "$t0")
        t0=$(date +%s%N); build/imagedb sql "$d" --nosync -f "$Q" > /dev/null; all=$(ms "$t0")
        echo "$state checkpoint, run $i: open $open ms; open + 1,000 W7c $all ms; so $(( (all - open) * 1000 / 1000 )) us a query" | tee -a "$O/timing.txt"
    done
    perf record -q -D "$((open + 150))" -F 4999 -o "$O/$state.data" -- build/imagedb sql "$d" --nosync -f "$Q" > /dev/null 2> "$O/$state-record.log"
    perf report -i "$O/$state.data" --no-children --sort symbol --stdio --percent-limit 1 2> /dev/null | grep -v '^#' | grep -v '^$' > "$O/$state-report.txt"
done
rm -rf "$d" "$L" "$Q"
echo "output: $O"
