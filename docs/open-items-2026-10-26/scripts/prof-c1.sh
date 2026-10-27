#!/bin/sh
# throwaway (2026-10-26, open item C): flat CPU profiles of tonight's SQL workload on main's build (alg 2):
# 200,000 rows by 10 INSERT statements, then one UPDATE of all of them, --nosync. Each statement is its own
# process, so the UPDATE's profile includes the open (replaying the INSERTs' commits) as well as the update.
#   sh .work/window.sh sh .work/prof-c1.sh
set -eu
cd /home/developer/imagedb
O=.work/prof-c1-$(date +%Y%m%d-%H%M)
mkdir -p "$O" build/tmp
awk 'BEGIN { for (s = 0; s < 10; s++) { printf "INSERT INTO t VALUES "; for (i = 0; i < 20000; i++) { id = s * 20000 + i
     printf "%s(%d, %d, %d.%02d, %s)", (i ? ", " : ""), id, id % 1000, id % 100000, id % 100, "'"'"'card payment'"'"'" } print ";" } }' \
    > build/tmp/prof-ins.sql
echo "UPDATE t SET memo = 'updated';" > build/tmp/prof-upd.sql
d=build/tmp/prof-db
rm -rf "$d"
build/imagedb init "$d" > /dev/null
build/imagedb sql "$d" --nosync -c "CREATE TABLE t (id INT64 PRIMARY KEY, u INT64 SUBJECT, amount DECIMAL(12,2), memo TEXT);" > /dev/null
for k in ins upd; do
    perf record -q -F 4999 -o "$O/$k.data" -- build/imagedb sql "$d" --nosync -f build/tmp/prof-$k.sql > /dev/null 2> "$O/$k-record.log"
    perf report -i "$O/$k.data" --no-children --sort dso,symbol --stdio --percent-limit 0.5 2> /dev/null | grep -v '^#' | grep -v '^$' > "$O/$k-report.txt"
    perf report -i "$O/$k.data" --no-children --sort comm --stdio 2> /dev/null | grep -v '^#' | grep -v '^$' > "$O/$k-threads.txt"
done
rm -rf "$d" build/tmp/prof-ins.sql build/tmp/prof-upd.sql
echo "output: $O"
