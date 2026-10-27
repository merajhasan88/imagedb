#!/bin/sh
# throwaway (2026-10-26, open items C and D), with W7's data as in prof-c2.sh:
# C: W7d (the whole join by region) 20 times before and after a CHECKPOINT, timed net of the open and profiled
#    (perf -D past the open), for docs/bench-2026-10-26.md finding 2 (45 ms in memory against 35 in segments);
# D: then 1,000 W7c queries 20 times back to back, each run's time beside its mean clock and the package
#    temperature (sampled every 200 ms), for the reports' run-to-run spread put down to heat.
#   sh .work/window.sh sh .work/prof-c3d.sh
set -eu
cd /home/developer/imagedb
O=.work/prof-c3d-$(date +%Y%m%d-%H%M)
mkdir -p "$O" build/tmp
L=build/tmp/w7-load.sql Q=build/tmp/w7d-q.sql Q2=build/tmp/w7c-q.sql
awk 'BEGIN { for (b = 0; b < 20; b++) { printf "INSERT INTO c VALUES "; for (i = 1; i <= 1000; i++) { id = b * 1000 + i; printf "%s(%d, %d, %s)", (i > 1 ? ", " : ""), id, id % 100, "'"'"'c" id "'"'"'" } print ";" }
             for (b = 0; b < 200; b++) { printf "INSERT INTO o VALUES "; for (i = 1; i <= 1000; i++) { id = b * 1000 + i; printf "%s(%d, %d, %d)", (i > 1 ? ", " : ""), id, (id * 7919) % 16000 + 1, id % 1000 } print ";" } }' > "$L"
awk 'BEGIN { for (k = 0; k < 20; k++) print "SELECT c.region, SUM(o.amount) FROM o JOIN c ON o.cust = c.id GROUP BY c.region;" }' > "$Q"
awk 'BEGIN { for (k = 0; k < 10; k++) for (r = 0; r < 100; r++) printf "SELECT COUNT(*) FROM c LEFT JOIN o ON c.id = o.cust WHERE c.region = %d AND o.id IS NULL;\n", r }' > "$Q2"
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
    build/imagedb sql "$d" --nosync -c "SELECT c.region, SUM(o.amount) FROM o JOIN c ON o.cust = c.id GROUP BY c.region;" | tail -n 1 > "$O/w7d-$state-path.txt"
    for i in 1 2 3; do
        t0=$(date +%s%N); build/imagedb sql "$d" --nosync -c "SELECT COUNT(*) FROM c WHERE id = -1;" > /dev/null; open=$(ms "$t0")
        t0=$(date +%s%N); build/imagedb sql "$d" --nosync -f "$Q" > /dev/null; all=$(ms "$t0")
        echo "W7d $state checkpoint, run $i: open $open ms; open + 20 W7d $all ms; so $(( (all - open) / 20 )) ms a query" | tee -a "$O/w7d-timing.txt"
    done
    perf record -q -D "$((open + 150))" -F 4999 -o "$O/w7d-$state.data" -- build/imagedb sql "$d" --nosync -f "$Q" > /dev/null 2> "$O/w7d-$state-record.log"
    perf report -i "$O/w7d-$state.data" --no-children --sort symbol --stdio --percent-limit 1 2> /dev/null | grep -v '^#' | grep -v '^$' > "$O/w7d-$state-report.txt"
done
# D: heat. A sampler logs the mean clock and the package temperature every 200 ms; each run is marked in it.
PKG=$(for z in /sys/class/thermal/thermal_zone*; do [ "$(cat "$z/type")" = x86_pkg_temp ] && echo "$z/temp"; done | head -n 1)
( while :; do echo "$(date +%s%N) $(awk '{s += $1; n++} END {printf "%.0f", s / n / 1000}' /sys/devices/system/cpu/cpu*/cpufreq/scaling_cur_freq) $(cat "$PKG")"; sleep 0.2; done ) > "$O/heat-samples.txt" &
HP=$!
i=0
while [ $i -lt 20 ]; do
    i=$((i + 1))
    a=$(date +%s%N)
    build/imagedb sql "$d" --nosync -f "$Q2" > /dev/null
    b=$(date +%s%N)
    echo "$i $a $b" >> "$O/heat-runs.txt"
done
kill $HP
awk 'NR == FNR { t[NR] = $1; mhz[NR] = $2; tc[NR] = $3; n = NR; next }
     { s = 0; m = 0; lo = 1e9; hi = 0; for (k = 1; k <= n; k++) if (t[k] >= $2 && t[k] <= $3) { s += mhz[k]; m++; if (tc[k] < lo) lo = tc[k]; if (tc[k] > hi) hi = tc[k] }
       printf "run %2d: %4d ms, mean clock %4.0f MHz, package %2d-%2d C\n", $1, ($3 - $2) / 1e6, m ? s / m : 0, lo / 1000, hi / 1000 }' "$O/heat-samples.txt" "$O/heat-runs.txt" | tee "$O/heat.txt"
rm -rf "$d" "$L" "$Q" "$Q2"
echo "output: $O"
