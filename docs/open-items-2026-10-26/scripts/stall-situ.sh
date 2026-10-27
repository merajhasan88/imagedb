#!/bin/sh
# throwaway (2026-10-26, open item A, in situ): tonight's SQL window (200,000 rows by 10 INSERT statements,
# then one UPDATE of all of them, --nosync) 30 times on main's build (alg 2), each statement under strace
# (-f, --seccomp-bpf: the sync calls only, each timed), with Dirty and Writeback from /proc/meminfo before
# each statement, and every 20 ms the state of every imagedb thread (.work/dstate.c: D, uninterruptible,
# with its kernel stack). A stall here then shows which sync call waited, or where else it waited.
#   sh .work/ramwatch.sh LOG sh .work/stall-situ.sh [RUNS]
set -eu
cd /home/developer/imagedb
N=${1:-30}
O=.work/stall-situ-$(date +%Y%m%d-%H%M)
mkdir -p "$O" build/tmp
awk 'BEGIN { for (s = 0; s < 10; s++) { printf "INSERT INTO t VALUES "; for (i = 0; i < 20000; i++) { id = s * 20000 + i
     printf "%s(%d, %d, %d.%02d, %s)", (i ? ", " : ""), id, id % 1000, id % 100000, id % 100, "'"'"'card payment'"'"'" } print ";" } }' \
    > build/tmp/situ-ins.sql
echo "UPDATE t SET memo = 'updated';" > build/tmp/situ-upd.sql
ms() { echo $(( ($(date +%s%N) - $1) / 1000000 )); }
mem() { awk '/^Dirty:/ {d = $2} /^Writeback:/ {w = $2} END {printf "dirty %d MB, writeback %d MB", d / 1024, w / 1024}' /proc/meminfo; }
slowest() { # the slowest sync call in a strace log: "<seconds> <call>"
    awk '{ if (match($0, /<[0-9.]+>$/)) { t = substr($0, RSTART + 1, RLENGTH - 2) + 0; c = $0; sub(/^[0-9]+ +/, "", c); sub(/\(.*/, "", c); sub(/^[0-9:.]+ +/, "", c)
           n++; if (t > m) { m = t; mc = c } } } END { printf "%d sync calls, slowest %.3f s (%s)", n, m, mc }' "$1"
}
S="strace -f --seccomp-bpf -T -tt -e trace=fsync,fdatasync,sync_file_range,syncfs"
cc -O2 -Wall -Wextra -Werror -o build/tmp/dstate .work/dstate.c
build/tmp/dstate imagedb 20 > "$O/dstate.txt" &
DP=$!
trap 'kill $DP 2> /dev/null || true' EXIT
i=0
while [ $i -lt "$N" ]; do
    i=$((i + 1))
    d=build/tmp/situ-db
    rm -rf "$d"
    build/imagedb init "$d" > /dev/null
    build/imagedb sql "$d" --nosync -c "CREATE TABLE t (id INT64 PRIMARY KEY, u INT64 SUBJECT, amount DECIMAL(12,2), memo TEXT);" > /dev/null
    m0=$(mem)
    t0=$(date +%s%N)
    $S -o "$O/ins-$i.strace" build/imagedb sql "$d" --nosync -f build/tmp/situ-ins.sql > /dev/null
    ins=$(ms "$t0")
    m1=$(mem)
    t0=$(date +%s%N)
    $S -o "$O/upd-$i.strace" build/imagedb sql "$d" --nosync -f build/tmp/situ-upd.sql > /dev/null
    upd=$(ms "$t0")
    echo "run $i $(date +%H:%M:%S): insert ${ins} ms ($m0 before; $(slowest "$O/ins-$i.strace")); update ${upd} ms ($m1 before; $(slowest "$O/upd-$i.strace"))" | tee -a "$O/runs.txt"
done
rm -rf build/tmp/situ-db build/tmp/situ-ins.sql build/tmp/situ-upd.sql
echo "output: $O"
