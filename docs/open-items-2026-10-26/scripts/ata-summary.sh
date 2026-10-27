#!/bin/sh
# throwaway (2026-10-26, open item A): the ATA latency distribution per command, and the commands slower than
# 100 ms, from a perf.data of libata:ata_qc_issue/complete_done.   sh .work/ata-summary.sh DIR
set -eu
D=$1
perf script -i "$D/perf.data" -F comm,pid,time,event,trace 2> /dev/null > "$D/perf.txt"
awk -f /home/developer/imagedb/.work/ata-latency.awk "$D/perf.txt" > "$D/ata-lat.txt"
sort -k2,2 -k3,3n "$D/ata-lat.txt" | awk '{ c = $2; if (c != pc && pc != "") out(); if (c != pc) { n = 0; pc = c } a[++n] = $3 }
    function out() { printf "%-26s n %6d  median %8.2f ms  p99 %8.2f ms  max %8.2f ms\n", pc, n, a[int(n / 2) + 1] * 1e3, a[(int(n * 0.99) + 1 > n ? n : int(n * 0.99) + 1)] * 1e3, a[n] * 1e3 }
    END { if (pc != "") out() }'
echo "--- commands slower than 100 ms (issue time on perf's clock):"
awk '$3 > 0.1 { printf "%.4f %.3f s %s\n", $4, $3, $2 }' "$D/ata-lat.txt" | sort -n | head -n 40
