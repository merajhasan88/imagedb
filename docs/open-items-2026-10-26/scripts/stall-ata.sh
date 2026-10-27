#!/bin/sh
# throwaway (2026-10-26, open item A): the in-situ loop again, traced at the ATA layer system-wide (v2: the block
# layer cannot time a cache flush, whose completion it does not trace): every
# disk request's issue and completion (block:block_rq_issue/complete, so each request's latency and kind:
# write, flush) and writeback throttling's decisions (wbt:wbt_step, wbt_stat, wbt_timer). The first in-situ
# loop (19:28) caught two 2.109 s fdatasyncs: ~0.9 s in wbt_wait, ~0.3 s waiting on writeback, ~0.8 s on the
# journal commit. This shows whether the disk stopped completing requests, or throttling stretched a short wait.
#   sh .work/window.sh sh .work/stall-trace.sh [RUNS]
set -eu
cd /home/developer/imagedb
O=.work/stall-ata-$(date +%Y%m%d-%H%M)
mkdir -p "$O"
perf record -a -q -o "$O/perf.data" -e libata:ata_qc_issue -e libata:ata_qc_complete_done -e block:block_rq_issue -e wbt:wbt_step \
    -e wbt:wbt_stat -e wbt:wbt_timer -e wbt:wbt_lat 2> "$O/perf-record.log" &
PP=$!
sleep 1
sh .work/stall-situ.sh "${1:-40}" > "$O/situ-console.txt" 2>&1 || true
kill -INT $PP
wait $PP 2> /dev/null || true
cp -p "$(awk '/^output: / {print $2}' "$O/situ-console.txt")/runs.txt" "$O/runs.txt" 2> /dev/null || true
echo "trace: $O ($(ls -la "$O/perf.data" | awk '{print $5}') bytes); situ: $(awk '/^output: / {print $2}' "$O/situ-console.txt")"
