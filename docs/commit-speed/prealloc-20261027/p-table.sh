#!/bin/sh
# throwaway (2026-10-27): the measurement's raw lines as one table: each case, before and after, both runs
#   sh .work/p-table.sh OUT
OUT=$1
for c in sync strict sync1k sync10k nosync; do
  for m in p50 p90 p99 p99.9 max worst_at mean over_5ms over_10ms after_rotation checkpoint rows_per_s close log_bytes log_segments reopen; do
    line=""
    for side in before after; do
      for r in 1 2; do
        f="$OUT/$c-$r-$side.txt"
        [ -f "$f" ] || continue
        v=$(awk -v m="$m" '$1 == "commit_lat" && $3 == m {print $4; exit}' "$f")
        line="$line $side$r=${v:--}"
      done
    done
    case "$line" in *=[0-9]*) printf '%-7s %-15s%s\n' "$c" "$m" "$line" ;; esac
  done
done
awk '$1 == "group_probe" {printf "%-7s %s N=%-5s %-6s %s %s\n", "probe", $2, $3, $4, $5, $6}' "$OUT/group-probe.txt" 2>/dev/null
