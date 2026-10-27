#!/bin/sh
# throwaway (2026-10-27): .work/p-measure3.sh's raw lines as one table: each case, before / p1 / p2, both runs
#   sh .work/p-table3.sh OUT
OUT=$1
for c in nosync nosync1 sync10k sync1k sync; do
  for m in p50 p90 p99 p99.9 max worst_at mean over_5ms over_10ms after_rotation rows_per_s close log_bytes reopen; do
    line=""
    for side in before p1 p2; do
      for r in 1 2; do
        f="$OUT/$c-$r-$side.txt"
        [ -f "$f" ] || continue
        v=$(awk -v m="$m" '$1 == "commit_lat" && $3 == m {print $4; exit}' "$f")
        line="$line $side.$r=${v:--}"
      done
    done
    case "$line" in *=[0-9]*) printf '%-7s %-15s%s\n' "$c" "$m" "$line" ;; esac
  done
done
for f in "$OUT"/*.txt; do awk 'END {if ($1 == "rc" && $2 != 0) print FILENAME ": " $0}' "$f"; done
