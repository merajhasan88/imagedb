#!/bin/sh
# throwaway (2026-10-27): whole.sh before (main) and after (P), imagedb and postgres, side by side
D=/home/developer/imagedb/.work/p-measure-20261027
for key in "single_row_commit commits_per_s" "single_row_commit p50" "single_row_commit p95" "single_row_commit p99" \
           "batch_insert_100 rows_per_s" "batch_insert_10000 rows_per_s" "churn_update_1000 rows_per_s" \
           "delete_reinsert_1000 rows_per_s" "reopen_load_state seconds" "w6_load_1000 rows_per_s" "w6_update_1000 rows_per_s" \
           "w7_load_1000 rows_per_s" "w8_unique_insert_100 rows_per_s" "storage size"; do
  for e in imagedb postgres; do
    b=$(awk -v e="$e" -v k="$key" 'BEGIN {split(k, a, " ")} $1 == e && $2 == a[1] && $3 == a[2] {print $4; exit}' "$D/whole-before.txt")
    a=$(awk -v e="$e" -v k="$key" 'BEGIN {split(k, a, " ")} $1 == e && $2 == a[1] && $3 == a[2] {print $4; exit}' "$D/whole-after.txt" 2>/dev/null)
    printf '%-9s %-34s before %-10s after %s\n' "$e" "$key" "${b:--}" "${a:--}"
  done
done
grep -h "^devstall\|pauses or slow flushes" "$D/whole-before.txt" "$D/whole-after.txt" 2>/dev/null
