#!/bin/sh
# throwaway (2026-10-27): bench/whole.sh with imagedb and the private PostgreSQL, from main (before) and
# from the preallocation copy (after), one after the other, each its own window (whole.sh sets it), output kept.
set -u
OUT=/home/developer/imagedb/.work/p-measure-20261027
cd /home/developer/imagedb && WHOLE_ONLY="probe imagedb postgres" sh bench/whole.sh build/whole > "$OUT/whole-before.txt" 2>&1
echo "before rc $?" >> "$OUT/whole-status.txt"
cd /home/developer/imagedb/.work/prealloc && WHOLE_ONLY="probe imagedb postgres" sh bench/whole.sh build/whole > "$OUT/whole-after.txt" 2>&1
echo "after rc $?" >> "$OUT/whole-status.txt"
echo done >> "$OUT/whole-status.txt"
