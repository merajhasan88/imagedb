#!/bin/sh
# throwaway (2026-10-27): a torn tail on a 21 MB tagged segment (its last non-zero sector zeroed: the last
# frame runs into it), repaired by the writable open; timed against a clean open of the same copy.
set -u
OUT=$1
P=/home/developer/imagedb/.work/prealloc/build
D=/home/developer/imagedb/build/tmp/pm
rm -rf "$D/clean-a1" && cp -a "$D/nosync-a1" "$D/clean-a1"
SEG=$(ls "$D"/torn-a1/log/*.ilg | tail -1)
L=$(/home/developer/imagedb/.work/p-tools/last_sector "$SEG") || exit 1
dd if=/dev/zero of="$SEG" bs=512 seek="$L" count=1 conv=notrunc 2>/dev/null || exit 1
sync
for x in clean-a1 torn-a1; do
    t0=$(date +%s%N)
    "$P/imagedb" sql "$D/$x" -c "SELECT COUNT(*) FROM txns;" > "$OUT/open-$x.txt" 2>&1
    rc=$?
    t1=$(date +%s%N)
    echo "$x: rc $rc, $(( (t1 - t0) / 1000000 )) ms (sector $L zeroed in torn-a1)" >> "$OUT/torn-reopen.txt"
done
t0=$(date +%s%N)
"$P/imagedb" sql "$D/torn-a1" -c "SELECT COUNT(*) FROM txns;" > "$OUT/open-torn-a1-again.txt" 2>&1
t1=$(date +%s%N)
echo "torn-a1 again (repaired): rc $?, $(( (t1 - t0) / 1000000 )) ms" >> "$OUT/torn-reopen.txt"
"$P/imagedb" verify "$D/torn-a1" > "$OUT/verify-torn-a1.txt" 2>&1; echo "verify rc $?" >> "$OUT/torn-reopen.txt"
"$P/imagedb-audit" verify "$D/torn-a1" > "$OUT/audit-torn-a1.txt" 2>&1; echo "audit rc $?" >> "$OUT/torn-reopen.txt"
