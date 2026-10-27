#!/bin/sh
# throwaway (2026-10-27): an unacknowledged torn tail on a 21 MB tagged segment: the watermark rewound one
# commit (forge durable-rewind: the rewrite an OS crash lost), the last frame's last sector zeroed; the
# writable open must drop it (the repair) and keep 200 commits; timed against a clean open of a copy.
set -u
OUT=$1
P=/home/developer/imagedb/.work/prealloc/build
D=/home/developer/imagedb/build/tmp/pm
rm -rf "$D/clean2" "$D/torn2" && cp -a "$D/nosync-a1" "$D/clean2" && cp -a "$D/nosync-a1" "$D/torn2"
"$P/imdb-forge" durable-rewind "$D/torn2" || exit 1
SEG=$(ls "$D"/torn2/log/*.ilg | tail -1)
L=$(/home/developer/imagedb/.work/p-tools/last_sector "$SEG") || exit 1
dd if=/dev/zero of="$SEG" bs=512 seek="$L" count=1 conv=notrunc 2>/dev/null || exit 1
sync
for x in clean2 torn2 torn2; do
    t0=$(date +%s%N)
    "$P/imagedb" sql "$D/$x" -c "SELECT COUNT(*) FROM txns;" > "$OUT/open2-$x.txt" 2>&1
    rc=$?
    t1=$(date +%s%N)
    echo "$x: rc $rc, $(( (t1 - t0) / 1000000 )) ms (torn2: sector $L zeroed, watermark rewound)" >> "$OUT/torn-reopen2.txt"
done
"$P/imagedb" verify "$D/torn2" > "$OUT/verify-torn2.txt" 2>&1
echo "verify rc $?" >> "$OUT/torn-reopen2.txt"
"$P/imagedb-audit" verify "$D/torn2" > "$OUT/audit-torn2.txt" 2>&1
echo "audit rc $?" >> "$OUT/torn-reopen2.txt"
