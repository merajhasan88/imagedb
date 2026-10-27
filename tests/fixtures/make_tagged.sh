#!/bin/sh
# Makes the tagged-segment fixture (tagged-20261027.tar.gz beside this script): make_alg2.sh's steps
# run by an imagedb that writes tagged, preallocated log segments (design.md §3, "Tagged, preallocated
# segments", 2026-10-27), so every later engine and auditor is tested on that format: the rotations
# (a manifest publish ends a segment: truncated, the next one filled), ERASE SUBJECT's redaction
# (rewritten as one group), the replica's apply. Every log segment of both directories must be tagged.
# Made by the binary of the preallocation copy (.work/prealloc, 2026-10-27).
#   sh tests/fixtures/make_tagged.sh BIN AUDIT OUTDIR   (OUTDIR must not exist)
#   tar -czf tests/fixtures/tagged-20261027.tar.gz -C OUTDIR primary replica
set -eu
sh "$(dirname "$0")/make_alg2.sh" "$@" > /dev/null
for f in "$3"/primary/log/*.ilg "$3"/replica/log/*.ilg; do
    [ "$(head -c 4 "$f")" = ILT1 ] || { echo "make_tagged: $f is not a tagged segment" >&2; exit 1; }
done
"$1" info "$3/primary"
