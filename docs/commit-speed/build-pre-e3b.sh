#!/bin/sh
# throwaway: main before the alg 2 key redefinition merge (.work/pre-e3b-merge-20261026-1845.tgz: digest_alg 2 as first
# defined), built as main is, in build/tmp/pre-e3b, for bench-redef*.sh's "old2". The two protected tarballs are left
# out of the extraction (only main's own copies exist).
set -eu
cd /home/developer/imagedb
D=build/tmp/pre-e3b
rm -rf "$D"
mkdir -p "$D"
tar -xzf .work/pre-e3b-merge-20261026-1845.tgz -C "$D" --exclude=./azadi-2026-10-19-dhcp.tar.gz \
    --exclude=./docs/imagedb-feedback-2026-10-21.tar.gz
grep -q 'lthash_expand2(key, (uint8_t \*)out->v);' "$D/src/lthash.c" ||
    { echo "build-pre-e3b: the tree is not the first definition (its element expands a hashed key)" >&2; exit 1; }
cd "$D"
nice -n 10 make -j4 all build/bench
echo "built: $(ls build/imagedb build/bench | tr '\n' ' ')"
