#!/bin/sh
# throwaway (2026-10-26, open item A): bench/devstall against the ground truth of the in-situ loop: every
# fdatasync the loop's strace finds slow should have a devstall line inside its time, and few devstall
# lines should fall outside one.   sh .work/window.sh sh .work/devstall-check.sh RUNS
set -eu
cd /home/developer/imagedb
O=.work/devstall-check-$(date +%Y%m%d-%H%M)
mkdir -p "$O"
build/devstall sda > "$O/devstall.txt" 2>&1 &
DS=$!
sh .work/stall-situ.sh "${1:-40}" > "$O/situ-console.txt" 2>&1 || true
kill $DS
S=$(awk '/^output: / {print $2}' "$O/situ-console.txt")
cp -p "$S/runs.txt" "$O/runs.txt"
for f in "$S"/*.strace; do awk -v f="$(basename "$f")" '$3 ~ /^f(data)?sync/ { d = $NF; gsub(/[<>]/, "", d); if (d + 0 > 0.2) print f, $2, d }' "$f"; done | sort -k2 > "$O/slow-syncs.txt"
echo "slow syncs (strace):"; cat "$O/slow-syncs.txt"
echo "devstall:"; cat "$O/devstall.txt"
echo "output: $O"
