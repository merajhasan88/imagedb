#!/bin/sh
# throwaway (2026-10-26, open item A): the mechanism test for the head-to-heads' stalls. Each scenario
# starts clean (sync, rm, sync, 3 s). The backlog is incompressible (a random file made once, synced) and
# left unsynced, as an engine leaves its data for the next one; the probe then writes durably beside it.
#   E0 no backlog (append, overwrite); E1 1 GB backlog then the append probe; E2 the same, overwrite;
#   E3 the 1 GB backlog synced first, then the append probe (the harness fix); E4 320 MB, append
#   sh .work/ramwatch.sh LOG sh .work/stall-mech.sh
set -eu
cd /home/developer/imagedb
P=build/tmp/stall_probe
W=build/tmp/stall-mech
O=.work/stall-mech-$(date +%Y%m%d-%H%M)
mkdir -p "$W" "$O"
cc -O2 -Wall -Wextra -Werror -o "$P" .work/stall_probe.c
head -c $((64 << 20)) /dev/urandom > build/tmp/stall-rand.bin
sync
mark() { echo "$(date +%H:%M:%S.%N | cut -c1-12) $*" >> "$O/scenarios.txt"; }
clean() { sync; rm -f "$W"/*; sync; sleep 3; }
backlog() { # $1 x 64 MiB, no sync
    i=0
    while [ $i -lt "$1" ]; do cat build/tmp/stall-rand.bin; i=$((i + 1)); done > "$W/backlog"
}
run() { # name seconds mode
    mark "$1 probe start ($3, $2 s)"
    "$P" "$W" "$2" "$3" > "$O/$1.txt" 2> "$O/$1.slow"
    mark "$1 probe end"
}
clean; run E0-append 15 append
clean; run E0-overwrite 15 overwrite
clean; mark "E1 backlog 1024 MiB"; backlog 16; run E1-append 50 append
clean; mark "E2 backlog 1024 MiB"; backlog 16; run E2-overwrite 50 overwrite
clean; mark "E3 backlog 1024 MiB, then sync"; backlog 16; sync; mark "E3 synced"; run E3-append-synced 50 append
clean; mark "E4 backlog 320 MiB"; backlog 5; run E4-append-320 50 append
clean
rm -f build/tmp/stall-rand.bin
for f in "$O"/*.slow; do printf '%s: %s\n' "$(basename "$f" .slow)" "$(grep '^summary' "$f")"; done
echo "output: $O"
