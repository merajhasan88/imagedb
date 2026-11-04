#!/bin/bash
# A really full file system (P0 resource limits, R3, 2026-11-04): make faults injects ENOSPC at every write of every
# scenario; this runs imagedb on a tmpfs that actually fills, in a private mount namespace (the mounts are this
# script's alone and go with it). Each scenario fills a fresh tmpfs, then checks what must hold on any full disk: the
# failing command reports the error cleanly; every acknowledged commit is there when the database is reopened on the
# still-full file system; VERIFY and the independent auditor pass there; and once the file system is grown (a
# remount), the same database takes writes, a CHECKPOINT, VERIFY and the auditor again.
#   A synced load, a --nosync load (synced at close), and --durable-ack;
#   CHECKPOINT on a full disk;
#   a backup written to a full disk (no FILE; its own FILE.tmp gone) and a restore into one (no DEST; DEST.tmp gone);
#   a replica's apply that fills its disk, then catches up once grown (its log equal to the primary's, frame by frame);
#   a writer killed mid-load and the rest of its disk filled, reopened while full.
# Needs root (mount). Opt in with IMDB_CRASH_OK=1 (not part of make test):
#   IMDB_CRASH_OK=1 bash tests/crash/disk_full.sh build/imagedb
set -euo pipefail

BIN=$(readlink -f "${1:?usage: disk_full.sh build/imagedb}")
AUDIT=$(dirname "$BIN")/imagedb-audit
[ "${IMDB_CRASH_OK:-}" = 1 ] || { echo "disk_full.sh: set IMDB_CRASH_OK=1 (root, tmpfs mounts)"; exit 2; }
[ "$(id -u)" = 0 ] || { echo "disk_full.sh: needs root"; exit 2; }
[ -x "$AUDIT" ] || { echo "disk_full.sh: $AUDIT not built"; exit 2; }
if [ "${IMDB_DFULL_NS:-}" != 1 ]; then
    IMDB_DFULL_NS=1 exec unshare --mount --propagation private bash "$0" "$@"
fi
WORK=$(readlink -f "${IMDB_CRASH_TMP:-build/tmp}")/disk-full-$$
mkdir -p "$WORK"
cleanup() {
    set +e
    for m in "$WORK"/*/; do mountpoint -q "$m" && umount "$m"; done
    [ "${IMDB_CRASH_KEEP:-}" = 1 ] || rm -rf "$WORK"
}
trap cleanup EXIT
fail() { echo "DISK FULL: FAILED: $*" >&2; exit 1; } # stderr: a failure inside $(...) must still be seen

PAD=$(head -c 900 /dev/zero | tr '\0' 'x')
batch() { # the SQL of batch b: 50 rows of about 900 bytes (no command that can fail: callers run it under set -e)
    local b=$1 i id s="INSERT INTO t VALUES " sep=""
    for i in $(seq 1 50); do id=$((b * 50 + i)); s="$s$sep($id, '$PAD')"; sep=", "; done
    echo "$s"
}
fresh() { # a tmpfs of $2 MB at $WORK/$1
    mkdir -p "$WORK/$1"
    mount -t tmpfs -o "size=${2}m" tmpfs "$WORK/$1"
}
# fill DIR with batches through `imagedb sql OPTS` until one fails; prints the number acknowledged
fill() {
    local dir=$1; shift
    local b=0 out
    while out=$("$BIN" sql "$dir" "$@" -c "$(batch $b)" 2>&1); do
        b=$((b + 1))
        [ "$b" -lt 100000 ] || fail "$dir never filled"
    done
    case "$out" in # --durable-ack may report the commit as in the log but not acknowledged
    *"No space left on device"* | *"reached the log but is not acknowledged"*) ;;
    *) fail "the failing batch said: $out" ;;
    esac
    echo "$b"
}
check() { # DIR ROWS [OPEN OPTIONS]: reopened, the acknowledged rows there (stdout alone, as CSV), VERIFY, the auditor
    local dir=$1 rows=$2 got
    shift 2
    local out # never a silent exit: a failing reopen under set -e and pipefail would end the script unexplained
    out=$("$BIN" sql "$dir" --csv "$@" -c "SELECT COUNT(*) FROM t" 2>&1) || fail "$dir: the reopen fails: $out"
    got=$(printf "%s\n" "$out" | awk 'NR == 2 { print $1 }')
    [ -n "$got" ] || fail "$dir: no count after the reopen"
    [ "$got" -ge "$rows" ] || fail "$dir: $got rows after the reopen, $rows acknowledged"
    "$BIN" verify "$dir" > "$WORK/verify.out" 2>&1 || fail "$dir: VERIFY: $(tail -1 "$WORK/verify.out")"
    "$AUDIT" verify "$dir" > "$WORK/audit.out" 2>&1 || fail "$dir: the auditor: $(tail -1 "$WORK/audit.out")"
}
grow() { mount -o "remount,size=${2}m" "$WORK/$1"; }
after_growth() { # DIR: a write, a CHECKPOINT, VERIFY and the auditor once there is room again
    local dir=$1
    "$BIN" sql "$dir" -c "INSERT INTO t VALUES (9999999, 'after'); CHECKPOINT" > "$WORK/grow.out" 2>&1 ||
        fail "$dir: after growing: $(tail -1 "$WORK/grow.out")"
    check "$dir" 1
}

for mode in sync nosync durable; do
    fresh "$mode" 12
    d="$WORK/$mode/db"
    "$BIN" init "$d" > /dev/null
    "$BIN" sql "$d" -c "CREATE TABLE t (id INT64 PRIMARY KEY, s TEXT)" > /dev/null
    case $mode in sync) opt=() ;; nosync) opt=(--nosync) ;; durable) opt=(--durable-ack) ;; esac
    n=$(fill "$d" "${opt[@]}") || exit 1
    check "$d" $((n * 50))
    "$BIN" sql "$d" -c "CHECKPOINT" > "$WORK/cp.out" 2>&1 && fail "$mode: a CHECKPOINT on a full disk succeeded"
    check "$d" $((n * 50))
    grow "$mode" 96
    after_growth "$d"
    echo "disk full: $mode load: $n commits acknowledged and kept; a CHECKPOINT refused while full; recovered once grown"
done

# a backup onto a full disk, a restore into one
fresh src 96
fresh dst 4
d="$WORK/src/db"
"$BIN" init "$d" > /dev/null
"$BIN" sql "$d" -c "CREATE TABLE t (id INT64 PRIMARY KEY, s TEXT)" > /dev/null
for b in $(seq 0 99); do "$BIN" sql "$d" --nosync -c "$(batch "$b")" > /dev/null; done
"$BIN" sql "$d" -c "CHECKPOINT" > /dev/null
"$BIN" backup-key "$WORK/src/key" > /dev/null
"$BIN" backup "$d" --key "$WORK/src/key" --out "$WORK/dst/b1" > "$WORK/bk.out" 2>&1 && fail "a backup onto a full disk succeeded"
[ ! -e "$WORK/dst/b1" ] || fail "a failed backup left its file"
[ ! -e "$WORK/dst/b1.tmp" ] || fail "a failed backup left its .tmp"
"$BIN" backup "$d" --key "$WORK/src/key" --out "$WORK/src/b1" > /dev/null
"$BIN" restore "$WORK/dst/r1" --key "$WORK/src/key" "$WORK/src/b1" > "$WORK/rs.out" 2>&1 && fail "a restore into a full disk succeeded"
[ ! -e "$WORK/dst/r1" ] || fail "a failed restore left its directory"
[ ! -e "$WORK/dst/r1.tmp" ] || fail "a failed restore left its .tmp"
grow dst 96
"$BIN" restore "$WORK/dst/r1" --key "$WORK/src/key" "$WORK/src/b1" > /dev/null || fail "the restore once grown"
check "$WORK/dst/r1" 5000 --read-only # a restored copy is read-only until promoted
echo "disk full: a backup and a restore refused on a full disk, nothing left behind; the restore once grown checked"

# a replica that fills its disk, then catches up
fresh rep 6
r="$WORK/rep/db"
"$BIN" init-replica "$r" "$d" > /dev/null
"$BIN" ship "$d" | "$BIN" apply "$r" > "$WORK/ap.out" 2>&1 && fail "a replica's apply onto a full disk succeeded"
"$BIN" verify "$r" > "$WORK/verify.out" 2>&1 || fail "the replica, full: VERIFY: $(tail -1 "$WORK/verify.out")"
grow rep 96
after=$("$BIN" info "$r" 2>/dev/null | awk '/^commit/ { print $2 }')
"$BIN" ship "$d" --after "${after:-0}" | "$BIN" apply "$r" > /dev/null || fail "the replica's catch-up once grown"
"$AUDIT" frames "$d" > "$WORK/fp" && "$AUDIT" frames "$r" > "$WORK/fr" || fail "frames"
cmp -s "$WORK/fp" "$WORK/fr" || fail "the replica's log differs from the primary's after the catch-up"
echo "disk full: a replica's apply stopped by a full disk, its state checked, caught up once grown, frame for frame"

# a writer killed while its disk fills, reopened while still full
fresh kill 12
k="$WORK/kill/db"
"$BIN" init "$k" > /dev/null
"$BIN" sql "$k" -c "CREATE TABLE t (id INT64 PRIMARY KEY, s TEXT)" > /dev/null
(for b in $(seq 0 999); do batch "$b"; echo ";"; done) > "$WORK/load.sql"
"$BIN" sql "$k" -f "$WORK/load.sql" > "$WORK/load.out" 2>&1 &
pid=$!
# killed mid-load (at 80% full, while it surely still writes), then the rest of the disk filled by another file:
# the reopen below meets a full disk and whatever the kill left at the log's end
while kill -0 "$pid" 2>/dev/null && [ "$(df --output=pcent "$WORK/kill" | tail -1 | tr -dc 0-9)" -lt 80 ]; do sleep 0.05; done
killed=no
kill -0 "$pid" 2>/dev/null && kill -9 "$pid" 2>/dev/null && killed=yes
wait "$pid" 2>/dev/null || true
[ "$killed" = yes ] || fail "the writer finished before it was killed: $(tail -1 "$WORK/load.out")"
dd if=/dev/zero of="$WORK/kill/filler" bs=64k > /dev/null 2>&1 || true # until ENOSPC
[ "$(df --output=avail "$WORK/kill" | tail -1 | tr -dc 0-9)" -lt 64 ] || fail "the filler left room"
check "$k" 0
grow kill 96
after_growth "$k"
echo "disk full: a writer killed mid-load, the disk then filled, reopened while full (VERIFY, the auditor), recovered once grown"
echo "DISK FULL: ALL CHECKS PASSED"
