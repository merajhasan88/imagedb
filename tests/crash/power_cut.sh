#!/bin/bash
# Real power-cut states (deferred.md R7d), on ext4 over a loop device.
#
# The workload runs through a dm-log-writes target, which logs every write,
# flush and FUA of the file system in order. After each imagedb command returns,
# the acknowledged commit (seq and hash, from `imagedb info`) goes into an
# acknowledgement record and a mark into the log. The log is then replayed onto
# a fresh image up to every flush (a state the disk was guaranteed to hold) and
# up to a sample of other entries (states it may have held); each image is
# mounted (ext4 recovers its journal), opened writable by imagedb, and must hold
# every commit acknowledged before that point, pass VERIFY and pass the auditor.
# First, as a check of the replayer itself, the whole log replayed onto a fresh
# image must equal the original device byte for byte.
#
# Needs root, the dm-log-writes module, losetup, dmsetup, mkfs.ext4. It creates
# loop and device-mapper devices and removes them at exit. Opt in with
# IMDB_CRASH_OK=1 (it is not part of make test):
#   IMDB_CRASH_OK=1 bash tests/crash/power_cut.sh build/imagedb
set -euo pipefail

BIN=$(readlink -f "${1:?usage: power_cut.sh build/imagedb}")
AUDIT=$(dirname "$BIN")/imagedb-audit
HERE=$(cd "$(dirname "$0")" && pwd)
[ "${IMDB_CRASH_OK:-}" = 1 ] || { echo "power_cut.sh: set IMDB_CRASH_OK=1 (root, loop and dm devices)"; exit 2; }
[ "$(id -u)" = 0 ] || { echo "power_cut.sh: needs root"; exit 2; }
[ -x "$AUDIT" ] || { echo "power_cut.sh: $AUDIT not built"; exit 2; }
# Mount in a private namespace: the desktop's volume monitors (udisksd, gvfs) look at every new
# mount in theirs, which held the first check image busy for a moment and failed its unmount.
# Only this script sees these mounts, and any it leaves go with the namespace.
if [ "${IMDB_CRASH_NS:-}" != 1 ]; then
    IMDB_CRASH_NS=1 exec unshare --mount --propagation private bash "$0" "$@"
fi

WORK=$(readlink -f "${IMDB_CRASH_TMP:-build/tmp}")/power-cut-$$
SAMPLE=${IMDB_CRASH_SAMPLE:-25}   # every Nth non-flush entry is replayed too
DM=imdb-lw-$$
mkdir -p "$WORK/mnt" "$WORK/chk"
cc -O2 -Wall -Wextra -Werror -o "$WORK/lw_replay" "$HERE/lw_replay.c"
cc -std=c11 -D_GNU_SOURCE -O2 -Wall -Wextra -Werror -pthread -I "$HERE/../../src" -o "$WORK/persist_writer" \
    "$HERE/persist_writer.c" "$(dirname "$BIN")/libimagedb.a"

DATA_LOOP="" LOG_LOOP="" CHK_LOOP=""
# Keep the devices off the desktop: udisks offers every new loop and dm device as a volume, so
# each check image came and went on screen, and one could be opened while it was being checked.
# The rule matches only this run's devices (its image files, its dm name); it lives in /run
# (gone at reboot) and is removed at exit.
RULE=/run/udev/rules.d/90-imagedb-crash-$$.rules
made_rules_dir=0
cleanup() {
    set +e
    mountpoint -q "$WORK/chk" && umount "$WORK/chk"
    mountpoint -q "$WORK/mnt" && umount "$WORK/mnt"
    [ -n "$CHK_LOOP" ] && losetup -d "$CHK_LOOP"
    dmsetup info "$DM" >/dev/null 2>&1 && dmsetup remove "$DM"
    [ -n "$DATA_LOOP" ] && losetup -d "$DATA_LOOP"
    [ -n "$LOG_LOOP" ] && losetup -d "$LOG_LOOP"
    rm -f "$RULE" && udevadm control --reload-rules
    [ "$made_rules_dir" = 1 ] && rmdir /run/udev/rules.d 2>/dev/null
    [ "${IMDB_CRASH_KEEP:-}" = 1 ] || rm -rf "$WORK"
}
trap cleanup EXIT
[ -d /run/udev/rules.d ] || { mkdir /run/udev/rules.d; made_rules_dir=1; }
cat > "$RULE" <<EOF
SUBSYSTEM=="block", KERNEL=="loop*", ATTR{loop/backing_file}=="$WORK/*", ENV{UDISKS_IGNORE}="1", ENV{UDISKS_AUTO}="0"
SUBSYSTEM=="block", KERNEL=="dm-*", ENV{DM_NAME}=="$DM", ENV{UDISKS_IGNORE}="1", ENV{UDISKS_AUTO}="0"
EOF
udevadm control --reload-rules
hidden() { # DEVICE: stop before making hundreds of devices if the desktop would still see them
    udevadm settle
    udevadm info --query=property --name="$1" | grep -qx 'UDISKS_IGNORE=1' ||
        { echo "power_cut.sh: the udev rule does not hide $1 from the desktop"; exit 2; }
}

modprobe dm-log-writes
truncate -s 96M "$WORK/data.img"
truncate -s 512M "$WORK/log.img"
DATA_LOOP=$(losetup -f --show "$WORK/data.img")
hidden "$DATA_LOOP"
LOG_LOOP=$(losetup -f --show "$WORK/log.img")
dmsetup create "$DM" --table "0 $(blockdev --getsz "$DATA_LOOP") log-writes $DATA_LOOP $LOG_LOOP"
DEV=/dev/mapper/$DM
hidden "$DEV"
mark() { dmsetup message "$DM" 0 mark "$1"; }

# no discards (they would zero ranges) and no lazy init (background writes after mount)
mkfs.ext4 -q -F -E nodiscard,lazy_itable_init=0,lazy_journal_init=0 "$DEV"
mark mkfs
mount -o data=ordered "$DEV" "$WORK/mnt"
D=$WORK/mnt/db
ACKS=$WORK/acks

# Each command is its own process: an open (recovery and its syncs), the work, a close.
step() {
    "$BIN" "$@" > /dev/null
    local seq head
    seq=$("$BIN" info "$D" | awk '$1 == "commit" {print $2}')
    head=$("$BIN" info "$D" | awk '$1 == "head" {print $2}')
    echo "$seq $head" >> "$ACKS"
    mark "a$seq"
}

step init "$D"
step sql "$D" -c "CREATE TABLE t (id INT64 PRIMARY KEY, user_id INT64 SUBJECT, memo TEXT);"
for i in $(seq 1 10); do step sql "$D" -c "INSERT INTO t VALUES ($i, $((i % 3)), 'secret-$((i % 3))-row-$i');"; done
step sql "$D" -c "CHECKPOINT;"
for i in $(seq 11 14); do step sql "$D" -c "UPDATE t SET memo = 'changed-$i' WHERE id = $((i - 10));"; done
step sql "$D" -c "ERASE SUBJECT 1;"
for i in $(seq 15 18); do step sql "$D" -c "INSERT INTO t VALUES ($i, 2, 'late-$i');"; done
step sql "$D" -c "DELETE FROM t WHERE id = 15;" -c "CHECKPOINT;"

# A persistent writer (persist_writer.c): one open, many commits, each acknowledgement recorded
# and marked before the next commit starts. Then the same with --durable-ack, after a mark: from
# its first acknowledgement on, DURABLE must be strict and name every acknowledged commit.
persistent() { # FIRST N [--durable-ack]
    coproc PW { "$WORK/persist_writer" "$D" "$@"; }
    local pid=$PW_PID seq head rd wr
    exec {rd}<&"${PW[0]}" {wr}>&"${PW[1]}" # bash unsets PW[] and closes its fds once it reaps the writer
    while read -r seq head <&"$rd"; do
        echo "$seq $head" >> "$ACKS"
        mark "a$seq"
        echo go >&"$wr" 2>/dev/null || true # after its last commit the writer may have exited already
    done
    exec {rd}<&- {wr}>&-
    wait "$pid" || { echo "FAIL: the persistent writer failed"; exit 1; }
}
persistent 100 40
mark strict
persistent 200 40 --durable-ack
umount "$WORK/mnt"
mark umounted
dmsetup remove "$DM"
echo "workload: $(wc -l < "$ACKS") acknowledged steps, last commit $(tail -n 1 "$ACKS" | cut -d' ' -f1)"

"$WORK/lw_replay" "$LOG_LOOP" --list > "$WORK/entries"
N=$(wc -l < "$WORK/entries")

fresh() { rm -f "$WORK/chk.img"; truncate -s 96M "$WORK/chk.img"; }

# 1. the replayer: the whole log must rebuild the device exactly
fresh
"$WORK/lw_replay" "$LOG_LOOP" "$WORK/chk.img" --upto $((N - 1))
cmp "$WORK/chk.img" "$WORK/data.img" || { echo "FAIL: replaying the whole log does not rebuild the device"; exit 1; }
echo "replayer: all $N entries rebuild the device byte for byte"

# 2. the states: every flush, every FUA write, and every SAMPLEth other entry after mkfs
start=$(awk '$5 == "mkfs" {print $1}' "$WORK/entries")
points=$(awk -v s="$start" -v k="$SAMPLE" '$1 > s && ($2 ~ /F/ || $2 ~ /U/ || ($1 % k) == 0) {print $1}' "$WORK/entries")
checked=0 strict_checked=0
strict_at=$(awk '$5 == "strict" {print $1}' "$WORK/entries")
[ -n "$strict_at" ] || { echo "FAIL: the log has no strict mark"; exit 1; }
for p in $points; do
    fresh
    "$WORK/lw_replay" "$LOG_LOOP" "$WORK/chk.img" --upto "$p"
    # the commits acknowledged before this point
    acked=$(awk -v p="$p" '$1 < p && $2 ~ /M/ && $5 ~ /^a[0-9]+$/ {print substr($5, 2)}' "$WORK/entries")
    CHK_LOOP=$(losetup -f --show "$WORK/chk.img")
    [ "$checked" -gt 0 ] || hidden "$CHK_LOOP"
    if ! mount "$CHK_LOOP" "$WORK/chk" 2>/dev/null; then
        echo "FAIL: entry $p: ext4 does not mount"; exit 1
    fi
    C=$WORK/chk/db
    # --durable-ack: once its writer has acknowledged a commit, the DURABLE on disk (read before any
    # writable open rewrites it) is strict and names the last acknowledged commit or a later one
    strict_acked=$(awk -v p="$p" -v s="$strict_at" '$1 < p && $1 > s && $2 ~ /M/ && $5 ~ /^a[0-9]+$/ {print substr($5, 2)}' \
                   "$WORK/entries" | tail -n 1)
    if [ -n "$strict_acked" ]; then
        last=$(echo "$acked" | tail -n 1)
        # (recover takes the directory's LOCK, creating that file on the check image: harmless)
        rec=$("$BIN" recover "$C" 2>&1 || true)
        dur=$(echo "$rec" | awk '$1 == "durable" && $2 == "commit" {print $3}')
        case "$rec" in *"(strict:"*) ;; *) echo "FAIL: entry $p: DURABLE is not strict:"; echo "$rec"; exit 1 ;; esac
        if [ -z "$dur" ] || [ "$dur" -lt "$last" ]; then
            echo "FAIL: entry $p: commit $last was acknowledged under --durable-ack, DURABLE names ${dur:-nothing}"; exit 1
        fi
        strict_checked=$((strict_checked + 1))
    fi
    if [ -z "$acked" ]; then
        :   # before init returned nothing is acknowledged (an interrupted init leaves a partial directory)
    else
        if ! out=$("$BIN" sql "$C" --csv -c "VERIFY;" -c "SHOW LOG 1000000;" 2>&1); then
            echo "FAIL: entry $p: the writable open or VERIFY fails:"; echo "$out" | tail -n 5; exit 1
        fi
        for s in $acked; do
            want=$(awk -v s="$s" '$1 == s {print $2}' "$ACKS" | tail -n 1)
            if [ "$s" = 0 ]; then continue; fi
            # (--csv quotes TEXT values, the hash among them; hex holds no quote)
            got=$(echo "$out" | awk -F, -v s="$s" '$1 == s {v = $3; gsub(/"/, "", v); print v}')
            if [ -z "$got" ]; then
                echo "FAIL: entry $p: acknowledged commit $s is missing"; exit 1
            elif [ "$got" != "$want" ]; then
                echo "FAIL: entry $p: acknowledged commit $s changed: the log has $got, acknowledged $want"; exit 1
            fi
        done
        if ! a=$("$AUDIT" verify "$C" 2>&1); then
            echo "FAIL: entry $p: the auditor rejects the recovered state:"; echo "$a" | tail -n 3; exit 1
        fi
    fi
    umount "$WORK/chk"
    losetup -d "$CHK_LOOP"
    CHK_LOOP=""
    checked=$((checked + 1))
done
echo "power cut: $checked replayed states (of $N log entries) recover, keep every acknowledged commit, VERIFY and audit"
echo "durable-ack: in $strict_checked of them DURABLE was strict and named every commit acknowledged under it"
echo "ALL POWER-CUT CHECKS PASSED"
