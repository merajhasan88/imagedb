#!/bin/sh
# The Python driver's tests: the codec against t_wire.c's vectors and section 4's pinned SCRAM exchanges, a scripted peer
# (the driver's own refusals and rules, no server), then live against imagedb-server: two servers it starts here, A at
# the default channel binding (the exporter alone: this driver's login is refused there by verdict 2) and B with
# --channel-binding any, each on its own socket and TCP port 0 with its own certificate, and a third CA (C) for the
# refusals; then B's certificate renewed (`cert --renew`), B restarted, and the pin checked again. Each server is
# stopped by its PID (SIGTERM, a second one after 10 s) and waited for; its exit status must be 0.
#   drivers/python/run_tests.sh   (IMDB_DRV_BIN: the directory of imagedb and imagedb-server, by default the repository's
#                                  build/; IMDB_PY_TWIRE: t_wire.c, by default the repository's tests/unit/t_wire.c)
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
BIN=${IMDB_DRV_BIN:-$HERE/../../build}  # the repository's build/ (after `make` and `make server`)
RUN=$HERE/tmp/run  # (on disk: tmpfs would hold the test databases in RAM)
PW=pw-drv-python
PIDS=""
FAILED=0

say() { printf '%s\n' "run_tests.sh: $*"; }
die() { say "FAIL: $*"; stop_all; exit 1; }

# stop_one PID: SIGTERM, a second one after 10 s (it cancels the running statement), then its exit status
stop_one() {
    kill -TERM "$1" 2>/dev/null
    n=0
    while kill -0 "$1" 2>/dev/null && [ $n -lt 100 ]; do sleep 0.1; n=$((n + 1)); done
    if kill -0 "$1" 2>/dev/null; then kill -TERM "$1" 2>/dev/null; fi
    wait "$1"
    st=$?
    left=""
    for p in $PIDS; do [ "$p" = "$1" ] || left="$left $p"; done
    PIDS=$left
    return $st
}

stop_all() {
    for p in $PIDS; do stop_one "$p" || say "server $p exited $?"; done
}

trap 'stop_all' EXIT
trap 'stop_all; exit 2' INT TERM

# start NAME ARGS...: a server in the background, its PID in PID_NAME, its TCP port in PORT_NAME
start() {
    name=$1
    shift
    nice -n 5 "$BIN/imagedb-server" "$@" > "$RUN/$name.out" 2>&1 &
    pid=$!
    PIDS="$PIDS $pid"
    port=""
    n=0
    while [ $n -lt 150 ]; do
        port=$(awk '/listening on tcp port/ { print $6 }' "$RUN/$name.out")
        [ -n "$port" ] && break
        kill -0 "$pid" 2>/dev/null || break
        sleep 0.1
        n=$((n + 1))
    done
    [ -n "$port" ] || die "server $name did not start: $(cat "$RUN/$name.out")"
    eval "PID_$name=$pid PORT_$name=$port"
    say "server $name: pid $pid, tcp port $port"
}

[ -x "$BIN/imagedb-server" ] && [ -x "$BIN/imagedb" ] || die "no binaries in $BIN"
rm -rf -- "$HERE/tmp/run"
mkdir -p "$RUN" || die "mkdir $RUN"
for db in a b; do
    "$BIN/imagedb" init "$RUN/$db" > /dev/null || die "init $db"
    "$BIN/imagedb" sql "$RUN/$db" --nosync -c "CREATE ROLE admin LOGIN SUPERUSER PASSWORD '$PW'" > /dev/null || die "role $db"
done
mkdir -m 700 "$RUN/sa" "$RUN/sb" "$RUN/sc" || die "mkdir server dirs"
PIN_A=$("$BIN/imagedb-server" cert "$RUN/sa" | awk '{ print $NF }')
PIN_B=$("$BIN/imagedb-server" cert "$RUN/sb" | awk '{ print $NF }')
PIN_C=$("$BIN/imagedb-server" cert "$RUN/sc" | awk '{ print $NF }')
[ ${#PIN_A} = 64 ] && [ ${#PIN_B} = 64 ] && [ ${#PIN_C} = 64 ] || die "cert's pins: $PIN_A $PIN_B $PIN_C"

start a "$RUN/a" --socket "$RUN/a.sock" --server-dir "$RUN/sa" --tcp 127.0.0.1:0 --nosync
start b "$RUN/b" --socket "$RUN/b.sock" --server-dir "$RUN/sb" --tcp 127.0.0.1:0 --channel-binding any --nosync

export IMDB_PY_RUN="$RUN" IMDB_PY_PASSWORD="$PW" IMDB_PY_PHASE=1
export IMDB_PY_A_SOCK="$RUN/a.sock" IMDB_PY_A_PORT="$PORT_a" IMDB_PY_A_SDIR="$RUN/sa" IMDB_PY_A_PIN="$PIN_A"
export IMDB_PY_B_SOCK="$RUN/b.sock" IMDB_PY_B_PORT="$PORT_b" IMDB_PY_B_SDIR="$RUN/sb" IMDB_PY_B_PIN="$PIN_B"
export IMDB_PY_C_SDIR="$RUN/sc" IMDB_PY_C_PIN="$PIN_C"
cd "$HERE" || die "cd $HERE"
nice -n 10 python3 -B -m unittest -v tests.test_codec tests.test_peer tests.test_live 2>&1 | tee "$RUN/phase1.log"
grep -q '^OK' "$RUN/phase1.log" || FAILED=1

# phase 2: B's certificate renewed under the same CA from the same key, B restarted: the pin the same, the certificate
# (and so tls-server-end-point's value) another
cp "$RUN/sb/tls/server.crt" "$RUN/old-server.crt" || die "cp server.crt"
stop_one "$PID_b" || { say "FAIL: server b exited $? at its stop"; FAILED=1; }
PIN_B2=$("$BIN/imagedb-server" cert "$RUN/sb" --renew | awk '{ print $NF }')
[ "$PIN_B2" = "$PIN_B" ] || die "cert --renew printed another pin: $PIN_B2, not $PIN_B"
start b2 "$RUN/b" --socket "$RUN/b.sock" --server-dir "$RUN/sb" --tcp 127.0.0.1:0 --channel-binding any --nosync
export IMDB_PY_PHASE=2 IMDB_PY_B_PORT="$PORT_b2" IMDB_PY_OLD_CRT="$RUN/old-server.crt"
nice -n 10 python3 -B -m unittest -v tests.test_live.Renewed 2>&1 | tee "$RUN/phase2.log"
grep -q '^OK' "$RUN/phase2.log" || FAILED=1

for p in $PIDS; do
    stop_one "$p" || { say "FAIL: server $p exited $? at its stop"; FAILED=1; }
done
trap - EXIT INT TERM
if [ "$FAILED" = 0 ]; then
    rm -rf -- "$HERE/tmp/run"
    say "PASS"
    exit 0
fi
say "FAIL (the servers' logs and the run kept in $RUN)"
exit 1
