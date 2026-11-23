#!/bin/sh
# The JS driver's tests (POSIX sh): compile with tsc, make two databases each with a superuser role and a certificate,
# start two servers (A: the default channel binding, TCP on 127.0.0.1; B: --channel-binding any, TCP on 127.0.0.2, its
# own CA), run the codec and live tests, then renew A's certificate, restart A and check the old pin and CA still work.
# Every server is stopped by its PID (SIGTERM) and waited for, on every exit path. A fresh directory a run under
# $IMDB_DRV_JS_TMP (default tmp/run beside this script, on disk); logs under $IMDB_DRV_JS_LOGS. Exit 0 only when every
# test passed.
# The binaries (imagedb, imagedb-server) are the repository's build/ (this script's ../../build), IMDB_DRV_BIN
# overriding; the contract's vectors are read from ../../tests/unit/t_wire.c, IMDB_DRV_TWIRE overriding. TMPDIR is set
# under the scratch directory (tmp/scratch beside this script, IMDB_DRV_JS_SCRATCH overriding) so nothing of the
# toolchain lands in /tmp.
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
BIN=${IMDB_DRV_BIN:-$HERE/../../build}
TWIRE=${IMDB_DRV_TWIRE:-$HERE/../../tests/unit/t_wire.c}
BASE=${IMDB_DRV_JS_TMP:-$HERE/tmp/run}
SCRATCH=${IMDB_DRV_JS_SCRATCH:-$HERE/tmp/scratch}
LOGS=${IMDB_DRV_JS_LOGS:-$SCRATCH/logs}
NODE_TIMEOUT=${IMDB_DRV_JS_TIMEOUT:-1200}
TMPDIR="$SCRATCH/tmp"
export TMPDIR
PW='drv-js-Secret_1'
STAMP=$(date +%Y%m%d-%H%M%S)-$$
RUN="$BASE/r$$" # (short: a socket's path is at most 107 bytes; the stamp names the logs)
LOG="$LOGS/run-$STAMP"
PIDS=''

say() { printf '%s\n' "run_tests: $*"; }
stop_pid() { # SIGTERM one server, wait for it, and forget its PID (never signalled again: a reaped PID may be reused)
    kill -TERM "$1" 2>/dev/null
    wait "$1" 2>/dev/null
    rest=''
    for p in $PIDS; do [ "$p" = "$1" ] || rest="$rest $p"; done
    PIDS=$rest
    return 0
}
cleanup() {
    for p in $PIDS; do kill -TERM "$p" 2>/dev/null; done
    for p in $PIDS; do wait "$p" 2>/dev/null; done
    PIDS=''
}
trap cleanup EXIT
trap 'cleanup; exit 130' INT TERM HUP

for f in "$BIN/imagedb" "$BIN/imagedb-server"; do [ -x "$f" ] || { say "no $f (IMDB_DRV_BIN names the binaries' directory)"; exit 1; }; done
[ -r "$TWIRE" ] || { say "no $TWIRE (IMDB_DRV_TWIRE names tests/unit/t_wire.c)"; exit 1; }
mkdir -p "$BASE" "$LOGS" "$TMPDIR" || exit 1
mkdir "$RUN" "$LOG" || exit 1
say "run directory $RUN, logs $LOG, binaries $BIN"

say 'compiling (tsc)'
(cd "$HERE" && nice tsc -p tsconfig.json) > "$LOG/tsc.log" 2>&1 || { cat "$LOG/tsc.log"; say 'tsc failed'; exit 1; }

# a database, its superuser role (made with the embedded CLI before the server starts), its certificate
make_db() { # NAME
    d="$RUN/$1"
    mkdir "$d" && mkdir -m 700 "$d/sd" "$d/s" || return 1
    nice "$BIN/imagedb" init "$d/db" > "$LOG/$1-init.log" 2>&1 || return 1
    nice "$BIN/imagedb" sql "$d/db" -c "CREATE ROLE admin LOGIN SUPERUSER PASSWORD '$PW'" >> "$LOG/$1-init.log" 2>&1 || return 1
    nice "$BIN/imagedb-server" cert "$d/sd" > "$d/cert.out" 2>&1 || return 1
    sed -n 's/.*its pin (the key.s SPKI SHA-256): \([0-9a-f]\{64\}\)$/\1/p' "$d/cert.out" > "$d/pin"
    [ -s "$d/pin" ] || return 1
}
# start a server in the background: NAME TCPADDR LOGNAME [options...]; sets SPID and SPORT
start_server() {
    n=$1; addr=$2; lg=$3; shift 3
    d="$RUN/$n"
    nice "$BIN/imagedb-server" "$d/db" --socket "$d/s/sock" --server-dir "$d/sd" --tcp "$addr:0" "$@" > "$LOG/$lg.log" 2>&1 &
    SPID=$!
    PIDS="$PIDS $SPID"
    SPORT=''
    i=0
    while [ $i -lt 100 ]; do
        SPORT=$(sed -n 's/^imagedb-server: listening on tcp port \([0-9]*\) .*/\1/p' "$LOG/$lg.log")
        [ -n "$SPORT" ] && break
        kill -0 "$SPID" 2>/dev/null || break
        sleep 0.1
        i=$((i + 1))
    done
    [ -n "$SPORT" ] || { cat "$LOG/$lg.log"; say "server $n did not start"; return 1; }
    say "server $n: pid $SPID, socket $d/s/sock, tcp $addr:$SPORT $*"
}

make_db a || { say 'making database a failed'; cat "$LOG"/a-init.log; exit 1; }
make_db b || { say 'making database b failed'; cat "$LOG"/b-init.log; exit 1; }
PIN_A=$(cat "$RUN/a/pin")
start_server a 127.0.0.1 server-a || exit 1
PID_A=$SPID PORT_A=$SPORT
start_server b 127.0.0.2 server-b --channel-binding any || exit 1
PID_B=$SPID PORT_B=$SPORT

export IMDB_JS_USER=admin IMDB_JS_PASSWORD="$PW" IMDB_JS_TMP="$RUN" IMDB_DRV_TWIRE="$TWIRE"
export IMDB_JS_SOCK_A="$RUN/a/s/sock" IMDB_JS_PORT_A="$PORT_A" IMDB_JS_CA_A="$RUN/a/sd/tls/ca.crt" IMDB_JS_PIN_A="$PIN_A"
export IMDB_JS_SOCK_B="$RUN/b/s/sock" IMDB_JS_PORT_B="$PORT_B" IMDB_JS_CA_B="$RUN/b/sd/tls/ca.crt" IMDB_JS_PIN_B="$(cat "$RUN/b/pin")"
export IMDB_JS_PID_B="$PID_B"

say "phase 1: codec and live tests (at most $NODE_TIMEOUT s)"
cd "$HERE" || exit 1
timeout "$NODE_TIMEOUT" nice node --test dist/test/codec.test.js dist/test/live.test.js > "$LOG/phase1.tap" 2>&1
RC1=$?
grep -E '^(not ok|ok) |^# (tests|pass|fail|cancelled|skipped)' "$LOG/phase1.tap"
[ $RC1 -eq 0 ] || say "phase 1 failed (exit $RC1): $LOG/phase1.tap"
stop_pid "$PID_B" # (the live tests' last one stopped it already: its plain close)

say 'phase 2: cert --renew, A restarted on its old socket path, the old pin and CA; tools/probe.mjs'
stop_pid "$PID_A"
nice "$BIN/imagedb-server" cert "$RUN/a/sd" --renew > "$RUN/a/renew.out" 2>&1 || { cat "$RUN/a/renew.out"; say 'renew failed'; exit 1; }
PIN_R=$(sed -n 's/.*its pin (the key.s SPKI SHA-256): \([0-9a-f]\{64\}\)$/\1/p' "$RUN/a/renew.out")
RC2=0
if [ "$PIN_R" != "$PIN_A" ]; then say "the renewal's pin $PIN_R is not the old $PIN_A"; RC2=1; fi
start_server a 127.0.0.1 server-a-renewed || exit 1
export IMDB_JS_PORT_A="$SPORT" IMDB_JS_SOCK_A="$RUN/a/s/sock"
timeout 120 nice node --test dist/test/renew.test.js > "$LOG/phase2.tap" 2>&1 || RC2=1
grep -E '^(not ok|ok) |^# (tests|pass|fail)' "$LOG/phase2.tap"
# the probe: one statement's rows and exit 0; a driver's error and exit 1
OUT=$(timeout 60 node tools/probe.mjs "$RUN/a/s/sock" "$PW" "SELECT 41 + 1 AS answer" 2>&1)
if [ $? -eq 0 ] && printf '%s\n' "$OUT" | grep -q '42'; then say "probe: ok ($(printf '%s' "$OUT" | tr '\n' ' '))"; else say "probe failed: $OUT"; RC2=1; fi
OUT=$(timeout 60 node tools/probe.mjs "$RUN/a/s/sock" "$PW" "SELEKT 1" 2>&1)
if [ $? -eq 1 ]; then say "probe of a bad statement: exit 1 ($(printf '%s' "$OUT" | tr '\n' ' '))"; else say "probe of a bad statement did not exit 1: $OUT"; RC2=1; fi
OUT=$(timeout 60 node tools/probe.mjs "$RUN/a/s/sock" "not-the-password" "SELECT 1" 2>&1)
if [ $? -eq 1 ]; then say "probe with a wrong password: exit 1 ($(printf '%s' "$OUT" | tr '\n' ' '))"; else say "probe with a wrong password did not exit 1: $OUT"; RC2=1; fi
[ $RC2 -eq 0 ] || say "phase 2 failed: $LOG/phase2.tap"
cleanup

if [ $RC1 -eq 0 ] && [ $RC2 -eq 0 ]; then
    say "PASS (logs $LOG; the run's databases in $RUN)"
    exit 0
fi
say "FAIL (logs $LOG)"
exit 1
