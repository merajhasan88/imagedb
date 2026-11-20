#!/usr/bin/env bash
# The 2026-11-18 review (docs/imagedb-feedback-2026-11-18.md; its checks/run.sh, ported): what only the binaries show.
# 1. A failed final close is the command's failure: imagedb-server, imagedb apply and imagedb rewind, built as close
#    probes (Makefile: probes; tests/integration/close_eio.c fails the close's last DURABLE fsync with EIO), exit 1, say
#    so and print no success (no "applied", no "rewound", no enrolment). The probe's own line is required, so a hook that
#    never fires fails the test. EXPECT=0 with PROBE_CLI and PROBE_SRV built from a tree before the fix shows 0/0/0.
# 2. The daemon's controls: --mem-limit and --seg-cache reach the handle (SHOW MEMORY), --iceberg writes the layer,
#    --anchor is kept and `verify --anchor` takes it with the layer current; --seg-cache all; bad sizes refused (2).
#   tests/integration/close_status.sh [path/to/imagedb]   (imagedb-server, imagedb-client and probe/ beside it)
set -euo pipefail

BIN=${1:-build/imagedb}
DIR=$(dirname "$BIN")
SRV=$DIR/imagedb-server
CLI=$DIR/imagedb-client
PCLI=${PROBE_CLI:-$DIR/probe/imagedb-closefail}
PSRV=${PROBE_SRV:-$DIR/probe/imagedb-server-closefail}
EXPECT=${EXPECT:-1}
WORK=$(mktemp -d "${IMDB_TEST_TMP:-/tmp}/imdb-cs.XXXXXX")
[ ${#WORK} -le 100 ] || { echo "FAIL: $WORK is too long for a Unix socket's path (107 bytes): a shorter IMDB_TEST_TMP" >&2; rm -rf "$WORK"; exit 1; }
spid=""
cleanup() {
  if [ -n "$spid" ]; then kill -TERM "$spid" 2>/dev/null || true; wait "$spid" 2>/dev/null || true; fi
  rm -rf "$WORK"
}
trap cleanup EXIT
fail() { echo "FAIL: $*" >&2; exit 1; }

P=$WORK/p
"$BIN" init "$P" >/dev/null
"$BIN" sql "$P" --nosync -c "CREATE ROLE admin LOGIN SUPERUSER PASSWORD 'fixture-only'" >/dev/null
mkdir -m 700 "$WORK/sd"
start() { # program, then the server's options
  local program=$1
  shift
  rm -f "$WORK/s"
  "$program" "$P" --socket "$WORK/s" --server-dir "$WORK/sd" "$@" >"$WORK/server.out" 2>"$WORK/server.err" &
  spid=$!
  for _ in $(seq 200); do
    grep -q 'listening on' "$WORK/server.out" && [ -S "$WORK/s" ] && return 0
    kill -0 "$spid" 2>/dev/null || break
    sleep 0.05
  done
  cat "$WORK/server.err" >&2
  fail "the server did not start: $*"
}
stop() { # SIGTERM, its exit code in stop_rc
  kill -TERM "$spid"
  stop_rc=0
  wait "$spid" || stop_rc=$?
  spid=""
}
net() { IMAGEDB_PASSWORD=fixture-only "$CLI" --socket "$WORK/s" --user admin "$@"; }

if [ "$EXPECT" = 1 ]; then
  # 2. the daemon's controls
  start "$SRV" --mem-limit 32M --seg-cache 2M --iceberg --anchor "$WORK/ext-anchor"
  net -c 'SHOW MEMORY' >"$WORK/show"
  grep -q 'budget 33554432, 8388608 of it kept' "$WORK/show" || fail "--mem-limit 32M: $(cat "$WORK/show")"
  grep -q 'segment images .*budget 2097152' "$WORK/show" || fail "--seg-cache 2M: $(cat "$WORK/show")"
  net -c 'CREATE TABLE lake_test (id INT64 PRIMARY KEY, n INT64)' -c 'INSERT INTO lake_test VALUES (1, 11), (2, 22)' \
      -c CHECKPOINT >/dev/null
  [ -s "$P/iceberg/LAYER" ] || fail "--iceberg: no layer after a CHECKPOINT"
  stop
  [ "$stop_rc" -eq 0 ] || fail "a clean stop exited $stop_rc"
  [ -s "$WORK/ext-anchor" ] || fail "--anchor: no anchor written"
  "$BIN" verify "$P" --anchor "$WORK/ext-anchor" >"$WORK/verify" || fail "verify --anchor: $(cat "$WORK/verify")"
  grep -q 'iceberg layer .*the one the lake gives' "$WORK/verify" || fail "verify: the layer not current"
  start "$SRV" --seg-cache all
  net -c 'SHOW MEMORY' >"$WORK/show"
  grep -q 'every one kept' "$WORK/show" || fail "--seg-cache all: $(cat "$WORK/show")"
  stop
  [ "$stop_rc" -eq 0 ] || fail "a clean stop exited $stop_rc"
  # N1e stage two: the server's constants as options, every one at once, and three out of their bounds refused
  start "$SRV" --preauth-max 8 --preauth-timeout 5000 --preauth-per-addr 2 --socket-reserve 4 --slice-ms 20 --queue-max 16 \
        --send-timeout 20000 --conn-cap 8M --reply-budget 64M --role-copy-spool 256M
  net -c 'SELECT 1' >/dev/null || fail "a server with every constant set did not answer"
  stop
  [ "$stop_rc" -eq 0 ] || fail "a clean stop exited $stop_rc"
  for pair in '--mem-limit 0' '--mem-limit 18446744073709551616' '--seg-cache 01M' '--seg-cache never' '--slice-ms 0' \
              '--queue-max 0' '--conn-cap 1K' '--role-copy-spool 2T'; do
    rc=0
    # shellcheck disable=SC2086 # two words, an option and its value
    "$SRV" "$P" --socket "$WORK/s" --server-dir "$WORK/sd" $pair >/dev/null 2>&1 || rc=$?
    [ "$rc" -eq 2 ] || fail "$pair: exit $rc, not the usage's 2"
  done
  echo "the daemon's controls: --mem-limit, --seg-cache (and all), --iceberg, --anchor, the nine constants and --role-copy-spool taken; eight bad values refused"
  # 2b-2b: the descriptors --max-conns needs (256: 2,496): a hard limit short of them refused before anything is opened;
  # a soft one short of them raised to the hard one
  rc=0
  (ulimit -n 1024 && exec "$SRV" "$P" --socket "$WORK/s" --server-dir "$WORK/sd") >"$WORK/nofile" 2>&1 || rc=$?
  { [ "$rc" -eq 1 ] && grep -q 'needs about 2496 file descriptors, and RLIMIT_NOFILE allows 1024' "$WORK/nofile"; } ||
    fail "a hard limit of 1,024: exit $rc: $(cat "$WORK/nofile")"
  [ ! -S "$WORK/s" ] || fail "a refused start made its socket"
  hard=$(ulimit -Hn)
  if [ "$hard" = unlimited ] || [ "$hard" -ge 4096 ]; then
    printf '#!/bin/sh\nulimit -Sn 1024 || exit 9\nexec "%s" "$@"\n' "$SRV" >"$WORK/soft1024"
    chmod +x "$WORK/soft1024"
    start "$WORK/soft1024"
    soft=$(awk '/^Max open files/ {print $4}' "/proc/$spid/limits")
    [ "$soft" = "$(awk '/^Max open files/ {print $5}' "/proc/$spid/limits")" ] || fail "a soft limit of 1,024 not raised: $soft"
    net -c 'CREATE TABLE fd_t (id INT64 PRIMARY KEY)' -c 'INSERT INTO fd_t VALUES (1)' -c CHECKPOINT >/dev/null
    fds=$(find "/proc/$spid/fd" -mindepth 1 -maxdepth 1 | wc -l)
    stop
    [ "$stop_rc" -eq 0 ] || fail "a clean stop exited $stop_rc"
    echo "the descriptors: a hard limit of 1,024 refused at start; a soft one raised to $soft; $fds open with no client (256 allowed for them)"
    [ "$fds" -lt 256 ] || fail "the server holds $fds descriptors with no client: past imdbs_fds_needed's 256"
  else
    echo "the descriptors: a hard limit of 1,024 refused at start; the soft limit's raise not tested (the hard limit is $hard)"
  fi
fi

# 1. a failed final close: the server, apply, rewind
"$BIN" ship "$P" >"$WORK/stream"
start "$PSRV" --nosync
stop
[ "$stop_rc" -eq "$EXPECT" ] || fail "the server's failed close exited $stop_rc, not $EXPECT"
grep -q 'final DURABLE fsync returned EIO' "$WORK/server.err" || fail "the server: the probe never fired"
R=$WORK/case
mkdir "$R"
"$BIN" init-replica "$R/rep" "$P" >/dev/null
rc=0
"$PCLI" apply "$R/rep" <"$WORK/stream" >"$R/a" 2>&1 || rc=$?
[ "$rc" -eq "$EXPECT" ] || fail "apply's failed close exited $rc, not $EXPECT: $(cat "$R/a")"
grep -q 'final DURABLE fsync returned EIO' "$R/a" || fail "apply: the probe never fired"
# a real split and rewind on disposable copies (neither writer running during the promotion or the rewind)
pub=$("$BIN" root-key "$R/key" 2>/dev/null)
"$BIN" init "$R/w" --root "$pub" >/dev/null
"$BIN" init-replica "$R/r" "$R/w" >/dev/null
"$BIN" sql "$R/w" -c 'CREATE TABLE t (id INT64 PRIMARY KEY)' >/dev/null
"$BIN" ship "$R/w" | "$BIN" apply "$R/r" >/dev/null 2>"$R/ship"
"$BIN" promote "$R/r" --root-key "$R/key" --old-writer-stopped >/dev/null
"$BIN" sql "$R/w" -c 'INSERT INTO t VALUES (10)' >/dev/null
rc=0
"$PCLI" rewind "$R/w" --demote --save "$R/save" -- "$BIN" ship "$R/r" --hashes --after '{after}' >"$R/rlog" 2>&1 || rc=$?
[ "$rc" -eq "$EXPECT" ] || fail "rewind's failed close exited $rc, not $EXPECT: $(cat "$R/rlog")"
grep -q 'final DURABLE fsync returned EIO' "$R/rlog" || fail "rewind: the probe never fired"
if [ "$EXPECT" = 1 ]; then
  grep -q 'final database close failed' "$WORK/server.err" || fail "the server did not say its close failed"
  grep -q 'final database close failed' "$R/a" || fail "apply did not say its close failed"
  grep -q 'final database close failed' "$R/rlog" || fail "rewind did not say its close failed"
  if grep -Eq '^applied [0-9]|^rewound |^enrol it' "$R/a" "$R/rlog"; then fail "a success printed after a failed close"; fi
  grep -q "commits past commit .* are in $R/save" "$R/rlog" || fail "rewind did not say where the saved commits are"
fi
echo "a failed final close (the last DURABLE fsync EIO): server / apply / rewind exit $EXPECT / $EXPECT / $EXPECT"
