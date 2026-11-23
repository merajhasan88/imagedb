#!/bin/sh
# The Go driver's tests (drivers/go), one command: sh run_tests.sh (on a shared machine, as one heavy job)
#
# 1. the standard library alone (go list -deps), gofmt and go vet;
# 2. go test of both packages: the codec against t_wire.c's vectors and §4's pinned SCRAM exchanges (and the copies held
#    to t_wire.c itself), the client against a fake server, offline; then the live tests against three imagedb-servers
#    this script starts, each its own database, and stops by its PID recorded from $! (SIGTERM, then wait), never a
#    process found by a lookup:
#      A: the default server (--channel-binding exporter) on its socket and 127.0.0.1:0, its certificate renewed once;
#      B: --channel-binding any, its own CA;
#      C: A's certificate and key served on 127.0.0.2:0 (a name the certificate lacks);
#      X: another CA (a certificate made, no server);
#    and cmd/probe run against A (a statement's rows, exit 0; a refused one, exit 1) and against the two mutant servers
#    (mutant-sig: the verdict's server signature one bit off; mutant-done: a byte past every DONE's body), each of which
#    must be refused by name;
# 3. the same again under the race detector (-race), against fresh servers.
#
# IMDB_DRV_BIN: the directory of imagedb and imagedb-server (default: the repository's build/ when this tree sits in the
# repository as drivers/go; else set it); IMDB_DRV_MUTANTS: the directory holding mutant-sig/ and mutant-done/ (none:
# that step said not run); IMDB_T_WIRE: tests/unit/t_wire.c (default the repository's); IMDB_DRV_GO_PASSES: "plain
# race"; IMDB_DRV_TOOLCHAINS: a directory holding go/ and cache/ (default: go from PATH, its caches under tmp/);
# IMDB_SAFE_KILL: a checked signaller for the servers (default: the script's own signal to its own child).
# Everything it writes: the test databases and server directories in tmp/run beside this script (on disk, never tmpfs),
# Go's temporary files, its telemetry counters and the logs in tmp/scratch (IMDB_DRV_GO_LOG for the logs). Nothing in
# the home directory or /tmp.
set -eu

HERE=$(cd "$(dirname "$0")" && pwd)
W=$HERE/tmp
if [ -n "${IMDB_DRV_BIN:-}" ]; then
	BIN=$IMDB_DRV_BIN
elif [ -r "$HERE/../../server/wire.c" ] && [ -x "$HERE/../../build/imagedb-server" ]; then
	BIN=$(cd "$HERE/../../build" && pwd)
else
	echo "run_tests.sh: no imagedb-server: build the repository (make; make server) or set IMDB_DRV_BIN" >&2
	exit 1
fi
MUT=${IMDB_DRV_MUTANTS:-}
if [ -n "${IMDB_T_WIRE:-}" ]; then
	T_WIRE=$IMDB_T_WIRE
elif [ -r "$HERE/../../tests/unit/t_wire.c" ]; then
	T_WIRE=$(cd "$HERE/../../tests/unit" && pwd)/t_wire.c
else
	echo "run_tests.sh: no tests/unit/t_wire.c (the vectors): set IMDB_T_WIRE" >&2
	exit 1
fi
R=$W/run
SCR=$W/scratch
LOG=${IMDB_DRV_GO_LOG:-$SCR/logs}
PW='Drv-go_pw.2026'

T=${IMDB_DRV_TOOLCHAINS:-}
if [ -n "$T" ]; then
	export PATH="$T/go/bin:$PATH" GOCACHE="$T/cache/go-build" GOPATH="$T/cache/gopath" GOMODCACHE="$T/cache/gopath/pkg/mod"
else
	export GOCACHE="$W/cache/go-build" GOPATH="$W/cache/gopath" GOMODCACHE="$W/cache/gopath/pkg/mod"
fi
# TMPDIR short (IMDB_DRV_GO_TMP overrides): the fake server's sockets live under it, and a socket's path is at most 107 bytes
GT=${IMDB_DRV_GO_TMP:-$W/t}
export GOTOOLCHAIN=local GOPROXY=off GOFLAGS="-mod=mod -p=2" XDG_CONFIG_HOME="$SCR/xdg" TMPDIR="$GT" GOTMPDIR="$GT"

# The servers are this script's own children, each PID recorded from $! as it starts (never one found by a lookup), and
# each stopped by SIGTERM and waited for here: through IMDB_SAFE_KILL when given (a signaller that checks its target is
# this project's own), else the script's own signal to its own child.
SK=${IMDB_SAFE_KILL:-}
PIDS=""
MP="" # a mutant server running (mutants), stopped by stop() too
STOP_FAILED=0
# stop_pid PID: SIGTERM to this script's own child, then wait for it. A refused signal is never waited on (the wait would
# never end and hold the shared lock): the PID recorded in pids.txt beside this script, and the run fails.
stop_pid() {
	if [ -n "$SK" ] && [ -r "$SK" ]; then
		if ! sh "$SK" -TERM "$1" >/dev/null 2>&1; then
			echo "run_tests.sh: safe-kill.sh refused server $1: left running, its PID in $HERE/pids.txt" >&2
			echo "$1" >>"$HERE/pids.txt"
			STOP_FAILED=1
			return 0
		fi
	else
		kill -TERM "$1" 2>/dev/null || true
	fi
	wait "$1" 2>/dev/null || true
}
stop() {
	for p in $PIDS $MP; do stop_pid "$p"; done
	PIDS="" MP=""
}
trap 'stop; [ "$STOP_FAILED" = 0 ] || exit 3' EXIT
trap 'exit 130' INT TERM

die() {
	echo "run_tests.sh: $*" >&2
	exit 1
}

pin_of() { # the pin `imagedb-server cert` prints
	sed -n 's/.*(the key.s SPKI SHA-256): \([0-9a-f]\{64\}\)$/\1/p'
}

port_of() { # the TCP port a server's "listening on tcp port N" line names, once it is out
	i=0
	while [ "$i" -lt 150 ]; do
		p=$(sed -n 's/^imagedb-server: listening on tcp port \([0-9][0-9]*\) .*/\1/p' "$1")
		if [ -n "$p" ]; then
			echo "$p"
			return 0
		fi
		sleep 0.1
		i=$((i + 1))
	done
	return 1
}

# servers: fresh databases, server directories and certificates, then A, B and C started
servers() {
	stop
	# the last pass's databases removed by a literal name inside this script's own tmp/ (never a path built from a variable)
	mkdir -p "$W"
	(cd "$W" && rm -rf ./run)
	mkdir -p "$R" "$GT" "$SCR/xdg" "$LOG"
	for s in a b c m; do # m: the mutant servers' database
		"$BIN/imagedb" init "$R/db-$s" >/dev/null
		"$BIN/imagedb" sql "$R/db-$s" -c "CREATE ROLE admin LOGIN SUPERUSER PASSWORD '$PW'" >/dev/null
		mkdir -p "$R/sdir-$s"
	done
	mkdir -p "$R/sdir-x"
	PIN_A=$("$BIN/imagedb-server" cert "$R/sdir-a" | pin_of)
	cp "$R/sdir-a/tls/server.crt" "$R/a-old.crt"
	PIN_A2=$("$BIN/imagedb-server" cert "$R/sdir-a" --renew | pin_of)
	[ -n "$PIN_A" ] && [ "$PIN_A" = "$PIN_A2" ] || die "cert --renew changed the pin ($PIN_A, $PIN_A2)"
	cmp -s "$R/a-old.crt" "$R/sdir-a/tls/server.crt" && die "cert --renew kept the certificate"
	PIN_B=$("$BIN/imagedb-server" cert "$R/sdir-b" | pin_of)
	PIN_X=$("$BIN/imagedb-server" cert "$R/sdir-x" | pin_of)
	mkdir -m 700 "$R/sdir-c/tls"
	cp -p "$R/sdir-a/tls/ca.crt" "$R/sdir-a/tls/ca.key" "$R/sdir-a/tls/server.crt" "$R/sdir-a/tls/server.key" "$R/sdir-c/tls/"
	"$BIN/imagedb-server" "$R/db-a" --socket "$R/a.sock" --server-dir "$R/sdir-a" --tcp 127.0.0.1:0 \
		>"$LOG/server-a.out" 2>"$LOG/server-a.err" &
	PIDS="$PIDS $!"
	"$BIN/imagedb-server" "$R/db-b" --socket "$R/b.sock" --server-dir "$R/sdir-b" --tcp 127.0.0.1:0 \
		--channel-binding any >"$LOG/server-b.out" 2>"$LOG/server-b.err" &
	PIDS="$PIDS $!"
	"$BIN/imagedb-server" "$R/db-c" --socket "$R/c.sock" --server-dir "$R/sdir-c" --tcp 127.0.0.2:0 \
		>"$LOG/server-c.out" 2>"$LOG/server-c.err" &
	PIDS="$PIDS $!"
	PA=$(port_of "$LOG/server-a.out") || die "server A did not start: $(cat "$LOG/server-a.err")"
	PB=$(port_of "$LOG/server-b.out") || die "server B did not start: $(cat "$LOG/server-b.err")"
	PC=$(port_of "$LOG/server-c.out") || die "server C did not start: $(cat "$LOG/server-c.err")"
	export IMDB_LIVE=1 IMDB_USER=admin IMDB_PASSWORD="$PW" \
		IMDB_A_SOCK="$R/a.sock" IMDB_A_ADDR="127.0.0.1:$PA" IMDB_A_CA="$R/sdir-a/tls/ca.crt" IMDB_A_PIN="$PIN_A" \
		IMDB_A_CRT="$R/sdir-a/tls/server.crt" IMDB_A_CRT_OLD="$R/a-old.crt" \
		IMDB_B_SOCK="$R/b.sock" IMDB_B_ADDR="127.0.0.1:$PB" IMDB_B_CA="$R/sdir-b/tls/ca.crt" IMDB_B_PIN="$PIN_B" \
		IMDB_C_ADDR="127.0.0.2:$PC" IMDB_C_CA="$R/sdir-a/tls/ca.crt" IMDB_C_PIN="$PIN_A" \
		IMDB_X_CA="$R/sdir-x/tls/ca.crt" IMDB_X_PIN="$PIN_X"
	echo "servers: A on 127.0.0.1:$PA, B on 127.0.0.1:$PB, C on 127.0.0.2:$PC (pids$PIDS)"
}

cd "$HERE"
mkdir -p "$GT" "$SCR/xdg" "$LOG"
[ -x "$BIN/imagedb" ] && [ -x "$BIN/imagedb-server" ] || die "no imagedb and imagedb-server in $BIN (IMDB_DRV_BIN names their directory)"
[ -r "$T_WIRE" ] || die "no t_wire.c at $T_WIRE (IMDB_T_WIRE names it)"
export IMDB_T_WIRE="$T_WIRE"
echo "binaries: $BIN; t_wire.c: $T_WIRE"
go version

# 1. the standard library alone: no package outside it but the module's own
deps=$(go list -deps -f '{{if not .Standard}}{{.ImportPath}}{{end}}' ./... | sort -u)
[ "$deps" = "$(printf 'imagedb.dev/imagedb\nimagedb.dev/imagedb/cmd/probe\nimagedb.dev/imagedb/wire')" ] || die "a dependency outside the standard library: $deps"
grep -q '^require' go.mod && die "go.mod requires a module"
echo "dependencies: the standard library alone (go list -deps: $(echo "$deps" | tr '\n' ' '))"
[ -z "$(gofmt -l .)" ] || die "gofmt: $(gofmt -l .)"
go vet ./...
# the acceptance probe, built once
mkdir -p "$SCR/bin"
go build -o "$SCR/bin/probe" ./cmd/probe

probe_check() { # cmd/probe against server A: rows and exit 0; a refused statement and a refused login, exit 1
	out=$("$SCR/bin/probe" "$R/a.sock" "$PW" "SELECT 1 AS one, 'é' AS t, NULL AS n") || die "probe: exit $? on a SELECT"
	want=$(printf 'one\tt\tn\n1\té\tNULL\n-- ')
	case "$out" in "$want"*) ;; *) die "probe: printed $out" ;; esac
	if "$SCR/bin/probe" "$R/a.sock" "$PW" "SELECT * FROM nosuch" >/dev/null 2>"$LOG/probe.err"; then die "probe: exit 0 on an error"; fi
	grep -q nosuch "$LOG/probe.err" || die "probe: its error: $(cat "$LOG/probe.err")"
	if "$SCR/bin/probe" "$R/a.sock" wrong-pw "SELECT 1" >/dev/null 2>&1; then die "probe: exit 0 with a wrong password"; fi
	echo "probe: rows (exit 0), a statement refused (exit 1: $(cat "$LOG/probe.err")), a login refused (exit 1)"
}

# mutants: cmd/probe against each mutant server (IMDB_DRV_MUTANTS: built elsewhere, never here) on its own database and socket,
# each stopped before the next: the probe must exit 1 naming what it refused (the server's signature; the DONE frame).
mutants() {
	for m in mutant-sig mutant-done; do
		srv=$MUT/$m/imagedb-server
		if [ ! -x "$srv" ]; then
			echo "mutants: $srv absent: not run"
			continue
		fi
		"$srv" "$R/db-m" --socket "$R/$m.sock" --server-dir "$R/sdir-m" >"$LOG/server-$m.out" 2>"$LOG/server-$m.err" &
		MP=$!
		i=0
		until grep -q 'listening on' "$LOG/server-$m.out" || [ "$i" -ge 150 ]; do
			sleep 0.1
			i=$((i + 1))
		done
		mrc=0
		"$SCR/bin/probe" "$R/$m.sock" "$PW" "SELECT 1 + 1" >"$LOG/probe-$m.out" 2>"$LOG/probe-$m.err" || mrc=$?
		stop_pid "$MP"
		MP=""
		case $m in
		mutant-sig) words="did not prove it holds the verifier" ;;
		*) words="DONE frame refused" ;;
		esac
		if [ "$mrc" != 1 ] || ! grep -q "$words" "$LOG/probe-$m.err"; then
			die "$m: probe exit $mrc: $(cat "$LOG/probe-$m.out" "$LOG/probe-$m.err") (want exit 1 and \"$words\")"
		fi
		echo "mutants: $m refused (exit 1: $(cat "$LOG/probe-$m.err"))"
	done
}

# 2. and 3.
rc=0
for pass in ${IMDB_DRV_GO_PASSES:-plain race}; do # a development run may name one
	servers
	if [ "$pass" = plain ]; then
		probe_check
		mutants
	fi
	flags=""
	[ "$pass" = race ] && flags="-race"
	echo "== go test $flags (offline and live)"
	if go test -p 2 -count=1 -v $flags -timeout 20m ./... >"$LOG/test-$pass.log" 2>&1; then
		echo "== $pass: ok"
	else
		echo "== $pass: FAILED (log: $LOG/test-$pass.log)"
		rc=1
	fi
	grep -E '^(--- |ok |FAIL|PASS$|panic)' "$LOG/test-$pass.log" || true
	if grep -q "^--- SKIP" "$LOG/test-$pass.log"; then
		echo "== $pass: a test skipped (every one runs here)"
		rc=1
	fi
	stop
done
exit $rc
