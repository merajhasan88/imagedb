#!/bin/sh
# imagedb's Rust driver, stage 1 (the server's Unix-domain socket; TCP with TLS 1.3 is stage 2, not built): every test.
# The offline tests (the primitives against their vectors and against sha256sum and OpenSSL's command line, the codec
# against t_wire.c, a scripted server) run first; then the live tests against the frozen server, which this script
# starts on a socket under its run directory and stops by its own child's PID; then the probe binary against the
# honest server and against two mutant servers, when given (a server signature one bit off, a byte past every
# DONE), which must be refused. The last line says PASS or FAIL.
#
# The one command (on a shared machine, as one heavy job):
#   sh run_tests.sh [cargo test filter]
# Environment: IMDB_DRV_BIN (imagedb and imagedb-server: the repository's build/ by default), IMDB_DRV_MUTANTS (the
# directory of the mutant-sig/ and mutant-done/ servers: none by default, that step said not run), IMDB_T_WIRE (the C
# reference's tests/unit/t_wire.c: the repository's by default), IMDB_TEST_ROOT (test databases and sockets: this
# crate's tmp/ by default; never tmpfs), IMDB_DRV_TMP (TMPDIR for the toolchain).
set -eu

HERE=$(cd "$(dirname "$0")" && pwd)
# defaults: the repository's own build/ and tests/ (this crate sits at drivers/rust in it)
if [ -n "${IMDB_DRV_BIN:-}" ]; then BIN=$IMDB_DRV_BIN
else BIN=$HERE/../../build
fi
MUT=${IMDB_DRV_MUTANTS:-$BIN}
if [ -z "${IMDB_T_WIRE:-}" ]; then IMDB_T_WIRE=$HERE/../../tests/unit/t_wire.c
fi
export IMDB_T_WIRE
echo "== binaries $BIN, vectors $IMDB_T_WIRE"
export TMPDIR="${IMDB_DRV_TMP:-$HERE/tmp/toolchain}"
mkdir -p "$TMPDIR"
[ -x "$BIN/imagedb" ] && [ -x "$BIN/imagedb-server" ] || { echo "no imagedb and imagedb-server in $BIN (IMDB_DRV_BIN)" >&2; exit 1; }
[ -f "$IMDB_T_WIRE" ] || { echo "no t_wire.c at $IMDB_T_WIRE (IMDB_T_WIRE)" >&2; exit 1; }
ROOT=${IMDB_TEST_ROOT:-$HERE/tmp}
FILTER=${1:-}
export PATH="$HOME/.cargo/bin:$PATH"
export CARGO_TARGET_DIR="$HERE/target"
export CARGO_NET_OFFLINE=true
J="-j 2"

mkdir -p "$ROOT"
RUN=$(mktemp -d "$ROOT/r.XXXXXX")
[ ${#RUN} -le 80 ] || { echo "the run directory's path is too long for a socket under 100 bytes: $RUN" >&2; exit 1; }
export IMDB_TEST_ROOT="$RUN" # the scripted server's sockets too
PIDS=""

# each server is this shell's own child: stopped by the PID $! gave, then waited for
stop_servers() {
    for p in $PIDS; do
        if kill -0 "$p" 2>/dev/null; then
            kill -TERM "$p" 2>/dev/null || true
        fi
        wait "$p" 2>/dev/null || true
    done
    PIDS=""
}
finish() {
    st=$?
    stop_servers
    if [ "$st" -eq 0 ]; then echo "== PASS (run directory $RUN)"; else echo "== FAIL (exit $st; run directory $RUN)"; fi
}
trap finish EXIT
trap 'exit 130' INT TERM

echo "== build and offline tests (primitives, codec, t_wire.c, a scripted server)"
cd "$HERE"
nice cargo build $J --offline --tests --bins --quiet
nice cargo test $J --offline --quiet --lib --test crypto --test codec --test t_wire_file --test fake_server -- --nocapture $FILTER
nice cargo test $J --offline --quiet --doc

# a database and its first role, made by the embedded CLI before the server starts
mkdb() { # DIR
    "$BIN/imagedb" init "$1" >/dev/null
    "$BIN/imagedb" sql "$1" -c "CREATE ROLE admin LOGIN SUPERUSER PASSWORD 'pw-admin'" >/dev/null
}

# a server on its own socket, a child of this shell: LAST_PID its PID once the socket exists
start_server() { # NAME SERVER-BINARY DB
    name=$1 srv=$2 db=$3
    mkdir -m 700 "$RUN/sdir-$name"
    nice "$srv" "$db" --socket "$RUN/$name.sock" --server-dir "$RUN/sdir-$name" >"$RUN/$name.log" 2>&1 &
    pid=$!
    PIDS="$PIDS $pid"
    i=0
    while [ ! -S "$RUN/$name.sock" ]; do
        if ! kill -0 "$pid" 2>/dev/null; then
            echo "server $name did not start:" >&2
            cat "$RUN/$name.log" >&2
            exit 1
        fi
        i=$((i + 1))
        [ $i -le 300 ] || { echo "server $name: no socket in 30 s" >&2; exit 1; }
        sleep 0.1
    done
    LAST_PID=$pid
}

stop_one() { # PID
    kill -TERM "$1" 2>/dev/null || true
    wait "$1" 2>/dev/null || true
    rest=""
    for p in $PIDS; do [ "$p" = "$1" ] || rest="$rest $p"; done
    PIDS=$rest
}

echo "== the server (run directory $RUN)"
mkdb "$RUN/db-a"
start_server a "$BIN/imagedb-server" "$RUN/db-a"
PID_A=$LAST_PID

export IMDB_LIVE=1
export IMDB_RUN="$RUN"
export IMDB_SOCK_A="$RUN/a.sock"
export IMDB_USER=admin IMDB_PASSWORD=pw-admin

echo "== live tests over the socket (one at a time: SESSIONS, KILL and cancel see each other)"
nice cargo test $J --offline --quiet --test live -- --test-threads=1 --nocapture $FILTER

PROBE="$CARGO_TARGET_DIR/debug/probe"
echo "== the probe binary (src/bin/probe.rs) against the honest server"
OUT=$("$PROBE" "$IMDB_SOCK_A" pw-admin "SELECT 40 + 2, 'x'")
[ "$OUT" = "42|x" ] || { echo "probe printed: $OUT" >&2; exit 1; }
if "$PROBE" "$IMDB_SOCK_A" wrong "SELECT 1" 2>"$RUN/probe.err"; then echo "probe: a wrong password taken" >&2; exit 1; fi
grep -q "authentication refused" "$RUN/probe.err" || { cat "$RUN/probe.err" >&2; exit 1; }
if "$PROBE" "$IMDB_SOCK_A" pw-admin "SELEC 1" 2>"$RUN/probe.err"; then echo "probe: a syntax error exit 0" >&2; exit 1; fi
echo "probe: rows, a refused login and a syntax error as expected"
stop_one "$PID_A"

echo "== the probe against the mutant servers (each must be refused, by name)"
if [ -x "$MUT/mutant-sig/imagedb-server" ] && [ -x "$MUT/mutant-done/imagedb-server" ]; then
    mkdb "$RUN/db-m"
    for m in mutant-sig mutant-done; do
        start_server "$m" "$MUT/$m/imagedb-server" "$RUN/db-m"
        if "$PROBE" "$RUN/$m.sock" pw-admin "SELECT 1 + 1" >"$RUN/$m.out" 2>&1; then
            echo "$m: ACCEPTED (a defect): $(cat "$RUN/$m.out")" >&2
            exit 1
        fi
        case $m in
        mutant-sig) want="did not prove it holds the verifier" ;;
        *) want="a DONE frame refused: a body with bytes past its end" ;;
        esac
        grep -q "$want" "$RUN/$m.out" || { echo "$m: refused, but not by its rule: $(cat "$RUN/$m.out")" >&2; exit 1; }
        echo "$m: refused ($(cat "$RUN/$m.out"))"
        stop_one "$LAST_PID"
    done
else
    echo "not run: no mutant-sig/ and mutant-done/ servers in $MUT (IMDB_DRV_MUTANTS)"
fi
