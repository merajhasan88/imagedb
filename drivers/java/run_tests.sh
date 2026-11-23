#!/bin/sh
# The Java driver's tests (POSIX sh): builds the driver with plain javac (no Maven, no Gradle), then runs
#   - the codec suite (no server: tests/unit/t_wire.c's vectors, docs/n1-design.md §4's pinned SCRAM exchanges, a
#     scripted peer, this JDK's TLS API);
#   - the live suite against two imagedb servers it starts and stops by PID: S1 a default server (the TLS exporter
#     alone), S2 one run with --channel-binding any; then both again after `imagedb-server cert --renew` (the pin kept).
#
# Usage: sh run_tests.sh [name-fragment]     the tests, every configuration the variables allow
#        sh run_tests.sh --build             build the default configuration only and print the probe's command line
#
# Configurations: "default" (the java and javac on PATH) always; with JDK25=<a JDK 25 home> "jdk25" (the JDK's own
# exporter); with JDK17=<a JDK 17 home> "jdk17" (the standard library alone: tls-server-end-point, taken by S2 only);
# with BCDIR=<BouncyCastle's jars: bctls, bcprov, bcutil> "jdk17bc" (BouncyCastle's exporter; "default-bc" when JDK17 is
# unset) and "jdk25bc" (the stack check alone: JDK 25 prefers its own exporter). CONFIGS overrides the list.
#
# Environment (each has a default; each may be set):
#   IMDB_DRV_BIN      the imagedb binaries (imagedb, imagedb-server)          default: ../../build (from this script)
#   T_WIRE            tests/unit/t_wire.c, the copied vectors checked in it   default: ../../tests/unit/t_wire.c
#   SCRATCH           logs and the JVMs' temporary directory (never /tmp)     default: ./build/scratch
#   IMDB_DRV_TESTDIR  the test databases; when set it must not exist or be empty (never removed by this script)
#                     default: tmp/run beside this script, removed and made again by each run
#   JDK25, JDK17, BCDIR, CONFIGS: above
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
BIN=${IMDB_DRV_BIN:-$HERE/../../build}
T_WIRE=${T_WIRE:-$HERE/../../tests/unit/t_wire.c}
SCRATCH=${SCRATCH:-$HERE/build/scratch}
JDK25=${JDK25:-}
JDK17=${JDK17:-}
BCDIR=${BCDIR:-}
FILTER=
BUILD_ONLY=0
case ${1:-} in
--build) BUILD_ONLY=1 ;;
*) FILTER=${1:-} ;;
esac
LOG=$SCRATCH/logs
BUILD=$HERE/build
PW='drv-Java-pw-2026' # the superuser's test password (printable ASCII, as CREATE ROLE takes one)
mkdir -p "$LOG" "$SCRATCH/tmp"
JOPTS="-XX:-UsePerfData -Djava.io.tmpdir=$SCRATCH/tmp"
JCOPTS="-J-XX:-UsePerfData -J-Djava.io.tmpdir=$SCRATCH/tmp"
FAILED=0
RAN=

say() { printf '%s\n' "run_tests: $*"; }

# the default JDK: the javac and java on PATH, as one home
JAVAC_PATH=$(command -v javac 2>/dev/null || true)
if [ -z "$JAVAC_PATH" ]; then
    say "no javac on PATH (JDK 17 or later)"
    exit 2
fi
JDKDEF=$(cd "$(dirname "$JAVAC_PATH")/.." && pwd)
if [ -L "$JAVAC_PATH" ]; then # a distribution's alternatives link: the JDK it names
    real=$(readlink -f "$JAVAC_PATH")
    JDKDEF=$(cd "$(dirname "$real")/.." && pwd)
fi

BCJARS=
if [ -n "$BCDIR" ]; then
    for j in bctls bcprov bcutil; do
        f=$(ls "$BCDIR"/$j-*.jar 2>/dev/null | head -1)
        if [ -z "$f" ]; then
            say "BCDIR=$BCDIR holds no $j-*.jar"
            exit 2
        fi
        BCJARS=${BCJARS:+$BCJARS:}$f
    done
fi

# ---- build: each JDK's javac, --release 17, the standard library alone; the BouncyCastle bridge against its jars ----
build() { # JDK OUT WITH_BC
    jdk=$1 out=$2 withbc=$3
    mkdir -p "$out/main" "$out/bc" "$out/test"
    # shellcheck disable=SC2046
    nice "$jdk/bin/javac" $JCOPTS -Xlint:all -Werror -encoding UTF-8 --release 17 -d "$out/main" \
        $(find "$HERE/src/main/java" -name '*.java') || return 1
    if [ "$withbc" = 1 ]; then
        # shellcheck disable=SC2046
        nice "$jdk/bin/javac" $JCOPTS -Xlint:all -encoding UTF-8 --release 17 -d "$out/bc" -cp "$out/main:$BCJARS" \
            $(find "$HERE/src/bc/java" -name '*.java') || return 1
    fi
    # shellcheck disable=SC2046
    nice "$jdk/bin/javac" $JCOPTS -Xlint:all -encoding UTF-8 --release 17 -d "$out/test" -cp "$out/main" \
        $(find "$HERE/src/test/java" -name '*.java') || return 1
}

if [ "$BUILD_ONLY" = 1 ]; then
    build "$JDKDEF" "$BUILD/default" 0 || { say "the build failed"; exit 1; }
    say "built $BUILD/default/main with $JDKDEF; the probe:"
    echo "java $JOPTS -cp $BUILD/default/main imagedb.tools.Probe SOCKET PASSWORD SQL"
    exit 0
fi

# ---- the test databases ----
if [ -n "${IMDB_DRV_TESTDIR:-}" ]; then
    W=$IMDB_DRV_TESTDIR
    if [ -e "$W" ] && [ -n "$(ls -A "$W" 2>/dev/null)" ]; then
        say "IMDB_DRV_TESTDIR=$W exists and is not empty: remove it or name another"
        exit 2
    fi
else
    W=$HERE/tmp/run # (on disk beside this script: tmpfs would hold the test databases in RAM)
    rm -rf -- "$HERE/tmp/run"
fi
mkdir -p "$W" || exit 2
for b in imagedb imagedb-server; do
    [ -x "$BIN/$b" ] || { say "no $b in $BIN (IMDB_DRV_BIN)"; exit 2; }
done

# ---- servers: started in the background, stopped by their PID (never pkill: other servers run on this machine) ----
start_server() { # NAME DIR SDIR [options]: its TCP port into LOG/NAME.port (run in this shell: the server our child)
    name=$1 dir=$2 sdir=$3
    shift 3
    rm -f "$W/$name.sock" "$LOG/$name.port"
    nice "$BIN/imagedb-server" "$dir" --socket "$W/$name.sock" --server-dir "$sdir" --tcp 127.0.0.1:0 "$@" \
        >"$LOG/$name.out" 2>"$LOG/$name.err" &
    pid=$!
    echo "$pid" >"$LOG/$name.pid"
    i=0
    while [ $i -lt 150 ]; do # 30 s at most
        if grep -q 'listening on tcp port' "$LOG/$name.out" 2>/dev/null; then break; fi
        if ! kill -0 "$pid" 2>/dev/null; then break; fi
        sleep 0.2
        i=$((i + 1))
    done
    port=$(sed -n 's/.*listening on tcp port \([0-9][0-9]*\).*/\1/p' "$LOG/$name.out")
    if [ -z "$port" ]; then
        say "server $name did not start:"
        cat "$LOG/$name.err" >&2
        return 1
    fi
    echo "$port" >"$LOG/$name.port"
}

stop_server() { # NAME: SIGTERM, a bounded wait; a second SIGTERM cancels running statements; then the last resort
    name=$1
    [ -f "$LOG/$name.pid" ] || return 0
    pid=$(cat "$LOG/$name.pid")
    rm -f "$LOG/$name.pid"
    kill -0 "$pid" 2>/dev/null || return 0
    kill -TERM "$pid" 2>/dev/null
    i=0
    while kill -0 "$pid" 2>/dev/null && [ $i -lt 100 ]; do sleep 0.2; i=$((i + 1)); done
    if kill -0 "$pid" 2>/dev/null; then
        say "server $name: a second SIGTERM"
        kill -TERM "$pid" 2>/dev/null
        i=0
        while kill -0 "$pid" 2>/dev/null && [ $i -lt 100 ]; do sleep 0.2; i=$((i + 1)); done
    fi
    if kill -0 "$pid" 2>/dev/null; then
        say "server $name (pid $pid) did not stop: SIGKILL"
        kill -KILL "$pid" 2>/dev/null
        FAILED=1
    fi
    wait "$pid" 2>/dev/null
    st=$?
    [ "$st" -eq 0 ] || say "server $name exited $st (its stderr: $LOG/$name.err)"
}

cleanup() {
    for n in s1 s2; do stop_server "$n"; done
}
trap 'cleanup' EXIT
trap 'cleanup; exit 130' INT TERM

# ---- set up: two databases, the superuser made before the servers start, three certificate directories ----
setup() {
    for d in db1 db2; do
        "$BIN/imagedb" init "$W/$d" >/dev/null || return 1
        "$BIN/imagedb" sql "$W/$d" -c "CREATE ROLE admin LOGIN SUPERUSER PASSWORD '$PW'" \
            -c "CREATE TABLE big (id BIGINT PRIMARY KEY, x BIGINT)" >/dev/null || return 1
        awk 'BEGIN { for (i = 1; i <= 1000000; i++) print i "," (i * 7919) % 1000003 }' |
            nice "$BIN/imagedb" sql "$W/$d" -c "COPY big FROM STDIN (BATCH 100000)" >/dev/null || return 1
    done
    for s in sd1 sd2 sd3; do
        mkdir -m 700 "$W/$s"
        "$BIN/imagedb-server" cert "$W/$s" >"$LOG/$s.cert" || return 1
    done
}

pin_of() { sed -n 's/.*SHA-256): \([0-9a-f]*\).*/\1/p' "$LOG/$1.cert"; }

run_java() { # JDK CLASSPATH LOGNAME ARGS...: one bounded run
    jdk=$1 cp=$2 logname=$3
    shift 3
    timeout 1200 nice "$jdk/bin/java" $JOPTS -cp "$cp" "$@" 2>&1 | tee "$LOG/$logname.log"
    RAN="$RAN $logname"
    grep -q ' 0 failed; [0-9]* checks, 0 failed' "$LOG/$logname.log" || FAILED=1
}

# the configurations
if [ -z "${CONFIGS:-}" ]; then
    CONFIGS=default
    [ -n "$JDK25" ] && CONFIGS="$CONFIGS jdk25"
    [ -n "$JDK17" ] && CONFIGS="$CONFIGS jdk17"
    if [ -n "$BCDIR" ]; then
        if [ -n "$JDK17" ]; then CONFIGS="$CONFIGS jdk17bc"; else CONFIGS="$CONFIGS default-bc"; fi
        [ -n "$JDK25" ] && CONFIGS="$CONFIGS jdk25bc"
    fi
fi
[ -n "$JDK25" ] || say "JDK25 not set: the JDK 25 configuration (its own exporter) not run"
[ -n "$JDK17" ] || say "JDK17 not set: the JDK 17 configuration (tls-server-end-point) not run"
[ -n "$BCDIR" ] || say "BCDIR not set: the BouncyCastle configurations not run"

config() { # CFG: sets jdk, out, withbc, expect ("" when AUTO decides at run time)
    case $1 in
    default) jdk=$JDKDEF out=$BUILD/default withbc=0 expect= ;;
    default-bc) jdk=$JDKDEF out=$BUILD/default-bc withbc=1 expect= ;;
    jdk25) jdk=$JDK25 out=$BUILD/jdk25 withbc=0 expect=JDK_EXPORTER ;;
    jdk25bc) jdk=$JDK25 out=$BUILD/jdk25bc withbc=1 expect=JDK_EXPORTER ;;
    jdk17) jdk=$JDK17 out=$BUILD/jdk17 withbc=0 expect=END_POINT ;;
    jdk17bc) jdk=$JDK17 out=$BUILD/jdk17bc withbc=1 expect=BC_EXPORTER ;;
    *) say "no configuration $1"; exit 2 ;;
    esac
    [ -n "$jdk" ] && [ -x "$jdk/bin/javac" ] || { say "configuration $1: no JDK ($jdk)"; exit 2; }
    cp="$out/main:$out/test"
    [ "$withbc" = 1 ] && cp="$out/main:$out/bc:$out/test:$BCJARS"
    eprop=
    [ -n "$expect" ] && eprop="-Dimdb.expect.binding=$expect"
}

for cfg in $CONFIGS; do
    config "$cfg"
    build "$jdk" "$out" "$withbc" || { say "the build failed ($cfg)"; exit 1; }
done
say "the driver: $HERE; the binaries: $BIN; the test databases: $W; logs: $LOG"
say "built: $CONFIGS (javac --release 17)"
setup || { say "the set-up failed"; exit 1; }
start_server s1 "$W/db1" "$W/sd1" || exit 1
start_server s2 "$W/db2" "$W/sd2" --channel-binding any || exit 1
P1=$(cat "$LOG/s1.port")
P2=$(cat "$LOG/s2.port")
say "S1 (default binding) on port $P1, S2 (--channel-binding any) on port $P2"

common() { # the live suite's places
    echo "-Dimdb.sock=$W/s1.sock -Dimdb.port=$P1 -Dimdb.pin=$(pin_of sd1) -Dimdb.ca=$W/sd1/tls/ca.crt \
-Dimdb.any.sock=$W/s2.sock -Dimdb.any.port=$P2 -Dimdb.any.pin=$(pin_of sd2) -Dimdb.any.ca=$W/sd2/tls/ca.crt \
-Dimdb.otherca=$W/sd3/tls/ca.crt -Dimdb.password=$PW -Dimdb.twire=$T_WIRE"
}

for cfg in $CONFIGS; do
    config "$cfg"
    say "== $cfg: $("$jdk/bin/java" -XX:-UsePerfData -version 2>&1 | head -1); AUTO should take ${expect:-what this JDK and class path give}"
    if [ "$cfg" = jdk25bc ]; then
        run_java "$jdk" "$cp" "$cfg-codec" -Dimdb.config=$cfg $eprop imagedb.test.Main codec tls_stack_proof
        continue
    fi
    # shellcheck disable=SC2046
    run_java "$jdk" "$cp" "$cfg-codec" -Dimdb.config=$cfg $eprop -Dimdb.twire="$T_WIRE" imagedb.test.Main codec $FILTER
    # shellcheck disable=SC2046
    run_java "$jdk" "$cp" "$cfg-live" -Dimdb.config=$cfg $eprop -Dimdb.tag=$(echo "$cfg" | tr -d -) $(common) \
        imagedb.test.Main live $FILTER
done

# the pin after `cert --renew`: both servers restarted on their renewed certificates, the old pins and CAs still taken
if [ -z "$FILTER" ] || [ "$FILTER" = renew ]; then
    for s in 1 2; do
        cp "$W/sd$s/tls/server.crt" "$LOG/old-server$s.crt"
        stop_server "s$s"
        "$BIN/imagedb-server" cert "$W/sd$s" --renew >"$LOG/sd$s.renew" || FAILED=1
        say "$(cat "$LOG/sd$s.renew")"
    done
    start_server s1 "$W/db1" "$W/sd1" || exit 1
    start_server s2 "$W/db2" "$W/sd2" --channel-binding any || exit 1
    P1=$(cat "$LOG/s1.port")
    P2=$(cat "$LOG/s2.port")
    for cfg in $CONFIGS; do
        [ "$cfg" = jdk25bc ] && continue
        config "$cfg"
        # shellcheck disable=SC2046
        run_java "$jdk" "$cp" "$cfg-renew" -Dimdb.config=$cfg $eprop -Dimdb.tag=$(echo "$cfg" | tr -d -) \
            -Dimdb.oldcert="$LOG/old-server1.crt" -Dimdb.any.oldcert="$LOG/old-server2.crt" $(common) imagedb.test.Main renew
    done
fi

cleanup
say "summary:"
for l in $RAN; do
    grep -h "^\(codec\|live\|renew\) (" "$LOG/$l.log" | sed "s/^/  /"
done
say "the probe: java $JOPTS -cp $BUILD/default/main imagedb.tools.Probe SOCKET PASSWORD SQL"
say "test databases: $W ($(du -sh "$W" 2>/dev/null | cut -f1)); remove them with: rm -rf $W"
if [ "$FAILED" -ne 0 ]; then
    say "FAILED"
    exit 1
fi
say "all passed"
exit 0
