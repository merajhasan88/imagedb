#!/bin/sh
# imagedb's C# driver (IMDBWIR1, docs/n1-design.md §4): build it offline with the .NET 10 SDK and run its tests.
#   sh run_tests.sh   (on a shared machine, as one heavy job)
# Phases: codec (t_wire.c's vectors), mock (an in-process server of crafted frames), live (imagedb-server: A with the
# default --channel-binding exporter, B with --channel-binding any, each on its socket and TCP with TLS), renew (B's
# certificate renewed, B restarted, the same pin). Every server is started here and stopped by its PID (SIGTERM).
# Nothing is written to the home directory or /tmp: the SDK's homes and caches are under the toolchains' cache (or tmp/),
# TMPDIR is tmp/sdk, no build server outlives a command; no NuGet package is referenced and NuGet.Config names no
# source, so nothing can be downloaded.
# IMDB_DRV_BIN: the directory of imagedb, imagedb-server (default: the repository's build/).
# IMDB_DRV_T_WIRE: t_wire.c, whose vectors the codec tests' copies must match (default: the repository's).
# IMDB_DRV_TOOLCHAINS: a directory holding dotnet-10/ and cache/ (default: dotnet from PATH, its homes under tmp/).
# Test databases, server directories and sockets: tmp/run beside this script (on disk, never tmpfs).
# IMDB_DRV_TMPDIR: TMPDIR for the SDK (default tmp/sdk beside this script).
set -eu

HERE=$(cd "$(dirname "$0")" && pwd)
TC=${IMDB_DRV_TOOLCHAINS:-}
BIN=${IMDB_DRV_BIN:-$HERE/../../build}
[ -x "$BIN/imagedb" ] && [ -x "$BIN/imagedb-server" ] || { echo "FAIL: no imagedb and imagedb-server in $BIN (build the repository, or set IMDB_DRV_BIN)" >&2; exit 1; }
export IMDB_DRV_T_WIRE="${IMDB_DRV_T_WIRE:-$HERE/../../tests/unit/t_wire.c}"
[ -r "$IMDB_DRV_T_WIRE" ] || { echo "FAIL: no $IMDB_DRV_T_WIRE (set IMDB_DRV_T_WIRE)" >&2; exit 1; }
RUN=$HERE/tmp/run
REAL_HOME=${HOME:-/nonexistent}

if [ -n "$TC" ]; then
  export DOTNET_ROOT="$TC/dotnet-10" PATH="$TC/dotnet-10:$PATH" DOTNET_CLI_HOME="$TC/cache/dotnet-home" NUGET_PACKAGES="$TC/cache/nuget"
  export NUGET_HTTP_CACHE_PATH="$TC/cache/nuget-http"
else
  export DOTNET_CLI_HOME="$HERE/tmp/dotnet-home" NUGET_PACKAGES="$HERE/tmp/nuget" NUGET_HTTP_CACHE_PATH="$HERE/tmp/nuget-http"
fi
export DOTNET_CLI_TELEMETRY_OPTOUT=1 DOTNET_NOLOGO=1 DOTNET_SKIP_FIRST_TIME_EXPERIENCE=1 DOTNET_GENERATE_ASPNET_CERTIFICATE=0
export DOTNET_ADD_GLOBAL_TOOLS_TO_PATH=0 DOTNET_CLI_WORKLOAD_UPDATE_NOTIFY_DISABLE=1 DOTNET_CLI_USE_MSBUILD_SERVER=0
export MSBUILDDISABLENODEREUSE=1
export HOME="$DOTNET_CLI_HOME" TMPDIR="${IMDB_DRV_TMPDIR:-$HERE/tmp/sdk}"
# the CLI's first run makes a named mutex under DOTNET_CLI_HOME: its directory must exist
mkdir -p "$DOTNET_CLI_HOME" "$NUGET_PACKAGES" "$TMPDIR"

fail=0
apid=""
bpid=""
stop() { # stop a server by its PID: SIGTERM, then wait for it
  if [ -n "$1" ] && kill -0 "$1" 2>/dev/null; then
    kill -TERM "$1"
    wait "$1" 2>/dev/null || true
  fi
}
cleanup() {
  stop "$apid"
  stop "$bpid"
}
trap cleanup EXIT INT TERM

echo "== build (offline, Release)"
for p in tests/Imagedb.Client.Tests/Imagedb.Client.Tests.csproj probe/Imagedb.Probe.csproj; do
  nice dotnet build "$HERE/$p" -c Release -nologo -v q -nodeReuse:false --disable-build-servers -p:UseSharedCompilation=false
done
DLL="$HERE/tests/Imagedb.Client.Tests/bin/Release/net10.0/Imagedb.Client.Tests.dll"
PROBE="$HERE/probe/bin/Release/net10.0/Imagedb.Probe.dll"

[ -n "$HERE" ] && rm -rf -- "$HERE/tmp/run" # (HERE resolved above: never empty)
mkdir -p "$RUN"
touch "$RUN/stamp"
export IMDB_DRV_RUN="$RUN"

echo "== codec and mock"
nice dotnet "$DLL" codec,mock || fail=1

echo "== live: two databases, two servers"
PW="pw-drv-csharp-$$"
for s in a b; do
  "$BIN/imagedb" init "$RUN/db-$s" > /dev/null
  "$BIN/imagedb" sql "$RUN/db-$s" --nosync -c "CREATE ROLE admin LOGIN SUPERUSER PASSWORD '$PW'" < /dev/null > /dev/null
  mkdir -m 700 "$RUN/sd-$s"
  "$BIN/imagedb-server" cert "$RUN/sd-$s" > "$RUN/cert-$s.out"
done
mkdir -m 700 "$RUN/sd-other" # a certificate directory never served: "another CA", "another server's pin"
"$BIN/imagedb-server" cert "$RUN/sd-other" > "$RUN/cert-other.out"

start() { # start server $1 with its extra options $2; its PID in the variable named $3; its TCP port printed
  "$BIN/imagedb-server" "$RUN/db-$1" --socket "$RUN/s-$1" --server-dir "$RUN/sd-$1" --tcp 127.0.0.1:0 --nosync $2 \
    > "$RUN/srv-$1.out" 2>&1 &
  eval "$3=$!"
  port=""
  i=0
  while [ $i -lt 100 ]; do
    port=$(awk '/listening on tcp port/ { print $6 }' "$RUN/srv-$1.out")
    [ -n "$port" ] && break
    sleep 0.1
    i=$((i + 1))
  done
  [ -n "$port" ] || { echo "FAIL: server $1 did not start: $(cat "$RUN/srv-$1.out")" >&2; exit 1; }
}

start a "" apid
export IMDB_DRV_A_PORT="$port"
start b "--channel-binding any" bpid
export IMDB_DRV_B_PORT="$port"
pin() { awk '{ print $NF }' "$1"; }
export IMDB_DRV_PASSWORD="$PW"
export IMDB_DRV_A_SOCK="$RUN/s-a" IMDB_DRV_A_PIN="$(pin "$RUN/cert-a.out")" IMDB_DRV_A_CA="$RUN/sd-a/tls/ca.crt" IMDB_DRV_A_SDIR="$RUN/sd-a"
export IMDB_DRV_B_SOCK="$RUN/s-b" IMDB_DRV_B_PIN="$(pin "$RUN/cert-b.out")" IMDB_DRV_B_CA="$RUN/sd-b/tls/ca.crt" IMDB_DRV_B_SDIR="$RUN/sd-b"
export IMDB_DRV_OTHER_CA="$RUN/sd-other/tls/ca.crt" IMDB_DRV_OTHER_PIN="$(pin "$RUN/cert-other.out")"
echo "   server A (default binding): pid $apid, tcp $IMDB_DRV_A_PORT; server B (--channel-binding any): pid $bpid, tcp $IMDB_DRV_B_PORT"
nice dotnet "$DLL" live || fail=1

echo "== the probe (Imagedb.Probe SOCKET PASSWORD SQL)"
if out=$(nice dotnet "$PROBE" "$RUN/s-a" "$PW" "SELECT 41 + 1 AS x") && [ "$(printf '%s\n' "$out" | sed -n 2p)" = "42" ]; then
  echo "   SELECT 41 + 1: exit 0, $(printf '%s\n' "$out" | tr '\n' ' ')"
else
  echo "FAIL: the probe's SELECT: $out" >&2
  fail=1
fi
if nice dotnet "$PROBE" "$RUN/s-a" "$PW" "SELEC 1" > /dev/null 2> "$RUN/probe.err"; then
  echo "FAIL: the probe took a syntax error" >&2
  fail=1
elif grep -q "error 10:" "$RUN/probe.err"; then
  echo "   SELEC 1: exit 1, $(cat "$RUN/probe.err")"
else
  echo "FAIL: the probe's error: $(cat "$RUN/probe.err")" >&2
  fail=1
fi

echo "== renew: cert --renew, B restarted, the same pin"
"$BIN/imagedb-server" cert "$RUN/sd-b" --renew > "$RUN/renew-b.out"
[ "$(pin "$RUN/renew-b.out")" = "$IMDB_DRV_B_PIN" ] || { echo "FAIL: the renewal printed another pin" >&2; fail=1; }
stop "$bpid"
bpid=""
start b "--channel-binding any" bpid
export IMDB_DRV_B_PORT="$port"
nice dotnet "$DLL" renew || fail=1

stop "$apid"
apid=""
stop "$bpid"
bpid=""

# nothing of the SDK's in the home directory or /tmp during this run
leak=$(find "$REAL_HOME/.dotnet" "$REAL_HOME/.nuget" "$REAL_HOME/.local/share/NuGet" /tmp/.dotnet /tmp/NuGetScratch* /tmp/MSBuildTemp* \
  -newer "$RUN/stamp" 2>/dev/null | head -3)
if [ -n "$leak" ]; then
  echo "FAIL: the SDK wrote outside its caches: $leak" >&2
  fail=1
else
  echo "== nothing written under $REAL_HOME/.dotnet, .nuget, .local/share/NuGet, /tmp/.dotnet, /tmp/NuGetScratch* or /tmp/MSBuildTemp*"
fi

if [ "$fail" = 0 ]; then
  rm -rf -- "$HERE/tmp/run"
  echo "== ALL PASSED"
else
  echo "== FAILED (the run's databases and server logs kept in $RUN)" >&2
fi
exit "$fail"
