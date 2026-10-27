#!/bin/sh
# Whole-engine benchmarks under equal contracts (deferred.md R8): bench/whole.c, one process per
# engine, one after the other on the same file system: imagedb (fdatasync per commit; then without
# its index on id; then with --durable-ack), SQLite (WAL, synchronous=FULL) and a private
# PostgreSQL instance (initdb into a scratch directory, its own port and socket, fsync and
# synchronous_commit on: the defaults; the system's cluster is not touched). Each line: "engine
# workload metric value unit".
#   bench/whole.sh [build/whole | build/whole-ext]          (root: the governor window and the postgres user)
# The CPU governor is set to performance for the run and put back as it was on exit, and so is the
# power profile where power-profiles-daemon runs (the user's yes, 2026-10-24: "You can switch to
# Performance briefly for your runs"). The run refuses to start on a busy machine (load above
# 1.5). The engines run in a fixed order (imagedb, imagedb --no-index: R8's imagedb without its
# ordered index on id, imagedb --durable-ack, SQLite, PostgreSQL), each after a minute's idle,
# with the CPU package temperature and the mean clock printed before and after each: a laptop
# that heats up favours the engines that run first, and these lines show whether it did. First,
# bench/fsync_probe.c: what one durable 4 KiB write costs on this disk (appended, overwritten,
# into fallocated space).
#
# Given build/whole-ext (the user's request, 2026-10-26), five more follow, each with its defaults:
# PostgreSQL 14 in a container (the container-overhead control: the native instance's settings),
# MySQL 8.4, MariaDB (LTS) and SQL Server 2025 Developer in containers, then DuckDB in process. A
# container keeps its data in $D (the same ext4 file system) and has no network: MySQL and MariaDB
# answer on a socket in $D; SQL Server, which has no socket, on loopback TCP with host networking.
# Its main process's host pid stands in for PostgreSQL's postmaster.pid, so the driver counts its
# memory, writes and CPU the same way. Each is started and initialised before its idle minute; its
# restart is timed from the stop to its first answer, through the driver's own client library.
# Each engine's idle minute starts with a sync, and the dirty and writeback memory is printed as the
# engine starts, so no engine inherits the previous one's unwritten data: written back under its
# commits, that costs a durable write tens of milliseconds here (docs/open-items-2026-10-26.md, A).
# bench/devstall.c, when built beside the driver, watches the disk under $D for the whole run, and
# its pauses and slow cache flushes are printed at the end. This machine's SSD sometimes holds
# commands for seconds, and those times explain a driver's stall lines.
# Knobs for checking the script itself (a smoke run), all off by default:
#   WHOLE_ONLY="sqlite mysql ..."  run only these engines (names as printed; probe for fsync_probe)
#   WHOLE_REST=N                   seconds of idle before each engine (default 60)
#   WHOLE_WINDOW=0                 leave the governor and the power profile alone
set -eu
W=$(readlink -f "${1:-build/whole}")
[ "$(id -u)" = 0 ] || { echo "whole.sh: needs root (the governor window and the postgres user)"; exit 2; }
load=$(cut -d' ' -f1 /proc/loadavg)
awk -v l="$load" 'BEGIN { exit !(l > 1.5) }' && { echo "whole.sh: load $load: run it alone"; exit 2; }
D=/var/tmp/imdb-whole-$$
C=imdb-whole-$$ # the containers: $C-pg, $C-mysql, $C-mariadb, $C-mssql
PGBIN=/usr/lib/postgresql/14/bin
PORT=54329
GOV=/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor
WIN=${WHOLE_WINDOW:-1}
old=$(cat "$GOV" 2>/dev/null || echo "")
PP=$(command -v powerprofilesctl || true)
oldpp=$([ -n "$PP" ] && "$PP" get 2>/dev/null || true)
EXT=0
"$W" 2>&1 | grep -q sqlserver && EXT=1 # whole-ext's usage names its engines
cleanup() {
    set +e
    [ -f "$D/pg/postmaster.pid" ] && su postgres -s /bin/sh -c "$PGBIN/pg_ctl -D $D/pg -m fast -w stop" >/dev/null 2>&1
    [ "$EXT" = 1 ] && for x in pg mysql mariadb mssql; do docker rm -f "$C-$x" >/dev/null 2>&1; done
    if [ "$WIN" = 1 ]; then
        [ -n "$old" ] && for g in /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor; do echo "$old" > "$g"; done
        [ -n "$oldpp" ] && "$PP" set "$oldpp"
    fi
    if [ -n "${DS:-}" ]; then
        kill "$DS" 2>/dev/null
        echo "device $DEV: $(grep -c '^devstall' "$D/devstall.txt") pauses or slow flushes (bench/devstall: 200 ms or more" \
             "with requests in flight and none completing, a lower bound, or 200 ms of flushes completed in 0.1 s)"
        cat "$D/devstall.txt"
    fi
    rm -rf "$D"
}
trap cleanup EXIT
trap 'exit 130' INT TERM # a signal ends the run: the EXIT trap cleans up (it once ran on, its directory gone)
if [ "$WIN" = 1 ]; then
    [ -n "$oldpp" ] && "$PP" set performance
    [ -n "$old" ] && for g in /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor; do echo performance > "$g"; done
fi
mkdir -p "$D"
chmod 755 "$D"
DEV=$(lsblk -no PKNAME "$(findmnt -no SOURCE -T "$D")" 2>/dev/null | head -n 1)
[ -n "$DEV" ] || DEV=$(basename "$(findmnt -no SOURCE -T "$D")")
DS=
if [ -x "$(dirname "$W")/devstall" ] && [ -r "/sys/block/$DEV/stat" ]; then
    "$(dirname "$W")/devstall" "$DEV" > "$D/devstall.txt" 2>&1 &
    DS=$!
fi
size() { du -sk "$@" | awk '{s += $1} END {printf "%.1f", s / 1024}'; }
PKG=$(for z in /sys/class/thermal/thermal_zone*; do [ "$(cat "$z/type")" = x86_pkg_temp ] && echo "$z/temp"; done | head -n 1)
heat() { # LABEL
    t=n/a
    [ -n "$PKG" ] && t="$(($(cat "$PKG") / 1000)) C"
    echo "$1: package $t, mean clock $(awk '/^cpu MHz/ {s += $4; n++} END {if (n) printf "%.0f", s / n}' /proc/cpuinfo) MHz"
}
REST=${WHOLE_REST:-60}
rest() {
    sync
    sleep "$REST"
    heat "$1 before (after $REST s idle)"
    echo "$1 before: synced, $(awk '/^Dirty:/ {d = $2} /^Writeback:/ {w = $2} END {printf "dirty %.1f MB, writeback %.1f MB", d / 1024, w / 1024}' /proc/meminfo)"
}
want() { [ -z "${WHOLE_ONLY:-}" ] && return 0; case " $WHOLE_ONLY " in *" $1 "*) return 0 ;; esac; return 1; }

# The durability check (WHOLE_SYNCS=N, instead of the workloads): each engine's setup, then N
# single-row commits, each its own transaction, with strace on every thread of the engine (its
# server's processes, or the driver itself), attached after the setup: the sync calls each commit
# makes. The files it holds open for writing under $D are listed with their open flags first, since
# a log written O_DSYNC or O_SYNC needs no sync call to be durable.
SYNCS=${WHOLE_SYNCS:-}
desc() { # PID...: those processes and every descendant, one per line
    ps -e -o pid=,ppid= | awk -v roots="$*" 'BEGIN { n = split(roots, r, " "); for (i = 1; i <= n; i++) keep[r[i]] = 1 }
        { p[NR] = $1; pp[NR] = $2 }
        END { do { added = 0; for (i = 1; i <= NR; i++) if (!(p[i] in keep) && (pp[i] in keep)) { keep[p[i]] = 1; added = 1 } } while (added)
              for (k in keep) print k }'
}
CDATA= # inside a container, the data directory as its processes see it (their fd links name that path)
fdflags() { # ENGINE PID...: the files of the data they hold open for writing, by directory and open flags
    e=$1
    shift
    for p in "$@"; do
        for fd in /proc/"$p"/fd/*; do
            t=$(readlink "$fd" 2>/dev/null) || continue
            case "$t" in
            "$D"/*) t=${t#"$D"/} ;;
            "${CDATA:-/nowhere}"/*) t=${t#"$CDATA"/} ;;
            *) continue ;;
            esac
            fl=$(awk '/^flags:/ {print $2}' "/proc/$p/fdinfo/${fd##*/}" 2>/dev/null) || continue
            echo "$fl $t"
        done
    done | sort -u | awk -v e="$e" '{ v = 0; for (i = 1; i <= length($1); i++) v = v * 8 + substr($1, i, 1)
        if (v % 4 == 0) next # opened read only
        f = ""
        if (int(v / 1024) % 2) f = f " O_APPEND"
        if (int(v / 4096) % 2) f = f " O_DSYNC"
        if (int(v / 16384) % 2) f = f " O_DIRECT"
        if (int(v / 1048576) % 2) f = f " O_SYNC"
        d = $2
        if (d ~ /\//) sub(/\/[^\/]*$/, "/", d); else d = "./"
        k = d " flags " $1 (f == "" ? " (none of O_DSYNC, O_SYNC, O_DIRECT)" : f)
        n[k]++
        if (!(k in ex)) ex[k] = $2 }
        END { for (k in n) print e " durability open " n[k] " in " k ", e.g. " ex[k] }' | sort
}
drive() { # ENGINE PIDFILE CMD...: the command; with WHOLE_SYNCS, its setup, then the commits under strace
    e=$1 pf=$2
    shift 2
    [ -n "$SYNCS" ] || { "$@"; return; }
    rm -f "$D/go"
    mkfifo "$D/go"
    WHOLE_COMMITS=$SYNCS "$@" < "$D/go" > "$D/out-$e.txt" 2>&1 &
    wp=$!
    exec 7> "$D/go" # the driver's stdin: its go after strace attaches
    i=0
    until grep -q 'ready for' "$D/out-$e.txt"; do
        i=$((i + 1))
        [ "$i" -le 600 ] || { cat "$D/out-$e.txt"; return 1; }
        sleep 0.1
    done
    if [ -n "$pf" ]; then roots=$(head -n 1 "$pf"); else roots=$wp; fi
    procs=$(desc $roots)
    tids=$(echo $procs | tr " " ",") # processes: strace -p attaches every thread of each (a thread named too is attached twice: EPERM)
    fdflags "$e" $procs
    # -v: io_submit's requests in full, since an engine writing through it may flush by a write's flag
    # (RWF_DSYNC) or by a request of its own (IOCB_CMD_FDSYNC) instead of a sync call
    strace -f -qq -v -e trace=fsync,fdatasync,sync_file_range,msync,io_submit,io_uring_enter -o "$D/strace-$e.txt" \
        -p "$tids" 2> "$D/strace-$e.err" &
    sp=$!
    sleep 1
    echo go >&7
    exec 7>&-
    wait "$wp" || { cat "$D/out-$e.txt"; return 1; }
    kill -INT "$sp" 2>/dev/null
    wait "$sp" || true
    awk -v e="$e" -v n="$SYNCS" 'match($0, /^[0-9]+ +[a-z_0-9]+\(/) { s = substr($0, RSTART, RLENGTH); sub(/^[0-9]+ +/, "", s); sub(/\($/, "", s); c[s]++ }
        /io_submit\(/ { s = $0; while (match(s, /IOCB_CMD_[A-Z]+|RWF_[A-Z]+/)) { r[substr(s, RSTART, RLENGTH)]++; s = substr(s, RSTART + RLENGTH) } }
        END { line = ""; for (s in c) line = line sprintf(" %s %d (%.2f a commit)", s, c[s], c[s] / n)
              for (s in r) line = line sprintf(", %s %d (%.2f a commit)", s, r[s], r[s] / n)
              print e " durability " n " single-row commits:" (line == "" ? " no sync call at all" : line) }' "$D/strace-$e.txt"
    # threads strace could not attach to (one tracer per thread: a process another tracer holds)
    for t in $(sed -n 's/.*PTRACE_SEIZE, \([0-9]*\)).*/\1/p' "$D/strace-$e.err"); do
        echo "$e durability not traced: thread $t of $(awk '/^Tgid:/ {print $2}' "/proc/$t/status" 2>/dev/null) ($(cat "/proc/$t/comm" 2>/dev/null)), TracerPid $(awk '/^TracerPid:/ {print $2}' "/proc/$t/status" 2>/dev/null)"
    done
}

# what one durable 4 KiB write costs on this disk: appended, overwritten, into fallocated space
want probe && "$(dirname "$W")/fsync_probe" "$D"

if want imagedb; then
    rest imagedb
    drive imagedb "" "$W" imagedb "$D/imagedb"
    heat "imagedb after"
    echo "imagedb storage size $(size "$D/imagedb") MB"
fi
if want imagedb-noindex; then
    rest imagedb-noindex
    drive imagedb-noindex "" "$W" imagedb "$D/imagedb-noindex" --no-index
    heat "imagedb-noindex after"
    echo "imagedb-noindex storage size $(size "$D/imagedb-noindex") MB"
fi
if want imagedb-durable-ack; then
    rest imagedb-durable-ack
    drive imagedb-durable-ack "" "$W" imagedb "$D/imagedb-strict" --durable-ack
    heat "imagedb-durable-ack after"
    echo "imagedb-durable-ack storage size $(size "$D/imagedb-strict") MB"
fi
if want sqlite; then
    rest sqlite
    drive sqlite "" "$W" sqlite "$D/sqlite.db"
    heat "sqlite after"
    echo "sqlite storage size $(size "$D"/sqlite.db*) MB"
fi

cd / # the postgres user cannot enter the tree
if want postgres; then
    mkdir -p "$D/pg"
    chown postgres "$D/pg"
    # C locale: text compares byte by byte, as in imagedb and SQLite
    su postgres -s /bin/sh -c "$PGBIN/initdb -D $D/pg -A trust -U postgres --locale=C" >/dev/null
    base=$(size "$D/pg")
    start_pg() { su postgres -s /bin/sh -c "$PGBIN/pg_ctl -D $D/pg -o \"-p $PORT -k $D/pg -c listen_addresses=''\" -w start" >/dev/null; }
    start_pg
    rest postgres
    drive postgres "$D/pg/postmaster.pid" "$W" postgres "host=$D/pg port=$PORT user=postgres dbname=postgres" "$D/pg/postmaster.pid"
    heat "postgres after"
    echo "postgres storage size $(awk -v a="$(size "$D/pg")" -v b="$base" 'BEGIN { printf "%.1f", a - b }') MB (beyond a fresh cluster)"
    if [ -z "$SYNCS" ]; then
        t0=$(date +%s.%N)
        su postgres -s /bin/sh -c "$PGBIN/pg_ctl -D $D/pg -m fast -w stop" >/dev/null
        start_pg
        "$PGBIN/psql" -h "$D/pg" -p "$PORT" -U postgres -d postgres -Atc "SELECT amount FROM t WHERE id = 1" >/dev/null
        t1=$(date +%s.%N)
        echo "postgres server_restart seconds $(awk -v a="$t0" -v b="$t1" 'BEGIN { printf "%.3f", b - a }') s"
    fi
fi
[ "$EXT" = 1 ] || exit 0

# ---- the extended engines (build/whole-ext) ------------------------------------------------------
ready() { # CONTAINER PATTERN: until its log has a line matching PATTERN (300 s at most)
    i=0
    until docker logs "$1" 2>&1 | grep -q -E "$2"; do
        i=$((i + 1))
        [ "$i" -le 600 ] || { echo "whole.sh: $1: no '$2' in its log"; docker logs --tail 20 "$1" 2>&1; return 1; }
        sleep 0.5
    done
}
hostpid() { docker inspect -f '{{.State.Pid}}' "$1" > "$2"; } # CONTAINER FILE
image() { echo "$1 image $(docker image inspect -f '{{index .RepoDigests 0}}' "$2")"; } # ENGINE IMAGE
restart() { # ENGINE CONTAINER PROBE...: a clean stop, a start, and the probe's first success
    e=$1 c=$2
    shift 2
    t0=$(date +%s.%N)
    if [ "$e" = sqlserver ]; then
        # its pid 1 is a launcher script that does not pass SIGTERM on, so docker stop ends in a SIGKILL
        # (a smoke run: 318 s, then crash recovery); T-SQL's SHUTDOWN checkpoints every database first
        "$W" ping sqlserver-shutdown >/dev/null 2>&1 || true
        docker wait "$c" >/dev/null
    else
        docker stop -t 300 "$c" >/dev/null
    fi
    ts=$(date +%s.%N)
    awk -v a="$t0" -v b="$ts" 'BEGIN { exit !(b - a > 290) }' && echo "whole.sh: $e: its stop took the whole timeout (SIGKILL, not clean)"
    docker start "$c" >/dev/null
    i=0
    until "$@" >/dev/null 2>&1; do
        i=$((i + 1))
        [ "$i" -le 6000 ] || { echo "whole.sh: $e: no answer after its restart"; return 1; }
        sleep 0.05
    done
    t1=$(date +%s.%N)
    echo "$e server_restart seconds $(awk -v a="$t0" -v b="$t1" 'BEGIN { printf "%.3f", b - a }') s (container stop, start, first answer)"
}

if want postgres-docker; then # the native instance's settings: trust, the C locale, the socket only
    mkdir -p "$D/pgc/data" "$D/pgc/run"
    chown 999:999 "$D/pgc/data" "$D/pgc/run" # the image's postgres user
    docker run -d --name "$C-pg" --network none -v "$D/pgc/data:/var/lib/postgresql/data" -v "$D/pgc/run:/var/run/postgresql" \
        -e POSTGRES_HOST_AUTH_METHOD=trust -e POSTGRES_INITDB_ARGS=--locale=C postgres:14 -c listen_addresses= >/dev/null
    ready "$C-pg" 'PostgreSQL init process complete' # the init server has stopped: what answers next is the real one
    i=0
    until "$PGBIN/psql" -h "$D/pgc/run" -p 5432 -U postgres -d postgres -Atc "SELECT 1" >/dev/null 2>&1; do
        i=$((i + 1)); [ "$i" -le 6000 ] || { echo "whole.sh: postgres-docker: no answer"; exit 1; }; sleep 0.05
    done
    image postgres-docker postgres:14
    base=$(size "$D/pgc/data")
    hostpid "$C-pg" "$D/pgc.pid"
    rest postgres-docker
    CDATA=/var/lib/postgresql/data drive postgres-docker "$D/pgc.pid" "$W" postgres "host=$D/pgc/run port=5432 user=postgres dbname=postgres" "$D/pgc.pid" postgres-docker
    heat "postgres-docker after"
    echo "postgres-docker storage size $(awk -v a="$(size "$D/pgc/data")" -v b="$base" 'BEGIN { printf "%.1f", a - b }') MB (beyond a fresh cluster)"
    [ -n "$SYNCS" ] || restart postgres-docker "$C-pg" "$PGBIN/psql" -h "$D/pgc/run" -p 5432 -U postgres -d postgres -Atc "SELECT amount FROM t WHERE id = 1"
    docker rm -f "$C-pg" >/dev/null
fi

if want mysql; then # its defaults: binlog on, sync_binlog=1, innodb_flush_log_at_trx_commit=1 (printed by the driver)
    mkdir -p "$D/my/data" "$D/my/run"
    chown 999:999 "$D/my/data" "$D/my/run" # the image's mysql user
    docker run -d --name "$C-mysql" --network none -v "$D/my/data:/var/lib/mysql" -v "$D/my/run:/var/run/mysqld" \
        -e MYSQL_ALLOW_EMPTY_PASSWORD=yes -e MYSQL_DATABASE=bench mysql:8.4 >/dev/null
    ready "$C-mysql" "socket: .*port: 3306 " # the final server: the init one listens on port 0
    image mysql mysql:8.4
    base=$(size "$D/my/data")
    hostpid "$C-mysql" "$D/my.pid"
    rest mysql
    CDATA=/var/lib/mysql drive mysql "$D/my.pid" "$W" mysql "$D/my/run/mysqld.sock" root "" "$D/my.pid"
    heat "mysql after"
    echo "mysql storage size $(awk -v a="$(size "$D/my/data")" -v b="$base" 'BEGIN { printf "%.1f", a - b }') MB (beyond a fresh instance)"
    [ -n "$SYNCS" ] || restart mysql "$C-mysql" "$W" ping mysql "$D/my/run/mysqld.sock" root ""
    docker rm -f "$C-mysql" >/dev/null
fi

if want mariadb; then # its defaults: no binlog, innodb_flush_log_at_trx_commit=1
    mkdir -p "$D/ma/data" "$D/ma/run"
    chown 999:999 "$D/ma/data" "$D/ma/run"
    docker run -d --name "$C-mariadb" --network none -v "$D/ma/data:/var/lib/mysql" -v "$D/ma/run:/run/mysqld" \
        -e MARIADB_ALLOW_EMPTY_ROOT_PASSWORD=1 -e MARIADB_DATABASE=bench -e MARIADB_USER=bench -e MARIADB_PASSWORD=bench \
        mariadb:lts >/dev/null
    ready "$C-mariadb" "socket: .*port: 3306 " # on the line after its "ready for connections."
    image mariadb mariadb:lts
    base=$(size "$D/ma/data")
    hostpid "$C-mariadb" "$D/ma.pid"
    rest mariadb
    CDATA=/var/lib/mysql drive mariadb "$D/ma.pid" "$W" mariadb "$D/ma/run/mysqld.sock" bench bench "$D/ma.pid"
    heat "mariadb after"
    echo "mariadb storage size $(awk -v a="$(size "$D/ma/data")" -v b="$base" 'BEGIN { printf "%.1f", a - b }') MB (beyond a fresh instance)"
    [ -n "$SYNCS" ] || restart mariadb "$C-mariadb" "$W" ping mariadb "$D/ma/run/mysqld.sock" bench bench
    docker rm -f "$C-mariadb" >/dev/null
fi

if want sqlserver; then # the Developer edition (the user accepted its licence, 2026-10-26); memory capped at 2 GB for the machine
    mkdir -p "$D/ms"
    chown 10001:10001 "$D/ms" # the image's mssql user
    SA="W$(od -An -N12 -tx1 /dev/urandom | tr -d ' \n')a1!" # upper, lower, digits, a symbol: its password rule
    (umask 077 && printf '%s\n' ACCEPT_EULA=Y MSSQL_PID=Developer "MSSQL_SA_PASSWORD=$SA" MSSQL_TCP_PORT=14330 \
        MSSQL_IP_ADDRESS=127.0.0.1 MSSQL_MEMORY_LIMIT_MB=2048 > "$D/ms.env")
    docker run -d --name "$C-mssql" --network host --env-file "$D/ms.env" -v "$D/ms:/var/opt/mssql" \
        mcr.microsoft.com/mssql/server:2025-CU9-ubuntu-22.04 >/dev/null
    ready "$C-mssql" 'SQL Server is now ready for client connections'
    WHOLE_ODBC="Driver={ODBC Driver 18 for SQL Server};Server=tcp:127.0.0.1,14330;UID=sa;PWD=$SA;Encrypt=no"
    export WHOLE_ODBC # the password stays out of every command line
    i=0
    until "$W" ping sqlserver-up >/dev/null 2>&1; do # the log line can come before logins work
        i=$((i + 1)); [ "$i" -le 6000 ] || { echo "whole.sh: sqlserver: no answer"; exit 1; }; sleep 0.05
    done
    image sqlserver mcr.microsoft.com/mssql/server:2025-CU9-ubuntu-22.04
    base=$(size "$D/ms")
    hostpid "$C-mssql" "$D/ms.pid"
    rest sqlserver
    CDATA=/var/opt/mssql drive sqlserver "$D/ms.pid" "$W" sqlserver "$D/ms.pid"
    heat "sqlserver after"
    echo "sqlserver storage size $(awk -v a="$(size "$D/ms")" -v b="$base" 'BEGIN { printf "%.1f", a - b }') MB (beyond a fresh instance)"
    [ -n "$SYNCS" ] || restart sqlserver "$C-mssql" "$W" ping sqlserver
    docker rm -f "$C-mssql" >/dev/null
fi

if want duckdb; then
    rest duckdb
    drive duckdb "" "$W" duckdb "$D/duck.db"
    heat "duckdb after"
    echo "duckdb storage size $(size "$D"/duck.db*) MB"
fi
