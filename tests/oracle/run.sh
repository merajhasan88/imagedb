#!/bin/bash
# The SQL oracle against every reference engine (P0, docs/plan-p0.md 1a): PostgreSQL, MySQL, MariaDB and SQL Server
# started in private containers (no network, but SQL Server's loopback port; their data under
# $IMDB_TEST_TMP/oracle-PID), build/oracle run with all six engines, the containers removed at exit, nothing else of
# docker's touched. Root (docker); the images present: postgres:14, mysql:8.4, mariadb:lts and the SQL Server image
# bench/whole.sh uses (the user accepted its licence, 2026-10-26). What the engines answer stays in this run's output,
# on this machine (SQL Server's licence: no result of it is published).
#   bash tests/oracle/run.sh build/oracle [the oracle's arguments, e.g. --seeds 1-200 --keep-going]
set -euo pipefail
O=$(readlink -f "${1:?usage: run.sh build/oracle [oracle arguments]}")
shift
T=$(readlink -f "${IMDB_TEST_TMP:-build/tmp}")
D=$T/oracle-$$
C=imdb-oracle-$$
mkdir -p "$D"
cleanup() {
    for x in pg mysql mariadb mssql; do docker rm -f "$C-$x" >/dev/null 2>&1 || true; done
    rm -rf "$D"
}
trap cleanup EXIT
avail=$(awk '/MemAvailable/ { print int($2 / 1024) }' /proc/meminfo)
[ "$avail" -ge 4096 ] || { echo "run.sh: MemAvailable ${avail} MB, under 4096: four servers would crowd the machine"; exit 1; }

# PostgreSQL 14: trust on its socket only, the C locale and UTF-8
mkdir -p "$D/pg/data" "$D/pg/run"
chown 999:999 "$D/pg/data" "$D/pg/run"
docker run -d --name "$C-pg" --network none -v "$D/pg/data:/var/lib/postgresql/data" -v "$D/pg/run:/var/run/postgresql" \
    -e POSTGRES_HOST_AUTH_METHOD=trust -e "POSTGRES_INITDB_ARGS=--locale=C --encoding=UTF8" postgres:14 \
    -c listen_addresses= >/dev/null
# MySQL 8.4: root without a password on its socket, database oracle
mkdir -p "$D/my/data" "$D/my/run"
chown 999:999 "$D/my/data" "$D/my/run"
docker run -d --name "$C-mysql" --network none -v "$D/my/data:/var/lib/mysql" -v "$D/my/run:/var/run/mysqld" \
    -e MYSQL_ALLOW_EMPTY_PASSWORD=yes -e MYSQL_DATABASE=oracle mysql:8.4 >/dev/null
# MariaDB (lts): user oracle on its socket, database oracle
mkdir -p "$D/ma/data" "$D/ma/run"
chown 999:999 "$D/ma/data" "$D/ma/run"
docker run -d --name "$C-mariadb" --network none -v "$D/ma/data:/var/lib/mysql" -v "$D/ma/run:/run/mysqld" \
    -e MARIADB_ALLOW_EMPTY_ROOT_PASSWORD=1 -e MARIADB_DATABASE=oracle -e MARIADB_USER=oracle -e MARIADB_PASSWORD=oracle \
    mariadb:lts >/dev/null
# SQL Server Developer: loopback TCP 14331 (host networking: it has no socket), memory capped at 2 GB; its password in
# a file and the environment, never on a command line
mkdir -p "$D/ms"
chown 10001:10001 "$D/ms"
SA="W$(od -An -N12 -tx1 /dev/urandom | tr -d ' \n')a1!"
(umask 077 && printf '%s\n' ACCEPT_EULA=Y MSSQL_PID=Developer "MSSQL_SA_PASSWORD=$SA" MSSQL_TCP_PORT=14331 \
    MSSQL_IP_ADDRESS=127.0.0.1 MSSQL_MEMORY_LIMIT_MB=2048 > "$D/ms.env")
docker run -d --name "$C-mssql" --network host --env-file "$D/ms.env" -v "$D/ms:/var/opt/mssql" \
    mcr.microsoft.com/mssql/server:2025-CU9-ubuntu-22.04 >/dev/null

export ORACLE_PG="host=$D/pg/run port=5432 user=postgres dbname=postgres"
export ORACLE_MYSQL="$D/my/run/mysqld.sock root - oracle"
export ORACLE_MARIADB="$D/ma/run/mysqld.sock oracle oracle oracle"
export ORACLE_ODBC="Driver={ODBC Driver 18 for SQL Server};Server=tcp:127.0.0.1,14331;UID=sa;PWD=$SA;Encrypt=no"
export LANG=C.UTF-8
# every server up when the oracle connects to all four (the init servers come and go first)
i=0
until "$O" --engines pg,mysql,mariadb,mssql --ping >/dev/null 2>&1; do
    i=$((i + 1))
    if [ "$i" -gt 240 ]; then
        echo "run.sh: the servers did not all answer within 120 s:"
        "$O" --engines pg,mysql,mariadb,mssql --ping || true
        exit 1
    fi
    sleep 0.5
done
echo "run.sh: four servers up after ~$((i / 2)) s; MemAvailable $(awk '/MemAvailable/ { print int($2 / 1024) }' /proc/meminfo) MB"
"$O" --engines imagedb,sqlite,pg,mysql,mariadb,mssql --dir "$D/run" "$@"
