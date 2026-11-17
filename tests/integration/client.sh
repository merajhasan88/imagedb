#!/usr/bin/env bash
# N1d-2: imagedb-client against imagedb sql (docs/n1-design.md §8d). One corpus run through `imagedb sql` on one copy of a
# database and through `imagedb-client` against `imagedb-server` on another, over the socket and over TCP with TLS (the
# pin): each run's stdout and stderr the same but the access path (not on the wire: taken off the CLI's status and
# row-count lines), its exit code the same, and the two copies' rows and counts equal at the end. What only the binaries show:
# -c, -f, piped stdin, COPY both ways with inline data, errors part way and the exit codes they give, --csv, a session
# zone across New York's spring change, and the line an open transaction leaves at exit. (The rebuilt results
# themselves, every type at its edges: t_conv's conv_render.)
#   tests/integration/client.sh [path/to/imagedb]   (imagedb-server and imagedb-client beside it)
set -euo pipefail

BIN=${1:-build/imagedb}
DIR=$(dirname "$BIN")
SRV=$DIR/imagedb-server
CLI=$DIR/imagedb-client
WORK=$(mktemp -d "${IMDB_TEST_TMP:-/tmp}/imdb-cl.XXXXXX")
[ ${#WORK} -le 100 ] || { echo "FAIL: $WORK is too long for a Unix socket's path (107 bytes): a shorter IMDB_TEST_TMP" >&2; rm -rf "$WORK"; exit 1; }
spid=""
cleanup() {
  if [ -n "$spid" ]; then kill -TERM "$spid" 2>/dev/null || true; wait "$spid" 2>/dev/null || true; fi
  rm -rf "$WORK"
}
trap cleanup EXIT
fail() { echo "FAIL: $*" >&2; exit 1; }
E=$WORK/emb
N=$WORK/net

"$BIN" init "$E" >/dev/null
"$BIN" sql "$E" --nosync -c "CREATE ROLE admin LOGIN SUPERUSER PASSWORD 'pw-client'" >/dev/null
cp -a "$E" "$N"
mkdir -m 700 "$WORK/sd"
pin=$("$SRV" cert "$WORK/sd" | awk '{ print $NF }')
"$SRV" "$N" --socket "$WORK/s" --server-dir "$WORK/sd" --tcp 127.0.0.1:0 --nosync > "$WORK/srv.out" 2>&1 &
spid=$!
port=""
for _ in $(seq 100); do
  port=$(awk '/listening on tcp port/ { print $6 }' "$WORK/srv.out")
  [ -n "$port" ] && break
  sleep 0.1
done
[ -n "$port" ] || fail "the server did not start: $(cat "$WORK/srv.out")"
export IMAGEDB_PASSWORD=pw-client

# the CLI's lines without the access path: "(2 rows)  [scan]  at commit 3", "UPDATE 1  [index t_pk]"
nopath() { sed -E 's/^(\([0-9]+ rows?\))  \[[^]]*\]/\1/; s/^([A-Z][A-Z_ ]*( [0-9]+)*)  \[[^]]*\]$/\1/'; }

n=0
# same NAME TRANSPORT [STDIN-FILE] -- ARGS...: the run through both, compared
same() {
  local name=$1 via=$2 in=$3
  shift 4
  n=$((n + 1))
  local ec=0 nc=0
  "$BIN" sql "$E" --nosync "$@" < "$in" > "$WORK/e.out" 2> "$WORK/e.err" || ec=$?
  if [ "$via" = tcp ]; then
    "$CLI" --host 127.0.0.1 --port "$port" --pin "$pin" --user admin "$@" < "$in" > "$WORK/n.out" 2> "$WORK/n.err" || nc=$?
  else
    "$CLI" --socket "$WORK/s" --user admin "$@" < "$in" > "$WORK/n.out" 2> "$WORK/n.err" || nc=$?
  fi
  nopath < "$WORK/e.out" > "$WORK/e.np"
  [ "$ec" = "$nc" ] || fail "$name: exit $ec embedded, $nc through the server"
  cmp -s "$WORK/e.np" "$WORK/n.out" || fail "$name: stdout differs:
$(diff "$WORK/e.np" "$WORK/n.out" | head -20)"
  cmp -s "$WORK/e.err" "$WORK/n.err" || fail "$name: stderr differs:
$(diff "$WORK/e.err" "$WORK/n.err" | head -20)"
}
none=/dev/null

same "every type, -c" sock $none -- -c "CREATE TYPE mood AS ENUM ('sad', 'ok', 'happy');
CREATE TABLE a (id INT64 PRIMARY KEY, s SMALLINT, n INTEGER, d DECIMAL(10,2), w DECIMAL(38,6), f FLOAT64, b BOOL, t TEXT,
  v VARCHAR(5), ts TIMESTAMP, tz TIMESTAMPTZ, dt DATE, tm TIME, u UUID, bb BYTEA, iv INTERVAL, m mood);
INSERT INTO a VALUES (1, 32767, 2147483647, 99999999.99, 99999999999999999999999999999999.999999, 1.5e0, TRUE, 'hé|x',
  'abcde', TIMESTAMP '0001-01-01 00:00:00', TIMESTAMPTZ '2026-03-08 06:30:00+00', DATE '0001-01-01', TIME '23:59:59.999999',
  UUID 'ffffffff-ffff-ffff-ffff-ffffffffffff', '\\x00ff', INTERVAL '1 day 02:03:04', 'happy');
INSERT INTO a VALUES (2, -32768, -2147483648, -99999999.99, -99999999999999999999999999999999.999999, -2.5e300, FALSE, '',
  '', TIMESTAMP '9999-12-31 23:59:59.999999', TIMESTAMPTZ '2026-03-08 07:30:00+00', DATE '9999-12-31', TIME '00:00:00',
  UUID '00000000-0000-0000-0000-000000000000', '\\x', INTERVAL '-3 months', 'sad');
INSERT INTO a (id) VALUES (3);
SELECT * FROM a ORDER BY id;
SELECT COUNT(*), SUM(d), SUM(w), AVG(d), MIN(t), MAX(m) FROM a;
CREATE TABLE big (id INT64 PRIMARY KEY, x INT64);
INSERT INTO big VALUES (1, 9223372036854775807), (2, 9223372036854775807), (3, 5);
SELECT SUM(x) FROM big;
SELECT id, SUM(x) OVER (ORDER BY id) FROM big;
UPDATE big SET x = x - 1 WHERE id = 3;
DELETE FROM big WHERE id = 2;
SHOW TABLES;
EXPLAIN SELECT * FROM a WHERE id = 1;
SELECT 1/0;
SELECT 'never reached';"
same "the same, --csv" sock $none -- --csv -c "SELECT * FROM a ORDER BY id; SELECT m, COUNT(*) FROM a GROUP BY m"
same "a zone across New York's spring change" sock $none -- -c "SET TIME ZONE 'America/New_York';
SELECT id, tz FROM a ORDER BY id; SHOW TIME ZONE; SET TIME ZONE 'UTC'; SELECT id, tz FROM a ORDER BY id"
printf '%s\n' "CREATE TABLE c (id INT64 PRIMARY KEY, name TEXT, v INT64);" "COPY c FROM STDIN;" '1,one,10' '2,"t,wo",20' \
  '3,"th""ree",30' '\.' "SELECT * FROM c ORDER BY id;" "COPY c TO STDOUT;" "COPY (SELECT id, v FROM c WHERE id > 1) TO STDOUT;" \
  "COPY c FROM STDIN;" '4,four,40' '5,five,notanumber' '\.' "SELECT COUNT(*) FROM c;" > "$WORK/s1.sql"
same "-f: COPY's inline data both ways, an error part way" sock $none -- -f "$WORK/s1.sql"
same "the same over TCP with TLS" tcp $none -- -c "SELECT COUNT(*), SUM(v) FROM c" -c "COPY c TO STDOUT"
printf '6,six,60\n7,seven,70\n' > "$WORK/data"
same "-c COPY with its data on stdin" sock "$WORK/data" -- -c "COPY c FROM STDIN"
printf '%s\n' "SELECT 7;" "COPY c FROM STDIN;" '8,eight,80' '\.' "SELECT id FROM c WHERE id >= 6 ORDER BY id;" > "$WORK/s2.sql"
same "piped stdin" sock "$WORK/s2.sql" --
same "piped stdin over TCP" tcp "$WORK/s2.sql" -- -c "DELETE FROM c WHERE id = 8"
same "an open transaction at exit" sock $none -- -c "BEGIN; INSERT INTO c VALUES (9, 'nine', 90); SELECT COUNT(*) FROM c"
same "errors' words" sock $none -- -c "SELEC 1" -c "INSERT INTO c VALUES (1, 'dup', 1)" -c "SELECT missing FROM c"
same "the copies agree" sock $none -- -c "SELECT COUNT(*), SUM(v) FROM c" -c "SELECT COUNT(*) FROM a"

kill -TERM "$spid"
sc=0
wait "$spid" || sc=$?
spid=""
# the server's own verdict: a clean stop, and (a sanitizer build) no report in what it wrote
[ "$sc" = 0 ] || fail "imagedb-server exited $sc at its stop:
$(cat "$WORK/srv.out")"
! grep -qE "runtime error|AddressSanitizer|LeakSanitizer|ThreadSanitizer" "$WORK/srv.out" || fail "imagedb-server's sanitizer:
$(cat "$WORK/srv.out")"
# the copies agree: each table's rows (COPY TO) and SHOW DIGEST's counts and commit. Not the digests: each row's commitment
# carries a salt drawn by the statement that wrote it, so two copies written apart never share one (a replica does: its
# salts come with the log)
for t in a big c; do
  [ "$("$BIN" sql "$E" -c "COPY $t TO STDOUT" 2>&1)" = "$("$BIN" sql "$N" -c "COPY $t TO STDOUT" 2>&1)" ] ||
    fail "table $t differs between the copies"
done
counts() { "$BIN" sql "$1" -c "SHOW DIGEST" | awk -F'|' 'NR > 2 && NF >= 3 { print $1, $2, $3 }'; }
[ "$(counts "$E")" = "$(counts "$N")" ] || fail "the copies' counts differ:
$(counts "$E")
$(counts "$N")"
echo "client.sh: $n runs alike through imagedb sql and imagedb-client (socket and TCP); the copies' rows equal"
echo "ALL CLIENT CHECKS PASSED"
