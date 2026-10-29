#!/bin/sh
# Makes the format's fixtures (2026-10-29: META 5, manifest version 4, op 16; alg1-20261029.tar.gz and
# alg2-20261029.tar.gz beside this script): a primary and its replica under digest algorithm ALG, by
# make_alg2.sh's steps, which reach every reader of the format: a log of several segments (each manifest
# publish ends one), CHECKPOINTs (manifests, segments, the lanes), a two-column index and a unique one,
# an UPDATE and a DELETE, ERASE SUBJECT (redacted log payloads, rewritten segments), commits after it, and
# a replica by ship | apply. Both tables are RETENTION FOREVER: a fixture is frozen data, so its history
# never expires under the tests that open it (the 24-hour default is tested by the unit tests). Every
# statement runs cross-checked; the engine and the auditor verify both directories, and the replica's
# digest must equal the primary's. The primary's signing key is in the tarball: it signs nothing but
# this fixture. The old fixtures (alg1-20261026, alg2-20261026, tagged-20261027) stay as directories
# this format refuses.
#   sh tests/fixtures/make_fixtures.sh BIN AUDIT ALG OUTDIR   (OUTDIR must not exist)
#   tar -czf tests/fixtures/algALG-20261029.tar.gz -C OUTDIR primary replica
set -eu
BIN=$1
AUD=$2
ALG=$3
OUT=$4
P=$OUT/primary
R=$OUT/replica
mkdir "$OUT"
"$BIN" init "$P" --digest-alg "$ALG" > /dev/null
"$BIN" init-replica "$R" "$P" > /dev/null
sql() { "$BIN" sql "$P" --cross-check -c "$1" > /dev/null; }
ship() { "$BIN" ship "$P" --after "$("$BIN" info "$R" | awk '/^commit/ {print $2}')" | "$BIN" apply "$R" > /dev/null; }
sql "CREATE TABLE acct (id INT64 PRIMARY KEY, owner INT64 SUBJECT, balance DECIMAL(12,2), name TEXT, opened TIMESTAMP) RETENTION FOREVER"
sql "CREATE TABLE ev (id INT64 PRIMARY KEY, acct INT64, kind INT64 NOT NULL, note TEXT NULL) RETENTION FOREVER"
v=""
i=1
while [ $i -le 200 ]; do # owner = id mod 20; balance id.25; a unique name
    v="$v${v:+, }($i, $((i % 20)), $i.25, 'acct-$i', '2026-10-$(printf %02d $((i % 28 + 1))) 09:00:00')"
    i=$((i + 1))
done
sql "INSERT INTO acct VALUES $v"
v=""
i=1
while [ $i -le 400 ]; do # acct = id mod 200 + 1; a quarter of the notes NULL
    if [ $((i % 4)) = 0 ]; then n=NULL; else n="'note-$i'"; fi
    v="$v${v:+, }($i, $((i % 200 + 1)), $((i % 7)), $n)"
    i=$((i + 1))
done
sql "INSERT INTO ev VALUES $v"
sql "CREATE INDEX ev_ak ON ev (acct, kind)"
sql "CREATE UNIQUE INDEX acct_name ON acct (name)"
sql "CHECKPOINT"
ship
sql "UPDATE acct SET balance = 1.00 WHERE id <= 10"
sql "DELETE FROM ev WHERE id BETWEEN 1 AND 5"
sql "ERASE SUBJECT 7"
sql "INSERT INTO ev VALUES (1001, 3, 2, 'after the erase'), (1002, 4, 6, NULL)"
sql "CHECKPOINT"
sql "INSERT INTO acct VALUES (201, 3, 9.99, 'acct-201', '2026-10-26 06:00:00')"
ship
for f in "$P"/log/*.ilg "$R"/log/*.ilg; do
    [ "$(head -c 4 "$f")" = ILT1 ] || { echo "make_fixtures: $f is not a tagged segment" >&2; exit 1; }
done
"$BIN" verify "$P" > /dev/null
"$BIN" verify "$R" > /dev/null
"$AUD" verify "$P" > /dev/null
"$AUD" verify "$R" > /dev/null
dp=$("$BIN" info "$P" | grep '^digest')
dr=$("$BIN" info "$R" | grep '^digest')
[ "$dp" = "$dr" ] || { echo "make_fixtures: the replica's digest differs: $dp / $dr" >&2; exit 1; }
head -1 "$P/META"
"$BIN" info "$P"
