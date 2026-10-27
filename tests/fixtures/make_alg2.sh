#!/bin/sh
# Makes the digest_alg 2 fixture (alg2-20261026.tar.gz beside this script): a primary and its
# replica written by imagedb once digest_alg 2 was final (its element keyed by the commitment), so
# every later engine and auditor is tested on it. The same steps as make_alg1.sh, which reach every
# reader of the format: a log of
# several segments (each manifest publish ends one), CHECKPOINTs (manifests, segments, the lanes),
# a two-column index and a unique one (manifest version 3), an UPDATE and a DELETE, ERASE SUBJECT
# (redacted log payloads, rewritten segments), commits after it, and a replica by ship | apply.
# Every statement runs cross-checked; the engine and the auditor verify both directories, and the
# replica's digest must equal the primary's. The primary's signing key is in the tarball: it signs
# nothing but this fixture.
# The init names --digest-alg 2, so the fixture does not depend on the default; made by the binary
# of the redefinition's copy (.work/e3b, 2026-10-26).
#   sh tests/fixtures/make_alg2.sh BIN AUDIT OUTDIR   (OUTDIR must not exist)
set -eu
BIN=$1
AUD=$2
OUT=$3
P=$OUT/primary
R=$OUT/replica
mkdir "$OUT"
"$BIN" init "$P" --digest-alg 2 > /dev/null
"$BIN" init-replica "$R" "$P" > /dev/null
sql() { "$BIN" sql "$P" --cross-check -c "$1" > /dev/null; }
ship() { "$BIN" ship "$P" --after "$("$BIN" info "$R" | awk '/^commit/ {print $2}')" | "$BIN" apply "$R" > /dev/null; }
sql "CREATE TABLE acct (id INT64 PRIMARY KEY, owner INT64 SUBJECT, balance DECIMAL(12,2), name TEXT, opened TIMESTAMP)"
sql "CREATE TABLE ev (id INT64 PRIMARY KEY, acct INT64, kind INT64 NOT NULL, note TEXT NULL)"
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
"$BIN" verify "$P" > /dev/null
"$BIN" verify "$R" > /dev/null
"$AUD" verify "$P" > /dev/null
"$AUD" verify "$R" > /dev/null
dp=$("$BIN" info "$P" | grep '^digest')
dr=$("$BIN" info "$R" | grep '^digest')
[ "$dp" = "$dr" ] || { echo "make_alg2: the replica's digest differs: $dp / $dr" >&2; exit 1; }
"$BIN" info "$P"
