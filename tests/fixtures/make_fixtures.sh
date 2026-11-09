#!/bin/sh
# Makes the format's fixtures (2026-11-09: META 5, log version 3, manifest version 8 and segment format 3 (F1 stage 4:
# a segment names its schema version by its hash with positions), ops 16, 19, 20, 21 and 22's kinds; alg1-20261109.tar.gz
# and alg2-20261109.tar.gz beside this script): a primary and its replica under digest algorithm ALG, by
# make_alg2.sh's steps, which reach every reader of the format: a log of several segments (each manifest
# publish ends one), CHECKPOINTs (manifests, segments, the lanes), a two-column index and a unique one,
# an UPDATE and a DELETE, ERASE SUBJECT (redacted log payloads, rewritten segments), commits after it, and
# a replica by ship | apply, a table dropped (op 19; the manifest's tombstone), and views (P2 S7: op 20, one on
# another, one dropped by op 21, the manifest's tombstone; one more after the first CHECKPOINT, which the replica
# applies from the log), (F4) a table whose key is two columns, not in their order, and (F1) that table altered after
# the first CHECKPOINT (op 22: an ADD with a TEXT DEFAULT, a NOT NULL one with its DEFAULT, a rename, an INSERT that
# leaves the added columns out: the manifest's schema history, a segment of version 1 under version 4; stage 4: a DROP
# COLUMN, a SET DEFAULT and a row after them, so the next CHECKPOINT cuts a segment of each side of the drop), (P2) a
# TIMESTAMPTZ (tag 7: rows of a gap's and an overlap's literals, offsets, a NULL, one updated from the log) with a view of
# date_trunc and AT TIME ZONE in its text, and (F3a) SMALLINT, INTEGER and BIGINT columns at their ranges' ends, one
# widened by SET TYPE after the first CHECKPOINT. The live
# tables are RETENTION FOREVER and the dropped one is kept a century, the longest but FOREVER: a fixture is frozen
# data, so its history
# never expires under the tests that open it (the 24-hour default is tested by the unit tests). Every
# statement runs cross-checked; the engine and the auditor verify both directories, and the replica's
# digest must equal the primary's. The primary's signing key is in the tarball: it signs nothing but
# this fixture. The old fixtures (alg1-20261026, alg2-20261026, tagged-20261027; alg1-20261029 and alg2-20261029,
# manifest version 4; alg1-20261104 and alg2-20261104, manifest version 5; alg1-20261106 and alg2-20261106, manifest
# version 6 and log version 2; alg1-20261108 and alg2-20261108, manifest version 7 and segment format 2) stay as
# directories this format refuses.
#   sh tests/fixtures/make_fixtures.sh BIN AUDIT ALG OUTDIR   (OUTDIR must not exist)
#   tar -czf tests/fixtures/algALG-20261109.tar.gz -C OUTDIR primary replica
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
sql "CREATE TABLE gone (id INT64 PRIMARY KEY, v INT64) RETENTION FOREVER"
sql "INSERT INTO gone VALUES (1, 10), (2, 20)"
sql "DROP TABLE gone RETENTION 36500 DAYS" # a FOREVER table is given a retention at its drop
sql "CREATE VIEW rich (id, bal) AS SELECT id, balance FROM acct WHERE balance > 100.00" # P2 S7: a column list
sql "CREATE VIEW per_acct AS SELECT acct, COUNT(*) AS n FROM ev GROUP BY acct"
sql "CREATE VIEW top AS SELECT id FROM rich WHERE bal > 150.00" # a view on a view
sql "CREATE VIEW kind3 AS SELECT id, note FROM ev WHERE kind = 3"
sql "DROP VIEW kind3" # a tombstone in the manifest
sql "CREATE TABLE pair (b TEXT, a INT64, v INT64, PRIMARY KEY (a, b)) RETENTION FOREVER" # F4: a key of two columns, not in
sql "INSERT INTO pair VALUES ('x', 1, 10), ('y', 1, 11), ('x', 2, 12), ('', -3, NULL)"    # the columns' order
sql "CREATE TABLE stamp (id INT64 PRIMARY KEY, at TIMESTAMPTZ, local TIMESTAMP) RETENTION FOREVER" # P2: an instant
sql "INSERT INTO stamp VALUES (1, '2026-03-29 01:30:00 Europe/London', '2026-03-29 01:30:00'), (2, '2026-10-25 01:30:00+01:00', NULL), (3, NULL, '2026-01-01 00:00:00'), (4, '1999-12-31 23:59:59.999999-05', '1999-12-31 23:59:59.999999')"
sql "CREATE VIEW stamp_day AS SELECT id, date_trunc('day', at, 'Asia/Kathmandu') AS d, at AT TIME ZONE 'America/St_Johns' AS sj FROM stamp" # zones in a view's text
sql "CREATE TABLE widths (id INTEGER PRIMARY KEY, s SMALLINT, i INTEGER, b BIGINT) RETENTION FOREVER" # F3a: the widths
sql "INSERT INTO widths VALUES (1, 32767, 2147483647, 9223372036854775807), (2, -32768, -2147483648, NULL), (3, NULL, 0, 1)"
sql "CHECKPOINT"
ship
sql "ALTER TABLE pair ADD w TEXT DEFAULT 'w0'"          # F1: op 22; pair's rows so far are in a segment of version 1
sql "ALTER TABLE pair ADD n INT64 NOT NULL DEFAULT 7"
sql "ALTER TABLE pair RENAME COLUMN v TO val"
sql "INSERT INTO pair (b, a, val) VALUES ('z', 9, 99)"   # w and n their DEFAULTs
sql "ALTER TABLE pair DROP COLUMN w"                     # F1 stage 4: a dropped position, its bytes kept in the rows
sql "ALTER TABLE pair ALTER COLUMN n SET DEFAULT 8"      # the write default parted from what older rows read (7)
sql "INSERT INTO pair (b, a, val) VALUES ('q', 4, 44)"   # n 8: the next CHECKPOINT cuts a segment of each version
sql "ALTER TABLE widths ALTER COLUMN s TYPE INTEGER"    # F3a: a widening, SET TYPE (op 22 kind 9); the first rows in a segment
sql "INSERT INTO widths VALUES (4, 40000, -1, -9223372036854775808)"  # of the SMALLINT version
sql "UPDATE stamp SET at = TIMESTAMPTZ '2030-01-01 12:00:00+05:45' WHERE id = 3" # P2: an instant from the log
sql "UPDATE acct SET balance = 1.00 WHERE id <= 10"
sql "DELETE FROM ev WHERE id BETWEEN 1 AND 5"
sql "ERASE SUBJECT 7"
sql "CREATE VIEW noted AS SELECT e.id, a.name FROM ev AS e JOIN acct AS a ON e.acct = a.id WHERE e.note IS NOT NULL"
sql "INSERT INTO ev VALUES (1001, 3, 2, 'after the erase'), (1002, 4, 6, NULL)"
sql "CHECKPOINT"
sql "INSERT INTO acct VALUES (201, 3, 9.99, 'acct-201', '2026-10-26 06:00:00')"
sql "UPDATE pair SET val = 13 WHERE a = 2 AND b = 'x'"; sql "DELETE FROM pair WHERE a = 1 AND b = 'y'" # by the key, from the log
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
