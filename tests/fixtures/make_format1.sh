#!/bin/sh
# Makes format 1's fixtures (docs/format-1.md §5; the freeze's slice 4, 2026-11-15): three sets, each copy verified by
# the engine and by the auditor, each pair at one digest. Together they hold every op (1-4, 10-37), every ALTER and
# DEFAULT kind, op 12's three lists, both WRITER_KEY forms, both body kinds and every type tag (t_format1's census):
#  main/     make_fixtures.sh's primary and replica, then what it lacks: a table of BOOL and FLOAT64 columns with
#            LOCALTIMESTAMP and LOCALTIME DEFAULTs, an index made and dropped, SET and DROP NOT NULL, DROP DEFAULT,
#            RENAME TO, COMPACT and COMPACT ... PURGE BEFORE, a rotated writer key (WRITERS), commits under an anchor
#            (anchor), a full and an incremental backup under a backup key with a catalogue (backup.key, full.bak,
#            incr.bak, catalogue) and a restore of the full one accepting the erasure after it (restored/: ERASE_DEBT)
#  cut/      a primary whose log RETIRE cut (a retention of one second: EXPIRE, then RETIRE at the first keeper of the
#            stride past commit 4,096: FLOOR), then its retention FOREVER, so that nothing expires at a later open; its
#            replica, which cut its own; the stream a new replica takes (seed.stream: the seed, then the commits after
#            it) and that replica (seeded)
#  promote/  a primary with a root key (root.key) and its replica, the old writer's last commit past the cut, the
#            replica promoted over it under the anchor (a root certificate in a body of kind 3; the ledger
#            root.key.ledger), the promoted writer's commits, the old writer rewound onto them and demoted to its
#            replica (rewind.save: the commit it gave up)
# Commit times are the clock's as it ran; every table is kept FOREVER at the end and no backup has an expiry, so a
# test opening a copy later finds nothing due.
#   sh tests/fixtures/make_format1.sh BIN AUDIT OUTDIR   (OUTDIR must not exist)
#   tar -czf tests/fixtures/format1-20261115.tar.gz -C OUTDIR main cut promote
set -eu
BIN=$1
AUD=$2
OUT=$3
mkdir "$OUT"
sh "$(dirname "$0")/make_fixtures.sh" "$BIN" "$AUD" "$OUT/main" > /dev/null
sql() { "$BIN" sql "$1" --cross-check -c "$2" > /dev/null; }
ship() { "$BIN" ship "$1" --after "$("$BIN" info "$2" | awk '/^commit/ {print $2}')" | "$BIN" apply "$2" > /dev/null; }
die() { echo "make_format1: $*" >&2; exit 1; }

# main: what make_fixtures.sh's steps lack
M=$OUT/main
P=$M/primary
R=$M/replica
sql "$P" "CREATE TABLE bf (id INT64 PRIMARY KEY, b BOOL, f FLOAT64, g FLOAT64 NULL, lt TIMESTAMP DEFAULT LOCALTIMESTAMP, lc TIME DEFAULT LOCALTIME) RETENTION FOREVER"
sql "$P" "INSERT INTO bf (id, b, f, g) VALUES (1, TRUE, 0.0, NULL), (2, FALSE, -0.0, 1.5e308), (3, NULL, 2.5e-308, -4.9e-324), (4, TRUE, 3.141592653589793, -1.0)"
sql "$P" "CREATE INDEX bf_f ON bf (f)"
sql "$P" "DROP INDEX bf_f"
sql "$P" "ALTER TABLE bf ALTER COLUMN f SET NOT NULL"
sql "$P" "ALTER TABLE bf ALTER COLUMN f DROP NOT NULL"
sql "$P" "ALTER TABLE bf ALTER COLUMN lt DROP DEFAULT"
sql "$P" "ALTER TABLE bf RENAME TO bools"
sql "$P" "INSERT INTO bools (id, b, f) VALUES (5, FALSE, 1e-300)"
sql "$P" "COMPACT acct"
purge=$("$BIN" info "$P" | awk '/^commit/ {print $2 - 20}')
sql "$P" "COMPACT ev PURGE BEFORE $purge"
ship "$P" "$R"
"$BIN" rotate-key "$P" > /dev/null
sql "$P" "INSERT INTO bools (id, b, f) VALUES (6, TRUE, 2.0)" # under the rotated key
"$BIN" sql "$P" --anchor "$M/anchor" -c "INSERT INTO bools (id, b, f) VALUES (7, FALSE, 3.0)" > /dev/null
ship "$P" "$R"
"$BIN" backup-key "$M/backup.key" > /dev/null
"$BIN" backup "$P" --key "$M/backup.key" --out "$M/full.bak" --catalogue "$M/catalogue" > /dev/null
sql "$P" "ERASE SUBJECT 8"
sql "$P" "INSERT INTO bools (id, b, f) VALUES (8, TRUE, 4.0)"
"$BIN" backup "$P" --key "$M/backup.key" --out "$M/incr.bak" --after "$M/full.bak" --catalogue "$M/catalogue" > /dev/null
ship "$P" "$R"
"$BIN" restore "$M/restored" --key "$M/backup.key" --catalogue "$M/catalogue" --accept-erased "$M/full.bak" > /dev/null
[ -f "$M/restored/ERASE_DEBT" ] || die "the restore of the full backup left no ERASE_DEBT"
[ -f "$P/WRITERS" ] || die "no WRITERS after rotate-key"

# cut: EXPIRE and RETIRE, a seed
C=$OUT/cut
mkdir "$C"
CP=$C/primary
CR=$C/replica
"$BIN" init "$CP" > /dev/null
"$BIN" init-replica "$CR" "$CP" > /dev/null
sql "$CP" "CREATE TABLE k (id INT64 PRIMARY KEY, v INT64, s TEXT) RETENTION 1 SECONDS"
v=""
i=1
while [ $i -le 10 ]; do
    v="$v${v:+, }($i, $i, 'k$i')"
    i=$((i + 1))
done
sql "$CP" "INSERT INTO k VALUES $v"
f=$C/updates.sql
: > "$f"
i=1
while [ $i -le 4200 ]; do # a commit each; a CHECKPOINT every 600 ends a segment, one of them past commit 4,096
    echo "UPDATE k SET v = v + 1 WHERE id = $((i % 10 + 1));" >> "$f"
    [ $((i % 600)) -eq 0 ] && echo "CHECKPOINT;" >> "$f"
    i=$((i + 1))
done
"$BIN" sql "$CP" -f "$f" > /dev/null
rm "$f"
ship "$CP" "$CR"
sleep 2
sql "$CP" "INSERT INTO k VALUES (11, 11, 'k11')" # after it the policy: every version ended more than a second ago expires,
sql "$CP" "INSERT INTO k VALUES (12, 12, 'k12')" # (expiry moves the horizon to a segment's start once the segment
sleep 2                                         # after it began more than the retention ago: 4,210's, then)
sql "$CP" "INSERT INTO k VALUES (14, 14, 'k14')" # then RETIRE at the keeper below the horizon
[ -f "$CP/FLOOR" ] || die "the cut set's primary has no FLOOR: no RETIRE"
sql "$CP" "ALTER TABLE k SET RETENTION FOREVER"
ship "$CP" "$CR"
[ -f "$CR/FLOOR" ] || die "the cut set's replica has no FLOOR"
"$BIN" init-replica "$C/seeded" "$CP" > /dev/null
"$BIN" ship "$CP" --after 0 > "$C/seed.stream"
"$BIN" apply "$C/seeded" < "$C/seed.stream" > /dev/null
[ "$(head -c 8 "$C/seed.stream" | od -An -c | tr -d ' \n')" != "" ] || die "an empty seed stream"
sql "$CP" "INSERT INTO k VALUES (13, 13, 'k13')"
ship "$CP" "$CR"
ship "$CP" "$C/seeded"

# promote: a root key, a promotion over the old writer's last commit, the old writer rewound and demoted
Q=$OUT/promote
mkdir "$Q"
rk=$("$BIN" root-key "$Q/root.key" | tr -d '\n')
QP=$Q/old
QR=$Q/writer
"$BIN" init "$QP" --root "$rk" > /dev/null
"$BIN" init-replica "$QR" "$QP" > /dev/null
sql "$QP" "CREATE TABLE p (id INT64 PRIMARY KEY, n TEXT) RETENTION FOREVER"
"$BIN" sql "$QP" --anchor "$Q/anchor" -c "INSERT INTO p VALUES (1, 'one'), (2, 'two')" > /dev/null
ship "$QP" "$QR"
"$BIN" sql "$QP" --anchor "$Q/anchor" -c "INSERT INTO p VALUES (3, 'lost')" > /dev/null # never shipped
"$BIN" promote "$QR" --root-key "$Q/root.key" --anchor "$Q/anchor" --abandon > /dev/null
[ -f "$Q/root.key.ledger" ] || die "the promotion left no ledger"
sql "$QR" "INSERT INTO p VALUES (3, 'three'), (4, 'four')"
sql "$QR" "CHECKPOINT"                          # the promoted writer's publication
"$BIN" rewind "$QP" --save "$Q/rewind.save" --demote -- "$BIN" ship "$QR" --hashes --after '{after}' > /dev/null
ship "$QR" "$QP"

# every copy verified twice; each pair at one digest
for d in "$P" "$R" "$M/restored" "$CP" "$CR" "$C/seeded" "$QP" "$QR"; do
    "$BIN" verify "$d" > /dev/null || die "VERIFY refused $d"
    "$AUD" verify "$d" > /dev/null || die "the auditor refused $d"
done
digest() { "$BIN" info "$1" | awk '/^digest/ {print $2}'; }
[ "$(digest "$P")" = "$(digest "$R")" ] || die "main: the replica's digest differs"
[ "$(digest "$CP")" = "$(digest "$CR")" ] && [ "$(digest "$CP")" = "$(digest "$C/seeded")" ] || die "cut: a digest differs"
[ "$(digest "$QR")" = "$(digest "$QP")" ] || die "promote: the old writer's digest differs from the promoted one's"
for d in "$P" "$CP" "$QR"; do "$BIN" info "$d" | grep '^commit\|^writer\|^lake'; done
