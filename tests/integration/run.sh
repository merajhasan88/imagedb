#!/usr/bin/env bash
# imagedb end-to-end: "if a user has 15 transactions in the database, the same
# user has 15 transactions in the data lake" -- and on the replica, after a
# delete, and after an erasure -- checked by the engine, by the independent
# auditor (imagedb-audit) reading only the files, and by grep.
#
#   tests/integration/run.sh [path/to/imagedb]
set -euo pipefail

BIN=${1:-build/imagedb}
AUD=${AUDIT:-$(dirname "$BIN")/imagedb-audit}   # independent C verifier, no code shared with the engine
WORK=$(mktemp -d "${IMDB_TEST_TMP:-/tmp}/imdb-it.XXXXXX")
trap 'rm -rf "$WORK"' EXIT
P=$WORK/primary
R=$WORK/replica
step() { printf '\n== %s\n' "$*"; }
fail() { echo "FAIL: $*" >&2; exit 1; }
expect() { case "$2" in *"$1"*) ;; *) fail "expected '$1' in output:
$2" ;; esac; }
sql() { "$BIN" sql "$P" --nosync --cross-check -c "$1"; }
cell() { awk 'NR==3{gsub(/^ +| +$/,"",$1); split($0,a,"|"); gsub(/ /,"",a[1]); print a[1]; exit}'; }
expect_cell() { got=$(echo "$2" | cell); [ "$got" = "$1" ] || fail "expected first cell '$1', got '$got' in:
$2"; }
rsql() { "$BIN" sql "$R" --nosync --cross-check -c "$1"; }
# flipbyte FILE OFFSET: xor one byte with 0x01 in place
flipbyte() { local b; b=$(od -An -tu1 -j"$2" -N1 "$1" | tr -d " "); printf "$(printf "\\%03o" $(( b ^ 1 )))" | dd of="$1" bs=1 seek="$2" count=1 conv=notrunc 2>/dev/null; }
ship() { "$BIN" ship "$P" --after "$("$BIN" info "$R" | awk '/^commit/{print $2}')" | "$BIN" apply "$R"; }

step "init primary and replica"
"$BIN" init "$P" >/dev/null
"$BIN" init-replica "$R" "$P" >/dev/null

step "schema + 15 transactions for user 42 (and noise for users 7 and 99)"
sql "CREATE TABLE txns (id INT64 PRIMARY KEY, user_id INT64 SUBJECT, amount DECIMAL(12,2), memo TEXT, at TIMESTAMP);" >/dev/null
vals=""
for i in $(seq 1 15); do
  vals="$vals${vals:+, }($i, 42, $i.50, 'card-42-MARKERX-$i', '2026-10-$(printf %02d "$i") 09:00:00')"
done
for i in $(seq 16 40); do
  u=$(( i % 2 == 0 ? 7 : 99 ))
  vals="$vals, ($i, $u, $i.00, 'other-$i', '2026-10-15 12:00:00')"
done
sql "INSERT INTO txns VALUES $vals;" >/dev/null
sql "CHECKPOINT;" >/dev/null

step "count user 42: database (index path cross-checked against the lake scan)"
out=$(sql "SELECT COUNT(*), SUM(amount) FROM txns WHERE user_id = 42;")
echo "$out"
expect_cell 15 "$out"
expect "127.50" "$out"
expect "cross-checked" "$out"

step "count user 42: lake files, read by the independent auditor (no engine code)"
out=$("$AUD" count "$P" txns user_id=42)
echo "$out"
expect "count=15 " "$out"
expect "sum(amount)=127.50" "$out"

step "replicate through a pipe: ship | apply"
ship
out=$("$AUD" count "$R" txns user_id=42)
echo "replica lake: $out"
expect "count=15 " "$out"
out=$(rsql "SELECT COUNT(*) FROM txns WHERE user_id = 42;")
expect_cell 15 "$out"
dp=$("$BIN" info "$P" | grep '^digest'); dr=$("$BIN" info "$R" | grep '^digest')
[ "$dp" = "$dr" ] || fail "digests differ: $dp / $dr"
echo "digest primary = replica: ${dp#digest }"
# the same frames in the same segments; the files' sectors follow each copy's own syncs (design.md §1)
fp=$("$AUD" frames "$P") && fr=$("$AUD" frames "$R") || fail "the auditor cannot read the logs' frames"
[ -n "$fp" ] && [ "$fp" = "$fr" ] || fail "log segments differ (their frames)"
diff -r "$P/objects" "$R/objects" >/dev/null || fail "lake objects differ"
cmp -s "$P/LAKE_HEAD" "$R/LAKE_HEAD" || fail "LAKE_HEAD differs"
echo "every log segment holds the same frames; LAKE_HEAD and every lake object are byte-identical"

step "per-subject digest: engine index vs engine scan vs the auditor over files"
out=$(sql "SHOW DIGEST txns SUBJECT 42;")
echo "$out"
expect "| yes" "$out"
eng=$(echo "$out" | awk -F'|' '/index/{gsub(/ /,"",$4); print $4}')
aud=$("$AUD" digest "$P" txns user_id=42 | sed -E 's/.*digest=([0-9a-f]+).*/\1/')
[ "$eng" = "$aud" ] || fail "subject digest differs: engine $eng auditor $aud"
echo "auditor digest = engine digest: $aud"

step "delete one transaction: 14 everywhere, history still says 15"
before=$("$BIN" info "$P" | awk '/^commit/{print $2}')
sql "DELETE FROM txns WHERE id = 3;" >/dev/null
sql "CHECKPOINT;" >/dev/null
ship
expect_cell 14 "$(sql "SELECT COUNT(*) FROM txns WHERE user_id = 42;")"
expect "count=14 " "$("$AUD" count "$P" txns user_id=42)"
expect "count=14 " "$("$AUD" count "$R" txns user_id=42)"
expect_cell 15 "$(sql "SELECT COUNT(*) FROM txns AS OF $before WHERE user_id = 42;")"
expect "count=15 " "$("$AUD" count "$P" txns user_id=42 --as-of "$before")"
echo "now 14 in db, lake, replica; AS OF $before still 15 (engine and lake files)"

step "the memory window (stage 3b): --mem-window takes seconds or none; history below its floor is read from the lake"
out=$("$BIN" sql "$P" --nosync --mem-window 30 -c "SHOW MEMORY;")
expect "memory window 30 s, floor commit " "$out"
out=$("$BIN" sql "$P" --nosync --mem-window none -c "SHOW MEMORY;")
expect "no memory window: " "$out"
"$BIN" sql "$P" --nosync --mem-window 0 -c "SHOW MEMORY;" >/dev/null 2>&1 && fail "--mem-window 0 accepted"
"$BIN" sql "$P" --nosync --mem-window 12x -c "SHOW MEMORY;" >/dev/null 2>&1 && fail "--mem-window 12x accepted"
expect_cell 15 "$("$BIN" sql "$P" --nosync --cross-check --mem-window 1 -c "SELECT COUNT(*) FROM txns AS OF $before WHERE user_id = 42;")"
echo "--mem-window 30 and none taken, 0 and 12x refused; AS OF $before still 15 under a one-second window"

step "the segment cache (stage 3c-1): --seg-cache takes bytes or all; with no image kept between statements each is read again"
out=$("$BIN" sql "$P" --nosync --seg-cache 1M -c "SHOW MEMORY;")
expect "; segment images " "$out"
expect ", budget 1048576; " "$out"
out=$("$BIN" sql "$P" --nosync --seg-cache all -c "SHOW MEMORY;")
expect " bytes, every one kept; 0 loaded since the open" "$out"
"$BIN" sql "$P" --nosync --seg-cache 0 -c "SHOW MEMORY;" >/dev/null 2>&1 && fail "--seg-cache 0 accepted"
"$BIN" sql "$P" --nosync --seg-cache 12x -c "SHOW MEMORY;" >/dev/null 2>&1 && fail "--seg-cache 12x accepted"
expect_cell 15 "$(IMDB_SEGCACHE=tiny "$BIN" sql "$P" --nosync --cross-check -c "SELECT COUNT(*) FROM txns AS OF $before WHERE user_id = 42;")"
out=$(IMDB_SEGCACHE=tiny "$BIN" sql "$P" --nosync -c "SELECT SUM(amount) FROM txns; SHOW MEMORY;")
echo "$out" | grep -q "segment images 0 bytes, budget 0; [1-9][0-9]* loaded since the open" || fail "tiny: no image read again:
$out"
echo "--seg-cache 1M and all taken, 0 and 12x refused; tiny: AS OF $before still 15, every image read again and dropped"

step "past the checkpoint: the auditor reads the lake plus the log tail, and prints the engine's view token"
sql "INSERT INTO txns VALUES (900, 7, 1.00, 'tail', '2026-10-16 09:00:00');" >/dev/null
ship
out=$("$AUD" count "$P" txns)
echo "$out"
expect "count=40 " "$out"   # 40 rows, row 3 deleted above, row 900 added
expect "+ log tail" "$out"
expect "count=40 " "$("$AUD" count "$R" txns)"
idtok() { "$BIN" sql "$1" --csv -c "SHOW IDENTITY;" | tail -n 1 | awk -F, '{gsub(/"/,"",$7); print $7}'; }
audtok() { "$AUD" identity "$1" | sed -E 's/.*view_token ([0-9a-f]+).*/\1/'; }
tp=$(idtok "$P"); tr=$(idtok "$R")
[ -n "$tp" ] && [ "$tp" = "$(audtok "$P")" ] || fail "view token: engine $tp, auditor $(audtok "$P")"
[ "$tp" = "$tr" ] && [ "$tr" = "$(audtok "$R")" ] || fail "view token of the replica differs: $tr"
echo "view token, engine = auditor, primary = replica: $tp"

step "erase subject 42 (right to be forgotten): 0 everywhere, no bytes left"
grep -rqa "MARKERX" "$P" || fail "marker missing before erase?"
out=$(sql "ERASE SUBJECT 42;")
echo "$out"
ship
expect_cell 0 "$(sql "SELECT COUNT(*) FROM txns WHERE user_id = 42;")"
expect_cell 0 "$(sql "SELECT COUNT(*) FROM txns AS OF $before WHERE user_id = 42;")"
expect "count=0 " "$("$AUD" count "$P" txns user_id=42)"
expect "count=0 " "$("$AUD" count "$R" txns user_id=42)"
if grep -rqa "MARKERX" "$P" "$R"; then fail "erased bytes still on disk"; fi
echo "grep -r MARKERX over both data directories: nothing"
expect "count=26 " "$("$AUD" count "$P" txns)"   # the 25 other rows and row 900

step "verification: engine and the independent auditor, both copies"
"$BIN" verify "$P"
"$BIN" verify "$R" >/dev/null
"$AUD" verify "$P"
"$AUD" verify "$R" >/dev/null
diff -r "$P/objects" "$R/objects" >/dev/null || fail "lake objects differ after erase"
diff -r "$P/log" "$R/log" >/dev/null || fail "log segments differ after erase"

step "follow: a replica that keeps applying and acknowledges; a synchronous commit waits for it"
F=$WORK/follower
FPID=
trap '[ -n "$FPID" ] && kill "$FPID" 2>/dev/null; rm -rf "$WORK"' EXIT
"$BIN" init-replica "$F" "$P" >/dev/null
"$BIN" replica-add "$P" f1 "$("$BIN" replica-key "$F")" >/dev/null
start_follow() { "$BIN" follow "$F" -- "$BIN" ship "$P" --follow --acks --after '{after}' 2>>"$WORK/follow.log" & FPID=$!; }
stop_follow() { kill "$FPID" 2>/dev/null || true; wait "$FPID" 2>/dev/null || true; FPID=; }
pcommit() { "$BIN" info "$P" | awk '/^commit/{print $2}'; }
caught_up() { # the follower acknowledged the primary's latest commit, by the commit column: the state "same history"
              # says only that the acknowledgement is of this history (a follower that acknowledged commit 0 of 7 has
              # the same history, 7 behind, and a search of the row for " 7 |" found its lag)
  local want; want=$(pcommit)
  for _ in $(seq 200); do
    out=$("$BIN" sql "$P" --csv -c "SHOW REPLICAS;")
    [ "$(echo "$out" | awk -F, '$1 == "\"f1\"" { gsub(/"/, "", $10); print $3 "," $10 }')" = "$want,same history" ] && return 0
    sleep 0.05
  done
  fail "the follower never acknowledged commit $want:
$out
$(cat "$WORK/follow.log")"
}
start_follow
caught_up # from commit 0, the ERASE included
expect "count=0 " "$("$AUD" count "$F" txns user_id=42)"
if grep -rqa "MARKERX" "$F"; then fail "erased bytes on the follower"; fi
out=$("$BIN" sql "$P" -c "SET sync_replicas = 1;" -c "SET sync_timeout_ms = 20000;" \
      -c "INSERT INTO txns VALUES (901, 7, 1.00, 'sync-901', '2026-10-22 01:00:00');" 2>&1)
case "$out" in *warning*) fail "the synchronous commit warned: $out" ;; esac
expect "replicated: confirmed by 1 of 1 replicas" "$out"
# returned, so the follower holds it: queried while follow still has it open for writing
expect_cell 1 "$("$BIN" sql "$F" --read-only -c "SELECT COUNT(*) FROM txns WHERE id = 901;")"
out=$("$BIN" sql "$P" -c "SHOW REPLICAS;")
echo "$out"
expect "same history" "$out"
stop_follow
out=$("$BIN" sql "$P" -c "SET sync_replicas = 1;" -c "SET sync_timeout_ms = 200;" \
      -c "INSERT INTO txns VALUES (902, 7, 1.00, 'sync-902', '2026-10-22 01:00:01');" 2>&1)
expect "only 0 of 1 replicas acknowledged it within 200 ms" "$out"
expect "replication unknown: acknowledged by 0 of 1 replicas" "$out"
echo "follower stopped: the commit stands, with a warning"
start_follow
caught_up
stop_follow
out=$("$BIN" sql "$P" -c "SHOW ERASURE;")
expect "complete here; 1 of 1 replicas report it complete" "$out"
"$BIN" verify "$F" >/dev/null
"$AUD" verify "$F" >/dev/null
[ "$("$BIN" info "$F" | awk '/^digest/{print $2}')" = "$("$BIN" info "$P" | awk '/^digest/{print $2}')" ] ||
  fail "the follower's digest differs from the primary's"
echo "follower verified; same digest as the primary at commit $(pcommit)"
# a restore from an older copy that keeps its key: caught at its first acknowledgement (it went
# back), refused until re-enrolled with a new key
cp -a "$F" "$WORK/follower-copy"
"$BIN" sql "$P" -c "INSERT INTO txns VALUES (903, 7, 1.00, 'after-the-copy', '2026-10-22 01:00:02');" >/dev/null
start_follow
caught_up
stop_follow
rm -rf "$F"
mv "$WORK/follower-copy" "$F"
start_follow
for _ in $(seq 200); do
  out=$("$BIN" sql "$P" -c "SHOW REPLICAS;")
  case "$out" in *"refused: went back"*) break ;; esac
  sleep 0.05
done
stop_follow
expect "refused: went back" "$out"
"$BIN" replica-add "$P" f1 "$("$BIN" replica-key "$F" --new 2>/dev/null)" --replace >/dev/null
start_follow
caught_up
stop_follow
echo "a restored follower is refused (it went back) until re-enrolled with a new key; then on the same history again"

step "writer epochs: a key rotation and a promotion, followed by every verifier"
E=$WORK/epochs
mkdir -p "$E"
ROOT=$("$BIN" root-key "$E/root.key" 2>/dev/null)
"$BIN" init "$E/p" --root "$ROOT" >/dev/null
"$BIN" identity "$E/p" | grep -q "^root $ROOT\$" || fail "the identity does not carry the root key"
esql() { "$BIN" sql "$E/$1" --nosync -c "$2" >/dev/null; }
esql p "CREATE TABLE acct (id INT64 PRIMARY KEY, owner INT64 SUBJECT, cents INT64);"
esql p "INSERT INTO acct VALUES (1, 42, 100), (2, 7, 200);"
"$BIN" init-replica "$E/r" "$E/p" >/dev/null
"$BIN" init-replica "$E/q" "$E/p" >/dev/null
"$BIN" rotate-key "$E/p" | grep -q "epoch 1" || fail "rotate-key did not report epoch 1"
esql p "INSERT INTO acct VALUES (3, 42, 300);"
esql p "CHECKPOINT;"                 # a lake snapshot under epoch 1: its readers need WRITERS
esql p "INSERT INTO acct VALUES (4, 7, 400);"
eship() { "$BIN" ship "$E/$1" --after "$("$BIN" info "$E/$2" | awk '/^commit/{print $2}')" | "$BIN" apply "$E/$2" >/dev/null; }
eship p r; eship p q
expect "count=4 " "$("$AUD" count "$E/r" acct)"   # the snapshot + its tail, keys from WRITERS
"$BIN" promote "$E/r" --root-key "$E/root.key" --old-writer-stopped >/dev/null
esql r "INSERT INTO acct VALUES (5, 42, 500);"
eship r q                                          # through the promotion frame
for d in p r q; do
  "$BIN" verify "$E/$d" >/dev/null || fail "engine VERIFY fails on $d"
  "$AUD" verify "$E/$d" >/dev/null || fail "the auditor rejects $d"
done
expect "writer     epoch 2" "$("$BIN" info "$E/q")"
expect "role       primary" "$("$BIN" info "$E/r")"
[ "$("$BIN" info "$E/q" | awk '/^digest/{print $2}')" = "$("$BIN" info "$E/r" | awk '/^digest/{print $2}')" ] ||
  fail "the follower's digest differs from the promoted writer's"
esql p "INSERT INTO acct VALUES (9, 7, 900);"   # the old writer, unfenced (no anchor), forks at epoch 1
if "$BIN" ship "$E/p" --after 5 | "$BIN" apply "$E/q" >/dev/null 2>&1; then
  fail "a follower of the promoted writer accepted the old writer's commit"
fi
echo "rotation (epoch 1) and promotion (epoch 2) verified on all three; the old writer's fork is refused"

step "backup and restore: an encrypted snapshot, a test restore, a restored copy promoted"
B=$WORK/backup
mkdir -p "$B/scratch"
BROOT=$("$BIN" root-key "$B/root.key" 2>/dev/null)
"$BIN" init "$B/p" --root "$BROOT" >/dev/null
bsql() { "$BIN" sql "$B/$1" --nosync -c "$2" >/dev/null; }
bsql p "CREATE TABLE acct (id INT64 PRIMARY KEY, owner INT64 SUBJECT, memo TEXT);"
bsql p "INSERT INTO acct VALUES (1, 42, 'BACKUPMARKER-1'), (2, 7, 'BACKUPMARKER-2');"
bsql p "CHECKPOINT;"
bsql p "INSERT INTO acct VALUES (3, 42, 'BACKUPMARKER-3');"
"$BIN" backup-key "$B/backup.key" >/dev/null 2>&1
out=$("$BIN" backup "$B/p" --key "$B/backup.key" --out "$B/full.bak")
echo "$out" | grep -q "a seed, then the commits after it" || fail "the backup is not a snapshot: $out"
! grep -q BACKUPMARKER "$B/full.bak" || fail "the backup holds a row in the clear"
"$BIN" backup-verify --key "$B/backup.key" --scratch "$B/scratch" "$B/full.bak" | grep -q "VERIFY passed" ||
  fail "backup-verify did not pass"
[ -z "$(ls -A "$B/scratch")" ] || fail "backup-verify left its copy"
"$BIN" restore "$B/r" --key "$B/backup.key" "$B/full.bak" >/dev/null 2>&1 || fail "the restore failed"
"$BIN" verify "$B/r" >/dev/null || fail "engine VERIFY fails on the restored copy"
"$AUD" verify "$B/r" >/dev/null || fail "the auditor rejects the restored copy"
[ "$("$BIN" info "$B/r" | awk '/^digest/{print $2}')" = "$("$BIN" info "$B/p" | awk '/^digest/{print $2}')" ] ||
  fail "the restored copy's digest differs from the primary's"
if "$BIN" restore "$B/r" --key "$B/backup.key" "$B/full.bak" >/dev/null 2>&1; then fail "a restore over an existing copy"; fi
"$BIN" backup-key "$B/other.key" >/dev/null 2>&1
if "$BIN" restore "$B/r2" --key "$B/other.key" "$B/full.bak" >/dev/null 2>&1; then fail "a restore under another key"; fi
[ ! -e "$B/r2" ] && [ ! -e "$B/r2.tmp" ] || fail "a refused restore left a directory"
"$BIN" promote "$B/r" --root-key "$B/root.key" --old-writer-stopped >/dev/null
bsql r "INSERT INTO acct VALUES (4, 7, 'BACKUPMARKER-4');"
"$BIN" verify "$B/r" >/dev/null || fail "engine VERIFY fails on the promoted copy"
"$AUD" verify "$B/r" >/dev/null || fail "the auditor rejects the promoted copy"
echo "backup (a snapshot, sealed: no row in the clear), backup-verify, restore (the primary's digest), another key refused, promoted and written"

step "tampering is detected by both verifiers"
T=$WORK/tampered
cp -a "$P" "$T"
seg=$(ls "$T"/objects/*.seg | head -1)
chmod u+w "$seg"
printf '\x01' | dd of="$seg" bs=1 seek=200 count=1 conv=notrunc 2>/dev/null
if "$BIN" verify "$T" >/dev/null 2>&1; then fail "engine verify missed a flipped byte"; fi
if "$AUD" verify "$T" >/dev/null 2>&1; then fail "auditor missed a flipped byte"; fi
echo "flipped byte in a segment: engine and auditor both fail, as they should"
cp -a "$P" "$T.2"
seg=$(ls "$T.2"/log/*.ilg | head -1)
flipbyte "$seg" $(($(stat -c %s "$seg") / 2))
if "$BIN" verify "$T.2" >/dev/null 2>&1; then fail "engine accepted a corrupted log"; fi
if "$AUD" verify "$T.2" >/dev/null 2>&1; then fail "auditor accepted a corrupted log"; fi
echo "flipped byte in the log: both refuse"

step "exact FLOAT64 SUM: the engine and the auditor, by different methods, agree to the bit"
F=$WORK/fsum
"$BIN" init "$F" >/dev/null
"$BIN" sql "$F" --nosync -c "CREATE TABLE f (id INT64 PRIMARY KEY, x FLOAT64, y FLOAT64);" >/dev/null
# x: 1 + 2^-53 + 2^-1074 + (1e308 - 1e308), the tie the smallest subnormal breaks: 1 + 2^-52
# y: DBL_MAX + 2^970 + 6, past the tie above DBL_MAX: out of range
"$BIN" sql "$F" --nosync -c "INSERT INTO f VALUES (1, 1.0, 1.7976931348623157e+308), (2, 1.1102230246251565e-16, 9.9792015476736e+291), (3, 4.9406564584124654e-324, 1.0), (4, 1e308, 2.0), (5, -1e308, 3.0);" >/dev/null
ex=$("$BIN" sql "$F" --csv -c "SELECT SUM(x) FROM f;" | tail -n 1)
[ "$ex" = "1.0000000000000002" ] || fail "engine SUM(x) is '$ex', not 1.0000000000000002"
ey=$("$BIN" sql "$F" --csv -c "SELECT SUM(y) FROM f;" 2>&1 || true)
expect "SUM out of FLOAT64 range" "$ey"
for when in "the log alone" "the lake"; do
  [ "$when" = "the lake" ] && "$BIN" sql "$F" --nosync -c "CHECKPOINT;" >/dev/null
  a=$("$AUD" count "$F" f)
  [ "$(echo "$a" | sed -n 's/.* sum(x)=\([^ ]*\).*/\1/p')" = "$ex" ] || fail "auditor SUM(x) from $when differs: $a"
  [ "$(echo "$a" | sed -n 's/.* sum(y)=\([^ ]*\).*/\1/p')" = "out-of-range" ] || fail "auditor SUM(y) from $when: $a"
done
echo "SUM(x) = $ex from the engine and from the auditor (log, then lake); SUM(y) out of range for both"

step "COPY (P2 S10): a file in and out through -c; a script's data inline up to a line \\.; the auditor"
C=$WORK/copy
"$BIN" init "$C" >/dev/null
"$BIN" sql "$C" --nosync -c "CREATE TABLE c (id INT64 PRIMARY KEY, s TEXT, d DECIMAL(9,2), b BOOL, at TIMESTAMP);" >/dev/null
printf 'id,s,d,b,at\n1,plain,1.50,true,2026-11-05 18:00:00\n2,"a, ""quoted""\nline",-0.01,false,\n3,"",0.00,,2026-01-01 00:00:00.000001\n4,,,,\n' > "$WORK/c.csv"
out=$("$BIN" sql "$C" --nosync -c "COPY c FROM STDIN (HEADER)" < "$WORK/c.csv")
expect "COPY 4" "$out"
"$BIN" sql "$C" -c "COPY c TO STDOUT (HEADER)" > "$WORK/c.out" 2> "$WORK/c.err"
cmp -s "$WORK/c.csv" "$WORK/c.out" || fail "COPY TO is not the file COPY FROM read: $(diff "$WORK/c.csv" "$WORK/c.out")"
expect "COPY 4" "$(cat "$WORK/c.err")" # the count beside the data: stdout is the data alone
# a script: its data after the statement (a comment on the statement's line), a ';' and a quoted field holding a line
# \. as data, a quoted field ending its line just before the \. that ends the data, a statement after it, and a COPY
# whose data runs to the script's end with no line end; then the same through a pipe
printf 'COPY c (id, s) FROM STDIN; -- inline\n10,x;y\n11,"\n\\.\nend"\n12,"abc"\n\\.\nSELECT COUNT(*) FROM c WHERE id >= 10;\nCOPY c (id) FROM STDIN;\n20\n21' > "$WORK/c.sql"
out=$("$BIN" sql "$C" --nosync --csv -f "$WORK/c.sql")
expect "COPY 3" "$out"
expect "$(printf 'count\n3')" "$out"
expect "COPY 2" "$out"
printf 'COPY c (id) FROM STDIN;\n30\n\\.\nSELECT COUNT(*) FROM c;\n' | "$BIN" sql "$C" --nosync --csv > "$WORK/c.pipe"
expect "$(printf 'count\n10')" "$(cat "$WORK/c.pipe")"
got=$("$BIN" sql "$C" -c "COPY (SELECT id, s FROM c WHERE id >= 10 ORDER BY id) TO STDOUT" 2>/dev/null)
want=$(printf '10,x;y\n11,"\n\\.\nend"\n12,abc\n20,\n21,\n30,')
[ "$got" = "$want" ] || fail "the script's rows: got
$got
want
$want"
# refused: a statement after the COPY on its line; a line '\. ' (a trailing space) is data, not the end, and fails as
# data, the script stopping there with nothing of that COPY written
if "$BIN" sql "$C" --nosync -f <(printf 'COPY c (id) FROM STDIN; SELECT 1;\n40\n\\.\n') > "$WORK/c.r1" 2>&1; then fail "a statement after COPY on its line ran"; fi
expect "its data starts on the line after it" "$(cat "$WORK/c.r1")"
if "$BIN" sql "$C" --nosync -f <(printf 'COPY c (id) FROM STDIN;\n41\n\\. \n42\n\\.\nSELECT 1;\n') > "$WORK/c.r2" 2>&1; then fail "a '\\. ' line ended COPY's data"; fi
expect "COPY line 2, column id: invalid integer literal" "$(cat "$WORK/c.r2")"
expect "$(printf 'count\n10')" "$("$BIN" sql "$C" --csv -c "SELECT COUNT(*) FROM c;")"
# the REPL, given a terminal by script(1): the data a line at a time up to its \. line, the statement after it the REPL's
# own (the marker's lookahead once read that line into COPY's buffer, and the REPL never saw it)
if command -v script >/dev/null 2>&1; then
  printf 'COPY c (id) FROM STDIN;\n50\n51\n\\.\nSELECT COUNT(*) FROM c;\n\\q\n' > "$WORK/c.repl"
  out=$(script -qec "$BIN sql $C --nosync --csv" /dev/null < "$WORK/c.repl" 2>&1 | tr -d '\r')
  expect "COPY 2" "$out"
  expect "$(printf 'count\n12')" "$out"
fi
"$BIN" verify "$C" >/dev/null || fail "VERIFY after the COPYs"
"$AUD" verify "$C" >/dev/null || fail "the auditor after the COPYs"
echo "COPY: a file's bytes back unchanged; a script's inline data to its \\. line, a quoted \\. kept as data; both verifiers agree"

# P2 S17: a logical dump (imagedb dump): restored into an empty database of the other digest algorithm by sql -f, it
# dumps again the same past its first line (the commit it names); each table's rows the same in key order; a replica's
# dump at the primary's commit the primary's, byte for byte; a dump of no directory fails with nothing on stdout
"$BIN" sql "$C" --nosync -c "CREATE TABLE d2 (k INT64 PRIMARY KEY, who INT64 SUBJECT, v DECIMAL(9,3) NOT NULL) RETENTION 90 MINUTES;" \
  -c "INSERT INTO d2 VALUES (3, 30, 1.5), (1, 10, -2.25), (2, 20, 0);" -c "CREATE UNIQUE INDEX d2v ON d2 (v);" \
  -c "UPDATE d2 SET v = 7.125 WHERE k = 1;" >/dev/null
"$BIN" dump "$C" --batch 4 > "$WORK/d.sql" || fail "imagedb dump"
expect "COPY c FROM STDIN (BATCH 4);" "$(cat "$WORK/d.sql")"
expect "CREATE UNIQUE INDEX d2v ON d2 (v);" "$(cat "$WORK/d.sql")"
nc=$("$BIN" sql "$C" --csv -c "SELECT COUNT(*) FROM c;" | tail -1) # 12, or 10 without script(1) above
expect "-- the end of the dump: 2 tables, $((nc + 3)) rows" "$(tail -1 "$WORK/d.sql")"
alg=$(sed -n '1s/.*digest algorithm \([12]\)).*/\1/p' "$WORK/d.sql")
other=$((3 - ${alg:-2}))
"$BIN" init "$WORK/dst" --digest-alg "$other" >/dev/null || fail "init the dump's target"
"$BIN" sql "$WORK/dst" --nosync -f "$WORK/d.sql" >/dev/null || fail "the dump's restore"
"$BIN" dump "$WORK/dst" --batch 4 > "$WORK/d2.sql" || fail "the restored copy's dump"
cmp -s <(tail -n +2 "$WORK/d.sql") <(tail -n +2 "$WORK/d2.sql") || fail "the restored copy's dump differs: $(diff "$WORK/d.sql" "$WORK/d2.sql")"
for q in "SELECT * FROM c ORDER BY id" "SELECT * FROM d2 ORDER BY k"; do
  [ "$("$BIN" sql "$C" --csv -c "$q;")" = "$("$BIN" sql "$WORK/dst" --csv -c "$q;")" ] || fail "rows differ after the restore: $q"
done
"$BIN" verify "$WORK/dst" >/dev/null || fail "VERIFY of the restored copy"
"$BIN" init-replica "$WORK/drep" "$C" >/dev/null || fail "a replica for the dump"
"$BIN" ship "$C" --after 0 | "$BIN" apply "$WORK/drep" >/dev/null || fail "the dump's replica apply"
cmp -s "$WORK/d.sql" <("$BIN" dump "$WORK/drep" --batch 4) || fail "the replica's dump is not the primary's"
if "$BIN" dump "$WORK/no-such-dir" > "$WORK/d.none" 2>/dev/null; then fail "a dump of no directory succeeded"; fi
[ ! -s "$WORK/d.none" ] || fail "a failed dump wrote to stdout"
echo "dump: restored into the other digest algorithm, dumped again the same; a replica's dump the primary's"
# a live primary's dump: another process commits throughout (a statement a process); each dump, opened read-only beside
# it, names a commit and holds exactly the rows the primary had then (AS OF it), with its totals line; the last restores
( for i in $(seq 1 40); do "$BIN" sql "$C" --nosync -c "INSERT INTO d2 VALUES ($((1000 + i)), $i, $((1000 + i)).25);" >/dev/null || { echo "the writer failed at i=$i" >&2; exit 1; }; done ) &
wpid=$!
k=0
while [ $k -lt 6 ]; do
  k=$((k + 1))
  "$BIN" dump "$C" > "$WORK/dl$k.sql" || fail "a dump beside a writer ($k)"
  n=$(sed -n '1s/^-- imagedb dump of commit \([0-9]*\) .*/\1/p' "$WORK/dl$k.sql")
  [ -n "$n" ] || fail "a dump beside a writer names no commit ($k)"
  expect "-- the end of the dump: 2 tables," "$(tail -1 "$WORK/dl$k.sql")"
  rows=$(awk '/^COPY d2 FROM STDIN/ {f = 1; next} f && $0 == "\\." {f = 0} f {r++} END {print r + 0}' "$WORK/dl$k.sql")
  want=$("$BIN" sql "$C" --read-only --csv -c "SELECT COUNT(*) FROM d2 AS OF $n;" | tail -1)
  [ "$rows" = "$want" ] || fail "a dump at commit $n holds $rows rows of d2, the primary had $want then"
done
if ! wait $wpid; then # what the writer saw, for the record: its rows past the first three, and VERIFY
  "$BIN" sql "$C" --read-only --csv -c "SELECT k, v FROM d2 WHERE k >= 1000 ORDER BY k;" >&2
  "$BIN" verify "$C" >&2
  fail "the writer beside the dumps"
fi
"$BIN" init "$WORK/dlive" >/dev/null && "$BIN" sql "$WORK/dlive" --nosync -f "$WORK/dl$k.sql" >/dev/null || fail "restoring a live dump"
[ "$("$BIN" sql "$WORK/dlive" --csv -c "SELECT COUNT(*) FROM d2;" | tail -1)" = "$rows" ] || fail "the live dump's restore"
echo "dump: six dumps beside a writer, each the primary's rows at the commit it names"

printf '\nALL INTEGRATION CHECKS PASSED\n'
