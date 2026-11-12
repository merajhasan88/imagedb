#!/usr/bin/env bash
# The independent auditor (imagedb-audit) must *reject* structurally valid but
# semantically hostile inputs, not only agree with the engine on good data.
# Each case is built (by tests/tools/forge.c) so that every checksum and
# content hash is consistent; only the rule under test is broken. The engine
# must reject it too.
#
#   tests/integration/audit_reject.sh [path/to/imagedb]
set -euo pipefail

BIN=${1:-build/imagedb}
AUD=${AUDIT:-$(dirname "$BIN")/imagedb-audit}
FORGE=${FORGE:-$(dirname "$BIN")/imdb-forge}
WORK=$(mktemp -d "${IMDB_TEST_TMP:-/tmp}/imdb-rej.XXXXXX")
trap 'rm -rf "$WORK"' EXIT
fail() { echo "FAIL: $*" >&2; exit 1; }
must_fail() { # must_fail "<expected message>" cmd...
  local want=$1; shift
  local out
  if out=$("$@" 2>&1); then fail "accepted (expected '$want'): $*"; fi
  case "$out" in *"$want"*) ;; *) fail "rejected for the wrong reason (expected '$want'):
$out" ;; esac
}

make_db() {
  "$BIN" init "$1" >/dev/null
  "$BIN" sql "$1" --nosync -c "CREATE TABLE t (id INT64 PRIMARY KEY, u INT64 SUBJECT, memo TEXT);
     INSERT INTO t VALUES (1, 42, 'secret-one'), (2, 7, 'two');
     INSERT INTO t VALUES (3, 42, 'secret-three');
     CHECKPOINT;" >/dev/null
}

echo "== A: payloads blanked without any ERASE record (descriptors, signatures, CRCs intact)"
A=$WORK/a; make_db "$A"
for seg in "$A"/log/*.ilg; do "$FORGE" redact-all "$seg"; done
must_fail "not authorised by any ERASE" "$AUD" verify "$A"
must_fail "not authorised by any ERASE" "$BIN" verify "$A"   # VERIFY (open starts from the lake snapshot)
echo "   rejected by the auditor and the engine"

echo "== B: ERASE committed but payloads still in the log (crash window)"
B=$WORK/b; make_db "$B"
cp -a "$B" "$WORK/b-pre"
"$BIN" sql "$B" --nosync -c "ERASE SUBJECT 42;" >/dev/null
# the crash: the ERASE (its own segment) durable, nothing redacted, the lake not yet published
cp "$B/log/$(ls "$B/log" | tail -1)" "$WORK/b-pre/log/"
rm -rf "$B"; mv "$WORK/b-pre" "$B"
must_fail "erasure incomplete" "$AUD" verify "$B"
must_fail "erasure incomplete" "$BIN" verify "$B"
echo "   rejected by the auditor and the engine (a normal open would finish the erasure)"

echo "== C: LAKE_HEAD names a different commit than its manifest"
C=$WORK/c; make_db "$C"
sed -i 's/^seq [0-9]*$/seq 1/' "$C/LAKE_HEAD"
must_fail "manifest seq differs from LAKE_HEAD" "$AUD" verify "$C"
must_fail "LAKE_HEAD does not name" "$BIN" verify "$C"
echo "   rejected by the auditor and the engine"

echo "== D: re-hashed segment whose zone map lies (content hashes all consistent)"
D=$WORK/d; make_db "$D"
"$FORGE" lie-zonemap "$D"
must_fail "zone map does not match" "$AUD" count "$D" t
must_fail "zone map does not match" "$AUD" verify "$D"
must_fail "LAKE_HEAD does not name" "$BIN" verify "$D"
echo "   rejected by the auditor (structural check) and the engine"

echo "== E: symlink planted in objects/ is refused, not followed"
E=$WORK/e; make_db "$E"
seg=$(ls "$E"/objects/*.seg | head -1)
mv "$seg" "$WORK/elsewhere.seg"
ln -s "$WORK/elsewhere.seg" "$seg"
must_fail "symbolic link" "$AUD" verify "$E"
must_fail "refusing to follow a symlink" "$BIN" verify "$E"
echo "   the auditor and the engine refuse the symlinked object"

echo "== F: a commit re-signed by another key"
F=$WORK/f; make_db "$F"
G=$WORK/g; make_db "$G"
cp "$G/META" "$F/META.other"; sed -i "s/^db_id .*/$(grep '^db_id' "$F/META")/" "$F/META.other"; mv "$F/META.other" "$F/META"
must_fail "not signed by the writer key" "$AUD" verify "$F"
must_fail "signature invalid" "$BIN" verify "$F"
echo "   a log is only accepted under the writer key pinned in META"

echo "== G: two log segments merged (a commit after a manifest in the same segment)"
G=$WORK/gg; make_db "$G"
"$BIN" sql "$G" --nosync -c "INSERT INTO t VALUES (9, 9, 'nine');" >/dev/null
s1=$(ls "$G"/log/*.ilg | head -1); s2=$(ls "$G"/log/*.ilg | tail -1)
[ "$s1" != "$s2" ] || fail "expected two segments"
"$FORGE" merge-segments "$s1" "$s2" # frames, in either format
must_fail "continues past a commit that publishes a manifest" "$AUD" verify "$G"
must_fail "continues past a commit that publishes a manifest" "$BIN" verify "$G"
echo "   the segment layout is a rule both enforce, not a convention"

echo "== H: the retained generation (prev_manifest) deleted from objects/"
H=$WORK/h; make_db "$H"
"$BIN" sql "$H" --nosync -c "INSERT INTO t VALUES (4, 5, 'four'); CHECKPOINT;" >/dev/null
cur=$(sed -n 's/^manifest //p' "$H/LAKE_HEAD")
old=$(ls "$H"/objects/*.man | grep -v "$cur")
[ -n "$old" ] || fail "expected a retained manifest"
rm "$old"
must_fail "is missing from objects/" "$AUD" verify "$H"
must_fail "retained generation the manifest names is missing" "$BIN" verify "$H"
echo "   one generation of retention is part of the format, checked by both"

echo "== I: a pre-ERASE segment left in objects/ (crash between LAKE_HEAD and GC)"
I=$WORK/i; make_db "$I"
mkdir "$WORK/i-old"; cp "$I"/objects/*.seg "$WORK/i-old/"
"$BIN" sql "$I" --nosync -c "ERASE SUBJECT 42;" >/dev/null
cp "$WORK"/i-old/*.seg "$I/objects/"
grep -rq secret-one "$I/objects" || fail "expected the erased rows back in objects/"
must_fail "neither the manifest nor its retained generation references" "$AUD" verify "$I"
must_fail "no retained manifest references" "$BIN" verify "$I"
"$BIN" sql "$I" --nosync -c "SELECT COUNT(*) FROM t;" >/dev/null   # a writable open completes the publish
if grep -rq secret-one "$I"; then fail "erased rows survived a writable open"; fi
"$AUD" verify "$I" >/dev/null || fail "the auditor rejects the healed directory"
"$BIN" verify "$I" >/dev/null || fail "VERIFY rejects the healed directory"
echo "   both reject leftover objects; a writable open removes them (GC finishes the publish)"

echo "== J: a writer signs a lake whose purged tombstone names another subject"
J=$WORK/j; make_db "$J"
"$BIN" sql "$J" --nosync -c "DELETE FROM t WHERE id = 2; COMPACT t PURGE BEFORE 5;" >/dev/null
"$AUD" verify "$J" >/dev/null || fail "the honest directory must verify"
"$FORGE" lie-tombstone "$J"   # segment, DV, manifest, LAKE_HEAD re-hashed; log re-signed from the snapshot
must_fail "names another subject" "$AUD" verify "$J"
must_fail "names another subject" "$BIN" verify "$J"
echo "   signatures prove who wrote the lake, not that it is right: tombstones are checked against the log"

flip_last_byte() { # flip_last_byte <file>: damage a complete final frame (its body checksum fails), where it lies
  "$FORGE" damage-last "$1"
}

echo "== K: an acknowledged final commit is damaged (must not be truncated as a torn tail)"
K=$WORK/k; make_db "$K"
"$BIN" sql "$K" --nosync -c "INSERT INTO t VALUES (4, 7, 'last-committed-row');" >/dev/null
last=$(find "$K/log" -name '*.ilg' | sort | tail -1)
flip_last_byte "$last"
before=$(sha256sum "$last")
must_fail "acknowledged as durable" "$AUD" verify "$K"
must_fail "acknowledged as durable" "$BIN" verify "$K"
must_fail "acknowledged as durable" "$BIN" sql "$K" --nosync -c "SELECT COUNT(*) FROM t;"
ship_quiet() { "$BIN" ship "$@" >/dev/null; }
must_fail "acknowledged as durable" ship_quiet "$K"
[ "$(sha256sum "$last")" = "$before" ] || fail "opening the damaged log changed its bytes"
# the operator's explicit way out: inspect, then discard with the bytes saved
must_fail "lost       commits 5..5" "$BIN" recover "$K"
[ "$(sha256sum "$last")" = "$before" ] || fail "recover without --discard-tail changed the log"
must_fail "needs --save" "$BIN" recover "$K" --discard-tail
size=$(wc -c < "$last")
"$BIN" recover "$K" --discard-tail --save "$WORK/k-tail.bin" >/dev/null || fail "recover --discard-tail failed"
[ -s "$WORK/k-tail.bin" ] || fail "recover did not save the discarded bytes" # tagged: the raw sectors it dropped
[ "$("$AUD" frames "$K" | tail -1 | cut -d" " -f2)" = 0 ] || fail "recover did not cut the damaged frame" # its frames, either format
out=$("$BIN" sql "$K" --nosync -c "SELECT COUNT(*) FROM t;") || fail "the recovered directory does not open"
case "$out" in *" 3"*) ;; *) fail "expected the 3 rows before the discarded commit: $out" ;; esac
"$AUD" verify "$K" >/dev/null || fail "the auditor rejects the recovered directory"
"$BIN" verify "$K" >/dev/null || fail "VERIFY rejects the recovered directory"
echo "   auditor, VERIFY, open and ship refuse it with the bytes untouched; imagedb recover discards it explicitly"

echo "== L: the same damage just past a watermark that may lag: an unfinished append or a damaged acknowledged commit"
L=$WORK/l; make_db "$L"
"$BIN" sql "$L" --nosync -c "INSERT INTO t VALUES (4, 7, 'maybe-acknowledged');" >/dev/null
"$FORGE" durable-rewind "$L"   # a watermark rewrite an OS crash lost (it is not synced per commit)
last=$(find "$L/log" -name '*.ilg' | sort | tail -1)
flip_last_byte "$last"
before=$(sha256sum "$last")
must_fail "cannot show it was never acknowledged" "$AUD" verify "$L"
must_fail "cannot show that commit 5 was never acknowledged" "$BIN" verify "$L"
must_fail "cannot show that commit 5 was never acknowledged" "$BIN" sql "$L" -c "SELECT COUNT(*) FROM t;"
must_fail "cannot show that commit 5 was never acknowledged" "$BIN" sql "$L" --read-only -c "SELECT COUNT(*) FROM t;"
[ -z "$("$BIN" ship "$L" --after 4)" ] || fail "ship sent a commit past the durable watermark" # it reads only up to it
[ "$(sha256sum "$last")" = "$before" ] || fail "opening the damaged log changed its bytes"
must_fail "unknown    the damaged frame after commit 4 is complete" "$BIN" recover "$L"
"$BIN" recover "$L" --discard-tail --save "$WORK/l-tail.bin" >/dev/null || fail "recover --discard-tail failed"
out=$("$BIN" sql "$L" -c "SELECT COUNT(*) FROM t;") || fail "the recovered directory does not open"
case "$out" in *" 3"*) ;; *) fail "expected the 3 rows before the discarded commit: $out" ;; esac
"$AUD" verify "$L" >/dev/null || fail "the auditor rejects the recovered directory"
echo "   nothing drops it: every open refuses with the bytes untouched (ship sends only the durable prefix); imagedb recover
   names the doubt and discards on request"

echo "== M: inputs the tools cannot evaluate exactly are refused, not guessed"
M=$WORK/m; "$BIN" init "$M" >/dev/null
"$BIN" sql "$M" --nosync -c "CREATE TABLE f (id INT64 PRIMARY KEY, u INT64 SUBJECT, x FLOAT64, ok BOOL);
   INSERT INTO f VALUES (1, 7, 2.0, true), (2, 7, 1e-323, false); CHECKPOINT;" >/dev/null
must_fail "not supported" "$AUD" count "$M" f x=2          # a FLOAT64 is stored as its order key, not as digits
must_fail "true or false" "$AUD" count "$M" f ok=maybe
must_fail "commit number" "$AUD" count "$M" f --as-of abc
must_fail "usage" "$BIN" ship "$M" --after abc               # "abc" must not mean commit 0
out=$("$AUD" count "$M" f ok=false) || fail "a valid BOOL filter was refused"
case "$out" in count=1*) ;; *) fail "expected count=1: $out" ;; esac
echo "   FLOAT64 filters, malformed BOOL filters and malformed commit numbers are refused"

echo "== N: a log tail past the lake snapshot whose payload no longer matches its signed commitment"
NT=$WORK/n; make_db "$NT"
"$BIN" sql "$NT" -c "INSERT INTO t VALUES (4, 42, 'tail-row');" >/dev/null
last=$(ls "$NT"/log/*.ilg | tail -n 1)
"$FORGE" lie-payload "$last"
must_fail "payload does not match its commitment" "$AUD" count "$NT" t u=42
must_fail "payload does not match its commitment" "$AUD" verify "$NT"
must_fail "does not match" "$BIN" verify "$NT"
out=$("$AUD" count "$NT" t u=42 --lake) || fail "the snapshot alone is intact and must be answered"
case "$out" in count=2*) ;; *) fail "expected count=2 from the snapshot: $out" ;; esac
echo "   the tail reader and both verifiers refuse it; the snapshot alone still answers"

echo "== O: a key rotation signed by a key that is not the writer's"
O=$WORK/o; make_db "$O"
"$FORGE" rotate-foreign "$O"
must_fail "not signed by the writer key" "$AUD" verify "$O"
must_fail "signature invalid" "$BIN" verify "$O"
echo "   a WRITER_KEY commit counts only under the key it replaces"

echo "== P: a promotion the root key certified for another history"
P=$WORK/p
ROOT=$("$BIN" root-key "$WORK/root.key" 2>/dev/null)
"$BIN" init "$P" --root "$ROOT" >/dev/null
"$BIN" sql "$P" --nosync -c "CREATE TABLE t (id INT64 PRIMARY KEY, u INT64 SUBJECT, memo TEXT);" \
  -c "INSERT INTO t VALUES (1, 42, 'x');" >/dev/null
"$FORGE" promote-elsewhere "$P" "$WORK/root.key"
must_fail "root certificate" "$AUD" verify "$P"
must_fail "root certificate" "$BIN" verify "$P"
echo "   a root certificate binds a promotion to one cut point of one history"

echo "== Q: WRITERS with an entry whose signature does not verify (its CRC consistent)"
Q=$WORK/q; make_db "$Q"
"$BIN" rotate-key "$Q" >/dev/null
"$BIN" sql "$Q" --nosync -c "INSERT INTO t VALUES (5, 7, 'five');" -c "CHECKPOINT;" \
  -c "INSERT INTO t VALUES (6, 7, 'six');" >/dev/null   # a snapshot under epoch 1, and a tail past it
"$FORGE" writers-resign "$Q"
must_fail "WRITERS: entry 1" "$AUD" count "$Q" t
"$AUD" verify "$Q" >/dev/null || fail "the auditor's full replay does not need WRITERS"
out=$("$BIN" sql "$Q" --nosync -c "SELECT COUNT(*) FROM t;" 2>&1)
case "$out" in *"replayed the whole log"*" 5"*) ;; *) fail "expected a full replay and 5 rows: $out" ;; esac
echo "   a WRITERS proof that fails is never used: the tail reader refuses, the engine replays the whole log"

echo "== R: under --durable-ack the same damage past the watermark is provably an unfinished append"
dur_flags() { od -An -tu4 -j48 -N4 "$1/DURABLE" | tr -d ' '; }
R=$WORK/r; make_db "$R"
"$BIN" sql "$R" --durable-ack -c "INSERT INTO t VALUES (4, 7, 'never-acknowledged');" >/dev/null
[ "$(dur_flags "$R")" = 3 ] || fail "a --durable-ack writer left a watermark that is not strict"
"$FORGE" durable-rewind "$R"   # the writer crashed before its watermark sync returned: commit 5 never acknowledged
last=$(find "$R/log" -name '*.ilg' | sort | tail -1)
flip_last_byte "$last"
out=$("$AUD" verify "$R") || fail "the auditor rejects a torn tail past a strict watermark"
case "$out" in *"torn tail"*) ;; *) fail "the auditor did not report the torn tail: $out" ;; esac
"$BIN" verify "$R" | grep -q "torn tail" || fail "VERIFY did not report the torn tail"
[ -z "$("$BIN" ship "$R" --after 4)" ] || fail "ship sent a commit past the durable watermark"
must_fail "needs a writable open with synchronous commits" "$BIN" sql "$R" --nosync --durable-ack -c "SELECT COUNT(*) FROM t;"
out=$("$BIN" sql "$R" --durable-ack -c "SELECT COUNT(*) FROM t;" 2>&1) || fail "a writable open must truncate the torn tail"
case "$out" in *"tail truncated"*" 3"*) ;; *) fail "expected truncation and 3 rows: $out" ;; esac
"$AUD" verify "$R" >/dev/null || fail "the auditor rejects the truncated directory"
# a later writer without --durable-ack marks the watermark not strict at its open, before any
# commit: the flag never outlives the guarantee behind it
"$BIN" sql "$R" -c "SELECT COUNT(*) FROM t;" >/dev/null
[ "$(dur_flags "$R")" = 1 ] || fail "a writable open without --durable-ack left the watermark strict"
"$BIN" sql "$R" -c "INSERT INTO t VALUES (5, 7, 'acknowledged');" >/dev/null
"$FORGE" durable-rewind "$R"   # its rewrite lost in an OS crash: commit 5 was acknowledged
last=$(find "$R/log" -name '*.ilg' | sort | tail -1)
flip_last_byte "$last"
must_fail "cannot show that commit 5 was never acknowledged" "$BIN" sql "$R" -c "SELECT COUNT(*) FROM t;"
must_fail "cannot show it was never acknowledged" "$AUD" verify "$R"
echo "   strict: both accept it as torn, a writable open truncates it; a later writer without the flag clears it first"

echo "== S: a pin naming a generation from before an ERASE does not make its files legitimate"
PS=$WORK/s; make_db "$PS"
cp -a "$PS/objects" "$WORK/s-objects"   # the generation before the ERASE (and the one it retains)
gen=$(awk '$1 == "manifest" {print $2}' "$PS/LAKE_HEAD")
"$BIN" sql "$PS" --nosync -c "ERASE SUBJECT 42;" -c "INSERT INTO t VALUES (9, 7, 'later');" -c "CHECKPOINT;" >/dev/null
for f in "$WORK/s-objects"/*; do [ -e "$PS/objects/${f##*/}" ] || cp "$f" "$PS/objects/"; done
: > "$PS/pins/$gen.pin"   # as a reader of that generation leaves it
must_fail "(nor a pinned one)" "$AUD" verify "$PS"
must_fail "no retained manifest references" "$BIN" verify "$PS"
echo "   both refuse: a pin keeps nothing from before the last ERASE (tests/unit t_lake pin_verify_rules: the exact case)"

echo "== T, U, V: index ops the log's rules forbid, each signed by the writer, alone in its commit"
for kind in column duplicate drop-absent; do
  PI=$WORK/idx-$kind; make_db "$PI"
  "$BIN" sql "$PI" --nosync -c "CREATE INDEX t_u ON t (u);" >/dev/null
  "$FORGE" index-lie "$PI" "$kind"
  case $kind in
    column) we="an index on a column"; wa="CREATE INDEX on a column the table lacks" ;;
    duplicate) we="an index name already in use"; wa="CREATE INDEX with a name in use" ;;
    drop-absent) we="DROP INDEX of an index"; wa="DROP INDEX of an index the table lacks" ;;
  esac
  must_fail "$we" "$BIN" verify "$PI"
  must_fail "$wa" "$AUD" verify "$PI"
done
echo "   T a missing column, U a name in use, V a DROP of an absent index: the engine and the auditor refuse each"

echo "== W, X: a manifest breaking one of its rules, re-pointed and re-signed so only that rule refuses it"
PW=$WORK/w; make_db "$PW"
"$FORGE" manifest-lie "$PW" boundary
must_fail "retirement boundary differs from the log's" "$BIN" verify "$PW"   # the open took the manifest's; the log's is 0
must_fail "retirement boundary differs from the log's" "$AUD" verify "$PW"
PX=$WORK/x; make_db "$PX"
"$BIN" sql "$PX" --nosync -c "CREATE INDEX t_u ON t (u);" -c "CHECKPOINT;" >/dev/null
"$FORGE" manifest-lie "$PX" column
must_fail "physical divergence" "$BIN" verify "$PX"
must_fail "manifest: bad index" "$AUD" verify "$PX"
echo "   W a retirement boundary no op made, X an index on a missing column: the auditor refuses on the rule,
   the engine on its boundary against the log's (W) or on rebuilding the lake (X) (t_index manifest_strict: the
   engine's rule itself)"

echo "== FA-FE: manifest 7 (the format design's slice 1) breaking one of its rules, re-pointed and re-signed"
PFA=$WORK/fa; make_db "$PFA"
"$FORGE" manifest-lie "$PFA" section
must_fail "a later imagedb's format" "$BIN" verify "$PFA"
must_fail "manifest: section 7 not empty" "$AUD" verify "$PFA"
PFB=$WORK/fb; make_db "$PFB"
"$FORGE" manifest-lie "$PFB" keylist
must_fail "physical divergence" "$BIN" verify "$PFB"   # an unreadable manifest: the open replays and rebuilds it (as X)
must_fail "schema: the key list is not its PRIMARY KEY column" "$AUD" verify "$PFB"
PFC=$WORK/fc; make_db "$PFC"
"$FORGE" manifest-lie "$PFC" order
must_fail "physical divergence" "$BIN" verify "$PFC"   # unreadable: the open replays and rebuilds it (as X)
must_fail "manifest: the sequences section missing or out of order" "$AUD" verify "$PFC"
PFD=$WORK/fd; make_db "$PFD"
"$FORGE" manifest-lie "$PFD" later
must_fail "its section 11 is not empty: a later imagedb's format" "$BIN" verify "$PFD"
must_fail "manifest: section 11 not empty (a later format's)" "$AUD" verify "$PFD"
PFE=$WORK/fe; make_db "$PFE"
"$FORGE" manifest-lie "$PFE" nsections
must_fail "physical divergence" "$BIN" verify "$PFE"   # unreadable: the open replays and rebuilds it (as X)
must_fail "manifest: bad sections" "$AUD" verify "$PFE"
echo "   FA a reserved section not empty and FD a longer one, both a later format's; FC one out of order; FE a
   section count of ten; FB a table's key list naming another column than its PRIMARY KEY: the auditor refuses each
   on its rule, the engine FA and FD by name, the others on rebuilding the lake (as X) (t_index manifest_sections:
   the engine's rules one by one)"

echo "== Y: an INSERT repeating a live row's key of a unique index, its state digest right, signed by the writer"
PY=$WORK/y; make_db "$PY"
"$BIN" sql "$PY" --nosync -c "CREATE UNIQUE INDEX t_memo ON t (memo);" >/dev/null
"$FORGE" index-lie "$PY" unique-dup
must_fail "duplicate key in unique index" "$BIN" verify "$PY"   # the replay of the log's tail refuses it
must_fail "share a key of unique index" "$AUD" verify "$PY"
echo "   Y a duplicate under a unique index: the engine's replay and the auditor refuse it"

echo "== FF, FG: an INSERT repeating a live row's whole primary key (two columns, then one), its state digest right,
   signed by the writer"
PFF=$WORK/ff; make_db "$PFF"
"$BIN" sql "$PFF" --nosync -c "CREATE TABLE ck (a INT64, b TEXT, v INT64, PRIMARY KEY (a, b));" \
  -c "INSERT INTO ck VALUES (1, 'x', 1), (1, 'y', 2);" >/dev/null
"$FORGE" index-lie "$PFF" pk-dup
must_fail "duplicate live primary key" "$BIN" verify "$PFF"   # the replay of the log's tail refuses it
must_fail "share its primary key" "$AUD" verify "$PFF"
PFG=$WORK/fg; make_db "$PFG"
"$FORGE" index-lie "$PFG" pk-dup
must_fail "duplicate live primary key" "$BIN" verify "$PFG"
must_fail "share its primary key" "$AUD" verify "$PFG"
echo "   FF a key of two columns, FG of one: the engine's replay and the auditor refuse each (the auditor checks a
   table's key since F4; it had checked only the unique indexes)"

echo "== FH: a segment built after ADD COLUMN whose row from before it reads another value than its missing one there
   (no commitment covers that value), its zone map made again, the lake re-hashed and the log re-signed by the writer"
PFH=$WORK/fh; "$BIN" init "$PFH" >/dev/null # rows still in memory at the ALTER: the CHECKPOINT after it builds them
"$BIN" sql "$PFH" --nosync -c "CREATE TABLE t (id INT64 PRIMARY KEY, u INT64 SUBJECT, memo TEXT);" \
  -c "INSERT INTO t VALUES (1, 42, 'one'), (2, 7, 'two');" >/dev/null
"$BIN" sql "$PFH" --nosync -c "ALTER TABLE t ADD n INT64 NOT NULL DEFAULT 5;" \
  -c "INSERT INTO t VALUES (4, 9, 'four', 9);" -c "CHECKPOINT;" >/dev/null
"$BIN" verify "$PFH" >/dev/null && "$AUD" verify "$PFH" >/dev/null || fail "the honest directory must verify"
"$FORGE" lie-missing "$PFH"
must_fail "holds another value than its missing one in column n" "$BIN" verify "$PFH"
must_fail "holds another value than its missing one in column n" "$AUD" verify "$PFH"
echo "   the engine's VERIFY and the auditor refuse it: a value its commitment does not cover is still one a reader reads"

echo "== FI: an ADD COLUMN of a name a live view reading the table holds (its text would bind the name to the new column),
   signed by the writer"
PFI=$WORK/fi; make_db "$PFI"
"$BIN" sql "$PFI" --nosync -c "CREATE TABLE u2 (id INT64 PRIMARY KEY, k INT64);" \
  -c "CREATE VIEW vk AS SELECT t.id, k FROM t JOIN u2 ON t.id = u2.id;" >/dev/null
"$FORGE" index-lie "$PFI" alter-view
must_fail "view vk reads table t and names k" "$BIN" verify "$PFI"   # the open's replay refuses it
must_fail "ADD COLUMN k of table t, which view vk reads and names" "$AUD" verify "$PFI"
echo "== FJ: a manifest whose schema history gives an added column another DEFAULT (it still ends at the table's schema),
   re-pointed and re-signed"
PFJ=$WORK/fj; make_db "$PFJ"
"$BIN" sql "$PFJ" --nosync -c "ALTER TABLE t ADD n INT64 NOT NULL DEFAULT 5;" -c "CHECKPOINT;" >/dev/null
"$FORGE" manifest-lie "$PFJ" default
must_fail "manifest schema of table t differs from the log" "$BIN" verify "$PFJ"
must_fail "the manifest's schema history differs from the log's" "$AUD" verify "$PFJ"
echo "   FI: the engine's replay and the auditor refuse the ADD; FJ: VERIFY and the auditor compare the history with the
   log's (the open took the manifest's: its old rows would read 6)"

echo "== FK: a SET NOT NULL of a column a live row holds NULL, and FL a DROP COLUMN of a column an index names (F1 stage
   4), each signed by the writer"
PFK=$WORK/fk; "$BIN" init "$PFK" >/dev/null
"$BIN" sql "$PFK" --nosync -c "CREATE TABLE t (id INT64 PRIMARY KEY, a INT64);" -c "INSERT INTO t VALUES (1, NULL), (2, 2);" \
  >/dev/null
"$BIN" verify "$PFK" >/dev/null && "$AUD" verify "$PFK" >/dev/null || fail "the honest directory must verify"
"$FORGE" index-lie "$PFK" alter-not-null
must_fail "column a of table t is NULL in a row" "$BIN" verify "$PFK"   # the open's replay refuses it
must_fail "SET NOT NULL of column a of table t, which a live row holds NULL" "$AUD" verify "$PFK"
PFL=$WORK/fl; "$BIN" init "$PFL" >/dev/null
"$BIN" sql "$PFL" --nosync -c "CREATE TABLE t (id INT64 PRIMARY KEY, a INT64);" -c "CREATE INDEX ta ON t (a);" \
  -c "INSERT INTO t VALUES (1, 1);" >/dev/null
"$FORGE" index-lie "$PFL" alter-drop-indexed
must_fail "index ta names column a" "$BIN" verify "$PFL"
must_fail "DROP COLUMN of a column index ta names" "$AUD" verify "$PFL"

echo "== FM: a signed INSERT whose DATE is 9999-12-31 + 1 (F3b): the replay and the auditor refuse the value"
PFM=$WORK/fm; "$BIN" init "$PFM" >/dev/null
"$BIN" sql "$PFM" --nosync -c "CREATE TABLE d (id INT64 PRIMARY KEY, dd DATE);" -c "INSERT INTO d VALUES (1, '9999-12-31');" >/dev/null
"$BIN" verify "$PFM" >/dev/null && "$AUD" verify "$PFM" >/dev/null || fail "the honest directory must verify"
"$FORGE" index-lie "$PFM" date-range
must_fail "date out of range" "$BIN" verify "$PFM"
must_fail "DATE out of range in column dd" "$AUD" verify "$PFM"

echo "== FN: a signed INSERT whose VARCHAR(4) holds 5 characters (F3c): the replay and the auditor refuse the value"
PFN=$WORK/fn; "$BIN" init "$PFN" >/dev/null
"$BIN" sql "$PFN" --nosync -c "CREATE TABLE v (id INT64 PRIMARY KEY, a VARCHAR(4));" -c "INSERT INTO v VALUES (1, 'abcd');" >/dev/null
"$BIN" verify "$PFN" >/dev/null && "$AUD" verify "$PFN" >/dev/null || fail "the honest directory must verify"
"$FORGE" index-lie "$PFN" varchar-long
must_fail "a value longer than VARCHAR(4)" "$BIN" verify "$PFN"
must_fail "a value longer than VARCHAR(4) in column a" "$AUD" verify "$PFN"

echo "== FO: a signed ADD COLUMN k VARCHAR(2) DEFAULT 'abc' (F3c): the replay and the auditor refuse the DEFAULT"
PFO=$WORK/fo; "$BIN" init "$PFO" >/dev/null
"$BIN" sql "$PFO" --nosync -c "CREATE TABLE v (id INT64 PRIMARY KEY, a INT64);" -c "INSERT INTO v VALUES (1, 1);" >/dev/null
"$BIN" verify "$PFO" >/dev/null && "$AUD" verify "$PFO" >/dev/null || fail "the honest directory must verify"
"$FORGE" index-lie "$PFO" alter-varchar-default
must_fail "bad DEFAULT" "$BIN" verify "$PFO"
must_fail "a value longer than VARCHAR(2) in column k" "$AUD" verify "$PFO"
echo "   the engine's replay and the auditor refuse each: SET NOT NULL by the live rows' payloads, DROP by the indexes"

echo "== FP, FQ, FR: a CREATE's DEFAULT (op 23) and a clock DEFAULT (F2a) breaking their rules, each signed"
PFP=$WORK/fp; make_db "$PFP"
"$FORGE" index-lie "$PFP" create-default-clock
must_fail "a bad column default" "$BIN" verify "$PFP"
must_fail "a clock DEFAULT its column's type does not take" "$AUD" verify "$PFP"
PFQ=$WORK/fq; make_db "$PFQ"
"$FORGE" index-lie "$PFQ" alter-clock-type
must_fail "that clock value is not of its type" "$BIN" verify "$PFQ"
must_fail "a clock DEFAULT its column's type does not take" "$AUD" verify "$PFQ"
PFR=$WORK/fr; "$BIN" init "$PFR" >/dev/null
"$BIN" sql "$PFR" --nosync -c "CREATE TABLE dv (id INT64 PRIMARY KEY, a TEXT, n INT64 DEFAULT 77);" \
  -c "INSERT INTO dv (id) VALUES (1);" -c "CHECKPOINT;" >/dev/null
"$BIN" verify "$PFR" >/dev/null && "$AUD" verify "$PFR" >/dev/null || fail "the honest directory must verify"
"$FORGE" manifest-lie "$PFR" create-default
must_fail "manifest schema of table dv differs from the log" "$BIN" verify "$PFR"
must_fail "the manifest's schema history differs from the log's" "$AUD" verify "$PFR"
echo "   FP a CREATE's clock DEFAULT on a column it does not suit (LOCALTIME on a TIMESTAMPTZ), FQ SET DEFAULT CURRENT_DATE
   on a TEXT column: the replay and the auditor refuse each; FR a manifest's version 1 DEFAULT another than the
   CREATE's (no version's hash covers it): VERIFY and the auditor refuse it"

echo "== FS, FT, FU: sequence ops and a manifest's sequence breaking their rules (F2a-2), each signed or re-pointed"
PFS=$WORK/fs; make_db "$PFS"
"$BIN" sql "$PFS" --nosync -c "CREATE SEQUENCE s;" -c "SELECT nextval('s');" -c "SELECT nextval('s');" >/dev/null
"$FORGE" index-lie "$PFS" seq-back
must_fail "mark goes back" "$BIN" verify "$PFS"
must_fail "mark goes back" "$AUD" verify "$PFS"
PFT=$WORK/ft; make_db "$PFT"
"$BIN" sql "$PFT" --nosync -c "CREATE TABLE ident (id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY, v TEXT);" \
  -c "INSERT INTO ident (v) VALUES ('a');" >/dev/null
"$FORGE" index-lie "$PFT" seq-drop-owned
must_fail "a column takes values from" "$BIN" verify "$PFT"
must_fail "DROP SEQUENCE of a column's IDENTITY" "$AUD" verify "$PFT"
PFU=$WORK/fu; "$BIN" init "$PFU" >/dev/null
"$BIN" sql "$PFU" --nosync -c "CREATE SEQUENCE fu_seq;" -c "SELECT nextval('fu_seq');" -c "CREATE TABLE z (id INT64 PRIMARY KEY);" \
  -c "CHECKPOINT;" >/dev/null
"$BIN" verify "$PFU" >/dev/null && "$AUD" verify "$PFU" >/dev/null || fail "the honest directory must verify"
"$FORGE" manifest-lie "$PFU" seq-state
must_fail "sequence fu_seq differs from the log" "$BIN" verify "$PFU"   # the snapshot open took the manifest's state
must_fail "the manifest's state differs from the log's" "$AUD" verify "$PFU"
echo "   FS a signed mark one increment back, FT a signed DROP SEQUENCE of an IDENTITY's: the replay and the auditor refuse
   each; FU a manifest's sequence one value on (aligned, in bounds): VERIFY and the auditor refuse it"

echo "== FV, FW, FX: CHECK constraints broken (F2b-1): a signed row failing one, a signed ADD CHECK a live row fails, a manifest's text"
PFV=$WORK/fv; "$BIN" init "$PFV" >/dev/null
"$BIN" sql "$PFV" --nosync -c "CREATE TABLE z (id INT64 PRIMARY KEY, a INT64 CHECK (a > 0), s TEXT);" \
  -c "INSERT INTO z VALUES (1, 2, 'x'), (2, 5, NULL);" >/dev/null
"$BIN" verify "$PFV" >/dev/null && "$AUD" verify "$PFV" >/dev/null || fail "the honest directory must verify"
cp -r "$PFV" "$WORK/fw"
"$FORGE" index-lie "$PFV" check-row
must_fail "violates check constraint z_a_check" "$BIN" verify "$PFV"   # the open's replay refuses it
must_fail "violates CHECK z_a_check" "$AUD" verify "$PFV"
PFW=$WORK/fw
"$FORGE" index-lie "$PFW" check-add
must_fail "check constraint forged of table z is violated by some row" "$BIN" verify "$PFW"
must_fail "ADD CHECK forged of table z, which a live row violates" "$AUD" verify "$PFW"
PFX=$WORK/fx; "$BIN" init "$PFX" >/dev/null
"$BIN" sql "$PFX" --nosync -c "CREATE TABLE z (id INT64 PRIMARY KEY, a INT64 CHECK (a > 0));" \
  -c "INSERT INTO z VALUES (1, 2);" -c "CHECKPOINT;" >/dev/null
"$BIN" verify "$PFX" >/dev/null && "$AUD" verify "$PFX" >/dev/null || fail "the honest directory must verify"
"$FORGE" manifest-lie "$PFX" check-text
must_fail "differ" "$BIN" verify "$PFX"   # the snapshot open took the manifest's CHECK
must_fail "differs from the log" "$AUD" verify "$PFX"
echo "   FV a signed INSERT of a row a CHECK refuses, FW a signed ADD CHECK a live row fails: the replay and the auditor
   refuse each; FX a manifest's version 1 CHECK of another text: VERIFY and the auditor refuse it"

echo "== FY, FZ: generated columns broken (F2c): a signed row whose generated value its expression does not give, a manifest's text"
PFY=$WORK/fy; "$BIN" init "$PFY" >/dev/null
"$BIN" sql "$PFY" --nosync -c "CREATE TABLE z (id INT64 PRIMARY KEY, a INT64, w INT64 GENERATED ALWAYS AS (a * 2) STORED);" \
  -c "INSERT INTO z (id, a) VALUES (1, 2), (2, 5);" >/dev/null
"$BIN" verify "$PFY" >/dev/null && "$AUD" verify "$PFY" >/dev/null || fail "the honest directory must verify"
cp -r "$PFY" "$WORK/fy2"
"$FORGE" index-lie "$PFY" gen-row
must_fail "generated column w holds another value than its expression gives" "$BIN" verify "$PFY"   # the open's replay
must_fail "holds another value in generated column w than its expression gives" "$AUD" verify "$PFY"
PFY2=$WORK/fy2
"$FORGE" index-lie "$PFY2" gen-update
must_fail "generated column w holds another value than its expression gives" "$BIN" verify "$PFY2"
must_fail "holds another value in generated column w than its expression gives" "$AUD" verify "$PFY2"
PFZ=$WORK/fz; "$BIN" init "$PFZ" >/dev/null
"$BIN" sql "$PFZ" --nosync -c "CREATE TABLE z (id INT64 PRIMARY KEY, a INT64, w INT64 GENERATED ALWAYS AS (a * 2) STORED);" \
  -c "INSERT INTO z (id, a) VALUES (1, 2);" -c "CHECKPOINT;" >/dev/null
"$BIN" verify "$PFZ" >/dev/null && "$AUD" verify "$PFZ" >/dev/null || fail "the honest directory must verify"
"$FORGE" manifest-lie "$PFZ" gen-text
must_fail "differ" "$BIN" verify "$PFZ"   # the snapshot open took the manifest's expression
must_fail "differs from the log" "$AUD" verify "$PFZ"
echo "   FY a signed INSERT and a signed UPDATE of a row whose generated column holds another value than its expression gives:
   the replay and the auditor refuse each; FZ a manifest's version 1 generation text another: VERIFY and the auditor refuse it"

echo "== GA, GB, GC: FOREIGN KEYs broken (F2b-2): a signed orphan, a signed delete of a referenced parent, a manifest's definition"
PGA=$WORK/ga; "$BIN" init "$PGA" >/dev/null
"$BIN" sql "$PGA" --nosync -c "CREATE TABLE p (id INT64 PRIMARY KEY, n TEXT);" \
  -c "CREATE TABLE c (id INT64 PRIMARY KEY, pid INT64 REFERENCES p ON DELETE CASCADE);" \
  -c "INSERT INTO p VALUES (1, 'a'), (2, 'b');" -c "INSERT INTO c VALUES (10, 1), (11, 2);" >/dev/null
"$BIN" verify "$PGA" >/dev/null && "$AUD" verify "$PGA" >/dev/null || fail "the honest directory must verify"
cp -r "$PGA" "$WORK/gb"
"$FORGE" index-lie "$PGA" fk-orphan
must_fail "violates foreign key c_pid_fkey: its parent key is not live" "$BIN" verify "$PGA"   # the open's replay
must_fail "violates foreign key c_pid_fkey: its parent key is not live" "$AUD" verify "$PGA"
PGB=$WORK/gb
"$FORGE" index-lie "$PGB" fk-delete
must_fail "violates foreign key constraint c_pid_fkey on table c" "$BIN" verify "$PGB"
must_fail "while a live row of table c references it by foreign key c_pid_fkey" "$AUD" verify "$PGB"
PGC=$WORK/gc; "$BIN" init "$PGC" >/dev/null
"$BIN" sql "$PGC" --nosync -c "CREATE TABLE p (id INT64 PRIMARY KEY);" \
  -c "CREATE TABLE c (id INT64 PRIMARY KEY, pid INT64 REFERENCES p ON DELETE CASCADE);" \
  -c "INSERT INTO p VALUES (1);" -c "INSERT INTO c VALUES (10, 1);" -c "CHECKPOINT;" >/dev/null
"$BIN" verify "$PGC" >/dev/null && "$AUD" verify "$PGC" >/dev/null || fail "the honest directory must verify"
"$FORGE" manifest-lie "$PGC" fk-def
must_fail "differ" "$BIN" verify "$PGC"   # the snapshot open took the manifest's definition
must_fail "differs from the log" "$AUD" verify "$PGC"
echo "   GA a signed INSERT of a child whose parent key is not live, GB a signed DELETE of a parent a live child references:
   the replay and the auditor refuse each; GC a manifest's version 1 FOREIGN KEY another: VERIFY and the auditor refuse it"

echo "== GD, GE: an ERASE excuses only its own deletes (F2b-2): a referenced parent's DELETE beside an ERASE of another version"
PGD=$WORK/gd; "$BIN" init "$PGD" >/dev/null
"$BIN" sql "$PGD" --nosync -c "CREATE TABLE p (id INT64 PRIMARY KEY, n TEXT);" \
  -c "CREATE TABLE c (id INT64 PRIMARY KEY, pid INT64 REFERENCES p ON DELETE CASCADE);" -c "CREATE TABLE x (id INT64 PRIMARY KEY);" \
  -c "INSERT INTO p VALUES (1, 'a'), (2, 'b');" -c "INSERT INTO c VALUES (10, 1), (11, 2);" \
  -c "INSERT INTO x VALUES (1);" -c "DELETE FROM x WHERE id = 1;" >/dev/null
"$BIN" verify "$PGD" >/dev/null && "$AUD" verify "$PGD" >/dev/null || fail "the honest directory must verify"
cp -r "$PGD" "$WORK/ge"
"$FORGE" index-lie "$PGD" fk-erase-other   # one commit: DELETE of p's row 1 (c's row 10 references it), ERASE of x's ended row
must_fail "violates foreign key constraint c_pid_fkey on table c" "$BIN" verify "$PGD"
must_fail "while a live row of table c references it by foreign key c_pid_fkey" "$AUD" verify "$PGD"
PGE=$WORK/ge
"$FORGE" index-lie "$PGE" fk-erase-named   # the same commit, its ERASE naming the deleted row itself: the control
"$BIN" sql "$PGE" -c "SELECT COUNT(*) FROM c;" >/dev/null || fail "the control's commit must replay (the open finishes its publish)"
"$BIN" verify "$PGE" >/dev/null && "$AUD" verify "$PGE" >/dev/null || fail "an ERASE of a referenced parent, its own delete, must verify"
echo "   GD a signed DELETE of a referenced parent beside an ERASE that names another version: the replay and the auditor
   refuse it; GE the same commit with the ERASE naming that parent (made as the writer makes one, its payload redacted)
   replays, publishes, and VERIFY and the auditor accept it"

echo "== HA, HB: UUID and BYTEA (F3d) broken, each signed: a 15-byte UUID, gen_random_uuid() on a TIMESTAMPTZ"
PHA=$WORK/ha; "$BIN" init "$PHA" >/dev/null
"$BIN" sql "$PHA" --nosync -c "CREATE TABLE hu (id INT64 PRIMARY KEY, u UUID NOT NULL);" \
  -c "INSERT INTO hu VALUES (1, 'a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11');" >/dev/null
"$BIN" verify "$PHA" >/dev/null && "$AUD" verify "$PHA" >/dev/null || fail "the honest directory must verify"
"$FORGE" index-lie "$PHA" uuid-short
must_fail "truncated UUID" "$BIN" verify "$PHA"
must_fail "row: truncated" "$AUD" verify "$PHA"
PHB=$WORK/hb; make_db "$PHB"
"$FORGE" index-lie "$PHB" create-default-uuid
must_fail "a bad column default" "$BIN" verify "$PHB"
must_fail "a clock DEFAULT its column's type does not take" "$AUD" verify "$PHB"
echo "   HA a signed INSERT whose UUID is 15 bytes (the row codec takes 16), HB a signed CREATE whose op 23 gives a
   TIMESTAMPTZ column gen_random_uuid() (kind 10, a UUID's alone): the replay and the auditor refuse each"

echo "== IA, IB: DECIMALs to 38 digits (F3e) broken: a signed row past its precision, a manifest's precision of 39"
PIA=$WORK/ia; "$BIN" init "$PIA" >/dev/null
"$BIN" sql "$PIA" --nosync -c "CREATE TABLE dw (id INT64 PRIMARY KEY, w DECIMAL(30,2) NOT NULL);" \
  -c "INSERT INTO dw VALUES (1, 9999999999999999999999999999.99);" >/dev/null
"$BIN" verify "$PIA" >/dev/null && "$AUD" verify "$PIA" >/dev/null || fail "the honest directory must verify"
cp -r "$PIA" "$WORK/ib"
"$FORGE" index-lie "$PIA" dec-range   # w 10^28: one past DECIMAL(30,2)'s 9999999999999999999999999999.99
must_fail "value exceeds DECIMAL(30,2)" "$BIN" verify "$PIA"
must_fail "value out of DECIMAL range in column w" "$AUD" verify "$PIA"
PIB=$WORK/ib
"$BIN" sql "$PIB" --nosync -c "CHECKPOINT;" >/dev/null
"$BIN" verify "$PIB" >/dev/null && "$AUD" verify "$PIB" >/dev/null || fail "the honest directory must verify"
"$FORGE" manifest-lie "$PIB" dec-precision
must_fail "manifest" "$BIN" verify "$PIB"
must_fail "schema: bad precision/scale" "$AUD" verify "$PIB"
echo "   IA a signed INSERT of a DECIMAL(30,2) of 10^28 (16 bytes, one past its precision): the replay and the auditor
   refuse it; IB a manifest whose schema gives w DECIMAL(39,2): VERIFY and the auditor refuse it"

echo "== JA, JB: INTERVAL (F3f) broken, each signed: a 15-byte INTERVAL, a CREATE whose key is an INTERVAL"
PJA=$WORK/ja; "$BIN" init "$PJA" >/dev/null
"$BIN" sql "$PJA" --nosync -c "CREATE TABLE ji (id INT64 PRIMARY KEY, iv INTERVAL NOT NULL);" \
  -c "INSERT INTO ji VALUES (1, '1 mon 2 days 03:04:05');" >/dev/null
"$BIN" verify "$PJA" >/dev/null && "$AUD" verify "$PJA" >/dev/null || fail "the honest directory must verify"
"$FORGE" index-lie "$PJA" iv-short
must_fail "row: truncated" "$BIN" verify "$PJA"
must_fail "row: truncated" "$AUD" verify "$PJA"
PJB=$WORK/jb; make_db "$PJB"
"$FORGE" index-lie "$PJB" create-interval-key
must_fail "a PRIMARY KEY column cannot be an INTERVAL" "$BIN" verify "$PJB"
must_fail "schema: bad PRIMARY KEY" "$AUD" verify "$PJB"
echo "   JA a signed INSERT whose INTERVAL is 15 bytes (the row codec takes 16), JB a signed CREATE whose key is an
   INTERVAL (deferred.md D26): the replay and the auditor refuse each"


echo "== KA-KG: ENUM types (F3g) broken, each signed or in the manifest: an ordinal past the labels, a CREATE of an unknown or a
   dropped type, a DROP TYPE under a live column, an ADD VALUE of a label held, a manifest's label the log never made, an
   ADD COLUMN's DEFAULT past the labels"
k_db() { # $1: a directory holding type kmood ('ka', 'kb', 'kc'), a dropped type, a table ke (id, m kmood NOT NULL) of a row
  "$BIN" init "$1" >/dev/null
  "$BIN" sql "$1" --nosync -c "CREATE TYPE kmood AS ENUM ('ka', 'kb', 'kc');" -c "CREATE TYPE kgone AS ENUM ('z');" \
    -c "DROP TYPE kgone;" -c "CREATE TABLE ke (id INT64 PRIMARY KEY, m kmood NOT NULL);" -c "INSERT INTO ke VALUES (1, 'kb');" >/dev/null
  "$BIN" verify "$1" >/dev/null && "$AUD" verify "$1" >/dev/null || fail "the honest directory must verify"
}
PKA=$WORK/ka; k_db "$PKA"
"$FORGE" index-lie "$PKA" enum-ord
must_fail "label of its ENUM type" "$BIN" verify "$PKA"
must_fail "holds no label of its ENUM type" "$AUD" verify "$PKA"
PKB=$WORK/kb; k_db "$PKB"
"$FORGE" index-lie "$PKB" create-enum-unknown
must_fail "ENUM type that is not live" "$BIN" verify "$PKB"
must_fail "ENUM type that is not live" "$AUD" verify "$PKB"
PKC=$WORK/kc; k_db "$PKC"
"$FORGE" index-lie "$PKC" create-enum-dropped
must_fail "ENUM type that is not live" "$BIN" verify "$PKC"
must_fail "ENUM type that is not live" "$AUD" verify "$PKC"
PKD=$WORK/kd; k_db "$PKD"
"$FORGE" index-lie "$PKD" enum-drop-used
must_fail "DROP of ENUM type" "$BIN" verify "$PKD"
must_fail "DROP TYPE kmood, a column of table ke" "$AUD" verify "$PKD"
PKE=$WORK/ke; k_db "$PKE"
"$FORGE" index-lie "$PKE" enum-add-dup
must_fail "ADD VALUE of a label" "$BIN" verify "$PKE"
must_fail "a label the type holds" "$AUD" verify "$PKE"
PKF=$WORK/kf; k_db "$PKF"
"$BIN" sql "$PKF" --nosync -c "CHECKPOINT;" >/dev/null
"$BIN" verify "$PKF" >/dev/null && "$AUD" verify "$PKF" >/dev/null || fail "the honest directory must verify"
"$FORGE" manifest-lie "$PKF" enum-label
must_fail "ENUM type kmood" "$BIN" verify "$PKF"
must_fail "ENUM type kmood in the manifest differs" "$AUD" verify "$PKF"
PKG=$WORK/kg; k_db "$PKG"
"$FORGE" index-lie "$PKG" enum-default-ord
must_fail "no label of its ENUM type" "$BIN" verify "$PKG"
must_fail "no label of its ENUM type" "$AUD" verify "$PKG"
echo "   KA a signed row whose ordinal is its type's label count, KB and KC a signed CREATE naming an unknown and a dropped
   type, KD a signed DROP TYPE under a live column, KE a signed ADD VALUE of a label the type holds, KG a signed ADD COLUMN
   whose DEFAULT is past the labels: the replay and the auditor refuse each; KF a manifest whose type holds a label the
   log never made: VERIFY and the auditor refuse it"

echo "== Z: a commit naming the other digest algorithm, re-signed by the writer (both ways round); META naming an unknown one"
for a in 1 2; do # explicit algorithms: under IMDB_DIGEST_ALG=2 make_db's would all be alg 2
  PZ=$WORK/z$a
  "$BIN" init "$PZ" --digest-alg "$a" >/dev/null
  "$BIN" sql "$PZ" --nosync -c "CREATE TABLE t (id INT64 PRIMARY KEY, u INT64 SUBJECT, memo TEXT);
     INSERT INTO t VALUES (1, 42, 'one'); CHECKPOINT; INSERT INTO t VALUES (2, 7, 'tail');" >/dev/null
  # the commit after the checkpoint: the snapshot open's checks stay as they were, the tail replays it
  "$FORGE" alg-flip "$PZ" "$("$BIN" info "$PZ" | awk '/^commit/ {print $2}')"
  must_fail "digest algorithm $((3 - a)), but this database's is $a" "$BIN" verify "$PZ"
  must_fail "digest algorithm $((3 - a)), but this database's is $a" "$AUD" verify "$PZ"
done
PM=$WORK/zm; "$BIN" init "$PM" >/dev/null
sed -i 's/^digest [12]$/digest 3/' "$PM/META"
must_fail "digest algorithm 3 is not one this version knows" "$BIN" verify "$PM"
must_fail "malformed digest algorithm" "$AUD" verify "$PM"
echo "   Z the algorithm byte of a signed commit flipped, either way, and META's unknown 3: the auditor refuses each,
   the engine at its open's replay (VERIFY's own check: t_round3 digest_alg_mismatch, under an open handle)"

echo "== VA-VE: view ops the log's rules forbid, each signed by the writer, alone in its commit (P2 S7, S7b)"
make_vdb() {
  make_db "$1"
  "$BIN" sql "$1" --nosync -c "CREATE VIEW v0 AS SELECT id, memo FROM t;" -c "CREATE VIEW v1 AS SELECT id FROM v0;" >/dev/null
}
for kind in drop-table name drop-named; do
  PV=$WORK/view-$kind; make_vdb "$PV"
  "$FORGE" view-lie "$PV" "$kind"
  case $kind in
    drop-table) we="which a live view names"; wa="which view v0 names" ;;
    name) we="takes a live table's or view's name"; wa="takes a live table's or view's name" ;;
    drop-named) we="which a live view names"; wa="which view v1 names" ;;
  esac
  must_fail "$we" "$BIN" verify "$PV"
  must_fail "$wa" "$AUD" verify "$PV"
done
for kind in deps type; do
  PV=$WORK/view-$kind; make_vdb "$PV"
  "$FORGE" view-lie "$PV" "$kind"
  must_fail "yields other columns or dependencies than it logged" "$BIN" verify "$PV"
  case $kind in deps) wa="tables and views, the log says" ;; type) wa="by its text and TEXT" ;; esac
  must_fail "$wa" "$AUD" verify "$PV"
done
echo "   VA a table dropped under a view, VB a view named as a table, VC a view dropped under another: both refuse;
   VD a view whose dependencies omit what its text reads, VE one whose column it types otherwise: the engine's
   re-bind and the auditor's own binder (P2 S7b) refuse both (design.md §5, Views)"


echo "== LA-LP: roles and grants (L) broken, each signed or in the manifest: a reserved name, a live role's name taken by a
   CREATE and by a RENAME, a payload entry not its commitment's, a redacted entry no ERASE names, an ALTER that changes
   nothing, a DROP of a role holding a privilege, a GRANT to a dropped role, on a dropped table, of bits held, a
   membership cycle, a manifest's grant another than the log's; stage 2: an ERASE of a live role's current name, one
   under another commitment, one naming part of a role's entries, an ERASE ROLE whose role's entries are still in the log"
l_db() { # $1: alice (LOGIN, a password, a member of staff), staff (SELECT on t), gone (dropped), gone2 (a password,
  # dropped); tables t and old (dropped)
  "$BIN" init "$1" >/dev/null
  "$BIN" sql "$1" --nosync -c "CREATE TABLE t (id INT64 PRIMARY KEY);" -c "CREATE TABLE old (id INT64 PRIMARY KEY);" \
    -c "CREATE ROLE alice LOGIN PASSWORD 'pw';" -c "CREATE ROLE staff;" -c "CREATE ROLE gone;" -c "DROP ROLE gone;" \
    -c "CREATE ROLE gone2 PASSWORD 'pw2';" -c "DROP ROLE gone2;" \
    -c "DROP TABLE old;" -c "GRANT SELECT ON t TO staff;" -c "GRANT staff TO alice;" -c "INSERT INTO t VALUES (1);" >/dev/null
  "$BIN" verify "$1" >/dev/null && "$AUD" verify "$1" >/dev/null || fail "the honest directory must verify"
}
l_case() { # $1 the forge's kind, $2 the engine's reason, $3 the auditor's
  local d=$WORK/l-$1; l_db "$d"
  "$FORGE" index-lie "$d" "$1"
  must_fail "$2" "$BIN" verify "$d"
  must_fail "$3" "$AUD" verify "$d"
}
l_case role-reserved "a role's name is malformed" "a role's name is malformed"                                     # LA
l_case role-taken "takes a live role's name" "takes a live role's name"                                             # LB
l_case role-rename-taken "takes a live role's name" "takes a live role's name"                                      # LC
l_case grant-dropped-role "names a role that is not live" "names a role that is not live"                           # LD
l_case grant-dropped-table "names a table or view that is not live" "names a table or view that is not live"         # LE
l_case drop-role-granted "role staff holds privileges" "DROP ROLE of a role holding a privilege or a membership"     # LF
l_case member-cycle "would close a cycle" "closes a cycle"                                                          # LG
l_case grant-held "not exactly those it adds" "not exactly those it changes"                                        # LH
l_case role-commitment "a role's name does not match its commitment" "a role's name is not its commitment's"        # LI
l_case role-redacted "redacted payloads that no ERASE authorises" "not authorised by any ERASE" # LK: stage 2, a debt never settled
l_case role-noop "ALTER ROLE of a field that changes nothing" "ALTER ROLE of a field that changes nothing"           # LL
l_case erase-role-live "an ERASE of a live role's current name or verifier" \
  "an ERASE of a live role's current name or verifier"                                                        # LM
l_case erase-role-commit "an ERASE's role entry with another commitment" \
  "an ERASE's role entry with another commitment"                                                             # LN
l_case erase-role-part "names part of role 4's entries" "names part of role 4's entries" # LO: gone2's name alone
PLP=$WORK/lp; l_db "$PLP" # LP: ERASE ROLE committed, its role's entries still in the log (the crash window, as B)
"$BIN" sql "$PLP" --nosync -c "CHECKPOINT;" >/dev/null
cp -a "$PLP" "$WORK/lp-pre"
"$BIN" sql "$PLP" --nosync -c "ERASE ROLE gone;" >/dev/null
cp "$PLP/log/$(ls "$PLP/log" | tail -1)" "$WORK/lp-pre/log/"
rm -rf "$PLP"; mv "$WORK/lp-pre" "$PLP"
must_fail "erasure incomplete" "$AUD" verify "$PLP"
must_fail "erasure incomplete" "$BIN" verify "$PLP"
PLJ=$WORK/lj; l_db "$PLJ"
"$BIN" sql "$PLJ" --nosync -c "CHECKPOINT;" >/dev/null
"$BIN" verify "$PLJ" >/dev/null && "$AUD" verify "$PLJ" >/dev/null || fail "the honest directory must verify"
"$FORGE" manifest-lie "$PLJ" grant-bits
must_fail "roles or grants differ from the log" "$BIN" verify "$PLJ" # LJ: the engine's catalog took the manifest's (a snapshot open)
must_fail "the manifest's roles or grants differ from the log's at its commit" "$AUD" verify "$PLJ"

echo "ALL REJECTION CHECKS PASSED"
