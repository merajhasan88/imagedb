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

echo "== W, X: a manifest breaking a version-4 rule, re-pointed and re-signed so only that rule refuses it"
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

echo "== Y: an INSERT repeating a live row's key of a unique index, its state digest right, signed by the writer"
PY=$WORK/y; make_db "$PY"
"$BIN" sql "$PY" --nosync -c "CREATE UNIQUE INDEX t_memo ON t (memo);" >/dev/null
"$FORGE" index-lie "$PY" unique-dup
must_fail "duplicate key in unique index" "$BIN" verify "$PY"   # the replay of the log's tail refuses it
must_fail "share a key of unique index" "$AUD" verify "$PY"
echo "   Y a duplicate under a unique index: the engine's replay and the auditor refuse it"

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

echo "ALL REJECTION CHECKS PASSED"
