#!/usr/bin/env bash
# Builds seed corpora for the fuzzers from a real database (so the fuzzers
# start from valid frames, segments, manifests and DVs instead of having to
# discover magic numbers).   fuzz/make_corpus.sh [path/to/imagedb] [outdir]
set -euo pipefail
BIN=${1:-build/imagedb}
OUT=${2:-build-fuzz/corpus}
WORK=$(mktemp -d "${IMDB_TEST_TMP:-/tmp}/imdb-corpus.XXXXXX")
trap 'rm -rf "$WORK"' EXIT
D=$WORK/db
"$BIN" init "$D" --digest-alg 1 >/dev/null
SQL="
CREATE TABLE txns (id INT64 PRIMARY KEY, user_id INT64 SUBJECT, amount DECIMAL(12,2) NOT NULL, memo TEXT NOT NULL, at TIMESTAMP NOT NULL);
CREATE TABLE flags (k TEXT PRIMARY KEY SUBJECT, b BOOL NOT NULL, n INT64 NOT NULL);
CREATE TABLE meas (id INT64 PRIMARY KEY, u INT64 SUBJECT, x FLOAT64, note TEXT, ok BOOL NOT NULL);
INSERT INTO txns VALUES (1, 42, 19.99, 'coffee', '2026-10-01 08:00:00'), (2, 42, -5.25, 'café', '2026-10-01 08:05:00.5'), (3, 7, 100.00, '', '1970-01-01');
INSERT INTO flags VALUES ('a', true, 1), ('bb', false, -2);
INSERT INTO meas VALUES (1, 42, 1.5, NULL, true), (2, 42, -2.5e-3, 'n', false), (3, 7, NULL, NULL, true), (4, 9, 6.02e23, 'x', false);
INSERT INTO meas (id, u, ok) VALUES (5, 9, true);
CHECKPOINT;
CREATE INDEX txns_amount ON txns (amount);
CREATE INDEX meas_x ON meas (x);
CREATE UNIQUE INDEX txns_um ON txns (user_id, memo);
CREATE INDEX meas_ux ON meas (u, x, note);
UPDATE txns SET amount = 20.00 WHERE id = 1;
DELETE FROM txns WHERE id = 3;
UPDATE meas SET x = NULL, note = 'was 1.5' WHERE id = 1;
DELETE FROM meas WHERE id = 4;
CHECKPOINT;
DROP INDEX meas_x;
ERASE SUBJECT 7;
COMPACT txns PURGE BEFORE 3;
"
"$BIN" sql "$D" --nosync -c "$SQL" >/dev/null
mkdir -p "$OUT"/{frame,stream,segment,manifest,sql,codec,ed25519}
"${FORGE:-$(dirname "$BIN")/imdb-forge}" corpus "$D" "$OUT"   # frames, stream seeds, objects, rows
cp "$D/DURABLE" "$OUT/frame/durable"                            # the watermark record (fuzz_frame decodes it too)
# the same database under digest_alg 2, so the frame, stream and manifest harnesses see both
# algorithms' header bytes and lanes (prefixed: forge names its seeds by a counter)
D2=$WORK/db2; O2=$WORK/db2-out
"$BIN" init "$D2" --digest-alg 2 >/dev/null
"$BIN" sql "$D2" --nosync -c "$SQL" >/dev/null
mkdir -p "$O2"/{frame,stream,segment,manifest,sql,codec,ed25519}
"${FORGE:-$(dirname "$BIN")/imdb-forge}" corpus "$D2" "$O2"
for d in frame stream segment manifest codec; do for f in "$O2/$d"/*; do [ -e "$f" ] && cp "$f" "$OUT/$d/alg2-$(basename "$f")"; done; done
# tagged log segments for fuzz_tseg: 8 bytes naming the first seq (the harness takes them mod 1000, plus 1),
# then the segment as the writer left it (--nosync: groups of many frames; the last keeps its fill)
mkdir -p "$OUT/tseg"
for f in "$D"/log/*.ilg "$D2"/log/*.ilg; do
  first=$(basename "$f" .ilg | sed "s/^0*//"); v=$(( (first - 1) % 1000 )); i=0
  { while [ $i -lt 8 ]; do printf "\\$(printf %03o $(( (v >> (8 * i)) & 255 )))"; i=$((i + 1)); done; cat "$f"; }     > "$OUT/tseg/$(basename "$(dirname "$(dirname "$f")")")-$(basename "$f")"
done
# writer epochs: a key rotation, then a promotion (a kind-3 frame, root-certified) on a replica
E=$WORK/epochs; ER=$WORK/epochs-r; EO=$WORK/epochs-out
ROOT=$("$BIN" root-key "$WORK/root.key" 2>/dev/null)
"$BIN" init "$E" --root "$ROOT" >/dev/null
"$BIN" sql "$E" --nosync -c "CREATE TABLE t (id INT64 PRIMARY KEY, u INT64 SUBJECT, s TEXT); INSERT INTO t VALUES (1, 42, 'a');" >/dev/null
"$BIN" rotate-key "$E" >/dev/null
"$BIN" sql "$E" --nosync -c "INSERT INTO t VALUES (2, 7, 'b');" >/dev/null
"$BIN" init-replica "$ER" "$E" >/dev/null
"$BIN" ship "$E" | "$BIN" apply "$ER" >/dev/null 2>&1
"$BIN" promote "$ER" --root-key "$WORK/root.key" --old-writer-stopped >/dev/null
"$BIN" sql "$ER" --nosync -c "INSERT INTO t VALUES (3, 42, 'c');" >/dev/null
mkdir -p "$EO"
"${FORGE:-$(dirname "$BIN")/imdb-forge}" corpus "$ER" "$EO"
for d in frame stream; do for f in "$EO/$d"/*; do cp "$f" "$OUT/$d/epochs-$(basename "$f")"; done; done
cp "$ER/WRITERS" "$OUT/frame/writers"
i=0
for q in "SELECT COUNT(*), SUM(amount) FROM txns AS OF 3 WHERE user_id = 42 AND amount BETWEEN 1 AND 2.5" \
         "INSERT INTO t (a, b) VALUES (1, 'x''y'), (-2, TIMESTAMP '2026-01-01'), (\$1, true)" \
         "CREATE TABLE t (id INT64 PRIMARY KEY, u BIGINT SUBJECT, d DECIMAL(18,4), s TEXT, b BOOL, ts TIMESTAMP)" \
         "UPDATE t SET a = 1.5, s = 'x' WHERE id != 3 AND s >= 'a'" "ERASE FROM t WHERE memo = 'pii'" \
         "SHOW DIGEST t SUBJECT 'alice' AS OF 9" "COMPACT t PURGE BEFORE 10" "SELECT u, MAX(s) FROM t GROUP BY u LIMIT 5" \
         "CREATE TABLE m (id INT64 PRIMARY KEY, x DOUBLE PRECISION NOT NULL, y FLOAT, s TEXT NULL)" \
         "SELECT COUNT(x), SUM(x) FROM m WHERE s IS NULL AND y IS NOT NULL AND x BETWEEN -1e300 AND 2.5E-3" \
         "INSERT INTO m VALUES (1, 6.02e23, NULL, NULL), (2, -0.0, 1e-320, 'z')" \
         "CREATE INDEX m_y ON m (y)" "DROP INDEX m_y" "SHOW INDEXES" "CREATE UNIQUE INDEX m_sx ON m (s, x)" \
         "SELECT COUNT(*), MIN(x) FROM m WHERE s = 'z' AND x BETWEEN -1 AND 1" \
         "SELECT a.id, b.s FROM t AS a LEFT OUTER JOIN m AS b ON a.id = b.id AS OF 4 WHERE a.u = 42 AND b.s IS NULL LIMIT 3" \
         "SELECT x.u, COUNT(*), MAX(y.s) FROM t AS x INNER JOIN t AS y ON x.u = y.u GROUP BY x.u" \
         "SELECT * FROM t WITH (NOLOCK) JOIN m ON t.id = m.id" "SELECT * FROM t RIGHT JOIN m ON t.id = m.id" \
         "SET join_plan = index" "SET join_plan = hash" "SET join_plan = nested"; do
  printf '%s' "$q" > "$OUT/sql/q$i"; i=$((i+1))
done
printf '2026-10-20 13:45:00.123456' > "$OUT/codec/ts"; printf -- '-922337203685477.5808' > "$OUT/codec/dec"
printf '1.7976931348623157e308' > "$OUT/codec/f64max"; printf -- '-4.9e-324' > "$OUT/codec/f64sub"
printf 'caf\xc3\xa9 \xf0\x9f\x98\x80 \xed\x9f\xbf' > "$OUT/codec/utf8"
# ed25519 seeds: RFC 8032 test 1 to verify (valid, and with S's high bits cleared), the
# same seed to sign, and the identity as key and R with S = 0 (an edge encoding)
hx() { printf "$(printf '%s' "$1" | sed 's/../\\x&/g')"; }
pk=d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a
sig=e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b
seed=9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60
id=0100000000000000000000000000000000000000000000000000000000000000
{ hx 00; hx $pk; hx $sig; } > "$OUT/ed25519/verify"
{ hx 02; hx $pk; hx $sig; printf 'x'; } > "$OUT/ed25519/verify-low-s"
{ hx 01; hx $seed; hx $sig; printf 'commit descriptor'; } > "$OUT/ed25519/sign"
{ hx 00; hx $id; hx $id; hx $(printf '%064d' 0); printf 'x'; } > "$OUT/ed25519/identity"
# batch seeds (mode bit 2): 9 valid signatures from a seed (records of zeros: nothing XORed), and
# the same with one corrupted byte in record 5
zeros=$(printf '%0128d' 0)
brec() { for i in $(seq 0 8); do if [ "$i" = "$1" ]; then hx 01; hx "$(printf '%0126d' 0)"; else hx "$zeros"; fi; hx "$(printf '%016x' "$i")"; done; }
{ hx 05; hx $seed; brec -1; } > "$OUT/ed25519/batch-valid"
{ hx 05; hx $seed; brec 5; } > "$OUT/ed25519/batch-one-bad"
echo "ed25519 seeds: $(ls "$OUT/ed25519" | wc -l)"
# WRITERS for fuzz_frame: the keys its entries are proven from (writer, root), then the file
idt=$("$BIN" identity "$ER")
{ hx "$(printf '%s\n' "$idt" | awk '/^writer /{print $2}')"; hx "$(printf '%s\n' "$idt" | awk '/^root /{print $2}')"
  cat "$ER/WRITERS"; } > "$OUT/frame/writers"
echo "corpus: $(find "$OUT" -type f | wc -l) seeds in $OUT"
