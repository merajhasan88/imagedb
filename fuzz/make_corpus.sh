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
         "SET join_plan = index" "SET join_plan = hash" "SET join_plan = nested" \
         "UPDATE acct SET balance = balance - 100, n = -(n % 7) WHERE id = 7 AND balance * 2 >= 1.5e0 + \$1" \
         "SELECT g, SUM(qty * price) / COUNT(*), MAX(a - b) * 1.0, -9223372036854775808 / -1 FROM s GROUP BY g" \
         "INSERT INTO t VALUES (1 + 2 * 3, (4 - 5) / 6, 0.0000000000000000000000000000000000001 * 10, -(-(1)))" \
         "SELECT ((((a)))) + 1, b * 2 - c / 3 FROM t WHERE a + b IS NOT NULL AND 7 = id AND g <= -1.25 AND a BETWEEN b * 2 AND c / 3" \
         "SELECT a > 1 OR NOT k, NOT (b BETWEEN 1 AND 2) FROM t WHERE (a = 0 OR 10 / a > 1) AND NOT (k OR b IS NULL) OR TRUE" \
         "SELECT DISTINCT g, a * 2 FROM t WHERE a > 0 ORDER BY 2 DESC NULLS FIRST, g ASC NULLS LAST LIMIT 5 OFFSET 2" \
         "SELECT g, AVG(price), COUNT(*) FROM s GROUP BY g HAVING AVG(qty) > 1.5 OR NOT COUNT(*) < 2 ORDER BY SUM(qty) OFFSET 1" \
         "SELECT id, UPPER(TRIM(s)) AS who, COALESCE(s, '-'), CASE WHEN a > 1 THEN 'x' ELSE 'y' END, CAST(a AS TEXT) || 'z' FROM t WHERE s LIKE 'a%' ESCAPE '!' AND g NOT IN (1, 2, 3)" \
         "SELECT 1 + 2, ROUND(2.5, 1), LENGTH('abc'), CASE g WHEN 1 THEN NULLIF(a, 0) END AS c" \
         "SELECT g, LOWER(s), COUNT(DISTINCT a), SUM(a) FILTER (WHERE a > 0) FROM t GROUP BY g, LOWER(s) HAVING COUNT(*) > 1" \
         "SELECT * FROM t FULL OUTER JOIN u USING (id, g)" "SELECT t.id FROM t CROSS JOIN u" \
         "SELECT t.id FROM t, u WHERE t.id = u.tid AND t.g = u.v" "SELECT t.id FROM t RIGHT JOIN u ON t.id = u.tid AND (t.g > u.v OR u.v IS NULL)" \
         "WITH a AS (SELECT id, g FROM t WHERE g > 1), b AS (SELECT g, COUNT(*) AS n FROM a GROUP BY g) SELECT * FROM b JOIN (SELECT id AS g FROM u) AS c ON b.g = c.g" \
         "SELECT id FROM t WHERE id IN (SELECT tid FROM u WHERE EXISTS (SELECT 1 FROM w WHERE w.x = (SELECT MAX(x) FROM w))) AND NOT EXISTS (SELECT 1 FROM u) OR a > (SELECT AVG(a) FROM t)" \
         "UPDATE t SET g = (SELECT MAX(g) FROM t) WHERE id NOT IN (SELECT tid FROM u)" "INSERT INTO t VALUES ((SELECT MAX(id) FROM t) + 1, 'x')" \
         "DELETE FROM t WHERE g = (SELECT MIN(g) FROM (SELECT g FROM t) AS q)" "EXPLAIN SELECT COUNT(*) FROM (SELECT id FROM t) AS q" \
         "SELECT * FROM (SELECT * FROM (SELECT * FROM (SELECT * FROM (SELECT * FROM t) AS a) AS b) AS c) AS d" \
         "SELECT AVG(f) FROM t HAVING COUNT(*) BETWEEN 1 AND 10 OFFSET 0 LIMIT 0"; do
  printf '%s' "$q" > "$OUT/sql/q$i"; i=$((i+1))
done
# expr seeds (fuzz_expr.c): type a, type b, scale a, scale b, 16 bytes each, op, a column's type, precision, scale,
# then a DECIMAL literal's text: INT64_MIN / -1; two 38-digit DECIMALs added; a FLOAT64 by an INT64 past 2^53
mkdir -p "$OUT/expr"
printf '\0\0\0\0\0\0\0\0\0\0\0\200\0\0\0\0\0\0\0\0\377\377\377\377\377\377\377\377\377\377\377\377\377\377\377\377\3\0\5\2-12.345' > "$OUT/expr/min-div"
printf '\1\1\46\46\377\377\377\377\377\377\377\377\377\377\377\377\377\377\377\177\377\377\377\377\377\377\377\377\377\377\377\377\377\377\377\177\0\1\21\2.5' > "$OUT/expr/dec-add"
printf '\2\100\0\0\0\0\0\0\0\0\360\77\0\0\0\0\0\0\0\0\1\0\0\0\0\0\40\0\0\0\0\0\0\0\0\0\2\2\5\1-0' > "$OUT/expr/flt-int"
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
# a backup for fuzz_backup, made with its fixed key (32 bytes of 'B'): the prologue, sealed chunks, two parts (a snapshot's
# seed, then the commits after it) and the summary
mkdir -p "$OUT/backup"
printf 'BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB' > "$WORK/fuzz-backup.key"
chmod 0400 "$WORK/fuzz-backup.key"
"$BIN" backup "$D" --key "$WORK/fuzz-backup.key" --out "$OUT/backup/full.bak" >/dev/null
echo "corpus: $(find "$OUT" -type f | wc -l) seeds in $OUT"
