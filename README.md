# imagedb

A C11 and x86-64 assembly database prototype in which the database and the
data lake are one storage: a signed, hash-chained commit log drives an MVCC
row store, deterministic columnar lake snapshots, replicas and an independent
C auditor. One authoritative history drives every representation.

**Status:** round 3, with the external review of 2026-10-22 and focused fixes
(docs/review-2026-10-22.md); an experimental engine, not a production database.
The review records current validation and remaining risks, including overlapping
writers during promotion and recovery with a stale watermark.
docs/review-2026-10-27.md integrates the review of 2026-10-26; deferred.md tracks
future work, and design.md explains the design. These documents are kept by the
author, not in this repository (below).

**The on-disk format is not frozen yet:** a later version may not open a database
made by this one (deferred.md D8, item 6). Do not keep data you need in it.

## Consistency contract

Compare views at the **same commit of the same database**. Every view of one
commit (index and scan paths, the lake files, a replica at that commit, the
auditor) holds exactly the same row versions, and a 32-byte digest shows it.
But views are not all at the latest commit:

- the lake segments describe the last published `LAKE_HEAD`, which lags the
  live database until the next CHECKPOINT (or never, with `imagedb sql
  --lake-sync`, which checkpoints after every change: priced, see
  docs/plan-round3.md);
- a replica is at the last commit it applied;
- engine `cross_check` compares two access paths of the engine, in memory; it
  is not an independent read of the files.

SELECT results print the commit they were answered at (`at commit N`); `SET
identity = on` prints the whole read point (database, commit, its hash and
state digest, the lake snapshot), and C callers find it in `imdb_result`. `SET
min_commit = N` makes a session's reads refuse a copy that has not reached N
(read-your-writes across a primary and its replicas). The auditor answers
*from files only* at the latest durable commit: the lake snapshot plus the
authenticated log tail after it (`--as-of N` for another commit, `--lake` for
the snapshot alone), and says which. Readers of the lake files (a read-only
open, the auditor) pin the generation they read (`pins/`, a lock the kernel
drops when they exit), so the writer's GC keeps it while they read, within
bounds; an ERASE revokes pins of older generations, and a reader whose
generation went starts again at the current one. A digest alone does not identify the
database, schema or history; the **view token** does: `SHOW IDENTITY` (engine)
and `imagedb-audit identity` (files) print SHA-256 over the db id, commit,
chain head and each table's schema, history horizon, live count and digest, so
equal tokens check this equivalence subject to the digest's cryptographic
assumptions. They do not prove that the commit is the newest or that erased
bytes are absent from every storage location.
Signatures prove who wrote a commit; the auditor checks that what was written
is right.

## Build and quickstart

```sh
make                    # gcc or clang, make, NASM; the engine links only libc and pthread
make NOASM=1            # without the NASM kernels (make clean when switching)
build/imagedb init /data/p
build/imagedb sql /data/p
```

```sql
CREATE TABLE txns (id INT64 PRIMARY KEY, user_id INT64 SUBJECT,
                   amount DECIMAL(12,2), memo TEXT, at TIMESTAMP);
INSERT INTO txns VALUES (1, 42, 19.99, 'coffee', '2026-10-01 08:00:00');
CHECKPOINT;
SET cross_check = on;
SELECT COUNT(*), SUM(amount) FROM txns WHERE user_id = 42;
SELECT * FROM txns AS OF 2;
SHOW DIGEST txns SUBJECT 42;
ERASE SUBJECT 42;
VERIFY;
```

Commits are fdatasynced by default. `--nosync` drops that promise until a
clean close (which syncs them; `imagedb sql` exits 1 and says so when the
closing sync could not run, and `imdb_close` returns `IMDB_ERR_IO`) or a
CHECKPOINT (the lake never names a commit the log could lose); a crash can lose
recent commits, and the next open says which.

The database lives in memory (the log and the lake are its durable copies).
`--mem-limit BYTES` (K, M or G suffix) gives it a budget: a write that would
grow it past the budget is refused before anything is written, while DELETE,
CHECKPOINT, COMPACT ... PURGE and ERASE are never refused, and an open always
succeeds. `SHOW MEMORY` shows what it holds by kind. A query result is capped at
1 GiB (a quarter of the budget when one is set): add LIMIT.

`--retain-history COMMITS` purges history older than the last COMMITS commits
automatically, on the primary, with a logged COMPACT ... PURGE that replicas
replay. It runs once a table has ended at least as many versions as it holds
live (and at least 4,096), and never reaches what an open transaction can
still read. It is off by default, because it removes AS OF history. It returns
the history's row payloads (about 16% of the per-update memory with typical
rows); every update still leaves a version entry, a tombstone once purged,
until log retirement exists.

## Durability and recovery

- The writer keeps a **durable watermark** (`DURABLE`): the last commit whose
  fdatasync returned. It decides what the end of the log means. A short or
  zero-filled final frame is an append that never finished and is truncated
  at the next writable open. A complete final frame that fails its checksum
  at or below the watermark is damage to an acknowledged commit: every open
  refuses, with every byte kept. A log that ends before the watermark has
  lost acknowledged commits and is refused too.
- By default DURABLE is not fsynced per commit, so after an OS crash it can
  lag an acknowledged commit. A complete but damaged final frame **past** it
  is therefore either an append that never finished or an acknowledged commit
  damaged later, and nothing can tell which: every open refuses it (read-only
  too) and `imagedb recover` decides. Nothing is dropped automatically.
- `--durable-ack` (`sql`, `apply`; `imdb_open_opts.durable_ack`) fsyncs DURABLE
  before each commit returns and marks it strict. A damaged final frame past a
  strict watermark was never acknowledged, and the next writable open truncates
  it. It costs one more device flush per commit (measured here: 6.7 ms instead
  of 3.4 ms for a one-row commit, 9.2 ms instead of 5.9 ms for 100 rows). If the
  DURABLE write fails, the commit returns an error (it reached the log but is
  not acknowledged) and the handle stops.
- `imagedb recover <dir>` shows such damage. Restore the segment from a
  replica to keep the commits, or run
  `imagedb recover <dir> --discard-tail --save FILE` to drop them explicitly
  (their bytes go to FILE first; put FILE outside the data directory, since a
  stray file in `log/` stops the next open). If a dropped commit was an ERASE whose
  redaction had already run, only restoring it from a replica works: the log
  would hold redactions that nothing authorises. A replica that had already
  received the dropped commits now holds commits the primary does not: its
  next apply fails the chain check (it is detected, never silent), so rebuild
  that replica, or restore the primary from it instead.
- A writable open fdatasyncs whatever a crashed writer left past the
  watermark before treating it as committed, and removes a log rewrite's
  `.tmp` left by a crash (readers skip it). A failed fsync or fdatasync stops
  the handle (fail-stop): reopen, and the open decides from the disk.
- CHECKPOINT and COMPACT that committed but could not publish the lake return
  success with a warning and mark the handle failed: reopen; do not retry as
  if they had rolled back. A GC that cannot remove old lake objects only
  warns; it is retried at the next publication and at open.
- `--anchor FILE` (on another device or host) makes open, VERIFY and the auditor
  check the directory against the retained signed anchor; an older or conflicting
  history is refused, and `--accept-rollback` continues from it deliberately.
  The anchor is not fsynced per commit and can lag. An absent anchor at open
  provides no rollback evidence. An active writer stops if its anchor
  becomes unreadable or invalid. A writable open with `--anchor FILE` also
  holds a lock on `FILE.lock` for its lifetime: one writer per anchor on a
  host (a second one, or a promotion, is refused while it runs).
- Snapshot open authenticates the published manifest and replays the log
  tail. Older history (AS OF TIMESTAMP, SHOW LOG) is authenticated by its
  hash chain up to the signed snapshot commit. VERIFY and the auditor check
  the whole log.

## Replication and auditing

```sh
build/imagedb init-replica /data/r /data/p
build/imagedb ship /data/p | build/imagedb apply /data/r      # or --follow, over ssh
build/imagedb-audit count /data/r txns user_id=42    # COUNT(*) and SUM of the value columns, from files only
build/imagedb-audit verify /data/r
```

The auditor's FLOAT64 sums are exact, like the engine's, by a different method
(Shewchuk partials in extended precision against the engine's integer
superaccumulator). The two agree bit for bit, out-of-range results included.

- Commits are signed with Ed25519. Only the primary holds `signing.key`;
  replicas pin the public key from META and cannot forge commits. The stream
  reader authenticates each frame's signed descriptor before decoding it.
  Replay and VERIFY check signatures in batches of 64 (about 4.8x fewer cycles
  per signature; a failed batch is rechecked one by one, so rejections are exact).
- The state digest's algorithm is chosen when a database is made: `imagedb init
  --digest-alg 2` (the default since 2026-10-26: elements by ChaCha20, the
  digest a tree of SHA-256, see design.md §4) or `--digest-alg 1` (MGF1-SHA256,
  as every earlier directory has). META and every commit name it, a replica
  takes its primary's, and a commit naming the other is refused everywhere.
  `imagedb info` prints it.
- `ship` sends nothing past the primary's durable watermark. With normal sync,
  those frames have passed fdatasync. Under `--nosync` the watermark does not
  wait for the disk, so a replica can hold commits the primary loses in a crash.
- A replica appends a commit to its log before publishing its lake objects,
  LAKE_HEAD or GC.
- A stream can carry rows whose payload was erased, ahead of the ERASE that
  authorises it. If the stream stops in between, apply returns
  `IMDB_ERR_AUTH`, keeps what it applied, publishes no lake and refuses reads
  until the next apply resumes from the replica's commit.
- Read-only handles cannot apply streams. C callers must call
  `imdb_check_history` before snapshot lookups or scans.
- `follow` keeps a replica applying and acknowledging, signed with the
  replica's own key; the primary allowlists it once:

  ```sh
  build/imagedb replica-add /data/p r1 "$(build/imagedb replica-key /data/r)"
  build/imagedb follow /data/r -- ssh p imagedb ship /data/p --follow --acks --after {after}
  build/imagedb sql /data/p -c "SET sync_replicas = 1;" -c "INSERT ..."   # waits; the status says the outcome
  build/imagedb sql /data/p -c "SHOW REPLICAS;" -c "SHOW ERASURE;"
  ```

  An acknowledgement says the replica holds the commit durably and through
  which commit its ERASE cleanup is complete. It is signed over the shipping
  session's random challenge, so one from another session never counts. A
  replica with another history is recorded and refused. A synchronous commit
  reports its outcome in the statement's status and in `SHOW REPLICATION`:
  confirmed by k replicas, or unknown after `sync_timeout_ms` (default 10 s,
  with a warning; the commit stands, it is durable here). Query a following
  replica with `imagedb sql /data/r --read-only`.
- Acknowledgements are statements about the past: `SHOW REPLICAS` and `SHOW
  ERASURE` give each one's age. A replica restored from an older copy keeps its
  key but has lost acknowledged commits: re-enrol it with
  `imagedb replica-key /data/r --new` and `replica-add ... --replace`. If you
  do not, its next acknowledgement goes back and the primary refuses it ("went
  back") until you do. `SHOW ERASURE` keeps the completion states apart: this
  database, each replica's last report, backups and copies (not tracked), and
  freed disk blocks (not guaranteed).
- Writer keys rotate and replicas get promoted through logged commits that every
  verifier follows:

  ```sh
  build/imagedb rotate-key /data/p                          # a new key, signed in by the old one
  build/imagedb root-key /offline/root.key                  # once, at setup; prints its public key
  build/imagedb init /data/p --root <that key>              # promotions need the root key in META
  build/imagedb promote /data/r --root-key /offline/root.key --anchor /shared/p.anchor
  build/imagedb promote /data/r --root-key /offline/root.key --old-writer-stopped  # no anchor
  ```

  A follower of the promoted writer refuses the old key from then on. With
  `--anchor`, promotion takes the anchor's writer lock, so it is refused while
  the old writer runs on that host; it refuses an anchor that shows another
  promotion, and old-writer commits past its cut unless `--abandon` drops them;
  it then publishes the new epoch to the anchor, and the old directory no longer
  opens with it. Without an anchor, `--old-writer-stopped` is your word, and
  nothing checks it. The root key's ledger (`root.key.ledger`, keep it with the
  key) locks and durably reserves each epoch once. Even an identical retry is
  refused: a restored copy has the same replica identity but could generate a
  different writer key. After an interrupted attempt, establish that no copy
  completed the promotion, stop all promoters, then remove the unused reservation
  by hand. Never replace or unlink a live ledger. The
  lock is per host: across hosts sharing an anchor, an old writer still running
  elsewhere is stopped at its next commit that reads the new epoch, but the
  window is not closed. **Stop and fence off the old writer before promoting**;
  this implementation does not provide exclusive failover across hosts.

## Erasure

DELETE keeps history. COMPACT ... PURGE removes old payloads from the lake but
keeps tombstones and the log. ERASE removes the targeted payloads from every
file imagedb manages (log, lake objects) and from its memory (buffers grow by
copy-and-wipe, never `realloc`; doomed transactions drop their writes), and a
replica applies the same ERASE. It reports cleanup as pending until the log
rewrite, the lake publication and the GC have all finished. It cannot reach
backups, exported results, disconnected replicas, freed device blocks or what
a client holds.

## Supported scope

One process and principal, one engine thread with worker parallelism, many
interleaved sessions. SNAPSHOT and READ COMMITTED transactions, statement
rollback, savepoints, `WITH (NOLOCK)` and optimistic `SELECT ... FOR UPDATE`
(first committer wins). SERIALIZABLE is refused; snapshot write skew is
possible.

Types: INT64, DECIMAL, TEXT, BOOL, TIMESTAMP, finite FLOAT64 (exact SUM,
rounded once) and nullable non-key columns. Comparisons with NULL, including
NULL parameters, are refused: use IS NULL / IS NOT NULL. The
lake format is imagedb's own; Parquet, other platforms and the desktop client
are deferred (deferred.md).

Ordered indexes:

```sql
CREATE INDEX t_amount ON t (amount);
CREATE INDEX t_user_at ON t (user_id, at);      -- up to 4 columns, in key order
CREATE UNIQUE INDEX t_email ON t (email);
DROP INDEX t_amount;
SHOW INDEXES;
```

- An index covers 1 to 4 columns of any types, and index names are unique per
  database.
- CREATE INDEX and DROP INDEX each commit on their own, outside an explicit
  transaction.
- An index serves equalities on its first columns and, after them, an equality
  or a range on the next one (`=`, `<`, `<=`, `>`, `>=`, `BETWEEN`); an index on
  `(user_id, at)` serves `user_id = 7 AND at >= '2026-10-01'`, not `at` alone.
  Such a query reads through it (path `index(ordered)`) when no primary-key or
  subject equality applies, the index with the most equalities first. Each
  row it returns passes the usual visibility and predicate checks.
- When every predicate and every item reads columns the index holds, and the
  query asks only for COUNT(*) or aggregates of them (COUNT, SUM, MIN, MAX),
  plain or grouped by one of them, the index answers alone (path
  `index(ordered, only)`): no row is read. Not for a TEXT column, whose index
  key is an 8-byte prefix, nor for a nullable column after the first, whose
  NULL the key cannot tell from the type's lowest value (declare it NOT NULL).
- The one exception: a plain SUM or COUNT over a range that covers much of a
  checkpointed table runs on the vectorised scan (path `scan`) when that is
  estimated to be cheaper. `SET access_path = ordered` forces the index.
- Negations (`!=`), `IS NULL` and `IS NOT NULL` are never what chooses an
  index: alone they use the scan, and next to a predicate an index serves they
  are checked on each row it returns. A row whose first indexed column is NULL
  is not in the index; one with a NULL in a later column is, so
  `user_id = 7` finds the rows whose `at` is NULL.
- **UNIQUE:** no two live rows may hold the same key. A row with a NULL in any
  of the columns is exempt, as in SQL. A duplicate is refused at the
  statement (`CONSTRAINT`); a key that another session committed after this
  transaction's snapshot fails the statement with `CONFLICT`, so a retry sees
  it. CREATE UNIQUE INDEX over live duplicates is refused (SHOW INDEXES says
  `yes` or `no` in its TEXT column `unique`). Every replay
  (open, replica) and the independent auditor check it again.
- The index structures are rebuilt at open and kept current on replicas; only
  the definitions are logged.

Joins:

```sql
SELECT o.id, c.name FROM orders AS o JOIN customers AS c ON o.cust = c.id WHERE o.amount > 10;
SELECT c.name, COUNT(*) FROM customers AS c LEFT JOIN orders AS o ON c.id = o.cust GROUP BY c.name;
SELECT c.id FROM customers AS c LEFT JOIN orders AS o ON c.id = o.cust WHERE o.id IS NULL;
```

- Two tables, INNER or LEFT [OUTER], on one equality of two columns of one type
  (a DECIMAL's scale included); a NULL key matches nothing. Qualify a column by
  its table or its alias (`AS`) when both tables have it. RIGHT, FULL and CROSS
  joins, a third table, AND or OR in ON (filter in WHERE) and FOR UPDATE are
  refused, each with its reason.
- Both tables are read at one snapshot (AS OF too). Each uses its own index or
  scan for its own WHERE predicates; under LEFT a predicate on the second table
  applies after the join, so the third query lists the customers without orders.
- Rows come in the first table's primary-key order, then the second's, a
  NULL-extended row last. Aggregates and GROUP BY work as on one table.
- Two plans. The hash join (path `join(build 2)`) hashes the second table after
  its own predicates and probes it with the first table's rows. The index
  nested-loop join (`join(index 2)`) looks up, for each row of the first
  table, the matching rows of the second through its primary key, its subject
  column or an index whose first column is the join column, so
  `WHERE o.id = 5` reads one order and one customer. An INNER join may also
  look up the first table for each row of the second (`join(index 1)`).
- The planner takes the index join when an upper bound of its lookups costs
  less than hashing; there are no statistics, so a predicate the structures
  cannot count (a scan's filter) counts as the whole table, and a lookup is
  priced at its first match (where one key matches many rows, the index join
  can be taken where hashing is faster; the answer is the same). `SET join_plan =
  hash` or `index` forces one (index falls back to the hash join where no such
  index exists; the path says which ran).
- With `SET cross_check = on` a second plan must agree: the hash join building
  the first table, with each table read whole (by a scan, or by the version
  store where the first plan scanned it), so it shares no lookup with the
  first plan.
- The hash, the kept columns and the kept rows have a cap equal to the
  result's, and the result its own, so a join holds at most half of a memory
  budget, three quarters under cross_check (the first plan's result is kept
  while the second runs).

## Validation

```sh
make test        # lint, unit suite in two modes (SIMD; scalar + one thread), integration + rejection scripts
make san         # the same under ASan + UBSan + LeakSanitizer
make tsan        # ThreadSanitizer (clang): pool tests and the unit suite
make faults      # every fault point of the crash scenarios (t_fault.c), on the build disk
make ct          # constant-time check of Ed25519 signing (clang MemorySanitizer)
make fuzz-run    # libFuzzer, 60 s per decoder, seeds from a real database
make bench       # kernels and engine; sync=0, so commit times are not durable latency
make whole       # root, a quiet machine: imagedb, SQLite and PostgreSQL at equal durability (docs/bench-2026-10-24.md)
build/test_unit review                                 # the regressions of the 2026-10-21 review
build/test_unit round3                                 # the regressions of the 2026-10-22 review
bash tests/integration/audit_reject.sh build/imagedb   # cases A-Y
IMDB_CRASH_OK=1 bash tests/crash/power_cut.sh build/imagedb   # root: real power-cut states (dm-log-writes on a
                                                             # loop device; a udev rule in /run hides the devices
                                                             # from the desktop and is removed at exit)
```

The unit tests use OpenSSL as an independent oracle, and the benchmark driver
(`make whole`) links SQLite and libpq; the engine links none of them. Current
review results and unavailable validation targets are recorded in
docs/review-2026-10-22.md. Earlier full matrix runs
in the plan documents (not published: below) apply to their frozen source versions, not automatically
to the latest code. Performance numbers there were measured on a laptop, mostly
under the powersave governor. The comparison with SQLite and PostgreSQL at equal
durability is docs/bench-2026-10-23.md: one machine,
one client, its caveats next to its numbers. The head-to-head after CREATE INDEX,
with ordered access on the key in all three engines, is
docs/bench-2026-10-24.md.

## License

imagedb is licensed under the [Apache License 2.0](LICENSE). The vendored Monocypher 4.0.3
(`src/vendor/monocypher`) keeps its own licence, BSD-2-Clause or CC0-1.0 at your choice
([LICENCE.md](src/vendor/monocypher/LICENCE.md)).

## Not in this repository

Kept by the author, on purpose:
- The documents: every Markdown file but this README and Monocypher's, so design.md, proposals.md,
  deferred.md, alternatives.md, CLAUDE.md and the reports under docs/ (the reviews, the benchmark
  reports, the CVE study). The code and the tests cite them. The raw runs and scripts beside the
  reports under docs/ are here.
- The ten-configuration head-to-head of 2026-10-26 (`docs/bench-2026-10-26-ten.md` and its raw
  runs). It includes SQL Server, whose licence requires Microsoft's prior written approval to publish
  benchmark results. Other documents still cite it.
- The working records: the session plan logs (`docs/plan-round2.md`, `docs/plan-round3.md`, which other
  documents cite as the plan log) and the two external reviews (`docs/imagedb-feedback-*.md`).
