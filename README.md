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
make install            # PREFIX=/usr/local, DESTDIR to stage; make uninstall
build/imagedb init /data/p
build/imagedb sql /data/p
build/imagedb sql /data/p -f script.sql   # or piped: each statement runs as it is read, any size
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
grow it past the budget less a query's share (a quarter of the budget, at most
1 GiB: a query's default limit, below) is refused before anything is written,
so the database and one query fit in the budget together; DELETE,
CHECKPOINT, COMPACT ... PURGE and ERASE are never refused, and an open always
succeeds. `SHOW MEMORY` shows what it holds by kind.

A query (SELECT, joins included, and SHOW) has a hard memory limit: everything
it allocates, its result, sort keys, groups and join pairs alike, is counted
before it is allocated, and a query that would pass the limit fails with
"statement memory" and changes nothing (narrow it, or add LIMIT). `SET
statement_memory = BYTES` sets it for the session (1 MiB to 16 GiB); by default
it is a quarter of the budget, or 1 GiB without one. The lake's segments a query
reads are not in this limit: they stay in memory until the query ends (the
segment cache, `--seg-cache`, trims them after it), so a query's peak is its limit
plus the segments it read; a scan that lets go of what it has passed is still to
come. Writes are bounded by the budget, not by this limit, and nothing spills to
disk.

`SET statement_timeout = MS` stops any statement of the session that runs longer
(0, the default, is none), and Ctrl-C in `imagedb sql` stops the running statement:
either fails it with "cancelled", and nothing it did stays (its writes are undone;
a transaction goes on). COMMIT, CREATE, DROP TABLE, DROP INDEX, ALTER, CHECKPOINT, COMPACT, ERASE and VERIFY always run
to their end. From C, `imdb_session_cancel` does the same from another thread.

`SET transaction_timeout = MS` and `SET idle_in_transaction_timeout = MS` (0, the
default, is none; taken at the next BEGIN) end a transaction that runs longer, or
sits between its statements longer: its next statement fails ("transaction
timeout", "idle in transaction") and it can only roll back. Another session's
statement ends an idle one too and frees what it held at once, so a session that
never comes back does not keep its writes in memory.

`SET statement_row_limit = N` (0, the default, is none) fails a statement that
tests more than N rows with a limit error, leaving nothing, as a timeout does.
A row is tested when it is visible and past the predicates an index or a scan
applies, before the rest of WHERE; a join's rows are the pairs it forms.
Every plan and every placement of the versions (memory or the lake) tests the
same rows, so unlike a timeout the limit trips at the same point on every copy
and on every run.

History is kept per table. `CREATE TABLE ... RETENTION 30 DAYS` (SECONDS, MINUTES,
HOURS or DAYS, up to a century; 24 HOURS by default) or `RETENTION FOREVER` says
how long AS OF can read a table's past; `ALTER TABLE t SET RETENTION ...` changes
it, and `SHOW RETENTION` shows each table's and the commit its readable history
starts at. On the primary, history older than that expires, by a logged EXPIRE
that replicas replay; AS OF below it is an error, never a partial answer. Once
every table's history has expired past a log segment, RETIRE drops the versions
ended before it from memory and the lake and cuts the log below it (a replica
heard from within 24 hours holds it back).

`DROP TABLE t` ends every row of t in one commit and frees its name and its
index names. Its history stays readable with AS OF before the drop, by the
same paths as any table's, until it expires by the table's retention; a table
kept FOREVER is dropped with a retention for that history (`DROP TABLE t
RETENTION 30 DAYS`). DROP TABLE commits on its own, outside an explicit
transaction, and a transaction that wrote or locked rows of the table can then
only roll back. `SHOW TABLES` lists a dropped table with the commit that
dropped it (`dropped_at`); ERASE SUBJECT still reaches its history.

**Install.** `make install` puts `imagedb` and `imagedb-audit` in `PREFIX/bin`,
`libimagedb.a` in `PREFIX/lib` and this README and the licence in
`PREFIX/share/doc/imagedb` (`PREFIX=/usr/local` by default; `DESTDIR` stages
it, for a package); `make uninstall` removes them. A sanitizer build is never
installed.

**Platforms.** Linux on x86-64. The kernels are chosen at run time: AVX2 where
the CPU has it, their C references elsewhere (`IMDB_NO_SIMD=1` forces those;
the test matrix runs both); `make NOASM=1` builds without NASM. Tested here:
Linux 6.8 (Ubuntu 22.04) on an Intel Core i7-8550U, gcc 11.4 (the builds) and
clang 14 (the ThreadSanitizer, MemorySanitizer and fuzz builds), NASM 2.15;
data directories on ext4 (power cuts replayed through dm-log-writes) and tmpfs.
Untested: other systems and architectures, other file systems (XFS, btrfs,
network file systems), a CPU without AVX2 (its code path runs only under
`IMDB_NO_SIMD=1`), AVX-512 and SHA-NI machines.

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

## Backup and restore

```sh
build/imagedb backup-key /safe/backup.key            # once: 32 random bytes (0400); prints the key's id
build/imagedb backup /data/p --key /safe/backup.key --out /backups/p-20261101.bak
build/imagedb backup /data/p --key /safe/backup.key --out /backups/p-1.bak --after /backups/p-20261101.bak
build/imagedb backup /data/p --key /safe/backup.key --out /backups/p-2.bak --after /backups/p-1.bak
build/imagedb backup-verify --key /safe/backup.key --scratch /tmp/check /backups/p-20261101.bak
build/imagedb restore /data/p2 --key /safe/backup.key /backups/p-20261101.bak /backups/p-1.bak /backups/p-2.bak
build/imagedb restore /data/p3 --key /safe/backup.key --until-time '2026-11-04 12:00:00' \
    /backups/p-20261101.bak /backups/p-1.bak /backups/p-2.bak       # the full one first, then in order
build/imagedb promote /data/p2 --root-key /offline/root.key --old-writer-stopped   # to write to the copy
```

- A backup runs beside the database, from its files: the last published snapshot (the manifest and lake objects of
  the last CHECKPOINT, with that commit's signed header and the writer keys up to it, as a new replica is seeded) and
  every commit after it that is durable when the backup ends. A database that never published a snapshot is backed
  up as its log from commit 1.
- The file is sealed with XChaCha20-Poly1305 under the key, in chunks of 1 MiB whose place in the file is bound into
  each tag: a damaged, moved, missing or added chunk is refused, and a file that ends before its summary is
  incomplete, never a shorter backup. Without the key a backup cannot be read or restored: keep the key apart from
  the backups (and the root key apart from both).
- It is written as FILE.tmp, synced, then renamed: a crash leaves FILE.tmp (remove it before the next backup), never
  a partial FILE. When the database publishes and retires its log under a running backup, the backup starts again
  from the newer snapshot (three attempts).
- `--after PREV` makes an incremental backup: the commits after PREV's last, checked to continue PREV's history
  (the source's next commit must name PREV's last as the one before it). Refused: nothing new since PREV (no file
  is written), a PREV of another database, and a source whose log no longer holds the commits after PREV (RETIRE cut
  it): take a full backup then, and take fulls at least as often as RETIRE runs. A restore takes a full backup and
  then its incrementals in order; a gap or another history is refused before anything is written.
- `backup-verify` is a test restore: the backup restored into a new directory under `--scratch`, VERIFY run on it,
  the directory removed. Run it after each backup: `backup` checks its own seal and frames, but only a restore reads
  the snapshot's seed.
- `restore` reads every file whole first (a damaged one is refused before anything is written), then applies the
  backup as a replica applies a stream, every commit's signature, chain and digest checked, into DEST.tmp, makes it
  durable and renames it to DEST. A restore that fails removes DEST.tmp; a crash leaves it: remove it and restore
  again.
- `--until N` restores through commit N, `--until-time 'YYYY-MM-DD HH:MM:SS[.ffffff]'` (UTC) through the last
  commit made at or before it: the apply stops before the next commit, as at a stream's end (the copy's state
  checked), and the copy is the database as it was there (its head is that commit's hash). A point the backups do
  not hold (before the full backup's snapshot, past the last commit, before the first commit's time) is refused
  before anything is written.
- **The copy** is a replica seeded at the snapshot's commit S, holding the database as it was at the backup's last
  commit (the same view token). Its history starts at S: VERIFY and the auditor start there, and `AS OF` an earlier
  commit is refused on it ("commit N is in no log segment"), where the source, which holds its whole log, answers.
- **No secret is in a backup**: the writer key stays with the primary. The copy becomes writable by promotion with
  the offline root key (a new signed epoch; the root key's ledger lets each epoch be taken once, so two restores
  cannot both become writers). A database made without `init --root` restores to a copy that stays read-only.
  Not in a backup: `replicas/` (enrol replicas again with `replica-add`), the anchor (give the copy a new one), pins.
- What is lost when the database is: the commits after the last backup's last commit, so the RPO is the interval
  between backups (incrementals make that interval short and cheap: each holds only the commits since the one
  before), or a replica's lag with `follow` (none with `SET sync_replicas`). A restore's time (the RTO) follows
  the snapshot's size and the commits after it, not the history: a database of 373,510 commits (200,000 live rows,
  380 MB) restored in 20 s from its snapshot and the 13,509 commits after it, against 151 s to replay its whole log
  (a USB SSD, 2026-11-01; its backup took 3.4 s); one of 10^6 rows of ~420 bytes (949 MB on disk) backed up in 5.6 s
  to a 492 MB file and restored in 15.5 s, opening in 6.2 s more, with the source's view token (the internal SSD,
  2026-11-04).
- An ERASE after a backup does not reach the backup: delete the file, or destroy the key, which makes every backup
  sealed under it unreadable. `SHOW ERASURE` counts backups among the copies it does not track.

## Erasure

DELETE keeps history. COMPACT ... PURGE removes old payloads from the lake but
keeps tombstones and the log. ERASE removes the targeted payloads from every
file imagedb manages (log, lake objects) and from its memory (buffers grow by
copy-and-wipe, never `realloc`; doomed transactions drop their writes), and a
replica applies the same ERASE. It reports cleanup as pending until the log
rewrite, the lake publication and the GC have all finished. It cannot reach
backups, exported results, disconnected replicas, freed device blocks or what
a client holds.

## Monitoring

`SHOW STATS` gives what a copy has done since its open, one `name value` row each,
always the same rows: statements by class (read, write, transaction, ddl,
physical, show, other) with their p50, p99 and largest latency in
microseconds; failures by kind (conflict, limit, cancelled, other); commits
and their latency (a replica's applied commits apart: `commits.applied`),
rollbacks, the log's bytes; the segment cache's hits and
loads; each CHECKPOINT, COMPACT, EXPIRE, RETIRE and eviction's count and time;
the open's time and the commits it replayed; the open transactions and the
oldest's age; the bytes on disk of the log and the lake; the running
statement and how long it has run. Syncs (`process.syncs.*`) are the process's,
every database it opened. A statement's latency runs from the end of its parse to
its own end: the parse is not in it, swapping its session's transaction in is.
Latencies are read from buckets four to an octave:
a quantile is at most a quarter above the true one. `SHOW TRANSACTIONS` lists
every open transaction: its state (active, parked, doomed, begun), isolation,
age, time since its last statement, writes and locks.

`--stats FILE` (on `sql`, `apply` and `follow`) has the copy write the same rows
to FILE, outside the data directory, with its pid, time, commit and whether its
handle failed, at most once a second (a replica's apply too) and at its close,
and at once when its handle fails: rewritten in place,
never synced, a CRC on its last line; a FILE that is not an export is left as
it is (the copy keeps no export and says why). `imagedb stats FILE` prints it with its
age. `imagedb health DIR [--stats FILE] [--max-statement-s N]` checks the
directory without opening it (META, DURABLE, no replica incident recorded) and
the export: exit 0 healthy, 1 a statement running past N seconds (60) or an
unreadable export, 2 the handle failed (reopen it), 3 the directory damaged or
a replica incident recorded. An idle copy writes no export until its next
statement: an old export with nothing running is idle, not hung.

`--events FILE` (on `sql`, `apply` and `follow`) appends one JSON object a line
to FILE, outside the data directory, each with `time_us` (the wall clock) and
`ev`: the open and its end (its time, the snapshot's commit, the commits
replayed) with its progress at most once a second; each CHECKPOINT, COMPACT,
EXPIRE, RETIRE and eviction with its time; each warning; the handle's failure,
once, with its reason; slow statements; the close. Lines are appended whole and
never synced: the log is advisory (a failed append is counted in
`events.errors`, never an error; a crash can tear the last line, and the next
open appends after it: a reader skips a line that does not parse). Past 64 MiB,
FILE becomes FILE.1 (an older FILE.1 replaced, never a file that is not an event log) and a new FILE begins.
A FILE that is not an event log is left as it is (the copy keeps no log and
says why). Give each process its own FILE. `SET slow_statement_ms = N` logs
each of the session's statements that runs N milliseconds or more: its class,
time, access path, rows tested, outcome and shape, the statement with every
literal (number, string, TRUE, FALSE) a `?` and its comments dropped, so no
value reaches the log, cut at 1 KiB. An open that passes two seconds prints
its progress on stderr: the lake's segments loaded, the commits replayed.

## Options and settings

Every command-line option, session setting and environment variable, in one
place; the sections above say more. `make lint` checks that each one the code
reads is listed here.

Command-line options (`imagedb` with no arguments prints the commands):

| Option | Commands | What it does | Default |
|---|---|---|---|
| `-c SQL` | sql | runs SQL; repeatable | |
| `-f FILE` | sql | runs a script, each statement as it is read, any size | |
| `--csv` | sql | prints results as CSV | a table |
| `--cross-check` | sql | `SET cross_check = on` for the session | off |
| `--nosync` | sql | commits are not fdatasynced until a clean close | synced |
| `--lake-sync` | sql | a CHECKPOINT after every change (priced) | off |
| `--durable-ack` | sql, apply | DURABLE fsynced before each commit returns | off |
| `--read-only` | sql | opens without writing anything (a replica's reads) | writable |
| `--anchor FILE` | sql, verify, promote | an external anchor: a log rolled back behind it is refused | none |
| `--accept-rollback` | sql | continues from a log behind the anchor, rewriting it | off |
| `--mem-limit BYTES` | sql, apply, follow | the memory budget (K, M or G) | none |
| `--mem-window SECONDS\|none` | sql, apply, follow | versions ended within it stay in memory | 600 |
| `--seg-cache BYTES\|all` | sql, apply, follow | the lake's segment images kept in memory | 256 MB |
| `--stats FILE` | sql, apply, follow | writes the stats export (Monitoring) | none |
| `--stats FILE` | health | reads that export too | the directory only |
| `--events FILE` | sql, apply, follow | the event log (Monitoring) | none |
| `--root KEY` | init | a root key that may certify a promotion | none |
| `--digest-alg N` | init | the state digest's algorithm, 1 or 2 | `IMDB_DIGEST_ALG`, else 2 |
| `--identity FILE` | init-replica | a replica from a primary's identity file | |
| `--after N` | ship | the commits after N | 0 |
| `--after PREV` | backup | an incremental backup after backup PREV | a full one |
| `--follow` | ship | keeps shipping new commits | stops at the end |
| `--acks` | ship | reads the replica's acknowledgements on stdin | off |
| `--new` | replica-key | a new replica key: a new incarnation | the existing key |
| `--replace` | replica-add | gives an allowlisted replica a new key | refused |
| `--max-statement-s N` | health | a statement running longer is unhealthy (exit 1) | 60 |
| `--discard-tail` | recover | cuts the damaged end of the log | inspect only |
| `--save FILE` | recover | the cut bytes, saved first | |
| `--key FILE` | backup, backup-verify, restore | the backup key | |
| `--out FILE` | backup | the backup's file | |
| `--scratch DIR` | backup-verify | where the test restore runs | |
| `--until N` | restore | through commit N | the last |
| `--until-time TS` | restore | through the last commit at or before TS | the last |
| `--root-key FILE` | promote | the root key certifying the promotion | |
| `--abandon` | promote | with `--anchor`: drops old-writer commits past its cut | refused |
| `--old-writer-stopped` | promote | without an anchor: your word that the old writer is stopped | |

Session settings (`SET name = value`; each session's own, from the next
statement):

| Setting | Values | Default | What it does |
|---|---|---|---|
| `cross_check` | on, off | off | runs each read along a second path too and fails on any difference |
| `access_path` | auto, index, scan, store, ordered | auto | forces a table's read path (EXPLAIN shows it) |
| `join_plan` | auto, hash, index | auto | forces a join's plan |
| `identity` | on, off | off | a read's result also names the database, its head, digest and manifest |
| `min_commit` | a commit number | 0 (none) | a read on a copy not yet at that commit is refused |
| `statement_timeout` | 0 to 86,400,000 ms | 0 (none) | cancels a statement that runs longer |
| `transaction_timeout` | 0 to 86,400,000 ms | 0 (none) | a transaction older than it can only roll back (from the next BEGIN) |
| `idle_in_transaction_timeout` | 0 to 86,400,000 ms | 0 (none) | a transaction idle that long can only roll back (from the next BEGIN) |
| `statement_memory` | 0, or 1 MiB to 16 GiB | 0: a quarter of the budget, or 1 GiB | a read statement's hard memory limit |
| `statement_row_limit` | 0 to 2^62 rows | 0 (none) | the rows a statement may test |
| `slow_statement_ms` | 0 to 86,400,000 ms | 0 (none) | statements at least that long go to the event log |
| `sync_replicas` | 0 to 64 | 0 | a commit waits for that many replicas' acknowledgements (a primary's) |
| `sync_timeout_ms` | 1 to 3,600,000 ms | 10,000 | how long a commit waits for them |

`BEGIN ISOLATION LEVEL SNAPSHOT | REPEATABLE READ | READ COMMITTED | READ
UNCOMMITTED` (or `SET TRANSACTION ISOLATION LEVEL ...`) chooses a transaction's
isolation: SNAPSHOT by default; REPEATABLE READ is SNAPSHOT, READ UNCOMMITTED is
READ COMMITTED (uncommitted data is never visible), SERIALIZABLE is refused.

Environment variables:

| Variable | What it does |
|---|---|
| `IMDB_THREADS=N` | the worker pool's size (default: the CPUs the process may use); 1 runs every parallel loop inline |
| `IMDB_DIGEST_ALG=1\|2` | the digest algorithm of the databases `init` creates (default 2); never read when a database opens |
| `IMDB_NO_SIMD=1` | the C reference kernels and the reference Ed25519, whatever the CPU |
| `IMDB_EVICT=eager` | a test mode: every publish evicts what it can (reads below the floor go to the lake) |
| `IMDB_SEGCACHE=tiny` | a test mode: no segment image is kept between operations |

## Supported scope

One process and principal, one engine thread with worker parallelism, many
interleaved sessions. SNAPSHOT and READ COMMITTED transactions, statement
rollback, savepoints, `WITH (NOLOCK)` and optimistic `SELECT ... FOR UPDATE`
(first committer wins, without fairness: a long transaction can lose every
round to short ones writing the same row, so retry with backoff). SERIALIZABLE
is refused; snapshot write skew is possible.

Types: INT64, DECIMAL, TEXT, BOOL, TIMESTAMP, finite FLOAT64 (exact SUM,
rounded once) and nullable non-key columns. Comparisons with NULL, including
NULL parameters, are refused: use IS NULL / IS NOT NULL.

TEXT is UTF-8, validated, without NUL, and compared and ordered byte by byte: there
are no collations. Platforms: see Build and quickstart.

Arithmetic: `+ - * / %`, unary minus and parentheses in SELECT lists, WHERE,
UPDATE ... SET and VALUES, aggregates included:

```sql
UPDATE accounts SET balance = balance - 100 WHERE id = 7;
SELECT region, SUM(qty * price), SUM(qty) * 1.0 / COUNT(*) FROM sales GROUP BY region;
SELECT id FROM t WHERE a + b > 10;
```

Every operation is checked: an INT64 overflow, a zero divisor or a DECIMAL past
38 digits is an error, never a wrapped or silently rounded value. INT64 `/`
truncates toward zero; a DECIMAL quotient keeps six more decimal places than
its operands, rounded half away from zero; an INT64 joins a FLOAT64 expression
only when exact (|v| ≤ 2^53). A computed value stored into a DECIMAL column is
rounded to its scale; a literal that would round is refused. design.md §5
("Expressions") has the rules.

Conditions: `AND`, `OR`, `NOT` and parentheses, with SQL's three-valued logic
(a comparison with a NULL is unknown, and WHERE keeps only what is true);
comparisons may be SELECT items or a BOOL column's value. Within a condition,
AND and OR are evaluated left to right and stop once decided, so
`a = 0 OR 10 / a > 1` does not divide by zero. design.md §5 ("Conditions").

Order: `ORDER BY` expressions or item positions, `ASC`/`DESC` and `NULLS
FIRST`/`LAST` (NULLs last for ascending keys by default, as in PostgreSQL),
`OFFSET` and `LIMIT`, and `SELECT DISTINCT`. Without ORDER BY rows come in
primary-key order (groups in their key's order); with it, that order breaks
ties, so every result's order is total. design.md §5 ("Order").

Aggregates: `COUNT`, `SUM`, `MIN`, `MAX` and `AVG`, of columns or expressions,
and `HAVING` over the groups (or over the one aggregate row). `AVG(a)` of an
INT64 is a DECIMAL with six decimal places, rounded half away from zero, while
`SUM(a) / COUNT(*)` stays an INT64 division and truncates; of a DECIMAL it keeps
six more places than the column. design.md §5 ("Aggregates").

Grouping: `GROUP BY` takes up to eight keys, each a column or an expression
(`GROUP BY region, LOWER(name)`); a select item outside an aggregate must be a
key or built from keys. Aggregates take `DISTINCT` and `FILTER (WHERE ...)`:

```sql
SELECT region, amount >= 1000 AS large, COUNT(DISTINCT customer),
       SUM(amount) FILTER (WHERE status = 'paid')
FROM orders GROUP BY region, amount >= 1000;
```

Groups come in their keys' order (each ascending, NULL last). A key must read a
column: `GROUP BY 1` is refused (no positions yet). design.md §5 ("Grouping").

Functions and forms, wherever a value stands:

```sql
SELECT id, UPPER(TRIM(name)) AS who, COALESCE(nick, '-'),
       CASE WHEN qty > 10 THEN 'bulk' ELSE 'unit' END, ROUND(price * 1.07, 2)
FROM orders WHERE status IN ('open', 'held') AND name LIKE 'A%' ORDER BY who;
SELECT CAST('42' AS INT64), 'a' || CAST(7 AS TEXT), LENGTH('héllo');   -- no FROM: one row
```

- Numbers: `ABS`, `SIGN`, `ROUND(x [, places])`, `CEIL`/`CEILING`, `FLOOR`,
  `MOD` (as `%`). ROUND rounds half away from zero; a FLOAT64 rounds to an
  integer only.
- Text, in characters (UTF-8 code points), never bytes: `LENGTH`
  (`CHAR_LENGTH`), `SUBSTR`/`SUBSTRING(s, start [, len])`, `POSITION(a IN b)`,
  `TRIM`/`LTRIM`/`RTRIM` (spaces), `REPLACE`, `LOWER`/`UPPER` (ASCII letters
  only for now) and `||` (TEXT only: CAST a number first).
- `CASE` (searched and simple), `COALESCE` and `NULLIF`; `x [NOT] IN (list)`
  with three-valued logic; `[NOT] LIKE` (`%`, `_` one character, case-sensitive;
  no default escape: write `ESCAPE '!'`); `NOT BETWEEN`.
- `CAST(x AS type)` is exact or refused: a DECIMAL to fewer places rounds half
  away from zero, but a fraction cast to INT64 is an error (ROUND, FLOOR or CEIL
  it first), and a TEXT converts only when it is a valid literal of the type.
- A select item may be named, `expr AS name` (or `expr name`), and ORDER BY may
  use the name. `SELECT` without `FROM` computes one row.
- New reserved words: `CASE WHEN THEN ELSE END CAST IN LIKE ESCAPE`.
- IN and LIKE are tested on each row read: no index serves them yet.
  design.md §5 ("Functions, CASE, CAST, IN, LIKE").

The
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
- `EXPLAIN SELECT ...`, `EXPLAIN UPDATE ...` and `EXPLAIN DELETE ...` show the
  plan without running it, one `item | detail` row each: the table and the
  snapshot; the path the statement would report and why (an equality, the
  prices compared, `SET access_path`, a read below this copy's memory floor);
  the index and how it is used; the conditions it serves and those tested on
  each row read; an upper bound of the versions read (there are no
  statistics); the segments a scan reads and those its zone maps skip; what
  the statement makes of the rows. A join's: its plan (`join(build N)`,
  `join(index N)`) and why, the prices of the hash join and of each
  orientation of the index join, each side's path. No row is read, nothing is
  written or locked. The plan is this copy's: two replicas may explain a
  statement differently (their memory floors differ) and answer it the same.
  An UPDATE or DELETE reports the path that found its rows
  (`UPDATE 3  [index(primary key)]`).
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
- Without ORDER BY, rows come in the first table's primary-key order, then the second's, a
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
make oracle      # build/oracle: imagedb's answers against reference engines (tests/oracle)
build/test_unit vectors   # the format's canonical vectors (fixed inputs), and build/imagedb-audit vectors derives them again
bash tests/oracle/run.sh build/oracle --seeds 1-100   # root, docker: SQLite, PostgreSQL, MySQL, MariaDB, SQL Server
build/test_unit review                                 # the regressions of the 2026-10-21 review
build/test_unit round3                                 # the regressions of the 2026-10-22 review
bash tests/integration/audit_reject.sh build/imagedb   # cases A-Y
IMDB_CRASH_OK=1 bash tests/crash/power_cut.sh build/imagedb   # root: real power-cut states (dm-log-writes on a
                                                             # loop device; a udev rule in /run hides the devices
                                                             # from the desktop and is removed at exit)
```

The unit tests use OpenSSL as an independent oracle, and the benchmark driver
(`make whole`) links SQLite and libpq; the engine links none of them. The SQL
oracle (`make oracle`, tests/oracle) runs the same generated statements on imagedb and on SQLite,
PostgreSQL, MySQL, MariaDB and SQL Server (the four servers in private containers) and compares every
answer after normalisation; it links their client libraries, the engine does not. Current
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
