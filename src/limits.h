/*
 * imagedb — every hard limit in one place.
 *
 * Rule (from the PostgreSQL CVE study, classes A/B): every length or count
 * that arrives from outside the process (SQL text, log frames, segment files,
 * replication streams) is compared against one of these limits *before* it is
 * used in any size computation or allocation.
 */
#ifndef IMDB_LIMITS_H
#define IMDB_LIMITS_H

#define IMDB_MAX_IDENT          63u          /* identifier bytes (no NUL)            */
#define IMDB_MAX_COLS           64u          /* user columns per table               */
#define IMDB_MAX_TABLES         1024u        /* tables per database                  */
#define IMDB_MAX_TEXT           65535u       /* bytes in one TEXT value              */
#define IMDB_MAX_ROW            (1u << 20)   /* canonical row bytes                  */
#define IMDB_MAX_SQL            (1u << 22)   /* bytes in one SQL statement           */
#define IMDB_MAX_TOKENS         (1u << 18)   /* tokens in one SQL statement          */
#define IMDB_MAX_INSERT_ROWS    100000u      /* rows in one INSERT ... VALUES        */
#define IMDB_MAX_PREDICATES     32u          /* AND-ed comparisons in a WHERE        */
#define IMDB_MAX_ORDER          16u          /* ORDER BY keys (1d)                   */
#define IMDB_MAX_PARAMS         256u         /* $n bound parameters                  */
#define IMDB_MAX_NUMERIC        128u         /* bytes in one numeric literal          */
#define IMDB_MAX_EXPR_NODES     16384u       /* terms in one statement's expressions (1b; a literal value takes none) */
#define IMDB_MAX_EXPR_DEPTH     64u          /* an expression's height: the parser's and evaluator's recursion */
#define IMDB_MAX_OPS_PER_COMMIT (1u << 20)   /* ops in one commit record             */
#define IMDB_MAX_TXN_BYTES      (768u << 20) /* row bytes one transaction may write (fits a frame) */
#define IMDB_MAX_TXN_LOCKS      (1u << 20)   /* rows one transaction may select FOR UPDATE */
#define IMDB_MAX_SAVEPOINTS     (1u << 14)   /* savepoints one transaction may hold   */
#define IMDB_MAX_FRAME          (1u << 30)   /* bytes in one log frame body          */
#define IMDB_MAX_HEADER         ((1u << 30) - 128u) /* chained header bytes in one commit */
#define IMDB_MAX_SEGMENT_ROWS   (1u << 22)   /* row versions in one segment          */
#define IMDB_MAX_VERSIONS       (1ull << 40) /* vids one table hands out: bounds its chunk directory (8 B a 2^16) */
#define IMDB_MEM_WINDOW_US      (600ull * 1000000) /* stage 3b: a version ended within it stays in memory (per process) */
#define IMDB_EVICT_MIN          4096u        /* an eviction pass waits for this many versions ended since the last */
#define IMDB_SEG_CACHE_BYTES    (256ull << 20) /* stage 3c-1: the lake's segment images kept in memory between operations */
#define IMDB_REPLICA_HOLD_MS    (24ll * 3600 * 1000) /* a replica heard from within this keeps the log it still needs */
#define IMDB_RETIRE_RECHECK_US  1000000u /* a policy RETIRE a replica held back looks again after this */
#define IMDB_FLOOR_STRIDE       4096u        /* a manifest kept for a future log floor: the first publish of each such
                                                block of commits (lake.c keepers); every one at a 64 MB cadence */
#define IMDB_SEED_HEAD_MAX      (64u << 20) /* a seed's FLOOR head: the floor's header, its key changes, its starts */
#define IMDB_SEED_OBJECTS_MAX   (1u << 24)  /* objects in one seed (a snapshot's manifests, segments, vectors) */
#define IMDB_BACKUP_CHUNK       (1u << 20)  /* plaintext bytes in one sealed chunk of a backup file (backup.h) */
#define IMDB_MAX_BACKUP_FILES   4096u        /* backup files one restore takes (a full one and its incrementals) */
#define IMDB_RESTORE_EVERY      4096u        /* commits a restore applies between its syncs (it is rerun after a crash) */
#define IMDB_MAX_PATH           4096u        /* bytes in an operator's path (a backup, a restore's destination) */
#define IMDB_MAX_NAME           255u         /* bytes in one name within it */
#define IMDB_MAX_OBJECT         (1ull << 34) /* bytes in one object file             */
#define IMDB_MAX_ALLOC          (1ull << 34) /* largest single allocation            */
#define IMDB_MAX_ERASE_ENTRIES  (1u << 24)   /* versions named by one ERASE          */
#define IMDB_MAX_SEGMENTS       65536u       /* live segments per table              */
#define IMDB_MAX_GROUPS         (1u << 22)   /* groups produced by one GROUP BY      */
#define IMDB_MAX_GROUP_KEYS     8u           /* GROUP BY keys (P2 S2)                */
#define IMDB_MAX_JOIN_KEYS      8u           /* a join's key pairs: ON's equalities, USING (P2 S3) */
#define IMDB_MAX_SUBQUERIES     8u           /* nested SELECTs one statement names (P2 S4) */
#define IMDB_MAX_SUBQUERY_DEPTH 4u           /* SELECTs nested in SELECTs, deepest (P2 S4) */
#define IMDB_MAX_SETOP_ARMS     64u          /* SELECTs one statement's set operations combine, every chain's counted (P2 S5) */
#define IMDB_MAX_RECURSION      1000000u     /* rounds of one WITH RECURSIVE (P2 S5): past them, refused */
#define IMDB_MAX_QUERY_PARENS   32u          /* queries parenthesized in queries, deepest (P2 S5: the parser's recursion) */
#define IMDB_CHECKPOINT_BYTES   (64ull << 20) /* default auto-CHECKPOINT segment size (primary) */
#define IMDB_LOG_FILL_CHUNK     (1u << 20)   /* zeros written ahead in a tagged segment at a time (design.md §3) */
#define IMDB_LOG_FILL_LOW       (256u << 10) /* less fill than this left after an append: the next chunk */
#define IMDB_RETAIN_MIN_US      1000000ull   /* a table's shortest retention (op 16): a second */
#define IMDB_RETAIN_MAX_US      (36525ull * 24 * 3600 * 1000000) /* its longest but FOREVER: a century */
#define IMDB_MAX_INDEXES        16u          /* CREATE INDEX: indexes per table      */
#define IMDB_MAX_INDEX_COLS     4u           /* CREATE INDEX: columns per index      */
#define IMDB_MAX_JOIN_ROWS      (1u << 22)   /* a join: build entries, joined rows   */
#define IMDB_VERIFY_BATCH       512u         /* commits VERIFY decodes and checks at once */
#define IMDB_VERIFY_BATCH_BYTES (64ull << 20) /* ... or fewer, once their frames reach this */
#define IMDB_VERIFY_LAKE_BYTES  (256ull << 20) /* segment bytes VERIFY holds at once (at least one segment) */
#define IMDB_MAX_REPLICAS       256u         /* allowlisted replicas per primary (replicas/) */
#define IMDB_MAX_SYNC_REPLICAS  64u          /* SET sync_replicas                     */
#define IMDB_MAX_SYNC_TIMEOUT_MS 3600000u    /* SET sync_timeout_ms (an hour)         */
#define IMDB_MAX_STATEMENT_TIMEOUT_MS 86400000u /* SET statement_timeout (a day; 0: none) */
#define IMDB_MAX_UNACKED        (1u << 20)   /* commits ship --acks sends past the last acknowledgement */
#define IMDB_MAX_EPOCHS         4096u        /* writer epochs (key rotations and promotions) per database */
#define IMDB_MAX_PINNED         8u           /* older lake generations GC keeps for readers that pin them */
#define IMDB_PIN_MAX_LAG        (1u << 20)   /* commits a pinned generation may lag the current one, kept */
#define IMDB_MAX_PIN_FILES      4096u        /* pins/ entries GC, VERIFY or the auditor reads */
#define IMDB_PIN_RETRIES        3u           /* reads a reader starts again when its generation vanished */
#define IMDB_MAX_RESULT_BYTES   (1ull << 30) /* one statement's result (cells and text); a memory budget tightens it */
#define IMDB_MIN_STATEMENT_MEMORY (1ull << 20) /* SET statement_memory's least (P0 R2): a read statement's workspace */
#define IMDB_MAX_STATEMENT_MEMORY (16ull << 30) /* and its most; the default is IMDB_MAX_RESULT_BYTES or a budget's quarter */
#define IMDB_MAX_STATEMENT_ROW_LIMIT (1ull << 62) /* SET statement_row_limit: rows a statement may test (0: none) */
#define IMDB_STATS_EXPORT_MAX 16384 /* P1 M1: the stats export's file, whole (a fixed buffer in imdb_db: no allocation) */
#define IMDB_EVENTS_LINE_MAX 8192  /* P1 M2: one event's line, its strings escaped and cut to fit (a fixed buffer) */
#define IMDB_EVENTS_CAP (64ull << 20) /* P1 M2: the event log's size before it becomes FILE.1 and a new FILE begins */

#endif
