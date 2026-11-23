/* The persistent writer of the power-cut run (power_cut.sh, R7d): one open, many commits, so the
 * in-place rewrites of DURABLE and the anchor between syncs are exercised with no open or close
 * between them. After each statement returns it prints "seq head" and waits for a line on stdin:
 * the driver has recorded the acknowledgement and marked the dm log, so every mark follows its
 * commit's acknowledgement and precedes the next commit.
 *   persist_writer DIR FIRST_ID N [--durable-ack | --group]   (--group: group commit, each group acknowledged once synced)
 * Statements: INSERTs of ids FIRST_ID.., an UPDATE every 7th, a CHECKPOINT every 10th, one ERASE SUBJECT 2 half
 * way, and (P2 S7) every 13th the view pvFIRST_ID made over t, or dropped if it is there, then read: so the
 * replayed states cut through ops 20 and 21 too, and the manifests the CHECKPOINTs publish hold a view or a
 * tombstone. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../../src/db.h"
#include "../../src/sql.h"

static int run(imdb_session *s, const char *sql, imdb_err *e)
{
    imdb_result r;
    imdb_err_clear(e);
    int rc = imdb_exec_one(s, sql, strlen(sql), NULL, 0, &r, e);
    if (!rc) imdb_result_free(&r);
    return rc;
}

int main(int argc, char **argv)
{
    bool group = argc == 5 && !strcmp(argv[4], "--group");
    if (argc < 4 || (argc == 5 && strcmp(argv[4], "--durable-ack") != 0 && !group) || argc > 5) {
        fprintf(stderr, "usage: persist_writer DIR FIRST_ID N [--durable-ack | --group]\n");
        return 2;
    }
    imdb_open_opts o = {.sync = 1, .durable_ack = argc == 5 && !group};
    imdb_db *db;
    imdb_err e = {0};
    if (imdb_open(argv[1], &o, &db, &e)) {
        fprintf(stderr, "persist_writer: open: %s\n", e.msg);
        return 1;
    }
    if (group && imdb_set_group_commit(db, true, &e)) { /* group commit (docs/txn-design.md §6): DURABLE strict from here */
        fprintf(stderr, "persist_writer: group commit: %s\n", e.msg);
        imdb_close(db);
        return 1;
    }
    imdb_session s;
    imdb_session_init(&s, db);
    long first = atol(argv[2]), n = atol(argv[3]);
    char view[32];
    snprintf(view, sizeof view, "pv%ld", first);
    int rc = 0;
    uint32_t maxg = 0; /* --group: the most deferred commits one group held */
    for (long i = 0; i < n && !rc; i++) {
        char sql[200];
        if (i % 13 == 5) { /* P2 S7: the view made or dropped (a commit alone), then read through */
            if (imdb_view_by_name(db, view)) snprintf(sql, sizeof sql, "DROP VIEW %s", view);
            else snprintf(sql, sizeof sql, "CREATE VIEW %s AS SELECT id, memo, LENGTH(memo) AS n FROM t WHERE id >= %ld", view, first);
        } else if (i == n / 2) snprintf(sql, sizeof sql, "ERASE SUBJECT 2");
        else if (i % 10 == 9) snprintf(sql, sizeof sql, "CHECKPOINT");
        else if (i % 7 == 6) snprintf(sql, sizeof sql, "UPDATE t SET memo = 'persistent-upd-%ld' WHERE id = %ld", i, first);
        else snprintf(sql, sizeof sql, "INSERT INTO t VALUES (%ld, %ld, 'persistent-%ld')", first + i, (first + i) % 3, i);
        if ((rc = run(&s, sql, &e))) {
            fprintf(stderr, "persist_writer: %s: %s\n", sql, e.msg);
            break;
        }
        char rd[64];
        snprintf(rd, sizeof rd, "SELECT COUNT(*) FROM %s", view);
        if (i % 13 == 5 && imdb_view_by_name(db, view) && (rc = run(&s, rd, &e))) {
            fprintf(stderr, "persist_writer: %s: %s\n", rd, e.msg);
            break;
        }
        /* --group: a deferred commit is acknowledged only once its group is durable: up to four statements share a
         * group (a statement that may not defer syncs it at its start), then one sync, then the acknowledgement of
         * the last; the driver records and marks only what is printed */
        if (group && imdb_group_pending(db) && i % 4 != 3 && i != n - 1) continue;
        if (group && db->group_n > maxg) maxg = db->group_n; /* (the driver requires a group of more than one) */
        if (group && (rc = imdb_group_sync(db, &e))) {
            fprintf(stderr, "persist_writer: the group's sync: %s\n", e.msg);
            break;
        }
        char hex[65];
        imdb_hex(db->head, 32, hex);
        printf("%llu %s\n", (unsigned long long)db->seq, hex); /* acknowledged: the statement returned */
        fflush(stdout);
        char line[16];
        if (!fgets(line, sizeof line, stdin)) break;
    }
    imdb_session_close(&s);
    if (group) fprintf(stderr, "persist_writer: largest group %u\n", maxg);
    if (imdb_close(db)) rc = 1;
    return rc ? 1 : 0;
}
