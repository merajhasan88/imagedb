/* The persistent writer of the power-cut run (power_cut.sh, R7d): one open, many commits, so the
 * in-place rewrites of DURABLE and the anchor between syncs are exercised with no open or close
 * between them. After each statement returns it prints "seq head" and waits for a line on stdin:
 * the driver has recorded the acknowledgement and marked the dm log, so every mark follows its
 * commit's acknowledgement and precedes the next commit.
 *   persist_writer DIR FIRST_ID N [--durable-ack]
 * Statements: INSERTs of ids FIRST_ID.., an UPDATE every 7th, a CHECKPOINT every 10th, and one
 * ERASE SUBJECT 2 half way. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../../src/db.h"
#include "../../src/sql.h"

int main(int argc, char **argv)
{
    if (argc < 4 || (argc == 5 && strcmp(argv[4], "--durable-ack") != 0) || argc > 5) {
        fprintf(stderr, "usage: persist_writer DIR FIRST_ID N [--durable-ack]\n");
        return 2;
    }
    imdb_open_opts o = {.sync = 1, .durable_ack = argc == 5};
    imdb_db *db;
    imdb_err e = {0};
    if (imdb_open(argv[1], &o, &db, &e)) {
        fprintf(stderr, "persist_writer: open: %s\n", e.msg);
        return 1;
    }
    imdb_session s;
    imdb_session_init(&s, db);
    long first = atol(argv[2]), n = atol(argv[3]);
    int rc = 0;
    for (long i = 0; i < n && !rc; i++) {
        char sql[200];
        if (i == n / 2) snprintf(sql, sizeof sql, "ERASE SUBJECT 2");
        else if (i % 10 == 9) snprintf(sql, sizeof sql, "CHECKPOINT");
        else if (i % 7 == 6) snprintf(sql, sizeof sql, "UPDATE t SET memo = 'persistent-upd-%ld' WHERE id = %ld", i, first);
        else snprintf(sql, sizeof sql, "INSERT INTO t VALUES (%ld, %ld, 'persistent-%ld')", first + i, (first + i) % 3, i);
        imdb_result r;
        imdb_err_clear(&e);
        if ((rc = imdb_exec_one(&s, sql, strlen(sql), NULL, 0, &r, &e))) {
            fprintf(stderr, "persist_writer: %s: %s\n", sql, e.msg);
            break;
        }
        imdb_result_free(&r);
        char hex[65];
        imdb_hex(db->head, 32, hex);
        printf("%llu %s\n", (unsigned long long)db->seq, hex); /* acknowledged: the statement returned */
        fflush(stdout);
        char line[16];
        if (!fgets(line, sizeof line, stdin)) break;
    }
    imdb_session_close(&s);
    if (imdb_close(db)) rc = 1;
    return rc ? 1 : 0;
}
