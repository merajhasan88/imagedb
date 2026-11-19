/* N1d-2: the SQL shell's runner (docs/n1-design.md §8d), shared by build/imagedb's sql (the embedded session) and
 * build/imagedb-client (the network): a script's statements split as they arrive (any size, in the memory of its
 * longest statement), COPY ... FROM STDIN's data taken as psql serves it (the script's text after the statement, to a
 * line \., or stdin), the REPL. Each statement goes through the backend's stmt, which runs it and prints its result or
 * its error. Outside src/: never in libimagedb.a, never under src/'s lint (the CLI's stdio is its own). */
#ifndef IMDB_CLI_RUN_H
#define IMDB_CLI_RUN_H

#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>

#include "../src/util.h"

typedef struct cli_src cli_src;
typedef struct cli_runner cli_runner;

/* runs one statement (len bytes): copy_in when it is a COPY ... FROM STDIN, its data then read by cli_copy_read(rn, ...)
 * to its end; prints its result, or its error (cli_print_err); returns 0, or its error's code (IMDB_ERR_*) */
typedef int (*cli_stmt_fn)(cli_runner *rn, const char *sql, size_t len, bool copy_in);

struct cli_runner {
    cli_stmt_fn stmt;
    void *ctx;          /* the backend's */
    bool csv;           /* results as CSV */
    bool timing;        /* \timing: each statement's time after its result */
    bool stop_on_error; /* a script stops at its first failure (not the REPL) */
    int failures;
    cli_src *script;    /* the stream being run (cli_run_stream): COPY's data inline, after the statement */
    cli_src *in;        /* stdin's, made at the first COPY ... FROM STDIN outside a script (-c, the REPL) */
    cli_src *active;    /* the running COPY's: cli_copy_read reads it */
    int (*meta)(cli_runner *rn, const char *line); /* N1e stage two: a client's backslash commands (NULL: none): 1 when
                                                   * it took the line, its outcome printed */
};

/* the running COPY's data, stopped before a \. line (the engine session's reader's signature, arg the runner): > 0
 * bytes, 0 its end, < 0 a failure (or no COPY running) */
long cli_copy_read(void *arg, char *out, size_t cap);
/* COPY ... TO STDOUT's bytes to stdout (arg unused): 0, or -1 when stdout fails */
int cli_copy_write(void *arg, const char *b, size_t n);
/* text's statements, each run (-c) */
int cli_run_text(cli_runner *rn, const char *text, size_t len);
/* f's statements, each as it arrives (-f, piped stdin) */
int cli_run_stream(cli_runner *rn, FILE *f);
/* a terminal's: lines to a ';', \timing, \q */
int cli_repl(cli_runner *rn);
/* stdin's COPY source, freed */
void cli_runner_end(cli_runner *rn);
/* "imagedb: WHAT: MSG (NAME)" on stderr, the CLI's form */
void cli_print_err(const char *what, const imdb_err *e);

#endif
