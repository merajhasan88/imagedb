/* N1d-2: an engine result rebuilt from IMDBWIR1's replies (COLUMNS, ROWS, DONE), as the engine's own (its blocks the
 * engine's helpers': imdb_result_free), so imdb_result_render prints it as the embedded CLI prints the original. The
 * server's frames are untrusted: a COLUMNS past the result's columns (IMDB_MAX_COLS + 4), a second COLUMNS for one
 * statement, ROWS before COLUMNS or of another count, COLUMNS or ROWS past DONE, an ENUM value no label of its column
 * names, rows past the engine's cap on a result (IMDB_MAX_RESULT_BYTES): each refused. What the
 * wire does not carry: the access path (path stays empty) and a TIMESTAMPTZ's offset, computed here from zone (NULL:
 * UTC) as the engine computes it from the session's. imagedb-client's, and the suite's round trip (t_conv). */
#ifndef IMDB_CLI_NETRES_H
#define IMDB_CLI_NETRES_H

#include "../server/wire.h"
#include "../src/sql.h"
#include "../src/tz.h"

int cli_res_cols(imdb_result *r, const imdbw_msg *cols, imdb_err *e);
int cli_res_rows(imdb_result *r, const imdbw_msg *cols, const imdbw_msg *rows, const imdb_tz *zone, imdb_err *e);
/* its status, count and read point; every cell's bytes where they stay (res_finish's) */
void cli_res_done(imdb_result *r, const imdbw_msg *done);

/* the reply's order for one statement (§4): its messages, then its DONE or ERROR, then READY. Anything but a WARNING
 * past its end is refused, and READY without it (the server's frames are untrusted: a ROWS past DONE once kept cells
 * DONE never fixed, and a READY with no DONE rendered them: N1d's review) */
typedef struct cli_order {
    bool ended; /* its DONE or ERROR came */
} cli_order;
int cli_order_next(cli_order *o, uint8_t type, imdb_err *e);
/* an ERROR's code as the engine's (negative): the wire carries any nonzero u32, so one past the engine's is INVALID, never
 * a positive return a caller reads as its own (the runner's "COPY took the data") nor INT_MIN negated */
int cli_res_code(uint32_t code);

#endif
