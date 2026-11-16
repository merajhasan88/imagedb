/* N1b: the engine's results and parameters to and from IMDBWIR1 (docs/n1-design.md §4): the server's conversion, run by a
 * connection thread on a result the engine thread handed it whole (it reads the result, never the engine's state, and
 * allocates through the wire's own allocator alone). A column's wire type comes from the statement (the result's ctype,
 * cscale, ceid, cwide), never from its cells, so a driver's metadata does not change between runs; a cell that does not
 * fit its column is an error, never sent. */
#ifndef IMDB_CONV_H
#define IMDB_CONV_H

#include "../src/sql.h"
#include "wire.h"

/* the engine's type tag as the wire's, and back (0 for none) */
uint8_t imdbw_type_of_engine(uint8_t engine_type);
uint8_t imdbw_engine_type_of(uint8_t wire_type);

/* a result's COLUMNS (its arrays the wire's own: imdbw_msg_free), its ENUM columns indexed. A top-level SUM's INT64 column
 * (cwide) a DECIMAL of no known precision at scale 0; a DECIMAL's precision not known (the engine reports a scale alone) */
int imdbw_columns_of(const imdb_result *r, imdbw_msg *cols, imdb_err *e);

/* the cell at row, col as a value of its column c (one of imdbw_columns_of's): pointers into the result */
int imdbw_value_of(const imdb_result *r, uint64_t row, uint16_t col, const imdbw_col *c, imdbw_value *v, imdb_err *e);

/* ROWS frames of the result's rows from *next, each cut at a row's end once past target bytes, appended to b until b
 * holds at least target bytes or the rows end (*next: the next row to send; a caller sends b and calls again) */
int imdbw_rows_of(const imdb_result *r, const imdbw_msg *cols, uint64_t *next, size_t target, imdbw_buf *b, imdb_err *e);

/* a result's DONE: its status, its count (a write's rows, or the rows it holds), its read point when it has one, its
 * commit when it made one (imdb_result.commit) */
void imdbw_done_of(const imdb_result *r, imdbw_msg *d);

/* a wire parameter as the engine's: its type's tag, its value's representation (a FLOAT64 its key, a DECIMAL in the form
 * its digits need, a NULL keeping its type); a non-NULL ENUM parameter refused: a label is sent as TEXT (docs/n1-design.md
 * §4). Pointers into the wire value's bytes */
int imdbw_param_of(const imdbw_value *w, imdb_value *out, imdb_err *e);

#endif
