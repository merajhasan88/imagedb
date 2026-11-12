/* The auditor's view binder (P2 S7b): a view's query text bound against the catalog at its commit by the auditor's own
 * lexer, parser and typer, giving the columns' types and the dependencies op 20 must log. No code shared with src/:
 * design.md §5 is its spec, the engine's grammar its reference; the type tags and dependency kinds are the log's bytes. */
#ifndef ABIND_H
#define ABIND_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define AB_MAX_COLS 64
#define AB_MAX_DEPS 256

typedef struct ab_col {
    char name[72];       /* an identifier, or (a result's column) a tree's text as the engine names it: up to 70 bytes */
    uint8_t type, scale; /* the log's type tags (1 INT64, 2 DECIMAL, 3 TEXT, 4 BOOL, 5 TIMESTAMP, 6 FLOAT64); a DECIMAL's
                          * scale, else 0 */
    uint16_t eid;        /* F3g: an ENUM's type id (tag 13), 0 for every other type */
} ab_col;

/* a relation the catalog holds by name at the view's commit: a live table (kind 1), or a live view (kind 2) with its
 * logged columns (a view is never expanded again: its own text was bound at its own commit); F3g: or a live ENUM type
 * (kind 3: its id, no columns), what a CAST names */
typedef struct ab_rel {
    uint8_t kind;
    uint32_t id;
    uint16_t ncols;
    const ab_col *cols; /* read during the call alone: the binder copies what it keeps */
} ab_rel;

typedef bool (*ab_lookup_fn)(void *arg, const char *name, ab_rel *out);

typedef struct ab_result {
    uint16_t ncols;
    ab_col cols[AB_MAX_COLS]; /* the query's own names (a CREATE's column list renames them: it is not in the text) */
    uint16_t ndeps;
    uint8_t dep_kind[AB_MAX_DEPS];
    uint32_t dep_id[AB_MAX_DEPS]; /* sorted by kind, then id; each once */
} ab_result;

/* 0 and *r; or -1 and the reason in err (the text refused, as the engine refuses it in a view, or not typed) */
int ab_bind(const char *text, size_t len, ab_lookup_fn lookup, void *arg, ab_result *r, char *err, size_t errn);

/* F1: 1 when the text holds ident as an identifier token (unquoted, folded to lowercase), 0 when not, -1 when it does
 * not lex (the reason in err): an ADD COLUMN's rule on the views that read its table */
int ab_names(const char *text, size_t len, const char *ident, char *err, size_t errn);

/* F2b-1: a CHECK constraint's text bound against its table's columns (cols: their names, types and scales, by index)
 * by this binder's strict typer of the engine's subset (design.md §5, CHECK constraints): 0 and *out, or -1 and the
 * reason (a text the engine refuses) */
typedef struct ab_check ab_check;
int ab_check_bind(const char *text, size_t len, const ab_col *cols, uint16_t ncols, ab_check **out, char *err, size_t errn);
void ab_check_free(ab_check *c);
/* a row's values by the table's columns, as the auditor decodes them (a DECIMAL scaled by its column's scale; a
 * TEXT's bytes) */
typedef struct ab_val {
    int64_t i;
    const uint8_t *s;
    uint32_t len;
    bool null;
    bool wide;   /* F3e: a DECIMAL of a column past 18 digits: its value hi:i */
    int64_t hi;
} ab_val;
/* 1: the row passes (TRUE or NULL), 0: it fails (FALSE), -1: its evaluation fails (an overflow, a zero divisor ...) */
int ab_check_eval(const ab_check *c, const ab_val *row, char *err, size_t errn);

/* F2c: a generated column's expression bound as a CHECK's text is (the same subset, the same strictness), its value of a type
 * column target takes (an integer column INT64; a DECIMAL INT64 or DECIMAL; any other its own type, never FLOAT64),
 * naming no column of genmask: 0 and *out, or -1 and the reason */
int ab_gen_bind(const char *text, size_t len, const ab_col *cols, uint16_t ncols, uint16_t target, uint64_t genmask,
                ab_check **out, char *err, size_t errn);
/* the column a value is assigned to: its type, an integer's width (16, 32, 0) or a DECIMAL's precision, its scale, a
 * VARCHAR's length (0 none), NULL allowed */
typedef struct ab_gcol {
    uint8_t type, prec, scale;
    uint32_t vlen;
    bool nullable;
} ab_gcol;
/* its value on a row assigned to its column by INSERT's rules: 0 and *out (a TEXT's bytes in *tbuf, malloc'd, the
 * caller's to free), -1 an evaluation the engine fails (an overflow, a zero divisor ...), -2 an assignment it refuses
 * (a range, a precision, a length, NOT NULL); the reason in err */
int ab_gen_eval(const ab_check *c, const ab_val *row, const ab_gcol *col, ab_val *out, uint8_t **tbuf, char *err, size_t errn);

#endif
