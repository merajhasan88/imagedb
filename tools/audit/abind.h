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
} ab_col;

/* a relation the catalog holds by name at the view's commit: a live table (kind 1), or a live view (kind 2) with its
 * logged columns (a view is never expanded again: its own text was bound at its own commit) */
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

#endif
