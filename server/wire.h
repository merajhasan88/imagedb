/* IMDBWIR1: imagedb's own protocol (docs/n1-design.md §4), the one implementation of its bytes, built into the server
 * and the C client. Pure functions over caller buffers: no socket, no engine state, and nothing allocated through the
 * engine's helpers (a connection thread must not touch the process-wide heap ceiling: §2), only through the wire's own
 * counted allocator. Every decoder reads through imdb_rd: exact lengths, no trailing bytes, every count bounded by the
 * bytes left before anything is sized by it, zero padding where the layout pads; a later protocol version is refused by
 * name (UNSUPPORTED), never as damage. Values are never copied into arrays: a decoder validates a run of them in place
 * (an imdbw_span) and its reader walks it (imdbw_span_next), so a frame costs its own bytes and a few small arrays.
 * Each field has one predicate, which its decoder and its encoder both apply: an encoder never writes what its decoder
 * would refuse (b->err instead), and any bytes a decoder takes encode back to themselves. */
#ifndef IMDB_WIRE_H
#define IMDB_WIRE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "../src/util.h"

#define IMDBW_MAGIC "IMDBWIR1"
#define IMDBW_VERSION 1u
#define IMDBW_USER 64u        /* a role name's field: UTF-8, 1 to 63 bytes, NUL-padded */
#define IMDBW_NONCE 32u
#define IMDBW_SALT 64u        /* a verifier's salt: 8 to 64 bytes (scram.h) */
#define IMDBW_KEY 32u
#define IMDBW_PREAUTH_HEAD 12u /* every pre-auth message's first bytes, in every version: "IMDBWIR1" and u32 its version */
#define IMDBW_HELLO_LEN 112u
#define IMDBW_CHALLENGE_LEN 120u
#define IMDBW_PROOF_LEN 32u
#define IMDBW_VERDICT_LEN 36u
#define IMDBW_AUTHMSG_LEN 279u /* "IMDBWIR1-SCRAM" (14) | endpoint | the hello's 112 bytes | the challenge's 120 | binding[32] */
#define IMDBW_HEAD 5u          /* a frame's u32 length and u8 type */
#define IMDBW_FRAME_MAX (16u << 20) /* a frame's type and body */
#define IMDBW_BATCH_MAX 4096u  /* statements in a QUERY, parameter sets in an EXECUTE */
#define IMDBW_VALUES_MAX 256u  /* values a statement or a set takes (IMDB_MAX_PARAMS); columns in a result */
#define IMDBW_NAME_MAX 63u     /* a prepared statement's name (IMDB_MAX_IDENT) */
#define IMDBW_COLNAME_MAX 70u  /* a result column's name (imdb_result: IMDB_MAX_IDENT + 7) */
#define IMDBW_SQL_MAX (1u << 22)  /* one statement's text (IMDB_MAX_SQL) */
#define IMDBW_VALUE_MAX 65535u /* a TEXT's or a BYTEA's bytes (IMDB_MAX_TEXT) */
#define IMDBW_LABEL_MAX 63u    /* an ENUM label's bytes (IMDB_MAX_ENUM_LABEL) */
#define IMDBW_LABELS_MAX 1024u /* an ENUM's labels (IMDB_MAX_ENUM_LABELS) */
#define IMDBW_STATUS_MAX 511u  /* a DONE's status text (imdb_result.status) */
#define IMDBW_MESSAGE_MAX 4096u /* an ERROR's or WARNING's text, a COPY_FAIL's reason */
#define IMDBW_SCRAM_ITER_MIN 1000u
#define IMDBW_SCRAM_ITER_MAX 1000000u
#define IMDBW_SCRAM_SALT_MIN 8u
#define IMDBW_PW_MAX 1024u     /* a password's bytes (IMDB_SCRAM_PW_MAX) */

enum { IMDBW_EP_TCP = 1, IMDBW_EP_UNIX = 2 };
/* §8f (decided 2026-11-18): a hello's flags are its channel binding's type, the rest of the word reserved (refused): none
 * on the Unix socket; on TCP the TLS exporter (RFC 9266, the default) or tls-server-end-point (RFC 5929: a hash of the
 * server's certificate; taken only by a server run with --channel-binding any). The AuthMessage holds the hello's bytes,
 * so the proof covers the type. A verdict's code 2: the binding type refused by this server (its proof never checked) */
enum { IMDBW_CB_NONE = 0, IMDBW_CB_EXPORTER = 1, IMDBW_CB_ENDPOINT = 2 };
enum { IMDBW_VERDICT_OK = 0, IMDBW_VERDICT_REFUSED = 1, IMDBW_VERDICT_BINDING = 2 };

/* frame types: the client's below 64, the server's from 64 */
enum {
    IMDBW_QUERY = 1,
    IMDBW_PREPARE = 2,
    IMDBW_EXECUTE = 3,
    IMDBW_DEALLOCATE = 4,
    IMDBW_COPY_DATA = 5,
    IMDBW_COPY_DONE = 6,
    IMDBW_COPY_FAIL = 7,
    IMDBW_CANCEL = 8,
    IMDBW_PING = 9,
    IMDBW_TERMINATE = 10,
    IMDBW_CLIENT_LAST = 10,
    IMDBW_COLUMNS = 64,
    IMDBW_ROWS = 65,
    IMDBW_DONE = 66,
    IMDBW_ERROR = 67,
    IMDBW_WARNING = 68,
    IMDBW_COPY_IN = 69,
    IMDBW_COPY_OUT = 70,
    IMDBW_READY = 71,
    IMDBW_PONG = 72,
    IMDBW_SERVER_LAST = 72,
};

/* READY's states: a failed statement is undone alone (statement-level rollback), so a transaction goes on after an
 * ERROR; a doomed one (an ALTER, an ERASE, a SERIALIZABLE conflict) takes only ROLLBACK */
enum { IMDBW_IDLE = 0, IMDBW_IN_TXN = 1, IMDBW_DOOMED = 2 };

/* a value's wire type: the contract (docs/n1-design.md §4), not the engine's internal forms */
enum {
    IMDBW_T_NONE = 0,        /* no type: a column whose type the statement does not know, a NULL of none */
    IMDBW_T_INT64 = 1,       /* i64 */
    IMDBW_T_FLOAT64 = 2,     /* IEEE 754 binary64's bits: finite, never -0 (the engine's one zero) */
    IMDBW_T_BOOL = 3,        /* u8 0 or 1 */
    IMDBW_T_TEXT = 4,        /* u32 length (at most 65,535), UTF-8 without NUL */
    IMDBW_T_DECIMAL = 5,     /* u8 scale (0-38), i128 unscaled (|v| < 10^38) */
    IMDBW_T_TIMESTAMP = 6,   /* i64 microseconds since 1970-01-01 00:00, no zone, years 1 to 9999 */
    IMDBW_T_TIMESTAMPTZ = 7, /* i64 microseconds since the epoch, UTC, years 1 to 9999 */
    IMDBW_T_DATE = 8,        /* i32 days since 1970-01-01 (0001-01-01 to 9999-12-31) */
    IMDBW_T_TIME = 9,        /* i64 microseconds since midnight (0 to 86,399,999,999) */
    IMDBW_T_UUID = 10,       /* 16 bytes */
    IMDBW_T_BYTEA = 11,      /* u32 length (at most 65,535), bytes */
    IMDBW_T_INTERVAL = 12,   /* i32 months, i32 days, i64 microseconds: any triple */
    IMDBW_T_ENUM = 13,       /* u8 length (0-63), the label's UTF-8: never the ordinal (the engine's); a parameter's
                              * only as a NULL (a label is sent as TEXT) */
    IMDBW_T_LAST = 13,
};
/* a value's tag: its type (1 to 13), or 0x80 | its type (0 to 13) for a NULL of that type: the engine binds a NULL
 * parameter by its type, so a NULL keeps one */
#define IMDBW_NULL_TAG 0x80u

typedef struct imdbw_value {
    uint8_t type;   /* IMDBW_T_*: a value's, or a NULL's (IMDBW_T_NONE: a NULL of no type) */
    bool null;
    uint8_t scale;  /* DECIMAL */
    int32_t mon;    /* INTERVAL */
    int32_t day;    /* INTERVAL; DATE's days */
    int64_t i;      /* INT64, BOOL, TIMESTAMP, TIMESTAMPTZ, TIME, INTERVAL's microseconds */
    uint64_t f;     /* FLOAT64's bits */
    __int128 d;     /* DECIMAL's unscaled value */
    const uint8_t *s; /* TEXT, BYTEA, ENUM's label, UUID's 16 bytes: into the bytes they came in, not owned */
    uint32_t len;
} imdbw_value;

/* ---- the wire's own allocations (docs/n1-design.md §2: never the engine's, whose ceiling is process-wide): zeroed
 * blocks, a count of the live ones and the largest request (the tests hold both) ---- */
void *imdbw_alloc(size_t n, size_t size); /* n x size, zeroed; NULL on overflow or failure */
void imdbw_free(void *p);
int64_t imdbw_live_blocks(void);
void imdbw_alloc_peak_reset(void); /* the largest request since: a count is bounded by its bytes before it sizes anything */
size_t imdbw_alloc_peak(void);
void imdbw_alloc_fail_at(int64_t n); /* tests: the nth allocation from now fails (0: none) */

/* ---- the output buffer: the wire's own, sticky on failure ---- */
typedef struct imdbw_buf {
    uint8_t *p;
    size_t len, cap;
    bool err;     /* an allocation failed, a limit was passed or a field its decoder refuses was given: send nothing */
    bool nomem;   /* of those, an allocation (out of memory, not a limit or a field: N1b's conversion says which) */
} imdbw_buf;
void imdbw_buf_init(imdbw_buf *b);
void imdbw_buf_free(imdbw_buf *b);
void imdbw_buf_reset(imdbw_buf *b); /* empty, its memory kept, err cleared */
void imdbw_put(imdbw_buf *b, const void *p, size_t n);
void imdbw_put_u8(imdbw_buf *b, uint8_t v);
void imdbw_put_u16(imdbw_buf *b, uint16_t v);
void imdbw_put_u32(imdbw_buf *b, uint32_t v);
void imdbw_put_u64(imdbw_buf *b, uint64_t v);
void imdbw_patch_u32(imdbw_buf *b, size_t at, uint32_t v); /* a count written before what it counts */

/* ---- before authentication: fixed sizes ---- */
typedef struct imdbw_hello {
    uint32_t version, flags;
    char user[IMDBW_USER];  /* NUL-terminated, at most 63 bytes */
    uint8_t nonce[IMDBW_NONCE];
} imdbw_hello;
typedef struct imdbw_challenge {
    uint32_t version;
    uint8_t salt_len;
    uint8_t salt[IMDBW_SALT];
    uint32_t iter;
    uint8_t nonce[IMDBW_NONCE];
} imdbw_challenge;
typedef struct imdbw_verdict {
    uint32_t code;          /* IMDBW_VERDICT_*: 0 accepted, 1 refused, 2 its binding type refused */
    uint8_t sig[IMDBW_KEY]; /* the server's signature; zeros when refused */
} imdbw_verdict;
/* the head every version keeps: a server reads a hello's 12 bytes first and answers a version it does not speak with its
 * own head (imdbw_version_put) and a close, so a later client can speak an earlier version; *version is any number,
 * UNSUPPORTED only for a later magic ("IMDBWIR2": another protocol), damage else */
int imdbw_preauth_head(const uint8_t in[IMDBW_PREAUTH_HEAD], uint32_t *version, imdb_err *e);
void imdbw_version_put(uint8_t out[IMDBW_PREAUTH_HEAD]);
/* each encoder writes what its decoder takes, or returns -1 (a field the decoder would refuse) */
int imdbw_hello_put(const imdbw_hello *h, uint8_t out[IMDBW_HELLO_LEN]);
int imdbw_hello_get(const uint8_t in[IMDBW_HELLO_LEN], imdbw_hello *h, imdb_err *e);
int imdbw_challenge_put(const imdbw_challenge *c, uint8_t out[IMDBW_CHALLENGE_LEN]);
int imdbw_challenge_get(const uint8_t in[IMDBW_CHALLENGE_LEN], imdbw_challenge *c, imdb_err *e);
int imdbw_verdict_put(const imdbw_verdict *v, uint8_t out[IMDBW_VERDICT_LEN]);
int imdbw_verdict_get(const uint8_t in[IMDBW_VERDICT_LEN], imdbw_verdict *v, imdb_err *e);
/* a role name's field: UTF-8, 1 to 63 bytes, no NUL */
bool imdbw_user_ok(const char *user, size_t len);

/* ---- SCRAM-SHA-256 (RFC 5802's computation over the AuthMessage below; docs/n1-design.md §3, §4) ---- */
/* "IMDBWIR1-SCRAM" | u8 endpoint | the hello's bytes | the challenge's bytes | binding[32] (the TLS exporter's bytes on
 * TCP, zeros on the socket): every byte either side sent before the proof, bound */
void imdbw_auth_message(uint8_t endpoint, const uint8_t hello[IMDBW_HELLO_LEN], const uint8_t challenge[IMDBW_CHALLENGE_LEN],
                        const uint8_t binding[IMDBW_KEY], uint8_t out[IMDBW_AUTHMSG_LEN]);
/* the client: the password's bytes (printable ASCII, 1 to 1,024 of them, as CREATE ROLE takes one) to its proof and the
 * server's signature it expects; -1 for a password CREATE ROLE would refuse */
int imdbw_scram_client(const char *pw, size_t pwlen, const imdbw_challenge *c, const uint8_t am[IMDBW_AUTHMSG_LEN],
                       uint8_t proof[IMDBW_KEY], uint8_t server_sig[IMDBW_KEY]);
/* the server: a verifier's StoredKey and ServerKey and the client's proof; true when the proof is the password's
 * (compared in constant time), the server's signature in sig either way (the caller sends zeros on a refusal) */
bool imdbw_scram_server(const uint8_t stored[IMDBW_KEY], const uint8_t server_key[IMDBW_KEY],
                        const uint8_t am[IMDBW_AUTHMSG_LEN], const uint8_t proof[IMDBW_KEY], uint8_t sig[IMDBW_KEY]);
/* an unknown name's salt: HMAC-SHA-256(secret, the name's 64-byte field), its first 16 bytes (the same for every attempt
 * at that name while the secret stays) */
void imdbw_fake_salt(const uint8_t secret[IMDBW_KEY], const char *user, uint8_t salt[16]);

/* ---- after authentication: frames ---- */
/* a frame's head: the length (of its type and body: 1 to IMDBW_FRAME_MAX) and a type of the direction's */
int imdbw_head_get(const uint8_t in[IMDBW_HEAD], bool from_server, uint32_t *len, uint8_t *type, imdb_err *e);
/* a frame begun and ended around a body written in between (the head patched with its length) */
size_t imdbw_frame_begin(imdbw_buf *b, uint8_t type);
void imdbw_frame_end(imdbw_buf *b, size_t at);

/* the longest prefix of s, at most max bytes, that is UTF-8 without NUL: cut before the first byte that is not, and
 * never inside a character (an engine message trimmed for an ERROR: imdb_err's 256 bytes may end inside one) */
size_t imdbw_utf8_fit(const uint8_t *s, size_t n, size_t max);

/* values */
bool imdbw_value_ok(const imdbw_value *v); /* the value's own rules: its decoder's and its encoder's */
void imdbw_value_put(imdbw_buf *b, const imdbw_value *v); /* b->err for a value imdbw_value_ok refuses */
int imdbw_value_get(imdb_rd *r, imdbw_value *v, imdb_err *e);
bool imdbw_value_eq(const imdbw_value *a, const imdbw_value *b); /* the same wire bytes */

typedef struct imdbw_text {
    const uint8_t *p;
    uint32_t len;
} imdbw_text;

/* a run of values a decoder validated in place */
typedef struct imdbw_span {
    const uint8_t *p;
    size_t len;
    uint32_t n;
} imdbw_span;
void imdbw_span_begin(const imdbw_span *s, imdb_rd *r);
bool imdbw_span_next(imdb_rd *r, imdbw_value *v); /* false at the run's end */

typedef struct imdbw_col {
    char name[IMDBW_COLNAME_MAX + 1];
    uint8_t type;            /* IMDBW_T_*; IMDBW_T_NONE when the statement does not know it: each value its own type */
    uint16_t precision, scale;
    imdbw_text *labels;      /* ENUM: its labels in order */
    uint16_t *sorted;        /* ENUM: the labels' indexes in byte order (membership, distinctness): imdbw_cols_index */
    uint32_t nlabels;
} imdbw_col;

/* a frame's body, decoded; arrays the wire's own (imdbw_msg_free), every pointer into the body */
typedef struct imdbw_msg {
    uint8_t type;
    char name[IMDBW_NAME_MAX + 1];      /* PREPARE, EXECUTE, DEALLOCATE */
    imdbw_text *texts;                  /* QUERY: its statements; PREPARE: its statement; COPY_FAIL, ERROR, WARNING */
    imdbw_span *params;                 /* QUERY: each statement's values */
    uint32_t ntexts;
    imdbw_span vals;                    /* EXECUTE: nsets sets of nvals; ROWS: nsets rows of the columns' count */
    uint32_t nsets;
    uint16_t nvals;
    const uint8_t *data;                /* COPY_DATA, COPY_OUT */
    uint32_t dlen;
    imdbw_col *cols;                    /* COLUMNS */
    uint16_t ncols;
    imdbw_text status;                  /* DONE: its status, the rows returned or written */
    uint64_t count;
    bool has_read, has_write;
    uint64_t read_commit, lake_commit, write_commit;
    uint8_t read_hash[32], digest[32], lake_manifest[32], write_hash[32];
    uint8_t db_id[16];                  /* the database the read point is of (imdb_result.db_id) */
    bool own;                           /* the read saw its transaction's own writes, past its commit (snap_own) */
    uint32_t code, index;               /* ERROR: the engine's code (1 to 15 in this imagedb: IMDB_ERR_* negated), its index */
    uint8_t state;                      /* READY */
} imdbw_msg;

/* a frame's body decoded: a ROWS frame against the COLUMNS message before it (cols; ignored for the other types), each
 * value its column's type or NULL (imdbw_value_fits) */
int imdbw_msg_get(uint8_t type, const uint8_t *body, size_t len, const imdbw_msg *cols, imdbw_msg *m, imdb_err *e);
void imdbw_msg_free(imdbw_msg *m);
/* and encoded as a frame, the exact bytes its decoder takes (a decoded message encodes to the frame it came from), a ROWS
 * message against its COLUMNS (cols, as the decoder; ignored for the other types); b->err
 * for a field its decoder would refuse (every span walked: its count, its values and their columns) */
void imdbw_msg_put(imdbw_buf *b, const imdbw_msg *m, const imdbw_msg *cols);
/* a value checked against its column (ROWS' rule): NULL, or its type at the column's scale and within its precision, an
 * integer within its width, a TEXT within its VARCHAR's characters, an ENUM one of its labels (cols indexed) */
bool imdbw_value_fits(const imdbw_col *c, const imdbw_value *v);
/* a COLUMNS message's ENUM columns indexed, for one built by hand (the decoder does it): -1 for labels not distinct or
 * past their bounds, -2 out of memory; imdbw_cols_unindex frees what it made (imdbw_msg_free does too) */
int imdbw_cols_index(imdbw_msg *m);
void imdbw_cols_unindex(imdbw_msg *m);

/* ROWS a value at a time, each checked once against its column (imdbw_value_fits) and written: the server's path for a
 * result. b->err for a value that does not fit, a row left part way, or no row */
typedef struct imdbw_rows {
    imdbw_buf *b;
    const imdbw_msg *cols;
    size_t at;       /* the frame's head */
    uint32_t n;      /* rows written */
    uint16_t col;    /* the next value's column */
} imdbw_rows;
void imdbw_rows_begin(imdbw_rows *w, imdbw_buf *b, const imdbw_msg *cols);
void imdbw_rows_value(imdbw_rows *w, const imdbw_value *v);
void imdbw_rows_end(imdbw_rows *w);
/* the frame's bytes so far, and whether a row is whole: the server ends a frame at a row's end once past its target (a
 * few hundred KiB, far below the 16 MiB a frame may hold) and begins the next; a row longer than a frame cannot be sent */
size_t imdbw_rows_len(const imdbw_rows *w);
bool imdbw_rows_whole(const imdbw_rows *w);

#endif
