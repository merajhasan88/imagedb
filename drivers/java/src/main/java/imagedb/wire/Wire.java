package imagedb.wire;

/**
 * IMDBWIR1's constants (docs/n1-design.md §4; the C tiebreak: server/wire.h). Every integer on the wire is
 * little-endian.
 */
public final class Wire {
    private Wire() {}

    public static final byte[] MAGIC = {'I', 'M', 'D', 'B', 'W', 'I', 'R', '1'};
    public static final int VERSION = 1;
    public static final int USER = 64;          // a role name's field: 1 to 63 bytes of UTF-8, NUL-padded
    public static final int NONCE = 32;
    public static final int SALT = 64;          // the challenge's salt field; a verifier's salt is 8 to 64 bytes
    public static final int KEY = 32;
    public static final int PREAUTH_HEAD = 12;  // "IMDBWIR1" | u32 version, every version's first bytes
    public static final int HELLO_LEN = 112;
    public static final int CHALLENGE_LEN = 120;
    public static final int PROOF_LEN = 32;
    public static final int VERDICT_LEN = 36;
    public static final int AUTHMSG_LEN = 279;
    public static final int HEAD = 5;           // a frame's u32 length and u8 type
    public static final int FRAME_MAX = 16 << 20; // a frame's type and body
    public static final int BATCH_MAX = 4096;
    public static final int VALUES_MAX = 256;
    public static final int NAME_MAX = 63;
    public static final int COLNAME_MAX = 70;
    public static final int SQL_MAX = 1 << 22;
    public static final int VALUE_MAX = 65535;
    public static final int LABEL_MAX = 63;
    public static final int LABELS_MAX = 1024;
    public static final int STATUS_MAX = 511;
    public static final int MESSAGE_MAX = 4096;
    public static final int SCRAM_ITER_MIN = 1000;
    public static final int SCRAM_ITER_MAX = 1000000;
    public static final int SCRAM_SALT_MIN = 8;
    public static final int PW_MAX = 1024;
    public static final int SESSIONS_MAX = 65536;
    public static final int COPY_PIECE = 1 << 20; // a COPY_DATA frame's bytes at most (the C client's cut; §4: COPY_OUT's bound)

    /** the AuthMessage's endpoint byte */
    public static final int EP_TCP = 1, EP_UNIX = 2;
    /** §8f: a hello's flags, its channel binding's type */
    public static final int CB_NONE = 0, CB_EXPORTER = 1, CB_ENDPOINT = 2;
    /** a verdict's code */
    public static final int VERDICT_OK = 0, VERDICT_REFUSED = 1, VERDICT_BINDING = 2;

    // frame types: the client's 1 to 12, the server's 64 to 74
    public static final int QUERY = 1, PREPARE = 2, EXECUTE = 3, DEALLOCATE = 4, COPY_DATA = 5, COPY_DONE = 6,
            COPY_FAIL = 7, CANCEL = 8, PING = 9, TERMINATE = 10, SESSIONS = 11, KILL = 12, CLIENT_LAST = 12;
    public static final int COLUMNS = 64, ROWS = 65, DONE = 66, ERROR = 67, WARNING = 68, COPY_IN = 69, COPY_OUT = 70,
            READY = 71, PONG = 72, SESSIONS_LIST = 73, KILL_DONE = 74, SERVER_LAST = 74;

    /** READY's states */
    public static final int IDLE = 0, IN_TXN = 1, DOOMED = 2;
    /** KILL's kinds and KILL_DONE's codes */
    public static final int KILL_CANCEL = 1, KILL_TERMINATE = 2;
    public static final int KILLED = 0, KILL_NONE = 1;
    /** a session's state in SESSIONS_LIST */
    public static final int SS_IDLE = 0, SS_RUNNING = 1, SS_IN_TXN = 2, SS_COPY = 3;

    // value types (a value's tag; 0x80 | type for a NULL of that type)
    public static final int T_NONE = 0, T_INT64 = 1, T_FLOAT64 = 2, T_BOOL = 3, T_TEXT = 4, T_DECIMAL = 5,
            T_TIMESTAMP = 6, T_TIMESTAMPTZ = 7, T_DATE = 8, T_TIME = 9, T_UUID = 10, T_BYTEA = 11, T_INTERVAL = 12,
            T_ENUM = 13, T_LAST = 13;
    public static final int NULL_TAG = 0x80;

    // the ranges a value's own rules hold it to (wire.c: TS_MIN_US, TS_MAX_US; codec.h IMDB_DATE_MIN/MAX, IMDB_TIME_MAX)
    public static final long TS_MIN_US = -62135596800000000L;  // 0001-01-01 00:00:00
    public static final long TS_MAX_US = 253402300799999999L;  // 9999-12-31 23:59:59.999999
    public static final int DATE_MIN = -719162;                 // 0001-01-01
    public static final int DATE_MAX = 2932896;                 // 9999-12-31
    public static final long TIME_MAX = 86399999999L;          // 23:59:59.999999

    // the engine's error codes (IMDB_ERR_* magnitudes): an ERROR's code
    public static final int E_IO = 1, E_CORRUPT = 2, E_LIMIT = 3, E_INVALID = 4, E_NOMEM = 5, E_CONSTRAINT = 6,
            E_VERIFY = 7, E_AUTH = 8, E_STATE = 9, E_SYNTAX = 10, E_NOTFOUND = 11, E_UNSUPPORTED = 12, E_HISTORY = 13,
            E_CONFLICT = 14, E_CANCELLED = 15, E_PRIVILEGE = 16;

    public static String typeName(int t) {
        switch (t) {
        case T_NONE: return "NONE";
        case T_INT64: return "INT64";
        case T_FLOAT64: return "FLOAT64";
        case T_BOOL: return "BOOL";
        case T_TEXT: return "TEXT";
        case T_DECIMAL: return "DECIMAL";
        case T_TIMESTAMP: return "TIMESTAMP";
        case T_TIMESTAMPTZ: return "TIMESTAMPTZ";
        case T_DATE: return "DATE";
        case T_TIME: return "TIME";
        case T_UUID: return "UUID";
        case T_BYTEA: return "BYTEA";
        case T_INTERVAL: return "INTERVAL";
        case T_ENUM: return "ENUM";
        default: return "type " + t;
        }
    }

    public static String frameName(int t) {
        switch (t) {
        case QUERY: return "QUERY";
        case PREPARE: return "PREPARE";
        case EXECUTE: return "EXECUTE";
        case DEALLOCATE: return "DEALLOCATE";
        case COPY_DATA: return "COPY_DATA";
        case COPY_DONE: return "COPY_DONE";
        case COPY_FAIL: return "COPY_FAIL";
        case CANCEL: return "CANCEL";
        case PING: return "PING";
        case TERMINATE: return "TERMINATE";
        case SESSIONS: return "SESSIONS";
        case KILL: return "KILL";
        case COLUMNS: return "COLUMNS";
        case ROWS: return "ROWS";
        case DONE: return "DONE";
        case ERROR: return "ERROR";
        case WARNING: return "WARNING";
        case COPY_IN: return "COPY_IN";
        case COPY_OUT: return "COPY_OUT";
        case READY: return "READY";
        case PONG: return "PONG";
        case SESSIONS_LIST: return "SESSIONS_LIST";
        case KILL_DONE: return "KILL_DONE";
        default: return "frame type " + t;
        }
    }
}
