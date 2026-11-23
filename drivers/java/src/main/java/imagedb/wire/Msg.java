package imagedb.wire;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/** A server frame, decoded (§4's types 64 to 74). */
public abstract class Msg {
    public final int type;

    Msg(int type) { this.type = type; }

    @Override
    public String toString() { return Wire.frameName(type); }

    /** a result column: name, wire type (0: not known), precision, scale, an ENUM's labels in the type's order */
    public static final class Column {
        public final String name;
        public final int type, precision, scale;
        public final List<String> labels;
        final Set<ByteKey> labelSet;

        Column(String name, int type, int precision, int scale, List<String> labels, Set<ByteKey> labelSet) {
            this.name = name;
            this.type = type;
            this.precision = precision;
            this.scale = scale;
            this.labels = labels;
            this.labelSet = labelSet;
        }

        /** ROWS' rule (wire.c imdbw_value_fits): NULL of its type, or its type at its scale, width, length and labels */
        public boolean fits(Value v) {
            if (type == Wire.T_NONE) return true; // a column not known: each value its own type
            if (v.type != type) return false;     // a NULL too: one tag a column, its type's
            if (v.isNull) return true;
            switch (type) {
            case Wire.T_DECIMAL:
                return v.scale() == scale && v.unscaled().abs().compareTo(Value.POW10[precision != 0 ? precision : 38]) < 0;
            case Wire.T_INT64:
                return precision == 16 ? v.int64() >= Short.MIN_VALUE && v.int64() <= Short.MAX_VALUE
                       : precision == 32 ? v.int64() >= Integer.MIN_VALUE && v.int64() <= Integer.MAX_VALUE
                                         : true;
            case Wire.T_TEXT: {
                if (precision == 0) return true;
                byte[] b = v.rawBytes();
                return Utf8.chars(b, 0, b.length) <= precision;
            }
            case Wire.T_ENUM: return labelSet.contains(new ByteKey(v.rawBytes()));
            default: return true;
            }
        }

        @Override
        public String toString() {
            return name + " " + Wire.typeName(type) + (precision != 0 || scale != 0 ? "(" + precision + "," + scale + ")" : "")
                    + (labels.isEmpty() ? "" : " " + labels);
        }
    }

    /** a byte string as a set's key (labels compared by their bytes, as wire.c's label_cmp) */
    static final class ByteKey {
        final byte[] b;

        ByteKey(byte[] b) { this.b = b; }

        @Override
        public boolean equals(Object o) { return o instanceof ByteKey && Arrays.equals(b, ((ByteKey) o).b); }

        @Override
        public int hashCode() { return Arrays.hashCode(b); }
    }

    public static final class Columns extends Msg {
        public final List<Column> columns;

        Columns(List<Column> columns) {
            super(Wire.COLUMNS);
            this.columns = Collections.unmodifiableList(columns);
        }
    }

    /** ROWS: its rows, each the COLUMNS' count of values, each held to its column */
    public static final class Rows extends Msg {
        public final List<Value[]> rows;

        Rows(List<Value[]> rows) {
            super(Wire.ROWS);
            this.rows = Collections.unmodifiableList(rows);
        }
    }

    /** the engine's read point (imdb_result: snap, head, digest, lake_seq, lake_manifest, db_id, snap_own) */
    public static final class ReadPoint {
        public final long commit;        // u64
        public final byte[] hash;        // 32
        public final byte[] digest;      // 32: the state digest
        public final long lakeCommit;    // u64
        public final byte[] lakeManifest; // 32
        public final byte[] dbId;        // 16
        public final boolean own;        // the read saw its transaction's own writes, past that commit

        ReadPoint(long commit, byte[] hash, byte[] digest, long lakeCommit, byte[] lakeManifest, byte[] dbId, boolean own) {
            this.commit = commit;
            this.hash = hash;
            this.digest = digest;
            this.lakeCommit = lakeCommit;
            this.lakeManifest = lakeManifest;
            this.dbId = dbId;
            this.own = own;
        }

        @Override
        public String toString() {
            return "commit " + Long.toUnsignedString(commit) + " " + Der.hex(hash).substring(0, 16) + "... lake "
                    + Long.toUnsignedString(lakeCommit) + (own ? " (own writes)" : "");
        }
    }

    public static final class Done extends Msg {
        public final String status;
        public final long count;         // u64: the rows returned or written
        public final ReadPoint read;     // or null
        public final long writeCommit;   // 0 when the statement wrote no commit
        public final byte[] writeHash;   // or null

        Done(String status, long count, ReadPoint read, long writeCommit, byte[] writeHash) {
            super(Wire.DONE);
            this.status = status;
            this.count = count;
            this.read = read;
            this.writeCommit = writeCommit;
            this.writeHash = writeHash;
        }

        @Override
        public String toString() { return "DONE " + status; }
    }

    public static final class Error extends Msg {
        public final long code;   // u32 >= 1 (a later imagedb may add codes): kept whole
        public final int index;   // 0 to 4,095: the statement's (or parameter set's) index in its batch
        public final String message;

        /** the code as an int: one past int's range (no imagedb sends one) read as no class */
        public int codeInt() { return code > Integer.MAX_VALUE ? Integer.MAX_VALUE : (int) code; }

        Error(long code, int index, String message) {
            super(Wire.ERROR);
            this.code = code;
            this.index = index;
            this.message = message;
        }

        @Override
        public String toString() { return "ERROR " + code + " at " + index + ": " + message; }
    }

    public static final class Warning extends Msg {
        public final String message;

        Warning(String message) {
            super(Wire.WARNING);
            this.message = message;
        }
    }

    public static final class CopyIn extends Msg {
        CopyIn() { super(Wire.COPY_IN); }
    }

    public static final class CopyOut extends Msg {
        public final byte[] data;

        CopyOut(byte[] data) {
            super(Wire.COPY_OUT);
            this.data = data;
        }
    }

    public static final class Ready extends Msg {
        public final int state; // Wire.IDLE, IN_TXN, DOOMED

        Ready(int state) {
            super(Wire.READY);
            this.state = state;
        }

        @Override
        public String toString() { return "READY " + state; }
    }

    public static final class Pong extends Msg {
        Pong() { super(Wire.PONG); }
    }

    /** a session in SESSIONS_LIST */
    public static final class Session {
        public final long id;      // u64 >= 1, strictly increasing in the list
        public final long role;    // u32 >= 1
        public final int endpoint; // 1 TCP, 2 the socket
        public final int state;    // Wire.SS_*
        public final long ageMs;   // u64
        public final String name;  // its role's name now ("" for a role no longer among the logins)

        Session(long id, long role, int endpoint, int state, long ageMs, String name) {
            this.id = id;
            this.role = role;
            this.endpoint = endpoint;
            this.state = state;
            this.ageMs = ageMs;
            this.name = name;
        }

        @Override
        public String toString() {
            return "session " + Long.toUnsignedString(id) + " role " + role + " (" + name + ") " + (endpoint == 1 ? "tcp" : "socket")
                    + " state " + state + " " + Long.toUnsignedString(ageMs) + " ms";
        }
    }

    public static final class SessionsList extends Msg {
        public final List<Session> sessions;

        SessionsList(List<Session> sessions) {
            super(Wire.SESSIONS_LIST);
            this.sessions = Collections.unmodifiableList(sessions);
        }
    }

    public static final class KillDone extends Msg {
        public final int code;      // 0 done, 1 no such session
        public final long session;  // the KILL's session id

        KillDone(int code, long session) {
            super(Wire.KILL_DONE);
            this.code = code;
            this.session = session;
        }
    }

    static Set<ByteKey> newSet() { return new HashSet<>(); }
}
