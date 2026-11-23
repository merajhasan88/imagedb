package imagedb.wire;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Set;

/**
 * After authentication (§4): u32 length (of the type and the body: 1 to 16 MiB) | u8 type | body. The client's frames
 * encoded (each field held to its decoder's rule: an encoder never writes what a decoder refuses) and the server's
 * decoded strictly (wire.c body_get: exact lengths, no trailing bytes, every count bounded by the bytes left before it
 * sizes anything, a ROWS held to the COLUMNS before it).
 */
public final class Frames {
    private Frames() {}

    // ---- texts: UTF-8 without NUL after a length of 1, 2 or 4 bytes ----

    static void text(Buf b, int lenBytes, int min, int max, byte[] t, String what) throws WireException {
        if (t.length < min || t.length > max)
            throw new WireException(Wire.E_LIMIT, what + " of " + t.length + " bytes (" + min + " to " + max + ")");
        if (!Utf8.valid(t)) throw WireException.invalid(what + " that is not UTF-8 without NUL");
        if (lenBytes == 1) b.u8(t.length);
        else if (lenBytes == 2) b.u16(t.length);
        else b.u32(t.length);
        b.put(t);
    }

    static byte[] textGet(Reader r, int lenBytes, int min, int max) throws WireException {
        long n = lenBytes == 1 ? r.u8("a text") : lenBytes == 2 ? r.u16("a text") : r.u32("a text");
        if (n < min || n > max) throw WireException.limit("a text of " + n + " bytes (" + min + " to " + max + ")");
        byte[] t = r.bytes((int) n, "a text");
        if (!Utf8.valid(t)) throw WireException.corrupt("a text not UTF-8 without NUL");
        return t;
    }

    static String textGetString(Reader r, int lenBytes, int min, int max) throws WireException {
        byte[] t = textGet(r, lenBytes, min, max);
        return Utf8.decode(t, 0, t.length);
    }

    // ---- the client's frames ----

    private static int begin(Buf b, int type) throws WireException {
        int at = b.length();
        b.u32(0);
        b.u8(type);
        return at;
    }

    private static byte[] end(Buf b, int at) throws WireException {
        long n = b.length() - at - 4;
        if (n > Wire.FRAME_MAX) throw WireException.limit("a frame past 16 MiB");
        b.patch32(at, n);
        return b.bytes();
    }

    /** a value a parameter may be: any but a non-NULL ENUM (a label is sent as TEXT) */
    static void param(Buf b, Value v) throws WireException {
        if (v == null) throw WireException.invalid("a parameter: null (use a NULL Value)");
        if (v.type == Wire.T_ENUM && !v.isNull) throw WireException.invalid("an ENUM parameter: a label is sent as TEXT");
        v.encode(b);
    }

    /** one statement of a QUERY: its text and its $1 to $k */
    public static final class Stmt {
        public final byte[] sql;
        public final List<Value> params;

        public Stmt(String sql, List<Value> params) throws WireException {
            this.sql = Utf8.encode(sql);
            this.params = params == null ? Collections.emptyList() : params;
        }
    }

    /** QUERY: u32 n (1 to 4,096) | n x (statement | u16 k (0 to 256) | k values) */
    public static byte[] query(List<Stmt> stmts) throws WireException {
        if (stmts.isEmpty() || stmts.size() > Wire.BATCH_MAX)
            throw new WireException(Wire.E_LIMIT, "a QUERY holds 1 to 4,096 statements");
        Buf b = new Buf();
        int at = begin(b, Wire.QUERY);
        b.u32(stmts.size());
        for (Stmt s : stmts) {
            text(b, 4, 1, Wire.SQL_MAX, s.sql, "a statement");
            if (s.params.size() > Wire.VALUES_MAX) throw new WireException(Wire.E_LIMIT, "a statement's values: at most 256");
            b.u16(s.params.size());
            for (Value v : s.params) param(b, v);
        }
        return end(b, at);
    }

    static void name(Buf b, String name) throws WireException {
        if (name == null) throw WireException.invalid("a prepared statement's name is 1 to 63 bytes");
        byte[] n = Utf8.encode(name);
        if (n.length < 1 || n.length > Wire.NAME_MAX) throw WireException.invalid("a prepared statement's name is 1 to 63 bytes");
        text(b, 1, 1, Wire.NAME_MAX, n, "a name");
    }

    /** PREPARE: name | statement */
    public static byte[] prepare(String name, String sql) throws WireException {
        Buf b = new Buf();
        int at = begin(b, Wire.PREPARE);
        name(b, name);
        text(b, 4, 1, Wire.SQL_MAX, Utf8.encode(sql), "a statement");
        return end(b, at);
    }

    /** EXECUTE: name | u32 sets (1 to 4,096) | u16 values a set (0 to 256) | the sets' values in order */
    public static byte[] execute(String name, List<List<Value>> sets) throws WireException {
        if (sets.isEmpty() || sets.size() > Wire.BATCH_MAX)
            throw new WireException(Wire.E_LIMIT, "an EXECUTE of 1 to 4,096 parameter sets");
        int nv = sets.get(0).size();
        if (nv > Wire.VALUES_MAX) throw new WireException(Wire.E_LIMIT, "an EXECUTE's set: at most 256 values");
        Buf b = new Buf();
        int at = begin(b, Wire.EXECUTE);
        name(b, name);
        b.u32(sets.size());
        b.u16(nv);
        for (List<Value> set : sets) {
            if (set.size() != nv) throw WireException.invalid("an EXECUTE's sets hold the same count of values");
            for (Value v : set) param(b, v);
        }
        return end(b, at);
    }

    public static byte[] deallocate(String name) throws WireException {
        Buf b = new Buf();
        int at = begin(b, Wire.DEALLOCATE);
        name(b, name);
        return end(b, at);
    }

    /** COPY_DATA: its bytes (at least one; at most a frame) */
    public static byte[] copyData(byte[] p, int off, int len) throws WireException {
        if (len < 1) throw WireException.invalid("a COPY_DATA of no bytes");
        Buf b = new Buf();
        int at = begin(b, Wire.COPY_DATA);
        b.put(p, off, len);
        return end(b, at);
    }

    public static byte[] copyFail(String message) throws WireException {
        byte[] m = Utf8.encode(message);
        m = java.util.Arrays.copyOf(m, Utf8.fit(m, m.length, Wire.MESSAGE_MAX)); // cut at a character, as imdbw_utf8_fit
        Buf b = new Buf();
        int at = begin(b, Wire.COPY_FAIL);
        text(b, 2, 0, Wire.MESSAGE_MAX, m, "a COPY_FAIL's reason");
        return end(b, at);
    }

    /** a frame of no body: COPY_DONE, CANCEL, PING, TERMINATE, SESSIONS */
    public static byte[] empty(int type) {
        if (type != Wire.COPY_DONE && type != Wire.CANCEL && type != Wire.PING && type != Wire.TERMINATE && type != Wire.SESSIONS)
            throw new IllegalArgumentException("a frame with a body");
        return new byte[] {1, 0, 0, 0, (byte) type};
    }

    /** KILL: u8 kind (1 cancel, 2 terminate) | u64 a session's id (at least 1) */
    public static byte[] kill(int kind, long session) throws WireException {
        if ((kind != Wire.KILL_CANCEL && kind != Wire.KILL_TERMINATE) || session == 0)
            throw WireException.invalid("a KILL's kind is cancel or terminate, its session an id from SESSIONS");
        Buf b = new Buf();
        int at = begin(b, Wire.KILL);
        b.u8(kind);
        b.u64(session);
        return end(b, at);
    }

    // ---- the server's frames ----

    /** a frame's head from the server: the length of its type and body (1 to 16 MiB) and a server's type */
    public static int[] head(byte[] h) throws WireException {
        long len = Buf.getLe32(h, 0);
        int type = h[4] & 0xff;
        if (len < 1 || len > Wire.FRAME_MAX) throw WireException.limit("a frame of " + len + " bytes (1 to 16777216)");
        if (type < Wire.COLUMNS || type > Wire.SERVER_LAST) throw WireException.corrupt("a frame of a type this side does not send");
        return new int[] {(int) len, type};
    }

    /** a server frame's body, decoded; a ROWS against cols (the COLUMNS before it, or null) */
    public static Msg decode(int type, byte[] body, Msg.Columns cols) throws WireException {
        Reader r = new Reader(body);
        Msg m = body(type, r, cols);
        if (r.left() != 0) throw WireException.corrupt("a body with bytes past its end");
        return m;
    }

    private static Msg body(int type, Reader r, Msg.Columns cols) throws WireException {
        switch (type) {
        case Wire.COLUMNS: {
            int n = r.u16("a COLUMNS");
            if (n < 1 || n > Wire.VALUES_MAX || n > r.left() / 7) // a column: 7 bytes at least
                throw WireException.corrupt("a COLUMNS of 1 to 256 columns it holds the bytes of");
            List<Msg.Column> cs = new ArrayList<>(n);
            for (int i = 0; i < n; i++) cs.add(column(r));
            return new Msg.Columns(cs);
        }
        case Wire.ROWS: {
            if (cols == null) throw WireException.corrupt("a ROWS with no COLUMNS before it");
            long n = r.u32("a ROWS");
            if (n < 1) throw WireException.corrupt("a ROWS of no row");
            int nc = cols.columns.size();
            if (n * nc > r.left()) throw WireException.corrupt("more values than bytes"); // each value one byte at least
            List<Value[]> rows = new ArrayList<>((int) n);
            for (long k = 0; k < n; k++) {
                Value[] row = new Value[nc];
                for (int c = 0; c < nc; c++) {
                    Value v = Value.decode(r);
                    if (!cols.columns.get(c).fits(v)) throw WireException.corrupt("a value its column does not take");
                    row[c] = v;
                }
                rows.add(row);
            }
            return new Msg.Rows(rows);
        }
        case Wire.DONE: {
            String status = textGetString(r, 2, 0, Wire.STATUS_MAX);
            long count = r.u64("a DONE");
            int hr = r.u8("a DONE");
            if (hr > 1) throw WireException.corrupt("a DONE's read point flag");
            Msg.ReadPoint rp = null;
            if (hr == 1) {
                long commit = r.u64("a DONE");
                byte[] hash = r.bytes(32, "a DONE"), digest = r.bytes(32, "a DONE");
                long lake = r.u64("a DONE");
                byte[] man = r.bytes(32, "a DONE"), dbid = r.bytes(16, "a DONE");
                int own = r.u8("a DONE");
                if (own > 1) throw WireException.corrupt("a DONE's own-writes flag");
                rp = new Msg.ReadPoint(commit, hash, digest, lake, man, dbid, own == 1);
            }
            int hw = r.u8("a DONE");
            if (hw > 1) throw WireException.corrupt("a DONE's write flag");
            long wc = 0;
            byte[] wh = null;
            if (hw == 1) {
                wc = r.u64("a DONE");
                wh = r.bytes(32, "a DONE");
                if (wc == 0) throw WireException.corrupt("a DONE's write at commit 0");
            }
            return new Msg.Done(status, count, rp, wc, wh);
        }
        case Wire.ERROR: {
            long code = r.u32("an ERROR"), index = r.u32("an ERROR");
            if (code == 0 || index >= Wire.BATCH_MAX) throw WireException.corrupt("an ERROR's code 0 or its statement's index");
            return new Msg.Error(code, (int) index, textGetString(r, 2, 0, Wire.MESSAGE_MAX));
        }
        case Wire.WARNING: return new Msg.Warning(textGetString(r, 2, 0, Wire.MESSAGE_MAX));
        case Wire.COPY_IN: return new Msg.CopyIn();
        case Wire.COPY_OUT: {
            if (r.left() < 1) throw WireException.corrupt("a COPY piece of no bytes");
            return new Msg.CopyOut(r.bytes(r.left(), "a COPY_OUT"));
        }
        case Wire.READY: {
            int st = r.u8("a READY");
            if (st > Wire.DOOMED) throw WireException.corrupt("a READY's state");
            return new Msg.Ready(st);
        }
        case Wire.PONG: return new Msg.Pong();
        case Wire.SESSIONS_LIST: {
            long n = r.u32("a SESSIONS_LIST");
            if (n > Wire.SESSIONS_MAX || n > r.left() / 23) // an entry: 23 bytes at least
                throw WireException.corrupt("a SESSIONS_LIST of at most 65,536 sessions it holds the bytes of");
            List<Msg.Session> ss = new ArrayList<>((int) n);
            long prev = 0;
            for (long k = 0; k < n; k++) {
                long id = r.u64("a session"), role = r.u32("a session");
                int ep = r.u8("a session"), st = r.u8("a session");
                long age = r.u64("a session");
                String name = textGetString(r, 1, 0, Wire.USER - 1);
                if (Long.compareUnsigned(id, prev) <= 0 || role == 0 || (ep != 1 && ep != 2) || st > Wire.SS_COPY)
                    throw WireException.corrupt("a session's id out of order, or its role, endpoint or state");
                ss.add(new Msg.Session(id, role, ep, st, age, name));
                prev = id;
            }
            return new Msg.SessionsList(ss);
        }
        case Wire.KILL_DONE: {
            int code = r.u8("a KILL_DONE");
            long sid = r.u64("a KILL_DONE");
            if (code > Wire.KILL_NONE || sid == 0) throw WireException.corrupt("a KILL_DONE's code or a session id of 0");
            return new Msg.KillDone(code, sid);
        }
        default: throw WireException.corrupt("a frame of a type the protocol does not define");
        }
    }

    /** a COLUMNS entry (wire.c col_get, col_shape_ok): an ENUM's labels counted only for an ENUM column */
    private static Msg.Column column(Reader r) throws WireException {
        String name = textGetString(r, 1, 1, Wire.COLNAME_MAX);
        int type = r.u8("a column"), prec = r.u16("a column"), scale = r.u16("a column");
        List<String> labels = Collections.emptyList();
        Set<Msg.ByteKey> set = Msg.newSet();
        if (type == Wire.T_ENUM) {
            int n = r.u16("a column");
            if (n > Wire.LABELS_MAX || n > r.left()) throw WireException.corrupt("an ENUM's labels past their bounds or bytes");
            labels = new ArrayList<>(n);
            List<byte[]> raw = new ArrayList<>(n);
            for (int i = 0; i < n; i++) {
                byte[] l = textGet(r, 1, 0, Wire.LABEL_MAX);
                raw.add(l);
                labels.add(Utf8.decode(l, 0, l.length));
            }
            if (!shapeOk(type, prec, scale)) throw WireException.corrupt("a column's type, precision or scale its type does not take");
            for (byte[] l : raw)
                if (!set.add(new Msg.ByteKey(l))) throw WireException.corrupt("an ENUM's labels not distinct");
            labels = Collections.unmodifiableList(labels);
        } else if (!shapeOk(type, prec, scale)) {
            throw WireException.corrupt("a column's type, precision or scale its type does not take");
        }
        return new Msg.Column(name, type, prec, scale, labels, set);
    }

    static boolean shapeOk(int type, int prec, int scale) {
        if (type > Wire.T_LAST) return false;
        switch (type) {
        case Wire.T_DECIMAL: return prec <= 38 && scale <= (prec != 0 ? prec : 38); // precision 0: not known, 38 digits
        case Wire.T_INT64: return (prec == 0 || prec == 16 || prec == 32) && scale == 0;
        case Wire.T_TEXT: return scale == 0; // precision: a VARCHAR's length (0 none)
        default: return prec == 0 && scale == 0;
        }
    }
}
