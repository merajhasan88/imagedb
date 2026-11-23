package imagedb;

import imagedb.wire.Frames;
import imagedb.wire.Msg;
import imagedb.wire.Value;
import imagedb.wire.Wire;
import imagedb.wire.WireConnection;
import imagedb.wire.WireException;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.locks.ReentrantLock;

/**
 * A logged-in session: each call sends one request and reads its replies to its READY (one call at a time: calls from
 * several threads are serialized), except {@link #cancel()}, which any thread may call while a call runs. Each
 * statement commits on its own unless inside BEGIN ... COMMIT; a failed statement is undone alone (statement-level
 * rollback) and {@link #state()} tells whether the transaction goes on, is idle or is doomed (only ROLLBACK). The
 * protocol's level is {@link #wire()}.
 */
public final class Connection implements AutoCloseable {
    /** READY's states */
    public enum TxState { IDLE, IN_TRANSACTION, DOOMED }

    /** KILL's kinds */
    public enum Kill { CANCEL, TERMINATE }

    private final WireConnection w;
    private final ReentrantLock calls = new ReentrantLock();
    private volatile TxState state = TxState.IDLE;

    Connection(WireConnection w) { this.w = w; }

    /** the protocol's level underneath (send* and next): for pipelining; do not mix with calls in flight */
    public WireConnection wire() { return w; }

    /** the login's channel binding: which TLS stack computed which binding ("none" on the socket) */
    public String channelBinding() { return w.bindingName(); }

    /** the session's state at the last READY */
    public TxState state() { return state; }

    public boolean isClosed() { return w.isBroken(); }

    static ImagedbException wrap(IOException x) {
        if (x instanceof WireException) {
            WireException we = (WireException) x;
            return new ImagedbException(we.code(), -1, we.getMessage(), false, we);
        }
        return new ImagedbException(Wire.E_IO, -1, "the connection: " + x.getMessage(), false, x);
    }

    private static ImagedbException serverError(Msg.Error e) {
        return new ImagedbException(e.codeInt(), e.index, e.message, true, null);
    }

    private ImagedbException protocol(String what) {
        WireException x = new WireException(Wire.E_CORRUPT, "a frame refused, the connection closed: " + what);
        try {
            w.close();
        } catch (IOException ignored) {
        }
        return new ImagedbException(x.code(), -1, x.getMessage(), false, x);
    }

    private void lock() {
        calls.lock();
    }

    // ---- the reply loop ----

    /** one statement's answer as it arrives */
    private static final class Pending {
        Msg.Columns cols;
        List<Value[]> rows = new ArrayList<>();
        List<String> warnings = new ArrayList<>();
        ByteArrayOutputStream copy;
    }

    /**
     * replies to READY: a Result per statement (or set); the first ERROR ends the batch (its index the failing one);
     * a COPY_IN this call has no data for is failed at once (COPY_FAIL), COPY_OUT's bytes go to sink (or the result)
     */
    private List<Result> replies(OutputStream sink, InputStream copyIn) throws ImagedbException {
        List<Result> out = new ArrayList<>();
        Pending p = new Pending();
        Msg.Error err = null;
        ImagedbException local = null;
        try {
            for (;;) {
                Msg m = w.next();
                switch (m.type) {
                case Wire.COLUMNS:
                    p.cols = (Msg.Columns) m;
                    p.rows.clear();
                    break;
                case Wire.ROWS:
                    p.rows.addAll(((Msg.Rows) m).rows);
                    break;
                case Wire.WARNING:
                    p.warnings.add(((Msg.Warning) m).message);
                    break;
                case Wire.COPY_OUT: {
                    byte[] d = ((Msg.CopyOut) m).data;
                    if (local != null) break; // the sink failed: the rest dropped (a CANCEL is on its way)
                    if (sink != null) {
                        try {
                            sink.write(d);
                        } catch (IOException x) {
                            local = new ImagedbException(Wire.E_IO, -1, "COPY TO's output stream: " + x.getMessage(), false, x);
                            w.cancel(); // the statement stopped; its ERROR 15 (or its DONE) then READY
                        }
                    } else {
                        if (p.copy == null) p.copy = new ByteArrayOutputStream();
                        p.copy.write(d, 0, d.length);
                    }
                    break;
                }
                case Wire.COPY_IN:
                    if (copyIn == null) {
                        w.sendCopyFail("no data: COPY ... FROM STDIN runs through copyIn()");
                        local = new ImagedbException(Wire.E_STATE, -1, "COPY ... FROM STDIN runs through copyIn()", false, null);
                    } else {
                        upload(copyIn);
                        copyIn = null;
                    }
                    break;
                case Wire.DONE:
                    out.add(new Result(p.cols, p.rows, p.warnings, (Msg.Done) m, p.copy == null ? null : p.copy.toByteArray()));
                    p = new Pending();
                    break;
                case Wire.ERROR:
                    err = (Msg.Error) m; // the rows before it are not the statement's answer
                    p = new Pending();
                    break;
                case Wire.READY: {
                    int s = ((Msg.Ready) m).state;
                    state = s == Wire.IDLE ? TxState.IDLE : s == Wire.IN_TXN ? TxState.IN_TRANSACTION : TxState.DOOMED;
                    if (err != null && local == null) throw new BatchException(err.codeInt(), err.index, err.message, out);
                    if (local != null) throw local;
                    return out;
                }
                default: throw protocol("a " + m + " no request of this connection asked for");
                }
            }
        } catch (IOException x) {
            throw wrap(x);
        }
    }

    /** COPY ... FROM STDIN's data after its COPY_IN, then COPY_DONE; a failing input stream: COPY_FAIL (§4) */
    private void upload(InputStream in) throws IOException {
        byte[] buf = new byte[Wire.COPY_PIECE];
        for (;;) {
            int n;
            try {
                n = in.readNBytes(buf, 0, buf.length);
            } catch (IOException x) {
                w.sendCopyFail("the client's input failed: " + x.getMessage());
                return;
            }
            if (n > 0) w.sendCopyData(buf, 0, n);
            if (n < buf.length) break;
        }
        w.sendCopyDone();
    }

    private Result one(List<Result> rs) throws ImagedbException {
        if (rs.size() != 1) throw protocol(rs.size() + " answers to one statement");
        return rs.get(0);
    }

    // ---- requests ----

    /** one statement with its parameters ($1, $2, ...: Java values, see Params) */
    public Result query(String sql, Object... params) throws ImagedbException {
        return one(batch(Collections.singletonList(Statement.of(sql, params))));
    }

    /**
     * a batch in one QUERY (1 to 4,096 statements): run in order, the first ERROR ending it (a BatchException with
     * the results before it). A batch is not a transaction: each statement commits on its own unless in BEGIN ... COMMIT.
     */
    public List<Result> batch(List<Statement> stmts) throws ImagedbException {
        List<Frames.Stmt> fs = new ArrayList<>(stmts.size());
        try {
            for (Statement s : stmts) fs.add(new Frames.Stmt(s.sql, Params.list(s.params.toArray())));
        } catch (WireException x) {
            throw wrap(x);
        }
        lock();
        try {
            w.sendQuery(fs);
            return replies(null, null);
        } catch (IOException x) {
            throw wrap(x);
        } finally {
            calls.unlock();
        }
    }

    /** a PREPARE: its parameters typed at each EXECUTE, as the engine's PREPARE */
    public Prepared prepare(String name, String sql) throws ImagedbException {
        lock();
        try {
            w.sendPrepare(name, sql);
            replies(null, null);
            return new Prepared(this, name);
        } catch (IOException x) {
            throw wrap(x);
        } finally {
            calls.unlock();
        }
    }

    List<Result> execute(String name, List<Object[]> sets) throws ImagedbException {
        List<List<Value>> vs = new ArrayList<>(sets.size());
        for (Object[] s : sets) vs.add(Params.list(s));
        lock();
        try {
            w.sendExecute(name, vs);
            return replies(null, null);
        } catch (IOException x) {
            throw wrap(x);
        } finally {
            calls.unlock();
        }
    }

    void deallocate(String name) throws ImagedbException {
        lock();
        try {
            w.sendDeallocate(name);
            replies(null, null);
        } catch (IOException x) {
            throw wrap(x);
        } finally {
            calls.unlock();
        }
    }

    /**
     * COPY ... FROM STDIN with data: the statement, its COPY_IN, the data in frames of at most 1 MiB, COPY_DONE (or
     * COPY_FAIL when the stream fails), then its DONE or ERROR. A COPY the server refuses before its data (no such
     * table, a privilege) is answered without COPY_IN: nothing is sent then.
     */
    public Result copyIn(String sql, InputStream data) throws ImagedbException {
        if (data == null) throw new IllegalArgumentException("COPY's data");
        lock();
        try {
            w.sendQuery(Collections.singletonList(new Frames.Stmt(sql, null)));
            return one(replies(null, data));
        } catch (IOException x) {
            throw wrap(x);
        } finally {
            calls.unlock();
        }
    }

    public Result copyIn(String sql, byte[] data) throws ImagedbException { return copyIn(sql, new ByteArrayInputStream(data)); }

    /** COPY ... TO STDOUT: its bytes written to out as COPY_OUT frames arrive, then its DONE */
    public Result copyOut(String sql, OutputStream out) throws ImagedbException {
        if (out == null) throw new IllegalArgumentException("COPY's output");
        lock();
        try {
            w.sendQuery(Collections.singletonList(new Frames.Stmt(sql, null)));
            return one(replies(out, null));
        } catch (IOException x) {
            throw wrap(x);
        } finally {
            calls.unlock();
        }
    }

    /** PING: PONG */
    public void ping() throws ImagedbException {
        lock();
        try {
            w.sendPing();
            Msg m = w.next();
            if (m instanceof Msg.Error) throw serverError((Msg.Error) m); // a KILL's or a bound's, sent before its close
            if (!(m instanceof Msg.Pong)) throw protocol("a " + m + " where a PONG was due");
        } catch (IOException x) {
            throw wrap(x);
        } finally {
            calls.unlock();
        }
    }

    /** SESSIONS: a superuser's every session, a role's its own role's; ids strictly increasing */
    public List<Msg.Session> sessions() throws ImagedbException {
        lock();
        try {
            w.sendSessions();
            Msg m = w.next();
            if (m instanceof Msg.Error) throw serverError((Msg.Error) m);
            if (!(m instanceof Msg.SessionsList)) throw protocol("a " + m + " where a SESSIONS_LIST was due");
            return ((Msg.SessionsList) m).sessions;
        } catch (IOException x) {
            throw wrap(x);
        } finally {
            calls.unlock();
        }
    }

    /** KILL of a session by its id: true when done, false for no such session (to a role: another role's too) */
    public boolean kill(long session, Kill kind) throws ImagedbException {
        lock();
        try {
            w.sendKill(kind == Kill.CANCEL ? Wire.KILL_CANCEL : Wire.KILL_TERMINATE, session);
            Msg m = w.next();
            if (m instanceof Msg.Error) throw serverError((Msg.Error) m);
            if (!(m instanceof Msg.KillDone)) throw protocol("a " + m + " where a KILL_DONE was due");
            Msg.KillDone k = (Msg.KillDone) m;
            if (k.session != session) throw protocol("a KILL_DONE for another session");
            return k.code == Wire.KILLED;
        } catch (IOException x) {
            throw wrap(x);
        } finally {
            calls.unlock();
        }
    }

    /**
     * the statement this session runs now, cancelled (any thread; it ends in ERROR 15). A CANCEL reaches only a
     * statement running when it arrives: one sent while the request waits for its turn does nothing, so a caller that
     * must stop a statement may call this again until the call returns.
     */
    public void cancel() { w.cancel(); }

    /** TERMINATE, then the connection closed (an open transaction rolled back by the server) */
    @Override
    public void close() {
        if (w.isBroken()) return;
        try {
            if (calls.tryLock()) {
                try {
                    w.sendTerminate();
                } finally {
                    calls.unlock();
                }
            }
        } catch (IOException ignored) {
        } finally {
            try {
                w.close();
            } catch (IOException ignored) {
            }
        }
    }
}
