package imagedb.wire;

import java.io.Closeable;
import java.io.IOException;
import java.net.SocketTimeoutException;
import java.nio.file.Path;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.locks.ReentrantLock;

/**
 * IMDBWIR1 at the protocol's level: a logged-in connection, its client frames sent whole (send*) and the server's read
 * one at a time (next), requests pipelining as §4 allows. Every frame the server sends is decoded strictly: one the
 * decoder refuses ends the connection with an error naming it.
 *
 * <p>CANCEL travels in band (§4): cancel(), from any thread, writes it directly (Java's TLS and socket streams take one
 * reader and one writer at once) between whole frames; one asked while a frame is being sent goes out right after that
 * frame, before the next (a COPY's data); one asked while no request of this client is outstanding (each READY ends one)
 * is dropped, never left to cancel the next request (the C client's rules, client.c put_msg and recv_all).
 *
 * <p>A send that finds the connection closed reads what the server sent before its close: when the last frame before
 * the end is an ERROR, that ERROR is the reason reported (its code and its words), else the I/O error (§4's
 * closed_reason; the C client's bounds: 64 frames, 1 s a read). A read that meets the close after an ERROR reports it
 * alike.
 */
public final class WireConnection implements Closeable {
    private final Transport t;
    private final ReentrantLock wlock = new ReentrantLock(), rlock = new ReentrantLock();
    private final AtomicBoolean cancelAsked = new AtomicBoolean();
    private final AtomicInteger outstanding = new AtomicInteger();
    private Msg.Columns cols;
    private volatile WireException broken;
    private volatile int timeoutMs;
    private Msg.Error lastError; // the last frame read, when it was an ERROR

    private static final byte[] CANCEL = Frames.empty(Wire.CANCEL);

    WireConnection(Transport t) { this.t = t; }

    /** login over a transport already connected (nonce null: random); the transport closed on any failure */
    public static WireConnection login(Transport t, String user, char[] pw, byte[] nonce, int timeoutMs) throws IOException {
        boolean ok = false;
        try {
            Login.authenticate(t, user, pw, nonce, timeoutMs);
            ok = true;
            return new WireConnection(t);
        } finally {
            if (!ok) t.close();
        }
    }

    /** the server's Unix-domain socket */
    public static WireConnection socket(Path path, String user, char[] pw, int timeoutMs) throws IOException {
        PreAuth.userBytes(user); // refused before any byte leaves
        PreAuth.checkPassword(pw);
        return login(UnixTransport.connect(path), user, pw, null, timeoutMs);
    }

    /** TCP with TLS 1.3 (TlsTransport): address to connect to, verifyName the certificate must name in CA mode */
    public static WireConnection tcp(String address, int port, String verifyName, TlsTrust trust, TlsTransport.Binding binding,
                                     String user, char[] pw, int timeoutMs) throws IOException {
        PreAuth.userBytes(user);
        PreAuth.checkPassword(pw);
        return login(TlsTransport.connect(address, port, verifyName, trust, binding, timeoutMs), user, pw, null, timeoutMs);
    }

    public Transport transport() { return t; }

    public String bindingName() { return t.bindingName(); }

    /** a bound on each wait for a reply's bytes (0: none); past it next() fails and the connection is unusable */
    public void setTimeout(int ms) { this.timeoutMs = ms; }

    /** requests sent whose READY has not been read */
    public int outstanding() { return outstanding.get(); }

    /** the last COLUMNS (the one a ROWS is read against), or null */
    public Msg.Columns columns() { return cols; }

    public boolean isBroken() { return broken != null; }

    /** why the connection is unusable, or null */
    public WireException brokenReason() { return broken; }

    private void usable() throws WireException {
        WireException b = broken;
        if (b != null) throw new WireException(b.code(), b.getMessage(), b);
    }

    private WireException breakWith(WireException why) {
        if (broken == null) broken = why;
        try {
            t.close();
        } catch (IOException ignored) {
        }
        return why;
    }

    // ---- sending ----

    private void send(byte[] frame, boolean request) throws IOException {
        usable();
        wlock.lock();
        try {
            if (request && outstanding.get() == 0) cancelAsked.set(false); // asked while nothing ran: for nothing
            else if (outstanding.get() > 0 && cancelAsked.getAndSet(false)) t.write(CANCEL, 0, CANCEL.length);
            t.write(frame, 0, frame.length);
            if (request) outstanding.incrementAndGet(); // in the same critical section: a cancel then sees it
        } catch (IOException x) {
            WireException why = x instanceof WireException ? (WireException) x : closedReason(x);
            throw breakWith(why);
        } finally {
            wlock.unlock();
        }
        flushCancel();
    }

    /** a cancel asked while the lock was held, sent now */
    private void flushCancel() {
        while (cancelAsked.get() && wlock.tryLock()) {
            try {
                if (cancelAsked.getAndSet(false) && outstanding.get() > 0 && broken == null) t.write(CANCEL, 0, CANCEL.length);
            } catch (IOException ignored) {
                // the reader meets the close and reports it
            } finally {
                wlock.unlock();
            }
        }
    }

    /**
     * the statement this connection's server session runs now, cancelled (any thread). A CANCEL reaches only a
     * statement running when it arrives (§4): one sent while the request still waits for its turn does nothing.
     */
    public void cancel() {
        cancelAsked.set(true);
        flushCancel();
    }

    /**
     * a send found the connection closed: what the server sent before its close; its last frame, when an ERROR, is the
     * reason (client.c closed_reason). Read only when no other thread is reading.
     */
    private WireException closedReason(IOException x) {
        WireException plain = new WireException(Wire.E_IO, "the connection: " + (x.getMessage() != null ? x.getMessage() : x.toString()), x);
        try {
            if (!rlock.tryLock(1, TimeUnit.SECONDS)) return plain;
        } catch (InterruptedException ie) {
            Thread.currentThread().interrupt();
            return plain;
        }
        try {
            Msg.Error why = null;
            boolean ended = false;
            for (int k = 0; k < 64 && !ended; k++) {
                Msg m;
                try {
                    m = readFrame(1000);
                } catch (IOException e) {
                    ended = true;
                    break;
                }
                why = m instanceof Msg.Error ? (Msg.Error) m : null; // an ERROR before another frame answered that frame's request
            }
            if (!ended || why == null) return plain;
            return new WireException(why.codeInt(), "the server closed the connection: " + why.message, x);
        } finally {
            rlock.unlock();
        }
    }

    public void sendQuery(List<Frames.Stmt> stmts) throws IOException { send(Frames.query(stmts), true); }

    public void sendPrepare(String name, String sql) throws IOException { send(Frames.prepare(name, sql), true); }

    public void sendExecute(String name, List<List<Value>> sets) throws IOException { send(Frames.execute(name, sets), true); }

    public void sendDeallocate(String name) throws IOException { send(Frames.deallocate(name), true); }

    /** COPY ... FROM STDIN's data after its COPY_IN, cut into frames of at most 1 MiB */
    public void sendCopyData(byte[] p, int off, int len) throws IOException {
        while (len > 0) {
            int k = Math.min(len, Wire.COPY_PIECE);
            send(Frames.copyData(p, off, k), false);
            off += k;
            len -= k;
        }
    }

    public void sendCopyDone() throws IOException { send(Frames.empty(Wire.COPY_DONE), false); }

    public void sendCopyFail(String reason) throws IOException { send(Frames.copyFail(reason), false); }

    public void sendPing() throws IOException { send(Frames.empty(Wire.PING), false); }

    public void sendSessions() throws IOException { send(Frames.empty(Wire.SESSIONS), false); }

    public void sendKill(int kind, long session) throws IOException { send(Frames.kill(kind, session), false); }

    /** TERMINATE: the server ends the session (an open transaction rolled back) once the requests before it ran */
    public void sendTerminate() throws IOException { send(Frames.empty(Wire.TERMINATE), false); }

    /** bytes as they are (tests: crafted frames) */
    void sendRaw(byte[] b) throws IOException { send(b, false); }

    // ---- reading ----

    private void readFully(byte[] b, int timeout) throws IOException {
        int got = 0;
        while (got < b.length) {
            int k = t.read(b, got, b.length - got, timeout);
            if (k < 0) throw new WireException(Wire.E_IO, "the connection: closed by the server");
            got += k;
        }
    }

    private Msg readFrame(int timeout) throws IOException {
        byte[] head = new byte[Wire.HEAD];
        readFully(head, timeout);
        int[] h = Frames.head(head); // the length checked before anything is allocated
        byte[] body = new byte[h[0] - 1];
        readFully(body, timeout);
        Msg m = Frames.decode(h[1], body, cols);
        if (m instanceof Msg.Columns) cols = (Msg.Columns) m;
        if (m instanceof Msg.Ready) outstanding.updateAndGet(n -> n > 0 ? n - 1 : 0);
        lastError = m instanceof Msg.Error ? (Msg.Error) m : null;
        return m;
    }

    /** the next server frame, decoded (a ROWS against the last COLUMNS) */
    public Msg next() throws IOException {
        usable();
        rlock.lock();
        try {
            return readFrame(timeoutMs);
        } catch (SocketTimeoutException x) {
            throw breakWith(new WireException(Wire.E_IO, x.getMessage() + " (the connection is unusable: a frame may be part read)", x));
        } catch (WireException x) {
            if (x.code() == Wire.E_IO) {
                Msg.Error e = lastError; // the server's close after an ERROR: that ERROR is why
                throw breakWith(e != null ? new WireException(e.codeInt(), "the server closed the connection: " + e.message, x) : x);
            }
            throw breakWith(new WireException(x.code(), "a frame refused, the connection closed: " + x.getMessage(), x));
        } catch (IOException x) {
            Msg.Error e = lastError;
            throw breakWith(e != null ? new WireException(e.codeInt(), "the server closed the connection: " + e.message, x)
                                      : new WireException(Wire.E_IO, "the connection: " + x.getMessage(), x));
        } finally {
            rlock.unlock();
        }
    }

    @Override
    public void close() throws IOException {
        if (broken == null) broken = new WireException(Wire.E_STATE, "the connection is closed");
        t.close();
    }
}
