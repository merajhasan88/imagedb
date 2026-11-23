package imagedb.wire;

import java.io.IOException;
import java.net.SocketTimeoutException;
import java.net.StandardProtocolFamily;
import java.net.UnixDomainSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.ClosedSelectorException;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.nio.channels.SocketChannel;
import java.nio.file.Path;

/**
 * The server's Unix-domain socket (JDK 16+'s SocketChannel of StandardProtocolFamily.UNIX): no TLS, the binding's type
 * none and its bytes zeros (§4). Non-blocking under two selectors, one for the reader and one for the writer, so a
 * read can wait with a bound (a blocking SocketChannel has none) while another thread writes.
 */
public final class UnixTransport implements Transport {
    private final SocketChannel ch;
    private final Selector rsel, wsel;

    private UnixTransport(SocketChannel ch, Selector rsel, Selector wsel) {
        this.ch = ch;
        this.rsel = rsel;
        this.wsel = wsel;
    }

    public static UnixTransport connect(Path path) throws IOException {
        SocketChannel ch = SocketChannel.open(StandardProtocolFamily.UNIX);
        Selector r = null, w = null;
        try {
            ch.connect(UnixDomainSocketAddress.of(path));
            ch.configureBlocking(false);
            r = Selector.open();
            w = Selector.open();
            ch.register(r, SelectionKey.OP_READ);
            ch.register(w, SelectionKey.OP_WRITE);
            return new UnixTransport(ch, r, w);
        } catch (IOException | RuntimeException x) {
            if (r != null) r.close();
            if (w != null) w.close();
            ch.close();
            throw x;
        }
    }

    @Override
    public void write(byte[] b, int off, int len) throws IOException {
        ByteBuffer bb = ByteBuffer.wrap(b, off, len);
        while (bb.hasRemaining()) {
            if (ch.write(bb) > 0) continue;
            try {
                synchronized (wsel) {
                    wsel.selectedKeys().clear();
                    wsel.select(1000); // a full socket: wait for room (bounded per turn so a close is seen)
                }
            } catch (ClosedSelectorException x) {
                throw new IOException("the connection is closed");
            }
            if (!ch.isOpen()) throw new IOException("the connection is closed");
        }
    }

    @Override
    public int read(byte[] b, int off, int len, int timeoutMs) throws IOException {
        ByteBuffer bb = ByteBuffer.wrap(b, off, len);
        long deadline = timeoutMs > 0 ? System.nanoTime() + timeoutMs * 1_000_000L : 0;
        for (;;) {
            int k = ch.read(bb);
            if (k != 0) return k; // bytes, or -1 at the peer's close
            long wait = 1000; // each turn bounded, so a close by another thread is seen
            if (timeoutMs > 0) {
                long left = (deadline - System.nanoTime()) / 1_000_000L;
                if (left <= 0) throw new SocketTimeoutException("no reply within " + timeoutMs + " ms");
                wait = Math.min(wait, left);
            }
            try {
                synchronized (rsel) {
                    rsel.selectedKeys().clear();
                    rsel.select(wait);
                }
            } catch (ClosedSelectorException x) {
                throw new IOException("the connection is closed");
            }
            if (!ch.isOpen()) throw new IOException("the connection is closed");
        }
    }

    @Override
    public int endpoint() { return Wire.EP_UNIX; }

    @Override
    public int bindingType() { return Wire.CB_NONE; }

    @Override
    public byte[] binding() { return new byte[Wire.KEY]; }

    @Override
    public String bindingName() { return "none (the Unix socket)"; }

    @Override
    public void close() throws IOException {
        try {
            rsel.wakeup();
            wsel.wakeup();
            ch.close();
        } finally {
            rsel.close();
            wsel.close();
        }
    }
}
