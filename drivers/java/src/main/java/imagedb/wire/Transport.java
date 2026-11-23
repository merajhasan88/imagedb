package imagedb.wire;

import java.io.Closeable;
import java.io.IOException;

/**
 * A connection's bytes: the Unix-domain socket (no TLS) or TCP with TLS 1.3. One reader and one writer may use it at
 * once (the reader waiting for replies, another thread writing a CANCEL: §4 lets a stream that takes concurrent reading
 * and writing write it directly); writes are serialized by the caller.
 */
public interface Transport extends Closeable {
    /** every byte written, or an IOException (the connection closed or failed) */
    void write(byte[] b, int off, int len) throws IOException;

    /** at least one byte read, -1 at the peer's close; timeoutMs 0 waits without bound, else SocketTimeoutException */
    int read(byte[] b, int off, int len, int timeoutMs) throws IOException;

    /** Wire.EP_TCP or Wire.EP_UNIX: the AuthMessage's endpoint */
    int endpoint();

    /** the channel binding's type (Wire.CB_*) and its 32 bytes: zeros on the socket */
    int bindingType();

    byte[] binding() throws IOException;

    /** a description of the binding (which TLS stack computed it), for the caller's record */
    String bindingName();
}
