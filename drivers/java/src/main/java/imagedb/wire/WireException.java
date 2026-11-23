package imagedb.wire;

/**
 * A failure at the protocol's level: bytes a decoder refuses (CORRUPT), a bound passed (LIMIT), a later protocol
 * (UNSUPPORTED), a refused login (AUTH), the connection's I/O (IO), or a value an encoder refuses (INVALID). The code
 * is the engine's (IMDB_ERR_* magnitudes, §4's ERROR codes), so a server's ERROR and a local refusal read alike.
 */
public class WireException extends java.io.IOException {
    private static final long serialVersionUID = 1L;
    private final int code;

    public WireException(int code, String message) {
        super(message);
        this.code = code;
    }

    public WireException(int code, String message, Throwable cause) {
        super(message, cause);
        this.code = code;
    }

    /** the engine's code (1 to 16 in this imagedb; a later one possible) */
    public int code() { return code; }

    static WireException corrupt(String what) { return new WireException(Wire.E_CORRUPT, "wire: " + what); }

    static WireException limit(String what) { return new WireException(Wire.E_LIMIT, "wire: " + what); }

    static WireException invalid(String what) { return new WireException(Wire.E_INVALID, what); }
}
