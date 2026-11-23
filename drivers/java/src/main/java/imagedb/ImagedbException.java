package imagedb;

/**
 * A failure: the server's ERROR (its code, the failing statement's index in its batch, its words), or the driver's own
 * (a value it cannot send, the connection's I/O, a frame it refused). The code is the engine's (§4's ERROR codes), so
 * both read alike: {@link #kind()} names it; a code a later imagedb adds reads as {@link Kind#OTHER}.
 */
public class ImagedbException extends Exception {
    private static final long serialVersionUID = 1L;

    /** the engine's error classes (IMDB_ERR_* magnitudes) */
    public enum Kind {
        OTHER(0), IO(1), CORRUPT(2), LIMIT(3), INVALID(4), NOMEM(5), CONSTRAINT(6), VERIFY(7), AUTH(8), STATE(9), SYNTAX(10),
        NOT_FOUND(11), UNSUPPORTED(12), HISTORY(13), CONFLICT(14), CANCELLED(15), PRIVILEGE(16);

        public final int code;

        Kind(int code) { this.code = code; }

        public static Kind of(int code) {
            for (Kind k : values())
                if (k.code == code && k != OTHER) return k;
            return OTHER;
        }
    }

    private final int code;
    private final int index;
    private final boolean fromServer;

    public ImagedbException(int code, int index, String message, boolean fromServer, Throwable cause) {
        super(message, cause);
        this.code = code;
        this.index = index;
        this.fromServer = fromServer;
    }

    /** the engine's code (1 or more), 0 when none applies */
    public int code() { return code; }

    public Kind kind() { return Kind.of(code); }

    /** the failing statement's (or parameter set's) index in its batch, -1 when not a statement's */
    public int index() { return index; }

    /** true for the server's ERROR, false for the driver's own refusal or the connection's failure */
    public boolean fromServer() { return fromServer; }

    /** a conflict: retry the transaction */
    public boolean isRetryable() { return code == Kind.CONFLICT.code; }
}
