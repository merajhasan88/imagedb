package imagedb;

import imagedb.wire.TlsTransport;
import imagedb.wire.TlsTrust;
import imagedb.wire.WireConnection;
import java.io.IOException;
import java.nio.file.Path;
import java.util.Arrays;

/**
 * imagedb's Java driver for its own protocol, IMDBWIR1 (docs/n1-design.md §4): connect over the server's Unix-domain
 * socket, or over TCP with TLS 1.3 verified by a CA file or a pin (no unverified mode, no plaintext TCP, no fallback
 * from one to the other), logging in by SCRAM-SHA-256 with the server's signature checked.
 *
 * <pre>
 * try (Connection c = Imagedb.connect(Path.of("/run/imagedb/db.sock"), "admin", password)) {
 *     Result r = c.query("SELECT id, name FROM t WHERE id = $1", 7L);
 *     for (Row row : r) System.out.println(row.getLong(0) + " " + row.getString("name"));
 * }
 * </pre>
 */
public final class Imagedb {
    private Imagedb() {}

    /** connection options: a socket path, or a host and port with a TlsTrust */
    public static final class Options {
        Path socket;
        String host, address;
        int port;
        TlsTrust trust;
        String user;
        char[] password;
        int connectTimeoutMs = 30000, readTimeoutMs = 0;
        TlsTransport.Binding binding = TlsTransport.Binding.AUTO;

        public Options socket(Path p) {
            this.socket = p;
            return this;
        }

        /** TCP: the host the certificate must name (CA mode) and, unless address() says otherwise, the one connected to */
        public Options tcp(String host, int port, TlsTrust trust) {
            this.host = host;
            this.port = port;
            this.trust = trust;
            return this;
        }

        /** connect to this address but verify the certificate against tcp()'s host */
        public Options address(String address) {
            this.address = address;
            return this;
        }

        public Options user(String user) {
            this.user = user;
            return this;
        }

        /** the password's characters (copied: the caller may wipe its own): 1 to 1,024 printable ASCII */
        public Options password(char[] pw) {
            this.password = pw == null ? null : pw.clone();
            return this;
        }

        /** the Options' copy of the password wiped (connect then refuses them) */
        public Options clearPassword() {
            if (password != null) Arrays.fill(password, '\0');
            password = null;
            return this;
        }

        public Options connectTimeoutMs(int ms) {
            this.connectTimeoutMs = ms;
            return this;
        }

        /** each wait for a reply bounded (0: none); past it the connection is unusable */
        public Options readTimeoutMs(int ms) {
            this.readTimeoutMs = ms;
            return this;
        }

        /**
         * the channel binding (§8f): AUTO (the default) takes the TLS exporter when the JDK (25+) or BouncyCastle on the
         * class path computes it, else tls-server-end-point; a refused type is never retried with another
         */
        public Options binding(TlsTransport.Binding b) {
            this.binding = b;
            return this;
        }
    }

    public static Connection connect(Options o) throws ImagedbException {
        if (o.user == null || o.password == null) throw new IllegalArgumentException("a user and a password");
        if ((o.socket == null) == (o.host == null))
            throw new IllegalArgumentException("a socket path or a TCP host, exactly one (no fallback from one to the other)");
        if (o.host != null && o.trust == null) throw new IllegalArgumentException("TLS: a CA file or a pin (no unverified mode)");
        char[] pw = o.password.clone(); // this login's copy, wiped after it (the Options keep theirs: clearPassword)
        try {
            WireConnection w = o.socket != null ? WireConnection.socket(o.socket, o.user, pw, o.connectTimeoutMs)
                                                : WireConnection.tcp(o.address != null ? o.address : o.host, o.port, o.host,
                                                                     o.trust, o.binding, o.user, pw, o.connectTimeoutMs);
            w.setTimeout(o.readTimeoutMs);
            return new Connection(w);
        } catch (IOException x) {
            throw Connection.wrap(x);
        } finally {
            Arrays.fill(pw, '\0');
        }
    }

    /** the server's Unix-domain socket */
    public static Connection connect(Path socket, String user, char[] password) throws ImagedbException {
        return connect(new Options().socket(socket).user(user).password(password));
    }

    /** TCP with TLS 1.3: trust is TlsTrust.caFile(...) or TlsTrust.pin(...) */
    public static Connection connect(String host, int port, TlsTrust trust, String user, char[] password) throws ImagedbException {
        return connect(new Options().tcp(host, port, trust).user(user).password(password));
    }
}
