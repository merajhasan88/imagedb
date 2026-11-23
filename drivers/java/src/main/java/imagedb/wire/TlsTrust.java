package imagedb.wire;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;

/**
 * How a TCP connection verifies the server, exactly one of two ways (§4, the C client's imdbc_tls): a CA file (the chain
 * to that CA, and the host checked against the certificate's subjectAltName), or a pin (the server key's SPKI SHA-256,
 * as `imagedb-server cert` prints it; it survives `cert --renew`, which keeps the key). There is no constructor and no
 * third way: an unverified connection cannot be asked for.
 */
public final class TlsTrust {
    private final X509Certificate ca; // or null
    private final byte[] pin;         // or null

    private TlsTrust(X509Certificate ca, byte[] pin) {
        this.ca = ca;
        this.pin = pin;
    }

    /** the CA in a PEM (or DER) file, as `imagedb-server cert` writes SDIR/tls/ca.crt */
    public static TlsTrust caFile(Path file) throws IOException {
        if (file == null) throw new IllegalArgumentException("TLS: a CA file");
        try (InputStream in = Files.newInputStream(file)) {
            X509Certificate c = (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(in);
            return new TlsTrust(c, null);
        } catch (CertificateException x) {
            throw new WireException(Wire.E_INVALID, "TLS: " + file + " is not a certificate: " + x.getMessage(), x);
        }
    }

    /** the CA certificate itself */
    public static TlsTrust ca(X509Certificate c) {
        if (c == null) throw new IllegalArgumentException("TLS: a CA certificate");
        return new TlsTrust(c, null);
    }

    /** a pin: the server key's SPKI SHA-256, 32 bytes */
    public static TlsTrust pin(byte[] sha256) {
        if (sha256 == null || sha256.length != 32) throw new IllegalArgumentException("TLS: a pin is 32 bytes (the key's SPKI SHA-256)");
        return new TlsTrust(null, sha256.clone());
    }

    /** a pin as 64 hex digits, as `imagedb-server cert` prints it */
    public static TlsTrust pin(String hex) {
        if (hex == null || hex.length() != 64) throw new IllegalArgumentException("TLS: a pin is 64 hex digits");
        byte[] b = new byte[32];
        for (int i = 0; i < 32; i++) {
            int hi = Character.digit(hex.charAt(2 * i), 16), lo = Character.digit(hex.charAt(2 * i + 1), 16);
            if (hi < 0 || lo < 0) throw new IllegalArgumentException("TLS: a pin is 64 hex digits");
            b[i] = (byte) (hi << 4 | lo);
        }
        return new TlsTrust(null, b);
    }

    boolean pinned() { return pin != null; }

    X509Certificate caCert() { return ca; }

    byte[] pinBytes() { return pin.clone(); }

    @Override
    public String toString() { return pin != null ? "pin " + Der.hex(pin) : "CA " + ca.getSubjectX500Principal(); }

    @Override
    public boolean equals(Object o) {
        return o instanceof TlsTrust && Arrays.equals(pin, ((TlsTrust) o).pin) && java.util.Objects.equals(ca, ((TlsTrust) o).ca);
    }

    @Override
    public int hashCode() { return Arrays.hashCode(pin); }
}
