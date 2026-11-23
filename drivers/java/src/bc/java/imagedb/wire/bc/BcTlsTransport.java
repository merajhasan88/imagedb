package imagedb.wire.bc;

import imagedb.wire.Der;
import imagedb.wire.HostCheck;
import imagedb.wire.Transport;
import imagedb.wire.Wire;
import imagedb.wire.WireException;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.cert.CertPathValidator;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Vector;
import org.bouncycastle.tls.AlertDescription;
import org.bouncycastle.tls.CertificateRequest;
import org.bouncycastle.tls.ChannelBinding;
import org.bouncycastle.tls.DefaultTlsClient;
import org.bouncycastle.tls.ProtocolName;
import org.bouncycastle.tls.ProtocolVersion;
import org.bouncycastle.tls.SecurityParameters;
import org.bouncycastle.tls.TlsAuthentication;
import org.bouncycastle.tls.TlsClientProtocol;
import org.bouncycastle.tls.TlsCredentials;
import org.bouncycastle.tls.TlsFatalAlert;
import org.bouncycastle.tls.TlsServerCertificate;
import org.bouncycastle.tls.crypto.impl.bc.BcTlsCrypto;

/**
 * TLS 1.3 by BouncyCastle's own TLS API (bctls), for a JDK before 25, so the login binds by the TLS exporter (RFC 9266),
 * which a default server takes. Not through BouncyCastle's JSSE provider: its 1.87 clears the exporter's secret when
 * the handshake ends (TlsProtocol.cleanupHandshake: SecurityParameters.clear), so BCSSLConnection.getChannelBinding
 * ("tls-exporter") throws "Export of key material only available from notifyHandshakeComplete()" (found by the probe).
 * Here the exporter is taken inside notifyHandshakeComplete, where BouncyCastle allows it. The same rules as the JDK's
 * path: TLS 1.3 alone, ALPN imdbwir1, a CA file (PKIX to that CA, then the name against subjectAltName) or a pin (the
 * leaf's SPKI SHA-256, the chain not asked for). Compiled only when BouncyCastle's jars are on the class path; the core
 * reaches it by reflection (TlsTransport).
 */
public final class BcTlsTransport implements Transport {
    private static final String ALPN = "imdbwir1";

    private final Socket sock;
    private final TlsClientProtocol proto;
    private final InputStream in;
    private final OutputStream out;
    private final byte[] binding;
    private final X509Certificate peer;
    private int soTimeout = -1;

    private BcTlsTransport(Socket sock, TlsClientProtocol proto, byte[] binding, X509Certificate peer) {
        this.sock = sock;
        this.proto = proto;
        this.in = proto.getInputStream();
        this.out = proto.getOutputStream();
        this.binding = binding;
        this.peer = peer;
    }

    /** the client: its versions, ALPN, the server's certificate checked, the exporter taken at the handshake's end */
    static final class Client extends DefaultTlsClient {
        final String verifyName;
        final X509Certificate ca;
        final byte[] pin;
        byte[] exporter;
        String alpn;
        boolean v13;
        X509Certificate leaf;
        String refused;

        Client(String verifyName, X509Certificate ca, byte[] pin) {
            super(new BcTlsCrypto(new java.security.SecureRandom()));
            this.verifyName = verifyName;
            this.ca = ca;
            this.pin = pin;
        }

        @Override
        protected ProtocolVersion[] getSupportedVersions() { return ProtocolVersion.TLSv13.only(); }

        @Override
        @SuppressWarnings({"rawtypes", "unchecked"})
        protected Vector getProtocolNames() {
            Vector v = new Vector();
            v.add(ProtocolName.asUtf8Encoding(ALPN));
            return v;
        }

        @Override
        public TlsAuthentication getAuthentication() {
            return new TlsAuthentication() {
                @Override
                public void notifyServerCertificate(TlsServerCertificate sc) throws IOException {
                    check(sc);
                }

                @Override
                public TlsCredentials getClientCredentials(CertificateRequest r) { return null; } // SCRAM authenticates the client
            };
        }

        private void refuse(String why) throws IOException {
            refused = "TLS: " + why;
            throw new TlsFatalAlert(AlertDescription.bad_certificate, refused);
        }

        void check(TlsServerCertificate sc) throws IOException {
            org.bouncycastle.tls.Certificate chain = sc.getCertificate();
            if (chain == null || chain.isEmpty()) refuse("no server certificate");
            List<X509Certificate> xs = new ArrayList<>();
            try {
                CertificateFactory cf = CertificateFactory.getInstance("X.509");
                for (int i = 0; i < chain.getLength(); i++)
                    xs.add((X509Certificate) cf.generateCertificate(new ByteArrayInputStream(chain.getCertificateAt(i).getEncoded())));
            } catch (GeneralSecurityException x) {
                refuse("the server's certificate: " + x.getMessage());
            }
            leaf = xs.get(0);
            if (pin != null) {
                byte[] got;
                try {
                    got = Der.sha256(Der.spki(leaf.getEncoded()));
                } catch (GeneralSecurityException x) {
                    refuse("the server's certificate: " + x.getMessage());
                    return;
                }
                if (!MessageDigest.isEqual(got, pin)) refuse("the server's key is not the pinned one");
                return;
            }
            try { // PKIX to the one CA, then the name: what OpenSSL's verify and set1_host do for the C client
                PKIXParameters pp = new PKIXParameters(Collections.singleton(new TrustAnchor(ca, null)));
                pp.setRevocationEnabled(false);
                CertPathValidator.getInstance("PKIX").validate(CertificateFactory.getInstance("X.509").generateCertPath(xs), pp);
                List<String> eku = leaf.getExtendedKeyUsage();
                if (eku != null && !eku.contains("1.3.6.1.5.5.7.3.1") && !eku.contains("2.5.29.37.0"))
                    refuse("the server's certificate is not for a server (extended key usage)");
            } catch (GeneralSecurityException x) {
                refuse("the server's certificate: " + x.getMessage());
            }
            if (!HostCheck.matches(leaf, verifyName)) refuse("the server's certificate does not name " + verifyName);
        }

        @Override
        public void notifyHandshakeComplete() throws IOException {
            super.notifyHandshakeComplete();
            SecurityParameters sp = context.getSecurityParametersConnection();
            v13 = ProtocolVersion.TLSv13.equals(sp.getNegotiatedVersion());
            ProtocolName pn = sp.getApplicationProtocol();
            alpn = pn == null ? null : pn.getUtf8Decoding();
            exporter = context.exportChannelBinding(ChannelBinding.tls_exporter); // RFC 9266: here, before it is cleared
        }
    }

    public static BcTlsTransport connect(String address, int port, String verifyName, X509Certificate ca, byte[] pin, int timeoutMs)
            throws IOException {
        if ((ca == null) == (pin == null)) throw new IllegalArgumentException("TLS: a CA file or a pin, exactly one");
        Socket s = new Socket();
        boolean ok = false;
        try {
            s.setTcpNoDelay(true);
            s.setKeepAlive(true);
            s.connect(new InetSocketAddress(address, port), timeoutMs);
            s.setSoTimeout(timeoutMs);
            TlsClientProtocol p = new TlsClientProtocol(s.getInputStream(), s.getOutputStream());
            Client c = new Client(verifyName, ca, pin);
            try {
                p.connect(c);
            } catch (IOException x) {
                throw new WireException(Wire.E_AUTH, "TLS handshake: " + (c.refused != null ? c.refused : x.toString()), x);
            }
            if (!c.v13) throw new WireException(Wire.E_AUTH, "TLS: not 1.3");
            if (!ALPN.equals(c.alpn)) throw new WireException(Wire.E_AUTH, "TLS: the peer does not speak " + ALPN + " (ALPN)");
            if (c.exporter == null || c.exporter.length != Wire.KEY)
                throw new WireException(Wire.E_STATE, "TLS: BouncyCastle's exporter gave no 32 bytes");
            s.setSoTimeout(0);
            BcTlsTransport t = new BcTlsTransport(s, p, c.exporter, c.leaf);
            ok = true;
            return t;
        } finally {
            if (!ok) {
                try {
                    s.close();
                } catch (IOException ignored) {
                }
            }
        }
    }

    @Override
    public void write(byte[] b, int off, int len) throws IOException {
        out.write(b, off, len);
        out.flush();
    }

    @Override
    public int read(byte[] b, int off, int len, int timeoutMs) throws IOException {
        if (timeoutMs != soTimeout) {
            sock.setSoTimeout(timeoutMs);
            soTimeout = timeoutMs;
        }
        try {
            return in.read(b, off, len);
        } catch (SocketTimeoutException x) {
            throw new SocketTimeoutException("no reply within " + timeoutMs + " ms");
        }
    }

    @Override
    public int endpoint() { return Wire.EP_TCP; }

    @Override
    public int bindingType() { return Wire.CB_EXPORTER; }

    @Override
    public byte[] binding() { return binding.clone(); }

    @Override
    public String bindingName() { return "tls-exporter (BouncyCastle's TLS API, bctls)"; }

    public X509Certificate peerCertificate() { return peer; }

    @Override
    public void close() throws IOException {
        try {
            proto.close();
        } catch (IOException ignored) {
        } finally {
            sock.close();
        }
    }
}
