package imagedb.wire;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import javax.net.ssl.ExtendedSSLSession;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509ExtendedTrustManager;

/**
 * TCP with TLS 1.3 alone (ALPN "imdbwir1" checked after the handshake, as tls.c's imdbt_handshake), verified by a CA
 * file (PKIX to that CA, and the host against subjectAltName) or a pin (the server key's SPKI SHA-256: the chain not
 * asked for, as the C client's pinned mode), and the login's channel binding (§8f):
 * <ul>
 * <li>the TLS exporter (RFC 9266: label "EXPORTER-Channel-Binding", empty context, 32 bytes), type 1, which a default
 * server takes: by JDK 25's ExtendedSSLSession.exportKeyingMaterialData (the JDK's JSSE), or on an earlier JDK by
 * BouncyCastle's TLS API (bctls, through imagedb.wire.bc.BcTlsTransport) when its jars and that class are on the class
 * path;</li>
 * <li>else tls-server-end-point (RFC 5929: the SHA-256 of the server certificate's DER), type 2, which only a server run
 * with --channel-binding any takes; a default one answers verdict 2, and the driver never retries with another type.</li>
 * </ul>
 * Both exporters reached by reflection, so the core compiles and runs on JDK 17's standard library alone.
 */
public final class TlsTransport implements Transport {
    public static final String ALPN = "imdbwir1";
    static final String EXPORTER_LABEL = "EXPORTER-Channel-Binding";
    static final String BC_BRIDGE = "imagedb.wire.bc.BcTlsTransport";

    /** which TLS stack and binding a connection uses */
    public enum Binding {
        /** the strongest available, never retried with another: the JDK's exporter, else BouncyCastle's, else end-point */
        AUTO,
        /** the JDK's JSSE and its exporter (JDK 25+) */
        JDK_EXPORTER,
        /** BouncyCastle's TLS API and its exporter (bctls, bcprov, bcutil and the bridge on the class path) */
        BC_EXPORTER,
        /** the JDK's JSSE and tls-server-end-point (a server run with --channel-binding any) */
        END_POINT
    }

    private final SSLSocket s;
    private final InputStream in;
    private final OutputStream out;
    private final Binding binding;
    private final byte[] bindingBytes;
    private final X509Certificate peer;
    private int soTimeout = -1;

    private TlsTransport(SSLSocket s, Binding binding, byte[] bindingBytes, X509Certificate peer) throws IOException {
        this.s = s;
        this.in = s.getInputStream();
        this.out = s.getOutputStream();
        this.binding = binding;
        this.bindingBytes = bindingBytes;
        this.peer = peer;
    }

    /** JDK 25+: ExtendedSSLSession.exportKeyingMaterialData(String, byte[], int), or null (JDK 17 has none) */
    public static Method jdkExporter() {
        try {
            return ExtendedSSLSession.class.getMethod("exportKeyingMaterialData", String.class, byte[].class, int.class);
        } catch (NoSuchMethodException x) {
            return null;
        }
    }

    /** the BouncyCastle bridge's connect, or null when it or BouncyCastle is not on the class path */
    static Method bcConnect() {
        try {
            ClassLoader cl = TlsTransport.class.getClassLoader();
            Class.forName("org.bouncycastle.tls.TlsClientProtocol", false, cl);
            Class<?> b = Class.forName(BC_BRIDGE, true, cl);
            return b.getMethod("connect", String.class, int.class, String.class, X509Certificate.class, byte[].class, int.class);
        } catch (ClassNotFoundException | NoSuchMethodException | LinkageError x) {
            return null;
        }
    }

    /** what AUTO picks on this JVM and class path */
    public static Binding resolve(Binding want) {
        if (want != Binding.AUTO) return want;
        if (jdkExporter() != null) return Binding.JDK_EXPORTER;
        if (bcConnect() != null) return Binding.BC_EXPORTER;
        return Binding.END_POINT;
    }

    /**
     * connect to address:port, verify the server as trust says (in CA mode its certificate must name verifyName: a host
     * name or an address literal), and compute the binding. timeoutMs bounds the TCP connect and the handshake.
     */
    public static Transport connect(String address, int port, String verifyName, TlsTrust trust, Binding want, int timeoutMs)
            throws IOException {
        if (trust == null) throw new IllegalArgumentException("TLS: a CA file or a pin (no unverified mode)");
        if (address == null || verifyName == null) throw new IllegalArgumentException("TLS: a host");
        Binding b = resolve(want == null ? Binding.AUTO : want);
        if (b == Binding.BC_EXPORTER) {
            Method m = bcConnect();
            if (m == null)
                throw new WireException(Wire.E_UNSUPPORTED, "TLS: BouncyCastle (bctls, bcprov, bcutil) or " + BC_BRIDGE
                        + " is not on the class path");
            try {
                return (Transport) m.invoke(null, address, port, verifyName, trust.pinned() ? null : trust.caCert(),
                        trust.pinned() ? trust.pinBytes() : null, timeoutMs);
            } catch (InvocationTargetException x) {
                Throwable c = x.getCause();
                if (c instanceof IOException) throw (IOException) c;
                if (c instanceof RuntimeException) throw (RuntimeException) c;
                throw new WireException(Wire.E_STATE, "TLS: BouncyCastle: " + c, c);
            } catch (IllegalAccessException x) {
                throw new WireException(Wire.E_STATE, "TLS: BouncyCastle: " + x, x);
            }
        }
        Method jdkx = null;
        if (b == Binding.JDK_EXPORTER && (jdkx = jdkExporter()) == null)
            throw new WireException(Wire.E_UNSUPPORTED, "TLS: this JDK (" + System.getProperty("java.version")
                    + ") has no keying-material exporter (JDK 25+)");
        SSLContext ctx;
        PinManager pm = null;
        try {
            ctx = SSLContext.getInstance("TLSv1.3");
            TrustManager[] tms;
            if (trust.pinned()) {
                pm = new PinManager(trust.pinBytes());
                tms = new TrustManager[] {pm};
            } else {
                KeyStore ks = KeyStore.getInstance("PKCS12");
                ks.load(null, null);
                ks.setCertificateEntry("imagedb-ca", trust.caCert());
                TrustManagerFactory tmf = TrustManagerFactory.getInstance("PKIX");
                tmf.init(ks);
                tms = tmf.getTrustManagers();
            }
            ctx.init(null, tms, new SecureRandom()); // a fresh context a connection: no session cached across them
        } catch (GeneralSecurityException | IOException x) {
            throw new WireException(Wire.E_STATE, "TLS: the context: " + x, x);
        }
        Socket plain = new Socket();
        SSLSocket s = null;
        boolean ok = false;
        try {
            plain.setTcpNoDelay(true); // small frames never wait
            plain.setKeepAlive(true);  // a server gone without a FIN found
            plain.connect(new InetSocketAddress(address, port), timeoutMs);
            s = (SSLSocket) ctx.getSocketFactory().createSocket(plain, verifyName, port, true);
            SSLParameters p = s.getSSLParameters();
            p.setProtocols(new String[] {"TLSv1.3"});
            p.setApplicationProtocols(new String[] {ALPN});
            if (!trust.pinned()) p.setEndpointIdentificationAlgorithm("HTTPS"); // the name against subjectAltName
            s.setSSLParameters(p);
            s.setSoTimeout(timeoutMs);
            try {
                s.startHandshake();
            } catch (SSLException x) {
                String why = pm != null && pm.refused != null ? pm.refused : x.getMessage();
                throw new WireException(Wire.E_AUTH, "TLS handshake: " + why, x);
            }
            SSLSession ses = s.getSession();
            if (!"TLSv1.3".equals(ses.getProtocol()))
                throw new WireException(Wire.E_AUTH, "TLS: not 1.3 (" + ses.getProtocol() + ")");
            String alpn = s.getApplicationProtocol();
            if (!ALPN.equals(alpn)) throw new WireException(Wire.E_AUTH, "TLS: the peer does not speak " + ALPN + " (ALPN)");
            Certificate[] chain = ses.getPeerCertificates();
            if (chain.length < 1 || !(chain[0] instanceof X509Certificate))
                throw new WireException(Wire.E_AUTH, "TLS: no server certificate");
            X509Certificate leaf = (X509Certificate) chain[0];
            if (trust.pinned() && !MessageDigest.isEqual(Der.sha256(Der.spki(leaf.getEncoded())), trust.pinBytes()))
                throw new WireException(Wire.E_AUTH, "TLS: the server's key is not the pinned one"); // again, after it
            if (!trust.pinned() && !HostCheck.matches(leaf, verifyName)) // the stack's own check, and ours (one rule)
                throw new WireException(Wire.E_AUTH, "TLS: the server's certificate does not name " + verifyName);
            byte[] cb = b == Binding.JDK_EXPORTER ? export(jdkx, ses) : endPoint(leaf);
            s.setSoTimeout(0);
            TlsTransport t = new TlsTransport(s, b, cb, leaf);
            ok = true;
            return t;
        } catch (GeneralSecurityException x) {
            throw new WireException(Wire.E_AUTH, "TLS: " + x.getMessage(), x);
        } finally {
            if (!ok) closeQuietly(s != null ? s : plain);
        }
    }

    private static void closeQuietly(Socket x) {
        try {
            x.close();
        } catch (IOException ignored) {
        }
    }

    /** RFC 9266 by the JDK's own API (JDK 25+) */
    private static byte[] export(Method m, SSLSession ses) throws WireException {
        try {
            byte[] v = (byte[]) m.invoke(ses, EXPORTER_LABEL, new byte[0], Wire.KEY);
            if (v == null || v.length != Wire.KEY) throw new WireException(Wire.E_STATE, "TLS: the exporter gave no 32 bytes");
            return v;
        } catch (InvocationTargetException x) {
            throw new WireException(Wire.E_STATE, "TLS: the exporter: " + x.getCause(), x.getCause());
        } catch (IllegalAccessException | RuntimeException x) {
            throw new WireException(Wire.E_STATE, "TLS: the exporter: " + x, x);
        }
    }

    /**
     * RFC 5929's tls-server-end-point: the certificate's hash by its signature's hash, MD5 and SHA-1 taken to SHA-256.
     * imagedb's certificates are signed with SHA-256 and a server allowing this binding refuses another at its start
     * (§4), so SHA-256 is the one hash computed; a certificate signed with another hash is refused, never bound wrongly.
     */
    public static byte[] endPoint(X509Certificate c) throws CertificateException, WireException {
        String oid = c.getSigAlgOID();
        switch (oid) {
        case "1.2.840.10045.4.3.2":    // ecdsa-with-SHA256
        case "1.2.840.113549.1.1.11":  // sha256WithRSAEncryption
        case "2.16.840.1.101.3.4.3.2": // dsa-with-sha256
        case "1.2.840.113549.1.1.4":   // md5WithRSAEncryption: SHA-256 (RFC 5929)
        case "1.2.840.113549.1.1.5":   // sha1WithRSAEncryption: SHA-256
        case "1.2.840.10045.4.1":      // ecdsa-with-SHA1: SHA-256
        case "1.2.840.10040.4.3":      // dsa-with-sha1: SHA-256
            return Der.sha256(c.getEncoded());
        default:
            throw new WireException(Wire.E_UNSUPPORTED, "TLS: the server certificate's signature (" + c.getSigAlgName()
                    + ") is not by SHA-256: tls-server-end-point would need another hash");
        }
    }

    /** the pin: the leaf's SPKI SHA-256, its own bytes, compared in constant time; the chain not asked for */
    static final class PinManager extends X509ExtendedTrustManager {
        private final byte[] pin;
        volatile String refused;

        PinManager(byte[] pin) { this.pin = pin; }

        private void check(X509Certificate[] chain) throws CertificateException {
            if (chain == null || chain.length < 1) throw fail("no server certificate");
            byte[] got;
            try {
                got = Der.sha256(Der.spki(chain[0].getEncoded()));
            } catch (WireException x) {
                throw fail("the server certificate's subjectPublicKeyInfo: " + x.getMessage());
            }
            if (!MessageDigest.isEqual(got, pin)) throw fail("the server's key is not the pinned one");
        }

        private CertificateException fail(String why) {
            refused = "TLS: " + why;
            return new CertificateException(refused);
        }

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException { check(chain); }

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType, Socket socket) throws CertificateException {
            check(chain);
        }

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType, SSLEngine engine) throws CertificateException {
            check(chain);
        }

        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
            throw new CertificateException("a client's trust manager");
        }

        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType, Socket socket) throws CertificateException {
            throw new CertificateException("a client's trust manager");
        }

        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType, SSLEngine engine) throws CertificateException {
            throw new CertificateException("a client's trust manager");
        }

        @Override
        public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
    }

    @Override
    public void write(byte[] b, int off, int len) throws IOException {
        out.write(b, off, len);
        out.flush();
    }

    @Override
    public int read(byte[] b, int off, int len, int timeoutMs) throws IOException {
        if (timeoutMs != soTimeout) {
            s.setSoTimeout(timeoutMs);
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
    public int bindingType() { return binding == Binding.END_POINT ? Wire.CB_ENDPOINT : Wire.CB_EXPORTER; }

    @Override
    public byte[] binding() { return bindingBytes.clone(); }

    @Override
    public String bindingName() {
        return binding == Binding.JDK_EXPORTER ? "tls-exporter (the JDK's JSSE, " + System.getProperty("java.version") + ")"
                                               : "tls-server-end-point (the JDK's JSSE, " + System.getProperty("java.version") + ")";
    }

    /** the server's certificate as the handshake gave it */
    public X509Certificate peerCertificate() { return peer; }

    @Override
    public void close() throws IOException { s.close(); }
}
