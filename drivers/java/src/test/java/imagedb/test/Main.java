package imagedb.test;

import imagedb.wire.CodecTests;
import imagedb.wire.ScriptedTests;
import imagedb.wire.TlsTransport;
import java.lang.reflect.Method;

/**
 * The tests' entry: `codec` (no server: the codec against t_wire.c's vectors and §4's pinned exchanges, the scripted
 * peer, what this JDK's TLS stack exposes) or `live` (against servers run_tests.sh started; their places in system
 * properties). A name fragment as a second argument runs only the tests whose names hold it.
 */
public final class Main {
    private Main() {}

    /** what this JVM's JSSE exposes for the exporter: proven by reflection over every public javax.net.ssl type */
    static void stackProof() {
        T.run("tls_stack_proof (which binding this JDK and class path give)", () -> {
            int feature = Runtime.version().feature();
            Method m = TlsTransport.jdkExporter();
            T.note("java.version " + System.getProperty("java.version") + ", feature " + feature);
            int found = 0;
            for (Class<?> c : new Class<?>[] {javax.net.ssl.SSLSession.class, javax.net.ssl.ExtendedSSLSession.class,
                                              javax.net.ssl.SSLSocket.class, javax.net.ssl.SSLEngine.class, javax.net.ssl.SSLParameters.class,
                                              javax.net.ssl.SSLContext.class, javax.net.ssl.HandshakeCompletedEvent.class})
                for (Method x : c.getMethods()) {
                    String n = x.getName().toLowerCase();
                    if (n.contains("export") || n.contains("keying")) {
                        found++;
                        T.note("  " + c.getSimpleName() + "." + x.getName() + " " + java.util.Arrays.toString(x.getParameterTypes()));
                    }
                }
            if (feature < 25) {
                T.check(m == null && found == 0, "JDK " + feature + ": no exporter in any javax.net.ssl type");
            } else {
                T.check(m != null, "JDK " + feature + ": ExtendedSSLSession.exportKeyingMaterialData(String, byte[], int)");
            }
            TlsTransport.Binding b = TlsTransport.resolve(TlsTransport.Binding.AUTO);
            T.note("AUTO resolves to " + b);
            String want = System.getProperty("imdb.expect.binding");
            if (want != null) T.eq(want, b.name(), "the binding this configuration was set up to prove");
        });
    }

    public static void main(String[] a) throws Exception {
        String what = a.length > 0 ? a[0] : "codec";
        T.filter = a.length > 1 ? a[1] : null;
        String label = System.getProperty("imdb.config", "?");
        System.out.println("== " + what + " tests (" + label + ")");
        if (what.equals("codec")) {
            stackProof();
            CodecTests.all();
            ScriptedTests.all();
            imagedb.ConnectionScripted.all();
        } else if (what.equals("live")) {
            LiveTests.all();
        } else if (what.equals("renew")) {
            LiveTests.renewed();
        } else {
            System.err.println("usage: Main codec|live|renew [name-fragment]");
            System.exit(2);
        }
        System.exit(T.summary(what + " (" + label + ")"));
    }
}
