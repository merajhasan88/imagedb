package imagedb.test;

import static imagedb.test.T.check;
import static imagedb.test.T.eq;
import static imagedb.test.T.note;
import static imagedb.test.T.run;
import static imagedb.test.T.throwsIt;

import imagedb.BatchException;
import imagedb.Column;
import imagedb.Connection;
import imagedb.Imagedb;
import imagedb.ImagedbException;
import imagedb.Params;
import imagedb.Prepared;
import imagedb.Result;
import imagedb.Row;
import imagedb.Statement;
import imagedb.Type;
import imagedb.wire.Der;
import imagedb.wire.Interval;
import imagedb.wire.Msg;
import imagedb.wire.TlsTransport;
import imagedb.wire.TlsTrust;
import imagedb.wire.Value;
import imagedb.wire.Wire;
import imagedb.wire.WireConnection;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.LocalTime;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Random;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Against the real server (frozen binaries, run_tests.sh starts them): S1 a default server (the exporter alone), S2 one
 * run with --channel-binding any. Its places come in system properties (imdb.*). A logged-in role is the superuser
 * admin (until N1e's slice 2c only superusers log in: a role's refusal is not tested here).
 */
public final class LiveTests {
    private LiveTests() {}

    static String p(String k) {
        String v = System.getProperty("imdb." + k);
        if (v == null) throw new IllegalStateException("system property imdb." + k);
        return v;
    }

    static final String USER = "admin";

    static char[] pw() { return p("password").toCharArray(); }

    static String tag() { return p("tag"); }

    /** the socket of the server this configuration's TCP tests use, so both endpoints reach one database */
    static Connection sock() throws ImagedbException {
        return Imagedb.connect(new Imagedb.Options().socket(Paths.get(p(mainIsAny() ? "any.sock" : "sock"))).user(USER).password(pw())
                                   .readTimeoutMs(120000));
    }

    static Connection sockAny() throws ImagedbException { return Imagedb.connect(Paths.get(p("any.sock")), USER, pw()); }

    /** the binding this configuration takes: imdb.expect.binding when the script names it, else what AUTO resolves to here */
    static TlsTransport.Binding expected() {
        String e = System.getProperty("imdb.expect.binding");
        return e != null ? TlsTransport.Binding.valueOf(e) : TlsTransport.resolve(TlsTransport.Binding.AUTO);
    }

    /** the TCP server this configuration's binding is taken by: S1 for an exporter, S2 for end-point */
    static boolean mainIsAny() { return expected() == TlsTransport.Binding.END_POINT; }

    static Imagedb.Options tcpOpts(boolean any, boolean pinned) throws IOException {
        String pre = any ? "any." : "";
        TlsTrust tr = pinned ? TlsTrust.pin(p(pre + "pin")) : TlsTrust.caFile(Paths.get(p(pre + "ca")));
        return new Imagedb.Options().tcp("127.0.0.1", Integer.parseInt(p(pre + "port")), tr).user(USER).password(pw()).readTimeoutMs(120000);
    }

    static Connection tcp() throws Exception { return Imagedb.connect(tcpOpts(mainIsAny(), true)); }

    /** the main endpoint per test: the socket, then TCP */
    interface Ep {
        Connection open() throws Exception;
    }

    static final String[] EP_NAMES = {"socket", "tcp"};

    static Ep ep(int k) { return k == 0 ? LiveTests::sock : LiveTests::tcp; }

    static ImagedbException fails(T.Body b, String what) { return throwsIt(ImagedbException.class, b, what); }

    public static void all() {
        run("live_login (the socket and TCP, pin and CA, the binding this JDK takes)", () -> {
            try (Connection c = sock()) {
                c.ping();
                eq("none (the Unix socket)", c.channelBinding(), "the socket binds nothing");
                eq(1L, c.query("SELECT 1").row(0).getLong(0), "SELECT 1 on the socket");
            }
            Imagedb.Options again = tcpOpts(mainIsAny(), true); // one Options, two connections: its password kept
            try (Connection c1 = Imagedb.connect(again); Connection c2 = Imagedb.connect(again)) {
                c1.ping();
                c2.ping();
            }
            for (boolean pinned : new boolean[] {true, false}) {
                try (Connection c = Imagedb.connect(tcpOpts(mainIsAny(), pinned))) {
                    c.ping();
                    note((pinned ? "pin" : "CA") + ": " + c.channelBinding());
                    String want = expected() == TlsTransport.Binding.JDK_EXPORTER ? "tls-exporter (the JDK's JSSE"
                                  : expected() == TlsTransport.Binding.BC_EXPORTER ? "tls-exporter (BouncyCastle" : "tls-server-end-point";
                    check(c.channelBinding().startsWith(want), "the binding taken: " + c.channelBinding());
                    eq(2L, c.query("SELECT 1 + 1").row(0).getLong(0), "a statement over TCP");
                }
            }
        });

        run("live_binding_by_type (a default server refuses end-point with verdict 2; --channel-binding any takes it)", () -> {
            ImagedbException x = fails(() -> Imagedb.connect(tcpOpts(false, true).binding(TlsTransport.Binding.END_POINT)), "end-point at S1");
            check(x != null && x.kind() == ImagedbException.Kind.AUTH && x.getMessage().contains("channel binding type"),
                  "verdict 2 as its own refusal: " + x);
            try (Connection c = Imagedb.connect(tcpOpts(true, true).binding(TlsTransport.Binding.END_POINT))) {
                c.ping();
                check(c.channelBinding().startsWith("tls-server-end-point"), "end-point taken by S2: " + c.channelBinding());
            }
            try (Connection c = Imagedb.connect(tcpOpts(true, false).binding(TlsTransport.Binding.END_POINT))) {
                c.ping(); // CA mode too
            }
            if (expected() != TlsTransport.Binding.END_POINT) {
                try (Connection c = Imagedb.connect(tcpOpts(true, true))) { // S2 takes the exporter too
                    check(c.channelBinding().startsWith("tls-exporter"), "the exporter at S2: " + c.channelBinding());
                }
                try (Connection c = Imagedb.connect(tcpOpts(false, true))) {
                    check(c.channelBinding().startsWith("tls-exporter"), "AUTO at the default server: the exporter");
                }
            } else {
                ImagedbException y = fails(() -> Imagedb.connect(tcpOpts(false, true)), "AUTO (end-point) at S1");
                check(y != null && y.kind() == ImagedbException.Kind.AUTH && y.getMessage().contains("channel binding type"),
                      "a JDK without an exporter refused by a default server (verdict 2), never retried: " + y);
                ImagedbException z = fails(() -> Imagedb.connect(tcpOpts(false, true).binding(TlsTransport.Binding.JDK_EXPORTER)), "the JDK's exporter asked for");
                check(z != null && z.kind() == ImagedbException.Kind.UNSUPPORTED, "an exporter this JDK lacks refused before connecting: " + z);
            }
        });

        run("live_tls_negatives (wrong pin, another CA, a name outside the certificate, no unverified mode)", () -> {
            byte[] pin = Der.unhex(p(mainIsAny() ? "any.pin" : "pin"));
            pin[31] ^= 1;
            int port = Integer.parseInt(p(mainIsAny() ? "any.port" : "port"));
            ImagedbException a = fails(() -> Imagedb.connect("127.0.0.1", port, TlsTrust.pin(pin), USER, pw()), "a wrong pin");
            check(a != null && a.kind() == ImagedbException.Kind.AUTH && a.getMessage().contains("pinned"), "a wrong pin: " + a);
            ImagedbException b = fails(() -> Imagedb.connect("127.0.0.1", port, TlsTrust.caFile(Paths.get(p("otherca"))), USER, pw()), "another CA");
            check(b != null && b.kind() == ImagedbException.Kind.AUTH, "another CA: " + b);
            TlsTrust ca = TlsTrust.caFile(Paths.get(p(mainIsAny() ? "any.ca" : "ca")));
            ImagedbException c = fails(() -> Imagedb.connect(new Imagedb.Options().tcp("db.example.org", port, ca).address("127.0.0.1")
                                                                 .user(USER).password(pw())), "a name the certificate lacks");
            check(c != null && c.kind() == ImagedbException.Kind.AUTH, "a name outside subjectAltName: " + c);
            try (Connection ok = Imagedb.connect(new Imagedb.Options().tcp("localhost", port, ca).address("127.0.0.1").user(USER).password(pw()))) {
                ok.ping(); // DNS:localhost is in it
            }
            // no unverified mode: no TlsTrust but by a CA or a pin, and no TCP connection without one
            for (Constructor<?> k : TlsTrust.class.getDeclaredConstructors()) check(!Modifier.isPublic(k.getModifiers()), "no public constructor");
            for (Method m : TlsTrust.class.getMethods())
                if (Modifier.isStatic(m.getModifiers()) && m.getReturnType() == TlsTrust.class)
                    check(Arrays.asList("caFile", "ca", "pin").contains(m.getName()), "a TlsTrust factory: " + m.getName());
            throwsIt(IllegalArgumentException.class, () -> Imagedb.connect("127.0.0.1", port, null, USER, pw()), "no trust");
            throwsIt(IllegalArgumentException.class, () -> TlsTrust.pin(new byte[31]), "a 31-byte pin");
            throwsIt(IllegalArgumentException.class, () -> TlsTrust.pin("zz"), "a pin not hex");
            throwsIt(IllegalArgumentException.class, () -> Imagedb.connect(new Imagedb.Options().socket(Paths.get(p("sock")))
                                                         .tcp("127.0.0.1", port, ca).user(USER).password(pw())), "socket and TCP: no fallback");
            // the pin is the key's SPKI SHA-256 (as `cert` prints it), never the certificate's hash
            X509Certificate leaf = serverCert(mainIsAny());
            eq(p(mainIsAny() ? "any.pin" : "pin"), Der.hex(Der.sha256(Der.spki(leaf.getEncoded()))), "the pin from the certificate's own SPKI bytes");
            eq(Der.hex(Der.spki(leaf.getEncoded())), Der.hex(leaf.getPublicKey().getEncoded()), "the SPKI bytes are the JDK's encoding too");
            check(!p("pin").equals(Der.hex(Der.sha256(leaf.getEncoded()))), "the certificate's hash is another");
        });

        run("live_auth_negatives (a wrong password and an unknown name: one refusal)", () -> {
            for (int k = 0; k < 2; k++) {
                final int kk = k;
                ImagedbException a = fails(() -> Imagedb.connect(new Imagedb.Options().socket(Paths.get(p("sock"))).user(kk == 0 ? USER : "nobody")
                                                                     .password("wrong-password".toCharArray())), "refused");
                check(a != null && a.kind() == ImagedbException.Kind.AUTH && a.getMessage().equals("authentication refused"),
                      (k == 0 ? "a wrong password" : "an unknown name") + ": " + a);
            }
            ImagedbException t = fails(() -> Imagedb.connect(tcpOpts(mainIsAny(), true).password("wrong-password".toCharArray())), "TCP");
            check(t != null && t.kind() == ImagedbException.Kind.AUTH && t.getMessage().equals("authentication refused"), "over TCP: " + t);
            ImagedbException bad = fails(() -> Imagedb.connect(Paths.get(p("sock")), USER, "é".toCharArray()), "a password CREATE ROLE refuses");
            check(bad != null && bad.kind() == ImagedbException.Kind.INVALID, "refused before any byte: " + bad);
        });

        for (int k = 0; k < 2; k++) {
            final Ep ep = ep(k);
            final String en = EP_NAMES[k];
            run("live_types_" + en + " (every type at its edges, through parameters and literals, and back)", () -> typesRoundTrip(ep, en));
        }

        run("live_sum_type0_empty (a SUM as DECIMAL; SHOW's columns of no type; COLUMNS with no ROWS)", () -> {
            try (Connection c = sock()) {
                String t = "s_" + tag();
                c.query("CREATE TABLE " + t + " (id BIGINT PRIMARY KEY, v BIGINT)");
                c.query("INSERT INTO " + t + " VALUES (1, $1), (2, $2)", Long.MAX_VALUE, Long.MAX_VALUE);
                Result r = c.query("SELECT SUM(v) FROM " + t);
                eq(Type.DECIMAL, r.columns().get(0).type(), "SUM over INT64 is DECIMAL");
                eq(0, r.columns().get(0).scale(), "at scale 0");
                eq(new BigDecimal("18446744073709551614"), r.row(0).getBigDecimal(0), "two INT64 maxima, exact");
                throwsIt(IllegalStateException.class, () -> r.row(0).getLong(0), "not exactly a long");
                Result e = c.query("SELECT SUM(v) FROM " + t + " WHERE id > 5");
                eq(Type.DECIMAL, e.columns().get(0).type(), "an all-NULL SUM is DECIMAL too");
                check(e.row(0).isNull(0) && e.row(0).value(0).type == Wire.T_DECIMAL, "a NULL typed DECIMAL");
                Result none = c.query("SELECT id, v FROM " + t + " WHERE id > 5");
                check(none.hasColumns() && none.size() == 0 && none.count() == 0, "COLUMNS, no ROWS, DONE 0");
                eq("id", none.columns().get(0).name(), "its columns named");
                Result sh = c.query("SHOW TABLES");
                check(sh.hasColumns() && sh.size() >= 1, "SHOW TABLES answers");
                boolean anyNone = false;
                for (Column col : sh.columns()) anyNone |= col.type() == Type.NONE;
                note("SHOW TABLES' columns: " + sh.columns());
                if (anyNone) {
                    for (Row row : sh)
                        for (int i = 0; i < row.size(); i++) check(row.value(i).type != Wire.T_NONE || row.isNull(i), "a value under type 0 has its own type");
                } else {
                    Result st = c.query("SHOW STATS");
                    for (Column col : st.columns()) anyNone |= col.type() == Type.NONE;
                    note("SHOW STATS' columns: " + st.columns());
                }
                check(anyNone, "a column of no known type met (SHOW)");
            }
        });

        run("live_batch (a batch's results; an ERROR mid-batch: its index, the earlier ones' results, the rest unrun)", () -> {
            try (Connection c = sock()) {
                String t = "b_" + tag();
                c.query("CREATE TABLE " + t + " (id BIGINT PRIMARY KEY, s TEXT)");
                List<Result> rs = c.batch(Arrays.asList(Statement.of("INSERT INTO " + t + " VALUES ($1, $2)", 1L, "one"),
                                                        Statement.of("SELECT s FROM " + t + " WHERE id = $1", 1L),
                                                        Statement.of("SELECT 42")));
                eq(3, rs.size(), "three results");
                eq(1L, rs.get(0).count(), "INSERT 1");
                check(rs.get(0).writeCommit() >= 1 && rs.get(0).writeHash().length == 32, "the INSERT's own commit and hash");
                eq("one", rs.get(1).row(0).getString(0), "the SELECT in the batch");
                check(rs.get(1).readPoint() != null && rs.get(1).readPoint().commit == rs.get(0).writeCommit(), "it read the INSERT's commit");
                BatchException x = throwsIt(BatchException.class, () -> c.batch(Arrays.asList(
                        Statement.of("INSERT INTO " + t + " VALUES (2, 'two')"), Statement.of("INSERT INTO " + t + " VALUES (1, 'dup')"),
                        Statement.of("INSERT INTO " + t + " VALUES (3, 'three')"))), "a duplicate key mid-batch");
                if (x != null) {
                    eq(1, x.index(), "the ERROR's index names the failing statement");
                    eq(1, x.completed().size(), "the statement before it answered");
                    check(x.fromServer() && x.code() >= 1, "the server's code: " + x.code() + " " + x.getMessage());
                    note("duplicate key: code " + x.code() + " (" + x.kind() + "): " + x.getMessage());
                }
                eq(2L, c.query("SELECT COUNT(*) FROM " + t).row(0).getLong(0), "1 and 2 stand (each its own commit), 3 never ran");
                eq(Connection.TxState.IDLE, c.state(), "READY idle");
            }
        });

        run("live_prepared (PREPARE, EXECUTE of several sets, an ERROR's set index, DEALLOCATE)", () -> {
            try (Connection c = tcp()) {
                String t = "p_" + tag();
                c.query("CREATE TABLE " + t + " (id BIGINT PRIMARY KEY, d DECIMAL(10,2), s TEXT)");
                Prepared ins = c.prepare("ins_" + tag(), "INSERT INTO " + t + " VALUES ($1, $2, $3)");
                List<Result> rs = ins.executeBatch(Arrays.asList(new Object[] {1L, new BigDecimal("1.50"), "a"},
                                                                 new Object[] {2L, 7L, null}, // an INT64 into a DECIMAL: its literal's value
                                                                 new Object[] {3L, null, "c"}));
                eq(3, rs.size(), "three sets");
                Result one = ins.execute(4L, new BigDecimal("-99999999.99"), "d");
                eq(1L, one.count(), "one more");
                BatchException x = throwsIt(BatchException.class, () -> ins.executeBatch(Arrays.asList(new Object[] {5L, null, "e"},
                        new Object[] {5L, null, "dup"}, new Object[] {6L, null, "f"})), "a set failing");
                if (x != null) eq(1, x.index(), "the failing set's index");
                ImagedbException r = fails(() -> ins.execute(7L, new BigDecimal("1.005"), "g"), "1.005 into DECIMAL(10,2)");
                check(r != null && r.fromServer(), "never rounded: refused by the server: " + r);
                Prepared sel = c.prepare("sel_" + tag(), "SELECT id, d, s FROM " + t + " WHERE id = $1");
                Row row = sel.execute(2L).row(0);
                eq(new BigDecimal("7.00"), row.getBigDecimal(1), "7 stored as 7.00");
                check(row.isNull(2), "a NULL of no type into TEXT");
                eq(5L, c.query("SELECT COUNT(*) FROM " + t).row(0).getLong(0), "1 to 5: the set before the failure stands, the one after never ran");
                sel.deallocate();
                ImagedbException gone = fails(() -> sel.execute(1L), "EXECUTE after DEALLOCATE");
                check(gone != null && gone.fromServer(), "refused: " + gone);
                ins.close();
            }
        });

        run("live_transaction (READY's states, statement-level rollback, the read point's own writes, a doomed one)", () -> transaction());

        run("live_cancel (CANCEL of a self-join of a 1,000,000-row table from another thread)", () -> cancel());

        for (int k = 0; k < 2; k++) {
            final Ep ep = ep(k);
            final int kk = k;
            run("live_copy_" + EP_NAMES[k] + " (COPY FROM STDIN and TO STDOUT, their refusals)", () -> copy(ep, EP_NAMES[kk]));
        }

        run("live_sessions_kill (SESSIONS, KILL terminate and cancel, a send after the server closed)", () -> sessionsKill());

        run("live_big_result (rows across several ROWS frames)", () -> {
            try (Connection c = tcp()) {
                Result r = c.query("SELECT id, x FROM big WHERE id <= 300000 ORDER BY id");
                eq(300000, r.size(), "300,000 rows");
                long sum = 0;
                boolean inOrder = true;
                for (int i = 0; i < r.size(); i++) {
                    inOrder &= r.row(i).getLong(0) == i + 1;
                    sum += r.row(i).getLong(1);
                }
                check(inOrder, "in order");
                eq(c.query("SELECT SUM(x) FROM big WHERE id <= 300000").row(0).getLong(0), sum, "the same sum");
            }
        });

        run("live_close (TERMINATE: an open transaction rolled back; a closed connection refuses)", () -> {
            String t = "x_" + tag();
            try (Connection c = sock()) {
                c.query("CREATE TABLE " + t + " (id BIGINT PRIMARY KEY)");
            }
            Connection c = sock();
            c.query("BEGIN");
            c.query("INSERT INTO " + t + " VALUES (1)");
            c.close();
            check(c.isClosed(), "closed");
            ImagedbException x = fails(() -> c.query("SELECT 1"), "after close");
            check(x != null && !x.fromServer(), "refused locally: " + x);
            try (Connection d = sock()) {
                eq(0L, d.query("SELECT COUNT(*) FROM " + t).row(0).getLong(0), "the open transaction rolled back");
            }
        });

        run("live_frames_recorded (the server's own frames, recorded: each decoded and encoded back; every byte flipped three ways)", () -> {
            Recording rec = new Recording(imagedb.wire.UnixTransport.connect(Paths.get(p(mainIsAny() ? "any.sock" : "sock"))));
            WireConnection w = WireConnection.login(rec, USER, pw(), null, 30000);
            w.setTimeout(120000);
            String ty = "fr_" + tag();
            String[] qs = {"CREATE TYPE frm_" + tag() + " AS ENUM ('sad', '', 'é')",
                           "CREATE TABLE " + ty + " (id BIGINT PRIMARY KEY, i64 BIGINT, i16 SMALLINT, i32 INTEGER, f FLOAT64, b BOOL, x TEXT,"
                           + " v VARCHAR(5), d38 DECIMAL(38,10), d10 DECIMAL(10,2), ts TIMESTAMP, tz TIMESTAMPTZ, dt DATE, tm TIME, u UUID, ba BYTEA,"
                           + " iv INTERVAL, en frm_" + tag() + ")",
                           "INSERT INTO " + ty + " VALUES (1, -9223372036854775808, -32768, -2147483648, -1.5, false, '', 'éé',"
                           + " -9999999999999999999999999999.9999999999, -99999999.99, '0001-01-01 00:00:00', '9999-12-31 23:59:59.999999+00',"
                           + " '0001-01-01', '23:59:59.999999', 'ffffffff-ffff-ffff-ffff-ffffffffffff', '\\x00ff', '-1 mon 2 days -3 microseconds', 'é'),"
                           + " (2, 1, 2, 3, 0.1, true, 'hé', 'abcde', 0.0000000001, 0.01, '1970-01-01 00:00:00.000001',"
                           + " '1969-12-31 23:59:59.999999+00', '9999-12-31', '00:00:00', '00010203-0405-0607-0809-0a0b0c0d0e0f', '\\x',"
                           + " '0 days', ''), (3, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL)",
                           "SELECT * FROM " + ty + " ORDER BY id", "SHOW TABLES", "SELECT SUM(i64) FROM " + ty + " WHERE id = 2",
                           "SELECT 1 / 0", "BEGIN", "SELECT COUNT(*) FROM " + ty, "INSERT INTO " + ty + " (id) VALUES (99)", "COMMIT",
                           "DELETE FROM " + ty + " WHERE id = 99", "COPY (SELECT id FROM big WHERE id <= 5) TO STDOUT"};
            List<String> errors = new ArrayList<>();
            for (String q : qs) {
                w.sendQuery(Collections.singletonList(new imagedb.wire.Frames.Stmt(q, null)));
                for (Msg m = w.next(); !(m instanceof Msg.Ready); m = w.next())
                    if (m instanceof Msg.Error) errors.add(q + ": " + ((Msg.Error) m).message);
            }
            eq(1, errors.size(), "one ERROR (the division by zero): " + errors);
            w.sendSessions();
            check(w.next() instanceof Msg.SessionsList, "SESSIONS_LIST");
            w.sendKill(Wire.KILL_CANCEL, Long.MAX_VALUE);
            check(w.next() instanceof Msg.KillDone, "KILL_DONE");
            w.sendPing();
            check(w.next() instanceof Msg.Pong, "PONG");
            w.close();
            byte[] all = rec.got.toByteArray();
            byte[] frames = Arrays.copyOfRange(all, Wire.CHALLENGE_LEN + Wire.VERDICT_LEN, all.length);
            long[] r = imagedb.wire.FrameFlips.check(frames);
            note(r[0] + " frames recorded (" + frames.length + " bytes): " + r[1] + " flips taken, each re-encoded to itself; " + r[2] + " refused");
            check(r[0] >= 30, "the frames recorded: " + r[0]);
            eq(0L, r[3], "flips taken that encode otherwise, cuts taken, or a frame of the server's refused");
        });

        run("live_tls_stack_refusals (a TLS peer without ALPN imdbwir1, or TLS 1.2 alone, refused before any byte of the login)", () -> {
            Object[][] cases = { // protocols, ALPN the peer selects, the refusal wanted (null: the handshake passes)
                {new String[] {"TLSv1.3"}, new String[0], "ALPN"}, {new String[] {"TLSv1.2"}, new String[] {"imdbwir1"}, ""},
                {new String[] {"TLSv1.3"}, new String[] {"h2"}, ""}, {new String[] {"TLSv1.3"}, new String[] {"imdbwir1"}, null},
            };
            for (Object[] c : cases) {
                String[] prot = (String[]) c[0], alpn = (String[]) c[1];
                String want = (String) c[2];
                java.util.concurrent.atomic.AtomicInteger hello = new java.util.concurrent.atomic.AtomicInteger(-1);
                int port = fakeTlsServer(prot, alpn, hello);
                ImagedbException x = fails(() -> Imagedb.connect(new Imagedb.Options().tcp("127.0.0.1", port, TlsTrust.pin(p("pin"))).user(USER)
                                                                     .password(pw()).connectTimeoutMs(10000)), Arrays.toString(prot) + " " + Arrays.toString(alpn));
                String what = Arrays.toString(prot) + " ALPN " + Arrays.toString(alpn);
                if (want == null) {
                    check(x != null && x.kind() == ImagedbException.Kind.IO, "the control: the handshake passes, the peer then closes: " + x);
                    eq(112, waitFor(hello), "the control: the hello's 112 bytes reached the peer");
                } else {
                    check(x != null && x.kind() == ImagedbException.Kind.AUTH && x.getMessage().contains(want), what + ": refused in TLS: " + x);
                    check(waitFor(hello) <= 0, what + ": no byte of the login reached the peer (" + hello.get() + ")");
                }
                note(what + ": " + (x == null ? "taken" : x.getMessage()));
            }
        });

        run("live_wire_level (pipelined requests; a cancel with nothing outstanding dropped)", () -> {
            try (Connection c = sock()) {
                WireConnection w = c.wire();
                w.sendQuery(Collections.singletonList(new imagedb.wire.Frames.Stmt("SELECT 1", null)));
                w.sendQuery(Collections.singletonList(new imagedb.wire.Frames.Stmt("SELECT 2", null)));
                w.sendPing();
                List<String> seen = new ArrayList<>();
                int ready = 0;
                while (ready < 2 || !seen.contains("PONG")) { // PONG out of turn: before, among or after the replies
                    Msg m = w.next();
                    seen.add(Wire.frameName(m.type));
                    if (m.type == Wire.READY) ready++;
                }
                note("pipelined: " + seen);
                check(seen.contains("PONG"), "PONG answered among the replies");
                eq(0, w.outstanding(), "both requests answered");
                c.cancel(); // nothing outstanding: dropped, never cancelling the next request
                eq(3L, c.query("SELECT 3").row(0).getLong(0), "the next request runs uncancelled");
            }
        });
    }

    /** a transport whose every byte read is kept: the server's frames as sent */
    static final class Recording implements imagedb.wire.Transport {
        final imagedb.wire.Transport t;
        final ByteArrayOutputStream got = new ByteArrayOutputStream();

        Recording(imagedb.wire.Transport t) { this.t = t; }

        @Override
        public void write(byte[] b, int off, int len) throws IOException { t.write(b, off, len); }

        @Override
        public int read(byte[] b, int off, int len, int timeoutMs) throws IOException {
            int k = t.read(b, off, len, timeoutMs);
            if (k > 0) synchronized (got) { got.write(b, off, k); }
            return k;
        }

        @Override
        public int endpoint() { return t.endpoint(); }

        @Override
        public int bindingType() { return t.bindingType(); }

        @Override
        public byte[] binding() throws IOException { return t.binding(); }

        @Override
        public String bindingName() { return t.bindingName(); }

        @Override
        public void close() throws IOException { t.close(); }
    }

    static int waitFor(java.util.concurrent.atomic.AtomicInteger v) throws InterruptedException {
        for (int i = 0; i < 100 && v.get() == -1; i++) Thread.sleep(50);
        return v.get();
    }

    /**
     * a TLS peer of the JDK's own JSSE with S1's key and certificate, speaking the protocols and selecting the ALPN given
     * (none: no ALPN at all): one connection, the bytes it then reads counted into hello (-1 until the handshake ends,
     * 0 when it failed)
     */
    static int fakeTlsServer(String[] protocols, String[] alpn, java.util.concurrent.atomic.AtomicInteger hello) throws Exception {
        Path dir = Paths.get(p("ca")).getParent();
        String pem = new String(Files.readAllBytes(dir.resolve("server.key")), StandardCharsets.US_ASCII);
        byte[] der = java.util.Base64.getMimeDecoder().decode(pem.replaceAll("-----[A-Z ]+-----", ""));
        java.security.PrivateKey key = java.security.KeyFactory.getInstance("EC").generatePrivate(new java.security.spec.PKCS8EncodedKeySpec(der));
        java.security.cert.Certificate leaf, ca;
        try (InputStream a = Files.newInputStream(dir.resolve("server.crt")); InputStream b = Files.newInputStream(dir.resolve("ca.crt"))) {
            leaf = CertificateFactory.getInstance("X.509").generateCertificate(a);
            ca = CertificateFactory.getInstance("X.509").generateCertificate(b);
        }
        java.security.KeyStore ks = java.security.KeyStore.getInstance("PKCS12");
        ks.load(null, null);
        ks.setKeyEntry("k", key, "x".toCharArray(), new java.security.cert.Certificate[] {leaf, ca});
        javax.net.ssl.KeyManagerFactory kmf = javax.net.ssl.KeyManagerFactory.getInstance(javax.net.ssl.KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(ks, "x".toCharArray());
        javax.net.ssl.SSLContext sc = javax.net.ssl.SSLContext.getInstance("TLS");
        sc.init(kmf.getKeyManagers(), null, null);
        javax.net.ssl.SSLServerSocket ss = (javax.net.ssl.SSLServerSocket) sc.getServerSocketFactory()
                .createServerSocket(0, 1, java.net.InetAddress.getByName("127.0.0.1"));
        javax.net.ssl.SSLParameters sp = ss.getSSLParameters();
        sp.setProtocols(protocols);
        sp.setApplicationProtocols(alpn);
        ss.setSSLParameters(sp);
        Thread t = new Thread(() -> {
            try (javax.net.ssl.SSLServerSocket s0 = ss; javax.net.ssl.SSLSocket s = (javax.net.ssl.SSLSocket) s0.accept()) {
                s.setSoTimeout(5000);
                try {
                    s.startHandshake();
                } catch (IOException x) {
                    hello.set(0);
                    return;
                }
                int n = 0;
                byte[] buf = new byte[512];
                try {
                    while (n < 112) {
                        int k = s.getInputStream().read(buf, 0, Math.min(buf.length, 112 - n));
                        if (k < 0) break;
                        n += k;
                    }
                } catch (IOException x) {
                    // the client gave up
                }
                hello.set(n);
            } catch (IOException x) {
                hello.compareAndSet(-1, 0);
            }
        });
        t.setDaemon(true);
        t.start();
        return ss.getLocalPort();
    }

    static X509Certificate serverCert(boolean any) throws Exception {
        Path f = Paths.get(p(any ? "any.ca" : "ca")).getParent().resolve("server.crt");
        try (InputStream in = Files.newInputStream(f)) {
            return (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(in);
        }
    }

    // ---- every type ----

    static void typesRoundTrip(Ep ep, String en) throws Exception {
        String t = "ty_" + en + "_" + tag(), e = "mood_" + en + "_" + tag();
        try (Connection c = ep.open()) {
            c.query("CREATE TYPE " + e + " AS ENUM ('sad', 'ok', 'happy', '', 'é')");
            c.query("CREATE TABLE " + t + " (id BIGINT PRIMARY KEY, i64 BIGINT, i16 SMALLINT, i32 INTEGER, f FLOAT64, b BOOL, x TEXT,"
                    + " v VARCHAR(5), d38 DECIMAL(38,10), d10 DECIMAL(10,2), d0 DECIMAL(38,0), ts TIMESTAMP, tz TIMESTAMPTZ, dt DATE,"
                    + " tm TIME, u UUID, ba BYTEA, iv INTERVAL, en " + e + ")");
            Random rnd = new Random(7);
            byte[] big = new byte[65535];
            rnd.nextBytes(big);
            String longText = "x".repeat(65532) + "é" + "a"; // 65,535 bytes
            BigInteger lim = BigInteger.TEN.pow(38);
            Object[][] rows = {
                {1L, Long.MIN_VALUE, (long) Short.MIN_VALUE, (long) Integer.MIN_VALUE, -Double.MAX_VALUE, false, "", "",
                 new BigDecimal(lim.subtract(BigInteger.ONE).negate(), 10), new BigDecimal("-99999999.99"), new BigDecimal(lim.subtract(BigInteger.ONE).negate()),
                 LocalDateTime.of(1, 1, 1, 0, 0), Instant.parse("0001-01-01T00:00:00Z"), LocalDate.of(1, 1, 1), LocalTime.MIDNIGHT,
                 new UUID(0, 0), new byte[0], new Interval(Integer.MIN_VALUE, Integer.MIN_VALUE, Long.MIN_VALUE), "sad"},
                {2L, Long.MAX_VALUE, (long) Short.MAX_VALUE, (long) Integer.MAX_VALUE, Double.MAX_VALUE, true, longText, "ééééé",
                 new BigDecimal(lim.subtract(BigInteger.ONE), 10), new BigDecimal("99999999.99"), new BigDecimal(lim.subtract(BigInteger.ONE)),
                 LocalDateTime.of(9999, 12, 31, 23, 59, 59, 999999000), Instant.parse("9999-12-31T23:59:59.999999Z"), LocalDate.of(9999, 12, 31),
                 LocalTime.of(23, 59, 59, 999999000), new UUID(-1, -1), big, new Interval(Integer.MAX_VALUE, Integer.MAX_VALUE, Long.MAX_VALUE), "é"},
                {3L, 0L, -1L, 1L, Double.MIN_VALUE, true, "hé€😀", "aé€😀b",
                 new BigDecimal("0.0000000001"), new BigDecimal("0.01"), BigDecimal.ZERO,
                 LocalDateTime.of(1969, 12, 31, 23, 59, 59, 999999000), Instant.parse("1970-01-01T00:00:00.000001Z"), LocalDate.of(1970, 1, 1),
                 LocalTime.of(0, 0, 0, 1000), UUID.fromString("00010203-0405-0607-0809-0a0b0c0d0e0f"), new byte[] {0, (byte) 0xff, 0},
                 new Interval(1, -2, 3), ""},
                {4L, -1L, 0L, 0L, 0.1, false, "line\nbreak \"quoted\", comma", "x", new BigDecimal("-1.5"), new BigDecimal("-0.01"),
                 new BigDecimal("12345678901234567890123456789012345678"), LocalDateTime.of(2026, 11, 19, 20, 30, 0, 123456000),
                 Instant.parse("2026-11-19T20:30:00.654321Z"), LocalDate.of(2026, 11, 19), LocalTime.of(12, 0), UUID.randomUUID(),
                 "bytes".getBytes(), new Interval(0, 0, 0), "happy"},
                {5L, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null},
            };
            try (Prepared ins = c.prepare("tyins_" + en + "_" + tag(), "INSERT INTO " + t + " VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11,"
                                                                        + " $12, $13, $14, $15, $16, $17, $18, $19)")) {
                for (Object[] r : rows) {
                    try {
                        ins.execute(r);
                    } catch (ImagedbException x) {
                        check(false, "row " + r[0] + " refused: " + x.getMessage());
                    }
                }
                // typed NULLs of every column's own type (row 6), through EXECUTE
                ins.execute(6L, Params.nullOf(Type.INT64), Params.nullOf(Type.INT64), Params.nullOf(Type.INT64), Params.nullOf(Type.FLOAT64),
                            Params.nullOf(Type.BOOL), Params.nullOf(Type.TEXT), Params.nullOf(Type.TEXT), Params.nullOf(Type.DECIMAL),
                            Params.nullOf(Type.DECIMAL), Params.nullOf(Type.DECIMAL), Params.nullOf(Type.TIMESTAMP), Params.nullOf(Type.TIMESTAMPTZ),
                            Params.nullOf(Type.DATE), Params.nullOf(Type.TIME), Params.nullOf(Type.UUID), Params.nullOf(Type.BYTEA),
                            Params.nullOf(Type.INTERVAL), Params.nullOf(Type.ENUM));
            }
            // row 3 again by literals (row 13): the parameter binds as its literal
            c.query("INSERT INTO " + t + " VALUES (13, 0, -1, 1, 4.9e-324, true, 'hé€😀', 'aé€😀b', 0.0000000001, 0.01, 0,"
                    + " '1969-12-31 23:59:59.999999', '1970-01-01 00:00:00.000001+00', '1970-01-01', '00:00:00.000001',"
                    + " '00010203-0405-0607-0809-0a0b0c0d0e0f', '\\x00ff00', '1 mon -2 days 3 microseconds', '')");
            Result r = c.query("SELECT * FROM " + t + " ORDER BY id");
            // the columns' metadata
            String[] types = {"INT64", "INT64", "INT64", "INT64", "FLOAT64", "BOOL", "TEXT", "TEXT", "DECIMAL", "DECIMAL", "DECIMAL", "TIMESTAMP",
                              "TIMESTAMPTZ", "DATE", "TIME", "UUID", "BYTEA", "INTERVAL", "ENUM"};
            for (int i = 0; i < types.length; i++) eq(types[i], r.columns().get(i).type().name(), "column " + i + "'s type");
            // a result column's precision as this server sends it (server/conv.c 52: a DECIMAL's scale alone; imdb_result holds
            // no integer width and no VARCHAR length): 0 for every column, though §4 lets it carry 16, 32 and a length
            for (int i : new int[] {2, 3, 7, 8, 9}) eq(0, r.columns().get(i).precision(), "column " + i + "'s precision as sent");
            eq(10, r.columns().get(8).scale(), "DECIMAL(38,10)'s scale");
            eq(2, r.columns().get(9).scale(), "DECIMAL(10,2)'s scale");
            eq(Arrays.asList("sad", "ok", "happy", "", "é"), r.columns().get(18).labels(), "the ENUM's labels in order");
            eq(7, r.size(), "seven rows");
            for (int k = 0; k < 4; k++) {
                Row row = r.row(k);
                Object[] w = rows[k];
                eq(w[0], row.getLong(0), "id");
                eq(w[1], row.getLong(1), "BIGINT " + k);
                eq(w[2], row.getLong("i16"), "SMALLINT " + k);
                eq(w[3], row.getLong("i32"), "INTEGER " + k);
                eq(Double.doubleToRawLongBits((Double) w[4]), Double.doubleToRawLongBits(row.getDouble(4)), "FLOAT64 bit for bit " + k);
                eq(w[5], row.getBoolean(5), "BOOL " + k);
                eq(w[6], row.getString(6), "TEXT " + k);
                eq(w[7], row.getString("v"), "VARCHAR " + k);
                check(((BigDecimal) w[8]).compareTo(row.getBigDecimal(8)) == 0 && row.getBigDecimal(8).scale() == 10, "DECIMAL(38,10) " + k + ": " + row.getBigDecimal(8));
                check(((BigDecimal) w[9]).compareTo(row.getBigDecimal(9)) == 0 && row.getBigDecimal(9).scale() == 2, "DECIMAL(10,2) " + k);
                check(((BigDecimal) w[10]).compareTo(row.getBigDecimal(10)) == 0, "DECIMAL(38,0) " + k + ": " + row.getBigDecimal(10));
                eq(w[11], row.getLocalDateTime(11), "TIMESTAMP " + k);
                eq(w[12], row.getInstant(12), "TIMESTAMPTZ " + k);
                eq(w[13], row.getLocalDate(13), "DATE " + k);
                eq(w[14], row.getLocalTime(14), "TIME " + k);
                eq(w[15], row.getUuid(15), "UUID " + k);
                check(Arrays.equals((byte[]) w[16], row.getBytes(16)), "BYTEA " + k);
                eq(w[17], row.getInterval(17), "INTERVAL " + k);
                eq(w[18], row.getString(18), "ENUM " + k);
                eq(Wire.T_ENUM, row.value(18).type, "an ENUM value " + k);
            }
            for (int k = 4; k < 6; k++) {
                Row row = r.row(k);
                for (int i = 1; i < row.size(); i++) {
                    check(row.isNull(i), "row " + (k + 1) + " column " + i + " NULL");
                    eq(r.columns().get(i).type().code, row.value(i).type, "a NULL tagged with its column's type, column " + i);
                    check(row.getObject(i) == null, "getObject NULL");
                }
                throwsIt(IllegalStateException.class, () -> row.getLong(1), "getLong of a NULL");
            }
            Row lit = r.row(6), par = r.row(2);
            for (int i = 1; i < 19; i++) {
                check(lit.value(i).equals(par.value(i)), "column " + i + ": the parameter stored what the literal stores: " + lit.value(i) + " / " + par.value(i));
            }
            // getters asked for another type refuse
            throwsIt(IllegalStateException.class, () -> r.row(0).getDouble(1), "a BIGINT as a double");
            throwsIt(IllegalStateException.class, () -> r.row(0).getString(1), "a BIGINT as a string");
            // the server's refusals of values out of a column's range (the driver sends them: the server decides)
            ImagedbException over = fails(() -> c.query("INSERT INTO " + t + " (id, i16) VALUES (20, $1)", 32768L), "SMALLINT 32768");
            check(over != null && over.fromServer(), "32768 into SMALLINT refused by the server: " + over);
            ImagedbException vc = fails(() -> c.query("INSERT INTO " + t + " (id, v) VALUES (21, $1)", "abcdef"), "VARCHAR(5) of 6");
            check(vc != null && vc.fromServer(), "a VARCHAR(5) of 6 refused: " + vc);
            ImagedbException en1 = fails(() -> c.query("INSERT INTO " + t + " (id, en) VALUES (22, $1)", "nope"), "an unknown label");
            check(en1 != null && en1.fromServer(), "an unknown label refused: " + en1);
            // values the driver refuses before sending
            for (Object bad : new Object[] {Double.NaN, Double.POSITIVE_INFINITY, LocalDateTime.of(2026, 1, 1, 0, 0, 0, 1),
                                            new BigDecimal("1e-39"), "a\0b", new Object()}) {
                ImagedbException x = fails(() -> c.query("SELECT $1", bad), "refused locally: " + bad);
                check(x != null && !x.fromServer(), "the driver's own refusal: " + x);
            }
            Result neg0 = c.query("SELECT $1", -0.0);
            eq(0L, Double.doubleToRawLongBits(neg0.row(0).getDouble(0)), "-0.0 sent as the engine's one zero");
            throwsIt(IllegalArgumentException.class, () -> c.query("SELECT $1", (Object[]) null), "a null parameter array");
            ImagedbException untyped = fails(() -> c.query("SELECT $1", (Object) null), "a NULL of no type where a type is wanted");
            check(untyped != null && untyped.fromServer() && untyped.kind() == ImagedbException.Kind.INVALID, "refused by the engine (§4): " + untyped);
            Result typed = c.query("SELECT $1", Params.nullOf(Type.INT64));
            check(typed.row(0).isNull(0) && typed.row(0).value(0).type == Wire.T_INT64, "a typed NULL keeps its type: " + typed.row(0));
        }
    }

    // ---- transactions ----

    static void transaction() throws Exception {
        String t = "tx_" + tag();
        try (Connection c = tcp(); Connection d = sock()) {
            c.query("CREATE TABLE " + t + " (id BIGINT PRIMARY KEY, v BIGINT)");
            Result ins = c.query("INSERT INTO " + t + " VALUES (1, 10)");
            check(ins.writeCommit() >= 1, "an autocommit write has its commit");
            c.query("BEGIN");
            eq(Connection.TxState.IN_TRANSACTION, c.state(), "BEGIN: READY in a transaction");
            Result w = c.query("INSERT INTO " + t + " VALUES (2, 20)");
            eq(0L, w.writeCommit(), "a write inside a transaction has no commit yet");
            ImagedbException dup = fails(() -> c.query("INSERT INTO " + t + " VALUES (1, 99)"), "a duplicate inside");
            check(dup != null && dup.fromServer(), "refused: " + dup);
            eq(Connection.TxState.IN_TRANSACTION, c.state(), "statement-level rollback: the transaction goes on");
            Result own = c.query("SELECT COUNT(*) FROM " + t);
            eq(2L, own.row(0).getLong(0), "it sees its own write");
            check(own.readPoint() != null && own.readPoint().own, "the read point says own writes");
            eq(1L, d.query("SELECT COUNT(*) FROM " + t).row(0).getLong(0), "another session does not see it");
            Result com = c.query("COMMIT");
            eq(Connection.TxState.IDLE, c.state(), "COMMIT: idle");
            check(com.writeCommit() >= 1, "COMMIT's DONE carries the commit: " + com.writeCommit());
            Result after = d.query("SELECT COUNT(*) FROM " + t);
            eq(2L, after.row(0).getLong(0), "committed");
            eq(com.writeCommit(), after.readPoint().commit, "the other session reads at that commit");
            check(Arrays.equals(after.readPoint().dbId, own.readPoint().dbId) && after.readPoint().dbId.length == 16, "one database's id");
            // a batch stops at its ERROR: its COMMIT never runs, READY says the transaction is open
            BatchException x = throwsIt(BatchException.class, () -> c.batch(Arrays.asList(Statement.of("BEGIN"),
                    Statement.of("INSERT INTO " + t + " VALUES (3, 30)"), Statement.of("INSERT INTO " + t + " VALUES (1, 0)"),
                    Statement.of("COMMIT"))), "BEGIN, INSERT, a failure, COMMIT as one batch");
            if (x != null) eq(2, x.index(), "the failing INSERT");
            eq(Connection.TxState.IN_TRANSACTION, c.state(), "the transaction still open");
            c.query("ROLLBACK");
            eq(Connection.TxState.IDLE, c.state(), "ROLLBACK: idle");
            eq(2L, d.query("SELECT COUNT(*) FROM " + t).row(0).getLong(0), "the rolled-back row never committed");
            // a doomed transaction: a write, then another session's ALTER of the table
            c.query("BEGIN");
            c.query("INSERT INTO " + t + " VALUES (4, 40)");
            d.query("ALTER TABLE " + t + " ADD COLUMN z BIGINT");
            ImagedbException doom = null;
            try {
                c.query("SELECT COUNT(*) FROM " + t);
            } catch (ImagedbException e) {
                doom = e;
            }
            note("after another session's ALTER: " + (doom == null ? "answered" : doom.code() + " " + doom.getMessage()) + "; state " + c.state());
            eq(Connection.TxState.DOOMED, c.state(), "READY 2: doomed");
            ImagedbException only = fails(() -> c.query("SELECT 1"), "a doomed transaction takes only ROLLBACK");
            check(only != null && only.fromServer(), "refused: " + only);
            c.query("ROLLBACK");
            eq(Connection.TxState.IDLE, c.state(), "ROLLBACK ends it");
        }
    }

    // ---- cancel ----

    static void cancel() throws Exception {
        for (int k = 0; k < 2; k++) {
            try (Connection c = ep(k).open()) {
                AtomicReference<Object> out = new AtomicReference<>();
                Thread q = new Thread(() -> {
                    try {
                        out.set(c.query("SELECT COUNT(*) FROM big AS a JOIN big AS b ON a.x < b.x"));
                    } catch (ImagedbException x) {
                        out.set(x);
                    }
                });
                long t0 = System.nanoTime();
                q.start();
                int sent = 0;
                while (q.isAlive() && System.nanoTime() - t0 < 60_000_000_000L) { // a CANCEL before the statement runs does nothing: again
                    Thread.sleep(sent == 0 ? 300 : 200);
                    c.cancel();
                    sent++;
                }
                q.join(5000);
                long ms = (System.nanoTime() - t0) / 1_000_000;
                Object o = out.get();
                check(o instanceof ImagedbException && ((ImagedbException) o).kind() == ImagedbException.Kind.CANCELLED,
                      EP_NAMES[k] + ": the statement ended by ERROR 15: " + o);
                note(EP_NAMES[k] + ": cancelled after " + ms + " ms, " + sent + " cancel() calls: " + (o instanceof Exception ? ((Exception) o).getMessage() : o));
                eq(Connection.TxState.IDLE, c.state(), "idle after");
                eq(5L, c.query("SELECT 5").row(0).getLong(0), "the connection goes on");
                c.cancel(); // nothing outstanding: dropped
                eq(1000000L, c.query("SELECT COUNT(*) FROM big").row(0).getLong(0), "the next statement runs uncancelled");
            }
        }
        // a transaction's statement cancelled: the transaction goes on (nothing the statement did stays)
        try (Connection c = sock()) {
            c.query("BEGIN");
            Thread q = new Thread(() -> {
                try {
                    c.query("SELECT COUNT(*) FROM big AS a JOIN big AS b ON a.x < b.x");
                } catch (ImagedbException x) {
                    // expected
                }
            });
            q.start();
            long t0 = System.nanoTime();
            while (q.isAlive() && System.nanoTime() - t0 < 60_000_000_000L) {
                Thread.sleep(200);
                c.cancel();
            }
            q.join(5000);
            note("in a transaction, after the cancel: " + c.state());
            check(c.state() != Connection.TxState.IDLE, "still in the transaction (or doomed), not ended");
            c.query("ROLLBACK");
        }
    }

    // ---- COPY ----

    static void copy(Ep ep, String en) throws Exception {
        String t = "cp_" + en + "_" + tag();
        try (Connection c = ep.open()) {
            c.query("CREATE TABLE " + t + " (id BIGINT PRIMARY KEY, s TEXT, d DECIMAL(12,3))");
            StringBuilder sb = new StringBuilder();
            for (int i = 1; i <= 100000; i++) sb.append(i).append(",\"row ").append(i).append(", é\"").append(',').append(i % 1000).append(".5\n");
            byte[] data = sb.toString().getBytes(StandardCharsets.UTF_8);
            check(data.length > 2 * Wire.COPY_PIECE, "the data spans several COPY_DATA frames: " + data.length + " bytes");
            Result in = c.copyIn("COPY " + t + " FROM STDIN", new ByteArrayInputStream(data));
            eq(100000L, in.count(), "COPY 100,000: its DONE's count");
            note("COPY FROM: " + in.status());
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            Result o = c.copyOut("COPY (SELECT id, s, d FROM " + t + " ORDER BY id) TO STDOUT", out);
            note("COPY TO: " + o.status() + ", " + out.size() + " bytes");
            String back = out.toString(StandardCharsets.UTF_8);
            eq("1,\"row 1, é\",1.500", back.substring(0, back.indexOf('\n')), "the first line back");
            eq(100000, back.split("\n", -1).length - 1, "100,000 lines back");
            // COPY TO through query(): the bytes in the result
            Result q = c.query("COPY (SELECT id FROM " + t + " WHERE id <= 3 ORDER BY id) TO STDOUT");
            eq("1\n2\n3\n", new String(q.copyData(), StandardCharsets.UTF_8), "query() keeps a COPY TO's bytes");
            // a bad field on line 3: its ERROR after the data, the table unchanged
            String t2 = t + "b";
            c.query("CREATE TABLE " + t2 + " (id BIGINT PRIMARY KEY, s TEXT)");
            ImagedbException bad = fails(() -> c.copyIn("COPY " + t2 + " FROM STDIN", "1,a\n2,b\nx,c\n".getBytes()), "a bad field");
            check(bad != null && bad.fromServer(), "refused after the data: " + bad);
            eq(0L, c.query("SELECT COUNT(*) FROM " + t2).row(0).getLong(0), "nothing stays");
            // the client's input fails: COPY_FAIL, the statement refused unrun
            InputStream failing = new InputStream() {
                int n;

                @Override
                public int read() throws IOException {
                    if (n++ < 10) return '1';
                    throw new IOException("the disk went away");
                }
            };
            ImagedbException cf = fails(() -> c.copyIn("COPY " + t2 + " FROM STDIN", failing), "COPY_FAIL");
            check(cf != null && cf.kind() == ImagedbException.Kind.CANCELLED && cf.getMessage().contains("the disk went away"),
                  "COPY_FAIL's reason in its ERROR 15: " + cf);
            // refused before its data: no COPY_IN, nothing sent
            ImagedbException nt = fails(() -> c.copyIn("COPY no_such_table_" + tag() + " FROM STDIN", "1\n".getBytes()), "no such table");
            check(nt != null && nt.fromServer(), "answered without COPY_IN: " + nt);
            // COPY FROM through query(): failed at once (no data), the connection in step
            ImagedbException qi = fails(() -> c.query("COPY " + t2 + " FROM STDIN"), "COPY FROM via query()");
            check(qi != null && qi.kind() == ImagedbException.Kind.STATE, "refused: " + qi);
            eq(7L, c.query("SELECT 7").row(0).getLong(0), "the connection goes on");
            // an output stream that fails: the statement cancelled, the connection goes on
            OutputStream broken = new OutputStream() {
                @Override
                public void write(int b) throws IOException { throw new IOException("the reader went away"); }

                @Override
                public void write(byte[] b, int off, int len) throws IOException { throw new IOException("the reader went away"); }
            };
            ImagedbException ob = fails(() -> c.copyOut("COPY (SELECT id, x FROM big) TO STDOUT", broken), "a failing output");
            check(ob != null && !ob.fromServer() && ob.getMessage().contains("the reader went away"), "the output's failure: " + ob);
            eq(8L, c.query("SELECT 8").row(0).getLong(0), "the connection goes on after");
            eq(Connection.TxState.IDLE, c.state(), "idle");
        }
    }

    // ---- SESSIONS and KILL ----

    /** the error came from a write that failed (closed_reason's path), not from a read meeting the close */
    static boolean sendFailed(Throwable x) {
        for (Throwable c = x; c != null; c = c.getCause())
            if (c instanceof IOException && !(c instanceof imagedb.wire.WireException)) return true;
        return false;
    }

    static long newest(List<Msg.Session> ss) {
        long id = 0;
        for (Msg.Session s : ss) id = Math.max(id, s.id);
        return id;
    }

    static void sessionsKill() throws Exception {
        try (Connection op = sock()) {
            long me = newest(op.sessions()); // the operator's own: the newest accept
            // a victim on the socket, terminated; its next request right away (inside the server's lingering close)
            Connection v1 = sock();
            v1.query("BEGIN");
            List<Msg.Session> ss = op.sessions();
            long vid = newest(ss);
            check(vid > me, "the victim listed after the operator");
            Msg.Session vs = null;
            for (Msg.Session s : ss)
                if (s.id == vid) vs = s;
            check(vs != null && vs.endpoint == 2 && vs.state == Wire.SS_IN_TXN && vs.name.equals(USER), "the victim: socket, in a transaction, admin: " + vs);
            for (int i = 1; i < ss.size(); i++) check(Long.compareUnsigned(ss.get(i - 1).id, ss.get(i).id) < 0, "ids increasing");
            check(op.kill(vid, Connection.Kill.TERMINATE), "KILL terminate: done");
            ImagedbException a = fails(() -> v1.query("SELECT 1"), "the victim's next request");
            check(a != null && a.code() == 15 && a.getMessage().contains("ended by a KILL"), "the victim learns why (code 15, the words): " + a);
            note("victim, at once: " + a.getMessage() + " [" + (a != null && sendFailed(a) ? "a failed send" : "read as a reply") + "]");
            Connection v6 = sock(); // a victim whose next call is a PING
            long v6id = newest(op.sessions());
            check(op.kill(v6id, Connection.Kill.TERMINATE), "KILL terminate v6");
            ImagedbException a6 = fails(v6::ping, "the victim's PING");
            check(a6 != null && a6.code() == 15 && a6.getMessage().contains("ended by a KILL"), "ping() learns why too: " + a6);
            // a second victim: its next request after the lingering close (1 s): the send fails, closed_reason reads the ERROR
            Connection v2 = sock();
            long v2id = newest(op.sessions());
            check(op.kill(v2id, Connection.Kill.TERMINATE), "KILL terminate v2");
            Thread.sleep(3000); // past the server's lingering close (1 s at most)
            ImagedbException b = fails(() -> v2.query("SELECT 1"), "the send after the close");
            check(b != null && b.code() == 15 && b.getMessage().contains("ended by a KILL") && b.getMessage().contains("closed the connection"),
                  "a failed send reports the server's last ERROR: " + b);
            check(b != null && sendFailed(b), "the failed send itself (closed_reason): an I/O error from the write under it");
            note("victim, after the linger: " + b.getMessage() + " [" + (b != null && sendFailed(b) ? "a failed send" : "read as a reply") + "]");
            // over TCP: the words read as a reply (a first write after the close taken by the kernel)
            Connection v3 = tcp();
            long v3id = newest(op.sessions());
            check(op.kill(v3id, Connection.Kill.TERMINATE), "KILL terminate a TCP session");
            Thread.sleep(3000);
            ImagedbException c3 = fails(() -> v3.query("SELECT 1"), "the TCP victim");
            check(c3 != null && c3.code() == 15 && c3.getMessage().contains("ended by a KILL"), "over TCP, code 15 and the words: " + c3);
            note("TCP victim: " + c3.getMessage() + " [" + (c3 != null && sendFailed(c3) ? "a failed send" : "read as a reply") + "]");
            // KILL cancel: a long statement of another session
            try (Connection v4 = tcp()) {
                long v4id = newest(op.sessions());
                AtomicReference<Object> out = new AtomicReference<>();
                Thread q = new Thread(() -> {
                    try {
                        out.set(v4.query("SELECT COUNT(*) FROM big AS a JOIN big AS b ON a.x < b.x"));
                    } catch (ImagedbException x) {
                        out.set(x);
                    }
                });
                q.start();
                boolean running = false; // the victim's request seen running (state 1) before the KILL: no race with its arrival
                for (int i = 0; i < 600 && !running; i++) {
                    for (Msg.Session s : op.sessions()) running |= s.id == v4id && s.state == Wire.SS_RUNNING;
                    if (!running) Thread.sleep(50);
                }
                check(running, "the victim's statement seen running in SESSIONS (state 1)");
                check(op.kill(v4id, Connection.Kill.CANCEL), "KILL cancel: done");
                q.join(60000);
                check(!q.isAlive() && out.get() instanceof ImagedbException && ((ImagedbException) out.get()).code() == 15,
                      "the statement cancelled by the KILL: " + out.get());
                eq(9L, v4.query("SELECT 9").row(0).getLong(0), "its session goes on");
            }
            check(!op.kill(Long.MAX_VALUE, Connection.Kill.CANCEL), "no such session: KILL_DONE 1");
            check(!op.kill(vid, Connection.Kill.TERMINATE), "an ended session: none");
            // a protocol error the server closes on (COPY data with no COPY running): the send after its close names it
            Connection v5 = sock();
            v5.wire().sendCopyData(new byte[] {'x'}, 0, 1);
            Thread.sleep(3000);
            ImagedbException e5 = fails(() -> v5.query("SELECT 1"), "a send after the server closed for a protocol error");
            check(e5 != null && e5.code() == Wire.E_STATE && e5.getMessage().contains("no COPY running"), "the server's words: " + e5);
            check(e5 != null && sendFailed(e5), "the failed send itself (closed_reason)");
            note("after a protocol error: " + e5.getMessage() + " [" + (e5 != null && sendFailed(e5) ? "a failed send" : "read as a reply") + "]");
        }
    }

    // ---- after `cert --renew` and a restart: the pin survives (the key kept), the certificate is new ----

    public static void renewed() {
        run("live_pin_after_renew (the pin is the key's: it survives cert --renew)", () -> {
            Imagedb.Options o = tcpOpts(mainIsAny(), true);
            try (Connection c = Imagedb.connect(o)) {
                c.ping();
                eq(1L, c.query("SELECT 1").row(0).getLong(0), "the old pin logs in after the renewal");
            }
            try (Connection c = Imagedb.connect(tcpOpts(mainIsAny(), false))) {
                c.ping(); // the same CA
            }
            X509Certificate now = serverCert(mainIsAny()), old;
            try (InputStream in = Files.newInputStream(Paths.get(p(mainIsAny() ? "any.oldcert" : "oldcert")))) {
                old = (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(in);
            }
            check(!old.getSerialNumber().equals(now.getSerialNumber()), "a new certificate (serial " + old.getSerialNumber().toString(16) + " -> " + now.getSerialNumber().toString(16) + ")");
            eq(Der.hex(Der.spki(old.getEncoded())), Der.hex(Der.spki(now.getEncoded())), "the same key");
            eq(p(mainIsAny() ? "any.pin" : "pin"), Der.hex(Der.sha256(Der.spki(now.getEncoded()))), "its SPKI hash is the pin still");
        });
    }
}
