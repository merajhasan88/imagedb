package imagedb.wire;

import static imagedb.test.T.check;
import static imagedb.test.T.eq;
import static imagedb.test.T.run;
import static imagedb.test.T.throwsIt;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

/**
 * The connection's own logic against a scripted peer (what a live server cannot be made to do): the pinned SCRAM
 * exchanges through the real login, a server signature off by one bit, the verdicts, a later version, a frame the
 * decoder refuses, closed_reason's sequences, the cancel rules.
 */
public final class ScriptedTests {
    private ScriptedTests() {}

    interface Server {
        byte[] onWrite(byte[] written) throws IOException; // bytes the peer sends back
    }

    /** a peer whose replies the script gives; reads past them see the close */
    public static final class Fake implements Transport {
        final int endpoint, cbType;
        final byte[] binding;
        final ByteArrayOutputStream in = new ByteArrayOutputStream();
        int pos;
        public final List<byte[]> writes = Collections.synchronizedList(new ArrayList<>());
        Server server = w -> new byte[0];
        volatile IOException failWrites;
        volatile CountDownLatch blockAt, released;
        volatile int blockIndex = -1;
        boolean closed;

        Fake(int endpoint, int cbType, byte[] binding) {
            this.endpoint = endpoint;
            this.cbType = cbType;
            this.binding = binding;
        }

        public synchronized void give(byte[] b) { in.write(b, 0, b.length); }

        @Override
        public void write(byte[] b, int off, int len) throws IOException {
            int idx;
            synchronized (this) {
                idx = writes.size();
            }
            if (idx == blockIndex) { // the nth write held until released: a send under way
                blockAt.countDown();
                try {
                    released.await(10, TimeUnit.SECONDS);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            }
            if (failWrites != null) throw failWrites;
            byte[] w = Arrays.copyOfRange(b, off, off + len);
            writes.add(w);
            byte[] reply = server.onWrite(w);
            give(reply);
        }

        @Override
        public synchronized int read(byte[] b, int off, int len, int timeoutMs) {
            byte[] all = in.toByteArray();
            if (pos >= all.length) return -1;
            int k = Math.min(len, all.length - pos);
            System.arraycopy(all, pos, b, off, k);
            pos += k;
            return k;
        }

        @Override
        public int endpoint() { return endpoint; }

        @Override
        public int bindingType() { return cbType; }

        @Override
        public byte[] binding() { return binding.clone(); }

        @Override
        public String bindingName() { return "scripted"; }

        @Override
        public void close() { closed = true; }
    }

    static byte[] fill(int b) {
        byte[] x = new byte[32];
        Arrays.fill(x, (byte) b);
        return x;
    }

    public static byte[] frame(int type, String hexBody) {
        byte[] body = Der.unhex(hexBody);
        byte[] f = new byte[5 + body.length];
        Buf.le32(f, 0, body.length + 1);
        f[4] = (byte) type;
        System.arraycopy(body, 0, f, 5, body.length);
        return f;
    }

    public static byte[] cat(byte[]... parts) {
        ByteArrayOutputStream o = new ByteArrayOutputStream();
        for (byte[] p : parts) o.write(p, 0, p.length);
        return o.toByteArray();
    }

    static final byte[] CHALLENGE = CodecTests.challengeOf(fillN(16, 3), 4096, fill(2));

    static byte[] fillN(int n, int b) {
        byte[] x = new byte[n];
        Arrays.fill(x, (byte) b);
        return x;
    }

    /** a peer that plays §4's pinned exchange: it checks the hello and the proof, then sends verdict code with sig */
    static Fake pinnedPeer(int ep, int flags, int bind, String proof, int code, byte[] sig) {
        Fake f = new Fake(ep, flags, fill(bind));
        f.server = new Server() {
            int n;

            @Override
            public byte[] onWrite(byte[] w) throws IOException {
                if (n >= 2) return new byte[0]; // past the login: the script gives its own frames
                if (n++ == 0) {
                    check(Arrays.equals(w, PreAuth.hello(flags, "alice".getBytes(), fill(1))), "the hello's bytes (flags " + flags + ")");
                    return CHALLENGE;
                }
                eq(proof, Der.hex(w), "the ClientProof the driver sent (flags " + flags + ")");
                byte[] v = new byte[36];
                Buf.le32(v, 0, code);
                System.arraycopy(sig, 0, v, 4, 32);
                return v;
            }
        };
        return f;
    }

    static final String[][] PINNED = {
        {"1", "1", "4", "28562c1bef99b0a917ecb28c1b32c22930f154f92c134b13fee7a64e8deb733e",
         "5d3ef834c39e6c429d1f4e27993ba451a8b8e35322af9055abc1dd40e88ad322"},
        {"1", "2", "5", "1065f5e038b75f2671d831f5bd5d29f56d22a787f260db523bb986ef7c53f486",
         "28fef60553090aae9b5f184bfc0cfb455e58261131da359f525a59f4dfaa9904"},
        {"2", "0", "0", "5ee7e7bd402f0c91e2399a84c3d544763bace50b44ea82a780e57130bb5405a7",
         "82c9d498cc5fa830d26b29740244ecf4f343962f302a647150e9d74ea7588027"},
    };

    public static WireConnection loggedIn(Fake f) throws IOException {
        return WireConnection.login(f, "alice", "pencil".toCharArray(), fill(1), 1000);
    }

    /** a peer already past the login: the pinned socket exchange, then whatever the script adds */
    public static Fake afterLogin() {
        String[] p = PINNED[2];
        return pinnedPeer(2, 0, 0, p[3], 0, Der.unhex(p[4]));
    }

    public static void all() {
        run("scripted_login_pinned (the three exchanges of §4 through the real login, byte for byte)", () -> {
            for (String[] p : PINNED) {
                Fake f = pinnedPeer(Integer.parseInt(p[0]), Integer.parseInt(p[1]), Integer.parseInt(p[2]), p[3], 0, Der.unhex(p[4]));
                WireConnection c = loggedIn(f);
                check(!c.isBroken() && !f.closed, "logged in, flags " + p[1]);
            }
        });

        run("scripted_login_server_signature (a server that does not prove it holds the verifier)", () -> {
            for (int bit = 0; bit < 256; bit += 37) {
                byte[] sig = Der.unhex(PINNED[0][4]);
                sig[bit / 8] ^= (byte) (1 << (bit % 8));
                Fake f = pinnedPeer(1, 1, 4, PINNED[0][3], 0, sig);
                WireException x = throwsIt(WireException.class, () -> loggedIn(f), "signature bit " + bit);
                check(x != null && x.code() == Wire.E_AUTH && x.getMessage().contains("did not prove"), "refused as AUTH: " + x);
                check(f.closed, "the transport closed");
            }
        });

        run("scripted_login_verdicts (1 refused, 2 the binding type refused: never retried)", () -> {
            Fake f1 = pinnedPeer(1, 1, 4, PINNED[0][3], 1, new byte[32]);
            WireException x1 = throwsIt(WireException.class, () -> loggedIn(f1), "verdict 1");
            check(x1 != null && x1.code() == Wire.E_AUTH && x1.getMessage().contains("refused"), "verdict 1: " + x1);
            Fake f2 = pinnedPeer(1, 2, 5, PINNED[1][3], 2, new byte[32]);
            WireException x2 = throwsIt(WireException.class, () -> loggedIn(f2), "verdict 2");
            check(x2 != null && x2.code() == Wire.E_AUTH && x2.getMessage().contains("channel binding type"), "verdict 2: " + x2);
            eq(2, f2.writes.size(), "after verdict 2 nothing more sent (no retry with another type)");
            Fake f3 = pinnedPeer(1, 1, 4, PINNED[0][3], 1, fill(9)); // a refusal carrying a signature: damage
            WireException x3 = throwsIt(WireException.class, () -> loggedIn(f3), "a refusal with a signature");
            check(x3 != null && x3.code() == Wire.E_CORRUPT, "as damage: " + x3);
        });

        run("scripted_login_versions (a later version's head, a later magic, a cut challenge)", () -> {
            Fake f = new Fake(2, 0, new byte[32]);
            f.server = w -> cat("IMDBWIR1".getBytes(), new byte[] {2, 0, 0, 0}); // its own head, then the close
            WireException x = throwsIt(WireException.class, () -> loggedIn(f), "version 2");
            check(x != null && x.code() == Wire.E_UNSUPPORTED && x.getMessage().contains("version 2"), "UNSUPPORTED by name: " + x);
            Fake g = new Fake(2, 0, new byte[32]);
            g.server = w -> cat("IMDBWIR2".getBytes(), new byte[] {1, 0, 0, 0});
            WireException y = throwsIt(WireException.class, () -> loggedIn(g), "IMDBWIR2");
            check(y != null && y.code() == Wire.E_UNSUPPORTED && y.getMessage().contains("IMDBWIR2"), "a later magic by name: " + y);
            Fake h = new Fake(2, 0, new byte[32]);
            h.server = w -> Arrays.copyOf(CHALLENGE, 50);
            WireException z = throwsIt(WireException.class, () -> loggedIn(h), "a cut challenge");
            check(z != null && z.code() == Wire.E_IO, "a cut challenge is the connection's close: " + z);
        });

        run("scripted_refused_frame (a frame the decoder refuses ends the connection, naming it)", () -> {
            Fake f = afterLogin();
            WireConnection c = loggedIn(f);
            f.give(frame(Wire.READY, "03"));
            WireException x = throwsIt(WireException.class, c::next, "READY 3");
            check(x != null && x.code() == Wire.E_CORRUPT && x.getMessage().contains("a frame refused, the connection closed")
                  && x.getMessage().contains("READY"), "named: " + x);
            check(c.isBroken() && f.closed, "the connection closed");
            WireException y = throwsIt(WireException.class, c::sendPing, "a later send");
            check(y != null && y.code() == Wire.E_CORRUPT, "a later call fails fast with the reason: " + y);
            Fake g = afterLogin();
            WireConnection d = loggedIn(g);
            g.give(frame(Wire.ROWS, "01000000 81")); // no COLUMNS before it
            WireException z = throwsIt(WireException.class, d::next, "ROWS without COLUMNS");
            check(z != null && z.getMessage().contains("no COLUMNS"), "named: " + z);
            Fake h = afterLogin();
            WireConnection e = loggedIn(h);
            h.give(new byte[] {0, 0, 0, 2, 64}); // a length past 16 MiB
            WireException w = throwsIt(WireException.class, e::next, "a frame of 32 MiB");
            check(w != null && w.code() == Wire.E_LIMIT, "LIMIT before anything is allocated: " + w);
            Fake k = afterLogin();
            WireConnection kc = loggedIn(k);
            k.give(frame(Wire.QUERY, "")); // a client's type from the server
            WireException kx = throwsIt(WireException.class, kc::next, "a client frame type from the server");
            check(kx != null && kx.code() == Wire.E_CORRUPT, "refused: " + kx);
        });

        run("scripted_closed_reason (a send that finds the close reports the server's last ERROR)", () -> {
            byte[] err = frame(Wire.ERROR, "0f000000 00000000 1000 " + Der.hex("ended by a KILL!".getBytes()));
            Fake f = afterLogin();
            WireConnection c = loggedIn(f);
            f.give(err);
            f.failWrites = new IOException("Broken pipe");
            WireException x = throwsIt(WireException.class, () -> c.sendQuery(Collections.singletonList(new Frames.Stmt("SELECT 1", null))), "the send");
            check(x != null && x.code() == 15 && x.getMessage().contains("ended by a KILL!") && x.getMessage().contains("closed the connection"),
                  "ERROR then the close: its code and words: " + x);
            Fake g = afterLogin(); // an ERROR followed by another frame answered something else: no reason then
            WireConnection d = loggedIn(g);
            g.give(cat(err, frame(Wire.READY, "00")));
            g.failWrites = new IOException("Broken pipe");
            WireException y = throwsIt(WireException.class, d::sendPing, "the send");
            check(y != null && y.code() == Wire.E_IO && y.getMessage().contains("Broken pipe"), "the plain I/O error: " + y);
            Fake h = afterLogin(); // nothing sent before the close
            WireConnection e = loggedIn(h);
            h.failWrites = new IOException("Broken pipe");
            WireException z = throwsIt(WireException.class, e::sendPing, "the send");
            check(z != null && z.code() == Wire.E_IO, "the plain I/O error: " + z);
            Fake k = afterLogin(); // the read path: an ERROR then the close
            WireConnection kc = loggedIn(k);
            k.give(err);
            Msg m = kc.next();
            check(m instanceof Msg.Error && ((Msg.Error) m).code == 15, "the ERROR read as a reply");
            WireException kx = throwsIt(WireException.class, kc::next, "the close");
            check(kx != null && kx.code() == 15 && kx.getMessage().contains("ended by a KILL!"), "the read meeting the close names it: " + kx);
        });

        run("scripted_cancel_rules (dropped with nothing outstanding; sent after the frame under way, before the next)", () -> {
            Fake f = afterLogin();
            WireConnection c = loggedIn(f);
            int base = f.writes.size();
            c.cancel(); // nothing outstanding: dropped
            eq(base, f.writes.size(), "a cancel with nothing outstanding sends nothing");
            c.sendQuery(Collections.singletonList(new Frames.Stmt("SELECT 1", null)));
            c.sendQuery(Collections.singletonList(new Frames.Stmt("SELECT 2", null))); // the earlier cancel never reaches it
            eq(base + 2, f.writes.size(), "two requests, no CANCEL");
            eq(2, c.outstanding(), "two outstanding");
            c.cancel();
            eq(base + 3, f.writes.size(), "a cancel with a request outstanding is sent at once");
            check(Arrays.equals(f.writes.get(base + 2), Frames.empty(Wire.CANCEL)), "the CANCEL frame");
            f.give(cat(frame(Wire.READY, "00"), frame(Wire.READY, "00")));
            c.next();
            c.next();
            eq(0, c.outstanding(), "each READY ends one");
            c.cancel();
            eq(base + 3, f.writes.size(), "after the READYs: dropped");
            // a cancel asked while a COPY's data frame is being sent: after that frame, before the next
            c.sendQuery(Collections.singletonList(new Frames.Stmt("COPY t FROM STDIN", null)));
            int q = f.writes.size();
            f.blockAt = new CountDownLatch(1);
            f.released = new CountDownLatch(1);
            f.blockIndex = q; // the COPY_DATA's write
            Thread sender = new Thread(() -> {
                try {
                    c.sendCopyData(new byte[] {'1', '\n'}, 0, 2);
                    c.sendCopyDone();
                } catch (IOException e) {
                    check(false, "the sender: " + e);
                }
            });
            sender.start();
            check(f.blockAt.await(5, TimeUnit.SECONDS), "the data frame under way");
            long t0 = System.nanoTime();
            c.cancel(); // must not wait for the send
            check(System.nanoTime() - t0 < 2_000_000_000L, "cancel() returned while a frame was being sent");
            f.released.countDown();
            sender.join(5000);
            List<Integer> types = new ArrayList<>();
            for (int i = q; i < f.writes.size(); i++) types.add(f.writes.get(i)[4] & 0xff);
            eq(Arrays.asList(Wire.COPY_DATA, Wire.CANCEL, Wire.COPY_DONE), types, "COPY_DATA, then the CANCEL, then COPY_DONE");
        });
    }
}
