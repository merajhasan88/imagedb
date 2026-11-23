package imagedb.wire;

import java.io.IOException;
import java.security.MessageDigest;
import java.security.SecureRandom;

/**
 * The pre-auth exchange (§4, client.c authenticate): the hello (naming the binding's type), the challenge, the proof
 * over the AuthMessage (the binding's 32 bytes in it), the verdict and the server's signature, checked: a server that
 * does not prove it holds the verifier is refused like a wrong password. A verdict 2 (the binding type refused) is
 * never retried with another type (no downgrade, §8f).
 */
public final class Login {
    private Login() {}

    private static final SecureRandom RNG = new SecureRandom();

    static void readFully(Transport t, byte[] b, int timeoutMs) throws IOException {
        int got = 0;
        while (got < b.length) {
            int k = t.read(b, got, b.length - got, timeoutMs);
            if (k < 0) throw new WireException(Wire.E_IO, "the connection: closed by the server");
            got += k;
        }
    }

    /** the login over t (each wait bounded by timeoutMs, 0 none); nonce null: 32 random bytes */
    public static void authenticate(Transport t, String user, char[] pw, byte[] nonce, int timeoutMs) throws IOException {
        byte[] ub = PreAuth.userBytes(user);
        PreAuth.checkPassword(pw);
        if (nonce == null) {
            nonce = new byte[Wire.NONCE];
            RNG.nextBytes(nonce);
        }
        byte[] binding = t.binding();
        byte[] hello = PreAuth.hello(t.bindingType(), ub, nonce);
        t.write(hello, 0, hello.length);
        byte[] ch = new byte[Wire.CHALLENGE_LEN];
        byte[] head = new byte[Wire.PREAUTH_HEAD];
        readFully(t, head, timeoutMs);
        long version = PreAuth.head(head);
        if (version != Wire.VERSION)
            throw new WireException(Wire.E_UNSUPPORTED, "the server speaks IMDBWIR1 version " + version + ", not 1");
        System.arraycopy(head, 0, ch, 0, head.length);
        byte[] rest = new byte[Wire.CHALLENGE_LEN - Wire.PREAUTH_HEAD];
        readFully(t, rest, timeoutMs);
        System.arraycopy(rest, 0, ch, Wire.PREAUTH_HEAD, rest.length);
        PreAuth.Challenge c = PreAuth.challenge(ch);
        byte[] am = PreAuth.authMessage(t.endpoint(), hello, ch, binding);
        byte[][] ps = PreAuth.scramClient(pw, c, am);
        byte[] proof = ps[0], want = ps[1];
        try {
            t.write(proof, 0, proof.length);
            byte[] vb = new byte[Wire.VERDICT_LEN];
            readFully(t, vb, timeoutMs);
            PreAuth.Verdict v = PreAuth.verdict(vb);
            if (v.code == Wire.VERDICT_BINDING)
                throw new WireException(Wire.E_AUTH, "the server refuses this login's channel binding type ("
                        + t.bindingName() + ")");
            if (v.code != Wire.VERDICT_OK) throw new WireException(Wire.E_AUTH, "authentication refused");
            if (!MessageDigest.isEqual(v.sig, want))
                throw new WireException(Wire.E_AUTH, "the server did not prove it holds the verifier");
        } finally {
            PreAuth.wipe(proof);
            PreAuth.wipe(want);
            PreAuth.wipe(binding);
        }
    }
}
