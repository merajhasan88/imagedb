package imagedb.wire;

import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.Arrays;
import javax.crypto.Mac;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Before authentication (§4): fixed-size messages, the AuthMessage and SCRAM-SHA-256 (RFC 5802's computation over
 * it). Each decoder is strict (wire.c's: exact lengths, zero padding, a later version refused by name).
 */
public final class PreAuth {
    private PreAuth() {}

    /** a role name's field: 1 to 63 bytes of UTF-8 without NUL */
    public static byte[] userBytes(String user) throws WireException {
        if (user == null) throw WireException.invalid("a role's name is 1 to 63 bytes of UTF-8");
        byte[] u = Utf8.encode(user);
        if (u.length < 1 || u.length >= Wire.USER || !Utf8.valid(u))
            throw WireException.invalid("a role's name is 1 to 63 bytes of UTF-8");
        return u;
    }

    /** the client hello (112 bytes): the head | u32 flags (the binding's type) | user[64] | nonce[32] */
    public static byte[] hello(int flags, byte[] user, byte[] nonce) throws WireException {
        if (flags < Wire.CB_NONE || flags > Wire.CB_ENDPOINT) throw WireException.invalid("a hello's binding type is 0, 1 or 2");
        if (user.length < 1 || user.length >= Wire.USER || !Utf8.valid(user))
            throw WireException.invalid("a role's name is 1 to 63 bytes of UTF-8");
        if (nonce.length != Wire.NONCE) throw WireException.invalid("a nonce is 32 bytes");
        byte[] h = new byte[Wire.HELLO_LEN];
        System.arraycopy(Wire.MAGIC, 0, h, 0, 8);
        Buf.le32(h, 8, Wire.VERSION);
        Buf.le32(h, 12, flags);
        System.arraycopy(user, 0, h, 16, user.length);
        System.arraycopy(nonce, 0, h, 16 + Wire.USER, Wire.NONCE);
        return h;
    }

    /**
     * util.c imdb_later_magic: the same prefix and a larger trailing number ("IMDBWIR2" against "IMDBWIR1"): another,
     * later protocol, refused by name
     */
    static boolean laterMagic(byte[] b) {
        // "IMDBWIR" then digits: only the last byte is a digit in "IMDBWIR1"
        for (int i = 0; i < 7; i++)
            if (b[i] != Wire.MAGIC[i]) return false;
        int c = b[7] & 0xff;
        return c >= '0' && c <= '9' && c > '1';
    }

    /** the 12 bytes every pre-auth message begins with: its version (any number; 0 refused), or UNSUPPORTED by name */
    public static long head(byte[] b) throws WireException {
        if (b.length < Wire.PREAUTH_HEAD) throw WireException.corrupt("a pre-auth head cut short");
        long version = Buf.getLe32(b, 8);
        if (!Arrays.equals(b, 0, 8, Wire.MAGIC, 0, 8)) {
            if (laterMagic(b))
                throw new WireException(Wire.E_UNSUPPORTED, "wire: " + new String(b, 0, 8, java.nio.charset.StandardCharsets.ISO_8859_1)
                        + ", a later protocol, which this driver does not speak");
            throw WireException.corrupt("not imagedb's protocol");
        }
        if (version < 1) throw WireException.corrupt("protocol version 0");
        return version;
    }

    /** a decoded challenge */
    public static final class Challenge {
        public final int saltLen;
        public final byte[] salt;   // saltLen bytes
        public final int iter;
        public final byte[] nonce;  // 32 bytes

        Challenge(int saltLen, byte[] salt, int iter, byte[] nonce) {
            this.saltLen = saltLen;
            this.salt = salt;
            this.iter = iter;
            this.nonce = nonce;
        }
    }

    static boolean zeros(byte[] b, int off, int n) {
        for (int i = 0; i < n; i++)
            if (b[off + i] != 0) return false;
        return true;
    }

    /** the server challenge (120 bytes): the head | u8 salt length | salt[64] zero-padded | u32 iterations | nonce[32] | 7 zeros */
    public static Challenge challenge(byte[] c) throws WireException {
        if (c.length != Wire.CHALLENGE_LEN) throw WireException.corrupt("a challenge of another length");
        if (!Arrays.equals(c, 0, 8, Wire.MAGIC, 0, 8)) {
            if (laterMagic(c))
                throw new WireException(Wire.E_UNSUPPORTED, "wire: a later protocol, which this driver does not speak");
            throw WireException.corrupt("not imagedb's protocol");
        }
        long version = Buf.getLe32(c, 8);
        if (version > Wire.VERSION)
            throw new WireException(Wire.E_UNSUPPORTED, "wire: protocol version " + version
                    + ", a later one, which this driver (version 1) does not speak");
        if (version != Wire.VERSION) throw WireException.corrupt("an unknown protocol version");
        int saltLen = c[12] & 0xff;
        long iter = Buf.getLe32(c, 13 + Wire.SALT);
        if (saltLen < Wire.SCRAM_SALT_MIN || saltLen > Wire.SALT || iter < Wire.SCRAM_ITER_MIN || iter > Wire.SCRAM_ITER_MAX
                || !zeros(c, 13 + saltLen, Wire.SALT - saltLen))
            throw WireException.corrupt("a challenge's salt is not 8 to 64 bytes, zero-padded, or its iterations not 1,000 to 1,000,000");
        if (!zeros(c, 17 + Wire.SALT + Wire.NONCE, 7)) throw WireException.corrupt("a challenge's padding is not zero");
        return new Challenge(saltLen, Arrays.copyOfRange(c, 13, 13 + saltLen), (int) iter,
                Arrays.copyOfRange(c, 17 + Wire.SALT, 17 + Wire.SALT + Wire.NONCE));
    }

    /** a decoded verdict: its code (0 accepted, 1 refused, 2 the binding type refused) and the server's signature */
    public static final class Verdict {
        public final int code;
        public final byte[] sig;

        Verdict(int code, byte[] sig) {
            this.code = code;
            this.sig = sig;
        }
    }

    public static Verdict verdict(byte[] v) throws WireException {
        if (v.length != Wire.VERDICT_LEN) throw WireException.corrupt("a verdict of another length");
        long code = Buf.getLe32(v, 0);
        boolean ok = code == Wire.VERDICT_OK
                || ((code == Wire.VERDICT_REFUSED || code == Wire.VERDICT_BINDING) && zeros(v, 4, Wire.KEY));
        if (!ok) throw WireException.corrupt("a verdict neither accepted nor refused, or a refusal carrying a signature");
        return new Verdict((int) code, Arrays.copyOfRange(v, 4, 4 + Wire.KEY));
    }

    private static final byte[] AUTH_MAGIC = "IMDBWIR1-SCRAM".getBytes(java.nio.charset.StandardCharsets.US_ASCII);

    /** "IMDBWIR1-SCRAM" | u8 endpoint | the hello's 112 bytes | the challenge's 120 | binding[32] */
    public static byte[] authMessage(int endpoint, byte[] hello, byte[] challenge, byte[] binding) {
        if (hello.length != Wire.HELLO_LEN || challenge.length != Wire.CHALLENGE_LEN || binding.length != Wire.KEY)
            throw new IllegalArgumentException("the AuthMessage's parts");
        byte[] am = new byte[Wire.AUTHMSG_LEN];
        int o = AUTH_MAGIC.length;
        System.arraycopy(AUTH_MAGIC, 0, am, 0, o);
        am[o++] = (byte) endpoint;
        System.arraycopy(hello, 0, am, o, Wire.HELLO_LEN);
        o += Wire.HELLO_LEN;
        System.arraycopy(challenge, 0, am, o, Wire.CHALLENGE_LEN);
        o += Wire.CHALLENGE_LEN;
        System.arraycopy(binding, 0, am, o, Wire.KEY);
        return am;
    }

    /** CREATE ROLE's rule for a password: 1 to 1,024 bytes of printable ASCII (no SASLprep in imagedb yet) */
    public static void checkPassword(char[] pw) throws WireException {
        if (pw == null || pw.length < 1 || pw.length > Wire.PW_MAX)
            throw WireException.invalid("a password is 1 to 1,024 printable ASCII bytes");
        for (char ch : pw)
            if (ch < 0x20 || ch > 0x7e) throw WireException.invalid("a password is 1 to 1,024 printable ASCII bytes");
    }

    /** the client's proof and the server signature it expects: [0] ClientProof, [1] ServerSignature */
    public static byte[][] scramClient(char[] pw, Challenge c, byte[] am) throws WireException {
        checkPassword(pw);
        if (am.length != Wire.AUTHMSG_LEN) throw new IllegalArgumentException("the AuthMessage's length");
        byte[] sp = null, ck = null, sk = null, stored = null, cs = null;
        try {
            // PBKDF2-HMAC-SHA-256 of the password's bytes: printable ASCII, so the JCE's char-to-UTF-8 is those bytes
            PBEKeySpec spec = new PBEKeySpec(pw, c.salt, c.iter, 256);
            sp = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).getEncoded();
            spec.clearPassword();
            ck = hmac(sp, "Client Key".getBytes(java.nio.charset.StandardCharsets.US_ASCII));
            sk = hmac(sp, "Server Key".getBytes(java.nio.charset.StandardCharsets.US_ASCII));
            stored = MessageDigest.getInstance("SHA-256").digest(ck);
            cs = hmac(stored, am);
            byte[] proof = new byte[Wire.KEY];
            for (int i = 0; i < Wire.KEY; i++) proof[i] = (byte) (ck[i] ^ cs[i]);
            byte[] ssig = hmac(sk, am);
            return new byte[][] {proof, ssig};
        } catch (GeneralSecurityException x) {
            throw new WireException(Wire.E_STATE, "SCRAM: the platform's crypto: " + x.getMessage(), x);
        } finally {
            wipe(sp);
            wipe(ck);
            wipe(sk);
            wipe(stored);
            wipe(cs);
        }
    }

    static byte[] hmac(byte[] key, byte[] msg) throws GeneralSecurityException {
        Mac m = Mac.getInstance("HmacSHA256");
        m.init(new SecretKeySpec(key, "HmacSHA256"));
        return m.doFinal(msg);
    }

    static void wipe(byte[] b) {
        if (b != null) Arrays.fill(b, (byte) 0);
    }
}
