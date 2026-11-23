package imagedb.wire;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * The few DER facts a pin needs: a certificate's subjectPublicKeyInfo as its own bytes (never a re-encoding of the
 * parsed key: the pin is the SHA-256 of exactly what the certificate holds, tls.c spki_pin's i2d_X509_PUBKEY).
 */
public final class Der {
    private Der() {}

    /** [start, end) of the element at off: its tag, its length's bytes, its contents */
    private static int[] element(byte[] b, int off, int limit) throws WireException {
        if (off + 2 > limit) throw WireException.corrupt("a certificate cut short");
        int i = off + 1; // the tag (one byte: the fields read here never have a high tag number)
        int l0 = b[i++] & 0xff;
        long len;
        if (l0 < 0x80) len = l0;
        else {
            int n = l0 & 0x7f;
            if (n < 1 || n > 4 || i + n > limit) throw WireException.corrupt("a certificate's length");
            len = 0;
            for (int k = 0; k < n; k++) len = len << 8 | (b[i++] & 0xff);
        }
        if (len > limit - i) throw WireException.corrupt("a certificate's element past its end");
        return new int[] {off, i, (int) (i + len)}; // start, contents, end
    }

    /** the certificate's subjectPublicKeyInfo DER (tbsCertificate's seventh field, after an optional [0] version) */
    public static byte[] spki(byte[] cert) throws WireException {
        int[] c = element(cert, 0, cert.length);               // Certificate SEQUENCE
        int[] tbs = element(cert, c[1], c[2]);                 // tbsCertificate SEQUENCE
        int at = tbs[1];
        if ((cert[at] & 0xff) == 0xa0) at = element(cert, at, tbs[2])[2]; // [0] EXPLICIT version
        for (int k = 0; k < 5; k++) at = element(cert, at, tbs[2])[2]; // serial, signature, issuer, validity, subject
        int[] spki = element(cert, at, tbs[2]);
        if ((cert[at] & 0xff) != 0x30) throw WireException.corrupt("a certificate without a subjectPublicKeyInfo");
        byte[] out = new byte[spki[2] - spki[0]];
        System.arraycopy(cert, spki[0], out, 0, out.length);
        return out;
    }

    public static byte[] sha256(byte[] b) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(b);
        } catch (NoSuchAlgorithmException x) {
            throw new IllegalStateException("SHA-256", x);
        }
    }

    public static String hex(byte[] b) {
        StringBuilder s = new StringBuilder(b.length * 2);
        for (byte x : b) s.append(Character.forDigit((x >> 4) & 15, 16)).append(Character.forDigit(x & 15, 16));
        return s.toString();
    }

    public static byte[] unhex(String h) {
        h = h.replace(" ", "");
        if (h.length() % 2 != 0) throw new IllegalArgumentException("hex of odd length");
        byte[] b = new byte[h.length() / 2];
        for (int i = 0; i < b.length; i++) {
            int hi = Character.digit(h.charAt(2 * i), 16), lo = Character.digit(h.charAt(2 * i + 1), 16);
            if (hi < 0 || lo < 0) throw new IllegalArgumentException("not hex: " + h);
            b[i] = (byte) (hi << 4 | lo);
        }
        return b;
    }
}
