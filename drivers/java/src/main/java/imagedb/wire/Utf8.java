package imagedb.wire;

import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CharsetEncoder;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;

/**
 * UTF-8 by the engine's rule (wire.c utf8_valid): no NUL, no overlong form, no surrogate, nothing past U+10FFFF.
 * Every text the wire carries is held to it, both ways.
 */
public final class Utf8 {
    private Utf8() {}

    /** -1 when b[off, off+n) is valid; else the offset (from off) of the first byte of the first character that is not */
    public static int firstBad(byte[] b, int off, int n) {
        int i = 0;
        while (i < n) {
            int c = b[off + i] & 0xff;
            if (c >= 0x01 && c < 0x80) {
                i++;
                continue;
            }
            int need, lo = 0x80, hi = 0xBF;
            if (c >= 0xC2 && c <= 0xDF) need = 1;
            else if (c == 0xE0) { need = 2; lo = 0xA0; }
            else if (c >= 0xE1 && c <= 0xEC) need = 2;
            else if (c == 0xED) { need = 2; hi = 0x9F; }
            else if (c == 0xEE || c == 0xEF) need = 2;
            else if (c == 0xF0) { need = 3; lo = 0x90; }
            else if (c >= 0xF1 && c <= 0xF3) need = 3;
            else if (c == 0xF4) { need = 3; hi = 0x8F; }
            else return i; // NUL, C0, C1, F5..FF, a stray continuation
            if (need > n - i - 1) return i;
            int c1 = b[off + i + 1] & 0xff;
            if (c1 < lo || c1 > hi) return i;
            for (int j = 2; j <= need; j++)
                if ((b[off + i + j] & 0xC0) != 0x80) return i;
            i += need + 1;
        }
        return -1;
    }

    public static boolean valid(byte[] b, int off, int n) { return firstBad(b, off, n) < 0; }

    public static boolean valid(byte[] b) { return valid(b, 0, b.length); }

    /** the longest prefix of b[0, n), at most max bytes, that is UTF-8 without NUL (wire.c imdbw_utf8_fit) */
    public static int fit(byte[] b, int n, int max) {
        int k = Math.min(n, max);
        if (k == 0) return 0;
        int bad = firstBad(b, 0, k);
        return bad < 0 ? k : bad;
    }

    /** characters in valid UTF-8: the bytes that begin one */
    public static int chars(byte[] b, int off, int n) {
        int k = 0;
        for (int i = 0; i < n; i++) k += (b[off + i] & 0xC0) != 0x80 ? 1 : 0;
        return k;
    }

    /** a String's UTF-8, refusing an unpaired surrogate or a NUL (never a replacement character) */
    public static byte[] encode(String s) throws WireException {
        if (s.indexOf('\0') >= 0) throw WireException.invalid("a text holds a NUL, which the engine refuses");
        CharsetEncoder enc = StandardCharsets.UTF_8.newEncoder().onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT);
        try {
            ByteBuffer bb = enc.encode(CharBuffer.wrap(s));
            byte[] out = new byte[bb.remaining()];
            bb.get(out);
            return out;
        } catch (CharacterCodingException x) {
            throw WireException.invalid("a text holds an unpaired surrogate: not UTF-8");
        }
    }

    /** valid bytes (checked by the caller) as a String */
    public static String decode(byte[] b, int off, int n) { return new String(b, off, n, StandardCharsets.UTF_8); }
}
