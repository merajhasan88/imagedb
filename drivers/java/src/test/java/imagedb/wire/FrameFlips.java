package imagedb.wire;

import java.util.Arrays;

/**
 * Frames the live server sent, recorded byte for byte, each decoded, then every byte of its body flipped three ways and
 * every cut: what the decoder takes must encode back to exactly those bytes (one encoding), a cut must be refused (but
 * COPY_OUT's raw bytes). The anchor is the server's own output, not the driver's encoder.
 */
public final class FrameFlips {
    private FrameFlips() {}

    /** [frames, taken, refused, bad]; bad > 0 a failure (decoded flips that encode otherwise, cuts taken, a frame refused) */
    public static long[] check(byte[] stream) {
        long frames = 0, took = 0, refused = 0, bad = 0;
        Msg.Columns cols = null;
        int off = 0;
        while (off + Wire.HEAD <= stream.length) {
            int len = (int) Buf.getLe32(stream, off), type = stream[off + 4] & 0xff;
            if (off + 4 + len > stream.length) break;
            byte[] body = Arrays.copyOfRange(stream, off + Wire.HEAD, off + 4 + len);
            off += 4 + len;
            frames++;
            Msg m;
            try {
                m = Frames.decode(type, body, cols);
                if (!Arrays.equals(ServerEncoder.encode(m, cols), body)) bad++;
            } catch (WireException x) {
                bad++; // the server's own frame refused
                continue;
            }
            Msg.Columns use = cols;
            for (int i = 0; i < body.length; i++)
                for (int f : new int[] {0x01, 0x80, 0xff}) {
                    byte[] y = body.clone();
                    y[i] ^= (byte) f;
                    try {
                        Msg z = Frames.decode(type, y, use);
                        took++;
                        if (!Arrays.equals(ServerEncoder.encode(z, use), y)) bad++;
                    } catch (WireException x) {
                        refused++;
                    }
                }
            for (int cut = 0; cut < body.length; cut++) {
                try {
                    Frames.decode(type, Arrays.copyOf(body, cut), use);
                    if (type != Wire.COPY_OUT || cut == 0) bad++;
                } catch (WireException x) {
                    // refused
                }
            }
            if (m instanceof Msg.Columns) cols = (Msg.Columns) m;
        }
        if (off != stream.length) bad++; // a frame cut by the recording's end
        return new long[] {frames, took, refused, bad};
    }
}
