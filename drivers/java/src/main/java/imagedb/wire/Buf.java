package imagedb.wire;

import java.util.Arrays;

/** A little-endian output buffer bounded by a frame (16 MiB and its head): what passes the bound is refused. */
public final class Buf {
    private byte[] p = new byte[256];
    private int len;

    public int length() { return len; }

    public byte[] bytes() { return Arrays.copyOf(p, len); }

    /** the buffer itself (valid to length()) */
    byte[] raw() { return p; }

    public void reset() { len = 0; }

    private void reserve(int n) throws WireException {
        if (n < 0 || (long) len + n > (long) Wire.FRAME_MAX + Wire.HEAD) throw WireException.limit("past a frame's 16 MiB");
        if (len + n <= p.length) return;
        int cap = p.length;
        while (cap < len + n) cap = cap > (1 << 29) ? Wire.FRAME_MAX + Wire.HEAD : cap * 2;
        p = Arrays.copyOf(p, cap);
    }

    public void put(byte[] b) throws WireException { put(b, 0, b.length); }

    public void put(byte[] b, int off, int n) throws WireException {
        reserve(n);
        System.arraycopy(b, off, p, len, n);
        len += n;
    }

    public void u8(int v) throws WireException {
        reserve(1);
        p[len++] = (byte) v;
    }

    public void u16(int v) throws WireException {
        reserve(2);
        p[len++] = (byte) v;
        p[len++] = (byte) (v >>> 8);
    }

    public void u32(long v) throws WireException {
        reserve(4);
        for (int i = 0; i < 4; i++) p[len++] = (byte) (v >>> (8 * i));
    }

    public void u64(long v) throws WireException {
        reserve(8);
        for (int i = 0; i < 8; i++) p[len++] = (byte) (v >>> (8 * i));
    }

    /** a count or a length written before what it covers */
    void patch32(int at, long v) {
        for (int i = 0; i < 4; i++) p[at + i] = (byte) (v >>> (8 * i));
    }

    static void le32(byte[] b, int at, long v) {
        for (int i = 0; i < 4; i++) b[at + i] = (byte) (v >>> (8 * i));
    }

    static long getLe32(byte[] b, int at) {
        return (b[at] & 0xffL) | (b[at + 1] & 0xffL) << 8 | (b[at + 2] & 0xffL) << 16 | (b[at + 3] & 0xffL) << 24;
    }
}
