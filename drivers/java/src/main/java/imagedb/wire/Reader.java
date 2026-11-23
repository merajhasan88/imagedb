package imagedb.wire;

/**
 * A bounded little-endian reader over a body (the C's imdb_rd): every read checked against the bytes left, so a count
 * is never trusted past them; the caller asks left() == 0 at the end (no trailing bytes).
 */
public final class Reader {
    private final byte[] b;
    private final int end;
    private int off;

    public Reader(byte[] b) { this(b, 0, b.length); }

    public Reader(byte[] b, int off, int len) {
        this.b = b;
        this.off = off;
        this.end = off + len;
    }

    public int left() { return end - off; }

    public int offset() { return off; }

    byte[] array() { return b; }

    private void need(int n, String what) throws WireException {
        if (n < 0 || n > end - off) throw WireException.corrupt(what + " cut short");
    }

    public int u8(String what) throws WireException {
        need(1, what);
        return b[off++] & 0xff;
    }

    public int u16(String what) throws WireException {
        need(2, what);
        int v = (b[off] & 0xff) | (b[off + 1] & 0xff) << 8;
        off += 2;
        return v;
    }

    /** a u32 as a non-negative long */
    public long u32(String what) throws WireException {
        need(4, what);
        long v = Buf.getLe32(b, off);
        off += 4;
        return v;
    }

    public long u64(String what) throws WireException {
        need(8, what);
        long v = 0;
        for (int i = 7; i >= 0; i--) v = v << 8 | (b[off + i] & 0xffL);
        off += 8;
        return v;
    }

    public byte[] bytes(int n, String what) throws WireException {
        need(n, what);
        byte[] out = new byte[n];
        System.arraycopy(b, off, out, 0, n);
        off += n;
        return out;
    }

    /** n bytes skipped: their offset returned (a span validated in place) */
    int skip(int n, String what) throws WireException {
        need(n, what);
        int at = off;
        off += n;
        return at;
    }
}
