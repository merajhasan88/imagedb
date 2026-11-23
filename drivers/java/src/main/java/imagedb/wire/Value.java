package imagedb.wire;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.time.Instant;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.LocalTime;
import java.time.ZoneOffset;
import java.util.Arrays;
import java.util.UUID;

/**
 * A wire value (§4's table): a u8 tag, then its bytes. A tag is a type (1 to 13), or 0x80 | a type (0 to 13) for a
 * NULL of that type, which has no bytes. Immutable; each factory refuses what the decoder refuses (one predicate a
 * field, wire.c imdbw_value_ok), so nothing this class holds encodes to bytes a server would refuse.
 */
public final class Value {
    public final int type;      // Wire.T_*: the value's, or the NULL's (T_NONE: a NULL of no type)
    public final boolean isNull;
    private final long i;       // INT64, BOOL, TIMESTAMP, TIMESTAMPTZ, TIME, INTERVAL's microseconds; FLOAT64's bits
    private final int mon, day; // INTERVAL; DATE's days in day
    private final int scale;    // DECIMAL
    private final BigInteger d; // DECIMAL's unscaled value
    private final byte[] s;     // TEXT's or ENUM's UTF-8, BYTEA, UUID's 16 bytes

    static final BigInteger[] POW10 = new BigInteger[39];

    static {
        for (int k = 0; k <= 38; k++) POW10[k] = BigInteger.TEN.pow(k);
    }

    static final BigInteger DEC_LIM = POW10[38];

    private Value(int type, boolean isNull, long i, int mon, int day, int scale, BigInteger d, byte[] s) {
        this.type = type;
        this.isNull = isNull;
        this.i = i;
        this.mon = mon;
        this.day = day;
        this.scale = scale;
        this.d = d;
        this.s = s;
    }

    private static Value of(int type, long i) { return new Value(type, false, i, 0, 0, 0, null, null); }

    // ---- factories: each the decoder's rule ----

    /** a NULL of a type (Wire.T_NONE: of none) */
    public static Value nullOf(int type) throws WireException {
        if (type < 0 || type > Wire.T_LAST) throw WireException.invalid("a NULL of a type the protocol does not define");
        return new Value(type, true, 0, 0, 0, 0, null, null);
    }

    public static Value int64(long v) { return of(Wire.T_INT64, v); }

    /** finite, never -0 (the engine keeps one zero) */
    public static Value float64(double v) throws WireException { return float64Bits(Double.doubleToRawLongBits(v)); }

    public static Value float64Bits(long bits) throws WireException {
        if (((bits >>> 52) & 0x7ff) == 0x7ff) throw WireException.invalid("a FLOAT64 that is not finite");
        if (bits == 0x8000000000000000L) throw WireException.invalid("a FLOAT64 of -0: the engine keeps one zero");
        return of(Wire.T_FLOAT64, bits);
    }

    public static Value bool(boolean v) { return of(Wire.T_BOOL, v ? 1 : 0); }

    public static Value text(String v) throws WireException { return textUtf8(Utf8.encode(v)); }

    public static Value textUtf8(byte[] u) throws WireException {
        if (u.length > Wire.VALUE_MAX) throw new WireException(Wire.E_LIMIT, "a TEXT of " + u.length + " bytes (at most 65,535)");
        if (!Utf8.valid(u)) throw WireException.invalid("a TEXT that is not UTF-8 without NUL");
        return new Value(Wire.T_TEXT, false, 0, 0, 0, 0, null, u.clone());
    }

    public static Value bytea(byte[] b) throws WireException {
        if (b.length > Wire.VALUE_MAX) throw new WireException(Wire.E_LIMIT, "a BYTEA of " + b.length + " bytes (at most 65,535)");
        return new Value(Wire.T_BYTEA, false, 0, 0, 0, 0, null, b.clone());
    }

    /** an ENUM label (a result's: a parameter carries a label as TEXT, §4) */
    public static Value enumLabel(String label) throws WireException { return enumUtf8(Utf8.encode(label)); }

    public static Value enumUtf8(byte[] u) throws WireException {
        if (u.length > Wire.LABEL_MAX) throw new WireException(Wire.E_LIMIT, "an ENUM label of " + u.length + " bytes (at most 63)");
        if (!Utf8.valid(u)) throw WireException.invalid("an ENUM label that is not UTF-8 without NUL");
        return new Value(Wire.T_ENUM, false, 0, 0, 0, 0, null, u.clone());
    }

    /** scale 0 to 38, the unscaled value less than 10^38 in magnitude */
    public static Value decimal(BigInteger unscaled, int scale) throws WireException {
        if (scale < 0 || scale > 38) throw WireException.invalid("a DECIMAL's scale is 0 to 38");
        if (unscaled.abs().compareTo(DEC_LIM) >= 0) throw WireException.invalid("a DECIMAL of more than 38 digits");
        return new Value(Wire.T_DECIMAL, false, 0, 0, 0, scale, unscaled, null);
    }

    /**
     * a BigDecimal as its own value, never rounded: a negative scale made 0 (1E+3 is 1000), a scale past 38 taken only
     * when its trailing zeros bring it to 38 or less
     */
    public static Value decimal(BigDecimal v) throws WireException {
        BigDecimal x = v;
        if (x.scale() < 0) x = x.setScale(0);
        if (x.scale() > 38) {
            x = x.stripTrailingZeros();
            if (x.scale() < 0) x = x.setScale(0);
            if (x.scale() > 38) throw WireException.invalid("a DECIMAL of more than 38 places (never rounded)");
        }
        return decimal(x.unscaledValue(), x.scale());
    }

    public static Value timestamp(long micros) throws WireException {
        if (micros < Wire.TS_MIN_US || micros > Wire.TS_MAX_US) throw WireException.invalid("a TIMESTAMP outside years 1 to 9999");
        return of(Wire.T_TIMESTAMP, micros);
    }

    public static Value timestamptz(long micros) throws WireException {
        if (micros < Wire.TS_MIN_US || micros > Wire.TS_MAX_US) throw WireException.invalid("a TIMESTAMPTZ outside years 1 to 9999");
        return of(Wire.T_TIMESTAMPTZ, micros);
    }

    public static Value date(int days) throws WireException {
        if (days < Wire.DATE_MIN || days > Wire.DATE_MAX) throw WireException.invalid("a DATE outside 0001-01-01 to 9999-12-31");
        return new Value(Wire.T_DATE, false, 0, 0, days, 0, null, null);
    }

    public static Value time(long micros) throws WireException {
        if (micros < 0 || micros > Wire.TIME_MAX) throw WireException.invalid("a TIME outside 00:00 to 23:59:59.999999");
        return of(Wire.T_TIME, micros);
    }

    public static Value uuid(byte[] b) throws WireException {
        if (b == null || b.length != 16) throw WireException.invalid("a UUID is 16 bytes");
        return new Value(Wire.T_UUID, false, 0, 0, 0, 0, null, b.clone());
    }

    /** RFC 4122's byte order: the most significant bits first, as the text form reads */
    public static Value uuid(UUID u) throws WireException {
        byte[] b = new byte[16];
        long hi = u.getMostSignificantBits(), lo = u.getLeastSignificantBits();
        for (int k = 0; k < 8; k++) {
            b[k] = (byte) (hi >>> (56 - 8 * k));
            b[8 + k] = (byte) (lo >>> (56 - 8 * k));
        }
        return uuid(b);
    }

    /** any triple */
    public static Value interval(int months, int days, long micros) {
        return new Value(Wire.T_INTERVAL, false, micros, months, days, 0, null, null);
    }

    // ---- java.time: microseconds kept, never rounded ----

    static long micros(long epochSecond, int nano) throws WireException {
        if (nano % 1000 != 0) throw WireException.invalid("a time with nanoseconds past the microsecond (never rounded)");
        try {
            return Math.addExact(Math.multiplyExact(epochSecond, 1_000_000L), nano / 1000);
        } catch (ArithmeticException x) {
            throw WireException.invalid("a time outside years 1 to 9999");
        }
    }

    public static Value timestamp(LocalDateTime t) throws WireException {
        return timestamp(micros(t.toEpochSecond(ZoneOffset.UTC), t.getNano()));
    }

    public static Value timestamptz(Instant t) throws WireException { return timestamptz(micros(t.getEpochSecond(), t.getNano())); }

    public static Value date(LocalDate d) throws WireException {
        long e = d.toEpochDay();
        if (e < Wire.DATE_MIN || e > Wire.DATE_MAX) throw WireException.invalid("a DATE outside 0001-01-01 to 9999-12-31");
        return date((int) e);
    }

    public static Value time(LocalTime t) throws WireException {
        long n = t.toNanoOfDay();
        if (n % 1000 != 0) throw WireException.invalid("a TIME with nanoseconds past the microsecond (never rounded)");
        return time(n / 1000);
    }

    // ---- accessors ----

    public long int64() { return i; }

    public boolean bool() { return i != 0; }

    public long float64Bits() { return i; }

    public double float64() { return Double.longBitsToDouble(i); }

    public int scale() { return scale; }

    public BigInteger unscaled() { return d; }

    public BigDecimal decimal() { return new BigDecimal(d, scale); }

    public long micros() { return i; }

    public int days() { return day; }

    public int months() { return mon; }

    /** TEXT's or ENUM's UTF-8, BYTEA's bytes, UUID's 16 bytes: a copy */
    public byte[] bytes() { return s == null ? null : s.clone(); }

    public int byteLength() { return s == null ? 0 : s.length; }

    /** the bytes themselves, not a copy: the codec's own reads */
    byte[] rawBytes() { return s; }

    public String string() { return s == null ? null : Utf8.decode(s, 0, s.length); }

    public UUID uuid() {
        long hi = 0, lo = 0;
        for (int k = 0; k < 8; k++) {
            hi = hi << 8 | (s[k] & 0xff);
            lo = lo << 8 | (s[8 + k] & 0xff);
        }
        return new UUID(hi, lo);
    }

    public LocalDateTime localDateTime() {
        return LocalDateTime.ofEpochSecond(Math.floorDiv(i, 1_000_000L), (int) Math.floorMod(i, 1_000_000L) * 1000, ZoneOffset.UTC);
    }

    public Instant instant() { return Instant.ofEpochSecond(Math.floorDiv(i, 1_000_000L), Math.floorMod(i, 1_000_000L) * 1000); }

    public LocalDate localDate() { return LocalDate.ofEpochDay(day); }

    public LocalTime localTime() { return LocalTime.ofNanoOfDay(i * 1000); }

    /** the value as its Java type: null for a NULL */
    public Object toJava() {
        if (isNull) return null;
        switch (type) {
        case Wire.T_INT64: return i;
        case Wire.T_FLOAT64: return float64();
        case Wire.T_BOOL: return i != 0;
        case Wire.T_TEXT:
        case Wire.T_ENUM: return string();
        case Wire.T_DECIMAL: return decimal();
        case Wire.T_TIMESTAMP: return localDateTime();
        case Wire.T_TIMESTAMPTZ: return instant();
        case Wire.T_DATE: return localDate();
        case Wire.T_TIME: return localTime();
        case Wire.T_UUID: return uuid();
        case Wire.T_BYTEA: return s.clone();
        case Wire.T_INTERVAL: return new Interval(mon, day, i);
        default: throw new IllegalStateException("no type");
        }
    }

    // ---- the bytes ----

    public void encode(Buf b) throws WireException {
        if (isNull) {
            b.u8(Wire.NULL_TAG | type);
            return;
        }
        b.u8(type);
        switch (type) {
        case Wire.T_BOOL: b.u8((int) i); break;
        case Wire.T_TEXT:
        case Wire.T_BYTEA:
            b.u32(s.length);
            b.put(s);
            break;
        case Wire.T_ENUM:
            b.u8(s.length);
            b.put(s);
            break;
        case Wire.T_DECIMAL:
            b.u8(scale);
            b.put(i128(d));
            break;
        case Wire.T_DATE: b.u32(day & 0xffffffffL); break;
        case Wire.T_UUID: b.put(s); break;
        case Wire.T_INTERVAL:
            b.u32(mon & 0xffffffffL);
            b.u32(day & 0xffffffffL);
            b.u64(i);
            break;
        default: b.u64(i); // INT64, FLOAT64, TIMESTAMP, TIMESTAMPTZ, TIME
        }
    }

    public byte[] encode() throws WireException {
        Buf b = new Buf();
        encode(b);
        return b.bytes();
    }

    /** a two's-complement i128, little-endian */
    static byte[] i128(BigInteger v) {
        byte[] be = v.toByteArray(); // big-endian, minimal (at most 16 bytes: |v| < 10^38 < 2^127)
        byte[] le = new byte[16];
        byte fill = (byte) (v.signum() < 0 ? 0xff : 0);
        Arrays.fill(le, fill);
        for (int k = 0; k < be.length && k < 16; k++) le[k] = be[be.length - 1 - k];
        return le;
    }

    static BigInteger fromI128(byte[] le) {
        byte[] be = new byte[16];
        for (int k = 0; k < 16; k++) be[k] = le[15 - k];
        return new BigInteger(be);
    }

    /** one value, strictly (wire.c imdbw_value_get): a length past its bound refused before its bytes are read */
    public static Value decode(Reader r) throws WireException {
        int tag = r.u8("a value");
        if ((tag & Wire.NULL_TAG) != 0) {
            int t = tag & ~Wire.NULL_TAG;
            if (t > Wire.T_LAST) throw WireException.corrupt("a NULL of a type the protocol does not define");
            return new Value(t, true, 0, 0, 0, 0, null, null);
        }
        try {
            switch (tag) {
            case Wire.T_INT64: return int64(r.u64("a value"));
            case Wire.T_TIMESTAMP: return timestamp(r.u64("a value"));
            case Wire.T_TIMESTAMPTZ: return timestamptz(r.u64("a value"));
            case Wire.T_TIME: return time(r.u64("a value"));
            case Wire.T_FLOAT64: return float64Bits(r.u64("a value"));
            case Wire.T_BOOL: {
                int v = r.u8("a value");
                if (v > 1) throw WireException.corrupt("a value outside its type's rules");
                return of(Wire.T_BOOL, v);
            }
            case Wire.T_TEXT:
            case Wire.T_BYTEA: {
                long n = r.u32("a value");
                if (n > Wire.VALUE_MAX) throw WireException.limit("a value of " + n + " bytes (at most 65535)");
                byte[] b = r.bytes((int) n, "a value");
                if (tag == Wire.T_BYTEA) return new Value(Wire.T_BYTEA, false, 0, 0, 0, 0, null, b);
                if (!Utf8.valid(b)) throw WireException.corrupt("a value outside its type's rules");
                return new Value(Wire.T_TEXT, false, 0, 0, 0, 0, null, b);
            }
            case Wire.T_ENUM: {
                int n = r.u8("a value");
                if (n > Wire.LABEL_MAX) throw WireException.limit("a value of " + n + " bytes (at most 63)");
                byte[] b = r.bytes(n, "a value");
                if (!Utf8.valid(b)) throw WireException.corrupt("a value outside its type's rules");
                return new Value(Wire.T_ENUM, false, 0, 0, 0, 0, null, b);
            }
            case Wire.T_DECIMAL: {
                int sc = r.u8("a value");
                BigInteger v = fromI128(r.bytes(16, "a value"));
                return decimal(v, sc);
            }
            case Wire.T_DATE: return date((int) r.u32("a value"));
            case Wire.T_UUID: return new Value(Wire.T_UUID, false, 0, 0, 0, 0, null, r.bytes(16, "a value"));
            case Wire.T_INTERVAL: {
                int m = (int) r.u32("a value"), dd = (int) r.u32("a value");
                return interval(m, dd, r.u64("a value"));
            }
            default:
                throw WireException.corrupt("a value of a type the protocol does not define (a NULL's tag is 0x80 and its type)");
            }
        } catch (WireException x) {
            if (x.code() == Wire.E_INVALID) throw WireException.corrupt("a value outside its type's rules");
            throw x;
        }
    }

    public static Value decode(byte[] b) throws WireException {
        Reader r = new Reader(b);
        Value v = decode(r);
        if (r.left() != 0) throw WireException.corrupt("bytes past a value");
        return v;
    }

    @Override
    public boolean equals(Object o) {
        if (!(o instanceof Value)) return false;
        try {
            return Arrays.equals(encode(), ((Value) o).encode());
        } catch (WireException x) {
            return false;
        }
    }

    @Override
    public int hashCode() {
        try {
            return Arrays.hashCode(encode());
        } catch (WireException x) {
            return 0;
        }
    }

    @Override
    public String toString() {
        if (isNull) return "NULL(" + Wire.typeName(type) + ")";
        Object o = toJava();
        if (o instanceof byte[]) return Wire.typeName(type) + " \\x" + Der.hex((byte[]) o);
        return Wire.typeName(type) + " " + o;
    }
}
