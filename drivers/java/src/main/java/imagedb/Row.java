package imagedb;

import imagedb.wire.Interval;
import imagedb.wire.Value;
import imagedb.wire.Wire;
import java.math.BigDecimal;
import java.time.Instant;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.LocalTime;
import java.util.UUID;

/**
 * A result row. Each getter reads its value's own type (under a column of no known type each value carries one) and
 * converts only without loss: a getter asked for another type throws IllegalStateException naming the column and the
 * type; an object getter returns null for a NULL; a primitive one (getLong, getDouble, getBoolean) throws on a NULL
 * (ask isNull first), never a silent zero. Indexes are 0-based.
 */
public final class Row {
    private final Result r;
    private final Value[] v;

    Row(Result r, Value[] v) {
        this.r = r;
        this.v = v;
    }

    public int size() { return v.length; }

    /** the wire value itself */
    public Value value(int i) { return v[i]; }

    public Value value(String name) { return v[r.columnIndex(name)]; }

    public boolean isNull(int i) { return v[i].isNull; }

    public boolean isNull(String name) { return isNull(r.columnIndex(name)); }

    /** the value as its Java type (Long, Double, Boolean, String, BigDecimal, LocalDateTime, Instant, LocalDate, LocalTime, UUID, byte[], Interval), or null */
    public Object getObject(int i) { return v[i].toJava(); }

    public Object getObject(String name) { return getObject(r.columnIndex(name)); }

    private IllegalStateException wrong(int i, String want) {
        String col = r.columns().get(i).name();
        return new IllegalStateException("column " + i + " (" + col + ") holds " + v[i] + ", not " + want);
    }

    private Value nonNull(int i, String want) {
        if (v[i].isNull) throw new IllegalStateException("column " + i + " (" + r.columns().get(i).name() + ") is NULL, not " + want);
        return v[i];
    }

    private Value typed(int i, int type, String want) {
        if (v[i].isNull) return null;
        if (v[i].type != type) throw wrong(i, want);
        return v[i];
    }

    /** INT64 (SMALLINT and INTEGER too), or a DECIMAL that is exactly a long (a SUM over an INT64 column is DECIMAL) */
    public long getLong(int i) {
        Value x = nonNull(i, "a long");
        if (x.type == Wire.T_INT64) return x.int64();
        if (x.type == Wire.T_DECIMAL) {
            try {
                return x.decimal().longValueExact();
            } catch (ArithmeticException e) {
                throw wrong(i, "exactly a long");
            }
        }
        throw wrong(i, "a long");
    }

    public long getLong(String name) { return getLong(r.columnIndex(name)); }

    /** FLOAT64, bit for bit */
    public double getDouble(int i) {
        Value x = nonNull(i, "a double");
        if (x.type != Wire.T_FLOAT64) throw wrong(i, "a double (FLOAT64)");
        return x.float64();
    }

    public double getDouble(String name) { return getDouble(r.columnIndex(name)); }

    public boolean getBoolean(int i) {
        Value x = nonNull(i, "a boolean");
        if (x.type != Wire.T_BOOL) throw wrong(i, "a boolean");
        return x.bool();
    }

    public boolean getBoolean(String name) { return getBoolean(r.columnIndex(name)); }

    /** DECIMAL exactly (38 digits), or an INT64 */
    public BigDecimal getBigDecimal(int i) {
        if (v[i].isNull) return null;
        if (v[i].type == Wire.T_DECIMAL) return v[i].decimal();
        if (v[i].type == Wire.T_INT64) return BigDecimal.valueOf(v[i].int64());
        throw wrong(i, "a DECIMAL");
    }

    public BigDecimal getBigDecimal(String name) { return getBigDecimal(r.columnIndex(name)); }

    /** TEXT, or an ENUM's label */
    public String getString(int i) {
        if (v[i].isNull) return null;
        if (v[i].type != Wire.T_TEXT && v[i].type != Wire.T_ENUM) throw wrong(i, "a TEXT or an ENUM");
        return v[i].string();
    }

    public String getString(String name) { return getString(r.columnIndex(name)); }

    public byte[] getBytes(int i) {
        Value x = typed(i, Wire.T_BYTEA, "a BYTEA");
        return x == null ? null : x.bytes();
    }

    public byte[] getBytes(String name) { return getBytes(r.columnIndex(name)); }

    public UUID getUuid(int i) {
        Value x = typed(i, Wire.T_UUID, "a UUID");
        return x == null ? null : x.uuid();
    }

    public UUID getUuid(String name) { return getUuid(r.columnIndex(name)); }

    public LocalDate getLocalDate(int i) {
        Value x = typed(i, Wire.T_DATE, "a DATE");
        return x == null ? null : x.localDate();
    }

    public LocalDate getLocalDate(String name) { return getLocalDate(r.columnIndex(name)); }

    public LocalTime getLocalTime(int i) {
        Value x = typed(i, Wire.T_TIME, "a TIME");
        return x == null ? null : x.localTime();
    }

    public LocalTime getLocalTime(String name) { return getLocalTime(r.columnIndex(name)); }

    /** TIMESTAMP (no zone) */
    public LocalDateTime getLocalDateTime(int i) {
        Value x = typed(i, Wire.T_TIMESTAMP, "a TIMESTAMP");
        return x == null ? null : x.localDateTime();
    }

    public LocalDateTime getLocalDateTime(String name) { return getLocalDateTime(r.columnIndex(name)); }

    /** TIMESTAMPTZ: the instant */
    public Instant getInstant(int i) {
        Value x = typed(i, Wire.T_TIMESTAMPTZ, "a TIMESTAMPTZ");
        return x == null ? null : x.instant();
    }

    public Instant getInstant(String name) { return getInstant(r.columnIndex(name)); }

    public Interval getInterval(int i) {
        Value x = typed(i, Wire.T_INTERVAL, "an INTERVAL");
        return x == null ? null : new Interval(x.months(), x.days(), x.micros());
    }

    public Interval getInterval(String name) { return getInterval(r.columnIndex(name)); }

    @Override
    public String toString() {
        StringBuilder s = new StringBuilder("(");
        for (int i = 0; i < v.length; i++) s.append(i == 0 ? "" : ", ").append(v[i]);
        return s.append(')').toString();
    }
}
