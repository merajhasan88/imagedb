package imagedb;

import imagedb.wire.Interval;
import imagedb.wire.Value;
import imagedb.wire.Wire;
import imagedb.wire.WireException;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.time.Instant;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.LocalTime;
import java.time.OffsetDateTime;
import java.time.ZonedDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

/**
 * Java objects as wire parameters (§4: any value but a non-NULL ENUM; an ENUM label is sent as a String, TEXT). The
 * server binds a parameter as the literal of its value would be (N1b), so an Integer into a DECIMAL column is taken
 * when exact; nothing here rounds: a time past the microsecond, a BigDecimal past 38 places or 38 digits, a NaN or an
 * infinity is refused before anything is sent.
 */
public final class Params {
    private Params() {}

    /** a NULL of a type (a bare Java null is a NULL of no type: the engine takes it into any column) */
    public static Value nullOf(Type t) {
        try {
            return Value.nullOf(t.code);
        } catch (WireException x) {
            throw new IllegalArgumentException(x.getMessage());
        }
    }

    public static Value of(Object o) throws ImagedbException {
        try {
            return convert(o);
        } catch (WireException x) {
            throw new ImagedbException(x.code(), -1, "a parameter: " + x.getMessage(), false, x);
        }
    }

    static Value convert(Object o) throws WireException {
        if (o == null) return Value.nullOf(Wire.T_NONE);
        if (o instanceof Value) return (Value) o;
        if (o instanceof Long || o instanceof Integer || o instanceof Short || o instanceof Byte)
            return Value.int64(((Number) o).longValue());
        if (o instanceof Double || o instanceof Float) {
            double d = ((Number) o).doubleValue(); // a float widened exactly
            if (d == 0.0) d = 0.0;                  // -0.0 is the one zero the engine keeps (its literal's value)
            return Value.float64(d);
        }
        if (o instanceof Boolean) return Value.bool((Boolean) o);
        if (o instanceof String) return Value.text((String) o);
        if (o instanceof BigDecimal) return Value.decimal((BigDecimal) o);
        if (o instanceof BigInteger) return Value.decimal((BigInteger) o, 0);
        if (o instanceof LocalDateTime) return Value.timestamp((LocalDateTime) o);
        if (o instanceof Instant) return Value.timestamptz((Instant) o);
        if (o instanceof OffsetDateTime) return Value.timestamptz(((OffsetDateTime) o).toInstant());
        if (o instanceof ZonedDateTime) return Value.timestamptz(((ZonedDateTime) o).toInstant());
        if (o instanceof LocalDate) return Value.date((LocalDate) o);
        if (o instanceof LocalTime) return Value.time((LocalTime) o);
        if (o instanceof UUID) return Value.uuid((UUID) o);
        if (o instanceof byte[]) return Value.bytea((byte[]) o);
        if (o instanceof Interval) {
            Interval iv = (Interval) o;
            return Value.interval(iv.months, iv.days, iv.micros);
        }
        throw new WireException(Wire.E_INVALID, "no wire type for " + o.getClass().getName());
    }

    static List<Value> list(Object[] ps) throws ImagedbException {
        if (ps == null)
            throw new IllegalArgumentException("parameters: a null array (for one NULL parameter pass (Object) null)");
        List<Value> v = new ArrayList<>(ps.length);
        for (Object o : ps) v.add(of(o));
        return v;
    }
}
