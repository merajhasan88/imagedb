package imagedb;

import imagedb.wire.Wire;

/** a value's wire type (§4) */
public enum Type {
    NONE(Wire.T_NONE), INT64(Wire.T_INT64), FLOAT64(Wire.T_FLOAT64), BOOL(Wire.T_BOOL), TEXT(Wire.T_TEXT), DECIMAL(Wire.T_DECIMAL),
    TIMESTAMP(Wire.T_TIMESTAMP), TIMESTAMPTZ(Wire.T_TIMESTAMPTZ), DATE(Wire.T_DATE), TIME(Wire.T_TIME), UUID(Wire.T_UUID),
    BYTEA(Wire.T_BYTEA), INTERVAL(Wire.T_INTERVAL), ENUM(Wire.T_ENUM);

    public final int code;

    Type(int code) { this.code = code; }

    public static Type of(int code) {
        for (Type t : values())
            if (t.code == code) return t;
        throw new IllegalArgumentException("no wire type " + code);
    }
}
