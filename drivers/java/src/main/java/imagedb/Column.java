package imagedb;

import imagedb.wire.Msg;
import java.util.List;

/**
 * A result column (§4's COLUMNS): its name, its wire type (NONE when the statement does not know it: SHOW's rows, each
 * value then its own type), precision and scale (DECIMAL: 0 for not known, 38 digits; INT64: 0, 16 SMALLINT or 32
 * INTEGER; TEXT: its VARCHAR length, 0 none), an ENUM's labels in the type's order.
 */
public final class Column {
    private final Msg.Column c;

    Column(Msg.Column c) { this.c = c; }

    public String name() { return c.name; }

    public Type type() { return Type.of(c.type); }

    public int precision() { return c.precision; }

    public int scale() { return c.scale; }

    public List<String> labels() { return c.labels; }

    @Override
    public String toString() { return c.toString(); }
}
