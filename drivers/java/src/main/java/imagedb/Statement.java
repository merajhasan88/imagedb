package imagedb;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/** a statement of a batch: its text and its parameters ($1 to $k) */
public final class Statement {
    final String sql;
    final List<Object> params;

    private Statement(String sql, List<Object> params) {
        this.sql = sql;
        this.params = params;
    }

    public static Statement of(String sql, Object... params) {
        if (sql == null) throw new IllegalArgumentException("a statement's text");
        if (params == null)
            throw new IllegalArgumentException("parameters: a null array (for one NULL parameter pass (Object) null)");
        return new Statement(sql, Collections.unmodifiableList(Arrays.asList(params.clone())));
    }

    @Override
    public String toString() { return sql; }
}
