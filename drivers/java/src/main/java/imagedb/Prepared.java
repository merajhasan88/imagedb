package imagedb;

import java.util.Collections;
import java.util.List;

/** a prepared statement (PREPARE): EXECUTE with one parameter set or several (a batch), then DEALLOCATE */
public final class Prepared implements AutoCloseable {
    private final Connection c;
    private final String name;

    Prepared(Connection c, String name) {
        this.c = c;
        this.name = name;
    }

    public String name() { return name; }

    public Result execute(Object... params) throws ImagedbException {
        if (params == null)
            throw new IllegalArgumentException("parameters: a null array (for one NULL parameter pass (Object) null)");
        List<Result> r = c.execute(name, Collections.singletonList(params));
        if (r.size() != 1) throw new ImagedbException(2, -1, r.size() + " answers to one parameter set", false, null);
        return r.get(0);
    }

    /** 1 to 4,096 sets, each the same count of values: the first ERROR ends it (BatchException, its index the set's) */
    public List<Result> executeBatch(List<Object[]> sets) throws ImagedbException { return c.execute(name, sets); }

    public void deallocate() throws ImagedbException { c.deallocate(name); }

    @Override
    public void close() throws ImagedbException { deallocate(); }
}
