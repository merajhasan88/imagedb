package imagedb;

import imagedb.wire.Msg;
import imagedb.wire.Value;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;

/**
 * One statement's (or parameter set's) answer: its columns and rows (a statement that returns rows: COLUMNS even for
 * none), its WARNINGs, and its DONE: the status, the count of rows returned or written, the read point (the commit it
 * read, its hash, the state digest, the lake's commit and manifest, the database's id; own when it saw its
 * transaction's pending writes) and, for a write, the commit it made and its hash. A COPY ... TO STDOUT run by query()
 * keeps its bytes in copyData().
 */
public final class Result implements Iterable<Row> {
    private final List<Column> columns;
    private final List<Row> rows;
    private final List<String> warnings;
    private final Msg.Done done;
    private final byte[] copyData;

    Result(Msg.Columns cols, List<Value[]> rawRows, List<String> warnings, Msg.Done done, byte[] copyData) {
        List<Column> cs = new ArrayList<>();
        if (cols != null)
            for (Msg.Column c : cols.columns) cs.add(new Column(c));
        this.columns = Collections.unmodifiableList(cs);
        List<Row> rs = new ArrayList<>(rawRows.size());
        for (Value[] v : rawRows) rs.add(new Row(this, v));
        this.rows = Collections.unmodifiableList(rs);
        this.warnings = Collections.unmodifiableList(warnings);
        this.done = done;
        this.copyData = copyData;
    }

    /** the columns: empty for a statement that returns no rows (no COLUMNS was sent) */
    public List<Column> columns() { return columns; }

    public boolean hasColumns() { return !columns.isEmpty(); }

    /** a column's index by its name (the first of that name) */
    public int columnIndex(String name) {
        for (int i = 0; i < columns.size(); i++)
            if (columns.get(i).name().equals(name)) return i;
        throw new IllegalArgumentException("no column " + name);
    }

    public List<Row> rows() { return rows; }

    public int size() { return rows.size(); }

    public Row row(int i) { return rows.get(i); }

    @Override
    public Iterator<Row> iterator() { return rows.iterator(); }

    public List<String> warnings() { return warnings; }

    /** DONE's status ("SELECT 3", "INSERT 2", ...) */
    public String status() { return done.status; }

    /** the rows returned or written (DONE's u64) */
    public long count() { return done.count; }

    /** the read point, or null for a statement that read nothing */
    public Msg.ReadPoint readPoint() { return done.read; }

    /** the commit this statement made (at least 1), or 0 when it wrote none */
    public long writeCommit() { return done.writeCommit; }

    public byte[] writeHash() { return done.writeHash == null ? null : done.writeHash.clone(); }

    /** a COPY ... TO STDOUT's bytes when query() ran it, else null */
    public byte[] copyData() { return copyData == null ? null : copyData.clone(); }

    @Override
    public String toString() { return done.status + (columns.isEmpty() ? "" : " " + columns + " " + rows.size() + " rows"); }
}
