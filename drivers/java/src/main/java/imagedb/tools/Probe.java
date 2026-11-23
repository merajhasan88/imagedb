package imagedb.tools;

import imagedb.Column;
import imagedb.Connection;
import imagedb.Imagedb;
import imagedb.ImagedbException;
import imagedb.Result;
import imagedb.Row;
import imagedb.wire.Der;
import java.nio.file.Paths;

/**
 * A probe for an acceptance check: java imagedb.tools.Probe SOCKET PASSWORD SQL connects to the server's Unix-domain
 * socket as the role admin, runs the one statement, prints its rows (a header of the column names, then a line a row,
 * tab-separated; NULL as NULL, BYTEA as \x and hex) and exits 0; or prints the driver's error (its code and words) on
 * stderr and exits 1. Usage errors exit 2.
 */
public final class Probe {
    private Probe() {}

    static String cell(Object o) {
        if (o == null) return "NULL";
        if (o instanceof byte[]) return "\\x" + Der.hex((byte[]) o);
        return o.toString();
    }

    public static void main(String[] a) {
        if (a.length != 3) {
            System.err.println("usage: java imagedb.tools.Probe SOCKET PASSWORD SQL");
            System.exit(2);
        }
        int status;
        try (Connection c = Imagedb.connect(Paths.get(a[0]), "admin", a[1].toCharArray())) {
            Result r = c.query(a[2]);
            StringBuilder s = new StringBuilder();
            if (r.hasColumns()) {
                for (int i = 0; i < r.columns().size(); i++) {
                    Column col = r.columns().get(i);
                    s.append(i == 0 ? "" : "\t").append(col.name());
                }
                s.append('\n');
                for (Row row : r) {
                    for (int i = 0; i < row.size(); i++) s.append(i == 0 ? "" : "\t").append(cell(row.getObject(i)));
                    s.append('\n');
                }
            }
            System.out.print(s);
            System.out.flush();
            System.err.println(r.status());
            status = 0;
        } catch (ImagedbException x) {
            System.err.println("error " + x.code() + " (" + x.kind() + "): " + x.getMessage());
            status = 1;
        }
        System.exit(status); // after the connection's close (TERMINATE)
    }
}
