package imagedb;

import static imagedb.test.T.check;
import static imagedb.test.T.eq;
import static imagedb.test.T.run;
import static imagedb.test.T.throwsIt;

import imagedb.wire.ScriptedTests;
import imagedb.wire.Wire;
import java.util.Arrays;

/**
 * The idiomatic API's reply loop against a scripted peer, for the sequences a live server cannot be made to send: an
 * ERROR after a statement's COLUMNS and ROWS (its rows not the answer), a frame no request asked for, a batch's ERROR
 * after answers, a login accepted then refused for a bound (ERROR 3 unasked, then the close).
 */
public final class ConnectionScripted {
    private ConnectionScripted() {}

    static Connection over(ScriptedTests.Fake f) throws Exception { return new Connection(ScriptedTests.loggedIn(f)); }

    static final String COLS = "0100 0178 01 0000 0000"; // one column x INT64
    static final String DONE = "0800 53454c4543542031 0100000000000000 00 00";

    public static void all() {
        run("scripted_api_error_after_rows (an ERROR after COLUMNS and ROWS: those rows are not the answer)", () -> {
            ScriptedTests.Fake f = ScriptedTests.afterLogin();
            Connection c = over(f);
            f.give(ScriptedTests.cat(ScriptedTests.frame(Wire.COLUMNS, COLS), ScriptedTests.frame(Wire.ROWS, "01000000 01 0700000000000000"),
                                     ScriptedTests.frame(Wire.ERROR, "03000000 00000000 0600 6120726f772e"), ScriptedTests.frame(Wire.READY, "00")));
            BatchException x = throwsIt(BatchException.class, () -> c.query("SELECT x FROM t"), "the ERROR");
            check(x != null && x.code() == 3 && x.index() == 0 && x.completed().isEmpty(), "ERROR 3 at 0, no result kept: " + x);
            eq(Connection.TxState.IDLE, c.state(), "READY read");
            f.give(ScriptedTests.cat(ScriptedTests.frame(Wire.COLUMNS, COLS), ScriptedTests.frame(Wire.ROWS, "01000000 01 0900000000000000"),
                                     ScriptedTests.frame(Wire.DONE, DONE), ScriptedTests.frame(Wire.READY, "00")));
            Result r = c.query("SELECT x FROM t");
            eq(1, r.size(), "the next statement's own rows alone");
            eq(9L, r.row(0).getLong(0), "its value");
        });

        run("scripted_api_batch (answers before the ERROR kept, its index; WARNINGs; READY's states)", () -> {
            ScriptedTests.Fake f = ScriptedTests.afterLogin();
            Connection c = over(f);
            f.give(ScriptedTests.cat(ScriptedTests.frame(Wire.DONE, DONE), ScriptedTests.frame(Wire.WARNING, "0200 6869"),
                                     ScriptedTests.frame(Wire.DONE, DONE), ScriptedTests.frame(Wire.ERROR, "06000000 02000000 0000"),
                                     ScriptedTests.frame(Wire.READY, "01")));
            BatchException x = throwsIt(BatchException.class, () -> c.batch(Arrays.asList(Statement.of("a"), Statement.of("b"),
                                                                                            Statement.of("c"), Statement.of("d"))), "the batch");
            check(x != null && x.index() == 2 && x.completed().size() == 2 && x.completed().get(1).warnings().equals(Arrays.asList("hi")),
                  "two answers, the second's WARNING, the ERROR at 2: " + x);
            eq(Connection.TxState.IN_TRANSACTION, c.state(), "READY 1");
            f.give(ScriptedTests.cat(ScriptedTests.frame(Wire.ERROR, "0e000000 00000000 0000"), ScriptedTests.frame(Wire.READY, "02")));
            ImagedbException d = throwsIt(ImagedbException.class, () -> c.query("x"), "doomed");
            check(d != null && d.isRetryable(), "ERROR 14: retry the transaction");
            eq(Connection.TxState.DOOMED, c.state(), "READY 2");
            f.give(ScriptedTests.frame(Wire.ERROR, "63000000 00000000 0000")); // a code a later imagedb may add
            f.give(ScriptedTests.frame(Wire.READY, "00"));
            ImagedbException u = throwsIt(ImagedbException.class, () -> c.query("x"), "code 99");
            check(u != null && u.code() == 99 && u.kind() == ImagedbException.Kind.OTHER, "an unknown code: no class: " + u);
        });

        run("scripted_api_unasked (a frame no request asked for ends the connection; ERROR 3 after the login, then the close)", () -> {
            ScriptedTests.Fake f = ScriptedTests.afterLogin();
            Connection c = over(f);
            f.give(ScriptedTests.cat(ScriptedTests.frame(Wire.PONG, ""), ScriptedTests.frame(Wire.READY, "00")));
            ImagedbException x = throwsIt(ImagedbException.class, () -> c.query("SELECT 1"), "a PONG inside a query's replies");
            check(x != null && x.kind() == ImagedbException.Kind.CORRUPT && x.getMessage().contains("PONG"), "named: " + x);
            check(c.isClosed(), "the connection closed");
            ScriptedTests.Fake g = ScriptedTests.afterLogin();
            Connection d = over(g);
            g.give(ScriptedTests.frame(Wire.ERROR, "03000000 00000000 1d00 " + imagedb.wire.Der.hex("the role's connections: 4 at most".getBytes()).substring(0, 58)));
            ImagedbException y = throwsIt(ImagedbException.class, () -> d.query("SELECT 1"), "refused for a bound");
            check(y != null && y.code() == 3 && y.getMessage().contains("the role's connections"), "ERROR 3 and its words: " + y);
            ImagedbException z = throwsIt(ImagedbException.class, () -> d.query("SELECT 1"), "again");
            check(z != null && z.code() == 3, "later calls fail with that reason: " + z);
            ScriptedTests.Fake h = ScriptedTests.afterLogin(); // ping() meets the ERROR as query() does
            Connection e = over(h);
            h.give(ScriptedTests.frame(Wire.ERROR, "03000000 00000000 0400 626f756e"));
            ImagedbException p = throwsIt(ImagedbException.class, e::ping, "ping after a bound's ERROR");
            check(p != null && p.code() == 3 && p.fromServer(), "ping reports the ERROR 3: " + p);
        });

        run("scripted_api_copy (a COPY_IN query() has no data for: COPY_FAIL at once; copyIn refused before its data sends none)", () -> {
            ScriptedTests.Fake f = ScriptedTests.afterLogin();
            Connection c = over(f);
            int base = f.writes.size();
            f.give(ScriptedTests.cat(ScriptedTests.frame(Wire.COPY_IN, ""), ScriptedTests.frame(Wire.ERROR, "0f000000 00000000 0000"),
                                     ScriptedTests.frame(Wire.READY, "00")));
            ImagedbException x = throwsIt(ImagedbException.class, () -> c.query("COPY t FROM STDIN"), "COPY_IN in query()");
            check(x != null && x.kind() == ImagedbException.Kind.STATE, "refused: " + x);
            eq(Wire.COPY_FAIL, f.writes.get(base + 1)[4] & 0xff, "the QUERY then a COPY_FAIL");
            int b2 = f.writes.size();
            f.give(ScriptedTests.cat(ScriptedTests.frame(Wire.ERROR, "0b000000 00000000 0000"), ScriptedTests.frame(Wire.READY, "00")));
            ImagedbException y = throwsIt(ImagedbException.class, () -> c.copyIn("COPY nope FROM STDIN", "1\n".getBytes()), "refused first");
            check(y != null && y.code() == 11, "its ERROR: " + y);
            eq(b2 + 1, f.writes.size(), "the QUERY alone: no COPY_DATA after a refusal without COPY_IN");
            int b3 = f.writes.size();
            f.give(ScriptedTests.cat(ScriptedTests.frame(Wire.COPY_IN, ""), ScriptedTests.frame(Wire.DONE, DONE), ScriptedTests.frame(Wire.READY, "00")));
            byte[] data = new byte[(1 << 20) + 5];
            Arrays.fill(data, (byte) 'x');
            Result r = c.copyIn("COPY t FROM STDIN", data);
            eq(1L, r.count(), "its DONE");
            eq(Arrays.asList(Wire.QUERY, Wire.COPY_DATA, Wire.COPY_DATA, Wire.COPY_DONE),
               Arrays.asList(f.writes.get(b3)[4] & 0xff, f.writes.get(b3 + 1)[4] & 0xff, f.writes.get(b3 + 2)[4] & 0xff, f.writes.get(b3 + 3)[4] & 0xff),
               "QUERY, two COPY_DATA (1 MiB, then 5 bytes), COPY_DONE");
            eq((1 << 20) + 1, (f.writes.get(b3 + 1)[0] & 0xff) | (f.writes.get(b3 + 1)[1] & 0xff) << 8 | (f.writes.get(b3 + 1)[2] & 0xff) << 16,
               "the first piece 1 MiB");
        });
    }
}
