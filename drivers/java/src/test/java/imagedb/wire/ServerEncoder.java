package imagedb.wire;

import java.util.ArrayList;
import java.util.List;

/**
 * The server's messages encoded again (tests only): a consistency check of the decoders, never their reference (the
 * references are t_wire.c's bytes and the live server's frames). Samples laid out by hand from §4, after t_wire.c's
 * samples (lines 588-684).
 */
final class ServerEncoder {
    private ServerEncoder() {}

    static byte[] encode(Msg m, Msg.Columns cols) throws WireException {
        Buf b = new Buf();
        switch (m.type) {
        case Wire.COLUMNS:
            b.u16(((Msg.Columns) m).columns.size());
            for (Msg.Column c : ((Msg.Columns) m).columns) {
                Frames.text(b, 1, 1, Wire.COLNAME_MAX, Utf8.encode(c.name), "a name");
                b.u8(c.type);
                b.u16(c.precision);
                b.u16(c.scale);
                if (c.type == Wire.T_ENUM) {
                    b.u16(c.labels.size());
                    for (String l : c.labels) Frames.text(b, 1, 0, Wire.LABEL_MAX, Utf8.encode(l), "a label");
                }
            }
            break;
        case Wire.ROWS:
            b.u32(((Msg.Rows) m).rows.size());
            for (Value[] r : ((Msg.Rows) m).rows)
                for (Value v : r) v.encode(b);
            break;
        case Wire.DONE: {
            Msg.Done d = (Msg.Done) m;
            Frames.text(b, 2, 0, Wire.STATUS_MAX, Utf8.encode(d.status), "a status");
            b.u64(d.count);
            b.u8(d.read != null ? 1 : 0);
            if (d.read != null) {
                b.u64(d.read.commit);
                b.put(d.read.hash);
                b.put(d.read.digest);
                b.u64(d.read.lakeCommit);
                b.put(d.read.lakeManifest);
                b.put(d.read.dbId);
                b.u8(d.read.own ? 1 : 0);
            }
            b.u8(d.writeHash != null ? 1 : 0);
            if (d.writeHash != null) {
                b.u64(d.writeCommit);
                b.put(d.writeHash);
            }
            break;
        }
        case Wire.ERROR: {
            Msg.Error e = (Msg.Error) m;
            b.u32(e.code);
            b.u32(e.index);
            Frames.text(b, 2, 0, Wire.MESSAGE_MAX, Utf8.encode(e.message), "a message");
            break;
        }
        case Wire.WARNING: Frames.text(b, 2, 0, Wire.MESSAGE_MAX, Utf8.encode(((Msg.Warning) m).message), "a message"); break;
        case Wire.COPY_OUT: b.put(((Msg.CopyOut) m).data); break;
        case Wire.READY: b.u8(((Msg.Ready) m).state); break;
        case Wire.SESSIONS_LIST:
            b.u32(((Msg.SessionsList) m).sessions.size());
            for (Msg.Session s : ((Msg.SessionsList) m).sessions) {
                b.u64(s.id);
                b.u32(s.role);
                b.u8(s.endpoint);
                b.u8(s.state);
                b.u64(s.ageMs);
                Frames.text(b, 1, 0, 63, Utf8.encode(s.name), "a name");
            }
            break;
        case Wire.KILL_DONE:
            b.u8(((Msg.KillDone) m).code);
            b.u64(((Msg.KillDone) m).session);
            break;
        default: break; // COPY_IN, PONG: no body
        }
        return b.bytes();
    }

    static byte[][] s(int type, String hex) { return new byte[][] {{(byte) type}, Der.unhex(hex)}; }

    /** one of every server message; the first is the COLUMNS the ROWS are read against */
    static List<byte[][]> samples() {
        String z = "";
        List<byte[][]> v = new ArrayList<>();
        v.add(s(Wire.COLUMNS, "0400 026964 01 2000 0000 06616d6f756e74 05 2600 0600 046e616d65 04 0c00 0000 046d6f6f64 0d 0000 0000 0300 00 0178 02c3a9"));
        v.add(s(Wire.ROWS, "02000000 01 00000080ffffffff 05 06 7929edffffffffffffffffffffffffff 04 06000000 68c3a96c6c6f 0d 01 78"
                + " 81 05 06 ffffffff3f228a097ac4865aa84c3b4b 04 00000000 0d 00"));
        v.add(s(Wire.DONE, "0a00 494e5345525420302033 0300000000000000 01 2900000000000000 " + "01".repeat(32) + " " + "02".repeat(32)
                + " 2c00000000000000 " + "03".repeat(32) + " " + "04".repeat(16) + " 01 01 2a00000000000000 " + "05".repeat(32)));
        v.add(s(Wire.DONE, "0000 0000000000000000 00 00"));
        v.add(s(Wire.DONE, "0800 53454c4543542030 0000000000000000 01 0000000000000000 " + "00".repeat(32) + " " + "00".repeat(32)
                + " 0000000000000000 " + "00".repeat(32) + " " + "00".repeat(16) + " 00 00"));
        v.add(s(Wire.ERROR, "05000000 02000000 0500 424547494e"));
        v.add(s(Wire.WARNING, "0200 c3a9"));
        v.add(s(Wire.COPY_IN, z));
        v.add(s(Wire.COPY_OUT, "312c320a"));
        v.add(s(Wire.READY, "02"));
        v.add(s(Wire.PONG, z));
        v.add(s(Wire.SESSIONS_LIST, "02000000 0300000000000000 07000000 01 03 ffffffffffffffff 03 68c3a9 0400000000000000 ffffffff 02 00 0000000000000000 00"));
        v.add(s(Wire.SESSIONS_LIST, "00000000"));
        v.add(s(Wire.KILL_DONE, "00 0900000000000000"));
        v.add(s(Wire.KILL_DONE, "01 ffffffffffffffff"));
        return v;
    }
}
