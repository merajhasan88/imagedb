using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace Imagedb.Client.Wire;

/// <summary>IMDBWIR1's bytes (docs/n1-design.md §4; server/wire.c is the tiebreak). Each decoder is strict: exact
/// lengths, no trailing bytes, zero padding, every count bounded by the bytes left before anything is sized by it; a
/// later protocol refused by name (code 12), a length past its bound as a limit (code 3), anything else as damage (code
/// 2). Each field has one predicate, applied by its decoder and its encoder, so an encoder never writes what its decoder
/// refuses (it throws ArgumentException instead) and any bytes a decoder takes encode back to themselves.</summary>
public static class Codec
{
    internal static ImdbProtocolException Corrupt(string what) => new(ImdbErrorCode.Corrupt, "IMDBWIR1: " + what);
    internal static ImdbProtocolException Limit(string what) => new(ImdbErrorCode.Limit, "IMDBWIR1: " + what);
    internal static ImdbProtocolException Unsupported(string what) => new(ImdbErrorCode.Unsupported, "IMDBWIR1: " + what);

    private static readonly byte[] MagicBytes = Encoding.ASCII.GetBytes(Protocol.Magic);
    private static readonly byte[] AuthMagic = Encoding.ASCII.GetBytes("IMDBWIR1-SCRAM");

    // =============================== values ===============================

    /// <summary>A value's bytes (its tag, then its bytes).</summary>
    public static byte[] EncodeValue(in ImdbValue v)
    {
        var w = new ByteWriter(32);
        WriteValue(w, v);
        return w.ToArray();
    }

    /// <summary>One value from the start of b; consumed its bytes.</summary>
    public static ImdbValue DecodeValue(ReadOnlySpan<byte> b, out int consumed)
    {
        var r = new ByteReader(b);
        var v = ReadValue(ref r, null);
        consumed = r.Offset;
        return v;
    }

    internal static void WriteValue(ByteWriter w, in ImdbValue v)
    {
        if (v.IsNull)
        {
            w.U8((byte)(Protocol.NullTag | (byte)v.Type));
            return;
        }
        w.U8((byte)v.Type);
        switch (v.Type)
        {
            case ImdbType.Float64:
            case ImdbType.Int64:
            case ImdbType.Timestamp:
            case ImdbType.TimestampTz:
            case ImdbType.Time:
                w.U64((ulong)v.RawI);
                break;
            case ImdbType.Bool:
                w.U8((byte)v.RawI);
                break;
            case ImdbType.Text:
            {
                var b = Encoding.UTF8.GetBytes((string)v.RawRef!); // checked at FromText: strict, no NUL, at most 65,535
                w.U32((uint)b.Length);
                w.Bytes(b);
                break;
            }
            case ImdbType.Bytea:
            {
                var b = (byte[])v.RawRef!;
                w.U32((uint)b.Length);
                w.Bytes(b);
                break;
            }
            case ImdbType.Enum:
            {
                var b = Encoding.UTF8.GetBytes((string)v.RawRef!);
                w.U8((byte)b.Length);
                w.Bytes(b);
                break;
            }
            case ImdbType.Decimal:
                w.U8(v.RawScale);
                w.I128(v.RawD);
                break;
            case ImdbType.Date:
                w.U32((uint)v.RawDays);
                break;
            case ImdbType.Uuid:
                w.Bytes((byte[])v.RawRef!);
                break;
            case ImdbType.Interval:
                w.U32((uint)v.RawMonths);
                w.U32((uint)v.RawDays);
                w.U64((ulong)v.RawI);
                break;
            default:
                throw new ArgumentException("a value of no type: only a NULL has none");
        }
    }

    /// <summary>A value, and when col is given, held to it (ROWS' rule, wire.c's imdbw_value_fits).</summary>
    internal static ImdbValue ReadValue(ref ByteReader r, ImdbColumn? col)
    {
        byte tag = r.U8();
        ImdbValue v;
        if ((tag & Protocol.NullTag) != 0)
        {
            int t = tag & ~Protocol.NullTag;
            if (t > (int)ImdbType.Enum) throw Corrupt("a NULL of a type the protocol does not define");
            v = ImdbValue.Null((ImdbType)t);
            if (col != null && col.Type != ImdbType.None && col.Type != v.Type) throw Corrupt("a value its column does not take");
            return v;
        }
        switch ((ImdbType)tag)
        {
            case ImdbType.Int64:
                v = ImdbValue.Raw(ImdbType.Int64, (long)r.U64());
                break;
            case ImdbType.Timestamp:
            case ImdbType.TimestampTz:
            {
                long us = (long)r.U64();
                if (us < Protocol.TimestampMin || us > Protocol.TimestampMax) throw Corrupt("a value outside its type's rules");
                v = ImdbValue.Raw((ImdbType)tag, us);
                break;
            }
            case ImdbType.Time:
            {
                long us = (long)r.U64();
                if (us < 0 || us > Protocol.TimeMax) throw Corrupt("a value outside its type's rules");
                v = ImdbValue.Raw(ImdbType.Time, us);
                break;
            }
            case ImdbType.Float64:
            {
                ulong bits = r.U64();
                if (((bits >> 52) & 0x7ff) == 0x7ff || bits == 0x8000000000000000UL) throw Corrupt("a value outside its type's rules");
                v = ImdbValue.Raw(ImdbType.Float64, (long)bits);
                break;
            }
            case ImdbType.Bool:
            {
                byte b = r.U8();
                if (b > 1) throw Corrupt("a value outside its type's rules");
                v = ImdbValue.Raw(ImdbType.Bool, b);
                break;
            }
            case ImdbType.Text:
            case ImdbType.Bytea:
            case ImdbType.Enum:
            {
                bool isEnum = tag == (byte)ImdbType.Enum;
                uint len = isEnum ? r.U8() : r.U32();
                uint max = isEnum ? (uint)Protocol.LabelMax : Protocol.ValueMax;
                if (len > max) throw Limit($"a value of {len} bytes (at most {max})"); // before its bytes are asked for
                var s = r.Bytes((int)len);
                if (tag == (byte)ImdbType.Bytea)
                {
                    v = ImdbValue.Raw(ImdbType.Bytea, r: s.ToArray());
                    break;
                }
                if (!StrictUtf8.IsValid(s)) throw Corrupt("a value outside its type's rules");
                v = ImdbValue.Raw((ImdbType)tag, r: Encoding.UTF8.GetString(s));
                break;
            }
            case ImdbType.Decimal:
            {
                byte scale = r.U8();
                Int128 d = r.I128();
                if (scale > 38 || !ImdbDecimal.InRange(d, 38)) throw Corrupt("a value outside its type's rules");
                v = ImdbValue.Raw(ImdbType.Decimal, d: d, scale: scale);
                break;
            }
            case ImdbType.Date:
            {
                int days = (int)r.U32();
                if (days < Protocol.DateMin || days > Protocol.DateMax) throw Corrupt("a value outside its type's rules");
                v = ImdbValue.Raw(ImdbType.Date, day: days);
                break;
            }
            case ImdbType.Uuid:
                v = ImdbValue.Raw(ImdbType.Uuid, r: r.Bytes(16).ToArray());
                break;
            case ImdbType.Interval:
            {
                int mon = (int)r.U32(), day = (int)r.U32();
                long us = (long)r.U64();
                v = ImdbValue.Raw(ImdbType.Interval, us, mon: mon, day: day);
                break;
            }
            default:
                throw Corrupt("a value of a type the protocol does not define (a NULL's tag is 0x80 and its type)");
        }
        if (col != null && !Fits(col, v)) throw Corrupt("a value its column does not take");
        return v;
    }

    /// <summary>ROWS' rule: NULL or its column's type, at the column's scale and within its precision, an integer
    /// within its width, a TEXT within its VARCHAR's characters (checked on the bytes by ReadValue), an ENUM one of its
    /// labels; any value under a column of no type.</summary>
    internal static bool Fits(ImdbColumn c, in ImdbValue v)
    {
        if (c.Type == ImdbType.None) return true;
        if (v.Type != c.Type) return false;
        if (v.IsNull) return true;
        switch (c.Type)
        {
            case ImdbType.Decimal:
                return v.RawScale == c.Scale && ImdbDecimal.InRange(v.RawD, c.Precision != 0 ? c.Precision : 38);
            case ImdbType.Int64:
                return c.Precision == 16 ? v.RawI >= short.MinValue && v.RawI <= short.MaxValue
                     : c.Precision == 32 ? v.RawI >= int.MinValue && v.RawI <= int.MaxValue
                     : true;
            case ImdbType.Text:
                return c.Precision == 0 || CodePoints((string)v.RawRef!) <= c.Precision;
            case ImdbType.Enum:
                return c.HasLabel((string)v.RawRef!);
            default:
                return true;
        }
    }

    /// <summary>A valid string's characters (code points): a VARCHAR(n) counts these, never UTF-16 units (wire.c's
    /// utf8_chars over the bytes). A surrogate pair is one.</summary>
    internal static int CodePoints(string s)
    {
        int k = s.Length;
        foreach (char ch in s)
            if (char.IsLowSurrogate(ch)) k--;
        return k;
    }

    // =============================== texts ===============================

    private static string ReadText(ref ByteReader r, int lenBytes, int min, int max)
    {
        uint n = lenBytes == 1 ? r.U8() : lenBytes == 2 ? r.U16() : r.U32();
        if (n < min || n > max) throw Limit($"a text of {n} bytes ({min} to {max})");
        var s = r.Bytes((int)n);
        if (!StrictUtf8.IsValid(s)) throw Corrupt("a text not UTF-8 without NUL");
        return Encoding.UTF8.GetString(s);
    }

    private static void WriteText(ByteWriter w, int lenBytes, int min, int max, string s, string what)
    {
        var b = StrictUtf8.Encode(s, what);
        if (b.Length < min || b.Length > max)
            throw new ArgumentException($"{what}: {min} to {max} bytes of UTF-8 (this one {b.Length})", what);
        if (lenBytes == 1) w.U8((byte)b.Length);
        else if (lenBytes == 2) w.U16((ushort)b.Length);
        else w.U32((uint)b.Length);
        w.Bytes(b);
    }

    // =============================== frames ===============================

    /// <summary>A frame's head: its length (of its type and body: 1 to 16 MiB) and a type of the direction's, checked
    /// before anything is allocated for its body.</summary>
    public static FrameType DecodeHead(ReadOnlySpan<byte> head, bool fromServer, out int length)
    {
        if (head.Length != Protocol.HeadLength) throw new ArgumentException("a frame's head is 5 bytes", nameof(head));
        uint len = BinaryPrimitives.ReadUInt32LittleEndian(head);
        byte t = head[4];
        if (len < 1 || len > Protocol.FrameMax) throw Limit($"a frame of {len} bytes (1 to {Protocol.FrameMax})");
        bool known = fromServer ? t >= (byte)FrameType.Columns && t <= (byte)FrameType.KillDone
                                : t >= (byte)FrameType.Query && t <= (byte)FrameType.Kill;
        if (!known) throw Corrupt($"a frame of type {t}, which this side does not send");
        length = (int)len;
        return (FrameType)t;
    }

    // ---- the client's requests: encoders ----

    public static byte[] EncodeQuery(IReadOnlyList<ImdbStatement> statements)
    {
        ArgumentNullException.ThrowIfNull(statements);
        if (statements.Count < 1 || statements.Count > Protocol.BatchMax)
            throw new ArgumentException("a QUERY holds 1 to 4,096 statements", nameof(statements));
        var w = new ByteWriter();
        int at = w.BeginFrame(FrameType.Query);
        w.U32((uint)statements.Count);
        foreach (var st in statements)
        {
            WriteText(w, 4, 1, Protocol.SqlMax, st.Sql, "a statement");
            WriteParams(w, st.Parameters);
        }
        w.EndFrame(at);
        return w.ToArray();
    }

    private static void WriteParams(ByteWriter w, IReadOnlyList<ImdbValue> ps)
    {
        if (ps.Count > Protocol.ValuesMax) throw new ArgumentException("a statement takes at most 256 values");
        w.U16((ushort)ps.Count);
        foreach (var p in ps) WriteParam(w, p);
    }

    private static void WriteParam(ByteWriter w, in ImdbValue p)
    {
        if (p.Type == ImdbType.Enum && !p.IsNull)
            throw new ArgumentException("an ENUM parameter: a label is sent as TEXT (§4); only a NULL ENUM is a parameter");
        WriteValue(w, p);
    }

    public static byte[] EncodePrepare(string name, string sql)
    {
        var w = new ByteWriter();
        int at = w.BeginFrame(FrameType.Prepare);
        WriteText(w, 1, 1, Protocol.NameMax, name, "a prepared statement's name");
        WriteText(w, 4, 1, Protocol.SqlMax, sql, "a statement");
        w.EndFrame(at);
        return w.ToArray();
    }

    /// <summary>EXECUTE: 1 to 4,096 sets, each of the same count of values (0 to 256).</summary>
    public static byte[] EncodeExecute(string name, IReadOnlyList<IReadOnlyList<ImdbValue>> sets)
    {
        ArgumentNullException.ThrowIfNull(sets);
        if (sets.Count < 1 || sets.Count > Protocol.BatchMax)
            throw new ArgumentException("an EXECUTE holds 1 to 4,096 parameter sets", nameof(sets));
        int k = sets[0].Count;
        if (k > Protocol.ValuesMax) throw new ArgumentException("a parameter set holds at most 256 values", nameof(sets));
        var w = new ByteWriter();
        int at = w.BeginFrame(FrameType.Execute);
        WriteText(w, 1, 1, Protocol.NameMax, name, "a prepared statement's name");
        w.U32((uint)sets.Count);
        w.U16((ushort)k);
        foreach (var s in sets)
        {
            if (s.Count != k) throw new ArgumentException("every parameter set of an EXECUTE has the same count of values", nameof(sets));
            foreach (var p in s) WriteParam(w, p);
        }
        w.EndFrame(at);
        return w.ToArray();
    }

    public static byte[] EncodeDeallocate(string name)
    {
        var w = new ByteWriter();
        int at = w.BeginFrame(FrameType.Deallocate);
        WriteText(w, 1, 1, Protocol.NameMax, name, "a prepared statement's name");
        w.EndFrame(at);
        return w.ToArray();
    }

    public static byte[] EncodeCopyData(ReadOnlySpan<byte> data)
    {
        if (data.Length < 1) throw new ArgumentException("a COPY_DATA holds at least one byte", nameof(data));
        if (data.Length > Protocol.FrameMax - 1) throw new ArgumentException("a COPY_DATA past a frame", nameof(data));
        var f = new byte[Protocol.HeadLength + data.Length];
        BinaryPrimitives.WriteUInt32LittleEndian(f, (uint)(data.Length + 1));
        f[4] = (byte)FrameType.CopyData;
        data.CopyTo(f.AsSpan(Protocol.HeadLength));
        return f;
    }

    public static byte[] EncodeCopyFail(string reason)
    {
        var w = new ByteWriter();
        int at = w.BeginFrame(FrameType.CopyFail);
        WriteText(w, 2, 0, Protocol.MessageMax, reason, "a COPY_FAIL's reason");
        w.EndFrame(at);
        return w.ToArray();
    }

    /// <summary>A frame with no body: COPY_DONE, CANCEL, PING, TERMINATE, SESSIONS (or the server's COPY_IN, PONG).</summary>
    public static byte[] EncodeEmpty(FrameType t)
    {
        if (t is not (FrameType.CopyDone or FrameType.Cancel or FrameType.Ping or FrameType.Terminate or FrameType.Sessions
                      or FrameType.CopyIn or FrameType.Pong))
            throw new ArgumentException($"{t} has a body", nameof(t));
        return new byte[] { 1, 0, 0, 0, (byte)t };
    }

    public static byte[] EncodeKill(ImdbKillKind kind, ulong sessionId)
    {
        if (kind is not (ImdbKillKind.Cancel or ImdbKillKind.Terminate)) throw new ArgumentException("a KILL's kind: cancel or terminate", nameof(kind));
        if (sessionId == 0) throw new ArgumentException("a KILL's session id is at least 1 (an id from SESSIONS)", nameof(sessionId));
        var w = new ByteWriter(16);
        int at = w.BeginFrame(FrameType.Kill);
        w.U8((byte)kind);
        w.U64(sessionId);
        w.EndFrame(at);
        return w.ToArray();
    }

    // ---- the server's replies: the strict decoders ----

    /// <summary>A server frame's body decoded: a ROWS against the COLUMNS before it (columns), each value its column's.</summary>
    public static WireMessage DecodeServerBody(FrameType type, ReadOnlySpan<byte> body, ColumnsMessage? columns)
    {
        var r = new ByteReader(body);
        WireMessage m = type switch
        {
            FrameType.Columns => ReadColumns(ref r),
            FrameType.Rows => ReadRows(ref r, columns),
            FrameType.Done => ReadDone(ref r),
            FrameType.Error => ReadError(ref r),
            FrameType.Warning => new TextMessage(FrameType.Warning, ReadText(ref r, 2, 0, Protocol.MessageMax)),
            FrameType.CopyIn => new EmptyMessage(FrameType.CopyIn),
            FrameType.CopyOut => ReadData(ref r, FrameType.CopyOut),
            FrameType.Ready => ReadReady(ref r),
            FrameType.Pong => new EmptyMessage(FrameType.Pong),
            FrameType.SessionsList => ReadSessions(ref r),
            FrameType.KillDone => ReadKillDone(ref r),
            _ => throw Corrupt($"a frame of type {(byte)type}, which the server does not send"),
        };
        if (r.Left != 0) throw Corrupt("a body with bytes past its end");
        return m;
    }

    private static DataMessage ReadData(ref ByteReader r, FrameType t)
    {
        if (r.Left < 1) throw Corrupt("a COPY piece of no bytes");
        return new DataMessage(t, r.Bytes(r.Left).ToArray());
    }

    private static ColumnsMessage ReadColumns(ref ByteReader r)
    {
        ushort n = r.U16();
        if (n < 1 || n > Protocol.ValuesMax || n > r.Left / 7) // a column: 7 bytes at least
            throw Corrupt("a COLUMNS of 1 to 256 columns it holds the bytes of");
        var cols = new ImdbColumn[n];
        for (int i = 0; i < n; i++)
        {
            string name = ReadText(ref r, 1, 1, Protocol.ColumnNameMax);
            byte type = r.U8();
            ushort precision = r.U16(), scale = r.U16();
            string[]? labels = null;
            if (type == (byte)ImdbType.Enum)
            {
                ushort nl = r.U16();
                if (nl > Protocol.LabelsMax || nl > r.Left) throw Corrupt("an ENUM's labels past their bounds or bytes");
                labels = new string[nl];
                for (int k = 0; k < nl; k++) labels[k] = ReadText(ref r, 1, 0, Protocol.LabelMax);
            }
            if (!ColumnShapeOk(type, precision, scale)) throw Corrupt("a column's type, precision or scale its type does not take");
            var c = new ImdbColumn(name, (ImdbType)type, precision, scale, labels);
            if (labels != null && !c.LabelsDistinct()) throw Corrupt("an ENUM's labels not distinct");
            cols[i] = c;
        }
        return new ColumnsMessage(cols);
    }

    internal static bool ColumnShapeOk(byte type, ushort precision, ushort scale) => type switch
    {
        (byte)ImdbType.Decimal => precision <= 38 && scale <= (precision != 0 ? precision : 38), // 0: not known, 38 digits
        (byte)ImdbType.Int64 => (precision == 0 || precision == 16 || precision == 32) && scale == 0,
        (byte)ImdbType.Text => scale == 0, // precision: a VARCHAR's length (0 none)
        <= (byte)ImdbType.Enum => precision == 0 && scale == 0,
        _ => false,
    };

    private static RowsMessage ReadRows(ref ByteReader r, ColumnsMessage? cols)
    {
        if (cols == null) throw Corrupt("a ROWS with no COLUMNS before it");
        uint n = r.U32();
        if (n < 1) throw Corrupt("a ROWS of no row");
        int nc = cols.Columns.Count;
        if ((ulong)n * (ulong)nc > (ulong)r.Left) throw Corrupt("more values than bytes"); // each value is a byte at least
        var rows = new ImdbValue[n][];
        for (uint i = 0; i < n; i++)
        {
            var row = new ImdbValue[nc];
            for (int k = 0; k < nc; k++) row[k] = ReadValue(ref r, cols.Columns[k]);
            rows[i] = row;
        }
        return new RowsMessage(rows);
    }

    private static DoneMessage ReadDone(ref ByteReader r)
    {
        string status = ReadText(ref r, 2, 0, Protocol.StatusMax);
        ulong count = r.U64();
        byte hr = r.U8();
        if (hr > 1) throw Corrupt("a DONE's read point flag");
        ImdbReadPoint? read = null;
        if (hr == 1)
        {
            ulong commit = r.U64();
            var hash = r.Bytes(32).ToArray();
            var digest = r.Bytes(32).ToArray();
            ulong lake = r.U64();
            var manifest = r.Bytes(32).ToArray();
            var dbid = r.Bytes(16).ToArray();
            byte own = r.U8();
            if (own > 1) throw Corrupt("a DONE's own-writes flag");
            read = new ImdbReadPoint(commit, hash, digest, lake, manifest, dbid, own == 1);
        }
        byte hw = r.U8();
        if (hw > 1) throw Corrupt("a DONE's write flag");
        ImdbWriteCommit? write = null;
        if (hw == 1)
        {
            ulong commit = r.U64();
            var hash = r.Bytes(32).ToArray();
            if (commit < 1) throw Corrupt("a DONE's write at commit 0");
            write = new ImdbWriteCommit(commit, hash);
        }
        return new DoneMessage(status, count, read, write);
    }

    private static ErrorMessage ReadError(ref ByteReader r)
    {
        uint code = r.U32(), index = r.U32();
        if (code == 0 || index >= Protocol.BatchMax) throw Corrupt("an ERROR's code 0 or its statement's index");
        return new ErrorMessage(code, index, ReadText(ref r, 2, 0, Protocol.MessageMax));
    }

    private static ReadyMessage ReadReady(ref ByteReader r)
    {
        byte s = r.U8();
        if (s > (byte)ImdbTransactionState.Doomed) throw Corrupt("a READY's state");
        return new ReadyMessage((ImdbTransactionState)s);
    }

    private const int SessionMin = 23; // u64 id, u32 role, u8 endpoint, u8 state, u64 age, u8 length

    private static SessionsListMessage ReadSessions(ref ByteReader r)
    {
        uint n = r.U32();
        if (n > Protocol.SessionsMax || n > r.Left / SessionMin)
            throw Corrupt("a SESSIONS_LIST of at most 65,536 sessions it holds the bytes of");
        var s = new ImdbSession[n];
        ulong prev = 0;
        for (int i = 0; i < n; i++)
        {
            ulong id = r.U64();
            uint role = r.U32();
            byte ep = r.U8(), st = r.U8();
            ulong age = r.U64();
            string name = ReadText(ref r, 1, 0, Protocol.UserField - 1);
            if (id <= prev || role == 0 || (ep != 1 && ep != 2) || st > (byte)ImdbSessionState.ReceivingCopy)
                throw Corrupt("a session's id out of order, or its role, endpoint or state");
            s[i] = new ImdbSession(id, role, (ImdbEndpoint)ep, (ImdbSessionState)st, age, name);
            prev = id;
        }
        return new SessionsListMessage(s);
    }

    private static KillDoneMessage ReadKillDone(ref ByteReader r)
    {
        byte code = r.U8();
        ulong sid = r.U64();
        if (code > 1 || sid == 0) throw Corrupt("a KILL_DONE's code or a session id of 0");
        return new KillDoneMessage(code, sid);
    }

    // ---- the client's requests: strict decoders (a server's side: the tests' mock, and the encoders' round trip) ----

    public static WireMessage DecodeClientBody(FrameType type, ReadOnlySpan<byte> body)
    {
        var r = new ByteReader(body);
        WireMessage m;
        switch (type)
        {
            case FrameType.Query:
            {
                uint n = r.U32();
                if (n < 1 || n > Protocol.BatchMax || n > r.Left / 7) // a statement: 7 bytes at least
                    throw Corrupt("a QUERY of 1 to 4,096 statements it holds the bytes of");
                var st = new ImdbStatement[n];
                for (int i = 0; i < n; i++)
                {
                    string sql = ReadText(ref r, 4, 1, Protocol.SqlMax);
                    ushort k = r.U16();
                    if (k > Protocol.ValuesMax) throw Corrupt("a statement's values: at most 256");
                    st[i] = new ImdbStatement(sql, ReadParams(ref r, k));
                }
                m = new QueryMessage(st);
                break;
            }
            case FrameType.Prepare:
            {
                string name = ReadText(ref r, 1, 1, Protocol.NameMax);
                m = new PreparedMessage(FrameType.Prepare, name, ReadText(ref r, 4, 1, Protocol.SqlMax));
                break;
            }
            case FrameType.Execute:
            {
                string name = ReadText(ref r, 1, 1, Protocol.NameMax);
                uint sets = r.U32();
                ushort nv = r.U16();
                if (sets < 1 || sets > Protocol.BatchMax || nv > Protocol.ValuesMax)
                    throw Corrupt("an EXECUTE of 1 to 4,096 sets of at most 256 values");
                if ((ulong)sets * nv > (ulong)r.Left) throw Corrupt("more values than bytes");
                var all = new ImdbValue[sets][];
                for (int i = 0; i < sets; i++) all[i] = ReadParams(ref r, nv);
                m = new PreparedMessage(FrameType.Execute, name, null, nv, all);
                break;
            }
            case FrameType.Deallocate:
                m = new PreparedMessage(FrameType.Deallocate, ReadText(ref r, 1, 1, Protocol.NameMax));
                break;
            case FrameType.Kill:
            {
                byte kind = r.U8();
                ulong sid = r.U64();
                if ((kind != 1 && kind != 2) || sid == 0) throw Corrupt("a KILL's kind (1 cancel, 2 terminate) or a session id of 0");
                m = new KillMessage((ImdbKillKind)kind, sid);
                break;
            }
            case FrameType.CopyData:
                m = ReadData(ref r, FrameType.CopyData);
                break;
            case FrameType.CopyFail:
                m = new TextMessage(FrameType.CopyFail, ReadText(ref r, 2, 0, Protocol.MessageMax));
                break;
            case FrameType.CopyDone:
            case FrameType.Cancel:
            case FrameType.Ping:
            case FrameType.Terminate:
            case FrameType.Sessions:
                m = new EmptyMessage(type);
                break;
            default:
                throw Corrupt($"a frame of type {(byte)type}, which a client does not send");
        }
        if (r.Left != 0) throw Corrupt("a body with bytes past its end");
        return m;
    }

    private static ImdbValue[] ReadParams(ref ByteReader r, int k)
    {
        if (k > r.Left) throw Corrupt("more values than bytes");
        var v = new ImdbValue[k];
        for (int i = 0; i < k; i++)
        {
            v[i] = ReadValue(ref r, null);
            if (v[i].Type == ImdbType.Enum && !v[i].IsNull) throw Corrupt("an ENUM parameter: a label is sent as TEXT");
        }
        return v;
    }

    // ---- the server's replies: encoders (a server's side: the tests' mock, and the decoders' round trip) ----

    public static byte[] EncodeServer(WireMessage m, ColumnsMessage? columns = null)
    {
        var w = new ByteWriter();
        int at = w.BeginFrame(m.Type);
        switch (m)
        {
            case ColumnsMessage c:
                if (c.Columns.Count < 1 || c.Columns.Count > Protocol.ValuesMax) throw new ArgumentException("COLUMNS: 1 to 256 columns");
                w.U16((ushort)c.Columns.Count);
                foreach (var col in c.Columns)
                {
                    if (!ColumnShapeOk((byte)col.Type, col.Precision, col.Scale) || (col.Type != ImdbType.Enum && col.Labels.Count > 0)
                        || col.Labels.Count > Protocol.LabelsMax || !col.LabelsDistinct())
                        throw new ArgumentException("COLUMNS: a column its decoder refuses");
                    WriteText(w, 1, 1, Protocol.ColumnNameMax, col.Name, "a column's name");
                    w.U8((byte)col.Type);
                    w.U16(col.Precision);
                    w.U16(col.Scale);
                    if (col.Type == ImdbType.Enum)
                    {
                        w.U16((ushort)col.Labels.Count);
                        foreach (var l in col.Labels) WriteText(w, 1, 0, Protocol.LabelMax, l, "a label");
                    }
                }
                break;
            case RowsMessage rm:
                if (columns == null || rm.Rows.Length < 1) throw new ArgumentException("ROWS: at least one row, against its COLUMNS");
                w.U32((uint)rm.Rows.Length);
                foreach (var row in rm.Rows)
                {
                    if (row.Length != columns.Columns.Count) throw new ArgumentException("ROWS: a row of another count of values");
                    for (int k = 0; k < row.Length; k++)
                    {
                        if (!Fits(columns.Columns[k], row[k])) throw new ArgumentException("ROWS: a value its column does not take");
                        WriteValue(w, row[k]);
                    }
                }
                break;
            case DoneMessage d:
                WriteText(w, 2, 0, Protocol.StatusMax, d.Status, "a status");
                w.U64(d.Count);
                w.U8(d.Read != null ? (byte)1 : (byte)0);
                if (d.Read is { } rp)
                {
                    w.U64(rp.Commit);
                    w.Bytes(Exact(rp.CommitHash, 32));
                    w.Bytes(Exact(rp.StateDigest, 32));
                    w.U64(rp.LakeCommit);
                    w.Bytes(Exact(rp.LakeManifest, 32));
                    w.Bytes(Exact(rp.DatabaseId, 16));
                    w.U8(rp.OwnWrites ? (byte)1 : (byte)0);
                }
                w.U8(d.Write != null ? (byte)1 : (byte)0);
                if (d.Write is { } wc)
                {
                    if (wc.Commit < 1) throw new ArgumentException("DONE: a write at commit 0");
                    w.U64(wc.Commit);
                    w.Bytes(Exact(wc.CommitHash, 32));
                }
                break;
            case ErrorMessage e:
                if (e.Code == 0 || e.Index >= Protocol.BatchMax) throw new ArgumentException("ERROR: code 0 or its index");
                w.U32(e.Code);
                w.U32(e.Index);
                WriteText(w, 2, 0, Protocol.MessageMax, e.Message, "a message");
                break;
            case TextMessage t when t.Type is FrameType.Warning or FrameType.CopyFail:
                WriteText(w, 2, 0, Protocol.MessageMax, t.Text, "a message");
                break;
            case DataMessage dm when dm.Type is FrameType.CopyOut or FrameType.CopyData:
                if (dm.Data.Length < 1) throw new ArgumentException("a COPY piece of no bytes");
                w.Bytes(dm.Data);
                break;
            case ReadyMessage rd:
                w.U8((byte)rd.State);
                break;
            case EmptyMessage:
                break;
            case SessionsListMessage sl:
            {
                if (sl.Sessions.Count > Protocol.SessionsMax) throw new ArgumentException("SESSIONS_LIST: at most 65,536");
                w.U32((uint)sl.Sessions.Count);
                ulong prev = 0;
                foreach (var s in sl.Sessions)
                {
                    if (s.Id <= prev || s.RoleId == 0 || (s.Endpoint != ImdbEndpoint.Tcp && s.Endpoint != ImdbEndpoint.Socket)
                        || (byte)s.State > 3)
                        throw new ArgumentException("SESSIONS_LIST: a session its decoder refuses");
                    w.U64(s.Id);
                    w.U32(s.RoleId);
                    w.U8((byte)s.Endpoint);
                    w.U8((byte)s.State);
                    w.U64(s.AgeMilliseconds);
                    WriteText(w, 1, 0, Protocol.UserField - 1, s.RoleName, "a role's name");
                    prev = s.Id;
                }
                break;
            }
            case KillDoneMessage kd:
                if (kd.Code > 1 || kd.SessionId == 0) throw new ArgumentException("KILL_DONE: its code or session 0");
                w.U8(kd.Code);
                w.U64(kd.SessionId);
                break;
            default:
                throw new ArgumentException($"no server frame {m.Type}");
        }
        w.EndFrame(at);
        return w.ToArray();
    }

    private static byte[] Exact(byte[] b, int n) => b.Length == n ? b : throw new ArgumentException($"a field of {n} bytes");

    // =============================== before authentication ===============================

    private static bool IsLaterMagic(ReadOnlySpan<byte> m)
    {
        // util.c's imdb_later_magic: the same letters, then a higher number ("IMDBWIR2" is another protocol)
        if (m.Length < 8 || !m[..7].SequenceEqual(MagicBytes.AsSpan(0, 7))) return false;
        return m[7] >= (byte)'0' && m[7] <= (byte)'9' && m[7] > (byte)'1';
    }

    private static void CheckMagic(ReadOnlySpan<byte> m)
    {
        if (m[..8].SequenceEqual(MagicBytes)) return;
        if (IsLaterMagic(m)) throw Unsupported($"{Encoding.ASCII.GetString(m[..8])}, a later protocol, which this driver does not speak");
        throw Corrupt("not imagedb's protocol");
    }

    /// <summary>The 12 bytes every pre-auth message begins with, in every version: the version (any number; a later
    /// magic refused by name, another magic and version 0 as damage).</summary>
    public static uint DecodePreauthHead(ReadOnlySpan<byte> head)
    {
        if (head.Length < Protocol.PreauthHeadLength) throw Corrupt("a pre-auth head cut short");
        CheckMagic(head);
        uint v = BinaryPrimitives.ReadUInt32LittleEndian(head[8..]);
        if (v < 1) throw Corrupt("protocol version 0");
        return v;
    }

    private static void MagicVersion(ref ByteReader r)
    {
        CheckMagic(r.Bytes(8));
        uint v = r.U32();
        if (v > Protocol.Version) throw Unsupported($"protocol version {v}, a later one, which this driver (version 1) does not speak");
        if (v != Protocol.Version) throw Corrupt("an unknown protocol version");
    }

    public static bool UserOk(string user, out byte[] bytes)
    {
        bytes = Array.Empty<byte>();
        if (user == null || user.Contains('\0', StringComparison.Ordinal)) return false;
        try
        {
            bytes = StrictUtf8.Encode(user, "user");
        }
        catch (ArgumentException)
        {
            return false;
        }
        return bytes.Length >= 1 && bytes.Length < Protocol.UserField;
    }

    public static byte[] EncodeHello(ChannelBindingType flags, string user, ReadOnlySpan<byte> nonce)
    {
        if ((uint)flags > (uint)ChannelBindingType.ServerEndPoint) throw new ArgumentException("a binding type 0, 1 or 2", nameof(flags));
        if (!UserOk(user, out var u)) throw new ArgumentException("a role's name is 1 to 63 bytes of UTF-8 without NUL", nameof(user));
        if (nonce.Length != Protocol.NonceLength) throw new ArgumentException("a nonce of 32 bytes", nameof(nonce));
        var b = new byte[Protocol.HelloLength];
        MagicBytes.CopyTo(b, 0);
        BinaryPrimitives.WriteUInt32LittleEndian(b.AsSpan(8), Protocol.Version);
        BinaryPrimitives.WriteUInt32LittleEndian(b.AsSpan(12), (uint)flags);
        u.CopyTo(b, 16);
        nonce.CopyTo(b.AsSpan(16 + Protocol.UserField));
        return b;
    }

    public static Hello DecodeHello(ReadOnlySpan<byte> b)
    {
        if (b.Length != Protocol.HelloLength) throw Corrupt("a hello of another length");
        var r = new ByteReader(b);
        MagicVersion(ref r);
        uint flags = r.U32();
        var u = r.Bytes(Protocol.UserField);
        var nonce = r.Bytes(Protocol.NonceLength).ToArray();
        if (flags > (uint)ChannelBindingType.ServerEndPoint) throw Corrupt("a hello with flags no version defines (a binding type but 0, 1, 2)");
        int n = u.IndexOf((byte)0);
        if (n < 0) n = Protocol.UserField;
        if (n == Protocol.UserField || n < 1 || !StrictUtf8.IsValid(u[..n]) || u[n..].ContainsAnyExcept((byte)0))
            throw Corrupt("a hello's role name is not 1 to 63 bytes of UTF-8, NUL-padded");
        return new Hello(Protocol.Version, (ChannelBindingType)flags, Encoding.UTF8.GetString(u[..n]), nonce);
    }

    private static bool ChallengeOk(int saltLen, uint iter) =>
        saltLen >= Protocol.SaltMin && saltLen <= Protocol.SaltField && iter >= Protocol.IterationsMin && iter <= Protocol.IterationsMax;

    public static byte[] EncodeChallenge(ReadOnlySpan<byte> salt, uint iterations, ReadOnlySpan<byte> nonce)
    {
        if (!ChallengeOk(salt.Length, iterations) || nonce.Length != Protocol.NonceLength)
            throw new ArgumentException("a challenge's salt is 8 to 64 bytes, its iterations 1,000 to 1,000,000");
        var b = new byte[Protocol.ChallengeLength];
        MagicBytes.CopyTo(b, 0);
        BinaryPrimitives.WriteUInt32LittleEndian(b.AsSpan(8), Protocol.Version);
        b[12] = (byte)salt.Length;
        salt.CopyTo(b.AsSpan(13));
        BinaryPrimitives.WriteUInt32LittleEndian(b.AsSpan(13 + Protocol.SaltField), iterations);
        nonce.CopyTo(b.AsSpan(17 + Protocol.SaltField));
        return b; // then 7 zeros
    }

    public static Challenge DecodeChallenge(ReadOnlySpan<byte> b)
    {
        if (b.Length != Protocol.ChallengeLength) throw Corrupt("a challenge of another length");
        var r = new ByteReader(b);
        MagicVersion(ref r);
        byte sl = r.U8();
        var salt = r.Bytes(Protocol.SaltField);
        uint iter = r.U32();
        var nonce = r.Bytes(Protocol.NonceLength).ToArray();
        var pad = r.Bytes(7);
        if (!ChallengeOk(sl, iter) || salt[sl..].ContainsAnyExcept((byte)0))
            throw Corrupt("a challenge's salt is not 8 to 64 bytes, zero-padded, or its iterations not 1,000 to 1,000,000");
        if (pad.ContainsAnyExcept((byte)0)) throw Corrupt("a challenge's padding is not zero");
        return new Challenge(Protocol.Version, salt[..sl].ToArray(), iter, nonce);
    }

    public static byte[] EncodeVerdict(uint code, ReadOnlySpan<byte> signature)
    {
        if (signature.Length != Protocol.KeyLength || !VerdictOk(code, signature)) throw new ArgumentException("a verdict its decoder refuses");
        var b = new byte[Protocol.VerdictLength];
        BinaryPrimitives.WriteUInt32LittleEndian(b, code);
        signature.CopyTo(b.AsSpan(4));
        return b;
    }

    private static bool VerdictOk(uint code, ReadOnlySpan<byte> sig) =>
        code == 0 || ((code == 1 || code == 2) && !sig.ContainsAnyExcept((byte)0));

    public static Verdict DecodeVerdict(ReadOnlySpan<byte> b)
    {
        if (b.Length != Protocol.VerdictLength) throw Corrupt("a verdict of another length");
        uint code = BinaryPrimitives.ReadUInt32LittleEndian(b);
        var sig = b[4..];
        if (!VerdictOk(code, sig)) throw Corrupt("a verdict neither accepted nor refused, or a refusal carrying a signature");
        return new Verdict(code, sig.ToArray());
    }

    // =============================== SCRAM-SHA-256 ===============================

    /// <summary>The AuthMessage (279 bytes) both sides HMAC: "IMDBWIR1-SCRAM" | endpoint | the hello's 112 bytes | the
    /// challenge's 120 | binding[32] (the hello's type's value: zeros on the socket).</summary>
    public static byte[] AuthMessage(ImdbEndpoint endpoint, ReadOnlySpan<byte> hello, ReadOnlySpan<byte> challenge, ReadOnlySpan<byte> binding)
    {
        if (hello.Length != Protocol.HelloLength || challenge.Length != Protocol.ChallengeLength || binding.Length != Protocol.KeyLength)
            throw new ArgumentException("an AuthMessage of a 112-byte hello, a 120-byte challenge and a 32-byte binding");
        var am = new byte[Protocol.AuthMessageLength];
        AuthMagic.CopyTo(am, 0);
        am[14] = (byte)endpoint;
        hello.CopyTo(am.AsSpan(15));
        challenge.CopyTo(am.AsSpan(15 + Protocol.HelloLength));
        binding.CopyTo(am.AsSpan(15 + Protocol.HelloLength + Protocol.ChallengeLength));
        return am;
    }

    /// <summary>A password as CREATE ROLE takes one: 1 to 1,024 bytes of printable ASCII (no SASLprep in imagedb yet).</summary>
    public static bool PasswordOk(ReadOnlySpan<byte> pw)
    {
        if (pw.Length < 1 || pw.Length > Protocol.PasswordMax) return false;
        foreach (byte c in pw)
            if (c < 0x20 || c > 0x7e) return false;
        return true;
    }

    /// <summary>RFC 5802's client side over the AuthMessage: the ClientProof to send and the ServerSignature to expect.</summary>
    public static (byte[] Proof, byte[] ServerSignature) ScramClient(ReadOnlySpan<byte> password, Challenge c, ReadOnlySpan<byte> authMessage)
    {
        if (!PasswordOk(password)) throw new ArgumentException("a password is 1 to 1,024 bytes of printable ASCII (as CREATE ROLE takes one)");
        if (!ChallengeOk(c.Salt.Length, c.Iterations)) throw new ArgumentException("a challenge its decoder refuses");
        if (authMessage.Length != Protocol.AuthMessageLength) throw new ArgumentException("an AuthMessage of 279 bytes");
        var sp = Rfc2898DeriveBytes.Pbkdf2(password, c.Salt, (int)c.Iterations, HashAlgorithmName.SHA256, 32);
        var ck = HMACSHA256.HashData(sp, "Client Key"u8);
        var sk = HMACSHA256.HashData(sp, "Server Key"u8);
        var stored = SHA256.HashData(ck);
        var cs = HMACSHA256.HashData(stored, authMessage);
        var proof = new byte[32];
        for (int i = 0; i < 32; i++) proof[i] = (byte)(ck[i] ^ cs[i]);
        var ssig = HMACSHA256.HashData(sk, authMessage);
        CryptographicOperations.ZeroMemory(sp);
        CryptographicOperations.ZeroMemory(ck);
        CryptographicOperations.ZeroMemory(sk);
        CryptographicOperations.ZeroMemory(stored);
        CryptographicOperations.ZeroMemory(cs);
        return (proof, ssig);
    }

    /// <summary>A verifier's StoredKey and ServerKey (a server's side: the tests' mock).</summary>
    public static (byte[] StoredKey, byte[] ServerKey) ScramVerifier(ReadOnlySpan<byte> password, ReadOnlySpan<byte> salt, uint iterations)
    {
        var sp = Rfc2898DeriveBytes.Pbkdf2(password, salt, (int)iterations, HashAlgorithmName.SHA256, 32);
        var ck = HMACSHA256.HashData(sp, "Client Key"u8);
        var sk = HMACSHA256.HashData(sp, "Server Key"u8);
        var stored = SHA256.HashData(ck);
        CryptographicOperations.ZeroMemory(sp);
        CryptographicOperations.ZeroMemory(ck);
        return (stored, sk);
    }

    /// <summary>The server's check of a proof (constant time) and its ServerSignature (wire.c's imdbw_scram_server).</summary>
    public static bool ScramServer(ReadOnlySpan<byte> storedKey, ReadOnlySpan<byte> serverKey, ReadOnlySpan<byte> authMessage,
                                   ReadOnlySpan<byte> proof, out byte[] signature)
    {
        var cs = HMACSHA256.HashData(storedKey, authMessage);
        var ck = new byte[32];
        for (int i = 0; i < 32; i++) ck[i] = (byte)(proof[i] ^ cs[i]);
        bool ok = CryptographicOperations.FixedTimeEquals(SHA256.HashData(ck), storedKey);
        signature = HMACSHA256.HashData(serverKey, authMessage);
        CryptographicOperations.ZeroMemory(ck);
        return ok;
    }
}
