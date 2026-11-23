using System;
using System.Globalization;
using System.Numerics;
using Imagedb.Client.Wire;

namespace Imagedb.Client;

/// <summary>One IMDBWIR1 value, tagged by its type (§4's table): what a parameter is sent as and what a result cell
/// decodes to. Every factory checks the value's own rules (wire.c's imdbw_value_ok), so an encoder never writes what a
/// decoder refuses: a FLOAT64 finite and never -0, a TIMESTAMP within years 1 to 9999, a TEXT strict UTF-8 without NUL
/// of at most 65,535 bytes, a DECIMAL within 38 digits, and so on.
/// <para>The native types: INT64 long; FLOAT64 double (its bits kept exactly); BOOL bool; TEXT and ENUM string;
/// DECIMAL <see cref="ImdbDecimal"/>; TIMESTAMP DateTime (Kind Unspecified) and TIMESTAMPTZ DateTimeOffset (offset 0),
/// each from microseconds (a .NET tick is 100 ns, so microseconds fit exactly: ticks = microseconds x 10, and a
/// DateTime with a tick finer than a microsecond is refused, never rounded); DATE DateOnly; TIME TimeOnly; UUID Guid
/// (RFC 4122's big-endian bytes, as §4 sends them: Guid's own ToByteArray order is not used); BYTEA byte[]; INTERVAL
/// <see cref="ImdbInterval"/>. A NULL keeps a type (the engine binds a NULL parameter by it).</para></summary>
public readonly struct ImdbValue : IEquatable<ImdbValue>
{
    private static readonly long EpochTicks = DateTime.UnixEpoch.Ticks;
    private const int EpochDayNumber = 719162; // DateOnly's day number of 1970-01-01

    private readonly object? _ref; // TEXT and ENUM: string; BYTEA and UUID: byte[] (owned)
    private readonly Int128 _d;    // DECIMAL's unscaled value
    private readonly long _i;      // INT64, FLOAT64's bits, BOOL, TIMESTAMP(TZ), TIME, INTERVAL's microseconds
    private readonly int _mon, _day; // INTERVAL; DATE's days in _day
    private readonly byte _scale;

    private ImdbValue(ImdbType type, bool isNull, long i = 0, Int128 d = default, byte scale = 0, int mon = 0, int day = 0,
                      object? r = null)
    {
        Type = type;
        IsNull = isNull;
        _i = i;
        _d = d;
        _scale = scale;
        _mon = mon;
        _day = day;
        _ref = r;
    }

    /// <summary>The value's type; a NULL's type (None: a NULL of no type).</summary>
    public ImdbType Type { get; }

    public bool IsNull { get; }

    // ---- factories (each value's rules checked) ----

    /// <summary>A NULL of a type (or of none: a result's under a column of no type; as a parameter the engine takes it
    /// into any column, NOT NULL aside).</summary>
    public static ImdbValue Null(ImdbType type = ImdbType.None)
    {
        if ((byte)type > (byte)ImdbType.Enum) throw new ArgumentOutOfRangeException(nameof(type), "no such type");
        return new ImdbValue(type, true);
    }

    public static ImdbValue FromInt64(long v) => new(ImdbType.Int64, false, v);

    /// <summary>A FLOAT64: finite, and never -0 (the engine keeps one zero; wire.c refuses -0 both ways). A -0.0 is
    /// refused, not turned into 0.0.</summary>
    public static ImdbValue FromFloat64(double v) => FromFloat64Bits((ulong)BitConverter.DoubleToInt64Bits(v));

    public static ImdbValue FromFloat64Bits(ulong bits)
    {
        if (((bits >> 52) & 0x7ff) == 0x7ff)
            throw new ArgumentOutOfRangeException(nameof(bits), "FLOAT64: an infinity or a NaN, which imagedb does not hold");
        if (bits == 0x8000000000000000UL)
            throw new ArgumentOutOfRangeException(nameof(bits), "FLOAT64: -0, which the protocol does not carry (the engine keeps one zero): send 0.0");
        return new ImdbValue(ImdbType.Float64, false, (long)bits);
    }

    public static ImdbValue FromBool(bool v) => new(ImdbType.Bool, false, v ? 1 : 0);

    public static ImdbValue FromText(string s)
    {
        var b = StrictUtf8.Encode(s, "TEXT");
        if (b.Length > Protocol.ValueMax) throw new ArgumentOutOfRangeException(nameof(s), "TEXT: at most 65,535 bytes of UTF-8");
        return new ImdbValue(ImdbType.Text, false, r: s);
    }

    public static ImdbValue FromDecimal(ImdbDecimal d) => new(ImdbType.Decimal, false, d: d.Unscaled, scale: d.Scale);

    /// <summary>A TIMESTAMP (no zone) by its microseconds since 1970-01-01 00:00.</summary>
    public static ImdbValue FromTimestampMicros(long us)
    {
        if (us < Protocol.TimestampMin || us > Protocol.TimestampMax)
            throw new ArgumentOutOfRangeException(nameof(us), "TIMESTAMP: years 1 to 9999");
        return new ImdbValue(ImdbType.Timestamp, false, us);
    }

    /// <summary>A TIMESTAMP from a DateTime's clock reading (its Kind is not consulted: a TIMESTAMP has no zone).</summary>
    public static ImdbValue FromTimestamp(DateTime t) => FromTimestampMicros(MicrosOf(t.Ticks - EpochTicks));

    /// <summary>A TIMESTAMPTZ, the instant, by its microseconds since the epoch.</summary>
    public static ImdbValue FromTimestampTzMicros(long us)
    {
        if (us < Protocol.TimestampMin || us > Protocol.TimestampMax)
            throw new ArgumentOutOfRangeException(nameof(us), "TIMESTAMPTZ: years 1 to 9999");
        return new ImdbValue(ImdbType.TimestampTz, false, us);
    }

    public static ImdbValue FromTimestampTz(DateTimeOffset t) => FromTimestampTzMicros(MicrosOf(t.UtcTicks - EpochTicks));

    /// <summary>A TIMESTAMPTZ from a DateTime of Kind Utc (Unspecified and Local are refused: say which instant).</summary>
    public static ImdbValue FromTimestampTz(DateTime t)
    {
        if (t.Kind != DateTimeKind.Utc)
            throw new ArgumentException("TIMESTAMPTZ: a DateTime of Kind Utc (or a DateTimeOffset): which instant is an Unspecified or Local one", nameof(t));
        return FromTimestampTzMicros(MicrosOf(t.Ticks - EpochTicks));
    }

    public static ImdbValue FromDateDays(int days)
    {
        if (days < Protocol.DateMin || days > Protocol.DateMax)
            throw new ArgumentOutOfRangeException(nameof(days), "DATE: 0001-01-01 to 9999-12-31");
        return new ImdbValue(ImdbType.Date, false, day: days);
    }

    public static ImdbValue FromDate(DateOnly d) => FromDateDays(d.DayNumber - EpochDayNumber);

    public static ImdbValue FromTimeMicros(long us)
    {
        if (us < 0 || us > Protocol.TimeMax) throw new ArgumentOutOfRangeException(nameof(us), "TIME: 00:00:00 to 23:59:59.999999");
        return new ImdbValue(ImdbType.Time, false, us);
    }

    public static ImdbValue FromTime(TimeOnly t) => FromTimeMicros(MicrosOf(t.Ticks));

    /// <summary>A UUID: the Guid's RFC 4122 (big-endian) bytes, so "00010203-0405-..." travels as 00 01 02 03 04 05.</summary>
    public static ImdbValue FromUuid(Guid g)
    {
        var b = new byte[16];
        if (!g.TryWriteBytes(b, bigEndian: true, out int n) || n != 16) throw new InvalidOperationException("Guid.TryWriteBytes");
        return new ImdbValue(ImdbType.Uuid, false, r: b);
    }

    public static ImdbValue FromUuidBytes(ReadOnlySpan<byte> b)
    {
        if (b.Length != 16) throw new ArgumentException("UUID: 16 bytes", nameof(b));
        return new ImdbValue(ImdbType.Uuid, false, r: b.ToArray());
    }

    public static ImdbValue FromBytea(ReadOnlySpan<byte> b)
    {
        if (b.Length > Protocol.ValueMax) throw new ArgumentOutOfRangeException(nameof(b), "BYTEA: at most 65,535 bytes");
        return new ImdbValue(ImdbType.Bytea, false, r: b.ToArray());
    }

    public static ImdbValue FromInterval(ImdbInterval iv) =>
        new(ImdbType.Interval, false, iv.Microseconds, mon: iv.Months, day: iv.Days);

    public static ImdbValue FromInterval(int months, int days, long microseconds) =>
        FromInterval(new ImdbInterval(months, days, microseconds));

    /// <summary>An ENUM's label (a result's value). As a parameter a label is sent as TEXT (§4): the encoder refuses a
    /// non-NULL ENUM parameter.</summary>
    public static ImdbValue FromEnum(string label)
    {
        var b = StrictUtf8.Encode(label, "ENUM label");
        if (b.Length > Protocol.LabelMax) throw new ArgumentOutOfRangeException(nameof(label), "ENUM: a label of at most 63 bytes");
        return new ImdbValue(ImdbType.Enum, false, r: label);
    }

    private static long MicrosOf(long ticks)
    {
        if (ticks % 10 != 0)
            throw new ArgumentException("a time finer than a microsecond (a .NET tick is 100 ns; imagedb keeps microseconds): never rounded");
        return ticks / 10;
    }

    /// <summary>A parameter from a CLR value: null and DBNull a NULL of no type; long, int, short, sbyte, byte, ushort,
    /// uint (and ulong up to long.MaxValue) INT64; double and float FLOAT64; bool BOOL; string TEXT (an ENUM label too);
    /// ImdbDecimal, decimal, BigInteger and Int128 DECIMAL (the integers at scale 0); DateTime of Kind Unspecified
    /// TIMESTAMP, of Kind Utc TIMESTAMPTZ (Local refused: say which); DateTimeOffset TIMESTAMPTZ; DateOnly DATE;
    /// TimeOnly TIME; Guid UUID; byte[] and ReadOnlyMemory&lt;byte&gt; BYTEA; ImdbInterval INTERVAL; ImdbValue as itself.</summary>
    public static ImdbValue FromObject(object? o) => o switch
    {
        null => Null(),
        DBNull => Null(),
        ImdbValue v => v,
        long l => FromInt64(l),
        int i => FromInt64(i),
        short s => FromInt64(s),
        sbyte sb => FromInt64(sb),
        byte by => FromInt64(by),
        ushort us => FromInt64(us),
        uint ui => FromInt64(ui),
        ulong ul => ul <= long.MaxValue ? FromInt64((long)ul)
                                        : throw new ArgumentOutOfRangeException(nameof(o), "a ulong past long.MaxValue: send it as a DECIMAL (BigInteger)"),
        double d => FromFloat64(d),
        float f => FromFloat64(f),
        bool b => FromBool(b),
        string str => FromText(str),
        ImdbDecimal dec => FromDecimal(dec),
        decimal m => FromDecimal(ImdbDecimal.FromDecimal(m)),
        Int128 i128 => FromDecimal(new ImdbDecimal(i128, 0)),
        BigInteger bi => FromDecimal(BigToDecimal(bi)),
        DateTime dt => dt.Kind switch
        {
            DateTimeKind.Utc => FromTimestampTz(dt),
            DateTimeKind.Unspecified => FromTimestamp(dt),
            _ => throw new ArgumentException("a DateTime of Kind Local: ToUniversalTime() for a TIMESTAMPTZ, or Kind Unspecified for a TIMESTAMP", nameof(o)),
        },
        DateTimeOffset dto => FromTimestampTz(dto),
        DateOnly don => FromDate(don),
        TimeOnly ton => FromTime(ton),
        Guid g => FromUuid(g),
        byte[] bytes => FromBytea(bytes),
        ReadOnlyMemory<byte> rom => FromBytea(rom.Span),
        ImdbInterval iv => FromInterval(iv),
        _ => throw new ArgumentException($"no IMDBWIR1 type for a {o.GetType().Name}: pass an ImdbValue", nameof(o)),
    };

    private static ImdbDecimal BigToDecimal(BigInteger b)
    {
        if (BigInteger.Abs(b) >= (BigInteger)ImdbDecimal.Limit)
            throw new ArgumentOutOfRangeException(nameof(b), "a DECIMAL holds at most 38 digits");
        return new ImdbDecimal((Int128)b, 0);
    }

    // ---- internal construction from decoded bytes (the decoder has checked the rules) ----

    internal static ImdbValue Raw(ImdbType t, long i = 0, Int128 d = default, byte scale = 0, int mon = 0, int day = 0, object? r = null) =>
        new(t, false, i, d, scale, mon, day, r);

    internal long RawI => _i;
    internal Int128 RawD => _d;
    internal byte RawScale => _scale;
    internal int RawMonths => _mon;
    internal int RawDays => _day;
    internal object? RawRef => _ref;

    // ---- accessors ----

    private void Want(ImdbType t)
    {
        if (IsNull) throw new InvalidCastException($"a NULL {Type} has no value");
        if (Type != t) throw new InvalidCastException($"a {Type} value, not a {t}");
    }

    public long AsInt64()
    {
        Want(ImdbType.Int64);
        return _i;
    }

    public double AsFloat64()
    {
        Want(ImdbType.Float64);
        return BitConverter.Int64BitsToDouble(_i);
    }

    public ulong AsFloat64Bits()
    {
        Want(ImdbType.Float64);
        return (ulong)_i;
    }

    public bool AsBool()
    {
        Want(ImdbType.Bool);
        return _i != 0;
    }

    public string AsText()
    {
        Want(ImdbType.Text);
        return (string)_ref!;
    }

    public string AsEnumLabel()
    {
        Want(ImdbType.Enum);
        return (string)_ref!;
    }

    public ImdbDecimal AsDecimal()
    {
        Want(ImdbType.Decimal);
        return new ImdbDecimal(_d, _scale);
    }

    public long AsTimestampMicros()
    {
        Want(ImdbType.Timestamp);
        return _i;
    }

    /// <summary>A TIMESTAMP as a DateTime of Kind Unspecified (no zone).</summary>
    public DateTime AsTimestamp()
    {
        Want(ImdbType.Timestamp);
        return new DateTime(EpochTicks + _i * 10, DateTimeKind.Unspecified);
    }

    public long AsTimestampTzMicros()
    {
        Want(ImdbType.TimestampTz);
        return _i;
    }

    /// <summary>A TIMESTAMPTZ as a DateTimeOffset at offset 0 (the instant; a session's zone is for text alone).</summary>
    public DateTimeOffset AsTimestampTz()
    {
        Want(ImdbType.TimestampTz);
        return new DateTimeOffset(EpochTicks + _i * 10, TimeSpan.Zero);
    }

    public int AsDateDays()
    {
        Want(ImdbType.Date);
        return _day;
    }

    public DateOnly AsDate()
    {
        Want(ImdbType.Date);
        return DateOnly.FromDayNumber(_day + EpochDayNumber);
    }

    public long AsTimeMicros()
    {
        Want(ImdbType.Time);
        return _i;
    }

    public TimeOnly AsTime()
    {
        Want(ImdbType.Time);
        return new TimeOnly(_i * 10);
    }

    public Guid AsUuid()
    {
        Want(ImdbType.Uuid);
        return new Guid((byte[])_ref!, bigEndian: true);
    }

    /// <summary>A BYTEA's bytes (a copy), or a UUID's 16 bytes in wire order.</summary>
    public byte[] AsBytes()
    {
        if (IsNull || (Type != ImdbType.Bytea && Type != ImdbType.Uuid)) Want(ImdbType.Bytea);
        return ((byte[])_ref!).AsSpan().ToArray();
    }

    internal ReadOnlySpan<byte> BytesSpan => (byte[])_ref!;

    public ImdbInterval AsInterval()
    {
        Want(ImdbType.Interval);
        return new ImdbInterval(_mon, _day, _i);
    }

    /// <summary>The value as its natural CLR type (above), null for a NULL.</summary>
    public object? ToObject()
    {
        if (IsNull) return null;
        return Type switch
        {
            ImdbType.Int64 => _i,
            ImdbType.Float64 => BitConverter.Int64BitsToDouble(_i),
            ImdbType.Bool => _i != 0,
            ImdbType.Text or ImdbType.Enum => (string)_ref!,
            ImdbType.Decimal => AsDecimal(),
            ImdbType.Timestamp => AsTimestamp(),
            ImdbType.TimestampTz => AsTimestampTz(),
            ImdbType.Date => AsDate(),
            ImdbType.Time => AsTime(),
            ImdbType.Uuid => AsUuid(),
            ImdbType.Bytea => AsBytes(),
            ImdbType.Interval => AsInterval(),
            _ => null,
        };
    }

    /// <summary>The same wire bytes: type, NULL and value (a DECIMAL's scale included).</summary>
    public bool Equals(ImdbValue o)
    {
        if (Type != o.Type || IsNull != o.IsNull) return false;
        if (IsNull) return true;
        return Type switch
        {
            ImdbType.Text or ImdbType.Enum => string.Equals((string)_ref!, (string)o._ref!, StringComparison.Ordinal),
            ImdbType.Bytea or ImdbType.Uuid => ((byte[])_ref!).AsSpan().SequenceEqual((byte[])o._ref!),
            ImdbType.Decimal => _d == o._d && _scale == o._scale,
            ImdbType.Interval => _mon == o._mon && _day == o._day && _i == o._i,
            ImdbType.Date => _day == o._day,
            _ => _i == o._i,
        };
    }

    public override bool Equals(object? obj) => obj is ImdbValue v && Equals(v);

    public override int GetHashCode() => HashCode.Combine(Type, IsNull, _i, _d, _day);

    public static bool operator ==(ImdbValue a, ImdbValue b) => a.Equals(b);
    public static bool operator !=(ImdbValue a, ImdbValue b) => !a.Equals(b);

    /// <summary>A text of the value that loses nothing: microseconds kept, a FLOAT64 round-trippable, a DECIMAL exact,
    /// a BYTEA as \x and hex, a UUID in its canonical form; a NULL as "NULL".</summary>
    public override string ToString()
    {
        if (IsNull) return "NULL";
        var inv = CultureInfo.InvariantCulture;
        return Type switch
        {
            ImdbType.Int64 => _i.ToString(inv),
            ImdbType.Float64 => BitConverter.Int64BitsToDouble(_i).ToString("R", inv),
            ImdbType.Bool => _i != 0 ? "true" : "false",
            ImdbType.Text or ImdbType.Enum => (string)_ref!,
            ImdbType.Decimal => AsDecimal().ToString(),
            ImdbType.Timestamp => AsTimestamp().ToString("yyyy-MM-dd HH:mm:ss.ffffff", inv),
            ImdbType.TimestampTz => AsTimestampTz().ToString("yyyy-MM-dd HH:mm:ss.ffffff", inv) + "+00",
            ImdbType.Date => AsDate().ToString("yyyy-MM-dd", inv),
            ImdbType.Time => AsTime().ToString("HH:mm:ss.ffffff", inv),
            ImdbType.Uuid => AsUuid().ToString("D"),
            ImdbType.Bytea => "\\x" + Convert.ToHexString((byte[])_ref!).ToLowerInvariant(),
            ImdbType.Interval => AsInterval().ToString(),
            _ => "",
        };
    }
}
