using System;
using System.Collections;
using System.Collections.Generic;
using System.Data;
using System.Data.Common;
using System.Data.SqlTypes;
using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Numerics;
using System.Threading;
using System.Threading.Tasks;
using Imagedb.Client.Wire;

namespace Imagedb.Client;

/// <summary>ADO.NET's parameter. imagedb's parameters are positional: the collection's first is $1, its second $2, and
/// so on; a name, when given, is empty, "$k" or "k" for its own position k (anything else is refused at the execute, so
/// a named parameter can never bind to the wrong place).
/// <para>The wire type: <see cref="ImdbType"/> when set (INTERVAL and ENUM have no DbType), else <see cref="DbType"/>
/// when set, else the value's own (<see cref="ImdbValue.FromObject"/>; a TimeSpan an INTERVAL). A NULL (null or DBNull)
/// is sent as a NULL of that type (§4: the engine binds a NULL by its type), or a NULL of no type when none is set,
/// which the engine takes into a column but refuses where a type is wanted (SELECT $1). A value whose CLR type does not
/// suit the declared type is converted only when nothing is lost (an int as a DECIMAL, a DateTime at midnight as a DATE,
/// a TimeSpan of less than a day as a TIME), else refused before anything is sent. The engine binds what arrives as the
/// literal of its value would (an INT64 into a DECIMAL column, a TEXT label into an ENUM column), never by its bytes.
/// An ENUM parameter is sent as TEXT (§4: a label; the ordinal is the engine's). A double -0.0 is sent as 0.0 (the
/// engine keeps one zero; the codec refuses -0 itself); NaN and the infinities are refused. Size, Precision and Scale
/// are not sent (the column's own decide; the engine refuses a value that does not fit).</para></summary>
public sealed class ImdbDbParameter : DbParameter
{
    private DbType? _dbType;
    private string _name = "";
    private string _sourceColumn = "";

    public ImdbDbParameter() { }

    public ImdbDbParameter(string? name, object? value)
    {
        ParameterName = name;
        Value = value;
    }

    public ImdbDbParameter(string? name, DbType dbType, object? value = null)
    {
        ParameterName = name;
        DbType = dbType;
        Value = value;
    }

    /// <summary>The declared DbType, or the value's (as ADO.NET infers one) when none was set.</summary>
    public override DbType DbType
    {
        get => _dbType ?? Infer(Value);
        set => _dbType = value;
    }

    /// <summary>imagedb's own wire type (overrides <see cref="DbType"/>): INTERVAL, ENUM, or any other.</summary>
    public ImdbType? ImdbType { get; set; }

    public override ParameterDirection Direction
    {
        get => ParameterDirection.Input;
        set
        {
            if (value != ParameterDirection.Input) throw new ArgumentException("imagedb's parameters are input alone (RETURNING gives rows)");
        }
    }

    public override bool IsNullable { get; set; } = true;

    [AllowNull]
    public override string ParameterName
    {
        get => _name;
        set => _name = value ?? "";
    }

    [AllowNull]
    public override string SourceColumn
    {
        get => _sourceColumn;
        set => _sourceColumn = value ?? "";
    }

    public override bool SourceColumnNullMapping { get; set; }

    public override object? Value { get; set; }

    public override int Size { get; set; }

    public override void ResetDbType()
    {
        _dbType = null;
        ImdbType = null;
    }

    private static DbType Infer(object? v) => v switch
    {
        long => DbType.Int64,
        int => DbType.Int32,
        short => DbType.Int16,
        byte => DbType.Byte,
        sbyte => DbType.SByte,
        ushort => DbType.UInt16,
        uint => DbType.UInt32,
        ulong => DbType.UInt64,
        double => DbType.Double,
        float => DbType.Single,
        bool => DbType.Boolean,
        decimal or ImdbDecimal or SqlDecimal or BigInteger or Int128 => DbType.Decimal,
        DateTime d => d.Kind == DateTimeKind.Utc ? DbType.DateTimeOffset : DbType.DateTime2,
        DateTimeOffset => DbType.DateTimeOffset,
        DateOnly => DbType.Date,
        TimeOnly => DbType.Time,
        Guid => DbType.Guid,
        byte[] or ReadOnlyMemory<byte> or Memory<byte> or ArraySegment<byte> => DbType.Binary,
        _ => DbType.String, // ADO.NET's default for a parameter with no value
    };

    /// <summary>The value as it goes on the wire for position k (1-based).</summary>
    internal ImdbValue ToWire(int k)
    {
        string n = _name;
        if (n.Length > 0)
        {
            string digits = n[0] == '$' ? n.Substring(1) : n;
            if (!int.TryParse(digits, NumberStyles.None, CultureInfo.InvariantCulture, out int named) || named != k)
                throw new ArgumentException($"parameter {k}: named \"{n}\": imagedb's parameters are positional ($1 to $n, in the " +
                                            $"collection's order): give it no name, \"${k}\" or \"{k}\"");
        }
        try
        {
            return AdoValues.ToWire(Value, ImdbType, ImdbType == null ? _dbType : null);
        }
        catch (Exception e) when (e is ArgumentException or InvalidCastException or OverflowException)
        {
            throw new ArgumentException($"parameter ${k}: {e.Message}", e);
        }
    }
}

/// <summary>The command's parameters, in position order ($1 first).</summary>
public sealed class ImdbDbParameterCollection : DbParameterCollection
{
    private readonly List<ImdbDbParameter> _list = new();

    public override int Count => _list.Count;
    public override object SyncRoot => ((ICollection)_list).SyncRoot;

    public new ImdbDbParameter this[int index]
    {
        get => _list[index];
        set => _list[index] = value ?? throw new ArgumentNullException(nameof(value));
    }

    private static ImdbDbParameter Cast(object? value) =>
        value as ImdbDbParameter ?? throw new InvalidCastException("imagedb's commands take ImdbDbParameter alone");

    public override int Add(object value)
    {
        _list.Add(Cast(value));
        return _list.Count - 1;
    }

    public ImdbDbParameter Add(ImdbDbParameter p)
    {
        _list.Add(Cast(p));
        return p;
    }

    /// <summary>The next position's value ($1, $2, ... in the order added).</summary>
    public ImdbDbParameter AddWithValue(object? value) => Add(new ImdbDbParameter(null, value));

    public ImdbDbParameter AddWithValue(string? name, object? value) => Add(new ImdbDbParameter(name, value));

    /// <summary>A value with its declared type (a typed NULL with a null value).</summary>
    public ImdbDbParameter Add(object? value, DbType dbType) => Add(new ImdbDbParameter(null, dbType, value));

    /// <summary>A value with imagedb's own type (INTERVAL, ENUM: a typed NULL with a null value).</summary>
    public ImdbDbParameter Add(object? value, ImdbType type) => Add(new ImdbDbParameter { Value = value, ImdbType = type });

    public override void AddRange(Array values)
    {
        ArgumentNullException.ThrowIfNull(values);
        foreach (var v in values) Add(v!);
    }

    public override void Clear() => _list.Clear();
    public override bool Contains(object value) => value is ImdbDbParameter p && _list.Contains(p);
    public override bool Contains(string value) => IndexOf(value) >= 0;
    public override void CopyTo(Array array, int index) => ((ICollection)_list).CopyTo(array, index);
    public override IEnumerator GetEnumerator() => _list.GetEnumerator();
    protected override DbParameter GetParameter(int index) => _list[index];

    protected override DbParameter GetParameter(string parameterName)
    {
        int i = IndexOf(parameterName);
        return i >= 0 ? _list[i] : throw new IndexOutOfRangeException($"no parameter named {parameterName}");
    }

    public override int IndexOf(object value) => value is ImdbDbParameter p ? _list.IndexOf(p) : -1;

    public override int IndexOf(string parameterName)
    {
        for (int i = 0; i < _list.Count; i++)
            if (string.Equals(_list[i].ParameterName, parameterName, StringComparison.Ordinal)) return i;
        return -1;
    }

    public override void Insert(int index, object value) => _list.Insert(index, Cast(value));
    public override void Remove(object value) => _list.Remove(Cast(value));
    public override void RemoveAt(int index) => _list.RemoveAt(index);

    public override void RemoveAt(string parameterName)
    {
        int i = IndexOf(parameterName);
        if (i < 0) throw new IndexOutOfRangeException($"no parameter named {parameterName}");
        _list.RemoveAt(i);
    }

    protected override void SetParameter(int index, DbParameter value) => _list[index] = Cast(value);

    protected override void SetParameter(string parameterName, DbParameter value)
    {
        int i = IndexOf(parameterName);
        if (i < 0) throw new IndexOutOfRangeException($"no parameter named {parameterName}");
        _list[i] = Cast(value);
    }

    internal ImdbValue[] ToWire()
    {
        var v = new ImdbValue[_list.Count];
        for (int i = 0; i < v.Length; i++) v[i] = _list[i].ToWire(i + 1);
        return v;
    }
}

/// <summary>ADO.NET's command: one statement (CommandText, its parameters $1 to $n) as a QUERY, or, once
/// <see cref="Prepare"/>d, as an EXECUTE of the session's prepared statement. Several statements in one round trip: a
/// <see cref="ImdbDbBatch"/>.
/// <para>CommandTimeout (seconds; 0 none; the connection string's Command Timeout, 30 by default) and Cancel() both
/// cancel in band (CANCEL): the statement ends in ERROR 15 and the connection stays usable. A timeout throws an
/// <see cref="ImdbException"/> of code 15 whose inner exception is a TimeoutException; Cancel() the server's ERROR 15
/// (<see cref="ImdbServerException"/>); a token, OperationCanceledException. A statement the engine never checks
/// (COMMIT, a DDL) runs to its end, as a CANCEL that reaches the server before its statement started does (it cancels
/// nothing: srv.c cancels the statement running then).</para></summary>
public sealed class ImdbDbCommand : DbCommand
{
    private static long s_prepared;
    private string _text = "";
    private ImdbDbConnection? _conn;
    private int? _timeout;
    private string? _preparedName;
    private ImdbConnection? _preparedOn;
    private string? _preparedText;
    private volatile ImdbConnection? _running;

    public ImdbDbCommand() { }

    public ImdbDbCommand(string commandText, ImdbDbConnection? connection = null)
    {
        _text = commandText;
        _conn = connection;
    }

    [AllowNull]
    public override string CommandText
    {
        get => _text;
        set => _text = value ?? "";
    }

    /// <summary>Seconds (0: none): the connection string's Command Timeout until set.</summary>
    public override int CommandTimeout
    {
        get => _timeout ?? _conn?.DefaultCommandTimeout ?? 30;
        set
        {
            ArgumentOutOfRangeException.ThrowIfNegative(value);
            _timeout = value;
        }
    }

    public override CommandType CommandType
    {
        get => CommandType.Text;
        set
        {
            if (value != CommandType.Text) throw new ArgumentException("imagedb runs SQL text alone (CommandType.Text)");
        }
    }

    public override bool DesignTimeVisible { get; set; }

    public override UpdateRowSource UpdatedRowSource { get; set; }

    public new ImdbDbConnection? Connection
    {
        get => _conn;
        set => _conn = value;
    }

    protected override DbConnection? DbConnection
    {
        get => _conn;
        set => _conn = value switch
        {
            null => null,
            ImdbDbConnection c => c,
            _ => throw new ArgumentException("an ImdbDbCommand runs on an ImdbDbConnection"),
        };
    }

    public new ImdbDbParameterCollection Parameters { get; } = new();

    protected override DbParameterCollection DbParameterCollection => Parameters;

    /// <summary>Informational: the session holds one transaction, which every command on the connection runs in.</summary>
    protected override DbTransaction? DbTransaction { get; set; }

    protected override DbParameter CreateDbParameter() => new ImdbDbParameter();

    public new ImdbDbParameter CreateParameter() => new();

    /// <summary>Cancels this command's statement if it is running now (in band: CANCEL); otherwise nothing.</summary>
    public override void Cancel() => _running?.Cancel();

    private ImdbConnection Native()
    {
        if (_conn == null) throw new InvalidOperationException("the command has no connection");
        if (_conn.State != ConnectionState.Open) throw new InvalidOperationException($"the connection is {_conn.State}, not Open");
        if (string.IsNullOrWhiteSpace(_text)) throw new InvalidOperationException("the command has no text");
        return _conn.Native;
    }

    /// <summary>PREPARE on the session (its name the driver's own); each execution then an EXECUTE of the parameters
    /// (typed at each, as the engine's PREPARE). Changing the text or the connection prepares again at the next run;
    /// Dispose deallocates.</summary>
    public override void Prepare() => PrepareAsync(CancellationToken.None).GetAwaiter().GetResult();

    public override async Task PrepareAsync(CancellationToken cancellationToken = default)
    {
        var n = Native();
        if (_preparedName != null && _preparedOn == n && _preparedText == _text) return;
        await UnprepareAsync().ConfigureAwait(false);
        string name = "ado_" + Interlocked.Increment(ref s_prepared).ToString(CultureInfo.InvariantCulture);
        await n.PrepareAsync(name, _text, cancellationToken).ConfigureAwait(false);
        _preparedName = name;
        _preparedOn = n;
        _preparedText = _text;
    }

    private async Task UnprepareAsync()
    {
        var on = _preparedOn;
        var name = _preparedName;
        _preparedName = null;
        _preparedOn = null;
        _preparedText = null;
        if (on != null && name != null && on.IsOpen)
        {
            try
            {
                await on.DeallocateAsync(name).ConfigureAwait(false);
            }
            catch (ImdbException)
            {
                // the session ended or the name is gone: nothing held
            }
        }
    }

    /// <summary>The prepared statement's name on the session, while prepared.</summary>
    public string? PreparedName => _preparedName;

    internal async Task<ImdbResult> RunAsync(CancellationToken ct)
    {
        var n = Native();
        var args = Parameters.ToWire();
        if (_preparedName != null && (_preparedOn != n || _preparedText != _text))
            await PrepareAsync(ct).ConfigureAwait(false); // the text or the connection changed since: prepared again
        int secs = CommandTimeout;
        using var timeout = secs > 0 ? new CancellationTokenSource(TimeSpan.FromSeconds(secs)) : null;
        using var linked = timeout != null ? CancellationTokenSource.CreateLinkedTokenSource(ct, timeout.Token) : null;
        var token = linked?.Token ?? ct;
        _running = n;
        try
        {
            object?[] boxed = new object?[args.Length];
            for (int i = 0; i < args.Length; i++) boxed[i] = args[i];
            return _preparedName != null
                ? await n.ExecuteAsync(_preparedName, boxed, token).ConfigureAwait(false)
                : await n.QueryAsync(_text, boxed, token).ConfigureAwait(false);
        }
        catch (OperationCanceledException oce) when (timeout != null && timeout.IsCancellationRequested && !ct.IsCancellationRequested)
        {
            throw new ImdbException((int)ImdbErrorCode.Cancelled,
                $"the command passed its timeout of {secs} s and was cancelled (in band: its ERROR 15); the connection stays usable",
                new TimeoutException("CommandTimeout " + secs.ToString(CultureInfo.InvariantCulture) + " s", oce.InnerException ?? oce));
        }
        finally
        {
            _running = null;
        }
    }

    protected override DbDataReader ExecuteDbDataReader(CommandBehavior behavior) =>
        ExecuteDbDataReaderAsync(behavior, CancellationToken.None).GetAwaiter().GetResult();

    /// <summary>CommandBehavior.SchemaOnly is refused: imagedb cannot describe a statement without running it, and running
    /// a write for its columns would write. CloseConnection closes the connection with the reader; the rest are hints.</summary>
    protected override async Task<DbDataReader> ExecuteDbDataReaderAsync(CommandBehavior behavior, CancellationToken cancellationToken)
    {
        if ((behavior & CommandBehavior.SchemaOnly) != 0)
            throw new NotSupportedException("CommandBehavior.SchemaOnly: imagedb describes a statement's columns only by running it");
        var r = await RunAsync(cancellationToken).ConfigureAwait(false);
        return new ImdbDbDataReader(new[] { r }, null, null, behavior, _conn!);
    }

    public new ImdbDbDataReader ExecuteReader() => (ImdbDbDataReader)ExecuteDbDataReader(CommandBehavior.Default);

    public new ImdbDbDataReader ExecuteReader(CommandBehavior behavior) => (ImdbDbDataReader)ExecuteDbDataReader(behavior);

    /// <summary>The rows a write wrote (INSERT, UPDATE, DELETE, COPY: its DONE's count), -1 for any other statement
    /// (a SELECT, a DDL, BEGIN), as ADO.NET's convention.</summary>
    public override int ExecuteNonQuery() => ExecuteNonQueryAsync(CancellationToken.None).GetAwaiter().GetResult();

    public override async Task<int> ExecuteNonQueryAsync(CancellationToken cancellationToken)
    {
        var r = await RunAsync(cancellationToken).ConfigureAwait(false);
        return AdoValues.RecordsAffected(r);
    }

    /// <summary>The first row's first value (DBNull for a NULL), or null when no row came.</summary>
    public override object? ExecuteScalar() => ExecuteScalarAsync(CancellationToken.None).GetAwaiter().GetResult();

    public override async Task<object?> ExecuteScalarAsync(CancellationToken cancellationToken)
    {
        var r = await RunAsync(cancellationToken).ConfigureAwait(false);
        if (r.Rows.Count == 0 || r.Columns.Count == 0) return null;
        return AdoValues.ToClr(r.Rows[0].GetValue(0));
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing && _preparedName != null) UnprepareAsync().GetAwaiter().GetResult();
        base.Dispose(disposing);
    }

    public override async ValueTask DisposeAsync()
    {
        if (_preparedName != null) await UnprepareAsync().ConfigureAwait(false);
        await base.DisposeAsync().ConfigureAwait(false);
    }
}

/// <summary>The ADO.NET layer's value rules both ways (parameters out, cells in).</summary>
internal static class AdoValues
{
    private static readonly Int128 Pow96 = (Int128)1 << 96;

    internal static ImdbType? TypeOf(DbType t) => t switch
    {
        DbType.Int16 or DbType.Int32 or DbType.Int64 or DbType.Byte or DbType.SByte or DbType.UInt16 or DbType.UInt32 or DbType.UInt64 => ImdbType.Int64,
        DbType.Double or DbType.Single => ImdbType.Float64,
        DbType.Decimal or DbType.Currency or DbType.VarNumeric => ImdbType.Decimal,
        DbType.Boolean => ImdbType.Bool,
        DbType.String or DbType.AnsiString or DbType.StringFixedLength or DbType.AnsiStringFixedLength or DbType.Xml => ImdbType.Text,
        DbType.DateTime or DbType.DateTime2 => ImdbType.Timestamp,
        DbType.DateTimeOffset => ImdbType.TimestampTz,
        DbType.Date => ImdbType.Date,
        DbType.Time => ImdbType.Time,
        DbType.Guid => ImdbType.Uuid,
        DbType.Binary => ImdbType.Bytea,
        DbType.Object => null,
        _ => throw new ArgumentException($"no imagedb type for DbType.{t}"),
    };

    private static bool IsNull(object? v) => v is null or DBNull || (v is INullable n && n.IsNull);

    /// <summary>A parameter's value as its wire value: the declared type (imagedb's own first, else the DbType's), or
    /// the value's own when none is declared.</summary>
    internal static ImdbValue ToWire(object? v, ImdbType? declared, DbType? dbType)
    {
        ImdbType? t = declared ?? (dbType is { } d ? TypeOf(d) : null);
        if (IsNull(v))
        {
            if (t == null && v is SqlDecimal) t = ImdbType.Decimal;
            return t == null ? ImdbValue.Null() : ImdbValue.Null(t.Value);
        }
        if (t == null) return Natural(v!);
        switch (t.Value)
        {
            case ImdbType.Int64:
                return ImdbValue.FromInt64(v switch
                {
                    long or int or short or sbyte or byte or ushort or uint => Convert.ToInt64(v, CultureInfo.InvariantCulture),
                    ulong ul => ul <= long.MaxValue ? (long)ul : throw new OverflowException("a ulong past INT64's range"),
                    decimal or ImdbDecimal or SqlDecimal or BigInteger or Int128 => IntegralOf(DecimalOf(v)),
                    _ => throw Mismatch(v, "INT64"),
                });
            case ImdbType.Decimal:
                return v switch
                {
                    long or int or short or sbyte or byte or ushort or uint or ulong => ImdbValue.FromDecimal(DecimalOf(v)),
                    decimal or ImdbDecimal or SqlDecimal or BigInteger or Int128 => ImdbValue.FromDecimal(DecimalOf(v)),
                    _ => throw Mismatch(v, "DECIMAL"),
                };
            case ImdbType.Float64:
                return v switch
                {
                    double f => Float(f),
                    float f => Float(f),
                    // a number of another kind: sent as it is, the engine reading it as its literal (the nearest double)
                    long or int or short or sbyte or byte or ushort or uint or ulong or decimal or ImdbDecimal or SqlDecimal or BigInteger or Int128 => Natural(v),
                    _ => throw Mismatch(v, "FLOAT64"),
                };
            case ImdbType.Bool:
                return v is bool b ? ImdbValue.FromBool(b) : throw Mismatch(v, "BOOL");
            case ImdbType.Text:
            case ImdbType.Enum: // §4: an ENUM parameter is its label sent as TEXT
                return v switch
                {
                    string s => ImdbValue.FromText(s),
                    char c => ImdbValue.FromText(c.ToString()),
                    char[] cs => ImdbValue.FromText(new string(cs)),
                    _ => throw Mismatch(v, t == ImdbType.Enum ? "an ENUM's label (a string)" : "TEXT"),
                };
            case ImdbType.Timestamp:
                return v switch
                {
                    DateTime dt when dt.Kind == DateTimeKind.Unspecified => ImdbValue.FromTimestamp(dt),
                    DateTime => throw new ArgumentException("a TIMESTAMP (no zone) from a DateTime of Kind Utc or Local: give Kind Unspecified, " +
                                                            "or declare DbType.DateTimeOffset for a TIMESTAMPTZ"),
                    _ => throw Mismatch(v, "TIMESTAMP"),
                };
            case ImdbType.TimestampTz:
                return v switch
                {
                    DateTimeOffset o => ImdbValue.FromTimestampTz(o),
                    DateTime dt when dt.Kind == DateTimeKind.Utc => ImdbValue.FromTimestampTz(dt),
                    DateTime => throw new ArgumentException("a TIMESTAMPTZ from a DateTime of Kind Unspecified or Local: which instant is unsaid; " +
                                                            "give a DateTimeOffset or a DateTime of Kind Utc"),
                    _ => throw Mismatch(v, "TIMESTAMPTZ"),
                };
            case ImdbType.Date:
                return v switch
                {
                    DateOnly d0 => ImdbValue.FromDate(d0),
                    DateTime dt when dt.TimeOfDay == TimeSpan.Zero && dt.Kind != DateTimeKind.Local => ImdbValue.FromDate(DateOnly.FromDateTime(dt)),
                    DateTime => throw new ArgumentException("a DATE from a DateTime with a time of day (or of Kind Local): never cut"),
                    _ => throw Mismatch(v, "DATE"),
                };
            case ImdbType.Time:
                return v switch
                {
                    TimeOnly to => ImdbValue.FromTime(to),
                    TimeSpan ts when ts >= TimeSpan.Zero && ts < TimeSpan.FromDays(1) => ImdbValue.FromTime(TimeOnly.FromTimeSpan(ts)),
                    TimeSpan => throw new ArgumentOutOfRangeException(nameof(v), "a TIME from a TimeSpan outside 0 to 24 hours (an INTERVAL is ImdbType.Interval)"),
                    _ => throw Mismatch(v, "TIME"),
                };
            case ImdbType.Uuid:
                return v is Guid g ? ImdbValue.FromUuid(g) : throw Mismatch(v, "UUID");
            case ImdbType.Bytea:
                return v switch
                {
                    byte[] bs => ImdbValue.FromBytea(bs),
                    ReadOnlyMemory<byte> rm => ImdbValue.FromBytea(rm.Span),
                    Memory<byte> m => ImdbValue.FromBytea(m.Span),
                    ArraySegment<byte> seg => ImdbValue.FromBytea(seg),
                    _ => throw Mismatch(v, "BYTEA"),
                };
            case ImdbType.Interval:
                return v switch
                {
                    ImdbInterval iv => ImdbValue.FromInterval(iv),
                    TimeSpan ts => Interval(ts),
                    _ => throw Mismatch(v, "INTERVAL"),
                };
            default:
                throw new ArgumentException($"no parameter of type {t}");
        }
    }

    private static ArgumentException Mismatch(object? v, string what) =>
        new($"a {v?.GetType().Name} for a {what} parameter: imagedb converts no value into another kind (values are tagged)");

    private static ImdbValue Float(double f) => f == 0 ? ImdbValue.FromFloat64Bits(0) : ImdbValue.FromFloat64(f); // -0.0 sent as 0.0

    private static ImdbValue Interval(TimeSpan ts)
    {
        if (ts.Ticks % 10 != 0) throw new ArgumentException("an INTERVAL from a TimeSpan finer than a microsecond: never rounded");
        return ImdbValue.FromInterval(0, 0, ts.Ticks / 10);
    }

    /// <summary>A value with no declared type: its own (ImdbValue.FromObject), and the CLR types ADO.NET code hands a
    /// provider that the native layer does not take: a TimeSpan an INTERVAL (as PostgreSQL's drivers), a SqlDecimal a
    /// DECIMAL, a char or char[] a TEXT, a Memory or ArraySegment of bytes a BYTEA.</summary>
    private static ImdbValue Natural(object v) => v switch
    {
        double f => Float(f),
        float f => Float(f),
        TimeSpan ts => Interval(ts),
        SqlDecimal sd => ImdbValue.FromDecimal(FromSqlDecimal(sd)),
        char c => ImdbValue.FromText(c.ToString()),
        char[] cs => ImdbValue.FromText(new string(cs)),
        Memory<byte> m => ImdbValue.FromBytea(m.Span),
        ArraySegment<byte> seg => ImdbValue.FromBytea(seg),
        _ => ImdbValue.FromObject(v),
    };

    internal static ImdbDecimal DecimalOf(object v) => v switch
    {
        ImdbDecimal d => d,
        decimal m => ImdbDecimal.FromDecimal(m),
        SqlDecimal sd => FromSqlDecimal(sd),
        BigInteger b => BigInteger.Abs(b) < (BigInteger)ImdbDecimal.Limit ? new ImdbDecimal((Int128)b, 0)
                                                                          : throw new OverflowException("a DECIMAL holds at most 38 digits"),
        Int128 i => new ImdbDecimal(i, 0),
        ulong ul => new ImdbDecimal(ul, 0),
        _ => new ImdbDecimal(Convert.ToInt64(v, CultureInfo.InvariantCulture), 0),
    };

    private static long IntegralOf(ImdbDecimal d)
    {
        Int128 p = ImdbDecimal.Pow10(d.Scale);
        if (d.Unscaled % p != 0) throw new ArgumentException("a number with a fraction for an INT64 parameter: never rounded");
        Int128 q = d.Unscaled / p;
        if (q < long.MinValue || q > long.MaxValue) throw new OverflowException("a number past INT64's range");
        return (long)q;
    }

    internal static ImdbDecimal FromSqlDecimal(SqlDecimal sd)
    {
        int[] w = sd.Data; // the magnitude, 32 bits a word, least significant first
        Int128 mag = ((Int128)(uint)w[3] << 96) | ((Int128)(uint)w[2] << 64) | ((Int128)(uint)w[1] << 32) | (uint)w[0];
        return new ImdbDecimal(sd.IsPositive ? mag : -mag, sd.Scale);
    }

    /// <summary>SqlDecimal holds 38 digits and a scale to 38: every imagedb DECIMAL exactly (its scale kept).</summary>
    internal static SqlDecimal ToSqlDecimal(ImdbDecimal d)
    {
        Int128 mag = d.Unscaled < 0 ? -d.Unscaled : d.Unscaled;
        int digits = 1;
        for (Int128 x = mag; x >= 10; x /= 10) digits++;
        byte precision = (byte)Math.Max(Math.Max(digits, d.Scale), 1);
        return new SqlDecimal(precision, d.Scale, d.Unscaled >= 0,
                              (int)(uint)(mag & uint.MaxValue), (int)(uint)((mag >> 32) & uint.MaxValue),
                              (int)(uint)((mag >> 64) & uint.MaxValue), (int)(uint)((mag >> 96) & uint.MaxValue));
    }

    /// <summary>A DECIMAL as System.Decimal exactly: its scale kept when it fits, else the same number with trailing zeros
    /// dropped (1.500...0 at scale 30 is 1.5); OverflowException when no System.Decimal holds the number (past 96 bits of
    /// mantissa, or more than 28 places that are not zeros). Never rounded.</summary>
    internal static decimal ToDecimalExact(ImdbDecimal d)
    {
        Int128 u = d.Unscaled;
        int s = d.Scale;
        Int128 mag = u < 0 ? -u : u;
        while ((s > 28 || mag >= Pow96) && s > 0 && mag % 10 == 0)
        {
            mag /= 10;
            s--;
        }
        if (s > 28 || mag >= Pow96)
            throw new OverflowException($"the DECIMAL {d} does not fit System.Decimal (96 bits, 28 places) exactly: read it with " +
                                        "GetFieldValue<ImdbDecimal>, GetFieldValue<SqlDecimal>, GetProviderSpecificValue or GetString");
        return new ImdbDecimal(u < 0 ? -mag : mag, s).ToDecimal();
    }

    /// <summary>A cell as ADO.NET's GetValue gives it: DBNull for a NULL; INT64 long, FLOAT64 double, BOOL bool, TEXT and
    /// ENUM string, DECIMAL decimal (exactly, or OverflowException: <see cref="ToDecimalExact"/>), TIMESTAMP DateTime (Kind
    /// Unspecified), TIMESTAMPTZ DateTimeOffset (offset 0), DATE DateOnly, TIME TimeOnly, UUID Guid, BYTEA byte[], INTERVAL
    /// ImdbInterval.</summary>
    internal static object ToClr(ImdbValue v)
    {
        if (v.IsNull) return DBNull.Value;
        return v.Type == Wire.ImdbType.Decimal ? ToDecimalExact(v.AsDecimal()) : v.ToObject()!;
    }

    internal static Type ClrType(Wire.ImdbType t) => t switch
    {
        Wire.ImdbType.Int64 => typeof(long),
        Wire.ImdbType.Float64 => typeof(double),
        Wire.ImdbType.Bool => typeof(bool),
        Wire.ImdbType.Text or Wire.ImdbType.Enum => typeof(string),
        Wire.ImdbType.Decimal => typeof(decimal),
        Wire.ImdbType.Timestamp => typeof(DateTime),
        Wire.ImdbType.TimestampTz => typeof(DateTimeOffset),
        Wire.ImdbType.Date => typeof(DateOnly),
        Wire.ImdbType.Time => typeof(TimeOnly),
        Wire.ImdbType.Uuid => typeof(Guid),
        Wire.ImdbType.Bytea => typeof(byte[]),
        Wire.ImdbType.Interval => typeof(ImdbInterval),
        _ => typeof(object),
    };

    /// <summary>ADO.NET's RecordsAffected for one statement: a write's DONE count (INSERT, UPDATE, DELETE, COPY), else -1.</summary>
    internal static int RecordsAffected(ImdbResult r)
    {
        string s = r.Status;
        int sp = s.IndexOf(' ', StringComparison.Ordinal);
        string verb = sp < 0 ? s : s.Substring(0, sp);
        return verb is "INSERT" or "UPDATE" or "DELETE" or "COPY" or "MERGE"
            ? (int)Math.Min(r.Count, int.MaxValue)
            : -1;
    }
}
