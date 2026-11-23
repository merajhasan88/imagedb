using System;
using System.Collections.Generic;
using System.Globalization;
using System.Numerics;
using Imagedb.Client.Wire;

namespace Imagedb.Client;

/// <summary>A result column (COLUMNS): its name, its wire type, and its precision and scale by §4's rule: DECIMAL a
/// precision of 1 to 38 (0: not known, 38 digits) and a scale; INT64 a width (0 BIGINT, 16 SMALLINT, 32 INTEGER); TEXT
/// its VARCHAR length in characters (0 unbounded); ENUM its labels in the type's order; type None a column whose
/// statement does not know its type (each value carries its own).</summary>
public sealed class ImdbColumn
{
    public ImdbColumn(string name, ImdbType type, ushort precision = 0, ushort scale = 0, IReadOnlyList<string>? labels = null)
    {
        Name = name;
        Type = type;
        Precision = precision;
        Scale = scale;
        Labels = labels ?? Array.Empty<string>();
    }

    public string Name { get; }
    public ImdbType Type { get; }
    public ushort Precision { get; }
    public ushort Scale { get; }
    public IReadOnlyList<string> Labels { get; }

    private HashSet<string>? _labelSet;

    private HashSet<string> LabelSet => _labelSet ??= new HashSet<string>(Labels, StringComparer.Ordinal);

    /// <summary>ROWS' rule for an ENUM: the value one of its labels (ordinal: one string a byte sequence).</summary>
    internal bool HasLabel(string label) => LabelSet.Contains(label);

    internal bool LabelsDistinct() => LabelSet.Count == Labels.Count;

    /// <summary>The type as SQL spells it: INT64, SMALLINT, INTEGER, DECIMAL(38,6), DECIMAL(*,6) (precision not reported:
    /// 38 digits), VARCHAR(12), TEXT, ENUM, ... (imagedb-server reports a result column's DECIMAL scale alone: an INT64 width
    /// and a VARCHAR length travel as 0 there)</summary>
    public string TypeName => Type switch
    {
        ImdbType.Int64 => Precision == 16 ? "SMALLINT" : Precision == 32 ? "INTEGER" : "INT64",
        ImdbType.Decimal => Precision == 0 ? string.Create(CultureInfo.InvariantCulture, $"DECIMAL(*,{Scale})")
                                           : string.Create(CultureInfo.InvariantCulture, $"DECIMAL({Precision},{Scale})"),
        ImdbType.Text => Precision == 0 ? "TEXT" : string.Create(CultureInfo.InvariantCulture, $"VARCHAR({Precision})"),
        ImdbType.Float64 => "FLOAT64",
        ImdbType.Bool => "BOOL",
        ImdbType.Timestamp => "TIMESTAMP",
        ImdbType.TimestampTz => "TIMESTAMPTZ",
        ImdbType.Date => "DATE",
        ImdbType.Time => "TIME",
        ImdbType.Uuid => "UUID",
        ImdbType.Bytea => "BYTEA",
        ImdbType.Interval => "INTERVAL",
        ImdbType.Enum => "ENUM",
        _ => "(not known)",
    };

    public override string ToString() => Name + " " + TypeName;
}

/// <summary>The read point a DONE carries (the engine's imdb_result): the commit read, its hash, the state digest,
/// the lake's commit and manifest, the database's id, and whether the read also saw its transaction's own writes.</summary>
public sealed record ImdbReadPoint(ulong Commit, byte[] CommitHash, byte[] StateDigest, ulong LakeCommit, byte[] LakeManifest,
                                   byte[] DatabaseId, bool OwnWrites);

/// <summary>A write's own commit (at least 1) and its hash, in a DONE.</summary>
public sealed record ImdbWriteCommit(ulong Commit, byte[] CommitHash);

/// <summary>A session in SESSIONS_LIST: its id (a counter at its connection's accept, never reused), its role's id,
/// its endpoint, its state at its last request's end, its age since login, its role's name as the logins give it now
/// ("" for a role no longer among them).</summary>
public sealed record ImdbSession(ulong Id, uint RoleId, ImdbEndpoint Endpoint, ImdbSessionState State, ulong AgeMilliseconds,
                                 string RoleName);

/// <summary>A result row: its values in column order.</summary>
public sealed class ImdbRow
{
    private readonly ImdbValue[] _v;
    private readonly ImdbResult _r;

    internal ImdbRow(ImdbValue[] values, ImdbResult result)
    {
        _v = values;
        _r = result;
    }

    public int Count => _v.Length;

    /// <summary>The cell's natural CLR value (null for a NULL): see <see cref="ImdbValue"/>.</summary>
    public object? this[int i] => _v[i].ToObject();

    public object? this[string column] => _v[_r.Ordinal(column)].ToObject();

    /// <summary>The cell as it came: its type, NULL or value.</summary>
    public ImdbValue GetValue(int i) => _v[i];

    public bool IsNull(int i) => _v[i].IsNull;
    public long GetInt64(int i) => _v[i].AsInt64();
    public int GetInt32(int i) => checked((int)_v[i].AsInt64());
    public short GetInt16(int i) => checked((short)_v[i].AsInt64());
    public double GetDouble(int i) => _v[i].AsFloat64();
    public bool GetBoolean(int i) => _v[i].AsBool();

    /// <summary>A TEXT or an ENUM's label.</summary>
    public string GetString(int i) => _v[i].Type == ImdbType.Enum ? _v[i].AsEnumLabel() : _v[i].AsText();

    public ImdbDecimal GetDecimal(int i) => _v[i].AsDecimal();
    public DateTime GetTimestamp(int i) => _v[i].AsTimestamp();
    public DateTimeOffset GetTimestampTz(int i) => _v[i].AsTimestampTz();
    public DateOnly GetDate(int i) => _v[i].AsDate();
    public TimeOnly GetTime(int i) => _v[i].AsTime();
    public Guid GetGuid(int i) => _v[i].AsUuid();
    public byte[] GetBytes(int i) => _v[i].AsBytes();
    public ImdbInterval GetInterval(int i) => _v[i].AsInterval();

    /// <summary>The cell converted to T when no digit or tick is lost (an INT64 into int checked, a DECIMAL into decimal
    /// when it fits, a TIMESTAMPTZ into DateTime of Kind Utc).</summary>
    public T Get<T>(int i)
    {
        var v = _v[i];
        if (v.IsNull)
        {
            if (default(T) is null) return default!;
            throw new InvalidCastException($"column {i}: a NULL into a {typeof(T).Name}");
        }
        object o = typeof(T) switch
        {
            var t when t == typeof(long) => v.AsInt64(),
            var t when t == typeof(int) => checked((int)v.AsInt64()),
            var t when t == typeof(short) => checked((short)v.AsInt64()),
            var t when t == typeof(double) => v.AsFloat64(),
            var t when t == typeof(bool) => v.AsBool(),
            var t when t == typeof(string) => GetString(i),
            var t when t == typeof(ImdbDecimal) => v.AsDecimal(),
            var t when t == typeof(decimal) => v.Type == ImdbType.Int64 ? (decimal)v.AsInt64() : v.AsDecimal().ToDecimal(),
            var t when t == typeof(BigInteger) => v.Type == ImdbType.Int64 ? (BigInteger)v.AsInt64() : ScaleZero(v.AsDecimal()),
            var t when t == typeof(DateTime) => v.Type == ImdbType.TimestampTz ? v.AsTimestampTz().UtcDateTime : v.AsTimestamp(),
            var t when t == typeof(DateTimeOffset) => v.AsTimestampTz(),
            var t when t == typeof(DateOnly) => v.AsDate(),
            var t when t == typeof(TimeOnly) => v.AsTime(),
            var t when t == typeof(Guid) => v.AsUuid(),
            var t when t == typeof(byte[]) => v.AsBytes(),
            var t when t == typeof(ImdbInterval) => v.AsInterval(),
            var t when t == typeof(ImdbValue) => v,
            var t when t == typeof(object) => v.ToObject()!,
            _ => throw new InvalidCastException($"no conversion of a {v.Type} into a {typeof(T).Name}"),
        };
        return (T)o;
    }

    public T Get<T>(string column) => Get<T>(_r.Ordinal(column));

    private static BigInteger ScaleZero(ImdbDecimal d)
    {
        if (d.Scale != 0 && d.Unscaled % ImdbDecimal.Pow10(d.Scale) != 0)
            throw new InvalidCastException("a DECIMAL with a fraction into an integer");
        return (BigInteger)(d.Unscaled / ImdbDecimal.Pow10(d.Scale));
    }

    public IReadOnlyList<ImdbValue> Values => _v;
}

/// <summary>One statement's (or parameter set's) answer: its columns and rows when it returns rows (COLUMNS even for
/// none), its warnings, and its DONE (status, count, read point, own commit). COPY TO STDOUT's data, when the statement
/// ran through QueryAsync rather than CopyOutAsync, is in <see cref="CopyData"/>.</summary>
public sealed class ImdbResult
{
    private Dictionary<string, int>? _names;

    internal ImdbResult(IReadOnlyList<ImdbColumn> columns, List<ImdbValue[]> rows, IReadOnlyList<string> warnings,
                        DoneMessage done, byte[]? copyData)
    {
        Columns = columns;
        var r = new ImdbRow[rows.Count];
        for (int i = 0; i < r.Length; i++) r[i] = new ImdbRow(rows[i], this);
        Rows = r;
        Warnings = warnings;
        Status = done.Status;
        Count = done.Count;
        ReadPoint = done.Read;
        Write = done.Write;
        CopyData = copyData;
    }

    /// <summary>The columns (empty when the statement returned no rows: no COLUMNS was sent).</summary>
    public IReadOnlyList<ImdbColumn> Columns { get; }

    public bool ReturnsRows => Columns.Count > 0;
    public IReadOnlyList<ImdbRow> Rows { get; }
    public IReadOnlyList<string> Warnings { get; }

    /// <summary>The engine's status text ("INSERT 0 3", "SELECT 2", ...).</summary>
    public string Status { get; }

    /// <summary>The rows returned or written.</summary>
    public ulong Count { get; }

    public ImdbReadPoint? ReadPoint { get; }
    public ImdbWriteCommit? Write { get; }
    public byte[]? CopyData { get; }

    public int Ordinal(string column)
    {
        if (_names == null)
        {
            var d = new Dictionary<string, int>(StringComparer.Ordinal);
            for (int i = 0; i < Columns.Count; i++) d.TryAdd(Columns[i].Name, i);
            _names = d;
        }
        return _names.TryGetValue(column, out int k) ? k : throw new IndexOutOfRangeException($"no column named {column}");
    }
}

/// <summary>A batch's outcome (a QUERY's statements, an EXECUTE's sets): the results of those that ran, in order; the
/// ERROR that ended it (its index the failed one: those after it did not run), or null; READY's state. A batch is not
/// a transaction: each statement before the failed one stands, committed or in the open transaction.</summary>
public sealed class ImdbBatchResult
{
    internal ImdbBatchResult(IReadOnlyList<ImdbResult> results, ImdbServerException? error, ImdbTransactionState state)
    {
        Results = results;
        Error = error;
        State = state;
    }

    public IReadOnlyList<ImdbResult> Results { get; }
    public ImdbServerException? Error { get; }
    public ImdbTransactionState State { get; }

    /// <summary>The results, or the ERROR thrown (its CompletedResults the ones that ran).</summary>
    public IReadOnlyList<ImdbResult> ThrowIfError()
    {
        if (Error != null) throw Error;
        return Results;
    }
}
