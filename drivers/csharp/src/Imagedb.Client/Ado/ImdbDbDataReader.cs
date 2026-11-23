using System;
using System.Collections;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Data;
using System.Data.Common;
using System.Data.SqlTypes;
using System.Globalization;
using System.Numerics;
using System.Threading;
using System.Threading.Tasks;
using Imagedb.Client.Wire;

namespace Imagedb.Client;

/// <summary>ADO.NET's reader over a command's (or a batch's) results. The results are whole when the reader exists
/// (the native layer reads every frame of a request before it returns): Read and NextResult never wait, and the
/// connection is free for the next command at once. Not streaming: a result is held in memory whole (the native
/// QueryAsync's rule; the server bounds what it sends a result).
/// <para>Types (GetFieldType): INT64 long; FLOAT64 double (bit for bit); BOOL bool; TEXT and ENUM string; DECIMAL
/// decimal; TIMESTAMP DateTime (Kind Unspecified); TIMESTAMPTZ DateTimeOffset (offset 0; GetDateTime gives its UTC
/// DateTime); DATE DateOnly; TIME TimeOnly; UUID Guid; BYTEA byte[]; INTERVAL ImdbInterval; a column of no known type
/// object (each value its own).</para>
/// <para>DECIMAL to 38 digits: System.Decimal holds 28 or 29 (96 bits, 28 places), so GetValue and GetDecimal give the
/// exact System.Decimal when one holds the number (trailing zeros past 28 places dropped) and throw OverflowException
/// otherwise; they never round. Every DECIMAL is read exactly by GetFieldValue&lt;ImdbDecimal&gt; (an Int128 and its
/// scale), GetFieldValue&lt;SqlDecimal&gt; (38 digits, the BCL's), GetFieldValue&lt;BigInteger&gt; (an integral value),
/// GetString (its text) and GetProviderSpecificValue (the <see cref="ImdbValue"/>).</para></summary>
public sealed class ImdbDbDataReader : DbDataReader, IDbColumnSchemaGenerator
{
    private readonly IReadOnlyList<ImdbResult> _results;
    private readonly ImdbServerException? _pending; // a batch's ERROR: thrown when NextResult reaches its statement
    private readonly IReadOnlyList<ImdbDbBatchCommand>? _batch;
    private readonly CommandBehavior _behavior;
    private readonly ImdbDbConnection _conn;
    private int _res;
    private int _row = -1;
    private bool _closed;

    internal ImdbDbDataReader(IReadOnlyList<ImdbResult> results, ImdbServerException? pending, IReadOnlyList<ImdbDbBatchCommand>? batch,
                              CommandBehavior behavior, ImdbDbConnection conn)
    {
        _results = results;
        _pending = pending;
        _batch = batch;
        _behavior = behavior;
        _conn = conn;
        if (_batch != null)
            for (int i = 0; i < results.Count && i < _batch.Count; i++) _batch[i].Affected = AdoValues.RecordsAffected(results[i]);
    }

    private ImdbResult Cur => !_closed ? _results[_res] : throw new InvalidOperationException("the reader is closed");

    private ImdbRow Row
    {
        get
        {
            var r = Cur;
            if (_row < 0 || _row >= r.Rows.Count) throw new InvalidOperationException("no current row: call Read() first (and see that it returned true)");
            return r.Rows[_row];
        }
    }

    /// <summary>The current statement's result, as the native layer gives it (its DONE: status, count, read point,
    /// own commit; its warnings).</summary>
    public ImdbResult Result => Cur;

    public override int Depth => 0;
    public override int FieldCount => Cur.Columns.Count;
    public override bool HasRows => Cur.Rows.Count > 0;
    public override bool IsClosed => _closed;

    /// <summary>The rows the statements written so far wrote (INSERT, UPDATE, DELETE, COPY), -1 when none was a write.</summary>
    public override int RecordsAffected
    {
        get
        {
            int sum = -1;
            foreach (var r in _results)
            {
                int a = AdoValues.RecordsAffected(r);
                if (a >= 0) sum = (sum < 0 ? 0 : sum) + a;
            }
            return sum;
        }
    }

    public override object this[int ordinal] => GetValue(ordinal);
    public override object this[string name] => GetValue(GetOrdinal(name));

    public override bool Read()
    {
        var r = Cur;
        if (_row < r.Rows.Count) _row++;
        return _row < r.Rows.Count;
    }

    public override Task<bool> ReadAsync(CancellationToken cancellationToken) =>
        cancellationToken.IsCancellationRequested ? Task.FromCanceled<bool>(cancellationToken) : Task.FromResult(Read());

    /// <summary>The next statement's result; a batch's failed statement throws its ERROR here (the ones before it stand).</summary>
    public override bool NextResult()
    {
        _ = Cur;
        if (_res + 1 < _results.Count)
        {
            _res++;
            _row = -1;
            return true;
        }
        if (_pending != null && _res + 1 == _results.Count && _pending.Index == _results.Count)
        {
            _res = _results.Count - 1;
            _row = int.MaxValue - 1;
            throw _pending;
        }
        _row = Cur.Rows.Count;
        return false;
    }

    public override Task<bool> NextResultAsync(CancellationToken cancellationToken)
    {
        if (cancellationToken.IsCancellationRequested) return Task.FromCanceled<bool>(cancellationToken);
        try
        {
            return Task.FromResult(NextResult());
        }
        catch (Exception e)
        {
            return Task.FromException<bool>(e);
        }
    }

    public override void Close()
    {
        if (_closed) return;
        _closed = true;
        if ((_behavior & CommandBehavior.CloseConnection) != 0) _conn.Close();
    }

    public override async Task CloseAsync()
    {
        if (_closed) return;
        _closed = true;
        if ((_behavior & CommandBehavior.CloseConnection) != 0) await _conn.CloseAsync().ConfigureAwait(false);
    }

    // ---- metadata ----

    public override string GetName(int ordinal) => Cur.Columns[ordinal].Name;

    /// <summary>The name's ordinal: exact first, then ignoring case (ADO.NET's rule); IndexOutOfRangeException else.</summary>
    public override int GetOrdinal(string name)
    {
        var cols = Cur.Columns;
        for (int i = 0; i < cols.Count; i++)
            if (string.Equals(cols[i].Name, name, StringComparison.Ordinal)) return i;
        for (int i = 0; i < cols.Count; i++)
            if (string.Equals(cols[i].Name, name, StringComparison.OrdinalIgnoreCase)) return i;
        throw new IndexOutOfRangeException($"no column named {name}");
    }

    /// <summary>The column's type as imagedb names it (INT64, DECIMAL(*,6), TEXT, ENUM, ...: what COLUMNS carries).</summary>
    public override string GetDataTypeName(int ordinal) => Cur.Columns[ordinal].TypeName;

    public override Type GetFieldType(int ordinal) => AdoValues.ClrType(Cur.Columns[ordinal].Type);

    public override Type GetProviderSpecificFieldType(int ordinal) => typeof(ImdbValue);

    /// <summary>The column as COLUMNS sent it (its wire type, precision, scale and ENUM labels).</summary>
    public ImdbColumn GetColumn(int ordinal) => Cur.Columns[ordinal];

    // ---- values ----

    public override bool IsDBNull(int ordinal) => Row.IsNull(ordinal);

    public override Task<bool> IsDBNullAsync(int ordinal, CancellationToken cancellationToken) => Task.FromResult(IsDBNull(ordinal));

    public override object GetValue(int ordinal) => AdoValues.ToClr(Row.GetValue(ordinal));

    public override int GetValues(object[] values)
    {
        ArgumentNullException.ThrowIfNull(values);
        int n = Math.Min(values.Length, FieldCount);
        for (int i = 0; i < n; i++) values[i] = GetValue(i);
        return n;
    }

    /// <summary>The cell as it came (its type, NULL or value): exact for every type.</summary>
    public override object GetProviderSpecificValue(int ordinal) => Row.GetValue(ordinal);

    public override int GetProviderSpecificValues(object[] values)
    {
        ArgumentNullException.ThrowIfNull(values);
        int n = Math.Min(values.Length, FieldCount);
        for (int i = 0; i < n; i++) values[i] = Row.GetValue(i);
        return n;
    }

    private ImdbValue V(int ordinal)
    {
        var v = Row.GetValue(ordinal);
        if (v.IsNull) throw new InvalidCastException($"column {ordinal} ({GetName(ordinal)}) is NULL: test IsDBNull first");
        return v;
    }

    public override bool GetBoolean(int ordinal) => V(ordinal).AsBool();

    public override byte GetByte(int ordinal) => checked((byte)Integer(ordinal));
    public override short GetInt16(int ordinal) => checked((short)Integer(ordinal));
    public override int GetInt32(int ordinal) => checked((int)Integer(ordinal));
    public override long GetInt64(int ordinal) => Integer(ordinal);

    /// <summary>An INT64, or a DECIMAL whose value is a whole number within INT64 (a SUM is a DECIMAL: §4).</summary>
    private long Integer(int ordinal)
    {
        var v = V(ordinal);
        if (v.Type != ImdbType.Decimal) return v.AsInt64();
        var d = v.AsDecimal();
        Int128 p = ImdbDecimal.Pow10(d.Scale);
        if (d.Unscaled % p != 0) throw new InvalidCastException("a DECIMAL with a fraction read as an integer: never rounded");
        Int128 q = d.Unscaled / p;
        return q >= long.MinValue && q <= long.MaxValue ? (long)q : throw new OverflowException("a DECIMAL past INT64's range");
    }

    /// <summary>A FLOAT64; an INT64 or DECIMAL only when the double is exactly the value.</summary>
    public override double GetDouble(int ordinal)
    {
        var v = V(ordinal);
        switch (v.Type)
        {
            case ImdbType.Float64:
                return v.AsFloat64();
            case ImdbType.Int64:
                long l = v.AsInt64();
                double dl = l;
                return dl >= -9223372036854775808.0 && dl < 9223372036854775808.0 && (long)dl == l ? dl
                    : throw new InvalidCastException("an INT64 no double holds exactly");
            case ImdbType.Decimal:
                var d = v.AsDecimal();
                double dd = d.ToDouble();
                return ImdbDecimal.TryParse(dd.ToString("R", CultureInfo.InvariantCulture), out var back) && back.NumericEquals(d) ? dd
                    : throw new InvalidCastException("a DECIMAL no double holds exactly: GetFieldValue<ImdbDecimal>");
            default:
                return v.AsFloat64(); // throws, naming the type
        }
    }

    public override float GetFloat(int ordinal)
    {
        double d = GetDouble(ordinal);
        float f = (float)d;
        return (double)f == d ? f : throw new InvalidCastException("a FLOAT64 no float holds exactly");
    }

    /// <summary>A DECIMAL exactly (OverflowException when System.Decimal cannot hold it: see the class), or an INT64.</summary>
    public override decimal GetDecimal(int ordinal)
    {
        var v = V(ordinal);
        return v.Type == ImdbType.Int64 ? v.AsInt64() : AdoValues.ToDecimalExact(v.AsDecimal());
    }

    /// <summary>TEXT, an ENUM's label, or a DECIMAL's exact text.</summary>
    public override string GetString(int ordinal)
    {
        var v = V(ordinal);
        return v.Type switch
        {
            ImdbType.Enum => v.AsEnumLabel(),
            ImdbType.Decimal => v.AsDecimal().ToString(),
            _ => v.AsText(),
        };
    }

    public override char GetChar(int ordinal)
    {
        string s = GetString(ordinal);
        return s.Length == 1 ? s[0] : throw new InvalidCastException("a TEXT that is not one UTF-16 character");
    }

    /// <summary>A TIMESTAMP (Kind Unspecified), a TIMESTAMPTZ (its UTC instant, Kind Utc), or a DATE (its midnight).</summary>
    public override DateTime GetDateTime(int ordinal)
    {
        var v = V(ordinal);
        return v.Type switch
        {
            ImdbType.TimestampTz => v.AsTimestampTz().UtcDateTime,
            ImdbType.Date => v.AsDate().ToDateTime(TimeOnly.MinValue),
            _ => v.AsTimestamp(),
        };
    }

    public override Guid GetGuid(int ordinal) => V(ordinal).AsUuid();

    /// <summary>A BYTEA's bytes from dataOffset (ADO.NET's rule: a null buffer asks the length).</summary>
    public override long GetBytes(int ordinal, long dataOffset, byte[]? buffer, int bufferOffset, int length)
    {
        byte[] b = V(ordinal).AsBytes();
        if (buffer == null) return b.Length;
        ArgumentOutOfRangeException.ThrowIfNegative(dataOffset);
        if (dataOffset >= b.Length) return 0;
        int n = (int)Math.Min(length, b.Length - dataOffset);
        Array.Copy(b, dataOffset, buffer, bufferOffset, n);
        return n;
    }

    /// <summary>A TEXT's UTF-16 characters from dataOffset (a null buffer asks the length).</summary>
    public override long GetChars(int ordinal, long dataOffset, char[]? buffer, int bufferOffset, int length)
    {
        string s = GetString(ordinal);
        if (buffer == null) return s.Length;
        ArgumentOutOfRangeException.ThrowIfNegative(dataOffset);
        if (dataOffset >= s.Length) return 0;
        int n = (int)Math.Min(length, s.Length - dataOffset);
        s.CopyTo((int)dataOffset, buffer, bufferOffset, n);
        return n;
    }

    /// <summary>The cell as T, exactly or refused (InvalidCastException; a NULL into a non-nullable T too). Beyond the
    /// typed getters: ImdbDecimal, SqlDecimal, BigInteger, Int128, DateOnly, TimeOnly, TimeSpan (a TIME, or an INTERVAL
    /// of no months and days), DateTimeOffset, ImdbInterval, ImdbValue, byte[], and Nullable of each value type.</summary>
    public override T GetFieldValue<T>(int ordinal)
    {
        var v = Row.GetValue(ordinal);
        if (v.IsNull)
        {
            if (default(T) is null) return typeof(T) == typeof(object) ? (T)(object)DBNull.Value : default!;
            if (typeof(T) == typeof(ImdbValue)) return (T)(object)v;
            if (typeof(T) == typeof(SqlDecimal)) return (T)(object)SqlDecimal.Null;
            throw new InvalidCastException($"column {ordinal} ({GetName(ordinal)}) is NULL: read it as a nullable type");
        }
        Type t = Nullable.GetUnderlyingType(typeof(T)) ?? typeof(T);
        object o = t switch
        {
            _ when t == typeof(object) => AdoValues.ToClr(v),
            _ when t == typeof(ImdbValue) => v,
            _ when t == typeof(long) => GetInt64(ordinal),
            _ when t == typeof(int) => GetInt32(ordinal),
            _ when t == typeof(short) => GetInt16(ordinal),
            _ when t == typeof(byte) => GetByte(ordinal),
            _ when t == typeof(double) => GetDouble(ordinal),
            _ when t == typeof(float) => GetFloat(ordinal),
            _ when t == typeof(bool) => v.AsBool(),
            _ when t == typeof(string) => GetString(ordinal),
            _ when t == typeof(decimal) => GetDecimal(ordinal),
            _ when t == typeof(ImdbDecimal) => v.Type == ImdbType.Int64 ? new ImdbDecimal(v.AsInt64(), 0) : v.AsDecimal(),
            _ when t == typeof(SqlDecimal) => AdoValues.ToSqlDecimal(v.Type == ImdbType.Int64 ? new ImdbDecimal(v.AsInt64(), 0) : v.AsDecimal()),
            _ when t == typeof(BigInteger) => Row.Get<BigInteger>(ordinal),
            _ when t == typeof(Int128) => (Int128)Row.Get<BigInteger>(ordinal),
            _ when t == typeof(DateTime) => GetDateTime(ordinal),
            _ when t == typeof(DateTimeOffset) => v.AsTimestampTz(),
            _ when t == typeof(DateOnly) => v.AsDate(),
            _ when t == typeof(TimeOnly) => v.AsTime(),
            _ when t == typeof(TimeSpan) => v.Type == ImdbType.Interval ? SpanOf(v.AsInterval()) : v.AsTime().ToTimeSpan(),
            _ when t == typeof(Guid) => v.AsUuid(),
            _ when t == typeof(byte[]) => v.AsBytes(),
            _ when t == typeof(ImdbInterval) => v.AsInterval(),
            _ => throw new InvalidCastException($"no conversion of a {v.Type} into a {typeof(T).Name}"),
        };
        return (T)o;
    }

    private static TimeSpan SpanOf(ImdbInterval iv)
    {
        if (iv.Months != 0 || iv.Days != 0)
            throw new InvalidCastException("an INTERVAL of months or days into a TimeSpan (a day is not always 24 hours): ImdbInterval");
        return iv.Microseconds > TimeSpan.MaxValue.Ticks / 10 || iv.Microseconds < TimeSpan.MinValue.Ticks / 10
            ? throw new OverflowException("an INTERVAL past TimeSpan's range")
            : TimeSpan.FromTicks(iv.Microseconds * 10);
    }

    public override Task<T> GetFieldValueAsync<T>(int ordinal, CancellationToken cancellationToken) => Task.FromResult(GetFieldValue<T>(ordinal));

    public override IEnumerator GetEnumerator() => new DbEnumerator(this, closeReader: false);

    // ---- schema ----

    /// <summary>Each column: its name, ordinal, CLR type, imagedb's type name, its precision and scale as COLUMNS sent
    /// them (imagedb-server sends a DECIMAL's scale alone: precision 0), nullability not known (null).</summary>
    public ReadOnlyCollection<DbColumn> GetColumnSchema()
    {
        var cols = Cur.Columns;
        var list = new List<DbColumn>(cols.Count);
        for (int i = 0; i < cols.Count; i++) list.Add(new ImdbDbColumn(cols[i], i));
        return list.AsReadOnly();
    }

    /// <summary>ADO.NET's schema table (DataTable.Load reads it): one row a column, from <see cref="GetColumnSchema"/>.</summary>
    public override DataTable GetSchemaTable()
    {
        var t = new DataTable("SchemaTable") { Locale = CultureInfo.InvariantCulture };
        t.Columns.Add(SchemaTableColumn.ColumnName, typeof(string));
        t.Columns.Add(SchemaTableColumn.ColumnOrdinal, typeof(int));
        t.Columns.Add(SchemaTableColumn.ColumnSize, typeof(int));
        t.Columns.Add(SchemaTableColumn.NumericPrecision, typeof(short));
        t.Columns.Add(SchemaTableColumn.NumericScale, typeof(short));
        t.Columns.Add(SchemaTableColumn.DataType, typeof(Type));
        t.Columns.Add(SchemaTableColumn.ProviderType, typeof(int));
        t.Columns.Add(SchemaTableColumn.IsLong, typeof(bool));
        t.Columns.Add(SchemaTableColumn.AllowDBNull, typeof(bool));
        t.Columns.Add(SchemaTableOptionalColumn.IsReadOnly, typeof(bool));
        t.Columns.Add(SchemaTableColumn.IsUnique, typeof(bool));
        t.Columns.Add(SchemaTableColumn.IsKey, typeof(bool));
        t.Columns.Add(SchemaTableColumn.BaseColumnName, typeof(string));
        t.Columns.Add("DataTypeName", typeof(string));
        foreach (var c in GetColumnSchema())
        {
            var r = t.NewRow();
            r[SchemaTableColumn.ColumnName] = c.ColumnName;
            r[SchemaTableColumn.ColumnOrdinal] = c.ColumnOrdinal ?? 0;
            r[SchemaTableColumn.ColumnSize] = c.ColumnSize ?? -1;
            r[SchemaTableColumn.NumericPrecision] = (object?)(short?)c.NumericPrecision ?? DBNull.Value;
            r[SchemaTableColumn.NumericScale] = (object?)(short?)c.NumericScale ?? DBNull.Value;
            r[SchemaTableColumn.DataType] = c.DataType;
            r[SchemaTableColumn.ProviderType] = (int)((ImdbDbColumn)c).Column.Type;
            r[SchemaTableColumn.IsLong] = false;
            r[SchemaTableColumn.AllowDBNull] = true; // not known: a result column may hold a NULL
            r[SchemaTableOptionalColumn.IsReadOnly] = true;
            r[SchemaTableColumn.IsUnique] = false;
            r[SchemaTableColumn.IsKey] = false;
            r[SchemaTableColumn.BaseColumnName] = c.ColumnName;
            r["DataTypeName"] = c.DataTypeName;
            t.Rows.Add(r);
        }
        return t;
    }
}

/// <summary>A result column as ADO.NET's DbColumn.</summary>
public sealed class ImdbDbColumn : DbColumn
{
    internal ImdbDbColumn(ImdbColumn c, int ordinal)
    {
        Column = c;
        ColumnName = c.Name;
        BaseColumnName = c.Name;
        ColumnOrdinal = ordinal;
        DataType = AdoValues.ClrType(c.Type);
        DataTypeName = c.TypeName;
        if (c.Type == ImdbType.Decimal)
        {
            NumericPrecision = c.Precision == 0 ? 38 : c.Precision; // 0: not known, 38 digits (§4)
            NumericScale = c.Scale;
        }
        if (c.Type == ImdbType.Text && c.Precision != 0) ColumnSize = c.Precision;
        AllowDBNull = null;
        IsReadOnly = true;
    }

    /// <summary>The column as COLUMNS sent it.</summary>
    public ImdbColumn Column { get; }
}

/// <summary>One statement of a <see cref="ImdbDbBatch"/>: its text and its parameters ($1 to $n).</summary>
public sealed class ImdbDbBatchCommand : DbBatchCommand
{
    private string _text = "";

    public ImdbDbBatchCommand() { }

    public ImdbDbBatchCommand(string commandText) => _text = commandText;

    [System.Diagnostics.CodeAnalysis.AllowNull]
    public override string CommandText
    {
        get => _text;
        set => _text = value ?? "";
    }

    public override CommandType CommandType
    {
        get => CommandType.Text;
        set
        {
            if (value != CommandType.Text) throw new ArgumentException("imagedb runs SQL text alone (CommandType.Text)");
        }
    }

    internal int Affected = -1;

    /// <summary>Its rows written (a write), -1 otherwise or before the batch ran it.</summary>
    public override int RecordsAffected => Affected;

    public new ImdbDbParameterCollection Parameters { get; } = new();

    protected override DbParameterCollection DbParameterCollection => Parameters;

    public override bool CanCreateParameter => true;

    public override DbParameter CreateParameter() => new ImdbDbParameter();
}

/// <summary>The batch's statements, in order.</summary>
public sealed class ImdbDbBatchCommandCollection : DbBatchCommandCollection
{
    private readonly List<ImdbDbBatchCommand> _list = new();

    internal IReadOnlyList<ImdbDbBatchCommand> List => _list;

    private static ImdbDbBatchCommand Cast(DbBatchCommand c) =>
        c as ImdbDbBatchCommand ?? throw new InvalidCastException("an ImdbDbBatch takes ImdbDbBatchCommand alone");

    public override int Count => _list.Count;
    public override bool IsReadOnly => false;
    public override void Add(DbBatchCommand item) => _list.Add(Cast(item));

    public ImdbDbBatchCommand Add(string commandText, params object?[] values)
    {
        var c = new ImdbDbBatchCommand(commandText);
        foreach (var v in values) c.Parameters.AddWithValue(v);
        _list.Add(c);
        return c;
    }

    public override void Clear() => _list.Clear();
    public override bool Contains(DbBatchCommand item) => item is ImdbDbBatchCommand c && _list.Contains(c);

    public override void CopyTo(DbBatchCommand[] array, int arrayIndex)
    {
        ArgumentNullException.ThrowIfNull(array);
        for (int i = 0; i < _list.Count; i++) array[arrayIndex + i] = _list[i];
    }

    public override IEnumerator<DbBatchCommand> GetEnumerator() => _list.GetEnumerator();
    public override int IndexOf(DbBatchCommand item) => item is ImdbDbBatchCommand c ? _list.IndexOf(c) : -1;
    public override void Insert(int index, DbBatchCommand item) => _list.Insert(index, Cast(item));
    public override bool Remove(DbBatchCommand item) => item is ImdbDbBatchCommand c && _list.Remove(c);
    public override void RemoveAt(int index) => _list.RemoveAt(index);
    protected override DbBatchCommand GetBatchCommand(int index) => _list[index];
    protected override void SetBatchCommand(int index, DbBatchCommand batchCommand) => _list[index] = Cast(batchCommand);
}

/// <summary>ADO.NET's batch: its statements as ONE QUERY (§4: run in order; an ERROR ends the batch, its index the
/// failed statement, the ones after it unrun, the ones before it standing, committed or in the open transaction). The
/// reader's NextResult throws the failed statement's ERROR when it reaches it (ExecuteReader itself when the first
/// fails); the exception's BatchCommand names it. A batch is not a transaction.</summary>
public sealed class ImdbDbBatch : DbBatch
{
    private ImdbDbConnection? _conn;
    private volatile ImdbConnection? _running;

    public new ImdbDbBatchCommandCollection BatchCommands { get; } = new();

    protected override DbBatchCommandCollection DbBatchCommands => BatchCommands;

    /// <summary>Seconds (0: none): the connection string's Command Timeout until set.</summary>
    public override int Timeout
    {
        get => _timeout ?? _conn?.DefaultCommandTimeout ?? 30;
        set
        {
            ArgumentOutOfRangeException.ThrowIfNegative(value);
            _timeout = value;
        }
    }

    private int? _timeout;

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
            _ => throw new ArgumentException("an ImdbDbBatch runs on an ImdbDbConnection"),
        };
    }

    protected override DbTransaction? DbTransaction { get; set; }

    protected override DbBatchCommand CreateDbBatchCommand() => new ImdbDbBatchCommand();

    /// <summary>Cancels the batch's statement running now (in band: CANCEL): it ends in ERROR 15, the batch with it.</summary>
    public override void Cancel() => _running?.Cancel();

    /// <summary>A hint ADO.NET lets a provider ignore: a batch runs as one QUERY.</summary>
    public override void Prepare() { }

    public override Task PrepareAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;

    private async Task<ImdbDbDataReader> RunAsync(CommandBehavior behavior, CancellationToken ct)
    {
        if (_conn == null) throw new InvalidOperationException("the batch has no connection");
        if (_conn.State != ConnectionState.Open) throw new InvalidOperationException($"the connection is {_conn.State}, not Open");
        var cmds = BatchCommands.List;
        if (cmds.Count == 0) throw new InvalidOperationException("the batch has no commands");
        var sts = new ImdbStatement[cmds.Count];
        for (int i = 0; i < sts.Length; i++)
        {
            if (string.IsNullOrWhiteSpace(cmds[i].CommandText)) throw new InvalidOperationException($"the batch's command {i} has no text");
            cmds[i].Affected = -1;
            ImdbValue[] args;
            try
            {
                args = cmds[i].Parameters.ToWire();
            }
            catch (ArgumentException e)
            {
                throw new ArgumentException($"the batch's command {i}: {e.Message}", e);
            }
            sts[i] = new ImdbStatement(cmds[i].CommandText, args);
        }
        var n = _conn.Native;
        int secs = Timeout;
        using var timeout = secs > 0 ? new CancellationTokenSource(TimeSpan.FromSeconds(secs)) : null;
        using var linked = timeout != null ? CancellationTokenSource.CreateLinkedTokenSource(ct, timeout.Token) : null;
        ImdbBatchResult b;
        _running = n;
        try
        {
            b = await n.ExecuteBatchAsync(sts, linked?.Token ?? ct).ConfigureAwait(false);
        }
        catch (OperationCanceledException oce) when (timeout != null && timeout.IsCancellationRequested && !ct.IsCancellationRequested)
        {
            throw new ImdbException((int)ImdbErrorCode.Cancelled,
                $"the batch passed its timeout of {secs} s and was cancelled (in band: its ERROR 15); the connection stays usable",
                new TimeoutException("Timeout " + secs.ToString(CultureInfo.InvariantCulture) + " s", oce.InnerException ?? oce));
        }
        finally
        {
            _running = null;
        }
        var err = b.Error;
        if (err != null && err.Index < cmds.Count) err.FailedBatchCommand = cmds[(int)err.Index];
        var reader = new ImdbDbDataReader(b.Results, err, cmds, behavior, _conn);
        if (err != null && b.Results.Count == 0) throw err; // the first statement failed: nothing to read
        return reader;
    }

    protected override DbDataReader ExecuteDbDataReader(CommandBehavior behavior) => RunAsync(behavior, CancellationToken.None).GetAwaiter().GetResult();

    protected override async Task<DbDataReader> ExecuteDbDataReaderAsync(CommandBehavior behavior, CancellationToken cancellationToken) =>
        await RunAsync(behavior, cancellationToken).ConfigureAwait(false);

    public new ImdbDbDataReader ExecuteReader(CommandBehavior behavior = CommandBehavior.Default) => RunAsync(behavior, CancellationToken.None).GetAwaiter().GetResult();

    /// <summary>The rows the batch's writes wrote (-1 when none was a write); the failed statement's ERROR thrown.</summary>
    public override int ExecuteNonQuery() => ExecuteNonQueryAsync(CancellationToken.None).GetAwaiter().GetResult();

    public override async Task<int> ExecuteNonQueryAsync(CancellationToken cancellationToken = default)
    {
        var r = await RunAsync(CommandBehavior.Default, cancellationToken).ConfigureAwait(false);
        while (r.NextResult()) { } // reaches (and throws) a failed statement's ERROR
        return r.RecordsAffected;
    }

    public override object? ExecuteScalar() => ExecuteScalarAsync(CancellationToken.None).GetAwaiter().GetResult();

    public override async Task<object?> ExecuteScalarAsync(CancellationToken cancellationToken = default)
    {
        var r = await RunAsync(CommandBehavior.Default, cancellationToken).ConfigureAwait(false);
        object? first = r.Read() && r.FieldCount > 0 ? r.GetValue(0) : null;
        while (r.NextResult()) { }
        return first;
    }
}
