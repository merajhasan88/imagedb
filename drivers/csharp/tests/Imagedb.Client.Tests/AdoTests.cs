using System;
using System.Collections.Generic;
using System.Data;
using System.Data.Common;
using System.Data.SqlTypes;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Numerics;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Imagedb.Client.Wire;

namespace Imagedb.Client.Tests;

/// <summary>The ADO.NET layer (ImdbDbConnection, ImdbDbCommand, ImdbDbParameter, ImdbDbDataReader, ImdbDbTransaction,
/// ImdbDbBatch, ImdbDbFactory). Offline (group mock): the connection string's rules, each parameter's wire value (some
/// against §4's vectors), DECIMAL's exact conversions. Live (group live, after LiveTests: server B's socket, and its TCP
/// port by pin and by CA; server A's TCP port for the binding's refusal; big_sock is copy_in_1m_rows[sock]'s table).</summary>
public static class AdoTests
{
    public static IEnumerable<TestCase> All()
    {
        yield return new("mock", "ado_connection_string", ConnectionString);
        yield return new("mock", "ado_parameter_wire_values", ParameterWire);
        yield return new("mock", "ado_decimal_exact_conversions", DecimalConversions);
        yield return new("live", "ado_open_close_states", OpenClose);
        yield return new("live", "ado_tcp_pin_ca_and_refusals", TcpPinCa);
        yield return new("live", "ado_types_roundtrip_reader", TypesReader);
        yield return new("live", "ado_typed_null_parameters", TypedNulls);
        yield return new("live", "ado_decimal_38_digits", Decimal38);
        yield return new("live", "ado_nonquery_counts_and_statuses", NonQueryCounts);
        yield return new("live", "ado_transactions", Transactions);
        yield return new("live", "ado_prepare_execute_deallocate", Prepare);
        yield return new("live", "ado_cancel_token_and_timeout", Cancel);
        yield return new("live", "ado_batch_and_its_error", Batch);
        yield return new("live", "ado_factory_generic_code_and_datatable", Factory);
        yield return new("live", "ado_native_level_through_the_connection", NativeLevel);
    }

    private static string Env(string k) => Environment.GetEnvironmentVariable(k) ?? throw new CheckFailed($"{k} is not set (run_tests.sh sets it)");

    private static string Pw => Env("IMDB_DRV_PASSWORD");

    private static string SockCs => $"Socket={Env("IMDB_DRV_B_SOCK")};User=admin;Password={Pw};Reply Timeout=120";

    private static ImdbDbConnection OpenSock()
    {
        var c = new ImdbDbConnection(SockCs);
        c.Open();
        return c;
    }

    private static ImdbDbCommand Cmd(ImdbDbConnection c, string sql, params object?[] values)
    {
        var cmd = c.CreateCommand();
        cmd.CommandText = sql;
        foreach (var v in values) cmd.Parameters.AddWithValue(v);
        return cmd;
    }

    private static object? Scalar(ImdbDbConnection c, string sql, params object?[] values)
    {
        using var cmd = Cmd(c, sql, values);
        return cmd.ExecuteScalar();
    }

    private static int NonQuery(ImdbDbConnection c, string sql, params object?[] values)
    {
        using var cmd = Cmd(c, sql, values);
        return cmd.ExecuteNonQuery();
    }

    // ======================= offline =======================

    private static Task ConnectionString()
    {
        var b = new ImdbDbConnectionStringBuilder("Socket=/x/s;User=admin;Password=pw-1");
        var o = b.ToOptions();
        T.Eq("/x/s", o.SocketPath, "Socket");
        T.Eq("admin", o.User, "User");
        T.Check(o.Tls == null && o.Host == null, "no TLS on the socket");
        foreach (var syn in new[] { "Username", "User ID", "UID", "user" })
            T.Eq("bob", new ImdbDbConnectionStringBuilder($"Socket=/s;{syn}=bob;PWD=x").ToOptions().User, "synonym " + syn);
        var h = new ImdbDbConnectionStringBuilder($"Server=db.example;Port=7000;User=a;Password=b;Pin={new string('a', 64)}").ToOptions();
        T.Check(h.Host == "db.example" && h.Port == 7000 && h.Tls is { IsPinned: true }, "Server is Host; a pin");
        T.Eq(30, new ImdbDbConnectionStringBuilder("Socket=/s").CommandTimeout, "Command Timeout defaults to 30 s");
        T.Eq(TimeSpan.FromSeconds(7), new ImdbDbConnectionStringBuilder("Socket=/s;User=a;Password=b;Reply Timeout=7").ToOptions().ReplyTimeout, "Reply Timeout");
        // a key it does not know is refused, never ignored (a misspelt Pin must not leave a connection unverified)
        var e = T.Throws<ArgumentException>(() => new ImdbDbConnectionStringBuilder("Host=h;Port=1;User=a;Password=b;Pinn=00"), "an unknown key");
        T.Check(e.Message.Contains("pinn", StringComparison.OrdinalIgnoreCase), "named (the BCL parser lower-cases a key): " + e.Message);
        T.Throws<ArgumentException>(() => new ImdbDbConnection("Socket=/s;SslMode=Disable"), "an unknown key in the connection's string");
        T.Throws<ArgumentException>(() => new ImdbDbConnectionStringBuilder()["Trust Server Certificate"] = "true", "an unknown key through the indexer");
        // TCP: exactly one of Pin and CA File; the socket neither; a socket or a host, exactly one
        e = T.Throws<ArgumentException>(() => new ImdbDbConnectionStringBuilder("Host=h;Port=1;User=a;Password=secret-pw").ToOptions(), "TCP with neither");
        T.Check(!e.Message.Contains("secret-pw", StringComparison.Ordinal), "no password in a message");
        T.Throws<ArgumentException>(() => new ImdbDbConnectionStringBuilder($"Host=h;Port=1;User=a;Password=b;Pin={new string('a', 64)};CA File=/x").ToOptions(), "TCP with both");
        T.Throws<ArgumentException>(() => new ImdbDbConnectionStringBuilder($"Socket=/s;User=a;Password=b;Pin={new string('a', 64)}").ToOptions(), "the socket with a pin");
        T.Throws<ArgumentException>(() => new ImdbDbConnectionStringBuilder("Socket=/s;Host=h;Port=1;User=a;Password=b").ToOptions(), "both a socket and a host");
        T.Throws<ArgumentException>(() => new ImdbDbConnectionStringBuilder("User=a;Password=b").ToOptions(), "neither");
        T.Throws<ArgumentException>(() => new ImdbDbConnectionStringBuilder($"Host=h;Port=1;User=a;Password=b;Pin={new string('a', 63)}").ToOptions(), "a pin of 63 digits");
        T.Throws<ArgumentException>(() => new ImdbDbConnectionStringBuilder("Socket=/s;Port=x").ToOptions(), "a port not a number");
        // Open refuses before any byte (no server here)
        using var c = new ImdbDbConnection("Host=127.0.0.1;Port=1;User=a;Password=b");
        T.Throws<ArgumentException>(() => c.Open(), "Open with no verification");
        T.Eq(ConnectionState.Closed, c.State, "still closed");
        T.Throws<InvalidOperationException>(() => _ = c.ServerVersion, "no version while closed");
        T.Throws<NotSupportedException>(() => c.ChangeDatabase("x"), "one database a server");
        return Task.CompletedTask;
    }

    private static ImdbValue W(object? v, DbType? dbt = null, ImdbType? it = null)
    {
        var p = new ImdbDbParameter { Value = v };
        if (dbt is { } d) p.DbType = d;
        if (it is { } t) p.ImdbType = t;
        return p.ToWire(1);
    }

    private static void Wire(string hex, object? v, DbType? dbt, ImdbType? it, string what) =>
        T.Bytes(T.Hex(hex), Codec.EncodeValue(W(v, dbt, it)), what);

    private static void Refused(object? v, DbType? dbt, ImdbType? it, string what) =>
        T.Throws<ArgumentException>(() => W(v, dbt, it), what);

    private static Task ParameterWire()
    {
        // §4's value vectors (docs/n1-design.md, the values table) through the ADO.NET parameter
        Wire("81", null, DbType.Int64, null, "§4: a NULL INT64 is 81 (a null with DbType.Int64)");
        Wire("81", DBNull.Value, DbType.Int32, null, "a DBNull with DbType.Int32: a NULL INT64");
        Wire("01 feffffffffffffff", -2, DbType.Int32, null, "§4: -2 (an int declared Int32)");
        Wire("02 000000000000f83f", 1.5, null, null, "§4: 1.5");
        Wire("02 000000000000f83f", 1.5f, DbType.Single, null, "1.5f as FLOAT64");
        Wire("03 01", true, DbType.Boolean, null, "§4: true");
        Wire("04 03000000 68c3a9", "hé", DbType.String, null, "§4: \"hé\"");
        Wire("05 02 c7cfffffffffffffffffffffffffffff", -123.45m, DbType.Decimal, null, "§4: -123.45 (a System.Decimal)");
        Wire("05 02 c7cfffffffffffffffffffffffffffff", SqlDecimal.Parse("-123.45"), null, null, "§4: -123.45 (a SqlDecimal)");
        Wire("06 0040d400014023ff", new DateTime(1, 1, 1), DbType.DateTime2, null, "§4: TIMESTAMP 0001-01-01");
        Wire("07 ff5f73cc0c448403", new DateTimeOffset(DateTime.MaxValue.AddTicks(-9), TimeSpan.Zero), DbType.DateTimeOffset, null, "§4: TIMESTAMPTZ max");
        Wire("08 c606f5ff", new DateTime(1, 1, 1), DbType.Date, null, "§4: DATE 0001-01-01 from a DateTime at midnight");
        Wire("09 ff5fd71d14000000", TimeSpan.FromDays(1) - TimeSpan.FromTicks(10), DbType.Time, null, "§4: TIME 23:59:59.999999 from a TimeSpan");
        Wire("0a 000102030405060708090a0b0c0d0e0f", Guid.Parse("00010203-0405-0607-0809-0a0b0c0d0e0f"), DbType.Guid, null, "§4: the UUID vector");
        Wire("0b 02000000 00ff", new byte[] { 0, 0xff }, DbType.Binary, null, "§4: \\x00ff");
        Wire("0c 01000000 feffffff 0300000000000000", new ImdbInterval(1, -2, 3), null, ImdbType.Interval, "§4: 1 mon -2 days 3 us");
        // ENUM: a label is TEXT (§4: a parameter is any value but a non-NULL ENUM); a NULL ENUM keeps its type
        Wire("04 01000000 61", "a", null, ImdbType.Enum, "an ENUM label as TEXT");
        Wire("8d", null, null, ImdbType.Enum, "a NULL ENUM");
        Wire("8c", null, null, ImdbType.Interval, "a NULL INTERVAL");
        Wire("80", null, null, null, "a null of no declared type: a NULL of no type");
        Wire("85", SqlDecimal.Null, null, null, "SqlDecimal.Null: a NULL DECIMAL");
        // -0.0 sent as 0.0 (the engine keeps one zero); NaN and infinities refused
        Wire("02 0000000000000000", -0.0, null, null, "-0.0 as 0.0");
        Wire("02 0000000000000000", -0.0, DbType.Double, null, "-0.0 declared Double as 0.0");
        Refused(double.NaN, null, null, "NaN");
        Refused(double.PositiveInfinity, DbType.Double, null, "an infinity");
        // conversions only when nothing is lost
        Wire("05 00 05000000000000000000000000000000", 5, DbType.Decimal, null, "an int as a DECIMAL");
        Wire("05 00 ffffffffffffffff0000000000000000", ulong.MaxValue, DbType.Decimal, null, "ulong.MaxValue as a DECIMAL");
        Refused(ulong.MaxValue, null, null, "ulong.MaxValue undeclared: past INT64");
        Wire("01 0c00000000000000", 12.00m, DbType.Int64, null, "12.00m as an INT64");
        Refused(12.5m, DbType.Int64, null, "12.5m as an INT64");
        Refused(2.5, DbType.Decimal, null, "a double as a DECIMAL");
        Refused("5", DbType.Int32, null, "a string as an INT64");
        Refused(5, DbType.String, null, "an int as a TEXT");
        Refused(new DateTime(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc), DbType.DateTime2, null, "a UTC DateTime as a TIMESTAMP");
        Refused(new DateTime(2026, 1, 1), DbType.DateTimeOffset, null, "an Unspecified DateTime as a TIMESTAMPTZ");
        T.Eq(ImdbValue.FromTimestampTz(new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero)),
             W(new DateTime(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc), DbType.DateTimeOffset), "a UTC DateTime as a TIMESTAMPTZ");
        Refused(new DateTime(2026, 1, 1, 12, 0, 0), DbType.Date, null, "a DateTime with a time as a DATE");
        Refused(TimeSpan.FromHours(25), DbType.Time, null, "25 hours as a TIME");
        Refused("00010203-0405-0607-0809-0a0b0c0d0e0f", DbType.Guid, null, "a string as a UUID");
        Refused(new DateTime(2026, 1, 1, 0, 0, 0, DateTimeKind.Local), null, null, "a Local DateTime undeclared");
        Refused(BigInteger.Pow(10, 38), null, null, "10^38: past 38 digits");
        Refused(TimeSpan.FromTicks(1), null, null, "a TimeSpan finer than a microsecond");
        Wire("0c 00000000 00000000 00d6117e03000000", TimeSpan.FromMinutes(250), null, null, "a TimeSpan undeclared: an INTERVAL");
        Wire("04 01000000 63", 'c', DbType.String, null, "a char as TEXT");
        Wire("0b 01000000 02", new ArraySegment<byte>(new byte[] { 1, 2, 3 }, 1, 1), null, null, "an ArraySegment as BYTEA");
        // the inferred DbType (ADO.NET's convention) and the positional names
        T.Eq(DbType.Int64, new ImdbDbParameter { Value = 5L }.DbType, "a long's DbType");
        T.Eq(DbType.DateTimeOffset, new ImdbDbParameter { Value = DateTime.UtcNow }.DbType, "a UTC DateTime's DbType");
        T.Eq(DbType.Decimal, new ImdbDbParameter { Value = SqlDecimal.Parse("1") }.DbType, "a SqlDecimal's DbType");
        var pc = new ImdbDbParameterCollection();
        pc.AddWithValue("$1", 1L);
        pc.AddWithValue("2", 2L);
        pc.AddWithValue(3L);
        T.Eq(3, pc.ToWire().Length, "$1, 2 and no name in their places");
        pc.AddWithValue("$5", 4L);
        T.Throws<ArgumentException>(() => pc.ToWire(), "$5 in the fourth place");
        var pc2 = new ImdbDbParameterCollection();
        pc2.AddWithValue("@id", 1L);
        var ne = T.Throws<ArgumentException>(() => pc2.ToWire(), "a name not positional");
        T.Check(ne.Message.Contains("positional", StringComparison.Ordinal), ne.Message);
        T.Throws<ArgumentException>(() => new ImdbDbParameter { Direction = ParameterDirection.Output }, "input alone");
        return Task.CompletedTask;
    }

    private static Task DecimalConversions()
    {
        Int128 p96 = (Int128)1 << 96;
        T.Eq(decimal.MaxValue, AdoValues.ToDecimalExact(new ImdbDecimal(p96 - 1, 0)), "2^96 - 1 is decimal.MaxValue");
        T.Eq(decimal.MinValue, AdoValues.ToDecimalExact(new ImdbDecimal(-(p96 - 1), 0)), "-(2^96 - 1)");
        T.Throws<OverflowException>(() => AdoValues.ToDecimalExact(new ImdbDecimal(p96, 0)), "2^96: no System.Decimal holds it");
        T.Eq(decimal.MaxValue, AdoValues.ToDecimalExact(new ImdbDecimal((p96 - 1) * 10, 1)), "(2^96 - 1) at scale 1, a trailing zero: exact");
        var s29 = ImdbDecimal.Parse("1.00000000000000000000000000001");
        T.Eq(29, (int)s29.Scale, "scale 29");
        T.Throws<OverflowException>(() => AdoValues.ToDecimalExact(s29), "29 places that are not zeros: refused, never rounded");
        T.Eq(1.5m, AdoValues.ToDecimalExact(ImdbDecimal.Parse("1.500000000000000000000000000000")), "1.5 at scale 30: exact");
        T.Eq(2, decimal.GetBits(AdoValues.ToDecimalExact(ImdbDecimal.Parse("1.50")))[3] >> 16 & 0xff, "1.50 keeps its scale 2");
        T.Throws<OverflowException>(() => AdoValues.ToDecimalExact(ImdbDecimal.Parse(new string('9', 38))), "38 nines");
        foreach (var text in new[] { "0", "1", "-1", new string('9', 38), "-" + new string('9', 38), "0." + new string('9', 38),
                                     "-0." + new string('0', 37) + "1", "79228162514264337593543950336", "-123.45", "1.50" })
        {
            var d = ImdbDecimal.Parse(text);
            var sd = AdoValues.ToSqlDecimal(d);
            T.Eq(d.ToString(), sd.ToString(), "SqlDecimal's text, exactly: " + text);
            T.Eq(d, AdoValues.FromSqlDecimal(sd), "back from SqlDecimal, its scale kept: " + text);
        }
        return Task.CompletedTask;
    }

    // ======================= live =======================

    private static Task OpenClose()
    {
        var changes = new List<string>();
        using var c = new ImdbDbConnection(SockCs);
        c.StateChange += (_, e) => changes.Add($"{e.OriginalState}>{e.CurrentState}");
        T.Eq(ConnectionState.Closed, c.State, "closed before Open");
        c.Open();
        T.Eq(ConnectionState.Open, c.State, "open");
        T.Eq("IMDBWIR1", c.ServerVersion, "ServerVersion");
        T.Eq(Env("IMDB_DRV_B_SOCK"), c.DataSource, "DataSource");
        T.Eq(42L, Scalar(c, "SELECT 41 + 1"), "ExecuteScalar");
        T.Eq(42L, Scalar(c, "SELECT $1 + 1", 41L), "with a parameter");
        T.Throws<InvalidOperationException>(() => c.Open(), "open twice");
        T.Throws<InvalidOperationException>(() => c.ConnectionString = "Socket=/x", "the string of an open connection");
        c.Close();
        T.Eq(ConnectionState.Closed, c.State, "closed");
        T.Eq("Closed>Open,Open>Closed", string.Join(",", changes), "StateChange");
        c.Open(); // again, on the same object
        T.Eq(1L, Scalar(c, "SELECT 1"), "reopened");
        c.Close();
        T.Throws<InvalidOperationException>(() => Scalar(c, "SELECT 1"), "a command on a closed connection");
        // CloseConnection closes it with the reader; SchemaOnly is refused before anything runs (it would run a write)
        c.Open();
        using (var cmd = Cmd(c, "SELECT 7 AS seven"))
        {
            T.Throws<NotSupportedException>(() => cmd.ExecuteReader(CommandBehavior.SchemaOnly), "SchemaOnly");
            var r = cmd.ExecuteReader(CommandBehavior.CloseConnection);
            T.Check(r.Read() && r.GetInt64(0) == 7, "read");
            T.Eq(ConnectionState.Open, c.State, "open while the reader is");
            r.Close();
            T.Eq(ConnectionState.Closed, c.State, "closed with the reader");
        }
        // a wrong password: the native refusal, an ADO.NET DbException; no password in its words
        using var bad = new ImdbDbConnection($"Socket={Env("IMDB_DRV_B_SOCK")};User=admin;Password=not-it-123");
        var e = T.Throws<ImdbAuthenticationException>(() => bad.Open(), "a wrong password");
        T.Check(e is DbException, "a DbException");
        T.Check(!e.Message.Contains("not-it-123", StringComparison.Ordinal), "no password in the message");
        T.Eq(ConnectionState.Closed, bad.State, "still closed");
        return Task.CompletedTask;
    }

    private static async Task TcpPinCa()
    {
        string b = $"Host=127.0.0.1;Port={Env("IMDB_DRV_B_PORT")};User=admin;Password={Pw}";
        await using (var c = new ImdbDbConnection(b + $";Pin={Env("IMDB_DRV_B_PIN")}"))
        {
            await c.OpenAsync();
            T.Eq(ChannelBindingType.ServerEndPoint, c.Native.ChannelBinding, "TCP: tls-server-end-point");
            T.Eq(1L, Scalar(c, "SELECT 1"), "pinned");
        }
        await using (var c = new ImdbDbConnection(b + $";CA File={Env("IMDB_DRV_B_CA")};Server Name=localhost"))
        {
            await c.OpenAsync();
            T.Eq(1L, Scalar(c, "SELECT 1"), "by the CA, the name localhost");
        }
        await using (var c = new ImdbDbConnection(b + $";CA File={Env("IMDB_DRV_B_CA")};Server Name=other.example"))
        {
            var e = await T.ThrowsAsync<ImdbAuthenticationException>(() => c.OpenAsync(), "a name outside the certificate");
            T.Eq(ImdbAuthFailure.Tls, e.Failure, "refused at TLS");
        }
        await using (var c = new ImdbDbConnection(b + $";Pin={Env("IMDB_DRV_OTHER_PIN")}"))
        {
            var e = await T.ThrowsAsync<ImdbAuthenticationException>(() => c.OpenAsync(), "another server's pin");
            T.Eq(ImdbAuthFailure.Tls, e.Failure, "refused at TLS");
        }
        await using (var c = new ImdbDbConnection(b + $";CA File={Env("IMDB_DRV_OTHER_CA")}"))
        {
            var e = await T.ThrowsAsync<ImdbAuthenticationException>(() => c.OpenAsync(), "another CA");
            T.Eq(ImdbAuthFailure.Tls, e.Failure, "refused at TLS");
        }
        // server A (the default --channel-binding exporter) refuses the end-point binding .NET can make: verdict 2
        await using (var c = new ImdbDbConnection($"Host=127.0.0.1;Port={Env("IMDB_DRV_A_PORT")};User=admin;Password={Pw};Pin={Env("IMDB_DRV_A_PIN")}"))
        {
            var e = await T.ThrowsAsync<ImdbAuthenticationException>(() => c.OpenAsync(), "a default server");
            T.Eq(ImdbAuthFailure.BindingRefused, e.Failure, "verdict 2: " + e.Message);
            T.Eq(ConnectionState.Closed, c.State, "closed");
        }
    }

    private static readonly ImdbDecimal W38Max = ImdbDecimal.Parse("99999999999999999999999999999999.999999");
    private static readonly DateTime MaxTs = DateTime.MaxValue.AddTicks(-9);
    private static readonly DateTimeOffset MaxTz = new(DateTime.MaxValue.AddTicks(-9), TimeSpan.Zero);
    private static readonly TimeSpan MaxTime = TimeSpan.FromDays(1) - TimeSpan.FromTicks(10);

    private static Task TypesReader()
    {
        using var c = OpenSock();
        NonQuery(c, "CREATE TYPE ado_mood AS ENUM ('sad', 'ok', 'happy', 'é')");
        NonQuery(c, "CREATE TABLE ado_ty (id INT64 PRIMARY KEY, i64 INT64, s SMALLINT, n INTEGER, d DECIMAL(10,2), w DECIMAL(38,6), f FLOAT64, " +
                    "b BOOL, t TEXT, v VARCHAR(5), ts TIMESTAMP, tz TIMESTAMPTZ, dt DATE, tm TIME, u UUID, bb BYTEA, iv INTERVAL, m ado_mood)");
        const string ins = "INSERT INTO ado_ty VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18)";
        var dbt = new DbType?[] { DbType.Int64, DbType.Int64, DbType.Int16, DbType.Int32, DbType.Decimal, DbType.Decimal, DbType.Double, DbType.Boolean,
                                  DbType.String, DbType.String, DbType.DateTime2, DbType.DateTimeOffset, DbType.Date, DbType.Time, DbType.Guid,
                                  DbType.Binary, null, null };
        var it = new ImdbType?[] { null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, ImdbType.Interval, ImdbType.Enum };
        var big = new string('é', 32767) + "a"; // 65,535 bytes: TEXT's bound
        object?[] r1 =
        {
            1L, long.MaxValue, (short)32767, int.MinValue, 99999999.99m, W38Max, double.MaxValue, true, "hé|x\U0001F600", "abcd\U0001F600",
            MaxTs, MaxTz, DateOnly.MaxValue, MaxTime, Guid.Parse("ffffffff-ffff-ffff-ffff-ffffffffffff"), new byte[] { 0, 255, 0 },
            new ImdbInterval(int.MaxValue, int.MinValue, long.MaxValue), "é",
        };
        object?[] r3 = // no declared types: each value's own (a TimeSpan an INTERVAL; the label a TEXT the engine binds into the ENUM)
        {
            3L, long.MinValue, (short)-32768, int.MaxValue, -99999999.99m, ImdbDecimal.Parse("-" + W38Max), -2.5e300, false, big, "",
            DateTime.MinValue, DateTimeOffset.MinValue, DateOnly.MinValue, TimeOnly.MinValue, Guid.Empty, Array.Empty<byte>(), TimeSpan.FromTicks(-10), "sad",
        };
        using (var cmd = c.CreateCommand())
        {
            cmd.CommandText = ins;
            for (int k = 0; k < 18; k++) cmd.Parameters.Add(new ImdbDbParameter { Value = r1[k] });
            for (int k = 0; k < 18; k++)
            {
                if (dbt[k] is { } d) cmd.Parameters[k].DbType = d;
                cmd.Parameters[k].ImdbType = it[k];
            }
            T.Eq(1, cmd.ExecuteNonQuery(), "row 1: one row");
            // row 2: every value a NULL of its declared type
            cmd.Parameters[0].Value = 2L;
            for (int k = 1; k < 18; k++) cmd.Parameters[k].Value = k % 2 == 0 ? null : DBNull.Value;
            T.Eq(1, cmd.ExecuteNonQuery(), "row 2: NULLs");
        }
        using (var cmd = Cmd(c, ins, r3)) T.Eq(1, cmd.ExecuteNonQuery(), "row 3: undeclared");
        using (var cmd = Cmd(c, "SELECT * FROM ado_ty ORDER BY id"))
        using (var r = cmd.ExecuteReader())
        {
            var types = new[] { typeof(long), typeof(long), typeof(long), typeof(long), typeof(decimal), typeof(decimal), typeof(double), typeof(bool),
                                typeof(string), typeof(string), typeof(DateTime), typeof(DateTimeOffset), typeof(DateOnly), typeof(TimeOnly), typeof(Guid),
                                typeof(byte[]), typeof(ImdbInterval), typeof(string) };
            T.Eq(18, r.FieldCount, "18 columns");
            T.Check(r.HasRows, "rows");
            for (int k = 0; k < 18; k++) T.Eq(types[k], r.GetFieldType(k), "GetFieldType " + r.GetName(k));
            T.Eq("INT64,INT64,INT64,INT64,DECIMAL(*,2),DECIMAL(*,6),FLOAT64,BOOL,TEXT,TEXT,TIMESTAMP,TIMESTAMPTZ,DATE,TIME,UUID,BYTEA,INTERVAL,ENUM",
                 string.Join(",", Enumerable.Range(0, 18).Select(r.GetDataTypeName)), "GetDataTypeName (COLUMNS as imagedb-server sends it: §4 DEFECTS D9)");
            T.Eq(5, r.GetOrdinal("W"), "GetOrdinal ignoring case after an exact miss");
            // row 1
            T.Check(r.Read(), "row 1");
            T.Eq(1L, r.GetInt64(0), "id");
            T.Eq(long.MaxValue, r.GetInt64(1), "INT64 max");
            T.Eq((short)32767, r.GetInt16(2), "SMALLINT max");
            T.Eq(int.MinValue, r.GetInt32(3), "INTEGER min");
            T.Throws<OverflowException>(() => r.GetInt32(1), "INT64 max into an int: checked");
            T.Eq(99999999.99m, r.GetDecimal(4), "DECIMAL(10,2)");
            T.Eq(99999999.99m, r.GetValue(4), "GetValue: a decimal");
            T.Throws<OverflowException>(() => r.GetDecimal(5), "38 digits into System.Decimal: refused, never rounded");
            T.Throws<OverflowException>(() => r.GetValue(5), "GetValue alike");
            T.Eq(W38Max, r.GetFieldValue<ImdbDecimal>(5), "GetFieldValue<ImdbDecimal>: exact");
            T.Eq(W38Max.ToString(), r.GetFieldValue<SqlDecimal>(5).ToString(), "GetFieldValue<SqlDecimal>: exact");
            T.Eq(W38Max.ToString(), r.GetString(5), "GetString: the exact text");
            T.Check(r.GetProviderSpecificValue(5) is ImdbValue pv && pv.AsDecimal().Equals(W38Max), "GetProviderSpecificValue");
            T.Eq(BitConverter.DoubleToInt64Bits(double.MaxValue), BitConverter.DoubleToInt64Bits(r.GetDouble(6)), "FLOAT64 bit for bit");
            T.Check(r.GetBoolean(7), "BOOL");
            T.Eq("hé|x\U0001F600", r.GetString(8), "TEXT");
            T.Eq("abcd\U0001F600", r.GetString(9), "VARCHAR(5): five characters, one outside the BMP");
            T.Eq(6L, r.GetChars(9, 0, null, 0, 0), "GetChars: the UTF-16 length");
            var chars = new char[2];
            T.Eq(2L, r.GetChars(9, 4, chars, 0, 2), "GetChars from 4");
            T.Eq("\U0001F600", new string(chars), "the surrogate pair");
            T.Eq(MaxTs, r.GetDateTime(10), "TIMESTAMP max");
            T.Eq(DateTimeKind.Unspecified, r.GetDateTime(10).Kind, "TIMESTAMP: Kind Unspecified");
            T.Eq(MaxTz, r.GetFieldValue<DateTimeOffset>(11), "TIMESTAMPTZ max");
            T.Eq(MaxTz.UtcDateTime, r.GetDateTime(11), "TIMESTAMPTZ as its UTC DateTime");
            T.Eq(DateTimeKind.Utc, r.GetDateTime(11).Kind, "Kind Utc");
            T.Eq(DateOnly.MaxValue, r.GetFieldValue<DateOnly>(12), "DATE max");
            T.Eq(new DateTime(9999, 12, 31), r.GetDateTime(12), "DATE as its midnight");
            T.Eq(TimeOnly.FromTimeSpan(MaxTime), r.GetFieldValue<TimeOnly>(13), "TIME max (from a TimeSpan declared Time)");
            T.Eq(MaxTime, r.GetFieldValue<TimeSpan>(13), "TIME as a TimeSpan");
            T.Eq(Guid.Parse("ffffffff-ffff-ffff-ffff-ffffffffffff"), r.GetGuid(14), "UUID");
            T.Eq(3L, r.GetBytes(15, 0, null, 0, 0), "GetBytes: the length");
            var bytes = new byte[2];
            T.Eq(2L, r.GetBytes(15, 1, bytes, 0, 5), "GetBytes from 1");
            T.Bytes(new byte[] { 255, 0 }, bytes, "the bytes");
            T.Eq(new ImdbInterval(int.MaxValue, int.MinValue, long.MaxValue), r.GetFieldValue<ImdbInterval>(16), "INTERVAL's three fields at their ends");
            T.Throws<InvalidCastException>(() => r.GetFieldValue<TimeSpan>(16), "an INTERVAL of months into a TimeSpan: refused");
            T.Eq("é", r.GetString(17), "ENUM's label");
            for (int k = 0; k < 18; k++)
                if (k != 5) T.Eq(types[k], r.GetValue(k).GetType(), "GetValue's type is GetFieldType: " + r.GetName(k));
            // row 2: NULLs of every type
            T.Check(r.Read(), "row 2");
            for (int k = 1; k < 18; k++)
            {
                T.Check(r.IsDBNull(k), "NULL " + r.GetName(k));
                T.Eq(DBNull.Value, r.GetValue(k), "GetValue: DBNull " + r.GetName(k));
                T.Eq(r.GetColumn(k).Type, ((ImdbValue)r.GetProviderSpecificValue(k)).Type, "a NULL of its column's type " + r.GetName(k));
            }
            T.Check(r.GetFieldValue<long?>(1) == null, "GetFieldValue<long?>: null");
            T.Check(r.GetFieldValue<string>(8) == null, "GetFieldValue<string>: null");
            T.Throws<InvalidCastException>(() => r.GetInt64(1), "GetInt64 of a NULL");
            T.Throws<InvalidCastException>(() => r.GetFieldValue<long>(1), "GetFieldValue<long> of a NULL");
            // row 3: undeclared values
            T.Check(r.Read(), "row 3");
            T.Eq(long.MinValue, r.GetInt64(1), "INT64 min");
            T.Eq((short)-32768, r.GetInt16(2), "SMALLINT min");
            T.Eq(-99999999.99m, r.GetDecimal(4), "DECIMAL(10,2) min");
            T.Eq(ImdbDecimal.Parse("-" + W38Max), r.GetFieldValue<ImdbDecimal>(5), "DECIMAL(38,6) min");
            T.Eq(-2.5e300, r.GetDouble(6), "FLOAT64");
            T.Check(!r.GetBoolean(7), "false");
            T.Eq(big, r.GetString(8), "65,535 bytes of TEXT");
            T.Eq("", r.GetString(9), "an empty VARCHAR");
            T.Eq(DateTime.MinValue, r.GetDateTime(10), "TIMESTAMP min");
            T.Eq(DateTimeOffset.MinValue, r.GetFieldValue<DateTimeOffset>(11), "TIMESTAMPTZ min");
            T.Eq(DateOnly.MinValue, r.GetFieldValue<DateOnly>(12), "DATE min");
            T.Eq(TimeOnly.MinValue, r.GetFieldValue<TimeOnly>(13), "TIME min");
            T.Eq(Guid.Empty, r.GetGuid(14), "UUID zero");
            T.Eq(0L, r.GetBytes(15, 0, null, 0, 0), "an empty BYTEA");
            T.Eq(new ImdbInterval(0, 0, -1), r.GetFieldValue<ImdbInterval>(16), "a TimeSpan of -1 us as an INTERVAL");
            T.Eq(TimeSpan.FromTicks(-10), r.GetFieldValue<TimeSpan>(16), "and back as a TimeSpan");
            T.Eq("sad", r.GetString(17), "a TEXT label into the ENUM");
            T.Check(!r.Read(), "three rows");
            T.Check(!r.NextResult(), "one result");
        }
        // the engine refuses what its column does not take, and a non-NULL ENUM is never sent as one (§4)
        using (var cmd = Cmd(c, "INSERT INTO ado_ty (id, m) VALUES (9, $1)"))
        {
            cmd.Parameters.Add("nope", ImdbType.Enum);
            var e = T.Throws<ImdbServerException>(() => cmd.ExecuteNonQuery(), "a label the type lacks");
            T.Check(!e.Message.Contains("nope", StringComparison.Ordinal), "no value in the ERROR: " + e.Message);
        }
        using (var cmd = Cmd(c, "INSERT INTO ado_ty (id, v) VALUES (9, $1)", "abcdef"))
            T.Throws<ImdbServerException>(() => cmd.ExecuteNonQuery(), "six characters into VARCHAR(5)");
        T.Eq(ImdbTransactionState.Idle, c.Native.TransactionState, "idle");
        return Task.CompletedTask;
    }

    private static Task TypedNulls()
    {
        using var c = OpenSock();
        var cases = new (DbType? d, ImdbType? t, Type clr, ImdbType wire)[]
        {
            (DbType.Int32, null, typeof(long), ImdbType.Int64), (DbType.Decimal, null, typeof(decimal), ImdbType.Decimal),
            (DbType.Double, null, typeof(double), ImdbType.Float64), (DbType.Boolean, null, typeof(bool), ImdbType.Bool),
            (DbType.String, null, typeof(string), ImdbType.Text), (DbType.DateTime2, null, typeof(DateTime), ImdbType.Timestamp),
            (DbType.DateTimeOffset, null, typeof(DateTimeOffset), ImdbType.TimestampTz), (DbType.Date, null, typeof(DateOnly), ImdbType.Date),
            (DbType.Time, null, typeof(TimeOnly), ImdbType.Time), (DbType.Guid, null, typeof(Guid), ImdbType.Uuid),
            (DbType.Binary, null, typeof(byte[]), ImdbType.Bytea), (null, ImdbType.Interval, typeof(ImdbInterval), ImdbType.Interval),
        };
        foreach (var (d, t, clr, wire) in cases)
        {
            using var cmd = Cmd(c, "SELECT $1 AS x");
            var p = new ImdbDbParameter { Value = null, ImdbType = t };
            if (d is { } dd) p.DbType = dd;
            cmd.Parameters.Add(p);
            using var r = cmd.ExecuteReader();
            T.Check(r.Read() && r.IsDBNull(0), $"SELECT $1 of a NULL {wire}: one NULL");
            T.Eq(clr, r.GetFieldType(0), $"its column typed by the NULL's type ({wire})");
            T.Eq(wire, r.GetColumn(0).Type, "the wire's column type " + wire);
        }
        // a NULL of no type: the engine refuses it where a type is wanted (§4), takes it into a column
        using (var cmd = Cmd(c, "SELECT $1 AS x", new object?[] { null }))
        {
            var e = T.Throws<ImdbServerException>(() => cmd.ExecuteReader(), "SELECT $1 of a NULL of no type");
            T.Eq(4, e.Code, "ERROR 4: " + e.Message);
        }
        NonQuery(c, "CREATE TABLE ado_nul (id INT64 PRIMARY KEY, x DECIMAL(12,3))");
        T.Eq(1, NonQuery(c, "INSERT INTO ado_nul VALUES (1, $1)", new object?[] { null }), "a NULL of no type into a column");
        T.Check(Scalar(c, "SELECT x FROM ado_nul WHERE id = 1") is DBNull, "stored NULL");
        return Task.CompletedTask;
    }

    private static Task Decimal38()
    {
        using var c = OpenSock();
        NonQuery(c, "CREATE TABLE ado_dec (id INT64 PRIMARY KEY, z DECIMAL(38,0), p DECIMAL(38,29))");
        string[] zs = { "79228162514264337593543950335", "79228162514264337593543950336", new string('9', 38), "-" + new string('9', 38), "0" };
        string[] ps = { "1.00000000000000000000000000001", "1.50000000000000000000000000000", "-0.00000000000000000000000000001", "123456789.12345678901234567890123456789", "0.00000000000000000000000000000" };
        for (int i = 0; i < zs.Length; i++)
        {
            using var cmd = c.CreateCommand();
            cmd.CommandText = "INSERT INTO ado_dec VALUES ($1, $2, $3)";
            cmd.Parameters.AddWithValue((long)i);
            // two exact carriers of 38 digits: ImdbDecimal and the BCL's SqlDecimal
            cmd.Parameters.AddWithValue(i % 2 == 0 ? (object)ImdbDecimal.Parse(zs[i]) : SqlDecimal.Parse(zs[i]));
            cmd.Parameters.Add(i % 2 == 0 ? (object)SqlDecimal.Parse(ps[i]) : ImdbDecimal.Parse(ps[i]), DbType.Decimal);
            T.Eq(1, cmd.ExecuteNonQuery(), "row " + i);
        }
        using (var cmd = Cmd(c, "SELECT id, z, p FROM ado_dec ORDER BY id"))
        using (var r = cmd.ExecuteReader())
        {
            for (int i = 0; i < zs.Length; i++)
            {
                T.Check(r.Read(), "row " + i);
                T.Eq(zs[i], r.GetFieldValue<ImdbDecimal>(1).ToString(), "z exact (ImdbDecimal) " + zs[i]);
                T.Eq(zs[i], r.GetFieldValue<SqlDecimal>(1).ToString(), "z exact (SqlDecimal) " + zs[i]);
                T.Eq(BigInteger.Parse(zs[i], CultureInfo.InvariantCulture), r.GetFieldValue<BigInteger>(1), "z as a BigInteger");
                T.Eq(ImdbDecimal.Parse(ps[i]), r.GetFieldValue<ImdbDecimal>(2), "p exact " + ps[i]);
                T.Eq(ImdbDecimal.Parse(ps[i]).ToString(), r.GetString(2), "p's text");
            }
        }
        using (var cmd = Cmd(c, "SELECT z, p FROM ado_dec ORDER BY id"))
        using (var r = cmd.ExecuteReader())
        {
            r.Read(); // 2^96 - 1, 1.00..01 (29 places)
            T.Eq(decimal.MaxValue, r.GetDecimal(0), "2^96 - 1 is decimal.MaxValue");
            T.Throws<OverflowException>(() => r.GetDecimal(1), "29 places, the last not 0: refused");
            r.Read(); // 2^96, 1.5 at scale 29
            T.Throws<OverflowException>(() => r.GetDecimal(0), "2^96: refused");
            T.Throws<OverflowException>(() => r.GetValue(0), "GetValue: refused");
            T.Eq(1.5m, r.GetDecimal(1), "1.5 at scale 29: exact (trailing zeros dropped)");
            r.Read(); // 38 nines, -1e-29
            T.Throws<OverflowException>(() => r.GetDecimal(0), "38 digits");
            T.Throws<OverflowException>(() => r.GetDecimal(1), "-1e-29");
        }
        // System.Decimal's own range both ways; a SUM over INT64 is a DECIMAL (§4), read as an integer too
        NonQuery(c, "CREATE TABLE ado_dec2 (id INT64 PRIMARY KEY, m DECIMAL(38,10), x INT64)");
        NonQuery(c, "INSERT INTO ado_dec2 VALUES (1, $1, $2), (2, $3, $4)", 7922816251426433759354395033.5m, long.MaxValue, -0.0000000001m, long.MaxValue);
        T.Eq(7922816251426433759354395033.5m, Scalar(c, "SELECT m FROM ado_dec2 WHERE id = 1"), "a System.Decimal of 29 digits back");
        T.Eq(-0.0000000001m, Scalar(c, "SELECT m FROM ado_dec2 WHERE id = 2"), "scale 10 back");
        using (var cmd = Cmd(c, "SELECT SUM(x) AS s FROM ado_dec2"))
        using (var r = cmd.ExecuteReader())
        {
            T.Eq(typeof(decimal), r.GetFieldType(0), "SUM(INT64) is a DECIMAL");
            r.Read();
            T.Eq(18446744073709551614m, r.GetDecimal(0), "2 x INT64 max, exactly");
            T.Throws<OverflowException>(() => r.GetInt64(0), "past INT64");
        }
        using (var cmd = Cmd(c, "SELECT SUM(id) AS s FROM ado_dec2"))
        using (var r = cmd.ExecuteReader())
        {
            r.Read();
            T.Eq(3L, r.GetInt64(0), "a SUM within INT64 read by GetInt64");
        }
        return Task.CompletedTask;
    }

    private static Task NonQueryCounts()
    {
        using var c = OpenSock();
        string Status(string sql, params object?[] v)
        {
            using var cmd = Cmd(c, sql, v);
            using var r = cmd.ExecuteReader();
            return $"{r.Result.Status}|count {r.Result.Count}|affected {r.RecordsAffected}|rows {(r.FieldCount > 0 ? r.Result.Rows.Count : -1)}";
        }
        var seen = new List<string>
        {
            "CREATE TABLE: " + Status("CREATE TABLE ado_cnt (id INT64 PRIMARY KEY, x INT64)"),
            "INSERT 3: " + Status("INSERT INTO ado_cnt VALUES (1, 10), (2, 20), (3, 30)"),
            "INSERT RETURNING: " + Status("INSERT INTO ado_cnt VALUES (4, 40) RETURNING id, x"),
            "UPDATE 2: " + Status("UPDATE ado_cnt SET x = x + 1 WHERE id <= 2"),
            "DELETE 1: " + Status("DELETE FROM ado_cnt WHERE id = 3"),
            "SELECT: " + Status("SELECT * FROM ado_cnt"),
            "BEGIN: " + Status("BEGIN"),
            "INSERT in a transaction: " + Status("INSERT INTO ado_cnt VALUES (5, 50)"),
            "COMMIT: " + Status("COMMIT"),
        };
        foreach (var s in seen) Console.WriteLine("     DONE " + s);
        T.Eq(-1, NonQuery(c, "CREATE TABLE ado_cnt2 (id INT64 PRIMARY KEY, x INT64)"), "ExecuteNonQuery: a DDL is -1");
        T.Eq(3, NonQuery(c, "INSERT INTO ado_cnt2 VALUES (1, 0), (2, 0), (3, 0)"), "INSERT of 3");
        T.Eq(2, NonQuery(c, "UPDATE ado_cnt2 SET x = 1 WHERE id >= 2"), "UPDATE of 2");
        T.Eq(1, NonQuery(c, "DELETE FROM ado_cnt2 WHERE id = 1"), "DELETE of 1");
        T.Eq(0, NonQuery(c, "DELETE FROM ado_cnt2 WHERE id = 1"), "DELETE of none");
        T.Eq(-1, NonQuery(c, "SELECT * FROM ado_cnt2"), "a SELECT is -1");
        using (var cmd = Cmd(c, "INSERT INTO ado_cnt2 VALUES (7, 0), (8, 0) RETURNING id"))
        using (var r = cmd.ExecuteReader())
        {
            T.Eq(2, r.RecordsAffected, "INSERT ... RETURNING: its rows written");
            T.Check(r.Read() && r.GetInt64(0) == 7 && r.Read() && r.GetInt64(0) == 8 && !r.Read(), "and its rows");
        }
        // one text holding two statements: what the engine does with it (printed; the driver splits nothing)
        try
        {
            using var cmd = Cmd(c, "SELECT 1; SELECT 2");
            using var r = cmd.ExecuteReader();
            Console.WriteLine($"     one text of two statements: answered, {r.FieldCount} column(s), status \"{r.Result.Status}\"");
        }
        catch (ImdbServerException e)
        {
            Console.WriteLine($"     one text of two statements: ERROR {e.Code}: {e.ServerMessage}");
        }
        T.Eq(1L, Scalar(c, "SELECT 1"), "usable");
        return Task.CompletedTask;
    }

    private static async Task Transactions()
    {
        await using var c = new ImdbDbConnection(SockCs);
        await c.OpenAsync();
        NonQuery(c, "CREATE TABLE ado_tx (id INT64 PRIMARY KEY)");
        using (var t = c.BeginTransaction(IsolationLevel.Serializable))
        {
            T.Eq(ImdbTransactionState.InTransaction, c.Native.TransactionState, "BEGIN ... SERIALIZABLE: in a transaction");
            T.Eq(IsolationLevel.Serializable, t.IsolationLevel, "its level");
            T.Throws<InvalidOperationException>(() => c.BeginTransaction(), "one at a time");
            NonQuery(c, "INSERT INTO ado_tx VALUES (1)");
            t.Rollback();
            T.Check(((ImdbDbTransaction)t).IsCompleted, "completed");
            T.Throws<InvalidOperationException>(() => t.Commit(), "a commit after the rollback");
        }
        T.Eq(ImdbTransactionState.Idle, c.Native.TransactionState, "idle after ROLLBACK");
        T.Eq(0L, Scalar(c, "SELECT COUNT(*) FROM ado_tx"), "rolled back");
        await using (var t = await c.BeginTransactionAsync(IsolationLevel.Snapshot))
        {
            NonQuery(c, "INSERT INTO ado_tx VALUES (2)");
            // a failed statement is undone alone: the transaction goes on
            var e = T.Throws<ImdbServerException>(() => NonQuery(c, "INSERT INTO ado_tx VALUES (2)"), "a duplicate key");
            T.Eq(ImdbTransactionState.InTransaction, c.Native.TransactionState, "still in the transaction after ERROR " + e.Code);
            await t.CommitAsync();
        }
        T.Eq(1L, Scalar(c, "SELECT COUNT(*) FROM ado_tx"), "committed, the duplicate alone undone");
        using (var t = c.BeginTransaction(IsolationLevel.ReadCommitted))
            NonQuery(c, "INSERT INTO ado_tx VALUES (3)"); // disposed without a commit
        T.Eq(ImdbTransactionState.Idle, c.Native.TransactionState, "the dispose rolled back");
        T.Eq(1L, Scalar(c, "SELECT COUNT(*) FROM ado_tx"), "row 3 not there");
        foreach (var lvl in new[] { IsolationLevel.Unspecified, IsolationLevel.ReadUncommitted, IsolationLevel.RepeatableRead })
        {
            using var t = c.BeginTransaction(lvl);
            T.Eq(ImdbTransactionState.InTransaction, c.Native.TransactionState, "BEGIN for " + lvl);
            t.Commit();
        }
        T.Throws<ArgumentException>(() => c.BeginTransaction(IsolationLevel.Chaos), "Chaos refused");
        // a transaction left open when the connection closes: the server rolls it back
        var t2 = c.BeginTransaction();
        NonQuery(c, "INSERT INTO ado_tx VALUES (4)");
        await c.CloseAsync();
        T.Check(((ImdbDbTransaction)t2).IsCompleted, "ended with its connection");
        await c.OpenAsync();
        T.Eq(1L, Scalar(c, "SELECT COUNT(*) FROM ado_tx"), "row 4 rolled back by the close");
    }

    private static Task Prepare()
    {
        using var c = OpenSock();
        NonQuery(c, "CREATE TABLE ado_prep (id INT64 PRIMARY KEY, s TEXT, d DECIMAL(20,4))");
        string first;
        using (var cmd = c.CreateCommand())
        {
            cmd.CommandText = "INSERT INTO ado_prep VALUES ($1, $2, $3)";
            var pid = cmd.Parameters.Add(null, DbType.Int64);
            var ps = cmd.Parameters.Add(null, DbType.String);
            var pd = cmd.Parameters.Add(null, DbType.Decimal);
            cmd.Prepare();
            T.Check(cmd.PreparedName != null, "prepared");
            first = cmd.PreparedName!;
            for (int i = 1; i <= 3; i++)
            {
                pid.Value = (long)i;
                ps.Value = i == 2 ? null : "s" + i;
                pd.Value = i * 1.5m;
                T.Eq(1, cmd.ExecuteNonQuery(), "EXECUTE " + i);
            }
            T.Eq(first, cmd.PreparedName, "one PREPARE for the three");
            cmd.CommandText = "INSERT INTO ado_prep VALUES ($1, $2, $3 + 1)";
            pid.Value = 4L;
            T.Eq(1, cmd.ExecuteNonQuery(), "the text changed: prepared again");
            T.Check(cmd.PreparedName != null && cmd.PreparedName != first, "under a new name");
            var e = T.Throws<ImdbServerException>(() => c.Native.ExecuteAsync(first, new object?[] { 9L, "x", 1m }).GetAwaiter().GetResult(),
                                                  "the old name was deallocated");
            T.Check(e.Code > 0, "ERROR " + e.Code + ": " + e.ServerMessage);
            first = cmd.PreparedName!;
        }
        T.Throws<ImdbServerException>(() => c.Native.ExecuteAsync(first, new object?[] { 9L, "x", 1m }).GetAwaiter().GetResult(), "Dispose deallocated");
        using (var cmd = Cmd(c, "SELECT id, s, d FROM ado_prep WHERE id >= $1 ORDER BY id", 2L))
        {
            cmd.Prepare();
            using var r = cmd.ExecuteReader();
            T.Check(r.Read() && r.GetInt64(0) == 2 && r.IsDBNull(1) && r.GetDecimal(2) == 3.0m, "row 2 (a NULL TEXT)");
            T.Check(r.Read() && r.GetString(1) == "s3" && r.GetDecimal(2) == 4.5m, "row 3");
            T.Check(r.Read() && r.GetDecimal(2) == 5.5m && !r.Read(), "row 4, its $3 + 1 (4.5 + 1)");
        }
        return Task.CompletedTask;
    }

    private const string LongJoin = "SELECT COUNT(*) FROM big_sock AS a, big_sock AS b WHERE a.x < b.x";

    private static async Task Cancel()
    {
        using var c = OpenSock();
        T.Eq(1000000L, Scalar(c, "SELECT COUNT(*) FROM big_sock"), "copy_in_1m_rows[sock]'s table is there");
        // DbCommand.Cancel() from another thread, the command blocking in ExecuteScalar on its own
        using (var cmd = Cmd(c, LongJoin))
        {
            cmd.CommandTimeout = 0;
            var sw = Stopwatch.StartNew();
            var run = Task.Run(() => cmd.ExecuteScalar());
            await Task.Delay(300);
            T.Check(!run.IsCompleted, "the join runs after 300 ms");
            var th = new Thread(() => cmd.Cancel());
            th.Start();
            th.Join();
            var e = await T.ThrowsAsync<ImdbServerException>(() => run, "Cancel()");
            T.Eq(15, e.Code, "ERROR 15: " + e.ServerMessage);
            T.Check(sw.ElapsedMilliseconds < 20000, $"promptly ({sw.ElapsedMilliseconds} ms)");
        }
        T.Eq(1L, Scalar(c, "SELECT 1"), "usable after Cancel()");
        // the async path's token
        using (var cmd = Cmd(c, LongJoin))
        {
            cmd.CommandTimeout = 0;
            using var cts = new CancellationTokenSource(300);
            var oce = await T.ThrowsAsync<OperationCanceledException>(() => cmd.ExecuteScalarAsync(cts.Token), "a token");
            T.Check(oce.InnerException is ImdbServerException { Code: 15 }, "its ERROR 15 inside");
        }
        T.Eq(1L, Scalar(c, "SELECT 1"), "usable after the token");
        // CommandTimeout: in band too, the connection kept
        using (var cmd = Cmd(c, LongJoin))
        {
            cmd.CommandTimeout = 1;
            var sw = Stopwatch.StartNew();
            var e = T.Throws<ImdbException>(() => cmd.ExecuteScalar(), "CommandTimeout 1 s");
            T.Eq(15, e.Code, "code 15");
            T.Check(e.InnerException is TimeoutException, "a TimeoutException inside: " + e.InnerException?.GetType().Name);
            T.Check(e is not ImdbServerException, "the driver's own, not the server's");
            T.Check(sw.ElapsedMilliseconds >= 900 && sw.ElapsedMilliseconds < 20000, $"after about a second ({sw.ElapsedMilliseconds} ms)");
        }
        T.Eq(1L, Scalar(c, "SELECT 1"), "usable after the timeout");
        // Cancel() of a command not running: nothing, and nothing later
        using (var cmd = Cmd(c, "SELECT COUNT(*) FROM big_sock WHERE x < 1000"))
        {
            cmd.Cancel();
            await Task.Delay(100);
            T.Eq(1000L, cmd.ExecuteScalar(), "the next run is not cancelled");
        }
    }

    private static Task Batch()
    {
        using var c = OpenSock();
        NonQuery(c, "CREATE TABLE ado_batch (id INT64 PRIMARY KEY, s TEXT)");
        using (var b = c.CreateBatch())
        {
            b.BatchCommands.Add("INSERT INTO ado_batch VALUES ($1, $2)", 1L, "a");
            b.BatchCommands.Add("INSERT INTO ado_batch VALUES ($1, $2), ($3, $4)", 2L, "b", 3L, null);
            b.BatchCommands.Add("SELECT id, s FROM ado_batch WHERE id >= $1 ORDER BY id", 2L);
            b.BatchCommands.Add("SELECT COUNT(*) FROM ado_batch");
            using var r = b.ExecuteReader();
            T.Eq(0, r.FieldCount, "the first result: an INSERT (no columns)");
            T.Check(r.NextResult() && r.FieldCount == 0, "the second INSERT");
            T.Check(r.NextResult() && r.Read() && r.GetInt64(0) == 2 && r.Read() && r.IsDBNull(1) && !r.Read(), "the SELECT's rows");
            T.Check(r.NextResult() && r.Read() && r.GetInt64(0) == 3, "the COUNT");
            T.Check(!r.NextResult(), "four results");
            T.Eq(3, r.RecordsAffected, "the writes' rows");
            T.Eq("1,2,-1,-1", string.Join(",", b.BatchCommands.List.Select(x => x.RecordsAffected)), "each command's RecordsAffected");
        }
        // an ERROR mid-batch: those before it stand, those after it do not run; NextResult throws it with its command
        using (var b = c.CreateBatch())
        {
            b.BatchCommands.Add("INSERT INTO ado_batch VALUES ($1, 'x')", 10L);
            var bad = b.BatchCommands.Add("INSERT INTO ado_batch VALUES ($1, 'y')", 1L); // a duplicate key
            b.BatchCommands.Add("INSERT INTO ado_batch VALUES ($1, 'z')", 11L);
            using var r = b.ExecuteReader();
            T.Eq(1, r.RecordsAffected, "the first ran");
            var e = T.Throws<ImdbServerException>(() => r.NextResult(), "NextResult reaches the failed statement");
            T.Eq(1u, e.Index, "its index");
            T.Check(ReferenceEquals(bad, e.BatchCommand), "DbException.BatchCommand names it");
            T.Eq(1, e.CompletedResults.Count, "one completed");
        }
        T.Eq(1L, Scalar(c, "SELECT COUNT(*) FROM ado_batch WHERE id = 10"), "the statement before the ERROR stands");
        T.Eq(0L, Scalar(c, "SELECT COUNT(*) FROM ado_batch WHERE id = 11"), "the one after it did not run");
        using (var b = c.CreateBatch())
        {
            b.BatchCommands.Add("INSERT INTO ado_batch VALUES ($1, 'x')", 1L); // fails first
            b.BatchCommands.Add("INSERT INTO ado_batch VALUES ($1, 'z')", 12L);
            var e = T.Throws<ImdbServerException>(() => b.ExecuteReader(), "the first fails: ExecuteReader throws");
            T.Eq(0u, e.Index, "index 0");
            T.Throws<ImdbServerException>(() => b.ExecuteNonQuery(), "ExecuteNonQuery throws it too");
        }
        // a batch in a transaction: an ERROR ends the batch, its COMMIT unrun, the transaction still open (§4)
        using (var b = c.CreateBatch())
        {
            b.BatchCommands.Add("BEGIN");
            b.BatchCommands.Add("INSERT INTO ado_batch VALUES (20, 'q')");
            b.BatchCommands.Add("INSERT INTO ado_batch VALUES (20, 'q')");
            b.BatchCommands.Add("COMMIT");
            T.Throws<ImdbServerException>(() => b.ExecuteNonQuery(), "the duplicate");
            T.Eq(ImdbTransactionState.InTransaction, c.Native.TransactionState, "COMMIT never ran");
            NonQuery(c, "ROLLBACK");
        }
        T.Eq(0L, Scalar(c, "SELECT COUNT(*) FROM ado_batch WHERE id = 20"), "rolled back");
        return Task.CompletedTask;
    }

    private static Task Factory()
    {
        DbProviderFactories.RegisterFactory("Imagedb.Client", ImdbDbFactory.Instance);
        var f = DbProviderFactories.GetFactory("Imagedb.Client");
        T.Check(ReferenceEquals(ImdbDbFactory.Instance, f), "the registered factory");
        using DbConnection c = f.CreateConnection()!;
        var csb = f.CreateConnectionStringBuilder()!;
        csb["Socket"] = Env("IMDB_DRV_B_SOCK");
        csb["User"] = "admin";
        csb["Password"] = Pw;
        c.ConnectionString = csb.ConnectionString;
        c.Open();
        // generic System.Data.Common code alone
        using (DbCommand cmd = c.CreateCommand())
        {
            cmd.CommandText = "CREATE TABLE ado_gen (id INT64 PRIMARY KEY, name TEXT, at TIMESTAMPTZ, amount DECIMAL(12,2))";
            T.Eq(-1, cmd.ExecuteNonQuery(), "CREATE");
        }
        using (DbCommand cmd = c.CreateCommand())
        {
            cmd.CommandText = "INSERT INTO ado_gen VALUES ($1, $2, $3, $4)";
            foreach (var (t, v) in new (DbType, object?)[] { (DbType.Int64, 1L), (DbType.String, "one"),
                                                              (DbType.DateTimeOffset, new DateTimeOffset(2026, 11, 22, 21, 0, 0, TimeSpan.FromHours(1))),
                                                              (DbType.Decimal, 12.5m) })
            {
                var p = cmd.CreateParameter();
                p.DbType = t;
                p.Value = v;
                cmd.Parameters.Add(p);
            }
            T.Eq(1, cmd.ExecuteNonQuery(), "INSERT through DbParameters");
            cmd.Parameters[0].Value = 2L;
            cmd.Parameters[1].Value = DBNull.Value;
            cmd.Parameters[3].Value = DBNull.Value;
            T.Eq(1, cmd.ExecuteNonQuery(), "again with NULLs");
        }
        using (DbCommand cmd = c.CreateCommand())
        {
            cmd.CommandText = "SELECT id, name, at, amount FROM ado_gen ORDER BY id";
            using DbDataReader r = cmd.ExecuteReader();
            var dt = new DataTable { Locale = CultureInfo.InvariantCulture };
            dt.Load(r); // reads GetSchemaTable, then the rows
            T.Eq(2, dt.Rows.Count, "DataTable.Load: two rows");
            T.Eq("id,name,at,amount", string.Join(",", dt.Columns.Cast<DataColumn>().Select(x => x.ColumnName)), "its columns");
            T.Eq(typeof(long), dt.Columns["id"]!.DataType, "id long");
            T.Eq(typeof(DateTimeOffset), dt.Columns["at"]!.DataType, "at DateTimeOffset");
            T.Eq(typeof(decimal), dt.Columns["amount"]!.DataType, "amount decimal");
            T.Eq(new DateTimeOffset(2026, 11, 22, 20, 0, 0, TimeSpan.Zero), dt.Rows[0]["at"], "the instant");
            T.Eq(12.5m, dt.Rows[0]["amount"], "the amount");
            T.Check(dt.Rows[1]["name"] is DBNull && dt.Rows[1]["amount"] is DBNull, "the NULLs");
        }
        using (DbCommand cmd = c.CreateCommand())
        {
            cmd.CommandText = "SELECT id, amount FROM ado_gen ORDER BY id";
            using var r = cmd.ExecuteReader();
            var schema = ((IDbColumnSchemaGenerator)r).GetColumnSchema();
            T.Eq(38, schema[1].NumericPrecision ?? 0, "a DECIMAL's precision: not sent (0), reported as 38 (§4)");
            T.Eq(2, schema[1].NumericScale ?? -1, "its scale");
            int n = 0;
            foreach (IDataRecord rec in r) n += rec.GetInt64(0) > 0 ? 1 : 0; // DbEnumerator
            T.Eq(2, n, "enumerated");
        }
        T.Check(f.CanCreateBatch && f.CreateBatch() is ImdbDbBatch, "the factory's batch");
        // .NET 7's DbDataSource: a command that opens its own connection
        using (DbDataSource ds = f.CreateDataSource(csb.ConnectionString))
        {
            using (DbCommand cmd = ds.CreateCommand("SELECT COUNT(*) FROM ado_gen"))
                T.Eq(2L, cmd.ExecuteScalar(), "the data source's command");
            using var dc = ((ImdbDbDataSource)ds).OpenConnection();
            T.Eq(ConnectionState.Open, dc.State, "the data source's connection");
        }
        T.Throws<ArgumentException>(() => new ImdbDbDataSource("Host=h;Port=1;User=a;Password=b"), "a data source with no verification");
        return Task.CompletedTask;
    }

    private static async Task NativeLevel()
    {
        await using var c = new ImdbDbConnection(SockCs);
        await c.OpenAsync();
        var n = c.Native;
        T.Check(await n.PingAsync() >= TimeSpan.Zero, "PING through the ADO.NET connection");
        T.Check((await n.SessionsAsync()).Count >= 1, "SESSIONS");
        NonQuery(c, "CREATE TABLE ado_copy (id INT64 PRIMARY KEY, s TEXT)");
        var csv = Encoding.UTF8.GetBytes("1,a\n2,\"b,c\"\n3,\n");
        var res = await n.CopyInAsync("COPY ado_copy FROM STDIN", new MemoryStream(csv));
        T.Eq(3UL, res.Count, "COPY FROM STDIN: three rows");
        T.Eq(3L, Scalar(c, "SELECT COUNT(*) FROM ado_copy"), "seen by an ADO.NET command");
        var outp = new MemoryStream();
        await n.CopyOutAsync("COPY ado_copy TO STDOUT", outp);
        T.Check(outp.Length > 0, "COPY TO STDOUT: " + outp.Length + " bytes");
        var batch = await n.ExecuteBatchAsync("ado_none_such", new[] { (IReadOnlyList<object?>)new object?[] { 1L } });
        T.Check(batch.Error != null && batch.Results.Count == 0, "EXECUTE of an unknown name: its ERROR in the batch's result");
        T.Eq(1L, Scalar(c, "SELECT 1"), "usable");
    }
}
