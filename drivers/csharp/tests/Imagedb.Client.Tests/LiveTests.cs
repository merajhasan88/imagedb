using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net.Security;
using System.Net.Sockets;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Authentication;
using System.Security.Authentication.ExtendedProtection;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Imagedb.Client.Wire;

namespace Imagedb.Client.Tests;

/// <summary>Against the frozen imagedb-server binaries run_tests.sh starts: server A (the default, --channel-binding
/// exporter) and server B (--channel-binding any), each on its own socket and TCP port, each with its own certificate;
/// a third certificate directory (never served) for "another CA". Logins are a superuser's (superuser-only until N1e's
/// slice 2c).</summary>
public static class LiveTests
{
    private static string Env(string k) => Environment.GetEnvironmentVariable(k) ?? throw new CheckFailed($"{k} is not set (run_tests.sh sets it)");

    private static string Password => Env("IMDB_DRV_PASSWORD");
    private const string User = "admin";

    private sealed record Server(string Name, string Sock, int Port, string Pin, string Ca, string Sdir);

    private static Server A => new("A", Env("IMDB_DRV_A_SOCK"), int.Parse(Env("IMDB_DRV_A_PORT")), Env("IMDB_DRV_A_PIN"), Env("IMDB_DRV_A_CA"), Env("IMDB_DRV_A_SDIR"));
    private static Server B => new("B", Env("IMDB_DRV_B_SOCK"), int.Parse(Env("IMDB_DRV_B_PORT")), Env("IMDB_DRV_B_PIN"), Env("IMDB_DRV_B_CA"), Env("IMDB_DRV_B_SDIR"));

    private static ImdbConnectOptions Sock(Server s, string? user = null, string? pw = null) =>
        new() { SocketPath = s.Sock, User = user ?? User, Password = pw ?? Password, ReplyTimeout = TimeSpan.FromSeconds(120) };

    private static ImdbConnectOptions Tcp(Server s, ImdbTls tls, string host = "127.0.0.1", string? pw = null) =>
        new() { Host = host, Port = s.Port, Tls = tls, User = User, Password = pw ?? Password, ReplyTimeout = TimeSpan.FromSeconds(120) };

    /// <summary>A connection to server B over the transport named: "sock" or "tcp" (pinned).</summary>
    private static Task<ImdbConnection> Open(string via) =>
        ImdbConnection.ConnectAsync(via == "sock" ? Sock(B) : Tcp(B, ImdbTls.FromPin(B.Pin)));

    public static IEnumerable<TestCase> All()
    {
        yield return new("live", "login_socket_both_servers", LoginSocket);
        yield return new("live", "login_refused_alike", LoginRefused);
        yield return new("live", "tcp_pin_endpoint_binding", TcpPin);
        yield return new("live", "tcp_endpoint_value_is_the_stdlib_rfc5929", EndpointIsStdlib);
        yield return new("live", "tcp_ca_by_address_and_name", TcpCa);
        yield return new("live", "tcp_ca_name_outside_san_refused", TcpCaName);
        yield return new("live", "tcp_wrong_pin_refused", TcpWrongPin);
        yield return new("live", "tcp_other_ca_refused", TcpOtherCa);
        yield return new("live", "tcp_default_server_refuses_endpoint_verdict_2", DefaultRefusesEndpoint);
        yield return new("live", "unverified_impossible_by_construction", Unverified);
        foreach (var via in new[] { "sock", "tcp" })
        {
            string v = via;
            yield return new("live", $"types_roundtrip_edges[{v}]", () => Types(v));
            yield return new("live", $"sum_is_decimal[{v}]", () => SumDecimal(v));
            yield return new("live", $"batch_error_index[{v}]", () => BatchError(v));
            yield return new("live", $"prepared_execute_sets[{v}]", () => Prepared(v));
            yield return new("live", $"transaction_ready_states[{v}]", () => Transactions(v));
            yield return new("live", $"read_point_and_write_commit[{v}]", () => ReadPoint(v));
            yield return new("live", $"error_codes[{v}]", () => ErrorCodes(v));
            yield return new("live", $"copy_in_1m_rows[{v}]", () => CopyIn1M(v));
            yield return new("live", $"copy_in_failures[{v}]", () => CopyInFailures(v));
            yield return new("live", $"copy_out[{v}]", () => CopyOut(v));
            yield return new("live", $"large_results[{v}]", () => LargeResults(v));
            yield return new("live", $"cancel_long_join[{v}]", () => CancelJoin(v));
            yield return new("live", $"cancel_idle_dropped[{v}]", () => CancelIdle(v));
            yield return new("live", $"statement_timeout_not_ours[{v}]", () => StatementTimeout(v));
            yield return new("live", $"ping_during_a_statement[{v}]", () => PingDuring(v));
            yield return new("live", $"sessions_and_kill[{v}]", () => SessionsKill(v));
            yield return new("live", $"closed_reason_after_protocol_error[{v}]", () => ClosedReason(v));
            yield return new("live", $"terminate_rolls_back[{v}]", () => Terminate(v));
            yield return new("live", $"raw_pipelining[{v}]", () => RawPipelining(v));
            yield return new("live", $"concurrent_callers_one_connection[{v}]", () => Concurrent(v));
        }
        yield return new("renew", "pin_survives_cert_renew", PinSurvivesRenew);
    }

    private static async Task<ImdbResult> Q(ImdbConnection c, string sql, params object?[] args) => await c.QueryAsync(sql, args);

    // ======================= logins and TLS =======================

    private static async Task LoginSocket()
    {
        foreach (var s in new[] { A, B })
        {
            await using var c = await ImdbConnection.ConnectAsync(Sock(s));
            T.Eq(ImdbEndpoint.Socket, c.Endpoint, s.Name + " socket");
            T.Eq(ChannelBindingType.None, c.ChannelBinding, "no binding on the socket");
            T.Check(c.ServerCertificateSha256 == null, "no certificate on the socket");
            var r = await Q(c, "SELECT 1");
            T.Eq(1L, r.Rows[0].GetInt64(0), "SELECT 1");
            T.Eq(ImdbTransactionState.Idle, c.TransactionState, "idle");
        }
    }

    private static async Task LoginRefused()
    {
        var wrong = await T.ThrowsAsync<ImdbAuthenticationException>(() => ImdbConnection.ConnectAsync(Sock(B, pw: "not-the-password")), "a wrong password");
        var unknown = await T.ThrowsAsync<ImdbAuthenticationException>(() => ImdbConnection.ConnectAsync(Sock(B, user: "nobody-here", pw: "x")), "an unknown name");
        T.Eq(ImdbAuthFailure.Refused, wrong.Failure, "refused");
        T.Eq(wrong.Failure, unknown.Failure, "an unknown name and a wrong password alike (no oracle)");
        T.Eq(wrong.Message, unknown.Message, "the same words");
        T.Eq(8, wrong.Code, "code 8");
        await T.ThrowsAsync<ImdbAuthenticationException>(() => ImdbConnection.ConnectAsync(Tcp(B, ImdbTls.FromPin(B.Pin), pw: "wrong")), "TCP: a wrong password");
        T.Throws<ArgumentException>(() => Sock(B, pw: "café").Validate(), "a password not ASCII: refused before any byte");
    }

    private static byte[] CertDer(string sdir) => X509Certificate2.CreateFromPem(File.ReadAllText(Path.Combine(sdir, "tls", "server.crt"))).RawData;

    private static async Task TcpPin()
    {
        await using var c = await ImdbConnection.ConnectAsync(Tcp(B, ImdbTls.FromPin(B.Pin)));
        T.Eq(ImdbEndpoint.Tcp, c.Endpoint, "TCP");
        T.Eq(ChannelBindingType.ServerEndPoint, c.ChannelBinding, "tls-server-end-point");
        T.Bytes(SHA256.HashData(CertDer(B.Sdir)), c.ServerCertificateSha256, "the binding: SHA-256 of server.crt's DER");
        T.Eq("ok", (await Q(c, "SELECT 'ok'")).Rows[0].GetString(0), "a statement over TLS");
        // the pin is the key's SPKI SHA-256 (cert's printed pin), not the certificate's hash
        var x = X509Certificate2.CreateFromPem(File.ReadAllText(Path.Combine(B.Sdir, "tls", "server.crt")));
        T.Eq(B.Pin, Convert.ToHexString(SHA256.HashData(x.PublicKey.ExportSubjectPublicKeyInfo())).ToLowerInvariant(), "the pin is the SPKI's SHA-256");
        File.WriteAllText(Path.Combine(Env("IMDB_DRV_RUN"), "b-cert-before.sha256"), Convert.ToHexString(c.ServerCertificateSha256!));
    }

    // .NET's own RFC 5929 value (TransportContext.GetChannelBinding(Endpoint): a SEC_CHANNEL_BINDINGS whose application
    // data is "tls-server-end-point:" and the hash) equals the driver's SHA-256 of the DER: the stdlib computes the
    // binding type 2 the driver sends; it computes no RFC 9266 exporter
    private static async Task EndpointIsStdlib()
    {
        using var sock = new Socket(SocketType.Stream, ProtocolType.Tcp);
        await sock.ConnectAsync("127.0.0.1", B.Port);
        await using var ssl = new SslStream(new NetworkStream(sock, false));
        await ssl.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
        {
            TargetHost = "127.0.0.1",
            EnabledSslProtocols = SslProtocols.Tls13,
            ApplicationProtocols = new List<SslApplicationProtocol> { new("imdbwir1") },
            RemoteCertificateValidationCallback = (_, _, _, _) => true, // this probe sends nothing: only the handshake
        });
        using var cb = ssl.TransportContext.GetChannelBinding(ChannelBindingKind.Endpoint)!;
        var raw = new byte[cb.Size];
        Marshal.Copy(cb.DangerousGetHandle(), raw, 0, cb.Size);
        int len = BitConverter.ToInt32(raw, 24), off = BitConverter.ToInt32(raw, 28);
        var app = raw.AsSpan(off, len);
        T.Check(app.StartsWith("tls-server-end-point:"u8), "the stdlib's token names tls-server-end-point");
        T.Bytes(SHA256.HashData(CertDer(B.Sdir)), app[21..], "the stdlib's RFC 5929 hash is the driver's");
        var members = typeof(SslStream).Assembly.GetTypes().SelectMany(t => t.GetMembers(BindingFlags.Public | BindingFlags.NonPublic |
            BindingFlags.Instance | BindingFlags.Static | BindingFlags.DeclaredOnly)).Where(m => m.Name.Contains("Keying", StringComparison.OrdinalIgnoreCase)
            || (m.Name.Contains("Export", StringComparison.OrdinalIgnoreCase) && m.DeclaringType is { IsEnum: false })).Select(m => m.DeclaringType + "." + m.Name).ToList();
        T.Check(members.Count == 0, "System.Net.Security has no exporter member: " + string.Join(", ", members));
    }

    private static async Task TcpCa()
    {
        foreach (var host in new[] { "127.0.0.1", "localhost" })
        {
            await using var c = await ImdbConnection.ConnectAsync(Tcp(B, ImdbTls.FromCaFile(B.Ca), host));
            T.Eq(2L, (await Q(c, "SELECT 1 + 1")).Rows[0].GetInt64(0), "CA, host " + host);
        }
        // a name the certificate holds, checked apart from the address connected to
        await using var c2 = await ImdbConnection.ConnectAsync(Tcp(B, ImdbTls.FromCaFile(B.Ca, serverName: "localhost")));
        T.Check(c2.IsOpen, "CA, server name localhost at 127.0.0.1");
    }

    private static async Task TcpCaName()
    {
        var e = await T.ThrowsAsync<ImdbAuthenticationException>(
            () => ImdbConnection.ConnectAsync(Tcp(B, ImdbTls.FromCaFile(B.Ca, serverName: "other.example"))), "a name outside subjectAltName");
        T.Check(e.Failure == ImdbAuthFailure.Tls && e.Message.Contains("subjectAltName", StringComparison.Ordinal), e.Message);
    }

    private static async Task TcpWrongPin()
    {
        var pin = new byte[32];
        RandomNumberGenerator.Fill(pin);
        var e = await T.ThrowsAsync<ImdbAuthenticationException>(() => ImdbConnection.ConnectAsync(Tcp(B, ImdbTls.FromPin(pin))), "a random pin");
        T.Check(e.Failure == ImdbAuthFailure.Tls && e.Message.Contains("pinned", StringComparison.Ordinal), e.Message);
        e = await T.ThrowsAsync<ImdbAuthenticationException>(() => ImdbConnection.ConnectAsync(Tcp(B, ImdbTls.FromPin(Env("IMDB_DRV_OTHER_PIN")))), "another server's pin");
        T.Eq(ImdbAuthFailure.Tls, e.Failure, "TLS refused");
        // the certificate's hash as a pin: wrong by construction (the pin is the key's)
        e = await T.ThrowsAsync<ImdbAuthenticationException>(() => ImdbConnection.ConnectAsync(Tcp(B, ImdbTls.FromPin(SHA256.HashData(CertDer(B.Sdir))))),
                                                              "the certificate's hash is not the pin");
        T.Eq(ImdbAuthFailure.Tls, e.Failure, "TLS refused");
    }

    private static async Task TcpOtherCa()
    {
        var e = await T.ThrowsAsync<ImdbAuthenticationException>(() => ImdbConnection.ConnectAsync(Tcp(B, ImdbTls.FromCaFile(Env("IMDB_DRV_OTHER_CA")))), "another CA");
        T.Check(e.Failure == ImdbAuthFailure.Tls && e.Message.Contains("CA", StringComparison.Ordinal), e.Message);
        // server A's CA does not sign server B's certificate either
        await T.ThrowsAsync<ImdbAuthenticationException>(() => ImdbConnection.ConnectAsync(Tcp(B, ImdbTls.FromCaFile(A.Ca))), "A's CA for B");
    }

    private static async Task DefaultRefusesEndpoint()
    {
        foreach (var tls in new[] { ImdbTls.FromPin(A.Pin), ImdbTls.FromCaFile(A.Ca) })
        {
            var e = await T.ThrowsAsync<ImdbAuthenticationException>(() => ImdbConnection.ConnectAsync(Tcp(A, tls)), "a default server, end-point");
            T.Eq(ImdbAuthFailure.BindingRefused, e.Failure, "verdict 2: the binding type refused");
            T.Check(e.Message.Contains("--channel-binding any", StringComparison.Ordinal), e.Message);
        }
        // the same server takes the socket
        await using var c = await ImdbConnection.ConnectAsync(Sock(A));
        T.Check(c.IsOpen, "A's socket");
    }

    private static Task Unverified()
    {
        T.Throws<ArgumentException>(() => new ImdbConnectOptions { Host = "127.0.0.1", Port = B.Port, User = User, Password = Password }.Validate(),
                                    "TCP without Tls refused before any byte");
        T.Throws<ArgumentException>(() => new ImdbConnectOptions { SocketPath = B.Sock, Tls = ImdbTls.FromPin(B.Pin), User = User, Password = Password }.Validate(),
                                    "the socket with Tls: no fallback either way");
        T.Throws<ArgumentException>(() => new ImdbConnectOptions { SocketPath = B.Sock, Host = "127.0.0.1", Port = 1, User = User, Password = Password }.Validate(),
                                    "both endpoints");
        T.Eq(0, typeof(ImdbTls).GetConstructors(BindingFlags.Public | BindingFlags.Instance).Length, "ImdbTls has no public constructor");
        var factories = typeof(ImdbTls).GetMethods(BindingFlags.Public | BindingFlags.Static).Select(m => m.Name).Distinct().OrderBy(n => n, StringComparer.Ordinal).ToArray();
        T.Eq("FromCaCertificate,FromCaFile,FromPin", string.Join(",", factories), "every way to make one names a CA or a pin");
        T.Check(!typeof(ImdbConnectOptions).GetProperties().Any(p => typeof(Delegate).IsAssignableFrom(p.PropertyType)),
                "no validation callback of the caller's");
        T.Throws<ArgumentException>(() => ImdbTls.FromPin("00"), "a short pin");
        return Task.CompletedTask;
    }

    // ======================= values =======================

    private static readonly ImdbDecimal W38Max = ImdbDecimal.Parse("99999999999999999999999999999999.999999");
    private static readonly ImdbDecimal Z38Max = ImdbDecimal.Parse("99999999999999999999999999999999999999");

    private static async Task Types(string via)
    {
        await using var c = await Open(via);
        string ty = "ty_" + via, mood = "mood_" + via;
        await Q(c, $"CREATE TYPE {mood} AS ENUM ('sad', 'ok', 'happy', 'é')");
        await Q(c, $"CREATE TABLE {ty} (id INT64 PRIMARY KEY, i64 INT64, s SMALLINT, n INTEGER, d DECIMAL(10,2), w DECIMAL(38,6), " +
                   $"z DECIMAL(38,0), f FLOAT64, b BOOL, t TEXT, v VARCHAR(5), ts TIMESTAMP, tz TIMESTAMPTZ, dt DATE, tm TIME, u UUID, " +
                   $"bb BYTEA, iv INTERVAL, m {mood})");
        string ins = $"INSERT INTO {ty} VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19)";
        var maxTs = DateTime.MaxValue.AddTicks(-9);
        var maxTz = new DateTimeOffset(maxTs, TimeSpan.Zero);
        var big = new string('é', 32767) + "a"; // 65,535 bytes
        object?[] r1 =
        {
            1L, long.MaxValue, (short)32767, int.MaxValue, ImdbDecimal.Parse("99999999.99"), W38Max, Z38Max, double.MaxValue, true,
            "hé|x\U0001F600", "abcd\U0001F600", maxTs, maxTz, DateOnly.MaxValue, new TimeOnly(863999999990L),
            Guid.Parse("ffffffff-ffff-ffff-ffff-ffffffffffff"), new byte[] { 0, 255, 0 }, new ImdbInterval(int.MaxValue, int.MaxValue, long.MaxValue), "é",
        };
        object?[] r2 =
        {
            2L, long.MinValue, (short)-32768, int.MinValue, ImdbDecimal.Parse("-99999999.99"), ImdbDecimal.Parse("-99999999999999999999999999999999.999999"),
            ImdbDecimal.Parse("-99999999999999999999999999999999999999"), -2.5e300, false, "", "", DateTime.MinValue, DateTimeOffset.MinValue,
            DateOnly.MinValue, TimeOnly.MinValue, Guid.Empty, Array.Empty<byte>(), new ImdbInterval(int.MinValue, int.MinValue, long.MinValue), "sad",
        };
        object?[] r3 =
        {
            3L, 0L, (short)0, 0, ImdbDecimal.Parse("0.01"), ImdbDecimal.Parse("0.000001"), (ImdbDecimal)1, double.Epsilon, true, big, "ééééé",
            new DateTime(1970, 1, 1, 0, 0, 0, 1), new DateTimeOffset(2026, 3, 8, 2, 30, 0, TimeSpan.FromHours(-5)), new DateOnly(1970, 1, 1),
            new TimeOnly(0, 0, 0, 0, 1), Guid.Parse("00010203-0405-0607-0809-0a0b0c0d0e0f"), Enumerable.Range(0, 256).Select(i => (byte)i).ToArray(),
            new ImdbInterval(1, -2, 3), "ok",
        };
        var types = new[] { ImdbType.Int64, ImdbType.Int64, ImdbType.Int64, ImdbType.Int64, ImdbType.Decimal, ImdbType.Decimal, ImdbType.Decimal, ImdbType.Float64,
                            ImdbType.Bool, ImdbType.Text, ImdbType.Text, ImdbType.Timestamp, ImdbType.TimestampTz, ImdbType.Date, ImdbType.Time, ImdbType.Uuid,
                            ImdbType.Bytea, ImdbType.Interval, ImdbType.Enum };
        object?[] r4 = new object?[19];
        r4[0] = 4L;
        for (int k = 1; k < 19; k++) r4[k] = ImdbValue.Null(types[k]); // a NULL of each type
        object?[] r5 = new object?[19];
        r5[0] = 5L; // the rest a NULL of no type (C# null)
        foreach (var row in new[] { r1, r2, r3, r4, r5 })
        {
            var res = await c.QueryAsync(ins, row);
            T.Eq(1UL, res.Count, "one row written");
        }
        // the first row again by literals: the parameter path and the literal path store the same values
        await Q(c, $"INSERT INTO {ty} VALUES (6, 9223372036854775807, 32767, 2147483647, 99999999.99, 99999999999999999999999999999999.999999, " +
                   "99999999999999999999999999999999999999, 1.7976931348623157e308, TRUE, 'hé|x\U0001F600', 'abcd\U0001F600', " +
                   "TIMESTAMP '9999-12-31 23:59:59.999999', TIMESTAMPTZ '9999-12-31 23:59:59.999999+00', DATE '9999-12-31', TIME '23:59:59.999999', " +
                   "UUID 'ffffffff-ffff-ffff-ffff-ffffffffffff', '\\x00ff00', NULL, 'é')");
        var r = await Q(c, $"SELECT * FROM {ty} ORDER BY id");
        T.Eq(6, r.Rows.Count, "six rows");
        // the columns' metadata (§4: precision and scale by type)
        var cols = r.Columns;
        // what imagedb-server reports for a result: a DECIMAL's scale alone (precision 0: not known), an INT64's width and a
        // VARCHAR's length as 0 (conv.c imdbw_columns_of): §4 lets them travel, the server does not send them
        T.Eq("id INT64,i64 INT64,s INT64,n INT64,d DECIMAL(*,2),w DECIMAL(*,6),z DECIMAL(*,0),f FLOAT64,b BOOL,t TEXT,v TEXT," +
             "ts TIMESTAMP,tz TIMESTAMPTZ,dt DATE,tm TIME,u UUID,bb BYTEA,iv INTERVAL,m ENUM", string.Join(",", cols.Select(x => x.ToString())), "COLUMNS");
        T.Eq("sad,ok,happy,é", string.Join(",", cols[18].Labels), "the ENUM's labels in the type's order");
        for (int k = 0; k < 19; k++) T.Eq(types[k], cols[k].Type, "column type " + cols[k].Name);
        foreach (var (want, got) in new[] { (r1, r.Rows[0]), (r2, r.Rows[1]), (r3, r.Rows[2]) })
            for (int k = 0; k < 19; k++)
                T.Check(Same(want[k], got, k), $"row {want[0]} column {cols[k].Name}: sent {Show(want[k])}, read {Show(got[k])}");
        T.Eq(BitConverter.DoubleToInt64Bits(double.Epsilon), BitConverter.DoubleToInt64Bits(r.Rows[2].GetDouble(7)), "the least subnormal, bit for bit");
        T.Eq(maxTz, r.Rows[0].GetTimestampTz(12), "TIMESTAMPTZ max");
        T.Eq(new DateTimeOffset(2026, 3, 8, 7, 30, 0, TimeSpan.Zero), r.Rows[2].GetTimestampTz(12), "an instant read at offset 0");
        for (int k = 1; k < 19; k++)
        {
            T.Check(r.Rows[3].IsNull(k) && r.Rows[3].GetValue(k).Type == types[k], $"a typed NULL into {cols[k].Name}, read as a NULL of its type");
            T.Check(r.Rows[4].IsNull(k) && r.Rows[4].GetValue(k).Type == types[k], $"a NULL of no type into {cols[k].Name}");
        }
        for (int k = 1; k < 19; k++)
            if (k != 17) T.Check(r.Rows[5].GetValue(k).Equals(r.Rows[0].GetValue(k)), $"literal and parameter alike: {cols[k].Name}");
        // the driver refuses before sending what the wire does not carry; the engine refuses a value its column does not take
        await T.ThrowsAsync<ArgumentException>(() => c.QueryAsync(ins, r1.Select((x, i) => i == 7 ? (object)(-0.0) : x).ToArray()), "-0.0 refused by the driver");
        var e = await T.ThrowsAsync<ImdbServerException>(() => c.QueryAsync($"INSERT INTO {ty} (id, v) VALUES (7, $1)", "abcdef"), "six characters into VARCHAR(5)");
        T.Check(e.Code > 0, "the engine's ERROR: " + e.Message);
        e = await T.ThrowsAsync<ImdbServerException>(() => c.QueryAsync($"INSERT INTO {ty} (id, s) VALUES (7, $1)", 32768L), "32,768 into SMALLINT");
        e = await T.ThrowsAsync<ImdbServerException>(() => c.QueryAsync($"INSERT INTO {ty} (id, m) VALUES (7, $1)", "nope"), "a label the type lacks");
        T.Check(!e.Message.Contains("nope", StringComparison.Ordinal), "the ERROR never names the value: " + e.Message);
        T.Eq(ImdbTransactionState.Idle, c.TransactionState, "idle after the refusals");
    }

    private static bool Same(object? want, ImdbRow row, int k)
    {
        var v = row.GetValue(k);
        if (want == null) return v.IsNull;
        if (v.IsNull) return false;
        return want switch
        {
            long l => v.AsInt64() == l,
            short s => v.AsInt64() == s,
            int i => v.AsInt64() == i,
            ImdbDecimal d => v.AsDecimal().Equals(d),
            double f => BitConverter.DoubleToInt64Bits(v.AsFloat64()) == BitConverter.DoubleToInt64Bits(f),
            bool b => v.AsBool() == b,
            string s when v.Type == ImdbType.Enum => v.AsEnumLabel() == s,
            string s => v.AsText() == s,
            DateTime dt => v.AsTimestamp() == dt,
            DateTimeOffset dto => v.AsTimestampTz().UtcTicks == dto.UtcTicks,
            DateOnly d => v.AsDate() == d,
            TimeOnly t => v.AsTime() == t,
            Guid g => v.AsUuid() == g,
            byte[] b => v.AsBytes().AsSpan().SequenceEqual(b),
            ImdbInterval iv => v.AsInterval() == iv,
            _ => false,
        };
    }

    private static string Show(object? o) => o switch
    {
        null => "NULL",
        byte[] b => Convert.ToHexString(b.Length > 16 ? b[..16] : b),
        string s => s.Length > 20 ? s[..20] + "..." : s,
        _ => Convert.ToString(o, System.Globalization.CultureInfo.InvariantCulture) ?? "",
    };

    private static async Task SumDecimal(string via)
    {
        await using var c = await Open(via);
        string t = "sm_" + via;
        await Q(c, $"CREATE TABLE {t} (id INT64 PRIMARY KEY, x INT64)");
        await c.ExecuteBatchAsync(new[] { ImdbStatement.Of($"INSERT INTO {t} VALUES (1, $1)", long.MaxValue), ImdbStatement.Of($"INSERT INTO {t} VALUES (2, $1)", long.MaxValue) });
        var r = await Q(c, $"SELECT SUM(x) FROM {t}");
        T.Eq(ImdbType.Decimal, r.Columns[0].Type, "a SUM of INT64 is a DECIMAL (§4)");
        T.Eq(ImdbDecimal.Parse("18446744073709551614"), r.Rows[0].GetDecimal(0), "two INT64 maxima: 20 digits exactly");
        T.Eq(System.Numerics.BigInteger.Parse("18446744073709551614"), r.Rows[0].Get<System.Numerics.BigInteger>(0), "as BigInteger");
        r = await Q(c, $"SELECT SUM(x) FROM {t} WHERE id > 10");
        T.Check(r.Columns[0].Type == ImdbType.Decimal && r.Rows[0].IsNull(0) && r.Rows[0].GetValue(0).Type == ImdbType.Decimal,
                "an empty SUM: a DECIMAL NULL (the column's type from the statement, never its cells)");
    }

    // ======================= batches, prepared statements, transactions =======================

    private static async Task BatchError(string via)
    {
        await using var c = await Open(via);
        string t = "be_" + via;
        await Q(c, $"CREATE TABLE {t} (id INT64 PRIMARY KEY)");
        var b = await c.ExecuteBatchAsync(new[]
        {
            ImdbStatement.Of($"INSERT INTO {t} VALUES ($1)", 1L), ImdbStatement.Of($"SELECT id FROM {t}"),
            ImdbStatement.Of($"INSERT INTO {t} VALUES ($1)", 1L), ImdbStatement.Of($"INSERT INTO {t} VALUES ($1)", 3L),
        });
        T.Eq(2, b.Results.Count, "the two before the failure stand");
        T.Check(b.Error != null && b.Error.Index == 2 && b.Error.Code == (int)ImdbErrorCode.Constraint, $"ERROR's index 2, a constraint: {b.Error?.Index} {b.Error?.Code}");
        T.Eq(1, b.Results[1].Rows.Count, "the SELECT's answer");
        T.Eq(ImdbTransactionState.Idle, b.State, "READY idle");
        var r = await Q(c, $"SELECT COUNT(*) FROM {t}");
        T.Eq(1L, r.Rows[0].GetInt64(0), "the statement after the ERROR did not run");
        var e = T.Throws<ImdbServerException>(() => b.ThrowIfError(), "ThrowIfError");
        T.Eq(2, e.CompletedResults.Count, "the exception carries the results before it");
        // in a transaction: BEGIN, an INSERT, a failing one, COMMIT as ONE batch: the COMMIT never runs, READY says so
        b = await c.ExecuteBatchAsync(new[] { new ImdbStatement("BEGIN"), ImdbStatement.Of($"INSERT INTO {t} VALUES (5)"),
                                             ImdbStatement.Of($"INSERT INTO {t} VALUES (1)"), new ImdbStatement("COMMIT") });
        T.Check(b.Error?.Index == 2 && b.State == ImdbTransactionState.InTransaction, "stopped at the first error, the transaction open");
        T.Eq(ImdbTransactionState.InTransaction, c.TransactionState, "the connection's state");
        await Q(c, "ROLLBACK");
        T.Eq(0L, (await Q(c, $"SELECT COUNT(*) FROM {t} WHERE id = 5")).Rows[0].GetInt64(0), "rolled back");
    }

    private static async Task Prepared(string via)
    {
        await using var c = await Open(via);
        string t = "pr_" + via;
        await Q(c, $"CREATE TABLE {t} (id INT64 PRIMARY KEY, d DECIMAL(10,2), s TEXT)");
        await c.PrepareAsync("ins", $"INSERT INTO {t} VALUES ($1, $2, $3)");
        var b = await c.ExecuteBatchAsync("ins", new[]
        {
            new object?[] { 1L, ImdbDecimal.Parse("1.50"), "a" }, new object?[] { 2L, 7L, "b" }, new object?[] { 3L, ImdbDecimal.Parse("1.5"), null },
        });
        T.Check(b.Error == null && b.Results.Count == 3 && b.Results.All(x => x.Count == 1), "three sets, three answers");
        b = await c.ExecuteBatchAsync("ins", new[] { new object?[] { 4L, null, "x" }, new object?[] { 1L, null, "dup" }, new object?[] { 5L, null, "y" } });
        T.Check(b.Error?.Index == 1 && b.Results.Count == 1, "the failed set's index: 1");
        await c.PrepareAsync("sel", $"SELECT d, s FROM {t} WHERE id = $1");
        var r = await c.ExecuteAsync("sel", new object?[] { 2L });
        T.Eq(ImdbDecimal.Parse("7.00"), r.Rows[0].GetDecimal(0), "an INT64 parameter bound as its literal: 7 into DECIMAL(10,2) is 7.00");
        r = await c.ExecuteAsync("sel", new object?[] { 3L });
        T.Check(r.Rows[0].IsNull(1) && r.Rows[0].GetDecimal(0).Equals(new ImdbDecimal(150, 2)), "1.5 stored at the column's scale, a NULL kept");
        await c.DeallocateAsync("sel");
        var e = await T.ThrowsAsync<ImdbServerException>(() => c.ExecuteAsync("sel", new object?[] { 1L }), "EXECUTE after DEALLOCATE");
        T.Eq((int)ImdbErrorCode.NotFound, e.Code, "not found");
        e = await T.ThrowsAsync<ImdbServerException>(() => c.DeallocateAsync("nope"), "DEALLOCATE of none");
        T.Eq(0u, e.Index, "index 0 for a request of no batch");
        await T.ThrowsAsync<ArgumentException>(() => c.ExecuteBatchAsync("ins", new[] { new object?[] { 1L }, new object?[] { 1L, 2L } }), "sets of two counts");
    }

    private static async Task Transactions(string via)
    {
        await using var c = await Open(via);
        await using var other = await Open(via);
        string t = "tx_" + via;
        await Q(c, $"CREATE TABLE {t} (id INT64 PRIMARY KEY)");
        await Q(c, "BEGIN");
        T.Eq(ImdbTransactionState.InTransaction, c.TransactionState, "READY 1 after BEGIN");
        await Q(c, $"INSERT INTO {t} VALUES (1)");
        await T.ThrowsAsync<ImdbServerException>(() => Q(c, $"INSERT INTO {t} VALUES (1)"), "a duplicate");
        T.Eq(ImdbTransactionState.InTransaction, c.TransactionState, "statement-level rollback: still in the transaction");
        await Q(c, "COMMIT");
        T.Eq(ImdbTransactionState.Idle, c.TransactionState, "READY 0 after COMMIT");
        T.Eq(1L, (await Q(other, $"SELECT COUNT(*) FROM {t}")).Rows[0].GetInt64(0), "committed");
        // a doomed transaction: another session's ALTER of the table it wrote
        await Q(c, "BEGIN");
        await Q(c, $"INSERT INTO {t} VALUES (2)");
        await Q(other, $"ALTER TABLE {t} ADD COLUMN z INT64");
        var e = await T.ThrowsAsync<ImdbServerException>(() => Q(c, $"INSERT INTO {t} VALUES (3, 3)"), "a statement in a doomed transaction");
        T.Eq(ImdbTransactionState.Doomed, e.TransactionState, "READY 2: doomed: " + e.Message);
        T.Eq(ImdbTransactionState.Doomed, c.TransactionState, "the connection says doomed");
        await Q(c, "ROLLBACK");
        T.Eq(ImdbTransactionState.Idle, c.TransactionState, "idle after ROLLBACK");
    }

    private static async Task ReadPoint(string via)
    {
        await using var c = await Open(via);
        string t = "rp_" + via;
        await Q(c, $"CREATE TABLE {t} (id INT64 PRIMARY KEY)");
        var w1 = await Q(c, $"INSERT INTO {t} VALUES (1)");
        var w2 = await Q(c, $"INSERT INTO {t} VALUES (2)");
        T.Check(w1.Write != null && w2.Write != null && w2.Write.Commit == w1.Write.Commit + 1 && w1.Write.CommitHash.Length == 32,
                "each autocommit write its own commit");
        var r = await Q(c, $"SELECT id FROM {t}");
        T.Check(r.ReadPoint != null && r.ReadPoint.Commit >= w2.Write!.Commit && !r.ReadPoint.OwnWrites && r.ReadPoint.DatabaseId.Length == 16,
                "a read point at or past the write");
        T.Bytes(w2.Write!.CommitHash, r.ReadPoint!.CommitHash, "the read point's hash is that commit's");
        T.Eq("", r.Status, "a SELECT's status: none (its count is the rows)");
        T.Eq("INSERT 1", w1.Status, "an INSERT's status");
        T.Eq(2UL, r.Count, "the count");
        await Q(c, "BEGIN");
        await Q(c, $"INSERT INTO {t} VALUES (3)");
        r = await Q(c, $"SELECT id FROM {t}");
        T.Check(r.ReadPoint!.OwnWrites && r.Rows.Count == 3, "own writes seen");
        var cm = await Q(c, "COMMIT");
        T.Check(cm.Write != null && cm.Write.Commit == w2.Write.Commit + 1, "COMMIT's DONE carries the transaction's commit");
    }

    private static async Task ErrorCodes(string via)
    {
        await using var c = await Open(via);
        T.Eq((int)ImdbErrorCode.Syntax, (await T.ThrowsAsync<ImdbServerException>(() => Q(c, "SELEC 1"), "syntax")).Code, "10 a syntax error");
        T.Eq((int)ImdbErrorCode.NotFound, (await T.ThrowsAsync<ImdbServerException>(() => Q(c, "SELECT * FROM nosuch_table"), "no table")).Code, "11 not found");
        T.Eq((int)ImdbErrorCode.Invalid, (await T.ThrowsAsync<ImdbServerException>(() => Q(c, "SELECT 1 / 0"), "division")).Code, "4 invalid");
        T.Eq((int)ImdbErrorCode.Invalid, (await T.ThrowsAsync<ImdbServerException>(() => c.QueryAsync("SELECT $1 + 1", "text"), "TEXT + 1")).Code, "4 invalid");
        T.Check(c.IsOpen && (await Q(c, "SELECT 1")).Rows.Count == 1, "usable after errors");
    }

    // ======================= COPY =======================

    /// <summary>"1\n2\n...": n rows of one INT64, made as read (never held whole).</summary>
    private sealed class RowsStream : Stream
    {
        private readonly long _n;
        private long _next;
        private byte[] _pend = Array.Empty<byte>();
        private int _at;
        private readonly long _failAt;

        public RowsStream(long n, long failAt = -1)
        {
            _n = n;
            _failAt = failAt;
        }

        public long Reads;

        public override int Read(byte[] buffer, int offset, int count)
        {
            Reads++;
            int k = 0;
            while (k < count)
            {
                if (_at == _pend.Length)
                {
                    if (_next == _failAt) throw new IOException("the source failed on purpose");
                    if (_next >= _n) break;
                    _pend = Encoding.ASCII.GetBytes(_next.ToString(System.Globalization.CultureInfo.InvariantCulture) + "\n");
                    _at = 0;
                    _next++;
                }
                int m = Math.Min(count - k, _pend.Length - _at);
                Array.Copy(_pend, _at, buffer, offset + k, m);
                _at += m;
                k += m;
            }
            return k;
        }

        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override void Flush() { }
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }

    private static async Task CopyIn1M(string via)
    {
        await using var c = await Open(via);
        string t = "big_" + via;
        await Q(c, $"CREATE TABLE {t} (x INT64 PRIMARY KEY)");
        var sw = Stopwatch.StartNew();
        var r = await c.CopyInAsync($"COPY {t} FROM STDIN", new RowsStream(1000000));
        T.Eq(1000000UL, r.Count, "COPY's count: 1,000,000 rows");
        T.Eq(1000000L, (await Q(c, $"SELECT COUNT(*) FROM {t}")).Rows[0].GetInt64(0), "the table holds them");
        Console.WriteLine($"     COPY of 1,000,000 rows ({via}): {sw.ElapsedMilliseconds} ms");
    }

    private static async Task CopyInFailures(string via)
    {
        await using var c = await Open(via);
        string t = "cf_" + via;
        await Q(c, $"CREATE TABLE {t} (x INT64 PRIMARY KEY)");
        // a source that fails part way: COPY_FAIL, the statement refused unrun, the source's exception thrown
        var e = await T.ThrowsAsync<IOException>(() => c.CopyInAsync($"COPY {t} FROM STDIN", new RowsStream(500000, failAt: 300000)), "the source fails");
        T.Check(e.Message.Contains("on purpose", StringComparison.Ordinal), "the source's own exception");
        T.Eq(0L, (await Q(c, $"SELECT COUNT(*) FROM {t}")).Rows[0].GetInt64(0), "nothing of a failed COPY stays");
        // a bad field: answered after COPY_DONE (the data held whole first), nothing stays
        var bad = new MemoryStream(Encoding.ASCII.GetBytes("1\n2\nthree\n4\n"));
        var se = await T.ThrowsAsync<ImdbServerException>(() => c.CopyInAsync($"COPY {t} FROM STDIN", bad), "a bad field");
        T.Check(se.Code > 0 && !se.Message.Contains("three", StringComparison.Ordinal), "the ERROR names the line, never the value: " + se.Message);
        T.Eq(0L, (await Q(c, $"SELECT COUNT(*) FROM {t}")).Rows[0].GetInt64(0), "nothing stays");
        // refused before its data (no such table): no COPY_IN, so the source is never read
        var src = new RowsStream(10);
        await T.ThrowsAsync<ImdbServerException>(() => c.CopyInAsync("COPY no_such_table FROM STDIN", src), "no such table");
        T.Eq(0L, src.Reads, "no data sent: the server refused before COPY_IN");
        // a COPY FROM STDIN through QueryAsync: no source, ended at once by COPY_FAIL
        se = await T.ThrowsAsync<ImdbServerException>(() => Q(c, $"COPY {t} FROM STDIN"), "QueryAsync of a COPY FROM STDIN");
        T.Eq((int)ImdbErrorCode.Cancelled, se.Code, "COPY_FAIL fails the statement (15): " + se.Message);
        // cancelled by the caller's token while uploading a slow source
        using var cts = new CancellationTokenSource();
        var slow = new SlowStream(cts);
        await T.ThrowsAsync<OperationCanceledException>(() => c.CopyInAsync($"COPY {t} FROM STDIN", slow, cts.Token), "cancelled mid-upload");
        T.Eq(0L, (await Q(c, $"SELECT COUNT(*) FROM {t}")).Rows[0].GetInt64(0), "nothing of a cancelled COPY stays");
        T.Check(c.IsOpen, "usable after every failure");
        // and a good one after it all
        T.Eq(3UL, (await c.CopyInAsync($"COPY {t} FROM STDIN", new MemoryStream(Encoding.ASCII.GetBytes("1\n2\n3\n")))).Count, "three rows");
    }

    /// <summary>Rows forever, slowly; cancels the token after a few reads.</summary>
    private sealed class SlowStream : Stream
    {
        private readonly CancellationTokenSource _cts;
        private int _reads;
        public SlowStream(CancellationTokenSource cts) => _cts = cts;

        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken ct = default)
        {
            if (++_reads == 5) _cts.Cancel();
            await Task.Delay(20, ct);
            var b = Encoding.ASCII.GetBytes((1000 + _reads).ToString(System.Globalization.CultureInfo.InvariantCulture) + "\n");
            b.CopyTo(buffer);
            return b.Length;
        }

        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override void Flush() { }
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }

    private static async Task CopyOut(string via)
    {
        await using var c = await Open(via);
        string t = "co_" + via;
        await Q(c, $"CREATE TABLE {t} (id INT64 PRIMARY KEY, s TEXT)");
        await c.CopyInAsync($"COPY {t} FROM STDIN", new MemoryStream(Encoding.UTF8.GetBytes("1,a\n2,\"b,c\"\n3,hé\n")));
        var ms = new MemoryStream();
        var r = await c.CopyOutAsync($"COPY {t} TO STDOUT", ms);
        T.Eq("1,a\n2,\"b,c\"\n3,hé\n", Encoding.UTF8.GetString(ms.ToArray()), "COPY TO's bytes");
        T.Eq(3UL, r.Count, "its count");
        var q = await Q(c, $"COPY {t} TO STDOUT");
        T.Bytes(ms.ToArray(), q.CopyData, "through QueryAsync: the bytes in the result");
        // the big table out, streamed: 1,000,000 lines
        var big = new MemoryStream();
        r = await c.CopyOutAsync($"COPY big_{via} TO STDOUT", big);
        T.Eq(1000000UL, r.Count, "1,000,000 rows out");
        T.Eq(1000000, big.ToArray().Count(b => b == (byte)'\n'), "1,000,000 lines");
        // a destination that throws: the statement cancelled, its exception thrown, the connection usable
        var e = await T.ThrowsAsync<IOException>(() => c.CopyOutAsync($"COPY big_{via} TO STDOUT", new FailingSink()), "a failing destination");
        T.Check(e.Message.Contains("sink", StringComparison.Ordinal), e.Message);
        T.Eq(1L, (await Q(c, "SELECT 1")).Rows[0].GetInt64(0), "usable after");
    }

    private sealed class FailingSink : Stream
    {
        private int _n;
        public override void Write(byte[] buffer, int offset, int count)
        {
            if (++_n == 2) throw new IOException("the sink failed on purpose");
        }

        public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken ct = default)
        {
            Write(Array.Empty<byte>(), 0, 0);
            return ValueTask.CompletedTask;
        }

        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        public override bool CanRead => false;
        public override bool CanSeek => false;
        public override bool CanWrite => true;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override void Flush() { }
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
    }

    private static async Task LargeResults(string via)
    {
        await using var c = await Open(via);
        var r = await Q(c, $"SELECT x FROM big_{via} WHERE x < 200000 ORDER BY x");
        T.Eq(200000, r.Rows.Count, "200,000 rows (several ROWS frames)");
        T.Check(r.Rows.Select((row, i) => row.GetInt64(0) == i).All(b => b), "each in order");
        T.Eq(200000UL, r.Count, "DONE's count");
    }

    // ======================= cancel =======================

    private static string LongJoin(string via) => $"SELECT COUNT(*) FROM big_{via} AS a, big_{via} AS b WHERE a.x < b.x";

    private static async Task CancelJoin(string via)
    {
        await using var c = await Open(via);
        // Cancel() from another task
        var sw = Stopwatch.StartNew();
        var q = Q(c, LongJoin(via));
        await Task.Delay(300);
        T.Check(!q.IsCompleted, "the join still runs after 300 ms");
        _ = Task.Run(() => c.Cancel());
        var e = await T.ThrowsAsync<ImdbServerException>(() => q, "cancelled by Cancel()");
        T.Eq((int)ImdbErrorCode.Cancelled, e.Code, "ERROR 15: " + e.Message);
        T.Check(sw.ElapsedMilliseconds < 20000, $"cancelled promptly ({sw.ElapsedMilliseconds} ms)");
        T.Eq(1L, (await Q(c, "SELECT 1")).Rows[0].GetInt64(0), "usable after");
        // by the caller's token: OperationCanceledException, its ERROR inside
        using var cts = new CancellationTokenSource(300);
        var oce = await T.ThrowsAsync<OperationCanceledException>(() => c.QueryAsync(LongJoin(via), Array.Empty<object?>(), cts.Token), "cancelled by a token");
        T.Check(oce.InnerException is ImdbServerException { Code: 15 }, "its ERROR 15 inside");
        T.Eq(1L, (await Q(c, "SELECT 1")).Rows[0].GetInt64(0), "usable after");
        // from a thread blocked elsewhere: Cancel() never blocks
        var q2 = Q(c, LongJoin(via));
        await Task.Delay(200);
        var t0 = Stopwatch.GetTimestamp();
        new Thread(() => c.Cancel()).Start();
        await T.ThrowsAsync<ImdbServerException>(() => q2, "cancelled from a thread");
        T.Check(Stopwatch.GetElapsedTime(t0).TotalSeconds < 20, "promptly");
    }

    private static async Task CancelIdle(string via)
    {
        await using var c = await Open(via);
        c.Cancel(); // nothing outstanding: dropped (§4), never the next statement's
        await Task.Delay(100);
        T.Eq(1L, (await Q(c, "SELECT 1")).Rows[0].GetInt64(0), "the next statement runs");
        // a token cancelled after its request ended reaches nothing
        using var cts = new CancellationTokenSource();
        var r = await c.QueryAsync("SELECT 2", Array.Empty<object?>(), cts.Token);
        cts.Cancel();
        await Task.Delay(100);
        T.Eq(2L, r.Rows[0].GetInt64(0), "the first ran");
        var q = Q(c, $"SELECT COUNT(*) FROM big_{via} WHERE x < 1000");
        T.Eq(1000L, (await q).Rows[0].GetInt64(0), "the next is not cancelled");
        // many idle cancels, then a long-ish statement that must run to its end
        for (int i = 0; i < 50; i++) c.Cancel();
        await Task.Delay(100);
        T.Eq(1000000L, (await Q(c, $"SELECT COUNT(*) FROM big_{via}")).Rows[0].GetInt64(0), "runs to its end");
    }

    private static async Task StatementTimeout(string via)
    {
        await using var c = await Open(via);
        await Q(c, "SET statement_timeout = 300");
        using var cts = new CancellationTokenSource(); // never cancelled: the ERROR 15 is the server's own, not this caller's
        var e = await T.ThrowsAsync<ImdbServerException>(() => c.QueryAsync(LongJoin(via), Array.Empty<object?>(), cts.Token), "the server's timeout");
        T.Eq(15, e.Code, "15: " + e.Message);
        await Q(c, "SET statement_timeout = 0");
        T.Eq(1L, (await Q(c, "SELECT 1")).Rows[0].GetInt64(0), "usable");
    }

    private static async Task PingDuring(string via)
    {
        await using var c = await Open(via);
        var idle = await c.PingAsync();
        T.Check(idle < TimeSpan.FromSeconds(5), "PING idle");
        var q = Q(c, LongJoin(via));
        await Task.Delay(200);
        var rt = await c.PingAsync(); // answered out of turn by the connection's thread, the statement still running
        T.Check(!q.IsCompleted, $"PONG came while the statement ran ({rt.TotalMilliseconds:0} ms)");
        c.Cancel();
        await T.ThrowsAsync<ImdbServerException>(() => q, "then cancelled");
        await Task.WhenAll(Enumerable.Range(0, 20).Select(_ => c.PingAsync()));
        T.Check(true, "20 PINGs at once, each its PONG");
    }

    // ======================= SESSIONS and KILL =======================

    private static async Task<ulong> NewestId(ImdbConnection op) => (await op.SessionsAsync()).Max(s => s.Id);

    private static async Task SessionsKill(string via)
    {
        await using var op = await Open(via);
        var list = await op.SessionsAsync();
        T.Check(list.Count >= 1 && list.Zip(list.Skip(1)).All(p => p.First.Id < p.Second.Id), "ids strictly increasing");
        T.Check(list.All(s => s.RoleName == User && s.RoleId >= 1), "every session the superuser's here");
        await using var x = await Open(via);
        ulong xid = await NewestId(op);
        var xs = (await op.SessionsAsync()).Single(s => s.Id == xid);
        T.Eq(via == "sock" ? ImdbEndpoint.Socket : ImdbEndpoint.Tcp, xs.Endpoint, "its endpoint");
        T.Eq(ImdbSessionState.Idle, xs.State, "idle");
        // KILL cancel of X's running statement: ERROR 15, X usable after
        var q = Q(x, LongJoin(via));
        await Task.Delay(300);
        T.Eq(ImdbSessionState.Running, (await op.SessionsAsync()).Single(s => s.Id == xid).State, "running");
        T.Check(await op.KillAsync(xid, ImdbKillKind.Cancel), "KILL cancel: done");
        var e = await T.ThrowsAsync<ImdbServerException>(() => q, "X's statement cancelled by a KILL");
        T.Eq(15, e.Code, "15: " + e.Message);
        T.Eq(1L, (await Q(x, "SELECT 1")).Rows[0].GetInt64(0), "X usable after a KILL's cancel");
        // KILL terminate of an idle Y: Y's next send reports the server's words (closed_reason)
        var y = await Open(via);
        ulong yid = await NewestId(op);
        await Q(y, "BEGIN");
        T.Eq(ImdbSessionState.InTransaction, (await op.SessionsAsync()).Single(s => s.Id == yid).State, "Y in a transaction");
        T.Check(await op.KillAsync(yid, ImdbKillKind.Terminate), "KILL terminate: done");
        await Task.Delay(1500); // past the server's lingering close
        var ce = await T.ThrowsAsync<ImdbConnectionClosedException>(() => Q(y, "SELECT 1"), "Y after its terminate");
        T.Check(ce.Reason != null && ce.Reason.Code == 15 && ce.Code == 15, $"the reason: the server's ERROR 15: {ce.Message}");
        T.Check(ce.Message.Contains(ce.Reason!.ServerMessage, StringComparison.Ordinal), "its words");
        T.Check(!y.IsOpen, "Y closed");
        await y.DisposeAsync();
        T.Check((await op.SessionsAsync()).All(s => s.Id != yid), "Y gone from SESSIONS");
        // KILL terminate of Z while its statement runs: the statement ends, then ERROR 15 and the close (§4)
        var z = await Open(via);
        ulong zid = await NewestId(op);
        var zq = Q(z, LongJoin(via));
        await Task.Delay(300);
        T.Check(await op.KillAsync(zid, ImdbKillKind.Terminate), "KILL terminate of a running session: done");
        var ze = await T.ThrowsAsync<ImdbConnectionClosedException>(() => zq, "Z's statement, its session ended");
        T.Check(ze.Reason?.Code == 15, "the reason: ERROR 15: " + ze.Message);
        await z.DisposeAsync();
        T.Check(!await op.KillAsync(ulong.MaxValue - 1, ImdbKillKind.Terminate), "no such session: false");
        T.Check(!await op.KillAsync(yid, ImdbKillKind.Cancel), "a gone session: false");
    }

    // a frame the server refuses (COPY_DONE with no COPY running): its ERROR 9, then its close; the next call reports
    // that ERROR as the connection's end (the C client's closed_reason)
    private static async Task ClosedReason(string via)
    {
        var c = await Open(via);
        await c.SendRawForTestsAsync(Codec.EncodeEmpty(FrameType.CopyDone));
        await Task.Delay(1500);
        var e = await T.ThrowsAsync<ImdbConnectionClosedException>(() => Q(c, "SELECT 1"), "a send after the server's close");
        T.Check(e.Reason != null && e.Code == (int)ImdbErrorCode.State && e.Message.Contains("COPY data with no COPY running", StringComparison.Ordinal),
                $"the server's ERROR 9 is the reason: {e.Message}");
        await T.ThrowsAsync<ImdbConnectionClosedException>(() => c.PingAsync(), "every later call too");
        await c.DisposeAsync();
        await T.ThrowsAsync<ObjectDisposedException>(() => Q(c, "SELECT 1"), "after DisposeAsync");
    }

    private static async Task Terminate(string via)
    {
        await using var other = await Open(via);
        string t = "te_" + via;
        await Q(other, $"CREATE TABLE {t} (id INT64 PRIMARY KEY)");
        var c = await Open(via);
        await Q(c, "BEGIN");
        await Q(c, $"INSERT INTO {t} VALUES (77)");
        await c.TerminateAsync();
        T.Check(!c.IsOpen, "closed");
        T.Eq(0L, (await Q(other, $"SELECT COUNT(*) FROM {t}")).Rows[0].GetInt64(0), "TERMINATE rolled the transaction back");
        // DisposeAsync with a transaction open: the same
        var d = await Open(via);
        await Q(d, "BEGIN");
        await Q(d, $"INSERT INTO {t} VALUES (78)");
        await d.DisposeAsync();
        await Task.Delay(300);
        T.Eq(0L, (await Q(other, $"SELECT COUNT(*) FROM {t}")).Rows[0].GetInt64(0), "a disposed session's transaction rolled back");
    }

    // the protocol level: two QUERYs and a PING pipelined in one write, the replies read in order
    private static async Task RawPipelining(string via)
    {
        var o = via == "sock" ? Sock(B) : Tcp(B, ImdbTls.FromPin(B.Pin));
        await using var f = await ImdbConnection.ConnectRawAsync(o);
        var both = Codec.EncodeQuery(new[] { ImdbStatement.Of("SELECT $1", 41L) })
            .Concat(Codec.EncodeEmpty(FrameType.Ping))
            .Concat(Codec.EncodeQuery(new[] { ImdbStatement.Of("SELECT $1 + 1", 41L), new ImdbStatement("SELECT 'x'") })).ToArray();
        await f.WriteAsync(both);
        var seq = new StringBuilder();
        var vals = new List<string>();
        ColumnsMessage? cols = null;
        int readies = 0;
        while (readies < 2)
        {
            var fr = await f.ReadFrameAsync(fromServer: true) ?? throw new CheckFailed("closed early");
            var m = Codec.DecodeServerBody(fr.Type, fr.Body, cols);
            if (m is ColumnsMessage cm) cols = cm;
            if (m is RowsMessage rm) vals.AddRange(rm.Rows.Select(r => r[0].ToString()));
            if (m is ReadyMessage) readies++;
            seq.Append(m.Type switch
            {
                FrameType.Columns => 'C', FrameType.Rows => 'R', FrameType.Done => 'D', FrameType.Ready => 'Y', FrameType.Pong => 'P', _ => '?',
            });
        }
        T.Check(seq.ToString() is "CRDYPCRDCRDY" or "PCRDYCRDCRDY" or "CRDPYCRDCRDY" or "CRPDYCRDCRDY" or "CPRDYCRDCRDY",
                "the replies in order, the PONG out of turn: " + seq);
        T.Eq("41,42,x", string.Join(",", vals), "the values");
        await f.WriteAsync(Codec.EncodeEmpty(FrameType.Terminate));
        T.Check(await f.ReadFrameAsync(fromServer: true) == null, "TERMINATE: the server closes");
    }

    // many tasks on one connection: their requests serialized, each its own answer; PINGs and a SESSIONS among them
    private static async Task Concurrent(string via)
    {
        await using var c = await Open(via);
        var qs = Enumerable.Range(0, 64).Select(i => c.QueryAsync("SELECT $1 * 2, $2", (long)i, "s" + i)).ToArray();
        var ps = Enumerable.Range(0, 16).Select(_ => c.PingAsync()).ToArray();
        var ss = c.SessionsAsync();
        var rs = await Task.WhenAll(qs);
        await Task.WhenAll(ps);
        T.Check((await ss).Count >= 1, "SESSIONS among them");
        for (int i = 0; i < rs.Length; i++)
            T.Check(rs[i].Rows[0].GetInt64(0) == 2L * i && rs[i].Rows[0].GetString(1) == "s" + i, $"caller {i} its own answer");
        T.Eq(ImdbTransactionState.Idle, c.TransactionState, "idle");
    }

    // ======================= after `cert --renew` and a restart =======================

    private static async Task PinSurvivesRenew()
    {
        string before = File.ReadAllText(Path.Combine(Env("IMDB_DRV_RUN"), "b-cert-before.sha256")).Trim();
        await using var c = await ImdbConnection.ConnectAsync(Tcp(B, ImdbTls.FromPin(B.Pin)));
        T.Eq(1L, (await Q(c, "SELECT 1")).Rows[0].GetInt64(0), "the old pin logs in to the renewed certificate");
        string after = Convert.ToHexString(c.ServerCertificateSha256!);
        T.Check(after != before, "the certificate itself changed (a pin of its hash would now fail; the SPKI pin holds)");
        T.Bytes(SHA256.HashData(CertDer(B.Sdir)), c.ServerCertificateSha256, "the binding follows the new certificate");
        await using var c2 = await ImdbConnection.ConnectAsync(Tcp(B, ImdbTls.FromCaFile(B.Ca)));
        T.Check(c2.IsOpen, "and the CA still verifies it");
    }
}
