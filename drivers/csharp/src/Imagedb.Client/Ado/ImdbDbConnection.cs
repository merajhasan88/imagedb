using System;
using System.Collections.Generic;
using System.Data;
using System.Data.Common;
using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Threading;
using System.Threading.Tasks;
using Imagedb.Client.Wire;

namespace Imagedb.Client;

/// <summary>ADO.NET's connection string for imagedb. Keys (case-insensitive; synonyms in brackets): Socket, Host
/// [Server], Port, User [Username, User ID, UID], Password [PWD], CA File [CaFile], Pin, Server Name, Connect Timeout
/// (seconds), Reply Timeout (seconds, 0 none), Command Timeout (seconds, 0 none; default 30). A key it does not know is
/// refused (ArgumentException), never ignored: a misspelt "Pin" must not leave a connection unverified. A TCP host takes
/// exactly one of Pin and CA File; the socket takes neither (<see cref="ImdbConnectOptions"/>'s rules).</summary>
public sealed class ImdbDbConnectionStringBuilder : DbConnectionStringBuilder
{
    private static readonly Dictionary<string, string> Canon = new(StringComparer.OrdinalIgnoreCase)
    {
        ["Socket"] = "Socket",
        ["Host"] = "Host",
        ["Server"] = "Host",
        ["Port"] = "Port",
        ["User"] = "User",
        ["Username"] = "User",
        ["User ID"] = "User",
        ["UID"] = "User",
        ["Password"] = "Password",
        ["PWD"] = "Password",
        ["CA File"] = "CA File",
        ["CaFile"] = "CA File",
        ["Pin"] = "Pin",
        ["Server Name"] = "Server Name",
        ["Connect Timeout"] = "Connect Timeout",
        ["Reply Timeout"] = "Reply Timeout",
        ["Command Timeout"] = "Command Timeout",
    };

    public ImdbDbConnectionStringBuilder() { }

    public ImdbDbConnectionStringBuilder(string? connectionString) => ConnectionString = connectionString ?? "";

    /// <summary>The canonical name of a key, or ArgumentException naming it.</summary>
    private static string Key(string keyword)
    {
        ArgumentNullException.ThrowIfNull(keyword);
        return Canon.TryGetValue(keyword.Trim(), out var k) ? k
            : throw new ArgumentException($"imagedb's connection string has no key \"{keyword}\" (Socket, Host, Port, User, Password, " +
                                          "CA File, Pin, Server Name, Connect Timeout, Reply Timeout, Command Timeout)", nameof(keyword));
    }

    [AllowNull]
    public override object this[string keyword]
    {
        get => base[Key(keyword)];
        set
        {
            string k = Key(keyword);
            if (value == null) Remove(k);
            else base[k] = Convert.ToString(value, CultureInfo.InvariantCulture)!;
        }
    }

    public override bool ContainsKey(string keyword) => Canon.TryGetValue(keyword, out var k) && base.ContainsKey(k);

    public override bool Remove(string keyword) => Canon.TryGetValue(keyword, out var k) && base.Remove(k);

    public override bool TryGetValue(string keyword, [NotNullWhen(true)] out object? value)
    {
        value = null;
        return Canon.TryGetValue(keyword, out var k) && base.TryGetValue(k, out value);
    }

    private string? Get(string k) => base.TryGetValue(k, out var v) ? (string)v : null;

    private void Set(string k, object? v) => this[k] = v!;

    public string? Socket { get => Get("Socket"); set => Set("Socket", value); }
    public string? Host { get => Get("Host"); set => Set("Host", value); }
    public int Port { get => Int("Port", 0); set => Set("Port", value); }
    public string? User { get => Get("User"); set => Set("User", value); }
    public string? Password { get => Get("Password"); set => Set("Password", value); }
    public string? CaFile { get => Get("CA File"); set => Set("CA File", value); }
    public string? Pin { get => Get("Pin"); set => Set("Pin", value); }
    public string? ServerName { get => Get("Server Name"); set => Set("Server Name", value); }
    public int ConnectTimeout { get => Int("Connect Timeout", 30); set => Set("Connect Timeout", value); }
    public int ReplyTimeout { get => Int("Reply Timeout", 0); set => Set("Reply Timeout", value); }
    public int CommandTimeout { get => Int("Command Timeout", 30); set => Set("Command Timeout", value); }

    private int Int(string k, int dflt)
    {
        string? s = Get(k);
        if (s == null) return dflt;
        if (!int.TryParse(s, NumberStyles.None, CultureInfo.InvariantCulture, out int v))
            throw new ArgumentException($"the connection string's {k}: a whole number of 0 or more, not \"{s}\"");
        return v;
    }

    /// <summary>The native options these keys give, checked: a socket or a host, exactly one; a host with exactly one of
    /// Pin and CA File (no unverified mode); the socket with neither.</summary>
    public ImdbConnectOptions ToOptions()
    {
        bool sock = !string.IsNullOrEmpty(Socket), host = !string.IsNullOrEmpty(Host);
        if (sock == host) throw new ArgumentException("the connection string names a Socket or a Host, exactly one");
        bool pin = !string.IsNullOrEmpty(Pin), ca = !string.IsNullOrEmpty(CaFile);
        ImdbTls? tls = null;
        if (host)
        {
            if (pin == ca)
                throw new ArgumentException("a TCP connection is verified by exactly one of Pin (the server key's SPKI SHA-256) and CA File: " +
                                            "there is no unverified mode");
            tls = pin ? ImdbTls.FromPin(Pin!) : ImdbTls.FromCaFile(CaFile!, string.IsNullOrEmpty(ServerName) ? null : ServerName);
        }
        else if (pin || ca || !string.IsNullOrEmpty(ServerName))
            throw new ArgumentException("the Unix-domain socket has no TLS: Pin, CA File and Server Name are for a Host");
        int rt = ReplyTimeout;
        var o = new ImdbConnectOptions
        {
            SocketPath = sock ? Socket : null,
            Host = host ? Host : null,
            Port = host ? Port : 0,
            Tls = tls,
            User = User ?? "",
            Password = Password ?? "",
            ConnectTimeout = TimeSpan.FromSeconds(ConnectTimeout == 0 ? 30 : ConnectTimeout),
            ReplyTimeout = rt == 0 ? null : TimeSpan.FromSeconds(rt),
        };
        o.Validate();
        return o;
    }
}

/// <summary>ADO.NET's connection to imagedb over IMDBWIR1: a <see cref="DbConnection"/> over the native
/// <see cref="ImdbConnection"/> (<see cref="Native"/>: COPY, SESSIONS, KILL, PING, EXECUTE of several parameter sets,
/// pipelining's level). Commands run one at a time on it (the native connection's request lock); a reader holds its
/// results whole (they arrive whole before ExecuteReader returns), so a second command may run while a reader is
/// open. Cancel from any thread: <see cref="ImdbDbCommand.Cancel"/> or the token of an async call.</summary>
public sealed class ImdbDbConnection : DbConnection
{
    private string _cs = "";
    private ImdbDbConnectionStringBuilder _csb = new();
    private ImdbConnection? _native;
    private bool _wasOpened;
    internal ImdbDbTransaction? CurrentTransaction;

    public ImdbDbConnection() { }

    public ImdbDbConnection(string connectionString) => ConnectionString = connectionString;

    [AllowNull]
    public override string ConnectionString
    {
        get => _cs;
        set
        {
            if (_native != null) throw new InvalidOperationException("the connection string of an open connection: close it first");
            var b = new ImdbDbConnectionStringBuilder(value ?? ""); // unknown keys refused here
            _csb = b;
            _cs = value ?? "";
        }
    }

    /// <summary>imagedb has one database a server: "".</summary>
    public override string Database => "";

    /// <summary>The socket's path, or host:port.</summary>
    public override string DataSource =>
        !string.IsNullOrEmpty(_csb.Socket) ? _csb.Socket! : string.Create(CultureInfo.InvariantCulture, $"{_csb.Host}:{_csb.Port}");

    /// <summary>The protocol: IMDBWIR1 (the server reports no version of its own past the hello's).</summary>
    public override string ServerVersion => _native != null ? "IMDBWIR1" : throw new InvalidOperationException("the connection is not open");

    public override int ConnectionTimeout => _csb.ConnectTimeout;

    internal int DefaultCommandTimeout => _csb.CommandTimeout;

    /// <summary>Open, Closed, or Broken once the server ended an open connection (a KILL, a refused frame): Close it.</summary>
    public override ConnectionState State =>
        _native == null ? ConnectionState.Closed : _native.IsOpen ? ConnectionState.Open : ConnectionState.Broken;

    /// <summary>The native connection underneath (open connections only): COPY in and out, SESSIONS and KILL, PING,
    /// EXECUTE of several parameter sets, the transaction state READY last gave.</summary>
    public ImdbConnection Native => _native ?? throw new InvalidOperationException("the connection is not open");

    protected override DbProviderFactory DbProviderFactory => ImdbDbFactory.Instance;

    public override void Open() => OpenAsync(CancellationToken.None).GetAwaiter().GetResult();

    public override async Task OpenAsync(CancellationToken cancellationToken)
    {
        if (_native != null) throw new InvalidOperationException("the connection is already open");
        var o = _csb.ToOptions();
        var old = State;
        _native = await ImdbConnection.ConnectAsync(o, cancellationToken).ConfigureAwait(false);
        _wasOpened = true;
        if (old != ConnectionState.Open) OnStateChange(new StateChangeEventArgs(old, ConnectionState.Open));
    }

    public override void Close() => CloseAsync().GetAwaiter().GetResult();

    /// <summary>TERMINATE when idle (an open transaction rolled back by the server), then the socket closed.</summary>
    public override async Task CloseAsync()
    {
        var n = _native;
        if (n == null) return;
        _native = null;
        CurrentTransaction?.Abandon();
        CurrentTransaction = null;
        await n.DisposeAsync().ConfigureAwait(false);
        if (_wasOpened) OnStateChange(new StateChangeEventArgs(ConnectionState.Open, ConnectionState.Closed));
    }

    public override void ChangeDatabase(string databaseName) =>
        throw new NotSupportedException("imagedb has one database a server: connect to another server's socket or port");

    protected override DbTransaction BeginDbTransaction(IsolationLevel isolationLevel) =>
        BeginDbTransactionAsync(isolationLevel, CancellationToken.None).AsTask().GetAwaiter().GetResult();

    /// <summary>BEGIN, with the level named: Unspecified the session's default (BEGIN alone); ReadCommitted and
    /// ReadUncommitted READ COMMITTED (imagedb shows no uncommitted data); RepeatableRead and Snapshot snapshot
    /// isolation; Serializable SERIALIZABLE. Chaos is refused. One transaction at a time on a connection.</summary>
    protected override async ValueTask<DbTransaction> BeginDbTransactionAsync(IsolationLevel isolationLevel, CancellationToken cancellationToken)
    {
        string sql = isolationLevel switch
        {
            IsolationLevel.Unspecified => "BEGIN",
            IsolationLevel.ReadUncommitted => "BEGIN ISOLATION LEVEL READ UNCOMMITTED",
            IsolationLevel.ReadCommitted => "BEGIN ISOLATION LEVEL READ COMMITTED",
            IsolationLevel.RepeatableRead => "BEGIN ISOLATION LEVEL REPEATABLE READ",
            IsolationLevel.Snapshot => "BEGIN ISOLATION LEVEL SNAPSHOT",
            IsolationLevel.Serializable => "BEGIN ISOLATION LEVEL SERIALIZABLE",
            _ => throw new ArgumentException($"imagedb has no isolation level {isolationLevel}", nameof(isolationLevel)),
        };
        var n = Native;
        if (CurrentTransaction != null) throw new InvalidOperationException("a transaction is already open on this connection");
        await n.QueryAsync(sql, Array.Empty<object?>(), cancellationToken).ConfigureAwait(false);
        var t = new ImdbDbTransaction(this, isolationLevel);
        CurrentTransaction = t;
        return t;
    }

    protected override DbCommand CreateDbCommand() => new ImdbDbCommand { Connection = this };

    public new ImdbDbCommand CreateCommand() => (ImdbDbCommand)CreateDbCommand();

    public override bool CanCreateBatch => true;

    protected override DbBatch CreateDbBatch() => new ImdbDbBatch { Connection = this };

    public new ImdbDbBatch CreateBatch() => (ImdbDbBatch)CreateDbBatch();

    protected override void Dispose(bool disposing)
    {
        if (disposing) Close();
        base.Dispose(disposing);
    }

    public override async ValueTask DisposeAsync()
    {
        await CloseAsync().ConfigureAwait(false);
        GC.SuppressFinalize(this);
    }
}

/// <summary>ADO.NET's transaction: BEGIN at its start, COMMIT or ROLLBACK at its end; disposed while still open, it
/// is rolled back. A failed statement inside is undone alone (statement-level rollback); a transaction READY reports
/// doomed takes ROLLBACK alone (the engine's answer to COMMIT says so).</summary>
public sealed class ImdbDbTransaction : DbTransaction
{
    private ImdbDbConnection? _conn;

    internal ImdbDbTransaction(ImdbDbConnection conn, IsolationLevel level)
    {
        _conn = conn;
        IsolationLevel = level;
    }

    public override IsolationLevel IsolationLevel { get; }

    protected override DbConnection? DbConnection => _conn;

    /// <summary>True once COMMIT or ROLLBACK ran (or the connection closed under it).</summary>
    public bool IsCompleted => _conn == null;

    internal void Abandon() => _conn = null;

    private ImdbDbConnection Live() => _conn ?? throw new InvalidOperationException("the transaction has ended (committed, rolled back or its connection closed)");

    public override void Commit() => CommitAsync(CancellationToken.None).GetAwaiter().GetResult();

    public override void Rollback() => RollbackAsync(CancellationToken.None).GetAwaiter().GetResult();

    public override Task CommitAsync(CancellationToken cancellationToken = default) => EndAsync("COMMIT", cancellationToken);

    public override Task RollbackAsync(CancellationToken cancellationToken = default) => EndAsync("ROLLBACK", cancellationToken);

    private async Task EndAsync(string sql, CancellationToken ct)
    {
        var c = Live();
        try
        {
            await c.Native.QueryAsync(sql, Array.Empty<object?>(), ct).ConfigureAwait(false);
        }
        finally
        {
            // ended whatever the answer, unless the session is still in it (a COMMIT refused before it ran)
            if (c.State != ConnectionState.Open || c.Native.TransactionState == ImdbTransactionState.Idle)
            {
                _conn = null;
                if (c.CurrentTransaction == this) c.CurrentTransaction = null;
            }
        }
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing && _conn != null)
        {
            try
            {
                if (_conn.State == ConnectionState.Open) Rollback();
            }
            catch (ImdbException)
            {
                // a broken connection: the server rolls the transaction back at its close
            }
            if (_conn != null && _conn.CurrentTransaction == this) _conn.CurrentTransaction = null;
            _conn = null;
        }
        base.Dispose(disposing);
    }

    public override async ValueTask DisposeAsync()
    {
        if (_conn != null)
        {
            try
            {
                if (_conn.State == ConnectionState.Open) await RollbackAsync().ConfigureAwait(false);
            }
            catch (ImdbException)
            {
            }
            if (_conn != null && _conn.CurrentTransaction == this) _conn.CurrentTransaction = null;
            _conn = null;
        }
        GC.SuppressFinalize(this);
    }
}

/// <summary>ADO.NET's factory (DbProviderFactories.RegisterFactory("Imagedb.Client", ImdbDbFactory.Instance)).</summary>
public sealed class ImdbDbFactory : DbProviderFactory
{
    public static readonly ImdbDbFactory Instance = new();

    private ImdbDbFactory() { }

    public override DbConnection CreateConnection() => new ImdbDbConnection();
    public override DbCommand CreateCommand() => new ImdbDbCommand();
    public override DbParameter CreateParameter() => new ImdbDbParameter();
    public override DbConnectionStringBuilder CreateConnectionStringBuilder() => new ImdbDbConnectionStringBuilder();
    public override bool CanCreateBatch => true;
    public override DbBatch CreateBatch() => new ImdbDbBatch();
    public override DbBatchCommand CreateBatchCommand() => new ImdbDbBatchCommand();
    public override DbDataSource CreateDataSource(string connectionString) => new ImdbDbDataSource(connectionString);
}

/// <summary>ADO.NET's data source (.NET 7's entry point): a connection string checked once, connections made from it.
/// Its commands (CreateCommand) open a connection for each execution and close it after, as DbDataSource's own do.</summary>
public sealed class ImdbDbDataSource : DbDataSource
{
    private readonly string _cs;

    /// <summary>The string is checked here (its keys, a socket or a host, the host's one verification).</summary>
    public ImdbDbDataSource(string connectionString)
    {
        _ = new ImdbDbConnectionStringBuilder(connectionString).ToOptions();
        _cs = connectionString;
    }

    public override string ConnectionString => _cs;

    protected override DbConnection CreateDbConnection() => new ImdbDbConnection(_cs);

    public new ImdbDbConnection OpenConnection() => (ImdbDbConnection)base.OpenConnection();
}
