using System;
using System.Collections.Generic;

namespace Imagedb.Client.Wire;

/// <summary>A frame's body decoded (either direction: the server's replies, and the client's requests for tools and
/// tests that read them).</summary>
public abstract class WireMessage
{
    protected WireMessage(FrameType type) => Type = type;
    public FrameType Type { get; }
}

// ---- the server's frames ----

/// <summary>COLUMNS: the statement's result columns (1 to 256).</summary>
public sealed class ColumnsMessage : WireMessage
{
    public ColumnsMessage(IReadOnlyList<ImdbColumn> columns) : base(FrameType.Columns) => Columns = columns;
    public IReadOnlyList<ImdbColumn> Columns { get; }
}

/// <summary>ROWS: whole rows, each value held to its column (decoded against the COLUMNS before it).</summary>
public sealed class RowsMessage : WireMessage
{
    public RowsMessage(ImdbValue[][] rows) : base(FrameType.Rows) => Rows = rows;
    public ImdbValue[][] Rows { get; }
}

/// <summary>DONE: the statement's status, its count (the rows returned or written), its read point and its own commit.</summary>
public sealed class DoneMessage : WireMessage
{
    public DoneMessage(string status, ulong count, ImdbReadPoint? read, ImdbWriteCommit? write) : base(FrameType.Done)
    {
        Status = status;
        Count = count;
        Read = read;
        Write = write;
    }

    public string Status { get; }
    public ulong Count { get; }
    public ImdbReadPoint? Read { get; }
    public ImdbWriteCommit? Write { get; }
}

/// <summary>ERROR: the engine's code (1 or more), the failed statement's (or set's) index in its batch, its message.</summary>
public sealed class ErrorMessage : WireMessage
{
    public ErrorMessage(uint code, uint index, string message) : base(FrameType.Error)
    {
        Code = code;
        Index = index;
        Message = message;
    }

    public uint Code { get; }
    public uint Index { get; }
    public string Message { get; }
}

/// <summary>A message alone: WARNING (the server's), COPY_FAIL (the client's).</summary>
public sealed class TextMessage : WireMessage
{
    public TextMessage(FrameType type, string text) : base(type) => Text = text;
    public string Text { get; }
}

/// <summary>A frame of raw bytes: COPY_OUT (the server's), COPY_DATA (the client's); at least one byte.</summary>
public sealed class DataMessage : WireMessage
{
    public DataMessage(FrameType type, byte[] data) : base(type) => Data = data;
    public byte[] Data { get; }
}

/// <summary>A frame with no body: COPY_IN, PONG; COPY_DONE, CANCEL, PING, TERMINATE, SESSIONS.</summary>
public sealed class EmptyMessage : WireMessage
{
    public EmptyMessage(FrameType type) : base(type) { }
}

/// <summary>READY: the request ended; the session's transaction state.</summary>
public sealed class ReadyMessage : WireMessage
{
    public ReadyMessage(ImdbTransactionState state) : base(FrameType.Ready) => State = state;
    public ImdbTransactionState State { get; }
}

/// <summary>SESSIONS_LIST: the sessions this login may see (ids strictly increasing).</summary>
public sealed class SessionsListMessage : WireMessage
{
    public SessionsListMessage(IReadOnlyList<ImdbSession> sessions) : base(FrameType.SessionsList) => Sessions = sessions;
    public IReadOnlyList<ImdbSession> Sessions { get; }
}

/// <summary>KILL_DONE: 0 done, 1 no such session (as SESSIONS shows it), and the KILL's session id.</summary>
public sealed class KillDoneMessage : WireMessage
{
    public KillDoneMessage(byte code, ulong sessionId) : base(FrameType.KillDone)
    {
        Code = code;
        SessionId = sessionId;
    }

    public byte Code { get; }
    public ulong SessionId { get; }
}

// ---- the client's frames ----

/// <summary>A statement of a QUERY: its text and its $1 to $k.</summary>
public sealed record ImdbStatement(string Sql, IReadOnlyList<ImdbValue> Parameters)
{
    public ImdbStatement(string sql) : this(sql, Array.Empty<ImdbValue>()) { }

    /// <summary>A statement whose parameters are CLR values (<see cref="ImdbValue.FromObject"/>).</summary>
    public static ImdbStatement Of(string sql, params object?[] args)
    {
        var v = new ImdbValue[args.Length];
        for (int i = 0; i < args.Length; i++) v[i] = ImdbValue.FromObject(args[i]);
        return new ImdbStatement(sql, v);
    }
}

/// <summary>QUERY: 1 to 4,096 statements.</summary>
public sealed class QueryMessage : WireMessage
{
    public QueryMessage(IReadOnlyList<ImdbStatement> statements) : base(FrameType.Query) => Statements = statements;
    public IReadOnlyList<ImdbStatement> Statements { get; }
}

/// <summary>PREPARE (name and statement), EXECUTE (name and its sets), DEALLOCATE (name).</summary>
public sealed class PreparedMessage : WireMessage
{
    public PreparedMessage(FrameType type, string name, string? sql = null, int valuesPerSet = 0,
                           IReadOnlyList<ImdbValue[]>? sets = null) : base(type)
    {
        Name = name;
        Sql = sql;
        ValuesPerSet = valuesPerSet;
        Sets = sets ?? Array.Empty<ImdbValue[]>();
    }

    public string Name { get; }
    public string? Sql { get; }
    public int ValuesPerSet { get; }
    public IReadOnlyList<ImdbValue[]> Sets { get; }
}

/// <summary>KILL: cancel or terminate a session by its id.</summary>
public sealed class KillMessage : WireMessage
{
    public KillMessage(ImdbKillKind kind, ulong sessionId) : base(FrameType.Kill)
    {
        Kind = kind;
        SessionId = sessionId;
    }

    public ImdbKillKind Kind { get; }
    public ulong SessionId { get; }
}

// ---- before authentication ----

/// <summary>The client hello (112 bytes).</summary>
public sealed record Hello(uint Version, ChannelBindingType Flags, string User, byte[] Nonce);

/// <summary>The server challenge (120 bytes).</summary>
public sealed record Challenge(uint Version, byte[] Salt, uint Iterations, byte[] Nonce);

/// <summary>The server verdict (36 bytes): 0 accepted (its ServerSignature), 1 refused, 2 the binding type refused.</summary>
public sealed record Verdict(uint Code, byte[] Signature);
