// IMDBWIR1, imagedb's own protocol (docs/n1-design.md §4, §8f): its constants. Every integer on the wire is little-endian.
namespace Imagedb.Client.Wire;

/// <summary>The protocol's fixed numbers (server/wire.h's IMDBW_*).</summary>
public static class Protocol
{
    public const string Magic = "IMDBWIR1";
    public const uint Version = 1;
    public const int UserField = 64;       // a role name's field: UTF-8, 1 to 63 bytes, NUL-padded
    public const int NonceLength = 32;
    public const int SaltField = 64;       // a verifier's salt: 8 to 64 bytes
    public const int KeyLength = 32;
    public const int PreauthHeadLength = 12; // "IMDBWIR1" and u32 its version: every pre-auth message's first bytes
    public const int HelloLength = 112;
    public const int ChallengeLength = 120;
    public const int ProofLength = 32;
    public const int VerdictLength = 36;
    public const int AuthMessageLength = 279; // "IMDBWIR1-SCRAM" | endpoint | hello | challenge | binding[32]
    public const int HeadLength = 5;       // a frame's u32 length (of its type and body) and u8 type
    public const int FrameMax = 16 << 20;  // a frame's type and body: 1 to 16 MiB
    public const int BatchMax = 4096;      // statements in a QUERY, parameter sets in an EXECUTE
    public const int ValuesMax = 256;      // values a statement or a set takes; columns in a result
    public const int NameMax = 63;         // a prepared statement's name
    public const int ColumnNameMax = 70;
    public const int SqlMax = 1 << 22;     // one statement's text: 4 MiB
    public const int ValueMax = 65535;     // a TEXT's or a BYTEA's bytes
    public const int LabelMax = 63;        // an ENUM label's bytes
    public const int LabelsMax = 1024;     // an ENUM's labels
    public const int StatusMax = 511;      // a DONE's status
    public const int MessageMax = 4096;    // an ERROR's or WARNING's text, a COPY_FAIL's reason
    public const int SessionsMax = 65536;
    public const uint IterationsMin = 1000;
    public const uint IterationsMax = 1000000;
    public const int SaltMin = 8;
    public const int PasswordMax = 1024;   // CREATE ROLE's: 1 to 1,024 bytes of printable ASCII
    public const int CopyPiece = 1 << 20;  // the size a client cuts COPY_DATA into (client.c's; §4 says only "at least one")
    public const byte NullTag = 0x80;

    /// <summary>The TLS application protocol (ALPN) the server selects.</summary>
    public const string Alpn = "imdbwir1";

    // 0001-01-01 00:00:00 and 9999-12-31 23:59:59.999999 in microseconds since 1970-01-01 (a TIMESTAMP's range)
    public const long TimestampMin = -62135596800000000L;
    public const long TimestampMax = 253402300799999999L;
    public const int DateMin = -719162;    // 0001-01-01 in days since 1970-01-01
    public const int DateMax = 2932896;    // 9999-12-31
    public const long TimeMax = 86399999999L; // 23:59:59.999999 in microseconds
}

/// <summary>A value's wire type (§4's tags 1 to 13; 0 none: a column the statement does not know, a NULL of no type).</summary>
public enum ImdbType : byte
{
    None = 0,
    Int64 = 1,
    Float64 = 2,
    Bool = 3,
    Text = 4,
    Decimal = 5,
    Timestamp = 6,
    TimestampTz = 7,
    Date = 8,
    Time = 9,
    Uuid = 10,
    Bytea = 11,
    Interval = 12,
    Enum = 13,
}

/// <summary>Frame types: the client's 1 to 12, the server's 64 to 74.</summary>
public enum FrameType : byte
{
    Query = 1,
    Prepare = 2,
    Execute = 3,
    Deallocate = 4,
    CopyData = 5,
    CopyDone = 6,
    CopyFail = 7,
    Cancel = 8,
    Ping = 9,
    Terminate = 10,
    Sessions = 11,
    Kill = 12,
    Columns = 64,
    Rows = 65,
    Done = 66,
    Error = 67,
    Warning = 68,
    CopyIn = 69,
    CopyOut = 70,
    Ready = 71,
    Pong = 72,
    SessionsList = 73,
    KillDone = 74,
}

/// <summary>The hello's flags: its channel binding's type (§8f).</summary>
public enum ChannelBindingType : uint
{
    /// <summary>The Unix-domain socket's: no TLS session, the binding 32 zeros.</summary>
    None = 0,
    /// <summary>RFC 9266's tls-exporter (the server's default). .NET 10's SslStream does not expose it.</summary>
    Exporter = 1,
    /// <summary>RFC 5929's tls-server-end-point: the SHA-256 of the server certificate's DER (a server run with
    /// --channel-binding any takes it).</summary>
    ServerEndPoint = 2,
}

/// <summary>The AuthMessage's endpoint byte.</summary>
public enum ImdbEndpoint : byte
{
    Tcp = 1,
    Socket = 2,
}

/// <summary>READY's state: the session's transaction after a request.</summary>
public enum ImdbTransactionState : byte
{
    Idle = 0,
    InTransaction = 1,
    /// <summary>A doomed transaction (an ALTER, an ERASE, a SERIALIZABLE conflict): it takes only ROLLBACK.</summary>
    Doomed = 2,
}

/// <summary>A session's state in SESSIONS_LIST, at its last request's end.</summary>
public enum ImdbSessionState : byte
{
    Idle = 0,
    Running = 1,
    InTransaction = 2,
    ReceivingCopy = 3,
}

/// <summary>KILL's kind.</summary>
public enum ImdbKillKind : byte
{
    /// <summary>The request the session runs now (or next): each of its statements starting cancelled.</summary>
    Cancel = 1,
    /// <summary>The session ended as a client that leaves, its transaction rolled back.</summary>
    Terminate = 2,
}

/// <summary>An ERROR's code: the engine's (IMDB_ERR_*, its magnitude). A later imagedb may add codes: a code this enum
/// does not name is an error of no class.</summary>
public enum ImdbErrorCode
{
    Io = 1,
    Corrupt = 2,
    Limit = 3,
    Invalid = 4,
    OutOfMemory = 5,
    Constraint = 6,
    Verification = 7,
    Authentication = 8,
    State = 9,
    Syntax = 10,
    NotFound = 11,
    Unsupported = 12,
    HistoryPurged = 13,
    Conflict = 14,
    Cancelled = 15,
    Privilege = 16,
}
