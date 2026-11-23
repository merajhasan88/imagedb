using System;
using System.Data.Common;
using Imagedb.Client.Wire;

namespace Imagedb.Client;

/// <summary>Every error the driver raises for the protocol or the server, an ADO.NET <see cref="DbException"/>.
/// <see cref="Code"/> is the engine's code (§4's
/// list: 1 I/O ... 16 a privilege), so a caller can branch on one number whatever side found the error.</summary>
public class ImdbException : DbException
{
    public ImdbException(int code, string message, Exception? inner = null) : base(message, inner) => Code = code;

    /// <summary>ADO.NET: a conflict (14: retry the transaction) is the one error a retry of the same work may cure.</summary>
    public override bool IsTransient => Code == (int)ImdbErrorCode.Conflict;

    /// <summary>ADO.NET: the batch command whose statement failed (set by <see cref="ImdbDbBatch"/>), else null.</summary>
    protected override DbBatchCommand? DbBatchCommand => FailedBatchCommand;

    internal DbBatchCommand? FailedBatchCommand { get; set; }

    /// <summary>The code: the server's for its ERRORs, the driver's own (by the same table) otherwise.</summary>
    public int Code { get; }

    /// <summary>The code as the enum; a code this imagedb does not name casts to an unnamed value. (Not named ErrorCode:
    /// that is ExternalException's HRESULT, which DbException inherits.)</summary>
    public ImdbErrorCode Kind => (ImdbErrorCode)Code;
}

/// <summary>A server ERROR: its code, the index of the statement (or parameter set) that failed in its batch, and the
/// engine's message (never a row value).</summary>
public sealed class ImdbServerException : ImdbException
{
    public ImdbServerException(uint code, uint index, string serverMessage)
        : base(code > int.MaxValue ? int.MaxValue : (int)code, serverMessage)
    {
        ServerCode = code;
        Index = index;
        ServerMessage = serverMessage;
    }

    /// <summary>The code exactly as sent (u32).</summary>
    public uint ServerCode { get; }

    /// <summary>The failed statement's (or parameter set's) index in its batch: 0 to 4,095.</summary>
    public uint Index { get; }

    public string ServerMessage { get; }

    /// <summary>The session's transaction state after the batch (READY), when one came.</summary>
    public ImdbTransactionState? TransactionState { get; internal set; }

    /// <summary>The batch's statements that ran before the failed one (their results stand).</summary>
    public System.Collections.Generic.IReadOnlyList<ImdbResult> CompletedResults { get; internal set; } =
        Array.Empty<ImdbResult>();
}

/// <summary>A frame or a pre-auth message this driver's strict decoder refuses (wire.c's rules), or one that breaks the
/// replies' order: the connection is ended. Its code: 2 damaged bytes, 3 a length past its bound, 12 a later protocol.</summary>
public sealed class ImdbProtocolException : ImdbException
{
    public ImdbProtocolException(ImdbErrorCode code, string message, Exception? inner = null) : base((int)code, message, inner) { }
}

/// <summary>The connection is closed. When the last frame the server sent before its close was an ERROR (a refused
/// login's ERROR 3, a KILL's ERROR 15, a protocol error's ERROR 9), that ERROR is the <see cref="Reason"/> and this
/// exception's code is its code (§4: the C client's closed_reason); else the code is 1 (I/O).</summary>
public sealed class ImdbConnectionClosedException : ImdbException
{
    public ImdbConnectionClosedException(string message, ImdbServerException? reason = null, Exception? inner = null)
        : base(reason?.Code ?? (int)ImdbErrorCode.Io, message, inner ?? reason) => Reason = reason;

    public ImdbServerException? Reason { get; }
}

/// <summary>Why a login failed.</summary>
public enum ImdbAuthFailure
{
    /// <summary>The verdict refused the login: an unknown name and a wrong password alike (no oracle).</summary>
    Refused,
    /// <summary>The verdict's code 2: this server refuses the hello's channel binding type (a default server takes the
    /// TLS exporter alone; .NET's SslStream offers tls-server-end-point). Never retried with another type.</summary>
    BindingRefused,
    /// <summary>The verdict accepted, but its ServerSignature is not the one the password gives: the server did not
    /// prove it holds the verifier.</summary>
    ServerSignatureInvalid,
    /// <summary>The TLS handshake: a certificate that is not the pinned key, not signed by the CA, or not for the name;
    /// not TLS 1.3; not ALPN imdbwir1.</summary>
    Tls,
}

/// <summary>A login refused (code 8, authentication).</summary>
public sealed class ImdbAuthenticationException : ImdbException
{
    public ImdbAuthenticationException(ImdbAuthFailure failure, string message, Exception? inner = null)
        : base((int)ImdbErrorCode.Authentication, message, inner) => Failure = failure;

    public ImdbAuthFailure Failure { get; }
}
