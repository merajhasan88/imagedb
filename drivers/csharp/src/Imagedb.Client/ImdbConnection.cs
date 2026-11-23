using System;
using System.Buffers;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;
using Imagedb.Client.Wire;

namespace Imagedb.Client;

/// <summary>An authenticated IMDBWIR1 connection (docs/n1-design.md §4): the native async client.
/// <para>One background task reads the server's frames for the connection's whole life: the answers out of turn (PONG,
/// SESSIONS_LIST, KILL_DONE) go to their callers in the order asked; every other frame belongs to the one request in
/// flight. Requests run one at a time (QueryAsync, ExecuteBatchAsync, PrepareAsync, ExecuteAsync, DeallocateAsync,
/// CopyInAsync, CopyOutAsync, SessionsAsync, KillAsync): a second caller waits, so nothing is ever pipelined behind a
/// COPY ... FROM STDIN (which would be read as its data). PingAsync and <see cref="Cancel"/> may be called at any time
/// from any thread. Pipelining is the protocol level's (<see cref="ConnectRawAsync"/>).</para>
/// <para>Channel binding: .NET 10's SslStream exposes no TLS exporter (RFC 9266), so a TCP login binds by
/// tls-server-end-point (the SHA-256 of the server certificate's DER), which a server takes only when run with
/// --channel-binding any; a default server answers verdict 2 (<see cref="ImdbAuthFailure.BindingRefused"/>), and the
/// driver never retries with another type.</para></summary>
public sealed class ImdbConnection : IAsyncDisposable
{
    private const int CopyOutInMemoryMax = 256 << 20;
    private static readonly byte[] CancelFrame = Codec.EncodeEmpty(FrameType.Cancel);
    private static readonly byte[] PingFrame = Codec.EncodeEmpty(FrameType.Ping);
    private static readonly byte[] SessionsFrame = Codec.EncodeEmpty(FrameType.Sessions);
    private static readonly byte[] TerminateFrame = Codec.EncodeEmpty(FrameType.Terminate);
    private static readonly byte[] CopyDoneFrame = Codec.EncodeEmpty(FrameType.CopyDone);

    private readonly ImdbFrameStream _frames;
    private readonly SemaphoreSlim _writeLock = new(1, 1);
    private readonly SemaphoreSlim _requestLock = new(1, 1);
    private readonly Channel<WireMessage> _inTurn = Channel.CreateBounded<WireMessage>(
        new BoundedChannelOptions(64) { SingleReader = true, SingleWriter = true, FullMode = BoundedChannelFullMode.Wait });
    private readonly ConcurrentQueue<OotWaiter> _oot = new();
    private readonly TimeSpan? _replyTimeout;
    private long _sent;      // in-turn requests written: request n is the nth
    private long _ready;     // READYs read: request n is outstanding while _ready < n
    private long _cancelFor; // a cancel asked for request n and not yet written (0: none)
    private Task _reader = Task.CompletedTask;
    private Exception? _failure;
    private int _disposed;
    private int _state;

    private sealed class OotWaiter
    {
        public OotWaiter(FrameType want) => Want = want;
        public FrameType Want { get; }
        public TaskCompletionSource<WireMessage> Tcs { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
    }

    private sealed class RequestState
    {
        public long Seq;
        public volatile bool TokenCancelled;
    }

    private ImdbConnection(Stream stream, ImdbEndpoint endpoint, ChannelBindingType binding, byte[]? certHash, TimeSpan? replyTimeout)
    {
        _frames = new ImdbFrameStream(stream);
        Endpoint = endpoint;
        ChannelBinding = binding;
        ServerCertificateSha256 = certHash;
        _replyTimeout = replyTimeout;
    }

    /// <summary>The endpoint: the Unix-domain socket or TCP with TLS 1.3.</summary>
    public ImdbEndpoint Endpoint { get; }

    /// <summary>The login's channel binding: None on the socket, ServerEndPoint on TCP (see the class's remarks).</summary>
    public ChannelBindingType ChannelBinding { get; }

    /// <summary>On TCP, the SHA-256 of the server certificate's DER: the tls-server-end-point value the login bound.</summary>
    public byte[]? ServerCertificateSha256 { get; }

    /// <summary>The session's transaction state at its last READY.</summary>
    public ImdbTransactionState TransactionState => (ImdbTransactionState)Volatile.Read(ref _state);

    /// <summary>False once the connection ended (the server closed it, a frame was refused, it was disposed).</summary>
    public bool IsOpen => Volatile.Read(ref _failure) == null;

    // =============================== connecting ===============================

    /// <summary>Connects, verifies TLS (on TCP) and logs in by SCRAM-SHA-256, the server's signature checked.</summary>
    public static async Task<ImdbConnection> ConnectAsync(ImdbConnectOptions options, CancellationToken ct = default)
    {
        var (stream, ep, cb, hash) = await OpenAsync(options, ct).ConfigureAwait(false);
        var c = new ImdbConnection(stream, ep, cb, hash, options.ReplyTimeout);
        c._reader = Task.Run(c.ReadLoopAsync, CancellationToken.None);
        return c;
    }

    /// <summary>The protocol's level: an authenticated connection's frames, for a caller that writes requests and reads
    /// replies itself (pipelining included; its CANCEL and COPY rules are the caller's to keep, §4).</summary>
    public static async Task<ImdbFrameStream> ConnectRawAsync(ImdbConnectOptions options, CancellationToken ct = default)
    {
        var (stream, _, _, _) = await OpenAsync(options, ct).ConfigureAwait(false);
        return new ImdbFrameStream(stream);
    }

    private static async Task<(Stream, ImdbEndpoint, ChannelBindingType, byte[]?)> OpenAsync(ImdbConnectOptions o, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(o);
        o.Validate();
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(o.ConnectTimeout);
        Socket? sock = null;
        Stream? stream = null;
        try
        {
            ImdbEndpoint ep;
            ChannelBindingType cb;
            byte[] binding;
            byte[]? hash = null;
            if (o.SocketPath != null)
            {
                sock = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
                await sock.ConnectAsync(new UnixDomainSocketEndPoint(o.SocketPath), cts.Token).ConfigureAwait(false);
                stream = new NetworkStream(sock, ownsSocket: true);
                ep = ImdbEndpoint.Socket;
                cb = ChannelBindingType.None;
                binding = new byte[Protocol.KeyLength];
            }
            else
            {
                sock = new Socket(SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
                sock.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.KeepAlive, true);
                sock.SetSocketOption(SocketOptionLevel.Tcp, SocketOptionName.TcpKeepAliveTime, 60);
                sock.SetSocketOption(SocketOptionLevel.Tcp, SocketOptionName.TcpKeepAliveInterval, 10);
                sock.SetSocketOption(SocketOptionLevel.Tcp, SocketOptionName.TcpKeepAliveRetryCount, 6);
                await sock.ConnectAsync(o.Host!, o.Port, cts.Token).ConfigureAwait(false);
                var ns = new NetworkStream(sock, ownsSocket: true);
                stream = ns;
                var (ssl, h) = await TlsAsync(ns, o.Host!, o.Tls!, cts.Token).ConfigureAwait(false);
                stream = ssl;
                ep = ImdbEndpoint.Tcp;
                cb = ChannelBindingType.ServerEndPoint;
                binding = h;
                hash = (byte[])h.Clone();
            }
            await LoginAsync(stream, ep, cb, binding, o.User, o.Password, cts.Token).ConfigureAwait(false);
            return (stream, ep, cb, hash);
        }
        catch (Exception e)
        {
            if (stream != null) await stream.DisposeAsync().ConfigureAwait(false);
            else sock?.Dispose();
            if (e is OperationCanceledException && !ct.IsCancellationRequested)
                throw new ImdbException((int)ImdbErrorCode.Io, $"connect: no login within {o.ConnectTimeout.TotalMilliseconds:0} ms", e);
            if (e is SocketException se)
                throw new ImdbException((int)ImdbErrorCode.Io, "connect: " + se.Message, se);
            if (e is IOException io)
                throw new ImdbConnectionClosedException("the connection: " + io.Message, null, io);
            throw;
        }
    }

    // RFC 5929's rule takes MD5 and SHA-1 to SHA-256; a certificate signed with another hash would need that hash, which
    // IMDBWIR1's 32-byte binding does not carry (a server allowing tls-server-end-point refuses one at its start)
    private static readonly HashSet<string> Sha256Signatures = new(StringComparer.Ordinal)
    {
        "1.2.840.10045.4.3.2",    // ecdsa-with-SHA256 (imagedb-server cert's)
        "1.2.840.113549.1.1.11",  // sha256WithRSAEncryption
        "2.16.840.1.101.3.4.3.2", // dsa-with-sha256
        "1.2.840.113549.1.1.4",   // md5WithRSAEncryption: SHA-256 by RFC 5929
        "1.2.840.113549.1.1.5",   // sha1WithRSAEncryption: SHA-256 by RFC 5929
        "1.2.840.10045.4.1",      // ecdsa-with-SHA1: SHA-256 by RFC 5929
        "1.2.840.10040.4.3",      // dsa-with-sha1: SHA-256 by RFC 5929
    };

    /// <summary>TLS 1.3, ALPN imdbwir1, the server verified by its pin or the CA (and its name); returns the session and
    /// the tls-server-end-point value (SHA-256 of the certificate's DER), both before any byte of the hello leaves.</summary>
    private static async Task<(SslStream, byte[])> TlsAsync(Stream inner, string host, ImdbTls tls, CancellationToken ct)
    {
        var ssl = new SslStream(inner, leaveInnerStreamOpen: false);
        string target = tls.ServerName ?? host;
        string? why = null;
        var opt = new SslClientAuthenticationOptions
        {
            TargetHost = target,
            EnabledSslProtocols = SslProtocols.Tls13,
            ApplicationProtocols = new List<SslApplicationProtocol> { new(Protocol.Alpn) },
            AllowTlsResume = false,
            CertificateRevocationCheckMode = X509RevocationMode.NoCheck,
        };
        if (tls.Pin is { } pin)
        {
            // pinned: the chain is not asked for; the key is (the SPKI's SHA-256, constant time)
            opt.RemoteCertificateValidationCallback = (_, cert, _, _) =>
            {
                if (cert == null)
                {
                    why = "the server sent no certificate";
                    return false;
                }
                byte[] spki;
                if (cert is X509Certificate2 x2) spki = x2.PublicKey.ExportSubjectPublicKeyInfo();
                else
                {
                    using var loaded = X509CertificateLoader.LoadCertificate(cert.GetRawCertData());
                    spki = loaded.PublicKey.ExportSubjectPublicKeyInfo();
                }
                var got = SHA256.HashData(spki);
                bool ok = CryptographicOperations.FixedTimeEquals(got, pin);
                if (!ok) why = "the server's key is not the pinned one";
                return ok;
            };
        }
        else
        {
            var pol = new X509ChainPolicy
            {
                TrustMode = X509ChainTrustMode.CustomRootTrust,
                RevocationMode = X509RevocationMode.NoCheck, // the policy's default is Online: a private CA has no responder
            };
            pol.CustomTrustStore.Add(tls.Ca!);
            opt.CertificateChainPolicy = pol;
            opt.RemoteCertificateValidationCallback = (_, _, _, errors) =>
            {
                if (errors == SslPolicyErrors.None) return true;
                why = (errors & SslPolicyErrors.RemoteCertificateNotAvailable) != 0 ? "the server sent no certificate"
                    : (errors & SslPolicyErrors.RemoteCertificateNameMismatch) != 0 ? $"the server's certificate is not for {target} (subjectAltName)"
                    : "the server's certificate is not signed by the CA given, or is not valid now";
                return false;
            };
        }
        try
        {
            await ssl.AuthenticateAsClientAsync(opt, ct).ConfigureAwait(false);
        }
        catch (AuthenticationException e)
        {
            await ssl.DisposeAsync().ConfigureAwait(false);
            throw new ImdbAuthenticationException(ImdbAuthFailure.Tls, "TLS: " + (why ?? e.Message), e);
        }
        catch (IOException e) when (why != null)
        {
            await ssl.DisposeAsync().ConfigureAwait(false);
            throw new ImdbAuthenticationException(ImdbAuthFailure.Tls, "TLS: " + why, e);
        }
        catch (CryptographicException e)
        {
            // .NET 10 on OpenSSL 3: a chain against a CA that did not sign the certificate may fail inside the chain's
            // build (an OpenSSL code its mapping does not know, e.g. 30, the key identifiers' mismatch) before any callback
            await ssl.DisposeAsync().ConfigureAwait(false);
            throw new ImdbAuthenticationException(ImdbAuthFailure.Tls,
                "TLS: the server's certificate is not signed by the CA given (its chain could not be built: " + e.Message + ")", e);
        }
        try
        {
            if (ssl.SslProtocol != SslProtocols.Tls13)
                throw new ImdbAuthenticationException(ImdbAuthFailure.Tls, "TLS: not 1.3");
            if (ssl.NegotiatedApplicationProtocol != new SslApplicationProtocol(Protocol.Alpn))
                throw new ImdbAuthenticationException(ImdbAuthFailure.Tls, "TLS: the peer does not speak imdbwir1 (ALPN)");
            var rc = ssl.RemoteCertificate ?? throw new ImdbAuthenticationException(ImdbAuthFailure.Tls, "TLS: the server sent no certificate");
            byte[] der = rc.GetRawCertData();
            using var x = X509CertificateLoader.LoadCertificate(der);
            string oid = x.SignatureAlgorithm.Value ?? "";
            if (!Sha256Signatures.Contains(oid))
                throw new ImdbAuthenticationException(ImdbAuthFailure.Tls,
                    $"TLS: the server's certificate is signed with {oid}: tls-server-end-point would hash it with another hash than SHA-256, which IMDBWIR1's binding does not carry");
            return (ssl, SHA256.HashData(der));
        }
        catch
        {
            await ssl.DisposeAsync().ConfigureAwait(false);
            throw;
        }
    }

    /// <summary>The pre-auth exchange (§4): the hello, the challenge, the proof over the AuthMessage, the verdict and the
    /// server's signature.</summary>
    private static async Task LoginAsync(Stream s, ImdbEndpoint ep, ChannelBindingType cb, byte[] binding, string user, string password,
                                         CancellationToken ct)
    {
        var nonce = RandomNumberGenerator.GetBytes(Protocol.NonceLength);
        var hello = Codec.EncodeHello(cb, user, nonce);
        byte[] pw = System.Text.Encoding.ASCII.GetBytes(password);
        byte[]? proof = null, want = null;
        try
        {
            await s.WriteAsync(hello, ct).ConfigureAwait(false);
            await s.FlushAsync(ct).ConfigureAwait(false);
            var ch = new byte[Protocol.ChallengeLength];
            await ReadPreauthAsync(s, ch.AsMemory(0, Protocol.PreauthHeadLength), ct).ConfigureAwait(false);
            uint version = Codec.DecodePreauthHead(ch);
            if (version != Protocol.Version)
                throw Codec.Unsupported($"the server speaks IMDBWIR1 version {version}, not 1");
            await ReadPreauthAsync(s, ch.AsMemory(Protocol.PreauthHeadLength), ct).ConfigureAwait(false);
            var c = Codec.DecodeChallenge(ch);
            var am = Codec.AuthMessage(ep, hello, ch, binding);
            (proof, want) = Codec.ScramClient(pw, c, am);
            await s.WriteAsync(proof, ct).ConfigureAwait(false);
            await s.FlushAsync(ct).ConfigureAwait(false);
            var vb = new byte[Protocol.VerdictLength];
            await ReadPreauthAsync(s, vb, ct).ConfigureAwait(false);
            var v = Codec.DecodeVerdict(vb);
            if (v.Code == 2) // never retried with another type: no downgrade (§8f)
                throw new ImdbAuthenticationException(ImdbAuthFailure.BindingRefused,
                    $"the server refuses this login's channel binding type ({cb}): a default server takes the TLS exporter alone, which .NET's SslStream does not expose; the server must run with --channel-binding any");
            if (v.Code != 0) throw new ImdbAuthenticationException(ImdbAuthFailure.Refused, "authentication refused");
            if (!CryptographicOperations.FixedTimeEquals(v.Signature, want))
                throw new ImdbAuthenticationException(ImdbAuthFailure.ServerSignatureInvalid, "the server did not prove it holds the verifier");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(pw);
            if (proof != null) CryptographicOperations.ZeroMemory(proof);
            if (want != null) CryptographicOperations.ZeroMemory(want);
        }
    }

    private static async Task ReadPreauthAsync(Stream s, Memory<byte> into, CancellationToken ct)
    {
        try
        {
            await s.ReadExactlyAsync(into, ct).ConfigureAwait(false);
        }
        catch (EndOfStreamException e)
        {
            throw new ImdbConnectionClosedException("the connection: closed by the server during the login", null, e);
        }
    }

    // =============================== the reader ===============================

    private async Task ReadLoopAsync()
    {
        ColumnsMessage? cols = null;
        ErrorMessage? lastError = null; // the last frame read, when it was an ERROR: a close's reason
        Exception end;
        try
        {
            while (true)
            {
                var f = await _frames.ReadFrameAsync(fromServer: true).ConfigureAwait(false);
                if (f == null)
                {
                    end = Closed(lastError, null);
                    break;
                }
                WireMessage m;
                try
                {
                    m = Codec.DecodeServerBody(f.Value.Type, f.Value.Body, cols);
                }
                catch (ImdbProtocolException e)
                {
                    end = new ImdbProtocolException((ImdbErrorCode)e.Code, $"a {f.Value.Type} frame refused, the connection closed: {e.Message}", e);
                    break;
                }
                lastError = m as ErrorMessage;
                if (m is ColumnsMessage c) cols = c; // ROWS are read against the last COLUMNS (client.c's rule)
                if (m.Type is FrameType.Pong or FrameType.SessionsList or FrameType.KillDone)
                {
                    if (!_oot.TryDequeue(out var w) || w.Want != m.Type)
                    {
                        end = Codec.Corrupt($"a {m.Type} no request of this connection asked for");
                        break;
                    }
                    w.Tcs.TrySetResult(m);
                    continue;
                }
                if (Interlocked.Read(ref _ready) >= Interlocked.Read(ref _sent))
                {
                    if (m is ErrorMessage) continue; // unasked (a refused login's ERROR 3, a KILL's ERROR 15): the reason if the close follows
                    end = Codec.Corrupt($"a {m.Type} with no request outstanding");
                    break;
                }
                if (m is ReadyMessage rd)
                {
                    Volatile.Write(ref _state, (int)rd.State);
                    Interlocked.Increment(ref _ready);
                }
                await _inTurn.Writer.WriteAsync(m).ConfigureAwait(false);
            }
        }
        catch (ImdbProtocolException e) // a head refused: its length or a type the server does not send
        {
            end = new ImdbProtocolException((ImdbErrorCode)e.Code, "a frame's head refused, the connection closed: " + e.Message, e);
        }
        catch (Exception e)
        {
            // a reset after the server's last ERROR is still that ERROR's close
            end = Volatile.Read(ref _failure)
                  ?? (lastError == null && e is ImdbConnectionClosedException closed ? closed : Closed(lastError, e));
        }
        Fail(end);
    }

    private static ImdbConnectionClosedException Closed(ErrorMessage? lastError, Exception? io)
    {
        if (lastError != null)
            return new ImdbConnectionClosedException("the server closed the connection: " + lastError.Message, ToServerException(lastError), io);
        return new ImdbConnectionClosedException(io == null ? "the connection: closed by the server" : "the connection: " + io.Message, null, io);
    }

    private static ImdbServerException ToServerException(ErrorMessage e) => new(e.Code, e.Index, e.Message);

    private void Fail(Exception e)
    {
        Interlocked.CompareExchange(ref _failure, e, null);
        _inTurn.Writer.TryComplete();
        DrainWaiters();
        try
        {
            _frames.Stream.Dispose();
        }
        catch (Exception)
        {
            // already closed: nothing to release
        }
    }

    private void DrainWaiters()
    {
        while (_oot.TryDequeue(out var w)) w.Tcs.TrySetException(Failure());
    }

    /// <summary>A fresh exception for the connection's end, its first cause inside.</summary>
    private Exception Failure()
    {
        if (Volatile.Read(ref _disposed) != 0 && Volatile.Read(ref _failure) is ObjectDisposedException or null)
            return new ObjectDisposedException(nameof(ImdbConnection));
        return Volatile.Read(ref _failure) switch
        {
            ImdbConnectionClosedException c => new ImdbConnectionClosedException(c.Message, c.Reason, c),
            ImdbProtocolException p => new ImdbProtocolException((ImdbErrorCode)p.Code, p.Message, p),
            ImdbException i => new ImdbException(i.Code, i.Message, i),
            ObjectDisposedException => new ObjectDisposedException(nameof(ImdbConnection)),
            null => new InvalidOperationException("the connection has not ended"),
            var f => new ImdbConnectionClosedException("the connection: " + f.Message, null, f),
        };
    }

    private void ThrowIfEnded()
    {
        if (Volatile.Read(ref _disposed) != 0) throw new ObjectDisposedException(nameof(ImdbConnection));
        if (Volatile.Read(ref _failure) != null) throw Failure();
    }

    private Exception Violation(string what)
    {
        Fail(Codec.Corrupt("replies out of §4's order: " + what));
        return Failure();
    }

    // =============================== writing ===============================

    /// <summary>A frame under the write lock: a cancel asked for a request still outstanding goes out first (§4: before
    /// the next frame, a COPY's data included); a stale one is dropped. A write that finds the connection closed reports
    /// the server's last ERROR when the close followed one (closed_reason).</summary>
    private async Task WriteFrameAsync(byte[] frame, bool request = false, OotWaiter? oot = null)
    {
        await _writeLock.WaitAsync().ConfigureAwait(false);
        try
        {
            ThrowIfEnded();
            long target = Interlocked.Exchange(ref _cancelFor, 0);
            bool cancel = target != 0 && Interlocked.Read(ref _ready) < target;
            if (request) Interlocked.Increment(ref _sent);
            if (oot != null)
            {
                _oot.Enqueue(oot);
                if (Volatile.Read(ref _failure) != null) DrainWaiters();
            }
            try
            {
                if (cancel) await _frames.WriteAsync(CancelFrame).ConfigureAwait(false);
                await _frames.WriteAsync(frame).ConfigureAwait(false);
            }
            catch (Exception e) when (e is IOException or SocketException or ObjectDisposedException)
            {
                // what the server sent before its close is still to be read: the reader reaches its end (at most 1 s)
                await Task.WhenAny(_reader, Task.Delay(1000)).ConfigureAwait(false);
                Fail(new ImdbConnectionClosedException("the connection: a write failed: " + e.Message, null, e));
                throw Failure();
            }
        }
        finally
        {
            _writeLock.Release();
        }
    }

    /// <summary>Cancels the statement this connection runs now (in band: CANCEL). Any thread, at any time; it never
    /// blocks and never throws. Asked while no request is outstanding, it is dropped (§4: it would otherwise cancel the
    /// next request's statement). The cancelled statement ends in ERROR 15; a statement never checked (COMMIT, a DDL)
    /// runs to its end.</summary>
    public void Cancel() => CancelRequest(Interlocked.Read(ref _sent));

    private void CancelRequest(long seq)
    {
        if (seq == 0 || Interlocked.Read(ref _ready) >= seq) return; // nothing outstanding: dropped
        long cur;
        do
        {
            cur = Interlocked.Read(ref _cancelFor);
            if (cur >= seq) break;
        } while (Interlocked.CompareExchange(ref _cancelFor, seq, cur) != cur);
        _ = FlushCancelAsync();
    }

    private async Task FlushCancelAsync()
    {
        try
        {
            await _writeLock.WaitAsync().ConfigureAwait(false);
            try
            {
                long target = Interlocked.Exchange(ref _cancelFor, 0);
                if (target == 0 || Volatile.Read(ref _failure) != null || Interlocked.Read(ref _ready) >= target) return;
                await _frames.WriteAsync(CancelFrame).ConfigureAwait(false);
            }
            finally
            {
                _writeLock.Release();
            }
        }
        catch (Exception)
        {
            // the connection's end is reported to its callers by the reader
        }
    }

    // =============================== the replies of a request ===============================

    private async ValueTask<WireMessage> NextAsync()
    {
        try
        {
            if (_replyTimeout is { } t)
            {
                using var cts = new CancellationTokenSource(t);
                try
                {
                    return await _inTurn.Reader.ReadAsync(cts.Token).ConfigureAwait(false);
                }
                catch (OperationCanceledException) when (cts.IsCancellationRequested)
                {
                    Fail(new ImdbException((int)ImdbErrorCode.Io, $"no reply within {t.TotalMilliseconds:0} ms: the connection ended"));
                    throw Failure();
                }
            }
            return await _inTurn.Reader.ReadAsync().ConfigureAwait(false);
        }
        catch (ChannelClosedException)
        {
            throw Failure();
        }
    }

    private sealed class CopyIn
    {
        public CopyIn(Stream source) => Source = source;
        public Stream Source { get; }
        public bool Used;
        public Exception? SourceError;
    }

    private async Task<ImdbBatchResult> RunAsync(byte[] frame, int units, CopyIn? copyIn, Stream? copyOut, CancellationToken ct)
    {
        ThrowIfEnded();
        ct.ThrowIfCancellationRequested();
        await _requestLock.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            ThrowIfEnded();
            ct.ThrowIfCancellationRequested(); // nothing sent yet
            await WriteFrameAsync(frame, request: true).ConfigureAwait(false);
            var rs = new RequestState { Seq = Interlocked.Read(ref _sent) };
            using var reg = ct.CanBeCanceled ? ct.Register(() =>
            {
                rs.TokenCancelled = true;
                CancelRequest(rs.Seq);
            }) : default;
            return await RepliesAsync(rs, units, copyIn, copyOut, ct).ConfigureAwait(false);
        }
        finally
        {
            _requestLock.Release();
        }
    }

    private async Task<ImdbBatchResult> RepliesAsync(RequestState rs, int units, CopyIn? copyIn, Stream? copyOut, CancellationToken ct)
    {
        var results = new List<ImdbResult>();
        ImdbServerException? error = null;
        int errors = 0;
        IReadOnlyList<ImdbColumn> cols = Array.Empty<ImdbColumn>();
        var rows = new List<ImdbValue[]>();
        var warns = new List<string>();
        MemoryStream? copyData = null;
        Exception? sinkError = null;
        while (true)
        {
            var m = await NextAsync().ConfigureAwait(false);
            switch (m)
            {
                case ColumnsMessage c:
                    cols = c.Columns;
                    rows = new List<ImdbValue[]>();
                    break;
                case RowsMessage r:
                    rows.AddRange(r.Rows);
                    break;
                case TextMessage w when w.Type == FrameType.Warning:
                    warns.Add(w.Text);
                    break;
                case DataMessage d when d.Type == FrameType.CopyOut:
                    if (sinkError != null) break; // drained to READY: the statement is being cancelled
                    if (copyOut != null)
                    {
                        try
                        {
                            await copyOut.WriteAsync(d.Data, CancellationToken.None).ConfigureAwait(false);
                        }
                        catch (Exception e)
                        {
                            sinkError = e;
                            CancelRequest(rs.Seq);
                        }
                    }
                    else
                    {
                        copyData ??= new MemoryStream();
                        if (copyData.Length + d.Data.Length > CopyOutInMemoryMax)
                        {
                            sinkError = new ImdbException((int)ImdbErrorCode.Limit,
                                "COPY ... TO STDOUT through QueryAsync passed 256 MiB held in memory: use CopyOutAsync with a stream");
                            CancelRequest(rs.Seq);
                        }
                        else copyData.Write(d.Data);
                    }
                    break;
                case EmptyMessage { Type: FrameType.CopyIn }:
                    if (copyIn != null && !copyIn.Used)
                    {
                        copyIn.Used = true;
                        await UploadAsync(copyIn, rs, ct).ConfigureAwait(false);
                    }
                    else // a COPY ... FROM STDIN with no source: ended at once, or the connection would wait for data
                        await WriteFrameAsync(Codec.EncodeCopyFail("COPY ... FROM STDIN has no data source here: use ImdbConnection.CopyInAsync")).ConfigureAwait(false);
                    break;
                case DoneMessage d:
                    if (error != null || results.Count >= units) throw Violation("a DONE past its batch's statements or after its ERROR");
                    results.Add(new ImdbResult(cols, rows, warns, d, copyData?.ToArray()));
                    cols = Array.Empty<ImdbColumn>();
                    rows = new List<ImdbValue[]>();
                    warns = new List<string>();
                    copyData = null;
                    break;
                case ErrorMessage e:
                    errors++;
                    error ??= ToServerException(e);
                    cols = Array.Empty<ImdbColumn>(); // the rows before an ERROR are not the statement's answer
                    rows = new List<ImdbValue[]>();
                    warns = new List<string>();
                    copyData = null;
                    break;
                case ReadyMessage rd:
                    if (errors > 1 || (error == null && results.Count != units) || (error != null && error.Index != results.Count))
                        throw Violation($"a READY after {results.Count} of {units} answers and {errors} ERRORs");
                    if (error != null)
                    {
                        error.TransactionState = rd.State;
                        error.CompletedResults = results;
                    }
                    if (copyIn?.SourceError != null) throw copyIn.SourceError;
                    if (sinkError != null) throw sinkError;
                    if (rs.TokenCancelled && error != null && error.Code == (int)ImdbErrorCode.Cancelled)
                        throw new OperationCanceledException("the statement was cancelled: " + error.Message, error, ct);
                    return new ImdbBatchResult(results, error, rd.State);
                default:
                    throw Violation($"a {m.Type} among a request's replies");
            }
        }
    }

    /// <summary>COPY ... FROM STDIN's data, after its COPY_IN alone: 1 MiB pieces until the source ends, then COPY_DONE;
    /// COPY_FAIL when the source fails or the caller cancels. The server may answer the COPY before the data's end (its
    /// ERROR and READY): the upload stops there, and still ends with COPY_DONE (§4: the server reads to the client's end).</summary>
    private async Task UploadAsync(CopyIn ci, RequestState rs, CancellationToken ct)
    {
        var buf = ArrayPool<byte>.Shared.Rent(Protocol.CopyPiece);
        string? fail = null;
        try
        {
            while (true)
            {
                if (_inTurn.Reader.TryPeek(out var early) && early is ErrorMessage or ReadyMessage) break; // answered: the rest is not wanted
                if (rs.TokenCancelled)
                {
                    fail = "cancelled by its client";
                    break;
                }
                int n;
                try
                {
                    n = await ci.Source.ReadAsync(buf.AsMemory(0, Protocol.CopyPiece), ct).ConfigureAwait(false);
                }
                catch (OperationCanceledException) when (ct.IsCancellationRequested)
                {
                    fail = "cancelled by its client";
                    break;
                }
                catch (Exception e)
                {
                    ci.SourceError = e;
                    fail = "its client's data source failed (" + e.GetType().Name + ")";
                    break;
                }
                if (n == 0) break;
                await WriteFrameAsync(Codec.EncodeCopyData(buf.AsSpan(0, n))).ConfigureAwait(false);
            }
            await WriteFrameAsync(fail == null ? CopyDoneFrame : Codec.EncodeCopyFail(fail)).ConfigureAwait(false);
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buf);
        }
    }

    // =============================== requests ===============================

    /// <summary>One statement with its parameters ($1 to $n, CLR values: <see cref="ImdbValue.FromObject"/>); its result,
    /// or its ERROR as <see cref="ImdbServerException"/> (as OperationCanceledException when this call's token
    /// cancelled it).</summary>
    public Task<ImdbResult> QueryAsync(string sql, params object?[] args) => QueryAsync(sql, (IReadOnlyList<object?>)args, default);

    /// <summary>A statement of no parameters, cancellable by the token (never bound as a parameter).</summary>
    public Task<ImdbResult> QueryAsync(string sql, CancellationToken ct) => QueryAsync(sql, Array.Empty<object?>(), ct);

    public async Task<ImdbResult> QueryAsync(string sql, IReadOnlyList<object?> args, CancellationToken ct = default)
    {
        var st = new ImdbStatement(sql, ToArray(args));
        var b = await RunAsync(Codec.EncodeQuery(new[] { st }), 1, null, null, ct).ConfigureAwait(false);
        return b.ThrowIfError()[0];
    }

    /// <summary>A QUERY of several statements run in order: each its result; an ERROR ends the batch (its index the
    /// failed statement; those after it do not run; those before it stand). A batch is not a transaction.</summary>
    public Task<ImdbBatchResult> ExecuteBatchAsync(IReadOnlyList<ImdbStatement> statements, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(statements);
        return RunAsync(Codec.EncodeQuery(statements), statements.Count, null, null, ct);
    }

    /// <summary>PREPARE: the statement's parameters are typed at each EXECUTE, as the engine's PREPARE.</summary>
    public async Task PrepareAsync(string name, string sql, CancellationToken ct = default) =>
        (await RunAsync(Codec.EncodePrepare(name, sql), 1, null, null, ct).ConfigureAwait(false)).ThrowIfError();

    /// <summary>EXECUTE of one parameter set.</summary>
    public async Task<ImdbResult> ExecuteAsync(string name, IReadOnlyList<object?> args, CancellationToken ct = default)
    {
        var b = await ExecuteBatchAsync(name, new[] { args }, ct).ConfigureAwait(false);
        return b.ThrowIfError()[0];
    }

    /// <summary>EXECUTE of several parameter sets (each the same count of values), run in order as a batch.</summary>
    public Task<ImdbBatchResult> ExecuteBatchAsync(string name, IReadOnlyList<IReadOnlyList<object?>> sets, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(sets);
        var v = new IReadOnlyList<ImdbValue>[sets.Count];
        for (int i = 0; i < v.Length; i++) v[i] = ToArray(sets[i]);
        return RunAsync(Codec.EncodeExecute(name, v), v.Length, null, null, ct);
    }

    public async Task DeallocateAsync(string name, CancellationToken ct = default) =>
        (await RunAsync(Codec.EncodeDeallocate(name), 1, null, null, ct).ConfigureAwait(false)).ThrowIfError();

    /// <summary>COPY ... FROM STDIN: the statement, then the source's bytes as its data once the server's COPY_IN came
    /// (none when the server refuses the COPY before its data), then COPY_DONE; a failed source sends COPY_FAIL (the
    /// statement refused unrun) and its exception is thrown once the server answered. Its DONE's count is the rows.</summary>
    public async Task<ImdbResult> CopyInAsync(string sql, Stream data, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(data);
        var ci = new CopyIn(data);
        var b = await RunAsync(Codec.EncodeQuery(new[] { new ImdbStatement(sql) }), 1, ci, null, ct).ConfigureAwait(false);
        return b.ThrowIfError()[0];
    }

    /// <summary>COPY ... TO STDOUT: its COPY_OUT frames written to the destination as they come. A destination that
    /// throws cancels the statement; its exception is thrown once the server answered.</summary>
    public async Task<ImdbResult> CopyOutAsync(string sql, Stream destination, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(destination);
        var b = await RunAsync(Codec.EncodeQuery(new[] { new ImdbStatement(sql) }), 1, null, destination, ct).ConfigureAwait(false);
        return b.ThrowIfError()[0];
    }

    private static ImdbValue[] ToArray(IReadOnlyList<object?>? args)
    {
        if (args == null) return Array.Empty<ImdbValue>();
        var v = new ImdbValue[args.Count];
        for (int i = 0; i < v.Length; i++) v[i] = ImdbValue.FromObject(args[i]);
        return v;
    }

    // ---- answered out of turn ----

    private async Task<WireMessage> OutOfTurnAsync(byte[] frame, FrameType want, CancellationToken ct)
    {
        var w = new OotWaiter(want);
        await WriteFrameAsync(frame, oot: w).ConfigureAwait(false);
        var t = w.Tcs.Task.WaitAsync(ct);
        if (_replyTimeout is { } to)
        {
            try
            {
                return await t.WaitAsync(to, CancellationToken.None).ConfigureAwait(false);
            }
            catch (TimeoutException)
            {
                Fail(new ImdbException((int)ImdbErrorCode.Io, $"no reply within {to.TotalMilliseconds:0} ms: the connection ended"));
                throw Failure();
            }
        }
        return await t.ConfigureAwait(false);
    }

    /// <summary>PING, answered by the server's connection thread out of turn (between requests or during one): the
    /// round trip.</summary>
    public async Task<TimeSpan> PingAsync(CancellationToken ct = default)
    {
        ThrowIfEnded();
        long t0 = Stopwatch.GetTimestamp();
        await OutOfTurnAsync(PingFrame, FrameType.Pong, ct).ConfigureAwait(false);
        return Stopwatch.GetElapsedTime(t0);
    }

    /// <summary>SESSIONS: a superuser's every session, a role's its own role's (answered out of turn; serialized with
    /// this connection's requests, so it never lands inside a COPY's data).</summary>
    public async Task<IReadOnlyList<ImdbSession>> SessionsAsync(CancellationToken ct = default)
    {
        ThrowIfEnded();
        await _requestLock.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            var m = await OutOfTurnAsync(SessionsFrame, FrameType.SessionsList, ct).ConfigureAwait(false);
            return ((SessionsListMessage)m).Sessions;
        }
        finally
        {
            _requestLock.Release();
        }
    }

    /// <summary>KILL a session by its id (from <see cref="SessionsAsync"/>): true when done, false when there is no such
    /// session (to a role that is not a superuser, another role's too).</summary>
    public async Task<bool> KillAsync(ulong sessionId, ImdbKillKind kind, CancellationToken ct = default)
    {
        var frame = Codec.EncodeKill(kind, sessionId);
        ThrowIfEnded();
        await _requestLock.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            var m = (KillDoneMessage)await OutOfTurnAsync(frame, FrameType.KillDone, ct).ConfigureAwait(false);
            if (m.SessionId != sessionId) throw Violation("a KILL_DONE for another session");
            return m.Code == 0;
        }
        finally
        {
            _requestLock.Release();
        }
    }

    /// <summary>Tests: an encoded frame written as it is (a protocol error provoked on purpose).</summary>
    internal Task SendRawForTestsAsync(byte[] frame) => WriteFrameAsync(frame);

    // ---- the end ----

    /// <summary>TERMINATE once the requests before it ran: the server ends the session (an open transaction rolled back)
    /// and closes; then the connection is disposed.</summary>
    public async Task TerminateAsync(CancellationToken ct = default)
    {
        ThrowIfEnded();
        await _requestLock.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            await WriteFrameAsync(TerminateFrame).ConfigureAwait(false);
            await Task.WhenAny(_reader, Task.Delay(5000, ct)).ConfigureAwait(false);
        }
        finally
        {
            _requestLock.Release();
        }
        await DisposeAsync().ConfigureAwait(false);
    }

    /// <summary>Closes: TERMINATE first when no request is in flight (best effort), else the socket closed at once (the
    /// server then treats the session as a client that left: its statement cancelled, its transaction rolled back).</summary>
    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0) return;
        if (Volatile.Read(ref _failure) == null && _requestLock.Wait(0))
        {
            try
            {
                if (await _writeLock.WaitAsync(1000).ConfigureAwait(false))
                {
                    try
                    {
                        using var cts = new CancellationTokenSource(1000);
                        await _frames.WriteAsync(TerminateFrame, cts.Token).ConfigureAwait(false);
                    }
                    catch (Exception)
                    {
                        // closing anyway
                    }
                    finally
                    {
                        _writeLock.Release();
                    }
                    await Task.WhenAny(_reader, Task.Delay(1000)).ConfigureAwait(false);
                }
            }
            finally
            {
                _requestLock.Release();
            }
        }
        Fail(new ObjectDisposedException(nameof(ImdbConnection)));
        try
        {
            await _reader.ConfigureAwait(false);
        }
        catch (Exception)
        {
            // the reader reports through Fail
        }
    }
}
