using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Imagedb.Client.Wire;

namespace Imagedb.Client.Tests;

/// <summary>A server of this test's own on a Unix-domain socket (the codec's server side: EncodeChallenge, ScramServer,
/// EncodeServer, DecodeClientBody), for what a real server never sends: a wrong ServerSignature, a later protocol, a
/// frame the driver must refuse, a WARNING, an unasked ERROR before a close; and to see the client's frames in order
/// (CANCEL's place, COPY's end).</summary>
internal sealed class Mock : IAsyncDisposable
{
    public const string Password = "pw-mock";
    private readonly Socket _l;
    public int Accepted;

    public Mock(string name)
    {
        string dir = Environment.GetEnvironmentVariable("IMDB_DRV_RUN")
                     ?? System.IO.Path.Combine(System.IO.Path.GetTempPath(), "imdb-drv-csharp-mock");
        Directory.CreateDirectory(dir);
        Path = System.IO.Path.Combine(dir, "m-" + name + ".sock");
        if (File.Exists(Path)) File.Delete(Path);
        _l = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
        _l.Bind(new UnixDomainSocketEndPoint(Path));
        _l.Listen(8);
    }

    public string Path { get; }

    public ImdbConnectOptions Options(TimeSpan? replyTimeout = null) =>
        new() { SocketPath = Path, User = "alice", Password = Password, ReplyTimeout = replyTimeout ?? TimeSpan.FromSeconds(30) };

    public async Task<MockConn> AcceptAsync()
    {
        var s = await _l.AcceptAsync();
        Interlocked.Increment(ref Accepted);
        return new MockConn(s);
    }

    /// <summary>Runs the server's side for one connection, the client's side, and waits for both.</summary>
    public async Task Run(Func<MockConn, Task> server, Func<Task> client)
    {
        var st = Task.Run(async () =>
        {
            await using var c = await AcceptAsync();
            await server(c);
        });
        await client();
        await st.WaitAsync(TimeSpan.FromSeconds(30));
    }

    public ValueTask DisposeAsync()
    {
        _l.Dispose();
        try
        {
            File.Delete(Path);
        }
        catch (IOException)
        {
        }
        return ValueTask.CompletedTask;
    }
}

internal sealed class MockConn : IAsyncDisposable
{
    private readonly NetworkStream _s;
    private readonly ImdbFrameStream _f;

    public MockConn(Socket s)
    {
        _s = new NetworkStream(s, ownsSocket: true);
        _f = new ImdbFrameStream(_s);
    }

    public Task Send(byte[] b) => _s.WriteAsync(b).AsTask();
    public Task Send(WireMessage m, ColumnsMessage? cols = null) => Send(Codec.EncodeServer(m, cols));

    public async Task<byte[]> Read(int n)
    {
        var b = new byte[n];
        await _s.ReadExactlyAsync(b);
        return b;
    }

    /// <summary>The hello, a challenge, the proof checked; the verdict as given (null: the honest one).</summary>
    public async Task Login(Func<byte[], byte[]>? verdict = null, byte[]? challenge = null)
    {
        var hello = await Read(Protocol.HelloLength);
        var h = Codec.DecodeHello(hello);
        T.Eq(ChannelBindingType.None, h.Flags, "a socket hello's binding type");
        var salt = new byte[16];
        RandomNumberGenerator.Fill(salt);
        var ch = challenge ?? Codec.EncodeChallenge(salt, 4096, RandomNumberGenerator.GetBytes(32));
        await Send(ch);
        if (challenge != null) return;
        var proof = await Read(Protocol.ProofLength);
        var c = Codec.DecodeChallenge(ch);
        var (stored, skey) = Codec.ScramVerifier(Encoding.ASCII.GetBytes(Mock.Password), c.Salt, c.Iterations);
        var am = Codec.AuthMessage(ImdbEndpoint.Socket, hello, ch, new byte[32]);
        bool ok = Codec.ScramServer(stored, skey, am, proof, out var sig);
        T.Check(ok, "the client's proof is the password's");
        var honest = Codec.EncodeVerdict(0, sig);
        await Send(verdict == null ? honest : verdict(honest));
    }

    public async Task<WireMessage?> Next()
    {
        var f = await _f.ReadFrameAsync(fromServer: false);
        return f == null ? null : Codec.DecodeClientBody(f.Value.Type, f.Value.Body);
    }

    public async Task<WireMessage> Expect(FrameType t)
    {
        var m = await Next() ?? throw new CheckFailed($"the client closed; expected {t}");
        T.Eq(t, m.Type, "the client's next frame");
        return m;
    }

    public async Task Done(string status = "SELECT 1") => await Send(new DoneMessage(status, 1, null, null));
    public async Task Ready(ImdbTransactionState s = ImdbTransactionState.Idle) => await Send(new ReadyMessage(s));
    public void Close() => _s.Socket.Shutdown(SocketShutdown.Both);

    public async ValueTask DisposeAsync() => await _s.DisposeAsync();
}

public static class MockTests
{
    public static IEnumerable<TestCase> All()
    {
        yield return new("mock", "server_signature_checked", ServerSignature);
        yield return new("mock", "verdict_refused_with_a_signature", VerdictRefusedSig);
        yield return new("mock", "verdict_2_binding_never_retried", VerdictBinding);
        yield return new("mock", "a_later_magic_or_version_by_name", LaterProtocol);
        yield return new("mock", "a_challenge_its_decoder_refuses", BadChallenge);
        yield return new("mock", "closed_reason_unasked_error", UnaskedError);
        yield return new("mock", "closed_after_ready_no_reason", NoReason);
        yield return new("mock", "a_frame_refused_ends_the_connection", BadFrames);
        yield return new("mock", "warning_and_rows", WarningRows);
        yield return new("mock", "rows_before_an_error_are_not_an_answer", RowsThenError);
        yield return new("mock", "cancel_only_while_outstanding", CancelRules);
        yield return new("mock", "copy_in_without_a_source", CopyNoSource);
        yield return new("mock", "copy_in_answered_early_ends_with_copy_done", CopyEarly);
        yield return new("mock", "copy_in_refused_before_copy_in_sends_nothing", CopyRefused);
        yield return new("mock", "cancel_during_upload_goes_before_the_next_frame", CopyCancel);
        yield return new("mock", "out_of_turn_answers", OutOfTurn);
        yield return new("mock", "replies_out_of_order_refused", OutOfOrder);
        yield return new("mock", "reply_timeout_ends_the_connection", ReplyTimeout);
    }

    private static async Task ServerSignature()
    {
        await using var m = new Mock("sig");
        await m.Run(c => c.Login(v =>
        {
            v[10] ^= 1; // one bit of the ServerSignature off
            return v;
        }), async () =>
        {
            var e = await T.ThrowsAsync<ImdbAuthenticationException>(() => ImdbConnection.ConnectAsync(m.Options()), "a wrong ServerSignature");
            T.Eq(ImdbAuthFailure.ServerSignatureInvalid, e.Failure, "the server did not prove it holds the verifier");
        });
    }

    private static async Task VerdictRefusedSig()
    {
        await using var m = new Mock("vrs");
        await m.Run(c => c.Login(v =>
        {
            v[0] = 1; // refused, the signature left in
            return v;
        }), async () =>
        {
            var e = await T.ThrowsAsync<ImdbProtocolException>(() => ImdbConnection.ConnectAsync(m.Options()), "a refusal carrying a signature");
            T.Eq(ImdbErrorCode.Corrupt, e.Kind, "damage");
        });
        await m.Run(c => c.Login(_ => Codec.EncodeVerdict(1, new byte[32])), async () =>
        {
            var e = await T.ThrowsAsync<ImdbAuthenticationException>(() => ImdbConnection.ConnectAsync(m.Options()), "verdict 1");
            T.Eq(ImdbAuthFailure.Refused, e.Failure, "refused");
        });
    }

    private static async Task VerdictBinding()
    {
        await using var m = new Mock("vb");
        await m.Run(c => c.Login(_ => Codec.EncodeVerdict(2, new byte[32])), async () =>
        {
            var e = await T.ThrowsAsync<ImdbAuthenticationException>(() => ImdbConnection.ConnectAsync(m.Options()), "verdict 2");
            T.Eq(ImdbAuthFailure.BindingRefused, e.Failure, "the binding type refused");
        });
        await Task.Delay(300);
        T.Eq(1, m.Accepted, "one connection: never retried with another type");
    }

    private static async Task LaterProtocol()
    {
        await using var m = new Mock("later");
        var later = new byte[Protocol.ChallengeLength];
        Encoding.ASCII.GetBytes("IMDBWIR2").CopyTo(later, 0);
        later[8] = 1;
        await m.Run(c => c.Login(challenge: later), async () =>
        {
            var e = await T.ThrowsAsync<ImdbProtocolException>(() => ImdbConnection.ConnectAsync(m.Options()), "IMDBWIR2");
            T.Check(e.Kind == ImdbErrorCode.Unsupported && e.Message.Contains("IMDBWIR2", StringComparison.Ordinal), e.Message);
        });
        // a server that speaks only a later version answers its own head, then closes
        await m.Run(async c =>
        {
            await c.Read(Protocol.HelloLength);
            var head = new byte[12];
            Encoding.ASCII.GetBytes("IMDBWIR1").CopyTo(head, 0);
            head[8] = 2;
            await c.Send(head);
            c.Close();
        }, async () =>
        {
            var e = await T.ThrowsAsync<ImdbProtocolException>(() => ImdbConnection.ConnectAsync(m.Options()), "version 2");
            T.Check(e.Kind == ImdbErrorCode.Unsupported && e.Message.Contains("version 2", StringComparison.Ordinal), e.Message);
        });
    }

    private static async Task BadChallenge()
    {
        await using var m = new Mock("ch");
        var ch = Codec.EncodeChallenge(new byte[16], 4096, new byte[32]);
        System.Buffers.Binary.BinaryPrimitives.WriteUInt32LittleEndian(ch.AsSpan(13 + 64), 999);
        await m.Run(c => c.Login(challenge: ch), async () =>
            await T.ThrowsAsync<ImdbProtocolException>(() => ImdbConnection.ConnectAsync(m.Options()), "999 iterations"));
    }

    // a login answered, then an unasked ERROR and the close (a role's bound, §4): the next call reports those words
    private static async Task UnaskedError()
    {
        await using var m = new Mock("ue");
        await m.Run(async c =>
        {
            await c.Login();
            await c.Send(new ErrorMessage(3, 0, "too many connections for role alice (--role-conns 1)"));
            c.Close();
        }, async () =>
        {
            await using var cn = await ImdbConnection.ConnectAsync(m.Options());
            for (int i = 0; i < 50 && cn.IsOpen; i++) await Task.Delay(20);
            var e = await T.ThrowsAsync<ImdbConnectionClosedException>(() => cn.QueryAsync("SELECT 1"), "after the server's close");
            T.Check(e.Reason?.Code == 3 && e.Code == 3 && e.Message.Contains("--role-conns 1", StringComparison.Ordinal), e.Message);
            await T.ThrowsAsync<ImdbConnectionClosedException>(() => cn.PingAsync(), "PING too");
        });
    }

    // an ERROR followed by another frame answered its request: a close after it has no reason (code 1)
    private static async Task NoReason()
    {
        await using var m = new Mock("nr");
        await m.Run(async c =>
        {
            await c.Login();
            await c.Expect(FrameType.Query);
            await c.Send(new ErrorMessage(10, 0, "syntax error"));
            await c.Ready();
            c.Close();
        }, async () =>
        {
            await using var cn = await ImdbConnection.ConnectAsync(m.Options());
            var se = await T.ThrowsAsync<ImdbServerException>(() => cn.QueryAsync("SELEC 1"), "the statement's ERROR");
            T.Eq(10, se.Code, "10");
            for (int i = 0; i < 50 && cn.IsOpen; i++) await Task.Delay(20);
            var e = await T.ThrowsAsync<ImdbConnectionClosedException>(() => cn.QueryAsync("SELECT 1"), "closed");
            T.Check(e.Reason == null && e.Code == 1, "no reason: " + e.Message);
        });
    }

    private static async Task BadFrames()
    {
        await using var m = new Mock("bf");
        // a ROWS value its column does not take: an INT64 of 40,000 in a SMALLINT column
        var cols = new ColumnsMessage(new[] { new ImdbColumn("s", ImdbType.Int64, 16) });
        var rows = Codec.EncodeServer(new RowsMessage(new[] { new[] { ImdbValue.FromInt64(4000) } }), cols);
        System.Buffers.Binary.BinaryPrimitives.WriteInt64LittleEndian(rows.AsSpan(5 + 4 + 1), 40000);
        await m.Run(async c =>
        {
            await c.Login();
            await c.Expect(FrameType.Query);
            await c.Send(cols);
            await c.Send(rows);
            await Task.Delay(200);
        }, async () =>
        {
            await using var cn = await ImdbConnection.ConnectAsync(m.Options());
            var e = await T.ThrowsAsync<ImdbProtocolException>(() => cn.QueryAsync("SELECT s FROM t"), "a ROWS value past SMALLINT");
            T.Check(e.Message.Contains("Rows frame refused", StringComparison.Ordinal) && e.Message.Contains("column does not take", StringComparison.Ordinal), e.Message);
            T.Check(!cn.IsOpen, "the connection ended");
        });
        // heads: a length of 0 (a limit) and a client's type
        foreach (var (head, code) in new[] { (new byte[] { 0, 0, 0, 0, 66 }, ImdbErrorCode.Limit), (new byte[] { 1, 0, 0, 0, 1 }, ImdbErrorCode.Corrupt),
                                             (new byte[] { 1, 0, 0, 1, 66 }, ImdbErrorCode.Limit) })
        {
            await m.Run(async c =>
            {
                await c.Login();
                await c.Expect(FrameType.Query);
                await c.Send(head);
                await Task.Delay(200);
            }, async () =>
            {
                await using var cn = await ImdbConnection.ConnectAsync(m.Options());
                var e = await T.ThrowsAsync<ImdbProtocolException>(() => cn.QueryAsync("SELECT 1"), "head " + Convert.ToHexString(head));
                T.Check(e.Kind == code && e.Message.Contains("head refused", StringComparison.Ordinal), e.Message);
            });
        }
    }

    private static async Task WarningRows()
    {
        await using var m = new Mock("wr");
        var cols = new ColumnsMessage(new[] { new ImdbColumn("x", ImdbType.None) }); // a column of no type: each value its own
        await m.Run(async c =>
        {
            await c.Login();
            await c.Expect(FrameType.Query);
            await c.Send(cols);
            await c.Send(new RowsMessage(new[] { new[] { ImdbValue.FromText("a") }, new[] { ImdbValue.FromInt64(2) } }), cols);
            await c.Send(new RowsMessage(new[] { new[] { ImdbValue.Null() } }), cols);
            await c.Send(new TextMessage(FrameType.Warning, "CHECKPOINT failed: the log grows"));
            await c.Done();
            await c.Ready();
        }, async () =>
        {
            await using var cn = await ImdbConnection.ConnectAsync(m.Options());
            var r = await cn.QueryAsync("SHOW STATS");
            T.Check(r.Rows.Count == 3 && (string)r.Rows[0][0]! == "a" && (long)r.Rows[1][0]! == 2 && r.Rows[2][0] == null, "rows across two ROWS frames");
            T.Eq("CHECKPOINT failed: the log grows", r.Warnings.Single(), "the WARNING");
            T.Eq(ImdbType.None, r.Columns[0].Type, "a column of no known type");
        });
    }

    // §4: an ERROR may follow a statement's COLUMNS and some of its ROWS; those rows are not its answer
    private static async Task RowsThenError()
    {
        await using var m = new Mock("rte");
        var cols = new ColumnsMessage(new[] { new ImdbColumn("x", ImdbType.Int64) });
        await m.Run(async c =>
        {
            await c.Login();
            await c.Expect(FrameType.Query);
            await c.Send(cols);
            await c.Send(new RowsMessage(new[] { new[] { ImdbValue.FromInt64(1) } }), cols);
            await c.Done();
            await c.Send(cols);
            await c.Send(new RowsMessage(new[] { new[] { ImdbValue.FromInt64(2) } }), cols);
            await c.Send(new ErrorMessage(3, 1, "a row longer than a frame"));
            await c.Ready(ImdbTransactionState.InTransaction);
        }, async () =>
        {
            await using var cn = await ImdbConnection.ConnectAsync(m.Options());
            var b = await cn.ExecuteBatchAsync(new[] { new ImdbStatement("SELECT 1"), new ImdbStatement("SELECT 2"), new ImdbStatement("SELECT 3") });
            T.Check(b.Results.Count == 1 && b.Results[0].Rows.Single().GetInt64(0) == 1, "the first statement's answer alone");
            T.Check(b.Error is { Code: 3, Index: 1 } && b.Error.CompletedResults.Count == 1, "the ERROR, its index 1");
            T.Eq(ImdbTransactionState.InTransaction, b.State, "READY's state");
            T.Eq(ImdbTransactionState.InTransaction, cn.TransactionState, "the connection's");
        });
    }

    private static async Task CancelRules()
    {
        await using var m = new Mock("cr");
        var go = new TaskCompletionSource();
        await m.Run(async c =>
        {
            await c.Login();
            await c.Expect(FrameType.Query); // the idle Cancel() before it sent nothing
            await c.Expect(FrameType.Cancel); // the one asked while it was outstanding
            await c.Send(new ErrorMessage(15, 0, "cancelled"));
            await c.Ready();
            await c.Expect(FrameType.Query);
            await c.Expect(FrameType.Cancel); // the token's
            await c.Send(new ErrorMessage(15, 0, "cancelled"));
            await c.Ready();
            await c.Expect(FrameType.Query); // answered at once; its token cancelled after
            await c.Done();
            await c.Ready();
            await go.Task;
            await c.Expect(FrameType.Query); // no CANCEL before it
            await c.Done();
            await c.Ready();
        }, async () =>
        {
            await using var cn = await ImdbConnection.ConnectAsync(m.Options());
            cn.Cancel();
            await Task.Delay(100);
            var q = cn.QueryAsync("SELECT 1");
            await Task.Delay(100);
            cn.Cancel();
            var e = await T.ThrowsAsync<ImdbServerException>(() => q, "Cancel(): the statement's ERROR 15");
            T.Eq(15, e.Code, "15, an ImdbServerException (not this call's token)");
            using (var cts = new CancellationTokenSource(150))
                await T.ThrowsAsync<OperationCanceledException>(() => cn.QueryAsync("SELECT 2", Array.Empty<object?>(), cts.Token), "the token's");
            using (var late = new CancellationTokenSource())
            {
                await cn.QueryAsync("SELECT 3", Array.Empty<object?>(), late.Token);
                late.Cancel();
            }
            cn.Cancel();
            await Task.Delay(100);
            go.SetResult();
            await cn.QueryAsync("SELECT 4");
        });
    }

    private static async Task CopyNoSource()
    {
        await using var m = new Mock("cns");
        await m.Run(async c =>
        {
            await c.Login();
            await c.Expect(FrameType.Query);
            await c.Send(Codec.EncodeEmpty(FrameType.CopyIn));
            var f = (TextMessage)await c.Expect(FrameType.CopyFail);
            T.Check(f.Text.Contains("CopyInAsync", StringComparison.Ordinal), "its reason: " + f.Text);
            await c.Send(new ErrorMessage(15, 0, "COPY ... FROM STDIN failed by its client: " + f.Text));
            await c.Ready();
        }, async () =>
        {
            await using var cn = await ImdbConnection.ConnectAsync(m.Options());
            var e = await T.ThrowsAsync<ImdbServerException>(() => cn.QueryAsync("COPY t FROM STDIN"), "no source");
            T.Eq(15, e.Code, "15");
        });
    }

    private sealed class Endless : Stream
    {
        public override int Read(byte[] buffer, int offset, int count)
        {
            Thread.Sleep(5);
            var b = Encoding.ASCII.GetBytes("1,2\n");
            int k = Math.Min(count, b.Length);
            Array.Copy(b, 0, buffer, offset, k);
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

    // the server answers the COPY while its data still comes (its spool bound): the client stops, ends with COPY_DONE,
    // and only then sends its next request
    private static async Task CopyEarly()
    {
        await using var m = new Mock("ce");
        await m.Run(async c =>
        {
            await c.Login();
            await c.Expect(FrameType.Query);
            await c.Send(Codec.EncodeEmpty(FrameType.CopyIn));
            await c.Expect(FrameType.CopyData);
            await c.Expect(FrameType.CopyData);
            await c.Send(new ErrorMessage(3, 0, "COPY ... FROM STDIN: its data passed the server's spool bound"));
            await c.Ready();
            WireMessage? f;
            int more = 0;
            while ((f = await c.Next()) is { Type: FrameType.CopyData })
                if (++more > 50) throw new CheckFailed("the client kept uploading after the server's ERROR and READY");
            T.Eq(FrameType.CopyDone, f?.Type, $"the COPY ended by COPY_DONE ({more} pieces after the ERROR)");
            await c.Expect(FrameType.Query);
            await c.Done();
            await c.Ready();
        }, async () =>
        {
            await using var cn = await ImdbConnection.ConnectAsync(m.Options());
            var e = await T.ThrowsAsync<ImdbServerException>(() => cn.CopyInAsync("COPY t FROM STDIN", new Endless()), "answered early");
            T.Eq(3, e.Code, "3, a limit");
            await cn.QueryAsync("SELECT 1");
        });
    }

    private static async Task CopyRefused()
    {
        await using var m = new Mock("crf");
        var src = new MemoryStream(Encoding.ASCII.GetBytes("1\n"));
        await m.Run(async c =>
        {
            await c.Login();
            await c.Expect(FrameType.Query);
            await c.Send(new ErrorMessage(11, 0, "no table t"));
            await c.Ready();
            await c.Expect(FrameType.Query); // no COPY_DATA, COPY_DONE or COPY_FAIL before it
            await c.Done();
            await c.Ready();
        }, async () =>
        {
            await using var cn = await ImdbConnection.ConnectAsync(m.Options());
            await T.ThrowsAsync<ImdbServerException>(() => cn.CopyInAsync("COPY t FROM STDIN", src), "refused before its data");
            T.Eq(0L, src.Position, "the source never read");
            await cn.QueryAsync("SELECT 1");
        });
    }

    private sealed class Slow : Stream
    {
        private readonly CancellationTokenSource _cts;
        private int _n;
        public Slow(CancellationTokenSource cts) => _cts = cts;

        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken ct = default)
        {
            if (++_n == 4) _cts.Cancel();
            await Task.Delay(30, CancellationToken.None);
            buffer.Span[0] = (byte)'1';
            buffer.Span[1] = (byte)'\n';
            return 2;
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

    // a cancel asked while uploading goes out before the next frame (§4), and the upload ends by COPY_FAIL
    private static async Task CopyCancel()
    {
        await using var m = new Mock("cc");
        using var cts = new CancellationTokenSource();
        await m.Run(async c =>
        {
            await c.Login();
            await c.Expect(FrameType.Query);
            await c.Send(Codec.EncodeEmpty(FrameType.CopyIn));
            var seen = new List<FrameType>();
            WireMessage? f;
            while ((f = await c.Next()) != null)
            {
                seen.Add(f.Type);
                if (f.Type is FrameType.CopyDone or FrameType.CopyFail) break;
            }
            int cancelAt = seen.IndexOf(FrameType.Cancel);
            T.Check(cancelAt >= 0 && cancelAt < seen.Count - 1, "CANCEL came before the COPY's end: " + string.Join(",", seen));
            T.Eq(FrameType.CopyFail, seen[^1], "the upload ended by COPY_FAIL");
            T.Check(seen.Count(t => t == FrameType.CopyData) <= 4, "no data read after the cancel: " + string.Join(",", seen));
            await c.Send(new ErrorMessage(15, 0, "COPY ... FROM STDIN failed by its client: cancelled by its client"));
            await c.Ready();
        }, async () =>
        {
            await using var cn = await ImdbConnection.ConnectAsync(m.Options());
            await T.ThrowsAsync<OperationCanceledException>(() => cn.CopyInAsync("COPY t FROM STDIN", new Slow(cts), cts.Token), "cancelled mid-upload");
        });
    }

    private static async Task OutOfTurn()
    {
        await using var m = new Mock("oot");
        await m.Run(async c =>
        {
            await c.Login();
            await c.Expect(FrameType.Query);
            await c.Expect(FrameType.Ping); // asked while the QUERY waits for its answer
            await c.Send(Codec.EncodeEmpty(FrameType.Pong)); // answered out of turn, before the QUERY's replies
            await Task.Delay(200);
            await c.Done();
            await c.Ready();
            await c.Expect(FrameType.Sessions);
            await c.Send(new SessionsListMessage(new[] { new ImdbSession(5, 9, ImdbEndpoint.Socket, ImdbSessionState.Idle, 1234, "alice") }));
            var k = (KillMessage)await c.Expect(FrameType.Kill);
            T.Check(k.Kind == ImdbKillKind.Terminate && k.SessionId == 5, "KILL terminate 5");
            await c.Send(new KillDoneMessage(1, 5));
        }, async () =>
        {
            await using var cn = await ImdbConnection.ConnectAsync(m.Options());
            var q = cn.QueryAsync("SELECT 1");
            await Task.Delay(100);
            await cn.PingAsync();
            T.Check(!q.IsCompleted, "the PONG came while the request was outstanding");
            await q;
            var s = await cn.SessionsAsync();
            T.Check(s.Single() == new ImdbSession(5, 9, ImdbEndpoint.Socket, ImdbSessionState.Idle, 1234, "alice"), "SESSIONS_LIST read");
            T.Check(!await cn.KillAsync(5, ImdbKillKind.Terminate), "KILL_DONE 1: no such session");
        });
    }

    private static async Task OutOfOrder()
    {
        await using var m = new Mock("ooo");
        await m.Run(async c =>
        {
            await c.Login();
            await c.Expect(FrameType.Query);
            await c.Done();
            await c.Done(); // a second DONE for one statement
            await c.Ready();
            await Task.Delay(200);
        }, async () =>
        {
            await using var cn = await ImdbConnection.ConnectAsync(m.Options());
            var e = await T.ThrowsAsync<ImdbProtocolException>(() => cn.QueryAsync("SELECT 1"), "two DONEs");
            T.Check(e.Message.Contains("order", StringComparison.Ordinal) && !cn.IsOpen, e.Message);
        });
        await m.Run(async c =>
        {
            await c.Login();
            await c.Send(Codec.EncodeEmpty(FrameType.Pong)); // nobody asked
            await Task.Delay(300);
        }, async () =>
        {
            await using var cn = await ImdbConnection.ConnectAsync(m.Options());
            for (int i = 0; i < 50 && cn.IsOpen; i++) await Task.Delay(20);
            var e = await T.ThrowsAsync<ImdbProtocolException>(() => cn.QueryAsync("SELECT 1"), "an unasked PONG");
            T.Check(e.Message.Contains("asked", StringComparison.Ordinal), e.Message);
        });
        await m.Run(async c =>
        {
            await c.Login();
            await c.Expect(FrameType.Query);
            await c.Send(new ErrorMessage(6, 1, "a constraint")); // index 1 in a batch of one: no statement 1
            await c.Ready();
            await Task.Delay(200);
        }, async () =>
        {
            await using var cn = await ImdbConnection.ConnectAsync(m.Options());
            await T.ThrowsAsync<ImdbProtocolException>(() => cn.QueryAsync("SELECT 1"), "an ERROR's index past its batch");
        });
    }

    private static async Task ReplyTimeout()
    {
        await using var m = new Mock("rt");
        await m.Run(async c =>
        {
            await c.Login();
            await c.Expect(FrameType.Query);
            await Task.Delay(1000); // never answers in time
        }, async () =>
        {
            await using var cn = await ImdbConnection.ConnectAsync(m.Options(TimeSpan.FromMilliseconds(300)));
            var sw = System.Diagnostics.Stopwatch.StartNew();
            var e = await T.ThrowsAsync<ImdbException>(() => cn.QueryAsync("SELECT 1"), "no reply");
            T.Check(e.Code == 1 && sw.ElapsedMilliseconds < 5000 && !cn.IsOpen, $"code 1 after {sw.ElapsedMilliseconds} ms: {e.Message}");
        });
    }
}
