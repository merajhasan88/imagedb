using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;

namespace Imagedb.Client.Wire;

/// <summary>IMDBWIR1's frames over a stream (the protocol's level under <see cref="ImdbConnection"/>): a frame's head is
/// checked (its length 1 to 16 MiB, a type of the direction's) before its body is allocated. Reading and writing may
/// run at once (one reader, one writer: SslStream and NetworkStream take that); two writers or two readers may not.</summary>
public sealed class ImdbFrameStream : IAsyncDisposable
{
    private readonly Stream _s;
    private readonly byte[] _head = new byte[Protocol.HeadLength];

    public ImdbFrameStream(Stream stream) => _s = stream ?? throw new ArgumentNullException(nameof(stream));

    /// <summary>The stream underneath (an authenticated connection's socket or TLS session).</summary>
    public Stream Stream => _s;

    /// <summary>The next frame, or null when the peer closed at a frame's boundary. A frame cut short is an
    /// <see cref="ImdbConnectionClosedException"/>; a head or body the decoders refuse is an
    /// <see cref="ImdbProtocolException"/> (the body is not decoded here: <see cref="Codec.DecodeServerBody"/>).</summary>
    public async ValueTask<(FrameType Type, byte[] Body)?> ReadFrameAsync(bool fromServer, CancellationToken ct = default)
    {
        int got = await _s.ReadAtLeastAsync(_head, _head.Length, throwOnEndOfStream: false, ct).ConfigureAwait(false);
        if (got == 0) return null;
        if (got < _head.Length) throw new ImdbConnectionClosedException("the connection: closed inside a frame's head");
        var t = Codec.DecodeHead(_head, fromServer, out int len);
        var body = len > 1 ? new byte[len - 1] : Array.Empty<byte>();
        if (body.Length > 0)
        {
            try
            {
                await _s.ReadExactlyAsync(body, ct).ConfigureAwait(false);
            }
            catch (EndOfStreamException e)
            {
                throw new ImdbConnectionClosedException($"the connection: closed inside a {t} frame", null, e);
            }
        }
        return (t, body);
    }

    /// <summary>Encoded frames, written as they are.</summary>
    public async ValueTask WriteAsync(ReadOnlyMemory<byte> frames, CancellationToken ct = default)
    {
        await _s.WriteAsync(frames, ct).ConfigureAwait(false);
        await _s.FlushAsync(ct).ConfigureAwait(false);
    }

    public ValueTask DisposeAsync() => _s.DisposeAsync();
}
