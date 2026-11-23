using System;
using System.Buffers.Binary;
using System.Text;

namespace Imagedb.Client.Wire;

/// <summary>A bounded reader over received bytes (the C codec's imdb_rd): each read past the end refuses the whole
/// message as cut short, never a partial value.</summary>
internal ref struct ByteReader
{
    private readonly ReadOnlySpan<byte> _p;
    private int _off;

    public ByteReader(ReadOnlySpan<byte> p)
    {
        _p = p;
        _off = 0;
    }

    public readonly int Left => _p.Length - _off;
    public readonly int Offset => _off;

    private ReadOnlySpan<byte> Take(int n)
    {
        if (n < 0 || n > _p.Length - _off) throw Codec.Corrupt("a message cut short");
        var s = _p.Slice(_off, n);
        _off += n;
        return s;
    }

    public byte U8() => Take(1)[0];
    public ushort U16() => BinaryPrimitives.ReadUInt16LittleEndian(Take(2));
    public uint U32() => BinaryPrimitives.ReadUInt32LittleEndian(Take(4));
    public ulong U64() => BinaryPrimitives.ReadUInt64LittleEndian(Take(8));
    public Int128 I128() => BinaryPrimitives.ReadInt128LittleEndian(Take(16));
    public ReadOnlySpan<byte> Bytes(int n) => Take(n);
    public readonly ReadOnlySpan<byte> Slice(int from, int to) => _p.Slice(from, to - from);
}

/// <summary>A growable output buffer for one or more frames, never past a frame's bound (16 MiB and its head).</summary>
internal sealed class ByteWriter
{
    private byte[] _p;
    private int _len;

    public ByteWriter(int cap = 256) => _p = new byte[Math.Max(cap, 16)];

    public int Length => _len;

    private Span<byte> Reserve(int n)
    {
        if ((long)_len + n > Protocol.FrameMax + Protocol.HeadLength)
            throw new ImdbException((int)ImdbErrorCode.Limit, "IMDBWIR1: a frame past 16 MiB (its values travel in one frame)");
        if (_len + n > _p.Length)
        {
            long cap = _p.Length;
            while (cap < _len + n) cap *= 2;
            var q = new byte[Math.Min(cap, (long)Protocol.FrameMax + Protocol.HeadLength)];
            _p.AsSpan(0, _len).CopyTo(q);
            _p = q;
        }
        var s = _p.AsSpan(_len, n);
        _len += n;
        return s;
    }

    public void U8(byte v) => Reserve(1)[0] = v;
    public void U16(ushort v) => BinaryPrimitives.WriteUInt16LittleEndian(Reserve(2), v);
    public void U32(uint v) => BinaryPrimitives.WriteUInt32LittleEndian(Reserve(4), v);
    public void U64(ulong v) => BinaryPrimitives.WriteUInt64LittleEndian(Reserve(8), v);
    public void I128(Int128 v) => BinaryPrimitives.WriteInt128LittleEndian(Reserve(16), v);
    public void Bytes(ReadOnlySpan<byte> b)
    {
        if (b.Length > 0) b.CopyTo(Reserve(b.Length));
    }

    /// <summary>A frame's head, its length patched by <see cref="EndFrame"/>.</summary>
    public int BeginFrame(FrameType t)
    {
        int at = _len;
        var h = Reserve(Protocol.HeadLength);
        h.Clear();
        h[4] = (byte)t;
        return at;
    }

    public void EndFrame(int at)
    {
        long n = _len - at - 4; // its type and body
        if (n < 1 || n > Protocol.FrameMax)
            throw new ImdbException((int)ImdbErrorCode.Limit, "IMDBWIR1: a frame past 16 MiB (its values travel in one frame)");
        BinaryPrimitives.WriteUInt32LittleEndian(_p.AsSpan(at, 4), (uint)n);
    }

    public byte[] ToArray() => _p.AsSpan(0, _len).ToArray();
    public ReadOnlyMemory<byte> Memory => _p.AsMemory(0, _len);
}

/// <summary>UTF-8 by the engine's rule (codec.c's imdb_utf8_valid, wire.c's utf8_valid): no NUL, no overlong form, no
/// surrogate, nothing past U+10FFFF. Validated by hand, scalar, as the C codec does, so the verdict is the engine's;
/// .NET's own decoder then reads bytes already known good, and its encoder (throwing) refuses a lone surrogate.</summary>
public static class StrictUtf8
{
    private static readonly UTF8Encoding Throwing = new(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true);

    /// <summary>True when the bytes are UTF-8 without NUL; <paramref name="bad"/> the first byte of the first character
    /// that is not one (the length when all are).</summary>
    public static bool IsValid(ReadOnlySpan<byte> s, out int bad)
    {
        int i = 0, n = s.Length;
        while (i < n)
        {
            byte c = s[i];
            if (c >= 0x01 && c < 0x80)
            {
                i++;
                continue;
            }
            int need;
            byte lo = 0x80, hi = 0xBF;
            if (c >= 0xC2 && c <= 0xDF) need = 1;
            else if (c == 0xE0) { need = 2; lo = 0xA0; }
            else if (c >= 0xE1 && c <= 0xEC) need = 2;
            else if (c == 0xED) { need = 2; hi = 0x9F; }
            else if (c == 0xEE || c == 0xEF) need = 2;
            else if (c == 0xF0) { need = 3; lo = 0x90; }
            else if (c >= 0xF1 && c <= 0xF3) need = 3;
            else if (c == 0xF4) { need = 3; hi = 0x8F; }
            else { bad = i; return false; } // NUL, C0, C1, F5..FF, a stray continuation
            if (need > n - i - 1 || s[i + 1] < lo || s[i + 1] > hi) { bad = i; return false; }
            for (int j = 2; j <= need; j++)
                if ((s[i + j] & 0xC0) != 0x80) { bad = i; return false; }
            i += need + 1;
        }
        bad = n;
        return true;
    }

    public static bool IsValid(ReadOnlySpan<byte> s) => IsValid(s, out _);

    /// <summary>Characters (code points) in valid UTF-8: the bytes that begin one (a VARCHAR's length is counted so).</summary>
    public static int CountChars(ReadOnlySpan<byte> s)
    {
        int k = 0;
        foreach (byte b in s) k += (b & 0xC0) != 0x80 ? 1 : 0;
        return k;
    }

    /// <summary>The bytes as a string, or null when they are not UTF-8 without NUL.</summary>
    public static string? Decode(ReadOnlySpan<byte> s) => IsValid(s) ? Encoding.UTF8.GetString(s) : null;

    /// <summary>A string's UTF-8: refused (ArgumentException) when it holds a lone surrogate or a NUL, which no imagedb
    /// text holds.</summary>
    public static byte[] Encode(string s, string what)
    {
        ArgumentNullException.ThrowIfNull(s, what);
        if (s.Contains('\0', StringComparison.Ordinal))
            throw new ArgumentException($"{what}: a NUL character, which no imagedb text holds", what);
        try
        {
            return Throwing.GetBytes(s);
        }
        catch (EncoderFallbackException e)
        {
            throw new ArgumentException($"{what}: not a valid Unicode string (a lone surrogate)", what, e);
        }
    }

    /// <summary>The longest prefix of s within max bytes that is UTF-8 without NUL, never cut inside a character
    /// (wire.c's imdbw_utf8_fit).</summary>
    public static int Fit(ReadOnlySpan<byte> s, int max)
    {
        int k = Math.Min(s.Length, max);
        if (k == 0) return 0;
        return IsValid(s[..k], out int bad) ? k : bad;
    }
}
