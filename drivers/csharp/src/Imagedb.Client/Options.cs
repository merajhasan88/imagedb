using System;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using Imagedb.Client.Wire;

namespace Imagedb.Client;

/// <summary>How a TCP connection verifies the server: a CA file (the host, or <see cref="ServerName"/>, checked against
/// the certificate's subjectAltName) or a pin (the server key's SPKI SHA-256, as `imagedb-server cert` prints it; it
/// survives `cert --renew`, which keeps the key). Exactly one, by construction: there is no unverified mode, no
/// callback of the caller's, and no fallback to plaintext or to the socket.</summary>
public sealed class ImdbTls
{
    private ImdbTls(X509Certificate2? ca, byte[]? pin, string? serverName)
    {
        Ca = ca;
        Pin = pin;
        ServerName = serverName;
    }

    internal X509Certificate2? Ca { get; }
    internal byte[]? Pin { get; }

    /// <summary>The name checked against the certificate's subjectAltName (a CA's mode): the host connected to when
    /// null. A name or an address literal.</summary>
    public string? ServerName { get; }

    public bool IsPinned => Pin != null;

    /// <summary>A CA certificate's file, PEM or DER (`imagedb-server cert` writes SDIR/tls/ca.crt).</summary>
    public static ImdbTls FromCaFile(string path, string? serverName = null)
    {
        ArgumentNullException.ThrowIfNull(path);
        byte[] raw = File.ReadAllBytes(path);
        string text = System.Text.Encoding.ASCII.GetString(raw);
        var ca = text.Contains("-----BEGIN CERTIFICATE-----", StringComparison.Ordinal)
            ? X509Certificate2.CreateFromPem(text)
            : X509CertificateLoader.LoadCertificate(raw);
        return new ImdbTls(ca, null, serverName);
    }

    public static ImdbTls FromCaCertificate(X509Certificate2 ca, string? serverName = null)
    {
        ArgumentNullException.ThrowIfNull(ca);
        return new ImdbTls(ca, null, serverName);
    }

    /// <summary>A pin: 64 hexadecimal digits (the server key's SPKI SHA-256).</summary>
    public static ImdbTls FromPin(string hex)
    {
        ArgumentNullException.ThrowIfNull(hex);
        if (hex.Length != 64) throw new ArgumentException("a pin is 64 hexadecimal digits (the SPKI's SHA-256)", nameof(hex));
        return FromPin(Convert.FromHexString(hex));
    }

    public static ImdbTls FromPin(ReadOnlySpan<byte> pin)
    {
        if (pin.Length != 32) throw new ArgumentException("a pin is 32 bytes (the SPKI's SHA-256)", nameof(pin));
        return new ImdbTls(null, pin.ToArray(), null);
    }
}

/// <summary>Where and as whom to connect: the server's Unix-domain socket (no TLS: no negotiation exists to downgrade),
/// or TCP with TLS 1.3 (<see cref="Tls"/> required). A client never falls back from one to the other.</summary>
public sealed class ImdbConnectOptions
{
    /// <summary>The server's socket (--socket PATH).</summary>
    public string? SocketPath { get; init; }

    /// <summary>The server's TCP host (--tcp ADDR:PORT), with <see cref="Port"/> and <see cref="Tls"/>.</summary>
    public string? Host { get; init; }

    public int Port { get; init; }

    public ImdbTls? Tls { get; init; }

    /// <summary>A role's name: 1 to 63 bytes of UTF-8.</summary>
    public string User { get; init; } = "";

    /// <summary>The role's password: 1 to 1,024 bytes of printable ASCII, as CREATE ROLE takes one.</summary>
    public string Password { get; init; } = "";

    /// <summary>The bound on the TCP connect, the TLS handshake and the login together.</summary>
    public TimeSpan ConnectTimeout { get; init; } = TimeSpan.FromSeconds(30);

    /// <summary>A bound on each wait for a reply while a request is outstanding (null: none, the default): past it the
    /// connection is ended (a frame may be part read) and the call fails with code 1.</summary>
    public TimeSpan? ReplyTimeout { get; init; }

    internal void Validate()
    {
        if ((SocketPath == null) == (Host == null))
            throw new ArgumentException("a socket path or a host, exactly one");
        if (SocketPath != null && Tls != null)
            throw new ArgumentException("the Unix-domain socket has no TLS (nothing to verify): give Tls for a host alone");
        if (Host != null)
        {
            if (Tls == null) throw new ArgumentException("TCP is TLS 1.3 alone: give Tls (a CA file or a pin; no unverified mode)");
            if (Port < 1 || Port > 65535) throw new ArgumentException("a TCP port of 1 to 65,535");
        }
        if (!Codec.UserOk(User, out _)) throw new ArgumentException("a role's name is 1 to 63 bytes of UTF-8 without NUL");
        if (Password == null || !Codec.PasswordOk(System.Text.Encoding.Latin1.GetBytes(Password)) || HasNonAscii(Password))
            throw new ArgumentException("a password is 1 to 1,024 bytes of printable ASCII (as CREATE ROLE takes one)");
    }

    private static bool HasNonAscii(string s)
    {
        foreach (char c in s)
            if (c > 0x7e) return true;
        return false;
    }
}
