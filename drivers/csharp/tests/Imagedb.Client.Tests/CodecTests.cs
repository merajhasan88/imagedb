using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Numerics;
using System.Text;
using System.Threading.Tasks;
using Imagedb.Client.Wire;

namespace Imagedb.Client.Tests;

/// <summary>The codec against tests/unit/t_wire.c's vectors (the contract, §4): copied byte for byte with their line
/// ranges, and each copy checked to appear verbatim in t_wire.c (IMDB_DRV_T_WIRE; so a copy that drifted
/// from its source fails here).</summary>
public static class CodecTests
{

    public static IEnumerable<TestCase> All()
    {
        yield return new("codec", "value_vectors", () => Run(ValueVectors));
        yield return new("codec", "value_native_views", () => Run(ValueNative));
        yield return new("codec", "value_refused", () => Run(ValueRefused));
        yield return new("codec", "decimal_range", () => Run(DecimalRange));
        yield return new("codec", "scram_pinned_exchanges", () => Run(ScramPinned));
        yield return new("codec", "scram_server_side", () => Run(ScramServerSide));
        yield return new("codec", "preauth_messages", () => Run(Preauth));
        yield return new("codec", "frame_heads", () => Run(Heads));
        yield return new("codec", "frame_bodies_t_wire_bounds", () => Run(Bodies));
        yield return new("codec", "client_encoders_exact", () => Run(ClientEncoders));
        yield return new("codec", "server_frames_flipped", () => Run(ServerFlips));
        yield return new("codec", "server_bodies_random", () => Run(ServerRandom));
        yield return new("codec", "utf8_against_dotnet", () => Run(Utf8));
        yield return new("codec", "native_types", () => Run(NativeTypes));
        yield return new("codec", "vectors_match_t_wire_source", () => Run(Drift));
    }

    private static Task Run(Action a)
    {
        a();
        return Task.CompletedTask;
    }

    private static readonly byte[] Uuid0F = Enumerable.Range(0, 16).Select(i => (byte)i).ToArray();

    // t_wire.c lines 55-84 (kVecs): each type's bytes
    private static readonly (ImdbValue V, string Hex)[] Vecs =
    {
        (ImdbValue.Null(), "80"),
        (ImdbValue.Null(ImdbType.Int64), "81"),
        (ImdbValue.Null(ImdbType.Decimal), "85"),
        (ImdbValue.Null(ImdbType.Enum), "8d"),
        (ImdbValue.FromInt64(-2), "01 feffffffffffffff"),
        (ImdbValue.FromInt64(long.MinValue), "01 0000000000000080"),
        (ImdbValue.FromFloat64Bits(0x3ff8000000000000UL), "02 000000000000f83f"),
        (ImdbValue.FromFloat64Bits(0), "02 0000000000000000"),
        (ImdbValue.FromBool(true), "03 01"),
        (ImdbValue.FromBool(false), "03 00"),
        (ImdbValue.FromText("hé"), "04 03000000 68c3a9"),
        (ImdbValue.FromText(""), "04 00000000"),
        (ImdbValue.FromDecimal(new ImdbDecimal(-12345, 2)), "05 02 c7cfffffffffffffffffffffffffffff"),
        (ImdbValue.FromDecimal(new ImdbDecimal(0, 0)), "05 00 00000000000000000000000000000000"),
        (ImdbValue.FromTimestampMicros(1), "06 0100000000000000"),
        (ImdbValue.FromTimestampMicros(-62135596800000000L), "06 0040d400014023ff"),
        (ImdbValue.FromTimestampTzMicros(-1), "07 ffffffffffffffff"),
        (ImdbValue.FromTimestampTzMicros(253402300799999999L), "07 ff5f73cc0c448403"),
        (ImdbValue.FromDateDays(-719162), "08 c606f5ff"),
        (ImdbValue.FromDateDays(2932896), "08 a0c02c00"),
        (ImdbValue.FromTimeMicros(0), "09 0000000000000000"),
        (ImdbValue.FromTimeMicros(86399999999L), "09 ff5fd71d14000000"),
        (ImdbValue.FromUuidBytes(Uuid0F), "0a 000102030405060708090a0b0c0d0e0f"),
        (ImdbValue.FromBytea(new byte[] { 0x00, 0xff }), "0b 02000000 00ff"),
        (ImdbValue.FromInterval(1, -2, 3), "0c 01000000 feffffff 0300000000000000"),
        (ImdbValue.FromInterval(int.MinValue, int.MaxValue, long.MinValue), "0c 00000080 ffffff7f 0000000000000080"),
        (ImdbValue.FromEnum("a"), "0d 01 61"),
        (ImdbValue.FromEnum(""), "0d 00"),
    };

    private static void ValueVectors()
    {
        foreach (var (v, hex) in Vecs)
        {
            var want = T.Hex(hex);
            T.Bytes(want, Codec.EncodeValue(v), "encode " + hex);
            var got = Codec.DecodeValue(want, out int used);
            T.Eq(want.Length, used, "consumed " + hex);
            T.Check(got.Equals(v), "decode " + hex);
            for (int cut = 0; cut < want.Length; cut++)
            {
                int c = cut;
                T.Throws<ImdbProtocolException>(() => Codec.DecodeValue(want.AsSpan(0, c), out _), $"prefix {cut} of {hex}");
            }
        }
    }

    // the same vectors read as .NET's types
    private static void ValueNative()
    {
        T.Eq(1.5, Codec.DecodeValue(T.Hex("02 000000000000f83f"), out _).AsFloat64(), "1.5");
        T.Eq("-123.45", Codec.DecodeValue(T.Hex("05 02 c7cfffffffffffffffffffffffffffff"), out _).AsDecimal().ToString(), "-123.45");
        T.Eq(new DateTime(1, 1, 1, 0, 0, 0, DateTimeKind.Unspecified), Codec.DecodeValue(T.Hex("06 0040d400014023ff"), out _).AsTimestamp(), "0001-01-01");
        var tz = Codec.DecodeValue(T.Hex("07 ff5f73cc0c448403"), out _).AsTimestampTz();
        T.Eq(new DateTimeOffset(9999, 12, 31, 23, 59, 59, TimeSpan.Zero).AddTicks(9999990), tz, "9999-12-31 23:59:59.999999");
        T.Eq(TimeSpan.Zero, tz.Offset, "the instant at offset 0");
        T.Eq(new DateOnly(1, 1, 1), Codec.DecodeValue(T.Hex("08 c606f5ff"), out _).AsDate(), "DATE 0001-01-01");
        T.Eq(new DateOnly(9999, 12, 31), Codec.DecodeValue(T.Hex("08 a0c02c00"), out _).AsDate(), "DATE 9999-12-31");
        T.Eq(new TimeOnly(23, 59, 59).Add(TimeSpan.FromTicks(9999990)), Codec.DecodeValue(T.Hex("09 ff5fd71d14000000"), out _).AsTime(), "23:59:59.999999");
        T.Eq(Guid.Parse("00010203-0405-0607-0809-0a0b0c0d0e0f"), Codec.DecodeValue(T.Hex("0a 000102030405060708090a0b0c0d0e0f"), out _).AsUuid(),
             "UUID in RFC 4122 order");
        T.Bytes(T.Hex("0a 000102030405060708090a0b0c0d0e0f"), Codec.EncodeValue(ImdbValue.FromUuid(Guid.Parse("00010203-0405-0607-0809-0a0b0c0d0e0f"))),
                "a Guid sent big-endian");
        T.Eq(new ImdbInterval(1, -2, 3), Codec.DecodeValue(T.Hex("0c 01000000 feffffff 0300000000000000"), out _).AsInterval(), "1 mon -2 days 3 us");
        // the native constructors give the same bytes as the raw ones
        T.Bytes(T.Hex("06 0040d400014023ff"), Codec.EncodeValue(ImdbValue.FromTimestamp(new DateTime(1, 1, 1))), "DateTime 0001-01-01");
        T.Bytes(T.Hex("07 ff5f73cc0c448403"), Codec.EncodeValue(ImdbValue.FromTimestampTz(tz)), "DateTimeOffset 9999-12-31 23:59:59.999999");
        T.Bytes(T.Hex("08 a0c02c00"), Codec.EncodeValue(ImdbValue.FromDate(new DateOnly(9999, 12, 31))), "DateOnly");
        T.Bytes(T.Hex("09 ff5fd71d14000000"), Codec.EncodeValue(ImdbValue.FromTime(new TimeOnly(863999999990L))), "TimeOnly");
        T.Bytes(T.Hex("05 02 c7cfffffffffffffffffffffffffffff"), Codec.EncodeValue(ImdbValue.FromObject(-123.45m)), "System.Decimal -123.45");
        T.Bytes(T.Hex("02 000000000000f83f"), Codec.EncodeValue(ImdbValue.FromObject(1.5)), "double 1.5");
        T.Bytes(T.Hex("04 03000000 68c3a9"), Codec.EncodeValue(ImdbValue.FromObject("hé")), "string");
        T.Bytes(T.Hex("80"), Codec.EncodeValue(ImdbValue.FromObject(null)), "null: a NULL of no type");
    }

    // t_wire.c lines 122-143 (refused), 153 (limit), 168-182 (the encoder's refusals)
    private static readonly string[] Refused =
    {
        "03 02", "02 000000000000f07f", "02 000000000000f0ff", "02 010000000000f87f", "02 0000000000000080",
        "06 ff3fd400014023ff", "07 006073cc0c448403", "09 ffffffffffffffff", "09 0060d71d14000000", "08 c506f5ff",
        "08 a1c02c00", "04 01000000 ff", "04 01000000 00", "04 02000000 c0af", "0d 01 c3", "0d 01 00", "0e", "00", "8e",
        "ff", "",
    };

    private static readonly string[] LimitRefused = { "04 00000100", "0b 00000100", "0d 40" };

    private static void ValueRefused()
    {
        foreach (var hex in Refused)
        {
            var b = T.Hex(hex);
            T.Throws<ImdbProtocolException>(() => Codec.DecodeValue(b, out _), "refused " + hex);
        }
        foreach (var hex in LimitRefused)
        {
            var b = T.Hex(hex);
            var e = T.Throws<ImdbProtocolException>(() => Codec.DecodeValue(b, out _), "limit " + hex);
            T.Eq(ImdbErrorCode.Limit, e.Kind, "a length past its bound is a limit, before its bytes: " + hex);
        }
        // the encoder refuses what the decoder would (here: the factories and the parameter rule)
        T.Throws<ArgumentException>(() => ImdbValue.FromFloat64(-0.0), "-0");
        T.Throws<ArgumentException>(() => ImdbValue.FromFloat64(double.NaN), "NaN");
        T.Throws<ArgumentException>(() => ImdbValue.FromFloat64(double.PositiveInfinity), "+inf");
        T.Throws<ArgumentException>(() => ImdbValue.FromText("\ud800"), "a lone surrogate");
        T.Throws<ArgumentException>(() => ImdbValue.FromText("a\0b"), "a NUL");
        T.Throws<ArgumentException>(() => ImdbValue.FromText(new string('a', 65536)), "65,536 bytes");
        ImdbValue.FromText(new string('a', 65535));
        T.Throws<ArgumentException>(() => ImdbValue.FromText(new string('é', 32768)), "65,536 bytes of two-byte characters");
        T.Throws<ArgumentException>(() => ImdbValue.FromEnum(new string('0', 64)), "a label of 64 bytes");
        T.Throws<ArgumentException>(() => new ImdbDecimal(1, 39), "scale 39");
        T.Throws<ArgumentException>(() => ImdbValue.FromDateDays(2932897), "a DATE after 9999-12-31");
        T.Throws<ArgumentException>(() => ImdbValue.FromTimestampMicros(long.MaxValue), "TIMESTAMP past 9999");
        T.Throws<ArgumentException>(() => ImdbValue.FromTimestampTzMicros(Protocol.TimestampMin - 1), "TIMESTAMPTZ before year 1");
        T.Throws<ArgumentException>(() => ImdbValue.FromTimeMicros(86400000000L), "TIME of a day");
        T.Throws<ArgumentException>(() => ImdbValue.FromTimeMicros(-1), "TIME -1");
        T.Throws<ArgumentException>(() => ImdbValue.FromUuidBytes(new byte[15]), "UUID of 15 bytes");
        T.Throws<ArgumentException>(() => ImdbValue.Null((ImdbType)14), "a NULL of type 14");
        T.Throws<ArgumentException>(() => Codec.EncodeQuery(new[] { new ImdbStatement("a", new[] { ImdbValue.FromEnum("a") }) }),
                                    "an ENUM parameter: a label goes as TEXT");
    }

    // t_wire.c lines 99-112: 10^38 - 1 and its negation taken, 10^38 and -10^38 refused, scale 39 refused
    private static void DecimalRange()
    {
        var lim = ImdbDecimal.Limit;
        Int128[] ds = { lim - 1, -(lim - 1), lim, -lim };
        for (int k = 0; k < 4; k++)
        {
            var x = new byte[18];
            x[0] = 5;
            x[1] = 38;
            System.Buffers.Binary.BinaryPrimitives.WriteInt128LittleEndian(x.AsSpan(2), ds[k]);
            if (k < 2) Codec.DecodeValue(x, out _);
            else T.Throws<ImdbProtocolException>(() => Codec.DecodeValue(x, out _), "10^38 refused");
            x[1] = 39;
            T.Throws<ImdbProtocolException>(() => Codec.DecodeValue(x, out _), "scale 39 refused");
        }
        T.Eq("99999999999999999999999999999999.999999", new ImdbDecimal(lim - 1, 6).ToString(), "38 digits at scale 6");
        T.Eq(new ImdbDecimal(lim - 1, 6), ImdbDecimal.Parse("99999999999999999999999999999999.999999"), "parsed back");
        T.Check(!ImdbDecimal.TryParse("100000000000000000000000000000000000000", out _), "39 digits refused");
        T.Eq("-0.05", ImdbDecimal.Parse("-0.05").ToString(), "-0.05");
        T.Eq("0", ImdbDecimal.Parse("-0").ToString(), "one zero");
        T.Eq(new ImdbDecimal(150, 2), ImdbDecimal.FromDecimal(1.50m), "System.Decimal's scale kept");
        T.Eq(1.50m, new ImdbDecimal(150, 2).ToDecimal(), "back to System.Decimal");
        T.Eq(79228162514264337593543950335m, ImdbDecimal.FromDecimal(decimal.MaxValue).ToDecimal(), "decimal.MaxValue round trip");
        T.Throws<OverflowException>(() => new ImdbDecimal(lim - 1, 0).ToDecimal(), "38 digits do not fit System.Decimal");
        T.Check(new ImdbDecimal(15, 1).NumericEquals(new ImdbDecimal(150, 2)) && !new ImdbDecimal(15, 1).Equals(new ImdbDecimal(150, 2)),
                "1.5 and 1.50: one number, two wire forms");
        T.Eq((BigInteger)(lim - 1), new ImdbDecimal(lim - 1, 0).ToBigIntegerUnscaled(), "BigInteger");
    }

    // t_wire.c lines 415-470 (t_wire_scram): the pinned exchanges, computed by a program of OpenSSL alone
    private static (byte[] Hello, byte[] Challenge, Challenge C) ScramInputs(ChannelBindingType flags)
    {
        var hello = Codec.EncodeHello(flags, "alice", Enumerable.Repeat((byte)0x01, 32).ToArray());
        var salt = Enumerable.Repeat((byte)0x03, 16).ToArray();
        var ch = Codec.EncodeChallenge(salt, 4096, Enumerable.Repeat((byte)0x02, 32).ToArray());
        return (hello, ch, Codec.DecodeChallenge(ch));
    }

    private static readonly (ImdbEndpoint Ep, ChannelBindingType Flags, byte Bind, string Proof, string Sig)[] Pinned =
    {
        (ImdbEndpoint.Tcp, ChannelBindingType.Exporter, 0x04, "28562c1bef99b0a917ecb28c1b32c22930f154f92c134b13fee7a64e8deb733e",
         "5d3ef834c39e6c429d1f4e27993ba451a8b8e35322af9055abc1dd40e88ad322"),
        (ImdbEndpoint.Tcp, ChannelBindingType.ServerEndPoint, 0x05, "1065f5e038b75f2671d831f5bd5d29f56d22a787f260db523bb986ef7c53f486",
         "28fef60553090aae9b5f184bfc0cfb455e58261131da359f525a59f4dfaa9904"),
        (ImdbEndpoint.Socket, ChannelBindingType.None, 0x00, "5ee7e7bd402f0c91e2399a84c3d544763bace50b44ea82a780e57130bb5405a7",
         "82c9d498cc5fa830d26b29740244ecf4f343962f302a647150e9d74ea7588027"),
    };

    private static void ScramPinned()
    {
        foreach (var p in Pinned)
        {
            var (hello, ch, c) = ScramInputs(p.Flags);
            T.Eq((byte)p.Flags, hello[12], "the hello's flags byte: its binding type");
            var bind = Enumerable.Repeat(p.Bind, 32).ToArray();
            var am = Codec.AuthMessage(p.Ep, hello, ch, bind);
            // the AuthMessage laid out by hand: the magic, the endpoint, the two messages, the binding
            var want = new byte[279];
            Encoding.ASCII.GetBytes("IMDBWIR1-SCRAM").CopyTo(want, 0);
            want[14] = (byte)p.Ep;
            hello.CopyTo(want, 15);
            ch.CopyTo(want, 127);
            bind.CopyTo(want, 247);
            T.Bytes(want, am, "the AuthMessage's layout");
            var (proof, sig) = Codec.ScramClient("pencil"u8, c, am);
            T.Bytes(T.Hex(p.Proof), proof, $"ClientProof ({p.Ep}, flags {p.Flags})");
            T.Bytes(T.Hex(p.Sig), sig, $"ServerSignature ({p.Ep}, flags {p.Flags})");
        }
        T.Bytes(Encoding.ASCII.GetBytes("IMDBWIR1\x01\0\0\0\0\0\0\0alice"), ScramInputs(ChannelBindingType.None).Hello.AsSpan(0, 21),
                "t_wire.c line 230: the hello's first 21 bytes");
    }

    private static void ScramServerSide()
    {
        var (hello, ch, c) = ScramInputs(ChannelBindingType.Exporter);
        var bind = Enumerable.Repeat((byte)0x04, 32).ToArray();
        var am = Codec.AuthMessage(ImdbEndpoint.Tcp, hello, ch, bind);
        var (proof, sig) = Codec.ScramClient("pencil"u8, c, am);
        var (stored, skey) = Codec.ScramVerifier("pencil"u8, c.Salt, 4096);
        T.Check(Codec.ScramServer(stored, skey, am, proof, out var s2) && s2.AsSpan().SequenceEqual(sig), "the server takes the proof");
        // t_wire.c lines 486-495: a proof over a hello whose type byte alone differs is refused
        for (byte fl = 0; fl <= 2; fl++)
        {
            var h2 = (byte[])hello.Clone();
            h2[12] = fl;
            var am2 = Codec.AuthMessage(ImdbEndpoint.Tcp, h2, ch, bind);
            T.Eq(fl == 1, Codec.ScramServer(stored, skey, am2, proof, out _), $"the server's hello says {fl}, the proof's 1");
        }
        for (int bit = 0; bit < 256; bit++)
        {
            var p2 = (byte[])proof.Clone();
            p2[bit / 8] ^= (byte)(1 << (bit % 8));
            T.Check(!Codec.ScramServer(stored, skey, am, p2, out _), "a proof with a bit off refused");
        }
        for (int i = 0; i < am.Length; i++)
        {
            var am2 = (byte[])am.Clone();
            am2[i] ^= 0x20;
            T.Check(!Codec.ScramServer(stored, skey, am2, proof, out _), "every byte of the AuthMessage is bound");
        }
        // t_wire.c lines 528-541: the client refuses a password CREATE ROLE would
        T.Throws<ArgumentException>(() => Codec.ScramClient(""u8, c, am), "an empty password");
        T.Throws<ArgumentException>(() => Codec.ScramClient("a\x7f"u8, c, am), "DEL");
        T.Throws<ArgumentException>(() => Codec.ScramClient("a\x1f"u8, c, am), "a control");
        T.Throws<ArgumentException>(() => Codec.ScramClient("é"u8, c, am), "not ASCII");
        T.Throws<ArgumentException>(() => Codec.ScramClient(Enumerable.Repeat((byte)'a', 1025).ToArray(), c, am), "1,025 bytes");
        Codec.ScramClient(Enumerable.Repeat((byte)'a', 1024).ToArray(), c, am);
        T.Throws<ArgumentException>(() => Codec.ScramClient("pencil"u8, c with { Iterations = 999 }, am), "999 iterations");
    }

    // t_wire.c lines 223-398 (t_wire_preauth)
    private static void Preauth()
    {
        var nonce = new byte[32];
        new Random(7).NextBytes(nonce);
        var hb = Codec.EncodeHello(ChannelBindingType.None, "alice", nonce);
        var g = Codec.DecodeHello(hb);
        T.Check(g.User == "alice" && g.Nonce.AsSpan().SequenceEqual(nonce) && g.Version == 1 && g.Flags == ChannelBindingType.None, "hello read back");
        int took = 0, refused = 0;
        for (int i = 0; i < hb.Length; i++)
            foreach (byte f in new byte[] { 0x01, 0x80, 0xff })
            {
                var x = (byte[])hb.Clone();
                x[i] ^= f;
                try
                {
                    var h = Codec.DecodeHello(x);
                    T.Bytes(x, Codec.EncodeHello(h.Flags, h.User, h.Nonce), "a hello taken encodes back to itself");
                    took++;
                }
                catch (ImdbProtocolException)
                {
                    refused++;
                }
            }
        T.Check(took >= 32 * 3 + 1 && refused >= 16 * 3, $"hello flips: {took} taken, {refused} refused");
        for (uint fl = 0; fl < 5; fl++)
        {
            var y = (byte[])hb.Clone();
            y[12] = (byte)fl;
            if (fl <= 2) T.Eq((ChannelBindingType)fl, Codec.DecodeHello(y).Flags, "flags " + fl);
            else T.Eq(ImdbErrorCode.Corrupt, T.Throws<ImdbProtocolException>(() => Codec.DecodeHello(y), "flags " + fl).Kind, "flags as damage");
        }
        var v2 = (byte[])hb.Clone();
        v2[8] = 2;
        var e = T.Throws<ImdbProtocolException>(() => Codec.DecodeHello(v2), "version 2");
        T.Check(e.Kind == ImdbErrorCode.Unsupported && e.Message.Contains("version 2", StringComparison.Ordinal), "a later version by name");
        var m2 = (byte[])hb.Clone();
        m2[7] = (byte)'2';
        e = T.Throws<ImdbProtocolException>(() => Codec.DecodeHello(m2), "IMDBWIR2");
        T.Check(e.Kind == ImdbErrorCode.Unsupported && e.Message.Contains("IMDBWIR2", StringComparison.Ordinal), "a later magic by name");
        m2[7] = (byte)'0';
        T.Eq(ImdbErrorCode.Corrupt, T.Throws<ImdbProtocolException>(() => Codec.DecodeHello(m2), "IMDBWIR0").Kind, "IMDBWIR0 as damage");
        var x0 = (byte[])hb.Clone();
        x0[0] = (byte)'X';
        T.Eq(ImdbErrorCode.Corrupt, T.Throws<ImdbProtocolException>(() => Codec.DecodeHello(x0), "X").Kind, "another magic");
        x0 = (byte[])hb.Clone();
        x0[8] = 0;
        T.Eq(ImdbErrorCode.Corrupt, T.Throws<ImdbProtocolException>(() => Codec.DecodeHello(x0), "v0").Kind, "version 0");
        // the role name: 1 to 63 bytes of UTF-8, NUL-padded
        var u = (byte[])hb.Clone();
        Array.Clear(u, 16, 64);
        T.Throws<ImdbProtocolException>(() => Codec.DecodeHello(u), "an empty name");
        Array.Fill(u, (byte)'a', 16, 64);
        T.Throws<ImdbProtocolException>(() => Codec.DecodeHello(u), "64 bytes, no NUL");
        u[16 + 63] = 0;
        T.Eq(63, Codec.DecodeHello(u).User.Length, "63 bytes");
        Array.Clear(u, 16, 64);
        u[16] = (byte)'a';
        u[18] = (byte)'b';
        T.Throws<ImdbProtocolException>(() => Codec.DecodeHello(u), "a byte past the NUL");
        u[18] = 0;
        u[16] = 0xff;
        T.Throws<ImdbProtocolException>(() => Codec.DecodeHello(u), "not UTF-8");
        T.Check(Codec.UserOk("é", out _) && !Codec.UserOk("", out _) && !Codec.UserOk(new string('a', 64), out _), "imdbw_user_ok");
        T.Throws<ArgumentException>(() => Codec.EncodeHello((ChannelBindingType)3, "alice", nonce), "the encoder refuses flags 3");
        T.Eq((byte)2, Codec.EncodeHello(ChannelBindingType.ServerEndPoint, "alice", nonce)[12], "flags 2");
        // the head every version keeps
        T.Eq(1u, Codec.DecodePreauthHead(hb), "head v1");
        var hd = (byte[])hb.Clone();
        System.Buffers.Binary.BinaryPrimitives.WriteUInt32LittleEndian(hd.AsSpan(8), 7);
        T.Eq(7u, Codec.DecodePreauthHead(hd), "any version read by the head");
        System.Buffers.Binary.BinaryPrimitives.WriteUInt32LittleEndian(hd.AsSpan(8), 0);
        T.Eq(ImdbErrorCode.Corrupt, T.Throws<ImdbProtocolException>(() => Codec.DecodePreauthHead(hd), "head v0").Kind, "head version 0");
        System.Buffers.Binary.BinaryPrimitives.WriteUInt32LittleEndian(hd.AsSpan(8), 1);
        hd[7] = (byte)'2';
        T.Eq(ImdbErrorCode.Unsupported, T.Throws<ImdbProtocolException>(() => Codec.DecodePreauthHead(hd), "head IMDBWIR2").Kind, "head later magic");
        // the challenge: flips, bounds, padding
        var salt = new byte[16];
        new Random(8).NextBytes(salt);
        var cb = Codec.EncodeChallenge(salt, 4096, nonce);
        var d = Codec.DecodeChallenge(cb);
        T.Check(d.Salt.AsSpan().SequenceEqual(salt) && d.Iterations == 4096 && d.Nonce.AsSpan().SequenceEqual(nonce), "challenge read back");
        took = refused = 0;
        for (int i = 0; i < cb.Length; i++)
            foreach (byte f in new byte[] { 0x01, 0x80, 0xff })
            {
                var y = (byte[])cb.Clone();
                y[i] ^= f;
                try
                {
                    var c2 = Codec.DecodeChallenge(y);
                    T.Bytes(y, Codec.EncodeChallenge(c2.Salt, c2.Iterations, c2.Nonce), "a challenge taken encodes back");
                    took++;
                }
                catch (ImdbProtocolException)
                {
                    refused++;
                }
            }
        T.Check(took >= (16 + 32) * 3 && refused >= (48 + 7) * 3, $"challenge flips: {took} taken, {refused} refused");
        (int SaltLen, uint Iter, bool Ok)[] sc = { (7, 4096, false), (8, 4096, true), (64, 4096, true), (65, 4096, false), (16, 999, false),
                                                  (16, 1000, true), (16, 1000000, true), (16, 1000001, false) };
        foreach (var (sl, it, ok) in sc)
        {
            var s = new byte[sl];
            if (ok) T.Eq(it, Codec.DecodeChallenge(Codec.EncodeChallenge(s, it, nonce)).Iterations, $"salt {sl} iter {it}");
            else
            {
                T.Throws<ArgumentException>(() => Codec.EncodeChallenge(s, it, nonce), $"the encoder refuses salt {sl} iter {it}");
                var y = Codec.EncodeChallenge(new byte[16], 4096, nonce);
                y[12] = (byte)sl;
                System.Buffers.Binary.BinaryPrimitives.WriteUInt32LittleEndian(y.AsSpan(13 + 64), it);
                T.Throws<ImdbProtocolException>(() => Codec.DecodeChallenge(y), $"the decoder refuses salt {sl} iter {it}");
            }
        }
        var pad = Codec.EncodeChallenge(salt, 4096, nonce);
        pad[13 + 16] = 1;
        T.Throws<ImdbProtocolException>(() => Codec.DecodeChallenge(pad), "a byte in the salt's padding");
        pad = Codec.EncodeChallenge(salt, 4096, nonce);
        pad[119] = 1;
        T.Throws<ImdbProtocolException>(() => Codec.DecodeChallenge(pad), "a byte in the tail's padding");
        // the verdict
        var sig = new byte[32];
        new Random(9).NextBytes(sig);
        var vb = Codec.EncodeVerdict(0, sig);
        T.Check(Codec.DecodeVerdict(vb).Code == 0 && Codec.DecodeVerdict(vb).Signature.AsSpan().SequenceEqual(sig), "verdict 0");
        vb[0] = 1;
        T.Throws<ImdbProtocolException>(() => Codec.DecodeVerdict(vb), "a refusal with a signature");
        T.Throws<ArgumentException>(() => Codec.EncodeVerdict(1, sig), "the encoder refuses one");
        vb = Codec.EncodeVerdict(1, new byte[32]);
        T.Eq(1u, Codec.DecodeVerdict(vb).Code, "verdict 1");
        vb[0] = 2;
        T.Eq(2u, Codec.DecodeVerdict(vb).Code, "verdict 2: the binding type refused, no signature");
        vb[4] = 1;
        T.Throws<ImdbProtocolException>(() => Codec.DecodeVerdict(vb), "verdict 2 with a signature");
        vb[4] = 0;
        vb[0] = 3;
        T.Throws<ImdbProtocolException>(() => Codec.DecodeVerdict(vb), "verdict 3");
    }

    // t_wire.c lines 925-941: a frame's head
    private static void Heads()
    {
        var h = new byte[] { 0, 0, 0, 0, 1 };
        T.Eq(ImdbErrorCode.Limit, T.Throws<ImdbProtocolException>(() => Codec.DecodeHead(h, false, out _), "length 0").Kind, "length 0 a limit");
        System.Buffers.Binary.BinaryPrimitives.WriteUInt32LittleEndian(h, Protocol.FrameMax + 1);
        T.Eq(ImdbErrorCode.Limit, T.Throws<ImdbProtocolException>(() => Codec.DecodeHead(h, false, out _), "16 MiB + 1").Kind, "past 16 MiB");
        System.Buffers.Binary.BinaryPrimitives.WriteUInt32LittleEndian(h, Protocol.FrameMax);
        T.Eq(FrameType.Query, Codec.DecodeHead(h, false, out int len), "16 MiB taken");
        T.Eq(Protocol.FrameMax, len, "its length");
        T.Throws<ImdbProtocolException>(() => Codec.DecodeHead(h, true, out _), "a client's type from the server");
        byte[] badClient = { 0, 13, 63, 64, 74, 255 }, badServer = { 0, 1, 12, 63, 75, 255 };
        for (int i = 0; i < badClient.Length; i++)
        {
            h[4] = badClient[i];
            T.Throws<ImdbProtocolException>(() => Codec.DecodeHead(h, false, out _), "client type " + badClient[i]);
            h[4] = badServer[i];
            T.Throws<ImdbProtocolException>(() => Codec.DecodeHead(h, true, out _), "server type " + badServer[i]);
        }
        for (byte t = 64; t <= 74; t++)
        {
            h[4] = t;
            Codec.DecodeHead(h, true, out _);
        }
    }

    private enum V
    {
        Ok,
        Refused,
        Limit,
    }

    private static readonly string Zero32 = new('0', 64), Zero16 = new('0', 32);

    // t_wire.c lines 942-1065 (t_wire_bounds): bodies at their edges, a client's (left) and a server's (right)
    private static readonly (FrameType T, string Hex, V Want)[] BodyVecs =
    {
        (FrameType.Query, "00000000", V.Refused),
        (FrameType.Query, "01100000 01000000 61 0000", V.Refused),
        (FrameType.Query, "ffffffff 01000000 61 0000", V.Refused),
        (FrameType.Query, "01000000 00000000 0000", V.Refused),
        (FrameType.Query, "01000000 01004000 61 0000", V.Limit),
        (FrameType.Query, "01000000 01000000 61 0000", V.Ok),
        (FrameType.Query, "01000000 01000000 61 0100 81", V.Ok),
        (FrameType.Query, "01000000 01000000 61 0100 00", V.Refused),
        (FrameType.Query, "01000000 01000000 61 0100 0d0161", V.Refused),
        (FrameType.Query, "01000000 01000000 61 0100 8d", V.Ok),
        (FrameType.Query, "01000000 01000000 61 0101 00", V.Refused),
        (FrameType.Query, "01000000 01000000 61 0000 00", V.Refused),
        (FrameType.Query, "01000000 01000000 61", V.Refused),
        (FrameType.Query, "01000000 01000000 ff 0000", V.Refused),
        (FrameType.Query, "01000000 02000000 6100 0000", V.Refused),
        (FrameType.Deallocate, "01 c3", V.Refused),
        (FrameType.Columns, "0100 01ff 03 0000 0000", V.Refused),
        (FrameType.Columns, "0100 0161 0d 0000 0000 0100 01 80", V.Refused),
        (FrameType.Done, "0100 ff 0000000000000000 00 00", V.Refused),
        (FrameType.Error, "05000000 00000000 0100 00", V.Refused),
        (FrameType.Warning, "0200 c0af", V.Refused),
        (FrameType.CopyData, "ff00", V.Ok),
        (FrameType.Execute, "0170 01000000 0101", V.Refused),
        (FrameType.Execute, "0170 00000000 0000", V.Refused),
        (FrameType.Execute, "0170 01000000 0100 80", V.Ok),
        (FrameType.Execute, "0170 01000000 0100 0d0161", V.Refused),
        (FrameType.Execute, "00 01000000 0000", V.Refused),
        (FrameType.Prepare, "0170 01000000 61", V.Ok),
        (FrameType.Prepare, "0170 01000000 61 00", V.Refused),
        (FrameType.Deallocate, "40 6161616161616161616161616161616161616161616161616161616161616161" +
                               "6161616161616161616161616161616161616161616161616161616161616161", V.Refused),
        (FrameType.Rows, "01000000 00", V.Refused),
        (FrameType.Columns, "0000", V.Refused),
        (FrameType.Columns, "0100 0161 05 2700 0000", V.Refused),
        (FrameType.Columns, "0100 0161 05 0200 0300", V.Refused),
        (FrameType.Columns, "0100 0161 05 2600 2600", V.Ok),
        (FrameType.Columns, "0100 0161 01 0800 0000", V.Refused),
        (FrameType.Columns, "0100 0161 01 1000 0000", V.Ok),
        (FrameType.Columns, "0100 0161 03 0100 0000", V.Refused),
        (FrameType.Columns, "0100 0161 00 0000 0000", V.Ok),
        (FrameType.Columns, "0100 0161 00 0100 0000", V.Refused),
        (FrameType.Columns, "0100 0161 05 0000 2600", V.Ok),
        (FrameType.Columns, "0100 0161 05 0000 2700", V.Refused),
        (FrameType.Columns, "0100 0161 0e 0000 0000", V.Refused),
        (FrameType.Columns, "0100 0161 0d 0000 0000 ffff", V.Refused),
        (FrameType.Columns, "0100 0161 0d 0000 0000 0104", V.Refused),
        (FrameType.Columns, "0100 0161 0d 0000 0000 0100 00", V.Ok),
        (FrameType.Columns, "0100 0161 0d 0000 0000 0100 40", V.Limit),
        (FrameType.Columns, "0100 0161 0d 0100 0000 0100 00", V.Refused),
        (FrameType.Done, "0000 0000000000000000 02 00", V.Refused),
        (FrameType.Done, "0000 0000000000000000 00 00", V.Ok),
        (FrameType.Done, "0000 ffffffffffffffff 00 00", V.Ok),
        (FrameType.Done, "0000 00 00", V.Refused),
        (FrameType.Done, $"0000 0000000000000000 01 0000000000000000 {Zero32} {Zero32} 0100000000000000 01{Zero32[..62]} {Zero16} 00 00", V.Ok),
        (FrameType.Done, $"0000 0000000000000000 01 0000000000000000 {Zero32} {Zero32} 0100000000000000 {Zero32} {Zero16} 01 00", V.Ok),
        (FrameType.Done, $"0000 0000000000000000 01 0000000000000000 {Zero32} {Zero32} 0100000000000000 {Zero32} {Zero16} 02 00", V.Refused),
        (FrameType.Done, $"0000 0000000000000000 00 01 0000000000000000 {Zero32}", V.Refused),
        (FrameType.Done, "0002 " + new string('0', 1024) + " 00 00", V.Limit),
        (FrameType.Error, "05000000 00100000 0000", V.Refused),
        (FrameType.Error, "00000000 00000000 0000", V.Refused),
        (FrameType.Error, "05000000 ff0f0000 0000", V.Ok),
        (FrameType.Ready, "03", V.Refused),
        (FrameType.Ready, "", V.Refused),
        (FrameType.Ping, "00", V.Refused),
        (FrameType.Kill, "01 0100000000000000", V.Ok),
        (FrameType.Kill, "00 0100000000000000", V.Refused),
        (FrameType.Kill, "03 0100000000000000", V.Refused),
        (FrameType.Kill, "02 0000000000000000", V.Refused),
        (FrameType.Kill, "02 01000000000000", V.Refused),
        (FrameType.Kill, "02 0100000000000000 00", V.Refused),
        (FrameType.KillDone, "01 0100000000000000", V.Ok),
        (FrameType.KillDone, "02 0100000000000000", V.Refused),
        (FrameType.KillDone, "03 0100000000000000", V.Refused),
        (FrameType.KillDone, "00 0000000000000000", V.Refused),
        (FrameType.Sessions, "00", V.Refused),
        (FrameType.SessionsList, "00000000", V.Ok),
        (FrameType.SessionsList, "01000000 0100000000000000 01000000 01 00 0000000000000000 00", V.Ok),
        (FrameType.SessionsList, "01000000 0000000000000000 01000000 01 00 0000000000000000 00", V.Refused),
        (FrameType.SessionsList, "01000000 0100000000000000 00000000 01 00 0000000000000000 00", V.Refused),
        (FrameType.SessionsList, "01000000 0100000000000000 01000000 03 00 0000000000000000 00", V.Refused),
        (FrameType.SessionsList, "01000000 0100000000000000 01000000 01 04 0000000000000000 00", V.Refused),
        (FrameType.SessionsList, "01000000 0100000000000000 01000000 01 00 0000000000000000 40", V.Refused),
        (FrameType.SessionsList, "01000000 0100000000000000 01000000 01 00 0000000000000000 01 ff", V.Refused),
        (FrameType.SessionsList, "02000000 0200000000000000 01000000 01 00 0000000000000000 00 " +
                                 "0200000000000000 01000000 01 00 0000000000000000 00", V.Refused),
        (FrameType.SessionsList, "02000000 0200000000000000 01000000 01 00 0000000000000000 00 " +
                                 "0100000000000000 01000000 01 00 0000000000000000 00", V.Refused),
        (FrameType.SessionsList, "02000000 0100000000000000 01000000 01 00 0000000000000000 00", V.Refused),
        (FrameType.SessionsList, "01000100 0100000000000000 01000000 01 00 0000000000000000 00", V.Refused),
        (FrameType.CopyData, "", V.Refused),
        (FrameType.CopyFail, "0110", V.Limit),
        // t_wire.c lines 1077-1088: a count past its bytes refused before it sizes anything
        (FrameType.Query, "00100000 01000000 61 0000", V.Refused),
        (FrameType.Columns, "0001 0161 01 0000 0000", V.Refused),
        (FrameType.Columns, "0100 0161 0d 0000 0000 0004", V.Refused),
    };

    private static bool IsServer(FrameType t) => (byte)t >= 64;

    private static WireMessage DecodeBody(FrameType t, byte[] b) =>
        IsServer(t) ? Codec.DecodeServerBody(t, b, null) : Codec.DecodeClientBody(t, b);

    private static void Bodies()
    {
        foreach (var (t, hex, want) in BodyVecs)
        {
            var b = T.Hex(hex);
            string what = $"{t} {hex[..Math.Min(hex.Length, 60)]}";
            if (want == V.Ok)
            {
                var m = DecodeBody(t, b);
                if (IsServer(t)) T.Bytes(Frame(t, b), Codec.EncodeServer(m), "a body taken encodes back: " + what);
            }
            else
            {
                var e = T.Throws<ImdbProtocolException>(() => DecodeBody(t, b), what);
                if (want == V.Limit) T.Eq(ImdbErrorCode.Limit, e.Kind, "a limit: " + what);
            }
        }
        // an ENUM of 1,024 distinct labels taken, of 1,025 refused (t_wire.c lines 1050-1075)
        foreach (int nl in new[] { 1024, 1025 })
        {
            var ms = new MemoryStream();
            ms.Write(new byte[] { 1, 0, 1, (byte)'e', 13, 0, 0, 0, 0 });
            ms.Write(BitConverter.GetBytes((ushort)nl));
            for (int i = 0; i < nl; i++) ms.Write(new byte[] { 3, (byte)('a' + i / 676), (byte)('a' + i / 26 % 26), (byte)('a' + i % 26) });
            var body = ms.ToArray();
            if (nl == 1024) T.Eq(1024, ((ColumnsMessage)Codec.DecodeServerBody(FrameType.Columns, body, null)).Columns[0].Labels.Count, "1,024 labels");
            else T.Throws<ImdbProtocolException>(() => Codec.DecodeServerBody(FrameType.Columns, body, null), "1,025 labels");
        }
        // labels not distinct
        T.Throws<ImdbProtocolException>(() => Codec.DecodeServerBody(FrameType.Columns, T.Hex("0100 0161 0d 0000 0000 0200 0178 0178"), null),
                                        "a label twice");
        var two = Codec.DecodeServerBody(FrameType.Columns, T.Hex("0100 0161 0d 0000 0000 0200 0178 0179"), null);
        T.Eq(2, ((ColumnsMessage)two).Columns[0].Labels.Count, "two labels");
    }

    private static byte[] Frame(FrameType t, byte[] body)
    {
        var f = new byte[5 + body.Length];
        System.Buffers.Binary.BinaryPrimitives.WriteUInt32LittleEndian(f, (uint)(body.Length + 1));
        f[4] = (byte)t;
        body.CopyTo(f, 5);
        return f;
    }

    private static byte[] BodyOf(byte[] frame) => frame.AsSpan(5).ToArray();

    // the bodies t_wire.c's bounds take, made by this driver's encoders byte for byte; and the encoders' refusals
    private static void ClientEncoders()
    {
        T.Bytes(T.Hex("01000000 01000000 61 0000"), BodyOf(Codec.EncodeQuery(new[] { new ImdbStatement("a") })), "QUERY a");
        T.Bytes(T.Hex("01000000 01000000 61 0100 81"),
                BodyOf(Codec.EncodeQuery(new[] { new ImdbStatement("a", new[] { ImdbValue.Null(ImdbType.Int64) }) })), "QUERY a, a NULL INT64");
        T.Bytes(T.Hex("01000000 01000000 61 0100 8d"),
                BodyOf(Codec.EncodeQuery(new[] { new ImdbStatement("a", new[] { ImdbValue.Null(ImdbType.Enum) }) })), "QUERY a, a NULL ENUM");
        T.Bytes(T.Hex("0170 01000000 0100 80"), BodyOf(Codec.EncodeExecute("p", new[] { new[] { ImdbValue.Null() } })), "EXECUTE p (NULL)");
        T.Bytes(T.Hex("0170 01000000 61"), BodyOf(Codec.EncodePrepare("p", "a")), "PREPARE p a");
        T.Bytes(T.Hex("01 0100000000000000"), BodyOf(Codec.EncodeKill(ImdbKillKind.Cancel, 1)), "KILL cancel 1");
        T.Bytes(T.Hex("ff00"), BodyOf(Codec.EncodeCopyData(new byte[] { 0xff, 0x00 })), "COPY_DATA");
        T.Bytes(T.Hex("01000000 08"), Codec.EncodeEmpty(FrameType.Cancel), "CANCEL");
        T.Bytes(T.Hex("0000"), BodyOf(Codec.EncodeCopyFail("")), "COPY_FAIL of no words");
        T.Bytes(T.Hex("0170"), BodyOf(Codec.EncodeDeallocate("p")), "DEALLOCATE p");
        // every encoded frame is one the decoder takes, and back
        var q = Codec.EncodeQuery(new[]
        {
            ImdbStatement.Of("SELECT $1, $2", 7L, "t"), new ImdbStatement("BEGIN"),
            new ImdbStatement("é", new[] { ImdbValue.Null(ImdbType.Enum) }),
        });
        var qm = (QueryMessage)Codec.DecodeClientBody(FrameType.Query, BodyOf(q));
        T.Check(qm.Statements.Count == 3 && qm.Statements[0].Parameters[0].AsInt64() == 7 && qm.Statements[0].Parameters[1].AsText() == "t"
                && qm.Statements[2].Sql == "é", "QUERY read back");
        // the refusals
        T.Throws<ArgumentException>(() => Codec.EncodeQuery(Array.Empty<ImdbStatement>()), "no statement");
        T.Throws<ArgumentException>(() => Codec.EncodeQuery(Enumerable.Repeat(new ImdbStatement("a"), 4097).ToArray()), "4,097 statements");
        T.Throws<ArgumentException>(() => Codec.EncodeQuery(new[] { new ImdbStatement("") }), "an empty statement");
        T.Throws<ArgumentException>(() => Codec.EncodeQuery(new[] { new ImdbStatement("a\0") }), "a NUL in a statement");
        T.Throws<ArgumentException>(() => Codec.EncodeQuery(new[] { new ImdbStatement("a", Enumerable.Repeat(ImdbValue.Null(), 257).ToArray()) }), "257 values");
        T.Throws<ArgumentException>(() => Codec.EncodeExecute("p", Array.Empty<ImdbValue[]>()), "no set");
        T.Throws<ArgumentException>(() => Codec.EncodeExecute("p", new[] { new[] { ImdbValue.FromEnum("a") } }), "an ENUM parameter");
        T.Throws<ArgumentException>(() => Codec.EncodeExecute("p", new[] { new[] { ImdbValue.Null() }, Array.Empty<ImdbValue>() }), "sets of two counts");
        T.Throws<ArgumentException>(() => Codec.EncodeDeallocate(""), "an empty name");
        T.Throws<ArgumentException>(() => Codec.EncodeDeallocate(new string('a', 64)), "a name of 64 bytes");
        T.Throws<ArgumentException>(() => Codec.EncodeKill((ImdbKillKind)0, 1), "kind 0");
        T.Throws<ArgumentException>(() => Codec.EncodeKill((ImdbKillKind)3, 1), "kind 3");
        T.Throws<ArgumentException>(() => Codec.EncodeKill(ImdbKillKind.Terminate, 0), "session 0");
        T.Throws<ArgumentException>(() => Codec.EncodeCopyData(ReadOnlySpan<byte>.Empty), "an empty COPY_DATA");
        T.Throws<ArgumentException>(() => Codec.EncodeCopyFail(new string('a', 4097)), "4,097 bytes of reason");
        // a request's values travel in one frame: 16 MiB at most
        var big = Enumerable.Repeat(ImdbValue.FromBytea(new byte[65535]), 256).ToArray();
        T.Throws<ImdbException>(() => Codec.EncodeExecute("p", new[] { big }), "a frame past 16 MiB");
    }

    // samples of every server frame (t_wire.c's samples, lines 588-684), each byte flipped three ways: whatever the
    // strict decoder takes encodes back to the same frame, and nothing but ImdbProtocolException is thrown
    internal static List<(byte[] Frame, ColumnsMessage? Cols)> ServerSamples()
    {
        var cols = new ColumnsMessage(new[]
        {
            new ImdbColumn("id", ImdbType.Int64, 32), new ImdbColumn("amount", ImdbType.Decimal, 38, 6),
            new ImdbColumn("name", ImdbType.Text, 12), new ImdbColumn("mood", ImdbType.Enum, 0, 0, new[] { "", "x", "é" }),
        });
        var lim = ImdbDecimal.Limit;
        var rows = new RowsMessage(new[]
        {
            new[] { ImdbValue.FromInt64(int.MinValue), ImdbValue.FromDecimal(new ImdbDecimal(-1234567, 6)), ImdbValue.FromText("héllo"), ImdbValue.FromEnum("x") },
            new[] { ImdbValue.Null(ImdbType.Int64), ImdbValue.FromDecimal(new ImdbDecimal(lim - 1, 6)), ImdbValue.FromText(""), ImdbValue.FromEnum("") },
        });
        var anyCols = new ColumnsMessage(new[] { new ImdbColumn("x", ImdbType.None) });
        var anyRows = new RowsMessage(new[]
        {
            new[] { ImdbValue.FromFloat64(1.5) }, new[] { ImdbValue.Null() }, new[] { ImdbValue.FromTimestampTzMicros(-1) },
            new[] { ImdbValue.FromDateDays(2932896) }, new[] { ImdbValue.FromUuidBytes(Uuid0F) },
            new[] { ImdbValue.FromInterval(int.MinValue, int.MaxValue, long.MinValue) }, new[] { ImdbValue.FromBytea(new byte[] { 0, 255 }) },
            new[] { ImdbValue.FromBool(true) }, new[] { ImdbValue.FromTimeMicros(5) }, new[] { ImdbValue.FromTimestampMicros(7) },
        });
        Func<int, byte[]> h = k => Enumerable.Repeat((byte)k, 32).ToArray();
        var done = new DoneMessage("INSERT 0 3", 3, new ImdbReadPoint(41, h(1), h(2), 44, h(3), Enumerable.Repeat((byte)4, 16).ToArray(), true),
                                   new ImdbWriteCommit(42, h(5)));
        var list = new List<(byte[], ColumnsMessage?)>
        {
            (Codec.EncodeServer(cols), null),
            (Codec.EncodeServer(rows, cols), cols),
            (Codec.EncodeServer(anyCols), null),
            (Codec.EncodeServer(anyRows, anyCols), anyCols),
            (Codec.EncodeServer(done), null),
            (Codec.EncodeServer(new DoneMessage("", 0, null, null)), null),
            (Codec.EncodeServer(new DoneMessage("SELECT 0", 0, new ImdbReadPoint(1, h(0), h(0), 0, h(0), new byte[16], false), null)), null),
            (Codec.EncodeServer(new ErrorMessage(5, 2, "BEGIN")), null),
            (Codec.EncodeServer(new TextMessage(FrameType.Warning, "é")), null),
            (Codec.EncodeEmpty(FrameType.CopyIn), null),
            (Codec.EncodeServer(new DataMessage(FrameType.CopyOut, Encoding.ASCII.GetBytes("1,2\n"))), null),
            (Codec.EncodeServer(new ReadyMessage(ImdbTransactionState.Doomed)), null),
            (Codec.EncodeEmpty(FrameType.Pong), null),
            (Codec.EncodeServer(new SessionsListMessage(new[]
            {
                new ImdbSession(3, 7, ImdbEndpoint.Tcp, ImdbSessionState.ReceivingCopy, ulong.MaxValue, "hé"),
                new ImdbSession(4, uint.MaxValue, ImdbEndpoint.Socket, ImdbSessionState.Idle, 0, ""),
            })), null),
            (Codec.EncodeServer(new SessionsListMessage(Array.Empty<ImdbSession>())), null),
            (Codec.EncodeServer(new KillDoneMessage(0, 9)), null),
            (Codec.EncodeServer(new KillDoneMessage(1, ulong.MaxValue)), null),
        };
        return list;
    }

    private static bool TryRoundTrip(byte[] frame, ColumnsMessage? cols, out bool same)
    {
        same = false;
        FrameType t;
        try
        {
            t = Codec.DecodeHead(frame.AsSpan(0, 5), true, out int len);
            if (len + 4 != frame.Length) return false;
            var m = Codec.DecodeServerBody(t, frame.AsSpan(5), cols);
            same = Codec.EncodeServer(m, cols).AsSpan().SequenceEqual(frame);
            return true;
        }
        catch (ImdbProtocolException)
        {
            return false;
        }
    }

    private static void ServerFlips()
    {
        int took = 0, refused = 0;
        foreach (var (frame, cols) in ServerSamples())
        {
            T.Check(TryRoundTrip(frame, cols, out bool same0) && same0, "the sample itself round-trips: type " + frame[4]);
            for (int i = 0; i < frame.Length; i++)
                foreach (byte f in new byte[] { 0x01, 0x80, 0xff })
                {
                    var x = (byte[])frame.Clone();
                    x[i] ^= f;
                    if (TryRoundTrip(x, cols, out bool same))
                    {
                        T.Check(same, $"a flipped frame taken encodes back to itself (type {frame[4]}, byte {i}, ^{f:x2})");
                        took++;
                    }
                    else refused++;
                }
        }
        T.Check(took > 100 && refused > 100, $"flips: {took} taken, {refused} refused");
    }

    private static void ServerRandom()
    {
        var rnd = new Random(20261119);
        var samples = ServerSamples();
        var cols = samples[1].Cols;
        int took = 0;
        for (int round = 0; round < 60000; round++)
        {
            var t = (FrameType)(64 + rnd.Next(11));
            var body = new byte[rnd.Next(0, 48)];
            rnd.NextBytes(body);
            if (rnd.Next(3) == 0 && body.Length > 0) body[0] = (byte)rnd.Next(3); // small counts, so some bodies get far
            try
            {
                var m = Codec.DecodeServerBody(t, body, cols);
                T.Bytes(Frame(t, body), Codec.EncodeServer(m, cols), "a random body taken encodes back");
                took++;
            }
            catch (ImdbProtocolException)
            {
            }
        }
        T.Check(took > 0, $"{took} random bodies taken");
    }

    // the validator against .NET's own strict decoder plus the NUL rule, on bytes drawn to reach every rule
    private static void Utf8()
    {
        var strict = new UTF8Encoding(false, true);
        byte[] pick = { 0x00, 0x41, 0x7f, 0x80, 0x8f, 0x90, 0x9f, 0xa0, 0xbf, 0xc0, 0xc1, 0xc2, 0xdf, 0xe0, 0xe1, 0xec, 0xed, 0xee,
                        0xef, 0xf0, 0xf1, 0xf3, 0xf4, 0xf5, 0xff };
        var rnd = new Random(1119);
        for (int round = 0; round < 200000; round++)
        {
            var x = new byte[1 + rnd.Next(12)];
            for (int i = 0; i < x.Length; i++) x[i] = rnd.Next(4) != 0 ? pick[rnd.Next(pick.Length)] : (byte)rnd.Next(256);
            bool dotnet;
            try
            {
                strict.GetString(x);
                dotnet = Array.IndexOf(x, (byte)0) < 0;
            }
            catch (DecoderFallbackException)
            {
                dotnet = false;
            }
            if (StrictUtf8.IsValid(x) != dotnet) T.Check(false, "one verdict: " + Convert.ToHexString(x));
        }
        T.Check(true, "200,000 drawn inputs");
        // t_wire.c lines 188-197 (imdbw_utf8_fit)
        var s = Encoding.UTF8.GetBytes("abéc€");
        T.Eq(8, StrictUtf8.Fit(s, 100), "fit 100");
        T.Eq(8, StrictUtf8.Fit(s, 8), "fit 8");
        T.Eq(5, StrictUtf8.Fit(s, 7), "the euro cut: before it");
        T.Eq(5, StrictUtf8.Fit(s, 6), "fit 6");
        T.Eq(5, StrictUtf8.Fit(s, 5), "fit 5");
        T.Eq(2, StrictUtf8.Fit(s, 3), "e-acute cut");
        T.Eq(0, StrictUtf8.Fit(s, 0), "fit 0");
        T.Eq(2, StrictUtf8.Fit(new byte[] { 0x61, 0x62, 0xff, 0x63, 0x64 }, 5), "before the first byte that is not UTF-8");
        T.Eq(2, StrictUtf8.Fit(new byte[] { 0x61, 0x62, 0x00, 0x63, 0x64 }, 5), "nor a NUL");
        T.Eq(3, Codec.CodePoints("a\U0001F600b"), "a surrogate pair is one character");
        // ROWS' VARCHAR rule counts characters (wire.c's utf8_chars), never UTF-16 units nor bytes
        var v5 = new ColumnsMessage(new[] { new ImdbColumn("v", ImdbType.Text, 5) });
        Codec.DecodeServerBody(FrameType.Rows, T.Hex("01000000 04 08000000") .Concat(Encoding.UTF8.GetBytes("abcd\U0001F600")).ToArray(), v5);
        T.Throws<ImdbProtocolException>(() => Codec.DecodeServerBody(FrameType.Rows,
            T.Hex("01000000 04 09000000").Concat(Encoding.UTF8.GetBytes("abcde\U0001F600")).ToArray(), v5), "six characters in a VARCHAR(5)");
        T.Throws<ArgumentException>(() => Codec.EncodeServer(new RowsMessage(new[] { new[] { ImdbValue.FromText("abcde\U0001F600") } }), v5),
                                    "the encoder too");
    }

    private static void NativeTypes()
    {
        // DateTime: a tick is 100 ns, a microsecond 10 ticks: exact both ways, a finer time refused
        var dt = new DateTime(2026, 11, 19, 12, 34, 56, DateTimeKind.Unspecified).AddTicks(1234560);
        T.Eq(dt, ImdbValue.FromTimestamp(dt).AsTimestamp(), "TIMESTAMP round trip");
        T.Throws<ArgumentException>(() => ImdbValue.FromTimestamp(dt.AddTicks(1)), "a tick finer than a microsecond");
        T.Throws<ArgumentException>(() => ImdbValue.FromObject(new DateTime(2026, 1, 1, 0, 0, 0, DateTimeKind.Local)), "a Local DateTime");
        T.Eq(ImdbType.TimestampTz, ImdbValue.FromObject(new DateTime(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc)).Type, "a Utc DateTime");
        T.Eq(ImdbType.Timestamp, ImdbValue.FromObject(new DateTime(2026, 1, 1)).Type, "an Unspecified DateTime");
        var dto = new DateTimeOffset(2026, 3, 8, 2, 30, 0, TimeSpan.FromHours(-5));
        T.Eq(dto.UtcTicks, ImdbValue.FromTimestampTz(dto).AsTimestampTz().UtcTicks, "the instant kept, the offset not");
        T.Eq(DateTime.MinValue, ImdbValue.FromTimestampMicros(Protocol.TimestampMin).AsTimestamp(), "year 1");
        T.Eq(DateTime.MaxValue.AddTicks(-9), ImdbValue.FromTimestampMicros(Protocol.TimestampMax).AsTimestamp(), "year 9999's last microsecond");
        T.Eq(DateOnly.MinValue, ImdbValue.FromDateDays(Protocol.DateMin).AsDate(), "DateOnly.MinValue");
        T.Eq(DateOnly.MaxValue, ImdbValue.FromDateDays(Protocol.DateMax).AsDate(), "DateOnly.MaxValue");
        T.Throws<ArgumentException>(() => ImdbValue.FromTime(new TimeOnly(1)), "a TIME tick finer than a microsecond");
        // a Guid's own byte order is not the wire's
        var g = Guid.Parse("00112233-4455-6677-8899-aabbccddeeff");
        T.Bytes(T.Hex("0a 00112233445566778899aabbccddeeff"), Codec.EncodeValue(ImdbValue.FromUuid(g)), "RFC 4122 order");
        T.Eq(g, Codec.DecodeValue(Codec.EncodeValue(ImdbValue.FromUuid(g)), out _).AsUuid(), "Guid back");
        // CLR integers and decimals
        T.Eq(ImdbType.Int64, ImdbValue.FromObject(7).Type, "int");
        T.Eq(ImdbType.Decimal, ImdbValue.FromObject(BigInteger.Pow(10, 37)).Type, "BigInteger");
        T.Throws<ArgumentException>(() => ImdbValue.FromObject(BigInteger.Pow(10, 38)), "a BigInteger of 39 digits");
        T.Throws<ArgumentException>(() => ImdbValue.FromObject(ulong.MaxValue), "a ulong past long");
        T.Eq(ImdbValue.FromFloat64Bits(0x1), ImdbValue.FromObject(double.Epsilon), "the least subnormal, bit for bit");
        T.Throws<ArgumentException>(() => ImdbValue.FromObject(new object()), "an object of no type");
    }

    // every vector copied above appears verbatim in t_wire.c
    private static void Drift()
    {
        // run_tests.sh names it (IMDB_DRV_T_WIRE, by default ../../tests/unit/t_wire.c from the script): named and
        // missing fails; not named (the program run by hand) skips, saying so
        string? path = Environment.GetEnvironmentVariable("IMDB_DRV_T_WIRE");
        if (path == null)
        {
            Console.WriteLine("     (IMDB_DRV_T_WIRE not set: the copies' check against t_wire.c skipped)");
            return;
        }
        T.Check(File.Exists(path), $"t_wire.c at {path} (IMDB_DRV_T_WIRE)");
        string src = File.ReadAllText(path);
        foreach (var (_, hex) in Vecs) T.Check(src.Contains("\"" + hex + "\"", StringComparison.Ordinal), "kVecs " + hex);
        foreach (var hex in Refused.Where(r => r.Length > 0)) T.Check(src.Contains("\"" + hex + "\"", StringComparison.Ordinal), "refused " + hex);
        foreach (var hex in LimitRefused) T.Check(src.Contains("\"" + hex + "\"", StringComparison.Ordinal), "limit " + hex);
        foreach (var p in Pinned)
        {
            T.Check(src.Contains(p.Proof, StringComparison.Ordinal), "pinned proof " + p.Proof);
            T.Check(src.Contains(p.Sig, StringComparison.Ordinal), "pinned signature " + p.Sig);
        }
        foreach (var (_, hex, _) in BodyVecs)
        {
            if (hex.Contains(Zero32, StringComparison.Ordinal) || hex.Length > 100) continue; // built by snprintf or split across lines there
            T.Check(src.Contains("\"" + hex + "\"", StringComparison.Ordinal),
                    "bounds " + hex);
        }
    }
}
