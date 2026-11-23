using System;
using System.Globalization;
using System.Numerics;

namespace Imagedb.Client;

/// <summary>imagedb's DECIMAL exactly: an unscaled 128-bit integer below 10^38 in magnitude and a scale of 0 to 38 (the
/// wire's one form, §4). System.Decimal holds 28 to 29 digits only, so it cannot carry a DECIMAL(38,s); this type
/// does, and converts to and from System.Decimal and BigInteger without loss (or refuses, never rounds).
/// <para>Equality is the wire's: 1.5 and 1.50 are different values here (unscaled 15 at scale 1, 150 at scale 2), as
/// they are different wire bytes; <see cref="CompareTo"/> and <see cref="NumericEquals"/> compare numbers.</para></summary>
public readonly struct ImdbDecimal : IEquatable<ImdbDecimal>, IComparable<ImdbDecimal>, IFormattable
{
    /// <summary>10^38: every unscaled value is strictly inside (-10^38, 10^38).</summary>
    public static readonly Int128 Limit = Int128.Parse("100000000000000000000000000000000000000", CultureInfo.InvariantCulture);

    public const int MaxScale = 38;

    public ImdbDecimal(Int128 unscaled, int scale)
    {
        if (scale < 0 || scale > MaxScale) throw new ArgumentOutOfRangeException(nameof(scale), "a DECIMAL's scale is 0 to 38");
        if (unscaled <= -Limit || unscaled >= Limit)
            throw new ArgumentOutOfRangeException(nameof(unscaled), "a DECIMAL holds at most 38 digits (|unscaled| < 10^38)");
        Unscaled = unscaled;
        Scale = (byte)scale;
    }

    /// <summary>The value times 10^Scale.</summary>
    public Int128 Unscaled { get; }

    public byte Scale { get; }

    internal static bool InRange(Int128 d, int digits)
    {
        var lim = Pow10(digits);
        return d > -lim && d < lim;
    }

    internal static Int128 Pow10(int k)
    {
        Int128 r = 1;
        for (int i = 0; i < k; i++) r *= 10;
        return r;
    }

    /// <summary>Parses "[+|-]digits[.digits]" exactly (invariant culture, no exponent); the scale is the count of digits
    /// after the point. More than 38 digits in all (leading zeros aside) is refused.</summary>
    public static ImdbDecimal Parse(string s)
    {
        if (!TryParse(s, out var d)) throw new FormatException("not a DECIMAL of at most 38 digits: [+|-]digits[.digits]");
        return d;
    }

    public static bool TryParse(string? s, out ImdbDecimal value)
    {
        value = default;
        if (string.IsNullOrEmpty(s)) return false;
        int i = 0;
        bool neg = false;
        if (s[0] == '+' || s[0] == '-')
        {
            neg = s[0] == '-';
            i = 1;
        }
        Int128 u = 0;
        int digits = 0, scale = 0, intDigits = 0;
        bool point = false, any = false;
        for (; i < s.Length; i++)
        {
            char c = s[i];
            if (c == '.')
            {
                if (point || intDigits == 0) return false;
                point = true;
                continue;
            }
            if (c < '0' || c > '9') return false;
            any = true;
            if (point) scale++;
            else intDigits++;
            if (u != 0 || c != '0') digits++;
            if (digits > 38 || scale > MaxScale) return false;
            u = u * 10 + (c - '0');
        }
        if (!any || (point && scale == 0)) return false;
        value = new ImdbDecimal(neg ? -u : u, scale);
        return true;
    }

    public override string ToString() => ToString(null, null);

    public string ToString(string? format, IFormatProvider? provider)
    {
        var mag = Unscaled < 0 ? -Unscaled : Unscaled;
        string digits = mag.ToString(CultureInfo.InvariantCulture);
        string sign = Unscaled < 0 ? "-" : "";
        if (Scale == 0) return sign + digits;
        if (digits.Length <= Scale) digits = new string('0', Scale - digits.Length + 1) + digits;
        return sign + digits[..^Scale] + "." + digits[^Scale..];
    }

    public BigInteger ToBigIntegerUnscaled() => (BigInteger)Unscaled;

    /// <summary>The nearest double (correctly rounded from the exact decimal text).</summary>
    public double ToDouble() => double.Parse(ToString(), NumberStyles.AllowLeadingSign | NumberStyles.AllowDecimalPoint,
                                             CultureInfo.InvariantCulture);

    /// <summary>Exactly as System.Decimal, or OverflowException when it does not fit one (a 96-bit mantissa, a scale of
    /// at most 28): never rounded.</summary>
    public decimal ToDecimal()
    {
        var mag = Unscaled < 0 ? -Unscaled : Unscaled;
        if (Scale > 28 || mag >= ((Int128)1 << 96))
            throw new OverflowException("this DECIMAL does not fit System.Decimal (28-29 digits, scale 28): use ImdbDecimal or BigInteger");
        ulong low = (ulong)(mag & ulong.MaxValue);
        uint hi = (uint)(ulong)(mag >> 64);
        return new decimal((int)(uint)low, (int)(uint)(low >> 32), (int)hi, Unscaled < 0, Scale);
    }

    /// <summary>A System.Decimal exactly (its scale kept: 1.50m is unscaled 150 at scale 2).</summary>
    public static ImdbDecimal FromDecimal(decimal d)
    {
        Span<int> bits = stackalloc int[4];
        decimal.GetBits(d, bits);
        Int128 mag = ((Int128)(uint)bits[2] << 64) | ((Int128)(uint)bits[1] << 32) | (uint)bits[0];
        int scale = (bits[3] >> 16) & 0xFF;
        bool neg = bits[3] < 0;
        return new ImdbDecimal(neg ? -mag : mag, scale);
    }

    public static implicit operator ImdbDecimal(decimal d) => FromDecimal(d);
    public static implicit operator ImdbDecimal(long v) => new(v, 0);
    public static explicit operator decimal(ImdbDecimal d) => d.ToDecimal();

    public bool Equals(ImdbDecimal other) => Unscaled == other.Unscaled && Scale == other.Scale;
    public override bool Equals(object? obj) => obj is ImdbDecimal d && Equals(d);
    public override int GetHashCode() => HashCode.Combine(Unscaled, Scale);
    public static bool operator ==(ImdbDecimal a, ImdbDecimal b) => a.Equals(b);
    public static bool operator !=(ImdbDecimal a, ImdbDecimal b) => !a.Equals(b);

    /// <summary>The numbers' order (1.5 equals 1.50 here).</summary>
    public int CompareTo(ImdbDecimal other)
    {
        int s = Math.Max(Scale, other.Scale);
        var a = (BigInteger)Unscaled * BigInteger.Pow(10, s - Scale);
        var b = (BigInteger)other.Unscaled * BigInteger.Pow(10, s - other.Scale);
        return a.CompareTo(b);
    }

    public bool NumericEquals(ImdbDecimal other) => CompareTo(other) == 0;
}

/// <summary>imagedb's INTERVAL: months, days and microseconds, any triple (§4), kept apart as PostgreSQL keeps them
/// (a month is not 30 days, a day not 24 hours).</summary>
public readonly record struct ImdbInterval(int Months, int Days, long Microseconds)
{
    public override string ToString() =>
        string.Create(CultureInfo.InvariantCulture, $"{Months} mon {Days} days {Microseconds} us");
}
