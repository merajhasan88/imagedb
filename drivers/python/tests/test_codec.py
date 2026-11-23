"""The codec against the contract's own bytes: tests/unit/t_wire.c's value vectors, refusals and bounds, and section 4's
three pinned SCRAM exchanges (docs/n1-design.md lines 94-104, t_wire.c lines 444-471), each copied here with its place
named; test_vectors_are_t_wires checks every copied hex string still stands in t_wire.c (IMDB_PY_TWIRE, by default the
repository's tests/unit/t_wire.c, the driver living in drivers/python), so a change of the contract fails here. No
server."""

import datetime as dt
import os
import random
import ssl
import struct
import unittest
import uuid
from decimal import Decimal

import imagedb
from imagedb import _native as n
from imagedb import _wire as w

_DRIVER = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # drivers/python
TWIRE = os.environ.get("IMDB_PY_TWIRE",
                       os.path.normpath(os.path.join(_DRIVER, "..", "..", "tests", "unit", "t_wire.c")))

V = w.Value
UUID16 = bytes(range(16))

# t_wire.c lines 55-84 (kVecs): each type's bytes
VECS = [
    (V(w.T_NONE, True, None), "80"),
    (V(w.T_INT64, True, None), "81"),
    (V(w.T_DECIMAL, True, None), "85"),
    (V(w.T_ENUM, True, None), "8d"),
    (V(w.T_INT64, False, -2), "01 feffffffffffffff"),
    (V(w.T_INT64, False, -(1 << 63)), "01 0000000000000080"),
    (V(w.T_FLOAT64, False, 0x3FF8000000000000), "02 000000000000f83f"),
    (V(w.T_FLOAT64, False, 0), "02 0000000000000000"),
    (V(w.T_BOOL, False, 1), "03 01"),
    (V(w.T_BOOL, False, 0), "03 00"),
    (V(w.T_TEXT, False, b"h\xc3\xa9"), "04 03000000 68c3a9"),
    (V(w.T_TEXT, False, b""), "04 00000000"),
    (V(w.T_DECIMAL, False, (2, -12345)), "05 02 c7cfffffffffffffffffffffffffffff"),
    (V(w.T_DECIMAL, False, (0, 0)), "05 00 00000000000000000000000000000000"),
    (V(w.T_TIMESTAMP, False, 1), "06 0100000000000000"),
    (V(w.T_TIMESTAMP, False, -62135596800000000), "06 0040d400014023ff"),
    (V(w.T_TIMESTAMPTZ, False, -1), "07 ffffffffffffffff"),
    (V(w.T_TIMESTAMPTZ, False, 253402300799999999), "07 ff5f73cc0c448403"),
    (V(w.T_DATE, False, -719162), "08 c606f5ff"),
    (V(w.T_DATE, False, 2932896), "08 a0c02c00"),
    (V(w.T_TIME, False, 0), "09 0000000000000000"),
    (V(w.T_TIME, False, 86399999999), "09 ff5fd71d14000000"),
    (V(w.T_UUID, False, UUID16), "0a 000102030405060708090a0b0c0d0e0f"),
    (V(w.T_BYTEA, False, b"\x00\xff"), "0b 02000000 00ff"),
    (V(w.T_INTERVAL, False, (1, -2, 3)), "0c 01000000 feffffff 0300000000000000"),
    (V(w.T_INTERVAL, False, (-(1 << 31), (1 << 31) - 1, -(1 << 63))), "0c 00000080 ffffff7f 0000000000000080"),
    (V(w.T_ENUM, False, b"a"), "0d 01 61"),
    (V(w.T_ENUM, False, b""), "0d 00"),
]

# the same vectors as Python values (the driver's mapping; NULL and ENUM are a result's, so None and str)
NATIVE = [
    None, None, None, None, -2, -(1 << 63), 1.5, 0.0, True, False, "hé", "", Decimal("-123.45"), Decimal("0"),
    dt.datetime(1970, 1, 1, 0, 0, 0, 1), dt.datetime(1, 1, 1), dt.datetime(1969, 12, 31, 23, 59, 59, 999999,
                                                                           tzinfo=dt.timezone.utc),
    dt.datetime(9999, 12, 31, 23, 59, 59, 999999, tzinfo=dt.timezone.utc), dt.date(1, 1, 1), dt.date(9999, 12, 31),
    dt.time(0), dt.time(23, 59, 59, 999999), uuid.UUID(bytes=UUID16), b"\x00\xff", imagedb.Interval(1, -2, 3),
    imagedb.Interval(-(1 << 31), (1 << 31) - 1, -(1 << 63)), "a", "",
]

# t_wire.c lines 122-144: refused by the decoder
REFUSED = [
    "03 02", "02 000000000000f07f", "02 000000000000f0ff", "02 010000000000f87f", "02 0000000000000080",
    "06 ff3fd400014023ff", "07 006073cc0c448403", "09 ffffffffffffffff", "09 0060d71d14000000", "08 c506f5ff",
    "08 a1c02c00", "04 01000000 ff", "04 01000000 00", "04 02000000 c0af", "0d 01 c3", "0d 01 00", "0e", "00", "8e", "ff",
    "",
]
# t_wire.c line 153: a length past its bound refused before its bytes (LIMIT)
LIMITS = ["04 00000100", "0b 00000100", "0d 40"]

# section 4's pinned exchanges (n1-design.md lines 94-104; t_wire.c lines 444-457): user "alice", client nonce 32 x 01,
# salt 16 x 03, 4,096 iterations, server nonce 32 x 02, password "pencil"; (endpoint, flags, binding byte, proof, sig)
EXCHANGES = [
    (w.EP_TCP, w.CB_EXPORTER, 0x04, "28562c1bef99b0a917ecb28c1b32c22930f154f92c134b13fee7a64e8deb733e",
     "5d3ef834c39e6c429d1f4e27993ba451a8b8e35322af9055abc1dd40e88ad322"),
    (w.EP_TCP, w.CB_ENDPOINT, 0x05, "1065f5e038b75f2671d831f5bd5d29f56d22a787f260db523bb986ef7c53f486",
     "28fef60553090aae9b5f184bfc0cfb455e58261131da359f525a59f4dfaa9904"),
    (w.EP_UNIX, w.CB_NONE, 0x00, "5ee7e7bd402f0c91e2399a84c3d544763bace50b44ea82a780e57130bb5405a7",
     "82c9d498cc5fa830d26b29740244ecf4f343962f302a647150e9d74ea7588027"),
]


def hx(s):
    return bytes.fromhex(s.replace(" ", ""))


def decode_one(b):
    r = w.Reader(b)
    v = w.value_get(r)
    if r.left():
        raise w.WireError(w.CORRUPT, "bytes past the value")
    return v


def body(t, hexs, cols=None):
    """t_wire.c's body(): True when the decoder takes the body"""
    try:
        w.msg_get(t, hx(hexs), cols)
        return True
    except w.WireError:
        return False


def body_kind(t, hexs, cols=None):
    try:
        w.msg_get(t, hx(hexs), cols)
        return None
    except w.WireError as e:
        return e.kind


def utf8_valid_c(s):
    """a port of server/wire.c's utf8_valid (lines 157-186), to hold the driver's rule (Python's strict decoder and no
    NUL) to the C one: (ok, the first bad byte)"""
    i, n = 0, len(s)
    while i < n:
        c = s[i]
        if 0x01 <= c < 0x80:
            i += 1
            continue
        lo, hi = 0x80, 0xBF
        if 0xC2 <= c <= 0xDF:
            need = 1
        elif c == 0xE0:
            need, lo = 2, 0xA0
        elif 0xE1 <= c <= 0xEC:
            need = 2
        elif c == 0xED:
            need, hi = 2, 0x9F
        elif c in (0xEE, 0xEF):
            need = 2
        elif c == 0xF0:
            need, lo = 3, 0x90
        elif 0xF1 <= c <= 0xF3:
            need = 3
        elif c == 0xF4:
            need, hi = 3, 0x8F
        else:
            return False, i
        if need > n - i - 1 or s[i + 1] < lo or s[i + 1] > hi:
            return False, i
        for j in range(2, need + 1):
            if s[i + j] & 0xC0 != 0x80:
                return False, i
        i += need + 1
    return True, n


class Values(unittest.TestCase):
    def test_vectors_are_t_wires(self):
        """every vector copied here stands in t_wire.c as written (a contract changed there fails here)"""
        if not os.path.exists(TWIRE):
            self.skipTest("t_wire.c not at %s (IMDB_PY_TWIRE)" % TWIRE)
        with open(TWIRE, encoding="utf-8") as f:
            src = f.read()
        for _, h in VECS:
            self.assertIn('"%s"' % h, src)
        for h in REFUSED + LIMITS:
            self.assertIn('"%s"' % h, src)
        for _, _, _, p, s in EXCHANGES:
            self.assertIn(p, src)
            self.assertIn(s, src)

    def test_vectors_both_ways(self):
        for (v, h), nat in zip(VECS, NATIVE):
            want = hx(h)
            self.assertEqual(w.value_bytes(v), want, h)
            got = decode_one(want)
            self.assertEqual(got, v, h)
            for cut in range(len(want)):  # every prefix refused
                with self.assertRaises(w.WireError):
                    decode_one(want[:cut])
            # the driver's mapping: the vector's value as Python's
            if not v.null:
                self.assertEqual(n.to_native(got), nat, h)
                if v.type != w.T_ENUM:  # a label goes out as TEXT
                    self.assertEqual(w.value_bytes(n.from_native(nat)), want, h)
            else:
                self.assertIsNone(n.to_native(got))

    def test_decimal_range(self):
        """t_wire.c lines 105-116: 10^38 - 1 and its negation taken, 10^38 and -10^38 refused, scale 39 refused"""
        lim = 10 ** 38
        for k, d in enumerate((lim - 1, -(lim - 1), lim, -lim)):
            b = bytes([w.T_DECIMAL, 38]) + (d & ((1 << 128) - 1)).to_bytes(16, "little")
            if k < 2:
                decode_one(b)
            else:
                self.assertRaises(w.WireError, decode_one, b)
            self.assertRaises(w.WireError, decode_one, bytes([w.T_DECIMAL, 39]) + b[2:])

    def test_refused(self):
        for h in REFUSED:
            with self.assertRaises(w.WireError, msg=h):
                decode_one(hx(h))
        for h in LIMITS:
            with self.assertRaises(w.WireError) as cm:
                decode_one(hx(h))
            self.assertEqual(cm.exception.kind, w.LIMIT, h)

    def test_encoder_refuses(self):
        """t_wire.c lines 161-183: the encoder refuses what the decoder would"""
        no = [
            V(w.T_BOOL, False, 2), V(w.T_FLOAT64, False, 0x8000000000000000), V(w.T_TEXT, False, b"\xff"),
            V(w.T_TEXT, False, None), V(w.T_TEXT, False, bytes(65536)), V(w.T_ENUM, False, b"0123456789" * 6 + b"0123"),
            V(w.T_DECIMAL, False, (39, 0)), V(w.T_DATE, False, 2932897), V(w.T_TIMESTAMP, False, (1 << 63) - 1),
            V(w.T_UUID, False, UUID16[:15]), V(14, False, 0), V(w.T_NONE, False, None), V(14, True, None),
        ]
        for v in no:
            self.assertFalse(w.value_ok(v), v)
            with self.assertRaises(w.WireError, msg=repr(v)):
                w.value_bytes(v)

    def test_native_edges(self):
        """every type at its edges, Python's value to the wire and back unchanged"""
        cases = [
            0, 1, -1, (1 << 63) - 1, -(1 << 63), True, False, "", "\U0010fffféa", "x" * 65535,
            Decimal("99999999999999999999999999999999999999"), Decimal("-99999999999999999999999999999999999999"),
            Decimal("0.99999999999999999999999999999999999999"), Decimal("-0.00000000000000000000000000000000000001"),
            Decimal("1.50"), Decimal("0.00"), Decimal("123E+3"), b"", bytes(range(256)) * 255,
            dt.date(1, 1, 1), dt.date(9999, 12, 31), dt.date(1970, 1, 1), dt.time(0), dt.time(23, 59, 59, 999999),
            dt.datetime(1, 1, 1), dt.datetime(9999, 12, 31, 23, 59, 59, 999999), dt.datetime(2026, 3, 8, 6, 30),
            dt.datetime(1, 1, 1, tzinfo=dt.timezone.utc), dt.datetime(9999, 12, 31, 23, 59, 59, 999999, tzinfo=dt.timezone.utc),
            uuid.UUID(int=0), uuid.UUID(int=(1 << 128) - 1), imagedb.Interval(0, 0, 0),
            imagedb.Interval((1 << 31) - 1, -(1 << 31), (1 << 63) - 1),
        ]
        for x in cases:
            v = n.from_native(x)
            back = n.to_native(decode_one(w.value_bytes(v)))
            self.assertEqual(back, x, repr(x)[:80])
            self.assertEqual(type(back), type(x) if not isinstance(x, int) or isinstance(x, bool) else int)
            if isinstance(x, Decimal):
                self.assertEqual(str(back), str(x) if x.as_tuple().exponent <= 0 else str(back))
        # a DECIMAL keeps its scale exactly (never through a context's 28 digits)
        for s in ("99999999999999999999999999999999999999", "0.99999999999999999999999999999999999999", "1.50", "-0.00"):
            got = n.to_native(decode_one(w.value_bytes(n.from_native(Decimal(s)))))
            self.assertEqual(str(got), s.replace("-0.00", "0.00"))
        # an aware datetime as its instant (TIMESTAMPTZ, UTC back), whatever its zone
        x = dt.datetime(2026, 3, 8, 2, 30, tzinfo=dt.timezone(dt.timedelta(hours=-5)))
        back = n.to_native(decode_one(w.value_bytes(n.from_native(x))))
        self.assertEqual(back, x)
        self.assertEqual(back.tzinfo, dt.timezone.utc)
        # an integer past INT64: a DECIMAL of scale 0 (the engine's literal)
        self.assertEqual(n.from_native(1 << 63), V(w.T_DECIMAL, False, (0, 1 << 63)))
        self.assertEqual(n.from_native(10 ** 38 - 1).type, w.T_DECIMAL)
        # a timedelta: an INTERVAL of days and microseconds
        self.assertEqual(n.from_native(dt.timedelta(days=-1, microseconds=5)), V(w.T_INTERVAL, False, (0, -1, 5)))
        # trailing zeros a wire value cannot hold (scale past 38, or 39 digits): the same value at the scale that fits
        self.assertEqual(n.from_native(Decimal("1." + "0" * 40)).data, (37, 10 ** 37))
        self.assertEqual(n.from_native(Decimal("5." + "0" * 38)).data, (37, 5 * 10 ** 37))
        self.assertEqual(n.to_native(n.from_native(Decimal("1." + "0" * 40))), Decimal(1))

    def test_float_bits(self):
        """FLOAT64 bit for bit: every finite non-negative-zero double round-trips to its own bits"""
        rnd = random.Random(7)
        specials = [5e-324, 2.2250738585072014e-308, 1.7976931348623157e308, -1.7976931348623157e308, 0.1, -0.1,
                    1 / 3, 1e300, -5e-324]
        for x in specials + [struct.unpack("<d", struct.pack("<Q", rnd.getrandbits(64)))[0] for _ in range(20000)]:
            if x != x or x in (float("inf"), float("-inf")):
                self.assertRaises(n.EncodeError, n.from_native, x)
                continue
            b = w.value_bytes(n.from_native(x))
            back = n.to_native(decode_one(b))
            if x == 0.0:
                self.assertEqual(struct.pack("<d", back), struct.pack("<d", 0.0))
            else:
                self.assertEqual(struct.pack("<d", back), struct.pack("<d", x))
        # -0.0 goes out as 0.0 (the wire refuses -0: the engine keeps one zero)
        self.assertEqual(w.value_bytes(n.from_native(-0.0)), hx("02 0000000000000000"))

    def test_native_refusals(self):
        for x in (float("nan"), float("inf"), "a\x00b", "\ud800", Decimal("NaN"), Decimal("Infinity"),
                  Decimal("1E+38"), Decimal("1" * 39), Decimal("1E-39"), 10 ** 38, -(10 ** 38), "x" * 65536,
                  b"x" * 65536, dt.time(1, tzinfo=dt.timezone.utc), imagedb.Interval(1 << 31, 0, 0),
                  dt.datetime(1, 1, 1, tzinfo=dt.timezone(dt.timedelta(hours=1))),
                  object(), [1], {"a": 1}):
            self.assertRaises((n.EncodeError, TypeError, ValueError), lambda: w.value_bytes(n.from_native(x)))
        self.assertRaises(ValueError, imagedb.Null, 14)
        self.assertEqual(w.value_bytes(n.from_native(imagedb.Null(imagedb.T_DATE))), hx("88"))
        self.assertEqual(w.value_bytes(n.from_native(None)), hx("80"))

    def test_enum_parameter_refused(self):
        """a non-NULL ENUM is never a parameter (a label goes out as TEXT); a NULL ENUM is (t_wire.c lines 950-951)"""
        self.assertRaises(w.WireError, w.params_bytes, [V(w.T_ENUM, False, b"a")])
        self.assertEqual(w.params_bytes([V(w.T_ENUM, True, None)]), hx("8d"))


class Utf8(unittest.TestCase):
    def test_fit(self):
        """t_wire.c lines 186-197"""
        s = b"ab\xc3\xa9c\xe2\x82\xac"
        for mx, want in ((100, 8), (8, 8), (7, 5), (6, 5), (5, 5), (3, 2), (0, 0)):
            self.assertEqual(w.utf8_fit(s, mx), want)
        self.assertEqual(w.utf8_fit(b"ab\xffcd", 5), 2)
        self.assertEqual(w.utf8_fit(b"ab\x00cd", 5), 2)

    def test_rule_against_wire_c(self):
        """the driver's rule (Python's strict decoder, no NUL) against a port of wire.c's on drawn bytes (t_wire.c lines
        210-219's picks): one verdict, and utf8_fit's cut at the C rule's first bad byte"""
        pick = [0x00, 0x41, 0x7F, 0x80, 0x8F, 0x90, 0x9F, 0xA0, 0xBF, 0xC0, 0xC1, 0xC2, 0xDF, 0xE0, 0xE1, 0xEC, 0xED, 0xEE,
                0xEF, 0xF0, 0xF1, 0xF3, 0xF4, 0xF5, 0xFF]
        rnd = random.Random(11)
        for _ in range(200000):
            k = 1 + rnd.randrange(12)
            x = bytes(pick[rnd.randrange(len(pick))] if rnd.randrange(4) else rnd.randrange(256) for _ in range(k))
            ok, bad = utf8_valid_c(x)
            self.assertEqual(w.utf8_ok(x), ok, x.hex())
            self.assertEqual(w.utf8_fit(x, len(x)), len(x) if ok else bad, x.hex())


def hello_bytes(flags=0, user=b"alice", nonce=b"\x01" * 32):
    return w.hello_put(w.Hello(1, flags, user, nonce))


class PreAuth(unittest.TestCase):
    def test_hello(self):
        hb = hello_bytes(nonce=bytes(range(32)))
        self.assertEqual(hb[:21], b"IMDBWIR1\x01\0\0\0\0\0\0\0alice")  # t_wire.c line 230
        self.assertEqual(len(hb), w.HELLO_LEN)
        g = w.hello_get(hb)
        self.assertEqual((g.user, g.nonce, g.version, g.flags), (b"alice", bytes(range(32)), 1, 0))
        took = refused = 0
        for i in range(len(hb)):  # every byte flipped three ways: taken and encoded back the same, or refused
            for f in (0x01, 0x80, 0xFF):
                x = bytearray(hb)
                x[i] ^= f
                try:
                    g = w.hello_get(bytes(x))
                except w.WireError:
                    refused += 1
                    continue
                self.assertEqual(w.hello_put(g), bytes(x))
                took += 1
        self.assertGreaterEqual(took, 32 * 3 + 1)
        self.assertGreaterEqual(refused, 16 * 3)
        for fl in range(5):  # section 8f: 0, 1, 2 taken; past them refused
            y = bytearray(hb)
            y[12] = fl
            if fl <= 2:
                self.assertEqual(w.hello_get(bytes(y)).flags, fl)
            else:
                self.assertRaises(w.WireError, w.hello_get, bytes(y))
        x = bytearray(hb)
        x[8] = 2
        with self.assertRaises(w.WireError) as cm:
            w.hello_get(bytes(x))
        self.assertEqual(cm.exception.kind, w.UNSUPPORTED)
        self.assertIn("version 2", str(cm.exception))
        x = bytearray(hb)
        x[7] = ord("2")
        with self.assertRaises(w.WireError) as cm:
            w.hello_get(bytes(x))
        self.assertEqual(cm.exception.kind, w.UNSUPPORTED)
        self.assertIn("IMDBWIR2", str(cm.exception))
        x[7] = ord("0")
        self.assertEqual(self._kind(w.hello_get, x), w.CORRUPT)
        x = bytearray(hb)
        x[8] = 0
        self.assertEqual(self._kind(w.hello_get, x), w.CORRUPT)
        x = bytearray(hb)
        x[16:16 + 64] = bytes(64)
        self.assertRaises(w.WireError, w.hello_get, bytes(x))  # empty
        x[16:16 + 64] = b"a" * 64
        self.assertRaises(w.WireError, w.hello_get, bytes(x))  # no NUL
        x[16 + 63] = 0
        self.assertEqual(len(w.hello_get(bytes(x)).user), 63)
        x[16:16 + 64] = b"a\0b" + bytes(61)
        self.assertRaises(w.WireError, w.hello_get, bytes(x))  # a byte past the NUL
        x[16:16 + 64] = b"\xff" + bytes(63)
        self.assertRaises(w.WireError, w.hello_get, bytes(x))
        self.assertTrue(w.user_ok("é".encode()) and not w.user_ok(b"") and not w.user_ok(b"\xc3"))
        for bad in (dict(flags=3), dict(user=b""), dict(user=b"\xc3"), dict(user=b"a" * 64)):
            self.assertRaises(w.WireError, hello_bytes, **bad)

    def test_head(self):
        hb = hello_bytes()
        self.assertEqual(w.preauth_head(hb[:12]), 1)
        self.assertEqual(w.preauth_head(b"IMDBWIR1" + struct.pack("<I", 7)), 7)
        self.assertEqual(self._kind(w.preauth_head, b"IMDBWIR1" + bytes(4)), w.CORRUPT)
        self.assertEqual(self._kind(w.preauth_head, b"IMDBWIR2" + struct.pack("<I", 1)), w.UNSUPPORTED)
        self.assertEqual(self._kind(w.preauth_head, b"XMDBWIR2" + struct.pack("<I", 1)), w.CORRUPT)

    def _kind(self, f, b):
        try:
            f(bytes(b))
        except w.WireError as e:
            return e.kind
        return None

    def test_challenge(self):
        c = w.Challenge(1, bytes(range(1, 17)), 4096, bytes(range(32)))
        cb = w.challenge_put(c)
        self.assertEqual(len(cb), w.CHALLENGE_LEN)
        self.assertEqual(w.challenge_get(cb), c)
        took = refused = 0
        for i in range(len(cb)):
            for f in (0x01, 0x80, 0xFF):
                y = bytearray(cb)
                y[i] ^= f
                try:
                    d = w.challenge_get(bytes(y))
                except w.WireError:
                    refused += 1
                    continue
                self.assertEqual(w.challenge_put(d), bytes(y))
                took += 1
        self.assertGreaterEqual(took, (16 + 32) * 3)
        self.assertGreaterEqual(refused, (48 + 7) * 3)
        for slen, it, ok in ((7, 4096, False), (8, 4096, True), (64, 4096, True), (65, 4096, False), (16, 999, False),
                             (16, 1000, True), (16, 1000000, True), (16, 1000001, False)):  # t_wire.c lines 354-369
            y = bytearray(cb)
            y[12] = slen
            y[13 + 64:17 + 64] = struct.pack("<I", it)
            if slen <= 64:
                y[13:13 + 64] = bytes([3] * slen) + bytes(64 - slen)
            self.assertEqual(self._kind(w.challenge_get, y) is None, ok, (slen, it))
        y = bytearray(cb)
        y[13 + 16] = 1  # a byte in the salt's padding
        self.assertRaises(w.WireError, w.challenge_get, bytes(y))
        y = bytearray(cb)
        y[-1] = 1  # the 7 zeros
        self.assertRaises(w.WireError, w.challenge_get, bytes(y))

    def test_verdict(self):
        sig = bytes(range(32))
        vb = w.verdict_put(w.Verdict(0, sig))
        self.assertEqual(w.verdict_get(vb), w.Verdict(0, sig))
        self.assertRaises(w.WireError, w.verdict_get, b"\x01" + vb[1:])  # a refusal with a signature
        self.assertRaises(w.WireError, w.verdict_put, w.Verdict(1, sig))
        self.assertEqual(w.verdict_get(w.verdict_put(w.Verdict(1, bytes(32)))).code, 1)
        self.assertEqual(w.verdict_get(b"\x02" + bytes(35)).code, w.VERDICT_BINDING)
        self.assertRaises(w.WireError, w.verdict_get, b"\x02" + bytes(3) + b"\x01" + bytes(31))
        self.assertRaises(w.WireError, w.verdict_get, b"\x03" + bytes(35))
        self.assertRaises(w.WireError, w.verdict_put, w.Verdict(3, bytes(32)))


class Scram(unittest.TestCase):
    def setUp(self):
        self.c = w.Challenge(1, b"\x03" * 16, 4096, b"\x02" * 32)
        self.cb = w.challenge_put(self.c)

    def test_auth_message_layout(self):
        hb = hello_bytes(flags=w.CB_EXPORTER)
        am = w.auth_message(w.EP_TCP, hb, self.cb, b"\x04" * 32)
        self.assertEqual(am, b"IMDBWIR1-SCRAM" + b"\x01" + hb + self.cb + b"\x04" * 32)
        self.assertEqual(len(am), 279)

    def test_pinned_exchanges(self):
        """section 4's three exchanges, byte for byte: the proof and the server's signature"""
        for ep, flags, bind, proof, sig in EXCHANGES:
            hb = hello_bytes(flags=flags)
            self.assertEqual(hb[12], flags)
            am = w.auth_message(ep, hb, self.cb, bytes([bind]) * 32)
            p, s = w.scram_client(b"pencil", self.c, am)
            self.assertEqual(p.hex(), proof, (ep, flags))
            self.assertEqual(s.hex(), sig, (ep, flags))

    def test_type_byte_bound(self):
        """the hello's type byte is in the AuthMessage: a proof made over another type is another proof"""
        proofs = set()
        for fl in (0, 1, 2):
            am = w.auth_message(w.EP_TCP, hello_bytes(flags=fl), self.cb, b"\x04" * 32)
            proofs.add(w.scram_client(b"pencil", self.c, am)[0])
        self.assertEqual(len(proofs), 3)

    def test_password_rule(self):
        """t_wire.c lines 529-541"""
        am = w.auth_message(w.EP_UNIX, hello_bytes(), self.cb, bytes(32))
        for bad in (b"", b"a\x7f", b"a\x1f", "é".encode(), b"a" * 1025):
            self.assertRaises(w.WireError, w.scram_client, bad, self.c, am)
        w.scram_client(b"a" * 1024, self.c, am)
        self.assertRaises(w.WireError, w.scram_client, b"pencil", self.c._replace(iterations=999), am)


# ---- frames ----

def cols_msg(cols):
    return w.ColumnsMsg([w.Column(*c) for c in cols])


SAMPLE_COLS = cols_msg([("id", w.T_INT64, 32, 0, ()), ("amount", w.T_DECIMAL, 38, 6, ()),
                        ("name", w.T_TEXT, 12, 0, ()), ("mood", w.T_ENUM, 0, 0, ("", "x", "é"))])


def samples():
    """t_wire.c lines 588-684: one message of every type"""
    M = w.Msg
    ev = [V(w.T_INT64, False, -2), V(w.T_FLOAT64, False, 0x3FF8000000000000), V(w.T_NONE, True, None),
          V(w.T_DECIMAL, False, (2, -12345)), V(w.T_TIMESTAMPTZ, False, -1), V(w.T_DATE, False, 2932896),
          V(w.T_UUID, False, UUID16), V(w.T_INTERVAL, False, (-(1 << 31), (1 << 31) - 1, -(1 << 63)))]
    lim = 10 ** 38
    rv = [V(w.T_INT64, False, -(1 << 31)), V(w.T_DECIMAL, False, (6, -1234567)), V(w.T_TEXT, False, "héllo".encode()),
          V(w.T_ENUM, False, b"x"), V(w.T_INT64, True, None), V(w.T_DECIMAL, False, (6, lim - 1)),
          V(w.T_TEXT, False, b""), V(w.T_ENUM, False, b"")]
    rp = w.ReadPoint(41, b"\x01" * 32, b"\x02" * 32, 44, b"\x03" * 32, b"\x04" * 16, True)
    return [
        M(w.EXECUTE, name="p1", nvals=4, sets=[ev[:4], ev[4:]]),
        M(w.QUERY, stmts=[(b"SELECT $1, $2", [V(w.T_INT64, False, 7), V(w.T_TEXT, False, b"t")]), (b"BEGIN", []),
                          ("é".encode(), [V(w.T_ENUM, True, None)])]),
        M(w.QUERY, stmts=[(b"BEGIN", [])]),
        M(w.PREPARE, name="p1", text=b"SELECT $1, $2"),
        M(w.PREPARE, name="n" * 63, text=b"BEGIN"),
        M(w.EXECUTE, name="p2", nvals=0, sets=[[], [], []]),
        M(w.DEALLOCATE, name="p1"),
        M(w.COPY_DATA, data=b"a,b\n\x00\xff"),
        M(w.COPY_DONE), M(w.COPY_FAIL, message="SELECT $1, $2"), M(w.CANCEL), M(w.PING), M(w.TERMINATE), M(w.SESSIONS),
        M(w.KILL, kind=w.KILL_CANCEL, sid=1), M(w.KILL, kind=w.KILL_TERMINATE, sid=w.U64_MAX),
        M(w.COLUMNS, columns=SAMPLE_COLS),
        M(w.ROWS, rows=[rv[:4], rv[4:]]),
        M(w.DONE, status="INSERT 0 3", count=3, read=rp, write=w.WriteCommit(42, b"\x05" * 32)),
        M(w.DONE, status="", count=0, read=None, write=None),
        M(w.DONE, status="SELECT 0", count=0, read=w.ReadPoint(0, bytes(32), bytes(32), 0, bytes(32), bytes(16), False),
          write=None),
        M(w.ERROR, code=5, index=2, message="BEGIN"),
        M(w.WARNING, message="é"),
        M(w.COPY_IN), M(w.COPY_OUT, data=b"1,2\n"), M(w.READY, state=w.DOOMED), M(w.PONG),
        M(w.SESSIONS_LIST, sessions=[w.Session(3, 7, 1, w.SS_COPY, w.U64_MAX, "hé"),
                                     w.Session(4, w.U32_MAX, 2, w.SS_IDLE, 0, "")]),
        M(w.SESSIONS_LIST, sessions=[]),
        M(w.KILL_DONE, code=w.KILLED, sid=9), M(w.KILL_DONE, code=w.KILL_NONE, sid=w.U64_MAX),
    ]


def reencode(frame, cols):
    """t_wire.c's reencode: (True, same) when the decoder takes the frame, (False, kind) when it refuses it"""
    if len(frame) < w.HEAD:
        return False, None
    t = frame[4]
    try:
        flen, t = w.head_get(frame, t >= 64)
        if flen + 4 != len(frame):
            return False, "length"
        m = w.msg_get(t, frame[5:], cols)
    except w.WireError as e:
        return False, e.kind
    return True, w.msg_put(m, cols) == frame


class Frames(unittest.TestCase):
    def test_samples_round_trip(self):
        for m in samples():
            f = w.msg_put(m, SAMPLE_COLS)
            self.assertEqual(f[4], m.type)
            ok, same = reencode(f, SAMPLE_COLS)
            self.assertTrue(ok and same, m)
        # the decoded fields themselves (t_wire.c lines 736-759)
        d = w.msg_get(w.COLUMNS, w.msg_put(samples()[16])[5:])
        c = d.columns.columns
        self.assertEqual((len(c), c[1].name, c[1].precision, c[1].scale, c[3].labels), (4, "amount", 38, 6, ("", "x", "é")))
        q = w.msg_get(w.QUERY, w.msg_put(samples()[1])[5:])
        self.assertEqual([len(v) for _, v in q.stmts], [2, 0, 1])
        self.assertEqual(q.stmts[0][1], [V(w.T_INT64, False, 7), V(w.T_TEXT, False, b"t")])

    def test_flips_cuts_and_more(self):
        """t_wire.c lines 868-910: every byte of every sample flipped three ways (what the decoder takes encodes back to
        itself), every cut refused and one byte more refused, but COPY's raw pieces"""
        for m in samples():
            f = w.msg_put(m, SAMPLE_COLS)
            raw = m.type in (w.COPY_DATA, w.COPY_OUT)
            for i in range(w.HEAD, len(f)):
                for fl in (0x01, 0x80, 0xFF):
                    x = bytearray(f)
                    x[i] ^= fl
                    ok, same = reencode(bytes(x), SAMPLE_COLS)
                    if ok:
                        self.assertTrue(same, (m, i, fl))
            for cut in range(w.HEAD, len(f)):
                x = bytearray(f[:cut])
                x[0:4] = struct.pack("<I", cut - 4)
                ok, same = reencode(bytes(x), SAMPLE_COLS)
                if raw:
                    self.assertTrue(not ok or same or cut == w.HEAD, (m, cut))
                else:
                    self.assertFalse(ok, (m, cut))
            x = bytearray(f) + b"\x00"
            x[0:4] = struct.pack("<I", len(f) + 1 - 4)
            ok, same = reencode(bytes(x), SAMPLE_COLS)
            self.assertEqual(ok and same, raw, m)

    def test_rows_fit(self):
        """t_wire.c lines 774-839: a ROWS held to its COLUMNS"""
        lim = 10 ** 38
        cases = [
            (0, V(w.T_INT64, False, (1 << 31) - 1), True), (0, V(w.T_INT64, False, 1 << 31), False),
            (0, V(w.T_INT64, False, -(1 << 31) - 1), False), (0, V(w.T_TIMESTAMP, False, 1), False),
            (0, V(w.T_INT64, True, None), True), (0, V(w.T_TEXT, True, None), False), (0, V(w.T_NONE, True, None), False),
            (1, V(w.T_DECIMAL, False, (6, lim - 1)), True), (1, V(w.T_DECIMAL, False, (5, 1)), False),
            (1, V(w.T_INT64, False, 1), False), (2, V(w.T_TEXT, False, "é".encode() * 12), True),
            (2, V(w.T_TEXT, False, b"0123456789abc"), False), (2, V(w.T_BYTEA, False, b"a"), False),
            (3, V(w.T_ENUM, False, "é".encode()), True), (3, V(w.T_ENUM, False, b"y"), False),
            (3, V(w.T_ENUM, False, b"xx"), False), (3, V(w.T_TEXT, False, b"x"), False),
        ]
        cs, ls = SAMPLE_COLS.columns, SAMPLE_COLS._label_sets
        for col, v, ok in cases:
            self.assertEqual(w.value_fits(cs[col], ls[col], v), ok, (col, v))
            row = [V(w.T_INT64, True, None), V(w.T_DECIMAL, True, None), V(w.T_TEXT, True, None), V(w.T_ENUM, True, None)]
            row[col] = v
            hand = w.frame(w.ROWS, struct.pack("<I", 1) + b"".join(w.value_bytes(x) for x in row))
            got, same = reencode(hand, SAMPLE_COLS)
            self.assertEqual(got, ok, (col, v))
            try:
                enc = w.msg_put(w.Msg(w.ROWS, rows=[row]), SAMPLE_COLS)
                self.assertTrue(ok and enc == hand)
            except w.WireError:
                self.assertFalse(ok)
        sc = w.Column("s", w.T_INT64, 16, 0, ())
        self.assertTrue(w.value_fits(sc, None, V(w.T_INT64, False, 32767)))
        self.assertFalse(w.value_fits(sc, None, V(w.T_INT64, False, 32768)))
        d52 = w.Column("d", w.T_DECIMAL, 5, 2, ())
        self.assertTrue(w.value_fits(d52, None, V(w.T_DECIMAL, False, (2, -99999))))
        self.assertFalse(w.value_fits(d52, None, V(w.T_DECIMAL, False, (2, 100000))))
        d0 = w.Column("d", w.T_DECIMAL, 0, 2, ())
        self.assertTrue(w.value_fits(d0, None, V(w.T_DECIMAL, False, (2, lim - 1))))
        self.assertFalse(w.value_fits(d0, None, V(w.T_DECIMAL, False, (3, 0))))
        none = w.Column("x", w.T_NONE, 0, 0, ())
        for v in (V(w.T_INT64, False, 1), V(w.T_ENUM, False, b"q"), V(w.T_NONE, True, None), V(w.T_DATE, True, None)):
            self.assertTrue(w.value_fits(none, None, v))
        self.assertFalse(w.value_fits(none, None, V(w.T_BOOL, False, 2)))
        # the same COLUMNS with a label twice, made by hand: refused (t_wire.c line 856)
        with self.assertRaises(w.WireError) as cm:
            w.msg_get(w.COLUMNS, hx("0100 0165 0d 0000 0000 0200 0161 0161"))
        self.assertIn("distinct", str(cm.exception))
        self.assertRaises(w.WireError, w.msg_put, w.Msg(w.COLUMNS, columns=cols_msg([("e", 13, 0, 0, ("a", "b", "a"))])))

    def test_heads(self):
        """t_wire.c lines 926-941"""
        h = struct.pack("<I", 0) + bytes([w.QUERY])
        self.assertRaises(w.WireError, w.head_get, h, False)
        self.assertRaises(w.WireError, w.head_get, struct.pack("<I", w.FRAME_MAX + 1) + bytes([1]), False)
        self.assertEqual(w.head_get(struct.pack("<I", w.FRAME_MAX) + bytes([1]), False), (w.FRAME_MAX, 1))
        self.assertRaises(w.WireError, w.head_get, struct.pack("<I", w.FRAME_MAX) + bytes([1]), True)
        for bc, bs in zip((0, 13, 63, 64, 74, 255), (0, 1, 12, 63, 75, 255)):
            self.assertRaises(w.WireError, w.head_get, struct.pack("<I", 1) + bytes([bc]), False)
            self.assertRaises(w.WireError, w.head_get, struct.pack("<I", 1) + bytes([bs]), True)

    def test_bodies(self):
        """t_wire.c lines 942-1042, every body case (both directions: the driver decodes the server's and the tests the
        driver's)"""
        Q, D, C, DN, ER = w.QUERY, w.DEALLOCATE, w.COLUMNS, w.DONE, w.ERROR
        cases = [
            (Q, "00000000", False), (Q, "01100000 01000000 61 0000", False), (Q, "ffffffff 01000000 61 0000", False),
            (Q, "01000000 00000000 0000", False), (Q, "01000000 01000000 61 0000", True),
            (Q, "01000000 01000000 61 0100 81", True), (Q, "01000000 01000000 61 0100 00", False),
            (Q, "01000000 01000000 61 0100 0d0161", False), (Q, "01000000 01000000 61 0100 8d", True),
            (Q, "01000000 01000000 61 0101 00", False), (Q, "01000000 01000000 61 0000 00", False),
            (Q, "01000000 01000000 61", False), (Q, "01000000 01000000 ff 0000", False),
            (Q, "01000000 02000000 6100 0000", False), (D, "01 c3", False), (C, "0100 01ff 03 0000 0000", False),
            (C, "0100 0161 0d 0000 0000 0100 01 80", False), (DN, "0100 ff 0000000000000000 00 00", False),
            (ER, "05000000 00000000 0100 00", False), (w.WARNING, "0200 c0af", False), (w.COPY_DATA, "ff00", True),
            (w.EXECUTE, "0170 01000000 0101", False), (w.EXECUTE, "0170 00000000 0000", False),
            (w.EXECUTE, "0170 01000000 0100 80", True), (w.EXECUTE, "0170 01000000 0100 0d0161", False),
            (w.EXECUTE, "00 01000000 0000", False), (w.PREPARE, "0170 01000000 61", True),
            (w.PREPARE, "0170 01000000 61 00", False), (D, "40" + "61" * 64, False), (w.ROWS, "01000000 00", False),
            (C, "0000", False), (C, "0100 0161 05 2700 0000", False), (C, "0100 0161 05 0200 0300", False),
            (C, "0100 0161 05 2600 2600", True), (C, "0100 0161 01 0800 0000", False), (C, "0100 0161 01 1000 0000", True),
            (C, "0100 0161 03 0100 0000", False), (C, "0100 0161 00 0000 0000", True), (C, "0100 0161 00 0100 0000", False),
            (C, "0100 0161 05 0000 2600", True), (C, "0100 0161 05 0000 2700", False), (C, "0100 0161 0e 0000 0000", False),
            (C, "0100 0161 0d 0000 0000 ffff", False), (C, "0100 0161 0d 0000 0000 0104", False),
            (C, "0100 0161 0d 0000 0000 0100 00", True), (C, "0100 0161 0d 0100 0000 0100 00", False),
            (DN, "0000 0000000000000000 02 00", False), (DN, "0000 0000000000000000 00 00", True),
            (DN, "0000 ffffffffffffffff 00 00", True), (DN, "0000 00 00", False),
            (ER, "05000000 00100000 0000", False), (ER, "00000000 00000000 0000", False), (ER, "05000000 ff0f0000 0000", True),
            (w.READY, "03", False), (w.READY, "", False), (w.PING, "00", False),
            (w.KILL, "01 0100000000000000", True), (w.KILL, "00 0100000000000000", False),
            (w.KILL, "03 0100000000000000", False), (w.KILL, "02 0000000000000000", False),
            (w.KILL, "02 01000000000000", False), (w.KILL, "02 0100000000000000 00", False),
            (w.KILL_DONE, "01 0100000000000000", True), (w.KILL_DONE, "02 0100000000000000", False),
            (w.KILL_DONE, "03 0100000000000000", False), (w.KILL_DONE, "00 0000000000000000", False),
            (w.SESSIONS, "00", False), (w.SESSIONS_LIST, "00000000", True),
            (w.SESSIONS_LIST, "01000000 0100000000000000 01000000 01 00 0000000000000000 00", True),
            (w.SESSIONS_LIST, "01000000 0000000000000000 01000000 01 00 0000000000000000 00", False),
            (w.SESSIONS_LIST, "01000000 0100000000000000 00000000 01 00 0000000000000000 00", False),
            (w.SESSIONS_LIST, "01000000 0100000000000000 01000000 03 00 0000000000000000 00", False),
            (w.SESSIONS_LIST, "01000000 0100000000000000 01000000 01 04 0000000000000000 00", False),
            (w.SESSIONS_LIST, "01000000 0100000000000000 01000000 01 00 0000000000000000 40", False),
            (w.SESSIONS_LIST, "01000000 0100000000000000 01000000 01 00 0000000000000000 01 ff", False),
            (w.SESSIONS_LIST, "02000000 0200000000000000 01000000 01 00 0000000000000000 00 "
                              "0200000000000000 01000000 01 00 0000000000000000 00", False),
            (w.SESSIONS_LIST, "02000000 0200000000000000 01000000 01 00 0000000000000000 00 "
                              "0100000000000000 01000000 01 00 0000000000000000 00", False),
            (w.SESSIONS_LIST, "02000000 0100000000000000 01000000 01 00 0000000000000000 00", False),
            (w.SESSIONS_LIST, "01000100 0100000000000000 01000000 01 00 0000000000000000 00", False),
            (w.COPY_DATA, "", False),
        ]
        for t, h, ok in cases:
            self.assertEqual(body(t, h), ok, (w.FRAME_NAMES[t], h))
        # the LIMIT refusals (t_wire.c lines 946, 990, 1008, 1042)
        self.assertEqual(body_kind(Q, "01000000 01004000 61 0000"), w.LIMIT)
        self.assertEqual(body_kind(C, "0100 0161 0d 0000 0000 0100 40"), w.LIMIT)
        self.assertEqual(body_kind(DN, "0002" + "00" * 512), w.LIMIT)
        self.assertEqual(body_kind(w.COPY_FAIL, "0110"), w.LIMIT)
        # a DONE's read point (t_wire.c lines 996-1006)
        z32, z16 = "00" * 32, "00" * 16
        self.assertTrue(body(DN, "0000 %s 01 %s %s %s 0100000000000000 %s %s 01 00" % ("00" * 8, "00" * 8, z32, z32, z32, z16)))
        self.assertFalse(body(DN, "0000 %s 01 %s %s %s 0100000000000000 %s %s 02 00" % ("00" * 8, "00" * 8, z32, z32, z32, z16)))
        self.assertFalse(body(DN, "0000 %s 00 01 %s %s" % ("00" * 8, "00" * 8, z32)))  # a write at commit 0

    def test_enum_labels_bound(self):
        """t_wire.c lines 1043-1073: an ENUM of 1,024 distinct labels taken, of 1,025 refused"""
        for nl in (1024, 1025):
            labels = [bytes([97 + i // 676, 97 + i // 26 % 26, 97 + i % 26]) for i in range(nl)]
            b = bytes([1, 0, 1, ord("e"), w.T_ENUM, 0, 0, 0, 0]) + struct.pack("<H", nl) + b"".join(b"\x03" + x for x in labels)
            self.assertEqual(body(w.COLUMNS, b.hex()), nl == 1024)
            col = w.Column("e", w.T_ENUM, 0, 0, tuple(x.decode() for x in labels))
            try:
                w.msg_put(w.Msg(w.COLUMNS, columns=w.ColumnsMsg([col])))
                self.assertEqual(nl, 1024)
            except w.WireError:
                self.assertEqual(nl, 1025)

    def test_counts_refused_before_sizing(self):
        """t_wire.c lines 1074-1087: a count past its bytes refused"""
        for t, h in ((w.QUERY, "00100000 01000000 61 0000"), (w.COLUMNS, "0001 0161 01 0000 0000"),
                     (w.COLUMNS, "0100 0161 0d 0000 0000 0004")):
            self.assertFalse(body(t, h))


class Platform(unittest.TestCase):
    def test_python_ssl_has_no_exporter(self):
        """section 8f's premise for this driver, proved: Python's ssl module computes no TLS exporter (RFC 9266), only
        tls-unique, which RFC 9266 leaves undefined for TLS 1.3; so the driver binds by tls-server-end-point. A Python
        that gains it fails here: switch to the exporter then"""
        self.assertEqual(ssl.CHANNEL_BINDING_TYPES, ["tls-unique"])
        for cls in (ssl.SSLSocket, ssl.SSLObject):
            names = [x for x in dir(cls) if "export" in x.lower() or "keying" in x.lower()]
            self.assertEqual(names, [], cls)


if __name__ == "__main__":
    unittest.main()
