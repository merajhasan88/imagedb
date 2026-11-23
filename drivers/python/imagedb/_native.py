"""Wire values to and from Python's own types, without loss.

DECIMAL: decimal.Decimal built from its digits (never through a context's arithmetic, whose 28 digits would round a
38-digit value); INT64: int; FLOAT64: float, bit for bit; BOOL: bool; TEXT and ENUM: str; BYTEA: bytes; UUID: uuid.UUID;
DATE: datetime.date; TIME: datetime.time; TIMESTAMP: a naive datetime.datetime; TIMESTAMPTZ: an aware one in UTC;
INTERVAL: Interval(months, days, microseconds). Every date and time by integer timedelta arithmetic from an epoch
constant, never through a float (fromtimestamp, timestamp()). A NULL is None (its wire type is its column's).
"""

import datetime as _dt
import math
import struct
import uuid as _uuid
from collections import namedtuple
from decimal import Decimal

from . import _wire as w

_EPOCH = _dt.datetime(1970, 1, 1)
_EPOCH_TZ = _dt.datetime(1970, 1, 1, tzinfo=_dt.timezone.utc)
_EPOCH_ORD = _dt.date(1970, 1, 1).toordinal()  # 719163
_US = _dt.timedelta(microseconds=1)
_F8 = struct.Struct("<d")
_U8 = struct.Struct("<Q")


class Interval(namedtuple("Interval", "months days microseconds")):
    """imagedb's INTERVAL: any triple of i32 months, i32 days and i64 microseconds (PostgreSQL's), kept as it is: one
    month is not 30 days, nor one day 24 hours. to_timedelta() for one of no months."""
    __slots__ = ()

    def __new__(cls, months=0, days=0, microseconds=0):
        for x in (months, days, microseconds):
            if not isinstance(x, int) or isinstance(x, bool):
                raise TypeError("Interval's fields are integers")
        return super().__new__(cls, months, days, microseconds)

    def to_timedelta(self):
        if self.months:
            raise ValueError("an INTERVAL with months is no fixed span: it has no timedelta")
        return _dt.timedelta(days=self.days, microseconds=self.microseconds)


class Null:
    """a NULL parameter of a wire type (the engine binds a NULL parameter by its type): Null(imagedb.TEXT_T). A plain
    None is a NULL of no type, which the engine takes into any column but refuses where an expression wants a type."""
    __slots__ = ("type",)

    def __init__(self, type_code):
        if not isinstance(type_code, int) or not 0 <= type_code <= w.T_LAST:
            raise ValueError("a NULL's type is a wire type, 0 to 13")
        self.type = type_code

    def __repr__(self):
        return "Null(%s)" % w.TYPE_NAMES[self.type]

    def __eq__(self, other):
        return isinstance(other, Null) and other.type == self.type

    def __hash__(self):
        return hash(("Null", self.type))


class EncodeError(ValueError):
    """a Python value with no wire value that keeps it exactly"""


def dec_native(scale, d):
    sign = 1 if d < 0 else 0
    return Decimal((sign, tuple(int(c) for c in str(-d if sign else d)), -scale))


def time_native(us):
    s, u = divmod(us, 1000000)
    m, s = divmod(s, 60)
    h, m = divmod(m, 60)
    return _dt.time(h, m, s, u)


def to_native(v):
    """a decoded wire Value as a Python value"""
    if v.null:
        return None
    t, d = v.type, v.data
    if t == w.T_INT64:
        return d
    if t == w.T_TEXT or t == w.T_ENUM:
        return d.decode("utf-8")
    if t == w.T_DECIMAL:
        return dec_native(d[0], d[1])
    if t == w.T_FLOAT64:
        return _F8.unpack(_U8.pack(d))[0]
    if t == w.T_BOOL:
        return d == 1
    if t == w.T_TIMESTAMP:
        return _EPOCH + _dt.timedelta(microseconds=d)
    if t == w.T_TIMESTAMPTZ:
        return _EPOCH_TZ + _dt.timedelta(microseconds=d)
    if t == w.T_DATE:
        return _dt.date.fromordinal(_EPOCH_ORD + d)
    if t == w.T_TIME:
        return time_native(d)
    if t == w.T_UUID:
        return _uuid.UUID(bytes=d)
    if t == w.T_BYTEA:
        return d
    if t == w.T_INTERVAL:
        return Interval(*d)
    raise EncodeError("no such type %r" % t)


def _dec_value(x):
    if not x.is_finite():
        raise EncodeError("a DECIMAL is finite: %s has no wire value" % x)
    sign, digits, exp = x.as_tuple()
    if not any(digits):
        unscaled, scale = 0, max(0, -exp)
    elif exp >= 0:
        if exp + len(digits) > 38:
            raise EncodeError("a DECIMAL holds 38 digits: %s is past them" % x)
        unscaled, scale = int("".join(map(str, digits))) * 10 ** exp, 0
    else:
        unscaled, scale = int("".join(map(str, digits))), -exp
    # trailing zeros the wire cannot hold (a scale past 38, or 39 digits): the same value at the scale that fits (the
    # engine binds a DECIMAL parameter by its value, never its spelling)
    while (scale > 38 or unscaled >= w.DEC_LIM) and scale > 0 and unscaled % 10 == 0:
        unscaled //= 10
        scale -= 1
    if scale > 38:
        raise EncodeError("a DECIMAL's scale is 0 to 38: %s needs %d" % (x, scale))
    if unscaled >= w.DEC_LIM:
        raise EncodeError("a DECIMAL holds 38 digits: %s is past them" % x)
    return w.Value(w.T_DECIMAL, False, (scale, -unscaled if sign else unscaled))


def from_native(x):
    """a Python value as a wire Value (a parameter): EncodeError for one no wire value keeps exactly"""
    if x is None:
        return w.NULL_NONE
    if isinstance(x, Null):
        return w.Value(x.type, True, None)
    if isinstance(x, bool):  # before int: a bool is an int
        return w.Value(w.T_BOOL, False, 1 if x else 0)
    if isinstance(x, int):
        if w.I64_MIN <= x <= w.I64_MAX:
            return w.Value(w.T_INT64, False, int(x))
        if -w.DEC_LIM < x < w.DEC_LIM:  # past INT64: a DECIMAL of scale 0, as the engine reads such a literal
            return w.Value(w.T_DECIMAL, False, (0, int(x)))
        raise EncodeError("an integer of more than 38 digits has no wire value")
    if isinstance(x, float):
        if not math.isfinite(x):
            raise EncodeError("a FLOAT64 is finite: %r has no wire value" % x)
        if x == 0.0:
            x = 0.0  # -0.0 as 0.0: the engine keeps one zero, and the wire refuses -0
        return w.Value(w.T_FLOAT64, False, _U8.unpack(_F8.pack(x))[0])
    if isinstance(x, Decimal):
        return _dec_value(x)
    if isinstance(x, str):
        try:
            b = x.encode("utf-8")
        except UnicodeEncodeError:
            raise EncodeError("a TEXT is UTF-8: this str holds a lone surrogate") from None
        if b"\x00" in b:
            raise EncodeError("a TEXT holds no NUL")
        if len(b) > w.VALUE_MAX:
            raise EncodeError("a TEXT is at most 65,535 bytes (%d)" % len(b))
        return w.Value(w.T_TEXT, False, b)
    if isinstance(x, (bytes, bytearray, memoryview)):
        b = bytes(x)
        if len(b) > w.VALUE_MAX:
            raise EncodeError("a BYTEA is at most 65,535 bytes (%d)" % len(b))
        return w.Value(w.T_BYTEA, False, b)
    if isinstance(x, _dt.datetime):  # before date: a datetime is a date
        if x.tzinfo is not None and x.utcoffset() is not None:
            us = (x - _EPOCH_TZ) // _US
            t = w.T_TIMESTAMPTZ
        else:
            us = (x.replace(tzinfo=None) - _EPOCH) // _US
            t = w.T_TIMESTAMP
        if not w.TS_MIN_US <= us <= w.TS_MAX_US:
            raise EncodeError("a %s is in years 1 to 9999 (in UTC)" % w.TYPE_NAMES[t])
        return w.Value(t, False, us)
    if isinstance(x, _dt.date):
        return w.Value(w.T_DATE, False, x.toordinal() - _EPOCH_ORD)
    if isinstance(x, _dt.time):
        if x.tzinfo is not None:
            raise EncodeError("a TIME has no zone: pass a naive datetime.time")
        return w.Value(w.T_TIME, False, ((x.hour * 60 + x.minute) * 60 + x.second) * 1000000 + x.microsecond)
    if isinstance(x, Interval):
        v = w.Value(w.T_INTERVAL, False, tuple(x))
        if not w.value_ok(v):
            raise EncodeError("an INTERVAL's months and days are i32, its microseconds i64")
        return v
    if isinstance(x, _dt.timedelta):
        v = w.Value(w.T_INTERVAL, False, (0, x.days, x.seconds * 1000000 + x.microseconds))
        if not w.value_ok(v):
            raise EncodeError("an INTERVAL's days are i32")
        return v
    if isinstance(x, _uuid.UUID):
        return w.Value(w.T_UUID, False, x.bytes)
    raise EncodeError("no wire type for a parameter of Python type %s" % type(x).__name__)
