"""IMDBWIR1's bytes (docs/n1-design.md section 4), the Python driver's one implementation of them.

Pure functions over bytes: no socket, no state. Every decoder is strict, as server/wire.c's: exact lengths, no trailing
bytes, zero padding where the layout pads, every count bounded by the bytes left before anything is sized by it, every
text strict UTF-8 without NUL. Each field has one predicate, which its decoder and its encoder both apply: an encoder
never writes what its decoder refuses (WireError instead), and any bytes a decoder takes encode back to themselves.

Values here are wire values (Value: a type, a NULL flag and the type's raw data, as wire.h's imdbw_value); _native.py
maps them to and from Python's types.
"""

import hashlib
import hmac
import struct
from collections import namedtuple

MAGIC = b"IMDBWIR1"
VERSION = 1
USER = 64          # a role name's field: UTF-8, 1 to 63 bytes, NUL-padded
NONCE = 32
SALT = 64          # a verifier's salt: 8 to 64 bytes
KEY = 32
PREAUTH_HEAD = 12  # every pre-auth message's first bytes, in every version: the magic and u32 its version
HELLO_LEN = 112
CHALLENGE_LEN = 120
PROOF_LEN = 32
VERDICT_LEN = 36
AUTHMSG_LEN = 279
AUTH_MAGIC = b"IMDBWIR1-SCRAM"
HEAD = 5                 # a frame's u32 length and u8 type
FRAME_MAX = 16 << 20     # a frame's type and body
BATCH_MAX = 4096         # statements in a QUERY, parameter sets in an EXECUTE
VALUES_MAX = 256         # values a statement or a set takes; columns in a result
NAME_MAX = 63            # a prepared statement's name
COLNAME_MAX = 70         # a result column's name
SQL_MAX = 1 << 22        # one statement's text
VALUE_MAX = 65535        # a TEXT's or a BYTEA's bytes
LABEL_MAX = 63           # an ENUM label's bytes
LABELS_MAX = 1024        # an ENUM's labels
STATUS_MAX = 511         # a DONE's status text
MESSAGE_MAX = 4096       # an ERROR's or WARNING's text, a COPY_FAIL's reason
SESSIONS_MAX = 65536
SESS_MIN = 23            # a SESSIONS_LIST entry's bytes at least
SCRAM_ITER_MIN = 1000
SCRAM_ITER_MAX = 1000000
SCRAM_SALT_MIN = 8
PW_MAX = 1024
COPY_PIECE = 1 << 20     # the C client's COPY_DATA frames: at most 1 MiB each (client.c:432)

EP_TCP, EP_UNIX = 1, 2
CB_NONE, CB_EXPORTER, CB_ENDPOINT = 0, 1, 2
VERDICT_OK, VERDICT_REFUSED, VERDICT_BINDING = 0, 1, 2

QUERY, PREPARE, EXECUTE, DEALLOCATE, COPY_DATA, COPY_DONE, COPY_FAIL, CANCEL, PING, TERMINATE, SESSIONS, KILL = range(1, 13)
CLIENT_LAST = 12
COLUMNS, ROWS, DONE, ERROR, WARNING, COPY_IN, COPY_OUT, READY, PONG, SESSIONS_LIST, KILL_DONE = range(64, 75)
SERVER_LAST = 74
FRAME_NAMES = {
    1: "QUERY", 2: "PREPARE", 3: "EXECUTE", 4: "DEALLOCATE", 5: "COPY_DATA", 6: "COPY_DONE", 7: "COPY_FAIL",
    8: "CANCEL", 9: "PING", 10: "TERMINATE", 11: "SESSIONS", 12: "KILL", 64: "COLUMNS", 65: "ROWS", 66: "DONE",
    67: "ERROR", 68: "WARNING", 69: "COPY_IN", 70: "COPY_OUT", 71: "READY", 72: "PONG", 73: "SESSIONS_LIST",
    74: "KILL_DONE",
}

IDLE, IN_TXN, DOOMED = 0, 1, 2               # READY's states
KILL_CANCEL, KILL_TERMINATE = 1, 2           # KILL's kinds
KILLED, KILL_NONE = 0, 1                     # KILL_DONE's codes
SS_IDLE, SS_RUNNING, SS_IN_TXN, SS_COPY = 0, 1, 2, 3  # a session's state in SESSIONS_LIST

# a value's wire type: the contract, not the engine's internal forms
T_NONE, T_INT64, T_FLOAT64, T_BOOL, T_TEXT, T_DECIMAL, T_TIMESTAMP, T_TIMESTAMPTZ, T_DATE, T_TIME, T_UUID, T_BYTEA, \
    T_INTERVAL, T_ENUM = range(14)
T_LAST = 13
TYPE_NAMES = {
    0: "NONE", 1: "INT64", 2: "FLOAT64", 3: "BOOL", 4: "TEXT", 5: "DECIMAL", 6: "TIMESTAMP", 7: "TIMESTAMPTZ",
    8: "DATE", 9: "TIME", 10: "UUID", 11: "BYTEA", 12: "INTERVAL", 13: "ENUM",
}
NULL_TAG = 0x80

TS_MIN_US = -62135596800000000   # 0001-01-01 00:00:00
TS_MAX_US = 253402300799999999   # 9999-12-31 23:59:59.999999
DATE_MIN = -719162               # 0001-01-01 in days since 1970-01-01
DATE_MAX = 2932896               # 9999-12-31
TIME_MAX = 86399999999           # 23:59:59.999999
DEC_LIM = 10 ** 38
I64_MIN, I64_MAX = -(1 << 63), (1 << 63) - 1
I32_MIN, I32_MAX = -(1 << 31), (1 << 31) - 1
U64_MAX = (1 << 64) - 1
U32_MAX = (1 << 32) - 1

CORRUPT, LIMIT, UNSUPPORTED, INVALID = "corrupt", "limit", "unsupported", "invalid"


class WireError(Exception):
    """A decoder's refusal (kind CORRUPT, LIMIT or UNSUPPORTED, as wire.c's IMDB_ERR_*) or an encoder's (INVALID or
    LIMIT): what the other side would refuse is never written."""

    def __init__(self, kind, msg):
        super().__init__("wire: " + msg)
        self.kind = kind


def _bad(msg):
    return WireError(CORRUPT, msg)


# ---- a value: its wire type, NULL or not, and its raw data ----
#   INT64, TIMESTAMP, TIMESTAMPTZ, TIME: int; FLOAT64: int (the IEEE 754 bits); BOOL: 0 or 1; TEXT, ENUM: bytes (UTF-8);
#   BYTEA: bytes; UUID: 16 bytes; DECIMAL: (scale, unscaled int); DATE: int days; INTERVAL: (months, days, microseconds)
Value = namedtuple("Value", "type null data")
NULL_NONE = Value(T_NONE, True, None)

_I8 = struct.Struct("<q")
_U8B = struct.Struct("<Q")
_I4 = struct.Struct("<i")
_U4 = struct.Struct("<I")
_U2 = struct.Struct("<H")
_IV = struct.Struct("<iiq")
_HEADS = struct.Struct("<IB")


def utf8_ok(b):
    """UTF-8 by the engine's rule (codec.c's imdb_utf8_valid): no NUL, no overlong form, no surrogate, nothing past
    U+10FFFF. Python's strict UTF-8 decoder is RFC 3629's (the tests hold it to a port of wire.c's utf8_valid)."""
    if b"\x00" in b:
        return False
    try:
        b.decode("utf-8")
    except UnicodeDecodeError:
        return False
    return True


def utf8_fit(b, maximum):
    """The longest prefix of b, at most maximum bytes, that is UTF-8 without NUL (wire.c's imdbw_utf8_fit): an engine
    message (or a COPY_FAIL reason) trimmed at a character's boundary."""
    k = min(len(b), maximum)
    cut = b[:k]
    nul = cut.find(b"\x00")
    if nul >= 0:
        cut = cut[:nul]
    try:
        cut.decode("utf-8")
        return len(cut)
    except UnicodeDecodeError as e:
        return e.start


def utf8_chars(b):
    """characters of valid UTF-8: the bytes that begin one"""
    return len(b) - sum(1 for c in b if c & 0xC0 == 0x80)


class Reader:
    """a bounded reader (imdb_rd): every read checked against the bytes left"""

    __slots__ = ("b", "pos", "end")

    def __init__(self, b, pos=0, end=None):
        self.b = b
        self.pos = pos
        self.end = len(b) if end is None else end

    def left(self):
        return self.end - self.pos

    def take(self, n, what="a body cut short"):
        p = self.pos
        if n > self.end - p:
            raise _bad(what)
        self.pos = p + n
        return bytes(self.b[p:p + n])

    def u8(self, what="a body cut short"):
        p = self.pos
        if p >= self.end:
            raise _bad(what)
        self.pos = p + 1
        return self.b[p]

    def _st(self, st, what):
        p = self.pos
        if st.size > self.end - p:
            raise _bad(what)
        self.pos = p + st.size
        return st.unpack_from(self.b, p)[0]

    def u16(self, what="a body cut short"):
        return self._st(_U2, what)

    def u32(self, what="a body cut short"):
        return self._st(_U4, what)

    def i32(self, what="a body cut short"):
        return self._st(_I4, what)

    def u64(self, what="a body cut short"):
        return self._st(_U8B, what)

    def i64(self, what="a body cut short"):
        return self._st(_I8, what)


# ---- values ----

def value_ok(v):
    """the value's own rules: its decoder's and its encoder's (wire.c's imdbw_value_ok)"""
    t, d = v.type, v.data
    if v.null:
        return isinstance(t, int) and 0 <= t <= T_LAST  # a NULL of a type, or of none
    if t == T_INT64:
        return isinstance(d, int) and I64_MIN <= d <= I64_MAX
    if t == T_INTERVAL:
        return (isinstance(d, tuple) and len(d) == 3 and I32_MIN <= d[0] <= I32_MAX and I32_MIN <= d[1] <= I32_MAX
                and I64_MIN <= d[2] <= I64_MAX)
    if t == T_FLOAT64:  # finite, not -0 (the engine keeps one zero)
        return isinstance(d, int) and 0 <= d <= U64_MAX and ((d >> 52) & 0x7FF) != 0x7FF and d != 0x8000000000000000
    if t == T_BOOL:
        return d == 0 or d == 1
    if t == T_TEXT:
        return isinstance(d, bytes) and len(d) <= VALUE_MAX and utf8_ok(d)
    if t == T_BYTEA:
        return isinstance(d, bytes) and len(d) <= VALUE_MAX
    if t == T_ENUM:
        return isinstance(d, bytes) and len(d) <= LABEL_MAX and utf8_ok(d)
    if t == T_DECIMAL:
        return isinstance(d, tuple) and len(d) == 2 and 0 <= d[0] <= 38 and -DEC_LIM < d[1] < DEC_LIM
    if t in (T_TIMESTAMP, T_TIMESTAMPTZ):
        return isinstance(d, int) and TS_MIN_US <= d <= TS_MAX_US
    if t == T_DATE:
        return isinstance(d, int) and DATE_MIN <= d <= DATE_MAX
    if t == T_TIME:
        return isinstance(d, int) and 0 <= d <= TIME_MAX
    if t == T_UUID:
        return isinstance(d, bytes) and len(d) == 16
    return False  # no type: only a NULL has none


def value_put(out, v):
    """append the value's bytes to the bytearray out; WireError for a value its decoder would refuse"""
    if not value_ok(v):
        raise WireError(INVALID, "a value outside its type's rules (type %r)" % (v.type,))
    t, d = v.type, v.data
    if v.null:
        out.append(NULL_TAG | t)
        return
    out.append(t)
    if t in (T_INT64, T_TIMESTAMP, T_TIMESTAMPTZ, T_TIME):
        out += _I8.pack(d)
    elif t == T_FLOAT64:
        out += _U8B.pack(d)
    elif t == T_BOOL:
        out.append(d)
    elif t in (T_TEXT, T_BYTEA):
        out += _U4.pack(len(d))
        out += d
    elif t == T_ENUM:
        out.append(len(d))
        out += d
    elif t == T_DECIMAL:
        out.append(d[0])
        out += (d[1] & ((1 << 128) - 1)).to_bytes(16, "little")
    elif t == T_DATE:
        out += _I4.pack(d)
    elif t == T_UUID:
        out += d
    elif t == T_INTERVAL:
        out += _IV.pack(*d)


def value_bytes(v):
    out = bytearray()
    value_put(out, v)
    return bytes(out)


def value_get(r):
    """one value from the reader (wire.c's imdbw_value_get): WireError for bytes its rules refuse"""
    tag = r.u8("a value cut short")
    if tag & NULL_TAG:
        t = tag & 0x7F
        if t > T_LAST:
            raise _bad("a NULL of a type the protocol does not define")
        return Value(t, True, None)
    cut = "a value cut short"
    if tag in (T_INT64, T_TIMESTAMP, T_TIMESTAMPTZ, T_TIME):
        d = r.i64(cut)
    elif tag == T_FLOAT64:
        d = r.u64(cut)
    elif tag == T_BOOL:
        d = r.u8(cut)
    elif tag in (T_TEXT, T_BYTEA, T_ENUM):
        n = r.u8(cut) if tag == T_ENUM else r.u32(cut)
        lim = LABEL_MAX if tag == T_ENUM else VALUE_MAX
        if n > lim:  # before its bytes are asked for
            raise WireError(LIMIT, "a value of %d bytes (at most %d)" % (n, lim))
        d = r.take(n, cut)
    elif tag == T_DECIMAL:
        scale = r.u8(cut)
        raw = r.take(16, cut)
        d = (scale, int.from_bytes(raw, "little", signed=True))
    elif tag == T_DATE:
        d = r.i32(cut)
    elif tag == T_UUID:
        d = r.take(16, cut)
    elif tag == T_INTERVAL:
        raw = r.take(16, cut)
        d = _IV.unpack(raw)
    else:
        raise _bad("a value of a type the protocol does not define (a NULL's tag is 0x80 and its type)")
    v = Value(tag, False, d)
    if not value_ok(v):
        raise _bad("a value outside its type's rules")
    return v


# ---- before authentication: fixed sizes ----

def user_ok(user):
    """a role name's field: UTF-8, 1 to 63 bytes, no NUL"""
    return 1 <= len(user) < USER and utf8_ok(user)


def preauth_head(b):
    """the head every version keeps: its version (any number), UNSUPPORTED for a later magic, damage else"""
    if len(b) != PREAUTH_HEAD:
        raise _bad("a pre-auth head of another length")
    version = _U4.unpack_from(b, 8)[0]
    if b[:8] != MAGIC:
        if _later_magic(b[:8]):
            raise WireError(UNSUPPORTED, "%s, a later protocol, which this driver does not speak" % b[:8].decode("ascii"))
        raise _bad("not imagedb's protocol")
    if version < 1:
        raise _bad("protocol version 0")
    return version


def _later_magic(m):
    """another magic of the same family with a later number ("IMDBWIR2"): src/util.c's imdb_later_magic for an 8-byte
    magic whose last character is its digit"""
    return m[:7] == MAGIC[:7] and 0x30 <= m[7] <= 0x39 and m[7] > MAGIC[7]


def _magic_version(r):
    m = r.take(8, "a pre-auth message cut short")
    version = r.u32("a pre-auth message cut short")
    if m != MAGIC:
        if _later_magic(m):
            raise WireError(UNSUPPORTED, "%s, a later protocol, which this driver does not speak" % m.decode("ascii"))
        raise _bad("not imagedb's protocol")
    if version > VERSION:
        raise WireError(UNSUPPORTED, "protocol version %d, a later one, which this driver (version %d) does not speak"
                        % (version, VERSION))
    if version != VERSION:
        raise _bad("an unknown protocol version")
    return version


Hello = namedtuple("Hello", "version flags user nonce")
Challenge = namedtuple("Challenge", "version salt iterations nonce")
Verdict = namedtuple("Verdict", "code signature")


def hello_put(h):
    if h.version != VERSION or not 0 <= h.flags <= CB_ENDPOINT or not user_ok(h.user) or len(h.nonce) != NONCE:
        raise WireError(INVALID, "a hello its decoder would refuse")
    return MAGIC + _U4.pack(h.version) + _U4.pack(h.flags) + h.user + bytes(USER - len(h.user)) + h.nonce


def hello_get(b):
    if len(b) != HELLO_LEN:
        raise _bad("a hello of another length")
    r = Reader(b)
    version = _magic_version(r)
    flags = r.u32()
    u = r.take(USER)
    nonce = r.take(NONCE)
    if flags > CB_ENDPOINT:
        raise _bad("a hello with flags no version defines (a binding type but 0, 1, 2)")
    n = u.find(b"\x00")
    if n < 0 or not user_ok(u[:n]) or any(u[n:]):
        raise _bad("a hello's role name is not 1 to 63 bytes of UTF-8, NUL-padded")
    return Hello(version, flags, u[:n], nonce)


def _challenge_ok(c):
    return (c.version == VERSION and SCRAM_SALT_MIN <= len(c.salt) <= SALT and
            SCRAM_ITER_MIN <= c.iterations <= SCRAM_ITER_MAX and len(c.nonce) == NONCE)


def challenge_put(c):
    if not _challenge_ok(c):
        raise WireError(INVALID, "a challenge its decoder would refuse")
    return (MAGIC + _U4.pack(c.version) + bytes([len(c.salt)]) + c.salt + bytes(SALT - len(c.salt)) +
            _U4.pack(c.iterations) + c.nonce + bytes(7))


def challenge_get(b):
    if len(b) != CHALLENGE_LEN:
        raise _bad("a challenge of another length")
    r = Reader(b)
    version = _magic_version(r)
    salt_len = r.u8()
    salt = r.take(SALT)
    it = r.u32()
    nonce = r.take(NONCE)
    pad = r.take(7)
    c = Challenge(version, salt[:salt_len], it, nonce)
    if not SCRAM_SALT_MIN <= salt_len <= SALT or not _challenge_ok(c) or any(salt[salt_len:]):
        raise _bad("a challenge's salt is not 8 to 64 bytes, zero-padded, or its iterations not 1,000 to 1,000,000")
    if any(pad):
        raise _bad("a challenge's padding is not zero")
    return c


def _verdict_ok(v):
    return len(v.signature) == KEY and (v.code == VERDICT_OK or (v.code in (VERDICT_REFUSED, VERDICT_BINDING) and
                                                                 not any(v.signature)))


def verdict_put(v):
    if not _verdict_ok(v):
        raise WireError(INVALID, "a verdict its decoder would refuse")
    return _U4.pack(v.code) + v.signature


def verdict_get(b):
    if len(b) != VERDICT_LEN:
        raise _bad("a verdict of another length")
    v = Verdict(_U4.unpack_from(b, 0)[0], bytes(b[4:]))
    if not _verdict_ok(v):
        raise _bad("a verdict neither accepted nor refused, or a refusal carrying a signature")
    return v


# ---- SCRAM-SHA-256 (RFC 5802's computation over the AuthMessage) ----

def auth_message(endpoint, hello, challenge, binding):
    """"IMDBWIR1-SCRAM" | u8 endpoint | the hello's 112 bytes | the challenge's 120 | binding[32]: every byte either side
    sent before the proof, bound"""
    if len(hello) != HELLO_LEN or len(challenge) != CHALLENGE_LEN or len(binding) != KEY or endpoint not in (1, 2):
        raise WireError(INVALID, "an AuthMessage's parts")
    am = AUTH_MAGIC + bytes([endpoint]) + hello + challenge + binding
    assert len(am) == AUTHMSG_LEN
    return am


def password_ok(pw):
    """a password's bytes as CREATE ROLE takes one: 1 to 1,024 bytes of printable ASCII (no SASLprep in imagedb yet)"""
    return 1 <= len(pw) <= PW_MAX and all(0x20 <= c <= 0x7E for c in pw)


def scram_client(pw, challenge, am):
    """the client's proof and the server's signature it expects (RFC 5802 with SHA-256); WireError for a password CREATE
    ROLE would refuse or a challenge its decoder would"""
    if not password_ok(pw) or not _challenge_ok(challenge) or len(am) != AUTHMSG_LEN:
        raise WireError(INVALID, "a password is 1 to 1,024 printable ASCII bytes")
    sp = hashlib.pbkdf2_hmac("sha256", pw, challenge.salt, challenge.iterations, 32)
    ck = hmac.new(sp, b"Client Key", hashlib.sha256).digest()
    sk = hmac.new(sp, b"Server Key", hashlib.sha256).digest()
    stored = hashlib.sha256(ck).digest()
    cs = hmac.new(stored, am, hashlib.sha256).digest()
    proof = bytes(a ^ b for a, b in zip(ck, cs))
    server_sig = hmac.new(sk, am, hashlib.sha256).digest()
    return proof, server_sig


# ---- after authentication: frames ----

def head_get(b, from_server):
    """a frame's head: its length (of its type and body: 1 to 16 MiB) and a type of the direction's"""
    n, t = _HEADS.unpack_from(b, 0)
    if n < 1 or n > FRAME_MAX:
        raise WireError(LIMIT, "a frame of %d bytes (1 to %d)" % (n, FRAME_MAX))
    if not ((COLUMNS <= t <= SERVER_LAST) if from_server else (QUERY <= t <= CLIENT_LAST)):
        raise _bad("a frame of a type this side does not send (%d)" % t)
    return n, t


def frame(t, body=b""):
    n = 1 + len(body)
    if n > FRAME_MAX:
        raise WireError(LIMIT, "a frame past 16 MiB (%d bytes)" % n)
    return _HEADS.pack(n, t) + body


def _text_ok(b, lo, hi):
    return lo <= len(b) <= hi and utf8_ok(b)


def _text_get(r, lenbytes, lo, hi):
    n = r.u8() if lenbytes == 1 else r.u16() if lenbytes == 2 else r.u32()
    if n < lo or n > hi:
        raise WireError(LIMIT, "a text of %d bytes (%d to %d)" % (n, lo, hi))
    b = r.take(n, "a text cut short")
    if not utf8_ok(b):
        raise _bad("a text not UTF-8 without NUL")
    return b


def _text_put(out, lenbytes, lo, hi, b):
    if not isinstance(b, bytes) or not _text_ok(b, lo, hi):
        raise WireError(INVALID, "a text of %s bytes (%d to %d) or not UTF-8 without NUL"
                        % (len(b) if isinstance(b, bytes) else "?", lo, hi))
    if lenbytes == 1:
        out.append(len(b))
    elif lenbytes == 2:
        out += _U2.pack(len(b))
    else:
        out += _U4.pack(len(b))
    out += b


class Column(namedtuple("Column", "name type precision scale labels")):
    """a result column: its name (str), wire type (0 not known: each value its own type), precision, scale (DECIMAL; a
    VARCHAR's length in precision; an INTEGER's width) and an ENUM's labels (a tuple of str, in the type's order)"""
    __slots__ = ()


def _col_shape_ok(name_b, t, p, s, nlabels):
    if not _text_ok(name_b, 1, COLNAME_MAX) or not 0 <= t <= T_LAST:
        return False
    if t != T_ENUM and nlabels:
        return False
    if t == T_ENUM and nlabels > LABELS_MAX:
        return False
    if t == T_DECIMAL:  # precision 0: not known (a result's column), 38 digits
        return p <= 38 and s <= (p if p else 38)
    if t == T_INT64:
        return p in (0, 16, 32) and s == 0
    if t == T_TEXT:
        return s == 0  # precision: a VARCHAR's length (u16), 0 none
    return p == 0 and s == 0


class ColumnsMsg:
    """a COLUMNS message, with what a ROWS needs to be held to it"""

    __slots__ = ("columns", "_label_sets")

    def __init__(self, columns):
        self.columns = tuple(columns)
        self._label_sets = tuple(frozenset(lb.encode("utf-8") for lb in c.labels) if c.type == T_ENUM else None
                                 for c in self.columns)


def value_fits(col, labelset, v):
    """a value checked against its column (ROWS' rule, wire.c's imdbw_value_fits): NULL of the column's type, or its type
    at the column's scale and within its precision, an integer within its width, a TEXT within its VARCHAR's
    characters, an ENUM one of its labels; any valid value under a column of no type"""
    if not value_ok(v):
        return False
    ct = col.type
    if ct == T_NONE:
        return True
    if v.type != ct:  # a NULL too: one tag a column, its type's
        return False
    if v.null:
        return True
    if ct == T_DECIMAL:
        lim = DEC_LIM if not col.precision else 10 ** col.precision
        return v.data[0] == col.scale and -lim < v.data[1] < lim
    if ct == T_INT64:
        if col.precision == 16:
            return -32768 <= v.data <= 32767
        if col.precision == 32:
            return I32_MIN <= v.data <= I32_MAX
        return True
    if ct == T_TEXT:
        return not col.precision or len(v.data.decode("utf-8")) <= col.precision
    if ct == T_ENUM:
        return v.data in labelset
    return True


ReadPoint = namedtuple("ReadPoint", "commit hash digest lake_commit lake_manifest db_id own")
ReadPoint.__doc__ = ("a DONE's read point (the engine's imdb_result: snap, head, digest, lake_seq, lake_manifest, db_id, "
                     "snap_own): the commit read, its hash, the state digest there, the lake's commit and manifest "
                     "published when the statement ran, the database's id, and whether the read saw its "
                     "transaction's own pending writes")
WriteCommit = namedtuple("WriteCommit", "commit hash")
Session = namedtuple("Session", "id role endpoint state age_ms name")


class Msg:
    """a frame's body, decoded (wire.h's imdbw_msg); the fields its type has:
    QUERY: stmts, a list of (statement bytes, [Value]); PREPARE: name, text; EXECUTE: name, nvals, sets ([[Value]]);
    DEALLOCATE: name; COPY_DATA, COPY_OUT: data; COPY_FAIL, WARNING: message (str); KILL: kind, sid;
    COLUMNS: columns (a ColumnsMsg); ROWS: rows ([[Value]]); DONE: status (str), count, read (ReadPoint or None),
    write (WriteCommit or None); ERROR: code, index, message; READY: state; SESSIONS_LIST: sessions;
    KILL_DONE: code, sid"""

    def __init__(self, t, **kw):
        self.type = t
        self.__dict__.update(kw)

    def __repr__(self):
        return "<%s %s>" % (FRAME_NAMES.get(self.type, self.type),
                            ", ".join("%s=%r" % kv for kv in self.__dict__.items() if kv[0] != "type"))


def _values_get(r, n, cols=None):
    """n values; with cols (a ColumnsMsg), rows of its count, each value held to its column"""
    if n > r.left():  # each value is at least one byte
        raise _bad("more values than bytes")
    if cols is None:
        out = []
        for _ in range(n):
            v = value_get(r)
            if v.type == T_ENUM and not v.null:
                raise _bad("an ENUM parameter: a label is sent as TEXT")
            out.append(v)
        return out
    cs, ls = cols.columns, cols._label_sets
    nc = len(cs)
    rows = []
    for _ in range(n // nc):
        row = []
        for k in range(nc):
            v = value_get(r)
            if not value_fits(cs[k], ls[k], v):
                raise _bad("a value its column does not take (column %d, %s)" % (k + 1, cs[k].name))
            row.append(v)
        rows.append(row)
    return rows


def _name_get(r):
    return _text_get(r, 1, 1, NAME_MAX).decode("utf-8")


def _name_put(out, name):
    _text_put(out, 1, 1, NAME_MAX, name.encode("utf-8") if isinstance(name, str) else name)


def _col_get(r):
    name = _text_get(r, 1, 1, COLNAME_MAX)
    t = r.u8("a column cut short")
    p = r.u16("a column cut short")
    s = r.u16("a column cut short")
    labels = ()
    if t == T_ENUM:
        n = r.u16("an ENUM's labels past their bounds or bytes")
        if n > LABELS_MAX or n > r.left():
            raise _bad("an ENUM's labels past their bounds or bytes")
        labels = tuple(_text_get(r, 1, 0, LABEL_MAX) for _ in range(n))
    if not _col_shape_ok(name, t, p, s, len(labels)):
        raise _bad("a column's type, precision or scale its type does not take")
    return name, t, p, s, labels


def _done_ok(status, write):
    return _text_ok(status, 0, STATUS_MAX) and (write is None or write.commit >= 1)


def _sess_ok(s, prev):
    return (s.id > prev and s.role >= 1 and s.endpoint in (1, 2) and 0 <= s.state <= SS_COPY and
            _text_ok(s.name.encode("utf-8"), 0, USER - 1))


def msg_get(t, body, cols=None):
    """a frame's body decoded (wire.c's imdbw_msg_get): a ROWS against the COLUMNS before it (cols, a ColumnsMsg)"""
    r = Reader(body)
    m = _body_get(t, r, cols)
    if r.left():
        raise _bad("a body with bytes past its end")
    return m


def _body_get(t, r, cols):
    if t == QUERY:
        n = r.u32()
        if n < 1 or n > BATCH_MAX or n > r.left() // 7:  # a statement: 7 bytes at least
            raise _bad("a QUERY of 1 to 4,096 statements it holds the bytes of")
        stmts = []
        for _ in range(n):
            text = _text_get(r, 4, 1, SQL_MAX)
            nv = r.u16()
            if nv > VALUES_MAX:
                raise _bad("a statement's values: at most 256")
            stmts.append((text, _values_get(r, nv)))
        return Msg(t, stmts=stmts)
    if t == PREPARE:
        name = _name_get(r)
        return Msg(t, name=name, text=_text_get(r, 4, 1, SQL_MAX))
    if t == EXECUTE:
        name = _name_get(r)
        nsets = r.u32()
        nvals = r.u16()
        if nsets < 1 or nsets > BATCH_MAX or nvals > VALUES_MAX:
            raise _bad("an EXECUTE of 1 to 4,096 sets of at most 256 values")
        flat = _values_get(r, nsets * nvals)
        return Msg(t, name=name, nvals=nvals, sets=[flat[i * nvals:(i + 1) * nvals] for i in range(nsets)])
    if t == DEALLOCATE:
        return Msg(t, name=_name_get(r))
    if t == KILL:
        kind = r.u8()
        sid = r.u64()
        if kind not in (KILL_CANCEL, KILL_TERMINATE) or not sid:
            raise _bad("a KILL's kind (1 cancel, 2 terminate) or a session id of 0")
        return Msg(t, kind=kind, sid=sid)
    if t == KILL_DONE:
        code = r.u8()
        sid = r.u64()
        if code > KILL_NONE or not sid:
            raise _bad("a KILL_DONE's code or a session id of 0")
        return Msg(t, code=code, sid=sid)
    if t == SESSIONS_LIST:
        n = r.u32()
        if n > SESSIONS_MAX or n > r.left() // SESS_MIN:
            raise _bad("a SESSIONS_LIST of at most 65,536 sessions it holds the bytes of")
        out = []
        prev = 0
        for _ in range(n):
            sid = r.u64("a session cut short")
            role = r.u32("a session cut short")
            ep = r.u8("a session cut short")
            st = r.u8("a session cut short")
            age = r.u64("a session cut short")
            name = _text_get(r, 1, 0, USER - 1).decode("utf-8")
            s = Session(sid, role, ep, st, age, name)
            if not _sess_ok(s, prev):
                raise _bad("a session's id out of order, or its role, endpoint or state")
            prev = sid
            out.append(s)
        return Msg(t, sessions=out)
    if t in (COPY_DATA, COPY_OUT):
        if not r.left():
            raise _bad("a COPY piece of no bytes")
        return Msg(t, data=r.take(r.left()))
    if t in (COPY_FAIL, WARNING):
        return Msg(t, message=_text_get(r, 2, 0, MESSAGE_MAX).decode("utf-8"))
    if t in (SESSIONS, COPY_DONE, CANCEL, PING, TERMINATE, COPY_IN, PONG):
        return Msg(t)
    if t == COLUMNS:
        n = r.u16()
        if n < 1 or n > VALUES_MAX or n > r.left() // 7:  # a column: 7 bytes at least
            raise _bad("a COLUMNS of 1 to 256 columns it holds the bytes of")
        cs = []
        for _ in range(n):
            name, ct, p, s, labels = _col_get(r)
            if len(set(labels)) != len(labels):
                raise _bad("an ENUM's labels not distinct")
            cs.append(Column(name.decode("utf-8"), ct, p, s, tuple(lb.decode("utf-8") for lb in labels)))
        return Msg(t, columns=ColumnsMsg(cs))
    if t == ROWS:
        if cols is None or not cols.columns:
            raise _bad("a ROWS with no COLUMNS before it")
        nsets = r.u32()
        if nsets < 1:
            raise _bad("a ROWS of no row")
        return Msg(t, rows=_values_get(r, nsets * len(cols.columns), cols))
    if t == DONE:
        status = _text_get(r, 2, 0, STATUS_MAX)
        count = r.u64()
        hr = r.u8()
        if hr > 1:
            raise _bad("a DONE's read point flag")
        read = None
        if hr:
            rc = r.u64()
            rh = r.take(32)
            dg = r.take(32)
            lc = r.u64()
            lm = r.take(32)
            dbid = r.take(16)
            own = r.u8()
            if own > 1:
                raise _bad("a DONE's own-writes flag")
            read = ReadPoint(rc, rh, dg, lc, lm, dbid, bool(own))
        hw = r.u8()
        if hw > 1:
            raise _bad("a DONE's write flag")
        write = None
        if hw:
            write = WriteCommit(r.u64(), r.take(32))
        if not _done_ok(status, write):
            raise _bad("a DONE's write at commit 0")
        return Msg(t, status=status.decode("utf-8"), count=count, read=read, write=write)
    if t == ERROR:
        code = r.u32()
        index = r.u32()
        if not code or index >= BATCH_MAX:
            raise _bad("an ERROR's code 0 or its statement's index")
        return Msg(t, code=code, index=index, message=_text_get(r, 2, 0, MESSAGE_MAX).decode("utf-8"))
    if t == READY:
        state = r.u8()
        if state > DOOMED:
            raise _bad("a READY's state")
        return Msg(t, state=state)
    raise _bad("a frame of a type the protocol does not define")


def _values_put(out, vals, cols=None):
    if cols is None:
        for v in vals:
            if v.type == T_ENUM and not v.null:
                raise WireError(INVALID, "an ENUM parameter: a label is sent as TEXT")
            value_put(out, v)
        return
    cs, ls = cols.columns, cols._label_sets
    for k, v in enumerate(vals):
        if not value_fits(cs[k % len(cs)], ls[k % len(cs)], v):
            raise WireError(INVALID, "a value its column does not take")
        value_put(out, v)


def params_bytes(vals):
    """a parameter run's bytes: each value by its rules, never a non-NULL ENUM (a label is sent as TEXT)"""
    if len(vals) > VALUES_MAX:
        raise WireError(INVALID, "a statement or a set takes at most 256 values (%d)" % len(vals))
    out = bytearray()
    _values_put(out, vals)
    return bytes(out)


def query_frame(stmts):
    """QUERY from [(statement bytes, number of values, their bytes from params_bytes)]"""
    if not 1 <= len(stmts) <= BATCH_MAX:
        raise WireError(INVALID, "a QUERY holds 1 to 4,096 statements (%d)" % len(stmts))
    out = bytearray(_U4.pack(len(stmts)))
    for text, n, vb in stmts:
        _text_put(out, 4, 1, SQL_MAX, text)
        if n > VALUES_MAX:
            raise WireError(INVALID, "a statement's values: at most 256")
        out += _U2.pack(n)
        out += vb
    return frame(QUERY, bytes(out))


def execute_frame(name, nvals, nsets, vb):
    """EXECUTE of nsets sets of nvals values each, their bytes (params_bytes of each set) concatenated in set order"""
    if not 1 <= nsets <= BATCH_MAX or not 0 <= nvals <= VALUES_MAX:
        raise WireError(INVALID, "an EXECUTE of 1 to 4,096 sets of at most 256 values")
    out = bytearray()
    _name_put(out, name)
    out += _U4.pack(nsets)
    out += _U2.pack(nvals)
    out += vb
    return frame(EXECUTE, bytes(out))


def msg_put(m, cols=None):
    """a message encoded as a frame, the exact bytes its decoder takes (a ROWS against its COLUMNS); WireError for a field
    its decoder would refuse"""
    t = m.type
    out = bytearray()
    if t == QUERY:
        return query_frame([(text, len(vals), params_bytes(vals)) for text, vals in m.stmts])
    elif t == PREPARE:
        _name_put(out, m.name)
        _text_put(out, 4, 1, SQL_MAX, m.text)
    elif t == EXECUTE:
        for s in m.sets:
            if len(s) != m.nvals:
                raise WireError(INVALID, "an EXECUTE's sets each of its count of values")
        return execute_frame(m.name, m.nvals, len(m.sets), b"".join(params_bytes(s) for s in m.sets))
    elif t == DEALLOCATE:
        _name_put(out, m.name)
    elif t in (COPY_DATA, COPY_OUT):
        if not m.data:
            raise WireError(INVALID, "a COPY piece of no bytes")
        out += m.data
    elif t in (COPY_FAIL, WARNING):
        _text_put(out, 2, 0, MESSAGE_MAX, m.message.encode("utf-8"))
    elif t == COLUMNS:
        cs = m.columns.columns
        if not 1 <= len(cs) <= VALUES_MAX:
            raise WireError(INVALID, "a COLUMNS of 1 to 256 columns")
        out += _U2.pack(len(cs))
        for c in cs:
            nb = c.name.encode("utf-8")
            lbs = [lb.encode("utf-8") for lb in c.labels]
            if not _col_shape_ok(nb, c.type, c.precision, c.scale, len(lbs)) or len(set(lbs)) != len(lbs):
                raise WireError(INVALID, "a column its decoder would refuse")
            _text_put(out, 1, 1, COLNAME_MAX, nb)
            out.append(c.type)
            out += _U2.pack(c.precision)
            out += _U2.pack(c.scale)
            if c.type == T_ENUM:
                out += _U2.pack(len(lbs))
                for lb in lbs:
                    _text_put(out, 1, 0, LABEL_MAX, lb)
    elif t == ROWS:
        if not m.rows or cols is None or not cols.columns:
            raise WireError(INVALID, "a ROWS of no row, or against no COLUMNS")
        out += _U4.pack(len(m.rows))
        for row in m.rows:
            if len(row) != len(cols.columns):
                raise WireError(INVALID, "a row of another count of values than its COLUMNS")
            _values_put(out, row, cols)
    elif t == DONE:
        st = m.status.encode("utf-8")
        if not _done_ok(st, m.write):
            raise WireError(INVALID, "a DONE its decoder would refuse")
        _text_put(out, 2, 0, STATUS_MAX, st)
        out += _U8B.pack(m.count)
        if m.read is None:
            out.append(0)
        else:
            rp = m.read
            out.append(1)
            out += _U8B.pack(rp.commit) + rp.hash + rp.digest + _U8B.pack(rp.lake_commit) + rp.lake_manifest + rp.db_id
            out.append(1 if rp.own else 0)
        if m.write is None:
            out.append(0)
        else:
            out.append(1)
            out += _U8B.pack(m.write.commit) + m.write.hash
    elif t == ERROR:
        if not m.code or not 0 <= m.index < BATCH_MAX:
            raise WireError(INVALID, "an ERROR's code 0 or its statement's index")
        out += _U4.pack(m.code) + _U4.pack(m.index)
        _text_put(out, 2, 0, MESSAGE_MAX, m.message.encode("utf-8"))
    elif t == READY:
        if not 0 <= m.state <= DOOMED:
            raise WireError(INVALID, "a READY's state")
        out.append(m.state)
    elif t == KILL:
        if m.kind not in (KILL_CANCEL, KILL_TERMINATE) or not 1 <= m.sid <= U64_MAX:
            raise WireError(INVALID, "a KILL's kind is cancel or terminate, its session an id of 1 or more")
        out.append(m.kind)
        out += _U8B.pack(m.sid)
    elif t == KILL_DONE:
        if m.code not in (KILLED, KILL_NONE) or not 1 <= m.sid <= U64_MAX:
            raise WireError(INVALID, "a KILL_DONE's code or a session id of 0")
        out.append(m.code)
        out += _U8B.pack(m.sid)
    elif t == SESSIONS_LIST:
        if len(m.sessions) > SESSIONS_MAX:
            raise WireError(INVALID, "a SESSIONS_LIST of at most 65,536 sessions")
        out += _U4.pack(len(m.sessions))
        prev = 0
        for s in m.sessions:
            if not _sess_ok(s, prev):
                raise WireError(INVALID, "a session's id out of order, or its role, endpoint or state")
            prev = s.id
            out += _U8B.pack(s.id) + _U4.pack(s.role) + bytes([s.endpoint, s.state]) + _U8B.pack(s.age_ms)
            _text_put(out, 1, 0, USER - 1, s.name.encode("utf-8"))
    elif t in (SESSIONS, COPY_DONE, CANCEL, PING, TERMINATE, COPY_IN, PONG):
        pass
    else:
        raise WireError(INVALID, "no such frame")
    return frame(t, bytes(out))
