"""The driver against imagedb-server (the frozen binaries), two servers run_tests.sh starts: A at the default channel
binding (the exporter alone) and B with --channel-binding any, each on its socket and TCP (TLS 1.3) with its own
certificate; C's CA for the refusals. Phase 2 (Renewed) runs after B's certificate is renewed and B restarted.
Without run_tests.sh's environment every test here is skipped."""

import datetime as dt
import hashlib
import io
import os
import random
import select
import socket
import ssl
import struct
import threading
import time
import unittest
import uuid
from decimal import Decimal

import imagedb
from imagedb import _raw, _x509
from imagedb import _wire as w

E = os.environ
PHASE = E.get("IMDB_PY_PHASE")
PW = E.get("IMDB_PY_PASSWORD", "")
SLOW = "SELECT COUNT(*) FROM big2 AS a, big2 AS b WHERE a.v + b.v = 99"  # 10^12 pairs: never ends uncancelled


def live(phase="1"):
    return unittest.skipUnless(PHASE == phase, "needs run_tests.sh's servers (phase %s)" % phase)


def ca(name):
    return os.path.join(E["IMDB_PY_%s_SDIR" % name], "tls", "ca.crt")


def crt_der(path):
    with open(path) as f:
        return ssl.PEM_cert_to_DER_cert(f.read())


def sock(name="B", **kw):
    kw.setdefault("timeout", 120)
    return imagedb.connect(socket=E["IMDB_PY_%s_SOCK" % name], user="admin", password=PW, **kw)


def tcp(name="B", via="pin", host="127.0.0.1", **kw):
    kw.setdefault("timeout", 120)
    if via == "pin":
        kw["pin"] = E["IMDB_PY_%s_PIN" % name]
    else:
        kw["cafile"] = ca(name)
    return imagedb.connect(host=host, port=int(E["IMDB_PY_%s_PORT" % name]), user="admin", password=PW, **kw)


def both():
    """a connection over each transport: (name, conn)"""
    return (("socket", sock()), ("tcp", tcp()))


def own_id(conn):
    """this session's id: the newest in SESSIONS right after its login (the tests connect one at a time)"""
    return max(s.id for s in conn.sessions())


def ensure_big(c):
    """big (1,000 rows) and big2 (their cross product: 1,000,000 rows), made once"""
    try:
        c.execute("SELECT COUNT(*) FROM big2")
        return
    except imagedb.ProgrammingError:
        pass
    c.execute("CREATE TABLE big (id INT64 PRIMARY KEY, v INT64)")
    c.cursor().executemany("INSERT INTO big VALUES ($1, $2)", [(i, i % 50) for i in range(1000)])
    c.execute("CREATE TABLE big2 (id INT64 PRIMARY KEY, v INT64)")
    cur = c.execute("INSERT INTO big2 SELECT a.id * 1000 + b.id, a.v FROM big AS a, big AS b")
    assert cur.rowcount == 1000000, cur.rowcount


def run_cancelled(fn, cancel, every=0.25):
    """fn on a thread, cancel() from this one again and again until fn ends (a cancel that lands before the statement
    starts is lost: t_server's cancel_later repeats it too); (its exception, seconds)"""
    out = {}

    def go():
        t0 = time.monotonic()
        try:
            out["r"] = fn()
        except BaseException as e:  # noqa: BLE001
            out["e"] = e
        out["t"] = time.monotonic() - t0
    th = threading.Thread(target=go)
    th.start()
    th.join(every)
    while th.is_alive():
        cancel()
        th.join(every)
    return out.get("e"), out["t"]


def wait_hup(conn, secs=10):
    """the server closed this connection's socket wholly (after its lingering close)"""
    p = select.poll()
    p.register(conn.raw._fd, select.POLLIN)
    end = time.monotonic() + secs
    while time.monotonic() < end:
        for _, ev in p.poll(100):
            if ev & (select.POLLHUP | select.POLLERR):
                return True
    return False


class FakeTlsServer:
    """a TLS 1.3 listener holding B's own certificate and key (ALPN imdbwir1): what a client sends after the handshake"""

    def __init__(self, sdir, addr="127.0.0.1", alpn=("imdbwir1",), tls12=False):
        self.ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        if tls12:  # a listener that speaks TLS 1.2 alone
            self.ctx.minimum_version = ssl.TLSVersion.TLSv1_2
            self.ctx.maximum_version = ssl.TLSVersion.TLSv1_2
        else:
            self.ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        self.ctx.load_cert_chain(os.path.join(sdir, "tls", "server.crt"), os.path.join(sdir, "tls", "server.key"))
        if alpn:
            self.ctx.set_alpn_protocols(list(alpn))
        self.ls = socket.socket()
        self.ls.bind((addr, 0))
        self.ls.listen(1)
        self.port = self.ls.getsockname()[1]
        self.got = None
        self.th = threading.Thread(target=self._run)
        self.th.start()

    def _run(self):
        self.ls.settimeout(20)
        try:
            c, _ = self.ls.accept()
        except OSError:
            return
        data = b""
        try:
            ss = self.ctx.wrap_socket(c, server_side=True)
            ss.settimeout(5)
            while len(data) < w.HELLO_LEN:
                k = ss.recv(4096)
                if not k:
                    break
                data += k
        except (OSError, ssl.SSLError):
            pass
        self.got = data
        c.close()

    def done(self):
        self.th.join()
        self.ls.close()
        return self.got


@live()
class Logins(unittest.TestCase):
    def test_socket_both_servers(self):
        for name in ("A", "B"):  # the socket's binding is none: any server takes it
            with sock(name) as c:
                self.assertEqual(c.execute("SELECT 1").fetchall(), [(1,)])
                self.assertEqual(c.raw.binding_type, w.CB_NONE)

    def test_tcp_pin_and_ca(self):
        for kw in (dict(via="pin"), dict(via="ca"), dict(via="ca", host="localhost"),
                   dict(via="pin", host="localhost")):
            with tcp(**kw) as c:
                self.assertEqual(c.execute("SELECT 2").fetchall(), [(2,)], kw)
                self.assertEqual(c.raw.binding_type, w.CB_ENDPOINT)
        pin = bytes.fromhex(E["IMDB_PY_B_PIN"])  # a pin as 32 bytes too
        c = imagedb.connect(host="127.0.0.1", port=int(E["IMDB_PY_B_PORT"]), pin=pin, user="admin", password=PW)
        self.assertEqual(c.execute("SELECT 3").fetchall(), [(3,)])
        c.close()

    def test_default_server_refuses_end_point(self):
        """section 8f: a server at its default takes the exporter alone, so this driver's tls-server-end-point login is
        refused by verdict 2, by name, never retried with another type"""
        for via in ("pin", "ca"):
            with self.assertRaises(imagedb.AuthenticationError) as cm:
                tcp("A", via=via)
            self.assertIn("channel binding type (tls-server-end-point)", str(cm.exception))
            self.assertIn("--channel-binding any", str(cm.exception))

    def test_binding_value_checked(self):
        """the server computes the binding from its own end of the session and holds the proof to it: our end-point
        value is the one it computes (accepted above); a hello naming the exporter with our value, or the end-point with
        zeros, is refused (verdict 1: the proof is over another binding); a TCP hello naming none is verdict 2"""
        port = int(E["IMDB_PY_B_PORT"])
        for kw, words in ((dict(_cb_type=w.CB_EXPORTER), "authentication refused"),
                          (dict(_binding=bytes(32)), "authentication refused"),
                          (dict(_binding=b"\x01" + bytes(31)), "authentication refused"),
                          (dict(_cb_type=w.CB_NONE, _binding=bytes(32)), "channel binding type (none)")):
            with self.assertRaises(imagedb.AuthenticationError) as cm:
                _raw.connect_tcp("127.0.0.1", port, "admin", PW, pin=E["IMDB_PY_B_PIN"], **kw)
            self.assertIn(words, str(cm.exception), kw)

    def test_wrong_password_and_unknown_role(self):
        """one refusal for both (no user-existence oracle)"""
        msgs = set()
        for user, pw in (("admin", "wrong-password"), ("nosuchrole", PW), ("admin", PW + "x"), ("rôle-é", PW)):
            for mk in (lambda u, p: imagedb.connect(socket=E["IMDB_PY_B_SOCK"], user=u, password=p),
                       lambda u, p: imagedb.connect(host="127.0.0.1", port=int(E["IMDB_PY_B_PORT"]),
                                                    pin=E["IMDB_PY_B_PIN"], user=u, password=p)):
                with self.assertRaises(imagedb.AuthenticationError) as cm:
                    mk(user, pw)
                msgs.add(str(cm.exception))
        self.assertEqual(msgs, {"authentication refused"})

    def test_wrong_pin(self):
        for pin in (E["IMDB_PY_A_PIN"], E["IMDB_PY_C_PIN"], "00" * 32):
            with self.assertRaises(imagedb.AuthenticationError) as cm:
                imagedb.connect(host="127.0.0.1", port=int(E["IMDB_PY_B_PORT"]), pin=pin, user="admin", password=PW)
            self.assertIn("not the pinned one", str(cm.exception))

    def test_wrong_pin_sends_no_hello(self):
        """the pin is checked after the handshake and before the hello (which names the role) leaves: a listener holding
        B's key gets no byte from a client pinned to another key, and the hello from one pinned to B's"""
        f = FakeTlsServer(E["IMDB_PY_B_SDIR"])
        with self.assertRaises(imagedb.AuthenticationError):
            imagedb.connect(host="127.0.0.1", port=f.port, pin=E["IMDB_PY_A_PIN"], user="admin", password=PW,
                            connect_timeout=10)
        self.assertEqual(f.done(), b"")
        f = FakeTlsServer(E["IMDB_PY_B_SDIR"])
        with self.assertRaises(imagedb.OperationalError):  # the hello sent, then the fake's close
            imagedb.connect(host="127.0.0.1", port=f.port, pin=E["IMDB_PY_B_PIN"], user="admin", password=PW,
                            connect_timeout=10)
        got = f.done()
        self.assertEqual(len(got), w.HELLO_LEN)
        self.assertEqual(got[:16], b"IMDBWIR1\x01\0\0\0\x02\0\0\0")  # version 1, flags 2: tls-server-end-point
        self.assertEqual(got[16:21], b"admin")

    def test_name_outside_san(self):
        """CA mode checks the host against the certificate's subjectAltName (localhost, 127.0.0.1, ::1): B's own
        certificate and key served on 127.0.0.2 (loopback, not among its names) are refused, and no hello leaves"""
        f = FakeTlsServer(E["IMDB_PY_B_SDIR"], addr="127.0.0.2")
        with self.assertRaises(imagedb.AuthenticationError) as cm:
            imagedb.connect(host="127.0.0.2", port=f.port, cafile=ca("B"), user="admin", password=PW, connect_timeout=10)
        self.assertIn("certificate", str(cm.exception))
        self.assertEqual(f.done(), b"")

    def test_tls12_refused(self):
        """TLS 1.3 alone: a listener holding B's key that speaks TLS 1.2 alone gets no hello, by CA or by pin"""
        for kw in (dict(cafile=ca("B")), dict(pin=E["IMDB_PY_B_PIN"])):
            f = FakeTlsServer(E["IMDB_PY_B_SDIR"], tls12=True)
            with self.assertRaises(imagedb.OperationalError):
                imagedb.connect(host="127.0.0.1", port=f.port, user="admin", password=PW, connect_timeout=10, **kw)
            self.assertEqual(f.done(), b"", kw)

    def test_alpn_refused(self):
        """ALPN imdbwir1 checked after the handshake: a listener selecting none gets no hello, refused by name; one
        offering another protocol gets none either"""
        f = FakeTlsServer(E["IMDB_PY_B_SDIR"], alpn=())
        with self.assertRaises(imagedb.AuthenticationError) as cm:
            imagedb.connect(host="127.0.0.1", port=f.port, pin=E["IMDB_PY_B_PIN"], user="admin", password=PW,
                            connect_timeout=10)
        self.assertIn("ALPN", str(cm.exception))
        self.assertEqual(f.done(), b"")
        f = FakeTlsServer(E["IMDB_PY_B_SDIR"], alpn=("h2",))
        with self.assertRaises(imagedb.OperationalError):
            imagedb.connect(host="127.0.0.1", port=f.port, cafile=ca("B"), user="admin", password=PW,
                            connect_timeout=10)
        self.assertEqual(f.done(), b"")

    def test_another_ca(self):
        for host in ("127.0.0.1", "localhost"):
            with self.assertRaises(imagedb.AuthenticationError) as cm:
                imagedb.connect(host=host, port=int(E["IMDB_PY_B_PORT"]), cafile=ca("C"), user="admin", password=PW)
            self.assertIn("certificate", str(cm.exception))

    def test_unverified_impossible(self):
        """no unverified mode exists: TCP takes exactly one of a CA file and a pin, refused before any socket opens"""
        ls = socket.socket()
        ls.bind(("127.0.0.1", 0))
        ls.listen(1)
        port = ls.getsockname()[1]
        for kw in (dict(), dict(cafile=ca("B"), pin=E["IMDB_PY_B_PIN"]), dict(cafile=None, pin=None)):
            with self.assertRaises(imagedb.InterfaceError):
                imagedb.connect(host="127.0.0.1", port=port, user="admin", password=PW, **kw)
        for kw in (dict(verify=False), dict(ssl_context=ssl.create_default_context()), dict(sslmode="disable")):
            with self.assertRaises(TypeError):
                imagedb.connect(host="127.0.0.1", port=port, user="admin", password=PW, **kw)
        with self.assertRaises(imagedb.InterfaceError):
            imagedb.connect(socket=E["IMDB_PY_B_SOCK"], cafile=ca("B"), user="admin", password=PW)
        with self.assertRaises(imagedb.InterfaceError):
            imagedb.connect(socket=E["IMDB_PY_B_SOCK"], host="127.0.0.1", user="admin", password=PW)
        ls.settimeout(0.3)
        with self.assertRaises(socket.timeout):
            ls.accept()  # nothing ever connected
        ls.close()

    def test_bad_arguments(self):
        for kw in (dict(user=""), dict(user="a" * 64), dict(user="a\x00"), dict(password=""), dict(password="é"),
                   dict(password="a" * 1025), dict(password="tab\there")):
            args = dict(socket=E["IMDB_PY_B_SOCK"], user="admin", password=PW)
            args.update(kw)
            with self.assertRaises(imagedb.InterfaceError, msg=kw):
                imagedb.connect(**args)
        for pin in ("zz" * 32, "00" * 31, b"\x00" * 31):
            with self.assertRaises(imagedb.InterfaceError):
                imagedb.connect(host="127.0.0.1", port=int(E["IMDB_PY_B_PORT"]), pin=pin, user="admin", password=PW)

    def test_pin_is_the_spki(self):
        """the pin `cert` printed is the served key's SPKI SHA-256 (not the certificate's hash), and the certificate
        file's too"""
        ctx = _raw.tls_context(pin=bytes(32))
        s = ctx.wrap_socket(socket.create_connection(("127.0.0.1", int(E["IMDB_PY_B_PORT"])), timeout=10),
                            server_hostname="127.0.0.1")
        try:
            der = s.getpeercert(binary_form=True)
            self.assertEqual(s.version(), "TLSv1.3")
            self.assertEqual(s.selected_alpn_protocol(), "imdbwir1")
            # section 8f's premise, live: no exporter on this TLS 1.3 session
            with self.assertRaises(ValueError):
                s.get_channel_binding("tls-exporter")
        finally:
            s.close()
        self.assertEqual(_x509.spki_pin(der).hex(), E["IMDB_PY_B_PIN"])
        self.assertNotEqual(hashlib.sha256(der).hexdigest(), E["IMDB_PY_B_PIN"])
        self.assertEqual(der, crt_der(os.path.join(E["IMDB_PY_B_SDIR"], "tls", "server.crt")))
        self.assertEqual(_x509.end_point(der), hashlib.sha256(der).digest())  # ecdsa-with-SHA256: SHA-256 of the DER
        for name in ("A", "C"):
            self.assertEqual(_x509.spki_pin(crt_der(os.path.join(E["IMDB_PY_%s_SDIR" % name], "tls", "server.crt"))).hex(),
                             E["IMDB_PY_%s_PIN" % name])
        # a damaged certificate: its walker refuses it by CertError or reads past the damage, never another exception
        for k in range(len(der)):
            x = bytearray(der)
            x[k] ^= 0xFF
            try:
                _x509.spki_pin(bytes(x))
            except _x509.CertError:
                pass
        self.assertRaises(_x509.CertError, _x509.spki_pin, der[:-1])
        self.assertRaises(_x509.CertError, _x509.spki_pin, der + b"\x00")

    def test_endpoints_in_sessions(self):
        s, t = sock(), tcp()
        mine = {x.id: x for x in t.sessions()}
        ids = sorted(mine)
        self.assertEqual(mine[ids[-1]].endpoint, imagedb.ENDPOINT_TCP)
        self.assertEqual(mine[ids[-2]].endpoint, imagedb.ENDPOINT_SOCKET)
        self.assertEqual(mine[ids[-1]].name, "admin")
        s.close()
        t.close()


TYPES_DDL = ("CREATE TABLE ty (id INT64 PRIMARY KEY, i64 INT64, s SMALLINT, n INTEGER, d DECIMAL(10,2), w DECIMAL(38,6), "
             "z DECIMAL(38,0), q DECIMAL(38,38), f FLOAT64, b BOOL, t TEXT, v VARCHAR(5), ts TIMESTAMP, tz TIMESTAMPTZ, "
             "dt DATE, tm TIME, u UUID, bb BYTEA, iv INTERVAL, m mood)")
UTC = dt.timezone.utc
NINES = "9" * 38
ROW_MAX = (1, (1 << 63) - 1, 32767, (1 << 31) - 1, Decimal("99999999.99"),
           Decimal("99999999999999999999999999999999.999999"), Decimal(NINES), Decimal("0." + NINES),
           1.7976931348623157e308, True, "hé|x,\"q\"\n\U0001F600", "abcdé", dt.datetime(9999, 12, 31, 23, 59, 59, 999999),
           dt.datetime(9999, 12, 31, 23, 59, 59, 999999, tzinfo=UTC), dt.date(9999, 12, 31), dt.time(23, 59, 59, 999999),
           uuid.UUID(int=(1 << 128) - 1), bytes(range(256)), imagedb.Interval((1 << 31) - 1, (1 << 31) - 1, (1 << 63) - 1),
           "happy")
ROW_MIN = (2, -(1 << 63), -32768, -(1 << 31), Decimal("-99999999.99"),
           Decimal("-99999999999999999999999999999999.999999"), Decimal("-" + NINES), Decimal("-0." + NINES),
           5e-324, False, "", "", dt.datetime(1, 1, 1), dt.datetime(1, 1, 1, tzinfo=UTC), dt.date(1, 1, 1), dt.time(0),
           uuid.UUID(int=0), b"", imagedb.Interval(-(1 << 31), -(1 << 31), -(1 << 63)), "")
WANT_TYPES = [1, 1, 1, 1, 5, 5, 5, 5, 2, 3, 4, 4, 6, 7, 8, 9, 10, 11, 12, 13]
WANT_SCALES = [0, 0, 0, 0, 2, 6, 0, 38, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]


def same(a, b):
    """equal, a DECIMAL by its digits and scale too, a FLOAT64 bit for bit"""
    if isinstance(a, float) or isinstance(b, float):
        return type(a) is type(b) and struct.pack("<d", a) == struct.pack("<d", b)
    if isinstance(a, Decimal) or isinstance(b, Decimal):
        return type(a) is type(b) and str(a) == str(b)
    return type(a) is type(b) and a == b


@live()
class Types(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.c = sock()
        cls.c.execute("CREATE TYPE mood AS ENUM ('sad', 'ok', 'happy', 'é', '')")
        cls.c.execute(TYPES_DDL)
        ph = ", ".join("$%d" % k for k in range(1, 21))
        cls.c.execute("INSERT INTO ty VALUES (%s)" % ph, ROW_MAX)
        cls.c.execute("INSERT INTO ty VALUES (%s)" % ph, ROW_MIN)
        cls.c.execute("INSERT INTO ty VALUES (%s)" % ph, (3,) + (None,) * 19)  # NULLs of no type, into every column
        nulls = [imagedb.Null(t) for t in WANT_TYPES[1:]]
        cls.c.execute("INSERT INTO ty VALUES (%s)" % ph, [4] + nulls)  # NULLs of each column's type

    @classmethod
    def tearDownClass(cls):
        cls.c.close()

    def check_rows(self, conn):
        cur = conn.execute("SELECT * FROM ty ORDER BY id")
        self.assertEqual([d[1] for d in cur.description], WANT_TYPES)
        self.assertEqual([d[5] for d in cur.description], WANT_SCALES)
        self.assertEqual([d[0] for d in cur.description][:3], ["id", "i64", "s"])
        self.assertEqual(cur.columns[19].labels, ("sad", "ok", "happy", "é", ""))
        self.assertEqual(cur.description[11][1], imagedb.STRING)
        self.assertEqual(cur.description[4][1], imagedb.NUMBER)
        self.assertEqual(cur.description[12][1], imagedb.DATETIME)
        self.assertEqual(cur.description[17][1], imagedb.BINARY)
        rows = cur.fetchall()
        self.assertEqual(cur.rowcount, 4)
        for want, got in zip((ROW_MAX, ROW_MIN), rows[:2]):
            for k, (a, b) in enumerate(zip(want, got)):
                self.assertTrue(same(a, b), "column %d: %r != %r" % (k, a, b))
        self.assertEqual(rows[2], (3,) + (None,) * 19)
        self.assertEqual(rows[3], (4,) + (None,) * 19)
        self.assertEqual(rows[1][13].tzinfo, UTC)

    def test_round_trip_both_transports(self):
        for name, conn in both():
            with conn:
                self.check_rows(conn)

    def test_parameters_compare_exactly(self):
        """each edge value as a parameter finds its row by equality (the value binds as its literal would)"""
        cols = ["i64", "s", "n", "d", "w", "z", "q", "f", "b", "t", "v", "ts", "tz", "dt", "tm", "u", "bb"]
        for k, col in enumerate(cols, start=1):
            for row in (ROW_MAX, ROW_MIN):
                got = self.c.execute("SELECT id FROM ty WHERE %s = $1" % col, [row[k]]).fetchall()
                self.assertEqual(got, [(row[0],)], col)
        self.assertEqual(self.c.execute("SELECT id FROM ty WHERE m = $1", ["happy"]).fetchall(), [(1,)])
        # a DECIMAL of another scale binds by its value (no digit lost), as its literal would
        self.assertEqual(self.c.execute("SELECT id FROM ty WHERE d = $1", [Decimal("99999999.990")]).fetchall(), [(1,)])

    def test_literals(self):
        """the engine's own literals decoded (not the driver's encoder): every type"""
        q = ("SELECT DATE '0001-01-01', TIME '23:59:59.999999', TIMESTAMP '0001-01-01 00:00:00', "
             "TIMESTAMPTZ '9999-12-31 23:59:59.999999+00', UUID 'ffffffff-ffff-ffff-ffff-ffffffffffff', "
             "CAST('\\x00ff' AS BYTEA), INTERVAL '1 mon -2 days 00:00:00.000003', 1.5e0, "
             "CAST(-12345.678 AS DECIMAL(10,3)), CAST('ok' AS mood), TRUE, 'hé', -9223372036854775808, "
             "CAST(NULL AS DATE), 99999999999999999999999999999999999999")
        row = self.c.execute(q).fetchone()
        want = (dt.date(1, 1, 1), dt.time(23, 59, 59, 999999), dt.datetime(1, 1, 1),
                dt.datetime(9999, 12, 31, 23, 59, 59, 999999, tzinfo=UTC), uuid.UUID(int=(1 << 128) - 1), b"\x00\xff",
                imagedb.Interval(1, -2, 3), 1.5, Decimal("-12345.678"), "ok", True, "hé", -(1 << 63), None,
                Decimal(NINES))
        for a, b in zip(want, row):
            self.assertTrue(same(a, b), (a, b))

    def test_select_parameters(self):
        """parameters straight back, every type at its edges (and a TEXT and a BYTEA of 65,535 bytes)"""
        vals = list(ROW_MAX[1:-1]) + list(ROW_MIN[1:-1]) + ["x" * 65535, b"\xff" * 65535, 1 << 63, -(10 ** 38 - 1)]
        for k in range(0, len(vals), 9):
            part = vals[k:k + 9]
            row = self.c.execute("SELECT " + ", ".join("$%d" % (i + 1) for i in range(len(part))), part).fetchone()
            for a, b in zip(part, row):
                past = isinstance(a, int) and not isinstance(a, bool) and not w.I64_MIN <= a <= w.I64_MAX
                want = Decimal(a) if past else a  # an integer past INT64 goes as a DECIMAL of scale 0
                self.assertTrue(same(want, b), (a, b))
        self.assertEqual(self.c.execute("SELECT $1", [imagedb.Null(imagedb.T_TEXT)]).fetchall(), [(None,)])
        self.assertEqual(self.c.execute("SELECT $1", [imagedb.Null(imagedb.T_TEXT)]).description[0][1], imagedb.T_TEXT)
        with self.assertRaises(imagedb.DataError):  # a NULL of no type where an expression wants one
            self.c.execute("SELECT $1", [None])
        self.assertEqual(self.c.execute("SELECT $1", [dt.timedelta(days=-3, microseconds=7)]).fetchone()[0],
                         imagedb.Interval(0, -3, 7))

    def test_float64_bits(self):
        """2,000 drawn doubles through a table, bit for bit (-0.0 goes out as 0.0: the engine keeps one zero)"""
        rnd = random.Random(5)
        vals = []
        while len(vals) < 2000:
            x = struct.unpack("<d", struct.pack("<Q", rnd.getrandbits(64)))[0]
            if x == x and abs(x) != float("inf"):
                vals.append(x)
        vals[:6] = [5e-324, -5e-324, 2.2250738585072014e-308, 0.1, -0.0, 1 / 3]
        self.c.execute("CREATE TABLE fl (id INT64 PRIMARY KEY, f FLOAT64)")
        self.c.cursor().executemany("INSERT INTO fl VALUES ($1, $2)", list(enumerate(vals)))
        got = [r[0] for r in self.c.execute("SELECT f FROM fl ORDER BY id").fetchall()]
        want = [0.0 if x == 0 else x for x in vals]
        self.assertEqual([struct.pack("<d", x) for x in got], [struct.pack("<d", x) for x in want])

    def test_sum_is_decimal(self):
        """section 4: a SUM at a statement's top is DECIMAL whatever its column (two INT64 maxima sum past INT64)"""
        cur = self.c.execute("SELECT SUM(i64), SUM(z) FROM ty WHERE id = 1 OR id = 1")
        self.assertEqual(cur.description[0][1], imagedb.T_DECIMAL)
        self.c.execute("CREATE TABLE sm (id INT64 PRIMARY KEY, x INT64)")
        self.c.batch([("INSERT INTO sm VALUES ($1, $2)", [k, (1 << 63) - 1]) for k in (1, 2)])
        self.assertEqual(self.c.execute("SELECT SUM(x) FROM sm").fetchall(), [(Decimal(2 * ((1 << 63) - 1)),)])
        self.assertEqual(self.c.execute("SELECT SUM(x) FROM sm WHERE id > 5").fetchall(), [(None,)])
        self.assertEqual(self.c.execute("SELECT SUM(x) FROM sm WHERE id > 5").description[0][1], imagedb.T_DECIMAL)

    def test_columns_of_no_type(self):
        """SHOW's columns are of no type (0): each value its own"""
        cur = self.c.execute("SHOW TABLES")
        self.assertTrue(all(d[1] == imagedb.T_NONE for d in cur.description))
        names = [r[0] for r in cur.fetchall()]
        self.assertIn("ty", names)

    def test_refused_values(self):
        """values with no wire value refused by the driver before anything is sent (DataError), the connection fine"""
        for x in (float("nan"), float("inf"), "a\x00", Decimal("1E+38"), Decimal("1E-39"), 10 ** 38, object()):
            with self.assertRaises(imagedb.DataError):
                self.c.execute("SELECT $1", [x])
        with self.assertRaises(imagedb.DataError):  # a non-NULL ENUM is never a parameter: a label goes as TEXT
            self.c.execute("SELECT $1", [w.Value(w.T_ENUM, False, b"ok")])
        with self.assertRaises(imagedb.ProgrammingError):
            self.c.execute("SELECT 1", list(range(257)))
        with self.assertRaises(imagedb.ProgrammingError):
            self.c.execute("SELECT 1", "abc")
        with self.assertRaises(imagedb.ProgrammingError):
            self.c.execute("x" * ((4 << 20) + 1))
        self.assertEqual(self.c.execute("SELECT 5").fetchall(), [(5,)])

    def test_server_refusals(self):
        """the server's own refusals by code: a value past its column (VARCHAR(5), SMALLINT), a label not the type's"""
        for sql, params, code in (("INSERT INTO ty (id, v) VALUES ($1, $2)", [9, "abcdef"], None),
                                  ("INSERT INTO ty (id, s) VALUES ($1, $2)", [9, 32768], None),
                                  ("INSERT INTO ty (id, m) VALUES ($1, $2)", [9, "nosuch"], None),
                                  ("SELEC 1", [], 10), ("SELECT * FROM nosuch", [], 11)):
            with self.assertRaises(imagedb.DatabaseError) as cm:
                self.c.execute(sql, params)
            self.assertIsNotNone(cm.exception.code)
            if code:
                self.assertEqual(cm.exception.code, code)
            self.assertEqual(cm.exception.index, 0)
        self.assertEqual(self.c.execute("SELECT COUNT(*) FROM ty").fetchone(), (4,))


@live()
class Batches(unittest.TestCase):
    def setUp(self):
        self.c = sock()

    def tearDown(self):
        self.c.close()

    def test_error_mid_batch(self):
        c = self.c
        c.execute("CREATE TABLE bt (id INT64 PRIMARY KEY, v TEXT)")
        with self.assertRaises(imagedb.IntegrityError) as cm:
            c.batch(["INSERT INTO bt VALUES (1, 'a')", ("INSERT INTO bt VALUES ($1, $2)", [1, "dup"]),
                     "INSERT INTO bt VALUES (3, 'never')"])
        e = cm.exception
        self.assertEqual((e.code, e.index, len(e.results)), (6, 1, 1))
        self.assertEqual(e.results[0].status, "INSERT 1")
        self.assertEqual(c.execute("SELECT id FROM bt ORDER BY id").fetchall(), [(1,)])
        self.assertEqual(c.transaction_state, imagedb.IDLE)
        rs = c.batch(["SELECT 1", ("SELECT $1, $2", ["x", 2]), "INSERT INTO bt VALUES (4, 'd')", "SELECT COUNT(*) FROM bt"])
        self.assertEqual([r.rows for r in rs], [[(1,)], [("x", 2)], None, [(2,)]])
        self.assertEqual(rs[2].rowcount, 1)
        self.assertIsNotNone(rs[2].write)
        self.assertIsNone(rs[2].description)

    def test_batch_in_a_transaction(self):
        """an ERROR ends the batch: its COMMIT never runs, the transaction still open (READY 1)"""
        c = self.c
        c.execute("CREATE TABLE bt2 (id INT64 PRIMARY KEY)")
        with self.assertRaises(imagedb.IntegrityError) as cm:
            c.batch(["BEGIN", "INSERT INTO bt2 VALUES (1)", "INSERT INTO bt2 VALUES (1)", "COMMIT"])
        self.assertEqual(cm.exception.index, 2)
        self.assertEqual(c.transaction_state, imagedb.IN_TRANSACTION)
        c.rollback()
        self.assertEqual(c.transaction_state, imagedb.IDLE)
        self.assertEqual(c.execute("SELECT COUNT(*) FROM bt2").fetchone(), (0,))

    def test_pipelined_requests(self):
        """section 4: pipelined requests each run whatever an earlier one's ERROR; BEGIN, a failing INSERT and COMMIT
        as three requests commit the transaction without that INSERT"""
        c = self.c
        c.execute("CREATE TABLE pl (id INT64 PRIMARY KEY)")
        c.execute("INSERT INTO pl VALUES (1)")
        raw = c.raw
        for s in ("BEGIN", "INSERT INTO pl VALUES (2)", "INSERT INTO pl VALUES (1)", "INSERT INTO pl VALUES (3)",
                  "COMMIT"):
            raw.send_query([s])
        self.assertEqual(raw.outstanding, 5)
        kinds, readies = [], 0
        while readies < 5:
            m = raw.next()
            kinds.append((m.type, getattr(m, "code", None)))
            readies += m.type == w.READY
        self.assertEqual([k for k in kinds if k[0] == w.ERROR], [(w.ERROR, 6)])
        self.assertEqual(raw.state, imagedb.IDLE)
        self.assertEqual(c.execute("SELECT id FROM pl ORDER BY id").fetchall(), [(1,), (2,), (3,)])

    def test_batch_bounds(self):
        with self.assertRaises(imagedb.ProgrammingError):
            self.c.batch([])
        with self.assertRaises(imagedb.ProgrammingError):
            self.c.batch(["SELECT 1"] * 4097)
        rs = self.c.batch(["SELECT 1"] * 4096)
        self.assertEqual(len(rs), 4096)


@live()
class Prepared(unittest.TestCase):
    def setUp(self):
        self.c = sock()

    def tearDown(self):
        self.c.close()

    def test_prepare_execute_deallocate(self):
        c = self.c
        c.execute("CREATE TABLE pr (id INT64 PRIMARY KEY, d DECIMAL(10,2), t TEXT)")
        c.prepare("ins", "INSERT INTO pr VALUES ($1, $2, $3)")
        rs = c.execute_prepared("ins", [(1, Decimal("1.5"), "a"), (2, 7, None), (3, Decimal("2.25"), "c")])
        self.assertEqual([r.rowcount for r in rs], [1, 1, 1])
        c.prepare("sel", "SELECT d, t FROM pr WHERE id = $1")
        rs = c.execute_prepared("sel", [(1,), (2,), (9,)])
        self.assertEqual([r.rows for r in rs], [[(Decimal("1.50"), "a")], [(Decimal("7.00"), None)], []])
        c.deallocate("sel")
        with self.assertRaises(imagedb.DatabaseError):
            c.execute_prepared("sel", [(1,)])
        with self.assertRaises(imagedb.IntegrityError) as cm:
            c.execute_prepared("ins", [(4, 1, "d"), (1, 1, "dup"), (5, 1, "never")])
        self.assertEqual((cm.exception.index, len(cm.exception.results)), (1, 1))
        self.assertEqual(c.execute("SELECT COUNT(*) FROM pr").fetchone(), (4,))
        c.deallocate("ins")

    def test_executemany_frames(self):
        """5,000 sets: two EXECUTE requests (4,096 a frame); an error at set 4,500 named by its index in the whole run"""
        c = self.c
        cur = c.cursor()
        cur.execute("CREATE TABLE em (id INT64 PRIMARY KEY, v TEXT)")
        cur.executemany("INSERT INTO em VALUES ($1, $2)", [(k, "v%d" % k) for k in range(5000)])
        self.assertEqual(cur.rowcount, 5000)
        rows = [(k, "w") for k in range(5000, 10000)]
        rows[4500] = (7, "dup")
        with self.assertRaises(imagedb.IntegrityError) as cm:
            cur.executemany("INSERT INTO em VALUES ($1, $2)", rows)
        self.assertEqual(cm.exception.index, 4500)
        self.assertEqual(len(cm.exception.results), 4500)
        self.assertEqual(c.execute("SELECT COUNT(*) FROM em").fetchone(), (9500,))
        with self.assertRaises(imagedb.ProgrammingError):
            cur.executemany("INSERT INTO em VALUES ($1, $2)", [(1, "a"), (2,)])

    def test_bad_names(self):
        for name in ("", "n" * 64):
            with self.assertRaises(imagedb.ProgrammingError):
                self.c.prepare(name, "SELECT 1")
        self.c.prepare("n" * 63, "SELECT 1")
        self.c.deallocate("n" * 63)


@live()
class Transactions(unittest.TestCase):
    def test_states_and_commit(self):
        with sock() as c, sock() as d:
            c.execute("CREATE TABLE tx (id INT64 PRIMARY KEY)")
            c.commit()  # idle: nothing sent
            c.rollback()
            self.assertEqual(c.transaction_state, imagedb.IDLE)
            c.execute("BEGIN")
            self.assertEqual(c.transaction_state, imagedb.IN_TRANSACTION)
            c.execute("INSERT INTO tx VALUES (1)")
            with self.assertRaises(imagedb.IntegrityError):
                c.execute("INSERT INTO tx VALUES (1)")  # statement-level rollback: the transaction goes on
            self.assertEqual(c.transaction_state, imagedb.IN_TRANSACTION)
            cur = c.execute("SELECT COUNT(*) FROM tx")
            self.assertEqual(cur.fetchone(), (1,))
            self.assertTrue(cur.result.read.own)  # its own pending write seen
            self.assertEqual(d.execute("SELECT COUNT(*) FROM tx").fetchone(), (0,))
            c.commit()
            self.assertEqual(c.transaction_state, imagedb.IDLE)
            self.assertEqual(d.execute("SELECT COUNT(*) FROM tx").fetchone(), (1,))
            c.execute("BEGIN")
            c.execute("INSERT INTO tx VALUES (2)")
            c.rollback()
            self.assertEqual(d.execute("SELECT COUNT(*) FROM tx").fetchone(), (1,))

    def test_doomed(self):
        """another session's ALTER dooms a transaction that wrote the table: READY 2, then only ROLLBACK"""
        with sock() as c, sock() as d:
            c.execute("CREATE TABLE dm (id INT64 PRIMARY KEY)")
            c.execute("BEGIN")
            c.execute("INSERT INTO dm VALUES (1)")
            d.execute("ALTER TABLE dm ADD COLUMN z INT64")
            with self.assertRaises(imagedb.SerializationError) as cm:
                c.execute("SELECT 1")
            self.assertEqual(cm.exception.code, 14)
            self.assertEqual(c.transaction_state, imagedb.DOOMED)
            c.rollback()
            self.assertEqual(c.transaction_state, imagedb.IDLE)

    def test_read_point_and_write(self):
        with sock() as c:
            c.execute("CREATE TABLE rp (id INT64 PRIMARY KEY)")
            cur = c.execute("INSERT INTO rp VALUES (1)")
            wc = cur.result.write
            self.assertTrue(wc.commit >= 1 and len(wc.hash) == 32)
            cur = c.execute("SELECT * FROM rp")
            rp = cur.result.read
            self.assertEqual(rp.commit, wc.commit)
            self.assertEqual(rp.hash, wc.hash)
            self.assertEqual((len(rp.digest), len(rp.db_id), rp.own), (32, 16, False))
            with tcp() as t:  # the same database's id and read point over the other transport
                rp2 = t.execute("SELECT * FROM rp").result.read
                self.assertEqual((rp2.db_id, rp2.commit, rp2.digest), (rp.db_id, rp.commit, rp.digest))

    def test_close_rolls_back_and_context(self):
        with sock() as d:
            d.execute("CREATE TABLE cl (id INT64 PRIMARY KEY)")
            c = sock()
            c.execute("BEGIN")
            c.execute("INSERT INTO cl VALUES (1)")
            c.close()  # TERMINATE: rolled back
            self.assertTrue(c.closed)
            with self.assertRaises(imagedb.InterfaceError):
                c.execute("SELECT 1")
            with sock() as e:  # the context manager commits an open transaction at a clean exit
                e.execute("BEGIN")
                e.execute("INSERT INTO cl VALUES (2)")
            self.assertEqual(d.execute("SELECT id FROM cl").fetchall(), [(2,)])


@live()
class Cancel(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with sock() as c:
            ensure_big(c)

    def test_cancel_long_statement(self):
        """CANCEL from another thread, in band, over each transport: the batch's slow statement ends in ERROR 15 (its
        index 1, the first statement's rows kept), well before its statement_timeout"""
        for name, c in both():
            with c:
                c.execute("SET statement_timeout = 60000")
                e, secs = run_cancelled(lambda: c.batch(["SELECT 41", SLOW]), c.cancel)
                self.assertIsInstance(e, imagedb.QueryCanceledError, (name, e))
                self.assertEqual((e.code, e.index), (15, 1))
                self.assertEqual(e.results[0].rows, [(41,)])
                self.assertLess(secs, 30, name)
                self.assertGreaterEqual(c.raw.cancels_sent, 1)
                self.assertEqual(c.transaction_state, imagedb.IDLE)
                c.ping()
                self.assertEqual(c.execute("SELECT COUNT(*) FROM big").fetchone(), (1000,))

    def test_cancel_with_nothing_running_is_dropped(self):
        with sock() as c:
            c.cancel()
            self.assertEqual(c.execute("SELECT 7").fetchall(), [(7,)])
            self.assertEqual(c.raw.cancels_sent, 0)
            c.cancel()
            c.ping()  # a PING is no request: still nothing outstanding
            self.assertEqual(c.execute("SELECT 8").fetchall(), [(8,)])
            self.assertEqual(c.raw.cancels_sent, 0)

    def test_cancel_in_a_transaction(self):
        with tcp() as c:
            c.execute("SET statement_timeout = 60000")
            c.execute("BEGIN")
            e, _ = run_cancelled(lambda: c.execute(SLOW), c.cancel)
            self.assertIsInstance(e, imagedb.QueryCanceledError)
            self.assertEqual(c.transaction_state, imagedb.IN_TRANSACTION)  # the statement alone undone
            c.rollback()

    def test_timeout(self):
        """a reply that never comes within the connection's timeout: an error, the connection closed (the server cancels
        the statement of a client that leaves)"""
        c = sock()
        c.execute("SET statement_timeout = 60000")
        c.raw.timeout = 0.5  # the bound for the slow statement alone (the SET's reply under the usual one)
        t0 = time.monotonic()
        with self.assertRaises(imagedb.OperationalError) as cm:
            c.execute(SLOW)
        self.assertIn("no reply within", str(cm.exception))
        self.assertLess(time.monotonic() - t0, 10)
        self.assertTrue(c.closed)
        with sock() as d:
            self.assertEqual(d.execute("SELECT 9").fetchall(), [(9,)])


CSV_ROWS = ['1,one\n', '2,"t,wo"\n', '3,"th""ree"\n', '4,"multi\nline"\n', '5,hé\U0001F600\n', '6,\n']


@live()
class Copy(unittest.TestCase):
    def test_both_ways(self):
        for name, c in both():
            with c:
                t = "cp_" + name
                c.execute("CREATE TABLE %s (id INT64 PRIMARY KEY, name TEXT)" % t)
                self.assertEqual(c.copy_from("COPY %s FROM STDIN" % t, CSV_ROWS[:3]), 3)
                self.assertEqual(c.copy_from("COPY %s FROM STDIN" % t, io.BytesIO("".join(CSV_ROWS[3:]).encode())), 3)
                b = io.BytesIO()
                self.assertEqual(c.copy_to("COPY %s TO STDOUT" % t, b), 6)
                s = io.StringIO()
                self.assertEqual(c.copy_to("COPY (SELECT id, name FROM %s WHERE id > 1) TO STDOUT" % t, s), 5)
                pieces = []
                self.assertEqual(c.copy_to("COPY %s TO STDOUT" % t, pieces.append), 6)
                self.assertEqual(b"".join(pieces), b.getvalue())
                got = c.execute("SELECT id, name FROM %s ORDER BY id" % t).fetchall()
                self.assertEqual(got, [(1, "one"), (2, "t,wo"), (3, 'th"ree'), (4, "multi\nline"), (5, "hé\U0001F600"),
                                       (6, None)])
                c.execute("CREATE TABLE %s_2 (id INT64 PRIMARY KEY, name TEXT)" % t)
                self.assertEqual(c.copy_from("COPY %s_2 FROM STDIN" % t, io.StringIO(b.getvalue().decode())), 6)
                self.assertEqual(c.execute("SELECT id, name FROM %s_2 ORDER BY id" % t).fetchall(), got)
                self.assertTrue(s.getvalue().startswith('2,"t,wo"\n'))

    def test_large(self):
        """200,000 rows in (several COPY_DATA frames) and out (several COPY_OUT frames), byte for byte"""
        with tcp() as c:
            c.execute("CREATE TABLE cpl (id INT64 PRIMARY KEY, v TEXT, d DECIMAL(20,4))")
            data = "".join("%d,row number %d with some text,%d.%04d\n" % (k, k, k * 7, k % 10000) for k in range(200000))
            self.assertGreater(len(data), 3 << 20)
            self.assertEqual(c.copy_from("COPY cpl FROM STDIN", io.StringIO(data)), 200000)
            out = io.BytesIO()
            self.assertEqual(c.copy_to("COPY cpl TO STDOUT", out), 200000)
            self.assertEqual(out.getvalue().decode(), data)

    def test_refusals(self):
        with sock() as c:
            c.execute("CREATE TABLE cpr (id INT64 PRIMARY KEY, name TEXT)")
            c.copy_from("COPY cpr FROM STDIN", ["1,a\n"])

            def failing():
                yield "2,b\n"
                raise RuntimeError("the source broke")
            with self.assertRaises(RuntimeError):  # COPY_FAIL: nothing written; the source's own exception
                c.copy_from("COPY cpr FROM STDIN", failing())
            with self.assertRaises(imagedb.DataError) as cm:  # an error in the data: after COPY_DONE, unrun
                c.copy_from("COPY cpr FROM STDIN", ["3,c\n", "4\n"])
            self.assertEqual(cm.exception.code, 4)
            with self.assertRaises(imagedb.ProgrammingError) as cm:  # refused before its data: no COPY_IN
                c.copy_from("COPY nosuch FROM STDIN", ["1,a\n"])
            self.assertEqual(cm.exception.code, 11)
            with self.assertRaises(imagedb.ProgrammingError) as cm:  # no source: COPY_FAIL sent, the COPY unrun
                c.execute("COPY cpr FROM STDIN")
            self.assertIsInstance(cm.exception.__cause__, imagedb.QueryCanceledError)
            with self.assertRaises(imagedb.ProgrammingError):  # no sink: its data dropped
                c.execute("COPY cpr TO STDOUT")
            self.assertEqual(c.execute("SELECT id FROM cpr").fetchall(), [(1,)])
            self.assertEqual(c.transaction_state, imagedb.IDLE)
            c.ping()

    def test_cancel_upload(self):
        """a cancel asked while the driver sends COPY's data goes out before its next frame: the COPY refused unrun"""
        with tcp() as c:
            c.execute("CREATE TABLE cpc (id INT64 PRIMARY KEY)")

            def data():
                for k in range(1000):
                    if k == 500:
                        c.cancel()
                    yield "%d\n" % k
            with self.assertRaises(imagedb.QueryCanceledError):
                c.copy_from("COPY cpc FROM STDIN", data())
            self.assertEqual(c.execute("SELECT COUNT(*) FROM cpc").fetchone(), (0,))
            self.assertEqual(c.copy_from("COPY cpc FROM STDIN", ["1\n"]), 1)

    def test_copy_in_a_batch(self):
        """a COPY among a batch's statements: the batch pauses at its COPY_IN, the data goes, the batch goes on"""
        with sock() as c:
            c.execute("CREATE TABLE cpb (id INT64 PRIMARY KEY)")
            r = c._run(lambda: c.raw.send_query(["SELECT 1", "COPY cpb FROM STDIN", "SELECT COUNT(*) FROM cpb"]),
                       copy_source=["1\n2\n"])
            self.assertEqual([x.rows for x in r], [[(1,)], None, [(2,)]])
            self.assertEqual(r[1].rowcount, 2)


@live()
class SessionsKill(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with sock() as c:
            ensure_big(c)

    def test_sessions(self):
        with sock() as c:
            me = own_id(c)
            ss = {s.id: s for s in c.sessions()}
            s = ss[me]
            self.assertEqual((s.endpoint, s.state, s.name), (imagedb.ENDPOINT_SOCKET, imagedb.SESSION_IDLE, "admin"))
            self.assertGreaterEqual(s.role, 1)
            c.execute("BEGIN")
            self.assertEqual({s.id: s for s in c.sessions()}[me].state, imagedb.SESSION_IN_TRANSACTION)
            c.rollback()

    def test_kill_cancel_running(self):
        for name in ("socket", "tcp"):
            victim = sock() if name == "socket" else tcp()
            vid = own_id(victim)
            with victim, sock() as k:
                self.assertTrue(k.kill(vid))  # idle: done all the same
                victim.execute("SET statement_timeout = 60000")
                e, secs = run_cancelled(lambda: victim.execute(SLOW), lambda: k.kill(vid))
                self.assertIsInstance(e, imagedb.QueryCanceledError, name)
                self.assertLess(secs, 30)
                self.assertEqual(victim.execute("SELECT 1").fetchall(), [(1,)])

    def test_running_state(self):
        victim = sock()
        vid = own_id(victim)
        with victim, sock() as k:
            victim.execute("SET statement_timeout = 60000")
            states = []

            def look():
                states.append({s.id: s for s in k.sessions()}[vid].state)
                victim.cancel()
            e, _ = run_cancelled(lambda: victim.execute(SLOW), look)
            self.assertIsInstance(e, imagedb.QueryCanceledError)
            self.assertIn(imagedb.SESSION_RUNNING, states)

    def test_terminate_then_send_socket(self):
        """KILL's terminate of an idle session; its next request's send finds the connection closed (on the socket, once
        the server's lingering close ended): the server's words, ERROR 15, reported (closed_reason)"""
        victim = sock()
        vid = own_id(victim)
        with sock() as k:
            self.assertTrue(k.kill(vid, terminate=True))
            self.assertTrue(wait_hup(victim))
            with self.assertRaises(imagedb.QueryCanceledError) as cm:
                victim.execute("SELECT 1")
            e = cm.exception
            self.assertEqual((e.code, e.closed), (15, True))
            self.assertIn("ended by a KILL", str(e))
            self.assertTrue(victim.raw.wr_closed)  # the failed send's path
            self.assertTrue(victim.closed)
            for _ in range(100):  # its session's end runs on the engine thread
                if not k.kill(vid):
                    break
                time.sleep(0.05)
            self.assertFalse(k.kill(vid))
            self.assertNotIn(vid, [s.id for s in k.sessions()])
        victim.close()

    def test_terminate_tcp(self):
        """over TCP the first write after the close may be taken by the kernel: the words then come as the reply"""
        victim = tcp()
        vid = own_id(victim)
        with sock() as k:
            victim.execute("BEGIN")
            self.assertTrue(k.kill(vid, terminate=True))
            time.sleep(0.2)
            with self.assertRaises(imagedb.QueryCanceledError) as cm:
                victim.execute("SELECT 1")
            self.assertEqual((cm.exception.code, cm.exception.closed), (15, True))
            self.assertIn("ended by a KILL", str(cm.exception))
        victim.close()

    def test_terminate_running(self):
        victim = sock()
        vid = own_id(victim)
        victim.execute("SET statement_timeout = 60000")
        with sock() as k:
            e, secs = run_cancelled(lambda: victim.execute(SLOW), lambda: k.kill(vid, terminate=True))
            self.assertIsInstance(e, imagedb.QueryCanceledError)
            self.assertTrue(victim.closed)
            self.assertLess(secs, 30)
        victim.close()

    def test_plain_close_then_send(self):
        """TERMINATE: the server closes with no ERROR before it: a later send is the plain I/O error"""
        c = sock()
        c.raw.send_terminate()
        self.assertTrue(wait_hup(c))
        with self.assertRaises(imagedb.OperationalError) as cm:
            c.raw.send_ping()
        self.assertIsNone(cm.exception.code)
        self.assertIn("a write failed", str(cm.exception))
        c.close()

    def test_kill_bounds(self):
        with sock() as k:
            for bad in (0, -1, 1 << 64, "1"):
                with self.assertRaises(imagedb.InterfaceError):
                    k.kill(bad)
            self.assertFalse(k.kill((1 << 64) - 1))  # no such session


@live()
class Misc(unittest.TestCase):
    def test_large_result_and_fetch(self):
        with sock() as c:
            ensure_big(c)
            cur = c.cursor()
            cur.execute("SELECT id, v FROM big2 WHERE id < 150000 ORDER BY id")
            self.assertEqual(cur.rowcount, 150000)
            self.assertEqual(cur.fetchone(), (0, 0))
            self.assertEqual(cur.fetchmany(2), [(1, 0), (2, 0)])
            cur.arraysize = 3
            self.assertEqual(len(cur.fetchmany()), 3)
            rest = cur.fetchall()
            self.assertEqual(len(rest), 150000 - 6)
            self.assertEqual(rest[-1], (149999, 149 % 50))
            self.assertIsNone(cur.fetchone())
            self.assertEqual(sum(1 for _ in c.execute("SELECT id FROM big WHERE id < 10")), 10)
            cur.execute("CREATE TABLE ms (id INT64 PRIMARY KEY)")
            self.assertIsNone(cur.description)
            with self.assertRaises(imagedb.ProgrammingError):
                cur.fetchall()
            cur.close()
            with self.assertRaises(imagedb.InterfaceError):
                cur.execute("SELECT 1")

    def test_ping_and_module(self):
        with tcp(via="ca") as c:
            c.ping()
            c.ping()
        self.assertEqual((imagedb.apilevel, imagedb.threadsafety, imagedb.paramstyle), ("2.0", 1, "numeric"))
        with sock() as c:
            c.autocommit = True
            self.assertTrue(c.autocommit)
            with self.assertRaises(imagedb.NotSupportedError):
                c.autocommit = False
        self.assertTrue(issubclass(imagedb.IntegrityError, imagedb.DatabaseError))
        self.assertTrue(issubclass(imagedb.ProtocolError, imagedb.InterfaceError))


@live("2")
class Renewed(unittest.TestCase):
    def test_pin_survives_renewal(self):
        """after `cert --renew` and a restart: the same key (the pin unchanged, a login by it taken), another certificate
        (so tls-server-end-point's value changed, and the login bound by it is taken too), the CA file still good"""
        old = crt_der(E["IMDB_PY_OLD_CRT"])
        new = crt_der(os.path.join(E["IMDB_PY_B_SDIR"], "tls", "server.crt"))
        self.assertNotEqual(old, new)
        self.assertEqual(_x509.spki_pin(old), _x509.spki_pin(new))
        self.assertEqual(_x509.spki_pin(new).hex(), E["IMDB_PY_B_PIN"])
        for via in ("pin", "ca"):
            with tcp(via=via) as c:
                self.assertEqual(c.execute("SELECT 1").fetchall(), [(1,)])
        ctx = _raw.tls_context(pin=bytes(32))
        s = ctx.wrap_socket(socket.create_connection(("127.0.0.1", int(E["IMDB_PY_B_PORT"])), timeout=10),
                            server_hostname="127.0.0.1")
        served = s.getpeercert(binary_form=True)
        s.close()
        self.assertEqual(served, new)
        self.assertNotEqual(_x509.end_point(served), _x509.end_point(old))
        with sock() as c:  # the database came through the restart
            self.assertEqual(c.execute("SELECT COUNT(*) FROM big").fetchone(), (1000,))


if __name__ == "__main__":
    unittest.main()
