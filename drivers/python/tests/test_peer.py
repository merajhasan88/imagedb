"""The driver against a scripted peer on a socketpair (no server): what a live server never sends, and the bytes the
driver itself puts on the stream. The login's refusals (a wrong server signature, verdicts 1 and 2, a later version, a
challenge's padding); a refused frame ends the connection naming it; a frame out of its place; closed_reason in both
orders, and the reply path's close; the cancel rules (dropped with nothing outstanding, sent in band by the reading
thread, before the next COPY_DATA while uploading, before a pipelined frame)."""

import hashlib
import hmac
import os
import socket
import struct
import threading
import time
import unittest

import imagedb
from imagedb import _raw
from imagedb import _wire as w

PW = b"pencil"
SALT = b"\x03" * 16
ITER = 1000


def recv_exact(s, n):
    b = b""
    while len(b) < n:
        k = s.recv(n - len(b))
        if not k:
            raise EOFError("peer: closed")
        b += k
    return b


def read_frame(s):
    n, t = struct.unpack("<IB", recv_exact(s, 5))
    return t, recv_exact(s, n - 1)


def send_msg(s, m, cols=None):
    s.sendall(w.msg_put(m, cols))


def serve_auth(s, verdict="ok", **kw):
    try:
        _serve_auth(s, verdict, **kw)
    except (EOFError, OSError):  # the client refused what it was sent and closed
        pass


def _serve_auth(s, verdict="ok", head=None, pad=False, close_after_hello=False):
    hello = recv_exact(s, w.HELLO_LEN)
    if close_after_hello:
        s.close()
        return
    if head is not None:
        s.sendall(head)
        s.close()
        return
    cb = bytearray(w.challenge_put(w.Challenge(1, SALT, ITER, os.urandom(32))))
    if pad:
        cb[-1] = 1
    s.sendall(bytes(cb))
    proof = recv_exact(s, 32)
    am = w.auth_message(w.EP_UNIX, hello, bytes(cb), bytes(32))
    sp = hashlib.pbkdf2_hmac("sha256", PW, SALT, ITER, 32)
    ck = hmac.new(sp, b"Client Key", hashlib.sha256).digest()
    sk = hmac.new(sp, b"Server Key", hashlib.sha256).digest()
    stored = hashlib.sha256(ck).digest()
    cs = hmac.new(stored, am, hashlib.sha256).digest()
    ok = hashlib.sha256(bytes(a ^ b for a, b in zip(proof, cs))).digest() == stored
    sig = hmac.new(sk, am, hashlib.sha256).digest()
    if verdict == "ok":
        v = w.Verdict(0 if ok else 1, sig if ok else bytes(32))
    elif verdict == "badsig":
        v = w.Verdict(0, bytes([sig[0] ^ 1]) + sig[1:])
    elif verdict == "refused":
        v = w.Verdict(1, bytes(32))
    else:
        v = w.Verdict(2, bytes(32))
    s.sendall(w.verdict_put(v))


def pair(timeout=5.0):
    a, b = socket.socketpair()
    a.setblocking(False)
    b.settimeout(10)
    return _raw.RawConnection(_raw._Plain(a), w.EP_UNIX, timeout), b


def login(verdict="ok", **kw):
    raw, s = pair()
    th = threading.Thread(target=serve_auth, args=(s, verdict), kwargs=kw)
    th.start()
    try:
        raw._authenticate(w.CB_NONE, bytes(32), b"alice", PW)
    finally:
        th.join()
    return raw, s


def frame_types(s, n):
    return [read_frame(s)[0] for _ in range(n)]


class Login(unittest.TestCase):
    def test_accepted(self):
        raw, s = login()
        self.assertIsNone(raw.broken)
        raw.close()
        s.close()

    def test_refusals(self):
        for verdict, words in (("badsig", "did not prove"), ("refused", "authentication refused"),
                               ("binding", "channel binding type")):
            with self.assertRaises(imagedb.AuthenticationError) as cm:
                login(verdict)
            self.assertIn(words, str(cm.exception))
            self.assertEqual(cm.exception.code, 8)

    def test_wrong_password_proof(self):
        """the proof the driver computes is RFC 5802's: the scripted server's own check refuses another password"""
        raw, s = pair()
        th = threading.Thread(target=serve_auth, args=(s, "ok"))
        th.start()
        with self.assertRaises(imagedb.AuthenticationError):
            raw._authenticate(w.CB_NONE, bytes(32), b"alice", b"pencim")
        th.join()

    def test_login_bound(self):
        """a server that never answers the hello: the login ends at its bound (connect_timeout), never a hang"""
        raw, s = pair(timeout=None)
        raw._deadline = time.monotonic() + 0.5
        t0 = time.monotonic()
        with self.assertRaises(imagedb.OperationalError) as cm:
            raw._authenticate(w.CB_NONE, bytes(32), b"alice", PW)
        self.assertIn("connect_timeout", str(cm.exception))
        self.assertLess(time.monotonic() - t0, 5)
        s.close()

    def test_later_version_and_damage(self):
        raw, s = pair()
        th = threading.Thread(target=serve_auth, args=(s,), kwargs=dict(head=b"IMDBWIR1" + struct.pack("<I", 2)))
        th.start()
        with self.assertRaises(imagedb.NotSupportedError) as cm:
            raw._authenticate(w.CB_NONE, bytes(32), b"alice", PW)
        th.join()
        self.assertIn("version 2", str(cm.exception))
        raw, s = pair()
        th = threading.Thread(target=serve_auth, args=(s,), kwargs=dict(head=b"IMDBWIR2" + struct.pack("<I", 1)))
        th.start()
        with self.assertRaises(imagedb.NotSupportedError):
            raw._authenticate(w.CB_NONE, bytes(32), b"alice", PW)
        th.join()
        with self.assertRaises(imagedb.ProtocolError) as cm:
            login(pad=True)
        self.assertIn("challenge", str(cm.exception))
        with self.assertRaises(imagedb.OperationalError) as cm:
            login(close_after_hello=True)
        self.assertIn("closed", str(cm.exception))


class Frames(unittest.TestCase):
    def setUp(self):
        self.raw, self.s = login()

    def tearDown(self):
        self.raw.close()
        self.s.close()

    def refused(self, frames, words):
        self.raw.send_query(["SELECT 1"])
        read_frame(self.s)
        self.s.sendall(frames)
        with self.assertRaises(imagedb.ProtocolError) as cm:
            while True:
                self.raw.next()
        self.assertIn(words, str(cm.exception))
        self.assertTrue(cm.exception.closed)
        self.assertIsNotNone(self.raw.broken)
        with self.assertRaises(imagedb.InterfaceError):
            self.raw.send_ping()

    def test_ready_state_3(self):
        self.refused(w.frame(w.READY, b"\x03"), "a READY frame")

    def test_client_type(self):
        self.refused(w.frame(w.QUERY, b"\x00"), "a frame's head")

    def test_frame_length(self):
        self.refused(struct.pack("<IB", w.FRAME_MAX + 1, w.PONG), "a frame's head")

    def test_rows_past_column(self):
        cols = w.ColumnsMsg([w.Column("s", w.T_INT64, 16, 0, ())])
        rows = w.frame(w.ROWS, struct.pack("<I", 1) + w.value_bytes(w.Value(w.T_INT64, False, 40000)))
        self.refused(w.msg_put(w.Msg(w.COLUMNS, columns=cols)) + rows, "a ROWS frame")

    def test_rows_without_columns(self):
        rows = w.frame(w.ROWS, struct.pack("<I", 1) + b"\x81")
        self.refused(rows, "a ROWS frame")

    def test_out_of_place(self):
        self.raw.send_query(["SELECT 1"])
        read_frame(self.s)
        send_msg(self.s, w.Msg(w.READY, state=0))
        self.assertEqual(self.raw.next().type, w.READY)
        send_msg(self.s, w.Msg(w.READY, state=0))  # nothing outstanding: refused
        with self.assertRaises(imagedb.ProtocolError) as cm:
            self.raw.next()
        self.assertIn("out of its place", str(cm.exception))

    def test_pong_unasked(self):
        send_msg(self.s, w.Msg(w.PONG))
        with self.assertRaises(imagedb.ProtocolError):
            self.raw.next()

    def test_out_of_turn_amid_rows(self):
        """PONG, SESSIONS_LIST and KILL_DONE land anywhere among a request's replies (out of turn)"""
        cols = w.ColumnsMsg([w.Column("x", w.T_INT64, 0, 0, ())])
        self.raw.send_query(["SELECT 1"])
        self.raw.send_ping()
        self.raw.send_sessions()
        self.raw.send_kill(w.KILL_CANCEL, 5)
        self.assertEqual(frame_types(self.s, 4), [w.QUERY, w.PING, w.SESSIONS, w.KILL])
        one = w.Msg(w.ROWS, rows=[[w.Value(w.T_INT64, False, 1)]])
        for m in (w.Msg(w.COLUMNS, columns=cols), w.Msg(w.PONG), one, w.Msg(w.SESSIONS_LIST, sessions=[]), one,
                  w.Msg(w.KILL_DONE, code=1, sid=5), w.Msg(w.DONE, status="", count=2, read=None, write=None),
                  w.Msg(w.READY, state=0)):
            send_msg(self.s, m, cols)
        got = [self.raw.next().type for _ in range(8)]
        self.assertEqual(got, [w.COLUMNS, w.PONG, w.ROWS, w.SESSIONS_LIST, w.ROWS, w.KILL_DONE, w.DONE, w.READY])

    def test_warnings(self):
        """a WARNING lands on its statement's result, the cursor's and the connection's messages"""
        conn = imagedb.Connection(self.raw)
        cols = w.ColumnsMsg([w.Column("x", w.T_INT64, 0, 0, ())])

        def peer():
            read_frame(self.s)
            for m in (w.Msg(w.COLUMNS, columns=cols), w.Msg(w.ROWS, rows=[[w.Value(w.T_INT64, False, 1)]]),
                      w.Msg(w.WARNING, message="the anchor is stale"),
                      w.Msg(w.DONE, status="", count=1, read=None, write=None), w.Msg(w.READY, state=0)):
                send_msg(self.s, m, cols)
        th = threading.Thread(target=peer)
        th.start()
        cur = conn.execute("SELECT 1")
        th.join()
        self.assertEqual(cur.fetchall(), [(1,)])
        self.assertEqual(cur.result.warnings, ["the anchor is stale"])
        self.assertEqual(cur.messages, [(imagedb.Warning, "the anchor is stale")])
        self.assertEqual(conn.messages, [(imagedb.Warning, "the anchor is stale")])

    def test_closed_reason_error_last(self):
        """a send that finds the connection closed reports the server's last ERROR when it is the last frame"""
        send_msg(self.s, w.Msg(w.ERROR, code=15, index=0, message="the session was ended by a KILL"))
        self.s.close()
        time.sleep(0.05)
        with self.assertRaises(imagedb.QueryCanceledError) as cm:
            self.raw.send_query(["SELECT 1"])
        e = cm.exception
        self.assertTrue(self.raw.wr_closed)
        self.assertEqual((e.code, e.closed), (15, True))
        self.assertIn("ended by a KILL", str(e))
        self.assertIn("the server closed the connection", str(e))

    def test_closed_reason_error_then_frame(self):
        """an ERROR followed by another frame answered an earlier request: the plain I/O error"""
        self.raw.send_ping()
        read_frame(self.s)
        send_msg(self.s, w.Msg(w.ERROR, code=15, index=0, message="an earlier statement's"))
        send_msg(self.s, w.Msg(w.PONG))
        self.s.close()
        time.sleep(0.05)
        with self.assertRaises(imagedb.OperationalError) as cm:
            self.raw.send_query(["SELECT 1"])
        self.assertTrue(self.raw.wr_closed)
        self.assertIsNone(cm.exception.code)
        self.assertIn("a write failed", str(cm.exception))

    def test_closed_reason_nothing(self):
        self.s.close()
        time.sleep(0.05)
        with self.assertRaises(imagedb.OperationalError) as cm:
            self.raw.send_query(["SELECT 1"])
        self.assertIsNone(cm.exception.code)

    def test_reply_path_close(self):
        """the reply path: an ERROR, then the server's close, met by the read for READY: the ERROR is the reason"""
        conn = imagedb.Connection(self.raw)
        th = threading.Thread(target=lambda: (read_frame(self.s), send_msg(self.s, w.Msg(
            w.ERROR, code=3, index=0, message="too many connections for this role (--role-conns)")), self.s.close()))
        th.start()
        with self.assertRaises(imagedb.OperationalError) as cm:
            conn.execute("SELECT 1")
        th.join()
        self.assertEqual((cm.exception.code, cm.exception.closed), (3, True))
        self.assertIn("--role-conns", str(cm.exception))
        self.assertTrue(conn.closed)

    def test_login_refused_for_a_bound(self):
        """section 4: a login the verdict accepts refused for a bound, ERROR 3 unasked, then the close: the client's
        first request reports it (by its send or by its read)"""
        send_msg(self.s, w.Msg(w.ERROR, code=3, index=0, message="the remaining connection slots are reserved"))
        self.s.close()
        time.sleep(0.05)
        conn = imagedb.Connection(self.raw)
        with self.assertRaises(imagedb.OperationalError) as cm:
            conn.execute("SELECT 1")
        self.assertEqual(cm.exception.code, 3)
        self.assertIn("reserved", str(cm.exception))


class CancelRules(unittest.TestCase):
    def setUp(self):
        self.raw, self.s = login()

    def tearDown(self):
        self.raw.close()
        self.s.close()

    def test_dropped_with_nothing_outstanding(self):
        self.raw.cancel()
        self.raw.send_query(["SELECT 1"])
        self.raw.send_ping()
        self.assertEqual(frame_types(self.s, 2), [w.QUERY, w.PING])
        self.assertEqual(self.raw.cancels_sent, 0)

    def test_sent_by_the_reading_thread(self):
        self.raw.send_query(["SELECT slow"])
        self.assertEqual(read_frame(self.s)[0], w.QUERY)
        th = threading.Timer(0.2, self.raw.cancel)
        th.start()
        got = []

        def peer():
            got.append(read_frame(self.s)[0])  # the CANCEL, while the client waits in next()
            send_msg(self.s, w.Msg(w.ERROR, code=15, index=0, message="canceling statement due to user request"))
            send_msg(self.s, w.Msg(w.READY, state=0))
        pt = threading.Thread(target=peer)
        pt.start()
        conn = imagedb.Connection(self.raw)
        with self.assertRaises(imagedb.QueryCanceledError):
            conn._run(lambda: None)
        pt.join()
        th.join()
        self.assertEqual(got, [w.CANCEL])
        self.assertEqual(self.raw.cancels_sent, 1)
        self.assertEqual(self.raw.outstanding, 0)

    def test_before_a_pipelined_frame(self):
        self.raw.send_query(["SELECT 1"])
        self.raw.cancel()
        self.raw.send_ping()
        self.assertEqual(frame_types(self.s, 3), [w.QUERY, w.CANCEL, w.PING])

    def test_copy_upload(self):
        """a cancel asked while the driver uploads COPY's data goes out before the next COPY_DATA, and the upload ends
        (COPY_DONE): the COPY is refused unrun"""
        conn = imagedb.Connection(self.raw)
        got = []

        def peer():
            got.append(read_frame(self.s)[0])  # QUERY
            send_msg(self.s, w.Msg(w.COPY_IN))
            while True:
                t, _ = read_frame(self.s)
                got.append(t)
                if t in (w.COPY_DONE, w.COPY_FAIL):
                    break
            send_msg(self.s, w.Msg(w.ERROR, code=15, index=0, message="COPY ... FROM STDIN cancelled"))
            send_msg(self.s, w.Msg(w.READY, state=0))
        pt = threading.Thread(target=peer)
        pt.start()

        def data():
            yield "1,a\n"
            conn.cancel()
            yield "2,b\n"
            yield "3,c\n"
        with self.assertRaises(imagedb.QueryCanceledError):
            conn.copy_from("COPY t FROM STDIN", data())
        pt.join()
        self.assertEqual(got, [w.QUERY, w.COPY_DATA, w.CANCEL, w.COPY_DATA, w.COPY_DONE])

    def test_copy_source_fails(self):
        conn = imagedb.Connection(self.raw)
        got = []

        def peer():
            read_frame(self.s)
            send_msg(self.s, w.Msg(w.COPY_IN))
            while True:
                t, b = read_frame(self.s)
                got.append((t, b))
                if t in (w.COPY_DONE, w.COPY_FAIL):
                    break
            send_msg(self.s, w.Msg(w.ERROR, code=15, index=0, message="COPY ... FROM STDIN failed by its client"))
            send_msg(self.s, w.Msg(w.READY, state=0))
        pt = threading.Thread(target=peer)
        pt.start()

        def data():
            yield b"1,a\n"
            raise KeyError("the source's own failure")
        with self.assertRaises(KeyError):
            conn.copy_from("COPY t FROM STDIN", data())
        pt.join()
        self.assertEqual([t for t, _ in got], [w.COPY_DATA, w.COPY_FAIL])
        self.assertIn("KeyError", w.msg_get(w.COPY_FAIL, got[1][1]).message)
        self.assertIsNone(self.raw.broken)

    def test_copy_data_in_1mib_frames(self):
        conn = imagedb.Connection(self.raw)
        sizes = []

        def peer():
            read_frame(self.s)
            send_msg(self.s, w.Msg(w.COPY_IN))
            while True:
                t, b = read_frame(self.s)
                if t != w.COPY_DATA:
                    break
                sizes.append(len(b))
            send_msg(self.s, w.Msg(w.DONE, status="COPY 0", count=0, read=None, write=None))
            send_msg(self.s, w.Msg(w.READY, state=0))
        pt = threading.Thread(target=peer)
        pt.start()
        conn.copy_from("COPY t FROM STDIN", [b"x" * (3 << 20) + b"y"])
        pt.join()
        self.assertEqual(sizes, [1 << 20, 1 << 20, 1 << 20, 1])


if __name__ == "__main__":
    unittest.main()
