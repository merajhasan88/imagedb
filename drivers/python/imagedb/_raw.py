"""The protocol's level: one IMDBWIR1 connection over the Unix socket or TCP with TLS 1.3, its login, its requests and
its replies one message at a time (as client/client.c's imdbc).

The socket is non-blocking once connected and every wait is a poll on it and on a wake-up pipe, so cancel(), from any
thread, wakes the thread reading the replies, which sends CANCEL in band: Python's SSLSocket is one OpenSSL SSL object,
which takes no write from a second thread while one reads (docs/n1-design.md section 4). A read always tries the socket
(or the TLS session, which may hold bytes poll cannot see) before it polls. The cancel rules are client.c's: a cancel
asked while nothing is outstanding is dropped when the next request goes out; one asked while this side sends (a
COPY's data) goes out before the next frame.
"""

import errno
import hmac
import os
import secrets
import select
import socket as _socket
import ssl
import threading
import time

from . import _native
from . import _wire as w
from . import _x509
from ._errors import (AuthenticationError, DataError, Error, InterfaceError, NotSupportedError, OperationalError,
                      ProgrammingError, ProtocolError, server_error)

ALPN = "imdbwir1"
_CANCEL_FRAME = w.frame(w.CANCEL)
_REQUESTS = (w.QUERY, w.PREPARE, w.EXECUTE, w.DEALLOCATE)
_CHUNK = 256 << 10


class _WantRead(Exception):
    pass


class _WantWrite(Exception):
    pass


class _SendFailed(Exception):
    pass


class _Plain:
    """the Unix socket: no TLS (no negotiation exists to downgrade)"""

    def __init__(self, sock):
        self.sock = sock

    def fileno(self):
        return self.sock.fileno()

    def read_into(self, buf, n):
        try:
            return self.sock.recv_into(buf, n)
        except (BlockingIOError, InterruptedError):
            raise _WantRead() from None

    def write(self, view):
        try:
            return self.sock.send(view)
        except (BlockingIOError, InterruptedError):
            raise _WantWrite() from None

    def close(self):
        self.sock.close()


class _Tls:
    """TCP with TLS 1.3: the SSLSocket's reads and writes, non-blocking (a write retried with the same bytes)"""

    def __init__(self, ssock):
        self.sock = ssock

    def fileno(self):
        return self.sock.fileno()

    def read_into(self, buf, n):
        try:
            return self.sock.recv_into(buf, n)
        except ssl.SSLWantReadError:
            raise _WantRead() from None
        except ssl.SSLWantWriteError:
            raise _WantWrite() from None
        except (ssl.SSLZeroReturnError, ssl.SSLEOFError):
            return 0

    def write(self, view):
        try:
            return self.sock.send(view)
        except ssl.SSLWantWriteError:
            raise _WantWrite() from None
        except ssl.SSLWantReadError:
            raise _WantRead() from None

    def close(self):
        self.sock.close()


def _text_arg(x, what):
    if isinstance(x, str):
        try:
            return x.encode("utf-8")
        except UnicodeEncodeError:
            raise InterfaceError("%s is UTF-8: it holds a lone surrogate" % what) from None
    if isinstance(x, (bytes, bytearray, memoryview)):
        return bytes(x)
    raise InterfaceError("%s is a str" % what)


def _user_arg(user):
    u = _text_arg(user if user is not None else "", "a role's name")
    if not w.user_ok(u):
        raise InterfaceError("a role's name is 1 to 63 bytes of UTF-8 without NUL")
    return u


def _password_arg(password):
    if isinstance(password, str):
        try:
            pw = password.encode("ascii")
        except UnicodeEncodeError:
            raise InterfaceError("a password is 1 to 1,024 bytes of printable ASCII") from None
    elif isinstance(password, (bytes, bytearray)):
        pw = bytes(password)
    else:
        raise InterfaceError("a password is 1 to 1,024 bytes of printable ASCII")
    if not w.password_ok(pw):
        raise InterfaceError("a password is 1 to 1,024 bytes of printable ASCII")
    return pw


def encode_params(params):
    """Python values (or wire Values as they are) as one parameter run's bytes: DataError for a value no wire value keeps,
    ProgrammingError for more than 256"""
    if params is None:
        params = ()
    if isinstance(params, (str, bytes, dict)) or not hasattr(params, "__len__"):
        raise ProgrammingError("parameters are a sequence ($1 to $n), not %s" % type(params).__name__)
    if len(params) > w.VALUES_MAX:
        raise ProgrammingError("a statement takes at most 256 parameters (%d)" % len(params))
    vals = []
    for k, x in enumerate(params):
        if isinstance(x, w.Value):
            vals.append(x)
            continue
        try:
            vals.append(_native.from_native(x))
        except _native.EncodeError as e:
            raise DataError("parameter $%d: %s" % (k + 1, e)) from None
    try:
        return len(vals), w.params_bytes(vals)
    except w.WireError as e:
        raise DataError(str(e)) from None


class RawConnection:
    """one IMDBWIR1 connection (connect_unix, connect_tcp): requests sent whole (send_*), replies read one message at a
    time (next()); requests may pipeline. cancel() from any thread."""

    def __init__(self, transport, endpoint, timeout):
        self._t = transport
        self._fd = transport.fileno()
        self.endpoint = endpoint
        self.binding_type = w.CB_NONE
        self.timeout = timeout         # each wait for bytes, in seconds (None: none)
        self._deadline = None          # the login's bound (connect_timeout)
        self._lock = threading.Lock()  # the cancel flag, and the wake-up pipe's life
        self._cancel = False
        self._closed = False
        self.broken = None             # why the connection can no longer be used (an Error), or None
        r, wfd = os.pipe()
        os.set_blocking(r, False)
        os.set_blocking(wfd, False)
        self._wake_r, self._wake_w = r, wfd
        self._poll_rw = select.poll()   # the socket readable, or a cancel's wake-up
        self._poll_rw.register(self._fd, select.POLLIN)
        self._poll_rw.register(self._wake_r, select.POLLIN)
        self._poll_ww = select.poll()   # the socket writable, or a wake-up
        self._poll_ww.register(self._fd, select.POLLOUT)
        self._poll_ww.register(self._wake_r, select.POLLIN)
        self._poll_r = select.poll()
        self._poll_r.register(self._fd, select.POLLIN)
        self._poll_w = select.poll()
        self._poll_w.register(self._fd, select.POLLOUT)
        self._rbuf = bytearray()
        self._rpos = 0
        self._chunk = bytearray(_CHUNK)
        self._chunkv = memoryview(self._chunk)
        self.outstanding = 0           # requests sent whose READY has not been read (each READY ends one)
        self.pings = 0                 # PINGs, SESSIONSs and KILLs sent whose answer has not been read
        self.sessions_asked = 0
        self.kills = 0
        self.cancels_sent = 0
        self.state = w.IDLE            # READY's last state
        self._cols = None              # the COLUMNS a ROWS is read against: set by COLUMNS, ended by DONE or ERROR
        self._last_error = None        # the last frame read, when it was an ERROR (a close's reason)
        self.wr_closed = False         # a write found the connection closed (closed_reason ran)
        self._quiet = False            # closed_reason reads: nothing more is sent

    # ---- bytes ----

    def _wait(self, want_write, wake):
        if self._deadline is not None:
            left = self._deadline - time.monotonic()
            if left <= 0:
                raise self._fail(OperationalError("the login took longer than its bound (connect_timeout)"))
            ms = int(left * 1000) + 1
        else:
            ms = None if self.timeout is None else int(self.timeout * 1000)
        if wake:
            p = self._poll_ww if want_write else self._poll_rw
        else:
            p = self._poll_w if want_write else self._poll_r
        while True:
            try:
                ev = p.poll(ms)
                break
            except InterruptedError:
                continue
        if not ev:
            if self._deadline is not None:
                raise self._fail(OperationalError("the login took longer than its bound (connect_timeout)"))
            raise self._fail(OperationalError("no reply within %g s (the connection's timeout)" % self.timeout))
        for fd, _ in ev:
            if fd == self._wake_r:
                self._drain_wake()

    def _drain_wake(self):
        try:
            while os.read(self._wake_r, 64):
                pass
        except (BlockingIOError, OSError):
            pass

    def _maybe_cancel(self):
        """a cancel asked meanwhile, sent at once when a request is outstanding (else it was for nothing: dropped)"""
        with self._lock:
            go, self._cancel = self._cancel, False
        if go and self.outstanding and not self._quiet:
            self._send_cancel()

    def _send_cancel(self):
        try:
            self._send_all(_CANCEL_FRAME)
        except _SendFailed as e:
            raise self._closed_reason(e) from None
        self.cancels_sent += 1

    def _need(self, n):
        while len(self._rbuf) - self._rpos < n:
            self._maybe_cancel()
            try:
                k = self._t.read_into(self._chunk, _CHUNK)
            except _WantRead:
                self._wait(False, True)
                continue
            except _WantWrite:
                self._wait(True, True)
                continue
            except (OSError, ssl.SSLError) as e:
                raise self._eof("a read failed: %s" % e) from None
            if k == 0:
                raise self._eof("closed by the server")
            if self._rpos and self._rpos >= len(self._rbuf) // 2:
                del self._rbuf[:self._rpos]
                self._rpos = 0
            self._rbuf += self._chunkv[:k]

    def _take(self, n):
        self._need(n)
        p = self._rpos
        self._rpos = p + n
        return bytes(self._rbuf[p:p + n])

    def _send_all(self, data):
        view = memoryview(data)
        off, n = 0, len(view)
        while off < n:
            piece = view[off:off + _CHUNK]  # a retry sends the same bytes (TLS's rule)
            try:
                k = self._t.write(piece)
            except _WantWrite:
                self._wait(True, False)
                continue
            except _WantRead:
                self._wait(False, False)
                continue
            except (OSError, ssl.SSLError, ValueError) as e:
                self.wr_closed = True
                raise _SendFailed(e) from None
            if k <= 0:
                self.wr_closed = True
                raise _SendFailed(OSError(errno.EPIPE, "closed"))
            off += k

    # ---- failure ----

    def _fail(self, err):
        """the connection unusable from here: err is why"""
        if self.broken is None:
            self.broken = err
            err.closed = True
        self.close()
        return err

    def _eof(self, what):
        """the server's close met by a read: its reason when the last frame before it was an ERROR (section 4), else
        the plain I/O error"""
        le = self._last_error
        if le is not None and 1 <= le.code <= 64:
            return self._fail(server_error(le.code, le.index, le.message, closed=True,
                                           prefix="the server closed the connection: "))
        return self._fail(OperationalError("the connection: %s" % what))

    def _protocol(self, e, what):
        return self._fail(ProtocolError("IMDBWIR1: the server sent %s this driver refuses: %s" % (what, e)))

    def _closed_reason(self, err):
        """a send that found the connection closed (client.c's closed_reason): what the server sent before its close is
        read (1 s a wait, 64 frames at most); when its very last frame is an ERROR (a code of 1 to 64), that is the
        error reported, in the server's words; else the plain I/O error"""
        keep, self.timeout, self._deadline = self.timeout, 1.0, None
        self._quiet = True
        code, last, ended = 0, None, False
        for _ in range(64):
            try:
                m = self._next(lenient=True)
            except Exception:  # noqa: BLE001 (any end, as client.c's: the close, a timeout, bytes refused)
                ended = True
                break
            if m.type == w.ERROR:
                code, last = m.code, m
            else:
                code = 0  # an ERROR before another frame answered that frame's request, not the close
        self.timeout = keep
        self.broken = None
        if ended and code and code <= 64:
            return self._fail(server_error(code, last.index, last.message, closed=True,
                                           prefix="the server closed the connection: "))
        return self._fail(OperationalError("the connection: a write failed (%s)" % (err.args[0] if err.args else err)))

    def close(self):
        with self._lock:
            if self._closed:
                return
            self._closed = True
            os.close(self._wake_r)
            os.close(self._wake_w)
        if self.broken is None:
            self.broken = InterfaceError("the connection is closed", closed=True)
        try:
            self._t.close()
        except OSError:
            pass

    def __del__(self):  # an unclosed connection's socket and wake-up pipe given back when it is collected
        try:
            self.close()
        except Exception:  # noqa: BLE001 (a half-made object, or the interpreter's end)
            pass

    def _usable(self):
        if self.broken is not None:
            raise InterfaceError("the connection is closed (%s)" % self.broken, closed=True)

    # ---- the login ----

    def _authenticate(self, cb_type, binding, user, pw):
        """the pre-auth exchange (section 4): the hello, the challenge, the proof over the AuthMessage, the verdict and
        the server's signature, checked"""
        hello = w.hello_put(w.Hello(w.VERSION, cb_type, user, secrets.token_bytes(w.NONCE)))
        try:
            self._send_all(hello)
            head = self._take(w.PREAUTH_HEAD)
            try:
                version = w.preauth_head(head)
            except w.WireError as e:
                if e.kind == w.UNSUPPORTED:
                    raise self._fail(NotSupportedError(str(e))) from None
                raise self._protocol(e, "a challenge") from None
            if version != w.VERSION:
                raise self._fail(NotSupportedError("the server speaks IMDBWIR1 version %d, not 1" % version))
            chb = head + self._take(w.CHALLENGE_LEN - w.PREAUTH_HEAD)
            try:
                ch = w.challenge_get(chb)
            except w.WireError as e:
                raise self._protocol(e, "a challenge") from None
            am = w.auth_message(self.endpoint, hello, chb, binding)
            proof, want = w.scram_client(pw, ch, am)
            self._send_all(proof)
            vb = self._take(w.VERDICT_LEN)
        except _SendFailed as e:
            raise self._fail(OperationalError("the login: a write failed (%s)" % e.args[0])) from None
        try:
            v = w.verdict_get(vb)
        except w.WireError as e:
            raise self._protocol(e, "a verdict") from None
        if v.code == w.VERDICT_BINDING:  # never retried with another type: no downgrade (section 8f)
            raise self._fail(AuthenticationError(
                "the server refuses this login's channel binding type (%s)%s" % (
                    {0: "none", 1: "the TLS exporter", 2: "tls-server-end-point"}[cb_type],
                    ": the server takes tls-server-end-point only when run with --channel-binding any"
                    if cb_type == w.CB_ENDPOINT else ""), code=8))
        if v.code != w.VERDICT_OK:
            raise self._fail(AuthenticationError("authentication refused", code=8))
        if not hmac.compare_digest(v.signature, want):
            raise self._fail(AuthenticationError("the server did not prove it holds the verifier", code=8))
        self.binding_type = cb_type

    # ---- requests ----

    def _put(self, data, t):
        self._usable()
        req = t in _REQUESTS
        send_cancel = False
        with self._lock:
            if req and not self.outstanding:
                self._cancel = False  # one asked while nothing ran: for nothing
            elif self.outstanding and self._cancel:
                self._cancel = False  # asked while this side sends: before the next frame
                send_cancel = True
        try:
            if send_cancel:
                self._send_all(_CANCEL_FRAME)
                self.cancels_sent += 1
            self._send_all(data)
        except _SendFailed as e:
            raise self._closed_reason(e) from None
        if req:
            self.outstanding += 1
        elif t == w.PING:
            self.pings += 1
        elif t == w.SESSIONS:
            self.sessions_asked += 1
        elif t == w.KILL:
            self.kills += 1

    def send_query(self, stmts):
        """QUERY: a batch of statements, each (sql, params) or a bare sql string; params a sequence ($1 to $n) of Python
        values (or wire Values)"""
        parts = []
        for s in stmts:
            sql, params = (s, ()) if isinstance(s, (str, bytes)) else s
            sb = _text_arg(sql, "a statement")
            if not 1 <= len(sb) <= w.SQL_MAX or not w.utf8_ok(sb):
                raise ProgrammingError("a statement is 1 byte to 4 MiB of UTF-8 without NUL")
            n, vb = encode_params(params)
            parts.append((sb, n, vb))
        if not 1 <= len(parts) <= w.BATCH_MAX:
            raise ProgrammingError("a QUERY holds 1 to 4,096 statements (%d)" % len(parts))
        try:
            data = w.query_frame(parts)
        except w.WireError as e:
            raise InterfaceError("a request its encoder refuses: %s" % e) from None
        self._put(data, w.QUERY)

    def _name(self, name):
        nb = _text_arg(name, "a prepared statement's name")
        if not 1 <= len(nb) <= w.NAME_MAX or not w.utf8_ok(nb):
            raise ProgrammingError("a prepared statement's name is 1 to 63 bytes of UTF-8")
        return nb

    def send_prepare(self, name, sql):
        nb = self._name(name)
        sb = _text_arg(sql, "a statement")
        try:
            data = w.msg_put(w.Msg(w.PREPARE, name=nb, text=sb))
        except w.WireError as e:
            raise ProgrammingError("a PREPARE its encoder refuses: %s" % e) from None
        self._put(data, w.PREPARE)

    def execute_frames(self, name, sets):
        """the EXECUTE frames for sets of parameters: each at most 4,096 sets and 16 MiB; [(frame, first set's index,
        sets)]"""
        nb = self._name(name)
        sets = list(sets)
        if not sets:
            raise ProgrammingError("an EXECUTE takes one set of parameters at least")
        nvals = None
        encoded = []
        for k, s in enumerate(sets):
            n, vb = encode_params(s)
            if nvals is None:
                nvals = n
            elif n != nvals:
                raise ProgrammingError("every parameter set holds the same number of values (set %d: %d, not %d)"
                                       % (k, n, nvals))
            encoded.append(vb)
        frames, start = [], 0
        room = w.FRAME_MAX - 1 - (1 + len(nb) + 6)
        while start < len(encoded):
            end, size = start, 0
            while end < len(encoded) and end - start < w.BATCH_MAX and size + len(encoded[end]) <= room:
                size += len(encoded[end])
                end += 1
            if end == start:
                raise InterfaceError("a parameter set past a frame's 16 MiB")
            frames.append((w.execute_frame(nb, nvals, end - start, b"".join(encoded[start:end])), start, end - start))
            start = end
        return frames

    def send_execute(self, name, sets):
        """EXECUTE of a prepared statement with one or more parameter sets (one frame: at most 4,096 sets, 16 MiB)"""
        frames = self.execute_frames(name, sets)
        if len(frames) != 1:
            raise InterfaceError("an EXECUTE's sets past one frame (4,096 sets, 16 MiB): send them in several")
        self._put(frames[0][0], w.EXECUTE)

    def send_frame(self, data, t):
        self._put(data, t)

    def send_deallocate(self, name):
        self._put(w.msg_put(w.Msg(w.DEALLOCATE, name=self._name(name))), w.DEALLOCATE)

    def send_copy_data(self, data):
        """COPY ... FROM STDIN's data after its COPY_IN, in frames of at most 1 MiB (a cancel asked meanwhile goes out
        before the next)"""
        view = memoryview(data)
        for off in range(0, len(view), w.COPY_PIECE):
            self._put(w.frame(w.COPY_DATA, bytes(view[off:off + w.COPY_PIECE])), w.COPY_DATA)

    def send_copy_done(self):
        self._put(w.frame(w.COPY_DONE), w.COPY_DONE)

    def send_copy_fail(self, reason):
        b = _text_arg(reason, "a COPY_FAIL's reason")
        b = b[:w.utf8_fit(b, w.MESSAGE_MAX)]
        self._put(w.msg_put(w.Msg(w.COPY_FAIL, message=b.decode("utf-8"))), w.COPY_FAIL)

    def send_ping(self):
        self._put(w.frame(w.PING), w.PING)

    def send_sessions(self):
        self._put(w.frame(w.SESSIONS), w.SESSIONS)

    def send_kill(self, kind, sid):
        if kind not in (w.KILL_CANCEL, w.KILL_TERMINATE) or not isinstance(sid, int) or not 1 <= sid <= w.U64_MAX:
            raise InterfaceError("a KILL's kind is cancel or terminate, its session an id from SESSIONS (1 or more)")
        self._put(w.msg_put(w.Msg(w.KILL, kind=kind, sid=sid)), w.KILL)

    def send_terminate(self):
        self._put(w.frame(w.TERMINATE), w.TERMINATE)

    def cancel(self):
        """the statement running for this connection, cancelled: any thread (a flag and a wake-up; the reading thread
        sends CANCEL in band, or the sending thread before its next frame)"""
        with self._lock:
            if self._closed:
                return
            self._cancel = True
            try:
                os.write(self._wake_w, b"\x01")
            except OSError:  # a full pipe already wakes the reader
                pass

    # ---- replies ----

    def next(self):
        """the next reply, decoded (a ROWS against its statement's COLUMNS); a frame refused ends the connection
        (ProtocolError, naming it), as does the server's close (its reason when its last frame was an ERROR)"""
        self._usable()
        return self._next(False)

    def _next(self, lenient):
        head = self._take(w.HEAD)
        try:
            n, t = w.head_get(head, True)
        except w.WireError as e:
            raise self._protocol(e, "a frame's head") from None
        body = self._take(n - 1)
        name = "a %s frame" % w.FRAME_NAMES[t]
        try:
            m = w.msg_get(t, body, self._cols if t == w.ROWS else None)
        except w.WireError as e:
            raise self._protocol(e, name) from None
        if not lenient:
            self._place(m, name)
        if t == w.COLUMNS:
            self._cols = m.columns
        elif t in (w.DONE, w.ERROR, w.READY):
            self._cols = None
        self._last_error = m if t == w.ERROR else None
        return m

    def _place(self, m, name):
        """a reply in its place: COLUMNS opens a statement's result and ROWS stays in it; READY, COPY_IN, COPY_OUT, DONE
        and WARNING answer an outstanding request; PONG, SESSIONS_LIST and KILL_DONE (out of turn, anywhere) a PING, a
        SESSIONS, a KILL; an ERROR may come unasked (a refused login's bound, a KILL, a protocol error)"""
        t = m.type
        if t == w.ERROR:
            return
        if t == w.PONG:
            ok = self.pings > 0
            self.pings -= ok
        elif t == w.SESSIONS_LIST:
            ok = self.sessions_asked > 0
            self.sessions_asked -= ok
        elif t == w.KILL_DONE:
            ok = self.kills > 0
            self.kills -= ok
        elif t == w.COLUMNS:
            ok = self.outstanding > 0 and self._cols is None
        elif t == w.READY:
            ok = self.outstanding > 0
            if ok:
                self.outstanding -= 1
                self.state = m.state
        else:  # ROWS (its COLUMNS checked by the decoder), DONE, WARNING, COPY_IN, COPY_OUT
            ok = self.outstanding > 0
        if not ok:
            raise self._protocol("out of its place (nothing outstanding that it answers)", name)


def connect_unix(path, user, password, timeout=None, connect_timeout=30.0):
    """the server's Unix-domain socket (no TLS; the AuthMessage's endpoint 2, its binding zeros)"""
    u, pw = _user_arg(user), _password_arg(password)
    pb = os.fsencode(path)
    if not pb or len(pb) > 107:
        raise InterfaceError("the socket's path is 1 to 107 bytes")
    sock = _socket.socket(_socket.AF_UNIX, _socket.SOCK_STREAM)
    try:
        sock.settimeout(connect_timeout)
        sock.connect(pb)
        sock.setblocking(False)
    except OSError as e:
        sock.close()
        raise OperationalError("connect %s: %s" % (path, e.strerror or e)) from None
    raw = RawConnection(_Plain(sock), w.EP_UNIX, timeout)
    raw._deadline = time.monotonic() + connect_timeout
    try:
        raw._authenticate(w.CB_NONE, bytes(w.KEY), u, pw)
    finally:
        raw._deadline = None
    return raw


def tls_context(cafile=None, pin=None):
    """TLS 1.3 alone, ALPN imdbwir1, no tickets; verified by the CA file alone (no default certificates; the host checked
    against subjectAltName) or by the pin, checked after the handshake before any byte of ours leaves"""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.maximum_version = ssl.TLSVersion.TLSv1_3
    ctx.set_alpn_protocols([ALPN])
    ctx.options |= ssl.OP_NO_TICKET
    if cafile is not None:
        ctx.load_verify_locations(cafile=os.fspath(cafile))
        ctx.check_hostname = True
        ctx.verify_mode = ssl.CERT_REQUIRED
    else:  # pinned: the chain is not asked for; the key is
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _pin_arg(pin):
    if isinstance(pin, str):
        try:
            p = bytes.fromhex(pin)
        except ValueError:
            raise InterfaceError("a pin is the server key's SPKI SHA-256: 64 hex digits (or 32 bytes)") from None
    elif isinstance(pin, (bytes, bytearray)):
        p = bytes(pin)
    else:
        raise InterfaceError("a pin is the server key's SPKI SHA-256: 64 hex digits (or 32 bytes)")
    if len(p) != 32:
        raise InterfaceError("a pin is the server key's SPKI SHA-256: 64 hex digits (or 32 bytes)")
    return p


def connect_tcp(host, port, user, password, cafile=None, pin=None, timeout=None, connect_timeout=30.0,
                _cb_type=w.CB_ENDPOINT, _binding=None):
    """TCP with TLS 1.3, verified by a CA file or a pin, exactly one (no unverified mode, no fallback). The login binds
    the TLS session by tls-server-end-point (RFC 5929: the SHA-256 of the server certificate's DER), the binding Python's
    ssl module can compute: it has no TLS exporter (RFC 9266), so a server must run with --channel-binding any
    (section 8f). _cb_type and _binding are the tests' (a hello naming another type, a binding of other bytes)."""
    if (cafile is None) == (pin is None):
        raise InterfaceError("TLS: a CA file or a pin, exactly one (no unverified mode)")
    p = _pin_arg(pin) if pin is not None else None
    u, pw = _user_arg(user), _password_arg(password)
    if not isinstance(host, str) or not host:
        raise InterfaceError("a host, a port and TLS's CA file or pin")
    if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
        raise InterfaceError("a port is 1 to 65535")
    try:
        ctx = tls_context(None if cafile is None else cafile, p)
    except (OSError, ssl.SSLError) as e:
        raise InterfaceError("TLS: the CA file %s: %s" % (cafile, e)) from None
    deadline = time.monotonic() + connect_timeout
    try:
        sock = _socket.create_connection((host, port), timeout=connect_timeout)
    except OSError as e:
        raise OperationalError("connect %s port %d: %s" % (host, port, e.strerror or e)) from None
    try:
        sock.setsockopt(_socket.IPPROTO_TCP, _socket.TCP_NODELAY, 1)  # small frames never wait
        sock.setsockopt(_socket.SOL_SOCKET, _socket.SO_KEEPALIVE, 1)  # a server gone without a FIN found
        for opt, val in (("TCP_KEEPIDLE", 60), ("TCP_KEEPINTVL", 10), ("TCP_KEEPCNT", 6)):
            if hasattr(_socket, opt):
                sock.setsockopt(_socket.IPPROTO_TCP, getattr(_socket, opt), val)
        ssock = ctx.wrap_socket(sock, server_hostname=host, do_handshake_on_connect=False)
    except (OSError, ssl.SSLError) as e:
        sock.close()
        raise OperationalError("TLS: %s" % e) from None
    try:
        ssock.settimeout(max(0.001, deadline - time.monotonic()))
        ssock.do_handshake()
        if ssock.version() != "TLSv1.3":
            raise AuthenticationError("TLS: not 1.3")
        if ssock.selected_alpn_protocol() != ALPN:
            raise AuthenticationError("TLS: the peer does not speak %s (ALPN)" % ALPN)
        der = ssock.getpeercert(binary_form=True)
        if not der:
            raise AuthenticationError("TLS: the server sent no certificate")
        if p is not None:
            try:
                got = _x509.spki_pin(der)
            except _x509.CertError as e:
                raise AuthenticationError("TLS: the server's certificate: %s" % e) from None
            if not hmac.compare_digest(got, p):  # before the hello, which names the role, leaves
                raise AuthenticationError("TLS: the server's key is not the pinned one")
        if _binding is not None:
            binding = _binding
        else:
            try:
                binding = _x509.end_point(der)
            except _x509.CertError as e:
                raise AuthenticationError(str(e)) from None
        ssock.setblocking(False)
    except ssl.SSLCertVerificationError as e:
        ssock.close()
        raise AuthenticationError("TLS: the server's certificate: %s" % (e.verify_message or e)) from None
    except (ssl.SSLError, OSError) as e:
        ssock.close()
        if isinstance(e, _socket.timeout):
            raise OperationalError("TLS handshake: no answer within connect_timeout") from None
        raise OperationalError("TLS handshake: %s" % e) from None
    except Error:
        ssock.close()
        raise
    raw = RawConnection(_Tls(ssock), w.EP_TCP, timeout)
    raw._deadline = deadline
    try:
        raw._authenticate(_cb_type, binding, u, pw)
    finally:
        raw._deadline = None
    return raw
