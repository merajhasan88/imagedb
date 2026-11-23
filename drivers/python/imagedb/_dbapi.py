"""PEP 249 over the protocol's level: Connection and Cursor, a statement's whole reply read to its READY.

Transactions are the engine's: each statement commits on its own unless inside BEGIN ... COMMIT, and a DDL statement
refuses to run inside one ("CREATE TABLE commits on its own"), so the driver begins none of its own (a deviation from
PEP 249's "auto-commit initially off": autocommit is True and read-only). commit() and rollback() send COMMIT and
ROLLBACK when READY says a transaction is open (begun by the caller's BEGIN), and do nothing when it is idle.
"""

import codecs
import io
import itertools

from . import _native
from . import _wire as w
from ._errors import (Error, InterfaceError, NotSupportedError, OperationalError, ProgrammingError, Warning,
                      server_error)

_seq = itertools.count(1)
_MESSAGES_KEPT = 1000  # Connection.messages keeps the latest WARNINGs (PEP 249's extension; the caller may clear it)


class Result:
    """one statement's (or one parameter set's) answer: its columns (None when it returns no rows), its rows (tuples of
    Python values), and its DONE: the status, the count (rows returned or written), the read point and the write's
    commit; any WARNINGs it raised"""

    __slots__ = ("columns", "rows", "status", "rowcount", "read", "write", "warnings")

    def __init__(self, columns=None):
        self.columns = columns
        self.rows = [] if columns is not None else None
        self.status = None
        self.rowcount = -1
        self.read = None
        self.write = None
        self.warnings = []

    @property
    def description(self):
        if self.columns is None:
            return None
        return tuple((c.name, c.type, None, None, c.precision, c.scale, None) for c in self.columns)

    def __repr__(self):
        return "<Result %r rowcount=%d rows=%s>" % (self.status, self.rowcount,
                                                    None if self.rows is None else len(self.rows))


def _source_chunks(source):
    """COPY FROM's data: a file-like object's read() (bytes or str), or an iterable of bytes or str pieces"""
    if hasattr(source, "read"):
        while True:
            piece = source.read(w.COPY_PIECE)
            if not piece:
                return
            yield piece
    else:
        for piece in source:
            yield piece


class Connection:
    """a connection (imagedb.connect): PEP 249's methods, and the protocol's own requests (prepare, execute_prepared,
    deallocate, batch, cancel, ping, sessions, kill, copy_from, copy_to)"""

    def __init__(self, raw):
        self._raw = raw
        self.messages = []

    # ---- PEP 249 ----

    @property
    def autocommit(self):
        """always True: each statement commits on its own unless inside BEGIN ... COMMIT (the engine's model; a DDL
        statement refuses to run inside a transaction, so the driver opens none of its own)"""
        return True

    @autocommit.setter
    def autocommit(self, on):
        if not on:
            raise NotSupportedError("autocommit is the engine's model: a transaction is the caller's BEGIN ... COMMIT "
                                    "(a DDL statement refuses to run inside one), never the driver's")

    def close(self):
        """TERMINATE (an open transaction rolled back by the server), then the socket closed"""
        raw = self._raw
        if raw.broken is None:
            try:
                raw.send_terminate()
            except Error:
                pass
        raw.close()

    def commit(self):
        self._check()
        if self._raw.state != w.IDLE:
            self._run(lambda: self._raw.send_query(["COMMIT"]))

    def rollback(self):
        self._check()
        if self._raw.state != w.IDLE:
            self._run(lambda: self._raw.send_query(["ROLLBACK"]))

    def cursor(self):
        self._check()
        return Cursor(self)

    def execute(self, sql, params=()):
        """a cursor, the statement run on it (sqlite3's shortcut)"""
        return self.cursor().execute(sql, params)

    def __enter__(self):
        return self

    def __exit__(self, et, ev, tb):
        try:
            if self._raw.broken is None and self._raw.state == w.IN_TXN and et is None:
                self.commit()
        finally:
            self.close()

    @property
    def closed(self):
        return self._raw.broken is not None

    @property
    def transaction_state(self):
        """READY's last state: imagedb.IDLE, IN_TRANSACTION, or DOOMED (it takes only ROLLBACK)"""
        return self._raw.state

    @property
    def raw(self):
        """the protocol's level (imagedb.RawConnection): requests and replies one message at a time"""
        return self._raw

    # ---- the protocol's own requests ----

    def cancel(self):
        """cancel the statement this connection runs: from any thread (in band, over the connection's own stream; a
        cancel asked while nothing runs is dropped)"""
        self._raw.cancel()

    def ping(self):
        """PING, answered by PONG (the server's connection thread alone: no engine turn)"""
        self._check()
        self._raw.send_ping()
        self._await(w.PONG)

    def sessions(self):
        """SESSIONS: a superuser's every session, a role's its own role's: [imagedb.Session(id, role, endpoint (1 TCP, 2
        the socket), state (0 idle, 1 running, 2 in a transaction, 3 receiving a COPY's data), age_ms, name)]"""
        self._check()
        self._raw.send_sessions()
        return list(self._await(w.SESSIONS_LIST).sessions)

    def kill(self, session_id, terminate=False):
        """KILL a session by its id (from sessions()): cancel the request it runs (each of its statements starts
        cancelled until that request ends), or with terminate=True end the session (its transaction rolled back).
        True when done, False for no such session (another role's too)"""
        self._check()
        self._raw.send_kill(w.KILL_TERMINATE if terminate else w.KILL_CANCEL, session_id)
        m = self._await(w.KILL_DONE)
        if m.sid != session_id:
            raise self._raw._protocol("its session id is another than the KILL's", "a KILL_DONE frame")
        return m.code == w.KILLED

    def prepare(self, name, sql):
        """PREPARE: the statement parsed once under name (its parameters typed at each EXECUTE)"""
        self._check()
        self._run(lambda: self._raw.send_prepare(name, sql))

    def execute_prepared(self, name, param_sets):
        """EXECUTE of a prepared statement with several parameter sets (one EXECUTE a 4,096 sets or 16 MiB), in order:
        a Result each; an ERROR ends them (its index the set's, the results before it on the exception)"""
        self._check()
        results = []
        for data, start, n in self._raw.execute_frames(name, param_sets):
            try:
                results += self._run(lambda: self._raw.send_frame(data, w.EXECUTE))
            except Error as e:
                if e.index is not None and e.code is not None:
                    e.index += start
                e.results = results + e.results
                raise
        return results

    def deallocate(self, name):
        self._check()
        self._run(lambda: self._raw.send_deallocate(name))

    def batch(self, statements):
        """one QUERY of several statements, each sql or (sql, params), run in order: a Result each. Not a transaction:
        each commits on its own unless inside BEGIN ... COMMIT; an ERROR ends the batch (the statements after it do not
        run), raised with its index and the results before it (e.results)"""
        self._check()
        stmts = list(statements)
        return self._run(lambda: self._raw.send_query(stmts))

    def copy_from(self, sql, source):
        """COPY ... FROM STDIN with its data from source: a file-like object (read() of bytes or str) or an iterable of
        bytes or str pieces; the rows written. A source that raises fails the COPY (COPY_FAIL: nothing written), then
        its exception is raised"""
        self._check()
        r = self._run(lambda: self._raw.send_query([sql]), copy_source=source)
        return r[0].rowcount if r else -1

    def copy_to(self, sql, sink):
        """COPY ... TO STDOUT, its bytes to sink: a binary file-like object, a text one (UTF-8 decoded), or a callable
        taking bytes; the rows written out. On an ERROR the bytes already given are not the statement's whole answer"""
        self._check()
        if callable(sink) and not hasattr(sink, "write"):
            put = sink
        elif isinstance(sink, io.TextIOBase):
            dec = codecs.getincrementaldecoder("utf-8")()

            def put(b, _dec=dec, _w=sink.write):
                _w(_dec.decode(b))
        elif hasattr(sink, "write"):
            put = sink.write
        else:
            raise InterfaceError("copy_to's sink is a file-like object or a callable")
        r = self._run(lambda: self._raw.send_query([sql]), copy_sink=put)
        return r[0].rowcount if r else -1

    # ---- the reply loop ----

    def _check(self):
        if self._raw.broken is not None:
            raise InterfaceError("the connection is closed (%s)" % self._raw.broken, closed=True)

    def _await(self, t):
        while True:
            m = self._raw.next()
            if m.type == t:
                return m
            if m.type == w.ERROR:  # unasked: a KILL, a refused login's bound, a protocol error; the close follows
                continue
            raise self._raw._protocol("while no request ran", "a %s frame" % w.FRAME_NAMES[m.type])

    def _run(self, send, copy_source=None, copy_sink=None):
        """a request sent, its replies read to its READY: its Results, or its ERROR raised (e.results before it)"""
        send()
        raw = self._raw
        results, cur, warns, err, after = [], None, [], None, None
        while True:
            try:
                m = raw.next()
            except Error as e:
                e.results = results
                raise
            t = m.type
            if t == w.ROWS:
                to = _native.to_native
                cur.rows.extend([tuple([to(v) for v in row]) for row in m.rows])
            elif t == w.COLUMNS:
                cur = Result(list(m.columns.columns))
            elif t == w.DONE:
                r = cur if cur is not None else Result()
                r.status, r.rowcount, r.read, r.write = m.status, m.count, m.read, m.write
                r.warnings, warns = warns, []
                results.append(r)
                cur = None
            elif t == w.WARNING:
                warns.append(m.message)
                self.messages.append((Warning, m.message))
                if len(self.messages) > _MESSAGES_KEPT:
                    del self.messages[:-_MESSAGES_KEPT]
            elif t == w.ERROR:
                err = server_error(m.code, m.index, m.message)
                err.results = list(results)
                err.warnings, warns = warns, []
                cur = None
            elif t == w.COPY_IN:
                if copy_source is None:
                    raw.send_copy_fail("no data source: use Connection.copy_from()")
                    after = ProgrammingError("COPY ... FROM STDIN takes its data from Connection.copy_from()")
                else:
                    after = self._upload(copy_source) or after
            elif t == w.COPY_OUT:
                if copy_sink is None:
                    if after is None:
                        after = ProgrammingError("COPY ... TO STDOUT's data dropped: use Connection.copy_to()")
                else:
                    try:
                        copy_sink(m.data)
                    except Exception as e:  # noqa: BLE001 (the sink's own failure: the statement cancelled, then raised)
                        raw.cancel()
                        after = after or e
                        copy_sink = lambda b: None  # noqa: E731
            elif t == w.READY:
                break
            # PONG, SESSIONS_LIST, KILL_DONE: answers to requests a caller sent at the protocol's level; dropped here
        if after is not None:  # the caller's own cause first (no COPY source or sink, a source or sink that failed)
            if hasattr(after, "results"):
                after.results = results
            raise after from err
        if err is not None:
            raise err
        return results

    def _upload(self, source):
        """COPY's data after its COPY_IN: every piece, then COPY_DONE (the replies read after: section 4's order is the
        same either way); a cancel sent meanwhile ends the upload (the COPY refused unrun); a source that raises sends
        COPY_FAIL and its exception is returned, to be raised once the request's replies are read"""
        raw = self._raw
        before = raw.cancels_sent
        try:
            for piece in _source_chunks(source):
                if isinstance(piece, str):
                    piece = piece.encode("utf-8")
                elif not isinstance(piece, (bytes, bytearray, memoryview)):
                    raise TypeError("COPY's data is bytes or str, not %s" % type(piece).__name__)
                if piece:
                    raw.send_copy_data(piece)
                if raw.cancels_sent != before:  # cancelled while sending: the rest is not sent
                    break
        except Error:
            raise
        except Exception as e:  # noqa: BLE001 (the source's own failure)
            raw.send_copy_fail("the client's data source failed: %s: %s" % (type(e).__name__, e))
            return e
        raw.send_copy_done()
        return None

    def _temp_name(self):
        return "imdbpy_%d" % next(_seq)


class Cursor:
    """PEP 249's cursor: execute() runs one statement (a QUERY of one, its parameters $1 to $n as typed values, never
    spliced into its text) and reads its whole reply; fetch* read the rows it returned"""

    arraysize = 1

    def __init__(self, conn):
        self.connection = conn
        self._result = None
        self._pos = 0
        self.rowcount = -1
        self.messages = []
        self._closed = False

    @property
    def description(self):
        return self._result.description if self._result is not None else None

    @property
    def columns(self):
        """the result's columns as imagedb.Column (name, type, precision, scale, an ENUM's labels), or None"""
        return self._result.columns if self._result is not None else None

    @property
    def result(self):
        """the last statement's Result: its status, count, read point (the commit read, its hash, the state digest, the
        lake's commit, the database's id) and its write's commit"""
        return self._result

    lastrowid = None

    def _check(self):
        if self._closed:
            raise InterfaceError("the cursor is closed")
        self.connection._check()

    def _reset(self):
        self._result, self._pos, self.rowcount = None, 0, -1
        self.messages = []

    def execute(self, sql, params=()):
        self._check()
        self._reset()
        try:
            rs = self.connection._run(lambda: self.connection._raw.send_query([(sql, params)]))
        except Error as e:
            self.messages = [(Warning, x) for x in getattr(e, "warnings", [])]
            raise
        r = rs[0]
        self._result, self.rowcount = r, r.rowcount
        self.messages = [(Warning, x) for x in r.warnings]
        return self

    def executemany(self, sql, seq_of_params):
        """the statement prepared once and executed with each parameter set (EXECUTE: 4,096 sets or 16 MiB a request);
        an ERROR ends the run, its index the set's; rowcount the rows written in all"""
        self._check()
        self._reset()
        sets = list(seq_of_params)
        if not sets:
            self.rowcount = 0
            return self
        conn = self.connection
        name = conn._temp_name()
        conn.prepare(name, sql)
        total = 0
        try:
            for r in conn.execute_prepared(name, sets):
                total += max(r.rowcount, 0)
        finally:
            if conn._raw.broken is None:
                try:
                    conn.deallocate(name)
                except Error:
                    pass
        self.rowcount = total
        return self

    def fetchone(self):
        self._rows_check()
        if self._pos >= len(self._result.rows):
            return None
        row = self._result.rows[self._pos]
        self._pos += 1
        return row

    def fetchmany(self, size=None):
        self._rows_check()
        n = self.arraysize if size is None else size
        rows = self._result.rows[self._pos:self._pos + n]
        self._pos += len(rows)
        return rows

    def fetchall(self):
        self._rows_check()
        rows = self._result.rows[self._pos:]
        self._pos = len(self._result.rows)
        return rows

    def __iter__(self):
        while True:
            row = self.fetchone()
            if row is None:
                return
            yield row

    def _rows_check(self):
        if self._closed:
            raise InterfaceError("the cursor is closed")
        if self._result is None or self._result.rows is None:
            raise ProgrammingError("no result set: the last statement returned no rows")

    def close(self):
        self._closed = True
        self._result = None

    def setinputsizes(self, sizes):
        pass

    def setoutputsize(self, size, column=None):
        pass

    def callproc(self, procname, parameters=()):
        raise NotSupportedError("imagedb has no stored procedures")

    def nextset(self):
        return None

    def __enter__(self):
        return self

    def __exit__(self, et, ev, tb):
        self.close()


def connect(socket=None, host=None, port=None, user=None, password=None, cafile=None, pin=None, timeout=None,
            connect_timeout=30.0):
    """a connection to imagedb-server: over its Unix socket (socket=PATH) or over TCP with TLS 1.3 (host=, port=, and
    exactly one of cafile= (the private CA's certificate: the host checked against the server certificate's names) or
    pin= (the server key's SPKI SHA-256 that `imagedb-server cert` prints, 64 hex digits)). No unverified mode exists.
    user and password: a LOGIN role's (SCRAM-SHA-256; the server's signature checked). timeout bounds each wait for a
    reply (seconds; None: none)."""
    from . import _raw
    if (socket is None) == (host is None):
        raise InterfaceError("connect: a socket path, or a host and port, exactly one")
    if socket is not None:
        if cafile is not None or pin is not None or port is not None:
            raise InterfaceError("connect: the socket takes no TLS (cafile, pin) and no port")
        raw = _raw.connect_unix(socket, user, password, timeout=timeout, connect_timeout=connect_timeout)
    else:
        raw = _raw.connect_tcp(host, port, user, password, cafile=cafile, pin=pin, timeout=timeout,
                               connect_timeout=connect_timeout)
    return Connection(raw)
