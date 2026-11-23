"""imagedb's Python driver: its own protocol, IMDBWIR1 (docs/n1-design.md section 4), standard library alone.

    import imagedb
    conn = imagedb.connect(socket="/path/to/sock", user="admin", password="...")
    conn = imagedb.connect(host="127.0.0.1", port=7432, pin="<the SPKI SHA-256 `imagedb-server cert` prints>",
                           user="admin", password="...")
    cur = conn.cursor()
    cur.execute("SELECT id, d FROM t WHERE id = $1", [7])
    cur.fetchall()

PEP 249 (DB-API 2.0), paramstyle "numeric" with the engine's own placeholders $1 to $n (the values travel typed, never
spliced into the text). Values both ways: INT64 int, FLOAT64 float (bit for bit), BOOL bool, TEXT str, DECIMAL
decimal.Decimal (exact to 38 digits), TIMESTAMP naive datetime, TIMESTAMPTZ aware datetime (UTC), DATE date, TIME time,
UUID uuid.UUID, BYTEA bytes, INTERVAL imagedb.Interval(months, days, microseconds) (a timedelta goes out as one), ENUM
str (a label goes out as TEXT); NULL None (imagedb.Null(type) for a NULL of a type). The protocol's level underneath:
Connection.raw, imagedb.RawConnection.
"""

import datetime as _dt
import time as _time

from . import _wire as wire
from ._dbapi import Connection, Cursor, Result, connect
from ._errors import (AuthenticationError, DatabaseError, DataError, Error, InsufficientPrivilege, IntegrityError,
                      InterfaceError, InternalError, NotSupportedError, OperationalError, ProgrammingError,
                      ProtocolError, QueryCanceledError, SerializationError, Warning)
from ._native import Interval, Null
from ._raw import RawConnection, connect_tcp, connect_unix
from ._wire import Column, ReadPoint, Session, WriteCommit

apilevel = "2.0"
threadsafety = 1  # threads may share the module, not a connection (Connection.cancel() alone is any thread's)
paramstyle = "numeric"  # the engine's $1 .. $n

# wire types: a column's type_code in Cursor.description, a NULL's type (Null(T_TEXT))
T_NONE, T_INT64, T_FLOAT64, T_BOOL, T_TEXT, T_DECIMAL, T_TIMESTAMP, T_TIMESTAMPTZ, T_DATE, T_TIME, T_UUID, T_BYTEA, \
    T_INTERVAL, T_ENUM = range(14)

# READY's states (Connection.transaction_state)
IDLE, IN_TRANSACTION, DOOMED = 0, 1, 2
# a session's endpoint and state in Connection.sessions()
ENDPOINT_TCP, ENDPOINT_SOCKET = 1, 2
SESSION_IDLE, SESSION_RUNNING, SESSION_IN_TRANSACTION, SESSION_COPY = 0, 1, 2, 3


class _DBAPIType(frozenset):
    """PEP 249's type objects: equal to each wire type they group"""

    def __eq__(self, other):
        if isinstance(other, int):
            return other in self
        return frozenset.__eq__(self, other)

    def __ne__(self, other):
        return not self.__eq__(other)

    __hash__ = frozenset.__hash__


STRING = _DBAPIType({T_TEXT, T_ENUM})
BINARY = _DBAPIType({T_BYTEA})
NUMBER = _DBAPIType({T_INT64, T_FLOAT64, T_DECIMAL})
DATETIME = _DBAPIType({T_TIMESTAMP, T_TIMESTAMPTZ, T_DATE, T_TIME, T_INTERVAL})
ROWID = _DBAPIType()

Date = _dt.date
Time = _dt.time
Timestamp = _dt.datetime
Binary = bytes


def DateFromTicks(ticks):
    return Date(*_time.localtime(ticks)[:3])


def TimeFromTicks(ticks):
    return Time(*_time.localtime(ticks)[3:6])


def TimestampFromTicks(ticks):
    return Timestamp(*_time.localtime(ticks)[:6])


__all__ = [
    "apilevel", "threadsafety", "paramstyle", "connect", "Connection", "Cursor", "Result", "RawConnection",
    "connect_unix", "connect_tcp", "Interval", "Null", "Column", "ReadPoint", "WriteCommit", "Session", "Warning",
    "Error", "InterfaceError", "DatabaseError", "DataError", "OperationalError", "IntegrityError", "InternalError",
    "ProgrammingError", "NotSupportedError", "ProtocolError", "AuthenticationError", "SerializationError",
    "QueryCanceledError", "InsufficientPrivilege", "STRING", "BINARY", "NUMBER", "DATETIME", "ROWID", "Date", "Time",
    "Timestamp", "Binary", "DateFromTicks", "TimeFromTicks", "TimestampFromTicks", "IDLE", "IN_TRANSACTION", "DOOMED",
    "wire",
] + ["T_" + n for n in ("NONE", "INT64", "FLOAT64", "BOOL", "TEXT", "DECIMAL", "TIMESTAMP", "TIMESTAMPTZ", "DATE",
                        "TIME", "UUID", "BYTEA", "INTERVAL", "ENUM")]
