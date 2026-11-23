"""PEP 249's exceptions, and the server's ERROR codes (docs/n1-design.md section 4: the engine's IMDB_ERR_*, stable) to
them. Every error the server sent carries its code, its statement's (or parameter set's) index in its batch and its
words; one the driver made has code None."""


class Warning(Exception):  # noqa: A001 (PEP 249's name)
    pass


class Error(Exception):
    def __init__(self, message, code=None, index=None, closed=False):
        super().__init__(message)
        self.message = message
        self.code = code        # the server's ERROR code (1 or more), None for the driver's own errors
        self.index = index      # the failed statement's index in its batch (a QUERY's or an EXECUTE's sets)
        self.closed = closed    # the connection is gone (the server closed it, or the driver did)
        self.results = []       # a batch's: the results of the statements before the one that failed


class InterfaceError(Error):
    pass


class ProtocolError(InterfaceError):
    """the server sent bytes IMDBWIR1 refuses (a frame this driver's strict decoder does not take, or one out of its
    place): the connection is closed"""


class DatabaseError(Error):
    pass


class DataError(DatabaseError):
    pass


class OperationalError(DatabaseError):
    pass


class IntegrityError(DatabaseError):
    pass


class InternalError(DatabaseError):
    pass


class ProgrammingError(DatabaseError):
    pass


class NotSupportedError(DatabaseError):
    pass


class AuthenticationError(OperationalError):
    """a login refused (SCRAM's verdict, the server's signature, the TLS peer's certificate or pin)"""


class SerializationError(OperationalError):
    """code 14: a conflict; retry the transaction"""


class QueryCanceledError(OperationalError):
    """code 15: cancelled or timed out (nothing the statement did stays); a KILL's terminate too"""


class InsufficientPrivilege(ProgrammingError):
    """code 16: a privilege the role lacks"""


CODE_NAMES = {
    1: "I/O", 2: "damaged bytes", 3: "a limit", 4: "invalid input", 5: "out of memory", 6: "a constraint",
    7: "a verification", 8: "an authentication", 9: "a state", 10: "a syntax error", 11: "not found",
    12: "unsupported", 13: "history purged", 14: "a conflict", 15: "cancelled", 16: "a privilege",
}

_CODE_CLASS = {
    1: OperationalError, 2: InternalError, 3: OperationalError, 4: DataError, 5: OperationalError, 6: IntegrityError,
    7: InternalError, 8: AuthenticationError, 9: OperationalError, 10: ProgrammingError, 11: ProgrammingError,
    12: NotSupportedError, 13: OperationalError, 14: SerializationError, 15: QueryCanceledError,
    16: InsufficientPrivilege,
}


def server_error(code, index, message, closed=False, prefix=""):
    """the exception for a server's ERROR (a code a later imagedb adds: DatabaseError, an error of no class)"""
    cls = _CODE_CLASS.get(code, DatabaseError)
    return cls(prefix + message, code=code, index=index, closed=closed)
