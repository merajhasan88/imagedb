//! The driver's errors. A server's ERROR keeps its code (the engine's, §4: stable), its index in its batch and its words.

use std::fmt;

/// An ERROR frame: the engine's code (1 or more), the failed statement's (or parameter set's) index in its batch, and
/// its message (the engine's, never a row value).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServerError {
    pub code: u32,
    pub index: u32,
    pub message: String,
}

/// §4's codes, by name; a later imagedb may add codes, read as `Other` (an error of no class).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ErrorCode {
    Io,
    Corrupt,
    Limit,
    Invalid,
    OutOfMemory,
    Constraint,
    Verification,
    Authentication,
    State,
    Syntax,
    NotFound,
    Unsupported,
    HistoryPurged,
    Conflict,
    Cancelled,
    Privilege,
    Other(u32),
}

impl ServerError {
    pub fn kind(&self) -> ErrorCode {
        match self.code {
            1 => ErrorCode::Io,
            2 => ErrorCode::Corrupt,
            3 => ErrorCode::Limit,
            4 => ErrorCode::Invalid,
            5 => ErrorCode::OutOfMemory,
            6 => ErrorCode::Constraint,
            7 => ErrorCode::Verification,
            8 => ErrorCode::Authentication,
            9 => ErrorCode::State,
            10 => ErrorCode::Syntax,
            11 => ErrorCode::NotFound,
            12 => ErrorCode::Unsupported,
            13 => ErrorCode::HistoryPurged,
            14 => ErrorCode::Conflict,
            15 => ErrorCode::Cancelled,
            16 => ErrorCode::Privilege,
            n => ErrorCode::Other(n),
        }
    }
}

impl fmt::Display for ServerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} (code {}, statement {})", self.message, self.code, self.index)
    }
}

/// Every way a call fails. Non-exhaustive: stage 2 (TCP with TLS 1.3) adds its own variant.
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// The server's ERROR in reply to a request.
    Server(ServerError),
    /// The server closed the connection, its last frame before the close this ERROR (§4's closed_reason: a login
    /// refused for a bound, a KILL, a protocol error).
    Closed(ServerError),
    /// The connection's I/O: a failed read or write, or the server's close with no ERROR last.
    Io(std::io::Error),
    /// Bytes this driver's decoder refuses (a frame, a pre-auth message): the connection is unusable after it.
    /// `limit` marks a length or count past its bound (the engine's code 3), else damage (code 2).
    Protocol { limit: bool, message: String },
    /// A later protocol (another magic, a later version), refused by name.
    Unsupported(String),
    /// Authentication: refused (an unknown name and a wrong password alike), the channel binding's type refused by the
    /// server (never retried with another: no downgrade), or the server's signature not the verifier's.
    Auth(String),
    /// A value or a request this driver's encoder refuses: nothing was sent.
    Invalid(String),
    /// A reply the API did not expect at this point (the connection is then unusable).
    Unexpected(String),
}

impl Error {
    pub(crate) fn corrupt(m: impl Into<String>) -> Error {
        Error::Protocol { limit: false, message: m.into() }
    }

    pub(crate) fn limit(m: impl Into<String>) -> Error {
        Error::Protocol { limit: true, message: m.into() }
    }

    /// The server's ERROR, from a reply or the close's reason.
    pub fn server(&self) -> Option<&ServerError> {
        match self {
            Error::Server(e) | Error::Closed(e) => Some(e),
            _ => None,
        }
    }

    /// The engine's code this error carries: a server's, or the code the C reference gives the same refusal.
    pub fn code(&self) -> u32 {
        match self {
            Error::Server(e) | Error::Closed(e) => e.code,
            Error::Io(_) => 1,
            Error::Protocol { limit: true, .. } => 3,
            Error::Protocol { limit: false, .. } => 2,
            Error::Invalid(_) => 4,
            Error::Auth(_) => 8,
            Error::Unexpected(_) => 9,
            Error::Unsupported(_) => 12,
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Server(e) => write!(f, "{e}"),
            Error::Closed(e) => write!(f, "the server closed the connection: {}", e.message),
            Error::Io(e) => write!(f, "the connection: {e}"),
            Error::Protocol { message, .. } => write!(f, "wire: {message}"),
            Error::Unsupported(m) => write!(f, "{m}"),
            Error::Auth(m) => write!(f, "authentication: {m}"),
            Error::Invalid(m) => write!(f, "{m}"),
            Error::Unexpected(m) => write!(f, "{m}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Error {
        Error::Io(e)
    }
}

pub type Result<T> = std::result::Result<T, Error>;
