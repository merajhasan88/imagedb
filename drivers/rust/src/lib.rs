//! imagedb's driver for its own protocol, IMDBWIR1 (docs/n1-design.md §4), in Rust's standard library alone: its
//! SHA-256, HMAC, PBKDF2 and SCRAM-SHA-256 are this crate's own code (the user's decision: no crates).
//!
//! Stage 1: the server's Unix-domain socket. TCP with TLS 1.3 is stage 2, with its own review, and is not built here
//! (`Endpoint` has the socket alone; the transport seam is `conn`'s two halves and its `authenticate`).
//!
//! ```no_run
//! use imagedb::{Client, Value};
//! let mut c = Client::connect_unix("/run/imagedb/s", "admin", "secret")?;
//! let r = c.query("SELECT $1 + 1", &[Value::Int64(41)])?;
//! let n: i64 = r.rows[0].get(0)?;
//! assert_eq!(n, 42);
//! # Ok::<(), imagedb::Error>(())
//! ```

pub mod client;
pub mod conn;
pub mod crypto;
pub mod error;
pub mod types;
pub mod wire;

pub use client::{BatchResult, Client, Config, Endpoint, KillKind, KillOutcome, QueryResult, Row};
pub use conn::{Canceller, Connection, LoginInfo, TxnState};
pub use error::{Error, ErrorCode, Result, ServerError};
pub use types::{Date, Decimal, FromValue, Interval, SqlType, Time, Timestamp, TimestampTz, Type, Uuid, Value};
pub use wire::{Column, Columns, Done, Msg, ReadPoint, SessionInfo, Statement, WriteCommit};
