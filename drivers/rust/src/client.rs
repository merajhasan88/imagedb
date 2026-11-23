//! The idiomatic client over the protocol's level: a request sent, its replies read to READY, each statement's result
//! gathered (or streamed, `query_each`), the server's ERROR returned with its code and index.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use crate::conn::{Canceller, Connection, TxnState};
use crate::error::{Error, Result, ServerError};
use crate::types::{FromValue, Value};
use crate::wire::{self, Columns, Done, Msg, SessionInfo, Statement};

/// Where a connection goes. Stage 1: the server's Unix-domain socket. Non-exhaustive: stage 2 adds TCP with TLS 1.3
/// (verified by a CA or a pin, never unverified), which this crate does not build yet.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub enum Endpoint {
    /// The server's Unix-domain socket (`imagedb-server --socket PATH`).
    Unix(PathBuf),
}

/// A connection's settings.
#[derive(Clone, Debug)]
pub struct Config {
    pub endpoint: Endpoint,
    pub user: String,
    /// The password's bytes (printable ASCII, 1 to 1,024 of them: as CREATE ROLE takes one).
    pub password: Vec<u8>,
    /// Each wait for a reply's bytes (None: none).
    pub read_timeout: Option<Duration>,
    /// The login's bound (30 s when None).
    pub connect_timeout: Option<Duration>,
}

impl Config {
    pub fn unix(path: impl AsRef<Path>, user: &str, password: &str) -> Config {
        Config {
            endpoint: Endpoint::Unix(path.as_ref().to_path_buf()),
            user: user.to_string(),
            password: password.as_bytes().to_vec(),
            read_timeout: None,
            connect_timeout: None,
        }
    }

    pub fn read_timeout(mut self, d: Option<Duration>) -> Config {
        self.read_timeout = d;
        self
    }
}

/// A row of a result: its values in column order, read by index or by name as Rust types.
#[derive(Clone, Debug, PartialEq)]
pub struct Row {
    cols: Arc<Columns>,
    values: Vec<Value>,
}

impl Row {
    pub fn columns(&self) -> &Columns {
        &self.cols
    }

    pub fn values(&self) -> &[Value] {
        &self.values
    }

    pub fn into_values(self) -> Vec<Value> {
        self.values
    }

    pub fn len(&self) -> usize {
        self.values.len()
    }

    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }

    pub fn value(&self, i: usize) -> &Value {
        &self.values[i]
    }

    /// The i-th value as T: exact (an INT64 as i64, a DECIMAL as Decimal, ...), a NULL only into an Option.
    pub fn get<T: FromValue>(&self, i: usize) -> Result<T> {
        let v = self.values.get(i).ok_or_else(|| Error::Invalid(format!("no column {i}")))?;
        T::from_value(v)
    }

    pub fn get_by_name<T: FromValue>(&self, name: &str) -> Result<T> {
        let i = self.cols.index_of(name).ok_or_else(|| Error::Invalid(format!("no column {name:?}")))?;
        T::from_value(&self.values[i])
    }
}

/// One statement's result: its columns (for a statement that returns rows: even none), its rows, any warnings, COPY
/// TO's bytes, and its DONE (the status, the count, the read point and its own commit).
#[derive(Clone, Debug)]
pub struct QueryResult {
    pub columns: Option<Arc<Columns>>,
    pub rows: Vec<Row>,
    pub warnings: Vec<String>,
    pub copy_data: Vec<u8>,
    pub done: Done,
}

/// A batch's results: each statement (or parameter set) that ran, in order, then the ERROR that ended the batch (its
/// index names the one that failed; the ones after it did not run), and the session's state after it.
#[derive(Clone, Debug)]
pub struct BatchResult {
    pub results: Vec<QueryResult>,
    pub error: Option<ServerError>,
    pub state: TxnState,
}

impl BatchResult {
    /// The results, or the batch's ERROR.
    pub fn into_result(self) -> Result<Vec<QueryResult>> {
        match self.error {
            Some(e) => Err(Error::Server(e)),
            None => Ok(self.results),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KillKind {
    /// The request the session runs now, has begun or runs next: each of its statements.
    Cancel,
    /// The session ended, its open transaction rolled back.
    Terminate,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KillOutcome {
    Done,
    /// No such session (or, to a role that is not a superuser, another role's).
    NoSuchSession,
}

/// A client: one connection, one request at a time (the protocol's level, `connection()`, pipelines).
pub struct Client {
    conn: Connection,
}

#[derive(Default)]
struct Acc {
    columns: Option<Arc<Columns>>,
    rows: Vec<Row>,
    warnings: Vec<String>,
    copy: Vec<u8>,
}

/// What a request's reader does with rows and COPY TO's bytes.
enum Sink<'a> {
    Collect,
    Each(&'a mut dyn FnMut(Row) -> Result<()>),
    Copy(&'a mut dyn Write),
}

impl Client {
    /// Connects and logs in (SCRAM-SHA-256; the server's signature checked).
    pub fn connect(cfg: &Config) -> Result<Client> {
        let conn = match &cfg.endpoint {
            Endpoint::Unix(path) => Connection::connect_unix(path, &cfg.user, &cfg.password, cfg.connect_timeout)?,
        };
        let mut c = Client { conn };
        c.conn.set_read_timeout(cfg.read_timeout)?;
        Ok(c)
    }

    /// Over the server's Unix-domain socket.
    pub fn connect_unix(path: impl AsRef<Path>, user: &str, password: &str) -> Result<Client> {
        Client::connect(&Config::unix(path, user, password))
    }

    /// The protocol's level underneath (pipelining, raw replies).
    pub fn connection(&mut self) -> &mut Connection {
        &mut self.conn
    }

    pub fn canceller(&self) -> Canceller {
        self.conn.canceller()
    }

    pub fn state(&self) -> TxnState {
        self.conn.state()
    }

    pub fn set_read_timeout(&mut self, d: Option<Duration>) -> Result<()> {
        self.conn.set_read_timeout(d)
    }

    /// One statement with its parameters ($1 to $k), its whole result.
    pub fn query(&mut self, sql: &str, params: &[Value]) -> Result<QueryResult> {
        let mut b = self.batch(&[Statement { sql: sql.to_string(), params: params.to_vec() }])?;
        match b.error {
            Some(e) => Err(Error::Server(e)),
            None => b.results.pop().ok_or_else(|| Error::Unexpected("a statement answered with no DONE".into())),
        }
    }

    /// One statement; the rows it returned or wrote (DONE's count).
    pub fn execute(&mut self, sql: &str, params: &[Value]) -> Result<u64> {
        Ok(self.query(sql, params)?.done.count)
    }

    /// One statement, each row handed to `f` as it arrives (memory: a frame's bytes, never the whole result). An
    /// error from `f` cancels the statement; the replies are still read to READY.
    pub fn query_each(&mut self, sql: &str, params: &[Value], mut f: impl FnMut(Row) -> Result<()>) -> Result<Done> {
        self.conn.send(&Msg::Query(vec![Statement { sql: sql.to_string(), params: params.to_vec() }]))?;
        let mut b = self.read_request(Sink::Each(&mut f))?;
        match b.error {
            Some(e) => Err(Error::Server(e)),
            None => b.results.pop().map(|r| r.done).ok_or_else(|| Error::Unexpected("no DONE".into())),
        }
    }

    /// Several statements as one batch: they run in order, an ERROR ends the batch (its index names the statement).
    /// Each commits on its own unless inside BEGIN ... COMMIT.
    pub fn batch(&mut self, stmts: &[Statement]) -> Result<BatchResult> {
        self.conn.send(&Msg::Query(stmts.to_vec()))?;
        self.read_request(Sink::Collect)
    }

    /// PREPARE: the statement parsed once by the server under `name` (its parameters typed at each EXECUTE).
    pub fn prepare(&mut self, name: &str, sql: &str) -> Result<()> {
        self.conn.send(&Msg::Prepare { name: name.to_string(), sql: sql.to_string() })?;
        self.read_request(Sink::Collect)?.into_result().map(|_| ())
    }

    /// EXECUTE: the prepared statement run once a parameter set, in order; an ERROR ends the sets (its index names
    /// the set).
    pub fn execute_prepared(&mut self, name: &str, sets: &[Vec<Value>]) -> Result<BatchResult> {
        let nvals = sets.first().map_or(0, |s| s.len());
        if sets.iter().any(|s| s.len() != nvals) {
            return Err(Error::Invalid("every parameter set has the same count of values".into()));
        }
        if nvals > wire::VALUES_MAX || sets.len() > wire::BATCH_MAX as usize {
            return Err(Error::Invalid("an EXECUTE of 1 to 4,096 sets of at most 256 values".into()));
        }
        let values: Vec<Value> = sets.iter().flatten().cloned().collect();
        self.conn.send(&Msg::Execute { name: name.to_string(), sets: sets.len() as u32, nvals: nvals as u16, values })?;
        self.read_request(Sink::Collect)
    }

    pub fn deallocate(&mut self, name: &str) -> Result<()> {
        self.conn.send(&Msg::Deallocate { name: name.to_string() })?;
        self.read_request(Sink::Collect)?.into_result().map(|_| ())
    }

    /// PING: answered by the server's connection thread alone (PONG).
    pub fn ping(&mut self) -> Result<()> {
        self.conn.send(&Msg::Ping)?;
        match self.conn.next()? {
            Msg::Pong => Ok(()),
            m => Err(self.unexpected("PONG", &m)),
        }
    }

    /// SESSIONS: a superuser's every session, a role's its own role's (answered out of turn, as PING).
    pub fn sessions(&mut self) -> Result<Vec<SessionInfo>> {
        self.conn.send(&Msg::Sessions)?;
        match self.conn.next()? {
            Msg::SessionsList(v) => Ok(v),
            m => Err(self.unexpected("SESSIONS_LIST", &m)),
        }
    }

    /// KILL a session by its id (from `sessions`): cancel what it runs, or terminate it.
    pub fn kill(&mut self, session: u64, kind: KillKind) -> Result<KillOutcome> {
        let k = match kind {
            KillKind::Cancel => wire::KILL_CANCEL,
            KillKind::Terminate => wire::KILL_TERMINATE,
        };
        self.conn.send(&Msg::Kill { kind: k, session })?;
        match self.conn.next()? {
            Msg::KillDone { code, session: s } if s == session => {
                Ok(if code == 0 { KillOutcome::Done } else { KillOutcome::NoSuchSession })
            }
            m => Err(self.unexpected("KILL_DONE for that session", &m)),
        }
    }

    /// COPY ... FROM STDIN: the statement sent, then `data` in COPY_DATA frames of at most 1 MiB after its COPY_IN, then
    /// COPY_DONE; the statement's DONE. A failed read of `data` sends COPY_FAIL (the statement refused unrun) and returns
    /// that read's error. A statement refused before its data (no COPY_IN) returns its ERROR, no data sent.
    pub fn copy_in(&mut self, sql: &str, data: &mut dyn Read) -> Result<Done> {
        self.conn.send(&Msg::Query(vec![Statement { sql: sql.to_string(), params: vec![] }]))?;
        let mut err: Option<ServerError> = None;
        loop {
            match self.next_in_request(&err)? {
                Msg::CopyIn => break,
                Msg::Error(e) => err = Some(e),
                Msg::Ready(_) => {
                    return Err(match err {
                        Some(e) => Error::Server(e),
                        None => Error::Unexpected("not a COPY ... FROM STDIN: no COPY_IN".into()),
                    });
                }
                Msg::Columns(_) | Msg::Rows(_) | Msg::Done(_) | Msg::Warning(_) | Msg::CopyOut(_) => {}
                m => return Err(self.unexpected("COPY_IN", &m)),
            }
        }
        let mut buf = vec![0u8; wire::COPY_PIECE];
        let mut read_err: Option<std::io::Error> = None;
        loop {
            match data.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => self.conn.send(&Msg::CopyData(buf[..n].to_vec()))?,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                Err(e) => {
                    read_err = Some(e);
                    break;
                }
            }
        }
        match &read_err {
            None => self.conn.send(&Msg::CopyDone)?,
            Some(e) => {
                let why = format!("the client's data: {e}");
                let n = wire::utf8_fit(why.as_bytes(), wire::MESSAGE_MAX);
                self.conn.send(&Msg::CopyFail(String::from_utf8_lossy(&why.as_bytes()[..n]).into_owned()))?
            }
        }
        let mut b = self.read_request(Sink::Collect)?;
        if let Some(e) = read_err {
            return Err(Error::Io(e));
        }
        match b.error {
            Some(e) => Err(Error::Server(e)),
            None => b.results.pop().map(|r| r.done).ok_or_else(|| Error::Unexpected("no DONE".into())),
        }
    }

    /// COPY ... TO STDOUT: its bytes written to `out` as they arrive; its DONE. A failed write to `out` cancels the
    /// statement and returns that write's error once the replies are read.
    pub fn copy_out(&mut self, sql: &str, out: &mut dyn Write) -> Result<Done> {
        self.conn.send(&Msg::Query(vec![Statement { sql: sql.to_string(), params: vec![] }]))?;
        let mut b = self.read_request(Sink::Copy(out))?;
        match b.error {
            Some(e) => Err(Error::Server(e)),
            None => b.results.pop().map(|r| r.done).ok_or_else(|| Error::Unexpected("no DONE".into())),
        }
    }

    /// TERMINATE: the server ends the session (an open transaction rolled back); the connection is closed.
    pub fn terminate(mut self) -> Result<()> {
        self.conn.send(&Msg::Terminate)?;
        self.conn.close();
        Ok(())
    }

    fn unexpected(&mut self, want: &str, m: &Msg) -> Error {
        let e = Error::Unexpected(format!("expected {want}, the server sent frame type {}", m.frame_type()));
        self.conn.close();
        e
    }

    /// The next reply of a request whose ERROR may already be read: a close then reports that ERROR (§4: an ERROR
    /// followed by the close, no READY).
    fn next_in_request(&mut self, err: &Option<ServerError>) -> Result<Msg> {
        match self.conn.next() {
            Ok(m) => Ok(m),
            // the close after the request's ERROR: that ERROR is the reason (an engine's code, 1 to 64, as client.c:143
            // bounds a reason), else the plain I/O error
            Err(Error::Io(e)) => match err {
                Some(se) if se.code <= 64 => Err(Error::Closed(se.clone())),
                _ => Err(Error::Io(e)),
            },
            Err(e) => Err(e),
        }
    }

    /// A request's replies to its READY.
    fn read_request(&mut self, mut sink: Sink) -> Result<BatchResult> {
        let mut results = Vec::new();
        let mut acc = Acc::default();
        let mut error: Option<ServerError> = None;
        let mut sink_err: Option<Error> = None;
        loop {
            match self.next_in_request(&error)? {
                Msg::Columns(c) => {
                    acc = Acc::default();
                    acc.columns = Some(c);
                }
                Msg::Rows(r) => {
                    let cols = r.columns().clone();
                    for values in r.iter() {
                        let row = Row { cols: cols.clone(), values };
                        match &mut sink {
                            Sink::Each(f) if sink_err.is_none() => {
                                if let Err(e) = f(row) {
                                    sink_err = Some(e);
                                    self.conn.canceller().cancel();
                                }
                            }
                            Sink::Each(_) => {}
                            _ => acc.rows.push(row),
                        }
                    }
                }
                Msg::Warning(w) => acc.warnings.push(w),
                Msg::CopyOut(d) => match &mut sink {
                    Sink::Copy(w) if sink_err.is_none() => {
                        if let Err(e) = w.write_all(&d) {
                            sink_err = Some(Error::Io(e));
                            self.conn.canceller().cancel();
                        }
                    }
                    Sink::Copy(_) => {}
                    _ => acc.copy.extend_from_slice(&d),
                },
                Msg::CopyIn => {
                    // a COPY ... FROM STDIN outside copy_in: it has no data, so it is failed (never left waiting)
                    self.conn.send(&Msg::CopyFail("no data: COPY ... FROM STDIN goes through Client::copy_in".into()))?;
                }
                Msg::Done(d) => {
                    let a = std::mem::take(&mut acc);
                    results.push(QueryResult { columns: a.columns, rows: a.rows, warnings: a.warnings, copy_data: a.copy, done: d });
                }
                Msg::Error(e) => {
                    acc = Acc::default(); // rows before an ERROR are not the statement's answer
                    error = Some(e);
                }
                Msg::Ready(_) => break,
                m => return Err(self.unexpected("a statement's replies", &m)),
            }
        }
        if let Some(e) = sink_err {
            return Err(e);
        }
        Ok(BatchResult { results, error, state: self.conn.state() })
    }
}
