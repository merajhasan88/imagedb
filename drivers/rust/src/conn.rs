//! The protocol's level (docs/n1-design.md §4): a connection authenticated by SCRAM-SHA-256, requests sent whole and
//! replies read one frame at a time, strictly. Requests may pipeline. A `Canceller` from any thread sends CANCEL in
//! band; the read and write halves are separate, so it never waits for a blocked read.
//!
//! The transport seam: everything above the bytes goes through `ReadHalf` and `WriteHalf`, and the login through
//! `authenticate(endpoint, binding type, binding)`. Stage 1 has the Unix socket alone (endpoint 2, binding type 0,
//! zeros). Stage 2 (TCP with TLS 1.3: not built here) adds a transport implementing the two halves and calls
//! `authenticate` with endpoint 1 and the exporter's or the certificate's 32 bytes, then `Connection::new`; nothing
//! else changes.

use std::io::{self, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, TryLockError};
use std::time::Duration;

use crate::crypto::{ct_eq, random, wipe};
use crate::error::{Error, Result, ServerError};
use crate::wire::{self, Challenge, Columns, Hello, Msg, Verdict};

/// A transport's read half (the Unix socket's; stage 2: TLS's).
pub(crate) trait ReadHalf: Send {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize>;
    fn set_read_timeout(&mut self, d: Option<Duration>) -> io::Result<()>;
}

/// A transport's write half: whole writes, and a close (the socket shut; stage 2: TLS's close_notify first). It is
/// used from the reading thread and from a `Canceller`'s, under one lock.
pub(crate) trait WriteHalf: Send {
    fn write_all(&mut self, buf: &[u8]) -> io::Result<()>;
    fn close(&mut self);
}

impl ReadHalf for UnixStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        Read::read(self, buf)
    }
    fn set_read_timeout(&mut self, d: Option<Duration>) -> io::Result<()> {
        UnixStream::set_read_timeout(self, d)
    }
}

impl WriteHalf for UnixStream {
    fn write_all(&mut self, buf: &[u8]) -> io::Result<()> {
        Write::write_all(self, buf)
    }
    fn close(&mut self) {
        let _ = self.shutdown(std::net::Shutdown::Both);
    }
}

pub(crate) fn read_exact(r: &mut dyn ReadHalf, mut buf: &mut [u8]) -> io::Result<()> {
    while !buf.is_empty() {
        match r.read(buf) {
            Ok(0) => return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "closed by the server")),
            Ok(n) => buf = &mut buf[n..],
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

struct WState {
    out: Box<dyn WriteHalf>,
    /// requests sent whose READY has not been read: a cancel reaches only one of them (one asked with none outstanding
    /// is dropped, so a late CANCEL never cancels the next request: §4)
    outstanding: u32,
    closed: bool,
}

struct Shared {
    w: Mutex<WState>,
    /// a cancel asked and not yet sent or dropped: whoever holds the write lock next acts on it, so an upload's frames
    /// never starve it (std's Mutex is not fair)
    cancel: AtomicBool,
}

impl Shared {
    fn lock(&self) -> MutexGuard<'_, WState> {
        self.w.lock().unwrap_or_else(|e| e.into_inner())
    }
}

fn cancel_frame() -> [u8; 5] {
    [1, 0, 0, 0, wire::CANCEL]
}

/// Cancels the statement its connection runs now (§4: CANCEL, in band), from any thread. Cheap to clone.
#[derive(Clone)]
pub struct Canceller {
    shared: Arc<Shared>,
}

impl Canceller {
    /// Sends CANCEL when a request of this connection is outstanding; dropped when none is (it would otherwise cancel
    /// the next request's statement). A cancel asked while the connection sends (a COPY's data) goes out before its
    /// next frame. Never waits for a blocked read.
    pub fn cancel(&self) {
        let s = &self.shared;
        s.cancel.store(true, Ordering::SeqCst);
        loop {
            if !s.cancel.load(Ordering::SeqCst) {
                return; // a sender sent it before its frame, or dropped it with nothing outstanding
            }
            match s.w.try_lock() {
                Ok(mut w) => {
                    if s.cancel.swap(false, Ordering::SeqCst) && w.outstanding > 0 && !w.closed {
                        let _ = w.out.write_all(&cancel_frame());
                    }
                    return;
                }
                Err(TryLockError::WouldBlock) => std::thread::sleep(Duration::from_millis(1)),
                Err(TryLockError::Poisoned(_)) => return,
            }
        }
    }
}

/// The transaction state READY reports.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TxnState {
    Idle,
    InTransaction,
    /// A doomed transaction: it takes only ROLLBACK.
    Doomed,
}

impl TxnState {
    fn of(s: u8) -> TxnState {
        match s {
            0 => TxnState::Idle,
            1 => TxnState::InTransaction,
            _ => TxnState::Doomed,
        }
    }
}

/// The random value a login chose (public: it travels in the hello), from the operating system (crypto::random).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct LoginInfo {
    pub scram_nonce: [u8; 32],
}

/// An authenticated connection at the protocol's level.
pub struct Connection {
    info: LoginInfo,
    rd: Box<dyn ReadHalf>,
    shared: Arc<Shared>,
    /// the COLUMNS of the statement whose replies are being read (a ROWS is held to it; cleared at its DONE or ERROR)
    cols: Option<Arc<Columns>>,
    /// the first error that made the connection unusable
    broken: Option<String>,
    timeout: Option<Duration>,
    state: TxnState,
}

fn is_request(m: &Msg) -> bool {
    matches!(m, Msg::Query(_) | Msg::Prepare { .. } | Msg::Execute { .. } | Msg::Deallocate { .. })
}

/// What a login needs: the role's name and the password's bytes (printable ASCII, as CREATE ROLE takes one).
pub(crate) struct Login<'a> {
    pub user: &'a str,
    pub password: &'a [u8],
}

impl Connection {
    /// Over the server's Unix-domain socket (no TLS: the endpoint is the file system's; binding type none).
    pub fn connect_unix(path: &Path, user: &str, password: &[u8], timeout: Option<Duration>) -> Result<Connection> {
        check_login(user, password)?;
        let s = UnixStream::connect(path)?;
        let w = s.try_clone()?;
        let mut rd: Box<dyn ReadHalf> = Box::new(s);
        let mut wr: Box<dyn WriteHalf> = Box::new(w);
        rd.set_read_timeout(Some(timeout.unwrap_or(Duration::from_secs(30))))?;
        let nonce = authenticate(&mut *rd, &mut *wr, wire::EP_UNIX, wire::CB_NONE, &[0; 32], &Login { user, password })?;
        rd.set_read_timeout(timeout)?;
        Ok(Connection::new(rd, wr, timeout, nonce))
    }

    /// A connection over an authenticated transport (the seam a TCP-with-TLS transport joins at).
    pub(crate) fn new(
        rd: Box<dyn ReadHalf>,
        wr: Box<dyn WriteHalf>,
        timeout: Option<Duration>,
        scram_nonce: [u8; 32],
    ) -> Connection {
        Connection {
            rd,
            shared: Arc::new(Shared {
                w: Mutex::new(WState { out: wr, outstanding: 0, closed: false }),
                cancel: AtomicBool::new(false),
            }),
            cols: None,
            broken: None,
            timeout,
            state: TxnState::Idle,
            info: LoginInfo { scram_nonce },
        }
    }

    /// The login's random value (the SCRAM client nonce).
    pub fn login_info(&self) -> LoginInfo {
        self.info
    }

    /// A handle that cancels this connection's running statement from any thread.
    pub fn canceller(&self) -> Canceller {
        Canceller { shared: self.shared.clone() }
    }

    /// The transaction state the last READY reported.
    pub fn state(&self) -> TxnState {
        self.state
    }

    /// Requests sent whose READY has not been read.
    pub fn outstanding(&self) -> u32 {
        self.shared.lock().outstanding
    }

    /// A bound on each wait for a reply's bytes (None: none): past it `next` fails and the connection is unusable
    /// (a frame may be part read).
    pub fn set_read_timeout(&mut self, d: Option<Duration>) -> Result<()> {
        self.timeout = d;
        self.rd.set_read_timeout(d)?;
        Ok(())
    }

    fn check(&self) -> Result<()> {
        match &self.broken {
            Some(why) => Err(Error::Io(io::Error::new(io::ErrorKind::NotConnected, format!("unusable after an earlier error ({why})")))),
            None => Ok(()),
        }
    }

    /// A message sent whole (its bytes encoded first: nothing is sent for one its encoder refuses). A send that finds
    /// the connection closed reports the server's last ERROR when it is the last frame before the close (§4).
    pub fn send(&mut self, m: &Msg) -> Result<()> {
        self.check()?;
        let bytes = m.encode()?;
        self.send_bytes(&bytes, is_request(m))
    }

    /// Bytes sent as they are (tests: crafted frames).
    pub fn send_raw(&mut self, bytes: &[u8]) -> Result<()> {
        self.check()?;
        self.send_bytes(bytes, false)
    }

    fn send_bytes(&mut self, bytes: &[u8], req: bool) -> Result<()> {
        let r = {
            let mut w = self.shared.lock();
            if w.closed {
                return Err(Error::Io(io::Error::new(io::ErrorKind::NotConnected, "the connection is closed")));
            }
            let mut r = Ok(());
            if req && w.outstanding == 0 {
                self.shared.cancel.store(false, Ordering::SeqCst); // asked while nothing ran: for nothing
            } else if w.outstanding > 0 && self.shared.cancel.swap(false, Ordering::SeqCst) {
                r = w.out.write_all(&cancel_frame()); // before the next frame, never after the whole upload
            }
            if r.is_ok() {
                r = w.out.write_all(bytes);
            }
            if r.is_ok() && req {
                w.outstanding += 1;
            }
            r
        };
        match r {
            Ok(()) => Ok(()),
            Err(e) => {
                let err = self.closed_reason(e);
                self.broken = Some(err.to_string());
                Err(err)
            }
        }
    }

    /// §4's closed_reason (client.c): what the server sent before its close is read (1 s at most, 64 frames); when its
    /// very last frame is an ERROR, that is the reason reported, else the send's own I/O error.
    fn closed_reason(&mut self, e: io::Error) -> Error {
        let _ = self.rd.set_read_timeout(Some(Duration::from_secs(1)));
        let mut last: Option<ServerError> = None;
        let mut ended = false;
        for _ in 0..64 {
            match self.read_frame() {
                Ok(Msg::Error(se)) => last = Some(se),
                Ok(_) => last = None, // an ERROR before another frame answered that frame's request
                Err(_) => {
                    ended = true;
                    break;
                }
            }
        }
        let _ = self.rd.set_read_timeout(self.timeout);
        match last {
            // client.c:143: a reason only for a code of 1 to 64 (an engine's code); any failed read is the end (:133)
            Some(se) if ended && se.code <= 64 => Error::Closed(se),
            _ => Error::Io(e),
        }
    }

    fn read_frame(&mut self) -> Result<Msg> {
        let mut head = [0u8; wire::HEAD];
        read_exact(&mut *self.rd, &mut head)?;
        let (len, ty) = wire::head_get(&head, true)?;
        let mut body = vec![0u8; len as usize - 1];
        read_exact(&mut *self.rd, &mut body)?;
        let m = Msg::decode(ty, &body, if ty == wire::ROWS { self.cols.as_ref() } else { None }).map_err(|e| match e {
            // the refusal names its frame: "a DONE frame refused: a body with bytes past its end"
            Error::Protocol { limit, message } => {
                Error::Protocol { limit, message: format!("a {} frame refused: {message}", wire::frame_name(ty)) }
            }
            e => e,
        })?;
        match &m {
            Msg::Columns(c) => self.cols = Some(c.clone()),
            Msg::Done(_) | Msg::Error(_) => self.cols = None,
            Msg::Ready(s) => {
                self.cols = None;
                self.state = TxnState::of(*s);
                let mut w = self.shared.lock();
                w.outstanding = w.outstanding.saturating_sub(1);
            }
            _ => {}
        }
        Ok(m)
    }

    /// The next reply, decoded strictly (a ROWS against its statement's COLUMNS). A frame the decoder refuses, or a
    /// failed read, ends the connection: every later call fails with it.
    pub fn next(&mut self) -> Result<Msg> {
        self.check()?;
        match self.read_frame() {
            Ok(m) => Ok(m),
            Err(e) => {
                self.broken = Some(e.to_string());
                Err(e)
            }
        }
    }

    /// Closes the connection (an open transaction is rolled back by the server).
    pub fn close(&mut self) {
        let mut w = self.shared.lock();
        if !w.closed {
            w.closed = true;
            w.out.close();
        }
    }
}

impl Drop for Connection {
    fn drop(&mut self) {
        self.close();
    }
}

fn check_login(user: &str, password: &[u8]) -> Result<()> {
    if !wire::user_ok(user.as_bytes()) {
        return Err(Error::Invalid("a role's name is 1 to 63 bytes of UTF-8".into()));
    }
    if !wire::password_ok(password) {
        return Err(Error::Invalid("a password is 1 to 1,024 printable ASCII bytes".into()));
    }
    Ok(())
}

/// The pre-auth exchange (§4): the hello (its flags the binding's type), the challenge, the proof over the AuthMessage,
/// the verdict and the server's signature, compared in constant time. A verdict 2 (the binding type refused) is never
/// retried with another type: no downgrade (§8f).
pub(crate) fn authenticate(
    rd: &mut dyn ReadHalf,
    wr: &mut dyn WriteHalf,
    endpoint: u8,
    flags: u32,
    binding: &[u8; 32],
    login: &Login,
) -> Result<[u8; 32]> {
    check_login(login.user, login.password)?;
    let mut nonce = [0u8; 32];
    random(&mut nonce)?;
    let hello = Hello { version: wire::VERSION, flags, user: login.user.to_string(), nonce }.encode()?;
    wr.write_all(&hello)?;
    let mut ch = [0u8; wire::CHALLENGE_LEN];
    read_exact(rd, &mut ch[..wire::PREAUTH_HEAD])?;
    let version = wire::preauth_head(ch[..wire::PREAUTH_HEAD].try_into().unwrap())?;
    if version != wire::VERSION {
        return Err(Error::Unsupported(format!("the server speaks IMDBWIR1 version {version}, not 1")));
    }
    read_exact(rd, &mut ch[wire::PREAUTH_HEAD..])?;
    let c = Challenge::decode(&ch)?;
    let am = wire::auth_message(endpoint, &hello, &ch, binding);
    let (mut proof, mut want) = wire::scram_client(login.password, &c, &am)?;
    let sent = wr.write_all(&proof);
    wipe(&mut proof);
    if let Err(e) = sent {
        wipe(&mut want);
        return Err(e.into());
    }
    let mut vb = [0u8; wire::VERDICT_LEN];
    let got = read_exact(rd, &mut vb);
    let r = got.map_err(Error::from).and_then(|_| Verdict::decode(&vb)).and_then(|v| {
        if v.code == wire::VERDICT_BINDING {
            Err(Error::Auth("the server refuses this login's channel binding type".into()))
        } else if v.code != wire::VERDICT_OK {
            Err(Error::Auth("authentication refused".into()))
        } else if !ct_eq(&v.sig, &want) {
            Err(Error::Auth("the server did not prove it holds the verifier".into()))
        } else {
            Ok(())
        }
    });
    wipe(&mut want);
    r.map(|()| nonce)
}
