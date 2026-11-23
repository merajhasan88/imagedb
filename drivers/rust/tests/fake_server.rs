//! The client against a scripted server on a Unix socket (under IMDB_TEST_ROOT, else this crate's tmp/), for what the
//! real server never sends: a frame the decoder refuses (it ends the connection, naming it), a server signature that
//! is not the verifier's, an ERROR and then the close with no READY, a later protocol version, a ROWS without COLUMNS.
mod common;

use std::io::{Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;

use imagedb::crypto::hmac::{hmac_sha256, pbkdf2_sha256};
use imagedb::crypto::sha256::sha256;
use imagedb::wire::{self, Challenge, Hello, Msg, Verdict};
use imagedb::*;

fn sock_path(name: &str) -> PathBuf {
    let root = std::env::var("IMDB_TEST_ROOT").unwrap_or_else(|_| format!("{}/tmp", env!("CARGO_MANIFEST_DIR")));
    std::fs::create_dir_all(&root).unwrap();
    // short: a socket path stays under 100 bytes beneath the run directory
    let p = PathBuf::from(root).join(format!("{}-{name}.sock", std::process::id() % 100_000));
    let _ = std::fs::remove_file(&p);
    p
}

const PW: &[u8] = b"pencil";

/// The server's side of §4's exchange; `sig_ok` false sends a signature that is not the verifier's.
fn serve_login(s: &mut UnixStream, sig_ok: bool) {
    let mut hb = [0u8; wire::HELLO_LEN];
    s.read_exact(&mut hb).unwrap();
    let h = Hello::decode(&hb).unwrap();
    assert_eq!(h.flags, wire::CB_NONE);
    let c = Challenge { version: 1, salt: vec![3; 16], iterations: 4096, nonce: [2; 32] };
    let cb = c.encode().unwrap();
    s.write_all(&cb).unwrap();
    let mut proof = [0u8; 32];
    s.read_exact(&mut proof).unwrap();
    let am = wire::auth_message(wire::EP_UNIX, &hb, &cb, &[0; 32]);
    let mut sp = [0u8; 32];
    pbkdf2_sha256(PW, &c.salt, c.iterations, &mut sp);
    let stored = sha256(&hmac_sha256(&sp, b"Client Key"));
    let cs = hmac_sha256(&stored, &am);
    let ck: Vec<u8> = proof.iter().zip(cs.iter()).map(|(a, b)| a ^ b).collect();
    let ok = sha256(&ck) == stored;
    let mut sig = hmac_sha256(&hmac_sha256(&sp, b"Server Key"), &am);
    if !sig_ok {
        sig[0] ^= 1;
    }
    let v = if ok { Verdict { code: 0, sig } } else { Verdict { code: 1, sig: [0; 32] } };
    s.write_all(&v.encode().unwrap()).unwrap();
}

fn read_frame(s: &mut UnixStream) -> Option<(u8, Vec<u8>)> {
    let mut head = [0u8; 5];
    s.read_exact(&mut head).ok()?;
    let (len, ty) = wire::head_get(&head, false).unwrap();
    let mut body = vec![0u8; len as usize - 1];
    s.read_exact(&mut body).ok()?;
    Some((ty, body))
}

/// A server that logs the client in, then plays `script` with each request it reads.
fn fake(name: &str, sig_ok: bool, script: impl FnOnce(&mut UnixStream) + Send + 'static) -> (PathBuf, std::thread::JoinHandle<()>) {
    let p = sock_path(name);
    let l = UnixListener::bind(&p).unwrap();
    let gone = p.clone();
    let t = std::thread::spawn(move || {
        let (mut s, _) = l.accept().unwrap();
        let _ = std::fs::remove_file(&gone); // the socket file's job is done once connected
        serve_login(&mut s, sig_ok);
        script(&mut s);
    });
    (p, t)
}

fn frame(m: &Msg) -> Vec<u8> {
    m.encode().unwrap()
}

#[test]
fn login_against_the_pinned_exchange_server() {
    let (p, t) = fake("ok", true, |s| {
        let (ty, _) = read_frame(s).unwrap();
        assert_eq!(ty, wire::PING);
        s.write_all(&frame(&Msg::Pong)).unwrap();
    });
    let mut c = Client::connect_unix(&p, "alice", "pencil").unwrap();
    c.ping().unwrap();
    t.join().unwrap();
    // a wrong password: the server's verdict 1
    let (p, t) = fake("wrong", true, |_| {});
    let e = Client::connect_unix(&p, "alice", "pencim").err().unwrap();
    assert!(matches!(&e, Error::Auth(m) if m == "authentication refused"), "{e}");
    t.join().unwrap();
}

#[test]
fn a_server_signature_not_the_verifiers_is_refused() {
    let (p, t) = fake("sig", false, |_| {});
    let e = Client::connect_unix(&p, "alice", "pencil").err().unwrap();
    assert!(matches!(&e, Error::Auth(m) if m.contains("did not prove")), "{e}");
    t.join().unwrap();
}

#[test]
fn a_later_version_is_refused_by_name() {
    let p = sock_path("later");
    let l = UnixListener::bind(&p).unwrap();
    let gone = p.clone();
    let t = std::thread::spawn(move || {
        let (mut s, _) = l.accept().unwrap();
        let _ = std::fs::remove_file(&gone); // the socket file's job is done once connected
        let mut hb = [0u8; wire::HELLO_LEN];
        s.read_exact(&mut hb).unwrap();
        // a server of version 2 only answers with its own head and closes
        s.write_all(b"IMDBWIR1\x02\0\0\0").unwrap();
    });
    let e = Client::connect_unix(&p, "alice", "pencil").err().unwrap();
    assert!(matches!(&e, Error::Unsupported(m) if m.contains("version 2")), "{e}");
    t.join().unwrap();
    let p = sock_path("magic");
    let l = UnixListener::bind(&p).unwrap();
    let gone = p.clone();
    let t = std::thread::spawn(move || {
        let (mut s, _) = l.accept().unwrap();
        let _ = std::fs::remove_file(&gone); // the socket file's job is done once connected
        let mut hb = [0u8; wire::HELLO_LEN];
        s.read_exact(&mut hb).unwrap();
        s.write_all(b"IMDBWIR2\x01\0\0\0").unwrap();
    });
    let e = Client::connect_unix(&p, "alice", "pencil").err().unwrap();
    assert!(matches!(&e, Error::Unsupported(m) if m.contains("IMDBWIR2")), "{e}");
    t.join().unwrap();
}

#[test]
fn a_refused_frame_ends_the_connection_naming_it() {
    let (p, t) = fake("bad", true, |s| {
        read_frame(s).unwrap();
        // READY with a state no version defines
        s.write_all(&[2, 0, 0, 0, wire::READY, 3]).unwrap();
        let _ = read_frame(s); // nothing more comes: the client closed
    });
    let mut c = Client::connect_unix(&p, "alice", "pencil").unwrap();
    let e = c.query("SELECT 1", &[]).unwrap_err();
    assert!(matches!(&e, Error::Protocol { message, .. } if message.contains("a READY frame refused: a READY's state")), "{e}");
    let again = c.query("SELECT 1", &[]).unwrap_err();
    assert!(again.to_string().contains("unusable") && again.to_string().contains("READY's state"), "{again}");
    drop(c);
    t.join().unwrap();
}

#[test]
fn rows_need_their_statements_columns() {
    let cols = std::sync::Arc::new(Columns::new(vec![Column::new("x", Type::Int64, 0, 0)]).unwrap());
    let rows = wire::Rows::new(cols.clone(), &[vec![Value::Int64(5)]]).unwrap();
    let (p, t) = fake("rows", true, move |s| {
        read_frame(s).unwrap();
        s.write_all(&frame(&Msg::Columns(cols.clone()))).unwrap();
        s.write_all(&frame(&Msg::Rows(rows.clone()))).unwrap();
        s.write_all(&frame(&Msg::Done(Done { status: "SELECT 1".into(), count: 1, read: None, write: None }))).unwrap();
        // a ROWS after its statement's DONE: no COLUMNS of its own
        s.write_all(&frame(&Msg::Rows(rows.clone()))).unwrap();
        let _ = read_frame(s);
    });
    let mut c = Client::connect_unix(&p, "alice", "pencil").unwrap();
    let e = c.query("SELECT 5", &[]).unwrap_err();
    assert!(matches!(&e, Error::Protocol { message, .. } if message.contains("no COLUMNS")), "{e}");
    drop(c);
    t.join().unwrap();
}

#[test]
fn an_error_then_the_close_is_the_reason() {
    // a login answered, then refused for a bound: ERROR 3 unasked, then the close (no READY)
    let (p, t) = fake("closed", true, |s| {
        s.write_all(&frame(&Msg::Error(ServerError { code: 3, index: 0, message: "too many connections for this role".into() }))).unwrap();
        s.flush().unwrap();
        let _ = s.shutdown(std::net::Shutdown::Write);
        let _ = read_frame(s); // the lingering close: read what the client sends, then close
    });
    let mut c = Client::connect_unix(&p, "alice", "pencil").unwrap();
    let e = c.query("SELECT 1", &[]).unwrap_err();
    assert!(matches!(&e, Error::Server(se) | Error::Closed(se) if se.code == 3 && se.message.contains("too many")), "{e}");
    t.join().unwrap();
    // the failed send's path: the server gone whole, its last frame an ERROR
    let (p, t) = fake("closed2", true, |s| {
        s.write_all(&frame(&Msg::Error(ServerError { code: 15, index: 0, message: "ended by a KILL".into() }))).unwrap();
    });
    let mut c = Client::connect_unix(&p, "alice", "pencil").unwrap();
    t.join().unwrap(); // the server's socket is closed now
    std::thread::sleep(std::time::Duration::from_millis(100));
    let e = c.query("SELECT 1", &[]).unwrap_err();
    assert!(matches!(&e, Error::Closed(se) if se.code == 15), "{e:?}");
    // ... and when the last frame is READY, the plain I/O error
    let (p, t) = fake("closed3", true, |s| {
        s.write_all(&frame(&Msg::Error(ServerError { code: 4, index: 0, message: "an earlier statement's".into() }))).unwrap();
        s.write_all(&frame(&Msg::Ready(0))).unwrap();
    });
    let mut c = Client::connect_unix(&p, "alice", "pencil").unwrap();
    t.join().unwrap();
    std::thread::sleep(std::time::Duration::from_millis(100));
    let e = c.connection().send(&Msg::Ping).err();
    let e = match e {
        Some(e) => e,
        None => loop {
            match c.connection().next() {
                Ok(_) => {}
                Err(e) => break e,
            }
        },
    };
    assert!(matches!(e, Error::Io(_)), "{e:?}");
    // ... and when the last frame is an ERROR of a code past 64 (not an engine's: client.c:143 gives no reason then),
    // the plain I/O error on the failed send's path and on the read's alike
    let (p, t) = fake("closed4", true, |s| {
        s.write_all(&frame(&Msg::Error(ServerError { code: 65, index: 0, message: "not an engine's code".into() }))).unwrap();
    });
    let mut c = Client::connect_unix(&p, "alice", "pencil").unwrap();
    t.join().unwrap();
    std::thread::sleep(std::time::Duration::from_millis(100));
    let e = c.query("SELECT 1", &[]).unwrap_err();
    assert!(matches!(e, Error::Io(_)), "{e:?}");
}

#[test]
fn a_cancel_with_nothing_outstanding_is_never_sent() {
    let (p, t) = fake("cancel", true, |s| {
        // the first frame the server reads is the QUERY: no CANCEL before it
        let (ty, _) = read_frame(s).unwrap();
        assert_eq!(ty, wire::QUERY, "a CANCEL asked with nothing outstanding was sent");
        s.write_all(&frame(&Msg::Done(Done { status: "".into(), count: 0, read: None, write: None }))).unwrap();
        s.write_all(&frame(&Msg::Ready(0))).unwrap();
        // during the next request: the CANCEL arrives
        let (ty, _) = read_frame(s).unwrap();
        assert_eq!(ty, wire::QUERY);
        let (ty, _) = read_frame(s).unwrap();
        assert_eq!(ty, wire::CANCEL);
        s.write_all(&frame(&Msg::Error(ServerError { code: 15, index: 0, message: "canceled".into() }))).unwrap();
        s.write_all(&frame(&Msg::Ready(0))).unwrap();
    });
    let mut c = Client::connect_unix(&p, "alice", "pencil").unwrap();
    c.canceller().cancel(); // nothing outstanding: dropped
    c.query("BEGIN", &[]).unwrap();
    let k = c.canceller();
    let th = std::thread::spawn(move || {
        std::thread::sleep(std::time::Duration::from_millis(200));
        k.cancel();
    });
    let e = c.query("SELECT pg_sleep_forever()", &[]).unwrap_err();
    assert_eq!(e.code(), 15);
    th.join().unwrap();
    t.join().unwrap();
}
