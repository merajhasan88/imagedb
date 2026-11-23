//! IMDBWIR1's bytes (docs/n1-design.md §4; the C reference server/wire.c). Every decoder is strict: exact lengths, no
//! trailing bytes, zero padding, every count bounded by the bytes left before it sizes anything. Each field has one
//! predicate that its decoder and its encoder both apply, so an encoder never writes what its decoder refuses and any
//! bytes a decoder takes encode back to themselves. Both directions are here (the client's frames decode too), so the
//! codec is tested whole against the C reference's vectors.

use std::collections::HashSet;
use std::sync::Arc;

use crate::crypto::scram;
use crate::error::{Error, Result, ServerError};
use crate::types::*;

pub const MAGIC: &[u8; 8] = b"IMDBWIR1";
pub const VERSION: u32 = 1;
pub const USER: usize = 64;
pub const NONCE: usize = 32;
pub const SALT: usize = 64;
pub const KEY: usize = 32;
pub const PREAUTH_HEAD: usize = 12;
pub const HELLO_LEN: usize = 112;
pub const CHALLENGE_LEN: usize = 120;
pub const PROOF_LEN: usize = 32;
pub const VERDICT_LEN: usize = 36;
pub const AUTHMSG_LEN: usize = 279;
pub const HEAD: usize = 5;
pub const FRAME_MAX: u32 = 16 << 20;
pub const BATCH_MAX: u32 = 4096;
pub const VALUES_MAX: usize = 256;
pub const NAME_MAX: usize = 63;
pub const COLNAME_MAX: usize = 70;
pub const SQL_MAX: usize = 1 << 22;
pub const VALUE_MAX: usize = 65535;
pub const LABEL_MAX: usize = 63;
pub const LABELS_MAX: usize = 1024;
pub const STATUS_MAX: usize = 511;
pub const MESSAGE_MAX: usize = 4096;
pub const SCRAM_ITER_MIN: u32 = 1000;
pub const SCRAM_ITER_MAX: u32 = 1_000_000;
pub const SCRAM_SALT_MIN: usize = 8;
pub const PW_MAX: usize = 1024;
pub const SESSIONS_MAX: u32 = 65536;
/// COPY_DATA's pieces: the C client cuts at 1 MiB (client.c imdbc_copy_data), §4 bounds a frame alone.
pub const COPY_PIECE: usize = 1 << 20;

pub const EP_TCP: u8 = 1;
pub const EP_UNIX: u8 = 2;
pub const CB_NONE: u32 = 0;
pub const CB_EXPORTER: u32 = 1;
pub const CB_ENDPOINT: u32 = 2;
pub const VERDICT_OK: u32 = 0;
pub const VERDICT_REFUSED: u32 = 1;
pub const VERDICT_BINDING: u32 = 2;

pub const QUERY: u8 = 1;
pub const PREPARE: u8 = 2;
pub const EXECUTE: u8 = 3;
pub const DEALLOCATE: u8 = 4;
pub const COPY_DATA: u8 = 5;
pub const COPY_DONE: u8 = 6;
pub const COPY_FAIL: u8 = 7;
pub const CANCEL: u8 = 8;
pub const PING: u8 = 9;
pub const TERMINATE: u8 = 10;
pub const SESSIONS: u8 = 11;
pub const KILL: u8 = 12;
pub const COLUMNS: u8 = 64;
pub const ROWS: u8 = 65;
pub const DONE: u8 = 66;
pub const ERROR: u8 = 67;
pub const WARNING: u8 = 68;
pub const COPY_IN: u8 = 69;
pub const COPY_OUT: u8 = 70;
pub const READY: u8 = 71;
pub const PONG: u8 = 72;
pub const SESSIONS_LIST: u8 = 73;
pub const KILL_DONE: u8 = 74;

pub const KILL_CANCEL: u8 = 1;
pub const KILL_TERMINATE: u8 = 2;
pub const NULL_TAG: u8 = 0x80;

// ---- a bounded reader with a sticky error (the engine's imdb_rd): a read past the end yields zeros and sets err ----

pub(crate) struct Rd<'a> {
    b: &'a [u8],
    off: usize,
    err: bool,
}

impl<'a> Rd<'a> {
    pub(crate) fn new(b: &'a [u8]) -> Self {
        Rd { b, off: 0, err: false }
    }

    pub(crate) fn left(&self) -> usize {
        self.b.len() - self.off
    }

    pub(crate) fn bytes(&mut self, n: usize) -> Option<&'a [u8]> {
        if self.err || n > self.left() {
            self.err = true;
            return None;
        }
        let s = &self.b[self.off..self.off + n];
        self.off += n;
        Some(s)
    }

    fn arr<const N: usize>(&mut self) -> [u8; N] {
        match self.bytes(N) {
            Some(s) => s.try_into().unwrap(),
            None => [0; N],
        }
    }

    pub(crate) fn u8(&mut self) -> u8 {
        self.arr::<1>()[0]
    }

    pub(crate) fn u16(&mut self) -> u16 {
        u16::from_le_bytes(self.arr())
    }

    pub(crate) fn u32(&mut self) -> u32 {
        u32::from_le_bytes(self.arr())
    }

    pub(crate) fn u64(&mut self) -> u64 {
        u64::from_le_bytes(self.arr())
    }
}

/// The engine's UTF-8 rule (codec.c's imdb_utf8_valid, the C codec's utf8_valid): well-formed UTF-8 (no overlong form,
/// no surrogate, nothing past U+10FFFF: Rust's own rule) and no NUL.
pub fn utf8_ok(b: &[u8]) -> bool {
    !b.contains(&0) && std::str::from_utf8(b).is_ok()
}

/// The longest prefix of s, at most max bytes, that is UTF-8 without NUL: never cut inside a character (wire.c's
/// imdbw_utf8_fit).
pub fn utf8_fit(s: &[u8], max: usize) -> usize {
    let k = s.len().min(max);
    let s = &s[..k];
    let nul = s.iter().position(|&c| c == 0).unwrap_or(k);
    match std::str::from_utf8(&s[..nul]) {
        Ok(_) => nul,
        Err(e) => e.valid_up_to(),
    }
}

/// "IMDBWIR" and a digit past 1: a later protocol (util.c's imdb_later_magic for "IMDBWIR1").
fn later_magic(m: &[u8]) -> bool {
    m.len() == 8 && &m[..7] == b"IMDBWIR" && m[7] > b'1' && m[7] <= b'9'
}

fn magic_err(m: &[u8]) -> Error {
    if later_magic(m) {
        Error::Unsupported(format!(
            "wire: {}, a later protocol, which this driver does not speak",
            String::from_utf8_lossy(m)
        ))
    } else {
        Error::corrupt("not imagedb's protocol")
    }
}

// ---- before authentication ----

/// The head every pre-auth message begins with, in every version: any version read (a server answers a later client
/// with its own head and a close); another magic damage, a later magic by name, version 0 damage.
pub fn preauth_head(b: &[u8; PREAUTH_HEAD]) -> Result<u32> {
    if &b[..8] != MAGIC {
        return Err(magic_err(&b[..8]));
    }
    let v = u32::from_le_bytes(b[8..12].try_into().unwrap());
    if v < 1 {
        return Err(Error::corrupt("protocol version 0"));
    }
    Ok(v)
}

fn magic_version(r: &mut Rd) -> Result<u32> {
    let m = r.bytes(8);
    let v = r.u32();
    match m {
        Some(m) if m == MAGIC => {}
        Some(m) => return Err(magic_err(m)),
        None => return Err(Error::corrupt("not imagedb's protocol")),
    }
    if v > VERSION {
        return Err(Error::Unsupported(format!(
            "wire: protocol version {v}, a later one, which this driver (version {VERSION}) does not speak"
        )));
    }
    if v != VERSION {
        return Err(Error::corrupt("an unknown protocol version"));
    }
    Ok(v)
}

/// A role's name in a hello: 1 to 63 bytes of UTF-8 without NUL.
pub fn user_ok(user: &[u8]) -> bool {
    !user.is_empty() && user.len() < USER && utf8_ok(user)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Hello {
    pub version: u32,
    /// §8f: the channel binding's type (0 none, the socket's; 1 the TLS exporter; 2 tls-server-end-point).
    pub flags: u32,
    pub user: String,
    pub nonce: [u8; NONCE],
}

impl Hello {
    pub fn encode(&self) -> Result<[u8; HELLO_LEN]> {
        if self.version != VERSION || self.flags > CB_ENDPOINT || !user_ok(self.user.as_bytes()) {
            return Err(Error::Invalid("a hello its decoder would refuse".into()));
        }
        let mut out = [0u8; HELLO_LEN];
        out[..8].copy_from_slice(MAGIC);
        out[8..12].copy_from_slice(&self.version.to_le_bytes());
        out[12..16].copy_from_slice(&self.flags.to_le_bytes());
        out[16..16 + self.user.len()].copy_from_slice(self.user.as_bytes());
        out[16 + USER..].copy_from_slice(&self.nonce);
        Ok(out)
    }

    pub fn decode(b: &[u8; HELLO_LEN]) -> Result<Hello> {
        let mut r = Rd::new(b);
        let version = magic_version(&mut r)?;
        let flags = r.u32();
        let u = r.bytes(USER).unwrap();
        let nonce = r.arr::<NONCE>();
        if flags > CB_ENDPOINT {
            return Err(Error::corrupt("a hello with flags no version defines (a binding type but 0, 1, 2)"));
        }
        let n = u.iter().position(|&c| c == 0).unwrap_or(USER);
        if n == USER || !user_ok(&u[..n]) || u[n..].iter().any(|&c| c != 0) {
            return Err(Error::corrupt("a hello's role name is not 1 to 63 bytes of UTF-8, NUL-padded"));
        }
        Ok(Hello { version, flags, user: String::from_utf8(u[..n].to_vec()).unwrap(), nonce })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Challenge {
    pub version: u32,
    /// 8 to 64 bytes (a verifier's).
    pub salt: Vec<u8>,
    /// 1,000 to 1,000,000.
    pub iterations: u32,
    pub nonce: [u8; NONCE],
}

impl Challenge {
    fn ok(&self) -> bool {
        self.version == VERSION
            && (SCRAM_SALT_MIN..=SALT).contains(&self.salt.len())
            && (SCRAM_ITER_MIN..=SCRAM_ITER_MAX).contains(&self.iterations)
    }

    pub fn encode(&self) -> Result<[u8; CHALLENGE_LEN]> {
        if !self.ok() {
            return Err(Error::Invalid("a challenge its decoder would refuse".into()));
        }
        let mut out = [0u8; CHALLENGE_LEN];
        out[..8].copy_from_slice(MAGIC);
        out[8..12].copy_from_slice(&self.version.to_le_bytes());
        out[12] = self.salt.len() as u8;
        out[13..13 + self.salt.len()].copy_from_slice(&self.salt);
        out[13 + SALT..17 + SALT].copy_from_slice(&self.iterations.to_le_bytes());
        out[17 + SALT..17 + SALT + NONCE].copy_from_slice(&self.nonce);
        Ok(out) // then 7 zeros
    }

    pub fn decode(b: &[u8; CHALLENGE_LEN]) -> Result<Challenge> {
        let mut r = Rd::new(b);
        let version = magic_version(&mut r)?;
        let salt_len = r.u8() as usize;
        let salt = r.bytes(SALT).unwrap();
        let iterations = r.u32();
        let nonce = r.arr::<NONCE>();
        let pad = r.bytes(7).unwrap();
        let c = Challenge { version, salt: salt[..salt_len.min(SALT)].to_vec(), iterations, nonce };
        if !c.ok() || salt_len > SALT || salt[salt_len..].iter().any(|&x| x != 0) {
            return Err(Error::corrupt(
                "a challenge's salt is not 8 to 64 bytes, zero-padded, or its iterations not 1,000 to 1,000,000",
            ));
        }
        if pad.iter().any(|&x| x != 0) {
            return Err(Error::corrupt("a challenge's padding is not zero"));
        }
        Ok(c)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Verdict {
    /// 0 accepted, 1 refused, 2 the hello's binding type refused by this server.
    pub code: u32,
    /// The server's signature; zeros unless accepted.
    pub sig: [u8; KEY],
}

impl Verdict {
    fn ok(&self) -> bool {
        self.code == VERDICT_OK || ((self.code == VERDICT_REFUSED || self.code == VERDICT_BINDING) && self.sig == [0; KEY])
    }

    pub fn encode(&self) -> Result<[u8; VERDICT_LEN]> {
        if !self.ok() {
            return Err(Error::Invalid("a verdict its decoder would refuse".into()));
        }
        let mut out = [0u8; VERDICT_LEN];
        out[..4].copy_from_slice(&self.code.to_le_bytes());
        out[4..].copy_from_slice(&self.sig);
        Ok(out)
    }

    pub fn decode(b: &[u8; VERDICT_LEN]) -> Result<Verdict> {
        let v = Verdict { code: u32::from_le_bytes(b[..4].try_into().unwrap()), sig: b[4..].try_into().unwrap() };
        if !v.ok() {
            return Err(Error::corrupt("a verdict neither accepted nor refused, or a refusal carrying a signature"));
        }
        Ok(v)
    }
}

/// The AuthMessage (279 bytes): "IMDBWIR1-SCRAM" | u8 endpoint | the hello's 112 bytes | the challenge's 120 |
/// binding[32] (the exporter's or the certificate's hash on TCP, zeros on the socket).
pub fn auth_message(
    endpoint: u8,
    hello: &[u8; HELLO_LEN],
    challenge: &[u8; CHALLENGE_LEN],
    binding: &[u8; KEY],
) -> [u8; AUTHMSG_LEN] {
    let mut out = [0u8; AUTHMSG_LEN];
    out[..14].copy_from_slice(b"IMDBWIR1-SCRAM");
    out[14] = endpoint;
    out[15..15 + HELLO_LEN].copy_from_slice(hello);
    out[15 + HELLO_LEN..15 + HELLO_LEN + CHALLENGE_LEN].copy_from_slice(challenge);
    out[15 + HELLO_LEN + CHALLENGE_LEN..].copy_from_slice(binding);
    out
}

/// A password as CREATE ROLE takes one: 1 to 1,024 bytes of printable ASCII (no SASLprep in imagedb yet).
pub fn password_ok(pw: &[u8]) -> bool {
    !pw.is_empty() && pw.len() <= PW_MAX && pw.iter().all(|&c| (0x20..=0x7e).contains(&c))
}

/// RFC 5802's client computation over the AuthMessage: the ClientProof and the ServerSignature the client expects.
pub fn scram_client(pw: &[u8], c: &Challenge, am: &[u8; AUTHMSG_LEN]) -> Result<([u8; KEY], [u8; KEY])> {
    if !password_ok(pw) {
        return Err(Error::Invalid("a password is 1 to 1,024 printable ASCII bytes".into()));
    }
    if !c.ok() {
        return Err(Error::Invalid("a challenge its decoder would refuse".into()));
    }
    // the one SCRAM computation, RFC 7677's example its test (tests/crypto.rs)
    Ok(scram::client(pw, &c.salt, c.iterations, am))
}

// ---- values ----

fn dec_in(d: i128, digits: u32) -> bool {
    let lim = pow10_i128(digits);
    d > -lim && d < lim
}

/// A value's own rules (its decoder's and its encoder's); the native types' constructors hold the rest.
pub fn value_ok(v: &Value) -> bool {
    match v {
        Value::Float64(f) => f.is_finite() && f.to_bits() != 0x8000_0000_0000_0000,
        Value::Text(s) => s.len() <= VALUE_MAX && utf8_ok(s.as_bytes()),
        Value::Bytea(b) => b.len() <= VALUE_MAX,
        Value::Enum(s) => s.len() <= LABEL_MAX && utf8_ok(s.as_bytes()),
        _ => true,
    }
}

/// A value's bytes; refused (nothing written) when its decoder would refuse it.
pub fn put_value(out: &mut Vec<u8>, v: &Value) -> Result<()> {
    if !value_ok(v) {
        return Err(Error::Invalid(format!("a {:?} value its decoder would refuse", v.ty())));
    }
    match v {
        Value::Null(t) => out.push(NULL_TAG | *t as u8),
        Value::Int64(i) => {
            out.push(1);
            out.extend_from_slice(&i.to_le_bytes());
        }
        Value::Float64(f) => {
            out.push(2);
            out.extend_from_slice(&f.to_bits().to_le_bytes());
        }
        Value::Bool(b) => out.extend_from_slice(&[3, *b as u8]),
        Value::Text(s) => {
            out.push(4);
            out.extend_from_slice(&(s.len() as u32).to_le_bytes());
            out.extend_from_slice(s.as_bytes());
        }
        Value::Decimal(d) => {
            out.push(5);
            out.push(d.scale());
            out.extend_from_slice(&d.unscaled().to_le_bytes());
        }
        Value::Timestamp(t) => {
            out.push(6);
            out.extend_from_slice(&t.micros().to_le_bytes());
        }
        Value::TimestampTz(t) => {
            out.push(7);
            out.extend_from_slice(&t.micros().to_le_bytes());
        }
        Value::Date(d) => {
            out.push(8);
            out.extend_from_slice(&d.days().to_le_bytes());
        }
        Value::Time(t) => {
            out.push(9);
            out.extend_from_slice(&t.micros().to_le_bytes());
        }
        Value::Uuid(u) => {
            out.push(10);
            out.extend_from_slice(&u.0);
        }
        Value::Bytea(b) => {
            out.push(11);
            out.extend_from_slice(&(b.len() as u32).to_le_bytes());
            out.extend_from_slice(b);
        }
        Value::Interval(iv) => {
            out.push(12);
            out.extend_from_slice(&iv.months.to_le_bytes());
            out.extend_from_slice(&iv.days.to_le_bytes());
            out.extend_from_slice(&iv.micros.to_le_bytes());
        }
        Value::Enum(s) => {
            out.push(13);
            out.push(s.len() as u8);
            out.extend_from_slice(s.as_bytes());
        }
    }
    Ok(())
}

fn cut() -> Error {
    Error::corrupt("a value cut short")
}

/// One value: its tag, then its bytes; refused when cut short, past its bounds (a length before its bytes are asked
/// for) or outside its type's rules.
pub(crate) fn get_value(r: &mut Rd) -> Result<Value> {
    let tag = r.u8();
    if r.err {
        return Err(cut());
    }
    if tag & NULL_TAG != 0 {
        return match Type::from_u8(tag & !NULL_TAG) {
            Some(t) => Ok(Value::Null(t)),
            None => Err(Error::corrupt("a NULL of a type the protocol does not define")),
        };
    }
    let rule = || Error::corrupt("a value outside its type's rules");
    let v = match tag {
        1 => Value::Int64(r.u64() as i64),
        2 => {
            let f = f64::from_bits(r.u64());
            Value::Float64(f)
        }
        3 => match r.u8() {
            0 => Value::Bool(false),
            1 => Value::Bool(true),
            _ if r.err => return Err(cut()),
            _ => return Err(rule()),
        },
        4 | 11 | 13 => {
            let (len, max) = if tag == 13 { (r.u8() as usize, LABEL_MAX) } else { (r.u32() as usize, VALUE_MAX) };
            if r.err {
                return Err(cut());
            }
            if len > max {
                return Err(Error::limit(format!("a value of {len} bytes (at most {max})")));
            }
            let b = r.bytes(len).ok_or_else(cut)?;
            if tag == 11 {
                Value::Bytea(b.to_vec())
            } else {
                if !utf8_ok(b) {
                    return Err(rule());
                }
                let s = String::from_utf8(b.to_vec()).unwrap();
                if tag == 4 { Value::Text(s) } else { Value::Enum(s) }
            }
        }
        5 => {
            let scale = r.u8();
            let d = i128::from_le_bytes(r.arr());
            if r.err {
                return Err(cut());
            }
            Value::Decimal(Decimal::new(d, scale).map_err(|_| rule())?)
        }
        6 | 7 | 9 => {
            let i = r.u64() as i64;
            if r.err {
                return Err(cut());
            }
            match tag {
                6 => Value::Timestamp(Timestamp::from_micros(i).map_err(|_| rule())?),
                7 => Value::TimestampTz(TimestampTz::from_micros(i).map_err(|_| rule())?),
                _ => Value::Time(Time::from_micros(i).map_err(|_| rule())?),
            }
        }
        8 => {
            let d = r.u32() as i32;
            if r.err {
                return Err(cut());
            }
            Value::Date(Date::from_days(d).map_err(|_| rule())?)
        }
        10 => Value::Uuid(Uuid(r.arr())),
        12 => {
            let months = r.u32() as i32;
            let days = r.u32() as i32;
            let micros = r.u64() as i64;
            Value::Interval(Interval { months, days, micros })
        }
        _ => {
            return Err(Error::corrupt(
                "a value of a type the protocol does not define (a NULL's tag is 0x80 and its type)",
            ));
        }
    };
    if r.err {
        return Err(cut());
    }
    if !value_ok(&v) {
        return Err(rule());
    }
    Ok(v)
}

/// One value decoded from exactly these bytes (no byte past it).
pub fn decode_value(b: &[u8]) -> Result<Value> {
    let mut r = Rd::new(b);
    let v = get_value(&mut r)?;
    if r.left() != 0 {
        return Err(Error::corrupt("bytes past the value"));
    }
    Ok(v)
}

/// One value's bytes.
pub fn encode_value(v: &Value) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    put_value(&mut out, v)?;
    Ok(out)
}

// ---- columns ----

/// A result's column: its name, its wire type (`Type::None` when the statement does not know it: each value carries its
/// own), precision and scale (§4's rules), and an ENUM's labels in the type's order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Column {
    pub name: String,
    pub ty: Type,
    pub precision: u16,
    pub scale: u16,
    pub labels: Vec<String>,
}

impl Column {
    pub fn new(name: &str, ty: Type, precision: u16, scale: u16) -> Column {
        Column { name: name.to_string(), ty, precision, scale, labels: Vec::new() }
    }

    fn shape_ok(&self) -> bool {
        let n = self.name.len();
        if n < 1 || n > COLNAME_MAX || !utf8_ok(self.name.as_bytes()) {
            return false;
        }
        if self.ty != Type::Enum && !self.labels.is_empty() {
            return false;
        }
        if self.ty == Type::Enum && self.labels.len() > LABELS_MAX {
            return false;
        }
        match self.ty {
            // precision 0: not known (a result's column), 38 digits
            Type::Decimal => self.precision <= 38 && self.scale <= if self.precision > 0 { self.precision } else { 38 },
            Type::Int64 => matches!(self.precision, 0 | 16 | 32) && self.scale == 0,
            Type::Text => self.scale == 0, // precision: a VARCHAR's length in characters, 0 none
            _ => self.precision == 0 && self.scale == 0,
        }
    }
}

/// A COLUMNS message: its columns and, for each ENUM column, its labels as a set (membership and distinctness).
#[derive(Clone, Debug)]
pub struct Columns {
    cols: Vec<Column>,
    sets: Vec<Option<HashSet<String>>>,
}

impl PartialEq for Columns {
    fn eq(&self, o: &Columns) -> bool {
        self.cols == o.cols
    }
}

impl Columns {
    /// Columns checked as the decoder checks them: 1 to 256, each its type's shape, ENUM labels 0 to 63 bytes of
    /// UTF-8, distinct, at most 1,024.
    pub fn new(cols: Vec<Column>) -> Result<Columns> {
        if cols.is_empty() || cols.len() > VALUES_MAX {
            return Err(Error::Invalid("a COLUMNS of 1 to 256 columns".into()));
        }
        let mut sets = Vec::with_capacity(cols.len());
        for c in &cols {
            if !c.shape_ok() {
                return Err(Error::Invalid("a column's type, precision or scale its type does not take".into()));
            }
            if c.ty == Type::Enum {
                let mut set = HashSet::with_capacity(c.labels.len());
                for l in &c.labels {
                    if l.len() > LABEL_MAX || !utf8_ok(l.as_bytes()) {
                        return Err(Error::Invalid("an ENUM's label".into()));
                    }
                    if !set.insert(l.clone()) {
                        return Err(Error::Invalid("an ENUM's labels not distinct".into()));
                    }
                }
                sets.push(Some(set));
            } else {
                sets.push(None);
            }
        }
        Ok(Columns { cols, sets })
    }

    /// The columns, in order.
    pub fn cols(&self) -> &[Column] {
        &self.cols
    }

    pub fn len(&self) -> usize {
        self.cols.len()
    }

    pub fn is_empty(&self) -> bool {
        self.cols.is_empty()
    }

    /// The column's index by its name.
    pub fn index_of(&self, name: &str) -> Option<usize> {
        self.cols.iter().position(|c| c.name == name)
    }

    /// ROWS' rule: a value fits its column when it is NULL of the column's type or of it, at the column's scale and
    /// within its precision, an integer within its width, a TEXT within its VARCHAR's characters, an ENUM one of its
    /// labels; under a column of no known type, any valid value.
    pub fn fits(&self, i: usize, v: &Value) -> bool {
        let c = &self.cols[i];
        if !value_ok(v) {
            return false;
        }
        if c.ty == Type::None {
            return true;
        }
        if v.ty() != c.ty {
            return false; // a NULL too: one tag a column, its type's
        }
        match v {
            Value::Null(_) => true,
            Value::Decimal(d) => {
                d.scale() as u16 == c.scale && dec_in(d.unscaled(), if c.precision > 0 { c.precision as u32 } else { 38 })
            }
            Value::Int64(x) => match c.precision {
                16 => (i16::MIN as i64..=i16::MAX as i64).contains(x),
                32 => (i32::MIN as i64..=i32::MAX as i64).contains(x),
                _ => true,
            },
            Value::Text(s) => c.precision == 0 || s.chars().count() <= c.precision as usize,
            Value::Enum(s) => self.sets[i].as_ref().is_some_and(|set| set.contains(s)),
            _ => true,
        }
    }
}

// ---- messages ----

/// A statement of a QUERY: its text and its $1 to $k.
#[derive(Clone, Debug, PartialEq)]
pub struct Statement {
    pub sql: String,
    pub params: Vec<Value>,
}

/// DONE's read point (the engine's imdb_result: the commit read, its hash, the state digest, the lake's commit and
/// manifest, the database's id, whether the read saw its transaction's own writes).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReadPoint {
    pub commit: u64,
    pub hash: [u8; 32],
    pub digest: [u8; 32],
    pub lake_commit: u64,
    pub lake_manifest: [u8; 32],
    pub db_id: [u8; 16],
    pub own: bool,
}

/// DONE's write: the statement's own commit (at least 1) and its hash.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WriteCommit {
    pub commit: u64,
    pub hash: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Done {
    pub status: String,
    pub count: u64,
    pub read: Option<ReadPoint>,
    pub write: Option<WriteCommit>,
}

/// A session in SESSIONS_LIST.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionInfo {
    /// A counter given at its connection's accept, never reused (at least 1).
    pub id: u64,
    pub role: u32,
    /// 1 TCP, 2 the socket.
    pub endpoint: u8,
    /// 0 idle, 1 a request running or queued, 2 in a transaction at its last request's end, 3 receiving a COPY's data.
    pub state: u8,
    pub age_ms: u64,
    /// Its role's name as the logins give it now ("" for a role no longer among them).
    pub name: String,
}

/// A ROWS frame's values, validated against its COLUMNS when it arrived and kept as their bytes: a frame costs its own
/// bytes (§4: values are never copied into arrays), its rows decoded as they are read.
#[derive(Clone, Debug)]
pub struct Rows {
    cols: Arc<Columns>,
    n: u32,
    body: Vec<u8>,
}

impl PartialEq for Rows {
    fn eq(&self, o: &Rows) -> bool {
        self.n == o.n && self.body == o.body && self.cols == o.cols
    }
}

impl Rows {
    /// Rows built from values, each held to its column (the encoder's side).
    pub fn new(cols: Arc<Columns>, rows: &[Vec<Value>]) -> Result<Rows> {
        if rows.is_empty() {
            return Err(Error::Invalid("a ROWS of no row".into()));
        }
        let mut body = Vec::new();
        for row in rows {
            if row.len() != cols.len() {
                return Err(Error::Invalid("a row of another count of values than its COLUMNS".into()));
            }
            for (i, v) in row.iter().enumerate() {
                if !cols.fits(i, v) {
                    return Err(Error::Invalid("a value its column does not take".into()));
                }
                put_value(&mut body, v)?;
            }
        }
        if rows.len() > u32::MAX as usize {
            return Err(Error::Invalid("too many rows".into()));
        }
        Ok(Rows { cols, n: rows.len() as u32, body })
    }

    pub fn columns(&self) -> &Arc<Columns> {
        &self.cols
    }

    pub fn len(&self) -> usize {
        self.n as usize
    }

    pub fn is_empty(&self) -> bool {
        self.n == 0
    }

    /// The rows, each its values in column order.
    pub fn iter(&self) -> RowsIter<'_> {
        RowsIter { r: Rd::new(&self.body), left: self.n, ncols: self.cols.len() }
    }
}

pub struct RowsIter<'a> {
    r: Rd<'a>,
    left: u32,
    ncols: usize,
}

impl Iterator for RowsIter<'_> {
    type Item = Vec<Value>;
    fn next(&mut self) -> Option<Vec<Value>> {
        if self.left == 0 {
            return None;
        }
        self.left -= 1;
        let mut row = Vec::with_capacity(self.ncols);
        for _ in 0..self.ncols {
            // validated at the frame's decode: a failure here is this driver's bug, never silently a short row
            row.push(get_value(&mut self.r).expect("a ROWS frame validated at its decode"));
        }
        Some(row)
    }
}

/// A frame's message, either direction.
#[derive(Clone, Debug, PartialEq)]
pub enum Msg {
    Query(Vec<Statement>),
    Prepare { name: String, sql: String },
    /// `sets` x `nvals` values, set after set.
    Execute { name: String, sets: u32, nvals: u16, values: Vec<Value> },
    Deallocate { name: String },
    CopyData(Vec<u8>),
    CopyDone,
    CopyFail(String),
    Cancel,
    Ping,
    Terminate,
    Sessions,
    Kill { kind: u8, session: u64 },
    Columns(Arc<Columns>),
    Rows(Rows),
    Done(Done),
    Error(ServerError),
    Warning(String),
    CopyIn,
    CopyOut(Vec<u8>),
    /// 0 idle, 1 in a transaction, 2 in a doomed one.
    Ready(u8),
    Pong,
    SessionsList(Vec<SessionInfo>),
    /// code 0 done, 1 no such session; the KILL's session id.
    KillDone { code: u8, session: u64 },
}

/// A frame type's name (§4's table), for the messages that refuse one.
pub fn frame_name(ty: u8) -> &'static str {
    match ty {
        QUERY => "QUERY",
        PREPARE => "PREPARE",
        EXECUTE => "EXECUTE",
        DEALLOCATE => "DEALLOCATE",
        COPY_DATA => "COPY_DATA",
        COPY_DONE => "COPY_DONE",
        COPY_FAIL => "COPY_FAIL",
        CANCEL => "CANCEL",
        PING => "PING",
        TERMINATE => "TERMINATE",
        SESSIONS => "SESSIONS",
        KILL => "KILL",
        COLUMNS => "COLUMNS",
        ROWS => "ROWS",
        DONE => "DONE",
        ERROR => "ERROR",
        WARNING => "WARNING",
        COPY_IN => "COPY_IN",
        COPY_OUT => "COPY_OUT",
        READY => "READY",
        PONG => "PONG",
        SESSIONS_LIST => "SESSIONS_LIST",
        KILL_DONE => "KILL_DONE",
        _ => "unknown",
    }
}

/// A frame's head: the length of its type and body (1 to 16 MiB) and a type of the direction's (the client's 1 to 12,
/// the server's 64 to 74).
pub fn head_get(b: &[u8; HEAD], from_server: bool) -> Result<(u32, u8)> {
    let len = u32::from_le_bytes(b[..4].try_into().unwrap());
    let ty = b[4];
    if len < 1 || len > FRAME_MAX {
        return Err(Error::limit(format!("a frame of {len} bytes (1 to {FRAME_MAX})")));
    }
    let known = if from_server { (COLUMNS..=KILL_DONE).contains(&ty) } else { (QUERY..=KILL).contains(&ty) };
    if !known {
        return Err(Error::corrupt("a frame of a type this side does not send"));
    }
    Ok((len, ty))
}

fn text_get(r: &mut Rd, lenbytes: u8, min: usize, max: usize) -> Result<String> {
    let n = match lenbytes {
        1 => r.u8() as usize,
        2 => r.u16() as usize,
        _ => r.u32() as usize,
    };
    if r.err {
        return Err(Error::corrupt("a text cut short"));
    }
    if n < min || n > max {
        return Err(Error::limit(format!("a text of {n} bytes ({min} to {max})")));
    }
    let b = r.bytes(n).ok_or_else(|| Error::corrupt("a text cut short"))?;
    if !utf8_ok(b) {
        return Err(Error::corrupt("a text not UTF-8 without NUL"));
    }
    Ok(String::from_utf8(b.to_vec()).unwrap())
}

fn text_put(out: &mut Vec<u8>, lenbytes: u8, min: usize, max: usize, t: &str, what: &str) -> Result<()> {
    if t.len() < min || t.len() > max || !utf8_ok(t.as_bytes()) {
        return Err(Error::Invalid(format!("{what}: {min} to {max} bytes of UTF-8 without NUL")));
    }
    match lenbytes {
        1 => out.push(t.len() as u8),
        2 => out.extend_from_slice(&(t.len() as u16).to_le_bytes()),
        _ => out.extend_from_slice(&(t.len() as u32).to_le_bytes()),
    }
    out.extend_from_slice(t.as_bytes());
    Ok(())
}

/// n values, each a parameter's (never a non-NULL ENUM: a label is sent as TEXT); the count bounded by the bytes left
/// (each value at least one byte) before it sizes anything.
fn params_get(r: &mut Rd, n: u64) -> Result<Vec<Value>> {
    if n > r.left() as u64 {
        return Err(Error::corrupt("more values than bytes"));
    }
    let mut v = Vec::with_capacity(n as usize);
    for _ in 0..n {
        let x = get_value(r)?;
        if matches!(x, Value::Enum(_)) {
            return Err(Error::corrupt("an ENUM parameter: a label is sent as TEXT"));
        }
        v.push(x);
    }
    Ok(v)
}

fn params_put(out: &mut Vec<u8>, vals: &[Value]) -> Result<()> {
    for v in vals {
        if matches!(v, Value::Enum(_)) {
            return Err(Error::Invalid("an ENUM parameter: send its label as TEXT (§4)".into()));
        }
        put_value(out, v)?;
    }
    Ok(())
}

fn col_get(r: &mut Rd) -> Result<Column> {
    let name = text_get(r, 1, 1, COLNAME_MAX)?;
    let ty = r.u8();
    let precision = r.u16();
    let scale = r.u16();
    if r.err {
        return Err(Error::corrupt("a column cut short"));
    }
    let mut labels = Vec::new();
    if ty == Type::Enum as u8 {
        let n = r.u16() as usize;
        if r.err || n > LABELS_MAX || n > r.left() {
            return Err(Error::corrupt("an ENUM's labels past their bounds or bytes"));
        }
        labels.reserve(n);
        for _ in 0..n {
            labels.push(text_get(r, 1, 0, LABEL_MAX)?);
        }
    }
    let c = Column {
        name,
        ty: Type::from_u8(ty).ok_or_else(|| Error::corrupt("a column's type the protocol does not define"))?,
        precision,
        scale,
        labels,
    };
    if !c.shape_ok() {
        return Err(Error::corrupt("a column's type, precision or scale its type does not take"));
    }
    Ok(c)
}

fn done_get(r: &mut Rd) -> Result<Done> {
    let status = text_get(r, 2, 0, STATUS_MAX)?;
    let count = r.u64();
    let hr = r.u8();
    if r.err || hr > 1 {
        return Err(Error::corrupt("a DONE's read point flag"));
    }
    let read = if hr == 1 {
        let commit = r.u64();
        let hash = r.arr();
        let digest = r.arr();
        let lake_commit = r.u64();
        let lake_manifest = r.arr();
        let db_id = r.arr();
        let own = r.u8();
        if !r.err && own > 1 {
            return Err(Error::corrupt("a DONE's own-writes flag"));
        }
        Some(ReadPoint { commit, hash, digest, lake_commit, lake_manifest, db_id, own: own == 1 })
    } else {
        None
    };
    let hw = r.u8();
    if r.err || hw > 1 {
        return Err(Error::corrupt("a DONE's write flag"));
    }
    let write = if hw == 1 { Some(WriteCommit { commit: r.u64(), hash: r.arr() }) } else { None };
    if !r.err && write.as_ref().is_some_and(|w| w.commit < 1) {
        return Err(Error::corrupt("a DONE's write at commit 0"));
    }
    Ok(Done { status, count, read, write })
}

/// SESSIONS_LIST's entry: at least 23 bytes (u64 id, u32 role, u8 endpoint, u8 state, u64 age, u8 length).
const SESS_MIN: usize = 23;

fn sess_ok(s: &SessionInfo, prev: u64) -> bool {
    s.id > prev
        && s.role != 0
        && (s.endpoint == 1 || s.endpoint == 2)
        && s.state <= 3
        && s.name.len() < USER
        && utf8_ok(s.name.as_bytes())
}

impl Msg {
    pub fn frame_type(&self) -> u8 {
        match self {
            Msg::Query(_) => QUERY,
            Msg::Prepare { .. } => PREPARE,
            Msg::Execute { .. } => EXECUTE,
            Msg::Deallocate { .. } => DEALLOCATE,
            Msg::CopyData(_) => COPY_DATA,
            Msg::CopyDone => COPY_DONE,
            Msg::CopyFail(_) => COPY_FAIL,
            Msg::Cancel => CANCEL,
            Msg::Ping => PING,
            Msg::Terminate => TERMINATE,
            Msg::Sessions => SESSIONS,
            Msg::Kill { .. } => KILL,
            Msg::Columns(_) => COLUMNS,
            Msg::Rows(_) => ROWS,
            Msg::Done(_) => DONE,
            Msg::Error(_) => ERROR,
            Msg::Warning(_) => WARNING,
            Msg::CopyIn => COPY_IN,
            Msg::CopyOut(_) => COPY_OUT,
            Msg::Ready(_) => READY,
            Msg::Pong => PONG,
            Msg::SessionsList(_) => SESSIONS_LIST,
            Msg::KillDone { .. } => KILL_DONE,
        }
    }

    /// A frame's body decoded: a ROWS against the COLUMNS of its statement (`cols`; ignored for the other types).
    pub fn decode(ty: u8, body: &[u8], cols: Option<&Arc<Columns>>) -> Result<Msg> {
        let mut r = Rd::new(body);
        let m = Self::body_get(ty, &mut r, cols)?;
        if r.err {
            return Err(Error::corrupt("a body cut short"));
        }
        if r.left() != 0 {
            return Err(Error::corrupt("a body with bytes past its end"));
        }
        Ok(m)
    }

    fn body_get(ty: u8, r: &mut Rd, cols: Option<&Arc<Columns>>) -> Result<Msg> {
        Ok(match ty {
            QUERY => {
                let n = r.u32();
                // a statement: 7 bytes at least
                if r.err || n < 1 || n > BATCH_MAX || n as usize > r.left() / 7 {
                    return Err(Error::corrupt("a QUERY of 1 to 4,096 statements it holds the bytes of"));
                }
                let mut st = Vec::with_capacity(n as usize);
                for _ in 0..n {
                    let sql = text_get(r, 4, 1, SQL_MAX)?;
                    let nv = r.u16() as usize;
                    if r.err || nv > VALUES_MAX {
                        return Err(Error::corrupt("a statement's values: at most 256"));
                    }
                    st.push(Statement { sql, params: params_get(r, nv as u64)? });
                }
                Msg::Query(st)
            }
            PREPARE => {
                let name = text_get(r, 1, 1, NAME_MAX)?;
                Msg::Prepare { name, sql: text_get(r, 4, 1, SQL_MAX)? }
            }
            EXECUTE => {
                let name = text_get(r, 1, 1, NAME_MAX)?;
                let sets = r.u32();
                let nvals = r.u16();
                if r.err || sets < 1 || sets > BATCH_MAX || nvals as usize > VALUES_MAX {
                    return Err(Error::corrupt("an EXECUTE of 1 to 4,096 sets of at most 256 values"));
                }
                let values = params_get(r, sets as u64 * nvals as u64)?;
                Msg::Execute { name, sets, nvals, values }
            }
            DEALLOCATE => Msg::Deallocate { name: text_get(r, 1, 1, NAME_MAX)? },
            KILL => {
                let kind = r.u8();
                let session = r.u64();
                if r.err || !(kind == KILL_CANCEL || kind == KILL_TERMINATE) || session == 0 {
                    return Err(Error::corrupt("a KILL's kind (1 cancel, 2 terminate) or a session id of 0"));
                }
                Msg::Kill { kind, session }
            }
            KILL_DONE => {
                let code = r.u8();
                let session = r.u64();
                if r.err || code > 1 || session == 0 {
                    return Err(Error::corrupt("a KILL_DONE's code or a session id of 0"));
                }
                Msg::KillDone { code, session }
            }
            SESSIONS_LIST => {
                let n = r.u32();
                if r.err || n > SESSIONS_MAX || n as usize > r.left() / SESS_MIN {
                    return Err(Error::corrupt("a SESSIONS_LIST of at most 65,536 sessions it holds the bytes of"));
                }
                let mut v: Vec<SessionInfo> = Vec::with_capacity(n as usize);
                for _ in 0..n {
                    let id = r.u64();
                    let role = r.u32();
                    let endpoint = r.u8();
                    let state = r.u8();
                    let age_ms = r.u64();
                    if r.err {
                        return Err(Error::corrupt("a session cut short"));
                    }
                    let name = text_get(r, 1, 0, USER - 1)?;
                    let s = SessionInfo { id, role, endpoint, state, age_ms, name };
                    if !sess_ok(&s, v.last().map_or(0, |p| p.id)) {
                        return Err(Error::corrupt("a session's id out of order, or its role, endpoint or state"));
                    }
                    v.push(s);
                }
                Msg::SessionsList(v)
            }
            COPY_DATA | COPY_OUT => {
                let n = r.left();
                if n == 0 {
                    return Err(Error::corrupt("a COPY piece of no bytes"));
                }
                let d = r.bytes(n).unwrap().to_vec();
                if ty == COPY_DATA { Msg::CopyData(d) } else { Msg::CopyOut(d) }
            }
            COPY_FAIL => Msg::CopyFail(text_get(r, 2, 0, MESSAGE_MAX)?),
            WARNING => Msg::Warning(text_get(r, 2, 0, MESSAGE_MAX)?),
            SESSIONS => Msg::Sessions,
            COPY_DONE => Msg::CopyDone,
            CANCEL => Msg::Cancel,
            PING => Msg::Ping,
            TERMINATE => Msg::Terminate,
            COPY_IN => Msg::CopyIn,
            PONG => Msg::Pong,
            COLUMNS => {
                let n = r.u16() as usize;
                // a column: 7 bytes at least
                if r.err || n < 1 || n > VALUES_MAX || n > r.left() / 7 {
                    return Err(Error::corrupt("a COLUMNS of 1 to 256 columns it holds the bytes of"));
                }
                let mut cols = Vec::with_capacity(n);
                for _ in 0..n {
                    cols.push(col_get(r)?);
                }
                Msg::Columns(Arc::new(
                    Columns::new(cols).map_err(|_| Error::corrupt("an ENUM's labels not distinct"))?,
                ))
            }
            ROWS => {
                let cols = cols.ok_or_else(|| Error::corrupt("a ROWS with no COLUMNS before it"))?;
                let n = r.u32();
                if r.err || n < 1 {
                    return Err(Error::corrupt("a ROWS of no row"));
                }
                let total = n as u64 * cols.len() as u64;
                if total > r.left() as u64 {
                    return Err(Error::corrupt("more values than bytes"));
                }
                let at = r.off;
                for k in 0..total {
                    let v = get_value(r)?;
                    if !cols.fits((k % cols.len() as u64) as usize, &v) {
                        return Err(Error::corrupt("a value its column does not take"));
                    }
                }
                Msg::Rows(Rows { cols: cols.clone(), n, body: r.b[at..r.off].to_vec() })
            }
            DONE => Msg::Done(done_get(r)?),
            ERROR => {
                let code = r.u32();
                let index = r.u32();
                if r.err || code == 0 || index >= BATCH_MAX {
                    return Err(Error::corrupt("an ERROR's code 0 or its statement's index"));
                }
                Msg::Error(ServerError { code, index, message: text_get(r, 2, 0, MESSAGE_MAX)? })
            }
            READY => {
                let s = r.u8();
                if !r.err && s > 2 {
                    return Err(Error::corrupt("a READY's state"));
                }
                Msg::Ready(s)
            }
            _ => return Err(Error::corrupt("a frame of a type the protocol does not define")),
        })
    }

    /// The whole frame (head and body): the exact bytes its decoder takes, or Invalid for a field it would refuse.
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut out = vec![0u8, 0, 0, 0, self.frame_type()];
        self.body_put(&mut out)?;
        let n = out.len() - 4;
        if n > FRAME_MAX as usize {
            return Err(Error::Invalid(format!("a frame of {n} bytes (at most {FRAME_MAX})")));
        }
        out[..4].copy_from_slice(&(n as u32).to_le_bytes());
        Ok(out)
    }

    fn body_put(&self, out: &mut Vec<u8>) -> Result<()> {
        let inv = |m: &str| Err(Error::Invalid(m.to_string()));
        match self {
            Msg::Query(st) => {
                if st.is_empty() || st.len() > BATCH_MAX as usize {
                    return inv("a QUERY holds 1 to 4,096 statements");
                }
                out.extend_from_slice(&(st.len() as u32).to_le_bytes());
                for s in st {
                    text_put(out, 4, 1, SQL_MAX, &s.sql, "a statement")?;
                    if s.params.len() > VALUES_MAX {
                        return inv("a statement takes at most 256 values");
                    }
                    out.extend_from_slice(&(s.params.len() as u16).to_le_bytes());
                    params_put(out, &s.params)?;
                }
            }
            Msg::Prepare { name, sql } => {
                text_put(out, 1, 1, NAME_MAX, name, "a prepared statement's name")?;
                text_put(out, 4, 1, SQL_MAX, sql, "a statement")?;
            }
            Msg::Execute { name, sets, nvals, values } => {
                text_put(out, 1, 1, NAME_MAX, name, "a prepared statement's name")?;
                if *sets < 1 || *sets > BATCH_MAX || *nvals as usize > VALUES_MAX {
                    return inv("an EXECUTE of 1 to 4,096 sets of at most 256 values");
                }
                if values.len() as u64 != *sets as u64 * *nvals as u64 {
                    return inv("an EXECUTE's values are its sets times its values a set");
                }
                out.extend_from_slice(&sets.to_le_bytes());
                out.extend_from_slice(&nvals.to_le_bytes());
                params_put(out, values)?;
            }
            Msg::Deallocate { name } => text_put(out, 1, 1, NAME_MAX, name, "a prepared statement's name")?,
            Msg::CopyData(d) | Msg::CopyOut(d) => {
                if d.is_empty() {
                    return inv("a COPY piece of no bytes");
                }
                out.extend_from_slice(d);
            }
            Msg::CopyFail(t) | Msg::Warning(t) => text_put(out, 2, 0, MESSAGE_MAX, t, "a message")?,
            Msg::CopyDone | Msg::Cancel | Msg::Ping | Msg::Terminate | Msg::Sessions | Msg::CopyIn | Msg::Pong => {}
            Msg::Kill { kind, session } => {
                if !(*kind == KILL_CANCEL || *kind == KILL_TERMINATE) || *session == 0 {
                    return inv("a KILL's kind is cancel or terminate, its session an id from SESSIONS");
                }
                out.push(*kind);
                out.extend_from_slice(&session.to_le_bytes());
            }
            Msg::KillDone { code, session } => {
                if *code > 1 || *session == 0 {
                    return inv("a KILL_DONE's code or a session id of 0");
                }
                out.push(*code);
                out.extend_from_slice(&session.to_le_bytes());
            }
            Msg::SessionsList(v) => {
                if v.len() > SESSIONS_MAX as usize {
                    return inv("a SESSIONS_LIST of at most 65,536 sessions");
                }
                out.extend_from_slice(&(v.len() as u32).to_le_bytes());
                let mut prev = 0;
                for s in v {
                    if !sess_ok(s, prev) {
                        return inv("a session's id out of order, or its role, endpoint or state");
                    }
                    prev = s.id;
                    out.extend_from_slice(&s.id.to_le_bytes());
                    out.extend_from_slice(&s.role.to_le_bytes());
                    out.push(s.endpoint);
                    out.push(s.state);
                    out.extend_from_slice(&s.age_ms.to_le_bytes());
                    text_put(out, 1, 0, USER - 1, &s.name, "a role's name")?;
                }
            }
            Msg::Columns(c) => {
                // Columns::new checked every rule when it was made: its fields are private
                out.extend_from_slice(&(c.cols.len() as u16).to_le_bytes());
                for col in &c.cols {
                    text_put(out, 1, 1, COLNAME_MAX, &col.name, "a column's name")?;
                    out.push(col.ty as u8);
                    out.extend_from_slice(&col.precision.to_le_bytes());
                    out.extend_from_slice(&col.scale.to_le_bytes());
                    if col.ty == Type::Enum {
                        out.extend_from_slice(&(col.labels.len() as u16).to_le_bytes());
                        for l in &col.labels {
                            text_put(out, 1, 0, LABEL_MAX, l, "a label")?;
                        }
                    }
                }
            }
            Msg::Rows(rows) => {
                // walked again rather than trusted (an encoder walks every run it is handed)
                if rows.n < 1 {
                    return inv("a ROWS of no row");
                }
                let mut r = Rd::new(&rows.body);
                let total = rows.n as u64 * rows.cols.len() as u64;
                for k in 0..total {
                    let v = get_value(&mut r).map_err(|_| Error::Invalid("a ROWS value".into()))?;
                    if !rows.cols.fits((k % rows.cols.len() as u64) as usize, &v) {
                        return inv("a value its column does not take");
                    }
                }
                if r.left() != 0 {
                    return inv("a ROWS' bytes past its values");
                }
                out.extend_from_slice(&rows.n.to_le_bytes());
                out.extend_from_slice(&rows.body);
            }
            Msg::Done(d) => {
                if d.write.as_ref().is_some_and(|w| w.commit < 1) {
                    return inv("a DONE's write at commit 0");
                }
                text_put(out, 2, 0, STATUS_MAX, &d.status, "a status")?;
                out.extend_from_slice(&d.count.to_le_bytes());
                match &d.read {
                    Some(p) => {
                        out.push(1);
                        out.extend_from_slice(&p.commit.to_le_bytes());
                        out.extend_from_slice(&p.hash);
                        out.extend_from_slice(&p.digest);
                        out.extend_from_slice(&p.lake_commit.to_le_bytes());
                        out.extend_from_slice(&p.lake_manifest);
                        out.extend_from_slice(&p.db_id);
                        out.push(p.own as u8);
                    }
                    None => out.push(0),
                }
                match &d.write {
                    Some(w) => {
                        out.push(1);
                        out.extend_from_slice(&w.commit.to_le_bytes());
                        out.extend_from_slice(&w.hash);
                    }
                    None => out.push(0),
                }
            }
            Msg::Error(e) => {
                if e.code == 0 || e.index >= BATCH_MAX {
                    return inv("an ERROR's code 0 or its statement's index");
                }
                out.extend_from_slice(&e.code.to_le_bytes());
                out.extend_from_slice(&e.index.to_le_bytes());
                text_put(out, 2, 0, MESSAGE_MAX, &e.message, "a message")?;
            }
            Msg::Ready(s) => {
                if *s > 2 {
                    return inv("a READY's state");
                }
                out.push(*s);
            }
        }
        Ok(())
    }
}
