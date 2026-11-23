//! Live tests against the frozen server binaries, which run_tests.sh starts (IMDB_LIVE=1 and the variables below). Run
//! alone (`cargo test`), they say they were skipped; under run_tests.sh a missing variable fails them.
//! Stage 1: every scenario runs over the server's Unix-domain socket (`endpoints()`: stage 2 adds TCP with TLS 1.3).
mod common;

use std::io::{self, Read};
use std::sync::Arc;
use std::time::{Duration, Instant};

use imagedb::wire::{Msg, Statement};
use imagedb::*;

fn live() -> bool {
    match std::env::var("IMDB_LIVE").as_deref() {
        Ok("1") => true,
        _ => {
            eprintln!("skipped: the live tests run under run_tests.sh (IMDB_LIVE=1)");
            false
        }
    }
}

fn env(k: &str) -> String {
    std::env::var(k).unwrap_or_else(|_| panic!("{k} is not set: run the live tests through run_tests.sh"))
}

fn user() -> String {
    env("IMDB_USER")
}

fn pw() -> String {
    env("IMDB_PASSWORD")
}

fn socket_a() -> Config {
    Config::unix(env("IMDB_SOCK_A"), &user(), &pw()).read_timeout(Some(Duration::from_secs(60)))
}

/// Every endpoint a scenario runs over, each with a name that keeps its tables apart (stage 1: the socket alone).
fn endpoints() -> Vec<(&'static str, Config)> {
    vec![("sock", socket_a())]
}

fn connect(c: &Config) -> Client {
    Client::connect(c).unwrap_or_else(|e| panic!("connect: {e}"))
}

fn q(c: &mut Client, sql: &str) -> QueryResult {
    c.query(sql, &[]).unwrap_or_else(|e| panic!("{sql}: {e}"))
}

fn one_i64(c: &mut Client, sql: &str) -> i64 {
    q(c, sql).rows[0].get(0).unwrap()
}

#[test]
fn login_and_refusals() {
    if !live() {
        return;
    }
    for (name, cfg) in endpoints() {
        let mut c = connect(&cfg);
        assert_eq!(one_i64(&mut c, "SELECT 41 + 1"), 42, "{name}");
        // a wrong password and an unknown name: refused alike
        let mut bad = cfg.clone();
        bad.password = b"wrong-password".to_vec();
        let e1 = Client::connect(&bad).err().expect("a wrong password taken");
        let mut unknown = cfg.clone();
        unknown.user = "nobody_here".into();
        let e2 = Client::connect(&unknown).err().expect("an unknown name taken");
        assert!(matches!(&e1, Error::Auth(m) if m == "authentication refused"), "{name}: {e1}");
        assert_eq!(e1.to_string(), e2.to_string(), "{name}");
        // a password CREATE ROLE would refuse is refused before anything is sent
        let mut nonascii = cfg.clone();
        nonascii.password = "pässword".as_bytes().to_vec();
        assert!(matches!(Client::connect(&nonascii), Err(Error::Invalid(_))));
    }
}

fn mood(ep: &str) -> String {
    format!("mood_{ep}")
}

#[test]
fn every_type_round_trips() {
    if !live() {
        return;
    }
    for (ep, cfg) in endpoints() {
        let mut c = connect(&cfg);
        let t = format!("ty_{ep}");
        q(&mut c, &format!("CREATE TYPE {} AS ENUM ('sad', 'ok', 'happy')", mood(ep)));
        q(&mut c, &format!(
            "CREATE TABLE {t} (id BIGINT PRIMARY KEY, s SMALLINT, i INTEGER, f DOUBLE PRECISION, b BOOL, tx TEXT, \
             vc VARCHAR(5), d DECIMAL(38,6), dn DECIMAL(10,2), ts TIMESTAMP, tz TIMESTAMPTZ, dt DATE, tm TIME, u UUID, \
             bb BYTEA, iv INTERVAL, m {})",
            mood(ep)
        ));
        let dmax: Decimal = "99999999999999999999999999999999.999999".parse().unwrap();
        let dmin: Decimal = "-99999999999999999999999999999999.999999".parse().unwrap();
        let rows: Vec<Vec<Value>> = vec![
            vec![
                Value::Int64(i64::MAX),
                Value::Int64(i16::MAX as i64),
                Value::Int64(i32::MAX as i64),
                Value::Float64(f64::MAX),
                Value::Bool(true),
                Value::Text("h\u{e9}\u{20ac}\u{1F600}\u{10FFFF}".into()),
                Value::Text("\u{e9}\u{e9}\u{e9}\u{e9}\u{e9}".into()),
                Value::Decimal(dmax),
                Value::Decimal("99999999.99".parse().unwrap()),
                Value::Timestamp(Timestamp::from_micros(Timestamp::MAX_MICROS).unwrap()),
                Value::TimestampTz(TimestampTz::from_micros(TimestampTz::MAX_MICROS).unwrap()),
                Value::Date(Date::from_ymd(9999, 12, 31).unwrap()),
                Value::Time(Time::from_micros(Time::MAX_MICROS).unwrap()),
                Value::Uuid(Uuid([0xff; 16])),
                Value::Bytea((0..=255u8).cycle().take(65535).collect()),
                Value::Interval(Interval::new(i32::MAX, i32::MAX, i64::MAX)),
                Value::Text("happy".into()), // an ENUM's label is sent as TEXT (§4)
            ],
            vec![
                Value::Int64(i64::MIN),
                Value::Int64(i16::MIN as i64),
                Value::Int64(i32::MIN as i64),
                Value::Float64(-f64::from_bits(1)), // the least subnormal, negative
                Value::Bool(false),
                Value::Text("x".repeat(65535)),
                Value::Text("".into()),
                Value::Decimal(dmin),
                Value::Decimal("-99999999.99".parse().unwrap()),
                Value::Timestamp(Timestamp::from_micros(Timestamp::MIN_MICROS).unwrap()),
                Value::TimestampTz(TimestampTz::from_micros(TimestampTz::MIN_MICROS).unwrap()),
                Value::Date(Date::from_ymd(1, 1, 1).unwrap()),
                Value::Time(Time::from_micros(0).unwrap()),
                Value::Uuid(Uuid([0; 16])),
                Value::Bytea(vec![]),
                Value::Interval(Interval::new(i32::MIN, i32::MIN, i64::MIN)),
                Value::Text("sad".into()),
            ],
            vec![
                Value::Int64(0),
                Value::Null(Type::Int64),
                Value::Null(Type::None), // a NULL of no type binds into any column
                Value::Null(Type::Float64),
                Value::Null(Type::Bool),
                Value::Null(Type::Text),
                Value::Null(Type::Text),
                Value::Null(Type::Decimal),
                Value::Null(Type::Decimal),
                Value::Null(Type::Timestamp),
                Value::Null(Type::TimestampTz),
                Value::Null(Type::Date),
                Value::Null(Type::Time),
                Value::Null(Type::Uuid),
                Value::Null(Type::Bytea),
                Value::Null(Type::Interval),
                Value::Null(Type::Enum),
            ],
        ];
        let ins = format!("INSERT INTO {t} VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17)");
        for r in &rows {
            assert_eq!(c.execute(&ins, r).unwrap_or_else(|e| panic!("{ep}: {e}")), 1);
        }
        // by id descending: the maxima (row 0), the NULLs (id 0, row 2), the minima (row 1)
        let order = [0usize, 2, 1];
        let got = q(&mut c, &format!("SELECT * FROM {t} ORDER BY id DESC"));
        let cols = got.columns.clone().unwrap();
        let shape: Vec<(Type, u16, u16)> = cols.cols().iter().map(|c| (c.ty, c.precision, c.scale)).collect();
        assert_eq!(
            shape,
            vec![
                (Type::Int64, 0, 0),
                (Type::Int64, 0, 0), // conv.c:52: a result's widths are not sent (precision 0)
                (Type::Int64, 0, 0),
                (Type::Float64, 0, 0),
                (Type::Bool, 0, 0),
                (Type::Text, 0, 0),
                (Type::Text, 0, 0), // nor a VARCHAR's length
                (Type::Decimal, 0, 6), // a DECIMAL's precision not known: 38 digits at its scale
                (Type::Decimal, 0, 2),
                (Type::Timestamp, 0, 0),
                (Type::TimestampTz, 0, 0),
                (Type::Date, 0, 0),
                (Type::Time, 0, 0),
                (Type::Uuid, 0, 0),
                (Type::Bytea, 0, 0),
                (Type::Interval, 0, 0),
                (Type::Enum, 0, 0),
            ],
            "{ep}"
        );
        assert_eq!(cols.cols()[16].labels, vec!["sad", "ok", "happy"]);
        assert_eq!(got.rows.len(), 3);
        for (k, &ri) in order.iter().enumerate() {
            let want = &rows[ri];
            let have = got.rows[k].values();
            for (i, w) in want.iter().enumerate() {
                let w2 = match (i, w) {
                    (16, Value::Text(s)) => Value::Enum(s.clone()), // read back as the column's ENUM
                    (_, Value::Null(_)) => Value::Null(cols.cols()[i].ty), // a NULL comes back of its column's type
                    _ => w.clone(),
                };
                match (&have[i], &w2) {
                    (Value::Float64(a), Value::Float64(b)) => assert_eq!(a.to_bits(), b.to_bits(), "{ep} row {k} col {i}"),
                    (a, b) => assert_eq!(a, b, "{ep} row {k} col {i}"),
                }
            }
        }
        // typed reads
        let r0 = &got.rows[0];
        assert_eq!(r0.get::<i64>(0).unwrap(), i64::MAX);
        assert_eq!(r0.get_by_name::<Decimal>("d").unwrap(), dmax);
        assert_eq!(r0.get_by_name::<String>("m").unwrap(), "happy");
        assert_eq!(got.rows[1].get::<Option<i64>>(1).unwrap(), None);
        assert!(got.rows[1].get::<i64>(1).is_err());
        // a SUM over INT64 is a DECIMAL of scale 0 (§4): two INT64 maxima sum past INT64, exactly
        let s = q(&mut c, &format!("SELECT SUM(id) FROM {t} WHERE id > 0"));
        assert_eq!(s.columns.as_ref().unwrap().cols()[0].ty, Type::Decimal);
        assert_eq!(s.rows[0].get::<Decimal>(0).unwrap(), Decimal::new(i64::MAX as i128, 0).unwrap());
        q(&mut c, &format!("INSERT INTO {t} (id) VALUES ({})", i64::MAX - 1));
        let s = q(&mut c, &format!("SELECT SUM(id) FROM {t} WHERE id > 0"));
        assert_eq!(s.rows[0].get::<Decimal>(0).unwrap().to_string(), "18446744073709551613");
        // the server's own text of the same values (a literal's round trip): DECIMAL and TIMESTAMPTZ
        let lit = q(&mut c, "SELECT CAST('-99999999999999999999999999999999.999999' AS DECIMAL(38,6)), CAST('0001-01-01' AS DATE)");
        assert_eq!(lit.rows[0].get::<Decimal>(0).unwrap(), dmin);
        assert_eq!(lit.rows[0].get::<Date>(1).unwrap().days(), Date::MIN_DAYS);
    }
}

#[test]
fn decimal_scales_and_texts_at_their_edges() {
    if !live() {
        return;
    }
    for (ep, cfg) in endpoints() {
        let mut c = connect(&cfg);
        let t = format!("dz_{ep}");
        q(&mut c, &format!("CREATE TABLE {t} (id BIGINT PRIMARY KEY, a DECIMAL(38,0), b DECIMAL(38,38), s DECIMAL(1,0))"));
        let max = Decimal::MAX_UNSCALED;
        let rows = [
            (1, Decimal::new(max, 0).unwrap(), Decimal::new(max, 38).unwrap(), Decimal::new(9, 0).unwrap()),
            (2, Decimal::new(-max, 0).unwrap(), Decimal::new(-max, 38).unwrap(), Decimal::new(-9, 0).unwrap()),
            (3, Decimal::new(0, 0).unwrap(), Decimal::new(1, 38).unwrap(), Decimal::new(0, 0).unwrap()),
        ];
        for (id, a, b, s) in rows {
            let n = c.execute(&format!("INSERT INTO {t} VALUES ($1, $2, $3, $4)"), &[id.into(), a.into(), b.into(), s.into()]);
            assert_eq!(n.unwrap_or_else(|e| panic!("{ep} row {id}: {e}")), 1);
        }
        // one digit past a column's precision: refused by the server, never rounded
        assert!(c.execute(&format!("INSERT INTO {t} (id, s) VALUES (9, $1)"), &[Decimal::new(10, 0).unwrap().into()]).is_err());
        let r = q(&mut c, &format!("SELECT a, b, s FROM {t} ORDER BY id"));
        let scales: Vec<u16> = r.columns.as_ref().unwrap().cols().iter().map(|c| c.scale).collect();
        assert_eq!(scales, vec![0, 38, 0], "{ep}");
        for (k, (_, a, b, s)) in rows.iter().enumerate() {
            assert_eq!(r.rows[k].get::<Decimal>(0).unwrap(), *a, "{ep} {k}");
            assert_eq!(r.rows[k].get::<Decimal>(1).unwrap(), *b, "{ep} {k}");
            assert_eq!(r.rows[k].get::<Decimal>(2).unwrap(), *s, "{ep} {k}");
        }
        assert_eq!(r.rows[0].get::<Decimal>(0).unwrap().to_string(), "9".repeat(38));
        assert_eq!(r.rows[1].get::<Decimal>(1).unwrap().to_string(), format!("-0.{}", "9".repeat(38)));
        assert_eq!(r.rows[2].get::<Decimal>(1).unwrap().to_string(), format!("0.{}1", "0".repeat(37)));
        // the server's own texts and this driver's agree: a UUID in RFC 4122's byte order, a BYTEA's bytes
        let r = q(&mut c, "SELECT CAST('00010203-0405-0607-0809-0a0b0c0d0e0f' AS UUID), CAST('\\x00ff10' AS BYTEA)");
        let u: Uuid = r.rows[0].get(0).unwrap();
        assert_eq!(u.to_string(), "00010203-0405-0607-0809-0a0b0c0d0e0f");
        assert_eq!(u.0, [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]);
        assert_eq!(r.rows[0].get::<Vec<u8>>(1).unwrap(), vec![0x00, 0xff, 0x10]);
        // and a parameter compared with the server's literal of the same value
        let r = q(&mut c, "SELECT CAST('00010203-0405-0607-0809-0a0b0c0d0e0f' AS UUID) = CAST('00010203-0405-0607-0809-0a0b0c0d0e0f' AS UUID)");
        assert_eq!(r.rows[0].get::<bool>(0).unwrap(), true);
        let r = c.query("SELECT $1 = CAST('00010203-0405-0607-0809-0a0b0c0d0e0f' AS UUID)", &[u.into()]).unwrap();
        assert_eq!(r.rows[0].get::<bool>(0).unwrap(), true, "{ep}");
    }
}

#[test]
fn float64_bit_exact() {
    if !live() {
        return;
    }
    for (ep, cfg) in endpoints() {
        let mut c = connect(&cfg);
        let t = format!("fl_{ep}");
        q(&mut c, &format!("CREATE TABLE {t} (id BIGINT PRIMARY KEY, f DOUBLE PRECISION)"));
        let vals = [
            1.0 / 3.0,
            0.1,
            std::f64::consts::PI,
            f64::from_bits(1),
            f64::MAX,
            f64::MIN,
            -2.5e-308,
            f64::MIN_POSITIVE,
            0.0,
            1e300 * 1e-10,
            f64::from_bits(0x3fefffffffffffff),
        ];
        for (k, v) in vals.iter().enumerate() {
            c.execute(&format!("INSERT INTO {t} VALUES ($1, $2)"), &[Value::Int64(k as i64), Value::Float64(*v)]).unwrap();
        }
        let r = q(&mut c, &format!("SELECT f FROM {t} ORDER BY id"));
        for (k, v) in vals.iter().enumerate() {
            assert_eq!(r.rows[k].get::<f64>(0).unwrap().to_bits(), v.to_bits(), "{ep} {k}");
        }
        // -0 and the non-finite values are refused by the encoder: nothing sent, the connection usable
        for bad in [-0.0f64, f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
            assert!(matches!(c.query("SELECT $1", &[Value::Float64(bad)]), Err(Error::Invalid(_))));
        }
        assert_eq!(one_i64(&mut c, "SELECT 7"), 7);
    }
}

#[test]
fn batch_stops_at_its_error() {
    if !live() {
        return;
    }
    for (ep, cfg) in endpoints() {
        let mut c = connect(&cfg);
        let t = format!("bt_{ep}");
        let st = |s: &str| Statement { sql: s.to_string(), params: vec![] };
        let b = c
            .batch(&[
                st(&format!("CREATE TABLE {t} (k BIGINT PRIMARY KEY, v TEXT)")),
                Statement { sql: format!("INSERT INTO {t} VALUES ($1, $2)"), params: vec![Value::Int64(1), "one".into()] },
                st(&format!("INSERT INTO {t} VALUES (1, 'again')")),
                st(&format!("INSERT INTO {t} VALUES (2, 'never')")),
            ])
            .unwrap();
        assert_eq!(b.results.len(), 2, "{ep}");
        let e = b.error.clone().expect("the duplicate key's ERROR");
        assert_eq!((e.index, e.kind()), (2, ErrorCode::Constraint), "{ep}: {e}");
        assert_eq!(b.state, TxnState::Idle);
        assert_eq!(b.results[1].done.count, 1);
        assert!(b.results[1].done.write.as_ref().is_some_and(|w| w.commit >= 1), "an INSERT's own commit");
        assert_eq!(one_i64(&mut c, &format!("SELECT COUNT(*) FROM {t}")), 1, "the statement after the ERROR never ran");
        // a statement error's code and index through query()
        match c.query("SELECT 1 / 0", &[]) {
            Err(Error::Server(e)) => assert_eq!(e.index, 0),
            r => panic!("{ep}: {r:?}"),
        }
        match c.query("SELEC 1", &[]) {
            Err(Error::Server(e)) => assert_eq!(e.kind(), ErrorCode::Syntax),
            r => panic!("{ep}: {r:?}"),
        }
        // a read's point: the commit, its hash, the digest, the database's id
        let r = q(&mut c, &format!("SELECT v FROM {t}"));
        let p = r.done.read.as_ref().expect("a read point");
        assert!(p.commit >= 1 && p.db_id != [0; 16], "{ep}");
        assert_eq!(r.done.count, 1);
        c.ping().unwrap();
    }
}

#[test]
fn prepared_statements() {
    if !live() {
        return;
    }
    for (ep, cfg) in endpoints() {
        let mut c = connect(&cfg);
        let t = format!("pr_{ep}");
        q(&mut c, &format!("CREATE TABLE {t} (k BIGINT PRIMARY KEY, v TEXT, d DECIMAL(10,2))"));
        c.prepare("ins", &format!("INSERT INTO {t} VALUES ($1, $2, $3)")).unwrap();
        let sets: Vec<Vec<Value>> = (1..=3)
            .map(|k| vec![Value::Int64(k), Value::Text(format!("v{k}")), Value::Decimal(Decimal::new(k as i128 * 150, 2).unwrap())])
            .collect();
        let b = c.execute_prepared("ins", &sets).unwrap();
        assert!(b.error.is_none() && b.results.len() == 3 && b.results.iter().all(|r| r.done.count == 1), "{ep}");
        // a failing set ends the sets: its index named
        let sets2 = vec![
            vec![Value::Int64(4), "v4".into(), Value::Null(Type::Decimal)],
            vec![Value::Int64(1), "dup".into(), Value::Null(Type::Decimal)],
            vec![Value::Int64(5), "v5".into(), Value::Null(Type::Decimal)],
        ];
        let b = c.execute_prepared("ins", &sets2).unwrap();
        assert_eq!(b.results.len(), 1);
        assert_eq!(b.error.as_ref().map(|e| e.index), Some(1), "{ep}");
        // an INT64 into a DECIMAL column binds as its literal (N1b's rule): exact
        c.execute_prepared("ins", &[vec![Value::Int64(6), "v6".into(), Value::Int64(7)]]).unwrap().into_result().unwrap();
        c.prepare("sel", &format!("SELECT v, d FROM {t} WHERE k = $1")).unwrap();
        let b = c.execute_prepared("sel", &[vec![Value::Int64(2)], vec![Value::Int64(6)], vec![Value::Int64(99)]]).unwrap();
        let rs = b.into_result().unwrap();
        assert_eq!(rs[0].rows[0].get::<String>(0).unwrap(), "v2");
        assert_eq!(rs[0].rows[0].get::<Decimal>(1).unwrap().to_string(), "3.00");
        assert_eq!(rs[1].rows[0].get::<Decimal>(1).unwrap().to_string(), "7.00");
        assert!(rs[2].rows.is_empty() && rs[2].columns.is_some());
        c.deallocate("ins").unwrap();
        assert!(matches!(c.execute_prepared("ins", &[vec![Value::Int64(9), "x".into(), Value::Null(Type::None)]]).unwrap().error, Some(_)));
        assert!(matches!(c.deallocate("ins"), Err(Error::Server(_))));
        assert_eq!(one_i64(&mut c, &format!("SELECT COUNT(*) FROM {t}")), 5);
    }
}

#[test]
fn transactions_and_ready_states() {
    if !live() {
        return;
    }
    for (ep, cfg) in endpoints() {
        let mut a = connect(&cfg);
        let mut b = connect(&cfg);
        let t = format!("tx_{ep}");
        q(&mut a, &format!("CREATE TABLE {t} (id BIGINT PRIMARY KEY, v BIGINT)"));
        q(&mut a, &format!("INSERT INTO {t} VALUES (1, 0)"));
        assert_eq!(a.state(), TxnState::Idle);
        q(&mut a, "BEGIN");
        assert_eq!(a.state(), TxnState::InTransaction);
        q(&mut a, &format!("INSERT INTO {t} VALUES (2, 2)"));
        assert!(a.query(&format!("INSERT INTO {t} VALUES (2, 3)"), &[]).is_err());
        assert_eq!(a.state(), TxnState::InTransaction, "{ep}: a statement's error undoes it alone");
        // inside its transaction a read sees its own writes (DONE's own flag)
        let r = q(&mut a, &format!("SELECT COUNT(*) FROM {t}"));
        assert!(r.done.read.as_ref().unwrap().own);
        assert_eq!(one_i64(&mut b, &format!("SELECT COUNT(*) FROM {t}")), 1);
        let r = q(&mut a, "COMMIT");
        assert_eq!(a.state(), TxnState::Idle);
        assert!(r.done.write.is_some());
        assert_eq!(one_i64(&mut b, &format!("SELECT COUNT(*) FROM {t}")), 2);
        q(&mut a, "BEGIN");
        q(&mut a, &format!("UPDATE {t} SET v = 9 WHERE id = 1"));
        q(&mut a, "ROLLBACK");
        assert_eq!(one_i64(&mut b, &format!("SELECT v FROM {t} WHERE id = 1")), 0);
        // a batch is not a transaction, but a batch's ERROR keeps a transaction open (READY 1) and its COMMIT unrun
        let st = |s: String| Statement { sql: s, params: vec![] };
        let br = a.batch(&[st("BEGIN".into()), st(format!("INSERT INTO {t} VALUES (3, 3)")), st(format!("INSERT INTO {t} VALUES (3, 3)")), st("COMMIT".into())]).unwrap();
        assert_eq!((br.error.map(|e| e.index), br.state), (Some(2), TxnState::InTransaction));
        q(&mut a, "ROLLBACK");
        // a doomed transaction: idle past its limit, it takes only ROLLBACK (READY 2)
        q(&mut b, "SET idle_in_transaction_timeout = 100");
        q(&mut b, "BEGIN");
        q(&mut b, &format!("UPDATE {t} SET v = 5 WHERE id = 1"));
        std::thread::sleep(Duration::from_millis(1500));
        let r = b.query(&format!("SELECT v FROM {t}"), &[]);
        assert!(r.is_err(), "{ep}");
        assert_eq!(b.state(), TxnState::Doomed, "{ep}");
        q(&mut b, "ROLLBACK");
        assert_eq!(b.state(), TxnState::Idle);
    }
}

/// A CSV of n rows (k, k mod 1000) for COPY.
struct Gen {
    k: u64,
    n: u64,
    buf: Vec<u8>,
    at: usize,
}

impl Read for Gen {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if self.at == self.buf.len() {
            if self.k >= self.n {
                return Ok(0);
            }
            self.buf.clear();
            self.at = 0;
            while self.k < self.n && self.buf.len() < 60000 {
                self.buf.extend_from_slice(format!("{},{}\n", self.k, self.k % 1000).as_bytes());
                self.k += 1;
            }
        }
        let m = out.len().min(self.buf.len() - self.at);
        out[..m].copy_from_slice(&self.buf[self.at..self.at + m]);
        self.at += m;
        Ok(m)
    }
}

/// A reader that fails after some bytes.
struct Failing(usize);

impl Read for Failing {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if self.0 == 0 {
            return Err(io::Error::other("the source broke"));
        }
        let m = out.len().min(self.0).min(10);
        out[..m].copy_from_slice(&b"1,1\n2,2\n3,"[..m]);
        self.0 -= m;
        Ok(m)
    }
}

#[test]
fn copy_both_ways() {
    if !live() {
        return;
    }
    for (ep, cfg) in endpoints() {
        let mut c = connect(&cfg);
        let t = format!("cp_{ep}");
        q(&mut c, &format!("CREATE TABLE {t} (k BIGINT PRIMARY KEY, v BIGINT)"));
        let n = 200_000;
        let d = c.copy_in(&format!("COPY {t} FROM STDIN"), &mut Gen { k: 0, n, buf: vec![], at: 0 }).unwrap();
        assert_eq!(d.count, n, "{ep}");
        assert_eq!(one_i64(&mut c, &format!("SELECT COUNT(*) FROM {t}")), n as i64);
        let mut out = Vec::new();
        let d = c.copy_out(&format!("COPY {t} TO STDOUT"), &mut out).unwrap();
        assert_eq!(d.count, n);
        let mut want = Vec::new();
        Gen { k: 0, n, buf: vec![], at: 0 }.read_to_end(&mut want).unwrap();
        let (mut a, mut b): (Vec<&[u8]>, Vec<&[u8]>) = (out.split(|&x| x == b'\n').collect(), want.split(|&x| x == b'\n').collect());
        a.sort();
        b.sort();
        assert_eq!(a, b, "{ep}: COPY TO's rows are COPY FROM's");
        // refused before its data: no COPY_IN, nothing sent
        match c.copy_in("COPY no_such_table FROM STDIN", &mut &b"1,1\n"[..]) {
            Err(Error::Server(e)) => assert!(e.code > 0),
            r => panic!("{ep}: {r:?}"),
        }
        // an error in the data is answered after COPY_DONE; the table unchanged
        let r = c.copy_in(&format!("COPY {t} FROM STDIN"), &mut &b"9999999,1\nnot-a-number,2\n"[..]);
        assert!(matches!(r, Err(Error::Server(_))), "{ep}: {r:?}");
        // the source failing part way: COPY_FAIL, the statement refused unrun, the read's error returned
        let r = c.copy_in(&format!("COPY {t} FROM STDIN"), &mut Failing(25));
        assert!(matches!(&r, Err(Error::Io(e)) if e.to_string().contains("the source broke")), "{ep}: {r:?}");
        assert_eq!(one_i64(&mut c, &format!("SELECT COUNT(*) FROM {t}")), n as i64);
        // a COPY FROM STDIN through query(): failed by the driver (it has no data), never left waiting
        let r = c.query(&format!("COPY {t} FROM STDIN"), &[]);
        assert!(matches!(&r, Err(Error::Server(e)) if e.kind() == ErrorCode::Cancelled), "{ep}: {r:?}");
        // COPY TO through query(): its bytes in the result
        let r = q(&mut c, &format!("COPY (SELECT k FROM {t} WHERE k < 3 ORDER BY k) TO STDOUT"));
        assert_eq!(r.copy_data, b"0\n1\n2\n");
        assert_eq!(one_i64(&mut c, "SELECT 5"), 5);
    }
}

#[test]
fn cancel_from_another_thread() {
    if !live() {
        return;
    }
    let mut setup = connect(&socket_a());
    let big = "cn_big";
    q(&mut setup, &format!("CREATE TABLE {big} (k BIGINT PRIMARY KEY, v BIGINT)"));
    let d = setup.copy_in(&format!("COPY {big} FROM STDIN"), &mut Gen { k: 0, n: 1_000_000, buf: vec![], at: 0 }).unwrap();
    assert_eq!(d.count, 1_000_000);
    for (ep, cfg) in endpoints() {
        let mut c = connect(&cfg);
        q(&mut c, "SET statement_timeout = 30000"); // the backstop: a cancel that failed ends anyway, late
        // a cancel with nothing outstanding is dropped: the next statement is not cancelled
        c.canceller().cancel();
        assert_eq!(one_i64(&mut c, "SELECT 3"), 3, "{ep}");
        let k = c.canceller();
        let t0 = Instant::now();
        let th = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(500));
            k.cancel();
        });
        let r = c.query(&format!("SELECT COUNT(*) FROM {big} AS a, {big} AS b WHERE a.v + b.v = -1"), &[]);
        let took = t0.elapsed();
        th.join().unwrap();
        match r {
            Err(Error::Server(e)) => assert_eq!(e.kind(), ErrorCode::Cancelled, "{ep}: {e}"),
            r => panic!("{ep}: {r:?}"),
        }
        assert!(took < Duration::from_secs(20), "{ep}: the cancel ended it ({took:?})");
        assert_eq!(c.state(), TxnState::Idle);
        c.ping().unwrap();
        assert_eq!(one_i64(&mut c, "SELECT 4"), 4);
        // a row consumer that stops: its error returned, the statement cancelled, the connection usable
        let mut seen = 0;
        let r = c.query_each(&format!("SELECT k FROM {big}"), &[], |_row| {
            seen += 1;
            if seen == 1000 { Err(Error::Invalid("enough".into())) } else { Ok(()) }
        });
        assert!(matches!(r, Err(Error::Invalid(_))), "{ep}: {r:?}");
        let mut n = 0u64;
        let d = c.query_each(&format!("SELECT k, v FROM {big} WHERE k < 300000"), &[], |row| {
            assert_eq!(row.len(), 2);
            n += 1;
            Ok(())
        }).unwrap();
        assert_eq!((n, d.count), (300000, 300000), "{ep}: rows over many frames");
    }
}

#[test]
fn pipelined_requests() {
    if !live() {
        return;
    }
    for (ep, cfg) in endpoints() {
        let mut c = connect(&cfg);
        let conn = c.connection();
        for k in 0..3 {
            conn.send(&Msg::Query(vec![Statement { sql: format!("SELECT {k}"), params: vec![] }])).unwrap();
        }
        conn.send(&Msg::Ping).unwrap();
        assert_eq!(conn.outstanding(), 3);
        let mut seen = vec![];
        let mut pong = false;
        let mut readies = 0;
        while readies < 3 || !pong {
            match conn.next().unwrap() {
                Msg::Rows(r) => seen.push(r.iter().next().unwrap()[0].clone()),
                Msg::Ready(_) => readies += 1,
                Msg::Pong => pong = true,
                _ => {}
            }
        }
        assert_eq!(seen, vec![Value::Int64(0), Value::Int64(1), Value::Int64(2)], "{ep}");
        assert_eq!(conn.outstanding(), 0);
    }
}

fn session_ids(c: &mut Client) -> Vec<u64> {
    c.sessions().unwrap().iter().map(|s| s.id).collect()
}

#[test]
fn sessions_kill_and_closed_reason() {
    if !live() {
        return;
    }
    for (ep, cfg) in endpoints() {
        let mut a = connect(&cfg);
        let before = session_ids(&mut a);
        let mut b = connect(&cfg);
        let list = a.sessions().unwrap();
        let bid = *list.iter().map(|s| &s.id).filter(|id| !before.contains(id)).max().expect("b's session");
        let me = list.iter().find(|s| s.id == bid).unwrap();
        assert_eq!(me.name, user());
        assert_eq!(me.endpoint, if ep == "sock" { 2 } else { 1 }, "{ep}");
        assert!(list.windows(2).all(|w| w[0].id < w[1].id));
        // no such session
        assert_eq!(a.kill(u64::MAX, KillKind::Cancel).unwrap(), KillOutcome::NoSuchSession);
        // a cancel of an idle session: done, and nothing of it reaches b's next statement
        assert_eq!(a.kill(bid, KillKind::Cancel).unwrap(), KillOutcome::Done);
        assert_eq!(one_i64(&mut b, "SELECT 8"), 8, "{ep}");
        // terminate: b's next request meets the server's words ("ended by a KILL", code 15), as a reply or as the
        // reason of its failed send
        assert_eq!(a.kill(bid, KillKind::Terminate).unwrap(), KillOutcome::Done);
        let r = b.query("SELECT 1", &[]);
        let e = r.err().expect("a terminated session answered");
        assert_eq!(e.code(), 15, "{ep}: {e}");
        assert!(e.to_string().contains("KILL"), "{ep}: {e}");
        // closed_reason's own path: wait out the lingering close (1 s), then send. On the socket the send itself
        // fails and the last frame read is the KILL's ERROR; over TCP the kernel may take the first write, and the
        // words (or the plain error) come on the read
        let mut c2 = connect(&cfg);
        let cid = session_ids(&mut a).into_iter().max().unwrap();
        assert_eq!(a.kill(cid, KillKind::Terminate).unwrap(), KillOutcome::Done);
        std::thread::sleep(Duration::from_millis(1600));
        let e = c2.query("SELECT 1", &[]).err().expect("answered after the close");
        if ep == "sock" {
            assert!(matches!(&e, Error::Closed(se) if se.code == 15 && se.message.contains("KILL")), "{ep}: {e:?}");
        } else {
            assert!(e.code() == 15 || matches!(e, Error::Io(_)), "{ep}: {e:?}");
        }
        // a failing statement and TERMINATE pipelined unread: the last frame before the close is READY, so a later
        // send's error is the plain I/O one, never that statement's ERROR taken for the reason
        let mut d = connect(&cfg);
        d.connection().send(&Msg::Query(vec![Statement { sql: "SELECT 1 / 0".into(), params: vec![] }])).unwrap();
        d.connection().send(&Msg::Terminate).unwrap();
        std::thread::sleep(Duration::from_millis(1600));
        let mut e = d.connection().send(&Msg::Query(vec![Statement { sql: "SELECT 1".into(), params: vec![] }])).err();
        if e.is_none() {
            // TCP: the write taken by the kernel; the read then meets the replies and the close
            loop {
                match d.connection().next() {
                    Ok(_) => {}
                    Err(x) => {
                        e = Some(x);
                        break;
                    }
                }
            }
        }
        let e = e.unwrap();
        assert!(matches!(e, Error::Io(_)), "{ep}: {e:?}");
        assert_eq!(one_i64(&mut a, "SELECT 9"), 9);
    }
}

#[test]
fn rows_held_to_their_statement() {
    if !live() {
        return;
    }
    // the protocol's level: COLUMNS then ROWS then DONE; the ROWS' values Arc'd to their COLUMNS
    let mut c = connect(&socket_a());
    let conn = c.connection();
    conn.send(&Msg::Query(vec![Statement { sql: "SELECT 1 AS one, 'x' AS ex".into(), params: vec![] }])).unwrap();
    let mut cols = None;
    loop {
        match conn.next().unwrap() {
            Msg::Columns(cc) => cols = Some(cc),
            Msg::Rows(r) => assert!(Arc::ptr_eq(r.columns(), cols.as_ref().unwrap())),
            Msg::Ready(_) => break,
            _ => {}
        }
    }
    assert_eq!(cols.unwrap().cols()[1].name, "ex");
}

#[test]
fn randomness_differs_per_connection() {
    if !live() {
        return;
    }
    // each login's SCRAM nonce from the operating system: two connections' differ, neither is zeros
    let mut s1 = connect(&socket_a());
    let mut s2 = connect(&socket_a());
    let (a, b) = (s1.connection().login_info().scram_nonce, s2.connection().login_info().scram_nonce);
    assert_ne!(a, b);
    assert_ne!(a, [0; 32]);
    assert_ne!(b, [0; 32]);
}

/// A COPY source that hands out its rows slowly (a pause before each piece): an upload long enough for a cancel to land
/// in the middle of it.
struct Slow {
    inner: Gen,
    pause: Duration,
    reads: u32,
}

impl Read for Slow {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        std::thread::sleep(self.pause);
        self.reads += 1;
        let n = out.len().min(4096);
        self.inner.read(&mut out[..n])
    }
}

#[test]
fn cancel_during_a_copy_upload() {
    if !live() {
        return;
    }
    // §4: a cancel asked while the client sends a COPY's data goes out before its next frame, and the COPY is refused
    // unrun (ERROR 15), the rest of its data read and dropped by the server; the table is unchanged and the connection
    // usable after the client's COPY_DONE
    for (ep, cfg) in endpoints() {
        let mut c = connect(&cfg);
        let t = format!("cu_{ep}");
        q(&mut c, &format!("CREATE TABLE {t} (k BIGINT PRIMARY KEY, v BIGINT)"));
        let k = c.canceller();
        let th = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(400));
            k.cancel();
        });
        // about 50 pieces of 4 KiB, 20 ms apart: an upload of a second or more, the cancel at 400 ms inside it
        let mut src = Slow { inner: Gen { k: 0, n: 20_000, buf: vec![], at: 0 }, pause: Duration::from_millis(20), reads: 0 };
        let t0 = Instant::now();
        let r = c.copy_in(&format!("COPY {t} FROM STDIN"), &mut src);
        let took = t0.elapsed();
        th.join().unwrap();
        match &r {
            Err(Error::Server(e)) => assert_eq!(e.kind(), ErrorCode::Cancelled, "{ep}: {e}"),
            r => panic!("{ep}: {r:?}"),
        }
        assert!(src.reads >= 40 && took > Duration::from_millis(700), "{ep}: the cancel landed mid-upload ({} reads, {took:?})", src.reads);
        assert_eq!(one_i64(&mut c, &format!("SELECT COUNT(*) FROM {t}")), 0, "{ep}: the COPY ran");
        assert_eq!(c.state(), TxnState::Idle);
    }
}

#[test]
fn kill_cancels_a_running_statement() {
    if !live() {
        return;
    }
    // KILL's cancel from another session reaches a statement running on the engine thread (ERROR 15 to its session),
    // and the killed session goes on; then a KILL's terminate while a statement runs: its session meets the server's
    // words ("ended by a KILL") and the close
    for (ep, cfg) in endpoints() {
        let mut a = connect(&cfg);
        let big = format!("kl_{ep}");
        q(&mut a, &format!("CREATE TABLE {big} (k BIGINT PRIMARY KEY, v BIGINT)"));
        a.copy_in(&format!("COPY {big} FROM STDIN"), &mut Gen { k: 0, n: 200_000, buf: vec![], at: 0 }).unwrap();
        for kind in [KillKind::Cancel, KillKind::Terminate] {
            let before: Vec<u64> = a.sessions().unwrap().iter().map(|s| s.id).collect();
            let mut b = connect(&cfg);
            let bid = a.sessions().unwrap().iter().map(|s| s.id).filter(|id| !before.contains(id)).max().expect("b's id");
            q(&mut b, "SET statement_timeout = 30000"); // the backstop
            let sql = format!("SELECT COUNT(*) FROM {big} AS x, {big} AS y WHERE x.v + y.v = -1");
            let th = std::thread::spawn(move || {
                let t0 = Instant::now();
                let r = b.query(&sql, &[]);
                (r.map(|_| ()), t0.elapsed(), b)
            });
            // wait until SESSIONS shows b's request (state 1), 3 s at most, then let it run a little: a KILL reaches the
            // request b runs now, has begun or runs next (§4), so the wait only makes the case the running one
            let t0 = Instant::now();
            while !a.sessions().unwrap().iter().any(|s| s.id == bid && s.state == 1) && t0.elapsed() < Duration::from_secs(3) {
                std::thread::sleep(Duration::from_millis(20));
            }
            std::thread::sleep(Duration::from_millis(300));
            assert_eq!(a.kill(bid, kind).unwrap(), KillOutcome::Done, "{ep}");
            let (r, took, mut b) = th.join().unwrap();
            let e = r.err().expect("a killed statement answered");
            assert_eq!(e.code(), 15, "{ep} {kind:?}: {e}");
            assert!(took < Duration::from_secs(20), "{ep} {kind:?}: the KILL ended it ({took:?})");
            match kind {
                KillKind::Cancel => {
                    assert!(matches!(e, Error::Server(_)), "{ep}: {e:?}");
                    assert_eq!(one_i64(&mut b, "SELECT 21"), 21, "{ep}: the session goes on after a KILL's cancel");
                }
                KillKind::Terminate => {
                    // the server's words come with the statement's end, or (were the statement's own ERROR sent
                    // first) as the next request's reply or its failed send's reason
                    let e2 = b.query("SELECT 1", &[]).err().expect("a terminated session answered");
                    assert!(e.to_string().contains("KILL") || e2.to_string().contains("KILL"), "{ep}: {e} / {e2}");
                    eprintln!("    {ep}: terminate while running: {e} / then: {e2}");
                }
            }
        }
    }
}

#[test]
fn show_rows_decode() {
    if !live() {
        return;
    }
    // §4: SHOW's rows may come under columns of no known type (0), each value carrying its own; whatever the server
    // sends decodes, and the types are printed (what the frozen server sends, recorded)
    let mut c = connect(&socket_a());
    for sql in ["SHOW TABLES", "SHOW STATS", "SHOW ROLES"] {
        let r = q(&mut c, sql);
        let cols = r.columns.as_ref().unwrap_or_else(|| panic!("{sql}: no COLUMNS"));
        let types: Vec<String> = cols.cols().iter().map(|c| format!("{}:{:?}", c.name, c.ty)).collect();
        assert!(!r.rows.is_empty(), "{sql}: no rows");
        for row in &r.rows {
            assert_eq!(row.len(), cols.len());
            for (i, v) in row.values().iter().enumerate() {
                let ct = cols.cols()[i].ty;
                assert!(ct == Type::None || v.ty() == ct, "{sql}: column {i} {ct:?} holds a {:?}", v.ty());
            }
        }
        eprintln!("    {sql}: {} rows; columns {}", r.rows.len(), types.join(", "));
    }
}
