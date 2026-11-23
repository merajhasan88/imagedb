//! The codec against the C reference's vectors: the repository's tests/unit/t_wire.c (each block names its line
//! range there) and docs/n1-design.md §4's pinned SCRAM exchanges. Where t_wire.c builds a message as a C struct rather
//! than bytes, the test here mirrors it and checks the same property (marked "property").
mod common;

use std::sync::Arc;

use common::{hex, hexs};
use imagedb::wire::{self, Challenge, Column, Columns, Hello, Msg, Rows, Statement, Verdict};
use imagedb::*;

fn is_limit(e: &Error) -> bool {
    matches!(e, Error::Protocol { limit: true, .. })
}

fn uuid16() -> Uuid {
    Uuid([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15])
}

/// t_wire.c lines 55-84 (kVecs): each type's bytes, the contract the drivers keep.
fn vectors() -> Vec<(Value, &'static str)> {
    vec![
        (Value::Null(Type::None), "80"),
        (Value::Null(Type::Int64), "81"),
        (Value::Null(Type::Decimal), "85"),
        (Value::Null(Type::Enum), "8d"),
        (Value::Int64(-2), "01 feffffffffffffff"),
        (Value::Int64(i64::MIN), "01 0000000000000080"),
        (Value::Float64(f64::from_bits(0x3ff8000000000000)), "02 000000000000f83f"),
        (Value::Float64(0.0), "02 0000000000000000"),
        (Value::Bool(true), "03 01"),
        (Value::Bool(false), "03 00"),
        (Value::Text("h\u{e9}".into()), "04 03000000 68c3a9"),
        (Value::Text("".into()), "04 00000000"),
        (Value::Decimal(Decimal::new(-12345, 2).unwrap()), "05 02 c7cfffffffffffffffffffffffffffff"),
        (Value::Decimal(Decimal::new(0, 0).unwrap()), "05 00 00000000000000000000000000000000"),
        (Value::Timestamp(Timestamp::from_micros(1).unwrap()), "06 0100000000000000"),
        (Value::Timestamp(Timestamp::from_micros(-62135596800000000).unwrap()), "06 0040d400014023ff"),
        (Value::TimestampTz(TimestampTz::from_micros(-1).unwrap()), "07 ffffffffffffffff"),
        (Value::TimestampTz(TimestampTz::from_micros(253402300799999999).unwrap()), "07 ff5f73cc0c448403"),
        (Value::Date(Date::from_days(-719162).unwrap()), "08 c606f5ff"),
        (Value::Date(Date::from_days(2932896).unwrap()), "08 a0c02c00"),
        (Value::Time(Time::from_micros(0).unwrap()), "09 0000000000000000"),
        (Value::Time(Time::from_micros(86399999999).unwrap()), "09 ff5fd71d14000000"),
        (Value::Uuid(uuid16()), "0a 000102030405060708090a0b0c0d0e0f"),
        (Value::Bytea(vec![0, 0xff]), "0b 02000000 00ff"),
        (Value::Interval(Interval::new(1, -2, 3)), "0c 01000000 feffffff 0300000000000000"),
        (Value::Interval(Interval::new(i32::MIN, i32::MAX, i64::MIN)), "0c 00000080 ffffff7f 0000000000000080"),
        (Value::Enum("a".into()), "0d 01 61"),
        (Value::Enum("".into()), "0d 00"),
    ]
}

#[test]
fn value_vectors() {
    for (k, (v, h)) in vectors().iter().enumerate() {
        let want = hex(h);
        assert_eq!(wire::encode_value(v).unwrap(), want, "vector {k}");
        assert_eq!(&wire::decode_value(&want).unwrap(), v, "vector {k}");
        for cut in 0..want.len() {
            assert!(wire::decode_value(&want[..cut]).is_err(), "vector {k}: a prefix of {cut} taken");
        }
    }
    // §4's own table, every row's vector (docs/n1-design.md lines 272-285, the "Values" table, as of 2026-11-22), built
    // from the native value its row names, encoded and decoded both ways
    let table: Vec<(Value, &str)> = vec![
        (Value::Null(Type::Int64), "81"),
        (Value::Int64(-2), "01 feffffffffffffff"),
        (Value::Float64(1.5), "02 000000000000f83f"),
        (Value::Bool(true), "03 01"),
        (Value::Text("h\u{e9}".into()), "04 03000000 68c3a9"),
        (Value::Decimal("-123.45".parse().unwrap()), "05 02 c7cfffffffffffffffffffffffffffff"),
        (Value::Timestamp(Timestamp::from_parts(Date::from_ymd(1, 1, 1).unwrap(), Time::from_micros(0).unwrap())), "06 0040d400014023ff"),
        (
            Value::TimestampTz(TimestampTz::from_parts(
                Date::from_ymd(9999, 12, 31).unwrap(),
                Time::from_hms_micro(23, 59, 59, 999_999).unwrap(),
            )),
            "07 ff5f73cc0c448403",
        ),
        (Value::Date(Date::from_ymd(1, 1, 1).unwrap()), "08 c606f5ff"),
        (Value::Time(Time::from_hms_micro(23, 59, 59, 999_999).unwrap()), "09 ff5fd71d14000000"),
        (Value::Uuid("00010203-0405-0607-0809-0a0b0c0d0e0f".parse().unwrap()), "0a 000102030405060708090a0b0c0d0e0f"),
        (Value::Bytea(vec![0x00, 0xff]), "0b 02000000 00ff"),
        (Value::Interval(Interval::new(1, -2, 3)), "0c 01000000 feffffff 0300000000000000"),
        (Value::Enum("a".into()), "0d 01 61"),
    ];
    for (v, h) in &table {
        assert_eq!(wire::encode_value(v).unwrap(), hex(h), "§4's vector for {v:?}");
        assert_eq!(&wire::decode_value(&hex(h)).unwrap(), v, "§4's vector {h}");
    }
    // the dates and timestamps by their civil names
    assert_eq!(Date::from_ymd(1, 1, 1).unwrap().days(), -719162);
    assert_eq!(Date::from_ymd(9999, 12, 31).unwrap().days(), 2932896);
    assert_eq!(Date::from_days(-719162).unwrap().to_string(), "0001-01-01");
    assert_eq!(TimestampTz::from_micros(253402300799999999).unwrap().to_string(), "9999-12-31 23:59:59.999999+00");
    assert_eq!(Time::from_micros(86399999999).unwrap().to_string(), "23:59:59.999999");
}

#[test]
fn decimal_range() {
    // t_wire.c lines 105-116: 10^38 - 1 and its negation taken, 10^38 and -10^38 refused, scale 39 refused
    let lim: i128 = 100_000_000_000_000_000_000_000_000_000_000_000_000;
    for (k, d) in [lim - 1, -(lim - 1), lim, -lim].into_iter().enumerate() {
        let mut x = vec![5u8, 38];
        x.extend_from_slice(&d.to_le_bytes());
        assert_eq!(wire::decode_value(&x).is_ok(), k < 2, "case {k}");
        x[1] = 39;
        assert!(wire::decode_value(&x).is_err());
    }
    assert!(Decimal::new(lim, 0).is_err() && Decimal::new(0, 39).is_err());
    // exact text both ways
    for s in ["0", "-1", "123.4500", "-0.001", "99999999999999999999999999999999999999", "0.00000000000000000000000000000000000001"] {
        assert_eq!(s.parse::<Decimal>().unwrap().to_string(), s);
    }
    for s in ["", ".", "-", "1e5", "1.2.3", "100000000000000000000000000000000000000", "0.000000000000000000000000000000000000001"] {
        assert!(s.parse::<Decimal>().is_err(), "{s}");
    }
}

#[test]
fn values_refused() {
    // t_wire.c lines 122-144
    let refused = [
        "03 02", "02 000000000000f07f", "02 000000000000f0ff", "02 010000000000f87f", "02 0000000000000080",
        "06 ff3fd400014023ff", "07 006073cc0c448403", "09 ffffffffffffffff", "09 0060d71d14000000", "08 c506f5ff",
        "08 a1c02c00", "04 01000000 ff", "04 01000000 00", "04 02000000 c0af", "0d 01 c3", "0d 01 00", "0e", "00", "8e",
        "ff", "",
    ];
    for h in refused {
        assert!(wire::decode_value(&hex(h)).is_err(), "taken: {h}");
    }
    // lines 152-159: a length past its bound refused before its bytes (LIMIT)
    for h in ["04 00000100", "0b 00000100", "0d 40"] {
        assert!(is_limit(&wire::decode_value(&hex(h)).unwrap_err()), "{h}");
    }
    // lines 161-175: the encoder refuses what the decoder would. Those Rust's types can hold are tried; the rest
    // (a BOOL of 2, TEXT not UTF-8, a UUID of 15 bytes, type 14, a value of no type) cannot be built at all.
    let no = [
        Value::Float64(f64::from_bits(0x8000000000000000)),
        Value::Float64(f64::NAN),
        Value::Float64(f64::INFINITY),
        Value::Text("a\0b".into()),
        Value::Text("x".repeat(65536)),
        Value::Enum("0123456789012345678901234567890123456789012345678901234567890123".into()),
        Value::Enum("\0".into()),
    ];
    for v in &no {
        assert!(wire::encode_value(v).is_err(), "{v:?}");
    }
    assert!(Decimal::new(0, 39).is_err());
    assert!(Date::from_days(2932897).is_err());
    assert!(Timestamp::from_micros(i64::MAX).is_err());
    assert!(wire::encode_value(&Value::Text("x".repeat(65535))).is_ok());
}

#[test]
fn utf8_fit() {
    // t_wire.c lines 186-197
    let s = "ab\u{e9}c\u{20ac}".as_bytes();
    assert_eq!(s.len(), 8);
    for (max, want) in [(100, 8), (8, 8), (7, 5), (6, 5), (5, 5), (3, 2), (0, 0)] {
        assert_eq!(wire::utf8_fit(s, max), want, "max {max}");
    }
    assert_eq!(wire::utf8_fit(b"ab\xffcd", 5), 2);
    assert_eq!(wire::utf8_fit(b"ab\0cd", 5), 2);
}

fn hello_alice(flags: u32, nonce: [u8; 32]) -> Hello {
    Hello { version: 1, flags, user: "alice".into(), nonce }
}

#[test]
fn preauth() {
    // t_wire.c lines 223-312
    let h = hello_alice(0, [0x5a; 32]);
    let hb = h.encode().unwrap();
    assert_eq!(&hb[..21], b"IMDBWIR1\x01\0\0\0\0\0\0\0alice"); // line 230
    assert_eq!(Hello::decode(&hb).unwrap(), h);
    let (mut took, mut refused) = (0, 0);
    for i in 0..hb.len() {
        for f in [0x01u8, 0x80, 0xff] {
            let mut x = hb;
            x[i] ^= f;
            match Hello::decode(&x) {
                Ok(g) => {
                    assert_eq!(g.encode().unwrap(), x); // any bytes a decoder takes encode back to themselves
                    took += 1;
                }
                Err(_) => refused += 1,
            }
        }
    }
    assert!(took >= 32 * 3 + 1 && refused >= 16 * 3, "took {took} refused {refused}");
    for fl in 0..5u8 {
        let mut y = hb;
        y[12] = fl;
        match Hello::decode(&y) {
            Ok(g) => assert!(fl <= 2 && g.flags == fl as u32),
            Err(e) => assert!(fl > 2 && matches!(e, Error::Protocol { limit: false, .. })),
        }
    }
    let mut x = hb;
    x[8] = 2;
    let e = Hello::decode(&x).unwrap_err();
    assert!(matches!(&e, Error::Unsupported(m) if m.contains("version 2")), "{e}");
    let mut x = hb;
    x[7] = b'2';
    let e = Hello::decode(&x).unwrap_err();
    assert!(matches!(&e, Error::Unsupported(m) if m.contains("IMDBWIR2")), "{e}");
    x[7] = b'0';
    assert!(matches!(Hello::decode(&x), Err(Error::Protocol { .. })));
    let mut x = hb;
    x[0] = b'X';
    assert!(matches!(Hello::decode(&x), Err(Error::Protocol { .. })));
    let mut x = hb;
    x[8] = 0;
    assert!(matches!(Hello::decode(&x), Err(Error::Protocol { .. })));
    let mut x = hb;
    x[12] = 3;
    assert!(matches!(Hello::decode(&x), Err(Error::Protocol { .. })));
    // the role name: 1 to 63 bytes of UTF-8, NUL-padded (lines 280-295)
    let mut x = hb;
    x[16..80].fill(0);
    assert!(Hello::decode(&x).is_err());
    x[16..80].fill(b'a');
    assert!(Hello::decode(&x).is_err());
    x[16 + 63] = 0;
    assert_eq!(Hello::decode(&x).unwrap().user.len(), 63);
    x[16..80].fill(0);
    x[16] = b'a';
    x[18] = b'b';
    assert!(Hello::decode(&x).is_err());
    x[18] = 0;
    x[16] = 0xff;
    assert!(Hello::decode(&x).is_err());
    assert!(wire::user_ok("\u{e9}".as_bytes()) && !wire::user_ok(b"") && !wire::user_ok(b"\xc3"));
    // the head every version keeps (lines 298-312)
    assert_eq!(wire::preauth_head(hb[..12].try_into().unwrap()).unwrap(), 1);
    let mut y: [u8; 12] = hb[..12].try_into().unwrap();
    y[8..12].copy_from_slice(&7u32.to_le_bytes());
    assert_eq!(wire::preauth_head(&y).unwrap(), 7);
    y[8..12].copy_from_slice(&0u32.to_le_bytes());
    assert!(matches!(wire::preauth_head(&y), Err(Error::Protocol { .. })));
    y[8..12].copy_from_slice(&1u32.to_le_bytes());
    y[7] = b'2';
    assert!(matches!(wire::preauth_head(&y), Err(Error::Unsupported(_))));
    y[0] = b'X';
    assert!(matches!(wire::preauth_head(&y), Err(Error::Protocol { .. })));
    // the encoder refuses what the decoder would (lines 314-326)
    assert!(Hello { version: 2, ..h.clone() }.encode().is_err());
    assert!(Hello { flags: 3, ..h.clone() }.encode().is_err());
    assert_eq!(Hello { flags: 2, ..h.clone() }.encode().unwrap()[12], 2);
    assert!(Hello { user: "".into(), ..h.clone() }.encode().is_err());
    assert!(Hello { user: "a\0".into(), ..h.clone() }.encode().is_err());
    assert!(Hello { user: "a".repeat(64), ..h.clone() }.encode().is_err());
}

#[test]
fn challenge_and_verdict() {
    // t_wire.c lines 328-397
    let c = Challenge { version: 1, salt: (1..=16).collect(), iterations: 4096, nonce: [9; 32] };
    let cb = c.encode().unwrap();
    assert_eq!(Challenge::decode(&cb).unwrap(), c);
    let (mut took, mut refused) = (0, 0);
    for i in 0..cb.len() {
        for f in [0x01u8, 0x80, 0xff] {
            let mut y = cb;
            y[i] ^= f;
            match Challenge::decode(&y) {
                Ok(d) => {
                    assert_eq!(d.encode().unwrap(), y);
                    took += 1;
                }
                Err(_) => refused += 1,
            }
        }
    }
    assert!(took >= (16 + 32) * 3 && refused >= (48 + 7) * 3, "took {took} refused {refused}");
    // line 354: salt lengths and iteration counts at their bounds
    for (salt_len, iter, ok) in [(7usize, 4096u32, false), (8, 4096, true), (64, 4096, true), (65, 4096, false), (16, 999, false), (16, 1000, true), (16, 1000000, true), (16, 1000001, false)] {
        let ch = Challenge { salt: vec![3; salt_len], iterations: iter, ..c.clone() };
        assert_eq!(ch.encode().is_ok(), ok, "{salt_len} {iter}");
        let mut b = c.encode().unwrap(); // the same bytes made by hand: the decoder refuses them too
        b[12] = salt_len as u8;
        b[13 + 64..17 + 64].copy_from_slice(&iter.to_le_bytes());
        if salt_len <= 64 {
            b[13..13 + 64].fill(0);
            b[13..13 + salt_len].fill(3);
        }
        assert_eq!(Challenge::decode(&b).is_ok(), ok, "{salt_len} {iter}");
    }
    let mut b = cb;
    b[13 + 16] = 1; // a byte in the salt's padding
    assert!(Challenge::decode(&b).is_err());
    let mut b = cb;
    b[119] = 1; // the 7 bytes of padding
    assert!(Challenge::decode(&b).is_err());

    let v = Verdict { code: 0, sig: [0x11; 32] };
    let mut vb = v.encode().unwrap();
    assert_eq!(Verdict::decode(&vb).unwrap(), v);
    vb[0] = 1;
    assert!(Verdict::decode(&vb).is_err()); // a refusal with a signature
    assert!(Verdict { code: 1, sig: [0x11; 32] }.encode().is_err());
    let mut vb = Verdict { code: 1, sig: [0; 32] }.encode().unwrap();
    assert_eq!(Verdict::decode(&vb).unwrap().code, 1);
    vb[0] = 2;
    assert_eq!(Verdict::decode(&vb).unwrap().code, 2);
    vb[4] = 1;
    assert!(Verdict::decode(&vb).is_err());
    vb[4] = 0;
    vb[0] = 3;
    assert!(Verdict::decode(&vb).is_err());
    assert!(Verdict { code: 3, sig: [0; 32] }.encode().is_err());
}

#[test]
fn scram_pinned_exchanges() {
    // docs/n1-design.md §4 lines 93-104 and t_wire.c lines 415-471: user "alice", client nonce 32 x 01, salt 16 x 03,
    // 4,096 iterations, server nonce 32 x 02, password "pencil"
    let c = Challenge { version: 1, salt: vec![3; 16], iterations: 4096, nonce: [2; 32] };
    let cb = c.encode().unwrap();
    let cases = [
        // (endpoint, flags, binding byte, ClientProof, ServerSignature)
        (1u8, 1u32, 0x04u8, "28562c1bef99b0a917ecb28c1b32c22930f154f92c134b13fee7a64e8deb733e", "5d3ef834c39e6c429d1f4e27993ba451a8b8e35322af9055abc1dd40e88ad322"),
        (1, 2, 0x05, "1065f5e038b75f2671d831f5bd5d29f56d22a787f260db523bb986ef7c53f486", "28fef60553090aae9b5f184bfc0cfb455e58261131da359f525a59f4dfaa9904"),
        (2, 0, 0x00, "5ee7e7bd402f0c91e2399a84c3d544763bace50b44ea82a780e57130bb5405a7", "82c9d498cc5fa830d26b29740244ecf4f343962f302a647150e9d74ea7588027"),
    ];
    for (ep, flags, bind, proof, ssig) in cases {
        let hb = hello_alice(flags, [1; 32]).encode().unwrap();
        assert_eq!(hb[12] as u32, flags);
        let am = wire::auth_message(ep, &hb, &cb, &[bind; 32]);
        // the AuthMessage laid out by hand (t_wire.c lines 429-434)
        let mut want = b"IMDBWIR1-SCRAM".to_vec();
        want.push(ep);
        want.extend_from_slice(&hb);
        want.extend_from_slice(&cb);
        want.extend_from_slice(&[bind; 32]);
        assert_eq!(&am[..], &want[..]);
        let (p, s) = wire::scram_client(b"pencil", &c, &am).unwrap();
        assert_eq!(hexs(&p), proof, "endpoint {ep} flags {flags}");
        assert_eq!(hexs(&s), ssig, "endpoint {ep} flags {flags}");
    }
    // the client refuses a password CREATE ROLE would, and a challenge its decoder would (lines 530-541)
    let am = [0u8; 279];
    let c1 = Challenge { iterations: 1000, ..c.clone() };
    for pw in [&b""[..], b"a\x7f", b"a\x1f", "\u{e9}".as_bytes(), &[b'a'; 1025][..]] {
        assert!(wire::scram_client(pw, &c1, &am).is_err());
    }
    assert!(wire::scram_client(&[b'a'; 1024], &c1, &am).is_ok());
    assert!(wire::scram_client(b"pencil", &Challenge { iterations: 999, ..c.clone() }, &am).is_err());
}

fn body(ty: u8, h: &str, cols: Option<&Arc<Columns>>) -> Result<Msg> {
    Msg::decode(ty, &hex(h), cols)
}

#[test]
fn head_bounds() {
    // t_wire.c lines 926-941
    let h = |len: u32, ty: u8| -> [u8; 5] {
        let mut x = [0u8; 5];
        x[..4].copy_from_slice(&len.to_le_bytes());
        x[4] = ty;
        x
    };
    assert!(is_limit(&wire::head_get(&h(0, 1), false).unwrap_err()));
    assert!(is_limit(&wire::head_get(&h(wire::FRAME_MAX + 1, 1), false).unwrap_err()));
    assert_eq!(wire::head_get(&h(wire::FRAME_MAX, 1), false).unwrap(), (wire::FRAME_MAX, 1));
    assert!(wire::head_get(&h(wire::FRAME_MAX, 1), true).is_err());
    for (c, s) in [(0u8, 0u8), (13, 1), (63, 12), (64, 63), (74, 75), (255, 255)] {
        assert!(wire::head_get(&h(1, c), false).is_err(), "client {c}");
        assert!(wire::head_get(&h(1, s), true).is_err(), "server {s}");
    }
}

#[test]
fn body_bounds() {
    use wire::*;
    // t_wire.c lines 942-1042, in order
    let ok = |ty, h: &str| assert!(body(ty, h, None).is_ok(), "refused: {ty} {h}");
    let no = |ty, h: &str| assert!(body(ty, h, None).is_err(), "taken: {ty} {h}");
    let lim = |ty, h: &str| assert!(is_limit(&body(ty, h, None).unwrap_err()), "not LIMIT: {ty} {h}");
    no(QUERY, "00000000");
    no(QUERY, "01100000 01000000 61 0000");
    no(QUERY, "ffffffff 01000000 61 0000");
    no(QUERY, "01000000 00000000 0000");
    lim(QUERY, "01000000 01004000 61 0000");
    ok(QUERY, "01000000 01000000 61 0000");
    ok(QUERY, "01000000 01000000 61 0100 81");
    no(QUERY, "01000000 01000000 61 0100 00");
    no(QUERY, "01000000 01000000 61 0100 0d0161");
    ok(QUERY, "01000000 01000000 61 0100 8d");
    no(QUERY, "01000000 01000000 61 0101 00");
    no(QUERY, "01000000 01000000 61 0000 00");
    no(QUERY, "01000000 01000000 61");
    no(QUERY, "01000000 01000000 ff 0000");
    no(QUERY, "01000000 02000000 6100 0000");
    no(DEALLOCATE, "01 c3");
    no(COLUMNS, "0100 01ff 03 0000 0000");
    no(COLUMNS, "0100 0161 0d 0000 0000 0100 01 80");
    no(DONE, "0100 ff 0000000000000000 00 00");
    no(ERROR, "05000000 00000000 0100 00");
    no(WARNING, "0200 c0af");
    ok(COPY_DATA, "ff00");
    no(EXECUTE, "0170 01000000 0101");
    no(EXECUTE, "0170 00000000 0000");
    ok(EXECUTE, "0170 01000000 0100 80");
    no(EXECUTE, "0170 01000000 0100 0d0161");
    no(EXECUTE, "00 01000000 0000");
    ok(PREPARE, "0170 01000000 61");
    no(PREPARE, "0170 01000000 61 00");
    no(DEALLOCATE, &format!("40 {}", "61".repeat(64)));
    no(ROWS, "01000000 00");
    no(COLUMNS, "0000");
    no(COLUMNS, "0100 0161 05 2700 0000");
    no(COLUMNS, "0100 0161 05 0200 0300");
    ok(COLUMNS, "0100 0161 05 2600 2600");
    no(COLUMNS, "0100 0161 01 0800 0000");
    ok(COLUMNS, "0100 0161 01 1000 0000");
    no(COLUMNS, "0100 0161 03 0100 0000");
    ok(COLUMNS, "0100 0161 00 0000 0000");
    no(COLUMNS, "0100 0161 00 0100 0000");
    ok(COLUMNS, "0100 0161 05 0000 2600");
    no(COLUMNS, "0100 0161 05 0000 2700");
    no(COLUMNS, "0100 0161 0e 0000 0000");
    no(COLUMNS, "0100 0161 0d 0000 0000 ffff");
    no(COLUMNS, "0100 0161 0d 0000 0000 0104");
    ok(COLUMNS, "0100 0161 0d 0000 0000 0100 00");
    lim(COLUMNS, "0100 0161 0d 0000 0000 0100 40");
    no(COLUMNS, "0100 0161 0d 0100 0000 0100 00");
    no(DONE, "0000 0000000000000000 02 00");
    ok(DONE, "0000 0000000000000000 00 00");
    ok(DONE, "0000 ffffffffffffffff 00 00");
    no(DONE, "0000 00 00");
    let z32 = "00".repeat(32);
    let z16 = "00".repeat(16);
    // line 999: "01%.62s": a manifest whose first byte is 01, the rest of a 32-byte field zeros
    ok(DONE, &format!("0000 0000000000000000 01 0000000000000000 {z32} {z32} 0100000000000000 01{} {z16} 00 00", &z32[..62]));
    ok(DONE, &format!("0000 0000000000000000 01 0000000000000000 {z32} {z32} 0100000000000000 {z32} {z16} 01 00"));
    no(DONE, &format!("0000 0000000000000000 01 0000000000000000 {z32} {z32} 0100000000000000 {z32} {z16} 02 00"));
    no(DONE, &format!("0000 0000000000000000 00 01 0000000000000000 {z32}"));
    lim(DONE, &format!("0002 {} 00 00", "0".repeat(1024)));
    no(ERROR, "05000000 00100000 0000");
    no(ERROR, "00000000 00000000 0000");
    ok(ERROR, "05000000 ff0f0000 0000");
    no(READY, "03");
    no(READY, "");
    no(PING, "00");
    ok(KILL, "01 0100000000000000");
    no(KILL, "00 0100000000000000");
    no(KILL, "03 0100000000000000");
    no(KILL, "02 0000000000000000");
    no(KILL, "02 01000000000000");
    no(KILL, "02 0100000000000000 00");
    ok(KILL_DONE, "01 0100000000000000");
    no(KILL_DONE, "02 0100000000000000");
    no(KILL_DONE, "03 0100000000000000");
    no(KILL_DONE, "00 0000000000000000");
    no(SESSIONS, "00");
    ok(SESSIONS_LIST, "00000000");
    ok(SESSIONS_LIST, "01000000 0100000000000000 01000000 01 00 0000000000000000 00");
    no(SESSIONS_LIST, "01000000 0000000000000000 01000000 01 00 0000000000000000 00");
    no(SESSIONS_LIST, "01000000 0100000000000000 00000000 01 00 0000000000000000 00");
    no(SESSIONS_LIST, "01000000 0100000000000000 01000000 03 00 0000000000000000 00");
    no(SESSIONS_LIST, "01000000 0100000000000000 01000000 01 04 0000000000000000 00");
    no(SESSIONS_LIST, "01000000 0100000000000000 01000000 01 00 0000000000000000 40");
    no(SESSIONS_LIST, "01000000 0100000000000000 01000000 01 00 0000000000000000 01 ff");
    no(SESSIONS_LIST, "02000000 0200000000000000 01000000 01 00 0000000000000000 00 0200000000000000 01000000 01 00 0000000000000000 00");
    no(SESSIONS_LIST, "02000000 0200000000000000 01000000 01 00 0000000000000000 00 0100000000000000 01000000 01 00 0000000000000000 00");
    no(SESSIONS_LIST, "02000000 0100000000000000 01000000 01 00 0000000000000000 00");
    no(SESSIONS_LIST, "01000100 0100000000000000 01000000 01 00 0000000000000000 00");
    no(COPY_DATA, "");
    lim(COPY_FAIL, "0110");
    // lines 1074-1087: a count past its bytes refused (the allocation's bound itself is not measured here)
    no(QUERY, "00100000 01000000 61 0000");
    no(COLUMNS, "0001 0161 01 0000 0000");
    no(COLUMNS, "0100 0161 0d 0000 0000 0004");
    // every accepted body above encodes back to its own bytes (one encoding)
    for (ty, h) in [
        (QUERY, "01000000 01000000 61 0100 8d"),
        (EXECUTE, "0170 01000000 0100 80"),
        (PREPARE, "0170 01000000 61"),
        (COLUMNS, "0100 0161 0d 0000 0000 0100 00"),
        (KILL, "01 0100000000000000"),
        (SESSIONS_LIST, "01000000 0100000000000000 01000000 01 00 0000000000000000 00"),
        (ERROR, "05000000 ff0f0000 0000"),
        (DONE, "0000 ffffffffffffffff 00 00"),
    ] {
        let m = body(ty, h, None).unwrap();
        assert_eq!(&m.encode().unwrap()[5..], &hex(h)[..], "{ty} {h}");
    }
}

#[test]
fn enum_labels_distinct_and_count() {
    // t_wire.c lines 855-859: the label twice, made by hand, refused by the decoder (its message says "distinct")
    let e = body(wire::COLUMNS, "0100 0165 0d 0000 0000 0200 0161 0161", None).unwrap_err();
    assert!(e.to_string().contains("distinct"), "{e}");
    // lines 1043-1073: 1,024 distinct labels taken, 1,025 refused
    for nl in [1024usize, 1025] {
        let mut b = vec![1, 0, 1, b'e', 13, 0, 0, 0, 0];
        b.extend_from_slice(&(nl as u16).to_le_bytes());
        let mut labels = Vec::new();
        for i in 0..nl {
            let l = [b'a' + (i / 676) as u8, b'a' + (i / 26 % 26) as u8, b'a' + (i % 26) as u8];
            b.push(3);
            b.extend_from_slice(&l);
            labels.push(String::from_utf8(l.to_vec()).unwrap());
        }
        assert_eq!(Msg::decode(wire::COLUMNS, &b, None).is_ok(), nl == 1024);
        let c = Column { name: "e".into(), ty: Type::Enum, precision: 0, scale: 0, labels };
        assert_eq!(Columns::new(vec![c]).is_ok(), nl == 1024);
    }
    let dup = Column { name: "e".into(), ty: Type::Enum, precision: 0, scale: 0, labels: vec!["a".into(), "b".into(), "a".into()] };
    assert!(Columns::new(vec![dup]).is_err());
}

/// t_wire.c lines 593-607 (samples' columns): id INTEGER, amount DECIMAL(38,6), name VARCHAR(12), mood ENUM
fn sample_cols() -> Arc<Columns> {
    let mood = Column { name: "mood".into(), ty: Type::Enum, precision: 0, scale: 0, labels: vec!["".into(), "x".into(), "\u{e9}".into()] };
    Arc::new(Columns::new(vec![Column::new("id", Type::Int64, 32, 0), Column::new("amount", Type::Decimal, 38, 6), Column::new("name", Type::Text, 12, 0), mood]).unwrap())
}

#[test]
fn rows_fit() {
    // property, t_wire.c lines 766-864: a ROWS value held to its column
    let cols = sample_cols();
    let lim: i128 = 100_000_000_000_000_000_000_000_000_000_000_000_000;
    let d = |u: i128, s: u8| Value::Decimal(Decimal::new(u, s).unwrap());
    let cases: Vec<(usize, Value, bool)> = vec![
        (0, Value::Int64(i32::MAX as i64), true),
        (0, Value::Int64(i32::MAX as i64 + 1), false),
        (0, Value::Int64(i32::MIN as i64 - 1), false),
        (0, Value::Timestamp(Timestamp::from_micros(1).unwrap()), false),
        (0, Value::Null(Type::Int64), true),
        (0, Value::Null(Type::Text), false),
        (0, Value::Null(Type::None), false),
        (1, d(lim - 1, 6), true),
        (1, d(1, 5), false),
        (1, Value::Int64(1), false),
        (2, Value::Text("\u{e9}".repeat(12)), true),
        (2, Value::Text("0123456789abc".into()), false),
        (2, Value::Bytea(b"a".to_vec()), false),
        (3, Value::Enum("\u{e9}".into()), true),
        (3, Value::Enum("y".into()), false),
        (3, Value::Enum("xx".into()), false),
        (3, Value::Text("x".into()), false),
    ];
    for (k, (col, v, ok)) in cases.into_iter().enumerate() {
        assert_eq!(cols.fits(col, &v), ok, "case {k}");
        let mut row = vec![Value::Null(Type::Int64), Value::Null(Type::Decimal), Value::Null(Type::Text), Value::Null(Type::Enum)];
        row[col] = v.clone();
        assert_eq!(Rows::new(cols.clone(), &[row.clone()]).is_ok(), ok, "case {k}");
        // the same frame by hand, unchecked: the decoder agrees
        let mut b = 1u32.to_le_bytes().to_vec();
        for x in &row {
            b.extend_from_slice(&wire::encode_value(x).unwrap());
        }
        let got = Msg::decode(wire::ROWS, &b, Some(&cols));
        assert_eq!(got.is_ok(), ok, "case {k}");
        if let Ok(Msg::Rows(r)) = got {
            assert_eq!(r.iter().next().unwrap(), row);
        }
    }
    let sc = Arc::new(Columns::new(vec![Column::new("s", Type::Int64, 16, 0)]).unwrap());
    assert!(sc.fits(0, &Value::Int64(i16::MAX as i64)) && !sc.fits(0, &Value::Int64(i16::MAX as i64 + 1)));
    let d52 = Columns::new(vec![Column::new("d", Type::Decimal, 5, 2)]).unwrap();
    assert!(d52.fits(0, &d(-99999, 2)) && !d52.fits(0, &d(100000, 2)));
    let d0 = Columns::new(vec![Column::new("d", Type::Decimal, 0, 2)]).unwrap();
    assert!(d0.fits(0, &d(lim - 1, 2)) && !d0.fits(0, &d(0, 3)));
    let none = Columns::new(vec![Column::new("x", Type::None, 0, 0)]).unwrap();
    for v in [Value::Int64(1), Value::Enum("q".into()), Value::Null(Type::None), Value::Null(Type::Date)] {
        assert!(none.fits(0, &v));
    }
    // ROWS against no COLUMNS, or of no row
    assert!(Msg::decode(wire::ROWS, &hex("01000000 81"), None).is_err());
    assert!(Msg::decode(wire::ROWS, &hex("00000000"), Some(&sc)).is_err());
}

/// property, t_wire.c lines 588-684: one message of every type (the same fields where Rust's types can hold them)
fn samples() -> Vec<Msg> {
    let cols = sample_cols();
    let lim: i128 = 100_000_000_000_000_000_000_000_000_000_000_000_000;
    let ev = vec![
        Value::Int64(-2),
        Value::Float64(1.5),
        Value::Null(Type::None),
        Value::Decimal(Decimal::new(-12345, 2).unwrap()),
        Value::TimestampTz(TimestampTz::from_micros(-1).unwrap()),
        Value::Date(Date::from_days(2932896).unwrap()),
        Value::Uuid(uuid16()),
        Value::Interval(Interval::new(i32::MIN, i32::MAX, i64::MIN)),
    ];
    let rv = vec![
        vec![Value::Int64(i32::MIN as i64), Value::Decimal(Decimal::new(-1234567, 6).unwrap()), Value::Text("h\u{e9}llo".into()), Value::Enum("x".into())],
        vec![Value::Null(Type::Int64), Value::Decimal(Decimal::new(lim - 1, 6).unwrap()), Value::Text("".into()), Value::Enum("".into())],
    ];
    let done = Done {
        status: "INSERT 0 3".into(),
        count: 3,
        read: Some(ReadPoint { commit: 41, hash: [1; 32], digest: [2; 32], lake_commit: 44, lake_manifest: [3; 32], db_id: [4; 16], own: true }),
        write: Some(WriteCommit { commit: 42, hash: [5; 32] }),
    };
    vec![
        Msg::Execute { name: "p1".into(), sets: 2, nvals: 4, values: ev },
        Msg::Query(vec![
            Statement { sql: "SELECT $1, $2".into(), params: vec![Value::Int64(7), Value::Text("t".into())] },
            Statement { sql: "BEGIN".into(), params: vec![] },
            Statement { sql: "\u{e9}".into(), params: vec![Value::Null(Type::Enum)] },
        ]),
        Msg::Query(vec![Statement { sql: "BEGIN".into(), params: vec![] }]),
        Msg::Prepare { name: "p1".into(), sql: "SELECT $1, $2".into() },
        Msg::Prepare { name: "n".repeat(63), sql: "BEGIN".into() },
        Msg::Execute { name: "p2".into(), sets: 3, nvals: 0, values: vec![] },
        Msg::Deallocate { name: "p1".into() },
        Msg::CopyData(b"a,b\n\x00\xff".to_vec()),
        Msg::CopyDone,
        Msg::CopyFail("SELECT $1, $2".into()),
        Msg::Cancel,
        Msg::Ping,
        Msg::Terminate,
        Msg::Sessions,
        Msg::Kill { kind: 1, session: 1 },
        Msg::Kill { kind: 2, session: u64::MAX },
        Msg::Columns(cols.clone()),
        Msg::Rows(Rows::new(cols.clone(), &rv).unwrap()),
        Msg::Done(done),
        Msg::Done(Done { status: "".into(), count: 0, read: None, write: None }),
        Msg::Done(Done { status: "SELECT 0".into(), count: 0, read: Some(ReadPoint { commit: 0, hash: [0; 32], digest: [0; 32], lake_commit: 0, lake_manifest: [0; 32], db_id: [0; 16], own: false }), write: None }),
        Msg::Error(ServerError { code: 5, index: 2, message: "BEGIN".into() }),
        Msg::Warning("\u{e9}".into()),
        Msg::CopyIn,
        Msg::CopyOut(b"1,2\n".to_vec()),
        Msg::Ready(2),
        Msg::Pong,
        Msg::SessionsList(vec![
            SessionInfo { id: 3, role: 7, endpoint: 1, state: 3, age_ms: u64::MAX, name: "h\u{e9}".into() },
            SessionInfo { id: 4, role: u32::MAX, endpoint: 2, state: 0, age_ms: 0, name: "".into() },
        ]),
        Msg::SessionsList(vec![]),
        Msg::KillDone { code: 0, session: 9 },
        Msg::KillDone { code: 1, session: u64::MAX },
    ]
}

fn reencode(frame: &[u8], cols: &Arc<Columns>) -> std::result::Result<bool, Error> {
    let from_server = frame[4] >= 64;
    let (len, ty) = wire::head_get(frame[..5].try_into().unwrap(), from_server)?;
    if len as usize + 4 != frame.len() {
        return Err(Error::Invalid("length".into()));
    }
    let m = Msg::decode(ty, &frame[5..], Some(cols))?;
    Ok(m.encode().map(|b| b == frame).unwrap_or(false))
}

#[test]
fn messages_round_trip() {
    let cols = sample_cols();
    for (k, m) in samples().iter().enumerate() {
        let b = m.encode().unwrap();
        assert_eq!(b[4], m.frame_type());
        let back = Msg::decode(b[4], &b[5..], Some(&cols)).unwrap();
        assert_eq!(&back, m, "sample {k}");
        assert!(reencode(&b, &cols).unwrap(), "sample {k}");
    }
}

#[test]
fn messages_flipped_and_cut() {
    // property, t_wire.c lines 868-910: every byte of every sample flipped three ways, every cut and one byte more
    let cols = sample_cols();
    for (k, m) in samples().iter().enumerate() {
        let b = m.encode().unwrap();
        let raw = matches!(m, Msg::CopyData(_) | Msg::CopyOut(_));
        for i in 5..b.len() {
            for f in [0x01u8, 0x80, 0xff] {
                let mut x = b.clone();
                x[i] ^= f;
                if let Ok(same) = reencode(&x, &cols) {
                    assert!(same, "sample {k} byte {i} ^ {f:02x}: taken but encodes otherwise");
                }
            }
        }
        for cut in 5..b.len() {
            let mut x = b[..cut].to_vec();
            x[..4].copy_from_slice(&((cut - 4) as u32).to_le_bytes());
            let r = reencode(&x, &cols);
            if raw {
                assert!(cut == 5 || r.as_ref().is_ok_and(|s| *s), "sample {k} cut {cut}");
            } else {
                assert!(r.is_err(), "sample {k} cut at {cut} taken");
            }
        }
        let mut x = b.clone();
        x.push(0);
        x[..4].copy_from_slice(&((b.len() + 1 - 4) as u32).to_le_bytes());
        let r = reencode(&x, &cols);
        assert_eq!(r.is_ok(), raw, "sample {k} one byte more");
    }
}

#[test]
fn drawn_bodies_one_encoding() {
    // property (§4 "One encoding"; t_wire.c's 80,000 drawn bodies, wire_drawn): bytes drawn for every frame type, and
    // every sample with several bytes changed at once, never make a decoder panic, and whatever one takes encodes back to
    // the same bytes. The draws favour the small values lengths and counts need (0, 1, 2, 0xff), so many are taken.
    let cols = sample_cols();
    let mut x: u64 = 0x2545_f491_4f6c_dd1d;
    let mut next = move || {
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        x.wrapping_mul(0x2545_f491_4f6c_dd1d)
    };
    let types: Vec<u8> = (1..=12).chain(64..=74).collect();
    let (mut tried, mut taken) = (0u32, 0u32);
    let check = |frame: &[u8], tried: &mut u32, taken: &mut u32| {
        *tried += 1;
        if let Ok(same) = reencode(frame, &cols) {
            assert!(same, "taken but encodes otherwise: {}", hexs(frame));
            *taken += 1;
        }
    };
    for &ty in &types {
        for _ in 0..4000 {
            let n = (next() % 96) as usize;
            let mut b = vec![0u8; 5 + n];
            b[..4].copy_from_slice(&((n + 1) as u32).to_le_bytes());
            b[4] = ty;
            for v in b[5..].iter_mut() {
                let r = next();
                *v = match r % 8 {
                    0..=2 => 0,
                    3 => 1,
                    4 => 2,
                    5 => 0xff,
                    _ => (r >> 8) as u8,
                };
            }
            check(&b, &mut tried, &mut taken);
        }
    }
    for m in samples() {
        let b = m.encode().unwrap();
        if b.len() <= 5 {
            continue;
        }
        for _ in 0..2000 {
            let mut y = b.clone();
            for _ in 0..1 + next() % 4 {
                let i = 5 + (next() as usize) % (y.len() - 5);
                y[i] = next() as u8;
            }
            check(&y, &mut tried, &mut taken);
        }
    }
    eprintln!("    {tried} drawn frames, {taken} taken, each encoding back to its bytes");
    assert!(taken > 1000, "the draws reach the decoders' accepting paths");
}

#[test]
fn encoder_refuses() {
    // what the decoders refuse, the encoders refuse (nothing written)
    let q = |sql: &str, params: Vec<Value>| Msg::Query(vec![Statement { sql: sql.into(), params }]).encode();
    assert!(Msg::Query(vec![]).encode().is_err());
    assert!(q("", vec![]).is_err());
    assert!(q("a\0", vec![]).is_err());
    assert!(q("a", vec![Value::Enum("x".into())]).is_err()); // a label is sent as TEXT
    assert!(q("a", vec![Value::Null(Type::Enum)]).is_ok());
    assert!(q("a", vec![Value::Int64(1); 257]).is_err());
    assert!(q("a", vec![Value::Int64(1); 256]).is_ok());
    assert!(Msg::Query(vec![Statement { sql: "a".into(), params: vec![] }; 4097]).encode().is_err());
    assert_eq!(q("a", vec![]).unwrap(), hex("0c000000 01 01000000 01000000 61 0000"));
    assert!(Msg::Prepare { name: "".into(), sql: "a".into() }.encode().is_err());
    assert!(Msg::Prepare { name: "n".repeat(64), sql: "a".into() }.encode().is_err());
    assert!(Msg::Execute { name: "p".into(), sets: 0, nvals: 0, values: vec![] }.encode().is_err());
    assert!(Msg::Execute { name: "p".into(), sets: 2, nvals: 1, values: vec![Value::Int64(1)] }.encode().is_err());
    assert!(Msg::CopyData(vec![]).encode().is_err());
    assert!(Msg::CopyFail("x".repeat(4097)).encode().is_err());
    assert!(Msg::Kill { kind: 3, session: 1 }.encode().is_err());
    assert!(Msg::Kill { kind: 1, session: 0 }.encode().is_err());
    assert!(Msg::Error(ServerError { code: 0, index: 0, message: "".into() }).encode().is_err());
    assert!(Msg::Error(ServerError { code: 1, index: 4096, message: "".into() }).encode().is_err());
    assert!(Msg::Ready(3).encode().is_err());
    assert!(Msg::Done(Done { status: "".into(), count: 0, read: None, write: Some(WriteCommit { commit: 0, hash: [0; 32] }) }).encode().is_err());
    assert!(Msg::SessionsList(vec![SessionInfo { id: 2, role: 1, endpoint: 1, state: 0, age_ms: 0, name: "".into() }, SessionInfo { id: 2, role: 1, endpoint: 1, state: 0, age_ms: 0, name: "".into() }]).encode().is_err());
    assert_eq!(Msg::Cancel.encode().unwrap(), hex("01000000 08"));
}
