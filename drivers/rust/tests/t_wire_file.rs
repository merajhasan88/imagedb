//! The codec against the C reference's own test file, read where it is: IMDB_T_WIRE, else the repository's
//! tests/unit/t_wire.c (this crate at drivers/rust), else main's on this machine. Its byte vectors are taken from the file itself
//! (kVecs, the refused and LIMIT values, the pinned SCRAM exchanges, every literal body() bound), so a change there is
//! seen here; tests/codec.rs holds the same vectors copied with their line ranges.
mod common;

use common::hex;
use imagedb::wire::{self, Challenge, Hello, Msg};
use imagedb::Error;

fn source() -> String {
    // IMDB_T_WIRE, else the repository's (this crate at drivers/rust)
    let path = std::env::var("IMDB_T_WIRE")
        .unwrap_or_else(|_| format!("{}/../../tests/unit/t_wire.c", env!("CARGO_MANIFEST_DIR")));
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("t_wire.c at {path}: {e} (set IMDB_T_WIRE)"))
}

/// The lines from the one starting with `start` to the next "};" (inclusive).
fn block<'a>(src: &'a str, start: &str) -> Vec<&'a str> {
    let mut out = Vec::new();
    let mut on = false;
    for l in src.lines() {
        if l.contains(start) {
            on = true;
        }
        if on {
            out.push(l);
            if l.trim_start().starts_with("};") || (l.contains("};") && out.len() == 1 && l.contains(start)) {
                break;
            }
        }
    }
    assert!(!out.is_empty(), "t_wire.c: no {start}");
    out
}

/// The string literals of a C line (none holds an escape or a quote here).
fn literals(l: &str) -> Vec<String> {
    let code = l.split("/*").next().unwrap();
    code.split('"').skip(1).step_by(2).map(|s| s.to_string()).collect()
}

#[test]
fn kvecs_from_the_file() {
    let src = source();
    let mut n = 0;
    for l in block(&src, "static const vec kVecs[] = {") {
        let lits = literals(l);
        let Some(h) = lits.last() else { continue };
        if !l.trim_start().starts_with("{{") {
            continue;
        }
        let b = hex(h);
        let v = wire::decode_value(&b).unwrap_or_else(|e| panic!("t_wire.c kVecs {h}: {e}"));
        assert_eq!(wire::encode_value(&v).unwrap(), b, "{h}");
        for cut in 0..b.len() {
            assert!(wire::decode_value(&b[..cut]).is_err(), "{h}: a prefix of {cut} taken");
        }
        n += 1;
    }
    assert_eq!(n, 28, "t_wire.c's kVecs: 28 vectors (lines 55-84 on 2026-11-19)");
}

#[test]
fn refused_values_from_the_file() {
    let src = source();
    let mut n = 0;
    for l in block(&src, "static const char *const refused[] = {").iter().skip(1) {
        for h in literals(l) {
            assert!(wire::decode_value(&hex(&h)).is_err(), "t_wire.c refused[] {h:?} taken");
            n += 1;
        }
    }
    assert_eq!(n, 21);
    let lim = src.lines().find(|l| l.contains("static const char *const limit[] =")).expect("limit[]");
    let ls = literals(lim);
    assert_eq!(ls.len(), 3);
    for h in ls {
        assert!(matches!(wire::decode_value(&hex(&h)), Err(Error::Protocol { limit: true, .. })), "{h}");
    }
}

#[test]
fn pinned_scram_from_the_file() {
    let src = source();
    // the six 64-digit hex strings of t_wire_scram, in their order: the exporter's proof and signature, then more[]'s
    let start = src.find("static void t_wire_scram(void)").expect("t_wire_scram");
    let end = src[start..].find("static void t_wire_fake_salt").unwrap() + start;
    let pins: Vec<String> = src[start..end]
        .lines()
        .flat_map(literals)
        .filter(|s| s.len() == 64 && s.bytes().all(|c| c.is_ascii_hexdigit()))
        .collect();
    assert_eq!(pins.len(), 6, "{pins:?}");
    let c = Challenge { version: 1, salt: vec![3; 16], iterations: 4096, nonce: [2; 32] };
    let cb = c.encode().unwrap();
    for (k, (ep, flags, bind)) in [(1u8, 1u32, 4u8), (1, 2, 5), (2, 0, 0)].into_iter().enumerate() {
        let hb = Hello { version: 1, flags, user: "alice".into(), nonce: [1; 32] }.encode().unwrap();
        let am = wire::auth_message(ep, &hb, &cb, &[bind; 32]);
        let (p, s) = wire::scram_client(b"pencil", &c, &am).unwrap();
        assert_eq!(p.to_vec(), hex(&pins[2 * k]), "case {k} proof");
        assert_eq!(s.to_vec(), hex(&pins[2 * k + 1]), "case {k} signature");
    }
}

fn frame_type(name: &str) -> u8 {
    match name {
        "QUERY" => wire::QUERY,
        "PREPARE" => wire::PREPARE,
        "EXECUTE" => wire::EXECUTE,
        "DEALLOCATE" => wire::DEALLOCATE,
        "COPY_DATA" => wire::COPY_DATA,
        "COPY_DONE" => wire::COPY_DONE,
        "COPY_FAIL" => wire::COPY_FAIL,
        "CANCEL" => wire::CANCEL,
        "PING" => wire::PING,
        "TERMINATE" => wire::TERMINATE,
        "SESSIONS" => wire::SESSIONS,
        "KILL" => wire::KILL,
        "COLUMNS" => wire::COLUMNS,
        "ROWS" => wire::ROWS,
        "DONE" => wire::DONE,
        "ERROR" => wire::ERROR,
        "WARNING" => wire::WARNING,
        "COPY_IN" => wire::COPY_IN,
        "COPY_OUT" => wire::COPY_OUT,
        "READY" => wire::READY,
        "PONG" => wire::PONG,
        "SESSIONS_LIST" => wire::SESSIONS_LIST,
        "KILL_DONE" => wire::KILL_DONE,
        _ => panic!("t_wire.c: frame {name}"),
    }
}

#[test]
fn body_bounds_from_the_file() {
    let src = source();
    // every CHECK(body(IMDBW_X, "hex" ["hex" ...], NULL) OP) with literal bytes, statements joined across lines
    let mut stmts: Vec<String> = Vec::new();
    let mut cur = String::new();
    for l in src.lines() {
        let code = l.split("/*").next().unwrap();
        if cur.is_empty() && !code.contains("CHECK(body(IMDBW_") {
            continue;
        }
        cur.push_str(code);
        if code.trim_end().ends_with(';') {
            stmts.push(std::mem::take(&mut cur));
        }
    }
    let (mut ok, mut no, mut lim) = (0, 0, 0);
    for s in &stmts {
        let after = &s[s.find("CHECK(body(IMDBW_").unwrap() + "CHECK(body(IMDBW_".len()..];
        let name = &after[..after.find(',').unwrap()];
        let args = &after[after.find(',').unwrap() + 1..after.find(", NULL)").expect("NULL columns")];
        let lits = literals(args);
        if lits.is_empty() {
            continue; // bytes built at run time (snprintf'd DONE bodies): tests/codec.rs builds them alike
        }
        let hexs: String = lits.concat();
        let tail = &after[after.find(", NULL)").unwrap() + ", NULL)".len()..];
        let got = Msg::decode(frame_type(name), &hex(&hexs), None);
        if tail.contains("== IMDB_ERR_LIMIT") {
            assert!(matches!(got, Err(Error::Protocol { limit: true, .. })), "{name} {hexs}: {got:?}");
            lim += 1;
        } else if tail.contains("!= 0") {
            assert!(got.is_err(), "{name} {hexs}: taken");
            no += 1;
        } else if tail.contains("== 0") {
            let m = got.unwrap_or_else(|e| panic!("{name} {hexs}: {e}"));
            assert_eq!(&m.encode().unwrap()[5..], &hex(&hexs)[..], "{name} {hexs}: not one encoding");
            ok += 1;
        } else {
            panic!("t_wire.c: {s}");
        }
    }
    eprintln!("t_wire.c's body() bounds: {ok} taken, {no} refused, {lim} refused as LIMIT");
    assert_eq!((ok, no, lim), (18, 62, 3), "t_wire.c on 2026-11-19: 18 literal bodies taken, 62 refused, 3 as LIMIT");
}
