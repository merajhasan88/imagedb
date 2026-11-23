#![allow(dead_code)]
/// Hex digits (spaces allowed) to bytes; a malformed vector is the test's own bug.
pub fn hex(s: &str) -> Vec<u8> {
    let d: Vec<u8> = s.bytes().filter(|c| !c.is_ascii_whitespace()).collect();
    assert!(d.len() % 2 == 0, "odd hex: {s}");
    d.chunks(2).map(|p| u8::from_str_radix(std::str::from_utf8(p).unwrap(), 16).expect("hex")).collect()
}

pub fn hexs(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
