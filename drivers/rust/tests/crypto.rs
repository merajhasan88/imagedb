//! The primitives against their published vectors (tests/rfc_vectors.rs, cut from the RFC texts and Go's test file by
//! tools/gen_rfc_vectors.sh, each citing its line), then against independent implementations on this machine
//! (coreutils' sha256sum, OpenSSL's command line) over inputs no table covers. SCRAM-SHA-256 against RFC 7677's
//! example, through the one function a login uses; §4's pinned exchanges are tests/codec.rs's and t_wire_file.rs's.
mod common;
#[allow(dead_code)]
mod rfc_vectors;

use std::io::Write;
use std::process::{Command, Stdio};

use common::{hex, hexs};
use imagedb::crypto::hmac::{hmac_sha256, pbkdf2_sha256, HmacSha256};
use imagedb::crypto::sha256::{sha256, Sha256};
use imagedb::crypto::{ct_eq, random, scram};

#[test]
fn sha256_fips180_examples_rfc6234() {
    // RFC 6234 section 8.4's tests 1 to 4 (FIPS 180's "abc", its two-block message, a million 'a', an exact multiple of
    // 512 bits) and 6 (SHAVS's one-byte message)
    assert_eq!(rfc_vectors::SHA256_6234.len(), 5);
    for (msg, repeat, want, line) in rfc_vectors::SHA256_6234 {
        let mut s = Sha256::new();
        for _ in 0..*repeat {
            s.update(msg);
        }
        assert_eq!(hexs(&s.finalize()), *want, "RFC 6234 line {line}");
    }
}

#[test]
fn sha256_shavs_bytes_rfc6234() {
    // RFC 6234's tests 8 (16 bytes) and 10 (163 bytes), the byte-oriented ones it takes from NIST's SHAVS
    let v = rfc_vectors::SHA256_SHAVS_6234;
    assert_eq!(v.iter().map(|x| hex(x.0).len()).collect::<Vec<_>>(), vec![16, 163]);
    for (msg, want, line) in v {
        assert_eq!(hexs(&sha256(&hex(msg))), *want, "RFC 6234 line {line}");
    }
}

#[test]
fn sha256_go_golden_table() {
    // a second published table: Go's crypto/sha256 golden vectors, 0 to 132 bytes (the empty message, every length
    // 0 to 10, sentences across the 55/56-byte padding edge and past one block)
    let v = rfc_vectors::SHA256_GO;
    assert_eq!(v.len(), 31);
    assert!(v.iter().any(|x| x.0.is_empty()) && v.iter().any(|x| x.0.len() > 64));
    for (msg, want, line) in v {
        assert_eq!(hexs(&sha256(msg)), *want, "sha256_test.go line {line}");
    }
}

#[test]
fn sha256_streaming_splits() {
    // any split of the input gives the one-shot digest (the buffer's edges at 55, 56, 63, 64 and 65 bytes)
    let data: Vec<u8> = (0..300u32).map(|i| (i * 7 + 3) as u8).collect();
    for n in [0usize, 1, 55, 56, 57, 63, 64, 65, 119, 120, 128, 300] {
        let want = sha256(&data[..n]);
        for cut in 0..=n {
            let mut s = Sha256::new();
            s.update(&data[..cut]);
            s.update(&data[cut..n]);
            assert_eq!(s.finalize(), want, "n {n} cut {cut}");
        }
    }
}

/// Bytes from a small deterministic generator (xorshift64*): inputs no published table holds.
fn drawn(n: usize, seed: u64) -> Vec<u8> {
    let mut x = seed | 1;
    (0..n)
        .map(|_| {
            x ^= x >> 12;
            x ^= x << 25;
            x ^= x >> 27;
            (x.wrapping_mul(0x2545_f491_4f6c_dd1d) >> 56) as u8
        })
        .collect()
}

/// A tool's output for `input` on its stdin, or None (and a line saying so) when the tool is not on this machine.
fn tool(cmd: &str, args: &[&str], input: &[u8]) -> Option<String> {
    let child = Command::new(cmd).args(args).stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn();
    let mut child = match child {
        Ok(c) => c,
        Err(e) => {
            eprintln!("    not run: {cmd}: {e}");
            return None;
        }
    };
    {
        let mut si = child.stdin.take().unwrap();
        si.write_all(input).unwrap();
    }
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success(), "{cmd} {args:?}: {}", String::from_utf8_lossy(&out.stderr));
    Some(String::from_utf8(out.stdout).unwrap())
}

#[test]
fn sha256_against_coreutils() {
    // every length 0 to 300 (every padding case of one to six blocks), then longer inputs, against sha256sum
    let mut lens: Vec<usize> = (0..=300).collect();
    lens.extend([447, 448, 511, 512, 513, 1000, 4096, 65535, 65536, 1 << 20, (1 << 20) + 7]);
    let mut ran = 0;
    for (k, n) in lens.into_iter().enumerate() {
        let m = drawn(n, 0x9e37_79b9_7f4a_7c15 ^ k as u64);
        let Some(out) = tool("sha256sum", &[], &m) else { return };
        assert_eq!(&out[..64], hexs(&sha256(&m)), "{n} bytes");
        ran += 1;
    }
    eprintln!("    sha256sum agreed on {ran} inputs");
}

#[test]
fn hmac_rfc4231() {
    assert_eq!(rfc_vectors::HMAC_4231.len(), 7);
    for (key, data, want, line) in rfc_vectors::HMAC_4231 {
        let mac = hmac_sha256(&hex(key), &hex(data));
        let w = hex(want);
        assert_eq!(&mac[..w.len()], &w[..], "RFC 4231 line {line}");
        let mut m = HmacSha256::new(&hex(key));
        for b in hex(data).chunks(5) {
            m.update(b);
        }
        assert_eq!(m.finalize(), mac);
    }
}

#[test]
fn hmac_against_openssl() {
    // keys shorter than, equal to and longer than a block (hashed first), messages across the block edges
    let mut ran = 0;
    for (k, (klen, mlen)) in [(1, 0), (20, 1), (32, 55), (63, 56), (64, 64), (65, 65), (131, 200), (32, 1000)].iter().enumerate() {
        let key = drawn(*klen, 77 + k as u64);
        let msg = drawn(*mlen, 99 + k as u64);
        let opt = format!("hexkey:{}", hexs(&key));
        let Some(out) = tool("openssl", &["dgst", "-sha256", "-mac", "HMAC", "-macopt", opt.as_str()], &msg) else { return };
        let got = out.trim().rsplit(' ').next().unwrap().to_string();
        assert_eq!(got, hexs(&hmac_sha256(&key, &msg)), "key {klen} message {mlen}");
        ran += 1;
    }
    eprintln!("    openssl dgst -mac HMAC agreed on {ran} inputs");
}

#[test]
fn pbkdf2_rfc7914() {
    assert_eq!(rfc_vectors::PBKDF2_7914.len(), 2);
    for (pw, salt, c, want, line) in rfc_vectors::PBKDF2_7914 {
        let mut out = vec![0u8; 64];
        pbkdf2_sha256(pw.as_bytes(), salt.as_bytes(), *c, &mut out);
        assert_eq!(hexs(&out), *want, "RFC 7914 line {line}");
    }
}

#[test]
fn pbkdf2_against_openssl() {
    // SCRAM's shape: one 32-byte block; salts of 8, 16 and 64 bytes (a verifier's range), passwords of 1 to 1,024 bytes,
    // iterations from 1 to 4,096 (the pinned exchanges')
    let mut ran = 0;
    for (k, (pl, sl, it)) in [(1, 8, 1), (6, 16, 2), (6, 16, 1000), (64, 64, 4096), (65, 13, 3), (1024, 64, 1000)].iter().enumerate() {
        let pw = drawn(*pl, 5 + k as u64);
        let salt = drawn(*sl, 50 + k as u64);
        let (hp, hs, ic) = (format!("hexpass:{}", hexs(&pw)), format!("hexsalt:{}", hexs(&salt)), format!("iter:{it}"));
        let args = ["kdf", "-keylen", "32", "-kdfopt", "digest:SHA256", "-kdfopt", hp.as_str(), "-kdfopt", hs.as_str(), "-kdfopt", ic.as_str(), "PBKDF2"];
        let Some(out) = tool("openssl", &args, b"") else { return };
        let want: String = out.trim().chars().filter(|c| *c != ':').collect::<String>().to_lowercase();
        let mut got = [0u8; 32];
        pbkdf2_sha256(&pw, &salt, *it, &mut got);
        assert_eq!(hexs(&got), want, "password {pl}, salt {sl}, {it} iterations");
        ran += 1;
    }
    eprintln!("    openssl kdf PBKDF2 agreed on {ran} inputs");
}

/// RFC 4648 base64 with padding (the RFC's example prints its values so).
fn b64(b: &[u8]) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut s = String::new();
    for c in b.chunks(3) {
        let n = (c[0] as u32) << 16 | (*c.get(1).unwrap_or(&0) as u32) << 8 | *c.get(2).unwrap_or(&0) as u32;
        for i in 0..4 {
            if i <= c.len() {
                s.push(A[(n >> (18 - 6 * i) & 63) as usize] as char);
            } else {
                s.push('=');
            }
        }
    }
    s
}

#[test]
fn scram_rfc7677_example() {
    // RFC 7677 section 3: user "user", password "pencil", salt W22ZaJ0SNY7soEsUEjb6gQ== (4096 iterations), the client's
    // proof and the server's signature it prints. Copied from imagedb's tests/unit/t_role.c lines 162-174 (where the
    // engine's verifier is held to the same exchange): the salt's bytes (:164), the AuthMessage (:168-169, the RFC's
    // client-first-bare "," server-first "," client-final-without-proof), the signature (:172) and the proof (:174).
    let salt = [0x5b, 0x6d, 0x99, 0x68, 0x9d, 0x12, 0x35, 0x8e, 0xec, 0xa0, 0x4b, 0x14, 0x12, 0x36, 0xfa, 0x81];
    assert_eq!(b64(&salt), "W22ZaJ0SNY7soEsUEjb6gQ==");
    let am = "n=user,r=rOprNGfwEbeRWgbNEkqO,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,s=W22ZaJ0SNY7soEsUEjb6gQ==,\
              i=4096,c=biws,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0";
    let (proof, sig) = scram::client(b"pencil", &salt, 4096, am.as_bytes());
    assert_eq!(b64(&proof), "dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ=");
    assert_eq!(b64(&sig), "6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4=");
    // one byte of the AuthMessage, the password or the salt changed: both values change
    let (p2, s2) = scram::client(b"pencil", &salt, 4096, &am.as_bytes()[..am.len() - 1]);
    let (p3, s3) = scram::client(b"pencim", &salt, 4096, am.as_bytes());
    let mut salt2 = salt;
    salt2[15] ^= 1;
    let (p4, s4) = scram::client(b"pencil", &salt2, 4096, am.as_bytes());
    for (p, s) in [(p2, s2), (p3, s3), (p4, s4)] {
        assert!(p != proof && s != sig);
    }
}

#[test]
fn ct_eq_rules() {
    assert!(ct_eq(b"", b""));
    assert!(ct_eq(b"abc", b"abc"));
    assert!(!ct_eq(b"abc", b"abd"));
    assert!(!ct_eq(b"abc", b"ab"));
    for i in 0..32 {
        for bit in 0..8 {
            let a = [7u8; 32];
            let mut b = a;
            b[i] ^= 1 << bit;
            assert!(!ct_eq(&a, &b));
        }
    }
}

#[test]
fn random_from_the_os() {
    // two draws of a nonce's size differ (a generator stuck at a constant fails this; 2^-256 by chance)
    let (mut a, mut b) = ([0u8; 32], [0u8; 32]);
    random(&mut a).unwrap();
    random(&mut b).unwrap();
    assert_ne!(a, b);
    assert_ne!(a, [0u8; 32]);
}
