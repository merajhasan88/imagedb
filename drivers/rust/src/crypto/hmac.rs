//! HMAC-SHA-256 (RFC 2104) and PBKDF2-HMAC-SHA-256 (RFC 8018). Key-derived pads are wiped when dropped. (HKDF, TLS
//! 1.3's, is stage 2's: parked-tls-unreviewed/.)

use super::sha256::{Sha256, BLOCK, LEN};
use super::wipe;

#[derive(Clone)]
pub struct HmacSha256 {
    inner: Sha256,
    outer: Sha256,
}

impl HmacSha256 {
    pub fn new(key: &[u8]) -> Self {
        let mut k = [0u8; BLOCK];
        if key.len() > BLOCK {
            k[..LEN].copy_from_slice(&super::sha256::sha256(key));
        } else {
            k[..key.len()].copy_from_slice(key);
        }
        let mut ipad = [0u8; BLOCK];
        let mut opad = [0u8; BLOCK];
        for i in 0..BLOCK {
            ipad[i] = k[i] ^ 0x36;
            opad[i] = k[i] ^ 0x5c;
        }
        let mut inner = Sha256::new();
        inner.update(&ipad);
        let mut outer = Sha256::new();
        outer.update(&opad);
        wipe(&mut k);
        wipe(&mut ipad);
        wipe(&mut opad);
        HmacSha256 { inner, outer }
    }

    pub fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    pub fn finalize(self) -> [u8; 32] {
        let HmacSha256 { inner, mut outer } = self;
        let mut ih = inner.finalize();
        outer.update(&ih);
        wipe(&mut ih);
        outer.finalize()
    }
}

/// HMAC-SHA-256 of one message.
pub fn hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; 32] {
    let mut m = HmacSha256::new(key);
    m.update(msg);
    m.finalize()
}

/// PBKDF2-HMAC-SHA-256 (RFC 8018 5.2) into `out` (any length; SCRAM takes 32 bytes, one block).
pub fn pbkdf2_sha256(password: &[u8], salt: &[u8], iterations: u32, out: &mut [u8]) {
    assert!(iterations >= 1);
    let prf = HmacSha256::new(password);
    for (block, chunk) in out.chunks_mut(LEN).enumerate() {
        let i = (block as u32).checked_add(1).expect("PBKDF2: too long an output");
        let mut m = prf.clone();
        m.update(salt);
        m.update(&i.to_be_bytes());
        let mut u = m.finalize();
        let mut t = u;
        for _ in 1..iterations {
            let mut m = prf.clone();
            m.update(&u);
            let next = m.finalize();
            u = next;
            for k in 0..LEN {
                t[k] ^= u[k];
            }
        }
        chunk.copy_from_slice(&t[..chunk.len()]);
        wipe(&mut u);
        wipe(&mut t);
    }
}
