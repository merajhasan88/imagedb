//! The driver's own cryptography (the user's decision: no crates; std alone). Stage 1 holds what a login over the Unix
//! socket needs: SHA-256, HMAC-SHA-256, PBKDF2-HMAC-SHA-256 and SCRAM-SHA-256's client computation, each tested against
//! its published vectors (tests/crypto.rs), and the constant-time comparison a server's signature is checked with.
//! TLS 1.3's primitives (X25519, ChaCha20-Poly1305, HKDF, P-256 ECDSA, X.509) are stage 2's, not built here.

pub mod hmac;
pub mod scram;
pub mod sha256;

use std::io::Read;
use std::sync::atomic::{compiler_fence, Ordering};

/// Overwrites a secret with zeros in a way the optimizer keeps.
pub fn wipe(b: &mut [u8]) {
    for x in b.iter_mut() {
        // SAFETY: a valid, aligned, exclusive reference to one byte.
        unsafe { std::ptr::write_volatile(x, 0) };
    }
    compiler_fence(Ordering::SeqCst);
}

pub(crate) fn wipe_u32(b: &mut [u32]) {
    for x in b.iter_mut() {
        // SAFETY: a valid, aligned, exclusive reference.
        unsafe { std::ptr::write_volatile(x, 0) };
    }
    compiler_fence(Ordering::SeqCst);
}

/// Equality of two byte strings in time that depends on their length alone, never on where they differ.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut d = 0u8;
    for (x, y) in a.iter().zip(b) {
        d |= x ^ y;
    }
    // a data dependency the optimizer cannot short-circuit: the bits folded, then one comparison of the fold
    let d = std::hint::black_box(d);
    d == 0
}

/// Every random value the driver makes (the SCRAM client nonce) comes from here: the operating system's generator, read
/// from /dev/urandom (std exposes no generator of its own; the getrandom syscall needs libc). The file must be a
/// character device (a path someone replaced is refused), and a failed or short read is an error the connection fails
/// with, never a fallback.
pub fn random(out: &mut [u8]) -> std::io::Result<()> {
    use std::os::unix::fs::FileTypeExt;
    let mut f = std::fs::File::open("/dev/urandom")?;
    if !f.metadata()?.file_type().is_char_device() {
        return Err(std::io::Error::other("/dev/urandom is not a character device"));
    }
    f.read_exact(out)
}
