//! SCRAM-SHA-256's client computation (RFC 5802 section 3 with SHA-256, RFC 7677): from a password, a salt, an
//! iteration count and the AuthMessage's bytes, the ClientProof to send and the ServerSignature to expect. The
//! AuthMessage is any bytes, so RFC 7677's text exchange and IMDBWIR1's 279-byte AuthMessage (§4) run through this one
//! function: the RFC's example tests the code a login uses. Every intermediate key is wiped.

use super::hmac::{hmac_sha256, pbkdf2_sha256};
use super::sha256::sha256;
use super::wipe;

/// SaltedPassword = PBKDF2-HMAC-SHA-256(password, salt, i); ClientKey = HMAC(SaltedPassword, "Client Key"); StoredKey =
/// SHA-256(ClientKey); ClientSignature = HMAC(StoredKey, AuthMessage); ClientProof = ClientKey XOR ClientSignature;
/// ServerKey = HMAC(SaltedPassword, "Server Key"); ServerSignature = HMAC(ServerKey, AuthMessage). Returns (ClientProof,
/// ServerSignature). `iterations` is at least 1 (PBKDF2's own rule; IMDBWIR1's challenge holds 1,000 to 1,000,000,
/// checked by its decoder before this runs).
pub fn client(password: &[u8], salt: &[u8], iterations: u32, auth_message: &[u8]) -> ([u8; 32], [u8; 32]) {
    let mut sp = [0u8; 32];
    pbkdf2_sha256(password, salt, iterations, &mut sp);
    let mut ck = hmac_sha256(&sp, b"Client Key");
    let mut sk = hmac_sha256(&sp, b"Server Key");
    let mut stored = sha256(&ck);
    let mut cs = hmac_sha256(&stored, auth_message);
    let mut proof = [0u8; 32];
    for i in 0..32 {
        proof[i] = ck[i] ^ cs[i];
    }
    let sig = hmac_sha256(&sk, auth_message);
    wipe(&mut sp);
    wipe(&mut ck);
    wipe(&mut sk);
    wipe(&mut stored);
    wipe(&mut cs);
    (proof, sig)
}
