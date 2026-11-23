/* SCRAM-SHA-256 (RFC 5802's computation) over IMDBWIR1's AuthMessage (docs/n1-design.md §4): the client's proof and the
 * server's signature it expects, from the password's bytes. Node's crypto alone; the secrets wiped after use. */
import * as crypto from 'crypto';
import { ERR, ProtocolError } from './errors';
import { AUTHMSG_LEN, Challenge, challengeValid, KEY, PW_MAX } from './wire';

/* a password as CREATE ROLE takes one: 1 to 1,024 bytes of printable ASCII (no SASLprep in imagedb yet) */
export function passwordBytes(pw: string | Uint8Array): Buffer {
    const b = typeof pw === 'string' ? Buffer.from(pw, 'latin1') : Buffer.from(pw);
    let ok = b.length >= 1 && b.length <= PW_MAX && (typeof pw !== 'string' || pw.length === b.length);
    for (let i = 0; ok && i < b.length; i++) if (b[i] < 0x20 || b[i] > 0x7e) ok = false;
    if (typeof pw === 'string') for (let i = 0; ok && i < pw.length; i++) if (pw.charCodeAt(i) > 0x7e) ok = false;
    if (!ok) {
        b.fill(0);
        throw new ProtocolError(ERR.INVALID, 'a password is 1 to 1,024 printable ASCII bytes');
    }
    return b;
}

function hmac(key: Uint8Array, msg: Uint8Array | string): Buffer {
    return crypto.createHmac('sha256', key).update(msg).digest();
}

function pbkdf2(pw: Uint8Array, salt: Uint8Array, iter: number): Promise<Buffer> {
    return new Promise((res, rej) => crypto.pbkdf2(pw, salt, iter, 32, 'sha256', (e, k) => (e ? rej(e) : res(k))));
}

export interface ScramResult {
    proof: Buffer;
    serverSig: Buffer; /* what the server's verdict must carry: it proves the server holds the verifier */
}

/* from the password and the challenge, over the AuthMessage both sides hold: SaltedPassword, ClientKey, StoredKey,
 * ServerKey, ClientSignature, ClientProof and ServerSignature as RFC 5802 */
export async function scramClient(password: string | Uint8Array, c: Challenge, am: Buffer): Promise<ScramResult> {
    if (!challengeValid(c) || am.length !== AUTHMSG_LEN) throw new ProtocolError(ERR.INVALID, 'a challenge or AuthMessage its client refuses');
    const pw = passwordBytes(password);
    const sp = await pbkdf2(pw, c.salt, c.iter);
    pw.fill(0);
    const ck = hmac(sp, 'Client Key');
    const sk = hmac(sp, 'Server Key');
    const stored = crypto.createHash('sha256').update(ck).digest();
    const cs = hmac(stored, am);
    const proof = Buffer.alloc(KEY);
    for (let i = 0; i < KEY; i++) proof[i] = ck[i] ^ cs[i];
    const serverSig = hmac(sk, am);
    for (const b of [sp, ck, sk, stored, cs]) b.fill(0);
    return { proof, serverSig };
}

/* the server's side (a test's fake server): a verifier's keys from the password, the proof checked in constant time */
export function scramVerifier(password: string, salt: Uint8Array, iter: number): { stored: Buffer; serverKey: Buffer } {
    const sp = crypto.pbkdf2Sync(passwordBytes(password), salt, iter, 32, 'sha256');
    const ck = hmac(sp, 'Client Key');
    const stored = crypto.createHash('sha256').update(ck).digest();
    return { stored, serverKey: hmac(sp, 'Server Key') };
}
export function scramServer(stored: Buffer, serverKey: Buffer, am: Buffer, proof: Buffer): { ok: boolean; sig: Buffer } {
    const cs = hmac(stored, am);
    const ck = Buffer.alloc(KEY);
    for (let i = 0; i < KEY; i++) ck[i] = proof[i] ^ cs[i];
    const h = crypto.createHash('sha256').update(ck).digest();
    return { ok: crypto.timingSafeEqual(h, stored), sig: hmac(serverKey, am) };
}
