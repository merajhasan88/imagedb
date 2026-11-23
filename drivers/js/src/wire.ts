/* IMDBWIR1's bytes (docs/n1-design.md §4; the C reference server/wire.c), the protocol level under the driver. Every
 * decoder is strict as wire.c's: exact lengths, no trailing bytes, zero padding, every count bounded by the bytes left
 * before anything is sized by it; each field has one predicate, applied by its decoder and its encoder, so an encoder
 * never writes what its decoder refuses and any bytes a decoder takes encode back to themselves (the tests hold both).
 * Every integer is little-endian. */
import { ERR, ProtocolError } from './errors';

export const MAGIC = 'IMDBWIR1';
export const VERSION = 1;
export const PREAUTH_HEAD = 12;
export const USER_FIELD = 64;
export const NONCE = 32;
export const SALT_FIELD = 64;
export const KEY = 32;
export const HELLO_LEN = 112;
export const CHALLENGE_LEN = 120;
export const PROOF_LEN = 32;
export const VERDICT_LEN = 36;
export const AUTHMSG_LEN = 279;
export const HEAD = 5;
export const FRAME_MAX = 16 << 20;
export const BATCH_MAX = 4096;
export const VALUES_MAX = 256;
export const NAME_MAX = 63;
export const COLNAME_MAX = 70;
export const SQL_MAX = 1 << 22;
export const VALUE_MAX = 65535;
export const LABEL_MAX = 63;
export const LABELS_MAX = 1024;
export const STATUS_MAX = 511;
export const MESSAGE_MAX = 4096;
export const ITER_MIN = 1000;
export const ITER_MAX = 1000000;
export const SALT_MIN = 8;
export const PW_MAX = 1024;
export const SESSIONS_MAX = 65536;
export const COPY_PIECE = 1 << 20; /* a COPY_DATA frame's bytes at most (the C client's cut) */

export const EP = { TCP: 1, UNIX: 2 } as const;
export const CB = { NONE: 0, EXPORTER: 1, ENDPOINT: 2 } as const;
export const VERDICT = { OK: 0, REFUSED: 1, BINDING: 2 } as const;

export const F = {
    QUERY: 1,
    PREPARE: 2,
    EXECUTE: 3,
    DEALLOCATE: 4,
    COPY_DATA: 5,
    COPY_DONE: 6,
    COPY_FAIL: 7,
    CANCEL: 8,
    PING: 9,
    TERMINATE: 10,
    SESSIONS: 11,
    KILL: 12,
    COLUMNS: 64,
    ROWS: 65,
    DONE: 66,
    ERROR: 67,
    WARNING: 68,
    COPY_IN: 69,
    COPY_OUT: 70,
    READY: 71,
    PONG: 72,
    SESSIONS_LIST: 73,
    KILL_DONE: 74,
} as const;
export const CLIENT_LAST = 12;
export const SERVER_FIRST = 64;
export const SERVER_LAST = 74;
export const FRAME_NAMES: { [t: number]: string } = {};
for (const k of Object.keys(F) as (keyof typeof F)[]) FRAME_NAMES[F[k]] = k;

export const READY_STATE = { IDLE: 0, IN_TXN: 1, DOOMED: 2 } as const;
export const KILL_KIND = { CANCEL: 1, TERMINATE: 2 } as const;
export const KILL_CODE = { KILLED: 0, NONE: 1 } as const;
export const SESS_STATE = { IDLE: 0, RUNNING: 1, IN_TXN: 2, COPY: 3 } as const;

export const T = {
    NONE: 0,
    INT64: 1,
    FLOAT64: 2,
    BOOL: 3,
    TEXT: 4,
    DECIMAL: 5,
    TIMESTAMP: 6,
    TIMESTAMPTZ: 7,
    DATE: 8,
    TIME: 9,
    UUID: 10,
    BYTEA: 11,
    INTERVAL: 12,
    ENUM: 13,
} as const;
export const T_LAST = 13;
export const NULL_TAG = 0x80;
export const TYPE_NAMES = ['NONE', 'INT64', 'FLOAT64', 'BOOL', 'TEXT', 'DECIMAL', 'TIMESTAMP', 'TIMESTAMPTZ', 'DATE', 'TIME',
    'UUID', 'BYTEA', 'INTERVAL', 'ENUM'] as const;
export type TypeName = typeof TYPE_NAMES[number];

export const TS_MIN_US = -62135596800000000n; /* 0001-01-01 00:00:00 */
export const TS_MAX_US = 253402300799999999n; /* 9999-12-31 23:59:59.999999 */
export const DATE_MIN = -719162; /* 0001-01-01 */
export const DATE_MAX = 2932896; /* 9999-12-31 */
export const TIME_MAX = 86399999999n;
export const DEC_LIM = 10n ** 38n;
const I64_MIN = -(1n << 63n);
const I64_MAX = (1n << 63n) - 1n;
const U64_MAX = (1n << 64n) - 1n;
const I32_MIN = -(2 ** 31);
const I32_MAX = 2 ** 31 - 1;

function bad(what: string): never {
    throw new ProtocolError(ERR.CORRUPT, 'wire: ' + what);
}
function overLimit(what: string): never {
    throw new ProtocolError(ERR.LIMIT, 'wire: ' + what);
}

/* ---- UTF-8 by the engine's rule (wire.c utf8_valid: no NUL, no overlong form, no surrogate, nothing past U+10FFFF):
 * -1 when valid, else the offset of the first byte of the first character that is not one ---- */
export function utf8Invalid(s: Uint8Array, start = 0, end = s.length): number {
    let i = start;
    while (i < end) {
        const c = s[i];
        if (c >= 0x01 && c < 0x80) {
            i++;
            continue;
        }
        let need: number;
        let lo = 0x80, hi = 0xbf;
        if (c >= 0xc2 && c <= 0xdf) need = 1;
        else if (c === 0xe0) (need = 2), (lo = 0xa0);
        else if (c >= 0xe1 && c <= 0xec) need = 2;
        else if (c === 0xed) (need = 2), (hi = 0x9f);
        else if (c === 0xee || c === 0xef) need = 2;
        else if (c === 0xf0) (need = 3), (lo = 0x90);
        else if (c >= 0xf1 && c <= 0xf3) need = 3;
        else if (c === 0xf4) (need = 3), (hi = 0x8f);
        else return i; /* NUL, C0, C1, F5..FF, a stray continuation */
        if (need > end - i - 1 || s[i + 1] < lo || s[i + 1] > hi) return i;
        for (let j = 2; j <= need; j++) if ((s[i + j] & 0xc0) !== 0x80) return i;
        i += need + 1;
    }
    return -1;
}
export function utf8Ok(s: Uint8Array, start = 0, end = s.length): boolean {
    return utf8Invalid(s, start, end) < 0;
}
/* characters of valid UTF-8: the bytes that begin one (a VARCHAR's length, in characters) */
export function utf8Chars(s: Uint8Array, start = 0, end = s.length): number {
    let k = 0;
    for (let i = start; i < end; i++) if ((s[i] & 0xc0) !== 0x80) k++;
    return k;
}
/* the longest prefix of s, at most max bytes, that is UTF-8 without NUL, never cut inside a character (wire.c's
 * imdbw_utf8_fit: a message cut to its bound) */
export function utf8Fit(s: Uint8Array, max: number): number {
    const k = Math.min(s.length, max);
    if (!k) return 0;
    const at = utf8Invalid(s, 0, k);
    return at < 0 ? k : at;
}
/* a JS string holds UTF-16, which may carry a lone surrogate: Buffer.from would write U+FFFD in its place, silently.
 * Such a string has no UTF-8 form and is refused, as is a NUL (the engine's TEXT has none) */
export function wellFormed(s: string): boolean {
    for (let i = 0; i < s.length; i++) {
        const c = s.charCodeAt(i);
        if (c >= 0xd800 && c <= 0xdbff) {
            const d = i + 1 < s.length ? s.charCodeAt(i + 1) : 0;
            if (d < 0xdc00 || d > 0xdfff) return false;
            i++;
        } else if (c >= 0xdc00 && c <= 0xdfff) return false;
    }
    return true;
}
/* a text's bytes: UTF-8 without NUL, or null when it has none */
export function textBytes(s: string): Buffer | null {
    if (!wellFormed(s) || s.indexOf('\u0000') >= 0) return null;
    return Buffer.from(s, 'utf8');
}
/* valid UTF-8 to its string: every byte kept (a leading U+FEFF too: toString never strips one) */
export function utf8String(b: Uint8Array, start = 0, end = b.length): string {
    return Buffer.from(b.buffer, b.byteOffset + start, end - start).toString('utf8');
}

/* ---- a bounded reader over a body (imdb_rd): a read past its end is a body cut short ---- */
export class Reader {
    b: Buffer;
    off: number;
    end: number;
    constructor(b: Buffer, off = 0, end = b.length) {
        this.b = b;
        this.off = off;
        this.end = end;
    }
    left(): number {
        return this.end - this.off;
    }
    private need(n: number, what: string): void {
        if (n > this.end - this.off) bad(what + ' cut short');
    }
    u8(what = 'a body'): number {
        this.need(1, what);
        return this.b[this.off++];
    }
    u16(what = 'a body'): number {
        this.need(2, what);
        const v = this.b.readUInt16LE(this.off);
        this.off += 2;
        return v;
    }
    u32(what = 'a body'): number {
        this.need(4, what);
        const v = this.b.readUInt32LE(this.off);
        this.off += 4;
        return v;
    }
    i32(what = 'a body'): number {
        this.need(4, what);
        const v = this.b.readInt32LE(this.off);
        this.off += 4;
        return v;
    }
    u64(what = 'a body'): bigint {
        this.need(8, what);
        const v = this.b.readBigUInt64LE(this.off);
        this.off += 8;
        return v;
    }
    i64(what = 'a body'): bigint {
        this.need(8, what);
        const v = this.b.readBigInt64LE(this.off);
        this.off += 8;
        return v;
    }
    i128(what = 'a body'): bigint {
        const lo = this.u64(what), hi = this.u64(what);
        return BigInt.asIntN(128, (hi << 64n) | lo);
    }
    bytes(n: number, what = 'a body'): Buffer {
        this.need(n, what);
        const v = this.b.subarray(this.off, this.off + n);
        this.off += n;
        return v;
    }
}

/* ---- an output buffer: grown by doubling, bounded by a frame (a write past 16 MiB and its head is refused) ---- */
export class Writer {
    b: Buffer;
    len = 0;
    constructor(cap = 256) {
        this.b = Buffer.alloc(cap);
    }
    private room(n: number): void {
        if (this.len + n > FRAME_MAX + HEAD) overLimit('a frame past ' + FRAME_MAX + ' bytes');
        if (this.len + n <= this.b.length) return;
        let cap = this.b.length || 256;
        while (cap < this.len + n) cap *= 2;
        const nb = Buffer.alloc(cap);
        this.b.copy(nb, 0, 0, this.len);
        this.b = nb;
    }
    u8(v: number): void {
        this.room(1);
        this.b[this.len++] = v;
    }
    u16(v: number): void {
        this.room(2);
        this.b.writeUInt16LE(v, this.len);
        this.len += 2;
    }
    u32(v: number): void {
        this.room(4);
        this.b.writeUInt32LE(v, this.len);
        this.len += 4;
    }
    i32(v: number): void {
        this.room(4);
        this.b.writeInt32LE(v, this.len);
        this.len += 4;
    }
    u64(v: bigint): void {
        this.room(8);
        this.b.writeBigUInt64LE(v, this.len);
        this.len += 8;
    }
    i64(v: bigint): void {
        this.room(8);
        this.b.writeBigInt64LE(v, this.len);
        this.len += 8;
    }
    i128(v: bigint): void {
        const u = BigInt.asUintN(128, v);
        this.u64(u & U64_MAX);
        this.u64(u >> 64n);
    }
    put(p: Uint8Array): void {
        this.room(p.length);
        this.b.set(p, this.len);
        this.len += p.length;
    }
    patchU32(at: number, v: number): void {
        this.b.writeUInt32LE(v, at);
    }
    done(): Buffer {
        return this.b.subarray(0, this.len);
    }
}

/* ======================================================================================================================
 * before authentication: fixed sizes
 * ==================================================================================================================== */

/* a role name's field: UTF-8, 1 to 63 bytes, no NUL */
export function userOk(u: Uint8Array): boolean {
    return u.length >= 1 && u.length < USER_FIELD && utf8Ok(u);
}

export interface Hello {
    version: number;
    flags: number; /* the channel binding's type: 0 none (the socket), 1 the exporter, 2 tls-server-end-point */
    user: Buffer;
    nonce: Buffer;
}
export interface Challenge {
    version: number;
    salt: Buffer; /* 8 to 64 bytes */
    iter: number;
    nonce: Buffer;
}
export interface Verdict {
    code: number;
    sig: Buffer;
}

/* the head every version keeps: any version read, version 0 and another magic as damage, a later magic by name */
export function preauthHead(b: Uint8Array): number {
    const m = Buffer.from(b.buffer, b.byteOffset, 8).toString('latin1');
    const version = Buffer.from(b.buffer, b.byteOffset, PREAUTH_HEAD).readUInt32LE(8);
    if (m !== MAGIC) {
        if (laterMagic(b)) throw new ProtocolError(ERR.UNSUPPORTED, 'wire: ' + m + ', a later protocol, which this driver does not speak');
        bad("not imagedb's protocol");
    }
    if (version < 1) bad('protocol version 0');
    return version;
}
/* "IMDBWIR" then a digit past 1: a later protocol (util.c imdb_later_magic's rule for this magic) */
function laterMagic(b: Uint8Array): boolean {
    for (let i = 0; i < 7; i++) if (b[i] !== MAGIC.charCodeAt(i)) return false;
    return b[7] > 0x31 && b[7] <= 0x39;
}

export function encodeHello(h: Hello): Buffer {
    if (h.version !== VERSION || !Number.isInteger(h.flags) || h.flags < 0 || h.flags > CB.ENDPOINT || !userOk(h.user) ||
        h.nonce.length !== NONCE)
        throw new ProtocolError(ERR.INVALID, 'wire: a hello its encoder refuses');
    const out = Buffer.alloc(HELLO_LEN);
    out.write(MAGIC, 0, 'latin1');
    out.writeUInt32LE(h.version, 8);
    out.writeUInt32LE(h.flags, 12);
    out.set(h.user, 16);
    out.set(h.nonce, 16 + USER_FIELD);
    return out;
}

function magicVersion(r: Reader): number {
    const m = r.bytes(8);
    const version = r.u32();
    if (m.toString('latin1') !== MAGIC) {
        if (laterMagic(m)) throw new ProtocolError(ERR.UNSUPPORTED, 'wire: ' + m.toString('latin1') + ', a later protocol, which this driver does not speak');
        bad("not imagedb's protocol");
    }
    if (version > VERSION)
        throw new ProtocolError(ERR.UNSUPPORTED, 'wire: protocol version ' + version + ', a later one, which this driver (version 1) does not speak');
    if (version !== VERSION) bad('an unknown protocol version');
    return version;
}

export function decodeHello(b: Buffer): Hello {
    if (b.length !== HELLO_LEN) bad('a hello of another length');
    const r = new Reader(b);
    const version = magicVersion(r);
    const flags = r.u32();
    const u = r.bytes(USER_FIELD);
    const nonce = Buffer.from(r.bytes(NONCE));
    if (flags > CB.ENDPOINT) bad('a hello with flags no version defines (a binding type but 0, 1, 2)');
    let n = u.indexOf(0);
    if (n < 0) n = USER_FIELD;
    const user = Buffer.from(u.subarray(0, n));
    if (n === USER_FIELD || !userOk(user) || !zeros(u, n, USER_FIELD))
        bad("a hello's role name is not 1 to 63 bytes of UTF-8, NUL-padded");
    return { version, flags, user, nonce };
}

function challengeOk(c: Challenge): boolean {
    return c.version === VERSION && c.salt.length >= SALT_MIN && c.salt.length <= SALT_FIELD && c.iter >= ITER_MIN &&
        c.iter <= ITER_MAX && c.nonce.length === NONCE;
}
export function challengeValid(c: Challenge): boolean {
    return challengeOk(c);
}

export function encodeChallenge(c: Challenge): Buffer {
    if (!challengeOk(c)) throw new ProtocolError(ERR.INVALID, 'wire: a challenge its encoder refuses');
    const out = Buffer.alloc(CHALLENGE_LEN);
    out.write(MAGIC, 0, 'latin1');
    out.writeUInt32LE(c.version, 8);
    out[12] = c.salt.length;
    out.set(c.salt, 13);
    out.writeUInt32LE(c.iter, 13 + SALT_FIELD);
    out.set(c.nonce, 17 + SALT_FIELD);
    return out; /* then 7 zeros */
}

export function decodeChallenge(b: Buffer): Challenge {
    if (b.length !== CHALLENGE_LEN) bad('a challenge of another length');
    const r = new Reader(b);
    const version = magicVersion(r);
    const saltLen = r.u8();
    const saltField = r.bytes(SALT_FIELD);
    const iter = r.u32();
    const nonce = Buffer.from(r.bytes(NONCE));
    const pad = r.bytes(7);
    const c: Challenge = { version, salt: Buffer.from(saltField.subarray(0, Math.min(saltLen, SALT_FIELD))), iter, nonce };
    if (saltLen < SALT_MIN || saltLen > SALT_FIELD || !challengeOk(c) || !zeros(saltField, saltLen, SALT_FIELD))
        bad("a challenge's salt is not 8 to 64 bytes, zero-padded, or its iterations not 1,000 to 1,000,000");
    if (!zeros(pad, 0, 7)) bad("a challenge's padding is not zero");
    return c;
}

function verdictOk(v: Verdict): boolean {
    return v.sig.length === KEY && (v.code === VERDICT.OK || ((v.code === VERDICT.REFUSED || v.code === VERDICT.BINDING) && zeros(v.sig, 0, KEY)));
}
export function encodeVerdict(v: Verdict): Buffer {
    if (!verdictOk(v)) throw new ProtocolError(ERR.INVALID, 'wire: a verdict its encoder refuses');
    const out = Buffer.alloc(VERDICT_LEN);
    out.writeUInt32LE(v.code, 0);
    out.set(v.sig, 4);
    return out;
}
export function decodeVerdict(b: Buffer): Verdict {
    if (b.length !== VERDICT_LEN) bad('a verdict of another length');
    const v = { code: b.readUInt32LE(0), sig: Buffer.from(b.subarray(4, 36)) };
    if (!verdictOk(v)) bad('a verdict neither accepted nor refused, or a refusal carrying a signature');
    return v;
}

/* "IMDBWIR1-SCRAM" (14) | u8 endpoint | the hello's 112 bytes | the challenge's 120 | binding[32]: every byte either side
 * sent before the proof, bound */
export function authMessage(endpoint: number, hello: Buffer, challenge: Buffer, binding: Buffer): Buffer {
    if (hello.length !== HELLO_LEN || challenge.length !== CHALLENGE_LEN || binding.length !== KEY)
        throw new ProtocolError(ERR.INVALID, 'wire: an AuthMessage of another layout');
    const out = Buffer.alloc(AUTHMSG_LEN);
    out.write('IMDBWIR1-SCRAM', 0, 'latin1');
    out[14] = endpoint;
    out.set(hello, 15);
    out.set(challenge, 15 + HELLO_LEN);
    out.set(binding, 15 + HELLO_LEN + CHALLENGE_LEN);
    return out;
}

function zeros(b: Uint8Array, from: number, to: number): boolean {
    for (let i = from; i < to; i++) if (b[i]) return false;
    return true;
}

/* ======================================================================================================================
 * values: a u8 tag (a type 1 to 13, or 0x80 | a type 0 to 13 for a NULL of that type), then its bytes
 * ==================================================================================================================== */

export interface WireValue {
    type: number;
    null: boolean;
    i: bigint; /* INT64, BOOL (0 or 1), TIMESTAMP, TIMESTAMPTZ, TIME, INTERVAL's microseconds */
    f: bigint; /* FLOAT64's bits */
    scale: number; /* DECIMAL */
    d: bigint; /* DECIMAL's unscaled value */
    mon: number; /* INTERVAL */
    day: number; /* INTERVAL; DATE's days */
    s: Buffer | null; /* TEXT, BYTEA, ENUM's label, UUID's 16 bytes */
}

export function wv(p: Partial<WireValue> & { type: number }): WireValue {
    return { null: false, i: 0n, f: 0n, scale: 0, d: 0n, mon: 0, day: 0, s: null, ...p };
}
export function wnull(type: number): WireValue {
    return wv({ type, null: true });
}

const isInt = (n: number, lo: number, hi: number) => Number.isInteger(n) && n >= lo && n <= hi;

/* the value's own rules: its decoder's and its encoder's */
export function valueOk(v: WireValue): boolean {
    if (v.null) return isInt(v.type, 0, T_LAST);
    switch (v.type) {
        case T.INT64:
            return v.i >= I64_MIN && v.i <= I64_MAX;
        case T.INTERVAL:
            return isInt(v.mon, I32_MIN, I32_MAX) && isInt(v.day, I32_MIN, I32_MAX) && v.i >= I64_MIN && v.i <= I64_MAX;
        case T.FLOAT64:
            return v.f >= 0n && v.f <= U64_MAX && ((v.f >> 52n) & 0x7ffn) !== 0x7ffn && v.f !== 0x8000000000000000n;
        case T.BOOL:
            return v.i === 0n || v.i === 1n;
        case T.TEXT:
            return !!v.s && v.s.length <= VALUE_MAX && utf8Ok(v.s);
        case T.BYTEA:
            return !!v.s && v.s.length <= VALUE_MAX;
        case T.ENUM:
            return !!v.s && v.s.length <= LABEL_MAX && utf8Ok(v.s);
        case T.DECIMAL:
            return isInt(v.scale, 0, 38) && v.d > -DEC_LIM && v.d < DEC_LIM;
        case T.TIMESTAMP:
        case T.TIMESTAMPTZ:
            return v.i >= TS_MIN_US && v.i <= TS_MAX_US;
        case T.DATE:
            return isInt(v.day, DATE_MIN, DATE_MAX);
        case T.TIME:
            return v.i >= 0n && v.i <= TIME_MAX;
        case T.UUID:
            return !!v.s && v.s.length === 16;
        default:
            return false; /* no type: only a NULL has none */
    }
}

export function encodeValue(w: Writer, v: WireValue): void {
    if (!valueOk(v)) throw new ProtocolError(ERR.INVALID, 'wire: a value its encoder refuses (' + (TYPE_NAMES[v.type] ?? 'type ' + v.type) + ')');
    if (v.null) {
        w.u8(NULL_TAG | v.type);
        return;
    }
    w.u8(v.type);
    switch (v.type) {
        case T.FLOAT64:
            w.u64(v.f);
            break;
        case T.BOOL:
            w.u8(Number(v.i));
            break;
        case T.TEXT:
        case T.BYTEA:
            w.u32(v.s!.length);
            w.put(v.s!);
            break;
        case T.ENUM:
            w.u8(v.s!.length);
            w.put(v.s!);
            break;
        case T.DECIMAL:
            w.u8(v.scale);
            w.i128(v.d);
            break;
        case T.DATE:
            w.i32(v.day);
            break;
        case T.UUID:
            w.put(v.s!);
            break;
        case T.INTERVAL:
            w.i32(v.mon);
            w.i32(v.day);
            w.i64(v.i);
            break;
        default: /* INT64, TIMESTAMP, TIMESTAMPTZ, TIME */
            w.i64(v.i);
    }
}

export function valueBytes(v: WireValue): Buffer {
    const w = new Writer(32);
    encodeValue(w, v);
    return Buffer.from(w.done());
}

/* one value; s points into the body it came in (copy it to keep it past that body) */
export function decodeValue(r: Reader): WireValue {
    const tag = r.u8('a value');
    if (tag & NULL_TAG) {
        const t = tag & ~NULL_TAG;
        if (t > T_LAST) bad('a NULL of a type the protocol does not define');
        return wnull(t);
    }
    const v = wv({ type: tag });
    switch (tag) {
        case T.INT64:
        case T.TIMESTAMP:
        case T.TIMESTAMPTZ:
        case T.TIME:
            v.i = r.i64('a value');
            break;
        case T.FLOAT64:
            v.f = r.u64('a value');
            break;
        case T.BOOL:
            v.i = BigInt(r.u8('a value'));
            break;
        case T.TEXT:
        case T.BYTEA:
        case T.ENUM: {
            const n = tag === T.ENUM ? r.u8('a value') : r.u32('a value');
            const max = tag === T.ENUM ? LABEL_MAX : VALUE_MAX;
            if (n > max) overLimit('a value of ' + n + ' bytes (at most ' + max + ')'); /* before its bytes are asked for */
            v.s = r.bytes(n, 'a value');
            break;
        }
        case T.DECIMAL:
            v.scale = r.u8('a value');
            v.d = r.i128('a value');
            break;
        case T.DATE:
            v.day = r.i32('a value');
            break;
        case T.UUID:
            v.s = r.bytes(16, 'a value');
            break;
        case T.INTERVAL:
            v.mon = r.i32('a value');
            v.day = r.i32('a value');
            v.i = r.i64('a value');
            break;
        default:
            bad("a value of a type the protocol does not define (a NULL's tag is 0x80 and its type)");
    }
    if (!valueOk(v)) bad("a value outside its type's rules");
    return v;
}

/* ======================================================================================================================
 * frames: u32 length (of the type and the body: 1 to 16 MiB) | u8 type | body
 * ==================================================================================================================== */

/* a frame's head checked before anything is sized by it; a type of the direction's */
export function checkHead(len: number, type: number, fromServer: boolean): void {
    if (len < 1 || len > FRAME_MAX) overLimit('a frame of ' + len + ' bytes (1 to ' + FRAME_MAX + ')');
    const known = fromServer ? type >= SERVER_FIRST && type <= SERVER_LAST : type >= 1 && type <= CLIENT_LAST;
    if (!known) bad('a frame of a type this side does not send (' + type + ')');
}

function frameBegin(type: number, cap = 64): Writer {
    const w = new Writer(cap);
    w.u32(0);
    w.u8(type);
    return w;
}
function frameEnd(w: Writer): Buffer {
    const n = w.len - 4;
    if (n > FRAME_MAX) overLimit('a frame past ' + FRAME_MAX + ' bytes');
    w.patchU32(0, n);
    return Buffer.from(w.done());
}

/* a text by its length's width: UTF-8 without NUL within its bounds */
function textPut(w: Writer, lenBytes: number, min: number, max: number, t: Buffer, what: string): void {
    if (t.length < min || t.length > max || !utf8Ok(t)) throw new ProtocolError(ERR.INVALID, 'wire: ' + what + ' its encoder refuses');
    if (lenBytes === 1) w.u8(t.length);
    else if (lenBytes === 2) w.u16(t.length);
    else w.u32(t.length);
    w.put(t);
}
function textGet(r: Reader, lenBytes: number, min: number, max: number): Buffer {
    const n = lenBytes === 1 ? r.u8('a text') : lenBytes === 2 ? r.u16('a text') : r.u32('a text');
    if (n < min || n > max) overLimit('a text of ' + n + ' bytes (' + min + ' to ' + max + ')');
    const t = r.bytes(n, 'a text');
    if (!utf8Ok(t)) bad('a text not UTF-8 without NUL');
    return t;
}
function str(s: string | Buffer, what: string): Buffer {
    if (typeof s !== 'string') return s;
    const b = textBytes(s);
    if (!b) throw new ProtocolError(ERR.INVALID, what + ': not text (a lone surrogate or a NUL)');
    return b;
}

/* ---- the client's frames ---- */

export interface Statement {
    sql: string | Buffer;
    params: WireValue[];
}

/* a parameter: any value but a non-NULL ENUM (a label is sent as TEXT) */
function paramPut(w: Writer, v: WireValue): void {
    if (v.type === T.ENUM && !v.null) throw new ProtocolError(ERR.INVALID, 'wire: an ENUM parameter: a label is sent as TEXT');
    encodeValue(w, v);
}

export function encodeQuery(stmts: Statement[]): Buffer {
    if (stmts.length < 1 || stmts.length > BATCH_MAX) throw new ProtocolError(ERR.LIMIT, 'a QUERY holds 1 to 4,096 statements');
    const w = frameBegin(F.QUERY, 256);
    w.u32(stmts.length);
    for (const st of stmts) {
        textPut(w, 4, 1, SQL_MAX, str(st.sql, 'a statement'), 'a statement (1 to 4 MiB of UTF-8 without NUL)');
        if (st.params.length > VALUES_MAX) throw new ProtocolError(ERR.LIMIT, 'a statement takes at most 256 values');
        w.u16(st.params.length);
        for (const v of st.params) paramPut(w, v);
    }
    return frameEnd(w);
}

function namePut(w: Writer, name: string | Buffer): void {
    textPut(w, 1, 1, NAME_MAX, str(name, "a prepared statement's name"), "a prepared statement's name (1 to 63 bytes)");
}

export function encodePrepare(name: string | Buffer, sql: string | Buffer): Buffer {
    const w = frameBegin(F.PREPARE, 128);
    namePut(w, name);
    textPut(w, 4, 1, SQL_MAX, str(sql, 'a statement'), 'a statement (1 to 4 MiB of UTF-8 without NUL)');
    return frameEnd(w);
}

/* sets x nvals values, in set order */
export function encodeExecute(name: string | Buffer, nvals: number, sets: WireValue[][]): Buffer {
    if (sets.length < 1 || sets.length > BATCH_MAX || !isInt(nvals, 0, VALUES_MAX))
        throw new ProtocolError(ERR.LIMIT, 'an EXECUTE of 1 to 4,096 sets of at most 256 values');
    const w = frameBegin(F.EXECUTE, 128);
    namePut(w, name);
    w.u32(sets.length);
    w.u16(nvals);
    for (const set of sets) {
        if (set.length !== nvals) throw new ProtocolError(ERR.INVALID, "an EXECUTE's sets each of the same count of values");
        for (const v of set) paramPut(w, v);
    }
    return frameEnd(w);
}

export function encodeDeallocate(name: string | Buffer): Buffer {
    const w = frameBegin(F.DEALLOCATE);
    namePut(w, name);
    return frameEnd(w);
}

export function encodeCopyData(data: Uint8Array): Buffer {
    if (data.length < 1) throw new ProtocolError(ERR.INVALID, 'a COPY piece of no bytes');
    const w = frameBegin(F.COPY_DATA, data.length + 8);
    w.put(data);
    return frameEnd(w);
}

export function encodeCopyFail(message: string | Buffer): Buffer {
    const w = frameBegin(F.COPY_FAIL);
    textPut(w, 2, 0, MESSAGE_MAX, str(message, "a COPY_FAIL's reason"), "a COPY_FAIL's reason (at most 4,096 bytes)");
    return frameEnd(w);
}

/* COPY_DONE, CANCEL, PING, TERMINATE, SESSIONS (the client's) and COPY_IN, PONG (the server's): no body */
const EMPTY_TYPES: number[] = [F.COPY_DONE, F.CANCEL, F.PING, F.TERMINATE, F.SESSIONS, F.COPY_IN, F.PONG];
export function encodeEmpty(type: number): Buffer {
    if (!EMPTY_TYPES.includes(type)) throw new ProtocolError(ERR.INVALID, 'wire: frame type ' + type + ' has a body');
    const b = Buffer.alloc(5);
    b.writeUInt32LE(1, 0);
    b[4] = type;
    return b;
}

function killOk(kind: number, sid: bigint): boolean {
    return (kind === KILL_KIND.CANCEL || kind === KILL_KIND.TERMINATE) && sid >= 1n && sid <= U64_MAX;
}
export function encodeKill(kind: number, sid: bigint): Buffer {
    if (!killOk(kind, sid)) throw new ProtocolError(ERR.INVALID, "a KILL's kind is cancel or terminate, its session an id from SESSIONS");
    const w = frameBegin(F.KILL);
    w.u8(kind);
    w.u64(sid);
    return frameEnd(w);
}

/* ---- the server's frames, decoded strictly ---- */

export interface WireColumn {
    name: string;
    type: number; /* 0 (not known: each value its own type) to 13 */
    precision: number;
    scale: number;
    labels: string[] | null; /* ENUM: its labels, in the type's order */
    labelSet: Set<string> | null;
}
export interface ReadPoint {
    commit: bigint;
    hash: Buffer;
    digest: Buffer;
    lakeCommit: bigint;
    lakeManifest: Buffer;
    dbId: Buffer;
    own: boolean;
}
export interface WritePoint {
    commit: bigint;
    hash: Buffer;
}
export interface DoneMsg {
    status: string;
    count: bigint;
    read: ReadPoint | null;
    write: WritePoint | null;
}
export interface SessionMsg {
    id: bigint;
    role: number;
    endpoint: number;
    state: number;
    ageMs: bigint;
    name: string;
}
export type ServerMsg =
    | { type: 64; columns: WireColumn[] }
    | { type: 65; rows: WireValue[][] }
    | { type: 66; done: DoneMsg }
    | { type: 67; code: number; index: number; message: string }
    | { type: 68; message: string }
    | { type: 69 }
    | { type: 70; data: Buffer }
    | { type: 71; state: number }
    | { type: 72 }
    | { type: 73; sessions: SessionMsg[] }
    | { type: 74; code: number; sid: bigint };

const intWidthOk = (p: number) => p === 0 || p === 16 || p === 32;

function colShapeOk(c: WireColumn, nameBytes: Buffer): boolean {
    if (nameBytes.length < 1 || nameBytes.length > COLNAME_MAX || !utf8Ok(nameBytes)) return false;
    if (!isInt(c.type, 0, T_LAST)) return false;
    if (c.type !== T.ENUM && c.labels) return false;
    if (c.type === T.ENUM && (!c.labels || c.labels.length > LABELS_MAX)) return false;
    switch (c.type) {
        case T.DECIMAL: /* precision 0: not known (a result's column), 38 digits */
            return c.precision <= 38 && c.scale <= (c.precision ? c.precision : 38);
        case T.INT64:
            return intWidthOk(c.precision) && !c.scale;
        case T.TEXT:
            return !c.scale; /* precision: a VARCHAR's length in characters, 0 none */
        default:
            return !c.precision && !c.scale;
    }
}

function colGet(r: Reader): WireColumn {
    const nb = textGet(r, 1, 1, COLNAME_MAX);
    const c: WireColumn = { name: utf8String(nb), type: r.u8('a column'), precision: r.u16('a column'), scale: r.u16('a column'), labels: null, labelSet: null };
    if (c.type === T.ENUM) {
        const n = r.u16('a column');
        if (n > LABELS_MAX || n > r.left()) bad("an ENUM's labels past their bounds or bytes");
        c.labels = [];
        for (let i = 0; i < n; i++) c.labels.push(utf8String(textGet(r, 1, 0, LABEL_MAX)));
        c.labelSet = new Set(c.labels);
    }
    if (!colShapeOk(c, nb)) bad("a column's type, precision or scale its type does not take");
    if (c.labelSet && c.labelSet.size !== c.labels!.length) bad("an ENUM's labels not distinct");
    return c;
}

/* a value against its column (ROWS' rule): NULL of its type, or its type at the column's scale and within its precision,
 * an integer within its width, a TEXT within its VARCHAR's characters, an ENUM one of its labels */
export function valueFits(c: WireColumn, v: WireValue): boolean {
    if (!valueOk(v)) return false;
    if (c.type === T.NONE) return true;
    if (v.type !== c.type) return false; /* a NULL too: one tag a column, its type's */
    if (v.null) return true;
    switch (c.type) {
        case T.DECIMAL: {
            const lim = c.precision ? 10n ** BigInt(c.precision) : DEC_LIM;
            return v.scale === c.scale && v.d > -lim && v.d < lim;
        }
        case T.INT64:
            return c.precision === 16 ? v.i >= -32768n && v.i <= 32767n
                : c.precision === 32 ? v.i >= -2147483648n && v.i <= 2147483647n
                : true;
        case T.TEXT:
            return !c.precision || utf8Chars(v.s!) <= c.precision;
        case T.ENUM:
            return c.labelSet!.has(utf8String(v.s!));
        default:
            return true;
    }
}

const SESS_MIN = 23; /* an entry's bytes at least: u64 id, u32 role, u8 endpoint, u8 state, u64 age, u8 length */

export function decodeServer(type: number, body: Buffer, cols: WireColumn[] | null): ServerMsg {
    const r = new Reader(body);
    let m: ServerMsg;
    switch (type) {
        case F.COLUMNS: {
            const n = r.u16();
            if (n < 1 || n > VALUES_MAX || n > Math.floor(r.left() / 7)) bad('a COLUMNS of 1 to 256 columns it holds the bytes of');
            const columns: WireColumn[] = [];
            for (let i = 0; i < n; i++) columns.push(colGet(r));
            m = { type: 64, columns };
            break;
        }
        case F.ROWS: {
            if (!cols || cols.length < 1) bad('a ROWS with no COLUMNS before it');
            const n = r.u32();
            if (n < 1) bad('a ROWS of no row');
            const nv = n * cols.length;
            if (nv > r.left()) bad('more values than bytes'); /* each value is at least one byte */
            const rows: WireValue[][] = [];
            for (let k = 0; k < n; k++) {
                const row: WireValue[] = [];
                for (let j = 0; j < cols.length; j++) {
                    const v = decodeValue(r);
                    if (!valueFits(cols[j], v)) bad('a value its column does not take (column ' + (j + 1) + ', ' + cols[j].name + ')');
                    row.push(v);
                }
                rows.push(row);
            }
            m = { type: 65, rows };
            break;
        }
        case F.DONE: {
            const status = utf8String(textGet(r, 2, 0, STATUS_MAX));
            const count = r.u64();
            const hr = r.u8();
            if (hr > 1) bad("a DONE's read point flag");
            let read: ReadPoint | null = null;
            if (hr) {
                read = {
                    commit: r.u64(),
                    hash: Buffer.from(r.bytes(32)),
                    digest: Buffer.from(r.bytes(32)),
                    lakeCommit: r.u64(),
                    lakeManifest: Buffer.from(r.bytes(32)),
                    dbId: Buffer.from(r.bytes(16)),
                    own: false,
                };
                const own = r.u8();
                if (own > 1) bad("a DONE's own-writes flag");
                read.own = own === 1;
            }
            const hw = r.u8();
            if (hw > 1) bad("a DONE's write flag");
            let write: WritePoint | null = null;
            if (hw) {
                write = { commit: r.u64(), hash: Buffer.from(r.bytes(32)) };
                if (write.commit < 1n) bad("a DONE's write at commit 0");
            }
            m = { type: 66, done: { status, count, read, write } };
            break;
        }
        case F.ERROR: {
            const code = r.u32(), index = r.u32();
            if (!code || index >= BATCH_MAX) bad("an ERROR's code 0 or its statement's index");
            m = { type: 67, code, index, message: utf8String(textGet(r, 2, 0, MESSAGE_MAX)) };
            break;
        }
        case F.WARNING:
            m = { type: 68, message: utf8String(textGet(r, 2, 0, MESSAGE_MAX)) };
            break;
        case F.COPY_IN:
            m = { type: 69 };
            break;
        case F.COPY_OUT:
            if (!r.left()) bad('a COPY piece of no bytes');
            m = { type: 70, data: r.bytes(r.left()) };
            break;
        case F.READY: {
            const state = r.u8();
            if (state > READY_STATE.DOOMED) bad("a READY's state");
            m = { type: 71, state };
            break;
        }
        case F.PONG:
            m = { type: 72 };
            break;
        case F.SESSIONS_LIST: {
            const n = r.u32();
            if (n > SESSIONS_MAX || n > Math.floor(r.left() / SESS_MIN)) bad('a SESSIONS_LIST of at most 65,536 sessions it holds the bytes of');
            const sessions: SessionMsg[] = [];
            let prev = 0n;
            for (let i = 0; i < n; i++) {
                const id = r.u64('a session'), role = r.u32('a session'), endpoint = r.u8('a session'), state = r.u8('a session');
                const ageMs = r.u64('a session');
                const name = utf8String(textGet(r, 1, 0, USER_FIELD - 1));
                if (!(id > prev && role && (endpoint === 1 || endpoint === 2) && state <= SESS_STATE.COPY))
                    bad("a session's id out of order, or its role, endpoint or state");
                sessions.push({ id, role, endpoint, state, ageMs, name });
                prev = id;
            }
            m = { type: 73, sessions };
            break;
        }
        case F.KILL_DONE: {
            const code = r.u8(), sid = r.u64();
            if (code > KILL_CODE.NONE || !sid) bad("a KILL_DONE's code or a session id of 0");
            m = { type: 74, code, sid };
            break;
        }
        default:
            bad('a frame of a type the protocol does not define (' + type + ')');
    }
    if (r.left()) bad('a body with bytes past its end');
    return m;
}

/* ---- the server's frames encoded (a fake server's and the tests': each the exact bytes its decoder takes) ---- */

function colPut(w: Writer, c: WireColumn): void {
    const nb = str(c.name, "a column's name");
    if (!colShapeOk(c, nb) || (c.labels && new Set(c.labels).size !== c.labels.length))
        throw new ProtocolError(ERR.INVALID, 'wire: a column its encoder refuses');
    textPut(w, 1, 1, COLNAME_MAX, nb, "a column's name");
    w.u8(c.type);
    w.u16(c.precision);
    w.u16(c.scale);
    if (c.type === T.ENUM) {
        w.u16(c.labels!.length);
        for (const l of c.labels!) textPut(w, 1, 0, LABEL_MAX, str(l, 'a label'), 'a label');
    }
}

export function column(name: string, type: number, precision = 0, scale = 0, labels: string[] | null = null): WireColumn {
    return { name, type, precision, scale, labels, labelSet: labels ? new Set(labels) : null };
}

export function encodeServer(m: ServerMsg, cols: WireColumn[] | null = null): Buffer {
    const refuse = (what: string): never => {
        throw new ProtocolError(ERR.INVALID, 'wire: ' + what + ' its encoder refuses');
    };
    const w = frameBegin(m.type, 64);
    switch (m.type) {
        case F.COLUMNS:
            if (m.columns.length < 1 || m.columns.length > VALUES_MAX) refuse('a COLUMNS');
            w.u16(m.columns.length);
            for (const c of m.columns) colPut(w, c);
            break;
        case F.ROWS:
            if (!cols || !cols.length || m.rows.length < 1) refuse('a ROWS');
            w.u32(m.rows.length);
            for (const row of m.rows) {
                if (row.length !== cols!.length) refuse('a ROWS');
                row.forEach((v, j) => {
                    if (!valueFits(cols![j], v)) refuse('a value its column does not take');
                    encodeValue(w, v);
                });
            }
            break;
        case F.DONE: {
            const d = m.done;
            if (d.write && d.write.commit < 1n) refuse('a DONE');
            textPut(w, 2, 0, STATUS_MAX, str(d.status, 'a status'), 'a status');
            w.u64(d.count);
            w.u8(d.read ? 1 : 0);
            if (d.read) {
                w.u64(d.read.commit);
                w.put(d.read.hash);
                w.put(d.read.digest);
                w.u64(d.read.lakeCommit);
                w.put(d.read.lakeManifest);
                w.put(d.read.dbId);
                w.u8(d.read.own ? 1 : 0);
            }
            w.u8(d.write ? 1 : 0);
            if (d.write) {
                w.u64(d.write.commit);
                w.put(d.write.hash);
            }
            break;
        }
        case F.ERROR:
            if (!m.code || m.index >= BATCH_MAX) refuse('an ERROR');
            w.u32(m.code);
            w.u32(m.index);
            textPut(w, 2, 0, MESSAGE_MAX, str(m.message, 'a message'), 'a message');
            break;
        case F.WARNING:
            textPut(w, 2, 0, MESSAGE_MAX, str(m.message, 'a message'), 'a message');
            break;
        case F.COPY_OUT:
            if (!m.data.length) refuse('a COPY piece of no bytes');
            w.put(m.data);
            break;
        case F.READY:
            if (m.state > READY_STATE.DOOMED) refuse('a READY');
            w.u8(m.state);
            break;
        case F.SESSIONS_LIST: {
            if (m.sessions.length > SESSIONS_MAX) refuse('a SESSIONS_LIST');
            w.u32(m.sessions.length);
            let prev = 0n;
            for (const s of m.sessions) {
                if (!(s.id > prev && s.role && (s.endpoint === 1 || s.endpoint === 2) && s.state <= SESS_STATE.COPY)) refuse('a session');
                w.u64(s.id);
                w.u32(s.role);
                w.u8(s.endpoint);
                w.u8(s.state);
                w.u64(s.ageMs);
                textPut(w, 1, 0, USER_FIELD - 1, str(s.name, 'a name'), "a session's name");
                prev = s.id;
            }
            break;
        }
        case F.KILL_DONE:
            if (m.code > KILL_CODE.NONE || !m.sid) refuse('a KILL_DONE');
            w.u8(m.code);
            w.u64(m.sid);
            break;
        case F.COPY_IN:
        case F.PONG:
            break;
    }
    return frameEnd(w);
}

/* ---- frames from a byte stream: the head checked before its body is waited for or sized ---- */
export class FrameReader {
    private chunks: Buffer[] = [];
    private avail = 0;
    private head: { len: number; type: number } | null = null;
    readonly fromServer: boolean;
    constructor(fromServer = true) {
        this.fromServer = fromServer;
    }
    push(b: Buffer): void {
        if (!b.length) return;
        this.chunks.push(b);
        this.avail += b.length;
    }
    available(): number {
        return this.avail;
    }
    /* exactly n bytes, or null while fewer are here (the pre-auth messages' fixed sizes) */
    take(n: number): Buffer | null {
        if (n === 0) return Buffer.alloc(0); /* an empty body: none of the chunks touched */
        if (this.avail < n) return null;
        this.avail -= n;
        const first = this.chunks[0];
        if (first.length >= n) {
            const out = first.subarray(0, n);
            if (first.length === n) this.chunks.shift();
            else this.chunks[0] = first.subarray(n);
            return out;
        }
        const out = Buffer.allocUnsafe(n);
        let o = 0;
        while (o < n) {
            const c = this.chunks[0];
            const k = Math.min(c.length, n - o);
            c.copy(out, o, 0, k);
            o += k;
            if (k === c.length) this.chunks.shift();
            else this.chunks[0] = c.subarray(k);
        }
        return out;
    }
    /* the next whole frame, or null; a head this side refuses throws (the connection is then to end) */
    next(): { type: number; body: Buffer } | null {
        if (!this.head) {
            const h = this.take(HEAD);
            if (!h) return null;
            const len = h.readUInt32LE(0), type = h[4];
            checkHead(len, type, this.fromServer);
            this.head = { len, type };
        }
        const body = this.take(this.head.len - 1);
        if (!body) return null;
        const f = { type: this.head.type, body };
        this.head = null;
        return f;
    }
}
