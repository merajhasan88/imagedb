/* The codec against the contract's own bytes: the value vectors and refusals of tests/unit/t_wire.c (copied with their
 * line numbers, never derived here), the three pinned SCRAM exchanges of docs/n1-design.md §4 (t_wire.c 444-457), the
 * pre-auth layouts and bounds (t_wire_preauth), the client frames' accepted bodies and the server frames' accepted and
 * refused bodies of t_wire_bounds, and t_wire's samples round-tripped, flipped and cut (t_wire_flips' rule). */
import { test } from 'node:test';
import assert = require('node:assert');
import * as fs from 'fs';
import * as path from 'path';
import * as w from '../src/wire';
import { ERR, ProtocolError } from '../src/errors';
import { scramClient } from '../src/scram';
import { Decimal, Float64, fromWire, Interval, nullOf, SqlDate, SqlTime, Timestamp, TimestampTz, toWire, Uuid } from '../src/types';

const hex = (s: string) => Buffer.from(s.replace(/ /g, ''), 'hex');
const T = w.T;
const V = (p: Partial<w.WireValue> & { type: number }) => w.wv(p);
const UUID16 = Buffer.from([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]);

function decodeAll(b: Buffer): w.WireValue {
    const r = new w.Reader(b);
    const v = w.decodeValue(r);
    if (r.left()) throw new ProtocolError(ERR.CORRUPT, 'trailing');
    return v;
}
function code(fn: () => unknown): number {
    try {
        fn();
    } catch (e) {
        if (e instanceof ProtocolError) return e.code;
        throw e;
    }
    return 0;
}

/* t_wire.c 55-84: kVecs, the contract's value vectors */
const kVecs: [w.WireValue, string][] = [
    [V({ type: T.NONE, null: true }), '80'],
    [V({ type: T.INT64, null: true }), '81'],
    [V({ type: T.DECIMAL, null: true }), '85'],
    [V({ type: T.ENUM, null: true }), '8d'],
    [V({ type: T.INT64, i: -2n }), '01 feffffffffffffff'],
    [V({ type: T.INT64, i: -(1n << 63n) }), '01 0000000000000080'],
    [V({ type: T.FLOAT64, f: 0x3ff8000000000000n }), '02 000000000000f83f'],
    [V({ type: T.FLOAT64, f: 0n }), '02 0000000000000000'],
    [V({ type: T.BOOL, i: 1n }), '03 01'],
    [V({ type: T.BOOL, i: 0n }), '03 00'],
    [V({ type: T.TEXT, s: Buffer.from('68c3a9', 'hex') }), '04 03000000 68c3a9'],
    [V({ type: T.TEXT, s: Buffer.alloc(0) }), '04 00000000'],
    [V({ type: T.DECIMAL, scale: 2, d: -12345n }), '05 02 c7cfffffffffffffffffffffffffffff'],
    [V({ type: T.DECIMAL, scale: 0, d: 0n }), '05 00 00000000000000000000000000000000'],
    [V({ type: T.TIMESTAMP, i: 1n }), '06 0100000000000000'],
    [V({ type: T.TIMESTAMP, i: -62135596800000000n }), '06 0040d400014023ff'],
    [V({ type: T.TIMESTAMPTZ, i: -1n }), '07 ffffffffffffffff'],
    [V({ type: T.TIMESTAMPTZ, i: 253402300799999999n }), '07 ff5f73cc0c448403'],
    [V({ type: T.DATE, day: -719162 }), '08 c606f5ff'],
    [V({ type: T.DATE, day: 2932896 }), '08 a0c02c00'],
    [V({ type: T.TIME, i: 0n }), '09 0000000000000000'],
    [V({ type: T.TIME, i: 86399999999n }), '09 ff5fd71d14000000'],
    [V({ type: T.UUID, s: UUID16 }), '0a 000102030405060708090a0b0c0d0e0f'],
    [V({ type: T.BYTEA, s: Buffer.from([0, 0xff]) }), '0b 02000000 00ff'],
    [V({ type: T.INTERVAL, mon: 1, day: -2, i: 3n }), '0c 01000000 feffffff 0300000000000000'],
    [V({ type: T.INTERVAL, mon: -(2 ** 31), day: 2 ** 31 - 1, i: -(1n << 63n) }), '0c 00000080 ffffff7f 0000000000000080'],
    [V({ type: T.ENUM, s: Buffer.from('a') }), '0d 01 61'],
    [V({ type: T.ENUM, s: Buffer.alloc(0) }), '0d 00'],
];

test('value vectors (t_wire.c 55-84): encoded byte for byte, decoded, every prefix refused', () => {
    for (const [v, h] of kVecs) {
        const want = hex(h);
        assert.ok(w.valueBytes(v).equals(want), h);
        const back = decodeAll(want);
        assert.ok(w.valueBytes(back).equals(want), h);
        for (let cut = 0; cut < want.length; cut++) assert.notStrictEqual(code(() => decodeAll(want.subarray(0, cut))), 0, h + ' cut ' + cut);
    }
    /* t_wire.c 105-116: DECIMAL's range at scale 38: 10^38 - 1 and its negation taken, 10^38 and -10^38 refused, scale 39 */
    const lim = 10n ** 38n;
    [lim - 1n, -(lim - 1n), lim, -lim].forEach((d, k) => {
        const x = Buffer.alloc(18);
        x[0] = T.DECIMAL;
        x[1] = 38;
        const u = BigInt.asUintN(128, d);
        x.writeBigUInt64LE(u & ((1n << 64n) - 1n), 2);
        x.writeBigUInt64LE(u >> 64n, 10);
        assert.strictEqual(code(() => decodeAll(x)) === 0, k < 2);
        x[1] = 39;
        assert.notStrictEqual(code(() => decodeAll(x)), 0);
    });
});

/* t_wire.c 122-144: values refused */
const refused = ['03 02', '02 000000000000f07f', '02 000000000000f0ff', '02 010000000000f87f', '02 0000000000000080',
    '06 ff3fd400014023ff', '07 006073cc0c448403', '09 ffffffffffffffff', '09 0060d71d14000000', '08 c506f5ff', '08 a1c02c00',
    '04 01000000 ff', '04 01000000 00', '04 02000000 c0af', '0d 01 c3', '0d 01 00', '0e', '00', '8e', 'ff', ''];
/* §4's pinned SCRAM exchanges (t_wire.c 444-457): the exporter's, tls-server-end-point's, the socket's */
const pinnedHex = ['28562c1bef99b0a917ecb28c1b32c22930f154f92c134b13fee7a64e8deb733e', '5d3ef834c39e6c429d1f4e27993ba451a8b8e35322af9055abc1dd40e88ad322',
    '1065f5e038b75f2671d831f5bd5d29f56d22a787f260db523bb986ef7c53f486', '28fef60553090aae9b5f184bfc0cfb455e58261131da359f525a59f4dfaa9904',
    '5ee7e7bd402f0c91e2399a84c3d544763bace50b44ea82a780e57130bb5405a7', '82c9d498cc5fa830d26b29740244ecf4f343962f302a647150e9d74ea7588027'];
/* t_wire_bounds' accepted client bodies the encoders are held to (t_wire.c 947, 948, 951, 964, 967, 970, 1016) */
const clientBodies = ['01000000 01000000 61 0000', '01000000 01000000 61 0100 81', '01000000 01000000 61 0100 8d', 'ff00',
    '0170 01000000 0100 80', '0170 01000000 61', '01 0100000000000000'];

/* the copies above against the file itself (IMDB_DRV_TWIRE, else the repository's tests/unit/t_wire.c): a vector changed
 * there fails here, so the copies cannot drift from the contract */
test('the copied vectors are t_wire.c\'s own: kVecs, the refusals, the pinned exchanges, the client bodies', () => {
    const file = process.env.IMDB_DRV_TWIRE || path.join(__dirname, '..', '..', '..', '..', 'tests', 'unit', 't_wire.c');
    const src = fs.readFileSync(file, 'utf8');
    const block = (start: string) => {
        const i = src.indexOf(start);
        assert.ok(i >= 0, start + ' not in ' + file);
        return src.slice(i, src.indexOf('};', i)); /* the array's end (its entries hold no '};') */
    };
    const quoted = (s: string) => [...s.matchAll(/"([0-9a-f ]*)"/g)].map((m) => m[1]);
    const vecLines = block('static const vec kVecs[] = {').split('\n').slice(1);
    assert.deepStrictEqual(vecLines.map((l) => quoted(l).pop()).filter((x) => x !== undefined) /* a line's last string: its bytes */, kVecs.map((v) => v[1]));
    assert.deepStrictEqual(quoted(block('static const char *const refused[] = {')), refused);
    const scram = src.slice(src.indexOf('static void t_wire_scram(void)'), src.indexOf('static void t_wire_fake_salt(void)'));
    assert.deepStrictEqual([...scram.matchAll(/"([0-9a-f]{64})"/g)].map((m) => m[1]), pinnedHex);
    const bounds = src.slice(src.indexOf('static void t_wire_bounds(void)'), src.indexOf('static void t_wire_amplification(void)'));
    for (const b of clientBodies) assert.ok(bounds.includes('"' + b + '", NULL) == 0'), b + ' taken by t_wire_bounds');
});

test('values refused (t_wire.c 122-159): by rule, and a length past its bound as LIMIT before its bytes', () => {
    for (const h of refused) assert.strictEqual(code(() => decodeAll(hex(h))), ERR.CORRUPT, h);
    for (const h of ['04 00000100', '0b 00000100', '0d 40']) assert.strictEqual(code(() => decodeAll(hex(h))), ERR.LIMIT, h);
    /* t_wire.c 161-175: the encoder refuses what the decoder would */
    const no: w.WireValue[] = [
        V({ type: T.BOOL, i: 2n }), V({ type: T.FLOAT64, f: 0x8000000000000000n }), V({ type: T.TEXT, s: Buffer.from([0xff]) }),
        V({ type: T.TEXT, s: null }), V({ type: T.TEXT, s: Buffer.alloc(65536) }), V({ type: T.ENUM, s: Buffer.alloc(64, 0x30) }),
        V({ type: T.DECIMAL, scale: 39 }), V({ type: T.DATE, day: 2932897 }), V({ type: T.TIMESTAMP, i: (1n << 63n) - 1n }),
        V({ type: T.UUID, s: UUID16.subarray(0, 15) }), V({ type: 14 }), V({ type: T.NONE }), V({ type: 14, null: true }),
    ];
    for (const v of no) {
        assert.ok(!w.valueOk(v));
        assert.throws(() => w.valueBytes(v), ProtocolError);
    }
});

test('UTF-8 by the engine rule: utf8Fit (t_wire.c 188-197) and a differential against WHATWG fatal decoding', () => {
    const s = Buffer.from('ab\xc3\xa9c\xe2\x82\xac', 'latin1');
    const cases: [number, number][] = [[100, 8], [8, 8], [7, 5], [6, 5], [5, 5], [3, 2], [0, 0]];
    for (const [max, want] of cases) assert.strictEqual(w.utf8Fit(s, max), want);
    assert.strictEqual(w.utf8Fit(Buffer.from('ab\xffcd', 'latin1'), 5), 2);
    assert.strictEqual(w.utf8Fit(Buffer.from('ab\x00cd', 'latin1'), 5), 2);
    /* WHATWG's fatal decoder refuses overlong forms, surrogates and past U+10FFFF exactly as the engine's rule; NUL apart */
    const td = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });
    const pick = [0x00, 0x41, 0x7f, 0x80, 0x8f, 0x90, 0x9f, 0xa0, 0xbf, 0xc0, 0xc1, 0xc2, 0xdf, 0xe0, 0xe1, 0xec, 0xed, 0xee, 0xef,
        0xf0, 0xf1, 0xf3, 0xf4, 0xf5, 0xff];
    /* each rule at its edge, by hand: the last valid and the first invalid byte of every range */
    const edges: [string, boolean][] = [
        ['7f', true], ['00', false], ['80', false], ['c0 80', false], ['c1 bf', false], ['c2 80', true], ['df bf', true],
        ['e0 9f bf', false], ['e0 a0 80', true], ['ed 9f bf', true], ['ed a0 80', false], ['ed bf bf', false], ['ee 80 80', true],
        ['f0 8f bf bf', false], ['f0 90 80 80', true], ['f4 8f bf bf', true], ['f4 90 80 80', false], ['f5 80 80 80', false],
        ['e1 80', false], ['e1 80 7f', false], ['f1 80 80', false], ['ef bb bf', true], ['ff', false],
    ];
    for (const [h, ok] of edges) assert.strictEqual(w.utf8Ok(hex(h)), ok, h);
    let x = 0x9e3779b9; /* xorshift32: a full-period generator (a double LCG past 2^53 loses its low bits and cycles) */
    const rnd = () => {
        x ^= x << 13;
        x ^= x >>> 17;
        x ^= x << 5;
        return x >>> 0;
    };
    for (let round = 0; round < 200000; round++) {
        const n = 1 + (rnd() % 12);
        const x = Buffer.alloc(n);
        for (let i = 0; i < n; i++) x[i] = rnd() % 4 ? pick[rnd() % pick.length] : rnd() & 0xff;
        let ref = x.indexOf(0) < 0;
        if (ref) {
            try {
                td.decode(x);
            } catch {
                ref = false;
            }
        }
        assert.strictEqual(w.utf8Ok(x), ref, x.toString('hex'));
    }
});

test('native values: each type both ways, nothing lost, the JS traps refused', () => {
    const rt = (x: Parameters<typeof toWire>[0]) => fromWire(decodeAll(w.valueBytes(toWire(x))));
    assert.strictEqual(rt(-(1n << 63n)), -(1n << 63n));
    assert.strictEqual(rt((1n << 63n) - 1n), (1n << 63n) - 1n);
    assert.throws(() => toWire(1n << 63n), ProtocolError); /* refused, never wrapped */
    assert.throws(() => toWire(-(1n << 63n) - 1n), ProtocolError);
    assert.strictEqual(toWire(7).type, T.INT64); /* a safe integer number: INT64 */
    assert.strictEqual(toWire(1.5).type, T.FLOAT64);
    assert.strictEqual(toWire(2 ** 53).type, T.FLOAT64); /* past the safe integers: FLOAT64, never a rounded INT64 */
    assert.strictEqual(toWire(new Float64(7)).type, T.FLOAT64);
    assert.strictEqual(w.valueBytes(toWire(new Float64(-0))).toString('hex'), '020000000000000000'); /* the engine's one zero */
    assert.throws(() => toWire(NaN), ProtocolError);
    assert.throws(() => toWire(Infinity), ProtocolError);
    for (const f of [Number.MIN_VALUE, -Number.MAX_VALUE, 0.1, 1 / 3, -2.5e-300]) assert.ok(Object.is(rt(new Float64(f)), f));
    assert.strictEqual(rt('hé\u{1F600}'), 'hé\u{1F600}');
    assert.strictEqual(rt('﻿bom'), '﻿bom'); /* a leading U+FEFF kept */
    assert.throws(() => toWire('a\uD800b'), ProtocolError); /* a lone surrogate: Buffer.from would write U+FFFD */
    assert.throws(() => toWire('a\uDC00'), ProtocolError);
    assert.throws(() => toWire('a\u0000b'), ProtocolError);
    assert.throws(() => toWire('x'.repeat(65536)), ProtocolError);
    const d = Decimal.parse('-123.45');
    assert.strictEqual(w.valueBytes(toWire(d)).toString('hex'), '0502c7cfffffffffffffffffffffffffffff'); /* §4's vector */
    assert.ok((rt(d) as Decimal).equals(d));
    assert.strictEqual(String(rt(Decimal.parse('99999999999999999999999999999999999999'))), '99999999999999999999999999999999999999');
    assert.strictEqual(String(rt(new Decimal(-1n, 38))), '-0.00000000000000000000000000000000000001');
    assert.throws(() => toWire(Decimal.parse('100000000000000000000000000000000000000')), ProtocolError);
    assert.strictEqual(Decimal.parse('1.50').toString(), '1.50');
    assert.strictEqual(Decimal.parse('1.5e3').toString(), '1500');
    assert.strictEqual(Decimal.parse('-.5').toString(), '-0.5');
    assert.strictEqual(Decimal.parse('2.50E-2').toString(), '0.0250');
    /* §4's vectors through the classes: TIMESTAMP 0001-01-01, TIMESTAMPTZ 9999-12-31 23:59:59.999999, DATE, TIME, INTERVAL */
    assert.strictEqual(w.valueBytes(toWire(Timestamp.parse('0001-01-01 00:00:00'))).toString('hex'), '060040d400014023ff');
    assert.strictEqual(w.valueBytes(toWire(TimestampTz.parse('9999-12-31 23:59:59.999999Z'))).toString('hex'), '07ff5f73cc0c448403');
    assert.strictEqual(w.valueBytes(toWire(SqlDate.parse('0001-01-01'))).toString('hex'), '08c606f5ff');
    assert.strictEqual(w.valueBytes(toWire(SqlTime.parse('23:59:59.999999'))).toString('hex'), '09ff5fd71d14000000');
    assert.strictEqual(w.valueBytes(toWire(new Interval(1, -2, 3n))).toString('hex'), '0c01000000feffffff0300000000000000');
    assert.strictEqual(String(rt(Timestamp.parse('1969-12-31 23:59:59.999999'))), '1969-12-31 23:59:59.999999');
    assert.strictEqual(String(rt(TimestampTz.parse('2024-02-29 12:00:00.000001+05:30'))), '2024-02-29 06:30:00.000001+00');
    assert.strictEqual(String(rt(SqlDate.parse('9999-12-31'))), '9999-12-31');
    assert.throws(() => SqlDate.parse('2023-02-29'));
    assert.throws(() => toWire(new Timestamp(253402300800000000n)), ProtocolError);
    assert.throws(() => toWire(new SqlTime(86400000000n)), ProtocolError);
    assert.strictEqual(rt(new Uuid('00010203-0405-0607-0809-0a0b0c0d0e0f')), '00010203-0405-0607-0809-0a0b0c0d0e0f');
    assert.ok((rt(Buffer.from([0, 255])) as Buffer).equals(Buffer.from([0, 255])));
    assert.strictEqual(rt(true), true);
    assert.strictEqual(rt(null), null);
    assert.strictEqual(w.valueBytes(toWire(null)).toString('hex'), '80');
    assert.strictEqual(w.valueBytes(toWire(nullOf('INT64'))).toString('hex'), '81');
    assert.strictEqual(w.valueBytes(toWire(new Date(Date.UTC(1970, 0, 1, 0, 0, 0, 1)))).toString('hex'), '07e803000000000000');
    assert.throws(() => toWire({} as never), ProtocolError);
    /* a VARCHAR's length in characters, code points of the UTF-8 (never UTF-16 units: an emoji is one, not two) */
    const vc = w.column('v', T.TEXT, 2);
    assert.ok(w.valueFits(vc, toWire('\u{1F600}\u{1F600}')));
    assert.ok(!w.valueFits(vc, toWire('\u{1F600}\u{1F600}a')));
    /* a parameter is never a non-NULL ENUM (a label is sent as TEXT); a NULL ENUM is */
    assert.throws(() => w.encodeQuery([{ sql: 'a', params: [V({ type: T.ENUM, s: Buffer.from('a') })] }]), ProtocolError);
});

test('pre-auth: the hello, the challenge and the verdict (t_wire_preauth 225-397)', () => {
    const user = Buffer.from('alice');
    const nonce = Buffer.alloc(32, 9);
    const hb = w.encodeHello({ version: 1, flags: 0, user, nonce });
    assert.ok(hb.subarray(0, 21).equals(Buffer.from('IMDBWIR1\x01\0\0\0\0\0\0\0alice', 'latin1'))); /* t_wire.c 230 */
    assert.strictEqual(hb.length, 112);
    let took = 0, refused = 0;
    for (let i = 0; i < hb.length; i++)
        for (const f of [0x01, 0x80, 0xff]) {
            const x = Buffer.from(hb);
            x[i] ^= f;
            try {
                const g = w.decodeHello(x);
                assert.ok(w.encodeHello(g).equals(x));
                took++;
            } catch (e) {
                assert.ok(e instanceof ProtocolError);
                refused++;
            }
        }
    assert.ok(took >= 32 * 3 + 1 && refused >= 16 * 3); /* t_wire.c 248 */
    for (let fl = 0; fl < 5; fl++) {
        const y = Buffer.from(hb);
        y[12] = fl;
        assert.strictEqual(code(() => w.decodeHello(y)), fl <= 2 ? 0 : ERR.CORRUPT);
    }
    const later = Buffer.from(hb);
    later[8] = 2;
    assert.throws(() => w.decodeHello(later), (e: ProtocolError) => e.code === ERR.UNSUPPORTED && /version 2/.test(e.message));
    const magic2 = Buffer.from(hb);
    magic2[7] = 0x32;
    assert.throws(() => w.decodeHello(magic2), (e: ProtocolError) => e.code === ERR.UNSUPPORTED && /IMDBWIR2/.test(e.message));
    magic2[7] = 0x30;
    assert.strictEqual(code(() => w.decodeHello(magic2)), ERR.CORRUPT);
    const v0 = Buffer.from(hb);
    v0[8] = 0;
    assert.strictEqual(code(() => w.decodeHello(v0)), ERR.CORRUPT);
    /* the role name: 1 to 63 bytes of UTF-8, NUL-padded */
    const u = Buffer.from(hb);
    u.fill(0, 16, 80);
    assert.notStrictEqual(code(() => w.decodeHello(u)), 0);
    u.fill(0x61, 16, 80);
    assert.notStrictEqual(code(() => w.decodeHello(u)), 0);
    u[16 + 63] = 0;
    assert.strictEqual(w.decodeHello(u).user.length, 63);
    u.fill(0, 16, 80);
    u[16] = 0x61;
    u[18] = 0x62;
    assert.notStrictEqual(code(() => w.decodeHello(u)), 0);
    assert.ok(w.userOk(Buffer.from('c3a9', 'hex')) && !w.userOk(Buffer.alloc(0)) && !w.userOk(Buffer.from('c3', 'hex')));
    assert.throws(() => w.encodeHello({ version: 1, flags: 3, user, nonce }), ProtocolError);
    assert.throws(() => w.encodeHello({ version: 2, flags: 0, user, nonce }), ProtocolError);
    /* the head every version keeps */
    assert.strictEqual(w.preauthHead(hb), 1);
    const h7 = Buffer.from(hb.subarray(0, 12));
    h7.writeUInt32LE(7, 8);
    assert.strictEqual(w.preauthHead(h7), 7);
    h7.writeUInt32LE(0, 8);
    assert.strictEqual(code(() => w.preauthHead(h7)), ERR.CORRUPT);
    h7.writeUInt32LE(1, 8);
    h7[7] = 0x32;
    assert.strictEqual(code(() => w.preauthHead(h7)), ERR.UNSUPPORTED);
    h7[0] = 0x58;
    assert.strictEqual(code(() => w.preauthHead(h7)), ERR.CORRUPT);
    /* the challenge: t_wire.c 354-355's bounds, the salt's padding, the tail */
    const c = { version: 1, salt: Buffer.alloc(16, 3), iter: 4096, nonce: Buffer.alloc(32, 2) };
    const cb = w.encodeChallenge(c);
    assert.strictEqual(cb.length, 120);
    const d = w.decodeChallenge(cb);
    assert.ok(d.salt.equals(c.salt) && d.iter === 4096 && d.nonce.equals(c.nonce));
    for (const [sl, it, ok] of [[7, 4096, false], [8, 4096, true], [64, 4096, true], [65, 4096, false], [16, 999, false], [16, 1000, true],
        [16, 1000000, true], [16, 1000001, false]] as [number, number, boolean][]) {
        const x = Buffer.from(cb);
        x[12] = sl;
        x.fill(0, 13, 13 + 64);
        x.fill(3, 13, 13 + Math.min(sl, 64));
        x.writeUInt32LE(it, 13 + 64);
        assert.strictEqual(code(() => w.decodeChallenge(x)) === 0, ok, sl + ' ' + it);
    }
    const pad = Buffer.from(cb);
    pad[13 + 16] = 1;
    assert.notStrictEqual(code(() => w.decodeChallenge(pad)), 0);
    const tail = Buffer.from(cb);
    tail[119] = 1;
    assert.notStrictEqual(code(() => w.decodeChallenge(tail)), 0);
    /* the verdict: accepted with a signature; refused (1) and the binding type refused (2) with zeros alone */
    const vb = Buffer.alloc(36);
    vb.fill(7, 4);
    assert.strictEqual(w.decodeVerdict(vb).code, 0);
    vb[0] = 1;
    assert.notStrictEqual(code(() => w.decodeVerdict(vb)), 0);
    vb.fill(0, 4);
    assert.strictEqual(w.decodeVerdict(vb).code, 1);
    vb[0] = 2;
    assert.strictEqual(w.decodeVerdict(vb).code, 2);
    vb[4] = 1;
    assert.notStrictEqual(code(() => w.decodeVerdict(vb)), 0);
    vb[4] = 0;
    vb[0] = 3;
    assert.notStrictEqual(code(() => w.decodeVerdict(vb)), 0);
});

test('SCRAM: the three pinned exchanges of §4 (t_wire.c 436-471), byte for byte', async () => {
    const c = { version: 1, salt: Buffer.alloc(16, 3), iter: 4096, nonce: Buffer.alloc(32, 2) };
    const cb = w.encodeChallenge(c);
    const pinned: [number, number, number, string, string][] = [
        [w.EP.TCP, w.CB.EXPORTER, 0x04, pinnedHex[0], pinnedHex[1]],
        [w.EP.TCP, w.CB.ENDPOINT, 0x05, pinnedHex[2], pinnedHex[3]],
        [w.EP.UNIX, w.CB.NONE, 0x00, pinnedHex[4], pinnedHex[5]],
    ];
    for (const [ep, flags, bind, proof, ssig] of pinned) {
        const hb = w.encodeHello({ version: 1, flags, user: Buffer.from('alice'), nonce: Buffer.alloc(32, 1) });
        const am = w.authMessage(ep, hb, cb, Buffer.alloc(32, bind));
        /* t_wire.c 429-434: the AuthMessage laid out by hand */
        const want = Buffer.concat([Buffer.from('IMDBWIR1-SCRAM', 'latin1'), Buffer.from([ep]), hb, cb, Buffer.alloc(32, bind)]);
        assert.ok(am.equals(want) && am.length === 279);
        const r = await scramClient('pencil', w.decodeChallenge(cb), am);
        assert.strictEqual(r.proof.toString('hex'), proof);
        assert.strictEqual(r.serverSig.toString('hex'), ssig);
    }
    /* the client refuses a password CREATE ROLE would (t_wire.c 532-541) */
    const am = w.authMessage(1, w.encodeHello({ version: 1, flags: 1, user: Buffer.from('a'), nonce: Buffer.alloc(32) }), cb, Buffer.alloc(32));
    for (const pw of ['', 'a\x7f', 'a\x1f', 'é', 'a'.repeat(1025)]) await assert.rejects(scramClient(pw, c, am), ProtocolError);
    await scramClient('a'.repeat(1024), c, am);
});

/* the client's frames against t_wire_bounds' accepted bodies (t_wire.c 947-1016): the head, then those exact bytes */
test('client frames: encoders byte for byte against t_wire_bounds, and their refusals', () => {
    const frame = (type: number, body: string) => {
        const b = hex(body);
        const h = Buffer.alloc(5);
        h.writeUInt32LE(b.length + 1, 0);
        h[4] = type;
        return Buffer.concat([h, b]).toString('hex');
    };
    const F = w.F;
    assert.strictEqual(w.encodeQuery([{ sql: 'a', params: [] }]).toString('hex'), frame(F.QUERY, clientBodies[0])); /* 947 */
    assert.strictEqual(w.encodeQuery([{ sql: 'a', params: [w.wnull(T.INT64)] }]).toString('hex'), frame(F.QUERY, clientBodies[1])); /* 948 */
    assert.strictEqual(w.encodeQuery([{ sql: 'a', params: [w.wnull(T.ENUM)] }]).toString('hex'), frame(F.QUERY, clientBodies[2])); /* 951 */
    assert.strictEqual(w.encodeExecute('p', 1, [[w.wnull(T.NONE)]]).toString('hex'), frame(F.EXECUTE, clientBodies[4])); /* 967 */
    assert.strictEqual(w.encodePrepare('p', 'a').toString('hex'), frame(F.PREPARE, clientBodies[5])); /* 970 */
    assert.strictEqual(w.encodeKill(1, 1n).toString('hex'), frame(F.KILL, clientBodies[6])); /* 1016 */
    assert.strictEqual(w.encodeCopyData(hex('ff00')).toString('hex'), frame(F.COPY_DATA, clientBodies[3])); /* 964 */
    for (const t of [F.COPY_DONE, F.CANCEL, F.PING, F.TERMINATE, F.SESSIONS]) assert.strictEqual(w.encodeEmpty(t).toString('hex'), frame(t, ''));
    /* t_wire's QUERY sample (565-637): three statements, values 2, 0 and 1 */
    const q = w.encodeQuery([
        { sql: 'SELECT $1, $2', params: [V({ type: T.INT64, i: 7n }), V({ type: T.TEXT, s: Buffer.from('t') })] },
        { sql: 'BEGIN', params: [] },
        { sql: 'é', params: [w.wnull(T.ENUM)] },
    ]);
    assert.strictEqual(q.toString('hex'), frame(F.QUERY, '03000000 0d000000' + Buffer.from('SELECT $1, $2').toString('hex') +
        ' 0200 01 0700000000000000 04 01000000 74 05000000 424547494e 0000 02000000 c3a9 0100 8d'));
    /* the encoders refuse what t_wire_bounds' decoder refuses */
    assert.throws(() => w.encodeQuery([]), ProtocolError); /* 942: no statement */
    assert.throws(() => w.encodeQuery(Array(4097).fill({ sql: 'a', params: [] })), ProtocolError); /* 943 */
    assert.throws(() => w.encodeQuery([{ sql: '', params: [] }]), ProtocolError); /* 945 */
    assert.throws(() => w.encodeQuery([{ sql: 'a', params: Array(257).fill(w.wnull(0)) }]), ProtocolError); /* 952 */
    assert.throws(() => w.encodeQuery([{ sql: Buffer.from([0xff]), params: [] }]), ProtocolError); /* 956 */
    assert.throws(() => w.encodeQuery([{ sql: 'a\u0000', params: [] }]), ProtocolError); /* 957 */
    assert.throws(() => w.encodeDeallocate(Buffer.from([0xc3])), ProtocolError); /* 958 */
    assert.throws(() => w.encodeExecute('p', 257, [Array(257).fill(w.wnull(0))]), ProtocolError); /* 965 */
    assert.throws(() => w.encodeExecute('p', 0, []), ProtocolError); /* 966 */
    assert.throws(() => w.encodeExecute('', 0, [[]]), ProtocolError); /* 969 */
    assert.throws(() => w.encodeExecute('p', 1, [[V({ type: T.ENUM, s: Buffer.from('a') })]]), ProtocolError); /* 968 */
    assert.throws(() => w.encodeDeallocate('a'.repeat(64)), ProtocolError); /* 972 */
    assert.throws(() => w.encodeKill(0, 1n), ProtocolError); /* 1017 */
    assert.throws(() => w.encodeKill(3, 1n), ProtocolError);
    assert.throws(() => w.encodeKill(2, 0n), ProtocolError); /* 1019 */
    assert.throws(() => w.encodeCopyData(Buffer.alloc(0)), ProtocolError); /* 1041 */
    assert.throws(() => w.encodeCopyFail('x'.repeat(4097)), ProtocolError); /* 1042 */
    assert.throws(() => w.encodeExecute('p', 2, [[w.wnull(0), w.wnull(0)], [w.wnull(0)]]), ProtocolError); /* sets of one count */
});

function body(type: number, h: string, cols: w.WireColumn[] | null = null): number {
    return code(() => w.decodeServer(type, hex(h), cols));
}

test('server frames: t_wire_bounds bodies taken and refused (t_wire.c 959-1042)', () => {
    const F = w.F;
    const z32 = '00'.repeat(32), z16 = '00'.repeat(16);
    const cases: [number, string, number][] = [
        [F.COLUMNS, '0100 01ff 03 0000 0000', ERR.CORRUPT], /* 959 a column's name */
        [F.COLUMNS, '0100 0161 0d 0000 0000 0100 01 80', ERR.CORRUPT], /* 960 a label */
        [F.DONE, '0100 ff 0000000000000000 00 00', ERR.CORRUPT], /* 961 the status */
        [F.ERROR, '05000000 00000000 0100 00', ERR.CORRUPT], /* 962 the message */
        [F.WARNING, '0200 c0af', ERR.CORRUPT], /* 963 */
        [F.COPY_OUT, 'ff00', 0], /* COPY's bytes are raw */
        [F.COLUMNS, '0000', ERR.CORRUPT], /* 975 */
        [F.COLUMNS, '0100 0161 05 2700 0000', ERR.CORRUPT], /* 976 DECIMAL(39) */
        [F.COLUMNS, '0100 0161 05 0200 0300', ERR.CORRUPT], /* 977 scale past precision */
        [F.COLUMNS, '0100 0161 05 2600 2600', 0], /* 978 DECIMAL(38,38) */
        [F.COLUMNS, '0100 0161 01 0800 0000', ERR.CORRUPT], /* 979 INT64 of 8 bits */
        [F.COLUMNS, '0100 0161 01 1000 0000', 0], /* 980 SMALLINT */
        [F.COLUMNS, '0100 0161 03 0100 0000', ERR.CORRUPT], /* 981 BOOL with a precision */
        [F.COLUMNS, '0100 0161 00 0000 0000', 0], /* 982 a column of no known type */
        [F.COLUMNS, '0100 0161 00 0100 0000', ERR.CORRUPT], /* 983 */
        [F.COLUMNS, '0100 0161 05 0000 2600', 0], /* 984 */
        [F.COLUMNS, '0100 0161 05 0000 2700', ERR.CORRUPT], /* 985 */
        [F.COLUMNS, '0100 0161 0e 0000 0000', ERR.CORRUPT], /* 986 type 14 */
        [F.COLUMNS, '0100 0161 0d 0000 0000 ffff', ERR.CORRUPT], /* 987 labels past the bytes */
        [F.COLUMNS, '0100 0161 0d 0000 0000 0104', ERR.CORRUPT], /* 988 1,025 labels */
        [F.COLUMNS, '0100 0161 0d 0000 0000 0100 00', 0], /* 989 one empty label */
        [F.COLUMNS, '0100 0161 0d 0000 0000 0100 40', ERR.LIMIT], /* 990 a label of 64 bytes */
        [F.COLUMNS, '0100 0161 0d 0100 0000 0100 00', ERR.CORRUPT], /* 991 an ENUM with a precision */
        [F.COLUMNS, '0100 0165 0d 0000 0000 0200 0161 0161', ERR.CORRUPT], /* 856 a label twice */
        [F.DONE, '0000 0000000000000000 02 00', ERR.CORRUPT], /* 992 */
        [F.DONE, '0000 0000000000000000 00 00', 0], /* 993 */
        [F.DONE, '0000 ffffffffffffffff 00 00', 0], /* 994 */
        [F.DONE, '0000 00 00', ERR.CORRUPT], /* 995 */
        [F.DONE, '0000 0000000000000000 01 0000000000000000 ' + z32 + ' ' + z32 + ' 0100000000000000 01' + z32.slice(0, 62) + ' ' + z16 + ' 00 00', 0], /* 999: whatever the read point */
        [F.DONE, '0000 0000000000000000 01 0000000000000000 ' + z32 + ' ' + z32 + ' 0100000000000000 ' + z32 + ' ' + z16 + ' 01 00', 0], /* 1001 */
        [F.DONE, '0000 0000000000000000 01 0000000000000000 ' + z32 + ' ' + z32 + ' 0100000000000000 ' + z32 + ' ' + z16 + ' 02 00', ERR.CORRUPT], /* 1003 */
        [F.DONE, '0000 0000000000000000 00 01 0000000000000000 ' + z32, ERR.CORRUPT], /* 1005 a write at commit 0 */
        [F.DONE, '0002 ' + '00'.repeat(512) + ' 00 00', ERR.LIMIT], /* 1007 a status of 512 bytes */
        [F.ERROR, '05000000 00100000 0000', ERR.CORRUPT], /* 1009 index 4,096 */
        [F.ERROR, '00000000 00000000 0000', ERR.CORRUPT], /* 1010 code 0 */
        [F.ERROR, '05000000 ff0f0000 0000', 0], /* 1011 */
        [F.READY, '03', ERR.CORRUPT], /* 1012 */
        [F.READY, '', ERR.CORRUPT], /* 1013 */
        [F.PONG, '00', ERR.CORRUPT], /* 1014's rule: a body where none is */
        [F.COPY_IN, '00', ERR.CORRUPT],
        [F.KILL_DONE, '01 0100000000000000', 0], /* 1022 */
        [F.KILL_DONE, '02 0100000000000000', ERR.CORRUPT], /* 1023 */
        [F.KILL_DONE, '03 0100000000000000', ERR.CORRUPT], /* 1024 */
        [F.KILL_DONE, '00 0000000000000000', ERR.CORRUPT], /* 1025 */
        [F.SESSIONS_LIST, '00000000', 0], /* 1027 */
        [F.SESSIONS_LIST, '01000000 0100000000000000 01000000 01 00 0000000000000000 00', 0], /* 1028 */
        [F.SESSIONS_LIST, '01000000 0000000000000000 01000000 01 00 0000000000000000 00', ERR.CORRUPT], /* 1029 id 0 */
        [F.SESSIONS_LIST, '01000000 0100000000000000 00000000 01 00 0000000000000000 00', ERR.CORRUPT], /* 1030 role 0 */
        [F.SESSIONS_LIST, '01000000 0100000000000000 01000000 03 00 0000000000000000 00', ERR.CORRUPT], /* 1031 endpoint 3 */
        [F.SESSIONS_LIST, '01000000 0100000000000000 01000000 01 04 0000000000000000 00', ERR.CORRUPT], /* 1032 state 4 */
        [F.SESSIONS_LIST, '01000000 0100000000000000 01000000 01 00 0000000000000000 40', ERR.LIMIT], /* 1033 64 bytes */
        [F.SESSIONS_LIST, '01000000 0100000000000000 01000000 01 00 0000000000000000 01 ff', ERR.CORRUPT], /* 1034 */
        [F.SESSIONS_LIST, '02000000 0200000000000000 01000000 01 00 0000000000000000 00 0200000000000000 01000000 01 00 0000000000000000 00', ERR.CORRUPT], /* 1035 */
        [F.SESSIONS_LIST, '02000000 0200000000000000 01000000 01 00 0000000000000000 00 0100000000000000 01000000 01 00 0000000000000000 00', ERR.CORRUPT], /* 1037 */
        [F.SESSIONS_LIST, '02000000 0100000000000000 01000000 01 00 0000000000000000 00', ERR.CORRUPT], /* 1039 */
        [F.SESSIONS_LIST, '01000100 0100000000000000 01000000 01 00 0000000000000000 00', ERR.CORRUPT], /* 1040 */
        [F.COPY_OUT, '', ERR.CORRUPT], /* 1041's rule */
        [F.WARNING, '0110', ERR.LIMIT], /* 1042's rule: 4,097 bytes claimed */
        [F.ROWS, '01000000 00', ERR.CORRUPT], /* 974 no COLUMNS before */
        [F.COLUMNS, '0001 0161 01 0000 0000', ERR.CORRUPT], /* 1080 256 columns in 8 bytes */
        [F.COLUMNS, '0100 0161 0d 0000 0000 0004', ERR.CORRUPT], /* 1081 1,024 labels in none */
    ];
    for (const [type, h, want] of cases) assert.strictEqual(body(type, h), want, w.FRAME_NAMES[type] + ' ' + h);
    /* an ENUM of 1,024 distinct labels taken, of 1,025 refused (t_wire.c 1044-1073) */
    for (const nl of [1024, 1025]) {
        const parts = [Buffer.from([1, 0, 1, 0x65, T.ENUM, 0, 0, 0, 0]), Buffer.from([nl & 0xff, nl >> 8])];
        for (let i = 0; i < nl; i++) parts.push(Buffer.from([3, 0x61 + Math.floor(i / 676), 0x61 + (Math.floor(i / 26) % 26), 0x61 + (i % 26)]));
        assert.strictEqual(code(() => w.decodeServer(F.COLUMNS, Buffer.concat(parts), null)) === 0, nl === 1024);
    }
    /* frame heads (t_wire.c 929-941): length 0, past 16 MiB, a client's type from the server */
    assert.strictEqual(code(() => w.checkHead(0, F.READY, true)), ERR.LIMIT);
    assert.strictEqual(code(() => w.checkHead(w.FRAME_MAX + 1, F.READY, true)), ERR.LIMIT);
    assert.strictEqual(code(() => w.checkHead(w.FRAME_MAX, F.READY, true)), 0);
    for (const t of [0, 1, 12, 63, 75, 255]) assert.strictEqual(code(() => w.checkHead(5, t, true)), ERR.CORRUPT);
    const fr = new w.FrameReader(true);
    fr.push(hex('ffffffff 47'));
    assert.strictEqual(code(() => fr.next()), ERR.LIMIT); /* refused at its head: nothing sized by it */
});

/* t_wire's samples (565-683) of the server's types: each encoded, decoded and encoded again the same; every byte flipped
 * three ways, what the decoder takes encodes back to itself; every cut and one byte more refused but COPY_OUT's */
function samples(): { m: w.ServerMsg; cols: w.WireColumn[] | null }[] {
    const cols = [w.column('id', T.INT64, 32), w.column('amount', T.DECIMAL, 38, 6), w.column('name', T.TEXT, 12), w.column('mood', T.ENUM, 0, 0, ['', 'x', 'é'])];
    const lim = 10n ** 38n;
    const rv = [
        [V({ type: T.INT64, i: -(2n ** 31n) }), V({ type: T.DECIMAL, scale: 6, d: -1234567n }), V({ type: T.TEXT, s: Buffer.from('héllo') }), V({ type: T.ENUM, s: Buffer.from('x') })],
        [w.wnull(T.INT64), V({ type: T.DECIMAL, scale: 6, d: lim - 1n }), V({ type: T.TEXT, s: Buffer.alloc(0) }), V({ type: T.ENUM, s: Buffer.alloc(0) })],
    ];
    const rp: w.ReadPoint = { commit: 41n, hash: Buffer.alloc(32, 1), digest: Buffer.alloc(32, 2), lakeCommit: 44n, lakeManifest: Buffer.alloc(32, 3), dbId: Buffer.alloc(16, 4), own: true };
    return [
        { m: { type: 64, columns: cols }, cols: null },
        { m: { type: 65, rows: rv }, cols },
        { m: { type: 66, done: { status: 'INSERT 0 3', count: 3n, read: rp, write: { commit: 42n, hash: Buffer.alloc(32, 5) } } }, cols: null },
        { m: { type: 66, done: { status: '', count: 0n, read: null, write: null } }, cols: null },
        { m: { type: 67, code: 5, index: 2, message: 'BEGIN' }, cols: null },
        { m: { type: 68, message: 'é' }, cols: null },
        { m: { type: 69 }, cols: null },
        { m: { type: 70, data: Buffer.from('1,2\n') }, cols: null },
        { m: { type: 71, state: 2 }, cols: null },
        { m: { type: 72 }, cols: null },
        { m: { type: 73, sessions: [{ id: 3n, role: 7, endpoint: 1, state: 3, ageMs: (1n << 64n) - 1n, name: 'hé' }, { id: 4n, role: 2 ** 32 - 1, endpoint: 2, state: 0, ageMs: 0n, name: '' }] }, cols: null },
        { m: { type: 73, sessions: [] }, cols: null },
        { m: { type: 74, code: 0, sid: 9n }, cols: null },
        { m: { type: 74, code: 1, sid: (1n << 64n) - 1n }, cols: null },
    ];
}

function reencode(type: number, b: Buffer, cols: w.WireColumn[] | null): Buffer | null {
    try {
        return w.encodeServer(w.decodeServer(type, b, cols), cols).subarray(5);
    } catch (e) {
        if (e instanceof ProtocolError) return null;
        throw e;
    }
}

test('server frames: samples round-trip; flipped, what is taken encodes back; cut or longer refused (t_wire_flips)', () => {
    let taken = 0, refused = 0;
    for (const { m, cols } of samples()) {
        const f = w.encodeServer(m, cols);
        assert.strictEqual(f.readUInt32LE(0), f.length - 4);
        const b = f.subarray(5);
        const again = reencode(m.type, b, cols);
        assert.ok(again && again.equals(b), w.FRAME_NAMES[m.type]);
        const raw = m.type === 70;
        for (let i = 0; i < b.length; i++)
            for (const x of [0x01, 0x80, 0xff]) {
                const y = Buffer.from(b);
                y[i] ^= x;
                const r = reencode(m.type, y, cols);
                if (r) {
                    assert.ok(r.equals(y), w.FRAME_NAMES[m.type] + ' byte ' + i);
                    taken++;
                } else refused++;
            }
        for (let cut = 0; cut < b.length; cut++) {
            const r = reencode(m.type, b.subarray(0, cut), cols);
            assert.ok(raw && cut > 0 ? !!r && r.equals(b.subarray(0, cut)) : !r, w.FRAME_NAMES[m.type] + ' cut ' + cut);
        }
        const longer = Buffer.concat([b, Buffer.from([0])]);
        assert.strictEqual(!!reencode(m.type, longer, cols), raw, w.FRAME_NAMES[m.type] + ' longer');
    }
    assert.ok(taken > 0 && refused > 0);
});

test('ROWS held to COLUMNS (t_wire_rows_fit 773-839)', () => {
    const cols = samples()[0].m.type === 64 ? (samples()[0].m as { columns: w.WireColumn[] }).columns : [];
    const lim = 10n ** 38n;
    const cases: [number, w.WireValue, boolean][] = [
        [0, V({ type: T.INT64, i: 2n ** 31n - 1n }), true],
        [0, V({ type: T.INT64, i: 2n ** 31n }), false],
        [0, V({ type: T.INT64, i: -(2n ** 31n) - 1n }), false],
        [0, V({ type: T.TIMESTAMP, i: 1n }), false],
        [0, w.wnull(T.INT64), true],
        [0, w.wnull(T.TEXT), false],
        [0, w.wnull(T.NONE), false],
        [1, V({ type: T.DECIMAL, scale: 6, d: lim - 1n }), true],
        [1, V({ type: T.DECIMAL, scale: 5, d: 1n }), false],
        [1, V({ type: T.INT64, i: 1n }), false],
        [2, V({ type: T.TEXT, s: Buffer.from('é'.repeat(12)) }), true],
        [2, V({ type: T.TEXT, s: Buffer.from('0123456789abc') }), false],
        [2, V({ type: T.BYTEA, s: Buffer.from('a') }), false],
        [3, V({ type: T.ENUM, s: Buffer.from('é') }), true],
        [3, V({ type: T.ENUM, s: Buffer.from('y') }), false],
        [3, V({ type: T.ENUM, s: Buffer.from('xx') }), false],
        [3, V({ type: T.TEXT, s: Buffer.from('x') }), false],
    ];
    for (const [col, v, ok] of cases) {
        assert.strictEqual(w.valueFits(cols[col], v), ok);
        const row = [w.wnull(T.INT64), w.wnull(T.DECIMAL), w.wnull(T.TEXT), w.wnull(T.ENUM)];
        row[col] = v;
        const bodyHex = '01000000' + row.map((x) => w.valueBytes(x).toString('hex')).join('');
        assert.strictEqual(body(w.F.ROWS, bodyHex, cols) === 0, ok);
    }
    assert.ok(w.valueFits(w.column('s', T.INT64, 16), V({ type: T.INT64, i: 32767n })) && !w.valueFits(w.column('s', T.INT64, 16), V({ type: T.INT64, i: 32768n })));
    const d52 = w.column('d', T.DECIMAL, 5, 2);
    assert.ok(w.valueFits(d52, V({ type: T.DECIMAL, scale: 2, d: -99999n })) && !w.valueFits(d52, V({ type: T.DECIMAL, scale: 2, d: 100000n })));
    const none = w.column('x', T.NONE);
    for (const v of [V({ type: T.INT64, i: 1n }), V({ type: T.ENUM, s: Buffer.from('q') }), w.wnull(T.NONE), w.wnull(T.DATE)]) assert.ok(w.valueFits(none, v));
    assert.ok(!w.valueFits(none, V({ type: T.BOOL, i: 2n })));
});

test('mayBeCopy: the statements that hold the line', async () => {
    const { mayBeCopy } = await import('../src/client');
    for (const s of ['COPY t FROM STDIN', '  copy t from stdin', '-- c\n/* x */ Copy t FROM STDIN', '/* unterminated', '\ncopy\tt']) assert.ok(mayBeCopy(s), s);
    for (const s of ['SELECT 1', 'copyx', 'INSERT INTO copy VALUES (1)', '-- copy']) assert.ok(!mayBeCopy(s), s);
});
