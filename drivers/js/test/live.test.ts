/* The driver against the frozen imagedb-server, started by run_tests.sh: A (the default channel binding: the exporter
 * alone; TCP on 127.0.0.1) and B (--channel-binding any; TCP on 127.0.0.2, its own CA). Each test its own tables. */
import { test } from 'node:test';
import assert = require('node:assert');
import * as net from 'net';
import * as tls from 'tls';
import * as fs from 'fs';
import * as crypto from 'crypto';
import * as stream from 'stream';
import {
    AuthError, Client, ClosedError, connect, Decimal, ERR, Float64, ImdbError, Interval, nullOf, ProtocolError, ServerError,
    SqlDate, SqlTime, Timestamp, TimestampTz, Uuid, wire as w,
} from '../src/index';
import { scramServer, scramVerifier } from '../src/scram';

function env(k: string): string {
    const v = process.env[k];
    if (!v) throw new Error('run by run_tests.sh: ' + k + ' is not set');
    return v;
}
const cred = { user: env('IMDB_JS_USER'), password: env('IMDB_JS_PASSWORD') };
const A = { socket: env('IMDB_JS_SOCK_A'), port: +env('IMDB_JS_PORT_A'), caFile: env('IMDB_JS_CA_A'), pin: env('IMDB_JS_PIN_A') };
const B = { socket: env('IMDB_JS_SOCK_B'), port: +env('IMDB_JS_PORT_B'), caFile: env('IMDB_JS_CA_B'), pin: env('IMDB_JS_PIN_B'), pid: +env('IMDB_JS_PID_B') };
const TMP = env('IMDB_JS_TMP');
/* every client a test opens, destroyed by the last test whatever failed, so no socket holds the run open */
const opened: Client[] = [];
async function open(o: Parameters<typeof connect>[0], cr: Parameters<typeof connect>[1] = cred): Promise<Client> {
    const c = await connect(o, cr);
    opened.push(c);
    return c;
}
const sockA = () => open({ socket: A.socket });
const tcpA = () => open({ host: '127.0.0.1', port: A.port, caFile: A.caFile });
const sleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));

async function rejectsWith<T extends Error>(p: Promise<unknown>, cls: new (...a: any[]) => T, check?: (e: T) => boolean): Promise<T> {
    try {
        const v = await p;
        if (v instanceof Client) v.destroy(); /* a login that should have failed: its socket must not hold the run open */
    } catch (e) {
        assert.ok(e instanceof cls, 'expected ' + cls.name + ', got ' + (e as Error).name + ': ' + (e as Error).message);
        if (check) assert.ok(check(e as T), (e as Error).name + ': ' + (e as Error).message);
        return e as T;
    }
    assert.fail('expected a rejection (' + cls.name + ')');
}

test('the socket: login, PING, a SELECT and its read point, a write and its commit', { timeout: 90000 }, async () => {
    const c = await sockA();
    assert.strictEqual(c.endpoint, 'socket');
    await c.ping();
    const r = await c.query('SELECT 1 AS one, $1 AS p', [41n]);
    assert.deepStrictEqual(r.rows, [[1n, 41n]]);
    assert.strictEqual(r.columns![0].name, 'one');
    assert.strictEqual(r.columns![0].type, 'INT64');
    assert.strictEqual(r.state, 'idle');
    await c.query('CREATE TABLE s1 (id BIGINT PRIMARY KEY, v TEXT)');
    const ins = await c.query('INSERT INTO s1 VALUES ($1, $2)', [1, 'x']);
    assert.strictEqual(ins.count, 1n);
    assert.ok(ins.done.write && ins.done.write.commit >= 1n && ins.done.write.hash.length === 32);
    const sel = await c.query('SELECT * FROM s1');
    assert.ok(sel.done.read);
    assert.strictEqual(sel.done.read!.commit, ins.done.write!.commit); /* the read point is the write's commit */
    assert.strictEqual(sel.done.read!.dbId.length, 16);
    assert.ok(sel.done.read!.hash.equals(ins.done.write!.hash));
    assert.strictEqual(sel.done.read!.own, false);
    assert.deepStrictEqual(sel.objects(), [{ id: 1n, v: 'x' }]);
    await c.close();
    assert.ok(c.closed);
    await rejectsWith(c.query('SELECT 1'), ClosedError, (e) => e.reason === null);
});

test('TCP with TLS 1.3: the CA by address and by name, the pin as hex and as bytes; the exporter binding by default', { timeout: 90000 }, async () => {
    for (const host of ['127.0.0.1', 'localhost']) {
        const c = await open({ host, port: A.port, caFile: A.caFile }, cred);
        assert.strictEqual(c.endpoint, 'tcp');
        assert.deepStrictEqual((await c.query('SELECT 2')).rows, [[2n]]);
        await c.close();
    }
    const ca = fs.readFileSync(A.caFile);
    for (const o of [{ ca }, { pin: A.pin }, { pin: Buffer.from(A.pin, 'hex') }, { pin: A.pin.toUpperCase() }]) {
        const c = await open({ host: '127.0.0.1', port: A.port, ...o }, cred);
        await c.ping();
        await c.close();
    }
});

/* a raw login over a TLS session with a binding value chosen by the test: the server checks the binding (a wrong one
 * refused as a wrong password is), so a login with the driver's own value proves that value is the server's */
async function rawLogin(port: number, host: string, pin: string, cbType: number, binding: (s: tls.TLSSocket) => Buffer): Promise<void> {
    const ts = tls.connect({ host, port, rejectUnauthorized: false, ALPNProtocols: ['imdbwir1'], minVersion: 'TLSv1.3', maxVersion: 'TLSv1.3' });
    await new Promise<void>((res, rej) => {
        ts.once('secureConnect', res);
        ts.once('error', rej);
    });
    const c = new Client(ts, 'tcp');
    try {
        await c.authenticate(w.EP.TCP, cbType, binding(ts), Buffer.from(cred.user), cred.password);
        await c.ping();
        await c.close();
    } finally {
        c.destroy();
    }
}

test('channel binding: the exporter, tls-server-end-point by server mode, a wrong value refused (no downgrade)', { timeout: 90000 }, async () => {
    const exporter = (s: tls.TLSSocket) => s.exportKeyingMaterial(32, 'EXPORTER-Channel-Binding');
    const endpoint = (s: tls.TLSSocket) => crypto.createHash('sha256').update(s.getPeerX509Certificate()!.raw).digest();
    /* A (default: the exporter alone) */
    await rawLogin(A.port, '127.0.0.1', A.pin, w.CB.EXPORTER, exporter);
    await rejectsWith(rawLogin(A.port, '127.0.0.1', A.pin, w.CB.EXPORTER, () => Buffer.alloc(32)), AuthError, (e) => e.message === 'authentication refused');
    await rejectsWith(connect({ host: '127.0.0.1', port: A.port, pin: A.pin, channelBinding: 'tls-server-end-point' }, cred), AuthError,
        (e) => /channel binding type/.test(e.message)); /* verdict 2: never retried */
    /* B (any): both types; each value checked */
    for (const cb of ['tls-exporter', 'tls-server-end-point'] as const) {
        const c = await open({ host: '127.0.0.2', port: B.port, pin: B.pin, channelBinding: cb }, cred);
        await c.ping();
        await c.close();
    }
    await rawLogin(B.port, '127.0.0.2', B.pin, w.CB.ENDPOINT, endpoint);
    await rejectsWith(rawLogin(B.port, '127.0.0.2', B.pin, w.CB.ENDPOINT, (s) => { const b = endpoint(s); b[0] ^= 1; return b; }), AuthError);
    await rejectsWith(rawLogin(B.port, '127.0.0.2', B.pin, w.CB.ENDPOINT, exporter), AuthError); /* the type is bound too */
    /* the socket takes none: a hello naming a type there is refused (verdict 2) */
    const s = net.createConnection({ path: A.socket });
    await new Promise<void>((r) => s.once('connect', r));
    const c = new Client(s, 'socket');
    await rejectsWith(c.authenticate(w.EP.UNIX, w.CB.EXPORTER, Buffer.alloc(32), Buffer.from(cred.user), cred.password), AuthError, (e) => /binding/.test(e.message));
    c.destroy();
});

test('refused: a wrong pin, another CA, a host outside the certificate, a wrong password, an unknown name; no unverified mode', { timeout: 90000 }, async () => {
    await rejectsWith(connect({ host: '127.0.0.1', port: A.port, pin: B.pin }, cred), AuthError, (e) => /not the pinned one/.test(e.message));
    await rejectsWith(connect({ host: '127.0.0.1', port: A.port, caFile: B.caFile }, cred), AuthError, (e) => /^TLS: /.test(e.message));
    await rejectsWith(connect({ host: '127.0.0.2', port: B.port, caFile: B.caFile }, cred), AuthError, (e) => /127\.0\.0\.2/.test(e.message)); /* IP not in SAN */
    const wrongPw = await rejectsWith(connect({ socket: A.socket }, { user: cred.user, password: 'wrong-password' }), AuthError);
    const unknown = await rejectsWith(connect({ socket: A.socket }, { user: 'nobody_here', password: cred.password }), AuthError);
    assert.strictEqual(wrongPw.message, unknown.message); /* one path: no user-existence oracle */
    await rejectsWith(connect({ host: '127.0.0.1', port: A.port, pin: A.pin }, { user: cred.user, password: 'wrong' }), AuthError);
    /* no unverified mode by construction: neither a CA nor a pin, both, or Node's own switch, refused before any byte */
    await rejectsWith(connect({ host: '127.0.0.1', port: A.port } as never, cred), ProtocolError, (e) => /exactly one/.test(e.message));
    await rejectsWith(connect({ host: '127.0.0.1', port: A.port, pin: A.pin, caFile: A.caFile }, cred), ProtocolError);
    await rejectsWith(connect({ host: '127.0.0.1', port: A.port, pin: A.pin, rejectUnauthorized: false } as never, cred), TypeError);
    await rejectsWith(connect({ host: '127.0.0.1', port: A.port, pin: 'abcd' }, cred), ProtocolError);
    await rejectsWith(connect({ socket: A.socket }, { user: '', password: 'x' }), ProtocolError);
    await rejectsWith(connect({ socket: A.socket }, { user: 'admin', password: 'café' }), ProtocolError); /* printable ASCII */
    await rejectsWith(connect({ socket: TMP + '/no-such-socket' }, cred), ImdbError, (e) => e.code === ERR.IO);
});

test('every value type round-tripped through a table at its edges, NULLs typed, metadata', { timeout: 90000 }, async () => {
    const c = await tcpA();
    await c.query("CREATE TYPE mood AS ENUM ('sad', 'ok', 'happy', '')");
    await c.query('CREATE TABLE ty (id BIGINT PRIMARY KEY, i64 BIGINT, i32 INTEGER, i16 SMALLINT, f FLOAT64, b BOOL, t TEXT, vc VARCHAR(3), ' +
        'd38 DECIMAL(38,0), d3810 DECIMAL(38,10), d102 DECIMAL(10,2), ts TIMESTAMP, tz TIMESTAMPTZ, dt DATE, tm TIME, u UUID, bt BYTEA, iv INTERVAL, e mood)');
    const max38 = 10n ** 38n - 1n;
    const big = Buffer.alloc(65535);
    for (let i = 0; i < big.length; i++) big[i] = (i * 7) & 0xff;
    const rows: unknown[][] = [
        [1n, (1n << 63n) - 1n, 2147483647n, 32767n, Number.MAX_VALUE, true, '﻿hé\u{1F600}', '\u{1F600}\u{1F600}\u{1F600}',
            new Decimal(max38, 0), new Decimal(max38, 10), Decimal.parse('99999999.99'), Timestamp.parse('9999-12-31 23:59:59.999999'),
            TimestampTz.parse('9999-12-31 23:59:59.999999Z'), SqlDate.parse('9999-12-31'), SqlTime.parse('23:59:59.999999'),
            'ffffffff-ffff-ffff-ffff-ffffffffffff', big, new Interval(2 ** 31 - 1, 2 ** 31 - 1, (1n << 63n) - 1n), 'happy'],
        [2n, -(1n << 63n), -2147483648n, -32768n, -Number.MIN_VALUE, false, '', '', new Decimal(-max38, 0), new Decimal(-max38, 10),
            Decimal.parse('-99999999.99'), Timestamp.parse('0001-01-01 00:00:00'), TimestampTz.parse('0001-01-01 00:00:00Z'),
            SqlDate.parse('0001-01-01'), new SqlTime(0n), '00000000-0000-0000-0000-000000000000', Buffer.alloc(0),
            new Interval(-(2 ** 31), -(2 ** 31), -(1n << 63n)), ''],
        [3n, 0n, 0n, 0n, 0.1, true, 'a', 'abc', new Decimal(0n, 0), new Decimal(-1n, 10), Decimal.parse('0.01'),
            Timestamp.parse('1969-12-31 23:59:59.999999'), TimestampTz.parse('1970-01-01 00:00:00.000001+00:00'), SqlDate.parse('1970-01-01'),
            new SqlTime(1n), '00010203-0405-0607-0809-0a0b0c0d0e0f', Buffer.from([0]), new Interval(1, -2, 3n), 'sad'],
        [4n, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null],
    ];
    /* parameters: a UUID as Uuid (a string is TEXT), an ENUM label as TEXT (§4), a typed NULL here and there */
    const asParams = (r: unknown[]) => r.map((v, i) => (i === 15 && typeof v === 'string' ? new Uuid(v) : i === 4 && typeof v === 'number' ? new Float64(v) : v));
    for (const r of rows.slice(0, 3)) await c.query('INSERT INTO ty VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19)', asParams(r) as never);
    const nulls = [4n, nullOf('INT64'), null, nullOf('INT64'), nullOf('FLOAT64'), nullOf('BOOL'), nullOf('TEXT'), null, nullOf('DECIMAL'), null,
        nullOf('DECIMAL'), nullOf('TIMESTAMP'), nullOf('TIMESTAMPTZ'), nullOf('DATE'), nullOf('TIME'), nullOf('UUID'), nullOf('BYTEA'), nullOf('INTERVAL'), nullOf('ENUM')];
    await c.query('INSERT INTO ty VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19)', nulls as never);
    const r = await c.query('SELECT * FROM ty ORDER BY id');
    assert.deepStrictEqual(r.rows, rows);
    const cols = r.columns!;
    const meta = (n: string) => cols.find((x) => x.name === n)!;
    /* what the server reports for a result (conv.c imdbw_columns_of): a DECIMAL's scale alone (precision 0: not known),
     * no INT64 width and no VARCHAR length (precision 0), though §4 allows them (defects.md) */
    assert.deepStrictEqual([meta('i32').type, meta('i32').precision, meta('i16').precision, meta('i64').precision], ['INT64', 0, 0, 0]);
    assert.deepStrictEqual([meta('d102').type, meta('d102').precision, meta('d102').scale], ['DECIMAL', 0, 2]);
    assert.deepStrictEqual([meta('d3810').scale, meta('d38').scale], [10, 0]);
    assert.deepStrictEqual([meta('vc').type, meta('vc').precision], ['TEXT', 0]);
    assert.deepStrictEqual([meta('e').type, meta('e').labels], ['ENUM', ['sad', 'ok', 'happy', '']]);
    assert.deepStrictEqual(cols.map((x) => x.type), ['INT64', 'INT64', 'INT64', 'INT64', 'FLOAT64', 'BOOL', 'TEXT', 'TEXT', 'DECIMAL', 'DECIMAL',
        'DECIMAL', 'TIMESTAMP', 'TIMESTAMPTZ', 'DATE', 'TIME', 'UUID', 'BYTEA', 'INTERVAL', 'ENUM']);
    /* the values as the engine reads them: literals find the parameters' rows (no conversion on the way) */
    const find = async (pred: string) => (await c.query('SELECT id FROM ty WHERE ' + pred)).rows.map((x) => x[0]);
    assert.deepStrictEqual(await find('i64 = 9223372036854775807'), [1n]);
    assert.deepStrictEqual(await find("d3810 = -9999999999999999999999999999.9999999999"), [2n]);
    assert.deepStrictEqual(await find("tz = TIMESTAMPTZ '1970-01-01 00:00:00.000001+00'"), [3n]);
    assert.deepStrictEqual(await find("e = 'happy'"), [1n]);
    assert.deepStrictEqual(await find('f = 0.1'), [3n]);
    /* a SUM over an INT64 column is a DECIMAL at scale 0 (§4: 38 digits), whatever its cells */
    const sum = await c.query('SELECT SUM(i32) AS s FROM ty WHERE id > 100');
    assert.deepStrictEqual([sum.columns![0].type, sum.columns![0].scale, sum.rows[0][0]], ['DECIMAL', 0, null]);
    const sum2 = await c.query('SELECT SUM(i64) AS s FROM ty WHERE id = 1 OR id = 1');
    assert.ok((sum2.rows[0][0] as Decimal).equals(new Decimal((1n << 63n) - 1n, 0)));
    /* the engine's refusals reach the caller as ServerErrors, the connection usable after */
    await rejectsWith(c.query('INSERT INTO ty (id, vc) VALUES ($1, $2)', [9, '\u{1F600}\u{1F600}\u{1F600}a']), ServerError);
    await rejectsWith(c.query('INSERT INTO ty (id, i16) VALUES ($1, $2)', [9, 32768]), ServerError);
    await rejectsWith(c.query('INSERT INTO ty (id, e) VALUES ($1, $2)', [9, 'angry']), ServerError);
    /* a number by its value: an INT64 into a DECIMAL and a FLOAT64 column, a DECIMAL into an INT64 at scale 0 (N1b's rule) */
    await c.query('INSERT INTO ty (id, d102, f, i64) VALUES ($1, $2, $3, $4)', [10, 7, 2, new Decimal(5n, 0)]);
    assert.deepStrictEqual((await c.query('SELECT d102, f, i64 FROM ty WHERE id = 10')).rows, [[Decimal.parse('7.00'), 2, 5n]]);
    await c.close();
});

test('batches: in order, an ERROR mid-batch ends it (its index), the statements before it stand', { timeout: 90000 }, async () => {
    const c = await sockA();
    await c.query('CREATE TABLE bt (id BIGINT PRIMARY KEY)');
    const ok = await c.batch(['INSERT INTO bt VALUES (1)', { sql: 'INSERT INTO bt VALUES ($1)', params: [2] }, 'SELECT COUNT(*) FROM bt']);
    assert.strictEqual(ok.results.length, 3);
    assert.deepStrictEqual(ok.results[2].rows, [[2n]]);
    const e = await rejectsWith(c.batch(['INSERT INTO bt VALUES (3)', 'INSERT INTO bt VALUES (1)', 'INSERT INTO bt VALUES (4)']), ServerError);
    assert.strictEqual(e.index, 1);
    assert.strictEqual(e.code, ERR.CONSTRAINT);
    assert.strictEqual(e.results.length, 1);
    assert.strictEqual(e.state, 'idle');
    assert.deepStrictEqual((await c.query('SELECT id FROM bt ORDER BY id')).rows, [[1n], [2n], [3n]]); /* 4 never ran */
    /* a syntax error mid-batch: its code, its index */
    const s = await rejectsWith(c.batch(['SELECT 1', 'SELEKT 2']), ServerError);
    assert.deepStrictEqual([s.index, s.code, s.codeName], [1, ERR.SYNTAX, 'SYNTAX']);
    /* pipelining: 200 requests sent before any reply is read, each answered in order */
    const ps = [];
    for (let i = 0; i < 200; i++) ps.push(c.query('SELECT $1 AS v', [i]));
    ps.push(c.query('SELEKT')); /* one failing among them: its own request alone */
    for (let i = 0; i < 50; i++) ps.push(c.query('SELECT $1 AS v', [1000 + i]));
    const got = await Promise.allSettled(ps);
    got.forEach((g, i) => {
        if (i === 200) assert.ok(g.status === 'rejected' && g.reason instanceof ServerError);
        else assert.ok(g.status === 'fulfilled' && g.value.rows[0][0] === BigInt(i < 200 ? i : 1000 + i - 201));
    });
    await c.close();
});

test('prepared statements: several parameter sets, an ERROR at a set (its index), DEALLOCATE', { timeout: 90000 }, async () => {
    const c = await sockA();
    await c.query('CREATE TABLE pt (id BIGINT PRIMARY KEY, v TEXT)');
    const p = await c.prepare('ins', 'INSERT INTO pt VALUES ($1, $2)');
    assert.strictEqual(p.status, 'PREPARE');
    const r = await c.execute('ins', [[1, 'a'], [2, 'b'], [3, null]]);
    assert.deepStrictEqual(r.results.map((x) => x.count), [1n, 1n, 1n]);
    const e = await rejectsWith(c.execute('ins', [[4, 'd'], [2, 'dup'], [5, 'e']]), ServerError);
    assert.deepStrictEqual([e.index, e.code, e.results.length], [1, ERR.CONSTRAINT, 1]);
    await c.prepare('sel', 'SELECT v FROM pt WHERE id = $1');
    const s = await c.execute('sel', [[1], [3], [99]]);
    assert.deepStrictEqual(s.results.map((x) => x.rows), [[['a']], [[null]], []]);
    assert.strictEqual((await c.deallocate('ins')).status, 'DEALLOCATE');
    await rejectsWith(c.execute('ins', [[6, 'f']]), ServerError);
    await rejectsWith(c.prepare('bad', 'SELEKT'), ServerError, (x) => x.code === ERR.SYNTAX);
    await c.close();
});

test("transactions: READY's states, statement-level rollback, a batch stopping at its ERROR, a doomed transaction", { timeout: 90000 }, async () => {
    const c = await sockA(), d = await sockA();
    await c.query('CREATE TABLE tx (id BIGINT PRIMARY KEY)');
    assert.strictEqual((await c.query('BEGIN')).state, 'transaction');
    await c.query('INSERT INTO tx VALUES (1)');
    const e = await rejectsWith(c.query('INSERT INTO tx VALUES (1)'), ServerError);
    assert.strictEqual(e.state, 'transaction'); /* the failed statement undone alone */
    assert.strictEqual(c.state, 'transaction');
    assert.strictEqual((await c.query('COMMIT')).state, 'idle');
    assert.deepStrictEqual((await d.query('SELECT id FROM tx')).rows, [[1n]]);
    const b = await rejectsWith(c.batch(['BEGIN', 'INSERT INTO tx VALUES (2)', 'INSERT INTO tx VALUES (1)', 'COMMIT']), ServerError);
    assert.deepStrictEqual([b.index, b.state], [2, 'transaction']); /* its COMMIT never ran */
    assert.strictEqual((await c.query('ROLLBACK')).state, 'idle');
    assert.deepStrictEqual((await d.query('SELECT id FROM tx')).rows, [[1n]]);
    /* doomed: a transaction that wrote a table an ALTER then changed takes only ROLLBACK */
    await c.query('BEGIN');
    await c.query('INSERT INTO tx VALUES (5)');
    await d.query('ALTER TABLE tx ADD COLUMN z BIGINT');
    const x = await c.query('SELECT 1').then((r) => r.state, (err: ServerError) => err.state);
    assert.strictEqual(x, 'doomed');
    assert.strictEqual(c.state, 'doomed');
    assert.strictEqual((await c.query('ROLLBACK')).state, 'idle');
    await c.close();
    await d.close();
});

let bigLoaded = false;
async function loadBig(c: Client): Promise<void> {
    if (bigLoaded) return;
    await c.query('CREATE TABLE big (x BIGINT PRIMARY KEY)');
    async function* rows() {
        for (let k = 0; k < 100; k++) {
            let s = '';
            for (let i = k * 10000; i < (k + 1) * 10000; i++) s += i + '\n';
            yield s;
        }
    }
    const r = await c.copyFrom('COPY big FROM STDIN', rows());
    assert.strictEqual(r.count, 1000000n);
    bigLoaded = true;
}

/* CANCEL lands only on a running statement (§4), so it is sent again until the query settles */
async function cancelUntilSettled(c: Client, p: Promise<unknown>): Promise<unknown> {
    let settled = false;
    p.then(() => (settled = true), () => (settled = true));
    await sleep(150);
    assert.ok(!settled, 'the statement had ended before any CANCEL: nothing long to cancel');
    for (let k = 0; !settled && k < 100; k++) {
        c.cancel();
        await sleep(100);
    }
    return p;
}

test('COPY FROM: 1,000,000 rows from an async generator, then CANCEL of a self-join of them; PING during it', { timeout: 120000 }, async () => {
    const c = await sockA();
    await loadBig(c);
    assert.deepStrictEqual((await c.query('SELECT COUNT(*) FROM big')).rows, [[1000000n]]);
    assert.strictEqual(c.cancel(), false); /* nothing outstanding: dropped, the next statement not cancelled */
    assert.deepStrictEqual((await c.query('SELECT MAX(x) FROM big')).rows, [[999999n]]);
    const t0 = Date.now();
    const long = c.query('SELECT COUNT(*) FROM big AS a, big AS b WHERE a.x < b.x');
    long.catch(() => undefined); /* handled here; awaited below */
    await sleep(100);
    await c.ping(); /* answered out of turn while the statement runs */
    const e = await rejectsWith(cancelUntilSettled(c, long), ServerError);
    assert.strictEqual(e.code, ERR.CANCELLED);
    assert.ok(Date.now() - t0 < 60000);
    assert.deepStrictEqual((await c.query('SELECT 7')).rows, [[7n]]); /* the connection goes on */
    await c.close();
});

test('COPY both ways: sources and sinks, bad data, a failing source, a refused COPY, query()\'s COPY, the line held', { timeout: 120000 }, async () => {
    const c = await tcpA();
    await c.query('CREATE TABLE cp (id BIGINT PRIMARY KEY, t TEXT, d DECIMAL(10,2))');
    const r1 = await c.copyFrom('COPY cp FROM STDIN', '1,a,1.50\n2,"b,c",\n');
    assert.strictEqual(r1.count, 2n);
    const r2 = await c.copyFrom('COPY cp FROM STDIN', [Buffer.from('3,x'), Buffer.from('y,0.01\n4,'), 'é,2\n']); /* split anywhere */
    assert.strictEqual(r2.count, 2n);
    /* requests around a COPY: one before it runs first; ones asked while it is under way (a SESSIONS, a QUERY) are held
     * until its end (§4: a request between the COPY's QUERY and its end is ERROR 9 and the close), then run */
    const before = c.query('SELECT COUNT(*) FROM cp');
    const r3 = c.copyFrom('COPY cp FROM STDIN', (async function* () { await sleep(400); yield '5,five,5\n'; })());
    await sleep(150); /* the server's COPY_IN read, its data awaited: a request reaching it now would be ERROR 9 and the close */
    const held = c.query('SELECT COUNT(*) FROM cp');
    const sess = c.sessions();
    await c.ping(); /* PING passes the line (§4) */
    assert.strictEqual((await r3).count, 1n);
    assert.deepStrictEqual((await before).rows, [[4n]]);
    assert.deepStrictEqual((await held).rows, [[5n]]); /* asked after the COPY: run after it */
    assert.ok((await sess).length >= 1);
    /* COPY TO: to a function, to a Writable-like with backpressure, and into the result */
    const want = '1,a,1.50\n2,"b,c",\n3,xy,0.01\n4,é,2.00\n5,five,5.00\n';
    const parts: Buffer[] = [];
    const o1 = await c.copyTo('COPY cp TO STDOUT', (b) => { parts.push(b); });
    assert.strictEqual(Buffer.concat(parts).toString(), want);
    assert.strictEqual(o1.count, 5n);
    const slow: Buffer[] = [];
    const listeners: { [k: string]: (() => void)[] } = {};
    const sink = {
        write(b: Buffer) {
            slow.push(b);
            setTimeout(() => (listeners.drain ?? []).splice(0).forEach((f) => f()), 20);
            return false;
        },
        once(ev: string, f: () => void) {
            (listeners[ev] = listeners[ev] ?? []).push(f);
        },
    };
    await c.copyTo('COPY cp TO STDOUT', sink);
    assert.strictEqual(Buffer.concat(slow).toString(), want);
    const q = await c.query('COPY cp TO STDOUT');
    assert.strictEqual(q.copyOut!.toString(), want);
    /* a big COPY TO (1,000,000 rows, past one frame) through an async sink */
    await loadBig(c);
    let n = 0, bytes = 0;
    const big = await c.copyTo('COPY big TO STDOUT', async (b) => {
        bytes += b.length;
        for (const x of b) if (x === 10) n++;
    });
    assert.deepStrictEqual([big.count, n, bytes], [1000000n, 1000000, 6888890]);
    /* bad data: refused after the whole upload, by line; the connection goes on */
    const bad = await rejectsWith(c.copyFrom('COPY cp FROM STDIN', '6,ok,1\n7,bad,notanumber\n'), ServerError);
    assert.strictEqual(bad.index, 0);
    assert.deepStrictEqual((await c.query('SELECT COUNT(*) FROM cp')).rows, [[5n]]);
    /* a source that throws: COPY_FAIL, the statement refused unrun with its reason */
    async function* failing() {
        yield '8,eight,8\n';
        throw new Error('the source broke');
    }
    const f = await rejectsWith(c.copyFrom('COPY cp FROM STDIN', failing()), ServerError, (x) => x.code === ERR.CANCELLED);
    assert.match(f.message, /the source broke/);
    /* a COPY refused before its data (no such table): nothing sent, the connection goes on */
    await rejectsWith(c.copyFrom('COPY nope FROM STDIN', '1\n'), ServerError);
    /* query() of a COPY FROM: the driver has no data to give: COPY_FAIL, the statement refused, the connection goes on */
    await rejectsWith(c.query('COPY cp FROM STDIN'), ServerError, (x) => x.code === ERR.CANCELLED && /copyFrom/.test(x.message));
    /* CANCEL during an upload: sent before the next frame, the COPY refused unrun, its data's end still sent */
    let stop = false;
    let pulled: () => void = () => undefined;
    const firstPull = new Promise<void>((r) => (pulled = r));
    async function* slowSource() { /* first pulled once the COPY_IN is read: the server's COPY then open (a CANCEL refuses it) */
        for (let i = 100; !stop && i < 100000; i++) {
            pulled();
            yield i + ',s,1\n';
            await sleep(5);
        }
    }
    const up = c.copyFrom('COPY cp FROM STDIN', slowSource());
    let upSettled = false;
    up.then(() => (upSettled = true), () => (upSettled = true));
    await firstPull;
    assert.strictEqual(c.cancel(), true);
    for (let k = 0; !upSettled && k < 100; k++) { /* sent again until it settles: one is enough here, more never hurt */
        await sleep(50);
        if (!upSettled) c.cancel();
    }
    const ce = await rejectsWith(up, ServerError, (x) => x.code === ERR.CANCELLED);
    stop = true;
    assert.ok(ce);
    assert.deepStrictEqual((await c.query('SELECT COUNT(*) FROM cp')).rows, [[5n]]);
    /* a sink that throws: the statement cancelled, the call rejects with the sink's error */
    await rejectsWith(c.copyTo('COPY big TO STDOUT', () => { throw new Error('sink full'); }), Error, (x) => x.message === 'sink full');
    assert.deepStrictEqual((await c.query('SELECT 1')).rows, [[1n]]);
    await c.close();
});

test('large results, columns of no known type, and real Node streams both ways', { timeout: 120000 }, async () => {
    const c = await sockA();
    await loadBig(c);
    /* 1,000,000 rows read through ROWS frames (each cut at 64 KiB by the server: tens of thousands of rows a frame) */
    const all = await c.query('SELECT x FROM big ORDER BY x');
    assert.strictEqual(all.rows.length, 1000000);
    assert.deepStrictEqual([all.rows[0], all.rows[999999], all.count], [[0n], [999999n], 1000000n]);
    for (let i = 0; i < all.rows.length; i += 99991) assert.strictEqual(all.rows[i][0], BigInt(i));
    const flags = await c.query('SELECT x < 0 AS b FROM big'); /* two bytes a row: the most rows a frame holds */
    assert.strictEqual(flags.rows.length, 1000000);
    assert.ok(flags.rows.every((r) => r[0] === false));
    /* columns the statement does not type (SHOW, EXPLAIN): type NONE, each value its own type */
    const tables = await c.query('SHOW TABLES');
    assert.ok(tables.columns!.every((x) => x.type === 'NONE' && x.typeId === 0));
    const bigRow = tables.objects().find((o) => o.table === 'big')!;
    assert.deepStrictEqual([bigRow.live_rows, bigRow.dropped_at], [1000000n, null]);
    const ex = await c.query('EXPLAIN SELECT x FROM big WHERE x = 5');
    assert.deepStrictEqual(ex.columns!.map((x) => [x.name, x.type]), [['item', 'NONE'], ['detail', 'NONE']]);
    assert.ok(ex.rows.length >= 1 && ex.rows.every((r) => typeof r[0] === 'string'));
    const stats = await c.query('SHOW STATS');
    assert.ok(stats.rows.some((r) => typeof r[1] === 'bigint'));
    /* a real Readable as COPY's source, a real Writable (a small highWaterMark, slow writes) as its sink */
    await c.query('CREATE TABLE st (id BIGINT PRIMARY KEY, t TEXT)');
    const src = stream.Readable.from((function* () {
        for (let k = 0; k < 50; k++) {
            let s = '';
            for (let i = k * 2000; i < (k + 1) * 2000; i++) s += i + ',r' + i + '\n';
            yield Buffer.from(s);
        }
    })());
    assert.strictEqual((await c.copyFrom('COPY st FROM STDIN', src)).count, 100000n);
    let got = 0, writes = 0;
    const sink = new stream.Writable({
        highWaterMark: 4096,
        write(chunk: Buffer, _enc: string, cb: (e?: Error | null) => void) {
            got += chunk.length;
            writes++;
            setTimeout(() => cb(), writes % 8 ? 0 : 5);
        },
    });
    const out = await c.copyTo('COPY st TO STDOUT', sink);
    assert.strictEqual(out.count, 100000n);
    await new Promise<void>((r) => sink.end(() => r()));
    let want = 0;
    for (let i = 0; i < 100000; i++) want += 2 * String(i).length + 3;
    assert.strictEqual(got, want);
    assert.ok(sink.listenerCount('close') <= 1 && sink.listenerCount('error') <= 1, 'listeners left on the sink'); /* each removed */
    /* a sink that ends early: the statement cancelled, the call rejects with the sink's closing */
    const early = new stream.Writable({ highWaterMark: 1, write(_c: Buffer, _e: string, cb: (e?: Error | null) => void) { setTimeout(() => cb(), 1); } });
    setTimeout(() => early.destroy(), 30);
    await rejectsWith(c.copyTo('COPY big TO STDOUT', early), Error);
    assert.deepStrictEqual((await c.query('SELECT 1')).rows, [[1n]]);
    await c.close();
});

test('SESSIONS and KILL: list, cancel another session\'s statement, terminate it; its next call reports why', { timeout: 120000 }, async () => {
    const y = await sockA();
    await loadBig(y);
    const before = new Set((await y.sessions()).map((s) => s.id));
    const x = await tcpA();
    const list = await y.sessions();
    const mine = list.filter((s) => !before.has(s.id));
    assert.strictEqual(mine.length, 1);
    const xs = mine[0];
    assert.deepStrictEqual([xs.endpoint, xs.name, xs.state], ['tcp', 'admin', 'idle']);
    const long = x.query('SELECT COUNT(*) FROM big AS a, big AS b WHERE a.x < b.x');
    long.catch(() => undefined);
    await sleep(200);
    const running = (await y.sessions()).find((s) => s.id === xs.id)!;
    assert.strictEqual(running.state, 'running');
    assert.strictEqual(await y.kill(xs.id, 'cancel'), true);
    await rejectsWith(long, ServerError, (e) => e.code === ERR.CANCELLED);
    assert.deepStrictEqual((await x.query('SELECT 3')).rows, [[3n]]);
    assert.strictEqual(await y.kill(999999999n, 'cancel'), false); /* no such session */
    await x.query('BEGIN');
    const closed = new Promise<ClosedError>((r) => x.once('close', r));
    assert.strictEqual(await y.kill(xs.id, 'terminate'), true);
    const ce = await closed;
    assert.ok(ce.reason && ce.reason.code === ERR.CANCELLED && /KILL/.test(ce.reason.message), ce.message);
    /* a send after the server closed: the server's last ERROR is the reason (§4's closed_reason) */
    const after = await rejectsWith(x.query('SELECT 1'), ClosedError);
    assert.strictEqual(after.code, ERR.CANCELLED);
    assert.match(after.message, /the server closed the connection: .*KILL/);
    assert.ok(!(await y.sessions()).some((s) => s.id === xs.id));
    await y.close();
});

test('a protocol error the server answers: its ERROR, its close, then the reason on every later call', { timeout: 90000 }, async () => {
    const c = await sockA();
    const closed = new Promise<ClosedError>((r) => c.once('close', r));
    c.sendRaw(w.encodeCopyData(Buffer.from('x'))); /* COPY data with no COPY running */
    const ce = await closed;
    assert.strictEqual(ce.reason!.code, ERR.STATE);
    const e = await rejectsWith(c.query('SELECT 1'), ClosedError);
    assert.strictEqual(e.code, ERR.STATE);
    assert.match(e.message, /COPY data with no COPY running/);
    await rejectsWith(c.ping(), ClosedError);
    /* a request already in flight when the server refuses an earlier frame: that ERROR answers it */
    const d = await sockA();
    d.sendRaw(w.encodeCopyData(Buffer.from('x')));
    const q = await rejectsWith(d.query('SELECT 1'), ImdbError);
    assert.strictEqual(q.code, ERR.STATE);
});

/* a server that answers what the real one never does: the driver refuses the frame, ends the connection, and every
 * pending call rejects with the error naming it */
const fakes: net.Server[] = [];
function fakeServer(path: string, reply: (s: net.Socket) => void, onFrame?: (s: net.Socket, type: number) => void): Promise<net.Server> {
    const salt = Buffer.alloc(16, 9);
    const v = scramVerifier('pw-fake', salt, 4096);
    const srv = net.createServer((s) => {
        const fr = new w.FrameReader(false);
        let stage = 0;
        let hello: Buffer, ch: Buffer;
        s.on('error', () => undefined);
        s.on('data', (b: Buffer) => {
            fr.push(b);
            if (stage === 0) {
                const h = fr.take(112);
                if (!h) return;
                hello = h;
                ch = w.encodeChallenge({ version: 1, salt, iter: 4096, nonce: Buffer.alloc(32, 7) });
                s.write(ch);
                stage = 1;
            }
            if (stage === 1) {
                const p = fr.take(32);
                if (!p) return;
                const am = w.authMessage(w.EP.UNIX, hello, ch, Buffer.alloc(32));
                const r = scramServer(v.stored, v.serverKey, am, p);
                s.write(w.encodeVerdict({ code: r.ok ? 0 : 1, sig: r.ok ? r.sig : Buffer.alloc(32) }));
                stage = 2;
            }
            for (let f = stage === 2 ? fr.next() : null; f; f = fr.next()) {
                if (onFrame) onFrame(s, f.type);
                else if (f.type === w.F.QUERY) reply(s);
            }
        });
    });
    fakes.push(srv);
    return new Promise((res) => srv.listen(path, () => res(srv)));
}

test('a frame the decoder refuses ends the connection with an error naming it', { timeout: 90000 }, async () => {
    const cols = [w.column('n', w.T.INT64, 16)];
    const cases: [string, (s: net.Socket) => void, RegExp][] = [
        ['ROWS past its column', (s) => {
            s.write(w.encodeServer({ type: 64, columns: cols }));
            const body = Buffer.from('01000000' + '01' + '0080000000000000', 'hex'); /* 32768 in a SMALLINT */
            const h = Buffer.alloc(5);
            h.writeUInt32LE(body.length + 1, 0);
            h[4] = w.F.ROWS;
            s.write(Buffer.concat([h, body]));
        }, /ROWS frame refused.*column/],
        ['a type no server sends', (s) => s.write(Buffer.from('0100000005', 'hex')), /frame refused.*type/],
        ['a READY state 3', (s) => s.write(Buffer.from('020000004703', 'hex')), /READY frame refused/],
        ['a PONG never asked for', (s) => s.write(w.encodeEmpty(w.F.PONG)), /PONG/],
        ['a frame past 16 MiB', (s) => s.write(Buffer.from('0100000147', 'hex')), /frame refused.*bytes/],
    ];
    let k = 0;
    for (const [name, reply, re] of cases) {
        const path = TMP + '/fake' + k++ + '.sock';
        const srv = await fakeServer(path, reply);
        const c = await open({ socket: path }, { user: 'u', password: 'pw-fake' });
        const e = await rejectsWith(c.query('SELECT 1'), ProtocolError, (x) => re.test(x.message));
        assert.ok(c.closed, name);
        await rejectsWith(c.query('SELECT 1'), ClosedError);
        assert.ok(e);
        srv.close();
    }
    /* a server that does not prove it holds the verifier: refused */
    const path = TMP + '/fake-sig.sock';
    const srv = net.createServer((s) => {
        let got = 0;
        s.on('error', () => undefined);
        s.on('data', (b: Buffer) => {
            got += b.length;
            if (got === 112) s.write(w.encodeChallenge({ version: 1, salt: Buffer.alloc(16, 1), iter: 1000, nonce: Buffer.alloc(32) }));
            if (got === 144) s.write(w.encodeVerdict({ code: 0, sig: Buffer.alloc(32, 0x5a) }));
        });
    });
    fakes.push(srv);
    await new Promise<void>((r) => srv.listen(path, () => r()));
    await rejectsWith(connect({ socket: path }, { user: 'u', password: 'anything' }), AuthError, (e) => /did not prove/.test(e.message));
    srv.close();
});

/* what srv.c sends that the real server rarely shows on demand: an out-of-turn PONG between a statement's COLUMNS and
 * its ROWS, a WARNING before DONE and before an ERROR, an ERROR after rows (they are not the answer), a READY after
 * fewer DONEs than statements (a stopping server's) */
test('sequences: PONG among a statement\'s frames, WARNINGs, an ERROR after ROWS, a READY short of its DONEs', { timeout: 90000 }, async () => {
    const cols = [w.column('n', w.T.INT64)];
    const row = (i: bigint) => w.encodeServer({ type: 65, rows: [[w.wv({ type: w.T.INT64, i })]] }, cols);
    const done = (status: string) => w.encodeServer({ type: 66, done: { status, count: 1n, read: null, write: null } });
    const ready = w.encodeServer({ type: 71, state: 0 });
    let q = 0;
    let held: net.Socket | null = null;
    const path = TMP + '/fake-seq.sock';
    await fakeServer(path, () => undefined, (s, type) => {
        if (type === w.F.PING) {
            s.write(w.encodeEmpty(w.F.PONG)); /* between the first QUERY's COLUMNS and its ROWS */
            if (held) {
                held.write(Buffer.concat([row(1n), row(2n), w.encodeServer({ type: 68, message: 'w1' }), done('SELECT 2'), ready]));
                held = null;
            }
            return;
        }
        if (type !== w.F.QUERY) return;
        q++;
        if (q === 1) {
            s.write(w.encodeServer({ type: 64, columns: cols }));
            held = s;
        } else if (q === 2) {
            s.write(Buffer.concat([w.encodeServer({ type: 64, columns: cols }), row(7n), w.encodeServer({ type: 68, message: 'w2' }),
                w.encodeServer({ type: 67, code: 15, index: 0, message: 'cancelled' }), ready]));
        } else if (q === 3) {
            s.write(Buffer.concat([done('SELECT 1'), ready])); /* a batch of two answered by one DONE */
        } else if (q === 4) { /* one ROWS frame of 1,000,000 one-byte NULLs (§4 lets a frame hold 16 MiB) */
            const n = 1000000, f = Buffer.alloc(5 + 4 + n, 0x81);
            f.writeUInt32LE(1 + 4 + n, 0);
            f[4] = w.F.ROWS;
            f.writeUInt32LE(n, 5);
            s.write(Buffer.concat([w.encodeServer({ type: 64, columns: cols }), f, done('SELECT 1000000'), ready]));
        } else {
            s.write(Buffer.concat([w.encodeServer({ type: 64, columns: cols }), row(9n), done('SELECT 1'), ready]));
        }
    });
    const c = await open({ socket: path }, { user: 'u', password: 'pw-fake' });
    const first = c.query('SELECT n');
    await sleep(50);
    await c.ping();
    const r1 = await first;
    assert.deepStrictEqual([r1.rows, r1.warnings, r1.status], [[[1n], [2n]], ['w1'], 'SELECT 2']);
    const e2 = await rejectsWith(c.query('SELECT n'), ServerError);
    assert.deepStrictEqual([e2.code, e2.index, e2.warnings, e2.results.length, e2.state], [15, 0, ['w2'], 0, 'idle']);
    const e3 = await rejectsWith(c.batch(['SELECT 1', 'SELECT 2']), ServerError);
    assert.deepStrictEqual([e3.code, e3.index, e3.results.length], [ERR.STATE, 1, 1]);
    const nulls = await c.query('SELECT n');
    assert.ok(nulls.rows.length === 1000000 && nulls.rows[0][0] === null && nulls.rows[999999][0] === null);
    assert.deepStrictEqual((await c.query('SELECT n')).rows, [[9n]]); /* the connection goes on */
});

test('a server stopped (B, by its PID): the plain close, no reason, on the next call', { timeout: 90000 }, async () => {
    const c = await open({ host: '127.0.0.2', port: B.port, pin: B.pin }, cred);
    await c.ping();
    const closed = new Promise<ClosedError>((r) => c.once('close', r));
    process.kill(B.pid, 'SIGTERM');
    const ce = await closed;
    assert.strictEqual(ce.reason, null);
    const e = await rejectsWith(c.query('SELECT 1'), ClosedError);
    assert.deepStrictEqual([e.code, e.reason], [ERR.IO, null]);
});

test('the end: every client a test opened destroyed, every fake server closed (none holds the run open)', { timeout: 90000 }, async () => {
    for (const c of opened) c.destroy();
    for (const s of fakes) s.close();
});
