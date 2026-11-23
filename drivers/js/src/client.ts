/* The driver's client: a connection over the server's Unix-domain socket or TCP with TLS 1.3, its SCRAM-SHA-256 login,
 * and the requests of IMDBWIR1 (docs/n1-design.md §4) as promises. Requests pipeline: each is written whole, in order,
 * and its replies are read in order; the out-of-turn answers (PONG, SESSIONS_LIST, KILL_DONE) are matched to their own
 * askers, wherever they fall among a request's replies. Node's sockets read and write independently, so cancel() writes
 * CANCEL in band at once, between two whole frames. */
import * as crypto from 'crypto';
import { EventEmitter } from 'events';
import * as fs from 'fs';
import * as net from 'net';
import * as tls from 'tls';
import { AuthError, ClosedError, ERR, ImdbError, ProtocolError, ServerError, TxState } from './errors';
import { passwordBytes, scramClient } from './scram';
import { fromWire, Param, toWire, Value } from './types';
import {
    authMessage, CB, CHALLENGE_LEN, COPY_PIECE, decodeChallenge, decodeServer, decodeVerdict, DoneMsg, encodeCopyData,
    encodeCopyFail, encodeDeallocate, encodeEmpty, encodeExecute, encodeHello, encodeKill, encodePrepare, encodeQuery, EP, F,
    FRAME_NAMES, FrameReader, KEY, KILL_KIND, MESSAGE_MAX, PREAUTH_HEAD, preauthHead, ReadPoint, ServerMsg, textBytes,
    TYPE_NAMES, TypeName, userOk, utf8Fit, VERDICT, VERDICT_LEN, wellFormed, WireColumn, WritePoint,
} from './wire';

/* ---- options ---- */

export interface SocketOptions {
    socket: string; /* the server's Unix-domain socket */
    connectTimeoutMs?: number;
}
export interface TcpOptions {
    host: string;
    port: number;
    /* exactly one: the CA's certificate (PEM: ca.crt's contents, or caFile its path), the host then checked against the
     * server certificate's names; or the pin, the server key's SPKI SHA-256 (64 hex digits, as `cert` prints it, or 32
     * bytes). No unverified mode exists: neither, or both, is refused */
    ca?: string | Buffer;
    caFile?: string;
    pin?: string | Uint8Array;
    /* the login's channel binding (§8f): the TLS exporter (RFC 9266), the default, which a default server requires; or
     * tls-server-end-point (RFC 5929: the SHA-256 of the server certificate's DER), taken only by a server run with
     * --channel-binding any. One is offered; a refusal is never retried with the other (no downgrade) */
    channelBinding?: 'tls-exporter' | 'tls-server-end-point';
    connectTimeoutMs?: number;
}
export type ConnectOptions = SocketOptions | TcpOptions;
export interface Credentials {
    user: string; /* a role's name: 1 to 63 bytes of UTF-8 */
    password: string | Uint8Array; /* 1 to 1,024 printable ASCII bytes, as CREATE ROLE takes one */
}

/* ---- results ---- */

export interface Column {
    name: string;
    type: TypeName; /* NONE: the statement does not know it (each value carries its own) */
    typeId: number;
    precision: number; /* DECIMAL's digits (0: not known, 38), INT64's width (0, 16, 32), a VARCHAR's length (0: none) */
    scale: number;
    labels: string[] | null; /* an ENUM's labels, in the type's order, as its read point sees them */
}
export type Row = Value[];
export interface Done {
    status: string;
    count: bigint; /* the rows returned or written */
    read: ReadPoint | null; /* the engine's read point: the commit, its hash, the state digest, the lake's, the db's id */
    write: WritePoint | null; /* the statement's own commit and its hash */
}
export type { ReadPoint, WritePoint };

export class StatementResult {
    readonly columns: Column[] | null; /* null: the statement returns no rows */
    readonly rows: Row[];
    readonly done: Done;
    readonly warnings: string[];
    readonly copyOut: Buffer | null; /* a COPY ... TO STDOUT's bytes, when no sink took them */
    constructor(columns: Column[] | null, rows: Row[], done: Done, warnings: string[], copyOut: Buffer | null) {
        this.columns = columns;
        this.rows = rows;
        this.done = done;
        this.warnings = warnings;
        this.copyOut = copyOut;
    }
    get status(): string {
        return this.done.status;
    }
    get count(): bigint {
        return this.done.count;
    }
    /* each row as an object by column name (a name twice: its last column wins) */
    objects(): { [name: string]: Value }[] {
        const cols = this.columns ?? [];
        return this.rows.map((r) => {
            const o: { [name: string]: Value } = {};
            cols.forEach((c, i) => (o[c.name] = r[i]));
            return o;
        });
    }
}
export class QueryResult extends StatementResult {
    readonly state: TxState; /* READY's: idle, in a transaction, or in a doomed one (it takes only ROLLBACK) */
    constructor(r: StatementResult, state: TxState) {
        super(r.columns, r.rows, r.done, r.warnings, r.copyOut);
        this.state = state;
    }
}
export interface BatchResult {
    results: StatementResult[];
    state: TxState;
}
export interface SessionInfo {
    id: bigint; /* a counter given at its connection's accept, never reused */
    role: number;
    endpoint: 'tcp' | 'socket';
    state: 'idle' | 'running' | 'transaction' | 'copy';
    ageMs: bigint;
    name: string; /* its role's name now ("" once the role is gone) */
}
export type BatchItem = string | { sql: string; params?: Param[] };
export type CopyChunk = Uint8Array | string;
export type CopySource = CopyChunk | Iterable<CopyChunk> | AsyncIterable<CopyChunk>;
/* a Writable stream, or anything with its write/once (removeListener used when there) */
export interface WritableLike {
    write(chunk: Buffer): boolean;
    once(event: 'drain' | 'close' | 'error', fn: (e?: unknown) => void): unknown;
    removeListener?(event: 'drain' | 'close' | 'error', fn: (e?: unknown) => void): unknown;
}
export type CopySink = WritableLike | ((chunk: Buffer) => void | Promise<void>);

const STATES: TxState[] = ['idle', 'transaction', 'doomed'];
const SESS_STATES: SessionInfo['state'][] = ['idle', 'running', 'transaction', 'copy'];

interface Cur {
    wcols: WireColumn[] | null;
    columns: Column[] | null;
    rows: Row[];
    warnings: string[];
    copy: Buffer[] | null;
}
interface Req {
    type: number;
    frame: Buffer;
    n: number; /* statements, or parameter sets */
    copyish: boolean; /* a statement may be a COPY ... FROM STDIN: nothing but CANCEL and PING after it until it ends */
    source?: CopySource;
    sink?: CopySink;
    results: StatementResult[];
    cur: Cur | null;
    error: ServerError | null;
    onError: (() => void) | null;
    sawCopyIn: boolean;
    copyEnded: boolean;
    ready: boolean;
    state: TxState;
    settled: boolean;
    sinkFailure: unknown;
    sinkUnhook?: () => void; /* a Writable sink: its close and error listeners removed */
    sinkUnheld?: () => void; /* a Writable sink in backpressure: its drain listener removed, the reading let go */
    resolve: (v: BatchResult) => void;
    reject: (e: unknown) => void;
}
interface Deferred<T> {
    resolve: (v: T) => void;
    reject: (e: unknown) => void;
}
type Item =
    | { k: 'req'; req: Req }
    | { k: 'sessions'; frame: Buffer; d: Deferred<SessionInfo[]> }
    | { k: 'kill'; frame: Buffer; sid: bigint; d: Deferred<boolean> }
    | { k: 'terminate' };

/* a statement that may be a COPY ... FROM STDIN: its first word COPY, after spaces and comments (the server asks for
 * data only for one, so the guess errs one way: a COPY TO is held to the same rule, which costs only pipelining) */
export function mayBeCopy(sql: string): boolean {
    let i = 0;
    for (;;) {
        while (i < sql.length && /\s/.test(sql[i])) i++;
        if (sql.startsWith('--', i)) {
            const e = sql.indexOf('\n', i);
            if (e < 0) return false;
            i = e + 1;
            continue;
        }
        if (sql.startsWith('/*', i)) {
            const e = sql.indexOf('*/', i + 2);
            if (e < 0) return true; /* unsure: hold the line */
            i = e + 2;
            continue;
        }
        break;
    }
    return /^copy(?![A-Za-z0-9_$])/i.test(sql.slice(i, i + 5));
}

function toColumn(c: WireColumn): Column {
    return { name: c.name, type: TYPE_NAMES[c.type], typeId: c.type, precision: c.precision, scale: c.scale, labels: c.labels };
}

/* a COPY_FAIL's reason from an error: UTF-8 without NUL, cut at a character within 4,096 bytes */
function failText(e: unknown): Buffer {
    const s = e instanceof Error ? e.message : String(e);
    const b = Buffer.from(s.replace(/[\uD800-\uDFFF]/g, '?'), 'utf8');
    return b.subarray(0, utf8Fit(b, MESSAGE_MAX));
}

function chunkBytes(c: CopyChunk): Buffer {
    if (typeof c === 'string') { /* COPY's data is raw bytes (the server's reader judges them): only a string with no
                                  * UTF-8 form, a lone surrogate, is refused here (Buffer.from would write U+FFFD) */
        if (!wellFormed(c)) throw new ProtocolError(ERR.INVALID, 'COPY data: a string with a lone surrogate (it has no UTF-8 form)');
        return Buffer.from(c, 'utf8');
    }
    if (c instanceof Uint8Array) return Buffer.isBuffer(c) ? c : Buffer.from(c);
    throw new ProtocolError(ERR.INVALID, 'COPY data: chunks are strings or bytes');
}

function asAsyncIterator(src: CopySource): AsyncIterator<CopyChunk> {
    if (typeof src === 'string' || src instanceof Uint8Array) {
        let done = false;
        return { next: async () => (done ? { done: true, value: undefined } : ((done = true), { done: false, value: src })) };
    }
    const a = (src as AsyncIterable<CopyChunk>)[Symbol.asyncIterator];
    if (typeof a === 'function') return a.call(src);
    const s = (src as Iterable<CopyChunk>)[Symbol.iterator];
    if (typeof s === 'function') {
        const it = s.call(src);
        return { next: async () => it.next(), return: async () => (it.return ? it.return() : { done: true, value: undefined }) };
    }
    throw new ProtocolError(ERR.INVALID, 'COPY data: a string, bytes, or an (async) iterable of them');
}

function isWritable(s: CopySink): s is WritableLike {
    return typeof s === 'object' && s !== null && typeof (s as WritableLike).write === 'function';
}

export class Client extends EventEmitter {
    private sock: net.Socket;
    private fr = new FrameReader(true);
    private mode: 'auth' | 'frames' = 'auth';
    private waiter: { n: number; resolve: (b: Buffer) => void; reject: (e: unknown) => void } | null = null;
    private inflight: Req[] = [];
    private queue: Item[] = [];
    private gate: Req | null = null;
    private pongs: Deferred<void>[] = [];
    private sessQ: Deferred<SessionInfo[]>[] = [];
    private killQ: { sid: bigint; d: Deferred<boolean> }[] = [];
    private holds = 0;
    private lastError: ServerError | null = null; /* the last frame read, when it was an ERROR (closed_reason's rule) */
    private cause: Error | null = null;
    private closing = false;
    private closedBy: 'client' | null = null;
    private finished: ClosedError | null = null;
    private closeWaiters: (() => void)[] = [];
    /* the session's state by the last READY */
    state: TxState = 'idle';
    readonly endpoint: 'tcp' | 'socket';

    /* use connect() */
    constructor(sock: net.Socket, endpoint: 'tcp' | 'socket') {
        super();
        this.sock = sock;
        this.endpoint = endpoint;
        sock.on('data', (b: Buffer) => this.onData(b));
        sock.on('error', (e: Error) => {
            if (!this.cause) this.cause = e;
        });
        sock.on('close', () => this.finish());
    }

    /* ---- the login ---- */

    private onData(b: Buffer): void {
        this.fr.push(b);
        if (this.mode === 'auth') {
            const w = this.waiter;
            if (w && this.fr.available() >= w.n) {
                this.waiter = null;
                w.resolve(this.fr.take(w.n)!);
            }
            return;
        }
        this.pump();
    }

    private readExact(n: number): Promise<Buffer> {
        if (this.finished) return Promise.reject(this.finished);
        const b = this.fr.take(n);
        if (b) return Promise.resolve(b);
        return new Promise((resolve, reject) => (this.waiter = { n, resolve, reject }));
    }

    /* the pre-auth exchange (§4): the hello, the challenge, the proof over the AuthMessage, the verdict and the server's
     * signature checked: a server that cannot prove it holds the verifier is refused */
    async authenticate(endpoint: number, cbType: number, binding: Buffer, user: Buffer, password: string | Uint8Array): Promise<void> {
        const nonce = crypto.randomBytes(32);
        const hello = encodeHello({ version: 1, flags: cbType, user, nonce });
        this.sock.write(hello);
        const head = await this.readExact(PREAUTH_HEAD);
        const version = preauthHead(head);
        if (version !== 1) throw new ImdbError(ERR.UNSUPPORTED, 'the server speaks IMDBWIR1 version ' + version + ', not 1');
        const chb = Buffer.concat([head, await this.readExact(CHALLENGE_LEN - PREAUTH_HEAD)]);
        const ch = decodeChallenge(chb);
        const am = authMessage(endpoint, hello, chb, binding);
        const { proof, serverSig } = await scramClient(password, ch, am);
        this.sock.write(proof);
        const v = decodeVerdict(await this.readExact(VERDICT_LEN));
        try {
            if (v.code === VERDICT.BINDING) /* never retried with another type: no downgrade (§8f) */
                throw new AuthError("the server refuses this login's channel binding type" +
                    (cbType === CB.ENDPOINT ? ' (tls-server-end-point: the server takes it only with --channel-binding any)' : ''));
            if (v.code !== VERDICT.OK) throw new AuthError('authentication refused');
            if (!crypto.timingSafeEqual(v.sig, serverSig)) throw new AuthError('the server did not prove it holds the verifier');
        } finally {
            proof.fill(0);
            serverSig.fill(0);
        }
        this.mode = 'frames';
        this.pump(); /* frames the server sent at once (an ERROR for a bound, then its close) */
    }

    /* ---- requests ---- */

    /* one statement, its $1..$n */
    async query(sql: string, params: Param[] = []): Promise<QueryResult> {
        const r = await this.request(F.QUERY, encodeQuery([{ sql, params: params.map(toWire) }]), 1, mayBeCopy(sql));
        return new QueryResult(r.results[0], r.state);
    }

    /* several statements in one request, run in order: an ERROR ends the batch (its index the statement's); each
     * commits on its own unless inside BEGIN ... COMMIT (a batch is not a transaction) */
    async batch(items: BatchItem[]): Promise<BatchResult> {
        const stmts = items.map((x) => (typeof x === 'string' ? { sql: x, params: [] as Param[] } : { sql: x.sql, params: x.params ?? [] }));
        const frame = encodeQuery(stmts.map((s) => ({ sql: s.sql, params: s.params.map(toWire) })));
        return this.request(F.QUERY, frame, stmts.length, stmts.some((s) => mayBeCopy(s.sql)));
    }

    /* PREPARE: its parameters typed at each EXECUTE */
    async prepare(name: string, sql: string): Promise<QueryResult> {
        const r = await this.request(F.PREPARE, encodePrepare(name, sql), 1, false);
        return new QueryResult(r.results[0], r.state);
    }

    /* EXECUTE of several parameter sets, run in order: one result each; an ERROR's index is its set's */
    async execute(name: string, sets: Param[][] = [[]]): Promise<BatchResult> {
        if (!sets.length) sets = [[]];
        const nvals = sets[0].length;
        const frame = encodeExecute(name, nvals, sets.map((s) => s.map(toWire)));
        return this.request(F.EXECUTE, frame, sets.length, false);
    }

    async deallocate(name: string): Promise<QueryResult> {
        const r = await this.request(F.DEALLOCATE, encodeDeallocate(name), 1, false);
        return new QueryResult(r.results[0], r.state);
    }

    /* COPY ... FROM STDIN: the statement, then its data from source once the server asks (COPY_IN), cut into frames of at
     * most 1 MiB, then COPY_DONE; a source that throws ends it with COPY_FAIL (the statement refused, unrun). An ERROR
     * before the end stops the data (COPY_DONE still sent, §4); one before any COPY_IN sends nothing */
    async copyFrom(sql: string, source: CopySource): Promise<QueryResult> {
        const r = await this.request(F.QUERY, encodeQuery([{ sql, params: [] }]), 1, true, source);
        return new QueryResult(r.results[0], r.state);
    }

    /* COPY ... TO STDOUT: each COPY_OUT piece to sink (a Writable's backpressure, or a function's promise, holds the
     * reading); a sink that throws cancels the statement and the call rejects with its error */
    async copyTo(sql: string, sink: CopySink): Promise<QueryResult> {
        const r = await this.request(F.QUERY, encodeQuery([{ sql, params: [] }]), 1, mayBeCopy(sql), undefined, sink);
        return new QueryResult(r.results[0], r.state);
    }

    /* PING: answered out of turn by the server's connection thread (PONG), during a request too */
    ping(): Promise<void> {
        if (this.finished || this.closing) return Promise.reject(this.closedError());
        return new Promise((resolve, reject) => {
            this.pongs.push({ resolve, reject });
            this.sock.write(encodeEmpty(F.PING));
        });
    }

    /* SESSIONS: a superuser's every session, a role's its own role's (answered out of turn) */
    sessions(): Promise<SessionInfo[]> {
        if (this.finished || this.closing) return Promise.reject(this.closedError());
        const frame = encodeEmpty(F.SESSIONS);
        return new Promise((resolve, reject) => {
            this.queue.push({ k: 'sessions', frame, d: { resolve, reject } });
            this.flush();
        });
    }

    /* KILL a session by its id: cancel what it runs (each statement of its request), or terminate it (its transaction
     * rolled back). true: done; false: no such session (or another role's, to a role that is not a superuser) */
    kill(id: bigint | number, kind: 'cancel' | 'terminate' = 'cancel'): Promise<boolean> {
        if (this.finished || this.closing) return Promise.reject(this.closedError());
        const sid = BigInt(id);
        const frame = encodeKill(kind === 'terminate' ? KILL_KIND.TERMINATE : KILL_KIND.CANCEL, sid);
        return new Promise((resolve, reject) => {
            this.queue.push({ k: 'kill', frame, sid, d: { resolve, reject } });
            this.flush();
        });
    }

    /* CANCEL the statement running now for this connection, in band; callable while a request is pending. It cancels
     * the statement running when it arrives (an earlier request's, when several are pipelined), never one queued behind
     * it, and nothing outside a statement. One asked while no request of this client's is outstanding is dropped (§4: it
     * would cancel the next). true when sent */
    cancel(): boolean {
        if (this.finished || !this.inflight.length) return false;
        this.sock.write(encodeEmpty(F.CANCEL));
        return true;
    }

    /* TERMINATE once the requests before it are answered; resolves when the server has closed the connection */
    close(): Promise<void> {
        if (this.finished) return Promise.resolve();
        const p = new Promise<void>((resolve) => this.closeWaiters.push(resolve));
        if (!this.closing) {
            this.closing = true;
            this.queue.push({ k: 'terminate' });
            this.flush();
        }
        return p;
    }

    /* the connection dropped at once: every pending call rejected */
    destroy(): void {
        if (this.finished) return;
        this.closedBy = 'client';
        this.sock.destroy();
    }

    /* tests: bytes written as they are (crafted frames) */
    sendRaw(b: Uint8Array): void {
        this.sock.write(Buffer.from(b));
    }

    get closed(): boolean {
        return this.finished !== null;
    }
    /* requests written whose READY has not been read */
    get outstanding(): number {
        return this.inflight.length;
    }

    private closedError(): ClosedError {
        if (this.finished) return this.finished;
        return new ClosedError('the connection is closing (close() was called)', null);
    }

    private request(type: number, frame: Buffer, n: number, copyish: boolean, source?: CopySource, sink?: CopySink): Promise<BatchResult> {
        if (this.finished || this.closing) return Promise.reject(this.closedError());
        return new Promise((resolve, reject) => {
            const req: Req = {
                type, frame, n, copyish, source, sink, results: [], cur: null, error: null, onError: null, sawCopyIn: false,
                copyEnded: false, ready: false, state: 'idle', settled: false, sinkFailure: undefined, resolve, reject,
            };
            this.queue.push({ k: 'req', req });
            this.flush();
        });
    }

    /* the queue written in order while no COPY ... FROM STDIN holds the line (§4: after such a statement nothing but
     * CANCEL and PING until its COPY_IN, then its data and its end) */
    private flush(): void {
        while (!this.finished && !this.gate && this.queue.length) {
            const it = this.queue.shift()!;
            switch (it.k) {
                case 'req':
                    this.inflight.push(it.req);
                    this.sock.write(it.req.frame);
                    if (it.req.copyish) this.gate = it.req;
                    break;
                case 'sessions':
                    this.sessQ.push(it.d);
                    this.sock.write(it.frame);
                    break;
                case 'kill':
                    this.killQ.push({ sid: it.sid, d: it.d });
                    this.sock.write(it.frame);
                    break;
                case 'terminate':
                    this.sock.write(encodeEmpty(F.TERMINATE));
                    break;
            }
        }
    }

    private release(req: Req): void {
        if (this.gate === req && req.ready && (!req.sawCopyIn || req.copyEnded)) {
            this.gate = null;
            this.flush();
        }
    }

    /* ---- replies ---- */

    private pump(): void {
        while (!this.finished && this.holds === 0 && this.mode === 'frames') {
            let f: { type: number; body: Buffer } | null;
            try {
                f = this.fr.next();
            } catch (e) {
                this.fail(e instanceof ProtocolError ? new ProtocolError(e.code, 'a frame refused, the connection closed: ' + e.message) : e);
                return;
            }
            if (!f) return;
            try {
                this.onFrame(f.type, f.body);
            } catch (e) { /* anything thrown here ends the connection, never the process: every pending call rejected */
                const what = 'a ' + (FRAME_NAMES[f.type] ?? 'frame') + ' frame';
                this.fail(e instanceof ImdbError ? new ProtocolError(e.code, what + ' refused, the connection closed: ' + e.message)
                    : new ProtocolError(ERR.STATE, what + ' could not be taken, the connection closed: ' + (e instanceof Error ? e.message : String(e))));
                return;
            }
        }
    }

    private bad(what: string): never {
        throw new ProtocolError(ERR.CORRUPT, what);
    }

    private onFrame(type: number, body: Buffer): void {
        const head = this.inflight[0];
        const cols = type === F.ROWS && head && head.cur ? head.cur.wcols : null;
        const m: ServerMsg = decodeServer(type, body, cols);
        this.lastError = null;
        switch (m.type) {
            case 72: {
                const d = this.pongs.shift();
                if (!d) this.bad('a PONG no PING asked for');
                d.resolve();
                return;
            }
            case 73: {
                const d = this.sessQ.shift();
                if (!d) this.bad('a SESSIONS_LIST no SESSIONS asked for');
                d.resolve(m.sessions.map((s) => ({
                    id: s.id, role: s.role, endpoint: s.endpoint === 1 ? 'tcp' : 'socket', state: SESS_STATES[s.state], ageMs: s.ageMs, name: s.name,
                })));
                return;
            }
            case 74: {
                const k = this.killQ.shift();
                if (!k || k.sid !== m.sid) this.bad('a KILL_DONE no KILL of that session asked for');
                k.d.resolve(m.code === 0);
                return;
            }
        }
        const req = head;
        if (!req) {
            if (m.type === 67) { /* unasked: a refusal before the server's close (a bound, a protocol error, a KILL) */
                this.lastError = new ServerError(m.code, m.index, m.message);
                return;
            }
            this.bad('a reply with no request outstanding');
        }
        if (req.error && m.type !== 71) this.bad("a reply after its request's ERROR but READY");
        switch (m.type) {
            case 64:
                if (req.cur && (req.cur.columns || req.cur.copy)) this.bad('a second COLUMNS before its statement ended');
                req.cur = req.cur ?? this.newCur();
                req.cur.wcols = m.columns;
                req.cur.columns = m.columns.map(toColumn);
                return;
            case 65: /* decoded against this statement's COLUMNS (cols above) */
                for (const r of m.rows) req.cur!.rows.push(r.map(fromWire)); /* a loop: a frame may hold millions (never spread) */
                return;
            case 68:
                (req.cur = req.cur ?? this.newCur()).warnings.push(m.message);
                return;
            case 66: {
                const c = req.cur ?? this.newCur();
                req.cur = null;
                if (req.results.length >= req.n) this.bad('more DONEs than the request has statements');
                const copy = c.copy ? Buffer.concat(c.copy) : null;
                req.results.push(new StatementResult(c.columns, c.rows, this.done(m.done), c.warnings, copy));
                return;
            }
            case 67: {
                const e = new ServerError(m.code, m.index, m.message);
                e.warnings = req.cur ? req.cur.warnings : [];
                e.results = req.results;
                req.error = e;
                req.cur = null; /* rows before an ERROR are not the statement's answer (§4) */
                this.lastError = e;
                const on = req.onError;
                req.onError = null;
                if (on) on();
                return;
            }
            case 69:
                if (req.type !== F.QUERY || (req.cur && (req.cur.columns || req.cur.copy)) || (req.sawCopyIn && !req.copyEnded))
                    this.bad('a COPY_IN this request cannot take');
                req.sawCopyIn = true;
                req.copyEnded = false;
                if (req.source !== undefined) {
                    const src = req.source;
                    req.source = undefined; /* one source, one COPY */
                    void this.upload(req, src);
                } else { /* query() or batch(): no data to give; the statement refused unrun, the line released */
                    this.sock.write(encodeCopyFail(Buffer.from('this COPY ... FROM STDIN was sent without data (the driver gives data through copyFrom)')));
                    req.copyEnded = true;
                }
                return;
            case 70:
                if (req.type !== F.QUERY || (req.cur && req.cur.columns)) this.bad('a COPY_OUT this request cannot take');
                req.cur = req.cur ?? this.newCur();
                if (req.sink && req.sinkFailure === undefined) this.deliver(req, Buffer.from(m.data));
                else if (!req.sink) (req.cur.copy = req.cur.copy ?? []).push(Buffer.from(m.data));
                return;
            case 71: {
                if (req.cur) this.bad('a READY inside a statement (no DONE or ERROR)');
                if (!req.error && req.results.length !== req.n) {
                    /* the server stopping mid-batch ends a request so (srv.c run: its statements not run, no ERROR) */
                    const e = new ServerError(ERR.STATE, req.results.length, 'the server ended the request after ' + req.results.length +
                        ' of its ' + req.n + ' statements: the rest did not run');
                    e.results = req.results;
                    req.error = e;
                }
                this.inflight.shift();
                this.state = req.state = STATES[m.state];
                req.ready = true;
                this.settle(req);
                this.release(req);
                return;
            }
        }
    }

    private newCur(): Cur {
        return { wcols: null, columns: null, rows: [], warnings: [], copy: null };
    }

    private done(d: DoneMsg): Done {
        return { status: d.status, count: d.count, read: d.read, write: d.write };
    }

    /* a request settles once its READY is read and, when the server asked for COPY data, its end is written */
    private settle(req: Req): void {
        if (req.settled || !req.ready || (req.sawCopyIn && !req.copyEnded)) return;
        req.settled = true;
        if (req.sinkUnhook) req.sinkUnhook(); /* the sink is the caller's again: none of our listeners left on it */
        if (req.sinkFailure !== undefined) return req.reject(req.sinkFailure);
        if (req.error) {
            req.error.state = req.state;
            return req.reject(req.error);
        }
        req.resolve({ results: req.results, state: req.state });
    }

    private drained(): Promise<void> {
        if (this.finished) return Promise.resolve();
        return new Promise((resolve) => {
            const done = () => {
                this.sock.off('drain', done);
                this.sock.off('close', done);
                resolve();
            };
            this.sock.once('drain', done);
            this.sock.once('close', done);
        });
    }

    /* COPY's data: each chunk while no ERROR came and the connection holds, then COPY_DONE (or COPY_FAIL with the source's
     * error); an ERROR arriving while the source is still producing ends the wait at once */
    private async upload(req: Req, src: CopySource): Promise<void> {
        let it: AsyncIterator<CopyChunk> | null = null;
        let failure: unknown = undefined;
        const errored = new Promise<'error'>((resolve) => {
            if (req.error) resolve('error');
            else req.onError = () => resolve('error');
        });
        try {
            it = asAsyncIterator(src);
            for (;;) {
                if (req.error || this.finished) break;
                const r = await Promise.race([it.next(), errored]);
                if (r === 'error' || this.finished) {
                    const ret = it.return;
                    if (ret) void Promise.resolve(ret.call(it)).catch(() => undefined);
                    it = null;
                    break;
                }
                if (r.done) {
                    it = null;
                    break;
                }
                const b = chunkBytes(r.value);
                for (let off = 0; off < b.length && !req.error && !this.finished; off += COPY_PIECE) {
                    if (!this.sock.write(encodeCopyData(b.subarray(off, off + COPY_PIECE)))) await this.drained();
                }
            }
        } catch (e) {
            failure = e;
            if (it && it.return) void Promise.resolve(it.return()).catch(() => undefined);
        }
        req.onError = null;
        if (!this.finished) this.sock.write(failure === undefined ? encodeEmpty(F.COPY_DONE) : encodeCopyFail(failText(failure)));
        req.copyEnded = true;
        if (failure !== undefined && req.error) (req.error as { cause?: unknown }).cause = failure;
        this.settle(req);
        this.release(req);
    }

    private hold(): void {
        if (this.holds++ === 0) this.sock.pause();
    }
    private unhold(): void {
        if (--this.holds === 0) {
            this.sock.resume();
            this.pump();
        }
    }

    /* a COPY_OUT piece to its sink, the reading held while the sink is busy */
    private sinkFailed(req: Req, e: unknown): void {
        if (req.sinkFailure !== undefined) return;
        req.sinkFailure = e === undefined ? new Error('the COPY sink failed') : e;
        if (req.sinkUnheld) req.sinkUnheld(); /* a reading held for its drain: let go */
        this.cancel(); /* the rest of the output dropped; the statement ends cancelled */
    }

    private deliver(req: Req, data: Buffer): void {
        const sink = req.sink!;
        try {
            if (isWritable(sink)) {
                if (!req.sinkUnhook) { /* once a request: its error or close ends the COPY (never an unheard 'error') */
                    const onClose = () => this.sinkFailed(req, new Error('the COPY sink closed before the output ended'));
                    const onError = (e?: unknown) => this.sinkFailed(req, e ?? new Error('the COPY sink failed'));
                    sink.once('close', onClose);
                    sink.once('error', onError);
                    req.sinkUnhook = () => {
                        if (sink.removeListener) {
                            sink.removeListener('close', onClose);
                            sink.removeListener('error', onError);
                        }
                    };
                }
                if ((sink as { destroyed?: boolean }).destroyed) return this.sinkFailed(req, new Error('the COPY sink is destroyed'));
                if (!sink.write(data)) { /* its backpressure: the reading held until it drains */
                    this.hold();
                    const onDrain = () => {
                        if (req.sinkUnheld) req.sinkUnheld();
                    };
                    req.sinkUnheld = () => {
                        req.sinkUnheld = undefined;
                        if (sink.removeListener) sink.removeListener('drain', onDrain);
                        this.unhold();
                    };
                    sink.once('drain', onDrain);
                }
                return;
            }
            const r = sink(data);
            if (r && typeof (r as Promise<void>).then === 'function') {
                this.hold();
                (r as Promise<void>).then(() => this.unhold(), (e) => {
                    this.sinkFailed(req, e);
                    this.unhold();
                });
            }
        } catch (e) {
            this.sinkFailed(req, e);
        }
    }

    /* ---- the end ---- */

    /* a frame refused: the connection ends, every pending call rejected with the error naming it */
    private fail(e: unknown): void {
        if (!this.cause) this.cause = e instanceof Error ? e : new Error(String(e));
        this.protocolError = e;
        this.sock.destroy();
        this.finish();
    }
    private protocolError: unknown = null;

    private finish(): void {
        if (this.finished) return;
        const reason = this.protocolError ? null : this.lastError;
        let msg: string;
        if (this.protocolError) msg = 'the connection ended: ' + (this.protocolError as Error).message;
        else if (reason) msg = 'the server closed the connection: ' + reason.message;
        else if (this.closedBy === 'client') msg = 'the connection is closed (by the client)';
        else if (this.closing) msg = 'the connection is closed (close() was called)';
        else msg = 'the connection: ' + (this.cause ? (this.cause as Error).message : 'closed by the server');
        const ce = new ClosedError(msg, reason);
        if (this.cause) (ce as { cause?: unknown }).cause = this.cause;
        this.finished = ce;
        const perr = this.protocolError;
        if (this.waiter) {
            this.waiter.reject(perr ?? ce);
            this.waiter = null;
        }
        for (const req of this.inflight) {
            if (req.sinkUnhook) req.sinkUnhook();
            if (req.settled) continue;
            req.settled = true;
            req.reject(perr ?? req.error ?? ce); /* a request its ERROR answered (a KILL's, a refusal's): that ERROR */
        }
        this.inflight = [];
        for (const it of this.queue) {
            if (it.k === 'req') it.req.reject(ce);
            else if (it.k !== 'terminate') it.d.reject(ce);
        }
        this.queue = [];
        for (const d of this.pongs) d.reject(perr ?? ce);
        for (const d of this.sessQ) d.reject(perr ?? ce);
        for (const k of this.killQ) k.d.reject(perr ?? ce);
        this.pongs = [];
        this.sessQ = [];
        this.killQ = [];
        this.gate = null;
        for (const w of this.closeWaiters) w();
        this.closeWaiters = [];
        this.emit('close', ce);
    }
}

/* ---- connecting ---- */

const SOCKET_KEYS = ['socket', 'connectTimeoutMs'];
const TCP_KEYS = ['host', 'port', 'ca', 'caFile', 'pin', 'channelBinding', 'connectTimeoutMs'];

function pinBytes(pin: string | Uint8Array): Buffer {
    if (typeof pin === 'string') {
        if (!/^[0-9a-fA-F]{64}$/.test(pin)) throw new ProtocolError(ERR.INVALID, "a pin is the server key's SPKI SHA-256: 64 hex digits");
        return Buffer.from(pin, 'hex');
    }
    if (pin.length !== 32) throw new ProtocolError(ERR.INVALID, "a pin is the server key's SPKI SHA-256: 32 bytes");
    return Buffer.from(pin);
}

function ioError(e: unknown, what: string): ImdbError {
    if (e instanceof ImdbError) return e;
    const err = e as { message?: string; syscall?: string; code?: string };
    if (err && (err.syscall || err.code === 'ECONNRESET' || err.code === 'EPIPE')) return new ImdbError(ERR.IO, what + ': ' + err.message);
    return new AuthError('TLS: ' + (err && err.message ? err.message : String(e))); /* the handshake or the certificate */
}

/* a connected, logged-in client. {socket} | {host, port, ca | caFile | pin}, and the role's name and password */
export async function connect(opts: ConnectOptions, cred: Credentials): Promise<Client> {
    if (!opts || typeof opts !== 'object' || !cred || typeof cred !== 'object') throw new TypeError('connect(options, { user, password })');
    const user = typeof cred.user === 'string' ? textBytes(cred.user) : null;
    if (!user || !userOk(user)) throw new ProtocolError(ERR.INVALID, "a role's name is 1 to 63 bytes of UTF-8");
    passwordBytes(cred.password).fill(0); /* checked before any byte leaves */
    const tcp = 'host' in opts || 'port' in opts;
    const keys = tcp ? TCP_KEYS : SOCKET_KEYS;
    for (const k of Object.keys(opts)) if (!keys.includes(k)) throw new TypeError('connect: no option ' + JSON.stringify(k) + (tcp ? ' on TCP' : ' on the socket'));
    const timeoutMs = opts.connectTimeoutMs ?? 30000;
    if (!Number.isInteger(timeoutMs) || timeoutMs < 1) throw new TypeError('connectTimeoutMs: a positive integer');
    if (!tcp && (typeof (opts as SocketOptions).socket !== 'string' || !(opts as SocketOptions).socket))
        throw new TypeError('connect: { socket: PATH } or { host, port, ca | caFile | pin }');
    let sock: net.Socket;
    let endpoint: number, cbType: number;
    let binding: Buffer;
    let timer: NodeTimer | undefined;
    const deadline = new Promise<never>((_, reject) => {
        timer = setTimeout(() => reject(new ImdbError(ERR.IO, 'connect: no answer within ' + timeoutMs + ' ms')), timeoutMs);
    });
    deadline.catch(() => undefined); /* raced below; never an unhandled rejection */
    const race = <T>(p: Promise<T>) => Promise.race([p, deadline]);
    if (!tcp) {
        const o = opts as SocketOptions;
        sock = net.createConnection({ path: o.socket });
        endpoint = EP.UNIX;
        cbType = CB.NONE;
        binding = Buffer.alloc(KEY);
        try {
            await race(new Promise<void>((resolve, reject) => {
                sock.once('connect', resolve);
                sock.once('error', reject);
            }));
        } catch (e) {
            clearTimeout(timer);
            sock.destroy();
            throw ioError(e, 'connect ' + o.socket);
        }
    } else {
        const o = opts as TcpOptions;
        let pin: Buffer | null = null, ca: string | Buffer | undefined = undefined, cbName = 'tls-exporter';
        try {
            if (typeof o.host !== 'string' || !o.host || !Number.isInteger(o.port) || o.port < 1 || o.port > 65535)
                throw new TypeError('connect: a host and a port 1 to 65535');
            const given = [o.ca !== undefined, o.caFile !== undefined, o.pin !== undefined].filter(Boolean).length;
            if (given !== 1) throw new ProtocolError(ERR.INVALID, 'TLS: a CA (ca or caFile) or a pin, exactly one (no unverified mode)');
            cbName = o.channelBinding ?? 'tls-exporter';
            if (cbName !== 'tls-exporter' && cbName !== 'tls-server-end-point') throw new TypeError("channelBinding: 'tls-exporter' or 'tls-server-end-point'");
            pin = o.pin !== undefined ? pinBytes(o.pin) : null;
            ca = o.caFile !== undefined ? fs.readFileSync(o.caFile) : o.ca;
            if (!pin && (ca === undefined || !(typeof ca === 'string' || Buffer.isBuffer(ca)) || !ca.length)) throw new TypeError('ca: the CA certificate (PEM)');
        } catch (e) {
            clearTimeout(timer);
            throw e;
        }
        const ip = net.isIP(o.host) !== 0;
        const ts = tls.connect({
            host: o.host,
            port: o.port,
            servername: ip ? undefined : o.host, /* SNI is a name's alone; the check reads host either way */
            ALPNProtocols: ['imdbwir1'],
            minVersion: 'TLSv1.3',
            maxVersion: 'TLSv1.3',
            /* pinned: the chain is not asked for; the key is, below, before any byte of ours leaves */
            ...(pin ? { rejectUnauthorized: false } : { ca: ca!, rejectUnauthorized: true }),
        });
        sock = ts;
        endpoint = EP.TCP;
        cbType = cbName === 'tls-exporter' ? CB.EXPORTER : CB.ENDPOINT;
        try {
            await race(new Promise<void>((resolve, reject) => {
                ts.once('secureConnect', resolve);
                ts.once('error', reject);
                ts.once('close', () => reject(new ImdbError(ERR.IO, 'TLS: the connection closed during the handshake')));
            }));
            if (ts.alpnProtocol !== 'imdbwir1') throw new AuthError('TLS: the peer does not speak imdbwir1 (ALPN)');
            if (ts.getProtocol() !== 'TLSv1.3') throw new AuthError('TLS: not 1.3');
            const cert = ts.getPeerX509Certificate();
            if (!cert) throw new AuthError('TLS: the server sent no certificate');
            if (pin) {
                const got = crypto.createHash('sha256').update(cert.publicKey.export({ type: 'spki', format: 'der' })).digest();
                if (!crypto.timingSafeEqual(got, pin)) throw new AuthError("TLS: the server's key is not the pinned one");
            } else if (!ts.authorized) {
                throw new AuthError("TLS: the server's certificate: " + String(ts.authorizationError));
            }
            binding = cbType === CB.EXPORTER ? ts.exportKeyingMaterial(32, 'EXPORTER-Channel-Binding')
                : crypto.createHash('sha256').update(cert.raw).digest();
            ts.setNoDelay(true);
            ts.setKeepAlive(true, 60000);
        } catch (e) {
            clearTimeout(timer);
            ts.destroy();
            throw ioError(e, 'connect ' + o.host + ' port ' + o.port);
        }
    }
    const c = new Client(sock, endpoint === EP.TCP ? 'tcp' : 'socket');
    try {
        await race(c.authenticate(endpoint, cbType, binding, user, cred.password));
    } catch (e) {
        c.destroy();
        if (e instanceof ClosedError) throw new ImdbError(ERR.IO, 'the connection closed during the login' + (e.reason ? ': ' + e.reason.message : ''));
        throw e instanceof ImdbError ? e : ioError(e, 'login');
    } finally {
        clearTimeout(timer);
        binding.fill(0);
    }
    return c;
}
