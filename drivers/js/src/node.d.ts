/* The Node.js APIs this driver uses, declared here: the machine holds no @types/node, and the driver takes nothing from
 * outside Node's standard library (no package, no vendored code). Only what is used, as Node 19 documents it. */

type BufferEncoding = 'utf8' | 'utf-8' | 'hex' | 'latin1' | 'binary' | 'ascii' | 'base64';

interface Buffer extends Uint8Array {
    toString(encoding?: BufferEncoding, start?: number, end?: number): string;
    subarray(start?: number, end?: number): Buffer;
    equals(other: Uint8Array): boolean;
    compare(other: Uint8Array): number;
    copy(target: Uint8Array, targetStart?: number, sourceStart?: number, sourceEnd?: number): number;
    write(s: string, offset?: number, encoding?: BufferEncoding): number;
    readUInt8(off: number): number;
    readUInt16LE(off: number): number;
    readUInt32LE(off: number): number;
    readInt32LE(off: number): number;
    readBigUInt64LE(off: number): bigint;
    readBigInt64LE(off: number): bigint;
    readDoubleLE(off: number): number;
    writeUInt8(v: number, off: number): number;
    writeUInt16LE(v: number, off: number): number;
    writeUInt32LE(v: number, off: number): number;
    writeInt32LE(v: number, off: number): number;
    writeBigUInt64LE(v: bigint, off: number): number;
    writeBigInt64LE(v: bigint, off: number): number;
    writeDoubleLE(v: number, off: number): number;
}
declare var Buffer: {
    alloc(size: number, fill?: number): Buffer;
    allocUnsafe(size: number): Buffer;
    from(data: string, encoding?: BufferEncoding): Buffer;
    from(data: ArrayBuffer, byteOffset?: number, length?: number): Buffer;
    from(data: ArrayLike<number> | Iterable<number> | Uint8Array): Buffer;
    concat(list: readonly Uint8Array[], totalLength?: number): Buffer;
    byteLength(s: string, encoding?: BufferEncoding): number;
    isBuffer(x: unknown): x is Buffer;
};

declare class TextDecoder {
    constructor(label?: string, options?: { fatal?: boolean; ignoreBOM?: boolean });
    decode(input?: Uint8Array): string;
}

declare var process: {
    env: { [k: string]: string | undefined };
    argv: string[];
    pid: number;
    exitCode: number | undefined;
    exit(code?: number): never;
    hrtime: { bigint(): bigint };
    kill(pid: number, signal?: string): boolean;
};

declare var console: {
    log(...a: unknown[]): void;
    error(...a: unknown[]): void;
};

interface NodeTimer {
    unref(): NodeTimer;
    ref(): NodeTimer;
}
declare function setTimeout(fn: (...a: any[]) => void, ms?: number): NodeTimer;
declare function clearTimeout(t: NodeTimer | undefined): void;
declare function setImmediate(fn: (...a: any[]) => void): unknown;

declare module 'events' {
    class EventEmitter {
        on(event: string, listener: (...args: any[]) => void): this;
        once(event: string, listener: (...args: any[]) => void): this;
        off(event: string, listener: (...args: any[]) => void): this;
        removeListener(event: string, listener: (...args: any[]) => void): this;
        removeAllListeners(event?: string): this;
        emit(event: string, ...args: any[]): boolean;
        listenerCount(event: string): number;
    }
}

declare module 'stream' {
    import { EventEmitter } from 'events';
    class Readable extends EventEmitter implements AsyncIterable<any> {
        [Symbol.asyncIterator](): AsyncIterator<any>;
        destroy(err?: Error): this;
        static from(it: Iterable<any> | AsyncIterable<any>): Readable;
    }
    class Writable extends EventEmitter {
        constructor(opts?: {
            highWaterMark?: number;
            write?(chunk: any, encoding: string, cb: (err?: Error | null) => void): void;
        });
        write(chunk: Uint8Array | string, cb?: (err?: Error | null) => void): boolean;
        end(cb?: () => void): this;
        destroy(err?: Error): this;
        destroyed: boolean;
        writableNeedDrain: boolean;
    }
}

declare var __dirname: string;

declare module 'path' {
    function join(...parts: string[]): string;
}

declare module 'net' {
    import { EventEmitter } from 'events';
    interface ConnectOpts {
        path?: string;
        host?: string;
        port?: number;
        allowHalfOpen?: boolean;
    }
    class Socket extends EventEmitter {
        write(data: Uint8Array | string, cb?: (err?: Error | null) => void): boolean;
        end(cb?: () => void): this;
        destroy(err?: Error): this;
        pause(): this;
        resume(): this;
        setNoDelay(noDelay?: boolean): this;
        setKeepAlive(enable?: boolean, initialDelay?: number): this;
        readonly destroyed: boolean;
        readonly writable: boolean;
        readonly writableLength: number;
    }
    class Server extends EventEmitter {
        listen(path: string, cb?: () => void): this;
        listen(port: number, host: string, cb?: () => void): this;
        close(cb?: (err?: Error) => void): this;
        address(): { port: number } | string | null;
    }
    function createConnection(opts: ConnectOpts): Socket;
    function createServer(listener?: (s: Socket) => void): Server;
    function isIP(s: string): number;
}

declare module 'tls' {
    import * as net from 'net';
    import { X509Certificate } from 'crypto';
    interface ConnectionOptions {
        host?: string;
        port?: number;
        servername?: string;
        ca?: string | Buffer | Array<string | Buffer>;
        rejectUnauthorized?: boolean;
        ALPNProtocols?: string[];
        minVersion?: string;
        maxVersion?: string;
        checkServerIdentity?: (host: string, cert: any) => Error | undefined;
        session?: Buffer;
    }
    class TLSSocket extends net.Socket {
        readonly authorized: boolean;
        readonly authorizationError: Error | string | null;
        readonly alpnProtocol: string | false | null;
        getProtocol(): string | null;
        getPeerX509Certificate(): X509Certificate | undefined;
        exportKeyingMaterial(length: number, label: string, context?: Buffer): Buffer;
    }
    function connect(opts: ConnectionOptions): TLSSocket;
    function checkServerIdentity(host: string, cert: any): Error | undefined;
}

declare module 'crypto' {
    interface Hash {
        update(data: Uint8Array | string): Hash;
        digest(): Buffer;
        digest(enc: 'hex'): string;
    }
    class KeyObject {
        export(opts: { type: 'spki'; format: 'der' }): Buffer;
    }
    class X509Certificate {
        constructor(pem: string | Buffer);
        readonly raw: Buffer;
        readonly publicKey: KeyObject;
        readonly subjectAltName: string | undefined;
        readonly fingerprint256: string;
    }
    function randomBytes(n: number): Buffer;
    function createHash(alg: string): Hash;
    function createHmac(alg: string, key: Uint8Array | string): Hash;
    function pbkdf2(pw: Uint8Array, salt: Uint8Array, iter: number, keylen: number, digest: string,
                    cb: (err: Error | null, key: Buffer) => void): void;
    function pbkdf2Sync(pw: Uint8Array, salt: Uint8Array, iter: number, keylen: number, digest: string): Buffer;
    function timingSafeEqual(a: Uint8Array, b: Uint8Array): boolean;
}

declare module 'fs' {
    function readFileSync(path: string): Buffer;
    function readFileSync(path: string, enc: BufferEncoding): string;
    function existsSync(path: string): boolean;
}

declare module 'node:test' {
    type Fn = (t: any) => void | Promise<void>;
    interface Opts {
        timeout?: number;
        skip?: boolean | string;
        concurrency?: number | boolean;
    }
    function test(name: string, fn: Fn): Promise<void>;
    function test(name: string, opts: Opts, fn: Fn): Promise<void>;
    namespace test {
        function before(fn: () => void | Promise<void>): void;
        function after(fn: () => void | Promise<void>): void;
    }
    function describe(name: string, fn: () => void): void;
    function before(fn: () => void | Promise<void>): void;
    function after(fn: () => void | Promise<void>): void;
    export { test, describe, before, after };
    export default test;
}

declare module 'node:assert' {
    namespace assert {
        function ok(v: unknown, msg?: string): asserts v;
        function equal(a: unknown, b: unknown, msg?: string): void;
        function strictEqual(a: unknown, b: unknown, msg?: string): void;
        function notStrictEqual(a: unknown, b: unknown, msg?: string): void;
        function deepStrictEqual(a: unknown, b: unknown, msg?: string): void;
        function throws(fn: () => unknown, expected?: unknown, msg?: string): void;
        function rejects(p: Promise<unknown> | (() => Promise<unknown>), expected?: unknown, msg?: string): Promise<void>;
        function match(s: string, re: RegExp, msg?: string): void;
        function fail(msg?: string): never;
    }
    function assert(v: unknown, msg?: string): asserts v;
    export = assert;
}
