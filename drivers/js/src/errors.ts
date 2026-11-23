/* The driver's errors. An ERROR frame's code is the engine's (docs/n1-design.md §4): stable, 1 to 16 in this imagedb; a
 * later imagedb may add codes, read as an error of no class (codeName undefined). */

export const ERR = {
    IO: 1,
    CORRUPT: 2,
    LIMIT: 3,
    INVALID: 4,
    NOMEM: 5,
    CONSTRAINT: 6,
    VERIFY: 7,
    AUTH: 8,
    STATE: 9,
    SYNTAX: 10,
    NOTFOUND: 11,
    UNSUPPORTED: 12,
    HISTORY: 13,
    CONFLICT: 14,
    CANCELLED: 15,
    PRIVILEGE: 16,
} as const;

const NAMES: { [code: number]: string } = {};
for (const k of Object.keys(ERR) as (keyof typeof ERR)[]) NAMES[ERR[k]] = k;

export type TxState = 'idle' | 'transaction' | 'doomed';

export class ImdbError extends Error {
    readonly code: number;
    constructor(code: number, message: string) {
        super(message);
        this.code = code;
        this.name = 'ImdbError';
    }
    /* the code's class (IO, CORRUPT, ..., CANCELLED, PRIVILEGE), or undefined for a code this driver does not know */
    get codeName(): string | undefined {
        return NAMES[this.code];
    }
}

/* an ERROR frame: a statement's (or a parameter set's) failure, its index in its batch; the results of the statements
 * before it (each committed on its own unless in a transaction: a batch is not one), the WARNINGs before it, and the
 * session's state from the READY that ended the request (undefined when the connection closed before one) */
export class ServerError extends ImdbError {
    readonly index: number;
    results: unknown[] = [];
    warnings: string[] = [];
    state: TxState | undefined;
    constructor(code: number, index: number, message: string) {
        super(code, message);
        this.index = index;
        this.name = 'ServerError';
    }
}

/* bytes this driver refuses (a frame of the server's its decoder does not take) or a request its encoder refuses */
export class ProtocolError extends ImdbError {
    constructor(code: number, message: string) {
        super(code, message);
        this.name = 'ProtocolError';
    }
}

/* the login refused: a wrong password and an unknown name alike, a binding type refused, a server that did not prove
 * it holds the verifier, a TLS peer not verified */
export class AuthError extends ImdbError {
    constructor(message: string) {
        super(ERR.AUTH, message);
        this.name = 'AuthError';
    }
}

/* the connection is closed. reason: the server's last frame before its close when that was an ERROR (§4: why it
 * closed; its code is then this error's), else null and the code is IO */
export class ClosedError extends ImdbError {
    readonly reason: ServerError | null;
    constructor(message: string, reason: ServerError | null) {
        super(reason ? reason.code : ERR.IO, message);
        this.reason = reason;
        this.name = 'ClosedError';
    }
}
