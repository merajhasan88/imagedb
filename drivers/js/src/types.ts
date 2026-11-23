/* The driver's native values and their wire forms (docs/n1-design.md §4, Values). Nothing is lost either way:
 * - INT64: bigint, always (the full range; a number would lose past 2^53).
 * - FLOAT64: number, its bits as the wire's (finite; the engine keeps one zero, so -0 is sent as 0).
 * - DECIMAL: Decimal, an exact bigint and its scale (a string parameter is TEXT, and a DECIMAL's scale travels).
 * - TIMESTAMP and TIMESTAMPTZ: Timestamp and TimestampTz, bigint microseconds (Date keeps milliseconds alone; two
 *   classes so a parameter keeps its type).
 * - DATE SqlDate (days), TIME SqlTime (bigint microseconds), INTERVAL Interval (months, days, bigint microseconds).
 * - UUID: a string in a result (8-4-4-4-12, lowercase); as a parameter a Uuid (a string parameter is TEXT).
 * - BYTEA: Buffer (a Uint8Array parameter too). ENUM: its label, a string (a parameter label is TEXT: §4's rule).
 * - NULL: null; a parameter null or undefined is a NULL of no type, nullOf(type) one of a type. */
import { ERR, ProtocolError } from './errors';
import { DATE_MAX, DATE_MIN, DEC_LIM, T, T_LAST, textBytes, TIME_MAX, TS_MAX_US, TS_MIN_US, TYPE_NAMES, TypeName, utf8String, wnull, wv, WireValue } from './wire';

const US_PER_DAY = 86400000000n;

function refuse(what: string): never {
    throw new ProtocolError(ERR.INVALID, 'a parameter its encoder refuses: ' + what);
}

/* ---- the proleptic Gregorian calendar (days since 1970-01-01), years 1 to 9999 ---- */
export function daysFromCivil(y: number, m: number, d: number): number {
    y -= m <= 2 ? 1 : 0;
    const era = Math.floor(y / 400);
    const yoe = y - era * 400;
    const doy = Math.floor((153 * (m + (m > 2 ? -3 : 9)) + 2) / 5) + d - 1;
    const doe = yoe * 365 + Math.floor(yoe / 4) - Math.floor(yoe / 100) + doy;
    return era * 146097 + doe - 719468;
}
export function civilFromDays(z: number): [number, number, number] {
    z += 719468;
    const era = Math.floor(z / 146097);
    const doe = z - era * 146097;
    const yoe = Math.floor((doe - Math.floor(doe / 1460) + Math.floor(doe / 36524) - Math.floor(doe / 146096)) / 365);
    const doy = doe - (365 * yoe + Math.floor(yoe / 4) - Math.floor(yoe / 100));
    const mp = Math.floor((5 * doy + 2) / 153);
    const d = doy - Math.floor((153 * mp + 2) / 5) + 1;
    const m = mp < 10 ? mp + 3 : mp - 9;
    return [yoe + era * 400 + (m <= 2 ? 1 : 0), m, d];
}
const pad = (n: number | bigint, w: number) => String(n).padStart(w, '0');
function dateText(days: number): string {
    const [y, m, d] = civilFromDays(days);
    return pad(y, 4) + '-' + pad(m, 2) + '-' + pad(d, 2);
}
function timeText(us: bigint): string {
    const s = us / 1000000n, f = us % 1000000n;
    return pad(s / 3600n, 2) + ':' + pad((s / 60n) % 60n, 2) + ':' + pad(s % 60n, 2) + (f ? '.' + pad(f, 6) : '');
}
function floorDiv(a: bigint, b: bigint): bigint {
    const q = a / b;
    return a % b !== 0n && (a < 0n) !== (b < 0n) ? q - 1n : q;
}
function parseDate(s: string): number | null {
    const m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(s);
    if (!m) return null;
    const y = +m[1], mo = +m[2], d = +m[3];
    if (y < 1 || mo < 1 || mo > 12 || d < 1) return null;
    const leap = (y % 4 === 0 && y % 100 !== 0) || y % 400 === 0;
    const dim = [31, leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31][mo - 1];
    return d > dim ? null : daysFromCivil(y, mo, d);
}
function parseTime(s: string): bigint | null {
    const m = /^(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,6}))?$/.exec(s);
    if (!m || +m[1] > 23 || +m[2] > 59 || +m[3] > 59) return null;
    return (BigInt(+m[1] * 3600 + +m[2] * 60 + +m[3]) * 1000000n) + BigInt((m[4] ?? '').padEnd(6, '0') || '0');
}
/* 'YYYY-MM-DD HH:MM:SS[.ffffff]' (or a T between): microseconds since 1970-01-01 00:00 */
function parseDateTime(s: string): bigint | null {
    const m = /^(\d{4}-\d{2}-\d{2})[ T](\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?)$/.exec(s);
    if (!m) return null;
    const d = parseDate(m[1]), t = parseTime(m[2]);
    return d === null || t === null ? null : BigInt(d) * US_PER_DAY + t;
}

/* ---- the value classes ---- */

/* DECIMAL: unscaled x 10^-scale, exact (|unscaled| < 10^38, scale 0 to 38 on the wire) */
export class Decimal {
    readonly unscaled: bigint;
    readonly scale: number;
    constructor(unscaled: bigint, scale = 0) {
        if (typeof unscaled !== 'bigint' || !Number.isInteger(scale) || scale < 0) throw new TypeError('Decimal(unscaled: bigint, scale: a non-negative integer)');
        this.unscaled = unscaled;
        this.scale = scale;
    }
    /* "-123.45", "+7", ".5", "1e3", "1.50E-2": exact, the scale the digits written (an exponent moves it, never below 0) */
    static parse(s: string): Decimal {
        const m = /^([+-]?)(\d*)(?:\.(\d*))?(?:[eE]([+-]?\d+))?$/.exec(s.trim());
        if (!m || (!m[2] && !m[3])) throw new TypeError('not a decimal number: ' + JSON.stringify(s));
        const frac = m[3] ?? '';
        let u = BigInt((m[2] || '0') + frac);
        let scale = frac.length - (m[4] ? parseInt(m[4], 10) : 0);
        if (scale < 0) {
            u *= 10n ** BigInt(-scale);
            scale = 0;
        }
        return new Decimal(m[1] === '-' ? -u : u, scale);
    }
    /* a number by its shortest round-trip text (String(x)), a bigint at scale 0 */
    static from(x: number | bigint | string): Decimal {
        if (typeof x === 'bigint') return new Decimal(x, 0);
        if (typeof x === 'number') {
            if (!Number.isFinite(x)) throw new TypeError('not a finite number');
            return Decimal.parse(String(x));
        }
        return Decimal.parse(x);
    }
    toString(): string {
        const neg = this.unscaled < 0n;
        let digits = (neg ? -this.unscaled : this.unscaled).toString();
        if (this.scale > 0) {
            digits = digits.padStart(this.scale + 1, '0');
            digits = digits.slice(0, digits.length - this.scale) + '.' + digits.slice(digits.length - this.scale);
        }
        return (neg ? '-' : '') + digits;
    }
    toJSON(): string {
        return this.toString();
    }
    toNumber(): number {
        return Number(this.toString());
    }
    /* the same digits at the same scale (1.5 and 1.50 differ: use compare for the value) */
    equals(o: unknown): boolean {
        return o instanceof Decimal && o.unscaled === this.unscaled && o.scale === this.scale;
    }
    /* by value: -1, 0, 1 */
    compare(o: Decimal): number {
        const s = Math.max(this.scale, o.scale);
        const a = this.unscaled * 10n ** BigInt(s - this.scale), b = o.unscaled * 10n ** BigInt(s - o.scale);
        return a < b ? -1 : a > b ? 1 : 0;
    }
}

/* TIMESTAMP: microseconds since 1970-01-01 00:00, no zone */
export class Timestamp {
    readonly micros: bigint;
    constructor(micros: bigint) {
        if (typeof micros !== 'bigint') throw new TypeError('Timestamp(micros: bigint)');
        this.micros = micros;
    }
    static parse(s: string): Timestamp {
        const us = parseDateTime(s);
        if (us === null) throw new TypeError('not a timestamp (YYYY-MM-DD HH:MM:SS[.ffffff]): ' + JSON.stringify(s));
        return new Timestamp(us);
    }
    /* a Date's milliseconds as a wall-clock time read in UTC */
    static fromDate(d: Date): Timestamp {
        return new Timestamp(BigInt(d.getTime()) * 1000n);
    }
    toString(): string {
        const days = floorDiv(this.micros, US_PER_DAY);
        return dateText(Number(days)) + ' ' + timeText(this.micros - days * US_PER_DAY);
    }
    toJSON(): string {
        return this.toString();
    }
    /* lossy: milliseconds, the wall-clock time taken as UTC */
    toDate(): Date {
        return new Date(Number(floorDiv(this.micros, 1000n)));
    }
    equals(o: unknown): boolean {
        return o instanceof Timestamp && o.micros === this.micros;
    }
}

/* TIMESTAMPTZ: an instant, microseconds since the epoch (a session's zone is for text alone) */
export class TimestampTz {
    readonly micros: bigint;
    constructor(micros: bigint) {
        if (typeof micros !== 'bigint') throw new TypeError('TimestampTz(micros: bigint)');
        this.micros = micros;
    }
    /* 'YYYY-MM-DD HH:MM:SS[.ffffff]' then Z, +HH, +HH:MM or -HH:MM */
    static parse(s: string): TimestampTz {
        const m = /^(.*?)(Z|[+-]\d{2}(?::?\d{2})?)$/.exec(s.trim());
        const us = m ? parseDateTime(m[1]) : null;
        if (!m || us === null) throw new TypeError('not a timestamp with a zone: ' + JSON.stringify(s));
        let off = 0n;
        if (m[2] !== 'Z') {
            const sign = m[2][0] === '-' ? -1n : 1n, digits = m[2].slice(1).replace(':', '');
            off = sign * (BigInt(+digits.slice(0, 2)) * 3600n + BigInt(+(digits.slice(2) || '0')) * 60n) * 1000000n;
        }
        return new TimestampTz(us - off);
    }
    static fromDate(d: Date): TimestampTz {
        return new TimestampTz(BigInt(d.getTime()) * 1000n);
    }
    toString(): string {
        const days = floorDiv(this.micros, US_PER_DAY);
        return dateText(Number(days)) + ' ' + timeText(this.micros - days * US_PER_DAY) + '+00';
    }
    toJSON(): string {
        return this.toString();
    }
    /* lossy: milliseconds (floor) */
    toDate(): Date {
        return new Date(Number(floorDiv(this.micros, 1000n)));
    }
    equals(o: unknown): boolean {
        return o instanceof TimestampTz && o.micros === this.micros;
    }
}

/* DATE: days since 1970-01-01 */
export class SqlDate {
    readonly days: number;
    constructor(days: number) {
        if (!Number.isInteger(days)) throw new TypeError('SqlDate(days: an integer)');
        this.days = days;
    }
    static parse(s: string): SqlDate {
        const d = parseDate(s);
        if (d === null) throw new TypeError('not a date (YYYY-MM-DD): ' + JSON.stringify(s));
        return new SqlDate(d);
    }
    toString(): string {
        return dateText(this.days);
    }
    toJSON(): string {
        return this.toString();
    }
    equals(o: unknown): boolean {
        return o instanceof SqlDate && o.days === this.days;
    }
}

/* TIME: microseconds since midnight */
export class SqlTime {
    readonly micros: bigint;
    constructor(micros: bigint) {
        if (typeof micros !== 'bigint') throw new TypeError('SqlTime(micros: bigint)');
        this.micros = micros;
    }
    static parse(s: string): SqlTime {
        const t = parseTime(s);
        if (t === null) throw new TypeError('not a time (HH:MM:SS[.ffffff]): ' + JSON.stringify(s));
        return new SqlTime(t);
    }
    toString(): string {
        return timeText(this.micros);
    }
    toJSON(): string {
        return this.toString();
    }
    equals(o: unknown): boolean {
        return o instanceof SqlTime && o.micros === this.micros;
    }
}

/* INTERVAL: any triple, kept as the engine keeps it (PostgreSQL's: months, days and microseconds apart) */
export class Interval {
    readonly months: number;
    readonly days: number;
    readonly micros: bigint;
    constructor(months: number, days: number, micros: bigint) {
        if (!Number.isInteger(months) || !Number.isInteger(days) || typeof micros !== 'bigint') throw new TypeError('Interval(months, days: integers, micros: bigint)');
        this.months = months;
        this.days = days;
        this.micros = micros;
    }
    toString(): string {
        return this.months + ' mons ' + this.days + ' days ' + this.micros + ' us';
    }
    toJSON(): { months: number; days: number; micros: string } {
        return { months: this.months, days: this.days, micros: String(this.micros) };
    }
    equals(o: unknown): boolean {
        return o instanceof Interval && o.months === this.months && o.days === this.days && o.micros === this.micros;
    }
}

/* UUID as a parameter (a string is TEXT): from its text (32 hex digits, dashes anywhere between pairs ignored) or bytes */
export class Uuid {
    readonly bytes: Buffer;
    constructor(x: string | Uint8Array) {
        if (typeof x === 'string') {
            const h = x.replace(/-/g, '');
            if (!/^[0-9a-fA-F]{32}$/.test(h)) throw new TypeError('not a UUID: ' + JSON.stringify(x));
            this.bytes = Buffer.from(h.toLowerCase(), 'hex');
        } else {
            if (x.length !== 16) throw new TypeError('a UUID is 16 bytes');
            this.bytes = Buffer.from(x);
        }
    }
    toString(): string {
        const h = this.bytes.toString('hex');
        return h.slice(0, 8) + '-' + h.slice(8, 12) + '-' + h.slice(12, 16) + '-' + h.slice(16, 20) + '-' + h.slice(20);
    }
    toJSON(): string {
        return this.toString();
    }
}

/* a number sent as FLOAT64 whatever its value (a safe integer number is otherwise INT64) */
export class Float64 {
    readonly value: number;
    constructor(value: number) {
        this.value = value;
    }
}

/* a NULL of a type: the engine binds a NULL parameter by its type (§4) */
export class TypedNull {
    readonly type: number;
    constructor(type: number) {
        if (!Number.isInteger(type) || type < 0 || type > T_LAST) throw new TypeError('a type 0 to 13');
        this.type = type;
    }
}
export function nullOf(type: TypeName | number): TypedNull {
    return new TypedNull(typeof type === 'number' ? type : TYPE_NAMES.indexOf(type));
}

export type Param = null | undefined | boolean | number | bigint | string | Uint8Array | Date | Decimal | Timestamp | TimestampTz | SqlDate | SqlTime |
    Interval | Uuid | Float64 | TypedNull;
export type Value = null | boolean | number | bigint | string | Buffer | Decimal | Timestamp | TimestampTz | SqlDate | SqlTime | Interval;

const f64 = Buffer.alloc(8);
function floatBits(x: number): bigint {
    if (!Number.isFinite(x)) refuse('a FLOAT64 that is not finite (the engine has no NaN or infinity)');
    f64.writeDoubleLE(x === 0 ? 0 : x, 0); /* the engine's one zero: -0 sent as 0 */
    return f64.readBigUInt64LE(0);
}

/* a JS value as a wire parameter. A number: a safe integer is INT64 (it binds into INT64, DECIMAL and FLOAT64 columns by
 * its value, §4's rule), any other finite number FLOAT64; Float64 forces FLOAT64. A Date is a TIMESTAMPTZ (an instant). */
export function toWire(x: Param): WireValue {
    if (x === null || x === undefined) return wnull(T.NONE);
    if (x instanceof TypedNull) return wnull(x.type);
    switch (typeof x) {
        case 'boolean':
            return wv({ type: T.BOOL, i: x ? 1n : 0n });
        case 'bigint':
            if (x < -(1n << 63n) || x >= 1n << 63n) throw new ProtocolError(ERR.LIMIT, 'a parameter its encoder refuses: a bigint past INT64');
            return wv({ type: T.INT64, i: x });
        case 'number':
            if (Number.isSafeInteger(x)) return wv({ type: T.INT64, i: BigInt(x) });
            return wv({ type: T.FLOAT64, f: floatBits(x) });
        case 'string': {
            const b = textBytes(x);
            if (!b) refuse('a TEXT with a lone surrogate or a NUL');
            if (b.length > 65535) throw new ProtocolError(ERR.LIMIT, 'a parameter its encoder refuses: a TEXT past 65,535 bytes');
            return wv({ type: T.TEXT, s: b });
        }
    }
    if (x instanceof Float64) return wv({ type: T.FLOAT64, f: floatBits(x.value) });
    if (x instanceof Decimal) {
        if (x.scale > 38 || x.unscaled <= -DEC_LIM || x.unscaled >= DEC_LIM) throw new ProtocolError(ERR.LIMIT, 'a parameter its encoder refuses: a DECIMAL past 38 digits or scale 38');
        return wv({ type: T.DECIMAL, scale: x.scale, d: x.unscaled });
    }
    if (x instanceof Timestamp || x instanceof TimestampTz) {
        if (x.micros < TS_MIN_US || x.micros > TS_MAX_US) throw new ProtocolError(ERR.LIMIT, 'a parameter its encoder refuses: a timestamp outside years 1 to 9999');
        return wv({ type: x instanceof Timestamp ? T.TIMESTAMP : T.TIMESTAMPTZ, i: x.micros });
    }
    if (x instanceof Date) {
        const ms = x.getTime();
        if (!Number.isFinite(ms)) refuse('an invalid Date');
        return toWire(new TimestampTz(BigInt(ms) * 1000n));
    }
    if (x instanceof SqlDate) {
        if (x.days < DATE_MIN || x.days > DATE_MAX) throw new ProtocolError(ERR.LIMIT, 'a parameter its encoder refuses: a DATE outside 0001-01-01 to 9999-12-31');
        return wv({ type: T.DATE, day: x.days });
    }
    if (x instanceof SqlTime) {
        if (x.micros < 0n || x.micros > TIME_MAX) throw new ProtocolError(ERR.LIMIT, 'a parameter its encoder refuses: a TIME outside a day');
        return wv({ type: T.TIME, i: x.micros });
    }
    if (x instanceof Interval) {
        const v = wv({ type: T.INTERVAL, mon: x.months, day: x.days, i: x.micros });
        if (x.months < -(2 ** 31) || x.months >= 2 ** 31 || x.days < -(2 ** 31) || x.days >= 2 ** 31 || x.micros < -(1n << 63n) || x.micros >= 1n << 63n)
            throw new ProtocolError(ERR.LIMIT, "a parameter its encoder refuses: an INTERVAL's field past its width");
        return v;
    }
    if (x instanceof Uuid) return wv({ type: T.UUID, s: x.bytes });
    if (x instanceof Uint8Array) {
        if (x.length > 65535) throw new ProtocolError(ERR.LIMIT, 'a parameter its encoder refuses: a BYTEA past 65,535 bytes');
        return wv({ type: T.BYTEA, s: Buffer.from(x) });
    }
    return refuse('a value of no IMDBWIR1 type (' + Object.prototype.toString.call(x) + ')');
}

/* a wire value as its native one (its bytes copied: nothing points into the frame it came in) */
export function fromWire(v: WireValue): Value {
    if (v.null) return null;
    switch (v.type) {
        case T.INT64:
            return v.i;
        case T.FLOAT64:
            f64.writeBigUInt64LE(v.f, 0);
            return f64.readDoubleLE(0);
        case T.BOOL:
            return v.i === 1n;
        case T.TEXT:
        case T.ENUM:
            return utf8String(v.s!);
        case T.DECIMAL:
            return new Decimal(v.d, v.scale);
        case T.TIMESTAMP:
            return new Timestamp(v.i);
        case T.TIMESTAMPTZ:
            return new TimestampTz(v.i);
        case T.DATE:
            return new SqlDate(v.day);
        case T.TIME:
            return new SqlTime(v.i);
        case T.UUID:
            return new Uuid(v.s!).toString();
        case T.BYTEA:
            return Buffer.from(v.s!);
        case T.INTERVAL:
            return new Interval(v.mon, v.day, v.i);
    }
    throw new ProtocolError(ERR.CORRUPT, 'wire: a value of no type');
}
