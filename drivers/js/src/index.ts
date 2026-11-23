/* imagedb's TypeScript/JavaScript driver for its own protocol, IMDBWIR1 (docs/n1-design.md §4, §8f). Node's standard
 * library alone. The idiomatic API: connect() and the Client's promises; the protocol level underneath: wire (every
 * byte rule), scram (the login's computation). */
export { connect, Client, StatementResult, QueryResult, mayBeCopy } from './client';
export type {
    BatchItem, BatchResult, Column, ConnectOptions, CopyChunk, CopySink, CopySource, Credentials, Done, ReadPoint, Row, SessionInfo,
    SocketOptions, TcpOptions, WritableLike, WritePoint,
} from './client';
export { AuthError, ClosedError, ERR, ImdbError, ProtocolError, ServerError } from './errors';
export type { TxState } from './errors';
export { Decimal, Float64, Interval, nullOf, SqlDate, SqlTime, Timestamp, TimestampTz, TypedNull, Uuid, fromWire, toWire } from './types';
export type { Param, Value } from './types';
export * as wire from './wire';
export * as scram from './scram';
