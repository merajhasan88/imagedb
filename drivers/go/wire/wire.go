// Package wire is IMDBWIR1's bytes (imagedb's own protocol, docs/n1-design.md §4): pure functions over byte slices, no
// I/O. It mirrors the C codec (server/wire.c) field by field: every decoder is strict (exact lengths, no trailing
// bytes, zero padding, every count bounded by the bytes left before anything is sized by it), and each field has one
// predicate that its decoder and its encoder both apply, so an encoder never writes what its decoder refuses and any
// bytes a decoder takes encode back to themselves. Every integer is little-endian.
package wire

import "fmt"

// The pre-auth layout and the protocol's bounds (wire.h).
const (
	Magic        = "IMDBWIR1"
	Version      = 1
	UserField    = 64 // a role name's field: UTF-8, 1 to 63 bytes, NUL-padded
	NonceLen     = 32
	SaltField    = 64 // a verifier's salt: 8 to 64 bytes
	KeyLen       = 32
	PreauthHead  = 12 // every pre-auth message's first bytes, in every version: the magic and u32 its version
	HelloLen     = 112
	ChallengeLen = 120
	ProofLen     = 32
	VerdictLen   = 36
	AuthMsgLen   = 279 // "IMDBWIR1-SCRAM" | endpoint | hello | challenge | binding[32]
	HeadLen      = 5   // a frame's u32 length and u8 type
	FrameMax     = 16 << 20
	BatchMax     = 4096 // statements in a QUERY, parameter sets in an EXECUTE
	ValuesMax    = 256  // values a statement or a set takes; columns in a result
	NameMax      = 63   // a prepared statement's name
	ColNameMax   = 70
	SQLMax       = 1 << 22
	ValueMax     = 65535 // a TEXT's or a BYTEA's bytes
	LabelMax     = 63
	LabelsMax    = 1024
	StatusMax    = 511
	MessageMax   = 4096
	ScramIterMin = 1000
	ScramIterMax = 1000000
	ScramSaltMin = 8
	PasswordMax  = 1024
	SessionsMax  = 65536
)

// Endpoint is the AuthMessage's endpoint byte.
type Endpoint uint8

const (
	EndpointTCP  Endpoint = 1 // TCP with TLS
	EndpointUnix Endpoint = 2 // the Unix-domain socket
)

// Binding is a hello's flags: the channel binding's type (§8f).
type Binding uint32

const (
	BindingNone     Binding = 0 // the Unix socket's
	BindingExporter Binding = 1 // RFC 9266's tls-exporter (the server's default)
	BindingEndpoint Binding = 2 // RFC 5929's tls-server-end-point (a server run with --channel-binding any)
)

// A verdict's codes.
const (
	VerdictOK      = 0
	VerdictRefused = 1
	VerdictBinding = 2 // the hello's binding type refused by this server: never retried with another (no downgrade)
)

// FrameType is a frame's type byte: the client's 1 to 12, the server's 64 to 74.
type FrameType uint8

const (
	TQuery        FrameType = 1
	TPrepare      FrameType = 2
	TExecute      FrameType = 3
	TDeallocate   FrameType = 4
	TCopyData     FrameType = 5
	TCopyDone     FrameType = 6
	TCopyFail     FrameType = 7
	TCancel       FrameType = 8
	TPing         FrameType = 9
	TTerminate    FrameType = 10
	TSessions     FrameType = 11
	TKill         FrameType = 12
	clientLast    FrameType = 12
	TColumns      FrameType = 64
	TRows         FrameType = 65
	TDone         FrameType = 66
	TError        FrameType = 67
	TWarning      FrameType = 68
	TCopyIn       FrameType = 69
	TCopyOut      FrameType = 70
	TReady        FrameType = 71
	TPong         FrameType = 72
	TSessionsList FrameType = 73
	TKillDone     FrameType = 74
	serverLast    FrameType = 74
)

var frameNames = map[FrameType]string{
	TQuery: "QUERY", TPrepare: "PREPARE", TExecute: "EXECUTE", TDeallocate: "DEALLOCATE", TCopyData: "COPY_DATA",
	TCopyDone: "COPY_DONE", TCopyFail: "COPY_FAIL", TCancel: "CANCEL", TPing: "PING", TTerminate: "TERMINATE",
	TSessions: "SESSIONS", TKill: "KILL", TColumns: "COLUMNS", TRows: "ROWS", TDone: "DONE", TError: "ERROR",
	TWarning: "WARNING", TCopyIn: "COPY_IN", TCopyOut: "COPY_OUT", TReady: "READY", TPong: "PONG",
	TSessionsList: "SESSIONS_LIST", TKillDone: "KILL_DONE",
}

func (t FrameType) String() string {
	if n, ok := frameNames[t]; ok {
		return n
	}
	return fmt.Sprintf("frame type %d", uint8(t))
}

// FromServer reports whether t is a type the server sends.
func (t FrameType) FromServer() bool { return t >= TColumns && t <= serverLast }

// FromClient reports whether t is a type a client sends.
func (t FrameType) FromClient() bool { return t >= TQuery && t <= clientLast }

// READY's states.
const (
	Idle   = 0
	InTxn  = 1
	Doomed = 2 // a doomed transaction: it takes only ROLLBACK
)

// KILL's kinds and KILL_DONE's codes.
const (
	KillCancel    = 1
	KillTerminate = 2
	Killed        = 0
	KillNone      = 1 // no such session (to a role, another role's too)
)

// A session's state in SESSIONS_LIST.
const (
	SessIdle    = 0
	SessRunning = 1 // a request running or queued
	SessInTxn   = 2 // in a transaction at its last request's end
	SessCopy    = 3 // receiving a COPY's data
)

// Type is a value's wire type (§4's table): the contract, not the engine's internal forms.
type Type uint8

const (
	TypeNone        Type = 0 // no type: a column whose type the statement does not know, a NULL of none
	TypeInt64       Type = 1
	TypeFloat64     Type = 2
	TypeBool        Type = 3
	TypeText        Type = 4
	TypeDecimal     Type = 5
	TypeTimestamp   Type = 6
	TypeTimestampTZ Type = 7
	TypeDate        Type = 8
	TypeTime        Type = 9
	TypeUUID        Type = 10
	TypeBytea       Type = 11
	TypeInterval    Type = 12
	TypeEnum        Type = 13
	TypeLast        Type = 13
	NullTag              = 0x80 // a NULL's tag: 0x80 | its type
)

var typeNames = [...]string{"NONE", "INT64", "FLOAT64", "BOOL", "TEXT", "DECIMAL", "TIMESTAMP", "TIMESTAMPTZ", "DATE",
	"TIME", "UUID", "BYTEA", "INTERVAL", "ENUM"}

func (t Type) String() string {
	if t <= TypeLast {
		return typeNames[t]
	}
	return fmt.Sprintf("type %d", uint8(t))
}

// The engine's error codes (IMDB_ERR_*'s magnitude), stable on the wire.
const (
	CodeIO          = 1
	CodeCorrupt     = 2
	CodeLimit       = 3
	CodeInvalid     = 4
	CodeNoMem       = 5
	CodeConstraint  = 6
	CodeVerify      = 7
	CodeAuth        = 8
	CodeState       = 9
	CodeSyntax      = 10
	CodeNotFound    = 11
	CodeUnsupported = 12
	CodeHistory     = 13
	CodeConflict    = 14
	CodeCancelled   = 15
	CodePrivilege   = 16
)

// Error is a codec refusal: Code is CodeCorrupt (damaged bytes), CodeLimit (a length past its bound, refused before its
// bytes are asked for) or CodeUnsupported (a later protocol, refused by name), as wire.c's.
type Error struct {
	Code int
	Msg  string
}

func (e *Error) Error() string { return "wire: " + e.Msg }

func corrupt(msg string) error { return &Error{Code: CodeCorrupt, Msg: msg} }

func limitf(format string, a ...any) error {
	return &Error{Code: CodeLimit, Msg: fmt.Sprintf(format, a...)}
}

// refused is an encoder's refusal: a field its decoder would refuse (wire.c's b->err).
func refused(what string) error { return &Error{Code: CodeInvalid, Msg: "an encoder refuses " + what} }
