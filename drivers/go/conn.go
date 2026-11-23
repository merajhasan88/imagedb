// Package imagedb is a client of imagedb's own protocol, IMDBWIR1 (docs/n1-design.md §4), by the standard library alone:
// a native client (Connect, Conn.Query, Batch, Prepare/Execute, CopyFrom/CopyTo, Sessions/Kill, Cancel) and a
// database/sql driver registered as "imagedb". The protocol's bytes are package wire's.
//
// Transport: the server's Unix-domain socket, or TCP with TLS 1.3 alone (ALPN "imdbwir1") verified by a CA file (the host
// checked against the certificate's names) or by a pin (the server key's SPKI SHA-256), exactly one: there is no
// unverified mode, no plaintext TCP and no fallback. The login is SCRAM-SHA-256 over §4's AuthMessage, bound on TCP to
// the TLS session by the exporter (RFC 9266, the default) or by tls-server-end-point (RFC 5929, for a server run with
// --channel-binding any); the server's signature is checked.
package imagedb

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"imagedb.dev/imagedb/wire"
)

// Binding is the channel binding a TCP login offers: one, never retried with another after a refusal (no downgrade).
type Binding int

const (
	// BindingExporter is RFC 9266's tls-exporter (the server's default, and the strongest: a relay holding the server's
	// key cannot reuse a proof made over another TLS session).
	BindingExporter Binding = iota
	// BindingEndpoint is RFC 5929's tls-server-end-point (the SHA-256 of the server certificate's DER), which a server
	// takes only when run with --channel-binding any.
	BindingEndpoint
)

// Config says where and as whom to connect. Exactly one of Socket and Addr; on TCP exactly one of a CA (CAFile or
// CAPEM) and Pin.
type Config struct {
	Socket   string // the server's Unix-domain socket (no TLS: no negotiation exists to downgrade)
	Addr     string // host:port, TCP with TLS 1.3
	User     string // a role's name: 1 to 63 bytes of UTF-8
	Password string // 1 to 1,024 bytes of printable ASCII, as CREATE ROLE takes one

	CAFile  string  // TCP: the CA (PEM) the server's certificate chains to; the host checked against its names
	CAPEM   []byte  // TCP: the same, in memory
	Pin     []byte  // TCP: the server key's SPKI SHA-256 (32 bytes, as `imagedb-server cert` prints it)
	Binding Binding // TCP: BindingExporter (the default) or BindingEndpoint

	ConnectTimeout time.Duration // the dial, the TLS handshake and the login, when the context has no deadline (30 s)
	ReadTimeout    time.Duration // each wait for a reply's frame (0: none); past it the connection is closed
	CancelWait     time.Duration // after a context ends a request: the wait for its end before closing (0: none)
}

// The engine's error codes (stable on the wire; a later imagedb may add codes).
const (
	CodeIO          = wire.CodeIO
	CodeCorrupt     = wire.CodeCorrupt
	CodeLimit       = wire.CodeLimit
	CodeInvalid     = wire.CodeInvalid
	CodeNoMem       = wire.CodeNoMem
	CodeConstraint  = wire.CodeConstraint
	CodeVerify      = wire.CodeVerify
	CodeAuth        = wire.CodeAuth
	CodeState       = wire.CodeState
	CodeSyntax      = wire.CodeSyntax
	CodeNotFound    = wire.CodeNotFound
	CodeUnsupported = wire.CodeUnsupported
	CodeHistory     = wire.CodeHistory
	CodeConflict    = wire.CodeConflict
	CodeCancelled   = wire.CodeCancelled
	CodePrivilege   = wire.CodePrivilege
)

// Error is the server's ERROR (Code, Index, Message) or the driver's own refusal with the same codes.
type Error struct {
	Code    int    // the engine's code (CodeIO ... CodePrivilege); one this driver does not know is kept as a number
	Index   int    // the failed statement's (or parameter set's) index in its batch
	Message string // the engine's words (never a row value)
	Closed  bool   // the connection ended with it (a KILL, a refused login, a protocol error, the server's close)
	Err     error  // the cause: the context that cancelled the request, or a TLS or I/O error
}

func (e *Error) Error() string {
	s := fmt.Sprintf("imagedb: %s (code %d", e.Message, e.Code)
	if e.Index > 0 {
		s += fmt.Sprintf(", statement %d", e.Index)
	}
	s += ")"
	if e.Closed {
		s += "; the connection closed"
	}
	if e.Err != nil {
		s += ": " + e.Err.Error()
	}
	return s
}

func (e *Error) Unwrap() error { return e.Err }

// Is matches an *Error of the same code (errors.Is(err, &imagedb.Error{Code: imagedb.CodeCancelled})).
func (e *Error) Is(target error) bool {
	t, ok := target.(*Error)
	return ok && t.Code == e.Code && t.Message == "" && t.Index == 0
}

var (
	// ErrBusy is a call on a Conn while another call, or a Rows still open, holds it (a Conn runs one request at a time;
	// Cancel alone may be called from another goroutine).
	ErrBusy = errors.New("imagedb: the connection is busy (another call, or a Rows not closed)")
	// ErrClosed is a call on a Conn closed or failed.
	ErrClosed = errors.New("imagedb: the connection is closed")
)

func errf(code int, format string, a ...any) *Error {
	return &Error{Code: code, Message: fmt.Sprintf(format, a...)}
}

// Conn is one connection: one session on the server. Its calls run one at a time (ErrBusy otherwise); Cancel may be
// called from any goroutine.
type Conn struct {
	nc  net.Conn
	tc  *tls.Conn // nil on the socket
	br  *bufio.Reader
	cfg Config

	op  sync.Mutex // a high-level call, or an open Rows
	wmu sync.Mutex // a frame written whole
	rmu sync.Mutex // frames read in order

	sent      atomic.Uint64 // requests sent (QUERY, PREPARE, EXECUTE, DEALLOCATE)
	readied   atomic.Uint64 // READYs read: a request is outstanding while sent > readied
	cancelReq atomic.Bool   // a cancel asked and not yet sent
	cancels   atomic.Uint64 // Cancel calls: a COPY upload stops at one
	cancelAt  atomic.Int64  // a context's end: the read deadline it set (unix ns; 0 none)
	boundAt   atomic.Int64  // a hard bound on reads (unix ns; 0 none): closedReason's 1 s, an answer's context ended

	cols   *wire.Columns // the last COLUMNS: the ROWS after it are read against it
	state  atomic.Uint32 // the last READY's state
	broken atomic.Pointer[error]
}

// Connect opens a connection and logs in.
func Connect(ctx context.Context, cfg Config) (*Conn, error) {
	if (cfg.Socket == "") == (cfg.Addr == "") {
		return nil, errf(CodeInvalid, "a Config names a Socket or an Addr, exactly one")
	}
	if !wire.UserOK(cfg.User) {
		return nil, errf(CodeInvalid, "a role's name is 1 to 63 bytes of UTF-8 without NUL")
	}
	if !wire.PasswordOK(cfg.Password) {
		return nil, errf(CodeInvalid, "a password is 1 to 1,024 printable ASCII bytes")
	}
	var tcfg *tls.Config
	if cfg.Addr != "" {
		var err error
		if tcfg, err = tlsConfig(&cfg); err != nil {
			return nil, err
		}
	}
	if _, ok := ctx.Deadline(); !ok {
		to := cfg.ConnectTimeout
		if to <= 0 {
			to = 30 * time.Second
		}
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, to)
		defer cancel()
	}
	var d net.Dialer
	network, addr := "unix", cfg.Socket
	if cfg.Addr != "" {
		network, addr = "tcp", cfg.Addr
	}
	nc, err := d.DialContext(ctx, network, addr)
	if err != nil {
		return nil, &Error{Code: CodeIO, Message: "connect " + addr, Err: err}
	}
	c := &Conn{nc: nc, cfg: cfg}
	if tcp, ok := nc.(*net.TCPConn); ok {
		tcp.SetNoDelay(true)
		tcp.SetKeepAliveConfig(net.KeepAliveConfig{Enable: true, Idle: 60 * time.Second, Interval: 10 * time.Second, Count: 6})
	}
	if err := c.login(ctx, tcfg); err != nil {
		nc.Close()
		return nil, err
	}
	c.br = bufio.NewReaderSize(c.nc, 64<<10)
	return c, nil
}

// tlsConfig is TLS 1.3 alone, ALPN imdbwir1, verified by the CA or the pin: there is no field that skips it.
func tlsConfig(cfg *Config) (*tls.Config, error) {
	hasCA := cfg.CAFile != "" || len(cfg.CAPEM) > 0
	if hasCA == (len(cfg.Pin) > 0) || (cfg.CAFile != "" && len(cfg.CAPEM) > 0) {
		return nil, errf(CodeInvalid, "TLS: a CA (CAFile or CAPEM) or a Pin, exactly one (no unverified mode)")
	}
	if cfg.Binding != BindingExporter && cfg.Binding != BindingEndpoint {
		return nil, errf(CodeInvalid, "TLS: a binding is the exporter or tls-server-end-point")
	}
	host, _, err := net.SplitHostPort(cfg.Addr)
	if err != nil {
		return nil, &Error{Code: CodeInvalid, Message: "an Addr is host:port", Err: err}
	}
	tc := &tls.Config{
		MinVersion: tls.VersionTLS13,
		MaxVersion: tls.VersionTLS13,
		NextProtos: []string{"imdbwir1"},
	}
	check := func(cs tls.ConnectionState) error { // after the chain's verification, before our first byte leaves
		if cs.Version != tls.VersionTLS13 {
			return errors.New("not TLS 1.3")
		}
		if cs.NegotiatedProtocol != "imdbwir1" {
			return errors.New("the peer does not speak imdbwir1 (ALPN)")
		}
		return nil
	}
	if hasCA {
		pem := cfg.CAPEM
		if cfg.CAFile != "" {
			if pem, err = os.ReadFile(cfg.CAFile); err != nil {
				return nil, &Error{Code: CodeIO, Message: "TLS: the CA file", Err: err}
			}
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, errf(CodeInvalid, "TLS: the CA holds no certificate")
		}
		tc.RootCAs = pool
		tc.ServerName = host // a name or an address literal, checked against subjectAltName
		tc.VerifyConnection = check
		return tc, nil
	}
	if len(cfg.Pin) != 32 {
		return nil, errf(CodeInvalid, "TLS: a pin is 32 bytes (the server key's SPKI SHA-256)")
	}
	pin := bytes.Clone(cfg.Pin)
	// pinned: the chain is not asked for, the key is (the certificate's SubjectPublicKeyInfo, so a renewed certificate
	// of the same key keeps its pin). Go checks only through VerifyConnection when InsecureSkipVerify is set; it is
	// always set here together with the pin's check, never alone.
	tc.InsecureSkipVerify = true
	tc.VerifyConnection = func(cs tls.ConnectionState) error {
		if len(cs.PeerCertificates) == 0 {
			return errors.New("the server sent no certificate")
		}
		got := sha256.Sum256(cs.PeerCertificates[0].RawSubjectPublicKeyInfo)
		if subtle.ConstantTimeCompare(got[:], pin) != 1 {
			return errors.New("the server's key is not the pinned one")
		}
		return check(cs)
	}
	return tc, nil
}

// PinOf is the pin of a certificate (PEM or DER): its key's SPKI SHA-256, what `imagedb-server cert` prints.
func PinOf(cert []byte) ([]byte, error) {
	if b, _ := pem.Decode(cert); b != nil {
		cert = b.Bytes
	}
	x, err := x509.ParseCertificate(cert)
	if err != nil {
		return nil, err
	}
	h := sha256.Sum256(x.RawSubjectPublicKeyInfo)
	return h[:], nil
}

// ParsePin reads a pin's 64 hex digits.
func ParsePin(s string) ([]byte, error) {
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != 32 {
		return nil, errf(CodeInvalid, "a pin is 64 hex digits")
	}
	return b, nil
}

// endpointBinding is RFC 5929's tls-server-end-point: the certificate's hash by its signature's hash (MD5 and SHA-1
// taken to SHA-256). A server allowing this binding refuses at its start a certificate signed with another hash than
// SHA-256, so SHA-256 is the one computed; another is refused here rather than guessed.
func endpointBinding(cert *x509.Certificate) ([]byte, error) {
	switch cert.SignatureAlgorithm {
	case x509.SHA256WithRSA, x509.SHA256WithRSAPSS, x509.ECDSAWithSHA256, x509.MD5WithRSA, x509.SHA1WithRSA,
		x509.ECDSAWithSHA1, x509.DSAWithSHA1, x509.DSAWithSHA256:
		h := sha256.Sum256(cert.Raw)
		return h[:], nil
	}
	return nil, fmt.Errorf("tls-server-end-point: a certificate signed with %v (SHA-256 alone is computed)", cert.SignatureAlgorithm)
}

// login is the pre-auth exchange (§4): the hello, the challenge, the proof over the AuthMessage, the verdict and the
// server's signature.
func (c *Conn) login(ctx context.Context, tcfg *tls.Config) (err error) {
	dl, _ := ctx.Deadline()
	c.nc.SetDeadline(dl)
	raw := c.nc                                                                 // the socket itself: c.nc becomes the TLS connection below, while this func may run
	stop := context.AfterFunc(ctx, func() { raw.SetDeadline(time.Unix(1, 0)) }) // a cancelled ctx stops the exchange
	defer func() {
		if !stop() && err == nil {
			err = &Error{Code: CodeIO, Message: "login", Err: ctx.Err()}
		}
		c.nc.SetDeadline(time.Time{})
	}()
	ep, flags := wire.EndpointUnix, wire.BindingNone
	var binding [wire.KeyLen]byte
	if tcfg != nil {
		tc := tls.Client(c.nc, tcfg)
		if err := tc.HandshakeContext(ctx); err != nil { // the pin and the names checked here, before the hello names the role
			return &Error{Code: CodeAuth, Message: "TLS handshake", Err: err}
		}
		c.tc, c.nc = tc, tc
		cs := tc.ConnectionState()
		ep, flags = wire.EndpointTCP, wire.BindingExporter
		var b []byte
		if c.cfg.Binding == BindingEndpoint {
			flags = wire.BindingEndpoint
			b, err = endpointBinding(cs.PeerCertificates[0])
		} else {
			b, err = cs.ExportKeyingMaterial("EXPORTER-Channel-Binding", []byte{}, wire.KeyLen) // RFC 9266: empty context
		}
		if err != nil {
			return &Error{Code: CodeState, Message: "TLS: the channel binding", Err: err}
		}
		copy(binding[:], b)
		clear(b)
	}
	h := wire.Hello{Version: wire.Version, Flags: flags, User: c.cfg.User}
	if _, err := rand.Read(h.Nonce[:]); err != nil {
		return &Error{Code: CodeIO, Message: "random", Err: err}
	}
	hello, err := h.Encode()
	if err != nil {
		return &Error{Code: CodeInvalid, Message: "a hello its encoder refuses", Err: err}
	}
	if _, err := c.nc.Write(hello); err != nil {
		return &Error{Code: CodeIO, Message: "the hello", Err: err}
	}
	chb := make([]byte, wire.ChallengeLen)
	if _, err := io.ReadFull(c.nc, chb[:wire.PreauthHead]); err != nil { // the head first: a server of another version
		return &Error{Code: CodeIO, Message: "the challenge", Err: err} //   answers with its own 12 bytes and closes
	}
	ver, err := wire.DecodePreauthHead(chb)
	if err != nil {
		return wireErr(err, "the server's head")
	}
	if ver != wire.Version {
		return errf(CodeUnsupported, "the server speaks IMDBWIR1 version %d, not 1", ver)
	}
	if _, err := io.ReadFull(c.nc, chb[wire.PreauthHead:]); err != nil {
		return &Error{Code: CodeIO, Message: "the challenge", Err: err}
	}
	ch, err := wire.DecodeChallenge(chb)
	if err != nil {
		return wireErr(err, "the challenge")
	}
	am := wire.AuthMessage(ep, hello, chb, &binding)
	proof, want, err := wire.ScramClient(c.cfg.Password, &ch, am)
	clear(binding[:])
	if err != nil {
		return &Error{Code: CodeInvalid, Message: "a password is 1 to 1,024 printable ASCII bytes", Err: err}
	}
	defer clear(proof[:])
	defer clear(want[:])
	if _, err := c.nc.Write(proof[:]); err != nil {
		return &Error{Code: CodeIO, Message: "the proof", Err: err}
	}
	vb := make([]byte, wire.VerdictLen)
	if _, err := io.ReadFull(c.nc, vb); err != nil {
		return &Error{Code: CodeIO, Message: "the verdict", Err: err}
	}
	v, err := wire.DecodeVerdict(vb)
	if err != nil {
		return wireErr(err, "the verdict")
	}
	switch {
	case v.Code == wire.VerdictBinding: // never retried with another type: no downgrade (§8f)
		return errf(CodeAuth, "the server refuses this login's channel binding type (%s)", bindingName(flags))
	case v.Code != wire.VerdictOK:
		return errf(CodeAuth, "authentication refused")
	case subtle.ConstantTimeCompare(v.Sig[:], want[:]) != 1:
		return errf(CodeAuth, "the server did not prove it holds the verifier")
	}
	return nil
}

func bindingName(b wire.Binding) string {
	switch b {
	case wire.BindingExporter:
		return "tls-exporter"
	case wire.BindingEndpoint:
		return "tls-server-end-point"
	}
	return "none"
}

func wireErr(err error, what string) *Error {
	var we *wire.Error
	if errors.As(err, &we) {
		return &Error{Code: we.Code, Message: what + ": " + we.Msg}
	}
	return &Error{Code: CodeCorrupt, Message: what, Err: err}
}

// ---- frames ----

func isRequest(t wire.FrameType) bool {
	return t == wire.TQuery || t == wire.TPrepare || t == wire.TExecute || t == wire.TDeallocate
}

func (c *Conn) outstanding() bool { return c.sent.Load() > c.readied.Load() }

func (c *Conn) failed() error {
	if p := c.broken.Load(); p != nil {
		return *p
	}
	return nil
}

// fail marks the connection unusable (its first error kept for the calls after) and closes it; it returns err.
func (c *Conn) fail(err error) error {
	c.broken.CompareAndSwap(nil, &err)
	c.nc.Close()
	return err
}

var cancelFrame = []byte{1, 0, 0, 0, byte(wire.TCancel)}

// writeLocked writes bytes under wmu; a write that fails marks the connection's write side closed.
func (c *Conn) writeLocked(p []byte) error {
	_, err := c.nc.Write(p)
	return err
}

// Send writes one frame (the protocol's level). A request (QUERY, PREPARE, EXECUTE, DEALLOCATE) counts as outstanding
// until its READY is read; a cancel asked while none was outstanding is dropped here (it would cancel this request), and
// one asked while this client sends (a COPY's data) goes out before the frame (§4, the C client's rules). A send that
// finds the connection closed reports the server's last ERROR when it is the last frame before the close.
func (c *Conn) Send(m wire.Msg) error {
	_, err := c.send(m)
	return err
}

// send is Send, giving a request's generation (its number among the requests sent: outstanding while readied < gen).
func (c *Conn) send(m wire.Msg) (uint64, error) {
	if err := c.failed(); err != nil {
		return 0, err
	}
	frame, err := wire.AppendFrame(nil, m, nil)
	if err != nil {
		return 0, wireErr(err, "a request")
	}
	req := isRequest(m.Type())
	var gen uint64
	c.wmu.Lock()
	if req && !c.outstanding() {
		c.cancelReq.Store(false) // asked while nothing ran: for nothing
	} else if c.outstanding() && c.cancelReq.Swap(false) {
		if err := c.writeLocked(cancelFrame); err != nil {
			c.wmu.Unlock()
			return 0, c.closedReason(err)
		}
	}
	if req { // outstanding from its first byte: a Cancel under wmu after this sees it
		gen = c.sent.Add(1)
	}
	err = c.writeLocked(frame)
	c.wmu.Unlock()
	if err != nil {
		return 0, c.closedReason(err)
	}
	return gen, nil
}

// Cancel cancels the statement this connection's request runs (in band: a CANCEL frame on its own stream); callable
// from any goroutine. One asked while no request is outstanding does nothing. The server cancels only a statement
// running when the CANCEL arrives: one sent before the statement starts is lost (a context's end re-sends it).
func (c *Conn) Cancel() {
	c.cancels.Add(1)
	c.cancelReq.Store(true)
	if c.wmu.TryLock() {
		c.flushCancelLocked()
		c.wmu.Unlock()
		return
	}
	go func() { // a writer holds the stream (a COPY's data): it sends the cancel before its next frame, or this does
		c.wmu.Lock()
		c.flushCancelLocked()
		c.wmu.Unlock()
	}()
}

func (c *Conn) flushCancelLocked() {
	if !c.outstanding() {
		c.cancelReq.Store(false)
		return
	}
	if c.cancelReq.Swap(false) {
		c.writeLocked(cancelFrame) // a failure: the reader meets the close
	}
}

// cancelGen sends CANCEL if request gen (the gen-th sent) is still outstanding: never one that reached a later request.
func (c *Conn) cancelGen(gen uint64) {
	c.wmu.Lock()
	if c.readied.Load() < gen && c.failed() == nil {
		c.writeLocked(cancelFrame)
	}
	c.wmu.Unlock()
}

// closedReason: a send found the connection closed. What the server sent before its close is still to be read, and
// when its last frame is an ERROR, that is why it closed: that ERROR is reported (client.c's closed_reason; at most 64
// frames, 1 s). An ERROR followed by any frame answered something else: the I/O error then.
func (c *Conn) closedReason(werr error) error {
	ioErr := &Error{Code: CodeIO, Message: "the connection: a write failed", Closed: true, Err: werr}
	if !c.rmu.TryLock() { // another goroutine reads: it meets the close itself
		return c.fail(ioErr)
	}
	defer c.rmu.Unlock()
	c.boundAt.Store(time.Now().Add(time.Second).UnixNano()) // readFull honours it (a plain SetReadDeadline it would replace)
	var last *wire.ErrorMsg
	ended := false
	for k := 0; k < 64 && !ended; k++ {
		m, err := c.nextLocked()
		if err != nil {
			ended = true
		} else if e, ok := m.(wire.ErrorMsg); ok {
			last = &e
		} else {
			last = nil
		}
	}
	if !ended || last == nil {
		return c.fail(ioErr)
	}
	return c.fail(&Error{Code: int(last.Code), Index: int(last.Index), Message: last.Message, Closed: true})
}

// readFull reads exactly len(p) bytes, the deadline set first: the earliest of Config.ReadTimeout, a context's
// CancelWait (cancelAt) and a hard bound (boundAt). Another goroutine may store a bound and set the deadline itself while
// this sets it: the bounds are read again after the set, and the set made again when one moved, so a later deadline
// computed from a stale read never replaces theirs.
func (c *Conn) readFull(p []byte) error {
	for {
		ca, ba := c.cancelAt.Load(), c.boundAt.Load()
		var dl time.Time
		if c.cfg.ReadTimeout > 0 {
			dl = time.Now().Add(c.cfg.ReadTimeout)
		}
		for _, at := range [2]int64{ca, ba} {
			if at != 0 && (dl.IsZero() || at < dl.UnixNano()) {
				dl = time.Unix(0, at)
			}
		}
		c.nc.SetReadDeadline(dl)
		if c.cancelAt.Load() == ca && c.boundAt.Load() == ba {
			break
		}
	}
	_, err := io.ReadFull(c.br, p)
	return err
}

// Next reads the next reply, decoded (the protocol's level): a ROWS against the last COLUMNS. A frame the decoder
// refuses ends the connection, the error naming it.
func (c *Conn) Next() (wire.Msg, error) {
	c.rmu.Lock()
	defer c.rmu.Unlock()
	return c.nextLocked()
}

func (c *Conn) nextLocked() (wire.Msg, error) {
	if err := c.failed(); err != nil {
		return nil, err
	}
	var head [wire.HeadLen]byte
	if err := c.readFull(head[:]); err != nil {
		return nil, c.fail(ioError(err))
	}
	n, t, err := wire.DecodeHead(head[:], true)
	if err != nil {
		return nil, c.fail(&Error{Code: CodeCorrupt, Message: fmt.Sprintf("the server's frame head (%s) refused: %v", t, err)})
	}
	body := make([]byte, n-1)
	if err := c.readFull(body); err != nil {
		return nil, c.fail(ioError(err))
	}
	m, err := wire.DecodeBody(t, body, c.cols)
	if err != nil {
		var we *wire.Error
		code := CodeCorrupt
		if errors.As(err, &we) {
			code = we.Code
		}
		return nil, c.fail(&Error{Code: code, Message: fmt.Sprintf("the server's %s frame refused: %v", t, err), Closed: true})
	}
	switch m := m.(type) {
	case wire.Columns:
		c.cols = &m
	case wire.Ready:
		c.state.Store(uint32(m.State))
		c.readied.Add(1)
	}
	return m, nil
}

func ioError(err error) *Error {
	var ne net.Error
	switch {
	case errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF):
		return &Error{Code: CodeIO, Message: "the connection: closed by the server", Closed: true, Err: err}
	case errors.As(err, &ne) && ne.Timeout():
		return &Error{Code: CodeIO, Message: "no reply in time", Closed: true, Err: err}
	}
	return &Error{Code: CodeIO, Message: "the connection: a read failed", Closed: true, Err: err}
}

// Columns is the last COLUMNS read (the one a ROWS is read against), or nil.
func (c *Conn) Columns() *wire.Columns { return c.cols }

// TxState is the session's state at the last READY: wire.Idle, wire.InTxn or wire.Doomed (it takes only ROLLBACK).
func (c *Conn) TxState() int { return int(c.state.Load()) }

// Err is the error that made the connection unusable, or nil.
func (c *Conn) Err() error { return c.failed() }

// Close ends the session (TERMINATE: an open transaction rolled back) and the connection.
func (c *Conn) Close() error {
	if c.failed() != nil {
		c.nc.Close()
		return nil
	}
	c.nc.SetWriteDeadline(time.Now().Add(time.Second)) // first: a writer stalled on a full socket fails and lets go
	c.wmu.Lock()
	f, _ := wire.AppendFrame(nil, wire.Terminate{}, nil)
	c.writeLocked(f)
	c.wmu.Unlock()
	c.fail(ErrClosed)
	return nil
}
