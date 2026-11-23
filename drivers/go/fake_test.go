package imagedb

// A fake server on a Unix socket under the test's temporary directory (TMPDIR, the scratch directory's tmp/ in
// run_tests.sh): the client's side of what no live server does on demand (a wrong signature, a refused frame, a close
// after an ERROR, a CANCEL lost) checked against §4's rules, offline.

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"imagedb.dev/imagedb/wire"
)

const fakePW = "fake-pw"

type fakeOpts struct {
	head    []byte // the challenge's first 12 bytes replaced (another version or magic)
	verdict uint32
	badSig  bool
}

type fakeServer struct {
	t       *testing.T
	ln      net.Listener
	path    string
	opts    fakeOpts
	sess    chan *fakeSess
	accepts atomic.Int32 // connections taken: a refused binding is never retried with another type
}

type fakeSess struct {
	t *testing.T
	c net.Conn
}

func newFake(t *testing.T, o fakeOpts) *fakeServer {
	t.Helper()
	p := filepath.Join(t.TempDir(), "s")
	ln, err := net.Listen("unix", p)
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeServer{t: t, ln: ln, path: p, opts: o, sess: make(chan *fakeSess, 4)}
	go f.accept()
	t.Cleanup(func() { ln.Close() })
	return f
}

func (f *fakeServer) accept() {
	for {
		c, err := f.ln.Accept()
		if err != nil {
			return
		}
		f.accepts.Add(1)
		go f.login(c)
	}
}

func (f *fakeServer) login(c net.Conn) {
	hb := make([]byte, wire.HelloLen)
	if _, err := io.ReadFull(c, hb); err != nil {
		c.Close()
		return
	}
	h, err := wire.DecodeHello(hb)
	if err != nil || h.Flags != wire.BindingNone {
		c.Close()
		return
	}
	ch := wire.Challenge{Version: 1, Salt: bytes.Repeat([]byte{7}, 16), Iter: 1000}
	cb, _ := ch.Encode()
	if f.opts.head != nil {
		c.Write(f.opts.head)
		c.Close()
		return
	}
	c.Write(cb)
	var proof [32]byte
	if _, err := io.ReadFull(c, proof[:]); err != nil {
		c.Close()
		return
	}
	var zero [32]byte
	am := wire.AuthMessage(wire.EndpointUnix, hb, cb, &zero)
	stored, skey, _ := wire.ScramVerifier(fakePW, ch.Salt, ch.Iter)
	ok, sig := wire.ScramServer(&stored, &skey, am, &proof)
	v := wire.Verdict{Code: f.opts.verdict, Sig: sig}
	if !ok {
		v.Code = wire.VerdictRefused
	}
	if v.Code != 0 {
		v.Sig = [32]byte{}
	}
	if f.opts.badSig {
		v.Sig[0] ^= 1
	}
	vb, _ := v.Encode()
	c.Write(vb)
	if v.Code != 0 {
		c.Close()
		return
	}
	f.sess <- &fakeSess{t: f.t, c: c}
}

func (f *fakeServer) connect(t *testing.T) (*Conn, *fakeSess) {
	t.Helper()
	c, err := Connect(context.Background(), Config{Socket: f.path, User: "u", Password: fakePW})
	if err != nil {
		t.Fatal(err)
	}
	select {
	case s := <-f.sess:
		t.Cleanup(func() { s.c.Close(); c.Close() })
		return c, s
	case <-time.After(5 * time.Second):
		t.Fatal("no session")
	}
	return nil, nil
}

// read is the next client frame.
func (s *fakeSess) read() wire.Msg {
	s.t.Helper()
	var h [5]byte
	if _, err := io.ReadFull(s.c, h[:]); err != nil {
		return nil // the connection closed: the test is over
	}
	n, ty, err := wire.DecodeHead(h[:], false)
	if err != nil {
		s.t.Errorf("fake: head: %v", err)
		return nil
	}
	b := make([]byte, n-1)
	if _, err := io.ReadFull(s.c, b); err != nil {
		return nil
	}
	m, err := wire.DecodeBody(ty, b, nil)
	if err != nil {
		s.t.Errorf("fake: body: %v", err)
	}
	return m
}

func (s *fakeSess) write(cols *wire.Columns, ms ...wire.Msg) {
	s.t.Helper()
	var b []byte
	for _, m := range ms {
		var err error
		if b, err = wire.AppendFrame(b, m, cols); err != nil {
			s.t.Fatalf("fake: encode %s: %v", m.Type(), err)
		}
	}
	s.c.Write(b)
}

func asErr(t *testing.T, err error) *Error {
	t.Helper()
	var e *Error
	if !errors.As(err, &e) {
		t.Fatalf("not an *Error: %v", err)
	}
	return e
}

func TestFakeLogin(t *testing.T) {
	f := newFake(t, fakeOpts{})
	c, _ := f.connect(t)
	if c.Err() != nil {
		t.Fatal(c.Err())
	}
	for _, x := range []struct {
		o    fakeOpts
		pw   string
		code int
		msg  string
	}{
		{fakeOpts{}, "wrong-pw", CodeAuth, "authentication refused"},
		{fakeOpts{badSig: true}, fakePW, CodeAuth, "did not prove it holds the verifier"},
		{fakeOpts{verdict: wire.VerdictBinding}, fakePW, CodeAuth, "channel binding type"},
		{fakeOpts{head: []byte("IMDBWIR1\x02\x00\x00\x00")}, fakePW, CodeUnsupported, "version 2, not 1"},
		{fakeOpts{head: []byte("IMDBWIR2\x01\x00\x00\x00")}, fakePW, CodeUnsupported, "IMDBWIR2"},
		{fakeOpts{head: []byte("XMDBWIR1\x01\x00\x00\x00")}, fakePW, CodeCorrupt, "not imagedb's protocol"},
	} {
		f := newFake(t, x.o)
		_, err := Connect(context.Background(), Config{Socket: f.path, User: "u", Password: x.pw})
		e := asErr(t, err)
		if e.Code != x.code || !strings.Contains(e.Error(), x.msg) || f.accepts.Load() != 1 {
			t.Fatalf("%+v: %v", x.o, err)
		}
	}
	// a Config that cannot make an unverified or plaintext TCP connection
	for _, cfg := range []Config{
		{Addr: "127.0.0.1:1", User: "u", Password: "p"},                                      // neither CA nor pin
		{Addr: "127.0.0.1:1", User: "u", Password: "p", CAFile: "x", Pin: make([]byte, 32)},  // both
		{Addr: "127.0.0.1:1", User: "u", Password: "p", Pin: make([]byte, 31)},               // a short pin
		{Socket: "/x", Addr: "127.0.0.1:1", User: "u", Password: "p"},                        // both endpoints
		{Socket: "/x", User: "", Password: "p"}, {Socket: "/x", User: "u", Password: "\x01"}, // bad name, password
	} {
		if _, err := Connect(context.Background(), cfg); asErr(t, err).Code != CodeInvalid {
			t.Fatalf("%+v: %v", cfg, err)
		}
	}
}

// TestFakeRefusedFrame: a frame the decoder refuses ends the connection, the error naming it.
func TestFakeRefusedFrame(t *testing.T) {
	f := newFake(t, fakeOpts{})
	c, s := f.connect(t)
	go func() {
		s.read()
		// a ROWS with no COLUMNS before it, by hand
		s.c.Write([]byte{6, 0, 0, 0, byte(wire.TRows), 1, 0, 0, 0, 0x81})
	}()
	_, err := c.Exec(context.Background(), "SELECT 1")
	e := asErr(t, err)
	if !strings.Contains(e.Message, "ROWS frame refused") || !e.Closed || c.Err() == nil {
		t.Fatalf("%v", err)
	}
	if _, err := c.Exec(context.Background(), "SELECT 1"); err == nil {
		t.Fatal("a failed connection used again")
	}
}

// TestFakeClosedReason: a send that finds the connection closed reports the server's last ERROR when it is the last
// frame before the close; an ERROR followed by another frame gives the I/O error.
func TestFakeClosedReason(t *testing.T) {
	for _, tail := range []bool{false, true} {
		f := newFake(t, fakeOpts{})
		c, s := f.connect(t)
		ms := []wire.Msg{wire.ErrorMsg{Code: 15, Message: "ended by a KILL"}}
		if tail {
			ms = append(ms, wire.Pong{})
		}
		s.write(nil, ms...)
		s.c.Close()
		time.Sleep(100 * time.Millisecond)
		var err error
		sends := 0
		for err == nil && sends < 3 { // the failed send itself (Send: no reply read)
			err = c.Send(wire.Query{Stmts: []wire.Statement{{SQL: "SELECT 1"}}})
			sends++
		}
		t.Logf("the send failed at attempt %d", sends)
		e := asErr(t, err)
		if tail {
			if e.Code != CodeIO || !e.Closed {
				t.Fatalf("an ERROR then a PONG: %v", err)
			}
			continue
		}
		if e.Code != 15 || e.Message != "ended by a KILL" || !e.Closed {
			t.Fatalf("the close's reason: %v", err)
		}
	}
	// an ERROR met by the close instead of READY, as a request's reply
	f := newFake(t, fakeOpts{})
	c, s := f.connect(t)
	go func() {
		s.read()
		s.write(nil, wire.ErrorMsg{Code: 3, Message: "the role's connections are at its cap"})
		s.c.Close()
	}()
	_, err := c.Exec(context.Background(), "SELECT 1")
	if e := asErr(t, err); e.Code != 3 || !e.Closed {
		t.Fatalf("ERROR then the close: %v", err)
	}
}

// TestFakeSilentPeer: the reads that follow a failed send (closed_reason) are bounded at 1 s whatever Config.ReadTimeout
// says (here none): a server that stops reading (shutdown of its read side: the send fails, EPIPE) but neither writes
// nor closes. And an out-of-turn answer's context bounds its wait the same way (PING to a server that never answers).
// Before the bound was readFull's own (boundAt), readFull's deadline replaced closedReason's and both waits were endless.
func TestFakeSilentPeer(t *testing.T) {
	f := newFake(t, fakeOpts{})
	c, s := f.connect(t)
	if err := s.c.(*net.UnixConn).CloseRead(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	start := time.Now()
	go func() {
		var err error
		for i := 0; err == nil && i < 3; i++ {
			err = c.Send(wire.Query{Stmts: []wire.Statement{{SQL: "SELECT 1"}}})
		}
		done <- err
	}()
	select {
	case err := <-done:
		took := time.Since(start)
		if e := asErr(t, err); e.Code != CodeIO || !e.Closed || took < 900*time.Millisecond || took > 4*time.Second {
			t.Fatalf("a send to a silent peer: %v after %v", err, took)
		}
		t.Logf("the send's error after %v: %v", took, err)
	case <-time.After(8 * time.Second):
		t.Fatal("closed_reason's reads are unbounded (no error within 8 s)")
	}
	// PING whose answer never comes: its context's end ends the wait (the connection closed: out of step otherwise)
	f2 := newFake(t, fakeOpts{})
	c2, s2 := f2.connect(t)
	go func() {
		for s2.read() != nil {
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	go func() { done <- c2.Ping(ctx) }()
	select {
	case err := <-done:
		if !errors.Is(err, context.DeadlineExceeded) || c2.Err() == nil {
			t.Fatalf("a PING's context: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("a PING's context did not end its wait within 5 s")
	}
}

// TestFakeCancel: a cancel asked with nothing outstanding sends nothing (it would cancel the next request); one asked
// while a request runs is sent at once; a context's end re-sends it while the request is outstanding (a CANCEL that
// arrives before the statement starts is lost), and its ERROR 15 wraps the context's error.
func TestFakeCancel(t *testing.T) {
	f := newFake(t, fakeOpts{})
	c, s := f.connect(t)
	c.Cancel() // nothing outstanding: dropped
	got := make(chan wire.Msg, 8)
	go func() {
		for {
			m := s.read()
			if m == nil {
				return
			}
			got <- m
		}
	}()
	done := make(chan error)
	go func() { _, err := c.Exec(context.Background(), "SELECT 1"); done <- err }()
	if m := next(t, got); m.Type() != wire.TQuery {
		t.Fatalf("first frame %s: the dropped cancel was sent", m.Type())
	}
	c.Cancel() // the request outstanding: sent
	if m := next(t, got); m.Type() != wire.TCancel {
		t.Fatalf("%s, want CANCEL", m.Type())
	}
	s.write(nil, wire.ErrorMsg{Code: 15, Message: "cancelled"}, wire.Ready{})
	if e := asErr(t, <-done); e.Code != 15 {
		t.Fatal(e)
	}
	select {
	case m := <-got:
		t.Fatalf("a frame after READY: %s", m.Type())
	case <-time.After(300 * time.Millisecond):
	}
	// a context's end: the first CANCEL ignored (the statement not started), the second answered
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	go func() { _, err := c.Exec(ctx, "SELECT 2"); done <- err }()
	if m := next(t, got); m.Type() != wire.TQuery {
		t.Fatal(m.Type())
	}
	if m := next(t, got); m.Type() != wire.TCancel {
		t.Fatal(m.Type())
	}
	if m := next(t, got); m.Type() != wire.TCancel {
		t.Fatal("the cancel was not sent again")
	}
	s.write(nil, wire.ErrorMsg{Code: 15, Message: "cancelled"}, wire.Ready{})
	err := <-done
	if e := asErr(t, err); e.Code != 15 || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("%v", err)
	}
	select { // no CANCEL once its READY is read (it would reach the next request)
	case m := <-got:
		t.Fatalf("a frame after READY: %s", m.Type())
	case <-time.After(600 * time.Millisecond):
	}
}

// TestFakeCopyCancel: a Cancel asked while the client uploads goes out before its next COPY_DATA and ends the upload
// with COPY_FAIL (§4: the client still ends its COPY); a context's end ends it the same way, its CANCEL re-sent.
func TestFakeCopyCancel(t *testing.T) {
	for _, byCtx := range []bool{false, true} {
		f := newFake(t, fakeOpts{})
		c, s := f.connect(t)
		ctx, cancel := context.WithCancel(context.Background())
		reads := 0
		r := readerFunc(func(p []byte) (int, error) {
			reads++
			if reads == 2 { // the user's other goroutine, as it were, between two pieces
				if byCtx {
					cancel()
				} else {
					c.Cancel()
				}
			}
			return copy(p, "1,a\n"), nil
		})
		frames := make(chan wire.Msg, 64)
		go func() {
			for {
				m := s.read()
				if m == nil {
					return
				}
				frames <- m
			}
		}()
		done := make(chan error)
		go func() { _, err := c.CopyFrom(ctx, "COPY t FROM STDIN", r); done <- err }()
		if m := next(t, frames); m.Type() != wire.TQuery {
			t.Fatal(m.Type())
		}
		s.write(nil, wire.CopyIn{})
		var seq []wire.FrameType
		for {
			m := next(t, frames)
			seq = append(seq, m.Type())
			if m.Type() == wire.TCopyFail {
				if !strings.Contains(m.(wire.CopyFail).Message, "cancelled") {
					t.Fatal(m)
				}
				break
			}
		}
		if !byCtx && (len(seq) != 4 || seq[0] != wire.TCopyData || seq[1] != wire.TCancel || seq[2] != wire.TCopyData) {
			t.Fatalf("frames %v: want COPY_DATA, CANCEL, COPY_DATA, COPY_FAIL", seq)
		}
		s.write(nil, wire.ErrorMsg{Code: 15, Message: "cancelled by the client"}, wire.Ready{})
		err := <-done
		if asErr(t, err).Code != 15 || byCtx != errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
		cancel()
	}
}

type readerFunc func([]byte) (int, error)

func (f readerFunc) Read(p []byte) (int, error) { return f(p) }

// TestFakeOutOfTurn: the protocol's level pipelines; PING's PONG comes out of turn; a high-level call that meets an answer
// it did not ask for refuses it.
func TestFakeOutOfTurn(t *testing.T) {
	f := newFake(t, fakeOpts{})
	c, s := f.connect(t)
	if err := c.Send(wire.Query{Stmts: []wire.Statement{{SQL: "SELECT 1"}}}); err != nil {
		t.Fatal(err)
	}
	if err := c.Send(wire.Ping{}); err != nil {
		t.Fatal(err)
	}
	if s.read().Type() != wire.TQuery || s.read().Type() != wire.TPing {
		t.Fatal("order")
	}
	cols := &wire.Columns{Cols: []wire.Column{{Name: "x", Type: wire.TypeInt64}}}
	rows, _ := wire.NewRows(cols, [][]wire.Value{{{Type: wire.TypeInt64, I: 1}}})
	s.write(cols, wire.Pong{}, *cols, rows, wire.Done{Status: "SELECT 1", Count: 1}, wire.Ready{})
	want := []wire.FrameType{wire.TPong, wire.TColumns, wire.TRows, wire.TDone, wire.TReady}
	for _, w := range want {
		m, err := c.Next()
		if err != nil || m.Type() != w {
			t.Fatalf("%v %v, want %s", m, err, w)
		}
	}
	go func() {
		s.read()
		s.write(nil, wire.Pong{})
	}()
	if _, err := c.Exec(context.Background(), "SELECT 1"); asErr(t, err).Code != CodeState || c.Err() == nil {
		t.Fatalf("an unasked PONG: %v", err)
	}
}

// TestFakeRows: rows streamed, an ERROR after some ROWS surfacing through Rows.Err, a COPY_IN met by Query answered
// with COPY_FAIL.
func TestFakeRows(t *testing.T) {
	f := newFake(t, fakeOpts{})
	c, s := f.connect(t)
	cols := &wire.Columns{Cols: []wire.Column{{Name: "x", Type: wire.TypeInt64}, {Name: "t", Type: wire.TypeText}}}
	rows, _ := wire.NewRows(cols, [][]wire.Value{{{Type: wire.TypeInt64, I: 1}, {Type: wire.TypeText, S: []byte("a")}},
		{{Null: true, Type: wire.TypeInt64}, {Null: true, Type: wire.TypeText}}})
	go func() {
		s.read()
		s.write(cols, *cols, rows, rows, wire.ErrorMsg{Code: 3, Message: "a row longer than a frame"}, wire.Ready{})
	}()
	r, err := c.Query(context.Background(), "SELECT x, t FROM y")
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for r.Next() {
		var x *int64
		var s *string
		if err := r.Scan(&x, &s); err != nil {
			t.Fatal(err)
		}
		if n%2 == 0 && (x == nil || *x != 1 || *s != "a") || n%2 == 1 && (x != nil || s != nil) {
			t.Fatalf("row %d", n)
		}
		n++
	}
	if n != 4 || asErr(t, r.Err()).Code != 3 {
		t.Fatalf("%d rows, %v", n, r.Err())
	}
	r.Close()
	go func() {
		s.read()
		s.write(nil, wire.CopyIn{})
		if m := s.read(); m.Type() != wire.TCopyFail {
			t.Errorf("%s, want COPY_FAIL", m.Type())
		}
		s.write(nil, wire.ErrorMsg{Code: 15, Message: copyViaQuery}, wire.Ready{})
	}()
	if _, err := c.Exec(context.Background(), "COPY y FROM STDIN"); asErr(t, err).Code != 15 {
		t.Fatal(err)
	}
	if c.Err() != nil {
		t.Fatal("the connection lost its step")
	}
	_ = binary.LittleEndian
}

// TestFakeTimeouts: Config.ReadTimeout bounds each wait for a reply (the connection then closed); Config.CancelWait
// bounds the wait for a request a context ended, once its CANCEL is sent (a server that never answers).
func TestFakeTimeouts(t *testing.T) {
	f := newFake(t, fakeOpts{})
	c, err := Connect(context.Background(), Config{Socket: f.path, User: "u", Password: fakePW, ReadTimeout: 150 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	s := <-f.sess
	defer s.c.Close()
	start := time.Now()
	_, err = c.Exec(context.Background(), "SELECT 1")
	if e := asErr(t, err); e.Code != CodeIO || !e.Closed || time.Since(start) > 2*time.Second || c.Err() == nil {
		t.Fatalf("a read timeout: %v after %v", err, time.Since(start))
	}
	c2, err := Connect(context.Background(), Config{Socket: f.path, User: "u", Password: fakePW, CancelWait: 300 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	s2 := <-f.sess
	defer s2.c.Close()
	go func() { // reads the request and its CANCELs, answers nothing
		for s2.read() != nil {
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start = time.Now()
	_, err = c2.Exec(ctx, "SELECT 1")
	took := time.Since(start)
	if !errors.Is(err, context.DeadlineExceeded) || c2.Err() == nil || took < 350*time.Millisecond || took > 3*time.Second {
		t.Fatalf("CancelWait: %v after %v", err, took)
	}
}

// next is the fake's next frame from the client, or the test's failure within 5 s (a mutant that never sends it).
func next(t *testing.T, ch chan wire.Msg) wire.Msg {
	t.Helper()
	select {
	case m := <-ch:
		return m
	case <-time.After(5 * time.Second):
		t.Fatal("no frame from the client within 5 s")
	}
	return nil
}

// TestFakePendingCancel: a cancel pending when the client sends (its goroutine still waiting for the stream) goes out
// before the frame while a request is outstanding (a COPY's data: §4's "before its next frame"), and is dropped when the
// frame is a request sent with none outstanding (it would cancel that request).
func TestFakePendingCancel(t *testing.T) {
	f := newFake(t, fakeOpts{})
	c, s := f.connect(t)
	if err := c.Send(wire.Query{Stmts: []wire.Statement{{SQL: "COPY t FROM STDIN"}}}); err != nil {
		t.Fatal(err)
	}
	c.cancelReq.Store(true) // as Cancel leaves it when a writer holds the stream
	if err := c.Send(wire.CopyData{Data: []byte("1\n")}); err != nil {
		t.Fatal(err)
	}
	for _, w := range []wire.FrameType{wire.TQuery, wire.TCancel, wire.TCopyData} {
		if m := s.read(); m == nil || m.Type() != w {
			t.Fatalf("%v, want %s", m, w)
		}
	}
	s.write(nil, wire.ErrorMsg{Code: 15, Message: "cancelled"}, wire.Ready{})
	for {
		m, err := c.Next()
		if err != nil {
			t.Fatal(err)
		}
		if m.Type() == wire.TReady {
			break
		}
	}
	c.cancelReq.Store(true) // nothing outstanding now
	if err := c.Send(wire.Query{Stmts: []wire.Statement{{SQL: "SELECT 1"}}}); err != nil {
		t.Fatal(err)
	}
	if err := c.Send(wire.Ping{}); err != nil {
		t.Fatal(err)
	}
	for _, w := range []wire.FrameType{wire.TQuery, wire.TPing} {
		if m := s.read(); m == nil || m.Type() != w {
			t.Fatalf("%v, want %s: a cancel asked with nothing outstanding was sent", m, w)
		}
	}
}
