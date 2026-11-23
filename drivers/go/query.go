package imagedb

import (
	"context"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strings"
	"time"

	"imagedb.dev/imagedb/wire"
)

// Statement is one statement of a batch and its parameters ($1 to $k).
type Statement struct {
	SQL  string
	Args []any
}

// Column is a result's column.
type Column struct {
	Name string
	Type Type // TypeNone: the statement does not know it (SHOW's rows): each value carries its own type
	// Precision: DECIMAL 1 to 38 (0: not known, 38 digits); INT64 0 BIGINT, 16 SMALLINT, 32 INTEGER; TEXT a VARCHAR's
	// length in characters (0: unbounded)
	Precision int
	Scale     int      // DECIMAL's
	Labels    []string // ENUM: its labels in the type's order (a value is one of them)
}

// DatabaseTypeName is the column's type as the engine names it.
func (c Column) DatabaseTypeName() string {
	switch c.Type {
	case TypeNone:
		return ""
	case TypeInt64:
		switch c.Precision {
		case 16:
			return "SMALLINT"
		case 32:
			return "INTEGER"
		}
		return "INT64"
	case TypeText:
		if c.Precision > 0 {
			return "VARCHAR"
		}
	}
	return c.Type.String()
}

// Done is a statement's DONE: its status, its count (the rows returned or written), its read point (the commit it read,
// its hash, the state digest, the lake's commit and manifest, the database's id, its own writes seen) and its own
// commit when it wrote one.
type Done = wire.Done

// ReadPoint is DONE's read point.
type ReadPoint = wire.ReadPoint

// Session is a SESSIONS_LIST entry.
type Session = wire.Session

// Result is one statement's (or parameter set's) whole answer.
type Result struct {
	Columns  []Column // nil when the statement returned no rows (no COLUMNS)
	Rows     [][]any  // each row's values (FromValue's types)
	Warnings []string
	Done     Done
}

func columnsOf(m *wire.Columns) []Column {
	out := make([]Column, len(m.Cols))
	for i, c := range m.Cols {
		out[i] = Column{Name: c.Name, Type: c.Type, Precision: int(c.Precision), Scale: int(c.Scale), Labels: c.Labels}
	}
	return out
}

func nativeRow(vals []wire.Value) []any {
	row := make([]any, len(vals))
	for i := range vals {
		row[i] = FromValue(&vals[i])
	}
	return row
}

func params(args []any) ([]wire.Value, error) {
	if len(args) > wire.ValuesMax {
		return nil, errf(CodeLimit, "a statement takes at most 256 parameters")
	}
	vals := make([]wire.Value, len(args))
	for i, a := range args {
		v, err := ToValue(a)
		if err != nil {
			return nil, &Error{Code: CodeInvalid, Message: fmt.Sprintf("parameter $%d", i+1), Err: err}
		}
		vals[i] = v
	}
	return vals, nil
}

// begin holds the connection for one call.
func (c *Conn) begin(ctx context.Context) error {
	if !c.op.TryLock() {
		return ErrBusy
	}
	if err := c.failed(); err != nil {
		c.op.Unlock()
		return err
	}
	if err := ctx.Err(); err != nil {
		c.op.Unlock()
		return err
	}
	return nil
}

// watch makes a context's end cancel request gen: CANCEL sent, and again every 250 ms while that request is
// outstanding (the server cancels only a statement running when the CANCEL arrives: one queued or not yet started
// loses it, docs §4); never once its READY is read. With Config.CancelWait the wait for its end is bounded (the
// connection then closed). The returned func ends the watch, waiting for a cancel under way.
func (c *Conn) watch(ctx context.Context, gen uint64) func() {
	if ctx.Done() == nil {
		return func() {}
	}
	done, fin := make(chan struct{}), make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		defer close(fin)
		if c.cfg.CancelWait > 0 {
			at := time.Now().Add(c.cfg.CancelWait)
			c.cancelAt.Store(at.UnixNano())
			c.nc.SetReadDeadline(at)
		}
		t := time.NewTicker(250 * time.Millisecond)
		defer t.Stop()
		for {
			c.cancelGen(gen)
			select {
			case <-done:
				return
			case <-t.C:
			}
		}
	})
	return func() {
		close(done)
		if !stop() {
			<-fin
		}
		c.cancelAt.Store(0)
	}
}

// ctxErr ties an error to the context that ended its request.
func ctxErr(ctx context.Context, err error) error {
	if err == nil || ctx.Err() == nil || errors.Is(err, ctx.Err()) {
		return err
	}
	var e *Error
	if errors.As(err, &e) && (e.Code == CodeCancelled || e.Closed) { // what the context's end made: its cancel, or its close
		if e.Err == nil {
			e.Err = ctx.Err()
		} else { // an I/O error after it (CancelWait): both
			e.Err = errors.Join(ctx.Err(), e.Err)
		}
		return err
	}
	return err
}

func protoErr(c *Conn, m wire.Msg) error {
	return c.fail(errf(CodeState, "a %s frame where this call's replies were expected (the protocol level's Send and the "+
		"calls mixed, or the server out of step); the connection closed", m.Type()))
}

func errOf(m *wire.ErrorMsg, closed bool) *Error {
	return &Error{Code: int(m.Code), Index: int(m.Index), Message: m.Message, Closed: closed}
}

const copyViaQuery = "COPY ... FROM STDIN through a call that sends no data (use CopyFrom)"

// collect reads one request's replies to its READY: each statement's (or set's) COLUMNS, ROWS, WARNINGs and DONE, or
// the ERROR that ends the batch. keep: the rows kept (Exec drops them).
func (c *Conn) collect(keep bool) ([]*Result, error) {
	var out []*Result
	var cur *Result
	var first *Error
	var last *wire.ErrorMsg // an ERROR met by the close instead of READY: why the server closed
	copyOut := false
	var buf []wire.Value
	for {
		m, err := c.Next()
		if err != nil {
			if last != nil {
				return out, errOf(last, true)
			}
			return out, err
		}
		last = nil
		switch m := m.(type) {
		case wire.Columns:
			cur = &Result{Columns: columnsOf(&m)}
		case wire.Rows:
			if cur == nil || cur.Columns == nil {
				return out, protoErr(c, m)
			}
			if keep {
				it := m.Iter()
				for {
					var ok bool
					if buf, ok = it.Next(buf); !ok {
						break
					}
					cur.Rows = append(cur.Rows, nativeRow(buf))
				}
			}
		case wire.Warning:
			if cur == nil {
				cur = &Result{}
			}
			cur.Warnings = append(cur.Warnings, m.Message)
		case wire.Done:
			if cur == nil {
				cur = &Result{}
			}
			cur.Done = m
			out = append(out, cur)
			cur = nil
		case wire.ErrorMsg:
			last = &m
			if first == nil {
				first = errOf(&m, false)
			}
			cur = nil // rows before an ERROR are not the statement's answer
		case wire.CopyIn: // the stream kept in step: the COPY refused unrun, its reason in its ERROR
			if _, err := c.send(wire.CopyFail{Message: copyViaQuery}); err != nil {
				return out, err
			}
		case wire.CopyOut:
			copyOut = true
		case wire.Ready:
			if first != nil {
				return out, first
			}
			if copyOut {
				return out, errf(CodeState, "COPY ... TO STDOUT's data through a call that takes none (use CopyTo): dropped")
			}
			return out, nil
		default:
			return out, protoErr(c, m)
		}
	}
}

// run sends one request and collects its replies, its context watched.
func (c *Conn) run(ctx context.Context, m wire.Msg, keep bool) ([]*Result, error) {
	if err := c.begin(ctx); err != nil {
		return nil, err
	}
	defer c.op.Unlock()
	gen, err := c.send(m)
	if err != nil {
		return nil, err
	}
	stop := c.watch(ctx, gen)
	res, err := c.collect(keep)
	stop()
	return res, ctxErr(ctx, err)
}

// Batch runs statements as one QUERY: in order, each committing on its own unless inside BEGIN ... COMMIT. An ERROR ends
// the batch: the results of the statements before it, and the *Error whose Index names the one that failed (the
// statements after it did not run; it alone was undone).
func (c *Conn) Batch(ctx context.Context, stmts ...Statement) ([]*Result, error) {
	if len(stmts) < 1 || len(stmts) > wire.BatchMax {
		return nil, errf(CodeLimit, "a batch holds 1 to 4,096 statements")
	}
	q := wire.Query{Stmts: make([]wire.Statement, len(stmts))}
	for i, s := range stmts {
		p, err := params(s.Args)
		if err != nil {
			return nil, err
		}
		q.Stmts[i] = wire.Statement{SQL: s.SQL, Params: p}
	}
	return c.run(ctx, q, true)
}

// Exec runs one statement, its rows (if any) read and dropped.
func (c *Conn) Exec(ctx context.Context, sql string, args ...any) (*Done, error) {
	p, err := params(args)
	if err != nil {
		return nil, err
	}
	res, err := c.run(ctx, wire.Query{Stmts: []wire.Statement{{SQL: sql, Params: p}}}, false)
	if err != nil {
		return nil, err
	}
	if len(res) != 1 {
		return nil, c.fail(errf(CodeState, "a statement answered %d times", len(res)))
	}
	return &res[0].Done, nil
}

// Prepare prepares a statement by name on the server (its parameters typed at each Execute, as the engine's PREPARE).
func (c *Conn) Prepare(ctx context.Context, name, sql string) error {
	_, err := c.run(ctx, wire.Prepare{Name: name, SQL: sql}, false)
	return err
}

// Execute runs a prepared statement once a parameter set (each set as many values): one Result a set, an ERROR ending
// the run at its set's Index.
func (c *Conn) Execute(ctx context.Context, name string, sets ...[]any) ([]*Result, error) {
	if len(sets) == 0 {
		sets = [][]any{nil}
	}
	if len(sets) > wire.BatchMax {
		return nil, errf(CodeLimit, "an EXECUTE holds 1 to 4,096 parameter sets")
	}
	m := wire.Execute{Name: name, Sets: len(sets), NVals: len(sets[0])}
	for _, s := range sets {
		if len(s) != m.NVals {
			return nil, errf(CodeInvalid, "every parameter set of an EXECUTE holds as many values")
		}
		p, err := params(s)
		if err != nil {
			return nil, err
		}
		m.Values = append(m.Values, p...)
	}
	return c.run(ctx, m, true)
}

// Deallocate drops a prepared statement.
func (c *Conn) Deallocate(ctx context.Context, name string) error {
	_, err := c.run(ctx, wire.Deallocate{Name: name}, false)
	return err
}

// answer sends an out-of-turn request (PING, SESSIONS, KILL) and reads its answer: no request of this connection is
// outstanding (the calls run one at a time), so the answer is the next frame. A context's end closes the connection
// (an answer still on its way would put the stream out of step).
func (c *Conn) answer(ctx context.Context, m wire.Msg, want wire.FrameType) (wire.Msg, error) {
	if err := c.begin(ctx); err != nil {
		return nil, err
	}
	defer c.op.Unlock()
	if c.outstanding() {
		return nil, errf(CodeState, "%s with requests sent through Send still unanswered: read their replies first", m.Type())
	}
	if _, err := c.send(m); err != nil {
		return nil, err
	}
	stop := context.AfterFunc(ctx, func() { // a bound readFull keeps (never replaced by its own deadline), then the read woken
		c.boundAt.Store(time.Unix(1, 0).UnixNano())
		c.nc.SetReadDeadline(time.Unix(1, 0))
	})
	r, err := c.Next()
	if !stop() && err == nil {
		err = c.fail(&Error{Code: CodeIO, Message: m.Type().String(), Closed: true, Err: ctx.Err()})
	}
	if err != nil {
		return nil, ctxErr(ctx, err)
	}
	if e, ok := r.(wire.ErrorMsg); ok { // unasked: the server ends the connection with it (a KILL, a bound)
		return nil, c.fail(errOf(&e, true))
	}
	if r.Type() != want {
		return nil, protoErr(c, r)
	}
	return r, nil
}

// Ping asks the server for a PONG.
func (c *Conn) Ping(ctx context.Context) error {
	_, err := c.answer(ctx, wire.Ping{}, wire.TPong)
	return err
}

// Sessions lists the sessions (a superuser's every session; a role's its own role's).
func (c *Conn) Sessions(ctx context.Context) ([]Session, error) {
	r, err := c.answer(ctx, wire.Sessions{}, wire.TSessionsList)
	if err != nil {
		return nil, err
	}
	return r.(wire.SessionsList).Sessions, nil
}

// The kinds of Kill.
const (
	KillCancel    = wire.KillCancel    // the request the session runs now, has begun or runs next
	KillTerminate = wire.KillTerminate // the session ended, its transaction rolled back
)

// Kill cancels or terminates a session by its id (from Sessions): found is false for no such session (to a role, one
// of another role's too).
func (c *Conn) Kill(ctx context.Context, session uint64, kind int) (found bool, err error) {
	if (kind != KillCancel && kind != KillTerminate) || session == 0 {
		return false, errf(CodeInvalid, "a KILL's kind is KillCancel or KillTerminate, its session an id from Sessions")
	}
	r, err := c.answer(ctx, wire.Kill{Kind: uint8(kind), Session: session}, wire.TKillDone)
	if err != nil {
		return false, err
	}
	kd := r.(wire.KillDone)
	if kd.Session != session {
		return false, c.fail(errf(CodeState, "a KILL_DONE for another session (%d, asked %d)", kd.Session, session))
	}
	return kd.Code == wire.Killed, nil
}

// ---- COPY ----

// CopyFrom runs a COPY ... FROM STDIN, its data read from r and sent in pieces of at most 1 MiB, then COPY_DONE at r's
// end; r's error (or the context's end) sends COPY_FAIL instead, which fails the statement unrun. A COPY the server
// refuses before its data (no such table, a privilege) is answered at once and nothing of r is read.
func (c *Conn) CopyFrom(ctx context.Context, sql string, r io.Reader) (*Done, error) {
	if err := c.begin(ctx); err != nil {
		return nil, err
	}
	defer c.op.Unlock()
	gen, err := c.send(wire.Query{Stmts: []wire.Statement{{SQL: sql}}})
	if err != nil {
		return nil, err
	}
	stop := c.watch(ctx, gen)
	done, err := c.copyIn(ctx, r)
	stop()
	return done, ctxErr(ctx, err)
}

func (c *Conn) copyIn(ctx context.Context, r io.Reader) (*Done, error) {
	m, err := c.Next()
	if err != nil {
		return nil, err
	}
	switch m := m.(type) {
	case wire.CopyIn:
	case wire.ErrorMsg, wire.Done, wire.Columns, wire.Warning, wire.CopyOut: // refused before its data, or not a COPY FROM STDIN
		res, err := c.collectAfter(m)
		if err == nil {
			d := res
			return d, errf(CodeState, "the statement is not a COPY ... FROM STDIN (it ran: %q); no data sent", d.Status)
		}
		return nil, err
	default:
		return nil, protoErr(c, m)
	}
	buf := make([]byte, 1<<20)
	var reason string
	cancels := c.cancels.Load() // a Cancel from here on ends the upload (its CANCEL already refuses the COPY)
	for reason == "" {
		if ctx.Err() != nil || c.cancels.Load() != cancels {
			reason = "cancelled by the client"
			break
		}
		n, rerr := r.Read(buf)
		if n > 0 {
			if _, err := c.send(wire.CopyData{Data: buf[:n]}); err != nil {
				return nil, err
			}
		}
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			reason = "the client's data failed: " + rerr.Error()
		}
	}
	var end wire.Msg = wire.CopyDone{}
	if reason != "" {
		reason = strings.ReplaceAll(strings.ToValidUTF8(reason, "?"), "\x00", "?")
		reason = reason[:wire.UTF8Fit([]byte(reason), wire.MessageMax)]
		end = wire.CopyFail{Message: reason}
	}
	if _, err := c.send(end); err != nil {
		return nil, err
	}
	res, err := c.collect(false)
	if err != nil {
		return nil, err
	}
	if len(res) != 1 {
		return nil, c.fail(errf(CodeState, "a COPY answered %d times", len(res)))
	}
	return &res[0].Done, nil
}

// collectAfter is collect with its first frame already read: the one statement's DONE (or its ERROR).
func (c *Conn) collectAfter(first wire.Msg) (*Done, error) {
	var done *Done
	var firstErr *Error
	m := first
	for {
		switch x := m.(type) {
		case wire.Done:
			done = &x
		case wire.ErrorMsg:
			if firstErr == nil {
				firstErr = errOf(&x, false)
			}
		case wire.Columns, wire.Rows, wire.Warning, wire.CopyOut: // not a COPY FROM STDIN: read to its end, dropped
		case wire.Ready:
			if firstErr != nil {
				return nil, firstErr
			}
			if done == nil {
				return nil, c.fail(errf(CodeState, "a READY with no DONE"))
			}
			return done, nil
		default:
			return nil, protoErr(c, m)
		}
		var err error
		if m, err = c.Next(); err != nil {
			if firstErr != nil {
				firstErr.Closed = true
				return nil, firstErr
			}
			return nil, err
		}
	}
}

// CopyTo runs a COPY ... TO STDOUT, its data written to w as it arrives. A failed write cancels the statement and the
// rest of its data is read and dropped; the error is w's.
func (c *Conn) CopyTo(ctx context.Context, sql string, w io.Writer) (*Done, error) {
	if err := c.begin(ctx); err != nil {
		return nil, err
	}
	defer c.op.Unlock()
	gen, err := c.send(wire.Query{Stmts: []wire.Statement{{SQL: sql}}})
	if err != nil {
		return nil, err
	}
	stop := c.watch(ctx, gen)
	defer stop()
	var werr error
	var done *Done
	var first *Error
	rows := false
	for {
		m, err := c.Next()
		if err != nil {
			if first != nil {
				first.Closed = true
				return nil, ctxErr(ctx, first)
			}
			return nil, ctxErr(ctx, err)
		}
		switch m := m.(type) {
		case wire.CopyOut:
			if werr == nil {
				if _, werr = w.Write(m.Data); werr != nil {
					c.cancelGen(gen)
				}
			}
		case wire.Done:
			done = &m
		case wire.ErrorMsg:
			if first == nil {
				first = errOf(&m, false)
			}
		case wire.Columns, wire.Rows, wire.Warning:
			rows = rows || m.Type() != wire.TWarning
		case wire.CopyIn:
			if _, err := c.send(wire.CopyFail{Message: copyViaQuery}); err != nil {
				return nil, err
			}
		case wire.Ready:
			switch {
			case werr != nil:
				return done, werr
			case first != nil:
				return nil, ctxErr(ctx, first)
			case rows:
				return done, errf(CodeState, "the statement returned rows, not COPY ... TO STDOUT's data")
			}
			return done, nil
		default:
			return nil, protoErr(c, m)
		}
	}
}

// ---- rows, streamed ----

// Rows is a statement's rows, read frame by frame as Next asks for them. It holds its connection until Close (or until
// Next returns false).
type Rows struct {
	c        *Conn
	ctx      context.Context
	gen      uint64
	stop     func()
	cols     []Column
	it       *wire.RowsIter
	buf, cur []wire.Value
	done     *Done
	warnings []string
	err      error
	ended    bool // READY read, the connection let go
}

// Query runs one statement and streams its rows: Next, Values or Scan, then Close (Rows.Err the statement's ERROR,
// which may come after some rows: those are not its answer then).
func (c *Conn) Query(ctx context.Context, sql string, args ...any) (*Rows, error) {
	p, err := params(args)
	if err != nil {
		return nil, err
	}
	if err := c.begin(ctx); err != nil {
		return nil, err
	}
	gen, err := c.send(wire.Query{Stmts: []wire.Statement{{SQL: sql, Params: p}}})
	if err != nil {
		c.op.Unlock()
		return nil, err
	}
	r := &Rows{c: c, ctx: ctx, gen: gen, stop: c.watch(ctx, gen)}
	for r.cols == nil && !r.ended { // up to its COLUMNS, or its whole answer when it returns no rows
		if !r.step() {
			break
		}
	}
	if r.err != nil {
		r.finish()
		return nil, r.err
	}
	return r, nil
}

// step reads one frame; false once the statement's answer has ended (READY read).
func (r *Rows) step() bool {
	m, err := r.c.Next()
	if err != nil {
		if r.err != nil { // an ERROR met by the close instead of READY
			var e *Error
			if errors.As(r.err, &e) {
				e.Closed = true
			}
		} else {
			r.err = err
		}
		r.finish()
		return false
	}
	switch m := m.(type) {
	case wire.Columns:
		r.cols = columnsOf(&m)
	case wire.Rows:
		if r.cols == nil {
			r.err = protoErr(r.c, m)
			r.finish()
			return false
		}
		r.it = m.Iter()
	case wire.Warning:
		r.warnings = append(r.warnings, m.Message)
	case wire.Done:
		r.done = &m
	case wire.ErrorMsg:
		if r.err == nil {
			r.err = errOf(&m, false)
		}
		r.it = nil
	case wire.CopyIn:
		if _, err := r.c.send(wire.CopyFail{Message: copyViaQuery}); err != nil {
			r.err = err
			r.finish()
			return false
		}
	case wire.CopyOut:
		if r.err == nil {
			r.err = errf(CodeState, "COPY ... TO STDOUT's data through Query (use CopyTo): dropped")
		}
	case wire.Ready:
		r.finish()
		return false
	default:
		r.err = protoErr(r.c, m)
		r.finish()
		return false
	}
	return true
}

func (r *Rows) finish() {
	if r.ended {
		return
	}
	r.ended = true
	r.it = nil
	r.stop()
	r.err = ctxErr(r.ctx, r.err)
	r.c.op.Unlock()
}

// Columns is the statement's columns (nil when it returned no rows).
func (r *Rows) Columns() []Column { return r.cols }

// Next moves to the next row; false at the end of the rows or at an error (Err).
func (r *Rows) Next() bool {
	r.cur = nil
	for !r.ended {
		if r.it != nil {
			var ok bool
			if r.buf, ok = r.it.Next(r.buf); ok {
				r.cur = r.buf
				return true
			}
			r.it = nil
		}
		if r.done != nil || (r.err != nil && r.it == nil) {
			for r.step() { // to its READY
			}
			return false
		}
		r.step()
	}
	return false
}

// RawValues is the current row's wire values (valid until the next Next): the protocol's level, a NULL's type kept.
func (r *Rows) RawValues() []wire.Value { return r.cur }

// Values is the current row's values (FromValue's types; nil for NULL).
func (r *Rows) Values() []any { return nativeRow(r.cur) }

// Scan copies the current row's values into dest: *any, a sql.Scanner, a pointer to the value's own Go type (FromValue's
// table), or a pointer to a pointer of it (nil for NULL). database/sql gives conversions; this is exact.
func (r *Rows) Scan(dest ...any) error {
	if r.cur == nil {
		return errors.New("imagedb: Scan with no current row")
	}
	if len(dest) != len(r.cur) {
		return fmt.Errorf("imagedb: Scan of %d values into %d destinations", len(r.cur), len(dest))
	}
	for i := range dest {
		if err := assign(dest[i], FromValue(&r.cur[i])); err != nil {
			return fmt.Errorf("imagedb: column %d (%s): %w", i, r.cols[i].Name, err)
		}
	}
	return nil
}

type scanner interface{ Scan(src any) error }

func assign(dest, v any) error {
	if p, ok := dest.(*any); ok {
		*p = v
		return nil
	}
	if s, ok := dest.(scanner); ok {
		return s.Scan(v)
	}
	dv := reflect.ValueOf(dest)
	if dv.Kind() != reflect.Pointer || dv.IsNil() {
		return errors.New("a destination is a non-nil pointer")
	}
	dv = dv.Elem()
	if v == nil {
		switch dv.Kind() {
		case reflect.Pointer, reflect.Interface, reflect.Slice, reflect.Map:
			dv.Set(reflect.Zero(dv.Type()))
			return nil
		}
		return fmt.Errorf("a NULL into a %s (scan into a pointer to it)", dv.Type())
	}
	sv := reflect.ValueOf(v)
	if sv.Type().AssignableTo(dv.Type()) {
		dv.Set(sv)
		return nil
	}
	if dv.Kind() == reflect.Pointer && sv.Type().AssignableTo(dv.Type().Elem()) {
		p := reflect.New(dv.Type().Elem())
		p.Elem().Set(sv)
		dv.Set(p)
		return nil
	}
	return fmt.Errorf("a %T into a %s", v, dv.Type())
}

// Err is the statement's error (its ERROR, which may follow some rows: they are not its answer then), or nil.
func (r *Rows) Err() error { return r.err }

// Done is the statement's DONE, once Next has returned false (nil when it failed).
func (r *Rows) Done() *Done { return r.done }

// Warnings are the statement's WARNINGs.
func (r *Rows) Warnings() []string { return r.warnings }

// Close reads the statement's answer to its end (CANCEL first, should it still run) and lets the connection go.
func (r *Rows) Close() error {
	if r.ended {
		return nil
	}
	if r.done == nil && r.err == nil {
		r.c.cancelGen(r.gen)
	}
	r.it = nil
	for r.step() {
	}
	return r.c.failed() // nil unless the connection failed meanwhile
}
