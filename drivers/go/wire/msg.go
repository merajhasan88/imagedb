package wire

import (
	"encoding/binary"
)

// Msg is a frame's body, decoded: one struct a frame type.
type Msg interface{ Type() FrameType }

// Statement is one of a QUERY's statements and its parameters ($1 to $k).
type Statement struct {
	SQL    string
	Params []Value
}

// The client's frames.
type (
	Query      struct{ Stmts []Statement }
	Prepare    struct{ Name, SQL string }
	Deallocate struct{ Name string }
	CopyData   struct{ Data []byte }
	CopyDone   struct{}
	CopyFail   struct{ Message string }
	Cancel     struct{}
	Ping       struct{}
	Terminate  struct{}
	Sessions   struct{}
	Kill       struct {
		Kind    uint8 // KillCancel or KillTerminate
		Session uint64
	}
	// Execute runs a prepared statement once a parameter set: Sets sets of NVals values, Values in set order.
	Execute struct {
		Name   string
		Sets   int
		NVals  int
		Values []Value
	}
)

// The server's frames.
type (
	Warning  struct{ Message string }
	CopyIn   struct{}
	CopyOut  struct{ Data []byte }
	Ready    struct{ State uint8 }
	Pong     struct{}
	KillDone struct {
		Code    uint8 // Killed or KillNone
		Session uint64
	}
	// Error ends a statement (or a batch: Index names the statement or parameter set that failed).
	ErrorMsg struct {
		Code    uint32
		Index   uint32
		Message string
	}
	SessionsList struct{ Sessions []Session }
)

// Session is one entry of SESSIONS_LIST.
type Session struct {
	ID       uint64 // at least 1, strictly increasing in a list
	Role     uint32
	Endpoint uint8 // 1 TCP, 2 the socket
	State    uint8 // SessIdle .. SessCopy
	AgeMs    uint64
	Name     string // its role's name now, 0 to 63 bytes ("" once dropped, NOLOGIN or erased)
}

// Column is one of COLUMNS' columns.
type Column struct {
	Name      string
	Type      Type // TypeNone: the statement does not know it (each value its own type)
	Precision uint16
	Scale     uint16
	Labels    []string // ENUM: its labels in the type's order, distinct
	labels    map[string]struct{}
}

// Columns is a result's columns: the ROWS after it are read against it.
type Columns struct{ Cols []Column }

// Rows is one ROWS frame, validated in place against its COLUMNS: N rows of len(Cols) values in Data, decoded one row
// at a time (Iter), so a frame costs its own bytes and never one struct a value.
type Rows struct {
	N     uint32
	NCols int
	Data  []byte
}

// ReadPoint is DONE's read point: the commit the statement read, its hash, the state digest, the lake's commit and
// manifest, the database's id, and whether the read saw its transaction's own writes past that commit.
type ReadPoint struct {
	Commit       uint64
	Hash         [32]byte
	Digest       [32]byte
	LakeCommit   uint64
	LakeManifest [32]byte
	DatabaseID   [16]byte
	Own          bool
}

// Done ends a statement or a parameter set that succeeded.
type Done struct {
	Status      string
	Count       uint64 // the rows returned or written
	HasRead     bool
	Read        ReadPoint
	HasWrite    bool
	WriteCommit uint64 // at least 1
	WriteHash   [32]byte
}

func (Query) Type() FrameType        { return TQuery }
func (Prepare) Type() FrameType      { return TPrepare }
func (Execute) Type() FrameType      { return TExecute }
func (Deallocate) Type() FrameType   { return TDeallocate }
func (CopyData) Type() FrameType     { return TCopyData }
func (CopyDone) Type() FrameType     { return TCopyDone }
func (CopyFail) Type() FrameType     { return TCopyFail }
func (Cancel) Type() FrameType       { return TCancel }
func (Ping) Type() FrameType         { return TPing }
func (Terminate) Type() FrameType    { return TTerminate }
func (Sessions) Type() FrameType     { return TSessions }
func (Kill) Type() FrameType         { return TKill }
func (Columns) Type() FrameType      { return TColumns }
func (Rows) Type() FrameType         { return TRows }
func (Done) Type() FrameType         { return TDone }
func (ErrorMsg) Type() FrameType     { return TError }
func (Warning) Type() FrameType      { return TWarning }
func (CopyIn) Type() FrameType       { return TCopyIn }
func (CopyOut) Type() FrameType      { return TCopyOut }
func (Ready) Type() FrameType        { return TReady }
func (Pong) Type() FrameType         { return TPong }
func (SessionsList) Type() FrameType { return TSessionsList }
func (KillDone) Type() FrameType     { return TKillDone }

// ---- column rules ----

func intWidthOK(p uint16) bool { return p == 0 || p == 16 || p == 32 }

// shapeOK is wire.c's col_shape_ok.
func (c *Column) shapeOK() bool {
	if len(c.Name) < 1 || len(c.Name) > ColNameMax || !StringOK(c.Name) || c.Type > TypeLast {
		return false
	}
	if c.Type != TypeEnum && len(c.Labels) != 0 {
		return false
	}
	if c.Type == TypeEnum && len(c.Labels) > LabelsMax {
		return false
	}
	switch c.Type {
	case TypeDecimal: // precision 0: not known (a result's column), 38 digits
		max := c.Precision
		if max == 0 {
			max = DecimalMax
		}
		return c.Precision <= DecimalMax && c.Scale <= max
	case TypeInt64:
		return intWidthOK(c.Precision) && c.Scale == 0
	case TypeText:
		return c.Scale == 0 // precision: a VARCHAR's length in characters, 0 none
	}
	return c.Precision == 0 && c.Scale == 0
}

// index checks an ENUM column's labels (each 0 to 63 bytes of UTF-8, distinct) and indexes them for membership.
func (c *Column) index() error {
	if c.Type != TypeEnum {
		return nil
	}
	if len(c.Labels) > LabelsMax {
		return corrupt("an ENUM's labels past their bounds")
	}
	set := make(map[string]struct{}, len(c.Labels))
	for _, l := range c.Labels {
		if len(l) > LabelMax || !StringOK(l) {
			return corrupt("an ENUM's label past its bounds")
		}
		if _, dup := set[l]; dup {
			return corrupt("an ENUM's labels not distinct")
		}
		set[l] = struct{}{}
	}
	c.labels = set
	return nil
}

// Index checks and indexes a COLUMNS message built by hand (its ENUM labels distinct): the decoder does it itself.
func (m *Columns) Index() error {
	for i := range m.Cols {
		if err := m.Cols[i].index(); err != nil {
			return err
		}
	}
	return nil
}

// ValueFits is ROWS' rule (wire.c's imdbw_value_fits): a valid value, NULL or of its column's type (a NULL of its
// column's type too), at its scale and within its precision's digits, an integer within its width, a TEXT within its
// VARCHAR's characters, an ENUM one of its labels; under a column of no known type, any value.
func ValueFits(c *Column, v *Value) bool {
	if !ValueOK(v) {
		return false
	}
	if c.Type == TypeNone {
		return true
	}
	if v.Type != c.Type {
		return false
	}
	if v.Null {
		return true
	}
	switch c.Type {
	case TypeDecimal:
		digits := int(c.Precision)
		if digits == 0 {
			digits = DecimalMax
		}
		return uint16(v.Scale) == c.Scale && DecimalFits(v.Hi, v.Lo, digits)
	case TypeInt64:
		switch c.Precision {
		case 16:
			return v.I >= -32768 && v.I <= 32767
		case 32:
			return v.I >= -2147483648 && v.I <= 2147483647
		}
		return true
	case TypeText:
		return c.Precision == 0 || utf8Chars(v.S) <= int(c.Precision)
	case TypeEnum:
		if c.labels == nil { // not indexed: each label in turn
			for _, l := range c.Labels {
				if l == string(v.S) {
					return true
				}
			}
			return false
		}
		_, ok := c.labels[string(v.S)]
		return ok
	}
	return true
}

// ---- a reader over a body ----

type rd struct {
	b   []byte
	off int
	err bool
}

func (r *rd) left() int { return len(r.b) - r.off }

func (r *rd) bytes(n int) []byte {
	if r.err || n < 0 || r.left() < n {
		r.err = true
		return nil
	}
	p := r.b[r.off : r.off+n : r.off+n]
	r.off += n
	return p
}

func (r *rd) u8() uint8 {
	p := r.bytes(1)
	if p == nil {
		return 0
	}
	return p[0]
}

func (r *rd) u16() uint16 {
	p := r.bytes(2)
	if p == nil {
		return 0
	}
	return binary.LittleEndian.Uint16(p)
}

func (r *rd) u32() uint32 {
	p := r.bytes(4)
	if p == nil {
		return 0
	}
	return binary.LittleEndian.Uint32(p)
}

func (r *rd) u64() uint64 {
	p := r.bytes(8)
	if p == nil {
		return 0
	}
	return binary.LittleEndian.Uint64(p)
}

// text reads a length of lenBytes bytes, then that many bytes of UTF-8 without NUL (wire.c's text_get: a length past its
// bounds CodeLimit, before its bytes are asked for).
func (r *rd) text(lenBytes, min, max int) (string, error) {
	var n int
	switch lenBytes {
	case 1:
		n = int(r.u8())
	case 2:
		n = int(r.u16())
	default:
		n = int(r.u32())
	}
	if r.err {
		return "", corrupt("a text cut short")
	}
	if n < min || n > max {
		return "", limitf("a text of %d bytes (%d to %d)", n, min, max)
	}
	p := r.bytes(n)
	if p == nil {
		return "", corrupt("a text cut short")
	}
	if !TextOK(p) {
		return "", corrupt("a text not UTF-8 without NUL")
	}
	return string(p), nil
}

func textOK(s string, min, max int) bool { return len(s) >= min && len(s) <= max && StringOK(s) }

func putText(b []byte, lenBytes, min, max int, s string) ([]byte, error) {
	if !textOK(s, min, max) {
		return b, refused("a text past its bounds or not UTF-8 without NUL")
	}
	switch lenBytes {
	case 1:
		b = append(b, byte(len(s)))
	case 2:
		b = binary.LittleEndian.AppendUint16(b, uint16(len(s)))
	default:
		b = binary.LittleEndian.AppendUint32(b, uint32(len(s)))
	}
	return append(b, s...), nil
}

// span validates n values in place (each against its column when cols is given: value i's column is i mod their
// count; a parameter's, never a non-NULL ENUM), allocating nothing: wire.c's span_get.
func (r *rd) span(n uint64, cols *Columns) ([]byte, error) {
	if n > uint64(r.left()) { // each value is at least one byte
		return nil, corrupt("more values than bytes")
	}
	at := r.off
	nc := uint64(0)
	if cols != nil {
		nc = uint64(len(cols.Cols))
	}
	for i := uint64(0); i < n; i++ {
		v, off, err := DecodeValue(r.b, r.off)
		if err != nil {
			return nil, err
		}
		r.off = off
		if cols != nil && !ValueFits(&cols.Cols[i%nc], &v) {
			return nil, corrupt("a value its column does not take")
		}
		if cols == nil && v.Type == TypeEnum && !v.Null {
			return nil, corrupt("an ENUM parameter: a label is sent as TEXT")
		}
	}
	return r.b[at:r.off:r.off], nil
}

// decodeValues decodes a validated span into values (their S aliasing it).
func decodeValues(p []byte, n int) []Value {
	out := make([]Value, n)
	off := 0
	for i := range out {
		out[i], off, _ = DecodeValue(p, off)
	}
	return out
}

// appendParams writes a run of parameters (never a non-NULL ENUM: a label is sent as TEXT).
func appendParams(b []byte, vals []Value) ([]byte, error) {
	for i := range vals {
		if vals[i].Type == TypeEnum && !vals[i].Null {
			return b, refused("an ENUM parameter (a label is sent as TEXT)")
		}
		var err error
		if b, err = AppendValue(b, &vals[i]); err != nil {
			return b, err
		}
	}
	return b, nil
}

// ---- heads ----

// DecodeHead reads a frame's head: its length (of its type and body: 1 to 16 MiB) and a type of the direction's.
func DecodeHead(h []byte, fromServer bool) (uint32, FrameType, error) {
	if len(h) < HeadLen {
		return 0, 0, corrupt("a frame's head cut short")
	}
	n := binary.LittleEndian.Uint32(h)
	t := FrameType(h[4])
	if n < 1 || n > FrameMax {
		return n, t, limitf("a frame of %d bytes (1 to %d)", n, FrameMax)
	}
	if (fromServer && !t.FromServer()) || (!fromServer && !t.FromClient()) {
		return n, t, corrupt("a frame of a type this side does not send")
	}
	return n, t, nil
}

// ---- bodies ----

const sessMin = 23 // a SESSIONS_LIST entry's bytes at least: id, role, endpoint, state, age, the name's length

func sessOK(s *Session, prev uint64) bool {
	return s.ID > prev && s.Role != 0 && (s.Endpoint == 1 || s.Endpoint == 2) && s.State <= SessCopy &&
		textOK(s.Name, 0, UserField-1)
}

func killOK(kind uint8, sid uint64) bool {
	return (kind == KillCancel || kind == KillTerminate) && sid != 0
}

func doneOK(d *Done) bool {
	return textOK(d.Status, 0, StatusMax) && (!d.HasWrite || d.WriteCommit >= 1)
}

// DecodeBody decodes a frame's body (wire.c's imdbw_msg_get): a ROWS against the COLUMNS before it (cols; ignored for the
// other types). Texts and labels are copied; COPY data, ROWS data and SESSIONS_LIST names alias or copy as documented on
// each type (COPY data and ROWS data alias body).
func DecodeBody(t FrameType, body []byte, cols *Columns) (Msg, error) {
	r := &rd{b: body}
	m, err := bodyGet(t, r, cols)
	if err == nil && (r.err || r.left() != 0) {
		if r.err {
			err = corrupt("a body cut short")
		} else {
			err = corrupt("a body with bytes past its end")
		}
	}
	if err != nil {
		return nil, err
	}
	return m, nil
}

func bodyGet(t FrameType, r *rd, cols *Columns) (Msg, error) {
	switch t {
	case TQuery:
		n := r.u32()
		if r.err || n < 1 || n > BatchMax || uint64(n) > uint64(r.left()/7) { // a statement: 7 bytes at least
			return nil, corrupt("a QUERY of 1 to 4,096 statements it holds the bytes of")
		}
		q := Query{Stmts: make([]Statement, n)}
		for i := range q.Stmts {
			s, err := r.text(4, 1, SQLMax)
			if err != nil {
				return nil, err
			}
			nv := r.u16()
			if r.err || nv > ValuesMax {
				return nil, corrupt("a statement's values: at most 256")
			}
			p, err := r.span(uint64(nv), nil)
			if err != nil {
				return nil, err
			}
			q.Stmts[i] = Statement{SQL: s, Params: decodeValues(p, int(nv))}
		}
		return q, nil
	case TPrepare:
		name, err := r.text(1, 1, NameMax)
		if err != nil {
			return nil, err
		}
		s, err := r.text(4, 1, SQLMax)
		if err != nil {
			return nil, err
		}
		return Prepare{Name: name, SQL: s}, nil
	case TExecute:
		name, err := r.text(1, 1, NameMax)
		if err != nil {
			return nil, err
		}
		sets, nv := r.u32(), r.u16()
		if r.err || sets < 1 || sets > BatchMax || nv > ValuesMax {
			return nil, corrupt("an EXECUTE of 1 to 4,096 sets of at most 256 values")
		}
		p, err := r.span(uint64(sets)*uint64(nv), nil)
		if err != nil {
			return nil, err
		}
		return Execute{Name: name, Sets: int(sets), NVals: int(nv), Values: decodeValues(p, int(sets)*int(nv))}, nil
	case TDeallocate:
		name, err := r.text(1, 1, NameMax)
		if err != nil {
			return nil, err
		}
		return Deallocate{Name: name}, nil
	case TKill:
		k := Kill{Kind: r.u8(), Session: r.u64()}
		if r.err || !killOK(k.Kind, k.Session) {
			return nil, corrupt("a KILL's kind (1 cancel, 2 terminate) or a session id of 0")
		}
		return k, nil
	case TKillDone:
		k := KillDone{Code: r.u8(), Session: r.u64()}
		if r.err || k.Code > KillNone || k.Session == 0 {
			return nil, corrupt("a KILL_DONE's code or a session id of 0")
		}
		return k, nil
	case TSessionsList:
		n := r.u32()
		if r.err || n > SessionsMax || uint64(n) > uint64(r.left()/sessMin) {
			return nil, corrupt("a SESSIONS_LIST of at most 65,536 sessions it holds the bytes of")
		}
		sl := SessionsList{Sessions: make([]Session, n)}
		prev := uint64(0)
		for i := range sl.Sessions {
			s := &sl.Sessions[i]
			s.ID, s.Role, s.Endpoint, s.State, s.AgeMs = r.u64(), r.u32(), r.u8(), r.u8(), r.u64()
			if r.err {
				return nil, corrupt("a session cut short")
			}
			name, err := r.text(1, 0, UserField-1)
			if err != nil {
				return nil, err
			}
			s.Name = name
			if !sessOK(s, prev) {
				return nil, corrupt("a session's id out of order, or its role, endpoint or state")
			}
			prev = s.ID
		}
		return sl, nil
	case TCopyData, TCopyOut:
		n := r.left()
		if n == 0 {
			return nil, corrupt("a COPY piece of no bytes")
		}
		d := r.bytes(n)
		if t == TCopyData {
			return CopyData{Data: d}, nil
		}
		return CopyOut{Data: d}, nil
	case TCopyFail, TWarning:
		s, err := r.text(2, 0, MessageMax)
		if err != nil {
			return nil, err
		}
		if t == TCopyFail {
			return CopyFail{Message: s}, nil
		}
		return Warning{Message: s}, nil
	case TSessions:
		return Sessions{}, nil
	case TCopyDone:
		return CopyDone{}, nil
	case TCancel:
		return Cancel{}, nil
	case TPing:
		return Ping{}, nil
	case TTerminate:
		return Terminate{}, nil
	case TCopyIn:
		return CopyIn{}, nil
	case TPong:
		return Pong{}, nil
	case TColumns:
		n := r.u16()
		if r.err || n < 1 || n > ValuesMax || int(n) > r.left()/7 { // a column: 7 bytes at least
			return nil, corrupt("a COLUMNS of 1 to 256 columns it holds the bytes of")
		}
		m := Columns{Cols: make([]Column, n)}
		for i := range m.Cols {
			c := &m.Cols[i]
			name, err := r.text(1, 1, ColNameMax)
			if err != nil {
				return nil, err
			}
			c.Name = name
			c.Type, c.Precision, c.Scale = Type(r.u8()), r.u16(), r.u16()
			if r.err {
				return nil, corrupt("a column cut short")
			}
			if c.Type == TypeEnum {
				nl := r.u16()
				if r.err || nl > LabelsMax || int(nl) > r.left() {
					return nil, corrupt("an ENUM's labels past their bounds or bytes")
				}
				c.Labels = make([]string, nl)
				for k := range c.Labels {
					if c.Labels[k], err = r.text(1, 0, LabelMax); err != nil {
						return nil, err
					}
				}
			}
			if !c.shapeOK() {
				return nil, corrupt("a column's type, precision or scale its type does not take")
			}
		}
		if err := m.Index(); err != nil {
			return nil, err
		}
		return m, nil
	case TRows:
		if cols == nil || len(cols.Cols) < 1 {
			return nil, corrupt("a ROWS with no COLUMNS before it")
		}
		n := r.u32()
		if r.err || n < 1 {
			return nil, corrupt("a ROWS of no row")
		}
		p, err := r.span(uint64(n)*uint64(len(cols.Cols)), cols)
		if err != nil {
			return nil, err
		}
		return Rows{N: n, NCols: len(cols.Cols), Data: p}, nil
	case TDone:
		var d Done
		var err error
		if d.Status, err = r.text(2, 0, StatusMax); err != nil {
			return nil, err
		}
		d.Count = r.u64()
		hr := r.u8()
		if r.err || hr > 1 {
			return nil, corrupt("a DONE's read point flag")
		}
		if d.HasRead = hr == 1; d.HasRead {
			d.Read.Commit = r.u64()
			copy(d.Read.Hash[:], r.bytes(32))
			copy(d.Read.Digest[:], r.bytes(32))
			d.Read.LakeCommit = r.u64()
			copy(d.Read.LakeManifest[:], r.bytes(32))
			copy(d.Read.DatabaseID[:], r.bytes(16))
			own := r.u8()
			if !r.err && own > 1 {
				return nil, corrupt("a DONE's own-writes flag")
			}
			d.Read.Own = own == 1
		}
		hw := r.u8()
		if r.err || hw > 1 {
			return nil, corrupt("a DONE's write flag")
		}
		if d.HasWrite = hw == 1; d.HasWrite {
			d.WriteCommit = r.u64()
			copy(d.WriteHash[:], r.bytes(32))
		}
		if !r.err && !doneOK(&d) {
			return nil, corrupt("a DONE's write at commit 0")
		}
		return d, nil
	case TError:
		e := ErrorMsg{Code: r.u32(), Index: r.u32()}
		if r.err || e.Code == 0 || e.Index >= BatchMax {
			return nil, corrupt("an ERROR's code 0 or its statement's index")
		}
		s, err := r.text(2, 0, MessageMax)
		if err != nil {
			return nil, err
		}
		e.Message = s
		return e, nil
	case TReady:
		st := r.u8()
		if !r.err && st > Doomed {
			return nil, corrupt("a READY's state")
		}
		return Ready{State: st}, nil
	}
	return nil, corrupt("a frame of a type the protocol does not define")
}

// RowsIter walks a ROWS frame's rows.
type RowsIter struct {
	data []byte
	off  int
	left uint32
	ncol int
}

// Iter begins a walk of the frame's rows.
func (m Rows) Iter() *RowsIter { return &RowsIter{data: m.Data, left: m.N, ncol: m.NCols} }

// Next decodes the next row into dst (resized to the columns' count) and reports whether there was one; its values'
// S alias the frame's bytes.
func (it *RowsIter) Next(dst []Value) ([]Value, bool) {
	if it.left == 0 {
		return dst, false
	}
	dst = dst[:0]
	for i := 0; i < it.ncol; i++ {
		v, off, err := DecodeValue(it.data, it.off)
		if err != nil { // a frame its decoder validated: never
			return dst, false
		}
		it.off = off
		dst = append(dst, v)
	}
	it.left--
	return dst, true
}

// NewRows builds a ROWS frame's body from rows held to cols (the fake server's and the tests').
func NewRows(cols *Columns, rows [][]Value) (Rows, error) {
	if cols == nil || len(cols.Cols) < 1 || len(rows) < 1 {
		return Rows{}, refused("a ROWS against no COLUMNS, or of no row")
	}
	var data []byte
	for _, row := range rows {
		if len(row) != len(cols.Cols) {
			return Rows{}, refused("a row of another count of values than its columns")
		}
		for i := range row {
			if !ValueFits(&cols.Cols[i], &row[i]) {
				return Rows{}, refused("a value its column does not take")
			}
			data = appendRaw(data, &row[i])
		}
	}
	return Rows{N: uint32(len(rows)), NCols: len(cols.Cols), Data: data}, nil
}

// AppendFrame appends m as a frame (its head, type and body): the exact bytes its decoder takes, or a refusal of a
// field its decoder would refuse (wire.c's imdbw_msg_put), nothing appended then. A ROWS is checked against cols.
func AppendFrame(b []byte, m Msg, cols *Columns) ([]byte, error) {
	at := len(b)
	b = append(b, 0, 0, 0, 0, byte(m.Type()))
	out, err := bodyPut(b, m, cols)
	if err != nil {
		return b[:at], err
	}
	n := len(out) - at - 4 // the type and the body
	if n > FrameMax {
		return b[:at], refused("a frame past 16 MiB")
	}
	binary.LittleEndian.PutUint32(out[at:], uint32(n))
	return out, nil
}

func bodyPut(b []byte, m Msg, cols *Columns) ([]byte, error) {
	le := binary.LittleEndian
	var err error
	switch m := m.(type) {
	case Query:
		if len(m.Stmts) < 1 || len(m.Stmts) > BatchMax {
			return b, refused("a QUERY of 1 to 4,096 statements")
		}
		b = le.AppendUint32(b, uint32(len(m.Stmts)))
		for _, s := range m.Stmts {
			if b, err = putText(b, 4, 1, SQLMax, s.SQL); err != nil {
				return b, err
			}
			if len(s.Params) > ValuesMax {
				return b, refused("a statement of more than 256 values")
			}
			b = le.AppendUint16(b, uint16(len(s.Params)))
			if b, err = appendParams(b, s.Params); err != nil {
				return b, err
			}
		}
	case Prepare:
		if b, err = putText(b, 1, 1, NameMax, m.Name); err != nil {
			return b, err
		}
		return putText(b, 4, 1, SQLMax, m.SQL)
	case Execute:
		if b, err = putText(b, 1, 1, NameMax, m.Name); err != nil {
			return b, err
		}
		if m.Sets < 1 || m.Sets > BatchMax || m.NVals < 0 || m.NVals > ValuesMax || len(m.Values) != m.Sets*m.NVals {
			return b, refused("an EXECUTE of 1 to 4,096 sets of at most 256 values, each set as many")
		}
		b = le.AppendUint32(b, uint32(m.Sets))
		b = le.AppendUint16(b, uint16(m.NVals))
		return appendParams(b, m.Values)
	case Deallocate:
		return putText(b, 1, 1, NameMax, m.Name)
	case CopyData:
		if len(m.Data) == 0 {
			return b, refused("a COPY piece of no bytes")
		}
		return append(b, m.Data...), nil
	case CopyOut:
		if len(m.Data) == 0 {
			return b, refused("a COPY piece of no bytes")
		}
		return append(b, m.Data...), nil
	case CopyFail:
		return putText(b, 2, 0, MessageMax, m.Message)
	case Warning:
		return putText(b, 2, 0, MessageMax, m.Message)
	case Columns:
		if len(m.Cols) < 1 || len(m.Cols) > ValuesMax {
			return b, refused("a COLUMNS of 1 to 256 columns")
		}
		b = le.AppendUint16(b, uint16(len(m.Cols)))
		for i := range m.Cols {
			c := &m.Cols[i]
			if !c.shapeOK() {
				return b, refused("a column's type, precision or scale")
			}
			if c.Type == TypeEnum {
				if err := c.index(); err != nil { // its labels distinct
					return b, refused("an ENUM's labels not distinct or past their bounds")
				}
			}
			if b, err = putText(b, 1, 1, ColNameMax, c.Name); err != nil {
				return b, err
			}
			b = append(b, byte(c.Type))
			b = le.AppendUint16(b, c.Precision)
			b = le.AppendUint16(b, c.Scale)
			if c.Type == TypeEnum {
				b = le.AppendUint16(b, uint16(len(c.Labels)))
				for _, l := range c.Labels {
					if b, err = putText(b, 1, 0, LabelMax, l); err != nil {
						return b, err
					}
				}
			}
		}
	case Rows:
		if m.N < 1 || cols == nil || len(cols.Cols) < 1 || m.NCols != len(cols.Cols) {
			return b, refused("a ROWS against no COLUMNS, or another count of them")
		}
		r := &rd{b: m.Data}
		if _, err := r.span(uint64(m.N)*uint64(m.NCols), cols); err != nil || r.left() != 0 {
			return b, refused("a ROWS whose values are not its columns'")
		}
		b = le.AppendUint32(b, m.N)
		return append(b, m.Data...), nil
	case Done:
		if !doneOK(&m) {
			return b, refused("a DONE's status, or a write at commit 0")
		}
		b, _ = putText(b, 2, 0, StatusMax, m.Status)
		b = le.AppendUint64(b, m.Count)
		if m.HasRead {
			b = append(b, 1)
			b = le.AppendUint64(b, m.Read.Commit)
			b = append(b, m.Read.Hash[:]...)
			b = append(b, m.Read.Digest[:]...)
			b = le.AppendUint64(b, m.Read.LakeCommit)
			b = append(b, m.Read.LakeManifest[:]...)
			b = append(b, m.Read.DatabaseID[:]...)
			b = append(b, boolByte(m.Read.Own))
		} else {
			b = append(b, 0)
		}
		if m.HasWrite {
			b = append(b, 1)
			b = le.AppendUint64(b, m.WriteCommit)
			b = append(b, m.WriteHash[:]...)
		} else {
			b = append(b, 0)
		}
	case ErrorMsg:
		if m.Code == 0 || m.Index >= BatchMax {
			return b, refused("an ERROR's code 0 or its index")
		}
		b = le.AppendUint32(b, m.Code)
		b = le.AppendUint32(b, m.Index)
		return putText(b, 2, 0, MessageMax, m.Message)
	case Ready:
		if m.State > Doomed {
			return b, refused("a READY's state")
		}
		return append(b, m.State), nil
	case Kill:
		if !killOK(m.Kind, m.Session) {
			return b, refused("a KILL's kind or a session id of 0")
		}
		b = append(b, m.Kind)
		return le.AppendUint64(b, m.Session), nil
	case KillDone:
		if m.Code > KillNone || m.Session == 0 {
			return b, refused("a KILL_DONE's code or a session id of 0")
		}
		b = append(b, m.Code)
		return le.AppendUint64(b, m.Session), nil
	case SessionsList:
		if len(m.Sessions) > SessionsMax {
			return b, refused("a SESSIONS_LIST past 65,536 sessions")
		}
		b = le.AppendUint32(b, uint32(len(m.Sessions)))
		prev := uint64(0)
		for i := range m.Sessions {
			s := &m.Sessions[i]
			if !sessOK(s, prev) {
				return b, refused("a session's id out of order, or its role, endpoint, state or name")
			}
			prev = s.ID
			b = le.AppendUint64(b, s.ID)
			b = le.AppendUint32(b, s.Role)
			b = append(b, s.Endpoint, s.State)
			b = le.AppendUint64(b, s.AgeMs)
			b, _ = putText(b, 1, 0, UserField-1, s.Name)
		}
	case Sessions, CopyDone, Cancel, Ping, Terminate, CopyIn, Pong:
	default:
		return b, refused("no such frame")
	}
	return b, nil
}

func boolByte(x bool) byte {
	if x {
		return 1
	}
	return 0
}
