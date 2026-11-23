package wire

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strings"
	"testing"
)

// samples: one message of every type, as t_wire.c's samples() (lines 588-684) builds them.
func samples(t testing.TB) ([]Msg, *Columns) {
	cols := &Columns{Cols: []Column{
		{Name: "id", Type: TypeInt64, Precision: 32},
		{Name: "amount", Type: TypeDecimal, Precision: 38, Scale: 6},
		{Name: "name", Type: TypeText, Precision: 12},
		{Name: "mood", Type: TypeEnum, Labels: []string{"", "x", "\xc3\xa9"}},
	}}
	if err := cols.Index(); err != nil {
		t.Fatal(err)
	}
	ph, pl := Pow10(38)
	limHi, limLo := int64(ph), pl-1 // 10^38 - 1 (pl is not 0)
	rows, err := NewRows(cols, [][]Value{
		{{Type: TypeInt64, I: -2147483648}, {Type: TypeDecimal, Scale: 6, Hi: -1, Lo: ^uint64(1234567) + 1},
			{Type: TypeText, S: []byte("h\xc3\xa9llo")}, {Type: TypeEnum, S: []byte("x")}},
		{{Null: true, Type: TypeInt64}, {Type: TypeDecimal, Scale: 6, Hi: limHi, Lo: limLo}, {Type: TypeText, S: []byte{}},
			{Type: TypeEnum, S: []byte{}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	ev := []Value{{Type: TypeInt64, I: -2}, {Type: TypeFloat64, F: 0x3ff8000000000000}, {Null: true},
		{Type: TypeDecimal, Scale: 2, Hi: -1, Lo: uint64(0xffffffffffffcfc7)}, {Type: TypeTimestampTZ, I: -1},
		{Type: TypeDate, Day: 2932896}, {Type: TypeUUID, S: kUUID}, {Type: TypeInterval, Mon: -1 << 31, Day: 1<<31 - 1, I: -1 << 63}}
	var h1, h2, h3 [32]byte
	for i := range h1 {
		h1[i], h2[i], h3[i] = 1, 2, 3
	}
	d := Done{Status: "INSERT 0 3", Count: 3, HasRead: true, HasWrite: true, WriteCommit: 42,
		Read: ReadPoint{Commit: 41, Hash: h1, Digest: h2, LakeCommit: 44, LakeManifest: h3, Own: true}}
	for i := range d.Read.DatabaseID {
		d.Read.DatabaseID[i] = 4
	}
	for i := range d.WriteHash {
		d.WriteHash[i] = 5
	}
	ms := []Msg{
		Execute{Name: "p1", Sets: 2, NVals: 4, Values: ev},
		Query{Stmts: []Statement{{SQL: "SELECT $1, $2", Params: []Value{{Type: TypeInt64, I: 7}, {Type: TypeText, S: []byte("t")}}},
			{SQL: "BEGIN"}, {SQL: "\xc3\xa9", Params: []Value{{Null: true, Type: TypeEnum}}}}},
		Query{Stmts: []Statement{{SQL: "BEGIN"}}},
		Prepare{Name: "p1", SQL: "SELECT $1, $2"},
		Prepare{Name: strings.Repeat("n", 63), SQL: "BEGIN"},
		Execute{Name: "p2", Sets: 3},
		Deallocate{Name: "p1"},
		CopyData{Data: []byte("a,b\n\x00\xff")},
		CopyDone{}, CopyFail{Message: "SELECT $1, $2"}, Cancel{}, Ping{}, Terminate{}, Sessions{},
		Kill{Kind: KillCancel, Session: 1}, Kill{Kind: KillTerminate, Session: ^uint64(0)},
		*cols, rows, d,
		Done{Status: ""},
		Done{Status: "SELECT 0", HasRead: true},
		ErrorMsg{Code: 5, Index: 2, Message: "BEGIN"},
		Warning{Message: "\xc3\xa9"},
		CopyIn{}, CopyOut{Data: []byte("1,2\n")}, Ready{State: Doomed}, Pong{},
		SessionsList{Sessions: []Session{{ID: 3, Role: 7, Endpoint: 1, State: SessCopy, AgeMs: ^uint64(0), Name: "hé"},
			{ID: 4, Role: ^uint32(0), Endpoint: 2, State: SessIdle}}},
		SessionsList{},
		KillDone{Code: Killed, Session: 9}, KillDone{Code: KillNone, Session: ^uint64(0)},
	}
	return ms, cols
}

// reencode: a frame's body decoded, then encoded again: the same frame, or the decoder's refusal.
func reencode(frame []byte, cols *Columns) (same bool, err error) {
	if len(frame) < HeadLen {
		return false, corrupt("short")
	}
	n, t, err := DecodeHead(frame, FrameType(frame[4]).FromServer())
	if err != nil {
		return false, err
	}
	if int(n)+4 != len(frame) {
		return false, corrupt("length")
	}
	m, err := DecodeBody(t, frame[HeadLen:], cols)
	if err != nil {
		return false, err
	}
	again, err := AppendFrame(nil, m, cols)
	return err == nil && bytes.Equal(again, frame), nil
}

func TestMessages(t *testing.T) {
	ms, cols := samples(t)
	for k, m := range ms {
		f, err := AppendFrame(nil, m, cols)
		if err != nil || f[4] != byte(m.Type()) {
			t.Fatalf("sample %d (%s): %v", k, m.Type(), err)
		}
		if same, err := reencode(f, cols); err != nil || !same {
			t.Fatalf("sample %d (%s): round trip %v %v", k, m.Type(), same, err)
		}
	}
	// the decoded fields (t_wire.c lines 736-759)
	f, _ := AppendFrame(nil, *cols, nil)
	m, err := DecodeBody(TColumns, f[HeadLen:], nil)
	if err != nil {
		t.Fatal(err)
	}
	dc := m.(Columns)
	if len(dc.Cols) != 4 || dc.Cols[1].Name != "amount" || dc.Cols[1].Precision != 38 || dc.Cols[1].Scale != 6 ||
		len(dc.Cols[3].Labels) != 3 || dc.Cols[3].Labels[2] != "\xc3\xa9" {
		t.Fatalf("COLUMNS decoded: %+v", dc)
	}
	f, _ = AppendFrame(nil, ms[1], nil)
	m, err = DecodeBody(TQuery, f[HeadLen:], nil)
	q := m.(Query)
	if err != nil || len(q.Stmts) != 3 || len(q.Stmts[0].Params) != 2 || len(q.Stmts[1].Params) != 0 ||
		len(q.Stmts[2].Params) != 1 || q.Stmts[0].Params[0].I != 7 || string(q.Stmts[0].Params[1].S) != "t" {
		t.Fatalf("QUERY decoded: %+v %v", q, err)
	}
	// ROWS walked
	rf, _ := AppendFrame(nil, ms[17], cols)
	m, err = DecodeBody(TRows, rf[HeadLen:], cols)
	if err != nil {
		t.Fatal(err)
	}
	it := m.(Rows).Iter()
	var row []Value
	var n int
	for {
		var ok bool
		if row, ok = it.Next(row); !ok {
			break
		}
		n++
		if len(row) != 4 {
			t.Fatal("a row's values")
		}
	}
	if n != 2 {
		t.Fatalf("rows walked: %d", n)
	}
}

// TestFlips: every byte of every sample flipped three ways, every cut and one byte more: what a decoder takes encodes back
// to itself; a cut or a longer body is refused but for COPY's raw pieces (t_wire.c lines 868-910).
func TestFlips(t *testing.T) {
	ms, cols := samples(t)
	for k, m := range ms {
		f, err := AppendFrame(nil, m, cols)
		if err != nil {
			t.Fatal(err)
		}
		raw := m.Type() == TCopyData || m.Type() == TCopyOut
		for i := HeadLen; i < len(f); i++ {
			for _, b := range []byte{0x01, 0x80, 0xff} {
				x := bytes.Clone(f)
				x[i] ^= b
				if same, err := reencode(x, cols); err == nil && !same {
					t.Fatalf("sample %d (%s): byte %d ^ %x taken, not its bytes", k, m.Type(), i, b)
				}
			}
		}
		for cut := HeadLen; cut < len(f); cut++ {
			x := bytes.Clone(f[:cut])
			binary.LittleEndian.PutUint32(x, uint32(cut-4))
			same, err := reencode(x, cols)
			if raw && err == nil && !same && cut > HeadLen || !raw && err == nil {
				t.Fatalf("sample %d (%s): cut at %d taken", k, m.Type(), cut)
			}
		}
		x := append(bytes.Clone(f), 0)
		binary.LittleEndian.PutUint32(x, uint32(len(x)-4))
		same, err := reencode(x, cols)
		if raw && (err != nil || !same) || !raw && err == nil {
			t.Fatalf("sample %d (%s): a byte more: %v %v", k, m.Type(), same, err)
		}
	}
}

func body(t *testing.T, ty FrameType, h string, cols *Columns) error {
	t.Helper()
	_, err := DecodeBody(ty, unhex(t, h), cols)
	return err
}

// boundsCase is one of t_wire.c's t_wire_bounds checks (lines 942-1081): a body and its verdict.
type boundsCase struct {
	ty   FrameType
	hex  string
	want int // 0 taken, -1 refused (any code), else the code
}

func boundsTable() []boundsCase {
	zero32 := strings.Repeat("00", 32)
	zero16 := strings.Repeat("00", 16)
	return []boundsCase{
		{TQuery, "00000000", -1}, {TQuery, "01100000 01000000 61 0000", -1}, {TQuery, "ffffffff 01000000 61 0000", -1},
		{TQuery, "01000000 00000000 0000", -1}, {TQuery, "01000000 01004000 61 0000", CodeLimit},
		{TQuery, "01000000 01000000 61 0000", 0}, {TQuery, "01000000 01000000 61 0100 81", 0},
		{TQuery, "01000000 01000000 61 0100 00", -1}, {TQuery, "01000000 01000000 61 0100 0d0161", -1},
		{TQuery, "01000000 01000000 61 0100 8d", 0}, {TQuery, "01000000 01000000 61 0101 00", -1},
		{TQuery, "01000000 01000000 61 0000 00", -1}, {TQuery, "01000000 01000000 61", -1},
		{TQuery, "01000000 01000000 ff 0000", -1}, {TQuery, "01000000 02000000 6100 0000", -1},
		{TDeallocate, "01 c3", -1}, {TColumns, "0100 01ff 03 0000 0000", -1}, {TColumns, "0100 0161 0d 0000 0000 0100 01 80", -1},
		{TDone, "0100 ff 0000000000000000 00 00", -1}, {TError, "05000000 00000000 0100 00", -1}, {TWarning, "0200 c0af", -1},
		{TCopyData, "ff00", 0}, {TExecute, "0170 01000000 0101", -1}, {TExecute, "0170 00000000 0000", -1},
		{TExecute, "0170 01000000 0100 80", 0}, {TExecute, "0170 01000000 0100 0d0161", -1}, {TExecute, "00 01000000 0000", -1},
		{TPrepare, "0170 01000000 61", 0}, {TPrepare, "0170 01000000 61 00", -1},
		{TDeallocate, "40 " + strings.Repeat("61", 64), -1},
		{TColumns, "0000", -1}, {TColumns, "0100 0161 05 2700 0000", -1}, {TColumns, "0100 0161 05 0200 0300", -1},
		{TColumns, "0100 0161 05 2600 2600", 0}, {TColumns, "0100 0161 01 0800 0000", -1}, {TColumns, "0100 0161 01 1000 0000", 0},
		{TColumns, "0100 0161 03 0100 0000", -1}, {TColumns, "0100 0161 00 0000 0000", 0}, {TColumns, "0100 0161 00 0100 0000", -1},
		{TColumns, "0100 0161 05 0000 2600", 0}, {TColumns, "0100 0161 05 0000 2700", -1}, {TColumns, "0100 0161 0e 0000 0000", -1},
		{TColumns, "0100 0161 0d 0000 0000 ffff", -1}, {TColumns, "0100 0161 0d 0000 0000 0104", -1},
		{TColumns, "0100 0161 0d 0000 0000 0100 00", 0}, {TColumns, "0100 0161 0d 0000 0000 0100 40", CodeLimit},
		{TColumns, "0100 0161 0d 0100 0000 0100 00", -1},
		{TDone, "0000 0000000000000000 02 00", -1}, {TDone, "0000 0000000000000000 00 00", 0},
		{TDone, "0000 ffffffffffffffff 00 00", 0}, {TDone, "0000 00 00", -1},
		{TDone, fmt.Sprintf("0000 0000000000000000 01 0000000000000000 %s %s 0100000000000000 01%.62s %s 00 00", zero32, zero32, zero32, zero16), 0},
		{TDone, fmt.Sprintf("0000 0000000000000000 01 0000000000000000 %s %s 0100000000000000 %s %s 01 00", zero32, zero32, zero32, zero16), 0},
		{TDone, fmt.Sprintf("0000 0000000000000000 01 0000000000000000 %s %s 0100000000000000 %s %s 02 00", zero32, zero32, zero32, zero16), -1},
		{TDone, fmt.Sprintf("0000 0000000000000000 00 01 0000000000000000 %s", zero32), -1},
		{TDone, "0002 " + strings.Repeat("0", 1024) + " 00 00", CodeLimit},
		{TError, "05000000 00100000 0000", -1}, {TError, "00000000 00000000 0000", -1}, {TError, "05000000 ff0f0000 0000", 0},
		{TReady, "03", -1}, {TReady, "", -1}, {TPing, "00", -1},
		{TKill, "01 0100000000000000", 0}, {TKill, "00 0100000000000000", -1}, {TKill, "03 0100000000000000", -1},
		{TKill, "02 0000000000000000", -1}, {TKill, "02 01000000000000", -1}, {TKill, "02 0100000000000000 00", -1},
		{TKillDone, "01 0100000000000000", 0}, {TKillDone, "02 0100000000000000", -1}, {TKillDone, "03 0100000000000000", -1},
		{TKillDone, "00 0000000000000000", -1}, {TSessions, "00", -1},
		{TSessionsList, "00000000", 0},
		{TSessionsList, "01000000 0100000000000000 01000000 01 00 0000000000000000 00", 0},
		{TSessionsList, "01000000 0000000000000000 01000000 01 00 0000000000000000 00", -1},
		{TSessionsList, "01000000 0100000000000000 00000000 01 00 0000000000000000 00", -1},
		{TSessionsList, "01000000 0100000000000000 01000000 03 00 0000000000000000 00", -1},
		{TSessionsList, "01000000 0100000000000000 01000000 01 04 0000000000000000 00", -1},
		{TSessionsList, "01000000 0100000000000000 01000000 01 00 0000000000000000 40", -1},
		{TSessionsList, "01000000 0100000000000000 01000000 01 00 0000000000000000 01 ff", -1},
		{TSessionsList, "02000000 0200000000000000 01000000 01 00 0000000000000000 00 0200000000000000 01000000 01 00 0000000000000000 00", -1},
		{TSessionsList, "02000000 0200000000000000 01000000 01 00 0000000000000000 00 0100000000000000 01000000 01 00 0000000000000000 00", -1},
		{TSessionsList, "02000000 0100000000000000 01000000 01 00 0000000000000000 00", -1},
		{TSessionsList, "01000100 0100000000000000 01000000 01 00 0000000000000000 00", -1},
		{TCopyData, "", -1}, {TCopyFail, "0110", CodeLimit}, {TRows, "01000000 00", -1}, // ROWS: no COLUMNS before
		// lines 1079-1081: a count past its bytes refused before it sizes anything
		{TQuery, "00100000 01000000 61 0000", -1}, {TColumns, "0001 0161 01 0000 0000", -1},
		{TColumns, "0100 0161 0d 0000 0000 0004", -1},
	}
}

// TestBounds: t_wire.c's t_wire_bounds (lines 923-1089), each case with its verdict (0 taken, -1 refused, CodeLimit).
func TestBounds(t *testing.T) {
	h := []byte{0, 0, 0, 0, byte(TQuery)}
	if _, _, err := DecodeHead(h, false); code(err) != CodeLimit {
		t.Fatal("length 0")
	}
	binary.LittleEndian.PutUint32(h, FrameMax+1)
	if _, _, err := DecodeHead(h, false); code(err) != CodeLimit {
		t.Fatal("16 MiB + 1")
	}
	binary.LittleEndian.PutUint32(h, FrameMax)
	if n, _, err := DecodeHead(h, false); err != nil || n != FrameMax {
		t.Fatal("16 MiB")
	}
	if _, _, err := DecodeHead(h, true); err == nil {
		t.Fatal("a client's type from the server")
	}
	badClient, badServer := []byte{0, 13, 63, 64, 74, 255}, []byte{0, 1, 12, 63, 75, 255}
	for i := range badClient {
		h[4] = badClient[i]
		if _, _, err := DecodeHead(h, false); err == nil {
			t.Fatalf("client type %d taken", badClient[i])
		}
		h[4] = badServer[i]
		if _, _, err := DecodeHead(h, true); err == nil {
			t.Fatalf("server type %d taken", badServer[i])
		}
	}
	cases := boundsTable()
	for k, c := range cases {
		err := body(t, c.ty, c.hex, nil)
		ok := c.want == 0 && err == nil || c.want == -1 && err != nil || c.want > 0 && code(err) == c.want
		if !ok {
			t.Fatalf("case %d (%s %s): %v, want %d", k, c.ty, c.hex, err, c.want)
		}
	}
	if err := body(t, TRows, "01000000 00", nil); err == nil { // no COLUMNS before
		t.Fatal("ROWS without COLUMNS")
	}
	// lines 1044-1073: an ENUM of 1,024 distinct labels taken, of 1,025 refused
	for _, nl := range []int{1024, 1025} {
		b := []byte{1, 0, 1, 'e', byte(TypeEnum), 0, 0, 0, 0}
		b = binary.LittleEndian.AppendUint16(b, uint16(nl))
		labels := make([]string, nl)
		for i := 0; i < nl; i++ {
			l := string([]byte{byte('a' + i/676), byte('a' + i/26%26), byte('a' + i%26)})
			labels[i] = l
			b = append(append(b, 3), l...)
		}
		if _, err := DecodeBody(TColumns, b, nil); (err == nil) != (nl == 1024) {
			t.Fatalf("%d labels: %v", nl, err)
		}
		if _, err := AppendFrame(nil, Columns{Cols: []Column{{Name: "e", Type: TypeEnum, Labels: labels}}}, nil); (err == nil) != (nl == 1024) {
			t.Fatalf("%d labels encoded: %v", nl, err)
		}
	}
}

// TestRowsFit: a ROWS held to its COLUMNS (t_wire.c lines 766-864).
func TestRowsFit(t *testing.T) {
	_, cols := samples(t)
	ph, pl := Pow10(38)
	cases := []struct {
		col int
		v   Value
		ok  bool
	}{
		{0, Value{Type: TypeInt64, I: 2147483647}, true},
		{0, Value{Type: TypeInt64, I: 2147483648}, false},
		{0, Value{Type: TypeInt64, I: -2147483649}, false},
		{0, Value{Type: TypeTimestamp, I: 1}, false},
		{0, Value{Null: true, Type: TypeInt64}, true},
		{0, Value{Null: true, Type: TypeText}, false},
		{0, Value{Null: true}, false},
		{1, Value{Type: TypeDecimal, Scale: 6, Hi: int64(ph), Lo: pl - 1}, true},
		{1, Value{Type: TypeDecimal, Scale: 5, Lo: 1}, false},
		{1, Value{Type: TypeInt64, I: 1}, false},
		{2, Value{Type: TypeText, S: []byte(strings.Repeat("\xc3\xa9", 12))}, true},
		{2, Value{Type: TypeText, S: []byte("0123456789abc")}, false},
		{2, Value{Type: TypeBytea, S: []byte("a")}, false},
		{3, Value{Type: TypeEnum, S: []byte("\xc3\xa9")}, true},
		{3, Value{Type: TypeEnum, S: []byte("y")}, false},
		{3, Value{Type: TypeEnum, S: []byte("xx")}, false},
		{3, Value{Type: TypeText, S: []byte("x")}, false},
	}
	for k, c := range cases {
		if ValueFits(&cols.Cols[c.col], &c.v) != c.ok {
			t.Fatalf("case %d: fits %v", k, !c.ok)
		}
		row := []Value{{Null: true, Type: TypeInt64}, {Null: true, Type: TypeDecimal}, {Null: true, Type: TypeText},
			{Null: true, Type: TypeEnum}}
		row[c.col] = c.v
		_, encErr := NewRows(cols, [][]Value{row})
		var data []byte // the same frame by hand, unchecked: for the decoder
		for i := range row {
			data = appendRaw(data, &row[i])
		}
		raw := append(binary.LittleEndian.AppendUint32(nil, 1), data...)
		_, decErr := DecodeBody(TRows, raw, cols)
		if (encErr == nil) != c.ok || (decErr == nil) != c.ok {
			t.Fatalf("case %d: encoder %v, decoder %v", k, encErr, decErr)
		}
	}
	sc := Column{Name: "s", Type: TypeInt64, Precision: 16}
	if !ValueFits(&sc, &Value{Type: TypeInt64, I: 32767}) || ValueFits(&sc, &Value{Type: TypeInt64, I: 32768}) {
		t.Fatal("SMALLINT")
	}
	d52 := Column{Name: "d", Type: TypeDecimal, Precision: 5, Scale: 2}
	if !ValueFits(&d52, &Value{Type: TypeDecimal, Scale: 2, Hi: -1, Lo: ^uint64(99999) + 1}) ||
		ValueFits(&d52, &Value{Type: TypeDecimal, Scale: 2, Lo: 100000}) {
		t.Fatal("DECIMAL(5,2)")
	}
	d0 := Column{Name: "d", Type: TypeDecimal, Scale: 2}
	if !ValueFits(&d0, &Value{Type: TypeDecimal, Scale: 2, Hi: int64(ph), Lo: pl - 1}) || ValueFits(&d0, &Value{Type: TypeDecimal, Scale: 3}) {
		t.Fatal("DECIMAL of no known precision")
	}
	none := Column{Name: "x"}
	for _, v := range []Value{{Type: TypeInt64, I: 1}, {Type: TypeEnum, S: []byte("q")}, {Null: true}, {Null: true, Type: TypeDate}} {
		if !ValueFits(&none, &v) {
			t.Fatalf("a column of no type refuses %+v", v)
		}
	}
	if ValueFits(&none, &Value{Type: TypeBool, I: 2}) {
		t.Fatal("an invalid value under a column of no type")
	}
	dup := Columns{Cols: []Column{{Name: "e", Type: TypeEnum, Labels: []string{"a", "b", "a"}}}}
	if dup.Index() == nil {
		t.Fatal("labels twice indexed")
	}
	if _, err := DecodeBody(TColumns, unhex(t, "0100 0165 0d 0000 0000 0200 0161 0161"), nil); code(err) != CodeCorrupt ||
		!strings.Contains(err.Error(), "distinct") {
		t.Fatalf("labels twice decoded: %v", err)
	}
}

// TestAmplification: a frame costs its bytes: a ROWS of 2^18 rows of NULLs (a megabyte) decodes with a constant number of
// allocations, values never copied into arrays (t_wire.c lines 1093-1127).
func TestAmplification(t *testing.T) {
	_, cols := samples(t)
	rows := 1 << 18
	y := binary.LittleEndian.AppendUint32(nil, uint32(rows))
	for i := 0; i < rows; i++ {
		y = append(y, NullTag|byte(TypeInt64), NullTag|byte(TypeDecimal), NullTag|byte(TypeText), NullTag|byte(TypeEnum))
	}
	allocs := testing.AllocsPerRun(3, func() {
		if _, err := DecodeBody(TRows, y, cols); err != nil {
			t.Fatal(err)
		}
	})
	if allocs > 2 {
		t.Fatalf("a ROWS of NULLs: %v allocations", allocs)
	}
}
